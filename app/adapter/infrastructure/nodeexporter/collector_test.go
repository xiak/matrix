package nodeexporter

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

func TestSuccessiveUsageSeparatesRatesAvailableMemoryAndReservedFilesystemSpace(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	var source atomic.Value
	source.Store(exposition(0))
	collector := testCollector(t, &source, func() time.Time { return now })
	first, err := collector.ObserveExecutionTargetUsage(context.Background())
	if err != nil || first.CPU.State != paasv1.MeasurementWarmingUp || first.CPU.Value != nil {
		t.Fatalf("first counter sample fabricated a CPU rate: %#v, %v", first.CPU, err)
	}
	if first.Memory.State != paasv1.MeasurementAvailable || first.Memory.Value.UsedBytes != 3072 ||
		first.FilesystemsState != paasv1.MeasurementAvailable || len(first.Filesystems) != 1 {
		t.Fatal("current memory/filesystem measurement missing")
	}
	filesystem := first.Filesystems[0].Value
	if filesystem.UsedBytes != 6000 || filesystem.AvailableBytes != 3000 || *filesystem.TotalInodes != 100 || *filesystem.FreeInodes != 60 {
		t.Fatal("reserved filesystem blocks were counted as used or free inodes were lost")
	}
	now = now.Add(5 * time.Second)
	source.Store(exposition(1))
	second, err := collector.ObserveExecutionTargetUsage(context.Background())
	if err != nil || second.CPU.State != paasv1.MeasurementAvailable || second.CPU.Value.LogicalCPUs != 1 ||
		second.CPU.Value.WindowMillis != 5000 || math.Abs(second.CPU.Value.UtilizationRatio-0.3) > 1e-9 ||
		math.Abs(second.CPU.Value.IOWaitRatio-0.1) > 1e-9 || second.CPU.Value.Load1 != 0.25 {
		t.Fatalf("CPU delta, guest exclusion or units wrong: %#v, %v", second.CPU, err)
	}
	if !second.ObservedAt.After(first.ObservedAt) || second.ValidUntil.Sub(second.ObservedAt) != 15*time.Second {
		t.Fatal("measurement freshness did not advance")
	}
	// Reset and a long collection gap both require two new samples.
	now = now.Add(5 * time.Second)
	source.Store(exposition(0))
	reset, err := collector.ObserveExecutionTargetUsage(context.Background())
	if err != nil || reset.CPU.State != paasv1.MeasurementWarmingUp || reset.CPU.Value != nil {
		t.Fatal("counter reset fabricated a negative or zero utilization")
	}
	now = now.Add(20 * time.Second)
	source.Store(exposition(5))
	gap, err := collector.ObserveExecutionTargetUsage(context.Background())
	if err != nil || gap.CPU.State != paasv1.MeasurementWarmingUp {
		t.Fatal("stale baseline survived the observation window")
	}
}

func TestMissingAndMalformedMeasurementsDoNotBecomeZero(t *testing.T) {
	for name, test := range map[string]struct {
		change func(string) string
		check  func(paasv1.ExecutionTargetUsage) bool
	}{
		"missing available memory": {
			change: func(s string) string {
				return strings.ReplaceAll(s, "node_memory_MemAvailable_bytes", "ignored_memory_available")
			},
			check: func(v paasv1.ExecutionTargetUsage) bool {
				return v.Memory.State == paasv1.MeasurementUnavailable && v.Memory.Value == nil
			},
		},
		"duplicate memory": {
			change: func(s string) string { return s + "node_memory_MemTotal_bytes 4096\n" },
			check:  func(v paasv1.ExecutionTargetUsage) bool { return v.Memory.Value == nil },
		},
		"nonfinite memory": {
			change: func(s string) string {
				return strings.Replace(s, "node_memory_MemAvailable_bytes 1024", "node_memory_MemAvailable_bytes NaN", 1)
			},
			check: func(v paasv1.ExecutionTargetUsage) bool { return v.Memory.Value == nil },
		},
		"collector failed": {
			change: func(s string) string {
				return strings.Replace(s, `node_scrape_collector_success{collector="cpu"} 1`, `node_scrape_collector_success{collector="cpu"} 0`, 1)
			},
			check: func(v paasv1.ExecutionTargetUsage) bool {
				return v.CPU.State == paasv1.MeasurementUnavailable && v.Memory.Value != nil
			},
		},
		"missing CPU mode": {
			change: func(s string) string {
				return strings.Replace(s, `node_cpu_seconds_total{cpu="0",mode="idle"} 200`+"\n", "", 1)
			},
			check: func(v paasv1.ExecutionTargetUsage) bool { return v.CPU.State == paasv1.MeasurementUnavailable },
		},
		"duplicate CPU series": {
			change: func(s string) string { return s + `node_cpu_seconds_total{cpu="0",mode="idle"} 200` + "\n" },
			check:  func(v paasv1.ExecutionTargetUsage) bool { return v.CPU.State == paasv1.MeasurementUnavailable },
		},
		"explicit old timestamp": {
			change: func(s string) string {
				return strings.Replace(s, "node_memory_MemAvailable_bytes 1024", "node_memory_MemAvailable_bytes 1024 123", 1)
			},
			check: func(v paasv1.ExecutionTargetUsage) bool { return v.Memory.Value == nil },
		},
		"unsupported inodes": {
			change: func(s string) string {
				s = strings.Replace(s, filesystemSeries("files", 100), filesystemSeries("files", 0), 1)
				return strings.Replace(s, filesystemSeries("files_free", 60), filesystemSeries("files_free", 0), 1)
			},
			check: func(v paasv1.ExecutionTargetUsage) bool {
				return v.Filesystems[0].Value.InodesState == paasv1.MeasurementUnsupported && v.Filesystems[0].Value.TotalInodes == nil
			},
		},
		"unavailable filesystem": {
			change: func(s string) string {
				return strings.Replace(s, filesystemSeries("device_error", 0), filesystemSeries("device_error", 1), 1)
			},
			check: func(v paasv1.ExecutionTargetUsage) bool {
				return v.Filesystems[0].State == paasv1.MeasurementUnavailable && v.Filesystems[0].Value == nil
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			var source atomic.Value
			source.Store(test.change(exposition(0)))
			collector := testCollector(t, &source, time.Now)
			value, err := collector.ObserveExecutionTargetUsage(context.Background())
			if err != nil || !test.check(value) {
				t.Fatalf("missing value was not explicit: %#v, %v", value, err)
			}
		})
	}
}

func TestScrapeTransportAndPayloadAreBounded(t *testing.T) {
	for name, response := range map[string]func(http.ResponseWriter){
		"status": func(w http.ResponseWriter) { w.WriteHeader(http.StatusServiceUnavailable) },
		"redirect": func(w http.ResponseWriter) {
			w.Header().Set("Location", "http://127.0.0.1:1/private")
			w.WriteHeader(http.StatusFound)
		},
		"encoding": func(w http.ResponseWriter) {
			w.Header().Set("Content-Encoding", "gzip")
			_, _ = w.Write([]byte(exposition(0)))
		},
		"size":      func(w http.ResponseWriter) { _, _ = w.Write([]byte(strings.Repeat(" ", maximumScrapeBytes+1))) },
		"line":      func(w http.ResponseWriter) { _, _ = w.Write([]byte("# " + strings.Repeat("a", 16*1024) + "\n")) },
		"malformed": func(w http.ResponseWriter) { _, _ = w.Write([]byte("node_cpu_seconds_total{broken\n")) },
		"deadline":  func(w http.ResponseWriter) { time.Sleep(100 * time.Millisecond) },
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/plain; version=0.0.4")
				response(w)
			}))
			defer server.Close()
			collector := &Collector{endpoint: server.URL, http: &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, clock: time.Now}
			timeout := 2 * time.Second
			if name == "deadline" {
				timeout = 50 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			_, err := collector.ObserveExecutionTargetUsage(ctx)
			if err != ErrUnavailable {
				t.Fatalf("provider response escaped normalization: %v", err)
			}
		})
	}
}

func testCollector(t *testing.T, source *atomic.Value, clock func() time.Time) *Collector {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.Path != "/metrics" {
			t.Error("collector used an unexpected method or path")
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_, _ = w.Write([]byte(source.Load().(string)))
	}))
	t.Cleanup(server.Close)
	return &Collector{endpoint: server.URL + "/metrics", http: server.Client(), clock: clock}
}

func exposition(step int) string {
	var result strings.Builder
	result.WriteString("# TYPE node_scrape_collector_success gauge\n")
	for _, collector := range []string{"cpu", "loadavg", "meminfo", "filesystem"} {
		fmt.Fprintf(&result, "node_scrape_collector_success{collector=%q} 1\n", collector)
	}
	result.WriteString("# TYPE node_cpu_seconds_total counter\n")
	for index, value := range []int{100 + step*2, 3, 50 + step, 200 + step*6, 10 + step, 0, 0, 1} {
		fmt.Fprintf(&result, "node_cpu_seconds_total{cpu=\"0\",mode=%q} %d\n", cpuModes[index], value)
	}
	result.WriteString("# TYPE node_cpu_guest_seconds_total counter\nnode_cpu_guest_seconds_total{cpu=\"0\",mode=\"user\"} 99999\n")
	for name, value := range map[string]string{
		"node_load1": "0.25", "node_load5": "0.5", "node_load15": "0.75",
		"node_memory_MemTotal_bytes": "4096", "node_memory_MemAvailable_bytes": "1024",
		"node_memory_SwapTotal_bytes": "0", "node_memory_SwapFree_bytes": "0",
	} {
		fmt.Fprintf(&result, "# TYPE %s gauge\n%s %s\n", name, name, value)
	}
	for name, value := range map[string]int{"device_error": 0, "size_bytes": 10000, "free_bytes": 4000, "avail_bytes": 3000, "files": 100, "files_free": 60, "readonly": 0} {
		fmt.Fprintf(&result, "# TYPE node_filesystem_%s gauge\n%s\n", name, filesystemSeries(name, value))
	}
	return result.String()
}

func filesystemSeries(name string, value int) string {
	return fmt.Sprintf("node_filesystem_%s{device=\"/dev/test\",mountpoint=\"/\",fstype=\"ext4\",device_error=\"\"} %d", name, value)
}
