package compose

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

func TestDockerResourceCollectorUsesStructuredEngineDataAndKeepsStorageTime(t *testing.T) {
	now := time.Date(2026, 8, 31, 1, 2, 3, 0, time.UTC)
	containerID := strings.Repeat("a", 64)
	imageID := "sha256:" + strings.Repeat("b", 64)
	var inspectCalls, sizeCalls, statsCalls, diskCalls atomic.Int32
	var failDisk atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/v1.46/containers/" + containerID + "/json":
			inspectCalls.Add(1)
			value := map[string]any{
				"Id": containerID, "Image": imageID,
				"HostConfig": map[string]any{"NanoCpus": 500_000_000, "Memory": 64 << 20},
				"Mounts": []any{
					map[string]any{"Type": "volume", "Name": "volume-a"},
					map[string]any{"Type": "volume", "Name": "volume-a"},
					map[string]any{"Type": "bind", "Name": ""},
				},
			}
			if request.URL.Query().Get("size") == "true" {
				sizeCalls.Add(1)
				value["SizeRw"] = 1234
			}
			_ = json.NewEncoder(response).Encode(value)
		case "/v1.46/containers/" + containerID + "/stats":
			statsCalls.Add(1)
			_ = json.NewEncoder(response).Encode(map[string]any{
				"id":   containerID,
				"read": now.Format(time.RFC3339Nano), "preread": now.Add(-time.Second).Format(time.RFC3339Nano),
				"cpu_stats": map[string]any{
					"cpu_usage":        map[string]any{"total_usage": 1_000},
					"system_cpu_usage": 10_000, "online_cpus": 2,
				},
				"precpu_stats": map[string]any{
					"cpu_usage":        map[string]any{"total_usage": 500},
					"system_cpu_usage": 8_000,
				},
				"memory_stats": map[string]any{
					"usage": 10 << 20, "limit": 64 << 20,
					"stats": map[string]any{"inactive_file": 2 << 20},
				},
				"networks": map[string]any{
					"eth0": map[string]any{"rx_bytes": 100, "tx_bytes": 200, "rx_errors": 1, "tx_dropped": 2},
					"eth1": map[string]any{"rx_bytes": 10, "tx_bytes": 20, "rx_dropped": 3, "tx_errors": 4},
				},
				"blkio_stats": map[string]any{
					"io_service_bytes_recursive": []any{
						map[string]any{"op": "Read", "value": 300},
						map[string]any{"op": "Write", "value": 400},
					},
					"io_serviced_recursive": []any{
						map[string]any{"op": "Read", "value": 3},
						map[string]any{"op": "Write", "value": 4},
					},
				},
			})
		case "/v1.46/system/df":
			diskCalls.Add(1)
			if failDisk.Load() {
				response.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			_ = json.NewEncoder(response).Encode(map[string]any{
				"Images": []any{map[string]any{"Id": imageID, "Size": 1000, "SharedSize": 600}},
				"Volumes": []any{map[string]any{
					"Name": "volume-a", "UsageData": map[string]any{"Size": 500, "RefCount": 2},
				}},
			})
		default:
			t.Fatalf("unexpected Docker Engine path: %s", request.URL.String())
		}
	}))
	defer server.Close()
	collector := newDockerResourceCollectorWithEngine(
		&dockerEngineClient{http: server.Client(), endpoint: server.URL + "/v1.46"},
		func() time.Time { return now },
	)
	project := runtimeResourceProject(t)
	containers := []RuntimeContainer{{ID: containerID, State: "running"}}

	first, err := collector.observe(context.Background(), project, containers)
	if err != nil {
		t.Fatalf("collect Docker resources: %v", err)
	}
	value := first[containerID]
	if value.CPU.State != paasv1.MeasurementAvailable || value.CPU.Value == nil ||
		value.CPU.Value.WindowMillis != 1000 || value.CPU.Value.UsedCores != 0.5 ||
		value.CPU.Value.LimitCPUMillis != 500 || value.Memory.Value == nil ||
		value.Memory.Value.UsedBytes != 8<<20 || value.Network.Value == nil ||
		value.Network.Value.ReceivedBytes != 110 || value.Network.Value.TransmittedBytes != 220 ||
		value.Network.Value.ReceiveDrops != 3 || value.Network.Value.TransmitErrors != 4 ||
		value.BlockIO.Value == nil || value.BlockIO.Value.ReadBytes != 300 ||
		value.BlockIO.Value.WriteOperations != 4 || value.Storage.Value == nil ||
		value.Storage.Value.ObservedAt != now || value.Storage.Value.WritableLayerBytes != 1234 ||
		value.Storage.Value.ImageUniqueBytes != 400 || value.Storage.Value.Volumes == nil ||
		value.Storage.Value.Volumes.Count != 1 || value.Storage.Value.Volumes.SharedCount != 1 ||
		value.Storage.Value.Volumes.SharedBytes != 500 {
		t.Fatalf("normalized Docker resources = %#v", value)
	}
	if inspectCalls.Load() != 2 || sizeCalls.Load() != 1 || statsCalls.Load() != 1 || diskCalls.Load() != 1 {
		t.Fatalf("initial Engine calls inspect/size/stats/df = %d/%d/%d/%d",
			inspectCalls.Load(), sizeCalls.Load(), statsCalls.Load(), diskCalls.Load())
	}

	now = now.Add(5 * time.Second)
	second, err := collector.observe(context.Background(), project, containers)
	if err != nil || second[containerID].Storage.Value == nil ||
		second[containerID].Storage.Value.ObservedAt != first[containerID].Storage.Value.ObservedAt ||
		sizeCalls.Load() != 1 || diskCalls.Load() != 1 {
		t.Fatalf("storage cache was restamped or refreshed early: %#v / %v", second, err)
	}

	now = now.Add(90 * time.Second)
	failDisk.Store(true)
	stale, err := collector.observe(context.Background(), project, containers)
	if err != nil || stale[containerID].Storage.State != paasv1.MeasurementStale ||
		stale[containerID].Storage.Value == nil || stale[containerID].Storage.Value.ObservedAt != first[containerID].Storage.Value.ObservedAt {
		t.Fatalf("failed disk refresh did not retain an exact stale proof: %#v / %v", stale, err)
	}
}

func TestDockerResourceCollectorRejectsCrossContainerStatsAndSkipsStoppedStats(t *testing.T) {
	now := time.Date(2026, 8, 31, 1, 2, 3, 0, time.UTC)
	containerID := strings.Repeat("c", 64)
	imageID := "sha256:" + strings.Repeat("d", 64)
	var statsCalls atomic.Int32
	wrongStats := atomic.Bool{}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(request.URL.Path, "/json"):
			_ = json.NewEncoder(response).Encode(map[string]any{
				"Id": containerID, "Image": imageID, "SizeRw": 0,
				"HostConfig": map[string]any{"NanoCpus": 1_000_000_000, "Memory": 64 << 20},
				"Mounts":     []any{},
			})
		case strings.HasSuffix(request.URL.Path, "/stats"):
			statsCalls.Add(1)
			id := containerID
			if wrongStats.Load() {
				id = strings.Repeat("e", 64)
			}
			_ = json.NewEncoder(response).Encode(map[string]any{
				"id": id, "read": now.Format(time.RFC3339Nano),
				"preread":      now.Add(-time.Second).Format(time.RFC3339Nano),
				"cpu_stats":    map[string]any{"cpu_usage": map[string]any{"total_usage": 2}, "system_cpu_usage": 2, "online_cpus": 1},
				"precpu_stats": map[string]any{"cpu_usage": map[string]any{"total_usage": 1}, "system_cpu_usage": 1},
				"memory_stats": map[string]any{"usage": 1, "limit": 64 << 20, "stats": map[string]any{}},
				"networks":     map[string]any{}, "blkio_stats": map[string]any{},
			})
		case strings.HasSuffix(request.URL.Path, "/system/df"):
			_ = json.NewEncoder(response).Encode(map[string]any{
				"Images":  []any{map[string]any{"Id": imageID, "Size": 1, "SharedSize": 0}},
				"Volumes": []any{},
			})
		default:
			t.Fatalf("unexpected Docker Engine path: %s", request.URL.String())
		}
	}))
	defer server.Close()
	collector := newDockerResourceCollectorWithEngine(
		&dockerEngineClient{http: server.Client(), endpoint: server.URL + "/v1.46"},
		func() time.Time { return now },
	)
	project := runtimeResourceProject(t)
	stopped, err := collector.observe(context.Background(), project, []RuntimeContainer{{ID: containerID, State: "exited"}})
	if err != nil || stopped[containerID].CPU.State != paasv1.MeasurementUnavailable || statsCalls.Load() != 0 {
		t.Fatalf("stopped resource collection = %#v / %v / %d stats", stopped, err, statsCalls.Load())
	}
	wrongStats.Store(true)
	_, err = collector.observe(context.Background(), project, []RuntimeContainer{{ID: containerID, State: "running"}})
	if !errors.Is(err, ErrRuntimeOutputInvalid) {
		t.Fatalf("cross-container stats error = %v, want provider rejection", err)
	}
}

func TestDockerResourceCollectorOverlapsFastAndDiskObservation(t *testing.T) {
	now := time.Date(2026, 8, 31, 2, 3, 4, 0, time.UTC)
	containerID := strings.Repeat("f", 64)
	imageID := "sha256:" + strings.Repeat("e", 64)
	statsStarted := make(chan struct{})
	diskStarted := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(request.URL.Path, "/json"):
			value := map[string]any{
				"Id": containerID, "Image": imageID,
				"HostConfig": map[string]any{"NanoCpus": 1_000_000_000, "Memory": 64 << 20},
				"Mounts":     []any{},
			}
			if request.URL.Query().Get("size") == "true" {
				value["SizeRw"] = 1
			}
			_ = json.NewEncoder(response).Encode(value)
		case strings.HasSuffix(request.URL.Path, "/stats"):
			close(statsStarted)
			select {
			case <-release:
			case <-request.Context().Done():
				return
			}
			_ = json.NewEncoder(response).Encode(map[string]any{
				"id": containerID, "read": now.Format(time.RFC3339Nano),
				"preread":      now.Add(-time.Second).Format(time.RFC3339Nano),
				"cpu_stats":    map[string]any{"cpu_usage": map[string]any{"total_usage": 2}, "system_cpu_usage": 2, "online_cpus": 1},
				"precpu_stats": map[string]any{"cpu_usage": map[string]any{"total_usage": 1}, "system_cpu_usage": 1},
				"memory_stats": map[string]any{"usage": 1, "limit": 64 << 20, "stats": map[string]any{}},
				"networks":     map[string]any{}, "blkio_stats": map[string]any{},
			})
		case strings.HasSuffix(request.URL.Path, "/system/df"):
			close(diskStarted)
			select {
			case <-release:
			case <-request.Context().Done():
				return
			}
			_ = json.NewEncoder(response).Encode(map[string]any{
				"Images":  []any{map[string]any{"Id": imageID, "Size": 1, "SharedSize": 0}},
				"Volumes": []any{},
			})
		default:
			response.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	collector := newDockerResourceCollectorWithEngine(
		&dockerEngineClient{http: server.Client(), endpoint: server.URL + "/v1.46"},
		func() time.Time { return now },
	)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	project := runtimeResourceProject(t)
	type observation struct {
		resources map[string]RuntimeContainerResources
		err       error
	}
	completed := make(chan observation, 1)
	go func() {
		resources, err := collector.observe(
			ctx,
			project,
			[]RuntimeContainer{{ID: containerID, State: "running"}},
		)
		completed <- observation{resources: resources, err: err}
	}()
	for name, started := range map[string]<-chan struct{}{
		"container stats": statsStarted,
		"disk inventory":  diskStarted,
	} {
		select {
		case <-started:
		case <-time.After(500 * time.Millisecond):
			t.Fatalf("%s did not start within the shared observation budget", name)
		}
	}
	releaseOnce.Do(func() { close(release) })
	select {
	case result := <-completed:
		if result.err != nil || result.resources[containerID].Storage.State != paasv1.MeasurementAvailable {
			t.Fatalf("overlapped Docker resource observation = %#v / %v", result.resources, result.err)
		}
	case <-ctx.Done():
		t.Fatal("overlapped Docker resource observation exceeded its deadline")
	}
}

func TestNormalizeDockerDiskUsageFailsClosedOnAmbiguousProviderAccounting(t *testing.T) {
	now := time.Date(2026, 8, 31, 9, 0, 0, 0, time.UTC)
	decode := func(document string) dockerDiskUsage {
		t.Helper()
		var value dockerDiskUsage
		if err := json.Unmarshal([]byte(document), &value); err != nil {
			t.Fatalf("decode Docker disk fixture: %v", err)
		}
		return value
	}
	if normalizeDockerDiskUsage(
		decode(`{"Images":[{"Id":"sha256:image","Size":10,"SharedSize":4}]}`),
		now,
	) == nil {
		t.Fatal("valid Docker disk usage was rejected")
	}
	for name, document := range map[string]string{
		"invalid image accounting": `{"Images":[{"Id":"sha256:image","Size":4,"SharedSize":5}]}`,
		"duplicate image identity": `{"Images":[
			{"Id":"sha256:image","Size":10,"SharedSize":4},
			{"Id":"sha256:image","Size":10,"SharedSize":4}
		]}`,
		"invalid volume accounting": `{"Volumes":[{"Name":"volume","UsageData":null}]}`,
		"duplicate volume identity": `{"Volumes":[
			{"Name":"volume","UsageData":{"Size":10,"RefCount":1}},
			{"Name":"volume","UsageData":{"Size":10,"RefCount":1}}
		]}`,
	} {
		t.Run(name, func(t *testing.T) {
			if normalizeDockerDiskUsage(decode(document), now) != nil {
				t.Fatal("ambiguous Docker disk usage was accepted")
			}
		})
	}
}

func runtimeResourceProject(t *testing.T) RuntimeProject {
	t.Helper()
	directory := filepath.Clean(t.TempDir())
	return RuntimeProject{
		Name:                "matrix-" + strings.Repeat("a", 24),
		Directory:           directory,
		EffectDocument:      filepath.Join(directory, "compose.json"),
		ObservationDocument: filepath.Join(directory, "observe.json"),
		TimeoutSeconds:      3,
	}
}
