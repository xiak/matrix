// Package nodeexporter reads bounded, authenticated observations from the
// installation's unprivileged Prometheus node_exporter process. It has no
// Docker socket, SSH, OS collector implementation or scheduling authority.
package nodeexporter

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"mime"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
	nodev1 "github.com/xiak/matrix/api/adapter/node/v1"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
	nodehttps "github.com/xiak/matrix/app/adapter/node/https"
)

const maximumScrapeBytes = 8 * 1024 * 1024

var ErrUnavailable = errors.New("host usage collection is unavailable")

type Config struct {
	Endpoint    string
	Identity    nodev1.Identity
	Credentials nodehttps.Credentials
	Clock       func() time.Time
}

type Collector struct {
	endpoint   string
	http       *http.Client
	clock      func() time.Time
	mu         sync.Mutex
	previous   map[string][8]float64
	previousAt time.Time
}

func New(config Config) (*Collector, error) {
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.User != nil || endpoint.Path != "" ||
		endpoint.RawPath != "" || endpoint.RawQuery != "" || endpoint.ForceQuery || endpoint.Fragment != "" {
		return nil, ErrUnavailable
	}
	host, portText, err := net.SplitHostPort(endpoint.Host)
	port, portErr := strconv.ParseUint(portText, 10, 16)
	address := net.ParseIP(host)
	if err != nil || portErr != nil || port == 0 || address == nil || !address.IsLoopback() {
		return nil, ErrUnavailable
	}
	security, err := nodehttps.CollectorClientTLS(config.Credentials, config.Identity)
	if err != nil {
		return nil, ErrUnavailable
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	return &Collector{
		endpoint: endpoint.String() + "/metrics", clock: config.Clock,
		http: &http.Client{
			Timeout:       4 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			Transport: &http.Transport{
				Proxy: nil, DialContext: (&net.Dialer{Timeout: time.Second}).DialContext,
				TLSClientConfig: security, TLSHandshakeTimeout: time.Second,
				ResponseHeaderTimeout: 3 * time.Second, MaxResponseHeaderBytes: 16 * 1024,
				MaxConnsPerHost: 1, DisableCompression: true, DisableKeepAlives: true,
			},
		},
	}, nil
}

func (collector *Collector) Close() { collector.http.CloseIdleConnections() }

func (collector *Collector) ObserveExecutionTargetUsage(ctx context.Context) (paasv1.ExecutionTargetUsage, error) {
	collector.mu.Lock()
	defer collector.mu.Unlock()
	metrics, err := collector.scrape(ctx)
	if err != nil {
		collector.previous = nil
		return paasv1.ExecutionTargetUsage{}, ErrUnavailable
	}
	now := collector.clock().UTC().Truncate(time.Microsecond)
	value := paasv1.ExecutionTargetUsage{
		ObservedAt: now, ValidUntil: now.Add(nodev1.MaximumObservationAge),
		CPU: collector.cpu(metrics, now), Memory: memory(metrics),
	}
	value.FilesystemsState, value.Filesystems = filesystems(metrics)
	if paasv1.ValidateExecutionTargetUsage(value) != nil {
		collector.previous = nil
		return paasv1.ExecutionTargetUsage{}, ErrUnavailable
	}
	return value, nil
}

func (collector *Collector) scrape(ctx context.Context) (map[string]*dto.MetricFamily, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, collector.endpoint, nil)
	if err != nil {
		return nil, ErrUnavailable
	}
	request.Header.Set("Accept", "text/plain; version=0.0.4")
	response, err := collector.http.Do(request)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer response.Body.Close()
	mediaType, parameters, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || response.StatusCode != http.StatusOK || mediaType != "text/plain" ||
		(parameters["version"] != "" && parameters["version"] != "0.0.4") ||
		response.Header.Get("Content-Encoding") != "" || response.ContentLength > maximumScrapeBytes {
		return nil, ErrUnavailable
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maximumScrapeBytes+1))
	if err != nil || ctx.Err() != nil || len(body) > maximumScrapeBytes || len(body) == 0 ||
		bytes.Count(body, []byte{'\n'}) > 65536 {
		return nil, ErrUnavailable
	}
	// Bound parser allocation and pathological label scanning before parsing.
	for line := range bytes.SplitSeq(body, []byte{'\n'}) {
		if len(line) > 16*1024 {
			return nil, ErrUnavailable
		}
	}
	parser := expfmt.NewTextParser(model.LegacyValidation)
	metrics, err := parser.TextToMetricFamilies(bytes.NewReader(body))
	if err != nil || len(metrics) > 256 {
		return nil, ErrUnavailable
	}
	return metrics, nil
}

var cpuModes = []string{"user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal"}

func (collector *Collector) cpu(metrics map[string]*dto.MetricFamily, now time.Time) paasv1.CPUUsage {
	unavailable := paasv1.CPUUsage{State: paasv1.MeasurementUnavailable}
	current := cpuCounters(metrics)
	load1, ok1 := scalar(metrics, "node_load1")
	load5, ok5 := scalar(metrics, "node_load5")
	load15, ok15 := scalar(metrics, "node_load15")
	if current == nil || !succeeded(metrics, "cpu") || !succeeded(metrics, "loadavg") || !ok1 || !ok5 || !ok15 {
		collector.previous = nil
		return unavailable
	}
	previous, previousAt := collector.previous, collector.previousAt
	collector.previous, collector.previousAt = current, now
	warming := paasv1.CPUUsage{State: paasv1.MeasurementWarmingUp}
	window := now.Sub(previousAt)
	if len(previous) != len(current) || window < time.Millisecond || window > nodev1.MaximumObservationAge {
		return warming
	}
	var total, idle, ioWait float64
	for id, values := range current {
		before, found := previous[id]
		if !found {
			return warming
		}
		for mode, value := range values {
			delta := value - before[mode]
			if delta < 0 { // Reset, CPU hotplug or backward counter: re-prime, never fabricate a rate.
				return warming
			}
			total += delta
			if mode == 3 {
				idle += delta
			}
			if mode == 4 {
				ioWait += delta
			}
		}
	}
	if total <= 0 || math.IsInf(total, 0) {
		return warming
	}
	// Guest CPU time is already in user/nice; the exporter's separate guest
	// counters are not summed again. I/O wait is reported separately from busy.
	return paasv1.CPUUsage{State: paasv1.MeasurementAvailable, Value: &paasv1.CPUUsageValue{
		LogicalCPUs: int64(len(current)), WindowMillis: window.Milliseconds(),
		UtilizationRatio: math.Max(0, (total-idle-ioWait)/total), IOWaitRatio: ioWait / total,
		Load1: load1, Load5: load5, Load15: load15,
	}}
}

func cpuCounters(metrics map[string]*dto.MetricFamily) map[string][8]float64 {
	rows, ok := series(metrics, "node_cpu_seconds_total", dto.MetricType_COUNTER, "cpu", "mode")
	if !ok || len(rows)%len(cpuModes) != 0 || len(rows) > 4096*len(cpuModes) {
		return nil
	}
	result, counts := make(map[string][8]float64), make(map[string]int)
	for key, value := range rows {
		id, mode, _ := strings.Cut(key, "\x00")
		index := slices.Index(cpuModes, mode)
		if index < 0 || paasv1.ValidateID("cpu", id) != nil {
			return nil
		}
		values := result[id]
		values[index] = value
		result[id] = values
		counts[id]++
	}
	for _, count := range counts {
		if count != len(cpuModes) {
			return nil
		}
	}
	return result
}

func memory(metrics map[string]*dto.MetricFamily) paasv1.MemoryUsage {
	unavailable := paasv1.MemoryUsage{State: paasv1.MeasurementUnavailable}
	if !succeeded(metrics, "meminfo") {
		return unavailable
	}
	values := make([]int64, 4)
	for index, name := range []string{"MemTotal", "MemAvailable", "SwapTotal", "SwapFree"} {
		value, ok := scalar(metrics, "node_memory_"+name+"_bytes")
		if !ok || !safeInteger(value) {
			return unavailable
		}
		values[index] = int64(value)
	}
	if values[0] == 0 || values[1] > values[0] || values[3] > values[2] {
		return unavailable
	}
	return paasv1.MemoryUsage{State: paasv1.MeasurementAvailable, Value: &paasv1.MemoryUsageValue{
		TotalBytes: values[0], AvailableBytes: values[1], UsedBytes: values[0] - values[1],
		SwapTotalBytes: values[2], SwapFreeBytes: values[3],
	}}
}

func filesystems(metrics map[string]*dto.MetricFamily) (paasv1.MeasurementState, []paasv1.FilesystemUsage) {
	if !succeeded(metrics, "filesystem") {
		return paasv1.MeasurementUnavailable, nil
	}
	labels := []string{"device", "mountpoint", "fstype", "device_error"}
	devices, ok := series(metrics, "node_filesystem_device_error", dto.MetricType_GAUGE, labels...)
	if !ok || len(devices) > paasv1.MaximumObservedFilesystems {
		return paasv1.MeasurementUnavailable, nil
	}
	names := []string{"size_bytes", "free_bytes", "avail_bytes", "readonly"}
	values := make([]map[string]float64, len(names))
	for index, name := range names {
		values[index], _ = series(metrics, "node_filesystem_"+name, dto.MetricType_GAUGE, labels...)
	}
	totalInodes, _ := series(metrics, "node_filesystem_files", dto.MetricType_GAUGE, labels...)
	freeInodes, _ := series(metrics, "node_filesystem_files_free", dto.MetricType_GAUGE, labels...)
	result := make([]paasv1.FilesystemUsage, 0, len(devices))
	for key, deviceError := range devices {
		parts := strings.Split(key, "\x00")
		filesystem := paasv1.FilesystemUsage{
			Device: parts[0], MountPoint: parts[1], FilesystemType: parts[2], State: paasv1.MeasurementUnavailable,
		}
		// The exporter's raw device_error label is never copied into the API.
		if deviceError == 0 && parts[3] == "" {
			var fields [4]int64
			valid := true
			for index, field := range values {
				value, found := field[key]
				valid = valid && found && safeInteger(value)
				if valid {
					fields[index] = int64(value)
				}
			}
			if valid && fields[1] <= fields[0] && fields[2] <= fields[1] && fields[3] <= 1 {
				filesystem.State = paasv1.MeasurementAvailable
				filesystem.Value = &paasv1.FilesystemUsageValue{
					TotalBytes: fields[0], UsedBytes: fields[0] - fields[1], AvailableBytes: fields[2],
					InodesState: paasv1.MeasurementUnavailable, ReadOnly: fields[3] == 1,
				}
				total, totalOK := totalInodes[key]
				free, freeOK := freeInodes[key]
				if totalOK && freeOK && safeInteger(total) && safeInteger(free) && free <= total {
					if total == 0 {
						filesystem.Value.InodesState = paasv1.MeasurementUnsupported
					} else {
						totalValue, freeValue := int64(total), int64(free)
						filesystem.Value.InodesState = paasv1.MeasurementAvailable
						filesystem.Value.TotalInodes, filesystem.Value.FreeInodes = &totalValue, &freeValue
					}
				}
			}
		}
		result = append(result, filesystem)
	}
	slices.SortFunc(result, func(a, b paasv1.FilesystemUsage) int {
		if order := strings.Compare(a.MountPoint, b.MountPoint); order != 0 {
			return order
		}
		if order := strings.Compare(a.Device, b.Device); order != 0 {
			return order
		}
		return strings.Compare(a.FilesystemType, b.FilesystemType)
	})
	return paasv1.MeasurementAvailable, result
}

func succeeded(metrics map[string]*dto.MetricFamily, collector string) bool {
	values, ok := series(metrics, "node_scrape_collector_success", dto.MetricType_GAUGE, "collector")
	return ok && values[collector] == 1
}

func scalar(metrics map[string]*dto.MetricFamily, name string) (float64, bool) {
	values, ok := series(metrics, name, dto.MetricType_GAUGE)
	return values[""], ok && len(values) == 1
}

// series rejects duplicates, ambiguous labels, wrong types and explicit source
// timestamps. The selected exporter exposes current counters, not history.
func series(metrics map[string]*dto.MetricFamily, name string, kind dto.MetricType, labels ...string) (map[string]float64, bool) {
	family := metrics[name]
	if family == nil || family.GetType() != kind || len(family.Metric) == 0 {
		return nil, false
	}
	result := make(map[string]float64, len(family.Metric))
	for _, metric := range family.Metric {
		if metric == nil || metric.TimestampMs != nil || len(metric.Label) != len(labels) {
			return nil, false
		}
		parts, seen := make([]string, len(labels)), make([]bool, len(labels))
		for _, label := range metric.Label {
			index := slices.Index(labels, label.GetName())
			value := label.GetValue()
			if index < 0 || seen[index] || len(value) > 2048 || strings.ContainsRune(value, 0) {
				return nil, false
			}
			seen[index], parts[index] = true, value
		}
		key := strings.Join(parts, "\x00")
		if _, exists := result[key]; exists {
			return nil, false
		}
		var value float64
		switch kind {
		case dto.MetricType_GAUGE:
			if metric.Gauge == nil || metric.Gauge.Value == nil {
				return nil, false
			}
			value = metric.Gauge.GetValue()
		case dto.MetricType_COUNTER:
			if metric.Counter == nil || metric.Counter.Value == nil {
				return nil, false
			}
			value = metric.Counter.GetValue()
		default:
			return nil, false
		}
		if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 {
			return nil, false
		}
		result[key] = value
	}
	return result, true
}

func safeInteger(value float64) bool {
	return value >= 0 && value <= 9007199254740991 && math.Trunc(value) == value
}
