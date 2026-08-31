package compose

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

const (
	dockerEngineEndpoint             = "http://docker/v1.46"
	dockerEngineSocket               = "/var/run/docker.sock"
	maximumDockerInspectBytes        = 2 * 1024 * 1024
	maximumDockerStatsBytes          = 4 * 1024 * 1024
	maximumDockerDiskUsageBytes      = 32 * 1024 * 1024
	maximumDockerResourceConcurrency = 32
	maximumStorageCacheEntries       = 4096
	storageRefreshInterval           = 30 * time.Second
	storageValidityDuration          = 90 * time.Second
	maximumPublicMeasurementInteger  = uint64(9007199254740991)
)

var dockerContainerIDPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// RuntimeResourceObserver is an optional read-only provider capability. The
// executor invokes it only after the current sealed Compose generation and all
// container labels have been revalidated.
type RuntimeResourceObserver interface {
	ObserveResources(
		context.Context,
		RuntimeProject,
		[]RuntimeContainer,
	) (map[string]RuntimeContainerResources, error)
}

// RuntimeContainerResources is keyed internally by the provider container ID.
// The key never crosses the Compose adapter boundary; the executor replaces it
// with the deployment-scoped opaque instance identity.
type RuntimeContainerResources struct {
	CPU     paasv1.DeploymentInstanceCPUUsage
	Memory  paasv1.DeploymentInstanceMemoryUsage
	Network paasv1.DeploymentInstanceNetworkUsage
	BlockIO paasv1.DeploymentInstanceBlockIOUsage
	Storage paasv1.DeploymentInstanceStorageUsage
}

type dockerResourceCollector struct {
	engine *dockerEngineClient
	now    func() time.Time
	slots  chan struct{}

	cacheMu        sync.Mutex
	disk           *dockerDiskUsageSnapshot
	diskRefreshing bool
	containerCache map[string]dockerContainerStorageEntry
}

type dockerEngineClient struct {
	http     *http.Client
	endpoint string
}

type dockerFastSample struct {
	inspect   dockerContainerInspect
	resources RuntimeContainerResources
}

type dockerContainerStats struct {
	ID      string    `json:"id"`
	Read    time.Time `json:"read"`
	PreRead time.Time `json:"preread"`
	CPU     struct {
		Usage struct {
			Total uint64 `json:"total_usage"`
		} `json:"cpu_usage"`
		System     uint64 `json:"system_cpu_usage"`
		OnlineCPUs uint32 `json:"online_cpus"`
	} `json:"cpu_stats"`
	PreCPU struct {
		Usage struct {
			Total uint64 `json:"total_usage"`
		} `json:"cpu_usage"`
		System uint64 `json:"system_cpu_usage"`
	} `json:"precpu_stats"`
	Memory struct {
		Usage uint64            `json:"usage"`
		Limit uint64            `json:"limit"`
		Stats map[string]uint64 `json:"stats"`
	} `json:"memory_stats"`
	Networks map[string]struct {
		ReceivedBytes    uint64 `json:"rx_bytes"`
		TransmittedBytes uint64 `json:"tx_bytes"`
		ReceiveErrors    uint64 `json:"rx_errors"`
		TransmitErrors   uint64 `json:"tx_errors"`
		ReceiveDrops     uint64 `json:"rx_dropped"`
		TransmitDrops    uint64 `json:"tx_dropped"`
	} `json:"networks"`
	BlockIO struct {
		Bytes []dockerBlockIOEntry `json:"io_service_bytes_recursive"`
		Ops   []dockerBlockIOEntry `json:"io_serviced_recursive"`
	} `json:"blkio_stats"`
}

type dockerBlockIOEntry struct {
	Operation string `json:"op"`
	Value     uint64 `json:"value"`
}

type dockerContainerInspect struct {
	ID         string `json:"Id"`
	Image      string `json:"Image"`
	SizeRW     *int64 `json:"SizeRw"`
	HostConfig struct {
		NanoCPUs  int64 `json:"NanoCpus"`
		CPUPeriod int64 `json:"CpuPeriod"`
		CPUQuota  int64 `json:"CpuQuota"`
		Memory    int64 `json:"Memory"`
	} `json:"HostConfig"`
	Mounts []struct {
		Type string `json:"Type"`
		Name string `json:"Name"`
	} `json:"Mounts"`
}

type dockerDiskUsage struct {
	Images []struct {
		ID         string `json:"Id"`
		Size       int64  `json:"Size"`
		SharedSize int64  `json:"SharedSize"`
	} `json:"Images"`
	Volumes []struct {
		Name      string `json:"Name"`
		UsageData *struct {
			Size     int64 `json:"Size"`
			RefCount int64 `json:"RefCount"`
		} `json:"UsageData"`
	} `json:"Volumes"`
}

type dockerImageUsage struct {
	total  int64
	shared int64
}

type dockerVolumeUsage struct {
	bytes     int64
	reference int64
}

type dockerDiskUsageSnapshot struct {
	observedAt time.Time
	validUntil time.Time
	images     map[string]dockerImageUsage
	volumes    map[string]dockerVolumeUsage
}

type dockerContainerStorageEntry struct {
	identity    string
	refreshedAt time.Time
	value       paasv1.DeploymentInstanceStorageUsage
}

func newDockerResourceCollector() *dockerResourceCollector {
	dialer := &net.Dialer{Timeout: 2 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", dockerEngineSocket)
		},
		ForceAttemptHTTP2:     false,
		DisableCompression:    true,
		MaxIdleConns:          maximumDockerResourceConcurrency,
		MaxIdleConnsPerHost:   maximumDockerResourceConcurrency,
		MaxConnsPerHost:       maximumDockerResourceConcurrency,
		IdleConnTimeout:       30 * time.Second,
		ResponseHeaderTimeout: 2500 * time.Millisecond,
	}
	return newDockerResourceCollectorWithEngine(
		&dockerEngineClient{
			http: &http.Client{
				Transport: transport,
				Timeout:   2750 * time.Millisecond,
				CheckRedirect: func(*http.Request, []*http.Request) error {
					return errors.New("Docker Engine redirect rejected")
				},
			},
			endpoint: dockerEngineEndpoint,
		},
		time.Now,
	)
}

func newDockerResourceCollectorWithEngine(
	engine *dockerEngineClient,
	now func() time.Time,
) *dockerResourceCollector {
	return &dockerResourceCollector{
		engine:         engine,
		now:            now,
		slots:          make(chan struct{}, maximumDockerResourceConcurrency),
		containerCache: make(map[string]dockerContainerStorageEntry),
	}
}

func (runtime *LocalRuntime) ObserveResources(
	ctx context.Context,
	project RuntimeProject,
	containers []RuntimeContainer,
) (map[string]RuntimeContainerResources, error) {
	if runtime == nil || runtime.resources == nil {
		return nil, ErrRuntimeUnavailable
	}
	return runtime.resources.observe(ctx, project, containers)
}

func (collector *dockerResourceCollector) observe(
	ctx context.Context,
	project RuntimeProject,
	containers []RuntimeContainer,
) (map[string]RuntimeContainerResources, error) {
	if collector == nil || collector.engine == nil || collector.engine.http == nil ||
		collector.now == nil || ctx == nil || validateRuntimeProject(project) != nil ||
		len(containers) > paasv1.MaximumDeploymentRuntimeInstances {
		return nil, ErrRuntimeOutputInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, ErrRuntimeUnavailable
	}
	seen := make(map[string]struct{}, len(containers))
	for _, container := range containers {
		if !dockerContainerIDPattern.MatchString(container.ID) {
			return nil, ErrRuntimeOutputInvalid
		}
		if _, duplicate := seen[container.ID]; duplicate {
			return nil, ErrRuntimeOutputInvalid
		}
		seen[container.ID] = struct{}{}
	}
	samples := make([]dockerFastSample, len(containers))
	if err := collector.collectFast(ctx, containers, samples); err != nil {
		return nil, err
	}
	storage := collector.collectStorage(ctx, containers, samples)
	if ctx.Err() != nil {
		return nil, ErrRuntimeUnavailable
	}
	result := make(map[string]RuntimeContainerResources, len(containers))
	for index, container := range containers {
		sample := samples[index].resources
		sample.Storage = storage[index]
		result[container.ID] = sample
	}
	return result, nil
}

func (collector *dockerResourceCollector) collectFast(
	ctx context.Context,
	containers []RuntimeContainer,
	samples []dockerFastSample,
) error {
	work, cancel := context.WithCancel(ctx)
	defer cancel()
	var wait sync.WaitGroup
	var first error
	var firstMu sync.Mutex
	for index := range containers {
		index := index
		wait.Add(1)
		go func() {
			defer wait.Done()
			if err := collector.acquire(work); err != nil {
				setFirstError(&firstMu, &first, ErrRuntimeUnavailable, cancel)
				return
			}
			defer collector.release()
			inspect, err := collector.engine.inspect(work, containers[index].ID, false)
			if err != nil {
				setFirstError(&firstMu, &first, err, cancel)
				return
			}
			if containers[index].State != "running" &&
				containers[index].State != "restarting" &&
				containers[index].State != "paused" {
				samples[index] = dockerFastSample{
					inspect: inspect,
					resources: RuntimeContainerResources{
						CPU:     paasv1.DeploymentInstanceCPUUsage{State: paasv1.MeasurementUnavailable},
						Memory:  paasv1.DeploymentInstanceMemoryUsage{State: paasv1.MeasurementUnavailable},
						Network: paasv1.DeploymentInstanceNetworkUsage{State: paasv1.MeasurementUnavailable},
						BlockIO: paasv1.DeploymentInstanceBlockIOUsage{State: paasv1.MeasurementUnavailable},
						Storage: paasv1.DeploymentInstanceStorageUsage{State: paasv1.MeasurementUnavailable},
					},
				}
				return
			}
			stats, err := collector.engine.stats(work, containers[index].ID)
			if err != nil {
				setFirstError(&firstMu, &first, err, cancel)
				return
			}
			resources, err := normalizeDockerFastResources(containers[index].ID, inspect, stats)
			if err != nil {
				setFirstError(&firstMu, &first, ErrRuntimeOutputInvalid, cancel)
				return
			}
			samples[index] = dockerFastSample{inspect: inspect, resources: resources}
		}()
	}
	wait.Wait()
	if first != nil {
		return first
	}
	return nil
}

func setFirstError(mu *sync.Mutex, destination *error, err error, cancel context.CancelFunc) {
	mu.Lock()
	defer mu.Unlock()
	if *destination == nil {
		*destination = err
		cancel()
	}
}

func (collector *dockerResourceCollector) acquire(ctx context.Context) error {
	select {
	case collector.slots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (collector *dockerResourceCollector) release() { <-collector.slots }

func (engine *dockerEngineClient) inspect(
	ctx context.Context,
	id string,
	includeSize bool,
) (dockerContainerInspect, error) {
	var value dockerContainerInspect
	if !dockerContainerIDPattern.MatchString(id) {
		return value, ErrRuntimeOutputInvalid
	}
	query := url.Values{"size": []string{"false"}}
	if includeSize {
		query.Set("size", "true")
	}
	err := engine.getJSON(
		ctx,
		"/containers/"+url.PathEscape(id)+"/json?"+query.Encode(),
		maximumDockerInspectBytes,
		&value,
	)
	if err != nil {
		return dockerContainerInspect{}, err
	}
	if value.ID != id || value.Image == "" || len(value.Image) > 128 ||
		value.HostConfig.NanoCPUs < 0 || value.HostConfig.CPUPeriod < 0 ||
		value.HostConfig.CPUQuota < 0 || value.HostConfig.Memory < 0 {
		return dockerContainerInspect{}, ErrRuntimeOutputInvalid
	}
	return value, nil
}

func (engine *dockerEngineClient) stats(
	ctx context.Context,
	id string,
) (dockerContainerStats, error) {
	var value dockerContainerStats
	if !dockerContainerIDPattern.MatchString(id) {
		return value, ErrRuntimeOutputInvalid
	}
	query := url.Values{"stream": []string{"false"}}
	err := engine.getJSON(
		ctx,
		"/containers/"+url.PathEscape(id)+"/stats?"+query.Encode(),
		maximumDockerStatsBytes,
		&value,
	)
	if err != nil {
		return dockerContainerStats{}, err
	}
	if value.ID != id {
		return dockerContainerStats{}, ErrRuntimeOutputInvalid
	}
	return value, nil
}

func (engine *dockerEngineClient) diskUsage(ctx context.Context) (dockerDiskUsage, error) {
	var value dockerDiskUsage
	query := url.Values{"type": []string{"container", "image", "volume"}}
	if err := engine.getJSON(
		ctx,
		"/system/df?"+query.Encode(),
		maximumDockerDiskUsageBytes,
		&value,
	); err != nil {
		return dockerDiskUsage{}, err
	}
	return value, nil
}

func (engine *dockerEngineClient) getJSON(
	ctx context.Context,
	path string,
	maximum int64,
	destination any,
) error {
	if engine == nil || engine.http == nil || engine.endpoint == "" ||
		ctx == nil || !strings.HasPrefix(path, "/") || maximum <= 0 {
		return ErrRuntimeUnavailable
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, engine.endpoint+path, nil)
	if err != nil {
		return ErrRuntimeUnavailable
	}
	request.Header.Set("Accept", "application/json")
	response, err := engine.http.Do(request)
	if err != nil {
		return ErrRuntimeUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Encoding") != "" {
		return ErrRuntimeUnavailable
	}
	content, err := io.ReadAll(io.LimitReader(response.Body, maximum+1))
	if err != nil {
		return ErrRuntimeUnavailable
	}
	if int64(len(content)) > maximum {
		return ErrRuntimeOutputInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	if err := decoder.Decode(destination); err != nil {
		return ErrRuntimeOutputInvalid
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrRuntimeOutputInvalid
	}
	return nil
}

func normalizeDockerFastResources(
	id string,
	inspect dockerContainerInspect,
	stats dockerContainerStats,
) (RuntimeContainerResources, error) {
	if inspect.ID != id || stats.ID != id {
		return RuntimeContainerResources{}, ErrRuntimeOutputInvalid
	}
	cpu, err := dockerCPUUsage(inspect, stats)
	if err != nil {
		return RuntimeContainerResources{}, err
	}
	memory, err := dockerMemoryUsage(inspect, stats)
	if err != nil {
		return RuntimeContainerResources{}, err
	}
	network, err := dockerNetworkUsage(stats)
	if err != nil {
		return RuntimeContainerResources{}, err
	}
	block, err := dockerBlockIOUsage(stats)
	if err != nil {
		return RuntimeContainerResources{}, err
	}
	return RuntimeContainerResources{
		CPU: cpu, Memory: memory, Network: network, BlockIO: block,
		Storage: paasv1.DeploymentInstanceStorageUsage{State: paasv1.MeasurementUnavailable},
	}, nil
}

func dockerCPUUsage(
	inspect dockerContainerInspect,
	stats dockerContainerStats,
) (paasv1.DeploymentInstanceCPUUsage, error) {
	limit, ok := dockerCPULimitMillis(inspect)
	if !ok {
		return paasv1.DeploymentInstanceCPUUsage{State: paasv1.MeasurementUnsupported}, nil
	}
	if stats.Read.IsZero() || stats.PreRead.IsZero() || !stats.Read.After(stats.PreRead) ||
		stats.CPU.Usage.Total < stats.PreCPU.Usage.Total || stats.CPU.System <= stats.PreCPU.System ||
		stats.CPU.OnlineCPUs == 0 {
		return paasv1.DeploymentInstanceCPUUsage{State: paasv1.MeasurementWarmingUp}, nil
	}
	window := stats.Read.Sub(stats.PreRead)
	if window < time.Millisecond || window > time.Minute {
		return paasv1.DeploymentInstanceCPUUsage{State: paasv1.MeasurementWarmingUp}, nil
	}
	used := float64(stats.CPU.Usage.Total-stats.PreCPU.Usage.Total) /
		float64(stats.CPU.System-stats.PreCPU.System) * float64(stats.CPU.OnlineCPUs)
	if math.IsNaN(used) || math.IsInf(used, 0) || used < 0 || used > 4096 {
		return paasv1.DeploymentInstanceCPUUsage{}, ErrRuntimeOutputInvalid
	}
	return paasv1.DeploymentInstanceCPUUsage{
		State: paasv1.MeasurementAvailable,
		Value: &paasv1.DeploymentInstanceCPUUsageValue{
			WindowMillis: window.Milliseconds(), UsedCores: used, LimitCPUMillis: limit,
		},
	}, nil
}

func dockerCPULimitMillis(inspect dockerContainerInspect) (int64, bool) {
	var value float64
	if inspect.HostConfig.NanoCPUs > 0 {
		value = float64(inspect.HostConfig.NanoCPUs) / 1_000_000
	} else if inspect.HostConfig.CPUQuota > 0 && inspect.HostConfig.CPUPeriod > 0 {
		value = float64(inspect.HostConfig.CPUQuota) / float64(inspect.HostConfig.CPUPeriod) * 1000
	} else {
		return 0, false
	}
	limit := int64(math.Ceil(value))
	return limit, limit >= 1 && limit <= 4_096_000
}

func dockerMemoryUsage(
	inspect dockerContainerInspect,
	stats dockerContainerStats,
) (paasv1.DeploymentInstanceMemoryUsage, error) {
	if inspect.HostConfig.Memory == 0 || stats.Memory.Limit == 0 {
		return paasv1.DeploymentInstanceMemoryUsage{State: paasv1.MeasurementUnsupported}, nil
	}
	if inspect.HostConfig.Memory < 0 || uint64(inspect.HostConfig.Memory) != stats.Memory.Limit {
		return paasv1.DeploymentInstanceMemoryUsage{}, ErrRuntimeOutputInvalid
	}
	used := stats.Memory.Usage
	cache, found := stats.Memory.Stats["total_inactive_file"]
	if !found {
		cache = stats.Memory.Stats["inactive_file"]
	}
	if cache < used {
		used -= cache
	}
	usedValue, ok := publicInteger(used)
	limitValue, limitOK := publicInteger(stats.Memory.Limit)
	if !ok || !limitOK || usedValue > limitValue {
		return paasv1.DeploymentInstanceMemoryUsage{}, ErrRuntimeOutputInvalid
	}
	return paasv1.DeploymentInstanceMemoryUsage{
		State: paasv1.MeasurementAvailable,
		Value: &paasv1.DeploymentInstanceMemoryUsageValue{
			UsedBytes: usedValue, LimitBytes: limitValue,
		},
	}, nil
}

func dockerNetworkUsage(
	stats dockerContainerStats,
) (paasv1.DeploymentInstanceNetworkUsage, error) {
	if len(stats.Networks) == 0 {
		return paasv1.DeploymentInstanceNetworkUsage{State: paasv1.MeasurementUnsupported}, nil
	}
	var values [6]uint64
	for _, network := range stats.Networks {
		for index, value := range []uint64{
			network.ReceivedBytes, network.TransmittedBytes,
			network.ReceiveErrors, network.TransmitErrors,
			network.ReceiveDrops, network.TransmitDrops,
		} {
			if math.MaxUint64-values[index] < value {
				return paasv1.DeploymentInstanceNetworkUsage{}, ErrRuntimeOutputInvalid
			}
			values[index] += value
		}
	}
	converted, ok := publicIntegers(values[:]...)
	if !ok {
		return paasv1.DeploymentInstanceNetworkUsage{}, ErrRuntimeOutputInvalid
	}
	return paasv1.DeploymentInstanceNetworkUsage{
		State: paasv1.MeasurementAvailable,
		Value: &paasv1.DeploymentInstanceNetworkUsageValue{
			ReceivedBytes: converted[0], TransmittedBytes: converted[1],
			ReceiveErrors: converted[2], TransmitErrors: converted[3],
			ReceiveDrops: converted[4], TransmitDrops: converted[5],
		},
	}, nil
}

func dockerBlockIOUsage(
	stats dockerContainerStats,
) (paasv1.DeploymentInstanceBlockIOUsage, error) {
	if stats.BlockIO.Bytes == nil || stats.BlockIO.Ops == nil {
		return paasv1.DeploymentInstanceBlockIOUsage{State: paasv1.MeasurementUnsupported}, nil
	}
	bytesRead, bytesWritten, err := sumDockerBlockIO(stats.BlockIO.Bytes)
	if err != nil {
		return paasv1.DeploymentInstanceBlockIOUsage{}, err
	}
	reads, writes, err := sumDockerBlockIO(stats.BlockIO.Ops)
	if err != nil {
		return paasv1.DeploymentInstanceBlockIOUsage{}, err
	}
	converted, ok := publicIntegers(bytesRead, bytesWritten, reads, writes)
	if !ok {
		return paasv1.DeploymentInstanceBlockIOUsage{}, ErrRuntimeOutputInvalid
	}
	return paasv1.DeploymentInstanceBlockIOUsage{
		State: paasv1.MeasurementAvailable,
		Value: &paasv1.DeploymentInstanceBlockIOUsageValue{
			ReadBytes: converted[0], WriteBytes: converted[1],
			ReadOperations: converted[2], WriteOperations: converted[3],
		},
	}, nil
}

func sumDockerBlockIO(entries []dockerBlockIOEntry) (uint64, uint64, error) {
	var read uint64
	var write uint64
	for _, entry := range entries {
		var destination *uint64
		switch strings.ToLower(entry.Operation) {
		case "read":
			destination = &read
		case "write":
			destination = &write
		default:
			continue
		}
		if math.MaxUint64-*destination < entry.Value {
			return 0, 0, ErrRuntimeOutputInvalid
		}
		*destination += entry.Value
	}
	return read, write, nil
}

func publicInteger(value uint64) (int64, bool) {
	if value > maximumPublicMeasurementInteger {
		return 0, false
	}
	return int64(value), true
}

func publicIntegers(values ...uint64) ([]int64, bool) {
	result := make([]int64, len(values))
	for index, value := range values {
		converted, ok := publicInteger(value)
		if !ok {
			return nil, false
		}
		result[index] = converted
	}
	return result, true
}

func (collector *dockerResourceCollector) collectStorage(
	ctx context.Context,
	containers []RuntimeContainer,
	samples []dockerFastSample,
) []paasv1.DeploymentInstanceStorageUsage {
	now := collector.now().UTC().Truncate(time.Microsecond)
	disk := collector.currentDiskUsage(ctx, now)
	result := make([]paasv1.DeploymentInstanceStorageUsage, len(containers))
	type pendingStorage struct {
		index    int
		identity string
		previous dockerContainerStorageEntry
		hasOld   bool
	}
	pending := make([]pendingStorage, 0, len(containers))
	for index, container := range containers {
		identity := dockerStorageIdentity(samples[index].inspect)
		entry, found := collector.cachedStorage(container.ID, identity)
		if found && now.Sub(entry.refreshedAt) < storageRefreshInterval {
			result[index] = projectStorage(entry.value, now)
			continue
		}
		if disk == nil || !now.Before(disk.validUntil) {
			if found {
				result[index] = projectStorage(entry.value, now)
			} else {
				result[index] = paasv1.DeploymentInstanceStorageUsage{State: paasv1.MeasurementUnavailable}
			}
			continue
		}
		pending = append(pending, pendingStorage{
			index: index, identity: identity, previous: entry, hasOld: found,
		})
	}
	var wait sync.WaitGroup
	for position := range pending {
		position := position
		wait.Add(1)
		go func() {
			defer wait.Done()
			item := pending[position]
			if collector.acquire(ctx) != nil {
				if item.hasOld {
					result[item.index] = projectStorage(item.previous.value, now)
				} else {
					result[item.index] = paasv1.DeploymentInstanceStorageUsage{State: paasv1.MeasurementUnavailable}
				}
				return
			}
			defer collector.release()
			inspect, err := collector.engine.inspect(ctx, containers[item.index].ID, true)
			if err != nil || dockerStorageIdentity(inspect) != item.identity {
				if item.hasOld {
					result[item.index] = projectStorage(item.previous.value, now)
				} else {
					result[item.index] = paasv1.DeploymentInstanceStorageUsage{State: paasv1.MeasurementUnavailable}
				}
				return
			}
			value := dockerStorageUsage(inspect, disk, now)
			entry := dockerContainerStorageEntry{
				identity: item.identity, refreshedAt: now, value: value,
			}
			collector.storeStorage(containers[item.index].ID, entry)
			result[item.index] = value
		}()
	}
	wait.Wait()
	return result
}

func (collector *dockerResourceCollector) currentDiskUsage(
	ctx context.Context,
	now time.Time,
) *dockerDiskUsageSnapshot {
	collector.cacheMu.Lock()
	current := collector.disk
	if current != nil && now.Sub(current.observedAt) < storageRefreshInterval {
		collector.cacheMu.Unlock()
		return current
	}
	if collector.diskRefreshing {
		collector.cacheMu.Unlock()
		return current
	}
	collector.diskRefreshing = true
	collector.cacheMu.Unlock()

	value, err := collector.engine.diskUsage(ctx)
	var next *dockerDiskUsageSnapshot
	if err == nil {
		next = normalizeDockerDiskUsage(value, now)
	}
	collector.cacheMu.Lock()
	collector.diskRefreshing = false
	if next != nil {
		collector.disk = next
		current = next
	} else {
		current = collector.disk
	}
	collector.cacheMu.Unlock()
	return current
}

func normalizeDockerDiskUsage(
	value dockerDiskUsage,
	now time.Time,
) *dockerDiskUsageSnapshot {
	result := &dockerDiskUsageSnapshot{
		observedAt: now,
		validUntil: now.Add(storageValidityDuration),
		images:     make(map[string]dockerImageUsage, len(value.Images)),
		volumes:    make(map[string]dockerVolumeUsage, len(value.Volumes)),
	}
	for _, image := range value.Images {
		if image.ID == "" || len(image.ID) > 128 || image.Size < 0 || image.SharedSize < 0 ||
			image.SharedSize > image.Size || !publicSignedInteger(image.Size) ||
			!publicSignedInteger(image.SharedSize) {
			return nil
		}
		if _, duplicate := result.images[image.ID]; duplicate {
			return nil
		}
		result.images[image.ID] = dockerImageUsage{total: image.Size, shared: image.SharedSize}
	}
	for _, volume := range value.Volumes {
		if volume.Name == "" || len(volume.Name) > 255 || volume.UsageData == nil ||
			volume.UsageData.Size < 0 || volume.UsageData.RefCount < 0 ||
			!publicSignedInteger(volume.UsageData.Size) {
			return nil
		}
		if _, duplicate := result.volumes[volume.Name]; duplicate {
			return nil
		}
		result.volumes[volume.Name] = dockerVolumeUsage{
			bytes: volume.UsageData.Size, reference: volume.UsageData.RefCount,
		}
	}
	return result
}

func dockerStorageIdentity(value dockerContainerInspect) string {
	volumes := make([]string, 0, len(value.Mounts))
	seen := make(map[string]struct{}, len(value.Mounts))
	for _, mount := range value.Mounts {
		if mount.Type == "volume" {
			if _, duplicate := seen[mount.Name]; duplicate {
				continue
			}
			seen[mount.Name] = struct{}{}
			volumes = append(volumes, mount.Name)
		}
	}
	slices.Sort(volumes)
	return value.Image + "\x00" + strings.Join(volumes, "\x00")
}

func dockerStorageUsage(
	inspect dockerContainerInspect,
	disk *dockerDiskUsageSnapshot,
	_ time.Time,
) paasv1.DeploymentInstanceStorageUsage {
	image, found := disk.images[inspect.Image]
	if inspect.SizeRW == nil || *inspect.SizeRW < 0 || !found ||
		!publicSignedInteger(*inspect.SizeRW) || !publicSignedInteger(image.total) ||
		!publicSignedInteger(image.shared) {
		return paasv1.DeploymentInstanceStorageUsage{State: paasv1.MeasurementUnsupported}
	}
	volumes := paasv1.DeploymentInstanceVolumeUsage{}
	seenVolumes := make(map[string]struct{}, len(inspect.Mounts))
	for _, mount := range inspect.Mounts {
		if mount.Type != "volume" {
			continue
		}
		if _, duplicate := seenVolumes[mount.Name]; duplicate {
			continue
		}
		seenVolumes[mount.Name] = struct{}{}
		usage, found := disk.volumes[mount.Name]
		if mount.Name == "" || !found || !publicSignedInteger(usage.bytes) ||
			volumes.Count == math.MaxUint32 || volumes.SharedCount == math.MaxUint32 ||
			volumes.Bytes > int64(maximumPublicMeasurementInteger)-usage.bytes {
			return paasv1.DeploymentInstanceStorageUsage{State: paasv1.MeasurementUnsupported}
		}
		volumes.Count++
		volumes.Bytes += usage.bytes
		if usage.reference > 1 {
			if volumes.SharedBytes > int64(maximumPublicMeasurementInteger)-usage.bytes {
				return paasv1.DeploymentInstanceStorageUsage{State: paasv1.MeasurementUnsupported}
			}
			volumes.SharedCount++
			volumes.SharedBytes += usage.bytes
		}
	}
	return paasv1.DeploymentInstanceStorageUsage{
		State: paasv1.MeasurementAvailable,
		Value: &paasv1.DeploymentInstanceStorageUsageValue{
			ObservedAt: disk.observedAt, ValidUntil: disk.validUntil,
			WritableLayerBytes: *inspect.SizeRW,
			ImageTotalBytes:    image.total, ImageSharedBytes: image.shared,
			ImageUniqueBytes: image.total - image.shared,
			VolumesState:     paasv1.MeasurementAvailable,
			Volumes:          &volumes,
		},
	}
}

func publicSignedInteger(value int64) bool {
	return value >= 0 && uint64(value) <= maximumPublicMeasurementInteger
}

func projectStorage(
	value paasv1.DeploymentInstanceStorageUsage,
	now time.Time,
) paasv1.DeploymentInstanceStorageUsage {
	if value.Value == nil {
		return value
	}
	copy := *value.Value
	if copy.Volumes != nil {
		volumes := *copy.Volumes
		copy.Volumes = &volumes
	}
	if now.Before(copy.ObservedAt) || !now.Before(copy.ValidUntil) {
		value.State = paasv1.MeasurementStale
	}
	value.Value = &copy
	return value
}

func (collector *dockerResourceCollector) cachedStorage(
	id string,
	identity string,
) (dockerContainerStorageEntry, bool) {
	collector.cacheMu.Lock()
	defer collector.cacheMu.Unlock()
	value, found := collector.containerCache[id]
	if !found || value.identity != identity {
		return dockerContainerStorageEntry{}, false
	}
	return value, true
}

func (collector *dockerResourceCollector) storeStorage(
	id string,
	value dockerContainerStorageEntry,
) {
	collector.cacheMu.Lock()
	defer collector.cacheMu.Unlock()
	if _, found := collector.containerCache[id]; !found &&
		len(collector.containerCache) >= maximumStorageCacheEntries {
		clear(collector.containerCache)
	}
	collector.containerCache[id] = value
}
