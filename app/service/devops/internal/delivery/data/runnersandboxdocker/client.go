package runnersandboxdocker

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
)

const (
	engineOrigin        = "http://matrix-docker-engine"
	maximumRequestBytes = 128 * 1024
	maximumVersionBytes = 64 * 1024
	maximumInfoBytes    = 1024 * 1024
	maximumInspectBytes = 1024 * 1024
	maximumWaitBytes    = 64 * 1024
)

type Client struct {
	httpClient  *http.Client
	storageRoot string
	storageFree func(string) (uint64, error)
}

func New(socketPath, storageRoot string) (*Client, error) {
	if !validUnixAbsolutePath(socketPath, false) || !validUnixAbsolutePath(storageRoot, false) {
		return nil, ErrInvalid
	}
	httpClient, err := newEngineHTTPClient(socketPath)
	if err != nil {
		return nil, err
	}
	return newClient(httpClient, storageRoot, freeStorageBytes)
}

func newClient(
	httpClient *http.Client,
	storageRoot string,
	storageFree func(string) (uint64, error),
) (*Client, error) {
	if httpClient == nil || httpClient.Transport == nil ||
		!validUnixAbsolutePath(storageRoot, false) || storageFree == nil {
		return nil, ErrInvalid
	}
	return &Client{
		httpClient: httpClient, storageRoot: storageRoot, storageFree: storageFree,
	}, nil
}

func (client *Client) Preflight(ctx context.Context) (Report, error) {
	if client == nil || client.httpClient == nil || client.storageFree == nil || ctx == nil {
		return Report{}, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return Report{}, err
	}
	var version daemonVersion
	if err := client.getJSON(
		ctx, versionPath(), maximumVersionBytes, &version,
	); err != nil {
		return Report{}, err
	}
	report := Report{
		DockerVersion:    version.Version,
		EngineAPIVersion: version.APIVersion,
	}
	if !docker29(version.Version) {
		return ineligible(report, ReasonDockerRelease)
	}
	if !supportsEngineAPI(version.MinAPIVersion, version.APIVersion, EngineAPIVersion) {
		return ineligible(report, ReasonEngineAPI)
	}
	if version.OS != "linux" || version.Arch != "amd64" {
		return ineligible(report, ReasonHostPlatform)
	}

	var info daemonInfo
	if err := client.getJSON(ctx, infoPath(), maximumInfoBytes, &info); err != nil {
		return Report{}, err
	}
	report.LogicalCPUs = info.NCPU
	report.MemoryBytes = info.MemTotal
	if info.OSType != "linux" || (info.Architecture != "x86_64" && info.Architecture != "amd64") {
		return ineligible(report, ReasonHostPlatform)
	}
	if _, found := info.Runtimes[RuntimeName]; !found {
		return ineligible(report, ReasonRuntime)
	}
	if info.NCPU < minimumLogicalCPUs || info.MemTotal < minimumMemoryBytes ||
		!info.MemoryLimit || !info.SwapLimit || !info.CPUCFSQuota || !info.PidsLimit {
		return ineligible(report, ReasonResources)
	}

	var image imageInspection
	if err := client.getJSON(
		ctx, imagePath(ToolchainImage), maximumInspectBytes, &image,
	); err != nil {
		return Report{}, err
	}
	report.ImageID = image.ID
	if !validToolchainImage(image) {
		return ineligible(report, ReasonToolchain)
	}

	free, err := client.storageFree(client.storageRoot)
	if err != nil {
		return Report{}, errors.Join(ErrUnavailable, err)
	}
	report.StorageFreeBytes = free
	if free < minimumStorageBytes {
		return ineligible(report, ReasonStorage)
	}

	if err := client.runIsolationProbe(ctx); err != nil {
		if errors.Is(err, ErrIneligible) {
			return ineligible(report, ReasonIsolation)
		}
		return Report{}, err
	}
	report.Eligible = true
	return report, nil
}

func ineligible(report Report, reason Reason) (Report, error) {
	report.Eligible = false
	report.Reason = reason
	return report, ErrIneligible
}

func (client *Client) runIsolationProbe(ctx context.Context) (result error) {
	name, err := randomProbeName()
	if err != nil {
		return errors.Join(ErrUnavailable, err)
	}
	plan, err := newProbePlan(name)
	if err != nil {
		return err
	}
	content, err := plan.MarshalJSON()
	if err != nil {
		return err
	}
	var created createResponse
	if err := client.sendJSON(
		ctx,
		http.MethodPost,
		createPath(name),
		content,
		http.StatusCreated,
		maximumVersionBytes,
		&created,
	); err != nil {
		cleanupErr := client.deleteProbe(context.WithoutCancel(ctx), name)
		return errors.Join(err, cleanupErr)
	}
	if !validContainerID(created.ID) || len(created.Warnings) != 0 {
		if cleanupErr := client.deleteProbe(context.WithoutCancel(ctx), name); cleanupErr != nil {
			return errors.Join(ErrUnavailable, cleanupErr)
		}
		return ErrIneligible
	}
	defer func() {
		cleanupErr := client.deleteContainer(context.WithoutCancel(ctx), created.ID)
		if cleanupErr != nil {
			result = errors.Join(ErrUnavailable, result, cleanupErr)
		}
	}()
	if err := client.sendEmpty(
		ctx, http.MethodPost, startPath(created.ID), http.StatusNoContent,
	); err != nil {
		return err
	}
	var waited waitResponse
	if err := client.sendJSON(
		ctx,
		http.MethodPost,
		waitPath(created.ID),
		nil,
		http.StatusOK,
		maximumWaitBytes,
		&waited,
	); err != nil {
		return err
	}
	if waited.StatusCode != 0 || (waited.Error != nil && waited.Error.Message != "") {
		return ErrIneligible
	}
	var inspected containerInspection
	if err := client.getJSON(
		ctx, containerInspectPath(created.ID), maximumInspectBytes, &inspected,
	); err != nil {
		return err
	}
	if !validProbeInspection(inspected, created.ID, plan.request) {
		return ErrIneligible
	}
	return nil
}

func (client *Client) deleteContainer(ctx context.Context, containerID string) error {
	if !validContainerID(containerID) {
		return ErrInvalid
	}
	return client.sendEmpty(
		ctx, http.MethodDelete, deletePath(containerID), http.StatusNoContent,
	)
}

func (client *Client) deleteProbe(ctx context.Context, name string) error {
	if !validProbeName(name) {
		return ErrInvalid
	}
	return client.sendEmpty(
		ctx, http.MethodDelete, deletePath(name), http.StatusNoContent,
	)
}

func (client *Client) getJSON(
	ctx context.Context,
	target string,
	maximum int64,
	destination any,
) error {
	return client.sendJSON(
		ctx, http.MethodGet, target, nil, http.StatusOK, maximum, destination,
	)
}

func (client *Client) sendJSON(
	ctx context.Context,
	method string,
	target string,
	content []byte,
	expectedStatus int,
	maximum int64,
	destination any,
) error {
	if client == nil || client.httpClient == nil || ctx == nil || destination == nil ||
		maximum <= 0 || maximum > maximumInfoBytes ||
		(method != http.MethodGet && method != http.MethodPost) ||
		(len(content) > 0 && method != http.MethodPost) || len(content) > maximumRequestBytes {
		return ErrInvalid
	}
	request, err := newRequest(ctx, method, target, content)
	if err != nil {
		return err
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return ErrUnavailable
	}
	if response == nil || response.Body == nil || response.StatusCode != expectedStatus ||
		response.Header.Get("Content-Encoding") != "" ||
		len(response.Header.Values("Content-Encoding")) > 1 ||
		len(response.Header.Values("Content-Type")) != 1 {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return ErrUnavailable
	}
	mediaType, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if mediaErr != nil || mediaType != "application/json" ||
		response.ContentLength == 0 || response.ContentLength > maximum {
		_ = response.Body.Close()
		return ErrUnavailable
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, maximum+1))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || len(body) == 0 || int64(len(body)) > maximum ||
		(response.ContentLength >= 0 && int64(len(body)) != response.ContentLength) {
		return errors.Join(ErrUnavailable, readErr, closeErr)
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(destination); err != nil {
		return ErrUnavailable
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrUnavailable
	}
	return nil
}

func (client *Client) sendEmpty(
	ctx context.Context,
	method string,
	target string,
	expectedStatus int,
) error {
	if client == nil || client.httpClient == nil || ctx == nil ||
		(method != http.MethodPost && method != http.MethodDelete) {
		return ErrInvalid
	}
	request, err := newRequest(ctx, method, target, nil)
	if err != nil {
		return err
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return ErrUnavailable
	}
	if response == nil || response.Body == nil || response.StatusCode != expectedStatus ||
		response.Header.Get("Content-Encoding") != "" ||
		len(response.Header.Values("Content-Encoding")) > 1 ||
		(response.ContentLength != 0 && response.ContentLength != -1) {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return ErrUnavailable
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 1))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || len(body) != 0 {
		return errors.Join(ErrUnavailable, readErr, closeErr)
	}
	return nil
}

func newRequest(
	ctx context.Context,
	method string,
	target string,
	content []byte,
) (*http.Request, error) {
	if ctx == nil || !strings.HasPrefix(target, "/"+EngineAPIVersionPath()+"/") {
		return nil, ErrInvalid
	}
	request, err := http.NewRequestWithContext(
		ctx, method, engineOrigin+target, bytes.NewReader(content),
	)
	if err != nil {
		return nil, ErrInvalid
	}
	request.ContentLength = int64(len(content))
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "matrix-devops-runner/v1")
	if len(content) > 0 {
		request.Header.Set("Content-Type", "application/json")
	}
	return request, nil
}

type daemonVersion struct {
	Version       string `json:"Version"`
	APIVersion    string `json:"ApiVersion"`
	MinAPIVersion string `json:"MinAPIVersion"`
	OS            string `json:"Os"`
	Arch          string `json:"Arch"`
}

type daemonInfo struct {
	NCPU         int                        `json:"NCPU"`
	MemTotal     int64                      `json:"MemTotal"`
	MemoryLimit  bool                       `json:"MemoryLimit"`
	SwapLimit    bool                       `json:"SwapLimit"`
	CPUCFSQuota  bool                       `json:"CpuCfsQuota"`
	PidsLimit    bool                       `json:"PidsLimit"`
	OSType       string                     `json:"OSType"`
	Architecture string                     `json:"Architecture"`
	Runtimes     map[string]json.RawMessage `json:"Runtimes"`
}

type imageInspection struct {
	ID           string   `json:"Id"`
	RepoDigests  []string `json:"RepoDigests"`
	OS           string   `json:"Os"`
	Architecture string   `json:"Architecture"`
}

type createResponse struct {
	ID       string   `json:"Id"`
	Warnings []string `json:"Warnings"`
}

type waitResponse struct {
	StatusCode int64      `json:"StatusCode"`
	Error      *waitError `json:"Error"`
}

type waitError struct {
	Message string `json:"Message"`
}

type containerInspection struct {
	ID     string `json:"Id"`
	Image  string `json:"Image"`
	Config struct {
		Image           string            `json:"Image"`
		Cmd             []string          `json:"Cmd"`
		Entrypoint      []string          `json:"Entrypoint"`
		Env             []string          `json:"Env"`
		User            string            `json:"User"`
		WorkingDir      string            `json:"WorkingDir"`
		NetworkDisabled bool              `json:"NetworkDisabled"`
		AttachStdin     bool              `json:"AttachStdin"`
		AttachStdout    bool              `json:"AttachStdout"`
		AttachStderr    bool              `json:"AttachStderr"`
		OpenStdin       bool              `json:"OpenStdin"`
		StdinOnce       bool              `json:"StdinOnce"`
		Tty             bool              `json:"Tty"`
		Labels          map[string]string `json:"Labels"`
	} `json:"Config"`
	HostConfig hostConfig `json:"HostConfig"`
	State      struct {
		Status   string `json:"Status"`
		Running  bool   `json:"Running"`
		Paused   bool   `json:"Paused"`
		Dead     bool   `json:"Dead"`
		ExitCode int64  `json:"ExitCode"`
	} `json:"State"`
	NetworkSettings struct {
		Networks map[string]json.RawMessage `json:"Networks"`
	} `json:"NetworkSettings"`
}

func validToolchainImage(value imageInspection) bool {
	if value.ID != devopsv1.Go126OfflineToolchainImageDigest ||
		value.OS != "linux" || value.Architecture != "amd64" {
		return false
	}
	wantSuffix := "@" + devopsv1.Go126OfflineToolchainImageDigest
	for _, digest := range value.RepoDigests {
		if strings.HasSuffix(digest, wantSuffix) {
			return true
		}
	}
	return false
}

func validProbeInspection(
	value containerInspection,
	containerID string,
	want containerCreateRequest,
) bool {
	config := value.Config
	if value.ID != containerID || value.Image != devopsv1.Go126OfflineToolchainImageDigest ||
		config.Image != want.Image || !equalStrings(config.Cmd, want.Cmd) ||
		len(config.Entrypoint) != 0 || !equalEnvironment(config.Env, want.Env) ||
		config.User != want.User || config.WorkingDir != want.WorkingDir ||
		!config.NetworkDisabled || config.AttachStdin || !config.AttachStdout ||
		!config.AttachStderr || config.OpenStdin || config.StdinOnce || config.Tty ||
		!equalStringMap(config.Labels, want.Labels) ||
		value.State.Status != "exited" || value.State.Running || value.State.Paused ||
		value.State.Dead || value.State.ExitCode != 0 ||
		!validInspectedHostConfig(value.HostConfig, want.HostConfig) ||
		!validNoneNetworks(value.NetworkSettings.Networks) {
		return false
	}
	return true
}

func validInspectedHostConfig(value, want hostConfig) bool {
	return !value.AutoRemove && len(value.Binds) == 0 && len(value.CapAdd) == 0 &&
		equalStrings(value.CapDrop, want.CapDrop) && value.CgroupnsMode == want.CgroupnsMode &&
		value.ContainerIDFile == "" && len(value.Devices) == 0 && len(value.DeviceRequests) == 0 &&
		len(value.DNS) == 0 && len(value.DNSOptions) == 0 && len(value.DNSSearch) == 0 &&
		len(value.ExtraHosts) == 0 && len(value.GroupAdd) == 0 && value.IpcMode == want.IpcMode &&
		len(value.Links) == 0 && value.LogConfig.Type == want.LogConfig.Type &&
		len(value.LogConfig.Config) == 0 && value.Memory == want.Memory &&
		value.MemorySwap == want.MemorySwap && len(value.Mounts) == 0 &&
		value.NanoCPUs == want.NanoCPUs && value.NetworkMode == want.NetworkMode &&
		value.PidMode == "" && value.PidsLimit != nil && want.PidsLimit != nil &&
		*value.PidsLimit == *want.PidsLimit && len(value.PortBindings) == 0 &&
		!value.Privileged && !value.PublishAllPorts && value.ReadonlyRootfs &&
		value.RestartPolicy.Name == want.RestartPolicy.Name &&
		value.RestartPolicy.MaximumRetryCount == 0 && value.Runtime == want.Runtime &&
		equalStrings(value.SecurityOpt, want.SecurityOpt) && value.ShmSize == want.ShmSize &&
		len(value.StorageOpt) == 0 && len(value.Sysctls) == 0 && equalStringMap(value.Tmpfs, want.Tmpfs) &&
		len(value.Ulimits) == 0 && value.UTSMode == "" && len(value.VolumesFrom) == 0
}

func equalEnvironment(left, right []string) bool {
	leftValues, leftOK := environmentMap(left)
	rightValues, rightOK := environmentMap(right)
	return leftOK && rightOK && equalStringMap(leftValues, rightValues)
}

func environmentMap(values []string) (map[string]string, bool) {
	result := make(map[string]string, len(values))
	for _, value := range values {
		name, content, found := strings.Cut(value, "=")
		if !found || name == "" {
			return nil, false
		}
		if _, duplicate := result[name]; duplicate {
			return nil, false
		}
		result[name] = content
	}
	return result, true
}

func equalStringMap(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}

func validNoneNetworks(value map[string]json.RawMessage) bool {
	if len(value) == 0 {
		return true
	}
	_, found := value["none"]
	return found && len(value) == 1
}

func docker29(value string) bool {
	core := value
	if index := strings.IndexAny(core, "-+"); index >= 0 {
		if index == len(core)-1 {
			return false
		}
		for _, character := range core[index+1:] {
			if (character < '0' || character > '9') &&
				(character < 'a' || character > 'z') &&
				(character < 'A' || character > 'Z') &&
				character != '.' && character != '-' {
				return false
			}
		}
		core = core[:index]
	}
	parts := strings.Split(core, ".")
	if len(parts) != 3 || parts[0] != "29" {
		return false
	}
	for _, part := range parts {
		if part == "" || (len(part) > 1 && part[0] == '0') {
			return false
		}
		if _, err := strconv.ParseUint(part, 10, 32); err != nil {
			return false
		}
	}
	return true
}

func supportsEngineAPI(minimum, maximum, selected string) bool {
	minimumMajor, minimumMinor, minimumOK := apiVersion(minimum)
	maximumMajor, maximumMinor, maximumOK := apiVersion(maximum)
	selectedMajor, selectedMinor, selectedOK := apiVersion(selected)
	if !minimumOK || !maximumOK || !selectedOK {
		return false
	}
	selectedValue := selectedMajor*1_000 + selectedMinor
	return selectedValue >= minimumMajor*1_000+minimumMinor &&
		selectedValue <= maximumMajor*1_000+maximumMinor
}

func apiVersion(value string) (int, int, bool) {
	majorText, minorText, found := strings.Cut(value, ".")
	if !found || majorText == "" || minorText == "" || strings.Contains(minorText, ".") ||
		(len(majorText) > 1 && majorText[0] == '0') ||
		(len(minorText) > 1 && minorText[0] == '0') {
		return 0, 0, false
	}
	major, majorErr := strconv.Atoi(majorText)
	minor, minorErr := strconv.Atoi(minorText)
	return major, minor, majorErr == nil && minorErr == nil && major >= 0 && minor >= 0
}

func randomProbeName() (string, error) {
	value := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, value); err != nil {
		return "", err
	}
	return "matrix-runner-isolation-probe-" + hex.EncodeToString(value), nil
}

func validContainerID(value string) bool {
	return len(value) == 64 && lowerHex(value)
}

func validUnixAbsolutePath(value string, allowRoot bool) bool {
	return len(value) > 1 && len(value) <= 512 && strings.HasPrefix(value, "/") &&
		(allowRoot || value != "/") && path.Clean(value) == value &&
		!strings.ContainsAny(value, "\x00\r\n")
}

func EngineAPIVersionPath() string {
	return "v" + EngineAPIVersion
}

func versionPath() string {
	return "/" + EngineAPIVersionPath() + "/version"
}

func infoPath() string {
	return "/" + EngineAPIVersionPath() + "/info"
}

func imagePath(reference string) string {
	return "/" + EngineAPIVersionPath() + "/images/" + url.PathEscape(reference) + "/json"
}

func createPath(name string) string {
	return "/" + EngineAPIVersionPath() + "/containers/create?name=" + url.QueryEscape(name)
}

func startPath(containerID string) string {
	return "/" + EngineAPIVersionPath() + "/containers/" + containerID + "/start"
}

func waitPath(containerID string) string {
	return "/" + EngineAPIVersionPath() + "/containers/" + containerID +
		"/wait?condition=not-running"
}

func containerInspectPath(containerID string) string {
	return "/" + EngineAPIVersionPath() + "/containers/" + containerID + "/json?size=false"
}

func deletePath(reference string) string {
	return "/" + EngineAPIVersionPath() + "/containers/" + reference +
		"?force=true&v=true"
}
