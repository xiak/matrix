package releasee2e

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/xiak/matrix/app/service/installation/internal/journal"
	"github.com/xiak/matrix/app/service/installation/internal/lifecycle"
	"github.com/xiak/matrix/app/service/installation/release"
	"github.com/xiak/matrix/app/service/installation/topology"
)

const maximumCommandOutput = 1024 * 1024

type commandOutput struct {
	stdout []byte
	stderr []byte
	exit   int
}

type boundedBuffer struct {
	content   bytes.Buffer
	remaining int
	overflow  bool
}

func newBoundedBuffer(maximum int) *boundedBuffer {
	return &boundedBuffer{remaining: maximum}
}

func (value *boundedBuffer) Write(content []byte) (int, error) {
	original := len(content)
	if original > value.remaining {
		content = content[:value.remaining]
		value.overflow = true
	}
	written, err := value.content.Write(content)
	value.remaining -= written
	if err != nil {
		return written, err
	}
	return original, nil
}

func runProcess(ctx context.Context, executable string, arguments ...string) (commandOutput, error) {
	return runProcessInput(ctx, nil, executable, arguments...)
}

func runProcessInput(ctx context.Context, input io.Reader, executable string, arguments ...string) (commandOutput, error) {
	stdout := newBoundedBuffer(maximumCommandOutput)
	stderr := newBoundedBuffer(maximumCommandOutput)
	command := exec.CommandContext(ctx, executable, arguments...)
	command.Stdin = input
	command.Stdout = stdout
	command.Stderr = stderr
	err := command.Run()
	result := commandOutput{
		stdout: append([]byte(nil), stdout.content.Bytes()...),
		stderr: append([]byte(nil), stderr.content.Bytes()...),
	}
	if stdout.overflow || stderr.overflow {
		return commandOutput{}, errors.New("command output exceeded acceptance bound")
	}
	if err == nil {
		return result, nil
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		result.exit = exit.ExitCode()
		return result, nil
	}
	return commandOutput{}, err
}

type mxEnvelope struct {
	APIVersion string   `json:"apiVersion"`
	Kind       string   `json:"kind"`
	Action     string   `json:"action"`
	Status     string   `json:"status"`
	Result     mxResult `json:"result"`
}

type mxResult struct {
	State         string `json:"state"`
	ReleaseID     string `json:"releaseId,omitempty"`
	PreviousID    string `json:"previousId,omitempty"`
	BackupID      string `json:"backupId,omitempty"`
	Changed       bool   `json:"changed"`
	CorrelationID string `json:"correlationId,omitempty"`
}

type mxFailure struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Action     string `json:"action"`
	Status     string `json:"status"`
	Error      struct {
		Class   string `json:"class"`
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func mxPath(bundle release.VerifiedBundle) string {
	return filepath.Join(bundle.Root, filepath.FromSlash("bin/mx"))
}

func runMX(
	ctx context.Context,
	bundle release.VerifiedBundle,
	action string,
	arguments []string,
	forbidden [][]byte,
) (mxResult, error) {
	args := []string{"--format", "json", "platform", action}
	args = append(args, arguments...)
	output, err := runProcess(ctx, mxPath(bundle), args...)
	if err != nil || output.exit != 0 || containsAny(output.stdout, forbidden) ||
		containsAny(output.stderr, forbidden) || len(output.stderr) != 0 {
		return mxResult{}, fail("mx-" + action)
	}
	var envelope mxEnvelope
	if decodeOne(output.stdout, &envelope) != nil ||
		envelope.APIVersion != "cli.matrix.xiak.com/v1" ||
		envelope.Kind != "PlatformCommandResult" || envelope.Action != strings.ToUpper(action) ||
		envelope.Status != "SUCCEEDED" || envelope.Result.State != "READY" {
		return mxResult{}, fail("mx-" + action + "-result")
	}
	return envelope.Result, nil
}

func startMX(
	ctx context.Context,
	bundle release.VerifiedBundle,
	action string,
	arguments []string,
) (*exec.Cmd, *boundedBuffer, *boundedBuffer, error) {
	args := []string{"--format", "json", "platform", action}
	args = append(args, arguments...)
	stdout := newBoundedBuffer(maximumCommandOutput)
	stderr := newBoundedBuffer(maximumCommandOutput)
	command := exec.CommandContext(ctx, mxPath(bundle), args...)
	command.Stdin = nil
	command.Stdout = stdout
	command.Stderr = stderr
	if err := command.Start(); err != nil {
		return nil, nil, nil, err
	}
	return command, stdout, stderr, nil
}

func validateExpectedMXFailure(
	waitErr error,
	stdout, stderr *boundedBuffer,
	action string,
	forbidden [][]byte,
) error {
	var exit *exec.ExitError
	if !errors.As(waitErr, &exit) || exit.ExitCode() != 5 || stdout.overflow || stderr.overflow ||
		stdout.content.Len() != 0 || containsAny(stderr.content.Bytes(), forbidden) {
		return fail("failed-" + action + "-exit")
	}
	var envelope mxFailure
	if decodeOne(stderr.content.Bytes(), &envelope) != nil ||
		envelope.APIVersion != "cli.matrix.xiak.com/v1" ||
		envelope.Kind != "PlatformCommandFailure" || envelope.Action != strings.ToUpper(action) ||
		envelope.Status != "FAILED" || envelope.Error.Class != "VERIFICATION_FAILED" ||
		envelope.Error.Code == "" || strings.Contains(strings.ToLower(envelope.Error.Message), "docker") ||
		strings.Contains(strings.ToLower(envelope.Error.Message), "postgres") {
		return fail("failed-" + action + "-result")
	}
	return nil
}

func decodeOne(content []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func containsAny(content []byte, values [][]byte) bool {
	for _, value := range values {
		if len(value) != 0 && bytes.Contains(content, value) {
			return true
		}
	}
	return false
}

func docker(ctx context.Context, arguments ...string) ([]byte, error) {
	output, err := runProcess(ctx, "docker", arguments...)
	if err != nil || output.exit != 0 || len(output.stderr) != 0 {
		return nil, errors.New("Docker acceptance command failed")
	}
	return output.stdout, nil
}

func dockerLines(ctx context.Context, arguments ...string) ([]string, error) {
	content, err := docker(ctx, arguments...)
	if err != nil {
		return nil, err
	}
	trimmed := strings.TrimSpace(string(content))
	if trimmed == "" {
		return nil, nil
	}
	lines := strings.Split(trimmed, "\n")
	for index := range lines {
		lines[index] = strings.TrimSpace(lines[index])
		if lines[index] == "" || strings.ContainsAny(lines[index], "\r\t ") {
			return nil, errors.New("Docker returned an invalid identity list")
		}
	}
	return lines, nil
}

func readJournal(ctx context.Context, root string) (lifecycle.Journal, error) {
	session, err := journal.AcquireExisting(ctx, root)
	if err != nil {
		return lifecycle.Journal{}, err
	}
	value, readErr := session.Read()
	closeErr := session.Close()
	if readErr != nil {
		return lifecycle.Journal{}, readErr
	}
	if closeErr != nil {
		return lifecycle.Journal{}, closeErr
	}
	return value, nil
}

func assertNoExternalRoute() error {
	content, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return fail("external-network-route")
	}
	for index, line := range strings.Split(string(content), "\n") {
		if index == 0 || strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 4 && fields[1] == "00000000" {
			flags, parseErr := strconv.ParseUint(fields[3], 16, 32)
			if parseErr == nil && flags&1 != 0 {
				return fail("external-network-route")
			}
		}
	}
	connection, dialErr := net.DialTimeout("tcp", "1.1.1.1:443", 300*time.Millisecond)
	if connection != nil {
		_ = connection.Close()
	}
	if dialErr == nil {
		return fail("external-network-connectivity")
	}
	return nil
}

func assertEmptyDocker(ctx context.Context) error {
	checks := [][]string{
		{"container", "ls", "--all", "--quiet"},
		{"image", "ls", "--all", "--quiet"},
		{"volume", "ls", "--quiet"},
		{"network", "ls", "--quiet", "--filter", "label=com.xiak.matrix.managed=true"},
	}
	for _, arguments := range checks {
		lines, err := dockerLines(ctx, arguments...)
		if err != nil || len(lines) != 0 {
			return fail("clean-docker-namespace")
		}
	}
	return nil
}

type containerInspection struct {
	ID     string `json:"Id"`
	Name   string `json:"Name"`
	Config struct {
		Image  string            `json:"Image"`
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
	State struct {
		Running bool   `json:"Running"`
		Status  string `json:"Status"`
		Health  *struct {
			Status string `json:"Status"`
		} `json:"Health"`
	} `json:"State"`
	HostConfig struct {
		PortBindings map[string][]json.RawMessage `json:"PortBindings"`
		Memory       int64                        `json:"Memory"`
		NanoCPUs     int64                        `json:"NanoCpus"`
	} `json:"HostConfig"`
	NetworkSettings struct {
		Ports    map[string][]json.RawMessage `json:"Ports"`
		Networks map[string]struct {
			NetworkID string `json:"NetworkID"`
		} `json:"Networks"`
	} `json:"NetworkSettings"`
	Mounts []struct {
		Source      string `json:"Source"`
		Destination string `json:"Destination"`
		RW          bool   `json:"RW"`
	} `json:"Mounts"`
}

func inspectContainers(ctx context.Context, ids []string) ([]containerInspection, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	arguments := append([]string{"container", "inspect"}, ids...)
	content, err := docker(ctx, arguments...)
	if err != nil {
		return nil, err
	}
	var inspections []containerInspection
	if json.Unmarshal(content, &inspections) != nil || len(inspections) != len(ids) {
		return nil, errors.New("Docker container inspection is invalid")
	}
	return inspections, nil
}

func expectedPlatformServices(
	manifest release.Manifest,
	root, installationID string,
) (topology.Result, map[string]struct{}, error) {
	compiled, err := topology.Compile(manifest, topology.Options{
		InstallationID: installationID,
		Root:           filepath.ToSlash(root),
		Listener:       "0.0.0.0",
		Port:           8080,
	})
	if err != nil {
		return topology.Result{}, nil, err
	}
	var document map[string]json.RawMessage
	if decodeOne(compiled.ComposeJSON, &document) != nil {
		return topology.Result{}, nil, errors.New("compiled platform topology is invalid")
	}
	var declared map[string]json.RawMessage
	if json.Unmarshal(document["services"], &declared) != nil || len(declared) == 0 {
		return topology.Result{}, nil, errors.New("compiled platform service inventory is invalid")
	}
	services := make(map[string]struct{}, len(declared))
	for service := range declared {
		services[service] = struct{}{}
	}
	return compiled, services, nil
}

func assertPlatform(
	ctx context.Context,
	root string,
	manifest release.Manifest,
	wantPrevious string,
) (lifecycle.Journal, error) {
	state, err := readJournal(ctx, root)
	if err != nil || state.CurrentReleaseID != manifest.Release.ID ||
		state.PreviousRelease != wantPrevious || state.Active != nil {
		return lifecycle.Journal{}, fail("platform-journal")
	}
	_, expected, err := expectedPlatformServices(manifest, root, state.InstallationID)
	if err != nil {
		return lifecycle.Journal{}, fail("platform-topology-contract")
	}
	ids, err := dockerLines(
		ctx, "container", "ls", "--all", "--quiet",
		"--filter", "label=com.xiak.matrix.managed=true",
		"--filter", "label=com.xiak.matrix.installation="+state.InstallationID,
	)
	if err != nil || len(ids) != len(expected) {
		return lifecycle.Journal{}, fail("platform-container-inventory")
	}
	inspections, err := inspectContainers(ctx, ids)
	if err != nil {
		return lifecycle.Journal{}, fail("platform-container-inspection")
	}
	seen := make(map[string]struct{}, len(inspections))
	published := 0
	for _, inspection := range inspections {
		role := inspection.Config.Labels["com.xiak.matrix.role"]
		if _, ok := expected[role]; !ok || inspection.Config.Labels["com.xiak.matrix.release"] != manifest.Release.ID ||
			inspection.Config.Labels["com.xiak.matrix.installation"] != state.InstallationID ||
			!inspection.State.Running || inspection.State.Status != "running" ||
			inspection.State.Health == nil || inspection.State.Health.Status != "healthy" {
			return lifecycle.Journal{}, fail("platform-container-state")
		}
		if _, duplicate := seen[role]; duplicate {
			return lifecycle.Journal{}, fail("platform-container-identity")
		}
		seen[role] = struct{}{}
		for _, bindings := range inspection.HostConfig.PortBindings {
			published += len(bindings)
		}
		if role != "apisix" && len(inspection.HostConfig.PortBindings) != 0 {
			return lifecycle.Journal{}, fail("platform-port-boundary")
		}
	}
	if published != 1 {
		return lifecycle.Journal{}, fail("platform-edge-boundary")
	}
	return state, nil
}

func assertNoPlatformReleaseContainers(ctx context.Context, releaseID string) error {
	ids, err := dockerLines(
		ctx, "container", "ls", "--all", "--quiet",
		"--filter", "label=com.xiak.matrix.managed=true",
		"--filter", "label=com.xiak.matrix.release="+releaseID,
	)
	if err != nil || len(ids) != 0 {
		return fail("superseded-platform-containers")
	}
	return nil
}

func formatResourceVersion(value uint64) string {
	return fmt.Sprintf("\"%d\"", value)
}
