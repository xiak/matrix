package phase1e2e

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

	"github.com/xiak/matrix/app/service/installation/internal/cli"
	"github.com/xiak/matrix/app/service/installation/internal/journal"
	"github.com/xiak/matrix/app/service/installation/internal/lifecycle"
	"github.com/xiak/matrix/app/service/installation/release"
	"github.com/xiak/matrix/app/service/installation/topology"
)

const maximumCommandOutput = 1024 * 1024

var errCommandOutputLimit = errors.New("command output exceeded acceptance bound")

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
	stdout := newBoundedBuffer(maximumCommandOutput)
	stderr := newBoundedBuffer(maximumCommandOutput)
	command := exec.CommandContext(ctx, executable, arguments...)
	command.Stdin = nil
	command.Stdout = stdout
	command.Stderr = stderr
	err := command.Run()
	result := commandOutput{
		stdout: append([]byte(nil), stdout.content.Bytes()...),
		stderr: append([]byte(nil), stderr.content.Bytes()...),
	}
	if stdout.overflow || stderr.overflow {
		return commandOutput{}, errCommandOutputLimit
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

type mxSourceCredentialEnvelope struct {
	APIVersion string                   `json:"apiVersion"`
	Kind       string                   `json:"kind"`
	Action     string                   `json:"action"`
	Status     string                   `json:"status"`
	Result     mxSourceCredentialResult `json:"result"`
}

type mxSourceCredentialResult struct {
	State     string `json:"state"`
	Purpose   string `json:"purpose"`
	Tenant    string `json:"tenant"`
	Reference string `json:"reference"`
}

type mxSourceTrustEnvelope struct {
	APIVersion string              `json:"apiVersion"`
	Kind       string              `json:"kind"`
	Action     string              `json:"action"`
	Status     string              `json:"status"`
	Result     mxSourceTrustResult `json:"result"`
}

type mxSourceTrustResult struct {
	State          string `json:"state"`
	Tenant         string `json:"tenant"`
	EndpointOrigin string `json:"endpointOrigin"`
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
	return checkMXOutput(action, output, err, ctx.Err(), forbidden)
}

func checkMXOutput(action string, output commandOutput, processErr, contextErr error, forbidden [][]byte) (mxResult, error) {
	step := "mx-" + action
	if containsAny(output.stdout, forbidden) || containsAny(output.stderr, forbidden) {
		return mxResult{}, fail(step + "-sensitive-output")
	}
	if errors.Is(contextErr, context.DeadlineExceeded) {
		return mxResult{}, fail(step + "-deadline")
	}
	if contextErr != nil {
		return mxResult{}, fail(step + "-cancelled")
	}
	if errors.Is(processErr, errCommandOutputLimit) {
		return mxResult{}, fail(step + "-output-limit")
	}
	if processErr != nil {
		return mxResult{}, fail(step + "-process")
	}
	if output.exit != 0 {
		return mxResult{}, closedMXFailure(action, output)
	}
	if len(output.stderr) != 0 {
		return mxResult{}, fail(step + "-unexpected-stderr")
	}
	var envelope mxEnvelope
	if decodeOne(output.stdout, &envelope) != nil {
		return mxResult{}, fail(step + "-json")
	}
	if envelope.APIVersion != cli.OutputAPIVersion {
		return mxResult{}, fail(step + "-api-version")
	}
	if envelope.Kind != "PlatformCommandResult" {
		return mxResult{}, fail(step + "-kind")
	}
	if envelope.Action != strings.ToUpper(action) {
		return mxResult{}, fail(step + "-action")
	}
	if envelope.Status != "SUCCEEDED" {
		return mxResult{}, fail(step + "-status")
	}
	if envelope.Result.State != "READY" {
		return mxResult{}, fail(step + "-state")
	}
	return envelope.Result, nil
}

func runMXSourceCredential(
	ctx context.Context,
	bundle release.VerifiedBundle,
	operation, root, tenant, purpose, reference, fromFile, wantState string,
	forbidden [][]byte,
) error {
	action := ""
	switch operation {
	case "apply":
		action = "SOURCE_CREDENTIAL_APPLY"
		if fromFile == "" {
			return fail("mx-source-credential-command")
		}
	case "retire-previous":
		action = "SOURCE_CREDENTIAL_RETIRE_PREVIOUS"
		if fromFile != "" {
			return fail("mx-source-credential-command")
		}
	default:
		return fail("mx-source-credential-command")
	}
	args := []string{
		"--format", "json", "devops", "source-credential", operation,
		"--root", root, "--tenant", tenant, "--purpose", purpose,
		"--reference", reference,
	}
	if fromFile != "" {
		args = append(args, "--from-file", fromFile)
	}
	output, err := runProcess(ctx, mxPath(bundle), args...)
	if err != nil || output.exit != 0 || containsAny(output.stdout, forbidden) ||
		containsAny(output.stderr, forbidden) || len(output.stderr) != 0 {
		return fail("mx-source-credential-" + operation)
	}
	if !validMXSourceCredentialResult(
		output.stdout, action, wantState, purpose, tenant, reference,
	) {
		return fail("mx-source-credential-" + operation + "-result")
	}
	return nil
}

func validMXSourceCredentialResult(
	content []byte,
	action, state, purpose, tenant, reference string,
) bool {
	var envelope mxSourceCredentialEnvelope
	return decodeOne(content, &envelope) == nil &&
		envelope.APIVersion == "cli.matrix.xiak.com/v1" &&
		envelope.Kind == "SourceCredentialCommandResult" &&
		envelope.Action == action && envelope.Status == "SUCCEEDED" &&
		envelope.Result.State == state && envelope.Result.Purpose == purpose &&
		envelope.Result.Tenant == tenant && envelope.Result.Reference == reference
}

func runMXSourceTrust(
	ctx context.Context,
	bundle release.VerifiedBundle,
	operation, root, tenant, endpointOrigin, fromFile, wantState string,
	forbidden [][]byte,
) error {
	action := ""
	switch operation {
	case "apply":
		action = "SOURCE_TRUST_APPLY"
		if fromFile == "" {
			return fail("mx-source-trust-command")
		}
	case "remove":
		action = "SOURCE_TRUST_REMOVE"
		if fromFile != "" {
			return fail("mx-source-trust-command")
		}
	default:
		return fail("mx-source-trust-command")
	}
	args := []string{
		"--format", "json", "devops", "source-trust", operation,
		"--root", root, "--tenant", tenant, "--endpoint-origin", endpointOrigin,
	}
	if fromFile != "" {
		args = append(args, "--from-file", fromFile)
	}
	output, err := runProcess(ctx, mxPath(bundle), args...)
	if err != nil || output.exit != 0 || containsAny(output.stdout, forbidden) ||
		containsAny(output.stderr, forbidden) || len(output.stderr) != 0 {
		return fail("mx-source-trust-" + operation)
	}
	if !validMXSourceTrustResult(
		output.stdout, action, wantState, tenant, endpointOrigin,
	) {
		return fail("mx-source-trust-" + operation + "-result")
	}
	return nil
}

func validMXSourceTrustResult(
	content []byte,
	action, state, tenant, endpointOrigin string,
) bool {
	var envelope mxSourceTrustEnvelope
	return decodeOne(content, &envelope) == nil &&
		envelope.APIVersion == "cli.matrix.xiak.com/v1" &&
		envelope.Kind == "SourceTrustCommandResult" &&
		envelope.Action == action && envelope.Status == "SUCCEEDED" &&
		envelope.Result.State == state && envelope.Result.Tenant == tenant &&
		envelope.Result.EndpointOrigin == endpointOrigin
}

// These are diagnostic categories, never recovery permits. Unknown output and
// free-form messages remain private; even a recognized failure still fails.
func closedMXFailure(action string, output commandOutput) error {
	unknown := fail("mx-" + action + "-exit-unknown")
	var envelope mxFailure
	if action != "rollback" || len(output.stdout) != 0 || decodeOne(output.stderr, &envelope) != nil ||
		envelope.APIVersion != cli.OutputAPIVersion || envelope.Kind != "PlatformCommandFailure" ||
		envelope.Action != "ROLLBACK" || envelope.Status != "FAILED" {
		return unknown
	}
	known := map[string]struct {
		class cli.FaultClass
		exit  int
		step  string
	}{
		"ROLLBACK_SOURCE_NOT_READY":        {cli.FaultPrecondition, cli.ExitPrecondition, "source-not-ready"},
		"ROLLBACK_PREDECESSOR_UNAVAILABLE": {cli.FaultPrecondition, cli.ExitPrecondition, "predecessor-unavailable"},
		"ROLLBACK_PREDECESSOR_MISMATCH":    {cli.FaultPrecondition, cli.ExitPrecondition, "predecessor-mismatch"},
		"ROLLBACK_SCHEMA_INCOMPATIBLE":     {cli.FaultPrecondition, cli.ExitPrecondition, "profile-incompatible"},
		"INSTALLATION_STATE_INVALID":       {cli.FaultVerification, cli.ExitVerification, "journal-invalid"},
		"INSTALLATION_RELEASE_INVALID":     {cli.FaultVerification, cli.ExitVerification, "release-invalid"},
		"PLATFORM_VERIFICATION_FAILED":     {cli.FaultVerification, cli.ExitVerification, "verification-failed"},
		"DEPENDENCY_UNAVAILABLE":           {cli.FaultUnavailable, cli.ExitUnavailable, "dependency-unavailable"},
		"ROLLBACK_DEPENDENCY_UNAVAILABLE":  {cli.FaultUnavailable, cli.ExitUnavailable, "rollback-dependency-unavailable"},
		"ROLLBACK_OUTCOME_UNKNOWN":         {cli.FaultUnavailable, cli.ExitUnavailable, "outcome-unknown"},
		"COMMAND_INTERRUPTED":              {cli.FaultInterrupted, cli.ExitInterrupted, "interrupted"},
		"ROLLBACK_FAILED":                  {cli.FaultInternal, cli.ExitInternal, "execution-failed"},
	}
	category, ok := known[envelope.Error.Code]
	if !ok || envelope.Error.Class != string(category.class) || output.exit != category.exit {
		return unknown
	}
	return fail("mx-rollback-" + category.step)
}

func checkExplicitRollback(result mxResult, commandErr error, expectedRelease string) error {
	if commandErr != nil {
		return safeFailure(commandErr)
	}
	if result.ReleaseID != expectedRelease {
		return fail("platform-rollback-release")
	}
	if result.PreviousID != "" {
		return fail("platform-rollback-previous")
	}
	if !result.Changed {
		return fail("platform-rollback-unchanged")
	}
	return nil
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

// waitInjectedUpgrade starts the failure-recovery budget after injection,
// never extending the enclosing lifecycle deadline. Cancellation joins the
// already-started command before its captured output can be inspected.
func waitInjectedUpgrade(ctx context.Context, cancelCommand context.CancelFunc, waited <-chan error) error {
	rollbackContext, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	select {
	case err := <-waited:
		if rollbackContext.Err() != nil {
			return rollbackContext.Err()
		}
		return err
	case <-rollbackContext.Done():
		cancelCommand()
		<-waited
		return rollbackContext.Err()
	}
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
	Image  string `json:"Image"`
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
	} `json:"HostConfig"`
	NetworkSettings struct {
		Ports    map[string][]json.RawMessage `json:"Ports"`
		Networks map[string]struct {
			NetworkID string `json:"NetworkID"`
			Gateway   string `json:"Gateway"`
		} `json:"Networks"`
	} `json:"NetworkSettings"`
	Mounts []struct {
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
	root, installationID, northboundOrigin string,
) (topology.Result, map[string]struct{}, error) {
	compiled, err := topology.Compile(manifest, topology.Options{
		InstallationID:   installationID,
		Root:             filepath.ToSlash(root),
		Listener:         "0.0.0.0",
		Port:             8080,
		NorthboundOrigin: northboundOrigin,
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
	_, expected, err := expectedPlatformServices(manifest, root, state.InstallationID, state.NorthboundOrigin)
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
	expectedBindings := expectedPublishedPortBindings(manifest)
	expectedPublished := 0
	for _, count := range expectedBindings {
		expectedPublished += count
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
		rolePublished := 0
		for _, bindings := range inspection.HostConfig.PortBindings {
			rolePublished += len(bindings)
		}
		published += rolePublished
		if rolePublished != expectedBindings[role] {
			return lifecycle.Journal{}, fail("platform-port-boundary")
		}
	}
	if published != expectedPublished {
		return lifecycle.Journal{}, fail("platform-edge-boundary")
	}
	return state, nil
}

func expectedPublishedPortBindings(manifest release.Manifest) map[string]int {
	result := map[string]int{"apisix": 1}
	if manifest.IncludesProduct(release.ProductDevOps) {
		result["devops-executor-gateway"] = 1
	}
	return result
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
