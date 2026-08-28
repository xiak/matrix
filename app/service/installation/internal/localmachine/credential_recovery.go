package localmachine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/xiak/matrix/api/contractjson"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/installation/internal/layout"
	"github.com/xiak/matrix/app/service/installation/internal/lifecycle"
	"github.com/xiak/matrix/app/service/installation/internal/platformcommand"
)

const localRecoveryEntrypoint = "/matrix/bin/matrix-iam-local-recovery"

// This adapter is the installation's narrow, local capability consumer. It
// never uses a runtime/migration login or enters another service's database.
func (effects *Effects) PrepareCredentialRecovery(ctx context.Context, installed platformcommand.InstalledPlan, inputPath string, previous *lifecycle.Execution) (platformcommand.CredentialRecoveryPlan, error) {
	plan := platformcommand.CredentialRecoveryPlan{InstalledPlan: installed}
	if effects == nil || effects.runtime == nil || ctx == nil || ctx.Err() != nil {
		return plan, platformcommand.ErrEffectUnavailable
	}
	_, authority, err := authenticateCredentialRecovery(installed)
	if err != nil {
		return plan, err
	}
	var input platformcommand.CredentialRecoveryInput
	if inputPath != "" {
		input, err = readCredentialRecoveryInput(inputPath)
		if err != nil {
			return plan, err
		}
	} else if previous == nil {
		return plan, platformcommand.ErrEffectPrecondition
	}
	if previous != nil && (previous.Command.Action != lifecycle.ActionRecoverCredentials ||
		lifecycle.ValidateCommandID(previous.Command.ID) != nil || iamv1.ValidateDigest("inputCommitment", previous.Command.InputDigest) != nil) {
		return plan, platformcommand.ErrEffectVerification
	}
	if previous != nil && previous.CompletedAt.IsZero() && inputPath != "" && input.CommandID != previous.Command.ID {
		return plan, platformcommand.ErrEffectConflict
	}
	resume := previous != nil && (inputPath == "" || input.CommandID == previous.Command.ID)
	stored, exists, err := readCredentialRecoveryRequest(installed.Root, authority)
	if err != nil {
		return plan, err
	}
	if resume {
		plan.CommandID, plan.InputCommitment = previous.Command.ID, previous.Command.InputDigest
		if exists {
			commitment, verifyErr := iamv1.VerifyLocalCredentialRecoveryRequest(authority, stored)
			if verifyErr != nil || stored.CommandID != plan.CommandID || commitment != plan.InputCommitment {
				return plan, platformcommand.ErrEffectConflict
			}
			if inputPath != "" && !recoveryInputMatches(authority, stored, input, plan.InputCommitment) {
				return plan, platformcommand.ErrEffectConflict
			}
			plan.Request = &stored
			return plan, nil
		}
		if previous.Phase == lifecycle.PhaseCommitting || !previous.CompletedAt.IsZero() {
			// Cleanup may already have removed the private input. --resume uses
			// the sealed outcome, not a claim that a new password matches it.
			if inputPath != "" {
				return plan, platformcommand.ErrEffectConflict
			}
			return plan, nil
		}
		if previous.Phase == lifecycle.PhaseRecoveringCredentials || inputPath == "" {
			// Once apply may have started, only its exact receipt can resolve
			// a missing private request. Never reconstruct from current state.
			return plan, nil
		}
	} else if exists {
		return plan, platformcommand.ErrEffectConflict
	}
	inspection, err := effects.inspectCredentialRecovery(ctx, installed, authority, nil)
	if err != nil {
		return plan, err
	}
	if inspection.State != "ELIGIBLE" || inspection.Expected == nil {
		return plan, platformcommand.ErrEffectVerification
	}
	signed, err := iamv1.SignLocalCredentialRecoveryRequest(authority, iamv1.LocalCredentialRecoveryRequest{
		APIVersion: iamv1.APIVersion, Kind: "LocalCredentialRecoveryRequest", Purpose: iamv1.LocalCredentialRecoveryPurpose,
		CommandID: input.CommandID, Scope: authority.Scope, Expected: *inspection.Expected, NewPassword: input.Password,
	})
	if err != nil {
		return plan, platformcommand.ErrEffectVerification
	}
	commitment, err := iamv1.VerifyLocalCredentialRecoveryRequest(authority, signed)
	if err != nil {
		return plan, platformcommand.ErrEffectVerification
	}
	if resume && commitment != plan.InputCommitment {
		return plan, platformcommand.ErrEffectConflict
	}
	plan.CommandID, plan.InputCommitment, plan.Request = signed.CommandID, commitment, &signed
	return plan, nil
}

func recoveryInputMatches(authority iamv1.LocalCredentialRecoveryAuthority, stored iamv1.LocalCredentialRecoveryRequest, input platformcommand.CredentialRecoveryInput, commitment string) bool {
	if input.CommandID != stored.CommandID {
		return false
	}
	stored.NewPassword = input.Password
	actual, err := iamv1.VerifyLocalCredentialRecoveryRequest(authority, stored)
	return err == nil && actual == commitment
}

func authenticateCredentialRecovery(installed platformcommand.InstalledPlan) (platformcommand.InstallPlan, iamv1.LocalCredentialRecoveryAuthority, error) {
	plan, err := authenticateInstalledPlan(installed)
	if err != nil {
		return plan, iamv1.LocalCredentialRecoveryAuthority{}, platformcommand.ErrEffectVerification
	}
	clear(plan.TrustBytes)
	plan.TrustBytes = nil
	if err := platformcommand.ValidateCredentialRecoveryProfile(plan.Bundle.Manifest.Database); err != nil {
		return plan, iamv1.LocalCredentialRecoveryAuthority{}, err
	}
	authority, err := readLocalCredentialRecoveryAuthority(installed.Root, installed.InstallationID)
	if err != nil {
		return plan, authority, err
	}
	dsn, err := readManagedFile(installed.Root, filepath.FromSlash(layout.IAMCredentialRecovery), maximumCredentialFile)
	defer clear(dsn)
	if err != nil || validateDatabaseDSN(string(dsn), "matrix_iam_credential_recovery_login") != nil {
		return plan, authority, platformcommand.ErrEffectVerification
	}
	return plan, authority, nil
}

func readCredentialRecoveryRequest(root string, authority iamv1.LocalCredentialRecoveryAuthority) (iamv1.LocalCredentialRecoveryRequest, bool, error) {
	exists, err := managedFileExists(root, filepath.FromSlash(layout.IAMLocalRecoveryRequest))
	if err != nil {
		return iamv1.LocalCredentialRecoveryRequest{}, false, platformcommand.ErrEffectVerification
	}
	if !exists {
		return iamv1.LocalCredentialRecoveryRequest{}, false, nil
	}
	encoded, err := readManagedFile(root, filepath.FromSlash(layout.IAMLocalRecoveryRequest), iamv1.MaxLocalCredentialRecoveryBytes)
	if err != nil {
		return iamv1.LocalCredentialRecoveryRequest{}, false, platformcommand.ErrEffectVerification
	}
	defer clear(encoded)
	request, err := iamv1.DecodeLocalCredentialRecoveryRequest(bytes.NewReader(encoded))
	if err != nil || lifecycle.ValidateCommandID(request.CommandID) != nil {
		return iamv1.LocalCredentialRecoveryRequest{}, false, platformcommand.ErrEffectVerification
	}
	if _, err := iamv1.VerifyLocalCredentialRecoveryRequest(authority, request); err != nil {
		return iamv1.LocalCredentialRecoveryRequest{}, false, platformcommand.ErrEffectVerification
	}
	return request, true, nil
}

func (effects *Effects) ApplyCredentialRecoveryPhase(ctx context.Context, plan platformcommand.CredentialRecoveryPlan, phase lifecycle.Phase) error {
	if effects == nil || effects.runtime == nil || ctx == nil || ctx.Err() != nil {
		return platformcommand.ErrEffectUnavailable
	}
	if lifecycle.ValidateCommandID(plan.CommandID) != nil || iamv1.ValidateDigest("inputCommitment", plan.InputCommitment) != nil || plan.CorrelationID != plan.CommandID {
		return platformcommand.ErrEffectVerification
	}
	_, authority, err := authenticateCredentialRecovery(plan.InstalledPlan)
	if err != nil {
		return err
	}
	switch phase {
	case lifecycle.PhaseStaging:
		if plan.Request == nil {
			return platformcommand.ErrEffectPrecondition
		}
		commitment, err := iamv1.VerifyLocalCredentialRecoveryRequest(authority, *plan.Request)
		if err != nil || commitment != plan.InputCommitment || plan.Request.CommandID != plan.CommandID {
			return platformcommand.ErrEffectVerification
		}
		encoded, err := iamv1.EncodeLocalCredentialRecoveryRequest(*plan.Request)
		if err != nil {
			return platformcommand.ErrEffectVerification
		}
		defer clear(encoded)
		if writeManagedOnce(plan.Root, filepath.FromSlash(layout.IAMLocalRecoveryRequest), encoded) != nil {
			return platformcommand.ErrEffectConflict
		}
		return nil
	case lifecycle.PhaseRecoveringCredentials:
		return effects.applyCredentialRecovery(ctx, plan, authority)
	case lifecycle.PhaseCommitting:
		return effects.finalizeCredentialRecovery(ctx, plan, authority)
	default:
		return platformcommand.ErrEffectVerification
	}
}

func (effects *Effects) inspectCredentialRecovery(ctx context.Context, installed platformcommand.InstalledPlan, authority iamv1.LocalCredentialRecoveryAuthority, query *iamv1.LocalCredentialRecoveryReceiptQuery) (iamv1.LocalCredentialRecoveryInspection, error) {
	plan := platformcommand.CredentialRecoveryPlan{InstalledPlan: installed}
	if query != nil {
		if iamv1.ValidateLocalCredentialRecoveryReceiptQuery(*query) != nil {
			return iamv1.LocalCredentialRecoveryInspection{}, platformcommand.ErrEffectVerification
		}
		encoded, err := json.Marshal(query)
		if err != nil || writeManagedOnce(installed.Root, filepath.FromSlash(layout.IAMLocalRecoveryQuery), encoded) != nil {
			return iamv1.LocalCredentialRecoveryInspection{}, platformcommand.ErrEffectConflict
		}
		plan.CommandID, plan.InputCommitment = query.CommandID, query.InputCommitment
	}
	output, err := effects.runCredentialRecoveryEntry(ctx, plan, "inspect", query != nil)
	defer clear(output)
	if err != nil {
		return iamv1.LocalCredentialRecoveryInspection{}, err
	}
	var inspection iamv1.LocalCredentialRecoveryInspection
	if contractjson.DecodeObjectBytes(output, iamv1.MaxLocalCredentialRecoveryBytes, &inspection) != nil ||
		iamv1.ValidateLocalCredentialRecoveryInspection(inspection) != nil || inspection.Scope != authority.Scope {
		return inspection, platformcommand.ErrEffectOutcomeUnknown
	}
	if query == nil && inspection.State != "ELIGIBLE" || query != nil && (inspection.State == "ELIGIBLE" ||
		inspection.CommandID != query.CommandID || inspection.InputCommitment != query.InputCommitment) {
		return inspection, platformcommand.ErrEffectOutcomeUnknown
	}
	return inspection, nil
}

func (effects *Effects) applyCredentialRecovery(ctx context.Context, plan platformcommand.CredentialRecoveryPlan, authority iamv1.LocalCredentialRecoveryAuthority) error {
	request, exists, err := readCredentialRecoveryRequest(plan.Root, authority)
	if err != nil {
		return err
	}
	if exists {
		commitment, err := iamv1.VerifyLocalCredentialRecoveryRequest(authority, request)
		if err != nil || request.CommandID != plan.CommandID || commitment != plan.InputCommitment {
			return platformcommand.ErrEffectConflict
		}
	}
	query := iamv1.LocalCredentialRecoveryReceiptQuery{
		APIVersion: iamv1.APIVersion, Kind: "LocalCredentialRecoveryReceiptQuery", CommandID: plan.CommandID, InputCommitment: plan.InputCommitment,
	}
	inspection, err := effects.inspectCredentialRecovery(ctx, plan.InstalledPlan, authority, &query)
	if err != nil {
		return platformcommand.ErrEffectOutcomeUnknown
	}
	if inspection.State == "COMPLETED" {
		if exists && *inspection.Expected != request.Expected {
			return platformcommand.ErrEffectVerification
		}
		return nil
	}
	if !exists {
		return platformcommand.ErrEffectOutcomeUnknown
	}
	output, applyErr := effects.runCredentialRecoveryEntry(ctx, plan, "apply", true)
	defer clear(output)
	if applyErr == nil {
		var result iamv1.LocalCredentialRecoveryResult
		if contractjson.DecodeObjectBytes(output, iamv1.MaxLocalCredentialRecoveryBytes, &result) == nil &&
			iamv1.ValidateLocalCredentialRecoveryResult(result) == nil && result.Scope == authority.Scope &&
			result.CommandID == plan.CommandID && result.InputCommitment == plan.InputCommitment &&
			result.PreviousCredentialGeneration == request.Expected.CredentialGeneration &&
			result.PrincipalResourceVersion == request.Expected.PrincipalResourceVersion+1 {
			return nil
		}
	}
	// No output, a timeout, malformed success, and UNAVAILABLE all mean the
	// transaction may have committed. Resolve only its original receipt.
	inspection, err = effects.inspectCredentialRecovery(ctx, plan.InstalledPlan, authority, &query)
	if err == nil && inspection.State == "COMPLETED" && *inspection.Expected == request.Expected {
		return nil
	}
	if err == nil && inspection.State == "NOT_FOUND" && (errors.Is(applyErr, platformcommand.ErrCredentialRecoveryInvalid) ||
		errors.Is(applyErr, platformcommand.ErrCredentialRecoveryForbidden) || errors.Is(applyErr, platformcommand.ErrCredentialRecoveryConflict)) {
		return applyErr
	}
	return platformcommand.ErrEffectOutcomeUnknown
}

// A stopped, exactly owned one-shot container is retained after apply until
// the journal commits its outcome. We never stop/restart a service or kill an
// in-flight recovery. Re-entry queries IAM before replaying the same request.
func (effects *Effects) runCredentialRecoveryEntry(ctx context.Context, plan platformcommand.CredentialRecoveryPlan, mode string, requestFile bool) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	arguments, expected, err := effects.credentialRecoveryContainer(ctx, plan, mode, requestFile)
	if err != nil {
		return nil, err
	}
	for _, mount := range expected.service.Volumes {
		relative, err := filepath.Rel(plan.Root, mount.Source)
		if err != nil {
			return nil, platformcommand.ErrEffectVerification
		}
		content, err := readManagedFile(plan.Root, relative, iamv1.MaxLocalCredentialRecoveryBytes)
		clear(content)
		if err != nil {
			return nil, platformcommand.ErrEffectVerification
		}
	}
	return invokeCredentialRecoveryEntry(ctx, effects.runtime, arguments, expected)
}

func invokeCredentialRecoveryEntry(ctx context.Context, runtimeBoundary dockerRuntime, arguments []string, expected credentialRecoveryContainerExpectation) ([]byte, error) {
	mode := expected.mode
	current, exists, err := findCredentialRecoveryContainer(ctx, runtimeBoundary, expected)
	if err != nil {
		return nil, err
	}
	if exists {
		if current.State.Running || current.State.Status == "restarting" || current.State.Status == "paused" {
			return nil, platformcommand.ErrEffectOutcomeUnknown
		}
		if current.State.Status != "created" {
			if current.State.Status != "exited" || current.State.OOMKilled || current.State.Error != "" {
				return nil, platformcommand.ErrEffectOutcomeUnknown
			}
			if mode == "apply" {
				switch current.State.ExitCode {
				case 2, 3, 4:
					return nil, localRecoveryExitError(current.State.ExitCode)
				case 6:
					// The caller has just obtained NOT_FOUND for this exact
					// commitment. Retry the same intent, never a fresh inspect.
				default:
					return nil, platformcommand.ErrEffectOutcomeUnknown
				}
			}
			if err := removeCredentialRecoveryContainer(ctx, runtimeBoundary, current); err != nil {
				return nil, err
			}
			exists = false
		}
	}
	if !exists {
		output, _, err := runtimeBoundary.Run(ctx, nil, arguments...)
		defer clear(output)
		identity := strings.TrimSpace(string(output))
		if err != nil || !providerIdentity.MatchString(identity) {
			return nil, platformcommand.ErrEffectOutcomeUnknown
		}
		current, err = inspectPlatformContainer(ctx, runtimeBoundary, identity)
		if err != nil || validateCredentialRecoveryContainer(current, expected) != nil || current.State.Status != "created" {
			return nil, platformcommand.ErrEffectOutcomeUnknown
		}
	}
	output, _, startErr := runtimeBoundary.Run(ctx, nil, "container", "start", "--attach", current.ID)
	completed, inspectErr := inspectPlatformContainer(ctx, runtimeBoundary, current.ID)
	if inspectErr != nil || validateCredentialRecoveryContainer(completed, expected) != nil ||
		completed.State.Running || completed.State.Status != "exited" || completed.State.OOMKilled || completed.State.Error != "" {
		clear(output)
		return nil, platformcommand.ErrEffectOutcomeUnknown
	}
	if mode == "inspect" {
		if err := removeCredentialRecoveryContainer(ctx, runtimeBoundary, completed); err != nil {
			clear(output)
			return nil, err
		}
	}
	if completed.State.ExitCode != 0 {
		clear(output)
		return nil, localRecoveryExitError(completed.State.ExitCode)
	}
	if startErr != nil {
		clear(output)
		return nil, platformcommand.ErrEffectOutcomeUnknown
	}
	return output, nil
}

type credentialRecoveryContainerExpectation struct {
	name        string
	service     platformExpectedService
	environment []string
	mode        string
	networkID   string
	networkName string
}

func (effects *Effects) credentialRecoveryContainer(ctx context.Context, plan platformcommand.CredentialRecoveryPlan, mode string, requestFile bool) ([]string, credentialRecoveryContainerExpectation, error) {
	var expected credentialRecoveryContainerExpectation
	if (mode != "inspect" && mode != "apply") || mode == "apply" && !requestFile ||
		(requestFile && (lifecycle.ValidateCommandID(plan.CommandID) != nil || iamv1.ValidateDigest("inputCommitment", plan.InputCommitment) != nil)) {
		return nil, expected, platformcommand.ErrEffectVerification
	}
	installed, err := authenticateInstalledPlan(plan.InstalledPlan)
	if err != nil {
		return nil, expected, platformcommand.ErrEffectVerification
	}
	defer clear(installed.TrustBytes)
	if platformcommand.ValidateCredentialRecoveryProfile(installed.Bundle.Manifest.Database) != nil {
		return nil, expected, platformcommand.ErrEffectPrecondition
	}
	configuration, err := verifiedInstallationConfiguration(installed)
	if err != nil {
		return nil, expected, platformcommand.ErrEffectVerification
	}
	networkID, err := controlNetworkID(ctx, effects.runtime, configuration.topology.ProjectName, plan.InstallationID, plan.ReleaseID)
	if err != nil {
		return nil, expected, err
	}
	network, err := inspectPlatformNetwork(ctx, effects.runtime, networkID)
	if err != nil || !network.Internal || network.Name == "" {
		return nil, expected, platformcommand.ErrEffectVerification
	}
	imageID := ""
	for _, image := range installed.Bundle.Manifest.Images {
		if image.Component == "iam" {
			imageID = image.ImageID
		}
	}
	present, err := inspectExactImage(ctx, effects.runtime, imageID)
	if err != nil || !present {
		return nil, expected, platformcommand.ErrEffectVerification
	}
	imageEnvironment, _, err := effects.runtime.Run(ctx, nil, "image", "inspect", "--format", "{{json .Config.Env}}", imageID)
	defer clear(imageEnvironment)
	if err != nil || json.Unmarshal(imageEnvironment, &expected.environment) != nil || len(expected.environment) > 128 {
		return nil, expected, platformcommand.ErrEffectVerification
	}
	for _, value := range expected.environment {
		if len(value) > 8192 || strings.HasPrefix(value, "MATRIX_") {
			return nil, expected, platformcommand.ErrEffectVerification
		}
	}
	expected.name = configuration.topology.ProjectName + "-iam-local-recovery-" + mode
	expected.mode, expected.networkID = mode, networkID
	expected.networkName = network.Name
	expected.service = platformExpectedService{
		Image: imageID, User: "0:0", Restart: "no", ReadOnly: true,
		Networks: []string{"control"}, CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges:true"},
		Tmpfs: []string{"/tmp:rw,noexec,nosuid,size=64m"},
		Labels: map[string]string{"com.xiak.matrix.managed": "true", "com.xiak.matrix.installation": plan.InstallationID,
			"com.xiak.matrix.release": plan.ReleaseID, "com.xiak.matrix.role": "iam-local-recovery-" + mode,
			"com.xiak.matrix.command": plan.CommandID, "com.xiak.matrix.input": plan.InputCommitment},
	}
	expected.service.Deploy.Resources.Limits.CPUs = "1"
	expected.service.Deploy.Resources.Limits.Memory = "256M"
	arguments := []string{"container", "create", "--pull", "never", "--name", expected.name, "--network", networkID,
		"--user", "0:0", "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m", "--cap-drop", "ALL",
		"--security-opt", "no-new-privileges:true", "--cpus", "1", "--memory", "256m", "--memory-swap", "256m",
		"--pids-limit", "64", "--ipc", "private", "--cgroupns", "private", "--restart", "no", "--log-driver", "none"}
	labelNames := make([]string, 0, len(expected.service.Labels))
	for name := range expected.service.Labels {
		labelNames = append(labelNames, name)
	}
	slices.Sort(labelNames)
	for _, name := range labelNames {
		arguments = append(arguments, "--label", name+"="+expected.service.Labels[name])
	}
	mounts := []migrationMount{
		{layout.IAMCredentialRecovery, "/run/matrix/recovery-dsn", "MATRIX_IAM_LOCAL_RECOVERY_DATABASE_DSN_FILE"},
		{layout.IAMLocalRecoveryAuthority, "/run/matrix/recovery-authority.json", "MATRIX_IAM_LOCAL_RECOVERY_AUTHORITY_FILE"},
	}
	if requestFile {
		relative := layout.IAMLocalRecoveryRequest
		if mode == "inspect" {
			relative = layout.IAMLocalRecoveryQuery
		}
		mounts = append(mounts, migrationMount{relative, "/run/matrix/recovery-request.json", "MATRIX_IAM_LOCAL_RECOVERY_REQUEST_FILE"})
	}
	for _, mount := range mounts {
		source, err := managedPath(plan.Root, filepath.FromSlash(mount.relative))
		if err != nil || strings.ContainsRune(source, ',') {
			return nil, expected, platformcommand.ErrEffectVerification
		}
		arguments = append(arguments, "--mount", "type=bind,src="+source+",dst="+mount.destination+",readonly", "--env", mount.environment+"="+mount.destination)
		expected.service.Volumes = append(expected.service.Volumes, platformMount{Type: "bind", Source: source, Target: mount.destination, ReadOnly: true})
		expected.environment = append(expected.environment, mount.environment+"="+mount.destination)
	}
	arguments = append(arguments, "--entrypoint", localRecoveryEntrypoint, imageID, mode)
	return arguments, expected, nil
}

func findCredentialRecoveryContainer(ctx context.Context, runtimeBoundary dockerRuntime, expected credentialRecoveryContainerExpectation) (platformContainerInspection, bool, error) {
	output, _, err := runtimeBoundary.Run(ctx, nil, "container", "ls", "--all", "--quiet", "--no-trunc", "--filter", "name=^/"+expected.name+"$")
	if err != nil {
		return platformContainerInspection{}, false, platformcommand.ErrEffectUnavailable
	}
	identities := strings.Fields(string(output))
	if len(identities) == 0 {
		return platformContainerInspection{}, false, nil
	}
	if len(identities) != 1 || !providerIdentity.MatchString(identities[0]) {
		return platformContainerInspection{}, false, platformcommand.ErrEffectConflict
	}
	current, err := inspectPlatformContainer(ctx, runtimeBoundary, identities[0])
	if err != nil || validateCredentialRecoveryContainer(current, expected) != nil {
		return current, true, platformcommand.ErrEffectConflict
	}
	return current, true, nil
}

func validateCredentialRecoveryContainer(actual platformContainerInspection, expected credentialRecoveryContainerExpectation) error {
	// Docker has no attached endpoint before start (and can clear it after
	// exit). Check the exact configured network name AND immutable NetworkMode
	// ID in these states; do not mistake an unassigned endpoint for drift or
	// accept a foreign/extra network. Running processes require the real ID.
	if !actual.State.Running && (actual.State.Status == "created" || actual.State.Status == "exited") {
		endpoint, found := actual.NetworkSettings.Networks[expected.networkName]
		if !found || len(actual.NetworkSettings.Networks) != 1 || (endpoint.NetworkID != "" && endpoint.NetworkID != expected.networkID) {
			return platformcommand.ErrEffectConflict
		}
		endpoint.NetworkID = expected.networkID
		actual.NetworkSettings.Networks = map[string]struct {
			NetworkID string `json:"NetworkID"`
		}{expected.networkName: endpoint}
	}
	if actual.Name != "/"+expected.name || validatePlatformContainer(actual, expected.service, map[string]string{"control": expected.networkID}) != nil ||
		!slices.Equal(actual.Config.Entrypoint, []string{localRecoveryEntrypoint}) || !slices.Equal(actual.Config.Cmd, []string{expected.mode}) ||
		!equalStringInventory(actual.Config.Env, expected.environment, false) || actual.HostConfig.NetworkMode != expected.networkID ||
		actual.HostConfig.PidsLimit == nil || *actual.HostConfig.PidsLimit != 64 || actual.HostConfig.MemorySwap != 256*1024*1024 ||
		actual.HostConfig.LogConfig.Type != "none" || actual.HostConfig.PidMode != "" || actual.HostConfig.UTSMode != "" ||
		actual.HostConfig.UsernsMode != "" || actual.HostConfig.IpcMode != "private" || actual.HostConfig.CgroupnsMode != "private" ||
		len(actual.HostConfig.Devices) != 0 || len(actual.HostConfig.DeviceRequests) != 0 || len(actual.HostConfig.VolumesFrom) != 0 || len(actual.HostConfig.Binds) != 0 ||
		actual.HostConfig.AutoRemove {
		return platformcommand.ErrEffectConflict
	}
	for key, value := range expected.service.Labels {
		if actual.Config.Labels[key] != value {
			return platformcommand.ErrEffectConflict
		}
	}
	return nil
}

func removeCredentialRecoveryContainer(ctx context.Context, runtimeBoundary dockerRuntime, current platformContainerInspection) error {
	if !providerIdentity.MatchString(current.ID) || current.State.Running || (current.State.Status != "exited" && current.State.Status != "created") {
		return platformcommand.ErrEffectOutcomeUnknown
	}
	if _, _, err := runtimeBoundary.Run(ctx, nil, "container", "rm", current.ID); err != nil {
		return platformcommand.ErrEffectOutcomeUnknown
	}
	return nil
}

func localRecoveryExitError(code int) error {
	switch code {
	case 2:
		return platformcommand.ErrCredentialRecoveryInvalid
	case 3:
		return platformcommand.ErrCredentialRecoveryForbidden
	case 4:
		return platformcommand.ErrCredentialRecoveryConflict
	default:
		return platformcommand.ErrEffectOutcomeUnknown
	}
}

func (effects *Effects) finalizeCredentialRecovery(ctx context.Context, plan platformcommand.CredentialRecoveryPlan, authority iamv1.LocalCredentialRecoveryAuthority) error {
	request, exists, err := readCredentialRecoveryRequest(plan.Root, authority)
	if err != nil {
		return err
	}
	if exists {
		commitment, err := iamv1.VerifyLocalCredentialRecoveryRequest(authority, request)
		if err != nil || request.CommandID != plan.CommandID || commitment != plan.InputCommitment {
			return platformcommand.ErrEffectConflict
		}
	}
	for _, mode := range []string{"apply", "inspect"} {
		_, expected, err := effects.credentialRecoveryContainer(ctx, plan, mode, true)
		if err != nil {
			return err
		}
		container, found, err := findCredentialRecoveryContainer(ctx, effects.runtime, expected)
		if err != nil {
			return err
		}
		if found {
			if err := removeCredentialRecoveryContainer(ctx, effects.runtime, container); err != nil {
				return err
			}
		}
	}
	return finalizeCredentialRecoveryFiles(plan, authority)
}

func finalizeCredentialRecoveryFiles(plan platformcommand.CredentialRecoveryPlan, authority iamv1.LocalCredentialRecoveryAuthority) error {
	// No tree cleanup and no operator-input deletion. Both exact files remain
	// bound to the committed command even if an earlier unlink already finished.
	for _, relative := range []string{layout.IAMLocalRecoveryQuery, layout.IAMLocalRecoveryRequest} {
		present, err := managedFileExists(plan.Root, filepath.FromSlash(relative))
		if err != nil {
			return platformcommand.ErrEffectConflict
		}
		if !present {
			continue
		}
		content, err := readManagedFile(plan.Root, filepath.FromSlash(relative), iamv1.MaxLocalCredentialRecoveryBytes)
		if err != nil {
			return platformcommand.ErrEffectVerification
		}
		valid := false
		if relative == layout.IAMLocalRecoveryQuery {
			var query iamv1.LocalCredentialRecoveryReceiptQuery
			valid = contractjson.DecodeObjectBytes(content, iamv1.MaxLocalCredentialRecoveryBytes, &query) == nil &&
				iamv1.ValidateLocalCredentialRecoveryReceiptQuery(query) == nil && query.CommandID == plan.CommandID && query.InputCommitment == plan.InputCommitment
		} else {
			request, decodeErr := iamv1.DecodeLocalCredentialRecoveryRequest(bytes.NewReader(content))
			commitment, verifyErr := iamv1.VerifyLocalCredentialRecoveryRequest(authority, request)
			valid = decodeErr == nil && verifyErr == nil && request.CommandID == plan.CommandID && commitment == plan.InputCommitment
		}
		clear(content)
		path, pathErr := managedPath(plan.Root, filepath.FromSlash(relative))
		if !valid || pathErr != nil {
			return platformcommand.ErrEffectConflict
		}
		if os.Remove(path) != nil || syncManagedDirectory(filepath.Dir(path)) != nil {
			return platformcommand.ErrEffectOutcomeUnknown
		}
	}
	return nil
}
