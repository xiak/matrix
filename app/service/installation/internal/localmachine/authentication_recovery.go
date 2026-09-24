package localmachine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"time"

	installationv1 "github.com/xiak/matrix/api/adapter/installation/v1"
	"github.com/xiak/matrix/app/service/installation/internal/layout"
	"github.com/xiak/matrix/app/service/installation/internal/lifecycle"
	"github.com/xiak/matrix/app/service/installation/internal/platformcommand"
)

const authenticationRecoveryEntrypoint = "/matrix/bin/matrix-iam-authentication-recovery"

func (effects *Effects) closeAuthenticationRecovery(ctx context.Context, plan platformcommand.RecoveryPlan) error {
	intent := plan.AuthenticationIntent
	if installationv1.ValidateAuthenticationRecoveryIntent(intent) != nil ||
		(intent.AuthenticationStateDigest != "" && installationv1.ValidateCurrentAuthenticationRecoveryIntent(intent) != nil) ||
		validateAuthenticationRecoveryAnchor(plan.Current.Root, intent, false) != nil {
		return errors.Join(platformcommand.ErrEffectConflict, errors.New("authentication recovery anchor is invalid"))
	}
	encodedIntent, err := installationv1.EncodeAuthenticationRecoveryIntent(intent)
	if err != nil {
		return errors.Join(platformcommand.ErrEffectVerification, err)
	}
	defer clear(encodedIntent)
	intentRelative := filepath.FromSlash(layout.IAMAuthenticationRecoveryIntent(intent.CommandID))
	if err := writeManagedOnce(plan.Current.Root, intentRelative, encodedIntent); err != nil {
		return errors.Join(platformcommand.ErrEffectConflict, err)
	}
	closure, exists, err := readAuthenticationRecoveryClosure(plan.Current.Root, intent.CommandID)
	if err != nil {
		return errors.Join(platformcommand.ErrEffectConflict, err)
	} else if exists {
		if installationv1.ValidateAuthenticationRecoveryClosureForIntent(closure, intent) != nil ||
			(closure.SecuritySnapshotDigest != "") != (intent.AuthenticationStateDigest != "") {
			return errors.Join(platformcommand.ErrEffectConflict, errors.New("authentication recovery closure conflicts"))
		}
		if intent.AuthenticationStateDigest != "" {
			if _, snapshotExists, snapshotErr := readAuthenticationRecoverySecuritySnapshot(plan.Current.Root, intent, closure); snapshotErr != nil || !snapshotExists {
				return errors.Join(platformcommand.ErrEffectConflict, errors.New("authentication recovery security snapshot is unavailable"))
			}
		}
		return nil
	}
	intentDigest, err := installationv1.AuthenticationRecoveryIntentDigest(intent)
	if err != nil {
		return errors.Join(platformcommand.ErrEffectVerification, err)
	}
	output, err := effects.runAuthenticationRecoveryEntry(
		ctx, plan.Current, intent.CommandID, intentDigest, intentRelative,
		installationv1.AuthenticationRecoveryCloseCommand, "",
	)
	if err != nil {
		return err
	}
	if intent.AuthenticationStateDigest != "" {
		envelope, decodeErr := installationv1.DecodeAuthenticationRecoveryClosureEnvelope(bytes.NewReader(output))
		clear(output)
		sealedInstallationID, bootstrapDigest, scopeErr := sealedIAMBootstrapScope(plan.Current.Root, intent.InstallationID)
		if decodeErr != nil || scopeErr != nil || sealedInstallationID != intent.InstallationID ||
			installationv1.ValidateAuthenticationRecoveryClosureEnvelopeForIntent(envelope, intent, bootstrapDigest) != nil {
			return errors.Join(platformcommand.ErrEffectOutcomeUnknown, errors.New("authentication close envelope is unverifiable"))
		}
		encodedSnapshot, encodeErr := installationv1.EncodeAuthenticationRecoverySecuritySnapshot(envelope.SecuritySnapshot)
		if encodeErr != nil {
			return errors.Join(platformcommand.ErrEffectOutcomeUnknown, encodeErr)
		}
		defer clear(encodedSnapshot)
		// A committed close cannot authorize restore until these exact bytes are
		// durable outside the database backup's rollback range.
		if writeErr := writeManagedOnce(plan.Current.Root,
			filepath.FromSlash(layout.IAMAuthenticationRecoverySecuritySnapshot(intent.CommandID)), encodedSnapshot); writeErr != nil {
			return errors.Join(platformcommand.ErrEffectOutcomeUnknown, writeErr)
		}
		if _, exists, readErr := readAuthenticationRecoverySecuritySnapshot(plan.Current.Root, intent, envelope.Closure); readErr != nil || !exists {
			return errors.Join(platformcommand.ErrEffectOutcomeUnknown, errors.New("authentication security snapshot readback failed"))
		}
		closure = envelope.Closure
	} else {
		closure, err = installationv1.DecodeAuthenticationRecoveryClosure(bytes.NewReader(output))
		clear(output)
		if err != nil || installationv1.ValidateAuthenticationRecoveryClosureForIntent(closure, intent) != nil || closure.SecuritySnapshotDigest != "" {
			return errors.Join(platformcommand.ErrEffectOutcomeUnknown, errors.New("authentication close result is unverifiable"))
		}
	}
	encodedClosure, err := installationv1.EncodeAuthenticationRecoveryClosure(closure)
	if err != nil {
		return errors.Join(platformcommand.ErrEffectOutcomeUnknown, err)
	}
	defer clear(encodedClosure)
	if err := writeManagedOnce(plan.Current.Root,
		filepath.FromSlash(layout.IAMAuthenticationRecoveryClosure(intent.CommandID)), encodedClosure); err != nil {
		return errors.Join(platformcommand.ErrEffectOutcomeUnknown, err)
	}
	return nil
}

func (effects *Effects) reconcileAuthenticationRecovery(ctx context.Context, plan platformcommand.RecoveryPlan) error {
	intent := plan.AuthenticationIntent
	closure, exists, err := readAuthenticationRecoveryClosure(plan.Current.Root, intent.CommandID)
	if err != nil || !exists || installationv1.ValidateAuthenticationRecoveryClosureForIntent(closure, intent) != nil ||
		(closure.SecuritySnapshotDigest != "") != (intent.AuthenticationStateDigest != "") ||
		validateAuthenticationRecoveryAnchor(plan.Current.Root, intent, false) != nil {
		return errors.Join(platformcommand.ErrEffectConflict, errors.New("authentication recovery closure is unavailable"))
	}
	snapshotRelative := ""
	if intent.AuthenticationStateDigest != "" {
		if _, snapshotExists, snapshotErr := readAuthenticationRecoverySecuritySnapshot(plan.Current.Root, intent, closure); snapshotErr != nil || !snapshotExists {
			return errors.Join(platformcommand.ErrEffectConflict, errors.New("authentication recovery security snapshot is unavailable"))
		}
		snapshotRelative = filepath.FromSlash(layout.IAMAuthenticationRecoverySecuritySnapshot(intent.CommandID))
	}
	digest, err := installationv1.AuthenticationRecoveryClosureDigest(closure)
	if err != nil {
		return errors.Join(platformcommand.ErrEffectVerification, err)
	}
	closureRelative := filepath.FromSlash(layout.IAMAuthenticationRecoveryClosure(intent.CommandID))
	output, err := effects.runAuthenticationRecoveryEntry(
		ctx, plan.Target, intent.CommandID, digest, closureRelative,
		installationv1.AuthenticationRecoveryReconcileCommand, snapshotRelative,
	)
	if err != nil {
		return err
	}
	reconciled, err := installationv1.DecodeAuthenticationRecoveryClosure(bytes.NewReader(output))
	clear(output)
	if err != nil || reconciled != closure {
		return errors.Join(platformcommand.ErrEffectOutcomeUnknown, errors.New("authentication reconciliation result is unverifiable"))
	}
	return nil
}

func (effects *Effects) reopenAuthenticationRecovery(ctx context.Context, plan platformcommand.RecoveryPlan) error {
	intent := plan.AuthenticationIntent
	closure, exists, err := readAuthenticationRecoveryClosure(plan.Current.Root, intent.CommandID)
	if err != nil || !exists || installationv1.ValidateAuthenticationRecoveryClosureForIntent(closure, intent) != nil ||
		(closure.SecuritySnapshotDigest != "") != (intent.AuthenticationStateDigest != "") ||
		validateAuthenticationRecoveryAnchor(plan.Current.Root, intent, true) != nil {
		return errors.Join(platformcommand.ErrEffectConflict, errors.New("authentication recovery completion anchor is invalid"))
	}
	snapshotRelative := ""
	if intent.AuthenticationStateDigest != "" {
		if _, snapshotExists, snapshotErr := readAuthenticationRecoverySecuritySnapshot(plan.Current.Root, intent, closure); snapshotErr != nil || !snapshotExists {
			return errors.Join(platformcommand.ErrEffectConflict, errors.New("authentication recovery security snapshot is unavailable"))
		}
		snapshotRelative = filepath.FromSlash(layout.IAMAuthenticationRecoverySecuritySnapshot(intent.CommandID))
	}
	digest, err := installationv1.AuthenticationRecoveryClosureDigest(closure)
	if err != nil {
		return errors.Join(platformcommand.ErrEffectVerification, err)
	}
	closureRelative := filepath.FromSlash(layout.IAMAuthenticationRecoveryClosure(intent.CommandID))
	output, err := effects.runAuthenticationRecoveryEntry(
		ctx, plan.Target, intent.CommandID, digest, closureRelative,
		installationv1.AuthenticationRecoveryReopenCommand, snapshotRelative,
	)
	if err != nil {
		return err
	}
	completion, err := installationv1.DecodeAuthenticationRecoveryCompletion(bytes.NewReader(output))
	clear(output)
	if err != nil || installationv1.ValidateAuthenticationRecoveryCompletionForClosure(completion, closure) != nil {
		return errors.Join(platformcommand.ErrEffectOutcomeUnknown, errors.New("authentication reopen result is unverifiable"))
	}
	return persistAuthenticationRecoveryCompletion(plan.Current.Root, intent, closure, completion)
}

func readAuthenticationRecoveryClosure(root, commandID string) (installationv1.AuthenticationRecoveryClosure, bool, error) {
	relative := filepath.FromSlash(layout.IAMAuthenticationRecoveryClosure(commandID))
	exists, err := managedFileExists(root, relative)
	if err != nil || !exists {
		return installationv1.AuthenticationRecoveryClosure{}, false, err
	}
	encoded, err := readManagedFile(root, relative, installationv1.MaximumAuthenticationRecoveryBytes)
	if err != nil {
		return installationv1.AuthenticationRecoveryClosure{}, true, err
	}
	defer clear(encoded)
	closure, err := installationv1.DecodeAuthenticationRecoveryClosure(bytes.NewReader(encoded))
	return closure, true, err
}

func readAuthenticationRecoverySecuritySnapshot(
	root string,
	intent installationv1.AuthenticationRecoveryIntent,
	closure installationv1.AuthenticationRecoveryClosure,
) (installationv1.AuthenticationRecoverySecuritySnapshot, bool, error) {
	if installationv1.ValidateCurrentAuthenticationRecoveryIntent(intent) != nil ||
		installationv1.ValidateCurrentAuthenticationRecoveryClosure(closure) != nil {
		return installationv1.AuthenticationRecoverySecuritySnapshot{}, false, errors.New("authentication recovery snapshot anchor is invalid")
	}
	relative := filepath.FromSlash(layout.IAMAuthenticationRecoverySecuritySnapshot(intent.CommandID))
	exists, err := managedFileExists(root, relative)
	if err != nil || !exists {
		return installationv1.AuthenticationRecoverySecuritySnapshot{}, false, err
	}
	encoded, err := readManagedFile(root, relative, installationv1.MaximumAuthenticationRecoverySecuritySnapshotBytes)
	if err != nil {
		return installationv1.AuthenticationRecoverySecuritySnapshot{}, true, err
	}
	defer clear(encoded)
	snapshot, err := installationv1.DecodeAuthenticationRecoverySecuritySnapshot(bytes.NewReader(encoded))
	if err != nil {
		return installationv1.AuthenticationRecoverySecuritySnapshot{}, true, err
	}
	sealedInstallationID, bootstrapDigest, err := sealedIAMBootstrapScope(root, intent.InstallationID)
	if err != nil || sealedInstallationID != intent.InstallationID {
		return installationv1.AuthenticationRecoverySecuritySnapshot{}, true, errors.New("authentication recovery installation scope differs")
	}
	envelope := installationv1.AuthenticationRecoveryClosureEnvelope{
		APIVersion:       installationv1.AuthenticationRecoveryAPIVersion,
		Kind:             installationv1.AuthenticationRecoveryClosureEnvelopeKind,
		Purpose:          installationv1.AuthenticationRecoveryPurpose,
		Closure:          closure,
		SecuritySnapshot: snapshot,
	}
	if installationv1.ValidateAuthenticationRecoveryClosureEnvelopeForIntent(envelope, intent, bootstrapDigest) != nil {
		return installationv1.AuthenticationRecoverySecuritySnapshot{}, true, errors.New("authentication recovery snapshot differs from its sealed intent")
	}
	return snapshot, true, nil
}

func readAuthenticationRecoveryIntent(root, commandID string) (installationv1.AuthenticationRecoveryIntent, error) {
	encoded, err := readManagedFile(root, filepath.FromSlash(layout.IAMAuthenticationRecoveryIntent(commandID)),
		installationv1.MaximumAuthenticationRecoveryBytes)
	if err != nil {
		return installationv1.AuthenticationRecoveryIntent{}, err
	}
	defer clear(encoded)
	return installationv1.DecodeAuthenticationRecoveryIntent(bytes.NewReader(encoded))
}

func readAuthenticationRecoveryCompletion(root string) (installationv1.AuthenticationRecoveryCompletion, []byte, bool, error) {
	relative := filepath.FromSlash(layout.IAMAuthenticationRecoveryCompletion)
	exists, err := managedFileExists(root, relative)
	if err != nil || !exists {
		return installationv1.AuthenticationRecoveryCompletion{}, nil, false, err
	}
	encoded, err := readManagedFile(root, relative, installationv1.MaximumAuthenticationRecoveryBytes)
	if err != nil {
		return installationv1.AuthenticationRecoveryCompletion{}, nil, true, err
	}
	completion, err := installationv1.DecodeAuthenticationRecoveryCompletion(bytes.NewReader(encoded))
	if err != nil {
		clear(encoded)
		return installationv1.AuthenticationRecoveryCompletion{}, nil, true, err
	}
	return completion, encoded, true, nil
}

func validateAuthenticationRecoveryAnchor(root string, intent installationv1.AuthenticationRecoveryIntent, allowCurrent bool) error {
	completion, encoded, exists, err := readAuthenticationRecoveryCompletion(root)
	defer clear(encoded)
	if err != nil {
		return err
	}
	if !exists {
		if intent.Epoch != 1 {
			return errors.New("authentication recovery completion anchor is missing")
		}
		return nil
	}
	closure, found, err := readAuthenticationRecoveryClosure(root, completion.CommandID)
	if err != nil || !found || installationv1.ValidateAuthenticationRecoveryCompletionForClosure(completion, closure) != nil ||
		completion.InstallationID != intent.InstallationID {
		return errors.New("authentication recovery completion anchor differs")
	}
	if closure.SecuritySnapshotDigest != "" {
		previousIntent, intentErr := readAuthenticationRecoveryIntent(root, completion.CommandID)
		if intentErr != nil {
			return errors.New("authentication recovery previous intent is unavailable")
		}
		if _, snapshotExists, snapshotErr := readAuthenticationRecoverySecuritySnapshot(root, previousIntent, closure); snapshotErr != nil || !snapshotExists {
			return errors.New("authentication recovery previous security snapshot is unavailable")
		}
	}
	if allowCurrent && completion.CommandID == intent.CommandID {
		if completion.Epoch != intent.Epoch {
			return errors.New("authentication recovery current completion differs")
		}
		return nil
	}
	if completion.CommandID == intent.CommandID || completion.Epoch == ^uint64(0) || completion.Epoch+1 != intent.Epoch {
		return errors.New("authentication recovery completion epoch differs")
	}
	return nil
}

func persistAuthenticationRecoveryCompletion(
	root string,
	intent installationv1.AuthenticationRecoveryIntent,
	closure installationv1.AuthenticationRecoveryClosure,
	completion installationv1.AuthenticationRecoveryCompletion,
) error {
	if installationv1.ValidateAuthenticationRecoveryCompletionForClosure(completion, closure) != nil ||
		completion.CommandID != intent.CommandID || completion.Epoch != intent.Epoch ||
		(closure.SecuritySnapshotDigest != "") != (intent.AuthenticationStateDigest != "") {
		return errors.Join(platformcommand.ErrEffectOutcomeUnknown, errors.New("authentication recovery completion conflicts"))
	}
	after, err := installationv1.EncodeAuthenticationRecoveryCompletion(completion)
	if err != nil {
		return errors.Join(platformcommand.ErrEffectOutcomeUnknown, err)
	}
	defer clear(after)
	previous, before, exists, err := readAuthenticationRecoveryCompletion(root)
	defer clear(before)
	if err != nil {
		return errors.Join(platformcommand.ErrEffectOutcomeUnknown, err)
	}
	if exists && previous == completion {
		return nil
	}
	relative := filepath.FromSlash(layout.IAMAuthenticationRecoveryCompletion)
	if !exists {
		if intent.Epoch != 1 || writeManagedOnce(root, relative, after) != nil {
			return errors.Join(platformcommand.ErrEffectOutcomeUnknown, errors.New("publish authentication recovery completion failed"))
		}
		return nil
	}
	previousClosure, found, err := readAuthenticationRecoveryClosure(root, previous.CommandID)
	if err != nil || !found || installationv1.ValidateAuthenticationRecoveryCompletionForClosure(previous, previousClosure) != nil ||
		previous.InstallationID != intent.InstallationID || previous.Epoch+1 != intent.Epoch {
		return errors.Join(platformcommand.ErrEffectConflict, errors.New("authentication recovery completion replacement conflicts"))
	}
	if err := replaceManagedExpected(root, relative, before, after); err != nil {
		return errors.Join(platformcommand.ErrEffectOutcomeUnknown, err)
	}
	return nil
}

func (effects *Effects) runAuthenticationRecoveryEntry(
	ctx context.Context,
	plan platformcommand.InstallPlan,
	commandID string,
	inputDigest string,
	inputRelative string,
	mode string,
	snapshotRelative string,
) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	arguments, expected, err := effects.authenticationRecoveryContainer(
		ctx, plan, commandID, inputDigest, inputRelative, mode, snapshotRelative,
	)
	if err != nil {
		return nil, err
	}
	for _, mount := range expected.service.Volumes {
		relative, err := filepath.Rel(plan.Root, mount.Source)
		if err != nil {
			return nil, platformcommand.ErrEffectVerification
		}
		maximum := int64(maximumCredentialFile)
		switch mount.Target {
		case "/run/matrix/authentication-recovery-input.json":
			maximum = installationv1.MaximumAuthenticationRecoveryBytes
		case "/run/matrix/authentication-recovery-security-snapshot.json":
			maximum = installationv1.MaximumAuthenticationRecoverySecuritySnapshotBytes
		}
		content, err := readManagedFile(plan.Root, relative, maximum)
		clear(content)
		if err != nil {
			return nil, platformcommand.ErrEffectVerification
		}
	}
	output, err := invokeAuthenticationRecoveryEntry(ctx, effects.runtime, arguments, expected)
	if err != nil {
		return nil, err
	}
	if int64(len(output)) > installationv1.MaximumAuthenticationRecoveryEnvelopeBytes {
		clear(output)
		return nil, platformcommand.ErrEffectOutcomeUnknown
	}
	return output, nil
}

func invokeAuthenticationRecoveryEntry(
	ctx context.Context,
	runtimeBoundary dockerRuntime,
	arguments []string,
	expected purposeOnlyIAMContainerExpectation,
) ([]byte, error) {
	current, exists, err := findPurposeOnlyIAMContainer(ctx, runtimeBoundary, expected)
	if err != nil {
		return nil, err
	}
	if exists {
		if current.State.Running || current.State.Status == "restarting" || current.State.Status == "paused" {
			return nil, platformcommand.ErrEffectOutcomeUnknown
		}
		if current.State.Status == "exited" && !current.State.OOMKilled && current.State.Error == "" {
			code := current.State.ExitCode
			if err := removePurposeOnlyIAMContainer(ctx, runtimeBoundary, current); err != nil {
				return nil, err
			}
			if code != 0 {
				return nil, authenticationRecoveryExitError(code)
			}
			exists = false
		} else if current.State.Status != "created" {
			return nil, platformcommand.ErrEffectOutcomeUnknown
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
		if err != nil || validatePurposeOnlyIAMContainer(current, expected) != nil || current.State.Status != "created" {
			return nil, platformcommand.ErrEffectOutcomeUnknown
		}
	}
	output, _, startErr := runtimeBoundary.Run(ctx, nil, "container", "start", "--attach", current.ID)
	completed, inspectErr := inspectPlatformContainer(ctx, runtimeBoundary, current.ID)
	if inspectErr != nil || validatePurposeOnlyIAMContainer(completed, expected) != nil || completed.State.Running ||
		completed.State.Status != "exited" || completed.State.OOMKilled || completed.State.Error != "" {
		clear(output)
		return nil, platformcommand.ErrEffectOutcomeUnknown
	}
	code := completed.State.ExitCode
	if err := removePurposeOnlyIAMContainer(ctx, runtimeBoundary, completed); err != nil {
		clear(output)
		return nil, err
	}
	if code != 0 {
		clear(output)
		return nil, authenticationRecoveryExitError(code)
	}
	if startErr != nil {
		clear(output)
		return nil, platformcommand.ErrEffectOutcomeUnknown
	}
	return output, nil
}

func authenticationRecoveryExitError(code int) error {
	switch code {
	case installationv1.AuthenticationRecoveryExitInvalid:
		return errors.Join(platformcommand.ErrEffectVerification, errors.New("authentication recovery input was rejected"))
	case installationv1.AuthenticationRecoveryExitForbidden:
		return errors.Join(platformcommand.ErrEffectPrecondition, errors.New("authentication recovery authority was rejected"))
	case installationv1.AuthenticationRecoveryExitConflict:
		return errors.Join(platformcommand.ErrEffectConflict, errors.New("authentication recovery intent conflicts"))
	default:
		return platformcommand.ErrEffectOutcomeUnknown
	}
}

func (effects *Effects) authenticationRecoveryContainer(
	ctx context.Context,
	plan platformcommand.InstallPlan,
	commandID string,
	inputDigest string,
	inputRelative string,
	mode string,
	snapshotRelative string,
) ([]string, purposeOnlyIAMContainerExpectation, error) {
	var expected purposeOnlyIAMContainerExpectation
	if mode != installationv1.AuthenticationRecoveryCloseCommand &&
		mode != installationv1.AuthenticationRecoveryReconcileCommand &&
		mode != installationv1.AuthenticationRecoveryReopenCommand {
		return nil, expected, platformcommand.ErrEffectVerification
	}
	if lifecycle.ValidateCommandID(commandID) != nil || plan.CorrelationID != commandID ||
		!validSHA256(inputDigest) || inputRelative == "" ||
		(mode == installationv1.AuthenticationRecoveryCloseCommand && snapshotRelative != "") {
		return nil, expected, platformcommand.ErrEffectVerification
	}
	configuration, err := verifiedInstallationConfiguration(plan)
	if err != nil {
		return nil, expected, platformcommand.ErrEffectVerification
	}
	networkID, err := controlNetworkID(ctx, effects.runtime, configuration.topology.ProjectName, plan.InstallationID, plan.Bundle.Manifest.Release.ID)
	if err != nil {
		return nil, expected, err
	}
	network, err := inspectPlatformNetwork(ctx, effects.runtime, networkID)
	if err != nil || !network.Internal || network.Name == "" {
		return nil, expected, platformcommand.ErrEffectVerification
	}
	imageID := ""
	for _, image := range plan.Bundle.Manifest.Images {
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
	expected.name = configuration.topology.ProjectName + "-iam-authentication-recovery-" + mode
	expected.mode, expected.entrypoint = mode, authenticationRecoveryEntrypoint
	expected.networkID, expected.networkName = networkID, network.Name
	expected.service = platformExpectedService{
		Image: imageID, User: "0:0", Restart: "no", ReadOnly: true,
		Networks: []string{"control"}, CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges:true"},
		Tmpfs: []string{"/tmp:rw,noexec,nosuid,size=64m"},
		Labels: map[string]string{
			"com.xiak.matrix.managed":      "true",
			"com.xiak.matrix.installation": plan.InstallationID,
			"com.xiak.matrix.release":      plan.Bundle.Manifest.Release.ID,
			"com.xiak.matrix.role":         "iam-authentication-recovery-" + mode,
			"com.xiak.matrix.command":      commandID,
			"com.xiak.matrix.input":        inputDigest,
		},
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
		{layout.IAMAuthenticationRecovery, "/run/matrix/authentication-recovery-dsn", installationv1.AuthenticationRecoveryDatabaseDSNFileEnvironment},
		{filepath.ToSlash(inputRelative), "/run/matrix/authentication-recovery-input.json", authenticationRecoveryInputEnvironment(mode)},
	}
	if snapshotRelative != "" {
		mounts = append(mounts, migrationMount{
			filepath.ToSlash(snapshotRelative),
			"/run/matrix/authentication-recovery-security-snapshot.json",
			installationv1.AuthenticationRecoverySecuritySnapshotFileEnvironment,
		})
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
	arguments = append(arguments, "--entrypoint", authenticationRecoveryEntrypoint, imageID, mode)
	return arguments, expected, nil
}

func authenticationRecoveryInputEnvironment(mode string) string {
	if mode == installationv1.AuthenticationRecoveryCloseCommand {
		return installationv1.AuthenticationRecoveryIntentFileEnvironment
	}
	return installationv1.AuthenticationRecoveryClosureFileEnvironment
}
