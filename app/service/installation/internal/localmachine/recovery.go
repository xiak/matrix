package localmachine

import (
	"bytes"
	"context"
	"errors"
	"io"
	"path/filepath"
	"strconv"
	"strings"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/installation/internal/layout"
	"github.com/xiak/matrix/app/service/installation/internal/platformcommand"
	"github.com/xiak/matrix/app/service/installation/release"
)

const (
	recoveryVerificationTenantID    = paasv1.TenantID("organization-default")
	recoveryVerificationComponent   = "probe"
	recoveryVerificationDownTimeout = "30"
)

type recoveryVerificationParticipant struct {
	release release.ReleaseIdentity
	imageID string
}

type recoveryVerificationInventory struct {
	container *platformContainerInspection
	network   *platformNetworkInspection
	volumes   int
}

// RecoveryProjectInspector is the installation-owned, read-only port used to
// prove one exact verification workload before recovery may remove it.
type RecoveryProjectInspector interface {
	InspectRecoveryProject(
		bindingRoot string,
		tenantID paasv1.TenantID,
		deploymentID paasv1.ResourceID,
	) (RecoveryProjectState, bool, error)
}

// RecoveryProjectState is provider-normalized, non-secret evidence for the
// fixed verification workload. Provider documents remain adapter-owned.
type RecoveryProjectState struct {
	ProjectName           string
	Directory             string
	EffectDocument        string
	ObservationDocument   string
	TenantID              paasv1.TenantID
	DeploymentID          paasv1.ResourceID
	Generation            uint64
	ApplicationRevisionID paasv1.ResourceID
	ContentDigest         string
	Services              []RecoveryProjectService
	SecretFileCount       int
}

type RecoveryProjectService struct {
	Name     string
	Image    string
	Replicas uint32
}

func recoverBackup(
	ctx context.Context,
	runtimeBoundary dockerRuntime,
	streaming streamingDockerRuntime,
	projectInspector RecoveryProjectInspector,
	plan platformcommand.RecoveryPlan,
) error {
	current, target, manifest, err := authenticateRecoveryPlan(plan)
	if err != nil {
		return err
	}
	defer clear(current.TrustBytes)
	defer clear(target.TrustBytes)
	for _, image := range target.Bundle.Manifest.Images {
		present, inspectErr := inspectExactImage(ctx, runtimeBoundary, image.ImageID)
		if inspectErr != nil {
			return inspectErr
		}
		if !present {
			return errors.Join(
				platformcommand.ErrEffectVerification,
				errors.New("recovery release image identity is absent"),
			)
		}
	}

	state, err := inspectUpgradeProject(ctx, runtimeBoundary, current, target)
	if err != nil {
		return err
	}
	if state.releaseID != "" {
		participant := current
		if state.releaseID == target.Bundle.Manifest.Release.ID &&
			state.releaseID != current.Bundle.Manifest.Release.ID {
			participant = target
		}
		if err := rollbackInstallation(ctx, runtimeBoundary, participant); err != nil {
			return err
		}
	}
	if err := removeRecoveredVerificationProject(
		ctx, runtimeBoundary, projectInspector, current, target,
	); err != nil {
		return err
	}
	if err := replaceReleaseConfiguration(
		plan.Current, current.Bundle.Manifest, target.Bundle.Manifest,
	); err != nil {
		return err
	}
	postgresID, err := startRecoveryPostgres(ctx, runtimeBoundary, target)
	if err != nil {
		return err
	}
	backupRelative := filepath.Join(
		filepath.FromSlash(layout.BackupDirectory), plan.BackupID,
	)
	dumpRelative := filepath.Join(backupRelative, databaseDumpFilename)
	if err := verifyDatabaseDump(
		ctx, streaming, plan.Current.Root, dumpRelative, postgresID,
	); err != nil {
		return err
	}
	if err := restoreDatabaseDump(
		ctx, streaming, plan.Current.Root, dumpRelative, postgresID,
	); err != nil {
		return err
	}
	if err := verifyWorkloadSecretRestore(
		plan.Current.Root,
		filepath.Join(backupRelative, workloadSecretsFilename),
		true,
	); err != nil {
		if errors.Is(err, errManagedOutcomeUnknown) {
			return errors.Join(platformcommand.ErrEffectOutcomeUnknown, err)
		}
		return errors.Join(platformcommand.ErrEffectConflict, err)
	}
	profile, profileErr := manifest.databaseProfile()
	if profileErr != nil || profile != target.Bundle.Manifest.Database {
		return errors.Join(
			platformcommand.ErrEffectVerification,
			errors.New("recovery schema identity changed"),
		)
	}
	return migrateInstallation(ctx, runtimeBoundary, target)
}

func removeRecoveredVerificationProject(
	ctx context.Context,
	runtimeBoundary dockerRuntime,
	projectInspector RecoveryProjectInspector,
	current platformcommand.InstallPlan,
	target platformcommand.InstallPlan,
) error {
	deploymentID, err := paasv1.InstallationVerificationDeploymentID(current.InstallationID)
	if err != nil {
		return recoveryVerificationConflict()
	}
	executorRoot, err := managedPath(
		current.Root, filepath.FromSlash(layout.ExecutorRoot),
	)
	if err != nil {
		return recoveryVerificationConflict()
	}
	state, exists, err := projectInspector.InspectRecoveryProject(
		executorRoot, recoveryVerificationTenantID, deploymentID,
	)
	if err != nil || validateRecoveryProjectIdentity(
		executorRoot, state, recoveryVerificationTenantID, deploymentID,
	) != nil {
		return recoveryVerificationConflict()
	}
	inventory, err := inspectRecoveryVerificationInventory(
		ctx, runtimeBoundary, state.ProjectName,
	)
	if err != nil {
		return err
	}
	if !exists {
		if inventory.container != nil || inventory.network != nil || inventory.volumes != 0 {
			return recoveryVerificationConflict()
		}
		return nil
	}
	participants, err := recoveryVerificationParticipants(current, target)
	if err != nil || validateRecoveryVerificationState(state, participants) != nil {
		return recoveryVerificationConflict()
	}
	if err := validateRecoveryVerificationInventory(
		ctx, runtimeBoundary, current.InstallationID, state, inventory, participants, false,
	); err != nil {
		return err
	}
	if inventory.container != nil || inventory.network != nil {
		_, started, downErr := runtimeBoundary.Run(
			ctx, nil,
			"compose", "--ansi", "never", "--progress", "quiet",
			"--project-name", state.ProjectName,
			"--project-directory", state.Directory,
			"--file", state.ObservationDocument,
			"down", "--remove-orphans", "--timeout", recoveryVerificationDownTimeout,
		)
		remaining, observeErr := inspectRecoveryVerificationInventory(
			ctx, runtimeBoundary, state.ProjectName,
		)
		if observeErr != nil {
			if started {
				return errors.Join(
					platformcommand.ErrEffectOutcomeUnknown,
					errors.New("verification project cleanup outcome is unknown"),
				)
			}
			return observeErr
		}
		if remaining.container != nil || remaining.network != nil || remaining.volumes != 0 {
			if started {
				return errors.Join(
					platformcommand.ErrEffectOutcomeUnknown,
					errors.New("verification project cleanup outcome is unknown"),
				)
			}
			return errors.Join(
				platformcommand.ErrEffectUnavailable,
				errors.New("verification project cleanup did not start"),
			)
		}
		if downErr != nil && !started {
			return errors.Join(
				platformcommand.ErrEffectUnavailable,
				errors.New("verification project cleanup did not start"),
			)
		}
	}
	return removeRecoveredVerificationState(
		current.Root, executorRoot, projectInspector, state,
	)
}

func verifyRecoveredVerificationProject(
	ctx context.Context,
	runtimeBoundary dockerRuntime,
	projectInspector RecoveryProjectInspector,
	target platformcommand.InstallPlan,
	verification paasv1.InstallationVerification,
) error {
	expectedDeploymentID, err := paasv1.InstallationVerificationDeploymentID(target.InstallationID)
	if err != nil || verification.DeploymentID != expectedDeploymentID ||
		verification.Generation == 0 {
		return recoveryVerificationFailure()
	}
	executorRoot, err := managedPath(
		target.Root, filepath.FromSlash(layout.ExecutorRoot),
	)
	if err != nil {
		return recoveryVerificationFailure()
	}
	state, exists, err := projectInspector.InspectRecoveryProject(
		executorRoot, recoveryVerificationTenantID, expectedDeploymentID,
	)
	if err != nil || validateRecoveryProjectIdentity(
		executorRoot, state, recoveryVerificationTenantID, expectedDeploymentID,
	) != nil || !exists || state.Generation != verification.Generation {
		return recoveryVerificationFailure()
	}
	participants, err := recoveryVerificationParticipants(target)
	if err != nil || validateRecoveryVerificationState(state, participants) != nil {
		return recoveryVerificationFailure()
	}
	inventory, err := inspectRecoveryVerificationInventory(
		ctx, runtimeBoundary, state.ProjectName,
	)
	if err != nil {
		return err
	}
	if inventory.container == nil || inventory.network == nil || inventory.volumes != 0 {
		return recoveryVerificationFailure()
	}
	if err := validateRecoveryVerificationInventory(
		ctx, runtimeBoundary, target.InstallationID, state, inventory, participants, true,
	); err != nil {
		return err
	}
	return nil
}

func recoveryVerificationParticipants(
	plans ...platformcommand.InstallPlan,
) ([]recoveryVerificationParticipant, error) {
	participants := make([]recoveryVerificationParticipant, 0, len(plans))
	seen := make(map[string]struct{}, len(plans))
	for _, plan := range plans {
		imageID := ""
		for _, image := range plan.Bundle.Manifest.Images {
			if image.Component != "verification" {
				continue
			}
			if imageID != "" || image.ImageID == "" {
				return nil, errors.New("verification release image identity conflicts")
			}
			imageID = image.ImageID
		}
		if imageID == "" {
			return nil, errors.New("verification release image identity is absent")
		}
		key := plan.Bundle.Manifest.Release.ID + "\x00" + imageID
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		participants = append(participants, recoveryVerificationParticipant{
			release: plan.Bundle.Manifest.Release,
			imageID: imageID,
		})
	}
	if len(participants) == 0 {
		return nil, errors.New("verification recovery participant is absent")
	}
	return participants, nil
}

func validateRecoveryProjectIdentity(
	executorRoot string,
	state RecoveryProjectState,
	tenantID paasv1.TenantID,
	deploymentID paasv1.ResourceID,
) error {
	if state.TenantID != tenantID || state.DeploymentID != deploymentID ||
		state.ProjectName == "" || state.ProjectName == "." || state.ProjectName == ".." ||
		filepath.Base(state.ProjectName) != state.ProjectName ||
		paasv1.ValidateSafeExternalText(
			"projectName", state.ProjectName, 128, true,
		) != nil {
		return errors.New("verification project identity conflicts")
	}
	directory := filepath.Join(executorRoot, "projects", state.ProjectName)
	if state.Directory != directory || filepath.Clean(state.Directory) != state.Directory ||
		state.EffectDocument != filepath.Join(directory, "compose.json") ||
		state.ObservationDocument != filepath.Join(directory, "observe.json") {
		return errors.New("verification project path conflicts")
	}
	return nil
}

func validateRecoveryVerificationState(
	state RecoveryProjectState,
	participants []recoveryVerificationParticipant,
) error {
	if state.TenantID != recoveryVerificationTenantID || state.Generation == 0 ||
		state.SecretFileCount != 0 || len(state.Services) != 1 ||
		state.Services[0].Name != recoveryVerificationComponent ||
		state.Services[0].Replicas != 1 {
		return errors.New("verification project state conflicts")
	}
	for _, participant := range participants {
		if state.Services[0].Image == participant.imageID {
			return nil
		}
	}
	return errors.New("verification project image is not a recovery participant")
}

func inspectRecoveryVerificationInventory(
	ctx context.Context,
	runtimeBoundary dockerRuntime,
	project string,
) (recoveryVerificationInventory, error) {
	containers, err := listProjectObjects(ctx, runtimeBoundary, "container", project)
	if err != nil {
		return recoveryVerificationInventory{}, err
	}
	networks, err := listProjectObjects(ctx, runtimeBoundary, "network", project)
	if err != nil {
		return recoveryVerificationInventory{}, err
	}
	volumes, err := listProjectObjects(ctx, runtimeBoundary, "volume", project)
	if err != nil {
		return recoveryVerificationInventory{}, err
	}
	if len(containers) > 1 || len(networks) > 1 || len(volumes) != 0 ||
		(len(containers) == 1 && len(networks) != 1) {
		return recoveryVerificationInventory{}, recoveryVerificationConflict()
	}
	result := recoveryVerificationInventory{volumes: len(volumes)}
	if len(containers) == 1 {
		inspection, err := inspectPlatformContainer(ctx, runtimeBoundary, containers[0])
		if err != nil {
			return recoveryVerificationInventory{}, err
		}
		result.container = &inspection
	}
	if len(networks) == 1 {
		inspection, err := inspectPlatformNetwork(ctx, runtimeBoundary, networks[0])
		if err != nil {
			return recoveryVerificationInventory{}, err
		}
		result.network = &inspection
	}
	return result, nil
}

func validateRecoveryVerificationInventory(
	ctx context.Context,
	runtimeBoundary dockerRuntime,
	installationID string,
	state RecoveryProjectState,
	inventory recoveryVerificationInventory,
	participants []recoveryVerificationParticipant,
	requireReady bool,
) error {
	if inventory.volumes != 0 {
		return recoveryVerificationFailure()
	}
	if inventory.network != nil && validateRecoveryVerificationNetwork(
		state, *inventory.network,
	) != nil {
		return recoveryVerificationConflict()
	}
	if inventory.container == nil {
		if requireReady {
			return recoveryVerificationFailure()
		}
		return nil
	}
	if inventory.network == nil {
		return recoveryVerificationConflict()
	}
	services := map[string]platformExpectedService{
		recoveryVerificationComponent: {Image: state.Services[0].Image},
	}
	if err := loadPlatformServiceHashes(
		ctx, runtimeBoundary, state.EffectDocument, state.ProjectName, services,
	); err != nil {
		return err
	}
	if err := validateRecoveryVerificationContainer(
		installationID, state, *inventory.container, *inventory.network,
		participants, services[recoveryVerificationComponent].ConfigHash, requireReady,
	); err != nil {
		if requireReady {
			return recoveryVerificationFailure()
		}
		return recoveryVerificationConflict()
	}
	return nil
}

func validateRecoveryVerificationContainer(
	installationID string,
	state RecoveryProjectState,
	container platformContainerInspection,
	network platformNetworkInspection,
	participants []recoveryVerificationParticipant,
	configHash string,
	requireReady bool,
) error {
	labels := container.Config.Labels
	if container.Image != state.Services[0].Image ||
		labels["com.docker.compose.project"] != state.ProjectName ||
		labels["com.docker.compose.service"] != recoveryVerificationComponent ||
		!strings.EqualFold(labels["com.docker.compose.oneoff"], "false") ||
		labels["com.docker.compose.container-number"] != "1" ||
		labels["com.docker.compose.project.config_files"] != state.EffectDocument ||
		labels["com.docker.compose.project.working_dir"] != state.Directory ||
		labels["com.docker.compose.config-hash"] != configHash ||
		labels["com.xiak.matrix.application-revision-id"] != string(state.ApplicationRevisionID) ||
		labels["com.xiak.matrix.component"] != recoveryVerificationComponent ||
		labels["com.xiak.matrix.content-digest"] != state.ContentDigest ||
		labels["com.xiak.matrix.deployment-id"] != string(state.DeploymentID) ||
		labels["com.xiak.matrix.generation"] != strconv.FormatUint(state.Generation, 10) ||
		labels["com.xiak.matrix.tenant-id"] != string(state.TenantID) {
		return errors.New("verification container identity conflicts")
	}
	participant, found := recoveryVerificationContainerParticipant(
		installationID, container, participants,
	)
	if !found {
		return errors.New("verification container release identity conflicts")
	}
	for key, value := range release.BuiltImageLabels(participant.release, "verification") {
		if key == release.BuiltImageLabelComponent {
			continue
		}
		if labels[key] != value {
			return errors.New("verification container build identity conflicts")
		}
	}
	if container.HostConfig.Privileged || len(container.Mounts) != 0 ||
		container.HostConfig.NetworkMode != state.ProjectName+"_default" ||
		container.HostConfig.NanoCPUs != 50*1_000_000 ||
		container.HostConfig.Memory != 64*1024*1024 ||
		len(platformPortInventory(container.HostConfig.PortBindings)) != 0 ||
		len(platformPortInventory(container.NetworkSettings.Ports)) != 0 {
		return errors.New("verification container isolation conflicts")
	}
	if len(container.NetworkSettings.Networks) != 1 {
		return errors.New("verification project network identity conflicts")
	}
	for name, attachment := range container.NetworkSettings.Networks {
		if name != network.Name || attachment.NetworkID != network.ID {
			return errors.New("verification container network membership conflicts")
		}
	}
	if requireReady && (!container.State.Running || container.State.Status != "running" ||
		(container.State.Health != nil && container.State.Health.Status != "healthy")) {
		return errors.New("verification container is not ready")
	}
	return nil
}

func validateRecoveryVerificationNetwork(
	state RecoveryProjectState,
	network platformNetworkInspection,
) error {
	if network.Name != state.ProjectName+"_default" || network.Internal ||
		network.Labels["com.docker.compose.project"] != state.ProjectName ||
		network.Labels["com.docker.compose.network"] != "default" {
		return errors.New("verification project network identity conflicts")
	}
	return nil
}

func recoveryVerificationContainerParticipant(
	installationID string,
	container platformContainerInspection,
	participants []recoveryVerificationParticipant,
) (recoveryVerificationParticipant, bool) {
	values := make(map[string]string)
	for _, entry := range container.Config.Env {
		key, value, found := strings.Cut(entry, "=")
		if !found || !strings.HasPrefix(key, "MATRIX_") {
			continue
		}
		if _, duplicate := values[key]; duplicate {
			return recoveryVerificationParticipant{}, false
		}
		values[key] = value
	}
	if len(values) != 2 || values["MATRIX_INSTALLATION_ID"] != installationID {
		return recoveryVerificationParticipant{}, false
	}
	for _, participant := range participants {
		if participant.imageID == container.Image &&
			participant.release.ID == values["MATRIX_RELEASE_ID"] {
			return participant, true
		}
	}
	return recoveryVerificationParticipant{}, false
}

func removeRecoveredVerificationState(
	installationRoot string,
	executorRoot string,
	projectInspector RecoveryProjectInspector,
	state RecoveryProjectState,
) error {
	relative, err := filepath.Rel(installationRoot, state.Directory)
	if err != nil || relative != filepath.Join(
		filepath.FromSlash(layout.ExecutorRoot), "projects", state.ProjectName,
	) {
		return recoveryVerificationConflict()
	}
	if err := removeManagedTree(installationRoot, relative); err != nil {
		return errors.Join(
			platformcommand.ErrEffectOutcomeUnknown,
			errors.New("verification project state cleanup outcome is unknown"),
		)
	}
	verificationState, exists, err := projectInspector.InspectRecoveryProject(
		executorRoot, state.TenantID, state.DeploymentID,
	)
	if err != nil || exists || verificationState.ProjectName != state.ProjectName {
		return errors.Join(
			platformcommand.ErrEffectOutcomeUnknown,
			errors.New("verification project state cleanup outcome is unknown"),
		)
	}
	return nil
}

func recoveryVerificationConflict() error {
	return errors.Join(
		platformcommand.ErrEffectConflict,
		errors.New("verification project is not the fixed recovery probe"),
	)
}

func recoveryVerificationFailure() error {
	return errors.Join(
		platformcommand.ErrEffectVerification,
		errors.New("recovered verification project did not converge"),
	)
}

func authenticateRecoveryPlan(
	plan platformcommand.RecoveryPlan,
) (platformcommand.InstallPlan, platformcommand.InstallPlan, backupManifest, error) {
	if plan.Current.Root == "" || plan.Current.Root != plan.Target.Root ||
		plan.Current.InstallationID == "" ||
		plan.Current.InstallationID != plan.Target.InstallationID ||
		plan.Current.CorrelationID == "" ||
		plan.Current.CorrelationID != plan.Target.CorrelationID ||
		plan.Current.Listener != plan.Target.Listener || plan.Current.Port != plan.Target.Port ||
		plan.Current.Trust != plan.Target.Trust ||
		!bytes.Equal(plan.Current.TrustBytes, plan.Target.TrustBytes) ||
		!backupIDPattern.MatchString(plan.BackupID) || !validSHA256(plan.BackupDigest) {
		return platformcommand.InstallPlan{}, platformcommand.InstallPlan{}, backupManifest{},
			errors.Join(
				platformcommand.ErrEffectVerification,
				errors.New("recovery plan identity is invalid"),
			)
	}
	currentBundle, err := verifiedStagedBundle(plan.Current)
	if err != nil {
		return platformcommand.InstallPlan{}, platformcommand.InstallPlan{}, backupManifest{},
			errors.Join(platformcommand.ErrEffectVerification, err)
	}
	targetBundle, err := verifiedStagedBundle(plan.Target)
	if err != nil {
		return platformcommand.InstallPlan{}, platformcommand.InstallPlan{}, backupManifest{},
			errors.Join(platformcommand.ErrEffectVerification, err)
	}
	if currentBundle.Manifest.Database != targetBundle.Manifest.Database {
		return platformcommand.InstallPlan{}, platformcommand.InstallPlan{}, backupManifest{},
			errors.Join(
				platformcommand.ErrEffectVerification,
				errors.New("recovery database profiles are incompatible"),
			)
	}
	current := plan.Current
	current.Bundle = currentBundle
	current.TrustBytes = append([]byte(nil), plan.Current.TrustBytes...)
	target := plan.Target
	target.Bundle = targetBundle
	target.TrustBytes = append([]byte(nil), plan.Target.TrustBytes...)
	key, err := loadBackupSealKey(plan.Current.Root, nil, false)
	if err != nil {
		clear(current.TrustBytes)
		clear(target.TrustBytes)
		return platformcommand.InstallPlan{}, platformcommand.InstallPlan{}, backupManifest{}, err
	}
	defer clear(key)
	relative := filepath.Join(
		filepath.FromSlash(layout.BackupDirectory), plan.BackupID,
	)
	manifest, digest, err := readVerifiedBackupDirectory(
		plan.Current.Root, plan.Current.InstallationID, plan.BackupID, relative, key,
	)
	profile, profileErr := manifest.databaseProfile()
	if err != nil || profileErr != nil || digest != plan.BackupDigest ||
		manifest.ReleaseID != target.Bundle.Manifest.Release.ID ||
		manifest.ReleaseDigest != target.Bundle.ManifestSHA256 ||
		profile != target.Bundle.Manifest.Database {
		clear(current.TrustBytes)
		clear(target.TrustBytes)
		return platformcommand.InstallPlan{}, platformcommand.InstallPlan{}, backupManifest{},
			errors.Join(
				platformcommand.ErrEffectVerification,
				errors.New("recovery backup differs from its durable command"),
			)
	}
	if err := verifyWorkloadSecretRestore(
		plan.Current.Root, filepath.Join(relative, workloadSecretsFilename), false,
	); err != nil {
		clear(current.TrustBytes)
		clear(target.TrustBytes)
		return platformcommand.InstallPlan{}, platformcommand.InstallPlan{}, backupManifest{},
			errors.Join(platformcommand.ErrEffectConflict, err)
	}
	return current, target, manifest, nil
}

func startRecoveryPostgres(
	ctx context.Context,
	runtimeBoundary dockerRuntime,
	target platformcommand.InstallPlan,
) (string, error) {
	installation, err := verifiedInstallationConfiguration(target)
	if err != nil {
		return "", errors.Join(platformcommand.ErrEffectVerification, err)
	}
	_, started, runErr := runtimeBoundary.Run(
		ctx, nil,
		"compose", "--file", installation.composePath,
		"--project-name", installation.topology.ProjectName,
		"up", "--detach", "--wait", "--wait-timeout", migrationWaitSeconds,
		"--no-build", "--pull", "never", "postgres",
	)
	postgresID, observeErr := observeRecoveryPostgres(ctx, runtimeBoundary, target)
	if runErr == nil && observeErr == nil {
		return postgresID, nil
	}
	if !started {
		return "", errors.Join(platformcommand.ErrEffectUnavailable, runErr)
	}
	if observeErr == nil {
		return postgresID, nil
	}
	if errors.Is(observeErr, platformcommand.ErrEffectConflict) ||
		errors.Is(observeErr, platformcommand.ErrEffectVerification) {
		return "", observeErr
	}
	if ctx.Err() != nil {
		return "", errors.Join(platformcommand.ErrEffectOutcomeUnknown, ctx.Err())
	}
	return "", errors.Join(
		platformcommand.ErrEffectOutcomeUnknown, runErr, observeErr,
	)
}

func observeRecoveryPostgres(
	ctx context.Context,
	runtimeBoundary dockerRuntime,
	target platformcommand.InstallPlan,
) (string, error) {
	_, expectation, err := preparePlatformExpectation(ctx, runtimeBoundary, target)
	if err != nil {
		return "", err
	}
	observation, exists, err := inspectOwnedPlatformProject(ctx, runtimeBoundary, expectation)
	if err != nil {
		return "", err
	}
	postgres, found := observation.Containers["postgres"]
	if !exists || !found || len(observation.Containers) != 1 || postgres.ID == "" {
		return "", errors.Join(
			platformcommand.ErrEffectVerification,
			errors.New("recovery PostgreSQL topology is incomplete"),
		)
	}
	networkIDs := make(map[string]string, len(observation.Networks))
	for logicalName, network := range observation.Networks {
		networkIDs[logicalName] = network.ID
	}
	if err := validatePlatformContainer(
		postgres, expectation.Services["postgres"], networkIDs,
	); err != nil || !postgres.State.Running || postgres.State.Status != "running" ||
		postgres.State.Health == nil || postgres.State.Health.Status != "healthy" {
		return "", errors.Join(
			platformcommand.ErrEffectVerification,
			errors.New("recovery PostgreSQL service is not healthy and owned"),
		)
	}
	return postgres.ID, nil
}

func restoreDatabaseDump(
	ctx context.Context,
	runtimeBoundary streamingDockerRuntime,
	root string,
	relative string,
	postgresID string,
) error {
	target, err := managedPath(root, relative)
	if err != nil {
		return errors.Join(platformcommand.ErrEffectVerification, err)
	}
	file, err := openManagedRegularNoFollow(target)
	if err != nil {
		return errors.Join(platformcommand.ErrEffectVerification, err)
	}
	defer file.Close()
	started, err := runtimeBoundary.RunTo(
		ctx, file, io.Discard,
		"exec", "--interactive", "--user", "postgres", postgresID,
		"pg_restore", "--clean", "--if-exists", "--exit-on-error",
		// The authenticated custom archive carries the exact IAM/Audit owner
		// roles. Restoring those owners is required before their non-superuser
		// migrators can converge functions and tables. ACLs remain release-owned
		// and are intentionally reapplied by the target migration binaries.
		"--single-transaction", "--no-privileges", "--no-password",
		"--username", "matrix", "--dbname", "matrix",
	)
	if err == nil {
		return nil
	}
	if !started {
		return errors.Join(platformcommand.ErrEffectUnavailable, err)
	}
	if ctx.Err() != nil {
		return errors.Join(platformcommand.ErrEffectOutcomeUnknown, ctx.Err())
	}
	return errors.Join(
		platformcommand.ErrEffectVerification,
		errors.New("PostgreSQL backup recovery failed"),
	)
}

func verifyRecoveredInstallation(
	ctx context.Context,
	runtimeBoundary dockerRuntime,
	verifier installationVerifier,
	projectInspector RecoveryProjectInspector,
	plan platformcommand.RecoveryPlan,
) error {
	current, target, _, err := authenticateRecoveryPlan(plan)
	if err != nil {
		return err
	}
	defer clear(current.TrustBytes)
	defer clear(target.TrustBytes)
	installation, _, _, err := inspectReadyInstalledPlatform(
		ctx, runtimeBoundary, target,
	)
	if err != nil {
		return err
	}
	if err := verifyInstallationMigrations(
		ctx, runtimeBoundary, target, installation,
	); err != nil {
		return err
	}
	verification, err := verifier.Verify(ctx, target)
	if err != nil {
		return err
	}
	return verifyRecoveredVerificationProject(
		ctx, runtimeBoundary, projectInspector, target, verification,
	)
}
