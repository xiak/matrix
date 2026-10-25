package localmachine

import (
	"bytes"
	"context"
	"errors"

	"github.com/xiak/matrix/app/service/installation/internal/platformcommand"
	"github.com/xiak/matrix/app/service/installation/release"
	"github.com/xiak/matrix/app/service/installation/topology"
)

type upgradeProjectState struct {
	releaseID   string
	projectName string
	project     platformProjectObservation
}

// startUpgrade converges only from a wholly source-owned, wholly target-owned,
// or absent fixed project. Source objects are removed through the same exact
// ownership proof used by failed-install cleanup before target Compose starts.
func startUpgrade(
	ctx context.Context,
	runtimeBoundary dockerRuntime,
	plan platformcommand.UpgradePlan,
) error {
	source, err := authenticateInstalledPlan(plan.Source)
	if err != nil {
		return errors.Join(platformcommand.ErrEffectVerification, err)
	}
	defer clear(source.TrustBytes)
	if err := validateUpgradeIdentity(source, plan.Target); err != nil {
		return errors.Join(platformcommand.ErrEffectVerification, err)
	}
	targetInstallation, err := verifiedInstallationConfiguration(plan.Target)
	if err != nil {
		return errors.Join(platformcommand.ErrEffectVerification, err)
	}
	target := plan.Target
	target.Bundle = targetInstallation.bundle
	for _, image := range target.Bundle.Manifest.Images {
		_, present, inspectErr := inspectInstalledReleaseImage(ctx, runtimeBoundary, image)
		if inspectErr != nil {
			return inspectErr
		}
		if !present {
			return errors.Join(
				platformcommand.ErrEffectVerification,
				errors.New("upgrade target image identity is absent"),
			)
		}
	}

	state, err := inspectUpgradeProject(ctx, runtimeBoundary, source, target)
	if err != nil {
		return err
	}
	switch state.releaseID {
	case source.Bundle.Manifest.Release.ID:
		if err := rollbackInstallation(ctx, runtimeBoundary, source); err != nil {
			return err
		}
	case target.Bundle.Manifest.Release.ID, "":
		// A replay can observe a complete/partial target or the deliberate gap
		// after source cleanup. startInstallation observes before converging.
	default:
		return errors.Join(
			platformcommand.ErrEffectConflict,
			errors.New("platform project release is not an upgrade participant"),
		)
	}
	return startInstallation(ctx, runtimeBoundary, target)
}

// rollbackUpgrade removes only a fully authenticated target candidate, puts
// the source configuration back, and proves the previous release healthy. It
// intentionally preserves PostgreSQL data, release media, backups, and every
// non-platform Compose project.
func rollbackUpgrade(
	ctx context.Context,
	runtimeBoundary dockerRuntime,
	verifier installationVerifier,
	plan platformcommand.UpgradePlan,
) error {
	return rollbackUpgradeWithVerifier(
		ctx, runtimeBoundary, verifier, plan, release.VerifyDirectory,
	)
}

func rollbackUpgradeWithVerifier(
	ctx context.Context,
	runtimeBoundary dockerRuntime,
	verifier installationVerifier,
	plan platformcommand.UpgradePlan,
	verifyDirectory releaseDirectoryVerifier,
) error {
	previous, err := authenticateRollbackPredecessorWithVerifier(
		platformcommand.RollbackPlan{Current: plan.Target, Previous: plan.Source},
		verifyDirectory,
	)
	if err != nil {
		return err
	}
	defer clear(previous.TrustBytes)
	if err := prepareReleaseRollbackWithAuthenticatedPredecessor(
		ctx, runtimeBoundary, previous, plan.Target, verifyDirectory,
	); err != nil {
		return err
	}
	if err := startAuthenticatedPreviousRelease(
		ctx, runtimeBoundary, previous,
	); err != nil {
		return err
	}
	return verifyAuthenticatedPreviousRelease(
		ctx, runtimeBoundary, verifier, previous,
	)
}

func prepareReleaseRollback(
	ctx context.Context,
	runtimeBoundary dockerRuntime,
	plan platformcommand.RollbackPlan,
) error {
	previous, err := authenticateRollbackPredecessor(plan)
	if err != nil {
		return err
	}
	defer clear(previous.TrustBytes)
	return prepareReleaseRollbackWithAuthenticatedPredecessor(
		ctx, runtimeBoundary, previous, plan.Current, release.VerifyDirectory,
	)
}

func prepareReleaseRollbackWithAuthenticatedPredecessor(
	ctx context.Context,
	runtimeBoundary dockerRuntime,
	previous platformcommand.InstallPlan,
	current platformcommand.InstallPlan,
	verifyDirectory releaseDirectoryVerifier,
) error {
	state, err := inspectUpgradeProject(ctx, runtimeBoundary, previous, current)
	if err != nil {
		return err
	}
	switch state.releaseID {
	case current.Bundle.Manifest.Release.ID:
		bundle, verifyErr := verifiedStagedBundleWithVerifier(current, verifyDirectory)
		if verifyErr != nil {
			return errors.Join(platformcommand.ErrEffectVerification, verifyErr)
		}
		current.Bundle = bundle
		if err := rollbackInstallation(ctx, runtimeBoundary, current); err != nil {
			return err
		}
	case previous.Bundle.Manifest.Release.ID, "":
		if err := removeUpgradeMigrationContainers(
			ctx, runtimeBoundary, current, state.projectName, state.project,
		); err != nil {
			return err
		}
	default:
		return errors.Join(
			platformcommand.ErrEffectConflict,
			errors.New("platform project release is not an upgrade participant"),
		)
	}

	return restoreAuthenticatedUpgradeConfiguration(previous, current)
}

func startPreviousRelease(
	ctx context.Context,
	runtimeBoundary dockerRuntime,
	plan platformcommand.RollbackPlan,
) error {
	previous, err := authenticateRollbackPredecessor(plan)
	if err != nil {
		return err
	}
	defer clear(previous.TrustBytes)
	return startAuthenticatedPreviousRelease(ctx, runtimeBoundary, previous)
}

func startAuthenticatedPreviousRelease(
	ctx context.Context,
	runtimeBoundary dockerRuntime,
	previous platformcommand.InstallPlan,
) error {
	return startAuthenticatedInstallation(ctx, runtimeBoundary, previous)
}

func verifyPreviousRelease(
	ctx context.Context,
	runtimeBoundary dockerRuntime,
	verifier installationVerifier,
	plan platformcommand.RollbackPlan,
) error {
	previous, err := authenticateRollbackPredecessor(plan)
	if err != nil {
		return err
	}
	defer clear(previous.TrustBytes)
	return verifyAuthenticatedPreviousRelease(ctx, runtimeBoundary, verifier, previous)
}

func verifyAuthenticatedPreviousRelease(
	ctx context.Context,
	runtimeBoundary dockerRuntime,
	verifier installationVerifier,
	previous platformcommand.InstallPlan,
) error {
	installation, _, _, err := inspectReadyAuthenticatedPlatform(
		ctx, runtimeBoundary, previous,
	)
	if err != nil {
		return err
	}
	if err := verifyInstallationMigrations(
		ctx, runtimeBoundary, previous, installation,
	); err != nil {
		return err
	}
	_, err = verifier.Verify(ctx, previous)
	return err
}

func authenticateRollbackPredecessor(
	plan platformcommand.RollbackPlan,
) (platformcommand.InstallPlan, error) {
	return authenticateRollbackPredecessorWithVerifier(plan, release.VerifyDirectory)
}

func authenticateRollbackPredecessorWithVerifier(
	plan platformcommand.RollbackPlan,
	verifyDirectory releaseDirectoryVerifier,
) (platformcommand.InstallPlan, error) {
	previous, err := authenticateInstalledPlanWithVerifier(plan.Previous, verifyDirectory)
	if err != nil {
		return platformcommand.InstallPlan{}, errors.Join(platformcommand.ErrEffectVerification, err)
	}
	if err := validateUpgradeIdentity(previous, plan.Current); err != nil {
		clear(previous.TrustBytes)
		return platformcommand.InstallPlan{}, errors.Join(platformcommand.ErrEffectVerification, err)
	}
	return previous, nil
}

func validateUpgradeIdentity(
	source platformcommand.InstallPlan,
	target platformcommand.InstallPlan,
) error {
	if source.Root != target.Root ||
		source.InstallationID != target.InstallationID ||
		source.CorrelationID == "" || source.CorrelationID != target.CorrelationID ||
		source.Listener != target.Listener || source.Port != target.Port ||
		source.NorthboundOrigin == "" || source.NorthboundOrigin != target.NorthboundOrigin ||
		source.Trust != target.Trust ||
		!bytes.Equal(source.TrustBytes, target.TrustBytes) ||
		target.Bundle.Manifest.Release.ID == source.Bundle.Manifest.Release.ID ||
		target.Bundle.Manifest.Release.PreviousID != source.Bundle.Manifest.Release.ID ||
		target.Bundle.Manifest.Release.PreviousVersion != source.Bundle.Manifest.Release.Version ||
		target.Bundle.Manifest.Database != source.Bundle.Manifest.Database {
		return errors.New("upgrade source and target identities are inconsistent")
	}
	return nil
}

func inspectUpgradeProject(
	ctx context.Context,
	runtimeBoundary dockerRuntime,
	source platformcommand.InstallPlan,
	target platformcommand.InstallPlan,
) (upgradeProjectState, error) {
	sourceExpectation, err := compileUpgradeExpectation(source)
	if err != nil {
		return upgradeProjectState{}, err
	}
	targetExpectation, err := compileUpgradeExpectation(target)
	if err != nil || targetExpectation.Name != sourceExpectation.Name {
		return upgradeProjectState{}, errors.Join(
			platformcommand.ErrEffectVerification,
			errors.New("upgrade project identity changed"),
		)
	}
	state := upgradeProjectState{projectName: sourceExpectation.Name}
	containers, err := listProjectObjects(
		ctx, runtimeBoundary, "container", state.projectName,
	)
	if err != nil {
		return upgradeProjectState{}, err
	}
	networks, err := listProjectObjects(
		ctx, runtimeBoundary, "network", state.projectName,
	)
	if err != nil {
		return upgradeProjectState{}, err
	}
	volumes, err := listProjectObjects(
		ctx, runtimeBoundary, "volume", state.projectName,
	)
	if err != nil {
		return upgradeProjectState{}, err
	}
	if len(volumes) != 0 {
		return upgradeProjectState{}, errors.Join(
			platformcommand.ErrEffectConflict,
			errors.New("upgrade platform project contains a volume"),
		)
	}
	if len(containers) == 0 && len(networks) == 0 {
		return state, nil
	}

	admitLabels := func(labels map[string]string) error {
		if labels["com.xiak.matrix.managed"] != "true" ||
			labels["com.xiak.matrix.installation"] != source.InstallationID ||
			labels["com.docker.compose.project"] != state.projectName {
			return errors.New("upgrade platform object is not installation-owned")
		}
		releaseID := labels["com.xiak.matrix.release"]
		if releaseID != source.Bundle.Manifest.Release.ID &&
			releaseID != target.Bundle.Manifest.Release.ID {
			return errors.New("upgrade platform object has an unknown release")
		}
		if state.releaseID != "" && state.releaseID != releaseID {
			return errors.New("upgrade platform project mixes release identities")
		}
		state.releaseID = releaseID
		return nil
	}
	for _, identity := range containers {
		inspection, inspectErr := inspectPlatformContainer(
			ctx, runtimeBoundary, identity,
		)
		if inspectErr != nil {
			return upgradeProjectState{}, inspectErr
		}
		if err := admitLabels(inspection.Config.Labels); err != nil {
			return upgradeProjectState{}, errors.Join(platformcommand.ErrEffectConflict, err)
		}
	}
	for _, identity := range networks {
		inspection, inspectErr := inspectPlatformNetwork(
			ctx, runtimeBoundary, identity,
		)
		if inspectErr != nil {
			return upgradeProjectState{}, inspectErr
		}
		if err := admitLabels(inspection.Labels); err != nil {
			return upgradeProjectState{}, errors.Join(platformcommand.ErrEffectConflict, err)
		}
	}

	expectation := sourceExpectation
	if state.releaseID == target.Bundle.Manifest.Release.ID {
		expectation = targetExpectation
	}
	project, exists, err := inspectOwnedPlatformProject(
		ctx, runtimeBoundary, expectation,
	)
	if err != nil {
		return upgradeProjectState{}, err
	}
	if !exists {
		return upgradeProjectState{}, errors.Join(
			platformcommand.ErrEffectOutcomeUnknown,
			errors.New("upgrade platform project changed while observed"),
		)
	}
	state.project = project
	return state, nil
}

func compileUpgradeExpectation(
	plan platformcommand.InstallPlan,
) (platformComposeExpectation, error) {
	compiled, err := topology.Compile(plan.Bundle.Manifest, topology.Options{
		InstallationID:   plan.InstallationID,
		Root:             plan.Root,
		Listener:         plan.Listener,
		Port:             plan.Port,
		NorthboundOrigin: plan.NorthboundOrigin,
	})
	if err != nil {
		return platformComposeExpectation{}, errors.Join(
			platformcommand.ErrEffectVerification, err,
		)
	}
	expectation, err := decodePlatformExpectation(compiled.ComposeJSON, plan.Bundle.Manifest)
	if err != nil || expectation.Name != compiled.ProjectName {
		return platformComposeExpectation{}, errors.Join(
			platformcommand.ErrEffectVerification,
			errors.New("upgrade platform expectation is invalid"),
		)
	}
	return expectation, nil
}

func removeUpgradeMigrationContainers(
	ctx context.Context,
	runtimeBoundary dockerRuntime,
	target platformcommand.InstallPlan,
	projectName string,
	project platformProjectObservation,
) error {
	migrations, err := inspectOwnedMigrationContainers(
		ctx, runtimeBoundary, target, projectName, project,
	)
	if err != nil {
		return err
	}
	identities := make([]string, 0, len(migrations))
	for _, migration := range migrations {
		identities = append(identities, migration.ID)
	}
	if err := removeOwnedProviderObjects(
		ctx, runtimeBoundary, "container", identities,
	); err != nil {
		return err
	}
	migrations, err = inspectOwnedMigrationContainers(
		ctx, runtimeBoundary, target, projectName, project,
	)
	if err != nil {
		return err
	}
	if len(migrations) != 0 {
		return errors.Join(
			platformcommand.ErrEffectUnavailable,
			errors.New("upgrade migration containers remain after cleanup"),
		)
	}
	return nil
}
