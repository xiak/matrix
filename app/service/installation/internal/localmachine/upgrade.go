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
		present, inspectErr := inspectExactImage(ctx, runtimeBoundary, image.ImageID)
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

// rollbackUpgrade removes only a fully authenticated target candidate and
// puts the source configuration back. Equal database profiles can then start
// and verify that source while preserving PostgreSQL data. A cross-profile
// failure stops after cleanup: starting old binaries against the migrated
// schema is forbidden and the authenticated upgrade backup owns recovery.
func rollbackUpgrade(
	ctx context.Context,
	runtimeBoundary dockerRuntime,
	verifier installationVerifier,
	plan platformcommand.UpgradePlan,
) error {
	source, err := authenticateInstalledPlan(plan.Source)
	if err != nil {
		return errors.Join(platformcommand.ErrEffectVerification, err)
	}
	sourceDatabase := source.Bundle.Manifest.Database
	clear(source.TrustBytes)
	rollback := platformcommand.RollbackPlan{
		Current: plan.Target, Previous: plan.Source,
	}
	if err := prepareReleaseRollback(ctx, runtimeBoundary, rollback); err != nil {
		return err
	}
	if sourceDatabase != plan.Target.Bundle.Manifest.Database {
		return errors.Join(
			platformcommand.ErrEffectRecoveryRequired,
			errors.New("cross-profile upgrade rollback requires authenticated backup recovery"),
		)
	}
	if err := startPreviousRelease(ctx, runtimeBoundary, rollback); err != nil {
		return err
	}
	return verifyPreviousRelease(ctx, runtimeBoundary, verifier, rollback)
}

func prepareReleaseRollback(
	ctx context.Context,
	runtimeBoundary dockerRuntime,
	plan platformcommand.RollbackPlan,
) error {
	source, err := authenticateInstalledPlan(plan.Previous)
	if err != nil {
		return errors.Join(platformcommand.ErrEffectVerification, err)
	}
	defer clear(source.TrustBytes)
	if err := validateUpgradeIdentity(source, plan.Current); err != nil {
		return errors.Join(platformcommand.ErrEffectVerification, err)
	}

	state, err := inspectUpgradeProject(ctx, runtimeBoundary, source, plan.Current)
	if err != nil {
		return err
	}
	switch state.releaseID {
	case plan.Current.Bundle.Manifest.Release.ID:
		staged, verifyErr := verifiedStagedBundle(plan.Current)
		if verifyErr != nil {
			return errors.Join(platformcommand.ErrEffectVerification, verifyErr)
		}
		target := plan.Current
		target.Bundle = staged
		if err := rollbackInstallation(ctx, runtimeBoundary, target); err != nil {
			return err
		}
	case source.Bundle.Manifest.Release.ID, "":
		if err := removeUpgradeMigrationContainers(
			ctx, runtimeBoundary, plan.Current, state.projectName, state.project,
		); err != nil {
			return err
		}
	default:
		return errors.Join(
			platformcommand.ErrEffectConflict,
			errors.New("platform project release is not an upgrade participant"),
		)
	}

	return restoreUpgradeConfiguration(platformcommand.UpgradePlan{
		Source: plan.Previous, Target: plan.Current,
	})
}

func startPreviousRelease(
	ctx context.Context,
	runtimeBoundary dockerRuntime,
	plan platformcommand.RollbackPlan,
) error {
	source, err := authenticateInstalledPlan(plan.Previous)
	if err != nil {
		return errors.Join(platformcommand.ErrEffectVerification, err)
	}
	defer clear(source.TrustBytes)
	if err := validateUpgradeIdentity(source, plan.Current); err != nil {
		return errors.Join(platformcommand.ErrEffectVerification, err)
	}
	return startInstallation(ctx, runtimeBoundary, source)
}

func verifyPreviousRelease(
	ctx context.Context,
	runtimeBoundary dockerRuntime,
	verifier installationVerifier,
	plan platformcommand.RollbackPlan,
) error {
	source, err := authenticateInstalledPlan(plan.Previous)
	if err != nil {
		return errors.Join(platformcommand.ErrEffectVerification, err)
	}
	defer clear(source.TrustBytes)
	if err := validateUpgradeIdentity(source, plan.Current); err != nil {
		return errors.Join(platformcommand.ErrEffectVerification, err)
	}
	installation, _, _, err := inspectReadyInstalledPlatform(
		ctx, runtimeBoundary, source,
	)
	if err != nil {
		return err
	}
	if err := verifyInstallationMigrations(
		ctx, runtimeBoundary, source, installation,
	); err != nil {
		return err
	}
	_, err = verifier.Verify(ctx, source)
	return err
}

func validateUpgradeIdentity(
	source platformcommand.InstallPlan,
	target platformcommand.InstallPlan,
) error {
	if source.Root != target.Root ||
		source.InstallationID != target.InstallationID ||
		source.CorrelationID == "" || source.CorrelationID != target.CorrelationID ||
		source.Listener != target.Listener || source.Port != target.Port ||
		source.Trust != target.Trust ||
		!bytes.Equal(source.TrustBytes, target.TrustBytes) ||
		validateUpgradeReleasePair(source.Bundle, target.Bundle) != nil {
		return errors.New("upgrade source and target identities are inconsistent")
	}
	return nil
}

// validateUpgradeReleasePair authenticates the signed release relationship
// independently of a running lifecycle command. Read-only status and verify
// operations have no command correlation ID, while an active upgrade still
// validates that transaction boundary in validateUpgradeIdentity.
func validateUpgradeReleasePair(
	source release.VerifiedBundle,
	target release.VerifiedBundle,
) error {
	if target.Manifest.Release.ID == source.Manifest.Release.ID ||
		target.Manifest.Release.PreviousID != source.Manifest.Release.ID ||
		target.Manifest.Release.PreviousVersion != source.Manifest.Release.Version ||
		release.ValidateDatabaseUpgradePath(
			source.Manifest.Database, target.Manifest.Database,
		) != nil {
		return errors.New("upgrade release pair is inconsistent")
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
	compiled, err := topology.CompileInstalled(plan.Bundle.Manifest, topology.Options{
		InstallationID: plan.InstallationID,
		Root:           plan.Root,
		Listener:       plan.Listener,
		Port:           plan.Port,
	})
	if err != nil {
		return platformComposeExpectation{}, errors.Join(
			platformcommand.ErrEffectVerification, err,
		)
	}
	expectation, err := decodePlatformExpectation(compiled.ComposeJSON)
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
