package localmachine

import (
	"bytes"
	"context"
	"errors"
	"io"
	"path/filepath"

	"github.com/xiak/matrix/app/service/installation/internal/layout"
	"github.com/xiak/matrix/app/service/installation/internal/platformcommand"
)

func recoverBackup(
	ctx context.Context,
	runtimeBoundary dockerRuntime,
	streaming streamingDockerRuntime,
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
	if manifest.SchemaVersion != target.Bundle.Manifest.Database.SchemaVersion {
		return errors.Join(
			platformcommand.ErrEffectVerification,
			errors.New("recovery schema identity changed"),
		)
	}
	return migrateInstallation(ctx, runtimeBoundary, target)
}

func authenticateRecoveryPlan(
	plan platformcommand.RecoveryPlan,
) (platformcommand.InstallPlan, platformcommand.InstallPlan, backupManifest, error) {
	if plan.Current.Root == "" || plan.Current.Root != plan.Target.Root ||
		plan.Current.InstallationID == "" ||
		plan.Current.InstallationID != plan.Target.InstallationID ||
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
	if err != nil || digest != plan.BackupDigest ||
		manifest.ReleaseID != target.Bundle.Manifest.Release.ID ||
		manifest.ReleaseDigest != target.Bundle.ManifestSHA256 ||
		manifest.SchemaVersion != target.Bundle.Manifest.Database.SchemaVersion {
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
	return verifier.Verify(ctx, target)
}
