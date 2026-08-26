package localmachine

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"

	"github.com/xiak/matrix/app/service/installation/internal/layout"
	"github.com/xiak/matrix/app/service/installation/internal/platformcommand"
)

const migrationWaitSeconds = "120"

type migrationMount struct {
	relative    string
	destination string
	environment string
}

type migrationDefinition struct {
	component  string
	name       string
	entrypoint string
	mounts     []migrationMount
}

var platformMigrations = []migrationDefinition{
	{
		component: "iam", name: "iam", entrypoint: "/matrix/bin/matrix-iam-migrate",
		mounts: []migrationMount{
			{layout.PostgresMigration, "/run/matrix/migration-dsn", "MATRIX_MIGRATION_DATABASE_DSN_FILE"},
			{layout.IAMAPI, "/run/matrix/iam-api-dsn", "MATRIX_MIGRATION_IAM_API_DSN_FILE"},
			{layout.IAMWorker, "/run/matrix/iam-worker-dsn", "MATRIX_MIGRATION_IAM_WORKER_DSN_FILE"},
		},
	},
	{
		component: "audit", name: "audit", entrypoint: "/matrix/bin/matrix-audit-migrate",
		mounts: []migrationMount{
			{layout.PostgresMigration, "/run/matrix/migration-dsn", "MATRIX_MIGRATION_DATABASE_DSN_FILE"},
			{layout.AuditRuntime, "/run/matrix/audit-runtime-dsn", "MATRIX_MIGRATION_AUDIT_RUNTIME_DSN_FILE"},
		},
	},
	{
		component: "paas", name: "paas", entrypoint: "/matrix/bin/matrix-paas-migrate",
		mounts: []migrationMount{
			{layout.PostgresMigration, "/run/matrix/migration-dsn", "MATRIX_MIGRATION_DATABASE_DSN_FILE"},
			{layout.PaaSAPI, "/run/matrix/paas-api-dsn", "MATRIX_MIGRATION_PAAS_API_DSN_FILE"},
			{layout.PaaSWorker, "/run/matrix/paas-worker-dsn", "MATRIX_MIGRATION_PAAS_WORKER_DSN_FILE"},
		},
	},
}

func migrateInstallation(
	ctx context.Context,
	runtimeBoundary dockerRuntime,
	plan platformcommand.InstallPlan,
) error {
	installation, err := verifiedInstallationConfiguration(plan)
	if err != nil {
		return errors.Join(platformcommand.ErrEffectVerification, err)
	}
	_, started, err := runtimeBoundary.Run(
		ctx, nil,
		"compose", "--file", installation.composePath,
		"--project-name", installation.topology.ProjectName,
		"up", "--detach", "--wait", "--wait-timeout", migrationWaitSeconds,
		"--no-build", "--pull", "never", "postgres",
	)
	if err != nil {
		if started {
			return errors.Join(platformcommand.ErrEffectOutcomeUnknown, err)
		}
		return errors.Join(platformcommand.ErrEffectUnavailable, err)
	}
	return runMigrationModes(
		ctx, runtimeBoundary, plan, installation, "apply", "verify",
	)
}

func verifyInstallationMigrations(
	ctx context.Context,
	runtimeBoundary dockerRuntime,
	plan platformcommand.InstallPlan,
	installation verifiedInstallation,
) error {
	return runMigrationModes(ctx, runtimeBoundary, plan, installation, "verify")
}

func runMigrationModes(
	ctx context.Context,
	runtimeBoundary dockerRuntime,
	plan platformcommand.InstallPlan,
	installation verifiedInstallation,
	modes ...string,
) error {
	networkID, err := controlNetworkID(
		ctx, runtimeBoundary, installation.topology.ProjectName, plan.InstallationID,
		installation.bundle.Manifest.Release.ID,
	)
	if err != nil {
		return err
	}
	images := make(map[string]string, len(installation.bundle.Manifest.Images))
	for _, image := range installation.bundle.Manifest.Images {
		images[image.Component] = image.ImageID
	}
	for _, mode := range modes {
		if mode != "apply" && mode != "verify" {
			return errors.Join(
				platformcommand.ErrEffectVerification,
				errors.New("migration action is unsupported"),
			)
		}
		for _, migration := range platformMigrations {
			imageID, found := images[migration.component]
			if !found {
				return errors.Join(
					platformcommand.ErrEffectVerification,
					errors.New("migration image is absent from authenticated release"),
				)
			}
			present, err := inspectExactImage(ctx, runtimeBoundary, imageID)
			if err != nil {
				return err
			}
			if !present {
				return errors.Join(
					platformcommand.ErrEffectVerification,
					errors.New("migration image identity is absent"),
				)
			}
			arguments, err := migrationArguments(
				plan, installation.topology.ProjectName, networkID, imageID, migration, mode,
			)
			if err != nil {
				return errors.Join(platformcommand.ErrEffectVerification, err)
			}
			_, started, err := runtimeBoundary.Run(ctx, nil, arguments...)
			if err != nil {
				if !started {
					return errors.Join(platformcommand.ErrEffectUnavailable, err)
				}
				if ctx.Err() != nil {
					return errors.Join(platformcommand.ErrEffectOutcomeUnknown, err)
				}
				return errors.Join(platformcommand.ErrEffectVerification, err)
			}
		}
	}
	return nil
}

func controlNetworkID(
	ctx context.Context,
	runtimeBoundary dockerRuntime,
	project string,
	installationID string,
	releaseID string,
) (string, error) {
	output, _, err := runtimeBoundary.Run(
		ctx, nil,
		"network", "ls", "--quiet",
		"--filter", "label=com.docker.compose.project="+project,
		"--filter", "label=com.docker.compose.network=control",
	)
	if err != nil {
		return "", errors.Join(platformcommand.ErrEffectUnavailable, err)
	}
	identities := strings.Fields(string(output))
	if len(identities) != 1 || !providerIdentity.MatchString(identities[0]) {
		return "", errors.Join(
			platformcommand.ErrEffectVerification,
			errors.New("platform control network identity is invalid"),
		)
	}
	identity := identities[0]
	output, _, err = runtimeBoundary.Run(
		ctx, nil, "network", "inspect", "--format", "{{json .Labels}}", identity,
	)
	if err != nil {
		return "", errors.Join(platformcommand.ErrEffectUnavailable, err)
	}
	var labels map[string]string
	if err := json.Unmarshal(output, &labels); err != nil ||
		labels["com.xiak.matrix.managed"] != "true" ||
		labels["com.xiak.matrix.installation"] != installationID ||
		labels["com.xiak.matrix.release"] != releaseID ||
		labels["com.xiak.matrix.role"] != "network-control" ||
		labels["com.docker.compose.project"] != project ||
		labels["com.docker.compose.network"] != "control" {
		return "", errors.Join(
			platformcommand.ErrEffectConflict,
			errors.New("platform control network is not installation-owned"),
		)
	}
	return identity, nil
}

func migrationArguments(
	plan platformcommand.InstallPlan,
	project string,
	networkID string,
	imageID string,
	migration migrationDefinition,
	mode string,
) ([]string, error) {
	if mode != "apply" && mode != "verify" {
		return nil, errors.New("migration action is unsupported")
	}
	arguments := []string{
		"run", "--rm", "--pull", "never",
		"--name", project + "-migration-" + migration.name + "-" + mode,
		"--network", networkID,
		"--read-only",
		"--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
		"--security-opt", "no-new-privileges=true",
		"--cap-drop", "ALL",
		"--label", "com.xiak.matrix.managed=true",
		"--label", "com.xiak.matrix.installation=" + plan.InstallationID,
		"--label", "com.xiak.matrix.release=" + plan.Bundle.Manifest.Release.ID,
		"--label", "com.xiak.matrix.role=migration-" + migration.name,
	}
	for _, mount := range migration.mounts {
		source, err := managedPath(plan.Root, filepath.FromSlash(mount.relative))
		if err != nil || strings.ContainsRune(source, ',') {
			return nil, errors.New("migration secret mount path is invalid")
		}
		exists, err := managedFileExists(plan.Root, filepath.FromSlash(mount.relative))
		if err != nil || !exists {
			return nil, errors.New("migration secret mount is unavailable")
		}
		arguments = append(
			arguments,
			"--mount", "type=bind,src="+source+",dst="+mount.destination+",readonly",
			"--env", mount.environment+"="+mount.destination,
		)
	}
	arguments = append(arguments, "--entrypoint", migration.entrypoint, imageID, mode)
	return arguments, nil
}
