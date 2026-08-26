package localmachine

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/xiak/matrix/app/service/installation/internal/platformcommand"
	"github.com/xiak/matrix/app/service/installation/release"
	"github.com/xiak/matrix/app/service/installation/topology"
)

type migrationCleanupIdentity struct {
	imageID string
	labels  map[string]string
}

func rollbackInstallation(
	ctx context.Context,
	runtimeBoundary dockerRuntime,
	plan platformcommand.InstallPlan,
) error {
	compiled, err := topology.Compile(plan.Bundle.Manifest, topology.Options{
		InstallationID: plan.InstallationID,
		Root:           plan.Root,
		Listener:       plan.Listener,
		Port:           plan.Port,
	})
	if err != nil {
		return errors.Join(platformcommand.ErrEffectVerification, err)
	}
	expectation, err := decodePlatformExpectation(compiled.ComposeJSON)
	if err != nil || expectation.Name != compiled.ProjectName {
		return errors.Join(
			platformcommand.ErrEffectVerification,
			errors.New("compiled platform topology cannot be cleaned up"),
		)
	}

	project, _, err := inspectOwnedPlatformProject(ctx, runtimeBoundary, expectation)
	if err != nil {
		return err
	}
	migrations, err := inspectOwnedMigrationContainers(
		ctx, runtimeBoundary, plan, expectation.Name, project,
	)
	if err != nil {
		return err
	}
	containerIDs := make([]string, 0, len(project.Containers)+len(migrations))
	for _, container := range project.Containers {
		containerIDs = append(containerIDs, container.ID)
	}
	for _, container := range migrations {
		containerIDs = append(containerIDs, container.ID)
	}
	if err := removeOwnedProviderObjects(ctx, runtimeBoundary, "container", containerIDs); err != nil {
		return err
	}

	project, exists, err := inspectOwnedPlatformProject(ctx, runtimeBoundary, expectation)
	if err != nil {
		return err
	}
	migrations, err = inspectOwnedMigrationContainers(
		ctx, runtimeBoundary, plan, expectation.Name, project,
	)
	if err != nil {
		return err
	}
	if len(project.Containers) != 0 || len(migrations) != 0 {
		return errors.Join(
			platformcommand.ErrEffectUnavailable,
			errors.New("installation-owned containers remain after cleanup"),
		)
	}
	if !exists {
		return nil
	}
	networkIDs := make([]string, 0, len(project.Networks))
	for _, network := range project.Networks {
		networkIDs = append(networkIDs, network.ID)
	}
	if err := removeOwnedProviderObjects(ctx, runtimeBoundary, "network", networkIDs); err != nil {
		return err
	}
	project, exists, err = inspectOwnedPlatformProject(ctx, runtimeBoundary, expectation)
	if err != nil {
		return err
	}
	migrations, err = inspectOwnedMigrationContainers(
		ctx, runtimeBoundary, plan, expectation.Name, project,
	)
	if err != nil {
		return err
	}
	if exists || len(migrations) != 0 {
		return errors.Join(
			platformcommand.ErrEffectUnavailable,
			errors.New("installation-owned provider objects remain after cleanup"),
		)
	}
	return nil
}

func inspectOwnedMigrationContainers(
	ctx context.Context,
	runtimeBoundary dockerRuntime,
	plan platformcommand.InstallPlan,
	projectName string,
	project platformProjectObservation,
) ([]platformContainerInspection, error) {
	output, _, err := runtimeBoundary.Run(
		ctx, nil,
		"container", "ls", "--all", "--quiet", "--no-trunc",
		"--filter", "label=com.xiak.matrix.installation="+plan.InstallationID,
	)
	if err != nil {
		return nil, errors.Join(platformcommand.ErrEffectUnavailable, err)
	}
	identities := strings.Fields(string(output))
	if len(identities) > maximumProviderObjects {
		return nil, errors.Join(
			platformcommand.ErrEffectConflict,
			errors.New("installation container inventory exceeds its bound"),
		)
	}
	platformIDs := make(map[string]struct{}, len(project.Containers))
	for _, container := range project.Containers {
		platformIDs[container.ID] = struct{}{}
	}
	expected, err := expectedMigrationCleanupIdentities(plan, projectName)
	if err != nil {
		return nil, errors.Join(platformcommand.ErrEffectVerification, err)
	}
	seen := make(map[string]struct{}, len(identities))
	result := make([]platformContainerInspection, 0, len(identities))
	for _, identity := range identities {
		if !providerIdentity.MatchString(identity) {
			return nil, errors.Join(
				platformcommand.ErrEffectVerification,
				errors.New("installation container identity is invalid"),
			)
		}
		if _, found := platformIDs[identity]; found {
			continue
		}
		inspection, inspectErr := inspectPlatformContainer(ctx, runtimeBoundary, identity)
		if inspectErr != nil {
			return nil, inspectErr
		}
		name := strings.TrimPrefix(inspection.Name, "/")
		cleanup, found := expected[name]
		if !found || inspection.Name != "/"+name || inspection.Image != cleanup.imageID ||
			inspection.Config.Labels["com.docker.compose.project"] != "" ||
			!ownershipLabelsMatch(inspection.Config.Labels, cleanup.labels) {
			return nil, errors.Join(
				platformcommand.ErrEffectConflict,
				errors.New("installation container is not a current migration effect"),
			)
		}
		if _, duplicate := seen[name]; duplicate {
			return nil, errors.Join(
				platformcommand.ErrEffectConflict,
				errors.New("installation migration container is duplicated"),
			)
		}
		seen[name] = struct{}{}
		result = append(result, inspection)
	}
	return result, nil
}

func expectedMigrationCleanupIdentities(
	plan platformcommand.InstallPlan,
	projectName string,
) (map[string]migrationCleanupIdentity, error) {
	images := make(map[string]string, len(plan.Bundle.Manifest.Images))
	for _, image := range plan.Bundle.Manifest.Images {
		images[image.Component] = image.ImageID
	}
	result := make(map[string]migrationCleanupIdentity, len(platformMigrations)*2)
	for _, migration := range platformMigrations {
		imageID := images[migration.component]
		if imageID == "" {
			return nil, errors.New("migration cleanup image identity is absent")
		}
		for _, mode := range []string{"apply", "verify"} {
			name := strings.Join([]string{
				projectName,
				"migration", migration.name, mode,
			}, "-")
			role := "migration-" + migration.name
			labels := map[string]string{
				"com.xiak.matrix.managed":      "true",
				"com.xiak.matrix.installation": plan.InstallationID,
				"com.xiak.matrix.release":      plan.Bundle.Manifest.Release.ID,
				"com.xiak.matrix.role":         role,
			}
			for key, value := range release.BuiltImageLabels(
				plan.Bundle.Manifest.Release, migration.component,
			) {
				labels[key] = value
			}
			result[name] = migrationCleanupIdentity{
				imageID: imageID,
				labels:  labels,
			}
		}
	}
	return result, nil
}

func removeOwnedProviderObjects(
	ctx context.Context,
	runtimeBoundary dockerRuntime,
	objectType string,
	identities []string,
) error {
	if objectType != "container" && objectType != "network" {
		return errors.Join(
			platformcommand.ErrEffectVerification,
			errors.New("cleanup provider object type is unsupported"),
		)
	}
	identities = slices.Clone(identities)
	slices.Sort(identities)
	for _, identity := range identities {
		arguments := []string{objectType, "rm"}
		if objectType == "container" {
			arguments = append(arguments, "--force", "--volumes")
		}
		arguments = append(arguments, identity)
		_, started, err := runtimeBoundary.Run(ctx, nil, arguments...)
		if err == nil {
			continue
		}
		if !started {
			return errors.Join(platformcommand.ErrEffectUnavailable, err)
		}
		return errors.Join(platformcommand.ErrEffectOutcomeUnknown, err)
	}
	return nil
}
