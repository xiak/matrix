package localmachine

import (
	"bytes"
	"errors"
	"path/filepath"

	"github.com/xiak/matrix/app/service/installation/internal/layout"
	"github.com/xiak/matrix/app/service/installation/internal/platformcommand"
	"github.com/xiak/matrix/app/service/installation/release"
	"github.com/xiak/matrix/app/service/installation/topology"
)

func verifiedStagedBundle(plan platformcommand.InstallPlan) (release.VerifiedBundle, error) {
	root, err := managedPath(
		plan.Root,
		filepath.FromSlash(layout.ReleaseDirectory(plan.Bundle.Manifest.Release.ID)),
	)
	if err != nil {
		return release.VerifiedBundle{}, err
	}
	staged, err := release.VerifyDirectory(root, plan.TrustBytes)
	if err != nil || staged.ManifestSHA256 != plan.Bundle.ManifestSHA256 ||
		staged.Manifest.Release.ID != plan.Bundle.Manifest.Release.ID {
		return release.VerifiedBundle{}, errors.New("staged release differs from the installation plan")
	}
	return staged, nil
}

type verifiedInstallation struct {
	bundle      release.VerifiedBundle
	topology    topology.Result
	composePath string
}

func verifiedInstallationConfiguration(
	plan platformcommand.InstallPlan,
) (verifiedInstallation, error) {
	staged, err := verifiedStagedBundle(plan)
	if err != nil {
		return verifiedInstallation{}, err
	}
	compiled, err := topology.Compile(staged.Manifest, topology.Options{
		InstallationID: plan.InstallationID,
		Root:           plan.Root,
		Listener:       plan.Listener,
		Port:           plan.Port,
	})
	if err != nil {
		return verifiedInstallation{}, err
	}
	catalog, err := artifactCatalogConfig(staged.Manifest)
	if err != nil {
		return verifiedInstallation{}, errors.New("generated artifact catalog is invalid")
	}
	expectedFiles := []struct {
		path    string
		content []byte
	}{
		{layout.Compose, compiled.ComposeJSON},
		{layout.ArtifactCatalog, catalog},
		{layout.APISIXRoutes, apisixStandaloneConfig()},
		{layout.APISIXConfig, apisixMainConfig()},
		{layout.APISIXUID, []byte(compiled.ProjectName)},
	}
	for _, expected := range expectedFiles {
		content, readErr := readManagedFile(
			plan.Root, filepath.FromSlash(expected.path), maximumManagedFileBytes,
		)
		if readErr != nil || !bytes.Equal(content, expected.content) {
			return verifiedInstallation{}, errors.New(
				"generated installation configuration differs from authenticated input",
			)
		}
	}
	if _, err := readManagedFile(
		plan.Root, filepath.FromSlash(layout.APISIXNginx), maximumManagedFileBytes,
	); err != nil {
		return verifiedInstallation{}, errors.New("APISIX runtime configuration is unsafe")
	}
	composePath, err := managedPath(plan.Root, filepath.FromSlash(layout.Compose))
	if err != nil {
		return verifiedInstallation{}, err
	}
	return verifiedInstallation{
		bundle: staged, topology: compiled, composePath: composePath,
	}, nil
}
