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

func authenticateInstalledPlan(
	installed platformcommand.InstalledPlan,
) (platformcommand.InstallPlan, error) {
	trustPath, err := managedPath(
		installed.Root, filepath.FromSlash(layout.ReleaseTrust),
	)
	if err != nil {
		return platformcommand.InstallPlan{}, err
	}
	trustBytes, trust, err := release.ReadTrustRootFile(trustPath)
	if err != nil || trust.KeyID != installed.TrustKeyID ||
		trust.PublicKeyFingerprint != installed.TrustFingerprint {
		clear(trustBytes)
		return platformcommand.InstallPlan{}, errors.New(
			"installed release trust differs from the sealed journal",
		)
	}
	releaseRoot, err := managedPath(
		installed.Root,
		filepath.FromSlash(layout.ReleaseDirectory(installed.ReleaseID)),
	)
	if err != nil {
		clear(trustBytes)
		return platformcommand.InstallPlan{}, err
	}
	bundle, err := release.VerifyDirectory(releaseRoot, trustBytes)
	if err != nil || bundle.Manifest.Release.ID != installed.ReleaseID ||
		bundle.ManifestSHA256 != installed.ReleaseDigest ||
		bundle.Manifest.TopologyDigest != topology.ContractDigest() {
		clear(trustBytes)
		return platformcommand.InstallPlan{}, errors.New(
			"installed release differs from the sealed current pointer",
		)
	}
	return platformcommand.InstallPlan{
		Root: installed.Root, InstallationID: installed.InstallationID,
		Listener: installed.Listener, Port: installed.Port,
		Bundle: bundle, Trust: trust, TrustBytes: trustBytes,
	}, nil
}

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
