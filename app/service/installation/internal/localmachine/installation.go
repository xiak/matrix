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
	compose, err := readManagedFile(
		plan.Root,
		filepath.FromSlash(layout.Compose),
		maximumManagedFileBytes,
	)
	if err != nil || !bytes.Equal(compose, compiled.ComposeJSON) {
		return verifiedInstallation{}, errors.New(
			"generated Compose topology differs from authenticated release input",
		)
	}
	composePath, err := managedPath(plan.Root, filepath.FromSlash(layout.Compose))
	if err != nil {
		return verifiedInstallation{}, err
	}
	return verifiedInstallation{
		bundle: staged, topology: compiled, composePath: composePath,
	}, nil
}
