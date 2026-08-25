package localmachine

import (
	"errors"
	"path/filepath"

	"github.com/xiak/matrix/app/service/installation/internal/layout"
	"github.com/xiak/matrix/app/service/installation/internal/platformcommand"
	"github.com/xiak/matrix/app/service/installation/internal/release"
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
