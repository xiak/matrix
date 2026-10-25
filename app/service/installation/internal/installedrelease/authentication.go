// Package installedrelease authenticates a release already committed by the
// sealed installation journal.
package installedrelease

import (
	"errors"
	"path/filepath"

	"github.com/xiak/matrix/app/service/installation/internal/layout"
	"github.com/xiak/matrix/app/service/installation/internal/lifecycle"
	"github.com/xiak/matrix/app/service/installation/release"
	"github.com/xiak/matrix/app/service/installation/topology"
)

func Authenticate(
	root string,
	releaseID string,
	digest string,
	trustBytes []byte,
) (release.VerifiedBundle, error) {
	releaseRoot := filepath.Join(
		root, filepath.FromSlash(layout.ReleaseDirectory(releaseID)),
	)
	bundle, err := release.VerifyInstalledDirectory(releaseRoot, trustBytes)
	if err != nil || bundle.Manifest.Release.ID != releaseID ||
		bundle.ManifestSHA256 != digest ||
		topology.ValidateInstalledContract(bundle.Manifest) != nil {
		return release.VerifiedBundle{}, errors.New("committed release authentication failed")
	}
	return bundle, nil
}

// AuthenticateCurrent binds the installation-owned trust root to the sealed
// journal before authenticating its current release.
func AuthenticateCurrent(
	root string,
	state lifecycle.Journal,
) (release.VerifiedBundle, error) {
	if state.CurrentReleaseID == "" || state.CurrentReleaseDigest == "" {
		return release.VerifiedBundle{}, errors.New("committed release is absent")
	}
	trustPath := filepath.Join(root, filepath.FromSlash(layout.ReleaseTrust))
	trustBytes, trust, err := release.ReadTrustRootFile(trustPath)
	if err != nil {
		clear(trustBytes)
		return release.VerifiedBundle{}, errors.New("committed release trust is invalid")
	}
	defer clear(trustBytes)
	if trust.KeyID != state.ReleaseTrust.KeyID ||
		trust.PublicKeyFingerprint != state.ReleaseTrust.Fingerprint {
		return release.VerifiedBundle{}, errors.New("committed release trust is invalid")
	}
	return Authenticate(
		root, state.CurrentReleaseID, state.CurrentReleaseDigest, trustBytes,
	)
}
