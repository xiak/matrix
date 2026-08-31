package phase1e2e

import (
	"errors"
	"fmt"

	"github.com/xiak/matrix/app/service/installation/release"
)

const defaultEdgeEndpoint = "http://127.0.0.1:8080"

type options struct {
	root                    string
	releaseBase             string
	releaseA                string
	releaseB                string
	trustKey                string
	edge                    string
	afterStart              bool
	browserReady            bool
	multiHostLifecycle      bool
	nativeNodes             string
	nativeDeploymentRuntime bool
	browserPasswordFile     string
}

type releasePair struct {
	base *release.VerifiedBundle
	a    release.VerifiedBundle
	b    release.VerifiedBundle
}

type safeError struct {
	step string
}

func (value *safeError) Error() string {
	if value == nil {
		return "phase1 gate failed"
	}
	return "phase1 gate failed at " + value.step
}

func fail(step string) error { return &safeError{step: step} }

func validateReleasePair(a, b release.VerifiedBundle) error {
	if a.Manifest.Release.PreviousID != "" || a.Manifest.Release.PreviousVersion != "" {
		return fail("release-pair-contract")
	}
	return validateReleaseTransition(a, b)
}

func validateReleaseSequence(base, bridge, successor release.VerifiedBundle) error {
	if base.Manifest.Release.PreviousID != "" || base.Manifest.Release.PreviousVersion != "" {
		return fail("release-sequence-base-contract")
	}
	if err := validateReleaseTransition(base, bridge); err != nil {
		return err
	}
	return validateReleaseTransition(bridge, successor)
}

func validateReleaseTransition(a, b release.VerifiedBundle) error {
	if b.Manifest.Release.PreviousID != a.Manifest.Release.ID ||
		b.Manifest.Release.PreviousVersion != a.Manifest.Release.Version ||
		a.Manifest.Release.ID == b.Manifest.Release.ID ||
		a.Manifest.Release.Version == b.Manifest.Release.Version {
		return fail("release-pair-contract")
	}
	// Each directory is already authenticated. Admit distinct source binaries,
	// but do not start a destructive lifecycle exercise for an unproved profile.
	// Same-profile release fixtures still require an identical topology. The one
	// retained-data profile transition owns its authenticated topology change.
	sameProfile := a.Manifest.Database == b.Manifest.Database
	if a.Manifest.Kind != release.ManifestKind || b.Manifest.Kind != release.ManifestKind ||
		release.ValidateDatabaseUpgradePath(a.Manifest.Database, b.Manifest.Database) != nil ||
		(sameProfile && a.Manifest.TopologyDigest != b.Manifest.TopologyDigest) {
		return fail("release-pair-compatibility")
	}
	if _, ok := workloadImage(a.Manifest); !ok {
		return fail("release-a-workload")
	}
	if _, ok := workloadImage(b.Manifest); !ok {
		return fail("release-b-workload")
	}
	return nil
}

func workloadImage(manifest release.Manifest) (release.Image, bool) {
	var found release.Image
	count := 0
	for _, image := range manifest.Images {
		if image.Purpose == release.ImageWorkload {
			found = image
			count++
		}
	}
	return found, count == 1
}

func emit(step string) {
	_, _ = fmt.Println("PASS " + step)
}

func safeFailure(err error) error {
	var safe *safeError
	if errors.As(err, &safe) {
		return safe
	}
	return fail("internal-acceptance-error")
}
