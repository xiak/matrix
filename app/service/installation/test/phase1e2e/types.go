package phase1e2e

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/xiak/matrix/app/service/installation/release"
	"github.com/xiak/matrix/app/service/installation/topology"
)

const (
	defaultEdgeEndpoint = "http://127.0.0.1:8080"
	// These task-local signed packages already passed the accepted A/B gate.
	// They are fixture commitments, never product upgrade/recovery admission.
	acceptedPreparationManifestDigest = "sha256:edb1697ceaa9acb57ee0e4a4e2295495d28ed10dd793a6789636dd343b232122"
	acceptedEnablingManifestDigest    = "sha256:10ef07abf7dbb3a7481696d361a104fe99e6db4a491c06b93d0a5019b8ff7cab"
)

type options struct {
	root                      string
	releaseBase               string
	releaseA                  string
	releaseB                  string
	skippedRelease            string
	mismatchedRelease         string
	trustKey                  string
	edge                      string
	afterStart                bool
	browserReady              bool
	multiHostLifecycle        bool
	nativeNodes               string
	nativeDeploymentRuntime   bool
	browserPasswordFile       string
	securityMailConfiguration string
}

type releasePair struct {
	base       *release.VerifiedBundle
	a          release.VerifiedBundle
	b          release.VerifiedBundle
	skipped    *release.VerifiedBundle
	mismatched *release.VerifiedBundle
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
	if err := validateReleaseTransition(base, bridge); err != nil &&
		!acceptedHistoricalPreparationBridge(base, bridge) {
		return err
	}
	return validateReleaseTransition(bridge, successor)
}

func matchesCanonicalManifest(manifest release.Manifest, commitment string) bool {
	if manifest.Kind != release.ManifestKind {
		return false
	}
	encoded, err := release.EncodeCanonical(manifest)
	if err != nil {
		return false
	}
	digest := sha256.Sum256(encoded)
	return "sha256:"+hex.EncodeToString(digest[:]) == commitment
}

func acceptedHistoricalPreparationBridge(base, bridge release.VerifiedBundle) bool {
	return matchesCanonicalManifest(base.Manifest, acceptedPreparationManifestDigest) &&
		matchesCanonicalManifest(bridge.Manifest, acceptedEnablingManifestDigest)
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
	// Each profile is coupled to its one authenticated topology. The current
	// enabling release deliberately adds the purpose-only notification worker;
	// no arbitrary topology transition is admitted.
	if a.Manifest.Kind != release.ManifestKind || b.Manifest.Kind != release.ManifestKind ||
		release.ValidateDatabaseUpgradePath(a.Manifest.Database, b.Manifest.Database) != nil ||
		!supportedPlatformTopology(a.Manifest) || !supportedPlatformTopology(b.Manifest) {
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

func validateRejectedPredecessorCandidates(a, b, skipped, mismatched release.VerifiedBundle) error {
	for _, candidate := range []release.VerifiedBundle{skipped, mismatched} {
		if candidate.Manifest.Kind != b.Manifest.Kind ||
			candidate.Manifest.Release.ID != b.Manifest.Release.ID ||
			candidate.Manifest.Release.Version != b.Manifest.Release.Version ||
			candidate.Manifest.Release.SourceCommit != b.Manifest.Release.SourceCommit ||
			candidate.Manifest.Database != b.Manifest.Database ||
			candidate.Manifest.TopologyDigest != b.Manifest.TopologyDigest ||
			candidate.Manifest.Release.PreviousID == a.Manifest.Release.ID {
			return fail("rejected-predecessor-release-contract")
		}
	}
	if skipped.Manifest.Release.PreviousVersion == a.Manifest.Release.Version ||
		mismatched.Manifest.Release.PreviousVersion != a.Manifest.Release.Version ||
		skipped.Manifest.Release.PreviousID == mismatched.Manifest.Release.PreviousID {
		return fail("rejected-predecessor-release-contract")
	}
	return nil
}

func supportedPlatformTopology(manifest release.Manifest) bool {
	return manifest.Database == release.CurrentDatabaseProfile() && manifest.TopologyDigest == topology.ContractDigest() ||
		manifest.Database == release.SupportedDatabaseUpgradePredecessorProfile() &&
			manifest.TopologyDigest == topology.SupportedPredecessorContractDigest()
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
