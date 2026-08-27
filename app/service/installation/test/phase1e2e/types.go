package phase1e2e

import (
	"errors"
	"fmt"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
	managedservicev1 "github.com/xiak/matrix/api/managedservice/v1"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/installation/release"
)

const defaultEdgeEndpoint = "http://127.0.0.1:8080"

type options struct {
	root       string
	releaseA   string
	releaseB   string
	trustKey   string
	edge       string
	afterStart bool
}

type releasePair struct {
	a release.VerifiedBundle
	b release.VerifiedBundle
}

// This private test fixture crosses the outer engine restart, not a product
// API. It is stored outside the installation backup and never enters a bundle.
type iamRetention struct {
	InstallationID        string
	AdministratorPassword []byte
	Tenants               []tenantRetention
	PlatformAuditHashes   map[string]struct{}
}

type tenantRetention struct {
	Account              iamv1.OrganizationAccount
	Child                iamv1.Principal
	ChildBinding         iamv1.RoleBinding
	InitialPassword      []byte
	PrimaryPassword      []byte
	ChildPassword        []byte
	RecoveryPassword     []byte
	FinalPrimaryPassword []byte
	OldPrimaryCredential []byte
	OldChildCredential   []byte
	Operations           []paasv1.Operation
	Quota                managedservicev1.QuotaEntitlement
	AuditHashes          map[string]struct{}
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
	if a.Manifest.Release.PreviousID != "" || a.Manifest.Release.PreviousVersion != "" ||
		b.Manifest.Release.PreviousID != a.Manifest.Release.ID ||
		b.Manifest.Release.PreviousVersion != a.Manifest.Release.Version ||
		a.Manifest.Release.ID == b.Manifest.Release.ID ||
		a.Manifest.Release.Version == b.Manifest.Release.Version ||
		a.Manifest.Release.SourceCommit != b.Manifest.Release.SourceCommit ||
		a.Manifest.Database != release.CurrentDatabaseProfile() ||
		b.Manifest.Database != a.Manifest.Database {
		return fail("release-pair-contract")
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
