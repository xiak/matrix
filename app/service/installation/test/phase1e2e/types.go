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
	root                   string
	releaseA               string
	releaseB               string
	trustKey               string
	securityMail           string
	securityMailFixture    string
	securityMailFixtureSHA string
	securityMailFixtureID  string
	edge                   string
	afterStart             bool
}

type releasePair struct {
	a release.VerifiedBundle
	b release.VerifiedBundle
}

type securityReportSnapshot struct {
	requestID string
	metadata  iamv1.AccountSecurityReportMetadata
	document  iamv1.AccountSecurityReport
	csv       []byte
}

// This private test fixture crosses the outer engine restart, not a product
// API. It is stored outside the installation backup and never enters a bundle.
type iamRetention struct {
	InstallationID        string
	AdministratorPassword []byte
	AdministratorContact  iamv1.NotificationContact
	MFA                   mfaRetention
	AccessAnalyzer        iamv1.AccessAnalyzer
	PolicyChanges         policyAttachmentChangeRetention
	Tenants               []tenantRetention
	PlatformAuditHashes   map[string]struct{}
}

// policyAttachmentChangeRetention contains immutable command results rather
// than current relationship state. Both receipts are captured before the
// protected backup so recovery can retain them without weakening the
// authentication/authorization-state qualification of that backup.
type policyAttachmentChangeRetention struct {
	PreBackupCreate iamv1.PolicyAttachmentChange
	PreBackupRevoke iamv1.PolicyAttachmentChange
}

// mfaRetention is a mode-0600 test-only fixture outside both the signed
// release and installation backup. It lets the after-restart gate prove the
// same enrolled identity with a fresh OTP instead of inferring MFA retention
// from database rows or a still-valid bearer.
type mfaRetention struct {
	User             iamv1.User
	Password         []byte
	Seed             []byte
	Credential       []byte
	Contact          iamv1.NotificationContact
	State            iamv1.AuthenticatorState
	LastConsumedStep int64
}

type tenantRetention struct {
	Account                    iamv1.Account
	Child                      iamv1.User
	ChildAttachment            iamv1.PolicyAttachment
	DelegatedAuthority         *delegatedAuthorityRetention
	InitialPassword            []byte
	PrimaryPassword            []byte
	PreviousPrimaryPassword    []byte
	ChildPassword              []byte
	RecoveryPassword           []byte
	FinalPrimaryPassword       []byte
	OldPrimaryCredential       []byte
	OldChildCredential         []byte
	TemporaryPrimaryCredential []byte
	TemporaryChildCredential   []byte
	RetainedPrimaryCredential  []byte
	Operations                 []paasv1.Operation
	Quota                      managedservicev1.QuotaEntitlement
	AuditHashes                map[string]struct{}
	AccessKey                  *accessKeyRetention
}

// accessKeyRetention carries the one program credential that the signed
// lifecycle gate deliberately keeps active through release replacement,
// protected backup recovery and an outer-engine restart. Secret is stored
// only in the owner-only fixture above, never in a release or installation
// backup. CustodianGrant lets the final gate retire the key without granting
// a broader built-in administrator policy.
type accessKeyRetention struct {
	Key            iamv1.AccessKey
	Secret         []byte
	CustodianGrant iamv1.PolicyAttachment
}

// delegatedAuthorityRetention is the minimum durable Group and Role graph
// that the signed lifecycle gate carries through upgrade, rollback, protected
// backup recovery and an outer-engine restart. The credential is test-only
// material in the owner-only fixture above; it must stop authenticating after
// recovery invalidates its source LoginSession, while the immutable
// RoleSession receipt remains observable.
type delegatedAuthorityRetention struct {
	Group                 iamv1.Group
	Membership            iamv1.GroupMembership
	GroupAttachment       iamv1.PolicyAttachment
	Role                  iamv1.Role
	TrustVersion          iamv1.RoleTrustVersion
	RoleAttachment        iamv1.PolicyAttachment
	RoleBoundary          iamv1.RolePermissionBoundary
	PreRecoverySession    iamv1.RoleSession
	PreRecoveryCredential []byte
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
