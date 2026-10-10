package phase1e2e

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/installation/release"
)

func fixtureTrustPEM(t *testing.T, notBefore, notAfter time.Time) string {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "phase1 mail fixture CA"},
		NotBefore: notBefore, NotAfter: notAfter, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestOfflinePhase1Lifecycle(t *testing.T) {
	if os.Getenv("MATRIX_PHASE1_E2E") != "1" {
		t.Skip("set MATRIX_PHASE1_E2E=1 inside a clean external-network-disabled Linux Docker host")
	}
	config, err := optionsFromEnvironment()
	if err != nil {
		t.Fatal(safeFailure(err))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	if err := runGate(ctx, config); err != nil {
		t.Fatal(safeFailure(err))
	}
}

func TestReleasePairAllowsReleaseSpecificWorkloadImages(t *testing.T) {
	a := release.VerifiedBundle{Manifest: release.Manifest{
		Release:  release.ReleaseIdentity{ID: "release-a", Version: "v0.1.0", SourceCommit: "commit"},
		Images:   []release.Image{{Purpose: release.ImageWorkload, SourceDigest: "sha256:a"}},
		Database: release.CurrentDatabaseProfile(),
	}}
	b := release.VerifiedBundle{Manifest: release.Manifest{
		Release: release.ReleaseIdentity{
			ID: "release-b", Version: "v0.2.0", SourceCommit: "commit",
			PreviousID: "release-a", PreviousVersion: "v0.1.0",
		},
		Images:   []release.Image{{Purpose: release.ImageWorkload, SourceDigest: "sha256:b"}},
		Database: release.CurrentDatabaseProfile(),
	}}
	if err := validateReleasePair(a, b); err != nil {
		t.Fatalf("release-specific workload images rejected: %v", err)
	}
	b.Manifest.Database.ContractRevision++
	if validateReleasePair(a, b) == nil {
		t.Fatal("different release contract revision admitted to offline lifecycle gate")
	}
}

func TestCreateUserWireCarriesExplicitRootBoundary(t *testing.T) {
	encoded, err := json.Marshal(createUserWire{
		LoginName: "signed.fixture", DisplayName: "Signed fixture",
		InitialPassword: "Example-Only-Signed-Fixture-Password-51!", RequestID: "signed-fixture-create",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	var request iamv1.CreateUserRequest
	if json.Unmarshal(encoded, &request) != nil || iamv1.ValidateCreateUserRequest(request) != nil ||
		request.PermissionBoundary != nil {
		t.Fatal("signed lifecycle user creation did not carry the explicit protected-Root boundary choice")
	}
}

func delegatedAuthorityFixture(t *testing.T) delegatedAuthorityRetention {
	t.Helper()
	now := time.Date(2026, time.October, 3, 1, 2, 3, 0, time.UTC)
	trust := iamv1.TrustPolicyDocument{LanguageVersion: iamv1.TrustPolicyLanguageVersion, Statements: []iamv1.TrustPolicyStatement{{
		SID: "root-source", Effect: iamv1.PolicyAllow,
		Principals: []iamv1.TrustPrincipal{{Type: iamv1.PrincipalUser, ID: "root-user"}},
	}}}
	_, trustDigest, err := iamv1.CanonicalizeTrustPolicyDocument(trust)
	if err != nil {
		t.Fatal(err)
	}
	group := iamv1.Group{APIVersion: iamv1.APIVersion, Kind: "Group", ID: "group-retained", AccountID: "account-retained",
		Name: "Retained group", ResourceVersion: 1, CreatedAt: now, UpdatedAt: now}
	role := iamv1.Role{APIVersion: iamv1.APIVersion, Kind: "Role", ID: "role-retained", AccountID: group.AccountID,
		Name: "Retained role", Tags: []iamv1.RoleTag{}, Management: iamv1.RoleCustomerManaged, Status: iamv1.RoleActive,
		MaxSessionDurationSeconds: iamv1.DefaultRoleSessionDurationSeconds, ResourceVersion: 2,
		CurrentTrustVersionID: "trust-retained", CreatedAt: now, UpdatedAt: now.Add(time.Microsecond)}
	attachment := func(id string, target iamv1.PolicyAttachmentTarget) iamv1.PolicyAttachment {
		return iamv1.PolicyAttachment{APIVersion: iamv1.APIVersion, Kind: "PolicyAttachment", ID: iamv1.PolicyAttachmentID(id),
			AccountID: group.AccountID, Target: target, PolicyID: iamv1.SystemPolicyPaaSDeveloper,
			Scope: iamv1.AuthorityScopeTenant, ResourceVersion: 1, CreatedAt: now, UpdatedAt: now}
	}
	return delegatedAuthorityRetention{
		Group: group,
		Membership: iamv1.GroupMembership{APIVersion: iamv1.APIVersion, Kind: "GroupMembership", ID: "membership-retained",
			AccountID: group.AccountID, GroupID: group.ID, UserID: "member-user", CreatedBy: "root-user",
			ResourceVersion: 1, CreatedAt: now, UpdatedAt: now},
		GroupAttachment: attachment("attachment-group", iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetGroup, ID: string(group.ID)}),
		Role:            role,
		TrustVersion: iamv1.RoleTrustVersion{APIVersion: iamv1.APIVersion, Kind: "RoleTrustVersion", ID: role.CurrentTrustVersionID,
			AccountID: group.AccountID, RoleID: role.ID, Document: trust, ContentDigest: trustDigest, CreatedAt: now},
		RoleAttachment: attachment("attachment-role", iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetRole, ID: string(role.ID)}),
		RoleBoundary: iamv1.RolePermissionBoundary{APIVersion: iamv1.APIVersion, Kind: "RolePermissionBoundary", AccountID: group.AccountID,
			RoleID: role.ID, ResourceVersion: role.ResourceVersion, Policy: &iamv1.PolicyVersionReference{PolicyID: iamv1.SystemPolicyPaaSViewer,
				VersionID: "version-viewer", ContentDigest: "sha256:" + strings.Repeat("1", 64)}},
		PreRecoverySession: iamv1.RoleSession{APIVersion: iamv1.APIVersion, Kind: "RoleSession", ID: "session-retained",
			AccountID: group.AccountID, RoleID: role.ID, SourceUserID: "root-user", Status: iamv1.SessionActive,
			IssuedAt: now.Add(2 * time.Microsecond), ExpiresAt: now.Add(time.Hour)},
		PreRecoveryCredential: []byte("test-only-role-credential"),
	}
}

func TestDelegatedAuthorityRetentionBindsExactAccountGraph(t *testing.T) {
	if !validDelegatedAuthorityRetention(delegatedAuthorityFixture(t), "account-retained", "member-user", "root-user") {
		t.Fatal("valid delegated authority fixture was rejected")
	}
	for name, mutate := range map[string]func(*delegatedAuthorityRetention){
		"foreign group":          func(value *delegatedAuthorityRetention) { value.Group.AccountID = "account-other" },
		"foreign member":         func(value *delegatedAuthorityRetention) { value.Membership.UserID = "member-other" },
		"different group target": func(value *delegatedAuthorityRetention) { value.GroupAttachment.Target.ID = "group-other" },
		"different role target":  func(value *delegatedAuthorityRetention) { value.RoleAttachment.Target.ID = "role-other" },
		"wider boundary": func(value *delegatedAuthorityRetention) {
			value.RoleBoundary.Policy.PolicyID = iamv1.SystemPolicyPaaSDeveloper
		},
		"different trust": func(value *delegatedAuthorityRetention) {
			value.TrustVersion.Document.Statements[0].Principals[0].ID = "root-other"
		},
		"different session source": func(value *delegatedAuthorityRetention) { value.PreRecoverySession.SourceUserID = "root-other" },
		"missing credential":       func(value *delegatedAuthorityRetention) { value.PreRecoveryCredential = nil },
	} {
		t.Run(name, func(t *testing.T) {
			fixture := delegatedAuthorityFixture(t)
			mutate(&fixture)
			if validDelegatedAuthorityRetention(fixture, "account-retained", "member-user", "root-user") {
				t.Fatal("changed delegated authority graph was accepted")
			}
		})
	}
}

func TestRoleSessionReceiptRetainsIssuanceAndClosesAuthorityAfterRecovery(t *testing.T) {
	issued := delegatedAuthorityFixture(t).PreRecoverySession
	observedAt := issued.IssuedAt.Add(30 * time.Minute)
	access := func(session iamv1.RoleSession, lifecycle iamv1.RoleSessionLifecycle, available bool, restriction iamv1.CapabilityRestriction) iamv1.RoleSessionAccess {
		return iamv1.RoleSessionAccess{
			APIVersion: iamv1.APIVersion,
			Kind:       "RoleSessionAccess",
			ObservedAt: observedAt,
			Item: iamv1.RoleSessionListing{
				Session: session,
				Source: iamv1.RoleSessionSourceDisplay{Type: iamv1.PrincipalUser, User: &iamv1.RoleSourceUserDisplay{
					ID: issued.SourceUserID, LoginName: "root", DisplayName: "Root user",
				}},
				Lifecycle: lifecycle,
				RevokeCapability: iamv1.ActionCapability{
					Action: iamv1.ActionIAMRoleSessionRevoke,
					Resource: iamv1.ResourceReference{
						Kind: iamv1.ResourceRoleSession,
						ID:   string(issued.ID),
					},
					Available: available, RestrictionReason: restriction,
				},
			},
		}
	}
	active := access(issued, iamv1.RoleSessionUnrevoked, true, "")
	if !retainedRoleSessionReceipt(active, issued, false) {
		t.Fatal("active role session receipt was not retained before recovery")
	}
	revokedAt := issued.IssuedAt.Add(10 * time.Minute)
	revoked := issued
	revoked.Status, revoked.RevokedAt = iamv1.SessionRevoked, &revokedAt
	terminal := access(revoked, iamv1.RoleSessionRevoked, false, iamv1.CapabilitySessionNotRevocable)
	if !retainedRoleSessionReceipt(terminal, issued, true) {
		t.Fatal("terminal role session receipt lost immutable issuance after recovery")
	}
	for name, mutate := range map[string]func(*iamv1.RoleSessionAccess){
		"active authority": func(value *iamv1.RoleSessionAccess) {
			*value = active
		},
		"different account": func(value *iamv1.RoleSessionAccess) {
			value.Item.Session.AccountID = "account-other"
		},
		"different role": func(value *iamv1.RoleSessionAccess) {
			value.Item.Session.RoleID = "role-other"
		},
		"different source": func(value *iamv1.RoleSessionAccess) {
			value.Item.Session.SourceUserID = "root-other"
			value.Item.Source.User.ID = "root-other"
		},
		"different issuance": func(value *iamv1.RoleSessionAccess) {
			value.Item.Session.IssuedAt = value.Item.Session.IssuedAt.Add(time.Microsecond)
		},
		"wrong terminal restriction": func(value *iamv1.RoleSessionAccess) {
			value.Item.RevokeCapability.RestrictionReason = iamv1.CapabilityAuthorityRequired
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := terminal
			changed.Item.Source.User = &iamv1.RoleSourceUserDisplay{
				ID: terminal.Item.Source.User.ID, LoginName: terminal.Item.Source.User.LoginName, DisplayName: terminal.Item.Source.User.DisplayName,
			}
			mutate(&changed)
			if retainedRoleSessionReceipt(changed, issued, true) {
				t.Fatal("changed role session receipt was accepted after recovery")
			}
		})
	}
}

func TestNotificationContactRetentionRequiresExactVerifiedState(t *testing.T) {
	verifiedAt := time.Date(2026, time.October, 3, 1, 2, 3, 456000000, time.UTC)
	want := iamv1.NotificationContact{
		APIVersion: iamv1.APIVersion, Kind: "NotificationContact",
		AccountID: "account-retained", UserID: "principal-admin",
		State: "VERIFIED", ResourceVersion: 1, Email: "receiver@matrix.test", VerifiedAt: &verifiedAt,
	}
	if !sameNotificationContact(want, want) {
		t.Fatal("exact verified contact was not retained")
	}
	for name, mutate := range map[string]func(*iamv1.NotificationContact){
		"account":          func(value *iamv1.NotificationContact) { value.AccountID = "account-other" },
		"user":             func(value *iamv1.NotificationContact) { value.UserID = "principal-other" },
		"state":            func(value *iamv1.NotificationContact) { value.State = "NONE" },
		"resource-version": func(value *iamv1.NotificationContact) { value.ResourceVersion++ },
		"address":          func(value *iamv1.NotificationContact) { value.Email = "other@matrix.test" },
		"verification-time": func(value *iamv1.NotificationContact) {
			changed := value.VerifiedAt.Add(time.Microsecond)
			value.VerifiedAt = &changed
		},
		"missing-time": func(value *iamv1.NotificationContact) { value.VerifiedAt = nil },
	} {
		t.Run(name, func(t *testing.T) {
			observed := want
			mutate(&observed)
			if sameNotificationContact(observed, want) {
				t.Fatal("changed notification contact was accepted as retained")
			}
		})
	}
}

func TestAccessAnalyzerLifecycleCoverageStaysClosed(t *testing.T) {
	observedFrom := time.Date(2026, time.October, 3, 1, 2, 3, 0, time.UTC)
	observedThrough := observedFrom.Add(time.Minute)
	coverage := make([]iamv1.AccessObservationCoverage, 0, len(iamv1.AccessObservationCoverageSources()))
	for index, source := range iamv1.AccessObservationCoverageSources() {
		entry := iamv1.AccessObservationCoverage{Source: source}
		if index < 4 {
			entry.State = iamv1.AccessObservationInsufficientCoverage
			entry.Reason = iamv1.AccessObservationWindowIncomplete
			entry.ObservedFrom = &observedFrom
			entry.ObservedThrough = &observedThrough
		} else {
			entry.State = iamv1.AccessObservationNotIncluded
			entry.Reason = iamv1.AccessObservationSourceNotImplemented
		}
		coverage = append(coverage, entry)
	}
	if !accessAnalyzerCoverageIsClosed(coverage, iamv1.AccessObservationWindowIncomplete) ||
		!accessAnalyzerCoverageIsClosed(coverage, "") ||
		accessAnalyzerCoverageIsClosed(coverage, iamv1.AccessObservationRestoreGap) {
		t.Fatal("ordinary incomplete access coverage was not kept distinct")
	}
	for index := 0; index < 4; index++ {
		coverage[index].Reason = iamv1.AccessObservationRestoreGap
	}
	if !accessAnalyzerCoverageIsClosed(coverage, iamv1.AccessObservationRestoreGap) ||
		!accessAnalyzerCoverageIsClosed(coverage, "") ||
		accessAnalyzerCoverageIsClosed(coverage, iamv1.AccessObservationWindowIncomplete) {
		t.Fatal("restored access coverage was not kept distinct")
	}
	coverage[0].State = iamv1.AccessObservationComplete
	coverage[0].Reason = ""
	if accessAnalyzerCoverageIsClosed(coverage, "") {
		t.Fatal("complete access coverage admitted a no-effect lifecycle assertion")
	}
}

func TestSecurityMailFixtureTrustCoversLifecycleWindow(t *testing.T) {
	now := time.Date(2026, time.October, 3, 1, 2, 3, 0, time.UTC)
	through := now.Add(30 * time.Minute)
	valid := fixtureTrustPEM(t, now.Add(-time.Hour), through.Add(time.Hour))
	if !trustedCertificatesCoverWindow(valid, now, through) {
		t.Fatal("valid fixture trust did not cover lifecycle window")
	}
	for name, value := range map[string]string{
		"missing":         "",
		"malformed":       "not a certificate",
		"expired":         fixtureTrustPEM(t, now.Add(-2*time.Hour), now.Add(-time.Hour)),
		"not-yet-valid":   fixtureTrustPEM(t, now.Add(time.Minute), through.Add(time.Hour)),
		"expires-in-gate": fixtureTrustPEM(t, now.Add(-time.Hour), through.Add(-time.Minute)),
	} {
		t.Run(name, func(t *testing.T) {
			if trustedCertificatesCoverWindow(value, now, through) {
				t.Fatal("unsafe fixture trust covered lifecycle window")
			}
		})
	}
	if trustedCertificatesCoverWindow(valid, through, now) {
		t.Fatal("reversed lifecycle window was accepted")
	}
}

func TestOptionsRequirePrivateSecurityMailOnlyForEffectfulLifecycle(t *testing.T) {
	root := t.TempDir()
	for name, value := range map[string]string{
		"MATRIX_PHASE1_E2E_PHASE": "run",
		"MATRIX_PHASE1_ROOT":      filepath.Join(root, "installation"),
		"MATRIX_PHASE1_RELEASE_A": filepath.Join(root, "release-a"),
		"MATRIX_PHASE1_RELEASE_B": filepath.Join(root, "release-b"),
		"MATRIX_PHASE1_TRUST_KEY": filepath.Join(root, "release-trust.json"),
	} {
		t.Setenv(name, value)
	}
	if _, err := optionsFromEnvironment(); err == nil {
		t.Fatal("effectful lifecycle admitted without private security-mail configuration")
	}
	securityMail := filepath.Join(root, "security-mail.json")
	t.Setenv("MATRIX_PHASE1_SECURITY_MAIL_CONFIGURATION", securityMail)
	fixture := filepath.Join(root, "postfix-fixture.tar")
	t.Setenv("MATRIX_PHASE1_SECURITY_MAIL_FIXTURE_ARCHIVE", fixture)
	t.Setenv("MATRIX_PHASE1_SECURITY_MAIL_FIXTURE_SHA256", "sha256:"+strings.Repeat("a", 64))
	t.Setenv("MATRIX_PHASE1_SECURITY_MAIL_FIXTURE_IMAGE_ID", "sha256:"+strings.Repeat("b", 64))
	t.Setenv("MATRIX_PHASE1_EDGE", "http://127.0.0.1:49123")
	config, err := optionsFromEnvironment()
	if err != nil || config.securityMail != securityMail || config.securityMailFixture != fixture ||
		config.edge != "http://127.0.0.1:49123" {
		t.Fatalf("effectful lifecycle options = %#v / %v", config, err)
	}
	t.Setenv("MATRIX_PHASE1_SECURITY_MAIL_FIXTURE_SHA256", strings.Repeat("a", 64))
	if _, err := optionsFromEnvironment(); err == nil {
		t.Fatal("fixture archive admitted without an exact SHA-256 identity")
	}
	t.Setenv("MATRIX_PHASE1_SECURITY_MAIL_FIXTURE_SHA256", "sha256:"+strings.Repeat("a", 64))
	t.Setenv("MATRIX_PHASE1_EDGE", "http://example.test:49123")
	if _, err := optionsFromEnvironment(); err == nil {
		t.Fatal("non-loopback lifecycle endpoint admitted")
	}
	t.Setenv("MATRIX_PHASE1_EDGE", "http://127.0.0.1:49123")

	t.Setenv("MATRIX_PHASE1_E2E_PHASE", "after-restart")
	t.Setenv("MATRIX_PHASE1_RELEASE_B", "")
	t.Setenv("MATRIX_PHASE1_SECURITY_MAIL_CONFIGURATION", "")
	t.Setenv("MATRIX_PHASE1_SECURITY_MAIL_FIXTURE_ARCHIVE", "")
	t.Setenv("MATRIX_PHASE1_SECURITY_MAIL_FIXTURE_SHA256", "")
	t.Setenv("MATRIX_PHASE1_SECURITY_MAIL_FIXTURE_IMAGE_ID", "")
	if _, err := optionsFromEnvironment(); err != nil {
		t.Fatalf("read-only after-restart lifecycle requires removed private input: %v", err)
	}
}

func TestEdgeClientChecksSuccessAndProblemMediaTypes(t *testing.T) {
	for _, check := range []struct {
		name, mediaType string
		status          int
		valid           bool
	}{
		{"success", "application/json", http.StatusOK, true},
		{"authentication-denied", "application/problem+json", http.StatusUnauthorized, true},
		{"resource-hidden", "application/problem+json", http.StatusNotFound, true},
		{"invalid-success", "application/problem+json", http.StatusOK, false},
		{"invalid-problem", "application/json", http.StatusForbidden, false},
	} {
		t.Run(check.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
				response.Header().Set("Content-Type", check.mediaType)
				response.WriteHeader(check.status)
				_, _ = response.Write([]byte(`{}`))
			}))
			defer server.Close()
			client := newEdgeClient(server.URL)
			defer client.close()
			_, err := client.json(context.Background(), http.MethodGet, "/", nil, nil, nil, check.status)
			if (err == nil) != check.valid {
				t.Fatalf("response contract accepted=%t, want %t", err == nil, check.valid)
			}
		})
	}
}

func TestPhase1AccessKeySignerBindsExactNorthboundRequest(t *testing.T) {
	createdAt := time.Date(2026, time.October, 7, 1, 2, 3, 456000000, time.UTC)
	material := bytes.Repeat([]byte{0x2a}, 32)
	secret, err := iamv1.NewSecret("mak1." + base64.RawURLEncoding.EncodeToString(material))
	if err != nil {
		t.Fatal(err)
	}
	created := iamv1.CreateAccessKeyResponse{
		Outcome: "APPLIED",
		Key: iamv1.AccessKey{
			APIVersion: iamv1.APIVersion, Kind: "AccessKey", ID: "key-phase1",
			AccountID: "account-phase1", UserID: "user-phase1", Status: iamv1.AccessKeyEnabled,
			NetworkRestrictions: iamv1.AccessKeyNetworkRestrictions{AllowedSourceCIDRs: []string{"172.18.0.1/32"}},
			ResourceVersion:     1, CreatedAt: createdAt, UpdatedAt: createdAt,
		},
		Secret: secret,
	}
	header, err := signAccessKeyRequest(created, "installation-phase1", "http://127.0.0.1:8080",
		"/api/paas/v1/applications?after=pc1.opaque")
	if err != nil {
		t.Fatal(err)
	}
	headerBytes := header.CopyBytes()
	defer clear(headerBytes)
	parameters, signature, err := iamv1.ParseAccessKeyAuthorization(string(headerBytes))
	if err != nil || parameters.AccessKeyID != created.Key.ID || parameters.InstallationID != "installation-phase1" ||
		parameters.Audience != iamv1.ProductPaaS || parameters.SignedAt <= 0 {
		t.Fatalf("signed header parameters = %#v / %v", parameters, err)
	}
	httpRequest := iamv1.AccessKeyHTTPRequest{
		Method: http.MethodGet, Scheme: "http", Authority: "127.0.0.1:8080",
		EscapedPath: "/api/paas/v1/applications", RawQuery: "after=pc1.opaque", BodyDigest: fixedDigest(""),
	}
	canonical, err := iamv1.AccessKeySigningBytes(parameters, httpRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(canonical)
	mac := hmac.New(sha256.New, material)
	_, _ = mac.Write(canonical)
	wantSignature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	gotSignature := signature.CopyBytes()
	defer clear(gotSignature)
	if string(gotSignature) != wantSignature {
		t.Fatal("phase1 signer did not bind the exact external request")
	}
	for name, input := range map[string]struct{ origin, target string }{
		"https topology": {"https://127.0.0.1:8080", "/api/paas/v1/applications"},
		"origin path":    {"http://127.0.0.1:8080/base", "/api/paas/v1/applications"},
		"empty query":    {"http://127.0.0.1:8080", "/api/paas/v1/applications?"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := signAccessKeyRequest(created, "installation-phase1", input.origin, input.target); err == nil {
				t.Fatal("invalid signed fixture input accepted")
			}
		})
	}
	for _, name := range []string{"Authorization", "Forwarded", "X-Forwarded-For", "X-Real-IP",
		"X-Matrix-External-Origin", "X-Matrix-External-Request-Target", "X-Matrix-External-Source-IP",
		"X-Matrix-Edge-Assertion", "X-Matrix-Subject-Credential"} {
		if forgedEdgeHeaders("signed")[name] == "" {
			t.Fatalf("forged edge attack omitted %s", name)
		}
	}
}

func TestRetainedAccessKeyBindsCurrentCredentialAndCustodian(t *testing.T) {
	now := time.Date(2026, time.October, 10, 1, 2, 3, 456000000, time.UTC)
	secret := []byte("mak1." + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x3a}, 32)))
	fixture := accessKeyRetention{
		Key: iamv1.AccessKey{
			APIVersion: iamv1.APIVersion, Kind: "AccessKey", ID: "key-retained",
			AccountID: "account-retained", UserID: "member-user", Status: iamv1.AccessKeyEnabled,
			NetworkRestrictions: iamv1.AccessKeyNetworkRestrictions{AllowedSourceCIDRs: []string{"0.0.0.0/0"}},
			ResourceVersion:     3, CreatedAt: now, UpdatedAt: now.Add(time.Microsecond),
		},
		Secret: secret,
		CustodianGrant: iamv1.PolicyAttachment{
			APIVersion: iamv1.APIVersion, Kind: "PolicyAttachment", ID: "attachment-key-custodian",
			AccountID: "account-retained", Target: iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetUser, ID: "root-user"},
			PolicyID: "policy-key-custodian", Scope: iamv1.AuthorityScopeTenant, ResourceVersion: 1,
			CreatedAt: now, UpdatedAt: now,
		},
	}
	if !validAccessKeyRetention(fixture, "account-retained", "member-user", "root-user") {
		t.Fatal("valid retained access key was rejected")
	}
	secretValue, err := iamv1.NewSecret(string(secret))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signAccessKeyMaterial(fixture.Key, secretValue, "installation-phase1", "http://127.0.0.1:8080",
		"/api/paas/v1/applications"); err != nil {
		t.Fatalf("current retained key could not sign: %v", err)
	}
	for name, mutate := range map[string]func(*accessKeyRetention){
		"foreign account":   func(value *accessKeyRetention) { value.Key.AccountID = "account-other" },
		"foreign user":      func(value *accessKeyRetention) { value.Key.UserID = "member-other" },
		"disabled key":      func(value *accessKeyRetention) { value.Key.Status = iamv1.AccessKeyDisabled },
		"different network": func(value *accessKeyRetention) { value.Key.NetworkRestrictions.AllowedSourceCIDRs = []string{"192.0.2.0/24"} },
		"missing secret":    func(value *accessKeyRetention) { value.Secret = nil },
		"foreign custodian": func(value *accessKeyRetention) { value.CustodianGrant.Target.ID = "root-other" },
		"revoked custodian": func(value *accessKeyRetention) {
			revoked := now.Add(time.Second)
			value.CustodianGrant.RevokedAt = &revoked
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := fixture
			changed.Secret = append([]byte(nil), fixture.Secret...)
			mutate(&changed)
			if validAccessKeyRetention(changed, "account-retained", "member-user", "root-user") {
				t.Fatal("changed retained access key was accepted")
			}
		})
	}
}

func TestRetainedAccessKeyDirectoryAllowsSameTenantGrowthOnly(t *testing.T) {
	now := time.Date(2026, time.October, 10, 2, 3, 4, 567000000, time.UTC)
	application := func(id paasv1.ResourceID, tenant paasv1.TenantID) paasv1.Application {
		return paasv1.Application{APIVersion: paasv1.APIVersion, Kind: "Application", Metadata: paasv1.ResourceMetadata{
			ID: id, Name: string(id), Scope: paasv1.ResourceScope{Kind: paasv1.AuthorityTenant, TenantID: tenant},
			ResourceVersion: 1, CreatedAt: now, UpdatedAt: now,
		}}
	}
	directory := paasv1.ApplicationList{APIVersion: paasv1.APIVersion, Kind: "ApplicationList", Items: []paasv1.Application{
		application("phase1-after-upgrade", "account-retained"), application(tenantApplicationID, "account-retained"),
	}}
	if !validRetainedApplicationDirectory(directory, "account-retained") {
		t.Fatal("valid same-tenant directory growth was rejected")
	}
	for name, mutate := range map[string]func(*paasv1.ApplicationList){
		"target missing": func(value *paasv1.ApplicationList) { value.Items = value.Items[:1] },
		"foreign tenant": func(value *paasv1.ApplicationList) { value.Items[1].Metadata.Scope.TenantID = "account-other" },
		"incomplete page": func(value *paasv1.ApplicationList) { value.NextAfter = "pc1.more" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := directory
			changed.Items = append([]paasv1.Application(nil), directory.Items...)
			mutate(&changed)
			if validRetainedApplicationDirectory(changed, "account-retained") {
				t.Fatal("invalid retained AccessKey directory was accepted")
			}
		})
	}
}

func optionsFromEnvironment() (options, error) {
	phase := os.Getenv("MATRIX_PHASE1_E2E_PHASE")
	if phase != "run" && phase != "after-restart" {
		return options{}, fail("command-input")
	}
	edge := os.Getenv("MATRIX_PHASE1_EDGE")
	if edge == "" {
		edge = defaultEdgeEndpoint
	}
	endpoint, err := url.Parse(edge)
	if err != nil || endpoint.Scheme != "http" || endpoint.User != nil || endpoint.Path != "" ||
		endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return options{}, fail("command-input")
	}
	host, port, err := net.SplitHostPort(endpoint.Host)
	portNumber, portErr := strconv.ParseUint(port, 10, 16)
	if err != nil || host != "127.0.0.1" || portErr != nil || portNumber == 0 {
		return options{}, fail("command-input")
	}
	config := options{
		root:                   os.Getenv("MATRIX_PHASE1_ROOT"),
		releaseA:               os.Getenv("MATRIX_PHASE1_RELEASE_A"),
		releaseB:               os.Getenv("MATRIX_PHASE1_RELEASE_B"),
		trustKey:               os.Getenv("MATRIX_PHASE1_TRUST_KEY"),
		securityMail:           os.Getenv("MATRIX_PHASE1_SECURITY_MAIL_CONFIGURATION"),
		securityMailFixture:    os.Getenv("MATRIX_PHASE1_SECURITY_MAIL_FIXTURE_ARCHIVE"),
		securityMailFixtureSHA: os.Getenv("MATRIX_PHASE1_SECURITY_MAIL_FIXTURE_SHA256"),
		securityMailFixtureID:  os.Getenv("MATRIX_PHASE1_SECURITY_MAIL_FIXTURE_IMAGE_ID"),
		edge:                   edge,
		afterStart:             phase == "after-restart",
	}
	for _, path := range []string{config.root, config.releaseA, config.trustKey} {
		if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return options{}, fail("command-input")
		}
	}
	if !config.afterStart {
		for _, path := range []string{config.releaseB, config.securityMail, config.securityMailFixture} {
			if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
				return options{}, fail("command-input")
			}
		}
		if !validSHA256(config.securityMailFixtureSHA) || !validSHA256(config.securityMailFixtureID) {
			return options{}, fail("command-input")
		}
	}
	return config, nil
}

func runGate(ctx context.Context, config options) error {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		return fail("unsupported-host")
	}
	trust, err := os.ReadFile(config.trustKey)
	if err != nil {
		return fail("release-authentication")
	}
	defer clear(trust)
	a, err := release.VerifyDirectory(config.releaseA, trust)
	if err != nil {
		return fail("release-a-authentication")
	}
	if config.afterStart {
		return newGate(config, releasePair{a: a}).afterRestart(ctx)
	}
	b, err := release.VerifyDirectory(config.releaseB, trust)
	if err != nil {
		return fail("release-b-authentication")
	}
	if err := validateReleasePair(a, b); err != nil {
		return err
	}
	return newGate(config, releasePair{a: a, b: b}).beforeRestart(ctx)
}
