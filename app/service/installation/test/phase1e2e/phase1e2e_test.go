package phase1e2e

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
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

func TestContactReplacementRetentionRequiresThreeAcceptedDeliveries(t *testing.T) {
	verifiedAt := time.Date(2026, time.October, 4, 1, 2, 3, 456000000, time.UTC)
	contact := iamv1.NotificationContact{
		APIVersion: iamv1.APIVersion, Kind: "NotificationContact",
		AccountID: "account-retained", UserID: "principal-user", State: "VERIFIED",
		ResourceVersion: 2, Email: securityMailCurrentRecipient, VerifiedAt: &verifiedAt,
	}
	verification := iamv1.NotificationContactVerification{ID: "contact-replacement-one"}
	want := contactReplacementRetention{
		AccountID: contact.AccountID, UserID: contact.UserID, VerificationID: verification.ID,
		CompletionEventID: "event-contact-replaced", ExpectedResourceVersion: 1,
		Email: securityMailCurrentRecipient, State: "VERIFIED",
		Notifications: []securityNotificationRetention{
			{ID: "notice-code", EventID: "event-code", Kind: "ADDRESS_VERIFICATION", Email: securityMailCurrentRecipient, ContactRevision: 1, State: "ACCEPTED", Attempts: 1, LastOutcome: "ACCEPTED", LastSMTPCode: 250},
			{ID: "notice-current", EventID: "event-contact-replaced", Kind: "CONTACT_REPLACED_CURRENT", Email: securityMailCurrentRecipient, ContactRevision: 2, State: "ACCEPTED", Attempts: 1, LastOutcome: "ACCEPTED", LastSMTPCode: 250},
			{ID: "notice-previous", EventID: "event-contact-replaced", Kind: "CONTACT_REPLACED_PREVIOUS", Email: securityMailPreviousRecipient, ContactRevision: 1, State: "ACCEPTED", Attempts: 1, LastOutcome: "ACCEPTED", LastSMTPCode: 250},
		},
	}
	if !validContactReplacementRetention(want, contact, verification) || !sameContactReplacementRetention(want, want) {
		t.Fatal("exact replacement delivery history was not retained")
	}
	clone := func() contactReplacementRetention {
		observed := want
		observed.Notifications = append([]securityNotificationRetention(nil), want.Notifications...)
		return observed
	}
	for name, mutate := range map[string]func(*contactReplacementRetention){
		"account":      func(value *contactReplacementRetention) { value.AccountID = "account-other" },
		"user":         func(value *contactReplacementRetention) { value.UserID = "principal-other" },
		"verification": func(value *contactReplacementRetention) { value.VerificationID = "replacement-other" },
		"completion":   func(value *contactReplacementRetention) { value.CompletionEventID = "event-other" },
		"version":      func(value *contactReplacementRetention) { value.ExpectedResourceVersion++ },
		"address":      func(value *contactReplacementRetention) { value.Email = securityMailPreviousRecipient },
		"state":        func(value *contactReplacementRetention) { value.State = "PENDING" },
		"missing-row":  func(value *contactReplacementRetention) { value.Notifications = value.Notifications[:2] },
		"recipient":    func(value *contactReplacementRetention) { value.Notifications[2].Email = securityMailCurrentRecipient },
		"revision":     func(value *contactReplacementRetention) { value.Notifications[1].ContactRevision = 1 },
		"not-accepted": func(value *contactReplacementRetention) { value.Notifications[0].State = "PENDING" },
		"retry":        func(value *contactReplacementRetention) { value.Notifications[0].Attempts = 2 },
		"missing-250":  func(value *contactReplacementRetention) { value.Notifications[0].LastSMTPCode = 0 },
		"wrong-fact":   func(value *contactReplacementRetention) { value.Notifications[1].EventID = "event-other" },
		"duplicate-kind": func(value *contactReplacementRetention) {
			value.Notifications[2].Kind = "CONTACT_REPLACED_CURRENT"
		},
	} {
		t.Run(name, func(t *testing.T) {
			observed := clone()
			mutate(&observed)
			if validContactReplacementRetention(observed, contact, verification) || sameContactReplacementRetention(observed, want) {
				t.Fatal("changed replacement delivery history was accepted")
			}
		})
	}
}

func TestContactReplacementObservationQueryUsesClosedHexLiterals(t *testing.T) {
	accountID := iamv1.AccountID("account-'-$USER")
	userID := iamv1.PrincipalID("principal-'-$VERIFICATION")
	verificationID := "verification-'-$TENANT"
	query := contactReplacementObservationQuery(accountID, userID, verificationID)
	for _, unsafe := range []string{string(accountID), string(userID), verificationID, ":'", "$TENANT", "$USER", "$VERIFICATION"} {
		if strings.Contains(query, unsafe) {
			t.Fatalf("observation query contains an unencoded value or placeholder %q", unsafe)
		}
	}
	if strings.Count(query, "convert_from(decode('") != 3 {
		t.Fatal("observation query does not contain exactly three hex-decoded predicates")
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
