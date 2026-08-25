package authority

import (
	"errors"
	"strings"
	"testing"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
)

func TestBootstrapClassifiesApplyEqualReplayAndConflict(t *testing.T) {
	document := authorityBootstrap(t)
	outcome, receipt, err := ClassifyBootstrap(nil, document)
	if err != nil || outcome != BootstrapApply {
		t.Fatalf("classify initial bootstrap: outcome=%q receipt=%#v err=%v", outcome, receipt, err)
	}
	replayOutcome, replayReceipt, err := ClassifyBootstrap(&receipt, document)
	if err != nil || replayOutcome != BootstrapEqualReplay || replayReceipt != receipt {
		t.Fatalf("classify equal replay: outcome=%q receipt=%#v err=%v", replayOutcome, replayReceipt, err)
	}

	changed := document
	changed.Administrator.Password = authoritySecret(t, "Changed-Admin-Password-73!")
	_, _, err = ClassifyBootstrap(&receipt, changed)
	if !errors.Is(err, ErrBootstrapConflict) || strings.Contains(err.Error(), "Changed-Admin") {
		t.Fatalf("changed bootstrap error was not a secret-free conflict: %v", err)
	}
	changed = document
	changed.InstallationID = "installation-other"
	if _, _, err := ClassifyBootstrap(&receipt, changed); !errors.Is(err, ErrBootstrapConflict) {
		t.Fatalf("different installation error = %v, want conflict", err)
	}
}

func TestBootstrapDigestIsStableForAnExactDocument(t *testing.T) {
	document := authorityBootstrap(t)
	first, err := BootstrapDigest(document)
	if err != nil {
		t.Fatalf("digest bootstrap: %v", err)
	}
	second, err := BootstrapDigest(document)
	if err != nil || second != first {
		t.Fatalf("repeat bootstrap digest = %q err=%v, want %q", second, err, first)
	}
	if err := iamv1.ValidateDigest("bootstrap.digest", first); err != nil {
		t.Fatalf("bootstrap digest is not a contract digest: %v", err)
	}
}

func authorityBootstrap(t *testing.T) iamv1.BootstrapDocument {
	t.Helper()
	service := func(purpose iamv1.ServicePurpose, id, credential string) iamv1.BootstrapServiceCredential {
		return iamv1.BootstrapServiceCredential{
			Purpose: purpose, PrincipalID: iamv1.PrincipalID(id), Credential: authoritySecret(t, credential),
		}
	}
	return iamv1.BootstrapDocument{
		APIVersion:     iamv1.APIVersion,
		Kind:           "IAMBootstrap",
		InstallationID: "installation-example",
		Organization: iamv1.InitialOrganization{
			ID: "organization-example", DisplayName: "Example Organization",
		},
		Administrator: iamv1.InitialAdministrator{
			ID: "principal-admin", LoginName: "admin", DisplayName: "Initial Administrator",
			Password: authoritySecret(t, "Initial-Admin-Password-49!"),
		},
		Services: []iamv1.BootstrapServiceCredential{
			service(iamv1.ServicePaaS, "service-paas", "mx1.PaaSExampleCredential00000000000000000001"),
			service(iamv1.ServiceAudit, "service-audit", "mx1.AuditExampleCredential0000000000000000001"),
			service(iamv1.ServiceAPISIX, "service-apisix", "mx1.APISIXExampleCredential000000000000000001"),
			service(iamv1.ServiceInstallationVerifier, "service-verifier", "mx1.VerifierExampleCredential0000000000000001"),
		},
	}
}
