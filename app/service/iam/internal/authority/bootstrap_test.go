package authority

import (
	"bytes"
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

func TestBootstrapDigestPreservesLegacyReplayIdentity(t *testing.T) {
	document := authorityBootstrap(t)
	legacy := document
	legacy.Services = append(
		[]iamv1.BootstrapServiceCredential(nil),
		document.Services[:1]...,
	)
	legacy.Services = append(legacy.Services, document.Services[2:]...)
	if iamv1.ValidateBootstrapDocument(legacy) == nil ||
		iamv1.ValidateBootstrapReplayDocument(legacy) != nil {
		t.Fatal("legacy bootstrap validation boundary is invalid")
	}
	first, err := BootstrapDigest(legacy)
	if err != nil {
		t.Fatalf("digest legacy bootstrap replay: %v", err)
	}
	second, err := BootstrapDigest(legacy)
	if err != nil || second != first {
		t.Fatalf("repeat legacy digest = %q err=%v, want %q", second, err, first)
	}
}

func TestBootstrapDigestMatchesAcceptedLegacyCanonicalDocument(t *testing.T) {
	const legacyJSON = `{
  "apiVersion": "iam.matrix.xiak.com/v1",
  "kind": "IAMBootstrap",
  "installationId": "installation-example",
  "organization": {
    "id": "organization-example",
    "displayName": "Example Organization"
  },
  "administrator": {
    "id": "principal-admin",
    "loginName": "admin",
    "displayName": "Initial Administrator",
    "password": "Example-Only-Admin-Password-49!"
  },
  "services": [
    {
      "purpose": "IAM",
      "principalId": "service-iam",
      "credential": "example-only-iam-credential-00000000000000001"
    },
    {
      "purpose": "PAAS",
      "principalId": "service-paas",
      "credential": "example-only-paas-credential-0000000000000001"
    },
    {
      "purpose": "AUDIT",
      "principalId": "service-audit",
      "credential": "example-only-audit-credential-0000000000000001"
    },
    {
      "purpose": "INSTALLATION_VERIFIER",
      "principalId": "service-installation-verifier",
      "credential": "example-only-verifier-credential-00000000000001"
    }
  ]
}`
	document, err := iamv1.DecodeBootstrapReplayDocument(bytes.NewBufferString(legacyJSON))
	if err != nil {
		t.Fatalf("decode accepted legacy bootstrap: %v", err)
	}
	digest, err := BootstrapDigest(document)
	if err != nil {
		t.Fatalf("digest accepted legacy bootstrap: %v", err)
	}
	const acceptedDigest = "sha256:f2e63e7bcdfc75be50f40247ac0245ace26bbc27952026db538327b59b82ac7c"
	if digest != acceptedDigest {
		t.Fatalf("legacy bootstrap digest=%q want=%q", digest, acceptedDigest)
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
			service(iamv1.ServiceIAM, "service-iam", "mx1.IAMExampleCredential000000000000000000001"),
			service(iamv1.ServicePlatform, "service-platform", "mx1.PlatformExampleCredential0000000000000001"),
			service(iamv1.ServicePaaS, "service-paas", "mx1.PaaSExampleCredential00000000000000000001"),
			service(iamv1.ServiceAudit, "service-audit", "mx1.AuditExampleCredential0000000000000000001"),
			service(iamv1.ServiceInstallationVerifier, "service-verifier", "mx1.VerifierExampleCredential0000000000000001"),
		},
	}
}
