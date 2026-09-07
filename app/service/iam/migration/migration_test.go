package migration

import (
	"strings"
	"testing"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
)

func TestPlatformServiceArgumentsAreDeterministicAndInstallationBound(t *testing.T) {
	credentialText := "mx1.PlatformMigrationCredential000000000000000001"
	credential, err := iamv1.NewSecret(credentialText)
	if err != nil {
		t.Fatalf("create platform migration credential: %v", err)
	}
	binding := PlatformServiceBinding{
		InstallationID: "installation-example",
		Credential:     credential,
	}
	first, err := platformServiceArguments(binding)
	if err != nil {
		t.Fatalf("derive platform service arguments: %v", err)
	}
	second, err := platformServiceArguments(binding)
	if err != nil || second != first {
		t.Fatalf("repeat platform service arguments=%#v err=%v, want %#v", second, err, first)
	}
	if iamv1.ValidateDigest("lookupDigest", first.lookupDigest) != nil ||
		iamv1.ValidateDigest("verificationDigest", first.verificationDigest) != nil ||
		iamv1.ValidateDigest("requestDigest", first.requestDigest) != nil ||
		first.lookupDigest == first.verificationDigest {
		t.Fatalf("platform service digests are invalid: %#v", first)
	}

	other := binding
	other.InstallationID = "installation-other"
	otherArguments, err := platformServiceArguments(other)
	if err != nil {
		t.Fatalf("derive other installation arguments: %v", err)
	}
	if otherArguments.lookupDigest != first.lookupDigest ||
		otherArguments.verificationDigest != first.verificationDigest ||
		otherArguments.requestDigest == first.requestDigest {
		t.Fatalf("platform enrollment request is not installation-bound: %#v / %#v", first, otherArguments)
	}
}

func TestPlatformServiceArgumentsRejectInvalidBindingWithoutSecretLeak(t *testing.T) {
	credentialText := "mx1.PlatformMigrationSecretMustRemainRedacted000001"
	credential, err := iamv1.NewSecret(credentialText)
	if err != nil {
		t.Fatalf("create platform migration credential: %v", err)
	}
	_, err = platformServiceArguments(PlatformServiceBinding{
		InstallationID: "invalid installation",
		Credential:     credential,
	})
	if err == nil || strings.Contains(err.Error(), credentialText) {
		t.Fatalf("invalid platform binding error=%v", err)
	}
}
