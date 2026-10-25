package migration

import (
	"strings"
	"testing"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
)

func TestReleaseServiceArgumentsAreDeterministicAndInstallationBound(t *testing.T) {
	platform := testServiceCredential(t, "mx1.PlatformMigrationCredential000000000000000001")
	devops := testServiceCredential(t, "mx1.DevOpsMigrationCredential00000000000000000001")
	bindings := []ReleaseServiceBinding{
		{Purpose: iamv1.ServicePlatform, Credential: platform},
		{Purpose: iamv1.ServiceDevOps, Credential: devops},
	}
	first, err := releaseServiceArguments("installation-example", bindings)
	if err != nil {
		t.Fatalf("derive release service arguments: %v", err)
	}
	second, err := releaseServiceArguments("installation-example", bindings)
	if err != nil || len(second) != len(first) {
		t.Fatalf("repeat release service arguments=%#v err=%v, want %#v", second, err, first)
	}
	for index := range first {
		if second[index] != first[index] ||
			iamv1.ValidateDigest("lookupDigest", first[index].lookupDigest) != nil ||
			iamv1.ValidateDigest("verificationDigest", first[index].verificationDigest) != nil ||
			iamv1.ValidateDigest("requestDigest", first[index].requestDigest) != nil ||
			first[index].lookupDigest == first[index].verificationDigest {
			t.Fatalf("release service digests are invalid: %#v", first[index])
		}
	}
	if first[0].principalID != "service-platform" || first[1].principalID != "service-devops" ||
		first[0].requestDigest == first[1].requestDigest {
		t.Fatalf("release service identities are invalid: %#v", first)
	}

	other, err := releaseServiceArguments("installation-other", bindings)
	if err != nil {
		t.Fatalf("derive other installation arguments: %v", err)
	}
	if other[1].lookupDigest != first[1].lookupDigest ||
		other[1].verificationDigest != first[1].verificationDigest ||
		other[1].requestDigest == first[1].requestDigest {
		t.Fatalf("release enrollment request is not installation-bound: %#v / %#v", first, other)
	}
}

func TestReleaseServiceArgumentsRejectInvalidBindingsWithoutSecretLeak(t *testing.T) {
	credentialText := "mx1.ReleaseMigrationSecretMustRemainRedacted0000001"
	credential := testServiceCredential(t, credentialText)
	tests := [][]ReleaseServiceBinding{
		nil,
		{{Purpose: iamv1.ServiceDevOps, Credential: credential}},
		{
			{Purpose: iamv1.ServicePlatform, Credential: credential},
			{Purpose: iamv1.ServicePlatform, Credential: credential},
		},
		{
			{Purpose: iamv1.ServicePlatform, Credential: credential},
			{Purpose: iamv1.ServicePaaS, Credential: credential},
		},
	}
	for _, bindings := range tests {
		_, err := releaseServiceArguments("installation-example", bindings)
		if err == nil || strings.Contains(err.Error(), credentialText) {
			t.Fatalf("invalid release bindings=%#v error=%v", bindings, err)
		}
	}
	_, err := releaseServiceArguments("invalid installation", []ReleaseServiceBinding{{
		Purpose: iamv1.ServicePlatform, Credential: credential,
	}})
	if err == nil || strings.Contains(err.Error(), credentialText) {
		t.Fatalf("invalid installation binding error=%v", err)
	}
}

func testServiceCredential(t *testing.T, value string) iamv1.Secret {
	t.Helper()
	credential, err := iamv1.NewSecret(value)
	if err != nil {
		t.Fatalf("create service credential: %v", err)
	}
	return credential
}
