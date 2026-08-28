package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/iam/internal/usecase/identityaccess"
)

func TestLocalRecoveryProcessHasOnlyFixedModesAndStableFailures(t *testing.T) {
	for _, args := range [][]string{nil, {"recover"}, {"apply", "other"}, {"inspect", "--tenant", "other"}, {"--help"}, {"--database-dsn", "secret"}} {
		var output bytes.Buffer
		err := run(context.Background(), args, &output, func(string) string { t.Fatal("invalid argv read private configuration"); return "" })
		if !errors.Is(err, identityaccess.ErrInvalidArgument) || output.Len() != 0 {
			t.Fatalf("invalid mode result: %v", err)
		}
	}
	for _, candidate := range []struct {
		err  error
		code int
		text string
	}{
		{identityaccess.ErrInvalidArgument, 2, "IAM_LOCAL_RECOVERY_INVALID"},
		{identityaccess.ErrForbidden, 3, "IAM_LOCAL_RECOVERY_FORBIDDEN"},
		{identityaccess.ErrConflict, 4, "IAM_LOCAL_RECOVERY_CONFLICT"},
		{identityaccess.ErrUnavailable, 6, "IAM_LOCAL_RECOVERY_UNAVAILABLE"},
		{errors.New("native sensitive material"), 6, "IAM_LOCAL_RECOVERY_UNAVAILABLE"},
		{context.DeadlineExceeded, 6, "IAM_LOCAL_RECOVERY_UNAVAILABLE"},
	} {
		if exitCode(candidate.err) != candidate.code || errorCode(candidate.err) != candidate.text {
			t.Fatal("unstable local error classification")
		}
	}
	if exitCode(nil) != 0 {
		t.Fatal("success exit code is nonzero")
	}
}

func TestLocalRecoveryRejectsAlteredIntentBeforeDatabaseAccess(t *testing.T) {
	secret := func(value string) iamv1.Secret {
		result, err := iamv1.NewSecret(value)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	local := iamv1.LocalCredentialRecoveryAuthority{APIVersion: iamv1.APIVersion, Kind: "LocalCredentialRecoveryAuthority", Purpose: iamv1.LocalCredentialRecoveryPurpose,
		Scope:         iamv1.LocalCredentialRecoveryScope{InstallationID: "installation-original", BootstrapDigest: "sha256:" + strings.Repeat("a", 64), OrganizationID: "organization-original", PrincipalID: "principal-original"},
		CapabilityKey: secret(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x4a}, 32)))}
	request := iamv1.LocalCredentialRecoveryRequest{APIVersion: iamv1.APIVersion, Kind: "LocalCredentialRecoveryRequest", Purpose: iamv1.LocalCredentialRecoveryPurpose,
		CommandID: "command-original", Scope: local.Scope, Expected: iamv1.LocalCredentialRecoveryExpected{OrganizationResourceVersion: 1, PrincipalResourceVersion: 1, CredentialGeneration: 1,
			PlatformBindingID: "binding-original", PlatformBindingResourceVersion: 1}, NewPassword: secret("Original-Private-Password-19!")}
	signed, err := iamv1.SignLocalCredentialRecoveryRequest(local, request)
	if err != nil {
		t.Fatal(err)
	}
	signed.NewPassword = secret("Substituted-Private-Password-29!")
	dir := t.TempDir()
	authorityPath, requestPath := filepath.Join(dir, "authority.json"), filepath.Join(dir, "request.json")
	encoded, err := iamv1.EncodeLocalCredentialRecoveryAuthority(local)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(authorityPath, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	clear(encoded)
	encoded, err = iamv1.EncodeLocalCredentialRecoveryRequest(signed)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(requestPath, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	clear(encoded)
	var output bytes.Buffer
	err = run(context.Background(), []string{"apply"}, &output, func(name string) string {
		switch name {
		case authorityFileEnvironment:
			return authorityPath
		case requestFileEnvironment:
			return requestPath
		default:
			t.Fatal("unproved intent accessed database configuration")
			return ""
		}
	})
	if !errors.Is(err, identityaccess.ErrForbidden) || output.Len() != 0 {
		t.Fatalf("unproved local intent result: %v", err)
	}
}
