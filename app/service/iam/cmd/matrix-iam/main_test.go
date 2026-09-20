package main

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
)

func TestCursorKeyRequiresExactProtectedInstallationFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "iam-cursor-key")
	for _, value := range []string{"", strings.Repeat("a", 63), strings.Repeat("a", 65), strings.Repeat("A", 64), strings.Repeat("a", 63) + " ", strings.Repeat("a", 64) + "\n", strings.Repeat("g", 64)} {
		if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
		if key, err := readCursorKey(path); err == nil || key != nil {
			t.Fatal("noncanonical key file accepted")
		}
	}
	if err := os.WriteFile(path, []byte(strings.Repeat("ab", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	key, err := readCursorKey(path)
	if err != nil || !bytes.Equal(key, bytes.Repeat([]byte{0xab}, 32)) {
		t.Fatal("valid private key rejected")
	}
	clear(key)
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := readCursorKey(path); err == nil {
			t.Fatal("world-readable key accepted")
		}
	}
	if _, err := readCursorKey("relative-key"); err == nil {
		t.Fatal("relative key accepted")
	}
}

func TestIAMNetworkConfigurationRequiresPrivateFiles(t *testing.T) {
	fields := []string{databaseDSNFileEnvironment, bootstrapFileEnvironment, listenAddressEnvironment, cursorKeyFileEnvironment, accessKeyWrappingFileEnvironment, totpKeyringFileEnvironment}
	for _, field := range fields {
		t.Setenv(field, "fixture")
	}
	if _, err := loadConfiguration(); err != nil {
		t.Fatal(err)
	}
	for _, field := range fields {
		t.Setenv(field, "")
		if _, err := loadConfiguration(); err == nil {
			t.Fatal("network IAM accepted a missing required setting", field)
		}
		t.Setenv(field, "fixture")
	}
}

func TestAccessKeyWrappingFileBindsActualBootstrap(t *testing.T) {
	encodedBootstrap, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "..", "api", "iam", "v1", "examples", "bootstrap-document.json"))
	if err != nil {
		t.Fatal(err)
	}
	bootstrap, err := iamv1.DecodeBootstrapDocument(bytes.NewReader(encodedBootstrap))
	if err != nil {
		t.Fatal(err)
	}
	digest, err := iamv1.BootstrapDigest(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	material, err := iamv1.NewSecret(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x57}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	keyring := iamv1.AccessKeyWrappingKeyring{APIVersion: iamv1.APIVersion, Kind: "AccessKeyWrappingKeyring", Purpose: iamv1.AccessKeyWrappingPurpose,
		Scope: iamv1.AccessKeyWrappingScope{InstallationID: bootstrap.InstallationID, BootstrapDigest: digest}, ActiveWrappingKeyID: "wrapping-test",
		Keys: []iamv1.AccessKeyWrappingKey{{WrappingKeyID: "wrapping-test", FormatVersion: 1, KeyMaterial: material}}}
	encoded, err := iamv1.EncodeAccessKeyWrappingKeyring(keyring)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	path := filepath.Join(t.TempDir(), "wrapping-private.json")
	write := func(value []byte) {
		t.Helper()
		if err := os.WriteFile(path, value, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(encoded)
	actual, err := readAccessKeyWrapping(path, bootstrap)
	if err != nil || actual.Scope != keyring.Scope {
		t.Fatal("valid installation file rejected", err)
	}
	expectedCommitment, expectedErr := iamv1.AccessKeyWrappingKeyCommitment(keyring, keyring.ActiveWrappingKeyID)
	actualCommitment, actualErr := iamv1.AccessKeyWrappingKeyCommitment(actual, actual.ActiveWrappingKeyID)
	if expectedErr != nil || actualErr != nil || actualCommitment != expectedCommitment {
		t.Fatal("private reader changed wrapping material")
	}
	for _, variant := range []string{"installation", "bootstrap", "invalid-bootstrap"} {
		changed := bootstrap
		switch variant {
		case "installation":
			changed.InstallationID = "other-installation"
		case "bootstrap":
			changed.Administrator.DisplayName = "Different bootstrap"
		case "invalid-bootstrap":
			changed.Kind = "OtherKind"
		}
		if _, err := readAccessKeyWrapping(path, changed); err == nil {
			t.Fatal("wrapping accepted a different actual bootstrap", variant)
		}
	}
	for _, value := range [][]byte{nil, []byte("{}"), append(append([]byte(nil), encoded...), '\n'), bytes.Repeat([]byte{'x'}, int(iamv1.MaxAccessKeyWrappingKeyringBytes)+1)} {
		write(value)
		if _, err := readAccessKeyWrapping(path, bootstrap); err == nil || err.Error() != "IAM access key wrapping file is unavailable" {
			t.Fatal("noncanonical wrapping file accepted or error exposed input")
		}
	}
	write(encoded)
	for _, invalidPath := range []string{"relative-keyring", filepath.Dir(path), filepath.Join(filepath.Dir(path), "missing-private.json")} {
		if _, err := readAccessKeyWrapping(invalidPath, bootstrap); err == nil {
			t.Fatal("invalid file reference accepted")
		}
	}
	link := filepath.Join(filepath.Dir(path), "linked.json")
	if err := os.Symlink(path, link); err == nil {
		if _, err := readAccessKeyWrapping(link, bootstrap); err == nil {
			t.Fatal("linked wrapping file accepted")
		}
	} else if runtime.GOOS != "windows" {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		for _, mode := range []os.FileMode{0o400, 0o640, 0o644, 0o700, 0o600 | os.ModeSetuid} {
			if err := os.Chmod(path, mode); err != nil {
				t.Fatal(err)
			}
			if _, err := readAccessKeyWrapping(path, bootstrap); err == nil {
				t.Fatal("wrapping file accepted non-0600 permissions")
			}
		}
	}
}

func TestTOTPKeyringFileRequiresIndependentCanonicalInstallationMaterial(t *testing.T) {
	encodedBootstrap, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "..", "api", "iam", "v1", "examples", "bootstrap-document.json"))
	if err != nil {
		t.Fatal(err)
	}
	bootstrap, err := iamv1.DecodeBootstrapDocument(bytes.NewReader(encodedBootstrap))
	if err != nil {
		t.Fatal(err)
	}
	digest, err := iamv1.BootstrapDigest(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	material, _ := iamv1.NewSecret(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x74}, 32)))
	keyring := iamv1.TOTPKeyring{APIVersion: iamv1.APIVersion, Kind: "TOTPKeyring", Purpose: iamv1.TOTPWrappingPurpose,
		Scope:          iamv1.TOTPWrappingScope{InstallationID: bootstrap.InstallationID, BootstrapDigest: digest},
		KeysetRevision: 1, ActiveKeyID: "totp-test", Keys: []iamv1.TOTPWrappingKey{{KeyID: "totp-test", FormatVersion: 1, KeyMaterial: material}}}
	encoded, err := iamv1.EncodeTOTPKeyring(keyring)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	path := filepath.Join(t.TempDir(), "totp-private.json")
	write := func(value []byte) {
		t.Helper()
		if err := os.WriteFile(path, value, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(encoded)
	actual, err := readTOTPKeyring(path, bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	expectedDigest, _ := iamv1.TOTPKeysetDigest(keyring)
	actualDigest, err := iamv1.TOTPKeysetDigest(actual)
	if err != nil || actualDigest != expectedDigest {
		t.Fatal("reader changed TOTP material")
	}
	for _, variant := range []string{"installation", "bootstrap", "invalid-bootstrap"} {
		changed := bootstrap
		switch variant {
		case "installation":
			changed.InstallationID = "different-installation"
		case "bootstrap":
			changed.Administrator.DisplayName = "Different bootstrap"
		case "invalid-bootstrap":
			changed.Kind = "OtherKind"
		}
		if _, err := readTOTPKeyring(path, changed); err == nil {
			t.Fatal("TOTP accepted another sealed scope", variant)
		}
	}
	for _, value := range [][]byte{nil, []byte("{}"), append(append([]byte(nil), encoded...), '\n'),
		bytes.ReplaceAll(encoded, []byte(iamv1.TOTPWrappingPurpose), []byte(iamv1.AccessKeyWrappingPurpose)),
		bytes.Repeat([]byte{'x'}, int(iamv1.MaxTOTPKeyringBytes)+1)} {
		write(value)
		if _, err := readTOTPKeyring(path, bootstrap); err == nil || err.Error() != "IAM TOTP keyring file is unavailable" {
			t.Fatal("bad material accepted or error exposed input")
		}
	}
	write(encoded)
	for _, invalidPath := range []string{"relative-keyring", filepath.Dir(path), filepath.Join(filepath.Dir(path), "missing.json")} {
		if _, err := readTOTPKeyring(invalidPath, bootstrap); err == nil {
			t.Fatal("invalid material reference accepted")
		}
	}
	link := filepath.Join(filepath.Dir(path), "linked.json")
	if err := os.Symlink(path, link); err == nil {
		if _, err := readTOTPKeyring(link, bootstrap); err == nil {
			t.Fatal("linked material accepted")
		}
	} else if runtime.GOOS != "windows" {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		for _, mode := range []os.FileMode{0o400, 0o640, 0o644, 0o700, 0o600 | os.ModeSetuid} {
			if err := os.Chmod(path, mode); err != nil {
				t.Fatal(err)
			}
			if _, err := readTOTPKeyring(path, bootstrap); err == nil {
				t.Fatal("nonprivate material accepted")
			}
		}
	}
}
