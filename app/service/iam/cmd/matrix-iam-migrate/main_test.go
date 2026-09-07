package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadPlatformServiceBindingReadsExactSecretFile(t *testing.T) {
	credential := []byte("mx1.PlatformMigrationProcessCredential000000000001")
	path := filepath.Join(t.TempDir(), "platform-credential")
	if err := os.WriteFile(path, credential, 0o600); err != nil {
		t.Fatalf("write platform credential fixture: %v", err)
	}
	t.Setenv(installationIDEnvironment, "installation-example")
	t.Setenv(platformCredentialFileEnvironment, path)
	binding, err := loadPlatformServiceBinding()
	if err != nil {
		t.Fatalf("load platform service binding: %v", err)
	}
	actual := binding.Credential.CopyBytes()
	defer clear(actual)
	if binding.InstallationID != "installation-example" || !bytes.Equal(actual, credential) {
		t.Fatal("loaded platform service binding differs from its exact files")
	}
}

func TestLoadPlatformServiceBindingFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "platform-credential")
	if err := os.WriteFile(path, []byte("invalid\ncredential"), 0o600); err != nil {
		t.Fatalf("write invalid platform credential fixture: %v", err)
	}
	t.Setenv(installationIDEnvironment, "invalid installation")
	t.Setenv(platformCredentialFileEnvironment, path)
	if _, err := loadPlatformServiceBinding(); err == nil {
		t.Fatal("migration process accepted an invalid installation identity")
	}
	t.Setenv(installationIDEnvironment, "installation-example")
	if _, err := loadPlatformServiceBinding(); err == nil {
		t.Fatal("migration process accepted invalid credential content")
	}
}
