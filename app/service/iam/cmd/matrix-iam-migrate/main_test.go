package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadReleaseServiceBindingsReadsSelectedExactSecretFiles(t *testing.T) {
	platform := []byte("mx1.PlatformMigrationProcessCredential000000000001")
	devops := []byte("mx1.DevOpsMigrationProcessCredential00000000000001")
	directory := t.TempDir()
	platformPath := filepath.Join(directory, "platform-credential")
	devopsPath := filepath.Join(directory, "devops-credential")
	if err := os.WriteFile(platformPath, platform, 0o600); err != nil {
		t.Fatalf("write platform credential fixture: %v", err)
	}
	if err := os.WriteFile(devopsPath, devops, 0o600); err != nil {
		t.Fatalf("write DevOps credential fixture: %v", err)
	}
	t.Setenv(installationIDEnvironment, "installation-example")
	t.Setenv(platformCredentialFileEnvironment, platformPath)
	t.Setenv(devopsCredentialFileEnvironment, devopsPath)
	installationID, bindings, err := loadReleaseServiceBindings()
	if err != nil {
		t.Fatalf("load release service bindings: %v", err)
	}
	if installationID != "installation-example" || len(bindings) != 2 {
		t.Fatalf("loaded release service inventory=%q %#v", installationID, bindings)
	}
	actualPlatform := bindings[0].Credential.CopyBytes()
	actualDevOps := bindings[1].Credential.CopyBytes()
	defer clear(actualPlatform)
	defer clear(actualDevOps)
	if bindings[0].Purpose != "PLATFORM" || !bytes.Equal(actualPlatform, platform) ||
		bindings[1].Purpose != "DEVOPS" || !bytes.Equal(actualDevOps, devops) {
		t.Fatal("loaded release service bindings differ from their exact files")
	}
}

func TestLoadReleaseServiceBindingsOmitsUnselectedDevOps(t *testing.T) {
	credential := []byte("mx1.PlatformMigrationProcessCredential000000000001")
	path := filepath.Join(t.TempDir(), "platform-credential")
	if err := os.WriteFile(path, credential, 0o600); err != nil {
		t.Fatalf("write platform credential fixture: %v", err)
	}
	t.Setenv(installationIDEnvironment, "installation-example")
	t.Setenv(platformCredentialFileEnvironment, path)
	_, bindings, err := loadReleaseServiceBindings()
	if err != nil || len(bindings) != 1 || bindings[0].Purpose != "PLATFORM" {
		t.Fatalf("unselected DevOps binding=%#v err=%v", bindings, err)
	}
}

func TestLoadReleaseServiceBindingsFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "platform-credential")
	if err := os.WriteFile(path, []byte("invalid\ncredential"), 0o600); err != nil {
		t.Fatalf("write invalid platform credential fixture: %v", err)
	}
	t.Setenv(installationIDEnvironment, "invalid installation")
	t.Setenv(platformCredentialFileEnvironment, path)
	if _, _, err := loadReleaseServiceBindings(); err == nil {
		t.Fatal("migration process accepted an invalid installation identity")
	}
	t.Setenv(installationIDEnvironment, "installation-example")
	if _, _, err := loadReleaseServiceBindings(); err == nil {
		t.Fatal("migration process accepted invalid credential content")
	}
}
