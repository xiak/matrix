package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/xiak/matrix/app/service/installation/internal/releasetest"
	"github.com/xiak/matrix/app/service/installation/release"
)

func TestBuildHandlerAuthenticatesExactRelease(t *testing.T) {
	fixture, err := releasetest.Write(t.TempDir())
	if err != nil {
		t.Fatalf("write signed release fixture: %v", err)
	}
	credentialFile := filepath.Join(t.TempDir(), "platform-iam-credential")
	if err := os.WriteFile(credentialFile, []byte("platform-service-credential"), 0o600); err != nil {
		t.Fatalf("write platform credential: %v", err)
	}
	config := configuration{
		listenAddress:        "127.0.0.1:8080",
		iamEndpoint:          "http://iam:8080",
		iamCredentialFile:    credentialFile,
		installationID:       "mxi-0123456789abcdef0123456789abcdef",
		releaseID:            fixture.Manifest.Release.ID,
		releaseManifestFile:  filepath.Join(fixture.Root, release.ManifestFilename),
		releaseSignatureFile: filepath.Join(fixture.Root, release.SignatureFilename),
		releaseTrustFile:     fixture.TrustPath,
		paasEndpoint:         "http://paas-api:8080",
	}
	if handler, err := buildHandler(config); err != nil || handler == nil {
		t.Fatalf("build authenticated product-discovery handler = %T / %v", handler, err)
	}

	config.releaseID = "matrix-v0.2.0-0123456789ab"
	if _, err := buildHandler(config); err == nil {
		t.Fatal("configured release identity different from signed manifest was accepted")
	}
}

func TestBuildHandlerBindsDevOpsReadinessToSignedInventory(t *testing.T) {
	fixture, err := releasetest.WriteDevOps(t.TempDir())
	if err != nil {
		t.Fatalf("write signed DevOps release fixture: %v", err)
	}
	credentialFile := filepath.Join(t.TempDir(), "platform-iam-credential")
	if err := os.WriteFile(credentialFile, []byte("platform-service-credential"), 0o600); err != nil {
		t.Fatalf("write platform credential: %v", err)
	}
	config := configuration{
		listenAddress: "127.0.0.1:8080", iamEndpoint: "http://iam:8080",
		iamCredentialFile:    credentialFile,
		installationID:       "mxi-0123456789abcdef0123456789abcdef",
		releaseID:            fixture.Manifest.Release.ID,
		releaseManifestFile:  filepath.Join(fixture.Root, release.ManifestFilename),
		releaseSignatureFile: filepath.Join(fixture.Root, release.SignatureFilename),
		releaseTrustFile:     fixture.TrustPath, paasEndpoint: "http://paas-api:8080",
	}
	if _, err := buildHandler(config); err == nil {
		t.Fatal("signed DevOps inventory was accepted without its readiness endpoint")
	}
	config.devopsEndpoint = "http://devops-api:8080"
	if handler, err := buildHandler(config); err != nil || handler == nil {
		t.Fatalf("build DevOps product-discovery handler = %T / %v", handler, err)
	}
}

func TestBuildHandlerRejectsTamperedManifestAndInvalidConfiguration(t *testing.T) {
	fixture, err := releasetest.Write(t.TempDir())
	if err != nil {
		t.Fatalf("write signed release fixture: %v", err)
	}
	manifestPath := filepath.Join(fixture.Root, release.ManifestFilename)
	manifest, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read signed release fixture: %v", err)
	}
	manifest[len(manifest)-2] ^= 1
	if err := os.WriteFile(manifestPath, manifest, 0o600); err != nil {
		t.Fatalf("tamper signed release fixture: %v", err)
	}
	credentialFile := filepath.Join(t.TempDir(), "platform-iam-credential")
	if err := os.WriteFile(credentialFile, []byte("platform-service-credential"), 0o600); err != nil {
		t.Fatalf("write platform credential: %v", err)
	}
	config := configuration{
		listenAddress:        "127.0.0.1:8080",
		iamEndpoint:          "http://iam:8080",
		iamCredentialFile:    credentialFile,
		installationID:       "mxi-0123456789abcdef0123456789abcdef",
		releaseID:            fixture.Manifest.Release.ID,
		releaseManifestFile:  manifestPath,
		releaseSignatureFile: filepath.Join(fixture.Root, release.SignatureFilename),
		releaseTrustFile:     fixture.TrustPath,
		paasEndpoint:         "http://paas-api:8080",
	}
	if _, err := buildHandler(config); err == nil {
		t.Fatal("tampered release manifest was accepted")
	}

	lookup := func(name string) string {
		if name == installationIDEnvironment {
			return "caller-selected-installation"
		}
		return "configured"
	}
	if _, err := loadConfiguration(lookup); err == nil {
		t.Fatal("invalid installation or relative process files were accepted")
	}
	if _, err := loadConfiguration(nil); err == nil {
		t.Fatal("missing process configuration source was accepted")
	}
}
