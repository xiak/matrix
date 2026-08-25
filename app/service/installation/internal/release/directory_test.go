package release

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestVerifyDirectoryAuthenticatesExactRegularFileInventory(t *testing.T) {
	fixture := writeBundleFixture(t)
	verified, err := VerifyDirectory(fixture.root, fixture.trust)
	if err != nil {
		t.Fatalf("verify bundle directory: %v", err)
	}
	if verified.Manifest.Release.ID != fixture.manifest.Release.ID ||
		verified.Root != fixture.root || verified.ManifestSHA256 == "" {
		t.Fatalf("verified bundle = %#v", verified)
	}

	t.Run("payload tamper", func(t *testing.T) {
		fixture := writeBundleFixture(t)
		path := filepath.Join(fixture.root, "images", "apisix.tar")
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read payload: %v", err)
		}
		content[0] ^= 0xff
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatalf("tamper payload: %v", err)
		}
		if _, err := VerifyDirectory(fixture.root, fixture.trust); err == nil {
			t.Fatal("payload digest tampering must fail")
		}
	})

	t.Run("undeclared file", func(t *testing.T) {
		fixture := writeBundleFixture(t)
		if err := os.WriteFile(filepath.Join(fixture.root, "extra.txt"), []byte("extra"), 0o600); err != nil {
			t.Fatalf("write undeclared file: %v", err)
		}
		if _, err := VerifyDirectory(fixture.root, fixture.trust); err == nil {
			t.Fatal("undeclared bundle files must fail")
		}
	})

	t.Run("link", func(t *testing.T) {
		fixture := writeBundleFixture(t)
		path := filepath.Join(fixture.root, "images", "apisix.tar")
		if err := os.Remove(path); err != nil {
			t.Fatalf("remove declared payload: %v", err)
		}
		if err := os.Symlink("iam.tar", path); err != nil {
			t.Skipf("symbolic links are unavailable to this test user: %v", err)
		}
		if _, err := VerifyDirectory(fixture.root, fixture.trust); err == nil {
			t.Fatal("linked bundle payloads must fail")
		}
	})

	if runtime.GOOS != "windows" {
		t.Run("executable mode", func(t *testing.T) {
			fixture := writeBundleFixture(t)
			path := filepath.Join(fixture.root, "images", "apisix.tar")
			if err := os.Chmod(path, 0o700); err != nil {
				t.Fatalf("change payload mode: %v", err)
			}
			if _, err := VerifyDirectory(fixture.root, fixture.trust); err == nil {
				t.Fatal("payload executable-mode tampering must fail")
			}
		})
	}
}

type bundleFixture struct {
	root     string
	trust    []byte
	manifest Manifest
}

func writeBundleFixture(t *testing.T) bundleFixture {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	trust, err := NewTrustRoot("xiak-release-2026", publicKey)
	if err != nil {
		t.Fatalf("create trust root: %v", err)
	}
	trustBytes, err := EncodeTrustRoot(trust)
	if err != nil {
		t.Fatalf("encode trust root: %v", err)
	}
	root := filepath.Clean(t.TempDir())
	manifest := validManifest()
	for index := range manifest.Files {
		file := &manifest.Files[index]
		content := []byte("payload:" + file.Path)
		mode := os.FileMode(0o600)
		if file.Executable {
			mode = 0o700
		}
		target := filepath.Join(root, filepath.FromSlash(file.Path))
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			t.Fatalf("create payload directory: %v", err)
		}
		if err := os.WriteFile(target, content, mode); err != nil {
			t.Fatalf("write payload: %v", err)
		}
		file.Size = uint64(len(content))
		digest := sha256.Sum256(content)
		file.SHA256 = "sha256:" + hex.EncodeToString(digest[:])
	}
	manifestBytes, err := EncodeCanonical(manifest)
	if err != nil {
		t.Fatalf("encode manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, ManifestFilename), manifestBytes, 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	if err := os.WriteFile(
		filepath.Join(root, SignatureFilename),
		ed25519.Sign(privateKey, manifestBytes),
		0o600,
	); err != nil {
		t.Fatalf("write signature: %v", err)
	}
	return bundleFixture{root: root, trust: trustBytes, manifest: manifest}
}
