package releasebuild

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"

	installationrelease "github.com/xiak/matrix/app/service/installation/release"
)

func TestSigningKeyStaysSeparateAndMatchesTrustRoot(t *testing.T) {
	root := t.TempDir()
	privatePath := filepath.Join(root, "release-signing-key.json")
	trustPath := filepath.Join(root, "release-trust.json")
	trust, err := GenerateSigningFiles(
		"xiak-release-2026", privatePath, trustPath,
		bytes.NewReader(bytes.Repeat([]byte{0x51}, ed25519.SeedSize)),
	)
	if err != nil {
		t.Fatal(err)
	}
	material, derived, err := ReadSigningKey(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(material.PrivateKey)
	if derived != trust || material.KeyID != trust.KeyID {
		t.Fatal("private key and trust root differ")
	}
	trustBytes, stored, err := installationrelease.ReadTrustRootFile(trustPath)
	if err != nil {
		t.Fatal(err)
	}
	clear(trustBytes)
	if stored != trust {
		t.Fatal("stored trust root differs from generated identity")
	}
	if _, err := GenerateSigningFiles(
		"xiak-release-2026", privatePath, filepath.Join(root, "other-trust.json"),
		bytes.NewReader(bytes.Repeat([]byte{0x52}, ed25519.SeedSize)),
	); err == nil {
		t.Fatal("signing key generation overwrote an existing private key")
	}
	if info, err := os.Lstat(privatePath); err != nil || !info.Mode().IsRegular() {
		t.Fatal("private signing key file is absent")
	}
}
