package release

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestReadTrustRootFileUsesExactCanonicalRegularFile(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate release key: %v", err)
	}
	trust, err := NewTrustRoot("xiak-release-2026", publicKey)
	if err != nil {
		t.Fatalf("create release trust root: %v", err)
	}
	content, err := EncodeTrustRoot(trust)
	if err != nil {
		t.Fatalf("encode release trust root: %v", err)
	}
	target := filepath.Join(t.TempDir(), "release-trust.json")
	if err := os.WriteFile(target, content, 0o600); err != nil {
		t.Fatalf("write release trust root: %v", err)
	}
	read, decoded, err := ReadTrustRootFile(target)
	if err != nil || !slices.Equal(read, content) || decoded != trust {
		t.Fatalf("read trust root = %#v / %v", decoded, err)
	}

	link := filepath.Join(t.TempDir(), "release-trust.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symbolic links are unavailable to this test user: %v", err)
	}
	if _, _, err := ReadTrustRootFile(link); err == nil {
		t.Fatal("linked trust root must fail")
	}
}

func TestManifestCanonicalSignatureAndTamperRejection(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate release key: %v", err)
	}
	trust, err := NewTrustRoot("xiak-release-2026", publicKey)
	if err != nil {
		t.Fatalf("create release trust root: %v", err)
	}
	trustBytes, err := EncodeTrustRoot(trust)
	if err != nil {
		t.Fatalf("encode release trust root: %v", err)
	}
	manifest := validManifest()
	manifestBytes, err := EncodeCanonical(manifest)
	if err != nil {
		t.Fatalf("encode release manifest: %v", err)
	}
	signature := ed25519.Sign(privateKey, manifestBytes)
	verified, err := Verify(manifestBytes, signature, trustBytes)
	if err != nil || verified.Release.ID != manifest.Release.ID {
		t.Fatalf("verify release manifest = %#v / %v", verified.Release, err)
	}

	pretty, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatalf("pretty encode manifest: %v", err)
	}
	if _, err := Verify(pretty, ed25519.Sign(privateKey, pretty), trustBytes); err == nil {
		t.Fatal("non-canonical manifest must fail even with a valid signature")
	}
	tampered := append([]byte(nil), manifestBytes...)
	index := strings.Index(string(tampered), "build-gate-a")
	if index < 0 {
		t.Fatal("manifest fixture does not contain build identity")
	}
	tampered[index] = 'B'
	if _, err := Verify(tampered, signature, trustBytes); err == nil {
		t.Fatal("tampered manifest must fail signature verification")
	}
	otherPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate other release key: %v", err)
	}
	otherTrust, err := NewTrustRoot("xiak-release-2026", otherPublic)
	if err != nil {
		t.Fatalf("create other trust root: %v", err)
	}
	otherTrustBytes, _ := EncodeTrustRoot(otherTrust)
	if _, err := Verify(manifestBytes, signature, otherTrustBytes); err == nil {
		t.Fatal("another public key must not verify the release")
	}
}

func TestManifestRejectsUnsafeOrIncompleteInventory(t *testing.T) {
	tests := map[string]func(*Manifest){
		"path traversal": func(value *Manifest) {
			value.Files[0].Path = "../bin/mx"
		},
		"case-fold collision": func(value *Manifest) {
			value.Files = append(value.Files, File{
				Path: "docs/OPERATOR.md", MediaType: mediaMarkdown,
				Size: 1, SHA256: digest('d'),
			})
		},
		"duplicate path": func(value *Manifest) {
			value.Files = append(value.Files, value.Files[len(value.Files)-1])
		},
		"payload metadata": func(value *Manifest) {
			value.Files[0].Size = 0
		},
		"missing image": func(value *Manifest) {
			value.Images = value.Images[:len(value.Images)-1]
		},
		"image identity": func(value *Manifest) {
			value.Images[0].ImageID = "apisix:latest"
		},
		"source identity": func(value *Manifest) {
			value.Images[0].SourceDigest = "apisix:latest"
		},
		"duplicate image identity": func(value *Manifest) {
			value.Images[1].ImageID = value.Images[0].ImageID
		},
		"duplicate source identity": func(value *Manifest) {
			value.Images[1].SourceDigest = value.Images[0].SourceDigest
		},
		"architecture": func(value *Manifest) {
			value.Host.Architecture = "arm64"
		},
		"signer": func(value *Manifest) {
			value.Signer.Algorithm = "RSA"
		},
		"health contract": func(value *Manifest) {
			value.Images[1].HealthContract = "ready"
		},
		"image purpose": func(value *Manifest) {
			value.Images[0].Purpose = ImageWorkload
		},
		"previous release": func(value *Manifest) {
			value.Release.PreviousID = "matrix-v0.0.9-0123456789ab"
		},
		"previous release identity": func(value *Manifest) {
			value.Release.PreviousVersion = "v0.0.9"
			value.Release.PreviousID = "matrix-v0.0.9-not-a-commit"
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			value := validManifest()
			mutate(&value)
			if _, err := EncodeCanonical(value); err == nil {
				t.Fatal("invalid release manifest must fail")
			}
		})
	}
}

func TestManifestStrictDecodersRejectUnknownMetadataAndSignatureShape(t *testing.T) {
	manifestBytes, err := EncodeCanonical(validManifest())
	if err != nil {
		t.Fatalf("encode manifest: %v", err)
	}
	withUnknown := append([]byte(nil), manifestBytes[:len(manifestBytes)-1]...)
	withUnknown = append(withUnknown, []byte(`,"unknown":true}`)...)
	if _, err := DecodeCanonical(withUnknown); err == nil {
		t.Fatal("unknown release metadata must fail")
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate release key: %v", err)
	}
	trust, err := NewTrustRoot("xiak-release-2026", publicKey)
	if err != nil {
		t.Fatalf("create trust root: %v", err)
	}
	trustBytes, err := EncodeTrustRoot(trust)
	if err != nil {
		t.Fatalf("encode trust root: %v", err)
	}
	signature := ed25519.Sign(privateKey, manifestBytes)
	if _, err := Verify(manifestBytes, signature[:len(signature)-1], trustBytes); err == nil {
		t.Fatal("non-Ed25519 signature length must fail")
	}
	changedKeyID := validManifest()
	changedKeyID.Signer.KeyID = "other-release-key"
	changedBytes, err := EncodeCanonical(changedKeyID)
	if err != nil {
		t.Fatalf("encode changed signer manifest: %v", err)
	}
	if _, err := Verify(changedBytes, ed25519.Sign(privateKey, changedBytes), trustBytes); err == nil {
		t.Fatal("manifest signer identity must match the pinned trust root")
	}
}

func validManifest() Manifest {
	commit := strings.Repeat("a", 40)
	files := []File{{
		Path: "bin/mx", MediaType: mediaExecutable,
		Size: 1024, SHA256: digest('1'), Executable: true,
	}}
	required := RequiredImages()
	images := make([]Image, 0, len(required))
	fileDigests := "2345678"
	imageDigests := "89abcde"
	sourceDigests := "ef01234"
	for index, requirement := range required {
		archive := "images/" + requirement.Component + ".tar"
		files = append(files, File{
			Path: archive, MediaType: mediaDockerArchive,
			Size: 1024 + uint64(index), SHA256: digest(fileDigests[index]),
		})
		images = append(images, Image{
			Component: requirement.Component, Purpose: requirement.Purpose, ArchivePath: archive,
			ImageID: digest(imageDigests[index]), SourceDigest: digest(sourceDigests[index]),
			OS: "linux", Architecture: "amd64", HealthContract: requirement.HealthContract,
		})
	}
	slices.SortFunc(files, func(left, right File) int {
		return strings.Compare(left.Path, right.Path)
	})
	return Manifest{
		APIVersion: ManifestAPIVersion, Kind: ManifestKind,
		Release: ReleaseIdentity{
			ID: "matrix-v0.1.0-" + commit[:12], Version: "v0.1.0",
			SourceCommit: commit, BuildID: "build-gate-a",
			CreatedAt: time.Date(2026, 8, 25, 12, 0, 0, 123000000, time.UTC),
		},
		Signer: Signer{KeyID: "xiak-release-2026", Algorithm: SignatureAlgorithm},
		Host: HostProfile{
			OS: "linux", Architecture: "amd64", MinimumDocker: "29.0.0",
			MinimumCompose: "2.40.0", CommandContract: "v1",
		},
		MinimumFreeBytes: minimumFreeBytes,
		Database:         DatabaseProfile{SchemaVersion: 1, Compatibility: "expand-contract-n-minus-one"},
		TopologyDigest:   digest('f'), Files: files, Images: images,
	}
}

func digest(value byte) string {
	return "sha256:" + strings.Repeat(string(value), 64)
}
