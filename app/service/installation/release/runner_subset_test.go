package release

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestRunnerDirectoryAuthenticatesOnlyClosedDevOpsSubset(t *testing.T) {
	root := t.TempDir()
	gvisor := []byte("test-only-gvisor-archive")
	gvisorSum := sha256.Sum256(gvisor)
	gvisorDigest := "sha256:" + hex.EncodeToString(gvisorSum[:])
	checksum := []byte(strings.TrimPrefix(gvisorDigest, "sha256:") +
		"  " + filepath.Base(filepath.FromSlash(RunnerGVisorArchivePath)) + "\n")
	payloads := map[string][]byte{
		"bin/mx":                   []byte("test mx"),
		RunnerBinaryPath:           []byte("test runner"),
		RunnerToolchainArchivePath: []byte("test toolchain archive"),
		RunnerGVisorArchivePath:    gvisor,
		RunnerGVisorChecksumPath:   checksum,
	}
	manifest := devOpsRunnerManifest(t, payloads)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := NewTrustRoot(manifest.Signer.KeyID, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	trustBytes, err := EncodeTrustRoot(trust)
	if err != nil {
		t.Fatal(err)
	}
	manifestBytes, err := EncodeCanonical(manifest)
	if err != nil {
		t.Fatal(err)
	}
	for relative, content := range payloads {
		target := filepath.Join(root, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			t.Fatal(err)
		}
		mode := os.FileMode(0o600)
		if relative == "bin/mx" || relative == RunnerBinaryPath {
			mode = 0o700
		}
		if err := os.WriteFile(target, content, mode); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, ManifestFilename), manifestBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(root, SignatureFilename), ed25519.Sign(privateKey, manifestBytes), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	verified, err := verifyRunnerDirectory(root, trustBytes, gvisorDigest, checksum)
	if err != nil || verified.Manifest.Release.ID != manifest.Release.ID {
		t.Fatalf("verify runner subset=%#v err=%v", verified.Manifest.Release, err)
	}
	if _, err := VerifyDirectory(root, trustBytes); err == nil {
		t.Fatal("runner subset was accepted as a complete platform release")
	}
	if _, err := VerifyRunnerDirectory(root, trustBytes); err == nil {
		t.Fatal("test-only gVisor payload was accepted by the production profile")
	}
	if err := os.WriteFile(
		filepath.Join(root, filepath.FromSlash(RunnerBinaryPath)), []byte("tampered"), 0o700,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyRunnerDirectory(root, trustBytes, gvisorDigest, checksum); err == nil {
		t.Fatal("tampered runner executable was accepted")
	}
}

func TestDevOpsManifestRequiresExactRunnerPayloadSet(t *testing.T) {
	payloads := map[string][]byte{
		"bin/mx":                   []byte("mx"),
		RunnerBinaryPath:           []byte("runner"),
		RunnerToolchainArchivePath: []byte("toolchain"),
		RunnerGVisorArchivePath:    []byte("gvisor"),
		RunnerGVisorChecksumPath:   []byte("checksum"),
	}
	valid := devOpsRunnerManifest(t, payloads)
	if _, err := EncodeCanonical(valid); err != nil {
		t.Fatalf("valid DevOps runner manifest: %v", err)
	}

	missing := valid
	missing.Files = slices.DeleteFunc(slices.Clone(valid.Files), func(file File) bool {
		return file.Path == RunnerBinaryPath
	})
	if _, err := EncodeCanonical(missing); err == nil {
		t.Fatal("DevOps release without runner executable was accepted")
	}

	unselected := valid
	unselected.Products = []Product{ApplicationPaaSProduct(valid.Release.Version)}
	unselected.Images = slices.DeleteFunc(slices.Clone(valid.Images), func(image Image) bool {
		return image.Component == "devops"
	})
	unselected.Files = slices.DeleteFunc(slices.Clone(valid.Files), func(file File) bool {
		return file.Path == "images/devops.tar"
	})
	if _, err := EncodeCanonical(unselected); err == nil {
		t.Fatal("PaaS-only release carrying runner authority was accepted")
	}
}

func devOpsRunnerManifest(t *testing.T, payloads map[string][]byte) Manifest {
	t.Helper()
	manifest := validManifest()
	manifest.Products = append(manifest.Products, DevOpsProduct(manifest.Release.Version))
	manifest.Files = append(manifest.Files, File{
		Path: "images/devops.tar", MediaType: mediaDockerArchive,
		Size: 123, SHA256: digest('6'),
	})
	sourceDigest := digest('7')
	manifest.Images = append(manifest.Images, Image{
		Component: "devops", Purpose: ImagePlatform, ArchivePath: "images/devops.tar",
		ImageID: digest('6'), SourceDigest: sourceDigest,
		LocalReference: LocalImageReference("devops", sourceDigest),
		OS:             "linux", Architecture: "amd64",
		HealthContract: "devops-ready-v1",
	})
	for _, relative := range RunnerPayloadPaths() {
		content, found := payloads[relative]
		if !found {
			t.Fatalf("runner payload %s is missing", relative)
		}
		digestBytes := sha256.Sum256(content)
		file := File{
			Path: relative, Size: uint64(len(content)),
			SHA256:    "sha256:" + hex.EncodeToString(digestBytes[:]),
			MediaType: mediaDockerArchive,
		}
		switch relative {
		case RunnerBinaryPath:
			file.MediaType = mediaExecutable
			file.Executable = true
		case RunnerGVisorArchivePath:
			file.MediaType = mediaGVisorArchive
		case RunnerGVisorChecksumPath:
			file.MediaType = mediaPlainText
		}
		manifest.Files = append(manifest.Files, file)
	}
	for index := range manifest.Files {
		content, found := payloads[manifest.Files[index].Path]
		if !found {
			continue
		}
		digestBytes := sha256.Sum256(content)
		manifest.Files[index].Size = uint64(len(content))
		manifest.Files[index].SHA256 = "sha256:" + hex.EncodeToString(digestBytes[:])
	}
	slices.SortFunc(manifest.Files, func(left, right File) int {
		return strings.Compare(left.Path, right.Path)
	})
	slices.SortFunc(manifest.Images, func(left, right Image) int {
		return strings.Compare(left.Component, right.Component)
	})
	return manifest
}
