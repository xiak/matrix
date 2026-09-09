package releasebuild

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	installationrelease "github.com/xiak/matrix/app/service/installation/release"
)

type fakeEffects struct {
	baseMismatch bool
	binaries     map[string]struct{}
	images       map[string]ImageMetadata
	dockerfiles  map[string]string
	saved        map[string]ImageMetadata
	removed      map[string]struct{}
	paasImageID  string
}

type authenticRunnerEffects struct {
	*fakeEffects
	local *LocalEffects
}

func (effects *authenticRunnerEffects) SaveImage(
	ctx context.Context,
	imageID string,
	output string,
) (ImageMetadata, error) {
	if imageID == RunnerToolchainSourceID {
		return effects.local.SaveImage(ctx, imageID, output)
	}
	return effects.fakeEffects.SaveImage(ctx, imageID, output)
}

func (effects *authenticRunnerEffects) StageRunnerSandbox(
	ctx context.Context,
	source string,
	output string,
) (RunnerSandboxMetadata, error) {
	return effects.local.StageRunnerSandbox(ctx, source, output)
}

func newFakeEffects() *fakeEffects {
	return &fakeEffects{
		binaries: make(map[string]struct{}), images: make(map[string]ImageMetadata),
		dockerfiles: make(map[string]string), saved: make(map[string]ImageMetadata),
		removed: make(map[string]struct{}),
	}
}

func (fake *fakeEffects) BuildGoBinary(_ context.Context, _ string, packagePath, output string) error {
	fake.binaries[packagePath] = struct{}{}
	return os.WriteFile(output, []byte("linux-amd64:"+packagePath), 0o700)
}

func (fake *fakeEffects) InspectImage(_ context.Context, reference string) (ImageMetadata, error) {
	switch reference {
	case APISIXBaseReference:
		id := APISIXBaseImageID
		if fake.baseMismatch {
			id = testDigest("wrong-apisix")
		}
		return ImageMetadata{ID: id, OS: "linux", Architecture: "amd64"}, nil
	case DockerBaseReference:
		return ImageMetadata{ID: DockerBaseImageID, OS: "linux", Architecture: "amd64"}, nil
	case PostgresReference:
		return ImageMetadata{ID: PostgresImageID, OS: "linux", Architecture: "amd64"}, nil
	case RunnerToolchainReference:
		return ImageMetadata{ID: RunnerToolchainSourceID, OS: "linux", Architecture: "amd64"}, nil
	default:
		return fake.images[reference], nil
	}
}

func (fake *fakeEffects) BuildImage(_ context.Context, contextRoot, tag string) error {
	component := strings.Split(strings.TrimPrefix(tag, "matrix-release-build/"), ":")[0]
	content, err := os.ReadFile(filepath.Join(contextRoot, "Dockerfile"))
	if err != nil {
		return err
	}
	fake.dockerfiles[component] = string(content)
	metadata := ImageMetadata{ID: testDigest("image:" + component), OS: "linux", Architecture: "amd64"}
	fake.images[tag] = metadata
	if component == "paas" {
		fake.paasImageID = metadata.ID
	}
	return nil
}

func (fake *fakeEffects) SaveImage(_ context.Context, imageID, output string) (ImageMetadata, error) {
	identity := ImageMetadata{
		ID: testDigest("load:" + imageID), OS: "linux", Architecture: "amd64",
	}
	if imageID == RunnerToolchainSourceID {
		identity.ID = RunnerToolchainArchiveConfigID
	}
	fake.saved[imageID] = identity
	return identity, os.WriteFile(output, []byte("docker-archive:"+imageID), 0o600)
}

func (fake *fakeEffects) StageRunnerSandbox(
	_ context.Context,
	_ string,
	output string,
) (RunnerSandboxMetadata, error) {
	content := []byte("fixed-gvisor-test-archive")
	return RunnerSandboxMetadata{SHA256: RunnerGVisorSHA256, Size: uint64(len(content))},
		os.WriteFile(output, content, 0o600)
}

func (fake *fakeEffects) VerifyPaaSCLI(_ context.Context, imageID string) error {
	if imageID != fake.paasImageID {
		return os.ErrInvalid
	}
	return nil
}

func (fake *fakeEffects) RemoveBuildTag(_ context.Context, tag string) error {
	fake.removed[tag] = struct{}{}
	return nil
}

func TestAssembleProducesAuthenticatedCompleteRelease(t *testing.T) {
	base := t.TempDir()
	repository := filepath.Join(base, "repository")
	if err := os.Mkdir(repository, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repository, "go.mod"), []byte("module github.com/xiak/matrix\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x41}, ed25519.SeedSize))
	config := Config{
		RepositoryRoot: repository, Output: filepath.Join(base, "bundle"),
		GVisorArchive: filepath.Join(base, "gvisor-x86_64.tar.zstd"),
		Version:       "v0.1.0", BuildID: "release-test", SourceCommit: strings.Repeat("a", 40),
		CreatedAt: time.Date(2026, 8, 26, 15, 30, 0, 0, time.UTC),
		Signer:    SigningMaterial{KeyID: "xiak-release-2026", PrivateKey: privateKey},
		Entropy:   bytes.NewReader(make([]byte, 12)),
	}
	effects := newFakeEffects()
	result, err := Assemble(context.Background(), config, effects)
	if err != nil {
		t.Fatal(err)
	}
	trustBytes, err := installationrelease.EncodeTrustRoot(result.TrustRoot)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := installationrelease.VerifyDirectory(result.Output, trustBytes)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Manifest.Release != result.Manifest.Release ||
		verified.Manifest.TopologyDigest != result.Manifest.TopologyDigest {
		t.Fatal("published release differs from the signed result")
	}
	if len(effects.binaries) != len(binarySpecifications) ||
		len(effects.dockerfiles) != len(imageRecipes) ||
		len(effects.saved) != len(installationrelease.RequiredImages(result.Manifest.Products))+1 ||
		len(effects.removed) != len(imageRecipes) {
		t.Fatalf("fixed build closure is incomplete: binaries=%d images=%d archives=%d cleanup=%d",
			len(effects.binaries), len(effects.dockerfiles), len(effects.saved), len(effects.removed))
	}
	for component, dockerfile := range effects.dockerfiles {
		if strings.Contains(dockerfile, "RUN ") || strings.Contains(dockerfile, "http://") ||
			strings.Contains(dockerfile, "https://") || !strings.Contains(dockerfile, "COPY --chmod=0555") {
			t.Fatalf("image %s escaped the fixed offline recipe", component)
		}
		rootCopy := "COPY --from=matrix-system-roots /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt\n"
		if component == "devops" {
			if !strings.HasPrefix(dockerfile, "FROM "+DockerBaseReference+" AS matrix-system-roots\nFROM scratch\n") ||
				strings.Count(dockerfile, rootCopy) != 1 {
				t.Fatal("DevOps image does not carry the fixed system root bundle")
			}
		} else if strings.Contains(dockerfile, "matrix-system-roots") || strings.Contains(dockerfile, rootCopy) {
			t.Fatalf("image %s received an unowned system root bundle", component)
		}
	}
	for _, image := range verified.Manifest.Images {
		loadIdentity, found := effects.saved[image.SourceDigest]
		if !found || image.ImageID != loadIdentity.ID || image.ImageID == image.SourceDigest {
			t.Fatalf("image %s did not preserve distinct source and portable load identities", image.Component)
		}
	}
}

func TestAssembleRejectsChangedBaseBeforeWritingOrBuilding(t *testing.T) {
	base := t.TempDir()
	repository := filepath.Join(base, "repository")
	if err := os.Mkdir(repository, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repository, "go.mod"), []byte("module github.com/xiak/matrix\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	effects := newFakeEffects()
	effects.baseMismatch = true
	output := filepath.Join(base, "bundle")
	_, err := Assemble(context.Background(), Config{
		RepositoryRoot: repository, Output: output,
		GVisorArchive: filepath.Join(base, "gvisor-x86_64.tar.zstd"),
		Version:       "v0.1.0", BuildID: "release-test", SourceCommit: strings.Repeat("a", 40),
		CreatedAt: time.Date(2026, 8, 26, 15, 30, 0, 0, time.UTC),
		Signer: SigningMaterial{
			KeyID:      "xiak-release-2026",
			PrivateKey: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize)),
		},
	}, effects)
	if err == nil {
		t.Fatal("changed fixed base image was accepted")
	}
	if _, statErr := os.Lstat(output); !os.IsNotExist(statErr) {
		t.Fatal("failed base verification published a bundle")
	}
	if len(effects.binaries) != 0 || len(effects.dockerfiles) != 0 {
		t.Fatal("base mismatch started release build effects")
	}
}

func TestAssembleCarriesAuthenticTransferableRunnerSubset(t *testing.T) {
	gvisor := os.Getenv("MATRIX_TEST_GVISOR_ARCHIVE")
	if gvisor == "" || os.Getenv("MATRIX_TEST_RUNNER_TOOLCHAIN") != "1" {
		t.Skip("real runner release artifacts are not enabled")
	}
	base := t.TempDir()
	repository := filepath.Join(base, "repository")
	if err := os.Mkdir(repository, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(repository, "go.mod"), []byte("module github.com/xiak/matrix\n"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x43}, ed25519.SeedSize))
	effects := &authenticRunnerEffects{fakeEffects: newFakeEffects(), local: NewLocalEffects()}
	result, err := Assemble(context.Background(), Config{
		RepositoryRoot: repository, Output: filepath.Join(base, "full-release"),
		GVisorArchive: gvisor, Version: "v0.1.0", BuildID: "real-runner-artifacts",
		SourceCommit: strings.Repeat("c", 40),
		CreatedAt:    time.Date(2026, 9, 9, 8, 0, 0, 0, time.UTC),
		Signer:       SigningMaterial{KeyID: "xiak-release-2026", PrivateKey: privateKey},
		Entropy:      bytes.NewReader(make([]byte, 12)),
	}, effects)
	if err != nil {
		t.Fatal(err)
	}
	trustBytes, err := installationrelease.EncodeTrustRoot(result.TrustRoot)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := installationrelease.VerifyDirectory(result.Output, trustBytes)
	if err != nil {
		t.Fatal(err)
	}
	subset := filepath.Join(base, "runner-release")
	if err := os.Mkdir(subset, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, relative := range append(
		[]string{installationrelease.ManifestFilename, installationrelease.SignatureFilename},
		installationrelease.RunnerReleasePayloadPaths()...,
	) {
		source := filepath.Join(result.Output, filepath.FromSlash(relative))
		target := filepath.Join(subset, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := copyTestReleaseFile(source, target); err != nil {
			t.Fatal(err)
		}
	}
	runner, err := installationrelease.VerifyRunnerDirectory(subset, trustBytes)
	if err != nil || runner.ManifestSHA256 != verified.ManifestSHA256 ||
		runner.Manifest.Release.ID != result.Manifest.Release.ID {
		t.Fatalf("runner subset=%#v err=%v", runner.Manifest.Release, err)
	}
}

func copyTestReleaseFile(source, target string) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	info, err := input.Stat()
	if err != nil {
		return err
	}
	mode := os.FileMode(0o600)
	if info.Mode().Perm()&0o100 != 0 {
		mode = 0o700
	}
	output, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(output, input); err != nil {
		_ = output.Close()
		return err
	}
	return output.Close()
}

func testDigest(value string) string {
	digest := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(digest[:])
}
