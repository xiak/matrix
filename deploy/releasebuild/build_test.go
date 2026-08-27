package releasebuild

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	installationrelease "github.com/xiak/matrix/app/service/installation/release"
)

func TestNodeCollectorExtractionIsClosedAndRequiresAttribution(t *testing.T) {
	for _, change := range []string{"valid", "link", "path escape", "extra", "missing attribution", "duplicate"} {
		t.Run(change, func(t *testing.T) {
			var archive bytes.Buffer
			writer := tar.NewWriter(&archive)
			prefix := "node_exporter-1.12.1.linux-amd64/"
			names := []string{"node_exporter", "LICENSE", "NOTICE"}
			if change == "extra" {
				names = append(names, "arbitrary")
			}
			if change == "duplicate" {
				names = append(names, "NOTICE")
			}
			if change == "missing attribution" {
				names = names[:2]
			}
			for index, name := range names {
				header := &tar.Header{Name: prefix + name, Mode: 0o600, Typeflag: tar.TypeReg, Size: 3}
				if change == "path escape" && index == 0 {
					header.Name = "../node_exporter"
				}
				if change == "link" && index == 0 {
					header.Typeflag, header.Linkname, header.Size = tar.TypeSymlink, "/etc/passwd", 0
				}
				if err := writer.WriteHeader(header); err != nil {
					t.Fatal(err)
				}
				if header.Size > 0 {
					if _, err := writer.Write([]byte("abc")); err != nil {
						t.Fatal(err)
					}
				}
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			root := t.TempDir()
			if os.Mkdir(filepath.Join(root, "bin"), 0o700) != nil {
				t.Fatal("create binary directory")
			}
			err := extractNodeCollector(bytes.NewReader(archive.Bytes()), root)
			if (err == nil) != (change == "valid") {
				t.Fatalf("collector archive %s: %v", change, err)
			}
			if change == "valid" {
				for _, name := range []string{"bin/node-exporter", "licenses/node-exporter-license.txt", "licenses/node-exporter-notice.txt"} {
					content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
					if err != nil || string(content) != "abc" {
						t.Fatal("collector archive lost its executable or attribution")
					}
				}
			}
		})
	}
}

func TestNodeBuildAuthenticatesCollectorBeforeBuildingAnyExecutable(t *testing.T) {
	base := t.TempDir()
	if os.WriteFile(filepath.Join(base, "go.mod"), []byte("module github.com/xiak/matrix\n"), 0o600) != nil {
		t.Fatal("write build fixture")
	}
	archive := filepath.Join(base, "collector.tar.gz")
	if os.WriteFile(archive, []byte("untrusted executable bytes"), 0o600) != nil {
		t.Fatal("write archive fixture")
	}
	effects := newFakeEffects()
	_, err := Assemble(context.Background(), Config{Kind: installationrelease.NodeManifestKind, CollectorArchive: archive,
		RepositoryRoot: base, Output: filepath.Join(base, "bundle"), Version: "v0.1.0", BuildID: "node-build-gate", SourceCommit: strings.Repeat("a", 40),
		CreatedAt: time.Date(2026, 8, 26, 15, 30, 0, 0, time.UTC),
		Signer:    SigningMaterial{KeyID: "xiak-release-2026", PrivateKey: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))}}, effects)
	if err == nil || len(effects.binaries) != 0 || len(effects.images) != 0 || len(effects.saved) != 0 {
		t.Fatal("untrusted collector reached release build effects")
	}
	if _, err := os.Lstat(filepath.Join(base, "bundle")); !os.IsNotExist(err) {
		t.Fatal("untrusted collector published a node release")
	}
}

type fakeEffects struct {
	baseMismatch bool
	binaries     map[string]struct{}
	images       map[string]ImageMetadata
	dockerfiles  map[string]string
	saved        map[string]ImageMetadata
	removed      map[string]struct{}
	paasImageID  string
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
	fake.saved[imageID] = identity
	return identity, os.WriteFile(output, []byte("docker-archive:"+imageID), 0o600)
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
		Version: "v0.1.0", BuildID: "release-test", SourceCommit: strings.Repeat("a", 40),
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
		verified.Manifest.TopologyDigest != result.Manifest.TopologyDigest ||
		verified.Manifest.APIVersion != installationrelease.ManifestAPIVersion ||
		verified.Manifest.Database != installationrelease.CurrentDatabaseProfile() {
		t.Fatal("published release differs from the signed result")
	}
	if len(effects.binaries) != len(binarySpecifications) ||
		len(effects.dockerfiles) != len(imageRecipes) ||
		len(effects.saved) != len(installationrelease.RequiredImages()) ||
		len(effects.removed) != len(imageRecipes) {
		t.Fatalf("fixed build closure is incomplete: binaries=%d images=%d archives=%d cleanup=%d",
			len(effects.binaries), len(effects.dockerfiles), len(effects.saved), len(effects.removed))
	}
	for component, dockerfile := range effects.dockerfiles {
		if strings.Contains(dockerfile, "RUN ") || strings.Contains(dockerfile, "http://") ||
			strings.Contains(dockerfile, "https://") || !strings.Contains(dockerfile, "COPY --chmod=0555") {
			t.Fatalf("image %s escaped the fixed offline recipe", component)
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
		Version: "v0.1.0", BuildID: "release-test", SourceCommit: strings.Repeat("a", 40),
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

func testDigest(value string) string {
	digest := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(digest[:])
}
