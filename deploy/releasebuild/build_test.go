package releasebuild

import (
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

	iamv1 "github.com/xiak/matrix/api/iam/v1"
	installationrelease "github.com/xiak/matrix/app/service/installation/release"
)

type fakeEffects struct {
	baseMismatch bool
	baseMissing  bool
	baseForeign  bool
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
	case APISIXBasePinnedReference:
		return fake.baseImage("apache/apisix", APISIXBaseManifestDigest), nil
	case AlpineBasePinnedReference:
		return fake.baseImage("alpine", AlpineBaseManifestDigest), nil
	case DockerBasePinnedReference:
		return fake.baseImage("docker", DockerBaseManifestDigest), nil
	case PostgresPinnedReference:
		return fake.baseImage("postgres", PostgresManifestDigest), nil
	default:
		return fake.images[reference], nil
	}
}

func (fake *fakeEffects) baseImage(repository, manifestDigest string) ImageMetadata {
	digests := []string{repository + "@" + manifestDigest}
	if fake.baseMismatch {
		digests = []string{repository + "@" + testDigest("wrong-"+repository)}
	}
	if fake.baseMissing {
		digests = nil
	}
	if fake.baseForeign {
		digests = []string{"foreign.example/" + repository + "@" + manifestDigest}
	}
	return ImageMetadata{
		ID: testDigest("config:" + repository), RepositoryDigests: digests,
		OS: "linux", Architecture: "amd64",
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
	writeTestIAMAuthorizationProfiles(t, repository)
	testProduct := writeTestIAMAuthorizationProfile(t, repository)
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
	catalogFile, declaration, err := verified.OpenVerifiedPayload(installationrelease.IAMAuthorizationProfilesPath)
	if err != nil || declaration.MediaType != installationrelease.IAMAuthorizationProfilesMediaType {
		t.Fatal("signed release lacks the fixed IAM authorization profile catalog", err)
	}
	catalog, decodeErr := iamv1.DecodeAuthorizationProfileReleaseCatalog(catalogFile)
	closeErr := catalogFile.Close()
	if decodeErr != nil || closeErr != nil || len(catalog.Current) != 1 || catalog.Current[0].Product != testProduct.Product {
		t.Fatalf("signed IAM authorization profile catalog = %#v / %v / %v", catalog, decodeErr, closeErr)
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
	iamDockerfile := effects.dockerfiles["iam"]
	for _, required := range []string{
		"FROM " + AlpineBasePinnedReference + " AS matrix-system-roots",
		"FROM scratch",
		"COPY --from=matrix-system-roots /etc/ssl/cert.pem /etc/ssl/cert.pem",
		"COPY --from=matrix-system-roots /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt",
		"COPY --chmod=0555 matrix-iam-authentication-recovery /matrix/bin/matrix-iam-authentication-recovery",
		"COPY --chmod=0555 matrix-iam-backup-custody /matrix/bin/matrix-iam-backup-custody",
		"COPY --chmod=0555 matrix-iam-notification-dispatcher /matrix/bin/matrix-iam-notification-dispatcher",
	} {
		if !strings.Contains(iamDockerfile, required) {
			t.Fatalf("IAM image recipe lacks %q", required)
		}
	}
	if !strings.Contains(effects.dockerfiles["apisix"], "FROM "+APISIXBasePinnedReference+"\n") ||
		!strings.Contains(effects.dockerfiles["paas"], "FROM "+DockerBasePinnedReference+"\n") {
		t.Fatal("release image recipes do not pin their base manifest digests")
	}
	for _, image := range verified.Manifest.Images {
		loadIdentity, found := effects.saved[image.SourceDigest]
		if !found || image.ImageID != loadIdentity.ID || image.ImageID == image.SourceDigest {
			t.Fatalf("image %s did not preserve distinct source and portable load identities", image.Component)
		}
		if image.Component == "postgres" && image.SourceDigest == PostgresManifestDigest {
			t.Fatal("PostgreSQL archive used the registry manifest digest as a local image identity")
		}
	}
}

func TestAssembleRejectsUntrustedBaseBeforeWritingOrBuilding(t *testing.T) {
	for _, test := range []struct {
		name    string
		prepare func(*fakeEffects)
	}{
		{"changed-digest", func(effects *fakeEffects) { effects.baseMismatch = true }},
		{"missing-digest", func(effects *fakeEffects) { effects.baseMissing = true }},
		{"foreign-repository", func(effects *fakeEffects) { effects.baseForeign = true }},
	} {
		t.Run(test.name, func(t *testing.T) {
			base := t.TempDir()
			repository := filepath.Join(base, "repository")
			if err := os.Mkdir(repository, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(repository, "go.mod"), []byte("module github.com/xiak/matrix\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			writeTestIAMAuthorizationProfiles(t, repository)
			effects := newFakeEffects()
			test.prepare(effects)
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
				t.Fatal("untrusted fixed base image was accepted")
			}
			if _, statErr := os.Lstat(output); !os.IsNotExist(statErr) {
				t.Fatal("failed base verification published a bundle")
			}
			if len(effects.binaries) != 0 || len(effects.dockerfiles) != 0 {
				t.Fatal("base mismatch started release build effects")
			}
		})
	}
}

func TestAssembleRejectsInvalidIAMAuthorizationProfileCatalogBeforeBuild(t *testing.T) {
	base := t.TempDir()
	repository := filepath.Join(base, "repository")
	if err := os.Mkdir(repository, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repository, "go.mod"), []byte("module github.com/xiak/matrix\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	writeTestIAMAuthorizationProfiles(t, repository)
	catalogPath := filepath.Join(repository, "deploy", "releasebuild", "iam-authorization-profiles.json")
	if err := os.WriteFile(catalogPath, []byte(`{"apiVersion":"iam.matrix.xiak.com/v1","kind":"AuthorizationProfileReleaseCatalog","current":null,"historical":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(base, "bundle")
	effects := newFakeEffects()
	_, err := Assemble(context.Background(), Config{
		RepositoryRoot: repository, Output: output,
		Version: "v0.1.0", BuildID: "release-test", SourceCommit: strings.Repeat("a", 40),
		CreatedAt: time.Date(2026, 8, 26, 15, 30, 0, 0, time.UTC),
		Signer: SigningMaterial{
			KeyID:      "xiak-release-2026",
			PrivateKey: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x43}, ed25519.SeedSize)),
		},
	}, effects)
	if err == nil {
		t.Fatal("invalid IAM authorization profile catalog was signed")
	}
	if _, statErr := os.Lstat(output); !os.IsNotExist(statErr) || len(effects.binaries) != 0 || len(effects.dockerfiles) != 0 {
		t.Fatal("invalid IAM authorization profile catalog started release build effects")
	}
}

func writeTestIAMAuthorizationProfiles(t *testing.T, repository string) {
	t.Helper()
	target := filepath.Join(repository, "deploy", "releasebuild", "iam-authorization-profiles.json")
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		t.Fatal(err)
	}
	content := []byte(`{"apiVersion":"iam.matrix.xiak.com/v1","kind":"AuthorizationProfileReleaseCatalog","current":[],"historical":[]}`)
	if err := os.WriteFile(target, content, 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeTestIAMAuthorizationProfile(t *testing.T, repository string) iamv1.AuthorizationProfile {
	t.Helper()
	profile := iamv1.AuthorizationProfile{
		APIVersion: iamv1.APIVersion, Kind: "AuthorizationProfile", Product: "catalog", Revision: 1, CallingService: iamv1.ServicePaaS,
		Actions: []iamv1.AuthorizationProfileAction{{
			Action: "catalog.item.read", ResourceKind: "CATALOG_ITEM", Scope: iamv1.AuthorityScopeTenant,
			ResourceShapes: []iamv1.AuthorizationResourceShape{{Mode: iamv1.AuthorizationResourceInstance}},
			SubjectTypes:   []iamv1.SubjectType{iamv1.SubjectUser}, UserAuthenticationMethods: []iamv1.UserAuthenticationMethod{iamv1.UserAuthenticationLoginSession},
		}},
	}
	encoded, err := iamv1.EncodeAuthorizationProfileReleaseCatalog(iamv1.AuthorizationProfileReleaseCatalog{
		APIVersion: iamv1.APIVersion, Kind: iamv1.AuthorizationProfileReleaseCatalogKind,
		Current: []iamv1.AuthorizationProfile{profile}, Historical: []iamv1.AuthorizationProfile{},
	})
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(repository, "deploy", "releasebuild", "iam-authorization-profiles.json")
	if err := os.WriteFile(target, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	return profile
}

func testDigest(value string) string {
	digest := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(digest[:])
}
