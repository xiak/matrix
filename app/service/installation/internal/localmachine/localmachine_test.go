package localmachine

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	apphostingv1 "github.com/xiak/matrix/api/adapter/apphosting/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/installation/internal/layout"
	"github.com/xiak/matrix/app/service/installation/internal/platformcommand"
	"github.com/xiak/matrix/app/service/installation/internal/release"
	"github.com/xiak/matrix/app/service/installation/internal/releasetest"
	"github.com/xiak/matrix/app/service/installation/internal/topology"
)

func TestStageAndConfigurePreserveCredentialsAndExposeOnlyWorkload(t *testing.T) {
	plan := newInstallPlan(t)
	if err := stageInstallation(plan, rand.Reader); err != nil {
		t.Fatalf("stage installation: %v", err)
	}

	bootstrapBytes := readTestFile(t, plan.Root, layout.IAMBootstrap)
	bootstrap, err := iamv1.DecodeBootstrapDocument(bytes.NewReader(bootstrapBytes))
	if err != nil {
		t.Fatalf("decode staged IAM bootstrap: %v", err)
	}
	if bootstrap.InstallationID != plan.InstallationID ||
		len(bootstrap.Services) != len(iamv1.AllServicePurposes()) {
		t.Fatalf("staged IAM bootstrap identity = %#v", bootstrap)
	}

	serviceCredentials := make(map[iamv1.ServicePurpose][]byte, len(bootstrap.Services))
	for _, service := range bootstrap.Services {
		serviceCredentials[service.Purpose] = service.Credential.CopyBytes()
	}
	defer func() {
		for purpose, credential := range serviceCredentials {
			clear(credential)
			delete(serviceCredentials, purpose)
		}
	}()
	serviceFiles := map[iamv1.ServicePurpose][]string{
		iamv1.ServiceIAM:                  {layout.IAMAuditCredential},
		iamv1.ServicePaaS:                 {layout.PaaSIAMCredential, layout.PaaSAuditCredential},
		iamv1.ServiceAudit:                {layout.AuditIAMCredential},
		iamv1.ServiceAPISIX:               {layout.APISIXIAMCredential},
		iamv1.ServiceInstallationVerifier: {layout.InstallationVerifierCredential},
	}
	for purpose, paths := range serviceFiles {
		for _, path := range paths {
			if actual := readTestFile(t, plan.Root, path); !bytes.Equal(actual, serviceCredentials[purpose]) {
				t.Fatalf("service credential file %s differs from IAM bootstrap", path)
			}
		}
	}
	administrator := bootstrap.Administrator.Password.CopyBytes()
	defer clear(administrator)
	if actual := readTestFile(t, plan.Root, layout.InitialAdministratorPassword); !bytes.Equal(actual, administrator) {
		t.Fatal("initial administrator password file differs from IAM bootstrap")
	}

	for _, database := range []struct {
		path string
		role string
	}{
		{layout.PostgresMigration, "matrix"},
		{layout.IAMAPI, "matrix_iam_api_login"},
		{layout.IAMWorker, "matrix_iam_worker_login"},
		{layout.AuditRuntime, "matrix_audit_runtime_login"},
		{layout.PaaSAPI, "matrix_paas_api_login"},
		{layout.PaaSWorker, "matrix_paas_worker_login"},
	} {
		content := readTestFile(t, plan.Root, database.path)
		if err := validateDatabaseDSN(string(content), database.role); err != nil {
			t.Fatalf("validate staged database credential %s: %v", database.path, err)
		}
		clear(content)
	}

	before := snapshotManagedCredentials(t, plan.Root)
	if err := stageInstallation(plan, failingEntropy{}); err != nil {
		t.Fatalf("replay staged installation without new entropy: %v", err)
	}
	after := snapshotManagedCredentials(t, plan.Root)
	if !equalSnapshots(before, after) {
		t.Fatal("staging replay changed installation credentials")
	}

	compiled, err := topology.Compile(plan.Bundle.Manifest, topology.Options{
		InstallationID: plan.InstallationID,
		Root:           "/matrix-installation-root",
		Listener:       plan.Listener,
		Port:           plan.Port,
	})
	if err != nil {
		t.Fatalf("compile fixture topology: %v", err)
	}
	if err := publishInstallationConfiguration(plan.Root, plan.Bundle.Manifest, compiled); err != nil {
		t.Fatalf("publish installation configuration: %v", err)
	}
	catalogBytes := readTestFile(t, plan.Root, layout.ArtifactCatalog)
	catalog, err := apphostingv1.DecodeArtifactCatalog(catalogBytes)
	if err != nil {
		t.Fatalf("decode artifact catalog: %v", err)
	}
	var expected []apphostingv1.ArtifactCatalogEntry
	for _, image := range plan.Bundle.Manifest.Images {
		if image.Purpose == release.ImageWorkload {
			expected = append(expected, apphostingv1.ArtifactCatalogEntry{
				ArtifactDigest: image.SourceDigest,
				ImageID:        image.ImageID,
			})
		}
	}
	slices.SortFunc(expected, func(left, right apphostingv1.ArtifactCatalogEntry) int {
		return strings.Compare(left.ArtifactDigest, right.ArtifactDigest)
	})
	if !slices.Equal(catalog.Entries, expected) {
		t.Fatalf("workload catalog = %#v, want %#v", catalog.Entries, expected)
	}

	publicConfiguration := bytes.Join([][]byte{
		readTestFile(t, plan.Root, layout.Compose),
		catalogBytes,
		readTestFile(t, plan.Root, layout.APISIX),
	}, nil)
	secrets := [][]byte{administrator, readTestFile(t, plan.Root, layout.PostgresPassword)}
	for _, credential := range serviceCredentials {
		secrets = append(secrets, credential)
	}
	for _, secret := range secrets {
		if len(secret) == 0 || bytes.Contains(publicConfiguration, secret) {
			t.Fatal("generated configuration contains credential material")
		}
	}
}

func TestLoadInstallImagesUsesAuthenticatedStdinAndExactIdentities(t *testing.T) {
	plan := newInstallPlan(t)
	if err := stageInstallation(plan, rand.Reader); err != nil {
		t.Fatalf("stage installation: %v", err)
	}
	runtimeBoundary := newImageRuntime(plan.Bundle.Manifest, false)
	if err := loadInstallImages(context.Background(), runtimeBoundary, plan); err != nil {
		t.Fatalf("load installation images: %v", err)
	}
	if len(runtimeBoundary.loads) != len(plan.Bundle.Manifest.Images) {
		t.Fatalf("image load count = %d, want %d", len(runtimeBoundary.loads), len(plan.Bundle.Manifest.Images))
	}
	for _, image := range plan.Bundle.Manifest.Images {
		if !runtimeBoundary.present[image.ImageID] {
			t.Fatalf("image %s was not verified after load", image.Component)
		}
	}
	for _, arguments := range runtimeBoundary.commands {
		joined := strings.Join(arguments, " ")
		if strings.Contains(joined, " pull") || strings.Contains(joined, " build") ||
			strings.Contains(joined, " tag") || strings.Contains(joined, " push") ||
			strings.Contains(joined, " registry") {
			t.Fatalf("offline image loader used forbidden provider command %q", joined)
		}
	}
	loads := len(runtimeBoundary.loads)
	if err := loadInstallImages(context.Background(), runtimeBoundary, plan); err != nil {
		t.Fatalf("replay image loading: %v", err)
	}
	if len(runtimeBoundary.loads) != loads {
		t.Fatal("image-loading replay imported already verified images")
	}
}

func TestLoadInstallImagesKeepsStartedFailureOutcomeUnknown(t *testing.T) {
	plan := newInstallPlan(t)
	if err := stageInstallation(plan, rand.Reader); err != nil {
		t.Fatalf("stage installation: %v", err)
	}
	runtimeBoundary := newImageRuntime(plan.Bundle.Manifest, false)
	runtimeBoundary.failLoad = true
	err := loadInstallImages(context.Background(), runtimeBoundary, plan)
	if !errors.Is(err, platformcommand.ErrEffectOutcomeUnknown) {
		t.Fatalf("started image load failure = %v", err)
	}
}

func TestRejectProjectCollisionRequiresExactInstallationOwnership(t *testing.T) {
	foreign := &scriptedRuntime{run: func(arguments []string) ([]byte, bool, error) {
		switch {
		case len(arguments) >= 2 && arguments[1] == "ls" && arguments[0] == "container":
			return []byte("foreign-container\n"), true, nil
		case len(arguments) >= 2 && arguments[1] == "inspect":
			return []byte(`{"com.docker.compose.project":"matrix-mxi"}`), true, nil
		default:
			return nil, true, nil
		}
	}}
	err := rejectProjectCollision(
		context.Background(), foreign, "matrix-mxi", "mxi-11111111111111111111111111111111",
	)
	if !errors.Is(err, platformcommand.ErrEffectConflict) {
		t.Fatalf("foreign project collision = %v", err)
	}

	owned := &scriptedRuntime{run: func(arguments []string) ([]byte, bool, error) {
		switch {
		case len(arguments) >= 2 && arguments[1] == "ls" && arguments[0] == "network":
			return []byte("owned-network\n"), true, nil
		case len(arguments) >= 2 && arguments[1] == "inspect":
			return []byte(`{"com.xiak.matrix.managed":"true","com.xiak.matrix.installation":"mxi-11111111111111111111111111111111"}`), true, nil
		default:
			return nil, true, nil
		}
	}}
	if err := rejectProjectCollision(
		context.Background(), owned, "matrix-mxi", "mxi-11111111111111111111111111111111",
	); err != nil {
		t.Fatalf("installation-owned project collision: %v", err)
	}
}

func TestCompareProviderVersionUsesSemanticComponents(t *testing.T) {
	tests := []struct {
		actual  string
		minimum string
		want    int
	}{
		{actual: "29.0.1", minimum: "29.0.0", want: 1},
		{actual: "v29.0.0", minimum: "29.0.0", want: 0},
		{actual: "28.10.0", minimum: "29.0.0", want: -1},
		{actual: "2.40.0-desktop.1", minimum: "2.40.0", want: 0},
		{actual: "latest", minimum: "2.40.0", want: -1},
	}
	for _, test := range tests {
		if got := compareProviderVersion(test.actual, test.minimum); got != test.want {
			t.Errorf("compareProviderVersion(%q, %q) = %d, want %d", test.actual, test.minimum, got, test.want)
		}
	}
}

func TestGeneratedCredentialKindsCannotBeSubstituted(t *testing.T) {
	random := strings.Repeat("A", 43)
	service := []byte("mx1." + random)
	database := []byte("mxp1." + random)
	administrator := []byte("mxp1." + random + "-Aa1!")
	if !validGeneratedCredential(service, "mx1.", false) ||
		!validGeneratedCredential(database, "mxp1.", false) ||
		!validGeneratedCredential(administrator, "mxp1.", true) {
		t.Fatal("canonical generated credential was rejected")
	}
	if validGeneratedCredential(service, "mxp1.", false) ||
		validGeneratedCredential(database, "mx1.", false) ||
		validGeneratedCredential(administrator, "mxp1.", false) ||
		validGeneratedCredential(database, "mxp1.", true) {
		t.Fatal("generated credential was accepted for a different authority kind")
	}
}

func newInstallPlan(t *testing.T) platformcommand.InstallPlan {
	t.Helper()
	fixture, err := releasetest.Write(t.TempDir())
	if err != nil {
		t.Fatalf("write release fixture: %v", err)
	}
	trustBytes, err := os.ReadFile(fixture.TrustPath)
	if err != nil {
		t.Fatalf("read release trust: %v", err)
	}
	bundle, err := release.VerifyDirectory(fixture.Root, trustBytes)
	if err != nil {
		t.Fatalf("verify release fixture: %v", err)
	}
	return platformcommand.InstallPlan{
		Root: filepath.Clean(t.TempDir()), InstallationID: "mxi-11111111111111111111111111111111",
		Listener: "0.0.0.0", Port: 8080, Bundle: bundle,
		Trust: fixture.Trust, TrustBytes: trustBytes,
	}
}

func readTestFile(t *testing.T, root, relative string) []byte {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative)))
	if err != nil {
		t.Fatalf("read %s: %v", relative, err)
	}
	return content
}

func snapshotManagedCredentials(t *testing.T, root string) map[string]string {
	t.Helper()
	paths := []string{
		layout.ReleaseTrust, layout.IAMBootstrap, layout.AuditIAMCredential,
		layout.IAMAuditCredential, layout.PaaSIAMCredential, layout.PaaSAuditCredential,
		layout.InstallationVerifierCredential, layout.AuditCursorKey,
		layout.APISIXIAMCredential, layout.InitialAdministratorPassword,
		layout.PostgresPassword, layout.PostgresMigration, layout.IAMAPI,
		layout.IAMWorker, layout.AuditRuntime, layout.PaaSAPI, layout.PaaSWorker,
	}
	result := make(map[string]string, len(paths))
	for _, path := range paths {
		result[path] = string(readTestFile(t, root, path))
	}
	return result
}

func equalSnapshots(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for path, content := range left {
		if right[path] != content {
			return false
		}
	}
	return true
}

type failingEntropy struct{}

func (failingEntropy) Read([]byte) (int, error) {
	return 0, errors.New("unexpected entropy read")
}

type imageRuntime struct {
	present          map[string]bool
	payloadToImageID map[string]string
	commands         [][]string
	loads            []string
	failLoad         bool
}

func newImageRuntime(manifest release.Manifest, present bool) *imageRuntime {
	result := &imageRuntime{
		present:          make(map[string]bool, len(manifest.Images)),
		payloadToImageID: make(map[string]string, len(manifest.Images)),
	}
	for _, image := range manifest.Images {
		result.present[image.ImageID] = present
		result.payloadToImageID["matrix-release-payload:"+image.ArchivePath] = image.ImageID
	}
	return result
}

func (runtimeBoundary *imageRuntime) Run(
	_ context.Context,
	input io.Reader,
	arguments ...string,
) ([]byte, bool, error) {
	runtimeBoundary.commands = append(runtimeBoundary.commands, slices.Clone(arguments))
	switch {
	case slices.Equal(arguments[:min(len(arguments), 2)], []string{"image", "inspect"}):
		if len(arguments) != 5 || input != nil {
			return nil, false, errors.New("invalid image inspect command")
		}
		imageID := arguments[4]
		if !runtimeBoundary.present[imageID] {
			return nil, true, errors.New("image absent")
		}
		return []byte(imageID + "|linux|amd64\n"), true, nil
	case slices.Equal(arguments, []string{"image", "load", "--quiet"}):
		if input == nil {
			return nil, false, errors.New("image archive stdin is absent")
		}
		content, err := io.ReadAll(input)
		if err != nil {
			return nil, true, err
		}
		imageID, found := runtimeBoundary.payloadToImageID[string(content)]
		if !found {
			return nil, true, errors.New("image archive stdin is unauthenticated")
		}
		runtimeBoundary.loads = append(runtimeBoundary.loads, imageID)
		if runtimeBoundary.failLoad {
			return nil, true, errors.New("image load interrupted")
		}
		runtimeBoundary.present[imageID] = true
		return nil, true, nil
	default:
		return nil, false, fmt.Errorf("unexpected Docker command: %q", strings.Join(arguments, " "))
	}
}

type scriptedRuntime struct {
	run func([]string) ([]byte, bool, error)
}

func (runtimeBoundary *scriptedRuntime) Run(
	_ context.Context,
	input io.Reader,
	arguments ...string,
) ([]byte, bool, error) {
	if input != nil {
		return nil, false, errors.New("unexpected Docker stdin")
	}
	return runtimeBoundary.run(arguments)
}
