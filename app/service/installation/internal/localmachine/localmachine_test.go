package localmachine

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
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

func TestMigrateInstallationUsesFixedGoBinariesWithoutCredentialArguments(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("local-machine migration effects target Linux")
	}
	plan := newInstallPlan(t)
	if err := stageInstallation(plan, rand.Reader); err != nil {
		t.Fatalf("stage installation: %v", err)
	}
	images := newImageRuntime(plan.Bundle.Manifest, true)
	if err := configureInstallation(context.Background(), images, plan); err != nil {
		t.Fatalf("configure installation: %v", err)
	}
	compiled, err := topology.Compile(plan.Bundle.Manifest, topology.Options{
		InstallationID: plan.InstallationID, Root: plan.Root,
		Listener: plan.Listener, Port: plan.Port,
	})
	if err != nil {
		t.Fatalf("compile migration topology: %v", err)
	}
	runtimeBoundary := newMigrationRuntime(plan, compiled.ProjectName)
	if err := migrateInstallation(context.Background(), runtimeBoundary, plan); err != nil {
		t.Fatalf("migrate installation: %v", err)
	}
	if runtimeBoundary.composeCalls != 1 || len(runtimeBoundary.runs) != 6 {
		t.Fatalf("migration provider calls compose=%d run=%d", runtimeBoundary.composeCalls, len(runtimeBoundary.runs))
	}
	wantModes := []string{"apply", "apply", "apply", "verify", "verify", "verify"}
	wantEntrypoints := []string{
		"/matrix/bin/matrix-iam-migrate",
		"/matrix/bin/matrix-audit-migrate",
		"/matrix/bin/matrix-paas-migrate",
		"/matrix/bin/matrix-iam-migrate",
		"/matrix/bin/matrix-audit-migrate",
		"/matrix/bin/matrix-paas-migrate",
	}
	secretValues := [][]byte{
		readTestFile(t, plan.Root, layout.PostgresMigration),
		readTestFile(t, plan.Root, layout.IAMAPI),
		readTestFile(t, plan.Root, layout.IAMWorker),
		readTestFile(t, plan.Root, layout.AuditRuntime),
		readTestFile(t, plan.Root, layout.PaaSAPI),
		readTestFile(t, plan.Root, layout.PaaSWorker),
	}
	for index, arguments := range runtimeBoundary.runs {
		joined := strings.Join(arguments, " ")
		if arguments[len(arguments)-1] != wantModes[index] ||
			!hasArgumentPair(arguments, "--entrypoint", wantEntrypoints[index]) ||
			!hasArgumentPair(arguments, "--pull", "never") ||
			!slices.Contains(arguments, "--read-only") ||
			strings.Contains(joined, "docker.sock") ||
			strings.Contains(joined, "--privileged") ||
			strings.Contains(joined, "--network host") {
			t.Fatalf("migration command %d violates fixed isolation: %q", index, joined)
		}
		for _, secret := range secretValues {
			if bytes.Contains([]byte(joined), secret) {
				t.Fatalf("migration command %d contains database credential material", index)
			}
		}
	}
}

func TestStartInstallationObservesThenConvergesFixedOfflineTopology(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("local-machine platform start effects target Linux")
	}
	plan, expectation := configuredPlatformStartFixture(t)
	runtimeBoundary := newPlatformStartRuntime(plan, expectation)
	if err := startInstallation(context.Background(), runtimeBoundary, plan); err != nil {
		t.Fatalf("start installation: %v", err)
	}
	if runtimeBoundary.composeCalls != 1 || runtimeBoundary.observationsBeforeStart == 0 {
		t.Fatalf(
			"platform convergence compose=%d observations-before-start=%d",
			runtimeBoundary.composeCalls,
			runtimeBoundary.observationsBeforeStart,
		)
	}
	joined := strings.Join(runtimeBoundary.composeArguments, " ")
	if !hasArgumentPair(runtimeBoundary.composeArguments, "--pull", "never") ||
		!slices.Contains(runtimeBoundary.composeArguments, "--no-build") ||
		strings.Contains(joined, "registry") || strings.Contains(joined, "--privileged") {
		t.Fatalf("platform start command is not fixed offline input: %q", joined)
	}
	if err := startInstallation(context.Background(), runtimeBoundary, plan); err != nil {
		t.Fatalf("replay platform start: %v", err)
	}
	if runtimeBoundary.composeCalls != 1 {
		t.Fatal("healthy platform start replay invoked Compose again")
	}
}

func TestStartInstallationRejectsObservedRuntimeDriftWithoutRecreating(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("local-machine platform start effects target Linux")
	}
	plan, expectation := configuredPlatformStartFixture(t)
	runtimeBoundary := newPlatformStartRuntime(plan, expectation)
	runtimeBoundary.started = true
	runtimeBoundary.resourceDriftService = "paas-worker"
	err := startInstallation(context.Background(), runtimeBoundary, plan)
	if !errors.Is(err, platformcommand.ErrEffectVerification) ||
		runtimeBoundary.composeCalls != 0 {
		t.Fatalf("observed platform drift err=%v compose=%d", err, runtimeBoundary.composeCalls)
	}
}

func TestStartInstallationConvergesRecoverableComposeConfigurationDrift(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("local-machine platform start effects target Linux")
	}
	plan, expectation := configuredPlatformStartFixture(t)
	runtimeBoundary := newPlatformStartRuntime(plan, expectation)
	runtimeBoundary.started = true
	runtimeBoundary.configHashDriftService = "paas-api"
	if err := startInstallation(context.Background(), runtimeBoundary, plan); err != nil {
		t.Fatalf("converge recoverable platform configuration drift: %v", err)
	}
	if runtimeBoundary.composeCalls != 1 {
		t.Fatalf("recoverable platform drift Compose calls = %d", runtimeBoundary.composeCalls)
	}
}

func TestStartInstallationMarksUnobservedSuccessfulEffectUnknown(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("local-machine platform start effects target Linux")
	}
	plan, expectation := configuredPlatformStartFixture(t)
	runtimeBoundary := newPlatformStartRuntime(plan, expectation)
	runtimeBoundary.failObservationAfterStart = true
	err := startInstallation(context.Background(), runtimeBoundary, plan)
	if !errors.Is(err, platformcommand.ErrEffectOutcomeUnknown) ||
		errors.Is(err, platformcommand.ErrEffectVerification) ||
		runtimeBoundary.composeCalls != 1 {
		t.Fatalf("unobserved successful start err=%v compose=%d", err, runtimeBoundary.composeCalls)
	}
}

func TestRollbackInstallationRemovesOnlyProvedOwnedObjectsAndReplays(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("local-machine platform cleanup effects target Linux")
	}
	plan, expectation := configuredPlatformStartFixture(t)
	runtimeBoundary := newPlatformCleanupRuntime(t, plan, expectation)
	wantContainers := len(expectation.Services) + 1
	wantNetworks := len(expectation.Networks)

	if err := rollbackInstallation(context.Background(), runtimeBoundary, plan); err != nil {
		t.Fatalf("rollback installation: %v", err)
	}
	if len(runtimeBoundary.containers) != 0 || len(runtimeBoundary.networks) != 0 ||
		runtimeBoundary.containerRemovals != wantContainers ||
		runtimeBoundary.networkRemovals != wantNetworks ||
		runtimeBoundary.unexpectedRemovals != 0 {
		t.Fatalf(
			"cleanup inventory containers=%d networks=%d removals=%d/%d unexpected=%d",
			len(runtimeBoundary.containers), len(runtimeBoundary.networks),
			runtimeBoundary.containerRemovals, runtimeBoundary.networkRemovals,
			runtimeBoundary.unexpectedRemovals,
		)
	}

	if err := rollbackInstallation(context.Background(), runtimeBoundary, plan); err != nil {
		t.Fatalf("replay rollback installation: %v", err)
	}
	if runtimeBoundary.containerRemovals != wantContainers ||
		runtimeBoundary.networkRemovals != wantNetworks {
		t.Fatal("cleanup replay removed additional provider objects")
	}
}

func TestRollbackInstallationRejectsUnprovedOwnershipBeforeRemoval(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("local-machine platform cleanup effects target Linux")
	}
	plan, expectation := configuredPlatformStartFixture(t)
	runtimeBoundary := newPlatformCleanupRuntime(t, plan, expectation)
	migration := runtimeBoundary.containers[runtimeBoundary.migrationID]
	migration.Config.Labels["com.xiak.matrix.release"] = "sha256:" + strings.Repeat("f", 64)
	runtimeBoundary.containers[runtimeBoundary.migrationID] = migration

	err := rollbackInstallation(context.Background(), runtimeBoundary, plan)
	if !errors.Is(err, platformcommand.ErrEffectConflict) ||
		runtimeBoundary.containerRemovals != 0 || runtimeBoundary.networkRemovals != 0 {
		t.Fatalf(
			"unproved cleanup err=%v removals=%d/%d",
			err, runtimeBoundary.containerRemovals, runtimeBoundary.networkRemovals,
		)
	}
}

func TestRollbackInstallationReplaysAStartedRemovalWithUnknownOutcome(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("local-machine platform cleanup effects target Linux")
	}
	plan, expectation := configuredPlatformStartFixture(t)
	runtimeBoundary := newPlatformCleanupRuntime(t, plan, expectation)
	runtimeBoundary.failStartedRemovalOnce = true

	err := rollbackInstallation(context.Background(), runtimeBoundary, plan)
	if !errors.Is(err, platformcommand.ErrEffectOutcomeUnknown) ||
		runtimeBoundary.containerRemovals != 1 {
		t.Fatalf("started cleanup err=%v removals=%d", err, runtimeBoundary.containerRemovals)
	}
	if err := rollbackInstallation(context.Background(), runtimeBoundary, plan); err != nil {
		t.Fatalf("replay uncertain rollback: %v", err)
	}
	if len(runtimeBoundary.containers) != 0 || len(runtimeBoundary.networks) != 0 ||
		runtimeBoundary.containerRemovals != len(expectation.Services)+1 ||
		runtimeBoundary.networkRemovals != len(expectation.Networks) {
		t.Fatalf(
			"replayed cleanup inventory=%d/%d removals=%d/%d",
			len(runtimeBoundary.containers), len(runtimeBoundary.networks),
			runtimeBoundary.containerRemovals, runtimeBoundary.networkRemovals,
		)
	}
}

func configuredPlatformStartFixture(
	t *testing.T,
) (platformcommand.InstallPlan, platformComposeExpectation) {
	t.Helper()
	plan := newInstallPlan(t)
	if err := stageInstallation(plan, rand.Reader); err != nil {
		t.Fatalf("stage installation: %v", err)
	}
	images := newImageRuntime(plan.Bundle.Manifest, true)
	if err := configureInstallation(context.Background(), images, plan); err != nil {
		t.Fatalf("configure installation: %v", err)
	}
	installation, err := verifiedInstallationConfiguration(plan)
	if err != nil {
		t.Fatalf("verify installation configuration: %v", err)
	}
	expectation, err := decodePlatformExpectation(installation.topology.ComposeJSON)
	if err != nil {
		t.Fatalf("decode platform expectation: %v", err)
	}
	return plan, expectation
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

func TestLocalDockerEnvironmentPinsThePhaseOneEngineAndComposeInput(t *testing.T) {
	environment := localDockerEnvironment([]string{
		"PATH=/usr/bin",
		"DOCKER_HOST=tcp://remote.example:2376",
		"docker_context=remote",
		"DOCKER_API_VERSION=1.20",
		"COMPOSE_FILE=/tmp/untrusted.yaml",
		"COMPOSE_PROJECT_NAME=untrusted",
		"COMPOSE_ENV_FILES=/tmp/untrusted.env",
		"COMPOSE_DISABLE_ENV_FILE=0",
		"COMPOSE_REMOVE_ORPHANS=1",
	})
	values := make(map[string][]string)
	for _, entry := range environment {
		key, value, found := strings.Cut(entry, "=")
		if !found {
			t.Fatalf("Docker environment entry is malformed: %q", entry)
		}
		values[strings.ToUpper(key)] = append(values[strings.ToUpper(key)], value)
	}
	if !slices.Equal(values["PATH"], []string{"/usr/bin"}) ||
		!slices.Equal(values["DOCKER_HOST"], []string{"unix:///var/run/docker.sock"}) ||
		len(values["DOCKER_CONTEXT"]) != 0 || len(values["DOCKER_API_VERSION"]) != 0 ||
		len(values["COMPOSE_FILE"]) != 0 || len(values["COMPOSE_PROJECT_NAME"]) != 0 ||
		len(values["COMPOSE_ENV_FILES"]) != 0 ||
		!slices.Equal(values["COMPOSE_DISABLE_ENV_FILE"], []string{"1"}) ||
		!slices.Equal(values["COMPOSE_REMOVE_ORPHANS"], []string{"false"}) {
		t.Fatalf("fixed Docker command environment = %#v", values)
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
	root := filepath.Clean(t.TempDir())
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatalf("protect installation fixture root: %v", err)
	}
	return platformcommand.InstallPlan{
		Root: root, InstallationID: "mxi-11111111111111111111111111111111",
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

type migrationRuntime struct {
	images         map[string]bool
	project        string
	installation   string
	release        string
	composeCalls   int
	runs           [][]string
	controlNetwork string
}

type platformStartRuntime struct {
	expectation               platformComposeExpectation
	images                    map[string]bool
	started                   bool
	resourceDriftService      string
	configHashDriftService    string
	failObservationAfterStart bool
	composeCalls              int
	observationsBeforeStart   int
	composeArguments          []string
}

type platformCleanupRuntime struct {
	expectation            platformComposeExpectation
	installation           string
	containers             map[string]platformContainerInspection
	networks               map[string]platformNetworkInspection
	migrationID            string
	containerRemovals      int
	networkRemovals        int
	unexpectedRemovals     int
	failStartedRemovalOnce bool
	failedStartedRemoval   bool
}

const platformTestConfigHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func newPlatformStartRuntime(
	plan platformcommand.InstallPlan,
	expectation platformComposeExpectation,
) *platformStartRuntime {
	images := make(map[string]bool, len(plan.Bundle.Manifest.Images))
	for _, image := range plan.Bundle.Manifest.Images {
		images[image.ImageID] = true
	}
	return &platformStartRuntime{expectation: expectation, images: images}
}

func newPlatformCleanupRuntime(
	t *testing.T,
	plan platformcommand.InstallPlan,
	expectation platformComposeExpectation,
) *platformCleanupRuntime {
	t.Helper()
	runtimeBoundary := &platformCleanupRuntime{
		expectation:  expectation,
		installation: plan.InstallationID,
		containers:   make(map[string]platformContainerInspection, len(expectation.Services)+1),
		networks:     make(map[string]platformNetworkInspection, len(expectation.Networks)),
		migrationID:  "migration-test-container",
	}
	for serviceName, expected := range expectation.Services {
		identity := "container-" + serviceName
		labels := cloneTestLabels(expected.Labels)
		labels["com.docker.compose.project"] = expectation.Name
		labels["com.docker.compose.service"] = serviceName
		labels["com.docker.compose.oneoff"] = "False"
		runtimeBoundary.containers[identity] = platformContainerInspection{
			ID: identity, Name: "/" + expectation.Name + "-" + serviceName + "-1",
			Image: expected.Image, Config: platformContainerConfig{Labels: labels},
		}
	}
	for logicalName, expected := range expectation.Networks {
		identity := "network-" + logicalName
		labels := cloneTestLabels(expected.Labels)
		labels["com.docker.compose.project"] = expectation.Name
		labels["com.docker.compose.network"] = logicalName
		runtimeBoundary.networks[identity] = platformNetworkInspection{
			ID: identity, Internal: expected.Internal, Labels: labels,
		}
	}
	migrations, err := expectedMigrationCleanupIdentities(plan, expectation.Name)
	if err != nil {
		t.Fatalf("derive cleanup migration identities: %v", err)
	}
	names := make([]string, 0, len(migrations))
	for name := range migrations {
		names = append(names, name)
	}
	slices.Sort(names)
	selected := migrations[names[0]]
	runtimeBoundary.containers[runtimeBoundary.migrationID] = platformContainerInspection{
		ID: runtimeBoundary.migrationID, Name: "/" + names[0], Image: selected.imageID,
		Config: platformContainerConfig{Labels: map[string]string{
			"com.xiak.matrix.managed":      "true",
			"com.xiak.matrix.installation": plan.InstallationID,
			"com.xiak.matrix.release":      plan.Bundle.Manifest.Release.ID,
			"com.xiak.matrix.role":         selected.role,
		}},
	}
	return runtimeBoundary
}

func (runtimeBoundary *platformCleanupRuntime) Run(
	_ context.Context,
	input io.Reader,
	arguments ...string,
) ([]byte, bool, error) {
	if input != nil || len(arguments) < 2 {
		return nil, false, errors.New("platform cleanup Docker invocation is invalid")
	}
	if arguments[1] == "ls" {
		switch arguments[0] {
		case "container":
			if hasArgumentPair(
				arguments, "--filter",
				"label=com.xiak.matrix.installation="+runtimeBoundary.installation,
			) {
				return cleanupContainerInventory(runtimeBoundary.containers, "", ""), true, nil
			}
			return cleanupContainerInventory(
				runtimeBoundary.containers,
				"com.docker.compose.project", runtimeBoundary.expectation.Name,
			), true, nil
		case "network":
			return cleanupNetworkInventory(
				runtimeBoundary.networks,
				"com.docker.compose.project", runtimeBoundary.expectation.Name,
			), true, nil
		case "volume":
			return nil, true, nil
		}
	}
	identity := arguments[len(arguments)-1]
	if arguments[1] == "inspect" {
		switch arguments[0] {
		case "container":
			inspection, found := runtimeBoundary.containers[identity]
			if !found {
				return nil, true, errors.New("cleanup test container is absent")
			}
			content, err := json.Marshal(inspection)
			return content, true, err
		case "network":
			inspection, found := runtimeBoundary.networks[identity]
			if !found {
				return nil, true, errors.New("cleanup test network is absent")
			}
			content, err := json.Marshal(inspection)
			return content, true, err
		}
	}
	if arguments[1] == "rm" {
		removed := false
		switch arguments[0] {
		case "container":
			if _, found := runtimeBoundary.containers[identity]; found {
				delete(runtimeBoundary.containers, identity)
				runtimeBoundary.containerRemovals++
				removed = true
			}
		case "network":
			if _, found := runtimeBoundary.networks[identity]; found {
				delete(runtimeBoundary.networks, identity)
				runtimeBoundary.networkRemovals++
				removed = true
			}
		default:
			runtimeBoundary.unexpectedRemovals++
		}
		if !removed {
			return nil, true, errors.New("cleanup test object is absent or unsupported")
		}
		if runtimeBoundary.failStartedRemovalOnce && !runtimeBoundary.failedStartedRemoval {
			runtimeBoundary.failedStartedRemoval = true
			return nil, true, errors.New("cleanup test removal outcome is unknown")
		}
		return nil, true, nil
	}
	runtimeBoundary.unexpectedRemovals++
	return nil, false, fmt.Errorf("unexpected cleanup Docker command: %q", strings.Join(arguments, " "))
}

func cleanupContainerInventory(
	containers map[string]platformContainerInspection,
	label, value string,
) []byte {
	identities := make([]string, 0, len(containers))
	for identity, inspection := range containers {
		if label == "" || inspection.Config.Labels[label] == value {
			identities = append(identities, identity)
		}
	}
	slices.Sort(identities)
	if len(identities) == 0 {
		return nil
	}
	return []byte(strings.Join(identities, "\n") + "\n")
}

func cleanupNetworkInventory(
	networks map[string]platformNetworkInspection,
	label, value string,
) []byte {
	identities := make([]string, 0, len(networks))
	for identity, inspection := range networks {
		if inspection.Labels[label] == value {
			identities = append(identities, identity)
		}
	}
	slices.Sort(identities)
	if len(identities) == 0 {
		return nil
	}
	return []byte(strings.Join(identities, "\n") + "\n")
}

func (runtimeBoundary *platformStartRuntime) Run(
	_ context.Context,
	input io.Reader,
	arguments ...string,
) ([]byte, bool, error) {
	if input != nil || len(arguments) == 0 {
		return nil, false, errors.New("platform start Docker invocation is invalid")
	}
	if len(arguments) == 5 && arguments[0] == "image" && arguments[1] == "inspect" {
		imageID := arguments[4]
		if !runtimeBoundary.images[imageID] {
			return nil, true, errors.New("platform image is absent")
		}
		return []byte(imageID + "|linux|amd64\n"), true, nil
	}
	if arguments[0] == "compose" && slices.Contains(arguments, "config") {
		services := make([]string, 0, len(runtimeBoundary.expectation.Services))
		for service := range runtimeBoundary.expectation.Services {
			services = append(services, service+" "+platformTestConfigHash)
		}
		slices.Sort(services)
		return []byte(strings.Join(services, "\n") + "\n"), true, nil
	}
	if arguments[0] == "compose" {
		if !hasArgumentPair(arguments, "--pull", "never") ||
			!slices.Contains(arguments, "--no-build") ||
			!slices.Contains(arguments, "up") {
			return nil, true, errors.New("platform Compose invocation is not fixed offline input")
		}
		runtimeBoundary.composeCalls++
		runtimeBoundary.composeArguments = slices.Clone(arguments)
		runtimeBoundary.started = true
		return nil, true, nil
	}
	if len(arguments) >= 2 && arguments[1] == "ls" {
		if !runtimeBoundary.started {
			runtimeBoundary.observationsBeforeStart++
			return nil, true, nil
		}
		if runtimeBoundary.failObservationAfterStart {
			return nil, true, errors.New("platform observation is temporarily unavailable")
		}
		switch arguments[0] {
		case "container":
			services := make([]string, 0, len(runtimeBoundary.expectation.Services))
			for service := range runtimeBoundary.expectation.Services {
				services = append(services, "container-"+service)
			}
			slices.Sort(services)
			return []byte(strings.Join(services, "\n") + "\n"), true, nil
		case "network":
			networks := make([]string, 0, len(runtimeBoundary.expectation.Networks))
			for network := range runtimeBoundary.expectation.Networks {
				networks = append(networks, "network-"+network)
			}
			slices.Sort(networks)
			return []byte(strings.Join(networks, "\n") + "\n"), true, nil
		case "volume":
			return nil, true, nil
		}
	}
	if len(arguments) >= 2 && arguments[1] == "inspect" {
		switch arguments[0] {
		case "network":
			return runtimeBoundary.inspectNetwork(arguments[len(arguments)-1])
		case "container":
			return runtimeBoundary.inspectContainer(arguments[len(arguments)-1])
		}
	}
	return nil, false, fmt.Errorf("unexpected platform Docker command: %q", strings.Join(arguments, " "))
}

func (runtimeBoundary *platformStartRuntime) inspectNetwork(
	identity string,
) ([]byte, bool, error) {
	logicalName := strings.TrimPrefix(identity, "network-")
	expected, found := runtimeBoundary.expectation.Networks[logicalName]
	if !found {
		return nil, true, errors.New("platform test network is unknown")
	}
	labels := cloneTestLabels(expected.Labels)
	labels["com.docker.compose.project"] = runtimeBoundary.expectation.Name
	labels["com.docker.compose.network"] = logicalName
	content, err := json.Marshal(map[string]any{
		"Id": identity, "Internal": expected.Internal, "Labels": labels,
	})
	return content, true, err
}

func (runtimeBoundary *platformStartRuntime) inspectContainer(
	identity string,
) ([]byte, bool, error) {
	serviceName := strings.TrimPrefix(identity, "container-")
	expected, found := runtimeBoundary.expectation.Services[serviceName]
	if !found {
		return nil, true, errors.New("platform test service is unknown")
	}
	labels := cloneTestLabels(expected.Labels)
	labels["com.docker.compose.project"] = runtimeBoundary.expectation.Name
	labels["com.docker.compose.service"] = serviceName
	labels["com.docker.compose.oneoff"] = "False"
	labels["com.docker.compose.config-hash"] = platformTestConfigHash
	if runtimeBoundary.configHashDriftService == serviceName &&
		runtimeBoundary.composeCalls == 0 {
		labels["com.docker.compose.config-hash"] = strings.Repeat("b", 64)
	}
	imageID := expected.Image
	mounts := make([]map[string]any, 0, len(expected.Volumes))
	for _, mount := range expected.Volumes {
		mounts = append(mounts, map[string]any{
			"Type": mount.Type, "Source": mount.Source,
			"Destination": mount.Target, "RW": !mount.ReadOnly,
		})
	}
	networks := make(map[string]any, len(expected.Networks))
	for _, network := range expected.Networks {
		networks[runtimeBoundary.expectation.Name+"_"+network] = map[string]any{
			"NetworkID": "network-" + network,
		}
	}
	ports, err := testPortBindings(expected.Ports)
	if err != nil {
		return nil, true, err
	}
	initEnabled := expected.Init
	nanoCPUs, memory, err := expectedResourceLimits(expected.Deploy)
	if err != nil {
		return nil, true, err
	}
	if runtimeBoundary.resourceDriftService == serviceName {
		memory++
	}
	tmpfs, err := expectedTmpfsInventory(expected.Tmpfs)
	if err != nil {
		return nil, true, err
	}
	content, err := json.Marshal(map[string]any{
		"Id": identity, "Image": imageID,
		"Config": map[string]any{"Labels": labels},
		"State": map[string]any{
			"Status": "running", "Running": true,
			"Health": map[string]any{"Status": "healthy"},
		},
		"HostConfig": map[string]any{
			"Privileged": false, "ReadonlyRootfs": expected.ReadOnly,
			"Init": &initEnabled, "Memory": memory, "NanoCpus": nanoCPUs,
			"CapDrop": []string{"ALL"}, "Tmpfs": tmpfs,
			"SecurityOpt":   []string{"no-new-privileges:true"},
			"PortBindings":  ports,
			"RestartPolicy": map[string]any{"Name": expected.Restart},
		},
		"Mounts":          mounts,
		"NetworkSettings": map[string]any{"Networks": networks},
	})
	return content, true, err
}

func testPortBindings(values []string) (map[string][]map[string]string, error) {
	result := make(map[string][]map[string]string, len(values))
	for _, value := range values {
		separator := strings.LastIndexByte(value, ':')
		if separator < 1 || separator == len(value)-1 {
			return nil, errors.New("platform test port binding is invalid")
		}
		hostIP, hostPort, err := net.SplitHostPort(value[:separator])
		if err != nil {
			return nil, err
		}
		containerPort := value[separator+1:]
		result[containerPort] = append(result[containerPort], map[string]string{
			"HostIp": hostIP, "HostPort": hostPort,
		})
	}
	return result, nil
}

func cloneTestLabels(source map[string]string) map[string]string {
	result := make(map[string]string, len(source)+3)
	for key, value := range source {
		result[key] = value
	}
	return result
}

func newMigrationRuntime(plan platformcommand.InstallPlan, project string) *migrationRuntime {
	images := make(map[string]bool, len(plan.Bundle.Manifest.Images))
	for _, image := range plan.Bundle.Manifest.Images {
		images[image.ImageID] = true
	}
	return &migrationRuntime{
		images: images, project: project, installation: plan.InstallationID,
		release:        plan.Bundle.Manifest.Release.ID,
		controlNetwork: strings.Repeat("a", 64),
	}
}

func (runtimeBoundary *migrationRuntime) Run(
	_ context.Context,
	input io.Reader,
	arguments ...string,
) ([]byte, bool, error) {
	if input != nil || len(arguments) == 0 {
		return nil, false, errors.New("migration Docker invocation is invalid")
	}
	switch arguments[0] {
	case "compose":
		if !hasArgumentPair(arguments, "--pull", "never") ||
			!slices.Contains(arguments, "--no-build") ||
			arguments[len(arguments)-1] != "postgres" {
			return nil, true, errors.New("PostgreSQL Compose start is not offline")
		}
		runtimeBoundary.composeCalls++
		return nil, true, nil
	case "network":
		if len(arguments) >= 2 && arguments[1] == "ls" {
			return []byte(runtimeBoundary.controlNetwork + "\n"), true, nil
		}
		if len(arguments) >= 2 && arguments[1] == "inspect" {
			return []byte(fmt.Sprintf(
				`{"com.xiak.matrix.managed":"true","com.xiak.matrix.installation":%q,"com.xiak.matrix.release":%q,"com.xiak.matrix.role":"network-control","com.docker.compose.project":%q,"com.docker.compose.network":"control"}`,
				runtimeBoundary.installation, runtimeBoundary.release, runtimeBoundary.project,
			)), true, nil
		}
	case "image":
		if len(arguments) == 5 && arguments[1] == "inspect" && runtimeBoundary.images[arguments[4]] {
			return []byte(arguments[4] + "|linux|amd64\n"), true, nil
		}
	case "run":
		runtimeBoundary.runs = append(runtimeBoundary.runs, slices.Clone(arguments))
		return nil, true, nil
	}
	return nil, false, fmt.Errorf("unexpected migration Docker command: %q", strings.Join(arguments, " "))
}

func hasArgumentPair(arguments []string, name, value string) bool {
	for index := 0; index+1 < len(arguments); index++ {
		if arguments[index] == name && arguments[index+1] == value {
			return true
		}
	}
	return false
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
