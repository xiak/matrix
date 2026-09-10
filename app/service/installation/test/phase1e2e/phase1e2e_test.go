package phase1e2e

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/xiak/matrix/app/service/devops/sourcetrust"
	"github.com/xiak/matrix/app/service/installation/release"
)

func TestEdgeClientOwnsAndClearsForbiddenMaterial(t *testing.T) {
	client := newEdgeClient("http://127.0.0.1")
	original := []byte("phase1-secret-material")
	client.addForbidden(original)
	if len(client.forbidden) != 1 || !bytes.Equal(client.forbidden[0], original) {
		t.Fatal("edge client did not retain forbidden material")
	}
	owned := client.forbidden[0]
	clear(original)
	if bytes.Equal(owned, original) {
		t.Fatal("edge client retained the caller-owned secret slice")
	}
	client.close()
	if client.forbidden != nil || !bytes.Equal(owned, make([]byte, len(owned))) {
		t.Fatal("edge client did not clear forbidden material")
	}
}

func TestMXSourceCredentialResultIsStrict(t *testing.T) {
	exact := []byte(`{"apiVersion":"cli.matrix.xiak.com/v1","kind":"SourceCredentialCommandResult","action":"SOURCE_CREDENTIAL_APPLY","status":"SUCCEEDED","result":{"state":"APPLIED","purpose":"WEBHOOK","tenant":"organization-default","reference":"phase1-webhook"}}`)
	if !validMXSourceCredentialResult(
		exact, "SOURCE_CREDENTIAL_APPLY", "APPLIED", "WEBHOOK",
		"organization-default", "phase1-webhook",
	) {
		t.Fatal("exact source credential result was rejected")
	}
	for name, content := range map[string][]byte{
		"unknown field":  []byte(`{"apiVersion":"cli.matrix.xiak.com/v1","kind":"SourceCredentialCommandResult","action":"SOURCE_CREDENTIAL_APPLY","status":"SUCCEEDED","result":{"state":"APPLIED","purpose":"WEBHOOK","tenant":"organization-default","reference":"phase1-webhook","value":"forbidden"}}`),
		"wrong state":    []byte(`{"apiVersion":"cli.matrix.xiak.com/v1","kind":"SourceCredentialCommandResult","action":"SOURCE_CREDENTIAL_APPLY","status":"SUCCEEDED","result":{"state":"UNCHANGED","purpose":"WEBHOOK","tenant":"organization-default","reference":"phase1-webhook"}}`),
		"trailing value": append(append([]byte(nil), exact...), []byte("\n{}")...),
	} {
		t.Run(name, func(t *testing.T) {
			if validMXSourceCredentialResult(
				content, "SOURCE_CREDENTIAL_APPLY", "APPLIED", "WEBHOOK",
				"organization-default", "phase1-webhook",
			) {
				t.Fatal("unsafe source credential result was accepted")
			}
		})
	}
}

func TestMXSourceTrustResultIsStrict(t *testing.T) {
	exact := []byte(`{"apiVersion":"cli.matrix.xiak.com/v1","kind":"SourceTrustCommandResult","action":"SOURCE_TRUST_APPLY","status":"SUCCEEDED","result":{"state":"APPLIED","tenant":"organization-default","endpointOrigin":"https://gitea.phase1.invalid"}}`)
	if !validMXSourceTrustResult(
		exact, "SOURCE_TRUST_APPLY", "APPLIED", "organization-default",
		"https://gitea.phase1.invalid",
	) {
		t.Fatal("exact source trust result was rejected")
	}
	for name, content := range map[string][]byte{
		"unknown field":  []byte(`{"apiVersion":"cli.matrix.xiak.com/v1","kind":"SourceTrustCommandResult","action":"SOURCE_TRUST_APPLY","status":"SUCCEEDED","result":{"state":"APPLIED","tenant":"organization-default","endpointOrigin":"https://gitea.phase1.invalid","certificate":"forbidden"}}`),
		"wrong state":    []byte(`{"apiVersion":"cli.matrix.xiak.com/v1","kind":"SourceTrustCommandResult","action":"SOURCE_TRUST_APPLY","status":"SUCCEEDED","result":{"state":"UNCHANGED","tenant":"organization-default","endpointOrigin":"https://gitea.phase1.invalid"}}`),
		"trailing value": append(append([]byte(nil), exact...), []byte("\n{}")...),
	} {
		t.Run(name, func(t *testing.T) {
			if validMXSourceTrustResult(
				content, "SOURCE_TRUST_APPLY", "APPLIED", "organization-default",
				"https://gitea.phase1.invalid",
			) {
				t.Fatal("unsafe source trust result was accepted")
			}
		})
	}
}

func TestDevOpsSourceTrustFixtureIsCanonical(t *testing.T) {
	now := time.Now().UTC()
	bundle, err := newDevOpsSourceTrustBundle(now)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(bundle)
	if _, err := sourcetrust.CertPool(bundle, now); err != nil ||
		bytes.Contains(bundle, []byte("PRIVATE KEY")) {
		t.Fatalf("source trust fixture is invalid or contains a private key: %v", err)
	}
}

func TestDevOpsSourceInputCleanupTargetsOnlyExactEmptyPaths(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "credential-input")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(directory, "credential.input")
	if err := os.WriteFile(input, []byte("temporary-source-material"), 0o600); err != nil {
		t.Fatal(err)
	}
	sibling := filepath.Join(root, "must-remain")
	if err := os.WriteFile(sibling, []byte("owned-by-someone-else"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := removeDevOpsSourceInput(directory); err == nil {
		t.Fatal("non-empty source input directory was recursively removed")
	}
	if _, err := os.Stat(input); err != nil {
		t.Fatalf("failed directory removal changed its child: %v", err)
	}
	if err := removeDevOpsSourceInput(input); err != nil {
		t.Fatal(err)
	}
	if err := removeDevOpsSourceInput(directory); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("source input directory remains: %v", err)
	}
	if _, err := os.Stat(sibling); err != nil {
		t.Fatalf("source input cleanup changed a sibling: %v", err)
	}
}

func TestOfflinePhase1Lifecycle(t *testing.T) {
	if os.Getenv("MATRIX_PHASE1_E2E") != "1" {
		t.Skip("set MATRIX_PHASE1_E2E=1 inside a clean external-network-disabled Linux Docker host")
	}
	config, err := optionsFromEnvironment()
	if err != nil {
		t.Fatal(safeFailure(err))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	if err := runGate(ctx, config); err != nil {
		t.Fatal(safeFailure(err))
	}
}

func TestReleasePairAllowsReleaseSpecificWorkloadImages(t *testing.T) {
	a := release.VerifiedBundle{Manifest: release.Manifest{
		Release: release.ReleaseIdentity{ID: "release-a", Version: "v0.1.0", SourceCommit: "commit"},
		Products: []release.Product{
			release.ApplicationPaaSProduct("v0.1.0"), release.DevOpsProduct("v0.1.0"),
		},
		Images: []release.Image{{Purpose: release.ImageWorkload, SourceDigest: "sha256:a"}},
	}}
	b := release.VerifiedBundle{Manifest: release.Manifest{
		Release: release.ReleaseIdentity{
			ID: "release-b", Version: "v0.2.0", SourceCommit: "different-commit",
			PreviousID: "release-a", PreviousVersion: "v0.1.0",
		},
		Products: []release.Product{
			release.ApplicationPaaSProduct("v0.2.0"), release.DevOpsProduct("v0.2.0"),
		},
		Images: []release.Image{{Purpose: release.ImageWorkload, SourceDigest: "sha256:b"}},
	}}
	if err := validateReleasePair(a, b); err != nil {
		t.Fatalf("release-specific workload images rejected: %v", err)
	}
}

func TestReleasePairRequiresDevOpsInBothSignedLifecycles(t *testing.T) {
	baseA := release.VerifiedBundle{Manifest: release.Manifest{
		Release:  release.ReleaseIdentity{ID: "release-a", Version: "v0.1.0", SourceCommit: "commit-a"},
		Products: []release.Product{release.DevOpsProduct("v0.1.0")},
		Images:   []release.Image{{Purpose: release.ImageWorkload, SourceDigest: "sha256:a"}},
	}}
	baseB := release.VerifiedBundle{Manifest: release.Manifest{
		Release: release.ReleaseIdentity{
			ID: "release-b", Version: "v0.2.0", SourceCommit: "commit-b",
			PreviousID: "release-a", PreviousVersion: "v0.1.0",
		},
		Products: []release.Product{release.DevOpsProduct("v0.2.0")},
		Images:   []release.Image{{Purpose: release.ImageWorkload, SourceDigest: "sha256:b"}},
	}}
	for _, test := range []struct {
		name string
		a    release.VerifiedBundle
		b    release.VerifiedBundle
	}{
		{name: "release a", a: release.VerifiedBundle{Manifest: withoutProducts(baseA.Manifest)}, b: baseB},
		{name: "release b", a: baseA, b: release.VerifiedBundle{Manifest: withoutProducts(baseB.Manifest)}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := validateReleasePair(test.a, test.b); err == nil {
				t.Fatal("release pair without DevOps was accepted")
			}
		})
	}
}

func withoutProducts(manifest release.Manifest) release.Manifest {
	manifest.Products = nil
	return manifest
}

func optionsFromEnvironment() (options, error) {
	phase := os.Getenv("MATRIX_PHASE1_E2E_PHASE")
	if phase != "run" && phase != "after-restart" {
		return options{}, fail("command-input")
	}
	config := options{
		root:       os.Getenv("MATRIX_PHASE1_ROOT"),
		releaseA:   os.Getenv("MATRIX_PHASE1_RELEASE_A"),
		releaseB:   os.Getenv("MATRIX_PHASE1_RELEASE_B"),
		trustKey:   os.Getenv("MATRIX_PHASE1_TRUST_KEY"),
		edge:       defaultEdgeEndpoint,
		afterStart: phase == "after-restart",
	}
	for _, path := range []string{config.root, config.releaseA, config.releaseB, config.trustKey} {
		if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return options{}, fail("command-input")
		}
	}
	return config, nil
}

func runGate(ctx context.Context, config options) error {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		return fail("unsupported-host")
	}
	trust, err := os.ReadFile(config.trustKey)
	if err != nil {
		return fail("release-authentication")
	}
	defer clear(trust)
	a, err := release.VerifyInstalledDirectory(config.releaseA, trust)
	if err != nil {
		return fail("release-a-authentication")
	}
	b, err := release.VerifyDirectory(config.releaseB, trust)
	if err != nil {
		return fail("release-b-authentication")
	}
	if err := validateReleasePair(a, b); err != nil {
		return err
	}
	if config.afterStart {
		return newGate(config, releasePair{a: a, b: b}).afterRestart(ctx)
	}
	return newGate(config, releasePair{a: a, b: b}).beforeRestart(ctx)
}
