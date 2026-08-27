package phase1e2e

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/xiak/matrix/app/service/installation/release"
)

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
		Release:  release.ReleaseIdentity{ID: "release-a", Version: "v0.1.0", SourceCommit: "commit"},
		Images:   []release.Image{{Purpose: release.ImageWorkload, SourceDigest: "sha256:a"}},
		Database: release.CurrentDatabaseProfile(),
	}}
	b := release.VerifiedBundle{Manifest: release.Manifest{
		Release: release.ReleaseIdentity{
			ID: "release-b", Version: "v0.2.0", SourceCommit: "commit",
			PreviousID: "release-a", PreviousVersion: "v0.1.0",
		},
		Images:   []release.Image{{Purpose: release.ImageWorkload, SourceDigest: "sha256:b"}},
		Database: release.CurrentDatabaseProfile(),
	}}
	if err := validateReleasePair(a, b); err != nil {
		t.Fatalf("release-specific workload images rejected: %v", err)
	}
	b.Manifest.Database.ContractRevision++
	if validateReleasePair(a, b) == nil {
		t.Fatal("different release contract revision admitted to offline lifecycle gate")
	}
}

func TestEdgeClientChecksSuccessAndProblemMediaTypes(t *testing.T) {
	for _, check := range []struct {
		name, mediaType string
		status          int
		valid           bool
	}{
		{"success", "application/json", http.StatusOK, true},
		{"authentication-denied", "application/problem+json", http.StatusUnauthorized, true},
		{"resource-hidden", "application/problem+json", http.StatusNotFound, true},
		{"invalid-success", "application/problem+json", http.StatusOK, false},
		{"invalid-problem", "application/json", http.StatusForbidden, false},
	} {
		t.Run(check.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
				response.Header().Set("Content-Type", check.mediaType)
				response.WriteHeader(check.status)
				_, _ = response.Write([]byte(`{}`))
			}))
			defer server.Close()
			client := newEdgeClient(server.URL)
			defer client.close()
			_, err := client.json(context.Background(), http.MethodGet, "/", nil, nil, nil, check.status)
			if (err == nil) != check.valid {
				t.Fatalf("response contract accepted=%t, want %t", err == nil, check.valid)
			}
		})
	}
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
	for _, path := range []string{config.root, config.releaseA, config.trustKey} {
		if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return options{}, fail("command-input")
		}
	}
	if !config.afterStart && (config.releaseB == "" || !filepath.IsAbs(config.releaseB) ||
		filepath.Clean(config.releaseB) != config.releaseB) {
		return options{}, fail("command-input")
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
	a, err := release.VerifyDirectory(config.releaseA, trust)
	if err != nil {
		return fail("release-a-authentication")
	}
	if config.afterStart {
		return newGate(config, releasePair{a: a}).afterRestart(ctx)
	}
	b, err := release.VerifyDirectory(config.releaseB, trust)
	if err != nil {
		return fail("release-b-authentication")
	}
	if err := validateReleasePair(a, b); err != nil {
		return err
	}
	return newGate(config, releasePair{a: a, b: b}).beforeRestart(ctx)
}
