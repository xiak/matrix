package phase1e2e

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xiak/matrix/app/service/installation/release"
)

func TestEdgeClientAcceptsExpectedProblemResponses(t *testing.T) {
	for _, scenario := range []struct {
		name, media string
		status      int
		accepted    bool
	}{
		{"JSON success", "application/json", http.StatusOK, true},
		{"expected denial", "application/problem+json", http.StatusUnauthorized, true},
		{"problem is not success", "application/problem+json", http.StatusOK, false},
		{"HTML denial", "text/html", http.StatusUnauthorized, false},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", scenario.media)
				w.WriteHeader(scenario.status)
				_, _ = w.Write([]byte(`{"code":"TEST_RESPONSE"}`))
			}))
			defer server.Close()
			client := newEdgeClient(server.URL)
			defer client.close()
			result, err := client.json(context.Background(), http.MethodGet, "/test", nil, nil, nil, scenario.status)
			if (err == nil) != scenario.accepted || scenario.accepted && result.status != scenario.status {
				t.Fatal("edge gate misclassified the expected HTTP media/status contract")
			}
			clear(result.body)
		})
	}
}

func TestAuditQueryRetriesOnlyBoundedExplicitUnavailability(t *testing.T) {
	const unavailable = `{"type":"https://matrix.xiak.com/problems/audit.unavailable","title":"Audit unavailable","status":503,"code":"audit.unavailable","requestId":"request-test"}`
	const page = `{"apiVersion":"audit.matrix.xiak.com/v1","kind":"AuditRecordPage","tenantId":"organization-default","records":[]}`
	for _, scenario := range []struct {
		name         string
		status       int
		body         string
		persistent   bool
		wantAttempts int32
		wantSuccess  bool
	}{
		{name: "ready", status: 200, body: page, wantAttempts: 1, wantSuccess: true},
		{name: "retry transient unavailable", status: 503, body: unavailable, wantAttempts: 2, wantSuccess: true},
		{name: "bounded persistent unavailable", status: 503, body: unavailable, persistent: true, wantAttempts: 5},
		{name: "authentication denial", status: 401, body: unavailable, wantAttempts: 1},
		{name: "authorization denial", status: 403, body: unavailable, wantAttempts: 1},
		{name: "unexpected gateway response", status: 502, body: unavailable, wantAttempts: 1},
		{name: "different problem", status: 503, body: strings.ReplaceAll(unavailable, "audit.unavailable", "audit.other"), wantAttempts: 1},
		{name: "invalid unavailable problem", status: 503, body: `{}`, wantAttempts: 1},
		{name: "invalid successful page", status: 200, body: `{}`, wantAttempts: 1},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			var attempts atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				status, body := http.StatusOK, page
				if attempts.Add(1) == 1 || scenario.persistent {
					status, body = scenario.status, scenario.body
				}
				media := "application/json"
				if status >= 400 {
					media = "application/problem+json"
				}
				w.Header().Set("Content-Type", media)
				w.WriteHeader(status)
				_, _ = w.Write([]byte(body))
			}))
			defer server.Close()
			client := newEdgeClient(server.URL)
			defer client.close()
			records, err := client.allAuditRecords(context.Background(), nil)
			if (err == nil) != scenario.wantSuccess || attempts.Load() != scenario.wantAttempts {
				t.Fatalf("Audit query success=%t, attempts=%d", err == nil, attempts.Load())
			}
			if err == nil && containsAuditHistory(records, map[string]struct{}{"required-record-hash": {}}) {
				t.Fatal("a successful response masked missing immutable history")
			}
		})
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
		Images:  []release.Image{{Purpose: release.ImageWorkload, SourceDigest: "sha256:a"}},
	}}
	b := release.VerifiedBundle{Manifest: release.Manifest{
		Release: release.ReleaseIdentity{
			ID: "release-b", Version: "v0.2.0", SourceCommit: "commit",
			PreviousID: "release-a", PreviousVersion: "v0.1.0",
		},
		Images: []release.Image{{Purpose: release.ImageWorkload, SourceDigest: "sha256:b"}},
	}}
	if err := validateReleasePair(a, b); err != nil {
		t.Fatalf("release-specific workload images rejected: %v", err)
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
