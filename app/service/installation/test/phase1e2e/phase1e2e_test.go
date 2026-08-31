package phase1e2e

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	nodev1 "github.com/xiak/matrix/api/adapter/node/v1"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
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

func TestExecutionTargetTransitionRejectionRequiresExactProblemCode(t *testing.T) {
	for _, scenario := range []struct {
		name     string
		actual   paasv1.ErrorCode
		expected paasv1.ErrorCode
		accepted bool
	}{
		{name: "idempotency conflict", actual: paasv1.ErrorIdempotencyConflict, expected: paasv1.ErrorIdempotencyConflict, accepted: true},
		{name: "lifecycle conflict", actual: paasv1.ErrorConflict, expected: paasv1.ErrorConflict, accepted: true},
		{name: "different conflict class", actual: paasv1.ErrorIdempotencyConflict, expected: paasv1.ErrorConflict},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				if request.URL.Path != "/api/paas/v1/execution-targets/target-a/activate" ||
					request.Header.Get("Idempotency-Key") != "transition-a" ||
					request.Header.Get("If-Match") != `"2"` {
					response.WriteHeader(http.StatusBadRequest)
					return
				}
				response.Header().Set("Content-Type", "application/problem+json")
				response.WriteHeader(http.StatusConflict)
				_ = json.NewEncoder(response).Encode(paasv1.Problem{
					Type:  "https://matrix.xiak.com/problems/execution-target-transition",
					Title: "Execution target transition conflict", Status: http.StatusConflict,
					Code: scenario.actual, Detail: "the transition conflicts with retained state",
					TraceID: "request-transition-a", Retryable: false,
				})
			}))
			defer server.Close()
			client := newEdgeClient(server.URL)
			defer client.close()
			_, err := client.rejectExecutionTargetTransition(
				context.Background(), nil, "target-a", paasv1.OperationActivateExecutionTarget,
				"transition-a", `"2"`, scenario.expected,
			)
			if (err == nil) != scenario.accepted {
				t.Fatalf("transition rejection accepted=%t err=%v", err == nil, err)
			}
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

func TestTerminalTicketReplayRequiresTheNonDisclosingNotFoundContract(t *testing.T) {
	for _, scenario := range []struct {
		name   string
		status int
		code   paasv1.ErrorCode
		accept bool
	}{
		{name: "non-disclosing replay denial", status: http.StatusNotFound, code: paasv1.ErrorNotFound, accept: true},
		{name: "existence-revealing conflict", status: http.StatusConflict, code: paasv1.ErrorConflict},
		{name: "wrong problem code", status: http.StatusNotFound, code: paasv1.ErrorConflict},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				if request.Header.Get("Origin") != serverOrigin(request) ||
					request.Header.Get("Cookie") != terminalTicketCookieName+"="+strings.Repeat("A", 43) ||
					request.Header.Get("Sec-WebSocket-Protocol") != nodev1.TerminalSubprotocol {
					response.WriteHeader(http.StatusBadRequest)
					return
				}
				response.Header().Set("Content-Type", "application/problem+json")
				response.WriteHeader(scenario.status)
				_ = json.NewEncoder(response).Encode(paasv1.Problem{
					Type:  "https://matrix.xiak.com/problems/terminal-replay",
					Title: "Terminal unavailable", Status: scenario.status, Code: scenario.code,
					Detail:  "the terminal ticket cannot identify an available session",
					TraceID: "request-terminal-replay", Retryable: false,
				})
			}))
			defer server.Close()
			client := newEdgeClient(server.URL)
			defer client.close()
			err := rejectNativeTerminalReplay(
				context.Background(), client,
				"/api/paas/v1/terminal-sessions/terminal-session-"+strings.Repeat("a", 32)+"/connect",
				terminalTicketCookieName+"="+strings.Repeat("A", 43),
			)
			if (err == nil) != scenario.accept {
				t.Fatalf("replay denial accepted=%t err=%v", err == nil, err)
			}
		})
	}
}

func serverOrigin(request *http.Request) string {
	return "http://" + request.Host
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

func TestReleasePairRequiresCompatibleImmediatePredecessor(t *testing.T) {
	for _, scenario := range []struct {
		name   string
		mutate func(a, b *release.Manifest)
		accept bool
	}{
		{name: "actual different-source predecessor and workload", accept: true, mutate: func(_, b *release.Manifest) {
			b.Release.SourceCommit = strings.Repeat("b", 40)
		}},
		{name: "exact retained-data profile and topology successor", accept: true, mutate: func(a, _ *release.Manifest) {
			a.Database = release.SupportedDatabasePredecessorProfile()
			a.TopologyDigest = "sha256:" + strings.Repeat("3", 64)
		}},
		{name: "same-source lifecycle fixture", accept: true},
		{name: "wrong predecessor", mutate: func(_, b *release.Manifest) { b.Release.PreviousID = "other-release" }},
		{name: "wrong predecessor version", mutate: func(_, b *release.Manifest) { b.Release.PreviousVersion = "v0.0.1" }},
		{name: "skipped predecessor", mutate: func(a, _ *release.Manifest) {
			a.Release.PreviousID, a.Release.PreviousVersion = "older-release", "v0.0.1"
		}},
		{name: "same release", mutate: func(a, b *release.Manifest) { b.Release.ID = a.Release.ID }},
		{name: "same version", mutate: func(a, b *release.Manifest) { b.Release.Version = a.Release.Version }},
		{name: "different authority tuple", mutate: func(_, b *release.Manifest) { b.Database.Authorities.PaaS++ }},
		{name: "different contract revision", mutate: func(_, b *release.Manifest) { b.Database.ContractRevision++ }},
		{name: "profile downgrade", mutate: func(_, b *release.Manifest) { b.Database.ContractRevision-- }},
		{name: "invalid equal profiles", mutate: func(a, b *release.Manifest) {
			a.Database, b.Database = release.DatabaseProfile{}, release.DatabaseProfile{}
		}},
		{name: "different topology", mutate: func(_, b *release.Manifest) { b.TopologyDigest = "sha256:" + strings.Repeat("2", 64) }},
		{name: "unproved profile with changed topology", mutate: func(a, _ *release.Manifest) {
			a.Database.ContractRevision -= 2
			a.TopologyDigest = "sha256:" + strings.Repeat("3", 64)
		}},
		{name: "node is not a platform release", mutate: func(_, b *release.Manifest) { b.Kind = release.NodeManifestKind }},
		{name: "missing predecessor workload", mutate: func(a, _ *release.Manifest) { a.Images = nil }},
		{name: "missing successor workload", mutate: func(_, b *release.Manifest) { b.Images = nil }},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			a := release.VerifiedBundle{Manifest: release.Manifest{
				Kind: release.ManifestKind,
				Release: release.ReleaseIdentity{
					ID: "release-a", Version: "v0.1.0", SourceCommit: strings.Repeat("a", 40),
				},
				Database: release.CurrentDatabaseProfile(), TopologyDigest: "sha256:" + strings.Repeat("1", 64),
				Images: []release.Image{{Purpose: release.ImageWorkload, SourceDigest: "sha256:a"}},
			}}
			b := release.VerifiedBundle{Manifest: release.Manifest{
				Kind: release.ManifestKind,
				Release: release.ReleaseIdentity{
					ID: "release-b", Version: "v0.2.0", SourceCommit: a.Manifest.Release.SourceCommit,
					PreviousID: "release-a", PreviousVersion: "v0.1.0",
				},
				Database: release.CurrentDatabaseProfile(), TopologyDigest: a.Manifest.TopologyDigest,
				Images: []release.Image{{Purpose: release.ImageWorkload, SourceDigest: "sha256:b"}},
			}}
			if scenario.mutate != nil {
				scenario.mutate(&a.Manifest, &b.Manifest)
			}
			if err := validateReleasePair(a, b); (err == nil) != scenario.accept {
				t.Fatalf("release pair accepted=%t, want %t", err == nil, scenario.accept)
			}
		})
	}
}

func TestReleaseSequenceRequiresTwoCompatibleImmediateTransitions(t *testing.T) {
	for _, scenario := range []struct {
		name   string
		mutate func(base, bridge, successor *release.Manifest)
		accept bool
	}{
		{name: "base through bridge to successor", accept: true},
		{name: "base is not root", mutate: func(base, _, _ *release.Manifest) {
			base.Release.PreviousID, base.Release.PreviousVersion = "older", "v0.0.1"
		}},
		{name: "bridge skips base", mutate: func(_, bridge, _ *release.Manifest) {
			bridge.Release.PreviousID = "other-base"
		}},
		{name: "successor skips bridge", mutate: func(_, _, successor *release.Manifest) {
			successor.Release.PreviousID = "other-bridge"
		}},
		{name: "same-profile bridge changes topology", mutate: func(_, bridge, _ *release.Manifest) {
			bridge.TopologyDigest = "sha256:" + strings.Repeat("4", 64)
		}},
		{name: "successor topology changes without profile transition", mutate: func(_, bridge, successor *release.Manifest) {
			successor.Database = bridge.Database
		}},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			successorProfile := release.CurrentDatabaseProfile()
			bridgeProfile := release.SupportedDatabasePredecessorProfile()
			base := release.VerifiedBundle{Manifest: release.Manifest{
				Kind: release.ManifestKind,
				Release: release.ReleaseIdentity{
					ID: "release-base", Version: "v0.1.0", SourceCommit: strings.Repeat("a", 40),
				},
				Database: bridgeProfile, TopologyDigest: "sha256:" + strings.Repeat("1", 64),
				Images: []release.Image{{Purpose: release.ImageWorkload, SourceDigest: "sha256:base"}},
			}}
			bridge := release.VerifiedBundle{Manifest: release.Manifest{
				Kind: release.ManifestKind,
				Release: release.ReleaseIdentity{
					ID: "release-bridge", Version: "v0.2.0", SourceCommit: strings.Repeat("b", 40),
					PreviousID: base.Manifest.Release.ID, PreviousVersion: base.Manifest.Release.Version,
				},
				Database: bridgeProfile, TopologyDigest: base.Manifest.TopologyDigest,
				Images: []release.Image{{Purpose: release.ImageWorkload, SourceDigest: "sha256:bridge"}},
			}}
			successor := release.VerifiedBundle{Manifest: release.Manifest{
				Kind: release.ManifestKind,
				Release: release.ReleaseIdentity{
					ID: "release-successor", Version: "v0.3.0", SourceCommit: strings.Repeat("c", 40),
					PreviousID: bridge.Manifest.Release.ID, PreviousVersion: bridge.Manifest.Release.Version,
				},
				Database: successorProfile, TopologyDigest: "sha256:" + strings.Repeat("2", 64),
				Images: []release.Image{{Purpose: release.ImageWorkload, SourceDigest: "sha256:successor"}},
			}}
			if scenario.mutate != nil {
				scenario.mutate(&base.Manifest, &bridge.Manifest, &successor.Manifest)
			}
			if err := validateReleaseSequence(base, bridge, successor); (err == nil) != scenario.accept {
				t.Fatalf("release sequence accepted=%t, want %t", err == nil, scenario.accept)
			}
		})
	}
}

func TestMXStatusConsumesConfigurationDigestAndRejectsUnknownFields(t *testing.T) {
	for _, scenario := range []struct {
		name, addition string
		accept         bool
	}{
		{name: "known configuration commitment", accept: true},
		{name: "unknown result material", addition: `,"password":"forbidden"`},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			content := []byte(`{"apiVersion":"cli.matrix.xiak.com/v1","kind":"PlatformCommandResult","action":"STATUS","status":"SUCCEEDED","result":{"state":"READY","releaseId":"release-a","changed":false,"configurationDigest":"` + fixedDigest("controller-input") + `"` + scenario.addition + `}}`)
			var envelope mxEnvelope
			if err := decodeOne(content, &envelope); (err == nil) != scenario.accept {
				t.Fatalf("status contract accepted=%t, want %t", err == nil, scenario.accept)
			}
			if scenario.accept && envelope.Result.ConfigurationDigest != fixedDigest("controller-input") {
				t.Fatal("status decoder discarded the protected configuration commitment")
			}
		})
	}
}

func TestBrowserPasswordInputRequiresPrivateRegularBoundedContent(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("POSIX private-file contract")
	}
	directory := t.TempDir()
	path := filepath.Join(directory, "browser-password.private")
	write := func(content string, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}
	write("0123456789abcdefghij", 0o600)
	value := newGate(options{browserPasswordFile: path}, releasePair{})
	password, err := value.finalPassword()
	if err != nil || string(password) != "0123456789abcdefghij" {
		clear(password)
		t.Fatal("private bounded browser password was rejected")
	}
	clear(password)

	write("0123456789abcdefghij", 0o640)
	if password, err = value.finalPassword(); err == nil {
		clear(password)
		t.Fatal("group-readable browser password was accepted")
	}
	write("0123456789abcdefghi\n", 0o600)
	if password, err = value.finalPassword(); err == nil {
		clear(password)
		t.Fatal("line-delimited browser password was accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(directory, "missing"), path); err != nil {
		t.Fatal(err)
	}
	if password, err = value.finalPassword(); err == nil {
		clear(password)
		t.Fatal("symlinked browser password was accepted")
	}
}

func TestSpecializedAcceptancePhasesOwnOnlyTheirRequiredInputs(t *testing.T) {
	directory := t.TempDir()
	password := filepath.Join(directory, "browser-password.private")
	nodes := filepath.Join(directory, "native-nodes.json")
	for _, scenario := range []struct {
		name, phase string
		password    bool
		native      bool
		accept      bool
	}{
		{name: "browser acceptance with local runtime", phase: "browser", password: true, accept: true},
		{name: "browser acceptance without operator credential", phase: "browser"},
		{name: "multi-host lifecycle with native runtime", phase: "multi-host", native: true, accept: true},
		{name: "multi-host lifecycle without native runtime", phase: "multi-host"},
		{name: "ordinary lifecycle cannot expose an operator credential", phase: "run", password: true},
		{name: "existing native browser acceptance", phase: "run", password: true, native: true, accept: true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			t.Setenv("MATRIX_PHASE1_E2E_PHASE", scenario.phase)
			t.Setenv("MATRIX_PHASE1_ROOT", filepath.Join(directory, "installation"))
			t.Setenv("MATRIX_PHASE1_RELEASE_BASE", "")
			t.Setenv("MATRIX_PHASE1_RELEASE_A", filepath.Join(directory, "release-a"))
			t.Setenv("MATRIX_PHASE1_RELEASE_B", filepath.Join(directory, "release-b"))
			t.Setenv("MATRIX_PHASE1_TRUST_KEY", filepath.Join(directory, "trust.pem"))
			t.Setenv("MATRIX_PHASE1_NATIVE_NODES", "")
			t.Setenv("MATRIX_PHASE1_NATIVE_DEPLOYMENT_RUNTIME", "")
			t.Setenv("MATRIX_PHASE1_BROWSER_PASSWORD_FILE", "")
			if scenario.password {
				t.Setenv("MATRIX_PHASE1_BROWSER_PASSWORD_FILE", password)
			}
			if scenario.native {
				t.Setenv("MATRIX_PHASE1_NATIVE_NODES", nodes)
				t.Setenv("MATRIX_PHASE1_NATIVE_DEPLOYMENT_RUNTIME", "1")
			}
			config, err := optionsFromEnvironment()
			if (err == nil) != scenario.accept {
				t.Fatalf("browser phase accepted=%t, want %t", err == nil, scenario.accept)
			}
			if scenario.accept && (config.browserReady != (scenario.phase == "browser") ||
				config.multiHostLifecycle != (scenario.phase == "multi-host")) {
				t.Fatal("specialized acceptance phase was not retained independently of the native runtime")
			}
		})
	}
}

func optionsFromEnvironment() (options, error) {
	phase := os.Getenv("MATRIX_PHASE1_E2E_PHASE")
	if phase != "run" && phase != "after-restart" && phase != "browser" && phase != "multi-host" {
		return options{}, fail("command-input")
	}
	config := options{
		root:                    os.Getenv("MATRIX_PHASE1_ROOT"),
		releaseBase:             os.Getenv("MATRIX_PHASE1_RELEASE_BASE"),
		releaseA:                os.Getenv("MATRIX_PHASE1_RELEASE_A"),
		releaseB:                os.Getenv("MATRIX_PHASE1_RELEASE_B"),
		trustKey:                os.Getenv("MATRIX_PHASE1_TRUST_KEY"),
		edge:                    defaultEdgeEndpoint,
		afterStart:              phase == "after-restart",
		browserReady:            phase == "browser",
		multiHostLifecycle:      phase == "multi-host",
		nativeNodes:             os.Getenv("MATRIX_PHASE1_NATIVE_NODES"),
		nativeDeploymentRuntime: os.Getenv("MATRIX_PHASE1_NATIVE_DEPLOYMENT_RUNTIME") == "1",
		browserPasswordFile:     os.Getenv("MATRIX_PHASE1_BROWSER_PASSWORD_FILE"),
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
	if config.releaseBase != "" && (!filepath.IsAbs(config.releaseBase) ||
		filepath.Clean(config.releaseBase) != config.releaseBase) {
		return options{}, fail("command-input")
	}
	if config.nativeNodes != "" && (!filepath.IsAbs(config.nativeNodes) || filepath.Clean(config.nativeNodes) != config.nativeNodes) {
		return options{}, fail("command-input")
	}
	if mode := os.Getenv("MATRIX_PHASE1_NATIVE_DEPLOYMENT_RUNTIME"); mode != "" && mode != "1" {
		return options{}, fail("command-input")
	}
	if config.nativeDeploymentRuntime && (config.nativeNodes == "" || config.afterStart) {
		return options{}, fail("command-input")
	}
	if config.multiHostLifecycle && !config.nativeDeploymentRuntime {
		return options{}, fail("command-input")
	}
	if config.browserReady && config.browserPasswordFile == "" {
		return options{}, fail("command-input")
	}
	if config.browserPasswordFile != "" && ((!config.browserReady && !config.nativeDeploymentRuntime) || !filepath.IsAbs(config.browserPasswordFile) || filepath.Clean(config.browserPasswordFile) != config.browserPasswordFile) {
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
	releases := releasePair{a: a, b: b}
	if config.releaseBase == "" {
		if err := validateReleasePair(a, b); err != nil {
			return err
		}
	} else {
		base, err := release.VerifyDirectory(config.releaseBase, trust)
		if err != nil {
			return fail("release-base-authentication")
		}
		if err := validateReleaseSequence(base, a, b); err != nil {
			return err
		}
		releases.base = &base
	}
	return newGate(config, releases).beforeRestart(ctx)
}
