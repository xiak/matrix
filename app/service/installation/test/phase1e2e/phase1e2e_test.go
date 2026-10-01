package phase1e2e

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
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

func TestOptionsRequirePrivateSecurityMailOnlyForEffectfulLifecycle(t *testing.T) {
	root := t.TempDir()
	for name, value := range map[string]string{
		"MATRIX_PHASE1_E2E_PHASE": "run",
		"MATRIX_PHASE1_ROOT":      filepath.Join(root, "installation"),
		"MATRIX_PHASE1_RELEASE_A": filepath.Join(root, "release-a"),
		"MATRIX_PHASE1_RELEASE_B": filepath.Join(root, "release-b"),
		"MATRIX_PHASE1_TRUST_KEY": filepath.Join(root, "release-trust.json"),
	} {
		t.Setenv(name, value)
	}
	if _, err := optionsFromEnvironment(); err == nil {
		t.Fatal("effectful lifecycle admitted without private security-mail configuration")
	}
	securityMail := filepath.Join(root, "security-mail.json")
	t.Setenv("MATRIX_PHASE1_SECURITY_MAIL_CONFIGURATION", securityMail)
	t.Setenv("MATRIX_PHASE1_EDGE", "http://127.0.0.1:49123")
	config, err := optionsFromEnvironment()
	if err != nil || config.securityMail != securityMail || config.edge != "http://127.0.0.1:49123" {
		t.Fatalf("effectful lifecycle options = %#v / %v", config, err)
	}
	t.Setenv("MATRIX_PHASE1_EDGE", "http://example.test:49123")
	if _, err := optionsFromEnvironment(); err == nil {
		t.Fatal("non-loopback lifecycle endpoint admitted")
	}
	t.Setenv("MATRIX_PHASE1_EDGE", "http://127.0.0.1:49123")

	t.Setenv("MATRIX_PHASE1_E2E_PHASE", "after-restart")
	t.Setenv("MATRIX_PHASE1_RELEASE_B", "")
	t.Setenv("MATRIX_PHASE1_SECURITY_MAIL_CONFIGURATION", "")
	if _, err := optionsFromEnvironment(); err != nil {
		t.Fatalf("read-only after-restart lifecycle requires removed private input: %v", err)
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
	edge := os.Getenv("MATRIX_PHASE1_EDGE")
	if edge == "" {
		edge = defaultEdgeEndpoint
	}
	endpoint, err := url.Parse(edge)
	if err != nil || endpoint.Scheme != "http" || endpoint.User != nil || endpoint.Path != "" ||
		endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return options{}, fail("command-input")
	}
	host, port, err := net.SplitHostPort(endpoint.Host)
	portNumber, portErr := strconv.ParseUint(port, 10, 16)
	if err != nil || host != "127.0.0.1" || portErr != nil || portNumber == 0 {
		return options{}, fail("command-input")
	}
	config := options{
		root:         os.Getenv("MATRIX_PHASE1_ROOT"),
		releaseA:     os.Getenv("MATRIX_PHASE1_RELEASE_A"),
		releaseB:     os.Getenv("MATRIX_PHASE1_RELEASE_B"),
		trustKey:     os.Getenv("MATRIX_PHASE1_TRUST_KEY"),
		securityMail: os.Getenv("MATRIX_PHASE1_SECURITY_MAIL_CONFIGURATION"),
		edge:         edge,
		afterStart:   phase == "after-restart",
	}
	for _, path := range []string{config.root, config.releaseA, config.trustKey} {
		if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return options{}, fail("command-input")
		}
	}
	if !config.afterStart {
		for _, path := range []string{config.releaseB, config.securityMail} {
			if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
				return options{}, fail("command-input")
			}
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
