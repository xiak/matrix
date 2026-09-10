package web

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

func TestHandlerServesUnifiedShellAndProductDeepLinks(t *testing.T) {
	for _, route := range []string{
		"/", "/paas/configuration", "/devops/code", "/devops/pipelines", "/devops/runs", "/unknown",
	} {
		request := httptest.NewRequest(http.MethodGet, route, nil)
		response := httptest.NewRecorder()
		NewHandler().ServeHTTP(response, request)
		if response.Code != http.StatusOK ||
			!strings.HasPrefix(response.Header().Get("Content-Type"), "text/html") ||
			response.Header().Get("Content-Security-Policy") == "" ||
			response.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("shell route %q response is incomplete: status=%d headers=%v", route, response.Code, response.Header())
		}
		body := response.Body.String()
		for _, required := range []string{
			"product-navigation", "login-form", "configuration-form", "devops-view",
			"source-connection-form", "pipeline-form", "run-lookup-form", "/assets/app.ca6de690.js",
		} {
			if !strings.Contains(body, required) {
				t.Fatalf("unified shell is missing %q", required)
			}
		}
		if strings.Contains(body, "https://") || strings.Contains(body, "http://") {
			t.Fatal("offline shell references an external asset")
		}
	}
}

func TestBrowserClientUsesOnlyPublicMatrixRoutes(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/assets/app.ca6de690.js", nil)
	response := httptest.NewRecorder()
	NewHandler().ServeHTTP(response, request)
	if response.Code != http.StatusOK ||
		!strings.Contains(response.Header().Get("Cache-Control"), "max-age=") {
		t.Fatalf("browser client response=%d headers=%v", response.Code, response.Header())
	}
	body := response.Body.String()
	for _, required := range []string{
		"/api/iam/v1/auth/login", "/api/platform/v1/installed-products", "/api/paas/v1/applications",
		"/api/devops/v1/projects", "/api/devops/v1/source-connections",
		"/api/devops/v1/repository-bindings", "/api/devops/v1/pipelines/",
		"/api/devops/v1/runs/",
	} {
		if !strings.Contains(body, required) {
			t.Fatalf("browser client lacks public route %q", required)
		}
	}
	for _, forbidden := range []string{
		"http://iam", "http://paas-api", "http://devops", "Matrix-Subject-Credential",
		"localStorage", "sessionStorage", "indexedDB", "document.cookie", "innerHTML",
		"body.detail", "body.title",
	} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("browser client contains forbidden internal or persistent authority surface %q", forbidden)
		}
	}
}

func TestDevOpsShellOwnsExactPhaseOneInformationArchitecture(t *testing.T) {
	body, err := content.ReadFile("assets/index.html")
	if err != nil {
		t.Fatal(err)
	}
	shell := string(body)
	for _, required := range []string{
		`data-devops-route="code"`,
		`data-devops-route="pipelines"`,
		`data-devops-route="runs"`,
		`aria-label="DevOps 功能"`,
		`id="source-credential-commands"`,
		`id="run-stage-rail"`,
		`data-stage="RECEIVE"`,
		`data-stage="FETCH"`,
		`data-stage="VERIFY"`,
		`data-stage="REPORT"`,
	} {
		if !strings.Contains(shell, required) {
			t.Fatalf("DevOps shell is missing %q", required)
		}
	}
	if count := strings.Count(shell, "data-devops-route="); count != 3 {
		t.Fatalf("DevOps local navigation has %d entries, want exactly Code/Pipelines/Runs", count)
	}
	for _, forbidden := range []string{
		`data-devops-route="artifacts"`,
		`data-devops-route="delivery"`,
		`type="file"`,
		`id="webhook-secret-value"`,
		`id="fetch-credential-value"`,
		`id="report-credential-value"`,
	} {
		if strings.Contains(shell, forbidden) {
			t.Fatalf("DevOps shell exposes deferred or secret-bearing surface %q", forbidden)
		}
	}
	if count := strings.Count(shell, `type="password"`); count != 1 {
		t.Fatalf("shell has %d password inputs, want only the IAM login input", count)
	}
}

func TestDevOpsBrowserCommandsAreGuardedMemoryOnlyAndProviderNeutral(t *testing.T) {
	body, err := content.ReadFile("assets/app.ca6de690.js")
	if err != nil {
		t.Fatal(err)
	}
	client := string(body)
	for _, required := range []string{
		"'If-Match'",
		"'Idempotency-Key'",
		"/recheck",
		"/activate",
		"/cancel",
		"/replay",
		"/logs?afterSequence=",
		"GO_1_26_OFFLINE_V1",
		"MATRIX_NATIVE_ISOLATED_V1",
		"sourceFreshnessMilliseconds",
		"performance.now()",
		"mx devops source-credential apply --root <installation>",
		"['WEBHOOK'",
		"['FETCH'",
		"['REPORT'",
		"--purpose ' + command[0]",
		"--from-file <private-file>",
	} {
		if !strings.Contains(client, required) {
			t.Fatalf("DevOps browser client is missing %q", required)
		}
	}
	start := strings.Index(client, "async function guardedCommand")
	end := strings.Index(client, "function requireDevOpsKind")
	if start < 0 || end <= start {
		t.Fatal("guarded command boundary is missing")
	}
	if strings.Contains(client[start:end], "body:") ||
		strings.Contains(client, "status.health =") ||
		strings.Contains(client, "status.reason =") {
		t.Fatal("browser can send a guarded command body or forge observed source health")
	}
}

func TestEmbeddedAssetNamesMatchContentDigests(t *testing.T) {
	index, err := content.ReadFile("assets/index.html")
	if err != nil {
		t.Fatal(err)
	}
	entries, err := content.ReadDir("assets")
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, "app.") || (!strings.HasSuffix(name, ".js") && !strings.HasSuffix(name, ".css")) {
			continue
		}
		parts := strings.Split(name, ".")
		if len(parts) != 3 || len(parts[1]) != 8 {
			t.Fatalf("asset name is not content-addressed: %s", name)
		}
		body, readErr := content.ReadFile("assets/" + name)
		if readErr != nil {
			t.Fatal(readErr)
		}
		digest := fmt.Sprintf("%x", sha256.Sum256(body))
		if parts[1] != digest[:8] {
			t.Fatalf("asset %s digest prefix=%s", name, digest[:8])
		}
		if !strings.Contains(string(index), "/assets/"+name) {
			t.Fatalf("index does not reference embedded asset %s", name)
		}
		found++
	}
	if found != 2 {
		t.Fatalf("embedded content-addressed assets=%d, want JavaScript and CSS", found)
	}
}

func TestUnknownAssetFailsClosed(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/assets/not-declared.js", nil)
	response := httptest.NewRecorder()
	NewHandler().ServeHTTP(response, request)
	if response.Code != http.StatusNotFound ||
		response.Header().Get("Content-Type") != "application/problem+json" {
		t.Fatalf("unknown asset status=%d headers=%v", response.Code, response.Header())
	}
}

func TestConfigurationDigestUsesPublicPaaSContract(t *testing.T) {
	values := map[string]string{"APP_ENV": "production", "LOG_LEVEL": "info"}
	payload, err := json.Marshal(map[string]any{"values": values})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/ui/v1/configuration-digest", strings.NewReader(string(payload)))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	NewHandler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("digest status=%d body=%s", response.Code, response.Body.String())
	}
	var result digestResponse
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.APIVersion != APIVersion || result.Kind != "ConfigurationDigest" ||
		result.ContentDigest != paasv1.ConfigurationValuesDigest(values) {
		t.Fatalf("unexpected digest response: %+v", result)
	}
}

func TestConfigurationDigestRejectsSecretsWithoutReflectingValues(t *testing.T) {
	secret := "must-never-be-reflected"
	request := httptest.NewRequest(http.MethodPost, "/ui/v1/configuration-digest",
		strings.NewReader(`{"values":{"DATABASE_PASSWORD":"`+secret+`"}}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	NewHandler().ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || strings.Contains(response.Body.String(), secret) {
		t.Fatalf("invalid configuration response leaked or succeeded: status=%d body=%s", response.Code, response.Body.String())
	}
}
