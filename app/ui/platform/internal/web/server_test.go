package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

func TestHandlerServesUnifiedShellAndProductDeepLinks(t *testing.T) {
	for _, route := range []string{"/", "/paas/configuration", "/devops/pipelines", "/unknown"} {
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
			"product-navigation", "login-form", "configuration-form", "/assets/app.17897b0f.js",
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
	request := httptest.NewRequest(http.MethodGet, "/assets/app.17897b0f.js", nil)
	response := httptest.NewRecorder()
	NewHandler().ServeHTTP(response, request)
	if response.Code != http.StatusOK ||
		!strings.Contains(response.Header().Get("Cache-Control"), "max-age=") {
		t.Fatalf("browser client response=%d headers=%v", response.Code, response.Header())
	}
	body := response.Body.String()
	for _, required := range []string{
		"/api/iam/v1/auth/login", "/api/platform/v1/installed-products", "/api/paas/v1/applications",
	} {
		if !strings.Contains(body, required) {
			t.Fatalf("browser client lacks public route %q", required)
		}
	}
	for _, forbidden := range []string{"http://iam", "http://paas-api", "Matrix-Subject-Credential", "localStorage", "sessionStorage"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("browser client contains forbidden internal or persistent authority surface %q", forbidden)
		}
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
