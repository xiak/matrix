package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

func TestHandlerServesFunctionalConfigurationUI(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	response := httptest.NewRecorder()
	NewHandler().ServeHTTP(response, request)
	if response.Code != http.StatusOK ||
		!strings.HasPrefix(response.Header().Get("Content-Type"), "text/html") ||
		response.Header().Get("Content-Security-Policy") == "" {
		t.Fatalf("functional UI response is incomplete: status=%d headers=%v", response.Code, response.Header())
	}
	body := response.Body.String()
	for _, required := range []string{"login-form", "configuration-form", "/assets/app.js"} {
		if !strings.Contains(body, required) {
			t.Fatalf("functional UI is missing %q", required)
		}
	}
	if strings.Contains(body, "https://") || strings.Contains(body, "http://") {
		t.Fatal("offline UI references an external asset")
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
