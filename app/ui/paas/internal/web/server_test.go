package web

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func TestHandlerServesNextControlPlane(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	response := httptest.NewRecorder()
	NewHandler().ServeHTTP(response, request)
	if response.Code != http.StatusOK ||
		!strings.HasPrefix(response.Header().Get("Content-Type"), "text/html") ||
		response.Header().Get("Content-Security-Policy") == "" {
		t.Fatalf("control-plane response is incomplete: status=%d headers=%v", response.Code, response.Header())
	}
	body := response.Body.String()
	for _, required := range []string{"login-form", "Matrix Control Plane", "/_next/static/"} {
		if !strings.Contains(body, required) {
			t.Fatalf("control plane is missing %q", required)
		}
	}
	forbiddenRemoteAsset := regexp.MustCompile(`(?i)(?:src|href)=["']https?://`)
	if forbiddenRemoteAsset.MatchString(body) {
		t.Fatal("offline control plane references an external asset")
	}
}

func TestHandlerServesNestedRouteAndHashedAsset(t *testing.T) {
	handler := NewHandler()
	page := httptest.NewRecorder()
	handler.ServeHTTP(page, httptest.NewRequest(http.MethodGet, "/console/quotas/", nil))
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), "Matrix Control Plane") {
		t.Fatalf("nested Next route status=%d body=%s", page.Code, page.Body.String())
	}
	assetPattern := regexp.MustCompile(`(?:src|href)="(/_next/static/[^"]+\.(?:js|css))"`)
	match := assetPattern.FindStringSubmatch(page.Body.String())
	if len(match) != 2 {
		t.Fatal("nested route does not reference a hashed static asset")
	}
	asset := httptest.NewRecorder()
	handler.ServeHTTP(asset, httptest.NewRequest(http.MethodGet, match[1], nil))
	if asset.Code != http.StatusOK ||
		asset.Header().Get("Cache-Control") != "public, max-age=31536000, immutable" {
		t.Fatalf("hashed asset response status=%d headers=%v", asset.Code, asset.Header())
	}
}

func TestContentSecurityPolicyAllowsOnlyExactInlineScripts(t *testing.T) {
	response := httptest.NewRecorder()
	NewHandler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
	policy := response.Header().Get("Content-Security-Policy")
	if strings.Contains(policy, "'unsafe-inline'") || strings.Contains(policy, "'unsafe-eval'") {
		t.Fatalf("control-plane CSP is unsafe: %s", policy)
	}
	for _, match := range inlineScript.FindAllStringSubmatch(response.Body.String(), -1) {
		if len(match) != 2 || match[1] == "" {
			continue
		}
		digest := sha256.Sum256([]byte(match[1]))
		hash := "'sha256-" + base64.StdEncoding.EncodeToString(digest[:]) + "'"
		if !strings.Contains(policy, hash) {
			t.Fatalf("CSP does not allow an exact embedded Next script: %s", hash)
		}
	}
}

func TestHandlerRejectsAmbiguousStaticRequestAndUnknownAsset(t *testing.T) {
	handler := NewHandler()
	query := httptest.NewRecorder()
	handler.ServeHTTP(query, httptest.NewRequest(http.MethodGet, "/?unexpected=true", nil))
	if query.Code != http.StatusBadRequest {
		t.Fatalf("unexpected query status=%d", query.Code)
	}
	missing := httptest.NewRecorder()
	handler.ServeHTTP(missing, httptest.NewRequest(http.MethodGet, "/_next/static/missing.js", nil))
	if missing.Code != http.StatusNotFound || !strings.HasPrefix(missing.Header().Get("Content-Type"), "text/plain") {
		t.Fatalf("missing asset status=%d headers=%v", missing.Code, missing.Header())
	}
}
