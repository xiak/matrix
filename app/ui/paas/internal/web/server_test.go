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
	for _, path := range []string{"/console/messages/", "/console/applications/", "/console/logs/", "/console/logs/search/", "/console/logs/topics/", "/console/logs/collection/", "/console/devops/pipelines/", "/console/devops/environments/", "/console/observability/health/", "/console/observability/alerts/", "/console/access/users/", "/console/access/create-user/", "/console/access/groups/", "/console/access/policies/", "/console/access/roles/", "/console/access/providers/", "/console/access/user-sso/", "/console/access/federations/", "/console/access/keys/", "/console/access/settings/", "/console/access/tenants/"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Matrix Control Plane") {
			t.Fatalf("service route %s: status=%d", path, response.Code)
		}
	}
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

func TestHandlerServesClientNavigationPrefetch(t *testing.T) {
	handler := NewHandler()
	// These are the URLs requested by Next's client router, including a dynamic
	// route segment. A successful HTML fallback would still break prefetching.
	for _, path := range []string{
		"/console/__next.console.__PAGE__.txt?_rsc=probe",
		"/console/access/__next.console.access.__PAGE__.txt?_rsc=probe",
		"/console/access/roles/__next.console.access.$d$view.__PAGE__.txt?_rsc=probe",
	} {
		t.Run(path, func(t *testing.T) {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
			if response.Code != http.StatusOK ||
				!strings.HasPrefix(response.Header().Get("Content-Type"), "text/plain") ||
				response.Body.Len() == 0 ||
				strings.HasPrefix(response.Body.String(), "<!DOCTYPE") {
				t.Fatalf("client navigation segment unavailable: status=%d headers=%v", response.Code, response.Header())
			}
		})
	}
}

func TestContentSecurityPolicyAllowsOnlyExactInlineScripts(t *testing.T) {
	response := httptest.NewRecorder()
	NewHandler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
	policy := response.Header().Get("Content-Security-Policy")
	if regexp.MustCompile(`(?i)<[^>]+\sstyle\s*=`).MatchString(response.Body.String()) {
		t.Fatal("static login contains a CSP-blocked inline style attribute")
	}
	if !strings.Contains(response.Body.String(), `data-theme="dark"`) {
		t.Fatal("static login is missing the default dark theme before hydration")
	}
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

func TestBrandAssetsRemainAvailableOffline(t *testing.T) {
	handler := NewHandler()
	for _, path := range []string{"/brand/matrix-horizontal-cyan.svg", "/brand/matrix-header-cyan.svg", "/brand/matrix-symbol-cyan.svg"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusOK || !strings.Contains(response.Header().Get("Content-Type"), "image/svg+xml") {
			t.Fatalf("offline brand asset %s: status=%d", path, response.Code)
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
