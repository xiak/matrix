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

func TestHandlerServesBoundedClientWorkspaceQueriesWithoutSelectingContent(t *testing.T) {
	handler := NewHandler()
	for _, target := range []string{
		"/console/access/users/?id=principal-member",
		"/console/access/groups/?id=group%2Fexample",
		"/console/access/policies/?id=policy-reviewer",
		"/console/access/roles/?id=role-reviewer",
		"/console/access/simulator/?id=principal-member",
		"/console/access/create-policy/?method=visual",
		"/console/access/create-policy/?method=json",
		"/console/access/create-policy/?method=tags",
		"/console/access/create-policy/?method=features",
		"/console/access/users/__next.console.access.$d$view.__PAGE__.txt?id=principal-member&_rsc=probe",
	} {
		t.Run(target, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, target, nil)
			withQuery, withoutQuery := httptest.NewRecorder(), httptest.NewRecorder()
			handler.ServeHTTP(withQuery, request)
			handler.ServeHTTP(withoutQuery, httptest.NewRequest(http.MethodGet, request.URL.Path, nil))
			if withQuery.Code != http.StatusOK || withQuery.Body.String() != withoutQuery.Body.String() ||
				withQuery.Header().Get("Content-Security-Policy") != withoutQuery.Header().Get("Content-Security-Policy") {
				t.Fatalf("workspace query changed static content: status=%d", withQuery.Code)
			}
		})
	}
}

func TestHandlerRejectsAuthoritySelectorsAndAmbiguousWorkspaceQueries(t *testing.T) {
	handler := NewHandler()
	for _, target := range []string{
		"/console/access/users/?accountId=other",
		"/console/access/users/?id=member&tenantId=other",
		"/console/access/users/?id=member&authorization=secret",
		"/console/access/users/?id=member&resourceVersion=1",
		"/console/access/users/?id=a&id=b",
		"/console/access/users/?id=",
		"/console/access/users/?id=%GG",
		"/console/access/users/?id=%FF",
		"/console/access/users/?id=member%0A",
		"/console/access/users/?method=tags",
		"/console/access/users/?_rsc=probe",
		"/console/access/create-policy/?method=unknown",
		"/console/access/create-policy/?id=member",
		"/console/access/users/?id=" + strings.Repeat("a", 257),
		"/_next/static/missing.js?id=member",
		"/console/access/users/?" + strings.Repeat("id=a&", 500),
	} {
		t.Run(target, func(t *testing.T) {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, target, nil))
			if response.Code != http.StatusBadRequest {
				t.Fatalf("ambiguous query accepted: status=%d", response.Code)
			}
		})
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
