package web

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"path"
	"regexp"
	"strings"
	"testing"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

func TestStaticPagesAndRouterSegments(t *testing.T) {
	handler := NewHandler()
	for _, route := range []string{"/", "/account", "/paas/applications/", "/paas/configuration", "/paas/deployments", "/paas/operations", "/devops/code", "/devops/pipelines", "/devops/runs/"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, route, nil))
		if response.Code != 200 || !strings.HasPrefix(response.Header().Get("Content-Type"), "text/html") || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("page %s status=%d headers=%v", route, response.Code, response.Header())
		}
		if !strings.Contains(response.Body.String(), "Matrix Cloud") {
			t.Fatal("page has no accessible product identity")
		}
	}
	assets, _ := fs.Sub(content, "assets")
	count := 0
	err := fs.WalkDir(assets, ".", func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		extension := path.Ext(name)
		if extension != ".js" && extension != ".css" && extension != ".txt" && extension != ".svg" {
			return nil
		}
		target := "/" + name
		if extension == ".txt" {
			target += "?_rsc=router-test"
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, target, nil))
		if response.Code != 200 || response.Body.Len() == 0 {
			t.Fatalf("asset %s status=%d", name, response.Code)
		}
		if extension == ".css" && !strings.HasPrefix(response.Header().Get("Content-Type"), "text/css") {
			t.Fatalf("CSS MIME for %s", name)
		}
		if strings.HasPrefix(name, "_next/static/") && !strings.Contains(response.Header().Get("Cache-Control"), "immutable") {
			t.Fatalf("static asset %s not cached", name)
		}
		count++
		return nil
	})
	if err != nil || count < 1 {
		t.Fatalf("export inventory: %v, assets=%d", err, count)
	}
}

func TestStaticCSPAllowsOnlyExactBundledScripts(t *testing.T) {
	handler := NewHandler()
	assets, _ := fs.Sub(content, "assets")
	ref := regexp.MustCompile(`(?:src|href)="(/[^"]+)"`)
	err := fs.WalkDir(assets, ".", func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || path.Ext(name) != ".html" {
			return nil
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/"+name, nil))
		policy := response.Header().Get("Content-Security-Policy")
		for _, forbidden := range []string{"unsafe-inline", "unsafe-eval", "https:", "http:"} {
			if strings.Contains(policy, forbidden) {
				t.Fatalf("unsafe CSP: %s", forbidden)
			}
		}
		if !strings.Contains(policy, "style-src 'self'") || !strings.Contains(policy, "frame-ancestors 'none'") || !strings.Contains(policy, "connect-src 'self'") {
			t.Fatal("CSP lost its boundary")
		}
		page := response.Body.Bytes()
		for _, match := range inlineScript.FindAllSubmatch(page, -1) {
			if len(match[1]) == 0 {
				continue
			}
			hash := sha256.Sum256(match[1])
			if !strings.Contains(policy, "'sha256-"+base64.StdEncoding.EncodeToString(hash[:])+"'") {
				t.Fatalf("page %s has blocked hydration", name)
			}
		}
		for _, match := range ref.FindAllSubmatch(page, -1) {
			target := string(match[1])
			if strings.HasPrefix(target, "/_next/") || strings.HasPrefix(target, "/brand/") || strings.HasSuffix(target, ".svg") {
				target = strings.Split(target, "?")[0]
				if _, err := fs.ReadFile(assets, strings.TrimPrefix(target, "/")); err != nil {
					t.Fatalf("page %s has missing asset %s", name, target)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestUIRequestAndUnknownRouteBoundaries(t *testing.T) {
	handler := NewHandler()
	for _, route := range []string{"/unknown", "/console/access", "/api/iam/v1/auth/login", "/_next/static/missing.js"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, route, nil))
		if response.Code != 404 {
			t.Fatalf("unknown route %s status=%d", route, response.Code)
		}
	}
	for _, route := range []string{"/?tenant=other", "/ready?extra=1", "/index.txt?_rsc=a&_rsc=b", "/index.txt?_rsc=", "/index.txt?_rsc=%zz"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, route, nil))
		if response.Code != 400 {
			t.Fatalf("invalid query %s status=%d", route, response.Code)
		}
	}
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/", strings.NewReader("input"))
	handler.ServeHTTP(response, request)
	if response.Code != 400 {
		t.Fatal("GET body accepted")
	}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/ready", nil))
	var ready readiness
	if json.Unmarshal(response.Body.Bytes(), &ready) != nil || ready.Kind != "MatrixUIReadiness" || ready.APIVersion != APIVersion || ready.State != "READY" {
		t.Fatal("release readiness contract changed")
	}
	for name, value := range map[string]string{"X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "Cross-Origin-Resource-Policy": "same-origin", "Permissions-Policy": "camera=(), microphone=(), geolocation=()"} {
		if response.Header().Get(name) != value {
			t.Fatalf("security header %s changed", name)
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
