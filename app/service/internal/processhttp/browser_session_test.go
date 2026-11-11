package processhttp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestBrowserSessionCookieTransportKeepsAuthorityAndActorBinding(t *testing.T) {
	secret := "mx1." + strings.Repeat("a", 43)
	other := "mx1." + strings.Repeat("b", 43)
	const origin = "https://console.example.test"
	for _, test := range []struct {
		name, method, mode, origin, site, auth, cookie string
		status                                         int
		want                                           string
	}{
		{"read", "GET", "cookie", "", "same-origin", "MatrixSession " + BrowserCredentialReference(secret, false), secret, 204, "Bearer " + secret},
		{"write", "POST", "cookie", origin, "same-origin", "MatrixSession " + BrowserCredentialReference(secret, false), secret, 204, "Bearer " + secret},
		{"other tab changed account", "POST", "cookie", origin, "same-origin", "MatrixSession " + BrowserCredentialReference(secret, false), other, 401, ""},
		{"missing cookie", "GET", "cookie", "", "same-origin", "MatrixSession " + BrowserCredentialReference(secret, false), "", 401, ""},
		{"cookie alone", "GET", "", "", "", "", secret, 204, ""},
		{"native API client", "POST", "", "", "", "Bearer native-api-credential", secret, 204, "Bearer native-api-credential"},
		{"cross origin", "POST", "cookie", "https://attacker.example.test", "cross-site", "", secret, 403, ""},
		{"sibling subdomain", "GET", "cookie", "", "same-site", "", secret, 403, ""},
		{"missing write origin", "POST", "cookie", "", "same-origin", "", secret, 403, ""},
		{"opaque origin", "POST", "cookie", "null", "same-origin", "", secret, 403, ""},
		{"ambiguous carrier", "POST", "cookie", origin, "same-origin", "Bearer " + secret, secret, 401, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			handler, err := BrowserSessionHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Header.Get("Authorization") != test.want {
					t.Error("wrong authenticated carrier")
				}
				w.WriteHeader(http.StatusNoContent)
			}), origin)
			if err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest(test.method, "http://internal/v1/resource", nil)
			for key, value := range map[string]string{BrowserTransportHeader: test.mode, "Origin": test.origin, "Sec-Fetch-Site": test.site, "Authorization": test.auth} {
				if value != "" {
					r.Header.Set(key, value)
				}
			}
			if test.cookie != "" {
				r.AddCookie(&http.Cookie{Name: "__Host-matrix-session", Value: test.cookie})
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != test.status || (test.status != 204 && calls != 0) {
				t.Fatalf("status=%d calls=%d", w.Code, calls)
			}
			if strings.Contains(w.Body.String(), secret) || strings.Contains(w.Body.String(), other) {
				t.Fatal("credential in problem")
			}
		})
	}
}

func TestBrowserIssuanceUsesConfiguredHTTPSAndBindsRoleToSource(t *testing.T) {
	const origin = "https://console.example.test"
	source, role := "mx1."+strings.Repeat("a", 43), "mx1."+strings.Repeat("r", 43)
	expires := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	var reference string
	handler, err := BrowserSessionHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var issueErr error
		reference, issueErr = SetBrowserSession(w, r, origin, role, expires, true)
		if issueErr != nil {
			t.Fatal(issueErr)
		}
	}), origin)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "http://internal/v1/roles/test:assume", nil)
	r.Header.Set(BrowserTransportHeader, "cookie")
	r.Header.Set("Origin", origin)
	r.Header.Set("X-Forwarded-Proto", "http")
	r.AddCookie(&http.Cookie{Name: "__Host-matrix-session", Value: source})
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatal("missing role cookie")
	}
	cookie := cookies[0]
	if !cookie.HttpOnly || !cookie.Secure || cookie.Domain != "" || cookie.Path != "/" || cookie.SameSite != http.SameSiteLaxMode || !cookie.Expires.Equal(expires) || cookie.Name != "__Host-matrix-role-session" {
		t.Fatal("browser cookie confinement changed")
	}
	if reference != BrowserCredentialReference(role, true) || strings.Contains(reference, role) {
		t.Fatal("invalid public reference")
	}
	r.AddCookie(cookie)
	if got, ok := browserCookie(r, origin, true); !ok || got != role {
		t.Fatal("valid role source was rejected")
	}
	r.Header.Del("Cookie")
	r.AddCookie(cookie)
	r.AddCookie(&http.Cookie{Name: "__Host-matrix-session", Value: "mx1." + strings.Repeat("b", 43)})
	if _, ok := browserCookie(r, origin, true); ok {
		t.Fatal("old role survived a new source login")
	}
}

func TestBrowserSessionMatchesDefaultPortOriginSerialization(t *testing.T) {
	for _, test := range []struct {
		name, configured, presented string
		status                      int
	}{
		{"HTTPS default omitted", "https://console.example.test:443", "https://console.example.test", 204},
		{"HTTPS default explicit", "https://console.example.test:443", "https://console.example.test:443", 204},
		{"HTTP default omitted", "http://console.example.test:80", "http://console.example.test", 204},
		{"HTTPS non-default explicit", "https://console.example.test:8443", "https://console.example.test:8443", 204},
		{"HTTPS non-default omitted", "https://console.example.test:8443", "https://console.example.test", 403},
		{"HTTP non-default omitted", "http://console.example.test:8080", "http://console.example.test", 403},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			handler, err := BrowserSessionHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls++
				w.WriteHeader(http.StatusNoContent)
			}), test.configured)
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodPost, "http://internal/v1/auth/login", nil)
			request.Header.Set(BrowserTransportHeader, "cookie")
			request.Header.Set("Origin", test.presented)
			request.Header.Set("Sec-Fetch-Site", "same-origin")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("status=%d want=%d", response.Code, test.status)
			}
			wantCalls := 0
			if test.status == http.StatusNoContent {
				wantCalls = 1
			}
			if calls != wantCalls {
				t.Fatalf("calls=%d want=%d", calls, wantCalls)
			}
		})
	}
}

func TestBrowserTransportRejectsDuplicateCookiesAndDisabledConfiguration(t *testing.T) {
	secret := "mx1." + strings.Repeat("a", 43)
	for _, origin := range []string{"", "http://127.0.0.1:8080"} {
		handler, err := BrowserSessionHandler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("unbound request reached authority") }), origin)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("GET", "http://internal/resource", nil)
		r.Header.Set(BrowserTransportHeader, "cookie")
		r.Header.Set("Authorization", "MatrixSession "+BrowserCredentialReference(secret, false))
		for range 2 {
			r.AddCookie(&http.Cookie{Name: "matrix-session", Value: secret})
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != 401 && w.Code != 503 {
			t.Fatalf("unexpected status %d", w.Code)
		}
	}
}
