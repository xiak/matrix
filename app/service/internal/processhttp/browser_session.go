package processhttp

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Browser sessions are a transport for the existing IAM credentials. The
// adapter never authenticates a principal or caches an authorization decision.
const BrowserTransportHeader = "Matrix-Browser-Transport"

type browserSessionContext struct{}

// BrowserSessionHandler requires an explicit browser transport and binds each
// authenticated request to the credential reference observed by that page.
// Replacing a shared cookie in another tab cannot silently switch its actor.
func BrowserSessionHandler(next http.Handler, origin string) (http.Handler, error) {
	if next == nil {
		return nil, errors.New("browser session handler is required")
	}
	browserOrigin := origin
	if origin != "" {
		parsed, err := url.Parse(origin)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" ||
			parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.String() != origin {
			return nil, errors.New("browser session origin is invalid")
		}
		// URL origins used by the signed API boundary keep an explicit port,
		// while browsers omit a scheme's default port from the Origin header.
		// Accept only that one browser serialization of the sealed origin.
		port := parsed.Port()
		if (parsed.Scheme == "https" && port == "443") || (parsed.Scheme == "http" && port == "80") {
			browserOrigin = parsed.Scheme + "://" + strings.TrimSuffix(parsed.Host, ":"+port)
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		modes := r.Header.Values(BrowserTransportHeader)
		if len(modes) == 0 {
			// Cookies alone never authenticate API clients or cross-origin forms.
			next.ServeHTTP(w, r)
			return
		}
		if origin == "" {
			browserSessionProblem(w, http.StatusServiceUnavailable, "iam.browser-session.unavailable")
			return
		}
		origins, sites := r.Header.Values("Origin"), r.Header.Values("Sec-Fetch-Site")
		if len(modes) != 1 || modes[0] != "cookie" || len(origins) > 1 || len(sites) > 1 ||
			(len(origins) == 1 && origins[0] != origin && origins[0] != browserOrigin) ||
			(len(sites) == 1 && sites[0] != "same-origin") ||
			(r.Method != http.MethodGet && r.Method != http.MethodHead && len(origins) != 1) {
			browserSessionProblem(w, http.StatusForbidden, "iam.browser-session.origin-rejected")
			return
		}
		request := r.Clone(context.WithValue(r.Context(), browserSessionContext{}, true))
		auth := r.Header.Values("Authorization")
		if len(auth) != 0 {
			if len(auth) != 1 || !strings.HasPrefix(auth[0], "MatrixSession ") {
				browserSessionProblem(w, http.StatusUnauthorized, "iam.browser-session.invalid")
				return
			}
			reference := strings.TrimPrefix(auth[0], "MatrixSession ")
			role := strings.HasPrefix(reference, "mxb1.r.")
			credential, ok := browserCookie(r, origin, role)
			if !ok || subtle.ConstantTimeCompare([]byte(reference), []byte(BrowserCredentialReference(credential, role))) != 1 {
				browserSessionProblem(w, http.StatusUnauthorized, "iam.browser-session.changed")
				return
			}
			request.Header.Set("Authorization", "Bearer "+credential)
		}
		next.ServeHTTP(w, request)
	}), nil
}

func IsBrowserSessionRequest(r *http.Request) bool {
	value, _ := r.Context().Value(browserSessionContext{}).(bool)
	return value
}

func BrowserCredentialReference(credential string, role bool) string {
	digest := sha256.Sum256([]byte("matrix.browser-credential.v1\x00" + credential))
	kind := "s"
	if role {
		kind = "r"
	}
	return "mxb1." + kind + "." + hex.EncodeToString(digest[:])
}

// BrowserSessionCredential is used only by IAM's current-session read. Other
// requests must present a reference and use the ordinary credential PEP.
func BrowserSessionCredential(r *http.Request, origin string) (string, bool) {
	if !IsBrowserSessionRequest(r) {
		return "", false
	}
	return browserCookie(r, origin, false)
}

// SetBrowserSession keeps the reusable secret out of JSON and JavaScript.
// Role cookies also bind to their source browser session, preventing an old
// role from surviving a different user login in the same browser.
func SetBrowserSession(w http.ResponseWriter, r *http.Request, origin, credential string, expires time.Time, role bool) (string, error) {
	if !IsBrowserSessionRequest(r) || !validBrowserSecret(credential) {
		return "", errors.New("browser session issuance is invalid")
	}
	value := credential
	if role {
		source, ok := browserCookie(r, origin, false)
		if !ok {
			return "", errors.New("browser role source is unavailable")
		}
		value = BrowserCredentialReference(source, false) + ":" + credential
	}
	http.SetCookie(w, &http.Cookie{Name: browserCookieName(origin, role), Value: value, Path: "/",
		HttpOnly: true, Secure: strings.HasPrefix(origin, "https://"), SameSite: http.SameSiteLaxMode, Expires: expires.UTC()})
	return BrowserCredentialReference(credential, role), nil
}

func browserCookieName(origin string, role bool) string {
	name := "matrix-session"
	if role {
		name = "matrix-role-session"
	}
	if strings.HasPrefix(origin, "https://") {
		name = "__Host-" + name
	}
	return name
}

func browserCookie(r *http.Request, origin string, role bool) (string, bool) {
	cookies := r.CookiesNamed(browserCookieName(origin, role))
	if len(cookies) != 1 {
		return "", false
	}
	value := cookies[0].Value
	if role {
		source, ok := browserCookie(r, origin, false)
		binding, secret, found := strings.Cut(value, ":")
		if !ok || !found || subtle.ConstantTimeCompare([]byte(binding), []byte(BrowserCredentialReference(source, false))) != 1 {
			return "", false
		}
		value = secret
	}
	return value, validBrowserSecret(value)
}

func validBrowserSecret(value string) bool {
	if len(value) != 47 || !strings.HasPrefix(value, "mx1.") {
		return false
	}
	for _, c := range value[4:] {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func browserSessionProblem(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"status": status, "code": code})
}
