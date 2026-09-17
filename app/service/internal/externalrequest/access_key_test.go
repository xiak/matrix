package externalrequest

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
)

func TestBoundaryReconstructsExactExternalRequest(t *testing.T) {
	boundary, err := NewBoundary("https://api.example.test:443", "/api/paas", "installation-one", iamv1.ProductPaaS)
	if err != nil {
		t.Fatal(err)
	}
	request := signedTestRequest(t, http.MethodPost, "/v1/applications", []byte(`{"id":"application-one"}`))
	request.Header.Set(HeaderExternalOrigin, "https://api.example.test:443")
	request.Header.Set(HeaderExternalRequestTarget, "/api/paas/v1/applications")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "create-one")
	signed, err := boundary.SignedRequest(request, []byte(`{"id":"application-one"}`))
	if err != nil {
		t.Fatal(err)
	}
	if signed.Parameters.Audience != iamv1.ProductPaaS || signed.Parameters.InstallationID != "installation-one" ||
		signed.HTTP.Method != http.MethodPost || signed.HTTP.Scheme != "https" || signed.HTTP.Authority != "api.example.test:443" ||
		signed.HTTP.EscapedPath != "/api/paas/v1/applications" || signed.HTTP.RawQuery != "" ||
		signed.HTTP.ContentType != "application/json" || signed.HTTP.IdempotencyKey != "create-one" || signed.HTTP.IfMatch != "" ||
		signed.HTTP.BodyDigest != "sha256:3dfa2cf1abe65d5e9e5dbe8190a9b6e9f72ae1fbe936680bec29b7bae9d63f1a" {
		t.Fatalf("signed request = %#v", signed.HTTP)
	}
}

func TestBoundaryRejectsAmbiguousOrForgedEdgeFacts(t *testing.T) {
	boundary, err := NewBoundary("https://api.example.test:443", "/api/audit", "installation-one", iamv1.ProductAudit)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*http.Request)
	}{
		{"origin", func(r *http.Request) { r.Header.Set(HeaderExternalOrigin, "https://other.test:443") }},
		{"duplicate origin", func(r *http.Request) { r.Header.Add(HeaderExternalOrigin, "https://api.example.test:443") }},
		{"target prefix", func(r *http.Request) { r.Header.Set(HeaderExternalRequestTarget, "/api/paas/v1/records:query") }},
		{"target mapping", func(r *http.Request) { r.Header.Set(HeaderExternalRequestTarget, "/api/audit/v1/integrity:verify") }},
		{"empty query", func(r *http.Request) { r.Header.Set(HeaderExternalRequestTarget, "/api/audit/v1/records:query?") }},
		{"cookie", func(r *http.Request) { r.Header.Set("Cookie", "session=ambient") }},
		{"duplicate authorization", func(r *http.Request) { r.Header.Add("Authorization", r.Header.Get("Authorization")) }},
		{"media parameters", func(r *http.Request) { r.Header.Set("Content-Type", "application/json; charset=utf-8") }},
		{"unsigned method override", func(r *http.Request) { r.Header.Set("X-HTTP-Method-Override", "GET") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := []byte(`{"pageSize":10}`)
			request := signedTestRequest(t, http.MethodPost, "/v1/records:query", body)
			request.Header.Set(HeaderExternalOrigin, "https://api.example.test:443")
			request.Header.Set(HeaderExternalRequestTarget, "/api/audit/v1/records:query")
			request.Header.Set("Content-Type", "application/json")
			test.mutate(request)
			if _, err := boundary.SignedRequest(request, body); err == nil {
				t.Fatal("ambiguous edge request was accepted")
			}
		})
	}
}

func TestBoundaryRequiresCanonicalExplicitOrigin(t *testing.T) {
	for _, origin := range []string{"", "https://api.example.test", "HTTPS://api.example.test:443", "https://API.example.test:443", "https://user@api.example.test:443", "https://api.example.test:443/"} {
		if _, err := NewBoundary(origin, "/api/paas", "installation-one", iamv1.ProductPaaS); err == nil {
			t.Fatalf("origin %q was accepted", origin)
		}
	}
}

func signedTestRequest(t *testing.T, method, target string, body []byte) *http.Request {
	t.Helper()
	nonce, _ := iamv1.NewSecret(strings.Repeat("A", 22))
	signature, _ := iamv1.NewSecret(strings.Repeat("A", 43))
	header, err := iamv1.EncodeAccessKeyAuthorization(iamv1.AccessKeySignatureParameters{
		AccessKeyID: "key-one", InstallationID: "installation-one", Audience: iamv1.ProductAudit,
		SignedAt: 1800000000, Nonce: nonce,
	}, signature)
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(target, "/v1/applications") {
		header, err = iamv1.EncodeAccessKeyAuthorization(iamv1.AccessKeySignatureParameters{
			AccessKeyID: "key-one", InstallationID: "installation-one", Audience: iamv1.ProductPaaS,
			SignedAt: 1800000000, Nonce: nonce,
		}, signature)
		if err != nil {
			t.Fatal(err)
		}
	}
	plain := header.CopyBytes()
	request := httptest.NewRequest(method, "http://internal.invalid"+target, bytes.NewReader(body))
	request.Header.Set("Authorization", string(plain))
	clear(plain)
	return request
}
