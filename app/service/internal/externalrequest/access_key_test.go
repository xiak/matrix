package externalrequest

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
)

const testEdgeAssertion = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestBoundaryReconstructsExactExternalRequest(t *testing.T) {
	boundary, err := NewBoundary(
		"https://api.example.test:443", "/api/paas", "installation-one",
		iamv1.ProductPaaS, []byte(testEdgeAssertion),
	)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"id":"application-one"}`)
	request := signedTestRequest(t, http.MethodPost, "/v1/applications", body)
	request.Header.Set(HeaderExternalOrigin, "https://api.example.test:443")
	request.Header.Set(HeaderExternalRequestTarget, "/api/paas/v1/applications")
	request.Header.Set(HeaderExternalSourceIP, "2001:db8::1")
	request.Header.Set(HeaderEdgeAssertion, testEdgeAssertion)
	request.Header.Set("X-Real-IP", "2001:db8::1")
	request.Header.Set("X-Forwarded-For", "2001:db8::1")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "create-one")
	external, err := boundary.AccessKeyRequest(request, body)
	if err != nil {
		t.Fatal(err)
	}
	signed := external.SignedRequest
	if external.SourceIP != "2001:db8::1" {
		t.Fatalf("source IP = %q", external.SourceIP)
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
	boundary, err := NewBoundary(
		"https://api.example.test:443", "/api/audit", "installation-one",
		iamv1.ProductAudit, []byte(testEdgeAssertion),
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*http.Request)
	}{
		{"origin", func(r *http.Request) { r.Header.Set(HeaderExternalOrigin, "https://other.test:443") }},
		{"duplicate origin", func(r *http.Request) { r.Header.Add(HeaderExternalOrigin, "https://api.example.test:443") }},
		{"missing source IP", func(r *http.Request) { r.Header.Del(HeaderExternalSourceIP) }},
		{"duplicate source IP", func(r *http.Request) { r.Header.Add(HeaderExternalSourceIP, "192.0.2.10") }},
		{"missing edge assertion", func(r *http.Request) { r.Header.Del(HeaderEdgeAssertion) }},
		{"wrong edge assertion", func(r *http.Request) { r.Header.Set(HeaderEdgeAssertion, strings.Repeat("f", 64)) }},
		{"duplicate edge assertion", func(r *http.Request) { r.Header.Add(HeaderEdgeAssertion, testEdgeAssertion) }},
		{"noncanonical source IP", func(r *http.Request) { r.Header.Set(HeaderExternalSourceIP, "::ffff:192.0.2.10") }},
		{"invalid source IP", func(r *http.Request) { r.Header.Set(HeaderExternalSourceIP, "not-an-address") }},
		{"missing real IP", func(r *http.Request) { r.Header.Del("X-Real-IP") }},
		{"duplicate real IP", func(r *http.Request) { r.Header.Add("X-Real-IP", "192.0.2.10") }},
		{"missing forwarded for", func(r *http.Request) { r.Header.Del("X-Forwarded-For") }},
		{"duplicate forwarded for", func(r *http.Request) { r.Header.Add("X-Forwarded-For", "192.0.2.10") }},
		{"target prefix", func(r *http.Request) { r.Header.Set(HeaderExternalRequestTarget, "/api/paas/v1/records:query") }},
		{"target mapping", func(r *http.Request) { r.Header.Set(HeaderExternalRequestTarget, "/api/audit/v1/integrity:verify") }},
		{"empty query", func(r *http.Request) { r.Header.Set(HeaderExternalRequestTarget, "/api/audit/v1/records:query?") }},
		{"cookie", func(r *http.Request) { r.Header.Set("Cookie", "session=ambient") }},
		{"duplicate authorization", func(r *http.Request) { r.Header.Add("Authorization", r.Header.Get("Authorization")) }},
		{"media parameters", func(r *http.Request) { r.Header.Set("Content-Type", "application/json; charset=utf-8") }},
		{"unsigned method override", func(r *http.Request) { r.Header.Set("X-HTTP-Method-Override", "GET") }},
		{"forwarded source", func(r *http.Request) { r.Header.Set("Forwarded", "for=192.0.2.11") }},
		{"forwarded for mismatch", func(r *http.Request) { r.Header.Set("X-Forwarded-For", "192.0.2.11") }},
		{"real IP mismatch", func(r *http.Request) { r.Header.Set("X-Real-IP", "192.0.2.11") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := []byte(`{"pageSize":10}`)
			request := signedTestRequest(t, http.MethodPost, "/v1/records:query", body)
			request.Header.Set(HeaderExternalOrigin, "https://api.example.test:443")
			request.Header.Set(HeaderExternalRequestTarget, "/api/audit/v1/records:query")
			request.Header.Set(HeaderExternalSourceIP, "192.0.2.10")
			request.Header.Set(HeaderEdgeAssertion, testEdgeAssertion)
			request.Header.Set("X-Real-IP", "192.0.2.10")
			request.Header.Set("X-Forwarded-For", "192.0.2.10")
			request.Header.Set("Content-Type", "application/json")
			test.mutate(request)
			if _, err := boundary.AccessKeyRequest(request, body); err == nil {
				t.Fatal("ambiguous edge request was accepted")
			}
		})
	}
}

func TestBoundaryRequiresCanonicalExplicitOrigin(t *testing.T) {
	for _, origin := range []string{"", "https://api.example.test", "HTTPS://api.example.test:443", "https://API.example.test:443", "https://user@api.example.test:443", "https://api.example.test:443/"} {
		if _, err := NewBoundary(
			origin, "/api/paas", "installation-one", iamv1.ProductPaaS, []byte(testEdgeAssertion),
		); err == nil {
			t.Fatalf("origin %q was accepted", origin)
		}
	}
	for _, assertion := range []string{
		"", strings.Repeat("a", 63), strings.Repeat("a", 65), strings.Repeat("A", 64),
		strings.Repeat("g", 64), strings.Repeat("a", 63) + "\n",
	} {
		if _, err := NewBoundary(
			"https://api.example.test:443", "/api/paas", "installation-one",
			iamv1.ProductPaaS, []byte(assertion),
		); err == nil {
			t.Fatalf("edge assertion %q was accepted", assertion)
		}
	}
}

func signedTestRequest(t *testing.T, method, target string, body []byte) *http.Request {
	t.Helper()
	nonce, _ := iamv1.NewSecret(strings.Repeat("A", 22))
	signature, _ := iamv1.NewSecret(strings.Repeat("A", 43))
	audience := iamv1.ProductAudit
	if strings.HasPrefix(target, "/v1/applications") {
		audience = iamv1.ProductPaaS
	}
	header, err := iamv1.EncodeAccessKeyAuthorization(iamv1.AccessKeySignatureParameters{
		AccessKeyID: "key-one", InstallationID: "installation-one", Audience: audience,
		SignedAt: 1800000000, Nonce: nonce,
	}, signature)
	if err != nil {
		t.Fatal(err)
	}
	plain := header.CopyBytes()
	request := httptest.NewRequest(method, "http://internal.invalid"+target, bytes.NewReader(body))
	request.Header.Set("Authorization", string(plain))
	clear(plain)
	return request
}
