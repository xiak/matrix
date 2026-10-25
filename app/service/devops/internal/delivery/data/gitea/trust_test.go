package gitea

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
)

type staticTrustResolver struct {
	roots  *x509.CertPool
	custom bool
	err    error
	scope  devopsv1.ResourceScope
	origin string
}

func (resolver staticTrustResolver) Resolve(
	_ context.Context,
	scope devopsv1.ResourceScope,
	endpointOrigin string,
) (*x509.CertPool, bool, error) {
	if resolver.scope != (devopsv1.ResourceScope{}) && resolver.scope != scope {
		return nil, false, errors.New("unexpected scope")
	}
	if resolver.origin != "" && resolver.origin != endpointOrigin {
		return nil, false, errors.New("unexpected origin")
	}
	return resolver.roots, resolver.custom, resolver.err
}

func TestProviderHTTPClientSelectsCustomOnlyOrSystemRoots(t *testing.T) {
	template := &http.Client{
		Transport: &http.Transport{
			Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		},
		Timeout: time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("redirect denied")
		},
	}
	scope := devopsv1.ResourceScope{TenantID: "tenant-one"}
	origin := "https://git.internal.example"
	roots := x509.NewCertPool()
	roots.AddCert(testTrustCertificate(t))

	custom, closeCustom, err := providerHTTPClient(
		context.Background(), template,
		staticTrustResolver{roots: roots, custom: true, scope: scope, origin: origin},
		scope, origin,
	)
	if err != nil {
		t.Fatalf("providerHTTPClient(custom) error = %v", err)
	}
	defer closeCustom()
	customTransport, ok := custom.Transport.(*http.Transport)
	if !ok || customTransport.TLSClientConfig.RootCAs != roots {
		t.Fatal("providerHTTPClient(custom) did not install the custom-only roots")
	}
	base := template.Transport.(*http.Transport)
	if base.TLSClientConfig.RootCAs != nil || customTransport == base {
		t.Fatal("providerHTTPClient(custom) mutated the shared transport")
	}

	system, closeSystem, err := providerHTTPClient(
		context.Background(), template, staticTrustResolver{}, scope, origin,
	)
	if err != nil {
		t.Fatalf("providerHTTPClient(system) error = %v", err)
	}
	defer closeSystem()
	systemTransport := system.Transport.(*http.Transport)
	if systemTransport.TLSClientConfig.RootCAs != nil {
		t.Fatal("providerHTTPClient(system) installed non-system roots")
	}

	if _, _, err := providerHTTPClient(
		context.Background(), template,
		staticTrustResolver{roots: roots, custom: false}, scope, origin,
	); err == nil {
		t.Fatal("providerHTTPClient() accepted an incoherent trust selection")
	}
}

func TestProductionConstructorsRequireTrustResolver(t *testing.T) {
	credentials := staticCredentialResolver{purpose: "FETCH", value: fetcherToken}
	if _, err := NewFetcher(credentials, nil); err == nil {
		t.Fatal("NewFetcher() accepted nil trust")
	}
	if _, err := NewCheckReporter(credentials, nil); err == nil {
		t.Fatal("NewCheckReporter() accepted nil trust")
	}
	if _, err := NewObserver(credentials, credentials, credentials, nil); err == nil {
		t.Fatal("NewObserver() accepted nil trust")
	}
}

func TestProviderHTTPClientEnforcesSelectedTrust(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusNoContent)
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()

	template := &http.Client{
		Transport: &http.Transport{
			Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		},
		Timeout: time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("redirect denied")
		},
	}
	scope := devopsv1.ResourceScope{TenantID: "tenant-one"}
	trustedRoots := x509.NewCertPool()
	trustedRoots.AddCert(server.Certificate())
	trusted, closeTrusted, err := providerHTTPClient(
		context.Background(), template,
		staticTrustResolver{roots: trustedRoots, custom: true}, scope, server.URL,
	)
	if err != nil {
		t.Fatalf("create trusted client: %v", err)
	}
	response, err := trusted.Get(server.URL)
	closeTrusted()
	if err != nil || response.StatusCode != http.StatusNoContent {
		closeResponse(response)
		t.Fatalf("custom-only trust request status=%v err=%v", response, err)
	}
	closeResponse(response)

	for name, resolver := range map[string]TrustResolver{
		"wrong custom root": staticTrustResolver{
			roots: func() *x509.CertPool {
				roots := x509.NewCertPool()
				roots.AddCert(testTrustCertificate(t))
				return roots
			}(),
			custom: true,
		},
		"system roots": staticTrustResolver{},
	} {
		t.Run(name, func(t *testing.T) {
			client, closeClient, err := providerHTTPClient(
				context.Background(), template, resolver, scope, server.URL,
			)
			if err != nil {
				t.Fatalf("create untrusted client: %v", err)
			}
			defer closeClient()
			response, err := client.Get(server.URL)
			closeResponse(response)
			if err == nil {
				t.Fatal("provider request succeeded without the selected endpoint root")
			}
		})
	}
}

func testTrustCertificate(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate test root key: %v", err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Matrix test root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		BasicConstraintsValid: true, IsCA: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create test root: %v", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse test root: %v", err)
	}
	return certificate
}
