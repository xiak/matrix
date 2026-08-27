package nethttp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	nodev1 "github.com/xiak/matrix/api/adapter/node/v1"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/adapter/infrastructure/nodeexporter"
	nodehttps "github.com/xiak/matrix/app/adapter/node/https"
)

var nodeIdentity = nodev1.Identity{InstallationID: "installation-a", ExecutionTargetID: "target-a"}

const controllerID = "worker-a"

type sourceFunc func(context.Context) (paasv1.ExecutionTargetObservation, error)

func (fn sourceFunc) Current(ctx context.Context) (paasv1.ExecutionTargetObservation, error) {
	return fn(ctx)
}

func observedTarget() paasv1.ExecutionTargetObservation {
	capacity := paasv1.Capacity{CPUMillis: 2000, MemoryBytes: 8000, StorageBytes: 10000, WorkloadSlots: 2}
	now := time.Now().UTC().Truncate(time.Microsecond)
	return paasv1.ExecutionTargetObservation{
		ExecutionTargetID: nodeIdentity.ExecutionTargetID, IdentityFingerprint: "sha256:" + strings.Repeat("a", 64),
		Labels: map[string]string{"matrix-os": "linux"}, Capacity: capacity, Allocatable: capacity,
		Health: paasv1.ExecutionTargetHealthReady, SupportedIsolationGuarantees: []paasv1.IsolationGuarantee{paasv1.IsolationWorkload},
		ObservedAt: now,
		Usage: &paasv1.ExecutionTargetUsage{
			ObservedAt: now, ValidUntil: now.Add(nodev1.MaximumObservationAge),
			CPU:    paasv1.CPUUsage{State: paasv1.MeasurementUnavailable},
			Memory: paasv1.MemoryUsage{State: paasv1.MeasurementUnavailable}, FilesystemsState: paasv1.MeasurementUnavailable,
		},
	}
}

func observationCommand() paasv1.AdapterCommandEnvelope {
	return paasv1.AdapterCommandEnvelope{
		OperationID: "operation-a", CommandID: "command-a", Attempt: 1, Action: paasv1.AdapterObserveExecutionTarget,
		Scope: paasv1.ResourceScope{Kind: paasv1.AuthorityPlatform}, ExecutionTargetID: nodeIdentity.ExecutionTargetID,
		RequestDigest: "sha256:" + strings.Repeat("b", 64), BindingRef: "binding-a",
		Deadline: time.Now().UTC().Truncate(time.Microsecond).Add(5 * time.Second),
	}
}

func TestRealMTLSBindsBothPeersAndReturnsOnlyTheSelectedNode(t *testing.T) {
	authority := newAuthority(t)
	nodeURI, _ := nodev1.NodeURI(nodeIdentity)
	controllerURI, _ := nodev1.ControllerURI(nodeIdentity.InstallationID, controllerID)
	node := authority.issue(t, nodeURI, x509.ExtKeyUsageServerAuth, false)
	controller := authority.issue(t, controllerURI, x509.ExtKeyUsageClientAuth, false)
	var calls atomic.Int32
	server := startNode(t, node, sourceFunc(func(context.Context) (paasv1.ExecutionTargetObservation, error) {
		calls.Add(1)
		return observedTarget(), nil
	}), 8)
	client := newClient(t, server.URL, controller.credentials, nodeIdentity, controllerID)
	value, err := client.ObserveExecutionTarget(context.Background(), paasv1.ObserveExecutionTargetRequest{Command: observationCommand()})
	if err != nil || value.ExecutionTargetID != nodeIdentity.ExecutionTargetID || calls.Load() != 1 {
		t.Fatalf("authenticated observation failed: %#v, %v", value, err)
	}
	otherURI, _ := nodev1.ControllerURI(nodeIdentity.InstallationID, "worker-b")
	other := authority.issue(t, otherURI, x509.ExtKeyUsageClientAuth, false)
	wrongController := newClient(t, server.URL, other.credentials, nodeIdentity, "worker-b")
	if _, err := wrongController.ObserveExecutionTarget(context.Background(), paasv1.ObserveExecutionTargetRequest{Command: observationCommand()}); err == nil {
		t.Fatal("another controller identity passed mTLS")
	}
	wrongNodeIdentity := nodeIdentity
	wrongNodeIdentity.ExecutionTargetID = "target-b"
	wrongNode := newClient(t, server.URL, controller.credentials, wrongNodeIdentity, controllerID)
	command := observationCommand()
	command.ExecutionTargetID = wrongNodeIdentity.ExecutionTargetID
	if _, err := wrongNode.ObserveExecutionTarget(context.Background(), paasv1.ObserveExecutionTargetRequest{Command: command}); err == nil {
		t.Fatal("trusted CA alone admitted another node identity")
	}
	foreign := newAuthority(t).issue(t, controllerURI, x509.ExtKeyUsageClientAuth, false)
	expired := authority.issue(t, controllerURI, x509.ExtKeyUsageClientAuth, true)
	for name, certificate := range map[string]*tls.Certificate{"missing certificate": nil, "untrusted issuer": &foreign.pair, "expired certificate": &expired.pair} {
		t.Run(name, func(t *testing.T) {
			raw := authority.rawClient(certificate)
			defer raw.CloseIdleConnections()
			response, err := raw.Post(server.URL+nodev1.ObservationPath, "application/json", bytes.NewReader(requestBody(t, observationCommand())))
			if response != nil {
				response.Body.Close()
			}
			if err == nil {
				t.Fatal("unauthenticated peer reached the HTTP boundary")
			}
		})
	}
	if calls.Load() != 1 {
		t.Fatalf("rejected peer reached the observation source: %d calls", calls.Load())
	}
}

func TestAuthenticatedRequestsRejectInvalidInputBeforeReadingTheHost(t *testing.T) {
	authority := newAuthority(t)
	nodeURI, _ := nodev1.NodeURI(nodeIdentity)
	controllerURI, _ := nodev1.ControllerURI(nodeIdentity.InstallationID, controllerID)
	node := authority.issue(t, nodeURI, x509.ExtKeyUsageServerAuth, false)
	controller := authority.issue(t, controllerURI, x509.ExtKeyUsageClientAuth, false)
	var calls atomic.Int32
	server := startNode(t, node, sourceFunc(func(context.Context) (paasv1.ExecutionTargetObservation, error) {
		calls.Add(1)
		return observedTarget(), nil
	}), 8)
	raw := authority.rawClient(&controller.pair)
	defer raw.CloseIdleConnections()
	valid := string(requestBody(t, observationCommand()))
	expired := observationCommand()
	expired.Deadline = time.Now().UTC().Truncate(time.Microsecond).Add(-time.Second)
	distant := observationCommand()
	distant.Deadline = time.Now().UTC().Truncate(time.Microsecond).Add(time.Hour)
	for name, source := range map[string]string{
		"unknown":            strings.Replace(valid, `"command":`, `"shell":"/bin/sh","command":`, 1),
		"duplicate":          strings.Replace(valid, `"bindingRef":"binding-a"`, `"bindingRef":"binding-a","bindingRef":"binding-a"`, 1),
		"case alias":         strings.Replace(valid, `"bindingRef":`, `"BindingRef":`, 1),
		"wrong binding":      strings.Replace(valid, "binding-a", "binding-b", 1),
		"wrong installation": strings.Replace(valid, "installation-a", "installation-b", 1),
		"tenant identity":    strings.Replace(valid, `"kind":"PLATFORM"`, `"kind":"TENANT","tenantId":"tenant-a"`, 1),
		"expired":            string(requestBody(t, expired)), "distant deadline": string(requestBody(t, distant)),
		"oversize": valid + strings.Repeat(" ", nodev1.MaximumObservationRequestBytes),
		"deep":     `{"command":` + strings.Repeat(`[`, 64) + `0` + strings.Repeat(`]`, 64) + `}`,
		"trailing": valid + `{}`,
	} {
		t.Run(name, func(t *testing.T) {
			response, err := raw.Post(server.URL+nodev1.ObservationPath, "application/json", strings.NewReader(source))
			if err != nil {
				// A size rejection can close the connection before Windows has
				// finished writing the body. Refusal without source access is the
				// contract; successful delivery of an error body is not.
				if name == "oversize" {
					return
				}
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, _ := io.ReadAll(io.LimitReader(response.Body, 1024))
			if response.StatusCode < 400 || response.StatusCode >= 500 || strings.Contains(string(body), "/bin/sh") {
				t.Fatalf("invalid request not safely denied: %d %s", response.StatusCode, body)
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatalf("invalid request read the host: %d calls", calls.Load())
	}
	// A plaintext mount and forwarded certificate headers are not authentication.
	handler, err := New(sourceFunc(func(context.Context) (paasv1.ExecutionTargetObservation, error) {
		t.Fatal("plaintext request read the host")
		return paasv1.ExecutionTargetObservation{}, nil
	}), Config{Identity: nodeIdentity, ControllerID: controllerID, BindingRef: "binding-a"})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, nodev1.ObservationPath, strings.NewReader(valid))
	request.Header.Set("X-Forwarded-Client-Cert", controllerURI)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatal("plaintext handler admitted forwarded identity")
	}
}

func TestNodeBoundsConcurrencyAndNeverSerializesProviderErrors(t *testing.T) {
	authority := newAuthority(t)
	nodeURI, _ := nodev1.NodeURI(nodeIdentity)
	controllerURI, _ := nodev1.ControllerURI(nodeIdentity.InstallationID, controllerID)
	node := authority.issue(t, nodeURI, x509.ExtKeyUsageServerAuth, false)
	controller := authority.issue(t, controllerURI, x509.ExtKeyUsageClientAuth, false)
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	server := startNode(t, node, sourceFunc(func(ctx context.Context) (paasv1.ExecutionTargetObservation, error) {
		entered <- struct{}{}
		select {
		case <-ctx.Done():
			return paasv1.ExecutionTargetObservation{}, ctx.Err()
		case <-release:
			return paasv1.ExecutionTargetObservation{}, errors.New("provider secret=password /private/path")
		}
	}), 1)
	client := newClient(t, server.URL, controller.credentials, nodeIdentity, controllerID)
	first := make(chan error, 1)
	go func() {
		_, err := client.ObserveExecutionTarget(context.Background(), paasv1.ObserveExecutionTargetRequest{Command: observationCommand()})
		first <- err
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("first observation did not start")
	}
	_, err := client.ObserveExecutionTarget(context.Background(), paasv1.ObserveExecutionTargetRequest{Command: observationCommand()})
	var fault paasv1.AdapterFault
	if !errors.As(err, &fault) || fault.Normalized.Code != paasv1.ErrorRateLimited {
		t.Fatalf("concurrency limit error = %v", err)
	}
	close(release)
	select {
	case err := <-first:
		if !errors.As(err, &fault) || fault.Normalized.Code != paasv1.ErrorExecutionTargetUnavailable ||
			strings.Contains(err.Error(), "password") || strings.Contains(err.Error(), "/private/path") {
			t.Fatalf("native error escaped: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("observation did not finish")
	}
}

func TestClientRejectsUncorrelatedResponsesAndRedirects(t *testing.T) {
	authority := newAuthority(t)
	nodeURI, _ := nodev1.NodeURI(nodeIdentity)
	controllerURI, _ := nodev1.ControllerURI(nodeIdentity.InstallationID, controllerID)
	node := authority.issue(t, nodeURI, x509.ExtKeyUsageServerAuth, false)
	controller := authority.issue(t, controllerURI, x509.ExtKeyUsageClientAuth, false)
	for _, problem := range []string{"command", "identity", "fingerprint", "future", "stale", "missing usage", "future usage", "unknown", "oversize", "redirect"} {
		t.Run(problem, func(t *testing.T) {
			handler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				if problem == "redirect" {
					response.Header().Set("Location", "https://127.0.0.1:1/should-not-be-followed")
					response.WriteHeader(http.StatusTemporaryRedirect)
					return
				}
				command, err := nodev1.DecodeObservationRequest(request.Body)
				if err != nil {
					response.WriteHeader(http.StatusBadRequest)
					return
				}
				value := nodev1.ObservationResponse{
					APIVersion: nodev1.APIVersion, Kind: nodev1.ObservationResponseKind,
					Identity: nodeIdentity, CommandID: command.Command.CommandID, Observation: observedTarget(),
				}
				switch problem {
				case "command":
					value.CommandID = "other-command"
				case "identity":
					value.Identity.InstallationID = "installation-b"
				case "fingerprint":
					value.Observation.IdentityFingerprint = "sha256:" + strings.Repeat("c", 64)
				case "future":
					value.Observation.ObservedAt = time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond)
				case "stale":
					value.Observation.ObservedAt = time.Now().UTC().Add(-nodev1.MaximumObservationAge).Truncate(time.Microsecond)
				case "missing usage":
					value.Observation.Usage = nil
				case "future usage":
					value.Observation.Usage.ObservedAt = time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond)
					value.Observation.Usage.ValidUntil = value.Observation.Usage.ObservedAt.Add(time.Second)
				}
				body, _ := json.Marshal(value)
				if problem == "unknown" {
					body = append([]byte(`{"privateKey":"secret",`), body[1:]...)
				}
				if problem == "oversize" {
					body = append(body, bytes.Repeat([]byte(" "), nodev1.MaximumObservationResponseBytes)...)
				}
				response.Header().Set("Content-Type", "application/json")
				_, _ = response.Write(body)
			})
			server := startTLSServer(t, node, handler)
			client := newClient(t, server.URL, controller.credentials, nodeIdentity, controllerID)
			_, err := client.ObserveExecutionTarget(context.Background(), paasv1.ObserveExecutionTargetRequest{Command: observationCommand()})
			var fault paasv1.AdapterFault
			want := paasv1.ErrorAdapterRejected
			if problem == "stale" {
				want = paasv1.ErrorExecutionTargetUnavailable
			}
			if !errors.As(err, &fault) || fault.Normalized.Code != want || strings.Contains(err.Error(), "privateKey") {
				t.Fatalf("untrusted response accepted or leaked: %v", err)
			}
		})
	}
}

func TestCollectorTransportRequiresTheExactLocalCollectorAndNodeIdentities(t *testing.T) {
	authority := newAuthority(t)
	nodeURI, _ := nodev1.NodeURI(nodeIdentity)
	collectorURI, _ := nodev1.CollectorURI(nodeIdentity)
	controllerURI, _ := nodev1.ControllerURI(nodeIdentity.InstallationID, controllerID)
	node := authority.issue(t, nodeURI, x509.ExtKeyUsageClientAuth, false)
	controller := authority.issue(t, controllerURI, x509.ExtKeyUsageClientAuth, false)
	foreign := newAuthority(t).issue(t, collectorURI, x509.ExtKeyUsageServerAuth, false)
	for name, certificate := range map[string]issuedCertificate{
		"selected collector": authority.issue(t, collectorURI, x509.ExtKeyUsageServerAuth, false),
		"node role":          authority.issue(t, nodeURI, x509.ExtKeyUsageServerAuth, false),
		"untrusted":          foreign,
		"expired":            authority.issue(t, collectorURI, x509.ExtKeyUsageServerAuth, true),
	} {
		t.Run(name, func(t *testing.T) {
			var calls atomic.Int64
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", "text/plain; version=0.0.4")
				_, _ = w.Write([]byte("# TYPE node_scrape_collector_success gauge\nnode_scrape_collector_success{collector=\"cpu\"} 0\n"))
			}))
			server.TLS = &tls.Config{
				MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate.pair},
				ClientCAs: authority.roots, ClientAuth: tls.RequireAndVerifyClientCert,
				VerifyConnection: func(state tls.ConnectionState) error {
					if !nodev1.MatchesIdentity(state.PeerCertificates[0].URIs, nodeURI) {
						return errors.New("wrong node identity")
					}
					return nil
				},
			}
			server.Config.ErrorLog = log.New(io.Discard, "", 0)
			server.StartTLS()
			defer server.Close()
			collector, err := nodeexporter.New(nodeexporter.Config{Endpoint: server.URL, Identity: nodeIdentity, Credentials: node.credentials})
			if err != nil {
				t.Fatal(err)
			}
			defer collector.Close()
			_, err = collector.ObserveExecutionTargetUsage(context.Background())
			if name == "selected collector" {
				if err != nil || calls.Load() != 1 {
					t.Fatalf("authenticated collector rejected: %v", err)
				}
			} else if err != nodeexporter.ErrUnavailable || calls.Load() != 0 {
				t.Fatal("collector identity was not checked before HTTP")
			}
			if _, err := nodeexporter.New(nodeexporter.Config{Endpoint: server.URL, Identity: nodeIdentity, Credentials: controller.credentials}); err == nil {
				t.Fatal("controller identity can act as a node collector client")
			}
		})
	}
	for _, endpoint := range []string{"http://127.0.0.1:9100", "https://192.168.1.3:9100", "https://localhost:9100", "https://127.0.0.1:9100/metrics", "https://127.0.0.1:9100?target=other"} {
		if _, err := nodeexporter.New(nodeexporter.Config{Endpoint: endpoint, Identity: nodeIdentity, Credentials: node.credentials}); err == nil {
			t.Fatal("collector accepted a nonlocal or request-shaped endpoint")
		}
	}
}

func requestBody(t *testing.T, command paasv1.AdapterCommandEnvelope) []byte {
	t.Helper()
	value, err := json.Marshal(nodev1.ObservationRequest{APIVersion: nodev1.APIVersion, Kind: nodev1.ObservationRequestKind, Identity: nodeIdentity, Command: command})
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func startNode(t *testing.T, node issuedCertificate, source ObservationSource, concurrent int) *httptest.Server {
	t.Helper()
	handler, err := New(source, Config{Identity: nodeIdentity, ControllerID: controllerID, BindingRef: "binding-a", MaximumConcurrent: concurrent})
	if err != nil {
		t.Fatal(err)
	}
	return startTLSServer(t, node, handler)
}

func startTLSServer(t *testing.T, node issuedCertificate, handler http.Handler) *httptest.Server {
	t.Helper()
	security, err := nodehttps.ServerTLS(node.credentials, nodeIdentity, controllerID)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = security
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func newClient(t *testing.T, endpoint string, credentials nodehttps.Credentials, identity nodev1.Identity, controller string) *nodehttps.Client {
	t.Helper()
	client, err := nodehttps.New(nodehttps.Config{
		Endpoint: endpoint, Identity: identity, ControllerID: controller, BindingRef: "binding-a",
		ExpectedFingerprint: observedTarget().IdentityFingerprint, Credentials: credentials,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return client
}

type testAuthority struct {
	certificate *x509.Certificate
	key         ed25519.PrivateKey
	pem         []byte
	roots       *x509.CertPool
}
type issuedCertificate struct {
	credentials nodehttps.Credentials
	pair        tls.Certificate
}

func newAuthority(t *testing.T) testAuthority {
	t.Helper()
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "node test authority"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, public, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	return testAuthority{certificate: certificate, key: key, pem: encoded, roots: roots}
}

func (authority testAuthority) issue(t *testing.T, identity string, purpose x509.ExtKeyUsage, expired bool, additionalPurposes ...x509.ExtKeyUsage) issuedCertificate {
	t.Helper()
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uri, err := url.Parse(identity)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{
		SerialNumber: serial, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{purpose}, URIs: []*url.URL{uri},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	certificate.ExtKeyUsage = append(certificate.ExtKeyUsage, additionalPurposes...)
	if expired {
		certificate.NotAfter = time.Now().Add(-time.Minute)
	}
	der, err := x509.CreateCertificate(rand.Reader, certificate, authority.certificate, public, authority.key)
	if err != nil {
		t.Fatal(err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	defer clear(keyPEM)
	credentials, err := nodehttps.NewCredentials(encoded, keyPEM, authority.pem)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(encoded, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return issuedCertificate{credentials: credentials, pair: pair}
}

func (authority testAuthority) rawClient(certificate *tls.Certificate) *http.Client {
	security := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: authority.roots}
	if certificate != nil {
		security.Certificates = []tls.Certificate{*certificate}
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: security, DisableKeepAlives: true}, Timeout: 5 * time.Second}
}
