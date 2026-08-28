package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	nodev1 "github.com/xiak/matrix/api/adapter/node/v1"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
	nodehttps "github.com/xiak/matrix/app/adapter/node/https"
	"github.com/xiak/matrix/app/service/installation/nodeconfig"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/executionadmission"
)

func TestNodeConnectionsAreProtectedClosedInstallationInput(t *testing.T) {
	bindings, closeBindings, err := loadNodeBindings("", "installation-a")
	if err != nil || len(bindings) != 0 {
		t.Fatalf("empty optional node inventory = %v", err)
	}
	closeBindings()
	for _, document := range []string{
		`{"installationId":"other-installation","controllerId":"controller-a","certificateFile":"private-path","nodes":[]}`,
		`{"installationId":"installation-a","controllerId":"controller-a","nodes":[],"endpoint":"https://caller:443"}`,
		`{"installationId":"installation-a","installationId":"installation-b","nodes":[]}`,
		`{"installationId":"installation-a","nodes":[{"bindingRef":"binding-a","targetId":"node-a","endpoint":"https://node:443","identityFingerprint":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}],"certificateFile":"private-path"}`,
	} {
		path := filepath.Join(t.TempDir(), "nodes.json")
		if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
			t.Fatal(err)
		}
		_, closeBindings, err := loadNodeBindings(path, "installation-a")
		closeBindings()
		if err == nil || strings.Contains(err.Error(), "private-path") || strings.Contains(err.Error(), "https://") {
			t.Fatalf("bad node input exposed details or was accepted: %v", err)
		}
	}
	oversized := map[string]any{"apiVersion": nodeconfig.APIVersion, "kind": nodeconfig.ControllerKind, "installationId": "installation-a", "controllerId": "controller-a", "nodes": make([]nodeconfig.Connection, executionadmission.MaximumTargets+1)}
	document, err := json.Marshal(oversized)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "nodes.json")
	if err := os.WriteFile(path, document, 0o600); err != nil {
		t.Fatal(err)
	}
	_, closeBindings, err = loadNodeBindings(path, "installation-a")
	closeBindings()
	if err == nil {
		t.Fatal("unbounded node inventory accepted")
	}
}

func TestNodeCredentialReloadKeepsTheAdmittedMappingAndNeverFallsBack(t *testing.T) {
	root := t.TempDir()
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	authority := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "credential reload fixture"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, authority, authority, public, key)
	if err != nil {
		t.Fatal(err)
	}
	trust := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	trustFile := filepath.Join(root, "trust.pem")
	if err := os.WriteFile(trustFile, trust, 0o600); err != nil {
		t.Fatal(err)
	}
	identity := nodev1.Identity{InstallationID: "installation-a", ExecutionTargetID: "target-a"}
	nodeURI, _ := nodev1.NodeURI(identity)
	controllerURI, _ := nodev1.ControllerURI(identity.InstallationID, "controller-a")
	node := issueConnectionCertificate(t, root, "node", nodeURI, x509.ExtKeyUsageServerAuth, authority, key, trust)
	first := issueConnectionCertificate(t, root, "first", controllerURI, x509.ExtKeyUsageClientAuth, authority, key, trust)
	second := issueConnectionCertificate(t, root, "second", controllerURI, x509.ExtKeyUsageClientAuth, authority, key, trust)
	otherURI, _ := nodev1.ControllerURI(identity.InstallationID, "other-controller")
	other := issueConnectionCertificate(t, root, "other", otherURI, x509.ExtKeyUsageClientAuth, authority, key, trust)
	var calls atomic.Int32
	var peerSerial atomic.Value
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		peerSerial.Store(request.TLS.PeerCertificates[0].SerialNumber.String())
		calls.Add(1)
		response.WriteHeader(http.StatusServiceUnavailable)
	}))
	server.TLS, err = nodehttps.ServerTLS(node.credentials, identity, "controller-a")
	if err != nil {
		t.Fatal(err)
	}
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()
	read := func(path string) []byte {
		t.Helper()
		value, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	configuration := nodeconfig.ControllerConfiguration{APIVersion: nodeconfig.APIVersion, Kind: nodeconfig.ControllerKind, InstallationID: identity.InstallationID, ControllerID: "controller-a",
		Certificate: read(first.certificate), PrivateKey: read(first.key), Trust: trust,
		Nodes: []nodeconfig.Connection{{BindingRef: "binding-a", TargetID: identity.ExecutionTargetID, Endpoint: server.URL,
			IdentityFingerprint: "sha256:" + strings.Repeat("a", 64)}}}
	path := filepath.Join(root, "connections.json")
	write := func(value nodeconfig.ControllerConfiguration) {
		t.Helper()
		document, err := nodeconfig.EncodeController(value)
		if err != nil || os.WriteFile(path, document, 0o600) != nil {
			t.Fatal("write protected connection fixture")
		}
	}
	write(configuration)
	bindings, closeBindings, err := loadNodeBindings(path, identity.InstallationID)
	if err != nil || len(bindings) != 1 {
		t.Fatal("load protected binding", err)
	}
	defer closeBindings()
	observe := func(expectedSerial string) {
		t.Helper()
		before := calls.Load()
		_, err := bindings[0].Adapter.ObserveExecutionTarget(context.Background(), paasv1.ObserveExecutionTargetRequest{
			Command: paasv1.AdapterCommandEnvelope{OperationID: "operation-a", CommandID: "command-a", Attempt: 1,
				Action: paasv1.AdapterObserveExecutionTarget, Scope: paasv1.ResourceScope{Kind: paasv1.AuthorityPlatform},
				ExecutionTargetID: identity.ExecutionTargetID, BindingRef: "binding-a", RequestDigest: "sha256:" + strings.Repeat("b", 64),
				Deadline: time.Now().UTC().Truncate(time.Microsecond).Add(5 * time.Second)}})
		if err == nil {
			t.Fatal("fixture's explicit unavailable response was ignored")
		}
		if expectedSerial == "" {
			if calls.Load() != before {
				t.Fatal("invalid replacement used a cached credential or retargeted the connection")
			}
		} else if calls.Load() != before+1 || peerSerial.Load() != expectedSerial {
			t.Fatal("existing adapter did not use the current protected credential")
		}
	}
	observe(first.serial)
	configuration.Certificate, configuration.PrivateKey = read(second.certificate), read(second.key)
	write(configuration)
	observe(second.serial)
	for _, mode := range []string{"installation", "controller", "target", "binding", "endpoint", "fingerprint", "missing key", "wrong credential role", "untrusted signature", "malformed"} {
		t.Run(mode, func(t *testing.T) {
			changed := configuration
			changed.Nodes = append([]nodeconfig.Connection{}, configuration.Nodes...)
			switch mode {
			case "installation":
				changed.InstallationID = "other-installation"
			case "controller":
				changed.ControllerID = "other-controller"
			case "target":
				changed.Nodes[0].TargetID = "other-target"
			case "binding":
				changed.Nodes[0].BindingRef = "other-binding"
			case "endpoint":
				changed.Nodes[0].Endpoint = "https://127.0.0.1:1"
			case "fingerprint":
				changed.Nodes[0].IdentityFingerprint = "sha256:" + strings.Repeat("c", 64)
			case "missing key":
				changed.PrivateKey = []byte("not a private key")
			case "wrong credential role":
				changed.Certificate, changed.PrivateKey = read(other.certificate), read(other.key)
			case "untrusted signature":
				block, _ := pem.Decode(changed.Certificate)
				block.Bytes[len(block.Bytes)-1] ^= 1
				changed.Certificate = pem.EncodeToMemory(block)
			}
			write(changed)
			if mode == "missing key" || mode == "wrong credential role" || mode == "untrusted signature" {
				_, closeInvalid, err := loadNodeBindings(path, identity.InstallationID)
				closeInvalid()
				if err == nil {
					t.Fatal("invalid controller material was accepted at process startup")
				}
			}
			if mode == "malformed" && os.WriteFile(path, []byte(`{"unrecognized":true}`), 0o600) != nil {
				t.Fatal("write malformed fixture")
			}
			observe("")
			write(configuration)
			observe(second.serial)
		})
	}
}

type connectionCertificate struct {
	certificate, key, serial string
	credentials              nodehttps.Credentials
}

func issueConnectionCertificate(t *testing.T, root, name, identity string, purpose x509.ExtKeyUsage,
	authority *x509.Certificate, authorityKey ed25519.PrivateKey, trust []byte) connectionCertificate {
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
	certificate := &x509.Certificate{SerialNumber: serial, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{purpose}, URIs: []*url.URL{uri},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, certificate, authority, public, authorityKey)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})
	defer clear(keyPEM)
	value := connectionCertificate{certificate: filepath.Join(root, name+".pem"), key: filepath.Join(root, name+"-key.pem"), serial: serial.String()}
	if os.WriteFile(value.certificate, certificatePEM, 0o600) != nil || os.WriteFile(value.key, keyPEM, 0o600) != nil {
		t.Fatal("write private credential fixture")
	}
	value.credentials, err = nodehttps.NewCredentials(certificatePEM, keyPEM, trust)
	if err != nil {
		t.Fatal(err)
	}
	return value
}
