package enrollmenthttps

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/installation/internal/nodecommand"
	"github.com/xiak/matrix/app/service/installation/nodeconfig"
)

func TestBootstrapHTTPClientPinsIssuerAndClassifiesOnlyRetryableFailures(t *testing.T) {
	var status atomic.Int32
	status.Store(http.StatusOK)
	var contentType atomic.Value
	contentType.Store("application/json")
	var duplicateContentType atomic.Bool
	var body atomic.Value
	body.Store(`{"ok":true}`)
	installationID := "mxi-" + strings.Repeat("a", 32)
	issuerDER, issuerPrivate := enrollmentIssuer(t, installationID, 1)
	serverName, err := paasv1.NodeEnrollmentIngressServerName(installationID)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		t.Fatal(err)
	}
	serverPublic, serverPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: []string{serverName},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, issuer, serverPublic, issuerPrivate)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.Header.Get("Authorization") != "" ||
			request.Header.Get("Content-Type") != "application/json" {
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		response.Header().Set("Content-Type", contentType.Load().(string))
		if duplicateContentType.Load() {
			response.Header().Add("Content-Type", "application/octet-stream")
		}
		response.WriteHeader(int(status.Load()))
		_, _ = response.Write([]byte(body.Load().(string)))
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{
		Certificate: [][]byte{serverDER, issuerDER}, PrivateKey: serverPrivate,
	}}}
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()
	join := enrollmentJoin(t, server.URL, installationID, issuerDER, issuerPrivate)
	client := New()
	t.Run("success", func(t *testing.T) {
		var response struct {
			OK bool `json:"ok"`
		}
		if err := client.post(context.Background(), join, "exchange", struct{}{}, &response, false); err != nil || !response.OK {
			t.Fatalf("pinned bootstrap request: %#v / %v", response, err)
		}
	})
	t.Run("server unavailable", func(t *testing.T) {
		status.Store(http.StatusServiceUnavailable)
		if err := client.post(context.Background(), join, "exchange", struct{}{}, &struct{}{}, false); !errors.Is(err, nodecommand.ErrEnrollmentUnavailable) {
			t.Fatalf("server failure classification = %v", err)
		}
	})
	t.Run("definitive rejection", func(t *testing.T) {
		status.Store(http.StatusBadRequest)
		contentType.Store("application/problem+json")
		body.Store(`{"type":"https://xiak.com/problems/invalid-argument","title":"Invalid argument","status":400,"code":"INVALID_ARGUMENT","detail":"node enrollment exchange request is invalid","traceId":"request-test","retryable":false}`)
		if err := client.post(context.Background(), join, "exchange", struct{}{}, &struct{}{}, false); !errors.Is(err, nodecommand.ErrEnrollmentRejected) {
			t.Fatalf("client failure classification = %v", err)
		}
	})
	t.Run("unattributed client status is uncertain", func(t *testing.T) {
		status.Store(http.StatusBadRequest)
		contentType.Store("application/json")
		body.Store(`{"ok":true}`)
		if err := client.post(context.Background(), join, "exchange", struct{}{}, &struct{}{}, false); !errors.Is(err, nodecommand.ErrEnrollmentUnavailable) {
			t.Fatalf("unattributed client failure classification = %v", err)
		}
	})
	t.Run("authoritative not exchanged", func(t *testing.T) {
		status.Store(http.StatusNotFound)
		contentType.Store("application/problem+json")
		body.Store(`{"type":"https://xiak.com/problems/not-found","title":"Exchange not found","status":404,"code":"NOT_FOUND","detail":"node enrollment has no exchange result","traceId":"request-test","retryable":false}`)
		if err := client.post(context.Background(), join, "recovery-challenge", struct{}{}, &struct{}{}, true); !errors.Is(err, nodecommand.ErrEnrollmentNotExchanged) {
			t.Fatalf("recovery conflict classification = %v", err)
		}
		contentType.Store("application/json")
		body.Store(`{"ok":true}`)
	})
	t.Run("generic recovery not found is definitive", func(t *testing.T) {
		status.Store(http.StatusNotFound)
		contentType.Store("application/problem+json")
		body.Store(`{"type":"https://xiak.com/problems/not-found","title":"Not found","status":404,"code":"NOT_FOUND","detail":"node enrollment does not exist","traceId":"request-test","retryable":false}`)
		if err := client.post(context.Background(), join, "recovery-challenge", struct{}{}, &struct{}{}, true); !errors.Is(err, nodecommand.ErrEnrollmentRejected) {
			t.Fatalf("generic recovery not-found classification = %v", err)
		}
		contentType.Store("application/json")
		body.Store(`{"ok":true}`)
	})
	t.Run("recovery conflict is definitive", func(t *testing.T) {
		status.Store(http.StatusConflict)
		contentType.Store("application/problem+json")
		body.Store(`{"type":"https://xiak.com/problems/conflict","title":"Enrollment conflict","status":409,"code":"CONFLICT","detail":"node enrollment recovery conflicts with current installation authority","traceId":"request-test","retryable":false}`)
		if err := client.post(context.Background(), join, "recovery-challenge", struct{}{}, &struct{}{}, true); !errors.Is(err, nodecommand.ErrEnrollmentRejected) {
			t.Fatalf("recovery conflict classification = %v", err)
		}
	})
	t.Run("closed response", func(t *testing.T) {
		status.Store(http.StatusOK)
		contentType.Store("application/json")
		body.Store(`{"ok":true,"unexpected":true}`)
		var response struct {
			OK bool `json:"ok"`
		}
		if err := client.post(context.Background(), join, "exchange", struct{}{}, &response, false); !errors.Is(err, nodecommand.ErrEnrollmentUnavailable) {
			t.Fatalf("open response classification = %v", err)
		}
		body.Store(`{"ok":true}`)
	})
	t.Run("wrong media type", func(t *testing.T) {
		contentType.Store("application/json; charset=utf-8")
		if err := client.post(context.Background(), join, "exchange", struct{}{}, &struct{}{}, false); !errors.Is(err, nodecommand.ErrEnrollmentUnavailable) {
			t.Fatalf("response media-type classification = %v", err)
		}
		contentType.Store("application/json")
	})
	t.Run("duplicate media type", func(t *testing.T) {
		duplicateContentType.Store(true)
		if err := client.post(context.Background(), join, "exchange", struct{}{}, &struct{}{}, false); !errors.Is(err, nodecommand.ErrEnrollmentUnavailable) {
			t.Fatalf("duplicate response media-type classification = %v", err)
		}
		duplicateContentType.Store(false)
	})
	t.Run("wrong issuer", func(t *testing.T) {
		otherDER, otherPrivate := enrollmentIssuer(t, installationID, 10)
		otherJoin := enrollmentJoin(t, server.URL, installationID, otherDER, otherPrivate)
		if err := client.post(context.Background(), otherJoin, "exchange", struct{}{}, &struct{}{}, false); !errors.Is(err, nodecommand.ErrEnrollmentRejected) {
			t.Fatalf("TLS issuer mismatch classification = %v", err)
		}
	})
	t.Run("malformed exchange success preserves recovery", func(t *testing.T) {
		status.Store(http.StatusOK)
		contentType.Store("application/json")
		body.Store(`{}`)
		credential := sha256.Sum256([]byte("test bootstrap credential"))
		nodeRequest := enrollmentCertificateRequest(t)
		collectorRequest := enrollmentCertificateRequest(t)
		request := paasv1.ExchangeNodeEnrollmentRequest{
			APIVersion:            paasv1.NodeEnrollmentExchangeAPIVersion,
			Kind:                  paasv1.NodeEnrollmentExchangeRequestKind,
			EnrollmentID:          join.EnrollmentID,
			InstallationID:        join.InstallationID,
			ExecutionTargetID:     join.ExecutionTargetID,
			ExchangeID:            "node-exchange-" + strings.Repeat("a", 32),
			Credential:            base64.RawURLEncoding.EncodeToString(credential[:]),
			MachineFingerprint:    "sha256:" + strings.Repeat("a", 64),
			RuntimeContractDigest: nodeconfig.ContractDigest(),
			Listener: paasv1.NodeEnrollmentListenerClaim{
				ManagementPort: nodeconfig.DefaultManagementPort,
				CollectorPort:  nodeconfig.DefaultCollectorPort,
			},
			NodeCertificateRequest:      nodeRequest,
			CollectorCertificateRequest: collectorRequest,
		}
		if _, err := client.Exchange(context.Background(), join, request); !errors.Is(err, nodecommand.ErrEnrollmentUnavailable) {
			t.Fatalf("malformed committed exchange classification = %v", err)
		}
	})
	t.Run("malformed completion success preserves commit", func(t *testing.T) {
		status.Store(http.StatusOK)
		contentType.Store("application/json")
		body.Store(`{}`)
		request := paasv1.CompleteNodeEnrollmentRequest{
			APIVersion:                    paasv1.NodeEnrollmentExchangeAPIVersion,
			Kind:                          paasv1.NodeEnrollmentCompletionRequestKind,
			EnrollmentID:                  join.EnrollmentID,
			InstallationID:                join.InstallationID,
			ExecutionTargetID:             join.ExecutionTargetID,
			ExchangeID:                    "node-exchange-" + strings.Repeat("a", 32),
			MachineFingerprint:            "sha256:" + strings.Repeat("a", 64),
			RuntimeContractDigest:         nodeconfig.ContractDigest(),
			ControllerID:                  "controller-a",
			BindingRef:                    "node-binding-" + strings.Repeat("a", 32),
			NodeListenAddress:             "192.168.50.10:16443",
			CollectorEndpoint:             "https://127.0.0.1:19100",
			NodePublicKeyFingerprint:      "sha256:" + strings.Repeat("b", 64),
			CollectorPublicKeyFingerprint: "sha256:" + strings.Repeat("c", 64),
		}
		if err := client.Complete(context.Background(), join, request); !errors.Is(err, nodecommand.ErrEnrollmentUnavailable) {
			t.Fatalf("malformed committed completion classification = %v", err)
		}
	})
}

func TestEnrollmentEndpointCannotEscapeItsFixedCeremony(t *testing.T) {
	join := paasv1.NodeEnrollmentJoin{ControlPlaneURL: "https://matrix.internal/api/paas/v1/node-enrollments/enrollment-a/exchange"}
	for action, expected := range map[string]string{
		"exchange":           join.ControlPlaneURL,
		"recovery-challenge": "https://matrix.internal/api/paas/v1/node-enrollments/enrollment-a/recovery-challenge",
		"recover":            "https://matrix.internal/api/paas/v1/node-enrollments/enrollment-a/recover",
		"complete":           "https://matrix.internal/api/paas/v1/node-enrollments/enrollment-a/complete",
	} {
		actual, err := enrollmentEndpoint(join, action)
		if err != nil || actual != expected {
			t.Fatalf("%s endpoint = %q / %v", action, actual, err)
		}
	}
	if _, err := enrollmentEndpoint(join, "delete"); err == nil {
		t.Fatal("bootstrap client admitted an arbitrary action")
	}
	join.ControlPlaneURL = "https://matrix.internal/api/paas/v1/node-enrollments/enrollment-a/%65xchange"
	if _, err := enrollmentEndpoint(join, "exchange"); err == nil {
		t.Fatal("bootstrap client admitted an alternate escaped route")
	}
}

func enrollmentIssuer(t *testing.T, installationID string, serial int64) ([]byte, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuerURI, err := paasv1.NodeEnrollmentIssuerURI(installationID)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "Matrix node enrollment issuer"},
		NotBefore:             time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC),
		BasicConstraintsValid: true, IsCA: true, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		URIs:     []*url.URL{issuerURI},
	}
	certificate, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, private
}

func enrollmentCertificateRequest(t *testing.T) string {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	request, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, private)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(request)
}

func enrollmentJoin(
	t *testing.T,
	serverURL string,
	installationID string,
	issuerDER []byte,
	issuerPrivate ed25519.PrivateKey,
) paasv1.NodeEnrollmentJoin {
	t.Helper()
	credential := sha256.Sum256([]byte("test bootstrap credential"))
	credentialDigest := sha256.Sum256(credential[:])
	enrollmentID := paasv1.ResourceID("node-enrollment-" + strings.Repeat("a", 32))
	join := paasv1.NodeEnrollmentJoin{
		APIVersion: paasv1.NodeEnrollmentJoinAPIVersion, Kind: paasv1.NodeEnrollmentJoinKind,
		EnrollmentID: enrollmentID, InstallationID: installationID, ExecutionTargetID: "target-a",
		ControlPlaneURL:    serverURL + "/api/paas/v1/node-enrollments/" + string(enrollmentID) + "/exchange",
		CredentialDigest:   "sha256:" + hex.EncodeToString(credentialDigest[:]),
		ExpiresAt:          time.Now().UTC().Add(15 * time.Minute).Truncate(time.Microsecond),
		IssuerCertificate:  base64.RawURLEncoding.EncodeToString(issuerDER),
		SignatureAlgorithm: paasv1.NodeJoinSignatureEd25519,
	}
	commitment, err := paasv1.NodeEnrollmentJoinSigningBytes(join)
	if err != nil {
		t.Fatal(err)
	}
	join.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(issuerPrivate, commitment))
	if err := paasv1.ValidateNodeEnrollmentJoin(join); err != nil {
		t.Fatal(err)
	}
	return join
}
