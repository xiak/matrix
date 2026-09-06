package paasv1

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestNodeEnrollmentCreationContractContainsOnlyWrappedCredential(t *testing.T) {
	request, response, _ := nodeEnrollmentContractFixture(t)
	if err := ValidateCreateNodeEnrollmentRequest(request); err != nil {
		t.Fatal(err)
	}
	if err := ValidateCreateNodeEnrollmentResponse(response); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"join-credential-plaintext",
		"PRIVATE KEY",
		"token=",
		"?credential=",
	} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("creation response leaked %q", forbidden)
		}
	}

	for name, mutate := range map[string]func(*CreateNodeEnrollmentRequest){
		"weak wrapping key": func(value *CreateNodeEnrollmentRequest) {
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			value.WrappingPublicKey = base64.RawURLEncoding.EncodeToString(encoded)
		},
		"identity label": func(value *CreateNodeEnrollmentRequest) {
			value.Labels = map[string]string{"matrix-machine-fingerprint": "forged"}
		},
		"unknown pool": func(value *CreateNodeEnrollmentRequest) { value.ExecutionPoolID = "" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := request
			mutate(&changed)
			if err := ValidateCreateNodeEnrollmentRequest(changed); err == nil {
				t.Fatal("invalid enrollment request was accepted")
			}
		})
	}
}

func TestNodeEnrollmentSchemasRejectProviderAndSecretInputs(t *testing.T) {
	request, response, _ := nodeEnrollmentContractFixture(t)
	document := loadOpenAPI(t)
	requestSchema := compileOpenAPISchema(t, document, "CreateNodeEnrollmentRequest")
	if err := requestSchema.Validate(schemaInstance(t, request)); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{
		"endpoint", "hostPath", "shell", "composeYaml", "dockerOptions",
		"sshPassword", "certificate", "privateKey", "credential",
	} {
		value := schemaInstance(t, request).(map[string]any)
		value[field] = "forbidden"
		if err := requestSchema.Validate(value); err == nil {
			t.Fatalf("enrollment request schema accepts %s", field)
		}
	}
	responseSchema := compileOpenAPISchema(t, document, "CreateNodeEnrollmentResponse")
	if err := responseSchema.Validate(schemaInstance(t, response)); err != nil {
		t.Fatal(err)
	}
	join := schemaInstance(t, response.Join).(map[string]any)
	join["credential"] = "join-credential-plaintext"
	joinSchema := compileOpenAPISchema(t, document, "NodeEnrollmentJoin")
	if err := joinSchema.Validate(join); err == nil {
		t.Fatal("join metadata schema accepts a raw credential")
	}
}

func TestNodeEnrollmentJoinRejectsTamperingAndCredentialURLs(t *testing.T) {
	_, response, signer := nodeEnrollmentContractFixture(t)
	for name, scenario := range map[string]struct {
		mutate func(*NodeEnrollmentJoin)
		resign bool
	}{
		"target tamper": {
			mutate: func(value *NodeEnrollmentJoin) { value.ExecutionTargetID = "target-other" },
		},
		"credential query": {
			mutate: func(value *NodeEnrollmentJoin) { value.ControlPlaneURL += "?credential=forbidden" },
			resign: true,
		},
		"wrong path": {
			mutate: func(value *NodeEnrollmentJoin) {
				value.ControlPlaneURL = "https://matrix.internal/api/paas/v1/execution-targets"
			},
			resign: true,
		},
		"issuer installation": {
			mutate: func(value *NodeEnrollmentJoin) { value.InstallationID = "installation-other" },
			resign: true,
		},
		"issuer certificate signature": {
			mutate: func(value *NodeEnrollmentJoin) {
				certificate, err := base64.RawURLEncoding.Strict().DecodeString(value.IssuerCertificate)
				if err != nil {
					t.Fatal(err)
				}
				certificate[len(certificate)-1] ^= 0x01
				value.IssuerCertificate = base64.RawURLEncoding.EncodeToString(certificate)
			},
			resign: true,
		},
		"padded signature": {
			mutate: func(value *NodeEnrollmentJoin) { value.Signature += "=" },
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := response.Join
			scenario.mutate(&changed)
			if scenario.resign {
				if commitment, err := NodeEnrollmentJoinSigningBytes(changed); err == nil {
					changed.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(signer, commitment))
				}
			}
			if err := ValidateNodeEnrollmentJoin(changed); err == nil {
				t.Fatal("tampered join metadata was accepted")
			}
		})
	}
}

func TestNodeEnrollmentIngressServerNameIsDeterministicAndInstallationBound(t *testing.T) {
	installationID := "mxi-" + strings.Repeat("a", 32)
	first, err := NodeEnrollmentIngressServerName(installationID)
	second, secondErr := NodeEnrollmentIngressServerName(installationID)
	other, otherErr := NodeEnrollmentIngressServerName("mxi-" + strings.Repeat("b", 32))
	if err != nil || secondErr != nil || otherErr != nil || first != second || first == other ||
		!strings.HasPrefix(first, "mx-") || !strings.HasSuffix(first, ".enrollment.matrix.invalid") ||
		len(first) > 253 || strings.Contains(first, installationID) {
		t.Fatalf("node enrollment ingress names first=%q second=%q other=%q errors=%v/%v/%v", first, second, other, err, secondErr, otherErr)
	}
	if _, err := NodeEnrollmentIngressServerName(""); err == nil {
		t.Fatal("invalid installation produced a node enrollment ingress name")
	}
}

func TestNodeEnrollmentStatesAreClosedAndTimeBound(t *testing.T) {
	_, response, _ := nodeEnrollmentContractFixture(t)
	waiting := response.Enrollment
	consumedAt := waiting.Metadata.CreatedAt.Add(time.Minute)
	readyAt := consumedAt.Add(time.Minute)
	failure := NodeEnrollmentDiagnostic{
		Code: NodeEnrollmentDiagnosticMTLS, OccurredAt: readyAt,
	}
	expired := NodeEnrollmentDiagnostic{
		Code: NodeEnrollmentDiagnosticExpired, OccurredAt: waiting.ExpiresAt,
	}
	revoked := NodeEnrollmentDiagnostic{
		Code: NodeEnrollmentDiagnosticRevoked, OccurredAt: consumedAt,
	}
	states := []NodeEnrollment{
		waiting,
		func() NodeEnrollment {
			value := waiting
			value.State, value.CredentialConsumedAt = NodeEnrollmentVerifying, &consumedAt
			value.Metadata.UpdatedAt = consumedAt
			return value
		}(),
		func() NodeEnrollment {
			value := waiting
			value.State, value.CredentialConsumedAt, value.ReadyAt = NodeEnrollmentReady, &consumedAt, &readyAt
			value.Metadata.UpdatedAt = readyAt
			return value
		}(),
		func() NodeEnrollment {
			value := waiting
			value.State, value.CredentialConsumedAt, value.Diagnostic = NodeEnrollmentFailed, &consumedAt, &failure
			value.Metadata.UpdatedAt = readyAt
			return value
		}(),
		func() NodeEnrollment {
			value := waiting
			value.State, value.Diagnostic = NodeEnrollmentExpired, &expired
			value.Metadata.UpdatedAt = waiting.ExpiresAt
			return value
		}(),
		func() NodeEnrollment {
			value := waiting
			value.State, value.CredentialConsumedAt, value.Diagnostic = NodeEnrollmentRevoked, &consumedAt, &revoked
			value.Metadata.UpdatedAt = consumedAt
			value.ReplacedByID = "node-enrollment-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
			return value
		}(),
	}
	for _, value := range states {
		if err := ValidateNodeEnrollment(value); err != nil {
			t.Fatalf("valid state %s rejected: %v", value.State, err)
		}
	}

	invalid := states[1]
	invalid.State = NodeEnrollmentReady
	if err := ValidateNodeEnrollment(invalid); err == nil {
		t.Fatal("ready enrollment without completion proof was accepted")
	}
	invalid = waiting
	invalid.ExpiresAt = waiting.Metadata.CreatedAt.Add(MaximumNodeEnrollmentLifetime + time.Microsecond)
	if err := ValidateNodeEnrollment(invalid); err == nil {
		t.Fatal("overlong enrollment was accepted")
	}
	invalid = states[3]
	invalid.Diagnostic = &NodeEnrollmentDiagnostic{
		Code: NodeEnrollmentDiagnosticNetworkInterrupted, Retryable: false, OccurredAt: readyAt,
	}
	if err := ValidateNodeEnrollment(invalid); err == nil {
		t.Fatal("diagnostic with false retryability was accepted")
	}
}

func TestNodeEnrollmentExchangeBindsDistinctLocalKeysAndIssuedIdentity(t *testing.T) {
	request, response := nodeEnrollmentExchangeFixture(t)
	if err := ValidateExchangeNodeEnrollmentRequest(request); err != nil {
		t.Fatalf("validate exchange request: %v", err)
	}
	if err := ValidateNodeEnrollmentExchangeResponse(response); err != nil {
		t.Fatalf("validate exchange response: %v", err)
	}
	if err := ValidateNodeEnrollmentExchangeResponseForRequest(response, request); err != nil {
		t.Fatalf("bind exchange response: %v", err)
	}
	nodeKey, collectorKey, err := NodeEnrollmentExchangePublicKeys(request)
	if err != nil || len(nodeKey) == 0 || len(collectorKey) == 0 || string(nodeKey) == string(collectorKey) {
		t.Fatalf("canonical public keys are invalid: node=%d collector=%d err=%v", len(nodeKey), len(collectorKey), err)
	}
	if got := request.String(); got != "node enrollment exchange request <redacted>" || strings.Contains(got, request.Credential) {
		t.Fatalf("exchange formatting leaked credential: %q", got)
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{request.Credential, request.NodeCertificateRequest, request.CollectorCertificateRequest, "privateKey"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("exchange response leaked request material %q", forbidden)
		}
	}
}

func TestNodeEnrollmentExchangeRequestRejectsCredentialIdentityAndCSRVariation(t *testing.T) {
	request, _ := nodeEnrollmentExchangeFixture(t)
	for name, mutate := range map[string]func(*ExchangeNodeEnrollmentRequest){
		"padded credential":       func(value *ExchangeNodeEnrollmentRequest) { value.Credential += "=" },
		"short credential":        func(value *ExchangeNodeEnrollmentRequest) { value.Credential = value.Credential[:42] },
		"wrong installation":      func(value *ExchangeNodeEnrollmentRequest) { value.InstallationID = "" },
		"wrong exchange identity": func(value *ExchangeNodeEnrollmentRequest) { value.ExchangeID = "exchange-a" },
		"privileged listener":     func(value *ExchangeNodeEnrollmentRequest) { value.Listener.ManagementPort = 443 },
		"shared listener": func(value *ExchangeNodeEnrollmentRequest) {
			value.Listener.CollectorPort = value.Listener.ManagementPort
		},
		"shared public key": func(value *ExchangeNodeEnrollmentRequest) {
			value.CollectorCertificateRequest = value.NodeCertificateRequest
		},
		"CSR subject": func(value *ExchangeNodeEnrollmentRequest) {
			_, privateKey, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "caller-owned"}}, privateKey)
			if err != nil {
				t.Fatal(err)
			}
			value.NodeCertificateRequest = base64.RawURLEncoding.EncodeToString(encoded)
		},
		"CSR extension": func(value *ExchangeNodeEnrollmentRequest) {
			_, privateKey, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{"caller.invalid"}}, privateKey)
			if err != nil {
				t.Fatal(err)
			}
			value.NodeCertificateRequest = base64.RawURLEncoding.EncodeToString(encoded)
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := request
			mutate(&changed)
			if err := ValidateExchangeNodeEnrollmentRequest(changed); err == nil {
				t.Fatal("invalid exchange request was accepted")
			}
		})
	}
}

func TestNodeEnrollmentExchangeResponseRejectsRebindingAndCertificateTampering(t *testing.T) {
	request, response := nodeEnrollmentExchangeFixture(t)
	for name, mutate := range map[string]func(*NodeEnrollmentExchangeResponse){
		"public endpoint":      func(value *NodeEnrollmentExchangeResponse) { value.NodeListenAddress = "8.8.8.8:16443" },
		"remote collector":     func(value *NodeEnrollmentExchangeResponse) { value.CollectorEndpoint = "https://192.168.50.10:19100" },
		"changed installation": func(value *NodeEnrollmentExchangeResponse) { value.InstallationID = "installation-other" },
		"changed binding":      func(value *NodeEnrollmentExchangeResponse) { value.BindingRef = "binding-other" },
		"swapped role certificates": func(value *NodeEnrollmentExchangeResponse) {
			value.NodeCertificate, value.CollectorCertificate = value.CollectorCertificate, value.NodeCertificate
		},
		"tampered certificate": func(value *NodeEnrollmentExchangeResponse) {
			encoded, err := base64.RawURLEncoding.Strict().DecodeString(value.NodeCertificate)
			if err != nil {
				t.Fatal(err)
			}
			encoded[len(encoded)-1] ^= 1
			value.NodeCertificate = base64.RawURLEncoding.EncodeToString(encoded)
		},
		"overlong lifetime": func(value *NodeEnrollmentExchangeResponse) {
			value.CertificateNotAfter = value.CertificateNotBefore.Add(MaximumNodeEnrollmentCertificateLifetime + time.Microsecond)
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := response
			mutate(&changed)
			if err := ValidateNodeEnrollmentExchangeResponse(changed); err == nil {
				t.Fatal("invalid exchange response was accepted")
			}
		})
	}
	changed := request
	changed.ExchangeID = "node-exchange-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if err := ValidateNodeEnrollmentExchangeResponseForRequest(response, changed); err == nil {
		t.Fatal("exchange response was rebound to another request")
	}
}

func nodeEnrollmentExchangeFixture(t *testing.T) (ExchangeNodeEnrollmentRequest, NodeEnrollmentExchangeResponse) {
	t.Helper()
	now := time.Date(2026, 9, 6, 8, 0, 0, 0, time.UTC)
	notBefore, notAfter := now.Add(-5*time.Minute), now.Add(-5*time.Minute).Add(MaximumNodeEnrollmentCertificateLifetime)

	nodePublic, nodePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	collectorPublic, collectorPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr := func(privateKey ed25519.PrivateKey) string {
		encoded, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, privateKey)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(encoded)
	}
	request := ExchangeNodeEnrollmentRequest{
		APIVersion: NodeEnrollmentExchangeAPIVersion, Kind: NodeEnrollmentExchangeRequestKind,
		EnrollmentID: "node-enrollment-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", InstallationID: "installation-a",
		ExecutionTargetID:      "execution-target-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ExchangeID:             "node-exchange-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Credential:             base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")),
		MachineFingerprint:     "sha256:" + strings.Repeat("a", 64),
		RuntimeContractDigest:  "sha256:" + strings.Repeat("b", 64),
		Listener:               NodeEnrollmentListenerClaim{ManagementPort: 16443, CollectorPort: 19100},
		NodeCertificateRequest: csr(nodePrivate), CollectorCertificateRequest: csr(collectorPrivate),
	}

	issuerPublic, issuerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuerURI, err := NodeEnrollmentIssuerURI(request.InstallationID)
	if err != nil {
		t.Fatal(err)
	}
	issuerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Matrix node enrollment issuer"},
		NotBefore:             time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC),
		BasicConstraintsValid: true, IsCA: true, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		URIs:     []*url.URL{issuerURI},
	}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, issuerPublic, issuerPrivate)
	if err != nil {
		t.Fatal(err)
	}
	roleCertificate := func(role string, publicKey ed25519.PublicKey, address net.IP, usages []x509.ExtKeyUsage, serial int64) string {
		identityURI, err := url.Parse("spiffe://matrix.xiak.com/installations/" + request.InstallationID + "/" + role + "/" + string(request.ExecutionTargetID))
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{
			SerialNumber: big.NewInt(serial), NotBefore: notBefore, NotAfter: notAfter,
			BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
			ExtKeyUsage: usages, URIs: []*url.URL{identityURI}, IPAddresses: []net.IP{address},
		}
		encoded, err := x509.CreateCertificate(rand.Reader, template, issuerTemplate, publicKey, issuerPrivate)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(encoded)
	}
	response := NodeEnrollmentExchangeResponse{
		APIVersion: NodeEnrollmentExchangeAPIVersion, Kind: NodeEnrollmentExchangeResponseKind,
		EnrollmentID: request.EnrollmentID, InstallationID: request.InstallationID,
		ExecutionTargetID: request.ExecutionTargetID, ExchangeID: request.ExchangeID,
		MachineFingerprint: request.MachineFingerprint, RuntimeContractDigest: request.RuntimeContractDigest,
		ControllerID: "paas-controller-v1", BindingRef: "node-binding-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		NodeListenAddress: "192.168.50.10:16443", CollectorEndpoint: "https://127.0.0.1:19100",
		NodeCertificate:      roleCertificate("nodes", nodePublic, net.ParseIP("192.168.50.10"), []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, 2),
		CollectorCertificate: roleCertificate("collectors", collectorPublic, net.ParseIP("127.0.0.1"), []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, 3),
		IssuerCertificate:    base64.RawURLEncoding.EncodeToString(issuerDER),
		CertificateNotBefore: notBefore, CertificateNotAfter: notAfter,
	}
	return request, response
}

func nodeEnrollmentContractFixture(t *testing.T) (CreateNodeEnrollmentRequest, CreateNodeEnrollmentResponse, ed25519.PrivateKey) {
	t.Helper()
	now := time.Date(2026, 9, 6, 8, 0, 0, 0, time.UTC)
	expiresAt := now.Add(15 * time.Minute)

	wrappingKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	wrappingDER, err := x509.MarshalPKIXPublicKey(&wrappingKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	request := CreateNodeEnrollmentRequest{
		Name: "host-a", Labels: map[string]string{"zone": "private-a"},
		ExecutionPoolID:   "pool-a",
		WrappingPublicKey: base64.RawURLEncoding.EncodeToString(wrappingDER),
	}

	issuerPublic, issuerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "matrix-enrollment-issuer"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		BasicConstraintsValid: true, IsCA: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	issuerURI, err := NodeEnrollmentIssuerURI("installation-a")
	if err != nil {
		t.Fatal(err)
	}
	issuerTemplate.URIs = append(issuerTemplate.URIs, issuerURI)
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, issuerPublic, issuerPrivate)
	if err != nil {
		t.Fatal(err)
	}
	enrollment := NodeEnrollment{
		APIVersion: APIVersion, Kind: "NodeEnrollment",
		Metadata: ResourceMetadata{
			ID: "node-enrollment-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Name: request.Name,
			Scope: ResourceScope{Kind: AuthorityPlatform}, Labels: request.Labels,
			ResourceVersion: 1, CreatedAt: now, UpdatedAt: now,
		},
		ExecutionTargetID: "target-a", ExecutionPoolID: request.ExecutionPoolID,
		OperationID: "operation-a", State: NodeEnrollmentWaitingInstall, ExpiresAt: expiresAt,
	}
	join := NodeEnrollmentJoin{
		APIVersion: NodeEnrollmentJoinAPIVersion, Kind: NodeEnrollmentJoinKind,
		EnrollmentID: enrollment.Metadata.ID, InstallationID: "installation-a",
		ExecutionTargetID: enrollment.ExecutionTargetID,
		ControlPlaneURL:   "https://matrix.internal/api/paas/v1/node-enrollments/" + string(enrollment.Metadata.ID) + "/exchange",
		CredentialDigest:  "sha256:" + strings.Repeat("a", 64), ExpiresAt: expiresAt,
		IssuerCertificate:  base64.RawURLEncoding.EncodeToString(issuerDER),
		SignatureAlgorithm: NodeJoinSignatureEd25519,
	}
	commitment, err := NodeEnrollmentJoinSigningBytes(join)
	if err != nil {
		t.Fatal(err)
	}
	join.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(issuerPrivate, commitment))
	response := CreateNodeEnrollmentResponse{
		Enrollment: enrollment, Join: join,
		WrappedCredential: WrappedJoinCredential{
			Algorithm:  JoinCredentialRSAOAEP256,
			Ciphertext: base64.RawURLEncoding.EncodeToString(make([]byte, 384)),
		},
	}
	return request, response, issuerPrivate
}
