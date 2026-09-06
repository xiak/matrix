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
