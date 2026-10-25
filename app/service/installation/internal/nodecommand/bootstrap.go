package nodecommand

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"path/filepath"

	nodev1 "github.com/xiak/matrix/api/adapter/node/v1"
	"github.com/xiak/matrix/api/contractjson"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/installation/internal/layout"
	"github.com/xiak/matrix/app/service/installation/nodeconfig"
	"github.com/xiak/matrix/app/service/installation/release"
)

const (
	enrollmentIntentAPIVersion = "node.installation.matrix.xiak.com/v1"
	enrollmentIntentKind       = "NodeEnrollmentIntent"
	maximumEnrollmentBytes     = 64 * 1024
)

var (
	ErrEnrollmentUnavailable  = errors.New("node enrollment transport is unavailable")
	ErrEnrollmentRejected     = errors.New("node enrollment was rejected")
	ErrEnrollmentNotExchanged = errors.New("node enrollment has not been exchanged")
)

// EnrollmentHost identifies the machine locally. Implementations may inspect
// only the target host and never infer identity from a browser or server value.
type EnrollmentHost interface {
	MachineFingerprint(context.Context, string) (string, error)
}

// EnrollmentClient is the bounded node-facing bootstrap transport. It has no
// IAM session, target selection, registration, or arbitrary URL operation.
type EnrollmentClient interface {
	Exchange(context.Context, paasv1.NodeEnrollmentJoin, paasv1.ExchangeNodeEnrollmentRequest) (paasv1.NodeEnrollmentExchangeResponse, error)
	CreateRecoveryChallenge(context.Context, paasv1.NodeEnrollmentJoin, paasv1.CreateNodeEnrollmentRecoveryChallengeRequest) (paasv1.NodeEnrollmentRecoveryChallenge, error)
	RecoverExchange(context.Context, paasv1.NodeEnrollmentJoin, paasv1.RecoverNodeEnrollmentExchangeRequest) (paasv1.NodeEnrollmentExchangeResponse, error)
	Complete(context.Context, paasv1.NodeEnrollmentJoin, paasv1.CompleteNodeEnrollmentRequest) error
}

// EnrollmentIntent is written once before the first credential-bearing HTTP
// request. It contains protected host-local private keys but never the raw join
// credential. Its public commitment and both CSRs make substitution detectable.
type EnrollmentIntent struct {
	APIVersion                  string                             `json:"apiVersion"`
	Kind                        string                             `json:"kind"`
	Join                        paasv1.NodeEnrollmentJoin          `json:"join"`
	ExchangeID                  string                             `json:"exchangeId"`
	MachineFingerprint          string                             `json:"machineFingerprint"`
	RuntimeContractDigest       string                             `json:"runtimeContractDigest"`
	Listener                    paasv1.NodeEnrollmentListenerClaim `json:"listener"`
	NodeCertificateRequest      string                             `json:"nodeCertificateRequest"`
	CollectorCertificateRequest string                             `json:"collectorCertificateRequest"`
	NodePrivateKey              []byte                             `json:"nodePrivateKey"`
	CollectorPrivateKey         []byte                             `json:"collectorPrivateKey"`
	Commitment                  string                             `json:"commitment"`
}

func (EnrollmentIntent) String() string   { return "node enrollment intent <redacted>" }
func (EnrollmentIntent) GoString() string { return "node enrollment intent <redacted>" }

func (value EnrollmentIntent) Clear() {
	clear(value.NodePrivateKey)
	clear(value.CollectorPrivateKey)
}

type EnrollmentStore interface {
	ResumeEnrollmentCleanup(string) (bool, error)
	ReadEnrollmentIntent(string) (EnrollmentIntent, bool, error)
	CreateEnrollmentIntent(string, EnrollmentIntent) error
	EnrollmentExchangeAttempted(string, EnrollmentIntent) (bool, error)
	MarkEnrollmentExchangeAttempted(string, EnrollmentIntent) error
	ReadEnrollmentResponse(string, EnrollmentIntent) (paasv1.NodeEnrollmentExchangeResponse, bool, error)
	CreateEnrollmentResponse(string, EnrollmentIntent, paasv1.NodeEnrollmentExchangeResponse) error
	DiscardEnrollmentIntent(string, EnrollmentIntent) error
	FinalizeEnrollment(string, EnrollmentIntent, paasv1.NodeEnrollmentExchangeResponse) error
	CleanupRejectedEnrollment(context.Context, Plan, EnrollmentIntent, paasv1.NodeEnrollmentExchangeResponse) error
}

func ValidateEnrollmentResponse(intent EnrollmentIntent, response paasv1.NodeEnrollmentExchangeResponse) error {
	if ValidateEnrollmentIntent(intent) != nil ||
		paasv1.ValidateNodeEnrollmentExchangeResponseForRequest(
			response,
			intent.exchangeRequest(enrollmentPlaceholderCredential()),
		) != nil {
		return errors.New("node enrollment response is invalid")
	}
	return nil
}

// ValidateEnrollmentPlan proves that a cleanup target is the exact local
// material issued for this ceremony, not merely another structurally valid
// node plan supplied by an internal caller.
func ValidateEnrollmentPlan(
	plan Plan,
	intent EnrollmentIntent,
	response paasv1.NodeEnrollmentExchangeResponse,
) error {
	expected, err := planFromEnrollment(
		plan.Root, plan.Bundle, plan.Trust, plan.TrustBytes, intent, response,
	)
	if err != nil {
		return errors.New("node enrollment plan is invalid")
	}
	defer expected.Clear()
	if plan.Configuration != expected.Configuration || plan.Binding != expected.Binding ||
		!bytes.Equal(plan.Credentials.Certificate, expected.Credentials.Certificate) ||
		!bytes.Equal(plan.Credentials.PrivateKey, expected.Credentials.PrivateKey) ||
		!bytes.Equal(plan.Credentials.Trust, expected.Credentials.Trust) ||
		!bytes.Equal(plan.Credentials.CollectorCertificate, expected.Credentials.CollectorCertificate) ||
		!bytes.Equal(plan.Credentials.CollectorPrivateKey, expected.Credentials.CollectorPrivateKey) {
		return errors.New("node enrollment plan differs from its issued ceremony")
	}
	return nil
}

func newEnrollmentIntent(join paasv1.NodeEnrollmentJoin, machineFingerprint string, entropy io.Reader) (EnrollmentIntent, error) {
	if paasv1.ValidateNodeEnrollmentJoin(join) != nil ||
		paasv1.ValidateDigest("machineFingerprint", machineFingerprint) != nil || entropy == nil {
		return EnrollmentIntent{}, errors.New("node enrollment intent input is invalid")
	}
	exchangeEntropy := make([]byte, 16)
	if _, err := io.ReadFull(entropy, exchangeEntropy); err != nil {
		clear(exchangeEntropy)
		return EnrollmentIntent{}, errors.New("node enrollment exchange identity cannot be generated")
	}
	exchangeID := "node-exchange-" + hex.EncodeToString(exchangeEntropy)
	clear(exchangeEntropy)
	nodePublic, nodePrivate, err := ed25519.GenerateKey(entropy)
	if err != nil {
		return EnrollmentIntent{}, errors.New("node enrollment key cannot be generated")
	}
	collectorPublic, collectorPrivate, err := ed25519.GenerateKey(entropy)
	if err != nil {
		clear(nodePrivate)
		return EnrollmentIntent{}, errors.New("collector enrollment key cannot be generated")
	}
	defer clear(nodePrivate)
	defer clear(collectorPrivate)
	if bytes.Equal(nodePublic, collectorPublic) {
		return EnrollmentIntent{}, errors.New("node enrollment role keys are not distinct")
	}
	nodeCSR, err := enrollmentCertificateRequest(nodePrivate, entropy)
	if err != nil {
		return EnrollmentIntent{}, err
	}
	collectorCSR, err := enrollmentCertificateRequest(collectorPrivate, entropy)
	if err != nil {
		return EnrollmentIntent{}, err
	}
	nodeKey, err := enrollmentPrivateKey(nodePrivate)
	if err != nil {
		return EnrollmentIntent{}, err
	}
	collectorKey, err := enrollmentPrivateKey(collectorPrivate)
	if err != nil {
		clear(nodeKey)
		return EnrollmentIntent{}, err
	}
	value := EnrollmentIntent{
		APIVersion: enrollmentIntentAPIVersion, Kind: enrollmentIntentKind, Join: join,
		ExchangeID: exchangeID, MachineFingerprint: machineFingerprint,
		RuntimeContractDigest: nodeconfig.ContractDigest(),
		Listener: paasv1.NodeEnrollmentListenerClaim{
			ManagementPort: nodeconfig.DefaultManagementPort,
			CollectorPort:  nodeconfig.DefaultCollectorPort,
		},
		NodeCertificateRequest:      base64.RawURLEncoding.EncodeToString(nodeCSR),
		CollectorCertificateRequest: base64.RawURLEncoding.EncodeToString(collectorCSR),
		NodePrivateKey:              nodeKey,
		CollectorPrivateKey:         collectorKey,
	}
	value.Commitment, err = enrollmentIntentCommitment(value)
	if err != nil || ValidateEnrollmentIntent(value) != nil {
		value.Clear()
		return EnrollmentIntent{}, errors.New("node enrollment intent cannot be sealed")
	}
	return value, nil
}

func EncodeEnrollmentIntent(value EnrollmentIntent) ([]byte, error) {
	if ValidateEnrollmentIntent(value) != nil {
		return nil, errors.New("node enrollment intent is invalid")
	}
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) == 0 || len(encoded) > maximumEnrollmentBytes {
		clear(encoded)
		return nil, errors.New("node enrollment intent cannot be encoded")
	}
	return encoded, nil
}

func DecodeEnrollmentIntent(source []byte) (EnrollmentIntent, error) {
	var value EnrollmentIntent
	if contractjson.DecodeObjectBytes(source, maximumEnrollmentBytes, &value) != nil ||
		ValidateEnrollmentIntent(value) != nil {
		value.Clear()
		return EnrollmentIntent{}, errors.New("node enrollment intent is invalid")
	}
	canonical, err := EncodeEnrollmentIntent(value)
	if err != nil || subtle.ConstantTimeCompare(canonical, source) != 1 {
		clear(canonical)
		value.Clear()
		return EnrollmentIntent{}, errors.New("node enrollment intent is not canonical")
	}
	clear(canonical)
	return value, nil
}

func ValidateEnrollmentIntent(value EnrollmentIntent) error {
	if value.APIVersion != enrollmentIntentAPIVersion || value.Kind != enrollmentIntentKind ||
		paasv1.ValidateNodeEnrollmentJoin(value.Join) != nil ||
		paasv1.ValidateDigest("machineFingerprint", value.MachineFingerprint) != nil ||
		value.RuntimeContractDigest != nodeconfig.ContractDigest() ||
		value.Listener != (paasv1.NodeEnrollmentListenerClaim{
			ManagementPort: nodeconfig.DefaultManagementPort,
			CollectorPort:  nodeconfig.DefaultCollectorPort,
		}) {
		return errors.New("node enrollment intent metadata is invalid")
	}
	request := value.exchangeRequest(enrollmentPlaceholderCredential())
	nodePublic, collectorPublic, err := paasv1.NodeEnrollmentExchangePublicKeys(request)
	if err != nil {
		return errors.New("node enrollment intent certificate requests are invalid")
	}
	nodePrivate, nodeErr := parseEnrollmentPrivateKey(value.NodePrivateKey)
	collectorPrivate, collectorErr := parseEnrollmentPrivateKey(value.CollectorPrivateKey)
	if nodeErr == nil {
		defer clear(nodePrivate)
	}
	if collectorErr == nil {
		defer clear(collectorPrivate)
	}
	if nodeErr != nil || collectorErr != nil || bytes.Equal(nodePrivate, collectorPrivate) ||
		!bytes.Equal(nodePrivate.Public().(ed25519.PublicKey), publicKeyFromPKIX(nodePublic)) ||
		!bytes.Equal(collectorPrivate.Public().(ed25519.PublicKey), publicKeyFromPKIX(collectorPublic)) {
		return errors.New("node enrollment intent private keys are invalid")
	}
	commitment, err := enrollmentIntentCommitment(value)
	if err != nil || subtle.ConstantTimeCompare([]byte(commitment), []byte(value.Commitment)) != 1 {
		return errors.New("node enrollment intent commitment is invalid")
	}
	return nil
}

func (value EnrollmentIntent) exchangeRequest(credential string) paasv1.ExchangeNodeEnrollmentRequest {
	return paasv1.ExchangeNodeEnrollmentRequest{
		APIVersion: paasv1.NodeEnrollmentExchangeAPIVersion, Kind: paasv1.NodeEnrollmentExchangeRequestKind,
		EnrollmentID: value.Join.EnrollmentID, InstallationID: value.Join.InstallationID,
		ExecutionTargetID: value.Join.ExecutionTargetID, ExchangeID: value.ExchangeID,
		Credential: credential, MachineFingerprint: value.MachineFingerprint,
		RuntimeContractDigest: value.RuntimeContractDigest, Listener: value.Listener,
		NodeCertificateRequest:      value.NodeCertificateRequest,
		CollectorCertificateRequest: value.CollectorCertificateRequest,
	}
}

func (value EnrollmentIntent) recoveryChallengeRequest() (paasv1.CreateNodeEnrollmentRecoveryChallengeRequest, error) {
	nodeFingerprint, collectorFingerprint, err := value.publicKeyFingerprints()
	if err != nil {
		return paasv1.CreateNodeEnrollmentRecoveryChallengeRequest{}, err
	}
	request := paasv1.CreateNodeEnrollmentRecoveryChallengeRequest{
		APIVersion: paasv1.NodeEnrollmentRecoveryAPIVersion, Kind: paasv1.NodeEnrollmentRecoveryChallengeRequestKind,
		EnrollmentID: value.Join.EnrollmentID, InstallationID: value.Join.InstallationID,
		ExecutionTargetID: value.Join.ExecutionTargetID, ExchangeID: value.ExchangeID,
		MachineFingerprint: value.MachineFingerprint, RuntimeContractDigest: value.RuntimeContractDigest,
		NodePublicKeyFingerprint: nodeFingerprint, CollectorPublicKeyFingerprint: collectorFingerprint,
	}
	if paasv1.ValidateCreateNodeEnrollmentRecoveryChallengeRequest(request) != nil {
		return paasv1.CreateNodeEnrollmentRecoveryChallengeRequest{}, errors.New("node enrollment recovery request is invalid")
	}
	return request, nil
}

func (value EnrollmentIntent) recoveryProof(challenge paasv1.NodeEnrollmentRecoveryChallenge) (paasv1.RecoverNodeEnrollmentExchangeRequest, error) {
	request, err := value.recoveryChallengeRequest()
	if err != nil || paasv1.ValidateNodeEnrollmentRecoveryChallengeForRequest(challenge, request) != nil {
		return paasv1.RecoverNodeEnrollmentExchangeRequest{}, errors.New("node enrollment recovery challenge is invalid")
	}
	proof, err := paasv1.NodeEnrollmentRecoveryProofSigningBytes(challenge)
	if err != nil {
		return paasv1.RecoverNodeEnrollmentExchangeRequest{}, errors.New("node enrollment recovery proof cannot be encoded")
	}
	nodePrivate, nodeErr := parseEnrollmentPrivateKey(value.NodePrivateKey)
	collectorPrivate, collectorErr := parseEnrollmentPrivateKey(value.CollectorPrivateKey)
	if nodeErr != nil || collectorErr != nil {
		return paasv1.RecoverNodeEnrollmentExchangeRequest{}, errors.New("node enrollment recovery keys are invalid")
	}
	defer clear(nodePrivate)
	defer clear(collectorPrivate)
	result := paasv1.RecoverNodeEnrollmentExchangeRequest{
		APIVersion: paasv1.NodeEnrollmentRecoveryAPIVersion, Kind: paasv1.NodeEnrollmentRecoveryProofRequestKind,
		Challenge:          challenge,
		NodeSignature:      base64.RawURLEncoding.EncodeToString(ed25519.Sign(nodePrivate, proof)),
		CollectorSignature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(collectorPrivate, proof)),
	}
	if paasv1.ValidateRecoverNodeEnrollmentExchangeRequest(result) != nil {
		return paasv1.RecoverNodeEnrollmentExchangeRequest{}, errors.New("node enrollment recovery proof is invalid")
	}
	return result, nil
}

func (value EnrollmentIntent) completionRequest(response paasv1.NodeEnrollmentExchangeResponse) (paasv1.CompleteNodeEnrollmentRequest, error) {
	if ValidateEnrollmentResponse(value, response) != nil {
		return paasv1.CompleteNodeEnrollmentRequest{}, errors.New("node enrollment response is invalid")
	}
	nodeFingerprint, collectorFingerprint, err := value.publicKeyFingerprints()
	if err != nil {
		return paasv1.CompleteNodeEnrollmentRequest{}, err
	}
	request := paasv1.CompleteNodeEnrollmentRequest{
		APIVersion: paasv1.NodeEnrollmentExchangeAPIVersion, Kind: paasv1.NodeEnrollmentCompletionRequestKind,
		EnrollmentID: response.EnrollmentID, InstallationID: response.InstallationID,
		ExecutionTargetID: response.ExecutionTargetID, ExchangeID: response.ExchangeID,
		MachineFingerprint: response.MachineFingerprint, RuntimeContractDigest: response.RuntimeContractDigest,
		ControllerID: response.ControllerID, BindingRef: response.BindingRef,
		NodeListenAddress: response.NodeListenAddress, CollectorEndpoint: response.CollectorEndpoint,
		NodePublicKeyFingerprint: nodeFingerprint, CollectorPublicKeyFingerprint: collectorFingerprint,
	}
	if paasv1.ValidateCompleteNodeEnrollmentRequest(request) != nil {
		return paasv1.CompleteNodeEnrollmentRequest{}, errors.New("node enrollment completion is invalid")
	}
	return request, nil
}

func planFromEnrollment(
	root string,
	bundle release.VerifiedBundle,
	trust release.TrustRoot,
	trustBytes []byte,
	intent EnrollmentIntent,
	response paasv1.NodeEnrollmentExchangeResponse,
) (Plan, error) {
	if _, err := intent.completionRequest(response); err != nil {
		return Plan{}, err
	}
	nodeCertificate, err := enrollmentCertificatePEM(response.NodeCertificate)
	if err != nil {
		return Plan{}, err
	}
	collectorCertificate, err := enrollmentCertificatePEM(response.CollectorCertificate)
	if err != nil {
		clear(nodeCertificate)
		return Plan{}, err
	}
	issuerCertificate, err := enrollmentCertificatePEM(response.IssuerCertificate)
	if err != nil {
		clear(nodeCertificate)
		clear(collectorCertificate)
		return Plan{}, err
	}
	material := Credentials{
		Certificate: nodeCertificate, PrivateKey: bytes.Clone(intent.NodePrivateKey), Trust: issuerCertificate,
		CollectorCertificate: collectorCertificate, CollectorPrivateKey: bytes.Clone(intent.CollectorPrivateKey),
	}
	config := nodeconfig.Configuration{
		APIVersion: nodeconfig.APIVersion, Kind: nodeconfig.ConfigurationKind,
		Identity:     nodev1.Identity{InstallationID: response.InstallationID, ExecutionTargetID: response.ExecutionTargetID},
		ControllerID: response.ControllerID, BindingRef: response.BindingRef,
		ExpectedFingerprint: response.MachineFingerprint, ListenAddress: response.NodeListenAddress,
		CollectorEndpoint: response.CollectorEndpoint,
		StoragePath:       filepath.Join(root, filepath.FromSlash(layout.ExecutorRoot)),
		CertificateFile:   filepath.Join(root, filepath.FromSlash(layout.NodeCertificate)),
		PrivateKeyFile:    filepath.Join(root, filepath.FromSlash(layout.NodePrivateKey)),
		TrustFile:         filepath.Join(root, filepath.FromSlash(layout.NodeTrust)),
		SystemReserve:     nodeconfig.SelfEnrollmentSystemReserve(),
	}
	binding, err := Binding(config, material)
	if err != nil {
		material.Clear()
		return Plan{}, err
	}
	plan := Plan{Root: root, Bundle: bundle, Trust: trust, TrustBytes: trustBytes,
		Configuration: config, Credentials: material, Binding: binding}
	if ValidatePlan(plan) != nil {
		plan.Clear()
		return Plan{}, errors.New("node enrollment plan is invalid")
	}
	return plan, nil
}

func enrollmentIntentCommitment(value EnrollmentIntent) (string, error) {
	encoded, err := json.Marshal(struct {
		Purpose                     string                             `json:"purpose"`
		Join                        paasv1.NodeEnrollmentJoin          `json:"join"`
		ExchangeID                  string                             `json:"exchangeId"`
		MachineFingerprint          string                             `json:"machineFingerprint"`
		RuntimeContractDigest       string                             `json:"runtimeContractDigest"`
		Listener                    paasv1.NodeEnrollmentListenerClaim `json:"listener"`
		NodeCertificateRequest      string                             `json:"nodeCertificateRequest"`
		CollectorCertificateRequest string                             `json:"collectorCertificateRequest"`
	}{
		"MATRIX_NODE_ENROLLMENT_INTENT_V1", value.Join, value.ExchangeID,
		value.MachineFingerprint, value.RuntimeContractDigest, value.Listener,
		value.NodeCertificateRequest, value.CollectorCertificateRequest,
	})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func enrollmentCertificateRequest(private ed25519.PrivateKey, entropy io.Reader) ([]byte, error) {
	request, err := x509.CreateCertificateRequest(entropy, &x509.CertificateRequest{}, private)
	if err != nil || len(request) == 0 || len(request) > 4096 {
		return nil, errors.New("node enrollment certificate request cannot be generated")
	}
	return request, nil
}

func enrollmentPrivateKey(private ed25519.PrivateKey) ([]byte, error) {
	encoded, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return nil, errors.New("node enrollment private key cannot be encoded")
	}
	defer clear(encoded)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}), nil
}

func parseEnrollmentPrivateKey(source []byte) (ed25519.PrivateKey, error) {
	if len(source) == 0 || len(source) > 64*1024 {
		return nil, errors.New("node enrollment private key is invalid")
	}
	block, rest := pem.Decode(source)
	if block == nil || block.Type != "PRIVATE KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("node enrollment private key is invalid")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	private, ok := parsed.(ed25519.PrivateKey)
	if err != nil || !ok || len(private) != ed25519.PrivateKeySize {
		return nil, errors.New("node enrollment private key is invalid")
	}
	return private, nil
}

func publicKeyFromPKIX(source []byte) ed25519.PublicKey {
	parsed, err := x509.ParsePKIXPublicKey(source)
	public, ok := parsed.(ed25519.PublicKey)
	if err != nil || !ok {
		return nil
	}
	return public
}

func (value EnrollmentIntent) publicKeyFingerprints() (string, string, error) {
	nodePublic, collectorPublic, err := paasv1.NodeEnrollmentExchangePublicKeys(value.exchangeRequest(enrollmentPlaceholderCredential()))
	if err != nil {
		return "", "", errors.New("node enrollment public keys are invalid")
	}
	nodeDigest := sha256.Sum256(nodePublic)
	collectorDigest := sha256.Sum256(collectorPublic)
	return "sha256:" + hex.EncodeToString(nodeDigest[:]), "sha256:" + hex.EncodeToString(collectorDigest[:]), nil
}

func enrollmentCertificatePEM(value string) ([]byte, error) {
	encoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(encoded) == 0 || len(encoded) > 16*1024 ||
		base64.RawURLEncoding.EncodeToString(encoded) != value {
		clear(encoded)
		return nil, errors.New("node enrollment certificate is invalid")
	}
	if _, err := x509.ParseCertificate(encoded); err != nil {
		clear(encoded)
		return nil, errors.New("node enrollment certificate is invalid")
	}
	result := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: encoded})
	clear(encoded)
	return result, nil
}

func enrollmentPlaceholderCredential() string {
	return base64.RawURLEncoding.EncodeToString(make([]byte, 32))
}
