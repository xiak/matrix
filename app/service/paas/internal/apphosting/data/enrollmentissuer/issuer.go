// Package enrollmentissuer implements the protected cryptographic boundary for
// browser-created node joins. It never returns the raw one-time credential.
package enrollmentissuer

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"

	nodev1 "github.com/xiak/matrix/api/adapter/node/v1"
	"github.com/xiak/matrix/api/contractjson"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/nodeenrollment"
)

const controlPlaneAPIPath = "/api/paas/v1"

var nodeBindingPattern = regexp.MustCompile(`^node-binding-[0-9a-f]{32}$`)

type Issuer struct {
	installationID string
	certificate    []byte
	parsed         *x509.Certificate
	privateKey     ed25519.PrivateKey
	sealKey        []byte
	sealKeyID      string
	entropy        io.Reader
}

func New(installationID string, certificateDER, privateKeyDER []byte) (*Issuer, error) {
	if paasv1.ValidateID("installationId", installationID) != nil {
		return nil, errors.New("node enrollment issuer installation is invalid")
	}
	certificate, err := x509.ParseCertificate(certificateDER)
	expectedIssuer, issuerErr := paasv1.NodeEnrollmentIssuerURI(installationID)
	if err != nil || certificate == nil || !certificate.BasicConstraintsValid || !certificate.IsCA ||
		!certificate.MaxPathLenZero || certificate.MaxPathLen != 0 ||
		certificate.PublicKeyAlgorithm != x509.Ed25519 || certificate.SignatureAlgorithm != x509.PureEd25519 ||
		certificate.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageDigitalSignature ||
		certificate.CheckSignatureFrom(certificate) != nil ||
		issuerErr != nil || len(certificate.URIs) != 1 || certificate.URIs[0].String() != expectedIssuer.String() {
		return nil, errors.New("node enrollment issuer certificate is invalid")
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(privateKeyDER)
	privateKey, ok := parsedKey.(ed25519.PrivateKey)
	publicKey, publicOK := certificate.PublicKey.(ed25519.PublicKey)
	if err != nil || !ok || !publicOK || len(privateKey) != ed25519.PrivateKeySize ||
		!bytes.Equal(privateKey.Public().(ed25519.PublicKey), publicKey) {
		return nil, errors.New("node enrollment issuer private key is invalid")
	}
	seed := privateKey.Seed()
	sealKey := make([]byte, 32)
	_, err = io.ReadFull(
		hkdf.New(sha256.New, seed, nil, []byte("matrix-node-enrollment-result-seal-v1\x00"+installationID)),
		sealKey,
	)
	clear(seed)
	if err != nil {
		clear(sealKey)
		return nil, errors.New("node enrollment result seal key cannot be derived")
	}
	sealKeyDigest := sha256.Sum256(sealKey)
	return &Issuer{
		installationID: installationID,
		certificate:    bytes.Clone(certificateDER),
		parsed:         certificate,
		privateKey:     bytes.Clone(privateKey),
		sealKey:        sealKey,
		sealKeyID:      "sha256:" + hex.EncodeToString(sealKeyDigest[:]),
		entropy:        rand.Reader,
	}, nil
}

func (issuer *Issuer) IssueJoin(ctx context.Context, request nodeenrollment.JoinIssueRequest) (nodeenrollment.IssuedJoin, error) {
	if issuer == nil || issuer.entropy == nil || ctx == nil ||
		paasv1.ValidateID("enrollmentId", string(request.EnrollmentID)) != nil ||
		paasv1.ValidateID("executionTargetId", string(request.ExecutionTargetID)) != nil ||
		request.ExpiresAt.IsZero() ||
		nodeenrollment.ValidateControlPlaneBaseURL(request.ControlPlaneBaseURL) != nil {
		return nodeenrollment.IssuedJoin{}, nodeenrollment.ErrInvalidArgument
	}
	if err := ctx.Err(); err != nil {
		return nodeenrollment.IssuedJoin{}, err
	}
	wrappingKey, err := decodeWrappingKey(request.WrappingPublicKey)
	if err != nil {
		return nodeenrollment.IssuedJoin{}, nodeenrollment.ErrInvalidArgument
	}
	credential := make([]byte, 32)
	defer clear(credential)
	salt := make([]byte, 32)
	if _, err := io.ReadFull(issuer.entropy, credential); err != nil {
		clear(salt)
		return nodeenrollment.IssuedJoin{}, nodeenrollment.ErrUnavailable
	}
	if _, err := io.ReadFull(issuer.entropy, salt); err != nil {
		clear(salt)
		return nodeenrollment.IssuedJoin{}, nodeenrollment.ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		clear(salt)
		return nodeenrollment.IssuedJoin{}, err
	}
	label := []byte("matrix-node-enrollment-v1\x00" + issuer.installationID + "\x00" + string(request.EnrollmentID))
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), issuer.entropy, wrappingKey, credential, label)
	if err != nil {
		clear(salt)
		return nodeenrollment.IssuedJoin{}, nodeenrollment.ErrUnavailable
	}
	defer clear(ciphertext)
	credentialDigest := sha256.Sum256(credential)
	verifierInput := make([]byte, 0, len(salt)+len(credential))
	verifierInput = append(verifierInput, salt...)
	verifierInput = append(verifierInput, credential...)
	verifierDigest := sha256.Sum256(verifierInput)
	clear(verifierInput)

	endpoint, err := url.Parse(request.ControlPlaneBaseURL)
	if err != nil || endpoint.Path != controlPlaneAPIPath {
		clear(salt)
		return nodeenrollment.IssuedJoin{}, nodeenrollment.ErrInvalidArgument
	}
	endpoint.Path += "/node-enrollments/" + url.PathEscape(string(request.EnrollmentID)) + "/exchange"
	join := paasv1.NodeEnrollmentJoin{
		APIVersion: paasv1.NodeEnrollmentJoinAPIVersion, Kind: paasv1.NodeEnrollmentJoinKind,
		EnrollmentID: request.EnrollmentID, InstallationID: issuer.installationID,
		ExecutionTargetID: request.ExecutionTargetID, ControlPlaneURL: endpoint.String(),
		CredentialDigest: "sha256:" + hex.EncodeToString(credentialDigest[:]), ExpiresAt: request.ExpiresAt,
		IssuerCertificate:  base64.RawURLEncoding.EncodeToString(issuer.certificate),
		SignatureAlgorithm: paasv1.NodeJoinSignatureEd25519,
	}
	commitment, err := paasv1.NodeEnrollmentJoinSigningBytes(join)
	if err != nil {
		clear(salt)
		return nodeenrollment.IssuedJoin{}, nodeenrollment.ErrInvalidArgument
	}
	join.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(issuer.privateKey, commitment))
	issued := nodeenrollment.IssuedJoin{
		Join: join,
		WrappedCredential: paasv1.WrappedJoinCredential{
			Algorithm:  paasv1.JoinCredentialRSAOAEP256,
			Ciphertext: base64.RawURLEncoding.EncodeToString(ciphertext),
		},
		CredentialSalt: salt, CredentialVerifier: "sha256:" + hex.EncodeToString(verifierDigest[:]),
	}
	if nodeenrollment.ValidateIssuedJoin(issued, request) != nil {
		issued.Clear()
		return nodeenrollment.IssuedJoin{}, nodeenrollment.ErrUnavailable
	}
	return issued, nil
}

func (issuer *Issuer) IssueExchange(
	ctx context.Context,
	request nodeenrollment.ExchangeIssueRequest,
) (nodeenrollment.IssuedExchange, error) {
	nodePublicKey, collectorPublicKey, peer, err := issuer.validateExchangeIssue(ctx, request)
	if err != nil {
		return nodeenrollment.IssuedExchange{}, err
	}
	if err := ctx.Err(); err != nil {
		return nodeenrollment.IssuedExchange{}, err
	}
	identity := nodev1.Identity{
		InstallationID: request.InstallationID, ExecutionTargetID: request.ExecutionTargetID,
	}
	nodeURI, nodeURIErr := nodev1.NodeURI(identity)
	collectorURI, collectorURIErr := nodev1.CollectorURI(identity)
	if nodeURIErr != nil || collectorURIErr != nil {
		return nodeenrollment.IssuedExchange{}, nodeenrollment.ErrInvalidArgument
	}
	nodeAddress := net.JoinHostPort(peer.String(), strconv.Itoa(int(request.Listener.ManagementPort)))
	collectorEndpoint := "https://127.0.0.1:" + strconv.Itoa(int(request.Listener.CollectorPort))
	nodeCertificate, err := issuer.issueRoleCertificate(
		request, "node", nodeURI, peer, nodePublicKey,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	)
	if err != nil {
		return nodeenrollment.IssuedExchange{}, err
	}
	defer clear(nodeCertificate)
	collectorCertificate, err := issuer.issueRoleCertificate(
		request, "collector", collectorURI, netip.MustParseAddr("127.0.0.1"), collectorPublicKey,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	)
	if err != nil {
		return nodeenrollment.IssuedExchange{}, err
	}
	defer clear(collectorCertificate)
	response := paasv1.NodeEnrollmentExchangeResponse{
		APIVersion: paasv1.NodeEnrollmentExchangeAPIVersion, Kind: paasv1.NodeEnrollmentExchangeResponseKind,
		EnrollmentID: request.EnrollmentID, InstallationID: request.InstallationID,
		ExecutionTargetID: request.ExecutionTargetID, ExchangeID: request.ExchangeID,
		MachineFingerprint: request.MachineFingerprint, RuntimeContractDigest: request.RuntimeContractDigest,
		ControllerID: request.ControllerID, BindingRef: request.BindingRef,
		NodeListenAddress: nodeAddress, CollectorEndpoint: collectorEndpoint,
		NodeCertificate:      base64.RawURLEncoding.EncodeToString(nodeCertificate),
		CollectorCertificate: base64.RawURLEncoding.EncodeToString(collectorCertificate),
		IssuerCertificate:    base64.RawURLEncoding.EncodeToString(issuer.certificate),
		CertificateNotBefore: request.CertificateNotBefore, CertificateNotAfter: request.CertificateNotAfter,
	}
	if paasv1.ValidateNodeEnrollmentExchangeResponse(response) != nil {
		return nodeenrollment.IssuedExchange{}, nodeenrollment.ErrUnavailable
	}
	sealed, err := issuer.sealExchangeResult(ctx, response)
	if err != nil {
		return nodeenrollment.IssuedExchange{}, err
	}
	return nodeenrollment.IssuedExchange{Response: response, Sealed: sealed}, nil
}

func (issuer *Issuer) OpenExchangeResult(
	ctx context.Context,
	exchange nodeenrollment.StoredExchange,
	sealed nodeenrollment.SealedExchangeResult,
) (paasv1.NodeEnrollmentExchangeResponse, error) {
	if issuer == nil || issuer.entropy == nil || ctx == nil || exchange.InstallationID != issuer.installationID ||
		nodeenrollment.ValidateStoredExchange(exchange) != nil || nodeenrollment.ValidateSealedExchangeResult(sealed) != nil ||
		sealed.KeyID != issuer.sealKeyID {
		return paasv1.NodeEnrollmentExchangeResponse{}, nodeenrollment.ErrInvalidArgument
	}
	if err := ctx.Err(); err != nil {
		return paasv1.NodeEnrollmentExchangeResponse{}, err
	}
	nonce, nonceErr := base64.RawURLEncoding.Strict().DecodeString(sealed.Nonce)
	ciphertext, ciphertextErr := base64.RawURLEncoding.Strict().DecodeString(sealed.Ciphertext)
	if nonceErr != nil || ciphertextErr != nil {
		clear(nonce)
		clear(ciphertext)
		return paasv1.NodeEnrollmentExchangeResponse{}, nodeenrollment.ErrInvalidArgument
	}
	defer clear(nonce)
	defer clear(ciphertext)
	block, err := aes.NewCipher(issuer.sealKey)
	if err != nil {
		return paasv1.NodeEnrollmentExchangeResponse{}, nodeenrollment.ErrUnavailable
	}
	aead, err := cipher.NewGCM(block)
	if err != nil || len(nonce) != aead.NonceSize() {
		return paasv1.NodeEnrollmentExchangeResponse{}, nodeenrollment.ErrUnavailable
	}
	aad, err := storedExchangeAAD(exchange)
	if err != nil {
		return paasv1.NodeEnrollmentExchangeResponse{}, nodeenrollment.ErrInvalidArgument
	}
	defer clear(aad)
	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil || len(plaintext) == 0 || len(plaintext) > 64*1024 {
		clear(plaintext)
		return paasv1.NodeEnrollmentExchangeResponse{}, nodeenrollment.ErrInvalidArgument
	}
	defer clear(plaintext)
	var response paasv1.NodeEnrollmentExchangeResponse
	if contractjson.DecodeObjectBytes(plaintext, 64*1024, &response) != nil ||
		paasv1.ValidateNodeEnrollmentExchangeResponse(response) != nil ||
		exchangeResultDigest(plaintext) != exchange.ResultDigest ||
		!exchangeResponseMatchesStored(response, exchange) {
		return paasv1.NodeEnrollmentExchangeResponse{}, nodeenrollment.ErrInvalidArgument
	}
	return response, nil
}

func (issuer *Issuer) validateExchangeIssue(
	ctx context.Context,
	request nodeenrollment.ExchangeIssueRequest,
) (ed25519.PublicKey, ed25519.PublicKey, netip.Addr, error) {
	if issuer == nil || issuer.entropy == nil || issuer.parsed == nil || len(issuer.sealKey) != 32 || ctx == nil ||
		request.InstallationID != issuer.installationID ||
		paasv1.ValidateID("installationId", request.InstallationID) != nil ||
		paasv1.ValidateID("enrollmentId", string(request.EnrollmentID)) != nil ||
		paasv1.ValidateID("executionTargetId", string(request.ExecutionTargetID)) != nil ||
		paasv1.ValidateID("exchangeId", request.ExchangeID) != nil ||
		paasv1.ValidateDigest("machineFingerprint", request.MachineFingerprint) != nil ||
		paasv1.ValidateDigest("runtimeContractDigest", request.RuntimeContractDigest) != nil ||
		paasv1.ValidateID("controllerId", request.ControllerID) != nil || !nodeBindingPattern.MatchString(request.BindingRef) ||
		request.Listener.ManagementPort < paasv1.MinimumNodeEnrollmentListenerPort ||
		request.Listener.CollectorPort < paasv1.MinimumNodeEnrollmentListenerPort ||
		request.Listener.ManagementPort == request.Listener.CollectorPort ||
		request.CertificateNotBefore.Location() != time.UTC || request.CertificateNotAfter.Location() != time.UTC ||
		request.CertificateNotBefore.Nanosecond() != 0 || request.CertificateNotAfter.Nanosecond() != 0 ||
		!request.CertificateNotAfter.After(request.CertificateNotBefore) ||
		request.CertificateNotAfter.Sub(request.CertificateNotBefore) > paasv1.MaximumNodeEnrollmentCertificateLifetime ||
		request.CertificateNotBefore.Before(issuer.parsed.NotBefore) || request.CertificateNotAfter.After(issuer.parsed.NotAfter) {
		return nil, nil, netip.Addr{}, nodeenrollment.ErrInvalidArgument
	}
	peer, err := netip.ParseAddr(request.ObservedPeerAddress)
	if err != nil || peer.Is4In6() || !peer.IsPrivate() || peer.IsLoopback() || peer.IsUnspecified() ||
		peer.IsMulticast() || peer.IsLinkLocalUnicast() || peer.String() != request.ObservedPeerAddress {
		return nil, nil, netip.Addr{}, nodeenrollment.ErrInvalidArgument
	}
	nodeKey, nodeErr := parseExchangePublicKey(request.NodePublicKey)
	collectorKey, collectorErr := parseExchangePublicKey(request.CollectorPublicKey)
	if nodeErr != nil || collectorErr != nil || bytes.Equal(nodeKey, collectorKey) {
		return nil, nil, netip.Addr{}, nodeenrollment.ErrInvalidArgument
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, netip.Addr{}, err
	}
	return nodeKey, collectorKey, peer, nil
}

func (issuer *Issuer) issueRoleCertificate(
	request nodeenrollment.ExchangeIssueRequest,
	role string,
	identityURI string,
	address netip.Addr,
	publicKey ed25519.PublicKey,
	usages []x509.ExtKeyUsage,
) ([]byte, error) {
	uri, err := url.Parse(identityURI)
	if err != nil || uri.String() != identityURI || !address.IsValid() || len(publicKey) != ed25519.PublicKeySize {
		return nil, nodeenrollment.ErrInvalidArgument
	}
	serialInput := []byte(
		"matrix-node-enrollment-leaf/v1\x00" + request.InstallationID + "\x00" +
			string(request.EnrollmentID) + "\x00" + request.ExchangeID + "\x00" + role + "\x00",
	)
	serialInput = append(serialInput, publicKey...)
	serialDigest := sha256.Sum256(serialInput)
	clear(serialInput)
	serial := new(big.Int).SetBytes(serialDigest[:16])
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	template := &x509.Certificate{
		SerialNumber: serial, NotBefore: request.CertificateNotBefore, NotAfter: request.CertificateNotAfter,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: usages, URIs: []*url.URL{uri}, IPAddresses: []net.IP{net.IP(address.AsSlice())},
	}
	certificate, err := x509.CreateCertificate(issuer.entropy, template, issuer.parsed, publicKey, issuer.privateKey)
	if err != nil {
		return nil, nodeenrollment.ErrUnavailable
	}
	return certificate, nil
}

func (issuer *Issuer) sealExchangeResult(
	ctx context.Context,
	response paasv1.NodeEnrollmentExchangeResponse,
) (nodeenrollment.SealedExchangeResult, error) {
	plaintext, err := json.Marshal(response)
	if err != nil || len(plaintext) == 0 || len(plaintext) > 64*1024 {
		clear(plaintext)
		return nodeenrollment.SealedExchangeResult{}, nodeenrollment.ErrUnavailable
	}
	defer clear(plaintext)
	aad, err := responseExchangeAAD(response)
	if err != nil {
		return nodeenrollment.SealedExchangeResult{}, nodeenrollment.ErrUnavailable
	}
	defer clear(aad)
	block, err := aes.NewCipher(issuer.sealKey)
	if err != nil {
		return nodeenrollment.SealedExchangeResult{}, nodeenrollment.ErrUnavailable
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nodeenrollment.SealedExchangeResult{}, nodeenrollment.ErrUnavailable
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(issuer.entropy, nonce); err != nil {
		clear(nonce)
		return nodeenrollment.SealedExchangeResult{}, nodeenrollment.ErrUnavailable
	}
	defer clear(nonce)
	if err := ctx.Err(); err != nil {
		return nodeenrollment.SealedExchangeResult{}, err
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, aad)
	defer clear(ciphertext)
	sealed := nodeenrollment.SealedExchangeResult{
		Algorithm: nodeenrollment.ExchangeResultSealAlgorithm, KeyID: issuer.sealKeyID,
		Nonce: base64.RawURLEncoding.EncodeToString(nonce), Ciphertext: base64.RawURLEncoding.EncodeToString(ciphertext),
	}
	if nodeenrollment.ValidateSealedExchangeResult(sealed) != nil {
		return nodeenrollment.SealedExchangeResult{}, nodeenrollment.ErrUnavailable
	}
	return sealed, nil
}

type exchangeResultAADDocument struct {
	APIVersion            string            `json:"apiVersion"`
	Kind                  string            `json:"kind"`
	InstallationID        string            `json:"installationId"`
	EnrollmentID          paasv1.ResourceID `json:"enrollmentId"`
	ExecutionTargetID     paasv1.ResourceID `json:"executionTargetId"`
	ExchangeID            string            `json:"exchangeId"`
	MachineFingerprint    string            `json:"machineFingerprint"`
	RuntimeContractDigest string            `json:"runtimeContractDigest"`
	ControllerID          string            `json:"controllerId"`
	BindingRef            string            `json:"bindingRef"`
	NodeListenAddress     string            `json:"nodeListenAddress"`
	CollectorEndpoint     string            `json:"collectorEndpoint"`
}

func responseExchangeAAD(value paasv1.NodeEnrollmentExchangeResponse) ([]byte, error) {
	return encodeExchangeAAD(exchangeResultAADDocument{
		APIVersion: nodeenrollment.StoredExchangeAPIVersion, Kind: nodeenrollment.StoredExchangeKind,
		InstallationID: value.InstallationID, EnrollmentID: value.EnrollmentID,
		ExecutionTargetID: value.ExecutionTargetID, ExchangeID: value.ExchangeID,
		MachineFingerprint: value.MachineFingerprint, RuntimeContractDigest: value.RuntimeContractDigest,
		ControllerID: value.ControllerID, BindingRef: value.BindingRef,
		NodeListenAddress: value.NodeListenAddress, CollectorEndpoint: value.CollectorEndpoint,
	})
}

func storedExchangeAAD(value nodeenrollment.StoredExchange) ([]byte, error) {
	return encodeExchangeAAD(exchangeResultAADDocument{
		APIVersion: value.APIVersion, Kind: value.Kind,
		InstallationID: value.InstallationID, EnrollmentID: value.EnrollmentID,
		ExecutionTargetID: value.ExecutionTargetID, ExchangeID: value.ExchangeID,
		MachineFingerprint: value.MachineFingerprint, RuntimeContractDigest: value.RuntimeContractDigest,
		ControllerID: value.ControllerID, BindingRef: value.BindingRef,
		NodeListenAddress: value.NodeListenAddress, CollectorEndpoint: value.CollectorEndpoint,
	})
}

func encodeExchangeAAD(value exchangeResultAADDocument) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) > 4096 {
		clear(encoded)
		return nil, errors.New("node enrollment exchange AAD is invalid")
	}
	return encoded, nil
}

func exchangeResultDigest(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func exchangeResponseMatchesStored(
	response paasv1.NodeEnrollmentExchangeResponse,
	exchange nodeenrollment.StoredExchange,
) bool {
	if response.EnrollmentID != exchange.EnrollmentID || response.InstallationID != exchange.InstallationID ||
		response.ExecutionTargetID != exchange.ExecutionTargetID || response.ExchangeID != exchange.ExchangeID ||
		response.MachineFingerprint != exchange.MachineFingerprint ||
		response.RuntimeContractDigest != exchange.RuntimeContractDigest || response.ControllerID != exchange.ControllerID ||
		response.BindingRef != exchange.BindingRef || response.NodeListenAddress != exchange.NodeListenAddress ||
		response.CollectorEndpoint != exchange.CollectorEndpoint {
		return false
	}
	nodeCertificate, nodeErr := decodeExchangeCertificate(response.NodeCertificate)
	collectorCertificate, collectorErr := decodeExchangeCertificate(response.CollectorCertificate)
	return nodeErr == nil && collectorErr == nil &&
		base64.RawURLEncoding.EncodeToString(nodeCertificate.RawSubjectPublicKeyInfo) == exchange.NodePublicKey &&
		base64.RawURLEncoding.EncodeToString(collectorCertificate.RawSubjectPublicKeyInfo) == exchange.CollectorPublicKey
}

func decodeExchangeCertificate(value string) (*x509.Certificate, error) {
	encoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(encoded) != value {
		return nil, errors.New("node enrollment exchange certificate is invalid")
	}
	certificate, err := x509.ParseCertificate(encoded)
	if err != nil {
		return nil, errors.New("node enrollment exchange certificate is invalid")
	}
	return certificate, nil
}

func parseExchangePublicKey(encoded []byte) (ed25519.PublicKey, error) {
	parsed, err := x509.ParsePKIXPublicKey(encoded)
	publicKey, ok := parsed.(ed25519.PublicKey)
	canonical, marshalErr := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil || !ok || len(publicKey) != ed25519.PublicKeySize || marshalErr != nil || !bytes.Equal(canonical, encoded) {
		return nil, errors.New("node enrollment exchange public key is invalid")
	}
	return publicKey, nil
}

func decodeWrappingKey(value string) (*rsa.PublicKey, error) {
	if value == "" || len(value) > 16*1024 || strings.ContainsAny(value, "=\r\n\t ") {
		return nil, errors.New("wrapping public key is invalid")
	}
	encoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(encoded) != value {
		return nil, errors.New("wrapping public key is invalid")
	}
	parsed, err := x509.ParsePKIXPublicKey(encoded)
	key, ok := parsed.(*rsa.PublicKey)
	if err != nil || !ok || key.N == nil || key.N.BitLen() != 3072 || key.E != 65537 {
		return nil, errors.New("wrapping public key is invalid")
	}
	return key, nil
}
