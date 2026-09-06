// Package enrollmentissuer implements the protected cryptographic boundary for
// browser-created node joins. It never returns the raw one-time credential.
package enrollmentissuer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/url"
	"strings"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/nodeenrollment"
)

const controlPlaneAPIPath = "/api/paas/v1"

type Issuer struct {
	installationID string
	certificate    []byte
	privateKey     ed25519.PrivateKey
	entropy        io.Reader
}

func New(installationID string, certificateDER, privateKeyDER []byte) (*Issuer, error) {
	if paasv1.ValidateID("installationId", installationID) != nil {
		return nil, errors.New("node enrollment issuer installation is invalid")
	}
	certificate, err := x509.ParseCertificate(certificateDER)
	expectedIssuer, issuerErr := paasv1.NodeEnrollmentIssuerURI(installationID)
	if err != nil || certificate == nil || !certificate.BasicConstraintsValid || !certificate.IsCA ||
		certificate.PublicKeyAlgorithm != x509.Ed25519 || certificate.KeyUsage&x509.KeyUsageCertSign == 0 ||
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
	return &Issuer{
		installationID: installationID,
		certificate:    bytes.Clone(certificateDER),
		privateKey:     bytes.Clone(privateKey),
		entropy:        rand.Reader,
	}, nil
}

func (issuer *Issuer) Issue(ctx context.Context, request nodeenrollment.JoinIssueRequest) (nodeenrollment.IssuedJoin, error) {
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
