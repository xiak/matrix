package authority

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
)

var (
	ErrCredentialGeneration  = errors.New("credential generation failed")
	ErrInvalidCredentialType = errors.New("credential type is invalid")
	ErrInvalidCredentialHash = errors.New("stored credential digest is invalid")
)

type CredentialType string

const (
	CredentialSession CredentialType = "SESSION"
	CredentialService CredentialType = "SERVICE"
)

type CredentialIssuer struct {
	entropy io.Reader
}

type IssuedCredential struct {
	Credential         iamv1.Secret
	LookupDigest       string
	VerificationDigest string
}

func NewCredentialIssuer(entropy io.Reader) *CredentialIssuer {
	if entropy == nil {
		entropy = rand.Reader
	}
	return &CredentialIssuer{entropy: entropy}
}

func (issuer *CredentialIssuer) Issue(
	credentialType CredentialType,
	bindingID string,
) (IssuedCredential, error) {
	if issuer == nil || issuer.entropy == nil || !knownCredentialType(credentialType) ||
		iamv1.ValidateID("credential.bindingId", bindingID) != nil {
		return IssuedCredential{}, ErrCredentialGeneration
	}
	random := make([]byte, 32)
	if _, err := io.ReadFull(issuer.entropy, random); err != nil {
		clear(random)
		return IssuedCredential{}, ErrCredentialGeneration
	}
	encoded := "mx1." + base64.RawURLEncoding.EncodeToString(random)
	clear(random)
	credential, err := iamv1.NewSecret(encoded)
	if err != nil {
		return IssuedCredential{}, ErrCredentialGeneration
	}
	lookupDigest, err := LookupCredentialDigest(credentialType, credential)
	if err != nil {
		return IssuedCredential{}, ErrCredentialGeneration
	}
	verificationDigest, err := DigestCredential(credentialType, bindingID, credential)
	if err != nil {
		return IssuedCredential{}, ErrCredentialGeneration
	}
	return IssuedCredential{
		Credential: credential, LookupDigest: lookupDigest, VerificationDigest: verificationDigest,
	}, nil
}

func LookupCredentialDigest(
	credentialType CredentialType,
	credential iamv1.Secret,
) (string, error) {
	if !knownCredentialType(credentialType) {
		return "", ErrInvalidCredentialType
	}
	if !credential.Present() {
		return "", ErrInvalidCredentialHash
	}
	plaintext := credential.CopyBytes()
	defer clear(plaintext)
	digest := sha256.New()
	digest.Write([]byte("matrix.iam.credential-lookup.v1\x00"))
	digest.Write([]byte(credentialType))
	digest.Write([]byte{0})
	digest.Write(plaintext)
	return "sha256:" + hex.EncodeToString(digest.Sum(nil)), nil
}

func DigestCredential(
	credentialType CredentialType,
	bindingID string,
	credential iamv1.Secret,
) (string, error) {
	if !knownCredentialType(credentialType) {
		return "", ErrInvalidCredentialType
	}
	if iamv1.ValidateID("credential.bindingId", bindingID) != nil || !credential.Present() {
		return "", ErrInvalidCredentialHash
	}
	plaintext := credential.CopyBytes()
	defer clear(plaintext)
	digest := sha256.New()
	digest.Write([]byte("matrix.iam.credential.v1\x00"))
	digest.Write([]byte(credentialType))
	digest.Write([]byte{0})
	digest.Write([]byte(bindingID))
	digest.Write([]byte{0})
	digest.Write(plaintext)
	return "sha256:" + hex.EncodeToString(digest.Sum(nil)), nil
}

func VerifyCredential(
	credentialType CredentialType,
	bindingID string,
	credential iamv1.Secret,
	storedDigest string,
) (bool, error) {
	if iamv1.ValidateDigest("credential.digest", storedDigest) != nil {
		return false, ErrInvalidCredentialHash
	}
	actual, err := DigestCredential(credentialType, bindingID, credential)
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare([]byte(actual), []byte(storedDigest)) == 1, nil
}

func knownCredentialType(value CredentialType) bool {
	return value == CredentialSession || value == CredentialService
}
