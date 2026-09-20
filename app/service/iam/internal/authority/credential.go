package authority

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"time"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
)

var (
	ErrCredentialGeneration  = errors.New("credential generation failed")
	ErrInvalidCredentialType = errors.New("credential type is invalid")
	ErrInvalidCredentialHash = errors.New("stored credential digest is invalid")
	ErrAccessKeyProtection   = errors.New("access key protection failed")
	ErrAccessKeySignature    = errors.New("access key signature verification failed")
	ErrMFARecoveryCode       = errors.New("MFA recovery code verification failed")
)

type CredentialType string

const (
	CredentialSession     CredentialType = "SESSION"
	CredentialService     CredentialType = "SERVICE"
	CredentialRoleSession CredentialType = "ROLE_SESSION"
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
	return value == CredentialSession || value == CredentialService || value == CredentialRoleSession
}

const mfaRecoveryCodePrefix = "mrc1."

// MFARecoveryCodeScope comes from the actual USER and persisted recovery
// batch, never caller selectors. It is not an authenticated identity.
type MFARecoveryCodeScope struct {
	InstallationID string
	AccountID      iamv1.AccountID
	UserID         iamv1.PrincipalID
	BatchID        string
	CodeID         string
}

func (issuer *CredentialIssuer) IssueMFARecoveryCode() (iamv1.Secret, error) {
	if issuer == nil || issuer.entropy == nil {
		return iamv1.Secret{}, ErrCredentialGeneration
	}
	material := make([]byte, 16)
	defer clear(material)
	if _, err := io.ReadFull(issuer.entropy, material); err != nil {
		return iamv1.Secret{}, ErrCredentialGeneration
	}
	secret, err := iamv1.NewSecret(mfaRecoveryCodePrefix + base64.RawURLEncoding.EncodeToString(material))
	if err != nil {
		return iamv1.Secret{}, ErrCredentialGeneration
	}
	return secret, nil
}

// DigestMFARecoveryCode is a one-way verifier for a random 128-bit code.
// It deliberately does not encrypt, register or consume recovery material.
func DigestMFARecoveryCode(scope MFARecoveryCodeScope, code iamv1.Secret) (string, error) {
	fields := []string{scope.InstallationID, string(scope.AccountID), string(scope.UserID), scope.BatchID, scope.CodeID}
	for _, field := range fields {
		if iamv1.ValidateID("recovery.scope", field) != nil {
			return "", ErrMFARecoveryCode
		}
	}
	encoded := code.CopyBytes()
	defer clear(encoded)
	if len(encoded) != len(mfaRecoveryCodePrefix)+22 || !bytes.HasPrefix(encoded, []byte(mfaRecoveryCodePrefix)) {
		return "", ErrMFARecoveryCode
	}
	material := make([]byte, 16)
	defer clear(material)
	if n, err := base64.RawURLEncoding.Strict().Decode(material, encoded[len(mfaRecoveryCodePrefix):]); err != nil || n != len(material) ||
		base64.RawURLEncoding.EncodeToString(material) != string(encoded[len(mfaRecoveryCodePrefix):]) {
		return "", ErrMFARecoveryCode
	}
	digest := sha256.New()
	digest.Write([]byte("matrix.iam.mfa-recovery-code.v1\x00"))
	for _, field := range fields {
		// Validated IDs cannot contain NUL; the final secret has fixed length.
		digest.Write([]byte(field))
		digest.Write([]byte{0})
	}
	digest.Write(material)
	return "sha256:" + hex.EncodeToString(digest.Sum(nil)), nil
}

// VerifyMFARecoveryCode proves possession only. A successful result is not
// proof of current eligibility or non-consumption; those remain transactional
// authority checks. It never issues a Session or clears an MFA requirement.
func VerifyMFARecoveryCode(scope MFARecoveryCodeScope, code iamv1.Secret, storedDigest string) (bool, error) {
	if iamv1.ValidateDigest("recovery.digest", storedDigest) != nil {
		return false, ErrMFARecoveryCode
	}
	actual, err := DigestMFARecoveryCode(scope, code)
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare([]byte(actual), []byte(storedDigest)) == 1, nil
}

const (
	accessKeySecretPrefix = "mak1."
	accessKeySecretFormat = uint8(1)
	accessKeySecretSalt   = "matrix.iam.access-key-secret.hkdf-salt.v1"
)

// AccessKeySecretScope is supplied from authoritative identity, not from the
// encrypted document or the caller. It is not an authorization decision.
type AccessKeySecretScope struct {
	InstallationID string
	AccountID      iamv1.AccountID
	UserID         iamv1.PrincipalID
	AccessKeyID    string
}

// SealedAccessKeySecret is private credential storage material. A future
// persistence adapter must pass its fields explicitly, not export this value
// through ordinary API/log encoding. It contains no recoverable keyring.
type SealedAccessKeySecret struct {
	FormatVersion uint8
	WrappingKeyID string
	Nonce         []byte
	Ciphertext    []byte
}

func (SealedAccessKeySecret) String() string   { return "[REDACTED]" }
func (SealedAccessKeySecret) GoString() string { return "authority.SealedAccessKeySecret{[REDACTED]}" }
func (SealedAccessKeySecret) MarshalJSON() ([]byte, error) {
	return nil, ErrAccessKeyProtection
}
func (*SealedAccessKeySecret) UnmarshalJSON([]byte) error { return ErrAccessKeyProtection }

func (issuer *CredentialIssuer) IssueAccessKeySecret() (iamv1.Secret, error) {
	if issuer == nil || issuer.entropy == nil {
		return iamv1.Secret{}, ErrCredentialGeneration
	}
	random := make([]byte, 32)
	defer clear(random)
	if _, err := io.ReadFull(issuer.entropy, random); err != nil {
		return iamv1.Secret{}, ErrCredentialGeneration
	}
	secret, err := iamv1.NewSecret(accessKeySecretPrefix + base64.RawURLEncoding.EncodeToString(random))
	if err != nil {
		return iamv1.Secret{}, ErrCredentialGeneration
	}
	return secret, nil
}

// SealAccessKeySecret derives a record key with HKDF-SHA256 before using
// random-nonce AES-256-GCM. The caller must reserve a fresh server-generated
// AccessKeyID and seal at most once for that ID/wrapping-key version. Retries
// reuse the sealed result, never this call. This stateless primitive does not
// enforce that lifecycle, allocate IDs, perform admission or own a keyring.
func SealAccessKeySecret(scope AccessKeySecretScope, wrappingKeyID string, wrappingKey []byte, secret iamv1.Secret) (SealedAccessKeySecret, error) {
	aead, aad, err := accessKeySecretCipher(scope, wrappingKeyID, wrappingKey)
	if err != nil {
		return SealedAccessKeySecret{}, err
	}
	plaintext, err := accessKeySecretMaterial(secret)
	defer clear(plaintext)
	if err != nil {
		return SealedAccessKeySecret{}, ErrAccessKeyProtection
	}
	// NewGCMWithRandomNonce prepends its own 96-bit nonce. No caller-supplied
	// nonce is accepted. Lifecycle code still owns the per-record use limit.
	protected := aead.Seal(nil, nil, plaintext, aad)
	defer clear(protected)
	return SealedAccessKeySecret{FormatVersion: accessKeySecretFormat, WrappingKeyID: wrappingKeyID,
		Nonce: bytes.Clone(protected[:12]), Ciphertext: bytes.Clone(protected[12:])}, nil
}

func accessKeySecretMaterial(secret iamv1.Secret) ([]byte, error) {
	encoded := secret.CopyBytes()
	defer clear(encoded)
	if len(encoded) != len(accessKeySecretPrefix)+43 || !bytes.HasPrefix(encoded, []byte(accessKeySecretPrefix)) {
		return nil, ErrAccessKeyProtection
	}
	plaintext := make([]byte, 32)
	if n, err := base64.RawURLEncoding.Strict().Decode(plaintext, encoded[len(accessKeySecretPrefix):]); err != nil || n != len(plaintext) ||
		base64.RawURLEncoding.EncodeToString(plaintext) != string(encoded[len(accessKeySecretPrefix):]) {
		clear(plaintext)
		return nil, ErrAccessKeyProtection
	}
	return plaintext, nil
}

// VerifyAccessKeyRequestSignature proves only possession and exact request
// coverage. The use case must independently bind current service/key scope,
// enforce the database clock, consume the nonce, and run the current PDP.
// In particular this stateless function neither issues nor caches a permit.
func VerifyAccessKeyRequestSignature(secret iamv1.Secret, request iamv1.AccessKeySignedRequest) (bool, error) {
	if iamv1.ValidateAccessKeySignedRequest(request) != nil {
		return false, ErrAccessKeySignature
	}
	material, err := accessKeySecretMaterial(secret)
	defer clear(material)
	if err != nil {
		return false, ErrAccessKeySignature
	}
	encoded, err := iamv1.AccessKeySigningBytes(request.Parameters, request.HTTP)
	defer clear(encoded)
	if err != nil {
		return false, ErrAccessKeySignature
	}
	mac := hmac.New(sha256.New, material)
	_, _ = mac.Write(encoded)
	expected := mac.Sum(nil)
	defer clear(expected)
	signature := request.Signature.CopyBytes()
	defer clear(signature)
	actual := make([]byte, sha256.Size)
	defer clear(actual)
	n, err := base64.RawURLEncoding.Strict().Decode(actual, signature)
	if err != nil || n != len(actual) {
		return false, ErrAccessKeySignature
	}
	return hmac.Equal(expected, actual), nil
}

func ValidateAccessKeySignatureTime(signedAt int64, databaseTime time.Time) error {
	if validateAuthorityTime(databaseTime) != nil {
		return ErrAuthorityUnavailable
	}
	if signedAt <= 0 || signedAt > 253402300799 {
		return ErrUnauthenticated
	}
	signed := time.Unix(signedAt, 0).UTC()
	if signed.Before(databaseTime.Add(-time.Duration(iamv1.AccessKeySignaturePastSeconds)*time.Second)) ||
		signed.After(databaseTime.Add(time.Duration(iamv1.AccessKeySignatureFutureSeconds)*time.Second)) {
		return ErrUnauthenticated
	}
	return nil
}

func OpenAccessKeySecret(scope AccessKeySecretScope, wrappingKeyID string, wrappingKey []byte, sealed SealedAccessKeySecret) (iamv1.Secret, error) {
	if sealed.FormatVersion != accessKeySecretFormat || sealed.WrappingKeyID != wrappingKeyID || len(sealed.Nonce) != 12 || len(sealed.Ciphertext) != 32+16 {
		return iamv1.Secret{}, ErrAccessKeyProtection
	}
	aead, aad, err := accessKeySecretCipher(scope, wrappingKeyID, wrappingKey)
	if err != nil {
		return iamv1.Secret{}, err
	}
	protected := make([]byte, 0, 12+len(sealed.Ciphertext))
	protected = append(protected, sealed.Nonce...)
	protected = append(protected, sealed.Ciphertext...)
	defer clear(protected)
	plaintext, err := aead.Open(nil, nil, protected, aad)
	defer clear(plaintext)
	if err != nil || len(plaintext) != 32 {
		return iamv1.Secret{}, ErrAccessKeyProtection
	}
	secret, err := iamv1.NewSecret(accessKeySecretPrefix + base64.RawURLEncoding.EncodeToString(plaintext))
	if err != nil {
		return iamv1.Secret{}, ErrAccessKeyProtection
	}
	return secret, nil
}

func accessKeySecretCipher(scope AccessKeySecretScope, wrappingKeyID string, wrappingKey []byte) (cipher.AEAD, []byte, error) {
	if len(wrappingKey) != 32 {
		return nil, nil, ErrAccessKeyProtection
	}
	info, aad, err := iamv1.AccessKeySecretContext(scope.InstallationID, scope.AccountID, scope.UserID, scope.AccessKeyID, wrappingKeyID)
	if err != nil {
		return nil, nil, ErrAccessKeyProtection
	}
	recordKey, err := hkdf.Key(sha256.New, wrappingKey, []byte(accessKeySecretSalt), string(info), 32)
	if err != nil {
		return nil, nil, ErrAccessKeyProtection
	}
	defer clear(recordKey)
	block, err := aes.NewCipher(recordKey)
	if err != nil {
		return nil, nil, ErrAccessKeyProtection
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, nil, ErrAccessKeyProtection
	}
	return aead, aad, nil
}
