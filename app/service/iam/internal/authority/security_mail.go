package authority

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"math/big"
	"time"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
)

var (
	ErrSecurityMail                = errors.New("security mail is invalid")
	ErrEmailVerificationRejected   = errors.New("email verification failed")
	ErrEmailVerificationProtection = errors.New("email verification protection failed")
)

const emailVerificationDigits = 8

type SecurityMailKind string

const (
	MailAddressVerification     SecurityMailKind = "ADDRESS_VERIFICATION"
	MailAuthenticatorBound      SecurityMailKind = "AUTHENTICATOR_BOUND"
	MailAuthenticatorReplaced   SecurityMailKind = "AUTHENTICATOR_REPLACED"
	MailAuthenticatorRemoved    SecurityMailKind = "AUTHENTICATOR_REMOVED"
	MailRecoveryStarted         SecurityMailKind = "RECOVERY_STARTED"
	MailAuthenticatorRecovered  SecurityMailKind = "AUTHENTICATOR_RECOVERED"
	MailRecoveryCodesChanged    SecurityMailKind = "RECOVERY_CODES_CHANGED"
	MailSecuritySettingsChanged SecurityMailKind = "SECURITY_SETTINGS_CHANGED"
)

// SecurityMail is a purpose-limited delivery projection, not a recipient
// selector or proof of address ownership. The originating transaction owns
// eligibility, the fixed recipient revision and durable delivery identity.
type SecurityMail struct {
	NotificationID        string
	Recipient             string
	Kind                  SecurityMailKind
	OccurredAt            time.Time
	VerificationCode      iamv1.Secret
	VerificationExpiresAt time.Time
}

func (SecurityMail) String() string               { return "[REDACTED]" }
func (SecurityMail) GoString() string             { return "authority.SecurityMail{[REDACTED]}" }
func (SecurityMail) MarshalJSON() ([]byte, error) { return nil, ErrSecurityMail }
func (*SecurityMail) UnmarshalJSON([]byte) error  { return ErrSecurityMail }

func (message SecurityMail) Validate() error {
	if iamv1.ValidateID("notificationId", message.NotificationID) != nil ||
		iamv1.ValidateSecurityMailAddress(message.Recipient) != nil || !securityMailTime(message.OccurredAt) {
		return ErrSecurityMail
	}
	if message.Kind == MailAddressVerification {
		code := message.VerificationCode.CopyBytes()
		defer clear(code)
		if !validEmailVerificationCode(code) || !securityMailTime(message.VerificationExpiresAt) ||
			!message.VerificationExpiresAt.After(message.OccurredAt) ||
			message.VerificationExpiresAt.Sub(message.OccurredAt) > 10*time.Minute {
			return ErrSecurityMail
		}
		return nil
	}
	if message.VerificationCode.Present() || !message.VerificationExpiresAt.IsZero() {
		return ErrSecurityMail
	}
	switch message.Kind {
	case MailAuthenticatorBound, MailAuthenticatorReplaced, MailAuthenticatorRemoved,
		MailRecoveryStarted, MailAuthenticatorRecovered, MailRecoveryCodesChanged, MailSecuritySettingsChanged:
		return nil
	default:
		return ErrSecurityMail
	}
}

// IssueEmailVerificationCode creates only address-possession material. It is
// not a Session, recovery credential or TOTP. Rejection sampling avoids the
// bias of reducing arbitrary random bytes modulo the decimal code space.
// The workflow still owes durable attempt limits, intent binding and expiry.
func (issuer *CredentialIssuer) IssueEmailVerificationCode() (iamv1.Secret, error) {
	if issuer == nil || issuer.entropy == nil {
		return iamv1.Secret{}, ErrCredentialGeneration
	}
	random, err := rand.Int(issuer.entropy, big.NewInt(100_000_000))
	if err != nil {
		return iamv1.Secret{}, ErrCredentialGeneration
	}
	number := random.Uint64()
	defer clear(random.Bits())
	var code [emailVerificationDigits]byte
	defer clear(code[:])
	for index := len(code) - 1; index >= 0; index-- {
		code[index] = byte(number%10) + '0'
		number /= 10
	}
	secret, err := iamv1.NewSecret(string(code[:]))
	if err != nil {
		return iamv1.Secret{}, ErrCredentialGeneration
	}
	return secret, nil
}

// CompareEmailVerificationCode only compares transient material. Callers must
// have already committed the shared attempt debit and must consume success in
// the locked original-intent transaction; this does not prove either step.
func CompareEmailVerificationCode(expected, candidate iamv1.Secret) (bool, error) {
	reference, supplied := expected.CopyBytes(), candidate.CopyBytes()
	defer clear(reference)
	defer clear(supplied)
	if !validEmailVerificationCode(reference) {
		return false, ErrAuthorityUnavailable
	}
	if !validEmailVerificationCode(supplied) {
		return false, ErrEmailVerificationRejected
	}
	if subtle.ConstantTimeCompare(reference, supplied) != 1 {
		return false, ErrEmailVerificationRejected
	}
	return true, nil
}

func validEmailVerificationCode(code []byte) bool {
	if len(code) != emailVerificationDigits {
		return false
	}
	for _, digit := range code {
		if digit < '0' || digit > '9' {
			return false
		}
	}
	return true
}

func securityMailTime(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value == value.Round(0) &&
		value.Year() >= 1970 && value.Year() <= 9999 && value.Nanosecond()%1000 == 0
}

// The encrypted code belongs only to the original private notification
// intent. Neither ciphertext nor recipient-bearing AAD is an Audit payload.
type SealedEmailVerificationCode struct {
	FormatVersion uint8
	KeyID         string
	Nonce         []byte
	Ciphertext    []byte
}

func (SealedEmailVerificationCode) String() string { return "[REDACTED]" }
func (SealedEmailVerificationCode) GoString() string {
	return "authority.SealedEmailVerificationCode{[REDACTED]}"
}
func (SealedEmailVerificationCode) MarshalJSON() ([]byte, error) {
	return nil, ErrEmailVerificationProtection
}
func (*SealedEmailVerificationCode) UnmarshalJSON([]byte) error {
	return ErrEmailVerificationProtection
}

// SealEmailVerificationCode seals once for a reserved immutable intent/key.
// Retry reuses its committed result, not a new code, nonce, scope or lifetime.
func SealEmailVerificationCode(binding iamv1.EmailVerificationBinding, keyID string, key []byte, code iamv1.Secret) (SealedEmailVerificationCode, error) {
	aead, aad, err := emailVerificationCipher(binding, keyID, key)
	defer clear(aad)
	plaintext := code.CopyBytes()
	defer clear(plaintext)
	if err != nil || !validEmailVerificationCode(plaintext) {
		return SealedEmailVerificationCode{}, ErrEmailVerificationProtection
	}
	protected := aead.Seal(nil, nil, plaintext, aad)
	defer clear(protected)
	return SealedEmailVerificationCode{FormatVersion: 1, KeyID: keyID,
		Nonce: bytes.Clone(protected[:12]), Ciphertext: bytes.Clone(protected[12:])}, nil
}

func OpenEmailVerificationCode(binding iamv1.EmailVerificationBinding, keyID string, key []byte, sealed SealedEmailVerificationCode) (iamv1.Secret, error) {
	if sealed.FormatVersion != 1 || sealed.KeyID != keyID || len(sealed.Nonce) != 12 || len(sealed.Ciphertext) != emailVerificationDigits+16 {
		return iamv1.Secret{}, ErrEmailVerificationProtection
	}
	aead, aad, err := emailVerificationCipher(binding, keyID, key)
	defer clear(aad)
	if err != nil {
		return iamv1.Secret{}, ErrEmailVerificationProtection
	}
	protected := append(bytes.Clone(sealed.Nonce), sealed.Ciphertext...)
	defer clear(protected)
	plaintext, err := aead.Open(nil, nil, protected, aad)
	defer clear(plaintext)
	if err != nil || !validEmailVerificationCode(plaintext) {
		return iamv1.Secret{}, ErrEmailVerificationProtection
	}
	secret, err := iamv1.NewSecret(string(plaintext))
	if err != nil {
		return iamv1.Secret{}, ErrEmailVerificationProtection
	}
	return secret, nil
}

func emailVerificationCipher(binding iamv1.EmailVerificationBinding, keyID string, key []byte) (cipher.AEAD, []byte, error) {
	if len(key) != 32 {
		return nil, nil, ErrEmailVerificationProtection
	}
	info, aad, err := iamv1.EmailVerificationCipherContext(binding, keyID)
	defer clear(info)
	if err != nil {
		return nil, nil, ErrEmailVerificationProtection
	}
	recordKey, err := hkdf.Key(sha256.New, key, []byte("matrix.iam.email-verification.hkdf-sha256.v1"), string(info), 32)
	if err != nil {
		clear(aad)
		return nil, nil, ErrEmailVerificationProtection
	}
	defer clear(recordKey)
	block, err := aes.NewCipher(recordKey)
	if err != nil {
		clear(aad)
		return nil, nil, ErrEmailVerificationProtection
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		clear(aad)
		return nil, nil, ErrEmailVerificationProtection
	}
	return aead, aad, nil
}
