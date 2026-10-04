package authority

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"io"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
)

var (
	ErrTOTPRejected       = errors.New("TOTP verification failed")
	ErrTOTPSeedProtection = errors.New("TOTP seed protection failed")
)

const (
	totpSeedBytes     = 20
	totpPeriodSeconds = 30
	totpDigits        = 6
	totpMaximumUnix   = int64(253402300799)
	totpMaximumStep   = totpMaximumUnix / totpPeriodSeconds
	totpSeedKeySalt   = "matrix.iam.totp-seed.hkdf-sha256.v1"
)

type TOTPSeedScope struct {
	Installation iamv1.TOTPWrappingScope
	AccountID    iamv1.AccountID
	UserID       iamv1.PrincipalID
	FactorID     string
}

// TOTPSeedProtector owns an immutable copy of this process's validated material.
// It provides no factor lifecycle, registration or recovery authority.
type TOTPSeedProtector struct {
	scope       iamv1.TOTPWrappingScope
	activeKeyID string
	keys        map[string][]byte
}

func (*TOTPSeedProtector) String() string               { return "[REDACTED]" }
func (*TOTPSeedProtector) GoString() string             { return "authority.TOTPSeedProtector{[REDACTED]}" }
func (*TOTPSeedProtector) MarshalJSON() ([]byte, error) { return nil, ErrTOTPSeedProtection }

func NewTOTPSeedProtector(document iamv1.TOTPKeyring) (*TOTPSeedProtector, error) {
	if iamv1.ValidateTOTPKeyring(document) != nil {
		return nil, ErrTOTPSeedProtection
	}
	value := &TOTPSeedProtector{scope: document.Scope, activeKeyID: document.ActiveKeyID, keys: make(map[string][]byte, len(document.Keys))}
	for _, key := range document.Keys {
		encoded := key.KeyMaterial.CopyBytes()
		material := make([]byte, 32)
		n, err := base64.RawURLEncoding.Strict().Decode(material, encoded)
		clear(encoded)
		if err != nil || n != 32 {
			clear(material)
			for _, stored := range value.keys {
				clear(stored)
			}
			return nil, ErrTOTPSeedProtection
		}
		value.keys[key.KeyID] = material
	}
	return value, nil
}

func (value *TOTPSeedProtector) Open(scope TOTPSeedScope, sealed SealedTOTPSeed) (iamv1.Secret, error) {
	if value == nil || scope.Installation != value.scope {
		return iamv1.Secret{}, ErrTOTPSeedProtection
	}
	return OpenTOTPSeed(scope, sealed.KeyID, value.keys[sealed.KeyID], sealed)
}

func (value *TOTPSeedProtector) Seal(scope TOTPSeedScope, seed iamv1.Secret) (SealedTOTPSeed, error) {
	if value == nil || scope.Installation != value.scope {
		return SealedTOTPSeed{}, ErrTOTPSeedProtection
	}
	return SealTOTPSeed(scope, value.activeKeyID, value.keys[value.activeKeyID], seed)
}

// Ciphertext and its metadata stay in the private factor authority. Even a
// sealed seed is not a public factor response, log field or Audit payload.
type SealedTOTPSeed struct {
	FormatVersion uint8
	KeyID         string
	Nonce         []byte
	Ciphertext    []byte
}

func (SealedTOTPSeed) String() string   { return "[REDACTED]" }
func (SealedTOTPSeed) GoString() string { return "authority.SealedTOTPSeed{[REDACTED]}" }
func (SealedTOTPSeed) MarshalJSON() ([]byte, error) {
	return nil, ErrTOTPSeedProtection
}
func (*SealedTOTPSeed) UnmarshalJSON([]byte) error { return ErrTOTPSeedProtection }

// SealTOTPSeed encrypts exactly the fixed 20-byte seed under a per-factor
// HKDF key. It accepts no caller-selected nonce. The lifecycle must reserve
// the immutable factor ID and seal at most once for that factor/key version;
// retries reuse the result, and rewrapping requires the original row CAS.
// This primitive neither registers keys nor grants enrollment/recovery.
func SealTOTPSeed(scope TOTPSeedScope, keyID string, wrappingKey []byte, seed iamv1.Secret) (SealedTOTPSeed, error) {
	aead, aad, err := totpSeedCipher(scope, keyID, wrappingKey)
	if err != nil {
		return SealedTOTPSeed{}, err
	}
	plaintext, err := totpSeedMaterial(seed)
	defer clear(plaintext)
	if err != nil {
		return SealedTOTPSeed{}, ErrTOTPSeedProtection
	}
	protected := aead.Seal(nil, nil, plaintext, aad)
	defer clear(protected)
	return SealedTOTPSeed{FormatVersion: 1, KeyID: keyID,
		Nonce: bytes.Clone(protected[:12]), Ciphertext: bytes.Clone(protected[12:])}, nil
}

func OpenTOTPSeed(scope TOTPSeedScope, keyID string, wrappingKey []byte, sealed SealedTOTPSeed) (iamv1.Secret, error) {
	if sealed.FormatVersion != 1 || sealed.KeyID != keyID || len(sealed.Nonce) != 12 || len(sealed.Ciphertext) != totpSeedBytes+16 {
		return iamv1.Secret{}, ErrTOTPSeedProtection
	}
	aead, aad, err := totpSeedCipher(scope, keyID, wrappingKey)
	if err != nil {
		return iamv1.Secret{}, err
	}
	protected := append(bytes.Clone(sealed.Nonce), sealed.Ciphertext...)
	defer clear(protected)
	plaintext, err := aead.Open(nil, nil, protected, aad)
	defer clear(plaintext)
	if err != nil || len(plaintext) != totpSeedBytes {
		return iamv1.Secret{}, ErrTOTPSeedProtection
	}
	seed, err := iamv1.NewSecret(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(plaintext))
	if err != nil {
		return iamv1.Secret{}, ErrTOTPSeedProtection
	}
	return seed, nil
}

func totpSeedCipher(scope TOTPSeedScope, keyID string, wrappingKey []byte) (cipher.AEAD, []byte, error) {
	if len(wrappingKey) != 32 {
		return nil, nil, ErrTOTPSeedProtection
	}
	info, aad, err := iamv1.TOTPSeedContext(scope.Installation, scope.AccountID, scope.UserID, scope.FactorID, keyID)
	if err != nil {
		return nil, nil, ErrTOTPSeedProtection
	}
	recordKey, err := hkdf.Key(sha256.New, wrappingKey, []byte(totpSeedKeySalt), string(info), 32)
	if err != nil {
		return nil, nil, ErrTOTPSeedProtection
	}
	defer clear(recordKey)
	block, err := aes.NewCipher(recordKey)
	if err != nil {
		return nil, nil, ErrTOTPSeedProtection
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, nil, ErrTOTPSeedProtection
	}
	return aead, aad, nil
}

func (issuer *CredentialIssuer) IssueTOTPSeed() (iamv1.Secret, error) {
	if issuer == nil || issuer.entropy == nil {
		return iamv1.Secret{}, ErrCredentialGeneration
	}
	material := make([]byte, totpSeedBytes)
	defer clear(material)
	if _, err := io.ReadFull(issuer.entropy, material); err != nil {
		return iamv1.Secret{}, ErrCredentialGeneration
	}
	secret, err := iamv1.NewSecret(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(material))
	if err != nil {
		return iamv1.Secret{}, ErrCredentialGeneration
	}
	return secret, nil
}

// VerifyTOTP checks the fixed SHA1/six-digit/30-second profile using the
// authoritative database instant and the factor's locked consumption state.
// -1 means proven never consumed, NOT missing or unknown state. Success is
// only a candidate step: the use case must consume it atomically with its
// authenticated result. This function does not persist, authorize or issue
// anything, and cannot by itself prevent concurrent/restarted replays.
func VerifyTOTP(seed, code iamv1.Secret, databaseTime time.Time, lastConsumedStep int64) (int64, error) {
	if validateAuthorityTime(databaseTime) != nil || databaseTime.Unix() < 0 || databaseTime.Unix() > totpMaximumUnix ||
		lastConsumedStep < -1 || lastConsumedStep > totpMaximumStep {
		return 0, ErrAuthorityUnavailable
	}
	material, err := totpSeedMaterial(seed)
	defer clear(material)
	if err != nil {
		return 0, err
	}
	candidate := code.CopyBytes()
	defer clear(candidate)
	if len(candidate) != totpDigits {
		return 0, ErrTOTPRejected
	}
	for _, digit := range candidate {
		if digit < '0' || digit > '9' {
			return 0, ErrTOTPRejected
		}
	}
	current := databaseTime.Unix() / totpPeriodSeconds
	// Keep canonical input and authoritative time/replay policy here. The
	// library owns RFC4226 HMAC/truncation and constant-time code comparison;
	// its wall-clock boolean TOTP shortcut cannot return a consumable step or
	// detect a collision spanning an already consumed step.
	encodedSeed, passcode := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(material), string(candidate)
	matched, replay := int64(-1), false
	for step := max(int64(0), current-1); step <= min(totpMaximumStep, current+1); step++ {
		valid, err := hotp.ValidateCustom(passcode, uint64(step), encodedSeed, hotp.ValidateOpts{
			Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1, Encoder: otp.EncoderDefault,
		})
		if err != nil {
			return 0, ErrAuthorityUnavailable
		}
		if valid {
			matched = step
			replay = replay || step <= lastConsumedStep
		}
	}
	// A collision spanning an already consumed and a fresh candidate is a
	// replay, not permission to select a more convenient matching time step.
	if matched < 0 || replay {
		return 0, ErrTOTPRejected
	}
	return matched, nil
}

func totpSeedMaterial(seed iamv1.Secret) ([]byte, error) {
	encoded := seed.CopyBytes()
	defer clear(encoded)
	if len(encoded) != 32 {
		return nil, ErrAuthorityUnavailable
	}
	encoding := base32.StdEncoding.WithPadding(base32.NoPadding)
	material := make([]byte, totpSeedBytes)
	n, err := encoding.Decode(material, encoded)
	if err != nil || n != totpSeedBytes || encoding.EncodeToString(material) != string(encoded) {
		clear(material)
		return nil, ErrAuthorityUnavailable
	}
	return material, nil
}
