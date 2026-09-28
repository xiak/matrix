package authority

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"golang.org/x/crypto/argon2"
)

var (
	ErrWeakPassword        = errors.New("password does not satisfy the password requirements")
	ErrInvalidPasswordHash = errors.New("stored password hash is invalid")
	ErrPasswordHashing     = errors.New("password hashing failed")
)

const (
	passwordMemoryKiB         = 64 * 1024
	passwordIterations        = 3
	passwordParallelism       = 1
	passwordSaltBytes         = 16
	passwordKeyBytes          = 32
	minimumPasswordCodePoints = 15
	maximumPasswordCodePoints = 128
	maximumPasswordBytes      = 512
)

// This bounded offline asset carries its original MIT notice and fixed-source
// attribution. It contains only entries not already rejected by the length
// floor. It is not an online breach query or a complete compromised corpus.
//
//go:embed password_blocklist.txt
var commonPasswordDocument string

var commonPasswords = mustLoadCommonPasswords()

func mustLoadCommonPasswords() []string {
	values, err := parseCommonPasswords(commonPasswordDocument)
	if err != nil {
		// A missing/modified build asset must never silently disable admission.
		panic("invalid embedded IAM password blocklist")
	}
	return values
}

func parseCommonPasswords(document string) ([]string, error) {
	if fmt.Sprintf("%x", sha256.Sum256([]byte(document))) != "76031dba001805005624a4ef1ab5479a81d4b405fa87921cdca50cc676f3d699" {
		return nil, errors.New("embedded password blocklist is invalid")
	}
	_, entries, present := strings.Cut(document, "\n# Passwords\n")
	if !present || !strings.HasSuffix(entries, "\n") {
		return nil, errors.New("embedded password blocklist is invalid")
	}
	return strings.Split(strings.TrimSuffix(entries, "\n"), "\n"), nil
}

type PasswordHash string

// PasswordHasher owns the single accepted Phase 1 Argon2id profile.
type PasswordHasher struct {
	entropy io.Reader
}

func NewPasswordHasher(entropy io.Reader) *PasswordHasher {
	if entropy == nil {
		entropy = rand.Reader
	}
	return &PasswordHasher{entropy: entropy}
}

func (hasher *PasswordHasher) Hash(password iamv1.Secret) (PasswordHash, error) {
	if hasher == nil || hasher.entropy == nil {
		return "", ErrPasswordHashing
	}
	if err := ValidatePassword(password); err != nil {
		return "", err
	}
	plaintext := password.CopyBytes()
	defer clear(plaintext)
	salt := make([]byte, passwordSaltBytes)
	if _, err := io.ReadFull(hasher.entropy, salt); err != nil {
		clear(salt)
		return "", ErrPasswordHashing
	}
	derived := argon2.IDKey(
		plaintext,
		salt,
		passwordIterations,
		passwordMemoryKiB,
		passwordParallelism,
		passwordKeyBytes,
	)
	encoded := fmt.Sprintf(
		"$matrix-iam-v1$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		passwordMemoryKiB,
		passwordIterations,
		passwordParallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(derived),
	)
	clear(salt)
	clear(derived)
	return PasswordHash(encoded), nil
}

// ValidatePassword applies the new-password product baseline without hashing.
// Use cases call it before authentication so malformed input is rejected
// cheaply, then hash only after the caller has authenticated. Stored-secret
// verification deliberately does not apply today's admission rules.
func ValidatePassword(password iamv1.Secret) error {
	plaintext := password.CopyBytes()
	defer clear(plaintext)
	return validatePasswordPolicy(plaintext)
}

func (hasher *PasswordHasher) Verify(password iamv1.Secret, stored PasswordHash) (bool, error) {
	if hasher == nil || !password.Present() {
		return false, ErrInvalidPasswordHash
	}
	salt, expected, err := parsePasswordHash(stored)
	if err != nil {
		return false, err
	}
	defer clear(salt)
	defer clear(expected)
	plaintext := password.CopyBytes()
	defer clear(plaintext)
	actual := argon2.IDKey(
		plaintext,
		salt,
		passwordIterations,
		passwordMemoryKiB,
		passwordParallelism,
		passwordKeyBytes,
	)
	defer clear(actual)
	return subtle.ConstantTimeCompare(actual, expected) == 1, nil
}

func parsePasswordHash(stored PasswordHash) ([]byte, []byte, error) {
	parts := strings.Split(string(stored), "$")
	profile := fmt.Sprintf(
		"m=%d,t=%d,p=%d",
		passwordMemoryKiB,
		passwordIterations,
		passwordParallelism,
	)
	if len(parts) != 7 || parts[0] != "" || parts[1] != "matrix-iam-v1" ||
		parts[2] != "argon2id" || parts[3] != "v=19" || parts[4] != profile {
		return nil, nil, ErrInvalidPasswordHash
	}
	salt, err := base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if err != nil || len(salt) != passwordSaltBytes {
		clear(salt)
		return nil, nil, ErrInvalidPasswordHash
	}
	derived, err := base64.RawStdEncoding.Strict().DecodeString(parts[6])
	if err != nil || len(derived) != passwordKeyBytes {
		clear(salt)
		clear(derived)
		return nil, nil, ErrInvalidPasswordHash
	}
	return salt, derived, nil
}

func validatePasswordPolicy(password []byte) error {
	if len(password) > maximumPasswordBytes || !utf8.Valid(password) {
		return ErrWeakPassword
	}
	length := utf8.RuneCount(password)
	if length < minimumPasswordCodePoints || length > maximumPasswordCodePoints {
		return ErrWeakPassword
	}
	for _, character := range string(password) {
		if unicode.IsControl(character) {
			return ErrWeakPassword
		}
	}
	for _, blocked := range commonPasswords {
		// Compare the complete candidate, never a substring. Folding is only
		// for blocklist admission; hashing and Verify preserve the exact bytes.
		if strings.EqualFold(string(password), blocked) {
			return ErrWeakPassword
		}
	}
	return nil
}
