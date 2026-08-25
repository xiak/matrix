package authority

import (
	"crypto/rand"
	"crypto/subtle"
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
	ErrWeakPassword        = errors.New("password does not satisfy the fixed policy")
	ErrInvalidPasswordHash = errors.New("stored password hash is invalid")
	ErrPasswordHashing     = errors.New("password hashing failed")
)

const (
	passwordMemoryKiB    = 64 * 1024
	passwordIterations   = 3
	passwordParallelism  = 1
	passwordSaltBytes    = 16
	passwordKeyBytes     = 32
	minimumPasswordBytes = 14
	maximumPasswordBytes = 128
)

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
	plaintext := password.CopyBytes()
	defer clear(plaintext)
	if err := validatePasswordPolicy(plaintext); err != nil {
		return "", err
	}
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
	if len(password) < minimumPasswordBytes || len(password) > maximumPasswordBytes || !utf8.Valid(password) {
		return ErrWeakPassword
	}
	categories := 0
	hasLower, hasUpper, hasDigit, hasSymbol := false, false, false, false
	for _, character := range string(password) {
		switch {
		case unicode.IsControl(character), unicode.IsSpace(character):
			return ErrWeakPassword
		case unicode.IsLower(character):
			hasLower = true
		case unicode.IsUpper(character):
			hasUpper = true
		case unicode.IsDigit(character):
			hasDigit = true
		default:
			hasSymbol = true
		}
	}
	for _, present := range []bool{hasLower, hasUpper, hasDigit, hasSymbol} {
		if present {
			categories++
		}
	}
	if categories < 3 {
		return ErrWeakPassword
	}
	return nil
}
