package iamv1

import (
	"bytes"
	"encoding/json"
	"errors"
	"unicode"
	"unicode/utf8"
)

var (
	ErrInvalidSecret       = errors.New("credential is invalid")
	ErrSecretSerialization = errors.New("credential serialization is forbidden")
)

const maximumSecretBytes = 16 * 1024

// Secret is transient credential material. It can be decoded from an
// explicit request but cannot be serialized or formatted as plaintext.
type Secret struct {
	value string
}

func NewSecret(value string) (Secret, error) {
	if !validSecret(value) {
		return Secret{}, ErrInvalidSecret
	}
	return Secret{value: value}, nil
}

func (secret Secret) Present() bool {
	return validSecret(secret.value)
}

// CopyBytes returns an explicit mutable copy. Callers should clear it as soon
// as password or token verification completes.
func (secret Secret) CopyBytes() []byte {
	return append([]byte(nil), secret.value...)
}

func (secret Secret) String() string {
	return "[REDACTED]"
}

func (secret Secret) GoString() string {
	return "iamv1.Secret{[REDACTED]}"
}

func (secret Secret) MarshalJSON() ([]byte, error) {
	return nil, ErrSecretSerialization
}

func (secret *Secret) UnmarshalJSON(source []byte) error {
	if secret == nil {
		return ErrInvalidSecret
	}
	decoder := json.NewDecoder(bytes.NewReader(source))
	var value string
	if err := decoder.Decode(&value); err != nil || !validSecret(value) {
		return ErrInvalidSecret
	}
	*secret = Secret{value: value}
	return nil
}

func (secret Secret) reveal() string {
	return secret.value
}

func validSecret(value string) bool {
	if value == "" || len(value) > maximumSecretBytes || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character == 0 || unicode.IsControl(character) {
			return false
		}
	}
	return true
}
