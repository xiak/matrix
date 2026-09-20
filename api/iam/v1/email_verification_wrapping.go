package iamv1

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"

	"github.com/xiak/matrix/api/contractjson"
)

const (
	MaxEmailVerificationKeyringBytes   int64  = 8192
	MaxEmailVerificationWrappingKeys          = 8
	MaxEmailVerificationKeysetRevision uint64 = 1<<63 - 1
)

var ErrInvalidEmailVerificationKeyring = errors.New("email verification keyring is invalid")

type EmailVerificationWrappingKey struct {
	KeyID         string
	FormatVersion uint8
	KeyMaterial   Secret
}

// This separate purpose is shared only by IAM and its restricted mail worker,
// never by TOTP, AccessKey, Audit, ordinary JSON or a recovery authority.
// Validation of one file cannot establish registration history or retirement.
type EmailVerificationKeyring struct {
	APIVersion     string
	Kind           string
	Purpose        string
	Scope          SecurityMailInstallationScope
	KeysetRevision uint64
	ActiveKeyID    string
	Keys           []EmailVerificationWrappingKey
}

func (EmailVerificationWrappingKey) String() string { return "[REDACTED]" }
func (EmailVerificationWrappingKey) GoString() string {
	return "iamv1.EmailVerificationWrappingKey{[REDACTED]}"
}
func (EmailVerificationWrappingKey) MarshalJSON() ([]byte, error) {
	return nil, ErrInvalidEmailVerificationKeyring
}
func (*EmailVerificationWrappingKey) UnmarshalJSON([]byte) error {
	return ErrInvalidEmailVerificationKeyring
}
func (EmailVerificationKeyring) String() string { return "[REDACTED]" }
func (EmailVerificationKeyring) GoString() string {
	return "iamv1.EmailVerificationKeyring{[REDACTED]}"
}
func (EmailVerificationKeyring) MarshalJSON() ([]byte, error) {
	return nil, ErrInvalidEmailVerificationKeyring
}
func (*EmailVerificationKeyring) UnmarshalJSON([]byte) error {
	return ErrInvalidEmailVerificationKeyring
}

func ValidateEmailVerificationKeyring(value EmailVerificationKeyring) error {
	if value.APIVersion != APIVersion || value.Kind != "EmailVerificationKeyring" || value.Purpose != EmailVerificationWrappingPurpose ||
		ValidateID("installationId", value.Scope.InstallationID) != nil || ValidateDigest("bootstrapDigest", value.Scope.BootstrapDigest) != nil ||
		value.KeysetRevision == 0 || value.KeysetRevision > MaxEmailVerificationKeysetRevision ||
		ValidateID("activeKeyId", value.ActiveKeyID) != nil || len(value.Keys) == 0 || len(value.Keys) > MaxEmailVerificationWrappingKeys {
		return ErrInvalidEmailVerificationKeyring
	}
	active := false
	previous := ""
	for _, key := range value.Keys {
		if ValidateID("keyId", key.KeyID) != nil || key.KeyID <= previous || key.FormatVersion != 1 {
			return ErrInvalidEmailVerificationKeyring
		}
		material, err := emailVerificationKeyMaterial(key.KeyMaterial)
		clear(material)
		if err != nil {
			return ErrInvalidEmailVerificationKeyring
		}
		previous = key.KeyID
		active = active || key.KeyID == value.ActiveKeyID
	}
	if !active {
		return ErrInvalidEmailVerificationKeyring
	}
	return nil
}

func emailVerificationKeyMaterial(secret Secret) ([]byte, error) {
	encoded := secret.CopyBytes()
	defer clear(encoded)
	if len(encoded) != 43 {
		return nil, ErrInvalidEmailVerificationKeyring
	}
	material := make([]byte, 32)
	n, err := base64.RawURLEncoding.Strict().Decode(material, encoded)
	if err != nil || n != len(material) || base64.RawURLEncoding.EncodeToString(material) != string(encoded) {
		clear(material)
		return nil, ErrInvalidEmailVerificationKeyring
	}
	return material, nil
}

// A key commitment excludes its containing set revision/active selection,
// so existing key identity survives controlled expansion. It is not a permit.
func EmailVerificationKeyMaterialCommitment(value EmailVerificationKeyring, keyID string) (string, error) {
	if ValidateEmailVerificationKeyring(value) != nil {
		return "", ErrInvalidEmailVerificationKeyring
	}
	for _, key := range value.Keys {
		if key.KeyID == keyID {
			return emailVerificationKeyCommitment(value.Scope, key)
		}
	}
	return "", ErrInvalidEmailVerificationKeyring
}

func emailVerificationKeyCommitment(scope SecurityMailInstallationScope, key EmailVerificationWrappingKey) (string, error) {
	material, err := emailVerificationKeyMaterial(key.KeyMaterial)
	if err != nil {
		return "", ErrInvalidEmailVerificationKeyring
	}
	defer clear(material)
	encoded := credentialBindingBytes("matrix.iam.email-verification-wrapping-key.commitment.v1",
		[]byte(EmailVerificationWrappingPurpose), []byte(scope.InstallationID), []byte(scope.BootstrapDigest),
		[]byte(key.KeyID), []byte{key.FormatVersion}, material)
	defer clear(encoded)
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func EmailVerificationKeysetDigest(value EmailVerificationKeyring) (string, error) {
	if ValidateEmailVerificationKeyring(value) != nil {
		return "", ErrInvalidEmailVerificationKeyring
	}
	fields := [][]byte{[]byte(value.APIVersion), []byte(value.Kind), []byte(value.Purpose),
		[]byte(value.Scope.InstallationID), []byte(value.Scope.BootstrapDigest),
		binary.BigEndian.AppendUint64(nil, value.KeysetRevision), []byte(value.ActiveKeyID)}
	for _, key := range value.Keys {
		commitment, err := emailVerificationKeyCommitment(value.Scope, key)
		if err != nil {
			return "", ErrInvalidEmailVerificationKeyring
		}
		fields = append(fields, []byte(key.KeyID), []byte{key.FormatVersion}, []byte(commitment))
	}
	encoded := credentialBindingBytes("matrix.iam.email-verification-keyset.digest.v1", fields...)
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

type emailVerificationKeyringWire struct {
	APIVersion     string                        `json:"apiVersion"`
	Kind           string                        `json:"kind"`
	Purpose        string                        `json:"purpose"`
	Scope          SecurityMailInstallationScope `json:"scope"`
	KeysetRevision uint64                        `json:"keysetRevision"`
	ActiveKeyID    string                        `json:"activeKeyId"`
	Keys           []emailVerificationKeyWire    `json:"keys"`
}

type emailVerificationKeyWire struct {
	KeyID         string `json:"keyId"`
	FormatVersion uint8  `json:"formatVersion"`
	KeyMaterial   string `json:"keyMaterial"`
}

func EncodeEmailVerificationKeyring(value EmailVerificationKeyring) ([]byte, error) {
	if ValidateEmailVerificationKeyring(value) != nil {
		return nil, ErrInvalidEmailVerificationKeyring
	}
	wire := emailVerificationKeyringWire{APIVersion: value.APIVersion, Kind: value.Kind, Purpose: value.Purpose, Scope: value.Scope,
		KeysetRevision: value.KeysetRevision, ActiveKeyID: value.ActiveKeyID, Keys: make([]emailVerificationKeyWire, len(value.Keys))}
	defer clear(wire.Keys)
	for index, key := range value.Keys {
		wire.Keys[index] = emailVerificationKeyWire{KeyID: key.KeyID, FormatVersion: key.FormatVersion, KeyMaterial: key.KeyMaterial.reveal()}
	}
	encoded, err := json.Marshal(wire)
	if err != nil || int64(len(encoded)) > MaxEmailVerificationKeyringBytes {
		clear(encoded)
		return nil, ErrInvalidEmailVerificationKeyring
	}
	return encoded, nil
}

func DecodeEmailVerificationKeyring(reader io.Reader) (EmailVerificationKeyring, error) {
	if reader == nil {
		return EmailVerificationKeyring{}, ErrInvalidEmailVerificationKeyring
	}
	encoded, err := io.ReadAll(io.LimitReader(reader, MaxEmailVerificationKeyringBytes+1))
	defer clear(encoded)
	var wire emailVerificationKeyringWire
	defer func() { clear(wire.Keys) }()
	if err != nil || len(encoded) == 0 || int64(len(encoded)) > MaxEmailVerificationKeyringBytes ||
		contractjson.DecodeObjectBytes(encoded, MaxEmailVerificationKeyringBytes, &wire) != nil ||
		len(wire.Keys) == 0 || len(wire.Keys) > MaxEmailVerificationWrappingKeys {
		return EmailVerificationKeyring{}, ErrInvalidEmailVerificationKeyring
	}
	value := EmailVerificationKeyring{APIVersion: wire.APIVersion, Kind: wire.Kind, Purpose: wire.Purpose, Scope: wire.Scope,
		KeysetRevision: wire.KeysetRevision, ActiveKeyID: wire.ActiveKeyID, Keys: make([]EmailVerificationWrappingKey, len(wire.Keys))}
	for index, key := range wire.Keys {
		material, err := NewSecret(key.KeyMaterial)
		if err != nil {
			clear(value.Keys)
			return EmailVerificationKeyring{}, ErrInvalidEmailVerificationKeyring
		}
		value.Keys[index] = EmailVerificationWrappingKey{KeyID: key.KeyID, FormatVersion: key.FormatVersion, KeyMaterial: material}
	}
	canonical, err := EncodeEmailVerificationKeyring(value)
	defer clear(canonical)
	if err != nil || !bytes.Equal(encoded, canonical) {
		clear(value.Keys)
		return EmailVerificationKeyring{}, ErrInvalidEmailVerificationKeyring
	}
	return value, nil
}
