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
	AccessKeyWrappingPurpose               = "IAM_ACCESS_KEY_SECRET_WRAPPING"
	MaxAccessKeyWrappingKeyringBytes int64 = 4096
)

var (
	ErrInvalidAccessKeyWrappingKeyring = errors.New("access key wrapping keyring is invalid")
	ErrInvalidAccessKeySecretContext   = errors.New("access key secret context is invalid")
)

// This is a private installation file, never a public AccessKey document or
// an authorization capability. Runtime must independently match this scope
// against both bootstrap input and the database's sealed receipt.
type AccessKeyWrappingScope struct {
	InstallationID  string `json:"installationId"`
	BootstrapDigest string `json:"bootstrapDigest"`
}

type AccessKeyWrappingKey struct {
	WrappingKeyID string `json:"wrappingKeyId"`
	FormatVersion uint8  `json:"formatVersion"`
	KeyMaterial   Secret `json:"keyMaterial"`
}

type AccessKeyWrappingKeyring struct {
	APIVersion          string                 `json:"apiVersion"`
	Kind                string                 `json:"kind"`
	Purpose             string                 `json:"purpose"`
	Scope               AccessKeyWrappingScope `json:"scope"`
	ActiveWrappingKeyID string                 `json:"activeWrappingKeyId"`
	Keys                []AccessKeyWrappingKey `json:"keys"`
}

func (AccessKeyWrappingKey) String() string   { return "[REDACTED]" }
func (AccessKeyWrappingKey) GoString() string { return "iamv1.AccessKeyWrappingKey{[REDACTED]}" }
func (AccessKeyWrappingKey) MarshalJSON() ([]byte, error) {
	return nil, ErrInvalidAccessKeyWrappingKeyring
}
func (*AccessKeyWrappingKey) UnmarshalJSON([]byte) error {
	return ErrInvalidAccessKeyWrappingKeyring
}

func (AccessKeyWrappingKeyring) String() string { return "[REDACTED]" }
func (AccessKeyWrappingKeyring) GoString() string {
	return "iamv1.AccessKeyWrappingKeyring{[REDACTED]}"
}
func (AccessKeyWrappingKeyring) MarshalJSON() ([]byte, error) {
	return nil, ErrInvalidAccessKeyWrappingKeyring
}
func (*AccessKeyWrappingKeyring) UnmarshalJSON([]byte) error {
	return ErrInvalidAccessKeyWrappingKeyring
}

func ValidateAccessKeyWrappingKeyring(value AccessKeyWrappingKeyring) error {
	if value.APIVersion != APIVersion || value.Kind != "AccessKeyWrappingKeyring" ||
		value.Purpose != AccessKeyWrappingPurpose ||
		ValidateID("installationId", value.Scope.InstallationID) != nil ||
		ValidateDigest("bootstrapDigest", value.Scope.BootstrapDigest) != nil ||
		ValidateID("activeWrappingKeyId", value.ActiveWrappingKeyID) != nil || len(value.Keys) != 1 {
		return ErrInvalidAccessKeyWrappingKeyring
	}
	key := value.Keys[0]
	if key.WrappingKeyID != value.ActiveWrappingKeyID || key.FormatVersion != 1 {
		return ErrInvalidAccessKeyWrappingKeyring
	}
	material, err := accessKeyWrappingMaterial(key.KeyMaterial)
	clear(material)
	return err
}

func accessKeyWrappingMaterial(secret Secret) ([]byte, error) {
	encoded := secret.CopyBytes()
	defer clear(encoded)
	if len(encoded) != 43 {
		return nil, ErrInvalidAccessKeyWrappingKeyring
	}
	decoded := make([]byte, 32)
	n, err := base64.RawURLEncoding.Strict().Decode(decoded, encoded)
	if err != nil || n != len(decoded) || base64.RawURLEncoding.EncodeToString(decoded) != string(encoded) {
		clear(decoded)
		return nil, ErrInvalidAccessKeyWrappingKeyring
	}
	return decoded, nil
}

// AccessKeySecretContext preserves the material-format-1 HKDF info/AAD bytes.
// These pure bindings grant no authority and accept no caller-defined domain
// or encoding version. The two domains deliberately produce distinct buffers.
func AccessKeySecretContext(installationID string, accountID AccountID, userID PrincipalID, accessKeyID, wrappingKeyID string) (info, aad []byte, err error) {
	for _, id := range []string{installationID, string(accountID), string(userID), accessKeyID, wrappingKeyID} {
		if ValidateID("secretScope", id) != nil {
			return nil, nil, ErrInvalidAccessKeySecretContext
		}
	}
	fields := [][]byte{[]byte("ACCESS_KEY_SECRET"), {1}, []byte(installationID), []byte(accountID), []byte(userID), []byte(accessKeyID), []byte(wrappingKeyID)}
	return accessKeyBindingBytes("matrix.iam.access-key-secret.kdf-info.v1", fields...),
		accessKeyBindingBytes("matrix.iam.access-key-secret.aad.v1", fields...), nil
}

// AccessKeyWrappingKeyCommitment is non-secret consistency evidence for one
// immutable, high-entropy wrapping key, not authorization or a keyring-wide
// digest. Registry/backup consumers must compare it in constant time and must
// not permit a known wrapping-key ID to acquire another commitment.
func AccessKeyWrappingKeyCommitment(value AccessKeyWrappingKeyring, wrappingKeyID string) (string, error) {
	if ValidateAccessKeyWrappingKeyring(value) != nil || wrappingKeyID != value.Keys[0].WrappingKeyID {
		return "", ErrInvalidAccessKeyWrappingKeyring
	}
	material, err := accessKeyWrappingMaterial(value.Keys[0].KeyMaterial)
	if err != nil {
		return "", ErrInvalidAccessKeyWrappingKeyring
	}
	defer clear(material)
	encoded := accessKeyBindingBytes("matrix.iam.access-key-wrapping-key.commitment.v1",
		[]byte(value.Purpose), []byte(value.Scope.InstallationID), []byte(value.Scope.BootstrapDigest),
		[]byte(wrappingKeyID), []byte{value.Keys[0].FormatVersion}, material)
	defer clear(encoded)
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

// This is the single length-prefix primitive for key contexts and per-key
// commitments. Callers above validate their bounded, purpose-specific fields.
func accessKeyBindingBytes(domain string, fields ...[]byte) []byte {
	encoded := binary.BigEndian.AppendUint32(nil, uint32(len(domain)))
	encoded = append(encoded, domain...)
	for _, field := range fields {
		encoded = binary.BigEndian.AppendUint32(encoded, uint32(len(field)))
		encoded = append(encoded, field...)
	}
	return encoded
}

// The only plain-material wire representation is private to the explicit
// codec. Do not return it, log it, or pass it to ordinary contract handlers.
type accessKeyWrappingKeyringWire struct {
	APIVersion          string                 `json:"apiVersion"`
	Kind                string                 `json:"kind"`
	Purpose             string                 `json:"purpose"`
	Scope               AccessKeyWrappingScope `json:"scope"`
	ActiveWrappingKeyID string                 `json:"activeWrappingKeyId"`
	Keys                []struct {
		WrappingKeyID string `json:"wrappingKeyId"`
		FormatVersion uint8  `json:"formatVersion"`
		KeyMaterial   string `json:"keyMaterial"`
	} `json:"keys"`
}

func EncodeAccessKeyWrappingKeyring(value AccessKeyWrappingKeyring) ([]byte, error) {
	if ValidateAccessKeyWrappingKeyring(value) != nil {
		return nil, ErrInvalidAccessKeyWrappingKeyring
	}
	wire := accessKeyWrappingKeyringWire{
		APIVersion: value.APIVersion, Kind: value.Kind, Purpose: value.Purpose,
		Scope: value.Scope, ActiveWrappingKeyID: value.ActiveWrappingKeyID,
	}
	for _, key := range value.Keys {
		wire.Keys = append(wire.Keys, struct {
			WrappingKeyID string `json:"wrappingKeyId"`
			FormatVersion uint8  `json:"formatVersion"`
			KeyMaterial   string `json:"keyMaterial"`
		}{key.WrappingKeyID, key.FormatVersion, key.KeyMaterial.reveal()})
	}
	encoded, err := json.Marshal(wire)
	if err != nil || int64(len(encoded)) > MaxAccessKeyWrappingKeyringBytes {
		clear(encoded)
		return nil, ErrInvalidAccessKeyWrappingKeyring
	}
	return encoded, nil
}

// DecodeAccessKeyWrappingKeyring accepts only the exact canonical private
// file produced by Encode: no optional whitespace/newline or reordered keys.
// It proves syntax only. The caller owns file permissions, installation/DB
// matching and clearing its input buffer and transient decoded Secret copy.
func DecodeAccessKeyWrappingKeyring(reader io.Reader) (AccessKeyWrappingKeyring, error) {
	if reader == nil {
		return AccessKeyWrappingKeyring{}, ErrInvalidAccessKeyWrappingKeyring
	}
	encoded, err := io.ReadAll(io.LimitReader(reader, MaxAccessKeyWrappingKeyringBytes+1))
	defer clear(encoded)
	if err != nil || len(encoded) == 0 || int64(len(encoded)) > MaxAccessKeyWrappingKeyringBytes {
		return AccessKeyWrappingKeyring{}, ErrInvalidAccessKeyWrappingKeyring
	}
	var wire accessKeyWrappingKeyringWire
	if contractjson.DecodeObjectBytes(encoded, MaxAccessKeyWrappingKeyringBytes, &wire) != nil || len(wire.Keys) != 1 {
		return AccessKeyWrappingKeyring{}, ErrInvalidAccessKeyWrappingKeyring
	}
	material, err := NewSecret(wire.Keys[0].KeyMaterial)
	wire.Keys[0].KeyMaterial = ""
	if err != nil {
		return AccessKeyWrappingKeyring{}, ErrInvalidAccessKeyWrappingKeyring
	}
	value := AccessKeyWrappingKeyring{APIVersion: wire.APIVersion, Kind: wire.Kind, Purpose: wire.Purpose,
		Scope: wire.Scope, ActiveWrappingKeyID: wire.ActiveWrappingKeyID,
		Keys: []AccessKeyWrappingKey{{WrappingKeyID: wire.Keys[0].WrappingKeyID, FormatVersion: wire.Keys[0].FormatVersion, KeyMaterial: material}}}
	canonical, err := EncodeAccessKeyWrappingKeyring(value)
	defer clear(canonical)
	if err != nil || !bytes.Equal(encoded, canonical) {
		return AccessKeyWrappingKeyring{}, ErrInvalidAccessKeyWrappingKeyring
	}
	return value, nil
}
