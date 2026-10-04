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
	TOTPWrappingPurpose          = "IAM_TOTP_SEED_WRAPPING"
	MaxTOTPKeyringBytes   int64  = 8192
	MaxTOTPWrappingKeys          = 8
	MaxTOTPKeysetRevision uint64 = 1<<63 - 1
)

var (
	ErrInvalidTOTPKeyring     = errors.New("TOTP keyring is invalid")
	ErrInvalidTOTPSeedContext = errors.New("TOTP seed context is invalid")
)

// These installation-private contracts confer no authentication or recovery
// authority. Runtime separately matches both scope fields to the sealed
// installation and checks registered key history and actual database needs.
type TOTPWrappingScope struct {
	InstallationID  string `json:"installationId"`
	BootstrapDigest string `json:"bootstrapDigest"`
}

type TOTPWrappingKey struct {
	KeyID         string `json:"keyId"`
	FormatVersion uint8  `json:"formatVersion"`
	KeyMaterial   Secret `json:"keyMaterial"`
}

type TOTPKeyring struct {
	APIVersion     string            `json:"apiVersion"`
	Kind           string            `json:"kind"`
	Purpose        string            `json:"purpose"`
	Scope          TOTPWrappingScope `json:"scope"`
	KeysetRevision uint64            `json:"keysetRevision"`
	ActiveKeyID    string            `json:"activeKeyId"`
	Keys           []TOTPWrappingKey `json:"keys"`
}

func (TOTPWrappingKey) String() string   { return "[REDACTED]" }
func (TOTPWrappingKey) GoString() string { return "iamv1.TOTPWrappingKey{[REDACTED]}" }
func (TOTPWrappingKey) MarshalJSON() ([]byte, error) {
	return nil, ErrInvalidTOTPKeyring
}
func (*TOTPWrappingKey) UnmarshalJSON([]byte) error { return ErrInvalidTOTPKeyring }

func (TOTPKeyring) String() string   { return "[REDACTED]" }
func (TOTPKeyring) GoString() string { return "iamv1.TOTPKeyring{[REDACTED]}" }
func (TOTPKeyring) MarshalJSON() ([]byte, error) {
	return nil, ErrInvalidTOTPKeyring
}
func (*TOTPKeyring) UnmarshalJSON([]byte) error { return ErrInvalidTOTPKeyring }

func ValidateTOTPKeyring(value TOTPKeyring) error {
	if value.APIVersion != APIVersion || value.Kind != "TOTPKeyring" || value.Purpose != TOTPWrappingPurpose ||
		ValidateID("installationId", value.Scope.InstallationID) != nil ||
		ValidateDigest("bootstrapDigest", value.Scope.BootstrapDigest) != nil ||
		value.KeysetRevision == 0 || value.KeysetRevision > MaxTOTPKeysetRevision ||
		ValidateID("activeKeyId", value.ActiveKeyID) != nil || len(value.Keys) == 0 || len(value.Keys) > MaxTOTPWrappingKeys {
		return ErrInvalidTOTPKeyring
	}
	active := false
	previous := ""
	for _, key := range value.Keys {
		if ValidateID("keyId", key.KeyID) != nil || key.KeyID <= previous || key.FormatVersion != 1 {
			return ErrInvalidTOTPKeyring
		}
		material, err := totpWrappingMaterial(key.KeyMaterial)
		clear(material)
		if err != nil {
			return ErrInvalidTOTPKeyring
		}
		previous = key.KeyID
		active = active || key.KeyID == value.ActiveKeyID
	}
	if !active {
		return ErrInvalidTOTPKeyring
	}
	return nil
}

func totpWrappingMaterial(secret Secret) ([]byte, error) {
	encoded := secret.CopyBytes()
	defer clear(encoded)
	if len(encoded) != 43 {
		return nil, ErrInvalidTOTPKeyring
	}
	material := make([]byte, 32)
	n, err := base64.RawURLEncoding.Strict().Decode(material, encoded)
	if err != nil || n != len(material) || base64.RawURLEncoding.EncodeToString(material) != string(encoded) {
		clear(material)
		return nil, ErrInvalidTOTPKeyring
	}
	return material, nil
}

// TOTPKeyMaterialCommitment binds an immutable key, NOT its containing set or
// active selection. Adding a new key/revision must preserve the commitment
// needed by an older supported backup. Historical consistency and retirement
// still require authority checks; a digest is not a permit or anti-rollback.
func TOTPKeyMaterialCommitment(value TOTPKeyring, keyID string) (string, error) {
	if ValidateTOTPKeyring(value) != nil {
		return "", ErrInvalidTOTPKeyring
	}
	for _, key := range value.Keys {
		if key.KeyID == keyID {
			return totpKeyCommitment(value.Scope, key)
		}
	}
	return "", ErrInvalidTOTPKeyring
}

func totpKeyCommitment(scope TOTPWrappingScope, key TOTPWrappingKey) (string, error) {
	material, err := totpWrappingMaterial(key.KeyMaterial)
	if err != nil {
		return "", ErrInvalidTOTPKeyring
	}
	defer clear(material)
	encoded := credentialBindingBytes("matrix.iam.totp-wrapping-key.commitment.v1",
		[]byte(TOTPWrappingPurpose), []byte(scope.InstallationID), []byte(scope.BootstrapDigest),
		[]byte(key.KeyID), []byte{key.FormatVersion}, material)
	defer clear(encoded)
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

// TOTPKeysetDigest commits to the complete canonical set using only per-key
// commitments. It is not the same-snapshot backup custody summary, and cannot
// prove which keys the database/replicas/retained backups actually need.
func TOTPKeysetDigest(value TOTPKeyring) (string, error) {
	if ValidateTOTPKeyring(value) != nil {
		return "", ErrInvalidTOTPKeyring
	}
	fields := [][]byte{[]byte(value.APIVersion), []byte(value.Kind), []byte(value.Purpose),
		[]byte(value.Scope.InstallationID), []byte(value.Scope.BootstrapDigest),
		binary.BigEndian.AppendUint64(nil, value.KeysetRevision), []byte(value.ActiveKeyID)}
	for _, key := range value.Keys {
		commitment, err := totpKeyCommitment(value.Scope, key)
		if err != nil {
			return "", ErrInvalidTOTPKeyring
		}
		fields = append(fields, []byte(key.KeyID), []byte{key.FormatVersion}, []byte(commitment))
	}
	encoded := credentialBindingBytes("matrix.iam.totp-keyset.digest.v1", fields...)
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

// TOTPSeedContext fixes format-1 HKDF info/AAD to the actual immutable seed
// identity, independently of AccessKey. State, OTP watermark and keyset
// revision are deliberately not ciphertext identity. This proves no authority.
func TOTPSeedContext(scope TOTPWrappingScope, accountID AccountID, userID PrincipalID, factorID, keyID string) (info, aad []byte, err error) {
	for _, id := range []string{scope.InstallationID, string(accountID), string(userID), factorID, keyID} {
		if ValidateID("seedScope", id) != nil {
			return nil, nil, ErrInvalidTOTPSeedContext
		}
	}
	if ValidateDigest("bootstrapDigest", scope.BootstrapDigest) != nil {
		return nil, nil, ErrInvalidTOTPSeedContext
	}
	fields := [][]byte{[]byte(TOTPWrappingPurpose), {1}, []byte(scope.InstallationID), []byte(scope.BootstrapDigest),
		[]byte(accountID), []byte(userID), []byte(factorID), []byte(keyID)}
	return credentialBindingBytes("matrix.iam.totp-seed.kdf-info.v1", fields...),
		credentialBindingBytes("matrix.iam.totp-seed.aad.v1", fields...), nil
}

// Only this explicit private codec handles plain key material. Do not use
// this wire type as an HTTP contract or serialize it through generic logging.
type totpKeyringWire struct {
	APIVersion     string            `json:"apiVersion"`
	Kind           string            `json:"kind"`
	Purpose        string            `json:"purpose"`
	Scope          TOTPWrappingScope `json:"scope"`
	KeysetRevision uint64            `json:"keysetRevision"`
	ActiveKeyID    string            `json:"activeKeyId"`
	Keys           []totpKeyWire     `json:"keys"`
}

type totpKeyWire struct {
	KeyID         string `json:"keyId"`
	FormatVersion uint8  `json:"formatVersion"`
	KeyMaterial   string `json:"keyMaterial"`
}

func EncodeTOTPKeyring(value TOTPKeyring) ([]byte, error) {
	if ValidateTOTPKeyring(value) != nil {
		return nil, ErrInvalidTOTPKeyring
	}
	wire := totpKeyringWire{APIVersion: value.APIVersion, Kind: value.Kind, Purpose: value.Purpose,
		Scope: value.Scope, KeysetRevision: value.KeysetRevision, ActiveKeyID: value.ActiveKeyID,
		Keys: make([]totpKeyWire, len(value.Keys))}
	for index, key := range value.Keys {
		wire.Keys[index] = totpKeyWire{KeyID: key.KeyID, FormatVersion: key.FormatVersion, KeyMaterial: key.KeyMaterial.reveal()}
	}
	encoded, err := json.Marshal(wire)
	clear(wire.Keys)
	if err != nil || int64(len(encoded)) > MaxTOTPKeyringBytes {
		clear(encoded)
		return nil, ErrInvalidTOTPKeyring
	}
	return encoded, nil
}

// DecodeTOTPKeyring accepts only canonical private bytes, with a bounded
// read and no partial result or underlying error on failure. Callers still
// own file custody, scope/history checks and clearing their input buffers.
func DecodeTOTPKeyring(reader io.Reader) (TOTPKeyring, error) {
	if reader == nil {
		return TOTPKeyring{}, ErrInvalidTOTPKeyring
	}
	encoded, err := io.ReadAll(io.LimitReader(reader, MaxTOTPKeyringBytes+1))
	defer clear(encoded)
	if err != nil || len(encoded) == 0 || int64(len(encoded)) > MaxTOTPKeyringBytes {
		return TOTPKeyring{}, ErrInvalidTOTPKeyring
	}
	var wire totpKeyringWire
	defer func() { clear(wire.Keys) }()
	if contractjson.DecodeObjectBytes(encoded, MaxTOTPKeyringBytes, &wire) != nil ||
		len(wire.Keys) == 0 || len(wire.Keys) > MaxTOTPWrappingKeys {
		return TOTPKeyring{}, ErrInvalidTOTPKeyring
	}
	value := TOTPKeyring{APIVersion: wire.APIVersion, Kind: wire.Kind, Purpose: wire.Purpose,
		Scope: wire.Scope, KeysetRevision: wire.KeysetRevision, ActiveKeyID: wire.ActiveKeyID,
		Keys: make([]TOTPWrappingKey, len(wire.Keys))}
	for index, key := range wire.Keys {
		material, err := NewSecret(key.KeyMaterial)
		if err != nil {
			clear(value.Keys)
			return TOTPKeyring{}, ErrInvalidTOTPKeyring
		}
		value.Keys[index] = TOTPWrappingKey{KeyID: key.KeyID, FormatVersion: key.FormatVersion, KeyMaterial: material}
	}
	canonical, err := EncodeTOTPKeyring(value)
	defer clear(canonical)
	if err != nil || !bytes.Equal(encoded, canonical) {
		clear(value.Keys)
		return TOTPKeyring{}, ErrInvalidTOTPKeyring
	}
	return value, nil
}
