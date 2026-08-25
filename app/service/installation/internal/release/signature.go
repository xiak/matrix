package release

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
)

var publicKeyFingerprintPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

const ed25519SignatureBytes = ed25519.SignatureSize

func EncodeTrustRoot(value TrustRoot) ([]byte, error) {
	if _, err := validateTrustRoot(value); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, errors.New("encode release trust root failed")
	}
	return encoded, nil
}

func DecodeTrustRoot(content []byte) (TrustRoot, error) {
	if len(content) == 0 || len(content) > maximumTrustBytes {
		return TrustRoot{}, errors.New("release trust root size is invalid")
	}
	var value TrustRoot
	if err := decodeStrict(content, &value); err != nil {
		return TrustRoot{}, errors.New("release trust root is invalid")
	}
	encoded, err := EncodeTrustRoot(value)
	if err != nil || subtle.ConstantTimeCompare(encoded, content) != 1 {
		return TrustRoot{}, errors.New("release trust root is not canonical")
	}
	return value, nil
}

func Verify(manifestBytes, signature, trustBytes []byte) (Manifest, error) {
	manifest, err := DecodeCanonical(manifestBytes)
	if err != nil {
		return Manifest{}, err
	}
	trust, err := DecodeTrustRoot(trustBytes)
	if err != nil {
		return Manifest{}, err
	}
	publicKey, err := validateTrustRoot(trust)
	if err != nil || manifest.Signer.KeyID != trust.KeyID || len(signature) != ed25519.SignatureSize ||
		!ed25519.Verify(publicKey, manifestBytes, signature) {
		return Manifest{}, errors.New("release signature verification failed")
	}
	return manifest, nil
}

func NewTrustRoot(keyID string, publicKey ed25519.PublicKey) (TrustRoot, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return TrustRoot{}, errors.New("release public key is invalid")
	}
	digest := sha256.Sum256(publicKey)
	value := TrustRoot{
		APIVersion:           TrustAPIVersion,
		Kind:                 TrustKind,
		KeyID:                keyID,
		Algorithm:            SignatureAlgorithm,
		PublicKey:            base64.StdEncoding.EncodeToString(publicKey),
		PublicKeyFingerprint: "sha256:" + hex.EncodeToString(digest[:]),
	}
	if _, err := validateTrustRoot(value); err != nil {
		return TrustRoot{}, err
	}
	return value, nil
}

func validateTrustRoot(value TrustRoot) (ed25519.PublicKey, error) {
	if value.APIVersion != TrustAPIVersion || value.Kind != TrustKind ||
		!keyIDPattern.MatchString(value.KeyID) || value.Algorithm != SignatureAlgorithm ||
		!publicKeyFingerprintPattern.MatchString(value.PublicKeyFingerprint) {
		return nil, errors.New("release trust root is invalid")
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(value.PublicKey)
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, errors.New("release trust root public key is invalid")
	}
	digest := sha256.Sum256(decoded)
	expected := "sha256:" + hex.EncodeToString(digest[:])
	if subtle.ConstantTimeCompare([]byte(expected), []byte(value.PublicKeyFingerprint)) != 1 {
		return nil, errors.New("release trust root fingerprint is invalid")
	}
	return ed25519.PublicKey(decoded), nil
}
