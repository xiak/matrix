package release

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
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

// ReadTrustRootFile reads the public out-of-band trust root without following
// a link or reparse point. The returned bytes are the exact canonical bytes
// used to authenticate a release and later pinned into the installation.
func ReadTrustRootFile(target string) ([]byte, TrustRoot, error) {
	if target == "" || len(target) > 4096 || !filepath.IsAbs(target) ||
		filepath.Clean(target) != target || isFilesystemRoot(target) {
		return nil, TrustRoot{}, errors.New("release trust root path is invalid")
	}
	info, err := validateBundlePath(target)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 0 ||
		uint64(info.Size()) > maximumTrustBytes {
		return nil, TrustRoot{}, errors.New("release trust root file is unsafe")
	}
	file, err := openRegularNoFollow(target)
	if err != nil {
		return nil, TrustRoot{}, errors.New("open release trust root failed")
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, maximumTrustBytes+1))
	if err != nil || len(content) == 0 || uint64(len(content)) > maximumTrustBytes {
		return nil, TrustRoot{}, errors.New("read release trust root failed")
	}
	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		return nil, TrustRoot{}, errors.New("release trust root changed while opened")
	}
	trust, err := DecodeTrustRoot(content)
	if err != nil {
		return nil, TrustRoot{}, err
	}
	return content, trust, nil
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
