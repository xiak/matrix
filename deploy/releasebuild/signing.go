package releasebuild

import (
	"bytes"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"

	installationrelease "github.com/xiak/matrix/app/service/installation/release"
)

const (
	signingKeyAPIVersion   = "build.matrix.xiak.com/v1"
	signingKeyKind         = "ReleaseSigningKey"
	maximumSigningKeyBytes = 16 * 1024
)

type signingKeyDocument struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	KeyID      string `json:"keyId"`
	Algorithm  string `json:"algorithm"`
	PrivateKey string `json:"privateKey"`
}

func GenerateSigningFiles(
	keyID string,
	privatePath string,
	trustPath string,
	entropy io.Reader,
) (installationrelease.TrustRoot, error) {
	if entropy == nil || privatePath == trustPath {
		return installationrelease.TrustRoot{}, errors.New("release signing output is invalid")
	}
	for _, target := range []string{privatePath, trustPath} {
		if target == "" || !filepath.IsAbs(target) || filepath.Clean(target) != target ||
			isFilesystemRoot(target) {
			return installationrelease.TrustRoot{}, errors.New("release signing path is invalid")
		}
		parent, err := os.Lstat(filepath.Dir(target))
		if err != nil || !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 {
			return installationrelease.TrustRoot{}, errors.New("release signing parent is unsafe")
		}
		if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
			return installationrelease.TrustRoot{}, errors.New("release signing output already exists")
		}
	}
	publicKey, privateKey, err := ed25519.GenerateKey(entropy)
	if err != nil {
		return installationrelease.TrustRoot{}, errors.New("generate release signing key failed")
	}
	trust, err := installationrelease.NewTrustRoot(keyID, publicKey)
	if err != nil {
		return installationrelease.TrustRoot{}, err
	}
	document := signingKeyDocument{
		APIVersion: signingKeyAPIVersion, Kind: signingKeyKind,
		KeyID: keyID, Algorithm: installationrelease.SignatureAlgorithm,
		PrivateKey: base64.StdEncoding.EncodeToString(privateKey),
	}
	privateBytes, err := json.Marshal(document)
	document.PrivateKey = ""
	clear(privateKey)
	if err != nil {
		return installationrelease.TrustRoot{}, errors.New("encode release signing key failed")
	}
	trustBytes, err := installationrelease.EncodeTrustRoot(trust)
	if err != nil {
		clear(privateBytes)
		return installationrelease.TrustRoot{}, err
	}
	if err := writeExclusive(privatePath, privateBytes, 0o600); err != nil {
		clear(privateBytes)
		return installationrelease.TrustRoot{}, errors.New("write release signing key failed")
	}
	clear(privateBytes)
	if err := writeExclusive(trustPath, trustBytes, 0o600); err != nil {
		return installationrelease.TrustRoot{}, errors.New("write release trust root failed")
	}
	return trust, nil
}

func ReadSigningKey(target string) (SigningMaterial, installationrelease.TrustRoot, error) {
	if target == "" || !filepath.IsAbs(target) || filepath.Clean(target) != target ||
		isFilesystemRoot(target) {
		return SigningMaterial{}, installationrelease.TrustRoot{}, errors.New("release signing key path is invalid")
	}
	info, err := os.Lstat(target)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Size() <= 0 || info.Size() > maximumSigningKeyBytes ||
		(runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0) {
		return SigningMaterial{}, installationrelease.TrustRoot{}, errors.New("release signing key file is unsafe")
	}
	file, err := os.Open(target)
	if err != nil {
		return SigningMaterial{}, installationrelease.TrustRoot{}, errors.New("open release signing key failed")
	}
	content, err := io.ReadAll(io.LimitReader(file, maximumSigningKeyBytes+1))
	openedInfo, statErr := file.Stat()
	_ = file.Close()
	if err != nil || statErr != nil || !os.SameFile(info, openedInfo) ||
		len(content) == 0 || len(content) > maximumSigningKeyBytes {
		clear(content)
		return SigningMaterial{}, installationrelease.TrustRoot{}, errors.New("read release signing key failed")
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var document signingKeyDocument
	if err := decoder.Decode(&document); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		clear(content)
		return SigningMaterial{}, installationrelease.TrustRoot{}, errors.New("release signing key is invalid")
	}
	canonical, err := json.Marshal(document)
	if err != nil || subtle.ConstantTimeCompare(canonical, content) != 1 ||
		document.APIVersion != signingKeyAPIVersion || document.Kind != signingKeyKind ||
		document.Algorithm != installationrelease.SignatureAlgorithm {
		clear(content)
		clear(canonical)
		return SigningMaterial{}, installationrelease.TrustRoot{}, errors.New("release signing key is invalid")
	}
	clear(content)
	clear(canonical)
	privateKey, err := base64.StdEncoding.Strict().DecodeString(document.PrivateKey)
	document.PrivateKey = ""
	if err != nil || len(privateKey) != ed25519.PrivateKeySize {
		clear(privateKey)
		return SigningMaterial{}, installationrelease.TrustRoot{}, errors.New("release signing key material is invalid")
	}
	canonicalPrivateKey := ed25519.NewKeyFromSeed(privateKey[:ed25519.SeedSize])
	if subtle.ConstantTimeCompare(canonicalPrivateKey, privateKey) != 1 {
		clear(canonicalPrivateKey)
		clear(privateKey)
		return SigningMaterial{}, installationrelease.TrustRoot{}, errors.New("release signing key material is invalid")
	}
	clear(canonicalPrivateKey)
	material := SigningMaterial{KeyID: document.KeyID, PrivateKey: ed25519.PrivateKey(privateKey)}
	publicKey, ok := material.PrivateKey.Public().(ed25519.PublicKey)
	if !ok {
		clear(material.PrivateKey)
		return SigningMaterial{}, installationrelease.TrustRoot{}, errors.New("release signing key material is invalid")
	}
	trust, err := installationrelease.NewTrustRoot(material.KeyID, publicKey)
	if err != nil {
		clear(material.PrivateKey)
		return SigningMaterial{}, installationrelease.TrustRoot{}, err
	}
	return material, trust, nil
}
