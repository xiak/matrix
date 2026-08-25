package journal

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"

	"github.com/xiak/matrix/app/service/installation/internal/lifecycle"
)

const (
	sealAPIVersion      = "installation.matrix.xiak.com/v1"
	sealKind            = "SealedJournal"
	sealDomain          = "matrix-installation-journal-v1\x00"
	maximumJournalBytes = 4 * 1024 * 1024
)

var (
	sha256Pattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	hmacPattern   = regexp.MustCompile(`^hmac-sha256:[0-9a-f]{64}$`)
)

type sealedEnvelope struct {
	APIVersion    string          `json:"apiVersion"`
	Kind          string          `json:"kind"`
	Content       json.RawMessage `json:"content"`
	ContentSHA256 string          `json:"contentSha256"`
	Seal          string          `json:"seal"`
}

func encodeSealed(value lifecycle.Journal, key []byte) ([]byte, error) {
	if len(key) != sealKeyBytes {
		return nil, ErrIntegrity
	}
	if err := lifecycle.ValidateJournal(value); err != nil {
		return nil, err
	}
	content, err := json.Marshal(value)
	if err != nil {
		return nil, errors.New("encode installation journal failed")
	}
	digest := sha256.Sum256(content)
	envelope := sealedEnvelope{
		APIVersion:    sealAPIVersion,
		Kind:          sealKind,
		Content:       content,
		ContentSHA256: "sha256:" + hex.EncodeToString(digest[:]),
		Seal:          sealValue(content, key),
	}
	encoded, err := json.Marshal(envelope)
	if err != nil || len(encoded) > maximumJournalBytes {
		return nil, errors.New("encode sealed installation journal failed")
	}
	return encoded, nil
}

func decodeSealed(content, key []byte) (lifecycle.Journal, error) {
	if len(content) == 0 || len(content) > maximumJournalBytes || len(key) != sealKeyBytes {
		return lifecycle.Journal{}, ErrIntegrity
	}
	var envelope sealedEnvelope
	if err := decodeStrict(content, &envelope); err != nil ||
		envelope.APIVersion != sealAPIVersion || envelope.Kind != sealKind ||
		!sha256Pattern.MatchString(envelope.ContentSHA256) || !hmacPattern.MatchString(envelope.Seal) {
		return lifecycle.Journal{}, ErrIntegrity
	}
	var value lifecycle.Journal
	if err := decodeStrict(envelope.Content, &value); err != nil || lifecycle.ValidateJournal(value) != nil {
		return lifecycle.Journal{}, ErrIntegrity
	}
	canonicalContent, err := json.Marshal(value)
	if err != nil || subtle.ConstantTimeCompare(canonicalContent, envelope.Content) != 1 {
		return lifecycle.Journal{}, ErrIntegrity
	}
	digest := sha256.Sum256(envelope.Content)
	expectedDigest := "sha256:" + hex.EncodeToString(digest[:])
	expectedSeal := sealValue(envelope.Content, key)
	if subtle.ConstantTimeCompare([]byte(expectedDigest), []byte(envelope.ContentSHA256)) != 1 ||
		subtle.ConstantTimeCompare([]byte(expectedSeal), []byte(envelope.Seal)) != 1 {
		return lifecycle.Journal{}, ErrIntegrity
	}
	canonicalEnvelope, err := json.Marshal(envelope)
	if err != nil || subtle.ConstantTimeCompare(canonicalEnvelope, content) != 1 {
		return lifecycle.Journal{}, ErrIntegrity
	}
	return value, nil
}

func sealValue(content, key []byte) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(sealDomain))
	_, _ = mac.Write(content)
	return "hmac-sha256:" + hex.EncodeToString(mac.Sum(nil))
}

func decodeStrict(content []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("JSON has trailing content")
	}
	return nil
}
