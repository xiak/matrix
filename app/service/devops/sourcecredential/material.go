// Package sourcecredential owns the portable, purpose-bound filesystem
// contract for source credentials shared by the installer and DevOps runtime.
package sourcecredential

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"io"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
)

const (
	materialAPIVersion = "devops.matrix.xiak.com/v1"
	materialKind       = "SourceCredentialMaterial"

	MaterialFilename     = "material.json"
	MaximumMaterialBytes = 1024
)

type Purpose string

const (
	PurposeWebhook Purpose = "WEBHOOK"
	PurposeFetch   Purpose = "FETCH"
	PurposeReport  Purpose = "REPORT"
)

// Material is a copied credential set. Call Clear as soon as the values are
// no longer needed.
type Material struct {
	Current  []byte
	Previous []byte
}

type materialDocument struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Current    []byte `json:"current"`
	Previous   []byte `json:"previous,omitempty"`
}

func ValidatePurpose(value Purpose) error {
	switch value {
	case PurposeWebhook, PurposeFetch, PurposeReport:
		return nil
	default:
		return errors.New("source credential purpose is invalid")
	}
}

func NewMaterial(purpose Purpose, current, previous []byte) (Material, error) {
	if ValidatePurpose(purpose) != nil || !validValue(purpose, current) ||
		len(previous) != 0 && (purpose != PurposeWebhook || !validValue(purpose, previous)) ||
		len(previous) != 0 && subtle.ConstantTimeCompare(current, previous) == 1 {
		return Material{}, errors.New("source credential material is invalid")
	}
	return Material{
		Current: append([]byte(nil), current...), Previous: append([]byte(nil), previous...),
	}, nil
}

func Encode(purpose Purpose, material Material) ([]byte, error) {
	validated, err := NewMaterial(purpose, material.Current, material.Previous)
	if err != nil {
		return nil, err
	}
	defer validated.Clear()
	content, err := json.Marshal(materialDocument{
		APIVersion: materialAPIVersion, Kind: materialKind,
		Current: validated.Current, Previous: validated.Previous,
	})
	if err != nil || len(content) == 0 || len(content) > MaximumMaterialBytes {
		clear(content)
		return nil, errors.New("encode source credential material failed")
	}
	return content, nil
}

func Decode(purpose Purpose, content []byte) (Material, error) {
	if ValidatePurpose(purpose) != nil || len(content) == 0 || len(content) > MaximumMaterialBytes {
		return Material{}, errors.New("source credential material is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var document materialDocument
	if err := decoder.Decode(&document); err != nil {
		clear(document.Current)
		clear(document.Previous)
		return Material{}, errors.New("source credential material is invalid")
	}
	if err := requireJSONEnd(decoder); err != nil || document.APIVersion != materialAPIVersion ||
		document.Kind != materialKind {
		clear(document.Current)
		clear(document.Previous)
		return Material{}, errors.New("source credential material is invalid")
	}
	material, err := NewMaterial(purpose, document.Current, document.Previous)
	clear(document.Current)
	clear(document.Previous)
	if err != nil {
		return Material{}, err
	}
	canonical, err := Encode(purpose, material)
	if err != nil || len(canonical) != len(content) ||
		subtle.ConstantTimeCompare(canonical, content) != 1 {
		clear(canonical)
		material.Clear()
		return Material{}, errors.New("source credential material is not canonical")
	}
	clear(canonical)
	return material, nil
}

func (material *Material) Clear() {
	if material == nil {
		return
	}
	clear(material.Current)
	clear(material.Previous)
	material.Current = nil
	material.Previous = nil
}

// DirectoryName frames the purpose, tenant, and opaque reference into one
// portable path segment. The digest is configuration metadata, not a secret.
func DirectoryName(
	purpose Purpose,
	scope devopsv1.ResourceScope,
	reference devopsv1.ResourceID,
) (string, error) {
	if err := errors.Join(
		ValidatePurpose(purpose),
		devopsv1.ValidateResourceScope(scope),
		devopsv1.ValidateID("sourceCredentialRef", string(reference)),
	); err != nil {
		return "", errors.New("source credential identity is invalid")
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte("matrix-devops-source-credential-directory-v1"))
	writeFramed(digest, string(purpose))
	writeFramed(digest, string(scope.TenantID))
	writeFramed(digest, string(reference))
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func validValue(purpose Purpose, value []byte) bool {
	minimum := 32
	maximum := 256
	if purpose == PurposeWebhook {
		maximum = 128
	}
	if len(value) < minimum || len(value) > maximum {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}

func requireJSONEnd(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("source credential material has trailing content")
	}
	return nil
}

func writeFramed(writer hash.Hash, value string) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	_, _ = writer.Write(size[:])
	_, _ = writer.Write([]byte(value))
}
