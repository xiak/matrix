package managedservicev1

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"

	"github.com/xiak/matrix/api/contractjson"
)

const MaxRequestBytes = 64 * 1024

// DecodeRequest applies the repository-wide strict, single-object JSON
// boundary so native provider and forged authority fields cannot be ignored.
func DecodeRequest(reader io.Reader, destination any) error {
	return contractjson.DecodeObject(reader, MaxRequestBytes, destination)
}

// CanonicalizeServiceDefinition returns the single activation-contract
// encoding. Display metadata and current availability are intentionally not
// committed: changing either cannot silently reinterpret Account consent.
func CanonicalizeServiceDefinition(value ServiceDefinition) (document, contentDigest string, err error) {
	if err := validateServiceDefinitionCommitment(value.ID, value.Revision, value.ActivationPrerequisite); err != nil {
		return "", "", err
	}
	commitment := struct {
		APIVersion             string                        `json:"apiVersion"`
		Kind                   string                        `json:"kind"`
		ID                     string                        `json:"id"`
		Revision               uint64                        `json:"revision"`
		ActivationPrerequisite ServiceActivationPrerequisite `json:"activationPrerequisite"`
	}{
		APIVersion: APIVersion, Kind: "ServiceDefinition", ID: value.ID,
		Revision: value.Revision, ActivationPrerequisite: value.ActivationPrerequisite,
	}
	encoded, err := json.Marshal(commitment)
	if err != nil {
		return "", "", errors.New("service definition cannot be canonicalized")
	}
	digest := sha256.Sum256(encoded)
	return string(encoded), "sha256:" + hex.EncodeToString(digest[:]), nil
}
