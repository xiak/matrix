package iamv1

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"

	"github.com/xiak/matrix/api/contractjson"
)

var ErrEncodingFailed = errors.New("IAM contract encoding failed")

// BootstrapDigest is the single byte-preserving commitment to the sealed
// installer bootstrap document. It deliberately reuses its private encoder.
func BootstrapDigest(document BootstrapDocument) (string, error) {
	encoded, err := EncodeBootstrapDocument(document)
	if err != nil {
		return "", err
	}
	defer clear(encoded)
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

// DecodeRequest applies the common strict IAM request decoder.
func DecodeRequest(reader io.Reader, destination any) error {
	return contractjson.DecodeObject(reader, MaxRequestBytes, destination)
}

func (request *AuthorizationRequest) UnmarshalJSON(source []byte) error {
	type wire AuthorizationRequest
	var decoded wire
	if err := contractjson.DecodeObjectBytes(source, MaxRequestBytes, &decoded); err != nil {
		return err
	}
	if checkAuthorizationTargetEncoding(source, decoded.ResourceMode) != nil {
		return contractjson.ErrInvalidDocument
	}
	*request = AuthorizationRequest(decoded)
	return nil
}

func (decision *AuthorizationDecision) UnmarshalJSON(source []byte) error {
	type wire AuthorizationDecision
	var decoded wire
	if err := contractjson.DecodeObjectBytes(source, MaxRequestBytes, &decoded); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(source, &fields) != nil {
		return contractjson.ErrInvalidDocument
	}
	current := false
	for _, key := range []string{"profile", "resourceMode", "collectionUsage", "correlationId"} {
		if _, exists := fields[key]; exists {
			current = true
		}
	}
	// This preserves only historical syntax. It does not establish legacy row
	// eligibility; current consumers validate the mandatory full binding.
	if current {
		if checkAuthorizationTargetEncoding(source, decoded.ResourceMode) != nil || decoded.Profile == nil || decoded.CorrelationID == "" {
			return contractjson.ErrInvalidDocument
		}
	}
	*decision = AuthorizationDecision(decoded)
	return nil
}

func checkAuthorizationTargetEncoding(source []byte, mode AuthorizationResourceMode) error {
	var fields map[string]json.RawMessage
	if json.Unmarshal(source, &fields) != nil {
		return contractjson.ErrInvalidDocument
	}
	for _, key := range []string{"profile", "resourceMode", "correlationId"} {
		if value, exists := fields[key]; !exists || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return contractjson.ErrInvalidDocument
		}
	}
	usage, exists := fields["collectionUsage"]
	switch mode {
	case AuthorizationResourceInstance:
		if exists {
			return contractjson.ErrInvalidDocument
		}
	case AuthorizationResourceCollection:
		var value AuthorizationCollectionUsage
		if !exists || json.Unmarshal(usage, &value) != nil || (value != AuthorizationCollectionCreate && value != AuthorizationCollectionList) {
			return contractjson.ErrInvalidDocument
		}
	default:
		return contractjson.ErrInvalidDocument
	}
	return nil
}

func (value *UserPermissionBoundary) UnmarshalJSON(source []byte) error {
	type wire UserPermissionBoundary
	var decoded wire
	if err := contractjson.DecodeObjectBytes(source, MaxRequestBytes, &decoded); err != nil {
		return err
	}
	var fields struct {
		Policy json.RawMessage `json:"policy"`
	}
	if err := json.Unmarshal(source, &fields); err != nil || len(fields.Policy) == 0 {
		return contractjson.ErrInvalidDocument
	}
	result := UserPermissionBoundary(decoded)
	if err := ValidateUserPermissionBoundary(result); err != nil {
		return err
	}
	*value = result
	return nil
}

func (request *ChangePasswordRequest) UnmarshalJSON(source []byte) error {
	// A missing policy defaults to true; explicit null is not a boolean choice.
	// Reuse the strict decoder rather than bypassing its field/duplicate checks.
	type wire ChangePasswordRequest
	var decoded wire
	if err := contractjson.DecodeObjectBytes(source, MaxRequestBytes, &decoded); err != nil {
		return err
	}
	var policy struct {
		Value json.RawMessage `json:"revokeOtherSessions"`
	}
	if err := json.Unmarshal(source, &policy); err != nil || bytes.Equal(bytes.TrimSpace(policy.Value), []byte("null")) {
		return contractjson.ErrInvalidDocument
	}
	*request = ChangePasswordRequest(decoded)
	return nil
}

func DecodeBootstrapDocument(reader io.Reader) (BootstrapDocument, error) {
	var document BootstrapDocument
	if err := contractjson.DecodeObject(reader, MaxBootstrapBytes, &document); err != nil {
		return BootstrapDocument{}, err
	}
	if err := ValidateBootstrapDocument(document); err != nil {
		return BootstrapDocument{}, err
	}
	return document, nil
}

// EncodeBootstrapDocument is the only contract encoder that intentionally
// emits bootstrap credential material.
func EncodeBootstrapDocument(document BootstrapDocument) ([]byte, error) {
	if err := ValidateBootstrapDocument(document); err != nil {
		return nil, err
	}
	type administratorWire struct {
		ID          PrincipalID `json:"id"`
		LoginName   string      `json:"loginName"`
		DisplayName string      `json:"displayName"`
		Password    string      `json:"password"`
	}
	type serviceWire struct {
		Purpose     ServicePurpose `json:"purpose"`
		PrincipalID PrincipalID    `json:"principalId"`
		Credential  string         `json:"credential"`
	}
	services := make([]serviceWire, len(document.Services))
	for index, service := range document.Services {
		services[index] = serviceWire{
			Purpose: service.Purpose, PrincipalID: service.PrincipalID,
			Credential: service.Credential.reveal(),
		}
	}
	wire := struct {
		APIVersion     string              `json:"apiVersion"`
		Kind           string              `json:"kind"`
		InstallationID string              `json:"installationId"`
		Organization   InitialOrganization `json:"organization"`
		Administrator  administratorWire   `json:"administrator"`
		Services       []serviceWire       `json:"services"`
	}{
		APIVersion: document.APIVersion, Kind: document.Kind,
		InstallationID: document.InstallationID,
		Organization:   document.Organization,
		Administrator: administratorWire{
			ID: document.Administrator.ID, LoginName: document.Administrator.LoginName,
			DisplayName: document.Administrator.DisplayName,
			Password:    document.Administrator.Password.reveal(),
		},
		Services: services,
	}
	encoded, err := json.Marshal(wire)
	if err != nil {
		return nil, ErrEncodingFailed
	}
	return encoded, nil
}

// EncodeLoginResponse is the only response encoder that intentionally emits
// a newly issued session credential.
func EncodeLoginResponse(response LoginResponse) ([]byte, error) {
	if err := ValidateLoginResponse(response); err != nil {
		return nil, err
	}
	wire := struct {
		Session            Session `json:"session"`
		Credential         string  `json:"credential"`
		MustChangePassword bool    `json:"mustChangePassword"`
	}{
		Session:            response.Session,
		Credential:         response.Credential.reveal(),
		MustChangePassword: response.MustChangePassword,
	}
	encoded, err := json.Marshal(wire)
	if err != nil {
		return nil, ErrEncodingFailed
	}
	return encoded, nil
}
