package iamv1

import (
	"encoding/json"
	"errors"
	"io"

	"github.com/xiak/matrix/api/contractjson"
)

var ErrEncodingFailed = errors.New("IAM contract encoding failed")

// DecodeRequest applies the common strict IAM request decoder.
func DecodeRequest(reader io.Reader, destination any) error {
	return contractjson.DecodeObject(reader, MaxRequestBytes, destination)
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
