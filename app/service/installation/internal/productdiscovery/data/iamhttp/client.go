package iamhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/installation/internal/productdiscovery"
	"github.com/xiak/matrix/app/service/internal/authorityhttp"
)

var _ productdiscovery.Authorizer = (*Client)(nil)

type Config struct {
	Endpoint          string
	ServiceCredential iamv1.Secret
	HTTPClient        *http.Client
}

type Client struct {
	http              *authorityhttp.Client
	serviceCredential iamv1.Secret
}

func NewClient(config Config) (*Client, error) {
	httpClient, err := authorityhttp.New(config.Endpoint, config.HTTPClient)
	if err != nil {
		return nil, errors.New("IAM endpoint is invalid")
	}
	if !config.ServiceCredential.Present() {
		return nil, errors.New("platform service credential is required")
	}
	return &Client{http: httpClient, serviceCredential: config.ServiceCredential}, nil
}

func (client *Client) Ready(ctx context.Context) error {
	if client == nil || client.http == nil || ctx == nil {
		return productdiscovery.ErrAuthorizationUnavailable
	}
	response, err := client.http.Do(
		ctx,
		http.MethodGet,
		"/v1/service-identity",
		nil,
		"",
		client.serviceCredential,
		iamv1.Secret{},
	)
	if err != nil {
		return productdiscovery.ErrAuthorizationUnavailable
	}
	defer response.Body.Close()
	var identity iamv1.ServiceIdentity
	if response.StatusCode != http.StatusOK ||
		!authorityhttp.ResponseIsJSON(response) ||
		iamv1.DecodeRequest(response.Body, &identity) != nil ||
		iamv1.ValidateServiceIdentity(identity) != nil ||
		identity.Purpose != iamv1.ServicePlatform {
		return productdiscovery.ErrAuthorizationUnavailable
	}
	return nil
}

func (client *Client) Authorize(
	ctx context.Context,
	request productdiscovery.AuthorizationRequest,
) error {
	if client == nil || client.http == nil || ctx == nil {
		return productdiscovery.ErrAuthorizationUnavailable
	}
	subjectCredential, err := parseBearer(request.Credential)
	if err != nil {
		return productdiscovery.ErrUnauthenticated
	}
	iamRequest := iamv1.AuthorizationRequest{
		Action: iamv1.ActionInstallationProductRead,
		Resource: iamv1.ResourceReference{
			Kind: iamv1.ResourceInstallation,
			ID:   request.InstallationID,
		},
		RequestID:     request.RequestID,
		CorrelationID: request.RequestID,
	}
	if iamv1.ValidateAuthorizationRequest(iamRequest) != nil {
		return productdiscovery.ErrInvalidArgument
	}
	body, err := json.Marshal(iamRequest)
	if err != nil {
		return productdiscovery.ErrAuthorizationUnavailable
	}
	response, err := client.http.Do(
		ctx,
		http.MethodPost,
		"/v1/authorize",
		bytes.NewReader(body),
		"application/json",
		client.serviceCredential,
		subjectCredential,
	)
	if err != nil {
		return productdiscovery.ErrAuthorizationUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return authorizationStatusError(response.StatusCode)
	}
	var decision iamv1.AuthorizationDecision
	if !authorityhttp.ResponseIsJSON(response) ||
		iamv1.DecodeRequest(response.Body, &decision) != nil ||
		iamv1.ValidateAuthorizationDecision(decision) != nil ||
		decision.Action != iamRequest.Action ||
		decision.Resource != iamRequest.Resource ||
		decision.RequestID != iamRequest.RequestID {
		return productdiscovery.ErrAuthorizationUnavailable
	}
	if !decision.Allowed {
		return productdiscovery.ErrPermissionDenied
	}
	if decision.Subject == nil || decision.TenantID == "" {
		return productdiscovery.ErrAuthorizationUnavailable
	}
	return nil
}

func parseBearer(value string) (iamv1.Secret, error) {
	const prefix = "Bearer "
	if !strings.HasPrefix(value, prefix) || len(value) == len(prefix) ||
		strings.Contains(value[len(prefix):], " ") {
		return iamv1.Secret{}, errors.New("authorization credential is invalid")
	}
	return iamv1.NewSecret(value[len(prefix):])
}

func authorizationStatusError(status int) error {
	switch status {
	case http.StatusUnauthorized:
		return productdiscovery.ErrUnauthenticated
	case http.StatusForbidden:
		return productdiscovery.ErrPermissionDenied
	default:
		return productdiscovery.ErrAuthorizationUnavailable
	}
}
