package iamhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/internal/authorityhttp"
	"github.com/xiak/matrix/app/service/paas/internal/managedservice/port"
)

var _ port.Authorizer = (*Client)(nil)

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
		return nil, errors.New("managed-service IAM endpoint is invalid")
	}
	if !config.ServiceCredential.Present() {
		return nil, errors.New("managed-service PaaS credential is required")
	}
	return &Client{http: httpClient, serviceCredential: config.ServiceCredential}, nil
}

func (client *Client) Ready(ctx context.Context) error {
	if client == nil || client.http == nil || ctx == nil {
		return port.ErrAuthorizationUnavailable
	}
	response, err := client.http.Do(
		ctx, http.MethodGet, "/v1/service-identity", nil, "",
		client.serviceCredential, iamv1.Secret{},
	)
	if err != nil {
		return port.ErrAuthorizationUnavailable
	}
	defer response.Body.Close()
	var identity iamv1.ServiceIdentity
	if response.StatusCode != http.StatusOK || !authorityhttp.ResponseIsJSON(response) ||
		iamv1.DecodeRequest(response.Body, &identity) != nil ||
		iamv1.ValidateServiceIdentity(identity) != nil || identity.Purpose != iamv1.ServicePaaS {
		return port.ErrAuthorizationUnavailable
	}
	return nil
}

func (client *Client) Authorize(
	ctx context.Context,
	request port.AuthorizationRequest,
) (port.Authorization, error) {
	if client == nil || client.http == nil {
		return port.Authorization{}, port.ErrAuthorizationUnavailable
	}
	if ctx == nil || port.ValidateAuthorizationRequest(request) != nil {
		return port.Authorization{}, port.ErrUnauthenticated
	}
	subjectCredential, err := parseBearer(request.Credential)
	if err != nil {
		return port.Authorization{}, port.ErrUnauthenticated
	}
	iamRequest, err := toIAMRequest(request)
	if err != nil {
		return port.Authorization{}, port.ErrAuthorizationUnavailable
	}
	body, err := json.Marshal(iamRequest)
	if err != nil {
		return port.Authorization{}, port.ErrAuthorizationUnavailable
	}
	defer clear(body)
	response, err := client.http.Do(
		ctx, http.MethodPost, "/v1/authorize", bytes.NewReader(body), "application/json",
		client.serviceCredential, subjectCredential,
	)
	if err != nil {
		return port.Authorization{}, port.ErrAuthorizationUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return port.Authorization{}, authorizationStatusError(response.StatusCode)
	}
	var decision iamv1.AuthorizationDecision
	if !authorityhttp.ResponseIsJSON(response) ||
		iamv1.DecodeRequest(response.Body, &decision) != nil ||
		iamv1.ValidateAuthorizationDecision(decision) != nil ||
		decision.Action != iamRequest.Action || decision.Resource != iamRequest.Resource ||
		decision.RequestID != iamRequest.RequestID {
		return port.Authorization{}, port.ErrAuthorizationUnavailable
	}
	if !decision.Allowed {
		return port.Authorization{}, port.ErrPermissionDenied
	}
	if decision.Subject == nil {
		return port.Authorization{}, port.ErrAuthorizationUnavailable
	}
	authorization := port.Authorization{
		TenantID: string(decision.TenantID), SubjectID: string(decision.Subject.ID),
		DecisionID: string(decision.ID), RequestID: decision.RequestID,
	}
	if port.ValidateAuthorizationForRequest(authorization, request) != nil {
		return port.Authorization{}, port.ErrAuthorizationUnavailable
	}
	return authorization, nil
}

func toIAMRequest(request port.AuthorizationRequest) (iamv1.AuthorizationRequest, error) {
	resourceKind, err := toIAMResourceKind(request.Resource.Kind)
	if err != nil {
		return iamv1.AuthorizationRequest{}, err
	}
	result := iamv1.AuthorizationRequest{
		Action:    iamv1.Action(request.Action),
		Resource:  iamv1.ResourceReference{Kind: resourceKind, ID: request.Resource.ID},
		RequestID: request.RequestID, CorrelationID: request.RequestID,
	}
	if iamv1.ValidateAuthorizationRequest(result) != nil {
		return iamv1.AuthorizationRequest{}, errors.New("managed-service authorization cannot map to IAM")
	}
	return result, nil
}

func toIAMResourceKind(value string) (iamv1.ResourceKind, error) {
	switch value {
	case port.ResourceServiceOffering:
		return iamv1.ResourceServiceOffering, nil
	case port.ResourceRegion:
		return iamv1.ResourceRegion, nil
	case port.ResourceQuotaEntitlement:
		return iamv1.ResourceQuotaEntitlement, nil
	case port.ResourceServiceInstallation:
		return iamv1.ResourceServiceInstallation, nil
	default:
		return "", errors.New("managed-service authorization resource kind is invalid")
	}
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
		return port.ErrUnauthenticated
	case http.StatusForbidden:
		return port.ErrPermissionDenied
	default:
		return port.ErrAuthorizationUnavailable
	}
}
