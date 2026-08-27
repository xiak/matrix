package iamhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/internal/authorityhttp"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/port"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/verifyinstallation"
)

var _ port.Authorizer = (*Client)(nil)
var _ verifyinstallation.IAM = (*Client)(nil)

type Config struct {
	Endpoint          string
	ServiceCredential iamv1.Secret
	HTTPClient        *http.Client
	InstallationID    string
}

type Client struct {
	http              *authorityhttp.Client
	serviceCredential iamv1.Secret
	installationID    string
}

func NewClient(config Config) (*Client, error) {
	httpClient, err := authorityhttp.New(config.Endpoint, config.HTTPClient)
	if err != nil {
		return nil, errors.New("IAM endpoint is invalid")
	}
	if !config.ServiceCredential.Present() || paasv1.ValidateID("installationId", config.InstallationID) != nil {
		return nil, errors.New("PaaS installation and service credential are required")
	}
	return &Client{http: httpClient, serviceCredential: config.ServiceCredential, installationID: config.InstallationID}, nil
}

func (client *Client) Ready(ctx context.Context) error {
	if client == nil || client.http == nil || ctx == nil {
		return port.ErrAuthorizationUnavailable
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
		return port.ErrAuthorizationUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return port.ErrAuthorizationUnavailable
	}
	var identity iamv1.ServiceIdentity
	if !authorityhttp.ResponseIsJSON(response) ||
		iamv1.DecodeRequest(response.Body, &identity) != nil ||
		iamv1.ValidateServiceIdentity(identity) != nil ||
		identity.Purpose != iamv1.ServicePaaS || identity.InstallationID != client.installationID {
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
		ctx,
		http.MethodPost,
		"/v1/authorize",
		bytes.NewReader(body),
		"application/json",
		client.serviceCredential,
		subjectCredential,
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
	authorization, err := authorizationFromDecision(decision)
	if err != nil {
		return port.Authorization{}, err
	}
	if port.ValidateAuthorizationForRequest(authorization, request) != nil {
		return port.Authorization{}, port.ErrAuthorizationUnavailable
	}
	if authorization.InstallationID != "" && authorization.InstallationID != client.installationID {
		return port.Authorization{}, port.ErrAuthorizationUnavailable
	}
	return authorization, nil
}

func (client *Client) VerifyInstallation(
	ctx context.Context,
	credential string,
	installationID string,
	requestID string,
) (port.Authorization, error) {
	if client == nil || client.http == nil {
		return port.Authorization{}, port.ErrAuthorizationUnavailable
	}
	verifierCredential, err := parseBearer(credential)
	if err != nil || ctx == nil {
		return port.Authorization{}, port.ErrUnauthenticated
	}
	iamRequest := iamv1.AuthorizationRequest{
		Action: iamv1.ActionInstallationVerify,
		Resource: iamv1.ResourceReference{
			Kind: iamv1.ResourceInstallation,
			ID:   installationID,
		},
		RequestID:     requestID,
		CorrelationID: requestID,
	}
	if iamv1.ValidateAuthorizationRequest(iamRequest) != nil {
		return port.Authorization{}, port.ErrUnauthenticated
	}
	body, err := json.Marshal(iamRequest)
	if err != nil {
		return port.Authorization{}, port.ErrAuthorizationUnavailable
	}
	defer clear(body)
	response, err := client.http.Do(
		ctx,
		http.MethodPost,
		"/v1/installation:verify",
		bytes.NewReader(body),
		"application/json",
		verifierCredential,
		iamv1.Secret{},
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
		decision.Action != iamRequest.Action ||
		decision.Resource != iamRequest.Resource ||
		decision.RequestID != iamRequest.RequestID {
		return port.Authorization{}, port.ErrAuthorizationUnavailable
	}
	authorization, err := authorizationFromDecision(decision)
	if err != nil {
		return port.Authorization{}, err
	}
	if authorization.Subject.Type != paasv1.SubjectServiceAccount ||
		authorization.RequestID != requestID {
		return port.Authorization{}, port.ErrAuthorizationUnavailable
	}
	return authorization, nil
}

func authorizationFromDecision(
	decision iamv1.AuthorizationDecision,
) (port.Authorization, error) {
	if !decision.Allowed {
		return port.Authorization{}, port.ErrPermissionDenied
	}
	if decision.Subject == nil {
		return port.Authorization{}, port.ErrAuthorizationUnavailable
	}
	subjectType, err := toPaaSSubjectType(decision.Subject.Type)
	if err != nil {
		return port.Authorization{}, port.ErrAuthorizationUnavailable
	}
	authorization := port.Authorization{
		TenantID:       paasv1.TenantID(decision.TenantID),
		InstallationID: decision.InstallationID,
		Subject:        paasv1.SubjectRef{Type: subjectType, ID: string(decision.Subject.ID)},
		DecisionID:     string(decision.ID),
		RequestID:      decision.RequestID,
	}
	validate := port.ValidateAuthorization
	if iamv1.IsPlatformAction(decision.Action) {
		validate = port.ValidatePlatformAuthorization
	}
	if validate(authorization) != nil {
		return port.Authorization{}, port.ErrAuthorizationUnavailable
	}
	return authorization, nil
}

func parseBearer(value string) (iamv1.Secret, error) {
	const prefix = "Bearer "
	if !strings.HasPrefix(value, prefix) || len(value) == len(prefix) ||
		strings.Contains(value[len(prefix):], " ") {
		return iamv1.Secret{}, errors.New("authorization credential is invalid")
	}
	return iamv1.NewSecret(value[len(prefix):])
}

func toIAMRequest(request port.AuthorizationRequest) (iamv1.AuthorizationRequest, error) {
	resourceKind, err := toIAMResourceKind(request.Resource.Kind)
	if err != nil {
		return iamv1.AuthorizationRequest{}, err
	}
	result := iamv1.AuthorizationRequest{
		Action:        iamv1.Action(request.Action),
		Resource:      iamv1.ResourceReference{Kind: resourceKind, ID: string(request.Resource.ID)},
		RequestID:     request.RequestID,
		CorrelationID: request.RequestID,
	}
	if iamv1.ValidateAuthorizationRequest(result) != nil {
		return iamv1.AuthorizationRequest{}, errors.New("PaaS authorization cannot map to IAM")
	}
	return result, nil
}

func toIAMResourceKind(kind string) (iamv1.ResourceKind, error) {
	switch kind {
	case "Application":
		return iamv1.ResourceApplication, nil
	case "Configuration":
		return iamv1.ResourceConfiguration, nil
	case "ConfigurationRevision":
		return iamv1.ResourceConfigurationRevision, nil
	case "ApplicationRevision":
		return iamv1.ResourceApplicationRevision, nil
	case "Deployment":
		return iamv1.ResourceDeployment, nil
	case "Operation":
		return iamv1.ResourceOperation, nil
	case "ExecutionPool":
		return iamv1.ResourceExecutionPool, nil
	case "ExecutionTarget":
		return iamv1.ResourceExecutionTarget, nil
	default:
		return "", errors.New("PaaS authorization resource kind is invalid")
	}
}

func toPaaSSubjectType(value iamv1.PrincipalType) (paasv1.SubjectType, error) {
	switch value {
	case iamv1.PrincipalUser:
		return paasv1.SubjectUser, nil
	case iamv1.PrincipalServiceAccount:
		return paasv1.SubjectServiceAccount, nil
	default:
		return "", errors.New("IAM subject type cannot map to PaaS")
	}
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
