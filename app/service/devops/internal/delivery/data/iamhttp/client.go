// Package iamhttp adapts delivery authorization to the independently deployed
// Matrix IAM public API.
package iamhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/port"
	"github.com/xiak/matrix/app/service/internal/authorityhttp"
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
		return nil, errors.New("IAM endpoint is invalid")
	}
	if !config.ServiceCredential.Present() {
		return nil, errors.New("DevOps service credential is required")
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
	if response.StatusCode != http.StatusOK ||
		!authorityhttp.ResponseIsJSON(response) ||
		iamv1.DecodeRequest(response.Body, &identity) != nil ||
		iamv1.ValidateServiceIdentity(identity) != nil ||
		identity.Purpose != iamv1.ServiceDevOps {
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
	iamRequest := iamv1.AuthorizationRequest{
		Action: request.Action, Resource: request.Resource,
		RequestID: request.RequestID, CorrelationID: request.CorrelationID,
	}
	if iamv1.ValidateAuthorizationRequest(iamRequest) != nil {
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
	return authorizationFromDecision(request, decision)
}

func authorizationFromDecision(
	request port.AuthorizationRequest,
	decision iamv1.AuthorizationDecision,
) (port.Authorization, error) {
	if !decision.Allowed {
		return port.Authorization{}, port.ErrPermissionDenied
	}
	if decision.Subject == nil {
		return port.Authorization{}, port.ErrAuthorizationUnavailable
	}
	subjectKind, err := toDevOpsSubjectKind(decision.Subject.Type)
	if err != nil {
		return port.Authorization{}, port.ErrAuthorizationUnavailable
	}
	authorization := port.Authorization{
		TenantID:   devopsv1.TenantID(decision.TenantID),
		Subject:    devopsv1.SubjectRef{Kind: subjectKind, ID: string(decision.Subject.ID)},
		DecisionID: string(decision.ID), Action: decision.Action, Resource: decision.Resource,
		RequestID: decision.RequestID, CorrelationID: request.CorrelationID, TraceParent: request.TraceParent,
	}
	if port.ValidateAuthorizationForRequest(
		authorization, request.Action, request.Resource.Kind, devopsv1.ResourceID(request.Resource.ID),
	) != nil {
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

func toDevOpsSubjectKind(value iamv1.PrincipalType) (devopsv1.SubjectKind, error) {
	switch value {
	case iamv1.PrincipalUser:
		return devopsv1.SubjectUser, nil
	case iamv1.PrincipalServiceAccount:
		return devopsv1.SubjectServiceAccount, nil
	default:
		return "", errors.New("IAM subject type cannot map to DevOps")
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
