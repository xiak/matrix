package iamhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/audit/internal/usecase/auditlog"
	"github.com/xiak/matrix/app/service/internal/authorityhttp"
)

var _ auditlog.IAM = (*Client)(nil)

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
		return nil, errors.New("Audit service credential is required")
	}
	return &Client{
		http:              httpClient,
		serviceCredential: config.ServiceCredential,
	}, nil
}

func (client *Client) ResolveAuditProducer(
	ctx context.Context,
	producerCredential iamv1.Secret,
	request iamv1.ResolveAuditProducerRequest,
) (iamv1.AuditProducerAuthorization, error) {
	if client == nil || client.http == nil {
		return iamv1.AuditProducerAuthorization{}, auditlog.ErrUnavailable
	}
	if ctx == nil || !producerCredential.Present() || iamv1.ValidateResolveAuditProducerRequest(request) != nil {
		return iamv1.AuditProducerAuthorization{}, auditlog.ErrInvalidArgument
	}
	body, err := json.Marshal(request)
	if err != nil {
		return iamv1.AuditProducerAuthorization{}, auditlog.ErrUnavailable
	}
	response, err := client.http.Do(
		ctx,
		http.MethodPost,
		"/v1/audit-producer:resolve",
		bytes.NewReader(body),
		"application/json",
		producerCredential,
		iamv1.Secret{},
	)
	if err != nil {
		return iamv1.AuditProducerAuthorization{}, fmt.Errorf("call IAM authority: %w", auditlog.ErrUnavailable)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return iamv1.AuditProducerAuthorization{}, statusError(response.StatusCode)
	}
	var identity iamv1.AuditProducerAuthorization
	if !authorityhttp.ResponseIsJSON(response) || iamv1.DecodeRequest(response.Body, &identity) != nil ||
		iamv1.ValidateAuditProducerAuthorization(identity) != nil || identity.TenantID != iamv1.OrganizationID(request.Event.TenantID) ||
		identity.InstallationID != request.Event.InstallationID {
		return iamv1.AuditProducerAuthorization{}, auditlog.ErrUnavailable
	}
	return identity, nil
}

func (client *Client) Authorize(
	ctx context.Context,
	subjectCredential iamv1.Secret,
	authorization iamv1.AuthorizationRequest,
) (iamv1.AuthorizationDecision, error) {
	if client == nil || client.http == nil {
		return iamv1.AuthorizationDecision{}, auditlog.ErrUnavailable
	}
	if ctx == nil || !subjectCredential.Present() ||
		iamv1.ValidateAuthorizationRequest(authorization) != nil {
		return iamv1.AuthorizationDecision{}, auditlog.ErrInvalidArgument
	}
	body, err := json.Marshal(authorization)
	if err != nil {
		return iamv1.AuthorizationDecision{}, auditlog.ErrUnavailable
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
		return iamv1.AuthorizationDecision{}, fmt.Errorf("call IAM authority: %w", auditlog.ErrUnavailable)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return iamv1.AuthorizationDecision{}, statusError(response.StatusCode)
	}
	var decision iamv1.AuthorizationDecision
	if !authorityhttp.ResponseIsJSON(response) || iamv1.DecodeRequest(response.Body, &decision) != nil ||
		iamv1.ValidateAuthorizationDecision(decision) != nil {
		return iamv1.AuthorizationDecision{}, auditlog.ErrUnavailable
	}
	return decision, nil
}

func (client *Client) VerifyInstallation(
	ctx context.Context,
	verifierCredential iamv1.Secret,
	authorization iamv1.AuthorizationRequest,
) (iamv1.AuthorizationDecision, error) {
	if client == nil || client.http == nil {
		return iamv1.AuthorizationDecision{}, auditlog.ErrUnavailable
	}
	if ctx == nil || !verifierCredential.Present() ||
		iamv1.ValidateAuthorizationRequest(authorization) != nil ||
		authorization.Action != iamv1.ActionInstallationVerify ||
		authorization.Resource.Kind != iamv1.ResourceInstallation {
		return iamv1.AuthorizationDecision{}, auditlog.ErrInvalidArgument
	}
	body, err := json.Marshal(authorization)
	if err != nil {
		return iamv1.AuthorizationDecision{}, auditlog.ErrUnavailable
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
		return iamv1.AuthorizationDecision{}, fmt.Errorf("call IAM authority: %w", auditlog.ErrUnavailable)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return iamv1.AuthorizationDecision{}, statusError(response.StatusCode)
	}
	var decision iamv1.AuthorizationDecision
	if !authorityhttp.ResponseIsJSON(response) || iamv1.DecodeRequest(response.Body, &decision) != nil ||
		iamv1.ValidateAuthorizationDecision(decision) != nil ||
		decision.Action != authorization.Action || decision.Resource != authorization.Resource ||
		decision.RequestID != authorization.RequestID {
		return iamv1.AuthorizationDecision{}, auditlog.ErrUnavailable
	}
	return decision, nil
}

func statusError(status int) error {
	switch status {
	case http.StatusUnauthorized:
		return auditlog.ErrUnauthenticated
	case http.StatusForbidden:
		return auditlog.ErrForbidden
	default:
		return auditlog.ErrUnavailable
	}
}
