package iamhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/internal/authorityhttp"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/port"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/verifyinstallation"
)

var _ port.Authorizer = (*Client)(nil)
var _ port.AccessKeyAuthorizer = (*Client)(nil)
var _ verifyinstallation.IAM = (*Client)(nil)

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
		return nil, errors.New("PaaS service credential is required")
	}
	return &Client{http: httpClient, serviceCredential: config.ServiceCredential}, nil
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
		identity.Purpose != iamv1.ServicePaaS {
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
		iamv1.CheckAuthorizationDecisionForRequest(decision, iamRequest) != nil {
		return port.Authorization{}, port.ErrAuthorizationUnavailable
	}
	authorization, err := authorizationFromDecision(decision)
	if err != nil {
		return port.Authorization{}, err
	}
	if port.ValidateAuthorizationForRequest(authorization, request) != nil {
		return port.Authorization{}, port.ErrAuthorizationUnavailable
	}
	return authorization, nil
}

func (client *Client) AuthorizeAccessKey(
	ctx context.Context,
	request port.AccessKeyAuthorizationRequest,
) (port.Authorization, error) {
	if client == nil || client.http == nil {
		return port.Authorization{}, port.ErrAuthorizationUnavailable
	}
	if ctx == nil || port.ValidateAccessKeyAuthorizationRequest(request) != nil {
		return port.Authorization{}, port.ErrUnauthenticated
	}
	iamRequest, err := port.NewIAMAccessKeyAuthorizationRequest(request)
	if err != nil {
		return port.Authorization{}, port.ErrAuthorizationUnavailable
	}
	input := iamv1.AccessKeyAuthorizationRequest{Authorization: iamRequest, SignedRequest: request.SignedRequest}
	body, err := iamv1.EncodeAccessKeyAuthorizationRequest(input)
	if err != nil {
		return port.Authorization{}, port.ErrUnauthenticated
	}
	defer clear(body)
	response, err := client.http.Do(ctx, http.MethodPost, "/v1/authorize:access-key",
		bytes.NewReader(body), "application/json", client.serviceCredential, iamv1.Secret{})
	if err != nil {
		return port.Authorization{}, port.ErrAuthorizationUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return port.Authorization{}, authorizationStatusError(response.StatusCode)
	}
	result, err := iamv1.DecodeAccessKeyAuthorization(response.Body)
	if err != nil || iamv1.CheckAccessKeyAuthorizationForRequest(result, input) != nil {
		return port.Authorization{}, port.ErrAuthorizationUnavailable
	}
	authorization, err := authorizationFromDecision(result.Decision)
	if err != nil {
		return port.Authorization{}, err
	}
	if port.ValidateAccessKeyAuthorizationForRequest(authorization, request) != nil {
		return port.Authorization{}, port.ErrAuthorizationUnavailable
	}
	return authorization, nil
}

func (client *Client) ResolveSubject(
	ctx context.Context,
	request port.SubjectResolutionRequest,
) (port.AuthorizationSubjectContext, error) {
	if client == nil || client.http == nil {
		return port.AuthorizationSubjectContext{}, port.ErrAuthorizationUnavailable
	}
	if ctx == nil || port.ValidateSubjectResolutionRequest(request) != nil {
		return port.AuthorizationSubjectContext{}, port.ErrUnauthenticated
	}
	subjectCredential, err := parseBearer(request.Credential)
	if err != nil {
		return port.AuthorizationSubjectContext{}, port.ErrUnauthenticated
	}
	profile, known := iamv1.LookupAuthorizationProfile(iamv1.ProductPaaS)
	if !known || profile.CallingService != iamv1.ServicePaaS {
		return port.AuthorizationSubjectContext{}, port.ErrAuthorizationUnavailable
	}
	_, digest, err := iamv1.CanonicalizeAuthorizationProfile(profile)
	if err != nil {
		return port.AuthorizationSubjectContext{}, port.ErrAuthorizationUnavailable
	}
	iamRequest := iamv1.ResolveAuthorizationSubjectRequest{Profile: iamv1.AuthorizationProfileReference{
		Product: profile.Product, Revision: profile.Revision, ContentDigest: digest,
	}}
	body, err := json.Marshal(iamRequest)
	if err != nil {
		return port.AuthorizationSubjectContext{}, port.ErrAuthorizationUnavailable
	}
	defer clear(body)
	response, err := client.http.Do(ctx, http.MethodPost, "/v1/internal/authorization-subject:resolve",
		bytes.NewReader(body), "application/json", client.serviceCredential, subjectCredential)
	if err != nil {
		return port.AuthorizationSubjectContext{}, port.ErrAuthorizationUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return port.AuthorizationSubjectContext{}, authorizationStatusError(response.StatusCode)
	}
	var resolved iamv1.AuthorizationSubjectContext
	if !authorityhttp.ResponseIsJSON(response) || iamv1.DecodeRequest(response.Body, &resolved) != nil ||
		iamv1.CheckAuthorizationSubjectContextForRequest(resolved, iamRequest) != nil {
		return port.AuthorizationSubjectContext{}, port.ErrAuthorizationUnavailable
	}
	subject, err := toPaaSSubject(resolved.Subject)
	if err != nil {
		return port.AuthorizationSubjectContext{}, port.ErrAuthorizationUnavailable
	}
	result := port.AuthorizationSubjectContext{TenantID: paasv1.TenantID(resolved.TenantID), Subject: subject, Profile: resolved.Profile}
	if port.ValidateAuthorizationSubjectContext(result) != nil {
		return port.AuthorizationSubjectContext{}, port.ErrAuthorizationUnavailable
	}
	return result, nil
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
	iamRequest, err := iamv1.NewAuthorizationRequest(iamv1.ActionInstallationVerify,
		iamv1.ResourceReference{Kind: iamv1.ResourceInstallation, ID: installationID},
		iamv1.AuthorizationResourceInstance, "", requestID, requestID)
	if err != nil {
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
		iamv1.CheckAuthorizationDecisionForRequest(decision, iamRequest) != nil {
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
	subject, err := toPaaSSubject(*decision.Subject)
	if err != nil {
		return port.Authorization{}, port.ErrAuthorizationUnavailable
	}
	authorization := port.Authorization{
		TenantID:     paasv1.TenantID(decision.TenantID),
		Subject:      subject,
		DecisionID:   string(decision.ID),
		RequestID:    decision.RequestID,
		RequestTags:  slices.Clone(decision.RequestTags),
		ResourceTags: slices.Clone(decision.ResourceTags),
	}
	if port.ValidateAuthorization(authorization) != nil {
		return port.Authorization{}, port.ErrAuthorizationUnavailable
	}
	return authorization, nil
}

func toPaaSSubject(value iamv1.Subject) (paasv1.SubjectRef, error) {
	subjectType, err := toPaaSSubjectType(value.Type)
	if err != nil {
		return paasv1.SubjectRef{}, err
	}
	result := paasv1.SubjectRef{Type: subjectType, ID: value.ID, AccessKeyID: string(value.AccessKeyID)}
	if value.RoleSession != nil {
		if (value.RoleSession.SourceUserID == "") == (value.RoleSession.SourceServicePrincipalID == "") {
			return paasv1.SubjectRef{}, errors.New("role source cannot map to apphosting")
		}
		result.RoleSession = &paasv1.RoleSessionReference{
			SessionID: string(value.RoleSession.SessionID), SourceUserID: string(value.RoleSession.SourceUserID),
			SourceServicePrincipalID: string(value.RoleSession.SourceServicePrincipalID),
		}
	}
	if paasv1.ValidateSubjectRef(result) != nil {
		return paasv1.SubjectRef{}, errors.New("IAM subject cannot map to PaaS")
	}
	return result, nil
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
	result, err := port.NewIAMAuthorizationRequest(request)
	if err != nil {
		return iamv1.AuthorizationRequest{}, errors.New("PaaS authorization cannot map to IAM")
	}
	return result, nil
}

func toPaaSSubjectType(value iamv1.SubjectType) (paasv1.SubjectType, error) {
	switch value {
	case iamv1.SubjectUser:
		return paasv1.SubjectUser, nil
	case iamv1.SubjectRole:
		return paasv1.SubjectRole, nil
	case iamv1.SubjectServiceAccount:
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
	case http.StatusConflict:
		return port.ErrAuthorizationReplay
	default:
		return port.ErrAuthorizationUnavailable
	}
}
