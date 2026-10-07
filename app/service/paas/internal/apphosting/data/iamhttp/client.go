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
var _ port.BatchAuthorizer = (*Client)(nil)
var _ port.AccessKeyAuthorizer = (*Client)(nil)
var _ port.AccessKeyListAuthorizer = (*Client)(nil)
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

func (client *Client) AuthorizeBatch(
	ctx context.Context,
	request port.AuthorizationBatchRequest,
) (port.AuthorizationBatch, error) {
	if client == nil || client.http == nil {
		return port.AuthorizationBatch{}, port.ErrAuthorizationUnavailable
	}
	if ctx == nil || port.ValidateAuthorizationBatchRequest(request) != nil {
		return port.AuthorizationBatch{}, port.ErrUnauthenticated
	}
	subjectCredential, err := parseBearer(request.Credential)
	if err != nil {
		return port.AuthorizationBatch{}, port.ErrUnauthenticated
	}
	iamRequests := make([]iamv1.AuthorizationRequest, len(request.Requests))
	for index := range request.Requests {
		mapped, mapErr := toIAMRequest(request.Requests[index])
		if mapErr != nil {
			return port.AuthorizationBatch{}, port.ErrAuthorizationUnavailable
		}
		iamRequests[index] = mapped
	}
	iamRequest := iamv1.AuthorizationBatchRequest{Requests: iamRequests}
	body, err := json.Marshal(iamRequest)
	if err != nil {
		return port.AuthorizationBatch{}, port.ErrAuthorizationUnavailable
	}
	defer clear(body)
	response, err := client.http.Do(ctx, http.MethodPost, "/v1/authorize:batch",
		bytes.NewReader(body), "application/json", client.serviceCredential, subjectCredential)
	if err != nil {
		return port.AuthorizationBatch{}, port.ErrAuthorizationUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return port.AuthorizationBatch{}, authorizationStatusError(response.StatusCode)
	}
	var decision iamv1.AuthorizationBatchDecision
	if !authorityhttp.ResponseIsJSON(response) || iamv1.DecodeRequest(response.Body, &decision) != nil ||
		iamv1.CheckAuthorizationBatchDecisionForRequest(decision, iamRequest) != nil {
		return port.AuthorizationBatch{}, port.ErrAuthorizationUnavailable
	}
	result, err := authorizationBatchFromDecision(decision)
	if err != nil || port.ValidateAuthorizationBatchForRequest(result, request) != nil {
		return port.AuthorizationBatch{}, port.ErrAuthorizationUnavailable
	}
	return result, nil
}

func (client *Client) AuthorizeAccessKeyList(
	ctx context.Context,
	request port.AccessKeyListAuthorizationRequest,
) (port.AccessKeyListAuthorization, error) {
	if client == nil || client.http == nil {
		return port.AccessKeyListAuthorization{}, port.ErrAuthorizationUnavailable
	}
	if ctx == nil || port.ValidateAccessKeyListAuthorizationRequest(request) != nil {
		return port.AccessKeyListAuthorization{}, port.ErrUnauthenticated
	}
	iamRequest, err := port.NewIAMAccessKeyListAuthorizationRequest(request)
	if err != nil {
		return port.AccessKeyListAuthorization{}, port.ErrAuthorizationUnavailable
	}
	body, err := iamv1.EncodeAccessKeyListAuthorizationRequest(iamRequest)
	if err != nil {
		return port.AccessKeyListAuthorization{}, port.ErrUnauthenticated
	}
	defer clear(body)
	response, err := client.http.Do(ctx, http.MethodPost, "/v1/authorize:access-key-list",
		bytes.NewReader(body), "application/json", client.serviceCredential, iamv1.Secret{})
	if err != nil {
		return port.AccessKeyListAuthorization{}, port.ErrAuthorizationUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return port.AccessKeyListAuthorization{}, authorizationStatusError(response.StatusCode)
	}
	decision, err := iamv1.DecodeAccessKeyListAuthorization(response.Body)
	if err != nil || iamv1.CheckAccessKeyListAuthorizationForRequest(decision, iamRequest) != nil {
		return port.AccessKeyListAuthorization{}, port.ErrAuthorizationUnavailable
	}
	if !decision.Collection.Allowed {
		return port.AccessKeyListAuthorization{}, port.ErrPermissionDenied
	}
	collection, err := authorizationFromDecision(decision.Collection)
	if err != nil {
		return port.AccessKeyListAuthorization{}, err
	}
	batchDecision := iamv1.AuthorizationBatchDecision{
		APIVersion: iamv1.APIVersion, Kind: "AuthorizationBatchDecision",
		TenantID: decision.Collection.TenantID, Subject: *decision.Collection.Subject,
		Profile: *decision.Collection.Profile, Action: decision.Collection.Action,
		ResourceKind: decision.Collection.Resource.Kind, NetworkContext: decision.Collection.NetworkContext,
		CorrelationID: decision.Collection.CorrelationID, DecidedAt: decision.Collection.DecidedAt,
		Decisions: decision.Instances,
	}
	instances, err := authorizationBatchFromDecision(batchDecision)
	if err != nil {
		return port.AccessKeyListAuthorization{}, port.ErrAuthorizationUnavailable
	}
	result := port.AccessKeyListAuthorization{Collection: collection, Instances: instances}
	if port.ValidateAccessKeyListAuthorizationForRequest(result, request) != nil {
		return port.AccessKeyListAuthorization{}, port.ErrAuthorizationUnavailable
	}
	return result, nil
}

func authorizationBatchFromDecision(decision iamv1.AuthorizationBatchDecision) (port.AuthorizationBatch, error) {
	subject, err := toPaaSSubject(decision.Subject)
	if err != nil {
		return port.AuthorizationBatch{}, err
	}
	result := port.AuthorizationBatch{
		TenantID: paasv1.TenantID(decision.TenantID), Subject: subject,
		Items: make([]port.AuthorizationBatchItem, len(decision.Decisions)),
	}
	for index, item := range decision.Decisions {
		resource, mapErr := toPaaSResource(item.Resource)
		if mapErr != nil {
			return port.AuthorizationBatch{}, mapErr
		}
		result.Items[index] = port.AuthorizationBatchItem{
			Resource: resource, Allowed: item.Allowed, DecisionID: string(item.ID), RequestID: item.RequestID,
			RequestTags: slices.Clone(item.RequestTags), ResourceTags: slices.Clone(item.ResourceTags),
		}
	}
	return result, nil
}

func (client *Client) ResolveAccessKeySubject(
	ctx context.Context,
	signed iamv1.AccessKeySignedRequest,
) (port.AuthorizationSubjectContext, error) {
	if client == nil || client.http == nil {
		return port.AuthorizationSubjectContext{}, port.ErrAuthorizationUnavailable
	}
	if ctx == nil || iamv1.ValidateAccessKeySignedRequest(signed) != nil || signed.Parameters.Audience != iamv1.ProductPaaS {
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
	request := iamv1.ResolveAccessKeySubjectRequest{
		Profile:       iamv1.AuthorizationProfileReference{Product: profile.Product, Revision: profile.Revision, ContentDigest: digest},
		SignedRequest: signed,
	}
	body, err := iamv1.EncodeResolveAccessKeySubjectRequest(request)
	if err != nil {
		return port.AuthorizationSubjectContext{}, port.ErrUnauthenticated
	}
	defer clear(body)
	response, err := client.http.Do(ctx, http.MethodPost, "/v1/internal/access-key-subject:resolve",
		bytes.NewReader(body), "application/json", client.serviceCredential, iamv1.Secret{})
	if err != nil {
		return port.AuthorizationSubjectContext{}, port.ErrAuthorizationUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return port.AuthorizationSubjectContext{}, authorizationStatusError(response.StatusCode)
	}
	var resolved iamv1.AccessKeySubjectContext
	if !authorityhttp.ResponseIsJSON(response) || iamv1.DecodeRequest(response.Body, &resolved) != nil ||
		iamv1.CheckAccessKeySubjectContextForRequest(resolved, request) != nil {
		return port.AuthorizationSubjectContext{}, port.ErrAuthorizationUnavailable
	}
	subject, err := toPaaSSubject(resolved.Subject)
	if err != nil {
		return port.AuthorizationSubjectContext{}, port.ErrAuthorizationUnavailable
	}
	result := port.AuthorizationSubjectContext{TenantID: paasv1.TenantID(resolved.TenantID), Subject: subject, Profile: resolved.Profile}
	if port.ValidateAuthorizationSubjectContext(result) != nil || result.Subject.AccessKeyID == "" {
		return port.AuthorizationSubjectContext{}, port.ErrAuthorizationUnavailable
	}
	return result, nil
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

func toPaaSResource(value iamv1.ResourceReference) (paasv1.ResourceRef, error) {
	kinds := map[iamv1.ResourceKind]string{
		iamv1.ResourceApplication:           port.ResourceApplication,
		iamv1.ResourceConfiguration:         port.ResourceConfiguration,
		iamv1.ResourceConfigurationRevision: port.ResourceConfigurationRevision,
		iamv1.ResourceApplicationRevision:   port.ResourceApplicationRevision,
		iamv1.ResourceDeployment:            port.ResourceDeployment,
		iamv1.ResourceOperation:             port.ResourceOperation,
	}
	kind, known := kinds[value.Kind]
	if !known || paasv1.ValidateID("resource.id", value.ID) != nil {
		return paasv1.ResourceRef{}, errors.New("IAM resource cannot map to PaaS")
	}
	return paasv1.ResourceRef{Kind: kind, ID: paasv1.ResourceID(value.ID)}, nil
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
