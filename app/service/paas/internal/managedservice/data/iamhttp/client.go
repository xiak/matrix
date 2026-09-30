package iamhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/internal/authorityhttp"
	"github.com/xiak/matrix/app/service/paas/internal/managedservice/port"
)

var _ port.Authorizer = (*Client)(nil)
var _ port.WorkloadRoleAuthority = (*Client)(nil)

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
		iamv1.CheckAuthorizationDecisionForRequest(decision, iamRequest) != nil {
		return port.Authorization{}, port.ErrAuthorizationUnavailable
	}
	if !decision.Allowed {
		return port.Authorization{}, port.ErrPermissionDenied
	}
	if decision.Subject == nil {
		return port.Authorization{}, port.ErrAuthorizationUnavailable
	}
	authorization := port.Authorization{
		TenantID: string(decision.TenantID), SubjectType: port.SubjectType(decision.Subject.Type),
		SubjectID:  string(decision.Subject.ID),
		DecisionID: string(decision.ID), RequestID: decision.RequestID,
	}
	if port.ValidateAuthorizationForRequest(authorization, request) != nil {
		return port.Authorization{}, port.ErrAuthorizationUnavailable
	}
	return authorization, nil
}

func (client *Client) BindWorkloadRole(
	ctx context.Context,
	template iamv1.ServiceRoleTemplateReference,
	request port.AuthorizationRequest,
) (iamv1.ServiceLinkedRoleAccess, error) {
	if client == nil || client.http == nil {
		return iamv1.ServiceLinkedRoleAccess{}, port.ErrAuthorizationUnavailable
	}
	if ctx == nil || iamv1.ValidateServiceRoleTemplateReference(template) != nil ||
		port.ValidateAuthorizationRequest(request) != nil || request.Action != port.AuthorizeInstallationRoleBind ||
		request.Resource.Kind != port.ResourceServiceInstallation ||
		request.ResourceMode != iamv1.AuthorizationResourceInstance || request.CollectionUsage != "" {
		return iamv1.ServiceLinkedRoleAccess{}, port.ErrAuthorizationUnavailable
	}
	subjectCredential, err := parseBearer(request.Credential)
	if err != nil {
		return iamv1.ServiceLinkedRoleAccess{}, port.ErrUnauthenticated
	}
	iamAuthorization, err := toIAMRequest(request)
	if err != nil {
		return iamv1.ServiceLinkedRoleAccess{}, port.ErrAuthorizationUnavailable
	}
	command := iamv1.CreateWorkloadRoleBindingRequest{Template: template, Authorization: iamAuthorization}
	if iamv1.ValidateCreateWorkloadRoleBindingRequest(command) != nil {
		return iamv1.ServiceLinkedRoleAccess{}, port.ErrAuthorizationUnavailable
	}
	body, err := json.Marshal(command)
	if err != nil {
		return iamv1.ServiceLinkedRoleAccess{}, port.ErrAuthorizationUnavailable
	}
	defer clear(body)
	response, err := client.http.Do(
		ctx, http.MethodPost, "/v1/internal/workload-role-bindings", bytes.NewReader(body), "application/json",
		client.serviceCredential, subjectCredential,
	)
	if err != nil {
		return iamv1.ServiceLinkedRoleAccess{}, port.ErrAuthorizationUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return iamv1.ServiceLinkedRoleAccess{}, bindingStatusError(response.StatusCode)
	}
	var result iamv1.ServiceLinkedRoleAccess
	if !authorityhttp.ResponseIsJSON(response) || iamv1.DecodeRequest(response.Body, &result) != nil ||
		iamv1.ValidateServiceLinkedRoleAccess(result) != nil || len(result.Bindings) != 1 ||
		result.Relation.Template != template || result.Bindings[0].Template != template ||
		result.Relation.ServicePrincipal.Purpose != iamv1.ServicePaaS ||
		result.Bindings[0].Workload != iamAuthorization.Resource {
		return iamv1.ServiceLinkedRoleAccess{}, port.ErrAuthorizationUnavailable
	}
	return result, nil
}

func (client *Client) RevokeWorkloadRole(
	ctx context.Context,
	bindingID iamv1.WorkloadRoleBindingID,
	resourceVersion uint64,
	request port.AuthorizationRequest,
) (iamv1.WorkloadRoleBinding, error) {
	if client == nil || client.http == nil {
		return iamv1.WorkloadRoleBinding{}, port.ErrAuthorizationUnavailable
	}
	if ctx == nil || iamv1.ValidateID("bindingId", string(bindingID)) != nil || resourceVersion != 1 ||
		port.ValidateAuthorizationRequest(request) != nil || request.Action != port.AuthorizeInstallationRoleUnbind ||
		request.Resource.Kind != port.ResourceServiceInstallation ||
		request.ResourceMode != iamv1.AuthorizationResourceInstance || request.CollectionUsage != "" {
		return iamv1.WorkloadRoleBinding{}, port.ErrAuthorizationUnavailable
	}
	subjectCredential, err := parseBearer(request.Credential)
	if err != nil {
		return iamv1.WorkloadRoleBinding{}, port.ErrUnauthenticated
	}
	iamAuthorization, err := toIAMRequest(request)
	if err != nil {
		return iamv1.WorkloadRoleBinding{}, port.ErrAuthorizationUnavailable
	}
	command := iamv1.RevokeWorkloadRoleBindingRequest{
		Authorization: iamAuthorization, ResourceVersion: resourceVersion,
	}
	if iamv1.ValidateRevokeWorkloadRoleBindingRequest(command) != nil {
		return iamv1.WorkloadRoleBinding{}, port.ErrAuthorizationUnavailable
	}
	body, err := json.Marshal(command)
	if err != nil {
		return iamv1.WorkloadRoleBinding{}, port.ErrAuthorizationUnavailable
	}
	defer clear(body)
	response, err := client.http.Do(
		ctx, http.MethodDelete, "/v1/internal/workload-role-bindings/"+url.PathEscape(string(bindingID)),
		bytes.NewReader(body), "application/json", client.serviceCredential, subjectCredential,
	)
	if err != nil {
		return iamv1.WorkloadRoleBinding{}, port.ErrAuthorizationUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return iamv1.WorkloadRoleBinding{}, bindingStatusError(response.StatusCode)
	}
	var result iamv1.WorkloadRoleBinding
	if !authorityhttp.ResponseIsJSON(response) || iamv1.DecodeRequest(response.Body, &result) != nil ||
		iamv1.ValidateWorkloadRoleBinding(result) != nil || result.ID != bindingID ||
		result.Status != iamv1.WorkloadRoleBindingRevoked || result.ResourceVersion != resourceVersion+1 ||
		result.Workload != iamAuthorization.Resource {
		return iamv1.WorkloadRoleBinding{}, port.ErrAuthorizationUnavailable
	}
	return result, nil
}

func toIAMRequest(request port.AuthorizationRequest) (iamv1.AuthorizationRequest, error) {
	result, err := iamv1.NewAuthorizationRequest(request.Action,
		iamv1.ResourceReference{Kind: request.Resource.Kind, ID: request.Resource.ID},
		request.ResourceMode, request.CollectionUsage, request.RequestID, request.RequestID)
	profile, known := iamv1.LookupAuthorizationProfile(iamv1.ProductManagedService)
	if err != nil || !known || iamv1.CheckAuthorizationProfileReference(profile, result.Profile) != nil ||
		profile.CallingService != iamv1.ServicePaaS {
		return iamv1.AuthorizationRequest{}, errors.New("managed-service authorization cannot map to IAM")
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

func bindingStatusError(status int) error {
	if status == http.StatusConflict {
		return port.ErrWorkloadRoleConflict
	}
	return authorizationStatusError(status)
}
