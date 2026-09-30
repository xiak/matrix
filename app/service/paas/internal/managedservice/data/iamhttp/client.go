package iamhttp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/internal/authorityhttp"
	"github.com/xiak/matrix/app/service/paas/internal/managedservice/port"
)

var _ port.Authorizer = (*Client)(nil)
var _ port.WorkloadRoleAuthority = (*Client)(nil)
var _ port.WorkloadRoleRuntime = (*Client)(nil)

const workloadRoleSessionDurationSeconds uint32 = 60

type Config struct {
	Endpoint          string
	ServiceCredential iamv1.Secret
	HTTPClient        *http.Client
}

type Client struct {
	http              *authorityhttp.Client
	serviceCredential iamv1.Secret
}

type workloadRoleLease struct {
	mu            sync.Mutex
	client        *Client
	session       iamv1.RoleSession
	credential    iamv1.Secret
	authorization port.WorkloadRoleAuthorization
	exitRequestID string
	released      bool
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
	response, err := client.http.Do(
		ctx, http.MethodPost, "/v1/authorize:batch", bytes.NewReader(body), "application/json",
		client.serviceCredential, subjectCredential,
	)
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
	result := port.AuthorizationBatch{
		TenantID: string(decision.TenantID), SubjectType: port.SubjectType(decision.Subject.Type),
		SubjectID: decision.Subject.ID, Items: make([]port.AuthorizationBatchItem, len(decision.Decisions)),
	}
	for index, item := range decision.Decisions {
		result.Items[index] = port.AuthorizationBatchItem{
			Resource: port.ResourceReference{Kind: item.Resource.Kind, ID: item.Resource.ID},
			Allowed:  item.Allowed, DecisionID: string(item.ID), RequestID: item.RequestID,
		}
	}
	if port.ValidateAuthorizationBatchForRequest(result, request) != nil {
		return port.AuthorizationBatch{}, port.ErrAuthorizationUnavailable
	}
	return result, nil
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

// AssumeWorkloadRole exchanges the current private PaaS credential for one
// minute of exact workload authority, evaluates the product request through
// IAM's single PDP, and returns only a non-secret lease. Equal replay cannot be
// consumed because IAM deliberately never replays a temporary credential.
func (client *Client) AssumeWorkloadRole(
	ctx context.Context,
	bindingID iamv1.WorkloadRoleBindingID,
	assumeRequestID string,
	request port.WorkloadRoleAuthorizationRequest,
) (port.WorkloadRoleLease, error) {
	if client == nil || client.http == nil || ctx == nil ||
		iamv1.ValidateID("bindingId", string(bindingID)) != nil || iamv1.ValidateID("assumeRequestId", assumeRequestID) != nil ||
		port.ValidateWorkloadRoleAuthorizationRequest(request) != nil || request.Action != port.AuthorizeInstallationRead ||
		request.Resource.Kind != port.ResourceServiceInstallation || request.ResourceMode != iamv1.AuthorizationResourceInstance ||
		request.CollectionUsage != "" {
		return nil, port.ErrAuthorizationUnavailable
	}
	duration := workloadRoleSessionDurationSeconds
	command := iamv1.AssumeServiceRoleRequest{BindingID: bindingID, DurationSeconds: &duration, RequestID: assumeRequestID}
	if iamv1.ValidateAssumeServiceRoleRequest(command) != nil {
		return nil, port.ErrAuthorizationUnavailable
	}
	body, err := json.Marshal(command)
	if err != nil {
		return nil, port.ErrAuthorizationUnavailable
	}
	response, err := client.http.Do(
		ctx, http.MethodPost, "/v1/internal/service-role-sessions", bytes.NewReader(body), "application/json",
		client.serviceCredential, iamv1.Secret{},
	)
	clear(body)
	if err != nil {
		return nil, port.ErrAuthorizationUnavailable
	}
	if response.StatusCode != http.StatusOK {
		statusErr := bindingStatusError(response.StatusCode)
		_ = response.Body.Close()
		return nil, statusErr
	}
	var issued iamv1.AssumeRoleResponse
	privateResponse := responseIsPrivateJSON(response)
	decodeErr := iamv1.DecodeRequest(response.Body, &issued)
	if decodeErr != nil {
		_ = response.Body.Close()
		return nil, port.ErrAuthorizationUnavailable
	}
	// A malformed post-commit response can still carry a valid one-time
	// credential. Keep it adapter-private and make one bounded best-effort exit
	// before returning unavailable; never hand malformed authority to the use
	// case or wait for natural expiry when exact self-revocation is possible.
	lease := &workloadRoleLease{
		client: client, session: issued.Session, credential: issued.Credential,
		exitRequestID: workloadRoleExitRequestID(assumeRequestID),
	}
	validationErr := iamv1.ValidateAssumeRoleResponse(issued)
	issued.Credential = iamv1.Secret{}
	if validationErr != nil || issued.Outcome != "APPLIED" ||
		!lease.credential.Present() || issued.Session.Status != iamv1.SessionActive ||
		issued.Session.SourceUserID != "" || issued.Session.SourceServicePrincipalID == "" {
		_ = response.Body.Close()
		if lease.credential.Present() && iamv1.ValidateRoleSession(lease.session) == nil {
			_ = lease.Release(ctx)
		}
		lease.credential = iamv1.Secret{}
		return nil, port.ErrAuthorizationUnavailable
	}
	if closeErr := response.Body.Close(); !privateResponse || closeErr != nil ||
		issued.Session.ExpiresAt.Sub(issued.Session.IssuedAt) != time.Duration(workloadRoleSessionDurationSeconds)*time.Second {
		_ = lease.Release(ctx)
		return nil, port.ErrAuthorizationUnavailable
	}
	iamRequest, err := toIAMWorkloadRequest(request)
	if err != nil {
		_ = lease.Release(ctx)
		return nil, port.ErrAuthorizationUnavailable
	}
	body, err = json.Marshal(iamRequest)
	if err != nil {
		_ = lease.Release(ctx)
		return nil, port.ErrAuthorizationUnavailable
	}
	response, err = client.http.Do(
		ctx, http.MethodPost, "/v1/authorize", bytes.NewReader(body), "application/json",
		client.serviceCredential, lease.credential,
	)
	clear(body)
	if err != nil {
		_ = lease.Release(ctx)
		return nil, port.ErrAuthorizationUnavailable
	}
	if response.StatusCode != http.StatusOK {
		statusErr := authorizationStatusError(response.StatusCode)
		_ = response.Body.Close()
		_ = lease.Release(ctx)
		return nil, statusErr
	}
	var decision iamv1.AuthorizationDecision
	if !responseIsPrivateJSON(response) || iamv1.DecodeRequest(response.Body, &decision) != nil ||
		iamv1.CheckAuthorizationDecisionForRequest(decision, iamRequest) != nil {
		_ = response.Body.Close()
		_ = lease.Release(ctx)
		return nil, port.ErrAuthorizationUnavailable
	}
	if err := response.Body.Close(); err != nil {
		_ = lease.Release(ctx)
		return nil, port.ErrAuthorizationUnavailable
	}
	if !decision.Allowed {
		_ = lease.Release(ctx)
		return nil, port.ErrPermissionDenied
	}
	if decision.Subject == nil || decision.Subject.Type != iamv1.SubjectRole ||
		decision.Subject.ID != string(issued.Session.RoleID) || decision.Subject.RoleSession == nil ||
		decision.Subject.RoleSession.SessionID != issued.Session.ID || decision.Subject.RoleSession.SourceUserID != "" ||
		decision.Subject.RoleSession.SourceServicePrincipalID != issued.Session.SourceServicePrincipalID ||
		decision.TenantID != issued.Session.AccountID || decision.InstallationID != "" {
		_ = lease.Release(ctx)
		return nil, port.ErrAuthorizationUnavailable
	}
	lease.authorization = port.WorkloadRoleAuthorization{
		TenantID: string(decision.TenantID), BindingID: bindingID, RoleID: issued.Session.RoleID,
		RoleSessionID: issued.Session.ID, SourceServicePrincipalID: issued.Session.SourceServicePrincipalID,
		DecisionID: decision.ID, RequestID: decision.RequestID,
	}
	if port.ValidateWorkloadRoleAuthorizationForRequest(lease.authorization, bindingID, request) != nil {
		_ = lease.Release(ctx)
		return nil, port.ErrAuthorizationUnavailable
	}
	return lease, nil
}

func (lease *workloadRoleLease) Authorization() port.WorkloadRoleAuthorization {
	if lease == nil {
		return port.WorkloadRoleAuthorization{}
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	return lease.authorization
}

func (lease *workloadRoleLease) Release(ctx context.Context) error {
	if lease == nil || lease.client == nil || lease.client.http == nil || ctx == nil {
		return port.ErrAuthorizationUnavailable
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.released {
		return nil
	}
	if !lease.credential.Present() || iamv1.ValidateRoleSession(lease.session) != nil ||
		iamv1.ValidateID("exitRequestId", lease.exitRequestID) != nil {
		return port.ErrAuthorizationUnavailable
	}
	body, err := json.Marshal(iamv1.LogoutRequest{RequestID: lease.exitRequestID})
	if err != nil {
		return port.ErrAuthorizationUnavailable
	}
	releaseContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 6*time.Second)
	defer cancel()
	response, err := lease.client.http.Do(
		releaseContext, http.MethodPost, "/v1/auth/role-session:logout", bytes.NewReader(body), "application/json",
		lease.credential, iamv1.Secret{},
	)
	clear(body)
	if err != nil {
		return port.ErrAuthorizationUnavailable
	}
	if response.StatusCode != http.StatusOK {
		statusErr := authorizationStatusError(response.StatusCode)
		_ = response.Body.Close()
		return statusErr
	}
	var revoked iamv1.RoleSession
	if !responseIsPrivateJSON(response) || iamv1.DecodeRequest(response.Body, &revoked) != nil ||
		iamv1.ValidateRoleSession(revoked) != nil || revoked.Status != iamv1.SessionRevoked ||
		revoked.ID != lease.session.ID || revoked.AccountID != lease.session.AccountID || revoked.RoleID != lease.session.RoleID ||
		revoked.SourceUserID != "" || revoked.SourceServicePrincipalID != lease.session.SourceServicePrincipalID ||
		!revoked.IssuedAt.Equal(lease.session.IssuedAt) || !revoked.ExpiresAt.Equal(lease.session.ExpiresAt) {
		_ = response.Body.Close()
		return port.ErrAuthorizationUnavailable
	}
	if err := response.Body.Close(); err != nil {
		return port.ErrAuthorizationUnavailable
	}
	lease.credential = iamv1.Secret{}
	lease.released = true
	return nil
}

func toIAMRequest(request port.AuthorizationRequest) (iamv1.AuthorizationRequest, error) {
	result, err := port.NewIAMAuthorizationRequest(request)
	profile, known := iamv1.LookupAuthorizationProfile(iamv1.ProductManagedService)
	if err != nil || !known || iamv1.CheckAuthorizationProfileReference(profile, result.Profile) != nil ||
		profile.CallingService != iamv1.ServicePaaS {
		return iamv1.AuthorizationRequest{}, errors.New("managed-service authorization cannot map to IAM")
	}
	return result, nil
}

func toIAMWorkloadRequest(request port.WorkloadRoleAuthorizationRequest) (iamv1.AuthorizationRequest, error) {
	result, err := iamv1.NewAuthorizationRequest(request.Action,
		iamv1.ResourceReference{Kind: request.Resource.Kind, ID: request.Resource.ID},
		request.ResourceMode, request.CollectionUsage, request.RequestID, request.RequestID)
	profile, known := iamv1.LookupAuthorizationProfile(iamv1.ProductManagedService)
	if err != nil || !known || iamv1.CheckAuthorizationProfileReference(profile, result.Profile) != nil ||
		profile.CallingService != iamv1.ServicePaaS {
		return iamv1.AuthorizationRequest{}, errors.New("managed-service workload authorization cannot map to IAM")
	}
	return result, nil
}

func workloadRoleExitRequestID(assumeRequestID string) string {
	digest := sha256.Sum256([]byte("matrix-managedservice-workload-role-exit-v1\x00" + assumeRequestID))
	return "msrs-exit-" + hex.EncodeToString(digest[:])
}

func responseIsPrivateJSON(response *http.Response) bool {
	return authorityhttp.ResponseIsJSON(response) && response.Header.Get("Cache-Control") == "no-store"
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
