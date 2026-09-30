package port

import (
	"context"
	"errors"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
	managedservicev1 "github.com/xiak/matrix/api/managedservice/v1"
)

var (
	ErrUnauthenticated          = errors.New("managed-service IAM authentication failed")
	ErrPermissionDenied         = errors.New("managed-service IAM authorization denied")
	ErrAuthorizationUnavailable = errors.New("managed-service IAM authorization unavailable")
	ErrWorkloadRoleConflict     = errors.New("managed-service workload Role binding conflicts")
)

const (
	AuthorizeOfferingRead             = iamv1.ActionManagedServiceOfferingRead
	AuthorizeRegionRead               = iamv1.ActionManagedServiceRegionRead
	AuthorizeQuotaEntitlementActivate = iamv1.ActionManagedServiceQuotaEntitlementActivate
	AuthorizeQuotaEntitlementRead     = iamv1.ActionManagedServiceQuotaEntitlementRead
	AuthorizeInstallationCreate       = iamv1.ActionManagedServiceInstallationCreate
	AuthorizeInstallationRead         = iamv1.ActionManagedServiceInstallationRead
	AuthorizeInstallationRoleBind     = iamv1.ActionManagedServiceInstallationRoleBind
	AuthorizeInstallationRoleUnbind   = iamv1.ActionManagedServiceInstallationRoleUnbind
)

const (
	ResourceServiceOffering     = iamv1.ResourceServiceOffering
	ResourceRegion              = iamv1.ResourceRegion
	ResourceQuotaEntitlement    = iamv1.ResourceQuotaEntitlement
	ResourceServiceInstallation = iamv1.ResourceServiceInstallation
)

type ResourceReference struct {
	Kind iamv1.ResourceKind
	ID   string
}

type SubjectType string

const (
	SubjectUser           SubjectType = "USER"
	SubjectServiceAccount SubjectType = "SERVICE_ACCOUNT"
	SubjectRole           SubjectType = "ROLE"
)

type AuthorizationRequest struct {
	Credential      string
	Action          iamv1.Action
	Resource        ResourceReference
	ResourceMode    iamv1.AuthorizationResourceMode
	CollectionUsage iamv1.AuthorizationCollectionUsage
	RequestID       string
	CorrelationID   string
}

type Authorization struct {
	TenantID    string
	SubjectType SubjectType
	SubjectID   string
	DecisionID  string
	RequestID   string
}

type Authorizer interface {
	Authorize(context.Context, AuthorizationRequest) (Authorization, error)
	AuthorizeBatch(context.Context, AuthorizationBatchRequest) (AuthorizationBatch, error)
}

type AuthorizationBatchRequest struct {
	Credential string
	Requests   []AuthorizationRequest
}

type AuthorizationBatchItem struct {
	Resource   ResourceReference
	Allowed    bool
	DecisionID string
	RequestID  string
}

type AuthorizationBatch struct {
	TenantID    string
	SubjectType SubjectType
	SubjectID   string
	Items       []AuthorizationBatchItem
}

// WorkloadRoleAuthority is the product-to-IAM consent boundary. Its requests
// use the same current USER credential and normalized product authorization
// shape; the implementation adds the PaaS ServiceIdentity credential
// privately. Revocation identifies an existing binding but never re-selects
// its Account, Role, template, workload or service principal.
type WorkloadRoleAuthority interface {
	BindWorkloadRole(
		context.Context,
		iamv1.ServiceRoleTemplateReference,
		AuthorizationRequest,
	) (iamv1.ServiceLinkedRoleAccess, error)
	RevokeWorkloadRole(
		context.Context,
		iamv1.WorkloadRoleBindingID,
		uint64,
		AuthorizationRequest,
	) (iamv1.WorkloadRoleBinding, error)
}

// WorkloadRoleAuthorizationRequest is one product-owned business read. It has
// no caller credential or Account selector: the runtime recovers both from the
// current PaaS ServiceIdentity and the exact workload binding before asking the
// single IAM PDP.
type WorkloadRoleAuthorizationRequest struct {
	Action          iamv1.Action
	Resource        ResourceReference
	ResourceMode    iamv1.AuthorizationResourceMode
	CollectionUsage iamv1.AuthorizationCollectionUsage
	RequestID       string
}

// WorkloadRoleAuthorization is the non-secret authorization result retained
// by the product use case. The temporary Role credential remains inside the
// adapter-owned lease and can only be used to release that exact session.
type WorkloadRoleAuthorization struct {
	TenantID                 string
	BindingID                iamv1.WorkloadRoleBindingID
	RoleID                   iamv1.RoleID
	RoleSessionID            iamv1.RoleSessionID
	SourceServicePrincipalID iamv1.PrincipalID
	DecisionID               iamv1.DecisionID
	RequestID                string
}

type WorkloadRoleLease interface {
	Authorization() WorkloadRoleAuthorization
	Release(context.Context) error
}

type WorkloadRoleRuntime interface {
	AssumeWorkloadRole(
		context.Context,
		iamv1.WorkloadRoleBindingID,
		string,
		WorkloadRoleAuthorizationRequest,
	) (WorkloadRoleLease, error)
}

func ValidateAuthorization(value Authorization) error {
	var problems []error
	if value.SubjectType != SubjectUser && value.SubjectType != SubjectServiceAccount {
		problems = append(problems, errors.New("authorization subject type is invalid"))
	}
	problems = append(problems,
		managedservicev1.ValidateID("authorization.tenantId", value.TenantID),
		managedservicev1.ValidateID("authorization.subjectId", value.SubjectID),
		managedservicev1.ValidateID("authorization.decisionId", value.DecisionID),
		managedservicev1.ValidateID("authorization.requestId", value.RequestID),
	)
	return errors.Join(problems...)
}

func ValidateAuthorizationRequest(value AuthorizationRequest) error {
	if value.Credential == "" {
		return errors.New("authorization credential is required")
	}
	_, err := NewIAMAuthorizationRequest(value)
	return err
}

// NewIAMAuthorizationRequest is the single managed-service vocabulary
// adapter. Credential material remains outside the public IAM document.
func NewIAMAuthorizationRequest(value AuthorizationRequest) (iamv1.AuthorizationRequest, error) {
	correlationID := value.CorrelationID
	if correlationID == "" {
		correlationID = value.RequestID
	}
	profileRequest, err := iamv1.NewAuthorizationRequest(
		value.Action,
		iamv1.ResourceReference{Kind: value.Resource.Kind, ID: value.Resource.ID},
		value.ResourceMode,
		value.CollectionUsage,
		value.RequestID,
		correlationID,
	)
	profile, known := iamv1.LookupAuthorizationProfile(iamv1.ProductManagedService)
	if err != nil || !known || iamv1.CheckAuthorizationProfileReference(profile, profileRequest.Profile) != nil ||
		profile.CallingService != iamv1.ServicePaaS {
		return iamv1.AuthorizationRequest{}, errors.New("authorization request is outside the managed-service profile")
	}
	return profileRequest, nil
}

func ValidateAuthorizationBatchRequest(value AuthorizationBatchRequest) error {
	if value.Credential == "" || value.Requests == nil || len(value.Requests) < 1 || len(value.Requests) > iamv1.MaxAuthorizationBatchItems {
		return errors.New("authorization batch is invalid")
	}
	requests := make([]iamv1.AuthorizationRequest, len(value.Requests))
	for index, request := range value.Requests {
		if request.Credential != value.Credential || ValidateAuthorizationRequest(request) != nil {
			return errors.New("authorization batch item is invalid")
		}
		mapped, err := NewIAMAuthorizationRequest(request)
		if err != nil {
			return errors.New("authorization batch item is invalid")
		}
		requests[index] = mapped
	}
	if iamv1.ValidateAuthorizationBatchRequest(iamv1.AuthorizationBatchRequest{Requests: requests}) != nil {
		return errors.New("authorization batch is outside the managed-service profile")
	}
	return nil
}

func ValidateAuthorizationBatchForRequest(value AuthorizationBatch, request AuthorizationBatchRequest) error {
	if ValidateAuthorizationBatchRequest(request) != nil || value.Items == nil || len(value.Items) != len(request.Requests) ||
		managedservicev1.ValidateID("authorization.tenantId", value.TenantID) != nil ||
		(value.SubjectType != SubjectUser && value.SubjectType != SubjectRole) ||
		managedservicev1.ValidateID("authorization.subjectId", value.SubjectID) != nil {
		return errors.New("authorization batch response is invalid")
	}
	for index, item := range value.Items {
		if item.Resource != request.Requests[index].Resource || item.RequestID != request.Requests[index].RequestID ||
			managedservicev1.ValidateID("authorization.decisionId", item.DecisionID) != nil {
			return errors.New("authorization batch response differs")
		}
	}
	return nil
}

func ValidateAuthorizationForRequest(value Authorization, request AuthorizationRequest) error {
	if value.RequestID != request.RequestID {
		return errors.New("authorization request correlation differs")
	}
	return ValidateAuthorization(value)
}

func ValidateWorkloadRoleAuthorizationRequest(value WorkloadRoleAuthorizationRequest) error {
	profileRequest, err := iamv1.NewAuthorizationRequest(
		value.Action,
		iamv1.ResourceReference{Kind: value.Resource.Kind, ID: value.Resource.ID},
		value.ResourceMode,
		value.CollectionUsage,
		value.RequestID,
		value.RequestID,
	)
	profile, known := iamv1.LookupAuthorizationProfile(iamv1.ProductManagedService)
	if err != nil || !known || iamv1.CheckAuthorizationProfileReference(profile, profileRequest.Profile) != nil ||
		profile.CallingService != iamv1.ServicePaaS {
		return errors.New("workload Role authorization is outside the managed-service profile")
	}
	return nil
}

func ValidateWorkloadRoleAuthorization(value WorkloadRoleAuthorization) error {
	return errors.Join(
		managedservicev1.ValidateID("authorization.tenantId", value.TenantID),
		iamv1.ValidateID("authorization.bindingId", string(value.BindingID)),
		iamv1.ValidateID("authorization.roleId", string(value.RoleID)),
		iamv1.ValidateID("authorization.roleSessionId", string(value.RoleSessionID)),
		iamv1.ValidateID("authorization.sourceServicePrincipalId", string(value.SourceServicePrincipalID)),
		iamv1.ValidateID("authorization.decisionId", string(value.DecisionID)),
		managedservicev1.ValidateID("authorization.requestId", value.RequestID),
	)
}

func ValidateWorkloadRoleAuthorizationForRequest(
	value WorkloadRoleAuthorization,
	bindingID iamv1.WorkloadRoleBindingID,
	request WorkloadRoleAuthorizationRequest,
) error {
	if value.BindingID != bindingID || value.RequestID != request.RequestID {
		return errors.New("workload Role authorization correlation differs")
	}
	return ValidateWorkloadRoleAuthorization(value)
}
