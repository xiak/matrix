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
)

const (
	AuthorizeOfferingRead             = "managedservice.offering.read"
	AuthorizeRegionRead               = "managedservice.region.read"
	AuthorizeQuotaEntitlementActivate = "managedservice.quota-entitlement.activate"
	AuthorizeQuotaEntitlementRead     = "managedservice.quota-entitlement.read"
	AuthorizeInstallationCreate       = "managedservice.service-installation.create"
	AuthorizeInstallationRead         = "managedservice.service-installation.read"
)

const (
	ResourceServiceOffering     = "ServiceOffering"
	ResourceRegion              = "Region"
	ResourceQuotaEntitlement    = "QuotaEntitlement"
	ResourceServiceInstallation = "ServiceInstallation"
)

type ResourceReference struct {
	Kind string
	ID   string
}

type SubjectType string

const (
	SubjectUser           SubjectType = "USER"
	SubjectServiceAccount SubjectType = "SERVICE_ACCOUNT"
)

type AuthorizationRequest struct {
	Credential      string
	Action          string
	Resource        ResourceReference
	ResourceMode    iamv1.AuthorizationResourceMode
	CollectionUsage iamv1.AuthorizationCollectionUsage
	RequestID       string
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
	if value.Resource.Kind == "" || expectedResourceKind(value.Action) != value.Resource.Kind {
		return errors.New("authorization action and resource kind differ")
	}
	switch value.ResourceMode {
	case iamv1.AuthorizationResourceInstance:
		if value.CollectionUsage != "" {
			return errors.New("instance authorization cannot carry collection usage")
		}
	case iamv1.AuthorizationResourceCollection:
		if value.Resource.ID != "collection" || (value.CollectionUsage != iamv1.AuthorizationCollectionCreate && value.CollectionUsage != iamv1.AuthorizationCollectionList) {
			return errors.New("collection authorization target is invalid")
		}
	default:
		return errors.New("authorization resource mode is required")
	}
	return errors.Join(
		managedservicev1.ValidateID("authorization.resource.id", value.Resource.ID),
		managedservicev1.ValidateID("authorization.requestId", value.RequestID),
	)
}

func ValidateAuthorizationForRequest(value Authorization, request AuthorizationRequest) error {
	if value.RequestID != request.RequestID {
		return errors.New("authorization request correlation differs")
	}
	return ValidateAuthorization(value)
}

func expectedResourceKind(action string) string {
	switch action {
	case AuthorizeOfferingRead:
		return ResourceServiceOffering
	case AuthorizeRegionRead:
		return ResourceRegion
	case AuthorizeQuotaEntitlementActivate, AuthorizeQuotaEntitlementRead:
		return ResourceQuotaEntitlement
	case AuthorizeInstallationCreate, AuthorizeInstallationRead:
		return ResourceServiceInstallation
	default:
		return ""
	}
}
