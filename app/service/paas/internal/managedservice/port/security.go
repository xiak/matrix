package port

import (
	"context"
	"errors"

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

type AuthorizationRequest struct {
	Credential string
	Action     string
	Resource   ResourceReference
	RequestID  string
}

type Authorization struct {
	TenantID   string
	SubjectID  string
	DecisionID string
	RequestID  string
}

type Authorizer interface {
	Authorize(context.Context, AuthorizationRequest) (Authorization, error)
}

func ValidateAuthorization(value Authorization) error {
	return errors.Join(
		managedservicev1.ValidateID("authorization.tenantId", value.TenantID),
		managedservicev1.ValidateID("authorization.subjectId", value.SubjectID),
		managedservicev1.ValidateID("authorization.decisionId", value.DecisionID),
		managedservicev1.ValidateID("authorization.requestId", value.RequestID),
	)
}

func ValidateAuthorizationRequest(value AuthorizationRequest) error {
	if value.Credential == "" {
		return errors.New("authorization credential is required")
	}
	if expectedResourceKind(value.Action) != value.Resource.Kind {
		return errors.New("authorization action and resource kind differ")
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
