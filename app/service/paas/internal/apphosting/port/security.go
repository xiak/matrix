package port

import (
	"context"
	"errors"
	"fmt"
	"strings"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

var (
	ErrUnauthenticated          = errors.New("IAM authentication failed")
	ErrPermissionDenied         = errors.New("IAM authorization denied")
	ErrAuthorizationUnavailable = errors.New("IAM authorization unavailable")
)

const (
	AuthorizeApplicationCreate           = iamv1.ActionPaaSApplicationCreate
	AuthorizeApplicationRead             = iamv1.ActionPaaSApplicationRead
	AuthorizeConfigurationCreate         = iamv1.ActionPaaSConfigurationCreate
	AuthorizeConfigurationRead           = iamv1.ActionPaaSConfigurationRead
	AuthorizeConfigurationRevisionCreate = iamv1.ActionPaaSConfigurationRevisionCreate
	AuthorizeConfigurationRevisionRead   = iamv1.ActionPaaSConfigurationRevisionRead
	AuthorizeApplicationRevisionCreate   = iamv1.ActionPaaSApplicationRevisionCreate
	AuthorizeApplicationRevisionRead     = iamv1.ActionPaaSApplicationRevisionRead
	AuthorizeDeploymentCreate            = iamv1.ActionPaaSDeploymentCreate
	AuthorizeDeploymentUpdate            = iamv1.ActionPaaSDeploymentUpdate
	AuthorizeDeploymentStop              = iamv1.ActionPaaSDeploymentStop
	AuthorizeDeploymentRollback          = iamv1.ActionPaaSDeploymentRollback
	AuthorizeDeploymentRead              = iamv1.ActionPaaSDeploymentRead
	AuthorizeOperationRead               = iamv1.ActionPaaSOperationRead
)

const (
	ResourceApplication           = "Application"
	ResourceConfiguration         = "Configuration"
	ResourceConfigurationRevision = "ConfigurationRevision"
	ResourceApplicationRevision   = "ApplicationRevision"
	ResourceDeployment            = "Deployment"
	ResourceOperation             = "Operation"
)

// AuthorizationRequest carries transient credential material to the IAM
// boundary. Credential must never be persisted, logged, or copied into Audit.
type AuthorizationRequest struct {
	Credential      string
	Action          iamv1.Action
	Resource        paasv1.ResourceRef
	ResourceMode    iamv1.AuthorizationResourceMode
	CollectionUsage iamv1.AuthorizationCollectionUsage
	SourceIP        string
	RequestID       string
}

// Authorization is the trusted IAM result consumed by apphosting. Tenant and
// subject are never reconstructed from HTTP headers or request documents.
type Authorization struct {
	TenantID    paasv1.TenantID
	Subject     paasv1.SubjectRef
	DecisionID  string
	RequestID   string
	AuditID     string
	TraceParent string
}

// Authorizer is implemented by the independently deployable IAM boundary.
// Implementations must fail closed when identity or current policy cannot be
// established.
type Authorizer interface {
	Authorize(context.Context, AuthorizationRequest) (Authorization, error)
}

func ValidateAuthorizationRequest(value AuthorizationRequest) error {
	var problems []error
	if value.Credential == "" || strings.TrimSpace(value.Credential) != value.Credential ||
		len([]byte(value.Credential)) > 16*1024 {
		problems = append(problems, errors.New("authorization credential is invalid"))
	}
	_, requestErr := NewIAMAuthorizationRequest(value)
	problems = append(problems, requestErr)
	return errors.Join(problems...)
}

// NewIAMAuthorizationRequest is the single PaaS-to-IAM vocabulary adapter.
// The release-owned Profile remains the authority for actions, shapes,
// conditions and caller purpose; this function only translates PaaS resource
// names and binds the network fact observed by the PEP.
func NewIAMAuthorizationRequest(value AuthorizationRequest) (iamv1.AuthorizationRequest, error) {
	if !isAppHostingAction(value.Action) {
		return iamv1.AuthorizationRequest{}, errors.New("authorization action is outside apphosting")
	}
	resource, err := iamResourceReference(value.Resource)
	if err != nil {
		return iamv1.AuthorizationRequest{}, err
	}
	request, err := iamv1.NewAuthorizationRequest(value.Action, resource,
		value.ResourceMode, value.CollectionUsage, value.RequestID, value.RequestID)
	profile, known := iamv1.LookupAuthorizationProfile(iamv1.ProductPaaS)
	if err != nil || !known || iamv1.CheckAuthorizationProfileReference(profile, request.Profile) != nil ||
		profile.CallingService != iamv1.ServicePaaS {
		return iamv1.AuthorizationRequest{}, errors.New("authorization request is outside the PaaS profile")
	}
	request, err = iamv1.BindAuthorizationSourceIP(request, value.SourceIP)
	if err != nil {
		return iamv1.AuthorizationRequest{}, errors.New("authorization network context is invalid")
	}
	return request, nil
}

// isAppHostingAction is the PEP route boundary within the wider PaaS product
// Profile. Platform host and installation actions intentionally remain in the
// same release-owned product declaration but are not accepted by this HTTP
// adapter.
func isAppHostingAction(value iamv1.Action) bool {
	switch value {
	case AuthorizeApplicationCreate, AuthorizeApplicationRead,
		AuthorizeConfigurationCreate, AuthorizeConfigurationRead,
		AuthorizeConfigurationRevisionCreate, AuthorizeConfigurationRevisionRead,
		AuthorizeApplicationRevisionCreate, AuthorizeApplicationRevisionRead,
		AuthorizeDeploymentCreate, AuthorizeDeploymentUpdate,
		AuthorizeDeploymentStop, AuthorizeDeploymentRollback,
		AuthorizeDeploymentRead, AuthorizeOperationRead:
		return true
	default:
		return false
	}
}

func iamResourceReference(value paasv1.ResourceRef) (iamv1.ResourceReference, error) {
	kinds := map[string]iamv1.ResourceKind{
		ResourceApplication:           iamv1.ResourceApplication,
		ResourceConfiguration:         iamv1.ResourceConfiguration,
		ResourceConfigurationRevision: iamv1.ResourceConfigurationRevision,
		ResourceApplicationRevision:   iamv1.ResourceApplicationRevision,
		ResourceDeployment:            iamv1.ResourceDeployment,
		ResourceOperation:             iamv1.ResourceOperation,
	}
	kind, known := kinds[value.Kind]
	if !known {
		return iamv1.ResourceReference{}, fmt.Errorf("unknown PaaS resource kind %q", value.Kind)
	}
	return iamv1.ResourceReference{Kind: kind, ID: string(value.ID)}, nil
}

func ValidateAuthorizationForRequest(
	value Authorization,
	request AuthorizationRequest,
) error {
	problems := []error{ValidateAuthorization(value)}
	if value.RequestID != request.RequestID {
		problems = append(problems, errors.New("IAM authorization request correlation mismatch"))
	}
	return errors.Join(problems...)
}

func ValidateAuthorization(value Authorization) error {
	var problems []error
	problems = append(problems,
		paasv1.ValidateID("authorization.tenantId", string(value.TenantID)),
		paasv1.ValidateSubjectRef(value.Subject),
		paasv1.ValidateID("authorization.decisionId", value.DecisionID),
		paasv1.ValidateID("authorization.requestId", value.RequestID),
	)
	if value.AuditID != "" {
		problems = append(problems, paasv1.ValidateID("authorization.auditId", value.AuditID))
	}
	if value.TraceParent != "" {
		problems = append(problems,
			paasv1.ValidateSafeExternalText("authorization.traceparent", value.TraceParent, 55, false),
		)
	}
	return errors.Join(problems...)
}
