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
	ErrAuthorizationReplay      = errors.New("IAM signed request was already consumed")
	ErrAuthorizationUnavailable = errors.New("IAM authorization unavailable")
)

const (
	AuthorizeApplicationCreate           = "paas.application.create"
	AuthorizeApplicationRead             = "paas.application.read"
	AuthorizeConfigurationCreate         = "paas.configuration.create"
	AuthorizeConfigurationRead           = "paas.configuration.read"
	AuthorizeConfigurationRevisionCreate = "paas.configuration-revision.create"
	AuthorizeConfigurationRevisionRead   = "paas.configuration-revision.read"
	AuthorizeApplicationRevisionCreate   = "paas.application-revision.create"
	AuthorizeApplicationRevisionRead     = "paas.application-revision.read"
	AuthorizeDeploymentCreate            = "paas.deployment.create"
	AuthorizeDeploymentUpdate            = "paas.deployment.update"
	AuthorizeDeploymentStop              = "paas.deployment.stop"
	AuthorizeDeploymentRollback          = "paas.deployment.rollback"
	AuthorizeDeploymentRead              = "paas.deployment.read"
	AuthorizeOperationRead               = "paas.operation.read"
	AuthorizeExecutionPoolCreate         = "paas.execution-pool.create"
	AuthorizeExecutionPoolRead           = "paas.execution-pool.read"
	AuthorizeExecutionTargetRegister     = "paas.execution-target.register"
	AuthorizeExecutionTargetRead         = "paas.execution-target.read"
	AuthorizeExecutionTargetDrain        = "paas.execution-target.drain"
	AuthorizeExecutionTargetActivate     = "paas.execution-target.activate"
	AuthorizeExecutionTargetRemove       = "paas.execution-target.remove"
	AuthorizeNodeEnrollmentCreate        = "paas.node-enrollment.create"
	AuthorizeNodeEnrollmentRead          = "paas.node-enrollment.read"
	AuthorizeNodeEnrollmentRevoke        = "paas.node-enrollment.revoke"
	AuthorizeNodeEnrollmentRegenerate    = "paas.node-enrollment.regenerate"
	AuthorizePlatformOperationRead       = "paas.platform-operation.read"
	AuthorizeTerminalSessionCreate       = "paas.terminal-session.create"
	AuthorizeTerminalSessionClose        = "paas.terminal-session.close"
)

// AuthorizationRequest carries transient credential material to the IAM
// boundary. Credential must never be persisted, logged, or copied into Audit.
type AuthorizationRequest struct {
	Credential      string
	Action          string
	Resource        paasv1.ResourceRef
	ResourceMode    iamv1.AuthorizationResourceMode
	CollectionUsage iamv1.AuthorizationCollectionUsage
	RequestID       string
}

// AccessKeyAuthorizationRequest carries the exact external request extracted
// by the product HTTP boundary. It is not a bearer credential or reusable
// permit and must be sent to IAM at most once.
type AccessKeyAuthorizationRequest struct {
	Action          string
	Resource        paasv1.ResourceRef
	ResourceMode    iamv1.AuthorizationResourceMode
	CollectionUsage iamv1.AuthorizationCollectionUsage
	RequestID       string
	SignedRequest   iamv1.AccessKeySignedRequest
}

// Authorization is the trusted IAM result consumed by apphosting. Exactly one
// tenant or installation is authority; neither is reconstructed from HTTP input.
type Authorization struct {
	TenantID       paasv1.TenantID
	InstallationID string
	Subject        paasv1.SubjectRef
	DecisionID     string
	RequestID      string
	AuditID        string
	TraceParent    string
}

// Authorizer is implemented by the independently deployable IAM boundary.
// Implementations must fail closed when identity or current policy cannot be
// established.
type Authorizer interface {
	Authorize(context.Context, AuthorizationRequest) (Authorization, error)
}

type AccessKeyAuthorizer interface {
	AuthorizeAccessKey(context.Context, AccessKeyAuthorizationRequest) (Authorization, error)
}

func ValidateAuthorizationRequest(value AuthorizationRequest) error {
	var problems []error
	if value.Credential == "" || strings.TrimSpace(value.Credential) != value.Credential ||
		len([]byte(value.Credential)) > 16*1024 {
		problems = append(problems, errors.New("authorization credential is invalid"))
	}
	if !knownAuthorizationAction(value.Action) {
		problems = append(problems, fmt.Errorf("unknown authorization action %q", value.Action))
	}
	if strings.TrimSpace(value.Resource.Kind) == "" {
		problems = append(problems, errors.New("authorization resource kind is required"))
	}
	problems = append(problems,
		paasv1.ValidateID("authorization.resource.id", string(value.Resource.ID)),
		paasv1.ValidateID("authorization.requestId", value.RequestID),
		validateAuthorizationResourceShape(value.Resource, value.ResourceMode, value.CollectionUsage),
	)
	return errors.Join(problems...)
}

func ValidateAccessKeyAuthorizationRequest(value AccessKeyAuthorizationRequest) error {
	var problems []error
	if !accessKeyAuthorizationAction(value.Action) {
		problems = append(problems, errors.New("authorization action does not accept an access key"))
	}
	if strings.TrimSpace(value.Resource.Kind) == "" {
		problems = append(problems, errors.New("authorization resource kind is required"))
	}
	problems = append(problems,
		paasv1.ValidateID("authorization.resource.id", string(value.Resource.ID)),
		paasv1.ValidateID("authorization.requestId", value.RequestID),
		validateAuthorizationResourceShape(value.Resource, value.ResourceMode, value.CollectionUsage),
		iamv1.ValidateAccessKeySignedRequest(value.SignedRequest),
	)
	return errors.Join(problems...)
}

func validateAuthorizationResourceShape(
	resource paasv1.ResourceRef,
	mode iamv1.AuthorizationResourceMode,
	usage iamv1.AuthorizationCollectionUsage,
) error {
	switch mode {
	case iamv1.AuthorizationResourceInstance:
		if usage != "" {
			return errors.New("instance authorization cannot carry collection usage")
		}
	case iamv1.AuthorizationResourceCollection:
		if resource.ID != "collection" ||
			(usage != iamv1.AuthorizationCollectionList && usage != iamv1.AuthorizationCollectionCreate) {
			return errors.New("collection authorization shape is invalid")
		}
	default:
		return errors.New("authorization resource mode is invalid")
	}
	return nil
}

func ValidateAccessKeyAuthorizationForRequest(value Authorization, request AccessKeyAuthorizationRequest) error {
	problems := []error{ValidateAuthorization(value)}
	if value.RequestID != request.RequestID || value.Subject.AccessKeyID == "" {
		problems = append(problems, errors.New("IAM access-key authorization binding mismatch"))
	}
	return errors.Join(problems...)
}

func ValidateAuthorizationForRequest(
	value Authorization,
	request AuthorizationRequest,
) error {
	validate := ValidateAuthorization
	if isPlatformAuthorizationAction(request.Action) {
		validate = ValidatePlatformAuthorization
	}
	problems := []error{validate(value)}
	if value.RequestID != request.RequestID {
		problems = append(problems, errors.New("IAM authorization request correlation mismatch"))
	}
	return errors.Join(problems...)
}

func ValidateAuthorization(value Authorization) error {
	problems := []error{
		validateAuthorizedIdentity(value),
		paasv1.ValidateID("authorization.tenantId", string(value.TenantID)),
	}
	if value.InstallationID != "" {
		problems = append(problems, errors.New("tenant authorization cannot carry an installation"))
	}
	return errors.Join(problems...)
}

func ValidatePlatformAuthorization(value Authorization) error {
	problems := []error{
		validateAuthorizedIdentity(value),
		paasv1.ValidateID("authorization.installationId", value.InstallationID),
	}
	if value.TenantID != "" || value.Subject.Type != paasv1.SubjectUser {
		problems = append(problems, errors.New("platform authorization requires only an installation and a user"))
	}
	return errors.Join(problems...)
}

func validateAuthorizedIdentity(value Authorization) error {
	var problems []error
	problems = append(problems,
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

func knownAuthorizationAction(value string) bool {
	for _, candidate := range []string{
		AuthorizeApplicationCreate,
		AuthorizeApplicationRead,
		AuthorizeConfigurationCreate,
		AuthorizeConfigurationRead,
		AuthorizeConfigurationRevisionCreate,
		AuthorizeConfigurationRevisionRead,
		AuthorizeApplicationRevisionCreate,
		AuthorizeApplicationRevisionRead,
		AuthorizeDeploymentCreate,
		AuthorizeDeploymentUpdate,
		AuthorizeDeploymentStop,
		AuthorizeDeploymentRollback,
		AuthorizeDeploymentRead,
		AuthorizeOperationRead,
		AuthorizeExecutionPoolCreate,
		AuthorizeExecutionPoolRead,
		AuthorizeExecutionTargetRegister,
		AuthorizeExecutionTargetRead,
		AuthorizeExecutionTargetDrain,
		AuthorizeExecutionTargetActivate,
		AuthorizeExecutionTargetRemove,
		AuthorizeNodeEnrollmentCreate,
		AuthorizeNodeEnrollmentRead,
		AuthorizeNodeEnrollmentRevoke,
		AuthorizeNodeEnrollmentRegenerate,
		AuthorizePlatformOperationRead,
		AuthorizeTerminalSessionCreate,
		AuthorizeTerminalSessionClose,
	} {
		if value == candidate {
			return true
		}
	}
	return false
}

func isPlatformAuthorizationAction(value string) bool {
	switch value {
	case AuthorizeExecutionPoolCreate, AuthorizeExecutionPoolRead,
		AuthorizeExecutionTargetRegister, AuthorizeExecutionTargetRead,
		AuthorizeExecutionTargetDrain, AuthorizeExecutionTargetActivate,
		AuthorizeExecutionTargetRemove,
		AuthorizeNodeEnrollmentCreate, AuthorizeNodeEnrollmentRead,
		AuthorizeNodeEnrollmentRevoke, AuthorizeNodeEnrollmentRegenerate,
		AuthorizePlatformOperationRead:
		return true
	default:
		return false
	}
}

func accessKeyAuthorizationAction(value string) bool {
	switch value {
	case AuthorizeApplicationCreate, AuthorizeApplicationRead,
		AuthorizeConfigurationCreate, AuthorizeConfigurationRead,
		AuthorizeConfigurationRevisionCreate, AuthorizeConfigurationRevisionRead,
		AuthorizeApplicationRevisionCreate, AuthorizeApplicationRevisionRead,
		AuthorizeDeploymentCreate, AuthorizeDeploymentUpdate, AuthorizeDeploymentStop,
		AuthorizeDeploymentRollback, AuthorizeDeploymentRead, AuthorizeOperationRead:
		return true
	default:
		return false
	}
}
