package port

import (
	"context"
	"errors"
	"fmt"
	"strings"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

var (
	ErrUnauthenticated          = errors.New("IAM authentication failed")
	ErrPermissionDenied         = errors.New("IAM authorization denied")
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
	AuthorizePlatformOperationRead       = "paas.platform-operation.read"
	AuthorizeTerminalSessionCreate       = "paas.terminal-session.create"
	AuthorizeTerminalSessionClose        = "paas.terminal-session.close"
)

// AuthorizationRequest carries transient credential material to the IAM
// boundary. Credential must never be persisted, logged, or copied into Audit.
type AuthorizationRequest struct {
	Credential string
	Action     string
	Resource   paasv1.ResourceRef
	RequestID  string
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
	)
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
		paasv1.ValidateID("authorization.subject.id", value.Subject.ID),
		paasv1.ValidateID("authorization.decisionId", value.DecisionID),
		paasv1.ValidateID("authorization.requestId", value.RequestID),
	)
	if value.Subject.Type != paasv1.SubjectUser &&
		value.Subject.Type != paasv1.SubjectServiceAccount &&
		value.Subject.Type != paasv1.SubjectAgent &&
		value.Subject.Type != paasv1.SubjectSystemUser {
		problems = append(problems, fmt.Errorf("unknown authorized subject type %q", value.Subject.Type))
	}
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
		AuthorizePlatformOperationRead:
		return true
	default:
		return false
	}
}
