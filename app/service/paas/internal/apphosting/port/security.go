package port

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

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
	AuthorizeDeploymentRollback          = "paas.deployment.rollback"
	AuthorizeDeploymentRead              = "paas.deployment.read"
	AuthorizeOperationRead               = "paas.operation.read"
)

// AuthorizationRequest carries transient credential material to the IAM
// boundary. Credential must never be persisted, logged, or copied into Audit.
type AuthorizationRequest struct {
	Credential string
	Action     string
	Resource   paasv1.ResourceRef
	RequestID  string
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
		AuthorizeDeploymentRollback,
		AuthorizeDeploymentRead,
		AuthorizeOperationRead,
	} {
		if value == candidate {
			return true
		}
	}
	return false
}

type AuditResult string

const (
	AuditAccepted  AuditResult = "ACCEPTED"
	AuditSucceeded AuditResult = "SUCCEEDED"
)

const (
	AuditApplicationCreated           = "paas.application.created"
	AuditConfigurationCreated         = "paas.configuration.created"
	AuditConfigurationRevisionCreated = "paas.configuration-revision.created"
	AuditApplicationRevisionCreated   = "paas.application-revision.created"
	AuditDeploymentCreated            = "paas.deployment.created"
	AuditDeploymentUpdated            = "paas.deployment.updated"
	AuditDeploymentStopped            = "paas.deployment.stopped"
	AuditDeploymentRolledBack         = "paas.deployment.rolled-back"
)

// AuditEvent is the fixed, sanitized business fact apphosting sends to the
// Audit authority. It deliberately has no arbitrary attributes or request
// body field into which configuration, credentials, secrets, or native
// provider payloads could leak.
type AuditEvent struct {
	SchemaVersion string             `json:"schemaVersion"`
	EventID       string             `json:"eventId"`
	TenantID      paasv1.TenantID    `json:"tenantId"`
	Actor         paasv1.SubjectRef  `json:"actor"`
	IAMDecisionID string             `json:"iamDecisionId"`
	Action        string             `json:"action"`
	Target        paasv1.ResourceRef `json:"target"`
	OperationID   paasv1.OperationID `json:"operationId"`
	RequestDigest string             `json:"requestDigest"`
	Result        AuditResult        `json:"result"`
	RequestID     string             `json:"requestId"`
	AuditID       string             `json:"auditId,omitempty"`
	TraceParent   string             `json:"traceparent,omitempty"`
	OccurredAt    time.Time          `json:"occurredAt"`
}

// AuditIngestor must deduplicate EventID and treat an equal replay as success.
// Delivery is at least once because a successful remote call can be followed
// by a local completion failure.
type AuditIngestor interface {
	Ingest(context.Context, AuditEvent) error
}

func ValidateAuditEvent(value AuditEvent) error {
	var problems []error
	if value.SchemaVersion != "v1" {
		problems = append(problems, errors.New("audit schemaVersion must be v1"))
	}
	problems = append(problems,
		paasv1.ValidateID("audit.eventId", value.EventID),
		paasv1.ValidateID("audit.tenantId", string(value.TenantID)),
		paasv1.ValidateID("audit.actor.id", value.Actor.ID),
		paasv1.ValidateID("audit.iamDecisionId", value.IAMDecisionID),
		paasv1.ValidateID("audit.target.id", string(value.Target.ID)),
		paasv1.ValidateID("audit.operationId", string(value.OperationID)),
		paasv1.ValidateDigest("audit.requestDigest", value.RequestDigest),
		paasv1.ValidateID("audit.requestId", value.RequestID),
	)
	if value.Actor.Type != paasv1.SubjectUser &&
		value.Actor.Type != paasv1.SubjectServiceAccount &&
		value.Actor.Type != paasv1.SubjectAgent &&
		value.Actor.Type != paasv1.SubjectSystemUser {
		problems = append(problems, fmt.Errorf("unknown audit actor type %q", value.Actor.Type))
	}
	if value.AuditID != "" {
		problems = append(problems, paasv1.ValidateID("audit.auditId", value.AuditID))
	}
	if value.TraceParent != "" {
		problems = append(problems,
			paasv1.ValidateSafeExternalText("audit.traceparent", value.TraceParent, 55, false),
		)
	}
	expectedKind, expectedResult := auditActionContract(value.Action)
	if expectedKind == "" {
		problems = append(problems, fmt.Errorf("unknown audit action %q", value.Action))
	} else if value.Target.Kind != expectedKind {
		problems = append(problems, errors.New("audit action and target kind differ"))
	}
	if value.Result != expectedResult {
		problems = append(problems, errors.New("audit action and result differ"))
	}
	if value.OccurredAt.IsZero() || value.OccurredAt.Location() != time.UTC ||
		value.OccurredAt != value.OccurredAt.Round(0) ||
		value.OccurredAt.Nanosecond()%1_000 != 0 {
		problems = append(problems, errors.New("audit occurredAt must be UTC with microsecond precision"))
	}
	return errors.Join(problems...)
}

func auditActionContract(action string) (string, AuditResult) {
	switch action {
	case AuditApplicationCreated:
		return "Application", AuditSucceeded
	case AuditConfigurationCreated:
		return "Configuration", AuditSucceeded
	case AuditConfigurationRevisionCreated:
		return "ConfigurationRevision", AuditSucceeded
	case AuditApplicationRevisionCreated:
		return "ApplicationRevision", AuditSucceeded
	case AuditDeploymentCreated,
		AuditDeploymentUpdated,
		AuditDeploymentStopped,
		AuditDeploymentRolledBack:
		return "Deployment", AuditAccepted
	default:
		return "", ""
	}
}
