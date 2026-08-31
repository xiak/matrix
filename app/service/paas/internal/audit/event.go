package audit

import (
	"context"
	"errors"
	"fmt"
	"time"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

var (
	ErrInvalid         = errors.New("Audit ingestion rejected the PaaS event")
	ErrUnauthenticated = errors.New("Audit ingestion authentication failed")
	ErrConflict        = errors.New("Audit ingestion replay conflicts")
	ErrUnavailable     = errors.New("Audit ingestion is unavailable")
)

type Result string

const (
	Accepted     Result = "ACCEPTED"
	Succeeded    Result = "SUCCEEDED"
	Completed    Result = "COMPLETED"
	Unsupported  Result = "UNSUPPORTED"
	Expired      Result = "EXPIRED"
	Disconnected Result = "DISCONNECTED"
	Revoked      Result = "REVOKED"
	Replaced     Result = "REPLACED"
	Failed       Result = "FAILED"
)

const (
	ApplicationCreated           = "paas.application.created"
	ConfigurationCreated         = "paas.configuration.created"
	ConfigurationRevisionCreated = "paas.configuration-revision.created"
	ApplicationRevisionCreated   = "paas.application-revision.created"
	DeploymentCreated            = "paas.deployment.created"
	DeploymentUpdated            = "paas.deployment.updated"
	DeploymentStopped            = "paas.deployment.stopped"
	DeploymentRolledBack         = "paas.deployment.rolled-back"
	ExecutionPoolCreated         = "paas.execution-pool.created"
	ExecutionTargetRegistered    = "paas.execution-target.registered"
	TerminalSessionCreated       = "paas.terminal-session.created"
	TerminalSessionStarted       = "paas.terminal-session.started"
	TerminalSessionEnded         = "paas.terminal-session.ended"
	QuotaEntitlementActivated    = "managedservice.quota-entitlement.activated"
	ServiceInstallationCreated   = "managedservice.service-installation.created"
	ServiceInstallationReady     = "managedservice.service-installation.ready"
)

const (
	TargetQuotaEntitlement    = "QuotaEntitlement"
	TargetServiceInstallation = "ServiceInstallation"
	TargetTerminalSession     = "TerminalSession"
)

const (
	ActorUser           = paasv1.SubjectUser
	ActorServiceAccount = paasv1.SubjectServiceAccount
)

type ActorReference = paasv1.SubjectRef
type TargetReference = paasv1.ResourceRef
type TenantID = paasv1.TenantID
type OperationID = paasv1.OperationID
type ResourceID = paasv1.ResourceID

// Event is the fixed, sanitized business fact emitted by a PaaS bounded
// context. It deliberately has no arbitrary attributes or request body field
// into which configuration, credentials, secrets, or provider payloads could
// leak. The persisted JSON shape remains stable across PaaS contexts.
type Event struct {
	SchemaVersion  string             `json:"schemaVersion"`
	EventID        string             `json:"eventId"`
	TenantID       paasv1.TenantID    `json:"tenantId,omitempty"`
	InstallationID string             `json:"installationId,omitempty"`
	Actor          paasv1.SubjectRef  `json:"actor"`
	IAMDecisionID  string             `json:"iamDecisionId"`
	Action         string             `json:"action"`
	Target         paasv1.ResourceRef `json:"target"`
	OperationID    paasv1.OperationID `json:"operationId,omitempty"`
	RequestDigest  string             `json:"requestDigest"`
	Result         Result             `json:"result"`
	RequestID      string             `json:"requestId"`
	AuditID        string             `json:"auditId,omitempty"`
	TraceParent    string             `json:"traceparent,omitempty"`
	OccurredAt     time.Time          `json:"occurredAt"`
}

// Ingestor must deduplicate EventID and treat an equal replay as success.
// Delivery is at least once because a successful remote call can be followed
// by a local completion failure.
type Ingestor interface {
	Ingest(context.Context, Event) error
}

func ValidateEvent(value Event) error {
	var problems []error
	if value.SchemaVersion != "v1" {
		problems = append(problems, errors.New("audit schemaVersion must be v1"))
	}
	public, err := ToV1(value)
	problems = append(problems, err)
	if err == nil {
		problems = append(problems, auditv1.ValidateEventForSource(auditv1.SourcePaaS, public))
	}
	return errors.Join(problems...)
}

func ToV1(value Event) (auditv1.Event, error) {
	actorType, err := actorTypeToV1(value.Actor.Type)
	if err != nil {
		return auditv1.Event{}, err
	}
	targetKind, err := targetKindToV1(value.Target.Kind)
	if err != nil {
		return auditv1.Event{}, err
	}
	correlationID := value.AuditID
	if correlationID == "" {
		correlationID = value.RequestID
	}
	return auditv1.Event{
		APIVersion: auditv1.APIVersion, Kind: "AuditEvent",
		EventID: auditv1.EventID(value.EventID), TenantID: auditv1.TenantID(value.TenantID),
		InstallationID: value.InstallationID,
		Actor:          auditv1.ActorReference{Type: actorType, ID: auditv1.ActorID(value.Actor.ID)},
		IAMDecisionID:  auditv1.DecisionID(value.IAMDecisionID),
		Action:         auditv1.Action(value.Action),
		Target:         auditv1.TargetReference{Kind: targetKind, ID: string(value.Target.ID)},
		Result:         auditv1.Result(value.Result), RequestDigest: value.RequestDigest,
		RequestID: value.RequestID, CorrelationID: correlationID,
		OperationID: auditv1.OperationID(value.OperationID), TraceParent: value.TraceParent,
		OccurredAt: value.OccurredAt,
	}, nil
}

func actorTypeToV1(value paasv1.SubjectType) (auditv1.ActorType, error) {
	switch value {
	case paasv1.SubjectUser:
		return auditv1.ActorUser, nil
	case paasv1.SubjectServiceAccount:
		return auditv1.ActorServiceAccount, nil
	case paasv1.SubjectAgent, paasv1.SubjectSystemUser:
		return auditv1.ActorSystem, nil
	default:
		return "", fmt.Errorf("PaaS actor type %q cannot map to Audit", value)
	}
}

func targetKindToV1(value string) (auditv1.TargetKind, error) {
	switch value {
	case "Application":
		return auditv1.TargetApplication, nil
	case "Configuration":
		return auditv1.TargetConfiguration, nil
	case "ConfigurationRevision":
		return auditv1.TargetConfigurationRevision, nil
	case "ApplicationRevision":
		return auditv1.TargetApplicationRevision, nil
	case "Deployment":
		return auditv1.TargetDeployment, nil
	case TargetTerminalSession:
		return auditv1.TargetTerminalSession, nil
	case "ExecutionPool":
		return auditv1.TargetExecutionPool, nil
	case "ExecutionTarget":
		return auditv1.TargetExecutionTarget, nil
	case TargetQuotaEntitlement:
		return auditv1.TargetQuotaEntitlement, nil
	case TargetServiceInstallation:
		return auditv1.TargetServiceInstallation, nil
	default:
		return "", fmt.Errorf("PaaS target kind %q cannot map to Audit", value)
	}
}
