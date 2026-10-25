// Package terminalsession owns the short-lived, write-capable Deployment
// terminal lifecycle. It is deliberately independent of durable Operations.
package terminalsession

import (
	"context"
	"errors"
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/port"
	"github.com/xiak/matrix/app/service/paas/internal/audit"
)

var (
	ErrInvalidArgument      = errors.New("terminal session request is invalid")
	ErrNotFound             = errors.New("terminal session or runtime instance was not found")
	ErrPermissionDenied     = errors.New("terminal session belongs to another subject")
	ErrConflict             = errors.New("terminal session conflicts with current runtime")
	ErrIdempotencyConflict  = errors.New("terminal session idempotency conflict")
	ErrExpired              = errors.New("terminal session connection ticket expired")
	ErrRetryableTransaction = errors.New("terminal session transaction must be retried")
)

type CreateCommand struct {
	Authorization  port.Authorization
	DeploymentID   paasv1.ResourceID
	Request        paasv1.CreateTerminalSessionRequest
	IdempotencyKey string
	TicketDigest   string
}

type CloseCommand struct {
	Authorization port.Authorization
	SessionID     paasv1.ResourceID
}

type RuntimeBinding struct {
	DeploymentID          paasv1.ResourceID `json:"deploymentId"`
	Generation            uint64            `json:"generation"`
	ApplicationRevisionID paasv1.ResourceID `json:"applicationRevisionId"`
	ContentDigest         string            `json:"contentDigest"`
	ExecutionTargetID     paasv1.ResourceID `json:"executionTargetId"`
	PlacementDecisionID   paasv1.ResourceID `json:"placementDecisionId"`
	BindingRef            string            `json:"bindingRef"`
	InstanceID            paasv1.ResourceID `json:"instanceId"`
}

// StoredSession contains only durable authorization and runtime proof. It has
// no connection ticket, provider identity, terminal bytes or workload secret.
type StoredSession struct {
	Session                paasv1.TerminalSession `json:"session"`
	Binding                RuntimeBinding         `json:"binding"`
	Subject                paasv1.SubjectRef      `json:"subject"`
	IAMDecisionID          string                 `json:"iamDecisionId"`
	RequestID              string                 `json:"requestId"`
	AuditID                string                 `json:"auditId,omitempty"`
	TraceParent            string                 `json:"traceparent,omitempty"`
	IdempotencyFingerprint string                 `json:"idempotencyFingerprint"`
	RequestDigest          string                 `json:"requestDigest"`
}

type CreateResult struct {
	Stored     StoredSession
	Replayed   bool
	ReplacedID paasv1.ResourceID
}

type Transaction interface {
	TransactionTime(context.Context) (time.Time, error)
	FindByFingerprint(context.Context, string) (StoredSession, bool, error)
	LoadAndLockSession(context.Context, paasv1.ResourceID) (StoredSession, bool, error)
	LoadAndLockOpenForSubjectInstance(
		context.Context,
		paasv1.SubjectRef,
		paasv1.ResourceID,
		paasv1.ResourceID,
	) (StoredSession, bool, error)
	LoadAndLockCurrentRuntime(
		context.Context,
		paasv1.ResourceID,
		paasv1.ResourceID,
		time.Time,
	) (RuntimeBinding, bool, error)
	Insert(context.Context, StoredSession, string, audit.Event) error
	RotateTicket(context.Context, paasv1.ResourceID, string) error
	ConsumeTicket(context.Context, StoredSession, paasv1.TerminalSession) error
	Transition(context.Context, StoredSession, paasv1.TerminalSession, audit.Event) error
}

type Repository interface {
	WithinTenant(
		context.Context,
		paasv1.TenantID,
		func(context.Context, Transaction) error,
	) error
	WithinTicket(
		context.Context,
		paasv1.ResourceID,
		string,
		func(context.Context, Transaction, StoredSession) error,
	) error
}

type Config struct {
	MaxTransactionAttempts int
}

type Service struct {
	repository Repository
	config     Config
}
