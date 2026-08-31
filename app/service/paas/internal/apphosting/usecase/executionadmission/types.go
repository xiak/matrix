// Package executionadmission owns installation-authorized pool and node
// admission. Node bindings are protected process input, not user addresses.
package executionadmission

import (
	"context"
	"errors"
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/port"
	"github.com/xiak/matrix/app/service/paas/internal/audit"
)

const MaximumTargets = 128

var (
	ErrInvalidArgument         = errors.New("execution admission request is invalid")
	ErrNotFound                = errors.New("execution admission resource not found")
	ErrConflict                = errors.New("execution admission conflicts with stored authority")
	ErrIdempotencyConflict     = errors.New("execution admission idempotency conflict")
	ErrResourceVersionConflict = errors.New("execution target resource version conflict")
	ErrInvalidTransition       = errors.New("execution target lifecycle transition is invalid")
	ErrTargetInUse             = errors.New("execution target still owns live or unresolved work")
	ErrUnavailable             = errors.New("execution target observation is unavailable")
	ErrRetryableTransaction    = errors.New("execution admission transaction must be retried")
)

type Binding struct {
	Ref                 string
	TargetID            paasv1.ResourceID
	IdentityFingerprint string
	Adapter             port.InfrastructureAdapter
}

type Config struct {
	InstallationID         string
	Bindings               []Binding
	ObservationTimeout     time.Duration
	MaximumObservationAge  time.Duration
	MaxTransactionAttempts int
	Clock                  func() time.Time
}

type CreatePoolCommand struct {
	Authorization  port.Authorization
	Request        paasv1.CreateExecutionPoolRequest
	IdempotencyKey string
}

type RegisterTargetCommand struct {
	Authorization  port.Authorization
	Request        paasv1.RegisterExecutionTargetRequest
	IdempotencyKey string
}

type TransitionTargetCommand struct {
	Authorization           port.Authorization
	TargetID                paasv1.ResourceID
	Action                  paasv1.OperationAction
	ExpectedResourceVersion uint64
	IdempotencyKey          string
}

type TransitionTargetResult struct {
	Target    paasv1.ExecutionTarget
	Operation paasv1.Operation
	Replayed  bool
}

// Registration is the persisted node identity attached to an ExecutionTarget,
// not a second host resource. Refresh cannot change this accepted binding.
type Registration struct {
	Target              paasv1.ExecutionTarget
	BindingRef          string
	IdentityFingerprint string
}

type Submission struct {
	Operation  paasv1.Operation
	AuditEvent audit.Event
}

type Transaction interface {
	TransactionTime(context.Context) (time.Time, error)
	FindOperationByFingerprint(context.Context, string) (paasv1.Operation, bool, error)
	LoadOperation(context.Context, paasv1.OperationID) (paasv1.Operation, bool, error)
	LoadPool(context.Context, paasv1.ResourceID) (paasv1.ExecutionPool, bool, error)
	LoadPoolTarget(context.Context, paasv1.ResourceID) (paasv1.ExecutionTarget, bool, error)
	LoadTarget(context.Context, paasv1.ResourceID) (Registration, bool, error)
	ListPoolTargets(context.Context, paasv1.ResourceID) ([]paasv1.ExecutionTarget, error)
	ListTargets(context.Context) ([]Registration, error)
	ListTargetResources(context.Context) ([]paasv1.ExecutionTarget, error)
	CreatePool(context.Context, paasv1.ExecutionPool, Submission) error
	RegisterTarget(context.Context, Registration, uint64, paasv1.ExecutionPool, Submission) error
	TransitionTarget(context.Context, uint64, paasv1.ExecutionTarget, uint64, paasv1.ExecutionPool, Submission) error
	RefreshTarget(context.Context, uint64, paasv1.ExecutionTarget, uint64, paasv1.ExecutionPool) error
}

type Repository interface {
	WithinTransaction(context.Context, string, func(context.Context, Transaction) error) error
}

type Service struct {
	repository Repository
	config     Config
	bindings   map[string]Binding
}
