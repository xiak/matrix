package createplacement

import (
	"context"
	"errors"
	"time"

	paasv1 "matrix/api/paas/v1"
	"matrix/app/service/paas/internal/runtime/domain/placement"
)

var (
	ErrRetryableTransaction = errors.New("placement transaction must be retried")
	ErrIdempotencyConflict  = errors.New("placement operation idempotency conflict")
)

type Command struct {
	TenantID          paasv1.TenantID
	OperationID       paasv1.OperationID
	DecisionID        paasv1.ResourceID
	WorkloadReleaseID paasv1.ResourceID
	PlacementPolicyID paasv1.ResourceID
	RequestDigest     string
	TraceID           string
}

type Result struct {
	Decision paasv1.PlacementDecision
	Replayed bool
}

type StoredDecision struct {
	RequestDigest string
	Decision      paasv1.PlacementDecision
}

type DecisionCreation struct {
	OperationID   paasv1.OperationID
	RequestDigest string
	Decision      paasv1.PlacementDecision
	Reservation   *CapacityReservationCreation
}

// CapacityReservationCreation links the tenant-owned decision to the
// tenant-neutral capacity claim created by the PostgreSQL repository in the
// same transaction.
type CapacityReservationCreation struct {
	ID                paasv1.ResourceID
	TenantID          paasv1.TenantID
	WorkloadReleaseID paasv1.ResourceID
	DecisionID        paasv1.ResourceID
	RuntimeTargetID   paasv1.ResourceID
	Isolation         paasv1.IsolationClass
	Resources         placement.Resources
	State             placement.CapacityClaimState
	LeaseExpiresAt    time.Time
	ResourceVersion   uint64
}

type Transaction interface {
	TransactionTime(context.Context) (time.Time, error)
	FindDecisionByOperation(
		context.Context,
		paasv1.OperationID,
	) (StoredDecision, bool, error)
	LoadAndLockSnapshot(
		context.Context,
		paasv1.ResourceID,
		paasv1.ResourceID,
	) (placement.Snapshot, error)
	CreateDecision(context.Context, DecisionCreation) error
}

// Repository owns the persistence operations required by this use case. The
// callback is explicit because locking, decision creation, and reservation
// creation must commit atomically.
type Repository interface {
	WithinTransaction(
		context.Context,
		paasv1.TenantID,
		func(context.Context, Transaction) error,
	) error
}

type Config struct {
	PendingReservationTTL  time.Duration
	MaxTransactionAttempts int
}

type Usecase struct {
	planner    *placement.Planner
	repository Repository
	config     Config
}
