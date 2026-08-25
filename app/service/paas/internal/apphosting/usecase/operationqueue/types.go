package operationqueue

import (
	"context"
	"errors"
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

var (
	ErrNotFound          = errors.New("Operation not found")
	ErrStaleLease        = errors.New("Operation lease or fencing token is stale")
	ErrInvalidTransition = errors.New("Operation transition is invalid")
)

type Lease struct {
	TenantID       paasv1.TenantID
	Operation      paasv1.Operation
	WorkerID       string
	FencingToken   uint64
	LeaseExpiresAt time.Time
}

// LeaseGuard is the minimum database-authoritative write authority passed to
// another worker use case. Lease expiry is deliberately not copied: every
// mutation rechecks the current Operation row and database clock.
type LeaseGuard struct {
	TenantID     paasv1.TenantID
	OperationID  paasv1.OperationID
	WorkerID     string
	FencingToken uint64
}

func (lease Lease) Guard() LeaseGuard {
	return LeaseGuard{
		TenantID:     lease.TenantID,
		OperationID:  lease.Operation.ID,
		WorkerID:     lease.WorkerID,
		FencingToken: lease.FencingToken,
	}
}

type Transition struct {
	Lease         Lease
	State         paasv1.OperationState
	Problem       *paasv1.Problem
	NextAttemptAt *time.Time
	ReleaseLease  bool
}

type Repository interface {
	ClaimOperation(context.Context, string, time.Duration) (Lease, bool, error)
	AdvanceOperation(context.Context, Transition) (paasv1.Operation, error)
	ReleaseOperation(context.Context, Lease, time.Time) (paasv1.Operation, error)
}

type Config struct {
	LeaseDuration time.Duration
}

type Queue struct {
	repository Repository
	config     Config
}
