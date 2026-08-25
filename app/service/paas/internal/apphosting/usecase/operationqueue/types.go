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
}

type Config struct {
	LeaseDuration time.Duration
}

type Queue struct {
	repository Repository
	config     Config
}
