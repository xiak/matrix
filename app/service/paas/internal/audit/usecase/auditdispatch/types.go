package auditdispatch

import (
	"context"
	"errors"
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/paas/internal/audit"
)

var ErrStaleLease = errors.New("Audit outbox lease or fencing token is stale")

type Claim struct {
	TenantID       paasv1.TenantID
	EventID        string
	Attempts       int
	FencingToken   int64
	LeaseExpiresAt time.Time
	Stream         Stream
	Event          audit.Event
}

type Stream string

const (
	StreamAppHosting     Stream = "APPHOSTING"
	StreamManagedService Stream = "MANAGED_SERVICE"
)

type Outcome string

const (
	OutcomeDelivered  Outcome = "DELIVERED"
	OutcomeRetry      Outcome = "RETRY"
	OutcomeDeadLetter Outcome = "DEAD_LETTER"
)

type Completion struct {
	TenantID     paasv1.TenantID
	EventID      string
	Stream       Stream
	WorkerID     string
	FencingToken int64
	Outcome      Outcome
	RetryAt      time.Time
	ErrorCode    string
}

type Snapshot struct {
	Pending      int64
	Leased       int64
	Retry        int64
	Delivered    int64
	DeadLetter   int64
	ExpiredLease int64
}

type Repository interface {
	Claim(context.Context, string, time.Duration) (Claim, bool, error)
	Complete(context.Context, Completion) error
	Snapshot(context.Context) (Snapshot, error)
}

type Config struct {
	WorkerID        string
	LeaseDuration   time.Duration
	DeliveryTimeout time.Duration
	InitialBackoff  time.Duration
	MaxBackoff      time.Duration
	MaxAttempts     int
	Now             func() time.Time
}

type Result struct {
	Claimed    bool
	Delivered  bool
	Retried    bool
	DeadLetter bool
}

type Usecase struct {
	repository Repository
	ingestor   audit.Ingestor
	config     Config
}
