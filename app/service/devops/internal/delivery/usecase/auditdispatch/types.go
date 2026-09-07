// Package auditdispatch owns reliable delivery of committed DevOps Audit
// outbox events to the independently deployed Audit service.
package auditdispatch

import (
	"context"
	"errors"
	"time"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/port"
)

var ErrStaleLease = errors.New("Audit outbox lease or fencing token is stale")

type Claim struct {
	TenantID       devopsv1.TenantID
	EventID        auditv1.EventID
	Attempts       int
	FencingToken   int64
	LeaseExpiresAt time.Time
	Event          auditv1.Event
}

type Outcome string

const (
	OutcomeDelivered  Outcome = "DELIVERED"
	OutcomeRetry      Outcome = "RETRY"
	OutcomeDeadLetter Outcome = "DEAD_LETTER"
)

type Completion struct {
	TenantID     devopsv1.TenantID
	EventID      auditv1.EventID
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
	Readiness(context.Context) (devopsv1.Readiness, error)
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
	ingestor   port.AuditIngestor
	config     Config
}
