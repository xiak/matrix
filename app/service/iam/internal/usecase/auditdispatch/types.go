package auditdispatch

import (
	"context"
	"errors"
	"time"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
)

var (
	ErrStaleLease            = errors.New("IAM Audit lease or fencing token is stale")
	ErrIngestInvalid         = errors.New("Audit ingestion rejected the IAM event")
	ErrIngestUnauthenticated = errors.New("Audit ingestion authentication failed")
	ErrIngestConflict        = errors.New("Audit ingestion replay conflicts")
	ErrIngestUnavailable     = errors.New("Audit ingestion is unavailable")
)

type Claim struct {
	// OrganizationID owns the IAM outbox row, not necessarily the Audit chain.
	OrganizationID iamv1.OrganizationID
	// InstallationID is sealed by that organization's bootstrap receipt.
	InstallationID string
	EventID        auditv1.EventID
	Attempts       int
	FencingToken   uint64
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
	EventID      auditv1.EventID
	WorkerID     string
	FencingToken uint64
	Outcome      Outcome
	RetryDelay   time.Duration
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

type AuditIngestor interface {
	Ingest(context.Context, auditv1.Event) error
}

type Config struct {
	WorkerID        string
	LeaseDuration   time.Duration
	DeliveryTimeout time.Duration
	InitialBackoff  time.Duration
	MaxBackoff      time.Duration
	MaxAttempts     int
}

type Result struct {
	Claimed    bool
	Delivered  bool
	Retried    bool
	DeadLetter bool
}

type Usecase struct {
	repository Repository
	ingestor   AuditIngestor
	config     Config
}
