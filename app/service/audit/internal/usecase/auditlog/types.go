package auditlog

import (
	"context"
	"errors"
	"time"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/audit/internal/authority"
)

var (
	ErrInvalidArgument      = errors.New("Audit argument is invalid")
	ErrUnauthenticated      = errors.New("Audit authentication failed")
	ErrForbidden            = errors.New("Audit authorization denied")
	ErrConflict             = errors.New("Audit state conflicts with the request")
	ErrUnavailable          = errors.New("Audit authority is unavailable")
	ErrRetryableTransaction = errors.New("Audit transaction is retryable")
)

type Config struct {
	CursorKey              []byte
	MaxTransactionAttempts int
	NewID                  func(prefix string) (string, error)
}

type IAM interface {
	ResolveAuditProducer(context.Context, iamv1.Secret, iamv1.ResolveAuditProducerRequest) (iamv1.AuditProducerAuthorization, error)
	Authorize(
		context.Context,
		iamv1.Secret,
		iamv1.AuthorizationRequest,
	) (iamv1.AuthorizationDecision, error)
	VerifyInstallation(
		context.Context,
		iamv1.Secret,
		iamv1.AuthorizationRequest,
	) (iamv1.AuthorizationDecision, error)
}

type Repository interface {
	WithinTransaction(
		context.Context,
		func(context.Context, Transaction) error,
	) error
}

type Transaction interface {
	TransactionTime(context.Context) (time.Time, error)
	LockEvent(context.Context, auditv1.Source, auditv1.EventID) error
	LookupRecord(context.Context, auditv1.Source, auditv1.EventID) (StoredRecord, bool, error)
	LockTenantHead(context.Context, auditv1.TenantID) (authority.Checkpoint, time.Time, error)
	AppendRecord(context.Context, AppendMutation) (auditv1.IngestionOutcome, error)
	ReadRecords(context.Context, RecordQuery) ([]auditv1.AuditRecord, error)
	ReadCheckpoint(context.Context, auditv1.TenantID, uint64) (authority.Checkpoint, bool, error)
	ReadChain(context.Context, auditv1.TenantID, uint64, int) ([]auditv1.AuditRecord, error)
	LookupPaaSOperationRecord(
		context.Context,
		auditv1.TenantID,
		auditv1.OperationID,
	) (auditv1.AuditRecord, bool, error)
	Readiness(context.Context) (ReadinessSnapshot, error)
}

type StoredRecord struct {
	Record auditv1.AuditRecord
	Replay authority.ReplayState
}

type AppendMutation struct {
	Record auditv1.AuditRecord
	Fact   authority.CanonicalFact
}

type RecordQuery struct {
	TenantID       auditv1.TenantID
	BeforeSequence uint64
	Limit          int
	From           *time.Time
	To             *time.Time
	Action         auditv1.Action
	Actor          *auditv1.ActorReference
}

type ReadinessSnapshot struct {
	Ready         bool
	SchemaVersion uint64
	CheckedAt     time.Time
}

type Service struct {
	repository Repository
	iam        IAM
	config     Config
	cursors    authority.CursorCodec
}
