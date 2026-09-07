// Package runcontrol owns IAM-authorized PipelineRun reads and cancellation
// requests. Worker lease coordination remains in runlifecycle.
package runcontrol

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/port"
)

var traceParentPattern = regexp.MustCompile(`^00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$`)

var (
	ErrInvalidArgument         = errors.New("invalid PipelineRun control command")
	ErrNotFound                = errors.New("PipelineRun not found")
	ErrIdempotencyConflict     = errors.New("idempotency key was reused for a different cancellation")
	ErrResourceVersionConflict = errors.New("PipelineRun resource version conflict")
	ErrNoDesiredChange         = errors.New("PipelineRun cancellation is already requested")
	ErrTerminal                = errors.New("PipelineRun is terminal")
	ErrRetryableTransaction    = errors.New("retryable PipelineRun control transaction")
)

const (
	cancellationKind       = "CANCEL_PIPELINE_RUN"
	cancellationResultKind = "PipelineRun"
)

type CancellationOperation struct {
	SchemaVersion           string                  `json:"schemaVersion"`
	ID                      string                  `json:"id"`
	TenantID                devopsv1.TenantID       `json:"tenantId"`
	Kind                    string                  `json:"kind"`
	CommandTargetID         devopsv1.ResourceID     `json:"commandTargetId"`
	RunID                   devopsv1.ResourceID     `json:"runId"`
	RequestedBy             devopsv1.SubjectRef     `json:"requestedBy"`
	IAMDecisionID           string                  `json:"iamDecisionId"`
	IAMAction               iamv1.Action            `json:"iamAction"`
	IAMResource             iamv1.ResourceReference `json:"iamResource"`
	ExpectedResourceVersion uint64                  `json:"expectedResourceVersion"`
	IdempotencyFingerprint  string                  `json:"idempotencyFingerprint"`
	RequestDigest           string                  `json:"requestDigest"`
	ResultKind              string                  `json:"resultKind"`
	Target                  auditv1.TargetReference `json:"target"`
	RequestID               string                  `json:"requestId"`
	CorrelationID           string                  `json:"correlationId"`
	TraceParent             string                  `json:"traceparent,omitempty"`
	CreatedAt               time.Time               `json:"createdAt"`
}

type StoredCancellation struct {
	Operation CancellationOperation
	Result    devopsv1.PipelineRun
}

type Submission struct {
	Operation         CancellationOperation
	Result            devopsv1.PipelineRun
	CancellationEvent auditv1.Event
	TerminalEvent     *auditv1.Event
}

type Transaction interface {
	TransactionTime(context.Context) (time.Time, error)
	FindCancellation(context.Context, string) (StoredCancellation, bool, error)
	LoadPipelineRun(context.Context, devopsv1.ResourceID) (devopsv1.PipelineRun, bool, error)
	LockPipelineRunForCancellation(context.Context, devopsv1.ResourceID) (devopsv1.PipelineRun, bool, bool, error)
	CommitPipelineRunCancellation(context.Context, uint64, Submission) error
}

type Repository interface {
	WithinRunControlTransaction(context.Context, devopsv1.TenantID, func(context.Context, Transaction) error) error
}

type Config struct {
	MaxTransactionAttempts int
}

type Service struct {
	repository Repository
	config     Config
}

type GetQuery struct {
	Authorization port.Authorization
	RunID         devopsv1.ResourceID
}

type CancelCommand struct {
	Authorization           port.Authorization
	RunID                   devopsv1.ResourceID
	ExpectedResourceVersion uint64
	IdempotencyKey          string
}

type Result struct {
	Value    devopsv1.PipelineRun
	Replayed bool
}

func NewService(repository Repository, config Config) (*Service, error) {
	if repository == nil {
		return nil, errors.New("PipelineRun control repository is required")
	}
	if config.MaxTransactionAttempts < 1 || config.MaxTransactionAttempts > 10 {
		return nil, errors.New("maximum transaction attempts must be between 1 and 10")
	}
	return &Service{repository: repository, config: config}, nil
}

func ValidateCancellationOperation(value CancellationOperation) error {
	var problems []error
	problems = append(problems,
		devopsv1.ValidateID("cancellation.id", value.ID),
		devopsv1.ValidateID("cancellation.tenantId", string(value.TenantID)),
		devopsv1.ValidateID("cancellation.runId", string(value.RunID)),
		devopsv1.ValidateSubjectRef(value.RequestedBy),
		devopsv1.ValidateID("cancellation.iamDecisionId", value.IAMDecisionID),
		devopsv1.ValidateID("cancellation.iamResource.id", value.IAMResource.ID),
		devopsv1.ValidateDigest("cancellation.idempotencyFingerprint", value.IdempotencyFingerprint),
		devopsv1.ValidateDigest("cancellation.requestDigest", value.RequestDigest),
		devopsv1.ValidateID("cancellation.requestId", value.RequestID),
		devopsv1.ValidateID("cancellation.correlationId", value.CorrelationID),
	)
	if value.SchemaVersion != "v1" || value.Kind != cancellationKind ||
		value.CommandTargetID != value.RunID || value.ResultKind != cancellationResultKind ||
		value.Target != (auditv1.TargetReference{Kind: auditv1.TargetPipelineRun, ID: string(value.RunID)}) ||
		value.ID != operationID(value.IdempotencyFingerprint) {
		problems = append(problems, errors.New("cancellation Operation identity is invalid"))
	}
	if value.IAMAction != iamv1.ActionDevOpsRunCancel ||
		value.IAMResource.Kind != iamv1.ResourcePipelineRun ||
		value.IAMResource.ID != string(value.RunID) {
		problems = append(problems, errors.New("cancellation Operation authority is invalid"))
	}
	if value.ExpectedResourceVersion == 0 || value.ExpectedResourceVersion > devopsv1.MaximumContractInteger {
		problems = append(problems, errors.New("cancellation expected resource version is invalid"))
	}
	if value.CreatedAt.IsZero() || value.CreatedAt.Location() != time.UTC ||
		value.CreatedAt != value.CreatedAt.Round(0) || value.CreatedAt.Nanosecond()%1_000 != 0 {
		problems = append(problems, errors.New("cancellation createdAt must be UTC with microsecond precision"))
	}
	if value.TraceParent != "" && !traceParentPattern.MatchString(value.TraceParent) {
		problems = append(problems, errors.New("cancellation traceparent is invalid"))
	}
	return errors.Join(problems...)
}

func ValidateStoredCancellation(value StoredCancellation) error {
	var problems []error
	problems = append(problems,
		ValidateCancellationOperation(value.Operation),
		devopsv1.ValidatePipelineRun(value.Result),
	)
	if value.Result.Scope.TenantID != value.Operation.TenantID ||
		value.Result.ID != value.Operation.RunID ||
		value.Result.Status.ResourceVersion != value.Operation.ExpectedResourceVersion+1 ||
		value.Result.Status.CancellationRequestedAt == nil ||
		!value.Result.Status.CancellationRequestedAt.Equal(value.Operation.CreatedAt) ||
		!value.Result.UpdatedAt.Equal(value.Operation.CreatedAt) {
		problems = append(problems, errors.New("stored cancellation result differs from its Operation"))
	}
	return errors.Join(problems...)
}

func ValidateSubmission(value Submission) error {
	var problems []error
	problems = append(problems,
		ValidateStoredCancellation(StoredCancellation{Operation: value.Operation, Result: value.Result}),
		auditv1.ValidateEventForSource(auditv1.SourceDevOps, value.CancellationEvent),
	)
	event := value.CancellationEvent
	operation := value.Operation
	if event.TenantID != auditv1.TenantID(operation.TenantID) ||
		event.Actor != (auditv1.ActorReference{Type: auditv1.ActorType(operation.RequestedBy.Kind), ID: auditv1.ActorID(operation.RequestedBy.ID)}) ||
		string(event.IAMDecisionID) != operation.IAMDecisionID ||
		event.Action != auditv1.ActionDevOpsPipelineRunCancellationRequested ||
		event.Target != (auditv1.TargetReference{Kind: auditv1.TargetPipelineRun, ID: string(operation.RunID)}) ||
		event.Result != auditv1.ResultAccepted || event.Outcome != "" || event.Reason != "" ||
		event.RequestDigest != operation.RequestDigest || event.RequestID != operation.RequestID ||
		event.CorrelationID != operation.CorrelationID || string(event.OperationID) != operation.ID ||
		event.TraceParent != operation.TraceParent || !event.OccurredAt.Equal(operation.CreatedAt) {
		problems = append(problems, errors.New("cancellation Audit event differs from its Operation"))
	}
	if value.Result.Status.CompletedAt == nil {
		if value.TerminalEvent != nil {
			problems = append(problems, errors.New("pending cancellation cannot contain a terminal Audit event"))
		}
	} else if value.TerminalEvent == nil {
		problems = append(problems, errors.New("completed cancellation requires a terminal Audit event"))
	} else {
		problems = append(problems, auditv1.ValidateEventForSource(auditv1.SourceDevOps, *value.TerminalEvent))
		if value.TerminalEvent.Target.ID != string(operation.RunID) ||
			!value.TerminalEvent.OccurredAt.Equal(*value.Result.Status.CompletedAt) {
			problems = append(problems, errors.New("terminal Audit event differs from cancellation result"))
		}
	}
	return errors.Join(problems...)
}

func formatInvalid(err error) error {
	return fmt.Errorf("%w: %v", ErrInvalidArgument, err)
}
