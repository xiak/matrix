// Package runadmission owns the authenticated source-event transaction that
// creates immutable queued PipelineRuns without starting executor effects.
package runadmission

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/domain"
)

const (
	MaximumQueuedRuns    = uint64(32)
	sourceIngressActorID = auditv1.ActorID("system-devops-source-ingress")
)

var (
	ErrInvalidArgument       = errors.New("invalid run admission command")
	ErrPreconditionFailed    = errors.New("run admission precondition failed")
	ErrReplayConflict        = errors.New("source delivery replay changed")
	ErrQueueCapacityExceeded = errors.New("tenant queued-run capacity is exhausted")
	ErrRetryableTransaction  = errors.New("retryable run admission transaction")
)

var traceParentPattern = regexp.MustCompile(`^00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$`)

type Command struct {
	Change        domain.NormalizedChange
	RequestID     string
	CorrelationID string
	TraceParent   string
}

type Admission struct {
	Event devopsv1.SourceEvent
	Runs  []devopsv1.PipelineRun
}

type Result struct {
	Admission Admission
	Replayed  bool
}

type Submission struct {
	Admission   Admission
	AuditEvents []auditv1.Event
}

type Transaction interface {
	TransactionTime(context.Context) (time.Time, error)
	LoadAdmission(context.Context, devopsv1.ResourceID) (Admission, bool, error)
	LoadSourceConnection(context.Context, devopsv1.ResourceID) (devopsv1.SourceConnection, bool, error)
	LoadRepositoryBindingForSource(
		context.Context,
		devopsv1.ResourceID,
		devopsv1.ResourceID,
	) (devopsv1.RepositoryBinding, bool, error)
	LoadMatchingActiveRevisions(
		context.Context,
		devopsv1.ResourceID,
		string,
	) ([]devopsv1.PipelineActivation, error)
	QueuedRunCount(context.Context) (uint64, error)
	CommitAdmission(context.Context, Submission) error
}

type Repository interface {
	WithinAdmissionTransaction(
		context.Context,
		devopsv1.TenantID,
		func(context.Context, Transaction) error,
	) error
}

type Config struct {
	MaxTransactionAttempts int
}

type Usecase struct {
	repository Repository
	config     Config
}

func NewUsecase(repository Repository, config Config) (*Usecase, error) {
	if repository == nil {
		return nil, errors.New("run admission repository is required")
	}
	if config.MaxTransactionAttempts < 1 || config.MaxTransactionAttempts > 10 {
		return nil, errors.New("maximum transaction attempts must be between 1 and 10")
	}
	return &Usecase{repository: repository, config: config}, nil
}

func ValidateAdmission(value Admission) error {
	var problems []error
	problems = append(problems, devopsv1.ValidateSourceEvent(value.Event))
	if uint64(len(value.Runs)) > MaximumQueuedRuns {
		problems = append(problems, errors.New("admission contains too many PipelineRuns"))
	}
	var previousPipelineID devopsv1.ResourceID
	for index, run := range value.Runs {
		problems = append(problems, devopsv1.ValidatePipelineRun(run))
		if run.Replay != nil || run.Scope != value.Event.Scope ||
			run.ProjectID != value.Event.Spec.ProjectID ||
			run.Input.SourceEventID != value.Event.ID ||
			run.Input.SourceEventDigest != value.Event.ContentDigest ||
			run.Input.RepositoryBindingID != value.Event.Spec.RepositoryBindingID ||
			run.Input.RepositoryBindingDigest != value.Event.Spec.RepositoryBindingDigest ||
			run.Input.Change != value.Event.Spec.Change ||
			!run.CreatedAt.Equal(value.Event.ReceivedAt) {
			problems = append(problems, fmt.Errorf("PipelineRun %d does not bind the SourceEvent", index))
		}
		if index > 0 && previousPipelineID >= run.PipelineID {
			problems = append(problems, errors.New("PipelineRuns are not uniquely ordered by Pipeline identity"))
		}
		previousPipelineID = run.PipelineID
	}
	return errors.Join(problems...)
}

func ValidateSubmission(value Submission) error {
	var problems []error
	problems = append(problems, ValidateAdmission(value.Admission))
	if len(value.AuditEvents) != len(value.Admission.Runs)+1 {
		problems = append(problems, errors.New("admission Audit fact count is invalid"))
		return errors.Join(problems...)
	}
	event := value.Admission.Event
	problems = append(problems, validateAuditFact(
		value.AuditEvents[0], auditv1.ActionDevOpsSourceEventAdmitted,
		auditv1.TargetSourceEvent, string(event.ID), event.ContentDigest,
		event.Scope.TenantID, event.ReceivedAt,
	))
	requestID := value.AuditEvents[0].RequestID
	correlationID := value.AuditEvents[0].CorrelationID
	traceParent := value.AuditEvents[0].TraceParent
	for index, run := range value.Admission.Runs {
		if value.AuditEvents[index+1].RequestID != requestID ||
			value.AuditEvents[index+1].CorrelationID != correlationID ||
			value.AuditEvents[index+1].TraceParent != traceParent {
			problems = append(problems, errors.New("admission Audit correlation changed across facts"))
		}
		problems = append(problems, validateAuditFact(
			value.AuditEvents[index+1], auditv1.ActionDevOpsPipelineRunCreated,
			auditv1.TargetPipelineRun, string(run.ID), run.InputDigest,
			run.Scope.TenantID, run.CreatedAt,
		))
	}
	return errors.Join(problems...)
}

func validateAuditFact(
	value auditv1.Event,
	action auditv1.Action,
	targetKind auditv1.TargetKind,
	targetID string,
	requestDigest string,
	tenantID devopsv1.TenantID,
	occurredAt time.Time,
) error {
	if err := auditv1.ValidateEventForSource(auditv1.SourceDevOps, value); err != nil {
		return err
	}
	if value.Actor != (auditv1.ActorReference{Type: auditv1.ActorSystem, ID: sourceIngressActorID}) ||
		value.IAMDecisionID != "" || value.Action != action ||
		value.Target != (auditv1.TargetReference{Kind: targetKind, ID: targetID}) ||
		value.Result != auditv1.ResultAccepted || value.RequestDigest != requestDigest ||
		value.OperationID != auditv1.OperationID(targetID) ||
		value.EventID != admissionAuditEventID(action, targetID) ||
		value.TenantID != auditv1.TenantID(tenantID) || !value.OccurredAt.Equal(occurredAt) {
		return errors.New("admission Audit fact does not bind its target")
	}
	return nil
}

func validateCommand(value Command) error {
	var problems []error
	problems = append(problems,
		domain.ValidateNormalizedChange(value.Change),
		devopsv1.ValidateID("requestId", value.RequestID),
		devopsv1.ValidateID("correlationId", value.CorrelationID),
	)
	if value.TraceParent != "" && (!traceParentPattern.MatchString(value.TraceParent) ||
		value.TraceParent[3:35] == "00000000000000000000000000000000" ||
		value.TraceParent[36:52] == "0000000000000000") {
		problems = append(problems, errors.New("traceparent is invalid"))
	}
	if err := errors.Join(problems...); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	}
	return nil
}
