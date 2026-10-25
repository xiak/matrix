package runadmission

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/domain"
)

func (usecase *Usecase) Admit(ctx context.Context, command Command) (Result, error) {
	if usecase == nil || usecase.repository == nil {
		return Result{}, errors.New("run admission use case is nil")
	}
	if ctx == nil {
		return Result{}, errors.New("run admission context is nil")
	}
	if err := validateCommand(command); err != nil {
		return Result{}, err
	}
	eventID, err := devopsv1.SourceEventID(
		command.Change.Scope,
		command.Change.SourceConnectionID,
		command.Change.DeliveryID,
	)
	if err != nil {
		return Result{}, fmt.Errorf("derive SourceEvent identity: %w", err)
	}

	var result Result
	var transactionErr error
	for attempt := 0; attempt < usecase.config.MaxTransactionAttempts; attempt++ {
		result = Result{}
		transactionErr = usecase.repository.WithinAdmissionTransaction(
			ctx,
			command.Change.Scope.TenantID,
			func(txCtx context.Context, tx Transaction) error {
				stored, found, err := tx.LoadAdmission(txCtx, eventID)
				if err != nil {
					return err
				}
				if found {
					if err := ValidateAdmission(stored); err != nil {
						return fmt.Errorf("validate stored run admission: %w", err)
					}
					if err := domain.ValidateSourceEventReplay(stored.Event, command.Change); err != nil {
						return ErrReplayConflict
					}
					result = Result{Admission: stored, Replayed: true}
					return nil
				}

				now, err := tx.TransactionTime(txCtx)
				if err != nil {
					return err
				}
				connection, found, err := tx.LoadSourceConnection(txCtx, command.Change.SourceConnectionID)
				if err != nil || !found {
					return missing(err)
				}
				binding, found, err := tx.LoadRepositoryBindingForSource(
					txCtx,
					command.Change.SourceConnectionID,
					command.Change.ExternalRepositoryID,
				)
				if err != nil || !found {
					return missing(err)
				}
				event, err := domain.NewSourceEvent(command.Change, connection, binding, now)
				if err != nil {
					return mapDomainError(err)
				}
				activations, err := tx.LoadMatchingActiveRevisions(
					txCtx,
					event.Spec.RepositoryBindingID,
					event.Spec.RepositoryBindingDigest,
				)
				if err != nil {
					return err
				}
				sort.Slice(activations, func(first, second int) bool {
					return activations[first].Pipeline.Metadata.ID < activations[second].Pipeline.Metadata.ID
				})
				runs := make([]devopsv1.PipelineRun, len(activations))
				for index, activation := range activations {
					run, err := domain.NewPipelineRun(event, activation.Pipeline, activation.Revision)
					if err != nil {
						return mapDomainError(err)
					}
					runs[index] = run
				}
				queued, err := tx.QueuedRunCount(txCtx)
				if err != nil {
					return err
				}
				if queued > MaximumQueuedRuns || uint64(len(runs)) > MaximumQueuedRuns-queued {
					return ErrQueueCapacityExceeded
				}

				admission := Admission{Event: event, Runs: runs}
				submission := Submission{
					Admission:   admission,
					AuditEvents: newAuditEvents(admission, command),
				}
				if err := ValidateSubmission(submission); err != nil {
					return fmt.Errorf("invalid run admission submission: %w", err)
				}
				if err := tx.CommitAdmission(txCtx, submission); err != nil {
					return err
				}
				result = Result{Admission: admission}
				return nil
			},
		)
		if transactionErr == nil {
			return result, nil
		}
		if !errors.Is(transactionErr, ErrRetryableTransaction) {
			return Result{}, transactionErr
		}
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
	}
	return Result{}, fmt.Errorf("run admission transaction attempts exhausted: %w", transactionErr)
}

func newAuditEvents(admission Admission, command Command) []auditv1.Event {
	events := make([]auditv1.Event, 0, len(admission.Runs)+1)
	events = append(events, newAuditEvent(
		auditv1.ActionDevOpsSourceEventAdmitted,
		auditv1.TargetSourceEvent,
		admission.Event.ID,
		admission.Event.ContentDigest,
		admission.Event.Scope.TenantID,
		admission.Event.ReceivedAt,
		command,
	))
	for _, run := range admission.Runs {
		events = append(events, newAuditEvent(
			auditv1.ActionDevOpsPipelineRunCreated,
			auditv1.TargetPipelineRun,
			run.ID,
			run.InputDigest,
			run.Scope.TenantID,
			run.CreatedAt,
			command,
		))
	}
	return events
}

func newAuditEvent(
	action auditv1.Action,
	targetKind auditv1.TargetKind,
	targetID devopsv1.ResourceID,
	requestDigest string,
	tenantID devopsv1.TenantID,
	occurredAt time.Time,
	command Command,
) auditv1.Event {
	return auditv1.Event{
		APIVersion: auditv1.APIVersion,
		Kind:       "AuditEvent",
		EventID:    admissionAuditEventID(action, string(targetID)),
		TenantID:   auditv1.TenantID(tenantID),
		Actor: auditv1.ActorReference{
			Type: auditv1.ActorSystem,
			ID:   sourceIngressActorID,
		},
		Action:        action,
		Target:        auditv1.TargetReference{Kind: targetKind, ID: string(targetID)},
		Result:        auditv1.ResultAccepted,
		RequestDigest: requestDigest,
		RequestID:     command.RequestID,
		CorrelationID: command.CorrelationID,
		OperationID:   auditv1.OperationID(targetID),
		TraceParent:   command.TraceParent,
		OccurredAt:    occurredAt,
	}
}

func admissionAuditEventID(action auditv1.Action, targetID string) auditv1.EventID {
	digest := sha256.Sum256([]byte("matrix-devops-admission-audit-v1\x00" + string(action) + "\x00" + targetID))
	return auditv1.EventID("audit-" + hex.EncodeToString(digest[:]))
}

func missing(err error) error {
	if err != nil {
		return err
	}
	return ErrPreconditionFailed
}

func mapDomainError(err error) error {
	switch {
	case errors.Is(err, domain.ErrSourceNotReady),
		errors.Is(err, domain.ErrPipelineNotActive),
		errors.Is(err, domain.ErrReferenceMismatch):
		return fmt.Errorf("%w: %v", ErrPreconditionFailed, err)
	case errors.Is(err, domain.ErrInvalidTime):
		return fmt.Errorf("%w: %v", ErrRetryableTransaction, err)
	case errors.Is(err, domain.ErrSourceEventReplayChanged):
		return fmt.Errorf("%w: %v", ErrReplayConflict, err)
	default:
		return err
	}
}
