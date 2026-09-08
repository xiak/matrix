package runcontrol

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/domain"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/port"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/runaudit"
)

func (service *Service) Get(ctx context.Context, query GetQuery) (devopsv1.PipelineRun, error) {
	if service == nil || service.repository == nil {
		return devopsv1.PipelineRun{}, errors.New("PipelineRun control service is nil")
	}
	if ctx == nil {
		return devopsv1.PipelineRun{}, errors.New("PipelineRun read context is nil")
	}
	if err := errors.Join(
		devopsv1.ValidatePipelineRunID("runId", query.RunID),
		port.ValidateAuthorizationForRequest(
			query.Authorization, iamv1.ActionDevOpsRunRead, iamv1.ResourcePipelineRun, query.RunID,
		),
	); err != nil {
		return devopsv1.PipelineRun{}, formatInvalid(err)
	}
	var result devopsv1.PipelineRun
	err := service.retry(ctx, query.Authorization.TenantID, func(txCtx context.Context, tx Transaction) error {
		value, found, err := tx.LoadPipelineRun(txCtx, query.RunID)
		if err != nil {
			return err
		}
		if !found {
			return ErrNotFound
		}
		result = value
		return nil
	})
	return result, err
}

func (service *Service) Cancel(ctx context.Context, command CancelCommand) (Result, error) {
	if service == nil || service.repository == nil {
		return Result{}, errors.New("PipelineRun control service is nil")
	}
	if ctx == nil {
		return Result{}, errors.New("PipelineRun cancellation context is nil")
	}
	if err := errors.Join(
		devopsv1.ValidatePipelineRunID("runId", command.RunID),
		port.ValidateAuthorizationForRequest(
			command.Authorization, iamv1.ActionDevOpsRunCancel, iamv1.ResourcePipelineRun, command.RunID,
		),
		validateExpectedVersion(command.ExpectedResourceVersion),
		validateIdempotencyKey(command.IdempotencyKey),
	); err != nil {
		return Result{}, formatInvalid(err)
	}
	fingerprint, err := digestJSON(struct {
		TenantID       devopsv1.TenantID   `json:"tenantId"`
		Subject        devopsv1.SubjectRef `json:"subject"`
		Kind           string              `json:"kind"`
		TargetID       devopsv1.ResourceID `json:"targetId"`
		IdempotencyKey string              `json:"idempotencyKey"`
	}{command.Authorization.TenantID, command.Authorization.Subject, cancellationKind, command.RunID, command.IdempotencyKey})
	if err != nil {
		return Result{}, err
	}
	requestDigest, err := digestJSON(struct {
		Kind                    string              `json:"kind"`
		RunID                   devopsv1.ResourceID `json:"runId"`
		ExpectedResourceVersion uint64              `json:"expectedResourceVersion"`
	}{cancellationKind, command.RunID, command.ExpectedResourceVersion})
	if err != nil {
		return Result{}, err
	}

	var result Result
	err = service.retry(ctx, command.Authorization.TenantID, func(txCtx context.Context, tx Transaction) error {
		stored, found, err := tx.FindCancellation(txCtx, fingerprint)
		if err != nil {
			return err
		}
		if found {
			if err := ValidateStoredCancellation(stored); err != nil {
				return fmt.Errorf("validate stored PipelineRun cancellation: %w", err)
			}
			operation := stored.Operation
			if operation.RunID != command.RunID || operation.RequestedBy != command.Authorization.Subject ||
				operation.IAMAction != command.Authorization.Action || operation.IAMResource != command.Authorization.Resource ||
				operation.ExpectedResourceVersion != command.ExpectedResourceVersion ||
				operation.RequestDigest != requestDigest {
				return ErrIdempotencyConflict
			}
			result = Result{Value: stored.Result, Replayed: true}
			return nil
		}
		now, err := tx.TransactionTime(txCtx)
		if err != nil {
			return err
		}
		current, effectMayExist, found, err := tx.LockPipelineRunForCancellation(txCtx, command.RunID)
		if err != nil {
			return err
		}
		if !found {
			return ErrNotFound
		}
		cancelled, err := domain.RequestPipelineRunCancellation(
			current, command.ExpectedResourceVersion, effectMayExist, now,
		)
		if err != nil {
			return mapDomainError(err)
		}
		operation := CancellationOperation{
			SchemaVersion: "v1", ID: operationID(fingerprint),
			TenantID: command.Authorization.TenantID, Kind: cancellationKind,
			CommandTargetID: command.RunID, RunID: command.RunID,
			RequestedBy: command.Authorization.Subject, IAMDecisionID: command.Authorization.DecisionID,
			IAMAction: command.Authorization.Action, IAMResource: command.Authorization.Resource,
			ExpectedResourceVersion: command.ExpectedResourceVersion,
			IdempotencyFingerprint:  fingerprint, RequestDigest: requestDigest,
			ResultKind: cancellationResultKind,
			Target:     auditv1.TargetReference{Kind: auditv1.TargetPipelineRun, ID: string(command.RunID)},
			RequestID:  command.Authorization.RequestID, CorrelationID: command.Authorization.CorrelationID,
			TraceParent: command.Authorization.TraceParent, CreatedAt: now,
		}
		cancellationEvent := newCancellationEvent(operation)
		submission := Submission{Operation: operation, Result: cancelled, CancellationEvent: cancellationEvent}
		if cancelled.Status.CompletedAt != nil {
			terminal, err := runaudit.NewTerminalEvent(
				cancelled, command.Authorization.RequestID, runaudit.ControlActorID,
			)
			if err != nil {
				return err
			}
			submission.TerminalEvent = &terminal
		}
		if err := ValidateSubmission(submission); err != nil {
			return fmt.Errorf("invalid PipelineRun cancellation submission: %w", err)
		}
		if err := tx.CommitPipelineRunCancellation(
			txCtx, command.ExpectedResourceVersion, submission,
		); err != nil {
			return err
		}
		result = Result{Value: cancelled}
		return nil
	})
	return result, err
}

func (service *Service) Replay(ctx context.Context, command ReplayCommand) (Result, error) {
	if service == nil || service.repository == nil {
		return Result{}, errors.New("PipelineRun control service is nil")
	}
	if ctx == nil {
		return Result{}, errors.New("PipelineRun replay context is nil")
	}
	if err := errors.Join(
		devopsv1.ValidatePipelineRunID("sourceRunId", command.SourceRunID),
		port.ValidateAuthorizationForRequest(
			command.Authorization, iamv1.ActionDevOpsRunReplay,
			iamv1.ResourcePipelineRun, command.SourceRunID,
		),
		validateExpectedVersion(command.ExpectedResourceVersion),
		validateIdempotencyKey(command.IdempotencyKey),
	); err != nil {
		return Result{}, formatInvalid(err)
	}
	fingerprint, err := digestJSON(struct {
		TenantID       devopsv1.TenantID   `json:"tenantId"`
		Subject        devopsv1.SubjectRef `json:"subject"`
		Kind           string              `json:"kind"`
		SourceRunID    devopsv1.ResourceID `json:"sourceRunId"`
		IdempotencyKey string              `json:"idempotencyKey"`
	}{command.Authorization.TenantID, command.Authorization.Subject, replayKind, command.SourceRunID, command.IdempotencyKey})
	if err != nil {
		return Result{}, err
	}
	requestDigest, err := digestJSON(struct {
		Kind                    string              `json:"kind"`
		SourceRunID             devopsv1.ResourceID `json:"sourceRunId"`
		ExpectedResourceVersion uint64              `json:"expectedResourceVersion"`
	}{replayKind, command.SourceRunID, command.ExpectedResourceVersion})
	if err != nil {
		return Result{}, err
	}

	var result Result
	err = service.retry(ctx, command.Authorization.TenantID, func(txCtx context.Context, tx Transaction) error {
		stored, found, err := tx.FindReplay(txCtx, fingerprint)
		if err != nil {
			return err
		}
		if found {
			if err := ValidateStoredReplay(stored); err != nil {
				return fmt.Errorf("validate stored PipelineRun replay: %w", err)
			}
			operation := stored.Operation
			if operation.SourceRunID != command.SourceRunID ||
				operation.RequestedBy != command.Authorization.Subject ||
				operation.IAMAction != command.Authorization.Action ||
				operation.IAMResource != command.Authorization.Resource ||
				operation.ExpectedResourceVersion != command.ExpectedResourceVersion ||
				operation.RequestDigest != requestDigest {
				return ErrIdempotencyConflict
			}
			result = Result{Value: stored.Result, Replayed: true}
			return nil
		}

		source, replayedAt, found, err := tx.LockPipelineRunForReplay(
			txCtx, command.SourceRunID, command.ExpectedResourceVersion,
		)
		if err != nil {
			return err
		}
		if !found {
			return ErrNotFound
		}
		commandID := operationID(fingerprint)
		replayed, err := domain.ReplayPipelineRun(
			source, devopsv1.ResourceID(commandID), command.Authorization.Subject, replayedAt,
		)
		if err != nil {
			return mapDomainError(err)
		}
		operation := ReplayOperation{
			SchemaVersion: "v1", ID: commandID,
			TenantID: command.Authorization.TenantID, Kind: replayKind,
			CommandTargetID: command.SourceRunID, SourceRunID: command.SourceRunID,
			RequestedBy: command.Authorization.Subject, IAMDecisionID: command.Authorization.DecisionID,
			IAMAction: command.Authorization.Action, IAMResource: command.Authorization.Resource,
			ExpectedResourceVersion: command.ExpectedResourceVersion,
			IdempotencyFingerprint:  fingerprint, RequestDigest: requestDigest,
			ResultKind: replayResultKind,
			Target:     auditv1.TargetReference{Kind: auditv1.TargetPipelineRun, ID: string(replayed.ID)},
			RequestID:  command.Authorization.RequestID, CorrelationID: command.Authorization.CorrelationID,
			TraceParent: command.Authorization.TraceParent, CreatedAt: replayedAt,
		}
		submission := ReplaySubmission{
			Operation: operation, Result: replayed, AuditEvent: newReplayEvent(operation),
		}
		if err := ValidateReplaySubmission(submission); err != nil {
			return fmt.Errorf("invalid PipelineRun replay submission: %w", err)
		}
		if err := tx.CommitPipelineRunReplay(
			txCtx, command.ExpectedResourceVersion, submission,
		); err != nil {
			return err
		}
		result = Result{Value: replayed}
		return nil
	})
	return result, err
}

func (service *Service) retry(
	ctx context.Context,
	tenantID devopsv1.TenantID,
	work func(context.Context, Transaction) error,
) error {
	var transactionErr error
	for attempt := 0; attempt < service.config.MaxTransactionAttempts; attempt++ {
		transactionErr = service.repository.WithinRunControlTransaction(ctx, tenantID, work)
		if transactionErr == nil || !errors.Is(transactionErr, ErrRetryableTransaction) {
			return transactionErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	return fmt.Errorf("PipelineRun control transaction attempts exhausted: %w", transactionErr)
}

func newCancellationEvent(operation CancellationOperation) auditv1.Event {
	digest := sha256.Sum256([]byte("matrix-devops-audit-event-v1\x00" + operation.ID))
	return auditv1.Event{
		APIVersion: auditv1.APIVersion, Kind: "AuditEvent",
		EventID:       auditv1.EventID("audit-" + hex.EncodeToString(digest[:])),
		TenantID:      auditv1.TenantID(operation.TenantID),
		Actor:         auditv1.ActorReference{Type: auditv1.ActorType(operation.RequestedBy.Kind), ID: auditv1.ActorID(operation.RequestedBy.ID)},
		IAMDecisionID: auditv1.DecisionID(operation.IAMDecisionID),
		Action:        auditv1.ActionDevOpsPipelineRunCancellationRequested,
		Target:        auditv1.TargetReference{Kind: auditv1.TargetPipelineRun, ID: string(operation.RunID)},
		Result:        auditv1.ResultAccepted,
		RequestDigest: operation.RequestDigest, RequestID: operation.RequestID,
		CorrelationID: operation.CorrelationID, OperationID: auditv1.OperationID(operation.ID),
		TraceParent: operation.TraceParent, OccurredAt: operation.CreatedAt,
	}
}

func newReplayEvent(operation ReplayOperation) auditv1.Event {
	digest := sha256.Sum256([]byte("matrix-devops-audit-event-v1\x00" + operation.ID))
	return auditv1.Event{
		APIVersion: auditv1.APIVersion, Kind: "AuditEvent",
		EventID:       auditv1.EventID("audit-" + hex.EncodeToString(digest[:])),
		TenantID:      auditv1.TenantID(operation.TenantID),
		Actor:         auditv1.ActorReference{Type: auditv1.ActorType(operation.RequestedBy.Kind), ID: auditv1.ActorID(operation.RequestedBy.ID)},
		IAMDecisionID: auditv1.DecisionID(operation.IAMDecisionID),
		Action:        auditv1.ActionDevOpsPipelineRunReplayed,
		Target:        operation.Target,
		Result:        auditv1.ResultAccepted,
		RequestDigest: operation.RequestDigest, RequestID: operation.RequestID,
		CorrelationID: operation.CorrelationID, OperationID: auditv1.OperationID(operation.ID),
		TraceParent: operation.TraceParent, OccurredAt: operation.CreatedAt,
	}
}

func validateExpectedVersion(value uint64) error {
	if value == 0 || value > devopsv1.MaximumContractInteger {
		return errors.New("expected resource version is invalid")
	}
	return nil
}

func validateIdempotencyKey(value string) error {
	if value == "" || len([]byte(value)) > 128 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return errors.New("Idempotency-Key is invalid")
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return errors.New("Idempotency-Key is invalid")
		}
	}
	return nil
}

func digestJSON(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("encode PipelineRun control identity: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func operationID(fingerprint string) string {
	digest := sha256.Sum256([]byte("matrix-devops-operation-v1\x00" + fingerprint))
	return "operation-" + hex.EncodeToString(digest[:])
}

func mapDomainError(err error) error {
	switch {
	case errors.Is(err, domain.ErrVersionConflict), errors.Is(err, domain.ErrVersionExhausted):
		return fmt.Errorf("%w: %v", ErrResourceVersionConflict, err)
	case errors.Is(err, domain.ErrPipelineRunCancellationSet):
		return fmt.Errorf("%w: %v", ErrNoDesiredChange, err)
	case errors.Is(err, domain.ErrPipelineRunTerminal):
		return fmt.Errorf("%w: %v", ErrTerminal, err)
	case errors.Is(err, domain.ErrPipelineRunNotTerminal):
		return fmt.Errorf("%w: %v", ErrNotTerminal, err)
	case errors.Is(err, domain.ErrInvalidPipelineRunTransition), errors.Is(err, domain.ErrInvalidTime):
		return fmt.Errorf("%w: %v", ErrRetryableTransaction, err)
	default:
		return err
	}
}
