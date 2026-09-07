// Package runaudit projects PipelineRun lifecycle facts into Audit's closed
// indefinite-retention contract.
package runaudit

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	devopsv1 "github.com/xiak/matrix/api/devops/v1"
)

const (
	WorkerActorID  = "system-devops-run-worker"
	ControlActorID = "system-devops-run-control"
)

// NewTerminalEvent projects the exact terminal PipelineRun outcome. Callers
// select one closed normalized actor; scheduler instances and host identities
// are deliberately not Audit facts.
func NewTerminalEvent(run devopsv1.PipelineRun, requestID, actorID string) (auditv1.Event, error) {
	if err := devopsv1.ValidatePipelineRun(run); err != nil {
		return auditv1.Event{}, err
	}
	if err := devopsv1.ValidateID("requestId", requestID); err != nil {
		return auditv1.Event{}, err
	}
	if actorID != WorkerActorID && actorID != ControlActorID {
		return auditv1.Event{}, errors.New("PipelineRun terminal Audit actor is invalid")
	}
	if run.Status.CompletedAt == nil {
		return auditv1.Event{}, errors.New("PipelineRun terminal Audit requires a terminal run")
	}
	outcome, reason, err := terminalOutcome(run.Status)
	if err != nil {
		return auditv1.Event{}, err
	}
	operationID := string(run.ID) + ":terminal:" + strconv.FormatUint(run.Status.ResourceVersion, 10)
	eventHash := sha256.Sum256([]byte("matrix-devops-audit-event-v1\x00" + operationID))
	event := auditv1.Event{
		APIVersion: auditv1.APIVersion,
		Kind:       "AuditEvent",
		EventID:    auditv1.EventID("audit-" + hex.EncodeToString(eventHash[:])),
		TenantID:   auditv1.TenantID(run.Scope.TenantID),
		Actor: auditv1.ActorReference{
			Type: auditv1.ActorSystem,
			ID:   auditv1.ActorID(actorID),
		},
		Action: auditv1.ActionDevOpsPipelineRunCompleted,
		Target: auditv1.TargetReference{
			Kind: auditv1.TargetPipelineRun,
			ID:   string(run.ID),
		},
		Result:        auditv1.ResultSucceeded,
		Outcome:       outcome,
		Reason:        reason,
		RequestDigest: run.InputDigest,
		RequestID:     requestID,
		CorrelationID: string(run.ID),
		OperationID:   auditv1.OperationID(operationID),
		OccurredAt:    *run.Status.CompletedAt,
	}
	if err := auditv1.ValidateEventForSource(auditv1.SourceDevOps, event); err != nil {
		return auditv1.Event{}, err
	}
	return event, nil
}

func terminalOutcome(status devopsv1.PipelineRunStatus) (auditv1.Outcome, auditv1.Reason, error) {
	switch status.State {
	case devopsv1.PipelineRunSucceeded:
		return auditv1.OutcomeSucceeded, auditv1.ReasonCompleted, nil
	case devopsv1.PipelineRunFailed:
		return auditv1.OutcomeFailed, auditv1.Reason(status.Reason), nil
	case devopsv1.PipelineRunCancelled:
		return auditv1.OutcomeCancelled, auditv1.ReasonCancelled, nil
	case devopsv1.PipelineRunManualIntervention:
		return auditv1.OutcomeManualIntervention, auditv1.ReasonReconciliationExhausted, nil
	default:
		return "", "", errors.New("PipelineRun terminal Audit requires a closed terminal state")
	}
}
