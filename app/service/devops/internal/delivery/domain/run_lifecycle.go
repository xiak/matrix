package domain

import (
	"errors"
	"fmt"
	"time"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
)

var (
	ErrPipelineRunTerminal          = errors.New("PipelineRun is terminal")
	ErrInvalidPipelineRunTransition = errors.New("PipelineRun transition is invalid")
	ErrPipelineRunCancellationSet   = errors.New("PipelineRun cancellation is already requested")
)

// AdvancePipelineRun applies one durable, externally visible state change.
// Lease changes and observation attempts are deliberately absent: they are
// worker coordination, not public PipelineRun status.
func AdvancePipelineRun(
	current devopsv1.PipelineRun,
	nextState devopsv1.PipelineRunState,
	reason devopsv1.PipelineRunReason,
	observedAt time.Time,
) (devopsv1.PipelineRun, error) {
	if err := devopsv1.ValidatePipelineRun(current); err != nil {
		return devopsv1.PipelineRun{}, fmt.Errorf("validate current PipelineRun: %w", err)
	}
	if err := ValidatePipelineRunTransition(current.Status.State, nextState, reason); err != nil {
		return devopsv1.PipelineRun{}, err
	}
	if current.Status.CancellationRequestedAt != nil &&
		!terminalPipelineRunState(nextState) && nextState != devopsv1.PipelineRunReconciling {
		return devopsv1.PipelineRun{}, fmt.Errorf(
			"%w: cancellation prevents future stages",
			ErrInvalidPipelineRunTransition,
		)
	}
	if err := validateRunTransitionTime(current.UpdatedAt, observedAt); err != nil {
		return devopsv1.PipelineRun{}, err
	}
	if current.Status.ResourceVersion >= devopsv1.MaximumContractInteger {
		return devopsv1.PipelineRun{}, fmt.Errorf(
			"%w: PipelineRun resource version is exhausted",
			ErrInvalidPipelineRunTransition,
		)
	}

	next := current
	next.Status.State = nextState
	next.Status.Stage = transitionStage(current.Status.Stage, nextState)
	next.Status.Reason = reason
	next.Status.ResourceVersion++
	next.Status.ObservedAt = observedAt
	next.Status.CompletedAt = nil
	next.UpdatedAt = observedAt
	if terminalPipelineRunState(nextState) {
		completedAt := observedAt
		next.Status.CompletedAt = &completedAt
	}
	if err := devopsv1.ValidatePipelineRun(next); err != nil {
		return devopsv1.PipelineRun{}, fmt.Errorf(
			"%w: resulting PipelineRun is invalid: %v",
			ErrInvalidPipelineRunTransition,
			err,
		)
	}
	return next, nil
}

// RequestPipelineRunCancellation records the public request first. It closes
// the run immediately only when the transaction proves that no command intent
// can have an external effect; otherwise the current intent must be observed.
func RequestPipelineRunCancellation(
	current devopsv1.PipelineRun,
	expectedResourceVersion uint64,
	effectMayExist bool,
	requestedAt time.Time,
) (devopsv1.PipelineRun, error) {
	if err := devopsv1.ValidatePipelineRun(current); err != nil {
		return devopsv1.PipelineRun{}, fmt.Errorf("validate current PipelineRun: %w", err)
	}
	if terminalPipelineRunState(current.Status.State) {
		return devopsv1.PipelineRun{}, ErrPipelineRunTerminal
	}
	if current.Status.ResourceVersion != expectedResourceVersion {
		return devopsv1.PipelineRun{}, ErrVersionConflict
	}
	if current.Status.CancellationRequestedAt != nil {
		return devopsv1.PipelineRun{}, ErrPipelineRunCancellationSet
	}
	if current.Status.ResourceVersion >= devopsv1.MaximumContractInteger {
		return devopsv1.PipelineRun{}, ErrVersionExhausted
	}
	if err := validateRunTransitionTime(current.UpdatedAt, requestedAt); err != nil {
		return devopsv1.PipelineRun{}, err
	}
	if effectMayExist && current.Status.State == devopsv1.PipelineRunQueued {
		return devopsv1.PipelineRun{}, fmt.Errorf(
			"%w: queued PipelineRun cannot have an external effect",
			ErrInvalidPipelineRunTransition,
		)
	}
	if !effectMayExist && current.Status.State == devopsv1.PipelineRunReconciling {
		return devopsv1.PipelineRun{}, fmt.Errorf(
			"%w: reconciling PipelineRun must retain its uncertain intent",
			ErrInvalidPipelineRunTransition,
		)
	}

	next := current
	next.Status.ResourceVersion++
	next.Status.ObservedAt = requestedAt
	next.Status.CancellationRequestedAt = &requestedAt
	next.UpdatedAt = requestedAt
	if !effectMayExist {
		next.Status.State = devopsv1.PipelineRunCancelled
		next.Status.Reason = devopsv1.PipelineRunReasonCancelled
		next.Status.CompletedAt = &requestedAt
	}
	if err := devopsv1.ValidatePipelineRun(next); err != nil {
		return devopsv1.PipelineRun{}, fmt.Errorf(
			"%w: resulting cancellation state is invalid: %v",
			ErrInvalidPipelineRunTransition,
			err,
		)
	}
	return next, nil
}

// ValidatePipelineRunTransition is the single provider- and executor-neutral
// state graph used by both in-memory workflow tests and persistence adapters.
func ValidatePipelineRunTransition(
	current devopsv1.PipelineRunState,
	next devopsv1.PipelineRunState,
	reason devopsv1.PipelineRunReason,
) error {
	if terminalPipelineRunState(current) {
		return ErrPipelineRunTerminal
	}
	if !transitionTargetAllowed(current, next) || !transitionReasonAllowed(current, next, reason) {
		return fmt.Errorf(
			"%w: %s cannot advance to %s with reason %s",
			ErrInvalidPipelineRunTransition,
			current,
			next,
			reason,
		)
	}
	return nil
}

func transitionTargetAllowed(current, next devopsv1.PipelineRunState) bool {
	switch current {
	case devopsv1.PipelineRunQueued:
		return next == devopsv1.PipelineRunFetching ||
			next == devopsv1.PipelineRunFailed ||
			next == devopsv1.PipelineRunCancelled
	case devopsv1.PipelineRunFetching:
		return next == devopsv1.PipelineRunVerifying ||
			next == devopsv1.PipelineRunFailed ||
			next == devopsv1.PipelineRunCancelled
	case devopsv1.PipelineRunVerifying:
		return next == devopsv1.PipelineRunReporting ||
			next == devopsv1.PipelineRunFailed ||
			next == devopsv1.PipelineRunCancelled
	case devopsv1.PipelineRunReporting:
		return next == devopsv1.PipelineRunSucceeded ||
			next == devopsv1.PipelineRunFailed ||
			next == devopsv1.PipelineRunCancelled ||
			next == devopsv1.PipelineRunReconciling
	case devopsv1.PipelineRunReconciling:
		return next == devopsv1.PipelineRunSucceeded ||
			next == devopsv1.PipelineRunFailed ||
			next == devopsv1.PipelineRunCancelled ||
			next == devopsv1.PipelineRunManualIntervention
	default:
		return false
	}
}

func transitionReasonAllowed(
	current, next devopsv1.PipelineRunState,
	reason devopsv1.PipelineRunReason,
) bool {
	switch next {
	case devopsv1.PipelineRunFetching,
		devopsv1.PipelineRunVerifying,
		devopsv1.PipelineRunReporting:
		return reason == ""
	case devopsv1.PipelineRunSucceeded:
		return reason == devopsv1.PipelineRunReasonCompleted
	case devopsv1.PipelineRunCancelled:
		return reason == devopsv1.PipelineRunReasonCancelled
	case devopsv1.PipelineRunReconciling:
		return reason == devopsv1.PipelineRunReasonExternalEffectUncertain
	case devopsv1.PipelineRunManualIntervention:
		return reason == devopsv1.PipelineRunReasonReconciliationExhausted
	case devopsv1.PipelineRunFailed:
		return failureReasonAllowed(current, reason)
	default:
		return false
	}
}

func failureReasonAllowed(
	current devopsv1.PipelineRunState,
	reason devopsv1.PipelineRunReason,
) bool {
	switch current {
	case devopsv1.PipelineRunQueued:
		return reason == devopsv1.PipelineRunReasonDeadlineExceeded
	case devopsv1.PipelineRunFetching:
		return reason == devopsv1.PipelineRunReasonSourceUnavailable ||
			reason == devopsv1.PipelineRunReasonCommitMismatch ||
			reason == devopsv1.PipelineRunReasonDeadlineExceeded
	case devopsv1.PipelineRunVerifying:
		return reason == devopsv1.PipelineRunReasonExecutorUnavailable ||
			reason == devopsv1.PipelineRunReasonVerificationFailed ||
			reason == devopsv1.PipelineRunReasonDeadlineExceeded
	case devopsv1.PipelineRunReporting, devopsv1.PipelineRunReconciling:
		return reason == devopsv1.PipelineRunReasonVerificationFailed ||
			reason == devopsv1.PipelineRunReasonReportUnavailable ||
			reason == devopsv1.PipelineRunReasonReportConflict ||
			reason == devopsv1.PipelineRunReasonDeadlineExceeded
	default:
		return false
	}
}

func transitionStage(
	current devopsv1.PipelineRunStage,
	next devopsv1.PipelineRunState,
) devopsv1.PipelineRunStage {
	switch next {
	case devopsv1.PipelineRunFetching:
		return devopsv1.PipelineRunStageFetch
	case devopsv1.PipelineRunVerifying:
		return devopsv1.PipelineRunStageVerify
	case devopsv1.PipelineRunReporting,
		devopsv1.PipelineRunSucceeded,
		devopsv1.PipelineRunReconciling,
		devopsv1.PipelineRunManualIntervention:
		return devopsv1.PipelineRunStageReport
	default:
		return current
	}
}

func terminalPipelineRunState(value devopsv1.PipelineRunState) bool {
	switch value {
	case devopsv1.PipelineRunSucceeded,
		devopsv1.PipelineRunFailed,
		devopsv1.PipelineRunCancelled,
		devopsv1.PipelineRunManualIntervention:
		return true
	default:
		return false
	}
}

func validateRunTransitionTime(current, next time.Time) error {
	if next.IsZero() || next.Location() != time.UTC || next != next.Round(0) ||
		next.Nanosecond()%1_000 != 0 || !next.After(current) {
		return fmt.Errorf(
			"%w: observation time must be increasing canonical UTC microseconds",
			ErrInvalidPipelineRunTransition,
		)
	}
	return nil
}
