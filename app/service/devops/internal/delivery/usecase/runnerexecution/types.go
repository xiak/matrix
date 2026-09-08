package runnerexecution

import (
	"errors"
	"time"

	devopsbuildv1 "github.com/xiak/matrix/api/adapter/devopsbuild/v1"
	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/port"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/runnerlog"
)

const (
	RenewalInterval   = 10 * time.Second
	CancellationGrace = 30 * time.Second
	CleanupTimeout    = 10 * time.Second
)

var (
	ErrInvalid        = errors.New("runner execution input is invalid")
	ErrUnavailable    = errors.New("runner execution is unavailable")
	ErrOutcomeUnknown = errors.New("runner execution outcome is unknown")
)

type Result struct {
	Claimed      bool
	ExecutionID  string
	Deferred     bool
	Acknowledged bool
}

func validateEntry(value port.RunnerJournalEntry, runnerID string) error {
	if devopsbuildv1.ValidateAssignment(value.Assignment) != nil ||
		value.EffectID == "" || runnerlog.Validate(value.LogProgress) != nil {
		return ErrInvalid
	}
	for index, step := range value.Steps {
		if step.Ordinal != value.Assignment.Request.Steps[index].Ordinal ||
			step.Kind != value.Assignment.Request.Steps[index].Kind {
			return ErrInvalid
		}
	}
	if value.Receipt != nil &&
		(devopsbuildv1.ValidateReceipt(value.Assignment.Request, *value.Receipt) != nil ||
			value.Receipt.ExecutorID != runnerID) {
		return ErrInvalid
	}
	switch value.Phase {
	case port.RunnerJournalReceived, port.RunnerJournalEffectStarted:
		if value.Receipt != nil {
			return ErrInvalid
		}
	case port.RunnerJournalTerminal, port.RunnerJournalAcknowledged:
		if value.Receipt == nil {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

func receiptFor(
	entry port.RunnerJournalEntry,
	runnerID string,
) (devopsbuildv1.Receipt, error) {
	request := entry.Assignment.Request
	steps := [2]devopsbuildv1.StepReceipt{}
	for index, progress := range entry.Steps {
		conclusion := devopsbuildv1.StepConclusion("")
		switch progress.Phase {
		case port.RunnerStepPending:
			conclusion = devopsbuildv1.StepConclusionNotRun
		case port.RunnerStepPassed:
			conclusion = devopsbuildv1.StepConclusionPassed
		case port.RunnerStepFailed:
			conclusion = devopsbuildv1.StepConclusionFailed
		case port.RunnerStepCancelled:
			conclusion = devopsbuildv1.StepConclusionCancelled
		default:
			return devopsbuildv1.Receipt{}, ErrInvalid
		}
		steps[index] = devopsbuildv1.StepReceipt{
			Ordinal: progress.Ordinal, Kind: progress.Kind, Conclusion: conclusion,
		}
	}
	conclusion := devopsbuildv1.Conclusion("")
	switch {
	case steps[0].Conclusion == devopsbuildv1.StepConclusionFailed ||
		steps[1].Conclusion == devopsbuildv1.StepConclusionFailed:
		conclusion = devopsbuildv1.ConclusionFailed
	case steps[0].Conclusion == devopsbuildv1.StepConclusionCancelled ||
		steps[1].Conclusion == devopsbuildv1.StepConclusionCancelled:
		conclusion = devopsbuildv1.ConclusionCancelled
	case steps[0].Conclusion == devopsbuildv1.StepConclusionPassed &&
		steps[1].Conclusion == devopsbuildv1.StepConclusionPassed:
		conclusion = devopsbuildv1.ConclusionPassed
	default:
		return devopsbuildv1.Receipt{}, ErrInvalid
	}
	receipt := devopsbuildv1.Receipt{
		TenantID: request.TenantID, RunID: request.RunID, CommandID: request.CommandID,
		InputDigest: request.InputDigest, SourceArchiveDigest: request.SourceArchiveDigest,
		PipelineRevisionID:     request.PipelineRevisionID,
		PipelineRevisionDigest: request.PipelineRevisionDigest,
		ExecutorID:             runnerID, ExecutorProfile: request.ExecutorProfile,
		ToolchainImageDigest: request.ToolchainImageDigest,
		Conclusion:           conclusion, Steps: steps,
	}
	receipt.ContentDigest = devopsbuildv1.DigestReceipt(receipt)
	if devopsbuildv1.ValidateReceipt(request, receipt) != nil {
		return devopsbuildv1.Receipt{}, ErrInvalid
	}
	return receipt, nil
}

func nextStep(entry port.RunnerJournalEntry) (int, bool) {
	if entry.Steps[0].Phase == port.RunnerStepPending ||
		entry.Steps[0].Phase == port.RunnerStepStarted {
		return 0, true
	}
	if entry.Steps[0].Phase == port.RunnerStepPassed &&
		(entry.Steps[1].Phase == port.RunnerStepPending ||
			entry.Steps[1].Phase == port.RunnerStepStarted) {
		return 1, true
	}
	return 0, false
}

func terminalSteps(entry port.RunnerJournalEntry) bool {
	if entry.Steps[0].Phase == port.RunnerStepFailed ||
		entry.Steps[0].Phase == port.RunnerStepCancelled {
		return entry.Steps[1].Phase == port.RunnerStepPending
	}
	return entry.Steps[0].Phase == port.RunnerStepPassed &&
		(entry.Steps[1].Phase == port.RunnerStepPassed ||
			entry.Steps[1].Phase == port.RunnerStepFailed ||
			entry.Steps[1].Phase == port.RunnerStepCancelled)
}

func stepConclusion(value port.RunnerSandboxState) (devopsbuildv1.StepConclusion, error) {
	switch value {
	case port.RunnerSandboxPassed:
		return devopsbuildv1.StepConclusionPassed, nil
	case port.RunnerSandboxFailed:
		return devopsbuildv1.StepConclusionFailed, nil
	case port.RunnerSandboxCancelled:
		return devopsbuildv1.StepConclusionCancelled, nil
	default:
		return "", ErrInvalid
	}
}

func boundedDeadline(startedAt, runDeadline time.Time) time.Time {
	stepDeadline := startedAt.Add(
		time.Duration(devopsv1.FixedStepTimeoutSeconds) * time.Second,
	)
	if runDeadline.Before(stepDeadline) {
		return runDeadline
	}
	return stepDeadline
}
