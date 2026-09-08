package port

import (
	"context"
	"io"
	"time"

	devopsbuildv1 "github.com/xiak/matrix/api/adapter/devopsbuild/v1"
	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/runnerlog"
)

type RunnerJournalPhase string
type RunnerStepPhase string

const (
	RunnerJournalReceived      RunnerJournalPhase = "RECEIVED"
	RunnerJournalEffectStarted RunnerJournalPhase = "EFFECT_STARTED"
	RunnerJournalTerminal      RunnerJournalPhase = "TERMINAL"
	RunnerJournalAcknowledged  RunnerJournalPhase = "ACKNOWLEDGED"
)

const (
	RunnerStepPending   RunnerStepPhase = "PENDING"
	RunnerStepStarted   RunnerStepPhase = "STARTED"
	RunnerStepPassed    RunnerStepPhase = "PASSED"
	RunnerStepFailed    RunnerStepPhase = "FAILED"
	RunnerStepCancelled RunnerStepPhase = "CANCELLED"
)

type RunnerStepProgress struct {
	Ordinal   uint32
	Kind      devopsv1.VerificationStepKind
	Phase     RunnerStepPhase
	StartedAt time.Time
}

type RunnerJournalEntry struct {
	Assignment            devopsbuildv1.Assignment
	Phase                 RunnerJournalPhase
	EffectID              string
	CancellationRequested bool
	Steps                 [2]RunnerStepProgress
	LogProgress           runnerlog.Progress
	Receipt               *devopsbuildv1.Receipt
}

type RunnerClaim interface {
	Destination(devopsbuildv1.Assignment) (io.Writer, error)
	Commit(context.Context) (RunnerJournalEntry, error)
	Abort() error
}

type RunnerJournal interface {
	RunnerID() string
	BeginClaim(context.Context) (RunnerClaim, error)
	Entries(context.Context) ([]RunnerJournalEntry, error)
	MarkEffectStarted(
		context.Context, devopsbuildv1.Assignment, time.Time,
	) (RunnerJournalEntry, error)
	ApplyRenewal(
		context.Context, devopsbuildv1.Assignment, devopsbuildv1.Renewal,
	) (RunnerJournalEntry, error)
	MarkStepStarted(
		context.Context, devopsbuildv1.Assignment, devopsv1.VerificationStep, time.Time,
	) (RunnerJournalEntry, error)
	RecordStepConclusion(
		context.Context,
		devopsbuildv1.Assignment,
		devopsv1.VerificationStep,
		devopsbuildv1.StepConclusion,
		runnerlog.Progress,
	) (RunnerJournalEntry, error)
	RecordReceipt(
		context.Context, devopsbuildv1.Assignment, devopsbuildv1.Receipt,
	) (RunnerJournalEntry, error)
	Acknowledge(
		context.Context, devopsbuildv1.Assignment, devopsbuildv1.Receipt,
	) (RunnerJournalEntry, error)
	OpenArchive(context.Context, string) (io.ReadCloser, error)
}

type RunnerGateway interface {
	RunnerID() string
	Claim(
		context.Context, devopsbuildv1.AssignmentDestination,
	) (devopsbuildv1.Assignment, bool, error)
	Renew(
		context.Context, devopsbuildv1.Assignment,
	) (devopsbuildv1.Renewal, error)
	Complete(
		context.Context, devopsbuildv1.Assignment, devopsbuildv1.Receipt,
	) error
}

type RunnerWorkspace struct {
	ExecutionID string
	TreeDigest  string
	SourceRoot  string
}

type RunnerWorkspaceStore interface {
	Ensure(
		context.Context, string, devopsbuildv1.Request, io.ReadCloser,
	) (RunnerWorkspace, error)
}

type RunnerStepReference struct {
	EffectID   string
	Step       devopsv1.VerificationStep
	SourceRoot string
}

type RunnerSandboxState string

const (
	RunnerSandboxAbsent    RunnerSandboxState = "ABSENT"
	RunnerSandboxCreated   RunnerSandboxState = "CREATED"
	RunnerSandboxRunning   RunnerSandboxState = "RUNNING"
	RunnerSandboxPassed    RunnerSandboxState = "PASSED"
	RunnerSandboxFailed    RunnerSandboxState = "FAILED"
	RunnerSandboxCancelled RunnerSandboxState = "CANCELLED"
)

type RunnerSandboxResult struct {
	State       RunnerSandboxState
	Chunks      []runnerlog.Chunk
	LogProgress runnerlog.Progress
}

type RunnerSandbox interface {
	Create(context.Context, RunnerStepReference) error
	Start(context.Context, RunnerStepReference) error
	Observe(context.Context, RunnerStepReference) (RunnerSandboxState, error)
	Follow(
		context.Context, RunnerStepReference, runnerlog.Progress,
	) (RunnerSandboxResult, error)
	Cancel(context.Context, RunnerStepReference) (RunnerSandboxState, error)
	Delete(context.Context, RunnerStepReference) error
}

type RunnerLogPublisher interface {
	// Publish durably accepts a tenant-leading sequence batch. An exact replay
	// must succeed without duplication, while changed content for an existing
	// sequence must fail closed.
	Publish(
		context.Context,
		devopsbuildv1.Assignment,
		devopsv1.VerificationStep,
		[]runnerlog.Chunk,
	) error
}
