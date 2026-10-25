package checkreporting

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	devopsbuildv1 "github.com/xiak/matrix/api/adapter/devopsbuild/v1"
	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/domain"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/runlifecycle"
)

func TestReportCommandAndReceiptBindImmutableEvidence(t *testing.T) {
	command := reportCommand(t, runlifecycle.ClaimExecute, false, 0, devopsbuildv1.ConclusionPassed)
	if err := ValidateCommand(command); err != nil {
		t.Fatalf("validate command: %v", err)
	}
	contextName, err := CheckContext(command)
	if err != nil || contextName != "matrix/"+string(command.Lease.Run.PipelineID)+"/"+string(command.Lease.Run.ID) {
		t.Fatalf("context=%q err=%v", contextName, err)
	}
	state, description, err := CheckOutcome(command)
	if err != nil || state != CheckSuccess || description != PassedDescription {
		t.Fatalf("outcome=%q description=%q err=%v", state, description, err)
	}
	receipt, err := NewReceipt(command, 42)
	if err != nil || ValidateReceipt(command, receipt) != nil {
		t.Fatalf("receipt=%#v err=%v", receipt, err)
	}

	tampered := receipt
	tampered.ProviderStatusID++
	if !errors.Is(ValidateReceipt(command, tampered), ErrInvalidReceipt) {
		t.Fatal("tampered provider status was accepted")
	}
	failed := reportCommand(t, runlifecycle.ClaimExecute, false, 0, devopsbuildv1.ConclusionFailed)
	failedDigest, err := RequestDigest(failed)
	if err != nil || failedDigest == receipt.RequestDigest {
		t.Fatalf("failed digest=%q err=%v", failedDigest, err)
	}
}

func TestReporterCreatesOneTerminalCheckAndCompletesRun(t *testing.T) {
	tests := []struct {
		conclusion devopsbuildv1.Conclusion
		state      devopsv1.PipelineRunState
		reason     devopsv1.PipelineRunReason
	}{
		{devopsbuildv1.ConclusionPassed, devopsv1.PipelineRunSucceeded, devopsv1.PipelineRunReasonCompleted},
		{devopsbuildv1.ConclusionFailed, devopsv1.PipelineRunFailed, devopsv1.PipelineRunReasonVerificationFailed},
	}
	for _, test := range tests {
		t.Run(string(test.conclusion), func(t *testing.T) {
			command := reportCommand(t, runlifecycle.ClaimExecute, false, 0, test.conclusion)
			repository := newCheckRepository(command)
			reporter := &fakeReporter{providerStatusID: 42}
			service := checkService(t, repository, reporter)

			result, err := service.ReportOnce(context.Background())
			if err != nil || !result.Claimed || result.CommandID != command.Lease.Intent.CommandID ||
				result.Run.Status.State != test.state || result.Run.Status.Reason != test.reason {
				t.Fatalf("result=%#v err=%v", result, err)
			}
			if reporter.createCalls != 1 || reporter.observeCalls != 0 ||
				repository.completeCalls != 1 || repository.markCalls != 0 ||
				repository.completion.Receipt == nil ||
				ValidateReceipt(command, *repository.completion.Receipt) != nil {
				t.Fatalf(
					"create=%d observe=%d complete=%d mark=%d completion=%#v",
					reporter.createCalls, reporter.observeCalls, repository.completeCalls,
					repository.markCalls, repository.completion,
				)
			}
		})
	}
}

func TestRecoveredReportOnlyObservesDeterministicStatus(t *testing.T) {
	command := reportCommand(t, runlifecycle.ClaimObserve, false, 0, devopsbuildv1.ConclusionPassed)
	repository := newCheckRepository(command)
	reporter := &fakeReporter{providerStatusID: 81, observeFound: true}
	service := checkService(t, repository, reporter)

	result, err := service.ReportOnce(context.Background())
	if err != nil || result.Run.Status.State != devopsv1.PipelineRunSucceeded ||
		reporter.createCalls != 0 || reporter.observeCalls != 1 ||
		repository.completeCalls != 1 {
		t.Fatalf(
			"result=%#v err=%v create=%d observe=%d complete=%d",
			result, err, reporter.createCalls, reporter.observeCalls,
			repository.completeCalls,
		)
	}
}

func TestDefinitiveCreateFailuresCloseWithoutReceipt(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		reason devopsv1.PipelineRunReason
	}{
		{"unavailable", errors.Join(ErrReportUnavailable, errors.New("credential-secret")), devopsv1.PipelineRunReasonReportUnavailable},
		{"conflict", errors.Join(ErrReportConflict, errors.New("provider-response-secret")), devopsv1.PipelineRunReasonReportConflict},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			command := reportCommand(t, runlifecycle.ClaimExecute, false, 0, devopsbuildv1.ConclusionPassed)
			repository := newCheckRepository(command)
			reporter := &fakeReporter{createErr: test.err}

			result, err := checkService(t, repository, reporter).ReportOnce(context.Background())
			if err != nil || result.Run.Status.State != devopsv1.PipelineRunFailed ||
				result.Run.Status.Reason != test.reason || repository.completeCalls != 1 ||
				repository.completion.Receipt != nil || repository.markCalls != 0 {
				t.Fatalf("result=%#v err=%v completion=%#v", result, err, repository.completion)
			}
		})
	}
}

func TestCreateUncertaintyAndMalformedSuccessEnterReconciliation(t *testing.T) {
	tests := []struct {
		name     string
		reporter *fakeReporter
	}{
		{
			"native failure",
			&fakeReporter{createErr: errors.New("native failure contained report-token-secret")},
		},
		{
			"malformed success",
			&fakeReporter{
				providerStatusID: 42,
				mutate: func(receipt *Receipt) {
					receipt.ProviderStatusID++
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			command := reportCommand(t, runlifecycle.ClaimExecute, false, 0, devopsbuildv1.ConclusionPassed)
			repository := newCheckRepository(command)

			result, err := checkService(t, repository, test.reporter).ReportOnce(context.Background())
			if err != nil || result.Run.Status.State != devopsv1.PipelineRunReconciling ||
				result.Run.Status.Reason != devopsv1.PipelineRunReasonExternalEffectUncertain ||
				repository.markCalls != 1 || repository.completeCalls != 0 ||
				test.reporter.createCalls != 1 || test.reporter.observeCalls != 0 {
				t.Fatalf(
					"result=%#v err=%v create=%d mark=%d complete=%d",
					result, err, test.reporter.createCalls, repository.markCalls,
					repository.completeCalls,
				)
			}
		})
	}
}

func TestReconciliationAllowsTenObservationsThenRequiresManualIntervention(t *testing.T) {
	for attempts := uint64(0); attempts < runlifecycle.MaximumReconciliationAttempts; attempts++ {
		command := reportCommand(
			t, runlifecycle.ClaimObserve, true, attempts, devopsbuildv1.ConclusionPassed,
		)
		repository := newCheckRepository(command)
		reporter := &fakeReporter{}

		result, err := checkService(t, repository, reporter).ReportOnce(context.Background())
		if err != nil || result.ReconciliationAttempts != attempts+1 ||
			result.Run.Status.State != devopsv1.PipelineRunReconciling ||
			reporter.observeCalls != 1 || reporter.createCalls != 0 ||
			repository.deferCalls != 1 || repository.completeCalls != 0 {
			t.Fatalf(
				"attempt=%d result=%#v err=%v observe=%d defer=%d complete=%d",
				attempts, result, err, reporter.observeCalls, repository.deferCalls,
				repository.completeCalls,
			)
		}
	}

	command := reportCommand(
		t, runlifecycle.ClaimObserve, true, runlifecycle.MaximumReconciliationAttempts,
		devopsbuildv1.ConclusionPassed,
	)
	repository := newCheckRepository(command)
	reporter := &fakeReporter{}
	result, err := checkService(t, repository, reporter).ReportOnce(context.Background())
	if err != nil || result.Run.Status.State != devopsv1.PipelineRunManualIntervention ||
		result.Run.Status.Reason != devopsv1.PipelineRunReasonReconciliationExhausted ||
		reporter.observeCalls != 0 || reporter.createCalls != 0 ||
		repository.completeCalls != 1 || repository.deferCalls != 0 {
		t.Fatalf(
			"exhausted result=%#v err=%v create=%d observe=%d defer=%d complete=%d",
			result, err, reporter.createCalls, reporter.observeCalls,
			repository.deferCalls, repository.completeCalls,
		)
	}
}

func TestObservationFailureDefersWithoutAnotherCreate(t *testing.T) {
	command := reportCommand(t, runlifecycle.ClaimObserve, true, 3, devopsbuildv1.ConclusionPassed)
	repository := newCheckRepository(command)
	reporter := &fakeReporter{observeErr: ErrReportUnavailable}

	result, err := checkService(t, repository, reporter).ReportOnce(context.Background())
	if err != nil || result.ReconciliationAttempts != 4 || reporter.createCalls != 0 ||
		reporter.observeCalls != 1 || repository.deferCalls != 1 ||
		repository.completeCalls != 0 {
		t.Fatalf(
			"result=%#v err=%v create=%d observe=%d defer=%d complete=%d",
			result, err, reporter.createCalls, reporter.observeCalls,
			repository.deferCalls, repository.completeCalls,
		)
	}
}

func TestCancellationSkipsProviderEffect(t *testing.T) {
	for _, reconciled := range []bool{false, true} {
		mode := runlifecycle.ClaimExecute
		if reconciled {
			mode = runlifecycle.ClaimObserve
		}
		attempts := uint64(0)
		if reconciled {
			attempts = 1
		}
		command := reportCommand(t, mode, reconciled, attempts, devopsbuildv1.ConclusionPassed)
		requestedAt := command.Lease.Run.Status.ObservedAt
		command.Lease.Run.Status.CancellationRequestedAt = &requestedAt
		repository := newCheckRepository(command)
		reporter := &fakeReporter{providerStatusID: 42, observeFound: true}

		result, err := checkService(t, repository, reporter).ReportOnce(context.Background())
		if err != nil || result.Run.Status.State != devopsv1.PipelineRunCancelled ||
			reporter.createCalls != 0 || reporter.observeCalls != 0 ||
			repository.completeCalls != 1 || repository.completion.Receipt != nil {
			t.Fatalf(
				"reconciled=%t result=%#v err=%v create=%d observe=%d completion=%#v",
				reconciled, result, err, reporter.createCalls, reporter.observeCalls,
				repository.completion,
			)
		}
	}
}

func TestInvalidCommandIsRejectedBeforeProviderEffect(t *testing.T) {
	valid := reportCommand(t, runlifecycle.ClaimExecute, false, 0, devopsbuildv1.ConclusionPassed)
	mutations := map[string]func(*Command){
		"tenant": func(command *Command) {
			command.Connection.Metadata.Scope.TenantID = "tenant-other"
		},
		"binding revision": func(command *Command) {
			command.BindingRevision.ContentDigest = "sha256:" + strings.Repeat("f", 64)
		},
		"reporter policy": func(command *Command) {
			command.Revision.Spec.ReporterPolicy = devopsv1.ReporterPolicy("INVALID")
		},
		"build receipt": func(command *Command) {
			command.BuildReceipt.ContentDigest = "sha256:" + strings.Repeat("e", 64)
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			repository := newCheckRepository(candidate)
			reporter := &fakeReporter{providerStatusID: 42}

			_, err := checkService(t, repository, reporter).ReportOnce(context.Background())
			if !errors.Is(err, ErrInvalidCommand) || reporter.createCalls != 0 ||
				reporter.observeCalls != 0 || repository.completeCalls != 0 ||
				repository.markCalls != 0 {
				t.Fatalf(
					"err=%v create=%d observe=%d complete=%d mark=%d",
					err, reporter.createCalls, reporter.observeCalls,
					repository.completeCalls, repository.markCalls,
				)
			}
		})
	}
}

func TestReporterHealthAndClosedConfiguration(t *testing.T) {
	command := reportCommand(t, runlifecycle.ClaimExecute, false, 0, devopsbuildv1.ConclusionPassed)
	repository := newCheckRepository(command)
	reporter := &fakeReporter{}
	valid := Config{
		WorkerID: "check-reporter-one", LeaseDuration: LeaseDuration,
		Deadline: ProviderDeadline, RetryDelay: ReconciliationDelay,
		Now: func() time.Time { return command.Lease.Run.UpdatedAt.Add(time.Second) },
	}
	for name, mutate := range map[string]func(*Config){
		"worker": func(config *Config) { config.WorkerID = "invalid worker" },
		"lease":  func(config *Config) { config.LeaseDuration++ },
		"deadline": func(config *Config) {
			config.Deadline++
		},
		"retry": func(config *Config) { config.RetryDelay++ },
		"clock": func(config *Config) { config.Now = nil },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if _, err := NewService(repository, reporter, candidate); err == nil {
				t.Fatal("open check reporter configuration was accepted")
			}
		})
	}
	service, err := NewService(repository, reporter, valid)
	if err != nil {
		t.Fatal(err)
	}
	observedAt, err := service.Heartbeat(context.Background())
	if err != nil || observedAt != repository.heartbeat {
		t.Fatalf("heartbeat=%s err=%v", observedAt, err)
	}
	readiness, err := service.Readiness(context.Background())
	if err != nil || readiness != repository.readiness {
		t.Fatalf("readiness=%#v err=%v", readiness, err)
	}
}

type fakeCheckRepository struct {
	command       Command
	claimed       bool
	completion    Completion
	completeCalls int
	markCalls     int
	deferCalls    int
	heartbeat     time.Time
	readiness     devopsv1.Readiness
}

func newCheckRepository(command Command) *fakeCheckRepository {
	now := command.Lease.Run.UpdatedAt.Add(time.Second)
	return &fakeCheckRepository{
		command:   command,
		heartbeat: now,
		readiness: devopsv1.Readiness{
			APIVersion: devopsv1.APIVersion, Kind: "Readiness",
			State: devopsv1.ReadinessReady, SchemaVersion: 1, CheckedAt: now,
		},
	}
}

func (repository *fakeCheckRepository) Heartbeat(context.Context, string) (time.Time, error) {
	return repository.heartbeat, nil
}

func (repository *fakeCheckRepository) Claim(
	context.Context,
	string,
	time.Duration,
) (Command, bool, error) {
	if repository.claimed {
		return Command{}, false, nil
	}
	repository.claimed = true
	return repository.command, true, nil
}

func (repository *fakeCheckRepository) Complete(
	_ context.Context,
	completion Completion,
) (devopsv1.PipelineRun, error) {
	repository.completeCalls++
	repository.completion = completion
	return domain.AdvancePipelineRun(
		completion.Command.Lease.Run,
		completion.State,
		completion.Reason,
		completion.Command.Lease.Run.UpdatedAt.Add(time.Microsecond),
	)
}

func (repository *fakeCheckRepository) MarkUncertain(
	_ context.Context,
	reconciliation runlifecycle.Reconciliation,
) (devopsv1.PipelineRun, error) {
	repository.markCalls++
	return domain.AdvancePipelineRun(
		reconciliation.Lease.Run,
		devopsv1.PipelineRunReconciling,
		devopsv1.PipelineRunReasonExternalEffectUncertain,
		reconciliation.Lease.Run.UpdatedAt.Add(time.Microsecond),
	)
}

func (repository *fakeCheckRepository) Defer(
	_ context.Context,
	reconciliation runlifecycle.Reconciliation,
) (uint64, error) {
	repository.deferCalls++
	return reconciliation.Lease.ReconciliationAttempts + 1, nil
}

func (repository *fakeCheckRepository) Readiness(context.Context) (devopsv1.Readiness, error) {
	return repository.readiness, nil
}

type fakeReporter struct {
	providerStatusID uint64
	createErr        error
	observeErr       error
	observeFound     bool
	mutate           func(*Receipt)
	createCalls      int
	observeCalls     int
}

func (reporter *fakeReporter) Create(
	_ context.Context,
	command Command,
) (Receipt, error) {
	reporter.createCalls++
	if reporter.createErr != nil {
		return Receipt{}, reporter.createErr
	}
	return reporter.receipt(command)
}

func (reporter *fakeReporter) Observe(
	_ context.Context,
	command Command,
) (Receipt, bool, error) {
	reporter.observeCalls++
	if reporter.observeErr != nil {
		return Receipt{}, false, reporter.observeErr
	}
	if !reporter.observeFound {
		return Receipt{}, false, nil
	}
	receipt, err := reporter.receipt(command)
	return receipt, err == nil, err
}

func (reporter *fakeReporter) receipt(command Command) (Receipt, error) {
	providerStatusID := reporter.providerStatusID
	if providerStatusID == 0 {
		providerStatusID = 42
	}
	receipt, err := NewReceipt(command, providerStatusID)
	if err != nil {
		return Receipt{}, err
	}
	if reporter.mutate != nil {
		reporter.mutate(&receipt)
	}
	return receipt, nil
}

func checkService(
	t *testing.T,
	repository Repository,
	reporter Reporter,
) *Service {
	t.Helper()
	command := repository.(*fakeCheckRepository).command
	service, err := NewService(repository, reporter, Config{
		WorkerID: "check-reporter-one", LeaseDuration: LeaseDuration,
		Deadline: ProviderDeadline, RetryDelay: ReconciliationDelay,
		Now: func() time.Time { return command.Lease.Run.UpdatedAt.Add(time.Second) },
	})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func reportCommand(
	t *testing.T,
	mode runlifecycle.ClaimMode,
	reconciled bool,
	reconciliationAttempts uint64,
	conclusion devopsbuildv1.Conclusion,
) Command {
	t.Helper()
	base := time.Date(2026, 9, 8, 1, 2, 3, 0, time.UTC)
	scope := devopsv1.ResourceScope{TenantID: "organization-acme"}
	project, err := domain.NewDevOpsProject(devopsv1.CreateDevOpsProjectRequest{
		ID: "devops-project-platform", Name: "platform",
	}, scope, base)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := domain.NewSourceConnection(devopsv1.CreateSourceConnectionRequest{
		ID: "source-connection-primary", Name: "primary",
		Spec: devopsv1.SourceConnectionSpec{
			AdapterID: "source-adapter-gitea-v1", EndpointOrigin: "https://git.example.com",
			WebhookSecretRef: "webhook-secret", FetchCredentialRef: "fetch-secret",
			ReportCredentialRef: "report-secret",
		},
	}, scope, base)
	if err != nil {
		t.Fatal(err)
	}
	connection.Status.Health = devopsv1.SourceConnectionReady
	connection.Status.Reason = devopsv1.SourceConnectionReasonObserved
	binding, err := domain.NewRepositoryBinding(devopsv1.CreateRepositoryBindingRequest{
		ID: "repository-binding-api", Name: "api", ProjectID: project.Metadata.ID,
		Spec: devopsv1.RepositoryBindingSpec{
			SourceConnectionID: connection.Metadata.ID, ExternalRepositoryID: "42",
			RepositoryPath: "platform/api", TrustedDefaultBranch: "main",
		},
	}, project, connection, base)
	if err != nil {
		t.Fatal(err)
	}
	binding.Status.Health = devopsv1.RepositoryBindingReady
	binding.Status.Reason = devopsv1.RepositoryBindingReasonObserved
	pipeline, err := domain.NewPipeline(devopsv1.CreatePipelineRequest{
		ID: "pipeline-check", Name: "pipeline-check", ProjectID: project.Metadata.ID,
		Draft: devopsv1.PipelineDraftSpec{
			RepositoryBindingID: binding.Metadata.ID, TriggerPolicy: devopsv1.TriggerChange,
			VerificationProfile: devopsv1.VerificationGo126OfflineV1,
			DependencyEgress:    devopsv1.DependencyEgressNone,
			ReporterPolicy:      devopsv1.ReporterChangeCheckV1,
		},
	}, project, binding, base)
	if err != nil {
		t.Fatal(err)
	}
	activation, err := domain.ActivatePipeline(
		pipeline,
		pipeline.Metadata.ResourceVersion,
		devopsv1.SubjectRef{Kind: devopsv1.SubjectUser, ID: "user-alice"},
		binding,
		base.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	event, err := domain.NewSourceEvent(domain.NormalizedChange{
		Scope: scope, SourceConnectionID: connection.Metadata.ID,
		VerifiedSourceConnectionVersion: connection.Metadata.ResourceVersion,
		ExternalRepositoryID:            binding.Spec.ExternalRepositoryID,
		TrustedBaseBranch:               binding.Spec.TrustedDefaultBranch,
		DeliveryID:                      "123e4567-e89b-42d3-a456-426614174000",
		CanonicalPayloadDigest:          "sha256:" + strings.Repeat("a", 64),
		Change: devopsv1.ChangeIdentity{
			Number: 42, Action: devopsv1.ChangeOpened,
			HeadCommit: strings.Repeat("1", 40), TrustedBaseCommit: strings.Repeat("2", 40),
		},
	}, connection, binding, base.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	run, err := domain.NewPipelineRun(event, activation.Pipeline, activation.Revision)
	if err != nil {
		t.Fatal(err)
	}
	for _, state := range []devopsv1.PipelineRunState{
		devopsv1.PipelineRunFetching,
		devopsv1.PipelineRunVerifying,
		devopsv1.PipelineRunReporting,
	} {
		run, err = domain.AdvancePipelineRun(run, state, "", run.UpdatedAt.Add(time.Microsecond))
		if err != nil {
			t.Fatal(err)
		}
	}
	if reconciled {
		run, err = domain.AdvancePipelineRun(
			run,
			devopsv1.PipelineRunReconciling,
			devopsv1.PipelineRunReasonExternalEffectUncertain,
			run.UpdatedAt.Add(time.Microsecond),
		)
		if err != nil {
			t.Fatal(err)
		}
	}
	steps := devopsv1.FixedVerificationSteps()
	stepConclusions := [2]devopsbuildv1.StepConclusion{
		devopsbuildv1.StepConclusionPassed,
		devopsbuildv1.StepConclusionPassed,
	}
	if conclusion == devopsbuildv1.ConclusionFailed {
		stepConclusions[1] = devopsbuildv1.StepConclusionFailed
	}
	buildReceipt := devopsbuildv1.Receipt{
		TenantID: scope.TenantID, RunID: run.ID,
		CommandID:              runlifecycle.TaskCommandID(run.ID, devopsv1.PipelineRunStageVerify, 1),
		InputDigest:            run.InputDigest,
		SourceArchiveDigest:    "sha256:" + strings.Repeat("6", 64),
		PipelineRevisionID:     activation.Revision.ID,
		PipelineRevisionDigest: activation.Revision.ContentDigest,
		ExecutorID:             "executor-one",
		ExecutorProfile:        devopsv1.ExecutorMatrixNativeIsolatedV1,
		ToolchainImageDigest:   devopsv1.Go126OfflineToolchainImageDigest,
		Conclusion:             conclusion,
		Steps: [2]devopsbuildv1.StepReceipt{
			{Ordinal: steps[0].Ordinal, Kind: steps[0].Kind, Conclusion: stepConclusions[0]},
			{Ordinal: steps[1].Ordinal, Kind: steps[1].Kind, Conclusion: stepConclusions[1]},
		},
	}
	buildReceipt.ContentDigest = devopsbuildv1.DigestReceipt(buildReceipt)
	intent := runlifecycle.TaskIntent{
		RunID: run.ID, InputDigest: run.InputDigest,
		Stage: devopsv1.PipelineRunStageReport, Attempt: 1,
	}
	intent.CommandID = runlifecycle.TaskCommandID(intent.RunID, intent.Stage, intent.Attempt)
	fence := uint64(1)
	if mode == runlifecycle.ClaimObserve {
		fence = 2
	}
	return Command{
		Lease: runlifecycle.Lease{
			TenantID: scope.TenantID, Run: run, Intent: intent, Mode: mode,
			WorkerID: "check-reporter-one", FencingToken: fence,
			LeaseExpiresAt:         run.UpdatedAt.Add(LeaseDuration),
			ReconciliationAttempts: reconciliationAttempts,
		},
		Connection: connection, BindingRevision: binding,
		Revision: activation.Revision, BuildReceipt: buildReceipt,
	}
}
