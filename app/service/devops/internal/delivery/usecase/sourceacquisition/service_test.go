package sourceacquisition

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/domain"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/runlifecycle"
)

func TestFetcherPublishesAndAtomicallyCompletesExecuteClaim(t *testing.T) {
	command := sourceCommand(t, runlifecycle.ClaimExecute)
	repository := newFakeRepository(command)
	fetcher := &fakeFetcher{payload: []byte("deterministic archive")}
	store := &fakeArchiveStore{}
	service := sourceService(t, repository, fetcher, store)

	result, err := service.FetchOnce(context.Background())
	if err != nil || !result.Claimed || result.CommandID != command.Lease.Intent.CommandID ||
		result.Run.Status.State != devopsv1.PipelineRunVerifying {
		t.Fatalf("fetch result=%#v err=%v", result, err)
	}
	if fetcher.calls != 1 || store.publishCalls != 1 || store.observeCalls != 0 ||
		repository.completeCalls != 1 || repository.completion.Receipt == nil {
		t.Fatalf(
			"calls fetch=%d publish=%d observe=%d complete=%d completion=%#v",
			fetcher.calls, store.publishCalls, store.observeCalls,
			repository.completeCalls, repository.completion,
		)
	}
	if err := ValidateReceipt(command, *repository.completion.Receipt); err != nil {
		t.Fatalf("completed receipt: %v", err)
	}
}

func TestTakeoverObservesOnlyAndNeverContactsSource(t *testing.T) {
	command := sourceCommand(t, runlifecycle.ClaimObserve)
	receipt := testReceipt(command, []byte("already published"), ArchiveContent{
		ExpandedBytes: 17, PathCount: 1,
	})
	repository := newFakeRepository(command)
	fetcher := &fakeFetcher{err: errors.New("must not fetch")}
	store := &fakeArchiveStore{observed: receipt, observedFound: true}
	service := sourceService(t, repository, fetcher, store)

	result, err := service.FetchOnce(context.Background())
	if err != nil || result.Run.Status.State != devopsv1.PipelineRunVerifying ||
		fetcher.calls != 0 || store.publishCalls != 0 || store.observeCalls != 1 {
		t.Fatalf(
			"takeover result=%#v fetch=%d publish=%d observe=%d err=%v",
			result, fetcher.calls, store.publishCalls, store.observeCalls, err,
		)
	}
}

func TestTakeoverWithoutValidArchiveFailsClosed(t *testing.T) {
	command := sourceCommand(t, runlifecycle.ClaimObserve)
	repository := newFakeRepository(command)
	service := sourceService(t, repository, &fakeFetcher{}, &fakeArchiveStore{})

	result, err := service.FetchOnce(context.Background())
	if err != nil || result.Run.Status.State != devopsv1.PipelineRunFailed ||
		result.Run.Status.Reason != devopsv1.PipelineRunReasonSourceUnavailable ||
		repository.completion.Receipt != nil {
		t.Fatalf("missing archive result=%#v completion=%#v err=%v", result, repository.completion, err)
	}
}

func TestFetcherMapsOnlyClosedFailureReasons(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want devopsv1.PipelineRunReason
	}{
		{name: "commit mismatch", err: ErrCommitMismatch, want: devopsv1.PipelineRunReasonCommitMismatch},
		{name: "provider failure", err: errors.New("native provider detail"), want: devopsv1.PipelineRunReasonSourceUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			command := sourceCommand(t, runlifecycle.ClaimExecute)
			repository := newFakeRepository(command)
			service := sourceService(t, repository, &fakeFetcher{err: test.err}, &fakeArchiveStore{})
			result, err := service.FetchOnce(context.Background())
			if err != nil || result.Run.Status.State != devopsv1.PipelineRunFailed ||
				result.Run.Status.Reason != test.want || repository.completion.Receipt != nil {
				t.Fatalf("mapped result=%#v completion=%#v err=%v", result, repository.completion, err)
			}
		})
	}
}

func TestFetcherClosesDurablyCancelledRunWithoutEffects(t *testing.T) {
	command := sourceCommand(t, runlifecycle.ClaimExecute)
	requestedAt := command.Lease.Run.UpdatedAt.Add(time.Microsecond)
	cancelled, err := domain.RequestPipelineRunCancellation(
		command.Lease.Run,
		command.Lease.Run.Status.ResourceVersion,
		true,
		requestedAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	command.Lease.Run = cancelled
	command.Lease.LeaseExpiresAt = requestedAt.Add(LeaseDuration)
	repository := newFakeRepository(command)
	fetcher := &fakeFetcher{payload: []byte("must not be fetched")}
	store := &fakeArchiveStore{}
	service := sourceService(t, repository, fetcher, store)

	result, err := service.FetchOnce(context.Background())
	if err != nil || result.Run.Status.State != devopsv1.PipelineRunCancelled ||
		fetcher.calls != 0 || store.publishCalls != 0 || store.observeCalls != 0 ||
		repository.completion.Receipt != nil {
		t.Fatalf(
			"cancel result=%#v fetch=%d publish=%d observe=%d completion=%#v err=%v",
			result, fetcher.calls, store.publishCalls, store.observeCalls,
			repository.completion, err,
		)
	}
}

func TestLeaseRenewalFailureCancelsEffectAndLeavesIntentOpen(t *testing.T) {
	command := sourceCommand(t, runlifecycle.ClaimExecute)
	repository := newFakeRepository(command)
	repository.renewErr = runlifecycle.ErrStaleLease
	fetcher := &fakeFetcher{waitForCancellation: true}
	service := sourceService(t, repository, fetcher, &fakeArchiveStore{})
	service.renewalInterval = time.Millisecond

	result, err := service.FetchOnce(context.Background())
	if err == nil || !result.Claimed || repository.renewCalls == 0 ||
		repository.completeCalls != 0 {
		t.Fatalf(
			"renewal result=%#v renew=%d complete=%d err=%v",
			result, repository.renewCalls, repository.completeCalls, err,
		)
	}
}

func TestUncertainArchivePublicationLeavesIntentOpen(t *testing.T) {
	command := sourceCommand(t, runlifecycle.ClaimExecute)
	repository := newFakeRepository(command)
	store := &fakeArchiveStore{publishErr: ErrArchiveUncertain}
	service := sourceService(t, repository, &fakeFetcher{}, store)

	result, err := service.FetchOnce(context.Background())
	if !errors.Is(err, ErrArchiveUncertain) || !result.Claimed ||
		repository.completeCalls != 0 {
		t.Fatalf("uncertain result=%#v complete=%d err=%v", result, repository.completeCalls, err)
	}
}

func TestAcquisitionDeadlineIsTerminalButCallerShutdownIsRecoverable(t *testing.T) {
	t.Run("closed deadline", func(t *testing.T) {
		command := sourceCommand(t, runlifecycle.ClaimExecute)
		repository := newFakeRepository(command)
		service := sourceService(t, repository, &fakeFetcher{waitForCancellation: true}, &fakeArchiveStore{})
		service.config.Deadline = time.Millisecond

		result, err := service.FetchOnce(context.Background())
		if err != nil || result.Run.Status.State != devopsv1.PipelineRunFailed ||
			result.Run.Status.Reason != devopsv1.PipelineRunReasonDeadlineExceeded {
			t.Fatalf("deadline result=%#v err=%v", result, err)
		}
	})

	t.Run("caller shutdown", func(t *testing.T) {
		command := sourceCommand(t, runlifecycle.ClaimExecute)
		repository := newFakeRepository(command)
		service := sourceService(t, repository, &fakeFetcher{waitForCancellation: true}, &fakeArchiveStore{})
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		result, err := service.FetchOnce(ctx)
		if !errors.Is(err, context.Canceled) || !result.Claimed || repository.completeCalls != 0 {
			t.Fatalf("shutdown result=%#v complete=%d err=%v", result, repository.completeCalls, err)
		}
	})
}

func TestCommandAndReceiptRejectIdentityDrift(t *testing.T) {
	command := sourceCommand(t, runlifecycle.ClaimExecute)
	invalid := command
	invalid.Event.Spec.Change.HeadCommit = strings.Repeat("9", 40)
	invalid.Event.ContentDigest = devopsv1.SourceEventSpecDigest(invalid.Event.Spec)
	if !errors.Is(ValidateCommand(invalid), ErrInvalidCommand) {
		t.Fatal("changed SourceEvent was accepted")
	}
	invalid = command
	invalid.Event.ReceivedAt = invalid.Event.ReceivedAt.Add(time.Microsecond)
	if !errors.Is(ValidateCommand(invalid), ErrInvalidCommand) {
		t.Fatal("SourceEvent from another run time was accepted")
	}

	receipt := testReceipt(command, []byte("archive"), ArchiveContent{ExpandedBytes: 7, PathCount: 1})
	receipt.CommandID = "another-command"
	if !errors.Is(ValidateReceipt(command, receipt), ErrInvalidReceipt) {
		t.Fatal("receipt for another command was accepted")
	}
}

func TestHeartbeatAndReadinessStayRepositoryOwned(t *testing.T) {
	command := sourceCommand(t, runlifecycle.ClaimExecute)
	repository := newFakeRepository(command)
	service := sourceService(t, repository, &fakeFetcher{}, &fakeArchiveStore{})
	observedAt, err := service.Heartbeat(context.Background())
	if err != nil || observedAt != repository.heartbeatAt || repository.heartbeatWorker != "source-fetcher-one" {
		t.Fatalf("heartbeat=%s worker=%q err=%v", observedAt, repository.heartbeatWorker, err)
	}
	readiness, err := service.Readiness(context.Background())
	if err != nil || readiness != repository.readiness {
		t.Fatalf("readiness=%#v err=%v", readiness, err)
	}
	repository.heartbeatAt = repository.heartbeatAt.Add(time.Nanosecond)
	if _, err := service.Heartbeat(context.Background()); err == nil {
		t.Fatal("non-canonical heartbeat was accepted")
	}
}

type fakeRepository struct {
	command         Command
	found           bool
	heartbeatAt     time.Time
	heartbeatWorker string
	readiness       devopsv1.Readiness
	renewExpiry     time.Time
	renewErr        error
	renewCalls      int
	completion      Completion
	completeCalls   int
}

func newFakeRepository(command Command) *fakeRepository {
	checkedAt := command.Lease.Run.UpdatedAt.Add(time.Second)
	return &fakeRepository{
		command: command, found: true,
		heartbeatAt: checkedAt,
		readiness: devopsv1.Readiness{
			APIVersion: devopsv1.APIVersion, Kind: "Readiness",
			State: devopsv1.ReadinessReady, SchemaVersion: 1, CheckedAt: checkedAt,
		},
		renewExpiry: command.Lease.LeaseExpiresAt,
	}
}

func (repository *fakeRepository) Heartbeat(_ context.Context, workerID string) (time.Time, error) {
	repository.heartbeatWorker = workerID
	return repository.heartbeatAt, nil
}

func (repository *fakeRepository) Claim(
	context.Context,
	string,
	time.Duration,
) (Command, bool, error) {
	return repository.command, repository.found, nil
}

func (repository *fakeRepository) Renew(
	_ context.Context,
	_ runlifecycle.LeaseGuard,
	_ time.Duration,
) (time.Time, error) {
	repository.renewCalls++
	if repository.renewErr != nil {
		return time.Time{}, repository.renewErr
	}
	repository.renewExpiry = repository.renewExpiry.Add(LeaseDuration)
	return repository.renewExpiry, nil
}

func (repository *fakeRepository) Complete(
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

func (repository *fakeRepository) Readiness(context.Context) (devopsv1.Readiness, error) {
	return repository.readiness, nil
}

type fakeFetcher struct {
	payload             []byte
	err                 error
	waitForCancellation bool
	calls               int
}

func (fetcher *fakeFetcher) Fetch(
	ctx context.Context,
	_ Command,
	destination io.Writer,
) (ArchiveContent, error) {
	fetcher.calls++
	if fetcher.waitForCancellation {
		<-ctx.Done()
		return ArchiveContent{}, ctx.Err()
	}
	if fetcher.err != nil {
		return ArchiveContent{}, fetcher.err
	}
	if len(fetcher.payload) == 0 {
		fetcher.payload = []byte("archive")
	}
	if _, err := destination.Write(fetcher.payload); err != nil {
		return ArchiveContent{}, err
	}
	return ArchiveContent{ExpandedBytes: int64(len(fetcher.payload)), PathCount: 1}, nil
}

type fakeArchiveStore struct {
	observed      SourceArchiveReceipt
	observedFound bool
	publishErr    error
	observeErr    error
	publishCalls  int
	observeCalls  int
}

func (store *fakeArchiveStore) Publish(
	_ context.Context,
	command Command,
	write ArchiveWriter,
) (SourceArchiveReceipt, error) {
	store.publishCalls++
	if store.publishErr != nil {
		return SourceArchiveReceipt{}, store.publishErr
	}
	var archive bytes.Buffer
	content, err := write(&archive)
	if err != nil {
		return SourceArchiveReceipt{}, err
	}
	return testReceipt(command, archive.Bytes(), content), nil
}

func (store *fakeArchiveStore) Observe(
	context.Context,
	Command,
) (SourceArchiveReceipt, bool, error) {
	store.observeCalls++
	return store.observed, store.observedFound, store.observeErr
}

func sourceService(
	t *testing.T,
	repository Repository,
	fetcher SourceFetcher,
	store ArchiveStore,
) *Service {
	t.Helper()
	service, err := NewService(repository, fetcher, store, Config{
		WorkerID: "source-fetcher-one", LeaseDuration: LeaseDuration,
		Deadline: AcquisitionDeadline,
	})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func sourceCommand(t *testing.T, mode runlifecycle.ClaimMode) Command {
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
			AdapterID: "source-adapter-gitea", EndpointOrigin: "https://git.example.com",
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
			SourceConnectionID: connection.Metadata.ID, ExternalRepositoryID: "repository-42",
			RepositoryPath: "platform/api", TrustedDefaultBranch: "main",
		},
	}, project, connection, base)
	if err != nil {
		t.Fatal(err)
	}
	binding.Status.Health = devopsv1.RepositoryBindingReady
	binding.Status.Reason = devopsv1.RepositoryBindingReasonObserved
	pipeline, err := domain.NewPipeline(devopsv1.CreatePipelineRequest{
		ID: "pipeline-source", Name: "pipeline-source", ProjectID: project.Metadata.ID,
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
	change := domain.NormalizedChange{
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
	}
	event, err := domain.NewSourceEvent(change, connection, binding, base.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	run, err := domain.NewPipelineRun(event, activation.Pipeline, activation.Revision)
	if err != nil {
		t.Fatal(err)
	}
	run, err = domain.AdvancePipelineRun(
		run, devopsv1.PipelineRunFetching, "", run.UpdatedAt.Add(time.Microsecond),
	)
	if err != nil {
		t.Fatal(err)
	}
	fence := uint64(1)
	if mode == runlifecycle.ClaimObserve {
		fence = 2
	}
	intent := runlifecycle.TaskIntent{
		RunID: run.ID, InputDigest: run.InputDigest,
		Stage: devopsv1.PipelineRunStageFetch, Attempt: 1,
	}
	intent.CommandID = runlifecycle.TaskCommandID(intent.RunID, intent.Stage, intent.Attempt)
	return Command{
		Lease: runlifecycle.Lease{
			TenantID: scope.TenantID, Run: run, Intent: intent, Mode: mode,
			WorkerID: "source-fetcher-one", FencingToken: fence,
			LeaseExpiresAt: run.UpdatedAt.Add(LeaseDuration),
		},
		Connection: connection, BindingRevision: binding,
		Revision: activation.Revision, Event: event,
	}
}

func testReceipt(
	command Command,
	payload []byte,
	content ArchiveContent,
) SourceArchiveReceipt {
	digest := sha256.Sum256(payload)
	return receiptFromDigest(command, digest[:], int64(len(payload)), content)
}

func receiptFromDigest(
	command Command,
	digest []byte,
	archiveBytes int64,
	content ArchiveContent,
) SourceArchiveReceipt {
	return SourceArchiveReceipt{
		TenantID: command.Lease.TenantID, RunID: command.Lease.Run.ID,
		CommandID: command.Lease.Intent.CommandID, InputDigest: command.Lease.Run.InputDigest,
		HeadCommit:        command.Lease.Run.Input.Change.HeadCommit,
		TrustedBaseCommit: command.Lease.Run.Input.Change.TrustedBaseCommit,
		MediaType:         ArchiveMediaType, ArchiveDigest: fmt.Sprintf("sha256:%x", digest),
		ArchiveBytes: archiveBytes, ExpandedBytes: content.ExpandedBytes, PathCount: content.PathCount,
	}
}
