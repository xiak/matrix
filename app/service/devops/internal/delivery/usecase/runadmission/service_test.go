package runadmission

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/domain"
)

func TestAuthenticatedSourceAdmissionCreatesAtomicOrderedRunsAndAuditFacts(t *testing.T) {
	repository := readyAdmissionRepository(t, 2)
	// The use case, not an adapter's incidental query order, owns fan-out order.
	repository.activations[0], repository.activations[1] = repository.activations[1], repository.activations[0]
	usecase := mustAdmissionUsecase(t, repository, 3)
	result, err := usecase.Admit(context.Background(), admissionCommand())
	if err != nil {
		t.Fatalf("admit source event: %v", err)
	}
	if result.Replayed || len(result.Admission.Runs) != 2 || repository.successfulCommits != 1 {
		t.Fatalf("admission result=%#v commits=%d", result, repository.successfulCommits)
	}
	if result.Admission.Runs[0].PipelineID != "pipeline-a" ||
		result.Admission.Runs[1].PipelineID != "pipeline-b" {
		t.Fatalf("PipelineRun order=%q,%q", result.Admission.Runs[0].PipelineID, result.Admission.Runs[1].PipelineID)
	}
	if err := ValidateSubmission(repository.submission); err != nil {
		t.Fatalf("validate persisted admission: %v", err)
	}
	if len(repository.submission.AuditEvents) != 3 ||
		repository.submission.AuditEvents[0].Action != auditv1.ActionDevOpsSourceEventAdmitted ||
		repository.submission.AuditEvents[1].Action != auditv1.ActionDevOpsPipelineRunCreated {
		t.Fatalf("admission Audit facts=%#v", repository.submission.AuditEvents)
	}
	for _, event := range repository.submission.AuditEvents {
		if event.Actor.Type != auditv1.ActorSystem || event.Actor.ID != sourceIngressActorID ||
			event.IAMDecisionID != "" {
			t.Fatalf("admission invented user authority: %#v", event)
		}
	}
}

func TestEqualReplayReturnsOriginalAdmissionBeforeMutableConfigurationLookup(t *testing.T) {
	repository := readyAdmissionRepository(t, 2)
	usecase := mustAdmissionUsecase(t, repository, 3)
	first, err := usecase.Admit(context.Background(), admissionCommand())
	if err != nil {
		t.Fatal(err)
	}
	repository.connection = devopsv1.SourceConnection{}
	repository.binding = devopsv1.RepositoryBinding{}
	repository.activations = nil
	repository.queued = MaximumQueuedRuns
	second, err := usecase.Admit(context.Background(), admissionCommand())
	if err != nil || !second.Replayed {
		t.Fatalf("equal replay=%#v err=%v", second, err)
	}
	if second.Admission.Event != first.Admission.Event ||
		len(second.Admission.Runs) != len(first.Admission.Runs) ||
		repository.successfulCommits != 1 || repository.configurationLoads != 2 {
		t.Fatalf("replay consulted mutable state or rewrote admission: %#v", repository)
	}
}

func TestChangedReplayAndQueueOverflowFailWithoutPartialAdmission(t *testing.T) {
	repository := readyAdmissionRepository(t, 2)
	usecase := mustAdmissionUsecase(t, repository, 3)
	if _, err := usecase.Admit(context.Background(), admissionCommand()); err != nil {
		t.Fatal(err)
	}
	changed := admissionCommand()
	changed.Change.CanonicalPayloadDigest = "sha256:" + strings.Repeat("b", 64)
	if _, err := usecase.Admit(context.Background(), changed); !errors.Is(err, ErrReplayConflict) {
		t.Fatalf("changed replay error=%v", err)
	}
	if repository.successfulCommits != 1 {
		t.Fatalf("changed replay persisted partial state: %d", repository.successfulCommits)
	}

	full := readyAdmissionRepository(t, 2)
	full.queued = MaximumQueuedRuns - 1
	if _, err := mustAdmissionUsecase(t, full, 3).Admit(
		context.Background(), admissionCommand(),
	); !errors.Is(err, ErrQueueCapacityExceeded) {
		t.Fatalf("queue overflow error=%v", err)
	}
	if full.successfulCommits != 0 || full.admission != nil {
		t.Fatal("queue overflow committed a partial admission")
	}
}

func TestAdmissionRetriesOnlyRetryableTransactions(t *testing.T) {
	repository := readyAdmissionRepository(t, 1)
	repository.failedCommits = 1
	result, err := mustAdmissionUsecase(t, repository, 2).Admit(
		context.Background(), admissionCommand(),
	)
	if err != nil || result.Replayed || repository.transactions != 2 || repository.successfulCommits != 1 {
		t.Fatalf("retried admission=%#v repository=%#v err=%v", result, repository, err)
	}

	exhausted := readyAdmissionRepository(t, 1)
	exhausted.failedCommits = 2
	if _, err := mustAdmissionUsecase(t, exhausted, 2).Admit(
		context.Background(), admissionCommand(),
	); !errors.Is(err, ErrRetryableTransaction) {
		t.Fatalf("exhausted transaction error=%v", err)
	}
	if exhausted.successfulCommits != 0 || exhausted.admission != nil {
		t.Fatal("exhausted transaction committed admission state")
	}
}

func TestAdmissionRejectsUntrustedContextAndAuditDrift(t *testing.T) {
	repository := readyAdmissionRepository(t, 1)
	command := admissionCommand()
	command.TraceParent = "00-00000000000000000000000000000000-0000000000000000-01"
	if _, err := mustAdmissionUsecase(t, repository, 1).Admit(context.Background(), command); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("invalid trace context error=%v", err)
	}

	valid, err := mustAdmissionUsecase(t, repository, 1).Admit(context.Background(), admissionCommand())
	if err != nil {
		t.Fatal(err)
	}
	submission := repository.submission
	submission.AuditEvents = append([]auditv1.Event(nil), submission.AuditEvents...)
	submission.AuditEvents[0].IAMDecisionID = "decision-forged"
	if err := ValidateSubmission(submission); err == nil {
		t.Fatal("admission accepted a forged IAM decision")
	}
	if err := ValidateAdmission(valid.Admission); err != nil {
		t.Fatal(err)
	}
	invalid := valid.Admission
	invalid.Runs = append([]devopsv1.PipelineRun(nil), invalid.Runs...)
	invalid.Runs[0].Input.SourceEventDigest = "sha256:" + strings.Repeat("f", 64)
	if err := ValidateAdmission(invalid); err == nil {
		t.Fatal("admission accepted a run detached from its event")
	}
}

type fakeAdmissionRepository struct {
	now                time.Time
	connection         devopsv1.SourceConnection
	binding            devopsv1.RepositoryBinding
	activations        []devopsv1.PipelineActivation
	queued             uint64
	admission          *Admission
	submission         Submission
	failedCommits      int
	transactions       int
	successfulCommits  int
	configurationLoads int
}

func (repository *fakeAdmissionRepository) WithinAdmissionTransaction(
	ctx context.Context,
	tenantID devopsv1.TenantID,
	callback func(context.Context, Transaction) error,
) error {
	repository.transactions++
	if tenantID != "organization-acme" {
		return errors.New("unexpected tenant")
	}
	tx := &fakeAdmissionTransaction{repository: repository}
	if err := callback(ctx, tx); err != nil {
		return err
	}
	if tx.pending != nil {
		admission := tx.pending.Admission
		repository.admission = &admission
		repository.submission = *tx.pending
		repository.successfulCommits++
	}
	return nil
}

type fakeAdmissionTransaction struct {
	repository *fakeAdmissionRepository
	pending    *Submission
}

func (transaction *fakeAdmissionTransaction) TransactionTime(context.Context) (time.Time, error) {
	return transaction.repository.now, nil
}

func (transaction *fakeAdmissionTransaction) LoadAdmission(
	_ context.Context,
	id devopsv1.ResourceID,
) (Admission, bool, error) {
	if transaction.repository.admission == nil || transaction.repository.admission.Event.ID != id {
		return Admission{}, false, nil
	}
	return *transaction.repository.admission, true, nil
}

func (transaction *fakeAdmissionTransaction) LoadSourceConnection(
	_ context.Context,
	id devopsv1.ResourceID,
) (devopsv1.SourceConnection, bool, error) {
	transaction.repository.configurationLoads++
	value := transaction.repository.connection
	return value, value.Metadata.ID == id, nil
}

func (transaction *fakeAdmissionTransaction) LoadRepositoryBindingForSource(
	_ context.Context,
	connectionID devopsv1.ResourceID,
	externalRepositoryID devopsv1.ResourceID,
) (devopsv1.RepositoryBinding, bool, error) {
	transaction.repository.configurationLoads++
	value := transaction.repository.binding
	found := value.Spec.SourceConnectionID == connectionID &&
		value.Spec.ExternalRepositoryID == externalRepositoryID
	return value, found, nil
}

func (transaction *fakeAdmissionTransaction) LoadMatchingActiveRevisions(
	_ context.Context,
	bindingID devopsv1.ResourceID,
	bindingDigest string,
) ([]devopsv1.PipelineActivation, error) {
	values := append([]devopsv1.PipelineActivation(nil), transaction.repository.activations...)
	for _, value := range values {
		if value.Revision.Spec.RepositoryBindingID != bindingID ||
			value.Revision.Spec.RepositoryBindingDigest != bindingDigest {
			return nil, errors.New("unexpected active revision query")
		}
	}
	return values, nil
}

func (transaction *fakeAdmissionTransaction) QueuedRunCount(context.Context) (uint64, error) {
	return transaction.repository.queued, nil
}

func (transaction *fakeAdmissionTransaction) CommitAdmission(_ context.Context, value Submission) error {
	if transaction.repository.failedCommits > 0 {
		transaction.repository.failedCommits--
		return ErrRetryableTransaction
	}
	transaction.pending = &value
	return nil
}

func readyAdmissionRepository(t *testing.T, pipelineCount int) *fakeAdmissionRepository {
	t.Helper()
	base := time.Date(2026, 9, 7, 4, 5, 6, 0, time.UTC)
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
			AdapterID: "source-adapter-one", AllowedEndpointOrigins: []string{"https://git.example.com"},
			WebhookSecretRef: "webhook-secret", FetchCredentialRef: "fetch-secret", ReportCredentialRef: "report-secret",
		},
	}, scope, base)
	if err != nil {
		t.Fatal(err)
	}
	connection.Status.Health = devopsv1.SourceConnectionReady
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
	activations := make([]devopsv1.PipelineActivation, pipelineCount)
	for index := 0; index < pipelineCount; index++ {
		letter := string(rune('a' + index))
		pipeline, err := domain.NewPipeline(devopsv1.CreatePipelineRequest{
			ID: devopsv1.ResourceID("pipeline-" + letter), Name: "pipeline-" + letter,
			ProjectID: project.Metadata.ID,
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
		activations[index], err = domain.ActivatePipeline(
			pipeline, pipeline.Metadata.ResourceVersion,
			devopsv1.SubjectRef{Kind: devopsv1.SubjectUser, ID: "user-alice"},
			binding, base.Add(time.Minute),
		)
		if err != nil {
			t.Fatal(err)
		}
	}
	return &fakeAdmissionRepository{
		now: base.Add(2 * time.Minute), connection: connection,
		binding: binding, activations: activations,
	}
}

func admissionCommand() Command {
	return Command{
		Change: domain.NormalizedChange{
			Scope:              devopsv1.ResourceScope{TenantID: "organization-acme"},
			SourceConnectionID: "source-connection-primary", ExternalRepositoryID: "42",
			DeliveryID:             "123e4567-e89b-42d3-a456-426614174000",
			CanonicalPayloadDigest: "sha256:" + strings.Repeat("a", 64),
			Change: devopsv1.ChangeIdentity{
				Number: 42, Action: devopsv1.ChangeOpened,
				HeadCommit: strings.Repeat("1", 40), TrustedBaseCommit: strings.Repeat("2", 40),
			},
		},
		RequestID: "request-source-event", CorrelationID: "correlation-source-event",
		TraceParent: "00-5bf92f3577b34da6a3ce929d0e0e4736-10f067aa0ba902b7-01",
	}
}

func mustAdmissionUsecase(t *testing.T, repository Repository, attempts int) *Usecase {
	t.Helper()
	usecase, err := NewUsecase(repository, Config{MaxTransactionAttempts: attempts})
	if err != nil {
		t.Fatal(err)
	}
	return usecase
}
