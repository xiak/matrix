package applicationlifecycle

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

var lifecycleTime = time.Date(2026, 8, 25, 16, 0, 0, 123_000, time.UTC)

func TestSubmitCreatesDeploymentGenerationAndOperationAtomically(t *testing.T) {
	transaction := lifecycleTransaction()
	repository := &fakeLifecycleRepository{transaction: transaction}
	result, err := mustLifecycleUsecase(t, repository).Submit(
		context.Background(),
		lifecycleCreateCommand(),
	)
	if err != nil {
		t.Fatalf("submit Deployment: %v", err)
	}
	if result.Replayed || result.Deployment.Generation != 1 ||
		result.Deployment.Metadata.ResourceVersion != 1 ||
		result.Deployment.Status.Phase != paasv1.DeploymentPending ||
		result.Operation.Action != paasv1.OperationDeploy ||
		result.Operation.State != paasv1.OperationAccepted {
		t.Fatalf("submission result = %#v", result)
	}
	if result.Generation.CreatedByOperationID != result.Operation.ID ||
		result.Generation.ContentDigest != paasv1.DeploymentSpecContentDigest(result.Deployment.Spec) {
		t.Fatalf("generation identity = %#v", result.Generation)
	}
	if !result.Operation.CreatedAt.Equal(lifecycleTime) ||
		!result.Deployment.Metadata.CreatedAt.Equal(lifecycleTime) {
		t.Fatalf("submission did not use database transaction time: %#v", result)
	}
	if err := paasv1.ValidateDeploymentAgainstRevision(result.Deployment, transaction.revision); err != nil {
		t.Fatalf("created Deployment is invalid: %v", err)
	}
	if err := paasv1.ValidateDeploymentGenerationAgainstRevision(result.Generation, transaction.revision); err != nil {
		t.Fatalf("created DeploymentGeneration is invalid: %v", err)
	}
	if err := paasv1.ValidateOperation(result.Operation); err != nil {
		t.Fatalf("created Operation is invalid: %v", err)
	}
	if transaction.submission == nil ||
		transaction.submission.ExpectedResourceVersion != 0 ||
		transaction.submission.Operation.ID != result.Operation.ID {
		t.Fatalf("atomic submission = %#v", transaction.submission)
	}
}

func TestSubmitReplaysBeforeCurrentStateChecksAndRejectsChangedPayload(t *testing.T) {
	command := lifecycleCreateCommand()
	initialTransaction := lifecycleTransaction()
	initial, err := mustLifecycleUsecase(
		t,
		&fakeLifecycleRepository{transaction: initialTransaction},
	).Submit(context.Background(), command)
	if err != nil {
		t.Fatalf("initial submit: %v", err)
	}

	replayTransaction := lifecycleTransaction()
	replayTransaction.deployment = initial.Deployment
	replayTransaction.deploymentFound = true
	replayTransaction.storedOperation = initial.Operation
	replayTransaction.operationFound = true
	replayTransaction.generationByOperation = initial.Generation
	replayed, err := mustLifecycleUsecase(
		t,
		&fakeLifecycleRepository{transaction: replayTransaction},
	).Submit(context.Background(), command)
	if err != nil {
		t.Fatalf("replay pending Deployment create: %v", err)
	}
	if !replayed.Replayed || replayed.Operation.ID != initial.Operation.ID ||
		replayed.Generation.Generation != initial.Generation.Generation {
		t.Fatalf("replayed result = %#v", replayed)
	}
	if replayTransaction.submission != nil {
		t.Fatalf("exact replay created another submission: %#v", replayTransaction.submission)
	}

	changed := command
	changed.Spec.Components[0].Replicas++
	_, err = mustLifecycleUsecase(
		t,
		&fakeLifecycleRepository{transaction: replayTransaction},
	).Submit(context.Background(), changed)
	if !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed replay error = %v, want idempotency conflict", err)
	}
}

func TestSubmitEnforcesIfMatchDesiredChangeAndActiveOperation(t *testing.T) {
	current := lifecycleReadyDeployment()
	tests := []struct {
		name    string
		command SubmitCommand
		mutate  func(*paasv1.Deployment)
		want    error
	}{
		{
			name:    "stale If-Match",
			command: lifecycleUpdateCommand(current, "config-revision-b"),
			want:    ErrResourceVersionConflict,
		},
		{
			name:    "unchanged desired content",
			command: lifecycleUpdateCommand(current, "config-revision-a"),
			want:    ErrNoDesiredChange,
		},
		{
			name:    "active operation",
			command: lifecycleUpdateCommand(current, "config-revision-b"),
			mutate: func(value *paasv1.Deployment) {
				value.Status.Phase = paasv1.DeploymentApplying
			},
			want: ErrOperationInProgress,
		},
	}
	tests[0].command.ExpectedResourceVersion--
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			deployment := current
			if test.mutate != nil {
				test.mutate(&deployment)
			}
			transaction := lifecycleTransaction()
			transaction.deployment = deployment
			transaction.deploymentFound = true
			_, err := mustLifecycleUsecase(
				t,
				&fakeLifecycleRepository{transaction: transaction},
			).Submit(context.Background(), test.command)
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
			if transaction.submission != nil {
				t.Fatalf("rejected mutation was submitted: %#v", transaction.submission)
			}
		})
	}
}

func TestSubmitUpdateAdvancesDesiredIdentityAndPreservesObservation(t *testing.T) {
	current := lifecycleReadyDeployment()
	transaction := lifecycleTransaction()
	transaction.deployment = current
	transaction.deploymentFound = true
	result, err := mustLifecycleUsecase(
		t,
		&fakeLifecycleRepository{transaction: transaction},
	).Submit(
		context.Background(),
		lifecycleUpdateCommand(current, "config-revision-b"),
	)
	if err != nil {
		t.Fatalf("update Deployment: %v", err)
	}
	if result.Deployment.Generation != current.Generation+1 ||
		result.Deployment.Metadata.ResourceVersion != current.Metadata.ResourceVersion+1 ||
		result.Operation.Action != paasv1.OperationUpdate ||
		result.Deployment.Status.Phase != paasv1.DeploymentPending ||
		result.Deployment.Status.PlacementDecisionID != current.Status.PlacementDecisionID {
		t.Fatalf("updated desired identity = %#v", result)
	}
	if result.Deployment.Status.ObservedGeneration != current.Status.ObservedGeneration ||
		result.Deployment.Status.ObservedApplicationRevisionID !=
			current.Status.ObservedApplicationRevisionID ||
		!result.Deployment.Status.ObservedAt.Equal(current.Status.ObservedAt) {
		t.Fatalf("update rewrote observed state: %#v", result.Deployment.Status)
	}
}

func TestSubmitStopChangesOnlyDesiredStateAndKeepsObservedPlacement(t *testing.T) {
	current := lifecycleReadyDeployment()
	command := lifecycleUpdateCommand(current, "config-revision-a")
	command.IdempotencyKey = "stop-deployment-a"
	command.Spec.DesiredState = paasv1.DeploymentDesiredStopped
	transaction := lifecycleTransaction()
	transaction.deployment = current
	transaction.deploymentFound = true
	result, err := mustLifecycleUsecase(
		t,
		&fakeLifecycleRepository{transaction: transaction},
	).Submit(context.Background(), command)
	if err != nil {
		t.Fatalf("stop Deployment: %v", err)
	}
	if result.Operation.Action != paasv1.OperationStop ||
		result.Deployment.Status.PlacementDecisionID != current.Status.PlacementDecisionID ||
		result.Deployment.Spec.DesiredState != paasv1.DeploymentDesiredStopped {
		t.Fatalf("stop desired mutation = %#v", result)
	}

	changed := command
	changed.IdempotencyKey = "stop-and-change-configuration"
	changed.Spec = lifecycleSpec("config-revision-b")
	changed.Spec.DesiredState = paasv1.DeploymentDesiredStopped
	transaction.submission = nil
	if _, err := mustLifecycleUsecase(
		t,
		&fakeLifecycleRepository{transaction: transaction},
	).Submit(context.Background(), changed); err == nil {
		t.Fatal("stop unexpectedly accepted another desired-state change")
	}
	if transaction.submission != nil {
		t.Fatalf("invalid stop was persisted: %#v", transaction.submission)
	}

	createStopped := lifecycleCreateCommand()
	createStopped.Spec.DesiredState = paasv1.DeploymentDesiredStopped
	if _, err := mustLifecycleUsecase(
		t,
		&fakeLifecycleRepository{transaction: lifecycleTransaction()},
	).Submit(context.Background(), createStopped); err == nil {
		t.Fatal("new stopped Deployment unexpectedly succeeded")
	}
}

func TestRollbackCopiesAcceptedSnapshotIntoNewGeneration(t *testing.T) {
	current := lifecycleReadyDeployment()
	current.Generation = 3
	current.Metadata.ResourceVersion = 5
	current.Status.ObservedGeneration = 3
	transaction := lifecycleTransaction()
	transaction.deployment = current
	transaction.deploymentFound = true
	source := paasv1.DeploymentGeneration{
		APIVersion:           paasv1.APIVersion,
		Kind:                 "DeploymentGeneration",
		Scope:                current.Metadata.Scope,
		DeploymentID:         current.Metadata.ID,
		Generation:           1,
		Spec:                 lifecycleSpec("config-revision-a"),
		CreatedByOperationID: "operation-source",
		CreatedAt:            lifecycleTime.Add(-time.Hour),
	}
	source.ContentDigest = paasv1.DeploymentSpecContentDigest(source.Spec)
	transaction.acceptedGenerations[1] = source
	result, err := mustLifecycleUsecase(
		t,
		&fakeLifecycleRepository{transaction: transaction},
	).Rollback(context.Background(), RollbackCommand{
		TenantID:                "tenant-a",
		DeploymentID:            "deployment-a",
		SourceGeneration:        1,
		ExpectedResourceVersion: 5,
		IdempotencyKey:          "rollback-to-one",
		RequestedBy:             lifecycleRequester(),
	})
	if err != nil {
		t.Fatalf("rollback Deployment: %v", err)
	}
	if result.Operation.Action != paasv1.OperationRollback ||
		result.Deployment.Generation != 4 ||
		result.Generation.Generation != 4 ||
		paasv1.DeploymentSpecContentDigest(result.Generation.Spec) != source.ContentDigest {
		t.Fatalf("rollback result = %#v", result)
	}
	if transaction.acceptedGenerations[1].Generation != 1 {
		t.Fatalf("rollback rewrote source generation: %#v", transaction.acceptedGenerations[1])
	}
	stoppedSource := source
	stoppedSource.Spec.DesiredState = paasv1.DeploymentDesiredStopped
	stoppedSource.ContentDigest = paasv1.DeploymentSpecContentDigest(stoppedSource.Spec)
	transaction.acceptedGenerations[1] = stoppedSource
	_, err = mustLifecycleUsecase(
		t,
		&fakeLifecycleRepository{transaction: transaction},
	).Rollback(context.Background(), RollbackCommand{
		TenantID:                "tenant-a",
		DeploymentID:            "deployment-a",
		SourceGeneration:        1,
		ExpectedResourceVersion: 5,
		IdempotencyKey:          "rollback-to-stopped",
		RequestedBy:             lifecycleRequester(),
	})
	if err == nil {
		t.Fatal("Compose v0.1 rollback to a stopped generation must be rejected")
	}
}

func TestSubmitRetriesRolledBackSerializableTransaction(t *testing.T) {
	transaction := lifecycleTransaction()
	repository := &fakeLifecycleRepository{
		transaction:         transaction,
		afterCallbackErrors: []error{ErrRetryableTransaction},
	}
	result, err := mustLifecycleUsecase(t, repository).Submit(
		context.Background(),
		lifecycleCreateCommand(),
	)
	if err != nil {
		t.Fatalf("submit after transaction retry: %v", err)
	}
	if repository.calls != 2 || result.Operation.State != paasv1.OperationAccepted {
		t.Fatalf("retry calls/result = %d/%#v", repository.calls, result)
	}
}

type fakeLifecycleRepository struct {
	transaction         Transaction
	afterCallbackErrors []error
	calls               int
}

func (repository *fakeLifecycleRepository) WithinTransaction(
	ctx context.Context,
	_ paasv1.TenantID,
	callback func(context.Context, Transaction) error,
) error {
	repository.calls++
	if err := callback(ctx, repository.transaction); err != nil {
		return err
	}
	index := repository.calls - 1
	if index < len(repository.afterCallbackErrors) {
		return repository.afterCallbackErrors[index]
	}
	return nil
}

type fakeLifecycleTransaction struct {
	now                   time.Time
	deployment            paasv1.Deployment
	deploymentFound       bool
	revision              paasv1.ApplicationRevision
	policy                paasv1.PlacementPolicy
	storedOperation       paasv1.Operation
	operationFound        bool
	acceptedGenerations   map[uint64]paasv1.DeploymentGeneration
	generationByOperation paasv1.DeploymentGeneration
	configurationError    error
	submission            *Submission
}

func (transaction *fakeLifecycleTransaction) TransactionTime(context.Context) (time.Time, error) {
	return transaction.now, nil
}

func (transaction *fakeLifecycleTransaction) FindOperationByFingerprint(
	_ context.Context,
	fingerprint string,
) (paasv1.Operation, bool, error) {
	if transaction.operationFound && transaction.storedOperation.IdempotencyFingerprint == fingerprint {
		return transaction.storedOperation, true, nil
	}
	return paasv1.Operation{}, false, nil
}

func (transaction *fakeLifecycleTransaction) LoadDeployment(
	context.Context,
	paasv1.ResourceID,
) (paasv1.Deployment, bool, error) {
	return transaction.deployment, transaction.deploymentFound, nil
}

func (transaction *fakeLifecycleTransaction) LoadApplicationRevision(
	context.Context,
	paasv1.ResourceID,
) (paasv1.ApplicationRevision, error) {
	return transaction.revision, nil
}

func (transaction *fakeLifecycleTransaction) ValidateConfigurationBindings(
	context.Context,
	paasv1.DeploymentSpec,
	paasv1.ResourceID,
) error {
	return transaction.configurationError
}

func (transaction *fakeLifecycleTransaction) LoadPlacementPolicy(
	context.Context,
	paasv1.ResourceID,
) (paasv1.PlacementPolicy, error) {
	return transaction.policy, nil
}

func (transaction *fakeLifecycleTransaction) LoadAcceptedGeneration(
	_ context.Context,
	_ paasv1.ResourceID,
	generation uint64,
) (paasv1.DeploymentGeneration, error) {
	value, found := transaction.acceptedGenerations[generation]
	if !found {
		return paasv1.DeploymentGeneration{}, ErrNotFound
	}
	return value, nil
}

func (transaction *fakeLifecycleTransaction) LoadGenerationByOperation(
	context.Context,
	paasv1.OperationID,
) (paasv1.DeploymentGeneration, error) {
	return transaction.generationByOperation, nil
}

func (transaction *fakeLifecycleTransaction) SubmitDeployment(
	_ context.Context,
	submission Submission,
) error {
	transaction.submission = &submission
	return nil
}

func mustLifecycleUsecase(t *testing.T, repository Repository) *Usecase {
	t.Helper()
	usecase, err := NewUsecase(repository, Config{MaxTransactionAttempts: 3})
	if err != nil {
		t.Fatalf("new application lifecycle use case: %v", err)
	}
	return usecase
}

func lifecycleTransaction() *fakeLifecycleTransaction {
	return &fakeLifecycleTransaction{
		now:                 lifecycleTime,
		revision:            lifecycleRevision(),
		policy:              lifecyclePolicy(),
		acceptedGenerations: make(map[uint64]paasv1.DeploymentGeneration),
	}
}

func lifecycleCreateCommand() SubmitCommand {
	return SubmitCommand{
		TenantID:       "tenant-a",
		DeploymentID:   "deployment-a",
		Name:           "deployment-a",
		Spec:           lifecycleSpec("config-revision-a"),
		IdempotencyKey: "create-deployment-a",
		RequestedBy:    lifecycleRequester(),
	}
}

func lifecycleUpdateCommand(
	current paasv1.Deployment,
	configurationRevisionID paasv1.ResourceID,
) SubmitCommand {
	return SubmitCommand{
		TenantID:                current.Metadata.Scope.TenantID,
		DeploymentID:            current.Metadata.ID,
		Spec:                    lifecycleSpec(configurationRevisionID),
		ExpectedResourceVersion: current.Metadata.ResourceVersion,
		IdempotencyKey:          "update-deployment-a-" + string(configurationRevisionID),
		RequestedBy:             lifecycleRequester(),
	}
}

func lifecycleRequester() paasv1.SubjectRef {
	return paasv1.SubjectRef{Type: paasv1.SubjectUser, ID: "user-a"}
}

func lifecycleSpec(configurationRevisionID paasv1.ResourceID) paasv1.DeploymentSpec {
	return paasv1.DeploymentSpec{
		ApplicationRevisionID: "revision-a",
		PlacementPolicyID:     "policy-a",
		DesiredState:          paasv1.DeploymentDesiredRunning,
		Components: []paasv1.DeploymentComponent{{
			Name:     "api",
			Replicas: 1,
			Bindings: []paasv1.ComponentBinding{
				{Name: "settings", ConfigurationRevisionID: configurationRevisionID},
				{
					Name: "credential",
					SecretVersion: &paasv1.SecretVersionReference{
						SecretID: "database-password",
						Version:  "version-1",
					},
				},
			},
		}},
	}
}

func lifecycleRevision() paasv1.ApplicationRevision {
	return paasv1.ApplicationRevision{
		APIVersion: paasv1.APIVersion,
		Kind:       "ApplicationRevision",
		Metadata:   lifecycleMetadata("revision-a", "revision-a", 1, true),
		Spec: paasv1.ApplicationRevisionSpec{
			ApplicationID: "application-a",
			Revision:      "revision-a",
			ContentDigest: lifecycleDigest('a'),
			Components: []paasv1.ApplicationRevisionComponent{{
				Name: "api",
				Artifact: paasv1.ArtifactRef{
					Kind:    paasv1.ArtifactOCIImage,
					Locator: "registry.example.invalid/application/api",
					Digest:  lifecycleDigest('b'),
				},
				Resources: paasv1.ResourceRequirements{
					CPUMillis:   250,
					MemoryBytes: 64 * 1024 * 1024,
				},
				Inputs: []paasv1.ComponentInput{
					{
						Name:      "settings",
						Kind:      paasv1.InputConfiguration,
						Injection: paasv1.InjectionEnvironment,
						Required:  true,
					},
					{
						Name:      "credential",
						Kind:      paasv1.InputSecret,
						Injection: paasv1.InjectionFile,
						Required:  true,
					},
				},
			}},
		},
	}
}

func lifecyclePolicy() paasv1.PlacementPolicy {
	return paasv1.PlacementPolicy{
		APIVersion: paasv1.APIVersion,
		Kind:       "PlacementPolicy",
		Metadata:   lifecycleMetadata("policy-a", "policy-a", 1, false),
		Spec: paasv1.PlacementPolicySpec{
			RequiredIsolationGuarantee: paasv1.IsolationWorkload,
			EligibleExecutionPoolIDs:   []paasv1.ResourceID{"pool-a"},
			Strategy:                   paasv1.PlacementFirstFit,
		},
	}
}

func lifecycleReadyDeployment() paasv1.Deployment {
	return paasv1.Deployment{
		APIVersion: paasv1.APIVersion,
		Kind:       "Deployment",
		Metadata:   lifecycleMetadata("deployment-a", "deployment-a", 3, false),
		Generation: 2,
		Spec:       lifecycleSpec("config-revision-a"),
		Status: paasv1.DeploymentStatus{
			Phase:                         paasv1.DeploymentReady,
			ObservedGeneration:            2,
			PlacementDecisionID:           "placement-a",
			CurrentOperationID:            "operation-ready",
			ObservedApplicationRevisionID: "revision-a",
			ReadyComponents:               1,
			ObservedAt:                    lifecycleTime.Add(-time.Minute),
		},
	}
}

func lifecycleMetadata(
	id paasv1.ResourceID,
	name string,
	resourceVersion uint64,
	immutable bool,
) paasv1.ResourceMetadata {
	createdAt := lifecycleTime.Add(-time.Hour)
	updatedAt := lifecycleTime.Add(-time.Minute)
	if immutable {
		updatedAt = createdAt
	}
	return paasv1.ResourceMetadata{
		ID:   id,
		Name: name,
		Scope: paasv1.ResourceScope{
			Kind:     paasv1.AuthorityTenant,
			TenantID: "tenant-a",
		},
		ResourceVersion: resourceVersion,
		CreatedAt:       createdAt,
		UpdatedAt:       updatedAt,
	}
}

func lifecycleDigest(character byte) string {
	return "sha256:" + strings.Repeat(string(character), 64)
}
