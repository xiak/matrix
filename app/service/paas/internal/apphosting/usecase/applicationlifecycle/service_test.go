package applicationlifecycle

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/port"
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
		transaction.submission.Operation.ID != result.Operation.ID ||
		transaction.submission.AuditEvent.OperationID != result.Operation.ID {
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
		Authorization:           lifecycleAuthorization(),
		DeploymentID:            "deployment-a",
		SourceGeneration:        1,
		ExpectedResourceVersion: 5,
		IdempotencyKey:          "rollback-to-one",
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
		Authorization:           lifecycleAuthorization(),
		DeploymentID:            "deployment-a",
		SourceGeneration:        1,
		ExpectedResourceVersion: 5,
		IdempotencyKey:          "rollback-to-stopped",
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

func TestListDeploymentsUsesAuthorizedTenantAndBoundedCursor(t *testing.T) {
	transaction := lifecycleTransaction()
	deployment := lifecycleReadyDeployment()
	transaction.deployments = []paasv1.Deployment{deployment}
	transaction.nextDeploymentAfter = deployment.Metadata.ID
	repository := &fakeLifecycleRepository{transaction: transaction}

	result, err := mustLifecycleUsecase(t, repository).ListDeployments(
		context.Background(),
		lifecycleAuthorization(),
		"deployment-before",
	)
	if err != nil {
		t.Fatalf("list Deployments: %v", err)
	}
	if len(repository.tenantIDs) != 1 || repository.tenantIDs[0] != "tenant-a" ||
		transaction.listAfter != "deployment-before" ||
		transaction.listLimit != paasv1.MaximumDeploymentListItems {
		t.Fatalf(
			"tenant/cursor/limit = %#v/%q/%d",
			repository.tenantIDs,
			transaction.listAfter,
			transaction.listLimit,
		)
	}
	if result.Scope.TenantID != "tenant-a" || len(result.Items) != 1 ||
		result.Items[0].Metadata.ID != deployment.Metadata.ID ||
		result.NextAfter != deployment.Metadata.ID || paasv1.ValidateDeploymentList(result) != nil {
		t.Fatalf("Deployment list = %#v", result)
	}
}

func TestGetDeploymentRuntimeUsesAuthorizedTenantAndReturnsExactSourceProof(t *testing.T) {
	transaction := lifecycleTransaction()
	observation := paasv1.DeploymentRuntimeObservation{
		DeploymentID:          "deployment-a",
		Generation:            2,
		ApplicationRevisionID: "revision-a",
		ExecutionTargetID:     "execution-target-a",
		Instances: []paasv1.DeploymentRuntimeInstance{{
			ID:            "instance-0123456789abcdef0123456789abcdef",
			ComponentName: "api",
			State:         paasv1.DeploymentInstanceRunning,
			Health:        paasv1.DeploymentInstanceHealthHealthy,
		}},
		ObservedAt: lifecycleTime.Add(-time.Second),
	}
	transaction.deploymentRuntime = paasv1.DeploymentRuntimeSnapshot{
		APIVersion: paasv1.APIVersion,
		Kind:       "DeploymentRuntimeSnapshot",
		Scope:      paasv1.ResourceScope{Kind: paasv1.AuthorityTenant, TenantID: "tenant-a"},
		State:      paasv1.MeasurementAvailable,
		Value: &paasv1.DeploymentRuntimeValue{
			Observation: observation,
			ValidUntil:  lifecycleTime.Add(10 * time.Second),
		},
	}
	transaction.deploymentRuntimeFound = true
	repository := &fakeLifecycleRepository{transaction: transaction}

	result, err := mustLifecycleUsecase(t, repository).GetDeploymentRuntime(
		context.Background(),
		lifecycleAuthorization(),
		"deployment-a",
	)
	if err != nil {
		t.Fatalf("get Deployment runtime: %v", err)
	}
	if len(repository.tenantIDs) != 1 || repository.tenantIDs[0] != "tenant-a" ||
		result.Value == nil || result.Value.Observation.ObservedAt != observation.ObservedAt ||
		paasv1.ValidateDeploymentRuntimeSnapshot(result) != nil {
		t.Fatalf("tenant/runtime = %#v/%#v", repository.tenantIDs, result)
	}
}

type fakeLifecycleRepository struct {
	transaction         Transaction
	afterCallbackErrors []error
	calls               int
	tenantIDs           []paasv1.TenantID
}

func (repository *fakeLifecycleRepository) WithinTransaction(
	ctx context.Context,
	tenantID paasv1.TenantID,
	callback func(context.Context, Transaction) error,
) error {
	repository.calls++
	repository.tenantIDs = append(repository.tenantIDs, tenantID)
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
	now                        time.Time
	deployment                 paasv1.Deployment
	deploymentFound            bool
	deployments                []paasv1.Deployment
	nextDeploymentAfter        paasv1.ResourceID
	deploymentRuntime          paasv1.DeploymentRuntimeSnapshot
	deploymentRuntimeFound     bool
	revision                   paasv1.ApplicationRevision
	revisionFound              bool
	policy                     paasv1.PlacementPolicy
	storedOperation            paasv1.Operation
	operationFound             bool
	acceptedGenerations        map[uint64]paasv1.DeploymentGeneration
	generationByOperation      paasv1.DeploymentGeneration
	configurationError         error
	submission                 *Submission
	application                paasv1.Application
	applicationFound           bool
	configuration              paasv1.Configuration
	configurationFound         bool
	configurationRevision      paasv1.ConfigurationRevision
	configurationRevisionFound bool
	loadedOperation            paasv1.Operation
	loadedOperationFound       bool
	resourceSubmission         *ResourceSubmission
	listAfter                  paasv1.ResourceID
	listLimit                  int
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
	_ context.Context,
	id paasv1.ResourceID,
) (paasv1.Deployment, bool, error) {
	if transaction.deployment.Metadata.ID != id {
		return paasv1.Deployment{}, false, nil
	}
	return transaction.deployment, transaction.deploymentFound, nil
}

func (transaction *fakeLifecycleTransaction) ListDeployments(
	_ context.Context,
	after paasv1.ResourceID,
	limit int,
) ([]paasv1.Deployment, paasv1.ResourceID, error) {
	transaction.listAfter, transaction.listLimit = after, limit
	return append([]paasv1.Deployment{}, transaction.deployments...), transaction.nextDeploymentAfter, nil
}

func (transaction *fakeLifecycleTransaction) LoadDeploymentRuntime(
	_ context.Context,
	_ paasv1.ResourceID,
) (paasv1.DeploymentRuntimeSnapshot, bool, error) {
	return transaction.deploymentRuntime, transaction.deploymentRuntimeFound, nil
}

func (transaction *fakeLifecycleTransaction) LoadApplication(
	_ context.Context,
	id paasv1.ResourceID,
) (paasv1.Application, bool, error) {
	if transaction.application.Metadata.ID != id {
		return paasv1.Application{}, false, nil
	}
	return transaction.application, transaction.applicationFound, nil
}

func (transaction *fakeLifecycleTransaction) LoadConfiguration(
	_ context.Context,
	id paasv1.ResourceID,
) (paasv1.Configuration, bool, error) {
	if transaction.configuration.Metadata.ID != id {
		return paasv1.Configuration{}, false, nil
	}
	return transaction.configuration, transaction.configurationFound, nil
}

func (transaction *fakeLifecycleTransaction) LoadConfigurationRevision(
	_ context.Context,
	id paasv1.ResourceID,
) (paasv1.ConfigurationRevision, bool, error) {
	if transaction.configurationRevision.Metadata.ID != id {
		return paasv1.ConfigurationRevision{}, false, nil
	}
	return transaction.configurationRevision, transaction.configurationRevisionFound, nil
}

func (transaction *fakeLifecycleTransaction) LoadApplicationRevision(
	_ context.Context,
	id paasv1.ResourceID,
) (paasv1.ApplicationRevision, error) {
	if !transaction.revisionFound || transaction.revision.Metadata.ID != id {
		return paasv1.ApplicationRevision{}, ErrNotFound
	}
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

func (transaction *fakeLifecycleTransaction) LoadOperation(
	_ context.Context,
	id paasv1.OperationID,
) (paasv1.Operation, bool, error) {
	if transaction.loadedOperation.ID != id {
		return paasv1.Operation{}, false, nil
	}
	return transaction.loadedOperation, transaction.loadedOperationFound, nil
}

func (transaction *fakeLifecycleTransaction) CreateApplication(
	_ context.Context,
	value paasv1.Application,
	submission ResourceSubmission,
) error {
	transaction.application, transaction.applicationFound = value, true
	transaction.resourceSubmission = &submission
	return nil
}

func (transaction *fakeLifecycleTransaction) CreateConfiguration(
	_ context.Context,
	value paasv1.Configuration,
	submission ResourceSubmission,
) error {
	transaction.configuration, transaction.configurationFound = value, true
	transaction.resourceSubmission = &submission
	return nil
}

func (transaction *fakeLifecycleTransaction) CreateConfigurationRevision(
	_ context.Context,
	value paasv1.ConfigurationRevision,
	submission ResourceSubmission,
) error {
	transaction.configurationRevision, transaction.configurationRevisionFound = value, true
	transaction.resourceSubmission = &submission
	return nil
}

func (transaction *fakeLifecycleTransaction) CreateApplicationRevision(
	_ context.Context,
	value paasv1.ApplicationRevision,
	submission ResourceSubmission,
) error {
	transaction.revision = value
	transaction.revisionFound = true
	transaction.resourceSubmission = &submission
	return nil
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
		revisionFound:       true,
		policy:              lifecyclePolicy(),
		acceptedGenerations: make(map[uint64]paasv1.DeploymentGeneration),
	}
}

func lifecycleCreateCommand() SubmitCommand {
	return SubmitCommand{
		Authorization:  lifecycleAuthorization(),
		DeploymentID:   "deployment-a",
		Name:           "deployment-a",
		Spec:           lifecycleSpec("config-revision-a"),
		IdempotencyKey: "create-deployment-a",
	}
}

func lifecycleUpdateCommand(
	current paasv1.Deployment,
	configurationRevisionID paasv1.ResourceID,
) SubmitCommand {
	return SubmitCommand{
		Authorization:           lifecycleAuthorization(),
		DeploymentID:            current.Metadata.ID,
		Spec:                    lifecycleSpec(configurationRevisionID),
		ExpectedResourceVersion: current.Metadata.ResourceVersion,
		IdempotencyKey:          "update-deployment-a-" + string(configurationRevisionID),
	}
}

func lifecycleAuthorization() port.Authorization {
	return port.Authorization{
		TenantID:   "tenant-a",
		Subject:    lifecycleRequester(),
		DecisionID: "decision-a",
		RequestID:  "request-a",
		AuditID:    "audit-flow-a",
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
