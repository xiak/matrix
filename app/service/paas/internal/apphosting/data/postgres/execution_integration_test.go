package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/port"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/applicationlifecycle"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/createplacement"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/operationqueue"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/reconciledeployment"
)

func assertInPlaceReplacementWorkflow(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	apiPool *pgxpool.Pool,
	workerPool *pgxpool.Pool,
	placementUsecase *createplacement.Usecase,
	fixture integrationFixture,
	prefix string,
) {
	t.Helper()
	executor := &postgresWorkerExecutor{
		t: t, ctx: ctx, admin: admin, fixture: fixture,
		plans: make(map[paasv1.OperationID]*postgresWorkerPlan),
	}
	workerFixture := newDeploymentWorkerFixture(
		t, apiPool, workerPool, placementUsecase, executor, fixture.targetID, "compose-local", 10*time.Second,
	)
	requestedBy := paasv1.SubjectRef{Type: paasv1.SubjectUser, ID: "replacement-integration-user"}
	deploymentID := paasv1.ResourceID(prefix + "-replacement-deployment")
	created := submitWorkerDeployment(t, ctx, workerFixture.application, applicationlifecycle.SubmitCommand{
		Authorization:  integrationAuthorization(fixture.tenantA, requestedBy, "replacement-deploy"),
		DeploymentID:   deploymentID,
		Name:           "replacement-deployment",
		Spec:           applicationIntegrationSpec(fixture, fixture.configurationRevisionIDs[0]),
		IdempotencyKey: "replacement-deploy",
	}, paasv1.OperationDeploy)
	executor.expect(created.Operation.ID, postgresWorkerPlan{
		method: "apply", resultState: paasv1.AdapterResultSucceeded,
		observationPhase: paasv1.DeploymentReady, expectedConsuming: 1,
		expectedConfigurationRevisionID: fixture.configurationRevisionIDs[0],
	})
	processWorkerOperation(t, ctx, workerFixture.worker)
	ready, operation := loadWorkerOutcome(t, ctx, admin, fixture.tenantA, deploymentID, created.Operation.ID)
	assertWorkerOutcome(t, ready, operation, 1, 1, paasv1.DeploymentReady, paasv1.OperationSucceeded)
	firstTarget := operationPlacementTargetID(t, ctx, admin, fixture.tenantA, created.Operation.ID)

	updated := submitWorkerDeployment(t, ctx, workerFixture.application, applicationlifecycle.SubmitCommand{
		Authorization:           integrationAuthorization(fixture.tenantA, requestedBy, "replacement-update"),
		DeploymentID:            deploymentID,
		Spec:                    applicationIntegrationSpec(fixture, fixture.configurationRevisionIDs[1]),
		ExpectedResourceVersion: ready.Metadata.ResourceVersion,
		IdempotencyKey:          "replacement-update",
	}, paasv1.OperationUpdate)
	executor.expect(updated.Operation.ID, postgresWorkerPlan{
		method: "apply", resultState: paasv1.AdapterResultSucceeded,
		observationPhase: paasv1.DeploymentReady, expectedConsuming: 2,
		expectedConfigurationRevisionID: fixture.configurationRevisionIDs[1],
	})
	processWorkerOperation(t, ctx, workerFixture.worker)
	ready, operation = loadWorkerOutcome(t, ctx, admin, fixture.tenantA, deploymentID, updated.Operation.ID)
	assertWorkerOutcome(t, ready, operation, 2, 2, paasv1.DeploymentReady, paasv1.OperationSucceeded)
	if nextTarget := operationPlacementTargetID(t, ctx, admin, fixture.tenantA, updated.Operation.ID); nextTarget != firstTarget {
		t.Fatalf("replacement moved from target %q to %q", firstTarget, nextTarget)
	}
	assertConsumingClaims(t, ctx, admin, fixture.targetID, 1)

	stopSpec := ready.Spec
	stopSpec.DesiredState = paasv1.DeploymentDesiredStopped
	stopping := submitWorkerDeployment(t, ctx, workerFixture.application, applicationlifecycle.SubmitCommand{
		Authorization:           integrationAuthorization(fixture.tenantA, requestedBy, "replacement-stop"),
		DeploymentID:            deploymentID,
		Spec:                    stopSpec,
		ExpectedResourceVersion: ready.Metadata.ResourceVersion,
		IdempotencyKey:          "replacement-stop",
	}, paasv1.OperationStop)
	executor.expect(stopping.Operation.ID, postgresWorkerPlan{
		method: "stop", resultState: paasv1.AdapterResultSucceeded,
		observationPhase: paasv1.DeploymentStopped, expectedConsuming: 1,
		expectedConfigurationRevisionID: fixture.configurationRevisionIDs[1],
	})
	processWorkerOperation(t, ctx, workerFixture.worker)
	stopped, operation := loadWorkerOutcome(t, ctx, admin, fixture.tenantA, deploymentID, stopping.Operation.ID)
	assertWorkerOutcome(t, stopped, operation, 3, 3, paasv1.DeploymentStopped, paasv1.OperationSucceeded)
	assertConsumingClaims(t, ctx, admin, fixture.targetID, 0)
}

func assertDeploymentWorkerWorkflow(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	apiPool *pgxpool.Pool,
	workerPool *pgxpool.Pool,
	placementUsecase *createplacement.Usecase,
	fixture integrationFixture,
	prefix string,
) {
	t.Helper()
	expandExecutionTargetCapacity(t, ctx, admin, fixture.targetID)
	executor := &postgresWorkerExecutor{
		t: t, ctx: ctx, admin: admin, fixture: fixture,
		plans: make(map[paasv1.OperationID]*postgresWorkerPlan),
	}
	workerFixture := newDeploymentWorkerFixture(
		t, apiPool, workerPool, placementUsecase, executor, fixture.targetID, "compose-local", 10*time.Second,
	)
	applicationUsecase := workerFixture.application
	worker := workerFixture.worker
	executionRepository := workerFixture.repository

	requestedBy := paasv1.SubjectRef{
		Type: paasv1.SubjectUser,
		ID:   "worker-integration-user",
	}
	deploymentID := paasv1.ResourceID(prefix + "-worker-deployment")
	created := submitWorkerDeployment(
		t,
		ctx,
		applicationUsecase,
		applicationlifecycle.SubmitCommand{
			Authorization: integrationAuthorization(fixture.tenantA, requestedBy, "worker-deploy"),
			DeploymentID:  deploymentID,
			Name:          "worker-deployment",
			Spec: applicationIntegrationSpec(
				fixture,
				fixture.configurationRevisionIDs[0],
			),
			IdempotencyKey: "worker-deploy",
		},
		paasv1.OperationDeploy,
	)
	executor.expect(created.Operation.ID, postgresWorkerPlan{
		method: "apply", resultState: paasv1.AdapterResultSucceeded,
		observationPhase: paasv1.DeploymentReady, expectedConsuming: 1,
		expectedConfigurationRevisionID: fixture.configurationRevisionIDs[0],
	})
	processWorkerOperation(t, ctx, worker)
	ready, operation := loadWorkerOutcome(t, ctx, admin, fixture.tenantA, deploymentID, created.Operation.ID)
	assertWorkerOutcome(t, ready, operation, 1, 1, paasv1.DeploymentReady, paasv1.OperationSucceeded)
	if _, err := executionRepository.Load(ctx, operationqueue.LeaseGuard{
		TenantID: fixture.tenantA, OperationID: created.Operation.ID,
		WorkerID: "worker-reconcile", FencingToken: 1,
	}); !errors.Is(err, reconciledeployment.ErrStaleLease) {
		t.Fatalf("terminal worker read error = %v, want stale lease", err)
	}
	firstPlacement := ready.Status.PlacementDecisionID
	assertReservationState(t, ctx, admin, fixture.tenantA, firstPlacement, "ACTIVE")
	assertConsumingClaims(t, ctx, admin, fixture.targetID, 1)

	updated := submitWorkerDeployment(
		t,
		ctx,
		applicationUsecase,
		applicationlifecycle.SubmitCommand{
			Authorization: integrationAuthorization(fixture.tenantA, requestedBy, "worker-update"),
			DeploymentID:  deploymentID,
			Spec: applicationIntegrationSpec(
				fixture,
				fixture.configurationRevisionIDs[1],
			),
			ExpectedResourceVersion: ready.Metadata.ResourceVersion,
			IdempotencyKey:          "worker-update",
		},
		paasv1.OperationUpdate,
	)
	if updated.Deployment.Status.PlacementDecisionID != firstPlacement {
		t.Fatalf("update discarded last observed placement: %#v", updated.Deployment.Status)
	}
	executor.expect(updated.Operation.ID, postgresWorkerPlan{
		method: "apply", resultState: paasv1.AdapterResultSucceeded,
		observationPhase: paasv1.DeploymentReady, expectedConsuming: 2,
		expectedConfigurationRevisionID: fixture.configurationRevisionIDs[1],
	})
	processWorkerOperation(t, ctx, worker)
	ready, operation = loadWorkerOutcome(t, ctx, admin, fixture.tenantA, deploymentID, updated.Operation.ID)
	assertWorkerOutcome(t, ready, operation, 2, 2, paasv1.DeploymentReady, paasv1.OperationSucceeded)
	secondPlacement := ready.Status.PlacementDecisionID
	if secondPlacement == firstPlacement {
		t.Fatal("update reused the prior generation placement decision")
	}
	assertReservationState(t, ctx, admin, fixture.tenantA, firstPlacement, "RELEASED")
	assertReservationState(t, ctx, admin, fixture.tenantA, secondPlacement, "ACTIVE")
	assertConsumingClaims(t, ctx, admin, fixture.targetID, 1)

	rolledBack, err := applicationUsecase.Rollback(ctx, applicationlifecycle.RollbackCommand{
		Authorization:    integrationAuthorization(fixture.tenantA, requestedBy, "worker-rollback"),
		DeploymentID:     deploymentID,
		SourceGeneration: 1, ExpectedResourceVersion: ready.Metadata.ResourceVersion,
		IdempotencyKey: "worker-rollback",
	})
	if err != nil {
		t.Fatalf("submit worker rollback: %v", err)
	}
	if rolledBack.Operation.Action != paasv1.OperationRollback ||
		rolledBack.Generation.Generation != 3 ||
		workerConfigurationRevisionID(t, rolledBack.Deployment) != fixture.configurationRevisionIDs[0] {
		t.Fatalf("rollback desired snapshot = %#v", rolledBack)
	}
	executor.expect(rolledBack.Operation.ID, postgresWorkerPlan{
		method: "rollback", resultState: paasv1.AdapterResultSucceeded,
		observationPhase: paasv1.DeploymentReady, expectedConsuming: 2,
		expectedConfigurationRevisionID: fixture.configurationRevisionIDs[0],
	})
	processWorkerOperation(t, ctx, worker)
	ready, operation = loadWorkerOutcome(
		t, ctx, admin, fixture.tenantA, deploymentID, rolledBack.Operation.ID,
	)
	assertWorkerOutcome(t, ready, operation, 3, 3, paasv1.DeploymentReady, paasv1.OperationSucceeded)
	thirdPlacement := ready.Status.PlacementDecisionID
	assertReservationState(t, ctx, admin, fixture.tenantA, secondPlacement, "RELEASED")
	assertReservationState(t, ctx, admin, fixture.tenantA, thirdPlacement, "ACTIVE")
	assertConsumingClaims(t, ctx, admin, fixture.targetID, 1)

	reservationsBeforeStop := countTenantReservations(t, ctx, admin, fixture.tenantA)
	stopSpec := ready.Spec
	stopSpec.DesiredState = paasv1.DeploymentDesiredStopped
	stopping := submitWorkerDeployment(
		t,
		ctx,
		applicationUsecase,
		applicationlifecycle.SubmitCommand{
			Authorization: integrationAuthorization(fixture.tenantA, requestedBy, "worker-stop"),
			DeploymentID:  deploymentID,
			Spec:          stopSpec, ExpectedResourceVersion: ready.Metadata.ResourceVersion,
			IdempotencyKey: "worker-stop",
		},
		paasv1.OperationStop,
	)
	if stopping.Deployment.Status.PlacementDecisionID != thirdPlacement {
		t.Fatalf("stop discarded the active placement before observation: %#v", stopping.Deployment.Status)
	}
	executor.expect(stopping.Operation.ID, postgresWorkerPlan{
		method: "stop", resultState: paasv1.AdapterResultSucceeded,
		observationPhase: paasv1.DeploymentStopped, expectedConsuming: 1,
		expectedConfigurationRevisionID: fixture.configurationRevisionIDs[0],
	})
	processWorkerOperation(t, ctx, worker)
	stopped, operation := loadWorkerOutcome(
		t, ctx, admin, fixture.tenantA, deploymentID, stopping.Operation.ID,
	)
	assertWorkerOutcome(t, stopped, operation, 4, 4, paasv1.DeploymentStopped, paasv1.OperationSucceeded)
	if stopped.Status.PlacementDecisionID != "" || stopped.Status.ReadyComponents != 0 {
		t.Fatalf("stopped Deployment retained runtime status: %#v", stopped.Status)
	}
	assertReservationState(t, ctx, admin, fixture.tenantA, thirdPlacement, "RELEASED")
	if countTenantReservations(t, ctx, admin, fixture.tenantA) != reservationsBeforeStop {
		t.Fatal("stop created a second capacity reservation instead of binding the active one")
	}
	assertOperationHasNoReservation(t, ctx, admin, fixture.tenantA, stopping.Operation.ID)
	assertConsumingClaims(t, ctx, admin, fixture.targetID, 0)

	failureID := paasv1.ResourceID(prefix + "-worker-failure")
	failure := submitWorkerDeployment(
		t,
		ctx,
		applicationUsecase,
		applicationlifecycle.SubmitCommand{
			Authorization: integrationAuthorization(fixture.tenantA, requestedBy, "worker-failure"),
			DeploymentID:  failureID, Name: "worker-failure",
			Spec:           applicationIntegrationSpec(fixture, fixture.configurationRevisionIDs[0]),
			IdempotencyKey: "worker-failure",
		},
		paasv1.OperationDeploy,
	)
	executor.expect(failure.Operation.ID, postgresWorkerPlan{
		method: "apply", resultState: paasv1.AdapterResultFailed,
		expectedConsuming:               1,
		expectedConfigurationRevisionID: fixture.configurationRevisionIDs[0],
	})
	processWorkerOperation(t, ctx, worker)
	failed, operation := loadWorkerOutcome(
		t, ctx, admin, fixture.tenantA, failureID, failure.Operation.ID,
	)
	assertWorkerOutcome(t, failed, operation, 1, 0, paasv1.DeploymentFailed, paasv1.OperationFailed)
	failurePlacement := operationPlacementID(t, ctx, admin, fixture.tenantA, failure.Operation.ID)
	assertReservationState(t, ctx, admin, fixture.tenantA, failurePlacement, "RELEASED")
	assertOperationReceiptState(t, ctx, admin, fixture.tenantA, failure.Operation.ID, "FAILED")
	assertConsumingClaims(t, ctx, admin, fixture.targetID, 0)

	unknownID := paasv1.ResourceID(prefix + "-worker-unknown")
	unknown := submitWorkerDeployment(
		t,
		ctx,
		applicationUsecase,
		applicationlifecycle.SubmitCommand{
			Authorization: integrationAuthorization(fixture.tenantA, requestedBy, "worker-unknown"),
			DeploymentID:  unknownID, Name: "worker-unknown",
			Spec:           applicationIntegrationSpec(fixture, fixture.configurationRevisionIDs[1]),
			IdempotencyKey: "worker-unknown",
		},
		paasv1.OperationDeploy,
	)
	executor.expect(unknown.Operation.ID, postgresWorkerPlan{
		method: "apply", resultState: paasv1.AdapterResultUnknown,
		observationPhase: paasv1.DeploymentReady, expectedConsuming: 1,
		expectedConfigurationRevisionID: fixture.configurationRevisionIDs[1],
	})
	processWorkerOperation(t, ctx, worker)
	reconciling, operation := loadWorkerOutcome(
		t, ctx, admin, fixture.tenantA, unknownID, unknown.Operation.ID,
	)
	if operation.State != paasv1.OperationReconciling ||
		reconciling.Status.Phase != paasv1.DeploymentApplying ||
		operation.TerminalAt != nil {
		t.Fatalf("unknown effect was not retained for reconciliation: %#v / %#v", reconciling, operation)
	}
	assertOperationLeaseReleased(t, ctx, admin, fixture.tenantA, unknown.Operation.ID)
	assertOperationReceiptState(t, ctx, admin, fixture.tenantA, unknown.Operation.ID, "UNKNOWN")
	assertConsumingClaims(t, ctx, admin, fixture.targetID, 1)
	processDueWorkerOperation(t, ctx, worker)
	reconciled, operation := loadWorkerOutcome(
		t, ctx, admin, fixture.tenantA, unknownID, unknown.Operation.ID,
	)
	assertWorkerOutcome(t, reconciled, operation, 1, 1, paasv1.DeploymentReady, paasv1.OperationSucceeded)
	plan := executor.plans[unknown.Operation.ID]
	if plan.effectCalls != 1 || plan.observeCalls != 1 {
		t.Fatalf("unknown outcome replayed an effect before observation: %#v", plan)
	}
	assertReservationState(
		t,
		ctx,
		admin,
		fixture.tenantA,
		reconciled.Status.PlacementDecisionID,
		"ACTIVE",
	)
	assertConsumingClaims(t, ctx, admin, fixture.targetID, 1)

	manualID := paasv1.ResourceID(prefix + "-worker-manual")
	manual := submitWorkerDeployment(
		t,
		ctx,
		applicationUsecase,
		applicationlifecycle.SubmitCommand{
			Authorization: integrationAuthorization(fixture.tenantA, requestedBy, "worker-manual"),
			DeploymentID:  manualID, Name: "worker-manual",
			Spec:           applicationIntegrationSpec(fixture, fixture.configurationRevisionIDs[0]),
			IdempotencyKey: "worker-manual",
		},
		paasv1.OperationDeploy,
	)
	executor.expect(manual.Operation.ID, postgresWorkerPlan{
		method: "apply", resultState: paasv1.AdapterResultUnknown,
		observationError: true, expectedConsuming: 2,
		expectedConfigurationRevisionID: fixture.configurationRevisionIDs[0],
	})
	processWorkerOperation(t, ctx, worker)
	processDueWorkerOperation(t, ctx, worker)
	processDueWorkerOperation(t, ctx, worker)
	manualDeployment, operation := loadWorkerOutcome(
		t, ctx, admin, fixture.tenantA, manualID, manual.Operation.ID,
	)
	assertWorkerOutcome(
		t,
		manualDeployment,
		operation,
		1,
		0,
		paasv1.DeploymentFailed,
		paasv1.OperationManualIntervention,
	)
	manualPlan := executor.plans[manual.Operation.ID]
	if manualPlan.effectCalls != 1 || manualPlan.observeCalls != 1 {
		t.Fatalf("manual intervention effect calls = %#v", manualPlan)
	}
	manualPlacement := operationPlacementID(t, ctx, admin, fixture.tenantA, manual.Operation.ID)
	assertReservationState(t, ctx, admin, fixture.tenantA, manualPlacement, "ACTIVE")
	assertConsumingClaims(t, ctx, admin, fixture.targetID, 2)
}

type deploymentWorkerFixture struct {
	application *applicationlifecycle.Usecase
	worker      *reconciledeployment.Worker
	repository  *DeploymentExecutionRepository
}

func newDeploymentWorkerFixture(
	t *testing.T,
	apiPool *pgxpool.Pool,
	workerPool *pgxpool.Pool,
	placementUsecase *createplacement.Usecase,
	executor port.DeploymentExecutor,
	executionTargetID paasv1.ResourceID,
	bindingRef string,
	effectTimeout time.Duration,
) deploymentWorkerFixture {
	t.Helper()
	applicationRepository, err := NewApplicationRepository(apiPool)
	if err != nil {
		t.Fatalf("create worker application repository: %v", err)
	}
	applicationUsecase, err := applicationlifecycle.NewUsecase(
		applicationRepository,
		applicationlifecycle.Config{MaxTransactionAttempts: 5},
	)
	if err != nil {
		t.Fatalf("create worker application lifecycle use case: %v", err)
	}
	queueRepository, err := NewOperationQueueRepository(workerPool)
	if err != nil {
		t.Fatalf("create worker Operation queue repository: %v", err)
	}
	queue, err := operationqueue.NewQueue(
		queueRepository,
		operationqueue.Config{LeaseDuration: 30 * time.Second},
	)
	if err != nil {
		t.Fatalf("create worker Operation queue: %v", err)
	}
	executionRepository, err := NewDeploymentExecutionRepository(workerPool)
	if err != nil {
		t.Fatalf("create Deployment execution repository: %v", err)
	}
	worker, err := reconciledeployment.NewWorker(
		queue,
		placementUsecase,
		executionRepository,
		[]reconciledeployment.DeploymentRoute{{
			ExecutionTargetID: executionTargetID, BindingRef: bindingRef, Executor: executor,
		}},
		reconciledeployment.Config{
			EffectTimeout:    effectTimeout,
			ReconcileBackoff: time.Millisecond, MaxAttempts: 3,
			Clock: func() time.Time {
				return time.Now().UTC().Truncate(time.Microsecond)
			},
		},
	)
	if err != nil {
		t.Fatalf("create Deployment reconciliation worker: %v", err)
	}
	return deploymentWorkerFixture{
		application: applicationUsecase, worker: worker, repository: executionRepository,
	}
}

func submitWorkerDeployment(
	t *testing.T,
	ctx context.Context,
	usecase *applicationlifecycle.Usecase,
	command applicationlifecycle.SubmitCommand,
	wantAction paasv1.OperationAction,
) applicationlifecycle.Result {
	t.Helper()
	result, err := usecase.Submit(ctx, command)
	if err != nil {
		t.Fatalf("submit worker Deployment: %v", err)
	}
	if result.Replayed || result.Operation.Action != wantAction ||
		result.Operation.State != paasv1.OperationAccepted {
		t.Fatalf("submitted worker Deployment = %#v", result)
	}
	return result
}

func processWorkerOperation(
	t *testing.T,
	ctx context.Context,
	worker *reconciledeployment.Worker,
) {
	t.Helper()
	found, err := worker.ProcessNext(ctx, "worker-reconcile")
	if err != nil || !found {
		t.Fatalf("process worker Operation found/error = %v/%v", found, err)
	}
}

func processDueWorkerOperation(
	t *testing.T,
	ctx context.Context,
	worker *reconciledeployment.Worker,
) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		found, err := worker.ProcessNext(ctx, "worker-reconcile")
		if err != nil {
			t.Fatalf("process due worker Operation: %v", err)
		}
		if found {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("reconciliation Operation did not become due")
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func expandExecutionTargetCapacity(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	targetID paasv1.ResourceID,
) {
	t.Helper()
	var resourceVersion uint64
	var document []byte
	if err := admin.QueryRow(
		ctx,
		"SELECT resource_version, document FROM paas.execution_targets WHERE id = $1",
		targetID,
	).Scan(&resourceVersion, &document); err != nil {
		t.Fatalf("load worker ExecutionTarget: %v", err)
	}
	var target paasv1.ExecutionTarget
	if err := decodeDocument("ExecutionTarget", document, &target); err != nil {
		t.Fatalf("decode worker ExecutionTarget: %v", err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	target.Metadata.ResourceVersion = resourceVersion + 1
	target.Metadata.UpdatedAt = now
	target.Status.Capacity = paasv1.Capacity{
		CPUMillis: 200, MemoryBytes: 64 * 1024 * 1024, WorkloadSlots: 2,
	}
	target.Status.Allocatable = target.Status.Capacity
	target.Status.ObservedAt = now
	if err := paasv1.ValidateExecutionTarget(target); err != nil {
		t.Fatalf("expand invalid ExecutionTarget: %v", err)
	}
	commandTag, err := admin.Exec(
		ctx,
		`UPDATE paas.execution_targets
		    SET resource_version = $2, document = $3::jsonb
		  WHERE id = $1 AND resource_version = $4`,
		targetID,
		target.Metadata.ResourceVersion,
		integrationJSON(t, target),
		resourceVersion,
	)
	if err != nil {
		t.Fatalf("expand ExecutionTarget capacity: %v", err)
	}
	if commandTag.RowsAffected() != 1 {
		t.Fatal("ExecutionTarget capacity update lost its resource-version race")
	}
}

func loadWorkerOutcome(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	tenantID paasv1.TenantID,
	deploymentID paasv1.ResourceID,
	operationID paasv1.OperationID,
) (paasv1.Deployment, paasv1.Operation) {
	t.Helper()
	var deploymentDocument []byte
	var operationDocument []byte
	if err := admin.QueryRow(
		ctx,
		`SELECT deployment.document, operation.document
		   FROM paas.deployments AS deployment
		   JOIN paas.operations AS operation
		     ON operation.tenant_id = deployment.tenant_id
		    AND operation.target_id = deployment.id
		  WHERE deployment.tenant_id = $1
		    AND deployment.id = $2
		    AND operation.id = $3`,
		tenantID,
		deploymentID,
		operationID,
	).Scan(&deploymentDocument, &operationDocument); err != nil {
		t.Fatalf("load worker outcome: %v", err)
	}
	var deployment paasv1.Deployment
	var operation paasv1.Operation
	if err := decodeDocument("Deployment", deploymentDocument, &deployment); err != nil {
		t.Fatalf("decode worker Deployment: %v", err)
	}
	if err := decodeDocument("Operation", operationDocument, &operation); err != nil {
		t.Fatalf("decode worker Operation: %v", err)
	}
	if err := paasv1.ValidateDeployment(deployment); err != nil {
		t.Fatalf("validate worker Deployment: %v", err)
	}
	if err := paasv1.ValidateOperation(operation); err != nil {
		t.Fatalf("validate worker Operation: %v", err)
	}
	return deployment, operation
}

func assertWorkerOutcome(
	t *testing.T,
	deployment paasv1.Deployment,
	operation paasv1.Operation,
	wantGeneration uint64,
	wantObservedGeneration uint64,
	wantPhase paasv1.DeploymentPhase,
	wantState paasv1.OperationState,
) {
	t.Helper()
	if deployment.Generation != wantGeneration ||
		deployment.Status.ObservedGeneration != wantObservedGeneration ||
		deployment.Status.Phase != wantPhase ||
		deployment.Status.CurrentOperationID != operation.ID ||
		operation.State != wantState ||
		operation.TerminalAt == nil {
		t.Fatalf("worker outcome = Deployment %#v / Operation %#v", deployment, operation)
	}
}

func workerConfigurationRevisionID(
	t *testing.T,
	deployment paasv1.Deployment,
) paasv1.ResourceID {
	t.Helper()
	if len(deployment.Spec.Components) != 1 {
		t.Fatalf("worker Deployment bindings = %#v", deployment.Spec.Components)
	}
	var found paasv1.ResourceID
	for _, binding := range deployment.Spec.Components[0].Bindings {
		if binding.ConfigurationRevisionID == "" {
			continue
		}
		if found != "" {
			t.Fatalf("worker Deployment has multiple configuration bindings: %#v", deployment.Spec.Components)
		}
		found = binding.ConfigurationRevisionID
	}
	if found == "" {
		t.Fatalf("worker Deployment has no configuration binding: %#v", deployment.Spec.Components)
	}
	return found
}

func assertReservationState(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	tenantID paasv1.TenantID,
	decisionID paasv1.ResourceID,
	want string,
) {
	t.Helper()
	var state string
	if err := admin.QueryRow(
		ctx,
		`SELECT claim.state
		   FROM paas.capacity_reservations AS reservation
		   JOIN paas.capacity_claims AS claim
		     ON claim.id = reservation.capacity_claim_id
		  WHERE reservation.tenant_id = $1 AND reservation.decision_id = $2`,
		tenantID,
		decisionID,
	).Scan(&state); err != nil {
		t.Fatalf("load reservation state for %q: %v", decisionID, err)
	}
	if state != want {
		t.Fatalf("reservation %q state = %q, want %q", decisionID, state, want)
	}
}

func assertConsumingClaims(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	targetID paasv1.ResourceID,
	want int,
) {
	t.Helper()
	var count int
	if err := admin.QueryRow(
		ctx,
		`SELECT count(*)
		   FROM paas.capacity_claims
		  WHERE execution_target_id = $1
		    AND (
		        state = 'ACTIVE'
		        OR (state = 'PENDING' AND lease_expires_at > transaction_timestamp())
		    )`,
		targetID,
	).Scan(&count); err != nil {
		t.Fatalf("count consuming capacity claims: %v", err)
	}
	if count != want {
		t.Fatalf("consuming capacity claims = %d, want %d", count, want)
	}
}

func countTenantReservations(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	tenantID paasv1.TenantID,
) int {
	t.Helper()
	var count int
	if err := admin.QueryRow(
		ctx,
		"SELECT count(*) FROM paas.capacity_reservations WHERE tenant_id = $1",
		tenantID,
	).Scan(&count); err != nil {
		t.Fatalf("count tenant capacity reservations: %v", err)
	}
	return count
}

func assertOperationHasNoReservation(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	tenantID paasv1.TenantID,
	operationID paasv1.OperationID,
) {
	t.Helper()
	var count int
	if err := admin.QueryRow(
		ctx,
		`SELECT count(*)
		   FROM paas.placement_decisions AS decision
		   JOIN paas.capacity_reservations AS reservation
		     ON reservation.tenant_id = decision.tenant_id
		    AND reservation.decision_id = decision.id
		  WHERE decision.tenant_id = $1 AND decision.operation_id = $2`,
		tenantID,
		operationID,
	).Scan(&count); err != nil {
		t.Fatalf("inspect stop capacity reservation: %v", err)
	}
	if count != 0 {
		t.Fatalf("stop Operation created %d capacity reservations", count)
	}
}

func operationPlacementID(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	tenantID paasv1.TenantID,
	operationID paasv1.OperationID,
) paasv1.ResourceID {
	t.Helper()
	var decisionID string
	if err := admin.QueryRow(
		ctx,
		"SELECT id FROM paas.placement_decisions WHERE tenant_id = $1 AND operation_id = $2",
		tenantID,
		operationID,
	).Scan(&decisionID); err != nil {
		t.Fatalf("load Operation placement decision: %v", err)
	}
	return paasv1.ResourceID(decisionID)
}

func operationPlacementTargetID(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	tenantID paasv1.TenantID,
	operationID paasv1.OperationID,
) paasv1.ResourceID {
	t.Helper()
	var targetID string
	if err := admin.QueryRow(
		ctx,
		"SELECT execution_target_id FROM paas.placement_decisions WHERE tenant_id = $1 AND operation_id = $2",
		tenantID,
		operationID,
	).Scan(&targetID); err != nil {
		t.Fatalf("load Operation placement target: %v", err)
	}
	return paasv1.ResourceID(targetID)
}

func assertOperationReceiptState(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	tenantID paasv1.TenantID,
	operationID paasv1.OperationID,
	want string,
) {
	t.Helper()
	var state string
	if err := admin.QueryRow(
		ctx,
		`SELECT receipt.state
		   FROM paas.adapter_receipts AS receipt
		   JOIN paas.adapter_commands AS command
		     ON command.tenant_id = receipt.tenant_id
		    AND command.id = receipt.command_id
		  WHERE command.tenant_id = $1
		    AND command.operation_id = $2
		    AND command.action <> 'OBSERVE_DEPLOYMENT'`,
		tenantID,
		operationID,
	).Scan(&state); err != nil {
		t.Fatalf("load Operation receipt: %v", err)
	}
	if state != want {
		t.Fatalf("Operation receipt state = %q, want %q", state, want)
	}
}

func assertOperationLeaseReleased(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	tenantID paasv1.TenantID,
	operationID paasv1.OperationID,
) {
	t.Helper()
	var owner *string
	var expiresAt *time.Time
	if err := admin.QueryRow(
		ctx,
		"SELECT lease_owner, lease_expires_at FROM paas.operations WHERE tenant_id = $1 AND id = $2",
		tenantID,
		operationID,
	).Scan(&owner, &expiresAt); err != nil {
		t.Fatalf("inspect released Operation lease: %v", err)
	}
	if owner != nil || expiresAt != nil {
		t.Fatalf("released Operation retained lease owner/expiry = %v/%v", owner, expiresAt)
	}
}

type postgresWorkerPlan struct {
	method                          string
	resultState                     paasv1.AdapterResultState
	observationPhase                paasv1.DeploymentPhase
	observationError                bool
	expectedConsuming               int
	expectedConfigurationRevisionID paasv1.ResourceID
	effectCalls                     int
	observeCalls                    int
}

type postgresWorkerExecutor struct {
	t       *testing.T
	ctx     context.Context
	admin   *pgx.Conn
	fixture integrationFixture
	plans   map[paasv1.OperationID]*postgresWorkerPlan
}

func (executor *postgresWorkerExecutor) expect(
	operationID paasv1.OperationID,
	plan postgresWorkerPlan,
) {
	executor.t.Helper()
	if _, exists := executor.plans[operationID]; exists {
		executor.t.Fatalf("duplicate executor plan for Operation %q", operationID)
	}
	executor.plans[operationID] = &plan
}

func (*postgresWorkerExecutor) Capabilities(
	context.Context,
) (paasv1.AdapterCapabilitiesContract, error) {
	return paasv1.AdapterCapabilitiesContract{}, nil
}

func (*postgresWorkerExecutor) ValidateDeployment(
	context.Context,
	paasv1.DeploymentExecutionRequest,
) (paasv1.AdapterResult, error) {
	return paasv1.AdapterResult{}, errors.New("unexpected validation call")
}

func (executor *postgresWorkerExecutor) ApplyDeployment(
	_ context.Context,
	request paasv1.DeploymentExecutionRequest,
) (paasv1.AdapterResult, error) {
	return executor.effect("apply", request)
}

func (executor *postgresWorkerExecutor) RollbackDeployment(
	_ context.Context,
	request paasv1.DeploymentExecutionRequest,
) (paasv1.AdapterResult, error) {
	return executor.effect("rollback", request)
}

func (executor *postgresWorkerExecutor) StopDeployment(
	_ context.Context,
	request paasv1.DeploymentExecutionRequest,
) (paasv1.AdapterResult, error) {
	return executor.effect("stop", request)
}

func (executor *postgresWorkerExecutor) effect(
	method string,
	request paasv1.DeploymentExecutionRequest,
) (paasv1.AdapterResult, error) {
	executor.t.Helper()
	plan := executor.plan(request.Command.OperationID)
	plan.effectCalls++
	if plan.method != method || plan.effectCalls != 1 {
		executor.t.Fatalf(
			"executor effect for %q = method/calls %s/%d, want %s/1",
			request.Command.OperationID,
			method,
			plan.effectCalls,
			plan.method,
		)
	}
	if len(request.ConfigurationRevisions) != 1 ||
		request.ConfigurationRevisions[0].Metadata.ID != plan.expectedConfigurationRevisionID {
		executor.t.Fatalf(
			"executor configuration snapshot for %q = %#v",
			request.Command.OperationID,
			request.ConfigurationRevisions,
		)
	}
	executor.assertPersistedEffectIntent(request)
	assertConsumingClaims(
		executor.t,
		executor.ctx,
		executor.admin,
		executor.fixture.targetID,
		plan.expectedConsuming,
	)

	now := time.Now().UTC().Truncate(time.Microsecond)
	result := paasv1.AdapterResult{
		CommandID:  request.Command.CommandID,
		State:      plan.resultState,
		ObservedAt: now,
	}
	switch plan.resultState {
	case paasv1.AdapterResultSucceeded:
		result.Receipt = "provider-receipt-" + string(request.Command.OperationID)
	case paasv1.AdapterResultFailed:
		result.Error = &paasv1.NormalizedAdapterError{
			Class: paasv1.AdapterErrorValidation, Code: paasv1.ErrorAdapterRejected,
			Message:   "The deployment input was rejected before a provider effect.",
			Retryable: false,
		}
	case paasv1.AdapterResultUnknown:
		result.Error = &paasv1.NormalizedAdapterError{
			Class:   paasv1.AdapterErrorUnknownOutcome,
			Code:    paasv1.ErrorAdapterOutcomeUnknown,
			Message: "The provider outcome is unknown.", Retryable: true,
		}
	default:
		executor.t.Fatalf("unsupported executor result state %q", plan.resultState)
	}
	return result, nil
}

func (executor *postgresWorkerExecutor) ObserveDeployment(
	_ context.Context,
	request paasv1.ObserveDeploymentRequest,
) (paasv1.DeploymentObservation, error) {
	executor.t.Helper()
	plan := executor.plan(request.Command.OperationID)
	plan.observeCalls++
	if (!plan.observationError && plan.observationPhase == "") || plan.observeCalls != 1 {
		executor.t.Fatalf(
			"executor observation for %q = phase/calls %s/%d",
			request.Command.OperationID,
			plan.observationPhase,
			plan.observeCalls,
		)
	}
	executor.assertPersistedObservationIntent(request)
	if plan.observationError {
		return paasv1.DeploymentObservation{}, errors.New("injected observation outage")
	}
	readyComponents := uint32(0)
	if plan.observationPhase == paasv1.DeploymentReady {
		readyComponents = 1
	}
	return paasv1.DeploymentObservation{
		DeploymentID:          request.Command.DeploymentID,
		Generation:            request.Generation,
		ApplicationRevisionID: request.Command.ApplicationRevisionID,
		Phase:                 plan.observationPhase, ReadyComponents: readyComponents,
		ReceiptDigest: integrationDigest("observation-" + string(request.Command.OperationID)),
		ObservedAt:    time.Now().UTC().Truncate(time.Microsecond),
	}, nil
}

func (executor *postgresWorkerExecutor) plan(
	operationID paasv1.OperationID,
) *postgresWorkerPlan {
	executor.t.Helper()
	plan, exists := executor.plans[operationID]
	if !exists {
		executor.t.Fatalf("executor received unplanned Operation %q", operationID)
	}
	return plan
}

func (executor *postgresWorkerExecutor) assertPersistedEffectIntent(
	request paasv1.DeploymentExecutionRequest,
) {
	executor.t.Helper()
	var operationState string
	var commandCount int
	var receiptCount int
	if err := executor.admin.QueryRow(
		executor.ctx,
		`SELECT
		    (SELECT state FROM paas.operations
		      WHERE tenant_id = $1 AND id = $2),
		    (SELECT count(*) FROM paas.adapter_commands
		      WHERE tenant_id = $1 AND id = $3 AND operation_id = $2),
		    (SELECT count(*) FROM paas.adapter_receipts
		      WHERE tenant_id = $1 AND command_id = $3)`,
		request.Command.Scope.TenantID,
		request.Command.OperationID,
		request.Command.CommandID,
	).Scan(&operationState, &commandCount, &receiptCount); err != nil {
		executor.t.Fatalf("inspect persisted effect intent: %v", err)
	}
	if operationState != string(paasv1.OperationExecuting) ||
		commandCount != 1 || receiptCount != 0 {
		executor.t.Fatalf(
			"effect visibility state/command/receipt = %s/%d/%d",
			operationState,
			commandCount,
			receiptCount,
		)
	}
}

func (executor *postgresWorkerExecutor) assertPersistedObservationIntent(
	request paasv1.ObserveDeploymentRequest,
) {
	executor.t.Helper()
	var operationState string
	var commandCount int
	var effectReceiptCount int
	if err := executor.admin.QueryRow(
		executor.ctx,
		`SELECT
		    (SELECT state FROM paas.operations
		      WHERE tenant_id = $1 AND id = $2),
		    (SELECT count(*) FROM paas.adapter_commands
		      WHERE tenant_id = $1 AND id = $3 AND operation_id = $2),
		    (SELECT count(*)
		       FROM paas.adapter_receipts AS receipt
		       JOIN paas.adapter_commands AS command
		         ON command.tenant_id = receipt.tenant_id
		        AND command.id = receipt.command_id
		      WHERE command.tenant_id = $1
		        AND command.operation_id = $2
		        AND command.action <> 'OBSERVE_DEPLOYMENT')`,
		request.Command.Scope.TenantID,
		request.Command.OperationID,
		request.Command.CommandID,
	).Scan(&operationState, &commandCount, &effectReceiptCount); err != nil {
		executor.t.Fatalf("inspect persisted observation intent: %v", err)
	}
	if operationState != string(paasv1.OperationVerifying) &&
		operationState != string(paasv1.OperationReconciling) {
		executor.t.Fatalf("observation ran from Operation state %q", operationState)
	}
	if commandCount != 1 || effectReceiptCount != 1 {
		executor.t.Fatalf(
			"observation visibility command/effect-receipt = %d/%d",
			commandCount,
			effectReceiptCount,
		)
	}
}
