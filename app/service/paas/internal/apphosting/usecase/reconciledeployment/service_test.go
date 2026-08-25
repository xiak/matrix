package reconciledeployment

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/domain"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/createplacement"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/operationqueue"
)

var workerTime = time.Date(2026, 8, 25, 20, 0, 0, 123_000, time.UTC)

func TestWorkerCompletesDeployRollbackAndStopWithReservationConsistency(t *testing.T) {
	tests := []struct {
		name       string
		action     paasv1.OperationAction
		wantPhase  paasv1.DeploymentPhase
		wantMethod string
	}{
		{name: "deploy", action: paasv1.OperationDeploy, wantPhase: paasv1.DeploymentReady, wantMethod: "apply"},
		{name: "rollback", action: paasv1.OperationRollback, wantPhase: paasv1.DeploymentReady, wantMethod: "rollback"},
		{name: "stop", action: paasv1.OperationStop, wantPhase: paasv1.DeploymentStopped, wantMethod: "stop"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			workflow := newFakeWorkflow(test.action)
			executor := &fakeDeploymentExecutor{
				effectStates:      []paasv1.AdapterResultState{paasv1.AdapterResultSucceeded},
				observationPhases: []paasv1.DeploymentPhase{test.wantPhase},
			}
			worker := mustWorker(t, workflow, executor)
			found, err := worker.ProcessNext(context.Background(), "worker-a")
			if err != nil || !found {
				t.Fatalf("process %s Operation found/error = %v/%v", test.action, found, err)
			}
			if workflow.finalOperation.State != paasv1.OperationSucceeded ||
				workflow.state.Deployment.Status.Phase != test.wantPhase {
				t.Fatalf(
					"final Operation/Deployment = %#v / %#v",
					workflow.finalOperation,
					workflow.state.Deployment,
				)
			}
			if executor.effectCalls(test.wantMethod) != 1 || executor.observeCalls != 1 {
				t.Fatalf("executor effects = %#v", executor)
			}
			if test.action == paasv1.OperationStop {
				if workflow.activeReservation || !workflow.oldReservationReleased ||
					workflow.state.Deployment.Status.PlacementDecisionID != "" {
					t.Fatalf("STOP capacity/status = %#v", workflow)
				}
			} else if !workflow.activeReservation || workflow.pendingReservation {
				t.Fatalf("successful apply capacity = %#v", workflow)
			}
			if test.action == paasv1.OperationRollback && !workflow.oldReservationReleased {
				t.Fatal("rollback did not release the previous active reservation")
			}
		})
	}
}

func TestWorkerDefinitiveFailureReleasesOnlyPendingCapacity(t *testing.T) {
	workflow := newFakeWorkflow(paasv1.OperationDeploy)
	executor := &fakeDeploymentExecutor{
		effectStates: []paasv1.AdapterResultState{paasv1.AdapterResultFailed},
	}
	worker := mustWorker(t, workflow, executor)
	if found, err := worker.ProcessNext(context.Background(), "worker-a"); err != nil || !found {
		t.Fatalf("process definitive failure found/error = %v/%v", found, err)
	}
	if workflow.finalOperation.State != paasv1.OperationFailed ||
		workflow.state.Deployment.Status.Phase != paasv1.DeploymentFailed ||
		workflow.pendingReservation || workflow.activeReservation ||
		!workflow.pendingReservationReleased {
		t.Fatalf("definitive failure state = %#v", workflow)
	}
	if executor.observeCalls != 0 {
		t.Fatalf("definitive pre-effect failure unexpectedly observed %d times", executor.observeCalls)
	}
}

func TestWorkerUnknownOutcomeObservesBeforeAnySecondEffect(t *testing.T) {
	workflow := newFakeWorkflow(paasv1.OperationDeploy)
	executor := &fakeDeploymentExecutor{
		effectStates:      []paasv1.AdapterResultState{paasv1.AdapterResultUnknown},
		observationPhases: []paasv1.DeploymentPhase{paasv1.DeploymentReady},
	}
	worker := mustWorker(t, workflow, executor)
	if found, err := worker.ProcessNext(context.Background(), "worker-a"); err != nil || !found {
		t.Fatalf("process unknown outcome found/error = %v/%v", found, err)
	}
	if workflow.queue.stored.Operation.State != paasv1.OperationReconciling ||
		workflow.finalOperation.ID != "" || !workflow.pendingReservation {
		t.Fatalf("unknown outcome was not retained for reconciliation: %#v", workflow)
	}
	if found, err := worker.ProcessNext(context.Background(), "worker-a"); err != nil || !found {
		t.Fatalf("reconcile unknown outcome found/error = %v/%v", found, err)
	}
	if workflow.finalOperation.State != paasv1.OperationSucceeded ||
		workflow.state.Deployment.Status.Phase != paasv1.DeploymentReady ||
		executor.applyCalls != 1 || executor.observeCalls != 1 {
		t.Fatalf("unknown outcome reconciliation = workflow %#v executor %#v", workflow, executor)
	}
}

func TestWorkerManualInterventionRetainsCapacityForUncertainEffect(t *testing.T) {
	workflow := newFakeWorkflow(paasv1.OperationDeploy)
	executor := &fakeDeploymentExecutor{
		effectStates: []paasv1.AdapterResultState{paasv1.AdapterResultUnknown},
	}
	worker := mustWorker(t, workflow, executor)
	for attempt := 1; attempt <= 3; attempt++ {
		found, err := worker.ProcessNext(context.Background(), "worker-a")
		if err != nil || !found {
			t.Fatalf("process uncertain attempt %d found/error = %v/%v", attempt, found, err)
		}
	}
	if workflow.finalOperation.State != paasv1.OperationManualIntervention ||
		workflow.state.Deployment.Status.Phase != paasv1.DeploymentFailed ||
		workflow.pendingReservation || !workflow.activeReservation ||
		workflow.pendingReservationReleased {
		t.Fatalf("manual intervention capacity state = %#v", workflow)
	}
	if executor.applyCalls != 1 || executor.observeCalls != 1 {
		t.Fatalf("uncertain effect calls = %#v", executor)
	}
}

func TestWorkerFinalizesPersistedReadyObservationWithoutCallingExecutorAgain(t *testing.T) {
	workflow := newFakeWorkflow(paasv1.OperationDeploy)
	command := createPlacementCommandForWorkflow(workflow)
	if _, err := workflow.CreatePlacement(
		context.Background(),
		command,
		operationqueue.LeaseGuard{},
	); err != nil {
		t.Fatalf("prepare stored-observation placement: %v", err)
	}
	lease := workflow.queue.stored
	lease.Operation.State = paasv1.OperationVerifying
	lease.WorkerID = "worker-a"
	lease.FencingToken = 1
	lease.LeaseExpiresAt = workerTime.Add(5 * time.Minute)
	workflow.queue.stored.Operation = lease.Operation
	request, _, err := workflow.PrepareObservation(
		context.Background(),
		lease,
		"binding-local",
		workerTime.Add(time.Minute),
	)
	if err != nil {
		t.Fatalf("prepare stored observation: %v", err)
	}
	observation := paasv1.DeploymentObservation{
		DeploymentID: request.Command.DeploymentID, Generation: request.Generation,
		ApplicationRevisionID: request.Command.ApplicationRevisionID,
		Phase:                 paasv1.DeploymentReady, ReadyComponents: 1,
		ReceiptDigest: workerDigest('f'), ObservedAt: workerTime,
	}
	workflow.state.Observation = &observation
	executor := &fakeDeploymentExecutor{}
	worker := mustWorker(t, workflow, executor)
	if found, err := worker.ProcessNext(context.Background(), "worker-a"); err != nil || !found {
		t.Fatalf("resume stored observation found/error = %v/%v", found, err)
	}
	if workflow.finalOperation.State != paasv1.OperationSucceeded ||
		executor.observeCalls != 0 {
		t.Fatalf("stored observation replay = workflow %#v executor %#v", workflow, executor)
	}
}

func createPlacementCommandForWorkflow(workflow *fakeWorkflow) createplacement.Command {
	return createplacement.Command{
		TenantID:    workflow.state.Generation.Scope.TenantID,
		OperationID: workflow.queue.stored.Operation.ID,
		DecisionID:  "placement-a", DeploymentID: workflow.state.Generation.DeploymentID,
		RequestDigest: workerDigest('e'), TraceID: "trace-placement-a",
	}
}

func mustWorker(
	t *testing.T,
	workflow *fakeWorkflow,
	executor *fakeDeploymentExecutor,
) *Worker {
	t.Helper()
	worker, err := NewWorker(workflow.queue, workflow, workflow, executor, Config{
		BindingRef: "binding-local", EffectTimeout: time.Minute,
		ReconcileBackoff: time.Second, MaxAttempts: 3,
		Clock: func() time.Time { return workerTime },
	})
	if err != nil {
		t.Fatalf("new Deployment worker: %v", err)
	}
	return worker
}

type fakeWorkflow struct {
	queue                      *fakeOperationQueue
	state                      State
	finalOperation             paasv1.Operation
	pendingReservation         bool
	activeReservation          bool
	pendingReservationReleased bool
	oldReservationActive       bool
	oldReservationReleased     bool
}

func newFakeWorkflow(action paasv1.OperationAction) *fakeWorkflow {
	generation := uint64(1)
	resourceVersion := uint64(1)
	desiredState := paasv1.DeploymentDesiredRunning
	status := paasv1.DeploymentStatus{
		Phase: paasv1.DeploymentPending, ObservedAt: workerTime.Add(-time.Minute),
	}
	oldActive := false
	if action == paasv1.OperationRollback || action == paasv1.OperationStop {
		generation = 2
		resourceVersion = 4
		oldActive = true
		status.ObservedGeneration = 1
		status.PlacementDecisionID = "placement-old"
		status.ObservedApplicationRevisionID = "revision-a"
		status.ReadyComponents = 1
	}
	if action == paasv1.OperationStop {
		desiredState = paasv1.DeploymentDesiredStopped
	}
	operation := paasv1.Operation{
		APIVersion: paasv1.APIVersion, Kind: "Operation", ID: "operation-a",
		Scope:  paasv1.ResourceScope{Kind: paasv1.AuthorityTenant, TenantID: "tenant-a"},
		Action: action, Target: paasv1.ResourceRef{Kind: "Deployment", ID: "deployment-a"},
		RequestedBy:            paasv1.SubjectRef{Type: paasv1.SubjectUser, ID: "user-a"},
		IdempotencyFingerprint: workerDigest('a'), RequestDigest: workerDigest('b'),
		State: paasv1.OperationAccepted, Attempt: 1,
		CreatedAt: workerTime.Add(-time.Minute), UpdatedAt: workerTime.Add(-time.Minute),
	}
	status.CurrentOperationID = operation.ID
	metadata := paasv1.ResourceMetadata{
		ID: "deployment-a", Name: "deployment-a",
		Scope: operation.Scope, ResourceVersion: resourceVersion,
		CreatedAt: workerTime.Add(-time.Hour), UpdatedAt: workerTime.Add(-time.Minute),
	}
	spec := paasv1.DeploymentSpec{
		ApplicationRevisionID: "revision-a", PlacementPolicyID: "policy-a",
		DesiredState: desiredState,
		Components:   []paasv1.DeploymentComponent{{Name: "web", Replicas: 1}},
	}
	deployment := paasv1.Deployment{
		APIVersion: paasv1.APIVersion, Kind: "Deployment", Metadata: metadata,
		Generation: generation, Spec: spec, Status: status,
	}
	generationValue := paasv1.DeploymentGeneration{
		APIVersion: paasv1.APIVersion, Kind: "DeploymentGeneration",
		Scope: operation.Scope, DeploymentID: deployment.Metadata.ID,
		Generation: generation, Spec: spec, CreatedByOperationID: operation.ID,
		CreatedAt: workerTime.Add(-time.Minute),
	}
	generationValue.ContentDigest = paasv1.DeploymentSpecContentDigest(spec)
	revisionMetadata := paasv1.ResourceMetadata{
		ID: "revision-a", Name: "revision-a", Scope: operation.Scope,
		ResourceVersion: 1, CreatedAt: workerTime.Add(-time.Hour),
		UpdatedAt: workerTime.Add(-time.Hour),
	}
	revision := paasv1.ApplicationRevision{
		APIVersion: paasv1.APIVersion, Kind: "ApplicationRevision",
		Metadata: revisionMetadata,
		Spec: paasv1.ApplicationRevisionSpec{
			ApplicationID: "application-a", Revision: "r1", ContentDigest: workerDigest('c'),
			Components: []paasv1.ApplicationRevisionComponent{{
				Name: "web",
				Artifact: paasv1.ArtifactRef{
					Kind:    paasv1.ArtifactOCIImage,
					Locator: "registry.example.invalid/matrix/web",
					Digest:  workerDigest('d'),
				},
				Resources: paasv1.ResourceRequirements{CPUMillis: 100, MemoryBytes: 1024},
			}},
		},
	}
	queue := &fakeOperationQueue{
		stored:  operationqueue.Lease{TenantID: "tenant-a", Operation: operation},
		pending: true,
	}
	return &fakeWorkflow{
		queue: queue,
		state: State{
			Deployment: deployment, Generation: generationValue,
			ApplicationRevision: revision,
		},
		oldReservationActive: oldActive,
	}
}

func (workflow *fakeWorkflow) CreatePlacement(
	_ context.Context,
	command createplacement.Command,
	_ operationqueue.LeaseGuard,
) (createplacement.Result, error) {
	return workflow.place(command, false)
}

func (workflow *fakeWorkflow) BindStopPlacement(
	_ context.Context,
	command createplacement.Command,
	_ operationqueue.LeaseGuard,
) (createplacement.Result, error) {
	return workflow.place(command, true)
}

func (workflow *fakeWorkflow) place(
	command createplacement.Command,
	reuse bool,
) (createplacement.Result, error) {
	decision := paasv1.PlacementDecision{
		APIVersion: paasv1.APIVersion, Kind: "PlacementDecision",
		Metadata: paasv1.ResourceMetadata{
			ID: command.DecisionID, Name: string(command.DecisionID),
			Scope: workflow.state.Generation.Scope, ResourceVersion: 1,
			CreatedAt: workerTime, UpdatedAt: workerTime,
		},
		DeploymentID:                workflow.state.Generation.DeploymentID,
		DeploymentGeneration:        workflow.state.Generation.Generation,
		DeploymentResourceVersion:   workflow.state.Deployment.Metadata.ResourceVersion,
		ApplicationRevisionID:       workflow.state.ApplicationRevision.Metadata.ID,
		PlacementPolicyID:           workflow.state.Generation.Spec.PlacementPolicyID,
		PolicyResourceVersion:       1,
		RequestedIsolationGuarantee: paasv1.IsolationWorkload,
		Outcome:                     paasv1.PlacementScheduled, ExecutionTargetID: "target-a",
		ExecutionTargetResourceVersion: 1,
		GrantedIsolationGuarantee:      paasv1.IsolationWorkload,
		CandidateSetDigest:             workerDigest('e'), DecidedAt: workerTime,
	}
	workflow.state.Placement = &decision
	if !reuse {
		workflow.pendingReservation = true
	}
	return createplacement.Result{Decision: decision}, nil
}

func (workflow *fakeWorkflow) Load(
	context.Context,
	operationqueue.LeaseGuard,
) (State, error) {
	return workflow.state, nil
}

func (workflow *fakeWorkflow) UpdatePhase(
	_ context.Context,
	_ operationqueue.LeaseGuard,
	phase paasv1.DeploymentPhase,
) (paasv1.Deployment, error) {
	workflow.state.Deployment.Status.Phase = phase
	workflow.state.Deployment.Metadata.ResourceVersion++
	return workflow.state.Deployment, nil
}

func (workflow *fakeWorkflow) PrepareEffect(
	_ context.Context,
	lease operationqueue.Lease,
	action paasv1.AdapterAction,
	bindingRef string,
	deadline time.Time,
) (paasv1.DeploymentExecutionRequest, bool, error) {
	replayed := workflow.state.EffectRequest != nil
	request, err := workflow.executionRequest(lease, action, bindingRef, deadline)
	if err != nil {
		return paasv1.DeploymentExecutionRequest{}, false, err
	}
	workflow.state.EffectRequest = &request
	return request, replayed, nil
}

func (workflow *fakeWorkflow) PrepareObservation(
	_ context.Context,
	lease operationqueue.Lease,
	bindingRef string,
	deadline time.Time,
) (paasv1.ObserveDeploymentRequest, bool, error) {
	replayed := workflow.state.ObserveRequest != nil
	command, err := workflow.command(lease, paasv1.AdapterObserveDeployment, bindingRef, deadline)
	if err != nil {
		return paasv1.ObserveDeploymentRequest{}, false, err
	}
	request := paasv1.ObserveDeploymentRequest{
		Command: command, Generation: workflow.state.Generation.Generation,
		ExpectedContentDigest: workflow.state.Generation.ContentDigest,
	}
	request.Command.RequestDigest = paasv1.ObserveDeploymentRequestDigest(request)
	workflow.state.ObserveRequest = &request
	return request, replayed, paasv1.ValidateObserveDeploymentRequest(request)
}

func (workflow *fakeWorkflow) executionRequest(
	lease operationqueue.Lease,
	action paasv1.AdapterAction,
	bindingRef string,
	deadline time.Time,
) (paasv1.DeploymentExecutionRequest, error) {
	command, err := workflow.command(lease, action, bindingRef, deadline)
	if err != nil {
		return paasv1.DeploymentExecutionRequest{}, err
	}
	request := paasv1.DeploymentExecutionRequest{
		Command: command, Generation: workflow.state.Generation,
		ApplicationRevision: workflow.state.ApplicationRevision,
		Placement:           *workflow.state.Placement,
	}
	request.Command.RequestDigest = paasv1.DeploymentExecutionRequestDigest(request)
	return request, paasv1.ValidateDeploymentExecutionRequest(request)
}

func (workflow *fakeWorkflow) command(
	lease operationqueue.Lease,
	action paasv1.AdapterAction,
	bindingRef string,
	deadline time.Time,
) (paasv1.AdapterCommandEnvelope, error) {
	commandID, err := domain.DeriveCommandID(domain.CommandIdentityInput{
		OperationID: lease.Operation.ID, Action: action,
		ExecutionTargetID:     workflow.state.Placement.ExecutionTargetID,
		DeploymentID:          workflow.state.Generation.DeploymentID,
		ApplicationRevisionID: workflow.state.ApplicationRevision.Metadata.ID,
	})
	if err != nil {
		return paasv1.AdapterCommandEnvelope{}, err
	}
	return paasv1.AdapterCommandEnvelope{
		OperationID: lease.Operation.ID, CommandID: commandID,
		Attempt: lease.Operation.Attempt, Action: action,
		Scope:                 workflow.state.Generation.Scope,
		ApplicationID:         workflow.state.ApplicationRevision.Spec.ApplicationID,
		ApplicationRevisionID: workflow.state.ApplicationRevision.Metadata.ID,
		DeploymentID:          workflow.state.Generation.DeploymentID,
		ExecutionTargetID:     workflow.state.Placement.ExecutionTargetID,
		BindingRef:            bindingRef, Deadline: deadline,
	}, nil
}

func (workflow *fakeWorkflow) RecordResult(
	_ context.Context,
	_ operationqueue.LeaseGuard,
	requestDigest string,
	result paasv1.AdapterResult,
) (bool, error) {
	receipt := &StoredReceipt{
		CommandID: result.CommandID, RequestDigest: requestDigest,
		State: result.State, Error: result.Error, ObservedAt: result.ObservedAt,
	}
	if result.State == paasv1.AdapterResultSucceeded {
		receipt.ReceiptDigest = domain.DigestPayload([]byte(result.Receipt))
	}
	workflow.state.Receipt = receipt
	return true, nil
}

func (workflow *fakeWorkflow) RecordObservation(
	_ context.Context,
	_ operationqueue.LeaseGuard,
	_ paasv1.CommandID,
	observation paasv1.DeploymentObservation,
) (bool, error) {
	workflow.state.Observation = &observation
	return true, nil
}

func (workflow *fakeWorkflow) FinalizeSuccess(
	_ context.Context,
	lease operationqueue.Lease,
	observation paasv1.DeploymentObservation,
) (paasv1.Deployment, paasv1.Operation, error) {
	workflow.pendingReservation = false
	if lease.Operation.Action == paasv1.OperationStop {
		workflow.oldReservationActive = false
		workflow.oldReservationReleased = true
		workflow.state.Deployment.Status.Phase = paasv1.DeploymentStopped
		workflow.state.Deployment.Status.PlacementDecisionID = ""
	} else {
		workflow.activeReservation = true
		if workflow.oldReservationActive {
			workflow.oldReservationActive = false
			workflow.oldReservationReleased = true
		}
		workflow.state.Deployment.Status.Phase = paasv1.DeploymentReady
		workflow.state.Deployment.Status.PlacementDecisionID =
			workflow.state.Placement.Metadata.ID
	}
	workflow.state.Deployment.Status.ObservedGeneration = observation.Generation
	workflow.state.Deployment.Status.ObservedApplicationRevisionID =
		observation.ApplicationRevisionID
	workflow.state.Deployment.Status.ReadyComponents = observation.ReadyComponents
	workflow.state.Deployment.Status.ObservedAt = observation.ObservedAt
	operation := lease.Operation
	operation.State = paasv1.OperationSucceeded
	operation.UpdatedAt = workerTime
	terminalAt := workerTime
	operation.TerminalAt = &terminalAt
	workflow.finalOperation = operation
	return workflow.state.Deployment, operation, nil
}

func (workflow *fakeWorkflow) FinalizeTerminal(
	_ context.Context,
	lease operationqueue.Lease,
	terminal Terminal,
) (paasv1.Deployment, paasv1.Operation, error) {
	if terminal.State == paasv1.OperationManualIntervention &&
		lease.Operation.Action != paasv1.OperationStop &&
		workflow.pendingReservation {
		workflow.pendingReservation = false
		workflow.activeReservation = true
	}
	if terminal.ReleasePending && workflow.pendingReservation {
		workflow.pendingReservation = false
		workflow.pendingReservationReleased = true
	}
	workflow.state.Deployment.Status.Phase = paasv1.DeploymentFailed
	operation := lease.Operation
	operation.State = terminal.State
	operation.Error = terminal.Problem
	operation.UpdatedAt = workerTime
	terminalAt := workerTime
	operation.TerminalAt = &terminalAt
	workflow.finalOperation = operation
	return workflow.state.Deployment, operation, nil
}

type fakeOperationQueue struct {
	stored  operationqueue.Lease
	pending bool
	claims  uint64
}

func (queue *fakeOperationQueue) ClaimNext(
	_ context.Context,
	workerID string,
) (operationqueue.Lease, bool, error) {
	if !queue.pending {
		return operationqueue.Lease{}, false, nil
	}
	queue.pending = false
	queue.claims++
	if queue.claims > 1 {
		queue.stored.Operation.Attempt++
	}
	queue.stored.WorkerID = workerID
	queue.stored.FencingToken = queue.claims
	queue.stored.LeaseExpiresAt = workerTime.Add(5 * time.Minute)
	return queue.stored, true, nil
}

func (queue *fakeOperationQueue) Advance(
	_ context.Context,
	transition operationqueue.Transition,
) (operationqueue.Lease, error) {
	operation := transition.Lease.Operation
	operation.State = transition.State
	operation.UpdatedAt = operation.UpdatedAt.Add(time.Microsecond)
	operation.Error = transition.Problem
	next := transition.Lease
	next.Operation = operation
	queue.stored = next
	if transition.ReleaseLease {
		queue.pending = true
		queue.stored.WorkerID = ""
		queue.stored.LeaseExpiresAt = time.Time{}
		next = queue.stored
		next.FencingToken = 0
		queue.stored.FencingToken = transition.Lease.FencingToken
	}
	return next, nil
}

func (queue *fakeOperationQueue) Release(
	_ context.Context,
	lease operationqueue.Lease,
	_ time.Time,
) (operationqueue.Lease, error) {
	queue.pending = true
	queue.stored = lease
	queue.stored.WorkerID = ""
	queue.stored.LeaseExpiresAt = time.Time{}
	lease.WorkerID = ""
	lease.FencingToken = 0
	lease.LeaseExpiresAt = time.Time{}
	return lease, nil
}

type fakeDeploymentExecutor struct {
	effectStates      []paasv1.AdapterResultState
	observationPhases []paasv1.DeploymentPhase
	applyCalls        int
	rollbackCalls     int
	stopCalls         int
	observeCalls      int
}

func (*fakeDeploymentExecutor) Capabilities(context.Context) (paasv1.AdapterCapabilitiesContract, error) {
	return paasv1.AdapterCapabilitiesContract{}, nil
}

func (*fakeDeploymentExecutor) ValidateDeployment(
	context.Context,
	paasv1.DeploymentExecutionRequest,
) (paasv1.AdapterResult, error) {
	return paasv1.AdapterResult{}, errors.New("unexpected validation call")
}

func (executor *fakeDeploymentExecutor) ApplyDeployment(
	_ context.Context,
	request paasv1.DeploymentExecutionRequest,
) (paasv1.AdapterResult, error) {
	executor.applyCalls++
	return executor.effectResult(request)
}

func (executor *fakeDeploymentExecutor) RollbackDeployment(
	_ context.Context,
	request paasv1.DeploymentExecutionRequest,
) (paasv1.AdapterResult, error) {
	executor.rollbackCalls++
	return executor.effectResult(request)
}

func (executor *fakeDeploymentExecutor) StopDeployment(
	_ context.Context,
	request paasv1.DeploymentExecutionRequest,
) (paasv1.AdapterResult, error) {
	executor.stopCalls++
	return executor.effectResult(request)
}

func (executor *fakeDeploymentExecutor) ObserveDeployment(
	_ context.Context,
	request paasv1.ObserveDeploymentRequest,
) (paasv1.DeploymentObservation, error) {
	executor.observeCalls++
	if len(executor.observationPhases) == 0 {
		return paasv1.DeploymentObservation{}, errors.New("no observation configured")
	}
	phase := executor.observationPhases[0]
	executor.observationPhases = executor.observationPhases[1:]
	ready := uint32(0)
	if phase == paasv1.DeploymentReady {
		ready = 1
	}
	return paasv1.DeploymentObservation{
		DeploymentID: request.Command.DeploymentID, Generation: request.Generation,
		ApplicationRevisionID: request.Command.ApplicationRevisionID,
		Phase:                 phase, ReadyComponents: ready,
		ReceiptDigest: workerDigest('f'), ObservedAt: workerTime,
	}, nil
}

func (executor *fakeDeploymentExecutor) effectResult(
	request paasv1.DeploymentExecutionRequest,
) (paasv1.AdapterResult, error) {
	if len(executor.effectStates) == 0 {
		return paasv1.AdapterResult{}, errors.New("no effect result configured")
	}
	state := executor.effectStates[0]
	executor.effectStates = executor.effectStates[1:]
	result := paasv1.AdapterResult{
		CommandID: request.Command.CommandID, State: state,
		Receipt: "receipt-a", ObservedAt: workerTime,
	}
	if state == paasv1.AdapterResultFailed {
		result.Receipt = ""
		result.Error = &paasv1.NormalizedAdapterError{
			Class: paasv1.AdapterErrorValidation, Code: paasv1.ErrorAdapterRejected,
			Message:   "The deployment input was rejected before any provider effect.",
			Retryable: false,
		}
	}
	if state == paasv1.AdapterResultUnknown {
		result.Receipt = ""
		result.Error = &paasv1.NormalizedAdapterError{
			Class:   paasv1.AdapterErrorUnknownOutcome,
			Code:    paasv1.ErrorAdapterOutcomeUnknown,
			Message: "The provider outcome is unknown.", Retryable: true,
		}
	}
	return result, nil
}

func (executor *fakeDeploymentExecutor) effectCalls(method string) int {
	switch method {
	case "apply":
		return executor.applyCalls
	case "rollback":
		return executor.rollbackCalls
	case "stop":
		return executor.stopCalls
	default:
		panic(fmt.Sprintf("unknown effect method %q", method))
	}
}

func workerDigest(character byte) string {
	return "sha256:" + strings.Repeat(string(character), 64)
}
