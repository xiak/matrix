package executionadmission

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/port"
)

func TestRefreshPreservesIntentAndDoesNotVersionMetricSamples(t *testing.T) {
	service, transaction, adapter, now := refreshFixture(t)
	initial := transaction.registration.Target
	adapter.before = func() {
		// Operator intent changes while the node probe is outside a transaction.
		transaction.registration.Target.Spec.DesiredState = paasv1.ExecutionTargetDraining
		transaction.registration.Target.Metadata.Labels["rack"] = "operator-choice"
		transaction.registration.Target.Metadata.ResourceVersion++
		adapter.observation.Labels = map[string]string{"rack": "untrusted-node-value"}
	}
	if err := service.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	current := transaction.registration.Target
	if current.Spec.DesiredState != paasv1.ExecutionTargetDraining || current.Metadata.Labels["rack"] != "operator-choice" ||
		current.Metadata.ResourceVersion != initial.Metadata.ResourceVersion+1 || !current.Status.ObservedAt.Equal(now) {
		t.Fatalf("refresh overwrote intent or versioned a sample: %#v", current)
	}
	if transaction.pool.Status.ReadyExecutionTargetCount != 0 || transaction.pool.Status.ExecutionTargetCount != 1 {
		t.Fatal("draining target remained eligible")
	}
	if adapter.probedInsideTransaction {
		t.Fatal("node probe ran inside the database transaction")
	}
}

func TestDisconnectionRetainsCapacityAndOriginalSampleTime(t *testing.T) {
	service, transaction, adapter, now := refreshFixture(t)
	initial := transaction.registration.Target
	service.config.Clock = func() time.Time { return now.Add(20 * time.Second) }
	transaction.now = now.Add(20 * time.Second)
	adapter.err = errors.New("private endpoint and certificate detail must not escape")
	if err := service.Refresh(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("refresh error = %v", err)
	}
	current := transaction.registration.Target
	if current.Status.Health != paasv1.ExecutionTargetHealthUnavailable || current.Status.Capacity != initial.Status.Capacity ||
		current.Status.Allocatable != initial.Status.Allocatable || !current.Status.ObservedAt.Equal(initial.Status.ObservedAt) ||
		current.Status.Usage.ObservedAt != initial.Status.Usage.ObservedAt || current.Status.Usage.CPU.State != paasv1.MeasurementStale ||
		current.Metadata.ResourceVersion != initial.Metadata.ResourceVersion+1 {
		t.Fatalf("disconnection fabricated or renewed a fact: %#v", current)
	}
	if transaction.pool.Status.ReadyExecutionTargetCount != 0 {
		t.Fatal("disconnected target remained eligible")
	}
	adapter.err = nil
	adapter.observation.ObservedAt = transaction.now
	adapter.observation.Usage.ObservedAt = transaction.now
	adapter.observation.Usage.ValidUntil = transaction.now.Add(15 * time.Second)
	if err := service.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if transaction.registration.Target.Status.Health != paasv1.ExecutionTargetHealthReady {
		t.Fatal("node did not recover")
	}
}

func TestChangedNodeIdentityCannotRebindRegisteredTarget(t *testing.T) {
	service, transaction, adapter, _ := refreshFixture(t)
	initial := transaction.registration
	adapter.observation.IdentityFingerprint = "sha256:" + strings.Repeat("b", 64)
	if err := service.Refresh(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("changed identity error = %v", err)
	}
	current := transaction.registration
	if current.IdentityFingerprint != initial.IdentityFingerprint || current.BindingRef != initial.BindingRef ||
		!reflect.DeepEqual(current.Target.Spec, initial.Target.Spec) || current.Target.Status.Health != paasv1.ExecutionTargetHealthUnavailable {
		t.Fatal("changed node rebound stored authority")
	}
}

func TestListTargetsUsesPersistedSnapshotWithoutProbingOrRenewingIt(t *testing.T) {
	service, transaction, adapter, now := refreshFixture(t)
	managed := transaction.registration.Target
	managed.Metadata.ID = "target-z"
	managed.Metadata.Name = "managed-z"
	local := transaction.registration.Target
	local.Metadata.ID = builtInTargetID
	local.Metadata.Name = "local"
	local.Spec.InfrastructureAdapter.Name = "localmachine"
	local.Status.ObservedAt = now.Add(-time.Minute)
	transaction.poolTargets = []paasv1.ExecutionTarget{managed, local}
	transaction.retryFirst = true
	service.config.Clock = func() time.Time { return now.Add(20 * time.Second) }
	authorization := port.Authorization{
		InstallationID: "installation-a",
		Subject:        paasv1.SubjectRef{Type: paasv1.SubjectUser, ID: "platform-user"},
		DecisionID:     "decision-list",
		RequestID:      "request-list",
	}
	result, err := service.ListTargets(context.Background(), authorization)
	if err != nil {
		t.Fatal(err)
	}
	if paasv1.ValidateExecutionTargetList(result) != nil || len(result.Items) != 2 ||
		result.Items[0].Metadata.ID != builtInTargetID || result.Items[1].Metadata.ID != "target-z" {
		t.Fatalf("execution target inventory = %#v", result)
	}
	if result.Items[0].Status.ObservedAt != local.Status.ObservedAt ||
		result.Items[1].Status.Usage.ObservedAt != managed.Status.Usage.ObservedAt ||
		result.Items[1].Status.Usage.CPU.State != paasv1.MeasurementStale ||
		result.Items[1].Status.Health != paasv1.ExecutionTargetHealthUnavailable {
		t.Fatal("execution target read renewed or hid a stale sample")
	}
	if adapter.calls != 0 || transaction.calls != 2 ||
		transaction.poolTargets[1].Status.Usage.CPU.State != paasv1.MeasurementUnavailable {
		t.Fatal("retried execution target read probed, duplicated, or mutated persisted state")
	}
}

func TestRefreshPreservesWorkerObservedLocalTarget(t *testing.T) {
	service, transaction, _, now := refreshFixture(t)
	local := transaction.registration.Target
	local.Metadata.ID = "execution-target-local"
	local.Metadata.Name = "local"
	local.Metadata.Labels = map[string]string{
		"matrix-profile": "local-compose",
		fingerprintLabel: "sha256:" + strings.Repeat("b", 64),
	}
	local.Spec.InfrastructureAdapter.Name = "localmachine"
	local.Status.ObservedAt = now.Add(-time.Minute)
	transaction.poolTargets = []paasv1.ExecutionTarget{local, transaction.registration.Target}
	transaction.pool.Status.ExecutionTargetCount = 2
	transaction.pool.Status.ReadyExecutionTargetCount = 2
	if err := service.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if transaction.pool.Status.Phase != paasv1.ExecutionPoolReady ||
		transaction.pool.Status.ExecutionTargetCount != 2 ||
		transaction.pool.Status.ReadyExecutionTargetCount != 2 {
		t.Fatalf("local target disappeared from pool: %#v", transaction.pool.Status)
	}
}

func TestAdmissionRequiresInstallationUserBeforeAnySideEffect(t *testing.T) {
	service, transaction, adapter, _ := refreshFixture(t)
	for _, authorization := range []port.Authorization{
		{TenantID: "tenant-a", Subject: paasv1.SubjectRef{Type: paasv1.SubjectUser, ID: "user-a"}},
		{InstallationID: "other-installation", Subject: paasv1.SubjectRef{Type: paasv1.SubjectUser, ID: "user-a"}},
		{InstallationID: "installation-a", Subject: paasv1.SubjectRef{Type: paasv1.SubjectServiceAccount, ID: "service-a"}},
		{InstallationID: "installation-a", TenantID: "tenant-a", Subject: paasv1.SubjectRef{Type: paasv1.SubjectUser, ID: "user-a"}},
	} {
		authorization.DecisionID, authorization.RequestID = "decision-a", "request-a"
		_, _, _, err := service.RegisterTarget(context.Background(), RegisterTargetCommand{Authorization: authorization})
		if !errors.Is(err, port.ErrPermissionDenied) {
			t.Fatalf("untrusted authority admitted: %v", err)
		}
	}
	if transaction.calls != 0 || adapter.calls != 0 {
		t.Fatal("denied admission reached a side effect")
	}
}

func TestAdmissionCannotClaimBuiltInProfileIdentities(t *testing.T) {
	service, transaction, adapter, _ := refreshFixture(t)
	authorization := port.Authorization{
		InstallationID: "installation-a",
		Subject:        paasv1.SubjectRef{Type: paasv1.SubjectUser, ID: "platform-user"},
		DecisionID:     "decision-a", RequestID: "request-a",
	}
	_, _, _, err := service.CreatePool(context.Background(), CreatePoolCommand{
		Authorization: authorization, IdempotencyKey: "reserved-pool",
		Request: paasv1.CreateExecutionPoolRequest{
			ID: builtInPoolID, Name: "reserved",
			Spec: paasv1.ExecutionPoolSpec{
				AllowedIsolationGuarantees: []paasv1.IsolationGuarantee{paasv1.IsolationWorkload},
			},
		},
	})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("built-in pool identity error = %v", err)
	}
	_, _, _, err = service.RegisterTarget(context.Background(), RegisterTargetCommand{
		Authorization: authorization, IdempotencyKey: "reserved-target",
		Request: paasv1.RegisterExecutionTargetRequest{
			ID: builtInTargetID, Name: "reserved", ExecutionPoolID: "pool-a",
			BindingRef: "binding-a",
		},
	})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("built-in target identity error = %v", err)
	}
	if transaction.calls != 0 || adapter.calls != 0 {
		t.Fatal("reserved identity reached a side effect")
	}
}

func TestLateObservationDoesNotOverwriteNewerMeasurement(t *testing.T) {
	service, transaction, adapter, now := refreshFixture(t)
	adapter.before = func() { transaction.registration.Target.Status.ObservedAt = now.Add(time.Second) }
	if err := service.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if transaction.registration.Target.Status.ObservedAt != now.Add(time.Second) {
		t.Fatal("late probe overwrote newer observation")
	}
}

func TestManagedTargetLifecycleIsExplicitTerminalAndNeverProbesTheNode(t *testing.T) {
	service, transaction, adapter, _ := refreshFixture(t)
	authorization := port.Authorization{
		InstallationID: "installation-a",
		Subject:        paasv1.SubjectRef{Type: paasv1.SubjectUser, ID: "platform-user"},
		DecisionID:     "decision-lifecycle",
		RequestID:      "request-lifecycle",
	}
	transition := func(action paasv1.OperationAction, version uint64, key string) TransitionTargetResult {
		t.Helper()
		result, err := service.TransitionTarget(context.Background(), TransitionTargetCommand{
			Authorization: authorization, TargetID: "target-a", Action: action,
			ExpectedResourceVersion: version, IdempotencyKey: key,
		})
		if err != nil {
			t.Fatalf("transition %s: %v", action, err)
		}
		return result
	}
	drained := transition(paasv1.OperationDrainExecutionTarget, 1, "drain-target")
	if drained.Target.Spec.DesiredState != paasv1.ExecutionTargetDraining ||
		drained.Target.Metadata.ResourceVersion != 2 || transaction.pool.Status.ExecutionTargetCount != 1 ||
		transaction.pool.Status.ReadyExecutionTargetCount != 0 || transaction.pool.Status.Phase != paasv1.ExecutionPoolUnavailable {
		t.Fatalf("drained target/pool = %#v / %#v", drained.Target, transaction.pool)
	}
	for _, changed := range []TransitionTargetCommand{
		{Authorization: authorization, TargetID: "target-a", Action: paasv1.OperationActivateExecutionTarget, ExpectedResourceVersion: 2, IdempotencyKey: "drain-target"},
		{Authorization: authorization, TargetID: "target-b", Action: paasv1.OperationDrainExecutionTarget, ExpectedResourceVersion: 1, IdempotencyKey: "drain-target"},
		{Authorization: authorization, TargetID: "target-a", Action: paasv1.OperationDrainExecutionTarget, ExpectedResourceVersion: 2, IdempotencyKey: "drain-target"},
	} {
		_, err := service.TransitionTarget(context.Background(), changed)
		if !errors.Is(err, ErrIdempotencyConflict) ||
			transaction.registration.Target.Spec.DesiredState != paasv1.ExecutionTargetDraining ||
			transaction.transitionCalls != 1 {
			t.Fatalf("changed replay mutated target: command=%#v err=%v target=%#v", changed, err, transaction.registration.Target)
		}
	}
	activated := transition(paasv1.OperationActivateExecutionTarget, 2, "activate-target")
	if activated.Target.Spec.DesiredState != paasv1.ExecutionTargetActive ||
		activated.Target.Metadata.ResourceVersion != 3 || transaction.pool.Status.ReadyExecutionTargetCount != 1 {
		t.Fatalf("activated target/pool = %#v / %#v", activated.Target, transaction.pool)
	}
	transition(paasv1.OperationDrainExecutionTarget, 3, "drain-target-again")
	removed := transition(paasv1.OperationRemoveExecutionTarget, 4, "remove-target")
	if removed.Target.Spec.DesiredState != paasv1.ExecutionTargetRemoved ||
		removed.Target.Metadata.ResourceVersion != 5 || transaction.pool.Status.ExecutionTargetCount != 0 ||
		transaction.pool.Status.ReadyExecutionTargetCount != 0 || transaction.pool.Status.Phase != paasv1.ExecutionPoolUnavailable {
		t.Fatalf("removed target/pool = %#v / %#v", removed.Target, transaction.pool)
	}
	replayed := transition(paasv1.OperationRemoveExecutionTarget, 4, "remove-target")
	if !replayed.Replayed || replayed.Operation.ID != removed.Operation.ID ||
		replayed.Target.Metadata.ResourceVersion != 5 || transaction.transitionCalls != 4 {
		t.Fatalf("remove replay changed state: %#v calls=%d", replayed, transaction.transitionCalls)
	}
	_, err := service.TransitionTarget(context.Background(), TransitionTargetCommand{
		Authorization: authorization, TargetID: "target-a", Action: paasv1.OperationActivateExecutionTarget,
		ExpectedResourceVersion: 5, IdempotencyKey: "resurrect-target",
	})
	if !errors.Is(err, ErrInvalidTransition) || transaction.registration.Target.Spec.DesiredState != paasv1.ExecutionTargetRemoved {
		t.Fatalf("removed target resurrected: %v %#v", err, transaction.registration.Target)
	}
	if adapter.calls != 0 {
		t.Fatalf("operator lifecycle called the node %d times", adapter.calls)
	}
}

func TestTargetLifecycleRejectsStaleVersionBeforeMutation(t *testing.T) {
	service, transaction, _, _ := refreshFixture(t)
	_, err := service.TransitionTarget(context.Background(), TransitionTargetCommand{
		Authorization: port.Authorization{
			InstallationID: "installation-a",
			Subject:        paasv1.SubjectRef{Type: paasv1.SubjectUser, ID: "platform-user"},
			DecisionID:     "decision-lifecycle",
			RequestID:      "request-lifecycle",
		},
		TargetID: "target-a", Action: paasv1.OperationDrainExecutionTarget,
		ExpectedResourceVersion: 2, IdempotencyKey: "stale-drain",
	})
	if !errors.Is(err, ErrResourceVersionConflict) ||
		transaction.registration.Target.Spec.DesiredState != paasv1.ExecutionTargetActive ||
		transaction.transitionCalls != 0 {
		t.Fatalf("stale transition mutated target: %v %#v", err, transaction.registration.Target)
	}
}

type refreshTransaction struct {
	Transaction
	now             time.Time
	registration    Registration
	poolTargets     []paasv1.ExecutionTarget
	pool            paasv1.ExecutionPool
	calls           int
	active          bool
	retryFirst      bool
	operations      map[string]paasv1.Operation
	transitionCalls int
}

func (transaction *refreshTransaction) WithinTransaction(ctx context.Context, installation string, callback func(context.Context, Transaction) error) error {
	transaction.calls++
	transaction.active = true
	defer func() { transaction.active = false }()
	if installation != "installation-a" {
		return ErrConflict
	}
	err := callback(ctx, transaction)
	if err == nil && transaction.retryFirst {
		transaction.retryFirst = false
		return ErrRetryableTransaction
	}
	return err
}
func (transaction *refreshTransaction) TransactionTime(context.Context) (time.Time, error) {
	return transaction.now, nil
}
func (transaction *refreshTransaction) FindOperationByFingerprint(_ context.Context, fingerprint string) (paasv1.Operation, bool, error) {
	operation, found := transaction.operations[fingerprint]
	return operation, found, nil
}
func (transaction *refreshTransaction) ListTargets(context.Context) ([]Registration, error) {
	return []Registration{transaction.registration}, nil
}
func (transaction *refreshTransaction) ListTargetResources(context.Context) ([]paasv1.ExecutionTarget, error) {
	if transaction.poolTargets == nil {
		return []paasv1.ExecutionTarget{transaction.registration.Target}, nil
	}
	return append([]paasv1.ExecutionTarget(nil), transaction.poolTargets...), nil
}
func (transaction *refreshTransaction) ListPoolTargets(context.Context, paasv1.ResourceID) ([]paasv1.ExecutionTarget, error) {
	if transaction.poolTargets == nil {
		return []paasv1.ExecutionTarget{transaction.registration.Target}, nil
	}
	return append([]paasv1.ExecutionTarget(nil), transaction.poolTargets...), nil
}
func (transaction *refreshTransaction) LoadTarget(context.Context, paasv1.ResourceID) (Registration, bool, error) {
	return transaction.registration, true, nil
}
func (transaction *refreshTransaction) LoadPoolTarget(context.Context, paasv1.ResourceID) (paasv1.ExecutionTarget, bool, error) {
	return transaction.registration.Target, true, nil
}
func (transaction *refreshTransaction) LoadPool(context.Context, paasv1.ResourceID) (paasv1.ExecutionPool, bool, error) {
	return transaction.pool, true, nil
}
func (transaction *refreshTransaction) RefreshTarget(_ context.Context, version uint64, target paasv1.ExecutionTarget, poolVersion uint64, pool paasv1.ExecutionPool) error {
	if version != transaction.registration.Target.Metadata.ResourceVersion || poolVersion != transaction.pool.Metadata.ResourceVersion {
		return ErrConflict
	}
	transaction.registration.Target, transaction.pool = target, pool
	for index := range transaction.poolTargets {
		if transaction.poolTargets[index].Metadata.ID == target.Metadata.ID {
			transaction.poolTargets[index] = target
		}
	}
	return nil
}
func (transaction *refreshTransaction) TransitionTarget(_ context.Context, version uint64, target paasv1.ExecutionTarget, poolVersion uint64, pool paasv1.ExecutionPool, submission Submission) error {
	if version != transaction.registration.Target.Metadata.ResourceVersion ||
		poolVersion != transaction.pool.Metadata.ResourceVersion {
		return ErrConflict
	}
	transaction.transitionCalls++
	transaction.registration.Target, transaction.pool = target, pool
	if transaction.operations == nil {
		transaction.operations = make(map[string]paasv1.Operation)
	}
	transaction.operations[submission.Operation.IdempotencyFingerprint] = submission.Operation
	return nil
}

type refreshAdapter struct {
	port.InfrastructureAdapter
	observation             paasv1.ExecutionTargetObservation
	transaction             *refreshTransaction
	before                  func()
	err                     error
	calls                   int
	probedInsideTransaction bool
}

func (adapter *refreshAdapter) ObserveExecutionTarget(context.Context, paasv1.ObserveExecutionTargetRequest) (paasv1.ExecutionTargetObservation, error) {
	adapter.calls++
	adapter.probedInsideTransaction = adapter.probedInsideTransaction || adapter.transaction.active
	if adapter.before != nil {
		adapter.before()
	}
	return adapter.observation, adapter.err
}

func refreshFixture(t *testing.T) (*Service, *refreshTransaction, *refreshAdapter, time.Time) {
	t.Helper()
	now := time.Date(2026, 8, 27, 4, 5, 6, 0, time.UTC)
	fingerprint := "sha256:" + strings.Repeat("a", 64)
	observation := paasv1.ExecutionTargetObservation{ExecutionTargetID: "target-a", IdentityFingerprint: fingerprint, Health: paasv1.ExecutionTargetHealthReady,
		Capacity:                     paasv1.Capacity{CPUMillis: 4000, MemoryBytes: 8 << 30, StorageBytes: 100 << 30, WorkloadSlots: 32},
		Allocatable:                  paasv1.Capacity{CPUMillis: 3000, MemoryBytes: 6 << 30, StorageBytes: 80 << 30, WorkloadSlots: 24},
		SupportedIsolationGuarantees: []paasv1.IsolationGuarantee{paasv1.IsolationWorkload}, ObservedAt: now,
		Usage: &paasv1.ExecutionTargetUsage{ObservedAt: now, ValidUntil: now.Add(15 * time.Second), CPU: paasv1.CPUUsage{State: paasv1.MeasurementUnavailable}, Memory: paasv1.MemoryUsage{State: paasv1.MeasurementUnavailable}, FilesystemsState: paasv1.MeasurementUnavailable}}
	target := paasv1.ExecutionTarget{APIVersion: paasv1.APIVersion, Kind: "ExecutionTarget", Metadata: metadata("target-a", "node-a", map[string]string{fingerprintLabel: fingerprint}, now.Add(-5*time.Second)),
		Spec: paasv1.ExecutionTargetSpec{ExecutionPoolID: "pool-a", InfrastructureAdapter: paasv1.AdapterRef{Kind: paasv1.AdapterInfrastructure, Name: "nodehttps", ContractVersion: "v1"}, DeploymentExecutor: paasv1.AdapterRef{Kind: paasv1.AdapterDeploymentExecutor, Name: "compose", ContractVersion: "v1"}, DesiredState: paasv1.ExecutionTargetActive}, Status: statusFromObservation(observation, now)}
	target.Status.ObservedAt = now.Add(-5 * time.Second)
	pool := paasv1.ExecutionPool{APIVersion: paasv1.APIVersion, Kind: "ExecutionPool", Metadata: metadata("pool-a", "nodes", nil, now.Add(-5*time.Second)), Spec: paasv1.ExecutionPoolSpec{AllowedIsolationGuarantees: []paasv1.IsolationGuarantee{paasv1.IsolationWorkload}}, Status: paasv1.ExecutionPoolStatus{Phase: paasv1.ExecutionPoolReady, ExecutionTargetCount: 1, ReadyExecutionTargetCount: 1, ObservedAt: now.Add(-5 * time.Second)}}
	transaction := &refreshTransaction{now: now, registration: Registration{Target: target, BindingRef: "binding-a", IdentityFingerprint: fingerprint}, pool: pool}
	adapter := &refreshAdapter{observation: observation, transaction: transaction}
	service, err := New(transaction, Config{InstallationID: "installation-a", Bindings: []Binding{{Ref: "binding-a", TargetID: "target-a", IdentityFingerprint: fingerprint, Adapter: adapter}}, ObservationTimeout: time.Second, MaximumObservationAge: 15 * time.Second, MaxTransactionAttempts: 3, Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	return service, transaction, adapter, now
}
