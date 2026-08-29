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

type refreshTransaction struct {
	Transaction
	now          time.Time
	registration Registration
	poolTargets  []paasv1.ExecutionTarget
	pool         paasv1.ExecutionPool
	calls        int
	active       bool
}

func (transaction *refreshTransaction) WithinTransaction(ctx context.Context, installation string, callback func(context.Context, Transaction) error) error {
	transaction.calls++
	transaction.active = true
	defer func() { transaction.active = false }()
	if installation != "installation-a" {
		return ErrConflict
	}
	return callback(ctx, transaction)
}
func (transaction *refreshTransaction) TransactionTime(context.Context) (time.Time, error) {
	return transaction.now, nil
}
func (transaction *refreshTransaction) ListTargets(context.Context) ([]Registration, error) {
	return []Registration{transaction.registration}, nil
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
