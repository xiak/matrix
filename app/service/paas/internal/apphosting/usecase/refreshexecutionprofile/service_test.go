package refreshexecutionprofile

import (
	"context"
	"errors"
	"testing"
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

var profileTestTime = time.Date(2026, 8, 26, 8, 0, 0, 0, time.UTC)

type profileAdapter struct {
	observation paasv1.ExecutionTargetObservation
}

func (adapter *profileAdapter) Capabilities(context.Context) (paasv1.AdapterCapabilitiesContract, error) {
	return paasv1.AdapterCapabilitiesContract{}, nil
}

func (adapter *profileAdapter) InspectExecutionTarget(
	context.Context,
	paasv1.InspectExecutionTargetRequest,
) (paasv1.ExecutionTargetObservation, error) {
	return paasv1.ExecutionTargetObservation{}, errors.New("unexpected inspection")
}

func (adapter *profileAdapter) ObserveExecutionTarget(
	_ context.Context,
	request paasv1.ObserveExecutionTargetRequest,
) (paasv1.ExecutionTargetObservation, error) {
	if paasv1.ValidateObserveExecutionTargetRequest(request) != nil ||
		request.Command.ExecutionTargetID != adapter.observation.ExecutionTargetID {
		return paasv1.ExecutionTargetObservation{}, errors.New("invalid observation request")
	}
	return adapter.observation, nil
}

type profileRepository struct {
	snapshot Snapshot
	saves    int
}

func (repository *profileRepository) WithinTransaction(
	ctx context.Context,
	_ paasv1.TenantID,
	_ string,
	callback func(context.Context, Transaction) error,
) error {
	return callback(ctx, &profileTransaction{repository: repository})
}

type profileTransaction struct {
	repository *profileRepository
}

func (transaction *profileTransaction) Load(context.Context, IDs) (Snapshot, error) {
	return transaction.repository.snapshot, nil
}

func (transaction *profileTransaction) Save(
	_ context.Context,
	versions Versions,
	profile Profile,
) error {
	current := transaction.repository.snapshot
	if versions.Pool != currentPoolVersion(current.Pool) ||
		versions.Target != currentTargetVersion(current.Target) ||
		versions.Policy != currentPolicyVersion(current.Policy) {
		return ErrRetryableTransaction
	}
	transaction.repository.snapshot.Pool = &profile.Pool
	transaction.repository.snapshot.Target = &profile.Target
	transaction.repository.snapshot.Policy = &profile.Policy
	found := false
	for index := range transaction.repository.snapshot.Targets {
		if transaction.repository.snapshot.Targets[index].Metadata.ID == profile.Target.Metadata.ID {
			transaction.repository.snapshot.Targets[index] = profile.Target
			found = true
		}
	}
	if !found {
		transaction.repository.snapshot.Targets = append(
			transaction.repository.snapshot.Targets,
			profile.Target,
		)
	}
	transaction.repository.saves++
	return nil
}

func TestRefreshCreatesAndKeepsLocalProfileFresh(t *testing.T) {
	adapter := &profileAdapter{observation: readyProfileObservation(profileTestTime)}
	repository := &profileRepository{snapshot: Snapshot{TransactionTime: profileTestTime}}
	service := newProfileService(t, adapter, repository)
	if err := service.Refresh(context.Background()); err != nil {
		t.Fatalf("create local execution profile: %v", err)
	}
	if repository.saves != 1 || repository.snapshot.Pool == nil ||
		repository.snapshot.Target == nil || repository.snapshot.Policy == nil {
		t.Fatalf("created execution profile = %#v", repository.snapshot)
	}
	if repository.snapshot.Policy.Metadata.ResourceVersion != 1 ||
		repository.snapshot.Target.Metadata.Labels[fingerprintLabel] !=
			adapter.observation.IdentityFingerprint ||
		repository.snapshot.Policy.Metadata.Scope.TenantID != "organization-default" {
		t.Fatalf("created execution profile authority = %#v", repository.snapshot)
	}
	if err := service.Ready(context.Background()); err != nil {
		t.Fatalf("fresh execution profile readiness: %v", err)
	}

	repository.snapshot.TransactionTime = profileTestTime.Add(time.Minute)
	adapter.observation.ObservedAt = profileTestTime.Add(time.Minute)
	if err := service.Refresh(context.Background()); err != nil {
		t.Fatalf("refresh local execution profile: %v", err)
	}
	if repository.snapshot.Pool.Metadata.ResourceVersion != 2 ||
		repository.snapshot.Target.Metadata.ResourceVersion != 2 ||
		repository.snapshot.Policy.Metadata.ResourceVersion != 1 {
		t.Fatalf("refreshed execution profile versions = %#v", repository.snapshot)
	}

	repository.snapshot.TransactionTime = profileTestTime.Add(2 * time.Minute)
	repository.snapshot.Target.Status.ObservedAt = repository.snapshot.TransactionTime.Add(
		maximumObservationFutureSkew + time.Microsecond,
	)
	if err := service.Ready(context.Background()); err == nil {
		t.Fatal("future execution profile observation reported ready")
	}
	repository.snapshot.Target.Status.ObservedAt = profileTestTime.Add(time.Minute)
	repository.snapshot.TransactionTime = profileTestTime.Add(7 * time.Minute)
	if err := service.Ready(context.Background()); err == nil {
		t.Fatal("stale execution profile reported ready")
	}
}

func TestRefreshPersistsDegradedProfileWithoutIsolation(t *testing.T) {
	observation := readyProfileObservation(profileTestTime)
	observation.Health = paasv1.ExecutionTargetHealthDegraded
	observation.SupportedIsolationGuarantees = nil
	adapter := &profileAdapter{observation: observation}
	repository := &profileRepository{snapshot: Snapshot{TransactionTime: profileTestTime}}
	service := newProfileService(t, adapter, repository)
	if err := service.Refresh(context.Background()); err != nil {
		t.Fatalf("refresh degraded local execution profile: %v", err)
	}
	if repository.snapshot.Pool.Status.Phase != paasv1.ExecutionPoolDegraded ||
		repository.snapshot.Pool.Status.ReadyExecutionTargetCount != 0 ||
		len(repository.snapshot.Target.Status.SupportedIsolationGuarantees) != 0 {
		t.Fatalf("degraded execution profile = %#v", repository.snapshot)
	}
	if err := service.Ready(context.Background()); err == nil {
		t.Fatal("degraded execution profile reported ready")
	}
}

func TestRefreshPreservesManagedTargetsAndLocalReadiness(t *testing.T) {
	adapter := &profileAdapter{observation: readyProfileObservation(profileTestTime)}
	repository := &profileRepository{snapshot: Snapshot{TransactionTime: profileTestTime}}
	service := newProfileService(t, adapter, repository)
	if err := service.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	managed := repository.snapshot.Targets[0]
	managed.Metadata.ID = "execution-target-managed"
	managed.Metadata.Name = "managed"
	managed.Metadata.ResourceVersion = 1
	managed.Metadata.Labels = map[string]string{
		"matrix-os": "linux", "matrix-arch": "amd64",
		profileLabelKey: profileLabelValue, fingerprintLabel: "sha256:" + repeatHex("b"),
	}
	managed.Spec.InfrastructureAdapter.Name = "nodehttps"
	managed.Status.ObservedAt = profileTestTime
	repository.snapshot.Targets = append(repository.snapshot.Targets, managed)
	repository.snapshot.TransactionTime = profileTestTime.Add(time.Second)
	adapter.observation.ObservedAt = repository.snapshot.TransactionTime
	if err := service.Refresh(context.Background()); err != nil {
		t.Fatalf("refresh profile with managed target: %v", err)
	}
	if len(repository.snapshot.Targets) != 2 ||
		repository.snapshot.Targets[1].Metadata.ID != managed.Metadata.ID ||
		repository.snapshot.Pool.Status.ExecutionTargetCount != 2 ||
		repository.snapshot.Pool.Status.ReadyExecutionTargetCount != 2 ||
		repository.snapshot.Pool.Status.Phase != paasv1.ExecutionPoolReady {
		t.Fatalf("managed target was not preserved: %#v", repository.snapshot)
	}

	repository.snapshot.Targets[1].Status.Health = paasv1.ExecutionTargetHealthUnavailable
	repository.snapshot.Targets[1].Status.SupportedIsolationGuarantees = nil
	repository.snapshot.TransactionTime = profileTestTime.Add(2 * time.Second)
	adapter.observation.ObservedAt = repository.snapshot.TransactionTime
	if err := service.Refresh(context.Background()); err != nil {
		t.Fatalf("refresh profile with unavailable managed target: %v", err)
	}
	if repository.snapshot.Pool.Status.Phase != paasv1.ExecutionPoolDegraded ||
		repository.snapshot.Pool.Status.ExecutionTargetCount != 2 ||
		repository.snapshot.Pool.Status.ReadyExecutionTargetCount != 1 {
		t.Fatalf("mixed pool status = %#v", repository.snapshot.Pool.Status)
	}
	if err := service.Ready(context.Background()); err != nil {
		t.Fatalf("local readiness depended on managed target: %v", err)
	}
}

func TestRefreshRejectsStoredProfileSelectorDrift(t *testing.T) {
	adapter := &profileAdapter{observation: readyProfileObservation(profileTestTime)}
	repository := &profileRepository{snapshot: Snapshot{TransactionTime: profileTestTime}}
	service := newProfileService(t, adapter, repository)
	if err := service.Refresh(context.Background()); err != nil {
		t.Fatalf("create local execution profile: %v", err)
	}
	repository.snapshot.TransactionTime = profileTestTime.Add(time.Minute)
	adapter.observation.ObservedAt = repository.snapshot.TransactionTime
	repository.snapshot.Pool.Spec.ExecutionTargetSelector.MatchLabels["unexpected"] = "drift"
	if err := service.Refresh(context.Background()); !errors.Is(err, ErrConflict) {
		t.Fatalf("stored selector drift error = %v", err)
	}
	if repository.saves != 1 {
		t.Fatal("stored selector drift rewrote the execution profile")
	}
}

func TestRefreshRejectsMachineIdentityChange(t *testing.T) {
	adapter := &profileAdapter{observation: readyProfileObservation(profileTestTime)}
	repository := &profileRepository{snapshot: Snapshot{TransactionTime: profileTestTime}}
	service := newProfileService(t, adapter, repository)
	if err := service.Refresh(context.Background()); err != nil {
		t.Fatalf("create local execution profile: %v", err)
	}
	repository.snapshot.TransactionTime = profileTestTime.Add(time.Minute)
	adapter.observation.ObservedAt = profileTestTime.Add(time.Minute)
	adapter.observation.IdentityFingerprint = "sha256:" + repeatHex("b")
	if err := service.Refresh(context.Background()); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed machine identity error = %v", err)
	}
	if repository.saves != 1 {
		t.Fatal("changed machine identity rewrote the execution profile")
	}
}

func newProfileService(
	t *testing.T,
	adapter *profileAdapter,
	repository *profileRepository,
) *Service {
	t.Helper()
	service, err := New(adapter, repository, Config{
		InstallationID: "installation-local",
		TenantID:       "organization-default",
		IDs: IDs{
			PoolID: "execution-pool-local", TargetID: "execution-target-local",
			PolicyID: "placement-policy-local",
		},
		MachineBindingRef: "local-machine-v1", ObservationTimeout: 5 * time.Second,
		MaximumObservationAge: 5 * time.Minute, MaxTransactionAttempts: 3,
		Clock: func() time.Time { return repository.snapshot.TransactionTime },
	})
	if err != nil {
		t.Fatalf("create execution profile service: %v", err)
	}
	return service
}

func readyProfileObservation(at time.Time) paasv1.ExecutionTargetObservation {
	return paasv1.ExecutionTargetObservation{
		ExecutionTargetID:   "execution-target-local",
		IdentityFingerprint: "sha256:" + repeatHex("a"),
		Labels:              map[string]string{"matrix-os": "linux", "matrix-arch": "amd64"},
		Capacity: paasv1.Capacity{
			CPUMillis: 8000, MemoryBytes: 16 * 1024 * 1024 * 1024,
			StorageBytes: 100 * 1024 * 1024 * 1024, WorkloadSlots: 8,
		},
		Allocatable: paasv1.Capacity{
			CPUMillis: 8000, MemoryBytes: 8 * 1024 * 1024 * 1024,
			StorageBytes: 50 * 1024 * 1024 * 1024, WorkloadSlots: 8,
		},
		Health:                       paasv1.ExecutionTargetHealthReady,
		SupportedIsolationGuarantees: []paasv1.IsolationGuarantee{paasv1.IsolationWorkload},
		ObservedAt:                   at,
	}
}

func repeatHex(value string) string {
	result := ""
	for len(result) < 64 {
		result += value
	}
	return result
}
