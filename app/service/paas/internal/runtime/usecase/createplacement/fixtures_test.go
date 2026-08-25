package createplacement

import (
	"context"
	"strings"
	"testing"
	"time"

	paasv1 "matrix/api/paas/v1"
	"matrix/app/service/paas/internal/runtime/domain/placement"
)

var createPlacementTime = time.Date(2026, 8, 25, 14, 0, 0, 123_000, time.UTC)

type fakeRepository struct {
	transaction         Transaction
	afterCallbackErrors []error
	calls               int
	tenantID            paasv1.TenantID
}

func (repository *fakeRepository) WithinTransaction(
	ctx context.Context,
	tenantID paasv1.TenantID,
	callback func(context.Context, Transaction) error,
) error {
	repository.calls++
	repository.tenantID = tenantID
	if err := callback(ctx, repository.transaction); err != nil {
		return err
	}
	index := repository.calls - 1
	if index < len(repository.afterCallbackErrors) {
		return repository.afterCallbackErrors[index]
	}
	return nil
}

type fakeTransaction struct {
	time        time.Time
	snapshot    placement.Snapshot
	found       bool
	stored      StoredDecision
	creation    DecisionCreation
	timeCalls   int
	loadCalls   int
	insertCalls int
}

func (transaction *fakeTransaction) TransactionTime(context.Context) (time.Time, error) {
	transaction.timeCalls++
	return transaction.time, nil
}

func (transaction *fakeTransaction) FindDecisionByOperation(
	context.Context,
	paasv1.OperationID,
) (StoredDecision, bool, error) {
	return transaction.stored, transaction.found, nil
}

func (transaction *fakeTransaction) LoadAndLockSnapshot(
	_ context.Context,
	releaseID paasv1.ResourceID,
	policyID paasv1.ResourceID,
) (placement.Snapshot, error) {
	transaction.loadCalls++
	return transaction.snapshot, nil
}

func (transaction *fakeTransaction) CreateDecision(
	_ context.Context,
	creation DecisionCreation,
) error {
	transaction.insertCalls++
	transaction.creation = creation
	return nil
}

func mustUsecase(t *testing.T, repository Repository) *Usecase {
	t.Helper()
	planner, err := placement.NewV1Planner(5 * time.Minute)
	if err != nil {
		t.Fatalf("new planner: %v", err)
	}
	usecase, err := NewUsecase(planner, repository, Config{
		PendingReservationTTL:  10 * time.Minute,
		MaxTransactionAttempts: 3,
	})
	if err != nil {
		t.Fatalf("new use case: %v", err)
	}
	return usecase
}

func createPlacementCommand() Command {
	return Command{
		TenantID:          "tenant-a",
		OperationID:       "operation-a",
		DecisionID:        "decision-a",
		WorkloadReleaseID: "release-a",
		PlacementPolicyID: "policy-a",
		RequestDigest:     createDigest('a'),
		TraceID:           "trace-a",
	}
}

func createPlacementSnapshot() placement.Snapshot {
	pool := paasv1.ResourcePool{
		APIVersion: paasv1.APIVersion,
		Kind:       "ResourcePool",
		Metadata:   createMetadata("pool-a", paasv1.AuthorityPlatform, "", 3),
		Spec: paasv1.ResourcePoolSpec{
			TargetSelector: paasv1.LabelSelector{MatchLabels: map[string]string{
				"runtime": "compose",
			}},
			AllowedIsolationClasses: []paasv1.IsolationClass{
				paasv1.IsolationSharedCompose,
				paasv1.IsolationDedicatedCompose,
			},
		},
		Status: paasv1.ResourcePoolStatus{
			Phase:            paasv1.ResourcePoolReady,
			TargetCount:      1,
			ReadyTargetCount: 1,
			ObservedAt:       createPlacementTime.Add(-time.Minute),
		},
	}
	target := paasv1.RuntimeTarget{
		APIVersion: paasv1.APIVersion,
		Kind:       "RuntimeTarget",
		Metadata:   createMetadata("target-a", paasv1.AuthorityPlatform, "", 7),
		Spec: paasv1.RuntimeTargetSpec{
			ResourcePoolID: "pool-a",
			InfrastructureAdapter: paasv1.AdapterRef{
				Kind:            paasv1.AdapterInfrastructure,
				Name:            "localmachine",
				ContractVersion: "v1",
			},
			RuntimeAdapter: paasv1.AdapterRef{
				Kind:            paasv1.AdapterRuntime,
				Name:            "compose",
				ContractVersion: "v1",
			},
			DesiredState: paasv1.TargetActive,
		},
		Status: paasv1.RuntimeTargetStatus{
			Health: paasv1.TargetHealthReady,
			Capacity: paasv1.Capacity{
				CPUMillis:     2_000,
				MemoryBytes:   2 * 1024 * 1024 * 1024,
				StorageBytes:  10_000,
				WorkloadSlots: 10,
			},
			Allocatable: paasv1.Capacity{
				CPUMillis:     1_000,
				MemoryBytes:   1024 * 1024 * 1024,
				StorageBytes:  8_000,
				WorkloadSlots: 5,
			},
			SupportedIsolationClasses: []paasv1.IsolationClass{
				paasv1.IsolationSharedCompose,
				paasv1.IsolationDedicatedCompose,
			},
			ObservedAt: createPlacementTime.Add(-time.Minute),
		},
	}
	target.Metadata.Labels = map[string]string{"runtime": "compose"}
	return placement.Snapshot{
		Release: paasv1.WorkloadRelease{
			APIVersion: paasv1.APIVersion,
			Kind:       "WorkloadRelease",
			Metadata:   createMetadata("release-a", paasv1.AuthorityTenant, "tenant-a", 2),
			Spec: paasv1.WorkloadReleaseSpec{
				WorkloadID:    "workload-a",
				Revision:      "revision-a",
				ContentDigest: createDigest('b'),
				Components: []paasv1.WorkloadComponent{{
					Name: "api",
					Artifact: paasv1.ArtifactRef{
						Kind:    paasv1.ArtifactOCIImage,
						Locator: "registry.example.invalid/workload/api",
						Digest:  createDigest('c'),
					},
					Replicas: 1,
					Resources: paasv1.ResourceRequirements{
						CPUMillis:   250,
						MemoryBytes: 64 * 1024 * 1024,
					},
				}},
			},
			Status: paasv1.WorkloadReleaseStatus{
				Phase:      paasv1.ReleasePending,
				ObservedAt: createPlacementTime.Add(-time.Minute),
			},
		},
		Policy: paasv1.PlacementPolicy{
			APIVersion: paasv1.APIVersion,
			Kind:       "PlacementPolicy",
			Metadata:   createMetadata("policy-a", paasv1.AuthorityTenant, "tenant-a", 4),
			Spec: paasv1.PlacementPolicySpec{
				RequiredIsolationClass: paasv1.IsolationSharedCompose,
				EligibleResourcePools:  []paasv1.ResourceID{"pool-a"},
				TargetSelector: paasv1.LabelSelector{MatchLabels: map[string]string{
					"runtime": "compose",
				}},
				Strategy: paasv1.PlacementFirstFit,
			},
		},
		Pools:   []paasv1.ResourcePool{pool},
		Targets: []paasv1.RuntimeTarget{target},
	}
}

func createMetadata(
	id paasv1.ResourceID,
	kind paasv1.AuthorityKind,
	tenantID paasv1.TenantID,
	version uint64,
) paasv1.ResourceMetadata {
	return paasv1.ResourceMetadata{
		ID:   id,
		Name: string(id),
		Scope: paasv1.ResourceScope{
			Kind:     kind,
			TenantID: tenantID,
		},
		ResourceVersion: version,
		CreatedAt:       createPlacementTime.Add(-10 * time.Minute),
		UpdatedAt:       createPlacementTime.Add(-5 * time.Minute),
	}
}

func scheduledDecision(command Command) paasv1.PlacementDecision {
	return paasv1.PlacementDecision{
		APIVersion:                   paasv1.APIVersion,
		Kind:                         "PlacementDecision",
		Metadata:                     createMetadata(command.DecisionID, paasv1.AuthorityTenant, command.TenantID, 1),
		WorkloadReleaseID:            command.WorkloadReleaseID,
		PlacementPolicyID:            command.PlacementPolicyID,
		PolicyResourceVersion:        4,
		RequestedIsolation:           paasv1.IsolationSharedCompose,
		Outcome:                      paasv1.PlacementScheduled,
		RuntimeTargetID:              "target-a",
		RuntimeTargetResourceVersion: 7,
		GrantedIsolation:             paasv1.IsolationSharedCompose,
		CandidateSetDigest:           createDigest('d'),
		DecidedAt:                    createPlacementTime,
	}
}

func createDigest(character byte) string {
	return "sha256:" + strings.Repeat(string(character), 64)
}
