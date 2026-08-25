package createplacement

import (
	"context"
	"strings"
	"testing"
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/domain/placement"
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
	deploymentID paasv1.ResourceID,
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
		TenantID:      "tenant-a",
		OperationID:   "operation-a",
		DecisionID:    "decision-a",
		DeploymentID:  "deployment-a",
		RequestDigest: createDigest('a'),
		TraceID:       "trace-a",
	}
}

func createPlacementSnapshot() placement.Snapshot {
	pool := paasv1.ExecutionPool{
		APIVersion: paasv1.APIVersion,
		Kind:       "ExecutionPool",
		Metadata:   createMetadata("pool-a", paasv1.AuthorityPlatform, "", 3),
		Spec: paasv1.ExecutionPoolSpec{
			ExecutionTargetSelector: paasv1.LabelSelector{MatchLabels: map[string]string{
				"executor": "compose",
			}},
			AllowedIsolationGuarantees: []paasv1.IsolationGuarantee{
				paasv1.IsolationWorkload,
			},
		},
		Status: paasv1.ExecutionPoolStatus{
			Phase:                     paasv1.ExecutionPoolReady,
			ExecutionTargetCount:      1,
			ReadyExecutionTargetCount: 1,
			ObservedAt:                createPlacementTime.Add(-time.Minute),
		},
	}
	target := paasv1.ExecutionTarget{
		APIVersion: paasv1.APIVersion,
		Kind:       "ExecutionTarget",
		Metadata:   createMetadata("target-a", paasv1.AuthorityPlatform, "", 7),
		Spec: paasv1.ExecutionTargetSpec{
			ExecutionPoolID: "pool-a",
			InfrastructureAdapter: paasv1.AdapterRef{
				Kind:            paasv1.AdapterInfrastructure,
				Name:            "localmachine",
				ContractVersion: "v1",
			},
			DeploymentExecutor: paasv1.AdapterRef{
				Kind:            paasv1.AdapterDeploymentExecutor,
				Name:            "compose",
				ContractVersion: "v1",
			},
			DesiredState: paasv1.ExecutionTargetActive,
		},
		Status: paasv1.ExecutionTargetStatus{
			Health: paasv1.ExecutionTargetHealthReady,
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
			SupportedIsolationGuarantees: []paasv1.IsolationGuarantee{
				paasv1.IsolationWorkload,
			},
			ObservedAt: createPlacementTime.Add(-time.Minute),
		},
	}
	target.Metadata.Labels = map[string]string{"executor": "compose"}
	return placement.Snapshot{
		Deployment: paasv1.Deployment{
			APIVersion: paasv1.APIVersion,
			Kind:       "Deployment",
			Metadata:   createMetadata("deployment-a", paasv1.AuthorityTenant, "tenant-a", 2),
			Generation: 1,
			Spec: paasv1.DeploymentSpec{
				ApplicationRevisionID: "revision-a",
				PlacementPolicyID:     "policy-a",
				DesiredState:          paasv1.DeploymentDesiredRunning,
				Components: []paasv1.DeploymentComponent{
					{Name: "api", Replicas: 1},
				},
			},
			Status: paasv1.DeploymentStatus{
				Phase:              paasv1.DeploymentPending,
				ObservedGeneration: 0,
				ObservedAt:         createPlacementTime.Add(-time.Minute),
			},
		},
		ApplicationRevision: paasv1.ApplicationRevision{
			APIVersion: paasv1.APIVersion,
			Kind:       "ApplicationRevision",
			Metadata:   createImmutableMetadata("revision-a", "tenant-a"),
			Spec: paasv1.ApplicationRevisionSpec{
				ApplicationID: "application-a",
				Revision:      "revision-a",
				ContentDigest: createDigest('b'),
				Components: []paasv1.ApplicationRevisionComponent{{
					Name: "api",
					Artifact: paasv1.ArtifactRef{
						Kind:    paasv1.ArtifactOCIImage,
						Locator: "registry.example.invalid/application/api",
						Digest:  createDigest('c'),
					},
					Resources: paasv1.ResourceRequirements{
						CPUMillis:   250,
						MemoryBytes: 64 * 1024 * 1024,
					},
				}},
			},
		},
		Policy: paasv1.PlacementPolicy{
			APIVersion: paasv1.APIVersion,
			Kind:       "PlacementPolicy",
			Metadata:   createMetadata("policy-a", paasv1.AuthorityTenant, "tenant-a", 4),
			Spec: paasv1.PlacementPolicySpec{
				RequiredIsolationGuarantee: paasv1.IsolationWorkload,
				EligibleExecutionPoolIDs:   []paasv1.ResourceID{"pool-a"},
				ExecutionTargetSelector: paasv1.LabelSelector{MatchLabels: map[string]string{
					"executor": "compose",
				}},
				Strategy: paasv1.PlacementFirstFit,
			},
		},
		Pools:   []paasv1.ExecutionPool{pool},
		Targets: []paasv1.ExecutionTarget{target},
	}
}

func createImmutableMetadata(
	id paasv1.ResourceID,
	tenantID paasv1.TenantID,
) paasv1.ResourceMetadata {
	createdAt := createPlacementTime.Add(-10 * time.Minute)
	return paasv1.ResourceMetadata{
		ID:   id,
		Name: string(id),
		Scope: paasv1.ResourceScope{
			Kind:     paasv1.AuthorityTenant,
			TenantID: tenantID,
		},
		ResourceVersion: 1,
		CreatedAt:       createdAt,
		UpdatedAt:       createdAt,
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
		APIVersion:                     paasv1.APIVersion,
		Kind:                           "PlacementDecision",
		Metadata:                       createMetadata(command.DecisionID, paasv1.AuthorityTenant, command.TenantID, 1),
		DeploymentID:                   command.DeploymentID,
		DeploymentGeneration:           1,
		DeploymentResourceVersion:      2,
		ApplicationRevisionID:          "revision-a",
		PlacementPolicyID:              "policy-a",
		PolicyResourceVersion:          4,
		RequestedIsolationGuarantee:    paasv1.IsolationWorkload,
		Outcome:                        paasv1.PlacementScheduled,
		ExecutionTargetID:              "target-a",
		ExecutionTargetResourceVersion: 7,
		GrantedIsolationGuarantee:      paasv1.IsolationWorkload,
		CandidateSetDigest:             createDigest('d'),
		DecidedAt:                      createPlacementTime,
	}
}

func createDigest(character byte) string {
	return "sha256:" + strings.Repeat(string(character), 64)
}
