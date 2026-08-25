package port

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

var _ DeploymentExecutor = (*replayDeploymentExecutor)(nil)

type replayDeploymentExecutor struct {
	mu             sync.Mutex
	requestDigests map[paasv1.CommandID]string
	results        map[paasv1.CommandID]paasv1.AdapterResult
	effects        int
}

func newReplayDeploymentExecutor() *replayDeploymentExecutor {
	return &replayDeploymentExecutor{
		requestDigests: make(map[paasv1.CommandID]string),
		results:        make(map[paasv1.CommandID]paasv1.AdapterResult),
	}
}

func (*replayDeploymentExecutor) Capabilities(context.Context) (paasv1.AdapterCapabilitiesContract, error) {
	return paasv1.AdapterCapabilitiesContract{}, nil
}

func (*replayDeploymentExecutor) ValidateDeployment(
	context.Context,
	paasv1.DeploymentExecutionRequest,
) (paasv1.AdapterResult, error) {
	return paasv1.AdapterResult{}, nil
}

func (adapter *replayDeploymentExecutor) ApplyDeployment(
	_ context.Context,
	request paasv1.DeploymentExecutionRequest,
) (paasv1.AdapterResult, error) {
	if err := paasv1.ValidateDeploymentExecutionRequest(request); err != nil {
		return paasv1.AdapterResult{}, err
	}
	adapter.mu.Lock()
	defer adapter.mu.Unlock()

	command := request.Command
	if digest, found := adapter.requestDigests[command.CommandID]; found {
		if digest != command.RequestDigest {
			return paasv1.AdapterResult{}, AdapterFault{
				Normalized: paasv1.NormalizedAdapterError{
					Class:     paasv1.AdapterErrorConflict,
					Code:      paasv1.ErrorIdempotencyConflict,
					Message:   "command identity was reused with a different request digest",
					Retryable: false,
				},
			}
		}
		result := adapter.results[command.CommandID]
		result.Replayed = true
		return result, nil
	}

	adapter.effects++
	result := paasv1.AdapterResult{
		CommandID:  command.CommandID,
		State:      paasv1.AdapterResultSucceeded,
		Receipt:    "receipt-" + string(command.CommandID),
		ObservedAt: time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC),
	}
	adapter.requestDigests[command.CommandID] = command.RequestDigest
	adapter.results[command.CommandID] = result
	return result, nil
}

func (*replayDeploymentExecutor) ObserveDeployment(
	context.Context,
	paasv1.ObserveDeploymentRequest,
) (paasv1.DeploymentObservation, error) {
	return paasv1.DeploymentObservation{}, nil
}

func (*replayDeploymentExecutor) StopDeployment(
	context.Context,
	paasv1.DeploymentExecutionRequest,
) (paasv1.AdapterResult, error) {
	return paasv1.AdapterResult{}, nil
}

func (*replayDeploymentExecutor) RollbackDeployment(
	context.Context,
	paasv1.DeploymentExecutionRequest,
) (paasv1.AdapterResult, error) {
	return paasv1.AdapterResult{}, nil
}

func TestDeploymentExecutorReplaysOneEffectForSameCommand(t *testing.T) {
	adapter := newReplayDeploymentExecutor()
	request := replayRequest(1)

	first, err := adapter.ApplyDeployment(context.Background(), request)
	if err != nil {
		t.Fatalf("first ApplyDeployment() error = %v", err)
	}
	second, err := adapter.ApplyDeployment(context.Background(), request)
	if err != nil {
		t.Fatalf("replayed ApplyDeployment() error = %v", err)
	}

	if first.Replayed {
		t.Fatal("first result must not be marked as replayed")
	}
	if !second.Replayed {
		t.Fatal("second result must be marked as replayed")
	}
	if first.Receipt != second.Receipt {
		t.Fatalf("replay receipt = %q, want original %q", second.Receipt, first.Receipt)
	}
	if adapter.effects != 1 {
		t.Fatalf("side effects = %d, want 1", adapter.effects)
	}
}

func TestDeploymentExecutorRejectsConflictingReplay(t *testing.T) {
	adapter := newReplayDeploymentExecutor()
	first := replayRequest(1)
	if _, err := adapter.ApplyDeployment(context.Background(), first); err != nil {
		t.Fatalf("first ApplyDeployment() error = %v", err)
	}

	conflict := replayRequest(2)
	_, err := adapter.ApplyDeployment(context.Background(), conflict)
	if err == nil {
		t.Fatal("conflicting replay must fail")
	}
	var fault AdapterFault
	if !errors.As(err, &fault) {
		t.Fatalf("conflicting replay error type = %T, want AdapterFault", err)
	}
	if fault.Normalized.Code != paasv1.ErrorIdempotencyConflict {
		t.Fatalf("conflicting replay code = %q, want %q", fault.Normalized.Code, paasv1.ErrorIdempotencyConflict)
	}
	if fault.Normalized.Retryable {
		t.Fatal("idempotency conflict must not be retryable")
	}
	if adapter.effects != 1 {
		t.Fatalf("side effects after conflict = %d, want 1", adapter.effects)
	}
}

func TestAdapterCommandEnvelopeCannotCarryRawAccessMaterial(t *testing.T) {
	envelope := reflect.TypeOf(paasv1.AdapterCommandEnvelope{})
	forbidden := []string{
		"credential",
		"password",
		"secret",
		"token",
		"authorization",
		"shell",
		"commandtext",
		"ssh",
		"hostpath",
		"privatekey",
	}
	for index := 0; index < envelope.NumField(); index++ {
		field := envelope.Field(index)
		wireName := strings.Split(field.Tag.Get("json"), ",")[0]
		normalized := strings.ToLower(field.Name + wireName)
		for _, marker := range forbidden {
			if strings.Contains(normalized, marker) {
				t.Errorf("adapter command field %q carries forbidden access material marker %q", field.Name, marker)
			}
		}
	}
}

func replayRequest(replicas uint32) paasv1.DeploymentExecutionRequest {
	createdAt := time.Date(2026, 8, 25, 11, 55, 0, 0, time.UTC)
	scope := paasv1.ResourceScope{
		Kind:     paasv1.AuthorityTenant,
		TenantID: "tenant-001",
	}
	metadata := paasv1.ResourceMetadata{
		ID: "revision-001", Name: "revision-001", Scope: scope,
		ResourceVersion: 1, CreatedAt: createdAt, UpdatedAt: createdAt,
	}
	spec := paasv1.DeploymentSpec{
		ApplicationRevisionID: "revision-001",
		PlacementPolicyID:     "policy-001",
		DesiredState:          paasv1.DeploymentDesiredRunning,
		Components: []paasv1.DeploymentComponent{{
			Name: "web", Replicas: replicas,
		}},
	}
	request := paasv1.DeploymentExecutionRequest{
		Command: paasv1.AdapterCommandEnvelope{
			OperationID:           "operation-001",
			CommandID:             "command-001",
			Attempt:               1,
			Action:                paasv1.AdapterApplyDeployment,
			Scope:                 scope,
			ApplicationID:         "application-001",
			ApplicationRevisionID: "revision-001",
			DeploymentID:          "deployment-001",
			ExecutionTargetID:     "target-local-001",
			BindingRef:            "binding-local-001",
			Deadline:              time.Date(2026, 8, 25, 12, 5, 0, 0, time.UTC),
		},
		Generation: paasv1.DeploymentGeneration{
			APIVersion: paasv1.APIVersion, Kind: "DeploymentGeneration", Scope: scope,
			DeploymentID: "deployment-001", Generation: 1, Spec: spec,
			CreatedByOperationID: "operation-001", CreatedAt: createdAt,
		},
		ApplicationRevision: paasv1.ApplicationRevision{
			APIVersion: paasv1.APIVersion, Kind: "ApplicationRevision", Metadata: metadata,
			Spec: paasv1.ApplicationRevisionSpec{
				ApplicationID: "application-001", Revision: "revision-001",
				ContentDigest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
				Components: []paasv1.ApplicationRevisionComponent{{
					Name: "web",
					Artifact: paasv1.ArtifactRef{
						Kind: paasv1.ArtifactOCIImage, Locator: "registry.example.invalid/web",
						Digest: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
					},
					Resources: paasv1.ResourceRequirements{CPUMillis: 100, MemoryBytes: 1024},
				}},
			},
		},
		Placement: paasv1.PlacementDecision{
			APIVersion: paasv1.APIVersion, Kind: "PlacementDecision",
			Metadata: paasv1.ResourceMetadata{
				ID: "decision-001", Name: "decision-001", Scope: scope,
				ResourceVersion: 1, CreatedAt: createdAt, UpdatedAt: createdAt,
			},
			DeploymentID: "deployment-001", DeploymentGeneration: 1,
			DeploymentResourceVersion: 1, ApplicationRevisionID: "revision-001",
			PlacementPolicyID: "policy-001", PolicyResourceVersion: 1,
			RequestedIsolationGuarantee: paasv1.IsolationWorkload,
			Outcome:                     paasv1.PlacementScheduled, ExecutionTargetID: "target-local-001",
			ExecutionTargetResourceVersion: 1, GrantedIsolationGuarantee: paasv1.IsolationWorkload,
			CandidateSetDigest: "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
			DecidedAt:          createdAt,
		},
	}
	request.Generation.ContentDigest = paasv1.DeploymentSpecContentDigest(request.Generation.Spec)
	request.Command.RequestDigest = paasv1.DeploymentExecutionRequestDigest(request)
	return request
}
