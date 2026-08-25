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
	DeploymentRequest,
) (paasv1.AdapterResult, error) {
	return paasv1.AdapterResult{}, nil
}

func (adapter *replayDeploymentExecutor) ApplyDeployment(
	_ context.Context,
	request DeploymentRequest,
) (paasv1.AdapterResult, error) {
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
	ObserveDeploymentRequest,
) (DeploymentObservation, error) {
	return DeploymentObservation{}, nil
}

func (*replayDeploymentExecutor) StopDeployment(
	context.Context,
	DeploymentRequest,
) (paasv1.AdapterResult, error) {
	return paasv1.AdapterResult{}, nil
}

func (*replayDeploymentExecutor) RollbackDeployment(
	context.Context,
	DeploymentRequest,
) (paasv1.AdapterResult, error) {
	return paasv1.AdapterResult{}, nil
}

func TestDeploymentExecutorReplaysOneEffectForSameCommand(t *testing.T) {
	adapter := newReplayDeploymentExecutor()
	request := replayRequest("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

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
	first := replayRequest("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if _, err := adapter.ApplyDeployment(context.Background(), first); err != nil {
		t.Fatalf("first ApplyDeployment() error = %v", err)
	}

	conflict := replayRequest("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
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

func replayRequest(digest string) DeploymentRequest {
	return DeploymentRequest{
		Command: paasv1.AdapterCommandEnvelope{
			OperationID: "operation-001",
			CommandID:   "command-001",
			Attempt:     1,
			Action:      paasv1.AdapterApplyDeployment,
			Scope: paasv1.ResourceScope{
				Kind:     paasv1.AuthorityTenant,
				TenantID: "tenant-001",
			},
			ApplicationID:         "application-001",
			ApplicationRevisionID: "revision-001",
			DeploymentID:          "deployment-001",
			ExecutionTargetID:     "target-local-001",
			RequestDigest:         digest,
			BindingRef:            "binding-local-001",
			Deadline:              time.Date(2026, 8, 25, 12, 5, 0, 0, time.UTC),
		},
	}
}
