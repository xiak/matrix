package runtime

import (
	"strings"
	"testing"

	paasv1 "matrix/api/paas/v1"
)

func TestDeriveCommandIDIsStable(t *testing.T) {
	input := CommandIdentityInput{
		OperationID:     "operation-001",
		Action:          paasv1.AdapterApply,
		RuntimeTargetID: "target-local-001",
		WorkloadID:      "workload-001",
		ReleaseID:       "release-001",
	}

	first, err := DeriveCommandID(input)
	if err != nil {
		t.Fatalf("DeriveCommandID() error = %v", err)
	}
	second, err := DeriveCommandID(input)
	if err != nil {
		t.Fatalf("DeriveCommandID() second call error = %v", err)
	}
	if first != second {
		t.Fatalf("command IDs differ: %q and %q", first, second)
	}
	if !strings.HasPrefix(string(first), "cmd_") || len(first) != len("cmd_")+64 {
		t.Fatalf("command ID %q is not a prefixed SHA-256 identity", first)
	}
}

func TestDeriveCommandIDChangesForEffectIdentityInputs(t *testing.T) {
	base := CommandIdentityInput{
		OperationID:     "operation-001",
		Action:          paasv1.AdapterApply,
		RuntimeTargetID: "target-local-001",
		WorkloadID:      "workload-001",
		ReleaseID:       "release-001",
	}
	baseID, err := DeriveCommandID(base)
	if err != nil {
		t.Fatalf("DeriveCommandID(base) error = %v", err)
	}

	tests := map[string]CommandIdentityInput{
		"operation": {
			OperationID:     "operation-002",
			Action:          base.Action,
			RuntimeTargetID: base.RuntimeTargetID,
			WorkloadID:      base.WorkloadID,
			ReleaseID:       base.ReleaseID,
		},
		"action": {
			OperationID:     base.OperationID,
			Action:          paasv1.AdapterStop,
			RuntimeTargetID: base.RuntimeTargetID,
			WorkloadID:      base.WorkloadID,
			ReleaseID:       base.ReleaseID,
		},
		"target": {
			OperationID:     base.OperationID,
			Action:          base.Action,
			RuntimeTargetID: "target-local-002",
			WorkloadID:      base.WorkloadID,
			ReleaseID:       base.ReleaseID,
		},
		"workload": {
			OperationID:     base.OperationID,
			Action:          base.Action,
			RuntimeTargetID: base.RuntimeTargetID,
			WorkloadID:      "workload-002",
			ReleaseID:       base.ReleaseID,
		},
		"release": {
			OperationID:     base.OperationID,
			Action:          base.Action,
			RuntimeTargetID: base.RuntimeTargetID,
			WorkloadID:      base.WorkloadID,
			ReleaseID:       "release-002",
		},
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := DeriveCommandID(input)
			if err != nil {
				t.Fatalf("DeriveCommandID() error = %v", err)
			}
			if got == baseID {
				t.Fatalf("changing %s did not change command identity", name)
			}
		})
	}
}

func TestDeriveCommandIDRejectsInvalidInputs(t *testing.T) {
	if _, err := DeriveCommandID(CommandIdentityInput{}); err == nil {
		t.Fatal("empty identity must be rejected")
	}
	if _, err := DeriveCommandID(CommandIdentityInput{
		OperationID:     "operation-001",
		Action:          paasv1.AdapterApply,
		RuntimeTargetID: "target with spaces",
	}); err == nil {
		t.Fatal("invalid target identity must be rejected")
	}
}

func TestDigestPayloadIsStableAndContentSensitive(t *testing.T) {
	first := DigestPayload([]byte(`{"release":"001"}`))
	second := DigestPayload([]byte(`{"release":"001"}`))
	changed := DigestPayload([]byte(`{"release":"002"}`))
	if first != second {
		t.Fatalf("same payload produced different digests: %q and %q", first, second)
	}
	if first == changed {
		t.Fatal("different payloads produced the same digest")
	}
	if !strings.HasPrefix(first, "sha256:") || len(first) != len("sha256:")+64 {
		t.Fatalf("digest %q is not a SHA-256 contract digest", first)
	}
}
