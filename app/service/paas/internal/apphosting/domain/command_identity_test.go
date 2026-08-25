package domain

import (
	"strings"
	"testing"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

func TestDeriveCommandIDIsStable(t *testing.T) {
	input := CommandIdentityInput{
		OperationID:           "operation-001",
		Action:                paasv1.AdapterApplyDeployment,
		ExecutionTargetID:     "target-local-001",
		DeploymentID:          "deployment-001",
		ApplicationRevisionID: "revision-001",
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
		OperationID:           "operation-001",
		Action:                paasv1.AdapterApplyDeployment,
		ExecutionTargetID:     "target-local-001",
		DeploymentID:          "deployment-001",
		ApplicationRevisionID: "revision-001",
	}
	baseID, err := DeriveCommandID(base)
	if err != nil {
		t.Fatalf("DeriveCommandID(base) error = %v", err)
	}

	tests := map[string]func(*CommandIdentityInput){
		"operation": func(input *CommandIdentityInput) {
			input.OperationID = "operation-002"
		},
		"action": func(input *CommandIdentityInput) {
			input.Action = paasv1.AdapterStopDeployment
		},
		"execution target": func(input *CommandIdentityInput) {
			input.ExecutionTargetID = "target-local-002"
		},
		"deployment": func(input *CommandIdentityInput) {
			input.DeploymentID = "deployment-002"
		},
		"application revision": func(input *CommandIdentityInput) {
			input.ApplicationRevisionID = "revision-002"
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			input := base
			mutate(&input)
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
		OperationID:       "operation-001",
		Action:            paasv1.AdapterApplyDeployment,
		ExecutionTargetID: "target with spaces",
	}); err == nil {
		t.Fatal("invalid target identity must be rejected")
	}
}

func TestDigestPayloadIsStableAndContentSensitive(t *testing.T) {
	first := DigestPayload([]byte(`{"deployment":"001"}`))
	second := DigestPayload([]byte(`{"deployment":"001"}`))
	changed := DigestPayload([]byte(`{"deployment":"002"}`))
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
