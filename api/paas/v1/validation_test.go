package paasv1

import (
	"strings"
	"testing"
	"time"
)

func TestValidateOperationEnforcesTerminalContract(t *testing.T) {
	var operation Operation
	decodeStrictJSON(t, "examples/operation.json", &operation)

	operation.State = OperationSucceeded
	if err := ValidateOperation(operation); err == nil ||
		!strings.Contains(err.Error(), "terminalAt") {
		t.Fatalf("terminal operation without terminalAt must fail, got %v", err)
	}

	terminalAt := operation.UpdatedAt
	operation.TerminalAt = &terminalAt
	if err := ValidateOperation(operation); err != nil {
		t.Fatalf("successful terminal operation must validate: %v", err)
	}

	operation.State = OperationFailed
	if err := ValidateOperation(operation); err == nil ||
		!strings.Contains(err.Error(), "normalized error") {
		t.Fatalf("failed operation without error must fail, got %v", err)
	}

	operation.Error = &Problem{
		Type:      "/problems/operation-failed",
		Title:     "Operation failed",
		Status:    500,
		Code:      ErrorOperationFailed,
		Detail:    "The runtime adapter rejected the release.",
		TraceID:   "trace-operation-001",
		Retryable: false,
	}
	if err := ValidateOperation(operation); err != nil {
		t.Fatalf("failed terminal operation with normalized error must validate: %v", err)
	}

	operation.State = OperationExecuting
	if err := ValidateOperation(operation); err == nil {
		t.Fatal("non-terminal operation cannot retain terminal fields")
	}
}

func TestValidateOperationDistinguishesPlatformAndTenantScope(t *testing.T) {
	var operation Operation
	decodeStrictJSON(t, "examples/operation.json", &operation)
	operation.Action = OperationRegisterTarget
	operation.Scope = ResourceScope{Kind: AuthorityPlatform}
	operation.Target = ResourceRef{Kind: "RuntimeTarget", ID: "target-local-001"}
	if err := ValidateOperation(operation); err != nil {
		t.Fatalf("platform target registration must validate: %v", err)
	}

	operation.Scope = ResourceScope{Kind: AuthorityTenant, TenantID: "tenant-a"}
	if err := ValidateOperation(operation); err == nil ||
		!strings.Contains(err.Error(), "platform scope") {
		t.Fatalf("tenant-scoped target registration must fail, got %v", err)
	}

	operation.Action = OperationDeploy
	operation.Scope = ResourceScope{Kind: AuthorityPlatform}
	if err := ValidateOperation(operation); err == nil ||
		!strings.Contains(err.Error(), "tenant scope") {
		t.Fatalf("platform-scoped deploy must fail, got %v", err)
	}
}

func TestValidateInfrastructureRequestsRequirePlatformScope(t *testing.T) {
	var request InspectTargetRequest
	decodeStrictJSON(t, "examples/inspect-target-request.json", &request)
	if err := ValidateInspectTargetRequest(request); err != nil {
		t.Fatalf("platform inspection request must validate: %v", err)
	}
	request.Command.Scope = ResourceScope{
		Kind:     AuthorityTenant,
		TenantID: "tenant-a",
	}
	if err := ValidateInspectTargetRequest(request); err == nil ||
		!strings.Contains(err.Error(), "platform scope") {
		t.Fatalf("tenant-scoped target inspection must fail, got %v", err)
	}
}

func TestValidateRuntimeTargetFailsClosedOnCapacityAndCapabilities(t *testing.T) {
	var target RuntimeTarget
	decodeStrictJSON(t, "examples/runtime-target.json", &target)
	target.Status.Allocatable.CPUMillis = target.Status.Capacity.CPUMillis + 1
	target.Status.SupportedIsolationClasses = append(
		target.Status.SupportedIsolationClasses,
		IsolationSharedCompose,
	)

	err := ValidateRuntimeTarget(target)
	if err == nil {
		t.Fatal("overcommitted target with duplicate capabilities must fail")
	}
	if !strings.Contains(err.Error(), "cannot exceed capacity") ||
		!strings.Contains(err.Error(), "duplicated") {
		t.Fatalf("unexpected target validation error: %v", err)
	}
}

func TestValidatePlacementPolicyRejectsDuplicateResourcePools(t *testing.T) {
	var policy PlacementPolicy
	decodeStrictJSON(t, "examples/placement-policy.json", &policy)
	policy.Spec.EligibleResourcePools = append(
		policy.Spec.EligibleResourcePools,
		policy.Spec.EligibleResourcePools[0],
	)
	if err := ValidatePlacementPolicy(policy); err == nil ||
		!strings.Contains(err.Error(), "duplicated") {
		t.Fatalf("duplicate resource pools must fail, got %v", err)
	}
}

func TestValidatePlacementDecisionBindsSelectedTargetVersion(t *testing.T) {
	var decision PlacementDecision
	decodeStrictJSON(t, "examples/placement-unschedulable.json", &decision)
	decision.Outcome = PlacementScheduled
	decision.RequestedIsolation = IsolationSharedCompose
	decision.RuntimeTargetID = "target-local-001"
	decision.RuntimeTargetResourceVersion = 7
	decision.GrantedIsolation = IsolationSharedCompose
	decision.Reason = nil
	if err := ValidatePlacementDecision(decision); err != nil {
		t.Fatalf("version-bound scheduled decision must validate: %v", err)
	}

	decision.RuntimeTargetResourceVersion = 0
	if err := ValidatePlacementDecision(decision); err == nil ||
		!strings.Contains(err.Error(), "runtimeTargetResourceVersion") {
		t.Fatalf("scheduled decision without target version must fail, got %v", err)
	}

	decision.Outcome = PlacementUnschedulable
	decision.RuntimeTargetID = ""
	decision.RuntimeTargetResourceVersion = 7
	decision.GrantedIsolation = ""
	decision.Reason = &Problem{
		Type:      "/problems/unschedulable",
		Title:     "Workload cannot be scheduled",
		Status:    422,
		Code:      ErrorUnschedulable,
		Detail:    "No eligible runtime target currently satisfies the placement policy.",
		TraceID:   "trace-0001",
		Retryable: true,
	}
	if err := ValidatePlacementDecision(decision); err == nil ||
		!strings.Contains(err.Error(), "cannot select or version") {
		t.Fatalf("unschedulable decision with target version must fail, got %v", err)
	}
}

func TestValidateAdapterCommandRejectsUnknownAction(t *testing.T) {
	command := validAdapterCommand()
	command.Action = AdapterAction("FUTURE_ACTION")
	if err := ValidateAdapterCommand(command); err == nil ||
		!strings.Contains(err.Error(), "unknown adapter action") {
		t.Fatalf("unknown action must fail closed, got %v", err)
	}
}

func TestSafeExternalTextRejectsControlAndRawSensitiveMaterial(t *testing.T) {
	for name, value := range map[string]string{
		"control":     "line1\nline2",
		"whitespace":  " untrimmed",
		"bearer":      "Authorization: Bearer abc",
		"password":    "password=not-allowed",
		"private key": "-----BEGIN PRIVATE KEY-----",
	} {
		t.Run(name, func(t *testing.T) {
			if err := ValidateSafeExternalText("value", value, 256, true); err == nil {
				t.Fatal("unsafe external text must be rejected")
			}
		})
	}
	if err := ValidateSafeExternalText("value", "safe normalized text", 256, true); err != nil {
		t.Fatalf("safe text rejected: %v", err)
	}
}

func TestEvidenceRejectsSensitiveAttributeValues(t *testing.T) {
	var evidence Evidence
	decodeStrictJSON(t, "examples/evidence.json", &evidence)
	evidence.Attributes["result"] = "access_token=must-not-leak"
	if err := ValidateEvidence(evidence); err == nil ||
		!strings.Contains(err.Error(), "sensitive") {
		t.Fatalf("sensitive evidence value must be rejected, got %v", err)
	}
}

func TestValidateAdapterCapabilitiesRejectsUnknownAndDuplicateValues(t *testing.T) {
	capabilities := AdapterCapabilitiesContract{
		Adapter: AdapterRef{
			Kind:            AdapterRuntime,
			Name:            "compose",
			ContractVersion: "v1",
		},
		Actions: []AdapterAction{
			AdapterApply,
			AdapterApply,
			AdapterAction("FUTURE_ACTION"),
		},
		IsolationClasses: []IsolationClass{
			IsolationSharedCompose,
			IsolationClass("FUTURE_ISOLATION"),
		},
		ObservedAt: time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC),
	}
	err := ValidateAdapterCapabilities(capabilities)
	if err == nil {
		t.Fatal("invalid capability contract must fail")
	}
	if !strings.Contains(err.Error(), "duplicated") ||
		!strings.Contains(err.Error(), "unknown") {
		t.Fatalf("unexpected capability validation error: %v", err)
	}
}

func TestValidateAdapterResultRequiresNormalizedUnknownOutcome(t *testing.T) {
	result := AdapterResult{
		CommandID: "command-001",
		State:     AdapterResultUnknown,
		Error: &NormalizedAdapterError{
			Class:     AdapterErrorUnknownOutcome,
			Code:      ErrorAdapterOutcomeUnknown,
			Message:   "The adapter outcome could not be proven.",
			Retryable: false,
		},
		ObservedAt: time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC),
	}
	if err := ValidateAdapterResult(result); err != nil {
		t.Fatalf("normalized unknown outcome must validate: %v", err)
	}

	result.Error.Class = AdapterErrorTransient
	if err := ValidateAdapterResult(result); err == nil ||
		!strings.Contains(err.Error(), "unknown") {
		t.Fatalf("unknown result with transient error must fail, got %v", err)
	}
}

func TestContractTimeRejectsOffsetNanosecondsAndMonotonicValues(t *testing.T) {
	tests := map[string]time.Time{
		"offset": time.Date(
			2026,
			8,
			25,
			12,
			0,
			0,
			0,
			time.FixedZone("UTC+8", 8*60*60),
		),
		"nanoseconds": time.Date(2026, 8, 25, 12, 0, 0, 1, time.UTC),
		"monotonic":   time.Now(),
	}
	for name, value := range tests {
		t.Run(name, func(t *testing.T) {
			if err := validateContractTime("observedAt", value); err == nil {
				t.Fatalf("%s time must be rejected", name)
			}
		})
	}
}

func validAdapterCommand() AdapterCommandEnvelope {
	return AdapterCommandEnvelope{
		OperationID: "operation-001",
		CommandID:   "command-001",
		Attempt:     1,
		Action:      AdapterApply,
		Scope: ResourceScope{
			Kind:     AuthorityTenant,
			TenantID: "tenant-001",
		},
		WorkloadID:      "workload-001",
		ReleaseID:       "release-001",
		RuntimeTargetID: "target-local-001",
		RequestDigest:   "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		BindingRef:      "binding-local-001",
		Deadline:        time.Date(2026, 8, 25, 12, 5, 0, 0, time.UTC),
	}
}
