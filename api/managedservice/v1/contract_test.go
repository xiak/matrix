package managedservicev1

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
)

func TestMutationSchemasAreClosedAndExcludeNativeAuthorityFields(t *testing.T) {
	encoded, err := os.ReadFile("openapi.json")
	if err != nil {
		t.Fatal("read managed-service OpenAPI")
	}
	var document map[string]any
	if json.Unmarshal(encoded, &document) != nil {
		t.Fatal("decode managed-service OpenAPI")
	}
	components := document["components"].(map[string]any)
	schemas := components["schemas"].(map[string]any)
	for _, name := range []string{"ActivateServiceRequest", "ActivateQuotaRequest", "CreateInstallationRequest", "BindServiceRoleRequest"} {
		schema := schemas[name].(map[string]any)
		if schema["additionalProperties"] != false {
			t.Fatalf("%s accepts unknown fields", name)
		}
		properties := schema["properties"].(map[string]any)
		for _, forbidden := range []string{
			"organizationId", "tenantId", "price", "currency", "payment",
			"image", "digest", "command", "compose", "hostPath", "credential",
			"accountId", "roleId", "installationId", "principalId", "purpose",
		} {
			if _, found := properties[forbidden]; found {
				t.Fatalf("%s exposes forbidden field %q", name, forbidden)
			}
		}
	}
}

func TestCommandResultContractIsClosedAndStateBound(t *testing.T) {
	now := time.Date(2026, 10, 13, 12, 0, 0, 123_000, time.UTC)
	completed := now.Add(time.Second)
	binding := iamv1.WorkloadRoleBindingID("binding-one")
	operation := InstallationOperation{
		ID: "operation-one", Kind: InstallationOperationProvision,
		Phase: InstallationProvisioning, ObservedAt: now,
	}
	base := CommandResult{
		Kind: "ManagedServiceCommandResult", RequestID: "request-one",
		CommandType: CommandInstallationCreate,
		InputDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		State:       CommandInProgress,
		Target: CommandTargetReference{
			Kind: CommandTargetServiceInstallation, ID: "installation-one",
		},
		Operation: &operation,
	}
	if err := ValidateCommandResult(base); err != nil {
		t.Fatalf("valid in-progress command result: %v", err)
	}
	quota := base
	quota.CommandType, quota.State = CommandQuotaActivate, CommandSucceeded
	quota.Target = CommandTargetReference{Kind: CommandTargetQuotaEntitlement, ID: "quota-one"}
	quota.Operation, quota.CompletedAt = nil, &completed
	if err := ValidateCommandResult(quota); err != nil {
		t.Fatalf("valid quota result: %v", err)
	}
	role := base
	role.CommandType, role.State = CommandServiceRoleBind, CommandSucceeded
	role.Operation, role.BindingID, role.CompletedAt = nil, &binding, &completed
	if err := ValidateCommandResult(role); err != nil {
		t.Fatalf("valid role result: %v", err)
	}
	invalid := []CommandResult{
		func() CommandResult { value := base; value.State = CommandSucceeded; return value }(),
		func() CommandResult { value := quota; value.Operation = &operation; return value }(),
		func() CommandResult { value := role; value.BindingID = nil; return value }(),
		func() CommandResult { value := base; value.CommandType = "ARBITRARY"; return value }(),
	}
	for index, value := range invalid {
		if ValidateCommandResult(value) == nil {
			t.Fatalf("invalid command result %d accepted", index)
		}
	}
	if err := ValidateCommandResultList(CommandResultList{
		Kind: "ManagedServiceCommandResultList", Items: []CommandResult{base, quota, role},
	}); err != nil {
		t.Fatalf("valid command result list: %v", err)
	}
}
