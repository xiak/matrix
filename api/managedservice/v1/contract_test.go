package managedservicev1

import (
	"encoding/json"
	"os"
	"strings"
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

func TestKibanaRequiresAnExactElasticsearchReference(t *testing.T) {
	base := CreateInstallationRequest{ID: "kibana-one", Name: "Kibana", OfferingID: KibanaOfferingID,
		QuotaEntitlementID: "quota-one", RegionID: "local-primary",
		Elasticsearch: &ElasticsearchReference{InstallationID: "search-one", ResourceVersion: 3}}
	if err := ValidateCreateInstallationRequest(base); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*CreateInstallationRequest){
		"missing":             func(v *CreateInstallationRequest) { v.Elasticsearch = nil },
		"self":                func(v *CreateInstallationRequest) { v.Elasticsearch.InstallationID = v.ID },
		"foreign offering":    func(v *CreateInstallationRequest) { v.OfferingID = LogstashOfferingID },
		"missing version":     func(v *CreateInstallationRequest) { v.Elasticsearch.ResourceVersion = 0 },
		"unsafe version":      func(v *CreateInstallationRequest) { v.Elasticsearch.ResourceVersion = 9007199254740992 },
		"not an installation": func(v *CreateInstallationRequest) { v.Elasticsearch.InstallationID = "URL:9200" },
	} {
		t.Run(name, func(t *testing.T) {
			value, reference := base, *base.Elasticsearch
			value.Elasticsearch = &reference
			change(&value)
			if ValidateCreateInstallationRequest(value) == nil {
				t.Fatal("invalid dependency selection admitted")
			}
		})
	}
	base.OfferingID, base.Elasticsearch = LogstashOfferingID, nil
	encoded, err := json.Marshal(base)
	if err != nil || ValidateCreateInstallationRequest(base) != nil || strings.Contains(string(encoded), "elasticsearch") {
		t.Fatal("existing independent product request acquired a dependency field")
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
		Kind: "ManagedServiceCommandResult", IdempotencyKey: "command-one",
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
	encoded, err := json.Marshal(base)
	if err != nil || !strings.Contains(string(encoded), `"idempotencyKey":"command-one"`) ||
		strings.Contains(string(encoded), `"requestId"`) {
		t.Fatalf("command result did not expose only its public idempotency identity: %s", encoded)
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
	failureCode := "PROVIDER_UNAVAILABLE"
	failed := base
	failed.State, failed.CompletedAt = CommandFailed, &completed
	failed.Operation = &InstallationOperation{
		ID: operation.ID, Kind: operation.Kind, Phase: InstallationFailed,
		SafeFailureCode: &failureCode, ObservedAt: completed,
	}
	if err := ValidateCommandResult(failed); err != nil {
		t.Fatalf("valid failed command result: %v", err)
	}
	missingFailureCode := failed
	missingFailureCode.Operation = &InstallationOperation{
		ID: operation.ID, Kind: operation.Kind, Phase: InstallationFailed, ObservedAt: completed,
	}
	nonFailedWithCode := base
	nonFailedWithCode.Operation = &InstallationOperation{
		ID: operation.ID, Kind: operation.Kind, Phase: operation.Phase,
		SafeFailureCode: &failureCode, ObservedAt: operation.ObservedAt,
	}
	invalidFailureCode := failed
	unsafeCode := "provider: password=secret"
	invalidFailureCode.Operation = &InstallationOperation{
		ID: operation.ID, Kind: operation.Kind, Phase: InstallationFailed,
		SafeFailureCode: &unsafeCode, ObservedAt: completed,
	}
	invalid := []CommandResult{
		func() CommandResult { value := base; value.State = CommandSucceeded; return value }(),
		func() CommandResult { value := quota; value.Operation = &operation; return value }(),
		func() CommandResult { value := role; value.BindingID = nil; return value }(),
		func() CommandResult { value := base; value.CommandType = "ARBITRARY"; return value }(),
		missingFailureCode,
		nonFailedWithCode,
		invalidFailureCode,
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
