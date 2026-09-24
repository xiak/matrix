package auditv1

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestEveryAuditOpenAPISchemaCompilesAsJSONSchema202012(t *testing.T) {
	document := loadAuditOpenAPI(t)
	for name := range auditOpenAPISchemas(t, document) {
		t.Run(name, func(t *testing.T) {
			_ = compileAuditOpenAPISchema(t, document, name)
		})
	}
}

func TestRoleActorLineageIsStrictAndFactBound(t *testing.T) {
	schema := compileAuditOpenAPISchema(t, loadAuditOpenAPI(t), "ActorReference")
	valid := `{"type":"ROLE","id":"role-one","roleSession":{"sessionId":"role-session-one","sourceUserId":"source-user"}}`
	for _, test := range []struct {
		body string
		want bool
	}{
		{valid, true},
		{`{"type":"USER","id":"source-user"}`, true},
		{`{"type":"USER","id":"source-user","roleSession":null}`, false},
		{`{"type":"ROLE","id":"role-one"}`, false},
		{`{"type":"ROLE","id":"role-one","roleSession":null}`, false},
		{strings.Replace(valid, `"sourceUserId":"source-user"`, `"sourceUserId":""`, 1), false},
		{strings.Replace(valid, `"sourceUserId":"source-user"`, `"sourceSessionId":"source-session"`, 1), false},
		{strings.Replace(valid, `"sessionId":"role-session-one"`, `"sessionId":"role-session-one","generation":1`, 1), false},
		{strings.Replace(valid, `"ROLE"`, `"SERVICE_ACCOUNT"`, 1), false},
	} {
		var actor ActorReference
		err := json.Unmarshal([]byte(test.body), &actor)
		instance, decodeErr := jsonschema.UnmarshalJSON(strings.NewReader(test.body))
		if (err == nil) != test.want || decodeErr != nil || (schema.Validate(instance) == nil) != test.want {
			t.Fatalf("actor decoder/schema differ for %s: %v", test.body, err)
		}
	}
	var actor, copy ActorReference
	if json.Unmarshal([]byte(valid), &actor) != nil || json.Unmarshal([]byte(valid), &copy) != nil || !actor.Equal(copy) {
		t.Fatal("independent decodes lost actor equality")
	}
	copy.RoleSession.SessionID = "another-session"
	if actor.Equal(copy) {
		t.Fatal("another session became the same actor")
	}
	permitted := map[Action]bool{ActionIAMAuthorizationDecided: true, ActionIAMRoleSessionExited: true, ActionPaaSApplicationCreated: true, ActionPaaSConfigurationCreated: true,
		ActionPaaSConfigurationRevisionCreated: true, ActionPaaSApplicationRevisionCreated: true, ActionPaaSDeploymentCreated: true,
		ActionPaaSDeploymentUpdated: true, ActionPaaSDeploymentStopped: true, ActionPaaSDeploymentRolledBack: true, ActionAuditRecordsRead: true, ActionAuditIntegrityVerified: true}
	eventSchema := compileAuditOpenAPISchema(t, loadAuditOpenAPI(t), "Event")
	for _, action := range AllActions() {
		contract, _ := ContractForAction(action)
		event := Event{APIVersion: APIVersion, Kind: "AuditEvent", EventID: "event-role", TenantID: "account-one", Actor: actor, Action: action,
			Target: TargetReference{Kind: contract.Target, ID: "target-one"}, Result: contract.Results[0], RequestID: "request-one", CorrelationID: "correlation-one",
			RequestDigest: "sha256:" + strings.Repeat("1", 64), OccurredAt: time.Date(2026, 9, 16, 0, 0, 0, 0, time.UTC)}
		if contract.PlatformOnly {
			event.TenantID = ""
			event.InstallationID = "installation-one"
		}
		if contract.IAMDecisionRequired {
			event.IAMDecisionID = "decision-one"
		}
		if action == ActionIAMAuthorizationDecided {
			event.Target.ID = string(event.IAMDecisionID)
		}
		if action == ActionIAMRoleSessionExited {
			event.Target.ID = actor.RoleSession.SessionID
		}
		if contract.OperationRequired {
			event.OperationID = "operation-one"
		}
		if action == ActionIAMAccountRootCredentialsRecovered || action == ActionIAMTenantAdministratorRecovered || action == ActionIAMInstallationPrimaryCredentialsRecovered {
			event.Target.TenantID = "account-one"
		}
		encoded, _ := json.Marshal(event)
		instance, _ := jsonschema.UnmarshalJSON(bytes.NewReader(encoded))
		if contract.RoleActorPermitted != permitted[action] || (ValidateEventForSource(contract.Source, event) == nil) != permitted[action] || (eventSchema.Validate(instance) == nil) != permitted[action] {
			t.Fatal("ROLE escaped its closed fact catalog", action)
		}
		if permitted[action] {
			_, digest, err := CanonicalizeEvent(contract.Source, event)
			event.Actor = copy
			if action == ActionIAMRoleSessionExited {
				if ValidateEvent(event) == nil {
					t.Fatal("role self-exit accepted another session target")
				}
				event.Target.ID = copy.RoleSession.SessionID
			}
			_, changed, changedErr := CanonicalizeEvent(contract.Source, event)
			if err != nil || changedErr != nil || changed == digest {
				t.Fatal("role session lineage was excluded from canonical digest")
			}
		}
	}
}

func TestAccessKeyActorIsStrictAndOnlyAdmittedByClosedFacts(t *testing.T) {
	document := loadAuditOpenAPI(t)
	schema := compileAuditOpenAPISchema(t, document, "ActorReference")
	valid := `{"type":"USER","id":"user-one","accessKeyId":"key-one"}`
	for _, test := range []struct {
		wire string
		want bool
	}{
		{valid, true},
		{`{"type":"USER","id":"user-one"}`, true},
		{strings.Replace(valid, `"key-one"`, `null`, 1), false},
		{strings.Replace(valid, `"key-one"`, `""`, 1), false},
		{strings.Replace(valid, `"USER"`, `"SERVICE_ACCOUNT"`, 1), false},
		{strings.Replace(valid, `"USER"`, `"SYSTEM"`, 1), false},
		{`{"type":"ROLE","id":"role-one","roleSession":{"sessionId":"role-session","sourceUserId":"user-one"},"accessKeyId":"key-one"}`, false},
		{`{"type":"USER","id":"user-one","accessKeyId":"key-one","roleSession":null}`, false},
		{strings.Replace(valid, `"accessKeyId":`, `"AccessKeyId":`, 1), false},
	} {
		var actor ActorReference
		err := json.Unmarshal([]byte(test.wire), &actor)
		instance, decodeErr := jsonschema.UnmarshalJSON(strings.NewReader(test.wire))
		if (err == nil) != test.want || decodeErr != nil || (schema.Validate(instance) == nil) != test.want {
			t.Fatalf("key actor decoder/schema accepted=%v/%v want=%v", err == nil, schema.Validate(instance) == nil, test.want)
		}
		if test.want {
			encoded, err := json.Marshal(actor)
			if err != nil || string(encoded) != test.wire {
				t.Fatal("key attribution changed public wire")
			}
		}
	}
	actor := ActorReference{Type: ActorUser, ID: "user-one", AccessKeyID: "key-one"}
	other := actor
	if !actor.Equal(other) {
		t.Fatal("same key attribution is unequal")
	}
	for _, key := range []string{"", "key-two"} {
		other.AccessKeyID = key
		if actor.Equal(other) {
			t.Fatal("key attribution was omitted from actor identity")
		}
	}
	permitted := map[Action]bool{ActionIAMAuthorizationDecided: true, ActionPaaSApplicationCreated: true, ActionPaaSConfigurationCreated: true,
		ActionPaaSConfigurationRevisionCreated: true, ActionPaaSApplicationRevisionCreated: true, ActionPaaSDeploymentCreated: true,
		ActionPaaSDeploymentUpdated: true, ActionPaaSDeploymentStopped: true, ActionPaaSDeploymentRolledBack: true, ActionAuditRecordsRead: true, ActionAuditIntegrityVerified: true}
	eventSchema := compileAuditOpenAPISchema(t, document, "Event")
	for _, action := range AllActions() {
		contract, _ := ContractForAction(action)
		for _, result := range contract.Results {
			event := Event{APIVersion: APIVersion, Kind: "AuditEvent", EventID: "event-key", TenantID: "account-one", Actor: actor, Action: action,
				Target: TargetReference{Kind: contract.Target, ID: "target-one"}, Result: result, RequestID: "request-one", CorrelationID: "correlation-one",
				RequestDigest: "sha256:" + strings.Repeat("1", 64), OccurredAt: time.Date(2026, 9, 17, 0, 0, 0, 0, time.UTC)}
			if contract.PlatformOnly {
				event.TenantID, event.InstallationID = "", "installation-one"
			}
			if contract.IAMDecisionRequired {
				event.IAMDecisionID = "decision-one"
			}
			if action == ActionIAMAuthorizationDecided {
				event.Target.ID = string(event.IAMDecisionID)
			}
			if contract.OperationRequired {
				event.OperationID = "operation-one"
			}
			if action == ActionIAMAccountRootCredentialsRecovered || action == ActionIAMTenantAdministratorRecovered || action == ActionIAMInstallationPrimaryCredentialsRecovered {
				event.Target.TenantID = "account-one"
			}
			encoded, _ := json.Marshal(event)
			instance, _ := jsonschema.UnmarshalJSON(bytes.NewReader(encoded))
			if contract.AccessKeyActorPermitted != permitted[action] || (ValidateEventForSource(contract.Source, event) == nil) != permitted[action] || (eventSchema.Validate(instance) == nil) != permitted[action] {
				t.Fatal("key actor escaped its closed fact contract", action)
			}
			if permitted[action] {
				_, digest, err := CanonicalizeEvent(contract.Source, event)
				event.Actor.AccessKeyID = "key-two"
				_, altered, alteredErr := CanonicalizeEvent(contract.Source, event)
				if err != nil || alteredErr != nil || altered == digest {
					t.Fatal("key attribution is not committed by the unique canonical owner")
				}
			}
		}
	}
}

func TestAuditSchemaAcceptsGoUTCSecondEncoding(t *testing.T) {
	value := Readiness{
		APIVersion: APIVersion, Kind: "Readiness", State: ReadinessReady,
		SchemaVersion: 1, CheckedAt: time.Date(2026, 8, 25, 1, 2, 3, 0, time.UTC),
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("encode readiness: %v", err)
	}
	instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(encoded))
	if err != nil {
		t.Fatalf("decode readiness: %v", err)
	}
	if err := compileAuditOpenAPISchema(t, loadAuditOpenAPI(t), "Readiness").Validate(instance); err != nil {
		t.Fatalf("Go-encoded UTC second does not satisfy Audit schema: %v", err)
	}
}

func TestAuditExamplesValidateAgainstOpenAPISchemas(t *testing.T) {
	document := loadAuditOpenAPI(t)
	examples := map[string]string{
		"examples/event-paas.json":            "Event",
		"examples/event-iam-denied.json":      "Event",
		"examples/ingestion-result.json":      "IngestionResult",
		"examples/query-records-request.json": "QueryRecordsRequest",
		"examples/record-page.json":           "RecordPage",
		"examples/verify-chain-request.json":  "VerifyChainRequest",
		"examples/chain-verification.json":    "ChainVerification",
		"examples/readiness.json":             "Readiness",
		"examples/problem.json":               "Problem",
	}
	for path, schemaName := range examples {
		t.Run(path, func(t *testing.T) {
			source, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(source))
			if err != nil {
				t.Fatalf("decode %s: %v", path, err)
			}
			if err := compileAuditOpenAPISchema(t, document, schemaName).Validate(instance); err != nil {
				t.Fatalf("%s does not satisfy %s: %v", path, schemaName, err)
			}
		})
	}
}

func TestAuditOpenAPIEnforcesClosedEventUnion(t *testing.T) {
	document := loadAuditOpenAPI(t)
	eventSchema := compileAuditOpenAPISchema(t, document, "Event")
	event := loadAuditSchemaExample(t, "examples/event-paas.json")
	delete(event, "iamDecisionId")
	if err := eventSchema.Validate(event); err == nil {
		t.Fatal("PaaS event without IAM decision must fail schema validation")
	}
	event = loadAuditSchemaExample(t, "examples/event-paas.json")
	event["target"].(map[string]any)["kind"] = string(TargetPrincipal)
	if err := eventSchema.Validate(event); err == nil {
		t.Fatal("Audit action with the wrong target kind must fail schema validation")
	}
	event = loadAuditSchemaExample(t, "examples/event-iam-denied.json")
	event["operationId"] = "operation-forged"
	if err := eventSchema.Validate(event); err == nil {
		t.Fatal("IAM decision event with a PaaS Operation must fail schema validation")
	}

	recordSchema := compileAuditOpenAPISchema(t, document, "AuditRecord")
	result := loadAuditSchemaExample(t, "examples/ingestion-result.json")
	record := result["record"].(map[string]any)
	record["source"] = string(SourceIAM)
	if err := recordSchema.Validate(record); err == nil {
		t.Fatal("record source that differs from its action authority must fail schema validation")
	}

	verificationSchema := compileAuditOpenAPISchema(t, document, "ChainVerification")
	verification := loadAuditSchemaExample(t, "examples/chain-verification.json")
	verification["nextSequence"] = float64(43)
	if err := verificationSchema.Validate(verification); err == nil {
		t.Fatal("complete verification with nextSequence must fail schema validation")
	}
}

func TestAuditSchemaRequiresTheActionAuthorityAndPlatformUser(t *testing.T) {
	schema := compileAuditOpenAPISchema(t, loadAuditOpenAPI(t), "Event")
	event := loadAuditSchemaExample(t, "examples/event-paas.json")
	delete(event, "tenantId")
	event["installationId"] = "installation-example"
	event["action"], event["result"] = string(ActionPaaSExecutionPoolCreated), string(ResultSucceeded)
	event["target"].(map[string]any)["kind"] = string(TargetExecutionPool)
	event["actor"].(map[string]any)["type"] = string(ActorUser)
	if err := schema.Validate(event); err != nil {
		t.Fatalf("platform event rejected: %v", err)
	}
	event["tenantId"] = "installation-example"
	if schema.Validate(event) == nil {
		t.Fatal("both authority IDs accepted")
	}
	delete(event, "tenantId")
	event["actor"].(map[string]any)["type"] = string(ActorSystem)
	if schema.Validate(event) == nil {
		t.Fatal("platform event accepted a non-user actor")
	}
	event["actor"].(map[string]any)["type"] = string(ActorUser)
	delete(event, "installationId")
	if schema.Validate(event) == nil {
		t.Fatal("no authority accepted")
	}
	event["tenantId"] = "installation-example"
	if schema.Validate(event) == nil {
		t.Fatal("platform action accepted tenant authority")
	}
}

func TestAuditTargetTenantIsRequiredOnlyForPrimaryRecovery(t *testing.T) {
	schema := compileAuditOpenAPISchema(t, loadAuditOpenAPI(t), "Event")
	event := loadAuditSchemaExample(t, "examples/event-paas.json")
	delete(event, "tenantId")
	delete(event, "operationId")
	event["installationId"] = "installation-example"
	event["action"], event["result"] = string(ActionIAMTenantAdministratorRecovered), string(ResultSucceeded)
	target := event["target"].(map[string]any)
	target["kind"], target["id"], target["tenantId"] = string(TargetPrincipal), "primary-original", "tenant-original"
	if err := schema.Validate(event); err != nil {
		t.Fatal(err)
	}
	delete(target, "tenantId")
	if schema.Validate(event) == nil {
		t.Fatal("recovery omitted its primary's tenant")
	}
	target["tenantId"] = "tenant-original"
	for _, action := range []Action{ActionIAMTenantCreated, ActionIAMTenantDisabled, ActionIAMTenantEnabled, ActionIAMOrganizationCreated} {
		event["action"] = string(action)
		target["kind"] = string(TargetOrganization)
		if action == ActionIAMOrganizationCreated {
			delete(event, "installationId")
			event["tenantId"] = "tenant-original"
		}
		if schema.Validate(event) == nil {
			t.Fatalf("%s accepted a target tenant selector", action)
		}
		delete(target, "tenantId")
		if err := schema.Validate(event); err != nil {
			t.Fatalf("valid lifecycle %s: %v", action, err)
		}
		target["tenantId"] = "tenant-original"
	}
	for _, namespace := range []any{nil, "", "tenant-original"} {
		target["tenantId"] = namespace
		if schema.Validate(event) == nil {
			t.Fatal("non-recovery schema accepted an explicit target namespace")
		}
		encoded, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		var decoded Event
		if DecodeRequest(bytes.NewReader(encoded), &decoded) == nil && ValidateEventForSource(SourceIAM, decoded) == nil {
			t.Fatal("non-recovery decoder erased or accepted an explicit target namespace")
		}
	}
}

func TestLocalCredentialRecoveryPlatformSystemFactIsClosed(t *testing.T) {
	schema := compileAuditOpenAPISchema(t, loadAuditOpenAPI(t), "Event")
	valid := func() map[string]any {
		event := loadAuditSchemaExample(t, "examples/event-paas.json")
		delete(event, "tenantId")
		delete(event, "iamDecisionId")
		delete(event, "operationId")
		event["installationId"] = "installation-original"
		event["action"], event["result"] = string(ActionIAMInstallationPrimaryCredentialsRecovered), string(ResultSucceeded)
		event["actor"] = map[string]any{"type": string(ActorSystem), "id": "iam-local-recovery"}
		event["target"] = map[string]any{"kind": string(TargetPrincipal), "id": "primary-original", "tenantId": "tenant-original"}
		return event
	}
	decode := func(event map[string]any) (Event, error) {
		encoded, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		var result Event
		err = DecodeRequest(bytes.NewReader(encoded), &result)
		return result, err
	}
	base := valid()
	event, err := decode(base)
	if err != nil || ValidateEventForSource(SourceIAM, event) != nil || schema.Validate(base) != nil {
		t.Fatal("valid local IAM security fact was rejected")
	}
	for _, source := range []Source{SourcePaaS, SourceAudit} {
		if ValidateEventForSource(source, event) == nil {
			t.Fatal("another producer acquired the local recovery action")
		}
	}
	for name, mutate := range map[string]func(map[string]any){
		"user actor":          func(e map[string]any) { e["actor"].(map[string]any)["type"] = string(ActorUser) },
		"service actor":       func(e map[string]any) { e["actor"].(map[string]any)["type"] = string(ActorServiceAccount) },
		"another system":      func(e map[string]any) { e["actor"].(map[string]any)["id"] = "installation-verifier" },
		"tenant chain":        func(e map[string]any) { delete(e, "installationId"); e["tenantId"] = "tenant-original" },
		"both scopes":         func(e map[string]any) { e["tenantId"] = "tenant-original" },
		"no target namespace": func(e map[string]any) { delete(e["target"].(map[string]any), "tenantId") },
		"wrong target":        func(e map[string]any) { e["target"].(map[string]any)["kind"] = string(TargetOrganization) },
		"invented decision":   func(e map[string]any) { e["iamDecisionId"] = "decision-forged" },
		"invented operation":  func(e map[string]any) { e["operationId"] = "operation-forged" },
		"wrong outcome":       func(e map[string]any) { e["result"] = string(ResultDenied) },
		"online recovery": func(e map[string]any) {
			e["action"] = string(ActionIAMTenantAdministratorRecovered)
			e["iamDecisionId"] = "decision-online"
		},
		"tenant lifecycle": func(e map[string]any) {
			e["action"] = string(ActionIAMTenantCreated)
			e["iamDecisionId"] = "decision-online"
			e["target"] = map[string]any{"kind": string(TargetOrganization), "id": "tenant-original"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid()
			mutate(candidate)
			if schema.Validate(candidate) == nil {
				t.Fatal("OpenAPI accepted a broadened local recovery fact")
			}
			decoded, err := decode(candidate)
			if err == nil && ValidateEventForSource(SourceIAM, decoded) == nil {
				t.Fatal("Go contract accepted a broadened local recovery fact")
			}
		})
	}
}

func TestAuthenticationRecoveryPlatformSystemFactsAreClosed(t *testing.T) {
	schema := compileAuditOpenAPISchema(t, loadAuditOpenAPI(t), "Event")
	for _, action := range []Action{
		ActionIAMAuthenticationRecoveryClosed,
		ActionIAMAuthenticationRecoveryReconciled,
		ActionIAMAuthenticationRecoveryReopened,
	} {
		t.Run(string(action), func(t *testing.T) {
			valid := func() map[string]any {
				event := loadAuditSchemaExample(t, "examples/event-paas.json")
				delete(event, "tenantId")
				delete(event, "iamDecisionId")
				delete(event, "operationId")
				event["installationId"] = "installation-original"
				event["action"], event["result"] = string(action), string(ResultSucceeded)
				event["actor"] = map[string]any{"type": string(ActorSystem), "id": "iam-authentication-recovery"}
				event["target"] = map[string]any{"kind": string(TargetInstallation), "id": "installation-original"}
				return event
			}
			decode := func(document map[string]any) (Event, error) {
				encoded, err := json.Marshal(document)
				if err != nil {
					t.Fatal(err)
				}
				var event Event
				err = DecodeRequest(bytes.NewReader(encoded), &event)
				return event, err
			}
			base := valid()
			event, err := decode(base)
			if err != nil || ValidateEventForSource(SourceIAM, event) != nil || schema.Validate(base) != nil {
				t.Fatal("valid authentication recovery fact was rejected")
			}
			for name, mutate := range map[string]func(map[string]any){
				"user actor":     func(value map[string]any) { value["actor"].(map[string]any)["type"] = string(ActorUser) },
				"another system": func(value map[string]any) { value["actor"].(map[string]any)["id"] = "iam-local-recovery" },
				"tenant scope": func(value map[string]any) {
					delete(value, "installationId")
					value["tenantId"] = "tenant-original"
				},
				"another target":    func(value map[string]any) { value["target"].(map[string]any)["id"] = "installation-other" },
				"target namespace":  func(value map[string]any) { value["target"].(map[string]any)["tenantId"] = "tenant-original" },
				"invented decision": func(value map[string]any) { value["iamDecisionId"] = "decision-forged" },
			} {
				t.Run(name, func(t *testing.T) {
					candidate := valid()
					mutate(candidate)
					decoded, decodeErr := decode(candidate)
					if schema.Validate(candidate) == nil && decodeErr == nil && ValidateEventForSource(SourceIAM, decoded) == nil {
						t.Fatal("authentication recovery fact accepted a broadened shape")
					}
				})
			}
		})
	}
}
