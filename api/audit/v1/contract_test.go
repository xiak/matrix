package auditv1

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/xiak/matrix/api/contractjson"
)

func TestAuditExamplesPassDomainValidation(t *testing.T) {
	tests := []struct {
		name string
		run  func(*testing.T)
	}{
		{"PaaS event", validAuditEvent("examples/event-paas.json", SourcePaaS)},
		{"denied IAM event", validAuditEvent("examples/event-iam-denied.json", SourceIAM)},
		{"ingestion result", validAuditExample[IngestionResult]("examples/ingestion-result.json", ValidateIngestionResult)},
		{"query request", validAuditExample[QueryRecordsRequest]("examples/query-records-request.json", ValidateQueryRecordsRequest)},
		{"record page", validAuditExample[RecordPage]("examples/record-page.json", ValidateRecordPage)},
		{"verify request", validAuditExample[VerifyChainRequest]("examples/verify-chain-request.json", ValidateVerifyChainRequest)},
		{"chain verification", validAuditExample[ChainVerification]("examples/chain-verification.json", ValidateChainVerification)},
		{"readiness", validAuditExample[Readiness]("examples/readiness.json", ValidateReadiness)},
		{"problem", validAuditExample[Problem]("examples/problem.json", ValidateProblem)},
	}
	for _, test := range tests {
		t.Run(test.name, test.run)
	}
}

func TestAuditInputCannotForgeSourceOrQueryTenant(t *testing.T) {
	event := `{"apiVersion":"audit.matrix.xiak.com/v1","kind":"AuditEvent","source":"IAM","eventId":"event-example","tenantId":"organization-example","actor":{"type":"SYSTEM","id":"paas"},"iamDecisionId":"decision-example","action":"paas.deployment.created","target":{"kind":"DEPLOYMENT","id":"deployment-example"},"result":"ACCEPTED","requestDigest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","requestId":"request-example","correlationId":"correlation-example","operationId":"operation-example","occurredAt":"2026-08-25T03:04:05.000000Z"}`
	var decodedEvent Event
	if err := DecodeRequest(strings.NewReader(event), &decodedEvent); !errors.Is(err, contractjson.ErrUnknownField) {
		t.Fatalf("forged event source error = %v, want unknown field", err)
	}

	for name, query := range map[string]string{
		"tenant":  `{"pageSize":10,"tenantId":"organization-forged"}`,
		"subject": `{"pageSize":10,"subject":{"type":"USER","id":"principal-forged"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			var request QueryRecordsRequest
			if err := DecodeRequest(strings.NewReader(query), &request); !errors.Is(err, contractjson.ErrUnknownField) {
				t.Fatalf("forged query %s error = %v, want unknown field", name, err)
			}
		})
	}

	var request QueryRecordsRequest
	if err := DecodeRequest(strings.NewReader(`{"pageSize":10,"pageSize":20}`), &request); !errors.Is(err, contractjson.ErrDuplicateField) {
		t.Fatalf("duplicate query field error = %v, want duplicate field", err)
	}
	if err := DecodeRequest(strings.NewReader(`{"pageSize":10} {}`), &request); !errors.Is(err, contractjson.ErrTrailingData) {
		t.Fatalf("trailing query document error = %v, want trailing data", err)
	}
	oversized := `{"pageSize":10,"cursor":"` + strings.Repeat("A", int(MaxRequestBytes)) + `"}`
	if err := DecodeRequest(strings.NewReader(oversized), &request); !errors.Is(err, contractjson.ErrDocumentTooLarge) {
		t.Fatalf("oversized query error = %v, want document too large", err)
	}
}

func TestAuditActionCatalogIsClosedAndSourceBound(t *testing.T) {
	for _, action := range AllActions() {
		contract, known := ContractForAction(action)
		if !known || contract.Source == "" || contract.Target == "" || len(contract.Results) == 0 {
			t.Fatalf("action %q has an incomplete contract: %#v", action, contract)
		}
		event := Event{
			APIVersion: APIVersion, Kind: "AuditEvent", EventID: "event-example",
			TenantID: "organization-example", Actor: ActorReference{Type: ActorSystem, ID: "system-example"},
			Action: action, Target: TargetReference{Kind: contract.Target, ID: "target-example"},
			Result:        contract.Results[0],
			RequestDigest: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
			RequestID:     "request-example", CorrelationID: "correlation-example",
			OccurredAt: time.Date(2026, 8, 25, 3, 4, 5, 0, time.UTC),
		}
		if contract.IAMDecisionRequired {
			event.IAMDecisionID = "decision-example"
		}
		if action == ActionIAMAuthorizationDecided {
			event.Target.ID = string(event.IAMDecisionID)
		}
		if contract.OperationRequired {
			event.OperationID = "operation-example"
		}
		if err := ValidateEventForSource(contract.Source, event); err != nil {
			t.Fatalf("valid action contract %q rejected: %v", action, err)
		}
		if err := ValidateEventForSource(otherAuditSource(contract.Source), event); err == nil {
			t.Fatalf("action %q accepted a forged source", action)
		}
	}
	if _, known := ContractForAction(Action("audit.unregistered")); known {
		t.Fatal("unregistered Audit action has a contract")
	}
}

func TestAuditWireTypesHaveNoArbitraryPayloadEscapeHatch(t *testing.T) {
	roots := []reflect.Type{
		reflect.TypeOf(Event{}), reflect.TypeOf(AuditRecord{}), reflect.TypeOf(IngestionResult{}),
		reflect.TypeOf(QueryRecordsRequest{}), reflect.TypeOf(RecordPage{}),
		reflect.TypeOf(VerifyChainRequest{}), reflect.TypeOf(ChainVerification{}),
	}
	seen := map[reflect.Type]bool{}
	for _, root := range roots {
		assertClosedAuditType(t, root, seen)
	}
}

func TestAuditOpenAPISecurityDerivesSourceAndTenantFromCredentials(t *testing.T) {
	document := loadAuditOpenAPI(t)
	paths := mustAuditObject(t, document["paths"], "paths")
	assertAuditSecurity(t, paths, "/v1/events", "ServiceCredential")
	assertAuditSecurity(t, paths, "/v1/records:query", "UserSession")
	assertAuditSecurity(t, paths, "/v1/integrity:verify", "UserSession")

	schemas := auditOpenAPISchemas(t, document)
	eventProperties := mustAuditObject(t, mustAuditObject(t, schemas["Event"], "event schema")["properties"], "event properties")
	if _, exists := eventProperties["source"]; exists {
		t.Fatal("Audit event request exposes a caller-selected source")
	}
	for _, schemaName := range []string{"QueryRecordsRequest", "VerifyChainRequest"} {
		properties := mustAuditObject(t, mustAuditObject(t, schemas[schemaName], schemaName)["properties"], schemaName+" properties")
		for _, forbidden := range []string{"tenantId", "organizationId", "subject", "source"} {
			if _, exists := properties[forbidden]; exists {
				t.Fatalf("%s exposes authority selector %q", schemaName, forbidden)
			}
		}
	}
	assertNoAuditAuthorityHeader(t, document)
}

func validAuditEvent(path string, source Source) func(*testing.T) {
	return func(t *testing.T) {
		value := decodeAuditExample[Event](t, path)
		if err := ValidateEventForSource(source, value); err != nil {
			t.Fatalf("validate %s: %v", path, err)
		}
	}
}

func validAuditExample[T any](path string, validate func(T) error) func(*testing.T) {
	return func(t *testing.T) {
		value := decodeAuditExample[T](t, path)
		if err := validate(value); err != nil {
			t.Fatalf("validate %s: %v", path, err)
		}
	}
}

func otherAuditSource(source Source) Source {
	if source == SourceIAM {
		return SourcePaaS
	}
	return SourceIAM
}

func assertClosedAuditType(t *testing.T, contract reflect.Type, seen map[reflect.Type]bool) {
	t.Helper()
	for contract.Kind() == reflect.Pointer || contract.Kind() == reflect.Slice {
		if contract.Kind() == reflect.Slice && contract.Elem().Kind() == reflect.Uint8 {
			t.Fatalf("Audit wire contract contains raw bytes: %s", contract)
		}
		contract = contract.Elem()
	}
	if contract == reflect.TypeOf(time.Time{}) || seen[contract] {
		return
	}
	seen[contract] = true
	switch contract.Kind() {
	case reflect.Map, reflect.Interface:
		t.Fatalf("Audit wire contract contains arbitrary %s: %s", contract.Kind(), contract)
	case reflect.Struct:
		for index := range contract.NumField() {
			field := contract.Field(index)
			jsonName := strings.Split(field.Tag.Get("json"), ",")[0]
			normalized := strings.ToLower(jsonName)
			for _, forbidden := range []string{"attributes", "body", "payload", "credential", "password", "secret", "native", "path"} {
				if normalized == forbidden || strings.HasSuffix(normalized, forbidden) {
					t.Fatalf("Audit wire contract contains forbidden field %s.%s", contract, field.Name)
				}
			}
			assertClosedAuditType(t, field.Type, seen)
		}
	}
}

func assertAuditSecurity(t *testing.T, paths map[string]any, path, scheme string) {
	t.Helper()
	pathObject := mustAuditObject(t, paths[path], path)
	operation := mustAuditObject(t, pathObject["post"], path+" operation")
	security, ok := operation["security"].([]any)
	if !ok || len(security) != 1 {
		t.Fatalf("%s security = %#v, want one requirement", path, operation["security"])
	}
	requirement := mustAuditObject(t, security[0], path+" security requirement")
	if len(requirement) != 1 || requirement[scheme] == nil {
		t.Fatalf("%s security = %#v, want only %s", path, requirement, scheme)
	}
}

func assertNoAuditAuthorityHeader(t *testing.T, value any) {
	t.Helper()
	switch typed := value.(type) {
	case []any:
		for _, item := range typed {
			assertNoAuditAuthorityHeader(t, item)
		}
	case map[string]any:
		if typed["in"] == "header" {
			name, _ := typed["name"].(string)
			normalized := strings.ToLower(name)
			if strings.Contains(normalized, "tenant") || strings.Contains(normalized, "organization") ||
				strings.Contains(normalized, "source") || strings.Contains(normalized, "subject") {
				t.Fatalf("Audit OpenAPI exposes authority selector header %q", name)
			}
		}
		for _, child := range typed {
			assertNoAuditAuthorityHeader(t, child)
		}
	}
}
