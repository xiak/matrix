package auditv1

import (
	"bytes"
	"os"
	"testing"

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
