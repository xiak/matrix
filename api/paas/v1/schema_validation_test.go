package paasv1

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestEveryOpenAPISchemaCompilesAsJSONSchema202012(t *testing.T) {
	document := loadOpenAPI(t)
	for name := range openAPISchemas(t, document) {
		t.Run(name, func(t *testing.T) {
			_ = compileOpenAPISchema(t, document, name)
		})
	}
}

func TestRoleSubjectLineageIsStrictAndIdentityBearing(t *testing.T) {
	schema := compileOpenAPISchema(t, loadOpenAPI(t), "SubjectRef")
	for _, test := range []struct {
		wire  string
		valid bool
	}{
		{`{"type":"USER","id":"user-a"}`, true},
		{`{"type":"ROLE","id":"role-a","roleSession":{"sessionId":"session-a","sourceUserId":"user-a"}}`, true},
		{`{"type":"ROLE","id":"role-a"}`, false},
		{`{"type":"ROLE","id":"role-a","roleSession":null}`, false},
		{`{"type":"ROLE","id":"role-a","roleSession":{"sessionId":"session-a"}}`, false},
		{`{"type":"ROLE","id":"role-a","roleSession":{"sessionId":"session-a","sourceUserId":"user-a","sourceSessionId":"private"}}`, false},
		{`{"type":"ROLE","id":"role-a","roleSession":{"sessionId":"","sourceUserId":"user-a"}}`, false},
		{`{"type":"USER","id":"user-a","roleSession":null}`, false},
		{`{"type":"SERVICE_ACCOUNT","id":"service-a","roleSession":{"sessionId":"session-a","sourceUserId":"user-a"}}`, false},
		{`{"type":"AGENT","id":"agent-a","roleSession":null}`, false},
		{`{"type":"SYSTEM_USER","id":"system-a","roleSession":null}`, false},
	} {
		var subject SubjectRef
		if err := json.Unmarshal([]byte(test.wire), &subject); (err == nil) != test.valid {
			t.Fatalf("subject decoder valid=%v: %s", err == nil, test.wire)
		}
		instance, err := jsonschema.UnmarshalJSON(bytes.NewBufferString(test.wire))
		if err != nil || (schema.Validate(instance) == nil) != test.valid {
			t.Fatalf("subject schema disagrees: %s", test.wire)
		}
		if test.valid {
			encoded, err := json.Marshal(subject)
			var other SubjectRef
			if err != nil || string(encoded) != test.wire || json.Unmarshal(encoded, &other) != nil || !subject.Equal(other) {
				t.Fatal("exact subject bytes or independently decoded identity changed")
			}
			if other.RoleSession != nil {
				other.RoleSession.SessionID = "session-b"
				if subject.Equal(other) {
					t.Fatal("another role session reused the same identity")
				}
			}
		}
	}
}

func TestExamplesValidateAgainstOpenAPISchemas(t *testing.T) {
	document := loadOpenAPI(t)
	examples := map[string]string{
		"examples/tenant.json":                             "Tenant",
		"examples/execution-pool.json":                     "ExecutionPool",
		"examples/execution-target.json":                   "ExecutionTarget",
		"examples/application.json":                        "Application",
		"examples/configuration.json":                      "Configuration",
		"examples/configuration-revision.json":             "ConfigurationRevision",
		"examples/placement-policy.json":                   "PlacementPolicy",
		"examples/application-revision.json":               "ApplicationRevision",
		"examples/deployment.json":                         "Deployment",
		"examples/placement-scheduled.json":                "PlacementDecision",
		"examples/placement-unschedulable.json":            "PlacementDecision",
		"examples/operation.json":                          "Operation",
		"examples/evidence.json":                           "Evidence",
		"examples/inspect-execution-target-request.json":   "InspectExecutionTargetRequest",
		"examples/execution-target-observation-ready.json": "ExecutionTargetObservation",
	}
	for path, schemaName := range examples {
		t.Run(path, func(t *testing.T) {
			schema := compileOpenAPISchema(t, document, schemaName)
			source, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(source))
			if err != nil {
				t.Fatalf("decode %s for JSON Schema validation: %v", path, err)
			}
			if err := schema.Validate(instance); err != nil {
				t.Fatalf("%s does not satisfy %s: %v", path, schemaName, err)
			}
		})
	}
}

func TestComponentInputSchemaEnforcesPhaseOneInjection(t *testing.T) {
	schema := compileOpenAPISchema(t, loadOpenAPI(t), "ComponentInput")
	invalid := [][]byte{
		[]byte(`{"name":"settings","kind":"CONFIGURATION","injection":"FILE","required":true}`),
		[]byte(`{"name":"credentials","kind":"SECRET","injection":"ENV","required":true}`),
	}
	for _, source := range invalid {
		instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(source))
		if err != nil {
			t.Fatalf("decode component input: %v", err)
		}
		if err := schema.Validate(instance); err == nil {
			t.Fatalf("unsupported Phase 1 input injection must fail schema validation: %s", source)
		}
	}
}

func TestPlacementDecisionSchemaBindsSelectedTargetVersion(t *testing.T) {
	document := loadOpenAPI(t)
	schema := compileOpenAPISchema(t, document, "PlacementDecision")
	scheduled := loadSchemaExample(t, "examples/placement-scheduled.json")
	targetVersion := scheduled["executionTargetResourceVersion"]
	delete(scheduled, "executionTargetResourceVersion")
	if err := schema.Validate(scheduled); err == nil {
		t.Fatal("scheduled placement without target resource version must fail schema validation")
	}

	unschedulable := loadSchemaExample(t, "examples/placement-unschedulable.json")
	unschedulable["executionTargetResourceVersion"] = targetVersion
	if err := schema.Validate(unschedulable); err == nil {
		t.Fatal("unschedulable placement with target resource version must fail schema validation")
	}
}

func TestExecutionAdapterValuesValidateAgainstOpenAPISchemas(t *testing.T) {
	document := loadOpenAPI(t)
	request := validDeploymentExecutionRequest(t)
	observe := ObserveDeploymentRequest{
		Command:               request.Command,
		Generation:            request.Generation.Generation,
		ExpectedContentDigest: request.Generation.ContentDigest,
	}
	observe.Command.Action = AdapterObserveDeployment
	observe.Command.CommandID = "command-observe-001"
	observe.Command.RequestDigest = ObserveDeploymentRequestDigest(observe)
	observation := DeploymentObservation{
		DeploymentID:          request.Generation.DeploymentID,
		Generation:            request.Generation.Generation,
		ApplicationRevisionID: request.ApplicationRevision.Metadata.ID,
		Phase:                 DeploymentReady,
		ReadyComponents:       1,
		Endpoints: []DeploymentEndpointObservation{{
			ComponentName: "web", EndpointName: "http", Protocol: EndpointHTTP,
			Address: "web", Port: 8080,
		}},
		ReceiptDigest: testExecutionDigest('f'),
		ObservedAt:    request.Generation.CreatedAt.Add(time.Minute),
	}
	values := map[string]any{
		"DeploymentGeneration":       request.Generation,
		"DeploymentExecutionRequest": request,
		"ObserveDeploymentRequest":   observe,
		"DeploymentObservation":      observation,
	}
	for schemaName, value := range values {
		t.Run(schemaName, func(t *testing.T) {
			encoded, err := json.Marshal(value)
			if err != nil {
				t.Fatalf("encode %s: %v", schemaName, err)
			}
			instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(encoded))
			if err != nil {
				t.Fatalf("decode %s JSON: %v", schemaName, err)
			}
			if err := compileOpenAPISchema(t, document, schemaName).Validate(instance); err != nil {
				t.Fatalf("%s does not satisfy OpenAPI schema: %v", schemaName, err)
			}
		})
	}

	executionSchema := compileOpenAPISchema(t, document, "DeploymentExecutionRequest")
	wrongAction := schemaInstance(t, request).(map[string]any)
	wrongAction["command"].(map[string]any)["action"] = string(AdapterObserveDeployment)
	if err := executionSchema.Validate(wrongAction); err == nil {
		t.Fatal("execution request schema must reject an observation action")
	}
	unscheduled := schemaInstance(t, request).(map[string]any)
	unscheduled["placement"] = loadSchemaExample(t, "examples/placement-unschedulable.json")
	if err := executionSchema.Validate(unscheduled); err == nil {
		t.Fatal("execution request schema must reject an unscheduled placement")
	}
	observeSchema := compileOpenAPISchema(t, document, "ObserveDeploymentRequest")
	wrongObserveAction := schemaInstance(t, observe).(map[string]any)
	wrongObserveAction["command"].(map[string]any)["action"] = string(AdapterApplyDeployment)
	if err := observeSchema.Validate(wrongObserveAction); err == nil {
		t.Fatal("observe request schema must reject an execution action")
	}
}

func schemaInstance(t *testing.T, value any) any {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("encode schema instance: %v", err)
	}
	instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(encoded))
	if err != nil {
		t.Fatalf("decode schema instance: %v", err)
	}
	return instance
}

func loadSchemaExample(t *testing.T, path string) map[string]any {
	t.Helper()
	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(source))
	if err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	object, ok := instance.(map[string]any)
	if !ok {
		t.Fatalf("%s contains %T, want object", path, instance)
	}
	return object
}

func compileOpenAPISchema(
	t *testing.T,
	document map[string]any,
	name string,
) *jsonschema.Schema {
	t.Helper()
	wrapper := map[string]any{
		"$schema":    "https://json-schema.org/draft/2020-12/schema",
		"$ref":       "#/components/schemas/" + name,
		"components": document["components"],
	}
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	resource := "https://matrix.paas.invalid/contracts/" + name + ".json"
	if err := compiler.AddResource(resource, wrapper); err != nil {
		t.Fatalf("add %s schema resource: %v", name, err)
	}
	schema, err := compiler.Compile(resource)
	if err != nil {
		t.Fatalf("compile %s schema: %v", name, err)
	}
	return schema
}
