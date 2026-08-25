package paasv1

import (
	"bytes"
	"os"
	"testing"

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
