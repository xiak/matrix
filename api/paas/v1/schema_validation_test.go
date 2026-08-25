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
		"examples/tenant.json":                   "Tenant",
		"examples/resource-pool.json":            "ResourcePool",
		"examples/runtime-target.json":           "RuntimeTarget",
		"examples/placement-policy.json":         "PlacementPolicy",
		"examples/workload-release.json":         "WorkloadRelease",
		"examples/placement-scheduled.json":      "PlacementDecision",
		"examples/placement-unschedulable.json":  "PlacementDecision",
		"examples/operation.json":                "Operation",
		"examples/evidence.json":                 "Evidence",
		"examples/inspect-target-request.json":   "InspectTargetRequest",
		"examples/target-observation-ready.json": "TargetObservation",
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

func TestPlacementDecisionSchemaBindsSelectedTargetVersion(t *testing.T) {
	document := loadOpenAPI(t)
	schema := compileOpenAPISchema(t, document, "PlacementDecision")
	scheduled, err := os.ReadFile("examples/placement-scheduled.json")
	if err != nil {
		t.Fatalf("read scheduled placement: %v", err)
	}
	withoutVersion := bytes.Replace(
		scheduled,
		[]byte("  \"runtimeTargetResourceVersion\": 1,\n"),
		nil,
		1,
	)
	instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(withoutVersion))
	if err != nil {
		t.Fatalf("decode scheduled placement without version: %v", err)
	}
	if err := schema.Validate(instance); err == nil {
		t.Fatal("scheduled placement without target resource version must fail schema validation")
	}

	unschedulable, err := os.ReadFile("examples/placement-unschedulable.json")
	if err != nil {
		t.Fatalf("read unschedulable placement: %v", err)
	}
	withVersion := bytes.Replace(
		unschedulable,
		[]byte("  \"outcome\": \"UNSCHEDULABLE\",\n"),
		[]byte("  \"outcome\": \"UNSCHEDULABLE\",\n  \"runtimeTargetResourceVersion\": 1,\n"),
		1,
	)
	instance, err = jsonschema.UnmarshalJSON(bytes.NewReader(withVersion))
	if err != nil {
		t.Fatalf("decode unschedulable placement with version: %v", err)
	}
	if err := schema.Validate(instance); err == nil {
		t.Fatal("unschedulable placement with target resource version must fail schema validation")
	}
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
