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
		"examples/tenant.json":                  "Tenant",
		"examples/resource-pool.json":           "ResourcePool",
		"examples/runtime-target.json":          "RuntimeTarget",
		"examples/placement-policy.json":        "PlacementPolicy",
		"examples/workload-release.json":        "WorkloadRelease",
		"examples/placement-unschedulable.json": "PlacementDecision",
		"examples/operation.json":               "Operation",
		"examples/evidence.json":                "Evidence",
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
