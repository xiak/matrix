package auditv1

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func loadAuditOpenAPI(t *testing.T) map[string]any {
	t.Helper()
	source, err := os.ReadFile("openapi.json")
	if err != nil {
		t.Fatalf("read openapi.json: %v", err)
	}
	var document map[string]any
	if err := json.Unmarshal(source, &document); err != nil {
		t.Fatalf("decode openapi.json: %v", err)
	}
	return document
}

func auditOpenAPISchemas(t *testing.T, document map[string]any) map[string]any {
	t.Helper()
	components := mustAuditObject(t, document["components"], "components")
	return mustAuditObject(t, components["schemas"], "component schemas")
}

func compileAuditOpenAPISchema(
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
	resource := "https://audit.matrix.xiak.com/contracts/" + name + ".json"
	if err := compiler.AddResource(resource, wrapper); err != nil {
		t.Fatalf("add %s schema resource: %v", name, err)
	}
	schema, err := compiler.Compile(resource)
	if err != nil {
		t.Fatalf("compile %s schema: %v", name, err)
	}
	return schema
}

func loadAuditSchemaExample(t *testing.T, path string) map[string]any {
	t.Helper()
	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(source))
	if err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return mustAuditObject(t, instance, path)
}

func decodeAuditExample[T any](t *testing.T, path string) T {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer file.Close()
	var value T
	if err := DecodeRequest(file, &value); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return value
}

func mustAuditObject(t *testing.T, value any, name string) map[string]any {
	t.Helper()
	object, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("%s contains %T, want object", name, value)
	}
	return object
}
