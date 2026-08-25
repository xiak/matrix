package iamv1

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func loadIAMOpenAPI(t *testing.T) map[string]any {
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

func iamOpenAPISchemas(t *testing.T, document map[string]any) map[string]any {
	t.Helper()
	components, ok := document["components"].(map[string]any)
	if !ok {
		t.Fatal("OpenAPI components are missing")
	}
	schemas, ok := components["schemas"].(map[string]any)
	if !ok {
		t.Fatal("OpenAPI component schemas are missing")
	}
	return schemas
}

func compileIAMOpenAPISchema(
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
	resource := "https://iam.matrix.xiak.com/contracts/" + name + ".json"
	if err := compiler.AddResource(resource, wrapper); err != nil {
		t.Fatalf("add %s schema resource: %v", name, err)
	}
	schema, err := compiler.Compile(resource)
	if err != nil {
		t.Fatalf("compile %s schema: %v", name, err)
	}
	return schema
}

func loadIAMSchemaExample(t *testing.T, path string) map[string]any {
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

func decodeIAMExample[T any](t *testing.T, path string) T {
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
