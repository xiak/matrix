package installationv1

import (
	"bytes"
	"os"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestEveryInstallationOpenAPISchemaCompiles(t *testing.T) {
	document := loadInstallationOpenAPI(t)
	for name := range installationOpenAPISchemas(t, document) {
		t.Run(name, func(t *testing.T) {
			_ = compileInstallationOpenAPISchema(t, document, name)
		})
	}
}

func TestInstallationExamplesValidateAgainstOpenAPI(t *testing.T) {
	document := loadInstallationOpenAPI(t)
	examples := map[string]string{
		"examples/installed-products.json": "InstalledProductList",
		"examples/readiness.json":          "Readiness",
		"examples/problem.json":            "Problem",
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
			if err := compileInstallationOpenAPISchema(t, document, schemaName).Validate(instance); err != nil {
				t.Fatalf("%s does not satisfy %s: %v", path, schemaName, err)
			}
		})
	}
}

func TestInstallationSchemasEnforceProductAndReadinessRules(t *testing.T) {
	document := loadInstallationOpenAPI(t)
	productSchema := compileInstallationOpenAPISchema(t, document, "InstalledProduct")
	list := loadInstallationSchemaExample(t, "examples/installed-products.json")
	product := list["products"].([]any)[0].(map[string]any)
	product["routeKey"] = "devops"
	if err := productSchema.Validate(product); err == nil {
		t.Fatal("product with mismatched route passed schema validation")
	}

	product = loadInstallationSchemaExample(t, "examples/installed-products.json")["products"].([]any)[0].(map[string]any)
	product["reason"] = string(ReasonObservationStale)
	if err := productSchema.Validate(product); err == nil {
		t.Fatal("ready product with a failure reason passed schema validation")
	}

	readinessSchema := compileInstallationOpenAPISchema(t, document, "Readiness")
	readiness := loadInstallationSchemaExample(t, "examples/readiness.json")
	delete(readiness, "releaseId")
	if err := readinessSchema.Validate(readiness); err == nil {
		t.Fatal("ready discovery without a release identity passed schema validation")
	}
}

func TestInstalledProductsEndpointRequiresOnlyUserSession(t *testing.T) {
	document := loadInstallationOpenAPI(t)
	paths := document["paths"].(map[string]any)
	operation := paths["/v1/installed-products"].(map[string]any)["get"].(map[string]any)
	security := operation["security"].([]any)
	if len(security) != 1 {
		t.Fatalf("installed-product security = %#v", security)
	}
	requirement := security[0].(map[string]any)
	if len(requirement) != 1 || requirement["UserSession"] == nil {
		t.Fatalf("installed-product security = %#v", requirement)
	}
}
