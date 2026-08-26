package managedservicev1

import (
	"encoding/json"
	"os"
	"testing"
)

func TestMutationSchemasAreClosedAndExcludeNativeAuthorityFields(t *testing.T) {
	encoded, err := os.ReadFile("openapi.json")
	if err != nil {
		t.Fatal("read managed-service OpenAPI")
	}
	var document map[string]any
	if json.Unmarshal(encoded, &document) != nil {
		t.Fatal("decode managed-service OpenAPI")
	}
	components := document["components"].(map[string]any)
	schemas := components["schemas"].(map[string]any)
	for _, name := range []string{"ActivateQuotaRequest", "CreateInstallationRequest"} {
		schema := schemas[name].(map[string]any)
		if schema["additionalProperties"] != false {
			t.Fatalf("%s accepts unknown fields", name)
		}
		properties := schema["properties"].(map[string]any)
		for _, forbidden := range []string{
			"organizationId", "tenantId", "price", "currency", "payment",
			"image", "digest", "command", "compose", "hostPath", "credential",
		} {
			if _, found := properties[forbidden]; found {
				t.Fatalf("%s exposes forbidden field %q", name, forbidden)
			}
		}
	}
}
