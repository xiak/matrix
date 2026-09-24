package main

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestGeneratedOpenAPIIsCurrent(t *testing.T) {
	want, err := os.ReadFile("../../openapi.json")
	if err != nil {
		t.Fatalf("read committed OpenAPI: %v", err)
	}
	got, err := json.MarshalIndent(buildDocument(), "", "  ")
	if err != nil {
		t.Fatalf("generate OpenAPI: %v", err)
	}
	got = append(got, '\n')
	if !bytes.Equal(got, want) {
		t.Fatal("openapi.json is stale; run go generate ./api/iam/v1")
	}
}

func TestPasswordOverloadOnlyDocumentsTheBoundedAuthenticationEntrypoints(t *testing.T) {
	for _, operation := range []string{"login", "changePassword", "verifyStepUp", "createUser", "regenerateRecoveryCodes"} {
		value := mutationOperation(operation, "test", "LoginRequest", "LoginResponse", "200", nil, nil)
		responses := value["responses"].(object)
		_, present := responses["429"]
		if present != (operation == "login" || operation == "changePassword" || operation == "verifyStepUp") {
			t.Fatal("overload contract leaked to unrelated commands")
		}
	}
}

func TestSecuritySettingsOnlyPublishesImplementedRead(t *testing.T) {
	document := buildDocument()
	found := false
	for path, value := range document["paths"].(object) {
		if strings.HasPrefix(path, "/v1/account/security-settings") {
			if path != "/v1/account/security-settings" || len(value.(object)) != 1 || value.(object)["get"] == nil {
				t.Fatal("read slice published an unimplemented settings mutation or completion route")
			}
			found = true
		}
	}
	if !found {
		t.Fatal("implemented settings read is not documented")
	}
}
