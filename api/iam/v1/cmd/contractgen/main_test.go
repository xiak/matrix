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

func TestSecuritySettingsComponentsDoNotPublishAnUnimplementedRoute(t *testing.T) {
	document := buildDocument()
	for path := range document["paths"].(object) {
		if strings.HasPrefix(path, "/v1/account/security-settings") {
			t.Fatal("pure contract slice published an unimplemented settings workflow")
		}
	}
}
