package main

import (
	"bytes"
	"encoding/json"
	"os"
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
	for _, operation := range []string{"login", "changePassword", "createUser"} {
		value := mutationOperation(operation, "test", "LoginRequest", "LoginResponse", "200", nil, nil)
		responses := value["responses"].(object)
		_, present := responses["429"]
		if present != (operation != "createUser") {
			t.Fatal("overload contract leaked to unrelated commands")
		}
	}
}
