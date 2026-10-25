package sourcecredential

import (
	"bytes"
	"testing"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
)

func TestMaterialRoundTripAndRotationRules(t *testing.T) {
	current := []byte("current-webhook-secret-000000000001")
	previous := []byte("previous-webhook-secret-0000000001")
	material, err := NewMaterial(PurposeWebhook, current, previous)
	if err != nil {
		t.Fatal(err)
	}
	defer material.Clear()
	content, err := Encode(PurposeWebhook, material)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(content)
	decoded, err := Decode(PurposeWebhook, content)
	if err != nil {
		t.Fatal(err)
	}
	defer decoded.Clear()
	if !bytes.Equal(decoded.Current, current) || !bytes.Equal(decoded.Previous, previous) {
		t.Fatal("source credential material did not round trip")
	}
	if _, err := NewMaterial(PurposeFetch, current, previous); err == nil {
		t.Fatal("fetch credential accepted a previous value")
	}
	if _, err := NewMaterial(PurposeWebhook, current, current); err == nil {
		t.Fatal("webhook credential accepted equal rotation values")
	}
}

func TestMaterialDecodeRejectsNonCanonicalAndUnsafeValues(t *testing.T) {
	valid, err := NewMaterial(PurposeFetch, []byte("fetch-token-0000000000000000000001"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer valid.Clear()
	content, err := Encode(PurposeFetch, valid)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(content)
	for name, candidate := range map[string][]byte{
		"trailing newline": append(append([]byte(nil), content...), '\n'),
		"unknown field":    []byte(`{"apiVersion":"devops.matrix.xiak.com/v1","kind":"SourceCredentialMaterial","current":"ZmV0Y2gtdG9rZW4tMDAwMDAwMDAwMDAwMDAwMDAwMDAwMQ==","extra":true}`),
		"short value":      []byte(`{"apiVersion":"devops.matrix.xiak.com/v1","kind":"SourceCredentialMaterial","current":"c2hvcnQ="}`),
	} {
		if material, err := Decode(PurposeFetch, candidate); err == nil {
			material.Clear()
			t.Fatalf("accepted %s material", name)
		}
	}
}

func TestDirectoryNameBindsPurposeTenantAndReference(t *testing.T) {
	scope := devopsv1.ResourceScope{TenantID: "tenant:one"}
	reference := devopsv1.ResourceID("credential:one")
	webhook, err := DirectoryName(PurposeWebhook, scope, reference)
	if err != nil {
		t.Fatal(err)
	}
	fetch, err := DirectoryName(PurposeFetch, scope, reference)
	if err != nil {
		t.Fatal(err)
	}
	otherTenant, err := DirectoryName(
		PurposeWebhook, devopsv1.ResourceScope{TenantID: "tenant:two"}, reference,
	)
	if err != nil {
		t.Fatal(err)
	}
	if webhook != "229e6de8a698054c0e7546f4bf01b8eee1071c0e9492ff6d94493e360067c9a3" ||
		webhook == fetch || webhook == otherTenant || webhook == string(reference) {
		t.Fatalf("credential directory identities are not purpose and tenant bound")
	}
}
