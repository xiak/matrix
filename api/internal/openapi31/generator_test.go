package openapi31

import (
	"reflect"
	"testing"
	"time"
)

type state string
type identifier string

type sample struct {
	ID        identifier `json:"id"`
	State     state      `json:"state"`
	CreatedAt time.Time  `json:"createdAt"`
	Optional  *string    `json:"optional,omitempty"`
}

func TestBuildDerivesClosedStructSchema(t *testing.T) {
	document := Build(Options{
		Title: "sample", Version: "1", Paths: Object{}, SecuritySchemes: Object{},
		Scalars: Object{
			"Timestamp":  Object{"type": "string", "format": "date-time"},
			"identifier": Object{"type": "string"},
		},
		Enums:   map[string][]string{"state": {"READY"}},
		Structs: map[string]reflect.Type{"sample": reflect.TypeOf(sample{})},
	})
	schemas := document["components"].(Object)["schemas"].(Object)
	contract := schemas["sample"].(Object)
	if contract["additionalProperties"] != false {
		t.Fatal("generated object must reject unknown fields")
	}
	properties := contract["properties"].(Object)
	if properties["id"].(Object)["$ref"] != "#/components/schemas/identifier" ||
		properties["state"].(Object)["$ref"] != "#/components/schemas/state" ||
		properties["createdAt"].(Object)["$ref"] != "#/components/schemas/Timestamp" {
		t.Fatalf("generated properties = %#v", properties)
	}
	required := contract["required"].([]string)
	if len(required) != 3 || required[0] != "createdAt" || required[1] != "id" || required[2] != "state" {
		t.Fatalf("required = %#v", required)
	}
}
