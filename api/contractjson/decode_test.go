package contractjson

import (
	"errors"
	"strings"
	"testing"
)

type request struct {
	Name   string `json:"name"`
	Nested struct {
		Value string `json:"value"`
	} `json:"nested"`
}

func TestDecodeObjectAcceptsOneStrictObject(t *testing.T) {
	var value request
	err := DecodeObject(
		strings.NewReader(`{"name":"matrix","nested":{"value":"paas"}}`),
		128,
		&value,
	)
	if err != nil {
		t.Fatalf("decode strict object: %v", err)
	}
	if value.Name != "matrix" || value.Nested.Value != "paas" {
		t.Fatalf("decoded value = %#v", value)
	}
}

func TestDecodeObjectRejectsAmbiguousOrUnboundedInput(t *testing.T) {
	tests := []struct {
		name    string
		source  string
		maximum int64
		want    error
	}{
		{name: "duplicate root", source: `{"name":"a","name":"b","nested":{"value":"c"}}`, maximum: 128, want: ErrDuplicateField},
		{name: "duplicate nested", source: `{"name":"a","nested":{"value":"b","value":"c"}}`, maximum: 128, want: ErrDuplicateField},
		{name: "case alias", source: `{"name":"a","Name":"b"}`, maximum: 128, want: ErrUnknownField},
		{name: "unknown", source: `{"name":"a","nested":{"value":"b"},"tenantId":"forged"}`, maximum: 128, want: ErrUnknownField},
		{name: "trailing object", source: `{"name":"a","nested":{"value":"b"}} {}`, maximum: 128, want: ErrTrailingData},
		{name: "array root", source: `[]`, maximum: 128, want: ErrInvalidDocument},
		{name: "too large", source: `{"name":"matrix","nested":{"value":"paas"}}`, maximum: 8, want: ErrDocumentTooLarge},
		{name: "invalid", source: `{"name":`, maximum: 128, want: ErrInvalidDocument},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var value request
			err := DecodeObject(strings.NewReader(test.source), test.maximum, &value)
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
			if err != nil && strings.Contains(err.Error(), test.source) {
				t.Fatal("decode error leaked request data")
			}
		})
	}
}

func TestDecodeObjectPreservesMapKeysAndChecksTypedCollections(t *testing.T) {
	type item struct {
		Name string `json:"name"`
	}
	var value struct {
		Labels map[string]string `json:"labels"`
		Items  []*item           `json:"items"`
	}
	source := `{"labels":{"Name":"upper","name":"lower"},"items":[{"name":"valid"}]}`
	if err := DecodeObject(strings.NewReader(source), 256, &value); err != nil ||
		value.Labels["Name"] != "upper" || value.Labels["name"] != "lower" || value.Items[0].Name != "valid" {
		t.Fatalf("typed collection/map decoding changed data: %#v, %v", value, err)
	}
	source = `{"labels":{},"items":[{"Name":"alias"}]}`
	if err := DecodeObject(strings.NewReader(source), 256, &value); !errors.Is(err, ErrUnknownField) {
		t.Fatalf("nested collection accepted a field alias: %v", err)
	}
}

func TestDecodeObjectRejectsInvalidDestination(t *testing.T) {
	if err := DecodeObject(strings.NewReader(`{}`), 16, request{}); !errors.Is(err, ErrInvalidDocument) {
		t.Fatalf("invalid destination error = %v", err)
	}
}

func TestDecodeObjectBoundsNestedObjectsAndArrays(t *testing.T) {
	for _, container := range []struct{ open, close string }{
		{`{"value":`, `}`}, {`[`, `]`},
	} {
		for _, depth := range []int{MaximumDepth, MaximumDepth + 1} {
			source := `{"nested":` + strings.Repeat(container.open, depth-1) + `null` +
				strings.Repeat(container.close, depth-1) + `}`
			var value map[string]any
			err := DecodeObject(strings.NewReader(source), 4096, &value)
			if depth == MaximumDepth && err != nil {
				t.Fatalf("document at depth limit rejected: %v", err)
			}
			if depth > MaximumDepth && !errors.Is(err, ErrDocumentTooDeep) {
				t.Fatalf("over-depth document error = %v", err)
			}
		}
	}
}
