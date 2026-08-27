// Package contractjson decodes bounded JSON objects for Matrix HTTP
// contracts. It rejects ambiguous documents before they reach a service.
package contractjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
)

var (
	ErrInvalidDocument  = errors.New("invalid JSON document")
	ErrDocumentTooLarge = errors.New("JSON document exceeds its size limit")
	ErrDocumentTooDeep  = errors.New("JSON document exceeds its nesting limit")
	ErrDuplicateField   = errors.New("JSON document contains a duplicate field")
	ErrUnknownField     = errors.New("JSON document contains an unknown field")
	ErrTrailingData     = errors.New("JSON document contains trailing data")
)

// MaximumDepth bounds object and array nesting before typed decoding.
const MaximumDepth = 32

// DecodeObject reads exactly one bounded JSON object into destination. Error
// values are deliberately normalized and never contain request data or native
// decoder diagnostics.
func DecodeObject(reader io.Reader, maximumBytes int64, destination any) error {
	if reader == nil || maximumBytes <= 0 || !writablePointer(destination) {
		return ErrInvalidDocument
	}
	source, err := io.ReadAll(io.LimitReader(reader, maximumBytes+1))
	if err != nil {
		return ErrInvalidDocument
	}
	if int64(len(source)) > maximumBytes {
		return ErrDocumentTooLarge
	}
	if len(bytes.TrimSpace(source)) == 0 {
		return ErrInvalidDocument
	}
	if err := inspectObject(source, reflect.TypeOf(destination)); err != nil {
		return err
	}

	decoder := json.NewDecoder(bytes.NewReader(source))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		if strings.HasPrefix(err.Error(), "json: unknown field ") {
			return ErrUnknownField
		}
		return ErrInvalidDocument
	}
	if err := requireEOF(decoder); err != nil {
		return err
	}
	return nil
}

// DecodeObjectBytes is the byte-slice form of DecodeObject.
func DecodeObjectBytes(source []byte, maximumBytes int64, destination any) error {
	return DecodeObject(bytes.NewReader(source), maximumBytes, destination)
}

func inspectObject(source []byte, destination reflect.Type) error {
	decoder := json.NewDecoder(bytes.NewReader(source))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil {
		return ErrInvalidDocument
	}
	delimiter, ok := token.(json.Delim)
	if !ok || delimiter != '{' {
		return ErrInvalidDocument
	}
	if err := inspectMembers(decoder, 1, destination); err != nil {
		return err
	}
	return requireEOF(decoder)
}

func inspectMembers(decoder *json.Decoder, depth int, destination reflect.Type) error {
	seen := make(map[string]struct{})
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return ErrInvalidDocument
		}
		name, ok := token.(string)
		if !ok {
			return ErrInvalidDocument
		}
		if _, duplicate := seen[name]; duplicate {
			return ErrDuplicateField
		}
		seen[name] = struct{}{}
		member, err := memberType(destination, name)
		if err != nil {
			return err
		}
		if err := inspectValue(decoder, depth, member); err != nil {
			return err
		}
	}
	token, err := decoder.Token()
	if err != nil || token != json.Delim('}') {
		return ErrInvalidDocument
	}
	return nil
}

func inspectValue(decoder *json.Decoder, depth int, destination reflect.Type) error {
	token, err := decoder.Token()
	if err != nil {
		return ErrInvalidDocument
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	if depth >= MaximumDepth {
		return ErrDocumentTooDeep
	}
	switch delimiter {
	case '{':
		return inspectMembers(decoder, depth+1, destination)
	case '[':
		destination = indirectType(destination)
		var element reflect.Type
		if destination != nil && (destination.Kind() == reflect.Slice || destination.Kind() == reflect.Array) {
			element = destination.Elem()
		}
		for decoder.More() {
			if err := inspectValue(decoder, depth+1, element); err != nil {
				return err
			}
		}
		token, err := decoder.Token()
		if err != nil || token != json.Delim(']') {
			return ErrInvalidDocument
		}
		return nil
	default:
		return ErrInvalidDocument
	}
}

// Matrix contracts declare their JSON fields explicitly. Checking those names
// before decoding prevents encoding/json's case-insensitive fallback from
// treating e.g. "tenantId" and "TenantId" as two assignments to one field.
// Map keys and raw JSON remain case-sensitive data, not struct properties.
func memberType(destination reflect.Type, name string) (reflect.Type, error) {
	destination = indirectType(destination)
	if destination == nil {
		return nil, nil
	}
	if destination.Kind() == reflect.Map {
		return destination.Elem(), nil
	}
	if destination.Kind() != reflect.Struct || reflect.PointerTo(destination).Implements(reflect.TypeFor[json.Unmarshaler]()) {
		return nil, nil
	}
	for index := 0; index < destination.NumField(); index++ {
		field := destination.Field(index)
		if !field.IsExported() {
			continue
		}
		fieldName, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		if fieldName == "-" {
			continue
		}
		if fieldName == "" {
			fieldName = field.Name
		}
		if name == fieldName {
			return field.Type, nil
		}
	}
	return nil, ErrUnknownField
}

func indirectType(value reflect.Type) reflect.Type {
	for value != nil && value.Kind() == reflect.Pointer {
		value = value.Elem()
	}
	return value
}

func requireEOF(decoder *json.Decoder) error {
	if _, err := decoder.Token(); errors.Is(err, io.EOF) {
		return nil
	} else if err == nil {
		return ErrTrailingData
	}
	return ErrInvalidDocument
}

func writablePointer(value any) bool {
	if value == nil {
		return false
	}
	reflected := reflect.ValueOf(value)
	return reflected.Kind() == reflect.Pointer && !reflected.IsNil()
}
