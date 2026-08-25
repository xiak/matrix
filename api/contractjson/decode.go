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
	ErrDuplicateField   = errors.New("JSON document contains a duplicate field")
	ErrUnknownField     = errors.New("JSON document contains an unknown field")
	ErrTrailingData     = errors.New("JSON document contains trailing data")
)

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
	if err := inspectObject(source); err != nil {
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

func inspectObject(source []byte) error {
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
	if err := inspectMembers(decoder); err != nil {
		return err
	}
	return requireEOF(decoder)
}

func inspectMembers(decoder *json.Decoder) error {
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
		if err := inspectValue(decoder); err != nil {
			return err
		}
	}
	token, err := decoder.Token()
	if err != nil || token != json.Delim('}') {
		return ErrInvalidDocument
	}
	return nil
}

func inspectValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return ErrInvalidDocument
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		return inspectMembers(decoder)
	case '[':
		for decoder.More() {
			if err := inspectValue(decoder); err != nil {
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

func requireEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); errors.Is(err, io.EOF) {
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
