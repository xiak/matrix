// Package openapi31 contains the small deterministic reflection layer shared
// by Matrix API contract generators. Runtime services do not import it.
package openapi31

import (
	"reflect"
	"slices"
	"strings"
	"time"
)

type Object map[string]any

type FieldOverlay func(owner string, field reflect.StructField, jsonName string, base Object) Object

type Options struct {
	Title           string
	Version         string
	Security        []any
	Paths           Object
	SecuritySchemes Object
	Parameters      Object
	Headers         Object
	Responses       Object
	Scalars         Object
	Enums           map[string][]string
	Structs         map[string]reflect.Type
	FieldOverlay    FieldOverlay
	SchemaOverlay   func(Object)
}

func Build(options Options) Object {
	schemas := Object{}
	for name, value := range options.Scalars {
		schemas[name] = value
	}
	for name, values := range options.Enums {
		schemas[name] = Object{"type": "string", "enum": append([]string(nil), values...)}
	}
	registry := make(map[string]struct{}, len(options.Scalars)+len(options.Enums)+len(options.Structs))
	for name := range schemas {
		registry[name] = struct{}{}
	}
	for name := range options.Structs {
		registry[name] = struct{}{}
	}
	for name, contract := range options.Structs {
		schemas[name] = structSchema(name, contract, registry, options.FieldOverlay)
	}
	if options.SchemaOverlay != nil {
		options.SchemaOverlay(schemas)
	}
	components := Object{
		"securitySchemes": options.SecuritySchemes,
		"schemas":         schemas,
	}
	if len(options.Parameters) > 0 {
		components["parameters"] = options.Parameters
	}
	if len(options.Headers) > 0 {
		components["headers"] = options.Headers
	}
	if len(options.Responses) > 0 {
		components["responses"] = options.Responses
	}
	return Object{
		"openapi": "3.1.0",
		"info": Object{
			"title": options.Title, "version": options.Version,
		},
		"security":   options.Security,
		"paths":      options.Paths,
		"components": components,
	}
}

func Ref(name string) Object {
	return Object{"$ref": "#/components/schemas/" + name}
}

func ComponentRef(path string) Object {
	return Object{"$ref": path}
}

func JSONRequestBody(schemaName string) Object {
	return Object{
		"required": true,
		"content": Object{
			"application/json": Object{"schema": Ref(schemaName)},
		},
	}
}

func JSONResponse(description, schemaName string) Object {
	return Object{
		"description": description,
		"content": Object{
			"application/json": Object{"schema": Ref(schemaName)},
		},
	}
}

func ProblemResponses(statuses ...string) Object {
	responses := Object{}
	for _, status := range statuses {
		responses[status] = ComponentRef("#/components/responses/ProblemResponse")
	}
	return responses
}

func PathIDParameter(name string) Object {
	return Object{
		"name": name, "in": "path", "required": true,
		"schema": Object{
			"type": "string", "minLength": 1, "maxLength": 128,
			"pattern": `^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`,
		},
	}
}

func StringValues[T ~string](values []T) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = string(value)
	}
	return result
}

func StructType[T any]() reflect.Type {
	return reflect.TypeOf((*T)(nil)).Elem()
}

func structSchema(
	owner string,
	contract reflect.Type,
	registry map[string]struct{},
	overlay FieldOverlay,
) Object {
	if contract.Kind() != reflect.Struct {
		panic("OpenAPI struct contract is not a struct: " + owner)
	}
	properties := Object{}
	required := make([]string, 0, contract.NumField())
	for index := range contract.NumField() {
		field := contract.Field(index)
		if field.PkgPath != "" {
			continue
		}
		jsonName, omitted, optional := jsonField(field)
		if omitted {
			continue
		}
		base := schemaForType(field.Type, registry)
		if overlay != nil {
			base = overlay(owner, field, jsonName, base)
		}
		properties[jsonName] = base
		if !optional {
			required = append(required, jsonName)
		}
	}
	slices.Sort(required)
	result := Object{
		"type":                 "object",
		"additionalProperties": false,
		"properties":           properties,
	}
	if len(required) > 0 {
		result["required"] = required
	}
	return result
}

func jsonField(field reflect.StructField) (name string, omitted bool, optional bool) {
	tag := field.Tag.Get("json")
	parts := strings.Split(tag, ",")
	name = parts[0]
	if name == "-" {
		return "", true, true
	}
	if name == "" {
		name = field.Name
	}
	for _, option := range parts[1:] {
		if option == "omitempty" || option == "omitzero" {
			optional = true
		}
	}
	if field.Type.Kind() == reflect.Pointer {
		optional = true
	}
	return name, false, optional
}

func schemaForType(contract reflect.Type, registry map[string]struct{}) Object {
	if contract == reflect.TypeOf(time.Time{}) {
		return Ref("Timestamp")
	}
	if contract.Kind() == reflect.Pointer {
		return schemaForType(contract.Elem(), registry)
	}
	if contract.PkgPath() != "" && contract.Name() != "" {
		if _, exists := registry[contract.Name()]; exists {
			return Ref(contract.Name())
		}
	}
	switch contract.Kind() {
	case reflect.String:
		return Object{"type": "string"}
	case reflect.Bool:
		return Object{"type": "boolean"}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return Object{"type": "integer", "minimum": 0, "maximum": 9007199254740991}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return Object{"type": "integer", "minimum": 0, "maximum": 9007199254740991}
	case reflect.Slice:
		return Object{"type": "array", "items": schemaForType(contract.Elem(), registry)}
	default:
		panic("unsupported OpenAPI contract type: " + contract.String())
	}
}
