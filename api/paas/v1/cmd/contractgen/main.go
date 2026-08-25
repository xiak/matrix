// Command contractgen deterministically generates the committed OpenAPI 3.1
// document from the executable Go wire types plus explicit semantic overlays.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"reflect"
	"slices"
	"strings"
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

type schema = map[string]any

var output = flag.String("output", "openapi.json", "generated OpenAPI output path")

func main() {
	flag.Parse()
	document := buildDocument()
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		fatalf("encode OpenAPI: %v", err)
	}
	encoded = append(encoded, '\n')
	if err := os.WriteFile(*output, encoded, 0o644); err != nil {
		fatalf("write %s: %v", *output, err)
	}
}

func buildDocument() schema {
	schemas := scalarSchemas()
	for name, values := range enumSchemas() {
		schemas[name] = schema{"type": "string", "enum": values}
	}
	for name, contract := range structContracts() {
		schemas[name] = structSchema(contract)
	}
	applySemanticOverlays(schemas)

	return schema{
		"openapi": "3.1.0",
		"info": schema{
			"title":   "Matrix Application PaaS v1 contracts",
			"version": "0.1.0",
		},
		"paths": schema{},
		"components": schema{
			"parameters": schema{
				"IdempotencyKey": schema{
					"name": "Idempotency-Key", "in": "header", "required": true,
					"schema": schema{"type": "string", "minLength": 1, "maxLength": 128},
				},
				"IfMatch": schema{
					"name": "If-Match", "in": "header", "required": true,
					"schema": schema{"type": "string", "minLength": 1, "maxLength": 128},
				},
			},
			"headers": schema{
				"ETag": schema{
					"description": "Opaque resource version validator.",
					"schema":      schema{"type": "string"},
				},
			},
			"responses": schema{
				"ProblemResponse": schema{
					"description": "Normalized Matrix problem response.",
					"content": schema{
						"application/problem+json": schema{
							"schema": schema{"$ref": "#/components/schemas/Problem"},
						},
					},
				},
			},
			"schemas": schemas,
		},
	}
}

func scalarSchemas() map[string]any {
	return map[string]any{
		"ID": schema{
			"type": "string", "minLength": 1, "maxLength": 128,
			"pattern": `^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`,
		},
		"Name": schema{
			"type": "string", "minLength": 1, "maxLength": 63,
			"pattern": `^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`,
		},
		"Digest": schema{
			"type": "string", "pattern": `^sha256:[0-9a-f]{64}$`,
		},
		"Timestamp": schema{
			"type": "string", "format": "date-time",
			"pattern": `^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z$`,
		},
		"Labels": schema{
			"type": "object", "maxProperties": 64,
			"propertyNames":        schema{"$ref": "#/components/schemas/Name"},
			"additionalProperties": schema{"type": "string", "maxLength": 128},
		},
	}
}

func enumSchemas() map[string][]string {
	return map[string][]string{
		"AuthorityKind":               stringsOf(paasv1.AuthorityPlatform, paasv1.AuthorityTenant),
		"TenantStatus":                stringsOf(paasv1.TenantActive, paasv1.TenantSuspended, paasv1.TenantDeactivated),
		"ExecutionPoolPhase":          stringsOf(paasv1.ExecutionPoolReady, paasv1.ExecutionPoolDegraded, paasv1.ExecutionPoolUnavailable),
		"ExecutionTargetHealth":       stringsOf(paasv1.ExecutionTargetHealthUnknown, paasv1.ExecutionTargetHealthReady, paasv1.ExecutionTargetHealthDegraded, paasv1.ExecutionTargetHealthUnavailable),
		"ExecutionTargetDesiredState": stringsOf(paasv1.ExecutionTargetActive, paasv1.ExecutionTargetDraining),
		"IsolationGuarantee":          stringsOfSlice(paasv1.IsolationGuarantees()),
		"PlacementStrategy":           stringsOf(paasv1.PlacementFirstFit, paasv1.PlacementSpread, paasv1.PlacementBinPack),
		"PlacementOutcome":            stringsOf(paasv1.PlacementScheduled, paasv1.PlacementUnschedulable),
		"DeploymentDesiredState":      stringsOf(paasv1.DeploymentDesiredRunning, paasv1.DeploymentDesiredStopped),
		"DeploymentPhase":             stringsOfSlice(paasv1.DeploymentPhases()),
		"OperationAction":             stringsOf(paasv1.OperationCreateExecutionPool, paasv1.OperationRegisterExecutionTarget, paasv1.OperationCreatePlacement, paasv1.OperationDeploy, paasv1.OperationUpdate, paasv1.OperationStop, paasv1.OperationRollback),
		"OperationState":              stringsOfSlice(paasv1.OperationStates()),
		"EvidenceType":                stringsOf(paasv1.EvidencePolicyDecision, paasv1.EvidencePlacementDecision, paasv1.EvidenceAdapterCommand, paasv1.EvidenceAdapterResult, paasv1.EvidenceObservation, paasv1.EvidenceVerification, paasv1.EvidenceAuditDispatch),
		"EvidenceSeverity":            stringsOf(paasv1.EvidenceInfo, paasv1.EvidenceWarning, paasv1.EvidenceError),
		"SubjectType":                 stringsOf(paasv1.SubjectUser, paasv1.SubjectServiceAccount, paasv1.SubjectAgent, paasv1.SubjectSystemUser),
		"ErrorCode":                   stringsOfSlice(paasv1.ErrorCodes()),
		"AdapterKind":                 stringsOf(paasv1.AdapterInfrastructure, paasv1.AdapterDeploymentExecutor, paasv1.AdapterGateway),
		"AdapterAction":               stringsOf(paasv1.AdapterCapabilities, paasv1.AdapterInspectExecutionTarget, paasv1.AdapterObserveExecutionTarget, paasv1.AdapterValidateDeployment, paasv1.AdapterApplyDeployment, paasv1.AdapterObserveDeployment, paasv1.AdapterStopDeployment, paasv1.AdapterRollbackDeployment, paasv1.AdapterReconcileRoutes, paasv1.AdapterObserveRoutes, paasv1.AdapterDeleteRoutes),
		"AdapterResultState":          stringsOf(paasv1.AdapterResultSucceeded, paasv1.AdapterResultInProgress, paasv1.AdapterResultFailed, paasv1.AdapterResultUnknown),
		"AdapterErrorClass":           stringsOf(paasv1.AdapterErrorValidation, paasv1.AdapterErrorConflict, paasv1.AdapterErrorPermissionDenied, paasv1.AdapterErrorQuotaExceeded, paasv1.AdapterErrorRateLimited, paasv1.AdapterErrorTransient, paasv1.AdapterErrorUnavailable, paasv1.AdapterErrorTimeout, paasv1.AdapterErrorNotFound, paasv1.AdapterErrorUnknownOutcome, paasv1.AdapterErrorInternal),
		"ArtifactKind":                stringsOf(paasv1.ArtifactOCIImage, paasv1.ArtifactOCIArtifact, paasv1.ArtifactReleaseBundle),
		"InputKind":                   stringsOf(paasv1.InputConfiguration, paasv1.InputSecret),
		"InjectionMode":               stringsOf(paasv1.InjectionEnvironment, paasv1.InjectionFile),
		"EndpointProtocol":            stringsOf(paasv1.EndpointHTTP, paasv1.EndpointGRPC, paasv1.EndpointTCP),
		"EndpointVisibility":          stringsOf(paasv1.EndpointPrivate, paasv1.EndpointPublic),
	}
}

func structContracts() map[string]reflect.Type {
	values := []any{
		paasv1.ResourceScope{}, paasv1.ResourceMetadata{}, paasv1.Tenant{},
		paasv1.LabelSelector{}, paasv1.ExecutionPoolSpec{}, paasv1.ExecutionPoolStatus{}, paasv1.ExecutionPool{},
		paasv1.AdapterRef{}, paasv1.Capacity{}, paasv1.ExecutionTargetSpec{}, paasv1.ExecutionTargetStatus{}, paasv1.ExecutionTarget{},
		paasv1.PlacementPolicySpec{}, paasv1.PlacementPolicy{}, paasv1.PlacementDecision{},
		paasv1.ArtifactRef{}, paasv1.ResourceRequirements{}, paasv1.ApplicationEndpoint{}, paasv1.ComponentInput{},
		paasv1.SecretVersionReference{}, paasv1.ComponentBinding{}, paasv1.Application{}, paasv1.Configuration{},
		paasv1.ConfigurationRevisionSpec{}, paasv1.ConfigurationRevision{}, paasv1.ApplicationRevisionComponent{},
		paasv1.ApplicationRevisionSpec{}, paasv1.ApplicationRevision{}, paasv1.DeploymentComponent{}, paasv1.DeploymentSpec{},
		paasv1.DeploymentStatus{}, paasv1.Deployment{}, paasv1.DeploymentGeneration{}, paasv1.SubjectRef{}, paasv1.ResourceRef{}, paasv1.FieldViolation{},
		paasv1.Problem{}, paasv1.Operation{}, paasv1.Evidence{}, paasv1.AdapterCapabilitiesContract{},
		paasv1.AdapterCommandEnvelope{}, paasv1.InspectExecutionTargetRequest{}, paasv1.ObserveExecutionTargetRequest{},
		paasv1.DeploymentExecutionRequest{}, paasv1.ObserveDeploymentRequest{}, paasv1.DeploymentEndpointObservation{},
		paasv1.DeploymentObservation{}, paasv1.ExecutionTargetObservation{}, paasv1.NormalizedAdapterError{}, paasv1.AdapterResult{},
	}
	result := make(map[string]reflect.Type, len(values))
	for _, value := range values {
		typeOf := reflect.TypeOf(value)
		result[typeOf.Name()] = typeOf
	}
	return result
}

func structSchema(contract reflect.Type) schema {
	properties := schema{}
	required := make([]string, 0, contract.NumField())
	for index := range contract.NumField() {
		field := contract.Field(index)
		parts := strings.Split(field.Tag.Get("json"), ",")
		if len(parts) == 0 || parts[0] == "" || parts[0] == "-" {
			fatalf("%s.%s is missing a JSON contract tag", contract.Name(), field.Name)
		}
		jsonName := parts[0]
		properties[jsonName] = schemaForField(contract.Name(), field, jsonName)
		if !slices.Contains(parts[1:], "omitempty") {
			required = append(required, jsonName)
		}
	}
	result := schema{
		"type":                 "object",
		"additionalProperties": false,
		"properties":           properties,
	}
	if len(required) > 0 {
		result["required"] = required
	}
	return result
}

func schemaForField(owner string, field reflect.StructField, jsonName string) schema {
	if owner == "DeploymentEndpointObservation" &&
		(field.Name == "ComponentName" || field.Name == "EndpointName" || field.Name == "Address") {
		return ref("Name")
	}
	if field.Name == "Labels" || field.Name == "MatchLabels" {
		return ref("Labels")
	}
	if owner == "ConfigurationRevisionSpec" && field.Name == "Values" {
		return schema{
			"type": "object", "maxProperties": 256,
			"propertyNames":        schema{"pattern": `^[A-Z_][A-Z0-9_]{0,127}$`},
			"additionalProperties": schema{"type": "string", "maxLength": 32768},
		}
	}
	if owner == "Evidence" && field.Name == "Attributes" {
		return schema{
			"type": "object", "maxProperties": 64,
			"additionalProperties": schema{"type": "string", "maxLength": 4096},
		}
	}
	if field.Name == "Name" {
		return ref("Name")
	}
	if strings.HasSuffix(field.Name, "Digest") || strings.HasSuffix(field.Name, "Fingerprint") {
		return ref("Digest")
	}
	if field.Name == "ContractVersion" {
		return schema{"type": "string", "pattern": `^v[1-9][0-9]*$`}
	}
	return schemaForType(field.Type, jsonName)
}

func schemaForType(contract reflect.Type, jsonName string) schema {
	if contract == reflect.TypeOf(time.Time{}) {
		return ref("Timestamp")
	}
	if contract.Kind() == reflect.Pointer {
		return schemaForType(contract.Elem(), jsonName)
	}
	if contract.PkgPath() != "" && contract.Name() != "" {
		switch contract.Name() {
		case "TenantID", "ResourceID", "OperationID", "CommandID":
			return ref("ID")
		}
		if contract.Kind() == reflect.Struct || contract.Kind() == reflect.String {
			return ref(contract.Name())
		}
	}
	switch contract.Kind() {
	case reflect.String:
		if jsonName == "id" || strings.HasSuffix(jsonName, "Id") {
			return ref("ID")
		}
		return schema{"type": "string"}
	case reflect.Bool:
		return schema{"type": "boolean"}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return schema{"type": "integer", "minimum": 0, "maximum": 9007199254740991}
	case reflect.Uint16:
		return schema{"type": "integer", "minimum": 0, "maximum": 65535}
	case reflect.Uint32:
		return schema{"type": "integer", "minimum": 0, "maximum": 4294967295}
	case reflect.Uint, reflect.Uint64:
		return schema{"type": "integer", "minimum": 0, "maximum": 9007199254740991}
	case reflect.Slice:
		return schema{"type": "array", "items": schemaForType(contract.Elem(), jsonName)}
	case reflect.Map:
		return schema{"type": "object", "additionalProperties": schemaForType(contract.Elem(), jsonName)}
	default:
		fatalf("unsupported Go contract type %s", contract)
		return nil
	}
}

func applySemanticOverlays(schemas map[string]any) {
	resourceKinds := map[string]string{
		"Application": "Application", "Configuration": "Configuration",
		"ConfigurationRevision": "ConfigurationRevision", "ApplicationRevision": "ApplicationRevision",
		"Deployment": "Deployment", "DeploymentGeneration": "DeploymentGeneration",
		"ExecutionPool": "ExecutionPool", "ExecutionTarget": "ExecutionTarget",
		"PlacementPolicy": "PlacementPolicy", "PlacementDecision": "PlacementDecision",
		"Operation": "Operation", "Evidence": "Evidence",
	}
	for name, kind := range resourceKinds {
		properties := object(schemas[name])["properties"].(schema)
		if _, found := properties["apiVersion"]; found {
			properties["apiVersion"] = schema{"const": paasv1.APIVersion}
		}
		if _, found := properties["kind"]; found {
			properties["kind"] = schema{"const": kind}
		}
	}

	for _, name := range []string{"ConfigurationRevisionSpec", "ApplicationRevisionSpec", "DeploymentGeneration", "PlacementDecision"} {
		object(schemas[name])["x-matrix-immutable"] = true
	}
	for _, name := range []string{
		"AdapterCapabilitiesContract", "AdapterCommandEnvelope", "InspectExecutionTargetRequest",
		"ObserveExecutionTargetRequest", "DeploymentExecutionRequest", "ObserveDeploymentRequest",
		"DeploymentEndpointObservation", "DeploymentObservation", "ExecutionTargetObservation",
		"NormalizedAdapterError", "AdapterResult",
	} {
		object(schemas[name])["x-matrix-visibility"] = "internal"
	}

	object(schemas["OperationState"])["x-matrix-terminal-values"] = stringsOf(
		paasv1.OperationSucceeded, paasv1.OperationFailed,
		paasv1.OperationCancelled, paasv1.OperationManualIntervention,
	)

	setArrayMinimum(schemas, "ExecutionPoolSpec", "allowedIsolationGuarantees", 1)
	setArrayMinimum(schemas, "ExecutionTargetStatus", "supportedIsolationGuarantees", 1)
	setArrayMinimum(schemas, "PlacementPolicySpec", "eligibleExecutionPoolIds", 1)
	setArrayMinimum(schemas, "ApplicationRevisionSpec", "components", 1)
	setArrayMinimum(schemas, "DeploymentSpec", "components", 1)
	setArrayMinimum(schemas, "AdapterCapabilitiesContract", "actions", 1)
	setIntegerMinimum(schemas, "ApplicationEndpoint", "port", 1)
	setIntegerMinimum(schemas, "DeploymentComponent", "replicas", 1)
	setIntegerMinimum(schemas, "Deployment", "generation", 1)
	setIntegerMinimum(schemas, "DeploymentGeneration", "generation", 1)
	setIntegerMinimum(schemas, "PlacementDecision", "deploymentGeneration", 1)
	setIntegerMinimum(schemas, "ObserveDeploymentRequest", "generation", 1)
	setIntegerMinimum(schemas, "DeploymentEndpointObservation", "port", 1)
	setIntegerMinimum(schemas, "DeploymentObservation", "generation", 1)

	componentBinding := object(schemas["ComponentBinding"])
	componentBinding["oneOf"] = []any{
		schema{"required": []string{"configurationRevisionId"}, "properties": schema{"secretVersion": false}},
		schema{"required": []string{"secretVersion"}, "properties": schema{"configurationRevisionId": false}},
	}

	componentInput := object(schemas["ComponentInput"])
	componentInput["allOf"] = []any{
		schema{
			"if": schema{
				"properties": schema{"kind": schema{"const": string(paasv1.InputConfiguration)}},
				"required":   []string{"kind"},
			},
			"then": schema{"properties": schema{"injection": schema{"const": string(paasv1.InjectionEnvironment)}}},
		},
		schema{
			"if": schema{
				"properties": schema{"kind": schema{"const": string(paasv1.InputSecret)}},
				"required":   []string{"kind"},
			},
			"then": schema{"properties": schema{"injection": schema{"const": string(paasv1.InjectionFile)}}},
		},
	}

	executionRequest := object(schemas["DeploymentExecutionRequest"])
	executionProperties := executionRequest["properties"].(schema)
	executionProperties["command"] = schema{"allOf": []any{
		ref("AdapterCommandEnvelope"),
		schema{"properties": schema{"action": schema{"enum": stringsOf(
			paasv1.AdapterValidateDeployment,
			paasv1.AdapterApplyDeployment,
			paasv1.AdapterStopDeployment,
			paasv1.AdapterRollbackDeployment,
		)}}},
	}}
	executionProperties["placement"] = schema{"allOf": []any{
		ref("PlacementDecision"),
		schema{"properties": schema{"outcome": schema{"const": string(paasv1.PlacementScheduled)}}},
	}}
	observeRequest := object(schemas["ObserveDeploymentRequest"])
	observeProperties := observeRequest["properties"].(schema)
	observeProperties["command"] = schema{"allOf": []any{
		ref("AdapterCommandEnvelope"),
		schema{"properties": schema{"action": schema{"const": string(paasv1.AdapterObserveDeployment)}}},
	}}

	placement := object(schemas["PlacementDecision"])
	placement["allOf"] = []any{
		schema{
			"if": schema{"properties": schema{"outcome": schema{"const": string(paasv1.PlacementScheduled)}}, "required": []string{"outcome"}},
			"then": schema{
				"required":   []string{"executionTargetId", "executionTargetResourceVersion", "grantedIsolationGuarantee"},
				"properties": schema{"reason": false},
			},
		},
		schema{
			"if": schema{"properties": schema{"outcome": schema{"const": string(paasv1.PlacementUnschedulable)}}, "required": []string{"outcome"}},
			"then": schema{
				"required": []string{"reason"},
				"properties": schema{
					"executionTargetId": false, "executionTargetResourceVersion": false,
					"grantedIsolationGuarantee": false,
				},
			},
		},
	}
}

func setArrayMinimum(schemas map[string]any, owner, property string, minimum int) {
	properties := object(schemas[owner])["properties"].(schema)
	object(properties[property])["minItems"] = minimum
	object(properties[property])["uniqueItems"] = true
}

func setIntegerMinimum(schemas map[string]any, owner, property string, minimum int) {
	properties := object(schemas[owner])["properties"].(schema)
	object(properties[property])["minimum"] = minimum
}

func object(value any) schema {
	result, ok := value.(schema)
	if !ok {
		fatalf("contract generator expected object, got %T", value)
	}
	return result
}

func ref(name string) schema {
	return schema{"$ref": "#/components/schemas/" + name}
}

func stringsOf[T ~string](values ...T) []string {
	return stringsOfSlice(values)
}

func stringsOfSlice[T ~string](values []T) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, string(value))
	}
	return result
}

func fatalf(format string, arguments ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", arguments...)
	os.Exit(1)
}
