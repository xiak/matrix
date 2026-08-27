// Command contractgen deterministically generates the committed Audit OpenAPI
// 3.1 document from executable Go contracts and explicit semantic overlays.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"reflect"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	"github.com/xiak/matrix/api/internal/openapi31"
)

type object = openapi31.Object

var output = flag.String("output", "openapi.json", "generated OpenAPI output path")

func main() {
	flag.Parse()
	encoded, err := json.MarshalIndent(buildDocument(), "", "  ")
	if err != nil {
		fatalf("encode Audit OpenAPI: %v", err)
	}
	encoded = append(encoded, '\n')
	if err := os.WriteFile(*output, encoded, 0o644); err != nil {
		fatalf("write %s: %v", *output, err)
	}
}

func buildDocument() object {
	return openapi31.Build(openapi31.Options{
		Title:    "Matrix Audit v1 contracts",
		Version:  "0.1.0",
		Security: []any{object{"UserSession": []string{}}},
		Paths:    buildPaths(),
		SecuritySchemes: object{
			"UserSession": object{
				"type": "http", "scheme": "bearer",
				"description": "Opaque IAM user session. Audit derives tenant and subject by calling IAM.",
			},
			"ServiceCredential": object{
				"type": "http", "scheme": "bearer",
				"description": "Opaque IAM service credential that determines the Audit event source.",
			},
			"InstallationVerifier": object{
				"type": "http", "scheme": "bearer",
				"description": "Narrow installation-verifier service credential authorized by IAM installation.verify.",
			},
		},
		Responses: object{
			"ProblemResponse": object{
				"description": "Normalized RFC 9457-style Audit problem.",
				"content": object{
					"application/problem+json": object{"schema": openapi31.Ref("Problem")},
				},
			},
		},
		Scalars:       scalarSchemas(),
		Enums:         enumSchemas(),
		Structs:       structContracts(),
		FieldOverlay:  fieldOverlay,
		SchemaOverlay: applySemanticOverlays,
	})
}

func buildPaths() object {
	return object{
		"/ready": object{"get": readOperation(
			"getAuditReadiness", "Get Audit readiness", "Readiness", []any{},
		)},
		"/v1/events": object{"post": ingestOperation()},
		"/v1/records:query": object{"post": mutationOperation(
			"queryAuditRecords", "Query the IAM-derived tenant's Audit records",
			"QueryRecordsRequest", "RecordPage", "200",
			[]any{object{"UserSession": []string{}}},
		)},
		"/v1/integrity:verify": object{"post": mutationOperation(
			"verifyAuditChain", "Verify a bounded segment of the IAM-derived tenant's chain",
			"VerifyChainRequest", "ChainVerification", "200",
			[]any{object{"UserSession": []string{}}},
		)},
		"/v1/platform/records:query": object{"post": mutationOperation(
			"queryPlatformAuditRecords", "Query the IAM-derived installation's Audit records",
			"QueryRecordsRequest", "RecordPage", "200",
			[]any{object{"UserSession": []string{}}},
		)},
		"/v1/platform/integrity:verify": object{"post": mutationOperation(
			"verifyPlatformAuditChain", "Verify a bounded segment of the IAM-derived installation's chain",
			"VerifyChainRequest", "ChainVerification", "200",
			[]any{object{"UserSession": []string{}}},
		)},
		"/v1/installation:verify": object{"post": mutationOperation(
			"verifyInstallationAudit", "Verify the exact fixed PaaS probe Audit fact and chain",
			"VerifyInstallationRequest", "InstallationVerification", "200",
			[]any{object{"InstallationVerifier": []string{}}},
		)},
	}
}

func ingestOperation() object {
	responses := openapi31.ProblemResponses("400", "401", "409", "413", "415", "422", "500", "503")
	responses["200"] = openapi31.JSONResponse("Equal event replay.", "IngestionResult")
	responses["201"] = openapi31.JSONResponse("New event accepted.", "IngestionResult")
	return object{
		"operationId": "ingestAuditEvent",
		"summary":     "Ingest a sanitized event from its authenticated source",
		"security":    []any{object{"ServiceCredential": []string{}}},
		"requestBody": openapi31.JSONRequestBody("Event"),
		"responses":   responses,
	}
}

func mutationOperation(
	operationID, summary, requestSchema, responseSchema, status string,
	security []any,
) object {
	responses := openapi31.ProblemResponses("400", "401", "403", "409", "413", "415", "422", "500", "503")
	responses[status] = openapi31.JSONResponse("Command completed.", responseSchema)
	return object{
		"operationId": operationID,
		"summary":     summary,
		"security":    security,
		"requestBody": openapi31.JSONRequestBody(requestSchema),
		"responses":   responses,
	}
}

func readOperation(operationID, summary, responseSchema string, security []any) object {
	responses := openapi31.ProblemResponses("500", "503")
	responses["200"] = openapi31.JSONResponse("Current authority state.", responseSchema)
	return object{
		"operationId": operationID,
		"summary":     summary,
		"security":    security,
		"responses":   responses,
	}
}

func scalarSchemas() object {
	id := object{
		"type": "string", "minLength": 1, "maxLength": 128,
		"pattern": `^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`,
	}
	result := object{
		"Timestamp": object{
			"type": "string", "format": "date-time",
			"pattern": `^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?Z$`,
		},
		"ID": id,
		"Digest": object{
			"type": "string", "pattern": `^sha256:[0-9a-f]{64}$`,
		},
		"Cursor": object{
			"type": "string", "minLength": 64, "maxLength": 4096,
			"pattern": `^v1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}$`,
		},
	}
	for _, name := range []string{"EventID", "TenantID", "ActorID", "DecisionID", "OperationID"} {
		result[name] = object{"allOf": []any{openapi31.Ref("ID")}}
	}
	return result
}

func enumSchemas() map[string][]string {
	sources := make([]string, 0, 3)
	targets := make([]string, 0, 12)
	results := make([]string, 0, 4)
	for _, action := range auditv1.AllActions() {
		contract, known := auditv1.ContractForAction(action)
		if !known {
			panic("Audit action has no contract: " + string(action))
		}
		sources = appendUnique(sources, string(contract.Source))
		targets = appendUnique(targets, string(contract.Target))
		for _, result := range contract.Results {
			results = appendUnique(results, string(result))
		}
	}
	return map[string][]string{
		"Source":                        sources,
		"ActorType":                     {string(auditv1.ActorUser), string(auditv1.ActorServiceAccount), string(auditv1.ActorSystem)},
		"Action":                        openapi31.StringValues(auditv1.AllActions()),
		"TargetKind":                    targets,
		"Result":                        results,
		"IngestionOutcome":              {string(auditv1.IngestionAccepted), string(auditv1.IngestionDuplicate)},
		"RetentionPolicy":               {string(auditv1.RetentionIndefinite)},
		"VerificationState":             {string(auditv1.VerificationVerified)},
		"ReadinessState":                {string(auditv1.ReadinessReady), string(auditv1.ReadinessNotReady)},
		"InstallationVerificationState": {string(auditv1.InstallationVerificationPending), string(auditv1.InstallationVerificationVerified)},
	}
}

func structContracts() map[string]reflect.Type {
	return map[string]reflect.Type{
		"ActorReference":            openapi31.StructType[auditv1.ActorReference](),
		"TargetReference":           openapi31.StructType[auditv1.TargetReference](),
		"Event":                     openapi31.StructType[auditv1.Event](),
		"AuditRecord":               openapi31.StructType[auditv1.AuditRecord](),
		"IngestionResult":           openapi31.StructType[auditv1.IngestionResult](),
		"QueryRecordsRequest":       openapi31.StructType[auditv1.QueryRecordsRequest](),
		"RecordPage":                openapi31.StructType[auditv1.RecordPage](),
		"VerifyChainRequest":        openapi31.StructType[auditv1.VerifyChainRequest](),
		"ChainVerification":         openapi31.StructType[auditv1.ChainVerification](),
		"VerifyInstallationRequest": openapi31.StructType[auditv1.VerifyInstallationRequest](),
		"InstallationVerification":  openapi31.StructType[auditv1.InstallationVerification](),
		"Readiness":                 openapi31.StructType[auditv1.Readiness](),
		"Problem":                   openapi31.StructType[auditv1.Problem](),
	}
}

func fieldOverlay(owner string, field reflect.StructField, jsonName string, base object) object {
	switch jsonName {
	case "id", "requestId", "correlationId", "installationId":
		if field.Type.Kind() == reflect.String {
			base = openapi31.Ref("ID")
		}
	case "requestDigest", "contentDigest", "previousHash", "recordHash", "firstPreviousHash", "lastRecordHash":
		base = openapi31.Ref("Digest")
	case "traceparent":
		base = object{
			"type": "string", "minLength": 55, "maxLength": 55,
			"pattern": `^00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$`,
		}
	case "pageSize":
		base["minimum"] = 1
		base["maximum"] = auditv1.MaxPageSize
	case "maximumRecords", "recordCount":
		base["minimum"] = 1
		base["maximum"] = auditv1.MaxVerifyRecords
	case "sequence", "recordSequence", "fromSequence", "toSequence", "nextSequence", "schemaVersion":
		base["minimum"] = 1
	case "status":
		if owner == "Problem" {
			base["minimum"] = 400
			base["maximum"] = 599
		}
	case "type":
		if owner == "Problem" {
			base["format"] = "uri"
		}
	}
	return base
}

func applySemanticOverlays(schemas object) {
	kinds := map[string]string{
		"Event": "AuditEvent", "AuditRecord": "AuditRecord",
		"IngestionResult": "IngestionResult", "RecordPage": "AuditRecordPage",
		"ChainVerification": "ChainVerification", "Readiness": "Readiness",
		"InstallationVerification": "InstallationVerification",
	}
	for owner, kind := range kinds {
		properties := schemas[owner].(object)["properties"].(object)
		if _, exists := properties["apiVersion"]; exists {
			properties["apiVersion"] = object{"const": auditv1.APIVersion}
		}
		properties["kind"] = object{"const": kind}
	}

	eventRules, recordRules := actionRules()
	schemas["Event"].(object)["allOf"] = eventRules
	schemas["AuditRecord"].(object)["allOf"] = recordRules
	schemas["RecordPage"].(object)["properties"].(object)["records"].(object)["maxItems"] = auditv1.MaxPageSize

	verification := schemas["ChainVerification"].(object)
	verification["allOf"] = []any{
		object{
			"if":   object{"properties": object{"complete": object{"const": true}}, "required": []string{"complete"}},
			"then": object{"properties": object{"nextSequence": false}},
		},
		object{
			"if":   object{"properties": object{"complete": object{"const": false}}, "required": []string{"complete"}},
			"then": object{"required": []string{"nextSequence"}},
		},
	}
	for _, owner := range []string{"RecordPage", "ChainVerification"} {
		schemas[owner].(object)["oneOf"] = []any{
			object{"required": []string{"tenantId"}, "properties": object{"installationId": false}},
			object{"required": []string{"installationId"}, "properties": object{"tenantId": false}},
		}
	}

	installation := schemas["InstallationVerification"].(object)
	installation["allOf"] = []any{
		object{
			"if": object{
				"properties": object{"state": object{"const": string(auditv1.InstallationVerificationPending)}},
				"required":   []string{"state"},
			},
			"then": object{"properties": object{
				"eventId": false, "iamDecisionId": false, "recordSequence": false,
				"fromSequence": false, "toSequence": false, "recordHash": false,
			}},
		},
		object{
			"if": object{
				"properties": object{"state": object{"const": string(auditv1.InstallationVerificationVerified)}},
				"required":   []string{"state"},
			},
			"then": object{"required": []string{
				"eventId", "iamDecisionId", "recordSequence", "fromSequence", "toSequence", "recordHash",
			}},
		},
	}
}

func actionRules() (eventRules []any, recordRules []any) {
	for _, action := range auditv1.AllActions() {
		contract, known := auditv1.ContractForAction(action)
		if !known {
			panic("Audit action has no contract: " + string(action))
		}
		thenProperties := object{
			"target": object{
				"properties": object{"kind": object{"const": string(contract.Target)}},
				"required":   []string{"kind"},
			},
			"result": object{"enum": openapi31.StringValues(contract.Results)},
		}
		thenRequired := []string{}
		target := thenProperties["target"].(object)
		if action == auditv1.ActionIAMTenantAdministratorRecovered {
			target["required"] = []string{"kind", "tenantId"}
		} else {
			target["properties"].(object)["tenantId"] = false
		}
		if contract.PlatformOnly {
			thenRequired = append(thenRequired, "installationId")
			thenProperties["tenantId"] = false
			thenProperties["actor"] = object{"properties": object{"type": object{"const": string(auditv1.ActorUser)}}}
		} else {
			thenRequired = append(thenRequired, "tenantId")
			thenProperties["installationId"] = false
		}
		if contract.IAMDecisionRequired {
			thenRequired = append(thenRequired, "iamDecisionId")
		} else if !contract.IAMDecisionPermitted {
			thenProperties["iamDecisionId"] = false
		}
		if contract.OperationRequired {
			thenRequired = append(thenRequired, "operationId")
		} else {
			thenProperties["operationId"] = false
		}
		then := object{"properties": thenProperties}
		if len(thenRequired) > 0 {
			then["required"] = thenRequired
		}
		eventRules = append(eventRules, object{
			"if": object{
				"properties": object{"action": object{"const": string(action)}},
				"required":   []string{"action"},
			},
			"then": then,
		})
		recordRules = append(recordRules, object{
			"if": object{
				"properties": object{
					"event": object{
						"properties": object{"action": object{"const": string(action)}},
						"required":   []string{"action"},
					},
				},
				"required": []string{"event"},
			},
			"then": object{
				"properties": object{"source": object{"const": string(contract.Source)}},
			},
		})
	}
	return eventRules, recordRules
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func fatalf(format string, arguments ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", arguments...)
	os.Exit(1)
}
