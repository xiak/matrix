package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"reflect"
	"strings"

	"github.com/xiak/matrix/api/internal/openapi31"
	managedservicev1 "github.com/xiak/matrix/api/managedservice/v1"
)

type object = openapi31.Object

func main() {
	output := flag.String("output", "", "output path")
	flag.Parse()
	if *output == "" {
		fatalf("output is required")
	}
	encoded, err := json.MarshalIndent(buildDocument(), "", "  ")
	if err != nil {
		fatalf("encode OpenAPI: %v", err)
	}
	encoded = append(encoded, '\n')
	if err := os.WriteFile(*output, encoded, 0o644); err != nil {
		fatalf("write OpenAPI: %v", err)
	}
}

func buildDocument() object {
	document := openapi31.Build(openapi31.Options{
		Title: "Matrix Managed Service API", Version: "v1",
		Security: []any{object{"bearerAuth": []any{}}},
		Paths:    paths(),
		SecuritySchemes: object{
			"bearerAuth": object{"type": "http", "scheme": "bearer"},
		},
		Parameters: object{
			"IdempotencyKey": object{
				"name": "Idempotency-Key", "in": "header", "required": true,
				"schema": openapi31.Ref("ID"),
			},
			"OfferingID":         openapi31.PathIDParameter("offeringId"),
			"RegionID":           openapi31.PathIDParameter("regionId"),
			"QuotaEntitlementID": openapi31.PathIDParameter("quotaEntitlementId"),
			"InstallationID": object{
				"name": "installationId", "in": "path", "required": true,
				"schema": openapi31.Ref("Name"),
			},
		},
		Responses: object{
			"ProblemResponse": object{
				"description": "Normalized managed-service problem.",
				"content":     object{"application/problem+json": object{"schema": openapi31.Ref("Problem")}},
			},
		},
		Scalars: object{
			"ID": object{
				"type": "string", "minLength": 1, "maxLength": 128,
				"pattern": `^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`,
			},
			"Name": object{
				"type": "string", "minLength": 2, "maxLength": 63,
				"pattern": `^[a-z0-9](?:[a-z0-9._-]{0,61}[a-z0-9])?$`,
			},
			"Timestamp": object{
				"type": "string", "format": "date-time",
				"pattern": `^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z$`,
			},
		},
		Enums: map[string][]string{
			"OfferingKind":      {string(managedservicev1.OfferingPostgreSQL)},
			"OfferingState":     {string(managedservicev1.OfferingAvailable), string(managedservicev1.OfferingUnavailable)},
			"RegionProfile":     {string(managedservicev1.RegionLocalMachine)},
			"RegionState":       {string(managedservicev1.RegionReady), string(managedservicev1.RegionStale), string(managedservicev1.RegionUnavailable)},
			"InstallationPhase": {string(managedservicev1.InstallationPending), string(managedservicev1.InstallationProvisioning), string(managedservicev1.InstallationReady), string(managedservicev1.InstallationFailed)},
			"ErrorCode": {
				string(managedservicev1.ErrorInvalidArgument), string(managedservicev1.ErrorUnauthenticated),
				string(managedservicev1.ErrorPermissionDenied), string(managedservicev1.ErrorIdentityUnavailable),
				string(managedservicev1.ErrorNotFound), string(managedservicev1.ErrorAlreadyExists),
				string(managedservicev1.ErrorIdempotencyConflict), string(managedservicev1.ErrorQuotaExhausted),
				string(managedservicev1.ErrorRegionUnavailable), string(managedservicev1.ErrorInternal),
			},
		},
		Structs: structs(), FieldOverlay: fieldOverlay, SchemaOverlay: schemaOverlay,
	})
	document["servers"] = []any{object{"url": "/managed-services"}}
	return document
}

func paths() object {
	return object{
		"/v1/offerings": object{
			"get": readOperation("listServiceOfferings", "List the closed service catalog.", "ServiceOfferingList"),
		},
		"/v1/offerings/{offeringId}": object{
			"get": readResourceOperation("getServiceOffering", "Read one closed service offering.", "OfferingID", "ServiceOffering"),
		},
		"/v1/regions": object{
			"get": readOperation("listRegions", "List eligible operator-owned regions.", "RegionList"),
		},
		"/v1/regions/{regionId}": object{
			"get": readResourceOperation("getRegion", "Read one eligible operator-owned region.", "RegionID", "Region"),
		},
		"/v1/quota-entitlements": object{
			"get":  readOperation("listQuotaEntitlements", "List organization quota entitlements.", "QuotaEntitlementList"),
			"post": mutationOperation("activateQuota", "Activate a bounded product entitlement.", "ActivateQuotaRequest", "QuotaEntitlement", "201"),
		},
		"/v1/quota-entitlements/{quotaEntitlementId}": object{
			"get": readResourceOperation("getQuotaEntitlement", "Read one organization quota entitlement.", "QuotaEntitlementID", "QuotaEntitlement"),
		},
		"/v1/service-installations": object{
			"get":  readOperation("listServiceInstallations", "List organization service installations.", "ServiceInstallationList"),
			"post": mutationOperation("createServiceInstallation", "Reserve quota and submit an installation.", "CreateInstallationRequest", "ServiceInstallation", "202"),
		},
		"/v1/service-installations/{installationId}": object{
			"get": readResourceOperation("getServiceInstallation", "Read one organization service installation.", "InstallationID", "ServiceInstallation"),
		},
		"/v1/service-installations/{installationId}/operation": object{
			"get": readResourceOperation("getInstallationOperation", "Read the current installation Operation.", "InstallationID", "InstallationOperation"),
		},
	}
}

func readOperation(operationID, summary, responseSchema string) object {
	responses := openapi31.ProblemResponses("400", "401", "403", "500", "503", "504")
	responses["200"] = openapi31.JSONResponse("Current organization-scoped collection.", responseSchema)
	return object{"operationId": operationID, "summary": summary, "responses": responses}
}

func readResourceOperation(operationID, summary, parameter, responseSchema string) object {
	responses := openapi31.ProblemResponses("400", "401", "403", "404", "500", "503", "504")
	responses["200"] = openapi31.JSONResponse("Current organization-scoped resource.", responseSchema)
	return object{
		"operationId": operationID, "summary": summary,
		"parameters": []any{openapi31.ComponentRef("#/components/parameters/" + parameter)},
		"responses":  responses,
	}
}

func mutationOperation(operationID, summary, requestSchema, responseSchema, createdStatus string) object {
	responses := openapi31.ProblemResponses("400", "401", "403", "404", "409", "415", "500", "503", "504")
	responses["200"] = openapi31.JSONResponse("Equal idempotent replay.", responseSchema)
	responses[createdStatus] = openapi31.JSONResponse("Durable managed-service result.", responseSchema)
	return object{
		"operationId": operationID, "summary": summary,
		"parameters":  []any{openapi31.ComponentRef("#/components/parameters/IdempotencyKey")},
		"requestBody": openapi31.JSONRequestBody(requestSchema), "responses": responses,
	}
}

func structs() map[string]reflect.Type {
	return map[string]reflect.Type{
		"QuotaShape":                openapi31.StructType[managedservicev1.QuotaShape](),
		"ServiceOffering":           openapi31.StructType[managedservicev1.ServiceOffering](),
		"ServiceOfferingList":       openapi31.StructType[managedservicev1.ServiceOfferingList](),
		"RegionCapacity":            openapi31.StructType[managedservicev1.RegionCapacity](),
		"Region":                    openapi31.StructType[managedservicev1.Region](),
		"RegionList":                openapi31.StructType[managedservicev1.RegionList](),
		"QuotaEntitlement":          openapi31.StructType[managedservicev1.QuotaEntitlement](),
		"QuotaEntitlementList":      openapi31.StructType[managedservicev1.QuotaEntitlementList](),
		"InstallationOperation":     openapi31.StructType[managedservicev1.InstallationOperation](),
		"ServiceInstallation":       openapi31.StructType[managedservicev1.ServiceInstallation](),
		"ServiceInstallationList":   openapi31.StructType[managedservicev1.ServiceInstallationList](),
		"ActivateQuotaRequest":      openapi31.StructType[managedservicev1.ActivateQuotaRequest](),
		"CreateInstallationRequest": openapi31.StructType[managedservicev1.CreateInstallationRequest](),
		"FieldViolation":            openapi31.StructType[managedservicev1.FieldViolation](),
		"Problem":                   openapi31.StructType[managedservicev1.Problem](),
	}
}

func fieldOverlay(owner string, field reflect.StructField, jsonName string, base object) object {
	if (owner == "CreateInstallationRequest" || owner == "ServiceInstallation") && field.Name == "ID" {
		return openapi31.Ref("Name")
	}
	if jsonName == "id" || strings.HasSuffix(jsonName, "Id") || strings.HasSuffix(jsonName, "Reference") {
		return openapi31.Ref("ID")
	}
	if field.Name == "ResourceVersion" {
		base["minimum"] = 1
	}
	if strings.HasSuffix(field.Name, "Count") {
		base["maximum"] = 100
	}
	if field.Name == "InstanceCount" || field.Name == "PurchasedCount" {
		base["minimum"] = 1
	}
	return base
}

func schemaOverlay(schemas object) {
	for name, kind := range map[string]string{
		"ServiceOfferingList": "ServiceOfferingList", "RegionList": "RegionList",
		"QuotaEntitlementList": "QuotaEntitlementList", "ServiceInstallationList": "ServiceInstallationList",
	} {
		properties := schemas[name].(object)["properties"].(object)
		properties["kind"] = object{"const": kind}
	}
	for _, name := range []string{"ServiceOfferingList", "RegionList", "QuotaEntitlementList", "ServiceInstallationList"} {
		properties := schemas[name].(object)["properties"].(object)
		properties["items"].(object)["maxItems"] = 1000
	}
	properties := schemas["ServiceOffering"].(object)["properties"].(object)
	properties["quotaShapes"].(object)["minItems"] = 1
	properties["quotaShapes"].(object)["maxItems"] = 16
}

func fatalf(format string, arguments ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", arguments...)
	os.Exit(1)
}
