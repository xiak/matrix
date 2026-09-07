// Command contractgen deterministically generates the committed installation
// OpenAPI 3.1 document from executable Go contracts and semantic overlays.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"reflect"

	installationv1 "github.com/xiak/matrix/api/installation/v1"
	"github.com/xiak/matrix/api/internal/openapi31"
)

type object = openapi31.Object

var output = flag.String("output", "openapi.json", "generated OpenAPI output path")

func main() {
	flag.Parse()
	encoded, err := json.MarshalIndent(buildDocument(), "", "  ")
	if err != nil {
		fatalf("encode installation OpenAPI: %v", err)
	}
	encoded = append(encoded, '\n')
	if err := os.WriteFile(*output, encoded, 0o644); err != nil {
		fatalf("write %s: %v", *output, err)
	}
}

func buildDocument() object {
	return openapi31.Build(openapi31.Options{
		Title:    "Matrix Installation v1 contracts",
		Version:  "0.1.0",
		Security: []any{object{"UserSession": []string{}}},
		Paths: object{
			"/ready": object{"get": readOperation(
				"getInstallationReadiness", "Get installation discovery readiness",
				"Readiness", []any{},
			)},
			"/v1/installed-products": object{"get": readOperation(
				"listInstalledProducts", "List authorized installed products",
				"InstalledProductList", []any{object{"UserSession": []string{}}},
			)},
		},
		SecuritySchemes: object{
			"UserSession": object{
				"type": "http", "scheme": "bearer",
				"description": "Opaque IAM user session credential.",
			},
		},
		Responses: object{
			"ProblemResponse": object{
				"description": "Normalized RFC 9457-style installation problem.",
				"content": object{
					"application/problem+json": object{"schema": openapi31.Ref("Problem")},
				},
			},
		},
		Scalars: object{
			"Timestamp": object{
				"type": "string", "format": "date-time",
				"pattern": `^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?Z$`,
			},
		},
		Enums: map[string][]string{
			"ProductID":     openapi31.StringValues(installationv1.AllProductIDs()),
			"ProductState":  openapi31.StringValues(installationv1.AllProductStates()),
			"ProductReason": openapi31.StringValues(installationv1.AllProductReasons()),
			"ReadinessState": {
				string(installationv1.ReadinessReady),
				string(installationv1.ReadinessNotReady),
			},
		},
		Structs: map[string]reflect.Type{
			"InstalledProduct":     openapi31.StructType[installationv1.InstalledProduct](),
			"InstalledProductList": openapi31.StructType[installationv1.InstalledProductList](),
			"Readiness":            openapi31.StructType[installationv1.Readiness](),
			"Problem":              openapi31.StructType[installationv1.Problem](),
		},
		FieldOverlay:  fieldOverlay,
		SchemaOverlay: applySemanticOverlays,
	})
}

func readOperation(
	operationID string,
	summary string,
	responseSchema string,
	security []any,
) object {
	responses := openapi31.ProblemResponses("401", "403", "500", "503")
	responses["200"] = openapi31.JSONResponse("Current installation state.", responseSchema)
	operation := object{
		"operationId": operationID,
		"summary":     summary,
		"responses":   responses,
	}
	if security != nil {
		operation["security"] = security
	}
	return operation
}

func fieldOverlay(owner string, field reflect.StructField, jsonName string, base object) object {
	switch jsonName {
	case "version", "releaseVersion":
		base = object{
			"type":    "string",
			"pattern": `^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z](?:[0-9A-Za-z.-]{0,62}[0-9A-Za-z])?)?$`,
		}
	case "releaseId":
		base = object{
			"type":    "string",
			"pattern": `^matrix-v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z](?:[0-9A-Za-z.-]{0,62}[0-9A-Za-z])?)?-[0-9a-f]{12}$`,
		}
	case "routeKey":
		base["minLength"] = 1
		base["maxLength"] = 32
	case "status":
		base["minimum"] = 400
		base["maximum"] = 599
	case "title":
		base["minLength"] = 1
		base["maxLength"] = 160
	case "detail":
		base["minLength"] = 1
		base["maxLength"] = 512
	case "requestId":
		base["minLength"] = 1
		base["maxLength"] = 128
	case "type":
		if owner == "Problem" {
			base["format"] = "uri"
			base["pattern"] = `^https://errors\.matrix\.xiak\.com/`
		}
	case "code":
		base["pattern"] = `^[a-z][a-z0-9.]{2,127}$`
	}
	return base
}

func applySemanticOverlays(schemas object) {
	kinds := map[string]string{
		"InstalledProductList": "InstalledProductList",
		"Readiness":            "Readiness",
	}
	for owner, kind := range kinds {
		properties := schemas[owner].(object)["properties"].(object)
		properties["apiVersion"] = object{"const": installationv1.APIVersion}
		properties["kind"] = object{"const": kind}
	}

	product := schemas["InstalledProduct"].(object)
	product["allOf"] = []any{
		object{
			"if": object{
				"properties": object{"id": object{"const": string(installationv1.ProductApplicationPaaS)}},
				"required":   []string{"id"},
			},
			"then": object{"properties": object{"routeKey": object{"const": "paas"}}},
		},
		object{
			"if": object{
				"properties": object{"id": object{"const": string(installationv1.ProductDevOps)}},
				"required":   []string{"id"},
			},
			"then": object{"properties": object{"routeKey": object{"const": "devops"}}},
		},
		object{
			"if": object{
				"properties": object{"state": object{"const": string(installationv1.ProductReady)}},
				"required":   []string{"state"},
			},
			"then": object{"properties": object{"reason": false}},
		},
		object{
			"if": object{
				"properties": object{
					"state": object{"enum": []string{
						string(installationv1.ProductDegraded),
						string(installationv1.ProductUnavailable),
					}},
				},
				"required": []string{"state"},
			},
			"then": object{"required": []string{"reason"}},
		},
	}

	listProperties := schemas["InstalledProductList"].(object)["properties"].(object)
	listProperties["products"] = object{
		"type":        "array",
		"items":       openapi31.Ref("InstalledProduct"),
		"minItems":    1,
		"maxItems":    installationv1.MaxProducts,
		"uniqueItems": true,
	}

	readiness := schemas["Readiness"].(object)
	readiness["allOf"] = []any{
		object{
			"if": object{
				"properties": object{"state": object{"const": string(installationv1.ReadinessReady)}},
				"required":   []string{"state"},
			},
			"then": object{"required": []string{"releaseId"}},
		},
		object{
			"if": object{
				"properties": object{"state": object{"const": string(installationv1.ReadinessNotReady)}},
				"required":   []string{"state"},
			},
			"then": object{"properties": object{"releaseId": false}},
		},
	}
}

func fatalf(format string, values ...any) {
	_, _ = fmt.Fprintf(os.Stderr, format+"\n", values...)
	os.Exit(1)
}
