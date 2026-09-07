// Command contractgen deterministically generates the committed Matrix DevOps
// OpenAPI 3.1 document from executable Go contracts and semantic overlays.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"reflect"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/api/internal/openapi31"
)

type object = openapi31.Object

var output = flag.String("output", "openapi.json", "generated OpenAPI output path")

func main() {
	flag.Parse()
	encoded, err := json.MarshalIndent(buildDocument(), "", "  ")
	if err != nil {
		fatalf("encode DevOps OpenAPI: %v", err)
	}
	encoded = append(encoded, '\n')
	if err := os.WriteFile(*output, encoded, 0o644); err != nil {
		fatalf("write %s: %v", *output, err)
	}
}

func buildDocument() object {
	return openapi31.Build(openapi31.Options{
		Title:    "Matrix DevOps v1 contracts",
		Version:  "0.1.0",
		Security: []any{object{"MatrixIAM": []string{}}},
		Paths:    buildPaths(),
		SecuritySchemes: object{
			"MatrixIAM": object{
				"type": "http", "scheme": "bearer",
				"description": "Matrix IAM credential resolved by the server-side DevOps Authorizer.",
			},
		},
		Parameters: object{
			"IdempotencyKey": object{
				"name": "Idempotency-Key", "in": "header", "required": true,
				"schema": object{"type": "string", "minLength": 1, "maxLength": 128},
			},
			"IfMatch": object{
				"name": "If-Match", "in": "header", "required": true,
				"description": "Strong ETag containing the current positive resourceVersion.",
				"schema": object{
					"type": "string", "minLength": 3, "maxLength": 22,
					"pattern": `^"[1-9][0-9]*"$`,
				},
			},
		},
		Headers: object{
			"ETag": object{
				"description": "Strong validator for the returned resource representation.",
				"schema":      object{"type": "string"},
			},
			"Location": object{
				"description": "Canonical URI of the created resource.",
				"schema":      object{"type": "string"},
			},
		},
		Responses: object{
			"ProblemResponse": object{
				"description": "Normalized RFC 9457-style DevOps problem.",
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
			"TenantID":   opaqueIDSchema(),
			"ResourceID": opaqueIDSchema(),
		},
		Enums: map[string][]string{
			"TriggerPolicy":           openapi31.StringValues(devopsv1.TriggerPolicies()),
			"VerificationProfile":     openapi31.StringValues(devopsv1.VerificationProfiles()),
			"ExecutorProfile":         openapi31.StringValues(devopsv1.ExecutorProfiles()),
			"DependencyEgressPolicy":  openapi31.StringValues(devopsv1.DependencyEgressPolicies()),
			"ReporterPolicy":          openapi31.StringValues(devopsv1.ReporterPolicies()),
			"VerificationStepKind":    openapi31.StringValues(devopsv1.VerificationStepKinds()),
			"SubjectKind":             openapi31.StringValues(devopsv1.SubjectKinds()),
			"SourceConnectionHealth":  openapi31.StringValues(devopsv1.SourceConnectionHealthStates()),
			"RepositoryBindingHealth": openapi31.StringValues(devopsv1.RepositoryBindingHealthStates()),
			"ReadinessState":          openapi31.StringValues(devopsv1.ReadinessStates()),
			"ChangeAction":            openapi31.StringValues(devopsv1.ChangeActions()),
			"PipelineRunState":        openapi31.StringValues(devopsv1.PipelineRunStates()),
			"PipelineRunStage":        openapi31.StringValues(devopsv1.PipelineRunStages()),
			"PipelineRunReason":       openapi31.StringValues(devopsv1.PipelineRunReasons()),
			"ErrorCode":               openapi31.StringValues(devopsv1.ErrorCodes()),
		},
		Structs: map[string]reflect.Type{
			"ResourceScope":                  openapi31.StructType[devopsv1.ResourceScope](),
			"ResourceMetadata":               openapi31.StructType[devopsv1.ResourceMetadata](),
			"DevOpsProject":                  openapi31.StructType[devopsv1.DevOpsProject](),
			"CreateDevOpsProjectRequest":     openapi31.StructType[devopsv1.CreateDevOpsProjectRequest](),
			"SourceConnectionSpec":           openapi31.StructType[devopsv1.SourceConnectionSpec](),
			"SourceConnectionStatus":         openapi31.StructType[devopsv1.SourceConnectionStatus](),
			"SourceConnection":               openapi31.StructType[devopsv1.SourceConnection](),
			"CreateSourceConnectionRequest":  openapi31.StructType[devopsv1.CreateSourceConnectionRequest](),
			"UpdateSourceConnectionRequest":  openapi31.StructType[devopsv1.UpdateSourceConnectionRequest](),
			"RepositoryBindingSpec":          openapi31.StructType[devopsv1.RepositoryBindingSpec](),
			"RepositoryBindingStatus":        openapi31.StructType[devopsv1.RepositoryBindingStatus](),
			"RepositoryBinding":              openapi31.StructType[devopsv1.RepositoryBinding](),
			"CreateRepositoryBindingRequest": openapi31.StructType[devopsv1.CreateRepositoryBindingRequest](),
			"UpdateRepositoryBindingRequest": openapi31.StructType[devopsv1.UpdateRepositoryBindingRequest](),
			"PipelineDraftSpec":              openapi31.StructType[devopsv1.PipelineDraftSpec](),
			"PipelineDraft":                  openapi31.StructType[devopsv1.PipelineDraft](),
			"PipelineRevisionReference":      openapi31.StructType[devopsv1.PipelineRevisionReference](),
			"Pipeline":                       openapi31.StructType[devopsv1.Pipeline](),
			"CreatePipelineRequest":          openapi31.StructType[devopsv1.CreatePipelineRequest](),
			"UpdatePipelineDraftRequest":     openapi31.StructType[devopsv1.UpdatePipelineDraftRequest](),
			"VerificationStep":               openapi31.StructType[devopsv1.VerificationStep](),
			"VerificationLimits":             openapi31.StructType[devopsv1.VerificationLimits](),
			"PipelineRevisionSpec":           openapi31.StructType[devopsv1.PipelineRevisionSpec](),
			"SubjectRef":                     openapi31.StructType[devopsv1.SubjectRef](),
			"PipelineRevision":               openapi31.StructType[devopsv1.PipelineRevision](),
			"PipelineActivation":             openapi31.StructType[devopsv1.PipelineActivation](),
			"ChangeIdentity":                 openapi31.StructType[devopsv1.ChangeIdentity](),
			"SourceEventSpec":                openapi31.StructType[devopsv1.SourceEventSpec](),
			"SourceEvent":                    openapi31.StructType[devopsv1.SourceEvent](),
			"PipelineRunInput":               openapi31.StructType[devopsv1.PipelineRunInput](),
			"PipelineRunStatus":              openapi31.StructType[devopsv1.PipelineRunStatus](),
			"PipelineRun":                    openapi31.StructType[devopsv1.PipelineRun](),
			"Readiness":                      openapi31.StructType[devopsv1.Readiness](),
			"FieldViolation":                 openapi31.StructType[devopsv1.FieldViolation](),
			"Problem":                        openapi31.StructType[devopsv1.Problem](),
		},
		FieldOverlay:  fieldOverlay,
		SchemaOverlay: applySemanticOverlays,
	})
}

func buildPaths() object {
	return object{
		"/ready": object{
			"get": object{
				"operationId": "getDevOpsReadiness",
				"summary":     "Get DevOps readiness",
				"security":    []any{},
				"responses": object{
					"200": response("DevOps is ready.", "Readiness", nil),
					"400": openapi31.ComponentRef("#/components/responses/ProblemResponse"),
					"405": openapi31.ComponentRef("#/components/responses/ProblemResponse"),
					"503": openapi31.ComponentRef("#/components/responses/ProblemResponse"),
				},
			},
		},
		"/v1/projects": object{
			"post": createOperation(
				"createDevOpsProject", "Create a DevOps project",
				"CreateDevOpsProjectRequest", "DevOpsProject",
			),
		},
		"/v1/projects/{projectId}": object{
			"get": readOperation(
				"getDevOpsProject", "Get a DevOps project", "projectId", "DevOpsProject",
			),
		},
		"/v1/source-connections": object{
			"post": createOperation(
				"createSourceConnection", "Create a source connection",
				"CreateSourceConnectionRequest", "SourceConnection",
			),
		},
		"/v1/source-connections/{sourceConnectionId}": object{
			"get": readOperation(
				"getSourceConnection", "Get a source connection",
				"sourceConnectionId", "SourceConnection",
			),
			"put": updateResourceOperation(
				"updateSourceConnection", "Replace source connection credential references",
				"sourceConnectionId", "UpdateSourceConnectionRequest", "SourceConnection",
			),
		},
		"/v1/repository-bindings": object{
			"post": createOperation(
				"createRepositoryBinding", "Create a repository binding",
				"CreateRepositoryBindingRequest", "RepositoryBinding",
			),
		},
		"/v1/repository-bindings/{repositoryBindingId}": object{
			"get": readOperation(
				"getRepositoryBinding", "Get a repository binding",
				"repositoryBindingId", "RepositoryBinding",
			),
			"put": updateResourceOperation(
				"updateRepositoryBinding", "Replace a repository binding specification",
				"repositoryBindingId", "UpdateRepositoryBindingRequest", "RepositoryBinding",
			),
		},
		"/v1/pipelines": object{
			"post": createOperation(
				"createPipeline", "Create a Pipeline with a mutable draft",
				"CreatePipelineRequest", "Pipeline",
			),
		},
		"/v1/pipelines/{pipelineId}": object{
			"get": readOperation("getPipeline", "Get a Pipeline", "pipelineId", "Pipeline"),
		},
		"/v1/pipelines/{pipelineId}/draft": object{
			"put": updateDraftOperation(),
		},
		"/v1/pipelines/{pipelineId}/activate": object{
			"post": activateOperation(),
		},
		"/v1/pipelines/{pipelineId}/revisions/{pipelineRevisionId}": object{
			"get": readPipelineRevisionOperation(),
		},
		"/v1/runs/{runId}": object{
			"get": readOperation(
				"getPipelineRun", "Get a PipelineRun", "runId", "PipelineRun",
			),
		},
		"/v1/runs/{runId}/cancel": object{
			"post": cancelPipelineRunOperation(),
		},
	}
}

func createOperation(operationID, summary, requestSchema, responseSchema string) object {
	responses := openapi31.ProblemResponses("400", "401", "403", "405", "409", "412", "413", "415", "422", "500", "503")
	responses["201"] = response(
		"Created resource.", responseSchema,
		object{"ETag": openapi31.ComponentRef("#/components/headers/ETag"), "Location": openapi31.ComponentRef("#/components/headers/Location")},
	)
	return object{
		"operationId": operationID,
		"summary":     summary,
		"parameters":  []any{openapi31.ComponentRef("#/components/parameters/IdempotencyKey")},
		"requestBody": openapi31.JSONRequestBody(requestSchema),
		"responses":   responses,
	}
}

func readOperation(operationID, summary, pathParameter, responseSchema string) object {
	responses := openapi31.ProblemResponses("400", "401", "403", "404", "405", "500", "503")
	responses["200"] = response(
		"Current authorized resource.", responseSchema,
		object{"ETag": openapi31.ComponentRef("#/components/headers/ETag")},
	)
	return object{
		"operationId": operationID,
		"summary":     summary,
		"parameters":  []any{openapi31.PathIDParameter(pathParameter)},
		"responses":   responses,
	}
}

func readPipelineRevisionOperation() object {
	operation := readOperation(
		"getPipelineRevision", "Get an immutable Pipeline revision",
		"pipelineRevisionId", "PipelineRevision",
	)
	operation["parameters"] = []any{
		openapi31.PathIDParameter("pipelineId"),
		openapi31.PathIDParameter("pipelineRevisionId"),
	}
	return operation
}

func updateDraftOperation() object {
	responses := openapi31.ProblemResponses("400", "401", "403", "404", "405", "409", "412", "413", "415", "422", "428", "500", "503")
	responses["200"] = response(
		"Pipeline with the updated mutable draft.", "Pipeline",
		object{"ETag": openapi31.ComponentRef("#/components/headers/ETag")},
	)
	return object{
		"operationId": "updatePipelineDraft",
		"summary":     "Replace a Pipeline draft",
		"parameters": []any{
			openapi31.PathIDParameter("pipelineId"),
			openapi31.ComponentRef("#/components/parameters/IdempotencyKey"),
			openapi31.ComponentRef("#/components/parameters/IfMatch"),
		},
		"requestBody": openapi31.JSONRequestBody("UpdatePipelineDraftRequest"),
		"responses":   responses,
	}
}

func updateResourceOperation(
	operationID, summary, pathParameter, requestSchema, responseSchema string,
) object {
	responses := openapi31.ProblemResponses("400", "401", "403", "404", "405", "409", "412", "413", "415", "422", "428", "500", "503")
	responses["200"] = response(
		"Updated resource.", responseSchema,
		object{"ETag": openapi31.ComponentRef("#/components/headers/ETag")},
	)
	return object{
		"operationId": operationID,
		"summary":     summary,
		"parameters": []any{
			openapi31.PathIDParameter(pathParameter),
			openapi31.ComponentRef("#/components/parameters/IdempotencyKey"),
			openapi31.ComponentRef("#/components/parameters/IfMatch"),
		},
		"requestBody": openapi31.JSONRequestBody(requestSchema),
		"responses":   responses,
	}
}

func activateOperation() object {
	responses := openapi31.ProblemResponses("400", "401", "403", "404", "405", "409", "412", "422", "428", "500", "503")
	responses["201"] = response(
		"Atomic Pipeline and immutable revision result.", "PipelineActivation",
		object{"ETag": openapi31.ComponentRef("#/components/headers/ETag"), "Location": openapi31.ComponentRef("#/components/headers/Location")},
	)
	return object{
		"operationId": "activatePipeline",
		"summary":     "Activate the current Pipeline draft",
		"description": "No caller body is accepted; IAM supplies the actor and If-Match selects the exact draft resource version.",
		"parameters": []any{
			openapi31.PathIDParameter("pipelineId"),
			openapi31.ComponentRef("#/components/parameters/IdempotencyKey"),
			openapi31.ComponentRef("#/components/parameters/IfMatch"),
		},
		"responses": responses,
	}
}

func cancelPipelineRunOperation() object {
	responses := openapi31.ProblemResponses(
		"400", "401", "403", "404", "405", "409", "412", "422", "428", "500", "503",
	)
	responses["200"] = response(
		"PipelineRun with its durable cancellation request.", "PipelineRun",
		object{"ETag": openapi31.ComponentRef("#/components/headers/ETag")},
	)
	return object{
		"operationId": "cancelPipelineRun",
		"summary":     "Request PipelineRun cancellation",
		"description": "No caller body is accepted. A run with a possible external effect remains nonterminal with cancellationRequestedAt until the fenced worker observes the same intent.",
		"parameters": []any{
			openapi31.PathIDParameter("runId"),
			openapi31.ComponentRef("#/components/parameters/IdempotencyKey"),
			openapi31.ComponentRef("#/components/parameters/IfMatch"),
		},
		"responses": responses,
	}
}

func response(description, schemaName string, headers object) object {
	result := object{
		"description": description,
		"content": object{
			"application/json": object{"schema": openapi31.Ref(schemaName)},
		},
	}
	if headers != nil {
		result["headers"] = headers
	}
	return result
}

func opaqueIDSchema() object {
	return object{
		"type": "string", "minLength": 1, "maxLength": 128,
		"pattern": `^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`,
	}
}

func fieldOverlay(owner string, field reflect.StructField, jsonName string, base object) object {
	switch jsonName {
	case "name":
		base = object{
			"type": "string", "minLength": 1, "maxLength": 63,
			"pattern": `^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`,
		}
	case "resourceVersion", "revision", "schemaVersion", "number":
		base["minimum"] = 1
		base["maximum"] = devopsv1.MaximumContractInteger
	case "ordinal":
		base["minimum"] = 1
		base["maximum"] = 2
	case "contentDigest", "repositoryBindingDigest", "toolchainImageDigest",
		"canonicalPayloadDigest", "sourceEventDigest", "pipelineRevisionDigest", "inputDigest":
		base = object{"type": "string", "pattern": `^sha256:[0-9a-f]{64}$`}
	case "deliveryId":
		base = object{
			"type": "string", "format": "uuid",
			"pattern": `^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`,
			"not":     object{"const": "00000000-0000-0000-0000-000000000000"},
		}
	case "headCommit", "trustedBaseCommit":
		base = object{
			"type": "string", "pattern": `^(?:[0-9a-f]{40}|[0-9a-f]{64})$`,
		}
	case "allowedEndpointOrigins":
		base = object{
			"type": "array", "minItems": 1, "maxItems": 8,
			"uniqueItems": true,
			"items": object{
				"type": "string", "format": "uri", "minLength": 1, "maxLength": 512,
				"pattern": `^https://[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::(?:[1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5]))?$`,
				"not":     object{"pattern": `^https://(?:[a-z0-9-]+\.)*localhost(?::|$)`},
			},
		}
	case "repositoryPath":
		base = object{
			"type": "string", "minLength": 3, "maxLength": 257,
			"pattern": `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}/[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`,
		}
	case "trustedDefaultBranch":
		base = object{
			"type": "string", "minLength": 1, "maxLength": 128,
			"pattern": `^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$`,
			"not": object{
				"pattern": `(?:\.\.|//|@\{|(?:^|/)\.|\.lock(?:/|$)|[/.]$)`,
			},
		}
	case "status":
		if owner == "Problem" {
			base["minimum"] = 400
			base["maximum"] = 599
		}
	case "type":
		if owner == "Problem" {
			base["format"] = "uri"
			base["pattern"] = `^https://errors\.matrix\.xiak\.com/`
		}
	case "title":
		base["minLength"] = 1
		base["maxLength"] = 160
	case "detail":
		base["minLength"] = 1
		base["maxLength"] = 512
	case "instance":
		base["minLength"] = 1
		base["maxLength"] = 256
		base["pattern"] = `^/`
	case "traceId":
		base = opaqueIDSchema()
	case "field":
		base["minLength"] = 1
		base["maxLength"] = 128
		base["pattern"] = `^[A-Za-z][A-Za-z0-9.\[\]-]{0,127}$`
	case "description":
		if owner == "FieldViolation" {
			base["minLength"] = 1
			base["maxLength"] = 256
		}
	case "violations":
		base["maxItems"] = 32
		base["uniqueItems"] = true
	}
	return base
}

func applySemanticOverlays(schemas object) {
	for owner, kind := range map[string]string{
		"DevOpsProject":      "DevOpsProject",
		"SourceConnection":   "SourceConnection",
		"RepositoryBinding":  "RepositoryBinding",
		"Pipeline":           "Pipeline",
		"PipelineRevision":   "PipelineRevision",
		"PipelineActivation": "PipelineActivation",
		"SourceEvent":        "SourceEvent",
		"PipelineRun":        "PipelineRun",
	} {
		properties := schemas[owner].(object)["properties"].(object)
		properties["apiVersion"] = object{"const": devopsv1.APIVersion}
		properties["kind"] = object{"const": kind}
	}

	limits := schemas["VerificationLimits"].(object)["properties"].(object)
	limits["stepTimeoutSeconds"] = object{"const": devopsv1.FixedStepTimeoutSeconds}
	limits["runTimeoutSeconds"] = object{"const": devopsv1.FixedRunTimeoutSeconds}
	limits["cpuMillis"] = object{"const": devopsv1.FixedCPUMillis}
	limits["memoryBytes"] = object{"const": devopsv1.FixedMemoryBytes}
	limits["writableBytes"] = object{"const": devopsv1.FixedWritableBytes}
	limits["processLimit"] = object{"const": devopsv1.FixedProcessLimit}
	limits["maxLogBytes"] = object{"const": devopsv1.FixedMaxLogBytes}

	revision := schemas["PipelineRevisionSpec"].(object)["properties"].(object)
	revision["executorProfile"] = object{"const": string(devopsv1.ExecutorMatrixNativeIsolatedV1)}
	revision["toolchainImageDigest"] = object{"const": devopsv1.Go126OfflineToolchainImageDigest}
	revision["steps"] = object{
		"type": "array", "minItems": 2, "maxItems": 2, "items": false,
		"prefixItems": []any{
			object{
				"type": "object", "additionalProperties": false,
				"properties": object{
					"ordinal": object{"const": 1},
					"kind":    object{"const": string(devopsv1.VerificationStepGoTest)},
				},
				"required": []string{"kind", "ordinal"},
			},
			object{
				"type": "object", "additionalProperties": false,
				"properties": object{
					"ordinal": object{"const": 2},
					"kind":    object{"const": string(devopsv1.VerificationStepGoVet)},
				},
				"required": []string{"kind", "ordinal"},
			},
		},
	}

	status := schemas["PipelineRunStatus"].(object)
	status["allOf"] = []any{
		pipelineRunStatusRule(
			devopsv1.PipelineRunQueued,
			[]devopsv1.PipelineRunStage{devopsv1.PipelineRunStageReceive},
			[]devopsv1.PipelineRunReason{devopsv1.PipelineRunReasonEventAdmitted},
			false,
		),
		pipelineRunStatusRule(
			devopsv1.PipelineRunFetching,
			[]devopsv1.PipelineRunStage{devopsv1.PipelineRunStageFetch}, nil, false,
		),
		pipelineRunStatusRule(
			devopsv1.PipelineRunVerifying,
			[]devopsv1.PipelineRunStage{devopsv1.PipelineRunStageVerify}, nil, false,
		),
		pipelineRunStatusRule(
			devopsv1.PipelineRunReporting,
			[]devopsv1.PipelineRunStage{devopsv1.PipelineRunStageReport}, nil, false,
		),
		pipelineRunStatusRule(
			devopsv1.PipelineRunSucceeded,
			[]devopsv1.PipelineRunStage{devopsv1.PipelineRunStageReport},
			[]devopsv1.PipelineRunReason{devopsv1.PipelineRunReasonCompleted},
			true,
		),
		pipelineRunStatusRule(
			devopsv1.PipelineRunFailed,
			devopsv1.PipelineRunStages(),
			[]devopsv1.PipelineRunReason{
				devopsv1.PipelineRunReasonSourceUnavailable,
				devopsv1.PipelineRunReasonCommitMismatch,
				devopsv1.PipelineRunReasonExecutorUnavailable,
				devopsv1.PipelineRunReasonVerificationFailed,
				devopsv1.PipelineRunReasonDeadlineExceeded,
				devopsv1.PipelineRunReasonReportUnavailable,
				devopsv1.PipelineRunReasonReportConflict,
			},
			true,
		),
		pipelineRunStatusRule(
			devopsv1.PipelineRunCancelled,
			devopsv1.PipelineRunStages(),
			[]devopsv1.PipelineRunReason{devopsv1.PipelineRunReasonCancelled},
			true,
		),
		pipelineRunStatusRule(
			devopsv1.PipelineRunReconciling,
			[]devopsv1.PipelineRunStage{devopsv1.PipelineRunStageReport},
			[]devopsv1.PipelineRunReason{devopsv1.PipelineRunReasonExternalEffectUncertain},
			false,
		),
		pipelineRunStatusRule(
			devopsv1.PipelineRunManualIntervention,
			[]devopsv1.PipelineRunStage{devopsv1.PipelineRunStageReport},
			[]devopsv1.PipelineRunReason{devopsv1.PipelineRunReasonReconciliationExhausted},
			true,
		),
	}

	problem := schemas["Problem"].(object)
	problem["allOf"] = []any{
		problemStatusRule(devopsv1.ErrorInvalidArgument, []int{400, 422}),
		problemStatusRule(devopsv1.ErrorUnauthenticated, []int{401}),
		problemStatusRule(devopsv1.ErrorForbidden, []int{403}),
		problemStatusRule(devopsv1.ErrorNotFound, []int{404}),
		problemStatusRule(devopsv1.ErrorMethodNotAllowed, []int{405}),
		problemStatusRule(devopsv1.ErrorConflict, []int{409}),
		problemStatusRule(devopsv1.ErrorResourceExhausted, []int{429}),
		problemStatusRule(devopsv1.ErrorPayloadTooLarge, []int{413}),
		problemStatusRule(devopsv1.ErrorUnsupportedMediaType, []int{415}),
		problemStatusRule(devopsv1.ErrorPreconditionRequired, []int{428}),
		problemStatusRule(devopsv1.ErrorPreconditionFailed, []int{412}),
		problemStatusRule(devopsv1.ErrorInternal, []int{500}),
		problemStatusRule(devopsv1.ErrorUnavailable, []int{503}),
	}
}

func pipelineRunStatusRule(
	state devopsv1.PipelineRunState,
	stages []devopsv1.PipelineRunStage,
	reasons []devopsv1.PipelineRunReason,
	completed bool,
) object {
	stageValues := make([]any, len(stages))
	for index, stage := range stages {
		stageValues[index] = string(stage)
	}
	then := object{
		"properties": object{"stage": object{"enum": stageValues}},
	}
	if state == devopsv1.PipelineRunQueued {
		then["properties"].(object)["resourceVersion"] = object{"const": 1}
		then["properties"].(object)["cancellationRequestedAt"] = false
	}
	if len(reasons) == 0 {
		then["not"] = object{
			"anyOf": []any{
				object{"required": []string{"reason"}},
				object{"required": []string{"completedAt"}},
			},
		}
	} else {
		reasonValues := make([]any, len(reasons))
		for index, reason := range reasons {
			reasonValues[index] = string(reason)
		}
		then["properties"].(object)["reason"] = object{"enum": reasonValues}
		then["required"] = []string{"reason"}
		if completed {
			then["required"] = []string{"reason", "completedAt"}
		} else {
			then["not"] = object{"required": []string{"completedAt"}}
		}
	}
	if state == devopsv1.PipelineRunCancelled {
		then["required"] = []string{"reason", "cancellationRequestedAt", "completedAt"}
	}
	return object{
		"if": object{
			"properties": object{"state": object{"const": string(state)}},
			"required":   []string{"state"},
		},
		"then": then,
	}
}

func problemStatusRule(code devopsv1.ErrorCode, statuses []int) object {
	values := make([]any, len(statuses))
	for index, status := range statuses {
		values[index] = status
	}
	return object{
		"if": object{
			"properties": object{"code": object{"const": string(code)}},
			"required":   []string{"code"},
		},
		"then": object{
			"properties": object{"status": object{"enum": values}},
		},
	}
}

func fatalf(format string, values ...any) {
	_, _ = fmt.Fprintf(os.Stderr, format+"\n", values...)
	os.Exit(1)
}
