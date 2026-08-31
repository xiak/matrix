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
		"security": []any{schema{"MatrixIAM": []string{}}},
		"paths":    buildPaths(),
		"components": schema{
			"securitySchemes": schema{
				"MatrixIAM": schema{
					"type": "http", "scheme": "bearer",
					"description": "Matrix IAM credential resolved by the server-side Authorizer.",
				},
				"MatrixInstallationVerifier": schema{
					"type": "http", "scheme": "bearer",
					"description": "Narrow installation-verifier service credential resolved through IAM installation.verify.",
				},
				"MatrixTerminalTicket": schema{
					"type": "apiKey", "in": "cookie", "name": "matrix_terminal_ticket",
					"description": "Single-use terminal connection ticket delivered only by an HttpOnly SameSite=Strict host-only cookie.",
				},
			},
			"parameters": schema{
				"IdempotencyKey": schema{
					"name": "Idempotency-Key", "in": "header", "required": true,
					"schema": schema{"type": "string", "minLength": 1, "maxLength": 128},
				},
				"IfMatch": schema{
					"name": "If-Match", "in": "header", "required": true,
					"description": "Strong ETag containing the current positive resourceVersion.",
					"schema": schema{
						"type": "string", "minLength": 3, "maxLength": 18,
						"pattern": `^"[1-9][0-9]*"$`,
					},
				},
			},
			"headers": schema{
				"ETag": schema{
					"description": "Opaque resource version validator.",
					"schema":      schema{"type": "string"},
				},
				"Location": schema{
					"description": "Canonical resource URI.",
					"schema":      schema{"type": "string"},
				},
				"OperationLocation": schema{
					"description": "Canonical Operation URI.",
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

func buildPaths() schema {
	paths := schema{
		"/ready": schema{"get": readinessOperation()},
	}
	for _, resource := range []struct {
		collection string
		parameter  string
		kind       string
		createBody string
		createID   string
		readID     string
	}{
		{collection: "execution-pools", parameter: "executionPoolId", kind: "ExecutionPool", createBody: "CreateExecutionPoolRequest", createID: "createExecutionPool", readID: "getExecutionPool"},
		{collection: "execution-targets", parameter: "executionTargetId", kind: "ExecutionTarget", createBody: "RegisterExecutionTargetRequest", createID: "registerExecutionTarget", readID: "getExecutionTarget"},
		{collection: "applications", parameter: "applicationId", kind: "Application", createBody: "CreateApplicationRequest", createID: "createApplication", readID: "getApplication"},
		{collection: "configurations", parameter: "configurationId", kind: "Configuration", createBody: "CreateConfigurationRequest", createID: "createConfiguration", readID: "getConfiguration"},
		{collection: "configuration-revisions", parameter: "configurationRevisionId", kind: "ConfigurationRevision", createBody: "CreateConfigurationRevisionRequest", createID: "createConfigurationRevision", readID: "getConfigurationRevision"},
		{collection: "application-revisions", parameter: "applicationRevisionId", kind: "ApplicationRevision", createBody: "CreateApplicationRevisionRequest", createID: "createApplicationRevision", readID: "getApplicationRevision"},
	} {
		paths["/v1/"+resource.collection] = schema{
			"post": mutationOperation(
				resource.createID,
				"Create "+resource.kind,
				resource.createBody,
				false,
				"201",
			),
		}
		paths["/v1/"+resource.collection+"/{"+resource.parameter+"}"] = schema{
			"get": readOperation(resource.readID, "Get "+resource.kind, resource.parameter, resource.kind),
		}
	}
	executionTargets := paths["/v1/execution-targets"].(schema)
	executionTargets["get"] = collectionReadOperation(
		"listExecutionTargets",
		"List installation-scoped ExecutionTargets",
		"ExecutionTargetList",
	)

	paths["/v1/deployments"] = schema{
		"get":  deploymentCollectionReadOperation(),
		"post": mutationOperation("createDeployment", "Create Deployment", "CreateDeploymentRequest", false, "202"),
	}
	paths["/v1/deployments/{deploymentId}"] = schema{
		"get": readOperation("getDeployment", "Get Deployment", "deploymentId", "Deployment"),
		"put": mutationOperationWithPath(
			"updateDeployment", "Update Deployment", "deploymentId", "DeploymentSpec", true, "202",
		),
	}
	paths["/v1/deployments/{deploymentId}/rollback"] = schema{
		"post": mutationOperationWithPath(
			"rollbackDeployment", "Roll back Deployment", "deploymentId", "RollbackDeploymentRequest", true, "202",
		),
	}
	paths["/v1/deployments/{deploymentId}/generations/{generation}"] = schema{
		"get": schema{
			"operationId": "getDeploymentGeneration",
			"summary":     "Get DeploymentGeneration",
			"parameters": []any{
				pathIDParameter("deploymentId"),
				schema{
					"name": "generation", "in": "path", "required": true,
					"schema": schema{"type": "integer", "minimum": 1, "maximum": 9007199254740991},
				},
			},
			"responses": readResponses("DeploymentGeneration"),
		},
	}
	paths["/v1/deployments/{deploymentId}/runtime"] = schema{
		"get": readOperation(
			"getDeploymentRuntime", "Get current Deployment runtime", "deploymentId", "DeploymentRuntimeSnapshot",
		),
	}
	paths["/v1/deployments/{deploymentId}/terminal-sessions"] = schema{
		"post": createTerminalSessionOperation(),
	}
	paths["/v1/terminal-sessions/{terminalSessionId}"] = schema{
		"delete": closeTerminalSessionOperation(),
	}
	paths["/v1/terminal-sessions/{terminalSessionId}/connect"] = schema{
		"get": connectTerminalSessionOperation(),
	}
	paths["/v1/operations/{operationId}"] = schema{
		"get": readOperation("getOperation", "Get Operation", "operationId", "Operation"),
	}
	paths["/v1/platform/operations/{operationId}"] = schema{
		"get": readOperation("getPlatformOperation", "Get an installation-scoped Operation", "operationId", "Operation"),
	}
	paths["/v1/installation:verify"] = schema{
		"post": schema{
			"operationId": "verifyInstallation",
			"summary":     "Run the fixed no-secret installation application probe",
			"parameters": []any{
				componentRef("#/components/parameters/IdempotencyKey"),
			},
			"security": []any{schema{
				"MatrixInstallationVerifier": []string{},
			}},
			"requestBody": jsonRequestBody("VerifyInstallationRequest"),
			"responses": schema{
				"200": schema{
					"description": "Current fixed installation probe state.",
					"content": schema{
						"application/json": schema{"schema": ref("InstallationVerification")},
					},
				},
				"400": componentRef("#/components/responses/ProblemResponse"),
				"401": componentRef("#/components/responses/ProblemResponse"),
				"403": componentRef("#/components/responses/ProblemResponse"),
				"409": componentRef("#/components/responses/ProblemResponse"),
				"415": componentRef("#/components/responses/ProblemResponse"),
				"500": componentRef("#/components/responses/ProblemResponse"),
				"503": componentRef("#/components/responses/ProblemResponse"),
			},
		},
	}
	return paths
}

func createTerminalSessionOperation() schema {
	success := schema{
		"description": "A durable terminal session and a single-use connection cookie.",
		"headers": schema{
			"Location":   componentRef("#/components/headers/Location"),
			"Set-Cookie": schema{"description": "HttpOnly SameSite=Strict host-only connection ticket; Secure is required when TLS is in use.", "schema": schema{"type": "string"}},
		},
		"content": schema{
			"application/json": schema{"schema": ref("TerminalSession")},
		},
	}
	return schema{
		"operationId": "createTerminalSession",
		"summary":     "Create a short-lived terminal session for one current Deployment instance",
		"parameters": []any{
			pathIDParameter("deploymentId"),
			componentRef("#/components/parameters/IdempotencyKey"),
		},
		"requestBody": jsonRequestBody("CreateTerminalSessionRequest"),
		"responses": schema{
			"200": success,
			"201": success,
			"400": componentRef("#/components/responses/ProblemResponse"),
			"401": componentRef("#/components/responses/ProblemResponse"),
			"403": componentRef("#/components/responses/ProblemResponse"),
			"404": componentRef("#/components/responses/ProblemResponse"),
			"409": componentRef("#/components/responses/ProblemResponse"),
			"415": componentRef("#/components/responses/ProblemResponse"),
			"500": componentRef("#/components/responses/ProblemResponse"),
			"503": componentRef("#/components/responses/ProblemResponse"),
			"504": componentRef("#/components/responses/ProblemResponse"),
		},
	}
}

func closeTerminalSessionOperation() schema {
	return schema{
		"operationId": "closeTerminalSession",
		"summary":     "Close the caller's exact terminal session",
		"parameters":  []any{pathIDParameter("terminalSessionId")},
		"responses": schema{
			"204": schema{"description": "The terminal session is closed or was already closed."},
			"400": componentRef("#/components/responses/ProblemResponse"),
			"401": componentRef("#/components/responses/ProblemResponse"),
			"403": componentRef("#/components/responses/ProblemResponse"),
			"404": componentRef("#/components/responses/ProblemResponse"),
			"409": componentRef("#/components/responses/ProblemResponse"),
			"500": componentRef("#/components/responses/ProblemResponse"),
			"503": componentRef("#/components/responses/ProblemResponse"),
		},
	}
}

func connectTerminalSessionOperation() schema {
	return schema{
		"operationId": "connectTerminalSession",
		"summary":     "Consume the single-use ticket and upgrade to the bounded terminal WebSocket",
		"parameters":  []any{pathIDParameter("terminalSessionId")},
		"security": []any{schema{
			"MatrixTerminalTicket": []string{},
		}},
		"x-matrix-websocket-subprotocol": "matrix.terminal.v1",
		"x-matrix-websocket-max-frame":   paasv1.MaximumTerminalFrameBytes,
		"responses": schema{
			"101": schema{"description": "WebSocket upgraded with the matrix.terminal.v1 subprotocol."},
			"400": componentRef("#/components/responses/ProblemResponse"),
			"401": componentRef("#/components/responses/ProblemResponse"),
			"403": componentRef("#/components/responses/ProblemResponse"),
			"404": componentRef("#/components/responses/ProblemResponse"),
			"409": componentRef("#/components/responses/ProblemResponse"),
			"410": componentRef("#/components/responses/ProblemResponse"),
			"500": componentRef("#/components/responses/ProblemResponse"),
			"503": componentRef("#/components/responses/ProblemResponse"),
		},
	}
}

func readinessOperation() schema {
	return schema{
		"operationId": "getPaaSReadiness",
		"summary":     "Get PaaS readiness",
		"security":    []any{},
		"responses": schema{
			"200": schema{
				"description": "PaaS is ready.",
				"content": schema{
					"application/json": schema{"schema": ref("Readiness")},
				},
			},
			"400": componentRef("#/components/responses/ProblemResponse"),
			"503": componentRef("#/components/responses/ProblemResponse"),
		},
	}
}

func mutationOperation(
	operationID string,
	summary string,
	bodySchema string,
	requiresIfMatch bool,
	successStatus string,
) schema {
	parameters := []any{componentRef("#/components/parameters/IdempotencyKey")}
	if requiresIfMatch {
		parameters = append(parameters, componentRef("#/components/parameters/IfMatch"))
	}
	return schema{
		"operationId": operationID,
		"summary":     summary,
		"parameters":  parameters,
		"requestBody": jsonRequestBody(bodySchema),
		"responses":   mutationResponses(successStatus),
	}
}

func mutationOperationWithPath(
	operationID string,
	summary string,
	pathParameter string,
	bodySchema string,
	requiresIfMatch bool,
	successStatus string,
) schema {
	operation := mutationOperation(operationID, summary, bodySchema, requiresIfMatch, successStatus)
	parameters := []any{pathIDParameter(pathParameter)}
	parameters = append(parameters, operation["parameters"].([]any)...)
	operation["parameters"] = parameters
	return operation
}

func readOperation(operationID, summary, pathParameter, responseSchema string) schema {
	return schema{
		"operationId": operationID,
		"summary":     summary,
		"parameters":  []any{pathIDParameter(pathParameter)},
		"responses":   readResponses(responseSchema),
	}
}

func collectionReadOperation(operationID, summary, responseSchema string) schema {
	responses := readResponses(responseSchema)
	object(responses["200"])["description"] = "Current bounded authorized collection."
	return schema{
		"operationId": operationID,
		"summary":     summary,
		"responses":   responses,
	}
}

func deploymentCollectionReadOperation() schema {
	operation := collectionReadOperation(
		"listDeployments", "List tenant-scoped Deployments", "DeploymentList",
	)
	operation["parameters"] = []any{schema{
		"name": "after", "in": "query", "required": false,
		"schema": ref("ID"),
	}}
	return operation
}

func jsonRequestBody(schemaName string) schema {
	return schema{
		"required": true,
		"content": schema{
			"application/json": schema{"schema": ref(schemaName)},
		},
	}
}

func mutationResponses(successStatus string) schema {
	responses := schema{
		"200": schema{
			"description": "Durable Operation accepted or completed.",
			"headers": schema{
				"Location":           componentRef("#/components/headers/Location"),
				"Operation-Location": componentRef("#/components/headers/OperationLocation"),
				"ETag":               componentRef("#/components/headers/ETag"),
			},
			"content": schema{
				"application/json": schema{"schema": ref("Operation")},
			},
		},
		"400": componentRef("#/components/responses/ProblemResponse"),
		"401": componentRef("#/components/responses/ProblemResponse"),
		"403": componentRef("#/components/responses/ProblemResponse"),
		"404": componentRef("#/components/responses/ProblemResponse"),
		"409": componentRef("#/components/responses/ProblemResponse"),
		"412": componentRef("#/components/responses/ProblemResponse"),
		"415": componentRef("#/components/responses/ProblemResponse"),
		"428": componentRef("#/components/responses/ProblemResponse"),
		"500": componentRef("#/components/responses/ProblemResponse"),
		"503": componentRef("#/components/responses/ProblemResponse"),
		"504": componentRef("#/components/responses/ProblemResponse"),
	}
	if successStatus != "200" {
		responses[successStatus] = responses["200"]
	}
	return responses
}

func readResponses(schemaName string) schema {
	return schema{
		"200": schema{
			"description": "Current tenant-scoped resource.",
			"headers":     schema{"ETag": componentRef("#/components/headers/ETag")},
			"content": schema{
				"application/json": schema{"schema": ref(schemaName)},
			},
		},
		"400": componentRef("#/components/responses/ProblemResponse"),
		"401": componentRef("#/components/responses/ProblemResponse"),
		"403": componentRef("#/components/responses/ProblemResponse"),
		"404": componentRef("#/components/responses/ProblemResponse"),
		"500": componentRef("#/components/responses/ProblemResponse"),
		"503": componentRef("#/components/responses/ProblemResponse"),
		"504": componentRef("#/components/responses/ProblemResponse"),
	}
}

func pathIDParameter(name string) schema {
	return schema{
		"name": name, "in": "path", "required": true,
		"schema": ref("ID"),
	}
}

func componentRef(path string) schema {
	return schema{"$ref": path}
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
		"AuthorityKind":                 stringsOf(paasv1.AuthorityPlatform, paasv1.AuthorityTenant),
		"TenantStatus":                  stringsOf(paasv1.TenantActive, paasv1.TenantSuspended, paasv1.TenantDeactivated),
		"ExecutionPoolPhase":            stringsOf(paasv1.ExecutionPoolReady, paasv1.ExecutionPoolDegraded, paasv1.ExecutionPoolUnavailable),
		"ExecutionTargetHealth":         stringsOf(paasv1.ExecutionTargetHealthUnknown, paasv1.ExecutionTargetHealthReady, paasv1.ExecutionTargetHealthDegraded, paasv1.ExecutionTargetHealthUnavailable),
		"MeasurementState":              stringsOf(paasv1.MeasurementAvailable, paasv1.MeasurementWarmingUp, paasv1.MeasurementUnavailable, paasv1.MeasurementUnsupported, paasv1.MeasurementStale),
		"ExecutionTargetDesiredState":   stringsOf(paasv1.ExecutionTargetActive, paasv1.ExecutionTargetDraining),
		"IsolationGuarantee":            stringsOfSlice(paasv1.IsolationGuarantees()),
		"PlacementStrategy":             stringsOf(paasv1.PlacementFirstFit, paasv1.PlacementSpread, paasv1.PlacementBinPack),
		"PlacementOutcome":              stringsOf(paasv1.PlacementScheduled, paasv1.PlacementUnschedulable),
		"DeploymentDesiredState":        stringsOf(paasv1.DeploymentDesiredRunning, paasv1.DeploymentDesiredStopped),
		"DeploymentPhase":               stringsOfSlice(paasv1.DeploymentPhases()),
		"DeploymentInstanceState":       stringsOfSlice(paasv1.DeploymentInstanceStates()),
		"DeploymentInstanceHealth":      stringsOfSlice(paasv1.DeploymentInstanceHealthStates()),
		"TerminalSessionState":          stringsOfSlice(paasv1.TerminalSessionStates()),
		"TerminalSessionOutcome":        stringsOfSlice(paasv1.TerminalSessionOutcomes()),
		"OperationAction":               stringsOfSlice(paasv1.OperationActions()),
		"OperationState":                stringsOfSlice(paasv1.OperationStates()),
		"EvidenceType":                  stringsOf(paasv1.EvidencePolicyDecision, paasv1.EvidencePlacementDecision, paasv1.EvidenceAdapterCommand, paasv1.EvidenceAdapterResult, paasv1.EvidenceObservation, paasv1.EvidenceVerification, paasv1.EvidenceAuditDispatch),
		"EvidenceSeverity":              stringsOf(paasv1.EvidenceInfo, paasv1.EvidenceWarning, paasv1.EvidenceError),
		"SubjectType":                   stringsOf(paasv1.SubjectUser, paasv1.SubjectServiceAccount, paasv1.SubjectAgent, paasv1.SubjectSystemUser),
		"ReadinessState":                stringsOf(paasv1.ReadinessReady, paasv1.ReadinessNotReady),
		"InstallationVerificationState": stringsOf(paasv1.InstallationVerificationPending, paasv1.InstallationVerificationReady, paasv1.InstallationVerificationFailed),
		"ErrorCode":                     stringsOfSlice(paasv1.ErrorCodes()),
		"AdapterKind":                   stringsOf(paasv1.AdapterInfrastructure, paasv1.AdapterDeploymentExecutor, paasv1.AdapterGateway),
		"AdapterAction":                 stringsOf(paasv1.AdapterCapabilities, paasv1.AdapterInspectExecutionTarget, paasv1.AdapterObserveExecutionTarget, paasv1.AdapterValidateDeployment, paasv1.AdapterApplyDeployment, paasv1.AdapterObserveDeployment, paasv1.AdapterStopDeployment, paasv1.AdapterRollbackDeployment, paasv1.AdapterReconcileRoutes, paasv1.AdapterObserveRoutes, paasv1.AdapterDeleteRoutes),
		"AdapterResultState":            stringsOf(paasv1.AdapterResultSucceeded, paasv1.AdapterResultInProgress, paasv1.AdapterResultFailed, paasv1.AdapterResultUnknown),
		"AdapterErrorClass":             stringsOf(paasv1.AdapterErrorValidation, paasv1.AdapterErrorConflict, paasv1.AdapterErrorPermissionDenied, paasv1.AdapterErrorQuotaExceeded, paasv1.AdapterErrorRateLimited, paasv1.AdapterErrorTransient, paasv1.AdapterErrorUnavailable, paasv1.AdapterErrorTimeout, paasv1.AdapterErrorNotFound, paasv1.AdapterErrorUnknownOutcome, paasv1.AdapterErrorInternal),
		"ArtifactKind":                  stringsOf(paasv1.ArtifactOCIImage, paasv1.ArtifactOCIArtifact, paasv1.ArtifactReleaseBundle),
		"InputKind":                     stringsOf(paasv1.InputConfiguration, paasv1.InputSecret),
		"InjectionMode":                 stringsOf(paasv1.InjectionEnvironment, paasv1.InjectionFile),
		"EndpointProtocol":              stringsOf(paasv1.EndpointHTTP, paasv1.EndpointGRPC, paasv1.EndpointTCP),
		"EndpointVisibility":            stringsOf(paasv1.EndpointPrivate, paasv1.EndpointPublic),
	}
}

func structContracts() map[string]reflect.Type {
	values := []any{
		paasv1.ResourceScope{}, paasv1.ResourceMetadata{}, paasv1.Tenant{},
		paasv1.LabelSelector{}, paasv1.ExecutionPoolSpec{}, paasv1.ExecutionPoolStatus{}, paasv1.ExecutionPool{},
		paasv1.CreateExecutionPoolRequest{}, paasv1.RegisterExecutionTargetRequest{},
		paasv1.AdapterRef{}, paasv1.Capacity{}, paasv1.ExecutionTargetSpec{}, paasv1.ExecutionTargetStatus{}, paasv1.ExecutionTarget{}, paasv1.ExecutionTargetList{},
		paasv1.ExecutionTargetUsage{}, paasv1.CPUUsage{}, paasv1.CPUUsageValue{}, paasv1.MemoryUsage{}, paasv1.MemoryUsageValue{},
		paasv1.FilesystemUsage{}, paasv1.FilesystemUsageValue{},
		paasv1.PlacementPolicySpec{}, paasv1.PlacementPolicy{}, paasv1.PlacementDecision{},
		paasv1.ArtifactRef{}, paasv1.ResourceRequirements{}, paasv1.ApplicationEndpoint{}, paasv1.ComponentInput{},
		paasv1.SecretVersionReference{}, paasv1.ComponentBinding{}, paasv1.Application{}, paasv1.CreateApplicationRequest{}, paasv1.Configuration{},
		paasv1.CreateConfigurationRequest{}, paasv1.ConfigurationRevisionSpec{}, paasv1.ConfigurationRevision{},
		paasv1.CreateConfigurationRevisionRequest{}, paasv1.ApplicationRevisionComponent{}, paasv1.ApplicationRevisionSpec{},
		paasv1.ApplicationRevision{}, paasv1.CreateApplicationRevisionRequest{}, paasv1.DeploymentComponent{}, paasv1.DeploymentSpec{},
		paasv1.DeploymentStatus{}, paasv1.Deployment{}, paasv1.CreateDeploymentRequest{}, paasv1.RollbackDeploymentRequest{},
		paasv1.DeploymentList{}, paasv1.DeploymentRuntimeInstance{}, paasv1.DeploymentRuntimeObservation{},
		paasv1.DeploymentInstanceCPUUsage{}, paasv1.DeploymentInstanceCPUUsageValue{},
		paasv1.DeploymentInstanceMemoryUsage{}, paasv1.DeploymentInstanceMemoryUsageValue{},
		paasv1.DeploymentInstanceNetworkUsage{}, paasv1.DeploymentInstanceNetworkUsageValue{},
		paasv1.DeploymentInstanceBlockIOUsage{}, paasv1.DeploymentInstanceBlockIOUsageValue{},
		paasv1.DeploymentInstanceVolumeUsage{}, paasv1.DeploymentInstanceStorageUsage{}, paasv1.DeploymentInstanceStorageUsageValue{},
		paasv1.DeploymentResourceInstance{}, paasv1.DeploymentResourceObservation{}, paasv1.DeploymentResourceValue{}, paasv1.DeploymentResourceSnapshot{},
		paasv1.DeploymentRuntimeValue{}, paasv1.DeploymentRuntimeSnapshot{},
		paasv1.TerminalSize{}, paasv1.CreateTerminalSessionRequest{}, paasv1.TerminalSession{},
		paasv1.DeploymentGeneration{}, paasv1.SubjectRef{}, paasv1.ResourceRef{}, paasv1.FieldViolation{}, paasv1.Readiness{},
		paasv1.VerifyInstallationRequest{}, paasv1.InstallationVerification{},
		paasv1.Problem{}, paasv1.Operation{}, paasv1.Evidence{}, paasv1.AdapterCapabilitiesContract{},
		paasv1.AdapterCommandEnvelope{}, paasv1.InspectExecutionTargetRequest{}, paasv1.ObserveExecutionTargetRequest{},
		paasv1.DeploymentExecutionRequest{}, paasv1.ObserveDeploymentRequest{}, paasv1.DeploymentEndpointObservation{},
		paasv1.ObserveDeploymentRuntimeRequest{},
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
	if (owner == "DeploymentRuntimeInstance" || owner == "DeploymentResourceInstance") && field.Name == "ID" {
		return schema{"type": "string", "pattern": `^instance-[0-9a-f]{32}$`}
	}
	if field.Name == "BindingRef" {
		return ref("ID")
	}
	if (owner == "DeploymentEndpointObservation" || owner == "DeploymentRuntimeInstance") &&
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
	case reflect.Float64:
		return schema{"type": "number", "minimum": 0}
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
	registrationLabels := object(schemas["RegisterExecutionTargetRequest"])["properties"].(schema)["labels"].(schema)
	registrationLabels["not"] = schema{"required": []string{"matrix-machine-fingerprint"}}
	resourceKinds := map[string]string{
		"Application": "Application", "Configuration": "Configuration",
		"ConfigurationRevision": "ConfigurationRevision", "ApplicationRevision": "ApplicationRevision",
		"Deployment": "Deployment", "DeploymentList": "DeploymentList",
		"DeploymentGeneration": "DeploymentGeneration", "DeploymentRuntimeSnapshot": "DeploymentRuntimeSnapshot",
		"TerminalSession": "TerminalSession",
		"ExecutionPool":   "ExecutionPool", "ExecutionTarget": "ExecutionTarget",
		"PlacementPolicy": "PlacementPolicy", "PlacementDecision": "PlacementDecision",
		"Operation": "Operation", "Evidence": "Evidence",
		"Readiness": "Readiness", "InstallationVerification": "InstallationVerification",
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
	object(schemas["DeploymentList"])["properties"].(schema)["items"].(schema)["maxItems"] = paasv1.MaximumDeploymentListItems
	object(schemas["DeploymentRuntimeObservation"])["properties"].(schema)["instances"].(schema)["maxItems"] = paasv1.MaximumDeploymentRuntimeInstances
	object(schemas["DeploymentResourceObservation"])["properties"].(schema)["instances"].(schema)["maxItems"] = paasv1.MaximumDeploymentRuntimeInstances
	for _, name := range []string{"DeploymentRuntimeObservation", "DeploymentResourceObservation", "ObserveDeploymentRuntimeRequest"} {
		object(schemas[name])["properties"].(schema)["generation"].(schema)["minimum"] = 1
	}
	object(schemas["DeploymentRuntimeSnapshot"])["properties"].(schema)["state"] = schema{
		"type": "string",
		"enum": stringsOf(
			paasv1.MeasurementAvailable,
			paasv1.MeasurementStale,
			paasv1.MeasurementUnavailable,
		),
	}
	object(schemas["DeploymentRuntimeSnapshot"])["allOf"] = []any{
		schema{
			"if":   schema{"properties": schema{"state": schema{"const": string(paasv1.MeasurementUnavailable)}}},
			"then": schema{"properties": schema{"value": false}},
		},
		schema{
			"if":   schema{"properties": schema{"state": schema{"enum": stringsOf(paasv1.MeasurementAvailable, paasv1.MeasurementStale)}}},
			"then": schema{"required": []string{"value"}},
		},
	}
	terminalSizeProperties := object(schemas["TerminalSize"])["properties"].(schema)
	terminalSizeProperties["columns"] = schema{"type": "integer", "minimum": paasv1.MinimumTerminalColumns, "maximum": paasv1.MaximumTerminalColumns}
	terminalSizeProperties["rows"] = schema{"type": "integer", "minimum": paasv1.MinimumTerminalRows, "maximum": paasv1.MaximumTerminalRows}
	object(schemas["CreateTerminalSessionRequest"])["properties"].(schema)["instanceId"] = schema{"type": "string", "pattern": `^instance-[0-9a-f]{32}$`}
	terminalProperties := object(schemas["TerminalSession"])["properties"].(schema)
	terminalProperties["id"] = schema{"type": "string", "pattern": `^terminal-session-[0-9a-f]{32}$`}
	terminalProperties["instanceId"] = schema{"type": "string", "pattern": `^instance-[0-9a-f]{32}$`}
	terminalProperties["generation"].(schema)["minimum"] = 1
	object(schemas["TerminalSession"])["allOf"] = []any{
		schema{
			"if":   schema{"properties": schema{"state": schema{"enum": stringsOf(paasv1.TerminalSessionPending, paasv1.TerminalSessionConnecting)}}, "required": []string{"state"}},
			"then": schema{"properties": schema{"outcome": false, "connectedAt": false, "endedAt": false}},
		},
		schema{
			"if":   schema{"properties": schema{"state": schema{"const": string(paasv1.TerminalSessionActive)}}, "required": []string{"state"}},
			"then": schema{"required": []string{"connectedAt"}, "properties": schema{"outcome": false, "endedAt": false}},
		},
		schema{
			"if":   schema{"properties": schema{"state": schema{"const": string(paasv1.TerminalSessionEnded)}}, "required": []string{"state"}},
			"then": schema{"required": []string{"outcome", "endedAt"}},
		},
	}
	object(schemas["DeploymentResourceSnapshot"])["properties"].(schema)["state"] = schema{
		"type": "string",
		"enum": stringsOf(
			paasv1.MeasurementAvailable,
			paasv1.MeasurementStale,
			paasv1.MeasurementUnavailable,
		),
	}
	object(schemas["DeploymentResourceSnapshot"])["allOf"] = []any{
		schema{
			"if":   schema{"properties": schema{"state": schema{"const": string(paasv1.MeasurementUnavailable)}}, "required": []string{"state"}},
			"then": schema{"properties": schema{"value": false}},
		},
		schema{
			"if": schema{"properties": schema{"state": schema{
				"enum": stringsOf(paasv1.MeasurementAvailable, paasv1.MeasurementStale),
			}}, "required": []string{"state"}},
			"then": schema{"required": []string{"value"}},
		},
	}
	for _, name := range []string{
		"DeploymentInstanceCPUUsage", "DeploymentInstanceMemoryUsage",
		"DeploymentInstanceNetworkUsage", "DeploymentInstanceBlockIOUsage",
		"DeploymentInstanceStorageUsage",
	} {
		states := stringsOf(
			paasv1.MeasurementAvailable,
			paasv1.MeasurementUnavailable,
			paasv1.MeasurementUnsupported,
		)
		if name == "DeploymentInstanceCPUUsage" {
			states = append(states, string(paasv1.MeasurementWarmingUp))
		}
		if name == "DeploymentInstanceStorageUsage" {
			states = append(states, string(paasv1.MeasurementStale))
		}
		object(schemas[name])["properties"].(schema)["state"] = schema{"type": "string", "enum": states}
		object(schemas[name])["allOf"] = []any{
			schema{
				"if": schema{"properties": schema{"state": schema{
					"enum": stringsOf(paasv1.MeasurementAvailable, paasv1.MeasurementStale),
				}}, "required": []string{"state"}},
				"then": schema{"required": []string{"value"}},
			},
			schema{
				"if": schema{"properties": schema{"state": schema{
					"enum": stringsOf(paasv1.MeasurementUnavailable, paasv1.MeasurementUnsupported, paasv1.MeasurementWarmingUp),
				}}, "required": []string{"state"}},
				"then": schema{"properties": schema{"value": false}},
			},
		}
	}
	storage := object(schemas["DeploymentInstanceStorageUsageValue"])
	storage["properties"].(schema)["volumesState"] = schema{
		"type": "string",
		"enum": stringsOf(paasv1.MeasurementAvailable, paasv1.MeasurementUnavailable, paasv1.MeasurementUnsupported),
	}
	storage["allOf"] = []any{
		schema{
			"if":   schema{"properties": schema{"volumesState": schema{"const": string(paasv1.MeasurementAvailable)}}, "required": []string{"volumesState"}},
			"then": schema{"required": []string{"volumes"}},
		},
		schema{
			"if": schema{"properties": schema{"volumesState": schema{
				"enum": stringsOf(paasv1.MeasurementUnavailable, paasv1.MeasurementUnsupported),
			}}, "required": []string{"volumesState"}},
			"then": schema{"properties": schema{"volumes": false}},
		},
	}
	object(schemas["DeploymentRuntimeInstance"])["allOf"] = []any{
		schema{
			"if":   schema{"required": []string{"exitCode"}},
			"then": schema{"properties": schema{"state": schema{"enum": stringsOf(paasv1.DeploymentInstanceExited, paasv1.DeploymentInstanceDead)}}},
		},
		schema{
			"if":   schema{"properties": schema{"state": schema{"enum": stringsOf(paasv1.DeploymentInstanceExited, paasv1.DeploymentInstanceDead)}}},
			"then": schema{"required": []string{"exitCode"}},
		},
	}
	for _, name := range []string{
		"AdapterCapabilitiesContract", "AdapterCommandEnvelope", "InspectExecutionTargetRequest",
		"ObserveExecutionTargetRequest", "DeploymentExecutionRequest", "ObserveDeploymentRequest",
		"ObserveDeploymentRuntimeRequest",
		"DeploymentEndpointObservation", "DeploymentObservation", "ExecutionTargetObservation",
		"NormalizedAdapterError", "AdapterResult",
	} {
		object(schemas[name])["x-matrix-visibility"] = "internal"
	}

	object(schemas["OperationState"])["x-matrix-terminal-values"] = stringsOf(
		paasv1.OperationSucceeded, paasv1.OperationFailed,
		paasv1.OperationCancelled, paasv1.OperationManualIntervention,
	)
	object(schemas["Operation"])["allOf"] = []any{schema{
		"if": schema{"properties": schema{"action": schema{"enum": stringsOf(paasv1.OperationCreateExecutionPool, paasv1.OperationRegisterExecutionTarget)}}},
		"then": schema{
			"required": []string{"installationId"},
			"properties": schema{
				"scope":       schema{"properties": schema{"kind": schema{"const": string(paasv1.AuthorityPlatform)}, "tenantId": false}},
				"requestedBy": schema{"properties": schema{"type": schema{"const": string(paasv1.SubjectUser)}}},
			},
		},
		"else": schema{"properties": schema{"installationId": false, "scope": schema{"properties": schema{"kind": schema{"const": string(paasv1.AuthorityTenant)}}, "required": []string{"tenantId"}}}},
	}}
	for _, target := range []struct {
		action paasv1.OperationAction
		kind   string
	}{
		{paasv1.OperationCreateExecutionPool, "ExecutionPool"},
		{paasv1.OperationRegisterExecutionTarget, "ExecutionTarget"},
	} {
		operation := object(schemas["Operation"])
		operation["allOf"] = append(operation["allOf"].([]any), schema{
			"if":   schema{"properties": schema{"action": schema{"const": string(target.action)}}},
			"then": schema{"properties": schema{"target": schema{"properties": schema{"kind": schema{"const": target.kind}}}}},
		})
	}

	setArrayMinimum(schemas, "ExecutionPoolSpec", "allowedIsolationGuarantees", 1)
	executionTargetListItems := object(schemas["ExecutionTargetList"])["properties"].(schema)["items"].(schema)
	executionTargetListItems["maxItems"] = paasv1.MaximumExecutionTargetListItems
	usageProperties := object(schemas["ExecutionTargetUsage"])["properties"].(schema)
	usageProperties["filesystems"].(schema)["maxItems"] = paasv1.MaximumObservedFilesystems
	usageProperties["filesystems"].(schema)["minItems"] = 1
	for _, measurement := range []struct {
		name, state string
		values      []string
		warming     bool
	}{
		{"CPUUsage", "state", []string{"value"}, true},
		{"MemoryUsage", "state", []string{"value"}, false},
		{"FilesystemUsage", "state", []string{"value"}, false},
		{"FilesystemUsageValue", "inodesState", []string{"totalInodes", "freeInodes"}, false},
		{"ExecutionTargetUsage", "filesystemsState", []string{"filesystems"}, false},
	} {
		states := stringsOf(paasv1.MeasurementAvailable, paasv1.MeasurementUnavailable, paasv1.MeasurementUnsupported, paasv1.MeasurementStale)
		if measurement.warming {
			states = append(states, string(paasv1.MeasurementWarmingUp))
		}
		properties := object(schemas[measurement.name])["properties"].(schema)
		properties[measurement.state] = schema{"type": "string", "enum": states}
		absent := schema{}
		for _, field := range measurement.values {
			absent[field] = false
		}
		object(schemas[measurement.name])["allOf"] = []any{
			schema{
				"if":   schema{"properties": schema{measurement.state: schema{"const": string(paasv1.MeasurementAvailable)}}, "required": []string{measurement.state}},
				"then": schema{"required": measurement.values},
			},
			schema{
				"if":   schema{"properties": schema{measurement.state: schema{"enum": stringsOf(paasv1.MeasurementUnavailable, paasv1.MeasurementUnsupported, paasv1.MeasurementWarmingUp)}}, "required": []string{measurement.state}},
				"then": schema{"properties": absent},
			},
		}
	}
	object(schemas["FilesystemUsageValue"])["dependentRequired"] = schema{"totalInodes": []string{"freeInodes"}, "freeInodes": []string{"totalInodes"}}
	setIntegerMinimum(schemas, "FilesystemUsageValue", "totalInodes", 1)
	cpuProperties := object(schemas["CPUUsageValue"])["properties"].(schema)
	for _, field := range []string{"utilizationRatio", "ioWaitRatio"} {
		cpuProperties[field].(schema)["maximum"] = 1
	}
	cpuProperties["logicalCpus"] = schema{"type": "integer", "minimum": 1, "maximum": 4096}
	cpuProperties["windowMillis"] = schema{"type": "integer", "minimum": 1, "maximum": 60000}
	filesystemProperties := object(schemas["FilesystemUsage"])["properties"].(schema)
	for field, maximum := range map[string]int{"device": 256, "mountPoint": 1024, "filesystemType": 64} {
		filesystemProperties[field] = schema{"type": "string", "minLength": 1, "maxLength": maximum}
	}
	setArrayUnique(schemas, "ExecutionTargetStatus", "supportedIsolationGuarantees")
	executionTargetStatus := object(schemas["ExecutionTargetStatus"])
	executionTargetStatus["allOf"] = []any{schema{
		"if": schema{
			"properties": schema{"health": schema{"const": string(paasv1.ExecutionTargetHealthReady)}},
			"required":   []string{"health"},
		},
		"then": schema{
			"properties": schema{"supportedIsolationGuarantees": schema{"minItems": 1}},
		},
	}}
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
	setIntegerMinimum(schemas, "RollbackDeploymentRequest", "sourceGeneration", 1)
	setIntegerMinimum(schemas, "Readiness", "schemaVersion", 1)
	setIntegerMinimum(schemas, "InstallationVerification", "generation", 1)

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
	setArrayUnique(schemas, owner, property)
	properties := object(schemas[owner])["properties"].(schema)
	object(properties[property])["minItems"] = minimum
}

func setArrayUnique(schemas map[string]any, owner, property string) {
	properties := object(schemas[owner])["properties"].(schema)
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
