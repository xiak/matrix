package devopsv1

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestEveryDevOpsOpenAPISchemaCompiles(t *testing.T) {
	document := loadDevOpsOpenAPI(t)
	for name := range devOpsOpenAPISchemas(t, document) {
		t.Run(name, func(t *testing.T) {
			_ = compileDevOpsOpenAPISchema(t, document, name)
		})
	}
}

func TestDevOpsExamplesValidateAgainstOpenAPI(t *testing.T) {
	document := loadDevOpsOpenAPI(t)
	examples := map[string]string{
		"examples/create-devops-project-request.json":     "CreateDevOpsProjectRequest",
		"examples/devops-project.json":                    "DevOpsProject",
		"examples/create-source-connection-request.json":  "CreateSourceConnectionRequest",
		"examples/update-source-connection-request.json":  "UpdateSourceConnectionRequest",
		"examples/source-connection.json":                 "SourceConnection",
		"examples/create-repository-binding-request.json": "CreateRepositoryBindingRequest",
		"examples/update-repository-binding-request.json": "UpdateRepositoryBindingRequest",
		"examples/repository-binding.json":                "RepositoryBinding",
		"examples/create-pipeline-request.json":           "CreatePipelineRequest",
		"examples/update-pipeline-draft-request.json":     "UpdatePipelineDraftRequest",
		"examples/pipeline.json":                          "Pipeline",
		"examples/pipeline-revision.json":                 "PipelineRevision",
		"examples/pipeline-activation.json":               "PipelineActivation",
		"examples/source-event.json":                      "SourceEvent",
		"examples/pipeline-run.json":                      "PipelineRun",
		"examples/pipeline-run-log-page.json":             "PipelineRunLogPage",
		"examples/readiness.json":                         "Readiness",
		"examples/problem.json":                           "Problem",
	}
	for path, schemaName := range examples {
		t.Run(path, func(t *testing.T) {
			source, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(source))
			if err != nil {
				t.Fatalf("decode %s: %v", path, err)
			}
			if err := compileDevOpsOpenAPISchema(t, document, schemaName).Validate(instance); err != nil {
				t.Fatalf("%s does not satisfy %s: %v", path, schemaName, err)
			}
		})
	}
}

func TestPipelineRunLogEndpointIsFixedCursorAndPubliclySanitized(t *testing.T) {
	document := loadDevOpsOpenAPI(t)
	paths := document["paths"].(map[string]any)
	operation := paths["/v1/runs/{runId}/logs"].(map[string]any)["get"].(map[string]any)
	parameters := operation["parameters"].([]any)
	if len(parameters) != 2 || parameters[0].(map[string]any)["name"] != "runId" ||
		parameters[1].(map[string]any)["name"] != "afterSequence" {
		t.Fatalf("PipelineRun log parameters = %#v", parameters)
	}
	query := parameters[1].(map[string]any)["schema"].(map[string]any)
	if query["default"] != float64(0) || query["maximum"] != float64(FixedMaxLogBytes) {
		t.Fatalf("PipelineRun log cursor schema = %#v", query)
	}
	schema := compileDevOpsOpenAPISchema(t, document, "PipelineRunLogPage")
	page := loadDevOpsSchemaExample(t, "examples/pipeline-run-log-page.json")
	chunk := page["chunks"].([]any)[0].(map[string]any)
	chunk["executionId"] = "sha256:" + strings.Repeat("f", 64)
	if err := schema.Validate(page); err == nil {
		t.Fatal("executor identity crossed the public PipelineRun log schema")
	}
}

func TestDevOpsSchemasRejectAuthorityAndTrustedProfileDrift(t *testing.T) {
	document := loadDevOpsOpenAPI(t)
	createSchema := compileDevOpsOpenAPISchema(t, document, "CreatePipelineRequest")
	request := loadDevOpsSchemaExample(t, "examples/create-pipeline-request.json")
	request["tenantId"] = "organization-forged"
	if err := createSchema.Validate(request); err == nil {
		t.Fatal("caller-supplied tenant authority passed schema validation")
	}

	connectionSchema := compileDevOpsOpenAPISchema(t, document, "CreateSourceConnectionRequest")
	connection := loadDevOpsSchemaExample(t, "examples/create-source-connection-request.json")
	connection["spec"].(map[string]any)["endpointOrigin"] = "https://localhost"
	if err := connectionSchema.Validate(connection); err == nil {
		t.Fatal("loopback source endpoint passed schema validation")
	}
	connectionResourceSchema := compileDevOpsOpenAPISchema(t, document, "SourceConnection")
	connectionResource := loadDevOpsSchemaExample(t, "examples/source-connection.json")
	connectionResource["status"].(map[string]any)["reason"] = "OBSERVED"
	if err := connectionResourceSchema.Validate(connectionResource); err == nil {
		t.Fatal("mismatched source health reason passed schema validation")
	}

	bindingSchema := compileDevOpsOpenAPISchema(t, document, "CreateRepositoryBindingRequest")
	binding := loadDevOpsSchemaExample(t, "examples/create-repository-binding-request.json")
	binding["spec"].(map[string]any)["trustedDefaultBranch"] = "feature/../main"
	if err := bindingSchema.Validate(binding); err == nil {
		t.Fatal("unsafe trusted branch passed schema validation")
	}
	bindingResourceSchema := compileDevOpsOpenAPISchema(t, document, "RepositoryBinding")
	bindingResource := loadDevOpsSchemaExample(t, "examples/repository-binding.json")
	bindingResource["status"].(map[string]any)["reason"] = "OBSERVED"
	if err := bindingResourceSchema.Validate(bindingResource); err == nil {
		t.Fatal("mismatched repository health reason passed schema validation")
	}

	revisionSchema := compileDevOpsOpenAPISchema(t, document, "PipelineRevision")
	revision := loadDevOpsSchemaExample(t, "examples/pipeline-revision.json")
	revision["spec"].(map[string]any)["toolchainImageDigest"] = "sha256:" + strings.Repeat("f", 64)
	if err := revisionSchema.Validate(revision); err == nil {
		t.Fatal("unapproved toolchain passed schema validation")
	}

	revision = loadDevOpsSchemaExample(t, "examples/pipeline-revision.json")
	revision["spec"].(map[string]any)["repositoryBindingDigest"] = "sha256:" + strings.Repeat("f", 64)
	if err := revisionSchema.Validate(revision); err != nil {
		// The schema can validate digest shape but only executable validation can
		// bind it to a stored RepositoryBinding snapshot.
		t.Fatalf("well-formed repository binding digest rejected by schema: %v", err)
	}

	revision = loadDevOpsSchemaExample(t, "examples/pipeline-revision.json")
	steps := revision["spec"].(map[string]any)["steps"].([]any)
	steps[0], steps[1] = steps[1], steps[0]
	if err := revisionSchema.Validate(revision); err == nil {
		t.Fatal("reordered verification steps passed schema validation")
	}

	revision = loadDevOpsSchemaExample(t, "examples/pipeline-revision.json")
	revision["spec"].(map[string]any)["limits"].(map[string]any)["processLimit"] = float64(257)
	if err := revisionSchema.Validate(revision); err == nil {
		t.Fatal("changed execution limit passed schema validation")
	}

	eventSchema := compileDevOpsOpenAPISchema(t, document, "SourceEvent")
	event := loadDevOpsSchemaExample(t, "examples/source-event.json")
	event["spec"].(map[string]any)["change"].(map[string]any)["headCommit"] = strings.Repeat("A", 40)
	if err := eventSchema.Validate(event); err == nil {
		t.Fatal("uppercase Git object ID passed schema validation")
	}

	runSchema := compileDevOpsOpenAPISchema(t, document, "PipelineRun")
	run := loadDevOpsSchemaExample(t, "examples/pipeline-run.json")
	run["inputDigest"] = "sha256:" + strings.Repeat("e", 64)
	if err := runSchema.Validate(run); err != nil {
		// JSON Schema can constrain digest shape, while executable validation
		// binds the digest to the complete immutable input.
		t.Fatalf("well-formed changed run input digest rejected by schema: %v", err)
	}

	run = loadDevOpsSchemaExample(t, "examples/pipeline-run.json")
	run["status"].(map[string]any)["resourceVersion"] = float64(2)
	if err := runSchema.Validate(run); err == nil {
		t.Fatal("queued run with changed resource version passed schema validation")
	}
}

func TestPipelineActivationEndpointAcceptsNoCallerBody(t *testing.T) {
	document := loadDevOpsOpenAPI(t)
	paths := document["paths"].(map[string]any)
	operation := paths["/v1/pipelines/{pipelineId}/activate"].(map[string]any)["post"].(map[string]any)
	if _, found := operation["requestBody"]; found {
		t.Fatal("Pipeline activation unexpectedly accepts caller-controlled content")
	}
	parameters := operation["parameters"].([]any)
	want := map[string]bool{
		"#/components/parameters/IdempotencyKey": false,
		"#/components/parameters/IfMatch":        false,
	}
	for _, raw := range parameters {
		parameter := raw.(map[string]any)
		if reference, ok := parameter["$ref"].(string); ok {
			if _, tracked := want[reference]; tracked {
				want[reference] = true
			}
		}
	}
	for reference, found := range want {
		if !found {
			t.Errorf("activation is missing %s", reference)
		}
	}
}

func TestPipelineRunCancellationEndpointAcceptsNoCallerBodyAndRequiresGuards(t *testing.T) {
	document := loadDevOpsOpenAPI(t)
	paths := document["paths"].(map[string]any)
	operation := paths["/v1/runs/{runId}/cancel"].(map[string]any)["post"].(map[string]any)
	if _, found := operation["requestBody"]; found {
		t.Fatal("PipelineRun cancellation unexpectedly accepts caller-controlled content")
	}
	parameters := operation["parameters"].([]any)
	if len(parameters) != 3 || parameters[0].(map[string]any)["name"] != "runId" ||
		parameters[1].(map[string]any)["$ref"] != "#/components/parameters/IdempotencyKey" ||
		parameters[2].(map[string]any)["$ref"] != "#/components/parameters/IfMatch" {
		t.Fatalf("PipelineRun cancellation parameters = %#v", parameters)
	}
	if _, found := paths["/v1/runs/{runId}"].(map[string]any)["get"]; !found {
		t.Fatal("PipelineRun read operation is missing")
	}
}

func TestPipelineRunReplaySchemaAndEndpointSealTheManualCause(t *testing.T) {
	document := loadDevOpsOpenAPI(t)
	runSchema := compileDevOpsOpenAPISchema(t, document, "PipelineRun")
	run := loadDevOpsSchemaExample(t, "examples/pipeline-run.json")
	run["replay"] = map[string]any{
		"sourceRunId": "pipeline-run-" + strings.Repeat("8", 48),
		"commandId":   "operation-" + strings.Repeat("9", 64),
		"requestedBy": map[string]any{
			"kind": string(SubjectUser), "id": "user-replay",
		},
	}
	if err := runSchema.Validate(run); err != nil {
		t.Fatalf("valid replay cause rejected by schema: %v", err)
	}
	run["replay"].(map[string]any)["sourceRunId"] = "pipeline-run-forged"
	if err := runSchema.Validate(run); err == nil {
		t.Fatal("noncanonical replay source passed schema validation")
	}

	paths := document["paths"].(map[string]any)
	operation := paths["/v1/runs/{runId}/replay"].(map[string]any)["post"].(map[string]any)
	if _, found := operation["requestBody"]; found {
		t.Fatal("PipelineRun replay unexpectedly accepts caller-controlled content")
	}
	parameters := operation["parameters"].([]any)
	if len(parameters) != 3 || parameters[0].(map[string]any)["name"] != "runId" ||
		parameters[1].(map[string]any)["$ref"] != "#/components/parameters/IdempotencyKey" ||
		parameters[2].(map[string]any)["$ref"] != "#/components/parameters/IfMatch" {
		t.Fatalf("PipelineRun replay parameters = %#v", parameters)
	}
	pathSchema := parameters[0].(map[string]any)["schema"].(map[string]any)
	if pathSchema["pattern"] != `^pipeline-run-[0-9a-f]{48}$` {
		t.Fatalf("PipelineRun replay path schema = %#v", pathSchema)
	}
	responses := operation["responses"].(map[string]any)
	created := responses["201"].(map[string]any)
	headers := created["headers"].(map[string]any)
	if headers["ETag"] == nil || headers["Location"] == nil {
		t.Fatalf("PipelineRun replay responses = %#v", responses)
	}
	tooManyRequests := responses["429"].(map[string]any)
	retryHeaders := tooManyRequests["headers"].(map[string]any)
	if retryHeaders["Retry-After"].(map[string]any)["$ref"] != "#/components/headers/RetryAfter" {
		t.Fatalf("PipelineRun replay 429 response = %#v", tooManyRequests)
	}
}

func TestPipelineRevisionReadBindsParentPipelineAndReadinessIsAnonymous(t *testing.T) {
	document := loadDevOpsOpenAPI(t)
	paths := document["paths"].(map[string]any)
	if _, legacy := paths["/v1/pipeline-revisions/{pipelineRevisionId}"]; legacy {
		t.Fatal("unscoped Pipeline revision route remains in the v1 contract")
	}
	operation := paths["/v1/pipelines/{pipelineId}/revisions/{pipelineRevisionId}"].(map[string]any)["get"].(map[string]any)
	parameters := operation["parameters"].([]any)
	if len(parameters) != 2 || parameters[0].(map[string]any)["name"] != "pipelineId" ||
		parameters[1].(map[string]any)["name"] != "pipelineRevisionId" {
		t.Fatalf("Pipeline revision parameters = %#v", parameters)
	}
	readiness := paths["/ready"].(map[string]any)["get"].(map[string]any)
	security, found := readiness["security"].([]any)
	if !found || len(security) != 0 {
		t.Fatalf("readiness security = %#v", readiness["security"])
	}
}

func TestProblemSchemaBindsCodeToHTTPStatus(t *testing.T) {
	schema := compileDevOpsOpenAPISchema(t, loadDevOpsOpenAPI(t), "Problem")
	problem := loadDevOpsSchemaExample(t, "examples/problem.json")
	problem["status"] = float64(409)
	if err := schema.Validate(problem); err == nil {
		t.Fatal("precondition error with conflict status passed schema validation")
	}
}

func TestDevOpsOpenAPIContainsNoProviderOrExecutorImplementation(t *testing.T) {
	encoded, err := json.Marshal(loadDevOpsOpenAPI(t))
	if err != nil {
		t.Fatalf("encode OpenAPI: %v", err)
	}
	normalized := strings.ToLower(string(encoded))
	for _, forbidden := range []string{"gitea", "jenkins", "prow", "docker", "gvisor", "runsc"} {
		if strings.Contains(normalized, forbidden) {
			t.Errorf("provider-neutral OpenAPI contains implementation term %q", forbidden)
		}
	}
}
