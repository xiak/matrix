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
	connection["spec"].(map[string]any)["allowedEndpointOrigins"] = []any{"https://localhost"}
	if err := connectionSchema.Validate(connection); err == nil {
		t.Fatal("loopback source endpoint passed schema validation")
	}

	bindingSchema := compileDevOpsOpenAPISchema(t, document, "CreateRepositoryBindingRequest")
	binding := loadDevOpsSchemaExample(t, "examples/create-repository-binding-request.json")
	binding["spec"].(map[string]any)["trustedDefaultBranch"] = "feature/../main"
	if err := bindingSchema.Validate(binding); err == nil {
		t.Fatal("unsafe trusted branch passed schema validation")
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
