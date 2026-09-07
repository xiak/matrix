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
		"examples/create-devops-project-request.json": "CreateDevOpsProjectRequest",
		"examples/devops-project.json":                "DevOpsProject",
		"examples/create-pipeline-request.json":       "CreatePipelineRequest",
		"examples/update-pipeline-draft-request.json": "UpdatePipelineDraftRequest",
		"examples/pipeline.json":                      "Pipeline",
		"examples/pipeline-revision.json":             "PipelineRevision",
		"examples/pipeline-activation.json":           "PipelineActivation",
		"examples/problem.json":                       "Problem",
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

	revisionSchema := compileDevOpsOpenAPISchema(t, document, "PipelineRevision")
	revision := loadDevOpsSchemaExample(t, "examples/pipeline-revision.json")
	revision["spec"].(map[string]any)["toolchainImageDigest"] = "sha256:" + strings.Repeat("f", 64)
	if err := revisionSchema.Validate(revision); err == nil {
		t.Fatal("unapproved toolchain passed schema validation")
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
