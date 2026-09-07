package devopsv1

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func validDraftSpec() PipelineDraftSpec {
	return PipelineDraftSpec{
		RepositoryBindingID: "repository-binding-api",
		TriggerPolicy:       TriggerChange,
		VerificationProfile: VerificationGo126OfflineV1,
		DependencyEgress:    DependencyEgressNone,
		ReporterPolicy:      ReporterChangeCheckV1,
	}
}

func validRevisionSpec() PipelineRevisionSpec {
	draft := validDraftSpec()
	return PipelineRevisionSpec{
		RepositoryBindingID:  draft.RepositoryBindingID,
		TriggerPolicy:        draft.TriggerPolicy,
		VerificationProfile:  draft.VerificationProfile,
		ExecutorProfile:      ExecutorMatrixNativeIsolatedV1,
		ToolchainImageDigest: Go126OfflineToolchainImageDigest,
		DependencyEgress:     draft.DependencyEgress,
		ReporterPolicy:       draft.ReporterPolicy,
		Steps:                FixedVerificationSteps(),
		Limits:               FixedVerificationLimits(),
	}
}

func validPipelineActivation(t *testing.T) PipelineActivation {
	t.Helper()
	createdAt := time.Date(2026, 9, 7, 4, 5, 6, 0, time.UTC)
	activatedAt := createdAt.Add(time.Minute)
	scope := ResourceScope{TenantID: "organization-acme"}
	spec := validRevisionSpec()
	digest := PipelineRevisionSpecDigest(spec)
	revisionID, err := PipelineRevisionID(scope, "pipeline-verify-change", 1, digest)
	if err != nil {
		t.Fatalf("derive revision ID: %v", err)
	}
	reference := &PipelineRevisionReference{ID: revisionID, Revision: 1, ContentDigest: digest}
	pipeline := Pipeline{
		APIVersion: APIVersion,
		Kind:       "Pipeline",
		Metadata: ResourceMetadata{
			ID: "pipeline-verify-change", Name: "verify-change", Scope: scope,
			ResourceVersion: 2, CreatedAt: createdAt, UpdatedAt: activatedAt,
		},
		ProjectID: "devops-project-platform",
		Draft: PipelineDraft{
			Spec: validDraftSpec(), ContentDigest: PipelineDraftSpecDigest(validDraftSpec()),
		},
		ActiveRevision: reference,
	}
	revision := PipelineRevision{
		APIVersion: APIVersion, Kind: "PipelineRevision", ID: revisionID,
		Scope: scope, PipelineID: pipeline.Metadata.ID, ProjectID: pipeline.ProjectID,
		Revision: 1, Spec: spec, ContentDigest: digest,
		ActivatedBy: SubjectRef{Kind: SubjectUser, ID: "user-alice"}, ActivatedAt: activatedAt,
	}
	return PipelineActivation{
		APIVersion: APIVersion, Kind: "PipelineActivation",
		Pipeline: pipeline, Revision: revision,
	}
}

func loadDevOpsOpenAPI(t *testing.T) map[string]any {
	t.Helper()
	source, err := os.ReadFile("openapi.json")
	if err != nil {
		t.Fatalf("read openapi.json: %v", err)
	}
	var document map[string]any
	if err := json.Unmarshal(source, &document); err != nil {
		t.Fatalf("decode openapi.json: %v", err)
	}
	return document
}

func devOpsOpenAPISchemas(t *testing.T, document map[string]any) map[string]any {
	t.Helper()
	components, ok := document["components"].(map[string]any)
	if !ok {
		t.Fatal("OpenAPI components are missing")
	}
	schemas, ok := components["schemas"].(map[string]any)
	if !ok {
		t.Fatal("OpenAPI component schemas are missing")
	}
	return schemas
}

func compileDevOpsOpenAPISchema(
	t *testing.T,
	document map[string]any,
	name string,
) *jsonschema.Schema {
	t.Helper()
	wrapper := map[string]any{
		"$schema":    "https://json-schema.org/draft/2020-12/schema",
		"$ref":       "#/components/schemas/" + name,
		"components": document["components"],
	}
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	resource := "https://devops.matrix.xiak.com/contracts/" + name + ".json"
	if err := compiler.AddResource(resource, wrapper); err != nil {
		t.Fatalf("add %s schema resource: %v", name, err)
	}
	schema, err := compiler.Compile(resource)
	if err != nil {
		t.Fatalf("compile %s schema: %v", name, err)
	}
	return schema
}

func loadDevOpsSchemaExample(t *testing.T, path string) map[string]any {
	t.Helper()
	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(source))
	if err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	object, ok := instance.(map[string]any)
	if !ok {
		t.Fatalf("%s contains %T, want object", path, instance)
	}
	return object
}

func decodeDevOpsExample[T any](t *testing.T, path string) T {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer file.Close()
	var value T
	if err := Decode(file, &value); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return value
}
