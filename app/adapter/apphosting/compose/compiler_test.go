package compose

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

type artifactFixture struct {
	images map[string]VerifiedImage
	err    error
	calls  *int
}

func (fixture artifactFixture) ResolveVerifiedImage(
	_ context.Context,
	artifact paasv1.ArtifactRef,
) (VerifiedImage, error) {
	if fixture.calls != nil {
		(*fixture.calls)++
	}
	if fixture.err != nil {
		return VerifiedImage{}, fixture.err
	}
	image, found := fixture.images[artifact.Digest]
	if !found {
		return VerifiedImage{}, errors.New("fixture image is absent")
	}
	return image, nil
}

func TestCompilerProducesDeterministicClosedComposeProfile(t *testing.T) {
	request, resolver := compileFixture(t)
	compiler, err := NewCompiler(resolver)
	if err != nil {
		t.Fatalf("new compiler: %v", err)
	}
	baseline, err := compiler.Compile(context.Background(), request)
	if err != nil {
		t.Fatalf("compile baseline: %v", err)
	}

	reordered := cloneCompileRequest(t, request)
	reverseCompile(reordered.Generation.Spec.Components)
	reverseCompile(reordered.Generation.Spec.Components[1].Bindings)
	reverseCompile(reordered.ApplicationRevision.Spec.Components)
	reverseCompile(reordered.ApplicationRevision.Spec.Components[1].Endpoints)
	reverseCompile(reordered.ApplicationRevision.Spec.Components[1].Inputs)
	reordered.ConfigurationRevisions[0].Spec.Values = map[string]string{
		"PORT":      "8080",
		"LOG_LEVEL": "info",
	}
	reordered.Command.RequestDigest = paasv1.DeploymentExecutionRequestDigest(reordered)
	candidate, err := compiler.Compile(context.Background(), reordered)
	if err != nil {
		t.Fatalf("compile reordered input: %v", err)
	}
	if baseline.ProjectName != candidate.ProjectName ||
		baseline.DocumentDigest != candidate.DocumentDigest ||
		!reflect.DeepEqual(baseline.Document, candidate.Document) ||
		!reflect.DeepEqual(baseline.SecretFiles, candidate.SecretFiles) {
		t.Fatal("semantic collection/map reordering changed the execution plan")
	}

	var document composeDocument
	if err := json.Unmarshal(baseline.Document, &document); err != nil {
		t.Fatalf("decode compiled document: %v", err)
	}
	if len(document.Services) != 2 {
		t.Fatalf("services = %d, want 2", len(document.Services))
	}
	web := document.Services["web"]
	if web.Image != testDigest('c') || web.PullPolicy != "never" {
		t.Fatalf("web image profile = %#v", web)
	}
	if web.Environment["LOG_LEVEL"] != "info" || web.Environment["PORT"] != "8080" {
		t.Fatalf("web environment = %#v", web.Environment)
	}
	if web.Deploy.Replicas != 2 ||
		web.Deploy.Resources.Limits.CPUs != "0.1" ||
		web.Deploy.Resources.Limits.Memory != "134217728b" {
		t.Fatalf("web resource profile = %#v", web.Deploy)
	}
	if len(web.Secrets) != 1 || web.Secrets[0].Target != "database" || web.Secrets[0].Mode != 0o444 {
		t.Fatalf("web secret grants = %#v", web.Secrets)
	}
	if len(baseline.SecretFiles) != 1 ||
		baseline.SecretFiles[0].Reference.SecretID != "secret-demo-db" ||
		baseline.SecretFiles[0].Reference.Version != "version-0001" ||
		!strings.HasPrefix(baseline.SecretFiles[0].RelativePath, "secrets/secret-") {
		t.Fatalf("secret file plan = %#v", baseline.SecretFiles)
	}
	secret := document.Secrets[web.Secrets[0].Source]
	if secret.File != baseline.SecretFiles[0].RelativePath {
		t.Fatalf("Compose secret file = %q, want %q", secret.File, baseline.SecretFiles[0].RelativePath)
	}
	if strings.Contains(string(baseline.Document), "secret-demo-db") ||
		strings.Contains(string(baseline.Document), "version-0001") {
		t.Fatal("Compose document exposes secret-provider identity")
	}

	var raw map[string]any
	if err := json.Unmarshal(baseline.Document, &raw); err != nil {
		t.Fatalf("decode raw Compose document: %v", err)
	}
	services := raw["services"].(map[string]any)
	for name, value := range services {
		service := value.(map[string]any)
		for _, forbidden := range []string{
			"build", "command", "entrypoint", "network_mode", "ports", "privileged", "volumes",
		} {
			if _, found := service[forbidden]; found {
				t.Errorf("service %q admits forbidden Compose capability %q", name, forbidden)
			}
		}
	}
	if _, found := raw["networks"]; found {
		t.Fatal("v0.1 must use only the project-scoped implicit default network")
	}
}

func TestCompilerRejectsInputOutsideComposeV01Profile(t *testing.T) {
	baseline, resolver := compileFixture(t)
	tests := map[string]struct {
		mutate   func(*paasv1.DeploymentExecutionRequest)
		resolver ArtifactResolver
		want     string
	}{
		"artifact kind": {
			mutate: func(value *paasv1.DeploymentExecutionRequest) {
				value.ApplicationRevision.Spec.Components[0].Artifact.Kind = paasv1.ArtifactOCIArtifact
			},
			want: "unsupported artifact kind",
		},
		"isolation": {
			mutate: func(value *paasv1.DeploymentExecutionRequest) {
				value.Placement.RequestedIsolationGuarantee = paasv1.IsolationTenant
				value.Placement.GrantedIsolationGuarantee = paasv1.IsolationTenant
			},
			want: "only WORKLOAD",
		},
		"stopped desired state": {
			mutate: func(value *paasv1.DeploymentExecutionRequest) {
				value.Generation.Spec.DesiredState = paasv1.DeploymentDesiredStopped
				value.Generation.ContentDigest = paasv1.DeploymentSpecContentDigest(value.Generation.Spec)
			},
			want: "requires RUNNING",
		},
		"missing resource limit": {
			mutate: func(value *paasv1.DeploymentExecutionRequest) {
				value.ApplicationRevision.Spec.Components[0].Resources.CPUMillis = 0
			},
			want: "positive CPU and memory",
		},
		"unverified local image": {
			resolver: artifactFixture{images: map[string]VerifiedImage{
				testDigest('a'): {ArtifactDigest: testDigest('f'), LocalReference: testDigest('c')},
				testDigest('b'): {ArtifactDigest: testDigest('b'), LocalReference: testDigest('d')},
			}},
			want: "unverified image",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			request := cloneCompileRequest(t, baseline)
			if test.mutate != nil {
				test.mutate(&request)
			}
			request.Command.RequestDigest = paasv1.DeploymentExecutionRequestDigest(request)
			selectedResolver := resolver
			if test.resolver != nil {
				selectedResolver = test.resolver
			}
			compiler, err := NewCompiler(selectedResolver)
			if err != nil {
				t.Fatalf("new compiler: %v", err)
			}
			if _, err := compiler.Compile(context.Background(), request); err == nil ||
				!strings.Contains(err.Error(), test.want) {
				t.Fatalf("unsupported input must fail with %q, got %v", test.want, err)
			}
		})
	}
}

func TestCompilerRejectsConfigurationKeyCollisionsBeforeArtifactEffect(t *testing.T) {
	request, resolver := compileFixture(t)
	request.ApplicationRevision.Spec.Components[0].Inputs = append(
		request.ApplicationRevision.Spec.Components[0].Inputs,
		paasv1.ComponentInput{
			Name: "override", Kind: paasv1.InputConfiguration,
			Injection: paasv1.InjectionEnvironment, Required: true,
		},
	)
	request.Generation.Spec.Components[0].Bindings = append(
		request.Generation.Spec.Components[0].Bindings,
		paasv1.ComponentBinding{Name: "override", ConfigurationRevisionID: "configuration-revision-override"},
	)
	override := request.ConfigurationRevisions[0]
	override.Metadata.ID = "configuration-revision-override"
	override.Metadata.Name = "configuration-override"
	override.Spec.ConfigurationID = "configuration-override"
	override.Spec.Values = map[string]string{"LOG_LEVEL": "debug"}
	override.Spec.ContentDigest = paasv1.ConfigurationValuesDigest(override.Spec.Values)
	request.ConfigurationRevisions = append(request.ConfigurationRevisions, override)
	request.Generation.ContentDigest = paasv1.DeploymentSpecContentDigest(request.Generation.Spec)
	request.Command.RequestDigest = paasv1.DeploymentExecutionRequestDigest(request)

	resolverCalls := 0
	countedResolver := resolver.(artifactFixture)
	countedResolver.calls = &resolverCalls
	compiler, err := NewCompiler(countedResolver)
	if err != nil {
		t.Fatalf("new compiler: %v", err)
	}
	if _, err := compiler.Compile(context.Background(), request); err == nil ||
		!strings.Contains(err.Error(), "conflicting configuration key") {
		t.Fatalf("configuration collision must fail closed, got %v", err)
	}
	if resolverCalls != 0 {
		t.Fatalf("artifact resolver calls = %d, want 0 before semantic validation completes", resolverCalls)
	}
}

func compileFixture(t *testing.T) (paasv1.DeploymentExecutionRequest, ArtifactResolver) {
	t.Helper()
	now := time.Date(2026, 8, 25, 9, 0, 0, 0, time.UTC)
	scope := paasv1.ResourceScope{Kind: paasv1.AuthorityTenant, TenantID: "tenant-a"}
	configuration := paasv1.ConfigurationRevision{
		APIVersion: paasv1.APIVersion,
		Kind:       "ConfigurationRevision",
		Metadata:   immutableMetadata("configuration-revision-demo", "configuration-demo", scope, now),
		Spec: paasv1.ConfigurationRevisionSpec{
			ConfigurationID: "configuration-demo",
			Values:          map[string]string{"LOG_LEVEL": "info", "PORT": "8080"},
		},
	}
	configuration.Spec.ContentDigest = paasv1.ConfigurationValuesDigest(configuration.Spec.Values)
	revision := paasv1.ApplicationRevision{
		APIVersion: paasv1.APIVersion,
		Kind:       "ApplicationRevision",
		Metadata:   immutableMetadata("revision-demo", "revision-demo", scope, now),
		Spec: paasv1.ApplicationRevisionSpec{
			ApplicationID: "application-demo",
			Revision:      "revision-0001",
			ContentDigest: testDigest('e'),
			Components: []paasv1.ApplicationRevisionComponent{
				{
					Name: "web",
					Artifact: paasv1.ArtifactRef{
						Kind: paasv1.ArtifactOCIImage, Locator: "registry.example.invalid/demo/web", Digest: testDigest('a'),
					},
					Resources: paasv1.ResourceRequirements{CPUMillis: 100, MemoryBytes: 128 * 1024 * 1024},
					Endpoints: []paasv1.ApplicationEndpoint{
						{Name: "http", Port: 8080, Protocol: paasv1.EndpointHTTP, Visibility: paasv1.EndpointPublic},
						{Name: "metrics", Port: 9090, Protocol: paasv1.EndpointHTTP, Visibility: paasv1.EndpointPrivate},
					},
					Inputs: []paasv1.ComponentInput{
						{Name: "environment", Kind: paasv1.InputConfiguration, Injection: paasv1.InjectionEnvironment, Required: true},
						{Name: "database", Kind: paasv1.InputSecret, Injection: paasv1.InjectionFile, Required: true},
					},
				},
				{
					Name: "worker",
					Artifact: paasv1.ArtifactRef{
						Kind: paasv1.ArtifactOCIImage, Locator: "registry.example.invalid/demo/worker", Digest: testDigest('b'),
					},
					Resources: paasv1.ResourceRequirements{CPUMillis: 250, MemoryBytes: 256 * 1024 * 1024},
				},
			},
		},
	}
	generation := paasv1.DeploymentGeneration{
		APIVersion:   paasv1.APIVersion,
		Kind:         "DeploymentGeneration",
		Scope:        scope,
		DeploymentID: "deployment-demo",
		Generation:   1,
		Spec: paasv1.DeploymentSpec{
			ApplicationRevisionID: revision.Metadata.ID,
			PlacementPolicyID:     "placement-policy-demo",
			DesiredState:          paasv1.DeploymentDesiredRunning,
			Components: []paasv1.DeploymentComponent{
				{
					Name: "web", Replicas: 2,
					Bindings: []paasv1.ComponentBinding{
						{Name: "environment", ConfigurationRevisionID: configuration.Metadata.ID},
						{Name: "database", SecretVersion: &paasv1.SecretVersionReference{SecretID: "secret-demo-db", Version: "version-0001"}},
					},
				},
				{Name: "worker", Replicas: 1},
			},
		},
		CreatedByOperationID: "operation-deploy-demo",
		CreatedAt:            now,
	}
	generation.ContentDigest = paasv1.DeploymentSpecContentDigest(generation.Spec)
	placement := paasv1.PlacementDecision{
		APIVersion:                     paasv1.APIVersion,
		Kind:                           "PlacementDecision",
		Metadata:                       immutableMetadata("decision-demo", "decision-demo", scope, now),
		DeploymentID:                   generation.DeploymentID,
		DeploymentGeneration:           generation.Generation,
		DeploymentResourceVersion:      2,
		ApplicationRevisionID:          revision.Metadata.ID,
		PlacementPolicyID:              generation.Spec.PlacementPolicyID,
		PolicyResourceVersion:          1,
		RequestedIsolationGuarantee:    paasv1.IsolationWorkload,
		Outcome:                        paasv1.PlacementScheduled,
		ExecutionTargetID:              "target-local",
		ExecutionTargetResourceVersion: 1,
		GrantedIsolationGuarantee:      paasv1.IsolationWorkload,
		CandidateSetDigest:             testDigest('f'),
		DecidedAt:                      now,
	}
	request := paasv1.DeploymentExecutionRequest{
		Command: paasv1.AdapterCommandEnvelope{
			OperationID: "operation-deploy-demo", CommandID: "command-deploy-demo", Attempt: 1,
			Action: paasv1.AdapterApplyDeployment, Scope: scope,
			ApplicationID: revision.Spec.ApplicationID, ApplicationRevisionID: revision.Metadata.ID,
			DeploymentID: generation.DeploymentID, ExecutionTargetID: placement.ExecutionTargetID,
			BindingRef: "binding-local", Deadline: now.Add(5 * time.Minute),
		},
		Generation:             generation,
		ApplicationRevision:    revision,
		ConfigurationRevisions: []paasv1.ConfigurationRevision{configuration},
		Placement:              placement,
	}
	request.Command.RequestDigest = paasv1.DeploymentExecutionRequestDigest(request)
	return request, artifactFixture{images: map[string]VerifiedImage{
		testDigest('a'): {ArtifactDigest: testDigest('a'), LocalReference: testDigest('c')},
		testDigest('b'): {ArtifactDigest: testDigest('b'), LocalReference: testDigest('d')},
	}}
}

func immutableMetadata(
	id paasv1.ResourceID,
	name string,
	scope paasv1.ResourceScope,
	createdAt time.Time,
) paasv1.ResourceMetadata {
	return paasv1.ResourceMetadata{
		ID: id, Name: name, Scope: scope, ResourceVersion: 1,
		CreatedAt: createdAt, UpdatedAt: createdAt,
	}
}

func cloneCompileRequest(t *testing.T, value paasv1.DeploymentExecutionRequest) paasv1.DeploymentExecutionRequest {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("encode request clone: %v", err)
	}
	var result paasv1.DeploymentExecutionRequest
	if err := json.Unmarshal(encoded, &result); err != nil {
		t.Fatalf("decode request clone: %v", err)
	}
	return result
}

func reverseCompile[T any](values []T) {
	for left, right := 0, len(values)-1; left < right; left, right = left+1, right-1 {
		values[left], values[right] = values[right], values[left]
	}
}

func testDigest(character byte) string {
	return "sha256:" + strings.Repeat(string(character), 64)
}
