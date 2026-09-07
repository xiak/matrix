package devopsv1

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/xiak/matrix/api/contractjson"
)

func TestDevOpsContractsAcceptTrustedActivation(t *testing.T) {
	activation := validPipelineActivation(t)
	if err := ValidatePipelineActivation(activation); err != nil {
		t.Fatalf("validate activation: %v", err)
	}
	project := DevOpsProject{
		APIVersion: APIVersion, Kind: "DevOpsProject",
		Metadata: ResourceMetadata{
			ID: "devops-project-platform", Name: "platform", Scope: activation.Pipeline.Metadata.Scope,
			ResourceVersion: 1, CreatedAt: activation.Pipeline.Metadata.CreatedAt,
			UpdatedAt: activation.Pipeline.Metadata.CreatedAt,
		},
	}
	if err := ValidateDevOpsProject(project); err != nil {
		t.Fatalf("validate project: %v", err)
	}
	connection := SourceConnection{
		APIVersion: APIVersion, Kind: "SourceConnection",
		Metadata: ResourceMetadata{
			ID: "source-connection-primary", Name: "primary", Scope: activation.Pipeline.Metadata.Scope,
			ResourceVersion: 1, CreatedAt: activation.Pipeline.Metadata.CreatedAt,
			UpdatedAt: activation.Pipeline.Metadata.CreatedAt,
		},
		Spec: validSourceConnectionSpec(),
		Status: SourceConnectionStatus{
			Health: SourceConnectionPending, ObservedAt: activation.Pipeline.Metadata.CreatedAt,
		},
	}
	if err := ValidateSourceConnection(connection); err != nil {
		t.Fatalf("validate source connection: %v", err)
	}
	bindingSpec := validRepositoryBindingSpec()
	binding := RepositoryBinding{
		APIVersion: APIVersion, Kind: "RepositoryBinding",
		Metadata: ResourceMetadata{
			ID: "repository-binding-api", Name: "api", Scope: activation.Pipeline.Metadata.Scope,
			ResourceVersion: 1, CreatedAt: activation.Pipeline.Metadata.CreatedAt,
			UpdatedAt: activation.Pipeline.Metadata.CreatedAt,
		},
		ProjectID: "devops-project-platform", Spec: bindingSpec,
		ContentDigest: RepositoryBindingSpecDigest(bindingSpec),
		Status: RepositoryBindingStatus{
			Health: RepositoryBindingPending, ObservedAt: activation.Pipeline.Metadata.CreatedAt,
		},
	}
	if err := ValidateRepositoryBinding(binding); err != nil {
		t.Fatalf("validate repository binding: %v", err)
	}
}

func TestDevOpsExamplesPassExecutableValidation(t *testing.T) {
	projectRequest := decodeDevOpsExample[CreateDevOpsProjectRequest](t, "examples/create-devops-project-request.json")
	if err := ValidateCreateDevOpsProjectRequest(projectRequest); err != nil {
		t.Fatalf("validate project request: %v", err)
	}
	project := decodeDevOpsExample[DevOpsProject](t, "examples/devops-project.json")
	if err := ValidateDevOpsProject(project); err != nil {
		t.Fatalf("validate project: %v", err)
	}
	connectionRequest := decodeDevOpsExample[CreateSourceConnectionRequest](t, "examples/create-source-connection-request.json")
	if err := ValidateCreateSourceConnectionRequest(connectionRequest); err != nil {
		t.Fatalf("validate source connection request: %v", err)
	}
	connectionUpdate := decodeDevOpsExample[UpdateSourceConnectionRequest](t, "examples/update-source-connection-request.json")
	if err := ValidateUpdateSourceConnectionRequest(connectionUpdate); err != nil {
		t.Fatalf("validate source connection update: %v", err)
	}
	connection := decodeDevOpsExample[SourceConnection](t, "examples/source-connection.json")
	if err := ValidateSourceConnection(connection); err != nil {
		t.Fatalf("validate source connection: %v", err)
	}
	bindingRequest := decodeDevOpsExample[CreateRepositoryBindingRequest](t, "examples/create-repository-binding-request.json")
	if err := ValidateCreateRepositoryBindingRequest(bindingRequest); err != nil {
		t.Fatalf("validate repository binding request: %v", err)
	}
	bindingUpdate := decodeDevOpsExample[UpdateRepositoryBindingRequest](t, "examples/update-repository-binding-request.json")
	if err := ValidateUpdateRepositoryBindingRequest(bindingUpdate); err != nil {
		t.Fatalf("validate repository binding update: %v", err)
	}
	binding := decodeDevOpsExample[RepositoryBinding](t, "examples/repository-binding.json")
	if err := ValidateRepositoryBinding(binding); err != nil {
		t.Fatalf("validate repository binding: %v", err)
	}
	pipelineRequest := decodeDevOpsExample[CreatePipelineRequest](t, "examples/create-pipeline-request.json")
	if err := ValidateCreatePipelineRequest(pipelineRequest); err != nil {
		t.Fatalf("validate Pipeline request: %v", err)
	}
	updateRequest := decodeDevOpsExample[UpdatePipelineDraftRequest](t, "examples/update-pipeline-draft-request.json")
	if err := ValidateUpdatePipelineDraftRequest(updateRequest); err != nil {
		t.Fatalf("validate draft update: %v", err)
	}
	pipeline := decodeDevOpsExample[Pipeline](t, "examples/pipeline.json")
	if err := ValidatePipeline(pipeline); err != nil {
		t.Fatalf("validate Pipeline: %v", err)
	}
	revision := decodeDevOpsExample[PipelineRevision](t, "examples/pipeline-revision.json")
	if err := ValidatePipelineRevision(revision); err != nil {
		t.Fatalf("validate revision: %v", err)
	}
	activation := decodeDevOpsExample[PipelineActivation](t, "examples/pipeline-activation.json")
	if err := ValidatePipelineActivation(activation); err != nil {
		t.Fatalf("validate activation: %v", err)
	}
	problem := decodeDevOpsExample[Problem](t, "examples/problem.json")
	if err := ValidateProblem(problem); err != nil {
		t.Fatalf("validate problem: %v", err)
	}
}

func TestPipelineValidationRejectsAuthorityAndProfileDrift(t *testing.T) {
	valid := validPipelineActivation(t)
	tests := map[string]func(*PipelineActivation){
		"type metadata": func(value *PipelineActivation) {
			value.Pipeline.Kind = "Workflow"
		},
		"tenant": func(value *PipelineActivation) {
			value.Revision.Scope.TenantID = "organization-other"
		},
		"draft digest": func(value *PipelineActivation) {
			value.Pipeline.Draft.ContentDigest = strings.Repeat("0", 71)
		},
		"toolchain": func(value *PipelineActivation) {
			value.Revision.Spec.ToolchainImageDigest = "sha256:" + strings.Repeat("f", 64)
		},
		"step order": func(value *PipelineActivation) {
			value.Revision.Spec.Steps[0], value.Revision.Spec.Steps[1] =
				value.Revision.Spec.Steps[1], value.Revision.Spec.Steps[0]
		},
		"limit": func(value *PipelineActivation) {
			value.Revision.Spec.Limits.ProcessLimit++
		},
		"revision reference": func(value *PipelineActivation) {
			value.Pipeline.ActiveRevision.Revision++
		},
		"actor": func(value *PipelineActivation) {
			value.Revision.ActivatedBy.Kind = SubjectKind("PROVIDER_USER")
		},
		"unsafe JSON version": func(value *PipelineActivation) {
			value.Pipeline.Metadata.ResourceVersion = MaximumContractInteger + 1
		},
		"binding snapshot": func(value *PipelineActivation) {
			value.Revision.Spec.RepositoryBindingDigest = "sha256:" + strings.Repeat("f", 64)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			value := valid
			steps := append([]VerificationStep(nil), valid.Revision.Spec.Steps...)
			value.Revision.Spec.Steps = steps
			if valid.Pipeline.ActiveRevision != nil {
				reference := *valid.Pipeline.ActiveRevision
				value.Pipeline.ActiveRevision = &reference
			}
			mutate(&value)
			if err := ValidatePipelineActivation(value); err == nil {
				t.Fatal("invalid activation was accepted")
			}
		})
	}
}

func TestDevOpsDecoderRejectsForgedAmbiguousAndOversizeInput(t *testing.T) {
	for name, document := range map[string]string{
		"tenant":     `{"id":"pipeline","name":"verify","projectId":"project","draft":{"repositoryBindingId":"binding","triggerPolicy":"CHANGE","verificationProfile":"GO_1_26_OFFLINE_V1","dependencyEgress":"NONE","reporterPolicy":"CHANGE_CHECK_V1"},"tenantId":"forged"}`,
		"credential": `{"id":"pipeline","name":"verify","projectId":"project","draft":{"repositoryBindingId":"binding","triggerPolicy":"CHANGE","verificationProfile":"GO_1_26_OFFLINE_V1","dependencyEgress":"NONE","reporterPolicy":"CHANGE_CHECK_V1","credential":"secret"}}`,
		"duplicate":  `{"draft":{"repositoryBindingId":"one","repositoryBindingId":"two"}}`,
		"trailing":   `{"draft":{"repositoryBindingId":"one"}} {}`,
	} {
		t.Run(name, func(t *testing.T) {
			var target CreatePipelineRequest
			err := Decode(strings.NewReader(document), &target)
			switch name {
			case "tenant", "credential":
				if !errors.Is(err, contractjson.ErrUnknownField) {
					t.Fatalf("forged field error = %v", err)
				}
			case "duplicate":
				if !errors.Is(err, contractjson.ErrDuplicateField) {
					t.Fatalf("duplicate field error = %v", err)
				}
			case "trailing":
				if !errors.Is(err, contractjson.ErrTrailingData) {
					t.Fatalf("trailing data error = %v", err)
				}
			}
		})
	}
	oversize := `{"id":"` + strings.Repeat("x", int(MaxDocumentBytes)) + `"}`
	var target CreatePipelineRequest
	if err := Decode(strings.NewReader(oversize), &target); !errors.Is(err, contractjson.ErrDocumentTooLarge) {
		t.Fatalf("oversize error = %v", err)
	}
}

func TestCallerOwnedRequestsContainNoServerAuthorityOrEscapeHatch(t *testing.T) {
	roots := []reflect.Type{
		reflect.TypeOf(CreateDevOpsProjectRequest{}),
		reflect.TypeOf(CreateSourceConnectionRequest{}),
		reflect.TypeOf(UpdateSourceConnectionRequest{}),
		reflect.TypeOf(CreateRepositoryBindingRequest{}),
		reflect.TypeOf(UpdateRepositoryBindingRequest{}),
		reflect.TypeOf(CreatePipelineRequest{}),
		reflect.TypeOf(UpdatePipelineDraftRequest{}),
	}
	for _, root := range roots {
		assertClosedRequestType(t, root, map[reflect.Type]bool{})
	}
}

func TestSourceAndRepositoryContractsFailClosed(t *testing.T) {
	connection := validSourceConnectionSpec()
	for name, mutate := range map[string]func(*SourceConnectionSpec){
		"plaintext credential alias": func(value *SourceConnectionSpec) {
			value.ReportCredentialRef = value.FetchCredentialRef
		},
		"insecure endpoint": func(value *SourceConnectionSpec) {
			value.AllowedEndpointOrigins = []string{"http://git.internal.example"}
		},
		"endpoint path": func(value *SourceConnectionSpec) {
			value.AllowedEndpointOrigins = []string{"https://git.internal.example/api"}
		},
		"unordered endpoints": func(value *SourceConnectionSpec) {
			value.AllowedEndpointOrigins = []string{
				"https://z.internal.example", "https://a.internal.example",
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			value := connection
			value.AllowedEndpointOrigins = append([]string(nil), connection.AllowedEndpointOrigins...)
			mutate(&value)
			if err := ValidateSourceConnectionSpec(value); err == nil {
				t.Fatal("invalid source connection specification was accepted")
			}
		})
	}
	binding := validRepositoryBindingSpec()
	for name, mutate := range map[string]func(*RepositoryBindingSpec){
		"repository traversal": func(value *RepositoryBindingSpec) { value.RepositoryPath = "../api" },
		"extra path segment":   func(value *RepositoryBindingSpec) { value.RepositoryPath = "org/team/api" },
		"unsafe branch":        func(value *RepositoryBindingSpec) { value.TrustedDefaultBranch = "feature/../main" },
		"lock branch":          func(value *RepositoryBindingSpec) { value.TrustedDefaultBranch = "refs/main.lock" },
	} {
		t.Run(name, func(t *testing.T) {
			value := binding
			mutate(&value)
			if err := ValidateRepositoryBindingSpec(value); err == nil {
				t.Fatal("invalid repository binding specification was accepted")
			}
		})
	}
}

func TestFixedVerificationStepsReturnIndependentCopies(t *testing.T) {
	first := FixedVerificationSteps()
	first[0].Kind = VerificationStepKind("MUTATED")
	second := FixedVerificationSteps()
	if second[0].Kind != VerificationStepGoTest {
		t.Fatal("trusted verification-step catalog was mutable")
	}
}

func TestPipelineDigestsAndIdentitiesAreDeterministicAndScoped(t *testing.T) {
	binding := validRepositoryBindingSpec()
	bindingDigest := RepositoryBindingSpecDigest(binding)
	binding.RepositoryPath = "platform/worker"
	if RepositoryBindingSpecDigest(binding) == bindingDigest {
		t.Fatal("repository binding digest did not bind normalized repository identity")
	}
	draft := validDraftSpec()
	if first, second := PipelineDraftSpecDigest(draft), PipelineDraftSpecDigest(draft); first != second {
		t.Fatalf("draft digest is not deterministic: %q != %q", first, second)
	}
	spec := validRevisionSpec()
	digest := PipelineRevisionSpecDigest(spec)
	first, err := PipelineRevisionID(ResourceScope{TenantID: "tenant-a"}, "pipeline", 1, digest)
	if err != nil {
		t.Fatalf("derive first ID: %v", err)
	}
	second, err := PipelineRevisionID(ResourceScope{TenantID: "tenant-b"}, "pipeline", 1, digest)
	if err != nil {
		t.Fatalf("derive second ID: %v", err)
	}
	if first == second {
		t.Fatal("revision identity did not bind tenant authority")
	}
	spec.Limits.ProcessLimit++
	if PipelineRevisionSpecDigest(spec) == digest {
		t.Fatal("revision digest did not bind execution limits")
	}
}

func TestContractTimeRequiresCanonicalUTCMicroseconds(t *testing.T) {
	valid := validPipelineActivation(t)
	valid.Revision.ActivatedAt = valid.Revision.ActivatedAt.In(time.FixedZone("offset", 0))
	if err := ValidatePipelineRevision(valid.Revision); err == nil {
		t.Fatal("non-UTC location was accepted")
	}
	valid = validPipelineActivation(t)
	valid.Revision.ActivatedAt = valid.Revision.ActivatedAt.Add(time.Nanosecond)
	if err := ValidatePipelineRevision(valid.Revision); err == nil {
		t.Fatal("sub-microsecond timestamp was accepted")
	}
}

func TestProblemCodeAndStatusAreBound(t *testing.T) {
	problem := decodeDevOpsExample[Problem](t, "examples/problem.json")
	problem.Status = 409
	if err := ValidateProblem(problem); err == nil {
		t.Fatal("precondition error with conflict status was accepted")
	}
}

func assertClosedRequestType(t *testing.T, contract reflect.Type, seen map[reflect.Type]bool) {
	t.Helper()
	for contract.Kind() == reflect.Pointer || contract.Kind() == reflect.Slice {
		if contract.Kind() == reflect.Slice && contract.Elem().Kind() == reflect.Uint8 {
			t.Fatalf("request contains raw bytes: %s", contract)
		}
		contract = contract.Elem()
	}
	if contract == reflect.TypeOf(time.Time{}) || seen[contract] {
		return
	}
	seen[contract] = true
	switch contract.Kind() {
	case reflect.Map, reflect.Interface:
		t.Fatalf("request contains arbitrary %s: %s", contract.Kind(), contract)
	case reflect.Struct:
		for index := range contract.NumField() {
			field := contract.Field(index)
			jsonName := strings.Split(field.Tag.Get("json"), ",")[0]
			normalized := strings.ToLower(jsonName)
			for _, forbidden := range []string{
				"tenantid", "scope", "resourceversion", "createdat", "updatedat",
				"actor", "activatedby", "credential", "secret", "payload", "native",
				"command", "argv", "hostpath", "workingdirectory", "image", "steps", "limits", "executorprofile",
			} {
				if normalized == forbidden || strings.HasSuffix(normalized, forbidden) {
					t.Fatalf("request contains server-owned or unsafe field %s.%s", contract, field.Name)
				}
			}
			assertClosedRequestType(t, field.Type, seen)
		}
	}
}
