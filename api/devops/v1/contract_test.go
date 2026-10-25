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
			Health: SourceConnectionPending, Reason: SourceConnectionReasonConfigurationChanged,
			ObservedAt: activation.Pipeline.Metadata.CreatedAt,
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
			Health: RepositoryBindingPending, Reason: RepositoryBindingReasonConfigurationChanged,
			ObservedAt: activation.Pipeline.Metadata.CreatedAt,
		},
	}
	if err := ValidateRepositoryBinding(binding); err != nil {
		t.Fatalf("validate repository binding: %v", err)
	}
}

func TestSourceEventAndPipelineRunContracts(t *testing.T) {
	event := validSourceEvent(t)
	if err := ValidateSourceEvent(event); err != nil {
		t.Fatalf("validate SourceEvent: %v", err)
	}
	run := validPipelineRun(t)
	if err := ValidatePipelineRun(run); err != nil {
		t.Fatalf("validate PipelineRun: %v", err)
	}

	for name, mutate := range map[string]func(*SourceEvent){
		"identity": func(value *SourceEvent) { value.ID = "source-event-forged" },
		"delivery": func(value *SourceEvent) { value.Spec.DeliveryID = "not-a-uuid" },
		"payload digest": func(value *SourceEvent) {
			value.Spec.CanonicalPayloadDigest = "sha256:" + strings.Repeat("f", 64)
		},
		"content digest": func(value *SourceEvent) {
			value.ContentDigest = "sha256:" + strings.Repeat("f", 64)
		},
		"provider action": func(value *SourceEvent) {
			value.Spec.Change.Action = ChangeAction("SYNCHRONIZED")
		},
		"uppercase commit": func(value *SourceEvent) {
			value.Spec.Change.HeadCommit = strings.Repeat("A", 40)
		},
	} {
		t.Run("SourceEvent "+name, func(t *testing.T) {
			value := event
			mutate(&value)
			if err := ValidateSourceEvent(value); err == nil {
				t.Fatal("invalid SourceEvent was accepted")
			}
		})
	}

	for name, mutate := range map[string]func(*PipelineRun){
		"identity": func(value *PipelineRun) { value.ID = "pipeline-run-forged" },
		"event digest": func(value *PipelineRun) {
			value.Input.SourceEventDigest = "sha256:" + strings.Repeat("e", 64)
		},
		"input digest": func(value *PipelineRun) {
			value.InputDigest = "sha256:" + strings.Repeat("e", 64)
		},
		"queued stage": func(value *PipelineRun) {
			value.Status.Stage = PipelineRunStageFetch
		},
		"queued version": func(value *PipelineRun) { value.Status.ResourceVersion = 2 },
		"terminal without time": func(value *PipelineRun) {
			value.Status.State = PipelineRunSucceeded
			value.Status.Stage = PipelineRunStageReport
			value.Status.Reason = PipelineRunReasonCompleted
		},
		"observation drift": func(value *PipelineRun) {
			value.UpdatedAt = value.UpdatedAt.Add(time.Second)
		},
	} {
		t.Run("PipelineRun "+name, func(t *testing.T) {
			value := run
			mutate(&value)
			if err := ValidatePipelineRun(value); err == nil {
				t.Fatal("invalid PipelineRun was accepted")
			}
		})
	}
}

func TestReplayedPipelineRunPreservesInputAndSealsManualCause(t *testing.T) {
	source := validPipelineRun(t)
	completedAt := source.UpdatedAt.Add(time.Second)
	source.Status = PipelineRunStatus{
		State: PipelineRunSucceeded, Stage: PipelineRunStageReport,
		Reason: PipelineRunReasonCompleted, ResourceVersion: 4,
		ObservedAt: completedAt, CompletedAt: &completedAt,
	}
	source.UpdatedAt = completedAt
	if err := ValidatePipelineRun(source); err != nil {
		t.Fatalf("validate replay source: %v", err)
	}
	commandID := ResourceID("operation-" + strings.Repeat("8", 64))
	replayedAt := completedAt.Add(time.Microsecond)
	id, err := ReplayedPipelineRunID(source.Scope, source.ID, commandID, source.InputDigest)
	if err != nil {
		t.Fatal(err)
	}
	replayed := PipelineRun{
		APIVersion: APIVersion, Kind: "PipelineRun", ID: id, Scope: source.Scope,
		ProjectID: source.ProjectID, PipelineID: source.PipelineID,
		Input: source.Input, InputDigest: source.InputDigest,
		Replay: &PipelineRunReplay{
			SourceRunID: source.ID, CommandID: commandID,
			RequestedBy: SubjectRef{Kind: SubjectUser, ID: "user-replay"},
		},
		Status: PipelineRunStatus{
			State: PipelineRunQueued, Stage: PipelineRunStageReceive,
			Reason: PipelineRunReasonEventAdmitted, ResourceVersion: 1,
			ObservedAt: replayedAt,
		},
		CreatedAt: replayedAt, UpdatedAt: replayedAt,
	}
	if err := ValidatePipelineRun(replayed); err != nil {
		t.Fatalf("validate replayed PipelineRun: %v", err)
	}
	if replayed.Input != source.Input || replayed.InputDigest != source.InputDigest || replayed.ID == source.ID {
		t.Fatalf("replay changed immutable executor input: source=%#v replay=%#v", source, replayed)
	}

	for name, mutate := range map[string]func(*PipelineRun){
		"source identity": func(value *PipelineRun) { value.Replay.SourceRunID = "run-forged" },
		"command":         func(value *PipelineRun) { value.Replay.CommandID = "" },
		"actor":           func(value *PipelineRun) { value.Replay.RequestedBy.ID = "" },
		"derived identity": func(value *PipelineRun) {
			value.Replay.CommandID = "operation-" + ResourceID(strings.Repeat("9", 64))
		},
		"self reference": func(value *PipelineRun) { value.Replay.SourceRunID = value.ID },
	} {
		t.Run(name, func(t *testing.T) {
			value := replayed
			cause := *replayed.Replay
			value.Replay = &cause
			mutate(&value)
			if err := ValidatePipelineRun(value); err == nil {
				t.Fatal("invalid replayed PipelineRun was accepted")
			}
		})
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
	event := decodeDevOpsExample[SourceEvent](t, "examples/source-event.json")
	if err := ValidateSourceEvent(event); err != nil {
		t.Fatalf("validate source event: %v", err)
	}
	run := decodeDevOpsExample[PipelineRun](t, "examples/pipeline-run.json")
	if err := ValidatePipelineRun(run); err != nil {
		t.Fatalf("validate Pipeline run: %v", err)
	}
	readiness := decodeDevOpsExample[Readiness](t, "examples/readiness.json")
	if err := ValidateReadiness(readiness); err != nil {
		t.Fatalf("validate readiness: %v", err)
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
			value.EndpointOrigin = "http://git.internal.example"
		},
		"endpoint path": func(value *SourceConnectionSpec) {
			value.EndpointOrigin = "https://git.internal.example/api"
		},
	} {
		t.Run(name, func(t *testing.T) {
			value := connection
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

func TestSourceHealthContractsAcceptOnlyClosedStateReasonPairs(t *testing.T) {
	now := time.Date(2026, 9, 8, 1, 2, 3, 0, time.UTC)
	validConnections := []SourceConnectionStatus{
		{Health: SourceConnectionPending, Reason: SourceConnectionReasonConfigurationChanged, ObservedAt: now},
		{Health: SourceConnectionReady, Reason: SourceConnectionReasonObserved, ObservedAt: now},
		{Health: SourceConnectionUnavailable, Reason: SourceConnectionReasonSecretUnavailable, ObservedAt: now},
		{Health: SourceConnectionUnavailable, Reason: SourceConnectionReasonProviderUnavailable, ObservedAt: now},
		{Health: SourceConnectionUnavailable, Reason: SourceConnectionReasonProviderUnsupported, ObservedAt: now},
		{Health: SourceConnectionUnavailable, Reason: SourceConnectionReasonCredentialRejected, ObservedAt: now},
	}
	for _, status := range validConnections {
		if err := ValidateSourceConnectionStatus(status); err != nil {
			t.Fatalf("valid source connection status %#v: %v", status, err)
		}
	}
	invalidConnection := validConnections[1]
	invalidConnection.Reason = SourceConnectionReasonProviderUnavailable
	if ValidateSourceConnectionStatus(invalidConnection) == nil {
		t.Fatal("mismatched ready source reason was accepted")
	}

	validBindings := []RepositoryBindingStatus{
		{Health: RepositoryBindingPending, Reason: RepositoryBindingReasonConfigurationChanged, ObservedAt: now},
		{Health: RepositoryBindingPending, Reason: RepositoryBindingReasonConnectionNotReady, ObservedAt: now},
		{Health: RepositoryBindingReady, Reason: RepositoryBindingReasonObserved, ObservedAt: now},
		{Health: RepositoryBindingUnavailable, Reason: RepositoryBindingReasonRepositoryUnavailable, ObservedAt: now},
		{Health: RepositoryBindingUnavailable, Reason: RepositoryBindingReasonIdentityMismatch, ObservedAt: now},
		{Health: RepositoryBindingUnavailable, Reason: RepositoryBindingReasonFetchPermissionDenied, ObservedAt: now},
		{Health: RepositoryBindingUnavailable, Reason: RepositoryBindingReasonReportPermissionDenied, ObservedAt: now},
	}
	for _, status := range validBindings {
		if err := ValidateRepositoryBindingStatus(status); err != nil {
			t.Fatalf("valid repository binding status %#v: %v", status, err)
		}
	}
	invalidBinding := validBindings[2]
	invalidBinding.Reason = RepositoryBindingReasonIdentityMismatch
	if ValidateRepositoryBindingStatus(invalidBinding) == nil {
		t.Fatal("mismatched ready repository reason was accepted")
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
	event := validSourceEvent(t)
	eventID, err := SourceEventID(event.Scope, event.Spec.SourceConnectionID, event.Spec.DeliveryID)
	if err != nil || eventID != event.ID {
		t.Fatalf("derive SourceEvent ID=%q err=%v", eventID, err)
	}
	changedDeliveryID, err := SourceEventID(
		event.Scope,
		event.Spec.SourceConnectionID,
		"223e4567-e89b-42d3-a456-426614174000",
	)
	if err != nil || changedDeliveryID == eventID {
		t.Fatalf("SourceEvent delivery identity=%q err=%v", changedDeliveryID, err)
	}
	changedContent := event.Spec
	changedContent.CanonicalPayloadDigest = "sha256:" + strings.Repeat("b", 64)
	changedContentID, err := SourceEventID(
		event.Scope,
		changedContent.SourceConnectionID,
		changedContent.DeliveryID,
	)
	if err != nil || changedContentID != eventID {
		t.Fatalf("changed replay escaped SourceEvent identity=%q err=%v", changedContentID, err)
	}
	if SourceEventSpecDigest(changedContent) == event.ContentDigest {
		t.Fatal("changed replay retained the original SourceEvent content digest")
	}
	run := validPipelineRun(t)
	changedRun, err := PipelineRunID(
		run.Scope,
		run.Input.SourceEventID,
		"pipeline-revision-other",
		run.InputDigest,
	)
	if err != nil || changedRun == run.ID {
		t.Fatalf("PipelineRun revision identity=%q err=%v", changedRun, err)
	}
	replayCommand := ResourceID("operation-" + strings.Repeat("8", 64))
	replayedRun, err := ReplayedPipelineRunID(run.Scope, run.ID, replayCommand, run.InputDigest)
	if err != nil || replayedRun == run.ID {
		t.Fatalf("replayed PipelineRun identity=%q err=%v", replayedRun, err)
	}
	changedReplay, err := ReplayedPipelineRunID(
		run.Scope, run.ID, "operation-"+ResourceID(strings.Repeat("9", 64)), run.InputDigest,
	)
	if err != nil || changedReplay == replayedRun {
		t.Fatalf("changed replay command identity=%q err=%v", changedReplay, err)
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

func TestPreconditionProblemCodesAreDistinct(t *testing.T) {
	required := Problem{
		Type:  "https://errors.matrix.xiak.com/devops/precondition-required",
		Title: "A precondition is required", Status: 428,
		Code: ErrorPreconditionRequired, TraceID: "trace-required", Retryable: false,
	}
	if err := ValidateProblem(required); err != nil {
		t.Fatalf("validate required precondition problem: %v", err)
	}
	required.Status = 412
	if err := ValidateProblem(required); err == nil {
		t.Fatal("missing-precondition code accepted a failed-precondition status")
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
