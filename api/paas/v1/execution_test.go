package paasv1

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestDeploymentExecutionDigestsAreSemanticAndOrderInvariant(t *testing.T) {
	request := validDeploymentExecutionRequest(t)
	request.ApplicationRevision.Spec.Components[0].Endpoints = append(
		request.ApplicationRevision.Spec.Components[0].Endpoints,
		ApplicationEndpoint{Name: "metrics", Port: 9090, Protocol: EndpointHTTP, Visibility: EndpointPrivate},
	)
	request.Command.RequestDigest = DeploymentExecutionRequestDigest(request)

	reordered := cloneExecutionRequest(t, request)
	reverse(reordered.Generation.Spec.Components[0].Bindings)
	reverse(reordered.ApplicationRevision.Spec.Components[0].Endpoints)
	reverse(reordered.ApplicationRevision.Spec.Components[0].Inputs)
	reordered.ConfigurationRevisions[0].Spec.Values = map[string]string{
		"PORT":      "8080",
		"LOG_LEVEL": "info",
	}
	if got, want := DeploymentSpecContentDigest(reordered.Generation.Spec), request.Generation.ContentDigest; got != want {
		t.Fatalf("deployment content digest changed under set reordering: got %q want %q", got, want)
	}
	if got, want := DeploymentExecutionRequestDigest(reordered), request.Command.RequestDigest; got != want {
		t.Fatalf("execution request digest changed under set/map reordering: got %q want %q", got, want)
	}

	mutations := map[string]func(*DeploymentExecutionRequest){
		"generation": func(value *DeploymentExecutionRequest) {
			value.Generation.Generation++
			value.Placement.DeploymentGeneration++
		},
		"replicas": func(value *DeploymentExecutionRequest) {
			value.Generation.Spec.Components[0].Replicas++
			value.Generation.ContentDigest = DeploymentSpecContentDigest(value.Generation.Spec)
		},
		"secret version": func(value *DeploymentExecutionRequest) {
			value.Generation.Spec.Components[0].Bindings[1].SecretVersion.Version = "version-0002"
			value.Generation.ContentDigest = DeploymentSpecContentDigest(value.Generation.Spec)
		},
		"artifact": func(value *DeploymentExecutionRequest) {
			value.ApplicationRevision.Spec.Components[0].Artifact.Digest = testExecutionDigest('c')
		},
		"configuration value": func(value *DeploymentExecutionRequest) {
			value.ConfigurationRevisions[0].Spec.Values["LOG_LEVEL"] = "debug"
			value.ConfigurationRevisions[0].Spec.ContentDigest = ConfigurationValuesDigest(
				value.ConfigurationRevisions[0].Spec.Values,
			)
		},
		"target": func(value *DeploymentExecutionRequest) {
			value.Command.ExecutionTargetID = "target-local-002"
			value.Placement.ExecutionTargetID = "target-local-002"
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			candidate := cloneExecutionRequest(t, request)
			mutate(&candidate)
			if DeploymentExecutionRequestDigest(candidate) == request.Command.RequestDigest {
				t.Fatal("desired execution input change did not change digest")
			}
		})
	}
}

func TestValidateDeploymentExecutionRequestRequiresExactResolvedInputs(t *testing.T) {
	request := validDeploymentExecutionRequest(t)
	if err := ValidateDeploymentExecutionRequest(request); err != nil {
		t.Fatalf("valid deployment execution request rejected: %v", err)
	}

	tests := map[string]struct {
		mutate func(*DeploymentExecutionRequest)
		want   string
	}{
		"missing configuration": {
			mutate: func(value *DeploymentExecutionRequest) { value.ConfigurationRevisions = nil },
			want:   "is missing",
		},
		"extra configuration": {
			mutate: func(value *DeploymentExecutionRequest) {
				extra := value.ConfigurationRevisions[0]
				extra.Metadata.ID = "configuration-revision-extra"
				extra.Metadata.Name = "configuration-extra"
				extra.Spec.ConfigurationID = "configuration-extra"
				value.ConfigurationRevisions = append(value.ConfigurationRevisions, extra)
			},
			want: "is not bound",
		},
		"unscheduled placement": {
			mutate: func(value *DeploymentExecutionRequest) {
				value.Placement.Outcome = PlacementUnschedulable
				value.Placement.ExecutionTargetID = ""
				value.Placement.ExecutionTargetResourceVersion = 0
				value.Placement.GrantedIsolationGuarantee = ""
				value.Placement.Reason = &Problem{
					Type: "/problems/unschedulable", Title: "Deployment cannot be scheduled",
					Status: 422, Code: ErrorUnschedulable, Detail: "No eligible target is ready.",
					TraceID: "trace-001", Retryable: true,
				}
			},
			want: "requires a scheduled placement",
		},
		"changed canonical input": {
			mutate: func(value *DeploymentExecutionRequest) {
				value.Generation.Spec.Components[0].Replicas++
				value.Generation.ContentDigest = DeploymentSpecContentDigest(value.Generation.Spec)
			},
			want: "requestDigest",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := cloneExecutionRequest(t, request)
			test.mutate(&candidate)
			if err := ValidateDeploymentExecutionRequest(candidate); err == nil ||
				!strings.Contains(err.Error(), test.want) {
				t.Fatalf("invalid request must fail with %q, got %v", test.want, err)
			}
		})
	}
}

func TestDeploymentAndObservationBindCurrentGeneration(t *testing.T) {
	var deployment Deployment
	decodeStrictJSON(t, "examples/deployment.json", &deployment)
	deployment.Status.Phase = DeploymentReady
	deployment.Status.ObservedGeneration = deployment.Generation
	deployment.Status.ObservedApplicationRevisionID = deployment.Spec.ApplicationRevisionID
	deployment.Status.ReadyComponents = uint32(len(deployment.Spec.Components))
	if err := ValidateDeployment(deployment); err != nil {
		t.Fatalf("fully observed ready deployment rejected: %v", err)
	}

	deployment.Status.ObservedGeneration = deployment.Generation + 1
	if err := ValidateDeployment(deployment); err == nil || !strings.Contains(err.Error(), "cannot exceed") {
		t.Fatalf("future observed generation must fail, got %v", err)
	}

	observation := DeploymentObservation{
		DeploymentID:          deployment.Metadata.ID,
		Generation:            deployment.Generation,
		ApplicationRevisionID: deployment.Spec.ApplicationRevisionID,
		Phase:                 DeploymentReady,
		ReadyComponents:       1,
		Endpoints: []DeploymentEndpointObservation{{
			ComponentName: "web", EndpointName: "http", Protocol: EndpointHTTP,
			Address: "web", Port: 8080,
		}},
		ReceiptDigest: testExecutionDigest('d'),
		ObservedAt:    time.Date(2026, 8, 25, 8, 3, 0, 0, time.UTC),
	}
	if err := ValidateDeploymentObservation(observation); err != nil {
		t.Fatalf("valid deployment observation rejected: %v", err)
	}
	observation.Endpoints = append(observation.Endpoints, observation.Endpoints[0])
	if err := ValidateDeploymentObservation(observation); err == nil || !strings.Contains(err.Error(), "duplicated") {
		t.Fatalf("duplicate observed endpoint must fail, got %v", err)
	}
}

func validDeploymentExecutionRequest(t *testing.T) DeploymentExecutionRequest {
	t.Helper()
	var revision ApplicationRevision
	var configuration ConfigurationRevision
	var deployment Deployment
	var placement PlacementDecision
	decodeStrictJSON(t, "examples/application-revision.json", &revision)
	decodeStrictJSON(t, "examples/configuration-revision.json", &configuration)
	decodeStrictJSON(t, "examples/deployment.json", &deployment)
	decodeStrictJSON(t, "examples/placement-scheduled.json", &placement)

	generation := DeploymentGeneration{
		APIVersion:           APIVersion,
		Kind:                 "DeploymentGeneration",
		Scope:                deployment.Metadata.Scope,
		DeploymentID:         deployment.Metadata.ID,
		Generation:           deployment.Generation,
		Spec:                 deployment.Spec,
		CreatedByOperationID: "operation-deploy-001",
		CreatedAt:            deployment.Metadata.CreatedAt,
	}
	generation.ContentDigest = DeploymentSpecContentDigest(generation.Spec)
	request := DeploymentExecutionRequest{
		Command: AdapterCommandEnvelope{
			OperationID:           "operation-deploy-001",
			CommandID:             "command-deploy-001",
			Attempt:               1,
			Action:                AdapterApplyDeployment,
			Scope:                 deployment.Metadata.Scope,
			ApplicationID:         revision.Spec.ApplicationID,
			ApplicationRevisionID: revision.Metadata.ID,
			DeploymentID:          deployment.Metadata.ID,
			ExecutionTargetID:     placement.ExecutionTargetID,
			BindingRef:            "binding-local-001",
			Deadline:              time.Date(2026, 8, 25, 8, 7, 0, 0, time.UTC),
		},
		Generation:             generation,
		ApplicationRevision:    revision,
		ConfigurationRevisions: []ConfigurationRevision{configuration},
		Placement:              placement,
	}
	request.Command.RequestDigest = DeploymentExecutionRequestDigest(request)
	return request
}

func cloneExecutionRequest(t *testing.T, value DeploymentExecutionRequest) DeploymentExecutionRequest {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("encode execution request clone: %v", err)
	}
	var result DeploymentExecutionRequest
	if err := json.Unmarshal(encoded, &result); err != nil {
		t.Fatalf("decode execution request clone: %v", err)
	}
	return result
}

func reverse[T any](values []T) {
	for left, right := 0, len(values)-1; left < right; left, right = left+1, right-1 {
		values[left], values[right] = values[right], values[left]
	}
}

func testExecutionDigest(character byte) string {
	return "sha256:" + strings.Repeat(string(character), 64)
}
