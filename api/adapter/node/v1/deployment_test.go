package nodev1

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

func TestDeploymentEffectProtocolRequiresExactBoundMaterials(t *testing.T) {
	valid := deploymentEffectFixture(t)
	encoded, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeDeploymentEffectRequest(bytes.NewReader(encoded))
	if err != nil || decoded.Execution.Command.CommandID != valid.Execution.Command.CommandID ||
		string(decoded.Materials.Secrets[0].Value) != "secret-value" {
		t.Fatalf("valid Deployment effect rejected: %#v, %v", decoded, err)
	}
	decoded.Materials.Clear()

	mutations := map[string]func(*DeploymentEffectRequest){
		"missing artifact": func(value *DeploymentEffectRequest) { value.Materials.Artifacts = nil },
		"extra artifact": func(value *DeploymentEffectRequest) {
			value.Materials.Artifacts = append(value.Materials.Artifacts, ResolvedArtifact{
				ArtifactDigest: deploymentDigest('e'), LocalImageID: deploymentDigest('f'),
			})
		},
		"duplicate artifact": func(value *DeploymentEffectRequest) {
			value.Materials.Artifacts = append(value.Materials.Artifacts, value.Materials.Artifacts[0])
		},
		"wrong image identity": func(value *DeploymentEffectRequest) {
			value.Materials.Artifacts[0].LocalImageID = "web:latest"
		},
		"missing secret": func(value *DeploymentEffectRequest) { value.Materials.Secrets = nil },
		"extra secret": func(value *DeploymentEffectRequest) {
			value.Materials.Secrets = append(value.Materials.Secrets, SecretMaterial{
				Reference: paasv1.SecretVersionReference{SecretID: "secret-b", Version: "version-1"},
				Value:     []byte("other"),
			})
		},
		"duplicate secret": func(value *DeploymentEffectRequest) {
			value.Materials.Secrets = append(value.Materials.Secrets, value.Materials.Secrets[0])
		},
		"oversize secret": func(value *DeploymentEffectRequest) {
			value.Materials.Secrets[0].Value = make([]byte, MaximumSecretMaterialBytes+1)
		},
		"wrong target": func(value *DeploymentEffectRequest) {
			value.Identity.ExecutionTargetID = "target-b"
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			candidate := deploymentEffectFixture(t)
			mutate(&candidate)
			if ValidateDeploymentEffectRequest(candidate) == nil {
				t.Fatal("invalid material set was accepted")
			}
			candidate.Materials.Clear()
		})
	}

	for name, document := range map[string][]byte{
		"unknown field":   bytes.Replace(encoded, []byte(`"materials":`), []byte(`"shell":"/bin/sh","materials":`), 1),
		"duplicate field": bytes.Replace(encoded, []byte(`"kind":"DeploymentEffectRequest"`), []byte(`"kind":"DeploymentEffectRequest","kind":"DeploymentEffectRequest"`), 1),
		"trailing":        append(append([]byte{}, encoded...), []byte(`{}`)...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeDeploymentEffectRequest(bytes.NewReader(document)); err == nil {
				t.Fatal("non-closed Deployment document was accepted")
			}
		})
	}
}

func TestDeploymentProtocolSeparatesEffectsFromObservation(t *testing.T) {
	effect := deploymentEffectFixture(t)
	stop := effect
	stop.Execution.Command.Action = paasv1.AdapterStopDeployment
	stop.Execution.Generation.Spec.DesiredState = paasv1.DeploymentDesiredStopped
	stop.Execution.Generation.ContentDigest = paasv1.DeploymentSpecContentDigest(stop.Execution.Generation.Spec)
	stop.Execution.Command.RequestDigest = paasv1.DeploymentExecutionRequestDigest(stop.Execution)
	stop.Materials = DeploymentMaterials{}
	if ValidateDeploymentEffectRequest(stop) != nil {
		t.Fatal("material-free stop was rejected")
	}
	stop.Materials.Secrets = []SecretMaterial{{
		Reference: paasv1.SecretVersionReference{SecretID: "secret-a", Version: "version-1"},
		Value:     []byte("secret-value"),
	}}
	if ValidateDeploymentEffectRequest(stop) == nil {
		t.Fatal("stop accepted secret material")
	}
	stop.Materials.Clear()

	command := effect.Execution.Command
	command.Action = paasv1.AdapterObserveDeployment
	observation := DeploymentObservationRequest{
		APIVersion: APIVersion, Kind: DeploymentObservationRequestKind,
		Identity: effect.Identity,
		Request: paasv1.ObserveDeploymentRequest{
			Command: command, Generation: effect.Execution.Generation.Generation,
			ExpectedContentDigest: effect.Execution.Generation.ContentDigest,
		},
	}
	observation.Request.Command.RequestDigest = paasv1.ObserveDeploymentRequestDigest(observation.Request)
	if ValidateDeploymentObservationRequest(observation) != nil {
		t.Fatal("valid exact Deployment observation request was rejected")
	}
	observation.Request.Command.ExecutionTargetID = "target-b"
	observation.Request.Command.RequestDigest = paasv1.ObserveDeploymentRequestDigest(observation.Request)
	if ValidateDeploymentObservationRequest(observation) == nil {
		t.Fatal("observation request crossed its node identity")
	}
}

func TestDeploymentMaterialsClearSecretBytes(t *testing.T) {
	secret := []byte("must-be-cleared")
	materials := DeploymentMaterials{Secrets: []SecretMaterial{{Value: secret}}}
	materials.Clear()
	if !bytes.Equal(secret, make([]byte, len(secret))) || materials.Secrets != nil || materials.Artifacts != nil {
		t.Fatal("Deployment material clear retained secret bytes or references")
	}
}

func deploymentEffectFixture(t *testing.T) DeploymentEffectRequest {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	scope := paasv1.ResourceScope{Kind: paasv1.AuthorityTenant, TenantID: "tenant-a"}
	metadata := func(id string) paasv1.ResourceMetadata {
		return paasv1.ResourceMetadata{
			ID: paasv1.ResourceID(id), Name: id, Scope: scope,
			ResourceVersion: 1, CreatedAt: now, UpdatedAt: now,
		}
	}
	revision := paasv1.ApplicationRevision{
		APIVersion: paasv1.APIVersion, Kind: "ApplicationRevision",
		Metadata: metadata("revision-a"),
		Spec: paasv1.ApplicationRevisionSpec{
			ApplicationID: "application-a", Revision: "revision-1",
			ContentDigest: deploymentDigest('b'),
			Components: []paasv1.ApplicationRevisionComponent{{
				Name: "web",
				Artifact: paasv1.ArtifactRef{
					Kind: paasv1.ArtifactOCIImage, Locator: "registry.example.invalid/web",
					Digest: deploymentDigest('a'),
				},
				Resources: paasv1.ResourceRequirements{CPUMillis: 100, MemoryBytes: 64 * 1024 * 1024},
				Inputs: []paasv1.ComponentInput{{
					Name: "password", Kind: paasv1.InputSecret,
					Injection: paasv1.InjectionFile, Required: true,
				}},
			}},
		},
	}
	generation := paasv1.DeploymentGeneration{
		APIVersion: paasv1.APIVersion, Kind: "DeploymentGeneration", Scope: scope,
		DeploymentID: "deployment-a", Generation: 1,
		Spec: paasv1.DeploymentSpec{
			ApplicationRevisionID: revision.Metadata.ID, PlacementPolicyID: "policy-a",
			DesiredState: paasv1.DeploymentDesiredRunning,
			Components: []paasv1.DeploymentComponent{{
				Name: "web", Replicas: 1,
				Bindings: []paasv1.ComponentBinding{{
					Name: "password", SecretVersion: &paasv1.SecretVersionReference{
						SecretID: "secret-a", Version: "version-1",
					},
				}},
			}},
		},
		CreatedByOperationID: "operation-a", CreatedAt: now,
	}
	generation.ContentDigest = paasv1.DeploymentSpecContentDigest(generation.Spec)
	placement := paasv1.PlacementDecision{
		APIVersion: paasv1.APIVersion, Kind: "PlacementDecision",
		Metadata: metadata("decision-a"), DeploymentID: generation.DeploymentID,
		DeploymentGeneration: generation.Generation, DeploymentResourceVersion: 1,
		ApplicationRevisionID: revision.Metadata.ID,
		PlacementPolicyID:     generation.Spec.PlacementPolicyID, PolicyResourceVersion: 1,
		RequestedIsolationGuarantee: paasv1.IsolationWorkload,
		Outcome:                     paasv1.PlacementScheduled, ExecutionTargetID: "target-a",
		ExecutionTargetResourceVersion: 1, GrantedIsolationGuarantee: paasv1.IsolationWorkload,
		CandidateSetDigest: deploymentDigest('c'), DecidedAt: now,
	}
	execution := paasv1.DeploymentExecutionRequest{
		Command: paasv1.AdapterCommandEnvelope{
			OperationID: "operation-a", CommandID: "command-a", Attempt: 1,
			Action: paasv1.AdapterApplyDeployment, Scope: scope,
			ApplicationID: revision.Spec.ApplicationID, ApplicationRevisionID: revision.Metadata.ID,
			DeploymentID: generation.DeploymentID, ExecutionTargetID: placement.ExecutionTargetID,
			BindingRef: "binding-a", Deadline: now.Add(time.Minute),
		},
		Generation: generation, ApplicationRevision: revision, Placement: placement,
	}
	execution.Command.RequestDigest = paasv1.DeploymentExecutionRequestDigest(execution)
	if err := paasv1.ValidateDeploymentExecutionRequest(execution); err != nil {
		t.Fatalf("invalid Deployment fixture: %v", err)
	}
	return DeploymentEffectRequest{
		APIVersion: APIVersion, Kind: DeploymentEffectRequestKind,
		Identity:  Identity{InstallationID: "installation-a", ExecutionTargetID: "target-a"},
		Execution: execution,
		Materials: DeploymentMaterials{
			Artifacts: []ResolvedArtifact{{
				ArtifactDigest: deploymentDigest('a'), LocalImageID: deploymentDigest('d'),
			}},
			Secrets: []SecretMaterial{{
				Reference: paasv1.SecretVersionReference{SecretID: "secret-a", Version: "version-1"},
				Value:     []byte("secret-value"),
			}},
		},
	}
}

func deploymentDigest(character byte) string {
	return "sha256:" + strings.Repeat(string(character), 64)
}
