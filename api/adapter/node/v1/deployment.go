package nodev1

import (
	"errors"
	"io"
	"time"

	"github.com/xiak/matrix/api/contractjson"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

const (
	DeploymentEffectPath                      = "/adapter/node/v1/deployment-effects"
	DeploymentObservationPath                 = "/adapter/node/v1/deployment-observations"
	DeploymentEffectRequestKind               = "DeploymentEffectRequest"
	DeploymentEffectResponseKind              = "DeploymentEffectResponse"
	DeploymentObservationRequestKind          = "DeploymentObservationRequest"
	DeploymentObservationResponseKind         = "DeploymentObservationResponse"
	MaximumDeploymentEffectRequestBytes       = 16 * 1024 * 1024
	MaximumDeploymentEffectResponseBytes      = 256 * 1024
	MaximumDeploymentObservationRequestBytes  = 128 * 1024
	MaximumDeploymentObservationResponseBytes = 512 * 1024
	MaximumDeploymentDuration                 = 5 * time.Minute
	MaximumSecretMaterialBytes                = 1024 * 1024
	MaximumDeploymentMaterialBytes            = 8 * 1024 * 1024
)

var ErrInvalidDeployment = errors.New("node deployment document is invalid")

// ResolvedArtifact binds a public immutable artifact to the exact image already
// loaded on the selected node. The node independently verifies LocalImageID and
// never pulls, builds or tags a replacement.
type ResolvedArtifact struct {
	ArtifactDigest string `json:"artifactDigest"`
	LocalImageID   string `json:"localImageId"`
}

// SecretMaterial is short-lived node-wire input for one exact secret version.
// It is never part of the persisted DeploymentExecutionRequest or a receipt.
type SecretMaterial struct {
	Reference paasv1.SecretVersionReference `json:"reference"`
	Value     []byte                        `json:"value"`
}

type DeploymentMaterials struct {
	Artifacts []ResolvedArtifact `json:"artifacts,omitempty"`
	Secrets   []SecretMaterial   `json:"secrets,omitempty"`
}

func (materials *DeploymentMaterials) Clear() {
	if materials == nil {
		return
	}
	for index := range materials.Secrets {
		clear(materials.Secrets[index].Value)
		materials.Secrets[index].Value = nil
	}
	materials.Artifacts = nil
	materials.Secrets = nil
}

type DeploymentEffectRequest struct {
	APIVersion string                            `json:"apiVersion"`
	Kind       string                            `json:"kind"`
	Identity   Identity                          `json:"identity"`
	Execution  paasv1.DeploymentExecutionRequest `json:"execution"`
	Materials  DeploymentMaterials               `json:"materials"`
}

type DeploymentEffectResponse struct {
	APIVersion string               `json:"apiVersion"`
	Kind       string               `json:"kind"`
	Identity   Identity             `json:"identity"`
	CommandID  paasv1.CommandID     `json:"commandId"`
	Result     paasv1.AdapterResult `json:"result"`
}

type DeploymentObservationRequest struct {
	APIVersion string                          `json:"apiVersion"`
	Kind       string                          `json:"kind"`
	Identity   Identity                        `json:"identity"`
	Request    paasv1.ObserveDeploymentRequest `json:"request"`
}

type DeploymentObservationResponse struct {
	APIVersion  string                       `json:"apiVersion"`
	Kind        string                       `json:"kind"`
	Identity    Identity                     `json:"identity"`
	CommandID   paasv1.CommandID             `json:"commandId"`
	Observation paasv1.DeploymentObservation `json:"observation"`
}

func ValidateDeploymentEffectRequest(value DeploymentEffectRequest) error {
	if value.APIVersion != APIVersion || value.Kind != DeploymentEffectRequestKind ||
		ValidateIdentity(value.Identity) != nil ||
		paasv1.ValidateDeploymentExecutionRequest(value.Execution) != nil ||
		value.Execution.Command.ExecutionTargetID != value.Identity.ExecutionTargetID ||
		value.Execution.Command.Deadline.IsZero() ||
		value.Execution.Command.Deadline.Location() != time.UTC {
		return ErrInvalidDeployment
	}
	switch value.Execution.Command.Action {
	case paasv1.AdapterValidateDeployment, paasv1.AdapterApplyDeployment, paasv1.AdapterRollbackDeployment:
		if validateDeploymentMaterials(value.Execution, value.Materials) != nil {
			return ErrInvalidDeployment
		}
	case paasv1.AdapterStopDeployment:
		if len(value.Materials.Artifacts) != 0 || len(value.Materials.Secrets) != 0 {
			return ErrInvalidDeployment
		}
	default:
		return ErrInvalidDeployment
	}
	return nil
}

func ValidateDeploymentEffectResponse(value DeploymentEffectResponse) error {
	if value.APIVersion != APIVersion || value.Kind != DeploymentEffectResponseKind ||
		ValidateIdentity(value.Identity) != nil ||
		paasv1.ValidateID("commandId", string(value.CommandID)) != nil ||
		paasv1.ValidateAdapterResult(value.Result) != nil || value.Result.CommandID != value.CommandID {
		return ErrInvalidDeployment
	}
	return nil
}

func ValidateDeploymentObservationRequest(value DeploymentObservationRequest) error {
	if value.APIVersion != APIVersion || value.Kind != DeploymentObservationRequestKind ||
		ValidateIdentity(value.Identity) != nil ||
		paasv1.ValidateObserveDeploymentRequest(value.Request) != nil ||
		value.Request.Command.ExecutionTargetID != value.Identity.ExecutionTargetID ||
		value.Request.Command.Deadline.IsZero() || value.Request.Command.Deadline.Location() != time.UTC {
		return ErrInvalidDeployment
	}
	return nil
}

func ValidateDeploymentObservationResponse(value DeploymentObservationResponse) error {
	if value.APIVersion != APIVersion || value.Kind != DeploymentObservationResponseKind ||
		ValidateIdentity(value.Identity) != nil ||
		paasv1.ValidateID("commandId", string(value.CommandID)) != nil ||
		paasv1.ValidateDeploymentObservation(value.Observation) != nil {
		return ErrInvalidDeployment
	}
	return nil
}

func DecodeDeploymentEffectRequest(reader io.Reader) (DeploymentEffectRequest, error) {
	var value DeploymentEffectRequest
	if contractjson.DecodeObject(reader, MaximumDeploymentEffectRequestBytes, &value) != nil ||
		ValidateDeploymentEffectRequest(value) != nil {
		value.Materials.Clear()
		return DeploymentEffectRequest{}, ErrInvalidDeployment
	}
	return value, nil
}

func DecodeDeploymentEffectResponse(reader io.Reader) (DeploymentEffectResponse, error) {
	var value DeploymentEffectResponse
	if contractjson.DecodeObject(reader, MaximumDeploymentEffectResponseBytes, &value) != nil ||
		ValidateDeploymentEffectResponse(value) != nil {
		return DeploymentEffectResponse{}, ErrInvalidDeployment
	}
	return value, nil
}

func DecodeDeploymentObservationRequest(reader io.Reader) (DeploymentObservationRequest, error) {
	var value DeploymentObservationRequest
	if contractjson.DecodeObject(reader, MaximumDeploymentObservationRequestBytes, &value) != nil ||
		ValidateDeploymentObservationRequest(value) != nil {
		return DeploymentObservationRequest{}, ErrInvalidDeployment
	}
	return value, nil
}

func DecodeDeploymentObservationResponse(reader io.Reader) (DeploymentObservationResponse, error) {
	var value DeploymentObservationResponse
	if contractjson.DecodeObject(reader, MaximumDeploymentObservationResponseBytes, &value) != nil ||
		ValidateDeploymentObservationResponse(value) != nil {
		return DeploymentObservationResponse{}, ErrInvalidDeployment
	}
	return value, nil
}

func validateDeploymentMaterials(
	request paasv1.DeploymentExecutionRequest,
	materials DeploymentMaterials,
) error {
	expectedArtifacts := make(map[string]struct{}, len(request.ApplicationRevision.Spec.Components))
	for _, component := range request.ApplicationRevision.Spec.Components {
		expectedArtifacts[component.Artifact.Digest] = struct{}{}
	}
	expectedSecrets := make(map[string]struct{})
	for _, component := range request.Generation.Spec.Components {
		for _, binding := range component.Bindings {
			if binding.SecretVersion != nil {
				expectedSecrets[secretKey(*binding.SecretVersion)] = struct{}{}
			}
		}
	}
	seenArtifacts := make(map[string]struct{}, len(materials.Artifacts))
	for _, material := range materials.Artifacts {
		if _, expected := expectedArtifacts[material.ArtifactDigest]; !expected ||
			paasv1.ValidateDigest("artifactDigest", material.ArtifactDigest) != nil ||
			paasv1.ValidateDigest("localImageId", material.LocalImageID) != nil {
			return ErrInvalidDeployment
		}
		if _, duplicate := seenArtifacts[material.ArtifactDigest]; duplicate {
			return ErrInvalidDeployment
		}
		seenArtifacts[material.ArtifactDigest] = struct{}{}
	}
	seenSecrets := make(map[string]struct{}, len(materials.Secrets))
	totalSecretBytes := 0
	for _, material := range materials.Secrets {
		key := secretKey(material.Reference)
		if _, expected := expectedSecrets[key]; !expected || len(material.Value) > MaximumSecretMaterialBytes {
			return ErrInvalidDeployment
		}
		if _, duplicate := seenSecrets[key]; duplicate {
			return ErrInvalidDeployment
		}
		totalSecretBytes += len(material.Value)
		if totalSecretBytes > MaximumDeploymentMaterialBytes {
			return ErrInvalidDeployment
		}
		seenSecrets[key] = struct{}{}
	}
	if len(seenArtifacts) != len(expectedArtifacts) || len(seenSecrets) != len(expectedSecrets) {
		return ErrInvalidDeployment
	}
	return nil
}

func secretKey(value paasv1.SecretVersionReference) string {
	return string(value.SecretID) + "\x00" + value.Version
}
