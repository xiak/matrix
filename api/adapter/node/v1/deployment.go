package nodev1

import (
	"errors"
	"io"
	"time"

	"github.com/xiak/matrix/api/contractjson"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

const (
	DeploymentEffectPath                       = "/adapter/node/v1/deployment-effects"
	DeploymentObservationPath                  = "/adapter/node/v1/deployment-observations"
	DeploymentRuntimeObservationPath           = "/adapter/node/v1/deployment-runtime-observations"
	DeploymentTelemetryObservationPath         = "/adapter/node/v1/deployment-telemetry-observations"
	DeploymentEffectRequestKind                = "DeploymentEffectRequest"
	DeploymentEffectResponseKind               = "DeploymentEffectResponse"
	DeploymentObservationRequestKind           = "DeploymentObservationRequest"
	DeploymentObservationResponseKind          = "DeploymentObservationResponse"
	DeploymentRuntimeObservationRequestKind    = "DeploymentRuntimeObservationRequest"
	DeploymentRuntimeObservationResponseKind   = "DeploymentRuntimeObservationResponse"
	DeploymentTelemetryObservationRequestKind  = "DeploymentTelemetryObservationRequest"
	DeploymentTelemetryObservationResponseKind = "DeploymentTelemetryObservationResponse"
	MaximumDeploymentEffectRequestBytes        = 16 * 1024 * 1024
	MaximumDeploymentEffectResponseBytes       = 256 * 1024
	MaximumDeploymentObservationRequestBytes   = 128 * 1024
	MaximumDeploymentObservationResponseBytes  = 512 * 1024
	MaximumDeploymentRuntimeRequestBytes       = 64 * 1024
	MaximumDeploymentRuntimeResponseBytes      = 256 * 1024
	MaximumDeploymentTelemetryResponseBytes    = 512 * 1024
	MaximumDeploymentDuration                  = 5 * time.Minute
	MaximumSecretMaterialBytes                 = 1024 * 1024
	MaximumDeploymentMaterialBytes             = 8 * 1024 * 1024
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

type DeploymentRuntimeObservationRequest struct {
	APIVersion string                                 `json:"apiVersion"`
	Kind       string                                 `json:"kind"`
	Identity   Identity                               `json:"identity"`
	BindingRef string                                 `json:"bindingRef"`
	Request    paasv1.ObserveDeploymentRuntimeRequest `json:"request"`
}

type DeploymentRuntimeObservationResponse struct {
	APIVersion  string                              `json:"apiVersion"`
	Kind        string                              `json:"kind"`
	Identity    Identity                            `json:"identity"`
	RequestID   paasv1.CommandID                    `json:"requestId"`
	Observation paasv1.DeploymentRuntimeObservation `json:"observation"`
}

type DeploymentTelemetryObservationRequest struct {
	APIVersion string                                 `json:"apiVersion"`
	Kind       string                                 `json:"kind"`
	Identity   Identity                               `json:"identity"`
	BindingRef string                                 `json:"bindingRef"`
	Request    paasv1.ObserveDeploymentRuntimeRequest `json:"request"`
}

type DeploymentTelemetryObservationResponse struct {
	APIVersion string                               `json:"apiVersion"`
	Kind       string                               `json:"kind"`
	Identity   Identity                             `json:"identity"`
	RequestID  paasv1.CommandID                     `json:"requestId"`
	Runtime    paasv1.DeploymentRuntimeObservation  `json:"runtime"`
	Resources  paasv1.DeploymentResourceObservation `json:"resources"`
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

func ValidateDeploymentRuntimeObservationRequest(value DeploymentRuntimeObservationRequest) error {
	if value.APIVersion != APIVersion || value.Kind != DeploymentRuntimeObservationRequestKind ||
		ValidateIdentity(value.Identity) != nil ||
		paasv1.ValidateID("bindingRef", value.BindingRef) != nil ||
		paasv1.ValidateObserveDeploymentRuntimeRequest(value.Request) != nil ||
		value.Request.ExecutionTargetID != value.Identity.ExecutionTargetID ||
		value.Request.Deadline.IsZero() || value.Request.Deadline.Location() != time.UTC {
		return ErrInvalidDeployment
	}
	return nil
}

func ValidateDeploymentRuntimeObservationResponse(value DeploymentRuntimeObservationResponse) error {
	if value.APIVersion != APIVersion || value.Kind != DeploymentRuntimeObservationResponseKind ||
		ValidateIdentity(value.Identity) != nil ||
		paasv1.ValidateID("requestId", string(value.RequestID)) != nil ||
		paasv1.ValidateDeploymentRuntimeObservation(value.Observation) != nil ||
		value.Observation.ExecutionTargetID != value.Identity.ExecutionTargetID {
		return ErrInvalidDeployment
	}
	return nil
}

func ValidateDeploymentTelemetryObservationRequest(value DeploymentTelemetryObservationRequest) error {
	if value.APIVersion != APIVersion || value.Kind != DeploymentTelemetryObservationRequestKind ||
		ValidateIdentity(value.Identity) != nil ||
		paasv1.ValidateID("bindingRef", value.BindingRef) != nil ||
		paasv1.ValidateObserveDeploymentRuntimeRequest(value.Request) != nil ||
		value.Request.ExecutionTargetID != value.Identity.ExecutionTargetID ||
		value.Request.Deadline.IsZero() || value.Request.Deadline.Location() != time.UTC {
		return ErrInvalidDeployment
	}
	return nil
}

func ValidateDeploymentTelemetryObservationResponse(value DeploymentTelemetryObservationResponse) error {
	if value.APIVersion != APIVersion || value.Kind != DeploymentTelemetryObservationResponseKind ||
		ValidateIdentity(value.Identity) != nil ||
		paasv1.ValidateID("requestId", string(value.RequestID)) != nil ||
		paasv1.ValidateDeploymentRuntimeObservation(value.Runtime) != nil ||
		paasv1.ValidateDeploymentResourceObservation(value.Resources) != nil ||
		value.Runtime.DeploymentID != value.Resources.DeploymentID ||
		value.Runtime.Generation != value.Resources.Generation ||
		value.Runtime.ApplicationRevisionID != value.Resources.ApplicationRevisionID ||
		value.Runtime.ExecutionTargetID != value.Identity.ExecutionTargetID ||
		value.Resources.ExecutionTargetID != value.Identity.ExecutionTargetID ||
		!sameTelemetryInstances(value.Runtime.Instances, value.Resources.Instances) {
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

func DecodeDeploymentRuntimeObservationRequest(reader io.Reader) (DeploymentRuntimeObservationRequest, error) {
	var value DeploymentRuntimeObservationRequest
	if contractjson.DecodeObject(reader, MaximumDeploymentRuntimeRequestBytes, &value) != nil ||
		ValidateDeploymentRuntimeObservationRequest(value) != nil {
		return DeploymentRuntimeObservationRequest{}, ErrInvalidDeployment
	}
	return value, nil
}

func DecodeDeploymentRuntimeObservationResponse(reader io.Reader) (DeploymentRuntimeObservationResponse, error) {
	var value DeploymentRuntimeObservationResponse
	if contractjson.DecodeObject(reader, MaximumDeploymentRuntimeResponseBytes, &value) != nil ||
		ValidateDeploymentRuntimeObservationResponse(value) != nil {
		return DeploymentRuntimeObservationResponse{}, ErrInvalidDeployment
	}
	return value, nil
}

func DecodeDeploymentTelemetryObservationRequest(reader io.Reader) (DeploymentTelemetryObservationRequest, error) {
	var value DeploymentTelemetryObservationRequest
	if contractjson.DecodeObject(reader, MaximumDeploymentRuntimeRequestBytes, &value) != nil ||
		ValidateDeploymentTelemetryObservationRequest(value) != nil {
		return DeploymentTelemetryObservationRequest{}, ErrInvalidDeployment
	}
	return value, nil
}

func DecodeDeploymentTelemetryObservationResponse(reader io.Reader) (DeploymentTelemetryObservationResponse, error) {
	var value DeploymentTelemetryObservationResponse
	if contractjson.DecodeObject(reader, MaximumDeploymentTelemetryResponseBytes, &value) != nil ||
		ValidateDeploymentTelemetryObservationResponse(value) != nil {
		return DeploymentTelemetryObservationResponse{}, ErrInvalidDeployment
	}
	return value, nil
}

func sameTelemetryInstances(
	runtime []paasv1.DeploymentRuntimeInstance,
	resources []paasv1.DeploymentResourceInstance,
) bool {
	if len(runtime) != len(resources) {
		return false
	}
	seen := make(map[paasv1.ResourceID]struct{}, len(runtime))
	for _, instance := range runtime {
		seen[instance.ID] = struct{}{}
	}
	for _, instance := range resources {
		if _, found := seen[instance.ID]; !found {
			return false
		}
	}
	return true
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
