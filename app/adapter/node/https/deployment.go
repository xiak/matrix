package nodehttps

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"time"

	apphostingv1 "github.com/xiak/matrix/api/adapter/apphosting/v1"
	nodev1 "github.com/xiak/matrix/api/adapter/node/v1"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

// DeploymentArtifactResolver resolves only release-admitted immutable image
// identities. The selected node independently verifies the returned image ID
// before Compose can use it.
type DeploymentArtifactResolver interface {
	ResolveDeploymentArtifact(context.Context, paasv1.ArtifactRef) (nodev1.ResolvedArtifact, error)
}

// DeploymentSecretResolver returns caller-owned bytes for one exact secret
// version. DeploymentClient clears every returned value after the request.
type DeploymentSecretResolver interface {
	ResolveSecret(context.Context, paasv1.SecretVersionReference) ([]byte, error)
}

type DeploymentConfig struct {
	Connection Config
	Artifacts  DeploymentArtifactResolver
	Secrets    DeploymentSecretResolver
}

// DeploymentClient is an exact target-bound DeploymentExecutor. It has no
// target selector and never falls back to local execution or another node.
type DeploymentClient struct {
	effectEndpoint      string
	observationEndpoint string
	identity            nodev1.Identity
	bindingRef          string
	artifacts           DeploymentArtifactResolver
	secrets             DeploymentSecretResolver
	http                *http.Client
}

func NewDeploymentClient(config DeploymentConfig) (*DeploymentClient, error) {
	if config.Artifacts == nil || config.Secrets == nil {
		return nil, errors.New("node Deployment material resolvers are required")
	}
	endpoint, connection, err := newControllerConnection(
		config.Connection,
		nodev1.MaximumDeploymentDuration,
		nodev1.MaximumDeploymentDuration,
	)
	if err != nil {
		return nil, err
	}
	return &DeploymentClient{
		effectEndpoint:      endpoint + nodev1.DeploymentEffectPath,
		observationEndpoint: endpoint + nodev1.DeploymentObservationPath,
		identity:            config.Connection.Identity, bindingRef: config.Connection.BindingRef,
		artifacts: config.Artifacts, secrets: config.Secrets, http: connection,
	}, nil
}

func (client *DeploymentClient) Close() {
	if client != nil && client.http != nil {
		client.http.CloseIdleConnections()
	}
}

func (client *DeploymentClient) Capabilities(
	ctx context.Context,
) (paasv1.AdapterCapabilitiesContract, error) {
	if client == nil || client.http == nil || ctx == nil {
		return paasv1.AdapterCapabilitiesContract{}, errors.New("node Deployment client is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return paasv1.AdapterCapabilitiesContract{}, err
	}
	value := paasv1.AdapterCapabilitiesContract{
		Adapter: paasv1.AdapterRef{
			Kind: paasv1.AdapterDeploymentExecutor, Name: "node-compose", ContractVersion: "v1",
		},
		Actions: []paasv1.AdapterAction{
			paasv1.AdapterCapabilities,
			paasv1.AdapterValidateDeployment,
			paasv1.AdapterApplyDeployment,
			paasv1.AdapterObserveDeployment,
			paasv1.AdapterStopDeployment,
			paasv1.AdapterRollbackDeployment,
		},
		IsolationGuarantees: []paasv1.IsolationGuarantee{paasv1.IsolationWorkload},
		ObservedAt:          time.Now().UTC().Truncate(time.Microsecond),
	}
	if paasv1.ValidateAdapterCapabilities(value) != nil {
		return paasv1.AdapterCapabilitiesContract{}, errors.New("node Deployment capabilities are invalid")
	}
	return value, nil
}

func (client *DeploymentClient) ValidateDeployment(
	ctx context.Context,
	request paasv1.DeploymentExecutionRequest,
) (paasv1.AdapterResult, error) {
	return client.effect(ctx, request, paasv1.AdapterValidateDeployment)
}

func (client *DeploymentClient) ApplyDeployment(
	ctx context.Context,
	request paasv1.DeploymentExecutionRequest,
) (paasv1.AdapterResult, error) {
	return client.effect(ctx, request, paasv1.AdapterApplyDeployment)
}

func (client *DeploymentClient) StopDeployment(
	ctx context.Context,
	request paasv1.DeploymentExecutionRequest,
) (paasv1.AdapterResult, error) {
	return client.effect(ctx, request, paasv1.AdapterStopDeployment)
}

func (client *DeploymentClient) RollbackDeployment(
	ctx context.Context,
	request paasv1.DeploymentExecutionRequest,
) (paasv1.AdapterResult, error) {
	return client.effect(ctx, request, paasv1.AdapterRollbackDeployment)
}

func (client *DeploymentClient) effect(
	ctx context.Context,
	execution paasv1.DeploymentExecutionRequest,
	action paasv1.AdapterAction,
) (paasv1.AdapterResult, error) {
	empty := paasv1.AdapterResult{}
	if err := client.validateEffect(ctx, execution, action); err != nil {
		return empty, err
	}
	materials, err := client.resolveMaterials(ctx, execution)
	if err != nil {
		return empty, err
	}
	defer materials.Clear()
	request := nodev1.DeploymentEffectRequest{
		APIVersion: nodev1.APIVersion, Kind: nodev1.DeploymentEffectRequestKind,
		Identity: client.identity, Execution: execution, Materials: materials,
	}
	if nodev1.ValidateDeploymentEffectRequest(request) != nil {
		return empty, deploymentFault(
			paasv1.AdapterErrorValidation,
			paasv1.ErrorInvalidArgument,
			"Remote Deployment input is invalid.",
			false,
		)
	}
	body, err := json.Marshal(request)
	if err != nil || len(body) > nodev1.MaximumDeploymentEffectRequestBytes {
		clear(body)
		return empty, deploymentFault(
			paasv1.AdapterErrorValidation,
			paasv1.ErrorInvalidArgument,
			"Remote Deployment input exceeds the closed node protocol.",
			false,
		)
	}
	defer clear(body)
	operationContext, cancel := context.WithDeadline(ctx, execution.Command.Deadline)
	defer cancel()
	httpRequest, err := http.NewRequestWithContext(
		operationContext,
		http.MethodPost,
		client.effectEndpoint,
		bytes.NewReader(body),
	)
	if err != nil {
		return empty, deploymentFault(
			paasv1.AdapterErrorValidation,
			paasv1.ErrorInvalidArgument,
			"Remote Deployment request could not be constructed.",
			false,
		)
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Accept", "application/json")
	response, err := client.http.Do(httpRequest)
	if err != nil {
		return empty, unknownDeploymentOutcome()
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return empty, deploymentEffectStatusFault(response.StatusCode)
	}
	if response.Header.Get("Content-Type") != "application/json" ||
		response.Header.Get("Content-Encoding") != "" {
		return empty, unknownDeploymentOutcome()
	}
	value, err := nodev1.DecodeDeploymentEffectResponse(response.Body)
	if err != nil || value.Identity != client.identity ||
		value.CommandID != execution.Command.CommandID ||
		value.Result.CommandID != execution.Command.CommandID {
		return empty, unknownDeploymentOutcome()
	}
	return value.Result, nil
}

func (client *DeploymentClient) ObserveDeployment(
	ctx context.Context,
	request paasv1.ObserveDeploymentRequest,
) (paasv1.DeploymentObservation, error) {
	empty := paasv1.DeploymentObservation{}
	if err := client.validateObservation(ctx, request); err != nil {
		return empty, err
	}
	value := nodev1.DeploymentObservationRequest{
		APIVersion: nodev1.APIVersion, Kind: nodev1.DeploymentObservationRequestKind,
		Identity: client.identity, Request: request,
	}
	if nodev1.ValidateDeploymentObservationRequest(value) != nil {
		return empty, invalidRemoteDeployment()
	}
	body, err := json.Marshal(value)
	if err != nil || len(body) > nodev1.MaximumDeploymentObservationRequestBytes {
		return empty, invalidRemoteDeployment()
	}
	operationContext, cancel := context.WithDeadline(ctx, request.Command.Deadline)
	defer cancel()
	httpRequest, err := http.NewRequestWithContext(
		operationContext,
		http.MethodPost,
		client.observationEndpoint,
		bytes.NewReader(body),
	)
	if err != nil {
		return empty, invalidRemoteDeployment()
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Accept", "application/json")
	response, err := client.http.Do(httpRequest)
	if err != nil {
		if errors.Is(operationContext.Err(), context.DeadlineExceeded) {
			return empty, deploymentFault(
				paasv1.AdapterErrorTimeout,
				paasv1.ErrorDeadlineExceeded,
				"Remote Deployment observation exceeded its deadline.",
				true,
			)
		}
		return empty, unavailableDeploymentObservation()
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return empty, deploymentObservationStatusFault(response.StatusCode)
	}
	if response.Header.Get("Content-Type") != "application/json" ||
		response.Header.Get("Content-Encoding") != "" {
		return empty, rejectedDeploymentObservation()
	}
	decoded, err := nodev1.DecodeDeploymentObservationResponse(response.Body)
	if err != nil || decoded.Identity != client.identity ||
		decoded.CommandID != request.Command.CommandID ||
		decoded.Observation.DeploymentID != request.Command.DeploymentID ||
		decoded.Observation.Generation != request.Generation ||
		decoded.Observation.ApplicationRevisionID != request.Command.ApplicationRevisionID ||
		decoded.Observation.ObservedAt.After(time.Now().Add(2*time.Second)) {
		return empty, rejectedDeploymentObservation()
	}
	return decoded.Observation, nil
}

func (client *DeploymentClient) validateEffect(
	ctx context.Context,
	request paasv1.DeploymentExecutionRequest,
	action paasv1.AdapterAction,
) error {
	if client == nil || client.http == nil || client.artifacts == nil || client.secrets == nil || ctx == nil ||
		paasv1.ValidateDeploymentExecutionRequest(request) != nil ||
		request.Command.Action != action ||
		request.Command.ExecutionTargetID != client.identity.ExecutionTargetID ||
		request.Command.BindingRef != client.bindingRef ||
		request.Command.Deadline.Sub(time.Now()) > nodev1.MaximumDeploymentDuration {
		return invalidRemoteDeployment()
	}
	if err := ctx.Err(); err != nil || !time.Now().Before(request.Command.Deadline) {
		return deploymentFault(
			paasv1.AdapterErrorTimeout,
			paasv1.ErrorDeadlineExceeded,
			"Remote Deployment command exceeded its deadline before dispatch.",
			true,
		)
	}
	return nil
}

func (client *DeploymentClient) validateObservation(
	ctx context.Context,
	request paasv1.ObserveDeploymentRequest,
) error {
	if client == nil || client.http == nil || ctx == nil ||
		paasv1.ValidateObserveDeploymentRequest(request) != nil ||
		request.Command.ExecutionTargetID != client.identity.ExecutionTargetID ||
		request.Command.BindingRef != client.bindingRef ||
		request.Command.Deadline.Sub(time.Now()) > nodev1.MaximumDeploymentDuration {
		return invalidRemoteDeployment()
	}
	if err := ctx.Err(); err != nil || !time.Now().Before(request.Command.Deadline) {
		return deploymentFault(
			paasv1.AdapterErrorTimeout,
			paasv1.ErrorDeadlineExceeded,
			"Remote Deployment observation exceeded its deadline before dispatch.",
			true,
		)
	}
	return nil
}

func (client *DeploymentClient) resolveMaterials(
	ctx context.Context,
	request paasv1.DeploymentExecutionRequest,
) (nodev1.DeploymentMaterials, error) {
	if request.Command.Action == paasv1.AdapterStopDeployment {
		return nodev1.DeploymentMaterials{}, nil
	}
	artifactsByDigest := make(map[string]paasv1.ArtifactRef)
	for _, component := range request.ApplicationRevision.Spec.Components {
		artifactsByDigest[component.Artifact.Digest] = component.Artifact
	}
	artifactDigests := make([]string, 0, len(artifactsByDigest))
	for digest := range artifactsByDigest {
		artifactDigests = append(artifactDigests, digest)
	}
	slices.Sort(artifactDigests)
	materials := nodev1.DeploymentMaterials{
		Artifacts: make([]nodev1.ResolvedArtifact, 0, len(artifactDigests)),
	}
	for _, digest := range artifactDigests {
		material, err := client.artifacts.ResolveDeploymentArtifact(ctx, artifactsByDigest[digest])
		if err != nil || material.ArtifactDigest != digest ||
			paasv1.ValidateDigest("localImageId", material.LocalImageID) != nil {
			materials.Clear()
			return nodev1.DeploymentMaterials{}, deploymentFault(
				paasv1.AdapterErrorValidation,
				paasv1.ErrorAdapterRejected,
				"An exact release-admitted image could not be resolved for the selected node.",
				false,
			)
		}
		materials.Artifacts = append(materials.Artifacts, material)
	}
	secretsByKey := make(map[string]paasv1.SecretVersionReference)
	for _, component := range request.Generation.Spec.Components {
		for _, binding := range component.Bindings {
			if binding.SecretVersion != nil {
				key := string(binding.SecretVersion.SecretID) + "\x00" + binding.SecretVersion.Version
				secretsByKey[key] = *binding.SecretVersion
			}
		}
	}
	secretKeys := make([]string, 0, len(secretsByKey))
	for key := range secretsByKey {
		secretKeys = append(secretKeys, key)
	}
	slices.Sort(secretKeys)
	materials.Secrets = make([]nodev1.SecretMaterial, 0, len(secretKeys))
	total := 0
	for _, key := range secretKeys {
		reference := secretsByKey[key]
		content, err := client.secrets.ResolveSecret(ctx, reference)
		if err != nil || len(content) > nodev1.MaximumSecretMaterialBytes ||
			total > nodev1.MaximumDeploymentMaterialBytes-len(content) {
			clear(content)
			materials.Clear()
			return nodev1.DeploymentMaterials{}, deploymentFault(
				paasv1.AdapterErrorUnavailable,
				paasv1.ErrorAdapterUnavailable,
				"An exact secret version could not be resolved safely.",
				false,
			)
		}
		total += len(content)
		materials.Secrets = append(materials.Secrets, nodev1.SecretMaterial{
			Reference: reference, Value: content,
		})
	}
	return materials, nil
}

// CatalogDeploymentArtifactResolver maps an authenticated release catalog to
// the immutable image identity the node must independently inspect.
type CatalogDeploymentArtifactResolver struct {
	entries map[string]string
}

func NewCatalogDeploymentArtifactResolver(
	catalog apphostingv1.ArtifactCatalog,
) (*CatalogDeploymentArtifactResolver, error) {
	if apphostingv1.ValidateArtifactCatalog(catalog) != nil {
		return nil, errors.New("remote Deployment artifact catalog is invalid")
	}
	entries := make(map[string]string, len(catalog.Entries))
	for _, entry := range catalog.Entries {
		entries[entry.ArtifactDigest] = entry.ImageID
	}
	return &CatalogDeploymentArtifactResolver{entries: entries}, nil
}

func (resolver *CatalogDeploymentArtifactResolver) ResolveDeploymentArtifact(
	ctx context.Context,
	artifact paasv1.ArtifactRef,
) (nodev1.ResolvedArtifact, error) {
	if resolver == nil || resolver.entries == nil || ctx == nil ||
		artifact.Kind != paasv1.ArtifactOCIImage ||
		paasv1.ValidateSafeExternalText("artifact.locator", artifact.Locator, 2048, true) != nil ||
		paasv1.ValidateDigest("artifact.digest", artifact.Digest) != nil {
		return nodev1.ResolvedArtifact{}, errors.New("remote Deployment artifact is invalid")
	}
	if err := ctx.Err(); err != nil {
		return nodev1.ResolvedArtifact{}, err
	}
	imageID, found := resolver.entries[artifact.Digest]
	if !found {
		return nodev1.ResolvedArtifact{}, errors.New("remote Deployment artifact is not admitted")
	}
	return nodev1.ResolvedArtifact{ArtifactDigest: artifact.Digest, LocalImageID: imageID}, nil
}

func deploymentEffectStatusFault(status int) error {
	switch status {
	case http.StatusBadRequest:
		return invalidRemoteDeployment()
	case http.StatusUnauthorized, http.StatusForbidden:
		return deploymentFault(
			paasv1.AdapterErrorPermissionDenied,
			paasv1.ErrorPermissionDenied,
			"The selected node denied this controller or binding.",
			false,
		)
	case http.StatusRequestTimeout:
		return deploymentFault(
			paasv1.AdapterErrorTimeout,
			paasv1.ErrorDeadlineExceeded,
			"The selected node rejected an expired Deployment command.",
			true,
		)
	case http.StatusTooManyRequests:
		return deploymentFault(
			paasv1.AdapterErrorRateLimited,
			paasv1.ErrorRateLimited,
			"The selected node reached its bounded Deployment concurrency.",
			true,
		)
	default:
		return unknownDeploymentOutcome()
	}
}

func deploymentObservationStatusFault(status int) error {
	switch status {
	case http.StatusBadRequest:
		return invalidRemoteDeployment()
	case http.StatusUnauthorized, http.StatusForbidden:
		return deploymentFault(
			paasv1.AdapterErrorPermissionDenied,
			paasv1.ErrorPermissionDenied,
			"The selected node denied this controller or binding.",
			false,
		)
	case http.StatusNotFound:
		return deploymentFault(
			paasv1.AdapterErrorNotFound,
			paasv1.ErrorNotFound,
			"The selected node has no state for this exact Deployment generation.",
			false,
		)
	case http.StatusConflict:
		return deploymentFault(
			paasv1.AdapterErrorConflict,
			paasv1.ErrorConflict,
			"The selected node has conflicting Deployment state.",
			false,
		)
	case http.StatusRequestTimeout, http.StatusGatewayTimeout:
		return deploymentFault(
			paasv1.AdapterErrorTimeout,
			paasv1.ErrorDeadlineExceeded,
			"Remote Deployment observation exceeded its deadline.",
			true,
		)
	case http.StatusTooManyRequests:
		return deploymentFault(
			paasv1.AdapterErrorRateLimited,
			paasv1.ErrorRateLimited,
			"The selected node reached its bounded observation concurrency.",
			true,
		)
	case http.StatusServiceUnavailable:
		return unavailableDeploymentObservation()
	default:
		return rejectedDeploymentObservation()
	}
}

func invalidRemoteDeployment() error {
	return deploymentFault(
		paasv1.AdapterErrorValidation,
		paasv1.ErrorInvalidArgument,
		"Remote Deployment input was rejected before any node effect.",
		false,
	)
}

func unknownDeploymentOutcome() error {
	return deploymentFault(
		paasv1.AdapterErrorUnknownOutcome,
		paasv1.ErrorAdapterOutcomeUnknown,
		"The remote Deployment effect outcome is unknown; observe the same target before retrying.",
		true,
	)
}

func unavailableDeploymentObservation() error {
	return deploymentFault(
		paasv1.AdapterErrorUnavailable,
		paasv1.ErrorExecutionTargetUnavailable,
		"The selected node is unavailable for Deployment observation.",
		true,
	)
}

func rejectedDeploymentObservation() error {
	return deploymentFault(
		paasv1.AdapterErrorValidation,
		paasv1.ErrorAdapterRejected,
		"The selected node returned an invalid Deployment observation.",
		false,
	)
}

func deploymentFault(
	class paasv1.AdapterErrorClass,
	code paasv1.ErrorCode,
	message string,
	retryable bool,
) paasv1.AdapterFault {
	normalized := paasv1.NormalizedAdapterError{
		Class: class, Code: code, Message: message, Retryable: retryable,
	}
	if paasv1.ValidateNormalizedAdapterError(normalized) != nil {
		normalized = paasv1.NormalizedAdapterError{
			Class: paasv1.AdapterErrorInternal, Code: paasv1.ErrorInternal,
			Message: "Remote Deployment failure could not be normalized.",
		}
	}
	return paasv1.AdapterFault{Normalized: normalized}
}
