package nethttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	nodev1 "github.com/xiak/matrix/api/adapter/node/v1"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

type ObservationSource interface {
	Current(context.Context) (paasv1.ExecutionTargetObservation, error)
}

type DeploymentService interface {
	Ready(context.Context) error
	ExecuteDeployment(context.Context, nodev1.DeploymentEffectRequest) (paasv1.AdapterResult, error)
	ObserveDeployment(context.Context, paasv1.ObserveDeploymentRequest) (paasv1.DeploymentObservation, error)
	ObserveDeploymentRuntime(context.Context, paasv1.ObserveDeploymentRuntimeRequest) (paasv1.DeploymentRuntimeObservation, error)
	ObserveDeploymentTelemetry(context.Context, paasv1.ObserveDeploymentRuntimeRequest) (
		paasv1.DeploymentRuntimeObservation,
		paasv1.DeploymentResourceObservation,
		error,
	)
}

type Config struct {
	Identity          nodev1.Identity
	ControllerID      string
	BindingRef        string
	MaximumConcurrent int
}

type Handler struct {
	identity      nodev1.Identity
	controllerURI string
	selfURI       string
	bindingRef    string
	source        ObservationSource
	deployments   DeploymentService
	slots         chan struct{}
}

func New(source ObservationSource, deployments DeploymentService, config Config) (*Handler, error) {
	controllerURI, err := nodev1.ControllerURI(config.Identity.InstallationID, config.ControllerID)
	selfURI, _ := nodev1.NodeURI(config.Identity)
	if config.MaximumConcurrent == 0 {
		config.MaximumConcurrent = 8
	}
	if source == nil || deployments == nil || err != nil || nodev1.ValidateIdentity(config.Identity) != nil ||
		paasv1.ValidateID("bindingRef", config.BindingRef) != nil ||
		config.MaximumConcurrent < 1 || config.MaximumConcurrent > 64 {
		return nil, errors.New("node HTTP configuration is invalid")
	}
	return &Handler{
		identity: config.Identity, controllerURI: controllerURI, selfURI: selfURI, bindingRef: config.BindingRef,
		source: source, deployments: deployments, slots: make(chan struct{}, config.MaximumConcurrent),
	}, nil
}

func (handler *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	// Keep this guard even though the listener requires mTLS: accidentally
	// mounting this handler on a plain HTTP server must never authorize a node.
	peerURI := handler.controllerURI
	if request.URL.Path == nodev1.ReadinessPath {
		peerURI = handler.selfURI
	}
	if !handler.authenticated(request, peerURI) {
		reject(response, http.StatusForbidden)
		return
	}
	if request.URL.Path == nodev1.ReadinessPath {
		handler.readiness(response, request)
		return
	}
	switch request.URL.Path {
	case nodev1.ObservationPath:
		handler.observation(response, request)
	case nodev1.DeploymentEffectPath:
		handler.deploymentEffect(response, request)
	case nodev1.DeploymentObservationPath:
		handler.deploymentObservation(response, request)
	case nodev1.DeploymentRuntimeObservationPath:
		handler.deploymentRuntimeObservation(response, request)
	case nodev1.DeploymentTelemetryObservationPath:
		handler.deploymentTelemetryObservation(response, request)
	default:
		reject(response, http.StatusBadRequest)
	}
}

func (handler *Handler) observation(response http.ResponseWriter, request *http.Request) {
	if request.URL.RawPath != "" ||
		request.URL.RawQuery != "" || request.URL.ForceQuery || request.Method != http.MethodPost ||
		request.Header.Get("Content-Type") != "application/json" ||
		request.Header.Get("Content-Encoding") != "" || request.ContentLength > nodev1.MaximumObservationRequestBytes {
		reject(response, http.StatusBadRequest)
		return
	}
	select {
	case handler.slots <- struct{}{}:
		defer func() { <-handler.slots }()
	default:
		reject(response, http.StatusTooManyRequests)
		return
	}
	// Body limits and socket timeouts apply before decoding. The caller cannot
	// extend this boundary by supplying a distant command deadline.
	controller := http.NewResponseController(response)
	_ = controller.SetReadDeadline(time.Now().Add(5 * time.Second))
	value, err := nodev1.DecodeObservationRequest(request.Body)
	if err != nil {
		reject(response, http.StatusBadRequest)
		return
	}
	if value.Identity != handler.identity || value.Command.BindingRef != handler.bindingRef {
		reject(response, http.StatusForbidden)
		return
	}
	now := time.Now()
	if !now.Before(value.Command.Deadline) {
		reject(response, http.StatusRequestTimeout)
		return
	}
	if value.Command.Deadline.Sub(now) > nodev1.MaximumObservationDuration {
		reject(response, http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithDeadline(request.Context(), value.Command.Deadline)
	defer cancel()
	if err := handler.deployments.Ready(ctx); err != nil {
		reject(response, http.StatusServiceUnavailable)
		return
	}
	observation, err := handler.source.Current(ctx)
	if err != nil || ctx.Err() != nil {
		reject(response, http.StatusServiceUnavailable)
		return
	}
	result := nodev1.ObservationResponse{
		APIVersion: nodev1.APIVersion, Kind: nodev1.ObservationResponseKind,
		Identity: handler.identity, CommandID: value.Command.CommandID, Observation: observation,
	}
	if nodev1.ValidateObservationResponse(result) != nil {
		reject(response, http.StatusServiceUnavailable)
		return
	}
	encoded, err := json.Marshal(result)
	if err != nil || len(encoded) > nodev1.MaximumObservationResponseBytes {
		reject(response, http.StatusServiceUnavailable)
		return
	}
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(encoded)
}

func (handler *Handler) deploymentEffect(response http.ResponseWriter, request *http.Request) {
	if !validJSONPost(request, nodev1.MaximumDeploymentEffectRequestBytes) || !handler.acquire(response) {
		return
	}
	defer handler.release()
	controller := http.NewResponseController(response)
	_ = controller.SetReadDeadline(time.Now().Add(15 * time.Second))
	value, err := nodev1.DecodeDeploymentEffectRequest(request.Body)
	if err != nil {
		reject(response, http.StatusBadRequest)
		return
	}
	defer value.Materials.Clear()
	if value.Identity != handler.identity || value.Execution.Command.BindingRef != handler.bindingRef {
		reject(response, http.StatusForbidden)
		return
	}
	now := time.Now()
	if !now.Before(value.Execution.Command.Deadline) {
		reject(response, http.StatusRequestTimeout)
		return
	}
	if value.Execution.Command.Deadline.Sub(now) > nodev1.MaximumDeploymentDuration {
		reject(response, http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithDeadline(request.Context(), value.Execution.Command.Deadline)
	defer cancel()
	result, effectErr := handler.deployments.ExecuteDeployment(ctx, value)
	if effectErr != nil {
		result, err = normalizedEffectFailure(value.Execution.Command.CommandID, effectErr, time.Now())
		if err != nil {
			reject(response, http.StatusServiceUnavailable)
			return
		}
	}
	responseValue := nodev1.DeploymentEffectResponse{
		APIVersion: nodev1.APIVersion, Kind: nodev1.DeploymentEffectResponseKind,
		Identity: handler.identity, CommandID: value.Execution.Command.CommandID, Result: result,
	}
	if nodev1.ValidateDeploymentEffectResponse(responseValue) != nil {
		reject(response, http.StatusServiceUnavailable)
		return
	}
	encoded, err := json.Marshal(responseValue)
	if err != nil || len(encoded) > nodev1.MaximumDeploymentEffectResponseBytes {
		reject(response, http.StatusServiceUnavailable)
		return
	}
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(encoded)
}

func (handler *Handler) deploymentObservation(response http.ResponseWriter, request *http.Request) {
	if !validJSONPost(request, nodev1.MaximumDeploymentObservationRequestBytes) || !handler.acquire(response) {
		return
	}
	defer handler.release()
	controller := http.NewResponseController(response)
	_ = controller.SetReadDeadline(time.Now().Add(5 * time.Second))
	value, err := nodev1.DecodeDeploymentObservationRequest(request.Body)
	if err != nil {
		reject(response, http.StatusBadRequest)
		return
	}
	if value.Identity != handler.identity || value.Request.Command.BindingRef != handler.bindingRef {
		reject(response, http.StatusForbidden)
		return
	}
	now := time.Now()
	if !now.Before(value.Request.Command.Deadline) {
		reject(response, http.StatusRequestTimeout)
		return
	}
	if value.Request.Command.Deadline.Sub(now) > nodev1.MaximumDeploymentDuration {
		reject(response, http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithDeadline(request.Context(), value.Request.Command.Deadline)
	observation, observeErr := handler.deployments.ObserveDeployment(ctx, value.Request)
	contextErr := ctx.Err()
	cancel()
	if observeErr != nil || contextErr != nil {
		reject(response, deploymentObservationStatus(observeErr, contextErr))
		return
	}
	responseValue := nodev1.DeploymentObservationResponse{
		APIVersion: nodev1.APIVersion, Kind: nodev1.DeploymentObservationResponseKind,
		Identity: handler.identity, CommandID: value.Request.Command.CommandID, Observation: observation,
	}
	if nodev1.ValidateDeploymentObservationResponse(responseValue) != nil {
		reject(response, http.StatusServiceUnavailable)
		return
	}
	encoded, err := json.Marshal(responseValue)
	if err != nil || len(encoded) > nodev1.MaximumDeploymentObservationResponseBytes {
		reject(response, http.StatusServiceUnavailable)
		return
	}
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(encoded)
}

func (handler *Handler) deploymentRuntimeObservation(response http.ResponseWriter, request *http.Request) {
	if !validJSONPost(request, nodev1.MaximumDeploymentRuntimeRequestBytes) || !handler.acquire(response) {
		return
	}
	defer handler.release()
	controller := http.NewResponseController(response)
	_ = controller.SetReadDeadline(time.Now().Add(5 * time.Second))
	value, err := nodev1.DecodeDeploymentRuntimeObservationRequest(request.Body)
	if err != nil {
		reject(response, http.StatusBadRequest)
		return
	}
	if value.Identity != handler.identity || value.BindingRef != handler.bindingRef {
		reject(response, http.StatusForbidden)
		return
	}
	now := time.Now()
	if !now.Before(value.Request.Deadline) {
		reject(response, http.StatusRequestTimeout)
		return
	}
	if value.Request.Deadline.Sub(now) > nodev1.MaximumDeploymentDuration {
		reject(response, http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithDeadline(request.Context(), value.Request.Deadline)
	observation, observeErr := handler.deployments.ObserveDeploymentRuntime(ctx, value.Request)
	contextErr := ctx.Err()
	cancel()
	if observeErr != nil || contextErr != nil {
		reject(response, deploymentObservationStatus(observeErr, contextErr))
		return
	}
	responseValue := nodev1.DeploymentRuntimeObservationResponse{
		APIVersion:  nodev1.APIVersion,
		Kind:        nodev1.DeploymentRuntimeObservationResponseKind,
		Identity:    handler.identity,
		RequestID:   value.Request.RequestID,
		Observation: observation,
	}
	if nodev1.ValidateDeploymentRuntimeObservationResponse(responseValue) != nil ||
		observation.DeploymentID != value.Request.DeploymentID ||
		observation.Generation != value.Request.Generation ||
		observation.ApplicationRevisionID != value.Request.ApplicationRevisionID {
		reject(response, http.StatusServiceUnavailable)
		return
	}
	encoded, err := json.Marshal(responseValue)
	if err != nil || len(encoded) > nodev1.MaximumDeploymentRuntimeResponseBytes {
		reject(response, http.StatusServiceUnavailable)
		return
	}
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(encoded)
}

func (handler *Handler) deploymentTelemetryObservation(response http.ResponseWriter, request *http.Request) {
	if !validJSONPost(request, nodev1.MaximumDeploymentRuntimeRequestBytes) || !handler.acquire(response) {
		return
	}
	defer handler.release()
	controller := http.NewResponseController(response)
	_ = controller.SetReadDeadline(time.Now().Add(5 * time.Second))
	value, err := nodev1.DecodeDeploymentTelemetryObservationRequest(request.Body)
	if err != nil {
		reject(response, http.StatusBadRequest)
		return
	}
	if value.Identity != handler.identity || value.BindingRef != handler.bindingRef {
		reject(response, http.StatusForbidden)
		return
	}
	now := time.Now()
	if !now.Before(value.Request.Deadline) {
		reject(response, http.StatusRequestTimeout)
		return
	}
	if value.Request.Deadline.Sub(now) > nodev1.MaximumDeploymentDuration {
		reject(response, http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithDeadline(request.Context(), value.Request.Deadline)
	runtimeObservation, resourceObservation, observeErr :=
		handler.deployments.ObserveDeploymentTelemetry(ctx, value.Request)
	contextErr := ctx.Err()
	cancel()
	if observeErr != nil || contextErr != nil {
		reject(response, deploymentObservationStatus(observeErr, contextErr))
		return
	}
	responseValue := nodev1.DeploymentTelemetryObservationResponse{
		APIVersion: nodev1.APIVersion,
		Kind:       nodev1.DeploymentTelemetryObservationResponseKind,
		Identity:   handler.identity,
		RequestID:  value.Request.RequestID,
		Runtime:    runtimeObservation,
		Resources:  resourceObservation,
	}
	if nodev1.ValidateDeploymentTelemetryObservationResponse(responseValue) != nil ||
		runtimeObservation.DeploymentID != value.Request.DeploymentID ||
		runtimeObservation.Generation != value.Request.Generation ||
		runtimeObservation.ApplicationRevisionID != value.Request.ApplicationRevisionID {
		reject(response, http.StatusServiceUnavailable)
		return
	}
	encoded, err := json.Marshal(responseValue)
	if err != nil || len(encoded) > nodev1.MaximumDeploymentTelemetryResponseBytes {
		reject(response, http.StatusServiceUnavailable)
		return
	}
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(encoded)
}

func validJSONPost(request *http.Request, maximum int64) bool {
	return request.URL.RawPath == "" && request.URL.RawQuery == "" && !request.URL.ForceQuery &&
		request.Method == http.MethodPost && request.Header.Get("Content-Type") == "application/json" &&
		request.Header.Get("Content-Encoding") == "" && request.ContentLength <= maximum
}

func (handler *Handler) acquire(response http.ResponseWriter) bool {
	select {
	case handler.slots <- struct{}{}:
		return true
	default:
		reject(response, http.StatusTooManyRequests)
		return false
	}
}

func (handler *Handler) release() { <-handler.slots }

func normalizedEffectFailure(
	commandID paasv1.CommandID,
	err error,
	observedAt time.Time,
) (paasv1.AdapterResult, error) {
	var fault paasv1.AdapterFault
	if !errors.As(err, &fault) || paasv1.ValidateNormalizedAdapterError(fault.Normalized) != nil {
		return paasv1.AdapterResult{}, errors.New("node Deployment failure is not normalized")
	}
	state := paasv1.AdapterResultFailed
	if fault.Normalized.Class == paasv1.AdapterErrorUnknownOutcome {
		state = paasv1.AdapterResultUnknown
	}
	normalized := fault.Normalized
	result := paasv1.AdapterResult{
		CommandID: commandID, State: state, Error: &normalized,
		ObservedAt: observedAt.UTC().Truncate(time.Microsecond),
	}
	if paasv1.ValidateAdapterResult(result) != nil {
		return paasv1.AdapterResult{}, errors.New("node Deployment failure is invalid")
	}
	return result, nil
}

func deploymentObservationStatus(observeErr, contextErr error) int {
	if errors.Is(contextErr, context.DeadlineExceeded) {
		return http.StatusGatewayTimeout
	}
	var fault paasv1.AdapterFault
	if !errors.As(observeErr, &fault) || paasv1.ValidateNormalizedAdapterError(fault.Normalized) != nil {
		return http.StatusServiceUnavailable
	}
	switch fault.Normalized.Class {
	case paasv1.AdapterErrorNotFound:
		return http.StatusNotFound
	case paasv1.AdapterErrorPermissionDenied:
		return http.StatusForbidden
	case paasv1.AdapterErrorConflict:
		return http.StatusConflict
	case paasv1.AdapterErrorValidation:
		return http.StatusBadRequest
	case paasv1.AdapterErrorRateLimited:
		return http.StatusTooManyRequests
	case paasv1.AdapterErrorTimeout:
		return http.StatusGatewayTimeout
	default:
		return http.StatusServiceUnavailable
	}
}

func (handler *Handler) readiness(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet || request.URL.RawPath != "" || request.URL.RawQuery != "" ||
		request.URL.ForceQuery || request.ContentLength != 0 || len(request.TransferEncoding) != 0 ||
		request.Header.Get("Content-Encoding") != "" {
		reject(response, http.StatusBadRequest)
		return
	}
	select {
	case handler.slots <- struct{}{}:
		defer func() { <-handler.slots }()
	default:
		reject(response, http.StatusTooManyRequests)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), 5*time.Second)
	defer cancel()
	if err := handler.deployments.Ready(ctx); err != nil {
		reject(response, http.StatusServiceUnavailable)
		return
	}
	observation, err := handler.source.Current(ctx)
	now := time.Now()
	if err != nil || ctx.Err() != nil || observation.ExecutionTargetID != handler.identity.ExecutionTargetID ||
		paasv1.ValidateExecutionTargetObservation(observation) != nil || observation.Health != paasv1.ExecutionTargetHealthReady ||
		observation.ObservedAt.After(now) || !now.Before(observation.ObservedAt.Add(nodev1.MaximumObservationAge)) ||
		observation.Usage == nil || observation.Usage.ObservedAt.After(now) ||
		!now.Before(observation.Usage.ValidUntil) ||
		!now.Before(observation.Usage.ObservedAt.Add(nodev1.MaximumObservationAge)) ||
		observation.Usage.CPU.State != paasv1.MeasurementAvailable ||
		observation.Usage.Memory.State != paasv1.MeasurementAvailable ||
		observation.Usage.FilesystemsState != paasv1.MeasurementAvailable {
		reject(response, http.StatusServiceUnavailable)
		return
	}
	observedAt := observation.ObservedAt
	if observation.Usage.ObservedAt.Before(observedAt) {
		observedAt = observation.Usage.ObservedAt
	}
	validUntil := observedAt.Add(nodev1.MaximumObservationAge)
	if observation.Usage.ValidUntil.Before(validUntil) {
		validUntil = observation.Usage.ValidUntil
	}
	value := nodev1.Readiness{
		APIVersion: nodev1.APIVersion, Kind: nodev1.ReadinessResponseKind, Identity: handler.identity,
		IdentityFingerprint: observation.IdentityFingerprint, ObservedAt: observedAt, ValidUntil: validUntil,
	}
	if nodev1.ValidateReadiness(value) != nil {
		reject(response, http.StatusServiceUnavailable)
		return
	}
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) > nodev1.MaximumReadinessResponseBytes {
		reject(response, http.StatusServiceUnavailable)
		return
	}
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(encoded)
}

func (handler *Handler) authenticated(request *http.Request, peerURI string) bool {
	state := request.TLS
	if state == nil || len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
		return false
	}
	leaf := state.PeerCertificates[0]
	now := time.Now()
	return !leaf.IsCA && !now.Before(leaf.NotBefore) && now.Before(leaf.NotAfter) &&
		nodev1.MatchesIdentity(leaf.URIs, peerURI)
}

func reject(response http.ResponseWriter, status int) {
	response.WriteHeader(status)
	_, _ = response.Write([]byte(`{"error":"node observation unavailable"}`))
}
