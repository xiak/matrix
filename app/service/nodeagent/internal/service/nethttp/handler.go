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

type Config struct {
	Identity          nodev1.Identity
	ControllerID      string
	BindingRef        string
	MaximumConcurrent int
}

type Handler struct {
	identity      nodev1.Identity
	controllerURI string
	bindingRef    string
	source        ObservationSource
	slots         chan struct{}
}

func New(source ObservationSource, config Config) (*Handler, error) {
	controllerURI, err := nodev1.ControllerURI(config.Identity.InstallationID, config.ControllerID)
	if config.MaximumConcurrent == 0 {
		config.MaximumConcurrent = 8
	}
	if source == nil || err != nil || nodev1.ValidateIdentity(config.Identity) != nil ||
		paasv1.ValidateID("bindingRef", config.BindingRef) != nil ||
		config.MaximumConcurrent < 1 || config.MaximumConcurrent > 64 {
		return nil, errors.New("node HTTP configuration is invalid")
	}
	return &Handler{
		identity: config.Identity, controllerURI: controllerURI, bindingRef: config.BindingRef,
		source: source, slots: make(chan struct{}, config.MaximumConcurrent),
	}, nil
}

func (handler *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	// Keep this guard even though the listener requires mTLS: accidentally
	// mounting this handler on a plain HTTP server must never authorize a node.
	if !handler.authenticated(request) {
		reject(response, http.StatusForbidden)
		return
	}
	if request.URL.Path != nodev1.ObservationPath || request.URL.RawPath != "" ||
		request.URL.RawQuery != "" || request.URL.ForceQuery || request.Method != http.MethodPost ||
		request.Header.Get("Content-Type") != "application/json" ||
		request.Header.Get("Content-Encoding") != "" || request.ContentLength > nodev1.MaximumObservationBytes {
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
	if err != nil || len(encoded) > nodev1.MaximumObservationBytes {
		reject(response, http.StatusServiceUnavailable)
		return
	}
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(encoded)
}

func (handler *Handler) authenticated(request *http.Request) bool {
	state := request.TLS
	if state == nil || len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
		return false
	}
	leaf := state.PeerCertificates[0]
	now := time.Now()
	return !leaf.IsCA && !now.Before(leaf.NotBefore) && now.Before(leaf.NotAfter) &&
		nodev1.MatchesIdentity(leaf.URIs, handler.controllerURI)
}

func reject(response http.ResponseWriter, status int) {
	response.WriteHeader(status)
	_, _ = response.Write([]byte(`{"error":"node observation unavailable"}`))
}
