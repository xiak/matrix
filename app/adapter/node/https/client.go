// Package nodehttps adapts infrastructure observations through a bounded,
// mutually authenticated node connection. It does not select a target or fall
// back to local execution.
package nodehttps

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	nodev1 "github.com/xiak/matrix/api/adapter/node/v1"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

type Config struct {
	Endpoint            string
	Identity            nodev1.Identity
	ControllerID        string
	BindingRef          string
	ExpectedFingerprint string
	// Credentials is evaluated for each TLS connection. An invalid replacement
	// must fail closed rather than using a credential cached at process startup.
	Credentials func() (Credentials, error)
}

type Client struct {
	endpoint            string
	terminalEndpoint    string
	identity            nodev1.Identity
	bindingRef          string
	expectedFingerprint string
	http                *http.Client
	terminalHTTP        *http.Client
}

func New(config Config) (*Client, error) {
	endpoint, connection, err := newControllerConnection(
		config,
		nodev1.MaximumObservationDuration,
		5*time.Second,
	)
	if err != nil {
		return nil, err
	}
	terminalEndpoint, terminalConnection, err := newControllerConnection(
		config,
		0,
		5*time.Second,
	)
	if err != nil {
		connection.CloseIdleConnections()
		return nil, err
	}
	return &Client{
		endpoint:         endpoint + nodev1.ObservationPath,
		terminalEndpoint: terminalEndpoint + nodev1.DeploymentTerminalSessionPath,
		identity:         config.Identity,
		bindingRef:       config.BindingRef, expectedFingerprint: config.ExpectedFingerprint,
		http: connection, terminalHTTP: terminalConnection,
	}, nil
}

func newControllerConnection(
	config Config,
	timeout time.Duration,
	responseHeaderTimeout time.Duration,
) (string, *http.Client, error) {
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || !validEndpoint(endpoint) || nodev1.ValidateIdentity(config.Identity) != nil ||
		paasv1.ValidateID("bindingRef", config.BindingRef) != nil ||
		paasv1.ValidateDigest("expectedFingerprint", config.ExpectedFingerprint) != nil || config.Credentials == nil {
		return "", nil, errors.New("node connection configuration is invalid")
	}
	credentials, err := config.Credentials()
	if err != nil {
		return "", nil, errors.New("node connection credentials are unavailable")
	}
	_, err = clientTLS(credentials, config.Identity, config.ControllerID)
	if err != nil {
		return "", nil, err
	}
	connection := newBoundedHTTPClient(nil, timeout, responseHeaderTimeout)
	connection.Transport.(*http.Transport).DialTLSContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		credentials, err := config.Credentials()
		if err != nil {
			return nil, errTLSIdentity
		}
		security, err := clientTLS(credentials, config.Identity, config.ControllerID)
		if err != nil {
			return nil, errTLSIdentity
		}
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return nil, errTLSIdentity
		}
		security.ServerName = host
		bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		dialer := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 5 * time.Second}, Config: security}
		return dialer.DialContext(bounded, network, address)
	}
	return endpoint.String(), connection, nil
}

func newHTTPClient(security *tls.Config) *http.Client {
	return newBoundedHTTPClient(
		security,
		nodev1.MaximumObservationDuration,
		5*time.Second,
	)
}

func newBoundedHTTPClient(
	security *tls.Config,
	timeout time.Duration,
	responseHeaderTimeout time.Duration,
) *http.Client {
	transport := &http.Transport{
		Proxy:           nil,
		DialContext:     (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		TLSClientConfig: security, TLSHandshakeTimeout: 5 * time.Second,
		ResponseHeaderTimeout: responseHeaderTimeout, MaxResponseHeaderBytes: 32 * 1024,
		MaxConnsPerHost: 8, DisableCompression: true, DisableKeepAlives: true,
	}
	return &http.Client{
		Transport: transport, Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// ReadinessClient uses only this node's own credential. Possessing it cannot
// construct a controller client or invoke a controller observation/action.
type ReadinessClient struct {
	endpoint    string
	identity    nodev1.Identity
	fingerprint string
	http        *http.Client
}

func NewReadinessClient(endpointText string, identity nodev1.Identity, fingerprint string, credentials Credentials) (*ReadinessClient, error) {
	endpoint, err := url.Parse(endpointText)
	if err != nil || !validEndpoint(endpoint) || nodev1.ValidateIdentity(identity) != nil ||
		paasv1.ValidateDigest("identityFingerprint", fingerprint) != nil {
		return nil, errors.New("node readiness connection is invalid")
	}
	security, err := readinessClientTLS(credentials, identity)
	if err != nil {
		return nil, err
	}
	return &ReadinessClient{endpoint: endpoint.String() + nodev1.ReadinessPath,
		identity: identity, fingerprint: fingerprint, http: newHTTPClient(security)}, nil
}

func (client *ReadinessClient) Close() { client.http.CloseIdleConnections() }

func (client *ReadinessClient) Verify(ctx context.Context) (nodev1.Readiness, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, client.endpoint, nil)
	if err != nil {
		return nodev1.Readiness{}, fault(paasv1.ErrorAdapterRejected)
	}
	response, err := client.http.Do(request)
	if err != nil {
		return nodev1.Readiness{}, fault(paasv1.ErrorExecutionTargetUnavailable)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nodev1.Readiness{}, responseFault(response.StatusCode)
	}
	if response.Header.Get("Content-Type") != "application/json" || response.Header.Get("Content-Encoding") != "" {
		return nodev1.Readiness{}, fault(paasv1.ErrorAdapterRejected)
	}
	value, err := nodev1.DecodeReadiness(response.Body)
	now := time.Now()
	if err != nil || value.Identity != client.identity || value.IdentityFingerprint != client.fingerprint ||
		value.ObservedAt.After(now) || !now.Before(value.ValidUntil) {
		return nodev1.Readiness{}, fault(paasv1.ErrorAdapterRejected)
	}
	return value, nil
}

func validEndpoint(value *url.URL) bool {
	if value == nil || value.Scheme != "https" || value.User != nil || value.Opaque != "" ||
		value.Path != "" || value.RawPath != "" || value.RawQuery != "" || value.ForceQuery ||
		value.Fragment != "" || strings.Contains(value.Host, "%") {
		return false
	}
	host, portText, err := net.SplitHostPort(value.Host)
	port, portErr := strconv.ParseUint(portText, 10, 16)
	return err == nil && portErr == nil && host != "" && port > 0
}

func (client *Client) Close() {
	if client == nil {
		return
	}
	if client.http != nil {
		client.http.CloseIdleConnections()
	}
	if client.terminalHTTP != nil {
		client.terminalHTTP.CloseIdleConnections()
	}
}

func (client *Client) Capabilities(ctx context.Context) (paasv1.AdapterCapabilitiesContract, error) {
	if err := ctx.Err(); err != nil {
		return paasv1.AdapterCapabilitiesContract{}, err
	}
	return paasv1.AdapterCapabilitiesContract{
		Adapter:             paasv1.AdapterRef{Kind: paasv1.AdapterInfrastructure, Name: "nodehttps", ContractVersion: "v1"},
		Actions:             []paasv1.AdapterAction{paasv1.AdapterCapabilities, paasv1.AdapterInspectExecutionTarget, paasv1.AdapterObserveExecutionTarget},
		IsolationGuarantees: []paasv1.IsolationGuarantee{paasv1.IsolationWorkload},
		ObservedAt:          time.Now().UTC().Truncate(time.Microsecond),
	}, nil
}

func (client *Client) InspectExecutionTarget(ctx context.Context, request paasv1.InspectExecutionTargetRequest) (paasv1.ExecutionTargetObservation, error) {
	if paasv1.ValidateInspectExecutionTargetRequest(request) != nil {
		return paasv1.ExecutionTargetObservation{}, fault(paasv1.ErrorInvalidArgument)
	}
	return client.observe(ctx, request.Command)
}

func (client *Client) ObserveExecutionTarget(ctx context.Context, request paasv1.ObserveExecutionTargetRequest) (paasv1.ExecutionTargetObservation, error) {
	if paasv1.ValidateObserveExecutionTargetRequest(request) != nil {
		return paasv1.ExecutionTargetObservation{}, fault(paasv1.ErrorInvalidArgument)
	}
	return client.observe(ctx, request.Command)
}

func (client *Client) observe(ctx context.Context, command paasv1.AdapterCommandEnvelope) (paasv1.ExecutionTargetObservation, error) {
	empty := paasv1.ExecutionTargetObservation{}
	request := nodev1.ObservationRequest{
		APIVersion: nodev1.APIVersion, Kind: nodev1.ObservationRequestKind, Identity: client.identity, Command: command,
	}
	if nodev1.ValidateObservationRequest(request) != nil || command.BindingRef != client.bindingRef ||
		time.Until(command.Deadline) > nodev1.MaximumObservationDuration {
		return empty, fault(paasv1.ErrorInvalidArgument)
	}
	if !time.Now().Before(command.Deadline) {
		return empty, fault(paasv1.ErrorDeadlineExceeded)
	}
	operationContext, cancel := context.WithDeadline(ctx, command.Deadline)
	defer cancel()
	body, err := json.Marshal(request)
	if err != nil || len(body) > nodev1.MaximumObservationRequestBytes {
		return empty, fault(paasv1.ErrorInvalidArgument)
	}
	httpRequest, err := http.NewRequestWithContext(operationContext, http.MethodPost, client.endpoint, bytes.NewReader(body))
	if err != nil {
		return empty, fault(paasv1.ErrorInvalidArgument)
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Accept", "application/json")
	response, err := client.http.Do(httpRequest)
	if err != nil {
		if errors.Is(operationContext.Err(), context.DeadlineExceeded) {
			return empty, fault(paasv1.ErrorDeadlineExceeded)
		}
		return empty, fault(paasv1.ErrorExecutionTargetUnavailable)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return empty, responseFault(response.StatusCode)
	}
	if response.Header.Get("Content-Type") != "application/json" || response.Header.Get("Content-Encoding") != "" {
		return empty, fault(paasv1.ErrorAdapterRejected)
	}
	value, err := nodev1.DecodeObservationResponse(response.Body)
	if errors.Is(operationContext.Err(), context.DeadlineExceeded) {
		return empty, fault(paasv1.ErrorDeadlineExceeded)
	}
	if err != nil || value.Identity != client.identity || value.CommandID != command.CommandID ||
		value.Observation.IdentityFingerprint != client.expectedFingerprint ||
		value.Observation.ObservedAt.After(time.Now().Add(2*time.Second)) || value.Observation.Usage == nil ||
		value.Observation.Usage.ObservedAt.After(time.Now().Add(2*time.Second)) ||
		value.Observation.Usage.ValidUntil.Sub(value.Observation.Usage.ObservedAt) > nodev1.MaximumObservationAge {
		return empty, fault(paasv1.ErrorAdapterRejected)
	}
	if !time.Now().Before(value.Observation.ObservedAt.Add(nodev1.MaximumObservationAge)) {
		return empty, fault(paasv1.ErrorExecutionTargetUnavailable)
	}
	usage := value.Observation.Usage.Snapshot(time.Now())
	value.Observation.Usage = &usage
	return value.Observation, nil
}

func responseFault(status int) error {
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden:
		return fault(paasv1.ErrorPermissionDenied)
	case http.StatusRequestTimeout, http.StatusGatewayTimeout:
		return fault(paasv1.ErrorDeadlineExceeded)
	case http.StatusTooManyRequests:
		return fault(paasv1.ErrorRateLimited)
	case http.StatusServiceUnavailable:
		return fault(paasv1.ErrorExecutionTargetUnavailable)
	default:
		return fault(paasv1.ErrorAdapterRejected)
	}
}

func fault(code paasv1.ErrorCode) paasv1.AdapterFault {
	value := paasv1.NormalizedAdapterError{Code: code}
	switch code {
	case paasv1.ErrorPermissionDenied:
		value.Class, value.Message = paasv1.AdapterErrorPermissionDenied, "node access denied"
	case paasv1.ErrorDeadlineExceeded:
		value.Class, value.Message, value.Retryable = paasv1.AdapterErrorTimeout, "node observation deadline exceeded", true
	case paasv1.ErrorRateLimited:
		value.Class, value.Message, value.Retryable = paasv1.AdapterErrorRateLimited, "node observation concurrency exceeded", true
	case paasv1.ErrorExecutionTargetUnavailable:
		value.Class, value.Message, value.Retryable = paasv1.AdapterErrorUnavailable, "node observation is unavailable", true
	default:
		value.Class, value.Message = paasv1.AdapterErrorValidation, "node observation was rejected"
	}
	return paasv1.AdapterFault{Normalized: value}
}
