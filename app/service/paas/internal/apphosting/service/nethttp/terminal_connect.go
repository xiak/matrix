package nethttp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	nodev1 "github.com/xiak/matrix/api/adapter/node/v1"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/port"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/terminalsession"
)

const (
	terminalNodeOpenTimeout = 10 * time.Second
	terminalWriteTimeout    = 5 * time.Second
)

type terminalRegistry struct {
	mu       sync.Mutex
	sessions map[paasv1.ResourceID]chan paasv1.TerminalSessionOutcome
}

func newTerminalRegistry() *terminalRegistry {
	return &terminalRegistry{sessions: make(map[paasv1.ResourceID]chan paasv1.TerminalSessionOutcome)}
}

func (registry *terminalRegistry) register(
	id paasv1.ResourceID,
) (<-chan paasv1.TerminalSessionOutcome, bool) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if _, exists := registry.sessions[id]; exists {
		return nil, false
	}
	revoked := make(chan paasv1.TerminalSessionOutcome, 1)
	registry.sessions[id] = revoked
	return revoked, true
}

func (registry *terminalRegistry) remove(id paasv1.ResourceID) {
	registry.mu.Lock()
	delete(registry.sessions, id)
	registry.mu.Unlock()
}

func (registry *terminalRegistry) revoke(id paasv1.ResourceID, outcome paasv1.TerminalSessionOutcome) {
	registry.mu.Lock()
	destination := registry.sessions[id]
	registry.mu.Unlock()
	if destination == nil {
		return
	}
	select {
	case destination <- outcome:
	default:
	}
}

type northboundTerminalEvent struct {
	kind    websocket.MessageType
	content []byte
	err     error
}

type nodeTerminalEvent struct {
	output  []byte
	control *nodev1.TerminalServerControl
	err     error
}

func (value *handler) connectTerminalSession(response http.ResponseWriter, request *http.Request) {
	requestID, ok := value.beginRequest(response)
	if !ok {
		return
	}
	sessionID, ok := pathTerminalSessionID(response, request, "terminalSessionId")
	if !ok {
		return
	}
	if !validNorthboundTerminalUpgrade(request) {
		writeProblem(response, requestID, http.StatusBadRequest, paasv1.ErrorInvalidArgument,
			"Invalid terminal connection", "terminal connection requires an exact same-origin one-time WebSocket upgrade", false)
		return
	}
	rawTicket, ok := exactTerminalCookie(request)
	if !ok {
		writeProblem(response, requestID, http.StatusUnauthorized, paasv1.ErrorUnauthenticated,
			"Unauthenticated", "one valid terminal connection ticket is required", false)
		return
	}
	ticketDigest := terminalTicketDigest(rawTicket)
	path := value.terminalConnectPath(sessionID)
	http.SetCookie(response, &http.Cookie{
		Name: terminalTicketCookie, Value: "", Path: path,
		Expires: time.Unix(1, 0).UTC(), MaxAge: -1,
		HttpOnly: true, Secure: request.TLS != nil || value.config.TerminalCookieSecure,
		SameSite: http.SameSiteStrictMode,
	})
	stored, err := value.terminal.Consume(request.Context(), sessionID, ticketDigest)
	if err != nil {
		writeTerminalError(response, requestID, err)
		return
	}
	connection, err := websocket.Accept(response, request, &websocket.AcceptOptions{
		Subprotocols:    []string{nodev1.TerminalSubprotocol},
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		value.finishTerminal(stored, paasv1.TerminalSessionDisconnected)
		return
	}
	defer connection.CloseNow()
	connection.SetReadLimit(paasv1.MaximumTerminalFrameBytes)
	if connection.Subprotocol() != nodev1.TerminalSubprotocol {
		value.finishTerminal(stored, paasv1.TerminalSessionFailed)
		return
	}
	nodeRequest, err := terminalNodeRequest(stored, time.Now())
	if err != nil {
		writeNorthboundControl(request.Context(), connection, nodev1.TerminalServerControl{
			Type: nodev1.TerminalServerError, Error: nodev1.TerminalErrorFailed,
		})
		value.finishTerminal(stored, paasv1.TerminalSessionFailed)
		return
	}
	openContext, cancelOpen := context.WithDeadline(request.Context(), nodeRequest.Request.Deadline)
	nodeConnection, err := value.terminalConnector.OpenTerminal(
		openContext, stored.Binding.BindingRef, nodeRequest,
	)
	cancelOpen()
	if err != nil {
		outcome, code := northboundTerminalOpenFailure(err)
		writeNorthboundControl(request.Context(), connection, nodev1.TerminalServerControl{
			Type: nodev1.TerminalServerError, Error: code,
		})
		value.finishTerminal(stored, outcome)
		return
	}
	defer nodeConnection.Close()
	revoked, registered := value.terminalRegistry.register(sessionID)
	if !registered {
		value.finishTerminal(stored, paasv1.TerminalSessionFailed)
		return
	}
	defer value.terminalRegistry.remove(sessionID)
	active, err := value.terminal.Activate(request.Context(), stored)
	if err != nil || terminalsession.ValidateStoredSession(active) != nil ||
		active.Session.State != paasv1.TerminalSessionActive ||
		!sameTerminalConnectionAuthority(stored, active) {
		value.finishTerminal(stored, paasv1.TerminalSessionFailed)
		return
	}
	if !writeNorthboundControl(request.Context(), connection, nodev1.TerminalServerControl{Type: nodev1.TerminalServerReady}) {
		value.finishTerminal(active, paasv1.TerminalSessionDisconnected)
		return
	}
	outcome := bridgeNorthboundTerminal(
		request.Context(), connection, nodeConnection, active.Session.ExpiresAt, revoked,
	)
	value.finishTerminal(active, outcome)
}

func sameTerminalConnectionAuthority(
	consumed terminalsession.StoredSession,
	active terminalsession.StoredSession,
) bool {
	return consumed.Session.ID == active.Session.ID &&
		consumed.Session.Scope == active.Session.Scope &&
		consumed.Session.DeploymentID == active.Session.DeploymentID &&
		consumed.Session.Generation == active.Session.Generation &&
		consumed.Session.ApplicationRevisionID == active.Session.ApplicationRevisionID &&
		consumed.Session.InstanceID == active.Session.InstanceID &&
		consumed.Session.Size == active.Session.Size &&
		consumed.Session.CreatedAt == active.Session.CreatedAt &&
		consumed.Session.ConnectBefore == active.Session.ConnectBefore &&
		consumed.Session.ExpiresAt == active.Session.ExpiresAt &&
		consumed.Binding == active.Binding && consumed.Subject == active.Subject &&
		consumed.IAMDecisionID == active.IAMDecisionID && consumed.RequestID == active.RequestID &&
		consumed.IdempotencyFingerprint == active.IdempotencyFingerprint &&
		consumed.RequestDigest == active.RequestDigest
}

func bridgeNorthboundTerminal(
	requestContext context.Context,
	browser *websocket.Conn,
	node port.TerminalConnection,
	expiresAt time.Time,
	revoked <-chan paasv1.TerminalSessionOutcome,
) paasv1.TerminalSessionOutcome {
	ctx, cancel := context.WithCancel(requestContext)
	defer cancel()
	browserEvents := make(chan northboundTerminalEvent, 1)
	nodeEvents := make(chan nodeTerminalEvent, 8)
	go readNorthboundTerminal(ctx, browser, browserEvents)
	go readNodeTerminal(ctx, node, nodeEvents)
	idle := time.NewTimer(paasv1.TerminalSessionIdleTimeout)
	defer idle.Stop()
	absolute := time.NewTimer(time.Until(expiresAt))
	defer absolute.Stop()
	for {
		select {
		case <-ctx.Done():
			return paasv1.TerminalSessionDisconnected
		case outcome := <-revoked:
			_ = browser.Close(websocket.StatusPolicyViolation, "terminal revoked")
			return outcome
		case <-absolute.C:
			_ = browser.Close(websocket.StatusPolicyViolation, "terminal expired")
			return paasv1.TerminalSessionExpired
		case <-idle.C:
			_ = browser.Close(websocket.StatusPolicyViolation, "terminal idle timeout")
			return paasv1.TerminalSessionExpired
		case event := <-nodeEvents:
			if event.err != nil {
				return paasv1.TerminalSessionFailed
			}
			resetTerminalTimer(idle)
			if len(event.output) > 0 {
				written := len(event.output) <= paasv1.MaximumTerminalFrameBytes &&
					writeNorthboundMessage(ctx, browser, websocket.MessageBinary, event.output)
				clear(event.output)
				if !written {
					return paasv1.TerminalSessionDisconnected
				}
				continue
			}
			if event.control == nil {
				return paasv1.TerminalSessionFailed
			}
			writeNorthboundControl(ctx, browser, *event.control)
			switch event.control.Type {
			case nodev1.TerminalServerExit:
				return paasv1.TerminalSessionCompleted
			case nodev1.TerminalServerError:
				if event.control.Error == nodev1.TerminalErrorUnsupported {
					return paasv1.TerminalSessionUnsupported
				}
				return paasv1.TerminalSessionFailed
			default:
				return paasv1.TerminalSessionFailed
			}
		case event := <-browserEvents:
			if event.err != nil {
				return paasv1.TerminalSessionDisconnected
			}
			resetTerminalTimer(idle)
			switch event.kind {
			case websocket.MessageBinary:
				if len(event.content) == 0 || len(event.content) > paasv1.MaximumTerminalFrameBytes ||
					node.SendInput(ctx, event.content) != nil {
					clear(event.content)
					return paasv1.TerminalSessionFailed
				}
				clear(event.content)
			case websocket.MessageText:
				control, err := nodev1.DecodeTerminalClientControl(bytes.NewReader(event.content))
				clear(event.content)
				if err != nil {
					return paasv1.TerminalSessionFailed
				}
				operationContext, cancelOperation := context.WithTimeout(ctx, terminalWriteTimeout)
				if control.Type == nodev1.TerminalClientClose {
					err = node.CloseInput(operationContext)
					cancelOperation()
					if err != nil {
						return paasv1.TerminalSessionFailed
					}
					return paasv1.TerminalSessionCompleted
				}
				err = node.Resize(operationContext, *control.Size)
				cancelOperation()
				if err != nil {
					return paasv1.TerminalSessionFailed
				}
			default:
				clear(event.content)
				return paasv1.TerminalSessionFailed
			}
		}
	}
}

func readNorthboundTerminal(
	ctx context.Context,
	connection *websocket.Conn,
	events chan<- northboundTerminalEvent,
) {
	for {
		kind, content, err := connection.Read(ctx)
		event := northboundTerminalEvent{kind: kind, content: content, err: err}
		select {
		case events <- event:
		case <-ctx.Done():
			clear(content)
			return
		}
		if err != nil {
			return
		}
	}
}

func readNodeTerminal(
	ctx context.Context,
	connection port.TerminalConnection,
	events chan<- nodeTerminalEvent,
) {
	for {
		output, control, err := connection.Receive(ctx)
		event := nodeTerminalEvent{output: output, control: control, err: err}
		select {
		case events <- event:
		case <-ctx.Done():
			clear(output)
			return
		}
		if err != nil {
			return
		}
	}
}

func (value *handler) finishTerminal(
	stored terminalsession.StoredSession,
	outcome paasv1.TerminalSessionOutcome,
) {
	ctx, cancel := context.WithTimeout(context.Background(), terminalWriteTimeout)
	defer cancel()
	_, _, _ = value.terminal.End(
		ctx, stored.Session.Scope.TenantID, stored.Session.ID, outcome,
	)
}

func terminalNodeRequest(
	stored terminalsession.StoredSession,
	now time.Time,
) (nodev1.TerminalOpenRequest, error) {
	if terminalsession.ValidateStoredSession(stored) != nil ||
		stored.Session.State != paasv1.TerminalSessionConnecting {
		return nodev1.TerminalOpenRequest{}, errors.New("stored terminal connection proof is invalid")
	}
	deadline := now.UTC().Truncate(time.Microsecond).Add(terminalNodeOpenTimeout)
	if !deadline.Before(stored.Session.ExpiresAt) {
		return nodev1.TerminalOpenRequest{}, errors.New("terminal connection has no open window")
	}
	return nodev1.TerminalOpenRequest{
		APIVersion:        nodev1.APIVersion,
		Kind:              nodev1.TerminalOpenRequestKind,
		BindingRef:        stored.Binding.BindingRef,
		TerminalSessionID: stored.Session.ID,
		Request: paasv1.ObserveDeploymentRuntimeRequest{
			RequestID:             paasv1.CommandID(stored.Session.ID),
			Scope:                 stored.Session.Scope,
			DeploymentID:          stored.Binding.DeploymentID,
			Generation:            stored.Binding.Generation,
			ApplicationRevisionID: stored.Binding.ApplicationRevisionID,
			ExecutionTargetID:     stored.Binding.ExecutionTargetID,
			ExpectedContentDigest: stored.Binding.ContentDigest,
			Deadline:              deadline,
		},
		InstanceID: stored.Binding.InstanceID,
		Size:       stored.Session.Size,
		ExpiresAt:  stored.Session.ExpiresAt,
	}, nil
}

func validNorthboundTerminalUpgrade(request *http.Request) bool {
	if request == nil || request.URL.RawPath != "" || request.URL.RawQuery != "" ||
		request.URL.ForceQuery || request.ContentLength != 0 || len(request.TransferEncoding) != 0 ||
		request.Header.Get("Content-Encoding") != "" || request.Header.Get("Authorization") != "" ||
		len(request.Header.Values("Matrix-Subject-Credential")) != 0 ||
		!exactNorthboundSubprotocol(request) || !sameTerminalOrigin(request) {
		return false
	}
	return true
}

func exactNorthboundSubprotocol(request *http.Request) bool {
	protocols := make([]string, 0, 1)
	for _, value := range request.Header.Values("Sec-WebSocket-Protocol") {
		for _, protocol := range strings.Split(value, ",") {
			protocols = append(protocols, strings.TrimSpace(protocol))
		}
	}
	return len(protocols) == 1 && protocols[0] == nodev1.TerminalSubprotocol
}

func sameTerminalOrigin(request *http.Request) bool {
	values := request.Header.Values("Origin")
	if len(values) != 1 {
		return false
	}
	origin, err := url.Parse(values[0])
	if err != nil || origin.User != nil || origin.Opaque != "" || origin.Host == "" ||
		(origin.Path != "" && origin.Path != "/") || origin.RawPath != "" ||
		origin.RawQuery != "" || origin.ForceQuery || origin.Fragment != "" ||
		(origin.Scheme != "http" && origin.Scheme != "https") ||
		!strings.EqualFold(origin.Host, request.Host) {
		return false
	}
	return request.TLS == nil || origin.Scheme == "https"
}

func exactTerminalCookie(request *http.Request) (string, bool) {
	var ticket string
	count := 0
	for _, cookie := range request.Cookies() {
		if cookie.Name != terminalTicketCookie {
			continue
		}
		count++
		ticket = cookie.Value
	}
	decoded, err := base64.RawURLEncoding.DecodeString(ticket)
	return ticket, count == 1 && err == nil && len(decoded) == 32 && len(ticket) == 43
}

func terminalTicketDigest(ticket string) string {
	digest := sha256.Sum256([]byte(ticket))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func northboundTerminalOpenFailure(
	err error,
) (paasv1.TerminalSessionOutcome, nodev1.TerminalErrorCode) {
	if errors.Is(err, port.ErrTerminalUnsupported) {
		return paasv1.TerminalSessionUnsupported, nodev1.TerminalErrorUnsupported
	}
	if errors.Is(err, port.ErrTerminalUnavailable) {
		return paasv1.TerminalSessionFailed, nodev1.TerminalErrorUnavailable
	}
	return paasv1.TerminalSessionFailed, nodev1.TerminalErrorFailed
}

func writeNorthboundControl(
	ctx context.Context,
	connection *websocket.Conn,
	control nodev1.TerminalServerControl,
) bool {
	if nodev1.ValidateTerminalServerControl(control) != nil {
		return false
	}
	content, err := json.Marshal(control)
	if err != nil || len(content) > nodev1.MaximumTerminalControlBytes {
		return false
	}
	defer clear(content)
	return writeNorthboundMessage(ctx, connection, websocket.MessageText, content)
}

func writeNorthboundMessage(
	ctx context.Context,
	connection *websocket.Conn,
	kind websocket.MessageType,
	content []byte,
) bool {
	writeContext, cancel := context.WithTimeout(ctx, terminalWriteTimeout)
	defer cancel()
	return connection.Write(writeContext, kind, content) == nil
}

func resetTerminalTimer(timer *time.Timer) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(paasv1.TerminalSessionIdleTimeout)
}
