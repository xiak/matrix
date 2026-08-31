package nethttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/coder/websocket"
	nodev1 "github.com/xiak/matrix/api/adapter/node/v1"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

const terminalWriteTimeout = 5 * time.Second

type terminalClientEvent struct {
	typeValue websocket.MessageType
	content   []byte
	err       error
}

type terminalProviderEvent struct {
	content []byte
	err     error
}

func (handler *Handler) terminalSession(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet || request.URL.RawPath != "" || request.URL.RawQuery != "" ||
		request.URL.ForceQuery || request.ContentLength != 0 || len(request.TransferEncoding) != 0 ||
		request.Header.Get("Content-Encoding") != "" || request.Header.Get("Origin") != "" ||
		!exactTerminalSubprotocol(request) {
		reject(response, http.StatusBadRequest)
		return
	}
	if !handler.acquire(response) {
		return
	}
	defer handler.release()
	connection, err := websocket.Accept(response, request, &websocket.AcceptOptions{
		Subprotocols:    []string{nodev1.TerminalSubprotocol},
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return
	}
	defer connection.CloseNow()
	if connection.Subprotocol() != nodev1.TerminalSubprotocol {
		_ = connection.Close(websocket.StatusPolicyViolation, "terminal protocol rejected")
		return
	}
	connection.SetReadLimit(paasv1.MaximumTerminalFrameBytes)
	openContext, cancelOpen := context.WithTimeout(request.Context(), 5*time.Second)
	typeValue, content, err := connection.Read(openContext)
	cancelOpen()
	if err != nil || typeValue != websocket.MessageText || len(content) > nodev1.MaximumTerminalOpenBytes {
		writeTerminalControl(request.Context(), connection, nodev1.TerminalServerControl{
			Type: nodev1.TerminalServerError, Error: nodev1.TerminalErrorFailed,
		})
		return
	}
	value, err := nodev1.DecodeTerminalOpenRequest(bytes.NewReader(content))
	clear(content)
	now := time.Now()
	if err != nil || value.Identity != handler.identity || value.BindingRef != handler.bindingRef ||
		!now.Before(value.Request.Deadline) || !now.Before(value.ExpiresAt) ||
		value.Request.Deadline.Sub(now) > nodev1.MaximumDeploymentDuration ||
		value.ExpiresAt.Sub(now) > paasv1.MaximumTerminalSessionDuration {
		writeTerminalControl(request.Context(), connection, nodev1.TerminalServerControl{
			Type: nodev1.TerminalServerError, Error: nodev1.TerminalErrorFailed,
		})
		return
	}
	openContext, cancelOpen = context.WithDeadline(request.Context(), value.Request.Deadline)
	terminal, err := handler.terminals.OpenTerminal(openContext, value)
	cancelOpen()
	if err != nil {
		writeTerminalControl(request.Context(), connection, nodev1.TerminalServerControl{
			Type: nodev1.TerminalServerError, Error: terminalErrorCode(err),
		})
		return
	}
	defer terminal.Close()
	if !writeTerminalControl(request.Context(), connection, nodev1.TerminalServerControl{Type: nodev1.TerminalServerReady}) {
		return
	}
	handler.bridgeTerminal(request.Context(), connection, terminal, value.ExpiresAt)
}

func (handler *Handler) bridgeTerminal(
	requestContext context.Context,
	connection *websocket.Conn,
	terminal TerminalSession,
	expiresAt time.Time,
) {
	ctx, cancel := context.WithCancel(requestContext)
	defer cancel()
	clientEvents := make(chan terminalClientEvent, 1)
	providerEvents := make(chan terminalProviderEvent, 8)
	go readTerminalClient(ctx, connection, clientEvents)
	go readTerminalProvider(ctx, terminal, providerEvents)
	idle := time.NewTimer(paasv1.TerminalSessionIdleTimeout)
	defer idle.Stop()
	absolute := time.NewTimer(time.Until(expiresAt))
	defer absolute.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-absolute.C:
			_ = connection.Close(websocket.StatusPolicyViolation, "terminal expired")
			return
		case <-idle.C:
			_ = connection.Close(websocket.StatusPolicyViolation, "terminal idle timeout")
			return
		case event := <-providerEvents:
			if event.err != nil {
				if errors.Is(event.err, io.EOF) {
					exitContext, cancelExit := context.WithTimeout(ctx, terminalWriteTimeout)
					exitCode, exitErr := terminal.ExitCode(exitContext)
					cancelExit()
					if exitErr == nil {
						writeTerminalControl(ctx, connection, nodev1.TerminalServerControl{
							Type: nodev1.TerminalServerExit, ExitCode: &exitCode,
						})
					} else {
						writeTerminalControl(ctx, connection, nodev1.TerminalServerControl{
							Type: nodev1.TerminalServerError, Error: terminalErrorCode(exitErr),
						})
					}
				} else {
					writeTerminalControl(ctx, connection, nodev1.TerminalServerControl{
						Type: nodev1.TerminalServerError, Error: terminalErrorCode(event.err),
					})
				}
				return
			}
			valid := len(event.content) > 0 && len(event.content) <= paasv1.MaximumTerminalFrameBytes
			written := valid && writeTerminalMessage(ctx, connection, websocket.MessageBinary, event.content)
			clear(event.content)
			if !written {
				return
			}
			resetTerminalIdle(idle)
		case event := <-clientEvents:
			if event.err != nil {
				return
			}
			resetTerminalIdle(idle)
			switch event.typeValue {
			case websocket.MessageBinary:
				if len(event.content) == 0 || len(event.content) > paasv1.MaximumTerminalFrameBytes ||
					writeAllTerminal(terminal, event.content) != nil {
					clear(event.content)
					writeTerminalControl(ctx, connection, nodev1.TerminalServerControl{
						Type: nodev1.TerminalServerError, Error: nodev1.TerminalErrorUnavailable,
					})
					return
				}
				clear(event.content)
			case websocket.MessageText:
				control, err := nodev1.DecodeTerminalClientControl(bytes.NewReader(event.content))
				clear(event.content)
				if err != nil {
					writeTerminalControl(ctx, connection, nodev1.TerminalServerControl{
						Type: nodev1.TerminalServerError, Error: nodev1.TerminalErrorFailed,
					})
					return
				}
				if control.Type == nodev1.TerminalClientClose {
					return
				}
				resizeContext, cancelResize := context.WithTimeout(ctx, terminalWriteTimeout)
				err = terminal.Resize(resizeContext, *control.Size)
				cancelResize()
				if err != nil {
					writeTerminalControl(ctx, connection, nodev1.TerminalServerControl{
						Type: nodev1.TerminalServerError, Error: terminalErrorCode(err),
					})
					return
				}
			default:
				return
			}
		}
	}
}

func readTerminalClient(ctx context.Context, connection *websocket.Conn, events chan<- terminalClientEvent) {
	for {
		typeValue, content, err := connection.Read(ctx)
		event := terminalClientEvent{typeValue: typeValue, content: content, err: err}
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

func readTerminalProvider(ctx context.Context, terminal TerminalSession, events chan<- terminalProviderEvent) {
	for {
		content := make([]byte, paasv1.MaximumTerminalFrameBytes)
		count, err := terminal.Read(content)
		if count > 0 {
			content = content[:count]
			select {
			case events <- terminalProviderEvent{content: content}:
			case <-ctx.Done():
				clear(content)
				return
			}
		} else {
			clear(content)
		}
		if err != nil {
			select {
			case events <- terminalProviderEvent{err: err}:
			case <-ctx.Done():
			}
			return
		}
	}
}

func writeAllTerminal(terminal TerminalSession, content []byte) error {
	for len(content) > 0 {
		count, err := terminal.Write(content)
		if count > 0 {
			content = content[count:]
		}
		if err != nil {
			return err
		}
		if count == 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}

func writeTerminalControl(ctx context.Context, connection *websocket.Conn, control nodev1.TerminalServerControl) bool {
	if nodev1.ValidateTerminalServerControl(control) != nil {
		return false
	}
	content, err := json.Marshal(control)
	if err != nil || len(content) > nodev1.MaximumTerminalControlBytes {
		return false
	}
	return writeTerminalMessage(ctx, connection, websocket.MessageText, content)
}

func writeTerminalMessage(ctx context.Context, connection *websocket.Conn, kind websocket.MessageType, content []byte) bool {
	writeContext, cancel := context.WithTimeout(ctx, terminalWriteTimeout)
	defer cancel()
	return connection.Write(writeContext, kind, content) == nil
}

func terminalErrorCode(err error) nodev1.TerminalErrorCode {
	if errors.Is(err, ErrTerminalUnsupported) {
		return nodev1.TerminalErrorUnsupported
	}
	var fault paasv1.AdapterFault
	if errors.Is(err, ErrTerminalUnavailable) ||
		(errors.As(err, &fault) && (fault.Normalized.Class == paasv1.AdapterErrorUnavailable ||
			fault.Normalized.Class == paasv1.AdapterErrorTimeout || fault.Normalized.Class == paasv1.AdapterErrorRateLimited)) {
		return nodev1.TerminalErrorUnavailable
	}
	return nodev1.TerminalErrorFailed
}

func exactTerminalSubprotocol(request *http.Request) bool {
	protocols := make([]string, 0, 1)
	for _, value := range request.Header.Values("Sec-WebSocket-Protocol") {
		for _, protocol := range bytes.Split([]byte(value), []byte(",")) {
			protocols = append(protocols, string(bytes.TrimSpace(protocol)))
		}
	}
	return len(protocols) == 1 && protocols[0] == nodev1.TerminalSubprotocol
}

func resetTerminalIdle(timer *time.Timer) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(paasv1.TerminalSessionIdleTimeout)
}
