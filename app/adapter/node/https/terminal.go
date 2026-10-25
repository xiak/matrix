package nodehttps

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"
	nodev1 "github.com/xiak/matrix/api/adapter/node/v1"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

var (
	ErrTerminalUnsupported = errors.New("node terminal is unsupported")
	ErrTerminalUnavailable = errors.New("node terminal is unavailable")
	ErrTerminalRejected    = errors.New("node terminal was rejected")
)

type TerminalConnection struct {
	connection *websocket.Conn
	writeMu    sync.Mutex
	closeOnce  sync.Once
}

func (client *Client) OpenTerminal(
	ctx context.Context,
	value nodev1.TerminalOpenRequest,
) (*TerminalConnection, error) {
	if client == nil || client.terminalHTTP == nil || ctx == nil ||
		nodev1.ValidateTerminalOpenRequest(value) != nil ||
		value.Identity != client.identity || value.BindingRef != client.bindingRef ||
		!time.Now().Before(value.Request.Deadline) ||
		value.Request.Deadline.Sub(time.Now()) > nodev1.MaximumDeploymentDuration {
		return nil, ErrTerminalRejected
	}
	operationContext, cancel := context.WithDeadline(ctx, value.Request.Deadline)
	defer cancel()
	connection, response, err := websocket.Dial(operationContext, client.terminalEndpoint, &websocket.DialOptions{
		HTTPClient:   client.terminalHTTP,
		Subprotocols: []string{nodev1.TerminalSubprotocol},
	})
	if err != nil {
		if response != nil {
			defer response.Body.Close()
			return nil, terminalHTTPFault(response.StatusCode)
		}
		return nil, ErrTerminalUnavailable
	}
	failed := true
	defer func() {
		if failed {
			connection.CloseNow()
		}
	}()
	if connection.Subprotocol() != nodev1.TerminalSubprotocol {
		return nil, ErrTerminalRejected
	}
	connection.SetReadLimit(paasv1.MaximumTerminalFrameBytes)
	document, err := json.Marshal(value)
	if err != nil || len(document) > nodev1.MaximumTerminalOpenBytes ||
		connection.Write(operationContext, websocket.MessageText, document) != nil {
		clear(document)
		return nil, ErrTerminalUnavailable
	}
	clear(document)
	typeValue, content, err := connection.Read(operationContext)
	if err != nil || typeValue != websocket.MessageText || len(content) > nodev1.MaximumTerminalControlBytes {
		clear(content)
		return nil, ErrTerminalUnavailable
	}
	control, err := nodev1.DecodeTerminalServerControl(bytes.NewReader(content))
	clear(content)
	if err != nil {
		return nil, ErrTerminalRejected
	}
	if control.Type == nodev1.TerminalServerError {
		return nil, terminalControlFault(control.Error)
	}
	if control.Type != nodev1.TerminalServerReady {
		return nil, ErrTerminalRejected
	}
	failed = false
	return &TerminalConnection{connection: connection}, nil
}

func (connection *TerminalConnection) Receive(
	ctx context.Context,
) ([]byte, *nodev1.TerminalServerControl, error) {
	if connection == nil || connection.connection == nil || ctx == nil {
		return nil, nil, ErrTerminalUnavailable
	}
	typeValue, content, err := connection.connection.Read(ctx)
	if err != nil {
		return nil, nil, err
	}
	switch typeValue {
	case websocket.MessageBinary:
		if len(content) == 0 || len(content) > paasv1.MaximumTerminalFrameBytes {
			clear(content)
			return nil, nil, ErrTerminalRejected
		}
		return content, nil, nil
	case websocket.MessageText:
		if len(content) > nodev1.MaximumTerminalControlBytes {
			clear(content)
			return nil, nil, ErrTerminalRejected
		}
		control, err := nodev1.DecodeTerminalServerControl(bytes.NewReader(content))
		clear(content)
		if err != nil || control.Type == nodev1.TerminalServerReady {
			return nil, nil, ErrTerminalRejected
		}
		return nil, &control, nil
	default:
		clear(content)
		return nil, nil, ErrTerminalRejected
	}
}

func (connection *TerminalConnection) SendInput(ctx context.Context, content []byte) error {
	if connection == nil || connection.connection == nil || ctx == nil ||
		len(content) == 0 || len(content) > paasv1.MaximumTerminalFrameBytes {
		return ErrTerminalRejected
	}
	return connection.write(ctx, websocket.MessageBinary, content)
}

func (connection *TerminalConnection) Resize(ctx context.Context, size paasv1.TerminalSize) error {
	if paasv1.ValidateTerminalSize(size) != nil {
		return ErrTerminalRejected
	}
	return connection.sendControl(ctx, nodev1.TerminalClientControl{
		Type: nodev1.TerminalClientResize, Size: &size,
	})
}

func (connection *TerminalConnection) CloseInput(ctx context.Context) error {
	return connection.sendControl(ctx, nodev1.TerminalClientControl{Type: nodev1.TerminalClientClose})
}

func (connection *TerminalConnection) Close() {
	if connection == nil {
		return
	}
	connection.closeOnce.Do(func() {
		if connection.connection != nil {
			connection.connection.CloseNow()
		}
	})
}

func (connection *TerminalConnection) sendControl(ctx context.Context, control nodev1.TerminalClientControl) error {
	if connection == nil || connection.connection == nil || ctx == nil ||
		nodev1.ValidateTerminalClientControl(control) != nil {
		return ErrTerminalRejected
	}
	content, err := json.Marshal(control)
	if err != nil || len(content) > nodev1.MaximumTerminalControlBytes {
		return ErrTerminalRejected
	}
	defer clear(content)
	return connection.write(ctx, websocket.MessageText, content)
}

func (connection *TerminalConnection) write(ctx context.Context, kind websocket.MessageType, content []byte) error {
	connection.writeMu.Lock()
	defer connection.writeMu.Unlock()
	if err := connection.connection.Write(ctx, kind, content); err != nil {
		return ErrTerminalUnavailable
	}
	return nil
}

func terminalHTTPFault(status int) error {
	switch status {
	case http.StatusTooManyRequests, http.StatusRequestTimeout, http.StatusGatewayTimeout, http.StatusServiceUnavailable:
		return ErrTerminalUnavailable
	default:
		return ErrTerminalRejected
	}
}

func terminalControlFault(code nodev1.TerminalErrorCode) error {
	switch code {
	case nodev1.TerminalErrorUnsupported:
		return ErrTerminalUnsupported
	case nodev1.TerminalErrorUnavailable:
		return ErrTerminalUnavailable
	default:
		return ErrTerminalRejected
	}
}
