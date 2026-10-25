// Package websocketclient owns the third-party WebSocket dependency used by
// real-runtime acceptance drivers. Product and installation bounded contexts
// depend only on this narrow repository-local test capability.
package websocketclient

import (
	"context"
	"errors"
	"net/http"

	"github.com/coder/websocket"
)

type MessageType uint8

const (
	MessageText MessageType = iota + 1
	MessageBinary
)

type DialOptions struct {
	HTTPClient      *http.Client
	HTTPHeader      http.Header
	Subprotocol     string
	MaxMessageBytes int64
}

type Connection struct {
	value *websocket.Conn
}

func Dial(
	ctx context.Context,
	endpoint string,
	options DialOptions,
) (*Connection, *http.Response, error) {
	if ctx == nil || endpoint == "" || options.HTTPClient == nil || options.Subprotocol == "" ||
		options.MaxMessageBytes <= 0 || options.MaxMessageBytes > 1024*1024 {
		return nil, nil, errors.New("WebSocket acceptance input is invalid")
	}
	connection, response, err := websocket.Dial(ctx, endpoint, &websocket.DialOptions{
		HTTPClient:      options.HTTPClient,
		HTTPHeader:      options.HTTPHeader.Clone(),
		Subprotocols:    []string{options.Subprotocol},
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return nil, response, err
	}
	connection.SetReadLimit(options.MaxMessageBytes)
	return &Connection{value: connection}, response, nil
}

func (connection *Connection) Subprotocol() string {
	if connection == nil || connection.value == nil {
		return ""
	}
	return connection.value.Subprotocol()
}

func (connection *Connection) Read(ctx context.Context) (MessageType, []byte, error) {
	if connection == nil || connection.value == nil || ctx == nil {
		return 0, nil, errors.New("WebSocket acceptance connection is unavailable")
	}
	kind, content, err := connection.value.Read(ctx)
	if err != nil {
		return 0, content, err
	}
	switch kind {
	case websocket.MessageText:
		return MessageText, content, nil
	case websocket.MessageBinary:
		return MessageBinary, content, nil
	default:
		return 0, content, errors.New("WebSocket acceptance message type is invalid")
	}
}

func (connection *Connection) Write(
	ctx context.Context,
	kind MessageType,
	content []byte,
) error {
	if connection == nil || connection.value == nil || ctx == nil || len(content) == 0 {
		return errors.New("WebSocket acceptance write is invalid")
	}
	var wireKind websocket.MessageType
	switch kind {
	case MessageText:
		wireKind = websocket.MessageText
	case MessageBinary:
		wireKind = websocket.MessageBinary
	default:
		return errors.New("WebSocket acceptance message type is invalid")
	}
	return connection.value.Write(ctx, wireKind, content)
}

func (connection *Connection) CloseNow() {
	if connection != nil && connection.value != nil {
		connection.value.CloseNow()
		connection.value = nil
	}
}
