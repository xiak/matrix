package websocketclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/coder/websocket"
)

func TestClientCarriesOneSubprotocolAndBoundedBinaryMessage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		connection, err := websocket.Accept(response, request, &websocket.AcceptOptions{
			Subprotocols: []string{"matrix.test.v1"},
		})
		if err != nil {
			return
		}
		defer connection.CloseNow()
		kind, content, err := connection.Read(request.Context())
		if err != nil || kind != websocket.MessageBinary {
			return
		}
		_ = connection.Write(request.Context(), websocket.MessageBinary, content)
	}))
	defer server.Close()

	connection, response, err := Dial(context.Background(), server.URL, DialOptions{
		HTTPClient: server.Client(), HTTPHeader: http.Header{"Origin": []string{server.URL}},
		Subprotocol: "matrix.test.v1", MaxMessageBytes: 64,
	})
	if err != nil || response == nil || response.StatusCode != http.StatusSwitchingProtocols ||
		connection.Subprotocol() != "matrix.test.v1" {
		t.Fatalf("dial = %#v / %#v / %v", connection, response, err)
	}
	defer connection.CloseNow()
	if err := connection.Write(context.Background(), MessageBinary, []byte("matrix")); err != nil {
		t.Fatal(err)
	}
	kind, content, err := connection.Read(context.Background())
	if err != nil || kind != MessageBinary || string(content) != "matrix" {
		t.Fatalf("echo = %d / %q / %v", kind, content, err)
	}
}

func TestClientRejectsUnboundedOrAmbiguousInput(t *testing.T) {
	for _, options := range []DialOptions{
		{},
		{HTTPClient: http.DefaultClient, Subprotocol: "matrix.test.v1"},
		{HTTPClient: http.DefaultClient, Subprotocol: "matrix.test.v1", MaxMessageBytes: 1024*1024 + 1},
	} {
		if connection, _, err := Dial(context.Background(), "http://127.0.0.1", options); err == nil || connection != nil {
			t.Fatal("invalid WebSocket acceptance input was admitted")
		}
	}
}
