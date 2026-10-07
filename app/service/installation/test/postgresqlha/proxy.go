package postgresqlha

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// stableEndpoint is an acceptance-only TCP endpoint. A route change owns the
// same lock used to establish and register connections, so no connection to a
// fenced backend can escape a completed switch.
type stableEndpoint struct {
	listener net.Listener

	mu          sync.Mutex
	backend     string
	connections map[*proxiedConnection]struct{}
	closed      bool

	wait sync.WaitGroup
}

type proxiedConnection struct {
	client  net.Conn
	backend net.Conn
	once    sync.Once
}

func newStableEndpoint(backend string) (*stableEndpoint, error) {
	if _, _, err := net.SplitHostPort(backend); err != nil {
		return nil, errors.New("stable endpoint backend is invalid")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, errors.New("stable endpoint cannot listen")
	}
	endpoint := &stableEndpoint{
		listener: listener, backend: backend,
		connections: make(map[*proxiedConnection]struct{}),
	}
	endpoint.wait.Add(1)
	go endpoint.accept()
	return endpoint, nil
}

func (endpoint *stableEndpoint) address() string {
	if endpoint == nil || endpoint.listener == nil {
		return ""
	}
	return endpoint.listener.Addr().String()
}

func (endpoint *stableEndpoint) disable() {
	endpoint.route("")
}

func (endpoint *stableEndpoint) switchTo(backend string) error {
	if _, _, err := net.SplitHostPort(backend); err != nil {
		return errors.New("stable endpoint backend is invalid")
	}
	endpoint.route(backend)
	return nil
}

func (endpoint *stableEndpoint) route(backend string) {
	if endpoint == nil {
		return
	}
	endpoint.mu.Lock()
	defer endpoint.mu.Unlock()
	endpoint.backend = backend
	for connection := range endpoint.connections {
		connection.close()
		delete(endpoint.connections, connection)
	}
}

func (endpoint *stableEndpoint) close() error {
	if endpoint == nil {
		return nil
	}
	endpoint.mu.Lock()
	if endpoint.closed {
		endpoint.mu.Unlock()
		return nil
	}
	endpoint.closed = true
	endpoint.backend = ""
	for connection := range endpoint.connections {
		connection.close()
		delete(endpoint.connections, connection)
	}
	endpoint.mu.Unlock()
	listenerErr := endpoint.listener.Close()
	endpoint.wait.Wait()
	if listenerErr != nil && !errors.Is(listenerErr, net.ErrClosed) {
		return errors.New("stable endpoint close failed")
	}
	return nil
}

func (endpoint *stableEndpoint) accept() {
	defer endpoint.wait.Done()
	for {
		client, err := endpoint.listener.Accept()
		if err != nil {
			return
		}
		endpoint.wait.Add(1)
		go endpoint.forward(client)
	}
}

func (endpoint *stableEndpoint) forward(client net.Conn) {
	defer endpoint.wait.Done()
	endpoint.mu.Lock()
	if endpoint.closed || endpoint.backend == "" {
		endpoint.mu.Unlock()
		_ = client.Close()
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	backend, err := (&net.Dialer{}).DialContext(ctx, "tcp", endpoint.backend)
	cancel()
	if err != nil {
		endpoint.mu.Unlock()
		_ = client.Close()
		return
	}
	connection := &proxiedConnection{client: client, backend: backend}
	endpoint.connections[connection] = struct{}{}
	endpoint.mu.Unlock()

	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(connection.backend, connection.client)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(connection.client, connection.backend)
		done <- struct{}{}
	}()
	<-done
	connection.close()
	<-done

	endpoint.mu.Lock()
	delete(endpoint.connections, connection)
	endpoint.mu.Unlock()
}

func (connection *proxiedConnection) close() {
	if connection == nil {
		return
	}
	connection.once.Do(func() {
		_ = connection.client.Close()
		_ = connection.backend.Close()
	})
}
