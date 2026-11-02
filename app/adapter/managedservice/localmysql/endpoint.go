package localmysql

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

// ServeEndpoint is a bounded TCP ingress to this project's MySQL service. It
// accepts no destination from a client, environment variable or tenant API.
// TLS and MySQL authentication remain end to end; no payload is parsed/logged.
func ServeEndpoint(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	listener, err := net.Listen("tcp4", ":13306")
	if err != nil {
		return errors.New("MySQL endpoint cannot listen")
	}
	defer listener.Close()
	healthListener, err := net.Listen("tcp4", "127.0.0.1:13307")
	if err != nil {
		return errors.New("MySQL endpoint health listener is unavailable")
	}
	defer healthListener.Close()
	health := &http.Server{
		ReadHeaderTimeout: 2 * time.Second, WriteTimeout: 2 * time.Second, IdleTimeout: 2 * time.Second, MaxHeaderBytes: 1024,
		Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if request.Method != http.MethodGet || request.URL.Path != "/ready" {
				writer.WriteHeader(http.StatusNotFound)
				return
			}
			writer.WriteHeader(http.StatusNoContent)
		}),
	}
	stopHealth := context.AfterFunc(ctx, func() { _ = health.Close() })
	defer stopHealth()
	healthDone := make(chan error, 1)
	go func() { healthDone <- health.Serve(healthListener); cancel() }()
	err = serveEndpoint(ctx, listener, "mysql:3306", 128, 8*time.Hour)
	_ = health.Close()
	healthErr := <-healthDone
	if err != nil || !errors.Is(healthErr, http.ErrServerClosed) {
		return errors.New("MySQL endpoint is unavailable")
	}
	return nil
}

// CheckEndpoint checks only the ingress listener process. MySQL's separate,
// authenticated health check owns database health. Unauthenticated synthetic
// database connections would accumulate MySQL host-cache handshake failures.
func CheckEndpoint(ctx context.Context) error {
	transport := &http.Transport{DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Timeout: 3 * time.Second, Transport: transport}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:13307/ready", nil)
	if err != nil {
		return errors.New("MySQL endpoint health request is unavailable")
	}
	response, err := client.Do(request)
	if err != nil {
		return errors.New("MySQL endpoint is unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		return errors.New("MySQL endpoint health is unavailable")
	}
	return nil
}

func serveEndpoint(ctx context.Context, listener net.Listener, target string, maximum int, idle time.Duration) error {
	ctx, cancel := context.WithCancel(ctx)
	defer listener.Close()
	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stop()
	capacity := make(chan struct{}, maximum)
	var connections sync.WaitGroup
	defer func() { cancel(); connections.Wait() }()
	for {
		client, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return errors.New("MySQL endpoint listener is unavailable")
		}
		select {
		case capacity <- struct{}{}:
		default:
			_ = client.Close()
			continue
		}
		connections.Add(1)
		go func() {
			defer connections.Done()
			defer func() { <-capacity }()
			defer client.Close()
			cancelClient := context.AfterFunc(ctx, func() { _ = client.Close() })
			defer cancelClient()
			dialer := net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}
			upstream, err := dialer.DialContext(ctx, "tcp4", target)
			if err != nil {
				return
			}
			defer upstream.Close()
			cancelUpstream := context.AfterFunc(ctx, func() { _ = upstream.Close() })
			defer cancelUpstream()
			// Bound idle reads and blocked writes in both directions. Wrapping
			// net.Conn prevents io.Copy's TCP fast path bypassing the deadlines.
			front := endpointConnection{Conn: client, idle: idle}
			back := endpointConnection{Conn: upstream, idle: idle}
			done := make(chan struct{})
			go func() {
				_, _ = io.Copy(back, front)
				_ = upstream.Close()
				close(done)
			}()
			_, _ = io.Copy(front, back)
			_ = client.Close()
			_ = upstream.Close()
			<-done
		}()
	}
}

type endpointConnection struct {
	net.Conn
	idle time.Duration
}

func (connection endpointConnection) Read(buffer []byte) (int, error) {
	_ = connection.SetReadDeadline(time.Now().Add(connection.idle))
	return connection.Conn.Read(buffer)
}

func (connection endpointConnection) Write(buffer []byte) (int, error) {
	_ = connection.SetWriteDeadline(time.Now().Add(connection.idle))
	return connection.Conn.Write(buffer)
}
