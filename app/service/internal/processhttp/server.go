package processhttp

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"time"
)

const ReadinessAPIVersion = "process.matrix.xiak.com/v1"

type readinessDocument struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	State      string `json:"state"`
}

// NewReadinessHandler exposes the same narrow internal process contract for
// long-running workers and dispatchers. Provider errors are deliberately not
// serialized into the response.
func NewReadinessHandler(check func(context.Context) error) (http.Handler, error) {
	if check == nil {
		return nil, errors.New("process readiness check is required")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ready", func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Cache-Control", "no-store")
		response.Header().Set("Content-Type", "application/json")
		response.Header().Set("X-Content-Type-Options", "nosniff")
		state := "READY"
		status := http.StatusOK
		if request.URL.RawQuery != "" || request.ContentLength > 0 ||
			len(request.TransferEncoding) > 0 {
			state = "NOT_READY"
			status = http.StatusBadRequest
		} else if err := check(request.Context()); err != nil {
			state = "NOT_READY"
			status = http.StatusServiceUnavailable
		}
		response.WriteHeader(status)
		_ = json.NewEncoder(response).Encode(readinessDocument{
			APIVersion: ReadinessAPIVersion, Kind: "ProcessReadiness", State: state,
		})
	})
	return mux, nil
}

func Serve(ctx context.Context, address string, handler http.Handler) error {
	return serve(ctx, address, handler, nil)
}

func serve(ctx context.Context, address string, handler http.Handler, security *tls.Config) error {
	if ctx == nil || address == "" || handler == nil {
		return errors.New("service HTTP configuration is invalid")
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return errors.New("service HTTP listener cannot start")
	}
	defer listener.Close()
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       time.Minute,
		MaxHeaderBytes:    32 * 1024,
		BaseContext: func(net.Listener) context.Context {
			return ctx
		},
	}
	defer server.Close()
	if security != nil {
		server.TLSConfig = security.Clone()
		// Peer-supplied handshake diagnostics are not process support output.
		server.ErrorLog = log.New(io.Discard, "", 0)
	}
	serveError := make(chan error, 1)
	go func() {
		if security != nil {
			serveError <- server.ServeTLS(listener, "", "")
		} else {
			serveError <- server.Serve(listener)
		}
	}()
	select {
	case err := <-serveError:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return errors.New("service HTTP server stopped unexpectedly")
	case <-ctx.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownContext); err != nil {
			return errors.New("service HTTP server cannot stop gracefully")
		}
		return nil
	}
}

// ServeWithBackground couples one internal readiness server to one
// long-running worker loop. If either boundary stops, its peer is cancelled so
// the container cannot remain falsely healthy with half of its process work
// missing.
func ServeWithBackground(
	ctx context.Context,
	address string,
	handler http.Handler,
	background func(context.Context) error,
) error {
	return serveWithBackground(ctx, address, handler, nil, background)
}

// ServeTLSWithBackground uses the same supervised lifecycle for a private TLS
// listener. A missing TLS configuration is an error, never a plaintext fallback.
func ServeTLSWithBackground(
	ctx context.Context,
	address string,
	handler http.Handler,
	security *tls.Config,
	background func(context.Context) error,
) error {
	if security == nil || len(security.Certificates) == 0 || security.MinVersion < tls.VersionTLS12 {
		return errors.New("service TLS configuration is invalid")
	}
	return serveWithBackground(ctx, address, handler, security, background)
}

func serveWithBackground(
	ctx context.Context,
	address string,
	handler http.Handler,
	security *tls.Config,
	background func(context.Context) error,
) error {
	if ctx == nil || handler == nil || background == nil {
		return errors.New("service background process configuration is invalid")
	}
	processContext, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan error, 2)
	go func() { results <- serve(processContext, address, handler, security) }()
	go func() { results <- background(processContext) }()
	first := <-results
	cancel()
	second := <-results
	if ctx.Err() != nil {
		return nil
	}
	if first != nil {
		return first
	}
	if second != nil {
		return second
	}
	return errors.New("service process stopped unexpectedly")
}
