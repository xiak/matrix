// Package web serves the independent Phase 1 PaaS browser application. The
// browser talks only to the public IAM and PaaS routes exposed by APISIX; this
// process owns no authority credential and never proxies user requests.
package web

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

const APIVersion = "ui.matrix.xiak.com/v1"

const maximumDigestRequestBytes = 1024 * 1024

//go:embed assets/*
var content embed.FS

type readiness struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	State      string `json:"state"`
}

type digestRequest struct {
	Values *map[string]string `json:"values"`
}

type digestResponse struct {
	APIVersion    string `json:"apiVersion"`
	Kind          string `json:"kind"`
	ContentDigest string `json:"contentDigest"`
}

func NewHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", serveAsset("assets/index.html", "text/html; charset=utf-8"))
	mux.HandleFunc("GET /assets/app.css", serveAsset("assets/app.css", "text/css; charset=utf-8"))
	mux.HandleFunc("GET /assets/app.js", serveAsset("assets/app.js", "text/javascript; charset=utf-8"))
	mux.HandleFunc("GET /ready", serveReadiness)
	mux.HandleFunc("POST /ui/v1/configuration-digest", serveConfigurationDigest)
	return securityHeaders(mux)
}

func serveAsset(name, contentType string) http.HandlerFunc {
	asset, err := content.ReadFile(name)
	if err != nil {
		panic("embedded PaaS UI asset is missing")
	}
	return func(response http.ResponseWriter, request *http.Request) {
		if request.URL.RawQuery != "" || request.ContentLength > 0 || len(request.TransferEncoding) > 0 {
			writeProblem(response, http.StatusBadRequest, "INVALID_REQUEST")
			return
		}
		response.Header().Set("Content-Type", contentType)
		response.Header().Set("Cache-Control", "no-store")
		response.WriteHeader(http.StatusOK)
		_, _ = response.Write(asset)
	}
}

func serveReadiness(response http.ResponseWriter, request *http.Request) {
	if request.URL.RawQuery != "" || request.ContentLength > 0 || len(request.TransferEncoding) > 0 {
		writeProblem(response, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	writeJSON(response, http.StatusOK, readiness{
		APIVersion: APIVersion, Kind: "PaaSUIReadiness", State: "READY",
	})
}

func serveConfigurationDigest(response http.ResponseWriter, request *http.Request) {
	if request.URL.RawQuery != "" || request.ContentLength > maximumDigestRequestBytes {
		writeProblem(response, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeProblem(response, http.StatusUnsupportedMediaType, "UNSUPPORTED_MEDIA_TYPE")
		return
	}
	decoder := json.NewDecoder(io.LimitReader(request.Body, maximumDigestRequestBytes+1))
	decoder.DisallowUnknownFields()
	var input digestRequest
	if err := decoder.Decode(&input); err != nil || input.Values == nil ||
		decoder.Decode(&struct{}{}) != io.EOF ||
		paasv1.ValidateConfigurationValues(*input.Values) != nil {
		writeProblem(response, http.StatusBadRequest, "INVALID_CONFIGURATION")
		return
	}
	writeJSON(response, http.StatusOK, digestResponse{
		APIVersion: APIVersion, Kind: "ConfigurationDigest",
		ContentDigest: paasv1.ConfigurationValuesDigest(*input.Values),
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Security-Policy", "default-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'")
		response.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		response.Header().Set("Referrer-Policy", "no-referrer")
		response.Header().Set("X-Content-Type-Options", "nosniff")
		response.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(response, request)
	})
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	encoded, err := json.Marshal(value)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "INTERNAL")
		return
	}
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(status)
	_, _ = io.Copy(response, bytes.NewReader(encoded))
}

func writeProblem(response http.ResponseWriter, status int, code string) {
	response.Header().Set("Content-Type", "application/problem+json")
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Code       string `json:"code"`
	}{APIVersion: APIVersion, Kind: "Problem", Code: code})
}

func Serve(ctx context.Context, address string, handler http.Handler) error {
	if ctx == nil || address == "" || handler == nil {
		return errors.New("PaaS UI server configuration is invalid")
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return errors.New("PaaS UI listener cannot start")
	}
	defer listener.Close()
	server := &http.Server{
		Handler: handler, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second,
		IdleTimeout: time.Minute, MaxHeaderBytes: 32 * 1024,
		BaseContext: func(net.Listener) context.Context { return ctx },
	}
	result := make(chan error, 1)
	go func() { result <- server.Serve(listener) }()
	select {
	case err := <-result:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return errors.New("PaaS UI server stopped unexpectedly")
	case <-ctx.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownContext); err != nil {
			return errors.New("PaaS UI server cannot stop gracefully")
		}
		return nil
	}
}
