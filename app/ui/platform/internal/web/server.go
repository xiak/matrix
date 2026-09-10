// Package web serves the Matrix private-cloud product shell. The browser talks
// only to public APISIX routes; this process owns no authority credential and
// never proxies user requests.
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
	"strings"
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

const APIVersion = "ui.matrix.xiak.com/v1"

const maximumDigestRequestBytes = 1024 * 1024

// The explicit inventory prevents generated or machine-local directories from
// becoming release inputs through a wildcard.
//
//go:embed assets/index.html assets/app.25456f0c.css assets/app.a17d5b08.js
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
	shell := serveAsset("assets/index.html", "text/html; charset=utf-8", "no-store")
	mux.HandleFunc("GET /{$}", shell)
	mux.HandleFunc("GET /assets/app.25456f0c.css", serveAsset(
		"assets/app.25456f0c.css", "text/css; charset=utf-8", "public, max-age=31536000, immutable",
	))
	mux.HandleFunc("GET /assets/app.a17d5b08.js", serveAsset(
		"assets/app.a17d5b08.js", "text/javascript; charset=utf-8", "public, max-age=31536000, immutable",
	))
	mux.HandleFunc("GET /ready", serveReadiness)
	mux.HandleFunc("POST /ui/v1/configuration-digest", serveConfigurationDigest)
	mux.HandleFunc("GET /{route...}", func(response http.ResponseWriter, request *http.Request) {
		if strings.HasPrefix(request.URL.Path, "/assets/") ||
			strings.HasPrefix(request.URL.Path, "/api/") ||
			strings.HasPrefix(request.URL.Path, "/ui/") {
			writeProblem(response, http.StatusNotFound, "ROUTE_NOT_FOUND")
			return
		}
		shell(response, request)
	})
	return securityHeaders(mux)
}

func serveAsset(name, contentType, cacheControl string) http.HandlerFunc {
	asset, err := content.ReadFile(name)
	if err != nil {
		panic("embedded Matrix UI asset is missing")
	}
	return func(response http.ResponseWriter, request *http.Request) {
		if !validEmptyRequest(request) {
			writeProblem(response, http.StatusBadRequest, "INVALID_REQUEST")
			return
		}
		response.Header().Set("Content-Type", contentType)
		response.Header().Set("Cache-Control", cacheControl)
		response.WriteHeader(http.StatusOK)
		_, _ = response.Write(asset)
	}
}

func serveReadiness(response http.ResponseWriter, request *http.Request) {
	if !validEmptyRequest(request) {
		writeProblem(response, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	writeJSON(response, http.StatusOK, readiness{
		APIVersion: APIVersion, Kind: "MatrixUIReadiness", State: "READY",
	})
}

func serveConfigurationDigest(response http.ResponseWriter, request *http.Request) {
	if request.URL.RawQuery != "" || request.ContentLength < 0 ||
		request.ContentLength > maximumDigestRequestBytes ||
		len(request.TransferEncoding) > 0 || request.Header.Get("Content-Encoding") != "" {
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

func validEmptyRequest(request *http.Request) bool {
	return request.URL.RawQuery == "" && request.ContentLength == 0 &&
		len(request.TransferEncoding) == 0 && request.Header.Get("Content-Encoding") == ""
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Security-Policy", "default-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'; script-src 'self'; style-src 'self'")
		response.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		response.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
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
		return errors.New("Matrix UI server configuration is invalid")
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return errors.New("Matrix UI listener cannot start")
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
		return errors.New("Matrix UI server stopped unexpectedly")
	case <-ctx.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownContext); err != nil {
			return errors.New("Matrix UI server cannot stop gracefully")
		}
		return nil
	}
}
