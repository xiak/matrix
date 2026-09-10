// Package web serves the Matrix private-cloud product shell. The browser talks
// only to public APISIX routes; this process owns no authority credential and
// never proxies user requests.
package web

import (
	"bytes"
	"context"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"mime"
	"net"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

const APIVersion = "ui.matrix.xiak.com/v1"

const maximumDigestRequestBytes = 1024 * 1024

// The normalized static export is the only asset inventory; its drift gate rejects extra files.
// Include underscore-prefixed router segments required by Next.
//
//go:embed all:assets
var content embed.FS

var inlineScript = regexp.MustCompile(`(?is)<script(?:\\s[^>]*)?>(.*?)</script>`)

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
	assets, err := fs.Sub(content, "assets")
	if err != nil {
		panic("embedded control-plane assets are missing")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ready", serveReadiness)
	mux.HandleFunc("POST /ui/v1/configuration-digest", serveConfigurationDigest)
	mux.HandleFunc("GET /", serveStatic(assets))
	return securityHeaders(mux, staticContentSecurityPolicy(assets))
}

func serveStatic(assets fs.FS) http.HandlerFunc {
	return func(response http.ResponseWriter, request *http.Request) {
		if request.ContentLength != 0 || request.Header.Get("Content-Encoding") != "" || len(request.TransferEncoding) > 0 ||
			strings.Contains(request.URL.Path, `\`) {
			writeProblem(response, http.StatusBadRequest, "INVALID_REQUEST")
			return
		}
		if strings.HasPrefix(request.URL.Path, "/api/") || strings.HasPrefix(request.URL.Path, "/ui/") || strings.HasPrefix(request.URL.Path, "/assets/") {
			writeProblem(response, http.StatusNotFound, "ROUTE_NOT_FOUND")
			return
		}
		assetName, pageRequest := staticAssetName(request.URL.Path)
		if assetName == "" || !validStaticQuery(request, assetName) {
			writeProblem(response, http.StatusBadRequest, "INVALID_REQUEST")
			return
		}
		asset, err := fs.ReadFile(assets, assetName)
		if err != nil {
			if !pageRequest || !errors.Is(err, fs.ErrNotExist) {
				http.NotFound(response, request)
				return
			}
			asset, err = fs.ReadFile(assets, "404.html")
			if err != nil {
				panic("embedded control-plane 404 page is missing")
			}
			writeStatic(response, http.StatusNotFound, "404.html", asset)
			return
		}
		writeStatic(response, http.StatusOK, assetName, asset)
	}
}

func staticAssetName(requestPath string) (string, bool) {
	if requestPath == "" || !strings.HasPrefix(requestPath, "/") {
		return "", false
	}
	cleaned := path.Clean(requestPath)
	relative := strings.TrimPrefix(cleaned, "/")
	if relative == "." || relative == "" {
		return "index.html", true
	}
	if relative == ".." || strings.HasPrefix(relative, "../") {
		return "", false
	}
	if path.Ext(relative) == "" {
		return path.Join(relative, "index.html"), true
	}
	return relative, false
}

func validStaticQuery(request *http.Request, assetName string) bool {
	if request.URL.RawQuery == "" {
		return true
	}
	values, err := url.ParseQuery(request.URL.RawQuery)
	if err != nil || len(request.URL.RawQuery) > 256 {
		return false
	}
	if path.Ext(assetName) != ".txt" || len(values) != 1 {
		return false
	}
	requestState, found := values["_rsc"]
	return found && len(requestState) == 1 && requestState[0] != ""
}

func writeStatic(response http.ResponseWriter, status int, assetName string, asset []byte) {
	contentType := mime.TypeByExtension(path.Ext(assetName))
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	response.Header().Set("Content-Type", contentType)
	if strings.HasPrefix(assetName, "_next/static/") {
		response.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		response.Header().Set("Cache-Control", "no-store")
	}
	response.WriteHeader(status)
	_, _ = response.Write(asset)
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

func staticContentSecurityPolicy(assets fs.FS) string {
	hashes := map[string]struct{}{}
	err := fs.WalkDir(assets, ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || path.Ext(name) != ".html" {
			return nil
		}
		page, err := fs.ReadFile(assets, name)
		if err != nil {
			return err
		}
		for _, match := range inlineScript.FindAllSubmatch(page, -1) {
			if len(match) != 2 || len(match[1]) == 0 {
				continue
			}
			digest := sha256.Sum256(match[1])
			hashes["'sha256-"+base64.StdEncoding.EncodeToString(digest[:])+"'"] = struct{}{}
		}
		return nil
	})
	if err != nil {
		panic("embedded control-plane CSP cannot be built")
	}
	allowedScripts := make([]string, 0, len(hashes)+1)
	allowedScripts = append(allowedScripts, "'self'")
	for hash := range hashes {
		allowedScripts = append(allowedScripts, hash)
	}
	sort.Strings(allowedScripts[1:])
	return "default-src 'none'; script-src " + strings.Join(allowedScripts, " ") +
		"; style-src 'self'; connect-src 'self'; img-src 'self' data:; font-src 'self';" +
		" form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'; worker-src 'none'"
}

func securityHeaders(next http.Handler, policy string) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Security-Policy", policy)
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
