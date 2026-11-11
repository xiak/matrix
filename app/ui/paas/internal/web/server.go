// Package web serves the independent Matrix PaaS control-plane application.
// The browser talks only to public APIs exposed by APISIX; this process owns no
// authority credential and never proxies user requests.
package web

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
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
	"unicode"
	"unicode/utf8"
)

const APIVersion = "ui.matrix.xiak.com/v1"

// Next's router fetches nested __next segment files. Directory embedding must
// include underscore-prefixed generated assets, not only HTML and JS/CSS.
//
//go:embed all:assets
var content embed.FS

// These documents belong to the static transport boundary. They remain
// available even when the application route itself cannot be admitted.
//
//go:embed bad-request.html bad-request.css
var transportProblemContent embed.FS

var inlineScript = regexp.MustCompile(`(?is)<script(?:\s[^>]*)?>(.*?)</script>`)

var clientViewQueryKeys = map[string]struct{}{
	"association": {}, "category": {}, "check": {}, "environment": {},
	"id": {}, "kind": {}, "method": {}, "q": {}, "read": {}, "region": {},
	"resource": {}, "retention": {}, "scope": {}, "state": {}, "tab": {}, "topic": {},
}

type readiness struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	State      string `json:"state"`
}

func NewHandler() http.Handler {
	assets, err := fs.Sub(content, "assets")
	if err != nil {
		panic("embedded control-plane assets are missing")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ready", serveReadiness)
	mux.HandleFunc("GET /_matrix/bad-request.css", serveBadRequestStyle)
	mux.HandleFunc("GET /", serveStatic(assets))
	return securityHeaders(mux)
}

func serveStatic(assets fs.FS) http.HandlerFunc {
	return func(response http.ResponseWriter, request *http.Request) {
		if request.ContentLength > 0 || len(request.TransferEncoding) > 0 ||
			strings.Contains(request.URL.Path, `\`) {
			writeProblem(response, http.StatusBadRequest, "INVALID_REQUEST")
			return
		}
		assetName, pageRequest := staticAssetName(request.URL.Path)
		if assetName == "" {
			writeProblem(response, http.StatusBadRequest, "INVALID_REQUEST")
			return
		}
		if !validStaticQuery(request, assetName) {
			if path.Ext(assetName) == ".html" {
				serveBadRequestDocument(response)
			} else {
				writeProblem(response, http.StatusBadRequest, "INVALID_REQUEST")
			}
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
	if len(request.URL.RawQuery) > 2048 {
		return false
	}
	values, err := url.ParseQuery(request.URL.RawQuery)
	if err != nil || len(values) == 0 {
		return false
	}
	extension, route := path.Ext(assetName), path.Dir(assetName)
	if extension != ".txt" && extension != ".html" {
		return false
	}
	consoleRoute := route == "console" || strings.HasPrefix(route, "console/")
	for key, entries := range values {
		if len(entries) != 1 || !validStaticQueryValue(key, entries[0]) {
			return false
		}
		if key == "_rsc" {
			if extension != ".txt" {
				return false
			}
			continue
		}
		if !consoleRoute {
			return false
		}
		if _, accepted := clientViewQueryKeys[key]; !accepted {
			return false
		}
	}
	return true
}

func validStaticQueryValue(key, value string) bool {
	if value == "" || len(value) > 256 || !utf8.ValidString(value) {
		return false
	}
	text := key == "q" || key == "environment"
	return strings.IndexFunc(value, func(character rune) bool {
		return unicode.IsControl(character) || (!text && unicode.IsSpace(character))
	}) < 0
}

func serveBadRequestDocument(response http.ResponseWriter) {
	document, err := transportProblemContent.ReadFile("bad-request.html")
	if err != nil {
		panic("embedded bad-request document is missing")
	}
	writeStatic(response, http.StatusBadRequest, "bad-request.html", document)
}

func serveBadRequestStyle(response http.ResponseWriter, request *http.Request) {
	if request.URL.RawQuery != "" || request.ContentLength > 0 || len(request.TransferEncoding) > 0 {
		writeProblem(response, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	stylesheet, err := transportProblemContent.ReadFile("bad-request.css")
	if err != nil {
		panic("embedded bad-request stylesheet is missing")
	}
	writeStatic(response, http.StatusOK, "bad-request.css", stylesheet)
}

func writeStatic(response http.ResponseWriter, status int, assetName string, asset []byte) {
	extension := path.Ext(assetName)
	contentType := mime.TypeByExtension(extension)
	// The offline font and favicon also run on hosts with no MIME registry.
	switch extension {
	case ".woff2":
		contentType = "font/woff2"
	case ".ico":
		contentType = "image/x-icon"
	}
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	response.Header().Set("Content-Type", contentType)
	if extension == ".html" {
		response.Header().Set("Content-Security-Policy", staticContentSecurityPolicy(asset))
	}
	if strings.HasPrefix(assetName, "_next/static/") {
		response.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		response.Header().Set("Cache-Control", "no-store")
	}
	response.WriteHeader(status)
	_, _ = response.Write(asset)
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

// Authorize only scripts in the document being served. A site-wide union grows
// with every route and can overflow the release gateway response-header buffer.
func staticContentSecurityPolicy(page []byte) string {
	hashes := map[string]struct{}{}
	for _, match := range inlineScript.FindAllSubmatch(page, -1) {
		if len(match) != 2 || len(match[1]) == 0 {
			continue
		}
		digest := sha256.Sum256(match[1])
		hashes["'sha256-"+base64.StdEncoding.EncodeToString(digest[:])+"'"] = struct{}{}
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

func securityHeaders(next http.Handler) http.Handler {
	contentSecurityPolicy := staticContentSecurityPolicy(nil)
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Security-Policy", contentSecurityPolicy)
		response.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		response.Header().Set("Referrer-Policy", "no-referrer")
		response.Header().Set("X-Content-Type-Options", "nosniff")
		response.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(response, request)
	})
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
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
