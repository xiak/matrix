//go:build linux

package runnersandboxdocker

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLinuxEngineTransportUsesOnlyProtectedUnixSocket(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	socketPath := filepath.Join(root, "engine.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := os.Chmod(socketPath, 0o660); err != nil {
		t.Fatal(err)
	}
	server := &http.Server{
		ReadHeaderTimeout: time.Second,
		Handler: http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			if request.URL.Path != versionPath() || request.Host != "matrix-docker-engine" {
				t.Errorf("request = %s %s host=%s", request.Method, request.URL.String(), request.Host)
				response.WriteHeader(http.StatusNotFound)
				return
			}
			response.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(response).Encode(daemonVersion{
				Version: "29.6.2", APIVersion: "1.55", MinAPIVersion: "1.40",
				OS: "linux", Arch: "amd64",
			})
		}),
	}
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Serve(listener) }()
	defer func() {
		_ = server.Close()
		if err := <-serverDone; err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("serve: %v", err)
		}
	}()

	client, err := New(socketPath, root)
	if err != nil {
		t.Fatal(err)
	}
	var version daemonVersion
	if err := client.getJSON(context.Background(), versionPath(), maximumVersionBytes, &version); err != nil {
		t.Fatal(err)
	}
	if version.Version != "29.6.2" {
		t.Fatalf("version = %#v", version)
	}
}

func TestLinuxEngineTransportRejectsUnprotectedSocket(t *testing.T) {
	root := t.TempDir()
	socketPath := filepath.Join(root, "engine.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := os.Chmod(socketPath, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := New(socketPath, root); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("error = %v", err)
	}
}

func TestLinuxStorageEvidenceRequiresPrivateOwnedDirectory(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if free, err := freeStorageBytes(root); err != nil || free == 0 {
		t.Fatalf("free = %d, error = %v", free, err)
	}
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := freeStorageBytes(root); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("public root error = %v", err)
	}
}
