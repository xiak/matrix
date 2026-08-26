// matrix-verification is the real no-secret workload shipped in every
// authenticated release. It exits before listening unless the PaaS-provided
// immutable installation and release bindings are valid.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/internal/processhttp"
)

const (
	installationIDEnvironment = "MATRIX_INSTALLATION_ID"
	releaseIDEnvironment      = "MATRIX_RELEASE_ID"
	listenAddress             = "0.0.0.0:8080"
	probeAPIVersion           = "verification.matrix.xiak.com/v1"
)

type configuration struct {
	installationID string
	releaseID      string
}

type probe struct {
	APIVersion     string `json:"apiVersion"`
	Kind           string `json:"kind"`
	InstallationID string `json:"installationId"`
	ReleaseID      string `json:"releaseId"`
	State          string `json:"state"`
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Getenv); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "matrix verification workload failed")
		os.Exit(1)
	}
}

func run(ctx context.Context, lookup func(string) string) error {
	config, err := loadConfiguration(lookup)
	if err != nil {
		return err
	}
	return processhttp.Serve(ctx, listenAddress, newHandler(config))
}

func loadConfiguration(lookup func(string) string) (configuration, error) {
	if lookup == nil {
		return configuration{}, errors.New("verification configuration source is unavailable")
	}
	config := configuration{
		installationID: lookup(installationIDEnvironment),
		releaseID:      lookup(releaseIDEnvironment),
	}
	if paasv1.ValidateID("installationId", config.installationID) != nil ||
		paasv1.ValidateID("releaseId", config.releaseID) != nil {
		return configuration{}, errors.New("verification configuration is invalid")
	}
	return config, nil
}

func newHandler(config configuration) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ready", func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Cache-Control", "no-store")
		response.Header().Set("Content-Type", "application/json")
		response.Header().Set("X-Content-Type-Options", "nosniff")
		if request.URL.RawQuery != "" || request.ContentLength > 0 || len(request.TransferEncoding) > 0 {
			response.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(response).Encode(struct {
				APIVersion string `json:"apiVersion"`
				Kind       string `json:"kind"`
				State      string `json:"state"`
			}{APIVersion: probeAPIVersion, Kind: "InstallationProbe", State: "NOT_READY"})
			return
		}
		_ = json.NewEncoder(response).Encode(probe{
			APIVersion: probeAPIVersion, Kind: "InstallationProbe",
			InstallationID: config.installationID, ReleaseID: config.releaseID,
			State: "READY",
		})
	})
	return mux
}
