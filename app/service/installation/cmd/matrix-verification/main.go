// matrix-verification is the fixed workload shipped in every authenticated
// release. Its default no-secret mode verifies installation identity; its
// lifecycle mode proves ordinary ENV, exact read-only Secret, and project
// network behavior without returning Secret material.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/internal/processhttp"
)

const (
	installationIDEnvironment = "MATRIX_INSTALLATION_ID"
	releaseIDEnvironment      = "MATRIX_RELEASE_ID"
	settingEnvironment        = "MATRIX_SETTING"
	generationEnvironment     = "MATRIX_GENERATION"
	applicationSecretPath     = "/run/secrets/credential"
	applicationProbeURL       = "http://web:8080/ready"
	listenAddress             = "0.0.0.0:8080"
	probeAPIVersion           = "verification.matrix.xiak.com/v1"
	maximumSecretBytes        = 1024 * 1024
	maximumProbeBytes         = 4096
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

type applicationConfiguration struct {
	setting      string
	generation   string
	secretDigest string
}

type applicationProbe struct {
	APIVersion     string `json:"apiVersion"`
	Kind           string `json:"kind"`
	State          string `json:"state"`
	Setting        string `json:"setting"`
	Generation     string `json:"generation"`
	SecretDigest   string `json:"secretDigest"`
	SecretReadOnly bool   `json:"secretReadOnly"`
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Getenv); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "matrix verification workload failed")
		os.Exit(1)
	}
}

func run(ctx context.Context, arguments []string, lookup func(string) string) error {
	if len(arguments) != 0 {
		return runNetworkProbe(ctx, arguments)
	}
	if lookup != nil && (lookup(settingEnvironment) != "" || lookup(generationEnvironment) != "") {
		config, err := loadApplicationConfiguration(lookup, os.ReadFile, secretReadOnly)
		if err != nil {
			return err
		}
		return processhttp.Serve(ctx, listenAddress, newApplicationHandler(config))
	}
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

func loadApplicationConfiguration(
	lookup func(string) string,
	readFile func(string) ([]byte, error),
	readOnly func(string) bool,
) (applicationConfiguration, error) {
	if lookup == nil || readFile == nil || readOnly == nil ||
		lookup(installationIDEnvironment) != "" || lookup(releaseIDEnvironment) != "" {
		return applicationConfiguration{}, errors.New("application probe configuration is invalid")
	}
	setting := lookup(settingEnvironment)
	generation := lookup(generationEnvironment)
	parsedGeneration, err := strconv.ParseUint(generation, 10, 64)
	if setting == "" || len(setting) > 256 || parsedGeneration == 0 ||
		strconv.FormatUint(parsedGeneration, 10) != generation {
		return applicationConfiguration{}, errors.New("application probe configuration is invalid")
	}
	secret, err := readFile(applicationSecretPath)
	if err != nil || len(secret) == 0 || len(secret) > maximumSecretBytes {
		clear(secret)
		return applicationConfiguration{}, errors.New("application probe Secret is unavailable")
	}
	digest := sha256.Sum256(secret)
	clear(secret)
	if !readOnly(applicationSecretPath) {
		return applicationConfiguration{}, errors.New("application probe Secret is writable")
	}
	return applicationConfiguration{
		setting: setting, generation: generation,
		secretDigest: "sha256:" + hex.EncodeToString(digest[:]),
	}, nil
}

func secretReadOnly(path string) bool {
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if file != nil {
		_ = file.Close()
	}
	return err != nil
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

func newApplicationHandler(config applicationConfiguration) http.Handler {
	result := applicationProbe{
		APIVersion: probeAPIVersion, Kind: "ApplicationProbe", State: "READY",
		Setting: config.setting, Generation: config.generation,
		SecretDigest: config.secretDigest, SecretReadOnly: true,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ready", func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Cache-Control", "no-store")
		response.Header().Set("Content-Type", "application/json")
		response.Header().Set("X-Content-Type-Options", "nosniff")
		if request.URL.RawQuery != "" || request.ContentLength > 0 || len(request.TransferEncoding) > 0 {
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(response).Encode(result)
	})
	return mux
}

func runNetworkProbe(ctx context.Context, arguments []string) error {
	if len(arguments) != 5 || arguments[0] != "probe" || arguments[1] != applicationProbeURL ||
		paasv1.ValidateDigest("secretDigest", arguments[3]) != nil {
		return errors.New("application network probe input is invalid")
	}
	parsedGeneration, err := strconv.ParseUint(arguments[4], 10, 64)
	if arguments[2] == "" || len(arguments[2]) > 256 || err != nil || parsedGeneration == 0 ||
		strconv.FormatUint(parsedGeneration, 10) != arguments[4] {
		return errors.New("application network probe input is invalid")
	}
	probeContext, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(probeContext, http.MethodGet, applicationProbeURL, nil)
	if err != nil {
		return errors.New("application network probe request is invalid")
	}
	client := &http.Client{
		Timeout: 2 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	var lastErr error
	for probeContext.Err() == nil {
		response, requestErr := client.Do(request.Clone(probeContext))
		if requestErr == nil {
			lastErr = verifyNetworkProbeResponse(response, arguments[2], arguments[3], arguments[4])
			if lastErr == nil {
				return nil
			}
		} else {
			lastErr = requestErr
		}
		select {
		case <-probeContext.Done():
		case <-time.After(100 * time.Millisecond):
		}
	}
	return errors.Join(errors.New("application network probe failed"), lastErr)
}

func verifyNetworkProbeResponse(
	response *http.Response,
	setting string,
	secretDigest string,
	generation string,
) error {
	if response == nil {
		return errors.New("application network probe response is unavailable")
	}
	defer response.Body.Close()
	mediaType, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if response.StatusCode != http.StatusOK || mediaErr != nil || mediaType != "application/json" ||
		response.Header.Get("Content-Encoding") != "" {
		return errors.New("application network probe response is invalid")
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, maximumProbeBytes+1))
	decoder.DisallowUnknownFields()
	var observed applicationProbe
	if err := decoder.Decode(&observed); err != nil {
		return errors.New("application network probe response is invalid")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) ||
		observed.APIVersion != probeAPIVersion || observed.Kind != "ApplicationProbe" ||
		observed.State != "READY" || observed.Setting != setting ||
		observed.Generation != generation || observed.SecretDigest != secretDigest ||
		!observed.SecretReadOnly {
		return errors.New("application network probe observation differs")
	}
	return nil
}
