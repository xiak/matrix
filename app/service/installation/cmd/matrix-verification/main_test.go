package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProbeBindsExactInstallationAndRelease(t *testing.T) {
	lookup := func(name string) string {
		switch name {
		case installationIDEnvironment:
			return "mxi-0123456789abcdef0123456789abcdef"
		case releaseIDEnvironment:
			return "matrix-v0.1.0-0123456789ab"
		default:
			return ""
		}
	}
	config, err := loadConfiguration(lookup)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/ready", nil)
	response := httptest.NewRecorder()
	newHandler(config).ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("probe status=%d body=%s", response.Code, response.Body.String())
	}
	var result probe
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.APIVersion != probeAPIVersion || result.Kind != "InstallationProbe" ||
		result.State != "READY" || result.InstallationID != config.installationID ||
		result.ReleaseID != config.releaseID {
		t.Fatalf("probe did not bind exact runtime identity: %+v", result)
	}
}

func TestApplicationProbeBindsENVAndReadOnlySecretWithoutReturningPlaintext(t *testing.T) {
	secret := []byte("application-probe-secret")
	lookup := func(name string) string {
		switch name {
		case settingEnvironment:
			return "one"
		case generationEnvironment:
			return "1"
		default:
			return ""
		}
	}
	config, err := loadApplicationConfiguration(
		lookup,
		func(path string) ([]byte, error) {
			if path != applicationSecretPath {
				t.Fatalf("Secret path=%q", path)
			}
			return append([]byte(nil), secret...), nil
		},
		func(path string) bool { return path == applicationSecretPath },
	)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(secret)
	if config.secretDigest != "sha256:"+hex.EncodeToString(digest[:]) {
		t.Fatal("application probe did not digest the exact Secret")
	}
	request := httptest.NewRequest(http.MethodGet, "/ready", nil)
	response := httptest.NewRecorder()
	newApplicationHandler(config).ServeHTTP(response, request)
	if response.Code != http.StatusOK || bytes.Contains(response.Body.Bytes(), secret) {
		t.Fatalf("application probe status=%d leaked=%t", response.Code, bytes.Contains(response.Body.Bytes(), secret))
	}
	if err := verifyNetworkProbeResponse(
		&http.Response{
			StatusCode: response.Code, Header: response.Header(),
			Body: io.NopCloser(strings.NewReader(response.Body.String())),
		},
		"one", config.secretDigest, "1",
	); err != nil {
		t.Fatalf("verify application probe response: %v", err)
	}
}

func TestApplicationProbeFailsClosedOnMixedIncompleteOrWritableInput(t *testing.T) {
	tests := []struct {
		name     string
		values   map[string]string
		readOnly bool
	}{
		{name: "missing generation", values: map[string]string{settingEnvironment: "one"}, readOnly: true},
		{name: "mixed installation", values: map[string]string{
			settingEnvironment: "one", generationEnvironment: "1", installationIDEnvironment: "installation-one",
		}, readOnly: true},
		{name: "writable Secret", values: map[string]string{
			settingEnvironment: "one", generationEnvironment: "1",
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := loadApplicationConfiguration(
				func(name string) string { return test.values[name] },
				func(string) ([]byte, error) { return []byte("secret"), nil },
				func(string) bool { return test.readOnly },
			)
			if err == nil {
				t.Fatal("invalid application probe configuration was accepted")
			}
		})
	}
	if err := run(context.Background(), []string{"probe", "http://external.invalid/"}, func(string) string { return "" }); err == nil {
		t.Fatal("caller-selected probe target was accepted")
	}
}

func TestProbeRejectsInvalidOrCallerControlledInput(t *testing.T) {
	if _, err := loadConfiguration(func(string) string { return "../unsafe" }); err == nil {
		t.Fatal("invalid runtime identity was accepted")
	}
	config := configuration{installationID: "mxi-0123456789abcdef0123456789abcdef", releaseID: "matrix-v0.1.0-0123456789ab"}
	request := httptest.NewRequest(http.MethodGet, "/ready?release=other", nil)
	response := httptest.NewRecorder()
	newHandler(config).ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("caller-controlled probe input was accepted: %d", response.Code)
	}
}
