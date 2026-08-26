package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
