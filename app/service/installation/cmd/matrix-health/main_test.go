package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHealthProbeAcceptsOnlyLocalExactReadiness(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.Header.Get("Accept") != "application/json" {
			t.Fatalf("health request=%s headers=%#v", request.Method, request.Header)
		}
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{"state":"READY"}`))
	}))
	defer server.Close()
	target := strings.Replace(server.URL, "localhost", "127.0.0.1", 1) + "/ready"
	if err := run(context.Background(), []string{target}, server.Client()); err != nil {
		t.Fatalf("probe ready process: %v", err)
	}
	for _, invalid := range []string{
		"https://127.0.0.1:8080/ready",
		"http://audit:8080/ready",
		"http://127.0.0.1:8080/ready?detail=true",
		"http://127.0.0.1:8080/other",
	} {
		if err := run(context.Background(), []string{invalid}, server.Client()); err == nil {
			t.Fatalf("unsafe health target %q must fail", invalid)
		}
	}
}

func TestHealthProbeRejectsRedirectAndProviderBodyWithoutLeaking(t *testing.T) {
	redirected := false
	targetServer := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirected = true
	}))
	defer targetServer.Close()
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Location", targetServer.URL)
		response.WriteHeader(http.StatusTemporaryRedirect)
		_, _ = response.Write([]byte("credential=native-secret /host/path"))
	}))
	defer server.Close()
	target := strings.Replace(server.URL, "localhost", "127.0.0.1", 1) + "/ready"
	err := run(context.Background(), []string{target}, server.Client())
	if err == nil || redirected || errors.Is(err, context.Canceled) ||
		strings.Contains(err.Error(), "native-secret") || strings.Contains(err.Error(), "/host/path") {
		t.Fatalf("redirect health probe error=%v redirected=%t", err, redirected)
	}
}
