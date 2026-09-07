package readinesshttp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	installationv1 "github.com/xiak/matrix/api/installation/v1"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

func TestObserverMapsOnlyValidatedPaaSReadiness(t *testing.T) {
	now := time.Date(2026, 9, 7, 3, 4, 5, 0, time.UTC)
	for name, state := range map[string]paasv1.ReadinessState{
		"ready":     paasv1.ReadinessReady,
		"not ready": paasv1.ReadinessNotReady,
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				if request.Method != http.MethodGet || request.URL.Path != "/ready" ||
					request.URL.RawQuery != "" {
					t.Errorf("readiness request = %s %s", request.Method, request.URL.String())
				}
				response.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(response).Encode(paasv1.Readiness{
					APIVersion:    paasv1.APIVersion,
					Kind:          "Readiness",
					State:         state,
					SchemaVersion: 1,
					CheckedAt:     now,
				})
			}))
			defer server.Close()
			observer := newTestObserver(t, server)
			result, err := observer.Observe(context.Background(), installationv1.ProductApplicationPaaS)
			if err != nil || result.ObservedAt != now {
				t.Fatalf("PaaS observation = %#v / %v", result, err)
			}
			if state == paasv1.ReadinessReady &&
				(result.State != installationv1.ProductReady || result.Reason != "") {
				t.Fatalf("ready PaaS mapped to %#v", result)
			}
			if state == paasv1.ReadinessNotReady &&
				(result.State != installationv1.ProductUnavailable ||
					result.Reason != installationv1.ReasonDependencyUnavailable) {
				t.Fatalf("not-ready PaaS mapped to %#v", result)
			}
		})
	}
}

func TestObserverRejectsNativeFailureAndUnknownProduct(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "text/plain")
		response.WriteHeader(http.StatusBadGateway)
		_, _ = response.Write([]byte("native secret-bearing failure"))
	}))
	defer server.Close()
	observer := newTestObserver(t, server)
	if _, err := observer.Observe(
		context.Background(),
		installationv1.ProductApplicationPaaS,
	); err == nil {
		t.Fatal("native PaaS failure was accepted")
	}
	if _, err := observer.Observe(
		context.Background(),
		installationv1.ProductDevOps,
	); err == nil {
		t.Fatal("undeclared readiness adapter was accepted")
	}
}

func newTestObserver(t *testing.T, server *httptest.Server) *Observer {
	t.Helper()
	observer, err := NewObserver(Config{
		PaaSEndpoint: server.URL,
		HTTPClient:   server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return observer
}
