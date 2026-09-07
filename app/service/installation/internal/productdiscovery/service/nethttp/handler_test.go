package nethttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	installationv1 "github.com/xiak/matrix/api/installation/v1"
	"github.com/xiak/matrix/app/service/installation/internal/productdiscovery"
)

const testRequestID = "request-0123456789abcdef0123456789abcdef"

func TestHandlerServesAuthorizedInstalledProducts(t *testing.T) {
	workflow := &fakeWorkflow{list: validList()}
	request := httptest.NewRequest(http.MethodGet, "/v1/installed-products", nil)
	request.Header.Set("Authorization", "Bearer user-session")
	response := httptest.NewRecorder()
	newTestHandler(t, workflow).ServeHTTP(response, request)
	if response.Code != http.StatusOK ||
		response.Header().Get("Matrix-Request-ID") != testRequestID ||
		response.Header().Get("Content-Security-Policy") == "" {
		t.Fatalf("installed-product response = %d headers=%v", response.Code, response.Header())
	}
	var result installationv1.InstalledProductList
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil ||
		installationv1.ValidateInstalledProductList(result) != nil {
		t.Fatalf("installed-product body = %s / %v", response.Body.String(), err)
	}
	if workflow.credential != "Bearer user-session" || workflow.requestID != testRequestID {
		t.Fatalf("workflow authority input = %q / %q", workflow.credential, workflow.requestID)
	}
}

func TestHandlerRejectsMissingAuthorityQueryAndBody(t *testing.T) {
	tests := []struct {
		name   string
		target string
		body   string
		status int
	}{
		{name: "missing credential", target: "/v1/installed-products", status: http.StatusUnauthorized},
		{name: "query", target: "/v1/installed-products?tenant=forged", status: http.StatusBadRequest},
		{name: "body", target: "/v1/installed-products", body: "{}", status: http.StatusBadRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var body *strings.Reader
			if test.body != "" {
				body = strings.NewReader(test.body)
			} else {
				body = strings.NewReader("")
			}
			request := httptest.NewRequest(http.MethodGet, test.target, body)
			if test.name != "missing credential" {
				request.Header.Set("Authorization", "Bearer user-session")
			}
			response := httptest.NewRecorder()
			newTestHandler(t, &fakeWorkflow{list: validList()}).ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
}

func TestHandlerNormalizesWorkflowErrorsWithoutNativeText(t *testing.T) {
	tests := []struct {
		err    error
		status int
	}{
		{err: productdiscovery.ErrUnauthenticated, status: http.StatusUnauthorized},
		{err: productdiscovery.ErrPermissionDenied, status: http.StatusForbidden},
		{err: errors.New("native secret-bearing failure"), status: http.StatusServiceUnavailable},
	}
	for _, test := range tests {
		workflow := &fakeWorkflow{err: test.err}
		request := httptest.NewRequest(http.MethodGet, "/v1/installed-products", nil)
		request.Header.Set("Authorization", "Bearer user-session")
		response := httptest.NewRecorder()
		newTestHandler(t, workflow).ServeHTTP(response, request)
		if response.Code != test.status ||
			strings.Contains(response.Body.String(), "native") ||
			strings.Contains(response.Body.String(), "secret-bearing") {
			t.Fatalf("normalized response=%d body=%s", response.Code, response.Body.String())
		}
	}
}

func TestHandlerReadinessUsesWorkflowState(t *testing.T) {
	for name, state := range map[string]installationv1.ReadinessState{
		"ready":     installationv1.ReadinessReady,
		"not-ready": installationv1.ReadinessNotReady,
	} {
		t.Run(name, func(t *testing.T) {
			readiness := installationv1.Readiness{
				APIVersion: installationv1.APIVersion,
				Kind:       "Readiness",
				State:      state,
				CheckedAt:  testTime(),
			}
			want := http.StatusServiceUnavailable
			if state == installationv1.ReadinessReady {
				readiness.ReleaseID = "matrix-v0.1.0-0123456789ab"
				want = http.StatusOK
			}
			response := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, "/ready", nil)
			newTestHandler(t, &fakeWorkflow{readiness: readiness}).ServeHTTP(response, request)
			if response.Code != want {
				t.Fatalf("readiness status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
}

type fakeWorkflow struct {
	list       installationv1.InstalledProductList
	readiness  installationv1.Readiness
	err        error
	credential string
	requestID  string
}

func (value *fakeWorkflow) List(
	_ context.Context,
	credential string,
	requestID string,
) (installationv1.InstalledProductList, error) {
	value.credential = credential
	value.requestID = requestID
	return value.list, value.err
}

func (value *fakeWorkflow) Readiness(context.Context) installationv1.Readiness {
	return value.readiness
}

func newTestHandler(t *testing.T, workflow Workflow) http.Handler {
	t.Helper()
	handler, err := NewHandler(workflow, Config{
		NewRequestID: func() (string, error) { return testRequestID, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func validList() installationv1.InstalledProductList {
	return installationv1.InstalledProductList{
		APIVersion:     installationv1.APIVersion,
		Kind:           "InstalledProductList",
		ReleaseID:      "matrix-v0.1.0-0123456789ab",
		ReleaseVersion: "v0.1.0",
		Products: []installationv1.InstalledProduct{{
			ID:         installationv1.ProductApplicationPaaS,
			Version:    "v0.1.0",
			RouteKey:   "paas",
			State:      installationv1.ProductReady,
			ObservedAt: testTime(),
		}},
		ObservedAt: testTime(),
	}
}

func testTime() time.Time {
	return time.Date(2026, 9, 7, 3, 4, 5, 0, time.UTC)
}
