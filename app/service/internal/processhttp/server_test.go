package processhttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestReadinessHandlerNormalizesProcessState(t *testing.T) {
	providerFailure := errors.New("native provider failure contains /secret/path")
	ready := true
	handler, err := NewReadinessHandler(func(context.Context) error {
		if ready {
			return nil
		}
		return providerFailure
	})
	if err != nil {
		t.Fatalf("create readiness handler: %v", err)
	}

	assertProcessReadiness(t, handler, "/ready", http.StatusOK, "READY")
	ready = false
	recorder := assertProcessReadiness(
		t, handler, "/ready", http.StatusServiceUnavailable, "NOT_READY",
	)
	if body := recorder.Body.String(); strings.Contains(body, "native provider failure") ||
		strings.Contains(body, "/secret/path") {
		t.Fatalf("process readiness leaked provider detail: %s", body)
	}
	assertProcessReadiness(t, handler, "/ready?detail=true", http.StatusBadRequest, "NOT_READY")
}

func TestServeWithBackgroundCancelsItsPeer(t *testing.T) {
	handler, err := NewReadinessHandler(func(context.Context) error { return nil })
	if err != nil {
		t.Fatalf("create readiness handler: %v", err)
	}
	backgroundFailure := errors.New("background failed")
	err = ServeWithBackground(
		context.Background(),
		"127.0.0.1:0",
		handler,
		func(context.Context) error { return backgroundFailure },
	)
	if !errors.Is(err, backgroundFailure) {
		t.Fatalf("serve background error = %v", err)
	}
}

func assertProcessReadiness(
	t *testing.T,
	handler http.Handler,
	target string,
	status int,
	state string,
) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, target, nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != status {
		t.Fatalf("readiness status=%d want=%d body=%s", recorder.Code, status, recorder.Body.String())
	}
	var document readinessDocument
	if err := json.Unmarshal(recorder.Body.Bytes(), &document); err != nil ||
		document.APIVersion != ReadinessAPIVersion ||
		document.Kind != "ProcessReadiness" || document.State != state {
		t.Fatalf("readiness document=%#v err=%v", document, err)
	}
	return recorder
}
