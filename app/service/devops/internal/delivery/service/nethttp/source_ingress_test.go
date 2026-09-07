package nethttp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/domain"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/runadmission"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/sourceingress"
)

func TestSourceWebhookUsesEndpointBoundSystemAdmission(t *testing.T) {
	authorizer := &fakeAuthorizer{}
	ingress := &fakeSourceIngress{result: validHTTPAdmission(t)}
	handler := sourceIngressHandler(t, authorizer, ingress)
	request := sourceWebhookRequest(strings.NewReader(`{"action":"opened"}`))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || response.Body.Len() != 0 ||
		response.Header().Get("Matrix-Request-ID") != "request-webhook" {
		t.Fatalf("source ingress status=%d headers=%#v body=%s", response.Code, response.Header(), response.Body.String())
	}
	if authorizer.calls != 0 || ingress.calls != 1 {
		t.Fatalf("source ingress IAM calls=%d workflow calls=%d", authorizer.calls, ingress.calls)
	}
	command := ingress.command
	if command.Scope.TenantID != "tenant-one" || command.SourceConnectionID != "connection-one" ||
		command.ProviderEvent != "pull_request" ||
		command.DeliveryID != "123e4567-e89b-42d3-a456-426614174000" ||
		command.Signature != strings.Repeat("a", 64) || string(command.Body) != `{"action":"opened"}` ||
		command.RequestID != "request-webhook" || command.CorrelationID != "request-webhook" ||
		command.TraceParent != "" {
		t.Fatalf("source ingress command=%#v", command)
	}
}

func TestSourceWebhookRejectsAmbiguousExternalEnvelope(t *testing.T) {
	tests := map[string]struct {
		mutate func(*http.Request)
		status int
		code   devopsv1.ErrorCode
	}{
		"method": {
			mutate: func(value *http.Request) { value.Method = http.MethodGet },
			status: http.StatusMethodNotAllowed, code: devopsv1.ErrorMethodNotAllowed,
		},
		"query": {
			mutate: func(value *http.Request) { value.URL.RawQuery = "tenant=forged" },
			status: http.StatusBadRequest, code: devopsv1.ErrorInvalidArgument,
		},
		"caller authorization": {
			mutate: func(value *http.Request) { value.Header.Set("Authorization", "Bearer must-not-cross") },
			status: http.StatusBadRequest, code: devopsv1.ErrorInvalidArgument,
		},
		"caller correlation": {
			mutate: func(value *http.Request) { value.Header.Set("Matrix-Correlation-ID", "forged") },
			status: http.StatusBadRequest, code: devopsv1.ErrorInvalidArgument,
		},
		"encoded body": {
			mutate: func(value *http.Request) { value.Header.Set("Content-Encoding", "gzip") },
			status: http.StatusUnsupportedMediaType, code: devopsv1.ErrorUnsupportedMediaType,
		},
		"wrong media": {
			mutate: func(value *http.Request) { value.Header.Set("Content-Type", "text/plain") },
			status: http.StatusUnsupportedMediaType, code: devopsv1.ErrorUnsupportedMediaType,
		},
		"duplicate event": {
			mutate: func(value *http.Request) { value.Header.Add("X-Gitea-Event", "pull_request") },
			status: http.StatusBadRequest, code: devopsv1.ErrorInvalidArgument,
		},
		"empty body": {
			mutate: func(value *http.Request) { value.Body = http.NoBody; value.ContentLength = 0 },
			status: http.StatusBadRequest, code: devopsv1.ErrorInvalidArgument,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ingress := &fakeSourceIngress{result: validHTTPAdmission(t)}
			handler := sourceIngressHandler(t, &fakeAuthorizer{}, ingress)
			request := sourceWebhookRequest(strings.NewReader(`{"action":"opened"}`))
			test.mutate(request)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			assertProblem(t, response, test.status, test.code)
			if ingress.calls != 0 {
				t.Fatal("invalid external envelope reached source ingress")
			}
		})
	}

	ingress := &fakeSourceIngress{result: validHTTPAdmission(t)}
	handler := sourceIngressHandler(t, &fakeAuthorizer{}, ingress)
	request := sourceWebhookRequest(strings.NewReader(strings.Repeat("x", sourceingress.MaximumWebhookBodyBytes+1)))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	assertProblem(t, response, http.StatusRequestEntityTooLarge, devopsv1.ErrorPayloadTooLarge)
	if ingress.calls != 0 {
		t.Fatal("oversize webhook reached source ingress")
	}
}

func TestSourceWebhookMapsClosedAdmissionOutcomes(t *testing.T) {
	tests := map[string]struct {
		err    error
		status int
		code   devopsv1.ErrorCode
	}{
		"forged":              {err: sourceingress.ErrUnauthenticated, status: 401, code: devopsv1.ErrorUnauthenticated},
		"provider payload":    {err: sourceingress.ErrInvalidArgument, status: 422, code: devopsv1.ErrorInvalidArgument},
		"unsupported event":   {err: sourceingress.ErrUnsupportedEvent, status: 422, code: devopsv1.ErrorInvalidArgument},
		"stale configuration": {err: runadmission.ErrPreconditionFailed, status: 412, code: devopsv1.ErrorPreconditionFailed},
		"changed replay":      {err: runadmission.ErrReplayConflict, status: 409, code: devopsv1.ErrorConflict},
		"queue capacity":      {err: runadmission.ErrQueueCapacityExceeded, status: 429, code: devopsv1.ErrorResourceExhausted},
		"temporary":           {err: errors.Join(sourceingress.ErrUnavailable, errors.New("secret path must not leak")), status: 503, code: devopsv1.ErrorUnavailable},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ingress := &fakeSourceIngress{err: test.err}
			handler := sourceIngressHandler(t, &fakeAuthorizer{}, ingress)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, sourceWebhookRequest(strings.NewReader(`{"action":"opened"}`)))
			assertProblem(t, response, test.status, test.code)
			if strings.Contains(response.Body.String(), "secret path") {
				t.Fatal("native ingress detail leaked")
			}
			if test.status == http.StatusTooManyRequests && response.Header().Get("Retry-After") != "30" {
				t.Fatalf("queue Retry-After=%q", response.Header().Get("Retry-After"))
			}
		})
	}
}

type fakeSourceIngress struct {
	command sourceingress.Command
	result  runadmission.Result
	err     error
	calls   int
}

func (value *fakeSourceIngress) Receive(
	_ context.Context,
	command sourceingress.Command,
) (runadmission.Result, error) {
	value.calls++
	value.command = command
	value.command.Body = append([]byte(nil), command.Body...)
	return value.result, value.err
}

func sourceIngressHandler(t *testing.T, authorizer *fakeAuthorizer, ingress *fakeSourceIngress) http.Handler {
	t.Helper()
	readiness := devopsv1.Readiness{
		APIVersion: devopsv1.APIVersion, Kind: "Readiness", State: devopsv1.ReadinessReady,
		SchemaVersion: 1, CheckedAt: time.Date(2026, 9, 8, 4, 5, 6, 0, time.UTC),
	}
	handler, err := NewHandler(authorizer, newFakeWorkflow(t), Config{
		Readiness:     func(context.Context) (devopsv1.Readiness, error) { return readiness, nil },
		NewRequestID:  func() (string, error) { return "request-webhook", nil },
		SourceIngress: ingress,
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func sourceWebhookRequest(body *strings.Reader) *http.Request {
	request := httptest.NewRequest(
		http.MethodPost, "/v1/source-ingress/tenant-one/connection-one", body,
	)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Gitea-Event", "pull_request")
	request.Header.Set("X-Gitea-Delivery", "123e4567-e89b-42d3-a456-426614174000")
	request.Header.Set("X-Gitea-Signature", strings.Repeat("a", 64))
	return request
}

func validHTTPAdmission(t *testing.T) runadmission.Result {
	t.Helper()
	now := time.Date(2026, 9, 8, 1, 2, 3, 0, time.UTC)
	scope := devopsv1.ResourceScope{TenantID: "tenant-one"}
	connection, err := domain.NewSourceConnection(devopsv1.CreateSourceConnectionRequest{
		ID: "connection-one", Name: "connection-one",
		Spec: devopsv1.SourceConnectionSpec{
			AdapterID: "source-adapter-gitea-v1", AllowedEndpointOrigins: []string{"https://git.example.com"},
			WebhookSecretRef: "webhook-secret", FetchCredentialRef: "fetch-secret", ReportCredentialRef: "report-secret",
		},
	}, scope, now)
	if err != nil {
		t.Fatal(err)
	}
	connection.Status.Health = devopsv1.SourceConnectionReady
	project, err := domain.NewDevOpsProject(devopsv1.CreateDevOpsProjectRequest{
		ID: "project-one", Name: "project-one",
	}, scope, now)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := domain.NewRepositoryBinding(devopsv1.CreateRepositoryBindingRequest{
		ID: "binding-one", Name: "binding-one", ProjectID: project.Metadata.ID,
		Spec: devopsv1.RepositoryBindingSpec{
			SourceConnectionID: connection.Metadata.ID, ExternalRepositoryID: "42",
			RepositoryPath: "matrix/api", TrustedDefaultBranch: "main",
		},
	}, project, connection, now)
	if err != nil {
		t.Fatal(err)
	}
	binding.Status.Health = devopsv1.RepositoryBindingReady
	event, err := domain.NewSourceEvent(domain.NormalizedChange{
		Scope: scope, SourceConnectionID: connection.Metadata.ID,
		VerifiedSourceConnectionVersion: connection.Metadata.ResourceVersion,
		ExternalRepositoryID:            binding.Spec.ExternalRepositoryID, TrustedBaseBranch: "main",
		DeliveryID:             "123e4567-e89b-42d3-a456-426614174000",
		CanonicalPayloadDigest: "sha256:" + strings.Repeat("a", 64),
		Change: devopsv1.ChangeIdentity{
			Number: 17, Action: devopsv1.ChangeOpened,
			HeadCommit: strings.Repeat("1", 40), TrustedBaseCommit: strings.Repeat("2", 40),
		},
	}, connection, binding, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	return runadmission.Result{Admission: runadmission.Admission{Event: event}}
}
