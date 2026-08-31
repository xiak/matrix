package nethttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/port"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/applicationlifecycle"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/executionadmission"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/verifyinstallation"
)

func TestHandlerReadinessIsOperationalAndSanitized(t *testing.T) {
	readyErr := error(nil)
	readiness := paasv1.Readiness{
		APIVersion: paasv1.APIVersion, Kind: "Readiness", State: paasv1.ReadinessReady,
		SchemaVersion: 1, CheckedAt: time.Date(2026, 8, 26, 3, 4, 5, 678_000, time.UTC),
	}
	handler, err := NewHandler(&fakeAuthorizer{}, &fakeWorkflow{}, &fakeExecutionWorkflow{}, &fakeInstallationVerifier{}, Config{
		Readiness: func(context.Context) (paasv1.Readiness, error) {
			return readiness, readyErr
		},
	})
	if err != nil {
		t.Fatalf("create readiness handler: %v", err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/ready", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("ready response=%d body=%q", response.Code, response.Body.String())
	}
	var got paasv1.Readiness
	if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil || got != readiness {
		t.Fatalf("decode readiness=%#v err=%v", got, err)
	}
	readyErr = errors.New("database credential=do-not-expose")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/ready", nil))
	if response.Code != http.StatusServiceUnavailable ||
		strings.Contains(response.Body.String(), "credential") {
		t.Fatalf("not-ready response=%d body=%q", response.Code, response.Body.String())
	}
}

func TestExecutionAdmissionAuthorizesTheActualResourceAndInstallation(t *testing.T) {
	authorization := port.Authorization{InstallationID: "installation-a", Subject: paasv1.SubjectRef{Type: paasv1.SubjectUser, ID: "platform-user"}, DecisionID: "decision-platform", RequestID: "request-test"}
	authorizer, workflow := &fakeAuthorizer{result: &authorization}, &fakeExecutionWorkflow{}
	handler, err := NewHandler(authorizer, &fakeWorkflow{}, workflow, &fakeInstallationVerifier{}, Config{
		NewRequestID: func() (string, error) { return "request-test", nil }, Readiness: func(context.Context) (paasv1.Readiness, error) { return paasv1.Readiness{}, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	request := jsonRequest(t, http.MethodPost, "/v1/execution-targets", paasv1.RegisterExecutionTargetRequest{ID: "node-a", Name: "host-a", ExecutionPoolID: "pool-a", BindingRef: "protected-a"})
	request.Header.Set("Authorization", "Bearer platform-user")
	request.Header.Set("Idempotency-Key", "register-a")
	request.Header.Set("X-Tenant-ID", "attacker-tenant")
	request.Header.Set("X-Installation-ID", "attacker-installation")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated || workflow.registerCalls != 1 ||
		authorizer.request.Action != port.AuthorizeExecutionTargetRegister || authorizer.request.Resource != (paasv1.ResourceRef{Kind: "ExecutionTarget", ID: "node-a"}) ||
		workflow.registerCommand.Authorization.InstallationID != "installation-a" || workflow.registerCommand.Authorization.TenantID != "" ||
		response.Header().Get("Operation-Location") != "/v1/platform/operations/operation-a" {
		t.Fatalf("host admission identity mismatch: status=%d body=%s request=%#v", response.Code, response.Body.String(), authorizer.request)
	}

	for _, body := range []string{
		`{"id":"node-a","id":"node-b","name":"host-a","executionPoolId":"pool-a","bindingRef":"protected-a"}`,
		`{"Id":"node-a","name":"host-a","executionPoolId":"pool-a","bindingRef":"protected-a"}`,
		`{"id":"node-a","name":"host-a","executionPoolId":"pool-a","bindingRef":"protected-a","installationId":"attacker"}`,
		`{"id":"node-a","name":"host-a","executionPoolId":"pool-a","bindingRef":"protected-a","endpoint":"https://attacker:443"}`,
		`{"id":"node-a","name":"host-a","executionPoolId":"pool-a","bindingRef":"protected-a","labels":{"matrix-machine-fingerprint":"forged"}}`,
		`{"id":"node-a","name":"host-a","executionPoolId":"pool-a","bindingRef":"protected-a"} {}`,
	} {
		authorizer.request = port.AuthorizationRequest{}
		request = httptest.NewRequest(http.MethodPost, "/v1/execution-targets", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Authorization", "Bearer platform-user")
		response = httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest || workflow.registerCalls != 1 || authorizer.request != (port.AuthorizationRequest{}) {
			t.Fatalf("ambiguous node admission reached authorization/workflow: status=%d body=%s", response.Code, response.Body.String())
		}
	}
	authorizer.err = port.ErrPermissionDenied
	request = jsonRequest(t, http.MethodPost, "/v1/execution-pools", paasv1.CreateExecutionPoolRequest{ID: "pool-a", Name: "hosts", Spec: paasv1.ExecutionPoolSpec{AllowedIsolationGuarantees: []paasv1.IsolationGuarantee{paasv1.IsolationWorkload}}})
	request.Header.Set("Authorization", "Bearer tenant-admin")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || workflow.createCalls != 0 {
		t.Fatal("tenant administrator could create a platform pool")
	}
}

func TestExecutionTargetInventoryIsPlatformAuthorizedAndSelectorFree(t *testing.T) {
	authorization := port.Authorization{
		InstallationID: "installation-a",
		Subject:        paasv1.SubjectRef{Type: paasv1.SubjectUser, ID: "platform-user"},
		DecisionID:     "decision-platform-list",
		RequestID:      "request-test",
	}
	authorizer := &fakeAuthorizer{result: &authorization}
	workflow := &fakeExecutionWorkflow{listResult: paasv1.ExecutionTargetList{
		APIVersion: paasv1.APIVersion,
		Kind:       "ExecutionTargetList",
		Items:      []paasv1.ExecutionTarget{},
	}}
	handler, err := NewHandler(authorizer, &fakeWorkflow{}, workflow, &fakeInstallationVerifier{}, Config{
		NewRequestID: func() (string, error) { return "request-test", nil },
		Readiness:    func(context.Context) (paasv1.Readiness, error) { return paasv1.Readiness{}, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/execution-targets", nil)
	request.Header.Set("Authorization", "Bearer platform-user")
	request.Header.Set("X-Tenant-ID", "attacker-tenant")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	var result paasv1.ExecutionTargetList
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &result) != nil ||
		paasv1.ValidateExecutionTargetList(result) != nil || workflow.listCalls != 1 ||
		authorizer.request.Action != port.AuthorizeExecutionTargetRead ||
		authorizer.request.Resource != (paasv1.ResourceRef{Kind: "ExecutionTarget", ID: "collection"}) ||
		workflow.listAuthorization.InstallationID != "installation-a" || workflow.listAuthorization.TenantID != "" {
		t.Fatalf("execution target inventory response=%d body=%s authorization=%#v", response.Code, response.Body.String(), authorizer.request)
	}
	for _, target := range []string{
		"/v1/execution-targets?tenantId=attacker",
		"/v1/execution-targets?executionTargetId=node-a",
	} {
		authorizer.request = port.AuthorizationRequest{}
		response = httptest.NewRecorder()
		request = httptest.NewRequest(http.MethodGet, target, nil)
		request.Header.Set("Authorization", "Bearer platform-user")
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest || workflow.listCalls != 1 ||
			authorizer.request != (port.AuthorizationRequest{}) {
			t.Fatalf("execution target selector reached authorization/workflow: status=%d", response.Code)
		}
	}
}

func TestHandlerUsesOnlyVerifierCredentialForFixedInstallationProbe(t *testing.T) {
	authorizer := &fakeAuthorizer{}
	verifier := &fakeInstallationVerifier{result: paasv1.InstallationVerification{
		APIVersion: paasv1.APIVersion, Kind: "InstallationVerification",
		InstallationID: "mxi-0123456789abcdef0123456789abcdef",
		ReleaseID:      "matrix-v0.1.0-001", State: paasv1.InstallationVerificationReady,
		DeploymentID: "installation-verification-deployment", Generation: 1,
		OperationID:     "operation-installation-verification",
		OperationState:  paasv1.OperationSucceeded,
		DeploymentPhase: paasv1.DeploymentReady,
		CheckedAt:       time.Date(2026, 8, 26, 3, 4, 5, 678_000, time.UTC),
	}}
	handler := mustHandlerWithVerifier(t, authorizer, &fakeWorkflow{}, verifier)
	request := jsonRequest(t, http.MethodPost, "/v1/installation:verify", paasv1.VerifyInstallationRequest{
		InstallationID: "mxi-0123456789abcdef0123456789abcdef",
		ReleaseID:      "matrix-v0.1.0-001",
	})
	request.Header.Set("Authorization", "Bearer verifier-credential")
	request.Header.Set("Idempotency-Key", "verify-installation-test")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("installation verification status=%d body=%s", response.Code, response.Body.String())
	}
	if verifier.calls != 1 || verifier.command.Credential != "Bearer verifier-credential" ||
		verifier.command.RequestID != "request-test" ||
		verifier.command.IdempotencyKey != "verify-installation-test" ||
		verifier.command.Request.InstallationID != "mxi-0123456789abcdef0123456789abcdef" {
		t.Fatalf("installation verification command=%#v", verifier.command)
	}
	if authorizer.request != (port.AuthorizationRequest{}) {
		t.Fatalf("fixed verifier route used generic user Authorizer: %#v", authorizer.request)
	}

	request = jsonRequest(t, http.MethodPost, "/v1/installation:verify", paasv1.VerifyInstallationRequest{
		InstallationID: "mxi-0123456789abcdef0123456789abcdef",
		ReleaseID:      "matrix-v0.1.0-001",
	})
	request.Header.Set("Authorization", "Bearer verifier-credential")
	request.Header.Set("Idempotency-Key", "verify-installation-test")
	request.Header.Set("Matrix-Subject-Credential", "user-session")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || verifier.calls != 1 {
		t.Fatalf("subject-bearing verifier status=%d calls=%d", response.Code, verifier.calls)
	}
}

func TestHandlerUsesAuthorizedTenantAndSubjectInsteadOfClientHeaders(t *testing.T) {
	authorizer := &fakeAuthorizer{}
	workflow := &fakeWorkflow{}
	handler := mustHandler(t, authorizer, workflow)
	body := paasv1.CreateDeploymentRequest{
		ID: "deployment-a", Name: "deployment-a",
		Spec: paasv1.DeploymentSpec{
			ApplicationRevisionID: "revision-a", PlacementPolicyID: "policy-a",
			DesiredState: paasv1.DeploymentDesiredRunning,
			Components:   []paasv1.DeploymentComponent{{Name: "api", Replicas: 1}},
		},
	}
	request := jsonRequest(t, http.MethodPost, "/v1/deployments", body)
	request.Header.Set("Authorization", "Bearer opaque-credential")
	request.Header.Set("Idempotency-Key", "create-deployment-a")
	request.Header.Set("X-Tenant-ID", "tenant-attacker")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if workflow.submitCalls != 1 ||
		workflow.submitCommand.Authorization.TenantID != "tenant-authorized" ||
		workflow.submitCommand.Authorization.Subject.ID != "user-authorized" {
		t.Fatalf("submitted command = %#v", workflow.submitCommand)
	}
	if authorizer.request.Action != port.AuthorizeDeploymentCreate ||
		authorizer.request.Resource != (paasv1.ResourceRef{Kind: "Deployment", ID: "collection"}) ||
		authorizer.request.Credential != "Bearer opaque-credential" {
		t.Fatalf("authorization request = %#v", authorizer.request)
	}
	if response.Header().Get("Location") != "/v1/deployments/deployment-a" ||
		response.Header().Get("Operation-Location") != "/v1/operations/operation-a" ||
		response.Header().Get("ETag") != `"1"` {
		t.Fatalf("mutation headers = %#v", response.Header())
	}
}

func TestHandlerRejectsClientIdentityFields(t *testing.T) {
	authorizer := &fakeAuthorizer{}
	workflow := &fakeWorkflow{}
	handler := mustHandler(t, authorizer, workflow)
	request := httptest.NewRequest(
		http.MethodPost,
		"/v1/applications",
		strings.NewReader(`{"id":"application-a","name":"application-a","tenantId":"tenant-attacker","requestedBy":{"type":"USER","id":"attacker"}}`),
	)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer opaque-credential")
	request.Header.Set("Idempotency-Key", "create-application-a")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if workflow.createApplicationCalls != 0 {
		t.Fatal("identity-bearing client document reached the workflow")
	}
}

func TestHandlerFailsClosedOnIAMDenialAndUnavailableError(t *testing.T) {
	tests := []struct {
		name       string
		authorizer *fakeAuthorizer
		status     int
		forbidden  string
	}{
		{name: "denied", authorizer: &fakeAuthorizer{err: port.ErrPermissionDenied}, status: http.StatusForbidden},
		{
			name:       "unavailable",
			authorizer: &fakeAuthorizer{err: errors.Join(port.ErrAuthorizationUnavailable, errors.New("token=do-not-expose"))},
			status:     http.StatusServiceUnavailable,
			forbidden:  "do-not-expose",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			workflow := &fakeWorkflow{}
			handler := mustHandler(t, test.authorizer, workflow)
			request := httptest.NewRequest(http.MethodGet, "/v1/applications/application-a", nil)
			request.Header.Set("Authorization", "Bearer opaque-credential")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
			}
			if test.forbidden != "" && strings.Contains(response.Body.String(), test.forbidden) {
				t.Fatalf("IAM native error leaked: %s", response.Body.String())
			}
			if workflow.getApplicationCalls != 0 {
				t.Fatal("denied IAM request reached workflow")
			}
		})
	}
}

func TestHandlerRejectsInvalidSuccessfulIAMDecision(t *testing.T) {
	authorizer := &fakeAuthorizer{result: &port.Authorization{
		TenantID:   "tenant-authorized",
		Subject:    paasv1.SubjectRef{Type: paasv1.SubjectUser, ID: "user-authorized"},
		DecisionID: "decision-authorized", RequestID: "different-request",
	}}
	workflow := &fakeWorkflow{}
	handler := mustHandler(t, authorizer, workflow)
	request := httptest.NewRequest(http.MethodGet, "/v1/applications/application-a", nil)
	request.Header.Set("Authorization", "Bearer opaque-credential")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if workflow.getApplicationCalls != 0 {
		t.Fatal("invalid IAM decision reached the workflow")
	}
}

func TestHandlerRequiresExactIfMatchForDeploymentMutation(t *testing.T) {
	authorizer := &fakeAuthorizer{}
	workflow := &fakeWorkflow{}
	handler := mustHandler(t, authorizer, workflow)
	request := jsonRequest(t, http.MethodPut, "/v1/deployments/deployment-a", paasv1.DeploymentSpec{})
	request.Header.Set("Authorization", "Bearer opaque-credential")
	request.Header.Set("Idempotency-Key", "update-deployment-a")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusPreconditionRequired {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if workflow.submitCalls != 0 {
		t.Fatal("update without If-Match reached workflow")
	}

	request = jsonRequest(t, http.MethodPut, "/v1/deployments/deployment-a", paasv1.DeploymentSpec{})
	request.Header.Set("Authorization", "Bearer opaque-credential")
	request.Header.Set("Idempotency-Key", "update-deployment-a")
	request.Header.Set("If-Match", `"7"`)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if workflow.submitCommand.ExpectedResourceVersion != 7 {
		t.Fatalf("expected resource version = %d", workflow.submitCommand.ExpectedResourceVersion)
	}
	if authorizer.request.Action != port.AuthorizeDeploymentUpdate {
		t.Fatalf("running Deployment authorization action = %q", authorizer.request.Action)
	}

	request = jsonRequest(t, http.MethodPut, "/v1/deployments/deployment-a", paasv1.DeploymentSpec{
		DesiredState: paasv1.DeploymentDesiredStopped,
	})
	request.Header.Set("Authorization", "Bearer opaque-credential")
	request.Header.Set("Idempotency-Key", "stop-deployment-a")
	request.Header.Set("If-Match", `"7"`)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("stop status = %d, body = %s", response.Code, response.Body.String())
	}
	if authorizer.request.Action != port.AuthorizeDeploymentStop {
		t.Fatalf("stopped Deployment authorization action = %q", authorizer.request.Action)
	}
}

func TestHandlerRoutesRollbackWithAuthorizedIdentityAndIfMatch(t *testing.T) {
	authorizer := &fakeAuthorizer{}
	workflow := &fakeWorkflow{}
	handler := mustHandler(t, authorizer, workflow)
	request := jsonRequest(
		t,
		http.MethodPost,
		"/v1/deployments/deployment-a/rollback",
		paasv1.RollbackDeploymentRequest{SourceGeneration: 2},
	)
	request.Header.Set("Authorization", "Bearer opaque-credential")
	request.Header.Set("Idempotency-Key", "rollback-deployment-a")
	request.Header.Set("If-Match", `"7"`)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	command := workflow.rollbackCommand
	if workflow.rollbackCalls != 1 || command.Authorization.TenantID != "tenant-authorized" ||
		command.DeploymentID != "deployment-a" || command.SourceGeneration != 2 ||
		command.ExpectedResourceVersion != 7 || command.IdempotencyKey != "rollback-deployment-a" {
		t.Fatalf("rollback command = %#v", command)
	}
	if authorizer.request.Action != port.AuthorizeDeploymentRollback ||
		authorizer.request.Resource != (paasv1.ResourceRef{Kind: "Deployment", ID: "deployment-a"}) {
		t.Fatalf("rollback authorization request = %#v", authorizer.request)
	}
}

func TestHandlerPassesIAMTenantToReadsAndIgnoresTenantHeader(t *testing.T) {
	authorizer := &fakeAuthorizer{}
	workflow := &fakeWorkflow{}
	handler := mustHandler(t, authorizer, workflow)
	request := httptest.NewRequest(http.MethodGet, "/v1/applications/application-a", nil)
	request.Header.Set("Authorization", "Bearer opaque-credential")
	request.Header.Set("X-Tenant-ID", "tenant-attacker")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if workflow.readAuthorization.TenantID != "tenant-authorized" ||
		workflow.readID != "application-a" {
		t.Fatalf("read authorization/id = %#v / %q", workflow.readAuthorization, workflow.readID)
	}
}

func TestHandlerListsDeploymentsWithOnlyOpaqueCursor(t *testing.T) {
	authorizer := &fakeAuthorizer{}
	workflow := &fakeWorkflow{deploymentList: paasv1.DeploymentList{
		APIVersion: paasv1.APIVersion,
		Kind:       "DeploymentList",
		Scope: paasv1.ResourceScope{
			Kind: paasv1.AuthorityTenant, TenantID: "tenant-authorized",
		},
		Items: []paasv1.Deployment{},
	}}
	handler := mustHandler(t, authorizer, workflow)
	request := httptest.NewRequest(http.MethodGet, "/v1/deployments?after=deployment-before", nil)
	request.Header.Set("Authorization", "Bearer opaque-credential")
	request.Header.Set("X-Tenant-ID", "tenant-attacker")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if workflow.listDeploymentsCalls != 1 || workflow.listAfter != "deployment-before" ||
		workflow.readAuthorization.TenantID != "tenant-authorized" {
		t.Fatalf("list workflow = %#v", workflow)
	}
	if authorizer.request.Action != port.AuthorizeDeploymentRead ||
		authorizer.request.Resource != (paasv1.ResourceRef{Kind: "Deployment", ID: "collection"}) {
		t.Fatalf("list authorization = %#v", authorizer.request)
	}

	request = httptest.NewRequest(
		http.MethodGet,
		"/v1/deployments?executionTargetId=execution-target-attacker",
		nil,
	)
	request.Header.Set("Authorization", "Bearer opaque-credential")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("selector status = %d, body = %s", response.Code, response.Body.String())
	}
	if workflow.listDeploymentsCalls != 1 {
		t.Fatal("provider selector reached Deployment list workflow")
	}

	request = httptest.NewRequest(
		http.MethodGet,
		"/v1/deployments?after=deployment-before;executionTargetId=execution-target-attacker",
		nil,
	)
	request.Header.Set("Authorization", "Bearer opaque-credential")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || workflow.listDeploymentsCalls != 1 {
		t.Fatalf("malformed selector status/calls = %d/%d", response.Code, workflow.listDeploymentsCalls)
	}
}

func TestHandlerReadsDeploymentRuntimeThroughExactDeploymentAuthorization(t *testing.T) {
	observedAt := time.Date(2026, 8, 30, 9, 0, 0, 0, time.UTC)
	authorizer := &fakeAuthorizer{}
	workflow := &fakeWorkflow{runtimeSnapshot: paasv1.DeploymentRuntimeSnapshot{
		APIVersion: paasv1.APIVersion,
		Kind:       "DeploymentRuntimeSnapshot",
		Scope: paasv1.ResourceScope{
			Kind: paasv1.AuthorityTenant, TenantID: "tenant-authorized",
		},
		State: paasv1.MeasurementAvailable,
		Value: &paasv1.DeploymentRuntimeValue{
			Observation: paasv1.DeploymentRuntimeObservation{
				DeploymentID:          "deployment-a",
				Generation:            1,
				ApplicationRevisionID: "revision-a",
				ExecutionTargetID:     "execution-target-a",
				Instances:             []paasv1.DeploymentRuntimeInstance{},
				ObservedAt:            observedAt,
			},
			ValidUntil: observedAt.Add(15 * time.Second),
		},
		Resources: paasv1.DeploymentResourceSnapshot{State: paasv1.MeasurementUnavailable},
	}}
	handler := mustHandler(t, authorizer, workflow)
	request := httptest.NewRequest(http.MethodGet, "/v1/deployments/deployment-a/runtime", nil)
	request.Header.Set("Authorization", "Bearer opaque-credential")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if workflow.runtimeCalls != 1 || workflow.readID != "deployment-a" ||
		workflow.readAuthorization.TenantID != "tenant-authorized" {
		t.Fatalf("runtime workflow = %#v", workflow)
	}
	if authorizer.request.Action != port.AuthorizeDeploymentRead ||
		authorizer.request.Resource != (paasv1.ResourceRef{Kind: "Deployment", ID: "deployment-a"}) {
		t.Fatalf("runtime authorization = %#v", authorizer.request)
	}

	for _, invalidRequest := range []*http.Request{
		httptest.NewRequest(http.MethodGet, "/v1/deployments/deployment-a/runtime?executionTargetId=execution-target-attacker", nil),
		httptest.NewRequest(http.MethodGet, "/v1/deployments/deployment-a/runtime?", nil),
		httptest.NewRequest(http.MethodGet, "/v1/deployments/deployment-a/runtime", strings.NewReader(`{}`)),
	} {
		invalidRequest.Header.Set("Authorization", "Bearer opaque-credential")
		invalidResponse := httptest.NewRecorder()
		handler.ServeHTTP(invalidResponse, invalidRequest)
		if invalidResponse.Code != http.StatusBadRequest {
			t.Fatalf("runtime selector/body status = %d, body = %s", invalidResponse.Code, invalidResponse.Body.String())
		}
	}
	if workflow.runtimeCalls != 1 {
		t.Fatal("runtime selector or body reached the Deployment workflow")
	}
}

type fakeAuthorizer struct {
	request port.AuthorizationRequest
	err     error
	result  *port.Authorization
}

func (authorizer *fakeAuthorizer) Authorize(
	_ context.Context,
	request port.AuthorizationRequest,
) (port.Authorization, error) {
	authorizer.request = request
	if authorizer.err != nil {
		return port.Authorization{}, authorizer.err
	}
	if authorizer.result != nil {
		return *authorizer.result, nil
	}
	return port.Authorization{
		TenantID:   "tenant-authorized",
		Subject:    paasv1.SubjectRef{Type: paasv1.SubjectUser, ID: "user-authorized"},
		DecisionID: "decision-authorized", RequestID: request.RequestID,
		AuditID: "audit-authorized",
	}, nil
}

type fakeWorkflow struct {
	createApplicationCalls int
	submitCalls            int
	submitCommand          applicationlifecycle.SubmitCommand
	rollbackCalls          int
	rollbackCommand        applicationlifecycle.RollbackCommand
	getApplicationCalls    int
	readAuthorization      port.Authorization
	readID                 paasv1.ResourceID
	listDeploymentsCalls   int
	listAfter              paasv1.ResourceID
	deploymentList         paasv1.DeploymentList
	runtimeCalls           int
	runtimeSnapshot        paasv1.DeploymentRuntimeSnapshot
}

type fakeInstallationVerifier struct {
	calls   int
	command verifyinstallation.Command
	result  paasv1.InstallationVerification
	err     error
}

func (value *fakeInstallationVerifier) VerifyInstallation(
	_ context.Context,
	command verifyinstallation.Command,
) (paasv1.InstallationVerification, error) {
	value.calls++
	value.command = command
	return value.result, value.err
}

func (workflow *fakeWorkflow) CreateApplication(
	_ context.Context,
	command applicationlifecycle.CreateApplicationCommand,
) (paasv1.Application, paasv1.Operation, bool, error) {
	workflow.createApplicationCalls++
	resource := paasv1.Application{Metadata: testMetadata(command.Request.ID, command.Request.Name)}
	return resource, testOperation("Application", resource.Metadata.ID, paasv1.OperationCreateApplication, paasv1.OperationSucceeded), false, nil
}

func (workflow *fakeWorkflow) CreateConfiguration(
	context.Context,
	applicationlifecycle.CreateConfigurationCommand,
) (paasv1.Configuration, paasv1.Operation, bool, error) {
	return paasv1.Configuration{}, paasv1.Operation{}, false, errors.New("unexpected CreateConfiguration")
}

func (workflow *fakeWorkflow) CreateConfigurationRevision(
	context.Context,
	applicationlifecycle.CreateConfigurationRevisionCommand,
) (paasv1.ConfigurationRevision, paasv1.Operation, bool, error) {
	return paasv1.ConfigurationRevision{}, paasv1.Operation{}, false, errors.New("unexpected CreateConfigurationRevision")
}

func (workflow *fakeWorkflow) CreateApplicationRevision(
	context.Context,
	applicationlifecycle.CreateApplicationRevisionCommand,
) (paasv1.ApplicationRevision, paasv1.Operation, bool, error) {
	return paasv1.ApplicationRevision{}, paasv1.Operation{}, false, errors.New("unexpected CreateApplicationRevision")
}

func (workflow *fakeWorkflow) Submit(
	_ context.Context,
	command applicationlifecycle.SubmitCommand,
) (applicationlifecycle.Result, error) {
	workflow.submitCalls++
	workflow.submitCommand = command
	deployment := paasv1.Deployment{
		Metadata: testMetadata(command.DeploymentID, "deployment-a"), Generation: 1,
	}
	return applicationlifecycle.Result{
		Deployment: deployment,
		Operation:  testOperation("Deployment", command.DeploymentID, paasv1.OperationDeploy, paasv1.OperationAccepted),
	}, nil
}

func (workflow *fakeWorkflow) Rollback(
	_ context.Context,
	command applicationlifecycle.RollbackCommand,
) (applicationlifecycle.Result, error) {
	workflow.rollbackCalls++
	workflow.rollbackCommand = command
	deployment := paasv1.Deployment{
		Metadata: testMetadata(command.DeploymentID, "deployment-a"), Generation: 3,
	}
	return applicationlifecycle.Result{
		Deployment: deployment,
		Operation:  testOperation("Deployment", command.DeploymentID, paasv1.OperationRollback, paasv1.OperationAccepted),
	}, nil
}

func (workflow *fakeWorkflow) GetApplication(
	_ context.Context,
	authorization port.Authorization,
	id paasv1.ResourceID,
) (paasv1.Application, error) {
	workflow.getApplicationCalls++
	workflow.readAuthorization, workflow.readID = authorization, id
	return paasv1.Application{
		APIVersion: paasv1.APIVersion, Kind: "Application", Metadata: testMetadata(id, "application-a"),
	}, nil
}

func (workflow *fakeWorkflow) GetConfiguration(context.Context, port.Authorization, paasv1.ResourceID) (paasv1.Configuration, error) {
	return paasv1.Configuration{}, errors.New("unexpected GetConfiguration")
}

func (workflow *fakeWorkflow) GetConfigurationRevision(context.Context, port.Authorization, paasv1.ResourceID) (paasv1.ConfigurationRevision, error) {
	return paasv1.ConfigurationRevision{}, errors.New("unexpected GetConfigurationRevision")
}

func (workflow *fakeWorkflow) GetApplicationRevision(context.Context, port.Authorization, paasv1.ResourceID) (paasv1.ApplicationRevision, error) {
	return paasv1.ApplicationRevision{}, errors.New("unexpected GetApplicationRevision")
}

func (workflow *fakeWorkflow) GetDeployment(context.Context, port.Authorization, paasv1.ResourceID) (paasv1.Deployment, error) {
	return paasv1.Deployment{}, errors.New("unexpected GetDeployment")
}

func (workflow *fakeWorkflow) ListDeployments(
	_ context.Context,
	authorization port.Authorization,
	after paasv1.ResourceID,
) (paasv1.DeploymentList, error) {
	workflow.listDeploymentsCalls++
	workflow.readAuthorization = authorization
	workflow.listAfter = after
	return workflow.deploymentList, nil
}

func (workflow *fakeWorkflow) GetDeploymentRuntime(
	_ context.Context,
	authorization port.Authorization,
	id paasv1.ResourceID,
) (paasv1.DeploymentRuntimeSnapshot, error) {
	workflow.runtimeCalls++
	workflow.readAuthorization, workflow.readID = authorization, id
	return workflow.runtimeSnapshot, nil
}

func (workflow *fakeWorkflow) GetDeploymentGeneration(context.Context, port.Authorization, paasv1.ResourceID, uint64) (paasv1.DeploymentGeneration, error) {
	return paasv1.DeploymentGeneration{}, errors.New("unexpected GetDeploymentGeneration")
}

func (workflow *fakeWorkflow) GetOperation(context.Context, port.Authorization, paasv1.OperationID) (paasv1.Operation, error) {
	return paasv1.Operation{}, errors.New("unexpected GetOperation")
}

func mustHandler(t *testing.T, authorizer port.Authorizer, workflow Workflow) http.Handler {
	return mustHandlerWithVerifier(t, authorizer, workflow, &fakeInstallationVerifier{})
}

func mustHandlerWithVerifier(
	t *testing.T,
	authorizer port.Authorizer,
	workflow Workflow,
	verifier InstallationVerifier,
) http.Handler {
	t.Helper()
	handler, err := NewHandler(authorizer, workflow, &fakeExecutionWorkflow{}, verifier, Config{
		NewRequestID: func() (string, error) { return "request-test", nil },
		Readiness: func(context.Context) (paasv1.Readiness, error) {
			return paasv1.Readiness{
				APIVersion: paasv1.APIVersion, Kind: "Readiness", State: paasv1.ReadinessReady,
				SchemaVersion: 1, CheckedAt: time.Date(2026, 8, 26, 3, 4, 5, 0, time.UTC),
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("create HTTP handler: %v", err)
	}
	return handler
}

func jsonRequest(t *testing.T, method, target string, value any) *http.Request {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("encode request: %v", err)
	}
	request := httptest.NewRequest(method, target, bytes.NewReader(encoded))
	request.Header.Set("Content-Type", "application/json")
	return request
}

func testMetadata(id paasv1.ResourceID, name string) paasv1.ResourceMetadata {
	now := time.Date(2026, 8, 25, 18, 0, 0, 0, time.UTC)
	return paasv1.ResourceMetadata{
		ID: id, Name: name,
		Scope:           paasv1.ResourceScope{Kind: paasv1.AuthorityTenant, TenantID: "tenant-authorized"},
		ResourceVersion: 1, CreatedAt: now, UpdatedAt: now,
	}
}

type fakeExecutionWorkflow struct {
	createCommand     executionadmission.CreatePoolCommand
	registerCommand   executionadmission.RegisterTargetCommand
	listAuthorization port.Authorization
	listResult        paasv1.ExecutionTargetList
	createCalls       int
	registerCalls     int
	listCalls         int
}

func (workflow *fakeExecutionWorkflow) CreatePool(_ context.Context, command executionadmission.CreatePoolCommand) (paasv1.ExecutionPool, paasv1.Operation, bool, error) {
	workflow.createCommand, workflow.createCalls = command, workflow.createCalls+1
	operation := testOperation("ExecutionPool", command.Request.ID, paasv1.OperationCreateExecutionPool, paasv1.OperationSucceeded)
	operation.Scope, operation.InstallationID = paasv1.ResourceScope{Kind: paasv1.AuthorityPlatform}, command.Authorization.InstallationID
	return paasv1.ExecutionPool{Metadata: testMetadata(command.Request.ID, command.Request.Name)}, operation, false, nil
}

func (workflow *fakeExecutionWorkflow) RegisterTarget(_ context.Context, command executionadmission.RegisterTargetCommand) (paasv1.ExecutionTarget, paasv1.Operation, bool, error) {
	workflow.registerCommand, workflow.registerCalls = command, workflow.registerCalls+1
	operation := testOperation("ExecutionTarget", command.Request.ID, paasv1.OperationRegisterExecutionTarget, paasv1.OperationSucceeded)
	operation.Scope, operation.InstallationID = paasv1.ResourceScope{Kind: paasv1.AuthorityPlatform}, command.Authorization.InstallationID
	return paasv1.ExecutionTarget{Metadata: testMetadata(command.Request.ID, command.Request.Name)}, operation, false, nil
}

func (*fakeExecutionWorkflow) GetPool(context.Context, port.Authorization, paasv1.ResourceID) (paasv1.ExecutionPool, error) {
	return paasv1.ExecutionPool{}, executionadmission.ErrNotFound
}
func (*fakeExecutionWorkflow) GetTarget(context.Context, port.Authorization, paasv1.ResourceID) (paasv1.ExecutionTarget, error) {
	return paasv1.ExecutionTarget{}, executionadmission.ErrNotFound
}
func (workflow *fakeExecutionWorkflow) ListTargets(_ context.Context, authorization port.Authorization) (paasv1.ExecutionTargetList, error) {
	workflow.listAuthorization, workflow.listCalls = authorization, workflow.listCalls+1
	if workflow.listResult.Items == nil {
		return paasv1.ExecutionTargetList{
			APIVersion: paasv1.APIVersion,
			Kind:       "ExecutionTargetList",
			Items:      []paasv1.ExecutionTarget{},
		}, nil
	}
	return workflow.listResult, nil
}
func (*fakeExecutionWorkflow) GetOperation(context.Context, port.Authorization, paasv1.OperationID) (paasv1.Operation, error) {
	return paasv1.Operation{}, executionadmission.ErrNotFound
}

func testOperation(
	targetKind string,
	targetID paasv1.ResourceID,
	action paasv1.OperationAction,
	state paasv1.OperationState,
) paasv1.Operation {
	now := time.Date(2026, 8, 25, 18, 0, 0, 0, time.UTC)
	operation := paasv1.Operation{
		APIVersion: paasv1.APIVersion, Kind: "Operation", ID: "operation-a",
		Scope:  paasv1.ResourceScope{Kind: paasv1.AuthorityTenant, TenantID: "tenant-authorized"},
		Action: action, Target: paasv1.ResourceRef{Kind: targetKind, ID: targetID},
		RequestedBy:            paasv1.SubjectRef{Type: paasv1.SubjectUser, ID: "user-authorized"},
		IdempotencyFingerprint: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		RequestDigest:          "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		State:                  state, Attempt: 1, CreatedAt: now, UpdatedAt: now,
	}
	if terminalOperation(state) {
		operation.TerminalAt = &now
	}
	return operation
}
