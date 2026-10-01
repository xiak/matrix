package nethttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/internal/externalrequest"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/port"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/applicationlifecycle"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/verifyinstallation"
)

func TestHandlerReadinessIsOperationalAndSanitized(t *testing.T) {
	readyErr := error(nil)
	readiness := paasv1.Readiness{
		APIVersion: paasv1.APIVersion, Kind: "Readiness", State: paasv1.ReadinessReady,
		SchemaVersion: 1, CheckedAt: time.Date(2026, 8, 26, 3, 4, 5, 678_000, time.UTC),
	}
	handler, err := NewHandler(&fakeAuthorizer{}, &fakeWorkflow{}, &fakeInstallationVerifier{}, Config{
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
	if !reflect.DeepEqual(authorizer.request, port.AuthorizationRequest{}) {
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
		authorizer.request.Credential != "Bearer opaque-credential" || authorizer.request.SourceIP != "192.0.2.1" {
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

func TestHandlerBindsOnlyDeclaredApplicationLabelsBeforeIAM(t *testing.T) {
	authorizer := &fakeAuthorizer{}
	workflow := &fakeWorkflow{}
	handler := mustHandler(t, authorizer, workflow)
	body := paasv1.CreateApplicationRequest{ID: "application-tags", Name: "application-tags", Labels: map[string]string{
		"environment": "production", "team": "payments", "1-metadata": "retained",
	}}
	request := jsonRequest(t, http.MethodPost, "/v1/applications", body)
	request.Header.Set("Authorization", "Bearer opaque-credential")
	request.Header.Set("Idempotency-Key", "create-application-tags")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated || workflow.createApplicationCalls != 1 {
		t.Fatalf("status=%d calls=%d body=%s", response.Code, workflow.createApplicationCalls, response.Body.String())
	}
	if !reflect.DeepEqual(authorizer.request.RequestLabels, body.Labels) {
		t.Fatalf("PEP did not bind the complete validated product label set: %#v", authorizer.request.RequestLabels)
	}
	expected := []iamv1.AuthorizationTag{{Key: "environment", Value: "production"}}
	if !reflect.DeepEqual(workflow.createApplicationCommand.Authorization.RequestTags, expected) ||
		!reflect.DeepEqual(workflow.createApplicationCommand.Request.Labels, body.Labels) {
		t.Fatalf("declared authorization tags or product labels changed: %#v", workflow.createApplicationCommand)
	}

	invalid := jsonRequest(t, http.MethodPost, "/v1/applications", paasv1.CreateApplicationRequest{
		ID: "application-invalid-tags", Name: "application-invalid-tags", Labels: map[string]string{"environment": " production"},
	})
	invalid.Header.Set("Authorization", "Bearer opaque-credential")
	invalid.Header.Set("Idempotency-Key", "create-application-invalid-tags")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, invalid)
	if response.Code != http.StatusBadRequest || workflow.createApplicationCalls != 1 {
		t.Fatalf("invalid label reached IAM/workflow: status=%d calls=%d", response.Code, workflow.createApplicationCalls)
	}
}

func TestHandlerCreatesApplicationThroughExactAccessKeyBoundary(t *testing.T) {
	authorizer := &fakeAuthorizer{}
	workflow := &fakeWorkflow{}
	handler := mustAccessKeyHandler(t, authorizer, workflow)
	body := paasv1.CreateApplicationRequest{ID: "application-key", Name: "application-key", Labels: map[string]string{
		"environment": "production", "team": "payments",
	}}
	request := jsonRequest(t, http.MethodPost, "/v1/applications", body)
	request.Header.Set("Idempotency-Key", "create-application-key")
	setAccessKeyEdgeHeaders(t, request, "/api/paas/v1/applications")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("AccessKey create status=%d body=%s", response.Code, response.Body.String())
	}
	if authorizer.accessKeyCalls != 1 || authorizer.authorizeCalls != 0 || workflow.createApplicationCalls != 1 {
		t.Fatalf("AccessKey boundary calls key=%d bearer=%d workflow=%d", authorizer.accessKeyCalls, authorizer.authorizeCalls, workflow.createApplicationCalls)
	}
	signed := authorizer.accessKeyRequest.SignedRequest
	if signed.Parameters.AccessKeyID != "key-one" || signed.Parameters.InstallationID != "installation-one" ||
		signed.Parameters.Audience != iamv1.ProductPaaS || signed.HTTP.Method != http.MethodPost ||
		signed.HTTP.Scheme != "https" || signed.HTTP.Authority != "api.example.test:443" ||
		signed.HTTP.EscapedPath != "/api/paas/v1/applications" || signed.HTTP.RawQuery != "" ||
		signed.HTTP.ContentType != "application/json" || signed.HTTP.IdempotencyKey != "create-application-key" {
		t.Fatalf("reconstructed signed request=%#v parameters=%#v", signed.HTTP, signed.Parameters)
	}
	if authorizer.accessKeyRequest.Action != port.AuthorizeApplicationCreate ||
		authorizer.accessKeyRequest.Resource != (paasv1.ResourceRef{Kind: "Application", ID: "collection"}) ||
		authorizer.accessKeyRequest.SourceIP != "192.0.2.1" ||
		!reflect.DeepEqual(authorizer.accessKeyRequest.RequestLabels, body.Labels) ||
		!reflect.DeepEqual(workflow.createApplicationCommand.Request, body) ||
		workflow.createApplicationCommand.Authorization.Subject.AccessKeyID != "key-one" {
		t.Fatalf("AccessKey PEP or workflow binding changed: request=%#v command=%#v", authorizer.accessKeyRequest, workflow.createApplicationCommand)
	}
	var operation paasv1.Operation
	if json.NewDecoder(response.Body).Decode(&operation) != nil ||
		!operation.RequestedBy.Equal(paasv1.SubjectRef{Type: paasv1.SubjectUser, ID: "user-authorized", AccessKeyID: "key-one"}) {
		t.Fatalf("AccessKey Operation attribution=%#v", operation.RequestedBy)
	}
}

func TestHandlerMapsSignedImmutableResourceGraphRoutesToExactActions(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	tests := []struct {
		name, internalPath, externalPath string
		body                             any
		action                           iamv1.Action
		resourceKind                     string
		status                           int
		calls                            func(*fakeWorkflow) int
	}{
		{
			name: "configuration", internalPath: "/v1/configurations", externalPath: "/api/paas/v1/configurations",
			body:   paasv1.CreateConfigurationRequest{ID: "configuration-key", Name: "configuration-key", ApplicationID: "application-key"},
			action: port.AuthorizeConfigurationCreate, resourceKind: port.ResourceConfiguration, status: http.StatusCreated,
			calls: func(workflow *fakeWorkflow) int { return workflow.createConfigurationCalls },
		},
		{
			name: "configuration revision", internalPath: "/v1/configuration-revisions", externalPath: "/api/paas/v1/configuration-revisions",
			body: paasv1.CreateConfigurationRevisionRequest{ID: "configuration-revision-key", Name: "configuration-revision-key",
				Spec: paasv1.ConfigurationRevisionSpec{ConfigurationID: "configuration-key", Values: map[string]string{"PORT": "8080"}, ContentDigest: digest}},
			action: port.AuthorizeConfigurationRevisionCreate, resourceKind: port.ResourceConfigurationRevision, status: http.StatusCreated,
			calls: func(workflow *fakeWorkflow) int { return workflow.createConfigurationRevisionCalls },
		},
		{
			name: "application revision", internalPath: "/v1/application-revisions", externalPath: "/api/paas/v1/application-revisions",
			body: paasv1.CreateApplicationRevisionRequest{ID: "application-revision-key", Name: "application-revision-key",
				Spec: paasv1.ApplicationRevisionSpec{ApplicationID: "application-key", Revision: "v1", ContentDigest: digest}},
			action: port.AuthorizeApplicationRevisionCreate, resourceKind: port.ResourceApplicationRevision, status: http.StatusCreated,
			calls: func(workflow *fakeWorkflow) int { return workflow.createApplicationRevisionCalls },
		},
		{
			name: "deployment", internalPath: "/v1/deployments", externalPath: "/api/paas/v1/deployments",
			body: paasv1.CreateDeploymentRequest{ID: "deployment-key", Name: "deployment-key", Spec: paasv1.DeploymentSpec{
				ApplicationRevisionID: "application-revision-key", PlacementPolicyID: "placement-key",
				DesiredState: paasv1.DeploymentDesiredRunning, Components: []paasv1.DeploymentComponent{{Name: "api", Replicas: 1}}}},
			action: port.AuthorizeDeploymentCreate, resourceKind: port.ResourceDeployment, status: http.StatusAccepted,
			calls: func(workflow *fakeWorkflow) int { return workflow.submitCalls },
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			authorizer := &fakeAuthorizer{}
			workflow := &fakeWorkflow{}
			handler := mustAccessKeyHandler(t, authorizer, workflow)
			request := jsonRequest(t, http.MethodPost, test.internalPath, test.body)
			request.Header.Set("Idempotency-Key", "create-"+strings.ReplaceAll(test.name, " ", "-"))
			setAccessKeyEdgeHeaders(t, request, test.externalPath)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status || authorizer.accessKeyCalls != 1 || authorizer.authorizeCalls != 0 || test.calls(workflow) != 1 {
				t.Fatalf("signed route status=%d key=%d bearer=%d workflow=%d body=%s",
					response.Code, authorizer.accessKeyCalls, authorizer.authorizeCalls, test.calls(workflow), response.Body.String())
			}
			if authorizer.accessKeyRequest.Action != test.action ||
				authorizer.accessKeyRequest.Resource != (paasv1.ResourceRef{Kind: test.resourceKind, ID: "collection"}) ||
				authorizer.accessKeyRequest.SignedRequest.HTTP.EscapedPath != test.externalPath {
				t.Fatalf("signed route mapped to %#v", authorizer.accessKeyRequest)
			}
			var operation paasv1.Operation
			if json.NewDecoder(response.Body).Decode(&operation) != nil ||
				!operation.RequestedBy.Equal(paasv1.SubjectRef{Type: paasv1.SubjectUser, ID: "user-authorized", AccessKeyID: "key-one"}) {
				t.Fatalf("signed route Operation attribution=%#v", operation.RequestedBy)
			}
		})
	}
}

func TestHandlerControlsDeploymentThroughExactAccessKeyBoundary(t *testing.T) {
	tests := []struct {
		name, method, internalPath, externalPath string
		body                                     any
		action                                   iamv1.Action
		workflowCalls                            func(*fakeWorkflow) int
		commandAuthorization                     func(*fakeWorkflow) port.Authorization
	}{
		{
			name: "update", method: http.MethodPut,
			internalPath: "/v1/deployments/deployment-key", externalPath: "/api/paas/v1/deployments/deployment-key",
			body: paasv1.DeploymentSpec{ApplicationRevisionID: "application-revision-key", PlacementPolicyID: "placement-key",
				DesiredState: paasv1.DeploymentDesiredRunning, Components: []paasv1.DeploymentComponent{{Name: "api", Replicas: 2}}},
			action:               port.AuthorizeDeploymentUpdate,
			workflowCalls:        func(workflow *fakeWorkflow) int { return workflow.submitCalls },
			commandAuthorization: func(workflow *fakeWorkflow) port.Authorization { return workflow.submitCommand.Authorization },
		},
		{
			name: "stop", method: http.MethodPut,
			internalPath: "/v1/deployments/deployment-key", externalPath: "/api/paas/v1/deployments/deployment-key",
			body: paasv1.DeploymentSpec{ApplicationRevisionID: "application-revision-key", PlacementPolicyID: "placement-key",
				DesiredState: paasv1.DeploymentDesiredStopped, Components: []paasv1.DeploymentComponent{{Name: "api", Replicas: 1}}},
			action:               port.AuthorizeDeploymentStop,
			workflowCalls:        func(workflow *fakeWorkflow) int { return workflow.submitCalls },
			commandAuthorization: func(workflow *fakeWorkflow) port.Authorization { return workflow.submitCommand.Authorization },
		},
		{
			name: "rollback", method: http.MethodPost,
			internalPath: "/v1/deployments/deployment-key/rollback", externalPath: "/api/paas/v1/deployments/deployment-key/rollback",
			body: paasv1.RollbackDeploymentRequest{SourceGeneration: 2}, action: port.AuthorizeDeploymentRollback,
			workflowCalls:        func(workflow *fakeWorkflow) int { return workflow.rollbackCalls },
			commandAuthorization: func(workflow *fakeWorkflow) port.Authorization { return workflow.rollbackCommand.Authorization },
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			authorizer := &fakeAuthorizer{}
			workflow := &fakeWorkflow{}
			handler := mustAccessKeyHandler(t, authorizer, workflow)
			request := jsonRequest(t, test.method, test.internalPath, test.body)
			request.Header.Set("Idempotency-Key", test.name+"-deployment-key")
			request.Header.Set("If-Match", `"7"`)
			setAccessKeyEdgeHeaders(t, request, test.externalPath)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusAccepted || authorizer.accessKeyCalls != 1 || authorizer.authorizeCalls != 0 || test.workflowCalls(workflow) != 1 {
				t.Fatalf("signed mutation status=%d key=%d bearer=%d workflow=%d body=%s",
					response.Code, authorizer.accessKeyCalls, authorizer.authorizeCalls, test.workflowCalls(workflow), response.Body.String())
			}
			if authorizer.accessKeyRequest.Action != test.action ||
				authorizer.accessKeyRequest.Resource != (paasv1.ResourceRef{Kind: port.ResourceDeployment, ID: "deployment-key"}) ||
				authorizer.accessKeyRequest.SignedRequest.HTTP.Method != test.method ||
				authorizer.accessKeyRequest.SignedRequest.HTTP.EscapedPath != test.externalPath ||
				authorizer.accessKeyRequest.SignedRequest.HTTP.IfMatch != `"7"` ||
				authorizer.accessKeyRequest.SignedRequest.HTTP.IdempotencyKey != test.name+"-deployment-key" {
				t.Fatalf("signed mutation mapped to %#v", authorizer.accessKeyRequest)
			}
			if !test.commandAuthorization(workflow).Subject.Equal(paasv1.SubjectRef{
				Type: paasv1.SubjectUser, ID: "user-authorized", AccessKeyID: "key-one",
			}) {
				t.Fatalf("signed mutation lost AccessKey attribution: %#v", test.commandAuthorization(workflow))
			}
		})
	}
}

func TestHandlerKeepsAccessKeyAdmissionClosedAndMapsNonceReplay(t *testing.T) {
	t.Run("route outside closed mapping", func(t *testing.T) {
		authorizer := &fakeAuthorizer{}
		workflow := &fakeWorkflow{}
		handler := mustAccessKeyHandler(t, authorizer, workflow)
		request := httptest.NewRequest(http.MethodGet, "/v1/applications", nil)
		setAccessKeyEdgeHeaders(t, request, "/api/paas/v1/configurations/configuration-a")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized || authorizer.accessKeyCalls != 0 ||
			authorizer.authorizeCalls != 0 || workflow.getApplicationCalls != 0 {
			t.Fatalf("closed AccessKey route status=%d key=%d bearer=%d workflow=%d body=%s",
				response.Code, authorizer.accessKeyCalls, authorizer.authorizeCalls, workflow.getApplicationCalls, response.Body.String())
		}
	})

	t.Run("consumed nonce", func(t *testing.T) {
		authorizer := &fakeAuthorizer{accessKeyErr: port.ErrAuthorizationReplay}
		workflow := &fakeWorkflow{}
		handler := mustAccessKeyHandler(t, authorizer, workflow)
		request := jsonRequest(t, http.MethodPost, "/v1/applications", paasv1.CreateApplicationRequest{
			ID: "application-replay", Name: "application-replay",
		})
		request.Header.Set("Idempotency-Key", "create-application-replay")
		setAccessKeyEdgeHeaders(t, request, "/api/paas/v1/applications")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusConflict || authorizer.accessKeyCalls != 1 || workflow.createApplicationCalls != 0 {
			t.Fatalf("AccessKey replay status=%d calls=%d workflow=%d body=%s",
				response.Code, authorizer.accessKeyCalls, workflow.createApplicationCalls, response.Body.String())
		}
	})
}

func TestAccessKeyRouteAdmissionIsAnExactClosedMap(t *testing.T) {
	for _, test := range []struct {
		method  string
		path    string
		actions []iamv1.Action
	}{
		{http.MethodGet, "/v1/applications/application-a", []iamv1.Action{port.AuthorizeApplicationRead}},
		{http.MethodGet, "/v1/configurations/configuration-a", []iamv1.Action{port.AuthorizeConfigurationRead}},
		{http.MethodGet, "/v1/configuration-revisions/configuration-revision-a", []iamv1.Action{port.AuthorizeConfigurationRevisionRead}},
		{http.MethodGet, "/v1/application-revisions/application-revision-a", []iamv1.Action{port.AuthorizeApplicationRevisionRead}},
		{http.MethodGet, "/v1/deployments/deployment-a", []iamv1.Action{port.AuthorizeDeploymentRead}},
		{http.MethodGet, "/v1/deployments/deployment-a/generations/1", []iamv1.Action{port.AuthorizeDeploymentRead}},
		{http.MethodGet, "/v1/deployments/deployment-a/generations/9007199254740991", []iamv1.Action{port.AuthorizeDeploymentRead}},
		{http.MethodGet, "/v1/operations/operation-a", []iamv1.Action{port.AuthorizeOperationRead}},
		{http.MethodPut, "/v1/deployments/deployment-a", []iamv1.Action{port.AuthorizeDeploymentUpdate, port.AuthorizeDeploymentStop}},
		{http.MethodPost, "/v1/deployments/deployment-a/rollback", []iamv1.Action{port.AuthorizeDeploymentRollback}},
		{http.MethodPut, "/v1/applications/application-a/labels/environment", []iamv1.Action{port.AuthorizeApplicationLabelSet}},
		{http.MethodDelete, "/v1/applications/application-a/labels/environment", []iamv1.Action{port.AuthorizeApplicationLabelDelete}},
	} {
		actions, admitted := accessKeyActionsForRoute(test.method, test.path)
		if !admitted || !reflect.DeepEqual(actions, test.actions) {
			t.Fatalf("declared route %s %s mapped to %v admitted=%v", test.method, test.path, actions, admitted)
		}
	}
	for _, test := range []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/v1/applications"},
		{http.MethodGet, "/v1/configurations/configuration-a/extra"},
		{http.MethodGet, "/v1/deployments/deployment-a/generations/0"},
		{http.MethodGet, "/v1/deployments/deployment-a/generations/9007199254740992"},
		{http.MethodGet, "/v1/deployments/deployment-a/generations/not-a-number"},
		{http.MethodGet, "/v1/deployments/deployment-a/generations/1/extra"},
		{http.MethodGet, "/v1/platform-operations/operation-a"},
		{http.MethodPost, "/v1/operations/operation-a"},
		{http.MethodPut, "/v1/deployments"},
		{http.MethodPut, "/v1/deployments/deployment-a/extra"},
		{http.MethodPost, "/v1/deployments/deployment-a/rollback/extra"},
		{http.MethodDelete, "/v1/deployments/deployment-a"},
		{http.MethodPut, "/v1/applications/application-a/labels/team"},
		{http.MethodDelete, "/v1/applications/application-a/labels/team"},
		{http.MethodPut, "/v1/applications/application-a/labels/environment/extra"},
	} {
		if actions, admitted := accessKeyActionsForRoute(test.method, test.path); admitted || actions != nil {
			t.Fatalf("undeclared route %s %s mapped to %v", test.method, test.path, actions)
		}
	}
}

func TestHandlerReadsExactApplicationThroughAccessKeySubjectResolution(t *testing.T) {
	labels := map[string]string{"environment": "production", "team": "payments"}
	metadata := testMetadata("application-key", "application-key")
	metadata.Labels = labels
	resource := paasv1.Application{APIVersion: paasv1.APIVersion, Kind: "Application", Metadata: metadata}
	authorizer := &fakeAuthorizer{}
	workflow := &fakeWorkflow{
		inspectSnapshot: &applicationlifecycle.ApplicationAuthorizationSnapshot{
			ID: metadata.ID, ResourceVersion: metadata.ResourceVersion, Labels: labels,
		},
		getApplicationResult: &resource,
	}
	handler := mustAccessKeyHandler(t, authorizer, workflow)
	request := httptest.NewRequest(http.MethodGet, "/v1/applications/application-key", nil)
	setAccessKeyEdgeHeaders(t, request, "/api/paas/v1/applications/application-key")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || authorizer.keyResolveCalls != 1 || authorizer.resolveCalls != 0 ||
		authorizer.accessKeyCalls != 1 || authorizer.authorizeCalls != 0 ||
		workflow.inspectApplicationCalls != 1 || workflow.getApplicationCalls != 1 {
		t.Fatalf("signed read status=%d key-resolve=%d bearer-resolve=%d key-authorize=%d bearer-authorize=%d inspect=%d get=%d body=%s",
			response.Code, authorizer.keyResolveCalls, authorizer.resolveCalls, authorizer.accessKeyCalls,
			authorizer.authorizeCalls, workflow.inspectApplicationCalls, workflow.getApplicationCalls, response.Body.String())
	}
	if authorizer.accessKeyRequest.Action != port.AuthorizeApplicationRead ||
		authorizer.accessKeyRequest.Resource != (paasv1.ResourceRef{Kind: port.ResourceApplication, ID: "application-key"}) ||
		authorizer.accessKeyRequest.SignedRequest.HTTP.Method != http.MethodGet ||
		authorizer.accessKeyRequest.SignedRequest.HTTP.EscapedPath != "/api/paas/v1/applications/application-key" ||
		!reflect.DeepEqual(authorizer.accessKeyRequest.ResourceLabels, labels) ||
		!workflow.readAuthorization.Subject.Equal(paasv1.SubjectRef{Type: paasv1.SubjectUser, ID: "user-authorized", AccessKeyID: "key-one"}) {
		t.Fatalf("signed read binding changed: request=%#v authorization=%#v", authorizer.accessKeyRequest, workflow.readAuthorization)
	}
	var got paasv1.Application
	if json.NewDecoder(response.Body).Decode(&got) != nil || got.Metadata.ID != metadata.ID || !reflect.DeepEqual(got.Metadata.Labels, labels) {
		t.Fatalf("signed read resource=%#v", got)
	}

	t.Run("body is rejected before IAM", func(t *testing.T) {
		authorizer := &fakeAuthorizer{}
		workflow := &fakeWorkflow{}
		handler := mustAccessKeyHandler(t, authorizer, workflow)
		request := httptest.NewRequest(http.MethodGet, "/v1/applications/application-key", strings.NewReader("{}"))
		request.Header.Set("Content-Type", "application/json")
		setAccessKeyEdgeHeaders(t, request, "/api/paas/v1/applications/application-key")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest || authorizer.keyResolveCalls != 0 || authorizer.accessKeyCalls != 0 ||
			workflow.inspectApplicationCalls != 0 || workflow.getApplicationCalls != 0 {
			t.Fatalf("signed read body reached authority: status=%d resolve=%d authorize=%d inspect=%d get=%d",
				response.Code, authorizer.keyResolveCalls, authorizer.accessKeyCalls, workflow.inspectApplicationCalls, workflow.getApplicationCalls)
		}
	})

	t.Run("subject resolution fails closed", func(t *testing.T) {
		authorizer := &fakeAuthorizer{resolveErr: port.ErrAuthorizationUnavailable}
		workflow := &fakeWorkflow{}
		handler := mustAccessKeyHandler(t, authorizer, workflow)
		request := httptest.NewRequest(http.MethodGet, "/v1/applications/application-key", nil)
		setAccessKeyEdgeHeaders(t, request, "/api/paas/v1/applications/application-key")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusServiceUnavailable || authorizer.keyResolveCalls != 1 || authorizer.accessKeyCalls != 0 ||
			workflow.inspectApplicationCalls != 0 || workflow.getApplicationCalls != 0 {
			t.Fatalf("failed subject resolution leaked work: status=%d resolve=%d authorize=%d inspect=%d get=%d",
				response.Code, authorizer.keyResolveCalls, authorizer.accessKeyCalls, workflow.inspectApplicationCalls, workflow.getApplicationCalls)
		}
	})

	t.Run("final decision cannot switch subject", func(t *testing.T) {
		authorizer := &fakeAuthorizer{accessKeyResult: &port.Authorization{
			TenantID: "other-account", Subject: paasv1.SubjectRef{Type: paasv1.SubjectUser, ID: "other-user", AccessKeyID: "key-one"},
			DecisionID: "decision-other", RequestID: "request-test",
		}}
		workflow := &fakeWorkflow{inspectSnapshot: &applicationlifecycle.ApplicationAuthorizationSnapshot{
			ID: metadata.ID, ResourceVersion: metadata.ResourceVersion, Labels: labels,
		}}
		handler := mustAccessKeyHandler(t, authorizer, workflow)
		request := httptest.NewRequest(http.MethodGet, "/v1/applications/application-key", nil)
		setAccessKeyEdgeHeaders(t, request, "/api/paas/v1/applications/application-key")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusServiceUnavailable || authorizer.keyResolveCalls != 1 || authorizer.accessKeyCalls != 1 ||
			workflow.inspectApplicationCalls != 1 || workflow.getApplicationCalls != 0 {
			t.Fatalf("subject substitution reached resource: status=%d resolve=%d authorize=%d inspect=%d get=%d",
				response.Code, authorizer.keyResolveCalls, authorizer.accessKeyCalls, workflow.inspectApplicationCalls, workflow.getApplicationCalls)
		}
	})
}

func TestHandlerMutatesApplicationLabelsWithCurrentAndRequestedEvidence(t *testing.T) {
	authorizer := &fakeAuthorizer{}
	workflow := &fakeWorkflow{inspectSnapshot: &applicationlifecycle.ApplicationAuthorizationSnapshot{
		ID: "application-labels", ResourceVersion: 7,
		Labels: map[string]string{"environment": "production", "team": "platform"},
	}}
	handler := mustHandler(t, authorizer, workflow)

	set := jsonRequest(t, http.MethodPut, "/v1/applications/application-labels/labels/environment",
		paasv1.SetApplicationLabelRequest{Value: "staging"})
	set.Header.Set("Authorization", "Bearer opaque-credential")
	set.Header.Set("Idempotency-Key", "set-application-environment")
	set.Header.Set("If-Match", `"7"`)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, set)
	if response.Code != http.StatusOK || workflow.setApplicationLabelCalls != 1 ||
		workflow.setApplicationLabel.ApplicationID != "application-labels" ||
		workflow.setApplicationLabel.LabelKey != "environment" || workflow.setApplicationLabel.Value != "staging" ||
		workflow.setApplicationLabel.ExpectedResourceVersion != 7 ||
		workflow.setApplicationLabel.IdempotencyKey != "set-application-environment" {
		t.Fatalf("set label status=%d command=%#v body=%s", response.Code, workflow.setApplicationLabel, response.Body.String())
	}
	if authorizer.request.Action != port.AuthorizeApplicationLabelSet ||
		!reflect.DeepEqual(authorizer.request.ResourceLabels, workflow.inspectSnapshot.Labels) ||
		!reflect.DeepEqual(authorizer.request.RequestLabels, map[string]string{"environment": "staging"}) ||
		!reflect.DeepEqual(workflow.setApplicationLabel.Authorization.ResourceTags, []iamv1.AuthorizationTag{{Key: "environment", Value: "production"}}) ||
		!reflect.DeepEqual(workflow.setApplicationLabel.Authorization.RequestTags, []iamv1.AuthorizationTag{{Key: "environment", Value: "staging"}}) {
		t.Fatalf("set label authorization request=%#v command=%#v", authorizer.request, workflow.setApplicationLabel)
	}
	if response.Header().Get("ETag") != `"8"` || response.Header().Get("Location") != "/v1/applications/application-labels" {
		t.Fatalf("set label response headers=%#v", response.Header())
	}

	workflow.inspectSnapshot.ResourceVersion = 8
	workflow.inspectSnapshot.Labels["environment"] = "staging"
	deleteRequest := httptest.NewRequest(http.MethodDelete, "/v1/applications/application-labels/labels/environment", nil)
	deleteRequest.Header.Set("Authorization", "Bearer opaque-credential")
	deleteRequest.Header.Set("Idempotency-Key", "delete-application-environment")
	deleteRequest.Header.Set("If-Match", `"8"`)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, deleteRequest)
	if response.Code != http.StatusOK || workflow.deleteApplicationLabelCalls != 1 ||
		workflow.deleteApplicationLabel.ExpectedResourceVersion != 8 ||
		authorizer.request.Action != port.AuthorizeApplicationLabelDelete ||
		!reflect.DeepEqual(authorizer.request.RequestLabels, map[string]string{"environment": "staging"}) ||
		!reflect.DeepEqual(workflow.deleteApplicationLabel.Authorization.RequestTags, []iamv1.AuthorizationTag{{Key: "environment", Value: "staging"}}) {
		t.Fatalf("delete label status=%d request=%#v command=%#v body=%s", response.Code, authorizer.request, workflow.deleteApplicationLabel, response.Body.String())
	}
}

func TestHandlerMutatesApplicationLabelsThroughExactAccessKeyBoundary(t *testing.T) {
	for _, test := range []struct {
		name, method, value string
		action              iamv1.Action
		requestTags         []iamv1.AuthorizationTag
	}{
		{name: "set", method: http.MethodPut, value: "staging", action: port.AuthorizeApplicationLabelSet,
			requestTags: []iamv1.AuthorizationTag{{Key: "environment", Value: "staging"}}},
		{name: "delete", method: http.MethodDelete, action: port.AuthorizeApplicationLabelDelete,
			requestTags: []iamv1.AuthorizationTag{{Key: "environment", Value: "production"}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			authorizer := &fakeAuthorizer{}
			workflow := &fakeWorkflow{inspectSnapshot: &applicationlifecycle.ApplicationAuthorizationSnapshot{
				ID: "application-label-key", ResourceVersion: 7,
				Labels: map[string]string{"environment": "production", "team": "platform"},
			}}
			handler := mustAccessKeyHandler(t, authorizer, workflow)
			internalPath := "/v1/applications/application-label-key/labels/environment"
			var request *http.Request
			if test.method == http.MethodPut {
				request = jsonRequest(t, test.method, internalPath, paasv1.SetApplicationLabelRequest{Value: test.value})
			} else {
				request = httptest.NewRequest(test.method, internalPath, nil)
			}
			request.Header.Set("Idempotency-Key", test.name+"-application-label-key")
			request.Header.Set("If-Match", `"7"`)
			externalPath := "/api/paas" + internalPath
			setAccessKeyEdgeHeaders(t, request, externalPath)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusOK || authorizer.keyResolveCalls != 1 || authorizer.resolveCalls != 0 ||
				authorizer.accessKeyCalls != 1 || authorizer.authorizeCalls != 0 {
				t.Fatalf("signed label %s status=%d keyResolve=%d bearerResolve=%d key=%d bearer=%d body=%s",
					test.name, response.Code, authorizer.keyResolveCalls, authorizer.resolveCalls,
					authorizer.accessKeyCalls, authorizer.authorizeCalls, response.Body.String())
			}
			expectedResourceTags := []iamv1.AuthorizationTag{{Key: "environment", Value: "production"}}
			if authorizer.accessKeyRequest.Action != test.action ||
				authorizer.accessKeyRequest.Resource != (paasv1.ResourceRef{Kind: port.ResourceApplication, ID: "application-label-key"}) ||
				!reflect.DeepEqual(authorizer.accessKeyRequest.ResourceLabels, workflow.inspectSnapshot.Labels) ||
				authorizer.accessKeyRequest.SignedRequest.HTTP.Method != test.method ||
				authorizer.accessKeyRequest.SignedRequest.HTTP.EscapedPath != externalPath ||
				authorizer.accessKeyRequest.SignedRequest.HTTP.IfMatch != `"7"` {
				t.Fatalf("signed label %s mapped to %#v", test.name, authorizer.accessKeyRequest)
			}
			var authorization port.Authorization
			if test.method == http.MethodPut {
				authorization = workflow.setApplicationLabel.Authorization
			} else {
				authorization = workflow.deleteApplicationLabel.Authorization
			}
			if !authorization.Subject.Equal(paasv1.SubjectRef{Type: paasv1.SubjectUser, ID: "user-authorized", AccessKeyID: "key-one"}) ||
				!reflect.DeepEqual(authorization.ResourceTags, expectedResourceTags) ||
				!reflect.DeepEqual(authorization.RequestTags, test.requestTags) {
				t.Fatalf("signed label %s lost key/tag evidence: %#v", test.name, authorization)
			}
		})
	}
}

func TestHandlerRejectsUndeclaredApplicationLabelBeforeIAM(t *testing.T) {
	authorizer := &fakeAuthorizer{}
	workflow := &fakeWorkflow{}
	handler := mustHandler(t, authorizer, workflow)
	request := jsonRequest(t, http.MethodPut, "/v1/applications/application-labels/labels/team",
		paasv1.SetApplicationLabelRequest{Value: "platform"})
	request.Header.Set("Authorization", "Bearer opaque-credential")
	request.Header.Set("Idempotency-Key", "set-undeclared-label")
	request.Header.Set("If-Match", `"1"`)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || workflow.inspectApplicationCalls != 0 ||
		workflow.setApplicationLabelCalls != 0 || authorizer.request.Action != "" {
		t.Fatalf("undeclared label reached authority: status=%d request=%#v workflow=%#v", response.Code, authorizer.request, workflow)
	}
}

func TestWorkflowNoDesiredChangeProblemIsResourceNeutral(t *testing.T) {
	response := httptest.NewRecorder()
	writeWorkflowError(response, "request-no-change", applicationlifecycle.ErrNoDesiredChange)

	var problem paasv1.Problem
	if err := json.NewDecoder(response.Body).Decode(&problem); err != nil {
		t.Fatalf("decode problem: %v", err)
	}
	if response.Code != http.StatusConflict || problem.Code != paasv1.ErrorConflict ||
		problem.Title != "No desired change" || problem.Detail != "the requested desired state is unchanged" ||
		problem.Retryable {
		t.Fatalf("no-change problem = status %d, %#v", response.Code, problem)
	}
	if strings.Contains(strings.ToLower(problem.Detail), "deployment") {
		t.Fatalf("resource-neutral workflow error leaked Deployment terminology: %#v", problem)
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

func TestHandlerBindsStoredApplicationLabelsAndRechecksAuthorizedSnapshot(t *testing.T) {
	authorizer := &fakeAuthorizer{}
	metadata := testMetadata("application-a", "application-a")
	metadata.ResourceVersion = 7
	metadata.Labels = map[string]string{
		"environment": "production",
		"team":        "payments",
	}
	application := paasv1.Application{
		APIVersion: paasv1.APIVersion,
		Kind:       "Application",
		Metadata:   metadata,
	}
	workflow := &fakeWorkflow{
		inspectSnapshot: &applicationlifecycle.ApplicationAuthorizationSnapshot{
			ID: metadata.ID, ResourceVersion: metadata.ResourceVersion, Labels: metadata.Labels,
		},
		getApplicationResult: &application,
	}
	handler := mustHandler(t, authorizer, workflow)
	request := httptest.NewRequest(http.MethodGet, "/v1/applications/application-a", nil)
	request.Header.Set("Authorization", "Bearer opaque-credential")
	request.Header.Set("X-Tenant-ID", "tenant-attacker")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if authorizer.resolveCalls != 1 || workflow.inspectApplicationCalls != 1 || workflow.getApplicationCalls != 1 {
		t.Fatalf("resolve/inspect/read calls=%d/%d/%d", authorizer.resolveCalls, workflow.inspectApplicationCalls, workflow.getApplicationCalls)
	}
	if !reflect.DeepEqual(authorizer.request.ResourceLabels, metadata.Labels) {
		t.Fatalf("PEP did not bind the complete stored label set: %#v", authorizer.request.ResourceLabels)
	}
	expected := []iamv1.AuthorizationTag{{Key: "environment", Value: "production"}}
	if !reflect.DeepEqual(workflow.readAuthorization.ResourceTags, expected) {
		t.Fatalf("declared resource tags=%#v, want %#v", workflow.readAuthorization.ResourceTags, expected)
	}
	if workflow.inspectSubject.TenantID != "tenant-authorized" ||
		workflow.inspectSubject.Subject != (paasv1.SubjectRef{Type: paasv1.SubjectUser, ID: "user-authorized"}) {
		t.Fatalf("inspection subject=%#v", workflow.inspectSubject)
	}
}

func TestHandlerFailsClosedWhenApplicationAuthorizationFactsChange(t *testing.T) {
	baseMetadata := testMetadata("application-a", "application-a")
	baseMetadata.ResourceVersion = 7
	baseMetadata.Labels = map[string]string{"environment": "production", "team": "payments"}
	baseSnapshot := applicationlifecycle.ApplicationAuthorizationSnapshot{
		ID: baseMetadata.ID, ResourceVersion: baseMetadata.ResourceVersion, Labels: baseMetadata.Labels,
	}
	resourceTags := []iamv1.AuthorizationTag{{Key: "environment", Value: "production"}}

	tests := []struct {
		name       string
		authorizer *fakeAuthorizer
		workflow   *fakeWorkflow
	}{
		{
			name: "subject changed between resolution and authorization",
			authorizer: &fakeAuthorizer{result: &port.Authorization{
				TenantID: "tenant-other", Subject: paasv1.SubjectRef{Type: paasv1.SubjectUser, ID: "user-other"},
				DecisionID: "decision-authorized", RequestID: "request-test", ResourceTags: resourceTags,
			}},
			workflow: &fakeWorkflow{inspectSnapshot: &baseSnapshot},
		},
		{
			name:       "resource version changed after authorization",
			authorizer: &fakeAuthorizer{},
			workflow: &fakeWorkflow{
				inspectSnapshot: &baseSnapshot,
				getApplicationResult: &paasv1.Application{
					APIVersion: paasv1.APIVersion, Kind: "Application",
					Metadata: func() paasv1.ResourceMetadata {
						changed := baseMetadata
						changed.ResourceVersion++
						return changed
					}(),
				},
			},
		},
		{
			name:       "declared resource tag changed after authorization",
			authorizer: &fakeAuthorizer{},
			workflow: &fakeWorkflow{
				inspectSnapshot: &baseSnapshot,
				getApplicationResult: &paasv1.Application{
					APIVersion: paasv1.APIVersion, Kind: "Application",
					Metadata: func() paasv1.ResourceMetadata {
						changed := baseMetadata
						changed.Labels = map[string]string{"environment": "staging", "team": "payments"}
						return changed
					}(),
				},
			},
		},
		{
			name:       "missing resource appeared after authorization",
			authorizer: &fakeAuthorizer{},
			workflow: &fakeWorkflow{
				inspectErr: applicationlifecycle.ErrNotFound,
				getApplicationResult: &paasv1.Application{
					APIVersion: paasv1.APIVersion, Kind: "Application", Metadata: baseMetadata,
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler := mustHandler(t, test.authorizer, test.workflow)
			request := httptest.NewRequest(http.MethodGet, "/v1/applications/application-a", nil)
			request.Header.Set("Authorization", "Bearer opaque-credential")
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			if response.Code != http.StatusServiceUnavailable {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
}

func TestHandlerPreservesApplicationNotFoundWithoutAuthorizingAnAppearingResource(t *testing.T) {
	authorizer := &fakeAuthorizer{}
	workflow := &fakeWorkflow{
		inspectErr:        applicationlifecycle.ErrNotFound,
		getApplicationErr: applicationlifecycle.ErrNotFound,
	}
	handler := mustHandler(t, authorizer, workflow)
	request := httptest.NewRequest(http.MethodGet, "/v1/applications/application-a", nil)
	request.Header.Set("Authorization", "Bearer opaque-credential")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusNotFound || workflow.inspectApplicationCalls != 1 || workflow.getApplicationCalls != 1 {
		t.Fatalf("status=%d inspect/read=%d/%d body=%s", response.Code, workflow.inspectApplicationCalls, workflow.getApplicationCalls, response.Body.String())
	}
	if authorizer.request.ResourceLabels != nil || workflow.readAuthorization.ResourceTags != nil {
		t.Fatalf("missing resource acquired tags: request=%#v authorization=%#v", authorizer.request.ResourceLabels, workflow.readAuthorization.ResourceTags)
	}
}

func TestHandlerUsesSocketPeerInsteadOfCallerForwardingHeaders(t *testing.T) {
	authorizer := &fakeAuthorizer{}
	workflow := &fakeWorkflow{}
	handler := mustHandler(t, authorizer, workflow)
	request := httptest.NewRequest(http.MethodGet, "/v1/applications/application-a", nil)
	request.RemoteAddr = "198.51.100.23:443"
	request.Header.Set("Authorization", "Bearer opaque-credential")
	request.Header.Set("Forwarded", "for=203.0.113.99")
	request.Header.Set("X-Forwarded-For", "203.0.113.98, 203.0.113.97")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || authorizer.request.SourceIP != "198.51.100.23" || workflow.getApplicationCalls != 1 {
		t.Fatalf("socket authority status=%d request=%#v calls=%d", response.Code, authorizer.request, workflow.getApplicationCalls)
	}
}

func TestHandlerFailsClosedWithoutCanonicalSocketPeer(t *testing.T) {
	for _, remote := range []string{"", "198.51.100.23", "198.51.100.23:0", "0.0.0.0:443", "[::]:443", "[::ffff:192.0.2.1]:443"} {
		t.Run(remote, func(t *testing.T) {
			authorizer := &fakeAuthorizer{}
			workflow := &fakeWorkflow{}
			handler := mustHandler(t, authorizer, workflow)
			request := httptest.NewRequest(http.MethodGet, "/v1/applications/application-a", nil)
			request.RemoteAddr = remote
			request.Header.Set("Authorization", "Bearer opaque-credential")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusServiceUnavailable || !reflect.DeepEqual(authorizer.request, port.AuthorizationRequest{}) || workflow.getApplicationCalls != 0 {
				t.Fatalf("invalid socket authority remote=%q status=%d request=%#v calls=%d", remote, response.Code, authorizer.request, workflow.getApplicationCalls)
			}
		})
	}
}

type fakeAuthorizer struct {
	request          port.AuthorizationRequest
	accessKeyRequest port.AccessKeyAuthorizationRequest
	resolveRequest   port.SubjectResolutionRequest
	resolveCalls     int
	keyResolveCalls  int
	authorizeCalls   int
	accessKeyCalls   int
	err              error
	accessKeyErr     error
	resolveErr       error
	result           *port.Authorization
	accessKeyResult  *port.Authorization
	resolveResult    *port.AuthorizationSubjectContext
}

func (authorizer *fakeAuthorizer) ResolveAccessKeySubject(
	_ context.Context,
	signed iamv1.AccessKeySignedRequest,
) (port.AuthorizationSubjectContext, error) {
	authorizer.keyResolveCalls++
	if authorizer.resolveErr != nil {
		return port.AuthorizationSubjectContext{}, authorizer.resolveErr
	}
	if authorizer.resolveResult != nil {
		return *authorizer.resolveResult, nil
	}
	profile, _ := iamv1.LookupAuthorizationProfile(iamv1.ProductPaaS)
	_, digest, _ := iamv1.CanonicalizeAuthorizationProfile(profile)
	return port.AuthorizationSubjectContext{
		TenantID: "tenant-authorized",
		Subject: paasv1.SubjectRef{Type: paasv1.SubjectUser, ID: "user-authorized",
			AccessKeyID: string(signed.Parameters.AccessKeyID)},
		Profile: iamv1.AuthorizationProfileReference{Product: profile.Product, Revision: profile.Revision, ContentDigest: digest},
	}, nil
}

func (authorizer *fakeAuthorizer) ResolveSubject(
	_ context.Context,
	request port.SubjectResolutionRequest,
) (port.AuthorizationSubjectContext, error) {
	authorizer.resolveCalls++
	authorizer.resolveRequest = request
	if authorizer.resolveErr != nil {
		return port.AuthorizationSubjectContext{}, authorizer.resolveErr
	}
	if authorizer.resolveResult != nil {
		return *authorizer.resolveResult, nil
	}
	profile, _ := iamv1.LookupAuthorizationProfile(iamv1.ProductPaaS)
	_, digest, _ := iamv1.CanonicalizeAuthorizationProfile(profile)
	return port.AuthorizationSubjectContext{
		TenantID: "tenant-authorized",
		Subject:  paasv1.SubjectRef{Type: paasv1.SubjectUser, ID: "user-authorized"},
		Profile: iamv1.AuthorizationProfileReference{
			Product: profile.Product, Revision: profile.Revision, ContentDigest: digest,
		},
	}, nil
}

func (authorizer *fakeAuthorizer) Authorize(
	_ context.Context,
	request port.AuthorizationRequest,
) (port.Authorization, error) {
	authorizer.authorizeCalls++
	authorizer.request = request
	if authorizer.err != nil {
		return port.Authorization{}, authorizer.err
	}
	if authorizer.result != nil {
		return *authorizer.result, nil
	}
	iamRequest, err := port.NewIAMAuthorizationRequest(request)
	if err != nil {
		return port.Authorization{}, err
	}
	return port.Authorization{
		TenantID:   "tenant-authorized",
		Subject:    paasv1.SubjectRef{Type: paasv1.SubjectUser, ID: "user-authorized"},
		DecisionID: "decision-authorized", RequestID: request.RequestID,
		RequestTags:  iamRequest.RequestTags,
		ResourceTags: iamRequest.ResourceTags,
		AuditID:      "audit-authorized",
	}, nil
}

func (authorizer *fakeAuthorizer) AuthorizeAccessKey(
	_ context.Context,
	request port.AccessKeyAuthorizationRequest,
) (port.Authorization, error) {
	authorizer.accessKeyCalls++
	authorizer.accessKeyRequest = request
	if authorizer.accessKeyErr != nil {
		return port.Authorization{}, authorizer.accessKeyErr
	}
	if authorizer.accessKeyResult != nil {
		return *authorizer.accessKeyResult, nil
	}
	iamRequest, err := port.NewIAMAccessKeyAuthorizationRequest(request)
	if err != nil {
		return port.Authorization{}, err
	}
	return port.Authorization{
		TenantID: "tenant-authorized",
		Subject: paasv1.SubjectRef{Type: paasv1.SubjectUser, ID: "user-authorized",
			AccessKeyID: string(request.SignedRequest.Parameters.AccessKeyID)},
		DecisionID: "decision-authorized", RequestID: request.RequestID,
		RequestTags: iamRequest.RequestTags, ResourceTags: iamRequest.ResourceTags,
		AuditID: "audit-authorized",
	}, nil
}

type fakeWorkflow struct {
	createApplicationCalls             int
	createApplicationCommand           applicationlifecycle.CreateApplicationCommand
	createConfigurationCalls           int
	createConfigurationCommand         applicationlifecycle.CreateConfigurationCommand
	createConfigurationRevisionCalls   int
	createConfigurationRevisionCommand applicationlifecycle.CreateConfigurationRevisionCommand
	createApplicationRevisionCalls     int
	createApplicationRevisionCommand   applicationlifecycle.CreateApplicationRevisionCommand
	setApplicationLabelCalls           int
	setApplicationLabel                applicationlifecycle.SetApplicationLabelCommand
	deleteApplicationLabelCalls        int
	deleteApplicationLabel             applicationlifecycle.DeleteApplicationLabelCommand
	submitCalls                        int
	submitCommand                      applicationlifecycle.SubmitCommand
	rollbackCalls                      int
	rollbackCommand                    applicationlifecycle.RollbackCommand
	getApplicationCalls                int
	inspectApplicationCalls            int
	readAuthorization                  port.Authorization
	readID                             paasv1.ResourceID
	inspectSubject                     port.AuthorizationSubjectContext
	inspectSnapshot                    *applicationlifecycle.ApplicationAuthorizationSnapshot
	inspectErr                         error
	getApplicationResult               *paasv1.Application
	getApplicationErr                  error
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
	workflow.createApplicationCommand = command
	resource := paasv1.Application{Metadata: testMetadata(command.Request.ID, command.Request.Name)}
	operation := testOperation("Application", resource.Metadata.ID, paasv1.OperationCreateApplication, paasv1.OperationSucceeded)
	operation.RequestedBy = command.Authorization.Subject
	return resource, operation, false, nil
}

func (workflow *fakeWorkflow) SetApplicationLabel(
	_ context.Context,
	command applicationlifecycle.SetApplicationLabelCommand,
) (applicationlifecycle.ApplicationLabelResult, error) {
	workflow.setApplicationLabelCalls++
	workflow.setApplicationLabel = command
	return applicationlifecycle.ApplicationLabelResult{
		Operation:       testOperation("Application", command.ApplicationID, paasv1.OperationSetApplicationLabel, paasv1.OperationSucceeded),
		ResourceVersion: command.ExpectedResourceVersion + 1,
	}, nil
}

func (workflow *fakeWorkflow) DeleteApplicationLabel(
	_ context.Context,
	command applicationlifecycle.DeleteApplicationLabelCommand,
) (applicationlifecycle.ApplicationLabelResult, error) {
	workflow.deleteApplicationLabelCalls++
	workflow.deleteApplicationLabel = command
	return applicationlifecycle.ApplicationLabelResult{
		Operation:       testOperation("Application", command.ApplicationID, paasv1.OperationDeleteApplicationLabel, paasv1.OperationSucceeded),
		ResourceVersion: command.ExpectedResourceVersion + 1,
	}, nil
}

func (workflow *fakeWorkflow) CreateConfiguration(
	_ context.Context,
	command applicationlifecycle.CreateConfigurationCommand,
) (paasv1.Configuration, paasv1.Operation, bool, error) {
	workflow.createConfigurationCalls++
	workflow.createConfigurationCommand = command
	resource := paasv1.Configuration{Metadata: testMetadata(command.Request.ID, command.Request.Name), ApplicationID: command.Request.ApplicationID}
	operation := testOperation("Configuration", resource.Metadata.ID, paasv1.OperationCreateConfiguration, paasv1.OperationSucceeded)
	operation.RequestedBy = command.Authorization.Subject
	return resource, operation, false, nil
}

func (workflow *fakeWorkflow) CreateConfigurationRevision(
	_ context.Context,
	command applicationlifecycle.CreateConfigurationRevisionCommand,
) (paasv1.ConfigurationRevision, paasv1.Operation, bool, error) {
	workflow.createConfigurationRevisionCalls++
	workflow.createConfigurationRevisionCommand = command
	resource := paasv1.ConfigurationRevision{Metadata: testMetadata(command.Request.ID, command.Request.Name), Spec: command.Request.Spec}
	operation := testOperation("ConfigurationRevision", resource.Metadata.ID, paasv1.OperationCreateConfigurationRevision, paasv1.OperationSucceeded)
	operation.RequestedBy = command.Authorization.Subject
	return resource, operation, false, nil
}

func (workflow *fakeWorkflow) CreateApplicationRevision(
	_ context.Context,
	command applicationlifecycle.CreateApplicationRevisionCommand,
) (paasv1.ApplicationRevision, paasv1.Operation, bool, error) {
	workflow.createApplicationRevisionCalls++
	workflow.createApplicationRevisionCommand = command
	resource := paasv1.ApplicationRevision{Metadata: testMetadata(command.Request.ID, command.Request.Name), Spec: command.Request.Spec}
	operation := testOperation("ApplicationRevision", resource.Metadata.ID, paasv1.OperationCreateApplicationRevision, paasv1.OperationSucceeded)
	operation.RequestedBy = command.Authorization.Subject
	return resource, operation, false, nil
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
	operation := testOperation("Deployment", command.DeploymentID, paasv1.OperationDeploy, paasv1.OperationAccepted)
	operation.RequestedBy = command.Authorization.Subject
	return applicationlifecycle.Result{Deployment: deployment, Operation: operation}, nil
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
	if workflow.getApplicationResult != nil || workflow.getApplicationErr != nil {
		if workflow.getApplicationResult == nil {
			return paasv1.Application{}, workflow.getApplicationErr
		}
		return *workflow.getApplicationResult, workflow.getApplicationErr
	}
	return paasv1.Application{
		APIVersion: paasv1.APIVersion, Kind: "Application", Metadata: testMetadata(id, "application-a"),
	}, nil
}

func (workflow *fakeWorkflow) InspectApplicationAuthorization(
	_ context.Context,
	subject port.AuthorizationSubjectContext,
	id paasv1.ResourceID,
) (applicationlifecycle.ApplicationAuthorizationSnapshot, error) {
	workflow.inspectApplicationCalls++
	workflow.inspectSubject, workflow.readID = subject, id
	if workflow.inspectSnapshot != nil || workflow.inspectErr != nil {
		if workflow.inspectSnapshot == nil {
			return applicationlifecycle.ApplicationAuthorizationSnapshot{}, workflow.inspectErr
		}
		return *workflow.inspectSnapshot, workflow.inspectErr
	}
	metadata := testMetadata(id, "application-a")
	return applicationlifecycle.ApplicationAuthorizationSnapshot{
		ID: metadata.ID, ResourceVersion: metadata.ResourceVersion, Labels: metadata.Labels,
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

func (workflow *fakeWorkflow) GetDeploymentGeneration(context.Context, port.Authorization, paasv1.ResourceID, uint64) (paasv1.DeploymentGeneration, error) {
	return paasv1.DeploymentGeneration{}, errors.New("unexpected GetDeploymentGeneration")
}

func (workflow *fakeWorkflow) GetOperation(context.Context, port.Authorization, paasv1.OperationID) (paasv1.Operation, error) {
	return paasv1.Operation{}, errors.New("unexpected GetOperation")
}

func mustHandler(t *testing.T, authorizer port.Authorizer, workflow Workflow) http.Handler {
	return mustHandlerWithVerifier(t, authorizer, workflow, &fakeInstallationVerifier{})
}

func mustAccessKeyHandler(t *testing.T, authorizer port.Authorizer, workflow Workflow) http.Handler {
	t.Helper()
	handler, err := NewHandler(authorizer, workflow, &fakeInstallationVerifier{}, Config{
		NorthboundOrigin: "https://api.example.test:443", InstallationID: "installation-one",
		NewRequestID: func() (string, error) { return "request-test", nil },
		Readiness: func(context.Context) (paasv1.Readiness, error) {
			return paasv1.Readiness{APIVersion: paasv1.APIVersion, Kind: "Readiness", State: paasv1.ReadinessReady,
				SchemaVersion: 1, CheckedAt: time.Date(2026, 8, 26, 3, 4, 5, 0, time.UTC)}, nil
		},
	})
	if err != nil {
		t.Fatalf("create AccessKey HTTP handler: %v", err)
	}
	return handler
}

func mustHandlerWithVerifier(
	t *testing.T,
	authorizer port.Authorizer,
	workflow Workflow,
	verifier InstallationVerifier,
) http.Handler {
	t.Helper()
	handler, err := NewHandler(authorizer, workflow, verifier, Config{
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

func setAccessKeyEdgeHeaders(t *testing.T, request *http.Request, externalTarget string) {
	t.Helper()
	nonce, err := iamv1.NewSecret("AAAAAAAAAAAAAAAAAAAAAA")
	if err != nil {
		t.Fatal(err)
	}
	signature, err := iamv1.NewSecret("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if err != nil {
		t.Fatal(err)
	}
	header, err := iamv1.EncodeAccessKeyAuthorization(iamv1.AccessKeySignatureParameters{
		AccessKeyID: "key-one", InstallationID: "installation-one", Audience: iamv1.ProductPaaS,
		SignedAt: 1800000000, Nonce: nonce,
	}, signature)
	if err != nil {
		t.Fatal(err)
	}
	plain := header.CopyBytes()
	request.Header.Set("Authorization", string(plain))
	clear(plain)
	request.Header.Set(externalrequest.HeaderExternalOrigin, "https://api.example.test:443")
	request.Header.Set(externalrequest.HeaderExternalRequestTarget, externalTarget)
}

func testMetadata(id paasv1.ResourceID, name string) paasv1.ResourceMetadata {
	now := time.Date(2026, 8, 25, 18, 0, 0, 0, time.UTC)
	return paasv1.ResourceMetadata{
		ID: id, Name: name,
		Scope:           paasv1.ResourceScope{Kind: paasv1.AuthorityTenant, TenantID: "tenant-authorized"},
		ResourceVersion: 1, CreatedAt: now, UpdatedAt: now,
	}
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
