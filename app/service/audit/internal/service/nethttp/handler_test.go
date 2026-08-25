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

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/audit/internal/authority"
)

func TestAuditHTTPExposesCredentialBoundRoutes(t *testing.T) {
	workflow := newHTTPWorkflow(t)
	handler := newTestHandler(t, workflow)

	readyResponse := httptest.NewRecorder()
	handler.ServeHTTP(readyResponse, httptest.NewRequest(http.MethodGet, "/ready", nil))
	if readyResponse.Code != http.StatusOK || workflow.readinessCalls != 1 ||
		readyResponse.Header().Get("Cache-Control") != "no-store" ||
		readyResponse.Header().Get("X-Content-Type-Options") != "nosniff" ||
		readyResponse.Header().Get("Matrix-Request-ID") != "request-http-test" {
		t.Fatalf("Audit readiness status=%d headers=%#v calls=%d", readyResponse.Code, readyResponse.Header(), workflow.readinessCalls)
	}

	ingestResponse := exerciseJSON(
		t,
		handler,
		http.MethodPost,
		"/v1/events",
		workflow.event,
		"service-producer-credential",
	)
	if ingestResponse.Code != http.StatusCreated || workflow.ingestCalls != 1 ||
		!workflow.ingestCredentialPresent {
		t.Fatalf("Audit ingest status=%d calls=%d body=%s", ingestResponse.Code, workflow.ingestCalls, ingestResponse.Body.String())
	}
	workflow.ingestion.Outcome = auditv1.IngestionDuplicate
	replayResponse := exerciseJSON(
		t,
		handler,
		http.MethodPost,
		"/v1/events",
		workflow.event,
		"service-producer-credential",
	)
	if replayResponse.Code != http.StatusOK || workflow.ingestCalls != 2 {
		t.Fatalf("Audit replay status=%d calls=%d body=%s", replayResponse.Code, workflow.ingestCalls, replayResponse.Body.String())
	}

	queryResponse := exerciseJSON(
		t,
		handler,
		http.MethodPost,
		"/v1/records:query",
		auditv1.QueryRecordsRequest{PageSize: 10},
		"user-session-credential",
	)
	if queryResponse.Code != http.StatusOK || workflow.queryCalls != 1 ||
		workflow.queryRequestID != "request-http-test" || !workflow.queryCredentialPresent {
		t.Fatalf("Audit query status=%d calls=%d requestId=%q body=%s", queryResponse.Code, workflow.queryCalls, workflow.queryRequestID, queryResponse.Body.String())
	}
	var page auditv1.RecordPage
	if err := json.Unmarshal(queryResponse.Body.Bytes(), &page); err != nil ||
		auditv1.ValidateRecordPage(page) != nil || page.TenantID != "organization-example" {
		t.Fatalf("decode Audit page: page=%#v err=%v", page, err)
	}

	verifyResponse := exerciseJSON(
		t,
		handler,
		http.MethodPost,
		"/v1/integrity:verify",
		auditv1.VerifyChainRequest{FromSequence: 1, MaximumRecords: 10},
		"user-session-credential",
	)
	if verifyResponse.Code != http.StatusOK || workflow.verifyCalls != 1 ||
		workflow.verifyRequestID != "request-http-test" || !workflow.verifyCredentialPresent {
		t.Fatalf("Audit verify status=%d calls=%d requestId=%q body=%s", verifyResponse.Code, workflow.verifyCalls, workflow.verifyRequestID, verifyResponse.Body.String())
	}

	installationResponse := exerciseJSON(
		t,
		handler,
		http.MethodPost,
		"/v1/installation:verify",
		auditv1.VerifyInstallationRequest{
			InstallationID: "mxi-0123456789abcdef0123456789abcdef",
			OperationID:    "operation-verification",
			DeploymentID:   "deployment-verification",
		},
		"installation-verifier-credential",
	)
	if installationResponse.Code != http.StatusOK || workflow.installationVerifyCalls != 1 ||
		workflow.installationVerifyRequestID != "request-http-test" || !workflow.verifyCredentialPresent {
		t.Fatalf("Audit installation verify status=%d calls=%d requestId=%q body=%s", installationResponse.Code, workflow.installationVerifyCalls, workflow.installationVerifyRequestID, installationResponse.Body.String())
	}

	missingCredential := httptest.NewRequest(
		http.MethodPost,
		"/v1/records:query",
		strings.NewReader(`{"pageSize":10}`),
	)
	missingCredential.Header.Set("Content-Type", "application/json")
	missingResponse := httptest.NewRecorder()
	handler.ServeHTTP(missingResponse, missingCredential)
	if missingResponse.Code != http.StatusUnauthorized || workflow.queryCalls != 1 {
		t.Fatalf("missing credential status=%d calls=%d", missingResponse.Code, workflow.queryCalls)
	}
}

func TestAuditHTTPRejectsAmbiguousInputAndRedactsFailures(t *testing.T) {
	workflow := newHTTPWorkflow(t)
	handler := newTestHandler(t, workflow)

	unknownField := httptest.NewRequest(
		http.MethodPost,
		"/v1/records:query",
		strings.NewReader(`{"pageSize":10,"tenantId":"organization-forged"}`),
	)
	unknownField.Header.Set("Content-Type", "application/json")
	unknownField.Header.Set("Authorization", "Bearer user-session-credential")
	unknownResponse := httptest.NewRecorder()
	handler.ServeHTTP(unknownResponse, unknownField)
	if unknownResponse.Code != http.StatusBadRequest || workflow.queryCalls != 0 {
		t.Fatalf("unknown selector status=%d calls=%d body=%s", unknownResponse.Code, workflow.queryCalls, unknownResponse.Body.String())
	}

	oversized := httptest.NewRequest(
		http.MethodPost,
		"/v1/records:query",
		strings.NewReader(`{"pageSize":10,"cursor":"`+strings.Repeat("A", int(auditv1.MaxRequestBytes))+`"}`),
	)
	oversized.Header.Set("Content-Type", "application/json")
	oversized.Header.Set("Authorization", "Bearer user-session-credential")
	oversizedResponse := httptest.NewRecorder()
	handler.ServeHTTP(oversizedResponse, oversized)
	if oversizedResponse.Code != http.StatusRequestEntityTooLarge || workflow.queryCalls != 0 {
		t.Fatalf("oversized status=%d calls=%d body=%s", oversizedResponse.Code, workflow.queryCalls, oversizedResponse.Body.String())
	}

	compressed := httptest.NewRequest(http.MethodPost, "/v1/events", strings.NewReader(`{}`))
	compressed.Header.Set("Content-Type", "application/json")
	compressed.Header.Set("Content-Encoding", "gzip")
	compressed.Header.Set("Authorization", "Bearer service-producer-credential")
	compressedResponse := httptest.NewRecorder()
	handler.ServeHTTP(compressedResponse, compressed)
	if compressedResponse.Code != http.StatusUnsupportedMediaType || workflow.ingestCalls != 0 {
		t.Fatalf("encoded body status=%d calls=%d", compressedResponse.Code, workflow.ingestCalls)
	}

	selector := httptest.NewRequest(
		http.MethodPost,
		"/v1/records:query?tenantId=organization-forged",
		strings.NewReader(`{"pageSize":10}`),
	)
	selector.Header.Set("Content-Type", "application/json")
	selector.Header.Set("Authorization", "Bearer user-session-credential")
	selectorResponse := httptest.NewRecorder()
	handler.ServeHTTP(selectorResponse, selector)
	if selectorResponse.Code != http.StatusBadRequest || workflow.queryCalls != 0 {
		t.Fatalf("query selector status=%d calls=%d", selectorResponse.Code, workflow.queryCalls)
	}

	duplicateCredential := httptest.NewRequest(
		http.MethodPost,
		"/v1/records:query",
		strings.NewReader(`{"pageSize":10}`),
	)
	duplicateCredential.Header.Set("Content-Type", "application/json")
	duplicateCredential.Header.Add("Authorization", "Bearer first-credential")
	duplicateCredential.Header.Add("Authorization", "Bearer second-credential")
	duplicateResponse := httptest.NewRecorder()
	handler.ServeHTTP(duplicateResponse, duplicateCredential)
	if duplicateResponse.Code != http.StatusUnauthorized || workflow.queryCalls != 0 {
		t.Fatalf("duplicate credential status=%d calls=%d", duplicateResponse.Code, workflow.queryCalls)
	}

	subjectVerifier := httptest.NewRequest(
		http.MethodPost,
		"/v1/installation:verify",
		strings.NewReader(`{"installationId":"mxi-0123456789abcdef0123456789abcdef","operationId":"operation-verification","deploymentId":"deployment-verification"}`),
	)
	subjectVerifier.Header.Set("Content-Type", "application/json")
	subjectVerifier.Header.Set("Authorization", "Bearer installation-verifier-credential")
	subjectVerifier.Header.Set("Matrix-Subject-Credential", "user-session")
	subjectVerifierResponse := httptest.NewRecorder()
	handler.ServeHTTP(subjectVerifierResponse, subjectVerifier)
	if subjectVerifierResponse.Code != http.StatusBadRequest || workflow.installationVerifyCalls != 0 {
		t.Fatalf("subject verifier status=%d calls=%d", subjectVerifierResponse.Code, workflow.installationVerifyCalls)
	}

	workflow.queryErr = errors.New("native failure contains user-session-credential and C:\\secret")
	failureResponse := exerciseJSON(
		t,
		handler,
		http.MethodPost,
		"/v1/records:query",
		auditv1.QueryRecordsRequest{PageSize: 10},
		"user-session-credential",
	)
	if failureResponse.Code != http.StatusServiceUnavailable ||
		bytes.Contains(failureResponse.Body.Bytes(), []byte("user-session-credential")) ||
		bytes.Contains(failureResponse.Body.Bytes(), []byte("native failure")) ||
		bytes.Contains(failureResponse.Body.Bytes(), []byte(`C:\secret`)) {
		t.Fatalf("Audit failure leaked internal data: status=%d body=%s", failureResponse.Code, failureResponse.Body.String())
	}
	var problem auditv1.Problem
	if err := json.Unmarshal(failureResponse.Body.Bytes(), &problem); err != nil ||
		auditv1.ValidateProblem(problem) != nil {
		t.Fatalf("decode normalized Audit problem: problem=%#v err=%v", problem, err)
	}

	methodResponse := httptest.NewRecorder()
	handler.ServeHTTP(methodResponse, httptest.NewRequest(http.MethodGet, "/v1/events", nil))
	if methodResponse.Code != http.StatusMethodNotAllowed || methodResponse.Header().Get("Allow") != http.MethodPost {
		t.Fatalf("Audit method status=%d allow=%q", methodResponse.Code, methodResponse.Header().Get("Allow"))
	}
	missingResponse := httptest.NewRecorder()
	handler.ServeHTTP(missingResponse, httptest.NewRequest(http.MethodGet, "/debug", nil))
	if missingResponse.Code != http.StatusNotFound {
		t.Fatalf("Audit unknown route status=%d body=%s", missingResponse.Code, missingResponse.Body.String())
	}
}

func newTestHandler(t *testing.T, workflow Workflow) http.Handler {
	t.Helper()
	handler, err := NewHandler(workflow, Config{
		NewRequestID: func() (string, error) { return "request-http-test", nil },
	})
	if err != nil {
		t.Fatalf("create Audit HTTP handler: %v", err)
	}
	return handler
}

func exerciseJSON(
	t *testing.T,
	handler http.Handler,
	method string,
	target string,
	body any,
	credential string,
) *httptest.ResponseRecorder {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("encode Audit HTTP request: %v", err)
	}
	request := httptest.NewRequest(method, target, bytes.NewReader(encoded))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+credential)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

type httpWorkflow struct {
	now                         time.Time
	event                       auditv1.Event
	ingestion                   auditv1.IngestionResult
	page                        auditv1.RecordPage
	verification                auditv1.ChainVerification
	installationVerification    auditv1.InstallationVerification
	readiness                   auditv1.Readiness
	queryErr                    error
	readinessCalls              int
	ingestCalls                 int
	queryCalls                  int
	verifyCalls                 int
	installationVerifyCalls     int
	ingestCredentialPresent     bool
	queryCredentialPresent      bool
	verifyCredentialPresent     bool
	queryRequestID              string
	verifyRequestID             string
	installationVerifyRequestID string
}

func newHTTPWorkflow(t *testing.T) *httpWorkflow {
	t.Helper()
	now := time.Date(2026, 8, 26, 15, 16, 17, 123000, time.UTC)
	event := auditv1.Event{
		APIVersion: auditv1.APIVersion,
		Kind:       "AuditEvent",
		EventID:    "event-http",
		TenantID:   "organization-example",
		Actor: auditv1.ActorReference{
			Type: auditv1.ActorServiceAccount,
			ID:   "service-iam",
		},
		Action:        auditv1.ActionIAMBootstrapApplied,
		Target:        auditv1.TargetReference{Kind: auditv1.TargetInstallation, ID: "installation-example"},
		Result:        auditv1.ResultSucceeded,
		RequestDigest: "sha256:" + strings.Repeat("1", 64),
		RequestID:     "request-event-http",
		CorrelationID: "correlation-event-http",
		OccurredAt:    now.Add(-time.Minute),
	}
	checkpoint, err := authority.GenesisCheckpoint(event.TenantID)
	if err != nil {
		t.Fatalf("create Audit HTTP checkpoint: %v", err)
	}
	record, _, err := authority.AppendRecord(checkpoint, 1, auditv1.SourceIAM, event, now)
	if err != nil {
		t.Fatalf("create Audit HTTP record: %v", err)
	}
	return &httpWorkflow{
		now:   now,
		event: event,
		ingestion: auditv1.IngestionResult{
			APIVersion: auditv1.APIVersion,
			Kind:       "IngestionResult",
			Outcome:    auditv1.IngestionAccepted,
			Record:     record,
		},
		page: auditv1.RecordPage{
			APIVersion: auditv1.APIVersion,
			Kind:       "AuditRecordPage",
			TenantID:   event.TenantID,
			Records:    []auditv1.AuditRecord{record},
		},
		verification: auditv1.ChainVerification{
			APIVersion:        auditv1.APIVersion,
			Kind:              "ChainVerification",
			TenantID:          event.TenantID,
			State:             auditv1.VerificationVerified,
			FromSequence:      1,
			ToSequence:        1,
			RecordCount:       1,
			FirstPreviousHash: record.PreviousHash,
			LastRecordHash:    record.RecordHash,
			Complete:          true,
			VerifiedAt:        now,
		},
		installationVerification: auditv1.InstallationVerification{
			APIVersion: auditv1.APIVersion, Kind: "InstallationVerification",
			InstallationID: "mxi-0123456789abcdef0123456789abcdef",
			OperationID:    "operation-verification", DeploymentID: "deployment-verification",
			State: auditv1.InstallationVerificationPending, CheckedAt: now,
		},
		readiness: auditv1.Readiness{
			APIVersion:    auditv1.APIVersion,
			Kind:          "Readiness",
			State:         auditv1.ReadinessReady,
			SchemaVersion: 1,
			CheckedAt:     now,
		},
	}
}

func (workflow *httpWorkflow) Readiness(context.Context) (auditv1.Readiness, error) {
	workflow.readinessCalls++
	return workflow.readiness, nil
}

func (workflow *httpWorkflow) Ingest(
	_ context.Context,
	credential iamv1.Secret,
	_ auditv1.Event,
) (auditv1.IngestionResult, error) {
	workflow.ingestCalls++
	workflow.ingestCredentialPresent = credential.Present()
	return workflow.ingestion, nil
}

func (workflow *httpWorkflow) QueryRecords(
	_ context.Context,
	credential iamv1.Secret,
	requestID string,
	_ auditv1.QueryRecordsRequest,
) (auditv1.RecordPage, error) {
	workflow.queryCalls++
	workflow.queryCredentialPresent = credential.Present()
	workflow.queryRequestID = requestID
	if workflow.queryErr != nil {
		return auditv1.RecordPage{}, workflow.queryErr
	}
	return workflow.page, nil
}

func (workflow *httpWorkflow) VerifyChain(
	_ context.Context,
	credential iamv1.Secret,
	requestID string,
	_ auditv1.VerifyChainRequest,
) (auditv1.ChainVerification, error) {
	workflow.verifyCalls++
	workflow.verifyCredentialPresent = credential.Present()
	workflow.verifyRequestID = requestID
	return workflow.verification, nil
}

func (workflow *httpWorkflow) VerifyInstallation(
	_ context.Context,
	credential iamv1.Secret,
	requestID string,
	_ auditv1.VerifyInstallationRequest,
) (auditv1.InstallationVerification, error) {
	workflow.installationVerifyCalls++
	workflow.installationVerifyRequestID = requestID
	workflow.verifyCredentialPresent = credential.Present()
	return workflow.installationVerification, workflow.queryErr
}
