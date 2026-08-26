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

	managedservicev1 "github.com/xiak/matrix/api/managedservice/v1"
	"github.com/xiak/matrix/app/service/paas/internal/managedservice/port"
	"github.com/xiak/matrix/app/service/paas/internal/managedservice/usecase"
)

func TestListOfferingsAuthorizesTheManagedServiceCollection(t *testing.T) {
	authorizer := &stubAuthorizer{}
	workflow := &stubWorkflow{
		offerings: managedservicev1.ServiceOfferingList{Kind: "ServiceOfferingList", Items: []managedservicev1.ServiceOffering{}},
	}
	handler := testHandler(t, authorizer, workflow)
	request := httptest.NewRequest(http.MethodGet, "/managed-services/v1/offerings", nil)
	request.Header.Set("Authorization", "Bearer session-secret")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if authorizer.request.Action != port.AuthorizeOfferingRead ||
		authorizer.request.Resource.Kind != port.ResourceServiceOffering ||
		authorizer.request.Credential != "Bearer session-secret" {
		t.Fatalf("authorization request=%#v", authorizer.request)
	}
	var result managedservicev1.ServiceOfferingList
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil || result.Kind != "ServiceOfferingList" {
		t.Fatalf("response=%#v err=%v", result, err)
	}
}

func TestQuotaActivationRejectsUnknownPaymentFields(t *testing.T) {
	workflow := &stubWorkflow{}
	handler := testHandler(t, &stubAuthorizer{}, workflow)
	request := httptest.NewRequest(
		http.MethodPost,
		"/managed-services/v1/quota-entitlements",
		strings.NewReader(`{"offeringId":"postgresql-18","quotaShapeId":"pg-small","instanceCount":1,"price":99}`),
	)
	request.Header.Set("Authorization", "Bearer session-secret")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "quota-request")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || workflow.activateCalls != 0 {
		t.Fatalf("status=%d calls=%d body=%s", response.Code, workflow.activateCalls, response.Body.String())
	}
}

func TestCreateInstallationReturnsOnlyNormalizedPendingState(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	workflow := &stubWorkflow{installation: managedservicev1.ServiceInstallation{
		ID: "postgres-primary", Name: "Postgres primary", OfferingID: "postgresql-18",
		EngineVersion: "18", QuotaEntitlementID: "quota-1", RegionID: "local-primary",
		Phase: managedservicev1.InstallationPending, CreatedAt: now,
		Operation: managedservicev1.InstallationOperation{
			ID: "operation-1", Phase: managedservicev1.InstallationPending, ObservedAt: now,
		},
	}}
	handler := testHandler(t, &stubAuthorizer{}, workflow)
	request := httptest.NewRequest(
		http.MethodPost,
		"/managed-services/v1/service-installations",
		strings.NewReader(`{"id":"postgres-primary","name":"Postgres primary","offeringId":"postgresql-18","quotaEntitlementId":"quota-1","regionId":"local-primary"}`),
	)
	request.Header.Set("Authorization", "Bearer session-secret")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "install-request")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted || workflow.createCalls != 1 {
		t.Fatalf("status=%d calls=%d body=%s", response.Code, workflow.createCalls, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "password") || strings.Contains(response.Body.String(), "image") {
		t.Fatalf("native or secret field leaked: %s", response.Body.String())
	}
}

func TestAuthorizationDenialFailsClosed(t *testing.T) {
	handler := testHandler(t, &stubAuthorizer{err: port.ErrPermissionDenied}, &stubWorkflow{})
	request := httptest.NewRequest(http.MethodGet, "/managed-services/v1/regions", nil)
	request.Header.Set("Authorization", "Bearer session-secret")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func testHandler(t *testing.T, authorizer port.Authorizer, workflow Workflow) http.Handler {
	t.Helper()
	handler, err := NewHandler(authorizer, workflow, Config{
		NewRequestID: func() (string, error) { return "request-test", nil },
	})
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}
	return handler
}

type stubAuthorizer struct {
	request port.AuthorizationRequest
	err     error
}

func (authorizer *stubAuthorizer) Authorize(
	_ context.Context,
	request port.AuthorizationRequest,
) (port.Authorization, error) {
	authorizer.request = request
	if authorizer.err != nil {
		return port.Authorization{}, authorizer.err
	}
	return port.Authorization{
		TenantID: "organization-test", SubjectID: "principal-test",
		DecisionID: "decision-test", RequestID: request.RequestID,
	}, nil
}

type stubWorkflow struct {
	offerings     managedservicev1.ServiceOfferingList
	installation  managedservicev1.ServiceInstallation
	activateCalls int
	createCalls   int
}

func (workflow *stubWorkflow) ListOfferings(context.Context, port.Authorization) (managedservicev1.ServiceOfferingList, error) {
	return workflow.offerings, nil
}

func (workflow *stubWorkflow) ListRegions(context.Context, port.Authorization) (managedservicev1.RegionList, error) {
	return managedservicev1.RegionList{Kind: "RegionList", Items: []managedservicev1.Region{}}, nil
}

func (workflow *stubWorkflow) ListQuotaEntitlements(context.Context, port.Authorization) (managedservicev1.QuotaEntitlementList, error) {
	return managedservicev1.QuotaEntitlementList{Kind: "QuotaEntitlementList", Items: []managedservicev1.QuotaEntitlement{}}, nil
}

func (workflow *stubWorkflow) ListServiceInstallations(context.Context, port.Authorization) (managedservicev1.ServiceInstallationList, error) {
	return managedservicev1.ServiceInstallationList{Kind: "ServiceInstallationList", Items: []managedservicev1.ServiceInstallation{}}, nil
}

func (workflow *stubWorkflow) ActivateQuota(
	context.Context,
	usecase.ActivateQuotaCommand,
) (managedservicev1.QuotaEntitlement, bool, error) {
	workflow.activateCalls++
	return managedservicev1.QuotaEntitlement{}, false, errors.New("not configured")
}

func (workflow *stubWorkflow) CreateInstallation(
	context.Context,
	usecase.CreateInstallationCommand,
) (managedservicev1.ServiceInstallation, bool, error) {
	workflow.createCalls++
	return workflow.installation, false, nil
}
