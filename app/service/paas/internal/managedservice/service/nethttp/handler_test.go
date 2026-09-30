package nethttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
	managedservicev1 "github.com/xiak/matrix/api/managedservice/v1"
	"github.com/xiak/matrix/app/service/paas/internal/managedservice/domain"
	"github.com/xiak/matrix/app/service/paas/internal/managedservice/port"
	"github.com/xiak/matrix/app/service/paas/internal/managedservice/usecase"
)

func TestListOfferingsAuthorizesCollectionAndFiltersExactCatalogInstances(t *testing.T) {
	authorizer := &stubAuthorizer{}
	workflow := &stubWorkflow{
		offerings: managedservicev1.ServiceOfferingList{Kind: "ServiceOfferingList", Items: domain.DefaultCatalog().List()},
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
	if len(authorizer.batchRequest.Requests) != 1 || authorizer.batchRequest.Requests[0].Resource.ID != domain.PostgreSQLOfferingID ||
		authorizer.batchRequest.Requests[0].ResourceMode != iamv1.AuthorizationResourceInstance {
		t.Fatalf("batch authorization request=%#v", authorizer.batchRequest)
	}
	var result managedservicev1.ServiceOfferingList
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil || result.Kind != "ServiceOfferingList" {
		t.Fatalf("response=%#v err=%v", result, err)
	}
}

func TestListOfferingsFiltersOnlyAllowedExactCandidates(t *testing.T) {
	offerings := domain.DefaultCatalog().List()
	second := offerings[0]
	second.ID = "postgresql-18-enterprise"
	second.DisplayName = "PostgreSQL 18 Enterprise"
	workflow := &stubWorkflow{offerings: managedservicev1.ServiceOfferingList{
		Kind: "ServiceOfferingList", Items: []managedservicev1.ServiceOffering{second, offerings[0]},
	}}
	authorizer := &stubAuthorizer{batchFunc: func(request port.AuthorizationBatchRequest) (port.AuthorizationBatch, error) {
		if len(request.Requests) != 2 || request.Requests[0].Resource.ID != offerings[0].ID ||
			request.Requests[1].Resource.ID != second.ID || request.Requests[0].RequestID == request.Requests[1].RequestID ||
			request.Requests[0].CorrelationID == "" || request.Requests[0].CorrelationID != request.Requests[1].CorrelationID {
			t.Fatalf("batch candidates were not exact, sorted and independently identified: %#v", request)
		}
		return port.AuthorizationBatch{
			TenantID: "organization-test", SubjectType: port.SubjectUser, SubjectID: "principal-test",
			Items: []port.AuthorizationBatchItem{
				{Resource: request.Requests[0].Resource, Allowed: true, DecisionID: "decision-allow", RequestID: request.Requests[0].RequestID},
				{Resource: request.Requests[1].Resource, Allowed: false, DecisionID: "decision-deny", RequestID: request.Requests[1].RequestID},
			},
		}, nil
	}}
	sequence := 0
	handler, err := NewHandler(authorizer, workflow, Config{NewRequestID: func() (string, error) {
		sequence++
		return fmt.Sprintf("request-list-%d", sequence), nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/managed-services/v1/offerings", nil)
	request.Header.Set("Authorization", "Bearer session-secret")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	var result managedservicev1.ServiceOfferingList
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &result) != nil ||
		len(result.Items) != 1 || result.Items[0].ID != offerings[0].ID {
		t.Fatalf("status=%d result=%#v body=%s", response.Code, result, response.Body.String())
	}
}

func TestListOfferingsAllDeniedReturnsAnEmptyAuthorizedList(t *testing.T) {
	offerings := domain.DefaultCatalog().List()
	authorizer := &stubAuthorizer{batchFunc: func(request port.AuthorizationBatchRequest) (port.AuthorizationBatch, error) {
		return port.AuthorizationBatch{
			TenantID: "organization-test", SubjectType: port.SubjectUser, SubjectID: "principal-test",
			Items: []port.AuthorizationBatchItem{{
				Resource: request.Requests[0].Resource, Allowed: false,
				DecisionID: "decision-denied", RequestID: request.Requests[0].RequestID,
			}},
		}, nil
	}}
	handler := testHandler(t, authorizer, &stubWorkflow{offerings: managedservicev1.ServiceOfferingList{Kind: "ServiceOfferingList", Items: offerings}})
	request := httptest.NewRequest(http.MethodGet, "/managed-services/v1/offerings", nil)
	request.Header.Set("Authorization", "Bearer session-secret")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	var result managedservicev1.ServiceOfferingList
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &result) != nil || result.Items == nil || len(result.Items) != 0 {
		t.Fatalf("status=%d result=%#v body=%s", response.Code, result, response.Body.String())
	}
}

func TestListOfferingsBatchMismatchAndOutageFailClosed(t *testing.T) {
	offerings := domain.DefaultCatalog().List()
	for name, authorizer := range map[string]*stubAuthorizer{
		"identity substitution": {batchFunc: func(request port.AuthorizationBatchRequest) (port.AuthorizationBatch, error) {
			return port.AuthorizationBatch{TenantID: "organization-other", SubjectType: port.SubjectUser, SubjectID: "principal-test",
				Items: []port.AuthorizationBatchItem{{Resource: request.Requests[0].Resource, Allowed: true, DecisionID: "decision-one", RequestID: request.Requests[0].RequestID}}}, nil
		}},
		"resource substitution": {batchFunc: func(request port.AuthorizationBatchRequest) (port.AuthorizationBatch, error) {
			return port.AuthorizationBatch{TenantID: "organization-test", SubjectType: port.SubjectUser, SubjectID: "principal-test",
				Items: []port.AuthorizationBatchItem{{Resource: port.ResourceReference{Kind: port.ResourceServiceOffering, ID: "offering-other"}, Allowed: true, DecisionID: "decision-one", RequestID: request.Requests[0].RequestID}}}, nil
		}},
		"authority unavailable": {batchFunc: func(port.AuthorizationBatchRequest) (port.AuthorizationBatch, error) {
			return port.AuthorizationBatch{}, port.ErrAuthorizationUnavailable
		}},
	} {
		t.Run(name, func(t *testing.T) {
			handler := testHandler(t, authorizer, &stubWorkflow{offerings: managedservicev1.ServiceOfferingList{Kind: "ServiceOfferingList", Items: offerings}})
			request := httptest.NewRequest(http.MethodGet, "/managed-services/v1/offerings", nil)
			request.Header.Set("Authorization", "Bearer session-secret")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), offerings[0].ID) {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
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

func TestGetInstallationOperationAuthorizesTheExactInstallation(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	authorizer := &stubAuthorizer{}
	workflow := &stubWorkflow{operation: managedservicev1.InstallationOperation{
		ID: "operation-1", Phase: managedservicev1.InstallationProvisioning, ObservedAt: now,
	}}
	handler := testHandler(t, authorizer, workflow)
	request := httptest.NewRequest(
		http.MethodGet,
		"/managed-services/v1/service-installations/postgres-primary/operation",
		nil,
	)
	request.Header.Set("Authorization", "Bearer session-secret")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if authorizer.request.Action != port.AuthorizeInstallationRead ||
		authorizer.request.Resource.Kind != port.ResourceServiceInstallation ||
		authorizer.request.Resource.ID != "postgres-primary" || workflow.operationReads != 1 {
		t.Fatalf("authorization=%#v operationReads=%d", authorizer.request, workflow.operationReads)
	}
	var result managedservicev1.InstallationOperation
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil || result.ID != "operation-1" {
		t.Fatalf("response=%#v err=%v", result, err)
	}
}

func TestBindServiceRoleUsesExactInstallationAndNoAuthoritySelectors(t *testing.T) {
	now := time.Date(2026, 9, 30, 8, 0, 0, 0, time.UTC)
	template := iamv1.ServiceRoleTemplateReference{
		ID: "managedservice.installation-reader", Version: 1,
		ContentDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	authorizer := &stubAuthorizer{}
	workflow := &stubWorkflow{roleReceipt: managedservicev1.ServiceRoleBindingReceipt{
		Kind: "ServiceRoleBindingReceipt", ServiceInstallationID: "postgres-primary",
		BindingID: "binding-one", RoleID: "role-one", Template: template,
		Status: iamv1.WorkloadRoleBindingActive, ResourceVersion: 1, CreatedAt: now,
	}}
	handler := testHandler(t, authorizer, workflow)
	request := httptest.NewRequest(http.MethodPost,
		"/managed-services/v1/service-installations/postgres-primary/service-role-bindings",
		strings.NewReader(`{"template":{"id":"managedservice.installation-reader","version":1,"contentDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}`))
	request.Header.Set("Authorization", "Bearer session-secret")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "bind-postgres-primary")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || workflow.bindCalls != 1 {
		t.Fatalf("status=%d calls=%d body=%s", response.Code, workflow.bindCalls, response.Body.String())
	}
	if authorizer.request.Action != port.AuthorizeInstallationRoleBind ||
		authorizer.request.Resource != (port.ResourceReference{Kind: port.ResourceServiceInstallation, ID: "postgres-primary"}) ||
		workflow.bindCommand.Credential != "Bearer session-secret" ||
		workflow.bindCommand.IdempotencyKey != "bind-postgres-primary" ||
		workflow.bindCommand.Request.Template != template {
		t.Fatalf("authorization=%#v command=%#v", authorizer.request, workflow.bindCommand)
	}
	for _, suffix := range []string{
		`?tenantId=forged`, `?roleId=forged`, `?purpose=PAAS`,
	} {
		attack := httptest.NewRequest(http.MethodPost,
			"/managed-services/v1/service-installations/postgres-primary/service-role-bindings"+suffix,
			strings.NewReader(`{"template":{"id":"managedservice.installation-reader","version":1,"contentDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}`))
		attack.Header = request.Header.Clone()
		attackResponse := httptest.NewRecorder()
		handler.ServeHTTP(attackResponse, attack)
		if attackResponse.Code != http.StatusBadRequest {
			t.Fatalf("selector %s status=%d body=%s", suffix, attackResponse.Code, attackResponse.Body.String())
		}
	}
	selectorBody := httptest.NewRequest(http.MethodPost,
		"/managed-services/v1/service-installations/postgres-primary/service-role-bindings",
		strings.NewReader(`{"template":{"id":"managedservice.installation-reader","version":1,"contentDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"accountId":"forged"}`))
	selectorBody.Header = request.Header.Clone()
	selectorResponse := httptest.NewRecorder()
	handler.ServeHTTP(selectorResponse, selectorBody)
	if selectorResponse.Code != http.StatusBadRequest {
		t.Fatalf("body selector status=%d body=%s", selectorResponse.Code, selectorResponse.Body.String())
	}
}

func TestUnbindServiceRoleUsesExactInstallationBindingAndNoAuthoritySelectors(t *testing.T) {
	now := time.Date(2026, 9, 30, 8, 0, 0, 0, time.UTC)
	template := iamv1.ServiceRoleTemplateReference{
		ID: "managedservice.installation-reader", Version: 1,
		ContentDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	authorizer := &stubAuthorizer{}
	workflow := &stubWorkflow{roleUnbindingReceipt: managedservicev1.ServiceRoleUnbindingReceipt{
		Kind: "ServiceRoleUnbindingReceipt", ServiceInstallationID: "postgres-primary",
		BindingID: "binding-one", RoleID: "role-one", Template: template,
		Status: iamv1.WorkloadRoleBindingRevoked, ResourceVersion: 2,
		CreatedAt: now, RevokedAt: now.Add(time.Second),
	}}
	handler := testHandler(t, authorizer, workflow)
	request := httptest.NewRequest(http.MethodDelete,
		"/managed-services/v1/service-installations/postgres-primary/service-role-bindings/binding-one",
		strings.NewReader(`{"resourceVersion":1}`))
	request.Header.Set("Authorization", "Bearer session-secret")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "unbind-postgres-primary")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || workflow.unbindCalls != 1 {
		t.Fatalf("status=%d calls=%d body=%s", response.Code, workflow.unbindCalls, response.Body.String())
	}
	if authorizer.request.Action != port.AuthorizeInstallationRoleUnbind ||
		authorizer.request.Resource != (port.ResourceReference{Kind: port.ResourceServiceInstallation, ID: "postgres-primary"}) ||
		workflow.unbindCommand.Credential != "Bearer session-secret" ||
		workflow.unbindCommand.InstallationID != "postgres-primary" || workflow.unbindCommand.BindingID != "binding-one" ||
		workflow.unbindCommand.IdempotencyKey != "unbind-postgres-primary" || workflow.unbindCommand.Request.ResourceVersion != 1 {
		t.Fatalf("authorization=%#v command=%#v", authorizer.request, workflow.unbindCommand)
	}
	for _, suffix := range []string{`?tenantId=forged`, `?roleId=forged`, `?purpose=PAAS`} {
		attack := httptest.NewRequest(http.MethodDelete,
			"/managed-services/v1/service-installations/postgres-primary/service-role-bindings/binding-one"+suffix,
			strings.NewReader(`{"resourceVersion":1}`))
		attack.Header = request.Header.Clone()
		attackResponse := httptest.NewRecorder()
		handler.ServeHTTP(attackResponse, attack)
		if attackResponse.Code != http.StatusBadRequest {
			t.Fatalf("selector %s status=%d body=%s", suffix, attackResponse.Code, attackResponse.Body.String())
		}
	}
	selectorBody := httptest.NewRequest(http.MethodDelete,
		"/managed-services/v1/service-installations/postgres-primary/service-role-bindings/binding-one",
		strings.NewReader(`{"resourceVersion":1,"accountId":"forged"}`))
	selectorBody.Header = request.Header.Clone()
	selectorResponse := httptest.NewRecorder()
	handler.ServeHTTP(selectorResponse, selectorBody)
	if selectorResponse.Code != http.StatusBadRequest {
		t.Fatalf("body selector status=%d body=%s", selectorResponse.Code, selectorResponse.Body.String())
	}
}

func TestResourceReadRejectsMalformedIdentityBeforeWorkflow(t *testing.T) {
	workflow := &stubWorkflow{}
	handler := testHandler(t, &stubAuthorizer{}, workflow)
	request := httptest.NewRequest(http.MethodGet, "/managed-services/v1/offerings/%20", nil)
	request.Header.Set("Authorization", "Bearer session-secret")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || workflow.offeringReads != 0 {
		t.Fatalf("status=%d reads=%d body=%s", response.Code, workflow.offeringReads, response.Body.String())
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
	request      port.AuthorizationRequest
	batchRequest port.AuthorizationBatchRequest
	batch        *port.AuthorizationBatch
	batchFunc    func(port.AuthorizationBatchRequest) (port.AuthorizationBatch, error)
	err          error
}

func (authorizer *stubAuthorizer) AuthorizeBatch(
	_ context.Context,
	request port.AuthorizationBatchRequest,
) (port.AuthorizationBatch, error) {
	authorizer.batchRequest = request
	if authorizer.err != nil {
		return port.AuthorizationBatch{}, authorizer.err
	}
	if authorizer.batchFunc != nil {
		return authorizer.batchFunc(request)
	}
	if authorizer.batch != nil {
		return *authorizer.batch, nil
	}
	result := port.AuthorizationBatch{
		TenantID: "organization-test", SubjectType: port.SubjectUser,
		SubjectID: "principal-test", Items: make([]port.AuthorizationBatchItem, len(request.Requests)),
	}
	for index, item := range request.Requests {
		result.Items[index] = port.AuthorizationBatchItem{
			Resource: item.Resource, Allowed: true,
			DecisionID: fmt.Sprintf("decision-batch-%d", index+1), RequestID: item.RequestID,
		}
	}
	return result, nil
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
		TenantID: "organization-test", SubjectType: port.SubjectUser,
		SubjectID:  "principal-test",
		DecisionID: "decision-test", RequestID: request.RequestID,
	}, nil
}

type stubWorkflow struct {
	offerings            managedservicev1.ServiceOfferingList
	installation         managedservicev1.ServiceInstallation
	operation            managedservicev1.InstallationOperation
	offeringReads        int
	operationReads       int
	activateCalls        int
	createCalls          int
	bindCalls            int
	bindCommand          usecase.BindServiceRoleCommand
	roleReceipt          managedservicev1.ServiceRoleBindingReceipt
	unbindCalls          int
	unbindCommand        usecase.UnbindServiceRoleCommand
	roleUnbindingReceipt managedservicev1.ServiceRoleUnbindingReceipt
}

func (workflow *stubWorkflow) ListOfferings(context.Context, port.Authorization) (managedservicev1.ServiceOfferingList, error) {
	return workflow.offerings, nil
}

func (workflow *stubWorkflow) GetOffering(context.Context, port.Authorization, string) (managedservicev1.ServiceOffering, error) {
	workflow.offeringReads++
	if len(workflow.offerings.Items) == 0 {
		return managedservicev1.ServiceOffering{}, usecase.ErrNotFound
	}
	return workflow.offerings.Items[0], nil
}

func (workflow *stubWorkflow) ListRegions(context.Context, port.Authorization) (managedservicev1.RegionList, error) {
	return managedservicev1.RegionList{Kind: "RegionList", Items: []managedservicev1.Region{}}, nil
}

func (workflow *stubWorkflow) GetRegion(context.Context, port.Authorization, string) (managedservicev1.Region, error) {
	return managedservicev1.Region{}, usecase.ErrNotFound
}

func (workflow *stubWorkflow) ListQuotaEntitlements(context.Context, port.Authorization) (managedservicev1.QuotaEntitlementList, error) {
	return managedservicev1.QuotaEntitlementList{Kind: "QuotaEntitlementList", Items: []managedservicev1.QuotaEntitlement{}}, nil
}

func (workflow *stubWorkflow) GetQuotaEntitlement(context.Context, port.Authorization, string) (managedservicev1.QuotaEntitlement, error) {
	return managedservicev1.QuotaEntitlement{}, usecase.ErrNotFound
}

func (workflow *stubWorkflow) ListServiceInstallations(context.Context, port.Authorization) (managedservicev1.ServiceInstallationList, error) {
	return managedservicev1.ServiceInstallationList{Kind: "ServiceInstallationList", Items: []managedservicev1.ServiceInstallation{}}, nil
}

func (workflow *stubWorkflow) GetServiceInstallation(context.Context, port.Authorization, string) (managedservicev1.ServiceInstallation, error) {
	return workflow.installation, nil
}

func (workflow *stubWorkflow) GetInstallationOperation(context.Context, port.Authorization, string) (managedservicev1.InstallationOperation, error) {
	workflow.operationReads++
	return workflow.operation, nil
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

func (workflow *stubWorkflow) BindServiceRole(
	_ context.Context,
	command usecase.BindServiceRoleCommand,
) (managedservicev1.ServiceRoleBindingReceipt, error) {
	workflow.bindCalls++
	workflow.bindCommand = command
	return workflow.roleReceipt, nil
}

func (workflow *stubWorkflow) UnbindServiceRole(
	_ context.Context,
	command usecase.UnbindServiceRoleCommand,
) (managedservicev1.ServiceRoleUnbindingReceipt, error) {
	workflow.unbindCalls++
	workflow.unbindCommand = command
	return workflow.roleUnbindingReceipt, nil
}
