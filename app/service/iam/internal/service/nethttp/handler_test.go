package nethttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/iam/internal/authority"
	"github.com/xiak/matrix/app/service/iam/internal/usecase/identityaccess"
)

func TestIAMHTTPExposesOnlyCredentialBoundCoreRoutes(t *testing.T) {
	workflow := newHTTPWorkflow(t)
	handler := newTestHandler(t, workflow)

	identityRequest := httptest.NewRequest(http.MethodGet, "/v1/service-identity", nil)
	identityRequest.Header.Set("Authorization", "Bearer service-credential")
	identityResponse := httptest.NewRecorder()
	handler.ServeHTTP(identityResponse, identityRequest)
	if identityResponse.Code != http.StatusOK || workflow.identityCalls != 1 {
		t.Fatalf("service identity status=%d calls=%d body=%s", identityResponse.Code, workflow.identityCalls, identityResponse.Body.String())
	}
	if identityResponse.Header().Get("Cache-Control") != "no-store" ||
		identityResponse.Header().Get("Matrix-Request-ID") != "request-http-test" {
		t.Fatalf("IAM security headers = %#v", identityResponse.Header())
	}
	var identity iamv1.ServiceIdentity
	if err := json.Unmarshal(identityResponse.Body.Bytes(), &identity); err != nil || identity != workflow.identity {
		t.Fatalf("decode service identity: identity=%#v err=%v", identity, err)
	}

	for name, target := range map[string]string{
		"tenant selector": "/v1/service-identity?tenantId=forged",
		"source selector": "/v1/service-identity?source=IAM",
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, target, nil)
			request.Header.Set("Authorization", "Bearer service-credential")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest || workflow.identityCalls != 1 {
				t.Fatalf("selector response status=%d calls=%d body=%s", response.Code, workflow.identityCalls, response.Body.String())
			}
		})
	}

	authorizeValue, err := iamv1.NewAuthorizationRequest(iamv1.ActionPaaSApplicationRead, workflow.decision.Resource, iamv1.AuthorizationResourceInstance, "", "request-authorize", "correlation-authorize")
	if err != nil {
		t.Fatal(err)
	}
	authorizeJSON, err := json.Marshal(authorizeValue)
	if err != nil {
		t.Fatal(err)
	}
	authorizeBody := string(authorizeJSON)
	missingSubject := httptest.NewRequest(http.MethodPost, "/v1/authorize", strings.NewReader(authorizeBody))
	missingSubject.Header.Set("Content-Type", "application/json")
	missingSubject.Header.Set("Authorization", "Bearer service-credential")
	missingSubjectResponse := httptest.NewRecorder()
	handler.ServeHTTP(missingSubjectResponse, missingSubject)
	if missingSubjectResponse.Code != http.StatusUnauthorized || workflow.authorizeCalls != 0 {
		t.Fatalf("missing subject status=%d calls=%d", missingSubjectResponse.Code, workflow.authorizeCalls)
	}

	authorizeRequest := httptest.NewRequest(http.MethodPost, "/v1/authorize", strings.NewReader(authorizeBody))
	authorizeRequest.Header.Set("Content-Type", "application/json")
	authorizeRequest.Header.Set("Authorization", "Bearer service-credential")
	authorizeRequest.Header.Set("Matrix-Subject-Credential", "subject-credential")
	authorizeResponse := httptest.NewRecorder()
	handler.ServeHTTP(authorizeResponse, authorizeRequest)
	if authorizeResponse.Code != http.StatusOK || workflow.authorizeCalls != 1 {
		t.Fatalf("authorize status=%d calls=%d body=%s", authorizeResponse.Code, workflow.authorizeCalls, authorizeResponse.Body.String())
	}
	var decision iamv1.AuthorizationDecision
	if err := json.Unmarshal(authorizeResponse.Body.Bytes(), &decision); err != nil || !reflect.DeepEqual(decision, workflow.decision) {
		t.Fatalf("decode authorization decision: decision=%#v err=%v", decision, err)
	}
	workflow.diagnosis = iamv1.CurrentAccessDiagnosis{
		APIVersion: iamv1.APIVersion, Kind: "CurrentAccessDiagnosis", Outcome: iamv1.AccessDiagnosisAllowed,
		TenantID: workflow.decision.TenantID, Subject: *workflow.decision.Subject,
		Action: authorizeValue.Action, Resource: authorizeValue.Resource, Profile: authorizeValue.Profile,
		ResourceMode: authorizeValue.ResourceMode, RequestID: authorizeValue.RequestID, CorrelationID: authorizeValue.CorrelationID,
		EvaluatedAt: workflow.decision.DecidedAt, Sources: []iamv1.AccessDiagnosisSource{}, Restrictions: []iamv1.AccessDiagnosisRestriction{},
		ResourceExistence: iamv1.AccessDiagnosisNotEvaluated, BusinessOutcome: iamv1.AccessDiagnosisNotEvaluated,
	}
	diagnoseRequest := httptest.NewRequest(http.MethodPost, "/v1/authorize:diagnose", strings.NewReader(authorizeBody))
	diagnoseRequest.Header.Set("Content-Type", "application/json")
	diagnoseRequest.Header.Set("Authorization", "Bearer service-credential")
	diagnoseRequest.Header.Set("Matrix-Subject-Credential", "subject-credential")
	diagnoseResponse := httptest.NewRecorder()
	handler.ServeHTTP(diagnoseResponse, diagnoseRequest)
	var diagnosis iamv1.CurrentAccessDiagnosis
	if diagnoseResponse.Code != http.StatusOK || workflow.diagnoseCalls != 1 ||
		json.Unmarshal(diagnoseResponse.Body.Bytes(), &diagnosis) != nil || !reflect.DeepEqual(diagnosis, workflow.diagnosis) {
		t.Fatalf("diagnose status=%d calls=%d diagnosis=%#v body=%s", diagnoseResponse.Code, workflow.diagnoseCalls, diagnosis, diagnoseResponse.Body.String())
	}
	for name, mutate := range map[string]func(*http.Request){
		"missing subject": func(request *http.Request) { request.Header.Del("Matrix-Subject-Credential") },
		"tenant selector": func(request *http.Request) { request.URL.RawQuery = "tenantId=forged" },
	} {
		t.Run("diagnose "+name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/v1/authorize:diagnose", strings.NewReader(authorizeBody))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Authorization", "Bearer service-credential")
			request.Header.Set("Matrix-Subject-Credential", "subject-credential")
			mutate(request)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusUnauthorized && response.Code != http.StatusBadRequest || workflow.diagnoseCalls != 1 {
				t.Fatalf("status=%d calls=%d body=%s", response.Code, workflow.diagnoseCalls, response.Body.String())
			}
		})
	}

	batchRequestValue := iamv1.AuthorizationBatchRequest{Requests: make([]iamv1.AuthorizationRequest, 2)}
	for index, sample := range []struct{ resource, requestID string }{{"offering-a", "request-batch-a"}, {"offering-b", "request-batch-b"}} {
		batchRequestValue.Requests[index], err = iamv1.NewAuthorizationRequest(
			iamv1.ActionManagedServiceOfferingRead,
			iamv1.ResourceReference{Kind: iamv1.ResourceServiceOffering, ID: sample.resource},
			iamv1.AuthorizationResourceInstance, "", sample.requestID, "correlation-batch",
		)
		if err != nil {
			t.Fatal(err)
		}
	}
	batchSubject := iamv1.Subject{Type: iamv1.SubjectUser, ID: "principal-admin"}
	workflow.batchDecision = iamv1.AuthorizationBatchDecision{
		APIVersion: iamv1.APIVersion, Kind: "AuthorizationBatchDecision",
		TenantID: "organization-example", Subject: batchSubject,
		Profile: batchRequestValue.Requests[0].Profile, Action: batchRequestValue.Requests[0].Action,
		ResourceKind:  batchRequestValue.Requests[0].Resource.Kind,
		CorrelationID: batchRequestValue.Requests[0].CorrelationID, DecidedAt: workflow.login.Session.IssuedAt,
		Decisions: make([]iamv1.AuthorizationDecision, len(batchRequestValue.Requests)),
	}
	for index, item := range batchRequestValue.Requests {
		allowed := index == 0
		workflow.batchDecision.Decisions[index] = iamv1.AuthorizationDecision{
			APIVersion: iamv1.APIVersion, Kind: "AuthorizationDecision", ID: iamv1.DecisionID(fmt.Sprintf("decision-batch-%d", index)),
			Allowed: allowed, Reason: iamv1.DecisionDenied, Action: item.Action, Resource: item.Resource,
			RequestID: item.RequestID, DecidedAt: workflow.batchDecision.DecidedAt, Profile: &item.Profile,
			ResourceMode: item.ResourceMode, CorrelationID: item.CorrelationID,
		}
		if allowed {
			workflow.batchDecision.Decisions[index].Reason = iamv1.DecisionAllowed
			workflow.batchDecision.Decisions[index].TenantID = workflow.batchDecision.TenantID
			workflow.batchDecision.Decisions[index].Subject = &batchSubject
		}
	}
	batchJSON, err := json.Marshal(batchRequestValue)
	if err != nil {
		t.Fatal(err)
	}
	missingBatchSubject := httptest.NewRequest(http.MethodPost, "/v1/authorize:batch", bytes.NewReader(batchJSON))
	missingBatchSubject.Header.Set("Content-Type", "application/json")
	missingBatchSubject.Header.Set("Authorization", "Bearer service-credential")
	missingBatchSubjectResponse := httptest.NewRecorder()
	handler.ServeHTTP(missingBatchSubjectResponse, missingBatchSubject)
	if missingBatchSubjectResponse.Code != http.StatusUnauthorized || workflow.authorizeBatchCalls != 0 {
		t.Fatalf("missing batch subject status=%d calls=%d", missingBatchSubjectResponse.Code, workflow.authorizeBatchCalls)
	}
	batchRequest := httptest.NewRequest(http.MethodPost, "/v1/authorize:batch", bytes.NewReader(batchJSON))
	batchRequest.Header.Set("Content-Type", "application/json")
	batchRequest.Header.Set("Authorization", "Bearer service-credential")
	batchRequest.Header.Set("Matrix-Subject-Credential", "subject-credential")
	batchResponse := httptest.NewRecorder()
	handler.ServeHTTP(batchResponse, batchRequest)
	var batchDecision iamv1.AuthorizationBatchDecision
	if batchResponse.Code != http.StatusOK || workflow.authorizeBatchCalls != 1 ||
		json.Unmarshal(batchResponse.Body.Bytes(), &batchDecision) != nil || !reflect.DeepEqual(batchDecision, workflow.batchDecision) ||
		!reflect.DeepEqual(workflow.authorizationBatchRequest, batchRequestValue) {
		t.Fatalf("batch authorize status=%d calls=%d decision=%#v body=%s", batchResponse.Code, workflow.authorizeBatchCalls, batchDecision, batchResponse.Body.String())
	}
	invalidBatch := httptest.NewRequest(http.MethodPost, "/v1/authorize:batch", strings.NewReader(`{"requests":[],"tenantId":"forged"}`))
	invalidBatch.Header.Set("Content-Type", "application/json")
	invalidBatch.Header.Set("Authorization", "Bearer service-credential")
	invalidBatch.Header.Set("Matrix-Subject-Credential", "subject-credential")
	invalidBatchResponse := httptest.NewRecorder()
	handler.ServeHTTP(invalidBatchResponse, invalidBatch)
	if invalidBatchResponse.Code != http.StatusBadRequest || workflow.authorizeBatchCalls != 1 {
		t.Fatalf("selector batch status=%d calls=%d body=%s", invalidBatchResponse.Code, workflow.authorizeBatchCalls, invalidBatchResponse.Body.String())
	}

	verifyValue, err := iamv1.NewAuthorizationRequest(iamv1.ActionInstallationVerify, workflow.verificationDecision.Resource, iamv1.AuthorizationResourceInstance, "", "request-installation-verify", "correlation-installation-verify")
	if err != nil {
		t.Fatal(err)
	}
	verifyJSON, err := json.Marshal(verifyValue)
	if err != nil {
		t.Fatal(err)
	}
	verifyBody := string(verifyJSON)
	verifyRequest := httptest.NewRequest(
		http.MethodPost, "/v1/installation:verify", strings.NewReader(verifyBody),
	)
	verifyRequest.Header.Set("Content-Type", "application/json")
	verifyRequest.Header.Set("Authorization", "Bearer verifier-credential")
	verifyResponse := httptest.NewRecorder()
	handler.ServeHTTP(verifyResponse, verifyRequest)
	if verifyResponse.Code != http.StatusOK || workflow.verifyInstallationCalls != 1 {
		t.Fatalf(
			"installation verify status=%d calls=%d body=%s",
			verifyResponse.Code, workflow.verifyInstallationCalls, verifyResponse.Body.String(),
		)
	}
	if err := json.Unmarshal(verifyResponse.Body.Bytes(), &decision); err != nil ||
		!reflect.DeepEqual(decision, workflow.verificationDecision) {
		t.Fatalf("decode installation verification decision: decision=%#v err=%v", decision, err)
	}

	unexpectedSubject := httptest.NewRequest(
		http.MethodPost, "/v1/installation:verify", strings.NewReader(verifyBody),
	)
	unexpectedSubject.Header.Set("Content-Type", "application/json")
	unexpectedSubject.Header.Set("Authorization", "Bearer verifier-credential")
	unexpectedSubject.Header.Set("Matrix-Subject-Credential", "user-session")
	unexpectedSubjectResponse := httptest.NewRecorder()
	handler.ServeHTTP(unexpectedSubjectResponse, unexpectedSubject)
	if unexpectedSubjectResponse.Code != http.StatusBadRequest || workflow.verifyInstallationCalls != 1 {
		t.Fatalf(
			"unexpected installation subject status=%d calls=%d",
			unexpectedSubjectResponse.Code, workflow.verifyInstallationCalls,
		)
	}
}

func TestSignedAuthorizationTransportDoesNotAcceptSubjectSelectors(t *testing.T) {
	workflow := newHTTPWorkflow(t)
	endpoint := newTestHandler(t, workflow)
	request, err := iamv1.NewAuthorizationRequest(iamv1.ActionPaaSApplicationRead, iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "application-signed"}, iamv1.AuthorizationResourceInstance, "", "signed-request", "signed-correlation")
	if err != nil {
		t.Fatal(err)
	}
	nonce, _ := iamv1.NewSecret(strings.Repeat("A", 22))
	signature, _ := iamv1.NewSecret(strings.Repeat("A", 43))
	input := iamv1.AccessKeyAuthorizationRequest{Authorization: request, SignedRequest: iamv1.AccessKeySignedRequest{
		Parameters: iamv1.AccessKeySignatureParameters{AccessKeyID: "key-one", InstallationID: "installation-one", Audience: "paas", SignedAt: 1700000000, Nonce: nonce},
		HTTP: iamv1.AccessKeyHTTPRequest{Method: "GET", Scheme: "https", Authority: "fixture.invalid:443", EscapedPath: "/api/paas/v1/applications/application-signed",
			BodyDigest: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}, Signature: signature}}
	body, err := iamv1.EncodeAccessKeyAuthorizationRequest(input)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(body)
	for _, name := range []string{"valid", "subject-header", "duplicate-bearer", "query-selector", "body-selector", "encoding", "method", "media"} {
		t.Run(name, func(t *testing.T) {
			wire := body
			if name == "body-selector" {
				wire = append(append([]byte(nil), body[:len(body)-1]...), []byte(`,"tenantId":"another-account"}`)...)
				defer clear(wire)
			}
			r := httptest.NewRequest(http.MethodPost, "/v1/authorize:access-key", bytes.NewReader(wire))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Authorization", "Bearer service-credential")
			want := http.StatusBadRequest
			switch name {
			case "valid":
				want = http.StatusOK
			case "subject-header":
				r.Header.Set("Matrix-Subject-Credential", "cannot-select-a-user")
			case "duplicate-bearer":
				r.Header.Add("Authorization", "Bearer another-service")
				want = http.StatusUnauthorized
			case "query-selector":
				r.URL.RawQuery = "tenantId=another-account"
			case "encoding":
				r.Header.Set("Content-Encoding", "gzip")
				want = http.StatusUnsupportedMediaType
			case "method":
				r.Method = http.MethodGet
				want = http.StatusMethodNotAllowed
			case "media":
				r.Header.Set("Content-Type", "application/json; charset=utf-8")
				want = http.StatusUnsupportedMediaType
			}
			before := workflow.keyCalls
			response := httptest.NewRecorder()
			endpoint.ServeHTTP(response, r)
			if response.Code != want {
				t.Fatalf("transport status=%d want=%d", response.Code, want)
			}
			if name == "valid" {
				result, err := iamv1.DecodeAccessKeyAuthorization(bytes.NewReader(response.Body.Bytes()))
				if err != nil || iamv1.CheckAccessKeyAuthorizationForRequest(result, input) != nil || workflow.keyCalls != before+1 || response.Header().Get("Cache-Control") != "no-store" {
					t.Fatal("signed wire or sanitized response differs", err)
				}
			} else if workflow.keyCalls != before {
				t.Fatal("invalid transport reached authority")
			}
		})
	}
}

func TestSignedListAuthorizationTransportDoesNotAcceptSubjectSelectors(t *testing.T) {
	workflow := newHTTPWorkflow(t)
	endpoint := newTestHandler(t, workflow)
	collection, err := iamv1.NewAuthorizationRequest(
		iamv1.ActionPaaSApplicationRead,
		iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "collection"},
		iamv1.AuthorizationResourceCollection,
		iamv1.AuthorizationCollectionList,
		"signed-list-collection",
		"signed-list-correlation",
	)
	if err != nil {
		t.Fatal(err)
	}
	instance := func(id, requestID string) iamv1.AuthorizationRequest {
		t.Helper()
		request, requestErr := iamv1.NewAuthorizationRequest(
			iamv1.ActionPaaSApplicationRead,
			iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: id},
			iamv1.AuthorizationResourceInstance,
			"",
			requestID,
			"signed-list-correlation",
		)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		return request
	}
	nonce, _ := iamv1.NewSecret(strings.Repeat("A", 22))
	signature, _ := iamv1.NewSecret(strings.Repeat("A", 43))
	input := iamv1.AccessKeyListAuthorizationRequest{
		Collection: collection,
		Instances: []iamv1.AuthorizationRequest{
			instance("application-a", "signed-list-a"),
			instance("application-b", "signed-list-b"),
		},
		SignedRequest: iamv1.AccessKeySignedRequest{
			Parameters: iamv1.AccessKeySignatureParameters{
				AccessKeyID: "key-one", InstallationID: "installation-one", Audience: iamv1.ProductPaaS,
				SignedAt: 1700000000, Nonce: nonce,
			},
			HTTP: iamv1.AccessKeyHTTPRequest{
				Method: "GET", Scheme: "https", Authority: "fixture.invalid:443", EscapedPath: "/api/paas/v1/applications",
				RawQuery: "after=cursor-one", BodyDigest: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			},
			Signature: signature,
		},
	}
	body, err := iamv1.EncodeAccessKeyListAuthorizationRequest(input)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(body)
	for _, name := range []string{"valid", "subject-header", "duplicate-bearer", "query-selector", "body-selector", "encoding", "method", "media"} {
		t.Run(name, func(t *testing.T) {
			wire := body
			if name == "body-selector" {
				wire = append(append([]byte(nil), body[:len(body)-1]...), []byte(`,"accountId":"another-account"}`)...)
				defer clear(wire)
			}
			request := httptest.NewRequest(http.MethodPost, "/v1/authorize:access-key-list", bytes.NewReader(wire))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Authorization", "Bearer service-credential")
			want := http.StatusBadRequest
			switch name {
			case "valid":
				want = http.StatusOK
			case "subject-header":
				request.Header.Set("Matrix-Subject-Credential", "cannot-select-a-user")
			case "duplicate-bearer":
				request.Header.Add("Authorization", "Bearer another-service")
				want = http.StatusUnauthorized
			case "query-selector":
				request.URL.RawQuery = "tenantId=another-account"
			case "encoding":
				request.Header.Set("Content-Encoding", "gzip")
				want = http.StatusUnsupportedMediaType
			case "method":
				request.Method = http.MethodGet
				want = http.StatusMethodNotAllowed
			case "media":
				request.Header.Set("Content-Type", "application/json; charset=utf-8")
				want = http.StatusUnsupportedMediaType
			}
			before := workflow.keyListCalls
			response := httptest.NewRecorder()
			endpoint.ServeHTTP(response, request)
			if response.Code != want {
				t.Fatalf("list transport status=%d want=%d", response.Code, want)
			}
			if name == "valid" {
				result, decodeErr := iamv1.DecodeAccessKeyListAuthorization(bytes.NewReader(response.Body.Bytes()))
				if decodeErr != nil || iamv1.CheckAccessKeyListAuthorizationForRequest(result, input) != nil ||
					workflow.keyListCalls != before+1 || !reflect.DeepEqual(workflow.keyListRequest, input) ||
					response.Header().Get("Cache-Control") != "no-store" {
					t.Fatal("signed list wire or sanitized response differs", decodeErr)
				}
			} else if workflow.keyListCalls != before {
				t.Fatal("invalid list transport reached authority")
			}
		})
	}
}

func TestSignedSubjectResolutionTransportIsExactAndNonAuthorizing(t *testing.T) {
	workflow := newHTTPWorkflow(t)
	endpoint := newTestHandler(t, workflow)
	profile, known := iamv1.LookupAuthorizationProfile(iamv1.ProductPaaS)
	if !known {
		t.Fatal("PaaS profile is unavailable")
	}
	_, profileDigest, err := iamv1.CanonicalizeAuthorizationProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	nonce, _ := iamv1.NewSecret(strings.Repeat("A", 22))
	signature, _ := iamv1.NewSecret(strings.Repeat("A", 43))
	input := iamv1.ResolveAccessKeySubjectRequest{
		Profile: iamv1.AuthorizationProfileReference{Product: profile.Product, Revision: profile.Revision, ContentDigest: profileDigest},
		SignedRequest: iamv1.AccessKeySignedRequest{
			Parameters: iamv1.AccessKeySignatureParameters{AccessKeyID: "key-one", InstallationID: "installation-one", Audience: iamv1.ProductPaaS, SignedAt: 1700000000, Nonce: nonce},
			HTTP: iamv1.AccessKeyHTTPRequest{Method: http.MethodGet, Scheme: "https", Authority: "fixture.invalid:443",
				EscapedPath: "/api/paas/v1/applications/application-signed", BodyDigest: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
			Signature: signature,
		},
	}
	body, err := iamv1.EncodeResolveAccessKeySubjectRequest(input)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(body)
	for _, name := range []string{"valid", "subject-header", "duplicate-bearer", "query-selector", "body-selector", "encoding", "method", "media"} {
		t.Run(name, func(t *testing.T) {
			wire := body
			if name == "body-selector" {
				wire = append(append([]byte(nil), body[:len(body)-1]...), []byte(`,"accountId":"another-account"}`)...)
				defer clear(wire)
			}
			request := httptest.NewRequest(http.MethodPost, "/v1/internal/access-key-subject:resolve", bytes.NewReader(wire))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Authorization", "Bearer service-credential")
			want := http.StatusBadRequest
			switch name {
			case "valid":
				want = http.StatusOK
			case "subject-header":
				request.Header.Set("Matrix-Subject-Credential", "cannot-select-a-user")
			case "duplicate-bearer":
				request.Header.Add("Authorization", "Bearer another-service")
				want = http.StatusUnauthorized
			case "query-selector":
				request.URL.RawQuery = "tenantId=another-account"
			case "encoding":
				request.Header.Set("Content-Encoding", "gzip")
				want = http.StatusUnsupportedMediaType
			case "method":
				request.Method = http.MethodGet
				want = http.StatusMethodNotAllowed
			case "media":
				request.Header.Set("Content-Type", "application/json; charset=utf-8")
				want = http.StatusUnsupportedMediaType
			}
			beforeResolve, beforeAuthorize := workflow.keyResolveCalls, workflow.keyCalls
			response := httptest.NewRecorder()
			endpoint.ServeHTTP(response, request)
			if response.Code != want {
				t.Fatalf("subject resolution status=%d want=%d body=%s", response.Code, want, response.Body.String())
			}
			if name == "valid" {
				var result iamv1.AccessKeySubjectContext
				if iamv1.DecodeRequest(bytes.NewReader(response.Body.Bytes()), &result) != nil ||
					iamv1.CheckAccessKeySubjectContextForRequest(result, input) != nil ||
					workflow.keyResolveCalls != beforeResolve+1 || workflow.keyCalls != beforeAuthorize ||
					response.Header().Get("Cache-Control") != "no-store" {
					t.Fatal("subject resolution issued a permit or changed its request binding")
				}
			} else if workflow.keyResolveCalls != beforeResolve || workflow.keyCalls != beforeAuthorize {
				t.Fatal("invalid subject resolution reached authority")
			}
		})
	}
}

func TestIAMHTTPAuthorizationProfileDiscoveryRequiresUserSession(t *testing.T) {
	workflow := newHTTPWorkflow(t)
	handler := newTestHandler(t, workflow)
	for _, test := range []struct {
		name, method, suffix, body, bearer string
		status                             int
	}{
		{"current metadata", http.MethodGet, "", "", "catalog-session", http.StatusOK},
		{"no bearer", http.MethodGet, "", "", "", http.StatusUnauthorized},
		{"account selector", http.MethodGet, "?accountId=other", "", "catalog-session", http.StatusBadRequest},
		{"history selector", http.MethodGet, "?revision=1", "", "catalog-session", http.StatusBadRequest},
		{"scope body", http.MethodGet, "", `{"scope":"INSTALLATION"}`, "catalog-session", http.StatusBadRequest},
		{"registration", http.MethodPost, "", `{}`, "catalog-session", http.StatusMethodNotAllowed},
	} {
		t.Run(test.name, func(t *testing.T) {
			before := workflow.policyCalls
			request := httptest.NewRequest(test.method, "/v1/authorization-profiles"+test.suffix, strings.NewReader(test.body))
			if test.bearer != "" {
				request.Header.Set("Authorization", "Bearer "+test.bearer)
			}
			request.Header.Set("Matrix-Tenant-ID", "forged-account")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("discovery status=%d want=%d", response.Code, test.status)
			}
			if test.status == http.StatusOK {
				wantedCredential, _ := iamv1.NewSecret(test.bearer)
				if workflow.policyCalls != before+1 || workflow.policyCredential != wantedCredential || response.Header().Get("Cache-Control") != "no-store" {
					t.Fatal("discovery lost its authenticated noncacheable workflow")
				}
				var result map[string]json.RawMessage
				if json.Unmarshal(response.Body.Bytes(), &result) != nil || string(result["kind"]) != `"AuthorizationProfileList"` || string(result["accountId"]) != `"account-catalog"` || len(result) != 4 {
					t.Fatal("discovery lost its strict current account envelope")
				}
			} else if workflow.policyCalls != before {
				t.Fatal("invalid discovery request reached the authority workflow")
			}
		})
	}
}

func TestIAMHTTPAuthenticationOverloadIsBoundedAndSanitized(t *testing.T) {
	response := httptest.NewRecorder()
	value := &handler{}
	value.writeError(response, httptest.NewRequest(http.MethodPost, "/v1/auth/login", nil), identityaccess.ErrOverloaded)
	if response.Code != http.StatusTooManyRequests || response.Header().Get("Retry-After") != "1" ||
		!strings.Contains(response.Body.String(), "iam.authentication.busy") || strings.Contains(response.Body.String(), "remaining") {
		t.Fatal("authentication overload lost its bounded public response")
	}
}

func TestIAMHTTPAuthorizationProfileDiscoveryRejectsInvalidMetadata(t *testing.T) {
	for _, test := range []struct {
		name    string
		failure error
		invalid bool
		status  int
	}{
		{"unauthenticated", identityaccess.ErrUnauthenticated, false, http.StatusUnauthorized},
		{"forbidden", identityaccess.ErrForbidden, false, http.StatusForbidden},
		{"unavailable", identityaccess.ErrUnavailable, false, http.StatusServiceUnavailable},
		{"invalid metadata", nil, true, http.StatusServiceUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			workflow := newHTTPWorkflow(t)
			workflow.profileErr, workflow.invalidProfile = test.failure, test.invalid
			request := httptest.NewRequest(http.MethodGet, "/v1/authorization-profiles", nil)
			request.Header.Set("Authorization", "Bearer catalog-session")
			response := httptest.NewRecorder()
			newTestHandler(t, workflow).ServeHTTP(response, request)
			if response.Code != test.status || workflow.policyCalls != 1 || strings.Contains(response.Body.String(), "AuthorizationProfileList") || strings.Contains(response.Body.String(), "contentDigest") {
				t.Fatal("directory failure leaked partial metadata or bypassed authority")
			}
		})
	}
}

func TestIAMHTTPServiceRoleTemplateDirectoryRequiresUserSession(t *testing.T) {
	workflow := newHTTPWorkflow(t)
	handler := newTestHandler(t, workflow)
	for _, test := range []struct {
		name, method, suffix, body, bearer string
		status                             int
	}{
		{"current templates", http.MethodGet, "", "", "template-session", http.StatusOK},
		{"no bearer", http.MethodGet, "", "", "", http.StatusUnauthorized},
		{"account selector", http.MethodGet, "?accountId=other", "", "template-session", http.StatusBadRequest},
		{"product selector", http.MethodGet, "?product=managedservice", "", "template-session", http.StatusBadRequest},
		{"purpose selector", http.MethodGet, "?purpose=PAAS", "", "template-session", http.StatusBadRequest},
		{"scope body", http.MethodGet, "", `{"installationId":"other"}`, "template-session", http.StatusBadRequest},
		{"registration", http.MethodPost, "", `{}`, "template-session", http.StatusMethodNotAllowed},
	} {
		t.Run(test.name, func(t *testing.T) {
			before := workflow.templateCalls
			request := httptest.NewRequest(test.method, "/v1/service-role-templates"+test.suffix, strings.NewReader(test.body))
			if test.bearer != "" {
				request.Header.Set("Authorization", "Bearer "+test.bearer)
			}
			request.Header.Set("Matrix-Tenant-ID", "forged-account")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("template directory status=%d want=%d body=%s", response.Code, test.status, response.Body.String())
			}
			if test.status == http.StatusOK {
				wantedCredential, _ := iamv1.NewSecret(test.bearer)
				var result iamv1.ServiceRoleTemplateList
				decoder := json.NewDecoder(response.Body)
				decoder.DisallowUnknownFields()
				expected, err := authority.BuiltInServiceRoleTemplates()
				if err != nil {
					t.Fatal(err)
				}
				if decoder.Decode(&result) != nil || iamv1.ValidateServiceRoleTemplateList(result) != nil ||
					!reflect.DeepEqual(result.Items, expected) || workflow.templateCalls != before+1 ||
					workflow.templateCredential != wantedCredential || response.Header().Get("Cache-Control") != "no-store" {
					t.Fatal("template directory lost its authenticated immutable projection")
				}
			} else if workflow.templateCalls != before {
				t.Fatal("invalid template request reached the authority workflow")
			}
		})
	}
}

func TestIAMHTTPServiceRoleTemplateDirectoryRejectsInvalidMetadata(t *testing.T) {
	for _, test := range []struct {
		name    string
		failure error
		invalid bool
		status  int
	}{
		{"unauthenticated", identityaccess.ErrUnauthenticated, false, http.StatusUnauthorized},
		{"forbidden", identityaccess.ErrForbidden, false, http.StatusForbidden},
		{"unavailable", identityaccess.ErrUnavailable, false, http.StatusServiceUnavailable},
		{"invalid template", nil, true, http.StatusServiceUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			workflow := newHTTPWorkflow(t)
			workflow.templateErr, workflow.invalidTemplate = test.failure, test.invalid
			request := httptest.NewRequest(http.MethodGet, "/v1/service-role-templates", nil)
			request.Header.Set("Authorization", "Bearer template-session")
			response := httptest.NewRecorder()
			newTestHandler(t, workflow).ServeHTTP(response, request)
			if response.Code != test.status || workflow.templateCalls != 1 ||
				strings.Contains(response.Body.String(), "ServiceRoleTemplate") || strings.Contains(response.Body.String(), "contentDigest") {
				t.Fatal("template directory failure leaked partial metadata or bypassed authority")
			}
		})
	}
}

func TestIAMHTTPServiceLinkedRoleDirectoryIsCurrentAccountOnly(t *testing.T) {
	workflow := newHTTPWorkflow(t)
	handler := newTestHandler(t, workflow)
	access := serviceLinkedRoleAccessForHTTPTest()
	roleID := access.Relation.Role.ID

	listRequest := httptest.NewRequest(http.MethodGet, "/v1/service-linked-roles", nil)
	listRequest.Header.Set("Authorization", "Bearer current-user")
	listRequest.Header.Set("Matrix-Tenant-ID", "forged-account")
	listResponse := httptest.NewRecorder()
	handler.ServeHTTP(listResponse, listRequest)
	var list iamv1.ServiceLinkedRoleList
	if listResponse.Code != http.StatusOK || json.Unmarshal(listResponse.Body.Bytes(), &list) != nil ||
		iamv1.ValidateServiceLinkedRoleList(list) != nil || len(list.Items) != 1 ||
		list.Items[0].Relation.Role.ID != roleID || list.Items[0].BindingCount != 1 ||
		list.Items[0].ActiveBindingCount != 1 || workflow.serviceLinkedRoleListCalls != 1 ||
		string(workflow.serviceLinkedRoleCredential.CopyBytes()) != "current-user" {
		t.Fatalf("service-linked role list status=%d body=%s", listResponse.Code, listResponse.Body.String())
	}

	detailRequest := httptest.NewRequest(http.MethodGet, "/v1/service-linked-roles/"+string(roleID), nil)
	detailRequest.Header.Set("Authorization", "Bearer current-user")
	detailResponse := httptest.NewRecorder()
	handler.ServeHTTP(detailResponse, detailRequest)
	var detail iamv1.ServiceLinkedRoleAccess
	if detailResponse.Code != http.StatusOK || json.Unmarshal(detailResponse.Body.Bytes(), &detail) != nil ||
		iamv1.ValidateServiceLinkedRoleAccess(detail) != nil || detail.Relation.Role.ID != roleID ||
		workflow.serviceLinkedRoleReadCalls != 1 || workflow.serviceLinkedRoleID != roleID {
		t.Fatalf("service-linked role detail status=%d body=%s", detailResponse.Code, detailResponse.Body.String())
	}

	for _, test := range []struct {
		name, method, target, body string
		status                     int
	}{
		{"list account selector", http.MethodGet, "/v1/service-linked-roles?accountId=other", "", http.StatusBadRequest},
		{"list body selector", http.MethodGet, "/v1/service-linked-roles", `{"tenantId":"other"}`, http.StatusBadRequest},
		{"list mutation", http.MethodPost, "/v1/service-linked-roles", `{}`, http.StatusMethodNotAllowed},
		{"detail account selector", http.MethodGet, "/v1/service-linked-roles/" + string(roleID) + "?tenantId=other", "", http.StatusBadRequest},
		{"detail body selector", http.MethodGet, "/v1/service-linked-roles/" + string(roleID), `{"templateId":"other"}`, http.StatusBadRequest},
		{"detail nested path", http.MethodGet, "/v1/service-linked-roles/" + string(roleID) + "/bindings", "", http.StatusNotFound},
		{"detail mutation", http.MethodDelete, "/v1/service-linked-roles/" + string(roleID), "", http.StatusMethodNotAllowed},
		{"missing bearer", http.MethodGet, "/v1/service-linked-roles", "", http.StatusUnauthorized},
	} {
		t.Run(test.name, func(t *testing.T) {
			beforeList, beforeRead := workflow.serviceLinkedRoleListCalls, workflow.serviceLinkedRoleReadCalls
			request := httptest.NewRequest(test.method, test.target, strings.NewReader(test.body))
			if test.name != "missing bearer" {
				request.Header.Set("Authorization", "Bearer current-user")
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status || workflow.serviceLinkedRoleListCalls != beforeList ||
				workflow.serviceLinkedRoleReadCalls != beforeRead {
				t.Fatalf("invalid service-linked role read status=%d want=%d body=%s", response.Code, test.status, response.Body.String())
			}
		})
	}
}

func TestIAMHTTPServiceLinkedRoleDirectoryRejectsInvalidWorkflowOutput(t *testing.T) {
	for _, detail := range []bool{false, true} {
		workflow := newHTTPWorkflow(t)
		workflow.invalidServiceLinkedRole = true
		access := serviceLinkedRoleAccessForHTTPTest()
		target := "/v1/service-linked-roles"
		if detail {
			target += "/" + string(access.Relation.Role.ID)
		}
		request := httptest.NewRequest(http.MethodGet, target, nil)
		request.Header.Set("Authorization", "Bearer current-user")
		response := httptest.NewRecorder()
		newTestHandler(t, workflow).ServeHTTP(response, request)
		if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), "service-linked") {
			t.Fatalf("invalid directory output leaked at %s: status=%d body=%s", target, response.Code, response.Body.String())
		}
	}
}

func TestIAMHTTPWorkloadRoleBindingRequiresExactlyTwoCredentialsAndNoSelectors(t *testing.T) {
	workflow := newHTTPWorkflow(t)
	handler := newTestHandler(t, workflow)
	templates, err := authority.BuiltInServiceRoleTemplates()
	if err != nil || len(templates) != 1 {
		t.Fatal(err)
	}
	authorization, err := iamv1.NewAuthorizationRequest(iamv1.ActionManagedServiceInstallationRoleBind,
		iamv1.ResourceReference{Kind: iamv1.ResourceServiceInstallation, ID: "service-installation-a"},
		iamv1.AuthorizationResourceInstance, "", "binding-command", "binding-command")
	if err != nil {
		t.Fatal(err)
	}
	command := iamv1.CreateWorkloadRoleBindingRequest{Template: templates[0].Reference(), Authorization: authorization}
	body, err := json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, method, suffix, body, service, subject string
		status                                       int
	}{
		{"valid", http.MethodPost, "", string(body), "paas-service", "current-user", http.StatusOK},
		{"missing service", http.MethodPost, "", string(body), "", "current-user", http.StatusUnauthorized},
		{"missing subject", http.MethodPost, "", string(body), "paas-service", "", http.StatusUnauthorized},
		{"query account", http.MethodPost, "?accountId=other", string(body), "paas-service", "current-user", http.StatusBadRequest},
		{"wrong method", http.MethodPut, "", string(body), "paas-service", "current-user", http.StatusMethodNotAllowed},
		{"body account", http.MethodPost, "", string(body[:len(body)-1]) + `,"accountId":"other"}`, "paas-service", "current-user", http.StatusBadRequest},
		{"body role", http.MethodPost, "", string(body[:len(body)-1]) + `,"roleId":"other"}`, "paas-service", "current-user", http.StatusBadRequest},
		{"body service", http.MethodPost, "", string(body[:len(body)-1]) + `,"servicePrincipalId":"other"}`, "paas-service", "current-user", http.StatusBadRequest},
	} {
		t.Run(test.name, func(t *testing.T) {
			before := workflow.workloadBindingCalls
			request := httptest.NewRequest(test.method, "/v1/internal/workload-role-bindings"+test.suffix, strings.NewReader(test.body))
			request.Header.Set("Content-Type", "application/json")
			if test.service != "" {
				request.Header.Set("Authorization", "Bearer "+test.service)
			}
			if test.subject != "" {
				request.Header.Set("Matrix-Subject-Credential", test.subject)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("workload binding status=%d want=%d body=%s", response.Code, test.status, response.Body.String())
			}
			if test.status == http.StatusOK {
				if workflow.workloadBindingCalls != before+1 || string(workflow.workloadServiceCredential.CopyBytes()) != test.service ||
					string(workflow.workloadSubjectCredential.CopyBytes()) != test.subject || !reflect.DeepEqual(workflow.workloadBindingRequest, command) {
					t.Fatal("dual-credential command lost its exact authenticated input")
				}
				var result iamv1.ServiceLinkedRoleAccess
				if json.Unmarshal(response.Body.Bytes(), &result) != nil || iamv1.ValidateServiceLinkedRoleAccess(result) != nil {
					t.Fatal("workload binding response is invalid")
				}
			} else if workflow.workloadBindingCalls != before {
				t.Fatal("invalid transport reached workload binding workflow")
			}
		})
	}
}

func TestIAMHTTPWorkloadRoleBindingRevocationRequiresExactPathAndTwoCredentials(t *testing.T) {
	workflow := newHTTPWorkflow(t)
	handler := newTestHandler(t, workflow)
	authorization, err := iamv1.NewAuthorizationRequest(iamv1.ActionManagedServiceInstallationRoleUnbind,
		iamv1.ResourceReference{Kind: iamv1.ResourceServiceInstallation, ID: "service-installation-a"},
		iamv1.AuthorizationResourceInstance, "", "binding-revoke", "binding-revoke")
	if err != nil {
		t.Fatal(err)
	}
	command := iamv1.RevokeWorkloadRoleBindingRequest{Authorization: authorization, ResourceVersion: 1}
	body, err := json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, method, suffix, body, service, subject string
		status                                       int
	}{
		{"valid", http.MethodDelete, "", string(body), "paas-service", "current-user", http.StatusOK},
		{"missing service", http.MethodDelete, "", string(body), "", "current-user", http.StatusUnauthorized},
		{"missing subject", http.MethodDelete, "", string(body), "paas-service", "", http.StatusUnauthorized},
		{"query account", http.MethodDelete, "?accountId=other", string(body), "paas-service", "current-user", http.StatusBadRequest},
		{"nested path", http.MethodDelete, "/other", string(body), "paas-service", "current-user", http.StatusNotFound},
		{"wrong method", http.MethodPost, "", string(body), "paas-service", "current-user", http.StatusMethodNotAllowed},
		{"body account", http.MethodDelete, "", string(body[:len(body)-1]) + `,"accountId":"other"}`, "paas-service", "current-user", http.StatusBadRequest},
		{"body role", http.MethodDelete, "", string(body[:len(body)-1]) + `,"roleId":"other"}`, "paas-service", "current-user", http.StatusBadRequest},
		{"body template", http.MethodDelete, "", string(body[:len(body)-1]) + `,"template":{"id":"other"}}`, "paas-service", "current-user", http.StatusBadRequest},
	} {
		t.Run(test.name, func(t *testing.T) {
			before := workflow.workloadRevocationCalls
			request := httptest.NewRequest(test.method, "/v1/internal/workload-role-bindings/binding-service-linked"+test.suffix, strings.NewReader(test.body))
			request.Header.Set("Content-Type", "application/json")
			if test.service != "" {
				request.Header.Set("Authorization", "Bearer "+test.service)
			}
			if test.subject != "" {
				request.Header.Set("Matrix-Subject-Credential", test.subject)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("workload revocation status=%d want=%d body=%s", response.Code, test.status, response.Body.String())
			}
			if test.status == http.StatusOK {
				if workflow.workloadRevocationCalls != before+1 || workflow.workloadRevocationID != "binding-service-linked" ||
					string(workflow.workloadRevokeServiceCredential.CopyBytes()) != test.service ||
					string(workflow.workloadRevokeSubjectCredential.CopyBytes()) != test.subject ||
					!reflect.DeepEqual(workflow.workloadRevocationRequest, command) {
					t.Fatal("dual-credential revocation lost its exact authenticated input")
				}
				var result iamv1.WorkloadRoleBinding
				if json.Unmarshal(response.Body.Bytes(), &result) != nil || iamv1.ValidateWorkloadRoleBinding(result) != nil ||
					result.Status != iamv1.WorkloadRoleBindingRevoked {
					t.Fatal("workload revocation response is invalid")
				}
			} else if workflow.workloadRevocationCalls != before {
				t.Fatal("invalid revocation reached the workflow")
			}
		})
	}
}

func TestIAMHTTPServiceRoleSessionUsesOnlyCurrentServiceCredential(t *testing.T) {
	workflow := newHTTPWorkflow(t)
	credential, err := iamv1.NewSecret("issued-service-role-credential")
	if err != nil {
		t.Fatal(err)
	}
	now := workflow.login.Session.IssuedAt
	workflow.serviceRoleSessionResult = iamv1.AssumeRoleResponse{Outcome: "APPLIED", Credential: credential,
		Session: iamv1.RoleSession{APIVersion: iamv1.APIVersion, Kind: "RoleSession", ID: "role-session-service",
			AccountID: "account-customer", RoleID: "role-service-linked", SourceServicePrincipalID: "service-paas",
			Status: iamv1.SessionActive, IssuedAt: now, ExpiresAt: now.Add(15 * time.Minute)}}
	workflow.serviceRoleSessionFound = true
	handler := newTestHandler(t, workflow)
	duration := uint32(600)
	command := iamv1.AssumeServiceRoleRequest{BindingID: "binding-service-linked", DurationSeconds: &duration, RequestID: "assume-service-role"}
	body, err := json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodPost, "/v1/internal/service-role-sessions", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer current-paas-service")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	var issued struct {
		Outcome    string            `json:"outcome"`
		Session    iamv1.RoleSession `json:"session"`
		Credential string            `json:"credential"`
	}
	decoder := json.NewDecoder(response.Body)
	decoder.DisallowUnknownFields()
	if response.Code != http.StatusOK || decoder.Decode(&issued) != nil || issued.Outcome != "APPLIED" ||
		iamv1.ValidateRoleSession(issued.Session) != nil || issued.Credential != "issued-service-role-credential" ||
		workflow.serviceRoleSessionCalls != 1 || !reflect.DeepEqual(workflow.serviceRoleSessionRequest, command) ||
		string(workflow.serviceRoleSessionCredential.CopyBytes()) != "current-paas-service" {
		t.Fatalf("service RoleSession issue status=%d body=%s", response.Code, response.Body.String())
	}

	read := httptest.NewRequest(http.MethodGet, "/v1/internal/service-role-sessions/by-request/assume-service-role", nil)
	read.Header.Set("Authorization", "Bearer current-paas-service")
	readResponse := httptest.NewRecorder()
	handler.ServeHTTP(readResponse, read)
	var retained iamv1.RoleSession
	if readResponse.Code != http.StatusOK || json.Unmarshal(readResponse.Body.Bytes(), &retained) != nil ||
		retained != workflow.serviceRoleSessionResult.Session || workflow.serviceRoleSessionReadCalls != 1 ||
		workflow.serviceRoleSessionReadRequestID != command.RequestID ||
		string(workflow.serviceRoleSessionReadCredential.CopyBytes()) != "current-paas-service" ||
		strings.Contains(readResponse.Body.String(), "issued-service-role-credential") {
		t.Fatalf("service RoleSession receipt status=%d body=%s", readResponse.Code, readResponse.Body.String())
	}

	for _, test := range []struct {
		name, method, target, body, bearer, subject string
		status                                      int
	}{
		{"issue missing bearer", http.MethodPost, "/v1/internal/service-role-sessions", string(body), "", "", http.StatusUnauthorized},
		{"issue second carrier", http.MethodPost, "/v1/internal/service-role-sessions", string(body), "current-paas-service", "user-session", http.StatusBadRequest},
		{"issue account query", http.MethodPost, "/v1/internal/service-role-sessions?accountId=other", string(body), "current-paas-service", "", http.StatusBadRequest},
		{"issue account body", http.MethodPost, "/v1/internal/service-role-sessions", string(body[:len(body)-1]) + `,"accountId":"other"}`, "current-paas-service", "", http.StatusBadRequest},
		{"issue role body", http.MethodPost, "/v1/internal/service-role-sessions", string(body[:len(body)-1]) + `,"roleId":"other"}`, "current-paas-service", "", http.StatusBadRequest},
		{"issue service body", http.MethodPost, "/v1/internal/service-role-sessions", string(body[:len(body)-1]) + `,"servicePrincipalId":"other"}`, "current-paas-service", "", http.StatusBadRequest},
		{"issue wrong method", http.MethodPut, "/v1/internal/service-role-sessions", string(body), "current-paas-service", "", http.StatusMethodNotAllowed},
		{"read second carrier", http.MethodGet, "/v1/internal/service-role-sessions/by-request/assume-service-role", "", "current-paas-service", "user-session", http.StatusBadRequest},
		{"read selector", http.MethodGet, "/v1/internal/service-role-sessions/by-request/assume-service-role?principalId=other", "", "current-paas-service", "", http.StatusBadRequest},
		{"read body", http.MethodGet, "/v1/internal/service-role-sessions/by-request/assume-service-role", `{}`, "current-paas-service", "", http.StatusBadRequest},
		{"read nested path", http.MethodGet, "/v1/internal/service-role-sessions/by-request/assume-service-role/other", "", "current-paas-service", "", http.StatusNotFound},
		{"read wrong method", http.MethodPost, "/v1/internal/service-role-sessions/by-request/assume-service-role", `{}`, "current-paas-service", "", http.StatusMethodNotAllowed},
	} {
		t.Run(test.name, func(t *testing.T) {
			beforeIssue, beforeRead := workflow.serviceRoleSessionCalls, workflow.serviceRoleSessionReadCalls
			request := httptest.NewRequest(test.method, test.target, strings.NewReader(test.body))
			request.Header.Set("Content-Type", "application/json")
			if test.bearer != "" {
				request.Header.Set("Authorization", "Bearer "+test.bearer)
			}
			if test.subject != "" {
				request.Header.Set("Matrix-Subject-Credential", test.subject)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status || workflow.serviceRoleSessionCalls != beforeIssue ||
				workflow.serviceRoleSessionReadCalls != beforeRead {
				t.Fatalf("invalid service RoleSession request status=%d want=%d body=%s", response.Code, test.status, response.Body.String())
			}
		})
	}

	workflow.serviceRoleSessionFound = false
	notFound := httptest.NewRequest(http.MethodGet, "/v1/internal/service-role-sessions/by-request/unknown-intent", nil)
	notFound.Header.Set("Authorization", "Bearer current-paas-service")
	notFoundResponse := httptest.NewRecorder()
	handler.ServeHTTP(notFoundResponse, notFound)
	if notFoundResponse.Code != http.StatusNotFound || strings.Contains(notFoundResponse.Body.String(), "role-session-service") {
		t.Fatalf("unknown receipt status=%d body=%s", notFoundResponse.Code, notFoundResponse.Body.String())
	}
}

func TestIAMHTTPPolicyDirectoriesDeriveScopeOnlyFromRoute(t *testing.T) {
	workflow := newHTTPWorkflow(t)
	handler := newTestHandler(t, workflow)
	for _, route := range []string{"/v1/policies", "/v1/platform-policies"} {
		for _, test := range []struct {
			name, method, suffix, body, bearer string
			status                             int
		}{
			{"read", http.MethodGet, "", "", "catalog-session", http.StatusOK},
			{"query scope", http.MethodGet, "?scope=INSTALLATION", "", "catalog-session", http.StatusBadRequest},
			{"query account", http.MethodGet, "?accountId=other", "", "catalog-session", http.StatusBadRequest},
			{"body selector", http.MethodGet, "", `{"installationId":"other"}`, "catalog-session", http.StatusBadRequest},
			{"missing bearer", http.MethodGet, "", "", "", http.StatusUnauthorized},
			{"wrong method", http.MethodPut, "", "", "catalog-session", http.StatusMethodNotAllowed},
		} {
			t.Run(route+"/"+test.name, func(t *testing.T) {
				before := workflow.policyCalls
				request := httptest.NewRequest(test.method, route+test.suffix, strings.NewReader(test.body))
				if test.bearer != "" {
					request.Header.Set("Authorization", "Bearer "+test.bearer)
				}
				request.Header.Set("Matrix-Tenant-ID", "forged-header")
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, request)
				if response.Code != test.status {
					t.Fatalf("status=%d want=%d", response.Code, test.status)
				}
				if test.status != http.StatusOK {
					if workflow.policyCalls != before {
						t.Fatal("invalid request reached directory workflow")
					}
					return
				}
				wantedCredential, _ := iamv1.NewSecret(test.bearer)
				if workflow.policyCalls != before+1 || workflow.policyPlatform != (route == "/v1/platform-policies") || workflow.policyCredential != wantedCredential {
					t.Fatal("directory route or credential changed")
				}
				var result iamv1.PolicyList
				if json.Unmarshal(response.Body.Bytes(), &result) != nil || iamv1.ValidatePolicyList(result) != nil || result.AccountID != "account-catalog" {
					t.Fatal("directory lost authoritative account")
				}
			})
		}
	}
}

func TestIAMHTTPPasswordRequirementsKeepOneIdentityCarrier(t *testing.T) {
	const own = "/v1/auth/password-requirements"
	const challenge = "/v1/auth/challenges/challenge-one/password-requirements"
	const body = `{"challengeCredential":"synthetic-challenge-secret"}`
	for _, sample := range []struct {
		name, method, path, body, bearer, subject string
		status                                    int
	}{
		{"self", http.MethodGet, own, "", "Bearer self-secret", "", 200},
		{"challenge", http.MethodPost, challenge, body, "", "", 200},
		{"unauthenticated", http.MethodGet, own, "", "", "", 401},
		{"self-query", http.MethodGet, own + "?userId=another", "", "Bearer self-secret", "", 400},
		{"self-body", http.MethodGet, own, `{}`, "Bearer self-secret", "", 400},
		{"self-method", http.MethodPost, own, "", "Bearer self-secret", "", 405},
		{"self-second-carrier", http.MethodGet, own, "", "Bearer self-secret", "other-secret", 400},
		{"challenge-bearer", http.MethodPost, challenge, body, "Bearer self-secret", "", 400},
		{"challenge-subject", http.MethodPost, challenge, body, "", "other-secret", 400},
		{"challenge-query", http.MethodPost, challenge + "?accountId=another", body, "", "", 400},
		{"challenge-selector", http.MethodPost, challenge, `{"challengeCredential":"secret","userId":"another"}`, "", "", 400},
		{"challenge-missing", http.MethodPost, challenge, `{}`, "", "", 400},
		{"challenge-null", http.MethodPost, challenge, `{"challengeCredential":null}`, "", "", 400},
		{"challenge-duplicate", http.MethodPost, challenge, `{"challengeCredential":"one","challengeCredential":"two"}`, "", "", 400},
		{"challenge-method", http.MethodGet, challenge, body, "", "", 405},
		{"challenge-nested", http.MethodPost, "/v1/auth/challenges/one/two/password-requirements", body, "", "", 404},
	} {
		t.Run(sample.name, func(t *testing.T) {
			workflow := newHTTPWorkflow(t)
			workflow.passwordRequirements = iamv1.PasswordRequirements{APIVersion: iamv1.APIVersion, Kind: "PasswordRequirements",
				Password: iamv1.AccountPasswordSettings{ExpiryMode: iamv1.PasswordExpiryChange, MinimumLength: 24, HistoryCount: 3}, MaximumLength: 128, MaximumUTF8Bytes: 512, SettingsVersion: 2, Source: "ACCOUNT"}
			request := httptest.NewRequest(sample.method, sample.path, strings.NewReader(sample.body))
			request.Header.Set("Content-Type", "application/json")
			if sample.bearer != "" {
				request.Header.Set("Authorization", sample.bearer)
			}
			if sample.subject != "" {
				request.Header.Set("Matrix-Subject-Credential", sample.subject)
			}
			response := httptest.NewRecorder()
			newTestHandler(t, workflow).ServeHTTP(response, request)
			if response.Code != sample.status || response.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("status=%d want=%d", response.Code, sample.status)
			}
			if sample.status != 200 {
				if workflow.passwordRequirementsCalls != 0 {
					t.Fatal("ambiguous input reached workflow")
				}
				return
			}
			var got iamv1.PasswordRequirements
			if json.Unmarshal(response.Body.Bytes(), &got) != nil || got != workflow.passwordRequirements || workflow.passwordRequirementsCalls != 1 {
				t.Fatal("effective requirements not preserved")
			}
			if sample.path == own && !bytes.Equal(workflow.passwordRequirementsBearer.CopyBytes(), []byte("self-secret")) {
				t.Fatal("actual bearer lost")
			}
			if sample.path == challenge && (workflow.verifiedChallengeID != "challenge-one" || !bytes.Equal(workflow.enrollmentCredential.CopyBytes(), []byte("synthetic-challenge-secret"))) {
				t.Fatal("original challenge identity lost")
			}
		})
	}
	for _, path := range []string{own, challenge} {
		for _, failure := range []error{nil, identityaccess.ErrUnauthenticated, identityaccess.ErrUnavailable} {
			workflow := newHTTPWorkflow(t)
			workflow.passwordRequirementsError = failure // nil still has an invalid result.
			method, input := http.MethodGet, ""
			if path == challenge {
				method, input = http.MethodPost, body
			}
			request := httptest.NewRequest(method, path, strings.NewReader(input))
			request.Header.Set("Content-Type", "application/json")
			if path == own {
				request.Header.Set("Authorization", "Bearer self-secret")
			}
			response := httptest.NewRecorder()
			newTestHandler(t, workflow).ServeHTTP(response, request)
			wanted := http.StatusServiceUnavailable
			if failure == identityaccess.ErrUnauthenticated {
				wanted = http.StatusUnauthorized
			}
			if response.Code != wanted || strings.Contains(response.Body.String(), "maximumLength") {
				t.Fatal("failed observation disclosed rules")
			}
		}
	}
}

func TestIAMHTTPChallengePasswordRejectsAmbiguousCarriers(t *testing.T) {
	const route = "/v1/auth/challenges/challenge-one:password"
	const valid = `{"requestId":"change-one","challengeCredential":"synthetic-challenge-secret","newPassword":"Synthetic-New-Password-827!"}`
	for _, sample := range []struct {
		name, path, method, body, authorization string
		status                                  int
	}{
		{"valid-reaches-workflow", route, http.MethodPost, valid, "", http.StatusServiceUnavailable},
		{"bearer-and-challenge", route, http.MethodPost, valid, "Bearer synthetic-session", http.StatusBadRequest},
		{"query-selector", route + "?userId=other", http.MethodPost, valid, "", http.StatusBadRequest},
		{"body-selector", route, http.MethodPost, strings.Replace(valid, `"requestId":`, `"accountId":"other","requestId":`, 1), "", http.StatusBadRequest},
		{"retain-session", route, http.MethodPost, strings.Replace(valid, `"requestId":`, `"revokeOtherSessions":false,"requestId":`, 1), "", http.StatusBadRequest},
		{"old-password", route, http.MethodPost, strings.Replace(valid, `"requestId":`, `"currentPassword":"old","requestId":`, 1), "", http.StatusBadRequest},
		{"null-password", route, http.MethodPost, strings.Replace(valid, `"Synthetic-New-Password-827!"`, `null`, 1), "", http.StatusBadRequest},
		{"duplicate-credential", route, http.MethodPost, strings.Replace(valid, `"requestId":`, `"challengeCredential":"other","requestId":`, 1), "", http.StatusBadRequest},
		{"wrong-method", route, http.MethodGet, valid, "", http.StatusMethodNotAllowed},
	} {
		t.Run(sample.name, func(t *testing.T) {
			workflow := newHTTPWorkflow(t)
			request := httptest.NewRequest(sample.method, sample.path, strings.NewReader(sample.body))
			request.Header.Set("Content-Type", "application/json")
			if sample.authorization != "" {
				request.Header.Set("Authorization", sample.authorization)
			}
			response := httptest.NewRecorder()
			newTestHandler(t, workflow).ServeHTTP(response, request)
			if response.Code != sample.status || response.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("restricted password transport differs", response.Code)
			}
			if (workflow.verifiedChallengeID != "") != (sample.status == http.StatusServiceUnavailable) {
				t.Fatal("invalid request reached password workflow")
			}
			if strings.Contains(response.Body.String(), "synthetic-challenge-secret") || strings.Contains(response.Body.String(), "Synthetic-New-Password-827!") {
				t.Fatal("password problem exposed authentication material")
			}
		})
	}
}

func TestIAMHTTPInitialEnrollmentKeepsOneCredentialAndOriginalIntent(t *testing.T) {
	const base = "/v1/auth/challenges/initial-one"
	const credential = `"challengeCredential":"synthetic-initial-secret"`
	for _, command := range []struct{ name, path, body, requestID, verificationID string }{
		{"inspect", base + ":enrollment-state", `{` + credential + `}`, "", ""},
		{"start-factor", base + ":enroll", `{` + credential + `,"requestId":"first-factor"}`, "first-factor", ""},
		{"confirm-factor", base + ":confirm-enrollment", `{` + credential + `,"requestId":"confirm-factor","code":"not-an-otp"}`, "confirm-factor", ""},
		{"start-contact", base + "/notification-contact/verifications", `{` + credential + `,"requestId":"first-contact","email":"first@example.invalid"}`, "first-contact", ""},
		{"confirm-contact", base + "/notification-contact/verifications/contact-one:confirm", `{` + credential + `,"requestId":"confirm-contact","code":"00123456"}`, "confirm-contact", "contact-one"},
	} {
		t.Run(command.name, func(t *testing.T) {
			for _, sample := range []struct {
				name, method, path, body, header, media string
				status                                  int
			}{
				{"valid", http.MethodPost, command.path, command.body, "", "application/json", 503},
				{"wrong-method", http.MethodGet, command.path, command.body, "", "application/json", 405},
				{"query-selector", http.MethodPost, command.path + "?accountId=other", command.body, "", "application/json", 400},
				{"bearer", http.MethodPost, command.path, command.body, "Authorization", "application/json", 400},
				{"internal-subject", http.MethodPost, command.path, command.body, "Matrix-Subject-Credential", "application/json", 400},
				{"null-secret", http.MethodPost, command.path, strings.Replace(command.body, `"synthetic-initial-secret"`, "null", 1), "", "application/json", 400},
				{"duplicate-secret", http.MethodPost, command.path, strings.TrimSuffix(command.body, "}") + `,` + credential + `}`, "", "application/json", 400},
				{"account-selector", http.MethodPost, command.path, strings.TrimSuffix(command.body, "}") + `,"accountId":"other"}`, "", "application/json", 400},
				{"fake-session", http.MethodPost, command.path, strings.TrimSuffix(command.body, "}") + `,"sessionId":"other"}`, "", "application/json", 400},
				{"fake-phase", http.MethodPost, command.path, strings.TrimSuffix(command.body, "}") + `,"nextStep":"ENROLLMENT"}`, "", "application/json", 400},
				{"malformed-id", http.MethodPost, strings.Replace(command.path, "initial-one", "invalid%20challenge", 1), command.body, "", "application/json", 404},
				{"wrong-media", http.MethodPost, command.path, command.body, "", "text/plain", 415},
				{"empty-json", http.MethodPost, command.path, `{}`, "", "application/json", 400},
			} {
				t.Run(sample.name, func(t *testing.T) {
					workflow := newHTTPWorkflow(t)
					workflow.enrollmentErr = identityaccess.ErrUnavailable
					endpoint := newTestHandler(t, workflow)
					request := httptest.NewRequest(sample.method, sample.path, strings.NewReader(sample.body))
					request.Header.Set("Content-Type", sample.media)
					if sample.header != "" {
						request.Header.Set(sample.header, "synthetic-second-identity")
					}
					response := httptest.NewRecorder()
					endpoint.ServeHTTP(response, request)
					if response.Code != sample.status || response.Header().Get("Cache-Control") != "no-store" {
						t.Fatal("restricted enrollment transport differs", response.Code, sample.status)
					}
					if (workflow.enrollmentCalls == 1) != (sample.status == 503) || workflow.loginCalls != 0 || workflow.totpCalls != 0 {
						t.Fatal("invalid carrier reached workflow or selected ordinary login/enrollment")
					}
					if sample.status == 503 && (workflow.verifiedChallengeID != "initial-one" || !workflow.enrollmentCredential.Present() ||
						workflow.enrollmentRequestID != command.requestID || workflow.enrollmentVerificationID != command.verificationID) {
						t.Fatal("challenge or original nested intent changed during dispatch")
					}
					for _, secret := range []string{"synthetic-initial-secret", "synthetic-second-identity", "not-an-otp", "00123456"} {
						if strings.Contains(response.Body.String(), secret) {
							t.Fatal("problem disclosed authentication input")
						}
					}
				})
			}
		})
	}
}

func TestIAMHTTPInitialEnrollmentProjectionDoesNotPromotePasswordStage(t *testing.T) {
	now := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	challenge := iamv1.AuthenticationChallenge{APIVersion: iamv1.APIVersion, Kind: "AuthenticationChallenge", ID: "initial-one", Purpose: "ENROLLMENT", NextStep: "PASSWORD_CHANGE", ExpiresAt: now.Add(5 * time.Minute)}
	for _, sample := range []struct {
		name   string
		change func(*iamv1.EnrollmentChallengeState)
		status int
	}{
		{"password-only", func(*iamv1.EnrollmentChallengeState) {}, 200},
		{"enrollment-contact", func(v *iamv1.EnrollmentChallengeState) {
			v.Challenge.NextStep = "ENROLLMENT"
			v.NotificationContact = &iamv1.NotificationContact{APIVersion: iamv1.APIVersion, Kind: "NotificationContact", AccountID: "account-a", UserID: "user-a", State: "NONE"}
		}, 200},
		{"wrong-challenge", func(v *iamv1.EnrollmentChallengeState) { v.Challenge.ID = "other" }, 503},
		{"wrong-purpose", func(v *iamv1.EnrollmentChallengeState) { v.Challenge.Purpose = "LOGIN" }, 503},
		{"contact-before-password", func(v *iamv1.EnrollmentChallengeState) {
			v.NotificationContact = &iamv1.NotificationContact{APIVersion: iamv1.APIVersion, Kind: "NotificationContact", AccountID: "account-a", UserID: "user-a", State: "NONE"}
		}, 503},
		{"missing-enrollment-state", func(v *iamv1.EnrollmentChallengeState) { v.Challenge.NextStep = "ENROLLMENT" }, 503},
	} {
		t.Run(sample.name, func(t *testing.T) {
			workflow := newHTTPWorkflow(t)
			workflow.enrollmentState = iamv1.EnrollmentChallengeState{Challenge: challenge}
			sample.change(&workflow.enrollmentState)
			request := httptest.NewRequest(http.MethodPost, "/v1/auth/challenges/initial-one:enrollment-state", strings.NewReader(`{"challengeCredential":"synthetic-initial-secret"}`))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			newTestHandler(t, workflow).ServeHTTP(response, request)
			if response.Code != sample.status {
				t.Fatal("challenge projection escaped closed response", response.Code)
			}
			var body map[string]json.RawMessage
			if json.Unmarshal(response.Body.Bytes(), &body) != nil {
				t.Fatal("invalid response")
			}
			for _, field := range []string{"credential", "challengeCredential", "session", "mustChangePassword", "provisioning", "recoveryCodes"} {
				if _, present := body[field]; present {
					t.Fatal("observation disclosed authentication material or a partial session")
				}
			}
			if sample.name == "password-only" && (body["notificationContact"] != nil || body["enrollment"] != nil) {
				t.Fatal("password phase exposed its successor state")
			}
		})
	}
}

func TestIAMHTTPReplacementKeepsBearerIntentAndOneTimeProvisioning(t *testing.T) {
	const path = "/v1/auth/totp/enrollments:replace"
	const body = `{"requestId":"replace-one","stepUpId":"proof-one","expectedFactorRevision":2}`
	for _, scenario := range []string{"applied", "replay", "initial-purpose", "other-intent", "other-revision", "replayed-secret",
		"missing-bearer", "query-selector", "body-selector", "duplicate-proof", "wrong-method", "unavailable"} {
		t.Run(scenario, func(t *testing.T) {
			workflow := newHTTPWorkflow(t)
			now := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
			seed, _ := iamv1.NewSecret("synthetic-replacement-seed")
			uri, _ := iamv1.NewSecret("synthetic-replacement-uri")
			workflow.enrollmentStart = iamv1.StartTOTPEnrollmentResponse{Outcome: "APPLIED",
				Enrollment: iamv1.TOTPEnrollment{APIVersion: iamv1.APIVersion, Kind: "TOTPEnrollment", ID: "new-factor", RequestID: "replace-one", Purpose: "REPLACEMENT",
					FactorRevision: 2, State: "PENDING", CreatedAt: now, ExpiresAt: now.Add(90 * time.Second)},
				Provisioning: &iamv1.TOTPProvisioning{Seed: seed, URI: uri}}
			method, target, input := http.MethodPost, path, body
			status, calls := http.StatusOK, 1
			switch scenario {
			case "replay":
				workflow.enrollmentStart.Outcome, workflow.enrollmentStart.Provisioning = "EQUAL_REPLAY", nil
			case "initial-purpose":
				workflow.enrollmentStart.Enrollment.Purpose = "INITIAL"
				status = http.StatusServiceUnavailable
			case "other-intent":
				workflow.enrollmentStart.Enrollment.RequestID = "other-command"
				status = http.StatusServiceUnavailable
			case "other-revision":
				workflow.enrollmentStart.Enrollment.FactorRevision++
				status = http.StatusServiceUnavailable
			case "replayed-secret":
				workflow.enrollmentStart.Outcome = "EQUAL_REPLAY"
				status = http.StatusServiceUnavailable
			case "missing-bearer":
				status, calls = http.StatusUnauthorized, 0
			case "query-selector":
				target += "?accountId=other"
				status, calls = http.StatusBadRequest, 0
			case "body-selector":
				input = strings.TrimSuffix(body, "}") + `,"sessionId":"other"}`
				status, calls = http.StatusBadRequest, 0
			case "duplicate-proof":
				input = strings.TrimSuffix(body, "}") + `,"stepUpId":"proof-one"}`
				status, calls = http.StatusBadRequest, 0
			case "wrong-method":
				method, status, calls = http.MethodGet, http.StatusMethodNotAllowed, 0
			case "unavailable":
				workflow.enrollmentErr, status = identityaccess.ErrUnavailable, http.StatusServiceUnavailable
			}
			request := httptest.NewRequest(method, target, strings.NewReader(input))
			request.Header.Set("Content-Type", "application/json")
			if scenario != "missing-bearer" {
				request.Header.Set("Authorization", "Bearer synthetic-replacement-session")
			}
			response := httptest.NewRecorder()
			newTestHandler(t, workflow).ServeHTTP(response, request)
			if response.Code != status || workflow.totpCalls != calls || response.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("replacement HTTP admission/result differs", response.Code, status, workflow.totpCalls, calls)
			}
			if calls != 0 && (!workflow.stepCredential.Present() || workflow.enrollmentRequestID != "replace-one") {
				t.Fatal("replacement lost its bearer or operation intent")
			}
			if bytes.Contains(response.Body.Bytes(), []byte("synthetic-replacement-seed")) != (scenario == "applied") {
				t.Fatal("replacement material escaped its single successful response")
			}
		})
	}
}

func TestIAMHTTPNotificationContactReplacementKeepsExactIntent(t *testing.T) {
	now := time.Date(2026, 10, 4, 8, 0, 0, 0, time.UTC)
	const path = "/v1/auth/notification-contact/replacements"
	const body = `{"stepUpId":"contact-proof","expectedResourceVersion":3,"email":"new@example.invalid","requestId":"replace-contact"}`
	for _, scenario := range []string{"accepted", "missing-bearer", "query-selector", "body-selector", "duplicate-proof", "wrong-result-purpose", "wrong-result-version", "wrong-result-email", "wrong-method", "unavailable"} {
		t.Run(scenario, func(t *testing.T) {
			workflow := newHTTPWorkflow(t)
			workflow.enrollmentMail = iamv1.NotificationContactVerification{APIVersion: iamv1.APIVersion, Kind: "NotificationContactVerification",
				ID: "contact-replacement", AccountID: "account-one", UserID: "user-one", RequestID: "replace-contact",
				Purpose: iamv1.NotificationContactReplacement, ExpectedResourceVersion: 3, Email: "new@example.invalid", State: "PENDING",
				IssuedAt: now, ExpiresAt: now.Add(10 * time.Minute), Delivery: iamv1.NotificationDeliveryObservation{State: "PENDING", UpdatedAt: now}}
			method, target, input := http.MethodPost, path, body
			status, calls := http.StatusOK, 1
			switch scenario {
			case "missing-bearer":
				status, calls = http.StatusUnauthorized, 0
			case "query-selector":
				target += "?accountId=other"
				status, calls = http.StatusBadRequest, 0
			case "body-selector":
				input = strings.TrimSuffix(body, "}") + `,"userId":"other"}`
				status, calls = http.StatusBadRequest, 0
			case "duplicate-proof":
				input = strings.TrimSuffix(body, "}") + `,"stepUpId":"other"}`
				status, calls = http.StatusBadRequest, 0
			case "wrong-result-purpose":
				workflow.enrollmentMail.Purpose = iamv1.NotificationContactFirstAddress
				workflow.enrollmentMail.ExpectedResourceVersion = 0
				status = http.StatusServiceUnavailable
			case "wrong-result-version":
				workflow.enrollmentMail.ExpectedResourceVersion++
				status = http.StatusServiceUnavailable
			case "wrong-result-email":
				workflow.enrollmentMail.Email = "other@example.invalid"
				status = http.StatusServiceUnavailable
			case "wrong-method":
				method, status, calls = http.MethodGet, http.StatusMethodNotAllowed, 0
			case "unavailable":
				workflow.enrollmentErr, status = identityaccess.ErrUnavailable, http.StatusServiceUnavailable
			}
			request := httptest.NewRequest(method, target, strings.NewReader(input))
			request.Header.Set("Content-Type", "application/json")
			if scenario != "missing-bearer" {
				request.Header.Set("Authorization", "Bearer current-contact-session")
			}
			response := httptest.NewRecorder()
			newTestHandler(t, workflow).ServeHTTP(response, request)
			if response.Code != status || workflow.stepCalls != calls || response.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("notification contact replacement transport differs", response.Code, status, workflow.stepCalls, calls)
			}
			if calls == 1 && (!workflow.stepCredential.Present() || workflow.notificationReplacementRequest != (iamv1.StartNotificationContactReplacementRequest{
				StepUpID: "contact-proof", ExpectedResourceVersion: 3, Email: "new@example.invalid", RequestID: "replace-contact"})) {
				t.Fatal("replacement transport changed the exact proof intent")
			}
		})
	}
}

func TestIAMHTTPInitialEnrollmentResponsesKeepSecretsPurposeBound(t *testing.T) {
	now := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	completed := now.Add(time.Second)
	factor := iamv1.TOTPEnrollment{APIVersion: iamv1.APIVersion, Kind: "TOTPEnrollment", ID: "factor-one", RequestID: "first-factor", Purpose: "INITIAL",
		FactorRevision: 1, State: "PENDING", CreatedAt: now, ExpiresAt: now.Add(3 * time.Minute)}
	seed, _ := iamv1.NewSecret("synthetic-initial-provisioning")
	uri, _ := iamv1.NewSecret("synthetic-initial-uri")
	const base = "/v1/auth/challenges/initial-one"
	const credential = `"challengeCredential":"synthetic-initial-secret"`
	for _, sample := range []struct {
		name, path, body    string
		change              func(*httpWorkflow)
		status              int
		provisioning, codes bool
	}{
		{"new-factor", base + ":enroll", `{` + credential + `,"requestId":"first-factor"}`, func(*httpWorkflow) {}, 200, true, false},
		{"original-factor", base + ":enroll", `{` + credential + `,"requestId":"first-factor"}`, func(w *httpWorkflow) {
			w.enrollmentStart.Outcome = "EQUAL_REPLAY"
			w.enrollmentStart.Provisioning = nil
		}, 200, false, false},
		{"wrong-factor-intent", base + ":enroll", `{` + credential + `,"requestId":"another-intent"}`, func(*httpWorkflow) {}, 503, false, false},
		{"replayed-seed", base + ":enroll", `{` + credential + `,"requestId":"first-factor"}`, func(w *httpWorkflow) { w.enrollmentStart.Outcome = "EQUAL_REPLAY" }, 503, false, false},
		{"factor-confirmed", base + ":confirm-enrollment", `{` + credential + `,"requestId":"confirm-factor","code":"123456"}`, func(*httpWorkflow) {}, 200, false, true},
		{"factor-without-codes", base + ":confirm-enrollment", `{` + credential + `,"requestId":"confirm-factor","code":"123456"}`, func(w *httpWorkflow) { w.enrollmentConfirmation.RecoveryCodes = nil }, 503, false, false},
		{"factor-instead-of-login", base + ":confirm-enrollment", `{` + credential + `,"requestId":"confirm-factor","code":"123456"}`, func(w *httpWorkflow) { w.enrollmentConfirmation.NextStep = "AUTHENTICATED" }, 503, false, false},
		{"contact-started", base + "/notification-contact/verifications", `{` + credential + `,"requestId":"first-contact","email":"first@example.invalid"}`, func(*httpWorkflow) {}, 200, false, false},
		{"wrong-contact-intent", base + "/notification-contact/verifications", `{` + credential + `,"requestId":"another-contact","email":"first@example.invalid"}`, func(*httpWorkflow) {}, 503, false, false},
		{"wrong-contact-recipient", base + "/notification-contact/verifications", `{` + credential + `,"requestId":"first-contact","email":"other@example.invalid"}`, func(*httpWorkflow) {}, 503, false, false},
		{"contact-confirmed", base + "/notification-contact/verifications/contact-one:confirm", `{` + credential + `,"requestId":"confirm-contact","code":"00123456"}`, func(w *httpWorkflow) { w.enrollmentMail.State = "VERIFIED"; w.enrollmentMail.CompletedAt = &completed }, 200, false, false},
		{"wrong-contact-id", base + "/notification-contact/verifications/contact-other:confirm", `{` + credential + `,"requestId":"confirm-contact","code":"00123456"}`, func(w *httpWorkflow) { w.enrollmentMail.State = "VERIFIED"; w.enrollmentMail.CompletedAt = &completed }, 503, false, false},
		{"pending-contact-not-completion", base + "/notification-contact/verifications/contact-one:confirm", `{` + credential + `,"requestId":"confirm-contact","code":"00123456"}`, func(*httpWorkflow) {}, 503, false, false},
	} {
		t.Run(sample.name, func(t *testing.T) {
			workflow := newHTTPWorkflow(t)
			workflow.enrollmentStart = iamv1.StartTOTPEnrollmentResponse{Outcome: "APPLIED", Enrollment: factor, Provisioning: &iamv1.TOTPProvisioning{Seed: seed, URI: uri}}
			confirmed := factor
			confirmed.State, confirmed.CompletedAt = "CONFIRMED", &completed
			workflow.enrollmentConfirmation = iamv1.ConfirmTOTPEnrollmentResponse{Enrollment: confirmed, NextStep: "REAUTHENTICATE"}
			for index := range 10 {
				code, _ := iamv1.NewSecret(fmt.Sprintf("synthetic-initial-recovery-%02d", index))
				workflow.enrollmentConfirmation.RecoveryCodes = append(workflow.enrollmentConfirmation.RecoveryCodes, code)
			}
			workflow.enrollmentMail = iamv1.NotificationContactVerification{APIVersion: iamv1.APIVersion, Kind: "NotificationContactVerification", ID: "contact-one", AccountID: "account-one", UserID: "user-one",
				RequestID: "first-contact", Purpose: iamv1.NotificationContactFirstAddress, Email: "first@example.invalid", State: "PENDING", IssuedAt: now, ExpiresAt: now.Add(3 * time.Minute), Delivery: iamv1.NotificationDeliveryObservation{State: "PENDING", UpdatedAt: now}}
			sample.change(workflow)
			request := httptest.NewRequest(http.MethodPost, sample.path, strings.NewReader(sample.body))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			newTestHandler(t, workflow).ServeHTTP(response, request)
			if response.Code != sample.status || response.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("initial enrollment result differs", response.Code, sample.status)
			}
			var body map[string]json.RawMessage
			if json.Unmarshal(response.Body.Bytes(), &body) != nil {
				t.Fatal("invalid result document")
			}
			if (body["provisioning"] != nil) != sample.provisioning || (body["recoveryCodes"] != nil) != sample.codes {
				t.Fatal("secret escaped its original successful operation")
			}
			for _, field := range []string{"session", "credential", "challengeCredential", "mustChangePassword"} {
				if body[field] != nil {
					t.Fatal("first enrollment issued a partial login")
				}
			}
			if sample.provisioning && !strings.Contains(response.Body.String(), "synthetic-initial-provisioning") {
				t.Fatal("explicit first provisioning encoder redacted its required one-time delivery")
			}
			if sample.codes {
				var codes []string
				if json.Unmarshal(body["recoveryCodes"], &codes) != nil || len(codes) != 10 || codes[0] != "synthetic-initial-recovery-00" {
					t.Fatal("explicit binding encoder did not deliver the original codes")
				}
			}
			if sample.status != 200 {
				for _, secret := range []string{"synthetic-initial", "first@example.invalid", "123456"} {
					if strings.Contains(response.Body.String(), secret) {
						t.Fatal("invalid response leaked a partial result or input")
					}
				}
			}
		})
	}
}

func TestIAMHTTPAuthenticatorRecoveryRejectsAmbiguousCarriers(t *testing.T) {
	for _, command := range []struct{ suffix, body string }{
		{"recover", `{"requestId":"recover-one","challengeCredential":"synthetic-challenge-secret","recoveryCode":"synthetic-recovery-code"}`},
		{"confirm-recovery", `{"requestId":"confirm-one","challengeCredential":"synthetic-challenge-secret","code":"123456"}`},
		{"recovery-result", `{"requestId":"recover-one","challengeCredential":"synthetic-challenge-secret"}`},
	} {
		t.Run(command.suffix, func(t *testing.T) {
			route := "/v1/auth/challenges/challenge-one:" + command.suffix
			for _, sample := range []struct {
				name, path, method, body, authorization string
				status                                  int
			}{
				{"valid", route, http.MethodPost, command.body, "", http.StatusServiceUnavailable},
				{"bearer-and-challenge", route, http.MethodPost, command.body, "Bearer synthetic-session", http.StatusBadRequest},
				{"query-selector", route + "?userId=other", http.MethodPost, command.body, "", http.StatusBadRequest},
				{"body-selector", route, http.MethodPost, strings.Replace(command.body, `"requestId":`, `"accountId":"other","requestId":`, 1), "", http.StatusBadRequest},
				{"password", route, http.MethodPost, strings.Replace(command.body, `"requestId":`, `"password":"not-accepted","requestId":`, 1), "", http.StatusBadRequest},
				{"retain-session", route, http.MethodPost, strings.Replace(command.body, `"requestId":`, `"revokeOtherSessions":false,"requestId":`, 1), "", http.StatusBadRequest},
				{"null-credential", route, http.MethodPost, strings.Replace(command.body, `"synthetic-challenge-secret"`, `null`, 1), "", http.StatusBadRequest},
				{"duplicate-credential", route, http.MethodPost, strings.Replace(command.body, `"requestId":`, `"challengeCredential":"other","requestId":`, 1), "", http.StatusBadRequest},
				{"wrong-method", route, http.MethodGet, command.body, "", http.StatusMethodNotAllowed},
			} {
				t.Run(sample.name, func(t *testing.T) {
					workflow := newHTTPWorkflow(t)
					request := httptest.NewRequest(sample.method, sample.path, strings.NewReader(sample.body))
					request.Header.Set("Content-Type", "application/json")
					if sample.authorization != "" {
						request.Header.Set("Authorization", sample.authorization)
					}
					response := httptest.NewRecorder()
					newTestHandler(t, workflow).ServeHTTP(response, request)
					if response.Code != sample.status || response.Header().Get("Cache-Control") != "no-store" {
						t.Fatal("restricted recovery transport differs", response.Code)
					}
					if (workflow.verifiedChallengeID != "") != (sample.status == http.StatusServiceUnavailable) {
						t.Fatal("invalid request reached recovery workflow")
					}
					for _, secret := range []string{"synthetic-challenge-secret", "synthetic-recovery-code", "123456", "not-accepted"} {
						if strings.Contains(response.Body.String(), secret) {
							t.Fatal("recovery problem exposed authentication material")
						}
					}
				})
			}
		})
	}
}

func TestIAMHTTPChallengeVerificationRejectsAmbiguousCarriers(t *testing.T) {
	valid := `{"requestId":"verify-one","challengeCredential":"synthetic-challenge-secret","code":"123456"}`
	for _, sample := range []struct {
		name, path, method, body, authorization string
		status                                  int
	}{
		{"valid", "/v1/auth/challenges/challenge-one:verify", http.MethodPost, valid, "", http.StatusOK},
		{"bearer-and-challenge", "/v1/auth/challenges/challenge-one:verify", http.MethodPost, valid, "Bearer synthetic-session", http.StatusBadRequest},
		{"query-selector", "/v1/auth/challenges/challenge-one:verify?userId=other", http.MethodPost, valid, "", http.StatusBadRequest},
		{"body-selector", "/v1/auth/challenges/challenge-one:verify", http.MethodPost, strings.Replace(valid, `"requestId":`, `"accountId":"other","requestId":`, 1), "", http.StatusBadRequest},
		{"missing-credential", "/v1/auth/challenges/challenge-one:verify", http.MethodPost, `{"requestId":"verify-one","code":"123456"}`, "", http.StatusBadRequest},
		{"null-code", "/v1/auth/challenges/challenge-one:verify", http.MethodPost, strings.Replace(valid, `"123456"`, `null`, 1), "", http.StatusBadRequest},
		{"wrong-method", "/v1/auth/challenges/challenge-one:verify", http.MethodGet, valid, "", http.StatusMethodNotAllowed},
	} {
		t.Run(sample.name, func(t *testing.T) {
			workflow := newHTTPWorkflow(t)
			endpoint := newTestHandler(t, workflow)
			req := httptest.NewRequest(sample.method, sample.path, strings.NewReader(sample.body))
			req.Header.Set("Content-Type", "application/json")
			if sample.authorization != "" {
				req.Header.Set("Authorization", sample.authorization)
			}
			response := httptest.NewRecorder()
			endpoint.ServeHTTP(response, req)
			if response.Code != sample.status || response.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("restricted challenge transport differs", response.Code)
			}
			if (workflow.verifiedChallengeID != "") == (sample.status != http.StatusOK) {
				t.Fatal("invalid carrier reached authentication workflow")
			}
			if sample.status != http.StatusOK && (strings.Contains(response.Body.String(), "synthetic-challenge-secret") || strings.Contains(response.Body.String(), "123456")) {
				t.Fatal("problem exposed authentication material")
			}
		})
	}
}

func TestIAMHTTPStepUpUsesOnlySessionAndClosedOperation(t *testing.T) {
	for _, command := range []struct{ name, path, body string }{
		{"start", "/v1/auth/step-up", `{"requestId":"regenerate-one","operation":"RECOVERY_CODES_REGENERATE","expectedFactorRevision":2}`},
		{"verify", "/v1/auth/step-up/proof-one:verify", `{"requestId":"verify-one","password":"synthetic-password","code":"malformed-candidate"}`},
		{"regenerate", "/v1/auth/recovery-codes:regenerate", `{"requestId":"regenerate-one","stepUpId":"proof-one","expectedFactorRevision":2}`},
		{"remove", "/v1/auth/totp:remove", `{"requestId":"remove-one","stepUpId":"proof-one","expectedFactorRevision":2}`},
	} {
		t.Run(command.name, func(t *testing.T) {
			for _, sample := range []struct {
				name, method, path, body, bearer string
				status                           int
			}{
				{"valid", "POST", command.path, command.body, "Bearer synthetic-session", 503},
				{"no-bearer", "POST", command.path, command.body, "", 401},
				{"wrong-method", "GET", command.path, command.body, "Bearer synthetic-session", 405},
				{"query-selector", "POST", command.path + "?sessionId=other", command.body, "Bearer synthetic-session", 400},
				{"body-selector", "POST", command.path, strings.TrimSuffix(command.body, "}") + `,"userId":"other"}`, "Bearer synthetic-session", 400},
				{"challenge-carrier", "POST", command.path, strings.TrimSuffix(command.body, "}") + `,"challengeCredential":"synthetic-challenge"}`, "Bearer synthetic-session", 400},
				{"duplicate-intent", "POST", command.path, strings.TrimSuffix(command.body, "}") + `,"requestId":"other"}`, "Bearer synthetic-session", 400},
				{"null-intent", "POST", command.path, strings.Replace(command.body, `"requestId":`, `"requestId":null,"unknown":`, 1), "Bearer synthetic-session", 400},
			} {
				t.Run(sample.name, func(t *testing.T) {
					workflow := newHTTPWorkflow(t)
					workflow.stepErr = identityaccess.ErrUnavailable
					request := httptest.NewRequest(sample.method, sample.path, strings.NewReader(sample.body))
					request.Header.Set("Content-Type", "application/json")
					if sample.bearer != "" {
						request.Header.Set("Authorization", sample.bearer)
					}
					response := httptest.NewRecorder()
					newTestHandler(t, workflow).ServeHTTP(response, request)
					if response.Code != sample.status || (workflow.stepCalls == 1) != (sample.status == 503) {
						t.Fatal("step-up transport boundary differs", response.Code, workflow.stepCalls)
					}
					if sample.status == 503 {
						wanted, _ := iamv1.NewSecret("synthetic-session")
						if workflow.stepCredential != wanted {
							t.Fatal("actual bearer was replaced")
						}
					}
					if response.Header().Get("Cache-Control") != "no-store" || strings.Contains(response.Body.String(), "synthetic-") || strings.Contains(response.Body.String(), "malformed-candidate") {
						t.Fatal("step-up failure cached or leaked candidate")
					}
				})
			}
		})
	}
	for _, route := range []string{"/v1/auth/step-up/by-request/regenerate-one", "/v1/auth/recovery-codes/regenerations/by-request/regenerate-one", "/v1/auth/totp/removals/by-request/remove-one"} {
		for _, sample := range []struct {
			method, suffix, body string
			status               int
		}{
			{"GET", "", "", 404}, {"GET", "?accountId=other", "", 400}, {"GET", "", "{}", 400},
			{"POST", "", "", 405}, {"GET", "/nested", "", 404},
		} {
			workflow := newHTTPWorkflow(t)
			workflow.stepErr = identityaccess.ErrStepUpNotFound
			if strings.Contains(route, "regenerations") {
				workflow.stepErr = identityaccess.ErrRecoveryCodeRegenerationNotFound
			}
			if strings.Contains(route, "removals") {
				workflow.stepErr = identityaccess.ErrAuthenticatorRemovalNotFound
			}
			request := httptest.NewRequest(sample.method, route+sample.suffix, strings.NewReader(sample.body))
			request.Header.Set("Authorization", "Bearer synthetic-session")
			response := httptest.NewRecorder()
			newTestHandler(t, workflow).ServeHTTP(response, request)
			if response.Code != sample.status || (workflow.stepCalls == 1) != (sample.method == "GET" && sample.suffix == "" && sample.body == "") {
				t.Fatal("read-only original metadata boundary differs", response.Code, workflow.stepCalls)
			}
		}
	}
}

func TestIAMHTTPRemovalReplayCannotRequestAnotherAuthenticationTransition(t *testing.T) {
	for _, sample := range []struct {
		outcome, next string
		status        int
	}{
		{"APPLIED", "REAUTHENTICATE", 200}, {"EQUAL_REPLAY", "", 200},
		{"APPLIED", "", 503}, {"EQUAL_REPLAY", "REAUTHENTICATE", 503},
	} {
		workflow := newHTTPWorkflow(t)
		workflow.removalResult = iamv1.RemoveTOTPResponse{Outcome: sample.outcome, NextStep: sample.next,
			Removal: iamv1.AuthenticatorRemoval{APIVersion: iamv1.APIVersion, Kind: "AuthenticatorRemoval", ID: "removal-one",
				RequestID: "remove-one", FactorID: "factor-one", FactorRevision: 3, RemovedAt: time.Date(2026, 9, 28, 1, 0, 0, 0, time.UTC)}}
		request := httptest.NewRequest("POST", "/v1/auth/totp:remove", strings.NewReader(`{"requestId":"remove-one","stepUpId":"proof-one","expectedFactorRevision":2}`))
		request.Header.Set("Authorization", "Bearer synthetic-session")
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		newTestHandler(t, workflow).ServeHTTP(response, request)
		if response.Code != sample.status || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("removal result failed open", response.Code)
		}
		if sample.outcome == "EQUAL_REPLAY" && strings.Contains(response.Body.String(), "nextStep") {
			t.Fatal("replay instructed another credential transition")
		}
	}
}

func TestIAMHTTPRecoveryCodeRegenerationOnlyDisclosesAppliedCodes(t *testing.T) {
	workflow := newHTTPWorkflow(t)
	workflow.regenerationResult = iamv1.RegenerateRecoveryCodesResponse{Outcome: "APPLIED", Regeneration: iamv1.RecoveryCodeRegeneration{
		APIVersion: iamv1.APIVersion, Kind: "RecoveryCodeRegeneration", ID: "regeneration-one", RequestID: "regenerate-one",
		FactorID: "factor-one", FactorRevision: 2, CreatedAt: time.Date(2026, 9, 21, 1, 0, 0, 0, time.UTC),
	}}
	for index := range 10 {
		code, _ := iamv1.NewSecret(fmt.Sprintf("synthetic-saved-code-%02d", index))
		workflow.regenerationResult.RecoveryCodes = append(workflow.regenerationResult.RecoveryCodes, code)
	}
	for _, mode := range []string{"applied", "replay-with-codes", "replay"} {
		if mode != "applied" {
			workflow.regenerationResult.Outcome = "EQUAL_REPLAY"
		}
		if mode == "replay" {
			workflow.regenerationResult.RecoveryCodes = nil
		}
		request := httptest.NewRequest("POST", "/v1/auth/recovery-codes:regenerate", strings.NewReader(`{"requestId":"regenerate-one","stepUpId":"proof-one","expectedFactorRevision":2}`))
		request.Header.Set("Authorization", "Bearer synthetic-session")
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		newTestHandler(t, workflow).ServeHTTP(response, request)
		wantedStatus := http.StatusOK
		if mode == "replay-with-codes" {
			wantedStatus = http.StatusServiceUnavailable
		}
		if response.Code != wantedStatus || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("regeneration encoding failed open", response.Code)
		}
		if mode != "applied" && (strings.Contains(response.Body.String(), "recoveryCodes") || strings.Contains(response.Body.String(), "synthetic-saved-code")) {
			t.Fatal("replay or error reissued saved codes")
		}
		if mode == "applied" {
			var result iamv1.RegenerateRecoveryCodesResponse
			if json.Unmarshal(response.Body.Bytes(), &result) != nil || len(result.RecoveryCodes) != 10 {
				t.Fatal("explicit first disclosure failed")
			}
		}
	}
}

func TestIAMHTTPEnrollmentAcceptsOnlyCurrentSessionAndClosedCommands(t *testing.T) {
	start := `{"requestId":"enroll-one","password":"synthetic-password","expectedFactorRevision":1}`
	confirm := `{"requestId":"confirm-one","code":"123456"}`
	for _, sample := range []struct {
		name, method, path, body string
		bearer                   bool
		status                   int
		calls                    int
	}{
		{"start", http.MethodPost, "/v1/auth/totp/enrollments", start, true, http.StatusServiceUnavailable, 1},
		{"confirm", http.MethodPost, "/v1/auth/totp/enrollments/factor-one:confirm", confirm, true, http.StatusServiceUnavailable, 1},
		{"malformed-code-is-attempt", http.MethodPost, "/v1/auth/totp/enrollments/factor-one:confirm", strings.Replace(confirm, "123456", "not-a-code", 1), true, http.StatusServiceUnavailable, 1},
		{"state", http.MethodGet, "/v1/auth/authenticators", "", true, http.StatusServiceUnavailable, 1},
		{"metadata", http.MethodGet, "/v1/auth/totp/enrollments/factor-one", "", true, http.StatusServiceUnavailable, 1},
		{"original-intent", http.MethodGet, "/v1/auth/totp/enrollments/by-request/enroll-one", "", true, http.StatusServiceUnavailable, 1},
		{"cancel", http.MethodDelete, "/v1/auth/totp/enrollments/factor-one", "", true, http.StatusServiceUnavailable, 1},
		{"missing-bearer", http.MethodPost, "/v1/auth/totp/enrollments", start, false, http.StatusUnauthorized, 0},
		{"query-user", http.MethodPost, "/v1/auth/totp/enrollments?userId=other", start, true, http.StatusBadRequest, 0},
		{"body-user", http.MethodPost, "/v1/auth/totp/enrollments", strings.Replace(start, `"requestId":`, `"userId":"other","requestId":`, 1), true, http.StatusBadRequest, 0},
		{"dual-carrier", http.MethodPost, "/v1/auth/totp/enrollments", strings.Replace(start, `"requestId":`, `"challengeCredential":"synthetic-challenge","requestId":`, 1), true, http.StatusBadRequest, 0},
		{"null-revision", http.MethodPost, "/v1/auth/totp/enrollments", strings.Replace(start, `:1}`, `:null}`, 1), true, http.StatusBadRequest, 0},
		{"duplicate-request", http.MethodPost, "/v1/auth/totp/enrollments", strings.TrimSuffix(start, "}") + `,"requestId":"another"}`, true, http.StatusBadRequest, 0},
		{"cancel-body", http.MethodDelete, "/v1/auth/totp/enrollments/factor-one", "{}", true, http.StatusBadRequest, 0},
		{"metadata-body", http.MethodGet, "/v1/auth/totp/enrollments/factor-one", "{}", true, http.StatusBadRequest, 0},
		{"request-query", http.MethodGet, "/v1/auth/totp/enrollments/by-request/enroll-one?accountId=other", "", true, http.StatusBadRequest, 0},
		{"metadata-method", http.MethodPatch, "/v1/auth/totp/enrollments/factor-one", "", true, http.StatusMethodNotAllowed, 0},
		{"nested-factor", http.MethodGet, "/v1/auth/totp/enrollments/factor/other", "", true, http.StatusNotFound, 0},
	} {
		t.Run(sample.name, func(t *testing.T) {
			workflow := newHTTPWorkflow(t)
			request := httptest.NewRequest(sample.method, sample.path, strings.NewReader(sample.body))
			if sample.body != "" {
				request.Header.Set("Content-Type", "application/json")
			}
			if sample.bearer {
				request.Header.Set("Authorization", "Bearer synthetic-session")
			}
			response := httptest.NewRecorder()
			newTestHandler(t, workflow).ServeHTTP(response, request)
			if response.Code != sample.status || workflow.totpCalls != sample.calls {
				t.Fatalf("enrollment boundary status=%d calls=%d", response.Code, workflow.totpCalls)
			}
			if response.Header().Get("Cache-Control") != "no-store" || strings.Contains(response.Body.String(), "synthetic-") {
				t.Fatal("enrollment error cached or exposed secret input")
			}
		})
	}
}

func TestIAMHTTPLoginChallengeNeverPublishesSessionFields(t *testing.T) {
	workflow := newHTTPWorkflow(t)
	secret, err := iamv1.NewSecret("example-only-challenge-credential")
	if err != nil {
		t.Fatal(err)
	}
	workflow.login = iamv1.LoginResponse{Outcome: iamv1.LoginChallengeRequired,
		Challenge: &iamv1.AuthenticationChallenge{APIVersion: iamv1.APIVersion, Kind: "AuthenticationChallenge",
			ID: "challenge-one", Purpose: "LOGIN", NextStep: "TOTP", ExpiresAt: time.Date(2026, 9, 20, 1, 7, 3, 0, time.UTC)},
		ChallengeCredential: secret}
	handler := newTestHandler(t, workflow)
	request := httptest.NewRequest(http.MethodPost, "/v1/auth/login",
		strings.NewReader(`{"loginName":"admin","password":"Example-only-password!49","requestId":"login-one"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("challenge result was not a non-cacheable authentication response")
	}
	var result iamv1.LoginResponse
	if iamv1.DecodeRequest(response.Body, &result) != nil || result.Outcome != iamv1.LoginChallengeRequired ||
		result.Credential.Present() || result.Session != (iamv1.Session{}) || result.ChallengeCredential != secret {
		t.Fatal("challenge result changed its purpose or exposed a Session")
	}
}

func TestIAMHTTPStrictDecodingAndRedactedProblems(t *testing.T) {
	workflow := newHTTPWorkflow(t)
	handler := newTestHandler(t, workflow)

	loginRequest := httptest.NewRequest(
		http.MethodPost,
		"/v1/auth/login",
		strings.NewReader(`{"loginName":"admin","password":"Initial-Admin-Password-49!","requestId":"request-login"}`),
	)
	loginRequest.Header.Set("Content-Type", "application/json")
	loginResponse := httptest.NewRecorder()
	handler.ServeHTTP(loginResponse, loginRequest)
	if loginResponse.Code != http.StatusOK || workflow.loginCalls != 1 ||
		!bytes.Contains(loginResponse.Body.Bytes(), []byte("issued-session-credential")) ||
		!bytes.Contains(loginResponse.Body.Bytes(), []byte(`"mustChangePassword":true`)) {
		t.Fatalf("login status=%d calls=%d body=%s", loginResponse.Code, workflow.loginCalls, loginResponse.Body.String())
	}

	unknownFieldRequest := httptest.NewRequest(
		http.MethodPost,
		"/v1/auth/login",
		strings.NewReader(`{"loginName":"admin","password":"Initial-Admin-Password-49!","requestId":"request-login","tenantId":"forged"}`),
	)
	unknownFieldRequest.Header.Set("Content-Type", "application/json")
	unknownFieldResponse := httptest.NewRecorder()
	handler.ServeHTTP(unknownFieldResponse, unknownFieldRequest)
	if unknownFieldResponse.Code != http.StatusBadRequest || workflow.loginCalls != 1 {
		t.Fatalf("unknown field status=%d calls=%d body=%s", unknownFieldResponse.Code, workflow.loginCalls, unknownFieldResponse.Body.String())
	}

	oversizedRequest := httptest.NewRequest(
		http.MethodPost,
		"/v1/auth/login",
		strings.NewReader(`{"loginName":"admin","password":"`+strings.Repeat("A", int(iamv1.MaxRequestBytes))+`","requestId":"request-login"}`),
	)
	oversizedRequest.Header.Set("Content-Type", "application/json")
	oversizedResponse := httptest.NewRecorder()
	handler.ServeHTTP(oversizedResponse, oversizedRequest)
	if oversizedResponse.Code != http.StatusRequestEntityTooLarge || workflow.loginCalls != 1 {
		t.Fatalf("oversized status=%d calls=%d body=%s", oversizedResponse.Code, workflow.loginCalls, oversizedResponse.Body.String())
	}

	workflow.loginErr = errors.New("native failure contains Initial-Admin-Password-49!")
	failureRequest := httptest.NewRequest(
		http.MethodPost,
		"/v1/auth/login",
		strings.NewReader(`{"loginName":"admin","password":"Initial-Admin-Password-49!","requestId":"request-failure"}`),
	)
	failureRequest.Header.Set("Content-Type", "application/json")
	failureResponse := httptest.NewRecorder()
	handler.ServeHTTP(failureResponse, failureRequest)
	if failureResponse.Code != http.StatusServiceUnavailable ||
		bytes.Contains(failureResponse.Body.Bytes(), []byte("Initial-Admin-Password")) ||
		bytes.Contains(failureResponse.Body.Bytes(), []byte("native failure")) {
		t.Fatalf("failure leaked internal data: status=%d body=%s", failureResponse.Code, failureResponse.Body.String())
	}
	var problem iamv1.Problem
	if err := json.Unmarshal(failureResponse.Body.Bytes(), &problem); err != nil || iamv1.ValidateProblem(problem) != nil {
		t.Fatalf("decode normalized IAM problem: problem=%#v err=%v", problem, err)
	}

	methodResponse := httptest.NewRecorder()
	handler.ServeHTTP(methodResponse, httptest.NewRequest(http.MethodGet, "/v1/auth/login", nil))
	if methodResponse.Code != http.StatusMethodNotAllowed || methodResponse.Header().Get("Allow") != http.MethodPost {
		t.Fatalf("method response status=%d allow=%q", methodResponse.Code, methodResponse.Header().Get("Allow"))
	}
	missingResponse := httptest.NewRecorder()
	handler.ServeHTTP(missingResponse, httptest.NewRequest(http.MethodGet, "/debug", nil))
	if missingResponse.Code != http.StatusNotFound {
		t.Fatalf("unknown route status=%d body=%s", missingResponse.Code, missingResponse.Body.String())
	}
}

func TestIAMOwnSessionRoutesRejectSelectorsBeforeWorkflow(t *testing.T) {
	workflow := newHTTPWorkflow(t)
	handler := newTestHandler(t, workflow)
	for _, test := range []struct {
		method, target, body string
		bearer               bool
		status               int
	}{
		{http.MethodGet, "/v1/auth/sessions", "", true, http.StatusOK},
		{http.MethodGet, "/v1/auth/sessions", "", false, http.StatusUnauthorized},
		{http.MethodGet, "/v1/auth/sessions?userId=foreign", "", true, http.StatusBadRequest},
		{http.MethodGet, "/v1/auth/sessions?accountId=foreign", "", true, http.StatusBadRequest},
		{http.MethodGet, "/v1/auth/sessions?currentSessionId=other", "", true, http.StatusBadRequest},
		{http.MethodGet, "/v1/auth/sessions?after=ic1.one&after=ic1.two", "", true, http.StatusBadRequest},
		{http.MethodGet, "/v1/auth/sessions?after=session-id", "", true, http.StatusBadRequest},
		{http.MethodGet, "/v1/auth/sessions", `{}`, true, http.StatusBadRequest},
		{http.MethodPost, "/v1/auth/sessions", `{}`, true, http.StatusMethodNotAllowed},
		{http.MethodPost, "/v1/auth/sessions/current:touch", "", true, http.StatusOK},
		{http.MethodPost, "/v1/auth/sessions/current:touch", "", false, http.StatusUnauthorized},
		{http.MethodGet, "/v1/auth/sessions/current:touch", "", true, http.StatusMethodNotAllowed},
		{http.MethodPost, "/v1/auth/sessions/current:touch?userId=foreign", "", true, http.StatusBadRequest},
		{http.MethodPost, "/v1/auth/sessions/current:touch", `{}`, true, http.StatusBadRequest},
		{http.MethodPost, "/v1/auth/sessions/current:touch/", "", true, http.StatusNotFound},
		{http.MethodPost, "/v1/auth/sessions/other:revoke", `{"requestId":"revoke-own"}`, true, http.StatusOK},
		{http.MethodPost, "/v1/auth/sessions/other:revoke", `{"requestId":"revoke-own"}`, false, http.StatusUnauthorized},
		{http.MethodPost, "/v1/auth/sessions/other:revoke?userId=foreign", `{"requestId":"revoke-own"}`, true, http.StatusBadRequest},
		{http.MethodPost, "/v1/auth/sessions/other:revoke", `{"requestId":"revoke-own","currentSessionId":"foreign"}`, true, http.StatusBadRequest},
		{http.MethodPost, "/v1/auth/sessions/other:revoke", `{"requestId":"revoke-own","accountId":"foreign"}`, true, http.StatusBadRequest},
		{http.MethodPost, "/v1/auth/sessions/other:revoke", `{"requestId":"one","requestId":"two"}`, true, http.StatusBadRequest},
		{http.MethodPost, "/v1/auth/sessions/nested/other:revoke", `{"requestId":"revoke-own"}`, true, http.StatusNotFound},
		{http.MethodPost, "/v1/auth/sessions:revoke-others", `{"requestId":"revoke-others"}`, true, http.StatusOK},
		{http.MethodPost, "/v1/auth/sessions:revoke-others", `{"requestId":"revoke-others"}`, false, http.StatusUnauthorized},
		{http.MethodGet, "/v1/auth/sessions:revoke-others", "", true, http.StatusMethodNotAllowed},
		{http.MethodPost, "/v1/auth/sessions:revoke-others?userId=foreign", `{"requestId":"revoke-others"}`, true, http.StatusBadRequest},
		{http.MethodPost, "/v1/auth/sessions:revoke-others", `{"requestId":"revoke-others","currentSessionId":"foreign"}`, true, http.StatusBadRequest},
		{http.MethodPost, "/v1/auth/sessions:revoke-others", `{"requestId":"revoke-others","accountId":"foreign"}`, true, http.StatusBadRequest},
		{http.MethodPost, "/v1/auth/sessions:revoke-others", `{"requestId":"revoke-others","sessionIds":[]}`, true, http.StatusBadRequest},
		{http.MethodPost, "/v1/auth/sessions:revoke-others", `{"requestId":"one","requestId":"two"}`, true, http.StatusBadRequest},
	} {
		before := workflow.ownSessionCalls
		request := httptest.NewRequest(test.method, test.target, strings.NewReader(test.body))
		if test.bearer {
			request.Header.Set("Authorization", "Bearer actual-login-credential")
		}
		if test.body != "" {
			request.Header.Set("Content-Type", "application/json")
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != test.status || (response.Code != http.StatusOK && workflow.ownSessionCalls != before) {
			t.Fatalf("%s %s status=%d want=%d or rejected input reached workflow", test.method, test.target, response.Code, test.status)
		}
		if response.Code == http.StatusOK && (response.Header().Get("Cache-Control") != "no-store" || strings.Contains(response.Body.String(), "actual-login-credential")) {
			t.Fatal("own session response exposed or cached authentication material")
		}
	}
}

func TestIAMHTTPManagementCommandsRequireCurrentSession(t *testing.T) {
	workflow := newHTTPWorkflow(t)
	handler := newTestHandler(t, workflow)
	requests := []struct {
		name   string
		target string
		body   string
		status int
	}{
		{
			name: "change password", target: "/v1/auth/password", status: http.StatusOK,
			body: `{"currentPassword":"Initial-Admin-Password-49!","newPassword":"Changed-Admin-Password-73!","requestId":"request-password"}`,
		},
		{
			name: "create user", target: "/v1/users", status: http.StatusCreated,
			body: `{"loginName":"developer","displayName":"Developer","initialPassword":"Initial-Developer-Password-84!","permissionBoundary":null,"requestId":"request-user"}`,
		},
		{
			name: "put binding", target: "/v1/policy-attachments", status: http.StatusOK,
			body: `{"target":{"kind":"USER","id":"principal-user"},"policyId":"system.paas-developer","policyResourceVersion":1,"requestId":"request-binding"}`,
		},
		{
			name: "revoke binding", target: "/v1/policy-attachments/binding-user:revoke", status: http.StatusOK,
			body: `{"resourceVersion":1,"requestId":"request-binding-revoke"}`,
		},
		{
			name: "revoke session", target: "/v1/sessions/session-user:revoke", status: http.StatusOK,
			body: `{"requestId":"request-session-revoke"}`,
		},
		{
			name: "logout", target: "/v1/auth/logout", status: http.StatusOK,
			body: `{"requestId":"request-logout"}`,
		},
	}
	for _, test := range requests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, test.target, strings.NewReader(test.body))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Authorization", "Bearer user-session-credential")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status || bytes.Contains(response.Body.Bytes(), []byte("Password-")) {
				t.Fatalf("management response status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}

	missingCredential := httptest.NewRequest(
		http.MethodPost,
		"/v1/users",
		strings.NewReader(`{"loginName":"developer","displayName":"Developer","initialPassword":"Initial-Developer-Password-84!","permissionBoundary":null,"requestId":"request-user"}`),
	)
	missingCredential.Header.Set("Content-Type", "application/json")
	missingResponse := httptest.NewRecorder()
	handler.ServeHTTP(missingResponse, missingCredential)
	if missingResponse.Code != http.StatusUnauthorized {
		t.Fatalf("missing management credential status=%d body=%s", missingResponse.Code, missingResponse.Body.String())
	}

	invalidPath := httptest.NewRequest(
		http.MethodPost,
		"/v1/sessions/not/one-id:revoke",
		strings.NewReader(`{"requestId":"request-session-revoke"}`),
	)
	invalidPath.Header.Set("Content-Type", "application/json")
	invalidPath.Header.Set("Authorization", "Bearer user-session-credential")
	invalidResponse := httptest.NewRecorder()
	handler.ServeHTTP(invalidResponse, invalidPath)
	if invalidResponse.Code != http.StatusNotFound {
		t.Fatalf("invalid command path status=%d body=%s", invalidResponse.Code, invalidResponse.Body.String())
	}
}

func TestIAMSecuritySettingsReadRejectsSelectorsAndAmbiguousWrites(t *testing.T) {
	workflow := newHTTPWorkflow(t)
	handler := newTestHandler(t, workflow)
	const path = "/v1/account/security-settings"
	for _, attack := range []struct {
		name, method, path, body, bearer string
		status                           int
	}{
		{"anonymous", http.MethodGet, path, "", "", http.StatusUnauthorized},
		{"query", http.MethodGet, path + "?accountId=other", "", "current", http.StatusBadRequest},
		{"body", http.MethodGet, path, `{"tenantId":"other"}`, "current", http.StatusBadRequest},
		{"incomplete write", http.MethodPut, path, `{"mfa":{"requiredForUsers":true}}`, "current", http.StatusBadRequest},
		{"history selector", http.MethodGet, path + "/changes/request-a?tenantId=other", "", "current", http.StatusBadRequest},
		{"account path", http.MethodGet, "/v1/accounts/other/security-settings", "", "current", http.StatusNotFound},
	} {
		t.Run(attack.name, func(t *testing.T) {
			request := httptest.NewRequest(attack.method, attack.path, strings.NewReader(attack.body))
			if attack.body != "" {
				request.Header.Set("Content-Type", "application/json")
			}
			if attack.bearer != "" {
				request.Header.Set("Authorization", "Bearer "+attack.bearer)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != attack.status || workflow.settingsCalls != 0 {
				t.Fatalf("rejected surface reached workflow: status=%d calls=%d", response.Code, workflow.settingsCalls)
			}
		})
	}
	for _, result := range []struct {
		err    error
		status int
	}{{nil, http.StatusOK}, {identityaccess.ErrForbidden, http.StatusForbidden}, {identityaccess.ErrUnauthenticated, http.StatusUnauthorized}, {identityaccess.ErrUnavailable, http.StatusServiceUnavailable}} {
		workflow.settingsErr = result.err
		request := httptest.NewRequest(http.MethodGet, path, nil)
		request.Header.Set("Authorization", "Bearer current")
		request.Header.Set("X-Tenant-ID", "other")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != result.status || string(workflow.settingsCredential.CopyBytes()) != "current" {
			t.Fatal("settings read did not preserve credential or sanitized outcome")
		}
		if result.err == nil {
			var settings iamv1.AccountSecuritySettings
			if json.Unmarshal(response.Body.Bytes(), &settings) != nil || iamv1.ValidateAccountSecuritySettings(settings) != nil || settings.AccountID != "account-catalog" {
				t.Fatal("settings response accepted the caller's tenant header")
			}
		}
	}
}

func TestIAMUserPasswordResetCompletionBoundary(t *testing.T) {
	const path = "/v1/users/reset-target/password-resets/reset-command"
	valid := iamv1.UserPasswordResetCompletion{APIVersion: iamv1.APIVersion, Kind: "UserPasswordResetCompletion",
		AccountID: "account-catalog", ActorPrincipalID: "reset-actor", UserID: "reset-target", RequestID: "reset-command",
		ExpectedResourceVersion: 7, ResultingResourceVersion: 8, EventID: "reset-event", OccurredAt: time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC)}
	for _, attack := range []struct {
		method, path, body string
		status             int
	}{
		{http.MethodGet, path, "", http.StatusBadRequest},
		{http.MethodGet, path + "?resourceVersion=7&resourceVersion=7", "", http.StatusBadRequest},
		{http.MethodGet, path + "?resourceVersion=7&accountId=other", "", http.StatusBadRequest},
		{http.MethodGet, path + "?resourceVersion=7", `{}`, http.StatusBadRequest},
		{http.MethodGet, path + "?ResourceVersion=7", "", http.StatusBadRequest},
		{http.MethodGet, path + "?resourceVersion=07", "", http.StatusBadRequest},
		{http.MethodGet, path + "?resourceVersion=0", "", http.StatusBadRequest},
		{http.MethodGet, path + "?resourceVersion=9007199254740991", "", http.StatusBadRequest},
		{http.MethodGet, path + "?resourceVersion=7;actor=other", "", http.StatusBadRequest},
		{http.MethodGet, path + "?resourceVersion=7&bad=%zz", "", http.StatusBadRequest},
		{http.MethodGet, path + "/extra?resourceVersion=7", "", http.StatusNotFound},
		{http.MethodPost, path + "?resourceVersion=7", "", http.StatusMethodNotAllowed},
	} {
		t.Run(attack.method+attack.path+attack.body, func(t *testing.T) {
			workflow := newHTTPWorkflow(t)
			request := httptest.NewRequest(attack.method, attack.path, strings.NewReader(attack.body))
			request.Header.Set("Authorization", "Bearer current")
			response := httptest.NewRecorder()
			newTestHandler(t, workflow).ServeHTTP(response, request)
			if response.Code != attack.status || workflow.resetCompletionCalls != 0 {
				t.Fatalf("invalid completion query reached workflow: status=%d calls=%d", response.Code, workflow.resetCompletionCalls)
			}
		})
	}
	for _, outcome := range []struct {
		err    error
		status int
	}{
		{nil, http.StatusOK}, {identityaccess.ErrUserPasswordResetCompletionNotFound, http.StatusNotFound},
		{identityaccess.ErrUnauthenticated, http.StatusUnauthorized}, {identityaccess.ErrForbidden, http.StatusForbidden},
		{identityaccess.ErrUnavailable, http.StatusServiceUnavailable},
	} {
		workflow := newHTTPWorkflow(t)
		workflow.resetCompletion, workflow.resetCompletionError = valid, outcome.err
		request := httptest.NewRequest(http.MethodGet, path+"?resourceVersion=7", nil)
		request.Header.Set("Authorization", "Bearer current")
		request.Header.Set("X-Tenant-ID", "forged-account")
		response := httptest.NewRecorder()
		newTestHandler(t, workflow).ServeHTTP(response, request)
		if response.Code != outcome.status || workflow.resetCompletionCalls != 1 {
			t.Fatalf("completion outcome was misrepresented: %d", response.Code)
		}
		if outcome.err == nil {
			var got iamv1.UserPasswordResetCompletion
			if json.Unmarshal(response.Body.Bytes(), &got) != nil || got != valid {
				t.Fatal("original completion changed or accepted a tenant selector")
			}
		}
	}
	for _, mutate := range []func(*iamv1.UserPasswordResetCompletion){
		func(v *iamv1.UserPasswordResetCompletion) { v.UserID = "wrong-target" },
		func(v *iamv1.UserPasswordResetCompletion) { v.RequestID = "wrong-command" },
		func(v *iamv1.UserPasswordResetCompletion) {
			v.ExpectedResourceVersion, v.ResultingResourceVersion = 8, 9
		},
		func(v *iamv1.UserPasswordResetCompletion) { v.EventID = "" },
	} {
		workflow := newHTTPWorkflow(t)
		workflow.resetCompletion = valid
		mutate(&workflow.resetCompletion)
		request := httptest.NewRequest(http.MethodGet, path+"?resourceVersion=7", nil)
		request.Header.Set("Authorization", "Bearer current")
		response := httptest.NewRecorder()
		newTestHandler(t, workflow).ServeHTTP(response, request)
		if response.Code != http.StatusServiceUnavailable {
			t.Fatal("unbound completion exposed")
		}
	}
}

func TestIAMSecuritySettingsWriteAndCompletion(t *testing.T) {
	const path = "/v1/account/security-settings"
	const body = `{"requestId":"settings-command","stepUpId":"settings-proof","expectedResourceVersion":1,"mfa":{"requiredForUsers":false},"password":{"minimumLength":15,"requireLowercase":false,"requireUppercase":false,"requireDigit":false,"requireSymbol":false,"historyCount":1,"maxAgeDays":0,"expiryMode":"CHANGE_PASSWORD"},"session":{"idleTimeoutMinutes":30},"accessKeyNetwork":{"allowedSourceCidrs":[]}}`
	for _, endpoint := range []struct{ method, path, body string }{
		{http.MethodPut, path, body}, {http.MethodGet, path + "/changes/settings-command", ""},
	} {
		for _, result := range []struct {
			err    error
			status int
		}{
			{nil, http.StatusOK}, {identityaccess.ErrForbidden, http.StatusForbidden},
			{identityaccess.ErrConflict, http.StatusConflict}, {identityaccess.ErrSecuritySettingsChangeNotFound, http.StatusNotFound},
			{identityaccess.ErrUnavailable, http.StatusServiceUnavailable}, {identityaccess.ErrUnauthenticated, http.StatusUnauthorized},
		} {
			workflow := newHTTPWorkflow(t)
			workflow.settingsErr = result.err
			workflow.settingsChange = iamv1.AccountSecuritySettingsChange{APIVersion: iamv1.APIVersion, Kind: "AccountSecuritySettingsChange",
				RequestID: "settings-command", ExpectedResourceVersion: 1, CallerSessionEnded: true,
				Settings: iamv1.AccountSecuritySettings{APIVersion: iamv1.APIVersion, Kind: "AccountSecuritySettings", AccountID: "account-catalog",
					ResourceVersion: 2, MFA: iamv1.AccountMFASettings{RequiredForUsers: false}, Password: &iamv1.AccountPasswordSettings{ExpiryMode: iamv1.PasswordExpiryChange, MinimumLength: 15, HistoryCount: 1},
					Session: &iamv1.AccountSessionSettings{IdleTimeoutMinutes: 30}, AccessKeyNetwork: &iamv1.AccessKeyNetworkRestrictions{AllowedSourceCIDRs: []string{}}, UpdatedAt: time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC)}}
			request := httptest.NewRequest(endpoint.method, endpoint.path, strings.NewReader(endpoint.body))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Authorization", "Bearer current")
			request.Header.Set("X-Tenant-ID", "forged-account")
			response := httptest.NewRecorder()
			newTestHandler(t, workflow).ServeHTTP(response, request)
			if response.Code != result.status || workflow.settingsCalls != 1 || string(workflow.settingsCredential.CopyBytes()) != "current" {
				t.Fatalf("settings route lost credential or closed outcome: %s status=%d", endpoint.method, response.Code)
			}
			if endpoint.method == http.MethodPut && (workflow.settingsRequest.RequestID != "settings-command" || workflow.settingsRequest.MFA.RequiredForUsers) {
				t.Fatal("explicit false or original intent was lost")
			}
			if endpoint.method == http.MethodGet && workflow.settingsCommand != "settings-command" {
				t.Fatal("completion route lost command ID")
			}
			if result.err == nil && !strings.Contains(response.Body.String(), `"accountId":"account-catalog"`) {
				t.Fatal("caller supplied account scope")
			}
			workflow.settingsErr = nil
			workflow.settingsChange.CallerSessionEnded = false
			request = httptest.NewRequest(endpoint.method, endpoint.path, strings.NewReader(endpoint.body))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Authorization", "Bearer current")
			response = httptest.NewRecorder()
			newTestHandler(t, workflow).ServeHTTP(response, request)
			if response.Code != http.StatusServiceUnavailable {
				t.Fatal("invalid completion escaped response validation")
			}
		}
	}
	for _, payload := range []string{
		`{"requestId":"settings-command","stepUpId":"settings-proof","expectedResourceVersion":1,"mfa":{}}`,
		`{"requestId":"settings-command","stepUpId":"settings-proof","expectedResourceVersion":1,"mfa":{"requiredForUsers":false,"requiredForUsers":true}}`,
		`{"requestId":"settings-command","stepUpId":"settings-proof","expectedResourceVersion":1,"mfa":{"requiredForUsers":false},"accountId":"other"}`,
	} {
		workflow := newHTTPWorkflow(t)
		request := httptest.NewRequest(http.MethodPut, path, strings.NewReader(payload))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Authorization", "Bearer current")
		response := httptest.NewRecorder()
		newTestHandler(t, workflow).ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest || workflow.settingsCalls != 0 {
			t.Fatal("ambiguous settings write reached workflow")
		}
	}
	response := httptest.NewRecorder()
	newTestHandler(t, newHTTPWorkflow(t)).ServeHTTP(response, httptest.NewRequest(http.MethodPost, path, nil))
	if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != "GET, PUT" {
		t.Fatal("settings allowed methods are incomplete")
	}
}

func TestIAMAccountRoutesRejectSelectorsAndMissingCredentialsBeforeWorkflow(t *testing.T) {
	handler := newTestHandler(t, newHTTPWorkflow(t))
	for _, target := range []string{"/v1/auth/me", "/v1/users", "/v1/accounts", "/v1/accounts/account-a"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, target, nil))
		if response.Code != http.StatusUnauthorized {
			t.Errorf("anonymous %s status=%d", target, response.Code)
		}
	}
	for _, target := range []string{"/v1/account:alias", "/v1/accounts", "/v1/users/user-a:set-status", "/v1/users/user-a:reset-password", "/v1/accounts/account-a:set-status", "/v1/accounts/account-a:recover-root-credentials"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, target, strings.NewReader(`{}`)))
		if response.Code != http.StatusUnauthorized {
			t.Errorf("anonymous %s status=%d", target, response.Code)
		}
	}
	for _, target := range []string{"/v1/auth/me?tenantId=forged", "/v1/users?tenantId=forged", "/v1/accounts/account-a?tenantId=forged", "/v1/accounts?after=a&after=b", "/v1/users?after=", "/v1/users?after=%2f", "/v1/users?after=" + strings.Repeat("a", 513)} {
		request := httptest.NewRequest(http.MethodGet, target, nil)
		request.Header.Set("Authorization", "Bearer only-test-credential")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Errorf("forged selector %s status=%d", target, response.Code)
		}
	}
	for _, target := range []string{"/v1/organizations", "/v1/organizations/account-a", "/v1/organization:alias", "/v1/principals", "/v1/principals/user-a:set-status"} {
		request := httptest.NewRequest(http.MethodGet, target, nil)
		request.Header.Set("Authorization", "Bearer only-test-credential")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusNotFound {
			t.Errorf("removed route %s status=%d", target, response.Code)
		}
	}
}

func TestIAMHTTPUserDetailUpdateAndDeleteAreBoundToTheRoute(t *testing.T) {
	workflow := newHTTPWorkflow(t)
	handler := newTestHandler(t, workflow)
	bearer := "user-session-credential"

	detailRequest := httptest.NewRequest(http.MethodGet, "/v1/users/principal-user", nil)
	detailRequest.Header.Set("Authorization", "Bearer "+bearer)
	detailResponse := httptest.NewRecorder()
	handler.ServeHTTP(detailResponse, detailRequest)
	if detailResponse.Code != http.StatusOK || workflow.getUserCalls != 1 || workflow.userID != "principal-user" {
		t.Fatalf("user detail status=%d calls=%d id=%q body=%s", detailResponse.Code, workflow.getUserCalls, workflow.userID, detailResponse.Body.String())
	}
	var detail iamv1.UserAccess
	if json.Unmarshal(detailResponse.Body.Bytes(), &detail) != nil || iamv1.ValidateUserAccess(detail) != nil || detail.User.ID != "principal-user" {
		t.Fatal("user detail response is not the exact validated resource")
	}

	updateBody := `{"displayName":"Renamed Developer","resourceVersion":7,"requestId":"request-user-update"}`
	updateRequest := httptest.NewRequest(http.MethodPost, "/v1/users/principal-user:update", strings.NewReader(updateBody))
	updateRequest.Header.Set("Authorization", "Bearer "+bearer)
	updateRequest.Header.Set("Content-Type", "application/json")
	updateResponse := httptest.NewRecorder()
	handler.ServeHTTP(updateResponse, updateRequest)
	if updateResponse.Code != http.StatusOK || workflow.updateUserCalls != 1 || workflow.updateUser.DisplayName != "Renamed Developer" ||
		workflow.updateUser.ResourceVersion != 7 || workflow.updateUser.RequestID != "request-user-update" {
		t.Fatalf("user update status=%d calls=%d request=%#v body=%s", updateResponse.Code, workflow.updateUserCalls, workflow.updateUser, updateResponse.Body.String())
	}

	deleteBody := `{"resourceVersion":8,"requestId":"request-user-delete"}`
	deleteRequest := httptest.NewRequest(http.MethodPost, "/v1/users/principal-user:delete", strings.NewReader(deleteBody))
	deleteRequest.Header.Set("Authorization", "Bearer "+bearer)
	deleteRequest.Header.Set("Content-Type", "application/json")
	deleteResponse := httptest.NewRecorder()
	handler.ServeHTTP(deleteResponse, deleteRequest)
	if deleteResponse.Code != http.StatusOK || workflow.deleteUserCalls != 1 || workflow.deleteUser.ResourceVersion != 8 ||
		workflow.deleteUser.RequestID != "request-user-delete" || bytes.Contains(deleteResponse.Body.Bytes(), []byte("password")) {
		t.Fatalf("user deletion status=%d calls=%d request=%#v body=%s", deleteResponse.Code, workflow.deleteUserCalls, workflow.deleteUser, deleteResponse.Body.String())
	}
	var deletion iamv1.UserDeletion
	if json.Unmarshal(deleteResponse.Body.Bytes(), &deletion) != nil || iamv1.ValidateUserDeletion(deletion) != nil || deletion.ID != "principal-user" {
		t.Fatal("user deletion response is not a valid non-secret receipt")
	}

	for _, test := range []struct {
		name, method, target, body string
		status                     int
	}{
		{"detail query selector", http.MethodGet, "/v1/users/principal-user?accountId=forged", "", http.StatusBadRequest},
		{"detail body selector", http.MethodGet, "/v1/users/principal-user", `{"accountId":"forged"}`, http.StatusBadRequest},
		{"update query selector", http.MethodPost, "/v1/users/principal-user:update?tenantId=forged", updateBody, http.StatusBadRequest},
		{"update body selector", http.MethodPost, "/v1/users/principal-user:update", `{"displayName":"Renamed Developer","resourceVersion":7,"requestId":"request-user-update","accountId":"forged"}`, http.StatusBadRequest},
		{"delete body selector", http.MethodPost, "/v1/users/principal-user:delete", `{"resourceVersion":8,"requestId":"request-user-delete","principalId":"forged"}`, http.StatusBadRequest},
		{"unknown command", http.MethodPost, "/v1/users/principal-user:transfer", `{}`, http.StatusNotFound},
		{"unsupported method", http.MethodPut, "/v1/users/principal-user", "", http.StatusMethodNotAllowed},
	} {
		t.Run(test.name, func(t *testing.T) {
			beforeGet, beforeUpdate, beforeDelete := workflow.getUserCalls, workflow.updateUserCalls, workflow.deleteUserCalls
			request := httptest.NewRequest(test.method, test.target, strings.NewReader(test.body))
			request.Header.Set("Authorization", "Bearer "+bearer)
			if test.method == http.MethodPost {
				request.Header.Set("Content-Type", "application/json")
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status || workflow.getUserCalls != beforeGet || workflow.updateUserCalls != beforeUpdate || workflow.deleteUserCalls != beforeDelete {
				t.Fatalf("invalid user request status=%d want=%d workflow=%d/%d/%d body=%s", response.Code, test.status, workflow.getUserCalls, workflow.updateUserCalls, workflow.deleteUserCalls, response.Body.String())
			}
			if test.method == http.MethodPut && response.Header().Get("Allow") != "GET, POST" {
				t.Fatalf("user route allow=%q", response.Header().Get("Allow"))
			}
		})
	}
}

func TestIAMHTTPSecurityReportRoutesAreCredentialBoundAndNoStore(t *testing.T) {
	report, csvDocument := httpSecurityReportFixture(t)
	workflow := newHTTPWorkflow(t)
	workflow.securityReport = report
	workflow.securityReportCSV = csvDocument
	workflow.securityReportOutcome = "APPLIED"
	handler := newTestHandler(t, workflow)

	create := httptest.NewRequest(http.MethodPost, "/v1/account/security-reports", strings.NewReader(`{"requestId":"report-request","formatVersion":1}`))
	create.Header.Set("Authorization", "Bearer current")
	create.Header.Set("Content-Type", "application/json")
	created := httptest.NewRecorder()
	handler.ServeHTTP(created, create)
	if created.Code != http.StatusCreated || workflow.securityReportCreateCalls != 1 ||
		workflow.securityReportRequest.RequestID != "report-request" || workflow.securityReportRequest.FormatVersion != 1 ||
		string(workflow.securityReportCredential.CopyBytes()) != "current" {
		t.Fatalf("security report create status=%d calls=%d request=%#v", created.Code, workflow.securityReportCreateCalls, workflow.securityReportRequest)
	}
	var response iamv1.CreateAccountSecurityReportResponse
	if json.Unmarshal(created.Body.Bytes(), &response) != nil || response.Outcome != "APPLIED" || response.Metadata != report.Metadata {
		t.Fatalf("security report create response=%s", created.Body.String())
	}

	for _, endpoint := range []struct {
		path     string
		content  bool
		expected string
	}{
		{path: "/v1/account/security-reports/report-one"},
		{path: "/v1/account/security-reports/report-one/content", content: true, expected: string(csvDocument)},
	} {
		request := httptest.NewRequest(http.MethodGet, endpoint.path, nil)
		request.Header.Set("Authorization", "Bearer current")
		result := httptest.NewRecorder()
		handler.ServeHTTP(result, request)
		if result.Code != http.StatusOK || result.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("security report read path=%s status=%d headers=%#v", endpoint.path, result.Code, result.Header())
		}
		if endpoint.content {
			if result.Body.String() != endpoint.expected || result.Header().Get("Content-Type") != "text/csv; charset=utf-8" ||
				result.Header().Get("Content-Disposition") != `attachment; filename="matrix-iam-security-report-report-one.csv"` {
				t.Fatalf("security report content headers=%#v body=%q", result.Header(), result.Body.String())
			}
		} else {
			var actual iamv1.AccountSecurityReport
			if json.Unmarshal(result.Body.Bytes(), &actual) != nil || !reflect.DeepEqual(actual, report) {
				t.Fatalf("security report body=%s", result.Body.String())
			}
		}
	}
	if workflow.securityReportReadCalls != 1 || workflow.securityReportDownloadCalls != 1 || workflow.securityReportID != "report-one" {
		t.Fatalf("security report calls read=%d download=%d id=%q", workflow.securityReportReadCalls, workflow.securityReportDownloadCalls, workflow.securityReportID)
	}

	for _, sample := range []struct{ method, path, body string }{
		{http.MethodPost, "/v1/account/security-reports?accountId=other", `{"requestId":"report-request","formatVersion":1}`},
		{http.MethodPost, "/v1/account/security-reports", `{"requestId":"report-request","formatVersion":1,"accountId":"other"}`},
		{http.MethodGet, "/v1/account/security-reports/report-one?accountId=other", ""},
		{http.MethodGet, "/v1/account/security-reports/report-one/content/nested", ""},
		{http.MethodPut, "/v1/account/security-reports/report-one", ""},
	} {
		request := httptest.NewRequest(sample.method, sample.path, strings.NewReader(sample.body))
		request.Header.Set("Authorization", "Bearer current")
		result := httptest.NewRecorder()
		handler.ServeHTTP(result, request)
		if result.Code < 400 || workflow.securityReportCreateCalls != 1 || workflow.securityReportReadCalls != 1 || workflow.securityReportDownloadCalls != 1 {
			t.Fatalf("invalid security report route method=%s path=%s status=%d", sample.method, sample.path, result.Code)
		}
	}

	workflow.securityReportErr = identityaccess.ErrSecurityReportNotFound
	notFound := httptest.NewRequest(http.MethodGet, "/v1/account/security-reports/report-missing", nil)
	notFound.Header.Set("Authorization", "Bearer current")
	notFoundResult := httptest.NewRecorder()
	handler.ServeHTTP(notFoundResult, notFound)
	if notFoundResult.Code != http.StatusNotFound || !strings.Contains(notFoundResult.Body.String(), "iam.security-report.not-found") {
		t.Fatalf("missing security report status=%d body=%s", notFoundResult.Code, notFoundResult.Body.String())
	}
}

func TestIAMHTTPAccessAnalyzerRoutesAreCredentialBoundAndStrict(t *testing.T) {
	now := time.Date(2026, 10, 3, 2, 0, 0, 0, time.UTC)
	analyzer := iamv1.AccessAnalyzer{APIVersion: iamv1.APIVersion, Kind: "AccessAnalyzer", ID: "analyzer-one", AccountID: "account-one",
		Type: iamv1.AccessAnalyzerUnusedAccess, Status: iamv1.AccessAnalyzerActive, UnusedAccessAgeDays: 90,
		Disposition:     iamv1.AccessDispositionRule{Mode: iamv1.AccessDispositionReviewOnly},
		ResourceVersion: 1, CreatedAt: now, UpdatedAt: now}
	through := now.Add(time.Hour)
	coverage := make([]iamv1.AccessObservationCoverage, 0, 6)
	for index, source := range iamv1.AccessObservationCoverageSources() {
		entry := iamv1.AccessObservationCoverage{Source: source}
		if index < 4 {
			entry.State, entry.Reason = iamv1.AccessObservationInsufficientCoverage, iamv1.AccessObservationSourceNotReady
			entry.ObservedFrom, entry.ObservedThrough = &now, &through
		} else {
			entry.State, entry.Reason = iamv1.AccessObservationNotIncluded, iamv1.AccessObservationSourceNotImplemented
		}
		coverage = append(coverage, entry)
	}
	workflow := newHTTPWorkflow(t)
	workflow.accessAnalyzer = analyzer
	workflow.accessAnalyzerList = iamv1.AccessAnalyzerList{APIVersion: iamv1.APIVersion, Kind: "AccessAnalyzerList", AccountID: analyzer.AccountID, Items: []iamv1.AccessAnalyzer{analyzer}}
	workflow.accessFindingList = iamv1.AccessFindingList{APIVersion: iamv1.APIVersion, Kind: "AccessFindingList", AccountID: analyzer.AccountID,
		AnalyzerID: analyzer.ID, ObservedAt: through, Coverage: coverage, Items: []iamv1.AccessFinding{}}
	workflow.accessFinding = iamv1.AccessFinding{APIVersion: iamv1.APIVersion, Kind: "AccessFinding", ID: "finding-one",
		AccountID: analyzer.AccountID, AnalyzerID: analyzer.ID, AnalyzerRevision: 1, Type: iamv1.AccessFindingUnusedPassword,
		Status: iamv1.AccessFindingActive, Target: iamv1.ResourceReference{Kind: iamv1.ResourceUser, ID: "user-one"},
		TargetResourceVersion: 1, ConditionGeneration: 1, ActivityRevision: 1, WindowStartedAt: now.Add(-90 * 24 * time.Hour),
		ObservedAt: now, ResourceVersion: 1, CreatedAt: now, UpdatedAt: now}
	handler := newTestHandler(t, workflow)

	call := func(method, path, body string, want int) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(method, path, strings.NewReader(body))
		request.Header.Set("Authorization", "Bearer current")
		if body != "" {
			request.Header.Set("Content-Type", "application/json")
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != want {
			t.Fatalf("%s %s status=%d want=%d body=%s", method, path, response.Code, want, response.Body.String())
		}
		return response
	}
	created := call(http.MethodPost, "/v1/account/access-analyzers", `{"type":"UNUSED_ACCESS","requestId":"analyzer-create"}`, http.StatusCreated)
	var createdAnalyzer iamv1.AccessAnalyzer
	if json.Unmarshal(created.Body.Bytes(), &createdAnalyzer) != nil || createdAnalyzer != analyzer || workflow.accessAnalyzerCreateCalls != 1 ||
		workflow.accessAnalyzerCreateRequest.RequestID != "analyzer-create" || string(workflow.accessAnalyzerCredential.CopyBytes()) != "current" {
		t.Fatalf("access analyzer creation was not preserved: %s", created.Body.String())
	}
	listed := call(http.MethodGet, "/v1/account/access-analyzers", "", http.StatusOK)
	if listed.Header().Get("Cache-Control") != "no-store" || workflow.accessAnalyzerListCalls != 1 {
		t.Fatal("access analyzer directory was not no-store")
	}
	read := call(http.MethodGet, "/v1/account/access-analyzers/analyzer-one", "", http.StatusOK)
	if read.Header().Get("Cache-Control") != "no-store" || workflow.accessAnalyzerReadCalls != 1 || workflow.accessAnalyzerID != analyzer.ID {
		t.Fatal("access analyzer read lost its target")
	}
	workflow.accessAnalyzer.Status, workflow.accessAnalyzer.UnusedAccessAgeDays, workflow.accessAnalyzer.ResourceVersion = iamv1.AccessAnalyzerDisabled, 60, 2
	updated := call(http.MethodPost, "/v1/account/access-analyzers/analyzer-one:update",
		`{"status":"DISABLED","unusedAccessAgeDays":60,"resourceVersion":1,"requestId":"analyzer-update"}`, http.StatusOK)
	if workflow.accessAnalyzerUpdateCalls != 1 || workflow.accessAnalyzerUpdateRequest.Status != iamv1.AccessAnalyzerDisabled ||
		!strings.Contains(updated.Body.String(), `"resourceVersion":2`) {
		t.Fatal("access analyzer update was not preserved")
	}
	workflow.accessAnalyzer.Disposition = iamv1.AccessDispositionRule{Mode: iamv1.AccessDispositionDisableAccessKeys, FindingDelayDays: 7}
	workflow.accessAnalyzer.ResourceVersion = 3
	disposition := call(http.MethodPost, "/v1/account/access-analyzers/analyzer-one:set-disposition",
		`{"disposition":{"mode":"DISABLE_UNUSED_ACCESS_KEYS","findingDelayDays":7},"resourceVersion":2,"requestId":"analyzer-disposition"}`, http.StatusOK)
	if workflow.accessDispositionCalls != 1 || workflow.accessDispositionRequest.Disposition != workflow.accessAnalyzer.Disposition ||
		workflow.accessDispositionRequest.ResourceVersion != 2 || !strings.Contains(disposition.Body.String(), `"DISABLE_UNUSED_ACCESS_KEYS"`) {
		t.Fatal("access disposition update was not preserved")
	}
	findings := call(http.MethodGet, "/v1/account/access-analyzers/analyzer-one/findings?status=ARCHIVED", "", http.StatusOK)
	if findings.Header().Get("Cache-Control") != "no-store" || workflow.accessFindingListCalls != 1 ||
		workflow.accessFindingFilter.Status != iamv1.AccessFindingStatusFilter(iamv1.AccessFindingArchived) ||
		!strings.Contains(findings.Body.String(), `"SOURCE_NOT_READY"`) || !strings.Contains(findings.Body.String(), `"items":[]`) {
		t.Fatalf("access finding coverage was not explicit: %s", findings.Body.String())
	}
	finding := call(http.MethodGet, "/v1/account/access-analyzers/analyzer-one/findings/finding-one", "", http.StatusOK)
	if finding.Header().Get("Cache-Control") != "no-store" || workflow.accessFindingReadCalls != 1 ||
		workflow.accessFindingID != "finding-one" {
		t.Fatal("access finding read lost its exact target")
	}
	archived := call(http.MethodPost, "/v1/account/access-analyzers/analyzer-one/findings/finding-one:archive",
		`{"resourceVersion":1,"requestId":"finding-archive"}`, http.StatusOK)
	if workflow.accessFindingArchiveCalls != 1 || workflow.accessFindingRequest.RequestID != "finding-archive" ||
		!strings.Contains(archived.Body.String(), `"status":"ARCHIVED"`) {
		t.Fatal("access finding archive was not preserved")
	}
	unarchived := call(http.MethodPost, "/v1/account/access-analyzers/analyzer-one/findings/finding-one:unarchive",
		`{"resourceVersion":2,"requestId":"finding-unarchive"}`, http.StatusOK)
	if workflow.accessFindingUnarchiveCalls != 1 || !strings.Contains(unarchived.Body.String(), `"status":"ACTIVE"`) {
		t.Fatal("access finding unarchive was not preserved")
	}

	for _, sample := range []struct {
		method, path, body string
		want               int
	}{
		{http.MethodGet, "/v1/account/access-analyzers?accountId=other", "", http.StatusBadRequest},
		{http.MethodPost, "/v1/account/access-analyzers", `{"type":"UNUSED_ACCESS","requestId":"x","accountId":"other"}`, http.StatusBadRequest},
		{http.MethodGet, "/v1/account/access-analyzers/analyzer-one?tenantId=other", "", http.StatusBadRequest},
		{http.MethodPost, "/v1/account/access-analyzers/analyzer-one:set-disposition", `{"disposition":{"mode":"DISABLE_UNUSED_ACCESS_KEYS","findingDelayDays":7},"resourceVersion":3,"requestId":"invalid","userId":"forged"}`, http.StatusBadRequest},
		{http.MethodGet, "/v1/account/access-analyzers/analyzer-one/findings?status=UNKNOWN", "", http.StatusBadRequest},
		{http.MethodGet, "/v1/account/access-analyzers/analyzer-one/findings?status=ACTIVE&status=ARCHIVED", "", http.StatusBadRequest},
		{http.MethodGet, "/v1/account/access-analyzers/analyzer-one/findings/finding-one/nested", "", http.StatusNotFound},
		{http.MethodPost, "/v1/account/access-analyzers/analyzer-one/findings/finding-one:resolve", `{"resourceVersion":3,"requestId":"invented"}`, http.StatusMethodNotAllowed},
		{http.MethodDelete, "/v1/account/access-analyzers/analyzer-one", "", http.StatusMethodNotAllowed},
	} {
		response := call(sample.method, sample.path, sample.body, sample.want)
		if response.Code < 400 {
			t.Fatal("invalid access analyzer route was accepted")
		}
	}
	workflow.accessAnalyzerErr = identityaccess.ErrAccessAnalyzerNotFound
	missing := call(http.MethodGet, "/v1/account/access-analyzers/analyzer-missing", "", http.StatusNotFound)
	if !strings.Contains(missing.Body.String(), "iam.access-analyzer.not-found") {
		t.Fatalf("missing access analyzer problem=%s", missing.Body.String())
	}
}

func httpSecurityReportFixture(t testing.TB) (iamv1.AccountSecurityReport, []byte) {
	t.Helper()
	observed := time.Date(2026, 10, 2, 8, 9, 10, 0, time.UTC)
	report := iamv1.AccountSecurityReport{
		Metadata: iamv1.AccountSecurityReportMetadata{APIVersion: iamv1.APIVersion, Kind: "AccountSecurityReportMetadata",
			ID: "report-one", AccountID: "account-one", FormatVersion: 1, ObservedAt: observed, ExpiresAt: observed.Add(iamv1.SecurityReportRetention),
			DocumentDigest: "sha256:" + strings.Repeat("0", 64), CSVContentDigest: "sha256:" + strings.Repeat("0", 64), UserCount: 1, RowCount: 2, CSVBytes: 1},
		AccountSecuritySettingsVersion: 1, Coverage: iamv1.SecurityReportCoverageContract(),
		Users: []iamv1.SecurityReportUser{{ID: "user-root", LoginName: "root", DisplayName: "Root", Status: iamv1.PrincipalActive,
			Root: true, ResourceVersion: 1, CreatedAt: observed.Add(-time.Hour), MFA: iamv1.SecurityReportMFAState{EnrollmentState: "NEVER_BOUND", FactorRevision: 1},
			LastPasswordLogin: iamv1.SecurityReportTimeObservation{State: iamv1.SecurityReportNotObservedInRetainedIAMState}}},
		AccessKeys: []iamv1.SecurityReportAccessKey{},
	}
	_, documentDigest, err := iamv1.CanonicalizeAccountSecurityReportDocument(report)
	if err != nil {
		t.Fatal(err)
	}
	csvDocument, csvDigest, err := iamv1.EncodeAccountSecurityReportCSV(report)
	if err != nil {
		t.Fatal(err)
	}
	report.Metadata.DocumentDigest, report.Metadata.CSVContentDigest, report.Metadata.CSVBytes = documentDigest, csvDigest, uint32(len(csvDocument))
	if iamv1.ValidateAccountSecurityReport(report) != nil {
		t.Fatal("invalid HTTP security report fixture")
	}
	return report, csvDocument
}

type httpWorkflow struct {
	resetCompletion            iamv1.UserPasswordResetCompletion
	resetCompletionCalls       int
	resetCompletionError       error
	passwordRequirements       iamv1.PasswordRequirements
	passwordRequirementsCalls  int
	passwordRequirementsError  error
	passwordRequirementsBearer iamv1.Secret
	Workflow
	policyCalls                      int
	ownSessionCalls                  int
	policyPlatform                   bool
	policyCredential                 iamv1.Secret
	profileErr                       error
	invalidProfile                   bool
	templateCalls                    int
	templateCredential               iamv1.Secret
	templateErr                      error
	invalidTemplate                  bool
	readiness                        iamv1.Readiness
	status                           iamv1.BootstrapStatus
	identity                         iamv1.ServiceIdentity
	login                            iamv1.LoginResponse
	decision                         iamv1.AuthorizationDecision
	diagnosis                        iamv1.CurrentAccessDiagnosis
	batchDecision                    iamv1.AuthorizationBatchDecision
	authorizationBatchRequest        iamv1.AuthorizationBatchRequest
	verificationDecision             iamv1.AuthorizationDecision
	loginErr                         error
	identityCalls                    int
	loginCalls                       int
	verifiedChallengeID              string
	enrollmentCalls                  int
	enrollmentCredential             iamv1.Secret
	enrollmentRequestID              string
	enrollmentVerificationID         string
	enrollmentState                  iamv1.EnrollmentChallengeState
	enrollmentStart                  iamv1.StartTOTPEnrollmentResponse
	enrollmentConfirmation           iamv1.ConfirmTOTPEnrollmentResponse
	enrollmentMail                   iamv1.NotificationContactVerification
	enrollmentErr                    error
	notificationReplacementRequest   iamv1.StartNotificationContactReplacementRequest
	totpCalls                        int
	stepCalls                        int
	stepCredential                   iamv1.Secret
	stepResult                       iamv1.StepUp
	regenerationResult               iamv1.RegenerateRecoveryCodesResponse
	removalResult                    iamv1.RemoveTOTPResponse
	stepErr                          error
	getUserCalls                     int
	updateUserCalls                  int
	deleteUserCalls                  int
	userID                           iamv1.PrincipalID
	updateUser                       iamv1.UpdateUserRequest
	deleteUser                       iamv1.DeleteUserRequest
	authorizeCalls                   int
	diagnoseCalls                    int
	authorizeBatchCalls              int
	keyCalls                         int
	keyListCalls                     int
	keyListRequest                   iamv1.AccessKeyListAuthorizationRequest
	keyResolveCalls                  int
	keyResolveRequest                iamv1.ResolveAccessKeySubjectRequest
	verifyInstallationCalls          int
	settingsCalls                    int
	settingsCredential               iamv1.Secret
	settingsErr                      error
	settingsRequest                  iamv1.UpdateAccountSecuritySettingsRequest
	settingsChange                   iamv1.AccountSecuritySettingsChange
	settingsCommand                  string
	securityReport                   iamv1.AccountSecurityReport
	securityReportCSV                []byte
	securityReportOutcome            string
	securityReportErr                error
	securityReportCreateCalls        int
	securityReportReadCalls          int
	securityReportDownloadCalls      int
	securityReportCredential         iamv1.Secret
	securityReportRequest            iamv1.CreateAccountSecurityReportRequest
	securityReportID                 iamv1.SecurityReportID
	accessAnalyzer                   iamv1.AccessAnalyzer
	accessAnalyzerList               iamv1.AccessAnalyzerList
	accessFindingList                iamv1.AccessFindingList
	accessFinding                    iamv1.AccessFinding
	accessFindingFilter              iamv1.AccessFindingFilter
	accessAnalyzerErr                error
	accessAnalyzerCredential         iamv1.Secret
	accessAnalyzerID                 iamv1.AccessAnalyzerID
	accessAnalyzerCreateRequest      iamv1.CreateAccessAnalyzerRequest
	accessAnalyzerUpdateRequest      iamv1.UpdateAccessAnalyzerRequest
	accessDispositionRequest         iamv1.SetAccessDispositionRequest
	accessAnalyzerCreateCalls        int
	accessAnalyzerListCalls          int
	accessAnalyzerReadCalls          int
	accessAnalyzerUpdateCalls        int
	accessDispositionCalls           int
	accessFindingListCalls           int
	accessFindingReadCalls           int
	accessFindingArchiveCalls        int
	accessFindingUnarchiveCalls      int
	accessFindingID                  iamv1.AccessFindingID
	accessFindingRequest             iamv1.AccessFindingDispositionRequest
	workloadBindingCalls             int
	workloadServiceCredential        iamv1.Secret
	workloadSubjectCredential        iamv1.Secret
	workloadBindingRequest           iamv1.CreateWorkloadRoleBindingRequest
	workloadRevocationCalls          int
	workloadRevokeServiceCredential  iamv1.Secret
	workloadRevokeSubjectCredential  iamv1.Secret
	workloadRevocationID             iamv1.WorkloadRoleBindingID
	workloadRevocationRequest        iamv1.RevokeWorkloadRoleBindingRequest
	serviceLinkedRoleListCalls       int
	serviceLinkedRoleReadCalls       int
	serviceLinkedRoleCredential      iamv1.Secret
	serviceLinkedRoleID              iamv1.RoleID
	invalidServiceLinkedRole         bool
	serviceRoleSessionCalls          int
	serviceRoleSessionCredential     iamv1.Secret
	serviceRoleSessionRequest        iamv1.AssumeServiceRoleRequest
	serviceRoleSessionReadCalls      int
	serviceRoleSessionReadCredential iamv1.Secret
	serviceRoleSessionReadRequestID  string
	serviceRoleSessionResult         iamv1.AssumeRoleResponse
	serviceRoleSessionFound          bool
	serviceRoleSessionErr            error
}

func (value *httpWorkflow) CreateAccountSecurityReport(_ context.Context, credential iamv1.Secret, request iamv1.CreateAccountSecurityReportRequest) (iamv1.CreateAccountSecurityReportResponse, error) {
	value.securityReportCreateCalls++
	value.securityReportCredential, value.securityReportRequest = credential, request
	return iamv1.CreateAccountSecurityReportResponse{Outcome: value.securityReportOutcome, Metadata: value.securityReport.Metadata}, value.securityReportErr
}

func (value *httpWorkflow) AccountSecurityReport(_ context.Context, credential iamv1.Secret, id iamv1.SecurityReportID, _ string) (iamv1.AccountSecurityReport, error) {
	value.securityReportReadCalls++
	value.securityReportCredential, value.securityReportID = credential, id
	return value.securityReport, value.securityReportErr
}

func (value *httpWorkflow) DownloadAccountSecurityReport(_ context.Context, credential iamv1.Secret, id iamv1.SecurityReportID, _ string) ([]byte, error) {
	value.securityReportDownloadCalls++
	value.securityReportCredential, value.securityReportID = credential, id
	return append([]byte(nil), value.securityReportCSV...), value.securityReportErr
}

func (value *httpWorkflow) CreateAccessAnalyzer(_ context.Context, credential iamv1.Secret, request iamv1.CreateAccessAnalyzerRequest) (iamv1.AccessAnalyzer, error) {
	value.accessAnalyzerCreateCalls++
	value.accessAnalyzerCredential, value.accessAnalyzerCreateRequest = credential, request
	return value.accessAnalyzer, value.accessAnalyzerErr
}

func (value *httpWorkflow) ListAccessAnalyzers(_ context.Context, credential iamv1.Secret, _ string, _ string) (iamv1.AccessAnalyzerList, error) {
	value.accessAnalyzerListCalls++
	value.accessAnalyzerCredential = credential
	return value.accessAnalyzerList, value.accessAnalyzerErr
}

func (value *httpWorkflow) AccessAnalyzer(_ context.Context, credential iamv1.Secret, id iamv1.AccessAnalyzerID, _ string) (iamv1.AccessAnalyzer, error) {
	value.accessAnalyzerReadCalls++
	value.accessAnalyzerCredential, value.accessAnalyzerID = credential, id
	return value.accessAnalyzer, value.accessAnalyzerErr
}

func (value *httpWorkflow) UpdateAccessAnalyzer(_ context.Context, credential iamv1.Secret, id iamv1.AccessAnalyzerID, request iamv1.UpdateAccessAnalyzerRequest) (iamv1.AccessAnalyzer, error) {
	value.accessAnalyzerUpdateCalls++
	value.accessAnalyzerCredential, value.accessAnalyzerID, value.accessAnalyzerUpdateRequest = credential, id, request
	return value.accessAnalyzer, value.accessAnalyzerErr
}

func (value *httpWorkflow) SetAccessDisposition(_ context.Context, credential iamv1.Secret, id iamv1.AccessAnalyzerID, request iamv1.SetAccessDispositionRequest) (iamv1.AccessAnalyzer, error) {
	value.accessDispositionCalls++
	value.accessAnalyzerCredential, value.accessAnalyzerID, value.accessDispositionRequest = credential, id, request
	return value.accessAnalyzer, value.accessAnalyzerErr
}

func (value *httpWorkflow) ListAccessFindings(_ context.Context, credential iamv1.Secret, id iamv1.AccessAnalyzerID,
	filter iamv1.AccessFindingFilter, _ string, _ string) (iamv1.AccessFindingList, error) {
	value.accessFindingListCalls++
	value.accessAnalyzerCredential, value.accessAnalyzerID = credential, id
	value.accessFindingFilter = filter
	return value.accessFindingList, value.accessAnalyzerErr
}

func (value *httpWorkflow) AccessFinding(_ context.Context, credential iamv1.Secret, analyzerID iamv1.AccessAnalyzerID,
	findingID iamv1.AccessFindingID, _ string) (iamv1.AccessFinding, error) {
	value.accessFindingReadCalls++
	value.accessAnalyzerCredential, value.accessAnalyzerID, value.accessFindingID = credential, analyzerID, findingID
	return value.accessFinding, value.accessAnalyzerErr
}

func (value *httpWorkflow) ArchiveAccessFinding(_ context.Context, credential iamv1.Secret, analyzerID iamv1.AccessAnalyzerID,
	findingID iamv1.AccessFindingID, request iamv1.AccessFindingDispositionRequest) (iamv1.AccessFinding, error) {
	value.accessFindingArchiveCalls++
	value.accessAnalyzerCredential, value.accessAnalyzerID, value.accessFindingID, value.accessFindingRequest = credential, analyzerID, findingID, request
	value.accessFinding.Status, value.accessFinding.ResourceVersion, value.accessFinding.UpdatedAt = iamv1.AccessFindingArchived, request.ResourceVersion+1, value.accessFinding.UpdatedAt.Add(time.Second)
	return value.accessFinding, value.accessAnalyzerErr
}

func (value *httpWorkflow) UnarchiveAccessFinding(_ context.Context, credential iamv1.Secret, analyzerID iamv1.AccessAnalyzerID,
	findingID iamv1.AccessFindingID, request iamv1.AccessFindingDispositionRequest) (iamv1.AccessFinding, error) {
	value.accessFindingUnarchiveCalls++
	value.accessAnalyzerCredential, value.accessAnalyzerID, value.accessFindingID, value.accessFindingRequest = credential, analyzerID, findingID, request
	value.accessFinding.Status, value.accessFinding.ResourceVersion, value.accessFinding.UpdatedAt = iamv1.AccessFindingActive, request.ResourceVersion+1, value.accessFinding.UpdatedAt.Add(time.Second)
	return value.accessFinding, value.accessAnalyzerErr
}

func (value *httpWorkflow) UserPasswordResetCompletion(_ context.Context, credential iamv1.Secret, user iamv1.PrincipalID, command string, version uint64, _ string) (iamv1.UserPasswordResetCompletion, error) {
	value.resetCompletionCalls++
	if string(credential.CopyBytes()) != "current" || user != "reset-target" || command != "reset-command" || version != 7 {
		return iamv1.UserPasswordResetCompletion{}, identityaccess.ErrUnavailable
	}
	return value.resetCompletion, value.resetCompletionError
}

func (value *httpWorkflow) UpdateAccountSecuritySettings(_ context.Context, credential iamv1.Secret, request iamv1.UpdateAccountSecuritySettingsRequest) (iamv1.UpdateAccountSecuritySettingsResponse, error) {
	value.settingsCalls++
	value.settingsCredential, value.settingsRequest = credential, request
	return iamv1.UpdateAccountSecuritySettingsResponse{Outcome: "APPLIED", Change: value.settingsChange}, value.settingsErr
}

func (value *httpWorkflow) SecuritySettingsChange(_ context.Context, credential iamv1.Secret, command, _ string) (iamv1.AccountSecuritySettingsChange, error) {
	value.settingsCalls++
	value.settingsCredential, value.settingsCommand = credential, command
	return value.settingsChange, value.settingsErr
}

func (value *httpWorkflow) AccountSecuritySettings(_ context.Context, credential iamv1.Secret, _ string) (iamv1.AccountSecuritySettings, error) {
	value.settingsCalls++
	value.settingsCredential = credential
	return iamv1.AccountSecuritySettings{APIVersion: iamv1.APIVersion, Kind: "AccountSecuritySettings", AccountID: "account-catalog",
		ResourceVersion: 1, MFA: iamv1.AccountMFASettings{RequiredForUsers: false}, Password: &iamv1.AccountPasswordSettings{ExpiryMode: iamv1.PasswordExpiryChange, MinimumLength: 15, HistoryCount: 1},
		Session: &iamv1.AccountSessionSettings{IdleTimeoutMinutes: 30}, AccessKeyNetwork: &iamv1.AccessKeyNetworkRestrictions{AllowedSourceCIDRs: []string{}}, UpdatedAt: time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC)}, value.settingsErr
}

func (value *httpWorkflow) ListAuthorizationProfiles(_ context.Context, credential iamv1.Secret, _ string) (iamv1.AuthorizationProfileList, error) {
	value.policyCalls++
	value.policyCredential = credential
	profile, _ := iamv1.LookupAuthorizationProfile(iamv1.ProductIAM)
	_, digest, _ := iamv1.CanonicalizeAuthorizationProfile(profile)
	if value.invalidProfile {
		digest = "invalid-digest"
	}
	return iamv1.AuthorizationProfileList{APIVersion: iamv1.APIVersion, Kind: "AuthorizationProfileList", AccountID: "account-catalog",
		Items: []iamv1.AuthorizationProfileEntry{{Profile: profile, ContentDigest: digest}}}, value.profileErr
}

func (value *httpWorkflow) ListServiceRoleTemplates(_ context.Context, credential iamv1.Secret, _ string) (iamv1.ServiceRoleTemplateList, error) {
	value.templateCalls++
	value.templateCredential = credential
	templates, err := authority.BuiltInServiceRoleTemplates()
	if err != nil {
		return iamv1.ServiceRoleTemplateList{}, identityaccess.ErrUnavailable
	}
	if value.invalidTemplate {
		templates[0].ContentDigest = "invalid-digest"
	}
	return iamv1.ServiceRoleTemplateList{APIVersion: iamv1.APIVersion, Kind: "ServiceRoleTemplateList", Items: templates}, value.templateErr
}

func (value *httpWorkflow) ListServiceLinkedRoles(_ context.Context, credential iamv1.Secret, _, _ string) (iamv1.ServiceLinkedRoleList, error) {
	value.serviceLinkedRoleListCalls++
	value.serviceLinkedRoleCredential = credential
	access := serviceLinkedRoleAccessForHTTPTest()
	count := uint64(1)
	if value.invalidServiceLinkedRole {
		count = 0
	}
	return iamv1.ServiceLinkedRoleList{APIVersion: iamv1.APIVersion, Kind: "ServiceLinkedRoleList",
		AccountID: access.Relation.Role.AccountID, Items: []iamv1.ServiceLinkedRoleListing{{
			Relation: access.Relation, BindingCount: count, ActiveBindingCount: count}}}, nil
}

func (value *httpWorkflow) GetServiceLinkedRole(_ context.Context, credential iamv1.Secret, id iamv1.RoleID, _, _ string) (iamv1.ServiceLinkedRoleAccess, error) {
	value.serviceLinkedRoleReadCalls++
	value.serviceLinkedRoleCredential, value.serviceLinkedRoleID = credential, id
	result := serviceLinkedRoleAccessForHTTPTest()
	if value.invalidServiceLinkedRole {
		result.Kind = "InvalidServiceLinkedRoleAccess"
	}
	return result, nil
}

func (value *httpWorkflow) CreateWorkloadRoleBinding(_ context.Context, serviceCredential, subjectCredential iamv1.Secret,
	request iamv1.CreateWorkloadRoleBindingRequest) (iamv1.ServiceLinkedRoleAccess, error) {
	value.workloadBindingCalls++
	value.workloadServiceCredential, value.workloadSubjectCredential, value.workloadBindingRequest = serviceCredential, subjectCredential, request
	return serviceLinkedRoleAccessForHTTPTest(), nil
}

func (value *httpWorkflow) RevokeWorkloadRoleBinding(_ context.Context, serviceCredential, subjectCredential iamv1.Secret,
	id iamv1.WorkloadRoleBindingID, request iamv1.RevokeWorkloadRoleBindingRequest,
) (iamv1.WorkloadRoleBinding, error) {
	value.workloadRevocationCalls++
	value.workloadRevokeServiceCredential, value.workloadRevokeSubjectCredential = serviceCredential, subjectCredential
	value.workloadRevocationID, value.workloadRevocationRequest = id, request
	binding := serviceLinkedRoleAccessForHTTPTest().Bindings[0]
	binding.ID, binding.Workload = id, request.Authorization.Resource
	revokedAt := binding.CreatedAt.Add(time.Second)
	binding.Status, binding.ResourceVersion, binding.UpdatedAt, binding.RevokedAt =
		iamv1.WorkloadRoleBindingRevoked, request.ResourceVersion+1, revokedAt, &revokedAt
	return binding, nil
}

func (value *httpWorkflow) AssumeServiceRole(_ context.Context, credential iamv1.Secret,
	request iamv1.AssumeServiceRoleRequest,
) (iamv1.AssumeRoleResponse, error) {
	value.serviceRoleSessionCalls++
	value.serviceRoleSessionCredential, value.serviceRoleSessionRequest = credential, request
	return value.serviceRoleSessionResult, value.serviceRoleSessionErr
}

func (value *httpWorkflow) GetServiceRoleSessionByRequest(_ context.Context, credential iamv1.Secret,
	requestID string,
) (iamv1.RoleSession, bool, error) {
	value.serviceRoleSessionReadCalls++
	value.serviceRoleSessionReadCredential, value.serviceRoleSessionReadRequestID = credential, requestID
	return value.serviceRoleSessionResult.Session, value.serviceRoleSessionFound, value.serviceRoleSessionErr
}

func serviceLinkedRoleAccessForHTTPTest() iamv1.ServiceLinkedRoleAccess {
	createdAt := time.Date(2026, 9, 30, 3, 0, 0, 0, time.UTC)
	templates, _ := authority.BuiltInServiceRoleTemplates()
	template := templates[0]
	role := iamv1.Role{APIVersion: iamv1.APIVersion, Kind: "Role", ID: "role-service-linked", AccountID: "account-a",
		Name: template.Spec.RoleName, Description: template.Spec.RoleDescription, Tags: []iamv1.RoleTag{}, Management: iamv1.RoleServiceLinked,
		Status: iamv1.RoleActive, MaxSessionDurationSeconds: template.Spec.MaxSessionDurationSeconds, ResourceVersion: 1,
		CurrentTrustVersionID: "trust-service-linked", CreatedAt: createdAt, UpdatedAt: createdAt}
	binding := iamv1.WorkloadRoleBinding{APIVersion: iamv1.APIVersion, Kind: "WorkloadRoleBinding", ID: "binding-service-linked",
		AccountID: role.AccountID, RoleID: role.ID, Template: template.Reference(),
		Workload: iamv1.ResourceReference{Kind: iamv1.ResourceServiceInstallation, ID: "service-installation-a"},
		Status:   iamv1.WorkloadRoleBindingActive, ResourceVersion: 1, CreatedAt: createdAt, UpdatedAt: createdAt}
	return iamv1.ServiceLinkedRoleAccess{APIVersion: iamv1.APIVersion, Kind: "ServiceLinkedRoleAccess",
		Relation: iamv1.ServiceLinkedRole{APIVersion: iamv1.APIVersion, Kind: "ServiceLinkedRole", Role: role,
			Template: template.Reference(), ServicePrincipal: iamv1.ServicePrincipalReference{
				InstallationID: "installation-a", PrincipalID: "service-paas-a", Purpose: iamv1.ServicePaaS},
			PermissionCeiling: template.Spec.PolicyVersion}, Bindings: []iamv1.WorkloadRoleBinding{binding}}
}

func (value *httpWorkflow) ListPolicies(_ context.Context, credential iamv1.Secret, platform bool, _ string) (iamv1.PolicyList, error) {
	value.policyCalls++
	value.policyPlatform, value.policyCredential = platform, credential
	result := iamv1.PolicyList{APIVersion: iamv1.APIVersion, Kind: "PolicyList", AccountID: "account-catalog", Scope: iamv1.AuthorityScopeTenant, Items: []iamv1.Policy{}}
	if platform {
		result.Scope, result.InstallationID = iamv1.AuthorityScopeInstallation, "installation-catalog"
	}
	return result, nil
}

func TestIAMRoleRoutesRejectSelectorsBeforeWorkflow(t *testing.T) {
	handler := newTestHandler(t, newHTTPWorkflow(t))
	for _, attack := range []struct {
		method, path, body string
		status             int
	}{
		{http.MethodGet, "/v1/roles?tenantId=other", "", http.StatusBadRequest},
		{http.MethodGet, "/v1/roles/role-a?accountId=other", "", http.StatusBadRequest},
		{http.MethodGet, "/v1/roles/role-a/trust-versions?roleId=other", "", http.StatusBadRequest},
		{http.MethodGet, "/v1/roles/role-a/trust-versions/trust-a?after=ic1.invalid", "", http.StatusBadRequest},
		{http.MethodGet, "/v1/roles", "{}", http.StatusBadRequest},
		{http.MethodPost, "/v1/roles", `{"name":"Readers","tags":[],"trustPolicy":{"languageVersion":"1","statements":[]},"accountId":"other","requestId":"create"}`, http.StatusBadRequest},
		{http.MethodPost, "/v1/roles", `{"name":"Readers","tags":[],"maxSessionDurationSeconds":null,"trustPolicy":{"languageVersion":"1","statements":[]},"requestId":"create"}`, http.StatusBadRequest},
		{http.MethodPost, "/v1/roles", `{"name":"Readers","name":"Other","tags":[],"trustPolicy":{"languageVersion":"1","statements":[]},"requestId":"create"}`, http.StatusBadRequest},
		{http.MethodPatch, "/v1/roles/role-a", `{"name":"Readers","tags":[],"maxSessionDurationSeconds":3600,"resourceVersion":1,"requestId":"update"}`, http.StatusBadRequest},
		{http.MethodPost, "/v1/roles/role-a:set-status", `{"status":"ACTIVE","resourceVersion":1,"actorSessionId":"other","requestId":"status"}`, http.StatusBadRequest},
		{http.MethodDelete, "/v1/roles/role-a?installationId=other", `{"resourceVersion":1,"requestId":"delete"}`, http.StatusBadRequest},
		{http.MethodPost, "/v1/roles/role-a:assume", `{}`, http.StatusUnprocessableEntity},
		{http.MethodPost, "/v1/roles/role-a:assume", `{"resourceVersion":1,"requestId":"x","sourceSessionId":"injected"}`, http.StatusBadRequest},
		{http.MethodPost, "/v1/roles/role-a:assume?tenantId=other", `{"resourceVersion":1,"requestId":"x"}`, http.StatusBadRequest},
		{http.MethodGet, "/v1/auth/role-sessions/by-request/x?userId=other", ``, http.StatusBadRequest},
		{http.MethodGet, "/v1/auth/role-session?roleId=other", ``, http.StatusBadRequest},
		{http.MethodGet, "/v1/auth/assumable-roles?accountId=other", ``, http.StatusBadRequest},
		{http.MethodGet, "/v1/auth/assumable-roles?userId=other", ``, http.StatusBadRequest},
		{http.MethodGet, "/v1/auth/assumable-roles?sourceSessionId=other", ``, http.StatusBadRequest},
		{http.MethodGet, "/v1/auth/assumable-roles?after=ic1.management", ``, http.StatusBadRequest},
		{http.MethodGet, "/v1/auth/assumable-roles", `{"sourceUserId":"other"}`, http.StatusBadRequest},
		{http.MethodPost, "/v1/auth/assumable-roles", `{}`, http.StatusMethodNotAllowed},
		{http.MethodGet, "/v1/auth/role-session", `{"sourceUserId":"other"}`, http.StatusBadRequest},
		{http.MethodPost, "/v1/auth/role-session", `{}`, http.StatusMethodNotAllowed},
		{http.MethodPost, "/v1/auth/role-sessions/by-request/x:revoke", `{"requestId":"y","roleId":"injected"}`, http.StatusBadRequest},
		{http.MethodPost, "/v1/sts/assume-role", `{}`, http.StatusNotFound},
		{http.MethodPost, "/v1/roles/role-a/trust-policy", `{}`, http.StatusMethodNotAllowed},
	} {
		t.Run(attack.method+attack.path+attack.body, func(t *testing.T) {
			request := httptest.NewRequest(attack.method, attack.path, strings.NewReader(attack.body))
			request.Header.Set("Authorization", "Bearer role-test-credential")
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != attack.status {
				t.Fatalf("role request status=%d want=%d", response.Code, attack.status)
			}
		})
	}
}

func TestIAMGroupRoutesRejectSelectorsBeforeWorkflow(t *testing.T) {
	handler := newTestHandler(t, newHTTPWorkflow(t))
	for _, attack := range []struct {
		method, path, body string
		status             int
	}{
		{http.MethodGet, "/v1/groups?tenantId=other", "", http.StatusBadRequest},
		{http.MethodGet, "/v1/groups/g1?accountId=other", "", http.StatusBadRequest},
		{http.MethodGet, "/v1/groups/g1/memberships?groupId=g2", "", http.StatusBadRequest},
		{http.MethodGet, "/v1/groups", "{}", http.StatusBadRequest},
		{http.MethodPost, "/v1/groups", `{"name":"group","requestId":"request","accountId":"other"}`, http.StatusBadRequest},
		{http.MethodPost, "/v1/groups/g1/memberships", `{"userId":"u1","requestId":"request","kind":"ROLE"}`, http.StatusBadRequest},
		{http.MethodPost, "/v1/groups/g1:update", `{"name":"changed","resourceVersion":1,"requestId":"request","policies":[]}`, http.StatusBadRequest},
		{http.MethodPost, "/v1/groups/g1:delete?installationId=other", `{"resourceVersion":1,"requestId":"request"}`, http.StatusBadRequest},
		{http.MethodPost, "/v1/groups/g1/memberships/m1:remove", `{"resourceVersion":1,"requestId":"request","userId":"u2"}`, http.StatusBadRequest},
		{http.MethodDelete, "/v1/groups/g1", "", http.StatusMethodNotAllowed},
		{http.MethodPost, "/v1/groups/g1/memberships/m1:activate", "{}", http.StatusNotFound},
	} {
		t.Run(attack.method+attack.path, func(t *testing.T) {
			request := httptest.NewRequest(attack.method, attack.path, strings.NewReader(attack.body))
			request.Header.Set("Authorization", "Bearer group-test-credential")
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != attack.status {
				t.Fatalf("group request status=%d want=%d body=%s", response.Code, attack.status, response.Body.String())
			}
		})
	}
}

func newHTTPWorkflow(t *testing.T) *httpWorkflow {
	t.Helper()
	now := time.Date(2026, 8, 26, 9, 10, 11, 123000, time.UTC)
	appliedAt := now.Add(-time.Hour)
	credential, err := iamv1.NewSecret("issued-session-credential")
	if err != nil {
		t.Fatalf("create HTTP test credential: %v", err)
	}
	subject := &iamv1.Subject{Type: iamv1.SubjectUser, ID: "principal-admin"}
	workflow := &httpWorkflow{
		readiness: iamv1.Readiness{
			APIVersion:    iamv1.APIVersion,
			Kind:          "Readiness",
			State:         iamv1.ReadinessReady,
			SchemaVersion: 1,
			CheckedAt:     now,
		},
		status: iamv1.BootstrapStatus{
			APIVersion:     iamv1.APIVersion,
			Kind:           "BootstrapStatus",
			State:          iamv1.BootstrapReady,
			InstallationID: "installation-example",
			AccountID:      "organization-example",
			ContentDigest:  "sha256:" + strings.Repeat("1", 64),
			AppliedAt:      &appliedAt,
		},
		identity: iamv1.ServiceIdentity{
			InstallationID: "installation-example",
			APIVersion:     iamv1.APIVersion,
			Kind:           "ServiceIdentity",
			AccountID:      "organization-example",
			PrincipalID:    "service-paas",
			Purpose:        iamv1.ServicePaaS,
		},
		login: iamv1.LoginResponse{
			Outcome: iamv1.LoginAuthenticated,
			Session: iamv1.Session{
				APIVersion:  iamv1.APIVersion,
				Kind:        "Session",
				ID:          "session-example",
				AccountID:   "organization-example",
				PrincipalID: "principal-admin",
				Status:      iamv1.SessionActive,
				IssuedAt:    now,
				ExpiresAt:   now.Add(time.Hour),
			},
			Credential:         credential,
			MustChangePassword: true,
		},
		decision: iamv1.AuthorizationDecision{
			APIVersion: iamv1.APIVersion,
			Kind:       "AuthorizationDecision",
			ID:         "decision-example",
			Allowed:    true,
			Reason:     iamv1.DecisionAllowed,
			TenantID:   "organization-example",
			Subject:    subject,
			Action:     iamv1.ActionPaaSApplicationRead,
			Resource:   iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "application-example"},
			RequestID:  "request-authorize",
			DecidedAt:  now,
		},
	}
	verificationSubject := &iamv1.Subject{
		Type: iamv1.SubjectServiceAccount, ID: "service-installation-verifier",
	}
	workflow.verificationDecision = iamv1.AuthorizationDecision{
		APIVersion: iamv1.APIVersion,
		Kind:       "AuthorizationDecision",
		ID:         "decision-installation-verification",
		Allowed:    true,
		Reason:     iamv1.DecisionAllowed,
		TenantID:   "organization-example",
		Subject:    verificationSubject,
		Action:     iamv1.ActionInstallationVerify,
		Resource: iamv1.ResourceReference{
			Kind: iamv1.ResourceInstallation, ID: "installation-example",
		},
		RequestID: "request-installation-verify",
		DecidedAt: now,
	}
	for decision, correlation := range map[*iamv1.AuthorizationDecision]string{
		&workflow.decision: "correlation-authorize", &workflow.verificationDecision: "correlation-installation-verify",
	} {
		request, err := iamv1.NewAuthorizationRequest(decision.Action, decision.Resource, iamv1.AuthorizationResourceInstance, "", decision.RequestID, correlation)
		if err != nil {
			t.Fatal(err)
		}
		decision.Profile, decision.ResourceMode, decision.CorrelationID = &request.Profile, request.ResourceMode, request.CorrelationID
	}
	return workflow
}

func (workflow *httpWorkflow) Readiness(context.Context) (iamv1.Readiness, error) {
	return workflow.readiness, nil
}

func (workflow *httpWorkflow) BootstrapStatus(context.Context, iamv1.Secret) (iamv1.BootstrapStatus, error) {
	return workflow.status, nil
}

func (workflow *httpWorkflow) ServiceIdentity(context.Context, iamv1.Secret) (iamv1.ServiceIdentity, error) {
	workflow.identityCalls++
	return workflow.identity, nil
}

func (workflow *httpWorkflow) Login(context.Context, iamv1.LoginRequest) (iamv1.LoginResponse, error) {
	workflow.loginCalls++
	if workflow.loginErr != nil {
		return iamv1.LoginResponse{}, workflow.loginErr
	}
	return workflow.login, nil
}

func (workflow *httpWorkflow) VerifyAuthenticationChallenge(_ context.Context, id string, _ iamv1.VerifyAuthenticationChallengeRequest) (iamv1.LoginResponse, error) {
	workflow.verifiedChallengeID = id
	return workflow.login, nil
}

func (workflow *httpWorkflow) ChangeChallengePassword(_ context.Context, id string, _ iamv1.ChallengePasswordChangeRequest) (iamv1.ChallengePasswordChangeResponse, error) {
	workflow.verifiedChallengeID = id
	return iamv1.ChallengePasswordChangeResponse{}, identityaccess.ErrUnavailable
}

func (workflow *httpWorkflow) StartAuthenticatorRecovery(_ context.Context, id string, _ iamv1.StartAuthenticatorRecoveryRequest) (iamv1.StartAuthenticatorRecoveryResponse, error) {
	workflow.verifiedChallengeID = id
	return iamv1.StartAuthenticatorRecoveryResponse{}, identityaccess.ErrUnavailable
}

func (workflow *httpWorkflow) ConfirmAuthenticatorRecovery(_ context.Context, id string, _ iamv1.VerifyAuthenticationChallengeRequest) (iamv1.ConfirmAuthenticatorRecoveryResponse, error) {
	workflow.verifiedChallengeID = id
	return iamv1.ConfirmAuthenticatorRecoveryResponse{}, identityaccess.ErrUnavailable
}

func (workflow *httpWorkflow) InspectAuthenticatorRecovery(_ context.Context, id string, _ iamv1.InspectAuthenticatorRecoveryRequest) (iamv1.AuthenticatorRecovery, error) {
	workflow.verifiedChallengeID = id
	return iamv1.AuthenticatorRecovery{}, identityaccess.ErrUnavailable
}

func (workflow *httpWorkflow) AuthenticatorState(context.Context, iamv1.Secret) (iamv1.AuthenticatorState, error) {
	workflow.totpCalls++
	return iamv1.AuthenticatorState{}, identityaccess.ErrUnavailable
}

func (workflow *httpWorkflow) InspectEnrollmentChallenge(_ context.Context, id string, body iamv1.InspectEnrollmentChallengeRequest) (iamv1.EnrollmentChallengeState, error) {
	workflow.enrollmentCalls++
	workflow.verifiedChallengeID, workflow.enrollmentCredential = id, body.ChallengeCredential
	return workflow.enrollmentState, workflow.enrollmentErr
}

func (workflow *httpWorkflow) StartChallengeTOTPEnrollment(_ context.Context, id string, body iamv1.StartChallengeTOTPEnrollmentRequest) (iamv1.StartTOTPEnrollmentResponse, error) {
	workflow.enrollmentCalls++
	workflow.verifiedChallengeID, workflow.enrollmentCredential, workflow.enrollmentRequestID = id, body.ChallengeCredential, body.RequestID
	return workflow.enrollmentStart, workflow.enrollmentErr
}

func (workflow *httpWorkflow) ConfirmChallengeTOTPEnrollment(_ context.Context, id string, body iamv1.VerifyAuthenticationChallengeRequest) (iamv1.ConfirmTOTPEnrollmentResponse, error) {
	workflow.enrollmentCalls++
	workflow.verifiedChallengeID, workflow.enrollmentCredential, workflow.enrollmentRequestID = id, body.ChallengeCredential, body.RequestID
	return workflow.enrollmentConfirmation, workflow.enrollmentErr
}

func (workflow *httpWorkflow) StartChallengeNotificationVerification(_ context.Context, id string, body iamv1.StartChallengeNotificationContactVerificationRequest) (iamv1.NotificationContactVerification, error) {
	workflow.enrollmentCalls++
	workflow.verifiedChallengeID, workflow.enrollmentCredential, workflow.enrollmentRequestID = id, body.ChallengeCredential, body.RequestID
	return workflow.enrollmentMail, workflow.enrollmentErr
}

func (workflow *httpWorkflow) ConfirmChallengeNotificationContact(_ context.Context, id, verificationID string, body iamv1.ConfirmChallengeNotificationContactVerificationRequest) (iamv1.NotificationContactVerification, error) {
	workflow.enrollmentCalls++
	workflow.verifiedChallengeID, workflow.enrollmentCredential, workflow.enrollmentRequestID = id, body.ChallengeCredential, body.RequestID
	workflow.enrollmentVerificationID = verificationID
	return workflow.enrollmentMail, workflow.enrollmentErr
}

func (workflow *httpWorkflow) StartNotificationContactReplacement(_ context.Context, credential iamv1.Secret, body iamv1.StartNotificationContactReplacementRequest) (iamv1.NotificationContactVerification, error) {
	workflow.stepCalls++
	workflow.stepCredential, workflow.notificationReplacementRequest = credential, body
	return workflow.enrollmentMail, workflow.enrollmentErr
}

func (workflow *httpWorkflow) StartStepUp(_ context.Context, credential iamv1.Secret, _ iamv1.StartStepUpRequest) (iamv1.StepUp, error) {
	workflow.stepCalls++
	workflow.stepCredential = credential
	return workflow.stepResult, workflow.stepErr
}
func (workflow *httpWorkflow) StepUpByRequest(_ context.Context, credential iamv1.Secret, _ string) (iamv1.StepUp, error) {
	workflow.stepCalls++
	workflow.stepCredential = credential
	return workflow.stepResult, workflow.stepErr
}
func (workflow *httpWorkflow) VerifyStepUp(_ context.Context, credential iamv1.Secret, _ string, _ iamv1.VerifyStepUpRequest) (iamv1.StepUp, error) {
	workflow.stepCalls++
	workflow.stepCredential = credential
	return workflow.stepResult, workflow.stepErr
}
func (workflow *httpWorkflow) RegenerateRecoveryCodes(_ context.Context, credential iamv1.Secret, _ iamv1.RegenerateRecoveryCodesRequest) (iamv1.RegenerateRecoveryCodesResponse, error) {
	workflow.stepCalls++
	workflow.stepCredential = credential
	return workflow.regenerationResult, workflow.stepErr
}
func (workflow *httpWorkflow) RecoveryCodeRegenerationByRequest(_ context.Context, credential iamv1.Secret, _ string) (iamv1.RecoveryCodeRegeneration, error) {
	workflow.stepCalls++
	workflow.stepCredential = credential
	return workflow.regenerationResult.Regeneration, workflow.stepErr
}
func (workflow *httpWorkflow) RemoveTOTP(_ context.Context, credential iamv1.Secret, _ iamv1.RemoveTOTPRequest) (iamv1.RemoveTOTPResponse, error) {
	workflow.stepCalls++
	workflow.stepCredential = credential
	return workflow.removalResult, workflow.stepErr
}
func (workflow *httpWorkflow) AuthenticatorRemovalByRequest(_ context.Context, credential iamv1.Secret, _ string) (iamv1.AuthenticatorRemoval, error) {
	workflow.stepCalls++
	workflow.stepCredential = credential
	return workflow.removalResult.Removal, workflow.stepErr
}
func (workflow *httpWorkflow) StartTOTPEnrollment(context.Context, iamv1.Secret, iamv1.StartTOTPEnrollmentRequest) (iamv1.StartTOTPEnrollmentResponse, error) {
	workflow.totpCalls++
	return iamv1.StartTOTPEnrollmentResponse{}, identityaccess.ErrUnavailable
}
func (workflow *httpWorkflow) StartTOTPReplacement(_ context.Context, credential iamv1.Secret, body iamv1.StartTOTPReplacementRequest) (iamv1.StartTOTPEnrollmentResponse, error) {
	workflow.totpCalls++
	workflow.stepCredential, workflow.enrollmentRequestID = credential, body.RequestID
	return workflow.enrollmentStart, workflow.enrollmentErr
}
func (workflow *httpWorkflow) TOTPEnrollment(context.Context, iamv1.Secret, string) (iamv1.TOTPEnrollment, error) {
	workflow.totpCalls++
	return iamv1.TOTPEnrollment{}, identityaccess.ErrUnavailable
}
func (workflow *httpWorkflow) TOTPEnrollmentByRequest(context.Context, iamv1.Secret, string) (iamv1.TOTPEnrollment, error) {
	workflow.totpCalls++
	return iamv1.TOTPEnrollment{}, identityaccess.ErrUnavailable
}
func (workflow *httpWorkflow) CancelTOTPEnrollment(context.Context, iamv1.Secret, string) (iamv1.TOTPEnrollment, error) {
	workflow.totpCalls++
	return iamv1.TOTPEnrollment{}, identityaccess.ErrUnavailable
}
func (workflow *httpWorkflow) ConfirmTOTPEnrollment(context.Context, iamv1.Secret, string, iamv1.ConfirmTOTPEnrollmentRequest) (iamv1.ConfirmTOTPEnrollmentResponse, error) {
	workflow.totpCalls++
	return iamv1.ConfirmTOTPEnrollmentResponse{}, identityaccess.ErrUnavailable
}

func (workflow *httpWorkflow) Logout(
	context.Context,
	iamv1.Secret,
	iamv1.LogoutRequest,
) (iamv1.LogoutResponse, error) {
	return iamv1.LogoutResponse{RevokedAt: workflow.login.Session.IssuedAt}, nil
}

func (workflow *httpWorkflow) ChangePassword(
	context.Context,
	iamv1.Secret,
	iamv1.ChangePasswordRequest,
) (iamv1.ChangePasswordResponse, error) {
	return iamv1.ChangePasswordResponse{
		ChangedAt: workflow.login.Session.IssuedAt, BootstrapFileRetirable: true,
	}, nil
}

func (workflow *httpWorkflow) CreateUser(
	context.Context,
	iamv1.Secret,
	iamv1.CreateUserRequest,
) (iamv1.User, error) {
	now := workflow.login.Session.IssuedAt
	return iamv1.User{
		APIVersion: iamv1.APIVersion, Kind: "User", ID: "principal-user",
		AccountID: "organization-example",
		LoginName: "developer", DisplayName: "Developer", Status: iamv1.PrincipalActive,
		MustChangePassword: true, ResourceVersion: 1, CreatedAt: now, UpdatedAt: now,
	}, nil
}

func (workflow *httpWorkflow) GetUser(
	_ context.Context,
	_ iamv1.Secret,
	id iamv1.PrincipalID,
	_ string,
) (iamv1.UserAccess, error) {
	workflow.getUserCalls++
	workflow.userID = id
	now := workflow.login.Session.IssuedAt
	return iamv1.UserAccess{
		User: iamv1.User{
			APIVersion: iamv1.APIVersion, Kind: "User", ID: id,
			AccountID: "organization-example", LoginName: "developer", DisplayName: "Developer",
			Status: iamv1.PrincipalActive, ResourceVersion: 7, CreatedAt: now, UpdatedAt: now,
		},
		PolicyAttachments: []iamv1.PolicyAttachment{},
		Capabilities: []iamv1.ActionCapability{
			{Action: iamv1.ActionIAMUserRead, Resource: iamv1.ResourceReference{Kind: iamv1.ResourceUser, ID: string(id)}, Available: true},
			{Action: iamv1.ActionIAMUserUpdate, Resource: iamv1.ResourceReference{Kind: iamv1.ResourceUser, ID: string(id)}, Available: true},
			{Action: iamv1.ActionIAMUserPermissionBoundarySet, Resource: iamv1.ResourceReference{Kind: iamv1.ResourceUser, ID: string(id)}, Available: true},
			{Action: iamv1.ActionIAMUserPermissionBoundaryRemove, Resource: iamv1.ResourceReference{Kind: iamv1.ResourceUser, ID: string(id)}, Available: true},
			{Action: iamv1.ActionIAMUserDelete, Resource: iamv1.ResourceReference{Kind: iamv1.ResourceUser, ID: string(id)}, Available: false, RestrictionReason: iamv1.CapabilityTargetMustBeDisabled},
			{Action: iamv1.ActionIAMUserSetStatus, Resource: iamv1.ResourceReference{Kind: iamv1.ResourceUser, ID: string(id)}, Available: true},
			{Action: iamv1.ActionIAMUserPasswordReset, Resource: iamv1.ResourceReference{Kind: iamv1.ResourceUser, ID: string(id)}, Available: true},
			{Action: iamv1.ActionIAMPolicyAttachmentCreate, Resource: iamv1.ResourceReference{Kind: iamv1.ResourceUser, ID: string(id)}, Available: true},
			{Action: iamv1.ActionIAMPlatformPolicyAttachmentCreate, Resource: iamv1.ResourceReference{Kind: iamv1.ResourceUser, ID: string(id)}, Available: true},
		},
	}, nil
}

func (workflow *httpWorkflow) UpdateUser(
	_ context.Context,
	_ iamv1.Secret,
	id iamv1.PrincipalID,
	request iamv1.UpdateUserRequest,
) (iamv1.User, error) {
	workflow.updateUserCalls++
	workflow.userID, workflow.updateUser = id, request
	now := workflow.login.Session.IssuedAt
	return iamv1.User{
		APIVersion: iamv1.APIVersion, Kind: "User", ID: id, AccountID: "organization-example",
		LoginName: "developer", DisplayName: request.DisplayName, Status: iamv1.PrincipalActive,
		ResourceVersion: request.ResourceVersion + 1, CreatedAt: now, UpdatedAt: now,
	}, nil
}

func (workflow *httpWorkflow) DeleteUser(
	_ context.Context,
	_ iamv1.Secret,
	id iamv1.PrincipalID,
	request iamv1.DeleteUserRequest,
) (iamv1.UserDeletion, error) {
	workflow.deleteUserCalls++
	workflow.userID, workflow.deleteUser = id, request
	return iamv1.UserDeletion{
		APIVersion: iamv1.APIVersion, Kind: "UserDeletion", AccountID: "organization-example",
		ID: id, LoginName: "developer", ResourceVersion: request.ResourceVersion + 1,
		DeletedAt: workflow.login.Session.IssuedAt,
	}, nil
}

func (workflow *httpWorkflow) CreatePolicyAttachment(
	context.Context,
	iamv1.Secret,
	iamv1.CreatePolicyAttachmentRequest,
) (iamv1.PolicyAttachment, error) {
	now := workflow.login.Session.IssuedAt
	return iamv1.PolicyAttachment{
		APIVersion: iamv1.APIVersion, Kind: "PolicyAttachment", ID: "binding-user",
		AccountID: "organization-example", Target: iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetUser, ID: "principal-user"},
		PolicyID: iamv1.SystemPolicyPaaSDeveloper, Scope: iamv1.AuthorityScopeTenant, ResourceVersion: 1, CreatedAt: now, UpdatedAt: now,
	}, nil
}

func (workflow *httpWorkflow) PolicyAttachmentChangeByRequest(
	_ context.Context,
	_ iamv1.Secret,
	requestID string,
	_ string,
) (iamv1.PolicyAttachmentChange, bool, error) {
	now := workflow.login.Session.IssuedAt
	target := iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetUser, ID: "principal-user"}
	attachment := iamv1.PolicyAttachment{
		APIVersion: iamv1.APIVersion, Kind: "PolicyAttachment", ID: "binding-user",
		AccountID: "organization-example", Target: target, PolicyID: iamv1.SystemPolicyPaaSDeveloper,
		Scope: iamv1.AuthorityScopeTenant, ResourceVersion: 1, CreatedAt: now, UpdatedAt: now,
	}
	return iamv1.PolicyAttachmentChange{
		APIVersion: iamv1.APIVersion, Kind: "PolicyAttachmentChange", Operation: iamv1.PolicyAttachmentChangeCreate,
		AccountID: "organization-example", ActorPrincipalID: "principal-user", RequestID: requestID, CompletedAt: now,
		Target: &target, PolicyID: attachment.PolicyID, PolicyResourceVersion: 1, Attachment: &attachment,
	}, true, nil
}

func (workflow *httpWorkflow) RevokePolicyAttachment(
	_ context.Context,
	_ iamv1.Secret,
	id iamv1.PolicyAttachmentID,
	_ iamv1.RevokePolicyAttachmentRequest,
) (iamv1.Revocation, error) {
	return iamv1.Revocation{
		APIVersion: iamv1.APIVersion, Kind: "Revocation", ID: string(id),
		ResourceVersion: 2, RevokedAt: workflow.login.Session.IssuedAt,
	}, nil
}

func (workflow *httpWorkflow) PasswordRequirements(_ context.Context, credential iamv1.Secret) (iamv1.PasswordRequirements, error) {
	workflow.passwordRequirementsCalls++
	workflow.passwordRequirementsBearer = credential
	return workflow.passwordRequirements, workflow.passwordRequirementsError
}

func (workflow *httpWorkflow) ChallengePasswordRequirements(_ context.Context, id string, request iamv1.ChallengePasswordRequirementsRequest) (iamv1.PasswordRequirements, error) {
	workflow.passwordRequirementsCalls++
	workflow.verifiedChallengeID, workflow.enrollmentCredential = id, request.ChallengeCredential
	return workflow.passwordRequirements, workflow.passwordRequirementsError
}

func (workflow *httpWorkflow) ListOwnSessions(_ context.Context, _ iamv1.Secret, _ string) (iamv1.SessionList, error) {
	workflow.ownSessionCalls++
	session := workflow.login.Session
	return iamv1.SessionList{APIVersion: iamv1.APIVersion, Kind: "SessionList", AccountID: session.AccountID,
		UserID: session.PrincipalID, CurrentSessionID: session.ID, ObservedAt: session.IssuedAt, Items: []iamv1.Session{session}}, nil
}

func (workflow *httpWorkflow) TouchCurrentSession(_ context.Context, _ iamv1.Secret) (iamv1.SessionActivity, error) {
	workflow.ownSessionCalls++
	session := workflow.login.Session
	return iamv1.SessionActivity{APIVersion: iamv1.APIVersion, Kind: "SessionActivity", SessionID: session.ID,
		AccountID: session.AccountID, UserID: session.PrincipalID, LastActivityAt: session.IssuedAt,
		IdleExpiresAt: session.IssuedAt.Add(30 * time.Minute), AbsoluteExpiresAt: session.ExpiresAt}, nil
}

func (workflow *httpWorkflow) RevokeOwnSession(ctx context.Context, credential iamv1.Secret, id iamv1.SessionID, request iamv1.RevokeSessionRequest) (iamv1.RevokeOwnSessionResponse, error) {
	workflow.ownSessionCalls++
	revocation, err := workflow.RevokeSession(ctx, credential, id, request)
	return iamv1.RevokeOwnSessionResponse{Outcome: "APPLIED", Revocation: revocation}, err
}

func (workflow *httpWorkflow) RevokeOtherSessions(_ context.Context, _ iamv1.Secret, request iamv1.RevokeSessionRequest) (iamv1.RevokeOtherSessionsResponse, error) {
	workflow.ownSessionCalls++
	session := workflow.login.Session
	return iamv1.RevokeOtherSessionsResponse{APIVersion: iamv1.APIVersion, Kind: "OtherSessionsRevocation", Outcome: "APPLIED",
		AccountID: session.AccountID, UserID: session.PrincipalID, CurrentSessionID: session.ID, RequestID: request.RequestID,
		CompletedAt: session.IssuedAt}, nil
}

func (workflow *httpWorkflow) RevokeSession(
	_ context.Context,
	_ iamv1.Secret,
	id iamv1.SessionID,
	_ iamv1.RevokeSessionRequest,
) (iamv1.Revocation, error) {
	return iamv1.Revocation{
		APIVersion: iamv1.APIVersion, Kind: "Revocation", ID: string(id),
		ResourceVersion: 2, RevokedAt: workflow.login.Session.IssuedAt,
	}, nil
}

func (workflow *httpWorkflow) Authorize(
	context.Context,
	iamv1.Secret,
	iamv1.Secret,
	iamv1.AuthorizationRequest,
) (iamv1.AuthorizationDecision, error) {
	workflow.authorizeCalls++
	return workflow.decision, nil
}

func (workflow *httpWorkflow) DiagnoseAuthorization(
	_ context.Context,
	_ iamv1.Secret,
	_ iamv1.Secret,
	_ iamv1.AuthorizationRequest,
) (iamv1.CurrentAccessDiagnosis, error) {
	workflow.diagnoseCalls++
	return workflow.diagnosis, nil
}

func (workflow *httpWorkflow) AuthorizeBatch(
	_ context.Context,
	_ iamv1.Secret,
	_ iamv1.Secret,
	request iamv1.AuthorizationBatchRequest,
) (iamv1.AuthorizationBatchDecision, error) {
	workflow.authorizeBatchCalls++
	workflow.authorizationBatchRequest = request
	return workflow.batchDecision, nil
}

func (workflow *httpWorkflow) VerifyInstallation(
	context.Context,
	iamv1.Secret,
	iamv1.AuthorizationRequest,
) (iamv1.AuthorizationDecision, error) {
	workflow.verifyInstallationCalls++
	return workflow.verificationDecision, nil
}

func (workflow *httpWorkflow) AuthorizeAccessKey(_ context.Context, _ iamv1.Secret, request iamv1.AccessKeyAuthorizationRequest) (iamv1.AccessKeyAuthorization, error) {
	workflow.keyCalls++
	digest, err := iamv1.AccessKeySignedRequestDigest(request.SignedRequest)
	decision := workflow.decision
	decision.Allowed, decision.Reason, decision.Subject, decision.TenantID, decision.InstallationID = false, iamv1.DecisionDenied, nil, "", ""
	decision.Action, decision.Resource, decision.RequestID, decision.CorrelationID = request.Authorization.Action, request.Authorization.Resource, request.Authorization.RequestID, request.Authorization.CorrelationID
	decision.Profile, decision.ResourceMode, decision.CollectionUsage = &request.Authorization.Profile, request.Authorization.ResourceMode, request.Authorization.CollectionUsage
	return iamv1.AccessKeyAuthorization{APIVersion: iamv1.APIVersion, Kind: "AccessKeyAuthorization", Decision: decision, SignedRequestDigest: digest}, err
}

func (workflow *httpWorkflow) AuthorizeAccessKeyList(_ context.Context, _ iamv1.Secret, request iamv1.AccessKeyListAuthorizationRequest) (iamv1.AccessKeyListAuthorization, error) {
	workflow.keyListCalls++
	workflow.keyListRequest = request
	digest, err := iamv1.AccessKeySignedRequestDigest(request.SignedRequest)
	decision := workflow.decision
	decision.Allowed, decision.Reason, decision.Subject, decision.TenantID, decision.InstallationID = false, iamv1.DecisionDenied, nil, "", ""
	decision.Action, decision.Resource, decision.RequestID, decision.CorrelationID = request.Collection.Action, request.Collection.Resource, request.Collection.RequestID, request.Collection.CorrelationID
	decision.Profile, decision.ResourceMode, decision.CollectionUsage = &request.Collection.Profile, request.Collection.ResourceMode, request.Collection.CollectionUsage
	return iamv1.AccessKeyListAuthorization{APIVersion: iamv1.APIVersion, Kind: "AccessKeyListAuthorization",
		Collection: decision, Instances: []iamv1.AuthorizationDecision{}, SignedRequestDigest: digest}, err
}

func (workflow *httpWorkflow) ResolveAccessKeySubject(_ context.Context, _ iamv1.Secret, request iamv1.ResolveAccessKeySubjectRequest) (iamv1.AccessKeySubjectContext, error) {
	workflow.keyResolveCalls++
	workflow.keyResolveRequest = request
	digest, err := iamv1.AccessKeySignedRequestDigest(request.SignedRequest)
	if err != nil {
		return iamv1.AccessKeySubjectContext{}, err
	}
	return iamv1.AccessKeySubjectContext{
		APIVersion: iamv1.APIVersion, Kind: "AccessKeySubjectContext", TenantID: "account-one",
		Subject: iamv1.Subject{Type: iamv1.SubjectUser, ID: "user-one", AccessKeyID: request.SignedRequest.Parameters.AccessKeyID},
		Profile: request.Profile, SignedRequestDigest: digest,
	}, nil
}

func newTestHandler(t *testing.T, workflow Workflow) http.Handler {
	t.Helper()
	handler, err := NewHandler(workflow, Config{
		NewRequestID: func() (string, error) { return "request-http-test", nil },
	})
	if err != nil {
		t.Fatalf("create IAM HTTP handler: %v", err)
	}
	return handler
}
