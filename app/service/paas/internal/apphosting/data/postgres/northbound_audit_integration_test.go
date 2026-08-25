package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/port"
	apphttp "github.com/xiak/matrix/app/service/paas/internal/apphosting/service/nethttp"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/applicationlifecycle"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/auditdispatch"
)

func assertAuditPersistenceAndFencing(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	apiPool *pgxpool.Pool,
	workerPool *pgxpool.Pool,
	result applicationlifecycle.Result,
) {
	t.Helper()
	var status string
	var document []byte
	if err := admin.QueryRow(
		ctx,
		`SELECT status, document
		   FROM paas.audit_outbox
		  WHERE tenant_id = $1 AND operation_id = $2`,
		result.Operation.Scope.TenantID,
		result.Operation.ID,
	).Scan(&status, &document); err != nil {
		t.Fatalf("read transactional Audit outbox event: %v", err)
	}
	if status != "PENDING" {
		t.Fatalf("new Audit outbox status = %q, want PENDING", status)
	}
	event, err := decodeAuditEvent(document)
	if err != nil {
		t.Fatalf("decode transactional Audit event: %v", err)
	}
	if event.OperationID != result.Operation.ID ||
		event.TenantID != result.Operation.Scope.TenantID ||
		event.Actor != result.Operation.RequestedBy ||
		event.Action != port.AuditDeploymentCreated ||
		event.Result != port.AuditAccepted {
		t.Fatalf("transactional Audit event = %#v", event)
	}
	for _, forbidden := range []string{"Bearer", "credential", "requestBody", "attributes"} {
		if strings.Contains(strings.ToLower(string(document)), strings.ToLower(forbidden)) {
			t.Fatalf("Audit event contains forbidden material %q: %s", forbidden, document)
		}
	}

	assertIAMAuditRoleIsolation(t, ctx, apiPool, workerPool)
	repository, err := NewAuditOutboxRepository(workerPool)
	if err != nil {
		t.Fatalf("create Audit outbox repository: %v", err)
	}
	stale, found, err := repository.Claim(ctx, "audit-worker-stale", time.Second)
	if err != nil || !found {
		t.Fatalf("claim Audit event for lease expiry: found=%v err=%v", found, err)
	}
	if stale.EventID != event.EventID || stale.FencingToken != 1 || stale.Attempts != 1 {
		t.Fatalf("first Audit claim = %#v", stale)
	}
	if _, err := admin.Exec(
		ctx,
		`UPDATE paas.audit_outbox
		    SET lease_expires_at = transaction_timestamp() - interval '1 microsecond',
		        updated_at = transaction_timestamp()
		  WHERE tenant_id = $1 AND event_id = $2`,
		stale.TenantID,
		stale.EventID,
	); err != nil {
		t.Fatalf("expire Audit lease: %v", err)
	}
	current, found, err := repository.Claim(ctx, "audit-worker-current", 30*time.Second)
	if err != nil || !found {
		t.Fatalf("reclaim expired Audit event: found=%v err=%v", found, err)
	}
	if current.EventID != stale.EventID || current.FencingToken != stale.FencingToken+1 ||
		current.Attempts != stale.Attempts+1 {
		t.Fatalf("reclaimed Audit event = %#v, first = %#v", current, stale)
	}
	err = repository.Complete(ctx, auditdispatch.Completion{
		TenantID: stale.TenantID, EventID: stale.EventID,
		WorkerID: "audit-worker-stale", FencingToken: stale.FencingToken,
		Outcome: auditdispatch.OutcomeDelivered,
	})
	if !errors.Is(err, auditdispatch.ErrStaleLease) {
		t.Fatalf("stale Audit completion error = %v", err)
	}
	if err := repository.Complete(ctx, auditdispatch.Completion{
		TenantID: current.TenantID, EventID: current.EventID,
		WorkerID: "audit-worker-current", FencingToken: current.FencingToken,
		Outcome: auditdispatch.OutcomeDelivered,
	}); err != nil {
		t.Fatalf("complete current Audit lease: %v", err)
	}
}

func assertIAMAuditRoleIsolation(
	t *testing.T,
	ctx context.Context,
	apiPool *pgxpool.Pool,
	workerPool *pgxpool.Pool,
) {
	t.Helper()
	_, err := apiPool.Exec(ctx, "INSERT INTO paas.applications DEFAULT VALUES")
	assertPostgresCode(t, err, "42501")
	_, err = apiPool.Exec(ctx, "SELECT * FROM paas.claim_audit_event('forbidden-api', 30)")
	assertPostgresCode(t, err, "42501")
	_, err = workerPool.Exec(ctx, "SELECT count(*) FROM paas.audit_outbox")
	assertPostgresCode(t, err, "42501")
	_, err = workerPool.Exec(
		ctx,
		"SELECT paas.create_apphosting_resource('{}'::jsonb, '{}'::jsonb, '{}'::jsonb)",
	)
	assertPostgresCode(t, err, "42501")
}

func assertNorthboundIAMAudit(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	apiPool *pgxpool.Pool,
	workerPool *pgxpool.Pool,
	fixture integrationFixture,
	prefix string,
) {
	t.Helper()
	handler := newIntegrationHTTPHandler(t, apiPool, fixture.tenantA)
	applicationID := paasv1.ResourceID(prefix + "-http-application")
	configurationID := paasv1.ResourceID(prefix + "-http-configuration")
	configurationRevisionID := paasv1.ResourceID(prefix + "-http-configuration-revision")
	applicationRevisionID := paasv1.ResourceID(prefix + "-http-application-revision")
	deploymentID := paasv1.ResourceID(prefix + "-http-deployment")

	applicationRequest := paasv1.CreateApplicationRequest{
		ID: applicationID, Name: "http-application", Labels: map[string]string{"source": "northbound"},
	}
	createdApplication := doIntegrationHTTP[paasv1.Operation](
		t, ctx, handler, http.MethodPost, "/v1/applications", applicationRequest,
		map[string]string{"Idempotency-Key": "http-create-application", "X-Tenant-ID": string(fixture.tenantB)},
		http.StatusCreated,
	)
	if createdApplication.Action != paasv1.OperationCreateApplication ||
		createdApplication.State != paasv1.OperationSucceeded ||
		createdApplication.Scope.TenantID != fixture.tenantA {
		t.Fatalf("northbound Application Operation = %#v", createdApplication)
	}
	replayedApplication := doIntegrationHTTP[paasv1.Operation](
		t, ctx, handler, http.MethodPost, "/v1/applications", applicationRequest,
		map[string]string{"Idempotency-Key": "http-create-application"},
		http.StatusOK,
	)
	if replayedApplication.ID != createdApplication.ID {
		t.Fatalf("northbound Application replay Operation = %q, want %q", replayedApplication.ID, createdApplication.ID)
	}
	application := doIntegrationHTTP[paasv1.Application](
		t, ctx, handler, http.MethodGet, "/v1/applications/"+string(applicationID), nil,
		map[string]string{"X-Tenant-ID": string(fixture.tenantB)}, http.StatusOK,
	)
	if application.Metadata.Scope.TenantID != fixture.tenantA {
		t.Fatalf("northbound Application tenant = %q, want trusted IAM tenant %q", application.Metadata.Scope.TenantID, fixture.tenantA)
	}
	tenantBHandler := newIntegrationHTTPHandler(t, apiPool, fixture.tenantB)
	doIntegrationHTTP[paasv1.Problem](
		t, ctx, tenantBHandler, http.MethodGet, "/v1/applications/"+string(applicationID), nil, nil,
		http.StatusNotFound,
	)

	doIntegrationHTTP[paasv1.Operation](
		t, ctx, handler, http.MethodPost, "/v1/configurations",
		paasv1.CreateConfigurationRequest{
			ID: configurationID, Name: "http-configuration", ApplicationID: applicationID,
		},
		map[string]string{"Idempotency-Key": "http-create-configuration"}, http.StatusCreated,
	)
	configurationValue := "northbound-ordinary-config-value"
	configurationValues := map[string]string{"MESSAGE": configurationValue}
	doIntegrationHTTP[paasv1.Operation](
		t, ctx, handler, http.MethodPost, "/v1/configuration-revisions",
		paasv1.CreateConfigurationRevisionRequest{
			ID: configurationRevisionID, Name: "http-configuration-revision",
			Spec: paasv1.ConfigurationRevisionSpec{
				ConfigurationID: configurationID,
				Values:          configurationValues,
				ContentDigest:   paasv1.ConfigurationValuesDigest(configurationValues),
			},
		},
		map[string]string{"Idempotency-Key": "http-create-configuration-revision"}, http.StatusCreated,
	)
	revisionComponents := applicationRevisionComponents(prefix)
	doIntegrationHTTP[paasv1.Operation](
		t, ctx, handler, http.MethodPost, "/v1/application-revisions",
		paasv1.CreateApplicationRevisionRequest{
			ID: applicationRevisionID, Name: "http-application-revision",
			Spec: paasv1.ApplicationRevisionSpec{
				ApplicationID: applicationID, Revision: "v1",
				ContentDigest: integrationDigest(prefix + "-http-application-revision"),
				Components:    revisionComponents,
			},
		},
		map[string]string{"Idempotency-Key": "http-create-application-revision"}, http.StatusCreated,
	)
	deploymentSpec := paasv1.DeploymentSpec{
		ApplicationRevisionID: applicationRevisionID,
		PlacementPolicyID:     fixture.policyID,
		DesiredState:          paasv1.DeploymentDesiredRunning,
		Components: []paasv1.DeploymentComponent{{
			Name: "web", Replicas: 1,
			Bindings: []paasv1.ComponentBinding{{
				Name: "settings", ConfigurationRevisionID: configurationRevisionID,
			}},
		}},
	}
	createdDeployment := doIntegrationHTTP[paasv1.Operation](
		t, ctx, handler, http.MethodPost, "/v1/deployments",
		paasv1.CreateDeploymentRequest{ID: deploymentID, Name: "http-deployment", Spec: deploymentSpec},
		map[string]string{"Idempotency-Key": "http-create-deployment"}, http.StatusAccepted,
	)
	if createdDeployment.Action != paasv1.OperationDeploy ||
		createdDeployment.State != paasv1.OperationAccepted ||
		createdDeployment.RequestedBy.ID != "integration-http-user" {
		t.Fatalf("northbound Deployment Operation = %#v", createdDeployment)
	}
	deployment := doIntegrationHTTP[paasv1.Deployment](
		t, ctx, handler, http.MethodGet, "/v1/deployments/"+string(deploymentID), nil, nil,
		http.StatusOK,
	)
	if deployment.Generation != 1 || deployment.Metadata.Scope.TenantID != fixture.tenantA {
		t.Fatalf("northbound Deployment = %#v", deployment)
	}

	targets := []paasv1.ResourceID{
		applicationID, configurationID, configurationRevisionID, applicationRevisionID, deploymentID,
	}
	var auditCount int
	var auditDocuments []byte
	if err := admin.QueryRow(
		ctx,
		`SELECT count(*), jsonb_agg(document ORDER BY event_id)
		   FROM paas.audit_outbox
		  WHERE tenant_id = $1
		    AND document#>>'{target,id}' = ANY($2::text[])`,
		fixture.tenantA,
		resourceIDsAsStrings(targets),
	).Scan(&auditCount, &auditDocuments); err != nil {
		t.Fatalf("inspect northbound Audit events: %v", err)
	}
	if auditCount != len(targets) {
		t.Fatalf("northbound Audit event count = %d, want %d", auditCount, len(targets))
	}
	if strings.Contains(string(auditDocuments), configurationValue) ||
		strings.Contains(string(auditDocuments), "integration-token") {
		t.Fatalf("northbound Audit documents leaked request material: %s", auditDocuments)
	}

	dispatchAllAuditEvents(t, ctx, admin, workerPool, targets, configurationValue)
}

func applicationRevisionComponents(prefix string) []paasv1.ApplicationRevisionComponent {
	return []paasv1.ApplicationRevisionComponent{{
		Name: "web",
		Artifact: paasv1.ArtifactRef{
			Kind: paasv1.ArtifactOCIImage, Locator: "registry.invalid/matrix/http-web",
			Digest: integrationDigest(prefix + "-http-artifact"),
		},
		Resources: paasv1.ResourceRequirements{CPUMillis: 100, MemoryBytes: 1024 * 1024},
		Inputs: []paasv1.ComponentInput{{
			Name: "settings", Kind: paasv1.InputConfiguration,
			Injection: paasv1.InjectionEnvironment, Required: true,
		}},
	}}
}

func dispatchAllAuditEvents(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	workerPool *pgxpool.Pool,
	wantTargets []paasv1.ResourceID,
	forbiddenValue string,
) {
	t.Helper()
	repository, err := NewAuditOutboxRepository(workerPool)
	if err != nil {
		t.Fatalf("create Audit dispatcher repository: %v", err)
	}
	ingestor := &integrationAuditIngestor{failuresRemaining: 1}
	dispatcher, err := auditdispatch.NewUsecase(repository, ingestor, auditdispatch.Config{
		WorkerID: "audit-worker-dispatch", LeaseDuration: 30 * time.Second,
		DeliveryTimeout: 5 * time.Second, InitialBackoff: time.Second,
		MaxBackoff: time.Minute, MaxAttempts: 3,
		Now: func() time.Time { return time.Now().UTC().Truncate(time.Microsecond) },
	})
	if err != nil {
		t.Fatalf("create Audit dispatcher: %v", err)
	}
	first, err := dispatcher.DispatchOnce(ctx)
	if err != nil || !first.Claimed || !first.Retried || len(ingestor.events) != 1 {
		t.Fatalf("first Audit dispatch retry = %#v events=%d err=%v", first, len(ingestor.events), err)
	}
	retriedEventID := ingestor.events[0].EventID
	var status string
	var errorCode *string
	var storedDocument []byte
	if err := admin.QueryRow(
		ctx,
		`SELECT status, last_error_code, document
		   FROM paas.audit_outbox
		  WHERE tenant_id = $1 AND event_id = $2`,
		ingestor.events[0].TenantID,
		retriedEventID,
	).Scan(&status, &errorCode, &storedDocument); err != nil {
		t.Fatalf("inspect retried Audit event: %v", err)
	}
	if status != "RETRY" || errorCode != nil || strings.Contains(string(storedDocument), "native-audit-credential") {
		t.Fatalf("retried Audit state = status=%q error=%v document=%s", status, errorCode, storedDocument)
	}
	if _, err := admin.Exec(
		ctx,
		`UPDATE paas.audit_outbox
		    SET available_at = transaction_timestamp(), updated_at = transaction_timestamp()
		  WHERE tenant_id = $1 AND event_id = $2`,
		ingestor.events[0].TenantID,
		retriedEventID,
	); err != nil {
		t.Fatalf("make Audit retry immediately available: %v", err)
	}

	for attempts := 0; attempts < 100; attempts++ {
		result, err := dispatcher.DispatchOnce(ctx)
		if err != nil {
			t.Fatalf("dispatch Audit event %d: %v", attempts+2, err)
		}
		if !result.Claimed {
			break
		}
		if attempts == 99 {
			t.Fatal("Audit dispatch did not drain within 100 claims")
		}
	}
	retryDeliveries := 0
	for _, event := range ingestor.events {
		if event.EventID == retriedEventID {
			retryDeliveries++
		}
	}
	if retryDeliveries < 2 {
		t.Fatalf("Audit event %q delivery count = %d, want at least two", retriedEventID, retryDeliveries)
	}
	wanted := make(map[paasv1.ResourceID]bool, len(wantTargets))
	for _, id := range wantTargets {
		wanted[id] = false
	}
	encoded, err := json.Marshal(ingestor.events)
	if err != nil {
		t.Fatalf("encode ingested Audit events: %v", err)
	}
	if strings.Contains(string(encoded), forbiddenValue) || strings.Contains(string(encoded), "native-audit-credential") {
		t.Fatalf("ingested Audit events leaked request/native material: %s", encoded)
	}
	for _, event := range ingestor.events {
		if _, found := wanted[event.Target.ID]; found {
			wanted[event.Target.ID] = true
		}
	}
	for id, delivered := range wanted {
		if !delivered {
			t.Errorf("northbound Audit target %q was not ingested", id)
		}
	}
	snapshot, err := dispatcher.Snapshot(ctx)
	if err != nil {
		t.Fatalf("read drained Audit snapshot: %v", err)
	}
	if snapshot.Pending != 0 || snapshot.Leased != 0 || snapshot.Retry != 0 ||
		snapshot.DeadLetter != 0 || snapshot.ExpiredLease != 0 {
		t.Fatalf("drained Audit snapshot = %#v", snapshot)
	}
}

type integrationHTTPAuthorizer struct {
	tenantID paasv1.TenantID
}

func (authorizer integrationHTTPAuthorizer) Authorize(
	_ context.Context,
	request port.AuthorizationRequest,
) (port.Authorization, error) {
	if request.Credential != "Bearer integration-token" {
		return port.Authorization{}, port.ErrUnauthenticated
	}
	return port.Authorization{
		TenantID:   authorizer.tenantID,
		Subject:    paasv1.SubjectRef{Type: paasv1.SubjectUser, ID: "integration-http-user"},
		DecisionID: "decision-" + request.RequestID,
		RequestID:  request.RequestID,
		AuditID:    "audit-" + request.RequestID,
	}, nil
}

func newIntegrationHTTPHandler(
	t *testing.T,
	apiPool *pgxpool.Pool,
	tenantID paasv1.TenantID,
) http.Handler {
	t.Helper()
	repository, err := NewApplicationRepository(apiPool)
	if err != nil {
		t.Fatalf("create northbound application repository: %v", err)
	}
	workflow, err := applicationlifecycle.NewUsecase(
		repository,
		applicationlifecycle.Config{MaxTransactionAttempts: 5},
	)
	if err != nil {
		t.Fatalf("create northbound application workflow: %v", err)
	}
	sequence := 0
	handler, err := apphttp.NewHandler(
		integrationHTTPAuthorizer{tenantID: tenantID},
		workflow,
		apphttp.Config{
			NewRequestID: func() (string, error) {
				sequence++
				return fmt.Sprintf("http-request-%d", sequence), nil
			},
			Readiness: func(context.Context) (paasv1.Readiness, error) {
				return paasv1.Readiness{
					APIVersion: paasv1.APIVersion, Kind: "Readiness",
					State: paasv1.ReadinessReady, SchemaVersion: 1,
					CheckedAt: time.Date(2026, 8, 26, 3, 4, 5, 0, time.UTC),
				}, nil
			},
		},
	)
	if err != nil {
		t.Fatalf("create northbound HTTP handler: %v", err)
	}
	return handler
}

func doIntegrationHTTP[T any](
	t *testing.T,
	ctx context.Context,
	handler http.Handler,
	method string,
	path string,
	body any,
	headers map[string]string,
	wantStatus int,
) T {
	t.Helper()
	var source io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("encode %s %s body: %v", method, path, err)
		}
		source = bytes.NewReader(encoded)
	}
	request := httptest.NewRequest(method, path, source).WithContext(ctx)
	request.Header.Set("Authorization", "Bearer integration-token")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != wantStatus {
		t.Fatalf("%s %s status = %d, want %d: %s", method, path, response.Code, wantStatus, response.Body.String())
	}
	var decoded T
	decoder := json.NewDecoder(response.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		t.Fatalf("decode %s %s response: %v", method, path, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		t.Fatalf("%s %s response has trailing JSON: %v", method, path, err)
	}
	return decoded
}

func resourceIDsAsStrings(values []paasv1.ResourceID) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, string(value))
	}
	return result
}

type integrationAuditIngestor struct {
	events            []port.AuditEvent
	failuresRemaining int
}

func (ingestor *integrationAuditIngestor) Ingest(
	_ context.Context,
	event port.AuditEvent,
) error {
	ingestor.events = append(ingestor.events, event)
	if ingestor.failuresRemaining > 0 {
		ingestor.failuresRemaining--
		return errors.New("native-audit-credential=must-not-persist")
	}
	return nil
}
