package integration

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	auditpostgres "github.com/xiak/matrix/app/service/audit/internal/data/postgres"
	audithttp "github.com/xiak/matrix/app/service/audit/internal/service/nethttp"
	"github.com/xiak/matrix/app/service/audit/internal/usecase/auditlog"
	auditmigration "github.com/xiak/matrix/app/service/audit/migration"
)

const (
	auditHTTPPostgresDSN   = "MATRIX_AUDIT_HTTP_POSTGRES_TEST_DSN"
	auditHTTPTestRole      = "matrix_audit_http_test_runtime"
	auditHTTPTestPassword  = "matrix-audit-http-test-only"
	producerCredentialA    = "mx1.AuditHTTPProducerCredentialA000000000000001"
	producerCredentialB    = "mx1.AuditHTTPProducerCredentialB000000000000001"
	paasProducerCredential = "mx1.AuditHTTPPaaSProducerCredential0000000000001"
	readerCredentialA      = "mx1.AuditHTTPReaderCredentialA0000000000000001"
	readerCredentialB      = "mx1.AuditHTTPReaderCredentialB0000000000000001"
	deniedCredential       = "mx1.AuditHTTPDeniedCredential00000000000000001"
	verifierCredential     = "mx1.AuditHTTPVerifierCredential0000000000000001"
)

func TestAuditHTTPPostgresVerticalSlice(t *testing.T) {
	dsn := os.Getenv(auditHTTPPostgresDSN)
	if dsn == "" {
		t.Skipf("set %s to a clean disposable PostgreSQL 18 database", auditHTTPPostgresDSN)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	adminConfig, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse Audit HTTP PostgreSQL DSN: %v", err)
	}
	if !strings.HasPrefix(adminConfig.Database, "matrix_audit_") {
		t.Fatalf("refusing Audit HTTP database %q without matrix_audit_ prefix", adminConfig.Database)
	}
	adminConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	admin, err := pgx.ConnectConfig(ctx, adminConfig)
	if err != nil {
		t.Fatalf("connect Audit HTTP PostgreSQL: %v", err)
	}
	defer func() { _ = admin.Close(context.Background()) }()
	assertAuditPostgres18(t, ctx, admin)
	assertCleanAuditSchema(t, ctx, admin)
	applyAuditSchema(t, ctx, admin)
	createAuditHTTPRole(t, ctx, admin)

	poolConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse Audit HTTP pool DSN: %v", err)
	}
	poolConfig.ConnConfig.User = auditHTTPTestRole
	poolConfig.ConnConfig.Password = auditHTTPTestPassword
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		t.Fatalf("open Audit HTTP runtime pool: %v", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("ping Audit HTTP runtime pool: %v", err)
	}
	repository, err := auditpostgres.NewRepository(pool)
	if err != nil {
		t.Fatalf("create Audit PostgreSQL repository: %v", err)
	}
	iam := &integrationIAM{now: time.Date(2026, 8, 26, 16, 17, 18, 123000, time.UTC)}
	identifier := 0
	workflow, err := auditlog.NewService(repository, iam, auditlog.Config{
		CursorKey: bytes.Repeat([]byte{0x6a}, 32),
		NewID: func(prefix string) (string, error) {
			identifier++
			return fmt.Sprintf("%s-http-%d", prefix, identifier), nil
		},
	})
	if err != nil {
		t.Fatalf("create Audit HTTP workflow: %v", err)
	}
	handler, err := audithttp.NewHandler(workflow, audithttp.Config{
		NewRequestID: func() (string, error) { return "request-http-integration", nil },
	})
	if err != nil {
		t.Fatalf("create Audit HTTP handler: %v", err)
	}

	ready := performAuditRequest(handler, http.MethodGet, "/ready", "", nil)
	if ready.Code != http.StatusOK {
		t.Fatalf("Audit readiness status=%d body=%s", ready.Code, ready.Body.String())
	}
	first := integrationEvent(
		"event-bootstrap-a",
		"organization-a",
		auditv1.ActionIAMBootstrapApplied,
		auditv1.TargetInstallation,
		"installation-a",
		iam.now.Add(-3*time.Minute),
	)
	accepted := ingestAuditEvent(t, handler, producerCredentialA, first, http.StatusCreated)
	if accepted.Outcome != auditv1.IngestionAccepted || accepted.Record.Sequence != 1 ||
		accepted.Record.Source != auditv1.SourceIAM {
		t.Fatalf("accepted Audit event=%#v", accepted)
	}
	duplicate := ingestAuditEvent(t, handler, producerCredentialA, first, http.StatusOK)
	if duplicate.Outcome != auditv1.IngestionDuplicate || duplicate.Record != accepted.Record {
		t.Fatalf("duplicate Audit event=%#v", duplicate)
	}
	changed := first
	changed.RequestID = "request-event-bootstrap-changed"
	ingestAuditEvent(t, handler, producerCredentialA, changed, http.StatusConflict)

	wrongTenant := first
	wrongTenant.EventID = "event-wrong-tenant"
	wrongTenant.TenantID = "organization-b"
	ingestAuditEvent(t, handler, producerCredentialA, wrongTenant, http.StatusUnprocessableEntity)
	wrongCredential := performAuditRequest(
		handler,
		http.MethodPost,
		"/v1/events",
		"wrong-producer-credential",
		mustJSON(t, first),
	)
	if wrongCredential.Code != http.StatusUnauthorized {
		t.Fatalf("wrong Audit producer status=%d body=%s", wrongCredential.Code, wrongCredential.Body.String())
	}

	second := integrationEvent(
		"event-session-a",
		"organization-a",
		auditv1.ActionIAMSessionIssued,
		auditv1.TargetSession,
		"session-a",
		iam.now.Add(-2*time.Minute),
	)
	accepted = ingestAuditEvent(t, handler, producerCredentialA, second, http.StatusCreated)
	if accepted.Record.Sequence != 2 {
		t.Fatalf("second tenant A sequence=%d want=2", accepted.Record.Sequence)
	}
	tenantB := integrationEvent(
		"event-bootstrap-b",
		"organization-b",
		auditv1.ActionIAMBootstrapApplied,
		auditv1.TargetInstallation,
		"installation-b",
		iam.now.Add(-time.Minute),
	)
	accepted = ingestAuditEvent(t, handler, producerCredentialB, tenantB, http.StatusCreated)
	if accepted.Record.Sequence != 1 || accepted.Record.Event.TenantID != "organization-b" {
		t.Fatalf("tenant B Audit record=%#v", accepted.Record)
	}

	firstPage := queryAuditRecords(
		t,
		handler,
		readerCredentialA,
		auditv1.QueryRecordsRequest{PageSize: 1},
		http.StatusOK,
	)
	if len(firstPage.Records) != 1 || firstPage.Records[0].Sequence != 2 ||
		firstPage.NextCursor == "" || firstPage.TenantID != "organization-a" {
		t.Fatalf("tenant A first Audit page=%#v", firstPage)
	}
	secondPage := queryAuditRecords(
		t,
		handler,
		readerCredentialA,
		auditv1.QueryRecordsRequest{PageSize: 1, Cursor: firstPage.NextCursor},
		http.StatusOK,
	)
	if len(secondPage.Records) != 1 || secondPage.Records[0].Sequence != 1 ||
		secondPage.NextCursor != "" || secondPage.TenantID != "organization-a" {
		t.Fatalf("tenant A second Audit page=%#v", secondPage)
	}
	actor := auditv1.ActorReference{Type: auditv1.ActorServiceAccount, ID: "service-iam"}
	from := first.OccurredAt.Add(-time.Second)
	to := first.OccurredAt.Add(time.Second)
	filtered := queryAuditRecords(
		t,
		handler,
		readerCredentialA,
		auditv1.QueryRecordsRequest{
			PageSize: 10,
			From:     &from,
			To:       &to,
			Action:   auditv1.ActionIAMBootstrapApplied,
			Actor:    &actor,
		},
		http.StatusOK,
	)
	if len(filtered.Records) != 1 || filtered.Records[0].Event.EventID != first.EventID {
		t.Fatalf("filtered tenant A Audit page=%#v", filtered)
	}

	tenantBPage := queryAuditRecords(
		t,
		handler,
		readerCredentialB,
		auditv1.QueryRecordsRequest{PageSize: 10},
		http.StatusOK,
	)
	if tenantBPage.TenantID != "organization-b" || len(tenantBPage.Records) != 1 ||
		tenantBPage.Records[0].Event.TenantID != "organization-b" {
		t.Fatalf("tenant B Audit page=%#v", tenantBPage)
	}
	queryAuditRecords(
		t,
		handler,
		readerCredentialB,
		auditv1.QueryRecordsRequest{PageSize: 1, Cursor: firstPage.NextCursor},
		http.StatusUnprocessableEntity,
	)

	verification := verifyAuditChain(
		t,
		handler,
		readerCredentialA,
		auditv1.VerifyChainRequest{FromSequence: 1, MaximumRecords: 5},
		http.StatusOK,
	)
	if verification.TenantID != "organization-a" || verification.RecordCount != 5 ||
		verification.ToSequence != 5 || !verification.Complete ||
		verification.State != auditv1.VerificationVerified {
		t.Fatalf("tenant A chain verification=%#v", verification)
	}
	queryAuditRecords(
		t,
		handler,
		deniedCredential,
		auditv1.QueryRecordsRequest{PageSize: 10},
		http.StatusForbidden,
	)
	installationRequest := auditv1.VerifyInstallationRequest{
		InstallationID: "mxi-0123456789abcdef0123456789abcdef",
		OperationID:    "operation-installation-probe",
		DeploymentID:   "deployment-installation-probe",
	}
	pendingInstallation := verifyInstallationAudit(
		t, handler, verifierCredential, installationRequest, http.StatusOK,
	)
	if pendingInstallation.State != auditv1.InstallationVerificationPending {
		t.Fatalf("pending installation Audit verification=%#v", pendingInstallation)
	}
	paasEvent := integrationEvent(
		"event-installation-probe",
		"organization-a",
		auditv1.ActionPaaSDeploymentCreated,
		auditv1.TargetDeployment,
		installationRequest.DeploymentID,
		iam.now,
	)
	paasEvent.Actor = auditv1.ActorReference{
		Type: auditv1.ActorServiceAccount, ID: "service-installation-verifier",
	}
	paasEvent.IAMDecisionID = "decision-paas-installation-probe"
	paasEvent.Result = auditv1.ResultAccepted
	paasEvent.OperationID = installationRequest.OperationID
	paasAccepted := ingestAuditEvent(t, handler, paasProducerCredential, paasEvent, http.StatusCreated)
	if paasAccepted.Record.Sequence == 0 || paasAccepted.Record.Source != auditv1.SourcePaaS {
		t.Fatalf("PaaS installation Audit record=%#v", paasAccepted.Record)
	}
	verifiedInstallation := verifyInstallationAudit(
		t, handler, verifierCredential, installationRequest, http.StatusOK,
	)
	if verifiedInstallation.State != auditv1.InstallationVerificationVerified ||
		verifiedInstallation.EventID != paasEvent.EventID ||
		verifiedInstallation.RecordSequence != paasAccepted.Record.Sequence ||
		verifiedInstallation.RecordHash != paasAccepted.Record.RecordHash {
		t.Fatalf("verified installation Audit result=%#v", verifiedInstallation)
	}

	assertAuditFacts(t, ctx, admin)
	assertAuditRuntimeBoundary(t, ctx, pool)
	assertAuditPlaintextAbsent(
		t,
		ctx,
		admin,
		producerCredentialA,
		producerCredentialB,
		paasProducerCredential,
		readerCredentialA,
		readerCredentialB,
		deniedCredential,
		verifierCredential,
	)

	iam.failure = errors.New("native IAM failure contains " + readerCredentialA + " and native-provider-path")
	failure := performAuditRequest(
		handler,
		http.MethodPost,
		"/v1/records:query",
		readerCredentialA,
		mustJSON(t, auditv1.QueryRecordsRequest{PageSize: 10}),
	)
	if failure.Code != http.StatusServiceUnavailable ||
		bytes.Contains(failure.Body.Bytes(), []byte(readerCredentialA)) ||
		bytes.Contains(failure.Body.Bytes(), []byte("native IAM failure")) ||
		bytes.Contains(failure.Body.Bytes(), []byte(`native-provider-path`)) {
		t.Fatalf("Audit IAM outage leaked native data: status=%d body=%s", failure.Code, failure.Body.String())
	}
}

func verifyInstallationAudit(
	t *testing.T,
	handler http.Handler,
	credential string,
	request auditv1.VerifyInstallationRequest,
	status int,
) auditv1.InstallationVerification {
	t.Helper()
	response := performAuditRequest(
		handler,
		http.MethodPost,
		"/v1/installation:verify",
		credential,
		mustJSON(t, request),
	)
	if response.Code != status {
		t.Fatalf("installation Audit verification status=%d want=%d body=%s", response.Code, status, response.Body.String())
	}
	if status != http.StatusOK {
		return auditv1.InstallationVerification{}
	}
	var verification auditv1.InstallationVerification
	if err := json.Unmarshal(response.Body.Bytes(), &verification); err != nil ||
		auditv1.ValidateInstallationVerification(verification) != nil {
		t.Fatalf("decode installation Audit verification=%#v err=%v", verification, err)
	}
	return verification
}

func integrationEvent(
	eventID auditv1.EventID,
	tenantID auditv1.TenantID,
	action auditv1.Action,
	targetKind auditv1.TargetKind,
	targetID string,
	occurredAt time.Time,
) auditv1.Event {
	return auditv1.Event{
		APIVersion: auditv1.APIVersion,
		Kind:       "AuditEvent",
		EventID:    eventID,
		TenantID:   tenantID,
		Actor: auditv1.ActorReference{
			Type: auditv1.ActorServiceAccount,
			ID:   "service-iam",
		},
		Action:        action,
		Target:        auditv1.TargetReference{Kind: targetKind, ID: targetID},
		Result:        auditv1.ResultSucceeded,
		RequestDigest: "sha256:" + strings.Repeat("2", 64),
		RequestID:     "request-" + string(eventID),
		CorrelationID: "correlation-" + string(eventID),
		OccurredAt:    occurredAt,
	}
}

func ingestAuditEvent(
	t *testing.T,
	handler http.Handler,
	credential string,
	event auditv1.Event,
	status int,
) auditv1.IngestionResult {
	t.Helper()
	response := performAuditRequest(
		handler,
		http.MethodPost,
		"/v1/events",
		credential,
		mustJSON(t, event),
	)
	if response.Code != status {
		t.Fatalf("Audit ingest %s status=%d want=%d body=%s", event.EventID, response.Code, status, response.Body.String())
	}
	if status != http.StatusOK && status != http.StatusCreated {
		return auditv1.IngestionResult{}
	}
	var result auditv1.IngestionResult
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil ||
		auditv1.ValidateIngestionResult(result) != nil {
		t.Fatalf("decode Audit ingestion result=%#v err=%v", result, err)
	}
	return result
}

func queryAuditRecords(
	t *testing.T,
	handler http.Handler,
	credential string,
	request auditv1.QueryRecordsRequest,
	status int,
) auditv1.RecordPage {
	t.Helper()
	response := performAuditRequest(
		handler,
		http.MethodPost,
		"/v1/records:query",
		credential,
		mustJSON(t, request),
	)
	if response.Code != status {
		t.Fatalf("Audit query status=%d want=%d body=%s", response.Code, status, response.Body.String())
	}
	if status != http.StatusOK {
		return auditv1.RecordPage{}
	}
	var page auditv1.RecordPage
	if err := json.Unmarshal(response.Body.Bytes(), &page); err != nil ||
		auditv1.ValidateRecordPage(page) != nil {
		t.Fatalf("decode Audit record page=%#v err=%v", page, err)
	}
	return page
}

func verifyAuditChain(
	t *testing.T,
	handler http.Handler,
	credential string,
	request auditv1.VerifyChainRequest,
	status int,
) auditv1.ChainVerification {
	t.Helper()
	response := performAuditRequest(
		handler,
		http.MethodPost,
		"/v1/integrity:verify",
		credential,
		mustJSON(t, request),
	)
	if response.Code != status {
		t.Fatalf("Audit verification status=%d want=%d body=%s", response.Code, status, response.Body.String())
	}
	if status != http.StatusOK {
		return auditv1.ChainVerification{}
	}
	var verification auditv1.ChainVerification
	if err := json.Unmarshal(response.Body.Bytes(), &verification); err != nil ||
		auditv1.ValidateChainVerification(verification) != nil {
		t.Fatalf("decode Audit chain verification=%#v err=%v", verification, err)
	}
	return verification
}

func performAuditRequest(
	handler http.Handler,
	method string,
	target string,
	bearer string,
	body []byte,
) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, target, bytes.NewReader(body))
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("encode Audit HTTP value: %v", err)
	}
	return encoded
}

func assertAuditPostgres18(t *testing.T, ctx context.Context, admin *pgx.Conn) {
	t.Helper()
	var version int
	if err := admin.QueryRow(ctx, "SELECT current_setting('server_version_num')::integer").Scan(&version); err != nil {
		t.Fatalf("read PostgreSQL version: %v", err)
	}
	if version < 180000 || version >= 190000 {
		t.Fatalf("PostgreSQL version=%d want major 18", version)
	}
}

func assertCleanAuditSchema(t *testing.T, ctx context.Context, admin *pgx.Conn) {
	t.Helper()
	var exists bool
	if err := admin.QueryRow(ctx, "SELECT to_regnamespace('audit') IS NOT NULL").Scan(&exists); err != nil {
		t.Fatalf("inspect Audit schema: %v", err)
	}
	if exists {
		t.Fatal("Audit HTTP integration database is not clean")
	}
}

func applyAuditSchema(t *testing.T, ctx context.Context, admin *pgx.Conn) {
	t.Helper()
	if err := auditmigration.Bootstrap(ctx, admin); err != nil {
		t.Fatalf("bootstrap Audit migration: %v", err)
	}
	if err := auditmigration.Up(ctx, admin); err != nil {
		t.Fatalf("apply Audit migration: %v", err)
	}
	if err := auditmigration.Verify(ctx, admin); err != nil {
		t.Fatalf("verify Audit migration: %v", err)
	}
}

func createAuditHTTPRole(t *testing.T, ctx context.Context, admin *pgx.Conn) {
	t.Helper()
	statement := `DO $matrix_audit_http_role$
	BEGIN
		IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = '` + auditHTTPTestRole + `') THEN
			CREATE ROLE ` + auditHTTPTestRole + ` LOGIN
				NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
		END IF;
	END
	$matrix_audit_http_role$;
	ALTER ROLE ` + auditHTTPTestRole + ` PASSWORD '` + auditHTTPTestPassword + `';
	GRANT matrix_audit_runtime TO ` + auditHTTPTestRole + `;`
	if _, err := admin.Exec(ctx, statement); err != nil {
		t.Fatalf("create Audit HTTP runtime role: %v", err)
	}
}

func assertAuditFacts(t *testing.T, ctx context.Context, admin *pgx.Conn) {
	t.Helper()
	var tenantA, tenantB, unexpectedTenants, accessA, accessB, verifierAccess, verifierAccessWithoutDecision int
	if err := admin.QueryRow(
		ctx,
		`SELECT
			count(*) FILTER (WHERE tenant_id = 'organization-a'),
			count(*) FILTER (WHERE tenant_id = 'organization-b'),
			count(*) FILTER (WHERE tenant_id NOT IN ('organization-a', 'organization-b')),
			count(*) FILTER (
				WHERE tenant_id = 'organization-a' AND source = 'AUDIT'
			),
			count(*) FILTER (
				WHERE tenant_id = 'organization-b' AND source = 'AUDIT'
			),
			count(*) FILTER (
				WHERE tenant_id = 'organization-a'
				  AND source = 'AUDIT'
				  AND event_document->>'action' = $1
				  AND event_document#>>'{actor,type}' = 'SERVICE_ACCOUNT'
				  AND event_document#>>'{actor,id}' = 'service-installation-verifier'
				  AND event_document#>>'{target,id}' = 'installation-verification'
			),
			count(*) FILTER (
				WHERE tenant_id = 'organization-a'
				  AND source = 'AUDIT'
				  AND event_document->>'action' = $1
				  AND event_document#>>'{actor,id}' = 'service-installation-verifier'
				  AND COALESCE(event_document->>'iamDecisionId', '') = ''
			)
		 FROM audit.records`,
		string(auditv1.ActionAuditIntegrityVerified),
	).Scan(
		&tenantA, &tenantB, &unexpectedTenants, &accessA, &accessB,
		&verifierAccess, &verifierAccessWithoutDecision,
	); err != nil {
		t.Fatalf("inspect Audit HTTP facts: %v", err)
	}
	if tenantA == 0 || tenantB == 0 || unexpectedTenants != 0 ||
		accessA == 0 || accessB == 0 || verifierAccess != 1 ||
		verifierAccessWithoutDecision != 0 {
		t.Fatalf(
			"Audit facts tenantA=%d tenantB=%d unexpected=%d accessA=%d accessB=%d verifierAccess=%d verifierMissingDecision=%d",
			tenantA, tenantB, unexpectedTenants, accessA, accessB,
			verifierAccess, verifierAccessWithoutDecision,
		)
	}
}

func assertAuditRuntimeBoundary(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
) {
	t.Helper()
	var count int
	err := pool.QueryRow(ctx, "SELECT count(*) FROM audit.records").Scan(&count)
	assertPostgresCode(t, err, "42501")
	err = pool.QueryRow(
		ctx,
		`SELECT audit.calculate_record_hash(
			'organization-a', 1, repeat('a', 71), repeat('b', 71),
			transaction_timestamp(), 'INDEFINITE'
		)`,
	).Scan(new(string))
	assertPostgresCode(t, err, "42501")
}

func assertPostgresCode(t *testing.T, err error, code string) {
	t.Helper()
	var postgresError *pgconn.PgError
	if !errors.As(err, &postgresError) || postgresError.Code != code {
		t.Fatalf("PostgreSQL error=%v want code=%s", err, code)
	}
}

func assertAuditPlaintextAbsent(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	plaintexts ...string,
) {
	t.Helper()
	for _, plaintext := range plaintexts {
		var present bool
		if err := admin.QueryRow(
			ctx,
			`SELECT EXISTS (
				SELECT 1 FROM audit.records
				 WHERE event_document::text LIKE '%' || $1 || '%'
				    OR canonical_document LIKE '%' || $1 || '%'
			)`,
			plaintext,
		).Scan(&present); err != nil {
			t.Fatalf("inspect Audit plaintext storage: %v", err)
		}
		if present {
			t.Fatal("Audit stored credential plaintext")
		}
	}
}

type integrationIAM struct {
	now      time.Time
	sequence int
	failure  error
}

func (client *integrationIAM) ServiceIdentity(
	_ context.Context,
	credential iamv1.Secret,
) (iamv1.ServiceIdentity, error) {
	organizationID := iamv1.OrganizationID("")
	switch {
	case secretEquals(credential, producerCredentialA):
		organizationID = "organization-a"
	case secretEquals(credential, producerCredentialB):
		organizationID = "organization-b"
	case secretEquals(credential, paasProducerCredential):
		return iamv1.ServiceIdentity{
			APIVersion: iamv1.APIVersion, Kind: "ServiceIdentity",
			OrganizationID: "organization-a", PrincipalID: "service-paas",
			Purpose: iamv1.ServicePaaS,
		}, nil
	default:
		return iamv1.ServiceIdentity{}, auditlog.ErrUnauthenticated
	}
	return iamv1.ServiceIdentity{
		APIVersion:     iamv1.APIVersion,
		Kind:           "ServiceIdentity",
		OrganizationID: organizationID,
		PrincipalID:    "service-iam",
		Purpose:        iamv1.ServiceIAM,
	}, nil
}

func (client *integrationIAM) Authorize(
	_ context.Context,
	credential iamv1.Secret,
	request iamv1.AuthorizationRequest,
) (iamv1.AuthorizationDecision, error) {
	if client.failure != nil {
		return iamv1.AuthorizationDecision{}, client.failure
	}
	client.sequence++
	decision := iamv1.AuthorizationDecision{
		APIVersion: iamv1.APIVersion,
		Kind:       "AuthorizationDecision",
		ID:         iamv1.DecisionID(fmt.Sprintf("decision-http-%d", client.sequence)),
		Allowed:    true,
		Reason:     iamv1.DecisionAllowed,
		Subject:    &iamv1.Subject{Type: iamv1.PrincipalUser, ID: "principal-reader"},
		Action:     request.Action,
		Resource:   request.Resource,
		RequestID:  request.RequestID,
		DecidedAt:  client.now,
	}
	switch {
	case secretEquals(credential, readerCredentialA):
		decision.TenantID = "organization-a"
	case secretEquals(credential, readerCredentialB):
		decision.TenantID = "organization-b"
	case secretEquals(credential, deniedCredential):
		decision.Allowed = false
		decision.Reason = iamv1.DecisionDenied
		decision.Subject = nil
	default:
		return iamv1.AuthorizationDecision{}, auditlog.ErrUnauthenticated
	}
	return decision, nil
}

func (client *integrationIAM) VerifyInstallation(
	_ context.Context,
	credential iamv1.Secret,
	request iamv1.AuthorizationRequest,
) (iamv1.AuthorizationDecision, error) {
	if client.failure != nil {
		return iamv1.AuthorizationDecision{}, client.failure
	}
	if !secretEquals(credential, verifierCredential) {
		return iamv1.AuthorizationDecision{}, auditlog.ErrUnauthenticated
	}
	client.sequence++
	return iamv1.AuthorizationDecision{
		APIVersion: iamv1.APIVersion, Kind: "AuthorizationDecision",
		ID:      iamv1.DecisionID(fmt.Sprintf("decision-http-%d", client.sequence)),
		Allowed: true, Reason: iamv1.DecisionAllowed,
		TenantID: "organization-a",
		Subject: &iamv1.Subject{
			Type: iamv1.PrincipalServiceAccount, ID: "service-installation-verifier",
		},
		Action: request.Action, Resource: request.Resource,
		RequestID: request.RequestID, DecidedAt: client.now,
	}, nil
}

func secretEquals(secret iamv1.Secret, expected string) bool {
	actual := secret.CopyBytes()
	defer clear(actual)
	return subtle.ConstantTimeCompare(actual, []byte(expected)) == 1
}
