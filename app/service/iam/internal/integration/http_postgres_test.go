package integration

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/iam/internal/authority"
	iampostgres "github.com/xiak/matrix/app/service/iam/internal/data/postgres"
	iamhttp "github.com/xiak/matrix/app/service/iam/internal/service/nethttp"
	"github.com/xiak/matrix/app/service/iam/internal/usecase/auditdispatch"
	"github.com/xiak/matrix/app/service/iam/internal/usecase/identityaccess"
	iammigration "github.com/xiak/matrix/app/service/iam/migration"
)

const (
	iamHTTPPostgresDSN       = "MATRIX_IAM_HTTP_POSTGRES_TEST_DSN"
	iamHTTPTestRole          = "matrix_iam_http_test_api"
	iamHTTPWorkerRole        = "matrix_iam_http_test_worker"
	iamHTTPTestPassword      = "matrix-iam-http-test-only"
	adminPassword            = "Initial-Admin-Password-49!"
	changedAdminPassword     = "Changed-Admin-Password-73!"
	initialDeveloperPassword = "Initial-Developer-Password-84!"
	changedDeveloperPassword = "Changed-Developer-Password-95!"
	paasCredential           = "mx1.PaaSHTTPIntegrationCredential000000000000001"
	auditCredential          = "mx1.AuditHTTPIntegrationCredential00000000000001"
	verifierCredential       = "mx1.VerifierHTTPIntegrationCredential0000000001"
	iamProducerCredential    = "mx1.IAMHTTPIntegrationCredential0000000000000001"
)

func findIAMCapability(values []iamv1.ActionCapability, action iamv1.Action, kind iamv1.ResourceKind, id string) (iamv1.ActionCapability, bool) {
	for _, value := range values {
		if value.Action == action && value.Resource.Kind == kind && value.Resource.ID == id {
			return value, true
		}
	}
	return iamv1.ActionCapability{}, false
}

var removedBuiltinRoleNames = []string{
	"ORGANIZATION_ADMIN",
	"PLATFORM_OPERATOR",
	"PAAS_DEVELOPER",
	"PAAS_VIEWER",
	"AUDIT_READER",
	"INSTALLATION_VERIFIER",
}

func proveDirectPolicyAttachments(t *testing.T, ctx context.Context, handler http.Handler, admin *pgx.Conn, primary string) {
	t.Helper()
	post := func(path, credential string, body any, want int) *httptest.ResponseRecorder {
		t.Helper()
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		response := performIAMRequest(handler, http.MethodPost, path, credential, encoded)
		if response.Code != want {
			t.Fatalf("policy management %s: status=%d want=%d body=%s", path, response.Code, want, response.Body.String())
		}
		return response
	}
	for _, path := range []string{"/v1/role-bindings", "/v1/role-bindings/old:revoke"} {
		post(path, primary, map[string]any{}, http.StatusNotFound)
	}
	response := post("/v1/users", primary, map[string]any{"loginName": "policy-member", "displayName": "Policy member", "initialPassword": initialDeveloperPassword, "requestId": "policy-member-create"}, http.StatusCreated)
	var member iamv1.User
	if json.Unmarshal(response.Body.Bytes(), &member) != nil || iamv1.ValidateUser(member) != nil {
		t.Fatal("invalid new member")
	}
	bearer := localRecoveryLogin(t, handler, "policy-member@"+string(member.AccountID), initialDeveloperPassword, true)
	bearer = localRecoveryChangePassword(t, handler, bearer, initialDeveloperPassword, changedDeveloperPassword)
	authorize := func(want bool) {
		t.Helper()
		body, _ := json.Marshal(iamv1.AuthorizationRequest{Action: iamv1.ActionPaaSApplicationRead, Resource: iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "attachment-app"}, RequestID: "attachment-read", CorrelationID: "attachment-read"})
		response := performIAMRequestWithSubject(handler, body, paasCredential, bearer)
		var decision iamv1.AuthorizationDecision
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &decision) != nil || decision.Allowed != want {
			t.Fatalf("member allowed=%t want=%t status=%d", decision.Allowed, want, response.Code)
		}
	}
	authorize(false)
	request := iamv1.CreatePolicyAttachmentRequest{Target: iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetUser, ID: string(member.ID)}, PolicyID: iamv1.SystemPolicyPaaSViewer, PolicyResourceVersion: 1, RequestID: "policy-member-grant"}
	parse := func(response *httptest.ResponseRecorder) iamv1.PolicyAttachment {
		t.Helper()
		var attachment iamv1.PolicyAttachment
		if json.Unmarshal(response.Body.Bytes(), &attachment) != nil || iamv1.ValidatePolicyAttachment(attachment) != nil {
			t.Fatal("invalid policy attachment response")
		}
		return attachment
	}
	attachment := parse(post("/v1/policy-attachments", primary, request, http.StatusOK))
	directoryAttachment := func(expected iamv1.PolicyAttachment, present bool) {
		t.Helper()
		response := performIAMRequest(handler, http.MethodGet, "/v1/users", primary, nil)
		var directory iamv1.UserList
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &directory) != nil || iamv1.ValidateUserList(directory) != nil || strings.Contains(response.Body.String(), `"roleBindings"`) {
			t.Fatalf("invalid policy directory: status=%d body=%s", response.Code, response.Body.String())
		}
		found := false
		for _, entry := range directory.Items {
			for _, actual := range entry.PolicyAttachments {
				if actual.ID == expected.ID {
					found = true
					if actual != expected {
						t.Fatal("directory altered attachment identity or scope")
					}
				}
			}
		}
		if found != present {
			t.Fatalf("directory attachment present=%t want=%t", found, present)
		}
	}
	directoryAttachment(attachment, true)
	if attachment.Target != request.Target || attachment.PolicyID != request.PolicyID || attachment.Scope != iamv1.AuthorityScopeTenant || attachment.AccountID != member.AccountID {
		t.Fatal("attachment authority differs")
	}
	if replay := parse(post("/v1/policy-attachments", primary, request, http.StatusOK)); replay.ID != attachment.ID || replay.CreatedAt != attachment.CreatedAt {
		t.Fatal("create replay changed attachment identity")
	}
	authorize(true)
	variant := request
	variant.PolicyID = iamv1.SystemPolicyPaaSDeveloper
	post("/v1/policy-attachments", primary, variant, http.StatusConflict)
	variant = request
	variant.RequestID = "policy-stale-version"
	variant.PolicyResourceVersion = 2
	post("/v1/policy-attachments", primary, variant, http.StatusConflict)
	variant = request
	variant.RequestID = "policy-foreign-user"
	variant.Target.ID = "foreign-user"
	post("/v1/policy-attachments", primary, variant, http.StatusForbidden)
	variant = request
	variant.RequestID = "policy-probe-user"
	variant.PolicyID = iamv1.SystemPolicyInstallationVerifier
	post("/v1/policy-attachments", primary, variant, http.StatusForbidden)
	variant = request
	variant.RequestID = "policy-self-admin"
	variant.PolicyID = iamv1.SystemPolicyAccountAdministrator
	post("/v1/policy-attachments", bearer, variant, http.StatusForbidden)
	administratorRequest := variant
	path := "/v1/policy-attachments/" + string(attachment.ID) + ":revoke"
	revoke := iamv1.RevokePolicyAttachmentRequest{ResourceVersion: 2, RequestID: "policy-member-revoke"}
	post(path, primary, revoke, http.StatusConflict)
	authorize(true)
	revoke.ResourceVersion = 1
	post(path, primary, revoke, http.StatusOK)
	post(path, primary, revoke, http.StatusOK)
	post("/v1/policy-attachments", primary, request, http.StatusConflict)
	authorize(false)
	directoryAttachment(attachment, false)
	var revoked bool
	var createdFacts, revokedFacts int
	if err := admin.QueryRow(ctx, `SELECT revoked_at IS NOT NULL AND resource_version=2 FROM iam.policy_attachments WHERE tenant_id=$1 AND id=$2`, member.AccountID, attachment.ID).Scan(&revoked); err != nil || !revoked {
		t.Fatal("attachment revocation did not persist")
	}
	if err := admin.QueryRow(ctx, `SELECT count(*) FILTER (WHERE event_document->>'action'='iam.policy-attachment.created'),count(*) FILTER (WHERE event_document->>'action'='iam.policy-attachment.revoked') FROM iam.audit_outbox WHERE tenant_id=$1 AND event_document#>>'{target,id}'=$2`, member.AccountID, attachment.ID).Scan(&createdFacts, &revokedFacts); err != nil || createdFacts != 1 || revokedFacts != 1 {
		t.Fatal("replay duplicated attachment facts")
	}
	regrant := request
	regrant.RequestID = "policy-member-new-explicit-grant"
	replacement := parse(post("/v1/policy-attachments", primary, regrant, http.StatusOK))
	if replacement.ID == attachment.ID {
		t.Fatal("explicit regrant reused revoked attachment")
	}
	authorize(true)
	post(path, primary, revoke, http.StatusOK)
	authorize(true) // Exact old revoke replay cannot revoke the new relationship.
	post("/v1/policy-attachments/"+string(replacement.ID)+":revoke", primary, iamv1.RevokePolicyAttachmentRequest{ResourceVersion: 1, RequestID: "policy-member-new-revoke"}, http.StatusOK)
	authorize(false)
	post("/v1/policy-attachments", primary, administratorRequest, http.StatusOK)
	variant = administratorRequest
	variant.RequestID = "policy-self-platform"
	variant.PolicyID = iamv1.SystemPolicyPlatformOperator
	post("/v1/policy-attachments", bearer, variant, http.StatusForbidden)
	platform := parse(post("/v1/policy-attachments", primary, variant, http.StatusOK))
	if platform.Scope != iamv1.AuthorityScopeInstallation || platform.InstallationID == "" {
		t.Fatal("platform grant lost sealed scope")
	}
	directoryAttachment(platform, true)
	post("/v1/policy-attachments/"+string(platform.ID)+":revoke", primary, iamv1.RevokePolicyAttachmentRequest{ResourceVersion: 1, RequestID: "policy-platform-revoke"}, http.StatusOK)
	directoryAttachment(platform, false)
	t.Run("platform attachment serializes with credential mutations", func(t *testing.T) {
		provePlatformCredentialProtection(t, ctx, handler, admin, primary, bearer)
	})
	rows, err := admin.Query(ctx, `SELECT event_document FROM iam.audit_outbox WHERE tenant_id=$1 AND event_document#>>'{target,id}'=$2 ORDER BY event_id`, member.AccountID, platform.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	facts := 0
	for rows.Next() {
		var body []byte
		var event auditv1.Event
		if rows.Scan(&body) != nil || json.Unmarshal(body, &event) != nil || auditv1.ValidateEventForSource(auditv1.SourceIAM, event) != nil || event.TenantID != "" || event.InstallationID != platform.InstallationID {
			t.Fatal("platform attachment fact lost its scope")
		}
		facts++
	}
	if rows.Err() != nil || facts != 2 {
		t.Fatal("missing platform attachment facts")
	}
}

func TestIAMPolicyAuthorityStoragePostgres(t *testing.T) {
	const environment = "MATRIX_IAM_POLICY_POSTGRES_TEST_DSN"
	dsn := os.Getenv(environment)
	if dsn == "" {
		t.Skipf("set %s to a clean disposable PostgreSQL 18 database", environment)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	config, err := pgx.ParseConfig(dsn)
	if err != nil || !strings.HasPrefix(config.Database, "matrix_iam_policy_") {
		t.Fatal("policy storage gate requires its own matrix_iam_policy_ database")
	}
	var migrationFaultReached atomic.Bool
	config.OnNotice = func(_ *pgconn.PgConn, notice *pgconn.Notice) {
		if notice.Message == "matrix-current-iam-fault" {
			migrationFaultReached.Store(true)
		}
	}
	config.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	admin, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal("connect policy storage database")
	}
	defer admin.Close(context.Background())
	assertIAMPostgres18(t, ctx, admin)
	assertCleanIAMSchema(t, ctx, admin)
	// The current clean-install gate proves the atomic boundary without
	// treating every unpublished historical schema as a release baseline.
	if err := iammigration.Bootstrap(ctx, admin); err != nil {
		t.Fatal("bootstrap current-schema atomicity fixture")
	}
	if _, err := admin.Exec(ctx, `CREATE FUNCTION public.matrix_current_iam_fault() RETURNS event_trigger LANGUAGE plpgsql AS $body$
		BEGIN IF EXISTS(SELECT 1 FROM pg_event_trigger_ddl_commands() WHERE object_identity='iam.group_memberships')
		THEN RAISE NOTICE 'matrix-current-iam-fault';
		RAISE EXCEPTION 'injected current IAM migration failure'; END IF; END $body$;
		CREATE EVENT TRIGGER matrix_current_iam_fault ON ddl_command_end EXECUTE FUNCTION public.matrix_current_iam_fault()`); err != nil {
		t.Fatal("install isolated current-schema fault")
	}
	// The production adapter intentionally sanitizes database errors. Observe
	// only the synthetic fixture notice to distinguish our fault from a setup error.
	if err := iammigration.Up(ctx, admin); err == nil || !migrationFaultReached.Load() {
		t.Fatalf("late current-schema fault not reached: %v", err)
	}
	if _, err := admin.Exec(ctx, "ROLLBACK; DROP EVENT TRIGGER matrix_current_iam_fault; DROP FUNCTION public.matrix_current_iam_fault()"); err != nil {
		t.Fatal("finish isolated current-schema fault")
	}
	var emptyAuthority bool
	if err := admin.QueryRow(ctx, `SELECT to_regclass('iam.principals') IS NULL
		AND to_regclass('iam.policy_attachments') IS NULL AND to_regclass('iam.authorization_decisions') IS NULL
		AND to_regclass('iam.audit_outbox') IS NULL AND to_regclass('iam.groups') IS NULL
		AND to_regclass('iam.group_memberships') IS NULL AND to_regprocedure('iam.readiness()') IS NULL`).Scan(&emptyAuthority); err != nil || !emptyAuthority {
		t.Fatal("failed current installation exposed a partial authority")
	}
	applyIAMSchema(t, ctx, admin)
	applyIAMSchema(t, ctx, admin)
	createIAMHTTPRole(t, ctx, admin)
	workflow := localRecoveryWorkflow(t, ctx, dsn, iamHTTPTestRole)
	document := iamHTTPBootstrap(t)
	status, err := workflow.Bootstrap(ctx, document)
	if err != nil || status.State != iamv1.BootstrapReady {
		t.Fatalf("bootstrap policy authority: status=%#v err=%v", status, err)
	}
	applyIAMSchema(t, ctx, admin)
	replayed, err := workflow.Bootstrap(ctx, document)
	if err != nil || replayed.ContentDigest != status.ContentDigest || replayed.AppliedAt == nil ||
		status.AppliedAt == nil || *replayed.AppliedAt != *status.AppliedAt {
		t.Fatalf("replay policy authority bootstrap: status=%#v err=%v", replayed, err)
	}
	handler, err := iamhttp.NewHandler(workflow, iamhttp.Config{})
	if err != nil {
		t.Fatal(err)
	}
	primary := localRecoveryLogin(t, handler, "admin", adminPassword, true)
	primary = localRecoveryChangePassword(t, handler, primary, adminPassword, changedAdminPassword)
	identityResponse := performIAMRequest(handler, http.MethodGet, "/v1/auth/me", primary, nil)
	var currentIdentity iamv1.CurrentIdentity
	if identityResponse.Code != http.StatusOK || json.Unmarshal(identityResponse.Body.Bytes(), &currentIdentity) != nil ||
		iamv1.ValidateCurrentIdentity(currentIdentity) != nil || len(currentIdentity.PolicySources) != 2 {
		t.Fatal("current identity did not consume the new policy snapshot")
	}
	readSnapshot := func() []authority.AttachedPolicy {
		t.Helper()
		tx, err := admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		if _, err := tx.Exec(ctx, `SET LOCAL ROLE matrix_iam_owner; SELECT set_config('matrix.iam_tenant_id',$1,true)`, document.Organization.ID); err != nil {
			t.Fatal(err)
		}
		var encoded []byte
		if err := tx.QueryRow(ctx, `SELECT iam.current_policy_snapshot($1,$2)`, document.Organization.ID, document.Administrator.ID).Scan(&encoded); err != nil {
			t.Fatal(err)
		}
		var rows []authority.AttachedPolicy
		if json.Unmarshal(encoded, &rows) != nil {
			t.Fatal("decode stored policy snapshot")
		}
		for index := range rows {
			row := &rows[index]
			row.Policy.CreatedAt, row.Policy.UpdatedAt = row.Policy.CreatedAt.UTC(), row.Policy.UpdatedAt.UTC()
			row.Attachment.CreatedAt, row.Attachment.UpdatedAt = row.Attachment.CreatedAt.UTC(), row.Attachment.UpdatedAt.UTC()
			if iamv1.ValidatePolicy(row.Policy) != nil || iamv1.ValidatePolicyVersion(row.Version) != nil || iamv1.ValidatePolicyAttachment(row.Attachment) != nil {
				t.Fatal("stored policy snapshot violates its public contract")
			}
		}
		return rows
	}
	initial := readSnapshot()
	if len(initial) != 2 {
		t.Fatalf("bootstrap must create separate account/platform attachments, got %d", len(initial))
	}
	for _, definition := range iamv1.AllRecordedActionDefinitions() {
		if _, current := iamv1.LookupActionDefinition(definition.Action); current {
			continue
		}
		body, err := json.Marshal(iamv1.AuthorizationRequest{Action: definition.Action,
			Resource:  iamv1.ResourceReference{Kind: definition.ResourceKind, ID: "retired-target"},
			RequestID: "retired-action-request", CorrelationID: "retired-action-request"})
		if err != nil {
			t.Fatal(err)
		}
		response := performIAMRequestWithSubject(handler, body, iamProducerCredential, primary)
		if response.Code != http.StatusUnprocessableEntity {
			t.Fatalf("retired action %s reached current HTTP authorization: %d", definition.Action, response.Code)
		}
	}
	var retiredDecisions int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM iam.authorization_decisions WHERE request_id='retired-action-request'`).Scan(&retiredDecisions); err != nil || retiredDecisions != 0 {
		t.Fatal("retired HTTP action created a current authorization decision")
	}
	assertDecision := func(action iamv1.Action, resource iamv1.ResourceReference, allowed bool) {
		t.Helper()
		result, evidence, err := authority.EvaluateAttachedPolicies(document.Organization.ID, document.InstallationID,
			iamv1.Subject{Type: iamv1.PrincipalUser, ID: document.Administrator.ID}, readSnapshot(), action, resource)
		if err != nil || result.Allowed != allowed || (allowed && len(evidence) == 0) {
			t.Fatalf("stored policy decision action=%s allowed=%t error=%v", action, result.Allowed, err)
		}
		body, err := json.Marshal(iamv1.AuthorizationRequest{Action: action, Resource: resource, RequestID: "policy-storage-authorize", CorrelationID: "policy-storage-authorize"})
		if err != nil {
			t.Fatal(err)
		}
		response := performIAMRequestWithSubject(handler, body, paasCredential, primary)
		var decision iamv1.AuthorizationDecision
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &decision) != nil || iamv1.ValidateAuthorizationDecision(decision) != nil || decision.Allowed != allowed {
			t.Fatalf("HTTP policy evaluation status=%d decision=%+v", response.Code, decision)
		}
		var stored []byte
		if err := admin.QueryRow(ctx, `SELECT policy_evidence FROM iam.authorization_decisions WHERE tenant_id=$1 AND id=$2`, document.Organization.ID, decision.ID).Scan(&stored); err != nil {
			t.Fatal(err)
		}
		var actual []authority.PolicyAttachmentEvidence
		if json.Unmarshal(stored, &actual) != nil || actual == nil || !slices.Equal(actual, evidence) {
			t.Fatal("HTTP decision did not persist exact evaluated attachment/version evidence")
		}
	}
	assertDecision(iamv1.ActionPaaSApplicationRead, iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "policy-storage-application"}, true)
	t.Run("policy directories isolate metadata and permissions", func(t *testing.T) {
		provePolicyDirectories(t, ctx, handler, admin, primary)
	})
	t.Run("direct policy attachment management", func(t *testing.T) {
		proveDirectPolicyAttachments(t, ctx, handler, admin, primary)
	})
	t.Run("group inheritance and terminal membership", func(t *testing.T) {
		proveGroupInheritance(t, ctx, handler, admin, primary)
	})
	t.Run("customer policy publication and current authority", func(t *testing.T) {
		proveCustomerPolicyPublication(t, ctx, handler, admin, primary)
	})
	t.Run("policy publication versus attachment revision", func(t *testing.T) {
		provePolicyDefaultAttachmentRaces(t, ctx, handler, admin, primary)
	})
	t.Run("policy-backed credential transaction races", func(t *testing.T) {
		provePasswordSessionRaces(t, ctx, handler, admin, primary)
	})
	t.Run("platform scope protects credentials independently of policy name", func(t *testing.T) {
		provePolicyScopeCredentialProtection(t, ctx, handler, admin, primary)
	})
	var accountAttachment iamv1.PolicyAttachment
	for _, row := range initial {
		if row.Policy.ID == iamv1.SystemPolicyAccountAdministrator {
			accountAttachment = row.Attachment
		}
	}
	if accountAttachment.ID == "" {
		t.Fatal("bootstrap account policy is absent")
	}
	assertRejected := func(name, sql, code string, args ...any) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			tx, err := admin.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			if _, err := tx.Exec(ctx, `SET LOCAL ROLE matrix_iam_owner; SELECT set_config('matrix.iam_tenant_id',$1,true)`, document.Organization.ID); err != nil {
				t.Fatal(err)
			}
			_, err = tx.Exec(ctx, sql, args...)
			var databaseError *pgconn.PgError
			if !errors.As(err, &databaseError) || databaseError.Code != code {
				t.Fatalf("attack result=%v want SQLSTATE %s", err, code)
			}
		})
	}
	assertRejected("immutable-version-update", `UPDATE iam.policy_versions SET content_digest=content_digest`, "42501")
	assertRejected("immutable-version-delete", `DELETE FROM iam.policy_versions`, "42501")
	assertRejected("immutable-decision-evidence", `UPDATE iam.authorization_decisions SET policy_evidence='[]'::jsonb`, "42501")
	for _, attack := range []struct{ name, evidence, code string }{
		{"allowed-without-policy-evidence", `'[]'::jsonb`, "22023"},
		{"decision-with-forged-version-digest", `jsonb_set(policy_evidence,'{0,version,contentDigest}',to_jsonb('sha256:'||repeat('0',64)))`, "42501"},
		{"decision-with-forged-attachment", `jsonb_set(policy_evidence,'{0,attachmentId}','"missing-attachment"'::jsonb)`, "42501"},
		{"decision-with-duplicate-evidence", `policy_evidence||policy_evidence`, "22023"},
		{"decision-with-unknown-evidence-field", `jsonb_set(policy_evidence,'{0,permit}','true'::jsonb)`, "22023"},
	} {
		// Refresh only the decision identity/time. Bad evidence must be refused
		// before the deliberately absent audit fact can be accepted or written.
		assertRejected(attack.name, `SELECT iam.record_authorization($1,$2,
			document||jsonb_build_object('id','forged-policy-decision','decidedAt',
			to_char(transaction_timestamp() AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')),
			'{}'::jsonb,`+attack.evidence+`) FROM iam.authorization_decisions WHERE allowed ORDER BY decided_at,id LIMIT 1`,
			attack.code, document.Organization.ID, document.Administrator.ID)
	}
	assertRejected("immutable-version-truncate", `TRUNCATE iam.policy_versions`, "0A000") // Referenced defaults also prohibit truncation.
	assertRejected("default-must-belong-to-policy", `UPDATE iam.policies SET default_version_id=(SELECT default_version_id FROM iam.policies WHERE id='system.platform-operator'),resource_version=resource_version+1,updated_at=transaction_timestamp() WHERE id='system.account-administrator'; SET CONSTRAINTS ALL IMMEDIATE`, "23503")
	assertRejected("attachment-identity-immutable", `UPDATE iam.policy_attachments SET policy_id='system.paas-viewer' WHERE id=$1`, "42501", accountAttachment.ID)
	assertRejected("attachment-history-delete", `DELETE FROM iam.policy_attachments WHERE id=$1`, "42501", accountAttachment.ID)
	assertRejected("attachment-forged-installation", `INSERT INTO iam.policy_attachments(tenant_id,id,target_id,policy_id,installation_id,resource_version,created_at,updated_at) VALUES($1,'forged-installation',$2,'system.platform-operator','other-installation',1,transaction_timestamp(),transaction_timestamp())`, "23503", document.Organization.ID, document.Administrator.ID)
	assertRejected("attachment-wrong-principal-kind", `INSERT INTO iam.policy_attachments(tenant_id,id,target_id,target_kind,policy_id,resource_version,created_at,updated_at) VALUES($1,'forged-kind',$2,'SERVICE_ACCOUNT','system.paas-viewer',1,transaction_timestamp(),transaction_timestamp())`, "23503", document.Organization.ID, document.Administrator.ID)
	assertRejected("tenant-attachment-cannot-select-installation", `INSERT INTO iam.policy_attachments(tenant_id,id,target_id,policy_id,installation_id,resource_version,created_at,updated_at) VALUES($1,'forged-tenant-scope',$2,'system.paas-viewer',$3,1,transaction_timestamp(),transaction_timestamp())`, "22023", document.Organization.ID, document.Administrator.ID, document.InstallationID)
	for _, role := range []string{iamHTTPTestRole, iamHTTPWorkerRole, "matrix_iam_credential_recovery"} {
		tx, err := admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+pgx.Identifier{role}.Sanitize()); err != nil {
			t.Fatal(err)
		}
		_, err = tx.Exec(ctx, `SELECT * FROM iam.policy_versions`)
		var databaseError *pgconn.PgError
		if !errors.As(err, &databaseError) || databaseError.Code != "42501" {
			t.Fatalf("runtime %s acquired policy table access: %v", role, err)
		}
		if err := tx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
	}
	// A different immutable default must drive evaluation; replaying the
	// code-owned seeds must not silently choose the original Allow again.
	denyDocument := iamv1.PolicyDocument{LanguageVersion: iamv1.PolicyLanguageVersion, Scope: iamv1.AuthorityScopeTenant,
		Statements: []iamv1.PolicyStatement{{SID: "deny-application-read", Effect: iamv1.PolicyDeny,
			Actions: []iamv1.Action{iamv1.ActionPaaSApplicationRead}, Resources: []iamv1.PolicyResourceSelector{
				{Kind: iamv1.ResourceApplication, Match: iamv1.PolicyResourceAnyInAuthority}}}}}
	canonical, digest, err := iamv1.CanonicalizePolicyDocument(denyDocument)
	if err != nil {
		t.Fatal(err)
	}
	// Create the foreign account through the current lifecycle so migration
	// replay also verifies its mandatory, immutable root relation. Only the
	// policy rows below are unpublished fixture-owner state.
	otherAccountRequest, err := json.Marshal(map[string]any{
		"id": "policy-other-account", "displayName": "Other account",
		"rootLoginName": "policy.other.root", "rootDisplayName": "Other account root",
		"initialPassword": initialDeveloperPassword, "requestId": "policy-other-account-create",
	})
	if err != nil {
		t.Fatal(err)
	}
	otherAccountResponse := performIAMRequest(handler, http.MethodPost, "/v1/accounts", primary, otherAccountRequest)
	var otherAccount iamv1.Account
	if otherAccountResponse.Code != http.StatusCreated || json.Unmarshal(otherAccountResponse.Body.Bytes(), &otherAccount) != nil ||
		iamv1.ValidateAccount(otherAccount) != nil || otherAccount.ID != "policy-other-account" {
		t.Fatalf("create valid foreign account fixture: status=%d", otherAccountResponse.Code)
	}
	if _, err := admin.Exec(ctx, `BEGIN;
		INSERT INTO iam.policies(id,management,owner_tenant_id,display_name,authority_scope,status,default_version_id,resource_version,created_at,updated_at)
		VALUES('customer.local','CUSTOMER',$1,'Same policy name','TENANT','ACTIVE','same-version-id',1,transaction_timestamp(),transaction_timestamp()),
		('customer.other','CUSTOMER','policy-other-account','Same policy name','TENANT','ACTIVE','same-version-id',1,transaction_timestamp(),transaction_timestamp());
		INSERT INTO iam.policy_versions(policy_id,id,authority_scope,document,canonical_document,content_digest,created_at)
		SELECT id,'same-version-id','TENANT',$2::jsonb,$2,$3,transaction_timestamp() FROM iam.policies WHERE id IN ('customer.local','customer.other');
		COMMIT;`, document.Organization.ID, canonical, digest); err != nil {
		t.Fatal(err)
	}
	rls, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rls.Exec(ctx, `SET LOCAL ROLE matrix_iam_owner; SELECT set_config('matrix.iam_tenant_id',$1,true)`, document.Organization.ID); err != nil {
		t.Fatal(err)
	}
	var visiblePolicies, visibleVersions int
	if err := rls.QueryRow(ctx, `SELECT (SELECT count(*) FROM iam.policies WHERE id IN ('customer.local','customer.other')),
		(SELECT count(*) FROM iam.policy_versions WHERE policy_id IN ('customer.local','customer.other'))`).Scan(&visiblePolicies, &visibleVersions); err != nil || visiblePolicies != 1 || visibleVersions != 1 {
		t.Fatal("customer metadata or versions escaped owner-forced RLS")
	}
	if err := rls.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	assertRejected("attachment-cannot-use-another-account-policy", `INSERT INTO iam.policy_attachments(tenant_id,id,target_id,policy_id,resource_version,created_at,updated_at) VALUES($1,'cross-account-policy',$2,'customer.other',1,transaction_timestamp(),transaction_timestamp())`, "23503", document.Organization.ID, document.Administrator.ID)
	allowDocument := denyDocument
	allowDocument.Statements = append([]iamv1.PolicyStatement{}, denyDocument.Statements...)
	allowDocument.Statements[0].Effect = iamv1.PolicyAllow
	allowCanonical, allowDigest, err := iamv1.CanonicalizePolicyDocument(allowDocument)
	if err != nil {
		t.Fatal(err)
	}
	// The 257th row deliberately sorts last and contains Deny. A projection
	// that silently truncates at 256 would authorize this request incorrectly.
	if _, err := admin.Exec(ctx, `BEGIN;
		INSERT INTO iam.policies(id,management,owner_tenant_id,display_name,authority_scope,status,default_version_id,resource_version,created_at,updated_at)
		SELECT 'budget-policy-'||i,'CUSTOMER',$1,'Budget policy '||i,'TENANT','ACTIVE','v1',1,transaction_timestamp(),transaction_timestamp() FROM generate_series(1,255) i;
		INSERT INTO iam.policy_versions(policy_id,id,authority_scope,document,canonical_document,content_digest,created_at)
		SELECT 'budget-policy-'||i,'v1','TENANT',CASE WHEN i=255 THEN $4::jsonb ELSE $2::jsonb END,
		CASE WHEN i=255 THEN $4 ELSE $2 END,CASE WHEN i=255 THEN $5 ELSE $3 END,transaction_timestamp() FROM generate_series(1,255) i;
		INSERT INTO iam.policy_attachments(tenant_id,id,target_id,policy_id,resource_version,created_at,updated_at)
		SELECT $1,'budget-attachment-'||i,$6,'budget-policy-'||i,1,transaction_timestamp(),transaction_timestamp() FROM generate_series(1,254) i;
		COMMIT;`, document.Organization.ID, allowCanonical, allowDigest, canonical, digest, document.Administrator.ID); err != nil {
		t.Fatal(err)
	}
	assertDecision(iamv1.ActionPaaSApplicationRead, iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "policy-storage-application"}, true)
	if _, err := admin.Exec(ctx, `INSERT INTO iam.policy_attachments(tenant_id,id,target_id,policy_id,resource_version,created_at,updated_at)
		VALUES($1,'zz-budget-attachment-deny',$2,'budget-policy-255',1,transaction_timestamp(),transaction_timestamp())`, document.Organization.ID, document.Administrator.ID); err != nil {
		t.Fatal(err)
	}
	var beforeBudget, afterBudget int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM iam.authorization_decisions`).Scan(&beforeBudget); err != nil {
		t.Fatal(err)
	}
	budgetRequest, _ := json.Marshal(iamv1.AuthorizationRequest{Action: iamv1.ActionPaaSApplicationRead,
		Resource:  iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "policy-storage-application"},
		RequestID: "policy-over-budget", CorrelationID: "policy-over-budget"})
	if response := performIAMRequestWithSubject(handler, budgetRequest, paasCredential, primary); response.Code != http.StatusServiceUnavailable {
		t.Fatalf("overflow policy snapshot was truncated or accepted: %d", response.Code)
	}
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM iam.authorization_decisions`).Scan(&afterBudget); err != nil || beforeBudget != afterBudget {
		t.Fatal("over-budget snapshot produced a partial authorization decision")
	}
	if _, err := admin.Exec(ctx, `UPDATE iam.policy_attachments SET revoked_at=transaction_timestamp(),updated_at=transaction_timestamp(),resource_version=resource_version+1
		WHERE tenant_id=$1 AND policy_id LIKE 'budget-policy-%'`, document.Organization.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `BEGIN;
		INSERT INTO iam.policy_versions(policy_id,id,authority_scope,document,canonical_document,content_digest,created_at)
		VALUES('system.account-administrator','storage-deny-v2','TENANT',$1::jsonb,$1,$2,transaction_timestamp());
		UPDATE iam.policies SET default_version_id='storage-deny-v2',resource_version=resource_version+1,updated_at=transaction_timestamp() WHERE id='system.account-administrator'; COMMIT;`, canonical, digest); err != nil {
		t.Fatal(err)
	}
	assertDecision(iamv1.ActionPaaSApplicationRead, iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "policy-storage-application"}, false)
	applyIAMSchema(t, ctx, admin)
	assertDecision(iamv1.ActionPaaSApplicationRead, iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "policy-storage-application"}, false)
	for _, row := range readSnapshot() {
		if row.Policy.ID == iamv1.SystemPolicyAccountAdministrator && (row.Version.ID != "storage-deny-v2" || row.Policy.ResourceVersion != 2 || row.Attachment.ID != accountAttachment.ID) {
			t.Fatal("migration rewrote a policy default, revision or attachment")
		}
	}
	for _, row := range initial {
		if row.Policy.ID == iamv1.SystemPolicyAccountAdministrator {
			if _, err := admin.Exec(ctx, `UPDATE iam.policies SET default_version_id=$1,resource_version=resource_version+1,updated_at=transaction_timestamp() WHERE id='system.account-administrator'`, row.Version.ID); err != nil {
				t.Fatal(err)
			}
		}
	}
	assertDecision(iamv1.ActionPaaSApplicationRead, iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "policy-storage-application"}, true)
	// Storage transition fixture, not an online root-revocation API. Verify
	// that replay cannot recreate an attachment even if its root still exists.
	if _, err := admin.Exec(ctx, `UPDATE iam.policy_attachments SET revoked_at=transaction_timestamp(),updated_at=transaction_timestamp(),resource_version=resource_version+1 WHERE tenant_id=$1 AND id=$2`, document.Organization.ID, accountAttachment.ID); err != nil {
		t.Fatal(err)
	}
	assertRejected("revoked-attachment-cannot-resurrect", `UPDATE iam.policy_attachments SET revoked_at=NULL,updated_at=transaction_timestamp(),resource_version=resource_version+1 WHERE id=$1`, "42501", accountAttachment.ID)
	applyIAMSchema(t, ctx, admin)
	if _, err := workflow.Bootstrap(ctx, document); err != nil {
		t.Fatal(err)
	}
	assertDecision(iamv1.ActionPaaSApplicationRead, iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "policy-storage-application"}, false)
	if _, err := admin.Exec(ctx, `UPDATE iam.policies SET status='RETIRED',resource_version=resource_version+1,updated_at=transaction_timestamp() WHERE id='system.platform-operator'`); err != nil {
		t.Fatal(err)
	}
	assertRejected("retired-policy-cannot-reactivate", `UPDATE iam.policies SET status='ACTIVE',resource_version=resource_version+1,updated_at=transaction_timestamp() WHERE id='system.platform-operator'`, "42501")
	applyIAMSchema(t, ctx, admin)
	if rows := readSnapshot(); len(rows) != 0 {
		t.Fatal("retired policy or revoked attachment was reactivated by migration")
	}
	var retainedVersions int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM iam.policy_versions WHERE policy_id='system.account-administrator'`).Scan(&retainedVersions); err != nil || retainedVersions != 2 {
		t.Fatal("migration lost an immutable version")
	}
	identity := performIAMRequest(handler, http.MethodGet, "/v1/service-identity", verifierCredential, nil)
	var service iamv1.ServiceIdentity
	if identity.Code != http.StatusOK || json.Unmarshal(identity.Body.Bytes(), &service) != nil ||
		service.Purpose != iamv1.ServiceInstallationVerifier || service.InstallationID != document.InstallationID {
		t.Fatal("policy migration changed sealed verifier purpose or installation")
	}
}

func proveCustomerPolicyPublication(t *testing.T, ctx context.Context, handler http.Handler, database *pgx.Conn, root string) {
	t.Helper()
	request := func(method, path, bearer string, body any, want int, result any) {
		t.Helper()
		var encoded []byte
		var err error
		if body != nil {
			encoded, err = json.Marshal(body)
		}
		if err != nil {
			t.Fatal(err)
		}
		response := performIAMRequest(handler, method, path, bearer, encoded)
		if response.Code != want {
			t.Fatalf("customer policy %s %s: status=%d want=%d body=%s", method, path, response.Code, want, response.Body.String())
		}
		if result != nil && json.Unmarshal(response.Body.Bytes(), result) != nil {
			t.Fatal("invalid customer policy response")
		}
	}
	post := func(path, bearer string, body any, want int, result any) {
		t.Helper()
		request(http.MethodPost, path, bearer, body, want, result)
	}
	get := func(path, bearer string, want int, result any) {
		t.Helper()
		request(http.MethodGet, path, bearer, nil, want, result)
	}
	create := iamv1.CreatePolicyRequest{DisplayName: "Selected application read", RequestID: "customer-policy-create",
		Document: iamv1.PolicyDocument{LanguageVersion: iamv1.PolicyLanguageVersion, Scope: iamv1.AuthorityScopeTenant,
			Statements: []iamv1.PolicyStatement{{SID: "selected", Effect: iamv1.PolicyAllow,
				Actions:   []iamv1.Action{iamv1.ActionPaaSApplicationRead},
				Resources: []iamv1.PolicyResourceSelector{{Kind: iamv1.ResourceApplication, Match: iamv1.PolicyResourceExact, ID: "customer-selected-app"}}}}}}
	var policy, replay, fetched iamv1.PolicyDetail
	post("/v1/policies", root, create, http.StatusCreated, &policy)
	post("/v1/policies", root, create, http.StatusCreated, &replay)
	get("/v1/policies/"+string(policy.Policy.ID), root, http.StatusOK, &fetched)
	if iamv1.ValidatePolicyDetail(policy) != nil || policy.Policy.Management != iamv1.PolicyCustomerManaged ||
		!bytes.Equal(mustIAMJSON(t, policy), mustIAMJSON(t, replay)) || !bytes.Equal(mustIAMJSON(t, policy), mustIAMJSON(t, fetched)) {
		t.Fatal("creation replay/read changed immutable policy identity or content")
	}
	var factCount, versionCount, attachmentCount int
	if err := database.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM iam.audit_outbox WHERE tenant_id=$1 AND event_document->>'action'='iam.policy.created' AND event_document#>>'{target,id}'=$2),
		(SELECT count(*) FROM iam.policy_versions WHERE policy_id=$2),
		(SELECT count(*) FROM iam.policy_attachments WHERE policy_id=$2)`, policy.Policy.AccountID, policy.Policy.ID).Scan(&factCount, &versionCount, &attachmentCount); err != nil || factCount != 1 || versionCount != 1 || attachmentCount != 0 {
		t.Fatalf("publication/replay is not atomic or implicitly attached: facts=%d versions=%d attachments=%d err=%v", factCount, versionCount, attachmentCount, err)
	}
	variant := create
	variant.DisplayName = "Different intent"
	post("/v1/policies", root, variant, http.StatusConflict, nil)
	variant = create
	variant.RequestID = "customer-policy-duplicate-name"
	post("/v1/policies", root, variant, http.StatusConflict, nil)
	post("/v1/policies?accountId=other", root, create, http.StatusBadRequest, nil)
	post("/v1/policies", paasCredential, create, http.StatusUnauthorized, nil)
	get("/v1/policies/"+string(iamv1.SystemPolicyPlatformOperator), root, http.StatusForbidden, nil)
	get("/v1/policies/missing-policy", root, http.StatusForbidden, nil)
	var member iamv1.User
	post("/v1/users", root, map[string]any{"loginName": "customer-policy-member", "displayName": "Policy member", "initialPassword": initialDeveloperPassword, "requestId": "customer-policy-member-create"}, http.StatusCreated, &member)
	bearer := localRecoveryLogin(t, handler, member.LoginName+"@"+string(member.AccountID), initialDeveloperPassword, true)
	post("/v1/policies", bearer, create, http.StatusForbidden, nil)
	bearer = localRecoveryChangePassword(t, handler, bearer, initialDeveloperPassword, changedDeveloperPassword)
	get("/v1/policies/"+string(policy.Policy.ID), bearer, http.StatusForbidden, nil)
	post("/v1/policies", bearer, create, http.StatusForbidden, nil)
	authorize := func(id string, want bool) {
		t.Helper()
		body := mustIAMJSON(t, iamv1.AuthorizationRequest{Action: iamv1.ActionPaaSApplicationRead,
			Resource: iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: id}, RequestID: "customer-policy-read", CorrelationID: "customer-policy-read"})
		response := performIAMRequestWithSubject(handler, body, paasCredential, bearer)
		var decision iamv1.AuthorizationDecision
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &decision) != nil || decision.Allowed != want {
			t.Fatalf("custom policy decision for %s: status=%d allowed=%t want=%t", id, response.Code, decision.Allowed, want)
		}
	}
	authorize("customer-selected-app", false)
	var attachment iamv1.PolicyAttachment
	grant := iamv1.CreatePolicyAttachmentRequest{Target: iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetUser, ID: string(member.ID)},
		PolicyID: policy.Policy.ID, PolicyResourceVersion: 1, RequestID: "customer-policy-attach"}
	post("/v1/policy-attachments", root, grant, http.StatusOK, &attachment)
	authorize("customer-selected-app", true)
	authorize("customer-unselected-app", false)
	post("/v1/policy-attachments/"+string(attachment.ID)+":revoke", root,
		iamv1.RevokePolicyAttachmentRequest{ResourceVersion: attachment.ResourceVersion, RequestID: "customer-policy-revoke"}, http.StatusOK, nil)
	authorize("customer-selected-app", false)
	// Even an explicit tenant administrator attachment does not yet delegate
	// the high-risk publishing workflow; it never becomes an implicit root.
	grant.PolicyID, grant.RequestID = iamv1.SystemPolicyAccountAdministrator, "customer-policy-admin"
	post("/v1/policy-attachments", root, grant, http.StatusOK, nil)
	get("/v1/policies/"+string(policy.Policy.ID), bearer, http.StatusOK, nil)
	variant.RequestID, variant.DisplayName = "customer-delegate-create", "Delegate policy"
	post("/v1/policies", bearer, variant, http.StatusForbidden, nil)
	post("/v1/accounts", root, map[string]any{"id": "customer-policy-other", "displayName": "Other policy account", "rootLoginName": "customer-policy-other", "rootDisplayName": "Other root", "initialPassword": initialDeveloperPassword, "requestId": "customer-policy-other-create"}, http.StatusCreated, nil)
	other := localRecoveryLogin(t, handler, "customer-policy-other", initialDeveloperPassword, true)
	other = localRecoveryChangePassword(t, handler, other, initialDeveloperPassword, changedDeveloperPassword)
	var foreign iamv1.PolicyDetail
	post("/v1/policies", other, create, http.StatusCreated, &foreign)
	if foreign.Policy.ID == policy.Policy.ID || foreign.Policy.AccountID == policy.Policy.AccountID || foreign.Policy.DisplayName != policy.Policy.DisplayName {
		t.Fatal("same-name customer policies did not retain independent account ownership")
	}
	get("/v1/policies/"+string(policy.Policy.ID), other, http.StatusForbidden, nil)
	get("/v1/policies/"+string(foreign.Policy.ID), root, http.StatusForbidden, nil)
	grant.PolicyID, grant.RequestID = foreign.Policy.ID, "customer-cross-account-attach"
	post("/v1/policy-attachments", root, grant, http.StatusForbidden, nil)
	var event auditv1.Event
	var raw []byte
	if err := database.QueryRow(ctx, `SELECT event_document FROM iam.audit_outbox WHERE tenant_id=$1 AND event_document->>'action'='iam.policy.created' AND event_document#>>'{target,id}'=$2`, policy.Policy.AccountID, policy.Policy.ID).Scan(&raw); err != nil || json.Unmarshal(raw, &event) != nil || auditv1.ValidateEvent(event) != nil || event.IAMDecisionID == "" || bytes.Contains(raw, []byte("customer-selected-app")) {
		t.Fatal("policy publication fact lacks authority correlation or discloses document content")
	}
	post("/v1/audit-producer:resolve", iamProducerCredential, iamv1.ResolveAuditProducerRequest{Event: event}, http.StatusOK, nil)
	for _, mutate := range []func(*auditv1.Event){
		func(v *auditv1.Event) { v.Target.ID = string(foreign.Policy.ID) },
		func(v *auditv1.Event) { v.TenantID = auditv1.TenantID(foreign.Policy.AccountID) },
		func(v *auditv1.Event) { v.RequestDigest = "sha256:" + strings.Repeat("f", 64) },
	} {
		forged := event
		mutate(&forged)
		post("/v1/audit-producer:resolve", iamProducerCredential, iamv1.ResolveAuditProducerRequest{Event: forged}, http.StatusForbidden, nil)
	}
	// Raw database publication has the same closed language boundary. Check
	// every registered action, not a prefix-based approximation of platform scope.
	checkDocument := func(canonical string, allowed bool) {
		t.Helper()
		tx, err := database.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		if _, err = tx.Exec(ctx, "SET LOCAL ROLE matrix_iam_owner"); err != nil {
			t.Fatal(err)
		}
		_, err = tx.Exec(ctx, `SELECT iam.assert_customer_policy_document($1,
			'sha256:'||encode(sha256(convert_to('matrix.iam.policy.v1','UTF8')||decode('00','hex')||convert_to($1,'UTF8')),'hex'))`, canonical)
		if allowed {
			if err != nil {
				t.Fatalf("valid customer document was rejected: %v", err)
			}
		} else {
			var invalid *pgconn.PgError
			if !errors.As(err, &invalid) || invalid.Code != "22023" {
				t.Fatalf("invalid customer document did not fail closed: %v", err)
			}
		}
	}
	for _, action := range iamv1.AllActionDefinitions() {
		document := iamv1.PolicyDocument{LanguageVersion: iamv1.PolicyLanguageVersion, Scope: action.AuthorityScope,
			Statements: []iamv1.PolicyStatement{{SID: "one", Effect: iamv1.PolicyAllow, Actions: []iamv1.Action{action.Action},
				Resources: []iamv1.PolicyResourceSelector{{Kind: action.ResourceKind, Match: iamv1.PolicyResourceAnyInAuthority}}}}}
		canonical, _, err := iamv1.CanonicalizePolicyDocument(document)
		if err != nil {
			t.Fatal(err)
		}
		checkDocument(canonical, action.AuthorityScope == iamv1.AuthorityScopeTenant)
		if action.AuthorityScope != iamv1.AuthorityScopeTenant {
			document.Scope = iamv1.AuthorityScopeTenant
			checkDocument(string(mustIAMJSON(t, document)), false)
		}
	}
	canonical, _, err := iamv1.CanonicalizePolicyDocument(create.Document)
	if err != nil {
		t.Fatal(err)
	}
	for _, malformed := range []string{
		strings.Replace(canonical, `"scope":`, `"scope":"TENANT","scope":`, 1),
		strings.Replace(canonical, `"effect":`, `"conditions":{"callerAdmin":true},"effect":`, 1),
		strings.Replace(canonical, `"paas.application.read"`, `"paas.future.allow"`, 1),
		strings.Replace(canonical, `"kind":"APPLICATION"`, `"kind":"USER","kind":"APPLICATION"`, 1),
		strings.Replace(canonical, `"id":"customer-selected-app"`, `"id":"*"`, 1),
		strings.Repeat(" ", int(iamv1.MaxPolicyBytes)) + canonical,
	} {
		checkDocument(malformed, false)
	}
	// Same-intent concurrent requests serialize on the publisher and return
	// one immutable creation; successful retries never add a second fact.
	concurrent := create
	concurrent.RequestID, concurrent.DisplayName = "customer-policy-concurrent", "Concurrent policy"
	body := mustIAMJSON(t, concurrent)
	responses := make(chan *httptest.ResponseRecorder, 2)
	for range 2 {
		go func() { responses <- performIAMRequest(handler, http.MethodPost, "/v1/policies", root, body) }()
	}
	var first []byte
	for range 2 {
		response := <-responses
		if response.Code != http.StatusCreated {
			t.Fatalf("concurrent publication: status=%d body=%s", response.Code, response.Body.String())
		}
		if first != nil && !bytes.Equal(first, response.Body.Bytes()) {
			t.Fatal("same-intent concurrent creation changed its result")
		}
		first = append([]byte(nil), response.Body.Bytes()...)
	}
	if err := database.QueryRow(ctx, `SELECT count(*) FROM iam.audit_outbox WHERE tenant_id=$1 AND event_document->>'action'='iam.policy.created' AND event_document->>'requestId'=$2`, policy.Policy.AccountID, concurrent.RequestID).Scan(&factCount); err != nil || factCount != 1 {
		t.Fatal("concurrent publication created multiple successful facts")
	}
	// The last write fails after the policy and immutable version inserts.
	// The real restricted API transaction must roll back all three, including
	// its successful decision, and permit only an exact fresh retry afterward.
	failing := create
	failing.RequestID, failing.DisplayName = "customer-policy-injected-failure", "Atomic policy"
	if _, err := database.Exec(ctx, `CREATE FUNCTION public.matrix_policy_outbox_fault() RETURNS trigger LANGUAGE plpgsql AS $body$
		BEGIN IF NEW.event_document->>'action'='iam.policy.created' AND NEW.event_document->>'requestId'='customer-policy-injected-failure'
		THEN RAISE EXCEPTION 'injected customer policy outbox failure'; END IF; RETURN NEW; END $body$;
		CREATE TRIGGER matrix_policy_outbox_fault BEFORE INSERT ON iam.audit_outbox FOR EACH ROW EXECUTE FUNCTION public.matrix_policy_outbox_fault()`); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := database.Exec(context.Background(), `DROP TRIGGER IF EXISTS matrix_policy_outbox_fault ON iam.audit_outbox; DROP FUNCTION IF EXISTS public.matrix_policy_outbox_fault()`); err != nil {
			t.Error("remove isolated policy fault")
		}
	}()
	post("/v1/policies", root, failing, http.StatusServiceUnavailable, nil)
	var partial bool
	if err := database.QueryRow(ctx, `SELECT
		EXISTS(SELECT 1 FROM iam.policies WHERE owner_tenant_id=$1 AND display_name=$2)
		OR EXISTS(SELECT 1 FROM iam.authorization_decisions WHERE tenant_id=$1 AND request_id=$3)
		OR EXISTS(SELECT 1 FROM iam.audit_outbox WHERE tenant_id=$1 AND event_document->>'requestId'=$3)`,
		policy.Policy.AccountID, failing.DisplayName, failing.RequestID).Scan(&partial); err != nil || partial {
		t.Fatalf("failed publication left partial authority: partial=%t err=%v", partial, err)
	}
	if _, err := database.Exec(ctx, `DROP TRIGGER matrix_policy_outbox_fault ON iam.audit_outbox; DROP FUNCTION public.matrix_policy_outbox_fault()`); err != nil {
		t.Fatal(err)
	}
	post("/v1/policies", root, failing, http.StatusCreated, nil)
	var otherIdentity iamv1.CurrentIdentity
	get("/v1/auth/me", other, http.StatusOK, &otherIdentity)
	mutation, err := pgx.ConnectConfig(ctx, database.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer mutation.Close(context.Background())
	tx, err := mutation.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	// Hold the same principal row needed by credential/status transitions.
	// A publisher already authenticated against the old snapshot must retry
	// after this revocation, not commit using its prior active identity.
	if _, err := tx.Exec(ctx, `UPDATE iam.principals SET status='DISABLED',resource_version=resource_version+1,
		updated_at=transaction_timestamp() WHERE tenant_id=$1 AND id=$2`, foreign.Policy.AccountID, otherIdentity.User.ID); err != nil {
		t.Fatal(err)
	}
	racing := create
	racing.RequestID, racing.DisplayName = "customer-policy-disabled-publisher", "Disabled publisher policy"
	racingBody := mustIAMJSON(t, racing)
	completed := make(chan *httptest.ResponseRecorder, 1)
	go func() { completed <- performIAMRequest(handler, http.MethodPost, "/v1/policies", other, racingBody) }()
	waitForLocalRecoveryLock(t, ctx, database, iamHTTPTestRole)
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case response := <-completed:
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("publication survived concurrent identity revocation: status=%d", response.Code)
		}
	case <-ctx.Done():
		t.Fatal("publication did not finish after identity revocation")
	}
	if err := database.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM iam.policies WHERE owner_tenant_id=$1 AND display_name=$2)
		OR EXISTS(SELECT 1 FROM iam.audit_outbox WHERE tenant_id=$1 AND event_document->>'requestId'=$3)`, foreign.Policy.AccountID, racing.DisplayName, racing.RequestID).Scan(&partial); err != nil || partial {
		t.Fatal("revoked publisher left a partial policy or fact")
	}
	if err := database.QueryRow(ctx, `SELECT event_document FROM iam.audit_outbox WHERE tenant_id=$1 AND event_document->>'action'='iam.policy.created' AND event_document#>>'{target,id}'=$2`, foreign.Policy.AccountID, foreign.Policy.ID).Scan(&raw); err != nil || json.Unmarshal(raw, &event) != nil {
		t.Fatal("read committed publication from disabled publisher")
	}
	post("/v1/audit-producer:resolve", iamProducerCredential, iamv1.ResolveAuditProducerRequest{Event: event}, http.StatusOK, nil)
}

func mustIAMJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func proveGroupInheritance(t *testing.T, ctx context.Context, handler http.Handler, database *pgx.Conn, operator string) {
	t.Helper()
	request := func(method, path, bearer string, body any, want int, result any) {
		t.Helper()
		var encoded []byte
		var err error
		if body != nil {
			encoded, err = json.Marshal(body)
		}
		if err != nil {
			t.Fatal(err)
		}
		response := performIAMRequest(handler, method, path, bearer, encoded)
		if response.Code != want {
			t.Fatalf("group %s %s: status=%d want=%d body=%s", method, path, response.Code, want, response.Body.String())
		}
		if response.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("group response is cacheable")
		}
		if result != nil {
			decoder := json.NewDecoder(response.Body)
			decoder.DisallowUnknownFields()
			if decoder.Decode(result) != nil {
				t.Fatal("invalid group response")
			}
		}
	}
	post := func(path, bearer string, body any, want int, result any) {
		t.Helper()
		request(http.MethodPost, path, bearer, body, want, result)
	}
	get := func(path, bearer string, want int, result any) {
		t.Helper()
		request(http.MethodGet, path, bearer, nil, want, result)
	}
	var actor iamv1.CurrentIdentity
	get("/v1/auth/me", operator, http.StatusOK, &actor)
	const otherAccount = "group-other-account"
	post("/v1/accounts", operator, map[string]any{"id": otherAccount, "displayName": "Group isolation", "rootLoginName": "group.other", "rootDisplayName": "Other owner", "initialPassword": initialDeveloperPassword, "requestId": "group-other-account-create"}, http.StatusCreated, nil)
	other := localRecoveryLogin(t, handler, "group.other", initialDeveloperPassword, true)
	other = localRecoveryChangePassword(t, handler, other, initialDeveloperPassword, changedDeveloperPassword)
	var member iamv1.User
	post("/v1/users", operator, map[string]any{"loginName": "group.member", "displayName": "Group member", "initialPassword": initialDeveloperPassword, "requestId": "group-member-user-create"}, http.StatusCreated, &member)
	bearer := localRecoveryLogin(t, handler, "group.member@"+string(member.AccountID), initialDeveloperPassword, true)
	bearer = localRecoveryChangePassword(t, handler, bearer, initialDeveloperPassword, changedDeveloperPassword)
	var group, foreign, replay iamv1.Group
	create := iamv1.CreateGroupRequest{Name: "Developers", Description: "Group permission test", RequestID: "group-create"}
	post("/v1/groups", operator, create, http.StatusCreated, &group)
	post("/v1/groups", operator, create, http.StatusCreated, &replay)
	if group != replay || iamv1.ValidateGroup(group) != nil || group.AccountID != member.AccountID {
		t.Fatal("group create replay or ownership differs")
	}
	post("/v1/groups", other, create, http.StatusCreated, &foreign)
	if foreign.AccountID == group.AccountID || foreign.ID == group.ID || foreign.Name != group.Name {
		t.Fatal("same-name groups are not isolated")
	}
	var foreignUser iamv1.User
	post("/v1/users", other, map[string]any{"loginName": "group.member", "displayName": "Other group member", "initialPassword": initialDeveloperPassword, "requestId": "foreign-group-user"}, http.StatusCreated, &foreignUser)
	var foreignMembership iamv1.GroupMembership
	post("/v1/groups/"+string(foreign.ID)+"/memberships", other,
		iamv1.CreateGroupMembershipRequest{UserID: foreignUser.ID, RequestID: "foreign-group-join"}, http.StatusOK, &foreignMembership)
	variant := create
	variant.Description = "Different intent"
	post("/v1/groups", operator, variant, http.StatusConflict, nil)
	variant = create
	variant.RequestID = "group-duplicate-name"
	post("/v1/groups", operator, variant, http.StatusConflict, nil)
	var directory iamv1.GroupList
	get("/v1/groups", operator, http.StatusOK, &directory)
	if iamv1.ValidateGroupList(directory) != nil || len(directory.Items) != 1 || directory.Items[0].Group != group {
		t.Fatal("group directory leaked or malformed")
	}
	get("/v1/groups/"+string(group.ID), other, http.StatusForbidden, nil)
	get("/v1/groups/"+string(foreign.ID), operator, http.StatusForbidden, nil)
	get("/v1/groups?accountId="+otherAccount, operator, http.StatusBadRequest, nil)
	get("/v1/groups", paasCredential, http.StatusUnauthorized, nil)
	get("/v1/groups", bearer, http.StatusForbidden, nil)
	path := "/v1/groups/" + string(group.ID)
	post(path+":update", operator, iamv1.UpdateGroupRequest{Name: "Invalid version", ResourceVersion: 0, RequestID: "group-zero-version"}, http.StatusUnprocessableEntity, nil)
	post(path+":update", operator, iamv1.UpdateGroupRequest{Name: "Overflow version", ResourceVersion: 9007199254740991, RequestID: "group-max-version"}, http.StatusConflict, nil)
	update := iamv1.UpdateGroupRequest{Name: "Operators", Description: "Renamed group", ResourceVersion: 1, RequestID: "group-rename"}
	post(path+":update", operator, update, http.StatusOK, &group)
	post(path+":update", operator, update, http.StatusOK, &replay)
	if group != replay || group.ResourceVersion != 2 {
		t.Fatal("group profile replay changed revision")
	}
	post("/v1/groups", operator, create, http.StatusConflict, nil)
	changedIntent := update
	changedIntent.ResourceVersion = group.ResourceVersion
	changedIntent.Name = "Reused command identity"
	post(path+":update", operator, changedIntent, http.StatusConflict, nil)
	update.RequestID = "group-stale-rename"
	update.Name = "Stale name"
	post(path+":update", operator, update, http.StatusConflict, nil)
	var membership, again iamv1.GroupMembership
	join := iamv1.CreateGroupMembershipRequest{UserID: member.ID, RequestID: "group-join"}
	post(path+"/memberships", operator, join, http.StatusOK, &membership)
	post(path+"/memberships", operator, join, http.StatusOK, &again)
	if membership != again || iamv1.ValidateGroupMembership(membership) != nil {
		t.Fatal("membership create replay changed identity")
	}
	for _, target := range []iamv1.PrincipalID{actor.User.ID, "service-paas", iamv1.PrincipalID(foreign.ID), "missing-user"} {
		post(path+"/memberships", operator, iamv1.CreateGroupMembershipRequest{UserID: target, RequestID: "group-invalid-" + string(target)}, http.StatusForbidden, nil)
	}
	// Restricted runtimes cannot write the table. Even a correctly shaped
	// migration-owner insert must not introduce a root or service relationship.
	for _, target := range []iamv1.PrincipalID{actor.User.ID, "service-paas"} {
		_, err := database.Exec(ctx, `INSERT INTO iam.group_memberships(tenant_id,id,group_id,user_id,created_by,resource_version,created_at,updated_at)
			VALUES($1,'forged-member-'||$2,$3,$2,$4,1,transaction_timestamp(),transaction_timestamp())`, member.AccountID, target, group.ID, actor.User.ID)
		var databaseError *pgconn.PgError
		if !errors.As(err, &databaseError) || databaseError.Code != "42501" {
			t.Fatal("membership persistence accepted a root or service as a User")
		}
	}
	post("/v1/groups/"+string(foreign.ID)+"/memberships", other, join, http.StatusForbidden, nil)
	post(path+"/memberships", other, join, http.StatusForbidden, nil)
	var members iamv1.GroupMembershipList
	get(path+"/memberships", operator, http.StatusOK, &members)
	if iamv1.ValidateGroupMembershipList(members) != nil || len(members.Items) != 1 || members.Items[0].Membership != membership {
		t.Fatal("group membership page differs")
	}
	// Raw resource IDs are not continuations, even within the same account.
	get("/v1/groups?after="+string(foreign.ID), operator, http.StatusBadRequest, nil)
	get(path+"/memberships?after="+string(foreignMembership.ID), operator, http.StatusBadRequest, nil)
	rls, err := database.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rls.Exec(ctx, `SET LOCAL ROLE matrix_iam_owner; SELECT set_config('matrix.iam_tenant_id',$1,true)`, member.AccountID); err != nil {
		t.Fatal(err)
	}
	var visibleGroup, hiddenGroup, visibleMember, hiddenMember bool
	if err := rls.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM iam.groups WHERE id=$1),
		EXISTS(SELECT 1 FROM iam.groups WHERE id=$2), EXISTS(SELECT 1 FROM iam.group_memberships WHERE id=$3),
		EXISTS(SELECT 1 FROM iam.group_memberships WHERE id=$4)`, group.ID, foreign.ID, membership.ID, foreignMembership.ID).
		Scan(&visibleGroup, &hiddenGroup, &visibleMember, &hiddenMember); err != nil || !visibleGroup || hiddenGroup || !visibleMember || hiddenMember {
		t.Fatal("forced group or membership RLS leaked a foreign authority")
	}
	if err := rls.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	var attachment iamv1.PolicyAttachment
	grant := iamv1.CreatePolicyAttachmentRequest{Target: iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetGroup, ID: string(group.ID)}, PolicyID: iamv1.SystemPolicyPaaSViewer, PolicyResourceVersion: 1, RequestID: "group-grant"}
	post("/v1/policy-attachments", operator, grant, http.StatusOK, &attachment)
	if iamv1.ValidatePolicyAttachment(attachment) != nil || attachment.Target != grant.Target {
		t.Fatal("invalid group attachment")
	}
	grant.RequestID = "group-platform-grant"
	grant.PolicyID = iamv1.SystemPolicyPlatformOperator
	post("/v1/policy-attachments", operator, grant, http.StatusForbidden, nil)
	var access iamv1.GroupAccess
	get(path, operator, http.StatusOK, &access)
	if iamv1.ValidateGroupAccess(access) != nil || len(access.PolicyAttachments) != 1 || access.PolicyAttachments[0] != attachment {
		t.Fatal("group direct attachment projection differs")
	}
	var identity iamv1.CurrentIdentity
	get("/v1/auth/me", bearer, http.StatusOK, &identity)
	if iamv1.ValidateCurrentIdentity(identity) != nil || len(identity.PolicySources) != 1 || identity.PolicySources[0].Kind != iamv1.PolicyGrantGroup || identity.PolicySources[0].Membership == nil || *identity.PolicySources[0].Membership != membership {
		t.Fatal("effective identity omitted group provenance")
	}
	authorize := func(want bool) iamv1.AuthorizationDecision {
		t.Helper()
		body, _ := json.Marshal(iamv1.AuthorizationRequest{Action: iamv1.ActionPaaSApplicationRead, Resource: iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "group-application"}, RequestID: "group-application-read", CorrelationID: "group-application-read"})
		response := performIAMRequestWithSubject(handler, body, paasCredential, bearer)
		var decision iamv1.AuthorizationDecision
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &decision) != nil || decision.Allowed != want {
			t.Fatalf("group permission allowed=%t want=%t status=%d", decision.Allowed, want, response.Code)
		}
		return decision
	}
	decision := authorize(true)
	var evidence []authority.PolicyAttachmentEvidence
	var encoded []byte
	if err := database.QueryRow(ctx, `SELECT policy_evidence FROM iam.authorization_decisions WHERE tenant_id=$1 AND id=$2`, member.AccountID, decision.ID).Scan(&encoded); err != nil || json.Unmarshal(encoded, &evidence) != nil || len(evidence) != 1 || evidence[0].MembershipID != membership.ID || evidence[0].MembershipResourceVersion != membership.ResourceVersion || evidence[0].AttachmentID != attachment.ID {
		t.Fatal("stored decision omitted exact inheritance evidence")
	}
	assertEvidenceRejected := func(expression, code string) {
		t.Helper()
		tx, err := database.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		if _, err = tx.Exec(ctx, `SET LOCAL ROLE matrix_iam_owner; SELECT set_config('matrix.iam_tenant_id',$1,true)`, member.AccountID); err != nil {
			t.Fatal(err)
		}
		_, err = tx.Exec(ctx, `SELECT iam.record_authorization($1,$2,document||jsonb_build_object('id','forged-group-decision','decidedAt',to_char(transaction_timestamp() AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')),'{}'::jsonb,`+expression+`) FROM iam.authorization_decisions WHERE tenant_id=$1 AND id=$3`, member.AccountID, member.ID, decision.ID)
		var databaseError *pgconn.PgError
		if !errors.As(err, &databaseError) || databaseError.Code != code {
			t.Fatalf("group evidence attack: %v want=%s", err, code)
		}
	}
	assertEvidenceRejected(`jsonb_set(policy_evidence,'{0,membershipId}','"wrong-membership"'::jsonb)`, "42501")
	assertEvidenceRejected(`jsonb_set(policy_evidence,'{0,membershipResourceVersion}','2'::jsonb)`, "42501")
	assertEvidenceRejected(`jsonb_build_array((policy_evidence->0)-'membershipId'-'membershipResourceVersion')`, "42501")
	assertEvidenceRejected(`jsonb_build_array((policy_evidence->0)-'membershipResourceVersion')`, "22023")
	removePath := path + "/memberships/" + string(membership.ID) + ":remove"
	remove := iamv1.RemoveGroupMembershipRequest{ResourceVersion: 2, RequestID: "group-remove"}
	post(removePath, operator, remove, http.StatusConflict, nil)
	authorize(true)
	remove.ResourceVersion = 1
	post(removePath, operator, remove, http.StatusOK, &again)
	var removed iamv1.GroupMembership
	post(removePath, operator, remove, http.StatusOK, &removed)
	if iamv1.ValidateGroupMembership(removed) != nil || removed.RemovedAt == nil || removed.ResourceVersion != 2 || !removed.RemovedAt.Equal(*again.RemovedAt) {
		t.Fatal("membership removal replay differs")
	}
	authorize(false)
	assertEvidenceRejected(`policy_evidence`, "42501")
	get("/v1/auth/me", bearer, http.StatusOK, &identity)
	if len(identity.PolicySources) != 0 {
		t.Fatal("removed membership remains an authority source")
	}
	post(path+"/memberships", operator, join, http.StatusConflict, nil)
	join.RequestID = "group-rejoin"
	post(path+"/memberships", operator, join, http.StatusOK, &again)
	if again.ID == membership.ID {
		t.Fatal("rejoin revived removed membership")
	}
	authorize(true)
	var direct iamv1.PolicyAttachment
	grant = iamv1.CreatePolicyAttachmentRequest{Target: iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetUser, ID: string(member.ID)}, PolicyID: iamv1.SystemPolicyPaaSViewer, PolicyResourceVersion: 1, RequestID: "group-member-direct-grant"}
	post("/v1/policy-attachments", operator, grant, http.StatusOK, &direct)
	denyDocument := iamv1.PolicyDocument{LanguageVersion: "1", Scope: iamv1.AuthorityScopeTenant,
		Statements: []iamv1.PolicyStatement{{SID: "group-deny", Effect: iamv1.PolicyDeny, Actions: []iamv1.Action{iamv1.ActionPaaSApplicationRead},
			Resources: []iamv1.PolicyResourceSelector{{Kind: iamv1.ResourceApplication, Match: iamv1.PolicyResourceAnyInAuthority}}}}}
	canonical, digest, err := iamv1.CanonicalizePolicyDocument(denyDocument)
	if err != nil {
		t.Fatal(err)
	}
	// Customer-policy publication belongs to IAM/005. This valid, owner-created
	// fixture proves the current evaluator and public attachment path only.
	if _, err := database.Exec(ctx, `BEGIN;
		INSERT INTO iam.policies(id,management,owner_tenant_id,display_name,authority_scope,status,default_version_id,resource_version,created_at,updated_at)
		VALUES('customer.group-deny','CUSTOMER',$1,'Group deny','TENANT','ACTIVE','v1',1,transaction_timestamp(),transaction_timestamp());
		INSERT INTO iam.policy_versions(policy_id,id,authority_scope,document,canonical_document,content_digest,created_at)
		VALUES('customer.group-deny','v1','TENANT',$2::jsonb,$2,$3,transaction_timestamp()); COMMIT;`, member.AccountID, canonical, digest); err != nil {
		t.Fatal(err)
	}
	var deniedAttachment iamv1.PolicyAttachment
	post("/v1/policy-attachments", operator, iamv1.CreatePolicyAttachmentRequest{Target: iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetGroup, ID: string(group.ID)}, PolicyID: "customer.group-deny", PolicyResourceVersion: 1, RequestID: "group-deny-attach"}, http.StatusOK, &deniedAttachment)
	authorize(false)
	post("/v1/policy-attachments/"+string(deniedAttachment.ID)+":revoke", operator, iamv1.RevokePolicyAttachmentRequest{ResourceVersion: 1, RequestID: "group-deny-revoke"}, http.StatusOK, nil)
	authorize(true)
	post("/v1/policy-attachments/"+string(attachment.ID)+":revoke", operator, iamv1.RevokePolicyAttachmentRequest{ResourceVersion: 1, RequestID: "group-revoke"}, http.StatusOK, nil)
	authorize(true)
	post("/v1/policy-attachments/"+string(direct.ID)+":revoke", operator, iamv1.RevokePolicyAttachmentRequest{ResourceVersion: 1, RequestID: "group-direct-revoke"}, http.StatusOK, nil)
	authorize(false)
	grant.Target = iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetGroup, ID: string(group.ID)}
	grant.RequestID = "group-regrant"
	post("/v1/policy-attachments", operator, grant, http.StatusOK, &attachment)
	authorize(true)
	var deletion, deletionReplay iamv1.GroupDeletion
	deleteRequest := iamv1.DeleteGroupRequest{ResourceVersion: group.ResourceVersion, RequestID: "group-delete"}
	post(path+":delete", operator, deleteRequest, http.StatusOK, &deletion)
	post(path+":delete", operator, deleteRequest, http.StatusOK, &deletionReplay)
	if iamv1.ValidateGroupDeletion(deletion) != nil || deletion != deletionReplay || deletion.RemovedMemberships != 1 || deletion.RevokedPolicyAttachments != 1 {
		t.Fatal("group deletion was partial or replay changed its result")
	}
	authorize(false)
	get(path, operator, http.StatusForbidden, nil)
	get("/v1/groups/"+string(foreign.ID), other, http.StatusOK, &access)
	post(path+"/memberships", operator, join, http.StatusForbidden, nil)
	post("/v1/policy-attachments", operator, grant, http.StatusForbidden, nil)
	create.Name = group.Name
	create.RequestID = "group-replace-name"
	post("/v1/groups", operator, create, http.StatusCreated, &replay)
	if replay.ID == group.ID {
		t.Fatal("reusing name revived group identity")
	}
	// Contenders use the same real HTTP/serializable transaction path. Inspect
	// terminal relations and facts, not which goroutine happened to run first.
	race := func(leftBearer, leftPath string, left any, rightBearer, rightPath string, right any) [2]*httptest.ResponseRecorder {
		t.Helper()
		var results [2]*httptest.ResponseRecorder
		ready := make(chan struct{})
		finished := make(chan int, 2)
		for index, command := range []struct {
			bearer string
			path   string
			body   any
		}{{leftBearer, leftPath, left}, {rightBearer, rightPath, right}} {
			encoded, err := json.Marshal(command.body)
			if err != nil {
				t.Fatal(err)
			}
			go func(index int, bearer, path string, body []byte) {
				<-ready
				results[index] = performIAMRequest(handler, http.MethodPost, path, bearer, body)
				finished <- index
			}(index, command.bearer, command.path, encoded)
		}
		close(ready)
		<-finished
		<-finished
		return results
	}
	concurrentPath := "/v1/groups/" + string(replay.ID)
	concurrentJoin := iamv1.CreateGroupMembershipRequest{UserID: member.ID, RequestID: "group-concurrent-join"}
	joined := race(operator, concurrentPath+"/memberships", concurrentJoin, operator, concurrentPath+"/memberships", concurrentJoin)
	var joins [2]iamv1.GroupMembership
	for index, response := range joined {
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &joins[index]) != nil || iamv1.ValidateGroupMembership(joins[index]) != nil {
			t.Fatalf("concurrent join status=%d: %s", response.Code, response.Body.String())
		}
	}
	if joins[0] != joins[1] {
		t.Fatal("concurrent equal joins created separate active relationships")
	}
	concurrentRemove := concurrentPath + "/memberships/" + string(joins[0].ID) + ":remove"
	removals := race(operator, concurrentRemove, iamv1.RemoveGroupMembershipRequest{ResourceVersion: 1, RequestID: "group-concurrent-remove-a"}, operator, concurrentRemove, iamv1.RemoveGroupMembershipRequest{ResourceVersion: 1, RequestID: "group-concurrent-remove-b"})
	if !((removals[0].Code == http.StatusOK && removals[1].Code == http.StatusConflict) || (removals[1].Code == http.StatusOK && removals[0].Code == http.StatusConflict)) {
		t.Fatalf("concurrent removals: %d/%d", removals[0].Code, removals[1].Code)
	}
	for index, command := range []struct {
		suffix string
		body   any
	}{
		{"/memberships", iamv1.CreateGroupMembershipRequest{UserID: member.ID, RequestID: "group-delete-race-join"}},
		{"attachment", iamv1.CreatePolicyAttachmentRequest{PolicyID: iamv1.SystemPolicyPaaSViewer, PolicyResourceVersion: 1, RequestID: "group-delete-race-attach"}},
	} {
		var competing iamv1.Group
		post("/v1/groups", operator, iamv1.CreateGroupRequest{Name: fmt.Sprintf("Race %d", index), RequestID: fmt.Sprintf("group-race-create-%d", index)}, http.StatusCreated, &competing)
		competingPath := "/v1/groups/" + string(competing.ID)
		mutationPath := competingPath + command.suffix
		if command.suffix == "attachment" {
			mutationPath = "/v1/policy-attachments"
			body := command.body.(iamv1.CreatePolicyAttachmentRequest)
			body.Target = iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetGroup, ID: string(competing.ID)}
			command.body = body
		}
		responses := race(operator, competingPath+":delete", iamv1.DeleteGroupRequest{ResourceVersion: 1, RequestID: fmt.Sprintf("group-race-delete-%d", index)}, operator, mutationPath, command.body)
		if responses[0].Code != http.StatusOK || (responses[1].Code != http.StatusOK && responses[1].Code != http.StatusForbidden) {
			t.Fatalf("group delete race %d: %d/%d %s %s", index, responses[0].Code, responses[1].Code, responses[0].Body.String(), responses[1].Body.String())
		}
		var activeMembers, activeAttachments int
		if err := database.QueryRow(ctx, `SELECT (SELECT count(*) FROM iam.group_memberships WHERE tenant_id=$1 AND group_id=$2 AND removed_at IS NULL),(SELECT count(*) FROM iam.policy_attachments WHERE tenant_id=$1 AND target_kind='GROUP' AND target_id=$2 AND revoked_at IS NULL)`, member.AccountID, competing.ID).Scan(&activeMembers, &activeAttachments); err != nil || activeMembers != 0 || activeAttachments != 0 {
			t.Fatal("concurrent group deletion retained active authority")
		}
	}
	var delegate iamv1.User
	post("/v1/users", operator, map[string]any{"loginName": "group.delegate", "displayName": "Group delegate", "initialPassword": initialDeveloperPassword, "requestId": "group-delegate-user"}, http.StatusCreated, &delegate)
	delegateBearer := localRecoveryLogin(t, handler, "group.delegate@"+string(delegate.AccountID), initialDeveloperPassword, true)
	delegateBearer = localRecoveryChangePassword(t, handler, delegateBearer, initialDeveloperPassword, changedDeveloperPassword)
	var delegation iamv1.PolicyAttachment
	post("/v1/policy-attachments", operator, iamv1.CreatePolicyAttachmentRequest{Target: iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetUser, ID: string(delegate.ID)}, PolicyID: iamv1.SystemPolicyAccountAdministrator, PolicyResourceVersion: 1, RequestID: "group-delegate-grant"}, http.StatusOK, &delegation)
	for _, target := range []iamv1.PrincipalID{delegate.ID, actor.User.ID} {
		post(concurrentPath+"/memberships", delegateBearer, iamv1.CreateGroupMembershipRequest{UserID: target, RequestID: "group-delegate-self-or-root-" + string(target)}, http.StatusForbidden, nil)
	}
	delegatedCreate := iamv1.CreateGroupRequest{Name: "Delegated create", RequestID: "group-delegated-create"}
	delegatedRace := race(delegateBearer, "/v1/groups", delegatedCreate, operator, "/v1/policy-attachments/"+string(delegation.ID)+":revoke",
		iamv1.RevokePolicyAttachmentRequest{ResourceVersion: delegation.ResourceVersion, RequestID: "group-delegate-revoke"})
	if delegatedRace[1].Code != http.StatusOK || (delegatedRace[0].Code != http.StatusCreated && delegatedRace[0].Code != http.StatusForbidden) {
		t.Fatalf("actor revocation vs group command: %d/%d", delegatedRace[0].Code, delegatedRace[1].Code)
	}
	delegatedCreate.RequestID, delegatedCreate.Name = "group-delegated-after-revoke", "Denied after revoke"
	post("/v1/groups", delegateBearer, delegatedCreate, http.StatusForbidden, nil)
	var groupsCreated, successes int
	if err := database.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM iam.groups WHERE tenant_id=$1 AND name IN ('Delegated create','Denied after revoke')),
		(SELECT count(*) FROM iam.audit_outbox WHERE tenant_id=$1 AND event_document->>'action'='iam.group.created'
		 AND event_document#>>'{actor,id}'=$2)`, member.AccountID, delegate.ID).Scan(&groupsCreated, &successes); err != nil || groupsCreated != successes ||
		(groupsCreated == 1) != (delegatedRace[0].Code == http.StatusCreated) || groupsCreated > 1 {
		t.Fatal("actor revocation left partial group state or a success fact without its effect")
	}
	var capacityUser iamv1.User
	post("/v1/users", operator, map[string]any{"loginName": "group.capacity", "displayName": "Capacity member", "initialPassword": initialDeveloperPassword, "requestId": "group-capacity-user-create"}, http.StatusCreated, &capacityUser)
	capacityBearer := localRecoveryLogin(t, handler, "group.capacity@"+string(capacityUser.AccountID), initialDeveloperPassword, true)
	capacityBearer = localRecoveryChangePassword(t, handler, capacityBearer, initialDeveloperPassword, changedDeveloperPassword)
	var lastGroup iamv1.Group
	for index := 0; index < 101; index++ {
		post("/v1/groups", operator, iamv1.CreateGroupRequest{Name: fmt.Sprintf("Capacity %03d", index), RequestID: fmt.Sprintf("capacity-group-%03d", index)}, http.StatusCreated, &lastGroup)
		if index < 100 {
			post("/v1/groups/"+string(lastGroup.ID)+"/memberships", operator, iamv1.CreateGroupMembershipRequest{UserID: capacityUser.ID, RequestID: fmt.Sprintf("capacity-member-%03d", index)}, http.StatusOK, nil)
		}
	}
	var firstPage, secondPage iamv1.GroupList
	get("/v1/groups", operator, http.StatusOK, &firstPage)
	get("/v1/groups?after="+firstPage.NextAfter, operator, http.StatusOK, &secondPage)
	if iamv1.ValidateGroupList(firstPage) != nil || iamv1.ValidateGroupList(secondPage) != nil || len(firstPage.Items) != 100 || firstPage.NextAfter == "" || len(secondPage.Items) == 0 || secondPage.NextAfter != "" {
		t.Fatal("group directory did not page past one hundred")
	}
	for _, item := range secondPage.Items {
		if item.Group.ID <= firstPage.Items[99].Group.ID || item.Group.AccountID != member.AccountID {
			t.Fatal("group cursor repeated or leaked another account")
		}
	}
	for _, route := range []string{"/v1/users", "/v1/groups/" + string(lastGroup.ID) + "/memberships", "/v1/accounts"} {
		get(route+"?after="+firstPage.NextAfter, operator, http.StatusUnprocessableEntity, nil)
	}
	get("/v1/groups?after="+firstPage.NextAfter, other, http.StatusUnprocessableEntity, nil)
	anotherSession := localRecoveryLogin(t, handler, "admin", changedAdminPassword, false)
	get("/v1/groups?after="+firstPage.NextAfter, anotherSession, http.StatusUnprocessableEntity, nil)
	encodedCursor, err := base64.RawURLEncoding.DecodeString(firstPage.NextAfter[4:])
	if err != nil {
		t.Fatal(err)
	}
	encodedCursor[len(encodedCursor)-1] ^= 1
	get("/v1/groups?after=ic1."+base64.RawURLEncoding.EncodeToString(encodedCursor), operator, http.StatusUnprocessableEntity, nil)
	// A removed source invalidates continuation even while an independent
	// administrator attachment still allows a fresh directory request.
	post("/v1/policy-attachments", operator, iamv1.CreatePolicyAttachmentRequest{Target: iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetUser, ID: string(delegate.ID)}, PolicyID: iamv1.SystemPolicyAccountAdministrator, PolicyResourceVersion: 1, RequestID: "cursor-delegate-admin"}, http.StatusOK, nil)
	var extraSource iamv1.PolicyAttachment
	post("/v1/policy-attachments", operator, iamv1.CreatePolicyAttachmentRequest{Target: iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetUser, ID: string(delegate.ID)}, PolicyID: iamv1.SystemPolicyAuditReader, PolicyResourceVersion: 1, RequestID: "cursor-delegate-extra"}, http.StatusOK, &extraSource)
	var delegatedPage iamv1.GroupList
	get("/v1/groups", delegateBearer, http.StatusOK, &delegatedPage)
	post("/v1/policy-attachments/"+string(extraSource.ID)+":revoke", operator, iamv1.RevokePolicyAttachmentRequest{ResourceVersion: extraSource.ResourceVersion, RequestID: "cursor-delegate-extra-revoke"}, http.StatusOK, nil)
	get("/v1/groups?after="+delegatedPage.NextAfter, delegateBearer, http.StatusUnprocessableEntity, nil)
	get("/v1/groups", delegateBearer, http.StatusOK, nil)
	// Regrant creates a new relationship; returning to the same policy set
	// cannot revive the previous signed authority lineage.
	post("/v1/policy-attachments", operator, iamv1.CreatePolicyAttachmentRequest{Target: iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetUser, ID: string(delegate.ID)}, PolicyID: iamv1.SystemPolicyAuditReader, PolicyResourceVersion: 1, RequestID: "cursor-delegate-extra-regrant"}, http.StatusOK, nil)
	get("/v1/groups?after="+delegatedPage.NextAfter, delegateBearer, http.StatusUnprocessableEntity, nil)
	var pagedGroup iamv1.Group
	post("/v1/groups", operator, iamv1.CreateGroupRequest{Name: "Paged members", RequestID: "cursor-many-members-group"}, http.StatusCreated, &pagedGroup)
	memberPath := "/v1/groups/" + string(pagedGroup.ID) + "/memberships"
	for index := 0; index < 101; index++ {
		var pageUser iamv1.User
		post("/v1/users", operator, map[string]any{"loginName": fmt.Sprintf("cursor.member.%03d", index), "displayName": "Cursor member", "initialPassword": initialDeveloperPassword, "requestId": fmt.Sprintf("cursor-many-user-%03d", index)}, http.StatusCreated, &pageUser)
		post(memberPath, operator, iamv1.CreateGroupMembershipRequest{UserID: pageUser.ID, RequestID: fmt.Sprintf("cursor-many-member-%03d", index)}, http.StatusOK, nil)
	}
	var memberFirst, memberSecond iamv1.GroupMembershipList
	get(memberPath, operator, http.StatusOK, &memberFirst)
	get(memberPath+"?after="+memberFirst.NextAfter, operator, http.StatusOK, &memberSecond)
	if iamv1.ValidateGroupMembershipList(memberFirst) != nil || iamv1.ValidateGroupMembershipList(memberSecond) != nil || len(memberFirst.Items) != 100 || len(memberSecond.Items) != 1 || memberSecond.NextAfter != "" || memberSecond.Items[0].Membership.ID <= memberFirst.Items[99].Membership.ID {
		t.Fatal("membership continuation did not yield exactly 100+1 distinct live relations")
	}
	get("/v1/groups/"+string(lastGroup.ID)+"/memberships?after="+memberFirst.NextAfter, operator, http.StatusUnprocessableEntity, nil)
	get("/v1/groups?after="+memberFirst.NextAfter, operator, http.StatusUnprocessableEntity, nil)
	get(memberPath+"?after="+memberFirst.NextAfter, anotherSession, http.StatusUnprocessableEntity, nil)
	var decisionsBefore, outboxBefore, decisionsAfter, outboxAfter int
	counts := func() (int, int) {
		t.Helper()
		var decisions, facts int
		if err := database.QueryRow(ctx, `SELECT (SELECT count(*) FROM iam.authorization_decisions),(SELECT count(*) FROM iam.audit_outbox)`).Scan(&decisions, &facts); err != nil {
			t.Fatal(err)
		}
		return decisions, facts
	}
	decisionsBefore, outboxBefore = counts()
	post("/v1/groups/"+string(lastGroup.ID)+"/memberships", operator, iamv1.CreateGroupMembershipRequest{UserID: capacityUser.ID, RequestID: "capacity-member-overflow"}, http.StatusServiceUnavailable, nil)
	decisionsAfter, outboxAfter = counts()
	if decisionsAfter != decisionsBefore || outboxAfter != outboxBefore {
		t.Fatal("membership overflow committed partial authority or audit")
	}
	// Capacity fixtures use valid owner writes to reach the evaluator bound.
	// Every attachment still traverses the real target/scope/uniqueness guards.
	if _, err := database.Exec(ctx, `INSERT INTO iam.policy_attachments(tenant_id,id,target_kind,target_id,policy_id,resource_version,created_at,updated_at)
		SELECT $1,'capacity-'||policy.suffix||'-'||member.id,'GROUP',member.group_id,policy.id,1,transaction_timestamp(),transaction_timestamp()
		FROM iam.group_memberships AS member CROSS JOIN (VALUES('viewer','system.paas-viewer'),('developer','system.paas-developer')) AS policy(suffix,id)
		WHERE member.tenant_id=$1 AND member.user_id=$2 AND member.removed_at IS NULL`, member.AccountID, capacityUser.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(ctx, `INSERT INTO iam.policy_attachments(tenant_id,id,target_kind,target_id,policy_id,resource_version,created_at,updated_at)
		SELECT $1,'capacity-audit-'||member.id,'GROUP',member.group_id,'system.audit-reader',1,transaction_timestamp(),transaction_timestamp()
		FROM iam.group_memberships AS member WHERE member.tenant_id=$1 AND member.user_id=$2 AND member.removed_at IS NULL ORDER BY member.id LIMIT 56`, member.AccountID, capacityUser.ID); err != nil {
		t.Fatal(err)
	}
	var capacityIdentity iamv1.CurrentIdentity
	get("/v1/auth/me", capacityBearer, http.StatusOK, &capacityIdentity)
	if iamv1.ValidateCurrentIdentity(capacityIdentity) != nil || len(capacityIdentity.PolicySources) != 256 {
		t.Fatal("inherited authority truncated before its budget")
	}
	if _, err := database.Exec(ctx, `INSERT INTO iam.policy_attachments(tenant_id,id,target_kind,target_id,policy_id,resource_version,created_at,updated_at)
		SELECT $1,'capacity-audit-'||member.id,'GROUP',member.group_id,'system.audit-reader',1,transaction_timestamp(),transaction_timestamp()
		FROM iam.group_memberships AS member WHERE member.tenant_id=$1 AND member.user_id=$2 AND member.removed_at IS NULL ORDER BY member.id OFFSET 56 LIMIT 1`, member.AccountID, capacityUser.ID); err != nil {
		t.Fatal(err)
	}
	decisionsBefore, outboxBefore = counts()
	get("/v1/auth/me", capacityBearer, http.StatusServiceUnavailable, nil)
	body, _ := json.Marshal(iamv1.AuthorizationRequest{Action: iamv1.ActionPaaSApplicationRead, Resource: iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "capacity-app"}, RequestID: "capacity-overflow-decide", CorrelationID: "capacity-overflow-decide"})
	if response := performIAMRequestWithSubject(handler, body, paasCredential, capacityBearer); response.Code != http.StatusServiceUnavailable {
		t.Fatal("authority overflow was evaluated after truncating sources")
	}
	decisionsAfter, outboxAfter = counts()
	if decisionsAfter != decisionsBefore || outboxAfter != outboxBefore {
		t.Fatal("authority overflow committed a partial decision")
	}
	post("/v1/users/"+string(capacityUser.ID)+":set-status", operator, map[string]any{"status": "DISABLED", "resourceVersion": capacityIdentity.User.ResourceVersion, "requestId": "capacity-user-disable"}, http.StatusOK, &capacityUser)
	post("/v1/groups/"+string(lastGroup.ID)+"/memberships", operator, iamv1.CreateGroupMembershipRequest{UserID: capacityUser.ID, RequestID: "group-disabled-user-join"}, http.StatusForbidden, nil)
	var userDeletion iamv1.UserDeletion
	post("/v1/users/"+string(capacityUser.ID)+":delete", operator, iamv1.DeleteUserRequest{ResourceVersion: capacityUser.ResourceVersion, RequestID: "capacity-user-delete"}, http.StatusOK, &userDeletion)
	post("/v1/groups/"+string(lastGroup.ID)+"/memberships", operator, iamv1.CreateGroupMembershipRequest{UserID: capacityUser.ID, RequestID: "group-deleted-user-join"}, http.StatusForbidden, nil)
	var activeRelationships int
	if err := database.QueryRow(ctx, `SELECT count(*) FROM iam.group_memberships WHERE tenant_id=$1 AND user_id=$2 AND removed_at IS NULL`, member.AccountID, capacityUser.ID).Scan(&activeRelationships); err != nil || activeRelationships != 0 {
		t.Fatal("deleted user retained group authority")
	}
	get("/v1/groups/"+string(lastGroup.ID), operator, http.StatusOK, &access)
	// Compare real retained authority and historical evidence, not SQL text.
	// HTTP requests below then prove the preserved terminal/live semantics.
	retained := func() []byte {
		t.Helper()
		var state []byte
		if err := database.QueryRow(ctx, `SELECT jsonb_build_object(
			'groups',(SELECT jsonb_agg(to_jsonb(g) ORDER BY tenant_id,id) FROM iam.groups g),
			'memberships',(SELECT jsonb_agg(to_jsonb(m) ORDER BY tenant_id,id) FROM iam.group_memberships m),
			'attachments',(SELECT jsonb_agg(to_jsonb(a) ORDER BY tenant_id,id) FROM iam.policy_attachments a),
			'decisions',(SELECT jsonb_agg(to_jsonb(d) ORDER BY tenant_id,id) FROM iam.authorization_decisions d),
			'outbox',(SELECT jsonb_agg(to_jsonb(e) ORDER BY tenant_id,event_id) FROM iam.audit_outbox e))`).Scan(&state); err != nil {
			t.Fatal("read populated group authority and history")
		}
		return state
	}
	beforeReplay := retained()
	for range 2 {
		applyIAMSchema(t, ctx, database)
		if !bytes.Equal(beforeReplay, retained()) {
			t.Fatal("current-schema replay changed group authority or historical evidence")
		}
	}
	authorize(false)
	get(path, operator, http.StatusForbidden, nil)
	get("/v1/auth/me", capacityBearer, http.StatusUnauthorized, nil)
	get("/v1/groups/"+string(foreign.ID), other, http.StatusOK, &access)
	if access.Group != foreign {
		t.Fatal("current-schema replay changed the independent live group")
	}
	post(path+":delete", operator, deleteRequest, http.StatusOK, &deletionReplay)
	if deletionReplay != deletion {
		t.Fatal("current-schema replay changed the completed deletion receipt")
	}
	var createdFacts, removedFacts, deletedFacts int
	if err := database.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM iam.audit_outbox WHERE tenant_id=$1 AND event_document->>'action'='iam.group.created' AND event_document#>>'{target,id}'=$2),
		(SELECT count(*) FROM iam.audit_outbox WHERE tenant_id=$1 AND event_document->>'action'='iam.group-membership.removed' AND event_document#>>'{target,id}'=$3),
		(SELECT count(*) FROM iam.audit_outbox WHERE tenant_id=$1 AND event_document->>'action'='iam.group.deleted' AND event_document#>>'{target,id}'=$2)`, member.AccountID, group.ID, membership.ID).Scan(&createdFacts, &removedFacts, &deletedFacts); err != nil || createdFacts != 1 || removedFacts != 1 || deletedFacts != 1 {
		t.Fatal("idempotent group commands duplicated success facts")
	}
}

func provePolicyDirectories(t *testing.T, ctx context.Context, handler http.Handler, database *pgx.Conn, operator string) {
	t.Helper()
	post := func(path, bearer string, body any, want int) *httptest.ResponseRecorder {
		t.Helper()
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		response := performIAMRequest(handler, http.MethodPost, path, bearer, encoded)
		if response.Code != want {
			t.Fatalf("directory setup %s status=%d want=%d: %s", path, response.Code, want, response.Body.String())
		}
		return response
	}
	read := func(path, bearer string, want int) iamv1.PolicyList {
		t.Helper()
		response := performIAMRequest(handler, http.MethodGet, path, bearer, nil)
		if response.Code != want {
			t.Fatalf("directory %s status=%d want=%d: %s", path, response.Code, want, response.Body.String())
		}
		var result iamv1.PolicyList
		if want == http.StatusOK {
			decoder := json.NewDecoder(response.Body)
			decoder.DisallowUnknownFields()
			if decoder.Decode(&result) != nil || iamv1.ValidatePolicyList(result) != nil {
				t.Fatal("directory exposes invalid metadata or additional fields")
			}
		}
		return result
	}
	home := read("/v1/policies", operator, http.StatusOK)
	platform := read("/v1/platform-policies", operator, http.StatusOK)
	if home.Scope != iamv1.AuthorityScopeTenant || platform.Scope != iamv1.AuthorityScopeInstallation || platform.AccountID != home.AccountID || platform.InstallationID != iamHTTPBootstrap(t).InstallationID {
		t.Fatal("directory scope was not derived from authoritative account and installation")
	}
	for _, secret := range []string{iamProducerCredential, paasCredential, verifierCredential} {
		read("/v1/policies", secret, http.StatusUnauthorized)
		read("/v1/platform-policies", secret, http.StatusUnauthorized)
	}
	for _, path := range []string{"/v1/policies?accountId=other", "/v1/policies?scope=INSTALLATION", "/v1/platform-policies?installationId=other", "/v1/policies?after=other"} {
		read(path, operator, http.StatusBadRequest)
	}
	const otherAccount = "organization-policy-catalog"
	post("/v1/accounts", operator, map[string]any{"id": otherAccount, "displayName": "Directory isolation", "rootLoginName": "catalog.primary", "rootDisplayName": "Catalog owner", "initialPassword": initialDeveloperPassword, "requestId": "catalog-account-create"}, http.StatusCreated)
	other := localRecoveryLogin(t, handler, "catalog.primary", initialDeveloperPassword, true)
	other = localRecoveryChangePassword(t, handler, other, initialDeveloperPassword, changedDeveloperPassword)
	if got := read("/v1/policies", other, http.StatusOK); got.AccountID != otherAccount {
		t.Fatal("foreign primary used home account directory")
	}
	read("/v1/platform-policies", other, http.StatusForbidden)
	created := post("/v1/users", operator, map[string]any{"loginName": "catalog.reader", "displayName": "Directory reader", "initialPassword": initialDeveloperPassword, "requestId": "catalog-reader-create"}, http.StatusCreated)
	var member iamv1.User
	if json.Unmarshal(created.Body.Bytes(), &member) != nil || iamv1.ValidateUser(member) != nil {
		t.Fatal("invalid catalog member")
	}
	bearer := localRecoveryLogin(t, handler, member.LoginName+"@"+string(member.AccountID), initialDeveloperPassword, true)
	bearer = localRecoveryChangePassword(t, handler, bearer, initialDeveloperPassword, changedDeveloperPassword)
	read("/v1/policies", bearer, http.StatusForbidden)
	read("/v1/platform-policies", bearer, http.StatusForbidden)
	// Fixture publication creates arbitrary customer IDs with identical display
	// names. Runtime authorization must not depend on a predefined role name.
	document := iamv1.PolicyDocument{LanguageVersion: iamv1.PolicyLanguageVersion, Scope: iamv1.AuthorityScopeTenant,
		Statements: []iamv1.PolicyStatement{{SID: "catalog", Effect: iamv1.PolicyAllow, Actions: []iamv1.Action{iamv1.ActionIAMPolicyList},
			Resources: []iamv1.PolicyResourceSelector{{Kind: iamv1.ResourceAccount, Match: iamv1.PolicyResourceAnyInAuthority}}}}}
	canonical, digest, err := iamv1.CanonicalizePolicyDocument(document)
	if err != nil {
		t.Fatal(err)
	}
	for _, fixture := range []struct {
		id      string
		account iamv1.AccountID
	}{{"customer.catalog-a", home.AccountID}, {"customer.catalog-b", otherAccount}} {
		if _, err := database.Exec(ctx, `BEGIN;
			INSERT INTO iam.policies(id,management,owner_tenant_id,display_name,authority_scope,status,default_version_id,resource_version,created_at,updated_at)
			VALUES($1,'CUSTOMER',$2,'Same display name','TENANT','ACTIVE','v1',1,transaction_timestamp(),transaction_timestamp());
			INSERT INTO iam.policy_versions(policy_id,id,authority_scope,document,canonical_document,content_digest,created_at)
			VALUES($1,'v1','TENANT',$3::jsonb,$3,$4,transaction_timestamp()); COMMIT;`, fixture.id, fixture.account, canonical, digest); err != nil {
			t.Fatal(err)
		}
	}
	find := func(list iamv1.PolicyList, id iamv1.PolicyID) *iamv1.Policy {
		t.Helper()
		for i := range list.Items {
			if list.Items[i].ID == id {
				return &list.Items[i]
			}
		}
		return nil
	}
	for _, fixture := range []struct {
		bearer          string
		present, absent iamv1.PolicyID
	}{{operator, "customer.catalog-a", "customer.catalog-b"}, {other, "customer.catalog-b", "customer.catalog-a"}} {
		list := read("/v1/policies", fixture.bearer, http.StatusOK)
		if find(list, fixture.present) == nil || find(list, fixture.absent) != nil {
			t.Fatal("customer metadata crossed account boundary")
		}
	}
	request := iamv1.CreatePolicyAttachmentRequest{Target: iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetUser, ID: string(member.ID)}, PolicyID: "customer.catalog-a", PolicyResourceVersion: 1, RequestID: "catalog-reader-grant"}
	post("/v1/policy-attachments", operator, request, http.StatusOK)
	if got := read("/v1/policies", bearer, http.StatusOK); find(got, request.PolicyID) == nil {
		t.Fatal("list-only policy did not permit its actual directory")
	}
	request.PolicyID, request.RequestID = iamv1.SystemPolicyPaaSViewer, "catalog-reader-escalation"
	post("/v1/policy-attachments", bearer, request, http.StatusForbidden)
	read("/v1/platform-policies", bearer, http.StatusForbidden)
	// A separately granted platform attachment is not tenant directory access.
	platformCreated := post("/v1/users", operator, map[string]any{"loginName": "catalog.platform", "displayName": "Platform directory", "initialPassword": initialDeveloperPassword, "requestId": "catalog-platform-create"}, http.StatusCreated)
	var platformMember iamv1.User
	if json.Unmarshal(platformCreated.Body.Bytes(), &platformMember) != nil || iamv1.ValidateUser(platformMember) != nil {
		t.Fatal("invalid platform catalog member")
	}
	platformBearer := localRecoveryLogin(t, handler, platformMember.LoginName+"@"+string(platformMember.AccountID), initialDeveloperPassword, true)
	platformBearer = localRecoveryChangePassword(t, handler, platformBearer, initialDeveloperPassword, changedDeveloperPassword)
	request.Target.ID, request.PolicyID, request.RequestID = string(platformMember.ID), iamv1.SystemPolicyPlatformOperator, "catalog-platform-grant"
	platformGrant := post("/v1/policy-attachments", operator, request, http.StatusOK)
	var platformAttachment iamv1.PolicyAttachment
	if json.Unmarshal(platformGrant.Body.Bytes(), &platformAttachment) != nil || iamv1.ValidatePolicyAttachment(platformAttachment) != nil {
		t.Fatal("invalid platform directory attachment")
	}
	read("/v1/platform-policies", platformBearer, http.StatusOK)
	read("/v1/policies", platformBearer, http.StatusForbidden)
	post("/v1/policy-attachments/"+string(platformAttachment.ID)+":revoke", operator,
		iamv1.RevokePolicyAttachmentRequest{ResourceVersion: platformAttachment.ResourceVersion, RequestID: "catalog-platform-revoke"}, http.StatusOK)
	read("/v1/platform-policies", platformBearer, http.StatusForbidden)
	if _, err := database.Exec(ctx, `UPDATE iam.policies SET status='RETIRED',resource_version=2,updated_at=transaction_timestamp() WHERE id='customer.catalog-a'`); err != nil {
		t.Fatal(err)
	}
	retired := find(read("/v1/policies", operator, http.StatusOK), "customer.catalog-a")
	if retired == nil || retired.Status != iamv1.PolicyRetired || retired.ResourceVersion != 2 {
		t.Fatal("retired metadata or current revision was hidden")
	}
	read("/v1/policies", bearer, http.StatusForbidden)
	// A prior read decision is a historical fact, not a reusable SQL permit.
	var oldDecision string
	if err := database.QueryRow(ctx, `SELECT id FROM iam.authorization_decisions WHERE tenant_id=$1 AND action_name='iam.policy.list' AND allowed ORDER BY decided_at DESC LIMIT 1`, home.AccountID).Scan(&oldDecision); err != nil {
		t.Fatal(err)
	}
	runtimeConfig := database.Config().Copy()
	runtimeConfig.User, runtimeConfig.Password = iamHTTPTestRole, iamHTTPTestPassword
	runtime, err := pgx.ConnectConfig(ctx, runtimeConfig)
	if err != nil {
		t.Fatal("connect restricted catalog runtime")
	}
	defer runtime.Close(context.Background())
	for _, scope := range []string{"TENANT", "INSTALLATION"} {
		var result []byte
		err := runtime.QueryRow(ctx, `SELECT iam.list_policies($1,$2,$3,$4)`, home.AccountID, iamHTTPBootstrap(t).Administrator.ID, oldDecision, scope).Scan(&result)
		var denied *pgconn.PgError
		if !errors.As(err, &denied) || denied.Code != "42501" {
			t.Fatalf("stale/mismatched directory decision was accepted: %v", err)
		}
	}
	for _, role := range []string{"matrix_iam_worker", "matrix_iam_credential_recovery"} {
		var permitted bool
		if err := database.QueryRow(ctx, `SELECT has_function_privilege($1,'iam.list_policies(text,text,text,text)','EXECUTE')`, role).Scan(&permitted); err != nil || permitted {
			t.Fatalf("non-API role can execute directory: %s err=%v", role, err)
		}
	}
	// Fill only the second account to the advertised complete-snapshot limit.
	// Its actor has one attachment, so an overflow must be the metadata budget,
	// not the independent current-authorization snapshot budget.
	before := read("/v1/policies", other, http.StatusOK)
	remaining := iamv1.MaxPolicyListItems - len(before.Items)
	if remaining < 1 {
		t.Fatal("invalid directory budget fixture")
	}
	insertBudget := func(first, last int) {
		t.Helper()
		if _, err := database.Exec(ctx, `BEGIN;
			INSERT INTO iam.policies(id,management,owner_tenant_id,display_name,authority_scope,status,default_version_id,resource_version,created_at,updated_at)
			SELECT 'catalog-budget-'||i,'CUSTOMER',$1,'Catalog budget '||i,'TENANT','ACTIVE','v1',1,transaction_timestamp(),transaction_timestamp() FROM generate_series($4::int,$5::int) i;
			INSERT INTO iam.policy_versions(policy_id,id,authority_scope,document,canonical_document,content_digest,created_at)
			SELECT 'catalog-budget-'||i,'v1','TENANT',$2::jsonb,$2,$3,transaction_timestamp() FROM generate_series($4::int,$5::int) i;
			COMMIT;`, otherAccount, canonical, digest, first, last); err != nil {
			t.Fatal(err)
		}
	}
	insertBudget(1, remaining)
	if got := read("/v1/policies", other, http.StatusOK); len(got.Items) != iamv1.MaxPolicyListItems {
		t.Fatal("complete directory truncated below its limit")
	}
	insertBudget(remaining+1, remaining+1)
	var decisionsBefore, decisionsAfter, outboxBefore, outboxAfter int
	if err := database.QueryRow(ctx, `SELECT (SELECT count(*) FROM iam.authorization_decisions),(SELECT count(*) FROM iam.audit_outbox)`).Scan(&decisionsBefore, &outboxBefore); err != nil {
		t.Fatal(err)
	}
	read("/v1/policies", other, http.StatusServiceUnavailable)
	if err := database.QueryRow(ctx, `SELECT (SELECT count(*) FROM iam.authorization_decisions),(SELECT count(*) FROM iam.audit_outbox)`).Scan(&decisionsAfter, &outboxAfter); err != nil || decisionsAfter != decisionsBefore || outboxAfter != outboxBefore {
		t.Fatal("overflow produced a partial catalog decision or audit fact")
	}
	if got := read("/v1/policies", operator, http.StatusOK); len(got.Items) >= iamv1.MaxPolicyListItems {
		t.Fatal("another account's catalog budget affected this account")
	}
}

func provePolicyDefaultAttachmentRaces(t *testing.T, ctx context.Context, handler http.Handler, database *pgx.Conn, operator string) {
	t.Helper()
	// Publication is a fixture-owner transaction, not an unimplemented online
	// policy editor. Actual USER commands run through restricted IAM HTTP.
	for _, transition := range []string{"switch", "retire", "rollback"} {
		t.Run(transition, func(t *testing.T) {
			policyID := iamv1.PolicyID("customer.publication-" + transition)
			requestID := "publication-" + transition
			created := performIAMRequest(handler, http.MethodPost, "/v1/users", operator,
				[]byte(`{"loginName":"publication.`+transition+`","displayName":"Publication member","initialPassword":"Publication-Initial-Password-49!","requestId":"`+requestID+`-user"}`))
			var member iamv1.User
			if created.Code != http.StatusCreated || json.Unmarshal(created.Body.Bytes(), &member) != nil || iamv1.ValidateUser(member) != nil {
				t.Fatal("create publication race member")
			}
			session := localRecoveryLogin(t, handler, member.LoginName+"@"+string(member.AccountID), "Publication-Initial-Password-49!", true)
			session = localRecoveryChangePassword(t, handler, session, "Publication-Initial-Password-49!", "Publication-Stable-Password-62!")
			document := iamv1.PolicyDocument{LanguageVersion: iamv1.PolicyLanguageVersion, Scope: iamv1.AuthorityScopeTenant,
				Statements: []iamv1.PolicyStatement{{SID: "read", Effect: iamv1.PolicyAllow,
					Actions: []iamv1.Action{iamv1.ActionPaaSApplicationRead}, Resources: []iamv1.PolicyResourceSelector{
						{Kind: iamv1.ResourceApplication, Match: iamv1.PolicyResourceAnyInAuthority}}}}}
			allow, allowDigest, err := iamv1.CanonicalizePolicyDocument(document)
			if err != nil {
				t.Fatal(err)
			}
			document.Statements[0].Effect = iamv1.PolicyDeny
			deny, denyDigest, err := iamv1.CanonicalizePolicyDocument(document)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := database.Exec(ctx, `BEGIN;
				INSERT INTO iam.policies(id,management,owner_tenant_id,display_name,authority_scope,status,default_version_id,resource_version,created_at,updated_at)
				VALUES($1,'CUSTOMER',$2,'Publication race '||$1,'TENANT','ACTIVE','v1',1,transaction_timestamp(),transaction_timestamp());
				INSERT INTO iam.policy_versions(policy_id,id,authority_scope,document,canonical_document,content_digest,created_at)
				VALUES($1,'v1','TENANT',$3::jsonb,$3,$4,transaction_timestamp()),
				($1,'v2','TENANT',$5::jsonb,$5,$6,transaction_timestamp()); COMMIT;`,
				policyID, member.AccountID, allow, allowDigest, deny, denyDigest); err != nil {
				t.Fatal(err)
			}
			publisher, err := pgx.ConnectConfig(ctx, database.Config().Copy())
			if err != nil {
				t.Fatal("connect publication transaction")
			}
			defer publisher.Close(context.Background())
			tx, err := publisher.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			if _, err := tx.Exec(ctx, `UPDATE iam.policies SET default_version_id='v2',resource_version=resource_version+1,
				status=CASE WHEN $2='retire' THEN 'RETIRED' ELSE 'ACTIVE' END,updated_at=transaction_timestamp() WHERE id=$1`, policyID, transition); err != nil {
				t.Fatal(err)
			}
			request := iamv1.CreatePolicyAttachmentRequest{Target: iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetUser, ID: string(member.ID)},
				PolicyID: policyID, PolicyResourceVersion: 1, RequestID: requestID}
			body, err := json.Marshal(request)
			if err != nil {
				t.Fatal(err)
			}
			completed := make(chan *httptest.ResponseRecorder, 1)
			go func() {
				completed <- performIAMRequest(handler, http.MethodPost, "/v1/policy-attachments", operator, body)
			}()
			// Confirm real blocking, not timing or an assumed goroutine order.
			waitForLocalRecoveryLock(t, ctx, database, iamHTTPTestRole)
			if transition == "rollback" {
				err = tx.Rollback(ctx)
			} else {
				err = tx.Commit(ctx)
			}
			if err != nil {
				t.Fatal(err)
			}
			var response *httptest.ResponseRecorder
			select {
			case response = <-completed:
			case <-ctx.Done():
				t.Fatal("attachment did not resolve after publication")
			}
			want := http.StatusConflict
			if transition == "retire" {
				want = http.StatusForbidden
			} else if transition == "rollback" {
				want = http.StatusOK
			}
			if response.Code != want {
				t.Fatalf("publication/attachment result=%d want=%d", response.Code, want)
			}
			assertIntent := func(id string, attachments, decisions, facts int) {
				t.Helper()
				var actualAttachments, actualDecisions, actualFacts int
				if err := database.QueryRow(ctx, `SELECT
					(SELECT count(*) FROM iam.policy_attachments WHERE tenant_id=$1 AND target_id=$2 AND policy_id=$3),
					(SELECT count(*) FROM iam.authorization_decisions WHERE tenant_id=$1 AND request_id=$4),
					(SELECT count(*) FROM iam.audit_outbox WHERE tenant_id=$1 AND event_document->>'requestId'=$4
					 AND event_document->>'action'='iam.policy-attachment.created')`,
					member.AccountID, member.ID, policyID, id).Scan(&actualAttachments, &actualDecisions, &actualFacts); err != nil ||
					actualAttachments != attachments || actualDecisions != decisions || actualFacts != facts {
					t.Fatalf("intent persisted attachments/decisions/facts=%d/%d/%d want=%d/%d/%d err=%v",
						actualAttachments, actualDecisions, actualFacts, attachments, decisions, facts, err)
				}
			}
			if transition != "rollback" {
				assertIntent(requestID, 0, 0, 0)
				if transition == "retire" {
					return
				}
				// A fresh explicit intent accepting the new revision is required.
				request.PolicyResourceVersion, request.RequestID = 2, requestID+"-confirmed"
				body, _ = json.Marshal(request)
				response = performIAMRequest(handler, http.MethodPost, "/v1/policy-attachments", operator, body)
				if response.Code != http.StatusOK {
					t.Fatalf("confirmed revision was not attachable: %d", response.Code)
				}
			}
			assertIntent(request.RequestID, 1, 1, 1)
			var attachment iamv1.PolicyAttachment
			if json.Unmarshal(response.Body.Bytes(), &attachment) != nil || iamv1.ValidatePolicyAttachment(attachment) != nil {
				t.Fatal("invalid publication attachment")
			}
			assertEvaluation := func(version string, digest string, allowed bool) []byte {
				t.Helper()
				body, _ := json.Marshal(iamv1.AuthorizationRequest{Action: iamv1.ActionPaaSApplicationRead,
					Resource:  iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "publication-resource"},
					RequestID: requestID + "-evaluate-" + version, CorrelationID: requestID})
				response := performIAMRequestWithSubject(handler, body, paasCredential, session)
				var decision iamv1.AuthorizationDecision
				if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &decision) != nil ||
					iamv1.ValidateAuthorizationDecision(decision) != nil || decision.Allowed != allowed {
					t.Fatalf("published version did not drive current decision: %d allowed=%t", response.Code, decision.Allowed)
				}
				var encoded []byte
				if err := database.QueryRow(ctx, `SELECT policy_evidence FROM iam.authorization_decisions WHERE tenant_id=$1 AND id=$2`, member.AccountID, decision.ID).Scan(&encoded); err != nil {
					t.Fatal(err)
				}
				var evidence []authority.PolicyAttachmentEvidence
				if json.Unmarshal(encoded, &evidence) != nil || len(evidence) != 1 || evidence[0].AttachmentID != attachment.ID ||
					evidence[0].Version.PolicyID != policyID || string(evidence[0].Version.VersionID) != version || evidence[0].Version.ContentDigest != digest {
					t.Fatal("decision evidence does not bind the evaluated policy version and attachment")
				}
				return encoded
			}
			if transition == "switch" {
				assertEvaluation("v2", denyDigest, false)
			} else {
				original := assertEvaluation("v1", allowDigest, true)
				if _, err := database.Exec(ctx, `UPDATE iam.policies SET default_version_id='v2',resource_version=resource_version+1,
					updated_at=transaction_timestamp() WHERE id=$1`, policyID); err != nil {
					t.Fatal(err)
				}
				assertEvaluation("v2", denyDigest, false)
				var retained []byte
				if err := database.QueryRow(ctx, `SELECT policy_evidence FROM iam.authorization_decisions WHERE tenant_id=$1 AND request_id=$2`,
					member.AccountID, requestID+"-evaluate-v1").Scan(&retained); err != nil || !bytes.Equal(original, retained) {
					t.Fatal("default publication rewrote prior immutable decision evidence")
				}
			}
		})
	}
}

func provePolicyScopeCredentialProtection(t *testing.T, ctx context.Context, handler http.Handler, database *pgx.Conn, operator string) {
	t.Helper()
	const initial = "Policy-Scope-Initial-Password-49!"
	const stable = "Policy-Scope-Stable-Password-62!"
	var beforePrincipals, beforeOutbox int
	if err := database.QueryRow(ctx, `SELECT (SELECT count(*) FROM iam.principals),(SELECT count(*) FROM iam.audit_outbox)`).Scan(&beforePrincipals, &beforeOutbox); err != nil {
		t.Fatal(err)
	}
	for _, role := range removedBuiltinRoleNames {
		body, _ := json.Marshal(map[string]any{"loginName": "policy.rejected", "displayName": "Rejected role carrier",
			"initialPassword": initial, "initialRole": role, "requestId": "rejected-initial-role"})
		if response := performIAMRequest(handler, http.MethodPost, "/v1/users", operator, body); response.Code != http.StatusBadRequest {
			t.Fatalf("removed initialRole reached user creation: status=%d", response.Code)
		}
	}
	var afterPrincipals, afterOutbox int
	if err := database.QueryRow(ctx, `SELECT (SELECT count(*) FROM iam.principals),(SELECT count(*) FROM iam.audit_outbox)`).Scan(&afterPrincipals, &afterOutbox); err != nil || beforePrincipals != afterPrincipals || beforeOutbox != afterOutbox {
		t.Fatal("rejected initial authority partially created an identity or fact")
	}
	created := performIAMRequest(handler, http.MethodPost, "/v1/users", operator,
		[]byte(`{"loginName":"policy.scope.protected","displayName":"Policy scope protection","initialPassword":"Policy-Scope-Initial-Password-49!","requestId":"scope-protection-create"}`))
	var member iamv1.User
	if created.Code != http.StatusCreated || json.Unmarshal(created.Body.Bytes(), &member) != nil {
		t.Fatal("create policy scope protection member")
	}
	var attachments int
	if err := database.QueryRow(ctx, `SELECT count(*) FROM iam.policy_attachments WHERE tenant_id=$1 AND target_id=$2`, member.AccountID, member.ID).Scan(&attachments); err != nil || attachments != 0 {
		t.Fatal("user creation implicitly granted a policy attachment")
	}
	session := localRecoveryLogin(t, handler, member.LoginName+"@"+string(member.AccountID), initial, true)
	localRecoveryChangePassword(t, handler, session, initial, stable)
	// A future published installation policy must protect its attached USER
	// even when it is not named PlatformOperator. Only this isolated fixture
	// owner publishes it; this is not an online system-policy editing API.
	version, err := authority.SystemPolicyVersion(iamv1.SystemPolicyPlatformOperator)
	if err != nil {
		t.Fatal(err)
	}
	canonical, digest, err := iamv1.CanonicalizePolicyDocument(version.Document)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(ctx, `BEGIN;
		INSERT INTO iam.policies(id,management,display_name,authority_scope,status,default_version_id,resource_version,created_at,updated_at)
		VALUES('system.scope-protection','SYSTEM','Scope protection','INSTALLATION','ACTIVE','scope-v1',1,transaction_timestamp(),transaction_timestamp());
		INSERT INTO iam.policy_versions(policy_id,id,authority_scope,document,canonical_document,content_digest,created_at)
		VALUES('system.scope-protection','scope-v1','INSTALLATION',$1::jsonb,$1,$2,transaction_timestamp());
		INSERT INTO iam.policy_attachments(tenant_id,id,target_id,policy_id,resource_version,created_at,updated_at)
		VALUES($3,'scope-protection-attachment',$4,'system.scope-protection',1,transaction_timestamp(),transaction_timestamp()); COMMIT;`,
		canonical, digest, member.AccountID, member.ID); err != nil {
		t.Fatal("prepare alternative platform policy fixture")
	}
	snapshot := func() (string, uint64) {
		t.Helper()
		var state string
		var revision uint64
		if err := database.QueryRow(ctx, `SELECT jsonb_build_array(principal.status,principal.resource_version,principal.must_change_password,
			credential.password_hash,credential.credential_version,
			(SELECT jsonb_agg(jsonb_build_array(id,status,resource_version,credential_version,revoked_at) ORDER BY id)
			FROM iam.sessions WHERE tenant_id=$1 AND principal_id=$2))::text,principal.resource_version
			FROM iam.principals AS principal JOIN iam.user_credentials AS credential
			ON credential.tenant_id=principal.tenant_id AND credential.principal_id=principal.id
			WHERE principal.tenant_id=$1 AND principal.id=$2`, member.AccountID, member.ID).Scan(&state, &revision); err != nil {
			t.Fatal("read protected credential state")
		}
		return state, revision
	}
	for _, phase := range []string{"active", "retired-policy", "disabled-user"} {
		if phase == "retired-policy" {
			if _, err := database.Exec(ctx, `UPDATE iam.policies SET status='RETIRED',resource_version=resource_version+1,updated_at=transaction_timestamp()
				WHERE id='system.scope-protection'`); err != nil {
				t.Fatal(err)
			}
		}
		if phase == "disabled-user" {
			if _, err := database.Exec(ctx, `UPDATE iam.principals SET status='DISABLED',resource_version=resource_version+1,updated_at=transaction_timestamp()
				WHERE tenant_id=$1 AND id=$2`, member.AccountID, member.ID); err != nil {
				t.Fatal(err)
			}
		}
		response := performIAMRequest(handler, http.MethodGet, "/v1/users", operator, nil)
		var directory iamv1.UserList
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &directory) != nil || iamv1.ValidateUserList(directory) != nil {
			t.Fatalf("protected identity directory %s: status=%d", phase, response.Code)
		}
		found := false
		for _, entry := range directory.Items {
			if entry.User.ID != member.ID {
				continue
			}
			for _, attachment := range entry.PolicyAttachments {
				if attachment.ID == "scope-protection-attachment" && attachment.Scope == iamv1.AuthorityScopeInstallation && attachment.RevokedAt == nil {
					found = true
				}
			}
		}
		if !found {
			t.Fatalf("directory hid protected association in %s", phase)
		}
		for _, operation := range []string{"set-status", "reset-password"} {
			before, revision := snapshot()
			body := map[string]any{"resourceVersion": revision, "requestId": "scope-protection-" + phase + "-" + operation}
			if operation == "set-status" {
				body["status"] = "ACTIVE"
			} else {
				body["initialPassword"] = "Policy-Scope-Forbidden-Password-73!"
			}
			encoded, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			response := performIAMRequest(handler, http.MethodPost, "/v1/users/"+string(member.ID)+":"+operation, operator, encoded)
			if response.Code != http.StatusForbidden {
				t.Fatalf("platform credential protection %s/%s status=%d", phase, operation, response.Code)
			}
			if after, _ := snapshot(); after != before {
				t.Fatal("rejected platform credential operation partially changed credentials or sessions")
			}
		}
	}
	var successes int
	if err := database.QueryRow(ctx, `SELECT count(*) FROM iam.audit_outbox WHERE event_document->>'requestId' LIKE 'scope-protection-%'
		AND event_document->>'result'='SUCCEEDED' AND event_document->>'action' IN ('iam.user.status-set','iam.user.password-reset')`).Scan(&successes); err != nil || successes != 0 {
		t.Fatal("rejected platform credential operation emitted a success fact")
	}
	if _, err := database.Exec(ctx, `UPDATE iam.policy_attachments SET revoked_at=transaction_timestamp(),updated_at=transaction_timestamp(),resource_version=resource_version+1
		WHERE tenant_id=$1 AND id='scope-protection-attachment'`, member.AccountID); err != nil {
		t.Fatal(err)
	}
	_, revision := snapshot()
	body, _ := json.Marshal(iamv1.SetUserStatusRequest{Status: iamv1.PrincipalActive, ResourceVersion: revision, RequestID: "scope-protection-after-revocation"})
	if response := performIAMRequest(handler, http.MethodPost, "/v1/users/"+string(member.ID)+":set-status", operator, body); response.Code != http.StatusOK {
		t.Fatalf("ordinary member remained unmanageable after platform attachment revocation: %d", response.Code)
	}
}

func TestIAMHTTPPostgresVerticalSlice(t *testing.T) {
	dsn := os.Getenv(iamHTTPPostgresDSN)
	if dsn == "" {
		t.Skipf("set %s to a clean disposable PostgreSQL 18 database", iamHTTPPostgresDSN)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	adminConfig, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse IAM HTTP PostgreSQL DSN: %v", err)
	}
	if !strings.HasPrefix(adminConfig.Database, "matrix_iam_") {
		t.Fatalf("refusing IAM HTTP database %q without matrix_iam_ prefix", adminConfig.Database)
	}
	adminConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	admin, err := pgx.ConnectConfig(ctx, adminConfig)
	if err != nil {
		t.Fatalf("connect IAM HTTP PostgreSQL: %v", err)
	}
	defer func() { _ = admin.Close(context.Background()) }()
	assertIAMPostgres18(t, ctx, admin)
	assertCleanIAMSchema(t, ctx, admin)
	applyIAMSchema(t, ctx, admin)
	createIAMHTTPRole(t, ctx, admin)

	poolConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse IAM HTTP pool DSN: %v", err)
	}
	poolConfig.ConnConfig.User = iamHTTPTestRole
	poolConfig.ConnConfig.Password = iamHTTPTestPassword
	poolConfig.MaxConns = 4
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		t.Fatalf("open IAM HTTP runtime pool: %v", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("ping IAM HTTP runtime pool: %v", err)
	}
	repository, err := iampostgres.NewRepository(pool)
	if err != nil {
		t.Fatalf("create IAM PostgreSQL repository: %v", err)
	}
	var sequence atomic.Int64
	workflow, err := identityaccess.NewAuthority(repository, identityaccess.Config{
		SessionLifetime: time.Hour,
		CursorKey:       bytes.Repeat([]byte{0x39}, 32),
		NewID: func(prefix string) (string, error) {
			return fmt.Sprintf("%s-http-%d", prefix, sequence.Add(1)), nil
		},
	})
	if err != nil {
		t.Fatalf("create IAM HTTP workflow: %v", err)
	}
	document := iamHTTPBootstrap(t)
	status, err := workflow.Bootstrap(ctx, document)
	if err != nil || status.State != iamv1.BootstrapReady {
		t.Fatalf("bootstrap IAM HTTP authority: status=%#v err=%v", status, err)
	}
	replayed, err := workflow.Bootstrap(ctx, document)
	if err != nil || replayed.ContentDigest != status.ContentDigest || replayed.AppliedAt == nil ||
		status.AppliedAt == nil || *replayed.AppliedAt != *status.AppliedAt {
		t.Fatalf("replay IAM HTTP bootstrap: status=%#v err=%v", replayed, err)
	}
	handler, err := iamhttp.NewHandler(workflow, iamhttp.Config{
		NewRequestID: func() (string, error) { return "request-http-integration", nil },
	})
	if err != nil {
		t.Fatalf("create IAM HTTP handler: %v", err)
	}

	ready := performIAMRequest(handler, http.MethodGet, "/ready", "", nil)
	if ready.Code != http.StatusOK {
		t.Fatalf("IAM readiness status=%d body=%s", ready.Code, ready.Body.String())
	}
	identity := performIAMRequest(handler, http.MethodGet, "/v1/service-identity", paasCredential, nil)
	if identity.Code != http.StatusOK {
		t.Fatalf("IAM service identity status=%d body=%s", identity.Code, identity.Body.String())
	}
	var serviceIdentity iamv1.ServiceIdentity
	if err := json.Unmarshal(identity.Body.Bytes(), &serviceIdentity); err != nil ||
		serviceIdentity.Purpose != iamv1.ServicePaaS || serviceIdentity.PrincipalID != "service-paas" {
		t.Fatalf("IAM service identity=%#v err=%v", serviceIdentity, err)
	}
	verificationBody := []byte(`{"action":"installation.verify","resource":{"kind":"INSTALLATION","id":"installation-http-integration"},"requestId":"request-installation-verify","correlationId":"correlation-installation-verify"}`)
	verification := performIAMRequest(
		handler, http.MethodPost, "/v1/installation:verify", verifierCredential, verificationBody,
	)
	var verificationDecision iamv1.AuthorizationDecision
	if verification.Code != http.StatusOK ||
		json.Unmarshal(verification.Body.Bytes(), &verificationDecision) != nil ||
		!verificationDecision.Allowed || verificationDecision.Subject == nil ||
		verificationDecision.Subject.Type != iamv1.PrincipalServiceAccount ||
		verificationDecision.Subject.ID != "service-verifier" {
		t.Fatalf(
			"IAM installation verification status=%d decision=%#v body=%s",
			verification.Code, verificationDecision, verification.Body.String(),
		)
	}
	verificationBody = []byte(`{"action":"installation.verify","resource":{"kind":"INSTALLATION","id":"installation-other"},"requestId":"request-installation-other","correlationId":"correlation-installation-other"}`)
	verification = performIAMRequest(
		handler, http.MethodPost, "/v1/installation:verify", verifierCredential, verificationBody,
	)
	if verification.Code != http.StatusOK ||
		json.Unmarshal(verification.Body.Bytes(), &verificationDecision) != nil ||
		verificationDecision.Allowed {
		t.Fatalf(
			"IAM cross-installation verification status=%d decision=%#v body=%s",
			verification.Code, verificationDecision, verification.Body.String(),
		)
	}

	loginBody := []byte(`{"loginName":"admin","password":"` + adminPassword + `","requestId":"request-login"}`)
	login := performIAMRequest(handler, http.MethodPost, "/v1/auth/login", "", loginBody)
	if login.Code != http.StatusOK {
		t.Fatalf("IAM login status=%d body=%s", login.Code, login.Body.String())
	}
	var loginWire struct {
		Credential string `json:"credential"`
	}
	if err := json.Unmarshal(login.Body.Bytes(), &loginWire); err != nil || loginWire.Credential == "" {
		t.Fatalf("decode IAM login credential: value=%q err=%v", loginWire.Credential, err)
	}
	var loginResult iamv1.LoginResponse
	if err := iamv1.DecodeRequest(bytes.NewReader(login.Body.Bytes()), &loginResult); err != nil {
		t.Fatalf("decode IAM login response contract: %v", err)
	}
	if !loginResult.MustChangePassword {
		t.Fatal("initial administrator login did not publish the password-change requirement")
	}
	secondInitialLogin := performIAMRequest(handler, http.MethodPost, "/v1/auth/login", "", loginBody)
	var secondInitialSession struct {
		Credential string `json:"credential"`
	}
	if secondInitialLogin.Code != http.StatusOK || json.Unmarshal(secondInitialLogin.Body.Bytes(), &secondInitialSession) != nil || secondInitialSession.Credential == "" {
		t.Fatal("could not establish the second initial-password session")
	}
	authorizeBody := []byte(`{"action":"paas.application.create","resource":{"kind":"APPLICATION","id":"application-example"},"requestId":"request-authorize","correlationId":"correlation-authorize"}`)
	authorize := performIAMRequestWithSubject(handler, authorizeBody, paasCredential, loginWire.Credential)
	if authorize.Code != http.StatusOK {
		t.Fatalf("IAM authorize status=%d body=%s", authorize.Code, authorize.Body.String())
	}
	var decision iamv1.AuthorizationDecision
	if err := json.Unmarshal(authorize.Body.Bytes(), &decision); err != nil || decision.Allowed {
		t.Fatalf("initial administrator decision=%#v err=%v, want audited deny", decision, err)
	}
	password := performIAMRequest(
		handler,
		http.MethodPost,
		"/v1/auth/password",
		loginWire.Credential,
		[]byte(`{"currentPassword":"`+adminPassword+`","newPassword":"`+changedAdminPassword+`","requestId":"request-admin-password"}`),
	)
	if password.Code != http.StatusOK {
		t.Fatalf("IAM administrator password status=%d body=%s", password.Code, password.Body.String())
	}
	var passwordResult iamv1.ChangePasswordResponse
	if err := json.Unmarshal(password.Body.Bytes(), &passwordResult); err != nil ||
		!passwordResult.BootstrapFileRetirable {
		t.Fatalf("IAM administrator password response=%#v err=%v", passwordResult, err)
	}
	if response := performIAMRequest(handler, http.MethodGet, "/v1/auth/me", secondInitialSession.Credential, nil); response.Code != http.StatusUnauthorized {
		t.Fatalf("password replacement promoted an old initial-password session: status=%d", response.Code)
	}
	oldPasswordLogin := performIAMRequest(handler, http.MethodPost, "/v1/auth/login", "", loginBody)
	if oldPasswordLogin.Code != http.StatusUnauthorized {
		t.Fatalf("IAM replaced password login status=%d body=%s", oldPasswordLogin.Code, oldPasswordLogin.Body.String())
	}
	weakPassword := performIAMRequest(
		handler,
		http.MethodPost,
		"/v1/auth/password",
		loginWire.Credential,
		[]byte(`{"currentPassword":"`+changedAdminPassword+`","newPassword":"weak","requestId":"request-weak-password"}`),
	)
	if weakPassword.Code != http.StatusUnprocessableEntity ||
		bytes.Contains(weakPassword.Body.Bytes(), []byte("weak")) {
		t.Fatalf("IAM weak password status=%d body=%s", weakPassword.Code, weakPassword.Body.String())
	}
	authorizeBody = []byte(`{"action":"paas.application.create","resource":{"kind":"APPLICATION","id":"application-example"},"requestId":"request-authorize-allowed","correlationId":"correlation-authorize-allowed"}`)
	authorize = performIAMRequestWithSubject(handler, authorizeBody, paasCredential, loginWire.Credential)
	if authorize.Code != http.StatusOK {
		t.Fatalf("IAM allowed authorize status=%d body=%s", authorize.Code, authorize.Body.String())
	}
	if err := json.Unmarshal(authorize.Body.Bytes(), &decision); err != nil || !decision.Allowed ||
		decision.TenantID != "organization-http-integration" {
		t.Fatalf("administrator allowed decision=%#v err=%v", decision, err)
	}
	managedServiceAuthorizeBody := []byte(`{"action":"managedservice.offering.read","resource":{"kind":"SERVICE_OFFERING","id":"collection"},"requestId":"request-managedservice-offering","correlationId":"correlation-managedservice-offering"}`)
	managedServiceAuthorize := performIAMRequestWithSubject(
		handler, managedServiceAuthorizeBody, paasCredential, loginWire.Credential,
	)
	if managedServiceAuthorize.Code != http.StatusOK {
		t.Fatalf(
			"IAM managed-service authorize status=%d body=%s",
			managedServiceAuthorize.Code,
			managedServiceAuthorize.Body.String(),
		)
	}
	if err := json.Unmarshal(managedServiceAuthorize.Body.Bytes(), &decision); err != nil ||
		!decision.Allowed || decision.Action != iamv1.ActionManagedServiceOfferingRead ||
		decision.Resource.Kind != iamv1.ResourceServiceOffering ||
		decision.TenantID != "organization-http-integration" {
		t.Fatalf("managed-service administrator decision=%#v err=%v", decision, err)
	}
	createUser := performIAMRequest(
		handler,
		http.MethodPost,
		"/v1/users",
		loginWire.Credential,
		[]byte(`{"loginName":"developer","displayName":"Platform Developer","initialPassword":"`+initialDeveloperPassword+`","requestId":"request-create-developer"}`),
	)
	if createUser.Code != http.StatusCreated {
		t.Fatalf("IAM create user status=%d body=%s", createUser.Code, createUser.Body.String())
	}
	var developer iamv1.User
	if err := json.Unmarshal(createUser.Body.Bytes(), &developer); err != nil ||
		developer.LoginName != "developer" || !developer.MustChangePassword {
		t.Fatalf("IAM created user=%#v err=%v", developer, err)
	}
	putBindingBody, err := json.Marshal(iamv1.CreatePolicyAttachmentRequest{
		Target:   iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetUser, ID: string(developer.ID)},
		PolicyID: iamv1.SystemPolicyPaaSDeveloper, PolicyResourceVersion: 1, RequestID: "request-bind-developer",
	})
	if err != nil {
		t.Fatalf("encode IAM role binding request: %v", err)
	}
	putBinding := performIAMRequest(
		handler, http.MethodPost, "/v1/policy-attachments", loginWire.Credential, putBindingBody,
	)
	if putBinding.Code != http.StatusOK {
		t.Fatalf("IAM put binding status=%d body=%s", putBinding.Code, putBinding.Body.String())
	}
	var binding iamv1.PolicyAttachment
	if err := json.Unmarshal(putBinding.Body.Bytes(), &binding); err != nil ||
		binding.Target.ID != string(developer.ID) || binding.PolicyID != iamv1.SystemPolicyPaaSDeveloper {
		t.Fatalf("IAM role binding=%#v err=%v", binding, err)
	}

	developerLogin := performIAMRequest(
		handler,
		http.MethodPost,
		"/v1/auth/login",
		"",
		[]byte(`{"loginName":"developer@organization-http-integration","password":"`+initialDeveloperPassword+`","requestId":"request-login-developer"}`),
	)
	if developerLogin.Code != http.StatusOK {
		t.Fatalf("IAM developer login status=%d body=%s", developerLogin.Code, developerLogin.Body.String())
	}
	var developerWire struct {
		Session            iamv1.Session `json:"session"`
		Credential         string        `json:"credential"`
		MustChangePassword bool          `json:"mustChangePassword"`
	}
	if err := json.Unmarshal(developerLogin.Body.Bytes(), &developerWire); err != nil ||
		developerWire.Credential == "" || !developerWire.MustChangePassword {
		t.Fatalf("decode IAM developer login=%#v err=%v", developerWire.Session, err)
	}
	developerAuthorizeBody := []byte(`{"action":"paas.application.create","resource":{"kind":"APPLICATION","id":"application-developer"},"requestId":"request-developer-before-password","correlationId":"correlation-developer-before-password"}`)
	developerAuthorize := performIAMRequestWithSubject(
		handler, developerAuthorizeBody, paasCredential, developerWire.Credential,
	)
	if developerAuthorize.Code != http.StatusOK {
		t.Fatalf("IAM initial developer authorize status=%d body=%s", developerAuthorize.Code, developerAuthorize.Body.String())
	}
	if err := json.Unmarshal(developerAuthorize.Body.Bytes(), &decision); err != nil || decision.Allowed {
		t.Fatalf("initial developer decision=%#v err=%v, want deny", decision, err)
	}
	developerPassword := performIAMRequest(
		handler,
		http.MethodPost,
		"/v1/auth/password",
		developerWire.Credential,
		[]byte(`{"currentPassword":"`+initialDeveloperPassword+`","newPassword":"`+changedDeveloperPassword+`","requestId":"request-developer-password"}`),
	)
	if developerPassword.Code != http.StatusOK {
		t.Fatalf("IAM developer password status=%d body=%s", developerPassword.Code, developerPassword.Body.String())
	}
	if err := json.Unmarshal(developerPassword.Body.Bytes(), &passwordResult); err != nil ||
		passwordResult.BootstrapFileRetirable {
		t.Fatalf("IAM developer password response=%#v err=%v", passwordResult, err)
	}
	deniedUser := performIAMRequest(
		handler,
		http.MethodPost,
		"/v1/users",
		developerWire.Credential,
		[]byte(`{"loginName":"denied.user","displayName":"Denied User","initialPassword":"Denied-User-Password-68!","requestId":"request-denied-user"}`),
	)
	if deniedUser.Code != http.StatusForbidden ||
		bytes.Contains(deniedUser.Body.Bytes(), []byte("Denied-User-Password")) {
		t.Fatalf("IAM denied role action status=%d body=%s", deniedUser.Code, deniedUser.Body.String())
	}
	developerAuthorizeBody = []byte(`{"action":"paas.application.create","resource":{"kind":"APPLICATION","id":"application-developer"},"requestId":"request-developer-allowed","correlationId":"correlation-developer-allowed"}`)
	developerAuthorize = performIAMRequestWithSubject(
		handler, developerAuthorizeBody, paasCredential, developerWire.Credential,
	)
	if developerAuthorize.Code != http.StatusOK {
		t.Fatalf("IAM developer authorize status=%d body=%s", developerAuthorize.Code, developerAuthorize.Body.String())
	}
	if err := json.Unmarshal(developerAuthorize.Body.Bytes(), &decision); err != nil ||
		!decision.Allowed || decision.Subject == nil || decision.Subject.ID != developer.ID {
		t.Fatalf("developer allowed decision=%#v err=%v", decision, err)
	}
	t.Run("tenant accounts and subusers", func(t *testing.T) {
		proveTenantAccounts(t, ctx, handler, admin, loginWire.Credential)
	})
	t.Run("password session policy", func(t *testing.T) {
		provePasswordSessionPolicy(t, ctx, handler, admin, loginWire.Credential)
	})
	t.Run("password session races", func(t *testing.T) {
		provePasswordSessionRaces(t, ctx, handler, admin, loginWire.Credential)
	})
	assertPlatformAuthorityHTTP(t, ctx, handler, admin, loginWire.Credential, developerWire.Credential, developer.ID)
	if _, err := workflow.Bootstrap(ctx, document); err != nil {
		t.Fatalf("replay bootstrap after platform role revocation: %v", err)
	}
	applyIAMSchema(t, ctx, admin)
	assertPlatformDecisionHTTP(t, handler, loginWire.Credential, paasCredential, false)
	if response := performIAMRequest(handler, http.MethodGet, "/v1/accounts", loginWire.Credential, nil); response.Code != http.StatusForbidden {
		t.Fatal("revoked bootstrap platform role retained tenant lifecycle authority")
	}

	revokeBinding := performIAMRequest(
		handler,
		http.MethodPost,
		"/v1/policy-attachments/"+string(binding.ID)+":revoke",
		loginWire.Credential,
		[]byte(`{"resourceVersion":1,"requestId":"request-revoke-developer-binding"}`),
	)
	if revokeBinding.Code != http.StatusOK {
		t.Fatalf("IAM revoke binding status=%d body=%s", revokeBinding.Code, revokeBinding.Body.String())
	}
	developerAuthorizeBody = []byte(`{"action":"paas.application.create","resource":{"kind":"APPLICATION","id":"application-developer"},"requestId":"request-developer-after-binding","correlationId":"correlation-developer-after-binding"}`)
	developerAuthorize = performIAMRequestWithSubject(
		handler, developerAuthorizeBody, paasCredential, developerWire.Credential,
	)
	if developerAuthorize.Code != http.StatusOK {
		t.Fatalf("IAM post-revocation authorize status=%d body=%s", developerAuthorize.Code, developerAuthorize.Body.String())
	}
	if err := json.Unmarshal(developerAuthorize.Body.Bytes(), &decision); err != nil || decision.Allowed {
		t.Fatalf("role-revoked decision=%#v err=%v, want deny", decision, err)
	}
	revokeSession := performIAMRequest(
		handler,
		http.MethodPost,
		"/v1/sessions/"+string(developerWire.Session.ID)+":revoke",
		loginWire.Credential,
		[]byte(`{"requestId":"request-revoke-developer-session"}`),
	)
	if revokeSession.Code != http.StatusOK {
		t.Fatalf("IAM revoke session status=%d body=%s", revokeSession.Code, revokeSession.Body.String())
	}
	developerAuthorize = performIAMRequestWithSubject(
		handler, developerAuthorizeBody, paasCredential, developerWire.Credential,
	)
	if developerAuthorize.Code != http.StatusUnauthorized {
		t.Fatalf("IAM revoked session authorize status=%d body=%s", developerAuthorize.Code, developerAuthorize.Body.String())
	}
	verifierRevocation := performIAMRequest(
		handler,
		http.MethodPost,
		"/v1/policy-attachments/bootstrap-verifier-binding:revoke",
		loginWire.Credential,
		[]byte(`{"resourceVersion":1,"requestId":"request-revoke-verifier-binding"}`),
	)
	if verifierRevocation.Code != http.StatusForbidden {
		t.Fatalf(
			"IAM verifier role revocation status=%d body=%s",
			verifierRevocation.Code, verifierRevocation.Body.String(),
		)
	}
	// Installation-probe service membership has no online USER-management route.
	// This storage revocation fixture proves current verifier authority, not a
	// supported service-identity administration workflow.
	if _, err := admin.Exec(ctx, "UPDATE iam.policy_attachments SET revoked_at=transaction_timestamp(),updated_at=transaction_timestamp(),resource_version=resource_version+1 WHERE tenant_id=$1 AND id='bootstrap-verifier-binding'", document.Organization.ID); err != nil {
		t.Fatal(err)
	}
	verificationBody = []byte(`{"action":"installation.verify","resource":{"kind":"INSTALLATION","id":"installation-http-integration"},"requestId":"request-installation-revoked","correlationId":"correlation-installation-revoked"}`)
	verification = performIAMRequest(
		handler, http.MethodPost, "/v1/installation:verify", verifierCredential, verificationBody,
	)
	if verification.Code != http.StatusOK ||
		json.Unmarshal(verification.Body.Bytes(), &verificationDecision) != nil ||
		verificationDecision.Allowed {
		t.Fatalf(
			"IAM revoked verifier status=%d decision=%#v body=%s",
			verification.Code, verificationDecision, verification.Body.String(),
		)
	}
	wrongService := performIAMRequestWithSubject(handler, authorizeBody, "wrong-service-credential", loginWire.Credential)
	if wrongService.Code != http.StatusUnauthorized {
		t.Fatalf("wrong service credential status=%d body=%s", wrongService.Code, wrongService.Body.String())
	}
	logout := performIAMRequest(
		handler,
		http.MethodPost,
		"/v1/auth/logout",
		loginWire.Credential,
		[]byte(`{"requestId":"request-admin-logout"}`),
	)
	if logout.Code != http.StatusOK {
		t.Fatalf("IAM administrator logout status=%d body=%s", logout.Code, logout.Body.String())
	}

	assertIAMSecretsAbsent(
		t,
		ctx,
		admin,
		paasCredential,
		auditCredential,
		verifierCredential,
		adminPassword,
		changedAdminPassword,
		initialDeveloperPassword,
		changedDeveloperPassword,
		loginWire.Credential,
		developerWire.Credential,
	)
	var decisionsHaveAudit bool
	if err := admin.QueryRow(
		ctx,
		`SELECT
			NOT EXISTS (
				SELECT 1 FROM iam.authorization_decisions AS decision
				WHERE (SELECT count(*) FROM iam.audit_outbox AS event
					WHERE event.tenant_id = decision.tenant_id
					AND event.event_document->>'action' = 'iam.authorization.decided'
					AND event.event_document->>'iamDecisionId' = decision.id
					AND event.event_document#>>'{actor,id}' = decision.principal_id
					AND event.event_document->>'requestId' = decision.request_id
					AND event.event_document->>'result' = CASE WHEN decision.allowed THEN 'ALLOWED' ELSE 'DENIED' END
				) <> 1
			)`,
	).Scan(&decisionsHaveAudit); err != nil {
		t.Fatalf("inspect IAM HTTP facts: %v", err)
	}
	if !decisionsHaveAudit {
		t.Fatal("not every IAM decision has an exact Audit fact")
	}
	var managedServiceFacts int
	if err := admin.QueryRow(
		ctx,
		`SELECT count(*)
		   FROM iam.authorization_decisions AS decision
		   JOIN iam.audit_outbox AS outbox
		     ON outbox.tenant_id = decision.tenant_id
		    AND outbox.event_document->>'iamDecisionId' = decision.id
		  WHERE decision.action_name = 'managedservice.offering.read'
		    AND decision.target_kind = 'SERVICE_OFFERING'
		    AND decision.target_id = 'collection'
		    AND decision.allowed`,
	).Scan(&managedServiceFacts); err != nil {
		t.Fatalf("inspect managed-service authorization facts: %v", err)
	}
	if managedServiceFacts != 1 {
		t.Fatalf("managed-service authorization facts=%d want=1", managedServiceFacts)
	}
	var deniedUsers int
	if err := admin.QueryRow(
		ctx,
		"SELECT count(*) FROM iam.login_index WHERE login_name = 'denied.user'",
	).Scan(&deniedUsers); err != nil {
		t.Fatalf("inspect denied IAM user: %v", err)
	}
	if deniedUsers != 0 {
		t.Fatalf("denied IAM users=%d want=0", deniedUsers)
	}
	t.Run("outbox physical owner and sealed chain", func(t *testing.T) {
		proveIAMOutboxClaims(t, ctx, admin, poolConfig, handler)
	})
}

func provePasswordSessionPolicy(t *testing.T, ctx context.Context, handler http.Handler, database *pgx.Conn, operator string) {
	t.Helper()
	const initial = "Session-Policy-Initial-Password-49!"
	const changed = "Session-Policy-Changed-Password-73!"
	const retained = "Session-Policy-Retained-Password-84!"
	const replaced = "Session-Policy-Replaced-Password-95!"
	const reset = "Session-Policy-Reset-Password-68!"
	var sequence atomic.Uint64
	request := func(method, path, bearer string, body map[string]any, expected int) *httptest.ResponseRecorder {
		t.Helper()
		var encoded []byte
		if body != nil {
			body["requestId"] = fmt.Sprintf("request-password-policy-%d", sequence.Add(1))
			var err error
			encoded, err = json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
		}
		response := performIAMRequest(handler, method, path, bearer, encoded)
		if response.Code != expected {
			t.Fatalf("password policy %s %s: status=%d want=%d", method, path, response.Code, expected)
		}
		return response
	}
	login := func(name, password string) string {
		t.Helper()
		response := request(http.MethodPost, "/v1/auth/login", "", map[string]any{"loginName": name, "password": password}, http.StatusOK)
		var result struct {
			Credential string `json:"credential"`
		}
		if json.Unmarshal(response.Body.Bytes(), &result) != nil || result.Credential == "" {
			t.Fatal("password policy login returned no credential")
		}
		return result.Credential
	}
	identity := func(bearer string) iamv1.CurrentIdentity {
		t.Helper()
		response := request(http.MethodGet, "/v1/auth/me", bearer, nil, http.StatusOK)
		var result iamv1.CurrentIdentity
		if json.Unmarshal(response.Body.Bytes(), &result) != nil || iamv1.ValidateCurrentIdentity(result) != nil {
			t.Fatal("password policy returned invalid current identity")
		}
		return result
	}
	change := func(bearer, from, to string, others *bool) {
		t.Helper()
		subject := identity(bearer).User
		var previousVersion, currentVersion int64
		if err := database.QueryRow(ctx, "SELECT credential_version FROM iam.user_credentials WHERE tenant_id=$1 AND principal_id=$2", subject.AccountID, subject.ID).Scan(&previousVersion); err != nil {
			t.Fatal(err)
		}
		body := map[string]any{"currentPassword": from, "newPassword": to}
		if others != nil {
			body["revokeOtherSessions"] = *others
		}
		request(http.MethodPost, "/v1/auth/password", bearer, body, http.StatusOK)
		if identity(bearer).User.MustChangePassword {
			t.Fatal("password change did not preserve and advance the verified current session")
		}
		if err := database.QueryRow(ctx, "SELECT credential_version FROM iam.user_credentials WHERE tenant_id=$1 AND principal_id=$2", subject.AccountID, subject.ID).Scan(&currentVersion); err != nil || currentVersion != previousVersion+1 {
			t.Fatal("password change did not advance the per-user credential generation exactly once")
		}
	}
	invalid := func(bearer string) {
		t.Helper()
		request(http.MethodGet, "/v1/auth/me", bearer, nil, http.StatusUnauthorized)
	}
	create := request(http.MethodPost, "/v1/users", operator, map[string]any{
		"loginName": "password.policy", "displayName": "Password policy", "initialPassword": initial,
	}, http.StatusCreated)
	var principal iamv1.User
	if json.Unmarshal(create.Body.Bytes(), &principal) != nil {
		t.Fatal("invalid password policy principal")
	}
	name := principal.LoginName + "@" + string(principal.AccountID)
	current, temporary := login(name, initial), login(name, initial)
	keep, revoke := false, true
	change(current, initial, changed, &keep)
	invalid(temporary)
	other, loggedOut := login(name, changed), login(name, changed)
	request(http.MethodPost, "/v1/auth/logout", loggedOut, map[string]any{}, http.StatusOK)

	// Compare only persisted security state and success facts, not incidental
	// request order. Never print the credential/hash-containing comparison value.
	securityState := func() string {
		t.Helper()
		var state string
		if err := database.QueryRow(ctx, `SELECT jsonb_build_object(
			'principal',to_jsonb(p),'credential',to_jsonb(c),
			'sessions',(SELECT jsonb_agg(to_jsonb(s) ORDER BY s.id) FROM iam.sessions AS s WHERE s.tenant_id=p.tenant_id AND s.principal_id=p.id),
			'successes',(SELECT jsonb_agg(e.event_document ORDER BY e.event_id) FROM iam.audit_outbox AS e WHERE e.tenant_id=p.tenant_id AND e.event_document->>'action'='iam.user.password-changed' AND e.event_document#>>'{target,id}'=p.id)
			)::text FROM iam.principals AS p JOIN iam.user_credentials AS c ON c.tenant_id=p.tenant_id AND c.principal_id=p.id
			WHERE p.tenant_id=$1 AND p.id=$2`, principal.AccountID, principal.ID).Scan(&state); err != nil {
			t.Fatal(err)
		}
		return state
	}
	for _, attack := range []struct {
		body   map[string]any
		status int
	}{
		{map[string]any{"currentPassword": initial, "newPassword": retained}, http.StatusUnauthorized},
		{map[string]any{"currentPassword": changed, "newPassword": "weak"}, http.StatusUnprocessableEntity},
		{map[string]any{"currentPassword": changed, "newPassword": retained, "sessionId": identity(other).User.ID}, http.StatusBadRequest},
		{map[string]any{"currentPassword": changed, "newPassword": retained, "revokeOtherSessions": "false"}, http.StatusBadRequest},
		{map[string]any{"currentPassword": changed, "newPassword": retained, "revokeOtherSessions": nil}, http.StatusBadRequest},
	} {
		before := securityState()
		request(http.MethodPost, "/v1/auth/password", current, attack.body, attack.status)
		if securityState() != before {
			t.Fatal("rejected password change partially altered security state or success facts")
		}
	}
	change(current, changed, retained, &keep)
	identity(other)
	invalid(temporary)
	invalid(loggedOut)
	identity(operator) // Another user's session is never in this mutation's scope.
	change(current, retained, replaced, nil)
	invalid(other)
	other = login(name, replaced)
	change(current, replaced, changed, &revoke)
	invalid(other)

	// Reset must revoke old sessions before issuing any replacement-password
	// sessions, and false cannot preserve another such temporary session.
	beforeReset := identity(current)
	request(http.MethodPost, "/v1/users/"+string(principal.ID)+":reset-password", operator,
		map[string]any{"initialPassword": reset, "resourceVersion": beforeReset.User.ResourceVersion}, http.StatusOK)
	invalid(current)
	resetCurrent, resetOther := login(name, reset), login(name, reset)
	change(resetCurrent, reset, retained, &keep)
	invalid(resetOther)
	invalid(temporary)
	invalid(loggedOut)

	// An old temporary session may not gain platform authority when this USER
	// later receives an explicit platform binding after confirmed replacement.
	grant := request(http.MethodPost, "/v1/policy-attachments", operator,
		map[string]any{"target": iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetUser, ID: string(principal.ID)}, "policyId": iamv1.SystemPolicyPlatformOperator, "policyResourceVersion": 1}, http.StatusOK)
	var platform iamv1.PolicyAttachment
	if json.Unmarshal(grant.Body.Bytes(), &platform) != nil {
		t.Fatal("invalid policy platform binding")
	}
	assertPlatformDecisionHTTP(t, handler, resetCurrent, paasCredential, true)
	for _, stale := range []string{temporary, resetOther, current, loggedOut} {
		invalid(stale)
	}
	request(http.MethodPost, "/v1/policy-attachments/"+string(platform.ID)+":revoke", operator, map[string]any{"resourceVersion": 1}, http.StatusOK)

	created := request(http.MethodPost, "/v1/accounts", operator, map[string]any{
		"id": "organization-password-policy", "displayName": "Password recovery policy", "rootLoginName": "password.primary",
		"rootDisplayName": "Password primary", "initialPassword": initial,
	}, http.StatusCreated)
	var account iamv1.Account
	if json.Unmarshal(created.Body.Bytes(), &account) != nil {
		t.Fatal("invalid password policy account")
	}
	primary, oldPrimary := login(account.RootIdentity.LoginName, initial), login(account.RootIdentity.LoginName, initial)
	change(primary, initial, changed, nil)
	request(http.MethodPost, "/v1/accounts/"+string(account.ID)+":recover-root-credentials", operator,
		map[string]any{"initialPassword": reset, "resourceVersion": account.ResourceVersion}, http.StatusOK)
	invalid(primary)
	invalid(oldPrimary)
	recovered, recoveredOther := login(account.RootIdentity.LoginName, reset), login(account.RootIdentity.LoginName, reset)
	change(recovered, reset, changed, &keep)
	invalid(recoveredOther)
	applyIAMSchema(t, ctx, database)
	applyIAMSchema(t, ctx, database)
	for _, stale := range []string{temporary, resetOther, current, loggedOut, primary, oldPrimary, recoveredOther} {
		invalid(stale)
	}
	identity(recovered)
	identity(resetCurrent)
	assertIAMSecretsAbsent(t, ctx, database, initial, changed, retained, replaced, reset)
}

func provePasswordSessionRaces(t *testing.T, ctx context.Context, handler http.Handler, database *pgx.Conn, operator string) {
	t.Helper()
	const initial = "Race-Session-Initial-Password-49!"
	const stable = "Race-Session-Stable-Password-62!"
	const changed = "Race-Session-Changed-Password-73!"
	const competing = "Race-Session-Competing-Password-84!"
	const reset = "Race-Session-Reset-Password-95!"
	for _, mutation := range []string{"change", "reset", "recover", "logout", "old-password-login"} {
		t.Run(mutation, func(t *testing.T) {
			var sequence atomic.Uint64
			request := func(path, bearer string, body map[string]any) *httptest.ResponseRecorder {
				body["requestId"] = fmt.Sprintf("request-session-race-%s-%d", mutation, sequence.Add(1))
				encoded, err := json.Marshal(body)
				if err != nil {
					t.Fatal(err)
				}
				return performIAMRequest(handler, http.MethodPost, path, bearer, encoded)
			}
			credential := func(response *httptest.ResponseRecorder) string {
				t.Helper()
				var result struct {
					Credential string `json:"credential"`
				}
				if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &result) != nil || result.Credential == "" {
					t.Fatalf("session race login status=%d", response.Code)
				}
				return result.Credential
			}
			identity := func(bearer string, valid bool) iamv1.CurrentIdentity {
				t.Helper()
				response := performIAMRequest(handler, http.MethodGet, "/v1/auth/me", bearer, nil)
				if !valid {
					if response.Code != http.StatusUnauthorized {
						t.Fatalf("session race retained a revoked session: %d", response.Code)
					}
					return iamv1.CurrentIdentity{}
				}
				var result iamv1.CurrentIdentity
				if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &result) != nil || iamv1.ValidateCurrentIdentity(result) != nil {
					t.Fatalf("session race lost an effective session: %d", response.Code)
				}
				return result
			}
			name := "password.race." + mutation
			var account iamv1.Account
			if mutation == "recover" {
				response := request("/v1/accounts", operator, map[string]any{"id": "organization-password-race", "displayName": "Recovery race",
					"rootLoginName": name, "rootDisplayName": "Recovery race primary", "initialPassword": initial})
				if response.Code != http.StatusCreated || json.Unmarshal(response.Body.Bytes(), &account) != nil {
					t.Fatalf("create password recovery race: %d", response.Code)
				}
			} else {
				response := request("/v1/users", operator, map[string]any{"loginName": name, "displayName": "Password race user", "initialPassword": initial})
				var principal iamv1.User
				if response.Code != http.StatusCreated || json.Unmarshal(response.Body.Bytes(), &principal) != nil {
					t.Fatalf("create password race user: %d", response.Code)
				}
				name += "@" + string(principal.AccountID)
			}
			login := func(password string) string {
				t.Helper()
				return credential(request("/v1/auth/login", "", map[string]any{"loginName": name, "password": password}))
			}
			current := login(initial)
			if response := request("/v1/auth/password", current, map[string]any{"currentPassword": initial, "newPassword": stable}); response.Code != http.StatusOK {
				t.Fatalf("initialize password race: %d", response.Code)
			}
			other, loggedOut := login(stable), login(stable)
			if response := request("/v1/auth/logout", loggedOut, map[string]any{}); response.Code != http.StatusOK {
				t.Fatalf("prepare revoked race session: %d", response.Code)
			}
			before := identity(current, true)
			changeID, competingID := "request-racing-password-"+mutation, "request-racing-peer-"+mutation
			changeBody, _ := json.Marshal(map[string]any{"currentPassword": stable, "newPassword": changed, "requestId": changeID})
			path, bearer := "/v1/auth/password", other
			body := map[string]any{"currentPassword": stable, "newPassword": competing, "revokeOtherSessions": false}
			switch mutation {
			case "reset":
				path, bearer = "/v1/users/"+string(before.User.ID)+":reset-password", operator
				body = map[string]any{"initialPassword": reset, "resourceVersion": before.User.ResourceVersion}
			case "recover":
				path, bearer = "/v1/accounts/"+string(account.ID)+":recover-root-credentials", operator
				body = map[string]any{"initialPassword": reset, "resourceVersion": account.ResourceVersion}
			case "logout":
				path, bearer, body = "/v1/auth/logout", current, map[string]any{}
			case "old-password-login":
				path, bearer, body = "/v1/auth/login", "", map[string]any{"loginName": name, "password": stable}
			}
			body["requestId"] = competingID
			competingBody, _ := json.Marshal(body)
			start := make(chan struct{})
			changes, peers := make(chan *httptest.ResponseRecorder, 1), make(chan *httptest.ResponseRecorder, 1)
			go func() {
				<-start
				changes <- performIAMRequest(handler, http.MethodPost, "/v1/auth/password", current, changeBody)
			}()
			go func() { <-start; peers <- performIAMRequest(handler, http.MethodPost, path, bearer, competingBody) }()
			close(start)
			changeResponse, peerResponse := <-changes, <-peers
			changeStatus, peerStatus := changeResponse.Code, peerResponse.Code
			if changeStatus != http.StatusOK && changeStatus != http.StatusUnauthorized {
				t.Fatalf("password race returned unexpected change status=%d", changeStatus)
			}
			switch mutation {
			case "change":
				if !((changeStatus == http.StatusOK && peerStatus == http.StatusUnauthorized) || (changeStatus == http.StatusUnauthorized && peerStatus == http.StatusOK)) {
					t.Fatalf("two competing password replacements did not serialize: %d/%d", changeStatus, peerStatus)
				}
				password := changed
				if peerStatus == http.StatusOK {
					password = competing
				}
				identity(login(password), true)
				identity(current, true) // Explicit false may retain this already valid session.
				identity(other, peerStatus == http.StatusOK)
			case "reset":
				if !((changeStatus == http.StatusOK && peerStatus == http.StatusConflict) || (changeStatus == http.StatusUnauthorized && peerStatus == http.StatusOK)) {
					t.Fatalf("reset and password replacement ignored principal version: %d/%d", changeStatus, peerStatus)
				}
				identity(current, changeStatus == http.StatusOK)
				identity(other, false)
				if peerStatus == http.StatusOK && !identity(login(reset), true).User.MustChangePassword {
					t.Fatal("racing reset lost required password change")
				}
			case "recover":
				if peerStatus != http.StatusOK {
					t.Fatalf("original-primary recovery lost to a non-lifecycle version: %d", peerStatus)
				}
				identity(current, false)
				identity(other, false)
				if !identity(login(reset), true).User.MustChangePassword {
					t.Fatal("racing recovery lost required password change")
				}
			case "logout":
				if peerStatus != http.StatusOK {
					t.Fatalf("racing logout failed: %d", peerStatus)
				}
				identity(current, false)
				identity(other, changeStatus != http.StatusOK)
			case "old-password-login":
				if changeStatus != http.StatusOK || (peerStatus != http.StatusOK && peerStatus != http.StatusUnauthorized) {
					t.Fatalf("old-password login/replacement did not serialize: %d/%d", changeStatus, peerStatus)
				}
				if peerStatus == http.StatusOK {
					identity(credential(peerResponse), false)
				}
				identity(current, true)
				identity(other, false)
			}
			identity(loggedOut, false)
			for requestID, succeeded := range map[string]bool{changeID: changeStatus == http.StatusOK, competingID: mutation == "change" && peerStatus == http.StatusOK} {
				var facts int
				if err := database.QueryRow(ctx, `SELECT count(*) FROM iam.audit_outbox WHERE event_document->>'action'='iam.user.password-changed' AND event_document->>'requestId'=$1`, requestID).Scan(&facts); err != nil {
					t.Fatal(err)
				}
				if succeeded && facts != 1 || !succeeded && facts != 0 {
					t.Fatal("racing password result and immutable success fact disagree")
				}
			}
		})
	}
	assertIAMSecretsAbsent(t, ctx, database, initial, stable, changed, competing, reset)
}

func proveIAMOutboxClaims(t *testing.T, ctx context.Context, admin *pgx.Conn, config *pgxpool.Config, handler http.Handler) {
	t.Helper()
	workerConfig := config.Copy()
	workerConfig.ConnConfig.User = iamHTTPWorkerRole
	workerConfig.MaxConns = 2
	pool, err := pgxpool.NewWithConfig(ctx, workerConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	repository, err := iampostgres.NewAuditOutboxRepository(pool)
	if err != nil {
		t.Fatal(err)
	}
	var tenantClaim, platformClaim auditdispatch.Claim
	// This gate tests claim/completion persistence only. The separate five-process
	// gate proves actual HTTP delivery of these events, without a fake ingestor.
	for count := 0; ; count++ {
		if count >= 2048 {
			t.Fatal("IAM claim fixture exceeded its bounded event budget")
		}
		claim, found, err := repository.Claim(ctx, "iam-http-scope-worker", 10*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if !found {
			break
		}
		if claim.Event.InstallationID != "" {
			if claim.AccountID != "organization-http-integration" || claim.InstallationID != "installation-http-integration" || claim.Event.TenantID != "" {
				t.Fatal("installation claim did not retain its sealed physical owner")
			}
			platformClaim = claim
		} else {
			if string(claim.AccountID) != string(claim.Event.TenantID) {
				t.Fatal("tenant claim changed owner")
			}
			tenantClaim = claim
		}
		if err := repository.Complete(ctx, auditdispatch.Completion{EventID: claim.EventID,
			WorkerID: "iam-http-scope-worker", FencingToken: claim.FencingToken, Outcome: auditdispatch.OutcomeDelivered}); err != nil {
			t.Fatal(err)
		}
		var completed bool
		if err := admin.QueryRow(ctx, "SELECT status='DELIVERED' FROM iam.audit_outbox WHERE tenant_id=$1 AND event_id=$2",
			claim.AccountID, claim.EventID).Scan(&completed); err != nil || !completed {
			t.Fatal("claim completion used event scope instead of the physical owner")
		}
	}
	if tenantClaim.EventID == "" || platformClaim.EventID == "" {
		t.Fatal("claim gate did not exercise both tenant and installation facts")
	}
	for _, claim := range []auditdispatch.Claim{tenantClaim, platformClaim} {
		event := claim.Event
		event.EventID += "-forged-scope"
		if event.InstallationID != "" {
			event.InstallationID = "installation-forged"
		} else {
			event.TenantID = "organization-forged"
		}
		encoded, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		// Deliberately corrupt storage as the test administrator, not through a
		// product command. The runtime worker must dead-letter it before delivery.
		if _, err := admin.Exec(ctx, `INSERT INTO iam.audit_outbox(tenant_id,event_id,event_document,next_attempt_at,created_at,updated_at)
			VALUES($1,$2,$3::jsonb,transaction_timestamp(),transaction_timestamp(),transaction_timestamp())`,
			claim.AccountID, event.EventID, string(encoded)); err != nil {
			t.Fatal(err)
		}
		if _, found, err := repository.Claim(ctx, "iam-http-scope-worker", 10*time.Second); err == nil || found {
			t.Fatal("forged chain scope escaped the claimed-event boundary")
		}
		var rejected bool
		if err := admin.QueryRow(ctx, "SELECT status='DEAD_LETTER' AND error_code='audit.event.corrupt' FROM iam.audit_outbox WHERE tenant_id=$1 AND event_id=$2",
			claim.AccountID, event.EventID).Scan(&rejected); err != nil || !rejected {
			t.Fatal("invalid scope was lost instead of retaining its owner-bound dead letter")
		}
	}
	if response := performIAMRequest(handler, http.MethodGet, "/ready", "", nil); response.Code != http.StatusServiceUnavailable {
		t.Fatal("corrupt outbox claims did not make readiness unhealthy")
	}
}

func proveTenantAccounts(t *testing.T, ctx context.Context, handler http.Handler, admin *pgx.Conn, root string) {
	t.Helper()
	const tenantA = "organization-http-integration"
	const tenantB = "organization-customer-b"
	const primaryBPassword = "Customer-B-Initial-Password-48!"
	const primaryBChanged = "Customer-B-Changed-Password-59!"
	const childPassword = "Account-Child-Initial-Password-74!"
	const childChangedA = "Account-A-Changed-Password-85!"
	const childChangedB = "Account-B-Changed-Password-96!"
	const resetPassword = "Account-Child-Reset-Password-63!"

	request := func(method, path, bearer string, body any, expected int) *httptest.ResponseRecorder {
		t.Helper()
		var encoded []byte
		var err error
		if body != nil {
			encoded, err = json.Marshal(body)
		}
		if err != nil {
			t.Fatalf("encode account test request: %v", err)
		}
		response := performIAMRequest(handler, method, path, bearer, encoded)
		if response.Code != expected {
			t.Fatalf("%s %s: status=%d want=%d body=%s", method, path, response.Code, expected, response.Body.String())
		}
		if response.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("account response is cacheable")
		}
		return response
	}
	identity := func(bearer string) iamv1.CurrentIdentity {
		t.Helper()
		response := request(http.MethodGet, "/v1/auth/me", bearer, nil, http.StatusOK)
		var result iamv1.CurrentIdentity
		if json.Unmarshal(response.Body.Bytes(), &result) != nil || iamv1.ValidateCurrentIdentity(result) != nil {
			t.Fatal("invalid current identity")
		}
		return result
	}
	login := func(name, password string, expected int) string {
		t.Helper()
		response := request(http.MethodPost, "/v1/auth/login", "", map[string]any{"loginName": name, "password": password, "requestId": "request-account-login"}, expected)
		if expected != http.StatusOK {
			return ""
		}
		var result struct {
			Credential string `json:"credential"`
		}
		if json.Unmarshal(response.Body.Bytes(), &result) != nil || result.Credential == "" {
			t.Fatal("login did not issue a credential")
		}
		return result.Credential
	}
	passwordChange := func(bearer, previous, next string) {
		request(http.MethodPost, "/v1/auth/password", bearer, map[string]any{"currentPassword": previous, "newPassword": next, "requestId": "request-account-password"}, http.StatusOK)
	}
	createUser := func(bearer, name string, policy iamv1.PolicyID, expected int) iamv1.User {
		t.Helper()
		body := map[string]any{"loginName": name, "displayName": "Account test user", "initialPassword": childPassword, "requestId": "request-account-user"}
		response := request(http.MethodPost, "/v1/users", bearer, body, expected)
		var result iamv1.User
		if expected == http.StatusCreated && (json.Unmarshal(response.Body.Bytes(), &result) != nil || iamv1.ValidateUser(result) != nil) {
			t.Fatal("invalid created user")
		}
		if policy != "" && result.ID != "" {
			request(http.MethodPost, "/v1/policy-attachments", bearer, iamv1.CreatePolicyAttachmentRequest{Target: iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetUser, ID: string(result.ID)}, PolicyID: policy, PolicyResourceVersion: 1, RequestID: "explicit-member-policy-" + string(result.ID)}, http.StatusOK)
		}
		return result
	}
	setAlias := func(bearer, alias string, version uint64, expected int) iamv1.Account {
		t.Helper()
		response := request(http.MethodPost, "/v1/account:alias", bearer, map[string]any{"alias": alias, "resourceVersion": version, "requestId": "request-account-alias"}, expected)
		var result iamv1.Account
		if expected == http.StatusOK && (json.Unmarshal(response.Body.Bytes(), &result) != nil || iamv1.ValidateAccount(result) != nil) {
			t.Fatal("invalid account alias response")
		}
		return result
	}
	assertPaasDecision := func(bearer string, action iamv1.Action, expected bool, tenant string) {
		t.Helper()
		kind, _ := iamv1.ResourceKindForAction(action)
		body, _ := json.Marshal(iamv1.AuthorizationRequest{Action: action, Resource: iamv1.ResourceReference{Kind: kind, ID: "shared-account-resource"}, RequestID: "request-account-paas", CorrelationID: "request-account-paas"})
		response := performIAMRequestWithSubject(handler, body, paasCredential, bearer)
		var result iamv1.AuthorizationDecision
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &result) != nil || result.Allowed != expected || (expected && string(result.TenantID) != tenant) {
			t.Fatalf("account-bound decision status=%d allowed=%t tenant=%s", response.Code, result.Allowed, result.TenantID)
		}
	}
	rootIdentity := identity(root)
	rootCreate, rootCanCreate := findIAMCapability(rootIdentity.Capabilities, iamv1.ActionIAMAccountCreate, iamv1.ResourceAccount, "accounts")
	rootRead, rootCanRead := findIAMCapability(rootIdentity.Capabilities, iamv1.ActionIAMAccountRead, iamv1.ResourceAccount, "accounts")
	if !rootCanCreate || !rootCreate.Available || !rootCanRead || !rootRead.Available || rootIdentity.Account.RootIdentity.PrincipalID != "principal-admin" {
		t.Fatal("bootstrap identity not recognized")
	}
	newTenantBody := map[string]any{"id": tenantB, "displayName": "Customer B", "rootLoginName": "customer.admin", "rootDisplayName": "Customer administrator", "initialPassword": primaryBPassword, "requestId": "request-account-create"}
	opened := request(http.MethodPost, "/v1/accounts", root, newTenantBody, http.StatusCreated)
	var tenant iamv1.Account
	if json.Unmarshal(opened.Body.Bytes(), &tenant) != nil || tenant.ID != tenantB {
		t.Fatal("tenant onboarding did not create the requested account")
	}
	request(http.MethodPost, "/v1/accounts", root, newTenantBody, http.StatusConflict)
	primaryB := login("customer.admin", primaryBPassword, http.StatusOK)
	primaryIdentity := identity(primaryB)
	if capability, found := findIAMCapability(primaryIdentity.Capabilities, iamv1.ActionIAMAccountCreate, iamv1.ResourceAccount, "accounts"); !found || capability.Available {
		t.Fatal("new primary inherited platform account-opening capability")
	}
	if capability, found := findIAMCapability(primaryIdentity.Capabilities, iamv1.ActionIAMAccountRead, iamv1.ResourceAccount, "accounts"); !found || capability.Available {
		t.Fatal("new primary inherited platform account-directory capability")
	}
	passwordChange(primaryB, primaryBPassword, primaryBChanged)
	t.Run("event-bound historical producer authority", func(t *testing.T) {
		proveHistoricalProducerHTTP(t, ctx, handler, admin, map[string]string{tenantA: root, tenantB: primaryB})
	})
	request(http.MethodPost, "/v1/audit-producer:resolve", paasCredential,
		map[string]any{"organizationId": tenantB}, http.StatusBadRequest)
	request(http.MethodGet, "/v1/accounts", primaryB, nil, http.StatusForbidden)
	request(http.MethodPost, "/v1/accounts", primaryB, newTenantBody, http.StatusForbidden)
	setAlias(root, "customer-a", rootIdentity.Account.ResourceVersion, http.StatusOK)
	setAlias(primaryB, "customer-b", 1, http.StatusOK)
	setAlias(primaryB, "customer-a", 2, http.StatusConflict)
	setAlias(primaryB, tenantA, 2, http.StatusConflict)
	setAlias(root, "stale-alias", 1, http.StatusConflict)
	request(http.MethodPost, "/v1/users", root, map[string]any{"loginName": "bad.verifier", "displayName": "Rejected initial role", "initialPassword": childPassword, "initialRole": "INSTALLATION_VERIFIER", "requestId": "rejected-verifier-initial-role"}, http.StatusBadRequest)

	childA := createUser(root, "shared.user", iamv1.SystemPolicyPaaSViewer, http.StatusCreated)
	childB := createUser(primaryB, "shared.user", "", http.StatusCreated)
	if childA.ID == childB.ID || childA.AccountID != tenantA || childB.AccountID != tenantB {
		t.Fatal("same-name child identities were not isolated")
	}
	createUser(root, "shared.user", "", http.StatusConflict)
	login("shared.user", childPassword, http.StatusUnauthorized)
	login("shared.user@unknown-tenant", childPassword, http.StatusUnauthorized)
	login("customer.admin@customer-b", primaryBChanged, http.StatusUnauthorized)
	childSessionA := login("shared.user@customer-a", childPassword, http.StatusOK)
	childSessionB := login("shared.user@"+tenantB, childPassword, http.StatusOK)
	passwordChange(childSessionA, childPassword, childChangedA)
	passwordChange(childSessionB, childPassword, childChangedB)
	login("shared.user@customer-b", childChangedA, http.StatusUnauthorized)
	if id := identity(childSessionA); id.User.ID != childA.ID || id.Account.ID != tenantA || func() bool {
		capability, found := findIAMCapability(id.Capabilities, iamv1.ActionIAMAccountCreate, iamv1.ResourceAccount, "accounts")
		return !found || capability.Available
	}() {
		t.Fatal("wrong tenant or platform capability in child identity")
	}
	if len(identity(childSessionB).PolicySources) != 0 {
		t.Fatal("new child gained implicit business permissions")
	}
	assertPaasDecision(childSessionA, iamv1.ActionManagedServiceInstallationRead, true, tenantA)
	assertPaasDecision(childSessionA, iamv1.ActionManagedServiceInstallationCreate, false, "")
	assertPaasDecision(childSessionB, iamv1.ActionManagedServiceInstallationRead, false, "")
	request(http.MethodGet, "/v1/users", childSessionA, nil, http.StatusForbidden)
	setAlias(childSessionA, "forged-alias", 2, http.StatusForbidden)
	request(http.MethodPost, "/v1/policy-attachments", childSessionA, map[string]any{"target": iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetUser, ID: string(childA.ID)}, "policyId": iamv1.SystemPolicyAccountAdministrator, "policyResourceVersion": 1, "requestId": "request-escalate"}, http.StatusForbidden)

	listResponse := request(http.MethodGet, "/v1/users", root, nil, http.StatusOK)
	var users iamv1.UserList
	if json.Unmarshal(listResponse.Body.Bytes(), &users) != nil || iamv1.ValidateUserList(users) != nil {
		t.Fatal("invalid tenant directory")
	}
	var childBinding iamv1.PolicyAttachmentID
	for _, entry := range users.Items {
		if entry.User.AccountID != tenantA {
			t.Fatal("directory leaked a different tenant or service identity")
		}
		if entry.User.ID == rootIdentity.Account.RootIdentity.PrincipalID {
			t.Fatal("root identity leaked into the ordinary user directory")
		}
		if entry.User.ID == childA.ID {
			if len(entry.PolicyAttachments) != 1 || entry.PolicyAttachments[0].PolicyID != iamv1.SystemPolicyPaaSViewer {
				t.Fatal("explicit user policy attachment missing")
			}
			childBinding = entry.PolicyAttachments[0].ID
			for _, expected := range []struct {
				action iamv1.Action
				kind   iamv1.ResourceKind
				id     string
			}{
				{iamv1.ActionIAMUserRead, iamv1.ResourceUser, string(childA.ID)},
				{iamv1.ActionIAMUserUpdate, iamv1.ResourceUser, string(childA.ID)},
				{iamv1.ActionIAMUserSetStatus, iamv1.ResourceUser, string(childA.ID)},
				{iamv1.ActionIAMUserPasswordReset, iamv1.ResourceUser, string(childA.ID)},
				{iamv1.ActionIAMPolicyAttachmentCreate, iamv1.ResourceUser, string(childA.ID)},
				{iamv1.ActionIAMPlatformPolicyAttachmentCreate, iamv1.ResourceUser, string(childA.ID)},
				{iamv1.ActionIAMPolicyAttachmentRevoke, iamv1.ResourcePolicyAttachment, string(childBinding)},
			} {
				capability, found := findIAMCapability(entry.Capabilities, expected.action, expected.kind, expected.id)
				if !found || !capability.Available || capability.RestrictionReason != "" {
					t.Fatalf("authorized target capability %s is unavailable", expected.action)
				}
			}
			deleteCapability, deleteFound := findIAMCapability(entry.Capabilities, iamv1.ActionIAMUserDelete, iamv1.ResourceUser, string(childA.ID))
			if !deleteFound || deleteCapability.Available || deleteCapability.RestrictionReason != iamv1.CapabilityTargetMustBeDisabled {
				t.Fatal("active target deletion capability did not require prior disable")
			}
		}
	}
	if childBinding == "" {
		t.Fatal("created child missing from directory")
	}
	request(http.MethodPost, "/v1/policy-attachments", root, map[string]any{"target": iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetUser, ID: string(childB.ID)}, "policyId": iamv1.SystemPolicyAccountAdministrator, "policyResourceVersion": 1, "requestId": "request-cross-tenant-role"}, http.StatusForbidden)
	request(http.MethodPost, "/v1/policy-attachments/"+string(childBinding)+":revoke", primaryB, map[string]any{"resourceVersion": 1, "requestId": "request-cross-tenant-revoke"}, http.StatusForbidden)
	for _, target := range []string{string(childB.ID), "principal-admin", "service-paas"} {
		request(http.MethodPost, "/v1/users/"+target+":set-status", root, map[string]any{"status": "DISABLED", "resourceVersion": 1, "requestId": "request-protected-status"}, http.StatusForbidden)
		request(http.MethodPost, "/v1/users/"+target+":reset-password", root, map[string]any{"initialPassword": resetPassword, "resourceVersion": 1, "requestId": "request-protected-password"}, http.StatusForbidden)
	}
	request(http.MethodPost, "/v1/policy-attachments/bootstrap-admin-binding:revoke", root, map[string]any{"resourceVersion": 1, "requestId": "request-primary-binding"}, http.StatusForbidden)
	request(http.MethodPost, "/v1/policy-attachments/primary-admin-binding:revoke", primaryB, map[string]any{"resourceVersion": 1, "requestId": "request-primary-binding"}, http.StatusForbidden)
	for _, path := range []string{"/v1/users?tenantId=" + tenantB, "/v1/users?after=x&after=y", "/v1/users?after=", "/v1/accounts?organizationId=" + tenantB, "/v1/auth/me?tenantId=" + tenantB} {
		request(http.MethodGet, path, root, nil, http.StatusBadRequest)
	}
	request(http.MethodPost, "/v1/account:alias", root, map[string]any{"alias": "forged", "tenantId": tenantB, "resourceVersion": 2, "requestId": "request-forged-alias"}, http.StatusBadRequest)
	request(http.MethodGet, "/v1/users?after="+string(childB.ID), root, nil, http.StatusBadRequest)

	delegated := createUser(root, "delegated.admin", iamv1.SystemPolicyAccountAdministrator, http.StatusCreated)
	delegatedSession := login("delegated.admin@customer-a", childPassword, http.StatusOK)
	passwordChange(delegatedSession, childPassword, childChangedA)
	if capability, found := findIAMCapability(identity(delegatedSession).Capabilities, iamv1.ActionIAMAccountCreate, iamv1.ResourceAccount, "accounts"); !found || capability.Available {
		t.Fatal("assignable administrator role granted platform access")
	}
	request(http.MethodGet, "/v1/accounts", delegatedSession, nil, http.StatusForbidden)
	request(http.MethodPost, "/v1/accounts", delegatedSession, newTenantBody, http.StatusForbidden)
	selfDirectory := request(http.MethodGet, "/v1/users", delegatedSession, nil, http.StatusOK)
	var selfUsers iamv1.UserList
	if json.Unmarshal(selfDirectory.Body.Bytes(), &selfUsers) != nil || iamv1.ValidateUserList(selfUsers) != nil {
		t.Fatal("delegated administrator directory is invalid")
	}
	foundSelf := false
	for _, entry := range selfUsers.Items {
		if entry.User.ID != delegated.ID {
			continue
		}
		foundSelf = true
		for _, action := range []iamv1.Action{iamv1.ActionIAMUserDelete, iamv1.ActionIAMUserSetStatus, iamv1.ActionIAMUserPasswordReset} {
			capability, found := findIAMCapability(entry.Capabilities, action, iamv1.ResourceUser, string(delegated.ID))
			if !found || capability.Available || capability.RestrictionReason != iamv1.CapabilitySelfProtected {
				t.Fatalf("self-protection capability %s is invalid", action)
			}
		}
	}
	if !foundSelf {
		t.Fatal("delegated administrator missing from its own user directory")
	}
	request(http.MethodPost, "/v1/users/"+string(delegated.ID)+":set-status", delegatedSession, map[string]any{"status": "DISABLED", "resourceVersion": 2, "requestId": "request-self-disable"}, http.StatusForbidden)
	setAlias(delegatedSession, "customer-a-new", 2, http.StatusOK)
	login("shared.user@customer-a", childChangedA, http.StatusUnauthorized)
	login("shared.user@customer-a-new", childChangedA, http.StatusOK)
	login("shared.user@"+tenantA, childChangedA, http.StatusOK)
	if identity(childSessionA).Account.ID != tenantA {
		t.Fatal("alias change altered existing session authority")
	}
	setAlias(primaryB, "customer-a", 2, http.StatusConflict)
	newTenantBody["id"] = "customer-a"
	newTenantBody["rootLoginName"] = "collision.admin"
	request(http.MethodPost, "/v1/accounts", root, newTenantBody, http.StatusConflict)
	setAlias(root, "customer-a", 3, http.StatusOK)
	login("shared.user@customer-a-new", childChangedA, http.StatusUnauthorized)
	login("shared.user@customer-a", childChangedA, http.StatusOK)

	request(http.MethodPost, "/v1/policy-attachments/"+string(childBinding)+":revoke", root, map[string]any{"resourceVersion": 1, "requestId": "request-child-revoke"}, http.StatusOK)
	assertPaasDecision(childSessionA, iamv1.ActionManagedServiceInstallationRead, false, "")
	grant := request(http.MethodPost, "/v1/policy-attachments", primaryB, map[string]any{"target": iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetUser, ID: string(childB.ID)}, "policyId": iamv1.SystemPolicyPaaSDeveloper, "policyResourceVersion": 1, "requestId": "request-child-grant"}, http.StatusOK)
	if bytes.Contains(grant.Body.Bytes(), []byte(tenantA)) {
		t.Fatal("grant selected the wrong tenant")
	}
	assertPaasDecision(childSessionB, iamv1.ActionManagedServiceInstallationCreate, true, tenantB)

	statusPath := "/v1/users/" + string(childA.ID) + ":set-status"
	request(http.MethodPost, statusPath, root, map[string]any{"status": "DISABLED", "resourceVersion": 1, "requestId": "request-stale-status"}, http.StatusConflict)
	request(http.MethodPost, statusPath, root, map[string]any{"status": "DISABLED", "resourceVersion": 2, "requestId": "request-disable"}, http.StatusOK)
	request(http.MethodGet, "/v1/auth/me", childSessionA, nil, http.StatusUnauthorized)
	login("shared.user@customer-a", childChangedA, http.StatusUnauthorized)
	disabledDirectory := request(http.MethodGet, "/v1/users", root, nil, http.StatusOK)
	var disabledUsers iamv1.UserList
	if json.Unmarshal(disabledDirectory.Body.Bytes(), &disabledUsers) != nil || iamv1.ValidateUserList(disabledUsers) != nil {
		t.Fatal("disabled target directory is invalid")
	}
	foundDisabled := false
	for _, entry := range disabledUsers.Items {
		if entry.User.ID != childA.ID {
			continue
		}
		foundDisabled = true
		for _, action := range []iamv1.Action{iamv1.ActionIAMPolicyAttachmentCreate, iamv1.ActionIAMPlatformPolicyAttachmentCreate} {
			capability, found := findIAMCapability(entry.Capabilities, action, iamv1.ResourceUser, string(childA.ID))
			if !found || capability.Available || capability.RestrictionReason != iamv1.CapabilityTargetDisabled {
				t.Fatalf("disabled-target capability %s is invalid", action)
			}
		}
	}
	if !foundDisabled {
		t.Fatal("disabled target missing from user directory")
	}
	request(http.MethodPost, statusPath, root, map[string]any{"status": "ACTIVE", "resourceVersion": 3, "requestId": "request-enable"}, http.StatusOK)
	request(http.MethodGet, "/v1/auth/me", childSessionA, nil, http.StatusUnauthorized)
	activeOne := login("shared.user@customer-a", childChangedA, http.StatusOK)
	activeTwo := login("shared.user@"+tenantA, childChangedA, http.StatusOK)
	request(http.MethodPost, "/v1/users/"+string(childA.ID)+":reset-password", root, map[string]any{"initialPassword": resetPassword, "resourceVersion": 4, "requestId": "request-reset"}, http.StatusOK)
	for _, bearer := range []string{activeOne, activeTwo} {
		request(http.MethodGet, "/v1/auth/me", bearer, nil, http.StatusUnauthorized)
	}
	login("shared.user@customer-a", childChangedA, http.StatusUnauthorized)
	resetSession := login("shared.user@customer-a", resetPassword, http.StatusOK)
	if !identity(resetSession).User.MustChangePassword {
		t.Fatal("reset password did not restrict the next login")
	}
	pendingDirectory := request(http.MethodGet, "/v1/users", root, nil, http.StatusOK)
	var pendingUsers iamv1.UserList
	if json.Unmarshal(pendingDirectory.Body.Bytes(), &pendingUsers) != nil || iamv1.ValidateUserList(pendingUsers) != nil {
		t.Fatal("password-change target directory is invalid")
	}
	foundPending := false
	for _, entry := range pendingUsers.Items {
		if entry.User.ID != childA.ID {
			continue
		}
		foundPending = true
		tenantCapability, tenantFound := findIAMCapability(entry.Capabilities, iamv1.ActionIAMPolicyAttachmentCreate, iamv1.ResourceUser, string(childA.ID))
		platformCapability, platformFound := findIAMCapability(entry.Capabilities, iamv1.ActionIAMPlatformPolicyAttachmentCreate, iamv1.ResourceUser, string(childA.ID))
		if !tenantFound || !tenantCapability.Available || !platformFound || platformCapability.Available ||
			platformCapability.RestrictionReason != iamv1.CapabilityTargetCredentialChangeRequired {
			t.Fatal("credential-change protection did not distinguish tenant and installation authority")
		}
	}
	if !foundPending {
		t.Fatal("password-change target missing from user directory")
	}
	assertPaasDecision(resetSession, iamv1.ActionManagedServiceInstallationRead, false, "")
	if identity(childSessionB).User.ID != childB.ID {
		t.Fatal("reset leaked across tenants")
	}

	// Reapply against populated multi-tenant state; no user, alias, session, or
	// authority identity may be replaced by bootstrap re-initialization.
	applyIAMSchema(t, ctx, admin)
	if identity(root).Account.LoginAlias == nil || *identity(root).Account.LoginAlias != "customer-a" || identity(primaryB).Account.ID != tenantB {
		t.Fatal("migration replay did not preserve account state")
	}
	login("shared.user@customer-b", childChangedB, http.StatusOK)
	beforePaging := request(http.MethodGet, "/v1/users", primaryB, nil, http.StatusOK)
	var existingUsers iamv1.UserList
	if json.Unmarshal(beforePaging.Body.Bytes(), &existingUsers) != nil || existingUsers.NextAfter != "" {
		t.Fatal("unable to establish the directory before pagination")
	}
	expectedUsers := map[iamv1.PrincipalID]bool{}
	for _, entry := range existingUsers.Items {
		expectedUsers[entry.User.ID] = true
	}
	for i := 0; i < 101; i++ {
		created := createUser(primaryB, fmt.Sprintf("page.user.%03d", i), "", http.StatusCreated)
		expectedUsers[created.ID] = true
	}
	pageOne := request(http.MethodGet, "/v1/users", primaryB, nil, http.StatusOK)
	var first, second iamv1.UserList
	if json.Unmarshal(pageOne.Body.Bytes(), &first) != nil || len(first.Items) != 100 || first.NextAfter == "" {
		t.Fatal("principal page is not bounded")
	}
	pageTwo := request(http.MethodGet, "/v1/users?after="+first.NextAfter, primaryB, nil, http.StatusOK)
	if json.Unmarshal(pageTwo.Body.Bytes(), &second) != nil || len(second.Items) > 100 || second.NextAfter != "" {
		t.Fatal("principal continuation is incomplete")
	}
	seen := map[iamv1.PrincipalID]bool{}
	for _, entry := range append(first.Items, second.Items...) {
		if seen[entry.User.ID] || entry.User.AccountID != tenantB || !expectedUsers[entry.User.ID] {
			t.Fatal("directory cursor duplicated or crossed tenants")
		}
		seen[entry.User.ID] = true
	}
	if len(seen) != len(expectedUsers) {
		t.Fatal("directory lost users across pages")
	}
	accountPage := request(http.MethodGet, "/v1/accounts", root, nil, http.StatusOK)
	var accounts iamv1.AccountList
	if json.Unmarshal(accountPage.Body.Bytes(), &accounts) != nil || iamv1.ValidateAccountList(accounts) != nil || len(accounts.Items) != 2 {
		t.Fatal("failed onboarding left a partial tenant")
	}
	for _, entry := range accounts.Items {
		statusCapability, statusFound := findIAMCapability(entry.Capabilities, iamv1.ActionIAMAccountSetStatus, iamv1.ResourceAccount, string(entry.Account.ID))
		recoveryCapability, recoveryFound := findIAMCapability(entry.Capabilities, iamv1.ActionIAMAccountRootCredentialsRecover, iamv1.ResourceAccount, string(entry.Account.ID))
		if !statusFound || !recoveryFound {
			t.Fatal("account directory omitted lifecycle capabilities")
		}
		if entry.Account.ID == tenantA {
			if statusCapability.Available || statusCapability.RestrictionReason != iamv1.CapabilitySystemAccountProtected ||
				recoveryCapability.Available || recoveryCapability.RestrictionReason != iamv1.CapabilityInstallationAuthorityProtected {
				t.Fatal("system account protection was inferred from a role name or omitted")
			}
		} else if !statusCapability.Available || !recoveryCapability.Available {
			t.Fatal("ordinary account lifecycle was unavailable to its authorized platform actor")
		}
	}
	// Account directories use the same signed protocol but a distinct platform
	// query. Exercise the real onboarding transaction, not synthesized rows.
	for index := 0; index < 99; index++ {
		request(http.MethodPost, "/v1/accounts", root, map[string]any{
			"id": fmt.Sprintf("cursor-account-%03d", index), "displayName": "Cursor account",
			"rootLoginName": fmt.Sprintf("cursor.root.%03d", index), "rootDisplayName": "Cursor root",
			"initialPassword": childPassword, "requestId": fmt.Sprintf("cursor-account-create-%03d", index),
		}, http.StatusCreated)
	}
	var accountFirst, accountSecond iamv1.AccountList
	firstResponse := request(http.MethodGet, "/v1/accounts", root, nil, http.StatusOK)
	if json.Unmarshal(firstResponse.Body.Bytes(), &accountFirst) != nil || iamv1.ValidateAccountList(accountFirst) != nil || len(accountFirst.Items) != 100 || accountFirst.NextAfter == "" {
		t.Fatal("account directory did not issue a bounded signed continuation")
	}
	secondResponse := request(http.MethodGet, "/v1/accounts?after="+accountFirst.NextAfter, root, nil, http.StatusOK)
	if json.Unmarshal(secondResponse.Body.Bytes(), &accountSecond) != nil || iamv1.ValidateAccountList(accountSecond) != nil || len(accountSecond.Items) != 1 || accountSecond.NextAfter != "" || accountSecond.Items[0].Account.ID <= accountFirst.Items[99].Account.ID {
		t.Fatal("account signed directory did not yield 100+1 distinct accounts")
	}
	request(http.MethodGet, "/v1/users?after="+accountFirst.NextAfter, root, nil, http.StatusUnprocessableEntity)
	request(http.MethodGet, "/v1/accounts?after="+accountFirst.NextAfter, primaryB, nil, http.StatusForbidden)
	request(http.MethodGet, "/v1/users?after="+first.NextAfter, root, nil, http.StatusUnprocessableEntity)
	// Two account administrators cannot acquire the same alias concurrently.
	startAliasRace := make(chan struct{})
	aliasResults := make(chan int, 2)
	for _, actor := range []string{root, primaryB} {
		version := identity(actor).Account.ResourceVersion
		body, err := json.Marshal(iamv1.SetAccountAliasRequest{Alias: "concurrent-company", ResourceVersion: version, RequestID: "request-alias-race"})
		if err != nil {
			t.Fatal(err)
		}
		go func(bearer string, encoded []byte) {
			<-startAliasRace
			aliasResults <- performIAMRequest(handler, http.MethodPost, "/v1/account:alias", bearer, encoded).Code
		}(actor, body)
	}
	close(startAliasRace)
	firstStatus, secondStatus := <-aliasResults, <-aliasResults
	if !((firstStatus == http.StatusOK && secondStatus == http.StatusConflict) || (secondStatus == http.StatusOK && firstStatus == http.StatusConflict)) {
		t.Fatalf("concurrent alias acquisition statuses=%d,%d", firstStatus, secondStatus)
	}
	for _, actor := range []struct{ bearer, alias string }{{root, "customer-a"}, {primaryB, "customer-b"}} {
		setAlias(actor.bearer, actor.alias, identity(actor.bearer).Account.ResourceVersion, http.StatusOK)
	}

	for _, action := range []string{"iam.account.created", "iam.account.alias-set", "iam.user.status-set", "iam.user.password-reset"} {
		var correlated bool
		if err := admin.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM iam.audit_outbox AS event JOIN iam.authorization_decisions AS decision ON decision.tenant_id=event.tenant_id AND decision.id=event.event_document->>'iamDecisionId' WHERE event.event_document->>'action'=$1 AND decision.allowed)`, action).Scan(&correlated); err != nil || !correlated {
			t.Fatalf("account mutation %s lacks atomic audit decision: %v", action, err)
		}
	}
	t.Run("user detail profile and irreversible deletion", func(t *testing.T) {
		proveUserProfileAndDeletion(t, ctx, handler, admin, root, primaryB)
	})
	assertIAMSecretsAbsent(t, ctx, admin, primaryBPassword, primaryBChanged, childPassword, childChangedA, childChangedB, resetPassword, primaryB, childSessionA, childSessionB, activeOne, activeTwo, resetSession)
	t.Run("platform tenant lifecycle and original primary recovery", func(t *testing.T) {
		proveTenantLifecycleHTTP(t, ctx, handler, admin, root, primaryB)
	})
}

func proveUserProfileAndDeletion(t *testing.T, ctx context.Context, handler http.Handler, database *pgx.Conn, root, otherTenantRoot string) {
	t.Helper()
	const accountID = "organization-http-integration"
	const initialPassword = "Profile-Initial-Password-47!"
	const changedPassword = "Profile-Changed-Password-58!"
	request := func(method, path, bearer string, body any, expected int) *httptest.ResponseRecorder {
		t.Helper()
		var encoded []byte
		var err error
		if body != nil {
			encoded, err = json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
		}
		response := performIAMRequest(handler, method, path, bearer, encoded)
		if response.Code != expected {
			t.Fatalf("user lifecycle %s %s: status=%d want=%d body=%s", method, path, response.Code, expected, response.Body.String())
		}
		return response
	}
	create := func(name string) iamv1.User {
		t.Helper()
		response := request(http.MethodPost, "/v1/users", root, map[string]any{
			"loginName": name, "displayName": "Disposable account user", "initialPassword": initialPassword,
			"requestId": "request-create-" + strings.ReplaceAll(name, ".", "-"),
		}, http.StatusCreated)
		var result iamv1.User
		if json.Unmarshal(response.Body.Bytes(), &result) != nil || iamv1.ValidateUser(result) != nil {
			t.Fatal("invalid profile/deletion user")
		}
		return result
	}
	grant := func(user iamv1.User, policy iamv1.PolicyID, requestID string) iamv1.PolicyAttachment {
		t.Helper()
		response := request(http.MethodPost, "/v1/policy-attachments", root, iamv1.CreatePolicyAttachmentRequest{
			Target:   iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetUser, ID: string(user.ID)},
			PolicyID: policy, PolicyResourceVersion: 1, RequestID: requestID,
		}, http.StatusOK)
		var result iamv1.PolicyAttachment
		if json.Unmarshal(response.Body.Bytes(), &result) != nil || iamv1.ValidatePolicyAttachment(result) != nil {
			t.Fatal("invalid profile/deletion attachment")
		}
		return result
	}
	login := func(name, password string, expected int) string {
		t.Helper()
		response := request(http.MethodPost, "/v1/auth/login", "", map[string]any{
			"loginName": name, "password": password, "requestId": "request-login-" + strings.ReplaceAll(name, "@", "-"),
		}, expected)
		if expected != http.StatusOK {
			return ""
		}
		var result struct {
			Credential string `json:"credential"`
		}
		if json.Unmarshal(response.Body.Bytes(), &result) != nil || result.Credential == "" {
			t.Fatal("profile/deletion login did not issue a credential")
		}
		return result.Credential
	}
	read := func(bearer string, id iamv1.PrincipalID, expected int) iamv1.UserAccess {
		t.Helper()
		response := request(http.MethodGet, "/v1/users/"+string(id), bearer, nil, expected)
		var result iamv1.UserAccess
		if expected == http.StatusOK && (json.Unmarshal(response.Body.Bytes(), &result) != nil || iamv1.ValidateUserAccess(result) != nil) {
			t.Fatal("invalid user detail")
		}
		return result
	}

	user := create("profile.delete")
	viewer := grant(user, iamv1.SystemPolicyPaaSViewer, "request-profile-viewer")
	grant(user, iamv1.SystemPolicyAccountAdministrator, "request-profile-administrator")
	bearer := login("profile.delete@"+accountID, initialPassword, http.StatusOK)
	request(http.MethodPost, "/v1/auth/password", bearer, map[string]any{
		"currentPassword": initialPassword, "newPassword": changedPassword, "requestId": "request-profile-password",
	}, http.StatusOK)
	detail := read(root, user.ID, http.StatusOK)
	if detail.User.ResourceVersion != 2 || detail.User.LoginName != user.LoginName || len(detail.PolicyAttachments) != 2 {
		t.Fatal("user detail lost its immutable identity or current policy attachments")
	}
	for _, action := range []iamv1.Action{iamv1.ActionIAMUserRead, iamv1.ActionIAMUserUpdate} {
		capability, found := findIAMCapability(detail.Capabilities, action, iamv1.ResourceUser, string(user.ID))
		if !found || !capability.Available || capability.RestrictionReason != "" {
			t.Fatalf("user detail capability %s is unavailable", action)
		}
	}
	deleteCapability, found := findIAMCapability(detail.Capabilities, iamv1.ActionIAMUserDelete, iamv1.ResourceUser, string(user.ID))
	if !found || deleteCapability.Available || deleteCapability.RestrictionReason != iamv1.CapabilityTargetMustBeDisabled {
		t.Fatal("active user detail did not require prior disable")
	}
	self := read(bearer, user.ID, http.StatusOK)
	selfDelete, found := findIAMCapability(self.Capabilities, iamv1.ActionIAMUserDelete, iamv1.ResourceUser, string(user.ID))
	if !found || selfDelete.Available || selfDelete.RestrictionReason != iamv1.CapabilitySelfProtected {
		t.Fatal("user detail did not protect self deletion")
	}
	request(http.MethodPost, "/v1/users/"+string(user.ID)+":delete", bearer,
		iamv1.DeleteUserRequest{ResourceVersion: detail.User.ResourceVersion, RequestID: "request-self-delete"}, http.StatusForbidden)
	read(otherTenantRoot, user.ID, http.StatusForbidden)
	read(root, "principal-admin", http.StatusForbidden)
	read(root, "service-paas", http.StatusForbidden)
	request(http.MethodGet, "/v1/users/"+string(user.ID)+"?accountId=organization-customer-b", root, nil, http.StatusBadRequest)
	request(http.MethodGet, "/v1/users/"+string(user.ID), root, map[string]any{"accountId": "organization-customer-b"}, http.StatusBadRequest)
	request(http.MethodPost, "/v1/users/"+string(user.ID)+":unknown", root, map[string]any{}, http.StatusNotFound)
	request(http.MethodPost, "/v1/users/"+string(user.ID)+":update", root, map[string]any{
		"displayName": "Forged", "resourceVersion": detail.User.ResourceVersion, "requestId": "request-forged-profile", "accountId": "organization-customer-b",
	}, http.StatusBadRequest)
	request(http.MethodPost, "/v1/users/"+string(user.ID)+":update", root, iamv1.UpdateUserRequest{
		DisplayName: "Stale profile", ResourceVersion: 1, RequestID: "request-stale-profile",
	}, http.StatusConflict)
	updatedResponse := request(http.MethodPost, "/v1/users/"+string(user.ID)+":update", root, iamv1.UpdateUserRequest{
		DisplayName: "Renamed account user", ResourceVersion: detail.User.ResourceVersion, RequestID: "request-profile-update",
	}, http.StatusOK)
	var updated iamv1.User
	if json.Unmarshal(updatedResponse.Body.Bytes(), &updated) != nil || iamv1.ValidateUser(updated) != nil ||
		updated.DisplayName != "Renamed account user" || updated.LoginName != user.LoginName || updated.AccountID != user.AccountID || updated.ResourceVersion != 3 {
		t.Fatal("profile update changed immutable identity fields")
	}
	request(http.MethodPost, "/v1/users/"+string(user.ID)+":delete", root,
		iamv1.DeleteUserRequest{ResourceVersion: updated.ResourceVersion, RequestID: "request-active-delete"}, http.StatusConflict)
	request(http.MethodPost, "/v1/users/"+string(user.ID)+":set-status", root,
		iamv1.SetUserStatusRequest{Status: iamv1.PrincipalDisabled, ResourceVersion: updated.ResourceVersion, RequestID: "request-profile-disable"}, http.StatusOK)
	read(root, user.ID, http.StatusOK)
	request(http.MethodPost, "/v1/users/"+string(user.ID)+":delete", otherTenantRoot,
		iamv1.DeleteUserRequest{ResourceVersion: 4, RequestID: "request-cross-account-delete"}, http.StatusForbidden)
	request(http.MethodPost, "/v1/users/"+string(user.ID)+":delete", root,
		iamv1.DeleteUserRequest{ResourceVersion: 3, RequestID: "request-stale-delete"}, http.StatusConflict)
	var before struct {
		Deleted        bool
		Credentials    int
		LiveAttachment int
		DeleteFacts    int
	}
	if err := database.QueryRow(ctx, `SELECT principal.deleted_at IS NOT NULL,
		(SELECT count(*) FROM iam.user_credentials AS credential WHERE credential.tenant_id=principal.tenant_id AND credential.principal_id=principal.id),
		(SELECT count(*) FROM iam.policy_attachments AS attachment WHERE attachment.tenant_id=principal.tenant_id AND attachment.target_id=principal.id AND attachment.revoked_at IS NULL),
		(SELECT count(*) FROM iam.audit_outbox AS outbox WHERE outbox.tenant_id=principal.tenant_id AND outbox.event_document->>'action'='iam.user.deleted' AND outbox.event_document#>>'{target,id}'=principal.id)
		FROM iam.principals AS principal WHERE principal.tenant_id=$1 AND principal.id=$2`, accountID, user.ID).
		Scan(&before.Deleted, &before.Credentials, &before.LiveAttachment, &before.DeleteFacts); err != nil || before.Deleted || before.Credentials != 1 || before.LiveAttachment != 2 || before.DeleteFacts != 0 {
		t.Fatalf("failed deletion changed state: before=%#v err=%v", before, err)
	}
	deletedResponse := request(http.MethodPost, "/v1/users/"+string(user.ID)+":delete", root,
		iamv1.DeleteUserRequest{ResourceVersion: 4, RequestID: "request-profile-delete"}, http.StatusOK)
	var deletion iamv1.UserDeletion
	if json.Unmarshal(deletedResponse.Body.Bytes(), &deletion) != nil || iamv1.ValidateUserDeletion(deletion) != nil ||
		deletion.AccountID != accountID || deletion.ID != user.ID || deletion.LoginName != user.LoginName || deletion.ResourceVersion != 5 {
		t.Fatal("invalid irreversible deletion receipt")
	}
	read(root, user.ID, http.StatusForbidden)
	request(http.MethodGet, "/v1/auth/me", bearer, nil, http.StatusUnauthorized)
	login("profile.delete@"+accountID, changedPassword, http.StatusUnauthorized)
	request(http.MethodPost, "/v1/users", root, map[string]any{
		"loginName": user.LoginName, "displayName": "Reused identity", "initialPassword": initialPassword, "requestId": "request-reuse-deleted-login",
	}, http.StatusConflict)
	list := request(http.MethodGet, "/v1/users", root, nil, http.StatusOK)
	var directory iamv1.UserList
	if json.Unmarshal(list.Body.Bytes(), &directory) != nil || iamv1.ValidateUserList(directory) != nil {
		t.Fatal("user directory invalid after deletion")
	}
	for _, item := range directory.Items {
		if item.User.ID == user.ID {
			t.Fatal("deleted user remained in the live directory")
		}
	}
	var status string
	var mustChange bool
	var deletedAt *time.Time
	var credentials, sessions, activeSessions, attachments, activeAttachments, loginNames, updatedFacts, deletedFacts int
	if err := database.QueryRow(ctx, `SELECT principal.status,principal.must_change_password,principal.deleted_at,
		(SELECT count(*) FROM iam.user_credentials AS credential WHERE credential.tenant_id=principal.tenant_id AND credential.principal_id=principal.id),
		(SELECT count(*) FROM iam.sessions AS session WHERE session.tenant_id=principal.tenant_id AND session.principal_id=principal.id),
		(SELECT count(*) FROM iam.sessions AS session WHERE session.tenant_id=principal.tenant_id AND session.principal_id=principal.id AND session.status='ACTIVE'),
		(SELECT count(*) FROM iam.policy_attachments AS attachment WHERE attachment.tenant_id=principal.tenant_id AND attachment.target_id=principal.id),
		(SELECT count(*) FROM iam.policy_attachments AS attachment WHERE attachment.tenant_id=principal.tenant_id AND attachment.target_id=principal.id AND attachment.revoked_at IS NULL),
		(SELECT count(*) FROM iam.login_index AS login WHERE login.tenant_id=principal.tenant_id AND login.principal_id=principal.id AND login.login_name=principal.login_name),
		(SELECT count(*) FROM iam.audit_outbox AS outbox WHERE outbox.tenant_id=principal.tenant_id AND outbox.event_document->>'action'='iam.user.updated' AND outbox.event_document#>>'{target,id}'=principal.id),
		(SELECT count(*) FROM iam.audit_outbox AS outbox WHERE outbox.tenant_id=principal.tenant_id AND outbox.event_document->>'action'='iam.user.deleted' AND outbox.event_document#>>'{target,id}'=principal.id)
		FROM iam.principals AS principal WHERE principal.tenant_id=$1 AND principal.id=$2`, accountID, user.ID).
		Scan(&status, &mustChange, &deletedAt, &credentials, &sessions, &activeSessions, &attachments, &activeAttachments, &loginNames, &updatedFacts, &deletedFacts); err != nil ||
		status != "DISABLED" || mustChange || deletedAt == nil || credentials != 0 || sessions == 0 || activeSessions != 0 || attachments != 2 || activeAttachments != 0 || loginNames != 1 || updatedFacts != 1 || deletedFacts != 1 {
		t.Fatalf("deleted user state is incomplete: status=%s mustChange=%t deleted=%v credential=%d sessions=%d/%d attachments=%d/%d login=%d facts=%d/%d err=%v",
			status, mustChange, deletedAt, credentials, activeSessions, sessions, activeAttachments, attachments, loginNames, updatedFacts, deletedFacts, err)
	}
	if viewer.ID == "" {
		t.Fatal("viewer attachment fixture was not created")
	}
	applyIAMSchema(t, ctx, database)
	read(root, user.ID, http.StatusForbidden)
	request(http.MethodGet, "/v1/auth/me", bearer, nil, http.StatusUnauthorized)
	login("profile.delete@"+accountID, changedPassword, http.StatusUnauthorized)
	request(http.MethodPost, "/v1/users", root, map[string]any{
		"loginName": user.LoginName, "displayName": "Replay reuse attack", "initialPassword": initialPassword, "requestId": "request-replay-reuse-deleted-login",
	}, http.StatusConflict)
	var replayDeleted, replayReserved bool
	var replayCredentials, replayActiveSessions, replayActiveAttachments, replayDeleteFacts int
	if err := database.QueryRow(ctx, `SELECT principal.deleted_at IS NOT NULL,
		EXISTS(SELECT 1 FROM iam.login_index AS login WHERE login.tenant_id=principal.tenant_id AND login.principal_id=principal.id AND login.login_name=principal.login_name),
		(SELECT count(*) FROM iam.user_credentials AS credential WHERE credential.tenant_id=principal.tenant_id AND credential.principal_id=principal.id),
		(SELECT count(*) FROM iam.sessions AS session WHERE session.tenant_id=principal.tenant_id AND session.principal_id=principal.id AND session.status='ACTIVE'),
		(SELECT count(*) FROM iam.policy_attachments AS attachment WHERE attachment.tenant_id=principal.tenant_id AND attachment.target_id=principal.id AND attachment.revoked_at IS NULL),
		(SELECT count(*) FROM iam.audit_outbox AS outbox WHERE outbox.tenant_id=principal.tenant_id AND outbox.event_document->>'action'='iam.user.deleted' AND outbox.event_document#>>'{target,id}'=principal.id)
		FROM iam.principals AS principal WHERE principal.tenant_id=$1 AND principal.id=$2`, accountID, user.ID).
		Scan(&replayDeleted, &replayReserved, &replayCredentials, &replayActiveSessions, &replayActiveAttachments, &replayDeleteFacts); err != nil ||
		!replayDeleted || !replayReserved || replayCredentials != 0 || replayActiveSessions != 0 || replayActiveAttachments != 0 || replayDeleteFacts != 1 {
		t.Fatalf("migration replay revived deleted authority: deleted=%t reserved=%t credentials=%d sessions=%d attachments=%d facts=%d err=%v",
			replayDeleted, replayReserved, replayCredentials, replayActiveSessions, replayActiveAttachments, replayDeleteFacts, err)
	}

	protected := create("platform.delete")
	protectedBearer := login("platform.delete@"+accountID, initialPassword, http.StatusOK)
	request(http.MethodPost, "/v1/auth/password", protectedBearer, map[string]any{
		"currentPassword": initialPassword, "newPassword": changedPassword, "requestId": "request-platform-password",
	}, http.StatusOK)
	platformAttachment := grant(protected, iamv1.SystemPolicyPlatformOperator, "request-platform-protection")
	request(http.MethodPost, "/v1/users/"+string(protected.ID)+":delete", root,
		iamv1.DeleteUserRequest{ResourceVersion: 2, RequestID: "request-platform-delete"}, http.StatusForbidden)
	protectedDetail := read(root, protected.ID, http.StatusOK)
	protectedDelete, found := findIAMCapability(protectedDetail.Capabilities, iamv1.ActionIAMUserDelete, iamv1.ResourceUser, string(protected.ID))
	if !found || protectedDelete.Available || protectedDelete.RestrictionReason != iamv1.CapabilityInstallationAuthorityProtected {
		t.Fatal("installation authority deletion protection is missing")
	}
	request(http.MethodPost, "/v1/policy-attachments/"+string(platformAttachment.ID)+":revoke", root,
		iamv1.RevokePolicyAttachmentRequest{ResourceVersion: platformAttachment.ResourceVersion, RequestID: "request-platform-protection-revoke"}, http.StatusOK)
	request(http.MethodPost, "/v1/users/"+string(protected.ID)+":set-status", root,
		iamv1.SetUserStatusRequest{Status: iamv1.PrincipalDisabled, ResourceVersion: 2, RequestID: "request-platform-cleanup-disable"}, http.StatusOK)
	request(http.MethodPost, "/v1/users/"+string(protected.ID)+":delete", root,
		iamv1.DeleteUserRequest{ResourceVersion: 3, RequestID: "request-platform-cleanup-delete"}, http.StatusOK)

	raceUser := create("concurrent.delete")
	request(http.MethodPost, "/v1/users/"+string(raceUser.ID)+":set-status", root,
		iamv1.SetUserStatusRequest{Status: iamv1.PrincipalDisabled, ResourceVersion: raceUser.ResourceVersion, RequestID: "request-race-disable"}, http.StatusOK)
	start := make(chan struct{})
	results := make(chan int, 3)
	for _, operation := range []struct {
		path string
		body any
	}{
		{"/v1/users/" + string(raceUser.ID) + ":update", iamv1.UpdateUserRequest{DisplayName: "Concurrent winner", ResourceVersion: 2, RequestID: "request-race-update"}},
		{"/v1/users/" + string(raceUser.ID) + ":set-status", iamv1.SetUserStatusRequest{Status: iamv1.PrincipalActive, ResourceVersion: 2, RequestID: "request-race-enable"}},
		{"/v1/users/" + string(raceUser.ID) + ":delete", iamv1.DeleteUserRequest{ResourceVersion: 2, RequestID: "request-race-delete"}},
	} {
		encoded, err := json.Marshal(operation.body)
		if err != nil {
			t.Fatal(err)
		}
		go func(path string, body []byte) {
			<-start
			results <- performIAMRequest(handler, http.MethodPost, path, root, body).Code
		}(operation.path, encoded)
	}
	close(start)
	statuses := []int{<-results, <-results, <-results}
	successes := 0
	for _, code := range statuses {
		if code == http.StatusOK {
			successes++
		} else if code != http.StatusConflict && code != http.StatusForbidden {
			t.Fatalf("concurrent user mutation returned unexpected status %d", code)
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent status/update/delete admitted %d mutations: %v", successes, statuses)
	}
	var version uint64
	var raceStatus, raceName string
	var raceDeleted *time.Time
	var raceCredentials, raceFacts int
	if err := database.QueryRow(ctx, `SELECT status,display_name,resource_version,deleted_at,
		(SELECT count(*) FROM iam.user_credentials AS credential WHERE credential.tenant_id=principal.tenant_id AND credential.principal_id=principal.id),
		(SELECT count(*) FROM iam.audit_outbox AS outbox WHERE outbox.tenant_id=principal.tenant_id AND outbox.event_document#>>'{target,id}'=principal.id AND outbox.event_document->>'action' IN ('iam.user.updated','iam.user.deleted','iam.user.status-set') AND outbox.event_document->>'requestId' IN ('request-race-update','request-race-enable','request-race-delete'))
		FROM iam.principals AS principal WHERE principal.tenant_id=$1 AND principal.id=$2`, accountID, raceUser.ID).
		Scan(&raceStatus, &raceName, &version, &raceDeleted, &raceCredentials, &raceFacts); err != nil || version != 3 || raceFacts != 1 {
		t.Fatalf("concurrent user mutation left ambiguous state: status=%s name=%s version=%d deleted=%v credentials=%d facts=%d err=%v",
			raceStatus, raceName, version, raceDeleted, raceCredentials, raceFacts, err)
	}
	if raceDeleted != nil {
		if raceStatus != "DISABLED" || raceCredentials != 0 {
			t.Fatal("winning deletion left live credentials")
		}
	} else if raceCredentials != 1 || !((raceStatus == "ACTIVE" && raceName == raceUser.DisplayName) ||
		(raceStatus == "DISABLED" && raceName == "Concurrent winner")) {
		t.Fatal("winning status/profile mutation mixed concurrent effects")
	}
	assertIAMSecretsAbsent(t, ctx, database, initialPassword, changedPassword, bearer, protectedBearer)
}

func proveTenantLifecycleHTTP(t *testing.T, ctx context.Context, handler http.Handler, database *pgx.Conn, root, otherPrimary string) {
	t.Helper()
	const home = "organization-http-integration"
	const tenantID = "organization-lifecycle"
	const initial = "Lifecycle-Initial-Password-38!"
	const changed = "Lifecycle-Changed-Password-49!"
	const recovered = "Lifecycle-Recovered-Password-57!"
	request := func(method, path, bearer string, body any, expected int) *httptest.ResponseRecorder {
		t.Helper()
		var encoded []byte
		if body != nil {
			var err error
			encoded, err = json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
		}
		response := performIAMRequest(handler, method, path, bearer, encoded)
		if response.Code != expected {
			t.Fatalf("lifecycle %s %s: status=%d want=%d body=%s", method, path, response.Code, expected, response.Body.String())
		}
		return response
	}
	login := func(name, password string, expected int) string {
		t.Helper()
		response := request(http.MethodPost, "/v1/auth/login", "", map[string]any{"loginName": name, "password": password, "requestId": "request-lifecycle-login"}, expected)
		if expected != http.StatusOK {
			return ""
		}
		var wire struct {
			Credential string `json:"credential"`
		}
		if json.Unmarshal(response.Body.Bytes(), &wire) != nil || wire.Credential == "" {
			t.Fatal("missing lifecycle credential")
		}
		return wire.Credential
	}
	changePassword := func(bearer, previous, next string) {
		request(http.MethodPost, "/v1/auth/password", bearer, map[string]any{"currentPassword": previous, "newPassword": next, "requestId": "request-lifecycle-password"}, http.StatusOK)
	}
	createMember := func(bearer, name string, policy iamv1.PolicyID) iamv1.User {
		t.Helper()
		body := map[string]any{"loginName": name, "displayName": "Lifecycle member", "initialPassword": initial, "requestId": "request-lifecycle-member"}
		response := request(http.MethodPost, "/v1/users", bearer, body, http.StatusCreated)
		var result iamv1.User
		if json.Unmarshal(response.Body.Bytes(), &result) != nil {
			t.Fatal("invalid lifecycle member")
		}
		if policy != "" && result.ID != "" {
			request(http.MethodPost, "/v1/policy-attachments", bearer, iamv1.CreatePolicyAttachmentRequest{Target: iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetUser, ID: string(result.ID)}, PolicyID: policy, PolicyResourceVersion: 1, RequestID: "explicit-member-policy-" + string(result.ID)}, http.StatusOK)
		}
		return result
	}
	operatorUser := createMember(root, "lifecycle.operator", "")
	operator := login("lifecycle.operator@"+home, initial, http.StatusOK)
	changePassword(operator, initial, changed)
	request(http.MethodPost, "/v1/policy-attachments", root, map[string]any{"target": iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetUser, ID: string(operatorUser.ID)}, "policyId": iamv1.SystemPolicyPlatformOperator, "policyResourceVersion": 1, "requestId": "request-lifecycle-platform-grant"}, http.StatusOK)
	operatorIdentity := request(http.MethodGet, "/v1/auth/me", operator, nil, http.StatusOK)
	var identity iamv1.CurrentIdentity
	if json.Unmarshal(operatorIdentity.Body.Bytes(), &identity) != nil {
		t.Fatal("platform operator identity is invalid")
	}
	operatorCreate, operatorCanCreate := findIAMCapability(identity.Capabilities, iamv1.ActionIAMAccountCreate, iamv1.ResourceAccount, "accounts")
	if !operatorCanCreate || !operatorCreate.Available || len(identity.PolicySources) != 1 || identity.User.ID == identity.Account.RootIdentity.PrincipalID {
		t.Fatal("tenant lifecycle still requires bootstrap/primary or tenant-admin identity")
	}
	protectedDirectory := request(http.MethodGet, "/v1/users", root, nil, http.StatusOK)
	var protectedUsers iamv1.UserList
	if json.Unmarshal(protectedDirectory.Body.Bytes(), &protectedUsers) != nil || iamv1.ValidateUserList(protectedUsers) != nil {
		t.Fatal("platform-bound target directory is invalid")
	}
	foundProtected := false
	for _, entry := range protectedUsers.Items {
		if entry.User.ID != operatorUser.ID {
			continue
		}
		foundProtected = true
		for _, action := range []iamv1.Action{iamv1.ActionIAMUserSetStatus, iamv1.ActionIAMUserPasswordReset} {
			capability, found := findIAMCapability(entry.Capabilities, action, iamv1.ResourceUser, string(operatorUser.ID))
			if !found || capability.Available || capability.RestrictionReason != iamv1.CapabilityInstallationAuthorityProtected {
				t.Fatalf("installation authority protection capability %s is invalid", action)
			}
		}
	}
	if !foundProtected {
		t.Fatal("platform-bound target missing from user directory")
	}
	request(http.MethodGet, "/v1/users", operator, nil, http.StatusForbidden)
	created := request(http.MethodPost, "/v1/accounts", operator, map[string]any{
		"id": tenantID, "displayName": "Lifecycle tenant", "rootLoginName": "lifecycle.primary", "rootDisplayName": "Lifecycle owner", "initialPassword": initial, "requestId": "request-lifecycle-create"}, http.StatusCreated)
	var account iamv1.Account
	if json.Unmarshal(created.Body.Bytes(), &account) != nil || account.ID != tenantID {
		t.Fatal("platform operator could not onboard tenant")
	}
	primaryID := account.RootIdentity.PrincipalID
	primary := login("lifecycle.primary", initial, http.StatusOK)
	changePassword(primary, initial, changed)
	member := createMember(primary, "shared.user", iamv1.SystemPolicyPaaSViewer)
	memberSession := login("shared.user@"+tenantID, initial, http.StatusOK)
	changePassword(memberSession, initial, changed)
	readAccount := func(id string) iamv1.Account {
		t.Helper()
		response := request(http.MethodGet, "/v1/accounts/"+id, operator, nil, http.StatusOK)
		var result iamv1.AccountAccess
		if json.Unmarshal(response.Body.Bytes(), &result) != nil || iamv1.ValidateAccountAccess(result) != nil || result.Account.ID != iamv1.AccountID(id) {
			t.Fatal("invalid platform tenant detail")
		}
		return result.Account
	}
	status := func(id string, next iamv1.AccountStatus, version uint64, expected int) {
		request(http.MethodPost, "/v1/accounts/"+id+":set-status", operator,
			map[string]any{"status": next, "resourceVersion": version, "requestId": "request-lifecycle-status"}, expected)
	}
	recoverPrimary := func(id string, version uint64, expected int) {
		request(http.MethodPost, "/v1/accounts/"+id+":recover-root-credentials", operator,
			map[string]any{"initialPassword": recovered, "resourceVersion": version, "requestId": "request-lifecycle-recover"}, expected)
	}
	// Compare credential, session, role and lifecycle-success state, not SQL text
	// or incidental request/decision ordering. Denied decisions may be audited.
	securityState := func() string {
		t.Helper()
		var state string
		err := database.QueryRow(ctx, `SELECT jsonb_build_object(
			'organizations',(SELECT jsonb_agg(jsonb_build_array(o.id,o.status,o.resource_version) ORDER BY o.id) FROM iam.accounts AS o),
			'principals',(SELECT jsonb_agg(jsonb_build_array(p.tenant_id,p.id,p.status,p.must_change_password,p.resource_version,c.password_hash) ORDER BY p.tenant_id,p.id) FROM iam.principals AS p LEFT JOIN iam.user_credentials AS c ON c.tenant_id=p.tenant_id AND c.principal_id=p.id),
			'sessions',(SELECT jsonb_agg(jsonb_build_array(s.tenant_id,s.id,s.status,s.resource_version,s.revoked_at) ORDER BY s.tenant_id,s.id) FROM iam.sessions AS s),
			'bindings',(SELECT jsonb_agg(jsonb_build_array(b.tenant_id,b.id,b.target_id,b.policy_id,b.resource_version,b.revoked_at) ORDER BY b.tenant_id,b.id) FROM iam.policy_attachments AS b),
			'successes',(SELECT jsonb_agg(jsonb_build_array(e.event_id,e.event_document) ORDER BY e.event_id) FROM iam.audit_outbox AS e WHERE e.event_document->>'result'='SUCCEEDED')
		)::text`).Scan(&state)
		if err != nil {
			t.Fatal(err)
		}
		return state
	}
	unchanged := func(attempt func()) {
		t.Helper()
		before := securityState()
		attempt()
		if securityState() != before {
			t.Fatal("denied/conflicting lifecycle command partially changed security state or success facts")
		}
	}
	for _, actor := range []string{primary, otherPrimary, memberSession} {
		request(http.MethodGet, "/v1/accounts/"+tenantID, actor, nil, http.StatusForbidden)
		request(http.MethodPost, "/v1/accounts/"+tenantID+":set-status", actor,
			map[string]any{"status": "DISABLED", "resourceVersion": 1, "requestId": "request-lifecycle-tenant-attack"}, http.StatusForbidden)
		request(http.MethodPost, "/v1/accounts/"+tenantID+":recover-root-credentials", actor,
			map[string]any{"initialPassword": recovered, "resourceVersion": 1, "requestId": "request-lifecycle-recovery-attack"}, http.StatusForbidden)
	}
	unchanged(func() {
		status(home, iamv1.AccountDisabled, readAccount(home).ResourceVersion, http.StatusForbidden)
	})
	unchanged(func() { status(tenantID, iamv1.AccountDisabled, 99, http.StatusConflict) })
	unchanged(func() { recoverPrimary(tenantID, 99, http.StatusConflict) })
	for _, selector := range []string{string(member.ID), "service-paas", "principal-admin"} {
		selector := selector
		unchanged(func() {
			request(http.MethodPost, "/v1/accounts/"+tenantID+":recover-root-credentials", operator,
				map[string]any{"principalId": selector, "initialPassword": recovered, "resourceVersion": 1, "requestId": "request-root-selector-attack"}, http.StatusBadRequest)
		})
	}
	unchanged(func() {
		request(http.MethodPost, "/v1/accounts/"+tenantID+":recover-root-credentials?accountId=organization-customer-b", operator,
			map[string]any{"initialPassword": recovered, "resourceVersion": 1, "requestId": "request-root-query-selector-attack"}, http.StatusBadRequest)
	})
	unchanged(func() {
		recoverPrimary(home, readAccount(home).ResourceVersion, http.StatusForbidden)
	})
	// A legacy disabled platform primary remains protected by the binding, not
	// by a current effective-permissions calculation.
	if _, err := database.Exec(ctx, "UPDATE iam.principals SET status='DISABLED' WHERE tenant_id=$1 AND id='principal-admin'", home); err != nil {
		t.Fatal(err)
	}
	unchanged(func() {
		recoverPrimary(home, readAccount(home).ResourceVersion, http.StatusForbidden)
	})
	if _, err := database.Exec(ctx, "UPDATE iam.principals SET status='ACTIVE' WHERE tenant_id=$1 AND id='principal-admin'", home); err != nil {
		t.Fatal(err)
	}
	request(http.MethodGet, "/v1/auth/me", primary, nil, http.StatusOK)
	request(http.MethodGet, "/v1/auth/me", memberSession, nil, http.StatusOK)
	// Seed a legacy damaged primary only as an adversarial fixture. Recovery
	// itself must go through HTTP and must not resurrect the old revoked binding.
	if _, err := database.Exec(ctx, `WITH revoked AS (
		UPDATE iam.policy_attachments SET revoked_at=transaction_timestamp(),updated_at=transaction_timestamp(),resource_version=resource_version+1
		WHERE tenant_id=$1 AND target_kind='USER' AND target_id=$2 AND policy_id='system.account-administrator' AND revoked_at IS NULL RETURNING id)
		UPDATE iam.principals SET status='DISABLED',updated_at=transaction_timestamp(),resource_version=resource_version+1
		WHERE tenant_id=$1 AND id=$2`, tenantID, primaryID); err != nil {
		t.Fatal(err)
	}
	recoverPrimary(tenantID, 1, http.StatusOK)
	if fresh := readAccount(tenantID); fresh.RootIdentity.PrincipalID != primaryID || fresh.ResourceVersion != 2 {
		t.Fatal("primary recovery transferred ownership")
	}
	var retainedRevocation, repaired bool
	if err := database.QueryRow(ctx, `SELECT
		EXISTS(SELECT 1 FROM iam.policy_attachments WHERE tenant_id=$1 AND id='primary-admin-binding' AND revoked_at IS NOT NULL),
		(SELECT count(*)=1 FROM iam.policy_attachments WHERE tenant_id=$1 AND target_id=$2 AND policy_id='system.account-administrator' AND revoked_at IS NULL)`,
		tenantID, primaryID).Scan(&retainedRevocation, &repaired); err != nil || !retainedRevocation || !repaired {
		t.Fatal("primary recovery revived an old binding or did not restore exactly one tenant-admin binding")
	}
	request(http.MethodGet, "/v1/auth/me", primary, nil, http.StatusUnauthorized)
	request(http.MethodGet, "/v1/auth/me", memberSession, nil, http.StatusOK)
	login("lifecycle.primary", changed, http.StatusUnauthorized)
	primary = login("lifecycle.primary", recovered, http.StatusOK)
	current := request(http.MethodGet, "/v1/auth/me", primary, nil, http.StatusOK)
	if json.Unmarshal(current.Body.Bytes(), &identity) != nil {
		t.Fatal("recovered root identity is invalid")
	}
	recoveredCreate, recoveredCanCreate := findIAMCapability(identity.Capabilities, iamv1.ActionIAMAccountCreate, iamv1.ResourceAccount, "accounts")
	if !identity.User.MustChangePassword || !recoveredCanCreate || recoveredCreate.Available ||
		recoveredCreate.RestrictionReason != iamv1.CapabilityCurrentCredentialChangeRequired || len(identity.PolicySources) != 1 || identity.PolicySources[0].Attachment.PolicyID != iamv1.SystemPolicyAccountAdministrator {
		t.Fatal("primary recovery gained platform access or skipped required password change")
	}
	request(http.MethodGet, "/v1/users", primary, nil, http.StatusForbidden)
	changePassword(primary, recovered, changed)
	// A delegated administrator is revocable; the primary is not replaced by it.
	delegate := createMember(primary, "daily.admin", iamv1.SystemPolicyAccountAdministrator)
	delegateSession := login("daily.admin@"+tenantID, initial, http.StatusOK)
	changePassword(delegateSession, initial, changed)
	directory := request(http.MethodGet, "/v1/users", primary, nil, http.StatusOK)
	var users iamv1.UserList
	if json.Unmarshal(directory.Body.Bytes(), &users) != nil {
		t.Fatal("invalid lifecycle directory")
	}
	for _, user := range users.Items {
		if user.User.ID == delegate.ID {
			for _, binding := range user.PolicyAttachments {
				request(http.MethodPost, "/v1/policy-attachments/"+string(binding.ID)+":revoke", primary, map[string]any{"resourceVersion": 1, "requestId": "request-daily-admin-handoff"}, http.StatusOK)
			}
		}
	}
	request(http.MethodGet, "/v1/users", delegateSession, nil, http.StatusForbidden)
	unchanged(func() {
		request(http.MethodPost, "/v1/policy-attachments/primary-admin-binding:revoke", primary, map[string]any{"resourceVersion": 1, "requestId": "request-primary-handoff-attack"}, http.StatusForbidden)
	})
	knownPassword := changed
	for _, next := range []iamv1.AccountStatus{iamv1.AccountDisabled, iamv1.AccountActive} {
		fresh := readAccount(tenantID)
		if fresh.Status == next {
			opposite := iamv1.AccountActive
			if next == iamv1.AccountActive {
				opposite = iamv1.AccountDisabled
			}
			status(tenantID, opposite, fresh.ResourceVersion, http.StatusOK)
			fresh = readAccount(tenantID)
		}
		var oldHash string
		if err := database.QueryRow(ctx, "SELECT password_hash FROM iam.user_credentials WHERE tenant_id=$1 AND principal_id=$2", tenantID, primaryID).Scan(&oldHash); err != nil {
			t.Fatal(err)
		}
		recoveryJSON, _ := json.Marshal(map[string]any{"initialPassword": recovered, "resourceVersion": fresh.ResourceVersion, "requestId": "request-race-recover-" + string(next)})
		statusJSON, _ := json.Marshal(map[string]any{"status": next, "resourceVersion": fresh.ResourceVersion, "requestId": "request-race-status-" + string(next)})
		start := make(chan struct{})
		results := make(chan struct {
			recovery bool
			status   int
		}, 2)
		go func() {
			<-start
			results <- struct {
				recovery bool
				status   int
			}{true, performIAMRequest(handler, http.MethodPost, "/v1/accounts/"+tenantID+":recover-root-credentials", operator, recoveryJSON).Code}
		}()
		go func() {
			<-start
			results <- struct {
				recovery bool
				status   int
			}{false, performIAMRequest(handler, http.MethodPost, "/v1/accounts/"+tenantID+":set-status", operator, statusJSON).Code}
		}()
		close(start)
		first, second := <-results, <-results
		if !((first.status == http.StatusOK && second.status == http.StatusConflict) || (second.status == http.StatusOK && first.status == http.StatusConflict)) {
			t.Fatalf("same-version lifecycle race statuses=%d/%d", first.status, second.status)
		}
		recoveryWon := first.recovery && first.status == http.StatusOK || second.recovery && second.status == http.StatusOK
		freshAfter := readAccount(tenantID)
		if freshAfter.RootIdentity.PrincipalID != primaryID || freshAfter.ResourceVersion != fresh.ResourceVersion+1 {
			t.Fatal("race consumed a version twice or changed primary")
		}
		if recoveryWon {
			knownPassword = recovered
			if freshAfter.Status != fresh.Status {
				t.Fatal("recovery also changed tenant status")
			}
		} else {
			var passwordUnchanged bool
			if err := database.QueryRow(ctx, "SELECT password_hash=$3 FROM iam.user_credentials WHERE tenant_id=$1 AND principal_id=$2", tenantID, primaryID, oldHash).Scan(&passwordUnchanged); err != nil || !passwordUnchanged || freshAfter.Status != next {
				t.Fatal("losing recovery changed credentials or status winner was lost")
			}
		}
		for _, outcome := range []struct {
			requestID string
			expected  bool
		}{{"request-race-recover-" + string(next), recoveryWon}, {"request-race-status-" + string(next), !recoveryWon}} {
			var committed bool
			if err := database.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM iam.audit_outbox WHERE event_document->>'requestId'=$1 AND event_document->>'result'='SUCCEEDED')", outcome.requestID).Scan(&committed); err != nil || committed != outcome.expected {
				t.Fatal("losing lifecycle race committed a success fact")
			}
		}
		if freshAfter.Status == iamv1.AccountDisabled {
			status(tenantID, iamv1.AccountActive, freshAfter.ResourceVersion, http.StatusOK)
		}
		primary = login("lifecycle.primary", knownPassword, http.StatusOK)
		if recoveryWon {
			changePassword(primary, recovered, changed)
			knownPassword = changed
		}
	}
	oldPrimary := primary
	status(tenantID, iamv1.AccountDisabled, readAccount(tenantID).ResourceVersion, http.StatusOK)
	for _, bearer := range []string{oldPrimary, memberSession, delegateSession} {
		request(http.MethodGet, "/v1/auth/me", bearer, nil, http.StatusUnauthorized)
	}
	login("lifecycle.primary", knownPassword, http.StatusUnauthorized)
	login("shared.user@"+tenantID, changed, http.StatusUnauthorized)
	recoverPrimary(tenantID, readAccount(tenantID).ResourceVersion, http.StatusOK)
	if readAccount(tenantID).Status != iamv1.AccountDisabled {
		t.Fatal("recovery implicitly resumed tenant")
	}
	login("lifecycle.primary", recovered, http.StatusUnauthorized)
	applyIAMSchema(t, ctx, database)
	if readAccount(tenantID).Status != iamv1.AccountDisabled {
		t.Fatal("migration replay revived suspended tenant")
	}
	status(tenantID, iamv1.AccountActive, readAccount(tenantID).ResourceVersion, http.StatusOK)
	request(http.MethodGet, "/v1/auth/me", oldPrimary, nil, http.StatusUnauthorized)
	request(http.MethodGet, "/v1/auth/me", memberSession, nil, http.StatusUnauthorized)
	login("lifecycle.primary", knownPassword, http.StatusUnauthorized)
	primary = login("lifecycle.primary", recovered, http.StatusOK)
	changePassword(primary, recovered, changed)
	status(tenantID, iamv1.AccountDisabled, readAccount(tenantID).ResourceVersion, http.StatusOK)
	rows, err := database.Query(ctx, "SELECT event_document FROM iam.audit_outbox WHERE event_document->>'action'=ANY($1::text[])", []string{"iam.account.created", "iam.account.disabled", "iam.account.enabled", "iam.account-root.credentials-recovered"})
	if err != nil {
		t.Fatal(err)
	}
	var facts []auditv1.Event
	for rows.Next() {
		var encoded []byte
		var event auditv1.Event
		if rows.Scan(&encoded) != nil || json.Unmarshal(encoded, &event) != nil {
			t.Fatal("invalid lifecycle fact")
		}
		facts = append(facts, event)
	}
	rows.Close()
	if rows.Err() != nil || len(facts) == 0 {
		t.Fatal("missing lifecycle facts")
	}
	for _, event := range facts {
		if event.TenantID != "" || event.InstallationID != "installation-http-integration" || auditv1.ValidateEventForSource(auditv1.SourceIAM, event) != nil {
			t.Fatal("lifecycle event entered a tenant chain")
		}
		if event.Action == auditv1.ActionIAMAccountRootCredentialsRecovered && (event.Target.ID != string(primaryID) || event.Target.TenantID != tenantID) {
			t.Fatal("recovery fact did not bind original primary and tenant")
		}
		request(http.MethodPost, "/v1/audit-producer:resolve", iamProducerCredential, map[string]any{"event": event}, http.StatusOK)
		if event.Action == auditv1.ActionIAMAccountRootCredentialsRecovered {
			event.Target.TenantID = "organization-customer-b"
			request(http.MethodPost, "/v1/audit-producer:resolve", iamProducerCredential, map[string]any{"event": event}, http.StatusForbidden)
		}
	}
	assertIAMSecretsAbsent(t, ctx, database, initial, changed, recovered, operator, primary, memberSession, delegateSession)
}

func proveHistoricalProducerHTTP(t *testing.T, ctx context.Context, handler http.Handler, database *pgx.Conn, tenants map[string]string) {
	t.Helper()
	post := func(path, bearer string, body any, status int) *httptest.ResponseRecorder {
		t.Helper()
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		response := performIAMRequest(handler, http.MethodPost, path, bearer, encoded)
		if response.Code != status {
			t.Fatalf("proof path=%s status=%d want=%d body=%s", path, response.Code, status, response.Body.String())
		}
		return response
	}
	resolve := func(credential string, event auditv1.Event, status int) {
		t.Helper()
		response := post("/v1/audit-producer:resolve", credential, iamv1.ResolveAuditProducerRequest{Event: event}, status)
		if status != http.StatusOK {
			return
		}
		var proof iamv1.AuditProducerAuthorization
		contract, _ := auditv1.ContractForAction(event.Action)
		_, digest, err := auditv1.CanonicalizeEvent(contract.Source, event)
		if json.Unmarshal(response.Body.Bytes(), &proof) != nil || iamv1.ValidateAuditProducerAuthorization(proof) != nil || err != nil ||
			proof.TenantID != iamv1.AccountID(event.TenantID) || proof.InstallationID != event.InstallationID || proof.ContentDigest != digest ||
			proof.Producer.AccountID != "organization-http-integration" || proof.Producer.InstallationID != "installation-http-integration" {
			t.Fatal("producer proof lost event, installation or credential binding")
		}
	}
	const initial = "Proof-Actor-Initial-Password-93!"
	const changed = "Proof-Actor-Changed-Password-84!"
	for tenant, root := range tenants {
		created := post("/v1/users", root, map[string]any{"loginName": "proof.actor", "displayName": "Proof actor", "initialPassword": initial, "requestId": "request-proof-actor"}, http.StatusCreated)
		var principal iamv1.User
		if json.Unmarshal(created.Body.Bytes(), &principal) != nil {
			t.Fatal("decode proof actor")
		}
		post("/v1/policy-attachments", root, iamv1.CreatePolicyAttachmentRequest{Target: iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetUser, ID: string(principal.ID)}, PolicyID: iamv1.SystemPolicyAccountAdministrator, PolicyResourceVersion: 1, RequestID: "proof-actor-policy"}, http.StatusOK)
		loggedIn := post("/v1/auth/login", "", map[string]any{"loginName": "proof.actor@" + tenant, "password": initial, "requestId": "request-proof-login"}, http.StatusOK)
		var session struct {
			Credential string `json:"credential"`
		}
		if json.Unmarshal(loggedIn.Body.Bytes(), &session) != nil {
			t.Fatal("decode proof login")
		}
		post("/v1/auth/password", session.Credential, map[string]any{"currentPassword": initial, "newPassword": changed, "requestId": "request-proof-password"}, http.StatusOK)
		var historical []struct {
			credential string
			event      auditv1.Event
		}
		for _, producer := range []struct {
			credential  string
			action      iamv1.Action
			eventAction auditv1.Action
			kind        iamv1.ResourceKind
			targetKind  auditv1.TargetKind
			target      string
		}{
			{paasCredential, iamv1.ActionPaaSApplicationCreate, auditv1.ActionPaaSApplicationCreated, iamv1.ResourceApplication, auditv1.TargetApplication, "collection"},
			{auditCredential, iamv1.ActionAuditRecordRead, auditv1.ActionAuditRecordsRead, iamv1.ResourceAuditRecord, auditv1.TargetAuditRecords, "records"},
		} {
			body, _ := json.Marshal(iamv1.AuthorizationRequest{Action: producer.action, Resource: iamv1.ResourceReference{Kind: producer.kind, ID: producer.target}, RequestID: "request-proof-business", CorrelationID: "correlation-proof-business"})
			response := performIAMRequestWithSubject(handler, body, producer.credential, session.Credential)
			var decision iamv1.AuthorizationDecision
			if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &decision) != nil || !decision.Allowed || decision.Subject == nil {
				t.Fatal("proof actor lacked real original authority")
			}
			event := auditv1.Event{APIVersion: auditv1.APIVersion, Kind: "AuditEvent", EventID: auditv1.EventID("event-" + string(decision.ID)), TenantID: auditv1.TenantID(tenant),
				Actor: auditv1.ActorReference{Type: auditv1.ActorUser, ID: auditv1.ActorID(principal.ID)}, IAMDecisionID: auditv1.DecisionID(decision.ID), Action: producer.eventAction,
				Target: auditv1.TargetReference{Kind: producer.targetKind, ID: producer.target}, Result: auditv1.ResultSucceeded, RequestDigest: "sha256:" + strings.Repeat("a", 64),
				RequestID: decision.RequestID, CorrelationID: "correlation-proof-business", OccurredAt: decision.DecidedAt.Add(time.Microsecond)}
			if producer.credential == paasCredential {
				event.Target.ID = "application-proof"
				event.OperationID = "operation-proof"
			}
			resolve(producer.credential, event, http.StatusOK)
			for _, attack := range []func(*auditv1.Event){
				func(e *auditv1.Event) { e.TenantID = "unknown-account" },
				func(e *auditv1.Event) {
					for other := range tenants {
						if other != tenant {
							e.TenantID = auditv1.TenantID(other)
							break
						}
					}
				},
				func(e *auditv1.Event) { e.Actor.ID = "principal-forged" },
				func(e *auditv1.Event) { e.IAMDecisionID = "decision-forged" },
				func(e *auditv1.Event) { e.RequestID = "request-forged" },
				func(e *auditv1.Event) { e.CorrelationID = "correlation-forged" },
				func(e *auditv1.Event) { e.OccurredAt = decision.DecidedAt.Add(-time.Microsecond) },
			} {
				forged := event
				attack(&forged)
				resolve(producer.credential, forged, http.StatusForbidden)
			}
			resolve(verifierCredential, event, http.StatusForbidden)
			resolve(root, event, http.StatusUnauthorized)
			otherProducer := paasCredential
			if otherProducer == producer.credential {
				otherProducer = auditCredential
			}
			resolve(otherProducer, event, http.StatusForbidden)
			historical = append(historical, struct {
				credential string
				event      auditv1.Event
			}{producer.credential, event})
		}
		post("/v1/auth/logout", session.Credential, map[string]any{"requestId": "request-proof-logout"}, http.StatusOK)
		post("/v1/users/"+string(principal.ID)+":set-status", root, map[string]any{"status": "DISABLED", "resourceVersion": 2, "requestId": "request-proof-disable"}, http.StatusOK)
		for _, fact := range historical {
			resolve(fact.credential, fact.event, http.StatusOK)
		}
		if response := performIAMRequest(handler, http.MethodGet, "/v1/auth/me", session.Credential, nil); response.Code != http.StatusUnauthorized {
			t.Fatal("historical proof revived revoked session")
		}
	}
	rows, err := database.Query(ctx, `SELECT DISTINCT ON (event_document->>'action') event_document FROM iam.audit_outbox ORDER BY event_document->>'action',event_id`)
	if err != nil {
		t.Fatal(err)
	}
	var ownFacts []auditv1.Event
	for rows.Next() {
		var raw []byte
		var event auditv1.Event
		if rows.Scan(&raw) != nil || json.Unmarshal(raw, &event) != nil {
			rows.Close()
			t.Fatal("decode own committed IAM fact")
		}
		event.OccurredAt = event.OccurredAt.UTC()
		ownFacts = append(ownFacts, event)
	}
	rows.Close()
	if rows.Err() != nil || len(ownFacts) == 0 {
		t.Fatal("missing committed IAM evidence")
	}
	for _, event := range ownFacts {
		resolve(iamProducerCredential, event, http.StatusOK)
		forged := event
		forged.RequestDigest = "sha256:" + strings.Repeat("b", 64)
		resolve(iamProducerCredential, forged, http.StatusForbidden)
	}
	assertIAMSecretsAbsent(t, ctx, database, initial, changed)
}

func assertPlatformAuthorityHTTP(t *testing.T, ctx context.Context, handler http.Handler, database *pgx.Conn, administrator, member string, memberID iamv1.PrincipalID) {
	t.Helper()
	put := func(actor string, principalID iamv1.PrincipalID, policy iamv1.PolicyID, expected int) iamv1.PolicyAttachment {
		t.Helper()
		body, err := json.Marshal(iamv1.CreatePolicyAttachmentRequest{Target: iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetUser, ID: string(principalID)}, PolicyID: policy, PolicyResourceVersion: 1, RequestID: "request-platform-policy-" + string(principalID) + "-" + string(policy)})
		if err != nil {
			t.Fatal(err)
		}
		response := performIAMRequest(handler, http.MethodPost, "/v1/policy-attachments", actor, body)
		if response.Code != expected {
			t.Fatalf("platform role grant status=%d expected=%d body=%s", response.Code, expected, response.Body.String())
		}
		var binding iamv1.PolicyAttachment
		if expected == http.StatusOK && (json.Unmarshal(response.Body.Bytes(), &binding) != nil || iamv1.ValidatePolicyAttachment(binding) != nil) {
			t.Fatal("platform role grant returned an invalid binding")
		}
		return binding
	}
	revoke := func(actor string, id iamv1.PolicyAttachmentID, expected int) {
		t.Helper()
		response := performIAMRequest(handler, http.MethodPost, "/v1/policy-attachments/"+string(id)+":revoke", actor,
			[]byte(`{"resourceVersion":1,"requestId":"request-platform-policy-revoke"}`))
		if response.Code != expected {
			t.Fatalf("platform role revocation status=%d expected=%d body=%s", response.Code, expected, response.Body.String())
		}
	}
	assertPlatformDecisionHTTP(t, handler, administrator, paasCredential, true)
	assertPlatformDecisionHTTP(t, handler, administrator, auditCredential, false)
	assertPlatformDecisionHTTP(t, handler, member, paasCredential, false)
	organizationBinding := put(administrator, memberID, iamv1.SystemPolicyAccountAdministrator, http.StatusOK)
	assertPlatformDecisionHTTP(t, handler, member, paasCredential, false)
	put(member, memberID, iamv1.SystemPolicyPlatformOperator, http.StatusForbidden)
	revoke(member, "bootstrap-platform-operator-binding", http.StatusForbidden)
	put(administrator, "service-paas", iamv1.SystemPolicyPlatformOperator, http.StatusForbidden)
	platformBinding := put(administrator, memberID, iamv1.SystemPolicyPlatformOperator, http.StatusOK)
	assertPlatformDecisionHTTP(t, handler, member, paasCredential, true)
	for _, command := range []struct{ suffix, body string }{
		{":set-status", `{"status":"DISABLED","resourceVersion":2,"requestId":"request-protect-platform-status"}`},
		{":reset-password", `{"initialPassword":"Platform-Reset-Attack-Password-39!","resourceVersion":2,"requestId":"request-protect-platform-password"}`},
	} {
		response := performIAMRequest(handler, http.MethodPost, "/v1/users/"+string(memberID)+command.suffix, administrator, []byte(command.body))
		if response.Code != http.StatusForbidden {
			t.Fatalf("tenant command took over platform identity: status=%d", response.Code)
		}
	}
	assertPlatformDecisionHTTP(t, handler, member, paasCredential, true)
	revoke(administrator, platformBinding.ID, http.StatusOK)
	revoke(administrator, platformBinding.ID, http.StatusOK)
	assertPlatformDecisionHTTP(t, handler, member, paasCredential, false)
	t.Run("platform grant serializes with credential mutations", func(t *testing.T) {
		provePlatformCredentialProtection(t, ctx, handler, database, administrator, member)
	})
	revoke(administrator, organizationBinding.ID, http.StatusOK)
	revoke(administrator, "bootstrap-platform-operator-binding", http.StatusOK)
	assertPlatformDecisionHTTP(t, handler, administrator, paasCredential, false)
}

func provePlatformCredentialProtection(t *testing.T, ctx context.Context, handler http.Handler, database *pgx.Conn, operator, tenantAdministrator string) {
	t.Helper()
	const initial = "Platform-Race-Initial-Password-36!"
	const changed = "Platform-Race-Changed-Password-47!"
	const reset = "Platform-Race-Reset-Password-58!"
	request := func(path, bearer string, body any) *httptest.ResponseRecorder {
		t.Helper()
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		return performIAMRequest(handler, http.MethodPost, path, bearer, encoded)
	}
	for _, mutation := range []string{"reset-password", "set-status", "legacy-disabled"} {
		t.Run(mutation, func(t *testing.T) {
			created := request("/v1/users", operator, map[string]any{
				"loginName": "platform.race." + mutation, "displayName": "Platform race user",
				"initialPassword": initial, "requestId": "request-race-create-" + mutation,
			})
			var principal iamv1.User
			if created.Code != http.StatusCreated || json.Unmarshal(created.Body.Bytes(), &principal) != nil {
				t.Fatalf("create platform race user status=%d", created.Code)
			}
			grantBody := iamv1.CreatePolicyAttachmentRequest{Target: iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetUser, ID: string(principal.ID)}, PolicyID: iamv1.SystemPolicyPlatformOperator, PolicyResourceVersion: 1, RequestID: "request-race-grant-" + mutation}
			if response := request("/v1/policy-attachments", operator, grantBody); response.Code != http.StatusForbidden {
				t.Fatal("unconfirmed initial password gained platform authority")
			}
			login := request("/v1/auth/login", "", map[string]any{
				"loginName": principal.LoginName + "@" + string(principal.AccountID), "password": initial, "requestId": "request-race-login-" + mutation,
			})
			var session struct {
				Credential string `json:"credential"`
			}
			if login.Code != http.StatusOK || json.Unmarshal(login.Body.Bytes(), &session) != nil || session.Credential == "" {
				t.Fatalf("login platform race user status=%d", login.Code)
			}
			if response := request("/v1/auth/password", session.Credential, map[string]any{
				"currentPassword": initial, "newPassword": changed, "requestId": "request-race-password-" + mutation,
			}); response.Code != http.StatusOK {
				t.Fatalf("initialize platform race user status=%d", response.Code)
			}
			if mutation == "legacy-disabled" {
				if response := request("/v1/policy-attachments", operator, grantBody); response.Code != http.StatusOK {
					t.Fatalf("grant legacy platform fixture status=%d", response.Code)
				}
				// Model a disabled platform user from an older installation. New
				// tenant commands cannot create this state or recover its credentials.
				var version uint64
				if err := database.QueryRow(ctx, `UPDATE iam.principals SET status='DISABLED',resource_version=resource_version+1
					WHERE tenant_id=$1 AND id=$2 RETURNING resource_version`, principal.AccountID, principal.ID).Scan(&version); err != nil {
					t.Fatal(err)
				}
				for _, body := range []map[string]any{
					{"status": "ACTIVE", "resourceVersion": version, "requestId": "request-disabled-platform-enable"},
					{"initialPassword": reset, "resourceVersion": version, "requestId": "request-disabled-platform-reset"},
				} {
					suffix := ":set-status"
					if _, ok := body["initialPassword"]; ok {
						suffix = ":reset-password"
					}
					if response := request("/v1/users/"+string(principal.ID)+suffix, tenantAdministrator, body); response.Code != http.StatusForbidden {
						t.Fatalf("tenant administrator recovered a disabled platform identity: %d", response.Code)
					}
				}
				return
			}
			changeBody := map[string]any{"resourceVersion": 2, "requestId": "request-race-change-" + mutation}
			if mutation == "reset-password" {
				changeBody["initialPassword"] = reset
			} else {
				changeBody["status"] = "DISABLED"
			}
			grantJSON, _ := json.Marshal(grantBody)
			changeJSON, _ := json.Marshal(changeBody)
			start := make(chan struct{})
			grants, changes := make(chan int, 1), make(chan int, 1)
			go func() {
				<-start
				grants <- performIAMRequest(handler, http.MethodPost, "/v1/policy-attachments", operator, grantJSON).Code
			}()
			go func() {
				<-start
				changes <- performIAMRequest(handler, http.MethodPost, "/v1/users/"+string(principal.ID)+":"+mutation, tenantAdministrator, changeJSON).Code
			}()
			close(start)
			grantStatus, changeStatus := <-grants, <-changes
			if !((grantStatus == http.StatusOK && changeStatus == http.StatusForbidden) ||
				(grantStatus == http.StatusForbidden && changeStatus == http.StatusOK)) {
				t.Fatalf("platform grant/mutation race statuses=%d/%d", grantStatus, changeStatus)
			}
			var activePlatform bool
			var status string
			var mustChange bool
			if err := database.QueryRow(ctx, `SELECT p.status,p.must_change_password,
				EXISTS(SELECT 1 FROM iam.policy_attachments AS b WHERE b.tenant_id=p.tenant_id AND b.target_id=p.id AND b.authority_scope='INSTALLATION' AND b.revoked_at IS NULL)
				FROM iam.principals AS p WHERE p.tenant_id=$1 AND p.id=$2`, principal.AccountID, principal.ID).Scan(&status, &mustChange, &activePlatform); err != nil {
				t.Fatal(err)
			}
			if activePlatform != (grantStatus == http.StatusOK) || activePlatform && (status != "ACTIVE" || mustChange) {
				t.Fatal("platform grant raced past disabled or replaced credentials")
			}
		})
	}
	assertIAMSecretsAbsent(t, ctx, database, initial, changed, reset)
}

func assertPlatformDecisionHTTP(t *testing.T, handler http.Handler, subject, caller string, allowed bool) {
	t.Helper()
	body := []byte(`{"action":"paas.execution-target.register","resource":{"kind":"EXECUTION_TARGET","id":"target-example"},"requestId":"request-node-register","correlationId":"request-node-register"}`)
	response := performIAMRequestWithSubject(handler, body, caller, subject)
	var decision iamv1.AuthorizationDecision
	if response.Code != http.StatusOK || iamv1.DecodeRequest(bytes.NewReader(response.Body.Bytes()), &decision) != nil ||
		iamv1.ValidateAuthorizationDecision(decision) != nil || decision.Allowed != allowed || decision.TenantID != "" {
		t.Fatalf("platform authorization status=%d allowed=%t body=%s", response.Code, allowed, response.Body.String())
	}
	if allowed && (decision.InstallationID != "installation-http-integration" || decision.Subject == nil) {
		t.Fatal("platform decision lost the sealed installation identity")
	}
}

func performIAMRequest(
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

func performIAMRequestWithSubject(
	handler http.Handler,
	body []byte,
	serviceCredential string,
	subjectCredential string,
) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "/v1/authorize", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+serviceCredential)
	request.Header.Set("Matrix-Subject-Credential", subjectCredential)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func assertIAMPostgres18(t *testing.T, ctx context.Context, admin *pgx.Conn) {
	t.Helper()
	var version int
	if err := admin.QueryRow(ctx, "SELECT current_setting('server_version_num')::integer").Scan(&version); err != nil {
		t.Fatalf("read PostgreSQL version: %v", err)
	}
	if version < 180000 || version >= 190000 {
		t.Fatalf("PostgreSQL version=%d want major 18", version)
	}
}

func assertCleanIAMSchema(t *testing.T, ctx context.Context, admin *pgx.Conn) {
	t.Helper()
	var exists bool
	if err := admin.QueryRow(ctx, "SELECT to_regnamespace('iam') IS NOT NULL").Scan(&exists); err != nil {
		t.Fatalf("inspect IAM schema: %v", err)
	}
	if exists {
		t.Fatal("IAM HTTP integration database is not clean")
	}
}

func applyIAMSchema(t *testing.T, ctx context.Context, admin *pgx.Conn) {
	t.Helper()
	if err := iammigration.Bootstrap(ctx, admin); err != nil {
		t.Fatalf("bootstrap IAM migration: %v", err)
	}
	if err := iammigration.Up(ctx, admin); err != nil {
		t.Fatalf("apply IAM migration: %v", err)
	}
	if err := iammigration.Verify(ctx, admin); err != nil {
		t.Fatalf("verify IAM migration: %v", err)
	}
}

func createIAMHTTPRole(t *testing.T, ctx context.Context, admin *pgx.Conn) {
	t.Helper()
	statement := `DO $matrix_iam_http_role$
	BEGIN
		IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = '` + iamHTTPTestRole + `') THEN
			CREATE ROLE ` + iamHTTPTestRole + ` LOGIN PASSWORD '` + iamHTTPTestPassword + `'
				NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
		END IF;
		IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = '` + iamHTTPWorkerRole + `') THEN
			CREATE ROLE ` + iamHTTPWorkerRole + ` LOGIN PASSWORD '` + iamHTTPTestPassword + `'
				NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
		END IF;
	END
	$matrix_iam_http_role$;
	GRANT matrix_iam_api TO ` + iamHTTPTestRole + `;
	GRANT matrix_iam_worker TO ` + iamHTTPWorkerRole + `;`
	if _, err := admin.Exec(ctx, statement); err != nil {
		t.Fatalf("create IAM HTTP runtime role: %v", err)
	}
}

func assertIAMSecretsAbsent(t *testing.T, ctx context.Context, admin *pgx.Conn, plaintexts ...string) {
	t.Helper()
	for _, plaintext := range plaintexts {
		var servicePlaintext, passwordPlaintext, sessionPlaintext, auditPlaintext bool
		if err := admin.QueryRow(
			ctx,
			`SELECT
				EXISTS (
					SELECT 1 FROM iam.service_credentials
					 WHERE lookup_digest = $1 OR verification_digest = $1
				),
				EXISTS (SELECT 1 FROM iam.user_credentials WHERE password_hash = $1),
				EXISTS (SELECT 1 FROM iam.sessions WHERE verification_digest = $1),
				EXISTS (
					SELECT 1 FROM iam.audit_outbox
					 WHERE event_document::text LIKE '%' || $1 || '%'
				)`,
			plaintext,
		).Scan(&servicePlaintext, &passwordPlaintext, &sessionPlaintext, &auditPlaintext); err != nil {
			t.Fatalf("inspect IAM secret storage: %v", err)
		}
		if servicePlaintext || passwordPlaintext || sessionPlaintext || auditPlaintext {
			t.Fatalf(
				"IAM stored plaintext service=%t password=%t session=%t audit=%t",
				servicePlaintext,
				passwordPlaintext,
				sessionPlaintext,
				auditPlaintext,
			)
		}
	}
}

func iamHTTPBootstrap(t *testing.T) iamv1.BootstrapDocument {
	t.Helper()
	service := func(purpose iamv1.ServicePurpose, id, credential string) iamv1.BootstrapServiceCredential {
		return iamv1.BootstrapServiceCredential{
			Purpose:     purpose,
			PrincipalID: iamv1.PrincipalID(id),
			Credential:  iamHTTPSecret(t, credential),
		}
	}
	return iamv1.BootstrapDocument{
		APIVersion:     iamv1.APIVersion,
		Kind:           "IAMBootstrap",
		InstallationID: "installation-http-integration",
		Organization: iamv1.InitialOrganization{
			ID:          "organization-http-integration",
			DisplayName: "HTTP Integration Organization",
		},
		Administrator: iamv1.InitialAdministrator{
			ID:          "principal-admin",
			LoginName:   "admin",
			DisplayName: "Initial Administrator",
			Password:    iamHTTPSecret(t, adminPassword),
		},
		Services: []iamv1.BootstrapServiceCredential{
			service(iamv1.ServiceIAM, "service-iam", iamProducerCredential),
			service(iamv1.ServicePaaS, "service-paas", paasCredential),
			service(iamv1.ServiceAudit, "service-audit", auditCredential),
			service(iamv1.ServiceInstallationVerifier, "service-verifier", verifierCredential),
		},
	}
}

func iamHTTPSecret(t *testing.T, value string) iamv1.Secret {
	t.Helper()
	secret, err := iamv1.NewSecret(value)
	if err != nil {
		t.Fatalf("create IAM HTTP secret: %v", err)
	}
	return secret
}
