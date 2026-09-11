package integration

import (
	"bytes"
	"context"
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
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	config, err := pgx.ParseConfig(dsn)
	if err != nil || !strings.HasPrefix(config.Database, "matrix_iam_policy_") {
		t.Fatal("policy storage gate requires its own matrix_iam_policy_ database")
	}
	config.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	admin, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal("connect policy storage database")
	}
	defer admin.Close(context.Background())
	assertIAMPostgres18(t, ctx, admin)
	assertCleanIAMSchema(t, ctx, admin)
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
		iamv1.ValidateCurrentIdentity(currentIdentity) != nil || len(currentIdentity.PolicyAttachments) != 2 {
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
	assertRejected("attachment-forged-installation", `INSERT INTO iam.policy_attachments(tenant_id,id,principal_id,policy_id,installation_id,resource_version,created_at,updated_at) VALUES($1,'forged-installation',$2,'system.platform-operator','other-installation',1,transaction_timestamp(),transaction_timestamp())`, "23503", document.Organization.ID, document.Administrator.ID)
	assertRejected("attachment-wrong-principal-kind", `INSERT INTO iam.policy_attachments(tenant_id,id,principal_id,target_kind,policy_id,resource_version,created_at,updated_at) VALUES($1,'forged-kind',$2,'SERVICE_ACCOUNT','system.paas-viewer',1,transaction_timestamp(),transaction_timestamp())`, "23503", document.Organization.ID, document.Administrator.ID)
	assertRejected("tenant-attachment-cannot-select-installation", `INSERT INTO iam.policy_attachments(tenant_id,id,principal_id,policy_id,installation_id,resource_version,created_at,updated_at) VALUES($1,'forged-tenant-scope',$2,'system.paas-viewer',$3,1,transaction_timestamp(),transaction_timestamp())`, "22023", document.Organization.ID, document.Administrator.ID, document.InstallationID)
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
	assertRejected("attachment-cannot-use-another-account-policy", `INSERT INTO iam.policy_attachments(tenant_id,id,principal_id,policy_id,resource_version,created_at,updated_at) VALUES($1,'cross-account-policy',$2,'customer.other',1,transaction_timestamp(),transaction_timestamp())`, "23503", document.Organization.ID, document.Administrator.ID)
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
		SELECT 'budget-policy-'||i,'CUSTOMER',$1,'Budget policy','TENANT','ACTIVE','v1',1,transaction_timestamp(),transaction_timestamp() FROM generate_series(1,255) i;
		INSERT INTO iam.policy_versions(policy_id,id,authority_scope,document,canonical_document,content_digest,created_at)
		SELECT 'budget-policy-'||i,'v1','TENANT',CASE WHEN i=255 THEN $4::jsonb ELSE $2::jsonb END,
		CASE WHEN i=255 THEN $4 ELSE $2 END,CASE WHEN i=255 THEN $5 ELSE $3 END,transaction_timestamp() FROM generate_series(1,255) i;
		INSERT INTO iam.policy_attachments(tenant_id,id,principal_id,policy_id,resource_version,created_at,updated_at)
		SELECT $1,'budget-attachment-'||i,$6,'budget-policy-'||i,1,transaction_timestamp(),transaction_timestamp() FROM generate_series(1,254) i;
		COMMIT;`, document.Organization.ID, allowCanonical, allowDigest, canonical, digest, document.Administrator.ID); err != nil {
		t.Fatal(err)
	}
	assertDecision(iamv1.ActionPaaSApplicationRead, iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "policy-storage-application"}, true)
	if _, err := admin.Exec(ctx, `INSERT INTO iam.policy_attachments(tenant_id,id,principal_id,policy_id,resource_version,created_at,updated_at)
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
			SELECT 'catalog-budget-'||i,'CUSTOMER',$1,'Catalog budget','TENANT','ACTIVE','v1',1,transaction_timestamp(),transaction_timestamp() FROM generate_series($4::int,$5::int) i;
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
				VALUES($1,'CUSTOMER',$2,'Publication race','TENANT','ACTIVE','v1',1,transaction_timestamp(),transaction_timestamp());
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
					(SELECT count(*) FROM iam.policy_attachments WHERE tenant_id=$1 AND principal_id=$2 AND policy_id=$3),
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
	if err := database.QueryRow(ctx, `SELECT count(*) FROM iam.policy_attachments WHERE tenant_id=$1 AND principal_id=$2`, member.AccountID, member.ID).Scan(&attachments); err != nil || attachments != 0 {
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
		INSERT INTO iam.policy_attachments(tenant_id,id,principal_id,policy_id,resource_version,created_at,updated_at)
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
	if !rootIdentity.CanCreateAccounts || rootIdentity.Account.RootIdentity.PrincipalID != "principal-admin" {
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
	if identity(primaryB).CanCreateAccounts {
		t.Fatal("new primary inherited platform account-opening capability")
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
	if id := identity(childSessionA); id.User.ID != childA.ID || id.Account.ID != tenantA || id.CanCreateAccounts {
		t.Fatal("wrong tenant or platform capability in child identity")
	}
	if len(identity(childSessionB).PolicyAttachments) != 0 {
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
	request(http.MethodGet, "/v1/users?after="+string(childB.ID), root, nil, http.StatusOK)

	delegated := createUser(root, "delegated.admin", iamv1.SystemPolicyAccountAdministrator, http.StatusCreated)
	delegatedSession := login("delegated.admin@customer-a", childPassword, http.StatusOK)
	passwordChange(delegatedSession, childPassword, childChangedA)
	if identity(delegatedSession).CanCreateAccounts {
		t.Fatal("assignable administrator role granted platform access")
	}
	request(http.MethodGet, "/v1/accounts", delegatedSession, nil, http.StatusForbidden)
	request(http.MethodPost, "/v1/accounts", delegatedSession, newTenantBody, http.StatusForbidden)
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
	if json.Unmarshal(accountPage.Body.Bytes(), &accounts) != nil || len(accounts.Items) != 2 {
		t.Fatal("failed onboarding left a partial tenant")
	}
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
	assertIAMSecretsAbsent(t, ctx, admin, primaryBPassword, primaryBChanged, childPassword, childChangedA, childChangedB, resetPassword, primaryB, childSessionA, childSessionB, activeOne, activeTwo, resetSession)
	t.Run("platform tenant lifecycle and original primary recovery", func(t *testing.T) {
		proveTenantLifecycleHTTP(t, ctx, handler, admin, root, primaryB)
	})
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
	if json.Unmarshal(operatorIdentity.Body.Bytes(), &identity) != nil || !identity.CanCreateAccounts || len(identity.PolicyAttachments) != 1 || identity.User.ID == identity.Account.RootIdentity.PrincipalID {
		t.Fatal("tenant lifecycle still requires bootstrap/primary or tenant-admin identity")
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
		var result iamv1.Account
		if json.Unmarshal(response.Body.Bytes(), &result) != nil || iamv1.ValidateAccount(result) != nil {
			t.Fatal("invalid platform tenant detail")
		}
		return result
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
			'bindings',(SELECT jsonb_agg(jsonb_build_array(b.tenant_id,b.id,b.principal_id,b.policy_id,b.resource_version,b.revoked_at) ORDER BY b.tenant_id,b.id) FROM iam.policy_attachments AS b),
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
		WHERE tenant_id=$1 AND principal_id=$2 AND policy_id='system.account-administrator' AND revoked_at IS NULL RETURNING id)
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
		(SELECT count(*)=1 FROM iam.policy_attachments WHERE tenant_id=$1 AND principal_id=$2 AND policy_id='system.account-administrator' AND revoked_at IS NULL)`,
		tenantID, primaryID).Scan(&retainedRevocation, &repaired); err != nil || !retainedRevocation || !repaired {
		t.Fatal("primary recovery revived an old binding or did not restore exactly one tenant-admin binding")
	}
	request(http.MethodGet, "/v1/auth/me", primary, nil, http.StatusUnauthorized)
	request(http.MethodGet, "/v1/auth/me", memberSession, nil, http.StatusOK)
	login("lifecycle.primary", changed, http.StatusUnauthorized)
	primary = login("lifecycle.primary", recovered, http.StatusOK)
	current := request(http.MethodGet, "/v1/auth/me", primary, nil, http.StatusOK)
	if json.Unmarshal(current.Body.Bytes(), &identity) != nil || !identity.User.MustChangePassword || identity.CanCreateAccounts || len(identity.PolicyAttachments) != 1 || identity.PolicyAttachments[0].PolicyID != iamv1.SystemPolicyAccountAdministrator {
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
				EXISTS(SELECT 1 FROM iam.policy_attachments AS b WHERE b.tenant_id=p.tenant_id AND b.principal_id=p.id AND b.authority_scope='INSTALLATION' AND b.revoked_at IS NULL)
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
