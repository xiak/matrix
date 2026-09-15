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
	"reflect"
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

// Diagnostics only: count transient database failures without retaining SQL,
// arguments, credentials or error details from the runtime connection.
type iamTransactionFailureTrace struct {
	serialization atomic.Int64
	deadlock      atomic.Int64
}

func (*iamTransactionFailureTrace) TraceQueryStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryStartData) context.Context {
	return ctx
}

func (trace *iamTransactionFailureTrace) TraceQueryEnd(_ context.Context, _ *pgx.Conn, data pgx.TraceQueryEndData) {
	var databaseError *pgconn.PgError
	if errors.As(data.Err, &databaseError) {
		switch databaseError.Code {
		case "40001":
			trace.serialization.Add(1)
		case "40P01":
			trace.deadlock.Add(1)
		}
	}
}

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
		body, _ := json.Marshal(profileBoundIAMRequest(t, iamv1.AuthorizationRequest{Action: iamv1.ActionPaaSApplicationRead, Resource: iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "attachment-app"}, RequestID: "attachment-read", CorrelationID: "attachment-read"}, iamv1.AuthorizationResourceInstance, ""))
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

func profileBoundIAMRequest(t *testing.T, request iamv1.AuthorizationRequest, mode iamv1.AuthorizationResourceMode, usage iamv1.AuthorizationCollectionUsage) iamv1.AuthorizationRequest {
	t.Helper()
	result, err := iamv1.NewAuthorizationRequest(request.Action, request.Resource, mode, usage, request.RequestID, request.CorrelationID)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestIAMPolicyAuthorityStoragePostgres(t *testing.T) {
	const environment = "MATRIX_IAM_POLICY_POSTGRES_TEST_DSN"
	dsn := os.Getenv(environment)
	if dsn == "" {
		t.Skipf("set %s to a clean disposable PostgreSQL 18 database", environment)
	}
	// This retained-data fixture now runs ten serial protocol flows. Bound
	// their aggregate separately from each flow; it is not an operation SLO.
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
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
		AND to_regclass('iam.authorization_profiles') IS NULL AND to_regclass('iam.authorization_profile_heads') IS NULL
		AND to_regclass('iam.group_memberships') IS NULL AND to_regprocedure('iam.readiness()') IS NULL`).Scan(&emptyAuthority); err != nil || !emptyAuthority {
		t.Fatal("failed current installation exposed a partial authority")
	}
	// Insert a valid but different declaration at the exact source tuple before
	// normal seed registration. This is an isolated trusted-migrator collision,
	// not a runtime API, a legacy marker, or disabled immutability protection.
	variantProfile := iamv1.AllAuthorizationProfiles()[0]
	if len(variantProfile.Actions) < 2 {
		t.Fatal("profile collision fixture requires multiple declared actions")
	}
	variantProfile.Actions = variantProfile.Actions[:len(variantProfile.Actions)-1]
	variantCanonical, variantDigest, err := iamv1.CanonicalizeAuthorizationProfile(variantProfile)
	if err != nil {
		t.Fatal(err)
	}
	quote := func(value string) string { return "'" + strings.ReplaceAll(value, "'", "''") + "'" }
	collisionSQL := fmt.Sprintf(`CREATE FUNCTION public.matrix_current_iam_fault() RETURNS event_trigger LANGUAGE plpgsql AS $body$
		BEGIN IF EXISTS(SELECT 1 FROM pg_event_trigger_ddl_commands() WHERE object_identity='iam.authorization_profiles')
		THEN INSERT INTO iam.authorization_profiles(product,revision,canonical_document,content_digest)
		VALUES(%s,%d,%s,%s); RAISE NOTICE 'matrix-current-iam-fault'; END IF; END $body$;
		CREATE EVENT TRIGGER matrix_current_iam_fault ON ddl_command_end EXECUTE FUNCTION public.matrix_current_iam_fault()`,
		quote(string(variantProfile.Product)), variantProfile.Revision, quote(variantCanonical), quote(variantDigest))
	migrationFaultReached.Store(false)
	if _, err := admin.Exec(ctx, collisionSQL); err != nil {
		t.Fatal("install exact-tuple collision fixture")
	}
	if err := iammigration.Up(ctx, admin); err == nil || !migrationFaultReached.Load() {
		t.Fatal("valid same-revision profile variant did not reject registration")
	}
	if _, err := admin.Exec(ctx, "ROLLBACK; DROP EVENT TRIGGER matrix_current_iam_fault; DROP FUNCTION public.matrix_current_iam_fault()"); err != nil {
		t.Fatal("finish exact-tuple collision fixture")
	}
	if err := admin.QueryRow(ctx, `SELECT to_regclass('iam.authorization_profiles') IS NULL
		AND to_regclass('iam.authorization_profile_heads') IS NULL AND to_regclass('iam.principals') IS NULL
		AND to_regclass('iam.policy_attachments') IS NULL AND to_regclass('iam.audit_outbox') IS NULL`).Scan(&emptyAuthority); err != nil || !emptyAuthority {
		t.Fatal("same-revision conflict exposed partial IAM state")
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
		retired := profileBoundIAMRequest(t, iamv1.AuthorizationRequest{Action: iamv1.ActionIAMUserRead,
			Resource:  iamv1.ResourceReference{Kind: iamv1.ResourceUser, ID: "retired-target"},
			RequestID: "retired-action-request", CorrelationID: "retired-action-request"}, iamv1.AuthorizationResourceInstance, "")
		retired.Action, retired.Resource.Kind = definition.Action, definition.ResourceKind
		body, err := json.Marshal(retired)
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
		var databaseTime time.Time
		if err := admin.QueryRow(ctx, "SELECT transaction_timestamp()").Scan(&databaseTime); err != nil {
			t.Fatal(err)
		}
		result, evidence, err := authority.EvaluateAttachedPolicies(databaseTime.UTC(), document.Organization.ID, document.InstallationID,
			iamv1.Subject{Type: iamv1.PrincipalUser, ID: document.Administrator.ID}, readSnapshot(), action, resource)
		if err != nil || result.Allowed != allowed || (allowed && len(evidence) == 0) {
			t.Fatalf("stored policy decision action=%s allowed=%t error=%v", action, result.Allowed, err)
		}
		body, err := json.Marshal(profileBoundIAMRequest(t, iamv1.AuthorizationRequest{Action: action, Resource: resource, RequestID: "policy-storage-authorize", CorrelationID: "policy-storage-authorize"}, iamv1.AuthorizationResourceInstance, ""))
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
	// Establish history while the original attachment is valid. Later fixtures
	// revoke that attachment and retire policies before advancing a profile head.
	for _, source := range []struct {
		credential string
		action     iamv1.Action
		kind       iamv1.ResourceKind
		usage      iamv1.AuthorizationCollectionUsage
	}{
		{paasCredential, iamv1.ActionPaaSApplicationCreate, iamv1.ResourceApplication, iamv1.AuthorizationCollectionCreate},
		{auditCredential, iamv1.ActionAuditRecordRead, iamv1.ResourceAuditRecord, iamv1.AuthorizationCollectionList},
	} {
		request := profileBoundIAMRequest(t, iamv1.AuthorizationRequest{Action: source.action,
			Resource: iamv1.ResourceReference{Kind: source.kind, ID: "collection"}, RequestID: "registry-historical", CorrelationID: "registry-historical"}, iamv1.AuthorizationResourceCollection, source.usage)
		response := performIAMRequestWithSubject(handler, mustIAMJSON(t, request), source.credential, primary)
		var decision iamv1.AuthorizationDecision
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &decision) != nil || !decision.Allowed || iamv1.CheckAuthorizationDecisionForRequest(decision, request) != nil {
			t.Fatal("missing original profile-bound business authority")
		}
	}
	t.Run("profile-bound recorder rejects incomplete and substituted authority", func(t *testing.T) {
		proveProfileBoundRecorder(t, ctx, admin, handler, primary)
	})
	t.Run("instance list and creation decisions cannot be interchanged", func(t *testing.T) {
		proveDecisionTargetConsumption(t, ctx, admin, handler, primary)
	})
	runFlow := func(name string, prove func(*testing.T, context.Context, http.Handler, *pgx.Conn, string)) {
		t.Run(name, func(t *testing.T) {
			flowContext, cancel := context.WithTimeout(ctx, 2*time.Minute)
			defer cancel()
			deadline, _ := flowContext.Deadline()
			boundedHandler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				requestContext, cancelRequest := context.WithDeadline(request.Context(), deadline)
				defer cancelRequest()
				stop := context.AfterFunc(flowContext, cancelRequest)
				defer stop()
				handler.ServeHTTP(response, request.WithContext(requestContext))
			})
			prove(t, flowContext, boundedHandler, admin, primary)
		})
	}
	runFlow("policy directories isolate metadata and permissions", provePolicyDirectories)
	runFlow("user_permission_boundaries", proveUserPermissionBoundaries)
	runFlow("user_boundary_policy_competition", proveUserBoundaryPolicyRaces)
	runFlow("direct policy attachment management", proveDirectPolicyAttachments)
	runFlow("group inheritance and terminal membership", proveGroupInheritance)
	runFlow("customer policy publication and current authority", proveCustomerPolicyPublication)
	runFlow("customer immutable versions and default selection", proveCustomerPolicyVersions)
	runFlow("customer policy metadata lifecycle", proveCustomerPolicyMetadata)
	runFlow("customer policy terminal deletion", proveCustomerPolicyDeletion)
	runFlow("policy publication versus attachment revision", provePolicyDefaultAttachmentRaces)
	runFlow("policy-backed credential transaction races", provePasswordSessionRaces)
	runFlow("platform scope protects credentials independently of policy name", provePolicyScopeCredentialProtection)
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
	assertRejected("immutable-boundary-evidence", `UPDATE iam.authorization_decisions SET boundary_evidence='{}'::jsonb`, "42501")
	for _, attack := range []struct{ name, evidence string }{
		{"boundary-evidence-missing", `NULL::jsonb`},
		{"boundary-evidence-empty", `'{}'::jsonb`},
		{"boundary-evidence-wrong-scope", `'{"state":"NOT_APPLICABLE"}'::jsonb`},
		{"boundary-evidence-stale-user", `jsonb_set(boundary_evidence,'{userResourceVersion}','9007199254740991'::jsonb)`},
	} {
		assertRejected(attack.name, `SELECT iam.record_authorization($1,$2,
			jsonb_build_object('request',document-'apiVersion'-'kind'-'id'-'allowed'-'reason'-'decidedAt'-'tenantId'-'installationId'-'subject','decision',
			document||jsonb_build_object('id','forged-boundary-decision','decidedAt',
			to_char(transaction_timestamp() AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))),
			'{}'::jsonb,policy_evidence,`+attack.evidence+`,2) FROM iam.authorization_decisions
			WHERE principal_id=$2 AND action_name='paas.application.read' AND allowed ORDER BY decided_at,id LIMIT 1`,
			"42501", document.Organization.ID, document.Administrator.ID)
	}
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
			jsonb_build_object('request',document-'apiVersion'-'kind'-'id'-'allowed'-'reason'-'decidedAt'-'tenantId'-'installationId'-'subject','decision',
			document||jsonb_build_object('id','forged-policy-decision','decidedAt',
			to_char(transaction_timestamp() AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))),
			'{}'::jsonb,`+attack.evidence+`,boundary_evidence,2) FROM iam.authorization_decisions WHERE allowed ORDER BY decided_at,id LIMIT 1`,
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
	budgetRequest, _ := json.Marshal(profileBoundIAMRequest(t, iamv1.AuthorizationRequest{Action: iamv1.ActionPaaSApplicationRead,
		Resource:  iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "policy-storage-application"},
		RequestID: "policy-over-budget", CorrelationID: "policy-over-budget"}, iamv1.AuthorizationResourceInstance, ""))
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
	retiredContent := func() []byte {
		t.Helper()
		var encoded []byte
		if err := admin.QueryRow(ctx, `SELECT COALESCE(jsonb_agg(jsonb_build_object('policyId',policy_id,'versionId',id,
			'document',document,'canonical',canonical_document,'digest',content_digest,'createdAt',created_at,'retiredAt',retired_at)
			ORDER BY policy_id,id),'[]'::jsonb) FROM iam.policy_versions WHERE retired_at IS NOT NULL`).Scan(&encoded); err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	beforeRetiredContent := retiredContent()
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
	if !bytes.Equal(beforeRetiredContent, retiredContent()) {
		t.Fatal("schema/bootstrap replay altered retired version identity, content or terminal state")
	}
	var retainedVersions int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM iam.policy_versions WHERE policy_id='system.account-administrator'`).Scan(&retainedVersions); err != nil || retainedVersions != 2 {
		t.Fatal("migration lost an immutable version")
	}
	var deletionChanged bool
	if err := admin.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM iam.audit_outbox fact
		LEFT JOIN iam.policies p ON p.id=fact.event_document#>>'{target,id}' AND p.owner_tenant_id=fact.tenant_id
		LEFT JOIN iam.policy_versions v ON v.policy_id=p.id AND v.id=p.default_version_id
		WHERE fact.event_document->>'action'='iam.policy.deleted' AND (p.id IS NULL OR p.status<>'RETIRED' OR v.id IS NULL
		OR EXISTS(SELECT 1 FROM iam.policy_attachments a WHERE a.policy_id=p.id AND a.revoked_at IS NULL)))`).Scan(&deletionChanged); err != nil || deletionChanged {
		t.Fatal("schema/bootstrap replay lost deleted policy history or resurrected authority")
	}
	identity := performIAMRequest(handler, http.MethodGet, "/v1/service-identity", verifierCredential, nil)
	var service iamv1.ServiceIdentity
	if identity.Code != http.StatusOK || json.Unmarshal(identity.Body.Bytes(), &service) != nil ||
		service.Purpose != iamv1.ServiceInstallationVerifier || service.InstallationID != document.InstallationID {
		t.Fatal("policy migration changed sealed verifier purpose or installation")
	}
	// This final fixture deliberately advances a trusted release head. The old
	// source must refuse it, not downgrade it during cleanup or migration replay.
	t.Run("immutable profile registry and current source admission", func(t *testing.T) {
		proveAuthorizationProfileRegistry(t, ctx, dsn, admin, handler, primary)
	})
}

func proveDecisionTargetConsumption(t *testing.T, ctx context.Context, admin *pgx.Conn, handler http.Handler, bearer string) {
	t.Helper()
	targets := []struct {
		action iamv1.Action
		mode   iamv1.AuthorizationResourceMode
		usage  iamv1.AuthorizationCollectionUsage
	}{
		{iamv1.ActionManagedServiceInstallationRead, iamv1.AuthorizationResourceInstance, ""},
		{iamv1.ActionManagedServiceInstallationRead, iamv1.AuthorizationResourceCollection, iamv1.AuthorizationCollectionList},
		{iamv1.ActionManagedServiceInstallationCreate, iamv1.AuthorizationResourceCollection, iamv1.AuthorizationCollectionCreate},
	}
	for index, original := range targets {
		request := profileBoundIAMRequest(t, iamv1.AuthorizationRequest{Action: original.action,
			Resource: iamv1.ResourceReference{Kind: iamv1.ResourceServiceInstallation, ID: "collection"}, RequestID: "target-consumption", CorrelationID: "target-consumption"}, original.mode, original.usage)
		response := performIAMRequestWithSubject(handler, mustIAMJSON(t, request), paasCredential, bearer)
		var decision iamv1.AuthorizationDecision
		if response.Code != http.StatusOK || iamv1.DecodeRequest(response.Body, &decision) != nil || !decision.Allowed || iamv1.CheckAuthorizationDecisionForRequest(decision, request) != nil {
			t.Fatal("missing actual target-mode decision")
		}
		var policy, boundary, event []byte
		if err := admin.QueryRow(ctx, `SELECT d.policy_evidence,d.boundary_evidence,o.event_document
			FROM iam.authorization_decisions d JOIN iam.audit_outbox o ON o.tenant_id=d.tenant_id
			AND o.event_document->>'action'='iam.authorization.decided' AND o.event_document->>'iamDecisionId'=d.id
			WHERE d.tenant_id=$1 AND d.id=$2`, decision.TenantID, decision.ID).Scan(&policy, &boundary, &event); err != nil {
			t.Fatal(err)
		}
		var fact auditv1.Event
		if json.Unmarshal(event, &fact) != nil {
			t.Fatal("invalid source authority fact")
		}
		tx, err := admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		var now time.Time
		if err := tx.QueryRow(ctx, "SELECT transaction_timestamp()").Scan(&now); err != nil {
			t.Fatal(err)
		}
		decision.ID, decision.DecidedAt = "target-consumption-fixture", now.UTC()
		fact.EventID, fact.IAMDecisionID, fact.Target.ID, fact.OccurredAt = "target-consumption-fact", auditv1.DecisionID(decision.ID), string(decision.ID), now.UTC()
		if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+pgx.Identifier{iamHTTPTestRole}.Sanitize()); err != nil {
			t.Fatal(err)
		}
		envelope := struct {
			Request  iamv1.AuthorizationRequest  `json:"request"`
			Decision iamv1.AuthorizationDecision `json:"decision"`
		}{request, decision}
		if _, err := tx.Exec(ctx, `SELECT iam.record_authorization($1,$2,$3::jsonb,$4::jsonb,$5::jsonb,$6::jsonb,2)`,
			decision.TenantID, decision.Subject.ID, string(mustIAMJSON(t, envelope)), string(mustIAMJSON(t, fact)), string(policy), string(boundary)); err != nil {
			t.Fatalf("record target fixture: %v", err)
		}
		// The assertion is private; its owning SECURITY DEFINER entrypoints call
		// it as owner. Switching here tests that exact invariant, not a new grant.
		if _, err := tx.Exec(ctx, "RESET ROLE; SET LOCAL ROLE matrix_iam_owner"); err != nil {
			t.Fatal(err)
		}
		for candidateIndex, candidate := range targets {
			if _, err := tx.Exec(ctx, "SAVEPOINT target_consumer"); err != nil {
				t.Fatal(err)
			}
			var usage any
			if candidate.usage != "" {
				usage = string(candidate.usage)
			}
			_, err := tx.Exec(ctx, `SELECT iam.assert_allowed_decision($1,$2,$3,$4,'SERVICE_INSTALLATION','collection',$5,$6)`,
				decision.TenantID, decision.Subject.ID, decision.ID, candidate.action, candidate.mode, usage)
			if candidateIndex == index {
				if err != nil {
					t.Fatalf("matching target rejected: %v", err)
				}
			} else {
				var failure *pgconn.PgError
				if !errors.As(err, &failure) || failure.Code != "42501" {
					t.Fatalf("different target mode consumed a decision: %v", err)
				}
			}
			if _, err := tx.Exec(ctx, "ROLLBACK TO SAVEPOINT target_consumer"); err != nil {
				t.Fatal(err)
			}
		}
		if err := tx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
	}
}

func proveProfileBoundRecorder(t *testing.T, ctx context.Context, admin *pgx.Conn, handler http.Handler, bearer string) {
	t.Helper()
	request := profileBoundIAMRequest(t, iamv1.AuthorizationRequest{Action: iamv1.ActionPaaSApplicationRead,
		Resource: iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "collection"}, RequestID: "wire-proof", CorrelationID: "wire-correlation"}, iamv1.AuthorizationResourceInstance, "")
	for _, allowed := range []bool{false, true} {
		credential := auditCredential
		if allowed {
			credential = paasCredential
		}
		response := performIAMRequestWithSubject(handler, mustIAMJSON(t, request), credential, bearer)
		var decision iamv1.AuthorizationDecision
		if response.Code != http.StatusOK || iamv1.DecodeRequest(response.Body, &decision) != nil || decision.Allowed != allowed || iamv1.CheckAuthorizationDecisionForRequest(decision, request) != nil {
			t.Fatalf("actual bound authorization failed: status=%d", response.Code)
		}
		var version int
		var product, digest, mode, tenant, principal string
		var revision uint64
		var usage *string
		var factBytes, policyBytes, boundaryBytes []byte
		if err := admin.QueryRow(ctx, `SELECT d.tenant_id,d.principal_id,d.contract_version,d.profile_product,d.profile_revision,d.profile_content_digest,d.resource_mode,d.collection_usage,
			o.event_document,d.policy_evidence,d.boundary_evidence FROM iam.authorization_decisions d JOIN iam.audit_outbox o
			ON o.tenant_id=d.tenant_id AND o.event_document->>'action'='iam.authorization.decided' AND o.event_document->>'iamDecisionId'=d.id WHERE d.id=$1`, decision.ID).
			Scan(&tenant, &principal, &version, &product, &revision, &digest, &mode, &usage, &factBytes, &policyBytes, &boundaryBytes); err != nil {
			t.Fatal(err)
		}
		if version != 2 || product != string(request.Profile.Product) || revision != request.Profile.Revision || digest != request.Profile.ContentDigest || mode != string(request.ResourceMode) || usage != nil {
			t.Fatal("stored row did not preserve exact contract/instance binding")
		}
		var fact auditv1.Event
		if json.Unmarshal(factBytes, &fact) != nil {
			t.Fatal("invalid original fact")
		}
		for name, mutate := range map[string]func(map[string]any){
			"valid":            func(map[string]any) {},
			"missing request":  func(e map[string]any) { delete(e, "request") },
			"missing decision": func(e map[string]any) { delete(e, "decision") },
			"extra envelope":   func(e map[string]any) { e["permit"] = true },
			"null request":     func(e map[string]any) { e["request"] = nil },
			"profile":          func(e map[string]any) { e["request"].(map[string]any)["profile"] = nil },
			"resource":         func(e map[string]any) { e["request"].(map[string]any)["resource"].(map[string]any)["id"] = "other" },
			"action":           func(e map[string]any) { e["request"].(map[string]any)["action"] = "paas.application.create" },
			"requestId":        func(e map[string]any) { e["request"].(map[string]any)["requestId"] = "other-request" },
			"correlationId":    func(e map[string]any) { e["request"].(map[string]any)["correlationId"] = "other-correlation" },
			"mode":             func(e map[string]any) { e["request"].(map[string]any)["resourceMode"] = "COLLECTION" },
			"usage presence":   func(e map[string]any) { e["request"].(map[string]any)["collectionUsage"] = nil },
			"both stale revision": func(e map[string]any) {
				for _, k := range []string{"request", "decision"} {
					e[k].(map[string]any)["profile"].(map[string]any)["revision"] = 1000
				}
			},
			"both wrong digest": func(e map[string]any) {
				for _, k := range []string{"request", "decision"} {
					e[k].(map[string]any)["profile"].(map[string]any)["contentDigest"] = "sha256:" + strings.Repeat("0", 64)
				}
			},
			"both null usage": func(e map[string]any) {
				for _, k := range []string{"request", "decision"} {
					e[k].(map[string]any)["collectionUsage"] = nil
				}
			},
			"both missing profile": func(e map[string]any) {
				for _, k := range []string{"request", "decision"} {
					delete(e[k].(map[string]any), "profile")
				}
			},
		} {
			t.Run(fmt.Sprintf("allowed=%v/%s", allowed, name), func(t *testing.T) {
				tx, err := admin.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback(ctx)
				var now time.Time
				if err := tx.QueryRow(ctx, "SELECT transaction_timestamp()").Scan(&now); err != nil {
					t.Fatal(err)
				}
				copyDecision, copyFact := decision, fact
				copyDecision.ID, copyDecision.DecidedAt = "recorder-fixture", now.UTC()
				copyFact.EventID, copyFact.IAMDecisionID, copyFact.Target.ID, copyFact.OccurredAt = "recorder-fixture-event", "recorder-fixture", "recorder-fixture", now.UTC()
				envelope := map[string]any{}
				if json.Unmarshal(mustIAMJSON(t, struct {
					Request  iamv1.AuthorizationRequest  `json:"request"`
					Decision iamv1.AuthorizationDecision `json:"decision"`
				}{request, copyDecision}), &envelope) != nil {
					t.Fatal("invalid envelope")
				}
				mutate(envelope)
				if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+pgx.Identifier{iamHTTPTestRole}.Sanitize()); err != nil {
					t.Fatal(err)
				}
				_, err = tx.Exec(ctx, "SELECT iam.record_authorization($1,$2,$3::jsonb,$4::jsonb,$5::jsonb,$6::jsonb,2)", tenant, principal, string(mustIAMJSON(t, envelope)), string(mustIAMJSON(t, copyFact)), string(policyBytes), string(boundaryBytes))
				if name == "valid" {
					if err != nil {
						t.Fatalf("restricted recorder rejected complete original input: %v", err)
					}
				} else {
					var failure *pgconn.PgError
					if !errors.As(err, &failure) || failure.Code != "22023" {
						t.Fatalf("bad binding error=%v", err)
					}
				}
				if err := tx.Rollback(ctx); err != nil {
					t.Fatal(err)
				}
				var count int
				if err := admin.QueryRow(ctx, `SELECT (SELECT count(*) FROM iam.authorization_decisions WHERE id='recorder-fixture')+(SELECT count(*) FROM iam.audit_outbox WHERE event_id='recorder-fixture-event')`).Scan(&count); err != nil || count != 0 {
					t.Fatal("recorder fixture exposed partial facts")
				}
			})
		}
	}
	for _, call := range []struct{ sql, code string }{
		{`SELECT iam.record_authorization('tenant','principal','{}','{}','[]','{}')`, "42883"},
		{`SELECT iam.record_authorization('tenant','principal','{}','{}','[]','{}',1)`, "22023"},
		{`SELECT iam.record_authorization('tenant','principal','{}','{}','[]','{}',NULL)`, "22023"},
	} {
		tx, err := admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(ctx, "SET LOCAL ROLE "+pgx.Identifier{iamHTTPTestRole}.Sanitize()); err != nil {
			t.Fatal(err)
		}
		_, err = tx.Exec(ctx, call.sql)
		_ = tx.Rollback(ctx)
		var failure *pgconn.PgError
		if !errors.As(err, &failure) || failure.Code != call.code {
			t.Fatalf("old/unspecified contract admitted: %v", err)
		}
	}
}

func proveAuthorizationProfileRegistry(t *testing.T, ctx context.Context, dsn string, admin *pgx.Conn, handler http.Handler, bearer string) {
	t.Helper()
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.User, config.ConnConfig.Password = iamHTTPTestRole, iamHTTPTestPassword
	config.MaxConns = 2
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal("open restricted profile reader")
	}
	defer pool.Close()
	repository, err := iampostgres.NewRepository(pool)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := func() []byte {
		t.Helper()
		var result []byte
		if err := admin.QueryRow(ctx, `SELECT jsonb_build_object(
			'archive',(SELECT jsonb_agg(to_jsonb(a) ORDER BY product,revision) FROM iam.authorization_profiles a),
			'heads',(SELECT jsonb_agg(to_jsonb(h) ORDER BY product) FROM iam.authorization_profile_heads h))`).Scan(&result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	before := snapshot()
	applyIAMSchema(t, ctx, admin)
	if !bytes.Equal(before, snapshot()) {
		t.Fatal("equal registration replay changed immutable content or registration/adoption time")
	}
	checkCurrent := func() error {
		return repository.WithinTransaction(ctx, func(ctx context.Context, tx identityaccess.Transaction) error {
			return tx.CheckCurrentAuthorizationProfiles(ctx)
		})
	}
	if err := checkCurrent(); err != nil {
		t.Fatalf("current registry differs from running source: %v", err)
	}
	var historicalEvent auditv1.Event
	var historicalBytes []byte
	if err := admin.QueryRow(ctx, `SELECT event_document FROM iam.audit_outbox
		WHERE event_document->>'action'='iam.bootstrap.applied' LIMIT 1`).Scan(&historicalBytes); err != nil || json.Unmarshal(historicalBytes, &historicalEvent) != nil {
		t.Fatal("read original committed IAM fact")
	}
	resolveHistory := func() {
		t.Helper()
		body, err := json.Marshal(iamv1.ResolveAuditProducerRequest{Event: historicalEvent})
		if err != nil {
			t.Fatal(err)
		}
		response := performIAMRequest(handler, http.MethodPost, "/v1/audit-producer:resolve", iamProducerCredential, body)
		var proof iamv1.AuditProducerAuthorization
		_, expectedDigest, err := auditv1.CanonicalizeEvent(auditv1.SourceIAM, historicalEvent)
		if err != nil || response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &proof) != nil ||
			iamv1.ValidateAuditProducerAuthorization(proof) != nil || proof.ContentDigest != expectedDigest {
			t.Fatal("current catalog drift changed original fact admission or content commitment")
		}
	}
	resolveHistory()
	// Original source facts are synthetic, but their authority is obtained from
	// actual HTTP decisions. Replaying them must use each immutable archive, not
	// a current-head check or a newly inferred request shape.
	var businessHistory []struct {
		credential string
		event      auditv1.Event
		document   []byte
	}
	for _, source := range []struct {
		credential string
		action     iamv1.Action
		resource   iamv1.ResourceKind
		usage      iamv1.AuthorizationCollectionUsage
		fact       auditv1.Action
		target     auditv1.TargetReference
		operation  auditv1.OperationID
	}{
		{paasCredential, iamv1.ActionPaaSApplicationCreate, iamv1.ResourceApplication, iamv1.AuthorizationCollectionCreate, auditv1.ActionPaaSApplicationCreated, auditv1.TargetReference{Kind: auditv1.TargetApplication, ID: "registry-history-app"}, "registry-history-operation"},
		{auditCredential, iamv1.ActionAuditRecordRead, iamv1.ResourceAuditRecord, iamv1.AuthorizationCollectionList, auditv1.ActionAuditRecordsRead, auditv1.TargetReference{Kind: auditv1.TargetAuditRecords, ID: "records"}, ""},
	} {
		request := profileBoundIAMRequest(t, iamv1.AuthorizationRequest{Action: source.action,
			Resource: iamv1.ResourceReference{Kind: source.resource, ID: "collection"}, RequestID: "registry-historical", CorrelationID: "registry-historical"}, iamv1.AuthorizationResourceCollection, source.usage)
		var document []byte
		if err := admin.QueryRow(ctx, `SELECT document FROM iam.authorization_decisions
			WHERE request_id='registry-historical' AND action_name=$1 AND contract_version=2`, source.action).Scan(&document); err != nil {
			t.Fatal("missing original protected business decision")
		}
		var decision iamv1.AuthorizationDecision
		if json.Unmarshal(document, &decision) != nil || !decision.Allowed ||
			iamv1.CheckAuthorizationDecisionForRequest(decision, request) != nil || decision.Subject == nil {
			t.Fatal("missing real profile-bound historical decision")
		}
		fact := auditv1.Event{APIVersion: auditv1.APIVersion, Kind: "AuditEvent", EventID: auditv1.EventID("history-" + decision.ID),
			TenantID: auditv1.TenantID(decision.TenantID), Actor: auditv1.ActorReference{Type: auditv1.ActorUser, ID: auditv1.ActorID(decision.Subject.ID)},
			IAMDecisionID: auditv1.DecisionID(decision.ID), Action: source.fact, Target: source.target, Result: auditv1.ResultSucceeded,
			RequestDigest: "sha256:" + strings.Repeat("1", 64), RequestID: request.RequestID, CorrelationID: request.CorrelationID,
			OperationID: source.operation, OccurredAt: decision.DecidedAt.Add(time.Microsecond)}
		businessHistory = append(businessHistory, struct {
			credential string
			event      auditv1.Event
			document   []byte
		}{source.credential, fact, document})
	}
	resolveBusinessHistory := func() {
		t.Helper()
		for _, original := range businessHistory {
			response := performIAMRequest(handler, http.MethodPost, "/v1/audit-producer:resolve", original.credential,
				mustIAMJSON(t, iamv1.ResolveAuditProducerRequest{Event: original.event}))
			var proof iamv1.AuditProducerAuthorization
			contract, _ := auditv1.ContractForAction(original.event.Action)
			_, digest, err := auditv1.CanonicalizeEvent(contract.Source, original.event)
			if err != nil || response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &proof) != nil ||
				iamv1.ValidateAuditProducerAuthorization(proof) != nil || proof.ContentDigest != digest {
				t.Fatal("historical business proof consulted a current head or changed its event commitment")
			}
			var current []byte
			if err := admin.QueryRow(ctx, `SELECT document FROM iam.authorization_decisions WHERE tenant_id=$1 AND id=$2 AND contract_version=2`, original.event.TenantID, original.event.IAMDecisionID).Scan(&current); err != nil || !bytes.Equal(current, original.document) {
				t.Fatal("historical decision changed while current profile advanced")
			}
		}
	}
	resolveBusinessHistory()
	profile, found := iamv1.LookupAuthorizationProfile(iamv1.ProductPaaS)
	if !found {
		t.Fatal("missing PaaS source profile")
	}
	original, digest, err := iamv1.CanonicalizeAuthorizationProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	reference := iamv1.AuthorizationProfileReference{Product: profile.Product, Revision: profile.Revision, ContentDigest: digest}
	var returnedCanonical, archivedCanonical string
	if err := pool.QueryRow(ctx, `SELECT canonical_document FROM iam.lookup_authorization_profile($1,$2,$3)`, reference.Product, reference.Revision, reference.ContentDigest).Scan(&returnedCanonical); err != nil {
		t.Fatal("restricted exact lookup did not return archived content")
	}
	if err := admin.QueryRow(ctx, `SELECT canonical_document FROM iam.authorization_profiles WHERE product=$1 AND revision=$2`, reference.Product, reference.Revision).Scan(&archivedCanonical); err != nil ||
		returnedCanonical != archivedCanonical || returnedCanonical != original {
		t.Fatal("exact lookup rewrote original archive bytes")
	}
	lookup := func(expected iamv1.AuthorizationProfileReference, want bool) {
		t.Helper()
		err := repository.WithinTransaction(ctx, func(ctx context.Context, tx identityaccess.Transaction) error {
			actual, found, err := tx.LookupAuthorizationProfile(ctx, expected)
			if err != nil {
				return err
			}
			if found != want || (found && iamv1.CheckAuthorizationProfileReference(actual, expected) != nil) {
				t.Error("historical lookup changed the requested product/revision/digest")
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	lookup(reference, true)
	wrong := reference
	wrong.ContentDigest = "sha256:" + strings.Repeat("0", 64)
	lookup(wrong, false)
	wrong = reference
	wrong.Revision++
	lookup(wrong, false)
	wrong = reference
	wrong.Product = "unregistered-product"
	lookup(wrong, false)
	rejectSQL := func(role, statement, code string, args ...any) {
		t.Helper()
		tx, err := admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+pgx.Identifier{role}.Sanitize()); err != nil {
			t.Fatal(err)
		}
		_, err = tx.Exec(ctx, statement, args...)
		var failure *pgconn.PgError
		if !errors.As(err, &failure) || failure.Code != code {
			t.Fatalf("profile mutation/read did not fail with %s: %v", code, err)
		}
	}
	for _, statement := range []string{
		`UPDATE iam.authorization_profiles SET content_digest=content_digest`,
		`DELETE FROM iam.authorization_profiles`,
		`TRUNCATE iam.authorization_profiles CASCADE`,
		`UPDATE iam.authorization_profile_heads SET revision=revision`,
		`DELETE FROM iam.authorization_profile_heads`,
		`TRUNCATE iam.authorization_profile_heads`,
	} {
		rejectSQL("matrix_iam_owner", statement, "42501")
	}
	for _, role := range []string{"matrix_iam_api", "matrix_iam_worker", "matrix_iam_credential_recovery"} {
		rejectSQL(role, `INSERT INTO iam.authorization_profiles(product,revision,canonical_document,content_digest) VALUES($1,2,$2,$3)`, "42501", profile.Product, original, digest)
		rejectSQL(role, `UPDATE iam.authorization_profile_heads SET revision=revision+1,adopted_at=transaction_timestamp()`, "42501")
		rejectSQL(role, `SELECT * FROM iam.authorization_profiles`, "42501")
		if role != "matrix_iam_api" {
			rejectSQL(role, `SELECT * FROM iam.current_authorization_profiles()`, "42501")
			rejectSQL(role, `SELECT * FROM iam.lookup_authorization_profile($1,$2,$3)`, "42501", reference.Product, reference.Revision, reference.ContentDigest)
		}
	}
	// Trusted release fixture only: an archived declaration is not implicitly
	// current. Runtime identities never acquire this insertion capability.
	profile.Revision++
	canonical, futureDigest, err := iamv1.CanonicalizeAuthorizationProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	future := iamv1.AuthorizationProfileReference{Product: profile.Product, Revision: profile.Revision, ContentDigest: futureDigest}
	rejectSQL("matrix_iam_owner", `UPDATE iam.authorization_profile_heads SET revision=$2,adopted_at=transaction_timestamp() WHERE product=$1`, "23503", future.Product, future.Revision)
	rejectSQL("matrix_iam_owner", `INSERT INTO iam.authorization_profiles(product,revision,canonical_document,content_digest) VALUES($1,$2,$3,$4)`, "23514", future.Product, future.Revision, canonical, digest)
	if _, err := admin.Exec(ctx, `INSERT INTO iam.authorization_profiles(product,revision,canonical_document,content_digest) VALUES($1,$2,$3,$4)`, profile.Product, profile.Revision, canonical, futureDigest); err != nil {
		t.Fatal(err)
	}
	lookup(future, true)
	lookup(reference, true)
	if err := checkCurrent(); err != nil {
		t.Fatal("non-current archive was incorrectly treated as current source drift")
	}
	applyIAMSchema(t, ctx, admin)
	lookup(future, true)
	for _, function := range []string{"iam.current_authorization_profiles()", "iam.lookup_authorization_profile(text,bigint,text)",
		"iam.record_authorization(text,text,jsonb,jsonb,jsonb,jsonb,integer)", "iam.read_audit_evidence(text,text,text,text,jsonb)"} {
		// Configuration spelling is not the boundary: accept the same two
		// PostgreSQL identifiers with different whitespace, then roll it back.
		equivalent, err := admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := equivalent.Exec(ctx, "SELECT set_config('search_path',' pg_catalog , pg_temp ',true); ALTER FUNCTION "+function+" SET search_path FROM CURRENT"); err != nil {
			_ = equivalent.Rollback(ctx)
			t.Fatal(err)
		}
		err = iammigration.Verify(ctx, equivalent)
		_ = equivalent.Rollback(ctx)
		if err != nil {
			t.Fatal("verification compared configuration formatting rather than safe namespace semantics")
		}
		for _, mutation := range []string{
			"ALTER FUNCTION " + function + " SET search_path=public,pg_catalog,pg_temp",
			"ALTER FUNCTION " + function + " SET search_path=pg_temp,pg_catalog",
			"ALTER FUNCTION " + function + " SET search_path TO 'pg_catalog , pg_temp'",
			"GRANT EXECUTE ON FUNCTION " + function + " TO PUBLIC",
			"GRANT EXECUTE ON FUNCTION " + function + " TO matrix_iam_worker",
			"GRANT EXECUTE ON FUNCTION " + function + " TO matrix_iam_api WITH GRANT OPTION",
		} {
			tx, err := admin.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(ctx, mutation); err != nil {
				_ = tx.Rollback(ctx)
				t.Fatal("install isolated registry read-boundary drift")
			}
			err = iammigration.Verify(ctx, tx)
			_ = tx.Rollback(ctx)
			if err == nil {
				t.Fatal("verification accepted unsafe function search_path or execute privilege")
			}
		}
	}
	for _, mutation := range []string{
		"ALTER TABLE iam.authorization_decisions ALTER COLUMN contract_version SET DEFAULT 1",
		"ALTER TABLE iam.authorization_decisions ALTER COLUMN contract_version DROP NOT NULL",
		"ALTER TABLE iam.authorization_decisions DROP CONSTRAINT authorization_decision_contract_valid",
		"ALTER TABLE iam.authorization_decisions DISABLE TRIGGER authorization_decisions_are_immutable",
		"ALTER TABLE iam.authorization_decisions DISABLE TRIGGER authorization_decisions_cannot_be_truncated",
	} {
		tx, err := admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, mutation); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatal("install isolated decision contract drift")
		}
		var ready bool
		if err := tx.QueryRow(ctx, "SELECT ready FROM iam.readiness()").Scan(&ready); err != nil || ready {
			_ = tx.Rollback(ctx)
			t.Fatal("readiness accepted missing decision history protection")
		}
		err = iammigration.Verify(ctx, tx)
		_ = tx.Rollback(ctx)
		if err == nil {
			t.Fatal("verification accepted missing decision history protection")
		}
	}
	if err := iammigration.Verify(ctx, admin); err != nil {
		t.Fatal("registry boundary drift fixture changed the installed authority")
	}
	// A checked authorization transaction holds the selected head until commit.
	// Prove the competing publisher actually reaches PostgreSQL and is blocked,
	// rather than relying on goroutine scheduling or an incidental sleep.
	if err := repository.WithinTransaction(ctx, func(ctx context.Context, tx identityaccess.Transaction) error {
		if err := tx.CheckCurrentAuthorizationProfiles(ctx); err != nil {
			return err
		}
		competing, err := admin.Begin(ctx)
		if err != nil {
			return err
		}
		defer competing.Rollback(ctx)
		if _, err := competing.Exec(ctx, `SET LOCAL lock_timeout='150ms'`); err != nil {
			return err
		}
		_, err = competing.Exec(ctx, `UPDATE iam.authorization_profile_heads SET revision=$2,adopted_at=transaction_timestamp() WHERE product=$1`, future.Product, future.Revision)
		var failure *pgconn.PgError
		if !errors.As(err, &failure) || failure.Code != "55P03" {
			return fmt.Errorf("current profile head was not held through the authority transaction: %v", err)
		}
		return tx.CheckCurrentAuthorizationProfiles(ctx)
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `UPDATE iam.authorization_profile_heads SET revision=$2,adopted_at=transaction_timestamp() WHERE product=$1`, future.Product, future.Revision); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(checkCurrent(), identityaccess.ErrUnavailable) {
		t.Fatal("new current declaration was accepted by an old source")
	}
	for _, path := range []string{"/ready", "/v1/auth/me", "/v1/users"} {
		if response := performIAMRequest(handler, http.MethodGet, path, bearer, nil); response.Code != http.StatusServiceUnavailable {
			t.Fatalf("source mismatch %s: status=%d", path, response.Code)
		}
	}
	request, _ := json.Marshal(profileBoundIAMRequest(t, iamv1.AuthorizationRequest{Action: iamv1.ActionPaaSApplicationRead,
		Resource: iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "registry-drift"}, RequestID: "registry-drift", CorrelationID: "registry-drift"}, iamv1.AuthorizationResourceInstance, ""))
	if response := performIAMRequestWithSubject(handler, request, paasCredential, bearer); response.Code != http.StatusServiceUnavailable {
		t.Fatalf("current decision continued with a different registered meaning: status=%d", response.Code)
	}
	var decisions int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM iam.authorization_decisions WHERE request_id='registry-drift'`).Scan(&decisions); err != nil || decisions != 0 {
		t.Fatal("source mismatch partially committed a current decision")
	}
	lookup(reference, true)
	lookup(future, true)
	wrong = reference
	wrong.ContentDigest = futureDigest
	lookup(wrong, false)
	resolveHistory()
	resolveBusinessHistory()
	var currentBytes []byte
	if err := admin.QueryRow(ctx, `SELECT event_document FROM iam.audit_outbox WHERE event_id=$1`, historicalEvent.EventID).Scan(&currentBytes); err != nil || !bytes.Equal(currentBytes, historicalBytes) {
		t.Fatal("profile advance rewrote old outbox bytes")
	}
	// Credential revocation is not a new permission decision and must remain
	// available even while the product release combination is unavailable.
	if response := performIAMRequest(handler, http.MethodPost, "/v1/auth/logout", bearer, []byte(`{"requestId":"registry-logout"}`)); response.Code != http.StatusOK {
		t.Fatalf("profile mismatch prevented self logout: status=%d", response.Code)
	}
	retained := snapshot()
	if err := iammigration.Up(ctx, admin); err == nil {
		t.Fatal("old migration silently downgraded a registered current head")
	}
	if _, err := admin.Exec(ctx, "ROLLBACK"); err != nil || !bytes.Equal(retained, snapshot()) {
		t.Fatal("rejected downgrade partially changed registry or archive")
	}
	if err := iammigration.Verify(ctx, admin); err == nil {
		t.Fatal("migration verify accepted a different current profile")
	}
	if _, err := admin.Exec(ctx, "ROLLBACK"); err != nil {
		t.Fatal(err)
	}
}

func proveUserPermissionBoundaries(t *testing.T, ctx context.Context, handler http.Handler, database *pgx.Conn, root string) {
	t.Helper()
	call := func(method, path, bearer string, body any, want int, destination any) {
		t.Helper()
		var encoded []byte
		if body != nil {
			encoded = mustIAMJSON(t, body)
		}
		response := performIAMRequest(handler, method, path, bearer, encoded)
		if response.Code != want {
			t.Fatalf("boundary %s %s status=%d want=%d body=%s", method, path, response.Code, want, response.Body.String())
		}
		if destination != nil && json.Unmarshal(response.Body.Bytes(), destination) != nil {
			t.Fatal("invalid boundary HTTP response")
		}
	}
	var member iamv1.User
	call(http.MethodPost, "/v1/users", root, map[string]any{"loginName": "boundary-member", "displayName": "Boundary member", "initialPassword": initialDeveloperPassword, "requestId": "boundary-member-create"}, http.StatusCreated, &member)
	bearer := localRecoveryLogin(t, handler, member.LoginName+"@"+string(member.AccountID), initialDeveloperPassword, true)
	bearer = localRecoveryChangePassword(t, handler, bearer, initialDeveloperPassword, changedDeveloperPassword)
	path := "/v1/users/" + string(member.ID) + "/permission-boundary"
	checkCapabilities := func(credential string, available bool) {
		t.Helper()
		var access iamv1.UserAccess
		call(http.MethodGet, "/v1/users/"+string(member.ID), credential, nil, http.StatusOK, &access)
		if iamv1.ValidateUserAccess(access) != nil {
			t.Fatal("invalid boundary management capabilities")
		}
		for _, action := range []iamv1.Action{iamv1.ActionIAMUserPermissionBoundarySet, iamv1.ActionIAMUserPermissionBoundaryRemove} {
			value, found := findIAMCapability(access.Capabilities, action, iamv1.ResourceUser, string(member.ID))
			if !found || value.Available != available || (!available && value.RestrictionReason != iamv1.CapabilityAuthorityRequired) {
				t.Fatalf("boundary capability %s disagrees with original-root management restriction", action)
			}
		}
	}
	checkCapabilities(root, true)
	var view iamv1.UserPermissionBoundary
	call(http.MethodGet, path, root, nil, http.StatusOK, &view)
	if iamv1.ValidateUserPermissionBoundary(view) != nil || view.Policy != nil {
		t.Fatal("initial user has an implicit boundary")
	}
	var policy iamv1.PolicyDetail
	creation := iamv1.CreatePolicyRequest{DisplayName: "Boundary selected application", RequestID: "boundary-policy-create", Document: iamv1.PolicyDocument{LanguageVersion: iamv1.PolicyLanguageVersion, Scope: iamv1.AuthorityScopeTenant,
		Statements: []iamv1.PolicyStatement{{SID: "selected", Effect: iamv1.PolicyAllow, Actions: []iamv1.Action{iamv1.ActionPaaSApplicationRead}, Resources: []iamv1.PolicyResourceSelector{{Kind: iamv1.ResourceApplication, Match: iamv1.PolicyResourceExact, ID: "application-boundary-allowed"}}}}}}
	call(http.MethodPost, "/v1/policies", root, creation, http.StatusCreated, &policy)
	set := iamv1.SetUserPermissionBoundaryRequest{PolicyID: policy.Policy.ID, PolicyResourceVersion: policy.Policy.ResourceVersion, ResourceVersion: view.ResourceVersion, RequestID: "boundary-set"}
	call(http.MethodPut, path, root, set, http.StatusOK, &view)
	var replay iamv1.UserPermissionBoundary
	call(http.MethodPut, path, root, set, http.StatusOK, &replay)
	if !bytes.Equal(mustIAMJSON(t, view), mustIAMJSON(t, replay)) {
		t.Fatal("boundary replay changed its result")
	}
	authorize := func(id string, want bool) iamv1.AuthorizationDecision {
		t.Helper()
		request := profileBoundIAMRequest(t, iamv1.AuthorizationRequest{Action: iamv1.ActionPaaSApplicationRead, Resource: iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: id}, RequestID: "boundary-read", CorrelationID: "boundary-read"}, iamv1.AuthorizationResourceInstance, "")
		response := performIAMRequestWithSubject(handler, mustIAMJSON(t, request), paasCredential, bearer)
		var result iamv1.AuthorizationDecision
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &result) != nil || result.Allowed != want {
			t.Fatalf("boundary authorization status=%d allowed=%v want=%v", response.Code, result.Allowed, want)
		}
		var encoded []byte
		var evidence authority.UserBoundaryEvidence
		if err := database.QueryRow(ctx, `SELECT boundary_evidence FROM iam.authorization_decisions WHERE tenant_id=$1 AND id=$2`, member.AccountID, result.ID).Scan(&encoded); err != nil || json.Unmarshal(encoded, &evidence) != nil || evidence.State != "BOUND" || evidence.Version == nil || evidence.Version.PolicyID != policy.Policy.ID || evidence.Version.VersionID != policy.Policy.DefaultVersionID {
			t.Fatal("actual boundary decision lost independent version proof")
		}
		return result
	}
	authorize("application-boundary-allowed", false)
	// With no positive attachment to this Policy, only the boundary reference
	// can prevent deletion. Do not let a later attachment mask this invariant.
	call(http.MethodDelete, "/v1/policies/"+string(policy.Policy.ID), root, iamv1.DeletePolicyRequest{ResourceVersion: policy.Policy.ResourceVersion, RequestID: "boundary-only-policy-delete"}, http.StatusConflict, nil)
	call(http.MethodPost, "/v1/policy-attachments", root, iamv1.CreatePolicyAttachmentRequest{Target: iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetUser, ID: string(member.ID)}, PolicyID: iamv1.SystemPolicyPaaSDeveloper, PolicyResourceVersion: 1, RequestID: "boundary-developer-grant"}, http.StatusOK, nil)
	authorize("application-boundary-allowed", true)
	authorize("application-boundary-other", false)
	var identity iamv1.CurrentIdentity
	call(http.MethodGet, "/v1/auth/me", bearer, nil, http.StatusOK, &identity)
	if iamv1.ValidateCurrentIdentity(identity) != nil || identity.PermissionBoundary.Policy == nil || identity.PermissionBoundary.Policy.PolicyID != policy.Policy.ID || len(identity.PolicySources) != 1 {
		t.Fatal("current identity mixed boundary with positive grants")
	}
	var inheritedGroups []iamv1.Group
	var inheritedMemberships []iamv1.GroupMembership
	for index := range 2 {
		var group iamv1.Group
		var membership iamv1.GroupMembership
		call(http.MethodPost, "/v1/groups", root, iamv1.CreateGroupRequest{Name: fmt.Sprintf("Boundary source %d", index), RequestID: fmt.Sprintf("boundary-group-%d", index)}, http.StatusCreated, &group)
		call(http.MethodPost, "/v1/groups/"+string(group.ID)+"/memberships", root, iamv1.CreateGroupMembershipRequest{UserID: member.ID, RequestID: fmt.Sprintf("boundary-join-%d", index)}, http.StatusOK, &membership)
		call(http.MethodPost, "/v1/policy-attachments", root, iamv1.CreatePolicyAttachmentRequest{Target: iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetGroup, ID: string(group.ID)}, PolicyID: iamv1.SystemPolicyPaaSViewer, PolicyResourceVersion: 1, RequestID: fmt.Sprintf("boundary-group-grant-%d", index)}, http.StatusOK, nil)
		inheritedGroups = append(inheritedGroups, group)
		inheritedMemberships = append(inheritedMemberships, membership)
	}
	mixedDecision := authorize("application-boundary-allowed", true)
	authorize("application-boundary-other", false)
	var mixedEvidence []authority.PolicyAttachmentEvidence
	var mixedRaw []byte
	if err := database.QueryRow(ctx, `SELECT policy_evidence FROM iam.authorization_decisions WHERE tenant_id=$1 AND id=$2`, member.AccountID, mixedDecision.ID).Scan(&mixedRaw); err != nil || json.Unmarshal(mixedRaw, &mixedEvidence) != nil {
		t.Fatal("read mixed boundary sources")
	}
	for _, membership := range inheritedMemberships {
		if !slices.ContainsFunc(mixedEvidence, func(e authority.PolicyAttachmentEvidence) bool {
			return e.MembershipID == membership.ID && e.MembershipResourceVersion == membership.ResourceVersion
		}) {
			t.Fatal("boundary intersection lost a current group inheritance source")
		}
	}
	// Ordinary group Deny defeats both an Allow boundary and every Allow source.
	ordinaryDeny := creation.Document
	ordinaryDeny.Statements = append([]iamv1.PolicyStatement(nil), creation.Document.Statements...)
	ordinaryDeny.Statements[0].Effect = iamv1.PolicyDeny
	var deniedPolicy iamv1.PolicyDetail
	call(http.MethodPost, "/v1/policies", root, iamv1.CreatePolicyRequest{DisplayName: "Boundary ordinary group deny", Document: ordinaryDeny, RequestID: "boundary-ordinary-deny-policy"}, http.StatusCreated, &deniedPolicy)
	var denyAttachment iamv1.PolicyAttachment
	call(http.MethodPost, "/v1/policy-attachments", root, iamv1.CreatePolicyAttachmentRequest{Target: iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetGroup, ID: string(inheritedGroups[0].ID)}, PolicyID: deniedPolicy.Policy.ID, PolicyResourceVersion: 1, RequestID: "boundary-ordinary-deny-grant"}, http.StatusOK, &denyAttachment)
	authorize("application-boundary-allowed", false)
	call(http.MethodPost, "/v1/policy-attachments/"+string(denyAttachment.ID)+":revoke", root, iamv1.RevokePolicyAttachmentRequest{ResourceVersion: denyAttachment.ResourceVersion, RequestID: "boundary-ordinary-deny-revoke"}, http.StatusOK, nil)
	authorize("application-boundary-allowed", true)
	// Referencing one Policy on both sides does not collapse its two purposes.
	call(http.MethodPost, "/v1/policy-attachments", root, iamv1.CreatePolicyAttachmentRequest{Target: iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetUser, ID: string(member.ID)}, PolicyID: policy.Policy.ID, PolicyResourceVersion: policy.Policy.ResourceVersion, RequestID: "boundary-same-policy-grant"}, http.StatusOK, nil)
	decision := authorize("application-boundary-allowed", true)
	var attachmentEvidence []authority.PolicyAttachmentEvidence
	var encodedEvidence []byte
	if err := database.QueryRow(ctx, `SELECT policy_evidence FROM iam.authorization_decisions WHERE tenant_id=$1 AND id=$2`, member.AccountID, decision.ID).Scan(&encodedEvidence); err != nil || json.Unmarshal(encodedEvidence, &attachmentEvidence) != nil {
		t.Fatal("read boundary positive provenance")
	}
	if !slices.ContainsFunc(attachmentEvidence, func(e authority.PolicyAttachmentEvidence) bool { return e.Version.PolicyID == policy.Policy.ID }) {
		t.Fatal("same Policy lost its independent positive attachment")
	}
	originalVersion := policy.Version.ID
	deny := creation.Document
	deny.Statements = append([]iamv1.PolicyStatement(nil), deny.Statements...)
	deny.Statements[0].Effect = iamv1.PolicyDeny
	var published iamv1.PolicyVersionDetail
	policyPath := "/v1/policies/" + string(policy.Policy.ID)
	call(http.MethodPost, policyPath+"/versions", root, iamv1.CreatePolicyVersionRequest{Document: deny, ResourceVersion: policy.Policy.ResourceVersion, RequestID: "boundary-publish-deny"}, http.StatusCreated, &published)
	policy.Policy = published.Policy
	authorize("application-boundary-allowed", true)
	call(http.MethodPost, policyPath+":set-default-version", root, iamv1.SetDefaultPolicyVersionRequest{VersionID: published.Version.ID, ResourceVersion: policy.Policy.ResourceVersion, RequestID: "boundary-select-deny"}, http.StatusOK, &policy)
	authorize("application-boundary-allowed", false)
	call(http.MethodPost, policyPath+":set-default-version", root, iamv1.SetDefaultPolicyVersionRequest{VersionID: originalVersion, ResourceVersion: policy.Policy.ResourceVersion, RequestID: "boundary-select-original"}, http.StatusOK, &policy)
	authorize("application-boundary-allowed", true)
	call(http.MethodPut, path, root, set, http.StatusConflict, nil)
	call(http.MethodDelete, "/v1/policies/"+string(policy.Policy.ID), root, iamv1.DeletePolicyRequest{ResourceVersion: policy.Policy.ResourceVersion, RequestID: "boundary-policy-delete"}, http.StatusConflict, nil)
	call(http.MethodGet, path, root, nil, http.StatusOK, &view)
	variant := set
	variant.ResourceVersion = view.ResourceVersion
	variant.PolicyID = iamv1.SystemPolicyPlatformOperator
	variant.RequestID = "boundary-platform-attack"
	call(http.MethodPut, path, root, variant, http.StatusForbidden, nil)
	var rootIdentity iamv1.CurrentIdentity
	call(http.MethodGet, "/v1/auth/me", root, nil, http.StatusOK, &rootIdentity)
	variant.PolicyID = policy.Policy.ID
	variant.ResourceVersion = rootIdentity.User.ResourceVersion
	variant.RequestID = "boundary-root-attack"
	call(http.MethodPut, "/v1/users/"+string(rootIdentity.User.ID)+"/permission-boundary", root, variant, http.StatusForbidden, nil)
	// Even an explicitly authorized administrator bounded by AccountAdministrator
	// cannot use the management action to remove its own maximum permission.
	call(http.MethodPost, "/v1/policy-attachments", root, iamv1.CreatePolicyAttachmentRequest{Target: iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetUser, ID: string(member.ID)}, PolicyID: iamv1.SystemPolicyAccountAdministrator, PolicyResourceVersion: 1, RequestID: "boundary-admin-grant"}, http.StatusOK, nil)
	call(http.MethodGet, path, root, nil, http.StatusOK, &view)
	variant = iamv1.SetUserPermissionBoundaryRequest{PolicyID: iamv1.SystemPolicyAccountAdministrator, PolicyResourceVersion: 1, ResourceVersion: view.ResourceVersion, RequestID: "boundary-system-set"}
	call(http.MethodPut, path, root, variant, http.StatusOK, &view)
	checkCapabilities(bearer, false)
	call(http.MethodDelete, path, bearer, iamv1.RemoveUserPermissionBoundaryRequest{ResourceVersion: view.ResourceVersion, RequestID: "boundary-self-remove"}, http.StatusForbidden, nil)
	call(http.MethodPost, "/v1/users/"+string(member.ID)+":set-status", root, iamv1.SetUserStatusRequest{Status: iamv1.PrincipalDisabled, ResourceVersion: view.ResourceVersion, RequestID: "boundary-disable"}, http.StatusOK, &member)
	checkCapabilities(root, true)
	remove := iamv1.RemoveUserPermissionBoundaryRequest{ResourceVersion: member.ResourceVersion, RequestID: "boundary-remove"}
	call(http.MethodDelete, path, root, remove, http.StatusOK, &view)
	call(http.MethodDelete, path, root, remove, http.StatusOK, &replay)
	if view.Policy != nil || !bytes.Equal(mustIAMJSON(t, view), mustIAMJSON(t, replay)) {
		t.Fatal("boundary removal replay differs")
	}
	call(http.MethodPut, path, root, set, http.StatusConflict, nil)
	call(http.MethodGet, "/v1/auth/me", bearer, nil, http.StatusUnauthorized, nil)
	var state string
	var facts int
	if err := database.QueryRow(ctx, `SELECT status,(SELECT count(*) FROM iam.audit_outbox WHERE tenant_id=$1 AND event_document#>>'{target,id}'=$2 AND event_document->>'action' IN ('iam.user.permission-boundary.set','iam.user.permission-boundary.removed')) FROM iam.principals WHERE tenant_id=$1 AND id=$2`, member.AccountID, member.ID).Scan(&state, &facts); err != nil || state != "DISABLED" || facts != 3 {
		t.Fatal("boundary workflow enabled user or duplicated success facts")
	}
	// A late outbox failure must roll back the relationship, User revision,
	// authorization evidence and success fact together, even for a disabled User.
	before := view
	if _, err := database.Exec(ctx, `CREATE FUNCTION public.matrix_boundary_outbox_fault() RETURNS trigger LANGUAGE plpgsql AS $body$
		BEGIN IF NEW.event_document->>'action'='iam.user.permission-boundary.set' AND NEW.event_document->>'requestId'='boundary-injected-failure'
		THEN RAISE EXCEPTION 'injected boundary outbox failure'; END IF; RETURN NEW; END $body$;
		CREATE TRIGGER matrix_boundary_outbox_fault BEFORE INSERT ON iam.audit_outbox FOR EACH ROW EXECUTE FUNCTION public.matrix_boundary_outbox_fault()`); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := database.Exec(context.Background(), `DROP TRIGGER IF EXISTS matrix_boundary_outbox_fault ON iam.audit_outbox; DROP FUNCTION IF EXISTS public.matrix_boundary_outbox_fault()`); err != nil {
			t.Error("remove isolated boundary fault")
		}
	}()
	variant = iamv1.SetUserPermissionBoundaryRequest{PolicyID: policy.Policy.ID, PolicyResourceVersion: policy.Policy.ResourceVersion, ResourceVersion: view.ResourceVersion, RequestID: "boundary-injected-failure"}
	call(http.MethodPut, path, root, variant, http.StatusServiceUnavailable, nil)
	call(http.MethodGet, path, root, nil, http.StatusOK, &view)
	if !bytes.Equal(mustIAMJSON(t, before), mustIAMJSON(t, view)) {
		t.Fatal("failed boundary mutation changed the User or boundary")
	}
	if err := database.QueryRow(ctx, `SELECT (SELECT count(*) FROM iam.audit_outbox WHERE tenant_id=$1 AND event_document->>'requestId'='boundary-injected-failure')+
		(SELECT count(*) FROM iam.authorization_decisions WHERE tenant_id=$1 AND document->>'requestId'='boundary-injected-failure')+
		(SELECT count(*) FROM iam.user_permission_boundaries WHERE tenant_id=$1 AND user_id=$2 AND revoked_at IS NULL)`, member.AccountID, member.ID).Scan(&facts); err != nil || facts != 0 {
		t.Fatal("failed boundary mutation left a relationship or authority facts")
	}
	if _, err := database.Exec(ctx, `DROP TRIGGER matrix_boundary_outbox_fault ON iam.audit_outbox; DROP FUNCTION public.matrix_boundary_outbox_fault()`); err != nil {
		t.Fatal(err)
	}
	// Two valid set intents at the same User revision cannot overwrite each other.
	completed := make(chan *httptest.ResponseRecorder, 2)
	for index, policyID := range []iamv1.PolicyID{policy.Policy.ID, iamv1.SystemPolicyAccountAdministrator} {
		policyRevision := uint64(1)
		if policyID == policy.Policy.ID {
			policyRevision = policy.Policy.ResourceVersion
		}
		body := mustIAMJSON(t, iamv1.SetUserPermissionBoundaryRequest{PolicyID: policyID, PolicyResourceVersion: policyRevision, ResourceVersion: view.ResourceVersion, RequestID: fmt.Sprintf("boundary-set-race-%d", index)})
		go func() { completed <- performIAMRequest(handler, http.MethodPut, path, root, body) }()
	}
	winners, conflicts := 0, 0
	for range 2 {
		select {
		case response := <-completed:
			switch response.Code {
			case http.StatusOK:
				winners++
				if json.Unmarshal(response.Body.Bytes(), &view) != nil {
					t.Fatal("decode boundary race result")
				}
			case http.StatusConflict:
				conflicts++
			default:
				t.Fatalf("boundary race status=%d", response.Code)
			}
		case <-ctx.Done():
			t.Fatal("boundary race deadline")
		}
	}
	if winners != 1 || conflicts != 1 || view.ResourceVersion != before.ResourceVersion+1 || view.Policy == nil {
		t.Fatal("boundary race lost optimistic concurrency")
	}
	// Historical IAM-source proof remains valid after replacement, removal and
	// identity disable; it does not use the user's current effective permissions.
	var event auditv1.Event
	var raw []byte
	if err := database.QueryRow(ctx, `SELECT event_document FROM iam.audit_outbox WHERE tenant_id=$1 AND event_document->>'requestId'='boundary-set' AND event_document->>'action'='iam.user.permission-boundary.set'`, member.AccountID).Scan(&raw); err != nil || json.Unmarshal(raw, &event) != nil {
		t.Fatal("read original boundary fact")
	}
	call(http.MethodPost, "/v1/audit-producer:resolve", iamProducerCredential, iamv1.ResolveAuditProducerRequest{Event: event}, http.StatusOK, nil)
	// Equal names never make a foreign policy or User local to the caller.
	call(http.MethodPost, "/v1/accounts", root, map[string]any{"id": "boundary-other-account", "displayName": "Boundary other", "rootLoginName": "boundary-other-root", "rootDisplayName": "Other root", "initialPassword": initialDeveloperPassword, "requestId": "boundary-other-create"}, http.StatusCreated, nil)
	other := localRecoveryLogin(t, handler, "boundary-other-root", initialDeveloperPassword, true)
	other = localRecoveryChangePassword(t, handler, other, initialDeveloperPassword, changedDeveloperPassword)
	var foreign iamv1.PolicyDetail
	creation.RequestID = "boundary-foreign-policy"
	call(http.MethodPost, "/v1/policies", other, creation, http.StatusCreated, &foreign)
	variant = iamv1.SetUserPermissionBoundaryRequest{PolicyID: foreign.Policy.ID, PolicyResourceVersion: foreign.Policy.ResourceVersion, ResourceVersion: view.ResourceVersion, RequestID: "boundary-foreign-policy-attack"}
	call(http.MethodPut, path, root, variant, http.StatusForbidden, nil)
	call(http.MethodPut, path, other, variant, http.StatusForbidden, nil)
	call(http.MethodGet, path, other, nil, http.StatusForbidden, nil)
	call(http.MethodGet, path, paasCredential, nil, http.StatusUnauthorized, nil)
	call(http.MethodGet, path+"?accountId=boundary-other-account", root, nil, http.StatusBadRequest, nil)
	call(http.MethodPut, path, root, map[string]any{"policyId": policy.Policy.ID, "policyResourceVersion": 1, "resourceVersion": view.ResourceVersion, "requestId": "boundary-selector-attack", "accountId": "boundary-other-account"}, http.StatusBadRequest, nil)
	call(http.MethodGet, path, root, nil, http.StatusOK, &replay)
	if !bytes.Equal(mustIAMJSON(t, view), mustIAMJSON(t, replay)) {
		t.Fatal("rejected boundary attacks changed current state")
	}
	// Pause after authentication/PDP but before mutation locks, using an actual
	// database lock rather than a timing sleep. Logout of this exact bearer must
	// finish first, and the pending write must not persist stale authority.
	blockedBearer := localRecoveryLogin(t, handler, rootIdentity.User.LoginName, changedAdminPassword, false)
	if _, err := database.Exec(ctx, `CREATE FUNCTION public.matrix_boundary_auth_barrier() RETURNS trigger LANGUAGE plpgsql AS $body$
		BEGIN IF NEW.request_id='boundary-after-logout'
		THEN PERFORM pg_advisory_xact_lock(54831,18); END IF; RETURN NEW; END $body$;
		CREATE TRIGGER matrix_boundary_auth_barrier BEFORE INSERT ON iam.authorization_decisions FOR EACH ROW EXECUTE FUNCTION public.matrix_boundary_auth_barrier();
		SELECT pg_advisory_lock(54831,18)`); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := database.Exec(context.Background(), `SELECT pg_advisory_unlock(54831,18);
			DROP TRIGGER IF EXISTS matrix_boundary_auth_barrier ON iam.authorization_decisions; DROP FUNCTION IF EXISTS public.matrix_boundary_auth_barrier()`); err != nil {
			t.Error("remove isolated boundary authentication barrier")
		}
	}()
	blockedContext, cancelBlocked := context.WithTimeout(ctx, 5*time.Second)
	defer cancelBlocked()
	blockedBody := mustIAMJSON(t, iamv1.RemoveUserPermissionBoundaryRequest{ResourceVersion: view.ResourceVersion, RequestID: "boundary-after-logout"})
	go func() {
		request := httptest.NewRequest(http.MethodDelete, path, bytes.NewReader(blockedBody)).WithContext(blockedContext)
		request.Header.Set("Authorization", "Bearer "+blockedBearer)
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		completed <- response
	}()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for waiting := false; !waiting; {
		if err := database.QueryRow(blockedContext, `SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND NOT granted
			AND database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND classid=54831 AND objid=18)`).Scan(&waiting); err != nil {
			t.Fatal("observe boundary authentication barrier")
		}
		if !waiting {
			select {
			case <-ticker.C:
			case <-blockedContext.Done():
				t.Fatal("boundary never reached authentication barrier")
			}
		}
	}
	call(http.MethodPost, "/v1/auth/logout", blockedBearer, map[string]any{"requestId": "boundary-blocked-session-logout"}, http.StatusOK, nil)
	if _, err := database.Exec(ctx, `SELECT pg_advisory_unlock(54831,18)`); err != nil {
		t.Fatal("release boundary barrier")
	}
	select {
	case response := <-completed:
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("boundary pending on revoked bearer status=%d", response.Code)
		}
	case <-blockedContext.Done():
		t.Fatal("boundary pending request did not finish")
	}
	call(http.MethodGet, path, root, nil, http.StatusOK, &replay)
	if !bytes.Equal(mustIAMJSON(t, view), mustIAMJSON(t, replay)) {
		t.Fatal("pending revoked bearer changed boundary")
	}
	if err := database.QueryRow(ctx, `SELECT count(*) FROM iam.audit_outbox WHERE tenant_id=$1 AND event_document->>'requestId'='boundary-after-logout'`, member.AccountID).Scan(&facts); err != nil || facts != 0 {
		t.Fatal("pending revoked bearer persisted stale authority")
	}
	for _, role := range []string{"matrix_iam_api", "matrix_iam_worker", "matrix_iam_credential_recovery", "matrix_iam_owner"} {
		attacks := []string{
			`DELETE FROM iam.user_permission_boundaries WHERE tenant_id=$1 AND user_id=$2`,
			`UPDATE iam.user_permission_boundaries SET revoked_at=NULL WHERE tenant_id=$1 AND user_id=$2 AND revoked_at IS NOT NULL`,
		}
		if role != "matrix_iam_owner" {
			attacks = append(attacks, `SELECT * FROM iam.user_permission_boundaries WHERE tenant_id=$1 AND user_id=$2`)
		}
		for _, attack := range attacks {
			tx, err := database.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			// Role names are the fixed test catalog above, never request input.
			if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+role); err != nil {
				_ = tx.Rollback(ctx)
				t.Fatal("select boundary attack role")
			}
			if _, err := tx.Exec(ctx, `SELECT set_config('matrix.iam_tenant_id',$1,true)`, member.AccountID); err != nil {
				_ = tx.Rollback(ctx)
				t.Fatal("set isolated boundary attack scope")
			}
			_, attackErr := tx.Exec(ctx, attack, member.AccountID, member.ID)
			_ = tx.Rollback(ctx)
			var pgError *pgconn.PgError
			if !errors.As(attackErr, &pgError) || pgError.Code != "42501" {
				t.Fatalf("boundary history attack role=%s was not forbidden", role)
			}
		}
	}
	// Deletion and removal share the User revision. A losing command cannot
	// leave a live bound behind a deleted user, nor erase relationship history.
	var relationshipsBefore int
	if err := database.QueryRow(ctx, `SELECT count(*) FROM iam.user_permission_boundaries WHERE tenant_id=$1 AND user_id=$2`, member.AccountID, member.ID).Scan(&relationshipsBefore); err != nil {
		t.Fatal("read pre-deletion boundary history")
	}
	type deletionRaceResult struct {
		deletion bool
		response *httptest.ResponseRecorder
	}
	race := make(chan deletionRaceResult, 2)
	removeBody := mustIAMJSON(t, iamv1.RemoveUserPermissionBoundaryRequest{ResourceVersion: view.ResourceVersion, RequestID: "boundary-remove-delete-race"})
	deleteBody := mustIAMJSON(t, iamv1.DeleteUserRequest{ResourceVersion: view.ResourceVersion, RequestID: "boundary-delete-remove-race"})
	go func() {
		race <- deletionRaceResult{false, performIAMRequest(handler, http.MethodDelete, path, root, removeBody)}
	}()
	go func() {
		race <- deletionRaceResult{true, performIAMRequest(handler, http.MethodPost, "/v1/users/"+string(member.ID)+":delete", root, deleteBody)}
	}()
	winners, conflicts = 0, 0
	deleted := false
	for range 2 {
		select {
		case result := <-race:
			switch result.response.Code {
			case http.StatusOK:
				winners++
				deleted = result.deletion
			case http.StatusConflict, http.StatusForbidden:
				conflicts++
			default:
				t.Fatalf("boundary remove/delete race status=%d", result.response.Code)
			}
		case <-ctx.Done():
			t.Fatal("boundary remove/delete race deadline")
		}
	}
	if winners != 1 || conflicts != 1 {
		t.Fatal("boundary remove/delete did not have one winner")
	}
	if err := database.QueryRow(ctx, `SELECT count(*) FROM iam.audit_outbox WHERE tenant_id=$1
		AND event_document->>'requestId' IN ('boundary-remove-delete-race','boundary-delete-remove-race')
		AND event_document->>'action' IN ('iam.user.permission-boundary.removed','iam.user.deleted')`, member.AccountID).Scan(&facts); err != nil || facts != 1 {
		t.Fatal("boundary remove/delete race persisted wrong completion facts")
	}
	if !deleted {
		call(http.MethodGet, path, root, nil, http.StatusOK, &view)
		call(http.MethodPost, "/v1/users/"+string(member.ID)+":delete", root, iamv1.DeleteUserRequest{ResourceVersion: view.ResourceVersion, RequestID: "boundary-delete-after-removal"}, http.StatusOK, nil)
	}
	var relationships, activeRelationships, credentials int
	if err := database.QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE revoked_at IS NULL),
		(SELECT count(*) FROM iam.user_credentials WHERE tenant_id=$1 AND principal_id=$2)
		FROM iam.user_permission_boundaries WHERE tenant_id=$1 AND user_id=$2`, member.AccountID, member.ID).Scan(&relationships, &activeRelationships, &credentials); err != nil || relationships != relationshipsBefore || activeRelationships != 0 || credentials != 0 {
		t.Fatal("user deletion erased boundary history or retained live authority")
	}
	for index, group := range inheritedGroups {
		var access iamv1.GroupAccess
		call(http.MethodGet, "/v1/groups/"+string(group.ID), root, nil, http.StatusOK, &access)
		call(http.MethodPost, "/v1/groups/"+string(group.ID)+":delete", root, iamv1.DeleteGroupRequest{ResourceVersion: access.Group.ResourceVersion, RequestID: fmt.Sprintf("boundary-group-delete-%d", index)}, http.StatusOK, nil)
	}
	call(http.MethodPut, path, root, set, http.StatusForbidden, nil)
	call(http.MethodGet, path, root, nil, http.StatusForbidden, nil)
	call(http.MethodPost, "/v1/audit-producer:resolve", iamProducerCredential, iamv1.ResolveAuditProducerRequest{Event: event}, http.StatusOK, nil)
}

func proveUserBoundaryPolicyRaces(t *testing.T, ctx context.Context, handler http.Handler, database *pgx.Conn, root string) {
	t.Helper()
	call := func(method, path string, body any, want int, destination any) {
		t.Helper()
		var encoded []byte
		if body != nil {
			encoded = mustIAMJSON(t, body)
		}
		response := performIAMRequest(handler, method, path, root, encoded)
		if response.Code != want {
			t.Fatalf("boundary policy competition %s status=%d want=%d", path, response.Code, want)
		}
		if destination != nil && json.Unmarshal(response.Body.Bytes(), destination) != nil {
			t.Fatal("decode boundary competition result")
		}
	}
	document := iamv1.PolicyDocument{LanguageVersion: iamv1.PolicyLanguageVersion, Scope: iamv1.AuthorityScopeTenant,
		Statements: []iamv1.PolicyStatement{{SID: "upper-bound", Effect: iamv1.PolicyAllow, Actions: []iamv1.Action{iamv1.ActionPaaSApplicationRead},
			Resources: []iamv1.PolicyResourceSelector{{Kind: iamv1.ResourceApplication, Match: iamv1.PolicyResourceAnyInAuthority}}}}}
	for _, mode := range []string{"replace-remove", "default", "delete"} {
		t.Run(mode, func(t *testing.T) {
			prefix := "boundary-compete-" + mode
			var user iamv1.User
			call(http.MethodPost, "/v1/users", map[string]any{"loginName": prefix, "displayName": prefix, "initialPassword": initialDeveloperPassword, "requestId": prefix + "-user"}, http.StatusCreated, &user)
			path := "/v1/users/" + string(user.ID) + "/permission-boundary"
			var policy iamv1.PolicyDetail
			call(http.MethodPost, "/v1/policies", iamv1.CreatePolicyRequest{DisplayName: prefix, Document: document, RequestID: prefix + "-policy"}, http.StatusCreated, &policy)
			policyPath := "/v1/policies/" + string(policy.Policy.ID)
			var view iamv1.UserPermissionBoundary
			call(http.MethodGet, path, nil, http.StatusOK, &view)
			peerMethod, peerPath := http.MethodDelete, policyPath
			var peerBody any = iamv1.DeletePolicyRequest{ResourceVersion: policy.Policy.ResourceVersion, RequestID: prefix + "-peer"}
			if mode == "replace-remove" {
				call(http.MethodPut, path, iamv1.SetUserPermissionBoundaryRequest{PolicyID: policy.Policy.ID, PolicyResourceVersion: 1, ResourceVersion: view.ResourceVersion, RequestID: prefix + "-initial"}, http.StatusOK, &view)
				call(http.MethodPost, "/v1/policies", iamv1.CreatePolicyRequest{DisplayName: prefix + "-replacement", Document: document, RequestID: prefix + "-replacement"}, http.StatusCreated, &policy)
				peerPath, peerBody = path, iamv1.RemoveUserPermissionBoundaryRequest{ResourceVersion: view.ResourceVersion, RequestID: prefix + "-peer"}
			} else if mode == "default" {
				deny := document
				deny.Statements = append([]iamv1.PolicyStatement(nil), document.Statements...)
				deny.Statements[0].Effect = iamv1.PolicyDeny
				var version iamv1.PolicyVersionDetail
				call(http.MethodPost, policyPath+"/versions", iamv1.CreatePolicyVersionRequest{Document: deny, ResourceVersion: 1, RequestID: prefix + "-version"}, http.StatusCreated, &version)
				policy.Policy = version.Policy
				peerMethod, peerPath = http.MethodPost, policyPath+":set-default-version"
				peerBody = iamv1.SetDefaultPolicyVersionRequest{VersionID: version.Version.ID, ResourceVersion: version.Policy.ResourceVersion, RequestID: prefix + "-peer"}
			}
			set := iamv1.SetUserPermissionBoundaryRequest{PolicyID: policy.Policy.ID, PolicyResourceVersion: policy.Policy.ResourceVersion, ResourceVersion: view.ResourceVersion, RequestID: prefix + "-set"}
			type outcome struct {
				set      bool
				response *httptest.ResponseRecorder
			}
			results := make(chan outcome, 2)
			setBytes, peerBytes := mustIAMJSON(t, set), mustIAMJSON(t, peerBody)
			go func() { results <- outcome{true, performIAMRequest(handler, http.MethodPut, path, root, setBytes)} }()
			go func() { results <- outcome{false, performIAMRequest(handler, peerMethod, peerPath, root, peerBytes)} }()
			setStatus, peerStatus := 0, 0
			for range 2 {
				select {
				case result := <-results:
					if result.set {
						setStatus = result.response.Code
					} else {
						peerStatus = result.response.Code
					}
				case <-ctx.Done():
					t.Fatal("boundary policy competition deadline")
				}
			}
			call(http.MethodGet, path, nil, http.StatusOK, &view)
			if mode == "default" {
				// Set before the default switch may legitimately succeed: a bound
				// follows defaults. A set ordered after it must reject stale input.
				if peerStatus != http.StatusOK || (setStatus != http.StatusOK && setStatus != http.StatusConflict) {
					t.Fatalf("set/default outcomes=%d/%d", setStatus, peerStatus)
				}
				var current iamv1.PolicyDetail
				call(http.MethodGet, policyPath, nil, http.StatusOK, &current)
				if current.Version.Document.Statements[0].Effect != iamv1.PolicyDeny ||
					(setStatus == http.StatusOK && (view.Policy == nil || view.Policy.VersionID != current.Version.ID)) ||
					(setStatus != http.StatusOK && view.Policy != nil) {
					t.Fatal("set/default retained an obsolete bound or partial relationship")
				}
			} else {
				if (setStatus == http.StatusOK) == (peerStatus == http.StatusOK) ||
					(setStatus != http.StatusOK && setStatus != http.StatusConflict && setStatus != http.StatusForbidden) ||
					(peerStatus != http.StatusOK && peerStatus != http.StatusConflict) {
					t.Fatalf("boundary competition outcomes=%d/%d", setStatus, peerStatus)
				}
				if (view.Policy != nil) != (setStatus == http.StatusOK) || (view.Policy != nil && view.Policy.PolicyID != policy.Policy.ID) {
					t.Fatal("boundary competition state differs from winner")
				}
			}
			var invalidReferences, setFacts int
			if err := database.QueryRow(ctx, `SELECT (SELECT count(*) FROM iam.user_permission_boundaries b JOIN iam.policies p ON p.id=b.policy_id
				WHERE b.tenant_id=$1 AND b.user_id=$2 AND b.revoked_at IS NULL AND p.status<>'ACTIVE'),
				(SELECT count(*) FROM iam.audit_outbox WHERE tenant_id=$1 AND event_document->>'action'='iam.user.permission-boundary.set' AND event_document->>'requestId'=$3)`, user.AccountID, user.ID, set.RequestID).Scan(&invalidReferences, &setFacts); err != nil || invalidReferences != 0 || (setFacts == 1) != (setStatus == http.StatusOK) || setFacts > 1 {
				t.Fatal("boundary competition left invalid reference or completion")
			}
			if mode == "replace-remove" {
				// Re-establish a real bound if removal won, then use two temporary
				// sessions to prove forced change is independent of business Allow.
				if view.Policy == nil {
					call(http.MethodPut, path, iamv1.SetUserPermissionBoundaryRequest{PolicyID: policy.Policy.ID, PolicyResourceVersion: 1, ResourceVersion: view.ResourceVersion, RequestID: prefix + "-forced-bound"}, http.StatusOK, &view)
				}
				first := localRecoveryLogin(t, handler, user.LoginName+"@"+string(user.AccountID), initialDeveloperPassword, true)
				other := localRecoveryLogin(t, handler, user.LoginName+"@"+string(user.AccountID), initialDeveloperPassword, true)
				response := performIAMRequest(handler, http.MethodPost, "/v1/auth/password", first, mustIAMJSON(t, map[string]any{"currentPassword": initialDeveloperPassword, "newPassword": changedDeveloperPassword, "revokeOtherSessions": false, "requestId": prefix + "-forced-change"}))
				if response.Code != http.StatusOK {
					t.Fatalf("bounded forced password change status=%d", response.Code)
				}
				var identity iamv1.CurrentIdentity
				response = performIAMRequest(handler, http.MethodGet, "/v1/auth/me", first, nil)
				if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &identity) != nil || iamv1.ValidateCurrentIdentity(identity) != nil || identity.User.MustChangePassword || identity.PermissionBoundary.Policy == nil || identity.PermissionBoundary.Policy.PolicyID != policy.Policy.ID || len(identity.PolicySources) != 0 {
					t.Fatal("forced change lost bound or acquired permissions")
				}
				if response := performIAMRequest(handler, http.MethodGet, "/v1/auth/me", other, nil); response.Code != http.StatusUnauthorized {
					t.Fatal("bounded forced change retained another temporary session")
				}
				if response := performIAMRequest(handler, http.MethodPost, "/v1/auth/logout", first, mustIAMJSON(t, iamv1.LogoutRequest{RequestID: prefix + "-logout"})); response.Code != http.StatusOK {
					t.Fatal("boundary prevented self logout")
				}
			}
		})
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
		body := mustIAMJSON(t, profileBoundIAMRequest(t, iamv1.AuthorizationRequest{Action: iamv1.ActionPaaSApplicationRead,
			Resource: iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: id}, RequestID: "customer-policy-read", CorrelationID: "customer-policy-read"}, iamv1.AuthorizationResourceInstance, ""))
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
		document.Statements[0].Resources[0] = iamv1.PolicyResourceSelector{Kind: action.ResourceKind, Match: iamv1.PolicyResourcePrefixInAuthority, ID: "resource-"}
		checkDocument(string(mustIAMJSON(t, document)), action.ResourcePrefixAllowed)
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

func proveCustomerPolicyVersions(t *testing.T, ctx context.Context, handler http.Handler, database *pgx.Conn, root string) {
	t.Helper()
	request := func(method, path, bearer string, body any, want int, result any) {
		t.Helper()
		var encoded []byte
		if body != nil {
			encoded = mustIAMJSON(t, body)
		}
		response := performIAMRequest(handler, method, path, bearer, encoded)
		if response.Code != want {
			t.Fatalf("policy versions %s %s: status=%d want=%d body=%s", method, path, response.Code, want, response.Body.String())
		}
		if result != nil && json.Unmarshal(response.Body.Bytes(), result) != nil {
			t.Fatal("decode policy version result")
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
	allow := iamv1.PolicyDocument{LanguageVersion: iamv1.PolicyLanguageVersion, Scope: iamv1.AuthorityScopeTenant,
		Statements: []iamv1.PolicyStatement{{SID: "selected", Effect: iamv1.PolicyAllow, Actions: []iamv1.Action{iamv1.ActionPaaSApplicationRead},
			Resources: []iamv1.PolicyResourceSelector{{Kind: iamv1.ResourceApplication, Match: iamv1.PolicyResourceExact, ID: "version-application"}}}}}
	var initial iamv1.PolicyDetail
	post("/v1/policies", root, iamv1.CreatePolicyRequest{DisplayName: "Versioned application read", Document: allow, RequestID: "version-policy-create"}, http.StatusCreated, &initial)
	path := "/v1/policies/" + string(initial.Policy.ID)
	deny := allow
	deny.Statements = append([]iamv1.PolicyStatement(nil), allow.Statements...)
	deny.Statements[0].Effect = iamv1.PolicyDeny
	create := iamv1.CreatePolicyVersionRequest{Document: deny, ResourceVersion: 1, RequestID: "version-deny-create"}
	var version, replay iamv1.PolicyVersionDetail
	post(path+"/versions", root, create, http.StatusCreated, &version)
	post(path+"/versions", root, create, http.StatusCreated, &replay)
	if iamv1.ValidatePolicyVersionDetail(version) != nil || version.Policy.ResourceVersion != 2 || version.Policy.DefaultVersionID != initial.Version.ID ||
		!bytes.Equal(mustIAMJSON(t, version), mustIAMJSON(t, replay)) {
		t.Fatal("version creation changed default or exact replay result")
	}
	get(path+"/versions/"+string(version.Version.ID), root, http.StatusOK, &replay)
	if !bytes.Equal(mustIAMJSON(t, version), mustIAMJSON(t, replay)) {
		t.Fatal("exact nondefault version read differs")
	}
	var inventory iamv1.PolicyVersionList
	get(path+"/versions", root, http.StatusOK, &inventory)
	if iamv1.ValidatePolicyVersionList(inventory) != nil || len(inventory.Items) != 2 || inventory.Policy != version.Policy {
		t.Fatal("invalid version inventory")
	}
	var member iamv1.User
	post("/v1/users", root, map[string]any{"loginName": "version-member", "displayName": "Version member", "initialPassword": initialDeveloperPassword, "requestId": "version-member-create"}, http.StatusCreated, &member)
	bearer := localRecoveryLogin(t, handler, member.LoginName+"@"+string(member.AccountID), initialDeveloperPassword, true)
	bearer = localRecoveryChangePassword(t, handler, bearer, initialDeveloperPassword, changedDeveloperPassword)
	post("/v1/policy-attachments", root, iamv1.CreatePolicyAttachmentRequest{Target: iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetUser, ID: string(member.ID)}, PolicyID: initial.Policy.ID, PolicyResourceVersion: 2, RequestID: "version-member-grant"}, http.StatusOK, nil)
	authorize := func(requestID string, want bool, wantVersion iamv1.PolicyVersionID) iamv1.DecisionID {
		t.Helper()
		body := mustIAMJSON(t, profileBoundIAMRequest(t, iamv1.AuthorizationRequest{Action: iamv1.ActionPaaSApplicationRead, Resource: iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "version-application"}, RequestID: requestID, CorrelationID: requestID}, iamv1.AuthorizationResourceInstance, ""))
		response := performIAMRequestWithSubject(handler, body, paasCredential, bearer)
		var decision iamv1.AuthorizationDecision
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &decision) != nil || decision.Allowed != want {
			t.Fatalf("version decision status=%d allowed=%t want=%t", response.Code, decision.Allowed, want)
		}
		var encoded []byte
		if err := database.QueryRow(ctx, `SELECT policy_evidence FROM iam.authorization_decisions WHERE tenant_id=$1 AND id=$2`, member.AccountID, decision.ID).Scan(&encoded); err != nil {
			t.Fatal(err)
		}
		var evidence []authority.PolicyAttachmentEvidence
		if json.Unmarshal(encoded, &evidence) != nil || len(evidence) != 1 || evidence[0].Version.VersionID != wantVersion {
			t.Fatalf("decision does not bind selected immutable version: %s", encoded)
		}
		return decision.ID
	}
	oldDecision := authorize("version-before-default", true, initial.Version.ID)
	selectDefault := iamv1.SetDefaultPolicyVersionRequest{VersionID: version.Version.ID, ResourceVersion: 2, RequestID: "version-select-deny"}
	var selected, again iamv1.PolicyDetail
	post(path+":set-default-version", root, selectDefault, http.StatusOK, &selected)
	post(path+":set-default-version", root, selectDefault, http.StatusOK, &again)
	if selected.Policy.ResourceVersion != 3 || selected.Version.ID != version.Version.ID || !bytes.Equal(mustIAMJSON(t, selected), mustIAMJSON(t, again)) {
		t.Fatal("default switch/replay changed revision or content")
	}
	authorize("version-after-default", false, version.Version.ID)
	post(path+"/versions", root, create, http.StatusConflict, nil)
	var raw []byte
	var oldEvent auditv1.Event
	if err := database.QueryRow(ctx, `SELECT event_document FROM iam.audit_outbox WHERE tenant_id=$1 AND event_document->>'iamDecisionId'=$2 AND event_document->>'action'='iam.authorization.decided'`, member.AccountID, oldDecision).Scan(&raw); err != nil || json.Unmarshal(raw, &oldEvent) != nil {
		t.Fatal("read old version authority fact")
	}
	post("/v1/audit-producer:resolve", iamProducerCredential, iamv1.ResolveAuditProducerRequest{Event: oldEvent}, http.StatusOK, nil)
	post(path+":set-default-version", root, iamv1.SetDefaultPolicyVersionRequest{VersionID: initial.Version.ID, ResourceVersion: 3, RequestID: "version-select-original"}, http.StatusOK, &selected)
	post(path+":set-default-version", root, selectDefault, http.StatusConflict, nil)
	authorize("version-after-explicit-rollback", true, initial.Version.ID)
	post(path+":set-default-version", root, iamv1.SetDefaultPolicyVersionRequest{VersionID: "missing-version", ResourceVersion: 4, RequestID: "version-select-missing"}, http.StatusForbidden, nil)
	get(path+"/versions/missing-version", root, http.StatusForbidden, nil)
	get(path+":set-default-version/versions", root, http.StatusForbidden, nil)
	get(path+"/versions?accountId=other", root, http.StatusBadRequest, nil)
	get(path+"/versions", paasCredential, http.StatusUnauthorized, nil)
	get(path+"/versions", bearer, http.StatusForbidden, nil)
	post(path+"/versions", bearer, create, http.StatusForbidden, nil)
	post("/v1/policies/"+string(iamv1.SystemPolicyAccountAdministrator)+"/versions", root, create, http.StatusForbidden, nil)
	get("/v1/policies/"+string(iamv1.SystemPolicyAccountAdministrator)+"/versions", root, http.StatusForbidden, nil)
	failureDocument := allow
	failureDocument.Statements = append([]iamv1.PolicyStatement(nil), allow.Statements...)
	failureDocument.Statements[0].SID = "faulted-version"
	if _, err := database.Exec(ctx, `CREATE FUNCTION public.matrix_policy_version_outbox_fault() RETURNS trigger LANGUAGE plpgsql AS $body$
		BEGIN IF NEW.event_document->>'action'='iam.policy-version.created' AND NEW.event_document->>'requestId'='version-injected-failure'
		THEN RAISE EXCEPTION 'injected policy version outbox failure'; END IF; RETURN NEW; END $body$;
		CREATE TRIGGER matrix_policy_version_outbox_fault BEFORE INSERT ON iam.audit_outbox FOR EACH ROW EXECUTE FUNCTION public.matrix_policy_version_outbox_fault()`); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := database.Exec(context.Background(), `DROP TRIGGER IF EXISTS matrix_policy_version_outbox_fault ON iam.audit_outbox; DROP FUNCTION IF EXISTS public.matrix_policy_version_outbox_fault()`); err != nil {
			t.Error("remove isolated version fault")
		}
	}()
	post(path+"/versions", root, iamv1.CreatePolicyVersionRequest{Document: failureDocument, ResourceVersion: 4, RequestID: "version-injected-failure"}, http.StatusServiceUnavailable, nil)
	get(path+"/versions", root, http.StatusOK, &inventory)
	var faultFacts int
	if len(inventory.Items) != 2 || inventory.Policy.ResourceVersion != 4 || inventory.Policy.DefaultVersionID != initial.Version.ID {
		t.Fatal("failed version publication left content or metadata mutation")
	}
	if err := database.QueryRow(ctx, `SELECT count(*) FROM iam.audit_outbox WHERE tenant_id=$1 AND event_document->>'requestId'='version-injected-failure'`, member.AccountID).Scan(&faultFacts); err != nil || faultFacts != 0 {
		t.Fatal("failed version publication left authority facts")
	}
	if _, err := database.Exec(ctx, `DROP TRIGGER matrix_policy_version_outbox_fault ON iam.audit_outbox; DROP FUNCTION public.matrix_policy_version_outbox_fault()`); err != nil {
		t.Fatal(err)
	}
	// Competing explicit commands at one expected revision have one winner,
	// not two independent defaults or a partially inserted losing version.
	completed := make(chan *httptest.ResponseRecorder, 2)
	for index := 0; index < 2; index++ {
		document := allow
		document.Statements = append([]iamv1.PolicyStatement(nil), allow.Statements...)
		document.Statements[0].SID = fmt.Sprintf("concurrent-version-%d", index)
		body := mustIAMJSON(t, iamv1.CreatePolicyVersionRequest{Document: document, ResourceVersion: 4, RequestID: fmt.Sprintf("version-race-%d", index)})
		go func() { completed <- performIAMRequest(handler, http.MethodPost, path+"/versions", root, body) }()
	}
	winners, conflicts := 0, 0
	for range 2 {
		select {
		case response := <-completed:
			switch response.Code {
			case http.StatusCreated:
				winners++
				if json.Unmarshal(response.Body.Bytes(), &version) != nil {
					t.Fatal("decode concurrent version")
				}
				selected.Policy = version.Policy
			case http.StatusConflict:
				conflicts++
			default:
				t.Fatalf("version race status=%d", response.Code)
			}
		case <-ctx.Done():
			t.Fatal("version race did not complete")
		}
	}
	get(path+"/versions", root, http.StatusOK, &inventory)
	if winners != 1 || conflicts != 1 || len(inventory.Items) != 3 || inventory.Policy.ResourceVersion != 5 {
		t.Fatal("concurrent version revision did not have one atomic winner")
	}
	// Fill the bounded version inventory with explicit new revisions. Merely
	// adding content must keep the already selected default and live grants.
	for index := 0; index < 2; index++ {
		document := allow
		document.Statements = append([]iamv1.PolicyStatement(nil), allow.Statements...)
		document.Statements[0].SID = fmt.Sprintf("variant-%d", index)
		post(path+"/versions", root, iamv1.CreatePolicyVersionRequest{Document: document, ResourceVersion: selected.Policy.ResourceVersion, RequestID: fmt.Sprintf("version-extra-%d", index)}, http.StatusCreated, &version)
		selected.Policy = version.Policy
	}
	get(path+"/versions", root, http.StatusOK, &inventory)
	if iamv1.ValidatePolicyVersionList(inventory) != nil || len(inventory.Items) != iamv1.MaxPolicyVersions || inventory.Policy.DefaultVersionID != initial.Version.ID {
		t.Fatal("version limit inventory/default differs")
	}
	create.ResourceVersion, create.RequestID = selected.Policy.ResourceVersion, "version-over-budget"
	create.Document.Statements[0].SID = "over-budget"
	post(path+"/versions", root, create, http.StatusConflict, nil)
	authorize("version-after-inventory-growth", true, initial.Version.ID)
	get(path+"/versions", root, http.StatusOK, &inventory)
	if len(inventory.Items) != iamv1.MaxPolicyVersions || inventory.Policy != selected.Policy {
		t.Fatal("rejected over-budget version changed policy state")
	}
	var delegatedAdministrator iamv1.PolicyAttachment
	post("/v1/policy-attachments", root, iamv1.CreatePolicyAttachmentRequest{Target: iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetUser, ID: string(member.ID)}, PolicyID: iamv1.SystemPolicyAccountAdministrator, PolicyResourceVersion: 1, RequestID: "version-member-administrator"}, http.StatusOK, &delegatedAdministrator)
	get(path+"/versions", bearer, http.StatusOK, nil)
	post(path+"/versions", bearer, create, http.StatusForbidden, nil)
	selection := iamv1.SetDefaultPolicyVersionRequest{VersionID: version.Version.ID, ResourceVersion: selected.Policy.ResourceVersion, RequestID: "version-delegate-select"}
	post(path+":set-default-version", bearer, selection, http.StatusForbidden, nil)
	post("/v1/accounts", root, map[string]any{"id": "version-other-account", "displayName": "Other version account", "rootLoginName": "version-other-root", "rootDisplayName": "Other owner", "initialPassword": initialDeveloperPassword, "requestId": "version-other-account-create"}, http.StatusCreated, nil)
	other := localRecoveryLogin(t, handler, "version-other-root", initialDeveloperPassword, true)
	other = localRecoveryChangePassword(t, handler, other, initialDeveloperPassword, changedDeveloperPassword)
	get(path+"/versions", other, http.StatusForbidden, nil)
	get(path+"/versions/"+string(initial.Version.ID), other, http.StatusForbidden, nil)
	post(path+"/versions", other, create, http.StatusForbidden, nil)
	post(path+":set-default-version", other, selection, http.StatusForbidden, nil)
	// The default counts toward the five-version inventory. Retiring an old
	// nondefault publication must free capacity without destroying its proof.
	deleteVersion := func(id iamv1.PolicyVersionID, principal string, command iamv1.DeletePolicyVersionRequest, want int, result any) {
		t.Helper()
		request(http.MethodDelete, path+"/versions/"+string(id), principal, command, want, result)
	}
	retirement := iamv1.DeletePolicyVersionRequest{ResourceVersion: inventory.Policy.ResourceVersion, RequestID: "version-retire-original"}
	deleteVersion(initial.Version.ID, root, retirement, http.StatusConflict, nil)
	deleteVersion(initial.Version.ID, bearer, retirement, http.StatusForbidden, nil)
	deleteVersion(initial.Version.ID, other, retirement, http.StatusForbidden, nil)
	deleteVersion(initial.Version.ID, paasCredential, retirement, http.StatusUnauthorized, nil)
	deleteVersion("missing-version", root, retirement, http.StatusForbidden, nil)
	request(http.MethodDelete, "/v1/policies/"+string(iamv1.SystemPolicyAccountAdministrator)+"/versions/"+string(initial.Version.ID), root, retirement, http.StatusForbidden, nil)
	for _, field := range []string{"accountId", "versionId", "scope", "force", "document"} {
		request(http.MethodDelete, path+"/versions/"+string(initial.Version.ID), root, map[string]any{"resourceVersion": retirement.ResourceVersion, "requestId": retirement.RequestID, field: "injected"}, http.StatusBadRequest, nil)
	}
	request(http.MethodDelete, path+"/versions/"+string(initial.Version.ID)+"?accountId=other", root, retirement, http.StatusBadRequest, nil)
	post(path+":set-default-version", root, iamv1.SetDefaultPolicyVersionRequest{VersionID: version.Version.ID, ResourceVersion: inventory.Policy.ResourceVersion, RequestID: "version-select-before-retire"}, http.StatusOK, &selected)
	retirement.ResourceVersion = selected.Policy.ResourceVersion
	if _, err := database.Exec(ctx, `CREATE FUNCTION public.matrix_version_retirement_fault() RETURNS trigger LANGUAGE plpgsql AS $body$
		BEGIN IF NEW.event_document->>'action'='iam.policy-version.deleted' THEN RAISE EXCEPTION 'injected retirement outbox failure'; END IF; RETURN NEW; END $body$;
		CREATE TRIGGER matrix_version_retirement_fault BEFORE INSERT ON iam.audit_outbox FOR EACH ROW EXECUTE FUNCTION public.matrix_version_retirement_fault()`); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := database.Exec(context.Background(), `DROP TRIGGER IF EXISTS matrix_version_retirement_fault ON iam.audit_outbox; DROP FUNCTION IF EXISTS public.matrix_version_retirement_fault()`); err != nil {
			t.Error("remove retirement fault")
		}
	}()
	deleteVersion(initial.Version.ID, root, retirement, http.StatusServiceUnavailable, nil)
	get(path+"/versions", root, http.StatusOK, &inventory)
	if len(inventory.Items) != iamv1.MaxPolicyVersions || inventory.Policy != selected.Policy {
		t.Fatal("failed retirement changed inventory or default")
	}
	if err := database.QueryRow(ctx, `SELECT (SELECT count(*) FROM iam.audit_outbox WHERE tenant_id=$1 AND event_document->>'requestId'=$2)+(SELECT count(*) FROM iam.authorization_decisions WHERE tenant_id=$1 AND request_id=$2)`, initial.Policy.AccountID, retirement.RequestID).Scan(&faultFacts); err != nil || faultFacts != 0 {
		t.Fatal("failed retirement left decision or fact")
	}
	if _, err := database.Exec(ctx, `DROP TRIGGER matrix_version_retirement_fault ON iam.audit_outbox; DROP FUNCTION public.matrix_version_retirement_fault()`); err != nil {
		t.Fatal(err)
	}
	var retired, retiredReplay iamv1.PolicyDetail
	deleteVersion(initial.Version.ID, root, retirement, http.StatusOK, &retired)
	deleteVersion(initial.Version.ID, root, retirement, http.StatusOK, &retiredReplay)
	if iamv1.ValidatePolicyDetail(retired) != nil || retired.Policy.ResourceVersion != retirement.ResourceVersion+1 ||
		retired.Version.ID != selected.Version.ID || !bytes.Equal(mustIAMJSON(t, retired), mustIAMJSON(t, retiredReplay)) {
		t.Fatal("retirement changed default or replay result")
	}
	get(path+"/versions/"+string(initial.Version.ID), root, http.StatusForbidden, nil)
	post(path+":set-default-version", root, iamv1.SetDefaultPolicyVersionRequest{VersionID: initial.Version.ID, ResourceVersion: retired.Policy.ResourceVersion, RequestID: "version-select-retired"}, http.StatusForbidden, nil)
	variantDeletion := retirement
	variantDeletion.ResourceVersion++
	deleteVersion(initial.Version.ID, root, variantDeletion, http.StatusConflict, nil)
	variantDeletion.RequestID = "version-retire-again"
	deleteVersion(initial.Version.ID, root, variantDeletion, http.StatusConflict, nil)
	get(path+"/versions", root, http.StatusOK, &inventory)
	if len(inventory.Items) != iamv1.MaxPolicyVersions-1 {
		t.Fatal("retirement did not release one slot")
	}
	post(path+"/versions", root, iamv1.CreatePolicyVersionRequest{Document: selected.Version.Document, ResourceVersion: retired.Policy.ResourceVersion, RequestID: "version-active-duplicate"}, http.StatusConflict, nil)
	var republished iamv1.PolicyVersionDetail
	post(path+"/versions", root, iamv1.CreatePolicyVersionRequest{Document: initial.Version.Document, ResourceVersion: retired.Policy.ResourceVersion, RequestID: "version-republish-original"}, http.StatusCreated, &republished)
	if republished.Version.ID == initial.Version.ID || republished.Version.ContentDigest != initial.Version.ContentDigest || republished.Policy.DefaultVersionID != selected.Version.ID {
		t.Fatal("same-content publication revived an identity or changed default")
	}
	deleteVersion(initial.Version.ID, root, retirement, http.StatusConflict, nil)
	post(path+"/versions", root, create, http.StatusConflict, nil)
	get(path+"/versions", root, http.StatusOK, &inventory)
	if len(inventory.Items) != iamv1.MaxPolicyVersions {
		t.Fatal("republished content did not use exactly one slot")
	}
	var removable iamv1.PolicyVersion
	for _, item := range inventory.Items {
		if item.ID != inventory.Policy.DefaultVersionID && item.ID != republished.Version.ID {
			removable = item
			break
		}
	}
	if removable.ID == "" {
		t.Fatal("missing nondefault version")
	}
	deleteVersion(removable.ID, root, iamv1.DeletePolicyVersionRequest{ResourceVersion: inventory.Policy.ResourceVersion, RequestID: "version-release-another-slot"}, http.StatusOK, &retired)
	fresh := initial.Version.Document
	fresh.Statements = append([]iamv1.PolicyStatement(nil), fresh.Statements...)
	fresh.Statements[0].SID = "new-content-after-retirement"
	post(path+"/versions", root, iamv1.CreatePolicyVersionRequest{Document: fresh, ResourceVersion: retired.Policy.ResourceVersion, RequestID: "version-use-released-slot"}, http.StatusCreated, &version)
	get(path+"/versions", root, http.StatusOK, &inventory)
	if len(inventory.Items) != iamv1.MaxPolicyVersions || inventory.Policy.DefaultVersionID != selected.Version.ID {
		t.Fatal("new content failed to reuse management capacity")
	}
	var retainedCanonical, retainedDigest string
	var isRetired bool
	if err := database.QueryRow(ctx, `SELECT canonical_document,content_digest,retired_at IS NOT NULL FROM iam.policy_versions WHERE policy_id=$1 AND id=$2`, initial.Policy.ID, initial.Version.ID).Scan(&retainedCanonical, &retainedDigest, &isRetired); err != nil || !isRetired || retainedDigest != initial.Version.ContentDigest {
		t.Fatal("retired content disappeared")
	}
	wantCanonical, _, err := iamv1.CanonicalizePolicyDocument(initial.Version.Document)
	if err != nil || retainedCanonical != wantCanonical {
		t.Fatal("retirement rewrote canonical history")
	}
	post("/v1/audit-producer:resolve", iamProducerCredential, iamv1.ResolveAuditProducerRequest{Event: oldEvent}, http.StatusOK, nil)
	var retirementEvent auditv1.Event
	if err := database.QueryRow(ctx, `SELECT event_document FROM iam.audit_outbox WHERE tenant_id=$1 AND event_document->>'action'='iam.policy-version.deleted' AND event_document->>'requestId'=$2`, initial.Policy.AccountID, retirement.RequestID).Scan(&raw); err != nil || json.Unmarshal(raw, &retirementEvent) != nil {
		t.Fatal("read retirement fact")
	}
	post("/v1/audit-producer:resolve", iamProducerCredential, iamv1.ResolveAuditProducerRequest{Event: retirementEvent}, http.StatusOK, nil)
	for _, attack := range []string{
		`INSERT INTO iam.policy_versions(policy_id,id,authority_scope,document,canonical_document,content_digest,created_at,retired_at)
		 SELECT policy_id,'forged-retired-version',authority_scope,document,canonical_document,content_digest,transaction_timestamp(),transaction_timestamp()
		 FROM iam.policy_versions WHERE policy_id=$1 AND id=$2`,
		`UPDATE iam.policy_versions SET retired_at=NULL WHERE policy_id=$1 AND id=$2`,
		`UPDATE iam.policy_versions SET canonical_document='{}' WHERE policy_id=$1 AND id=$2`,
		`DELETE FROM iam.policy_versions WHERE policy_id=$1 AND id=$2`,
		`UPDATE iam.policies SET default_version_id=$2,resource_version=resource_version+1,updated_at=transaction_timestamp() WHERE id=$1`,
	} {
		tx, err := database.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		_, err = tx.Exec(ctx, attack, initial.Policy.ID, initial.Version.ID)
		var pgError *pgconn.PgError
		if !errors.As(err, &pgError) || pgError.Code != "42501" {
			t.Fatalf("retired history attack was not rejected: %v", err)
		}
		if err := tx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
	}
	// This policy is deliberately unattached so whole-policy deletion is a
	// real competitor, not a request that always loses to a live reference.
	var racePolicy iamv1.PolicyDetail
	post("/v1/policies", root, iamv1.CreatePolicyRequest{DisplayName: "Version retirement race", Document: allow, RequestID: "version-retirement-race-create"}, http.StatusCreated, &racePolicy)
	racePath := "/v1/policies/" + string(racePolicy.Policy.ID)
	var raceVersion iamv1.PolicyVersionDetail
	post(racePath+"/versions", root, iamv1.CreatePolicyVersionRequest{Document: fresh, ResourceVersion: 1, RequestID: "version-retirement-race-content"}, http.StatusCreated, &raceVersion)
	fresh.Statements[0].SID = "concurrent-publication"
	operations := []struct {
		method, path, requestID string
		body                    any
		action                  auditv1.Action
	}{
		{http.MethodDelete, racePath + "/versions/" + string(raceVersion.Version.ID), "version-retirement-race-retire", iamv1.DeletePolicyVersionRequest{ResourceVersion: 2, RequestID: "version-retirement-race-retire"}, auditv1.ActionIAMPolicyVersionDeleted},
		{http.MethodPost, racePath + ":set-default-version", "version-retirement-race-default", iamv1.SetDefaultPolicyVersionRequest{VersionID: raceVersion.Version.ID, ResourceVersion: 2, RequestID: "version-retirement-race-default"}, auditv1.ActionIAMPolicyDefaultVersionSet},
		{http.MethodPost, racePath + "/versions", "version-retirement-race-publish", iamv1.CreatePolicyVersionRequest{Document: fresh, ResourceVersion: 2, RequestID: "version-retirement-race-publish"}, auditv1.ActionIAMPolicyVersionCreated},
		{http.MethodDelete, racePath, "version-retirement-race-policy", iamv1.DeletePolicyRequest{ResourceVersion: 2, RequestID: "version-retirement-race-policy"}, auditv1.ActionIAMPolicyDeleted},
	}
	type outcome struct {
		index    int
		response *httptest.ResponseRecorder
	}
	outcomes := make(chan outcome, len(operations))
	for index, operation := range operations {
		body := mustIAMJSON(t, operation.body)
		go func() {
			outcomes <- outcome{index, performIAMRequest(handler, operation.method, operation.path, root, body)}
		}()
	}
	winner, losers := -1, 0
	for range operations {
		select {
		case result := <-outcomes:
			switch result.response.Code {
			case http.StatusOK, http.StatusCreated:
				if winner != -1 {
					t.Fatal("multiple version lifecycle winners")
				}
				winner = result.index
			case http.StatusConflict, http.StatusForbidden:
				losers++
			default:
				t.Fatalf("version lifecycle race status=%d", result.response.Code)
			}
		case <-ctx.Done():
			t.Fatal("version lifecycle race timed out")
		}
	}
	if winner < 0 || losers != 3 {
		t.Fatal("version lifecycle race did not have exactly one winner")
	}
	var raceStored iamv1.Policy
	var allVersions, activeVersions int
	var candidateRetired bool
	if err := database.QueryRow(ctx, `SELECT iam.lookup_policy($1,$2),(SELECT count(*) FROM iam.policy_versions WHERE policy_id=$2),
		(SELECT count(*) FROM iam.policy_versions WHERE policy_id=$2 AND retired_at IS NULL),
		(SELECT retired_at IS NOT NULL FROM iam.policy_versions WHERE policy_id=$2 AND id=$3)`, racePolicy.Policy.AccountID, racePolicy.Policy.ID, raceVersion.Version.ID).Scan(&raw, &allVersions, &activeVersions, &candidateRetired); err != nil || json.Unmarshal(raw, &raceStored) != nil {
		t.Fatal("read version lifecycle winner")
	}
	wantStatus, wantDefault, wantTotal, wantActive := iamv1.PolicyActive, racePolicy.Version.ID, 2, 2
	if winner == 0 {
		wantActive = 1
	}
	if winner == 1 {
		wantDefault = raceVersion.Version.ID
	}
	if winner == 2 {
		wantTotal = 3
		wantActive = 3
	}
	if winner == 3 {
		wantStatus = iamv1.PolicyRetired
	}
	if raceStored.ResourceVersion != 3 || raceStored.Status != wantStatus || raceStored.DefaultVersionID != wantDefault ||
		allVersions != wantTotal || activeVersions != wantActive || candidateRetired != (winner == 0) {
		t.Fatal("losing version mutation changed state or capacity")
	}
	var lifecycleCount, matched int
	if err := database.QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE event_document->>'action'=$3 AND event_document->>'requestId'=$4
		AND EXISTS(SELECT 1 FROM iam.authorization_decisions d WHERE d.tenant_id=o.tenant_id AND d.id=o.event_document->>'iamDecisionId' AND d.allowed AND d.request_id=$4))
		FROM iam.audit_outbox o WHERE tenant_id=$1 AND event_document#>>'{target,id}'=$2
		AND event_document->>'requestId' IN ('version-retirement-race-retire','version-retirement-race-default','version-retirement-race-publish','version-retirement-race-policy')
		AND event_document->>'action' IN ('iam.policy-version.deleted','iam.policy.default-version-set','iam.policy-version.created','iam.policy.deleted')`, racePolicy.Policy.AccountID, racePolicy.Policy.ID, operations[winner].action, operations[winner].requestID).Scan(&lifecycleCount, &matched); err != nil || lifecycleCount != 1 || matched != 1 {
		t.Fatal("version lifecycle race has no single winner-bound success fact")
	}
	// Exercise a real database clock after publishing and attaching a bounded
	// grant. Current request fields cannot supply or override that clock.
	post("/v1/policy-attachments/"+string(delegatedAdministrator.ID)+":revoke", root, iamv1.RevokePolicyAttachmentRequest{ResourceVersion: delegatedAdministrator.ResourceVersion, RequestID: "time-remove-broad-administrator"}, http.StatusOK, nil)
	var timedGroup iamv1.Group
	var timedMembership iamv1.GroupMembership
	post("/v1/groups", root, iamv1.CreateGroupRequest{Name: "Time limited readers", RequestID: "time-group-create"}, http.StatusCreated, &timedGroup)
	post("/v1/groups/"+string(timedGroup.ID)+"/memberships", root, iamv1.CreateGroupMembershipRequest{UserID: member.ID, RequestID: "time-group-join"}, http.StatusOK, &timedMembership)
	var clock time.Time
	if err := database.QueryRow(ctx, "SELECT transaction_timestamp()").Scan(&clock); err != nil {
		t.Fatal(err)
	}
	clock = clock.UTC()
	expires := clock.Add(5 * time.Second)
	timedDocument := iamv1.PolicyDocument{LanguageVersion: iamv1.PolicyLanguageVersion, Scope: iamv1.AuthorityScopeTenant,
		Statements: []iamv1.PolicyStatement{{SID: "timed", Effect: iamv1.PolicyAllow, Actions: []iamv1.Action{iamv1.ActionPaaSApplicationRead},
			Resources: []iamv1.PolicyResourceSelector{{Kind: iamv1.ResourceApplication, Match: iamv1.PolicyResourceExact, ID: "time-window-application"}},
			Conditions: []iamv1.PolicyCondition{
				{Key: iamv1.ConditionIAMCurrentTime, Operator: iamv1.PolicyDateGreaterThanEquals, Values: []string{clock.Add(-time.Minute).Format(time.RFC3339Nano)}},
				{Key: iamv1.ConditionIAMCurrentTime, Operator: iamv1.PolicyDateLessThan, Values: []string{expires.Format(time.RFC3339Nano)}},
			}}}}
	var timedPolicy iamv1.PolicyDetail
	post("/v1/policies", root, iamv1.CreatePolicyRequest{DisplayName: "Time limited application read", Document: timedDocument, RequestID: "time-policy-create"}, http.StatusCreated, &timedPolicy)
	post("/v1/policy-attachments", root, iamv1.CreatePolicyAttachmentRequest{Target: iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetGroup, ID: string(timedGroup.ID)}, PolicyID: timedPolicy.Policy.ID, PolicyResourceVersion: 1, RequestID: "time-policy-attach"}, http.StatusOK, nil)
	timeRequest := profileBoundIAMRequest(t, iamv1.AuthorizationRequest{Action: iamv1.ActionPaaSApplicationRead, Resource: iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "time-window-application"}, RequestID: "time-policy-allowed", CorrelationID: "time-policy"}, iamv1.AuthorizationResourceInstance, "")
	timeDecision := func(want bool) iamv1.AuthorizationDecision {
		t.Helper()
		response := performIAMRequestWithSubject(handler, mustIAMJSON(t, timeRequest), paasCredential, bearer)
		var decision iamv1.AuthorizationDecision
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &decision) != nil || iamv1.ValidateAuthorizationDecision(decision) != nil || decision.Allowed != want {
			t.Fatalf("timed authority status=%d allowed=%t", response.Code, decision.Allowed)
		}
		if decision.Allowed && !decision.DecidedAt.Before(expires) {
			t.Fatal("authorization used a caller/local time instead of its recorded clock")
		}
		var evidence []authority.PolicyAttachmentEvidence
		if err := database.QueryRow(ctx, `SELECT policy_evidence FROM iam.authorization_decisions WHERE tenant_id=$1 AND id=$2`, member.AccountID, decision.ID).Scan(&raw); err != nil || json.Unmarshal(raw, &evidence) != nil {
			t.Fatal("read timed grant evidence")
		}
		if (want && (len(evidence) != 1 || evidence[0].Version.VersionID != timedPolicy.Version.ID || evidence[0].MembershipID != timedMembership.ID)) || (!want && len(evidence) != 0) {
			t.Fatal("time condition lost exact inherited authority or retained expired grant")
		}
		return decision
	}
	allowedTimeDecision := timeDecision(true)
	var timeEvent auditv1.Event
	if err := database.QueryRow(ctx, `SELECT event_document FROM iam.audit_outbox WHERE tenant_id=$1 AND event_document->>'iamDecisionId'=$2 AND event_document->>'action'='iam.authorization.decided'`, member.AccountID, allowedTimeDecision.ID).Scan(&raw); err != nil || json.Unmarshal(raw, &timeEvent) != nil {
		t.Fatal("read timed decision fact")
	}
	for _, field := range []string{"currentTime", "conditions", "attributes"} {
		forged := bytes.Replace(mustIAMJSON(t, timeRequest), []byte(`"action":`), []byte(`"`+field+`":"forged","action":`), 1)
		if response := performIAMRequestWithSubject(handler, forged, paasCredential, bearer); response.Code != http.StatusBadRequest {
			t.Fatalf("caller clock accepted: status=%d", response.Code)
		}
	}
	for clock.Before(expires) {
		select {
		case <-ctx.Done():
			t.Fatal("time condition gate deadline")
		case <-time.After(50 * time.Millisecond):
		}
		if err := database.QueryRow(ctx, "SELECT transaction_timestamp()").Scan(&clock); err != nil {
			t.Fatal(err)
		}
	}
	timeRequest.RequestID = "time-policy-expired"
	expiredDecision := timeDecision(false)
	if expiredDecision.DecidedAt.Before(expires) {
		t.Fatal("expiration gate did not observe the database boundary")
	}
	post("/v1/audit-producer:resolve", iamProducerCredential, iamv1.ResolveAuditProducerRequest{Event: timeEvent}, http.StatusOK, nil)
	canonicalTimed, _, err := iamv1.CanonicalizePolicyDocument(timedDocument)
	if err != nil {
		t.Fatal(err)
	}
	for _, malformed := range []string{
		strings.Replace(canonicalTimed, "iam.current-time", "caller.current-time", 1),
		strings.Replace(canonicalTimed, "DATE_LESS_THAN", "DATE_GREATER_THAN_EQUALS", 1),
		strings.Replace(canonicalTimed, expires.Format(time.RFC3339Nano), "2026-02-30T00:00:00Z", 1),
	} {
		_, err := database.Exec(ctx, `SELECT iam.assert_customer_policy_document($1,'sha256:'||encode(sha256(convert_to('matrix.iam.policy.v1','UTF8')||decode('00','hex')||convert_to($1,'UTF8')),'hex'))`, malformed)
		var failure *pgconn.PgError
		if !errors.As(err, &failure) || failure.Code != "22023" {
			t.Fatalf("storage admitted malformed conditions: %v", err)
		}
	}
	proveIdentityStringConditions(t, ctx, handler, database, root, member, bearer)
}

func proveIdentityStringConditions(t *testing.T, ctx context.Context, handler http.Handler, database *pgx.Conn, root string, member iamv1.User, bearer string) {
	t.Helper()
	post := func(path, credential string, body any, want int, result any) {
		t.Helper()
		response := performIAMRequest(handler, http.MethodPost, path, credential, mustIAMJSON(t, body))
		if response.Code != want {
			t.Fatalf("identity condition %s: status=%d want=%d", path, response.Code, want)
		}
		if result != nil && json.Unmarshal(response.Body.Bytes(), result) != nil {
			t.Fatal("decode identity condition response")
		}
	}
	var other iamv1.User
	post("/v1/users", root, map[string]any{"loginName": "string-other", "displayName": "Other group member", "initialPassword": initialDeveloperPassword, "requestId": "string-other-create"}, http.StatusCreated, &other)
	otherBearer := localRecoveryLogin(t, handler, other.LoginName+"@"+string(other.AccountID), initialDeveloperPassword, true)
	otherBearer = localRecoveryChangePassword(t, handler, otherBearer, initialDeveloperPassword, changedDeveloperPassword)
	var group iamv1.Group
	post("/v1/groups", root, iamv1.CreateGroupRequest{Name: "Identity readers", RequestID: "identity-group-create"}, http.StatusCreated, &group)
	var memberships [2]iamv1.GroupMembership
	for index, user := range []iamv1.User{member, other} {
		post("/v1/groups/"+string(group.ID)+"/memberships", root, iamv1.CreateGroupMembershipRequest{UserID: user.ID, RequestID: "identity-join-" + string(user.ID)}, http.StatusOK, &memberships[index])
	}
	document := iamv1.PolicyDocument{LanguageVersion: iamv1.PolicyLanguageVersion, Scope: iamv1.AuthorityScopeTenant,
		Statements: []iamv1.PolicyStatement{{SID: "identity", Effect: iamv1.PolicyAllow, Actions: []iamv1.Action{iamv1.ActionPaaSApplicationRead},
			Resources: []iamv1.PolicyResourceSelector{{Kind: iamv1.ResourceApplication, Match: iamv1.PolicyResourceExact, ID: "identity-application"}},
			Conditions: []iamv1.PolicyCondition{
				{Key: iamv1.ConditionIAMAccountID, Operator: iamv1.PolicyStringEquals, Values: []string{string(member.AccountID)}},
				{Key: iamv1.ConditionIAMPrincipalID, Operator: iamv1.PolicyStringEquals, Values: []string{"unrelated-user", string(member.ID)}},
				{Key: iamv1.ConditionIAMPrincipalID, Operator: iamv1.PolicyStringNotEquals, Values: []string{string(other.ID), "another-excluded-user"}},
			}}}}
	var policy, replay iamv1.PolicyDetail
	creation := iamv1.CreatePolicyRequest{DisplayName: "Identity selected application", Document: document, RequestID: "identity-policy-create"}
	post("/v1/policies", root, creation, http.StatusCreated, &policy)
	// Reordering the candidate set is the same canonical creation intent.
	creation.Document.Statements[0].Conditions[1].Values = []string{string(member.ID), "unrelated-user"}
	post("/v1/policies", root, creation, http.StatusCreated, &replay)
	if iamv1.ValidatePolicyDetail(policy) != nil || !bytes.Equal(mustIAMJSON(t, policy), mustIAMJSON(t, replay)) {
		t.Fatal("reordered identity set changed the publication intent")
	}
	var attachment iamv1.PolicyAttachment
	post("/v1/policy-attachments", root, iamv1.CreatePolicyAttachmentRequest{Target: iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetGroup, ID: string(group.ID)}, PolicyID: policy.Policy.ID, PolicyResourceVersion: 1, RequestID: "identity-policy-attach"}, http.StatusOK, &attachment)
	authorize := func(credential string, user iamv1.User, want bool, version iamv1.PolicyVersionID, membership iamv1.GroupMembershipID) iamv1.AuthorizationDecision {
		t.Helper()
		request := profileBoundIAMRequest(t, iamv1.AuthorizationRequest{Action: iamv1.ActionPaaSApplicationRead, Resource: iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "identity-application"}, RequestID: "identity-read", CorrelationID: "identity-read"}, iamv1.AuthorizationResourceInstance, "")
		response := performIAMRequestWithSubject(handler, mustIAMJSON(t, request), paasCredential, credential)
		var decision iamv1.AuthorizationDecision
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &decision) != nil || decision.Allowed != want ||
			want && (decision.TenantID != user.AccountID || decision.Subject == nil || decision.Subject.ID != user.ID) ||
			!want && (decision.TenantID != "" || decision.Subject != nil) {
			t.Fatalf("identity decision status=%d allowed=%t want=%t or public scope differs", response.Code, decision.Allowed, want)
		}
		var raw []byte
		var evidence []authority.PolicyAttachmentEvidence
		var storedPrincipal iamv1.PrincipalID
		if err := database.QueryRow(ctx, `SELECT principal_id,policy_evidence FROM iam.authorization_decisions WHERE tenant_id=$1 AND id=$2`, user.AccountID, decision.ID).Scan(&storedPrincipal, &raw); err != nil || storedPrincipal != user.ID || json.Unmarshal(raw, &evidence) != nil {
			t.Fatal("read identity condition evidence")
		}
		if want && (len(evidence) != 1 || evidence[0].Version.VersionID != version || evidence[0].MembershipID != membership) || !want && len(evidence) != 0 {
			t.Fatal("identity condition lost its precise inherited version")
		}
		return decision
	}
	original := authorize(bearer, member, true, policy.Version.ID, memberships[0].ID)
	authorize(otherBearer, other, false, "", "")
	serviceAsUser := profileBoundIAMRequest(t, iamv1.AuthorizationRequest{Action: iamv1.ActionPaaSApplicationRead, Resource: iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "identity-application"}, RequestID: "identity-service-as-user", CorrelationID: "identity-service-as-user"}, iamv1.AuthorizationResourceInstance, "")
	if response := performIAMRequestWithSubject(handler, mustIAMJSON(t, serviceAsUser), paasCredential, paasCredential); response.Code != http.StatusUnauthorized {
		t.Fatal("service credential supplied USER identity conditions")
	}
	var event auditv1.Event
	var raw []byte
	if err := database.QueryRow(ctx, `SELECT event_document FROM iam.audit_outbox WHERE tenant_id=$1 AND event_document->>'iamDecisionId'=$2 AND event_document->>'action'='iam.authorization.decided'`, member.AccountID, original.ID).Scan(&raw); err != nil || json.Unmarshal(raw, &event) != nil {
		t.Fatal("read identity authority fact")
	}
	for _, field := range []string{"accountId", "principalId", "attributes", "context"} {
		request := map[string]any{"action": iamv1.ActionPaaSApplicationRead, "resource": map[string]any{"kind": iamv1.ResourceApplication, "id": "identity-application"}, "requestId": "identity-forged", "correlationId": "identity-forged", field: string(member.ID)}
		if response := performIAMRequestWithSubject(handler, mustIAMJSON(t, request), paasCredential, otherBearer); response.Code != http.StatusBadRequest {
			t.Fatal("caller supplied an identity condition source")
		}
	}
	canonical, _, err := iamv1.CanonicalizePolicyDocument(document)
	if err != nil {
		t.Fatal(err)
	}
	for _, malformed := range []string{
		strings.Replace(canonical, "iam.account-id", "caller.account-id", 1),
		strings.Replace(canonical, "STRING_NOT_EQUALS", "STRING_EQUALS", 1),
		strings.Replace(canonical, "STRING_NOT_EQUALS", "DATE_LESS_THAN", 1),
		strings.Replace(canonical, "unrelated-user", string(member.ID), 1),
		strings.Replace(canonical, "unrelated-user", "user-*", 1),
	} {
		_, err := database.Exec(ctx, `SELECT iam.assert_customer_policy_document($1,'sha256:'||encode(sha256(convert_to('matrix.iam.policy.v1','UTF8')||decode('00','hex')||convert_to($1,'UTF8')),'hex'))`, malformed)
		var failure *pgconn.PgError
		if !errors.As(err, &failure) || failure.Code != "22023" {
			t.Fatal("storage admitted malformed identity conditions")
		}
	}
	document.Statements[0].Conditions[1].Values = []string{string(other.ID)}
	document.Statements[0].Conditions[2].Values = []string{string(member.ID)}
	var version iamv1.PolicyVersionDetail
	path := "/v1/policies/" + string(policy.Policy.ID)
	post(path+"/versions", root, iamv1.CreatePolicyVersionRequest{Document: document, ResourceVersion: 1, RequestID: "identity-new-version"}, http.StatusCreated, &version)
	authorize(bearer, member, true, policy.Version.ID, memberships[0].ID)
	authorize(otherBearer, other, false, "", "")
	post(path+":set-default-version", root, iamv1.SetDefaultPolicyVersionRequest{VersionID: version.Version.ID, ResourceVersion: 2, RequestID: "identity-select-version"}, http.StatusOK, nil)
	authorize(bearer, member, false, "", "")
	authorize(otherBearer, other, true, version.Version.ID, memberships[1].ID)
	post("/v1/groups/"+string(group.ID)+"/memberships/"+string(memberships[1].ID)+":remove", root,
		iamv1.RemoveGroupMembershipRequest{ResourceVersion: memberships[1].ResourceVersion, RequestID: "identity-remove-member"}, http.StatusOK, nil)
	authorize(otherBearer, other, false, "", "")
	post("/v1/groups/"+string(group.ID)+"/memberships", root, iamv1.CreateGroupMembershipRequest{UserID: other.ID, RequestID: "identity-rejoin-member"}, http.StatusOK, &memberships[1])
	authorize(otherBearer, other, true, version.Version.ID, memberships[1].ID)
	post("/v1/policy-attachments/"+string(attachment.ID)+":revoke", root, iamv1.RevokePolicyAttachmentRequest{ResourceVersion: attachment.ResourceVersion, RequestID: "identity-revoke"}, http.StatusOK, nil)
	authorize(otherBearer, other, false, "", "")
	post("/v1/audit-producer:resolve", iamProducerCredential, iamv1.ResolveAuditProducerRequest{Event: event}, http.StatusOK, nil)
	// A separate account may use the same user/group/policy names and resource
	// ID. Its current subject, not the producer's home or a supplied selector,
	// provides the identity values.
	var foreignAccount iamv1.Account
	post("/v1/accounts", root, map[string]any{"id": "organization-identity-conditions-b", "displayName": "Identity condition account B",
		"rootLoginName": "identity.conditions.root", "rootDisplayName": "Identity root B", "initialPassword": initialDeveloperPassword, "requestId": "identity-account-b"}, http.StatusCreated, &foreignAccount)
	foreignRoot := localRecoveryLogin(t, handler, foreignAccount.RootIdentity.LoginName, initialDeveloperPassword, true)
	foreignRoot = localRecoveryChangePassword(t, handler, foreignRoot, initialDeveloperPassword, changedDeveloperPassword)
	var foreignMember iamv1.User
	post("/v1/users", foreignRoot, map[string]any{"loginName": member.LoginName, "displayName": "Same named member B", "initialPassword": initialDeveloperPassword, "requestId": "identity-member-b"}, http.StatusCreated, &foreignMember)
	foreignBearer := localRecoveryLogin(t, handler, foreignMember.LoginName+"@"+string(foreignMember.AccountID), initialDeveloperPassword, true)
	foreignBearer = localRecoveryChangePassword(t, handler, foreignBearer, initialDeveloperPassword, changedDeveloperPassword)
	var foreignGroup iamv1.Group
	var foreignMembership iamv1.GroupMembership
	post("/v1/groups", foreignRoot, iamv1.CreateGroupRequest{Name: group.Name, RequestID: "identity-group-b"}, http.StatusCreated, &foreignGroup)
	post("/v1/groups/"+string(foreignGroup.ID)+"/memberships", foreignRoot, iamv1.CreateGroupMembershipRequest{UserID: foreignMember.ID, RequestID: "identity-join-b"}, http.StatusOK, &foreignMembership)
	var foreignPolicy iamv1.PolicyDetail
	post("/v1/policies", foreignRoot, iamv1.CreatePolicyRequest{DisplayName: creation.DisplayName, Document: document, RequestID: "identity-policy-b"}, http.StatusCreated, &foreignPolicy)
	post("/v1/policy-attachments", foreignRoot, iamv1.CreatePolicyAttachmentRequest{Target: iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetGroup, ID: string(foreignGroup.ID)}, PolicyID: foreignPolicy.Policy.ID, PolicyResourceVersion: 1, RequestID: "identity-attach-b"}, http.StatusOK, nil)
	authorize(foreignBearer, foreignMember, false, "", "")
	forgedRequest := httptest.NewRequest(http.MethodPost, "/v1/authorize", bytes.NewReader(mustIAMJSON(t, profileBoundIAMRequest(t, iamv1.AuthorizationRequest{
		Action: iamv1.ActionPaaSApplicationRead, Resource: iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "identity-application"}, RequestID: "identity-header-forged", CorrelationID: "identity-header-forged"}, iamv1.AuthorizationResourceInstance, ""))))
	forgedRequest.Header.Set("Content-Type", "application/json")
	forgedRequest.Header.Set("Authorization", "Bearer "+paasCredential)
	forgedRequest.Header.Set("Matrix-Subject-Credential", foreignBearer)
	forgedRequest.Header.Set("X-Tenant-ID", string(member.AccountID))
	forgedRequest.Header.Set("X-Principal-ID", string(other.ID))
	forgedResponse := httptest.NewRecorder()
	handler.ServeHTTP(forgedResponse, forgedRequest)
	var forgedDecision iamv1.AuthorizationDecision
	if forgedResponse.Code != http.StatusOK || json.Unmarshal(forgedResponse.Body.Bytes(), &forgedDecision) != nil || forgedDecision.Allowed || forgedDecision.TenantID != "" || forgedDecision.Subject != nil {
		t.Fatal("caller header replaced authoritative identity")
	}
	var retainedIdentity bool
	if err := database.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM iam.authorization_decisions WHERE tenant_id=$1 AND principal_id=$2 AND id=$3)`, foreignMember.AccountID, foreignMember.ID, forgedDecision.ID).Scan(&retainedIdentity); err != nil || !retainedIdentity {
		t.Fatal("forged header changed private decision ownership")
	}
	document.Statements[0].Conditions[0].Values = []string{string(foreignMember.AccountID)}
	document.Statements[0].Conditions[1].Values = []string{string(foreignMember.ID)}
	var foreignVersion iamv1.PolicyVersionDetail
	foreignPath := "/v1/policies/" + string(foreignPolicy.Policy.ID)
	post(foreignPath+"/versions", foreignRoot, iamv1.CreatePolicyVersionRequest{Document: document, ResourceVersion: 1, RequestID: "identity-version-b"}, http.StatusCreated, &foreignVersion)
	post(foreignPath+":set-default-version", foreignRoot, iamv1.SetDefaultPolicyVersionRequest{VersionID: foreignVersion.Version.ID, ResourceVersion: 2, RequestID: "identity-default-b"}, http.StatusOK, nil)
	authorize(foreignBearer, foreignMember, true, foreignVersion.Version.ID, foreignMembership.ID)
	authorize(bearer, member, false, "", "")
	if response := performIAMRequest(handler, http.MethodGet, path, foreignRoot, nil); response.Code != http.StatusForbidden {
		t.Fatal("foreign root read another account's conditional policy")
	}
	// Reuse the two actual accounts/groups, but grant a distinct resource
	// prefix. Identical resource IDs still require each account's own attachment.
	prefixDocument := iamv1.PolicyDocument{LanguageVersion: iamv1.PolicyLanguageVersion, Scope: iamv1.AuthorityScopeTenant,
		Statements: []iamv1.PolicyStatement{
			{SID: "prefix-read", Effect: iamv1.PolicyAllow, Actions: []iamv1.Action{iamv1.ActionPaaSApplicationRead}, Resources: []iamv1.PolicyResourceSelector{{Kind: iamv1.ResourceApplication, Match: iamv1.PolicyResourcePrefixInAuthority, ID: "prefix-app-"}}},
			{SID: "prefix-private", Effect: iamv1.PolicyDeny, Actions: []iamv1.Action{iamv1.ActionPaaSApplicationRead}, Resources: []iamv1.PolicyResourceSelector{{Kind: iamv1.ResourceApplication, Match: iamv1.PolicyResourcePrefixInAuthority, ID: "prefix-app-private"}}},
		}}
	prefixDecide := func(credential string, user iamv1.User, resource string, want bool) iamv1.AuthorizationDecision {
		t.Helper()
		request := profileBoundIAMRequest(t, iamv1.AuthorizationRequest{Action: iamv1.ActionPaaSApplicationRead, Resource: iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: resource}, RequestID: "prefix-read-" + resource, CorrelationID: "prefix-read"}, iamv1.AuthorizationResourceInstance, "")
		response := performIAMRequestWithSubject(handler, mustIAMJSON(t, request), paasCredential, credential)
		var decision iamv1.AuthorizationDecision
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &decision) != nil || iamv1.ValidateAuthorizationDecision(decision) != nil || decision.Allowed != want {
			t.Fatalf("prefix decision resource=%s status=%d allowed=%v", resource, response.Code, decision.Allowed)
		}
		var owned bool
		if err := database.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM iam.authorization_decisions WHERE tenant_id=$1 AND principal_id=$2 AND id=$3)`, user.AccountID, user.ID, decision.ID).Scan(&owned); err != nil || !owned {
			t.Fatal("resource prefix changed authoritative ownership")
		}
		return decision
	}
	for index, account := range []struct {
		root, bearer string
		user         iamv1.User
		group        iamv1.Group
		membership   iamv1.GroupMembership
	}{
		{root, bearer, member, group, memberships[0]}, {foreignRoot, foreignBearer, foreignMember, foreignGroup, foreignMembership},
	} {
		prefixDecide(account.bearer, account.user, "prefix-app-api", false)
		var prefixPolicy iamv1.PolicyDetail
		post("/v1/policies", account.root, iamv1.CreatePolicyRequest{DisplayName: "Prefixed applications", Document: prefixDocument, RequestID: "prefix-policy-create"}, http.StatusCreated, &prefixPolicy)
		var prefixAttachment iamv1.PolicyAttachment
		post("/v1/policy-attachments", account.root, iamv1.CreatePolicyAttachmentRequest{Target: iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetGroup, ID: string(account.group.ID)}, PolicyID: prefixPolicy.Policy.ID, PolicyResourceVersion: 1, RequestID: "prefix-policy-attach"}, http.StatusOK, &prefixAttachment)
		allowed := prefixDecide(account.bearer, account.user, "prefix-app-api", true)
		prefixDecide(account.bearer, account.user, "prefix-app-", true)
		for _, id := range []string{"prefix-app", "Prefix-app-api", "other-app-api", "prefix-app-private", "prefix-app-private-api"} {
			prefixDecide(account.bearer, account.user, id, false)
		}
		var evidence []authority.PolicyAttachmentEvidence
		if err := database.QueryRow(ctx, `SELECT policy_evidence FROM iam.authorization_decisions WHERE tenant_id=$1 AND id=$2`, account.user.AccountID, allowed.ID).Scan(&raw); err != nil || json.Unmarshal(raw, &evidence) != nil || len(evidence) != 1 || evidence[0].MembershipID != account.membership.ID || evidence[0].Version.VersionID != prefixPolicy.Version.ID {
			t.Fatal("prefix permission lost actual group/version provenance")
		}
		if index == 0 {
			prefixDecide(foreignBearer, foreignMember, "prefix-app-api", false)
			post("/v1/policy-attachments", foreignRoot, iamv1.CreatePolicyAttachmentRequest{Target: iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetGroup, ID: string(foreignGroup.ID)}, PolicyID: prefixPolicy.Policy.ID, PolicyResourceVersion: 1, RequestID: "prefix-foreign-policy"}, http.StatusForbidden, nil)
		}
		var prefixFact auditv1.Event
		if err := database.QueryRow(ctx, `SELECT event_document FROM iam.audit_outbox WHERE tenant_id=$1 AND event_document->>'iamDecisionId'=$2 AND event_document->>'action'='iam.authorization.decided'`, account.user.AccountID, allowed.ID).Scan(&raw); err != nil || json.Unmarshal(raw, &prefixFact) != nil {
			t.Fatal("read prefix decision fact")
		}
		changed := prefixDocument
		changed.Statements = append([]iamv1.PolicyStatement(nil), prefixDocument.Statements...)
		changed.Statements[0].Resources = []iamv1.PolicyResourceSelector{{Kind: iamv1.ResourceApplication, Match: iamv1.PolicyResourcePrefixInAuthority, ID: "prefix-other-"}}
		var next iamv1.PolicyVersionDetail
		prefixPath := "/v1/policies/" + string(prefixPolicy.Policy.ID)
		post(prefixPath+"/versions", account.root, iamv1.CreatePolicyVersionRequest{Document: changed, ResourceVersion: 1, RequestID: "prefix-version"}, http.StatusCreated, &next)
		prefixDecide(account.bearer, account.user, "prefix-app-api", true)
		post(prefixPath+":set-default-version", account.root, iamv1.SetDefaultPolicyVersionRequest{VersionID: next.Version.ID, ResourceVersion: 2, RequestID: "prefix-default"}, http.StatusOK, nil)
		prefixDecide(account.bearer, account.user, "prefix-app-api", false)
		prefixDecide(account.bearer, account.user, "prefix-other-api", true)
		post("/v1/policy-attachments/"+string(prefixAttachment.ID)+":revoke", account.root, iamv1.RevokePolicyAttachmentRequest{ResourceVersion: prefixAttachment.ResourceVersion, RequestID: "prefix-revoke"}, http.StatusOK, nil)
		prefixDecide(account.bearer, account.user, "prefix-other-api", false)
		post("/v1/audit-producer:resolve", iamProducerCredential, iamv1.ResolveAuditProducerRequest{Event: prefixFact}, http.StatusOK, nil)
	}
	prefixCanonical, _, err := iamv1.CanonicalizePolicyDocument(prefixDocument)
	if err != nil {
		t.Fatal(err)
	}
	for _, malformed := range []string{strings.Replace(prefixCanonical, `"id":"prefix-app-"`, `"id":""`, 1), strings.Replace(prefixCanonical, `"id":"prefix-app-"`, `"id":"prefix-app-*"`, 1), strings.Replace(prefixCanonical, "PREFIX_IN_AUTHORITY", "REGEX", 1)} {
		_, err := database.Exec(ctx, `SELECT iam.assert_customer_policy_document($1,'sha256:'||encode(sha256(convert_to('matrix.iam.policy.v1','UTF8')||decode('00','hex')||convert_to($1,'UTF8')),'hex'))`, malformed)
		var failure *pgconn.PgError
		if !errors.As(err, &failure) || failure.Code != "22023" {
			t.Fatal("storage admitted malformed resource prefix")
		}
	}
}

func proveCustomerPolicyMetadata(t *testing.T, ctx context.Context, handler http.Handler, database *pgx.Conn, root string) {
	t.Helper()
	call := func(method, path, bearer string, body any, want int, result any) {
		t.Helper()
		var encoded []byte
		if body != nil {
			encoded = mustIAMJSON(t, body)
		}
		response := performIAMRequest(handler, method, path, bearer, encoded)
		if response.Code != want {
			t.Fatalf("policy metadata %s %s status=%d want=%d body=%s", method, path, response.Code, want, response.Body.String())
		}
		if result != nil && json.Unmarshal(response.Body.Bytes(), result) != nil {
			t.Fatal("decode policy metadata")
		}
	}
	document := iamv1.PolicyDocument{LanguageVersion: iamv1.PolicyLanguageVersion, Scope: iamv1.AuthorityScopeTenant,
		Statements: []iamv1.PolicyStatement{{SID: "metadata", Effect: iamv1.PolicyAllow, Actions: []iamv1.Action{iamv1.ActionPaaSApplicationRead},
			Resources: []iamv1.PolicyResourceSelector{{Kind: iamv1.ResourceApplication, Match: iamv1.PolicyResourceExact, ID: "metadata-application"}}}}}
	var initial, renamed, replay iamv1.PolicyDetail
	call(http.MethodPost, "/v1/policies", root, iamv1.CreatePolicyRequest{DisplayName: "Original metadata", Document: document, RequestID: "metadata-create"}, http.StatusCreated, &initial)
	path := "/v1/policies/" + string(initial.Policy.ID)
	update := iamv1.UpdatePolicyRequest{DisplayName: "Renamed metadata", ResourceVersion: 1, RequestID: "metadata-rename"}
	call(http.MethodPatch, path, root, update, http.StatusOK, &renamed)
	call(http.MethodPatch, path, root, update, http.StatusOK, &replay)
	if iamv1.ValidatePolicyDetail(renamed) != nil || renamed.Policy.ID != initial.Policy.ID || renamed.Policy.AccountID != initial.Policy.AccountID ||
		renamed.Policy.ResourceVersion != 2 || renamed.Policy.DisplayName != update.DisplayName || renamed.Policy.DefaultVersionID != initial.Policy.DefaultVersionID ||
		!bytes.Equal(mustIAMJSON(t, renamed.Version), mustIAMJSON(t, initial.Version)) || !bytes.Equal(mustIAMJSON(t, renamed), mustIAMJSON(t, replay)) {
		t.Fatal("rename changed content, identity or replay result")
	}
	call(http.MethodGet, path, root, nil, http.StatusOK, &replay)
	if !bytes.Equal(mustIAMJSON(t, renamed), mustIAMJSON(t, replay)) {
		t.Fatal("rename was not visible to current read")
	}
	variant := update
	variant.DisplayName = "Variant metadata"
	call(http.MethodPatch, path, root, variant, http.StatusConflict, nil)
	variant.RequestID = "metadata-stale"
	call(http.MethodPatch, path, root, variant, http.StatusConflict, nil)
	variant.ResourceVersion = 2
	variant.DisplayName = renamed.Policy.DisplayName
	variant.RequestID = "metadata-noop"
	call(http.MethodPatch, path, root, variant, http.StatusConflict, nil)
	call(http.MethodPatch, "/v1/policies/"+string(iamv1.SystemPolicyAccountAdministrator), root, update, http.StatusForbidden, nil)
	call(http.MethodPatch, path+"?accountId=other", root, update, http.StatusBadRequest, nil)
	// A service secret is not a user bearer; authentication itself must fail.
	call(http.MethodPatch, path, iamProducerCredential, update, http.StatusUnauthorized, nil)
	for _, field := range []string{"accountId", "scope", "management", "defaultVersionId", "document", "id"} {
		attack := map[string]any{"displayName": "attack", "resourceVersion": 2, "requestId": "metadata-selector", field: "injected"}
		call(http.MethodPatch, path, root, attack, http.StatusBadRequest, nil)
	}
	// A second active policy may reuse the old display name, but not the new
	// one. Stable identity and immutable content never depend on that name.
	var second iamv1.PolicyDetail
	call(http.MethodPost, "/v1/policies", root, iamv1.CreatePolicyRequest{DisplayName: initial.Policy.DisplayName, Document: document, RequestID: "metadata-second"}, http.StatusCreated, &second)
	variant.DisplayName = second.Policy.DisplayName
	variant.RequestID = "metadata-collision"
	call(http.MethodPatch, path, root, variant, http.StatusConflict, nil)
	if _, err := database.Exec(ctx, `CREATE FUNCTION public.matrix_policy_metadata_fault() RETURNS trigger LANGUAGE plpgsql AS $body$
		BEGIN IF NEW.event_document->>'requestId'='metadata-injected-failure' THEN RAISE EXCEPTION 'injected metadata outbox failure'; END IF; RETURN NEW; END $body$;
		CREATE TRIGGER matrix_policy_metadata_fault BEFORE INSERT ON iam.audit_outbox FOR EACH ROW EXECUTE FUNCTION public.matrix_policy_metadata_fault()`); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := database.Exec(context.Background(), `DROP TRIGGER IF EXISTS matrix_policy_metadata_fault ON iam.audit_outbox; DROP FUNCTION IF EXISTS public.matrix_policy_metadata_fault()`); err != nil {
			t.Error("remove isolated metadata fault")
		}
	}()
	variant.DisplayName = "Rollback metadata"
	variant.RequestID = "metadata-injected-failure"
	call(http.MethodPatch, path, root, variant, http.StatusServiceUnavailable, nil)
	call(http.MethodGet, path, root, nil, http.StatusOK, &replay)
	if !bytes.Equal(mustIAMJSON(t, renamed), mustIAMJSON(t, replay)) {
		t.Fatal("outbox failure left partial metadata")
	}
	var count int
	if err := database.QueryRow(ctx, `SELECT (SELECT count(*) FROM iam.audit_outbox WHERE tenant_id=$1 AND event_document->>'requestId'='metadata-injected-failure')+
		(SELECT count(*) FROM iam.authorization_decisions WHERE tenant_id=$1 AND request_id='metadata-injected-failure')`, initial.Policy.AccountID).Scan(&count); err != nil || count != 0 {
		t.Fatal("failed rename left a fact or decision")
	}
	if _, err := database.Exec(ctx, `DROP TRIGGER matrix_policy_metadata_fault ON iam.audit_outbox; DROP FUNCTION public.matrix_policy_metadata_fault()`); err != nil {
		t.Fatal(err)
	}
	// Two edits to one revision have one winner; the losing name and old
	// command cannot overwrite it after transaction retries.
	completed := make(chan *httptest.ResponseRecorder, 2)
	for index := 0; index < 2; index++ {
		body := mustIAMJSON(t, iamv1.UpdatePolicyRequest{DisplayName: fmt.Sprintf("Metadata winner %d", index), ResourceVersion: 2, RequestID: fmt.Sprintf("metadata-race-%d", index)})
		go func() { completed <- performIAMRequest(handler, http.MethodPatch, path, root, body) }()
	}
	winners, conflicts := 0, 0
	for range 2 {
		select {
		case response := <-completed:
			switch response.Code {
			case http.StatusOK:
				winners++
				if json.Unmarshal(response.Body.Bytes(), &renamed) != nil {
					t.Fatal("decode metadata race")
				}
			case http.StatusConflict:
				conflicts++
			default:
				t.Fatalf("metadata race status=%d", response.Code)
			}
		case <-ctx.Done():
			t.Fatal("metadata race timed out")
		}
	}
	if winners != 1 || conflicts != 1 || renamed.Policy.ResourceVersion != 3 {
		t.Fatal("rename concurrency did not have one winner")
	}
	call(http.MethodPatch, path, root, update, http.StatusConflict, nil)
	var event auditv1.Event
	var raw []byte
	if err := database.QueryRow(ctx, `SELECT event_document FROM iam.audit_outbox WHERE tenant_id=$1 AND event_document->>'action'='iam.policy.updated' AND event_document->>'requestId'='metadata-rename'`, initial.Policy.AccountID).Scan(&raw); err != nil || json.Unmarshal(raw, &event) != nil {
		t.Fatal("read original rename fact")
	}
	call(http.MethodPost, "/v1/audit-producer:resolve", iamProducerCredential, iamv1.ResolveAuditProducerRequest{Event: event}, http.StatusOK, nil)
	if err := database.QueryRow(ctx, `SELECT count(*) FROM iam.audit_outbox WHERE tenant_id=$1 AND event_document->>'action'='iam.policy.updated' AND event_document#>>'{target,id}'=$2`, initial.Policy.AccountID, initial.Policy.ID).Scan(&count); err != nil || count != 2 {
		t.Fatal("rename duplicated or lost success facts")
	}
	var member iamv1.User
	call(http.MethodPost, "/v1/users", root, map[string]any{"loginName": "metadata-member", "displayName": "Metadata member", "initialPassword": initialDeveloperPassword, "requestId": "metadata-member-create"}, http.StatusCreated, &member)
	bearer := localRecoveryLogin(t, handler, member.LoginName+"@"+string(member.AccountID), initialDeveloperPassword, true)
	bearer = localRecoveryChangePassword(t, handler, bearer, initialDeveloperPassword, changedDeveloperPassword)
	call(http.MethodPost, "/v1/policy-attachments", root, iamv1.CreatePolicyAttachmentRequest{Target: iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetUser, ID: string(member.ID)}, PolicyID: iamv1.SystemPolicyAccountAdministrator, PolicyResourceVersion: 1, RequestID: "metadata-member-admin"}, http.StatusOK, nil)
	call(http.MethodGet, path, bearer, nil, http.StatusOK, nil)
	variant.ResourceVersion = 3
	variant.RequestID = "metadata-delegate"
	call(http.MethodPatch, path, bearer, variant, http.StatusForbidden, nil)
	call(http.MethodPost, "/v1/accounts", root, map[string]any{"id": "metadata-other-account", "displayName": "Metadata other", "rootLoginName": "metadata-other-root", "rootDisplayName": "Other root", "initialPassword": initialDeveloperPassword, "requestId": "metadata-other-create"}, http.StatusCreated, nil)
	other := localRecoveryLogin(t, handler, "metadata-other-root", initialDeveloperPassword, true)
	other = localRecoveryChangePassword(t, handler, other, initialDeveloperPassword, changedDeveloperPassword)
	call(http.MethodPatch, path, other, variant, http.StatusForbidden, nil)
	call(http.MethodGet, path, root, nil, http.StatusOK, &replay)
	if !bytes.Equal(mustIAMJSON(t, renamed), mustIAMJSON(t, replay)) {
		t.Fatal("rejected caller changed metadata")
	}
	var foreign iamv1.PolicyDetail
	call(http.MethodPost, "/v1/policies", other, iamv1.CreatePolicyRequest{DisplayName: renamed.Policy.DisplayName, Document: document, RequestID: "metadata-foreign-same-name"}, http.StatusCreated, &foreign)
	if foreign.Policy.AccountID == renamed.Policy.AccountID || foreign.Policy.ID == renamed.Policy.ID {
		t.Fatal("same display name merged account identities")
	}
	// Metadata and default selection share the same optimistic revision. A
	// concurrent edit cannot accidentally select content, or overwrite a
	// selection that has already advanced the policy.
	deny := document
	deny.Statements = append([]iamv1.PolicyStatement(nil), document.Statements...)
	deny.Statements[0].Effect = iamv1.PolicyDeny
	var version iamv1.PolicyVersionDetail
	call(http.MethodPost, path+"/versions", root, iamv1.CreatePolicyVersionRequest{Document: deny, ResourceVersion: 3, RequestID: "metadata-race-version"}, http.StatusCreated, &version)
	renameBody := mustIAMJSON(t, iamv1.UpdatePolicyRequest{DisplayName: "Metadata versus default", ResourceVersion: 4, RequestID: "metadata-default-race-rename"})
	selectBody := mustIAMJSON(t, iamv1.SetDefaultPolicyVersionRequest{VersionID: version.Version.ID, ResourceVersion: 4, RequestID: "metadata-default-race-select"})
	go func() { completed <- performIAMRequest(handler, http.MethodPatch, path, root, renameBody) }()
	go func() {
		completed <- performIAMRequest(handler, http.MethodPost, path+":set-default-version", root, selectBody)
	}()
	winners, conflicts = 0, 0
	for range 2 {
		select {
		case response := <-completed:
			switch response.Code {
			case http.StatusOK:
				winners++
				if json.Unmarshal(response.Body.Bytes(), &replay) != nil {
					t.Fatal("decode metadata/default race")
				}
			case http.StatusConflict:
				conflicts++
			default:
				t.Fatalf("metadata/default race status=%d", response.Code)
			}
		case <-ctx.Done():
			t.Fatal("metadata/default race timed out")
		}
	}
	if winners != 1 || conflicts != 1 || replay.Policy.ResourceVersion != 5 {
		t.Fatal("metadata/default race did not have one winner")
	}
	if replay.Policy.DisplayName == "Metadata versus default" {
		if replay.Version.ID != initial.Version.ID {
			t.Fatal("rename implicitly selected competing content")
		}
	} else if replay.Policy.DisplayName != renamed.Policy.DisplayName || replay.Version.ID != version.Version.ID {
		t.Fatal("default selection overwrote competing metadata")
	}
	var otherIdentity iamv1.CurrentIdentity
	call(http.MethodGet, "/v1/auth/me", other, nil, http.StatusOK, &otherIdentity)
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
	if _, err := tx.Exec(ctx, `UPDATE iam.principals SET status='DISABLED',resource_version=resource_version+1,updated_at=transaction_timestamp() WHERE tenant_id=$1 AND id=$2`, foreign.Policy.AccountID, otherIdentity.User.ID); err != nil {
		t.Fatal(err)
	}
	racingBody := mustIAMJSON(t, iamv1.UpdatePolicyRequest{DisplayName: "Disabled publisher rename", ResourceVersion: 1, RequestID: "metadata-disabled-publisher"})
	go func() {
		completed <- performIAMRequest(handler, http.MethodPatch, "/v1/policies/"+string(foreign.Policy.ID), other, racingBody)
	}()
	waitForLocalRecoveryLock(t, ctx, database, iamHTTPTestRole)
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case response := <-completed:
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("rename survived publisher revocation: %d", response.Code)
		}
	case <-ctx.Done():
		t.Fatal("publisher revocation race timed out")
	}
	var originalName string
	var revision uint64
	if err := database.QueryRow(ctx, `SELECT display_name,resource_version FROM iam.policies WHERE id=$1`, foreign.Policy.ID).Scan(&originalName, &revision); err != nil || originalName != foreign.Policy.DisplayName || revision != 1 {
		t.Fatal("revoked publisher left partial metadata")
	}
	if err := database.QueryRow(ctx, `SELECT count(*) FROM iam.audit_outbox WHERE tenant_id=$1 AND event_document->>'requestId'='metadata-disabled-publisher'`, foreign.Policy.AccountID).Scan(&count); err != nil || count != 0 {
		t.Fatal("revoked publisher left success fact")
	}
}

func proveCustomerPolicyDeletion(t *testing.T, ctx context.Context, handler http.Handler, database *pgx.Conn, root string) {
	t.Helper()
	call := func(method, path, bearer string, body any, want int, result any) {
		t.Helper()
		var encoded []byte
		if body != nil {
			encoded = mustIAMJSON(t, body)
		}
		response := performIAMRequest(handler, method, path, bearer, encoded)
		if response.Code != want {
			t.Fatalf("policy deletion %s %s status=%d want=%d body=%s", method, path, response.Code, want, response.Body.String())
		}
		if result != nil && json.Unmarshal(response.Body.Bytes(), result) != nil {
			t.Fatal("decode policy deletion response")
		}
	}
	document := iamv1.PolicyDocument{LanguageVersion: iamv1.PolicyLanguageVersion, Scope: iamv1.AuthorityScopeTenant, Statements: []iamv1.PolicyStatement{{SID: "deletion", Effect: iamv1.PolicyAllow, Actions: []iamv1.Action{iamv1.ActionPaaSApplicationRead}, Resources: []iamv1.PolicyResourceSelector{{Kind: iamv1.ResourceApplication, Match: iamv1.PolicyResourceExact, ID: "deletion-application"}}}}}
	creation := iamv1.CreatePolicyRequest{DisplayName: "Deletable policy", Document: document, RequestID: "delete-policy-create"}
	var policy iamv1.PolicyDetail
	call(http.MethodPost, "/v1/policies", root, creation, http.StatusCreated, &policy)
	path := "/v1/policies/" + string(policy.Policy.ID)
	deletion := iamv1.DeletePolicyRequest{ResourceVersion: 1, RequestID: "delete-policy"}
	var member iamv1.User
	call(http.MethodPost, "/v1/users", root, map[string]any{"loginName": "deletion.member", "displayName": "Deletion member", "initialPassword": initialDeveloperPassword, "requestId": "deletion-member-create"}, http.StatusCreated, &member)
	bearer := localRecoveryLogin(t, handler, member.LoginName+"@"+string(member.AccountID), initialDeveloperPassword, true)
	bearer = localRecoveryChangePassword(t, handler, bearer, initialDeveloperPassword, changedDeveloperPassword)
	var attachment iamv1.PolicyAttachment
	grant := iamv1.CreatePolicyAttachmentRequest{Target: iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetUser, ID: string(member.ID)}, PolicyID: policy.Policy.ID, PolicyResourceVersion: 1, RequestID: "deletion-user-grant"}
	call(http.MethodPost, "/v1/policy-attachments", root, grant, http.StatusOK, &attachment)
	call(http.MethodDelete, path, root, deletion, http.StatusConflict, nil)
	var access iamv1.UserAccess
	call(http.MethodGet, "/v1/users/"+string(member.ID), root, nil, http.StatusOK, &access)
	call(http.MethodPost, "/v1/users/"+string(member.ID)+":set-status", root, iamv1.SetUserStatusRequest{Status: iamv1.PrincipalDisabled, ResourceVersion: access.User.ResourceVersion, RequestID: "deletion-member-disable"}, http.StatusOK, &member)
	call(http.MethodDelete, path, root, deletion, http.StatusConflict, nil)
	call(http.MethodPost, "/v1/policy-attachments/"+string(attachment.ID)+":revoke", root, iamv1.RevokePolicyAttachmentRequest{ResourceVersion: 1, RequestID: "deletion-user-revoke"}, http.StatusOK, nil)
	var group iamv1.Group
	call(http.MethodPost, "/v1/groups", root, iamv1.CreateGroupRequest{Name: "Deletion group", RequestID: "deletion-group-create"}, http.StatusCreated, &group)
	grant.Target = iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetGroup, ID: string(group.ID)}
	grant.RequestID = "deletion-group-grant"
	call(http.MethodPost, "/v1/policy-attachments", root, grant, http.StatusOK, &attachment)
	call(http.MethodDelete, path, root, deletion, http.StatusConflict, nil)
	call(http.MethodPost, "/v1/policy-attachments/"+string(attachment.ID)+":revoke", root, iamv1.RevokePolicyAttachmentRequest{ResourceVersion: 1, RequestID: "deletion-group-revoke"}, http.StatusOK, nil)
	call(http.MethodDelete, path+"?accountId=other", root, deletion, http.StatusBadRequest, nil)
	call(http.MethodDelete, path, iamProducerCredential, deletion, http.StatusUnauthorized, nil)
	call(http.MethodDelete, "/v1/policies/"+string(iamv1.SystemPolicyAccountAdministrator), root, deletion, http.StatusForbidden, nil)
	for _, field := range []string{"accountId", "scope", "management", "id", "force"} {
		call(http.MethodDelete, path, root, map[string]any{"resourceVersion": 1, "requestId": "deletion-selector", field: "injected"}, http.StatusBadRequest, nil)
	}
	wrong := deletion
	wrong.ResourceVersion = 2
	call(http.MethodDelete, path, root, wrong, http.StatusConflict, nil)
	if _, err := database.Exec(ctx, `CREATE FUNCTION public.matrix_policy_delete_fault() RETURNS trigger LANGUAGE plpgsql AS $body$
		BEGIN IF NEW.event_document->>'action'='iam.policy.deleted' THEN RAISE EXCEPTION 'injected deletion outbox failure'; END IF; RETURN NEW; END $body$;
		CREATE TRIGGER matrix_policy_delete_fault BEFORE INSERT ON iam.audit_outbox FOR EACH ROW EXECUTE FUNCTION public.matrix_policy_delete_fault()`); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := database.Exec(context.Background(), `DROP TRIGGER IF EXISTS matrix_policy_delete_fault ON iam.audit_outbox; DROP FUNCTION IF EXISTS public.matrix_policy_delete_fault()`); err != nil {
			t.Error("remove isolated policy deletion fault")
		}
	}()
	call(http.MethodDelete, path, root, deletion, http.StatusServiceUnavailable, nil)
	var before iamv1.PolicyDetail
	call(http.MethodGet, path, root, nil, http.StatusOK, &before)
	if !bytes.Equal(mustIAMJSON(t, before), mustIAMJSON(t, policy)) {
		t.Fatal("failed deletion left metadata changes")
	}
	var count int
	if err := database.QueryRow(ctx, `SELECT (SELECT count(*) FROM iam.audit_outbox WHERE tenant_id=$1 AND event_document->>'requestId'=$2)+(SELECT count(*) FROM iam.authorization_decisions WHERE tenant_id=$1 AND request_id=$2)`, policy.Policy.AccountID, deletion.RequestID).Scan(&count); err != nil || count != 0 {
		t.Fatal("failed deletion left decision or fact")
	}
	if _, err := database.Exec(ctx, `DROP TRIGGER matrix_policy_delete_fault ON iam.audit_outbox; DROP FUNCTION public.matrix_policy_delete_fault()`); err != nil {
		t.Fatal(err)
	}
	var retired, replayed iamv1.Policy
	call(http.MethodDelete, path, root, deletion, http.StatusOK, &retired)
	call(http.MethodDelete, path, root, deletion, http.StatusOK, &replayed)
	if iamv1.ValidatePolicy(retired) != nil || retired.Status != iamv1.PolicyRetired || retired.ResourceVersion != 2 || retired.ID != policy.Policy.ID || retired.DefaultVersionID != policy.Version.ID || retired != replayed {
		t.Fatal("policy deletion identity or replay differs")
	}
	wrong = deletion
	wrong.RequestID = "deletion-different-intent"
	call(http.MethodDelete, path, root, wrong, http.StatusConflict, nil)
	call(http.MethodGet, path, root, nil, http.StatusForbidden, nil)
	call(http.MethodGet, path+"/versions", root, nil, http.StatusForbidden, nil)
	call(http.MethodPatch, path, root, iamv1.UpdatePolicyRequest{DisplayName: "Revived", ResourceVersion: 2, RequestID: "deletion-revive-name"}, http.StatusForbidden, nil)
	call(http.MethodPost, path+"/versions", root, iamv1.CreatePolicyVersionRequest{Document: document, ResourceVersion: 2, RequestID: "deletion-revive-version"}, http.StatusForbidden, nil)
	call(http.MethodPost, path+":set-default-version", root, iamv1.SetDefaultPolicyVersionRequest{VersionID: policy.Version.ID, ResourceVersion: 2, RequestID: "deletion-revive-default"}, http.StatusForbidden, nil)
	grant.RequestID = "deletion-revive-attachment"
	grant.PolicyResourceVersion = 2
	call(http.MethodPost, "/v1/policy-attachments", root, grant, http.StatusForbidden, nil)
	call(http.MethodPost, "/v1/policies", root, creation, http.StatusConflict, nil)
	var inventory iamv1.PolicyList
	call(http.MethodGet, "/v1/policies", root, nil, http.StatusOK, &inventory)
	for _, item := range inventory.Items {
		if item.ID == retired.ID {
			t.Fatal("deleted policy still occupies management inventory")
		}
	}
	var raw []byte
	var event auditv1.Event
	for _, action := range []auditv1.Action{auditv1.ActionIAMPolicyCreated, auditv1.ActionIAMPolicyDeleted} {
		if err := database.QueryRow(ctx, `SELECT event_document FROM iam.audit_outbox WHERE tenant_id=$1 AND event_document->>'action'=$2 AND event_document#>>'{target,id}'=$3`, retired.AccountID, action, retired.ID).Scan(&raw); err != nil || json.Unmarshal(raw, &event) != nil {
			t.Fatal("read retained lifecycle fact")
		}
		call(http.MethodPost, "/v1/audit-producer:resolve", iamProducerCredential, iamv1.ResolveAuditProducerRequest{Event: event}, http.StatusOK, nil)
	}
	var canonical, digest string
	if err := database.QueryRow(ctx, `SELECT canonical_document,content_digest FROM iam.policy_versions WHERE policy_id=$1 AND id=$2`, retired.ID, retired.DefaultVersionID).Scan(&canonical, &digest); err != nil || digest != policy.Version.ContentDigest {
		t.Fatal("deletion destroyed original immutable content")
	}
	// Real deletion frees the name and capacity; large retired history is
	// read-budget data, not a claim that a bulk SQL fixture used this API.
	if _, err := database.Exec(ctx, `BEGIN;
		INSERT INTO iam.policies(id,management,owner_tenant_id,display_name,authority_scope,status,default_version_id,resource_version,created_at,updated_at)
		SELECT 'delete-history-'||i,'CUSTOMER',$1,'Retired history '||i,'TENANT','RETIRED','v1',1,transaction_timestamp(),transaction_timestamp() FROM generate_series(1,257) i;
		INSERT INTO iam.policy_versions(policy_id,id,authority_scope,document,canonical_document,content_digest,created_at)
		SELECT 'delete-history-'||i,'v1','TENANT',$2::jsonb,$2,$3,transaction_timestamp() FROM generate_series(1,257) i;COMMIT;`, retired.AccountID, canonical, digest); err != nil {
		t.Fatal(err)
	}
	var replacement iamv1.PolicyDetail
	creation.RequestID = "deletion-replacement"
	call(http.MethodPost, "/v1/policies", root, creation, http.StatusCreated, &replacement)
	if replacement.Policy.ID == retired.ID {
		t.Fatal("replacement resurrected old policy identity")
	}
	call(http.MethodGet, "/v1/policies", root, nil, http.StatusOK, &inventory)
	if err := database.QueryRow(ctx, `SELECT count(*) FROM iam.audit_outbox WHERE tenant_id=$1 AND event_document->>'action'='iam.policy.deleted' AND event_document#>>'{target,id}'=$2`, retired.AccountID, retired.ID).Scan(&count); err != nil || count != 1 {
		t.Fatal("deletion replay duplicated success fact")
	}
	// Restoration of the member does not restore its revoked attachment.
	call(http.MethodPost, "/v1/users/"+string(member.ID)+":set-status", root, iamv1.SetUserStatusRequest{Status: iamv1.PrincipalActive, ResourceVersion: member.ResourceVersion, RequestID: "deletion-member-enable"}, http.StatusOK, nil)
	bearer = localRecoveryLogin(t, handler, member.LoginName+"@"+string(member.AccountID), changedDeveloperPassword, false)
	call(http.MethodPost, "/v1/policy-attachments", root, iamv1.CreatePolicyAttachmentRequest{Target: iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetUser, ID: string(member.ID)}, PolicyID: iamv1.SystemPolicyAccountAdministrator, PolicyResourceVersion: 1, RequestID: "deletion-member-admin"}, http.StatusOK, nil)
	call(http.MethodDelete, "/v1/policies/"+string(replacement.Policy.ID), bearer, deletion, http.StatusForbidden, nil)
	call(http.MethodPost, "/v1/accounts", root, map[string]any{"id": "deletion-other-account", "displayName": "Deletion other", "rootLoginName": "deletion-other-root", "rootDisplayName": "Other root", "initialPassword": initialDeveloperPassword, "requestId": "deletion-other-create"}, http.StatusCreated, nil)
	other := localRecoveryLogin(t, handler, "deletion-other-root", initialDeveloperPassword, true)
	other = localRecoveryChangePassword(t, handler, other, initialDeveloperPassword, changedDeveloperPassword)
	call(http.MethodDelete, "/v1/policies/"+string(replacement.Policy.ID), other, deletion, http.StatusForbidden, nil)
	// Delete and attach coordinate through the same Policy lock. No schedule
	// may leave a live attachment pointing at a retired policy.
	grant.PolicyID = replacement.Policy.ID
	grant.PolicyResourceVersion = 1
	grant.RequestID = "deletion-racing-attachment"
	deleteBody := mustIAMJSON(t, iamv1.DeletePolicyRequest{ResourceVersion: 1, RequestID: "deletion-racing-delete"})
	grantBody := mustIAMJSON(t, grant)
	completed := make(chan *httptest.ResponseRecorder, 2)
	go func() {
		completed <- performIAMRequest(handler, http.MethodDelete, "/v1/policies/"+string(replacement.Policy.ID), root, deleteBody)
	}()
	go func() {
		completed <- performIAMRequest(handler, http.MethodPost, "/v1/policy-attachments", root, grantBody)
	}()
	winners, denied := 0, 0
	for range 2 {
		select {
		case response := <-completed:
			switch response.Code {
			case http.StatusOK:
				winners++
			case http.StatusConflict, http.StatusForbidden:
				denied++
			default:
				t.Fatalf("delete/attach race status=%d", response.Code)
			}
		case <-ctx.Done():
			t.Fatal("delete/attach race timed out")
		}
	}
	if winners != 1 || denied != 1 {
		t.Fatal("delete/attach race did not have one winner")
	}
	var inconsistent bool
	if err := database.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM iam.policies p JOIN iam.policy_attachments a ON a.policy_id=p.id WHERE p.id=$1 AND p.status='RETIRED' AND a.revoked_at IS NULL)`, replacement.Policy.ID).Scan(&inconsistent); err != nil || inconsistent {
		t.Fatal("delete/attach race left a live retired-policy reference")
	}
	// Deletion competes with all metadata/content mutation paths at one
	// expected revision; their shared lock must not merely protect delete
	// against itself or attachment creation.
	creation.DisplayName = "Deletion multiway race"
	creation.RequestID = "deletion-multi-create"
	var competing iamv1.PolicyDetail
	call(http.MethodPost, "/v1/policies", root, creation, http.StatusCreated, &competing)
	competingPath := "/v1/policies/" + string(competing.Policy.ID)
	variant := document
	variant.Statements = append([]iamv1.PolicyStatement(nil), document.Statements...)
	variant.Statements[0].Effect = iamv1.PolicyDeny
	var next iamv1.PolicyVersionDetail
	call(http.MethodPost, competingPath+"/versions", root, iamv1.CreatePolicyVersionRequest{Document: variant, ResourceVersion: 1, RequestID: "deletion-multi-version"}, http.StatusCreated, &next)
	variant.Statements[0].SID = "competing-version"
	type mutationResult struct {
		index    int
		response *httptest.ResponseRecorder
	}
	results := make(chan mutationResult, 4)
	operations := []struct {
		method, path string
		body         any
	}{
		{http.MethodDelete, competingPath, iamv1.DeletePolicyRequest{ResourceVersion: 2, RequestID: "deletion-multi-race-delete"}},
		{http.MethodPatch, competingPath, iamv1.UpdatePolicyRequest{DisplayName: "Deletion race renamed", ResourceVersion: 2, RequestID: "deletion-multi-race-update"}},
		{http.MethodPost, competingPath + "/versions", iamv1.CreatePolicyVersionRequest{Document: variant, ResourceVersion: 2, RequestID: "deletion-multi-race-version"}},
		{http.MethodPost, competingPath + ":set-default-version", iamv1.SetDefaultPolicyVersionRequest{VersionID: next.Version.ID, ResourceVersion: 2, RequestID: "deletion-multi-race-default"}},
	}
	for index, operation := range operations {
		body := mustIAMJSON(t, operation.body)
		go func() {
			results <- mutationResult{index, performIAMRequest(handler, operation.method, operation.path, root, body)}
		}()
	}
	winner := -1
	denied = 0
	for range 4 {
		select {
		case result := <-results:
			switch result.response.Code {
			case http.StatusOK, http.StatusCreated:
				if winner != -1 {
					t.Fatal("multiple policy mutations won one revision")
				}
				winner = result.index
			case http.StatusConflict, http.StatusForbidden:
				denied++
			default:
				t.Fatalf("multiway policy race status=%d", result.response.Code)
			}
		case <-ctx.Done():
			t.Fatal("multiway policy mutation race timed out")
		}
	}
	if winner < 0 || denied != 3 {
		t.Fatal("policy lifecycle race had no single winner")
	}
	var stored iamv1.Policy
	var contentCount int
	if err := database.QueryRow(ctx, `SELECT iam.lookup_policy($1,$2),(SELECT count(*) FROM iam.policy_versions WHERE policy_id=$2)`, competing.Policy.AccountID, competing.Policy.ID).Scan(&raw, &contentCount); err != nil || json.Unmarshal(raw, &stored) != nil {
		t.Fatal("read multiway policy result")
	}
	wantStatus, wantName, wantDefault, wantContent := iamv1.PolicyActive, competing.Policy.DisplayName, competing.Version.ID, 2
	if winner == 0 {
		wantStatus = iamv1.PolicyRetired
	}
	if winner == 1 {
		wantName = "Deletion race renamed"
	}
	if winner == 2 {
		wantContent = 3
	}
	if winner == 3 {
		wantDefault = next.Version.ID
	}
	if stored.ResourceVersion != 3 || stored.Status != wantStatus || stored.DisplayName != wantName ||
		contentCount != wantContent || stored.DefaultVersionID != wantDefault || stored.ID != competing.Policy.ID || stored.AccountID != competing.Policy.AccountID {
		t.Fatal("losing policy mutation left partial state")
	}
	// Authorization itself also emits a fact. Count the lifecycle fact, then
	// bind it to the actual winning command and its committed decision.
	wantAction := []auditv1.Action{auditv1.ActionIAMPolicyDeleted, auditv1.ActionIAMPolicyUpdated, auditv1.ActionIAMPolicyVersionCreated, auditv1.ActionIAMPolicyDefaultVersionSet}[winner]
	var winningRequest struct {
		RequestID string `json:"requestId"`
	}
	if json.Unmarshal(mustIAMJSON(t, operations[winner].body), &winningRequest) != nil {
		t.Fatal("read winning command identity")
	}
	var matched int
	if err := database.QueryRow(ctx, `SELECT count(*),count(*) FILTER (WHERE o.event_document->>'action'=$2
		AND o.event_document->>'requestId'=$3 AND o.event_document#>>'{target,id}'=$4
		AND EXISTS(SELECT 1 FROM iam.authorization_decisions d WHERE d.tenant_id=o.tenant_id
		AND d.id=o.event_document->>'iamDecisionId' AND d.allowed AND d.request_id=$3))
		FROM iam.audit_outbox o WHERE o.tenant_id=$1 AND o.event_document->>'requestId' LIKE 'deletion-multi-race-%'
		AND o.event_document->>'action' IN ('iam.policy.deleted','iam.policy.updated','iam.policy-version.created','iam.policy.default-version-set')`,
		competing.Policy.AccountID, wantAction, winningRequest.RequestID, competing.Policy.ID).Scan(&count, &matched); err != nil || count != 1 || matched != 1 {
		t.Fatal("policy lifecycle race did not commit one winner-bound fact")
	}
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
		body, _ := json.Marshal(profileBoundIAMRequest(t, iamv1.AuthorizationRequest{Action: iamv1.ActionPaaSApplicationRead, Resource: iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "group-application"}, RequestID: "group-application-read", CorrelationID: "group-application-read"}, iamv1.AuthorizationResourceInstance, ""))
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
		_, err = tx.Exec(ctx, `SELECT iam.record_authorization($1,$2,jsonb_build_object('request',document-'apiVersion'-'kind'-'id'-'allowed'-'reason'-'decidedAt'-'tenantId'-'installationId'-'subject','decision',document||jsonb_build_object('id','forged-group-decision','decidedAt',to_char(transaction_timestamp() AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))),'{}'::jsonb,`+expression+`,boundary_evidence,2) FROM iam.authorization_decisions WHERE tenant_id=$1 AND id=$3`, member.AccountID, member.ID, decision.ID)
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
	// Boundary transitions invalidate the whole authority snapshot, even when
	// the old and new defaults both still allow listing this exact directory.
	boundaryPath := "/v1/users/" + string(delegate.ID) + "/permission-boundary"
	var boundaryView iamv1.UserPermissionBoundary
	get(boundaryPath, operator, http.StatusOK, &boundaryView)
	var directoryBound iamv1.PolicyDetail
	directoryDocument := iamv1.PolicyDocument{LanguageVersion: iamv1.PolicyLanguageVersion, Scope: iamv1.AuthorityScopeTenant,
		Statements: []iamv1.PolicyStatement{{SID: "list-before", Effect: iamv1.PolicyAllow, Actions: []iamv1.Action{iamv1.ActionIAMGroupList},
			Resources: []iamv1.PolicyResourceSelector{{Kind: iamv1.ResourceAccount, Match: iamv1.PolicyResourceAnyInAuthority}}}}}
	post("/v1/policies", operator, iamv1.CreatePolicyRequest{DisplayName: "Directory boundary", Document: directoryDocument, RequestID: "cursor-boundary-policy"}, http.StatusCreated, &directoryBound)
	get("/v1/groups", delegateBearer, http.StatusOK, &delegatedPage)
	boundaryResponse := performIAMRequest(handler, http.MethodPut, boundaryPath, operator, mustIAMJSON(t, iamv1.SetUserPermissionBoundaryRequest{
		PolicyID: directoryBound.Policy.ID, PolicyResourceVersion: 1, ResourceVersion: boundaryView.ResourceVersion, RequestID: "cursor-boundary-set"}))
	if boundaryResponse.Code != http.StatusOK {
		t.Fatalf("directory boundary set status=%d", boundaryResponse.Code)
	}
	get("/v1/groups?after="+delegatedPage.NextAfter, delegateBearer, http.StatusUnprocessableEntity, nil)
	directoryDocument.Statements[0].SID = "list-after"
	var directoryVersion iamv1.PolicyVersionDetail
	post("/v1/policies/"+string(directoryBound.Policy.ID)+"/versions", operator, iamv1.CreatePolicyVersionRequest{
		Document: directoryDocument, ResourceVersion: 1, RequestID: "cursor-boundary-version"}, http.StatusCreated, &directoryVersion)
	get("/v1/groups", delegateBearer, http.StatusOK, &delegatedPage)
	if len(delegatedPage.Items) != 100 || delegatedPage.NextAfter == "" {
		t.Fatal("bounded directory did not produce a real continuation")
	}
	post("/v1/policies/"+string(directoryBound.Policy.ID)+":set-default-version", operator, iamv1.SetDefaultPolicyVersionRequest{
		VersionID: directoryVersion.Version.ID, ResourceVersion: directoryVersion.Policy.ResourceVersion, RequestID: "cursor-boundary-default"}, http.StatusOK, nil)
	get("/v1/groups?after="+delegatedPage.NextAfter, delegateBearer, http.StatusUnprocessableEntity, nil)
	get("/v1/groups", delegateBearer, http.StatusOK, &delegatedPage)
	get("/v1/groups?after="+delegatedPage.NextAfter, delegateBearer, http.StatusOK, nil)
	get(boundaryPath, operator, http.StatusOK, &boundaryView)
	boundaryResponse = performIAMRequest(handler, http.MethodDelete, boundaryPath, operator, mustIAMJSON(t, iamv1.RemoveUserPermissionBoundaryRequest{
		ResourceVersion: boundaryView.ResourceVersion, RequestID: "cursor-boundary-remove"}))
	if boundaryResponse.Code != http.StatusOK {
		t.Fatal("directory boundary removal failed")
	}
	get("/v1/groups?after="+delegatedPage.NextAfter, delegateBearer, http.StatusUnprocessableEntity, nil)
	get("/v1/groups", delegateBearer, http.StatusOK, nil)
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
	body, _ := json.Marshal(profileBoundIAMRequest(t, iamv1.AuthorizationRequest{Action: iamv1.ActionPaaSApplicationRead, Resource: iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "capacity-app"}, RequestID: "capacity-overflow-decide", CorrelationID: "capacity-overflow-decide"}, iamv1.AuthorizationResourceInstance, ""))
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
	if retired != nil {
		t.Fatal("retired policy occupied the active management directory")
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
				body, _ := json.Marshal(profileBoundIAMRequest(t, iamv1.AuthorizationRequest{Action: iamv1.ActionPaaSApplicationRead,
					Resource:  iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "publication-resource"},
					RequestID: requestID + "-evaluate-" + version, CorrelationID: requestID}, iamv1.AuthorizationResourceInstance, ""))
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
	// Bulk disabled identities are pagination data, not evidence of online
	// user creation. Put the real HTTP-created protected USER beyond page one
	// even when this subtest is run alone; unrelated random IDs must not decide
	// whether the protection assertion is exercised.
	if _, err := database.Exec(ctx, `INSERT INTO iam.principals(tenant_id,id,principal_type,login_name,display_name,status,must_change_password,resource_version,created_at,updated_at)
		SELECT $1,'0-scope-page-'||lpad(i::text,3,'0'),'USER','scope.page.'||i,'Scope pagination fixture','DISABLED',false,1,transaction_timestamp(),transaction_timestamp()
		FROM generate_series(1,100) i`, member.AccountID); err != nil {
		t.Fatal("prepare protected-directory pagination")
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
		found := false
		path := "/v1/users"
		seen := map[string]bool{}
		pages := 0
		for ; pages < 10; pages++ {
			response := performIAMRequest(handler, http.MethodGet, path, operator, nil)
			var directory iamv1.UserList
			if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &directory) != nil || iamv1.ValidateUserList(directory) != nil {
				t.Fatalf("protected identity directory %s: status=%d", phase, response.Code)
			}
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
			if found || directory.NextAfter == "" {
				break
			}
			if seen[directory.NextAfter] {
				t.Fatal("protected directory cursor did not advance")
			}
			seen[directory.NextAfter] = true
			path = "/v1/users?after=" + directory.NextAfter
		}
		if !found || pages == 0 {
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
	transactionFailures := &iamTransactionFailureTrace{}
	poolConfig.ConnConfig.Tracer = transactionFailures
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
	verificationBody := mustIAMJSON(t, profileBoundIAMRequest(t, iamv1.AuthorizationRequest{Action: iamv1.ActionInstallationVerify, Resource: iamv1.ResourceReference{Kind: iamv1.ResourceInstallation, ID: "installation-http-integration"}, RequestID: "request-installation-verify", CorrelationID: "correlation-installation-verify"}, iamv1.AuthorizationResourceInstance, ""))
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
	verificationBody = mustIAMJSON(t, profileBoundIAMRequest(t, iamv1.AuthorizationRequest{Action: iamv1.ActionInstallationVerify, Resource: iamv1.ResourceReference{Kind: iamv1.ResourceInstallation, ID: "installation-other"}, RequestID: "request-installation-other", CorrelationID: "correlation-installation-other"}, iamv1.AuthorizationResourceInstance, ""))
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
	authorizeBody := mustIAMJSON(t, profileBoundIAMRequest(t, iamv1.AuthorizationRequest{Action: iamv1.ActionPaaSApplicationCreate, Resource: iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "collection"}, RequestID: "request-authorize", CorrelationID: "correlation-authorize"}, iamv1.AuthorizationResourceCollection, iamv1.AuthorizationCollectionCreate))
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
	authorizeBody = mustIAMJSON(t, profileBoundIAMRequest(t, iamv1.AuthorizationRequest{Action: iamv1.ActionPaaSApplicationCreate, Resource: iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "collection"}, RequestID: "request-authorize-allowed", CorrelationID: "correlation-authorize-allowed"}, iamv1.AuthorizationResourceCollection, iamv1.AuthorizationCollectionCreate))
	authorize = performIAMRequestWithSubject(handler, authorizeBody, paasCredential, loginWire.Credential)
	if authorize.Code != http.StatusOK {
		t.Fatalf("IAM allowed authorize status=%d body=%s", authorize.Code, authorize.Body.String())
	}
	if err := json.Unmarshal(authorize.Body.Bytes(), &decision); err != nil || !decision.Allowed ||
		decision.TenantID != "organization-http-integration" {
		t.Fatalf("administrator allowed decision=%#v err=%v", decision, err)
	}
	managedServiceAuthorizeBody := mustIAMJSON(t, profileBoundIAMRequest(t, iamv1.AuthorizationRequest{Action: iamv1.ActionManagedServiceOfferingRead, Resource: iamv1.ResourceReference{Kind: iamv1.ResourceServiceOffering, ID: "collection"}, RequestID: "request-managedservice-offering", CorrelationID: "correlation-managedservice-offering"}, iamv1.AuthorizationResourceCollection, iamv1.AuthorizationCollectionList))
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
	developerAuthorizeBody := mustIAMJSON(t, profileBoundIAMRequest(t, iamv1.AuthorizationRequest{Action: iamv1.ActionPaaSApplicationCreate, Resource: iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "collection"}, RequestID: "request-developer-before-password", CorrelationID: "correlation-developer-before-password"}, iamv1.AuthorizationResourceCollection, iamv1.AuthorizationCollectionCreate))
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
	developerAuthorizeBody = mustIAMJSON(t, profileBoundIAMRequest(t, iamv1.AuthorizationRequest{Action: iamv1.ActionPaaSApplicationCreate, Resource: iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "collection"}, RequestID: "request-developer-allowed", CorrelationID: "correlation-developer-allowed"}, iamv1.AuthorizationResourceCollection, iamv1.AuthorizationCollectionCreate))
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
		proveTenantAccounts(t, ctx, handler, admin, loginWire.Credential, transactionFailures)
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
	developerAuthorizeBody = mustIAMJSON(t, profileBoundIAMRequest(t, iamv1.AuthorizationRequest{Action: iamv1.ActionPaaSApplicationCreate, Resource: iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "collection"}, RequestID: "request-developer-after-binding", CorrelationID: "correlation-developer-after-binding"}, iamv1.AuthorizationResourceCollection, iamv1.AuthorizationCollectionCreate))
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
	verificationBody = mustIAMJSON(t, profileBoundIAMRequest(t, iamv1.AuthorizationRequest{Action: iamv1.ActionInstallationVerify, Resource: iamv1.ResourceReference{Kind: iamv1.ResourceInstallation, ID: "installation-http-integration"}, RequestID: "request-installation-revoked", CorrelationID: "correlation-installation-revoked"}, iamv1.AuthorizationResourceInstance, ""))
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

func proveTenantAccounts(t *testing.T, ctx context.Context, handler http.Handler, admin *pgx.Conn, root string, failures *iamTransactionFailureTrace) {
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
	assertPaasDecision := func(bearer string, action iamv1.Action, usage iamv1.AuthorizationCollectionUsage, expected bool, tenant string) {
		t.Helper()
		kind, _ := iamv1.ResourceKindForAction(action)
		body, _ := json.Marshal(profileBoundIAMRequest(t, iamv1.AuthorizationRequest{Action: action, Resource: iamv1.ResourceReference{Kind: kind, ID: "collection"}, RequestID: "request-account-paas", CorrelationID: "request-account-paas"}, iamv1.AuthorizationResourceCollection, usage))
		response := performIAMRequestWithSubject(handler, body, paasCredential, bearer)
		var result iamv1.AuthorizationDecision
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &result) != nil || result.Allowed != expected || (expected && string(result.TenantID) != tenant) {
			t.Fatalf("account-bound decision status=%d allowed=%t tenant=%s", response.Code, result.Allowed, result.TenantID)
		}
	}
	rootIdentity := identity(root)
	rootCreate, rootCanCreate := findIAMCapability(rootIdentity.Capabilities, iamv1.ActionIAMAccountCreate, iamv1.ResourceAccount, "collection")
	rootRead, rootCanRead := findIAMCapability(rootIdentity.Capabilities, iamv1.ActionIAMAccountRead, iamv1.ResourceAccount, "collection")
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
	if capability, found := findIAMCapability(primaryIdentity.Capabilities, iamv1.ActionIAMAccountCreate, iamv1.ResourceAccount, "collection"); !found || capability.Available {
		t.Fatal("new primary inherited platform account-opening capability")
	}
	if capability, found := findIAMCapability(primaryIdentity.Capabilities, iamv1.ActionIAMAccountRead, iamv1.ResourceAccount, "collection"); !found || capability.Available {
		t.Fatal("new primary inherited platform account-directory capability")
	}
	passwordChange(primaryB, primaryBPassword, primaryBChanged)
	t.Run("event-bound historical producer authority", func(t *testing.T) {
		proveHistoricalProducerHTTP(t, ctx, handler, admin, root, map[string]string{tenantA: root, tenantB: primaryB})
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
		capability, found := findIAMCapability(id.Capabilities, iamv1.ActionIAMAccountCreate, iamv1.ResourceAccount, "collection")
		return !found || capability.Available
	}() {
		t.Fatal("wrong tenant or platform capability in child identity")
	}
	if len(identity(childSessionB).PolicySources) != 0 {
		t.Fatal("new child gained implicit business permissions")
	}
	assertPaasDecision(childSessionA, iamv1.ActionManagedServiceInstallationRead, iamv1.AuthorizationCollectionList, true, tenantA)
	assertPaasDecision(childSessionA, iamv1.ActionManagedServiceInstallationCreate, iamv1.AuthorizationCollectionCreate, false, "")
	assertPaasDecision(childSessionB, iamv1.ActionManagedServiceInstallationRead, iamv1.AuthorizationCollectionList, false, "")
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
	if capability, found := findIAMCapability(identity(delegatedSession).Capabilities, iamv1.ActionIAMAccountCreate, iamv1.ResourceAccount, "collection"); !found || capability.Available {
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
	assertPaasDecision(childSessionA, iamv1.ActionManagedServiceInstallationRead, iamv1.AuthorizationCollectionList, false, "")
	grant := request(http.MethodPost, "/v1/policy-attachments", primaryB, map[string]any{"target": iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetUser, ID: string(childB.ID)}, "policyId": iamv1.SystemPolicyPaaSDeveloper, "policyResourceVersion": 1, "requestId": "request-child-grant"}, http.StatusOK)
	if bytes.Contains(grant.Body.Bytes(), []byte(tenantA)) {
		t.Fatal("grant selected the wrong tenant")
	}
	assertPaasDecision(childSessionB, iamv1.ActionManagedServiceInstallationCreate, iamv1.AuthorizationCollectionCreate, true, tenantB)

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
	assertPaasDecision(resetSession, iamv1.ActionManagedServiceInstallationRead, iamv1.AuthorizationCollectionList, false, "")
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
	for round := 0; round < 8; round++ {
		startAliasRace := make(chan struct{})
		type aliasOutcome struct{ actor, status int }
		aliasResults := make(chan aliasOutcome, 2)
		actors := []string{root, primaryB}
		beforeIdentity := []iamv1.CurrentIdentity{identity(root), identity(primaryB)}
		before := []iamv1.Account{beforeIdentity[0].Account, beforeIdentity[1].Account}
		alias, requestID := fmt.Sprintf("concurrent-company-%d", round), fmt.Sprintf("request-alias-race-%d", round)
		serialization, deadlocks := failures.serialization.Load(), failures.deadlock.Load()
		for index, actor := range actors {
			body, err := json.Marshal(iamv1.SetAccountAliasRequest{Alias: alias, ResourceVersion: before[index].ResourceVersion, RequestID: requestID})
			if err != nil {
				t.Fatal(err)
			}
			go func(index int, bearer string, encoded []byte) {
				<-startAliasRace
				aliasResults <- aliasOutcome{index, performIAMRequest(handler, http.MethodPost, "/v1/account:alias", bearer, encoded).Code}
			}(index, actor, body)
		}
		close(startAliasRace)
		first, second := <-aliasResults, <-aliasResults
		transient := fmt.Sprintf("40001=%d 40P01=%d", failures.serialization.Load()-serialization, failures.deadlock.Load()-deadlocks)
		if !((first.status == http.StatusOK && second.status == http.StatusConflict) || (second.status == http.StatusOK && first.status == http.StatusConflict)) {
			t.Fatalf("concurrent alias acquisition round=%d statuses=%d,%d %s", round, first.status, second.status, transient)
		}
		for _, result := range []aliasOutcome{first, second} {
			afterIdentity := identity(actors[result.actor])
			after := afterIdentity.Account
			if !reflect.DeepEqual(afterIdentity.User, beforeIdentity[result.actor].User) {
				t.Fatal("alias acquisition changed the original principal")
			}
			var totalLoginRows, matchingLoginRows int
			if err := admin.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE login_name=$3) FROM iam.login_index WHERE tenant_id=$1 AND principal_id=$2`, after.ID, afterIdentity.User.ID, afterIdentity.User.LoginName).Scan(&totalLoginRows, &matchingLoginRows); err != nil || totalLoginRows != 1 || matchingLoginRows != 1 {
				t.Fatal("alias acquisition changed the original login index")
			}
			// This CAS route does not promise an idempotent success receipt:
			// replaying the original version must conflict without another write.
			request(http.MethodPost, "/v1/account:alias", actors[result.actor], iamv1.SetAccountAliasRequest{Alias: alias, ResourceVersion: before[result.actor].ResourceVersion, RequestID: requestID}, http.StatusConflict)
			if !reflect.DeepEqual(identity(actors[result.actor]).Account, after) {
				t.Fatal("replaying the original alias CAS changed the account")
			}
			var facts, aliases int
			if err := admin.QueryRow(ctx, `SELECT count(*) FROM iam.audit_outbox WHERE tenant_id=$1 AND event_document->>'action'='iam.account.alias-set' AND event_document->>'requestId'=$2`, after.ID, requestID).Scan(&facts); err != nil {
				t.Fatal(err)
			}
			if err := admin.QueryRow(ctx, `SELECT count(*) FROM iam.account_aliases WHERE tenant_id=$1 AND alias=$2`, after.ID, alias).Scan(&aliases); err != nil {
				t.Fatal(err)
			}
			if result.status == http.StatusConflict {
				if !reflect.DeepEqual(after, before[result.actor]) || facts != 0 || aliases != 0 {
					t.Fatal("losing alias transaction changed account, reservation or success fact")
				}
			} else if after.ResourceVersion != before[result.actor].ResourceVersion+1 || after.LoginAlias == nil || *after.LoginAlias != alias || facts != 1 || aliases != 1 {
				t.Fatal("winning alias transaction lacks exactly one version, reservation or success fact")
			}
		}
		t.Logf("alias competition round=%d: one success, one conflict, loser unchanged; %s", round, transient)
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
	operatorCreate, operatorCanCreate := findIAMCapability(identity.Capabilities, iamv1.ActionIAMAccountCreate, iamv1.ResourceAccount, "collection")
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
	recoveredCreate, recoveredCanCreate := findIAMCapability(identity.Capabilities, iamv1.ActionIAMAccountCreate, iamv1.ResourceAccount, "collection")
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

func proveHistoricalProducerHTTP(t *testing.T, ctx context.Context, handler http.Handler, database *pgx.Conn, platformActor string, tenants map[string]string) {
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
			usage       iamv1.AuthorizationCollectionUsage
		}{
			{paasCredential, iamv1.ActionPaaSApplicationCreate, auditv1.ActionPaaSApplicationCreated, iamv1.ResourceApplication, auditv1.TargetApplication, "collection", iamv1.AuthorizationCollectionCreate},
			{auditCredential, iamv1.ActionAuditRecordRead, auditv1.ActionAuditRecordsRead, iamv1.ResourceAuditRecord, auditv1.TargetAuditRecords, "records", iamv1.AuthorizationCollectionList},
		} {
			body, _ := json.Marshal(profileBoundIAMRequest(t, iamv1.AuthorizationRequest{Action: producer.action, Resource: iamv1.ResourceReference{Kind: producer.kind, ID: "collection"}, RequestID: "request-proof-business", CorrelationID: "correlation-proof-business"}, iamv1.AuthorizationResourceCollection, producer.usage))
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
	for _, mapping := range []struct {
		action   iamv1.Action
		fact     auditv1.Action
		resource string
		mode     iamv1.AuthorizationResourceMode
		usage    iamv1.AuthorizationCollectionUsage
	}{
		{iamv1.ActionPaaSNodeEnrollmentCreate, auditv1.ActionPaaSExecutionTargetRegistered, "collection", iamv1.AuthorizationResourceCollection, iamv1.AuthorizationCollectionCreate},
		{iamv1.ActionPaaSExecutionTargetRegister, auditv1.ActionPaaSExecutionTargetRegistered, "execution-target-proof", iamv1.AuthorizationResourceInstance, ""},
		{iamv1.ActionPaaSExecutionTargetDrain, auditv1.ActionPaaSExecutionTargetDrained, "execution-target-proof", iamv1.AuthorizationResourceInstance, ""},
		{iamv1.ActionPaaSExecutionTargetActivate, auditv1.ActionPaaSExecutionTargetActivated, "execution-target-proof", iamv1.AuthorizationResourceInstance, ""},
		{iamv1.ActionPaaSExecutionTargetRemove, auditv1.ActionPaaSExecutionTargetRemoved, "execution-target-proof", iamv1.AuthorizationResourceInstance, ""},
	} {
		kind, _ := iamv1.ResourceKindForAction(mapping.action)
		request := profileBoundIAMRequest(t, iamv1.AuthorizationRequest{Action: mapping.action, Resource: iamv1.ResourceReference{Kind: kind, ID: mapping.resource},
			RequestID: "proof-" + string(mapping.action), CorrelationID: "correlation-platform-proof"}, mapping.mode, mapping.usage)
		encoded, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		response := performIAMRequestWithSubject(handler, encoded, paasCredential, platformActor)
		var decision iamv1.AuthorizationDecision
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &decision) != nil || !decision.Allowed || decision.Subject == nil || decision.InstallationID != "installation-http-integration" {
			t.Fatalf("platform action lacks real authority: %s status=%d", mapping.action, response.Code)
		}
		event := auditv1.Event{APIVersion: auditv1.APIVersion, Kind: "AuditEvent", EventID: auditv1.EventID("event-" + string(decision.ID)),
			InstallationID: decision.InstallationID, Actor: auditv1.ActorReference{Type: auditv1.ActorUser, ID: auditv1.ActorID(decision.Subject.ID)},
			IAMDecisionID: auditv1.DecisionID(decision.ID), Action: mapping.fact, Target: auditv1.TargetReference{Kind: auditv1.TargetExecutionTarget, ID: "execution-target-proof"},
			Result: auditv1.ResultSucceeded, RequestDigest: "sha256:" + strings.Repeat("a", 64), RequestID: request.RequestID, CorrelationID: request.CorrelationID,
			OperationID: "operation-platform-proof", OccurredAt: decision.DecidedAt.Add(time.Microsecond)}
		resolve(paasCredential, event, http.StatusOK)
		for _, attack := range []func(*auditv1.Event){
			func(e *auditv1.Event) { e.RequestID = "request-forged" },
			func(e *auditv1.Event) { e.CorrelationID = "correlation-forged" },
			func(e *auditv1.Event) { e.InstallationID = "installation-forged" },
			func(e *auditv1.Event) { e.Actor.ID = "principal-forged" },
		} {
			forged := event
			attack(&forged)
			resolve(paasCredential, forged, http.StatusForbidden)
		}
		forged := event
		forged.Target.ID = "execution-target-other"
		if mapping.mode == iamv1.AuthorizationResourceCollection {
			// The source transaction, not this authority receipt, proves the final ID.
			resolve(paasCredential, forged, http.StatusOK)
			forged.Action = auditv1.ActionPaaSExecutionTargetRemoved
			resolve(paasCredential, forged, http.StatusForbidden)
		} else {
			resolve(paasCredential, forged, http.StatusForbidden)
		}
		resolve(verifierCredential, event, http.StatusForbidden)
		resolve(auditCredential, event, http.StatusForbidden)
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
	body := mustIAMJSON(t, profileBoundIAMRequest(t, iamv1.AuthorizationRequest{Action: iamv1.ActionPaaSExecutionTargetRegister, Resource: iamv1.ResourceReference{Kind: iamv1.ResourceExecutionTarget, ID: "target-example"}, RequestID: "request-node-register", CorrelationID: "request-node-register"}, iamv1.AuthorizationResourceInstance, ""))
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
