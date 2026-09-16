package authorityprocess

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	managedservicev1 "github.com/xiak/matrix/api/managedservice/v1"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
	auditmigration "github.com/xiak/matrix/app/service/audit/migration"
	iammigration "github.com/xiak/matrix/app/service/iam/migration"
	installationrelease "github.com/xiak/matrix/app/service/installation/release"
	paasmigration "github.com/xiak/matrix/app/service/paas/migration"
)

const (
	authorityProcessDSN = "MATRIX_AUTHORITY_PROCESS_POSTGRES_TEST_DSN"

	iamAPILogin       = "matrix_authority_process_iam_api"
	iamWorkerLogin    = "matrix_authority_process_iam_worker"
	auditRuntimeLogin = "matrix_authority_process_audit_runtime"
	paasAPILogin      = "matrix_authority_process_paas_api"
	paasWorkerLogin   = "matrix_authority_process_paas_worker"
	processDBPassword = "matrix-authority-process-test-only"

	initialAdminPassword     = "Initial-Process-Admin-Password-49!"
	changedAdminPassword     = "Changed-Process-Admin-Password-73!"
	initialReaderPassword    = "Initial-Process-Reader-Password-84!"
	changedReaderPassword    = "Changed-Process-Reader-Password-95!"
	initialDeveloperPassword = "Initial-Process-Developer-Password-57!"
	changedDeveloperPassword = "Changed-Process-Developer-Password-61!"

	iamServiceCredential   = "mx1.ProcessIAMServiceCredential00000000000000001"
	paasServiceCredential  = "mx1.ProcessPaaSServiceCredential0000000000000001"
	auditServiceCredential = "mx1.ProcessAuditServiceCredential000000000000001"
	verifierCredential     = "mx1.ProcessVerifierCredential0000000000000001"
)

func TestRuntimeDSNBindsLeastPrivilegeLogin(t *testing.T) {
	admin, err := pgx.ParseConfig("postgres://migration:admin-password@127.0.0.1:5432/matrix_authority_process_unit?sslmode=disable&user=postgres&password=query-admin")
	if err != nil {
		t.Fatal(err)
	}
	dsn := runtimeDSN(t, admin, paasAPILogin, "runtime-password-with-&?#-characters")
	parsed, err := pgxpool.ParseConfig(dsn)
	if err != nil || parsed.ConnConfig.User != paasAPILogin || parsed.ConnConfig.Password != "runtime-password-with-&?#-characters" || parsed.ConnConfig.Database != admin.Database || parsed.ConnConfig.Host != admin.Host || parsed.ConnConfig.Port != admin.Port || parsed.MaxConns != 2 || parsed.ConnConfig.RuntimeParams["application_name"] != "matrix-authority-process:"+paasAPILogin {
		t.Fatal("process DSN retained a migration credential or lost its bounded target")
	}
	if admin.User != "postgres" || admin.Password != "query-admin" {
		t.Fatal("runtime DSN mutated migration configuration")
	}
	direct, err := pgx.ParseConfig(localRecoveryMigrationDSN(t, dsn))
	if err != nil || direct.User != parsed.ConnConfig.User || direct.Password != parsed.ConnConfig.Password || direct.Host != admin.Host || direct.Port != admin.Port || direct.Database != admin.Database || direct.RuntimeParams["pool_max_conns"] != "" {
		t.Fatal("migration DSN changed its restricted identity or retained a pool-only server parameter")
	}
}

func TestIAMRetainedAccountProcessUpgrade(t *testing.T) {
	testIAMRetainedProcessUpgrade(t, "MATRIX_IAM_UPGRADE_POSTGRES_TEST_DSN", "9fd45b03ea398828fa3e74bf99961d2348c68299", false)
}

func TestIAMRetainedSessionProcessUpgrade(t *testing.T) {
	testIAMRetainedProcessUpgrade(t, "MATRIX_IAM_SESSION_UPGRADE_POSTGRES_TEST_DSN", "a36cf9817f522549b995ea9c1f0d873499b4fe62", true)
}

func TestIAMRetainedRoleCapabilityProcessUpgrade(t *testing.T) {
	const variable = "MATRIX_IAM_ROLE_PROFILE_UPGRADE_POSTGRES_TEST_DSN"
	dsn := os.Getenv(variable)
	if dsn == "" {
		t.Skipf("set %s to a clean disposable PostgreSQL 18 database", variable)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	config, err := pgx.ParseConfig(dsn)
	if err != nil || !strings.HasPrefix(config.Database, "matrix_iam_upgrade_roles_") {
		t.Fatal("role capability predecessor requires its own disposable database")
	}
	config.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	admin, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal("connect role capability predecessor database")
	}
	defer admin.Close(context.Background())
	assertPostgres18(t, ctx, admin)
	assertCleanSchemas(t, ctx, admin)
	root, temporary := repositoryRoot(t), t.TempDir()
	// This accepted R1 executable actually publishes USER-only compiled
	// policies. It is a distinct interpretation boundary from IAM21's author
	// documents, not a replay of every unpublished development migration.
	baseline := extractFixedIAMSource(t, ctx, root, temporary, "d45402d91c89a5bb23f52fcfde65491435cd0f55")
	oldMigrator := buildAuthorityBinary(t, ctx, baseline, temporary, "matrix-iam-role-r1-migrate", "./app/service/iam/cmd/matrix-iam-migrate")
	oldBinary := buildAuthorityBinary(t, ctx, baseline, temporary, "matrix-iam-role-r1", "./app/service/iam/cmd/matrix-iam")
	currentBinary := buildAuthorityBinary(t, ctx, root, temporary, "matrix-iam-role-r2", "./app/service/iam/cmd/matrix-iam")
	apiDSN := runtimeDSN(t, config, "matrix_iam_api_login", processDBPassword)
	migrationEnvironment := []string{}
	for _, value := range []struct{ name, dsn string }{
		{"MATRIX_MIGRATION_DATABASE_DSN_FILE", dsn},
		{"MATRIX_MIGRATION_IAM_API_DSN_FILE", localRecoveryMigrationDSN(t, apiDSN)},
		{"MATRIX_MIGRATION_IAM_WORKER_DSN_FILE", localRecoveryMigrationDSN(t, runtimeDSN(t, config, "matrix_iam_worker_login", processDBPassword))},
		{"MATRIX_MIGRATION_IAM_RECOVERY_DSN_FILE", localRecoveryMigrationDSN(t, runtimeDSN(t, config, localRecoveryProcessLogin, processDBPassword))},
	} {
		migrationEnvironment = append(migrationEnvironment, value.name+"="+writeProtectedFile(t, temporary, value.name, []byte(value.dsn)))
	}
	var children []*childProcess
	sensitive := []string{initialAdminPassword, changedAdminPassword, processDBPassword}
	defer func() {
		for _, child := range children {
			child.stop()
		}
		assertProcessOutputsSanitized(t, children, sensitive...)
	}()
	for _, action := range []string{"apply", "verify"} {
		child := startChild(t, baseline, oldMigrator, migrationEnvironment, action)
		children = append(children, child)
		if err := child.wait(30 * time.Second); err != nil {
			t.Fatal("actual R1 migrator failed")
		}
	}
	bootstrap, err := iamv1.EncodeBootstrapDocument(processBootstrap(t))
	if err != nil {
		t.Fatal(err)
	}
	bootstrapPath := writeProtectedFile(t, temporary, "iam-bootstrap", bootstrap)
	clear(bootstrap)
	address := freeAddress(t)
	endpoint := "http://" + address
	environment := []string{"MATRIX_IAM_DATABASE_DSN_FILE=" + writeProtectedFile(t, temporary, "iam-api-dsn", []byte(apiDSN)),
		"MATRIX_IAM_BOOTSTRAP_FILE=" + bootstrapPath, "MATRIX_IAM_LISTEN_ADDRESS=" + address,
		"MATRIX_IAM_CURSOR_KEY_FILE=" + writeProtectedFile(t, temporary, "iam-cursor-key", []byte(strings.Repeat("36", 32)))}
	start := func(binary string) *childProcess {
		child := startChild(t, root, binary, environment)
		children = append(children, child)
		waitHTTPStatus(t, ctx, child, endpoint+"/ready", http.StatusOK)
		assertRuntimeProcessLogins(t, ctx, admin, "matrix_iam_api_login")
		return child
	}
	old := start(oldBinary)
	primary := loginIAM(t, endpoint, "admin", initialAdminPassword, "role-profile-login")
	changePasswordIAM(t, endpoint, primary.Credential, initialAdminPassword, changedAdminPassword, "role-profile-password")
	sensitive = append(sensitive, primary.Credential)
	call := func(method, path string, body any, want int, result any) {
		t.Helper()
		response := performJSON(t, method, endpoint+path, primary.Credential, body)
		if response.Status != want || result != nil && json.Unmarshal(response.Body, result) != nil {
			t.Fatalf("retained role capability %s %s status=%d want=%d", method, path, response.Status, want)
		}
	}
	var role iamv1.Role
	call(http.MethodPost, "/v1/roles", iamv1.CreateRoleRequest{Name: "Retained USER-only role grant", Tags: []iamv1.RoleTag{}, RequestID: "role-profile-create",
		TrustPolicy: iamv1.TrustPolicyDocument{LanguageVersion: "1", Statements: []iamv1.TrustPolicyStatement{{SID: "root", Effect: iamv1.PolicyAllow,
			Principals: []iamv1.TrustPrincipal{{Type: iamv1.PrincipalUser, ID: "principal-admin"}}}}}}, http.StatusCreated, &role)
	var frozen iamv1.PolicyDetail
	call(http.MethodGet, "/v1/policies/"+string(iamv1.SystemPolicyPaaSViewer), nil, http.StatusOK, &frozen)
	if iamv1.ValidatePolicyDetail(frozen) != nil || frozen.Version.ContractVersion != 2 || frozen.Version.Compilation == nil {
		t.Fatal("actual R1 did not provide a compiled policy")
	}
	var reference iamv1.AuthorizationProfileReference
	for _, candidate := range frozen.Version.Compilation.Profiles {
		if candidate.Product == iamv1.ProductPaaS {
			reference = candidate
		}
	}
	if reference.Product != iamv1.ProductPaaS {
		t.Fatal("actual R1 compilation has no PaaS declaration")
	}
	var archive string
	if err := admin.QueryRow(ctx, `SELECT canonical_document FROM iam.authorization_profiles WHERE product=$1 AND revision=$2 AND content_digest=$3`, reference.Product, reference.Revision, reference.ContentDigest).Scan(&archive); err != nil {
		t.Fatal("read actual R1 frozen profile", err)
	}
	declaration, err := iamv1.DecodeAuthorizationProfile(strings.NewReader(archive))
	if err != nil || iamv1.CheckAuthorizationProfileSubject(declaration, reference, iamv1.ActionPaaSApplicationRead, iamv1.SubjectUser) != nil ||
		iamv1.CheckAuthorizationProfileSubject(declaration, reference, iamv1.ActionPaaSApplicationRead, iamv1.SubjectRole) == nil {
		t.Fatal("R1 fixture is not a proven USER-only compilation")
	}
	var attachment iamv1.PolicyAttachment
	call(http.MethodPost, "/v1/policy-attachments", iamv1.CreatePolicyAttachmentRequest{Target: iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetRole, ID: string(role.ID)},
		PolicyID: frozen.Policy.ID, PolicyResourceVersion: frozen.Policy.ResourceVersion, RequestID: "role-profile-attach-frozen"}, http.StatusOK, &attachment)
	createIAMPolicyAttachment(t, endpoint, primary.Credential, "principal-admin", frozen.Policy.ID, "role-profile-attach-old-user")
	old.stop()
	for range 2 {
		if err := iammigration.Up(ctx, admin); err != nil {
			t.Fatal("upgrade real R1 role capability data", err)
		}
		if err := iammigration.Verify(ctx, admin); err != nil {
			t.Fatal("verify role capability schema", err)
		}
	}
	current := start(currentBinary)
	rolePath := "/v1/roles/" + string(role.ID)
	call(http.MethodPost, rolePath+":assume", iamv1.AssumeRoleRequest{ResourceVersion: role.ResourceVersion, RequestID: "role-profile-implicit-assume"}, http.StatusForbidden, nil)
	var management iamv1.PolicyDetail
	call(http.MethodPost, "/v1/policies", iamv1.CreatePolicyRequest{DisplayName: "Explicit current STS management", RequestID: "role-profile-management",
		Document: iamv1.PolicyDocument{LanguageVersion: "1", Scope: iamv1.AuthorityScopeTenant, Statements: []iamv1.PolicyStatement{{SID: "sts", Effect: iamv1.PolicyAllow,
			Actions: []iamv1.Action{iamv1.ActionIAMRoleAssume, iamv1.ActionIAMRolePermissionBoundarySet}, Resources: []iamv1.PolicyResourceSelector{{Kind: iamv1.ResourceRole, Match: iamv1.PolicyResourceAnyInAuthority}}}}}}, http.StatusCreated, &management)
	createIAMPolicyAttachment(t, endpoint, primary.Credential, "principal-admin", management.Policy.ID, "role-profile-management-attach")
	var replacement iamv1.PolicyDetail
	call(http.MethodPost, "/v1/policies", iamv1.CreatePolicyRequest{DisplayName: "Explicit current ROLE business", Document: frozen.Version.Document, RequestID: "role-profile-recompile"}, http.StatusCreated, &replacement)
	var boundary iamv1.RolePermissionBoundary
	call(http.MethodPut, rolePath+"/permission-boundary", iamv1.SetRolePermissionBoundaryRequest{PolicyID: replacement.Policy.ID, PolicyResourceVersion: replacement.Policy.ResourceVersion,
		ResourceVersion: role.ResourceVersion, RequestID: "role-profile-boundary"}, http.StatusOK, &boundary)
	issue := func(id string) (iamv1.AssumeRoleResponse, string) {
		t.Helper()
		var access iamv1.RoleAccess
		call(http.MethodGet, rolePath, nil, http.StatusOK, &access)
		var issued iamv1.AssumeRoleResponse
		call(http.MethodPost, rolePath+":assume", iamv1.AssumeRoleRequest{ResourceVersion: access.Role.ResourceVersion, RequestID: id}, http.StatusOK, &issued)
		if iamv1.ValidateAssumeRoleResponse(issued) != nil || issued.Outcome != "APPLIED" {
			t.Fatal("retained role explicit issuance failed")
		}
		secret := issued.Credential.CopyBytes()
		token := string(secret)
		clear(secret)
		sensitive = append(sensitive, token)
		return issued, token
	}
	_, initialToken := issue("role-profile-issued-frozen")
	request, err := iamv1.NewAuthorizationRequest(iamv1.ActionPaaSApplicationRead, iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "retained-role-application"}, iamv1.AuthorizationResourceInstance, "", "role-profile-frozen-business", "role-profile-business")
	if err != nil {
		t.Fatal(err)
	}
	decide := func(token string, want int, allow bool) {
		t.Helper()
		response := performJSONWithHeaders(t, http.MethodPost, endpoint+"/v1/authorize", paasServiceCredential, "", request, map[string]string{"Matrix-Subject-Credential": token})
		var decision iamv1.AuthorizationDecision
		if response.Status != want || want == http.StatusOK && (json.Unmarshal(response.Body, &decision) != nil || iamv1.CheckAuthorizationDecisionForRequest(decision, request) != nil || decision.Allowed != allow) {
			t.Fatalf("frozen subject capability status=%d want=%d", response.Status, want)
		}
	}
	decide(initialToken, http.StatusServiceUnavailable, false)
	decide(primary.Credential, http.StatusOK, true) // The same old compilation remains valid for USER.
	// Merely adding a new Allow cannot erase an incompatible frozen source.
	call(http.MethodPost, "/v1/policy-attachments", iamv1.CreatePolicyAttachmentRequest{Target: iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetRole, ID: string(role.ID)},
		PolicyID: replacement.Policy.ID, PolicyResourceVersion: replacement.Policy.ResourceVersion, RequestID: "role-profile-attach-current"}, http.StatusOK, nil)
	_, mixedToken := issue("role-profile-issued-mixed")
	request.RequestID = "role-profile-mixed-business"
	decide(mixedToken, http.StatusServiceUnavailable, false)
	call(http.MethodPost, "/v1/policy-attachments/"+string(attachment.ID)+":revoke", iamv1.RevokePolicyAttachmentRequest{ResourceVersion: attachment.ResourceVersion, RequestID: "role-profile-revoke-frozen"}, http.StatusOK, nil)
	_, freshToken := issue("role-profile-issued-current")
	request.RequestID = "role-profile-explicit-business"
	decide(freshToken, http.StatusOK, true)
	decide(initialToken, http.StatusUnauthorized, false)
	decide(mixedToken, http.StatusUnauthorized, false)
	for restart := 0; restart < 2; restart++ {
		current.stop()
		if err := iammigration.Up(ctx, admin); err != nil {
			t.Fatal("replay role capability schema", err)
		}
		current = start(currentBinary)
		var retained iamv1.PolicyDetail
		call(http.MethodGet, "/v1/policies/"+string(frozen.Policy.ID), nil, http.StatusOK, &retained)
		if !reflect.DeepEqual(retained, frozen) {
			t.Fatal("new role capability changed old SYSTEM policy/default/compilation")
		}
		request.RequestID = fmt.Sprintf("role-profile-restart-%d", restart)
		decide(freshToken, http.StatusOK, true)
		decide(primary.Credential, http.StatusOK, true)
		decide(initialToken, http.StatusUnauthorized, false)
		decide(mixedToken, http.StatusUnauthorized, false)
	}
}

func TestIAMRetainedPolicyProcessUpgrade(t *testing.T) {
	const variable = "MATRIX_IAM_POLICY_UPGRADE_POSTGRES_TEST_DSN"
	dsn := os.Getenv(variable)
	if dsn == "" {
		t.Skipf("set %s to a clean disposable PostgreSQL 18 database", variable)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	config, err := pgx.ParseConfig(dsn)
	if err != nil || !strings.HasPrefix(config.Database, "matrix_iam_upgrade_") {
		t.Fatal("policy upgrade requires its own matrix_iam_upgrade_ database")
	}
	config.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	admin, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal("connect retained policy database")
	}
	defer admin.Close(context.Background())
	assertPostgres18(t, ctx, admin)
	assertCleanSchemas(t, ctx, admin)
	root, temporary := repositoryRoot(t), t.TempDir()
	// This is the explicit interpretation predecessor, not a claim that an
	// arbitrary pre-v1 database or an absent compilation proves its source.
	baseline := extractFixedIAMSource(t, ctx, root, temporary, "1dc1079c4e7bec80f5345d06929875b492ba9a86")
	oldMigrator := buildAuthorityBinary(t, ctx, baseline, temporary, "matrix-iam-schema21-migrate", "./app/service/iam/cmd/matrix-iam-migrate")
	oldBinary := buildAuthorityBinary(t, ctx, baseline, temporary, "matrix-iam-schema21", "./app/service/iam/cmd/matrix-iam")
	currentBinary := buildAuthorityBinary(t, ctx, root, temporary, "matrix-iam-compiled-policies", "./app/service/iam/cmd/matrix-iam")
	apiDSN := runtimeDSN(t, config, "matrix_iam_api_login", processDBPassword)
	workerDSN := runtimeDSN(t, config, "matrix_iam_worker_login", processDBPassword)
	recoveryDSN := runtimeDSN(t, config, localRecoveryProcessLogin, processDBPassword)
	migrationEnvironment := []string{}
	for _, value := range []struct{ name, dsn string }{
		{"MATRIX_MIGRATION_DATABASE_DSN_FILE", dsn},
		{"MATRIX_MIGRATION_IAM_API_DSN_FILE", localRecoveryMigrationDSN(t, apiDSN)},
		{"MATRIX_MIGRATION_IAM_WORKER_DSN_FILE", localRecoveryMigrationDSN(t, workerDSN)},
		{"MATRIX_MIGRATION_IAM_RECOVERY_DSN_FILE", localRecoveryMigrationDSN(t, recoveryDSN)},
	} {
		migrationEnvironment = append(migrationEnvironment, value.name+"="+writeProtectedFile(t, temporary, value.name, []byte(value.dsn)))
	}
	var children []*childProcess
	defer func() {
		for _, child := range children {
			child.stop()
		}
		assertProcessOutputsSanitized(t, children, initialAdminPassword, changedAdminPassword, initialReaderPassword, changedReaderPassword, processDBPassword)
	}()
	for _, action := range []string{"apply", "verify"} {
		child := startChild(t, baseline, oldMigrator, migrationEnvironment, action)
		children = append(children, child)
		if err := child.wait(30 * time.Second); err != nil {
			t.Fatal("actual fixed schema21 migrator failed")
		}
	}
	encoded, err := iamv1.EncodeBootstrapDocument(processBootstrap(t))
	if err != nil {
		t.Fatal(err)
	}
	bootstrapPath := writeProtectedFile(t, temporary, "iam-bootstrap.json", encoded)
	clear(encoded)
	address := freeAddress(t)
	endpoint := "http://" + address
	environment := []string{
		"MATRIX_IAM_DATABASE_DSN_FILE=" + writeProtectedFile(t, temporary, "iam-api-dsn", []byte(apiDSN)),
		"MATRIX_IAM_BOOTSTRAP_FILE=" + bootstrapPath, "MATRIX_IAM_LISTEN_ADDRESS=" + address,
		"MATRIX_IAM_CURSOR_KEY_FILE=" + writeProtectedFile(t, temporary, "iam-cursor-key", []byte(strings.Repeat("35", 32))),
	}
	start := func(binary string) *childProcess {
		child := startChild(t, root, binary, environment)
		children = append(children, child)
		waitHTTPStatus(t, ctx, child, endpoint+"/ready", http.StatusOK)
		assertRuntimeProcessLogins(t, ctx, admin, "matrix_iam_api_login")
		return child
	}
	old := start(oldBinary)
	// Requests sent to the actual predecessor must use its authenticated
	// declaration, not this test executable's newer ROLE-capable PaaS profile.
	// This is a test-only old-consumer boundary; current production admission
	// remains exact and never accepts a caller-selected old profile.
	var oldPaaSBytes, oldPaaSDigest string
	if err := admin.QueryRow(ctx, `SELECT canonical_document,content_digest FROM iam.authorization_profiles WHERE product='paas' AND revision=1`).Scan(&oldPaaSBytes, &oldPaaSDigest); err != nil {
		t.Fatal("read actual predecessor PaaS declaration", err)
	}
	oldPaaS, err := iamv1.DecodeAuthorizationProfile(strings.NewReader(oldPaaSBytes))
	if err != nil {
		t.Fatal("decode actual predecessor PaaS declaration", err)
	}
	oldPaaSReference := iamv1.AuthorizationProfileReference{Product: oldPaaS.Product, Revision: oldPaaS.Revision, ContentDigest: oldPaaSDigest}
	if iamv1.CheckAuthorizationProfileReference(oldPaaS, oldPaaSReference) != nil || oldPaaS.Product != iamv1.ProductPaaS {
		t.Fatal("predecessor declaration commitment is invalid")
	}
	checkOldDecision := func(decision iamv1.AuthorizationDecision, request iamv1.AuthorizationRequest) bool {
		return iamv1.CheckAuthorizationProfileTarget(oldPaaS, request.Profile, request.Action, request.Resource, request.ResourceMode, request.CollectionUsage) == nil &&
			iamv1.ValidateAuthorizationDecisionForProfile(decision, oldPaaS) == nil && decision.Profile != nil && *decision.Profile == request.Profile &&
			decision.Action == request.Action && decision.Resource == request.Resource && decision.ResourceMode == request.ResourceMode &&
			decision.CollectionUsage == request.CollectionUsage && decision.RequestID == request.RequestID && decision.CorrelationID == request.CorrelationID
	}
	primary := loginIAM(t, endpoint, "admin", initialAdminPassword, "policy-upgrade-primary-login")
	changePasswordIAM(t, endpoint, primary.Credential, initialAdminPassword, changedAdminPassword, "policy-upgrade-primary-change")
	keeper := createIAMUser(t, endpoint, primary.Credential, "retained.operator", "Retained platform operator", initialReaderPassword, "policy-upgrade-operator-create")
	keeperLogin := loginIAM(t, endpoint, "retained.operator@organization-process", initialReaderPassword, "policy-upgrade-operator-login")
	changePasswordIAM(t, endpoint, keeperLogin.Credential, initialReaderPassword, changedReaderPassword, "policy-upgrade-operator-change")
	createIAMPolicyAttachment(t, endpoint, primary.Credential, keeper.ID, iamv1.SystemPolicyPlatformOperator, "policy-upgrade-operator-grant")
	opened := performJSON(t, http.MethodPost, endpoint+"/v1/accounts", primary.Credential, map[string]any{
		"id": "retained-paused", "displayName": "Retained paused account", "rootLoginName": "retained.paused.root",
		"rootDisplayName": "Retained paused Root", "initialPassword": initialReaderPassword, "requestId": "policy-upgrade-paused-create",
	})
	var pausedAccount iamv1.Account
	if opened.Status != http.StatusCreated || json.Unmarshal(opened.Body, &pausedAccount) != nil || iamv1.ValidateAccount(pausedAccount) != nil {
		t.Fatal("old binary did not open the paused-account fixture")
	}
	pausedLogin := loginIAM(t, endpoint, "retained.paused.root", initialReaderPassword, "policy-upgrade-paused-login")
	changePasswordIAM(t, endpoint, pausedLogin.Credential, initialReaderPassword, changedReaderPassword, "policy-upgrade-paused-password")
	paused := performJSON(t, http.MethodPost, endpoint+"/v1/accounts/retained-paused:set-status", primary.Credential,
		iamv1.SetAccountStatusRequest{Status: iamv1.AccountDisabled, ResourceVersion: pausedAccount.ResourceVersion, RequestID: "policy-upgrade-paused-disable"})
	if paused.Status != http.StatusOK || json.Unmarshal(paused.Body, &pausedAccount) != nil || pausedAccount.Status != iamv1.AccountDisabled {
		t.Fatal("old binary did not explicitly pause the account")
	}
	user := createIAMUser(t, endpoint, primary.Credential, "retained.policy", "Retained policy user", initialReaderPassword, "policy-upgrade-user-create")
	member := loginIAM(t, endpoint, "retained.policy@organization-process", initialReaderPassword, "policy-upgrade-member-login")
	changePasswordIAM(t, endpoint, member.Credential, initialReaderPassword, changedReaderPassword, "policy-upgrade-member-change")
	active := createIAMPolicyAttachment(t, endpoint, primary.Credential, user.ID, iamv1.SystemPolicyPaaSViewer, "policy-upgrade-active-attachment")
	revoked := createIAMPolicyAttachment(t, endpoint, primary.Credential, user.ID, iamv1.SystemPolicyPaaSDeveloper, "policy-upgrade-revoked-attachment")
	revokeIAMPolicyAttachment(t, endpoint, primary.Credential, revoked.ID, revoked.ResourceVersion, "policy-upgrade-attachment-revoke")
	revokeIAMPolicyAttachment(t, endpoint, primary.Credential, "bootstrap-platform-operator-binding", 1, "policy-upgrade-platform-revoke")
	retired := loginIAM(t, endpoint, "retained.policy@organization-process", changedReaderPassword, "policy-upgrade-retired-login")
	revokeIAMSession(t, endpoint, primary.Credential, retired.Session.ID, "policy-upgrade-session-revoke")
	assertViewerCeiling := func(stage string) {
		t.Helper()
		for _, mode := range []iamv1.AuthorizationResourceMode{iamv1.AuthorizationResourceInstance, iamv1.AuthorizationResourceCollection} {
			action, usage, resourceID, allowed := iamv1.ActionPaaSApplicationRead, iamv1.AuthorizationCollectionUsage(""), "retained-selected", true
			if mode == iamv1.AuthorizationResourceCollection {
				action, usage, resourceID, allowed = iamv1.ActionPaaSApplicationCreate, iamv1.AuthorizationCollectionCreate, "collection", false
			}
			id := "retained-viewer-" + stage + "-" + string(mode)
			request, err := iamv1.NewAuthorizationRequest(action, iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: resourceID}, mode, usage, id, id)
			if err != nil {
				t.Fatal(err)
			}
			if stage == "old" {
				request.Profile = oldPaaSReference
			}
			response := performJSONWithHeaders(t, http.MethodPost, endpoint+"/v1/authorize", paasServiceCredential, "", request, map[string]string{"Matrix-Subject-Credential": member.Credential})
			var decision iamv1.AuthorizationDecision
			valid := response.Status == http.StatusOK && json.Unmarshal(response.Body, &decision) == nil
			if stage == "old" {
				valid = valid && checkOldDecision(decision, request)
			} else {
				valid = valid && iamv1.CheckAuthorizationDecisionForRequest(decision, request) == nil
			}
			if !valid || decision.Allowed != allowed {
				t.Fatal("fixed SYSTEM read/create ceiling changed across cutover")
			}
			if allowed && (decision.Subject == nil || decision.Subject.ID != string(user.ID) || decision.TenantID != user.AccountID) {
				t.Fatal("fixed SYSTEM allowance changed its authenticated tenant/subject")
			}
		}
		if stage != "old" {
			assertPlatformAuthorization(t, endpoint, member.Credential, string(user.ID), "retained-viewer-platform-"+stage, false)
		} else {
			for index, action := range oldPaaS.Actions {
				if action.Scope != iamv1.AuthorityScopeInstallation {
					continue
				}
				for shapeIndex, shape := range action.ResourceShapes {
					resourceID := "retained-platform-resource"
					if shape.Mode == iamv1.AuthorizationResourceCollection {
						resourceID = "collection"
					}
					id := fmt.Sprintf("retained-old-platform-%d-%d", index, shapeIndex)
					request := iamv1.AuthorizationRequest{Action: action.Action, Resource: iamv1.ResourceReference{Kind: action.ResourceKind, ID: resourceID},
						Profile: oldPaaSReference, ResourceMode: shape.Mode, CollectionUsage: shape.CollectionUsage, RequestID: id, CorrelationID: id}
					response := performJSONWithHeaders(t, http.MethodPost, endpoint+"/v1/authorize", paasServiceCredential, "", request, map[string]string{"Matrix-Subject-Credential": member.Credential})
					var decision iamv1.AuthorizationDecision
					if response.Status != http.StatusOK || json.Unmarshal(response.Body, &decision) != nil || !checkOldDecision(decision, request) || decision.Allowed {
						t.Fatal("actual predecessor granted platform authority to its viewer")
					}
				}
			}
		}
	}
	assertViewerCeiling("old")
	legacyRequest, err := iamv1.NewAuthorizationRequest(iamv1.ActionPaaSApplicationCreate,
		iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "collection"}, iamv1.AuthorizationResourceCollection,
		iamv1.AuthorizationCollectionCreate, "policy-upgrade-old-business", "policy-upgrade-old-business")
	if err != nil {
		t.Fatal(err)
	}
	// The fixed predecessor already binds its request/decision to Profile r1;
	// only its policy content is document-only. Do not strip current fields.
	legacyRequest.Profile = oldPaaSReference
	legacyResponse := performJSONWithHeaders(t, http.MethodPost, endpoint+"/v1/authorize", paasServiceCredential, "",
		legacyRequest,
		map[string]string{"Matrix-Subject-Credential": primary.Credential})
	var originalDecision iamv1.AuthorizationDecision
	if legacyResponse.Status != http.StatusOK || json.Unmarshal(legacyResponse.Body, &originalDecision) != nil ||
		!checkOldDecision(originalDecision, legacyRequest) || !originalDecision.Allowed || originalDecision.Subject == nil {
		t.Fatal("old binary did not issue an original business decision")
	}
	oldFact := auditv1.Event{APIVersion: auditv1.APIVersion, Kind: "AuditEvent", EventID: "policy-upgrade-old-business-event",
		TenantID: auditv1.TenantID(originalDecision.TenantID), Actor: auditv1.ActorReference{Type: auditv1.ActorUser, ID: auditv1.ActorID(originalDecision.Subject.ID)},
		IAMDecisionID: auditv1.DecisionID(originalDecision.ID), Action: auditv1.ActionPaaSApplicationCreated,
		Target: auditv1.TargetReference{Kind: auditv1.TargetApplication, ID: "policy-upgrade-old-app"}, Result: auditv1.ResultSucceeded,
		RequestDigest: "sha256:" + strings.Repeat("1", 64), RequestID: originalDecision.RequestID, CorrelationID: "policy-upgrade-old-business",
		OperationID: "policy-upgrade-old-operation", OccurredAt: originalDecision.DecidedAt.Add(time.Microsecond)}
	customer := createIAMUser(t, endpoint, primary.Credential, "retained.customer", "Retained customer user", initialReaderPassword, "policy-upgrade-customer-create")
	customerLogin := loginIAM(t, endpoint, "retained.customer@organization-process", initialReaderPassword, "policy-upgrade-customer-login")
	changePasswordIAM(t, endpoint, customerLogin.Credential, initialReaderPassword, changedReaderPassword, "policy-upgrade-customer-change")
	publication := iamv1.CreatePolicyRequest{DisplayName: "Retained author document", RequestID: "policy-upgrade-customer-policy",
		Document: iamv1.PolicyDocument{LanguageVersion: iamv1.PolicyLanguageVersion, Scope: iamv1.AuthorityScopeTenant,
			Statements: []iamv1.PolicyStatement{{SID: "selected", Effect: iamv1.PolicyAllow, Actions: []iamv1.Action{iamv1.ActionPaaSApplicationRead},
				Resources: []iamv1.PolicyResourceSelector{{Kind: iamv1.ResourceApplication, Match: iamv1.PolicyResourceExact, ID: "retained-selected"}}}}}}
	// Decode only this real predecessor's old wire shape in the test. The
	// current production decoder must reject missing contractVersion.
	var oldPolicy struct {
		Policy  iamv1.Policy    `json:"policy"`
		Version json.RawMessage `json:"version"`
	}
	response := performJSON(t, http.MethodPost, endpoint+"/v1/policies", primary.Credential, publication)
	if response.Status != http.StatusCreated || json.Unmarshal(response.Body, &oldPolicy) != nil || iamv1.ValidatePolicy(oldPolicy.Policy) != nil {
		t.Fatal("actual predecessor did not publish the customer document")
	}
	createIAMPolicyAttachment(t, endpoint, primary.Credential, customer.ID, oldPolicy.Policy.ID, "policy-upgrade-customer-attach")
	var inheritedGroup iamv1.Group
	response = performJSON(t, http.MethodPost, endpoint+"/v1/groups", primary.Credential, iamv1.CreateGroupRequest{Name: "Retained Root preflight group", RequestID: "policy-upgrade-group-create"})
	if response.Status != http.StatusCreated || json.Unmarshal(response.Body, &inheritedGroup) != nil || iamv1.ValidateGroup(inheritedGroup) != nil {
		t.Fatal("old binary did not create the retained group")
	}
	response = performJSON(t, http.MethodPost, endpoint+"/v1/policy-attachments", primary.Credential,
		iamv1.CreatePolicyAttachmentRequest{Target: iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetGroup, ID: string(inheritedGroup.ID)}, PolicyID: oldPolicy.Policy.ID,
			PolicyResourceVersion: oldPolicy.Policy.ResourceVersion, RequestID: "policy-upgrade-group-attach"})
	if response.Status != http.StatusOK {
		t.Fatal("old binary did not attach the retained group policy")
	}
	rootAttachment := createIAMPolicyAttachment(t, endpoint, primary.Credential, "principal-admin", oldPolicy.Policy.ID, "policy-upgrade-root-attach")
	old.stop()
	var originalVersions []string
	if err := admin.QueryRow(ctx, `SELECT array_agg(id ORDER BY id) FROM iam.policy_versions`).Scan(&originalVersions); err != nil {
		t.Fatal("read predecessor version identities")
	}
	// Only original content rows are compared: the migration may insert new
	// compiled SYSTEM versions, but never advance existing defaults or rewrite
	// old canonical bytes, evidence, credentials, attachments or receipts.
	snapshot := func() []byte {
		t.Helper()
		var state []byte
		if err := admin.QueryRow(ctx, `SELECT jsonb_build_object(
			'accounts',(SELECT jsonb_agg(to_jsonb(a) ORDER BY id) FROM iam.accounts a),
			'roots',(SELECT jsonb_agg(to_jsonb(r) ORDER BY account_id) FROM iam.account_roots r),
			'groups',(SELECT jsonb_agg(to_jsonb(g) ORDER BY tenant_id,id) FROM iam.groups g),
			'memberships',(SELECT jsonb_agg(to_jsonb(m) ORDER BY tenant_id,id) FROM iam.group_memberships m),
			'attachments',(SELECT jsonb_agg(to_jsonb(a) ORDER BY tenant_id,id) FROM iam.policy_attachments a),
			'policies',(SELECT jsonb_agg(to_jsonb(p) ORDER BY id) FROM iam.policies p),
			'versions',(SELECT jsonb_agg(to_jsonb(v)-'contract_version'-'compilation' ORDER BY policy_id,id) FROM iam.policy_versions v WHERE id=ANY($1::text[])),
			'receipt',(SELECT jsonb_agg(to_jsonb(r)) FROM iam.bootstrap_receipts r),
			'principals',(SELECT jsonb_agg(to_jsonb(p) ORDER BY tenant_id,id) FROM iam.principals p),
			'credentials',(SELECT jsonb_agg(to_jsonb(c) ORDER BY tenant_id,principal_id) FROM iam.user_credentials c),
			'sessions',(SELECT jsonb_agg(to_jsonb(s) ORDER BY tenant_id,id) FROM iam.sessions s),
			'decisions',(SELECT jsonb_agg(to_jsonb(d)-'subject_type'-'role_id'-'source_principal_id'-'role_evidence' ORDER BY tenant_id,id) FROM iam.authorization_decisions d),
			'outbox',(SELECT jsonb_agg(to_jsonb(e) ORDER BY tenant_id,event_id) FROM iam.audit_outbox e))`, originalVersions).Scan(&state); err != nil {
			t.Fatal("read retained policy authority")
		}
		return state
	}
	before := snapshot()
	assertUnchanged := func() {
		t.Helper()
		var originalShape bool
		if err := admin.QueryRow(ctx, `SELECT schema_version=21 AND NOT EXISTS(SELECT 1 FROM pg_attribute
			WHERE attrelid='iam.policy_versions'::regclass AND attname='contract_version' AND NOT attisdropped) FROM iam.readiness()`).Scan(&originalShape); err != nil || !originalShape || !bytes.Equal(before, snapshot()) {
			t.Fatal("rejected cutover changed schema, marker or original authority")
		}
	}
	if err := iammigration.Up(ctx, admin); err == nil {
		t.Fatal("Root legacy CUSTOMER attachment was accepted by cutover")
	}
	if _, err := admin.Exec(ctx, "ROLLBACK"); err != nil {
		t.Fatal("finish rejected Root cutover")
	}
	assertUnchanged()
	old = start(oldBinary)
	revokeIAMPolicyAttachment(t, endpoint, primary.Credential, rootAttachment.ID, rootAttachment.ResourceVersion, "policy-upgrade-root-detach")
	old.stop()
	before = snapshot()
	// Privileged corruption fixtures are negative tests, not reachable old API
	// states or evidence of legacy provenance. The old API forbids Root group
	// membership. Every temporary change and disabled trigger rolls back.
	for _, fixture := range []string{
		`ALTER TABLE iam.principals DISABLE TRIGGER USER;
		 UPDATE iam.principals SET status='DISABLED' WHERE tenant_id='organization-process' AND id='principal-admin'`,
		`ALTER TABLE iam.account_roots DISABLE TRIGGER USER;
		 DELETE FROM iam.account_roots WHERE account_id='organization-process'`,
		`ALTER TABLE iam.group_memberships DISABLE TRIGGER USER;
		 INSERT INTO iam.group_memberships(tenant_id,id,group_id,user_id,created_by,resource_version,created_at,updated_at)
		 SELECT 'organization-process','synthetic-root-membership',id,'principal-admin','principal-admin',1,transaction_timestamp(),transaction_timestamp()
		 FROM iam.groups WHERE tenant_id='organization-process' AND name='Retained Root preflight group'`,
	} {
		if _, err := admin.Exec(ctx, "BEGIN; "+fixture); err != nil {
			t.Fatal("install isolated invalid Root qualification")
		}
		if err := iammigration.Up(ctx, admin); err == nil {
			t.Fatal("invalid Root qualification crossed the cutover")
		}
		if _, err := admin.Exec(ctx, "ROLLBACK"); err != nil {
			t.Fatal("restore original Root qualification")
		}
		assertUnchanged()
	}
	var historicalEvidence bool
	if err := admin.QueryRow(ctx, "SELECT count(*)>0 AND bool_and(policy_evidence IS NOT NULL) FROM iam.authorization_decisions").Scan(&historicalEvidence); err != nil || !historicalEvidence {
		t.Fatal("old executable did not create real version-bound decisions")
	}
	if _, err := admin.Exec(ctx, `CREATE FUNCTION public.matrix_group_upgrade_fault() RETURNS event_trigger LANGUAGE plpgsql AS $body$
		BEGIN IF EXISTS(SELECT 1 FROM pg_event_trigger_ddl_commands() WHERE object_identity='iam.group_memberships')
		THEN RAISE EXCEPTION 'injected late group migration failure'; END IF; END $body$;
		CREATE EVENT TRIGGER matrix_group_upgrade_fault ON ddl_command_end EXECUTE FUNCTION public.matrix_group_upgrade_fault()`); err != nil {
		t.Fatal("install isolated late group migration fault")
	}
	if err := iammigration.Up(ctx, admin); err == nil {
		t.Fatal("injected group migration unexpectedly succeeded")
	}
	if _, err := admin.Exec(ctx, "ROLLBACK; DROP EVENT TRIGGER matrix_group_upgrade_fault; DROP FUNCTION public.matrix_group_upgrade_fault()"); err != nil {
		t.Fatal("finish isolated migration failure")
	}
	assertUnchanged()
	unmigrated := startChild(t, root, currentBinary, environment)
	children = append(children, unmigrated)
	if err := unmigrated.wait(10 * time.Second); err == nil || errors.Is(err, errProcessWaitTimeout) {
		t.Fatal("current IAM accepted an unmigrated policy database")
	}
	// Negative corruption fixture in this disposable database only. A real old
	// row missing required content must abort the entire cutover, not acquire a
	// legacy marker merely because its new wire fields are absent.
	for _, expression := range []string{"document-'languageVersion'", "jsonb_set(document,'{statements}','null'::jsonb)"} {
		if _, err := admin.Exec(ctx, `BEGIN; ALTER TABLE iam.policy_versions DISABLE TRIGGER policy_versions_are_immutable;
			ALTER TABLE iam.policy_versions DROP CONSTRAINT policy_versions_content_valid;
			UPDATE iam.policy_versions SET document=`+expression+` WHERE policy_id=$1`, oldPolicy.Policy.ID); err != nil {
			t.Fatal("install isolated incomplete old-policy fixture")
		}
		if err := iammigration.Up(ctx, admin); err == nil {
			t.Fatal("incomplete old policy was admitted as historical authority")
		}
		if _, err := admin.Exec(ctx, "ROLLBACK"); err != nil {
			t.Fatal("rollback incomplete old-decision fixture")
		}
		assertUnchanged()
	}
	for range 2 {
		if err := iammigration.Up(ctx, admin); err != nil {
			t.Fatalf("upgrade actual schema21 policy data: %v", err)
		}
		if err := iammigration.Verify(ctx, admin); err != nil {
			t.Fatalf("retained authority verification failed: %v", err)
		}
		after := snapshot()
		if !bytes.Equal(before, after) {
			var oldSections, newSections map[string]json.RawMessage
			if json.Unmarshal(before, &oldSections) != nil || json.Unmarshal(after, &newSections) != nil {
				t.Fatal("invalid retained authority snapshot")
			}
			for name, value := range oldSections {
				if !bytes.Equal(value, newSections[name]) {
					t.Errorf("migration changed retained authority section %s", name)
				}
			}
			t.Fatal("migration changed original authority; sensitive values are not logged")
		}
		var legacyOnly bool
		if err := admin.QueryRow(ctx, `SELECT count(*)>0 AND bool_and(contract_version=1 AND compilation IS NULL)
			FROM iam.policy_versions WHERE id=ANY($1::text[])`, originalVersions).Scan(&legacyOnly); err != nil || !legacyOnly {
			t.Fatal("retained original versions acquired fabricated compilation")
		}
		var originalSubjects bool
		if err := admin.QueryRow(ctx, `SELECT count(*)>0 AND bool_and(contract_version IN (1,2) AND principal_id IS NOT NULL
			 AND subject_type IS NULL AND role_id IS NULL AND source_principal_id IS NULL AND role_evidence IS NULL)
			 FROM iam.authorization_decisions`).Scan(&originalSubjects); err != nil || !originalSubjects {
			t.Fatal("migration fabricated ROLE metadata or replaced original USER authority", err)
		}
	}
	obsolete := startChild(t, root, oldBinary, environment)
	children = append(children, obsolete)
	if err := obsolete.wait(10 * time.Second); err == nil || errors.Is(err, errProcessWaitTimeout) {
		t.Fatal("old document-only executable accepted compiled policy authority")
	}
	for restart := range 2 {
		current := start(currentBinary)
		assertViewerCeiling(fmt.Sprintf("current-%d", restart))
		proofResponse := performJSON(t, http.MethodPost, endpoint+"/v1/audit-producer:resolve", paasServiceCredential, iamv1.ResolveAuditProducerRequest{Event: oldFact})
		var proof iamv1.AuditProducerAuthorization
		_, expectedDigest, err := auditv1.CanonicalizeEvent(auditv1.SourcePaaS, oldFact)
		if err != nil || proofResponse.Status != http.StatusOK || json.Unmarshal(proofResponse.Body, &proof) != nil ||
			iamv1.ValidateAuditProducerAuthorization(proof) != nil || proof.ContentDigest != expectedDigest || proof.TenantID != originalDecision.TenantID {
			t.Fatal("retained original business proof was reinterpreted or lost after restart")
		}
		identityResponse := performJSON(t, http.MethodGet, endpoint+"/v1/auth/me", member.Credential, nil)
		var identity iamv1.CurrentIdentity
		if identityResponse.Status != http.StatusOK || json.Unmarshal(identityResponse.Body, &identity) != nil || iamv1.ValidateCurrentIdentity(identity) != nil ||
			len(identity.PolicySources) != 1 || identity.PolicySources[0].Kind != iamv1.PolicyGrantDirect || identity.PolicySources[0].Attachment.ID != active.ID {
			t.Fatal("retained session lost its exact direct source or revived revoked permission")
		}
		if response := performJSON(t, http.MethodGet, endpoint+"/v1/auth/me", retired.Credential, nil); response.Status != http.StatusUnauthorized {
			t.Fatal("upgrade or bootstrap restart revived a revoked session")
		}
		assertPlatformAuthorization(t, endpoint, primary.Credential, "principal-admin", "policy-upgrade-platform-denied", false)
		if response := performJSON(t, http.MethodGet, endpoint+"/v1/groups", primary.Credential, nil); response.Status != http.StatusOK {
			t.Fatal("fixed SYSTEM management ceiling became unreachable")
		}
		if response := performJSON(t, http.MethodGet, endpoint+"/v1/roles", primary.Credential, nil); response.Status != http.StatusForbidden {
			t.Fatal("new IAM profile silently granted retained Root the role directory")
		}
		if response := performJSON(t, http.MethodPost, endpoint+"/v1/roles", primary.Credential,
			iamv1.CreateRoleRequest{Name: "Unpublished role", Tags: []iamv1.RoleTag{}, TrustPolicy: iamv1.TrustPolicyDocument{LanguageVersion: "1", Statements: []iamv1.TrustPolicyStatement{}}, RequestID: fmt.Sprintf("retained-role-denied-%d", restart)}); response.Status != http.StatusForbidden {
			t.Fatal("retained Root bypassed current Role PDP")
		}
		if response := performJSON(t, http.MethodGet, endpoint+"/v1/auth/me", customerLogin.Credential, nil); response.Status != http.StatusServiceUnavailable {
			t.Fatal("unknown legacy CUSTOMER interpretation became current authority")
		}
		if response := performJSON(t, http.MethodGet, endpoint+"/v1/auth/me", pausedLogin.Credential, nil); response.Status != http.StatusUnauthorized {
			t.Fatal("cutover or restart implicitly enabled a paused account")
		}
		current.stop()
	}
	current := start(currentBinary)
	// A new product declaration never rewrites old SYSTEM defaults. The real
	// retained Root must publish and attach explicit current TENANT authority.
	var oldAdminDefault iamv1.PolicyVersionID
	if err := admin.QueryRow(ctx, "SELECT default_version_id FROM iam.policies WHERE id=$1", iamv1.SystemPolicyAccountAdministrator).Scan(&oldAdminDefault); err != nil {
		t.Fatal("read original SYSTEM default")
	}
	rolePolicyRequest := iamv1.CreatePolicyRequest{DisplayName: "Explicit retained role management", RequestID: "retained-role-policy",
		Document: iamv1.PolicyDocument{LanguageVersion: iamv1.PolicyLanguageVersion, Scope: iamv1.AuthorityScopeTenant, Statements: []iamv1.PolicyStatement{{SID: "roles", Effect: iamv1.PolicyAllow,
			Actions:   []iamv1.Action{iamv1.ActionIAMRoleList, iamv1.ActionIAMRoleCreate, iamv1.ActionIAMRoleRead, iamv1.ActionIAMRoleDelete},
			Resources: []iamv1.PolicyResourceSelector{{Kind: iamv1.ResourceAccount, Match: iamv1.PolicyResourceAnyInAuthority}, {Kind: iamv1.ResourceRole, Match: iamv1.PolicyResourceAnyInAuthority}}}}}}
	var rolePolicy iamv1.PolicyDetail
	response = performJSON(t, http.MethodPost, endpoint+"/v1/policies", primary.Credential, rolePolicyRequest)
	if response.Status != http.StatusCreated || json.Unmarshal(response.Body, &rolePolicy) != nil || iamv1.ValidatePolicyDetail(rolePolicy) != nil || rolePolicy.Policy.Scope != iamv1.AuthorityScopeTenant {
		t.Fatal("retained Root could not explicitly publish current Role authority")
	}
	roleGrant := createIAMPolicyAttachment(t, endpoint, primary.Credential, "principal-admin", rolePolicy.Policy.ID, "retained-role-attach")
	var role iamv1.Role
	roleCreate := iamv1.CreateRoleRequest{Name: "Explicit retained role", Tags: []iamv1.RoleTag{}, TrustPolicy: iamv1.TrustPolicyDocument{LanguageVersion: "1", Statements: []iamv1.TrustPolicyStatement{}}, RequestID: "retained-role-create"}
	response = performJSON(t, http.MethodPost, endpoint+"/v1/roles", primary.Credential, roleCreate)
	if response.Status != http.StatusCreated || json.Unmarshal(response.Body, &role) != nil || iamv1.ValidateRole(role) != nil {
		t.Fatal("explicit current TENANT grant did not permit retained Root role creation")
	}
	response = performJSON(t, http.MethodDelete, endpoint+"/v1/roles/"+string(role.ID), primary.Credential, iamv1.DeleteRoleRequest{ResourceVersion: role.ResourceVersion, RequestID: "retained-role-delete"})
	if response.Status != http.StatusOK {
		t.Fatal("retained Root could not explicitly delete its role")
	}
	revokeIAMPolicyAttachment(t, endpoint, primary.Credential, roleGrant.ID, roleGrant.ResourceVersion, "retained-role-revoke")
	current.stop()
	if err := iammigration.Up(ctx, admin); err != nil {
		t.Fatal("replay current schema with terminal role state", err)
	}
	current = start(currentBinary)
	if response := performJSON(t, http.MethodGet, endpoint+"/v1/roles", primary.Credential, nil); response.Status != http.StatusForbidden {
		t.Fatal("replay or restart revived revoked Role authority")
	}
	var retainedRoleState bool
	if err := admin.QueryRow(ctx, `SELECT (SELECT default_version_id=$1 FROM iam.policies WHERE id=$2)
		AND EXISTS(SELECT 1 FROM iam.roles WHERE tenant_id='organization-process' AND id=$3 AND deleted_at IS NOT NULL AND resource_version=2)
		AND EXISTS(SELECT 1 FROM iam.policy_attachments WHERE tenant_id='organization-process' AND id=$4 AND revoked_at IS NOT NULL AND resource_version=2)`,
		oldAdminDefault, iamv1.SystemPolicyAccountAdministrator, role.ID, roleGrant.ID).Scan(&retainedRoleState); err != nil || !retainedRoleState {
		t.Fatal("Role registration/replay changed SYSTEM default or terminal authority", err)
	}
	response = performJSON(t, http.MethodPost, endpoint+"/v1/accounts/retained-paused:set-status", keeperLogin.Credential,
		iamv1.SetAccountStatusRequest{Status: iamv1.AccountActive, ResourceVersion: pausedAccount.ResourceVersion, RequestID: "policy-upgrade-paused-enable"})
	if response.Status != http.StatusOK {
		t.Fatal("retained platform operator cannot explicitly resume the account")
	}
	resumedLogin := loginIAM(t, endpoint, "retained.paused.root", changedReaderPassword, "policy-upgrade-paused-resumed-login")
	resumedPublication := publication
	resumedPublication.RequestID = "policy-upgrade-resumed-root-publish"
	response = performJSON(t, http.MethodPost, endpoint+"/v1/policies", resumedLogin.Credential, resumedPublication)
	var resumedPolicy iamv1.PolicyDetail
	if response.Status != http.StatusCreated || json.Unmarshal(response.Body, &resumedPolicy) != nil || iamv1.ValidatePolicyDetail(resumedPolicy) != nil || resumedPolicy.Version.ContractVersion != 2 {
		t.Fatal("explicitly resumed Root cannot create a compiled policy")
	}
	var enableFacts int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM iam.audit_outbox WHERE event_document->>'action'='iam.account.enabled'
		AND event_document#>>'{target,id}'='retained-paused' AND event_document->>'requestId'='policy-upgrade-paused-enable'`).Scan(&enableFacts); err != nil || enableFacts != 1 {
		t.Fatal("explicit resume lost its single correlated lifecycle fact")
	}
	var retained iamv1.PolicyDetail
	response = performJSON(t, http.MethodGet, endpoint+"/v1/policies/"+string(oldPolicy.Policy.ID), primary.Credential, nil)
	if response.Status != http.StatusOK || json.Unmarshal(response.Body, &retained) != nil || iamv1.ValidatePolicyDetail(retained) != nil || retained.Version.ContractVersion != 1 || retained.Version.Compilation != nil {
		t.Fatal("Root cannot inspect original CUSTOMER content without authorizing it")
	}
	var published iamv1.PolicyVersionDetail
	response = performJSON(t, http.MethodPost, endpoint+"/v1/policies/"+string(oldPolicy.Policy.ID)+"/versions", primary.Credential,
		iamv1.CreatePolicyVersionRequest{Document: publication.Document, ResourceVersion: retained.Policy.ResourceVersion, RequestID: "policy-upgrade-explicit-publication"})
	if response.Status != http.StatusCreated || json.Unmarshal(response.Body, &published) != nil || iamv1.ValidatePolicyVersionDetail(published) != nil || published.Version.ContractVersion != 2 || published.Policy.DefaultVersionID != retained.Version.ID {
		t.Fatal("Root publication did not preserve the original default")
	}
	if response := performJSON(t, http.MethodGet, endpoint+"/v1/auth/me", customerLogin.Credential, nil); response.Status != http.StatusServiceUnavailable {
		t.Fatal("publication alone advanced legacy CUSTOMER authority")
	}
	response = performJSON(t, http.MethodPost, endpoint+"/v1/policies/"+string(oldPolicy.Policy.ID)+":set-default-version", primary.Credential,
		iamv1.SetDefaultPolicyVersionRequest{VersionID: published.Version.ID, ResourceVersion: published.Policy.ResourceVersion, RequestID: "policy-upgrade-explicit-default"})
	if response.Status != http.StatusOK {
		t.Fatal("Root cannot explicitly select the compiled version")
	}
	request, err := iamv1.NewAuthorizationRequest(iamv1.ActionPaaSApplicationRead, iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "retained-selected"},
		iamv1.AuthorizationResourceInstance, "", "policy-upgrade-selected", "policy-upgrade-selected")
	if err != nil {
		t.Fatal(err)
	}
	response = performJSONWithHeaders(t, http.MethodPost, endpoint+"/v1/authorize", paasServiceCredential, "", request, map[string]string{"Matrix-Subject-Credential": customerLogin.Credential})
	var selected iamv1.AuthorizationDecision
	if response.Status != http.StatusOK || json.Unmarshal(response.Body, &selected) != nil || iamv1.CheckAuthorizationDecisionForRequest(selected, request) != nil || !selected.Allowed {
		t.Fatal("explicitly selected compiled version did not authorize its resource")
	}
	proveFrozenFamilyProfileAdvance(t, ctx, admin, root, temporary, endpoint, primary.Credential, customerLogin.Credential,
		migrationEnvironment, start, current, oldFact)
	current.stop()
	t.Log("actual fixed IAM21 -> current compiled authority: original bytes/defaults/history retained; Root preflight and late rollback; unknown CUSTOMER remains closed until explicit publish and select")
}

// This is an independently built future-source fixture, not a mutable runtime
// catalog or a production PaaS action. The existing migrator registers its next revision;
// no test DML installs a head, version, attachment or authorization decision.
func proveFrozenFamilyProfileAdvance(t *testing.T, ctx context.Context, admin *pgx.Conn, root, temporary, endpoint, primary, member string,
	migrationEnvironment []string, start func(string) *childProcess, current *childProcess, originalFact auditv1.Event) {
	t.Helper()
	const addedAction iamv1.Action = "paas.application.inspect"
	profile, found := iamv1.LookupAuthorizationProfile(iamv1.ProductPaaS)
	if !found {
		t.Fatal("future-source fixture requires its explicit original PaaS revision")
	}
	originalRevision := profile.Revision
	originalProfile, _, err := iamv1.CanonicalizeAuthorizationProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	var added iamv1.AuthorizationProfileAction
	for index, action := range profile.Actions {
		if action.Action == iamv1.ActionPaaSApplicationRead {
			added = action
			profile.Actions[index].Conditions = nil
			for _, condition := range action.Conditions {
				if condition.Key != iamv1.ConditionIAMPrincipalID {
					profile.Actions[index].Conditions = append(profile.Actions[index].Conditions, condition)
				}
			}
		}
	}
	added.Action = addedAction
	profile.Revision++
	profile.Actions = append(profile.Actions, added)
	_, futureDigest, err := iamv1.CanonicalizeAuthorizationProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	futureReference := iamv1.AuthorizationProfileReference{Product: profile.Product, Revision: profile.Revision, ContentDigest: futureDigest}
	author := iamv1.PolicyDocument{LanguageVersion: iamv1.PolicyLanguageVersion, Scope: iamv1.AuthorityScopeTenant,
		Statements: []iamv1.PolicyStatement{{SID: "family", Effect: iamv1.PolicyAllow, Actions: []iamv1.Action{"paas.application.*"},
			Resources: []iamv1.PolicyResourceSelector{{Kind: iamv1.ResourceApplication, Match: iamv1.PolicyResourceExact, ID: "family-retained"}}}}}
	response := performJSON(t, http.MethodPost, endpoint+"/v1/policies", primary,
		iamv1.CreatePolicyRequest{DisplayName: "Frozen family", Document: author, RequestID: "family-profile-create"})
	var original iamv1.PolicyDetail
	if response.Status != http.StatusCreated || json.Unmarshal(response.Body, &original) != nil || iamv1.ValidatePolicyDetail(original) != nil {
		t.Fatal("original executable did not publish the real family version")
	}
	identityResponse := performJSON(t, http.MethodGet, endpoint+"/v1/auth/me", member, nil)
	var identity iamv1.CurrentIdentity
	if identityResponse.Status != http.StatusOK || json.Unmarshal(identityResponse.Body, &identity) != nil || iamv1.ValidateCurrentIdentity(identity) != nil {
		t.Fatal("retained family member identity unavailable")
	}
	attachment := createIAMPolicyAttachment(t, endpoint, primary, identity.User.ID, original.Policy.ID, "family-profile-attach")
	denyAuthor := iamv1.PolicyDocument{LanguageVersion: iamv1.PolicyLanguageVersion, Scope: iamv1.AuthorityScopeTenant,
		Statements: []iamv1.PolicyStatement{{SID: "nonmatching-deny", Effect: iamv1.PolicyDeny, Actions: []iamv1.Action{"paas.application.*"},
			Resources:  []iamv1.PolicyResourceSelector{{Kind: iamv1.ResourceApplication, Match: iamv1.PolicyResourceExact, ID: "different-family-resource"}},
			Conditions: []iamv1.PolicyCondition{{Key: iamv1.ConditionIAMPrincipalID, Operator: iamv1.PolicyStringEquals, Values: []string{string(identity.User.ID)}}}}}}
	response = performJSON(t, http.MethodPost, endpoint+"/v1/policies", primary,
		iamv1.CreatePolicyRequest{DisplayName: "Frozen nonmatching Deny", Document: denyAuthor, RequestID: "family-deny-create"})
	var frozenDeny iamv1.PolicyDetail
	if response.Status != http.StatusCreated || json.Unmarshal(response.Body, &frozenDeny) != nil || iamv1.ValidatePolicyDetail(frozenDeny) != nil {
		t.Fatal("original executable did not publish frozen nonmatching Deny")
	}
	originalVersionBytes, err := iamv1.CanonicalizePolicyVersion(original.Version)
	if err != nil {
		t.Fatal(err)
	}
	request, err := iamv1.NewAuthorizationRequest(iamv1.ActionPaaSApplicationRead,
		iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "family-retained"}, iamv1.AuthorizationResourceInstance, "", "family-before", "family-before")
	if err != nil {
		t.Fatal(err)
	}
	decide := func(profile iamv1.AuthorizationProfile, request iamv1.AuthorizationRequest, allowed bool) iamv1.AuthorizationDecision {
		t.Helper()
		response := performJSONWithHeaders(t, http.MethodPost, endpoint+"/v1/authorize", paasServiceCredential, "", request,
			map[string]string{"Matrix-Subject-Credential": member})
		var decision iamv1.AuthorizationDecision
		if response.Status != http.StatusOK || json.Unmarshal(response.Body, &decision) != nil ||
			iamv1.ValidateAuthorizationDecisionForProfile(decision, profile) != nil || decision.Profile == nil || *decision.Profile != request.Profile ||
			decision.Action != request.Action || decision.Resource != request.Resource || decision.ResourceMode != request.ResourceMode ||
			decision.RequestID != request.RequestID || decision.CorrelationID != request.CorrelationID || decision.Allowed != allowed {
			t.Fatalf("family source transition request %s: status=%d allowed=%v want=%v", request.RequestID, response.Status, decision.Allowed, allowed)
		}
		return decision
	}
	originalDeclaration, _ := iamv1.LookupAuthorizationProfile(iamv1.ProductPaaS)
	before := decide(originalDeclaration, request, true)
	var retainedDecision []byte
	if err := admin.QueryRow(ctx, "SELECT document FROM iam.authorization_decisions WHERE id=$1", before.ID).Scan(&retainedDecision); err != nil {
		t.Fatal(err)
	}
	// Go's overlay changes only this build's source declaration. The checked-out
	// catalog and all other executables retain the current revision; no runtime
	// selector is added, and archived declarations are not changed by the overlay.
	sourcePath := filepath.Join(root, "api/iam/v1/enums.go")
	source, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	const declaration = "\troleBusinessProfile(paasProfileRevisionOne),"
	if strings.Count(string(source), declaration) != 1 {
		t.Fatal("future source declaration anchor is not unique")
	}
	// The added action keeps the original capabilities; only read loses this
	// condition in the future build. Even a resource-nonmatching old Deny must
	// then fail closed, rather than disappear behind another Allow.
	replacement := fmt.Sprintf(`func() AuthorizationProfile {
		profile := roleBusinessProfile(paasProfileRevisionOne)
		profile.Revision = %d
		var added AuthorizationProfileAction
		for index, action := range profile.Actions {
			if action.Action == ActionPaaSApplicationRead {
				added = action
				profile.Actions[index].Conditions = nil
				for _, condition := range action.Conditions {
					if condition.Key != ConditionIAMPrincipalID { profile.Actions[index].Conditions = append(profile.Actions[index].Conditions, condition) }
				}
			}
		}
		added.Action = Action("paas.application.inspect")
		profile.Actions = append(profile.Actions, added)
		return profile
	}(),`, profile.Revision)
	futureSource := strings.Replace(string(source), declaration, replacement, 1)
	overlaySource := writeProtectedFile(t, temporary, "future-profile-enums.go", []byte(futureSource))
	overlayJSON, err := json.Marshal(map[string]any{"Replace": map[string]string{sourcePath: overlaySource}})
	if err != nil {
		t.Fatal(err)
	}
	overlay := writeProtectedFile(t, temporary, "future-profile-overlay.json", overlayJSON)
	build := func(name, packagePath string) string {
		t.Helper()
		if runtime.GOOS == "windows" {
			name += ".exe"
		}
		path := filepath.Join(temporary, name)
		command := exec.CommandContext(ctx, "go", "build", "-p", "2", "-overlay", overlay, "-o", path, packagePath)
		command.Dir = root
		command.Env = append(os.Environ(), "GOMAXPROCS=2", "GOMEMLIMIT=512MiB")
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("build future declaration consumer: %v\n%s", err, output)
		}
		return path
	}
	futureBinary := build("matrix-iam-future-profile", "./app/service/iam/cmd/matrix-iam")
	futureMigrator := build("matrix-iam-future-profile-migrate", "./app/service/iam/cmd/matrix-iam-migrate")
	current.stop()
	for _, action := range []string{"apply", "apply", "verify"} {
		child := startChild(t, root, futureMigrator, migrationEnvironment, action)
		err := child.wait(30 * time.Second)
		child.stop()
		assertProcessOutputsSanitized(t, []*childProcess{child}, processDBPassword)
		if err != nil {
			t.Fatalf("future-source migrator %s failed: %v", action, err)
		}
	}
	future := start(futureBinary)
	defer future.stop()
	assertOriginal := func() {
		t.Helper()
		var canonical, archive string
		var document []byte
		if err := admin.QueryRow(ctx, "SELECT canonical_document FROM iam.policy_versions WHERE policy_id=$1 AND id=$2", original.Policy.ID, original.Version.ID).Scan(&canonical); err != nil || canonical != originalVersionBytes {
			t.Fatal("future registration rewrote frozen policy bytes")
		}
		if err := admin.QueryRow(ctx, "SELECT canonical_document FROM iam.authorization_profiles WHERE product='paas' AND revision=$1", originalRevision).Scan(&archive); err != nil || archive != originalProfile {
			t.Fatal("future registration replaced original profile archive")
		}
		if err := admin.QueryRow(ctx, "SELECT document FROM iam.authorization_decisions WHERE id=$1", before.ID).Scan(&document); err != nil || !bytes.Equal(document, retainedDecision) {
			t.Fatal("future registration changed historical decision evidence")
		}
		proofResponse := performJSON(t, http.MethodPost, endpoint+"/v1/audit-producer:resolve", paasServiceCredential, iamv1.ResolveAuditProducerRequest{Event: originalFact})
		var proof iamv1.AuditProducerAuthorization
		_, expectedDigest, err := auditv1.CanonicalizeEvent(auditv1.SourcePaaS, originalFact)
		if err != nil || proofResponse.Status != http.StatusOK || json.Unmarshal(proofResponse.Body, &proof) != nil ||
			iamv1.ValidateAuditProducerAuthorization(proof) != nil || proof.ContentDigest != expectedDigest || string(proof.TenantID) != string(originalFact.TenantID) {
			t.Fatal("new head lost exact archived business proof")
		}
	}
	assertOriginal()
	request.RequestID = "family-old-online-protocol"
	response = performJSONWithHeaders(t, http.MethodPost, endpoint+"/v1/authorize", paasServiceCredential, "", request,
		map[string]string{"Matrix-Subject-Credential": member})
	var mismatchDecisions int
	if response.Status != http.StatusUnprocessableEntity {
		t.Fatalf("old online request was not a protocol mismatch: status=%d", response.Status)
	}
	if err := admin.QueryRow(ctx, "SELECT count(*) FROM iam.authorization_decisions WHERE request_id=$1", request.RequestID).Scan(&mismatchDecisions); err != nil || mismatchDecisions != 0 {
		t.Fatal("protocol mismatch became an ordinary policy DENY")
	}
	request.Profile, request.Action, request.RequestID, request.CorrelationID = futureReference, addedAction, "family-new-before-publication", "family-new-before-publication"
	decide(profile, request, false)
	request.Action, request.RequestID = iamv1.ActionPaaSApplicationRead, "family-old-after-registration"
	decide(profile, request, true)
	response = performJSON(t, http.MethodPost, endpoint+"/v1/policies/"+string(original.Policy.ID)+"/versions", primary,
		iamv1.CreatePolicyVersionRequest{Document: author, ResourceVersion: original.Policy.ResourceVersion, RequestID: "family-new-publish"})
	var published iamv1.PolicyVersionDetail
	if response.Status != http.StatusCreated || json.Unmarshal(response.Body, &published) != nil || iamv1.ValidatePolicyVersionDetail(published) != nil ||
		published.Policy.DefaultVersionID != original.Version.ID || published.Version.ContentDigest == original.Version.ContentDigest ||
		published.Version.Compilation == nil || len(published.Version.Compilation.Profiles) != 1 || published.Version.Compilation.Profiles[0] != futureReference {
		t.Fatalf("explicit future publication lost frozen/default contract: status=%d", response.Status)
	}
	if _, _, err := iamv1.CanonicalizePolicyCompilation(author, *published.Version.Compilation, []iamv1.AuthorizationProfile{profile}); err != nil {
		t.Fatal("future binary returned an incomplete expanded version", err)
	}
	request.Action, request.RequestID = addedAction, "family-new-published-not-selected"
	decide(profile, request, false)
	response = performJSON(t, http.MethodPost, endpoint+"/v1/policies/"+string(original.Policy.ID)+":set-default-version", primary,
		iamv1.SetDefaultPolicyVersionRequest{VersionID: published.Version.ID, ResourceVersion: published.Policy.ResourceVersion, RequestID: "family-new-select"})
	if response.Status != http.StatusOK {
		t.Fatal("explicit future default selection failed")
	}
	request.RequestID = "family-new-selected"
	decide(profile, request, true)
	future.stop()
	future = start(futureBinary)
	defer future.stop()
	request.RequestID = "family-new-after-restart"
	decide(profile, request, true)
	denyAttachment := createIAMPolicyAttachment(t, endpoint, primary, identity.User.ID, frozenDeny.Policy.ID, "family-deny-attach")
	request.Action, request.RequestID = iamv1.ActionPaaSApplicationRead, "family-incompatible-nonmatching-deny"
	response = performJSONWithHeaders(t, http.MethodPost, endpoint+"/v1/authorize", paasServiceCredential, "", request,
		map[string]string{"Matrix-Subject-Credential": member})
	if response.Status != http.StatusServiceUnavailable {
		t.Fatalf("incompatible nonmatching frozen Deny was skipped: status=%d", response.Status)
	}
	if err := admin.QueryRow(ctx, "SELECT count(*) FROM iam.authorization_decisions WHERE request_id=$1", request.RequestID).Scan(&mismatchDecisions); err != nil || mismatchDecisions != 0 {
		t.Fatal("incompatible frozen policy produced an ordinary decision")
	}
	revokeIAMPolicyAttachment(t, endpoint, primary, denyAttachment.ID, denyAttachment.ResourceVersion, "family-deny-revoke")
	request.RequestID = "family-after-incompatible-deny-revoke"
	decide(profile, request, true)
	revokeIAMPolicyAttachment(t, endpoint, primary, attachment.ID, attachment.ResourceVersion, "family-new-revoke")
	request.Action = addedAction
	request.RequestID = "family-new-after-revoke"
	decide(profile, request, false)
	assertOriginal()
	t.Log("source-built Profile r2: old family frozen; new publication does not select; explicit selection grants; restart/revocation hold; not a production PaaS inspect endpoint or release-upgrade gate")
}

func testIAMRetainedProcessUpgrade(t *testing.T, variable, fixedCommit string, qualifiedChild bool) {
	t.Helper()
	dsn := os.Getenv(variable)
	if dsn == "" {
		t.Skipf("set %s to a clean disposable PostgreSQL 18 database", variable)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	config, err := pgx.ParseConfig(dsn)
	if err != nil || !strings.HasPrefix(config.Database, "matrix_iam_upgrade_") {
		t.Fatal("IAM upgrade requires its own matrix_iam_upgrade_ database")
	}
	config.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	admin, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admin.Close(context.Background()) }()
	assertPostgres18(t, ctx, admin)
	assertCleanSchemas(t, ctx, admin)
	if err := iammigration.Bootstrap(ctx, admin); err != nil {
		t.Fatal(err)
	}
	root, temporary := repositoryRoot(t), t.TempDir()
	baselineRoot := extractFixedIAMSource(t, ctx, root, temporary, fixedCommit)
	migrations := []string{"000001_authority"}
	if qualifiedChild {
		migrations = append(migrations, "000003_tenant_accounts")
	}
	for _, migration := range migrations {
		oldSQL, err := os.ReadFile(filepath.Join(baselineRoot, "app/service/iam/internal/data/postgres/migrations", migration, "up.sql"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := admin.Exec(ctx, string(oldSQL)); err != nil {
			t.Fatalf("apply fixed retained IAM schema: %v", err)
		}
	}
	createProcessLogin(t, ctx, admin, iamAPILogin, "matrix_iam_api")
	oldBinary := buildAuthorityBinary(t, ctx, baselineRoot, temporary, "matrix-iam-baseline", "./app/service/iam/cmd/matrix-iam")
	currentBinary := buildAuthorityBinary(t, ctx, root, temporary, "matrix-iam-upgrade", "./app/service/iam/cmd/matrix-iam")
	bootstrapBytes, err := iamv1.EncodeBootstrapDocument(processBootstrap(t))
	if err != nil {
		t.Fatal(err)
	}
	bootstrapPath := writeProtectedFile(t, temporary, "iam-bootstrap.json", bootstrapBytes)
	clear(bootstrapBytes)
	dsnPath := writeProtectedFile(t, temporary, "iam-dsn", []byte(runtimeDSN(t, config, iamAPILogin, processDBPassword)))
	address := freeAddress(t)
	endpoint := "http://" + address
	environment := []string{"MATRIX_IAM_DATABASE_DSN_FILE=" + dsnPath, "MATRIX_IAM_BOOTSTRAP_FILE=" + bootstrapPath, "MATRIX_IAM_LISTEN_ADDRESS=" + address,
		"MATRIX_IAM_CURSOR_KEY_FILE=" + writeProtectedFile(t, temporary, "iam-cursor-key", []byte(strings.Repeat("35", 32)))}
	var children []*childProcess
	defer func() {
		for _, child := range children {
			child.stop()
		}
		assertProcessOutputsSanitized(t, children, initialAdminPassword, changedAdminPassword, initialReaderPassword, changedReaderPassword)
	}()
	start := func(binary string) *childProcess {
		child := startChild(t, root, binary, environment)
		children = append(children, child)
		waitHTTPStatus(t, ctx, child, endpoint+"/ready", http.StatusOK)
		assertRuntimeProcessLogins(t, ctx, admin, iamAPILogin)
		return child
	}
	old := start(oldBinary)
	oldChildLogin := "retained.viewer"
	if qualifiedChild {
		oldChildLogin += "@organization-process"
	}
	administrator := loginIAM(t, endpoint, "admin", initialAdminPassword, "request-upgrade-admin-login")
	changePasswordIAM(t, endpoint, administrator.Credential, initialAdminPassword, changedAdminPassword, "request-upgrade-admin-password")
	userID := createLegacyIAMUser(t, endpoint, administrator.Credential, "retained.viewer", "Retained viewer", initialReaderPassword, "request-upgrade-member")
	member := loginIAM(t, endpoint, oldChildLogin, initialReaderPassword, "request-upgrade-member-login")
	legacyTemporary := loginIAM(t, endpoint, oldChildLogin, initialReaderPassword, "request-upgrade-old-temporary")
	changePasswordIAM(t, endpoint, member.Credential, initialReaderPassword, changedReaderPassword, "request-upgrade-member-password")
	legacyCurrent := loginIAM(t, endpoint, oldChildLogin, changedReaderPassword, "request-upgrade-old-current")
	deleteCandidateID := createLegacyIAMUser(t, endpoint, administrator.Credential, "retained.deleted", "Retained deletion candidate", initialReaderPassword, "request-upgrade-delete-candidate")
	binding := putLegacyIAMBinding(t, endpoint, administrator.Credential, userID, legacyRolePaaSViewer, "request-upgrade-role")
	revokeLegacyIAMBinding(t, endpoint, administrator.Credential, binding.ID, "request-upgrade-role-revoke")
	revokeIAMSession(t, endpoint, administrator.Credential, member.Session.ID, "request-upgrade-session-revoke")
	revokeLegacyIAMBinding(t, endpoint, administrator.Credential, "bootstrap-platform-operator-binding", "request-upgrade-platform-revoke")
	old.stop()
	rows, err := admin.Query(ctx, "SELECT event_id,event_document FROM iam.audit_outbox")
	if err != nil {
		t.Fatal(err)
	}
	retained := map[string]auditv1.Event{}
	for rows.Next() {
		var id string
		var raw []byte
		var event auditv1.Event
		if rows.Scan(&id, &raw) != nil || json.Unmarshal(raw, &event) != nil {
			rows.Close()
			t.Fatal("decode retained IAM fact")
		}
		event.OccurredAt = event.OccurredAt.UTC()
		retained[id] = event
	}
	rows.Close()
	if rows.Err() != nil || len(retained) == 0 {
		t.Fatal("old installation has no retained facts")
	}
	unmigrated := startChild(t, root, currentBinary, environment)
	children = append(children, unmigrated)
	if err := unmigrated.wait(10 * time.Second); err == nil || errors.Is(err, errProcessWaitTimeout) {
		t.Fatal("current IAM served an unmigrated authority schema")
	}
	for attempt := 0; attempt < 2; attempt++ {
		if err := iammigration.Up(ctx, admin); err != nil {
			t.Fatalf("upgrade populated IAM: %v", err)
		}
		if err := iammigration.Verify(ctx, admin); err != nil {
			t.Fatal(err)
		}
	}
	var retainedUsersLive bool
	if err := admin.QueryRow(ctx, `SELECT count(*)=2 AND bool_and(deleted_at IS NULL)
		FROM iam.principals WHERE tenant_id='organization-process' AND id=ANY($1::text[])`,
		[]string{string(userID), string(deleteCandidateID)}).Scan(&retainedUsersLive); err != nil || !retainedUsersLive {
		t.Fatal("upgrade failed to preserve live legacy users as non-tombstoned identities")
	}
	current := start(currentBinary)
	// These rows were created by the actual old executable, not fabricated by
	// current-schema writes. Neither pre-change nor post-change timestamps prove
	// a credential epoch; both must require a new login after upgrade.
	for _, retainedSession := range []iamv1.Session{legacyTemporary.Session, legacyCurrent.Session} {
		var unboundActiveSession bool
		if err := admin.QueryRow(ctx, `SELECT credential_version IS NULL AND status='ACTIVE'
			FROM iam.sessions WHERE tenant_id=$1 AND id=$2`, retainedSession.AccountID, retainedSession.ID).Scan(&unboundActiveSession); err != nil || !unboundActiveSession {
			t.Fatal("migration filled an unproved epoch or lost the old executable's active-session fixture")
		}
	}
	retainedReaderPassword := changedReaderPassword
	var retainedNewSession string
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			current.stop()
			current = start(currentBinary)
		}
		for _, invalid := range []string{member.Credential, legacyTemporary.Credential, legacyCurrent.Credential, administrator.Credential} {
			if got := performJSON(t, http.MethodGet, endpoint+"/v1/auth/me", invalid, nil); got.Status != http.StatusUnauthorized {
				t.Fatal("upgrade/restart revived a revoked or unversioned legacy session")
			}
		}
		if retainedNewSession != "" {
			if got := performJSON(t, http.MethodGet, endpoint+"/v1/auth/me", retainedNewSession, nil); got.Status != http.StatusOK {
				t.Fatal("restart lost a valid credential-version-bound retained session")
			}
		}
		primary := loginIAM(t, endpoint, "admin", changedAdminPassword, "request-upgrade-retained-primary")
		identityResponse := performJSON(t, http.MethodGet, endpoint+"/v1/auth/me", primary.Credential, nil)
		var identity iamv1.CurrentIdentity
		if identityResponse.Status != http.StatusOK || json.Unmarshal(identityResponse.Body, &identity) != nil || identity.Account.RootIdentity.PrincipalID != "principal-admin" || identity.User.MustChangePassword {
			t.Fatal("upgrade replaced primary ownership or credentials")
		}
		detailResponse := performJSON(t, http.MethodGet, endpoint+"/v1/users/"+string(userID), primary.Credential, nil)
		var detail iamv1.UserAccess
		if detailResponse.Status != http.StatusOK || json.Unmarshal(detailResponse.Body, &detail) != nil || iamv1.ValidateUserAccess(detail) != nil || detail.User.ID != userID {
			t.Fatal("upgraded legacy user did not expose the current detail contract")
		}
		if attempt == 0 {
			updatedResponse := performJSON(t, http.MethodPost, endpoint+"/v1/users/"+string(userID)+":update", primary.Credential,
				iamv1.UpdateUserRequest{DisplayName: "Retained viewer upgraded", ResourceVersion: detail.User.ResourceVersion, RequestID: "request-upgrade-retained-profile"})
			var updated iamv1.User
			if updatedResponse.Status != http.StatusOK || json.Unmarshal(updatedResponse.Body, &updated) != nil || iamv1.ValidateUser(updated) != nil ||
				updated.ID != userID || updated.DisplayName != "Retained viewer upgraded" || updated.ResourceVersion != detail.User.ResourceVersion+1 {
				t.Fatal("current profile mutation did not operate on the retained legacy user")
			}
		} else if detail.User.DisplayName != "Retained viewer upgraded" {
			t.Fatal("migration replay or restart lost the retained user profile mutation")
		}
		if attempt == 0 {
			candidateResponse := performJSON(t, http.MethodGet, endpoint+"/v1/users/"+string(deleteCandidateID), primary.Credential, nil)
			var candidate iamv1.UserAccess
			if candidateResponse.Status != http.StatusOK || json.Unmarshal(candidateResponse.Body, &candidate) != nil || iamv1.ValidateUserAccess(candidate) != nil {
				t.Fatal("retained deletion candidate is unavailable after upgrade")
			}
			disabledResponse := performJSON(t, http.MethodPost, endpoint+"/v1/users/"+string(deleteCandidateID)+":set-status", primary.Credential,
				iamv1.SetUserStatusRequest{Status: iamv1.PrincipalDisabled, ResourceVersion: candidate.User.ResourceVersion, RequestID: "request-upgrade-retained-delete-disable"})
			var disabled iamv1.User
			if disabledResponse.Status != http.StatusOK || json.Unmarshal(disabledResponse.Body, &disabled) != nil || disabled.Status != iamv1.PrincipalDisabled {
				t.Fatal("retained deletion candidate could not be disabled")
			}
			deletedResponse := performJSON(t, http.MethodPost, endpoint+"/v1/users/"+string(deleteCandidateID)+":delete", primary.Credential,
				iamv1.DeleteUserRequest{ResourceVersion: disabled.ResourceVersion, RequestID: "request-upgrade-retained-delete"})
			var deletion iamv1.UserDeletion
			if deletedResponse.Status != http.StatusOK || json.Unmarshal(deletedResponse.Body, &deletion) != nil || iamv1.ValidateUserDeletion(deletion) != nil || deletion.ID != deleteCandidateID {
				t.Fatal("current deletion did not tombstone the retained legacy user")
			}
		}
		if got := performJSON(t, http.MethodGet, endpoint+"/v1/users/"+string(deleteCandidateID), primary.Credential, nil); got.Status != http.StatusForbidden {
			t.Fatal("deleted retained user became readable after migration replay or restart")
		}
		if got := performJSON(t, http.MethodPost, endpoint+"/v1/auth/login", "", map[string]any{
			"loginName": "retained.deleted@organization-process", "password": initialReaderPassword, "requestId": "request-upgrade-deleted-login",
		}); got.Status != http.StatusUnauthorized {
			t.Fatal("deleted retained user could authenticate after migration replay or restart")
		}
		var tombstoned bool
		var credentials, activeSessions, activeAttachments, deleteFacts int
		if err := admin.QueryRow(ctx, `SELECT principal.deleted_at IS NOT NULL,
			(SELECT count(*) FROM iam.user_credentials AS credential WHERE credential.tenant_id=principal.tenant_id AND credential.principal_id=principal.id),
			(SELECT count(*) FROM iam.sessions AS session WHERE session.tenant_id=principal.tenant_id AND session.principal_id=principal.id AND session.status='ACTIVE'),
			(SELECT count(*) FROM iam.policy_attachments AS attachment WHERE attachment.tenant_id=principal.tenant_id AND attachment.target_id=principal.id AND attachment.revoked_at IS NULL),
			(SELECT count(*) FROM iam.audit_outbox AS outbox WHERE outbox.tenant_id=principal.tenant_id AND outbox.event_document->>'action'='iam.user.deleted' AND outbox.event_document#>>'{target,id}'=principal.id)
			FROM iam.principals AS principal WHERE principal.tenant_id='organization-process' AND principal.id=$1`, deleteCandidateID).
			Scan(&tombstoned, &credentials, &activeSessions, &activeAttachments, &deleteFacts); err != nil || !tombstoned || credentials != 0 || activeSessions != 0 || activeAttachments != 0 || deleteFacts != 1 {
			t.Fatal("migration replay or restart revived retained user authority")
		}
		assertPlatformAuthorization(t, endpoint, primary.Credential, "principal-admin", "request-upgrade-platform-denied", false)
		child := loginIAM(t, endpoint, "retained.viewer@organization-process", retainedReaderPassword, "request-upgrade-retained-child")
		childResponse := performJSON(t, http.MethodGet, endpoint+"/v1/auth/me", child.Credential, nil)
		var childIdentity iamv1.CurrentIdentity
		if childResponse.Status != http.StatusOK || json.Unmarshal(childResponse.Body, &childIdentity) != nil || childIdentity.User.ID != userID || len(childIdentity.PolicySources) != 0 {
			t.Fatal("upgrade changed member identity or revived a revoked role")
		}
		if attempt == 0 {
			retainedNewSession = loginIAM(t, endpoint, "retained.viewer@organization-process", retainedReaderPassword, "request-upgrade-new-current").Credential
			retainedReaderPassword = "Retained-Session-Replacement-Password-68!"
			changed := performJSON(t, http.MethodPost, endpoint+"/v1/auth/password", child.Credential, map[string]any{
				"currentPassword": changedReaderPassword, "newPassword": retainedReaderPassword, "revokeOtherSessions": false, "requestId": "request-upgrade-retain-valid-sessions",
			})
			if changed.Status != http.StatusOK {
				t.Fatalf("retained legacy session password policy status=%d", changed.Status)
			}
			for _, invalid := range []string{member.Credential, legacyTemporary.Credential, legacyCurrent.Credential} {
				if got := performJSON(t, http.MethodGet, endpoint+"/v1/auth/me", invalid, nil); got.Status != http.StatusUnauthorized {
					t.Fatal("explicit false revived a revoked or unversioned legacy session")
				}
			}
			if got := performJSON(t, http.MethodGet, endpoint+"/v1/auth/me", retainedNewSession, nil); got.Status != http.StatusOK {
				t.Fatal("explicit false lost a valid credential-version-bound session")
			}
			if err := iammigration.Up(ctx, admin); err != nil {
				t.Fatal(err)
			}
			if err := iammigration.Verify(ctx, admin); err != nil {
				t.Fatal(err)
			}
		}
		serviceResponse := performJSON(t, http.MethodGet, endpoint+"/v1/service-identity", paasServiceCredential, nil)
		var service iamv1.ServiceIdentity
		if serviceResponse.Status != http.StatusOK || json.Unmarshal(serviceResponse.Body, &service) != nil || iamv1.ValidateServiceIdentity(service) != nil || service.InstallationID != "installation-process" {
			t.Fatal("upgraded service lost sealed installation")
		}
		for id, event := range retained {
			var raw []byte
			var stored auditv1.Event
			if err := admin.QueryRow(ctx, "SELECT event_document FROM iam.audit_outbox WHERE event_id=$1", id).Scan(&raw); err != nil || json.Unmarshal(raw, &stored) != nil {
				t.Fatal("upgrade lost IAM fact")
			}
			stored.OccurredAt = stored.OccurredAt.UTC()
			before, digest, beforeErr := auditv1.CanonicalizeEvent(auditv1.SourceIAM, event)
			after, _, afterErr := auditv1.CanonicalizeEvent(auditv1.SourceIAM, stored)
			if beforeErr != nil || afterErr != nil || before != after {
				t.Fatal("upgrade rewrote canonical IAM evidence")
			}
			proofResponse := performJSON(t, http.MethodPost, endpoint+"/v1/audit-producer:resolve", iamServiceCredential, iamv1.ResolveAuditProducerRequest{Event: event})
			var proof iamv1.AuditProducerAuthorization
			if proofResponse.Status != http.StatusOK || json.Unmarshal(proofResponse.Body, &proof) != nil || proof.ContentDigest != digest {
				t.Fatal("retained committed IAM fact cannot be delivered after upgrade")
			}
		}
	}
}

// This gate builds the accepted old executable from fixed Git objects in its
// own temporary directory. Old source is never a product/runtime dependency.
func extractFixedIAMSource(t *testing.T, ctx context.Context, root, temporary, fixedCommit string) string {
	t.Helper()
	command := exec.CommandContext(ctx, "git", "archive", "--format=zip", fixedCommit, "go.mod", "go.sum", "api", "app/service/iam", "app/service/internal")
	command.Dir = root
	archive, err := command.Output()
	if err != nil || len(archive) > 32<<20 {
		t.Fatal("cannot read bounded fixed IAM source archive")
	}
	reader, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(temporary, "iam-baseline")
	for _, entry := range reader.File {
		path := filepath.FromSlash(entry.Name)
		if !filepath.IsLocal(path) || entry.UncompressedSize64 > 8<<20 {
			t.Fatal("unsafe fixed source entry")
		}
		target := filepath.Join(destination, path)
		if entry.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o700); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			t.Fatal(err)
		}
		source, err := entry.Open()
		if err != nil {
			t.Fatal(err)
		}
		content, readErr := io.ReadAll(io.LimitReader(source, 8<<20))
		closeErr := source.Close()
		if readErr != nil || closeErr != nil {
			t.Fatal("cannot extract fixed source entry")
		}
		if err := os.WriteFile(target, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return destination
}

func TestIndependentIAMAuditAndPaaSProcesses(t *testing.T) {
	testIndependentAuthorityProcesses(t, false)
}

// This opt-in fixture is for observed browser acceptance, not an unattended
// substitute for TestIndependentIAMAuditAndPaaSProcesses or signed APISIX gates.
func TestIAMConsoleBrowser(t *testing.T) {
	if os.Getenv("MATRIX_IAM_CONSOLE_BROWSER") != "1" {
		t.Skip("set MATRIX_IAM_CONSOLE_BROWSER=1 for the bounded local browser fixture")
	}
	testIndependentAuthorityProcesses(t, true)
}

func testIndependentAuthorityProcesses(t *testing.T, browser bool) {
	dsn := os.Getenv(authorityProcessDSN)
	if dsn == "" {
		t.Skipf("set %s to a clean disposable PostgreSQL 18 database", authorityProcessDSN)
	}
	duration := 6 * time.Minute
	if browser {
		duration = 30 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()
	root := repositoryRoot(t)
	adminConfig, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse authority process DSN: %v", err)
	}
	if !strings.HasPrefix(adminConfig.Database, "matrix_authority_process_") {
		t.Fatalf("refusing authority process database %q", adminConfig.Database)
	}
	adminConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	admin, err := pgx.ConnectConfig(ctx, adminConfig)
	if err != nil {
		t.Fatalf("connect authority process database: %v", err)
	}
	defer func() { _ = admin.Close(context.Background()) }()
	assertPostgres18(t, ctx, admin)
	assertCleanSchemas(t, ctx, admin)
	applyPlatformSchemas(t, ctx, admin)
	createProcessLogins(t, ctx, admin)
	assertCrossSchemaIsolation(t, ctx, adminConfig)
	seedProcessExecutionProfile(t, ctx, adminConfig)

	temporary := t.TempDir()
	binaries := buildAuthorityBinaries(t, ctx, root, temporary)
	bootstrap := processBootstrap(t)
	bootstrapBytes, err := iamv1.EncodeBootstrapDocument(bootstrap)
	if err != nil {
		t.Fatalf("encode authority process bootstrap: %v", err)
	}
	bootstrapPath := writeProtectedFile(t, temporary, "iam-bootstrap.json", bootstrapBytes)
	clear(bootstrapBytes)
	changedBootstrap := bootstrap
	changedBootstrap.Organization.DisplayName = "Changed Organization"
	changedBytes, err := iamv1.EncodeBootstrapDocument(changedBootstrap)
	if err != nil {
		t.Fatalf("encode changed authority bootstrap: %v", err)
	}
	changedBootstrapPath := writeProtectedFile(t, temporary, "iam-bootstrap-changed.json", changedBytes)
	clear(changedBytes)
	iamDSNPath := writeProtectedFile(
		t,
		temporary,
		"iam-dsn",
		[]byte(runtimeDSN(t, adminConfig, iamAPILogin, processDBPassword)),
	)
	iamWorkerDSNPath := writeProtectedFile(
		t,
		temporary,
		"iam-worker-dsn",
		[]byte(runtimeDSN(t, adminConfig, iamWorkerLogin, processDBPassword)),
	)
	auditDSNPath := writeProtectedFile(
		t,
		temporary,
		"audit-dsn",
		[]byte(runtimeDSN(t, adminConfig, auditRuntimeLogin, processDBPassword)),
	)
	paasDSNPath := writeProtectedFile(
		t,
		temporary,
		"paas-dsn",
		[]byte(runtimeDSN(t, adminConfig, paasAPILogin, processDBPassword)),
	)
	paasWorkerDSNPath := writeProtectedFile(
		t,
		temporary,
		"paas-worker-dsn",
		[]byte(runtimeDSN(t, adminConfig, paasWorkerLogin, processDBPassword)),
	)
	auditCredentialPath := writeProtectedFile(
		t,
		temporary,
		"audit-service-credential",
		[]byte(auditServiceCredential),
	)
	iamCredentialPath := writeProtectedFile(
		t,
		temporary,
		"iam-service-credential",
		[]byte(iamServiceCredential),
	)
	paasCredentialPath := writeProtectedFile(
		t,
		temporary,
		"paas-service-credential",
		[]byte(paasServiceCredential),
	)
	wrongCredentialPath := writeProtectedFile(
		t,
		temporary,
		"wrong-iam-service-credential",
		[]byte("mx1.ProcessWrongIAMCredential000000000000000001"),
	)
	cursorKeyPath := writeProtectedFile(
		t,
		temporary,
		"audit-cursor-key",
		[]byte(hex.EncodeToString(bytes.Repeat([]byte{0x6a}, 32))),
	)
	iamCursorKeyPath := writeProtectedFile(t, temporary, "iam-cursor-key", []byte(strings.Repeat("35", 32)))

	iamAddress := freeAddress(t)
	auditAddress := freeAddress(t)
	paasAddress := freeAddress(t)
	iamDispatcherAddress := freeAddress(t)
	paasDispatcherAddress := freeAddress(t)
	iamEndpoint := "http://" + iamAddress
	auditEndpoint := "http://" + auditAddress
	paasEndpoint := "http://" + paasAddress
	iamEnvironment := []string{
		"MATRIX_IAM_DATABASE_DSN_FILE=" + iamDSNPath,
		"MATRIX_IAM_BOOTSTRAP_FILE=" + bootstrapPath,
		"MATRIX_IAM_LISTEN_ADDRESS=" + iamAddress,
		"MATRIX_IAM_CURSOR_KEY_FILE=" + iamCursorKeyPath,
	}
	auditEnvironment := []string{
		"MATRIX_AUDIT_DATABASE_DSN_FILE=" + auditDSNPath,
		"MATRIX_AUDIT_IAM_ENDPOINT=" + iamEndpoint,
		"MATRIX_AUDIT_SERVICE_CREDENTIAL_FILE=" + auditCredentialPath,
		"MATRIX_AUDIT_CURSOR_KEY_FILE=" + cursorKeyPath,
		"MATRIX_AUDIT_LISTEN_ADDRESS=" + auditAddress,
	}
	iamDispatcherEnvironment := func(credentialPath string, workerID string) []string {
		return []string{
			"MATRIX_IAM_AUDIT_DATABASE_DSN_FILE=" + iamWorkerDSNPath,
			"MATRIX_IAM_AUDIT_ENDPOINT=" + auditEndpoint,
			"MATRIX_IAM_AUDIT_CREDENTIAL_FILE=" + credentialPath,
			"MATRIX_IAM_AUDIT_WORKER_ID=" + workerID,
			"MATRIX_IAM_AUDIT_LISTEN_ADDRESS=" + iamDispatcherAddress,
		}
	}
	paasEnvironment := []string{
		"MATRIX_PAAS_DATABASE_DSN_FILE=" + paasDSNPath,
		"MATRIX_PAAS_IAM_ENDPOINT=" + iamEndpoint,
		"MATRIX_PAAS_SERVICE_CREDENTIAL_FILE=" + paasCredentialPath,
		"MATRIX_PAAS_LISTEN_ADDRESS=" + paasAddress,
		"MATRIX_PAAS_INSTALLATION_ID=" + bootstrap.InstallationID,
		"MATRIX_PAAS_RELEASE_ID=matrix-v0.1.0-process",
		"MATRIX_PAAS_VERIFICATION_ARTIFACT_DIGEST=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	paasDispatcherEnvironment := func(credentialPath string, workerID string) []string {
		return []string{
			"MATRIX_PAAS_AUDIT_DATABASE_DSN_FILE=" + paasWorkerDSNPath,
			"MATRIX_PAAS_AUDIT_ENDPOINT=" + auditEndpoint,
			"MATRIX_PAAS_AUDIT_CREDENTIAL_FILE=" + credentialPath,
			"MATRIX_PAAS_AUDIT_WORKER_ID=" + workerID,
			"MATRIX_PAAS_AUDIT_LISTEN_ADDRESS=" + paasDispatcherAddress,
		}
	}
	children := make([]*childProcess, 0)
	sensitive := []string{
		initialAdminPassword,
		changedAdminPassword,
		initialReaderPassword,
		changedReaderPassword,
		initialDeveloperPassword,
		changedDeveloperPassword,
		"Initial-Outage-User-Password-68!",
		"Initial-Dead-Letter-Password-79!",
		iamServiceCredential,
		paasServiceCredential,
		auditServiceCredential,
		"mx1.ProcessWrongIAMCredential000000000000000001",
		verifierCredential,
	}
	start := func(binary string, environment []string) *childProcess {
		child := startChild(t, root, binary, environment)
		children = append(children, child)
		return child
	}
	defer func() {
		for _, child := range children {
			child.stop()
		}
		assertProcessOutputsSanitized(t, children, sensitive...)
	}()

	iamProcess := start(binaries.iam, iamEnvironment)
	waitHTTPStatus(t, ctx, iamProcess, iamEndpoint+"/ready", http.StatusOK)
	iamProcess.stop()
	iamProcess = start(binaries.iam, iamEnvironment)
	waitHTTPStatus(t, ctx, iamProcess, iamEndpoint+"/ready", http.StatusOK)
	iamProcess.stop()
	changedEnvironment := append([]string(nil), iamEnvironment...)
	changedEnvironment[1] = "MATRIX_IAM_BOOTSTRAP_FILE=" + changedBootstrapPath
	changedProcess := start(binaries.iam, changedEnvironment)
	if err := changedProcess.wait(30 * time.Second); err == nil ||
		errors.Is(err, errProcessWaitTimeout) {
		t.Fatal("changed IAM bootstrap process succeeded")
	}
	iamProcess = start(binaries.iam, iamEnvironment)
	waitHTTPStatus(t, ctx, iamProcess, iamEndpoint+"/ready", http.StatusOK)
	assertIAMWeakLoginRejected(t, iamEndpoint)

	auditProcess := start(binaries.audit, auditEnvironment)
	waitHTTPStatus(t, ctx, auditProcess, auditEndpoint+"/ready", http.StatusOK)
	dispatcher := start(
		binaries.dispatcher,
		iamDispatcherEnvironment(iamCredentialPath, "iam-audit-worker-a"),
	)
	waitHTTPStatus(t, ctx, dispatcher, "http://"+iamDispatcherAddress+"/ready", http.StatusOK)
	waitAllIAMOutboxDelivered(t, ctx, admin)
	assertIAMEventsStoredOnce(t, ctx, admin)
	paasProcess := start(binaries.paas, paasEnvironment)
	waitHTTPStatus(t, ctx, paasProcess, paasEndpoint+"/ready", http.StatusOK)
	// This source tree intentionally leads the last accepted release profile.
	// Exercise the exact source services together without weakening install
	// admission: the workflow separately proves the published installer rejects
	// this unmatched database shape before effects.
	sourceProfile := installationrelease.AuthoritySchemas{IAM: 25, Audit: 15, PaaS: 2}
	publishedProfile := installationrelease.CurrentDatabaseProfile()
	if publishedProfile.Authorities == sourceProfile {
		t.Fatal("unreleased authority source shape was published without a final profile gate")
	}
	for _, authority := range []struct {
		name, endpoint string
		version        uint64
	}{
		{"IAM", iamEndpoint, sourceProfile.IAM},
		{"Audit", auditEndpoint, sourceProfile.Audit},
		{"PaaS", paasEndpoint, sourceProfile.PaaS},
	} {
		response := performJSON(t, http.MethodGet, authority.endpoint+"/ready", "", nil)
		var readiness struct {
			SchemaVersion uint64 `json:"schemaVersion"`
		}
		if response.Status != http.StatusOK || json.Unmarshal(response.Body, &readiness) != nil || readiness.SchemaVersion != authority.version {
			t.Fatalf("%s runtime schema=%d does not match source shape=%d (status=%d)", authority.name, readiness.SchemaVersion, authority.version, response.Status)
		}
	}
	paasDispatcher := start(
		binaries.paasDispatcher,
		paasDispatcherEnvironment(paasCredentialPath, "paas-audit-worker-a"),
	)
	waitHTTPStatus(t, ctx, paasDispatcher, "http://"+paasDispatcherAddress+"/ready", http.StatusOK)
	assertRuntimeProcessLogins(t, ctx, admin, iamAPILogin, iamWorkerLogin, auditRuntimeLogin, paasAPILogin, paasWorkerLogin)
	paasInstallationVerification := verifyPaaSInstallation(
		t,
		paasEndpoint,
		verifierCredential,
		paasv1.VerifyInstallationRequest{
			InstallationID: bootstrap.InstallationID,
			ReleaseID:      "matrix-v0.1.0-process",
		},
	)
	if paasInstallationVerification.State != paasv1.InstallationVerificationPending {
		t.Fatalf("fixed PaaS installation verification=%#v", paasInstallationVerification)
	}
	waitAllIAMOutboxDelivered(t, ctx, admin)
	waitAllPaaSOutboxDelivered(t, ctx, admin)
	auditInstallationVerification := verifyAuditInstallation(
		t,
		auditEndpoint,
		verifierCredential,
		auditv1.VerifyInstallationRequest{
			InstallationID: bootstrap.InstallationID,
			OperationID:    auditv1.OperationID(paasInstallationVerification.OperationID),
			DeploymentID:   string(paasInstallationVerification.DeploymentID),
		},
	)
	if auditInstallationVerification.State != auditv1.InstallationVerificationVerified ||
		auditInstallationVerification.OperationID != auditv1.OperationID(paasInstallationVerification.OperationID) ||
		auditInstallationVerification.DeploymentID != string(paasInstallationVerification.DeploymentID) {
		t.Fatalf("fixed Audit installation verification=%#v", auditInstallationVerification)
	}
	assertAuditAccessRecorded(t, ctx, admin, auditv1.ActionAuditIntegrityVerified, "service-verifier")

	adminLogin := loginIAM(t, iamEndpoint, "admin", initialAdminPassword, "request-admin-login")
	sensitive = append(sensitive, adminLogin.Credential)
	changePasswordIAM(
		t,
		iamEndpoint,
		adminLogin.Credential,
		initialAdminPassword,
		changedAdminPassword,
		"request-admin-password",
	)
	if browser {
		runIAMConsoleBrowser(t, ctx, admin, root, temporary, iamEndpoint, auditEndpoint, paasEndpoint, adminLogin.Credential, start)
		return
	}
	platformDecisions := []iamv1.AuthorizationDecision{
		assertPlatformAuthorization(t, iamEndpoint, adminLogin.Credential, "principal-admin", "request-platform-admin", true),
	}
	// A second real process uses its own bounded runtime login but the same
	// authoritative state. No sticky routing or in-memory session replication.
	const replicaLogin = "matrix_authority_process_iam_replica"
	createProcessLogin(t, ctx, admin, replicaLogin, "matrix_iam_api")
	replicaDSNPath := writeProtectedFile(t, temporary, "iam-replica-dsn", []byte(runtimeDSN(t, adminConfig, replicaLogin, processDBPassword)))
	replicaAddress := freeAddress(t)
	replicaEndpoint := "http://" + replicaAddress
	replicaProcess := start(binaries.iam, []string{
		"MATRIX_IAM_DATABASE_DSN_FILE=" + replicaDSNPath,
		"MATRIX_IAM_BOOTSTRAP_FILE=" + bootstrapPath,
		"MATRIX_IAM_LISTEN_ADDRESS=" + replicaAddress,
		"MATRIX_IAM_CURSOR_KEY_FILE=" + iamCursorKeyPath,
	})
	waitHTTPStatus(t, ctx, replicaProcess, replicaEndpoint+"/ready", http.StatusOK)
	assertRuntimeProcessLogins(t, ctx, admin, replicaLogin)
	platformDecisions = append(platformDecisions,
		assertPlatformAuthorization(t, replicaEndpoint, adminLogin.Credential, "principal-admin", "request-replica-existing-session", true))
	sensitive = append(sensitive, proveTenantAccountProcesses(t, ctx, admin, iamEndpoint, replicaEndpoint, auditEndpoint, paasEndpoint, adminLogin.Credential,
		func(admit func()) {
			auditProcess.stop()
			admit()
			auditProcess = start(binaries.audit, auditEnvironment)
			waitHTTPStatus(t, ctx, auditProcess, auditEndpoint+"/ready", http.StatusOK)
		}, func() {
			iamProcess.stop()
			iamProcess = start(binaries.iam, iamEnvironment)
			waitHTTPStatus(t, ctx, iamProcess, iamEndpoint+"/ready", http.StatusOK)
		})...)
	platformAuditRecord := ingestPlatformAuditFixture(t, auditEndpoint, platformDecisions[0])
	platformAuditRecords := []auditv1.AuditRecord{platformAuditRecord}
	for index, mapping := range []struct {
		action iamv1.Action
		fact   auditv1.Action
		mode   iamv1.AuthorizationResourceMode
		usage  iamv1.AuthorizationCollectionUsage
	}{
		{iamv1.ActionPaaSNodeEnrollmentCreate, auditv1.ActionPaaSExecutionTargetRegistered, iamv1.AuthorizationResourceCollection, iamv1.AuthorizationCollectionCreate},
		{iamv1.ActionPaaSExecutionTargetDrain, auditv1.ActionPaaSExecutionTargetDrained, iamv1.AuthorizationResourceInstance, ""},
		{iamv1.ActionPaaSExecutionTargetActivate, auditv1.ActionPaaSExecutionTargetActivated, iamv1.AuthorizationResourceInstance, ""},
		{iamv1.ActionPaaSExecutionTargetRemove, auditv1.ActionPaaSExecutionTargetRemoved, iamv1.AuthorizationResourceInstance, ""},
	} {
		kind, _ := iamv1.ResourceKindForAction(mapping.action)
		resource := iamv1.ResourceReference{Kind: kind, ID: "execution-target-process"}
		if mapping.mode == iamv1.AuthorizationResourceCollection {
			resource.ID = "collection"
		}
		decision := assertPlatformActionAuthorization(t, iamEndpoint, adminLogin.Credential, "principal-admin", fmt.Sprintf("platform-proof-%d", index), mapping.action, resource, mapping.mode, mapping.usage, true)
		event := platformAuditRecord.Event
		event.EventID, event.Action = auditv1.EventID(fmt.Sprintf("event-platform-proof-%d", index)), mapping.fact
		event.OperationID = auditv1.OperationID(fmt.Sprintf("operation-platform-proof-%d", index))
		event.IAMDecisionID, event.RequestID, event.CorrelationID, event.OccurredAt = auditv1.DecisionID(decision.ID), decision.RequestID, decision.RequestID, decision.DecidedAt
		platformAuditRecords = append(platformAuditRecords, ingestPlatformAuditEvent(t, auditEndpoint, event))
	}
	assertPlatformAuditAccess(t, auditEndpoint, adminLogin.Credential, http.StatusOK)
	waitAllIAMOutboxDelivered(t, ctx, admin)
	adminPage := queryAudit(t, auditEndpoint, adminLogin.Credential, auditv1.QueryRecordsRequest{PageSize: 200}, http.StatusOK)
	if adminPage.TenantID != "organization-process" || len(adminPage.Records) < 3 {
		t.Fatalf("administrator Audit page tenant=%s records=%d", adminPage.TenantID, len(adminPage.Records))
	}
	assertAuditQueryConfinement(t, auditEndpoint, adminLogin.Credential)
	developer := createIAMUser(
		t,
		iamEndpoint,
		adminLogin.Credential,
		"paas.developer",
		"PaaS Developer",
		initialDeveloperPassword,
		"request-create-developer",
	)
	developerBinding := createIAMPolicyAttachment(
		t,
		iamEndpoint,
		adminLogin.Credential,
		developer.ID,
		iamv1.SystemPolicyPaaSDeveloper,
		"request-bind-developer",
	)
	developerLogin := loginIAM(
		t,
		iamEndpoint,
		"paas.developer@organization-process",
		initialDeveloperPassword,
		"request-developer-login",
	)
	sensitive = append(sensitive, developerLogin.Credential)
	changePasswordIAM(
		t,
		iamEndpoint,
		developerLogin.Credential,
		initialDeveloperPassword,
		changedDeveloperPassword,
		"request-developer-password",
	)
	platformDecisions = append(platformDecisions,
		assertPlatformAuthorization(t, iamEndpoint, developerLogin.Credential, string(developer.ID), "request-platform-developer-denied", false),
	)
	assertPlatformAuditAccess(t, auditEndpoint, developerLogin.Credential, http.StatusForbidden)
	platformBinding := createIAMPolicyAttachment(t, replicaEndpoint, adminLogin.Credential, developer.ID,
		iamv1.SystemPolicyPlatformOperator, "request-bind-platform-operator")
	platformDecisions = append(platformDecisions,
		assertPlatformAuthorization(t, iamEndpoint, developerLogin.Credential, string(developer.ID), "request-platform-developer-granted", true),
	)
	assertPlatformAuditAccess(t, auditEndpoint, developerLogin.Credential, http.StatusOK)
	queryAudit(t, auditEndpoint, developerLogin.Credential, auditv1.QueryRecordsRequest{PageSize: 10}, http.StatusForbidden)
	revokeIAMPolicyAttachment(t, iamEndpoint, adminLogin.Credential, platformBinding.ID, 1, "request-revoke-platform-operator")
	platformDecisions = append(platformDecisions,
		assertPlatformAuthorization(t, iamEndpoint, developerLogin.Credential, string(developer.ID), "request-platform-developer-revoked", false),
		assertPlatformAuthorization(t, replicaEndpoint, developerLogin.Credential, string(developer.ID), "request-replica-platform-revoked", false),
	)
	assertPlatformAuditAccess(t, auditEndpoint, developerLogin.Credential, http.StatusForbidden)
	developerOperation := createPaaSApplication(
		t,
		paasEndpoint,
		developerLogin.Credential,
		"application-process",
		"process-application",
		"create-application-process",
		http.StatusCreated,
	)
	createPaaSApplication(t, paasEndpoint, developerLogin.Credential, "application-nonprefix", "nonprefix-application", "create-application-nonprefix", http.StatusCreated)
	if developerOperation.Scope != (paasv1.ResourceScope{
		Kind: paasv1.AuthorityTenant, TenantID: "organization-process",
	}) || developerOperation.RequestedBy != (paasv1.SubjectRef{
		Type: paasv1.SubjectUser, ID: string(developer.ID),
	}) {
		t.Fatalf("PaaS did not preserve exact IAM authority: %#v", developerOperation)
	}
	waitAllIAMOutboxDelivered(t, ctx, admin)
	waitAllPaaSOutboxDelivered(t, ctx, admin)
	assertPaaSAuditFact(
		t,
		ctx,
		admin,
		auditv1.ActionPaaSApplicationCreated,
		"application-process",
		string(developer.ID),
	)
	revokeIAMPolicyAttachment(t, iamEndpoint, adminLogin.Credential, developerBinding.ID, 1, "request-revoke-developer-binding")
	// The policy editor's real read path returns whole registered declarations,
	// not a second embedded catalog or a reusable permission. Compile only from
	// these response values; the publication API independently recompiles them.
	discoverProfiles := func(endpoint string, want int) iamv1.AuthorizationProfileList {
		t.Helper()
		response := performJSON(t, http.MethodGet, endpoint+"/v1/authorization-profiles", adminLogin.Credential, nil)
		if response.Status != want {
			t.Fatalf("real product discovery status=%d want=%d", response.Status, want)
		}
		if want != http.StatusOK {
			if bytes.Contains(response.Body, []byte(`"items"`)) || bytes.Contains(response.Body, []byte(`"contentDigest"`)) {
				t.Fatal("unavailable discovery returned source constants or stale metadata")
			}
			return iamv1.AuthorizationProfileList{}
		}
		catalog, err := iamv1.DecodeAuthorizationProfileList(bytes.NewReader(response.Body))
		if err != nil || catalog.AccountID != "organization-process" {
			t.Fatal("invalid actual product discovery")
		}
		return catalog
	}
	var discovery iamv1.AuthorizationProfileList
	for _, endpoint := range []string{iamEndpoint, replicaEndpoint} {
		catalog := discoverProfiles(endpoint, http.StatusOK)
		if discovery.Kind != "" && !reflect.DeepEqual(discovery, catalog) {
			t.Fatal("IAM replicas disagreed about current product declarations")
		}
		discovery = catalog
	}
	profiles := make([]iamv1.AuthorizationProfile, 0, len(discovery.Items))
	for _, entry := range discovery.Items {
		profiles = append(profiles, entry.Profile)
	}
	// Publish through the real IAM API, then consume the exact resource rule
	// through the independent PaaS PEP. No owner-side policy fixtures are used.
	customRequest := iamv1.CreatePolicyRequest{DisplayName: "Selected process application", RequestID: "request-process-custom-policy",
		Document: iamv1.PolicyDocument{LanguageVersion: iamv1.PolicyLanguageVersion, Scope: iamv1.AuthorityScopeTenant,
			Statements: []iamv1.PolicyStatement{{SID: "read-selected", Effect: iamv1.PolicyAllow,
				Actions:   []iamv1.Action{"paas.application.*"},
				Resources: []iamv1.PolicyResourceSelector{{Kind: iamv1.ResourceApplication, Match: iamv1.PolicyResourceExact, ID: "application-process"}}}}}}
	compiled, err := iamv1.CompilePolicyDocument(customRequest.Document, profiles)
	if err != nil {
		t.Fatal("cannot compile a product family from actual discovered declarations")
	}
	compiledCanonical, compiledDigest, err := iamv1.CanonicalizePolicyCompilation(customRequest.Document, compiled, profiles)
	if err != nil {
		t.Fatal(err)
	}
	publication := performJSON(t, http.MethodPost, replicaEndpoint+"/v1/policies", adminLogin.Credential, customRequest)
	var customPolicy iamv1.PolicyDetail
	if publication.Status != http.StatusCreated || json.Unmarshal(publication.Body, &customPolicy) != nil || iamv1.ValidatePolicyDetail(customPolicy) != nil {
		t.Fatalf("process customer policy publication status=%d", publication.Status)
	}
	publishedCanonical, err := iamv1.CanonicalizePolicyVersion(customPolicy.Version)
	if err != nil || publishedCanonical != compiledCanonical || customPolicy.Version.ContentDigest != compiledDigest {
		t.Fatal("HTTP publication did not bind the exact complete discovered interpretation")
	}
	getPaaSApplication(t, paasEndpoint, developerLogin.Credential, "application-process", http.StatusForbidden)
	customAttachment := createIAMPolicyAttachment(t, iamEndpoint, adminLogin.Credential, developer.ID, customPolicy.Policy.ID, "request-process-custom-attach")
	getPaaSApplication(t, paasEndpoint, developerLogin.Credential, "application-process", http.StatusOK)
	getPaaSApplication(t, paasEndpoint, developerLogin.Credential, "application-custom-not-selected", http.StatusForbidden)
	denyDocument := customRequest.Document
	denyDocument.Statements = append([]iamv1.PolicyStatement(nil), customRequest.Document.Statements...)
	denyDocument.Statements[0].Effect = iamv1.PolicyDeny
	versionResponse := performJSON(t, http.MethodPost, iamEndpoint+"/v1/policies/"+string(customPolicy.Policy.ID)+"/versions", adminLogin.Credential,
		iamv1.CreatePolicyVersionRequest{Document: denyDocument, ResourceVersion: 1, RequestID: "request-process-deny-version"})
	var denyVersion iamv1.PolicyVersionDetail
	if versionResponse.Status != http.StatusCreated || json.Unmarshal(versionResponse.Body, &denyVersion) != nil || iamv1.ValidatePolicyVersionDetail(denyVersion) != nil || denyVersion.Policy.DefaultVersionID != customPolicy.Version.ID {
		t.Fatalf("process nondefault version status=%d", versionResponse.Status)
	}
	getPaaSApplication(t, paasEndpoint, developerLogin.Credential, "application-process", http.StatusOK)
	selectDefault := func(version iamv1.PolicyVersionID, revision uint64, requestID string) {
		t.Helper()
		response := performJSON(t, http.MethodPost, replicaEndpoint+"/v1/policies/"+string(customPolicy.Policy.ID)+":set-default-version", adminLogin.Credential,
			iamv1.SetDefaultPolicyVersionRequest{VersionID: version, ResourceVersion: revision, RequestID: requestID})
		var result iamv1.PolicyDetail
		if response.Status != http.StatusOK || json.Unmarshal(response.Body, &result) != nil || iamv1.ValidatePolicyDetail(result) != nil || result.Version.ID != version || result.Policy.ResourceVersion != revision+1 {
			t.Fatalf("process default version switch status=%d", response.Status)
		}
	}
	selectDefault(denyVersion.Version.ID, 2, "request-process-default-deny")
	getPaaSApplication(t, paasEndpoint, developerLogin.Credential, "application-process", http.StatusForbidden)
	selectDefault(customPolicy.Version.ID, 3, "request-process-default-original")
	getPaaSApplication(t, paasEndpoint, developerLogin.Credential, "application-process", http.StatusOK)
	metadataResponse := performJSON(t, http.MethodPatch, replicaEndpoint+"/v1/policies/"+string(customPolicy.Policy.ID), adminLogin.Credential,
		iamv1.UpdatePolicyRequest{DisplayName: "Renamed process application policy", ResourceVersion: 4, RequestID: "request-process-policy-rename"})
	var renamedPolicy iamv1.PolicyDetail
	if metadataResponse.Status != http.StatusOK || json.Unmarshal(metadataResponse.Body, &renamedPolicy) != nil ||
		iamv1.ValidatePolicyDetail(renamedPolicy) != nil || renamedPolicy.Policy.ResourceVersion != 5 || renamedPolicy.Policy.ID != customPolicy.Policy.ID ||
		renamedPolicy.Version.ID != customPolicy.Version.ID || renamedPolicy.Version.ContentDigest != customPolicy.Version.ContentDigest {
		t.Fatalf("process policy rename changed immutable identity/content status=%d", metadataResponse.Status)
	}
	getPaaSApplication(t, paasEndpoint, developerLogin.Credential, "application-process", http.StatusOK)
	getPaaSApplication(t, paasEndpoint, developerLogin.Credential, "application-custom-not-selected", http.StatusForbidden)
	retireVersionResponse := performJSON(t, http.MethodDelete, replicaEndpoint+"/v1/policies/"+string(customPolicy.Policy.ID)+"/versions/"+string(denyVersion.Version.ID), adminLogin.Credential,
		iamv1.DeletePolicyVersionRequest{ResourceVersion: 5, RequestID: "request-process-version-delete"})
	var versionRetired iamv1.PolicyDetail
	if retireVersionResponse.Status != http.StatusOK || json.Unmarshal(retireVersionResponse.Body, &versionRetired) != nil ||
		iamv1.ValidatePolicyDetail(versionRetired) != nil || versionRetired.Policy.ResourceVersion != 6 || versionRetired.Version.ID != customPolicy.Version.ID {
		t.Fatalf("process version retirement status=%d", retireVersionResponse.Status)
	}
	getPaaSApplication(t, paasEndpoint, developerLogin.Credential, "application-process", http.StatusOK)
	revokeIAMPolicyAttachment(t, replicaEndpoint, adminLogin.Credential, customAttachment.ID, customAttachment.ResourceVersion, "request-process-custom-revoke")
	getPaaSApplication(t, paasEndpoint, developerLogin.Credential, "application-process", http.StatusForbidden)
	deleteResponse := performJSON(t, http.MethodDelete, iamEndpoint+"/v1/policies/"+string(customPolicy.Policy.ID), adminLogin.Credential,
		iamv1.DeletePolicyRequest{ResourceVersion: 6, RequestID: "request-process-policy-delete"})
	var retiredPolicy iamv1.Policy
	if deleteResponse.Status != http.StatusOK || json.Unmarshal(deleteResponse.Body, &retiredPolicy) != nil || iamv1.ValidatePolicy(retiredPolicy) != nil ||
		retiredPolicy.Status != iamv1.PolicyRetired || retiredPolicy.ResourceVersion != 7 || retiredPolicy.ID != customPolicy.Policy.ID || retiredPolicy.DefaultVersionID != customPolicy.Version.ID {
		t.Fatalf("process policy deletion status=%d", deleteResponse.Status)
	}
	getPaaSApplication(t, paasEndpoint, developerLogin.Credential, "application-process", http.StatusForbidden)
	waitAllIAMOutboxDelivered(t, ctx, admin)
	if countAuditFacts(t, ctx, admin, auditv1.SourceIAM, auditv1.ActionIAMPolicyCreated, auditv1.ResultSucceeded) != 1 {
		t.Fatal("custom policy publication did not reach the immutable tenant Audit chain")
	}
	if countAuditFacts(t, ctx, admin, auditv1.SourceIAM, auditv1.ActionIAMPolicyVersionCreated, auditv1.ResultSucceeded) != 1 ||
		countAuditFacts(t, ctx, admin, auditv1.SourceIAM, auditv1.ActionIAMPolicyVersionDeleted, auditv1.ResultSucceeded) != 1 ||
		countAuditFacts(t, ctx, admin, auditv1.SourceIAM, auditv1.ActionIAMPolicyDefaultVersionSet, auditv1.ResultSucceeded) != 2 ||
		countAuditFacts(t, ctx, admin, auditv1.SourceIAM, auditv1.ActionIAMPolicyUpdated, auditv1.ResultSucceeded) != 1 ||
		countAuditFacts(t, ctx, admin, auditv1.SourceIAM, auditv1.ActionIAMPolicyDeleted, auditv1.ResultSucceeded) != 1 {
		t.Fatal("immutable version/default selection facts did not reach the original tenant chain")
	}
	// A separately published time grant is the developer's sole permission on
	// this application. Real IAM database time, not a test-supplied clock or
	// PEP attributes, governs the exact same bearer through both replicas.
	var policyClock time.Time
	if err := admin.QueryRow(ctx, "SELECT transaction_timestamp()").Scan(&policyClock); err != nil {
		t.Fatal(err)
	}
	policyClock = policyClock.UTC()
	policyExpiry := policyClock.Add(6 * time.Second)
	timedRequest := customRequest
	timedRequest.DisplayName, timedRequest.RequestID = "Time bound process application", "request-process-time-policy"
	timedRequest.Document.Statements = append([]iamv1.PolicyStatement(nil), customRequest.Document.Statements...)
	// Keep the independent instance-prefix gate narrow: application.create
	// is part of the family but does not support a resource prefix.
	timedRequest.Document.Statements[0].Actions = []iamv1.Action{iamv1.ActionPaaSApplicationRead}
	timedRequest.Document.Statements[0].Resources = []iamv1.PolicyResourceSelector{{Kind: iamv1.ResourceApplication, Match: iamv1.PolicyResourcePrefixInAuthority, ID: "application-pro"}}
	timedRequest.Document.Statements[0].Conditions = []iamv1.PolicyCondition{
		{Key: iamv1.ConditionIAMAccountID, Operator: iamv1.PolicyStringEquals, Values: []string{string(developer.AccountID)}},
		{Key: iamv1.ConditionIAMPrincipalID, Operator: iamv1.PolicyStringEquals, Values: []string{"another-principal", string(developer.ID)}},
		{Key: iamv1.ConditionIAMCurrentTime, Operator: iamv1.PolicyDateGreaterThanEquals, Values: []string{policyClock.Add(-time.Minute).Format(time.RFC3339Nano)}},
		{Key: iamv1.ConditionIAMCurrentTime, Operator: iamv1.PolicyDateLessThan, Values: []string{policyExpiry.Format(time.RFC3339Nano)}},
	}
	var timedPolicy iamv1.PolicyDetail
	timedResponse := performJSON(t, http.MethodPost, replicaEndpoint+"/v1/policies", adminLogin.Credential, timedRequest)
	if timedResponse.Status != http.StatusCreated || json.Unmarshal(timedResponse.Body, &timedPolicy) != nil || iamv1.ValidatePolicyDetail(timedPolicy) != nil {
		t.Fatalf("timed process policy publication status=%d", timedResponse.Status)
	}
	timedAttachment := createIAMPolicyAttachment(t, iamEndpoint, adminLogin.Credential, developer.ID, timedPolicy.Policy.ID, "request-process-time-attach")
	getPaaSApplication(t, paasEndpoint, developerLogin.Credential, "application-process", http.StatusOK)
	getPaaSApplication(t, paasEndpoint, developerLogin.Credential, "application-nonprefix", http.StatusForbidden)
	for policyClock.Before(policyExpiry) {
		select {
		case <-ctx.Done():
			t.Fatal("process policy time deadline")
		case <-time.After(50 * time.Millisecond):
		}
		if err := admin.QueryRow(ctx, "SELECT transaction_timestamp()").Scan(&policyClock); err != nil {
			t.Fatal(err)
		}
	}
	getPaaSApplication(t, paasEndpoint, developerLogin.Credential, "application-process", http.StatusForbidden)
	// Publishing a replacement is not a default change. Only the explicit
	// switch opens a new request; historical timed decisions remain intact.
	var untimedVersion iamv1.PolicyVersionDetail
	untimedDocument := customRequest.Document
	untimedDocument.Statements = append([]iamv1.PolicyStatement(nil), customRequest.Document.Statements...)
	untimedDocument.Statements[0].Actions = []iamv1.Action{iamv1.ActionPaaSApplicationRead}
	untimedDocument.Statements[0].Conditions = []iamv1.PolicyCondition{
		{Key: iamv1.ConditionIAMAccountID, Operator: iamv1.PolicyStringEquals, Values: []string{string(developer.AccountID)}},
		{Key: iamv1.ConditionIAMPrincipalID, Operator: iamv1.PolicyStringNotEquals, Values: []string{"excluded-principal-a", "excluded-principal-b"}},
	}
	untimedResponse := performJSON(t, http.MethodPost, iamEndpoint+"/v1/policies/"+string(timedPolicy.Policy.ID)+"/versions", adminLogin.Credential,
		iamv1.CreatePolicyVersionRequest{Document: untimedDocument, ResourceVersion: 1, RequestID: "request-process-untimed-version"})
	if untimedResponse.Status != http.StatusCreated || json.Unmarshal(untimedResponse.Body, &untimedVersion) != nil || iamv1.ValidatePolicyVersionDetail(untimedVersion) != nil {
		t.Fatal("untimed replacement publication failed")
	}
	getPaaSApplication(t, paasEndpoint, developerLogin.Credential, "application-process", http.StatusForbidden)
	selectedTimeResponse := performJSON(t, http.MethodPost, replicaEndpoint+"/v1/policies/"+string(timedPolicy.Policy.ID)+":set-default-version", adminLogin.Credential,
		iamv1.SetDefaultPolicyVersionRequest{VersionID: untimedVersion.Version.ID, ResourceVersion: 2, RequestID: "request-process-untimed-default"})
	if selectedTimeResponse.Status != http.StatusOK {
		t.Fatal("explicit untimed default failed")
	}
	getPaaSApplication(t, paasEndpoint, developerLogin.Credential, "application-process", http.StatusOK)
	// Excluding any one actual identity value makes NOT_EQUALS false; publishing
	// alone does not change authority, selecting its default does, on the same bearer.
	untimedDocument.Statements[0].Conditions[1].Values = []string{"unrelated-principal", string(developer.ID)}
	var excludedVersion iamv1.PolicyVersionDetail
	excludedResponse := performJSON(t, http.MethodPost, replicaEndpoint+"/v1/policies/"+string(timedPolicy.Policy.ID)+"/versions", adminLogin.Credential,
		iamv1.CreatePolicyVersionRequest{Document: untimedDocument, ResourceVersion: 3, RequestID: "request-process-identity-excluded"})
	if excludedResponse.Status != http.StatusCreated || json.Unmarshal(excludedResponse.Body, &excludedVersion) != nil || iamv1.ValidatePolicyVersionDetail(excludedVersion) != nil {
		t.Fatal("identity exclusion version failed")
	}
	getPaaSApplication(t, paasEndpoint, developerLogin.Credential, "application-process", http.StatusOK)
	excludedDefault := performJSON(t, http.MethodPost, iamEndpoint+"/v1/policies/"+string(timedPolicy.Policy.ID)+":set-default-version", adminLogin.Credential,
		iamv1.SetDefaultPolicyVersionRequest{VersionID: excludedVersion.Version.ID, ResourceVersion: 4, RequestID: "request-process-identity-default"})
	if excludedDefault.Status != http.StatusOK {
		t.Fatal("identity exclusion default failed")
	}
	getPaaSApplication(t, paasEndpoint, developerLogin.Credential, "application-process", http.StatusForbidden)
	revokeIAMPolicyAttachment(t, replicaEndpoint, adminLogin.Credential, timedAttachment.ID, timedAttachment.ResourceVersion, "request-process-time-revoke")
	getPaaSApplication(t, paasEndpoint, developerLogin.Credential, "application-process", http.StatusForbidden)
	proveUserBoundaryProcesses(t, ctx, admin, iamEndpoint, replicaEndpoint, auditEndpoint, paasEndpoint, adminLogin.Credential, developerLogin.Credential, developer.ID)
	waitAllIAMOutboxDelivered(t, ctx, admin)
	deniedBefore := countAuditFacts(
		t,
		ctx,
		admin,
		auditv1.SourceIAM,
		auditv1.ActionIAMAuthorizationDecided,
		auditv1.ResultDenied,
	)
	createPaaSApplication(
		t,
		paasEndpoint,
		developerLogin.Credential,
		"application-denied",
		"denied-application",
		"create-application-denied",
		http.StatusForbidden,
	)
	assertPaaSApplicationAbsent(t, ctx, admin, "application-denied")
	waitAllIAMOutboxDelivered(t, ctx, admin)
	if deniedAfter := countAuditFacts(
		t,
		ctx,
		admin,
		auditv1.SourceIAM,
		auditv1.ActionIAMAuthorizationDecided,
		auditv1.ResultDenied,
	); deniedAfter != deniedBefore+1 {
		t.Fatalf("denied IAM Audit facts before=%d after=%d", deniedBefore, deniedAfter)
	}
	createIAMPolicyAttachment(
		t,
		iamEndpoint,
		adminLogin.Credential,
		developer.ID,
		iamv1.SystemPolicyPaaSDeveloper,
		"request-rebind-developer",
	)
	createPaaSConfiguration(
		t,
		paasEndpoint,
		developerLogin.Credential,
		"configuration-process",
		"process-configuration",
		"application-process",
		"create-configuration-process",
		http.StatusCreated,
	)
	waitAllIAMOutboxDelivered(t, ctx, admin)
	waitAllPaaSOutboxDelivered(t, ctx, admin)
	expireIAMSession(t, ctx, admin, developerLogin.Session.ID)
	getPaaSApplication(
		t,
		paasEndpoint,
		developerLogin.Credential,
		"application-process",
		http.StatusUnauthorized,
	)

	reader := createIAMUser(
		t,
		iamEndpoint,
		adminLogin.Credential,
		"audit.reader",
		"Audit Reader",
		initialReaderPassword,
		"request-create-reader",
	)
	binding := createIAMPolicyAttachment(
		t,
		iamEndpoint,
		adminLogin.Credential,
		reader.ID,
		iamv1.SystemPolicyAuditReader,
		"request-bind-reader",
	)
	readerLogin := loginIAM(
		t,
		iamEndpoint,
		"audit.reader@organization-process",
		initialReaderPassword,
		"request-reader-login",
	)
	sensitive = append(sensitive, readerLogin.Credential)
	changePasswordIAM(
		t,
		iamEndpoint,
		readerLogin.Credential,
		initialReaderPassword,
		changedReaderPassword,
		"request-reader-password",
	)
	createPaaSApplication(
		t,
		paasEndpoint,
		readerLogin.Credential,
		"application-reader-denied",
		"reader-denied-application",
		"create-application-reader-denied",
		http.StatusForbidden,
	)
	assertPaaSApplicationAbsent(t, ctx, admin, "application-reader-denied")
	queryAudit(t, auditEndpoint, readerLogin.Credential, auditv1.QueryRecordsRequest{PageSize: 10}, http.StatusOK)
	revokeIAMPolicyAttachment(t, iamEndpoint, adminLogin.Credential, binding.ID, 1, "request-revoke-reader-binding")
	queryAudit(t, auditEndpoint, readerLogin.Credential, auditv1.QueryRecordsRequest{PageSize: 10}, http.StatusForbidden)
	createIAMPolicyAttachment(
		t,
		iamEndpoint,
		adminLogin.Credential,
		reader.ID,
		iamv1.SystemPolicyAuditReader,
		"request-rebind-reader",
	)
	queryAudit(t, auditEndpoint, readerLogin.Credential, auditv1.QueryRecordsRequest{PageSize: 10}, http.StatusOK)
	revokeIAMSession(
		t,
		iamEndpoint,
		adminLogin.Credential,
		readerLogin.Session.ID,
		"request-revoke-reader-session",
	)
	queryAudit(t, auditEndpoint, readerLogin.Credential, auditv1.QueryRecordsRequest{PageSize: 10}, http.StatusUnauthorized)
	if response := performJSON(t, http.MethodGet, replicaEndpoint+"/v1/auth/me", readerLogin.Credential, nil); response.Status != http.StatusUnauthorized {
		t.Fatalf("another IAM process accepted a revoked session: status=%d", response.Status)
	}
	waitAllIAMOutboxDelivered(t, ctx, admin)
	verification := verifyAudit(t, auditEndpoint, adminLogin.Credential)
	if verification.TenantID != "organization-process" ||
		verification.State != auditv1.VerificationVerified || verification.RecordCount < 1 {
		t.Fatalf("cross-process Audit verification=%#v", verification)
	}
	assertAuditAccessRecorded(t, ctx, admin, auditv1.ActionAuditRecordsRead, "principal-admin")
	assertAuditAccessRecorded(t, ctx, admin, auditv1.ActionAuditIntegrityVerified, "principal-admin")
	var verifyHistoricalRecovery func()
	var recoverySecrets []string
	adminLogin, verifyHistoricalRecovery, recoverySecrets = proveLocalCredentialRecoveryProcesses(t, ctx, admin, root, temporary, binaries.localRecovery, iamEndpoint, auditEndpoint, paasEndpoint, bootstrap, adminLogin,
		func(admit func()) {
			auditProcess.stop()
			admit()
			auditProcess = start(binaries.audit, auditEnvironment)
			waitHTTPStatus(t, ctx, auditProcess, auditEndpoint+"/ready", http.StatusOK)
		})
	sensitive = append(sensitive, recoverySecrets...)
	revokeIAMPolicyAttachment(t, iamEndpoint, adminLogin.Credential, "bootstrap-platform-operator-binding", 1, "request-revoke-bootstrap-platform")
	verifyHistoricalRecovery()
	platformDecisions = append(platformDecisions,
		assertPlatformAuthorization(t, iamEndpoint, adminLogin.Credential, "principal-admin", "request-platform-admin-revoked", false),
	)
	assertPlatformAuditAccess(t, auditEndpoint, adminLogin.Credential, http.StatusForbidden)
	selfGrant := performJSON(t, http.MethodPost, iamEndpoint+"/v1/policy-attachments", adminLogin.Credential,
		iamv1.CreatePolicyAttachmentRequest{Target: iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetUser, ID: "principal-admin"}, PolicyID: iamv1.SystemPolicyPlatformOperator, PolicyResourceVersion: 1, RequestID: "request-platform-self-grant"})
	if selfGrant.Status != http.StatusForbidden {
		t.Fatalf("organization administrator restored its platform authority: status=%d", selfGrant.Status)
	}
	iamProcess.stop()
	waitHTTPStatus(t, ctx, paasProcess, paasEndpoint+"/ready", http.StatusServiceUnavailable)
	assertReplicaRead := func(requestID string, status int) {
		t.Helper()
		request, err := iamv1.NewAuthorizationRequest(iamv1.ActionPaaSApplicationRead,
			iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "application-process"}, iamv1.AuthorizationResourceInstance, "", requestID, requestID)
		if err != nil {
			t.Fatal(err)
		}
		response := performJSONWithHeaders(t, http.MethodPost, replicaEndpoint+"/v1/authorize", paasServiceCredential, "", request,
			map[string]string{"Matrix-Subject-Credential": adminLogin.Credential})
		if response.Status != status {
			t.Fatalf("replica authorization status=%d want=%d", response.Status, status)
		}
		if status == http.StatusOK {
			var decision iamv1.AuthorizationDecision
			if json.Unmarshal(response.Body, &decision) != nil || iamv1.ValidateAuthorizationDecision(decision) != nil ||
				!decision.Allowed || decision.TenantID != bootstrap.Organization.ID || decision.Subject == nil || decision.Subject.ID != "principal-admin" {
				t.Fatal("surviving replica lost the existing session/authority")
			}
		} else if bytes.Contains(response.Body, []byte(`"allowed":true`)) {
			t.Fatal("unavailable replica returned an old permit")
		}
	}
	assertReplicaRead("request-replica-survives-peer", http.StatusOK)
	platformDecisions = append(platformDecisions,
		assertPlatformAuthorization(t, replicaEndpoint, adminLogin.Credential, "principal-admin", "request-replica-revocation-survives-peer", false))
	// Disconnect only this fixture's replica login. Other authority processes
	// keep their own connections and are not restarted or reconfigured.
	if _, err := admin.Exec(ctx, `ALTER ROLE matrix_authority_process_iam_replica NOLOGIN`); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `SELECT pg_terminate_backend(pid) FROM pg_stat_activity
		WHERE datname=current_database() AND usename='matrix_authority_process_iam_replica'`); err != nil {
		t.Fatal(err)
	}
	assertReplicaRead("request-replica-database-unavailable", http.StatusServiceUnavailable)
	discoverProfiles(replicaEndpoint, http.StatusServiceUnavailable)
	if _, err := admin.Exec(ctx, `ALTER ROLE matrix_authority_process_iam_replica LOGIN`); err != nil {
		t.Fatal(err)
	}
	waitHTTPStatus(t, ctx, replicaProcess, replicaEndpoint+"/ready", http.StatusOK)
	assertReplicaRead("request-replica-database-restored", http.StatusOK)
	if !reflect.DeepEqual(discovery, discoverProfiles(replicaEndpoint, http.StatusOK)) {
		t.Fatal("database reconnection changed the exact product discovery")
	}
	replicaProcess.stop()
	createPaaSApplication(
		t,
		paasEndpoint,
		adminLogin.Credential,
		"application-iam-unavailable",
		"iam-unavailable-application",
		"create-application-iam-unavailable",
		http.StatusServiceUnavailable,
	)
	assertPaaSApplicationAbsent(t, ctx, admin, "application-iam-unavailable")
	queryAudit(
		t,
		auditEndpoint,
		adminLogin.Credential,
		auditv1.QueryRecordsRequest{PageSize: 10},
		http.StatusServiceUnavailable,
	)
	iamProcess = start(binaries.iam, iamEnvironment)
	waitHTTPStatus(t, ctx, iamProcess, iamEndpoint+"/ready", http.StatusOK)
	waitHTTPStatus(t, ctx, paasProcess, paasEndpoint+"/ready", http.StatusOK)
	platformDecisions = append(platformDecisions,
		assertPlatformAuthorization(t, iamEndpoint, adminLogin.Credential, "principal-admin", "request-platform-admin-restarted", false),
	)
	if !reflect.DeepEqual(discovery, discoverProfiles(iamEndpoint, http.StatusOK)) {
		t.Fatal("IAM restart changed the original account or product metadata")
	}
	assertPlatformAuditAccess(t, auditEndpoint, adminLogin.Credential, http.StatusForbidden)
	waitAllIAMOutboxDelivered(t, ctx, admin)
	verifyHistoricalRecovery()
	assertPlatformDecisionAuditFacts(t, ctx, admin, platformDecisions)
	paasProcess.stop()
	wrongPaaSEnvironment := append([]string(nil), paasEnvironment...)
	wrongPaaSEnvironment[2] = "MATRIX_PAAS_SERVICE_CREDENTIAL_FILE=" + wrongCredentialPath
	paasProcess = start(binaries.paas, wrongPaaSEnvironment)
	waitHTTPStatus(t, ctx, paasProcess, paasEndpoint+"/ready", http.StatusServiceUnavailable)
	createPaaSApplication(
		t,
		paasEndpoint,
		adminLogin.Credential,
		"application-wrong-service",
		"wrong-service-application",
		"create-application-wrong-service",
		http.StatusUnauthorized,
	)
	assertPaaSApplicationAbsent(t, ctx, admin, "application-wrong-service")
	paasProcess.stop()
	paasProcess = start(binaries.paas, paasEnvironment)
	waitHTTPStatus(t, ctx, paasProcess, paasEndpoint+"/ready", http.StatusOK)

	auditProcess.stop()
	outageUser := createIAMUser(
		t,
		iamEndpoint,
		adminLogin.Credential,
		"outage.user",
		"Outage User",
		"Initial-Outage-User-Password-68!",
		"request-create-outage-user",
	)
	createPaaSApplication(
		t,
		paasEndpoint,
		adminLogin.Credential,
		"application-audit-outage",
		"audit-outage-application",
		"create-application-audit-outage",
		http.StatusCreated,
	)
	waitIAMOutboxRetry(t, ctx, admin)
	waitPaaSOutboxRetry(t, ctx, admin)
	auditProcess = start(binaries.audit, auditEnvironment)
	waitHTTPStatus(t, ctx, auditProcess, auditEndpoint+"/ready", http.StatusOK)
	for _, platformRecord := range platformAuditRecords {
		platformReplay := performJSON(t, http.MethodPost, auditEndpoint+"/v1/events", paasServiceCredential, platformRecord.Event)
		var platformDuplicate auditv1.IngestionResult
		if platformReplay.Status != http.StatusOK || json.Unmarshal(platformReplay.Body, &platformDuplicate) != nil ||
			auditv1.ValidateIngestionResult(platformDuplicate) != nil || platformDuplicate.Record != platformRecord ||
			platformDuplicate.Outcome != auditv1.IngestionDuplicate {
			t.Fatal("Audit restart changed the retained platform record or equal replay")
		}
	}
	assertPlatformAuditAccess(t, auditEndpoint, adminLogin.Credential, http.StatusForbidden)
	assertPlatformAuditStoredFacts(t, ctx, admin)
	waitAllIAMOutboxDelivered(t, ctx, admin)
	waitAllPaaSOutboxDelivered(t, ctx, admin)
	outageEventID, outageEvent := findIAMEvent(
		t,
		ctx,
		admin,
		auditv1.ActionIAMUserCreated,
		string(outageUser.ID),
	)
	var attemptsBefore int
	if err := admin.QueryRow(
		ctx,
		"SELECT attempts FROM iam.audit_outbox WHERE event_id = $1",
		outageEventID,
	).Scan(&attemptsBefore); err != nil {
		t.Fatalf("inspect IAM duplicate fixture: %v", err)
	}
	if _, err := admin.Exec(
		ctx,
		`UPDATE iam.audit_outbox
		    SET status = 'RETRY', worker_id = NULL, lease_expires_at = NULL,
		        next_attempt_at = transaction_timestamp(), error_code = NULL,
		        updated_at = transaction_timestamp()
		  WHERE event_id = $1 AND status = 'DELIVERED'`,
		outageEventID,
	); err != nil {
		t.Fatalf("inject IAM duplicate delivery: %v", err)
	}
	waitIAMEventDelivered(t, ctx, admin, outageEventID, attemptsBefore+1)
	assertAuditEventCount(t, ctx, admin, outageEventID, 1)
	changedEvent := outageEvent
	changedEvent.RequestID = "request-changed-replay"
	response := performJSON(
		t,
		http.MethodPost,
		auditEndpoint+"/v1/events",
		iamServiceCredential,
		changedEvent,
	)
	if response.Status != http.StatusForbidden {
		t.Fatalf("unproved IAM fact replay status=%d", response.Status)
	}
	assertAuditEventCount(t, ctx, admin, outageEventID, 1)
	paasEventID, paasEvent := findPaaSEvent(
		t,
		ctx,
		admin,
		auditv1.ActionPaaSApplicationCreated,
		"application-audit-outage",
	)
	var paasAttemptsBefore int
	if err := admin.QueryRow(
		ctx,
		"SELECT attempts FROM paas.audit_outbox WHERE event_id = $1",
		paasEventID,
	).Scan(&paasAttemptsBefore); err != nil {
		t.Fatalf("inspect PaaS duplicate fixture: %v", err)
	}
	if _, err := admin.Exec(
		ctx,
		`UPDATE paas.audit_outbox
		    SET status = 'RETRY', lease_owner = NULL, lease_expires_at = NULL,
		        available_at = transaction_timestamp(), last_error_code = NULL,
		        delivered_at = NULL, updated_at = transaction_timestamp()
		  WHERE event_id = $1 AND status = 'DELIVERED'`,
		paasEventID,
	); err != nil {
		t.Fatalf("inject PaaS duplicate delivery: %v", err)
	}
	waitPaaSEventDelivered(t, ctx, admin, paasEventID, paasAttemptsBefore+1)
	assertAuditSourceEventCount(t, ctx, admin, auditv1.SourcePaaS, paasEventID, 1)
	changedPaaSEvent := paasEvent
	changedPaaSEvent.RequestID = "request-changed-paas-replay"
	response = performJSON(
		t,
		http.MethodPost,
		auditEndpoint+"/v1/events",
		paasServiceCredential,
		changedPaaSEvent,
	)
	if response.Status != http.StatusForbidden {
		t.Fatalf("uncorrelated PaaS fact replay status=%d", response.Status)
	}
	changedPaaSEvent = paasEvent
	changedPaaSEvent.RequestDigest = "sha256:" + strings.Repeat("e", 64)
	response = performJSON(t, http.MethodPost, auditEndpoint+"/v1/events", paasServiceCredential, changedPaaSEvent)
	if response.Status != http.StatusConflict {
		t.Fatalf("authority-valid changed payload replay status=%d", response.Status)
	}
	assertAuditSourceEventCount(t, ctx, admin, auditv1.SourcePaaS, paasEventID, 1)

	waitAllIAMOutboxDelivered(t, ctx, admin)
	waitAllPaaSOutboxDelivered(t, ctx, admin)
	paasDispatcher.stop()
	createPaaSApplication(
		t,
		paasEndpoint,
		adminLogin.Credential,
		"application-dead-letter",
		"dead-letter-application",
		"create-application-dead-letter",
		http.StatusCreated,
	)
	wrongPaaSDispatcher := start(
		binaries.paasDispatcher,
		paasDispatcherEnvironment(wrongCredentialPath, "paas-audit-worker-wrong"),
	)
	waitPaaSDeadLetter(t, ctx, admin)
	waitHTTPStatus(t, ctx, paasProcess, paasEndpoint+"/ready", http.StatusServiceUnavailable)
	wrongPaaSDispatcher.stop()

	dispatcher.stop()
	createIAMUser(
		t,
		iamEndpoint,
		adminLogin.Credential,
		"deadletter.user",
		"Dead Letter User",
		"Initial-Dead-Letter-Password-79!",
		"request-create-deadletter-user",
	)
	wrongDispatcher := start(
		binaries.dispatcher,
		iamDispatcherEnvironment(wrongCredentialPath, "iam-audit-worker-wrong"),
	)
	waitIAMDeadLetter(t, ctx, admin)
	waitHTTPStatus(t, ctx, iamProcess, iamEndpoint+"/ready", http.StatusServiceUnavailable)
	wrongDispatcher.stop()
	if _, err := admin.Exec(ctx, `UPDATE iam.service_credentials SET revoked_at=transaction_timestamp()
		WHERE tenant_id='organization-process' AND purpose='IAM' AND revoked_at IS NULL`); err != nil {
		t.Fatal(err)
	}
	response = performJSON(t, http.MethodPost, auditEndpoint+"/v1/events", iamServiceCredential, outageEvent)
	if response.Status != http.StatusUnauthorized {
		t.Fatalf("revoked producer credential reused historical proof: status=%d", response.Status)
	}
	assertAuditEventCount(t, ctx, admin, outageEventID, 1)
	assertAuthorityPlaintextAbsent(t, ctx, admin, sensitive...)
}

type binarySet struct {
	iam            string
	localRecovery  string
	audit          string
	dispatcher     string
	paas           string
	paasDispatcher string
}

func runIAMConsoleBrowser(t *testing.T, ctx context.Context, database *pgx.Conn, root, temporary, iamEndpoint, auditEndpoint, paasEndpoint, bearer string, start func(string, []string) *childProcess) {
	t.Helper()
	var member iamv1.User
	for _, candidate := range []struct {
		login, name string
		policy      iamv1.PolicyID
	}{
		{"browser.admin", "Browser Administrator", iamv1.SystemPolicyAccountAdministrator},
		{"browser.member", "Browser Member", iamv1.SystemPolicyPaaSDeveloper},
	} {
		user := createIAMUser(t, iamEndpoint, bearer, candidate.login, candidate.name, initialDeveloperPassword, "browser-create-"+candidate.login)
		createIAMPolicyAttachment(t, iamEndpoint, bearer, user.ID, candidate.policy, "browser-grant-"+candidate.login)
		login := loginIAM(t, iamEndpoint, candidate.login+"@organization-process", initialDeveloperPassword, "browser-login-"+candidate.login)
		changePasswordIAM(t, iamEndpoint, login.Credential, initialDeveloperPassword, changedDeveloperPassword, "browser-password-"+candidate.login)
		if candidate.login == "browser.member" {
			member = user
		}
	}
	for _, candidate := range []struct{ name, application string }{
		{"Browser boundary A", "application-browser-a"},
		{"Browser boundary B", "application-browser-b"},
	} {
		createPaaSApplication(t, paasEndpoint, bearer, paasv1.ResourceID(candidate.application), candidate.application, "browser-create-"+candidate.application, http.StatusCreated)
		document := iamv1.PolicyDocument{LanguageVersion: iamv1.PolicyLanguageVersion, Scope: iamv1.AuthorityScopeTenant,
			Statements: []iamv1.PolicyStatement{{SID: "selected-application", Effect: iamv1.PolicyAllow,
				Actions:   []iamv1.Action{iamv1.ActionPaaSApplicationRead},
				Resources: []iamv1.PolicyResourceSelector{{Kind: iamv1.ResourceApplication, Match: iamv1.PolicyResourceExact, ID: candidate.application}}}}}
		response := performJSON(t, http.MethodPost, iamEndpoint+"/v1/policies", bearer,
			iamv1.CreatePolicyRequest{DisplayName: candidate.name, Document: document, RequestID: "browser-policy-" + candidate.application})
		var policy iamv1.PolicyDetail
		if response.Status != http.StatusCreated || json.Unmarshal(response.Body, &policy) != nil || iamv1.ValidatePolicyDetail(policy) != nil {
			t.Fatal("browser fixture could not publish a real boundary policy")
		}
	}
	uiAddress := freeAddress(t)
	uiBinary := buildAuthorityBinary(t, ctx, root, temporary, "matrix-paas-ui", "./app/ui/paas/cmd/matrix-paas-ui")
	ui := start(uiBinary, []string{"MATRIX_PAAS_UI_LISTEN_ADDRESS=" + uiAddress})
	waitHTTPStatus(t, ctx, ui, "http://"+uiAddress+"/ready", http.StatusOK)

	// Same-origin loopback routing only. No credentials/selectors are injected;
	// actual services enforce every request. This is not production APISIX.
	mux := http.NewServeMux()
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxConnsPerHost = 8
	transport.MaxIdleConnsPerHost = 8
	transport.ResponseHeaderTimeout = 15 * time.Second
	defer transport.CloseIdleConnections()
	for _, route := range []struct{ prefix, strip, endpoint string }{
		{"/api/iam/", "/api/iam", iamEndpoint},
		{"/api/audit/", "/api/audit", auditEndpoint},
		{"/api/managed-services/", "/api", paasEndpoint},
		{"/", "", "http://" + uiAddress},
	} {
		target, err := url.Parse(route.endpoint)
		if err != nil {
			t.Fatal("invalid local browser upstream")
		}
		proxy := httputil.NewSingleHostReverseProxy(target)
		proxy.Transport = transport
		proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, _ error) {
			http.Error(w, "upstream unavailable", http.StatusBadGateway)
		}
		mux.Handle(route.prefix, http.StripPrefix(route.strip, proxy))
	}
	requests := make(chan struct{}, 16)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case requests <- struct{}{}:
			defer func() { <-requests }()
			mux.ServeHTTP(w, r)
		default:
			http.Error(w, "browser fixture capacity exceeded", http.StatusServiceUnavailable)
		}
	}))
	server.Config.ReadHeaderTimeout = 5 * time.Second
	server.Config.ReadTimeout = 30 * time.Second
	server.Config.WriteTimeout = 30 * time.Second
	server.Config.IdleTimeout = 30 * time.Second
	server.Start()
	defer server.Close()
	finish := filepath.Join(temporary, "browser-finished")
	t.Logf("BROWSER_FIXTURE url=%s/console/access finish=%s member=%s; synthetic credentials are the existing changed test constants", server.URL, finish, member.ID)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			t.Fatal("browser observation timed out; not accepted")
		case <-ticker.C:
			if exited, _ := ui.poll(); exited {
				t.Fatal("browser UI exited during observation")
			}
			info, err := os.Lstat(finish)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil || !info.Mode().IsRegular() {
				t.Fatal("invalid browser completion marker")
			}
			goto finished
		}
	}
finished:
	waitAllIAMOutboxDelivered(t, ctx, database)
	waitAllPaaSOutboxDelivered(t, ctx, database)
	page := queryAudit(t, auditEndpoint, bearer, auditv1.QueryRecordsRequest{PageSize: 200}, http.StatusOK)
	sets, removals := 0, 0
	for _, record := range page.Records {
		if record.Event.Target.ID != string(member.ID) {
			continue
		}
		switch record.Event.Action {
		case auditv1.ActionIAMUserPermissionBoundarySet:
			sets++
		case auditv1.ActionIAMUserPermissionBoundaryRemoved:
			removals++
		}
	}
	if sets != 2 || removals != 1 {
		t.Fatalf("observed boundary facts set=%d remove=%d, want set+replace+remove", sets, removals)
	}
	response := performJSON(t, http.MethodGet, iamEndpoint+"/v1/users/"+string(member.ID)+"/permission-boundary", bearer, nil)
	var boundary iamv1.UserPermissionBoundary
	if response.Status != http.StatusOK || json.Unmarshal(response.Body, &boundary) != nil || iamv1.ValidateUserPermissionBoundary(boundary) != nil || boundary.Policy != nil {
		t.Fatal("browser removal did not leave an explicit unbound user")
	}
	if verification := verifyAudit(t, auditEndpoint, bearer); verification.State != auditv1.VerificationVerified {
		t.Fatal("browser facts failed the real Audit chain verification")
	}
	t.Log("browser fixture finished with real set/replace/remove facts; visual assertions belong to recorded browser observations")
}

func buildAuthorityBinaries(
	t *testing.T,
	ctx context.Context,
	root string,
	temporary string,
) binarySet {
	t.Helper()
	build := func(name, packagePath string) string {
		return buildAuthorityBinary(t, ctx, root, temporary, name, packagePath)
	}
	return binarySet{
		iam:            build("matrix-iam", "./app/service/iam/cmd/matrix-iam"),
		localRecovery:  build("matrix-iam-local-recovery", "./app/service/iam/cmd/matrix-iam-local-recovery"),
		audit:          build("matrix-audit", "./app/service/audit/cmd/matrix-audit"),
		dispatcher:     build("matrix-iam-audit-dispatcher", "./app/service/iam/cmd/matrix-iam-audit-dispatcher"),
		paas:           build("matrix-paas", "./app/service/paas/cmd/matrix-paas"),
		paasDispatcher: build("matrix-paas-audit-dispatcher", "./app/service/paas/cmd/matrix-paas-audit-dispatcher"),
	}
}

func buildAuthorityBinary(t *testing.T, ctx context.Context, root, temporary, name, packagePath string) string {
	t.Helper()
	suffix := ""
	if runtime.GOOS == "windows" {
		suffix = ".exe"
	}
	path := filepath.Join(temporary, name+suffix)
	command := exec.CommandContext(ctx, "go", "build", "-p", "2", "-o", path, packagePath)
	command.Dir = root
	command.Env = append(os.Environ(), "GOMAXPROCS=2", "GOMEMLIMIT=512MiB")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", name, err, output)
	}
	return path
}

type childProcess struct {
	command *exec.Cmd
	done    chan error
	stdout  bytes.Buffer
	stderr  bytes.Buffer
	exited  bool
	err     error
}

var errProcessWaitTimeout = errors.New("authority process wait timed out")

func startChild(
	t *testing.T,
	root string,
	binary string,
	environment []string,
	arguments ...string,
) *childProcess {
	t.Helper()
	child := &childProcess{done: make(chan error, 1)}
	child.command = exec.Command(binary, arguments...)
	child.command.Dir = root
	child.command.Env = append(append(os.Environ(), environment...), "GOMAXPROCS=2", "GOMEMLIMIT=512MiB")
	child.command.Stdout = &child.stdout
	child.command.Stderr = &child.stderr
	if err := child.command.Start(); err != nil {
		t.Fatalf("start authority process: %v", err)
	}
	go func() { child.done <- child.command.Wait() }()
	return child
}

func (child *childProcess) poll() (bool, error) {
	if child.exited {
		return true, child.err
	}
	select {
	case child.err = <-child.done:
		child.exited = true
		return true, child.err
	default:
		return false, nil
	}
}

func (child *childProcess) wait(timeout time.Duration) error {
	if child.exited {
		return child.err
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case child.err = <-child.done:
		child.exited = true
		return child.err
	case <-timer.C:
		return errProcessWaitTimeout
	}
}

func (child *childProcess) stop() {
	if child == nil || child.exited || child.command == nil || child.command.Process == nil {
		return
	}
	_ = child.command.Process.Kill()
	_ = child.wait(10 * time.Second)
}

func (child *childProcess) output() string {
	return child.stdout.String() + child.stderr.String()
}

func waitHTTPStatus(
	t *testing.T,
	ctx context.Context,
	child *childProcess,
	endpoint string,
	want int,
) {
	t.Helper()
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		if exited, err := child.poll(); exited {
			t.Fatalf("authority process exited before HTTP status %d: %v output=%q", want, err, child.output())
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			t.Fatalf("create authority readiness request: %v", err)
		}
		response, err := processHTTPClient().Do(request)
		if err == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64*1024))
			_ = response.Body.Close()
			if response.StatusCode == want {
				return
			}
		}
		select {
		case <-ctx.Done():
			t.Fatalf("authority readiness context: %v", ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
	t.Fatalf("authority endpoint %s did not return %d", endpoint, want)
}

type processResponse struct {
	Status int
	Body   []byte
}

func performJSON(
	t *testing.T,
	method string,
	endpoint string,
	bearer string,
	body any,
) processResponse {
	t.Helper()
	return performJSONWithIdempotency(t, method, endpoint, bearer, "", body)
}

func performJSONWithIdempotency(
	t *testing.T,
	method string,
	endpoint string,
	bearer string,
	idempotencyKey string,
	body any,
) processResponse {
	t.Helper()
	return performJSONWithHeaders(t, method, endpoint, bearer, idempotencyKey, body, nil)
}

func performJSONWithHeaders(t *testing.T, method, endpoint, bearer, idempotencyKey string, body any, headers map[string]string) processResponse {
	t.Helper()
	var encoded []byte
	var err error
	if body != nil {
		encoded, err = json.Marshal(body)
		if err != nil {
			t.Fatalf("encode authority HTTP request: %v", err)
		}
	}
	request, err := http.NewRequest(method, endpoint, bytes.NewReader(encoded))
	if err != nil {
		t.Fatalf("create authority HTTP request: %v", err)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	if idempotencyKey != "" {
		request.Header.Set("Idempotency-Key", idempotencyKey)
	}
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response, err := processHTTPClient().Do(request)
	if err != nil {
		t.Fatalf("call authority HTTP endpoint: %v", err)
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, 2*1024*1024))
	if err != nil {
		t.Fatalf("read authority HTTP response: %v", err)
	}
	return processResponse{Status: response.StatusCode, Body: responseBody}
}

var authorityHTTPClient = newProcessHTTPClient()

func processHTTPClient() *http.Client {
	return authorityHTTPClient
}

func newProcessHTTPClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

type loginResult struct {
	Session    iamv1.Session
	Credential string
}

func loginIAM(
	t *testing.T,
	endpoint string,
	loginName string,
	password string,
	requestID string,
) loginResult {
	t.Helper()
	response := performJSON(t, http.MethodPost, endpoint+"/v1/auth/login", "", struct {
		LoginName string `json:"loginName"`
		Password  string `json:"password"`
		RequestID string `json:"requestId"`
	}{LoginName: loginName, Password: password, RequestID: requestID})
	if response.Status != http.StatusOK {
		t.Fatalf("IAM login %s status=%d", loginName, response.Status)
	}
	var wire struct {
		Session    iamv1.Session `json:"session"`
		Credential string        `json:"credential"`
	}
	if err := json.Unmarshal(response.Body, &wire); err != nil ||
		iamv1.ValidateSession(wire.Session) != nil || wire.Credential == "" {
		t.Fatalf("decode IAM login for %s: %v", loginName, err)
	}
	return loginResult{Session: wire.Session, Credential: wire.Credential}
}

func assertIAMWeakLoginRejected(t *testing.T, endpoint string) {
	t.Helper()
	const weakPassword = "weak"
	response := performJSON(t, http.MethodPost, endpoint+"/v1/auth/login", "", struct {
		LoginName string `json:"loginName"`
		Password  string `json:"password"`
		RequestID string `json:"requestId"`
	}{LoginName: "admin", Password: weakPassword, RequestID: "request-weak-login"})
	if response.Status != http.StatusUnauthorized ||
		bytes.Contains(response.Body, []byte(weakPassword)) {
		t.Fatalf("weak IAM login status=%d body=%s", response.Status, response.Body)
	}
}

func proveUserBoundaryProcesses(t *testing.T, ctx context.Context, database *pgx.Conn, iamEndpoint, replicaEndpoint, auditEndpoint, paasEndpoint, root, bearer string, user iamv1.PrincipalID) {
	t.Helper()
	path := "/v1/users/" + string(user) + "/permission-boundary"
	var boundary iamv1.UserPermissionBoundary
	read := func(endpoint string) {
		t.Helper()
		response := performJSON(t, http.MethodGet, endpoint+path, root, nil)
		if response.Status != http.StatusOK || json.Unmarshal(response.Body, &boundary) != nil || iamv1.ValidateUserPermissionBoundary(boundary) != nil || boundary.UserID != user {
			t.Fatal("process boundary read lost current user authority")
		}
	}
	read(replicaEndpoint)
	if boundary.Policy != nil {
		t.Fatal("process user unexpectedly bounded before explicit command")
	}
	document := iamv1.PolicyDocument{LanguageVersion: iamv1.PolicyLanguageVersion, Scope: iamv1.AuthorityScopeTenant,
		Statements: []iamv1.PolicyStatement{{SID: "boundary-selected", Effect: iamv1.PolicyAllow, Actions: []iamv1.Action{iamv1.ActionPaaSApplicationRead},
			Resources: []iamv1.PolicyResourceSelector{{Kind: iamv1.ResourceApplication, Match: iamv1.PolicyResourceExact, ID: "application-process"}}}}}
	var policy iamv1.PolicyDetail
	publication := performJSON(t, http.MethodPost, iamEndpoint+"/v1/policies", root,
		iamv1.CreatePolicyRequest{DisplayName: "Process user upper bound", Document: document, RequestID: "process-boundary-policy"})
	if publication.Status != http.StatusCreated || json.Unmarshal(publication.Body, &policy) != nil || iamv1.ValidatePolicyDetail(policy) != nil {
		t.Fatal("process boundary policy publication failed")
	}
	response := performJSON(t, http.MethodPut, replicaEndpoint+path, root,
		iamv1.SetUserPermissionBoundaryRequest{PolicyID: policy.Policy.ID, PolicyResourceVersion: policy.Policy.ResourceVersion, ResourceVersion: boundary.ResourceVersion, RequestID: "process-boundary-set"})
	if response.Status != http.StatusOK {
		t.Fatalf("process boundary set status=%d", response.Status)
	}
	assertPermissions := func(selected, other bool) {
		t.Helper()
		for _, endpoint := range []string{iamEndpoint, replicaEndpoint} {
			for _, candidate := range []struct {
				id      string
				allowed bool
			}{{"application-process", selected}, {"application-nonprefix", other}} {
				request, err := iamv1.NewAuthorizationRequest(iamv1.ActionPaaSApplicationRead,
					iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: candidate.id}, iamv1.AuthorizationResourceInstance, "", "process-boundary-read", "process-boundary-read")
				if err != nil {
					t.Fatal(err)
				}
				response := performJSONWithHeaders(t, http.MethodPost, endpoint+"/v1/authorize", paasServiceCredential, "", request, map[string]string{"Matrix-Subject-Credential": bearer})
				var decision iamv1.AuthorizationDecision
				if response.Status != http.StatusOK || json.Unmarshal(response.Body, &decision) != nil || iamv1.ValidateAuthorizationDecision(decision) != nil || decision.Allowed != candidate.allowed {
					t.Fatalf("process replica boundary allowed=%v want=%v status=%d", decision.Allowed, candidate.allowed, response.Status)
				}
			}
		}
		for _, candidate := range []struct {
			id      string
			allowed bool
		}{{"application-process", selected}, {"application-nonprefix", other}} {
			status := http.StatusForbidden
			if candidate.allowed {
				status = http.StatusOK
			}
			getPaaSApplication(t, paasEndpoint, bearer, paasv1.ResourceID(candidate.id), status)
		}
	}
	assertPermissions(false, false) // A boundary alone is never a grant.
	grant := createIAMPolicyAttachment(t, iamEndpoint, root, user, iamv1.SystemPolicyPaaSDeveloper, "process-boundary-positive-grant")
	assertPermissions(true, false)
	// Both real IAM processes project the same current bound, not an attachment.
	for _, endpoint := range []string{iamEndpoint, replicaEndpoint} {
		response := performJSON(t, http.MethodGet, endpoint+"/v1/auth/me", bearer, nil)
		var identity iamv1.CurrentIdentity
		if response.Status != http.StatusOK || json.Unmarshal(response.Body, &identity) != nil || iamv1.ValidateCurrentIdentity(identity) != nil ||
			identity.PermissionBoundary.Policy == nil || identity.PermissionBoundary.Policy.PolicyID != policy.Policy.ID || len(identity.PolicySources) != 1 {
			t.Fatal("replica identity lost independent permission boundary")
		}
	}
	document.Statements[0].Effect = iamv1.PolicyDeny
	var version iamv1.PolicyVersionDetail
	response = performJSON(t, http.MethodPost, iamEndpoint+"/v1/policies/"+string(policy.Policy.ID)+"/versions", root,
		iamv1.CreatePolicyVersionRequest{Document: document, ResourceVersion: 1, RequestID: "process-boundary-deny-version"})
	if response.Status != http.StatusCreated || json.Unmarshal(response.Body, &version) != nil || iamv1.ValidatePolicyVersionDetail(version) != nil {
		t.Fatal("process boundary version publication failed")
	}
	assertPermissions(true, false)
	response = performJSON(t, http.MethodPost, replicaEndpoint+"/v1/policies/"+string(policy.Policy.ID)+":set-default-version", root,
		iamv1.SetDefaultPolicyVersionRequest{VersionID: version.Version.ID, ResourceVersion: version.Policy.ResourceVersion, RequestID: "process-boundary-deny-default"})
	if response.Status != http.StatusOK {
		t.Fatal("process boundary default selection failed")
	}
	assertPermissions(false, false)
	read(iamEndpoint)
	response = performJSON(t, http.MethodDelete, iamEndpoint+path, root,
		iamv1.RemoveUserPermissionBoundaryRequest{ResourceVersion: boundary.ResourceVersion, RequestID: "process-boundary-remove"})
	if response.Status != http.StatusOK {
		t.Fatal("process boundary removal failed")
	}
	read(replicaEndpoint)
	if boundary.Policy != nil {
		t.Fatal("replica retained removed boundary")
	}
	assertPermissions(true, true)
	revokeIAMPolicyAttachment(t, replicaEndpoint, root, grant.ID, grant.ResourceVersion, "process-boundary-positive-revoke")
	assertPermissions(false, false)
	waitAllIAMOutboxDelivered(t, ctx, database)
	for _, action := range []auditv1.Action{auditv1.ActionIAMUserPermissionBoundarySet, auditv1.ActionIAMUserPermissionBoundaryRemoved} {
		records := queryAudit(t, auditEndpoint, root, auditv1.QueryRecordsRequest{PageSize: 100, Action: action}, http.StatusOK)
		if len(records.Records) != 1 || records.TenantID != auditv1.TenantID(boundary.AccountID) || records.Records[0].Event.Target.ID != string(user) || records.Records[0].Event.IAMDecisionID == "" {
			t.Fatal("dispatcher lost single correlated tenant boundary fact")
		}
	}
	if chain := verifyAudit(t, auditEndpoint, root); !chain.Complete || chain.TenantID != auditv1.TenantID(boundary.AccountID) {
		t.Fatal("process boundary mutation broke tenant audit chain")
	}
}

func assertPlatformAuthorization(
	t *testing.T,
	endpoint, credential, principalID, requestID string,
	allowed bool,
) iamv1.AuthorizationDecision {
	t.Helper()
	profile, found := iamv1.LookupAuthorizationProfile(iamv1.ProductPaaS)
	if !found {
		t.Fatal("missing platform profile")
	}
	for index, declaration := range profile.Actions {
		if declaration.Scope != iamv1.AuthorityScopeInstallation || declaration.Action == iamv1.ActionPaaSExecutionTargetRegister {
			continue
		}
		for shapeIndex, shape := range declaration.ResourceShapes {
			resource := iamv1.ResourceReference{Kind: declaration.ResourceKind, ID: "resource-platform-process"}
			if shape.Mode == iamv1.AuthorizationResourceCollection {
				resource.ID = "collection"
			}
			assertPlatformActionAuthorization(t, endpoint, credential, principalID, fmt.Sprintf("%s-%d-%d", requestID, index, shapeIndex), declaration.Action, resource, shape.Mode, shape.CollectionUsage, allowed)
		}
	}
	resource := iamv1.ResourceReference{Kind: iamv1.ResourceExecutionTarget, ID: "execution-target-process"}
	return assertPlatformActionAuthorization(t, endpoint, credential, principalID, requestID, iamv1.ActionPaaSExecutionTargetRegister, resource, iamv1.AuthorizationResourceInstance, "", allowed)
}

func assertPlatformActionAuthorization(t *testing.T, endpoint, credential, principalID, requestID string, action iamv1.Action, resource iamv1.ResourceReference, mode iamv1.AuthorizationResourceMode, usage iamv1.AuthorizationCollectionUsage, allowed bool) iamv1.AuthorizationDecision {
	t.Helper()
	authorization, err := iamv1.NewAuthorizationRequest(action, resource, mode, usage, requestID, requestID)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(authorization)
	if err != nil {
		t.Fatalf("encode platform authorization request: %v", err)
	}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, endpoint+"/v1/authorize", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create platform authorization request: %v", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+paasServiceCredential)
	request.Header.Set("Matrix-Subject-Credential", credential)
	response, err := processHTTPClient().Do(request)
	if err != nil {
		t.Fatalf("request platform authorization: %v", err)
	}
	defer response.Body.Close()
	var decision iamv1.AuthorizationDecision
	if response.StatusCode != http.StatusOK ||
		iamv1.DecodeRequest(response.Body, &decision) != nil ||
		iamv1.CheckAuthorizationDecisionForRequest(decision, authorization) != nil ||
		decision.Allowed != allowed || decision.TenantID != "" ||
		decision.RequestID != requestID || decision.Action != action ||
		decision.Resource != resource {
		t.Fatalf("invalid platform authorization: status=%d allowed=%t request=%s", response.StatusCode, allowed, requestID)
	}
	if allowed && (decision.InstallationID != "installation-process" || decision.Subject == nil ||
		decision.Subject.Type != iamv1.SubjectUser || string(decision.Subject.ID) != principalID) {
		t.Fatal("platform authorization lost the exact installation or user identity")
	}
	return decision
}

func ingestPlatformAuditFixture(t *testing.T, endpoint string, decision iamv1.AuthorizationDecision) auditv1.AuditRecord {
	t.Helper()
	// This tests the authenticated producer/Audit boundary, not host admission
	// or a PaaS Operation; those effects have their own real-runtime gates.
	event := auditv1.Event{
		APIVersion: auditv1.APIVersion, Kind: "AuditEvent", EventID: "event-platform-process",
		InstallationID: decision.InstallationID,
		Actor:          auditv1.ActorReference{Type: auditv1.ActorUser, ID: auditv1.ActorID(decision.Subject.ID)},
		IAMDecisionID:  auditv1.DecisionID(decision.ID), Action: auditv1.ActionPaaSExecutionTargetRegistered,
		Target: auditv1.TargetReference{Kind: auditv1.TargetExecutionTarget, ID: decision.Resource.ID},
		Result: auditv1.ResultSucceeded, RequestDigest: "sha256:" + strings.Repeat("1", 64),
		RequestID: decision.RequestID, CorrelationID: decision.RequestID,
		OperationID: "operation-platform-audit-fixture", OccurredAt: decision.DecidedAt,
	}
	return ingestPlatformAuditEvent(t, endpoint, event)
}

func ingestPlatformAuditEvent(t *testing.T, endpoint string, event auditv1.Event) auditv1.AuditRecord {
	t.Helper()
	response := performJSON(t, http.MethodPost, endpoint+"/v1/events", paasServiceCredential, event)
	var result auditv1.IngestionResult
	if response.Status != http.StatusCreated || json.Unmarshal(response.Body, &result) != nil ||
		auditv1.ValidateIngestionResult(result) != nil || result.Record.Event != event {
		t.Fatalf("platform Audit ingestion failed: status=%d", response.Status)
	}
	wrong := event
	wrong.EventID, wrong.InstallationID = "event-wrong-platform", "another-installation"
	if got := performJSON(t, http.MethodPost, endpoint+"/v1/events", paasServiceCredential, wrong); got.Status != http.StatusForbidden {
		t.Fatalf("wrong installation Audit ingestion status=%d", got.Status)
	}
	if got := performJSON(t, http.MethodPost, endpoint+"/v1/events", iamServiceCredential, event); got.Status != http.StatusForbidden {
		t.Fatalf("wrong producer purpose emitted platform PaaS event: status=%d", got.Status)
	}
	return result.Record
}

func assertPlatformAuditAccess(t *testing.T, endpoint, credential string, status int) {
	t.Helper()
	for _, query := range []struct {
		path string
		body any
	}{
		{"/v1/platform/records:query", auditv1.QueryRecordsRequest{PageSize: 20}},
		{"/v1/platform/integrity:verify", auditv1.VerifyChainRequest{FromSequence: 1, MaximumRecords: 20}},
	} {
		response := performJSON(t, http.MethodPost, endpoint+query.path, credential, query.body)
		if response.Status != status {
			t.Fatalf("platform Audit %s status=%d want=%d", query.path, response.Status, status)
		}
		if status != http.StatusOK {
			continue
		}
		if query.path == "/v1/platform/records:query" {
			var page auditv1.RecordPage
			if json.Unmarshal(response.Body, &page) != nil || auditv1.ValidateRecordPage(page) != nil ||
				page.InstallationID != "installation-process" || page.TenantID != "" || len(page.Records) == 0 {
				t.Fatal("platform Audit query lost installation authority")
			}
		} else {
			var verification auditv1.ChainVerification
			if json.Unmarshal(response.Body, &verification) != nil || auditv1.ValidateChainVerification(verification) != nil ||
				verification.InstallationID != "installation-process" || verification.TenantID != "" || verification.RecordCount == 0 {
				t.Fatal("platform Audit verification lost installation authority")
			}
		}
	}
}

func assertPlatformAuditStoredFacts(t *testing.T, ctx context.Context, admin *pgx.Conn) {
	t.Helper()
	var records, matched int
	if err := admin.QueryRow(ctx, `SELECT count(*), count(*) FILTER (
		WHERE (decision.allowed AND record.tenant_id IS NULL
		  AND decision.document->>'installationId' = record.installation_id
		  AND NOT (decision.document ? 'tenantId')
		  AND record.event_document#>>'{actor,id}' = decision.principal_id
		  AND record.event_document->>'requestId' = decision.request_id)
		 OR (record.source='IAM' AND record.event_document->>'action'='iam.installation-primary.credentials-recovered'
		  AND record.event_document#>>'{actor,type}'='SYSTEM' AND record.event_document#>>'{actor,id}'='iam-local-recovery'
		  AND NOT (record.event_document ? 'iamDecisionId') AND record.tenant_id IS NULL
		  AND recovery.installation_id=record.installation_id
		  AND recovery.primary_principal_id=record.event_document#>>'{target,id}'
		  AND recovery.tenant_id=record.event_document#>>'{target,tenantId}'
		  AND recovery.command_id=record.event_document->>'requestId'
		  AND outbox.event_document=record.event_document))
		FROM audit.records AS record LEFT JOIN iam.authorization_decisions AS decision
		  ON decision.id = record.event_document->>'iamDecisionId'
		LEFT JOIN iam.local_credential_recoveries AS recovery ON recovery.event_id=record.event_id
		LEFT JOIN iam.audit_outbox AS outbox ON outbox.tenant_id=recovery.tenant_id AND outbox.event_id=recovery.event_id
		WHERE record.installation_id = 'installation-process'`).Scan(&records, &matched); err != nil {
		t.Fatal(err)
	}
	if records < 5 || matched != records {
		t.Fatalf("platform facts lost immutable IAM correlation: records=%d matched=%d", records, matched)
	}
}

func changePasswordIAM(
	t *testing.T,
	endpoint string,
	bearer string,
	current string,
	next string,
	requestID string,
) {
	t.Helper()
	response := performJSON(t, http.MethodPost, endpoint+"/v1/auth/password", bearer, struct {
		CurrentPassword string `json:"currentPassword"`
		NewPassword     string `json:"newPassword"`
		RequestID       string `json:"requestId"`
	}{CurrentPassword: current, NewPassword: next, RequestID: requestID})
	if response.Status != http.StatusOK {
		t.Fatalf("IAM password change status=%d", response.Status)
	}
}

func createIAMUser(
	t *testing.T,
	endpoint string,
	bearer string,
	loginName string,
	displayName string,
	password string,
	requestID string,
) iamv1.User {
	t.Helper()
	response := performJSON(t, http.MethodPost, endpoint+"/v1/users", bearer, struct {
		LoginName       string `json:"loginName"`
		DisplayName     string `json:"displayName"`
		InitialPassword string `json:"initialPassword"`
		RequestID       string `json:"requestId"`
	}{LoginName: loginName, DisplayName: displayName, InitialPassword: password, RequestID: requestID})
	if response.Status != http.StatusCreated {
		t.Fatalf("create IAM user %s status=%d", loginName, response.Status)
	}
	var principal iamv1.User
	if err := json.Unmarshal(response.Body, &principal); err != nil ||
		iamv1.ValidateUser(principal) != nil {
		t.Fatalf("decode IAM user %s: %v", loginName, err)
	}
	return principal
}

func createLegacyIAMUser(
	t *testing.T,
	endpoint string,
	bearer string,
	loginName string,
	displayName string,
	password string,
	requestID string,
) iamv1.PrincipalID {
	t.Helper()
	response := performJSON(t, http.MethodPost, endpoint+"/v1/principals", bearer, struct {
		LoginName       string `json:"loginName"`
		DisplayName     string `json:"displayName"`
		InitialPassword string `json:"initialPassword"`
		RequestID       string `json:"requestId"`
	}{LoginName: loginName, DisplayName: displayName, InitialPassword: password, RequestID: requestID})
	var result struct {
		ID iamv1.PrincipalID `json:"id"`
	}
	if response.Status != http.StatusCreated || json.Unmarshal(response.Body, &result) != nil || iamv1.ValidateID("principalId", string(result.ID)) != nil {
		t.Fatalf("create retained legacy IAM user %s status=%d", loginName, response.Status)
	}
	return result.ID
}

func createIAMPolicyAttachment(
	t *testing.T,
	endpoint string,
	bearer string,
	principalID iamv1.PrincipalID,
	policy iamv1.PolicyID,
	requestID string,
) iamv1.PolicyAttachment {
	t.Helper()
	response := performJSON(t, http.MethodPost, endpoint+"/v1/policy-attachments", bearer, iamv1.CreatePolicyAttachmentRequest{Target: iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetUser, ID: string(principalID)}, PolicyID: policy, PolicyResourceVersion: 1, RequestID: requestID})
	if response.Status != http.StatusOK {
		t.Fatalf("put IAM binding status=%d", response.Status)
	}
	var binding iamv1.PolicyAttachment
	if err := json.Unmarshal(response.Body, &binding); err != nil ||
		iamv1.ValidatePolicyAttachment(binding) != nil {
		t.Fatalf("decode IAM binding: %v", err)
	}
	return binding
}

func revokeIAMPolicyAttachment(
	t *testing.T,
	endpoint string,
	bearer string,
	attachmentID iamv1.PolicyAttachmentID,
	resourceVersion uint64,
	requestID string,
) {
	t.Helper()
	response := performJSON(
		t,
		http.MethodPost,
		endpoint+"/v1/policy-attachments/"+string(attachmentID)+":revoke",
		bearer,
		iamv1.RevokePolicyAttachmentRequest{ResourceVersion: resourceVersion, RequestID: requestID},
	)
	if response.Status != http.StatusOK {
		t.Fatalf("revoke IAM binding status=%d", response.Status)
	}
}

func revokeIAMSession(
	t *testing.T,
	endpoint string,
	bearer string,
	sessionID iamv1.SessionID,
	requestID string,
) {
	t.Helper()
	response := performJSON(
		t,
		http.MethodPost,
		endpoint+"/v1/sessions/"+string(sessionID)+":revoke",
		bearer,
		iamv1.RevokeSessionRequest{RequestID: requestID},
	)
	if response.Status != http.StatusOK {
		t.Fatalf("revoke IAM session status=%d", response.Status)
	}
}

func expireIAMSession(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	sessionID iamv1.SessionID,
) {
	t.Helper()
	var expired bool
	if err := admin.QueryRow(
		ctx,
		`UPDATE iam.sessions
		    SET expires_at = issued_at + interval '1 microsecond'
		  WHERE tenant_id = 'organization-process'
		    AND id = $1
		    AND status = 'ACTIVE'
		RETURNING expires_at < transaction_timestamp()`,
		sessionID,
	).Scan(&expired); err != nil {
		t.Fatalf("expire IAM session: %v", err)
	}
	if !expired {
		t.Fatal("IAM session fixture did not expire in database time")
	}
}

func proveTenantAccountProcesses(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	endpoint string,
	replicaEndpoint string,
	auditEndpoint string,
	paasEndpoint string,
	bearer string,
	withAuditOutage func(func()),
	restartIAM func(),
) []string {
	t.Helper()
	const (
		crossTenantID = "organization-process-customer"
		initial       = "Customer-Process-Initial-Password-48!"
		changed       = "Customer-Process-Changed-Password-59!"
	)
	opened := performJSON(t, http.MethodPost, endpoint+"/v1/accounts", bearer, map[string]any{
		"id": crossTenantID, "displayName": "Process customer", "rootLoginName": "customer.primary",
		"rootDisplayName": "Customer owner", "initialPassword": initial, "requestId": "request-open-customer",
	})
	var account iamv1.Account
	if opened.Status != http.StatusCreated || json.Unmarshal(opened.Body, &account) != nil || iamv1.ValidateAccount(account) != nil {
		t.Fatalf("tenant HTTP onboarding status=%d", opened.Status)
	}
	primary := loginIAM(t, endpoint, "customer.primary", initial, "request-customer-login")
	changePasswordIAM(t, endpoint, primary.Credential, initial, changed, "request-customer-password")
	alias := performJSON(t, http.MethodPost, endpoint+"/v1/account:alias", primary.Credential, iamv1.SetAccountAliasRequest{
		Alias: "process-company", ResourceVersion: account.ResourceVersion, RequestID: "request-customer-alias",
	})
	if alias.Status != http.StatusOK {
		t.Fatalf("customer alias status=%d", alias.Status)
	}
	child := createIAMUser(t, endpoint, primary.Credential, "account.user", "Customer developer", initial, "request-customer-user")
	createIAMPolicyAttachment(t, endpoint, primary.Credential, child.ID, iamv1.SystemPolicyPaaSDeveloper, "request-customer-role")
	childLogin := loginIAM(t, endpoint, "account.user@process-company", initial, "request-customer-child-login")
	changePasswordIAM(t, endpoint, childLogin.Credential, initial, changed, "request-customer-child-password")
	operation := createPaaSApplication(t, paasEndpoint, childLogin.Credential, "application-customer-only", "customer-only", "create-customer-application", http.StatusCreated)
	if operation.Scope.TenantID != crossTenantID || operation.RequestedBy.ID != string(child.ID) {
		t.Fatal("new tenant PaaS mutation lost its IAM identity")
	}
	getPaaSApplication(t, paasEndpoint, childLogin.Credential, "application-customer-only", http.StatusOK)
	getPaaSApplication(t, paasEndpoint, bearer, "application-customer-only", http.StatusNotFound)
	response := performJSON(
		t,
		http.MethodPost,
		endpoint+"/v1/policy-attachments",
		bearer,
		iamv1.CreatePolicyAttachmentRequest{Target: iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetUser, ID: string(child.ID)}, PolicyID: iamv1.SystemPolicyAuditReader, PolicyResourceVersion: 1, RequestID: "request-process-cross-tenant-binding"},
	)
	if response.Status != http.StatusForbidden ||
		bytes.Contains(response.Body, []byte(child.ID)) ||
		bytes.Contains(response.Body, []byte("role binding principal")) {
		t.Fatalf("cross-tenant IAM binding status=%d body=%s", response.Status, response.Body)
	}
	var unauthorizedBindings int
	if err := admin.QueryRow(ctx,
		"SELECT count(*) FROM iam.policy_attachments WHERE target_id=$1 AND policy_id='system.audit-reader'",
		child.ID).Scan(&unauthorizedBindings); err != nil || unauthorizedBindings != 0 {
		t.Fatalf("cross-tenant IAM attack created bindings=%d err=%v", unauthorizedBindings, err)
	}
	waitAllIAMOutboxDelivered(t, ctx, admin)
	waitAllPaaSOutboxDelivered(t, ctx, admin)
	for _, action := range []auditv1.Action{auditv1.ActionIAMAccountAliasUpdated, auditv1.ActionIAMUserCreated, auditv1.ActionPaaSApplicationCreated} {
		page := queryAudit(t, auditEndpoint, primary.Credential, auditv1.QueryRecordsRequest{PageSize: 100, Action: action}, http.StatusOK)
		if page.TenantID != crossTenantID || len(page.Records) != 1 || page.Records[0].Event.TenantID != crossTenantID {
			t.Fatalf("new tenant audit action=%s was not delivered exactly once within its account", action)
		}
		other := queryAudit(t, auditEndpoint, bearer, auditv1.QueryRecordsRequest{PageSize: 100, Action: action}, http.StatusOK)
		for _, record := range other.Records {
			if record.Event.TenantID != "organization-process" {
				t.Fatal("bootstrap owner read another tenant's audit")
			}
		}
	}
	page := queryAudit(t, auditEndpoint, primary.Credential, auditv1.QueryRecordsRequest{PageSize: 1}, http.StatusOK)
	if page.NextCursor == "" {
		t.Fatal("new tenant audit page has no continuation")
	}
	queryAudit(t, auditEndpoint, bearer, auditv1.QueryRecordsRequest{PageSize: 1, Cursor: page.NextCursor}, http.StatusUnprocessableEntity)
	chain := verifyAudit(t, auditEndpoint, primary.Credential)
	if chain.TenantID != crossTenantID || chain.State != auditv1.VerificationVerified || !chain.Complete {
		t.Fatal("new tenant audit chain failed verification")
	}
	userProducer := performJSON(t, http.MethodPost, auditEndpoint+"/v1/events", primary.Credential, page.Records[0].Event)
	if userProducer.Status != http.StatusUnauthorized {
		t.Fatal("tenant owner gained audit producer authority")
	}
	retainedQuota, retainedDatabase, resourceSecrets := proveTenantResourceProcesses(t, ctx, admin, endpoint, auditEndpoint, paasEndpoint, bearer, primary.Credential, childLogin)
	sensitive := append(resourceSecrets, initial, changed, primary.Credential, childLogin.Credential)
	sensitive = append(sensitive, proveGroupResourceProcesses(t, ctx, admin, endpoint, replicaEndpoint, auditEndpoint, paasEndpoint, bearer, primary.Credential, withAuditOutage, restartIAM)...)
	roleOperator := loginIAM(t, endpoint, "customer.primary", changed, "process-role-operator-login")
	sensitive = append(sensitive, roleOperator.Credential)
	sensitive = append(sensitive, proveRoleManagementProcesses(t, ctx, admin, endpoint, replicaEndpoint, auditEndpoint, paasEndpoint, bearer, primary.Credential, roleOperator.Credential, withAuditOutage, restartIAM)...)
	readAccount := func(id string) iamv1.Account {
		t.Helper()
		response := performJSON(t, http.MethodGet, endpoint+"/v1/accounts/"+id, bearer, nil)
		var access iamv1.AccountAccess
		if response.Status != http.StatusOK || json.Unmarshal(response.Body, &access) != nil || iamv1.ValidateAccountAccess(access) != nil || access.Account.ID != iamv1.AccountID(id) {
			t.Fatalf("platform tenant detail status=%d", response.Status)
		}
		return access.Account
	}
	setStatus := func(id string, status iamv1.AccountStatus, expected int) {
		t.Helper()
		current := readAccount(id)
		response := performJSON(t, http.MethodPost, endpoint+"/v1/accounts/"+id+":set-status", bearer, iamv1.SetAccountStatusRequest{Status: status, ResourceVersion: current.ResourceVersion, RequestID: "request-process-tenant-status"})
		if response.Status != expected {
			t.Fatalf("set tenant status=%d want=%d", response.Status, expected)
		}
	}
	setStatus("organization-process", iamv1.AccountDisabled, http.StatusForbidden)
	var retainedApplication string
	if err := admin.QueryRow(ctx, "SELECT document::text FROM paas.applications WHERE tenant_id=$1 AND id='application-customer-only'", crossTenantID).Scan(&retainedApplication); err != nil {
		t.Fatal(err)
	}
	withAuditOutage(func() {
		createPaaSApplication(t, paasEndpoint, childLogin.Credential, "application-before-tenant-pause", "before-tenant-pause", "create-before-tenant-pause", http.StatusCreated)
		setStatus(crossTenantID, iamv1.AccountDisabled, http.StatusOK)
		createPaaSApplication(t, paasEndpoint, childLogin.Credential, "application-after-tenant-pause", "after-tenant-pause", "create-after-tenant-pause", http.StatusUnauthorized)
		assertPaaSApplicationAbsent(t, ctx, admin, "application-after-tenant-pause")
	})
	waitAllIAMOutboxDelivered(t, ctx, admin)
	waitAllPaaSOutboxDelivered(t, ctx, admin)
	_, historical := findPaaSEvent(t, ctx, admin, auditv1.ActionPaaSApplicationCreated, "application-before-tenant-pause")
	if historical.TenantID != crossTenantID || historical.Actor.ID != auditv1.ActorID(child.ID) {
		t.Fatal("paused tenant historical outbox lost identity")
	}
	replayed := performJSON(t, http.MethodPost, auditEndpoint+"/v1/events", paasServiceCredential, historical)
	var replay auditv1.IngestionResult
	if replayed.Status != http.StatusOK || json.Unmarshal(replayed.Body, &replay) != nil || replay.Outcome != auditv1.IngestionDuplicate {
		t.Fatal("suspended tenant lost committed historical audit delivery")
	}
	for _, credential := range []string{primary.Credential, childLogin.Credential} {
		if response := performJSON(t, http.MethodGet, endpoint+"/v1/auth/me", credential, nil); response.Status != http.StatusUnauthorized {
			t.Fatal("tenant suspension missed IAM")
		}
		getPaaSApplication(t, paasEndpoint, credential, "application-customer-only", http.StatusUnauthorized)
		queryAudit(t, auditEndpoint, credential, auditv1.QueryRecordsRequest{PageSize: 10}, http.StatusUnauthorized)
		for _, path := range []string{"/quota-entitlements/" + retainedQuota.ID, "/service-installations/" + retainedDatabase.ID, "/service-installations/" + retainedDatabase.ID + "/operation"} {
			if response := performJSON(t, http.MethodGet, paasEndpoint+"/managed-services/v1"+path, credential, nil); response.Status != http.StatusUnauthorized {
				t.Fatal("tenant suspension missed managed-service resource or Operation access")
			}
		}
	}
	const recoveryPassword = "Primary-Process-Recovered-Password-68!"
	current := readAccount(crossTenantID)
	recovery := performJSON(t, http.MethodPost, endpoint+"/v1/accounts/"+crossTenantID+":recover-root-credentials", bearer, map[string]any{
		"initialPassword": recoveryPassword, "resourceVersion": current.ResourceVersion, "requestId": "request-process-primary-recovery"})
	if recovery.Status != http.StatusOK {
		t.Fatalf("recover paused tenant primary status=%d", recovery.Status)
	}
	restartIAM()
	if readAccount(crossTenantID).Status != iamv1.AccountDisabled {
		t.Fatal("recovery or equal-bootstrap restart revived tenant")
	}
	if response := performJSON(t, http.MethodPost, endpoint+"/v1/auth/login", "", map[string]any{"loginName": "customer.primary", "password": recoveryPassword, "requestId": "request-paused-primary-login"}); response.Status != http.StatusUnauthorized {
		t.Fatal("recovered primary bypassed tenant suspension")
	}
	setStatus(crossTenantID, iamv1.AccountActive, http.StatusOK)
	getPaaSApplication(t, paasEndpoint, childLogin.Credential, "application-customer-only", http.StatusUnauthorized)
	if response := performJSON(t, http.MethodPost, endpoint+"/v1/auth/login", "", map[string]any{"loginName": "customer.primary", "password": changed, "requestId": "request-old-primary-login"}); response.Status != http.StatusUnauthorized {
		t.Fatal("primary recovery retained old password")
	}
	primary = loginIAM(t, endpoint, "customer.primary", recoveryPassword, "request-recovered-primary-login")
	sensitive = append(sensitive, recoveryPassword, primary.Credential)
	createPaaSApplication(t, paasEndpoint, primary.Credential, "application-before-recovery-change", "before-recovery-change", "create-before-recovery-change", http.StatusForbidden)
	changePasswordIAM(t, endpoint, primary.Credential, recoveryPassword, changed, "request-recovered-primary-password")
	getPaaSApplication(t, paasEndpoint, primary.Credential, "application-customer-only", http.StatusOK)
	getPaaSApplication(t, paasEndpoint, bearer, "application-customer-only", http.StatusNotFound)
	childLogin = loginIAM(t, endpoint, "account.user@process-company", changed, "request-resumed-child-login")
	sensitive = append(sensitive, childLogin.Credential)
	memberDisabled := performJSON(t, http.MethodPost, endpoint+"/v1/users/"+string(child.ID)+":set-status", primary.Credential, iamv1.SetUserStatusRequest{Status: iamv1.PrincipalDisabled, ResourceVersion: 2, RequestID: "request-process-creator-disabled"})
	var disabledMember iamv1.User
	if memberDisabled.Status != http.StatusOK || json.Unmarshal(memberDisabled.Body, &disabledMember) != nil ||
		iamv1.ValidateUser(disabledMember) != nil || disabledMember.Status != iamv1.PrincipalDisabled {
		t.Fatalf("disable resource creator status=%d", memberDisabled.Status)
	}
	memberDeleted := performJSON(t, http.MethodPost, endpoint+"/v1/users/"+string(child.ID)+":delete", primary.Credential,
		iamv1.DeleteUserRequest{ResourceVersion: disabledMember.ResourceVersion, RequestID: "request-process-creator-deleted"})
	var deletion iamv1.UserDeletion
	if memberDeleted.Status != http.StatusOK || json.Unmarshal(memberDeleted.Body, &deletion) != nil ||
		iamv1.ValidateUserDeletion(deletion) != nil || deletion.ID != child.ID || deletion.AccountID != crossTenantID {
		t.Fatalf("delete resource creator status=%d", memberDeleted.Status)
	}
	getPaaSApplication(t, paasEndpoint, childLogin.Credential, "application-customer-only", http.StatusUnauthorized)
	getPaaSApplication(t, paasEndpoint, primary.Credential, "application-customer-only", http.StatusOK)
	assertManagedServiceRetained(t, paasEndpoint, primary.Credential, retainedQuota, retainedDatabase)
	var retainedManagedActor string
	if err := admin.QueryRow(ctx, "SELECT requested_by_id FROM managedservice.operations WHERE tenant_id=$1 AND id=$2", crossTenantID, retainedDatabase.Operation.ID).Scan(&retainedManagedActor); err != nil || retainedManagedActor != string(child.ID) {
		t.Fatal("identity lifecycle changed database Operation tenant or creator")
	}
	var unchanged bool
	if err := admin.QueryRow(ctx, "SELECT document::text=$2 FROM paas.applications WHERE tenant_id=$1 AND id='application-customer-only'", crossTenantID, retainedApplication).Scan(&unchanged); err != nil || !unchanged {
		t.Fatal("identity lifecycle changed tenant resource ownership or content")
	}
	operationResponse := performJSON(t, http.MethodGet, paasEndpoint+"/v1/operations/"+string(operation.ID), primary.Credential, nil)
	var retainedOperation paasv1.Operation
	if operationResponse.Status != http.StatusOK || json.Unmarshal(operationResponse.Body, &retainedOperation) != nil || retainedOperation.Scope.TenantID != crossTenantID || retainedOperation.RequestedBy.ID != string(child.ID) {
		t.Fatal("creator suspension changed accepted Operation ownership")
	}
	if response := performJSON(t, http.MethodGet, paasEndpoint+"/v1/operations/"+string(operation.ID), bearer, nil); response.Status != http.StatusNotFound {
		t.Fatal("platform identity read another tenant's Operation")
	}
	waitAllIAMOutboxDelivered(t, ctx, admin)
	deletionRecords := queryAudit(t, auditEndpoint, primary.Credential, auditv1.QueryRecordsRequest{PageSize: 100, Action: auditv1.ActionIAMUserDeleted}, http.StatusOK)
	if deletionRecords.TenantID != crossTenantID || len(deletionRecords.Records) != 1 ||
		deletionRecords.Records[0].Event.Target.ID != string(child.ID) || deletionRecords.Records[0].Event.TenantID != crossTenantID {
		t.Fatal("resource creator deletion lost its tenant audit identity")
	}
	for _, action := range []auditv1.Action{auditv1.ActionIAMAccountCreated, auditv1.ActionIAMAccountDisabled, auditv1.ActionIAMAccountEnabled, auditv1.ActionIAMAccountRootCredentialsRecovered} {
		response := performJSON(t, http.MethodPost, auditEndpoint+"/v1/platform/records:query", bearer, auditv1.QueryRecordsRequest{PageSize: 100, Action: action})
		var records auditv1.RecordPage
		if response.Status != http.StatusOK || json.Unmarshal(response.Body, &records) != nil || len(records.Records) != 1 || records.InstallationID != "installation-process" || records.TenantID != "" {
			t.Fatalf("lifecycle platform audit action=%s status=%d", action, response.Status)
		}
		event := records.Records[0].Event
		if action == auditv1.ActionIAMAccountRootCredentialsRecovered && (event.Target.TenantID != crossTenantID || event.Target.ID != string(account.RootIdentity.PrincipalID)) {
			t.Fatal("delivered recovery fact substituted its primary tenant")
		}
	}
	assertPlatformAuditAccess(t, auditEndpoint, primary.Credential, http.StatusForbidden)
	chain = verifyAudit(t, auditEndpoint, primary.Credential)
	if chain.TenantID != crossTenantID || !chain.Complete {
		t.Fatal("recovery broke original tenant audit chain")
	}
	setStatus(crossTenantID, iamv1.AccountDisabled, http.StatusOK)
	restartIAM()
	getPaaSApplication(t, paasEndpoint, primary.Credential, "application-customer-only", http.StatusUnauthorized)
	if readAccount(crossTenantID).Status != iamv1.AccountDisabled {
		t.Fatal("restart revived paused tenant access")
	}
	return sensitive
}

// These are real application resources, database-service records and reserved
// quota. The local provisioner gate separately proves a running engine.
func proveRoleManagementProcesses(t *testing.T, ctx context.Context, admin *pgx.Conn, iamEndpoint, replicaEndpoint, auditEndpoint, paasEndpoint, homeBearer, ownerBearer, roleBearer string,
	withAuditOutage func(func()), restartIAM func()) []string {
	t.Helper()
	const tenant = "organization-process-customer"
	call := func(method, endpoint, path, bearer string, body any, want int, result any) {
		t.Helper()
		response := performJSON(t, method, endpoint+path, bearer, body)
		if response.Status != want {
			t.Fatalf("role process %s %s status=%d want=%d", method, path, response.Status, want)
		}
		if result != nil {
			reflect.ValueOf(result).Elem().SetZero()
			decoder := json.NewDecoder(bytes.NewReader(response.Body))
			decoder.DisallowUnknownFields()
			if decoder.Decode(result) != nil {
				t.Fatal("role process returned an invalid contract")
			}
		}
	}
	user := createIAMUser(t, iamEndpoint, ownerBearer, "role.candidate", "Role candidate", initialDeveloperPassword, "process-role-user")
	member := loginIAM(t, iamEndpoint, "role.candidate@"+tenant, initialDeveloperPassword, "process-role-user-login")
	changePasswordIAM(t, iamEndpoint, member.Credential, initialDeveloperPassword, changedDeveloperPassword, "process-role-user-password")
	trust := iamv1.TrustPolicyDocument{LanguageVersion: "1", Statements: []iamv1.TrustPolicyStatement{{SID: "candidate", Effect: iamv1.PolicyAllow,
		Principals: []iamv1.TrustPrincipal{{Type: iamv1.PrincipalUser, ID: user.ID}}}}}
	empty := iamv1.TrustPolicyDocument{LanguageVersion: "1", Statements: []iamv1.TrustPolicyStatement{}}
	create := iamv1.CreateRoleRequest{Name: "Application readers", Tags: []iamv1.RoleTag{}, TrustPolicy: empty, RequestID: "process-role-create"}
	var home, role, replay iamv1.Role
	var issued iamv1.AssumeRoleResponse
	roleCredential := ""
	call(http.MethodPost, iamEndpoint, "/v1/roles", homeBearer, create, http.StatusCreated, &home)
	create.TrustPolicy = trust
	var actor iamv1.CurrentIdentity
	call(http.MethodGet, iamEndpoint, "/v1/auth/me", roleBearer, nil, http.StatusOK, &actor)
	// This workload is authorized as the USER owner, never by the unissued Role.
	operation := createPaaSApplication(t, paasEndpoint, ownerBearer, "application-role-unrelated", "role-unrelated", "process-role-owner-application", http.StatusCreated)
	withAuditOutage(func() {
		call(http.MethodPost, iamEndpoint, "/v1/roles", roleBearer, create, http.StatusCreated, &role)
		call(http.MethodPost, replicaEndpoint, "/v1/roles", roleBearer, create, http.StatusCreated, &replay)
		if iamv1.ValidateRole(role) != nil || !reflect.DeepEqual(role, replay) || role.ID == home.ID || role.AccountID != tenant || home.AccountID != "organization-process" || role.Name != home.Name {
			t.Fatal("role process create/replay mixed account identity")
		}
		path := "/v1/roles/" + string(role.ID)
		for _, endpoint := range []string{iamEndpoint, replicaEndpoint} {
			call(http.MethodGet, endpoint, path, homeBearer, nil, http.StatusForbidden, nil)
			call(http.MethodGet, endpoint, "/v1/roles/"+string(home.ID), ownerBearer, nil, http.StatusForbidden, nil)
			var access iamv1.RoleAccess
			call(http.MethodGet, endpoint, path, ownerBearer, nil, http.StatusOK, &access)
			if iamv1.ValidateRoleAccess(access) != nil || len(access.PolicyAttachments) != 0 || len(access.TrustVersion.Document.Statements) != 1 {
				t.Fatal("replica role did not preserve precise empty permission/trust state")
			}
		}
		var attachment iamv1.PolicyAttachment
		grant := iamv1.CreatePolicyAttachmentRequest{Target: iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetRole, ID: string(role.ID)},
			PolicyID: iamv1.SystemPolicyPaaSDeveloper, PolicyResourceVersion: 1, RequestID: "process-role-grant"}
		call(http.MethodPost, iamEndpoint, "/v1/policy-attachments", roleBearer, grant, http.StatusOK, &attachment)
		if iamv1.ValidatePolicyAttachment(attachment) != nil || attachment.Target != grant.Target || attachment.Scope != iamv1.AuthorityScopeTenant {
			t.Fatal("role attachment lost its explicit tenant/ROLE discriminator")
		}
		// Merely trusting a user must not merge Role permissions into LoginSession.
		getPaaSApplication(t, paasEndpoint, member.Credential, operation.Target.ID, http.StatusForbidden)
		createPaaSApplication(t, paasEndpoint, member.Credential, "application-role-implicit-denied", "role-implicit-denied", "process-role-no-implicit-assume", http.StatusForbidden)
		assertPaaSApplicationAbsent(t, ctx, admin, "application-role-implicit-denied")
		call(http.MethodGet, iamEndpoint, "/v1/auth/me", string(role.ID), nil, http.StatusUnauthorized, nil)
		call(http.MethodPost, iamEndpoint, "/v1/sts/assume-role", member.Credential, map[string]any{"roleId": role.ID, "requestId": "process-role-not-issued"}, http.StatusNotFound, nil)
		var boundary iamv1.RolePermissionBoundary
		call(http.MethodGet, replicaEndpoint, path+"/permission-boundary", roleBearer, nil, http.StatusOK, &boundary)
		if boundary.Policy != nil {
			t.Fatal("new role has an implicit boundary")
		}
		call(http.MethodPut, iamEndpoint, path+"/permission-boundary", roleBearer, iamv1.SetRolePermissionBoundaryRequest{PolicyID: iamv1.SystemPolicyPaaSViewer,
			PolicyResourceVersion: 1, ResourceVersion: role.ResourceVersion, RequestID: "process-role-boundary-set"}, http.StatusOK, &boundary)
		if boundary.Policy == nil || boundary.Policy.PolicyID != iamv1.SystemPolicyPaaSViewer {
			t.Fatal("role boundary write lost its selected ceiling")
		}
		var sourceGrant iamv1.PolicyAttachment
		call(http.MethodPost, iamEndpoint, "/v1/policy-attachments", roleBearer, iamv1.CreatePolicyAttachmentRequest{
			Target: iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetUser, ID: string(user.ID)}, PolicyID: iamv1.SystemPolicyAccountAdministrator,
			PolicyResourceVersion: 1, RequestID: "process-role-assume-grant"}, http.StatusOK, &sourceGrant)
		assume := iamv1.AssumeRoleRequest{ResourceVersion: boundary.ResourceVersion, RequestID: "process-role-session-issue"}
		call(http.MethodPost, iamEndpoint, path+":assume", member.Credential, assume, http.StatusOK, &issued)
		if iamv1.ValidateAssumeRoleResponse(issued) != nil || issued.Outcome != "APPLIED" {
			t.Fatal("role process did not issue one credential")
		}
		credentialBytes := issued.Credential.CopyBytes()
		roleCredential = string(credentialBytes)
		clear(credentialBytes)
		var equal iamv1.AssumeRoleResponse
		call(http.MethodPost, replicaEndpoint, path+":assume", member.Credential, assume, http.StatusOK, &equal)
		if equal.Outcome != "EQUAL_REPLAY" || equal.Credential.Present() || !reflect.DeepEqual(equal.Session, issued.Session) {
			t.Fatal("replica reissued or replaced role credential")
		}
		call(http.MethodGet, replicaEndpoint, "/v1/auth/me", roleCredential, nil, http.StatusUnauthorized, nil)
		for _, endpoint := range []string{iamEndpoint, replicaEndpoint} {
			var current iamv1.RoleSession
			call(http.MethodGet, endpoint, "/v1/auth/role-session", roleCredential, nil, http.StatusOK, &current)
			if !reflect.DeepEqual(current, issued.Session) {
				t.Fatal("replica role identity differs")
			}
		}
		getPaaSApplication(t, paasEndpoint, roleCredential, operation.Target.ID, http.StatusOK)
		createPaaSApplication(t, paasEndpoint, roleCredential, "application-readonly-role-denied", "readonly-role-denied", "readonly-role-create", http.StatusForbidden)
		assertPaaSApplicationAbsent(t, ctx, admin, "application-readonly-role-denied")
		call(http.MethodPost, replicaEndpoint, "/v1/policy-attachments/"+string(sourceGrant.ID)+":revoke", roleBearer,
			iamv1.RevokePolicyAttachmentRequest{ResourceVersion: sourceGrant.ResourceVersion, RequestID: "process-role-assume-revoke"}, http.StatusOK, nil)
		for _, endpoint := range []string{iamEndpoint, replicaEndpoint} {
			call(http.MethodGet, endpoint, "/v1/auth/role-session", roleCredential, nil, http.StatusUnauthorized, nil)
		}
		var own iamv1.RoleSession
		intentPath := "/v1/auth/role-sessions/by-request/process-role-session-issue"
		call(http.MethodGet, iamEndpoint, intentPath, member.Credential, nil, http.StatusOK, &own)
		call(http.MethodGet, replicaEndpoint, intentPath, ownerBearer, nil, http.StatusNotFound, nil)
		call(http.MethodPost, replicaEndpoint, intentPath+":revoke", member.Credential, iamv1.RevokeRoleSessionRequest{RequestID: "process-role-session-revoke"}, http.StatusOK, &own)
		if own.Status != iamv1.SessionRevoked || own.ID != issued.Session.ID {
			t.Fatal("role source could not revoke its original issuance")
		}
		call(http.MethodDelete, replicaEndpoint, path+"/permission-boundary", roleBearer, iamv1.RemoveRolePermissionBoundaryRequest{ResourceVersion: boundary.ResourceVersion, RequestID: "process-role-boundary-remove"}, http.StatusOK, &boundary)
		if boundary.Policy != nil {
			t.Fatal("role boundary removal retained a ceiling")
		}
		role.ResourceVersion = boundary.ResourceVersion
		call(http.MethodPatch, replicaEndpoint, path, roleBearer, iamv1.UpdateRoleRequest{Name: role.Name, Description: "Current managed role", Tags: []iamv1.RoleTag{}, MaxSessionDurationSeconds: 900,
			ResourceVersion: role.ResourceVersion, RequestID: "process-role-update"}, http.StatusOK, &role)
		call(http.MethodPost, iamEndpoint, path+":set-status", roleBearer, iamv1.SetRoleStatusRequest{Status: iamv1.RoleDisabled, ResourceVersion: role.ResourceVersion, RequestID: "process-role-disable"}, http.StatusOK, &role)
		call(http.MethodPost, replicaEndpoint, path+":set-status", roleBearer, iamv1.SetRoleStatusRequest{Status: iamv1.RoleActive, ResourceVersion: role.ResourceVersion, RequestID: "process-role-enable"}, http.StatusOK, &role)
		call(http.MethodPut, iamEndpoint, path+"/trust-policy", roleBearer, iamv1.SetRoleTrustPolicyRequest{Document: empty, ResourceVersion: role.ResourceVersion, RequestID: "process-role-trust"}, http.StatusOK, &role)
		var history iamv1.RoleTrustVersionList
		call(http.MethodGet, replicaEndpoint, path+"/trust-versions", ownerBearer, nil, http.StatusOK, &history)
		if iamv1.ValidateRoleTrustVersionList(history) != nil || len(history.Items) != 2 {
			t.Fatal("role process rewrote its original immutable trust")
		}
		remove := iamv1.DeleteRoleRequest{ResourceVersion: role.ResourceVersion, RequestID: "process-role-delete"}
		var deletion, repeated iamv1.RoleDeletion
		call(http.MethodDelete, replicaEndpoint, path, roleBearer, remove, http.StatusOK, &deletion)
		call(http.MethodDelete, iamEndpoint, path, roleBearer, remove, http.StatusOK, &repeated)
		if iamv1.ValidateRoleDeletion(deletion) != nil || deletion != repeated || deletion.RevokedPolicyAttachments != 1 {
			t.Fatal("role deletion did not atomically close its attachment once")
		}
		call(http.MethodPost, iamEndpoint, "/v1/auth/logout", roleBearer, map[string]any{"requestId": "process-role-operator-logout"}, http.StatusOK, nil)
		call(http.MethodPost, replicaEndpoint, "/v1/auth/logout", member.Credential, map[string]any{"requestId": "process-role-source-logout"}, http.StatusOK, nil)
		call(http.MethodGet, replicaEndpoint, "/v1/auth/me", roleBearer, nil, http.StatusUnauthorized, nil)
	})
	// Delivery uses committed IAM facts, not the now-revoked original session.
	waitAllIAMOutboxDelivered(t, ctx, admin)
	waitAllPaaSOutboxDelivered(t, ctx, admin)
	for _, action := range []auditv1.Action{auditv1.ActionIAMRoleCreated, auditv1.ActionIAMRoleUpdated, auditv1.ActionIAMRoleDisabled, auditv1.ActionIAMRoleEnabled, auditv1.ActionIAMRoleTrustSet, auditv1.ActionIAMRoleDeleted,
		auditv1.ActionIAMRolePermissionBoundarySet, auditv1.ActionIAMRolePermissionBoundaryRemoved} {
		page := queryAudit(t, auditEndpoint, ownerBearer, auditv1.QueryRecordsRequest{PageSize: 100, Action: action}, http.StatusOK)
		if page.TenantID != tenant || len(page.Records) != 1 || page.NextCursor != "" {
			t.Fatalf("role action %s did not append exactly one tenant fact", action)
		}
		event := page.Records[0].Event
		if page.Records[0].Source != auditv1.SourceIAM || event.Target.Kind != auditv1.TargetRole || event.Target.ID != string(role.ID) || event.Actor.Type != auditv1.ActorUser || event.Actor.ID != auditv1.ActorID(actor.User.ID) || event.IAMDecisionID == "" || event.InstallationID != "" {
			t.Fatal("role fact changed current tenant, USER or final target proof")
		}
		var ingested auditv1.IngestionResult
		call(http.MethodPost, auditEndpoint, "/v1/events", iamServiceCredential, event, http.StatusOK, &ingested)
		if ingested.Outcome != auditv1.IngestionDuplicate {
			t.Fatal("role history replay appended after its originating session was revoked")
		}
		forged := event
		forged.Target.ID = string(home.ID)
		call(http.MethodPost, auditEndpoint, "/v1/events", iamServiceCredential, forged, http.StatusForbidden, nil)
		forged = event
		forged.TenantID = "organization-process"
		call(http.MethodPost, auditEndpoint, "/v1/events", iamServiceCredential, forged, http.StatusForbidden, nil)
	}
	for _, action := range []auditv1.Action{auditv1.ActionIAMRoleSessionIssued, auditv1.ActionIAMRoleSessionRevoked} {
		page := queryAudit(t, auditEndpoint, ownerBearer, auditv1.QueryRecordsRequest{PageSize: 100, Action: action}, http.StatusOK)
		if page.TenantID != tenant || len(page.Records) != 1 {
			t.Fatal("role issuance fact did not reach its tenant chain", action)
		}
		event := page.Records[0].Event
		if event.Actor.Type != auditv1.ActorUser || event.Actor.ID != auditv1.ActorID(user.ID) || event.Target.Kind != auditv1.TargetRoleSession ||
			event.Target.ID != string(issued.Session.ID) || (event.IAMDecisionID != "") != (action == auditv1.ActionIAMRoleSessionIssued) {
			t.Fatal("role issuance history changed actor or original decision")
		}
		var duplicate auditv1.IngestionResult
		call(http.MethodPost, auditEndpoint, "/v1/events", iamServiceCredential, event, http.StatusOK, &duplicate)
		if duplicate.Outcome != auditv1.IngestionDuplicate {
			t.Fatal("role receipt replay appended a second historical fact")
		}
		event.Target.ID = "role-session-forged"
		call(http.MethodPost, auditEndpoint, "/v1/events", iamServiceCredential, event, http.StatusForbidden, nil)
	}
	restartIAM()
	for _, endpoint := range []string{iamEndpoint, replicaEndpoint} {
		call(http.MethodGet, endpoint, "/v1/roles/"+string(role.ID), ownerBearer, nil, http.StatusForbidden, nil)
		call(http.MethodPost, endpoint, "/v1/roles", ownerBearer, create, http.StatusConflict, nil)
		call(http.MethodGet, endpoint, "/v1/roles/"+string(home.ID), homeBearer, nil, http.StatusOK, nil)
		call(http.MethodGet, endpoint, "/v1/auth/me", roleBearer, nil, http.StatusUnauthorized, nil)
	}
	currentSource := loginIAM(t, replicaEndpoint, "role.candidate@"+tenant, changedDeveloperPassword, "process-role-source-relogin")
	var retainedSession iamv1.RoleSession
	call(http.MethodGet, iamEndpoint, "/v1/auth/role-sessions/by-request/process-role-session-issue", currentSource.Credential, nil, http.StatusOK, &retainedSession)
	call(http.MethodGet, iamEndpoint, "/v1/auth/role-session", roleCredential, nil, http.StatusUnauthorized, nil)
	if retainedSession.Status != iamv1.SessionRevoked || retainedSession.ID != issued.Session.ID {
		t.Fatal("IAM restart revived or lost the original role receipt")
	}
	getPaaSApplication(t, paasEndpoint, ownerBearer, operation.Target.ID, http.StatusOK)
	var retained paasv1.Operation
	call(http.MethodGet, paasEndpoint, "/v1/operations/"+string(operation.ID), ownerBearer, nil, http.StatusOK, &retained)
	if retained.Scope != operation.Scope || retained.RequestedBy != operation.RequestedBy {
		t.Fatal("role deletion changed accepted USER workload/Operation ownership")
	}
	chain := verifyAudit(t, auditEndpoint, ownerBearer)
	if chain.TenantID != tenant || chain.State != auditv1.VerificationVerified || !chain.Complete {
		t.Fatal("role lifecycle broke the immutable tenant chain")
	}
	sensitive := []string{member.Credential, roleCredential, currentSource.Credential}
	return append(sensitive, proveRoleBusinessProcesses(t, ctx, admin, iamEndpoint, replicaEndpoint, auditEndpoint, paasEndpoint, homeBearer, ownerBearer, currentSource.Credential, user, withAuditOutage, restartIAM)...)
}

func proveRoleBusinessProcesses(t *testing.T, ctx context.Context, admin *pgx.Conn, iamEndpoint, replicaEndpoint, auditEndpoint, paasEndpoint, homeBearer, ownerBearer, sourceBearer string,
	user iamv1.User, withAuditOutage func(func()), restartIAM func()) []string {
	t.Helper()
	call := func(method, endpoint, path, bearer string, body any, want int, result any) {
		t.Helper()
		response := performJSON(t, method, endpoint+path, bearer, body)
		if response.Status != want || result != nil && json.Unmarshal(response.Body, result) != nil {
			t.Fatalf("role business %s %s status=%d want=%d", method, path, response.Status, want)
		}
	}
	var role iamv1.Role
	call(http.MethodPost, iamEndpoint, "/v1/roles", ownerBearer, iamv1.CreateRoleRequest{Name: "Business session", Tags: []iamv1.RoleTag{}, RequestID: "role-business-create",
		TrustPolicy: iamv1.TrustPolicyDocument{LanguageVersion: "1", Statements: []iamv1.TrustPolicyStatement{{SID: "source", Effect: iamv1.PolicyAllow,
			Principals: []iamv1.TrustPrincipal{{Type: iamv1.PrincipalUser, ID: user.ID}}}}}}, http.StatusCreated, &role)
	path := "/v1/roles/" + string(role.ID)
	for index, policy := range []iamv1.PolicyID{iamv1.SystemPolicyPaaSDeveloper, iamv1.SystemPolicyAuditReader} {
		call(http.MethodPost, iamEndpoint, "/v1/policy-attachments", ownerBearer, iamv1.CreatePolicyAttachmentRequest{
			Target: iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetRole, ID: string(role.ID)}, PolicyID: policy, PolicyResourceVersion: 1,
			RequestID: fmt.Sprintf("role-business-grant-%d", index)}, http.StatusOK, nil)
	}
	var sourceGrant iamv1.PolicyAttachment
	call(http.MethodPost, iamEndpoint, "/v1/policy-attachments", ownerBearer, iamv1.CreatePolicyAttachmentRequest{
		Target: iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetUser, ID: string(user.ID)}, PolicyID: iamv1.SystemPolicyAccountAdministrator,
		PolicyResourceVersion: 1, RequestID: "role-business-assume-grant"}, http.StatusOK, &sourceGrant)
	var boundary iamv1.RolePermissionBoundary
	call(http.MethodPut, iamEndpoint, path+"/permission-boundary", ownerBearer, iamv1.SetRolePermissionBoundaryRequest{PolicyID: iamv1.SystemPolicyAccountAdministrator,
		PolicyResourceVersion: 1, ResourceVersion: role.ResourceVersion, RequestID: "role-business-boundary"}, http.StatusOK, &boundary)
	issue := func(endpoint, requestID string) (iamv1.RoleSession, string) {
		t.Helper()
		var response iamv1.AssumeRoleResponse
		call(http.MethodPost, endpoint, path+":assume", sourceBearer, iamv1.AssumeRoleRequest{ResourceVersion: boundary.ResourceVersion, RequestID: requestID}, http.StatusOK, &response)
		if iamv1.ValidateAssumeRoleResponse(response) != nil || response.Outcome != "APPLIED" {
			t.Fatal("real business role was not issued")
		}
		secret := response.Credential.CopyBytes()
		defer clear(secret)
		return response.Session, string(secret)
	}
	session, credential := issue(iamEndpoint, "role-business-session-one")
	otherSession, otherCredential := issue(replicaEndpoint, "role-business-session-two")
	actor := paasv1.SubjectRef{Type: paasv1.SubjectRole, ID: string(role.ID), RoleSession: &paasv1.RoleSessionReference{SessionID: string(session.ID), SourceUserID: string(user.ID)}}
	first := createPaaSApplication(t, paasEndpoint, credential, "application-role-business-one", "role-business-one", "role-business-one", http.StatusCreated)
	second := createPaaSApplication(t, paasEndpoint, credential, "application-role-business-two", "role-business-two", "role-business-two", http.StatusCreated)
	for _, operation := range []paasv1.Operation{first, second} {
		if operation.Scope.TenantID != paasv1.TenantID(user.AccountID) || !operation.RequestedBy.Equal(actor) {
			t.Fatal("Operation replaced role session with source USER or lost tenant ownership")
		}
		var stored paasv1.Operation
		call(http.MethodGet, paasEndpoint, "/v1/operations/"+string(operation.ID), otherCredential, nil, http.StatusOK, &stored)
		if !stored.RequestedBy.Equal(actor) {
			t.Fatal("querying Operation as another session rewrote its original actor")
		}
		getPaaSApplication(t, paasEndpoint, homeBearer, operation.Target.ID, http.StatusNotFound)
	}
	replayed := createPaaSApplication(t, paasEndpoint, credential, first.Target.ID, "role-business-one", "role-business-one", http.StatusOK)
	if replayed.ID != first.ID || !replayed.RequestedBy.Equal(actor) {
		t.Fatal("exact role session lost business idempotency")
	}
	createPaaSApplication(t, paasEndpoint, otherCredential, first.Target.ID, "role-business-one", "role-business-one", http.StatusConflict)
	configuration := performJSONWithIdempotency(t, http.MethodPost, paasEndpoint+"/v1/configurations", credential, "role-business-configuration",
		paasv1.CreateConfigurationRequest{ID: "configuration-role-business", Name: "role-configuration", ApplicationID: first.Target.ID})
	var configured paasv1.Operation
	if configuration.Status != http.StatusCreated || json.Unmarshal(configuration.Body, &configured) != nil || !configured.RequestedBy.Equal(actor) {
		t.Fatal("role configuration creation lost actor or authority")
	}
	call(http.MethodGet, iamEndpoint, "/v1/users", credential, nil, http.StatusUnauthorized, nil)
	assertPlatformAuditAccess(t, auditEndpoint, credential, http.StatusForbidden)
	call(http.MethodGet, paasEndpoint, "/managed-services/v1/quota-entitlements", credential, nil, http.StatusForbidden, nil)
	waitAllIAMOutboxDelivered(t, ctx, admin)
	waitAllPaaSOutboxDelivered(t, ctx, admin)
	auditActor := auditv1.ActorReference{Type: auditv1.ActorRole, ID: auditv1.ActorID(role.ID), RoleSession: &auditv1.RoleSessionReference{SessionID: string(session.ID), SourceUserID: auditv1.ActorID(user.ID)}}
	query := auditv1.QueryRecordsRequest{PageSize: 1, Action: auditv1.ActionPaaSApplicationCreated, Actor: &auditActor}
	page := queryAudit(t, auditEndpoint, credential, query, http.StatusOK)
	if len(page.Records) != 1 || page.NextCursor == "" || !page.Records[0].Event.Actor.Equal(auditActor) {
		t.Fatal("real role Audit query lost its exact actor page")
	}
	query.Cursor = page.NextCursor
	queryAudit(t, auditEndpoint, homeBearer, query, http.StatusUnprocessableEntity)
	changed := query
	changed.Actor = &auditv1.ActorReference{Type: auditv1.ActorRole, ID: auditv1.ActorID(role.ID), RoleSession: &auditv1.RoleSessionReference{SessionID: string(otherSession.ID), SourceUserID: auditv1.ActorID(user.ID)}}
	queryAudit(t, auditEndpoint, otherCredential, changed, http.StatusUnprocessableEntity)
	last := queryAudit(t, auditEndpoint, credential, query, http.StatusOK)
	if len(last.Records) != 1 || last.NextCursor != "" || !last.Records[0].Event.Actor.Equal(auditActor) || last.Records[0].Event.EventID == page.Records[0].Event.EventID {
		t.Fatal("role actor pagination duplicated or crossed session filters")
	}
	exitRequest := iamv1.LogoutRequest{RequestID: "role-business-self-exit"}
	var exited iamv1.RoleSession
	withAuditOutage(func() {
		createPaaSApplication(t, paasEndpoint, credential, "application-role-business-delayed", "role-delayed", "role-business-delayed", http.StatusCreated)
		call(http.MethodPost, replicaEndpoint, "/v1/policy-attachments/"+string(sourceGrant.ID)+":revoke", ownerBearer,
			iamv1.RevokePolicyAttachmentRequest{ResourceVersion: sourceGrant.ResourceVersion, RequestID: "role-business-source-revoke"}, http.StatusOK, nil)
		for _, bearer := range []string{credential, otherCredential} {
			getPaaSApplication(t, paasEndpoint, bearer, first.Target.ID, http.StatusUnauthorized)
			for _, endpoint := range []string{iamEndpoint, replicaEndpoint} {
				call(http.MethodGet, endpoint, "/v1/auth/role-session", bearer, nil, http.StatusUnauthorized, nil)
			}
		}
		// Lost current source authority does not prevent destroying this exact
		// credential, and a delayed IAM fact does not need a fabricated decision.
		call(http.MethodPost, replicaEndpoint, "/v1/auth/role-session:logout", credential, exitRequest, http.StatusOK, &exited)
		if exited.ID != session.ID || exited.Status != iamv1.SessionRevoked || exited.RevokedAt == nil {
			t.Fatal("revoked business identity could not exit its exact role session")
		}
	})
	waitAllIAMOutboxDelivered(t, ctx, admin)
	waitAllPaaSOutboxDelivered(t, ctx, admin)
	_, historical := findPaaSEvent(t, ctx, admin, auditv1.ActionPaaSApplicationCreated, "application-role-business-delayed")
	if !historical.Actor.Equal(auditActor) {
		t.Fatal("delayed role fact changed its original actor")
	}
	var duplicate auditv1.IngestionResult
	call(http.MethodPost, auditEndpoint, "/v1/events", paasServiceCredential, historical, http.StatusOK, &duplicate)
	if duplicate.Outcome != auditv1.IngestionDuplicate || !duplicate.Record.Event.Equal(historical) {
		t.Fatal("post-revocation role business replay changed history")
	}
	forged := historical
	forged.Actor = *changed.Actor
	call(http.MethodPost, auditEndpoint, "/v1/events", paasServiceCredential, forged, http.StatusForbidden, nil)
	queryAudit(t, auditEndpoint, credential, auditv1.QueryRecordsRequest{PageSize: 1}, http.StatusUnauthorized)
	exitPage := queryAudit(t, auditEndpoint, ownerBearer, auditv1.QueryRecordsRequest{PageSize: 10, Action: auditv1.ActionIAMRoleSessionExited, Actor: &auditActor}, http.StatusOK)
	if len(exitPage.Records) != 1 || exitPage.Records[0].Event.Target.ID != string(session.ID) || exitPage.Records[0].Event.IAMDecisionID != "" {
		t.Fatal("independent IAM dispatcher did not deliver one exact role self-exit")
	}
	exitFact := exitPage.Records[0].Event
	var exitDuplicate auditv1.IngestionResult
	call(http.MethodPost, auditEndpoint, "/v1/events", iamServiceCredential, exitFact, http.StatusOK, &exitDuplicate)
	if exitDuplicate.Outcome != auditv1.IngestionDuplicate || !exitDuplicate.Record.Event.Equal(exitFact) {
		t.Fatal("historical role self-exit duplicate changed its actor or chain")
	}
	forgedExit := exitFact
	lineage := *forgedExit.Actor.RoleSession
	lineage.SessionID, forgedExit.Target.ID = string(otherSession.ID), string(otherSession.ID)
	forgedExit.Actor.RoleSession = &lineage
	call(http.MethodPost, auditEndpoint, "/v1/events", iamServiceCredential, forgedExit, http.StatusForbidden, nil)
	restartIAM()
	var exitReplay iamv1.RoleSession
	call(http.MethodPost, iamEndpoint, "/v1/auth/role-session:logout", credential, exitRequest, http.StatusOK, &exitReplay)
	if !reflect.DeepEqual(exited, exitReplay) {
		t.Fatal("restart re-executed an already committed role exit")
	}
	call(http.MethodPost, replicaEndpoint, "/v1/auth/role-session:logout", credential, iamv1.LogoutRequest{RequestID: "role-business-exit-variant"}, http.StatusConflict, nil)
	for _, bearer := range []string{credential, otherCredential} {
		getPaaSApplication(t, paasEndpoint, bearer, first.Target.ID, http.StatusUnauthorized)
	}
	getPaaSApplication(t, paasEndpoint, ownerBearer, first.Target.ID, http.StatusOK)
	var retained paasv1.Operation
	call(http.MethodGet, paasEndpoint, "/v1/operations/"+string(first.ID), ownerBearer, nil, http.StatusOK, &retained)
	if retained.Scope != first.Scope || !retained.RequestedBy.Equal(actor) {
		t.Fatal("source revocation or restart changed the accepted role Operation")
	}
	chain := verifyAudit(t, auditEndpoint, ownerBearer)
	if !chain.Complete || chain.State != auditv1.VerificationVerified || chain.TenantID != auditv1.TenantID(user.AccountID) {
		t.Fatal("role business facts broke the immutable tenant chain")
	}
	return []string{credential, otherCredential}
}

func proveGroupResourceProcesses(t *testing.T, ctx context.Context, admin *pgx.Conn, iamEndpoint, replicaEndpoint, auditEndpoint, paasEndpoint, homeBearer, ownerBearer string,
	withAuditOutage func(func()), restartIAM func()) []string {
	t.Helper()
	const tenant = "organization-process-customer"
	createGroup := func(bearer string) iamv1.Group {
		t.Helper()
		response := performJSON(t, http.MethodPost, iamEndpoint+"/v1/groups", bearer,
			iamv1.CreateGroupRequest{Name: "Application operators", RequestID: "process-group-create"})
		var group iamv1.Group
		if response.Status != http.StatusCreated || json.Unmarshal(response.Body, &group) != nil || iamv1.ValidateGroup(group) != nil {
			t.Fatalf("process group create status=%d", response.Status)
		}
		return group
	}
	homeGroup, group := createGroup(homeBearer), createGroup(ownerBearer)
	if group.AccountID != tenant || homeGroup.AccountID != "organization-process" || homeGroup.ID == group.ID || homeGroup.Name != group.Name {
		t.Fatal("same-name groups lost their exact account identity")
	}
	for index := 0; index < 100; index++ {
		response := performJSON(t, http.MethodPost, iamEndpoint+"/v1/groups", ownerBearer,
			iamv1.CreateGroupRequest{Name: fmt.Sprintf("Cursor process %03d", index), RequestID: fmt.Sprintf("cursor-process-group-%03d", index)})
		if response.Status != http.StatusCreated {
			t.Fatalf("create actual cursor directory: %d", response.Status)
		}
	}
	readPage := func(endpoint, after string) iamv1.GroupList {
		t.Helper()
		path := endpoint + "/v1/groups"
		if after != "" {
			path += "?after=" + after
		}
		response := performJSON(t, http.MethodGet, path, ownerBearer, nil)
		var page iamv1.GroupList
		if response.Status != http.StatusOK || json.Unmarshal(response.Body, &page) != nil || iamv1.ValidateGroupList(page) != nil {
			t.Fatalf("process signed directory: %d", response.Status)
		}
		return page
	}
	firstPage := readPage(iamEndpoint, "")
	secondPage := readPage(replicaEndpoint, firstPage.NextAfter)
	if len(firstPage.Items) != 100 || firstPage.NextAfter == "" || len(secondPage.Items) != 1 || secondPage.NextAfter != "" || secondPage.Items[0].Group.ID <= firstPage.Items[99].Group.ID {
		t.Fatal("two actual IAM processes did not share a signed 100+1 directory")
	}
	for _, endpoint := range []string{iamEndpoint, replicaEndpoint} {
		if response := performJSON(t, http.MethodGet, endpoint+"/v1/groups?after="+firstPage.NextAfter, homeBearer, nil); response.Status != http.StatusUnprocessableEntity {
			t.Fatal("process cursor crossed account authority")
		}
		if response := performJSON(t, http.MethodGet, endpoint+"/v1/users?after="+firstPage.NextAfter, ownerBearer, nil); response.Status != http.StatusUnprocessableEntity {
			t.Fatal("process cursor crossed directory query")
		}
	}
	restartIAM()
	if restarted := readPage(iamEndpoint, firstPage.NextAfter); len(restarted.Items) != 1 || restarted.Items[0].Group.ID != secondPage.Items[0].Group.ID {
		t.Fatal("process restart replaced the persistent cursor key")
	}
	for _, endpoint := range []string{iamEndpoint, replicaEndpoint} {
		if response := performJSON(t, http.MethodGet, endpoint+"/v1/groups/"+string(group.ID), homeBearer, nil); response.Status != http.StatusForbidden {
			t.Fatal("home owner read another account group")
		}
	}
	user := createIAMUser(t, iamEndpoint, ownerBearer, "group.operator", "Group operator", initialDeveloperPassword, "process-group-user")
	member := loginIAM(t, iamEndpoint, "group.operator@organization-process-customer", initialDeveloperPassword, "process-group-login")
	changePasswordIAM(t, iamEndpoint, member.Credential, initialDeveloperPassword, changedDeveloperPassword, "process-group-password")
	join := func(requestID string) iamv1.GroupMembership {
		t.Helper()
		response := performJSON(t, http.MethodPost, replicaEndpoint+"/v1/groups/"+string(group.ID)+"/memberships", ownerBearer,
			iamv1.CreateGroupMembershipRequest{UserID: user.ID, RequestID: requestID})
		var membership iamv1.GroupMembership
		if response.Status != http.StatusOK || json.Unmarshal(response.Body, &membership) != nil || iamv1.ValidateGroupMembership(membership) != nil ||
			membership.UserID != user.ID || membership.AccountID != tenant || membership.GroupID != group.ID {
			t.Fatalf("process group membership status=%d", response.Status)
		}
		return membership
	}
	membership := join("process-group-join")
	request := iamv1.CreatePolicyAttachmentRequest{Target: iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetGroup, ID: string(group.ID)},
		PolicyID: iamv1.SystemPolicyPaaSDeveloper, PolicyResourceVersion: 1, RequestID: "process-group-policy"}
	response := performJSON(t, http.MethodPost, iamEndpoint+"/v1/policy-attachments", ownerBearer, request)
	var attachment iamv1.PolicyAttachment
	if response.Status != http.StatusOK || json.Unmarshal(response.Body, &attachment) != nil || iamv1.ValidatePolicyAttachment(attachment) != nil || attachment.Target != request.Target {
		t.Fatalf("process group policy status=%d", response.Status)
	}
	request.PolicyID, request.RequestID = iamv1.SystemPolicyPlatformOperator, "process-group-platform-denied"
	if response := performJSON(t, http.MethodPost, iamEndpoint+"/v1/policy-attachments", ownerBearer, request); response.Status != http.StatusForbidden {
		t.Fatal("group acquired installation policy")
	}
	for _, endpoint := range []string{iamEndpoint, replicaEndpoint} {
		identityResponse := performJSON(t, http.MethodGet, endpoint+"/v1/auth/me", member.Credential, nil)
		var identity iamv1.CurrentIdentity
		if identityResponse.Status != http.StatusOK || json.Unmarshal(identityResponse.Body, &identity) != nil || iamv1.ValidateCurrentIdentity(identity) != nil ||
			len(identity.PolicySources) != 1 || identity.PolicySources[0].Kind != iamv1.PolicyGrantGroup || identity.PolicySources[0].Membership == nil ||
			identity.PolicySources[0].Membership.ID != membership.ID || identity.PolicySources[0].Attachment.ID != attachment.ID {
			t.Fatal("replicas did not agree on live group/attachment provenance")
		}
	}
	assertPlatformAuthorization(t, iamEndpoint, member.Credential, string(user.ID), "process-group-platform-action-denied", false)
	if response := performJSON(t, http.MethodGet, iamEndpoint+"/v1/groups", member.Credential, nil); response.Status != http.StatusForbidden {
		t.Fatal("PaaS group permission implied IAM group administration")
	}
	var operation paasv1.Operation
	withAuditOutage(func() {
		operation = createPaaSApplication(t, paasEndpoint, member.Credential, "application-group-only", "group-only", "process-group-application", http.StatusCreated)
		if operation.Scope.TenantID != tenant || operation.RequestedBy.ID != string(user.ID) {
			t.Fatal("group permission replaced tenant resource ownership or original actor")
		}
		getPaaSApplication(t, paasEndpoint, member.Credential, operation.Target.ID, http.StatusOK)
		removal := performJSON(t, http.MethodPost, replicaEndpoint+"/v1/groups/"+string(group.ID)+"/memberships/"+string(membership.ID)+":remove", ownerBearer,
			iamv1.RemoveGroupMembershipRequest{ResourceVersion: membership.ResourceVersion, RequestID: "process-group-remove"})
		var removed iamv1.GroupMembership
		if removal.Status != http.StatusOK || json.Unmarshal(removal.Body, &removed) != nil || iamv1.ValidateGroupMembership(removed) != nil || removed.RemovedAt == nil || removed.ID != membership.ID {
			t.Fatalf("process group removal status=%d", removal.Status)
		}
		getPaaSApplication(t, paasEndpoint, member.Credential, operation.Target.ID, http.StatusForbidden)
		if response := performJSON(t, http.MethodGet, paasEndpoint+"/v1/operations/"+string(operation.ID), member.Credential, nil); response.Status != http.StatusForbidden {
			t.Fatal("removed group member retained Operation read permission")
		}
		createPaaSApplication(t, paasEndpoint, member.Credential, "application-group-denied", "group-denied", "process-group-application-denied", http.StatusForbidden)
		assertPaaSApplicationAbsent(t, ctx, admin, "application-group-denied")
	})
	waitAllIAMOutboxDelivered(t, ctx, admin)
	waitAllPaaSOutboxDelivered(t, ctx, admin)
	_, historical := findPaaSEvent(t, ctx, admin, auditv1.ActionPaaSApplicationCreated, string(operation.Target.ID))
	var exactEvidence bool
	if err := admin.QueryRow(ctx, `SELECT policy_evidence @> jsonb_build_array(jsonb_build_object(
		'attachmentId',$2::text,'resourceVersion',1,'membershipId',$3::text,'membershipResourceVersion',1))
		FROM iam.authorization_decisions WHERE tenant_id=$1 AND id=$4`, tenant, attachment.ID, membership.ID, historical.IAMDecisionID).Scan(&exactEvidence); err != nil || !exactEvidence {
		t.Fatal("PaaS group decision did not bind the exact historical membership and attachment")
	}
	replay := performJSON(t, http.MethodPost, auditEndpoint+"/v1/events", paasServiceCredential, historical)
	var ingestion auditv1.IngestionResult
	if replay.Status != http.StatusOK || json.Unmarshal(replay.Body, &ingestion) != nil || ingestion.Outcome != auditv1.IngestionDuplicate {
		t.Fatal("committed group-authorized PaaS history could not deliver/replay after membership removal")
	}
	assertPaaSAuditFact(t, ctx, admin, auditv1.ActionPaaSApplicationCreated, string(operation.Target.ID), string(user.ID))
	forged := historical
	forged.EventID, forged.TenantID = "event-group-forged-tenant", "organization-process"
	if response := performJSON(t, http.MethodPost, auditEndpoint+"/v1/events", paasServiceCredential, forged); response.Status != http.StatusForbidden {
		t.Fatal("historical group decision authorized a forged tenant fact")
	}
	getPaaSApplication(t, paasEndpoint, ownerBearer, operation.Target.ID, http.StatusOK)
	getPaaSApplication(t, paasEndpoint, homeBearer, operation.Target.ID, http.StatusNotFound)
	direct := createIAMPolicyAttachment(t, iamEndpoint, ownerBearer, user.ID, iamv1.SystemPolicyPaaSViewer, "process-group-direct-viewer")
	getPaaSApplication(t, paasEndpoint, member.Credential, operation.Target.ID, http.StatusOK)
	rejoined := join("process-group-rejoin")
	if rejoined.ID == membership.ID {
		t.Fatal("rejoin revived the removed relationship")
	}
	deletionResponse := performJSON(t, http.MethodPost, replicaEndpoint+"/v1/groups/"+string(group.ID)+":delete", ownerBearer,
		iamv1.DeleteGroupRequest{ResourceVersion: group.ResourceVersion, RequestID: "process-group-delete"})
	var deletion iamv1.GroupDeletion
	if deletionResponse.Status != http.StatusOK || json.Unmarshal(deletionResponse.Body, &deletion) != nil || iamv1.ValidateGroupDeletion(deletion) != nil ||
		deletion.RemovedMemberships != 1 || deletion.RevokedPolicyAttachments != 1 {
		t.Fatalf("process group deletion status=%d", deletionResponse.Status)
	}
	getPaaSApplication(t, paasEndpoint, member.Credential, operation.Target.ID, http.StatusOK)
	revokeIAMPolicyAttachment(t, iamEndpoint, ownerBearer, direct.ID, direct.ResourceVersion, "process-group-direct-revoke")
	restartIAM()
	getPaaSApplication(t, paasEndpoint, member.Credential, operation.Target.ID, http.StatusForbidden)
	getPaaSApplication(t, paasEndpoint, ownerBearer, operation.Target.ID, http.StatusOK)
	retained := performJSON(t, http.MethodGet, paasEndpoint+"/v1/operations/"+string(operation.ID), ownerBearer, nil)
	var retainedOperation paasv1.Operation
	if retained.Status != http.StatusOK || json.Unmarshal(retained.Body, &retainedOperation) != nil || retainedOperation.Scope != operation.Scope || retainedOperation.RequestedBy != operation.RequestedBy {
		t.Fatal("group deletion or restart changed accepted resource/Operation ownership")
	}
	if response := performJSON(t, http.MethodGet, iamEndpoint+"/v1/groups/"+string(homeGroup.ID), homeBearer, nil); response.Status != http.StatusOK {
		t.Fatal("deleting customer group affected home group")
	}
	waitAllIAMOutboxDelivered(t, ctx, admin)
	for _, item := range []struct {
		action auditv1.Action
		count  int
	}{
		{auditv1.ActionIAMGroupCreated, len(firstPage.Items) + len(secondPage.Items)}, {auditv1.ActionIAMGroupMembershipCreated, 2},
		{auditv1.ActionIAMGroupMembershipRemoved, 1}, {auditv1.ActionIAMGroupDeleted, 1},
	} {
		query := auditv1.QueryRecordsRequest{PageSize: 100, Action: item.action}
		seen := map[auditv1.EventID]bool{}
		for {
			page := queryAudit(t, auditEndpoint, ownerBearer, query, http.StatusOK)
			if page.TenantID != tenant {
				t.Fatal("group audit page changed account")
			}
			for _, record := range page.Records {
				if record.Source != auditv1.SourceIAM || record.Event.IAMDecisionID == "" || record.Event.TenantID != tenant || seen[record.Event.EventID] {
					t.Fatal("group fact lost its source, decision, account or unique identity")
				}
				seen[record.Event.EventID] = true
			}
			if len(seen) > item.count {
				t.Fatal("group lifecycle replay appended an extra success fact")
			}
			if page.NextCursor == "" {
				break
			}
			query.Cursor = page.NextCursor
		}
		if len(seen) != item.count {
			t.Fatalf("group action %s has %d facts, want %d", item.action, len(seen), item.count)
		}
	}
	page := queryAudit(t, auditEndpoint, ownerBearer, auditv1.QueryRecordsRequest{PageSize: 1, Action: auditv1.ActionIAMGroupMembershipCreated}, http.StatusOK)
	if page.NextCursor == "" {
		t.Fatal("group facts did not exercise a continuation")
	}
	queryAudit(t, auditEndpoint, homeBearer, auditv1.QueryRecordsRequest{PageSize: 1, Action: auditv1.ActionIAMGroupMembershipCreated, Cursor: page.NextCursor}, http.StatusUnprocessableEntity)
	chain := verifyAudit(t, auditEndpoint, ownerBearer)
	if chain.TenantID != tenant || chain.State != auditv1.VerificationVerified || !chain.Complete {
		t.Fatal("group lifecycle changed tenant chain integrity")
	}
	return []string{member.Credential}
}

func proveTenantResourceProcesses(t *testing.T, ctx context.Context, admin *pgx.Conn, iamEndpoint, auditEndpoint, paasEndpoint, homeBearer, customerBearer string, customer loginResult) (managedservicev1.QuotaEntitlement, managedservicev1.ServiceInstallation, []string) {
	t.Helper()
	base := paasEndpoint + "/managed-services/v1"
	homeUser := createIAMUser(t, iamEndpoint, homeBearer, "account.user", "Home resource member", initialDeveloperPassword, "request-home-resource-member")
	home := loginIAM(t, iamEndpoint, "account.user@organization-process", initialDeveloperPassword, "request-home-resource-login")
	changePasswordIAM(t, iamEndpoint, home.Credential, initialDeveloperPassword, changedDeveloperPassword, "request-home-resource-password")
	developerBinding := createIAMPolicyAttachment(t, iamEndpoint, homeBearer, homeUser.ID, iamv1.SystemPolicyPaaSDeveloper, "request-home-resource-role")
	platformUser := createIAMUser(t, iamEndpoint, homeBearer, "resource.platform", "Platform only", initialDeveloperPassword, "request-resource-platform-member")
	platform := loginIAM(t, iamEndpoint, "resource.platform@organization-process", initialDeveloperPassword, "request-resource-platform-login")
	changePasswordIAM(t, iamEndpoint, platform.Credential, initialDeveloperPassword, changedDeveloperPassword, "request-resource-platform-password")
	createIAMPolicyAttachment(t, iamEndpoint, homeBearer, platformUser.ID, iamv1.SystemPolicyPlatformOperator, "request-resource-platform-role")
	tenants := []struct {
		id, owner, member string
		memberID          iamv1.PrincipalID
		quota             managedservicev1.QuotaEntitlement
		shared, unique    managedservicev1.ServiceInstallation
	}{
		{id: "organization-process", owner: homeBearer, member: home.Credential, memberID: homeUser.ID},
		{id: "organization-process-customer", owner: customerBearer, member: customer.Credential, memberID: customer.Session.PrincipalID},
	}
	assertStatus := func(response processResponse, status int, action string) {
		t.Helper()
		if response.Status != status {
			t.Fatalf("managed-service %s status=%d want=%d", action, response.Status, status)
		}
	}
	activation := managedservicev1.ActivateQuotaRequest{OfferingID: "postgresql-18", QuotaShapeID: "pg-small", InstanceCount: 2}
	for i := range tenants {
		tenant := &tenants[i]
		response := performJSONWithIdempotency(t, http.MethodPost, base+"/quota-entitlements", tenant.member, "shared-tenant-quota-key", activation)
		assertStatus(response, http.StatusCreated, "activate quota")
		if json.Unmarshal(response.Body, &tenant.quota) != nil || managedservicev1.ValidateQuotaEntitlement(tenant.quota) != nil {
			t.Fatal("invalid real quota")
		}
		replay := performJSONWithIdempotency(t, http.MethodPost, base+"/quota-entitlements", tenant.member, "shared-tenant-quota-key", activation)
		assertStatus(replay, http.StatusOK, "quota replay")
		var replayed managedservicev1.QuotaEntitlement
		if json.Unmarshal(replay.Body, &replayed) != nil || replayed.ID != tenant.quota.ID {
			t.Fatal("tenant quota replay changed identity")
		}
		changed := activation
		changed.InstanceCount = 3
		assertStatus(performJSONWithIdempotency(t, http.MethodPost, base+"/quota-entitlements", tenant.member, "shared-tenant-quota-key", changed), http.StatusConflict, "changed quota replay")
		for j, target := range []*managedservicev1.ServiceInstallation{&tenant.shared, &tenant.unique} {
			id := "postgres-shared-id"
			if j == 1 {
				id = "postgres-only-" + tenant.id
			}
			command := managedservicev1.CreateInstallationRequest{ID: id, Name: "Database for " + tenant.id, OfferingID: "postgresql-18", QuotaEntitlementID: tenant.quota.ID, RegionID: "local-primary"}
			key := fmt.Sprintf("shared-installation-key-%d", j)
			response := performJSONWithIdempotency(t, http.MethodPost, base+"/service-installations", tenant.member, key, command)
			assertStatus(response, http.StatusAccepted, "create installation")
			if json.Unmarshal(response.Body, target) != nil || managedservicev1.ValidateServiceInstallation(*target) != nil || target.ID != id || target.QuotaEntitlementID != tenant.quota.ID || target.Phase != managedservicev1.InstallationPending || target.Endpoint != nil || target.CredentialReference != nil {
				t.Fatal("database acceptance fabricated provisioning or changed its quota identity")
			}
			replay := performJSONWithIdempotency(t, http.MethodPost, base+"/service-installations", tenant.member, key, command)
			assertStatus(replay, http.StatusOK, "installation replay")
			var replayed managedservicev1.ServiceInstallation
			if json.Unmarshal(replay.Body, &replayed) != nil || replayed.Operation.ID != target.Operation.ID {
				t.Fatal("installation replay changed Operation")
			}
			command.Name = "Changed accepted installation"
			assertStatus(performJSONWithIdempotency(t, http.MethodPost, base+"/service-installations", tenant.member, key, command), http.StatusConflict, "changed installation replay")
		}
		full := managedservicev1.CreateInstallationRequest{ID: "postgres-over-quota", Name: "Over quota", OfferingID: "postgresql-18", QuotaEntitlementID: tenant.quota.ID, RegionID: "local-primary"}
		assertStatus(performJSONWithIdempotency(t, http.MethodPost, base+"/service-installations", tenant.member, "over-quota-key", full), http.StatusConflict, "quota exhausted")
	}
	if tenants[0].quota.ID == tenants[1].quota.ID || tenants[0].shared.Operation.ID == tenants[1].shared.Operation.ID {
		t.Fatal("cross-tenant idempotency merged independent quota or Operations")
	}
	for i := range tenants {
		tenant, other := &tenants[i], &tenants[1-i]
		for _, path := range []string{"/quota-entitlements/" + other.quota.ID, "/service-installations/" + other.unique.ID, "/service-installations/" + other.unique.ID + "/operation"} {
			assertStatus(performJSON(t, http.MethodGet, base+path, tenant.member, nil), http.StatusNotFound, "foreign resource ID")
		}
		foreign := managedservicev1.CreateInstallationRequest{ID: "postgres-foreign-quota", Name: "Foreign quota", OfferingID: "postgresql-18", QuotaEntitlementID: other.quota.ID, RegionID: "local-primary"}
		assertStatus(performJSONWithIdempotency(t, http.MethodPost, base+"/service-installations", tenant.member, "foreign-quota-key", foreign), http.StatusNotFound, "foreign quota reservation")
		for _, field := range []string{"tenantId", "organizationId", "requestedBy"} {
			body := map[string]any{"offeringId": "postgresql-18", "quotaShapeId": "pg-small", "instanceCount": 1, field: other.id}
			assertStatus(performJSONWithIdempotency(t, http.MethodPost, base+"/quota-entitlements", tenant.member, "forged-"+field, body), http.StatusBadRequest, "forged authority body")
		}
		for _, path := range []string{"/quota-entitlements", "/service-installations", "/service-installations/" + tenant.shared.ID + "/operation"} {
			for _, query := range []string{"?tenantId=" + other.id, "?cursor=" + other.unique.ID, "?after=" + other.quota.ID} {
				assertStatus(performJSON(t, http.MethodGet, base+path+query, tenant.member, nil), http.StatusBadRequest, "unsupported selector or cursor")
			}
			assertStatus(performJSON(t, http.MethodGet, base+path, platform.Credential, nil), http.StatusForbidden, "platform-only tenant read")
		}
		response := performJSONWithHeaders(t, http.MethodGet, base+"/service-installations/"+tenant.shared.ID, tenant.member, "", nil,
			map[string]string{"X-Tenant-ID": other.id, "Matrix-Tenant-ID": other.id, "Matrix-Subject-Credential": other.member})
		assertStatus(response, http.StatusOK, "caller header isolation")
		var current managedservicev1.ServiceInstallation
		if json.Unmarshal(response.Body, &current) != nil || current.Name != tenant.shared.Name || current.Operation.ID != tenant.shared.Operation.ID {
			t.Fatal("tenant headers selected the other same-ID database")
		}
		response = performJSON(t, http.MethodGet, base+"/service-installations", tenant.owner, nil)
		var list managedservicev1.ServiceInstallationList
		if response.Status != http.StatusOK || json.Unmarshal(response.Body, &list) != nil || len(list.Items) != 2 {
			t.Fatal("tenant service directory changed after cross-tenant or quota attacks")
		}
		for _, item := range list.Items {
			if item.QuotaEntitlementID != tenant.quota.ID || item.Name != tenant.shared.Name {
				t.Fatal("service directory exposed foreign tenant data")
			}
		}
		response = performJSON(t, http.MethodGet, base+"/quota-entitlements", tenant.owner, nil)
		var quotas managedservicev1.QuotaEntitlementList
		if response.Status != http.StatusOK || json.Unmarshal(response.Body, &quotas) != nil || len(quotas.Items) != 1 || quotas.Items[0].ID != tenant.quota.ID || quotas.Items[0].PurchasedCount != 2 || quotas.Items[0].ReservedCount != 2 || quotas.Items[0].ConsumedCount != 0 {
			t.Fatal("quota replay/attack left a partial reservation or exposed another tenant")
		}
		tenant.quota = quotas.Items[0]
		assertManagedServiceRetained(t, paasEndpoint, tenant.owner, tenant.quota, tenant.shared)
	}
	applicationValues := proveApplicationTenantProcesses(t, ctx, admin, paasEndpoint, home, customer, platform.Credential)
	assertStatus(performJSONWithIdempotency(t, http.MethodPost, base+"/quota-entitlements", platform.Credential, "platform-quota-attempt", activation), http.StatusForbidden, "platform-only tenant write")
	revokeIAMPolicyAttachment(t, iamEndpoint, homeBearer, developerBinding.ID, 1, "request-resource-developer-revoked")
	viewerBinding := createIAMPolicyAttachment(t, iamEndpoint, homeBearer, homeUser.ID, iamv1.SystemPolicyPaaSViewer, "request-resource-viewer")
	assertStatus(performJSON(t, http.MethodGet, base+"/service-installations", home.Credential, nil), http.StatusOK, "viewer read")
	assertStatus(performJSONWithIdempotency(t, http.MethodPost, base+"/quota-entitlements", home.Credential, "viewer-quota-attempt", activation), http.StatusForbidden, "viewer write")
	getPaaSApplication(t, paasEndpoint, home.Credential, "application-shared-id", http.StatusOK)
	createPaaSApplication(t, paasEndpoint, home.Credential, "application-viewer-denied", "viewer-denied", "viewer-application-attempt", http.StatusForbidden)
	assertPaaSApplicationAbsent(t, ctx, admin, "application-viewer-denied")
	revokeIAMPolicyAttachment(t, iamEndpoint, homeBearer, viewerBinding.ID, 1, "request-resource-viewer-revoked")
	assertStatus(performJSON(t, http.MethodGet, base+"/service-installations", home.Credential, nil), http.StatusForbidden, "next-request role revocation")
	getPaaSApplication(t, paasEndpoint, home.Credential, "application-shared-id", http.StatusForbidden)
	waitAllIAMOutboxDelivered(t, ctx, admin)
	waitAllPaaSOutboxDelivered(t, ctx, admin)
	for _, tenant := range tenants {
		for _, action := range []auditv1.Action{auditv1.ActionManagedServiceQuotaEntitlementActivated, auditv1.ActionManagedServiceInstallationCreated} {
			page := queryAudit(t, auditEndpoint, tenant.owner, auditv1.QueryRecordsRequest{PageSize: 100, Action: action}, http.StatusOK)
			expected := 1
			if action == auditv1.ActionManagedServiceInstallationCreated {
				expected = 2
			}
			if page.TenantID != auditv1.TenantID(tenant.id) || len(page.Records) != expected {
				t.Fatal("managed-service audit replay or tenant isolation failed")
			}
			for _, record := range page.Records {
				if record.Source != auditv1.SourcePaaS || record.Event.Actor.ID != auditv1.ActorID(tenant.memberID) || record.Event.IAMDecisionID == "" || record.Event.TenantID != auditv1.TenantID(tenant.id) {
					t.Fatal("managed-service fact lost its original tenant/actor/authority")
				}
			}
		}
	}
	return tenants[1].quota, tenants[1].shared, append(applicationValues, home.Credential, platform.Credential)
}

func proveApplicationTenantProcesses(t *testing.T, ctx context.Context, admin *pgx.Conn, endpoint string, home, customer loginResult, platformCredential string) []string {
	t.Helper()
	tenants := []struct {
		login      loginResult
		operations []paasv1.Operation
		value      string
	}{
		{login: home}, {login: customer},
	}
	assertStatus := func(response processResponse, expected int, boundary string) {
		t.Helper()
		if response.Status != expected {
			t.Fatalf("application tenant %s status=%d want=%d", boundary, response.Status, expected)
		}
	}
	for i := range tenants {
		tenant := &tenants[i]
		id, credential := string(tenant.login.Session.AccountID), tenant.login.Credential
		tenant.value = "private-configuration-for-" + id + "-end"
		shared := createPaaSApplication(t, endpoint, credential, "application-shared-id", "application-"+id, "shared-application-key", http.StatusCreated)
		unique := createPaaSApplication(t, endpoint, credential, paasv1.ResourceID("application-only-"+id), "only-"+id, "unique-application-key", http.StatusCreated)
		replay := createPaaSApplication(t, endpoint, credential, shared.Target.ID, "application-"+id, "shared-application-key", http.StatusOK)
		if replay.ID != shared.ID {
			t.Fatal("tenant application replay changed its Operation")
		}
		createPaaSApplication(t, endpoint, credential, shared.Target.ID, "changed-accepted-application", "shared-application-key", http.StatusConflict)
		configuration := createPaaSConfiguration(t, endpoint, credential, "configuration-shared-id", "configuration-"+id, shared.Target.ID, "shared-configuration-key", http.StatusCreated)
		uniqueConfiguration := createPaaSConfiguration(t, endpoint, credential, paasv1.ResourceID("configuration-only-"+id), "only-"+id, unique.Target.ID, "unique-configuration-key", http.StatusCreated)
		configurationReplay := createPaaSConfiguration(t, endpoint, credential, configuration.Target.ID, "configuration-"+id, shared.Target.ID, "shared-configuration-key", http.StatusOK)
		if configurationReplay.ID != configuration.ID {
			t.Fatal("tenant configuration replay changed its Operation")
		}
		createPaaSConfiguration(t, endpoint, credential, configuration.Target.ID, "changed-accepted-configuration", shared.Target.ID, "shared-configuration-key", http.StatusConflict)
		values := map[string]string{"TENANT_MARKER": tenant.value}
		request := paasv1.CreateConfigurationRevisionRequest{ID: "configuration-revision-shared-id", Name: "values-" + id,
			Spec: paasv1.ConfigurationRevisionSpec{ConfigurationID: configuration.Target.ID, Values: values, ContentDigest: paasv1.ConfigurationValuesDigest(values)}}
		response := performJSONWithIdempotency(t, http.MethodPost, endpoint+"/v1/configuration-revisions", credential, "shared-configuration-revision-key", request)
		assertStatus(response, http.StatusCreated, "create configuration revision")
		var revision paasv1.Operation
		if json.Unmarshal(response.Body, &revision) != nil || paasv1.ValidateOperation(revision) != nil || revision.Action != paasv1.OperationCreateConfigurationRevision || revision.Target.ID != request.ID {
			t.Fatal("configuration revision did not produce its real Operation")
		}
		tenant.operations = []paasv1.Operation{shared, unique, configuration, uniqueConfiguration, revision}
		for _, operation := range tenant.operations {
			if operation.Scope != (paasv1.ResourceScope{Kind: paasv1.AuthorityTenant, TenantID: paasv1.TenantID(id)}) || operation.RequestedBy != (paasv1.SubjectRef{Type: paasv1.SubjectUser, ID: string(tenant.login.Session.PrincipalID)}) {
				t.Fatal("application resource lost its current IAM tenant or actor")
			}
		}
	}
	for i := range tenants {
		tenant, other := &tenants[i], &tenants[1-i]
		id, credential := string(tenant.login.Session.AccountID), tenant.login.Credential
		shared := tenant.operations[0]
		if shared.ID == other.operations[0].ID {
			t.Fatal("same-key application requests merged two tenants")
		}
		headers := map[string]string{"X-Tenant-ID": string(other.login.Session.AccountID), "Matrix-Tenant-ID": string(other.login.Session.AccountID), "Matrix-Subject-Credential": other.login.Credential}
		response := performJSONWithHeaders(t, http.MethodGet, endpoint+"/v1/applications/"+string(shared.Target.ID)+"?tenantId="+string(other.login.Session.AccountID), credential, "", nil, headers)
		assertStatus(response, http.StatusOK, "same-ID header and URL confinement")
		var application paasv1.Application
		if json.Unmarshal(response.Body, &application) != nil || paasv1.ValidateApplication(application) != nil || application.Metadata.Scope != shared.Scope || application.Metadata.Name != "application-"+id {
			t.Fatal("caller selectors chose the other same-ID application")
		}
		response = performJSONWithHeaders(t, http.MethodGet, endpoint+"/v1/configurations/configuration-shared-id", credential, "", nil, headers)
		var configuration paasv1.Configuration
		if response.Status != http.StatusOK || json.Unmarshal(response.Body, &configuration) != nil || paasv1.ValidateConfiguration(configuration) != nil || configuration.Metadata.Scope != shared.Scope || configuration.ApplicationID != shared.Target.ID || configuration.Metadata.Name != "configuration-"+id {
			t.Fatal("same-ID configuration crossed tenant ownership")
		}
		response = performJSONWithHeaders(t, http.MethodGet, endpoint+"/v1/configuration-revisions/configuration-revision-shared-id", credential, "", nil, headers)
		var revision paasv1.ConfigurationRevision
		if response.Status != http.StatusOK || json.Unmarshal(response.Body, &revision) != nil || paasv1.ValidateConfigurationRevision(revision) != nil || revision.Metadata.Scope != shared.Scope || revision.Spec.Values["TENANT_MARKER"] != tenant.value || bytes.Contains(response.Body, []byte(other.value)) {
			t.Fatal("same-ID configuration revision exposed another tenant's values")
		}
		for _, path := range []string{"/applications/" + string(other.operations[1].Target.ID), "/configurations/" + string(other.operations[3].Target.ID)} {
			assertStatus(performJSONWithHeaders(t, http.MethodGet, endpoint+"/v1"+path, credential, "", nil, headers), http.StatusNotFound, "foreign resource")
		}
		for j, operation := range tenant.operations {
			response := performJSONWithHeaders(t, http.MethodGet, endpoint+"/v1/operations/"+string(operation.ID), credential, "", nil, headers)
			var current paasv1.Operation
			if response.Status != http.StatusOK || json.Unmarshal(response.Body, &current) != nil || !reflect.DeepEqual(current, operation) {
				t.Fatal("Operation read changed its tenant, actor or accepted resource")
			}
			assertStatus(performJSON(t, http.MethodGet, endpoint+"/v1/operations/"+string(other.operations[j].ID), credential, nil), http.StatusNotFound, "foreign Operation")
			assertStatus(performJSON(t, http.MethodGet, endpoint+"/v1/operations/"+string(operation.ID), platformCredential, nil), http.StatusForbidden, "platform-only Operation read")
		}
		for _, path := range []string{"/applications/application-shared-id", "/configurations/configuration-shared-id", "/configuration-revisions/configuration-revision-shared-id"} {
			assertStatus(performJSON(t, http.MethodGet, endpoint+"/v1"+path, platformCredential, nil), http.StatusForbidden, "platform-only tenant read")
		}
		createPaaSConfiguration(t, endpoint, credential, "configuration-foreign-reference", "foreign-application", other.operations[1].Target.ID, "foreign-application-reference", http.StatusNotFound)
		foreign := paasv1.CreateConfigurationRevisionRequest{ID: "configuration-revision-foreign-reference", Name: "foreign-configuration", Spec: paasv1.ConfigurationRevisionSpec{ConfigurationID: other.operations[3].Target.ID, Values: revision.Spec.Values, ContentDigest: revision.Spec.ContentDigest}}
		assertStatus(performJSONWithIdempotency(t, http.MethodPost, endpoint+"/v1/configuration-revisions", credential, "foreign-configuration-reference", foreign), http.StatusNotFound, "foreign configuration reference")
		for _, field := range []string{"tenantId", "organizationId", "requestedBy"} {
			request := map[string]any{"id": "application-forged-" + field, "name": "forged-authority", field: string(other.login.Session.AccountID)}
			assertStatus(performJSONWithIdempotency(t, http.MethodPost, endpoint+"/v1/applications", credential, "forged-application-"+field, request), http.StatusBadRequest, "authority body selector")
		}
		var partial int
		if err := admin.QueryRow(ctx, `SELECT
			(SELECT count(*) FROM paas.applications WHERE tenant_id=$1 AND id=ANY($2::text[])) +
			(SELECT count(*) FROM paas.configurations WHERE tenant_id=$1 AND id='configuration-foreign-reference') +
			(SELECT count(*) FROM paas.configuration_revisions WHERE tenant_id=$1 AND id='configuration-revision-foreign-reference') +
			(SELECT count(*) FROM paas.operations WHERE tenant_id=$1 AND target_id=ANY($2::text[])) +
			(SELECT count(*) FROM paas.audit_outbox WHERE tenant_id=$1 AND document#>>'{target,id}'=ANY($2::text[]))`,
			id, []string{"configuration-foreign-reference", "configuration-revision-foreign-reference", "application-forged-tenantId", "application-forged-organizationId", "application-forged-requestedBy"}).Scan(&partial); err != nil || partial != 0 {
			t.Fatalf("rejected tenant attack left resource/Operation/outbox changes=%d err=%v", partial, err)
		}
	}
	createPaaSApplication(t, endpoint, platformCredential, "application-platform-denied", "platform-denied", "platform-application-attempt", http.StatusForbidden)
	assertPaaSApplicationAbsent(t, ctx, admin, "application-platform-denied")
	waitAllIAMOutboxDelivered(t, ctx, admin)
	waitAllPaaSOutboxDelivered(t, ctx, admin)
	for _, tenant := range tenants {
		for _, operation := range tenant.operations {
			action := map[paasv1.OperationAction]auditv1.Action{
				paasv1.OperationCreateApplication:           auditv1.ActionPaaSApplicationCreated,
				paasv1.OperationCreateConfiguration:         auditv1.ActionPaaSConfigurationCreated,
				paasv1.OperationCreateConfigurationRevision: auditv1.ActionPaaSConfigurationRevisionCreated,
			}[operation.Action]
			assertPaaSAuditFact(t, ctx, admin, action, string(operation.Target.ID), operation.RequestedBy.ID)
		}
		var leaked bool
		if err := admin.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM audit.records WHERE event_document::text LIKE '%' || $1 || '%')", tenant.value).Scan(&leaked); err != nil || leaked {
			t.Fatal("configuration values entered the Audit contract")
		}
	}
	return []string{tenants[0].value, tenants[1].value}
}

func assertManagedServiceRetained(t *testing.T, endpoint, bearer string, quota managedservicev1.QuotaEntitlement, installation managedservicev1.ServiceInstallation) {
	t.Helper()
	base := endpoint + "/managed-services/v1"
	for _, resource := range []struct {
		path  string
		value any
	}{
		{"/quota-entitlements/" + quota.ID, quota},
		{"/service-installations/" + installation.ID, installation},
		{"/service-installations/" + installation.ID + "/operation", installation.Operation},
	} {
		response := performJSON(t, http.MethodGet, base+resource.path, bearer, nil)
		encoded, err := json.Marshal(resource.value)
		var expected, actual any
		if err != nil || response.Status != http.StatusOK || json.Unmarshal(encoded, &expected) != nil || json.Unmarshal(response.Body, &actual) != nil || !reflect.DeepEqual(actual, expected) {
			t.Fatal("identity lifecycle changed retained quota, database service or Operation")
		}
	}
}

func createPaaSApplication(
	t *testing.T,
	endpoint string,
	bearer string,
	id paasv1.ResourceID,
	name string,
	idempotencyKey string,
	status int,
) paasv1.Operation {
	t.Helper()
	response := performJSONWithIdempotency(
		t,
		http.MethodPost,
		endpoint+"/v1/applications",
		bearer,
		idempotencyKey,
		paasv1.CreateApplicationRequest{ID: id, Name: name},
	)
	if response.Status != status {
		t.Fatalf("create PaaS application %s status=%d want=%d", id, response.Status, status)
	}
	if status != http.StatusCreated && status != http.StatusOK {
		return paasv1.Operation{}
	}
	var operation paasv1.Operation
	if err := json.Unmarshal(response.Body, &operation); err != nil ||
		paasv1.ValidateOperation(operation) != nil ||
		operation.Action != paasv1.OperationCreateApplication ||
		operation.Target != (paasv1.ResourceRef{Kind: "Application", ID: id}) {
		t.Fatalf("decode PaaS application operation: operation=%#v err=%v", operation, err)
	}
	return operation
}

func createPaaSConfiguration(
	t *testing.T,
	endpoint string,
	bearer string,
	id paasv1.ResourceID,
	name string,
	applicationID paasv1.ResourceID,
	idempotencyKey string,
	status int,
) paasv1.Operation {
	t.Helper()
	response := performJSONWithIdempotency(
		t,
		http.MethodPost,
		endpoint+"/v1/configurations",
		bearer,
		idempotencyKey,
		paasv1.CreateConfigurationRequest{
			ID: id, Name: name, ApplicationID: applicationID,
		},
	)
	if response.Status != status {
		t.Fatalf("create PaaS configuration %s status=%d want=%d", id, response.Status, status)
	}
	if status != http.StatusCreated && status != http.StatusOK {
		return paasv1.Operation{}
	}
	var operation paasv1.Operation
	if err := json.Unmarshal(response.Body, &operation); err != nil ||
		paasv1.ValidateOperation(operation) != nil ||
		operation.Action != paasv1.OperationCreateConfiguration ||
		operation.Target != (paasv1.ResourceRef{Kind: "Configuration", ID: id}) {
		t.Fatalf("decode PaaS configuration operation: operation=%#v err=%v", operation, err)
	}
	return operation
}

func getPaaSApplication(
	t *testing.T,
	endpoint string,
	bearer string,
	id paasv1.ResourceID,
	status int,
) {
	t.Helper()
	response := performJSON(
		t,
		http.MethodGet,
		endpoint+"/v1/applications/"+string(id),
		bearer,
		nil,
	)
	if response.Status != status {
		t.Fatalf("get PaaS application %s status=%d want=%d", id, response.Status, status)
	}
	if status != http.StatusOK {
		return
	}
	var application paasv1.Application
	if err := json.Unmarshal(response.Body, &application); err != nil ||
		paasv1.ValidateApplication(application) != nil || application.Metadata.ID != id {
		t.Fatalf("decode PaaS application: application=%#v err=%v", application, err)
	}
}

func queryAudit(
	t *testing.T,
	endpoint string,
	bearer string,
	request auditv1.QueryRecordsRequest,
	status int,
) auditv1.RecordPage {
	t.Helper()
	response := performJSON(t, http.MethodPost, endpoint+"/v1/records:query", bearer, request)
	if response.Status != status {
		t.Fatalf("query Audit status=%d want=%d", response.Status, status)
	}
	if status != http.StatusOK {
		return auditv1.RecordPage{}
	}
	var page auditv1.RecordPage
	if err := json.Unmarshal(response.Body, &page); err != nil ||
		auditv1.ValidateRecordPage(page) != nil {
		t.Fatalf("decode Audit page: %v", err)
	}
	return page
}

func assertAuditQueryConfinement(t *testing.T, endpoint string, bearer string) {
	t.Helper()
	first := queryAudit(
		t,
		endpoint,
		bearer,
		auditv1.QueryRecordsRequest{PageSize: 1},
		http.StatusOK,
	)
	if first.NextCursor == "" {
		t.Fatal("Audit query confinement fixture did not produce a cursor")
	}
	changedFilter := performJSON(
		t,
		http.MethodPost,
		endpoint+"/v1/records:query",
		bearer,
		auditv1.QueryRecordsRequest{
			PageSize: 1,
			Cursor:   first.NextCursor,
			Action:   auditv1.ActionIAMBootstrapApplied,
		},
	)
	if changedFilter.Status != http.StatusUnprocessableEntity {
		t.Fatalf("cross-filter Audit cursor status=%d", changedFilter.Status)
	}
	const crossTenantID = "organization-process-cross-tenant"
	tenantSelector := performJSON(
		t,
		http.MethodPost,
		endpoint+"/v1/records:query",
		bearer,
		struct {
			PageSize int    `json:"pageSize"`
			TenantID string `json:"tenantId"`
		}{PageSize: 10, TenantID: crossTenantID},
	)
	if tenantSelector.Status != http.StatusBadRequest ||
		bytes.Contains(tenantSelector.Body, []byte(crossTenantID)) {
		t.Fatalf("tenant-selecting Audit query status=%d body=%s", tenantSelector.Status, tenantSelector.Body)
	}
}

func verifyAudit(
	t *testing.T,
	endpoint string,
	bearer string,
) auditv1.ChainVerification {
	t.Helper()
	response := performJSON(
		t,
		http.MethodPost,
		endpoint+"/v1/integrity:verify",
		bearer,
		auditv1.VerifyChainRequest{FromSequence: 1, MaximumRecords: auditv1.MaxVerifyRecords},
	)
	if response.Status != http.StatusOK {
		t.Fatalf("verify Audit status=%d", response.Status)
	}
	var verification auditv1.ChainVerification
	if err := json.Unmarshal(response.Body, &verification); err != nil ||
		auditv1.ValidateChainVerification(verification) != nil {
		t.Fatalf("decode Audit verification: %v", err)
	}
	return verification
}

func verifyPaaSInstallation(
	t *testing.T,
	endpoint string,
	bearer string,
	request paasv1.VerifyInstallationRequest,
) paasv1.InstallationVerification {
	t.Helper()
	response := performJSONWithIdempotency(
		t,
		http.MethodPost,
		endpoint+"/v1/installation:verify",
		bearer,
		"verify-process-installation",
		request,
	)
	if response.Status != http.StatusOK {
		t.Fatalf("verify PaaS installation status=%d body=%s", response.Status, response.Body)
	}
	var verification paasv1.InstallationVerification
	if err := json.Unmarshal(response.Body, &verification); err != nil ||
		paasv1.ValidateInstallationVerification(verification) != nil {
		t.Fatalf("decode PaaS installation verification: %v", err)
	}
	return verification
}

func verifyAuditInstallation(
	t *testing.T,
	endpoint string,
	bearer string,
	request auditv1.VerifyInstallationRequest,
) auditv1.InstallationVerification {
	t.Helper()
	response := performJSON(
		t,
		http.MethodPost,
		endpoint+"/v1/installation:verify",
		bearer,
		request,
	)
	if response.Status != http.StatusOK {
		t.Fatalf("verify installation Audit status=%d body=%s", response.Status, response.Body)
	}
	var verification auditv1.InstallationVerification
	if err := json.Unmarshal(response.Body, &verification); err != nil ||
		auditv1.ValidateInstallationVerification(verification) != nil {
		t.Fatalf("decode installation Audit verification: %v", err)
	}
	return verification
}

func waitAllIAMOutboxDelivered(t *testing.T, ctx context.Context, admin *pgx.Conn) {
	t.Helper()
	waitDatabase(t, ctx, "IAM Audit outbox delivery", func() (bool, error) {
		var outstanding int
		err := admin.QueryRow(
			ctx,
			"SELECT count(*) FROM iam.audit_outbox WHERE status <> 'DELIVERED'",
		).Scan(&outstanding)
		return outstanding == 0, err
	})
}

func waitIAMOutboxRetry(t *testing.T, ctx context.Context, admin *pgx.Conn) {
	t.Helper()
	waitDatabase(t, ctx, "IAM Audit outage retry", func() (bool, error) {
		var retries int
		err := admin.QueryRow(
			ctx,
			"SELECT count(*) FROM iam.audit_outbox WHERE status = 'RETRY' AND attempts >= 1",
		).Scan(&retries)
		return retries > 0, err
	})
}

func waitIAMDeadLetter(t *testing.T, ctx context.Context, admin *pgx.Conn) {
	t.Helper()
	waitDatabase(t, ctx, "IAM Audit dead letter", func() (bool, error) {
		var dead int
		err := admin.QueryRow(
			ctx,
			"SELECT count(*) FROM iam.audit_outbox WHERE status = 'DEAD_LETTER'",
		).Scan(&dead)
		return dead > 0, err
	})
}

func waitIAMEventDelivered(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	eventID string,
	minimumAttempts int,
) {
	t.Helper()
	waitDatabase(t, ctx, "IAM Audit duplicate delivery", func() (bool, error) {
		var status string
		var attempts int
		err := admin.QueryRow(
			ctx,
			"SELECT status, attempts FROM iam.audit_outbox WHERE event_id = $1",
			eventID,
		).Scan(&status, &attempts)
		return status == "DELIVERED" && attempts >= minimumAttempts, err
	})
}

func waitAllPaaSOutboxDelivered(t *testing.T, ctx context.Context, admin *pgx.Conn) {
	t.Helper()
	waitDatabase(t, ctx, "PaaS Audit outbox delivery", func() (bool, error) {
		var outstanding int
		err := admin.QueryRow(
			ctx,
			"SELECT (SELECT count(*) FROM paas.audit_outbox WHERE status <> 'DELIVERED') + (SELECT count(*) FROM managedservice.audit_outbox WHERE status <> 'DELIVERED')",
		).Scan(&outstanding)
		return outstanding == 0, err
	})
}

func waitPaaSOutboxRetry(t *testing.T, ctx context.Context, admin *pgx.Conn) {
	t.Helper()
	waitDatabase(t, ctx, "PaaS Audit outage retry", func() (bool, error) {
		var retries int
		err := admin.QueryRow(
			ctx,
			"SELECT count(*) FROM paas.audit_outbox WHERE status = 'RETRY' AND attempts >= 1",
		).Scan(&retries)
		return retries > 0, err
	})
}

func waitPaaSDeadLetter(t *testing.T, ctx context.Context, admin *pgx.Conn) {
	t.Helper()
	waitDatabase(t, ctx, "PaaS Audit dead letter", func() (bool, error) {
		var dead int
		err := admin.QueryRow(
			ctx,
			"SELECT count(*) FROM paas.audit_outbox WHERE status = 'DEAD_LETTER'",
		).Scan(&dead)
		return dead > 0, err
	})
}

func waitPaaSEventDelivered(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	eventID string,
	minimumAttempts int,
) {
	t.Helper()
	waitDatabase(t, ctx, "PaaS Audit duplicate delivery", func() (bool, error) {
		var status string
		var attempts int
		err := admin.QueryRow(
			ctx,
			"SELECT status, attempts FROM paas.audit_outbox WHERE event_id = $1",
			eventID,
		).Scan(&status, &attempts)
		return status == "DELIVERED" && attempts >= minimumAttempts, err
	})
}

func waitDatabase(
	t *testing.T,
	ctx context.Context,
	description string,
	condition func() (bool, error),
) {
	t.Helper()
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		ready, err := condition()
		if err != nil {
			t.Fatalf("inspect %s: %v", description, err)
		}
		if ready {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("wait for %s: %v", description, ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
	t.Fatalf("timed out waiting for %s", description)
}

func findIAMEvent(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	action auditv1.Action,
	targetID string,
) (string, auditv1.Event) {
	t.Helper()
	var eventID string
	var document []byte
	if err := admin.QueryRow(
		ctx,
		`SELECT event_id, event_document
		   FROM iam.audit_outbox
		  WHERE event_document->>'action' = $1
		    AND event_document#>>'{target,id}' = $2`,
		string(action),
		targetID,
	).Scan(&eventID, &document); err != nil {
		t.Fatalf("find IAM Audit event: %v", err)
	}
	defer clear(document)
	var event auditv1.Event
	if err := auditv1.DecodeRequest(bytes.NewReader(document), &event); err != nil ||
		auditv1.ValidateEventForSource(auditv1.SourceIAM, event) != nil {
		t.Fatalf("decode IAM Audit event: %v", err)
	}
	return eventID, event
}

func findPaaSEvent(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	action auditv1.Action,
	targetID string,
) (string, auditv1.Event) {
	t.Helper()
	var eventID string
	var document []byte
	if err := admin.QueryRow(
		ctx,
		`SELECT outbox.event_id, record.event_document
		   FROM paas.audit_outbox AS outbox
		   JOIN audit.records AS record
		     ON record.source = 'PAAS' AND record.event_id = outbox.event_id
		  WHERE outbox.document->>'action' = $1
		    AND outbox.document#>>'{target,id}' = $2`,
		string(action),
		targetID,
	).Scan(&eventID, &document); err != nil {
		t.Fatalf("find PaaS Audit event: %v", err)
	}
	defer clear(document)
	var event auditv1.Event
	if err := auditv1.DecodeRequest(bytes.NewReader(document), &event); err != nil ||
		auditv1.ValidateEventForSource(auditv1.SourcePaaS, event) != nil {
		t.Fatalf("decode PaaS Audit event: %v", err)
	}
	return eventID, event
}

func assertIAMEventsStoredOnce(t *testing.T, ctx context.Context, admin *pgx.Conn) {
	t.Helper()
	var outbox, records int
	if err := admin.QueryRow(
		ctx,
		`SELECT
			(SELECT count(*) FROM iam.audit_outbox),
			(SELECT count(*) FROM audit.records WHERE source = 'IAM')`,
	).Scan(&outbox, &records); err != nil {
		t.Fatalf("inspect initial IAM Audit delivery: %v", err)
	}
	if outbox != 1 || records != 1 {
		t.Fatalf("initial IAM Audit outbox=%d records=%d", outbox, records)
	}
}

func assertAuditEventCount(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	eventID string,
	want int,
) {
	t.Helper()
	assertAuditSourceEventCount(t, ctx, admin, auditv1.SourceIAM, eventID, want)
}

func assertAuditSourceEventCount(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	source auditv1.Source,
	eventID string,
	want int,
) {
	t.Helper()
	var count int
	if err := admin.QueryRow(
		ctx,
		"SELECT count(*) FROM audit.records WHERE source = $1 AND event_id = $2",
		string(source),
		eventID,
	).Scan(&count); err != nil {
		t.Fatalf("count Audit event %s: %v", eventID, err)
	}
	if count != want {
		t.Fatalf("Audit event %s count=%d want=%d", eventID, count, want)
	}
}

func assertPaaSAuditFact(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	action auditv1.Action,
	targetID string,
	actorID string,
) {
	t.Helper()
	var count int
	if err := admin.QueryRow(
		ctx,
		`SELECT count(*)
		   FROM paas.audit_outbox AS outbox
		   JOIN iam.authorization_decisions AS decision
		     ON decision.tenant_id = outbox.tenant_id
		    AND decision.id = outbox.document->>'iamDecisionId'
		   JOIN audit.records AS record
		     ON record.source = 'PAAS'
		    AND record.event_id = outbox.event_id
		  WHERE outbox.document->>'action' = $1
		    AND outbox.document#>>'{target,id}' = $2
		    AND outbox.document#>>'{actor,id}' = $3
		    AND decision.allowed
		    AND decision.principal_id = $3
		    AND record.event_document->>'iamDecisionId' = decision.id
		    AND record.event_document#>>'{actor,id}' = decision.principal_id
		    AND record.event_document->>'tenantId' = outbox.tenant_id
		    AND record.event_document#>>'{target,id}' = outbox.document#>>'{target,id}'
		    AND record.event_document->>'operationId' = outbox.operation_id`,
		string(action),
		targetID,
		actorID,
	).Scan(&count); err != nil {
		t.Fatalf("inspect PaaS Audit fact: %v", err)
	}
	if count != 1 {
		t.Fatalf("PaaS Audit fact action=%s target=%s actor=%s count=%d", action, targetID, actorID, count)
	}
}

func assertPlatformDecisionAuditFacts(t *testing.T, ctx context.Context, admin *pgx.Conn, decisions []iamv1.AuthorizationDecision) {
	t.Helper()
	for _, decision := range decisions {
		expectedResult := auditv1.ResultDenied
		if decision.Allowed {
			expectedResult = auditv1.ResultAllowed
		}
		var count int
		if err := admin.QueryRow(ctx, `SELECT count(*)
			FROM iam.authorization_decisions AS decision
			JOIN iam.audit_outbox AS outbox
			  ON outbox.tenant_id = decision.tenant_id
			 AND outbox.event_document->>'iamDecisionId' = decision.id
			JOIN audit.records AS record
			  ON record.source = 'IAM' AND record.event_id = outbox.event_id
			WHERE decision.tenant_id = 'organization-process'
			  AND decision.id = $1 AND decision.request_id = $2
			  AND decision.allowed = $3
			  AND outbox.event_document->>'action' = 'iam.authorization.decided'
			  AND outbox.event_document#>>'{target,id}' = decision.id
			  AND outbox.event_document#>>'{actor,id}' = decision.principal_id
			  AND outbox.event_document->>'result' = $4
			  AND record.tenant_id = decision.tenant_id
			  AND record.event_document = outbox.event_document`,
			string(decision.ID), decision.RequestID, decision.Allowed, string(expectedResult),
		).Scan(&count); err != nil {
			t.Fatalf("inspect platform authorization Audit fact: %v", err)
		}
		if count != 1 {
			t.Fatalf("platform decision %s has %d correlated Audit facts", decision.ID, count)
		}
	}
}

func countAuditFacts(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	source auditv1.Source,
	action auditv1.Action,
	result auditv1.Result,
) int {
	t.Helper()
	var count int
	if err := admin.QueryRow(
		ctx,
		`SELECT count(*)
		   FROM audit.records
		  WHERE source = $1
		    AND event_document->>'action' = $2
		    AND event_document->>'result' = $3`,
		string(source),
		string(action),
		string(result),
	).Scan(&count); err != nil {
		t.Fatalf("count Audit facts source=%s action=%s result=%s: %v", source, action, result, err)
	}
	return count
}

func assertAuditAccessRecorded(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	action auditv1.Action,
	actorID string,
) {
	t.Helper()
	var count int
	if err := admin.QueryRow(
		ctx,
		`SELECT count(*)
		   FROM audit.records
		  WHERE tenant_id = 'organization-process'
		    AND source = 'AUDIT'
		    AND event_document->>'action' = $1
		    AND event_document#>>'{actor,id}' = $2`,
		string(action),
		actorID,
	).Scan(&count); err != nil {
		t.Fatalf("inspect Audit access fact: %v", err)
	}
	if count < 1 {
		t.Fatalf("Audit access fact action=%s actor=%s count=%d", action, actorID, count)
	}
}

func assertPaaSApplicationAbsent(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	id paasv1.ResourceID,
) {
	t.Helper()
	var count int
	if err := admin.QueryRow(
		ctx,
		"SELECT count(*) FROM paas.applications WHERE id = $1",
		id,
	).Scan(&count); err != nil {
		t.Fatalf("inspect absent PaaS application %s: %v", id, err)
	}
	if count != 0 {
		t.Fatalf("denied PaaS application %s was persisted", id)
	}
}

func assertAuthorityPlaintextAbsent(
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
			`SELECT
				EXISTS (
					SELECT 1 FROM iam.audit_outbox
					 WHERE event_document::text LIKE '%' || $1 || '%'
				)
				OR EXISTS (
					SELECT 1 FROM paas.audit_outbox
					 WHERE document::text LIKE '%' || $1 || '%'
				)
				OR EXISTS (
					SELECT 1 FROM paas.operations
					 WHERE document::text LIKE '%' || $1 || '%'
				)
				OR EXISTS (
					SELECT 1 FROM managedservice.audit_outbox
					 WHERE document::text LIKE '%' || $1 || '%'
				)
				OR EXISTS (
					SELECT 1 FROM managedservice.operations AS operation
					 WHERE row_to_json(operation)::text LIKE '%' || $1 || '%'
				)
				OR EXISTS (
					SELECT 1 FROM audit.records
					 WHERE event_document::text LIKE '%' || $1 || '%'
					    OR canonical_document LIKE '%' || $1 || '%'
				)
				OR EXISTS (
					SELECT 1 FROM iam.local_credential_recoveries AS receipt
					 WHERE row_to_json(receipt)::text LIKE '%' || $1 || '%'
				)`,
			plaintext,
		).Scan(&present); err != nil {
			t.Fatalf("inspect authority plaintext storage: %v", err)
		}
		if present {
			t.Fatal("authority stored plaintext credential")
		}
	}
}

func assertProcessOutputsSanitized(
	t *testing.T,
	children []*childProcess,
	plaintexts ...string,
) {
	t.Helper()
	for _, child := range children {
		output := child.output()
		for _, plaintext := range plaintexts {
			if strings.Contains(output, plaintext) {
				t.Fatal("authority process output leaked credential material")
			}
		}
	}
}

func processBootstrap(t *testing.T) iamv1.BootstrapDocument {
	t.Helper()
	service := func(
		purpose iamv1.ServicePurpose,
		principalID string,
		credential string,
	) iamv1.BootstrapServiceCredential {
		return iamv1.BootstrapServiceCredential{
			Purpose: purpose, PrincipalID: iamv1.PrincipalID(principalID),
			Credential: processSecret(t, credential),
		}
	}
	return iamv1.BootstrapDocument{
		APIVersion:     iamv1.APIVersion,
		Kind:           "IAMBootstrap",
		InstallationID: "installation-process",
		Organization: iamv1.InitialOrganization{
			ID: "organization-process", DisplayName: "Process Organization",
		},
		Administrator: iamv1.InitialAdministrator{
			ID: "principal-admin", LoginName: "admin", DisplayName: "Administrator",
			Password: processSecret(t, initialAdminPassword),
		},
		Services: []iamv1.BootstrapServiceCredential{
			service(iamv1.ServiceIAM, "service-iam", iamServiceCredential),
			service(iamv1.ServicePaaS, "service-paas", paasServiceCredential),
			service(iamv1.ServiceAudit, "service-audit", auditServiceCredential),
			service(iamv1.ServiceInstallationVerifier, "service-verifier", verifierCredential),
		},
	}
}

func processSecret(t *testing.T, plaintext string) iamv1.Secret {
	t.Helper()
	secret, err := iamv1.NewSecret(plaintext)
	if err != nil {
		t.Fatalf("create authority process secret: %v", err)
	}
	return secret
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve authority process test source")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", ".."))
}

func assertPostgres18(t *testing.T, ctx context.Context, admin *pgx.Conn) {
	t.Helper()
	var version int
	if err := admin.QueryRow(ctx, "SELECT current_setting('server_version_num')::integer").Scan(&version); err != nil {
		t.Fatalf("read authority process PostgreSQL version: %v", err)
	}
	if version < 180000 || version >= 190000 {
		t.Fatalf("PostgreSQL version=%d want major 18", version)
	}
}

func assertCleanSchemas(t *testing.T, ctx context.Context, admin *pgx.Conn) {
	t.Helper()
	var iamExists, auditExists, paasExists bool
	if err := admin.QueryRow(
		ctx,
		`SELECT to_regnamespace('iam') IS NOT NULL,
		        to_regnamespace('audit') IS NOT NULL,
		        to_regnamespace('paas') IS NOT NULL`,
	).Scan(&iamExists, &auditExists, &paasExists); err != nil {
		t.Fatalf("inspect platform process schemas: %v", err)
	}
	if iamExists || auditExists || paasExists {
		t.Fatal("platform process integration database is not clean")
	}
}

func applyPlatformSchemas(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
) {
	t.Helper()
	if err := iammigration.Bootstrap(ctx, admin); err != nil {
		t.Fatalf("bootstrap platform IAM schema: %v", err)
	}
	if err := auditmigration.Bootstrap(ctx, admin); err != nil {
		t.Fatalf("bootstrap platform Audit schema: %v", err)
	}
	if err := iammigration.Up(ctx, admin); err != nil {
		t.Fatalf("apply platform IAM schema: %v", err)
	}
	if err := auditmigration.Up(ctx, admin); err != nil {
		t.Fatalf("apply platform Audit schema: %v", err)
	}
	if err := paasmigration.Up(ctx, admin); err != nil {
		t.Fatalf("apply platform PaaS schema: %v", err)
	}
	if err := iammigration.Verify(ctx, admin); err != nil {
		t.Fatalf("verify platform IAM schema: %v", err)
	}
	if err := auditmigration.Verify(ctx, admin); err != nil {
		t.Fatalf("verify platform Audit schema: %v", err)
	}
	if err := paasmigration.Verify(ctx, admin); err != nil {
		t.Fatalf("verify platform PaaS schema: %v", err)
	}
}

func createProcessLogins(t *testing.T, ctx context.Context, admin *pgx.Conn) {
	t.Helper()
	for _, binding := range []struct {
		login string
		group string
	}{
		{iamAPILogin, "matrix_iam_api"},
		{iamWorkerLogin, "matrix_iam_worker"},
		{localRecoveryProcessLogin, "matrix_iam_credential_recovery"},
		{auditRuntimeLogin, "matrix_audit_runtime"},
		{paasAPILogin, "matrix_paas_api"},
		{paasWorkerLogin, "matrix_paas_worker"},
	} {
		createProcessLogin(t, ctx, admin, binding.login, binding.group)
	}
}

func createProcessLogin(t *testing.T, ctx context.Context, admin *pgx.Conn, login, group string) {
	t.Helper()
	statement := fmt.Sprintf(`DO $matrix_process_role$
		BEGIN
			IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = %s) THEN
				CREATE ROLE %s LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE
					NOREPLICATION NOBYPASSRLS;
			END IF;
		END
		$matrix_process_role$;
		ALTER ROLE %s PASSWORD %s;
		GRANT %s TO %s;`,
		quoteLiteral(login),
		pgx.Identifier{login}.Sanitize(),
		pgx.Identifier{login}.Sanitize(),
		quoteLiteral(processDBPassword),
		pgx.Identifier{group}.Sanitize(),
		pgx.Identifier{login}.Sanitize(),
	)
	if _, err := admin.Exec(ctx, statement); err != nil {
		t.Fatalf("create authority process login %s: %v", login, err)
	}
}

func seedProcessExecutionProfile(
	t *testing.T,
	ctx context.Context,
	adminConfig *pgx.ConnConfig,
) {
	t.Helper()
	config := adminConfig.Copy()
	config.User = paasWorkerLogin
	config.Password = processDBPassword
	config.DefaultQueryExecMode = pgx.QueryExecModeCacheStatement
	connection, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatalf("connect PaaS worker execution-profile fixture: %v", err)
	}
	defer func() { _ = connection.Close(context.Background()) }()
	transaction, err := connection.BeginTx(ctx, pgx.TxOptions{
		IsoLevel: pgx.Serializable, AccessMode: pgx.ReadWrite,
	})
	if err != nil {
		t.Fatalf("begin PaaS execution-profile fixture: %v", err)
	}
	defer func() { _ = transaction.Rollback(context.Background()) }()
	var tenantSetting string
	var observedAt time.Time
	if err := transaction.QueryRow(
		ctx,
		"SELECT set_config('matrix.tenant_id', $1, true), transaction_timestamp()",
		"organization-process",
	).Scan(&tenantSetting, &observedAt); err != nil || tenantSetting != "organization-process" {
		t.Fatalf("bind PaaS execution-profile tenant: setting=%q err=%v", tenantSetting, err)
	}
	observedAt = observedAt.UTC().Truncate(time.Microsecond)
	platformScope := paasv1.ResourceScope{Kind: paasv1.AuthorityPlatform}
	tenantScope := paasv1.ResourceScope{
		Kind: paasv1.AuthorityTenant, TenantID: "organization-process",
	}
	pool := paasv1.ExecutionPool{
		APIVersion: paasv1.APIVersion,
		Kind:       "ExecutionPool",
		Metadata: paasv1.ResourceMetadata{
			ID: "execution-pool-local", Name: "local", Scope: platformScope,
			Labels:          map[string]string{"matrix-profile": "local-compose"},
			ResourceVersion: 1, CreatedAt: observedAt, UpdatedAt: observedAt,
		},
		Spec: paasv1.ExecutionPoolSpec{
			ExecutionTargetSelector: paasv1.LabelSelector{MatchLabels: map[string]string{
				"matrix-profile": "local-compose",
			}},
			AllowedIsolationGuarantees: []paasv1.IsolationGuarantee{paasv1.IsolationWorkload},
		},
		Status: paasv1.ExecutionPoolStatus{
			Phase: paasv1.ExecutionPoolReady, ExecutionTargetCount: 1,
			ReadyExecutionTargetCount: 1, ObservedAt: observedAt,
		},
	}
	capacity := paasv1.Capacity{
		CPUMillis: 8000, MemoryBytes: 16 * 1024 * 1024 * 1024,
		StorageBytes: 100 * 1024 * 1024 * 1024, WorkloadSlots: 8,
	}
	target := paasv1.ExecutionTarget{
		APIVersion: paasv1.APIVersion,
		Kind:       "ExecutionTarget",
		Metadata: paasv1.ResourceMetadata{
			ID: "execution-target-local", Name: "local", Scope: platformScope,
			Labels: map[string]string{
				"matrix-profile":             "local-compose",
				"matrix-machine-fingerprint": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			ResourceVersion: 1, CreatedAt: observedAt, UpdatedAt: observedAt,
		},
		Spec: paasv1.ExecutionTargetSpec{
			ExecutionPoolID: "execution-pool-local",
			InfrastructureAdapter: paasv1.AdapterRef{
				Kind: paasv1.AdapterInfrastructure, Name: "localmachine", ContractVersion: "v1",
			},
			DeploymentExecutor: paasv1.AdapterRef{
				Kind: paasv1.AdapterDeploymentExecutor, Name: "compose", ContractVersion: "v1",
			},
			DesiredState: paasv1.ExecutionTargetActive,
		},
		Status: paasv1.ExecutionTargetStatus{
			Health:   paasv1.ExecutionTargetHealthReady,
			Capacity: capacity, Allocatable: capacity,
			SupportedIsolationGuarantees: []paasv1.IsolationGuarantee{paasv1.IsolationWorkload},
			ObservedAt:                   observedAt,
		},
	}
	policy := paasv1.PlacementPolicy{
		APIVersion: paasv1.APIVersion,
		Kind:       "PlacementPolicy",
		Metadata: paasv1.ResourceMetadata{
			ID: "placement-policy-local", Name: "default-local", Scope: tenantScope,
			Labels: map[string]string{
				"matrix-profile": "local-compose", "purpose": "default",
			},
			ResourceVersion: 1, CreatedAt: observedAt, UpdatedAt: observedAt,
		},
		Spec: paasv1.PlacementPolicySpec{
			RequiredIsolationGuarantee: paasv1.IsolationWorkload,
			EligibleExecutionPoolIDs:   []paasv1.ResourceID{"execution-pool-local"},
			ExecutionTargetSelector: paasv1.LabelSelector{MatchLabels: map[string]string{
				"matrix-profile": "local-compose",
			}},
			Strategy: paasv1.PlacementFirstFit,
		},
	}
	for name, validation := range map[string]error{
		"pool":   paasv1.ValidateExecutionPool(pool),
		"target": paasv1.ValidateExecutionTarget(target),
		"policy": paasv1.ValidatePlacementPolicy(policy),
	} {
		if validation != nil {
			t.Fatalf("validate PaaS %s execution-profile fixture: %v", name, validation)
		}
	}
	poolDocument, err := json.Marshal(pool)
	if err != nil {
		t.Fatalf("encode PaaS pool fixture: %v", err)
	}
	targetDocument, err := json.Marshal(target)
	if err != nil {
		t.Fatalf("encode PaaS target fixture: %v", err)
	}
	policyDocument, err := json.Marshal(policy)
	if err != nil {
		t.Fatalf("encode PaaS policy fixture: %v", err)
	}
	var reconciled bool
	if err := transaction.QueryRow(
		ctx,
		`SELECT paas.reconcile_local_execution_profile(
		     0, $1::jsonb, 0, $2::jsonb, 0, $3::jsonb
		 )`,
		poolDocument,
		targetDocument,
		policyDocument,
	).Scan(&reconciled); err != nil || !reconciled {
		t.Fatalf("reconcile PaaS execution-profile fixture: reconciled=%t err=%v", reconciled, err)
	}
	if err := transaction.Commit(ctx); err != nil {
		t.Fatalf("commit PaaS execution-profile fixture: %v", err)
	}
}

func assertCrossSchemaIsolation(
	t *testing.T,
	ctx context.Context,
	adminConfig *pgx.ConnConfig,
) {
	t.Helper()
	for _, attack := range []struct {
		login string
		query string
	}{
		{paasAPILogin, "SELECT * FROM iam.bootstrap_status()"},
		{paasAPILogin, "SELECT * FROM audit.readiness()"},
		{paasWorkerLogin, "SELECT * FROM audit.readiness()"},
		{iamAPILogin, "SELECT * FROM paas.readiness()"},
		{iamWorkerLogin, "SELECT * FROM paas.audit_outbox_snapshot()"},
		{auditRuntimeLogin, "SELECT * FROM iam.bootstrap_status()"},
		{auditRuntimeLogin, "SELECT * FROM paas.readiness()"},
		{localRecoveryProcessLogin, "SELECT * FROM audit.readiness()"},
		{localRecoveryProcessLogin, "SELECT * FROM paas.readiness()"},
		{localRecoveryProcessLogin, "SELECT * FROM iam.bootstrap_status()"},
		{localRecoveryProcessLogin, "SET ROLE matrix_iam_api"},
		{localRecoveryProcessLogin, "SET ROLE matrix_iam_worker"},
		{iamAPILogin, "SELECT iam.inspect_local_credential_recovery('{}'::jsonb,NULL,NULL)"},
		{iamWorkerLogin, "SELECT iam.inspect_local_credential_recovery('{}'::jsonb,NULL,NULL)"},
		{auditRuntimeLogin, "SELECT iam.inspect_local_credential_recovery('{}'::jsonb,NULL,NULL)"},
		{paasAPILogin, "SELECT iam.inspect_local_credential_recovery('{}'::jsonb,NULL,NULL)"},
	} {
		config := adminConfig.Copy()
		config.User = attack.login
		config.Password = processDBPassword
		connection, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatalf("connect cross-schema attack role %s: %v", attack.login, err)
		}
		_, attackErr := connection.Exec(ctx, attack.query)
		_ = connection.Close(context.Background())
		var postgresError *pgconn.PgError
		if !errors.As(attackErr, &postgresError) || postgresError.Code != "42501" {
			t.Fatalf("cross-schema attack role=%s was not denied", attack.login)
		}
	}
}

func quoteLiteral(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

func runtimeDSN(t *testing.T, admin *pgx.ConnConfig, user string, password string) string {
	t.Helper()
	// ConnString returns the original parse input, not changes to Config fields.
	value, err := url.Parse(admin.ConnString())
	if err != nil || (value.Scheme != "postgres" && value.Scheme != "postgresql") || value.Host == "" {
		t.Fatal("authority process gate requires an explicit PostgreSQL URL")
	}
	value.User = url.UserPassword(user, password)
	query := value.Query()
	query.Del("user")
	query.Del("password")
	query.Set("application_name", "matrix-authority-process:"+user)
	query.Set("pool_max_conns", "2")
	value.RawQuery = query.Encode()
	return value.String()
}

func assertRuntimeProcessLogins(t *testing.T, ctx context.Context, admin *pgx.Conn, users ...string) {
	t.Helper()
	for _, user := range users {
		config, err := pgxpool.ParseConfig(runtimeDSN(t, admin.Config(), user, processDBPassword))
		if err != nil {
			t.Fatal("parse authority process identity probe")
		}
		// The probe must not satisfy the independent running-process assertion.
		config.ConnConfig.RuntimeParams["application_name"] += ":identity-probe"
		probe, err := pgx.ConnectConfig(ctx, config.ConnConfig)
		if err != nil {
			t.Fatalf("connect authority identity probe for %s", user)
		}
		var sessionUser, currentUser string
		var limited bool
		probeErr := probe.QueryRow(ctx, `SELECT session_user, current_user, NOT rolsuper AND NOT rolbypassrls
            FROM pg_roles WHERE rolname=current_user`).Scan(&sessionUser, &currentUser, &limited)
		_ = probe.Close(context.Background())
		if probeErr != nil || sessionUser != user || currentUser != user || !limited {
			t.Fatalf("authority identity probe for %s used an unexpected or privileged role", user)
		}
		var connections int
		var confined bool
		if err := admin.QueryRow(ctx, `SELECT count(*), COALESCE(bool_and(activity.usename=$2 AND NOT role.rolsuper AND NOT role.rolbypassrls),false)
            FROM pg_stat_activity AS activity JOIN pg_roles AS role ON role.rolname=activity.usename
			WHERE activity.datname=current_database() AND activity.application_name=$1`, "matrix-authority-process:"+user, user).Scan(&connections, &confined); err != nil || connections == 0 || connections > 2 || !confined {
			t.Fatalf("running authority %s did not use its bounded non-superuser database login", user)
		}
	}
}

func writeProtectedFile(
	t *testing.T,
	root string,
	name string,
	value []byte,
) string {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.WriteFile(path, value, 0o600); err != nil {
		t.Fatalf("write authority process input %s: %v", name, err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatalf("protect authority process input %s: %v", name, err)
		}
	}
	return path
}

func freeAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve authority process address: %v", err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("release authority process address: %v", err)
	}
	return address
}
