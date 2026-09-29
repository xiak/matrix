package authorityprocess

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
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
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp/hotp"

	installationv1 "github.com/xiak/matrix/api/adapter/installation/v1"
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
	admin, err := pgx.ParseConfig("postgres://migration:admin-password@127.0.0.1:5432/ignored-path?sslmode=disable&user=postgres&password=query-admin&host=127.0.0.1&port=5432&dbname=matrix_authority_process_unit")
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
	// A restored database uses a copied pgx config with a different target.
	// ConnString still names the source, so target fields must be serialized
	// deliberately too, rather than just replacing the login in the old URL.
	restored := admin.Copy()
	restored.Host, restored.Port, restored.Database = "::1", 5548, "matrix_authority_process_restored"
	retargeted, err := pgxpool.ParseConfig(runtimeDSN(t, restored, paasAPILogin, "restored-password"))
	if err != nil || retargeted.ConnConfig.Host != restored.Host || retargeted.ConnConfig.Port != restored.Port ||
		retargeted.ConnConfig.Database != restored.Database || retargeted.ConnConfig.User != paasAPILogin ||
		retargeted.ConnConfig.Password != "restored-password" {
		t.Fatal("copied runtime DSN still points at the source database")
	}
}

func TestIAMRetainedPredecessorProcessUpgrade(t *testing.T) {
	const variable = "MATRIX_IAM_PREDECESSOR_POSTGRES_TEST_DSN"
	const databasePrefix = "matrix_iam_upgrade_predecessor_"
	const source = "42035189eb823e388509f54525889c1a18c6b79d"
	const sourceSchema uint64 = 45
	const currentSchema uint64 = 51
	// Actual predecessor admission accepted these 14-byte passwords. The new
	// executable must replay the sealed bootstrap and verify existing secrets
	// without admitting them for a new password write.
	const initialAdminPassword = "Old-Secret-49!"
	const initialReaderPassword = "Old-Member-49!"
	dsn := os.Getenv(variable)
	if dsn == "" {
		t.Skipf("set %s to a clean disposable PostgreSQL 18 database", variable)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	config, err := pgx.ParseConfig(dsn)
	if err != nil || !strings.HasPrefix(config.Database, databasePrefix) {
		t.Fatal("own-session predecessor requires its own disposable database")
	}
	config.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	admin, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal("connect retained own-session database")
	}
	defer func() { _ = admin.Close(context.Background()) }()
	assertPostgres18(t, ctx, admin)
	assertCleanSchemas(t, ctx, admin)
	root, temporary := repositoryRoot(t), t.TempDir()
	// One fixed development predecessor creates all retained data through its
	// actual executable. Advancing this window replaces the predecessor; it
	// does not add another permanent matrix of unpublished schema versions.
	// This is not permission to cross a signed release profile.
	baseline := extractFixedAuthoritySource(t, ctx, root, temporary, source)
	oldMigrator := buildAuthorityBinary(t, ctx, baseline, temporary, "iam-session-predecessor-migrate", "./app/service/iam/cmd/matrix-iam-migrate")
	oldBinary := buildAuthorityBinary(t, ctx, baseline, temporary, "iam-session-predecessor", "./app/service/iam/cmd/matrix-iam")
	currentBinary := buildAuthorityBinary(t, ctx, root, temporary, "iam-session-current", "./app/service/iam/cmd/matrix-iam")
	currentMigrator := buildAuthorityBinary(t, ctx, root, temporary, "iam-session-current-migrate", "./app/service/iam/cmd/matrix-iam-migrate")
	apiDSN := runtimeDSN(t, config, "matrix_iam_api_login", processDBPassword)
	var migrationEnvironment []string
	for _, value := range []struct{ name, dsn string }{
		{"MATRIX_MIGRATION_DATABASE_DSN_FILE", dsn},
		{"MATRIX_MIGRATION_IAM_API_DSN_FILE", localRecoveryMigrationDSN(t, apiDSN)},
		{installationv1.AuthenticationRecoveryMigrationDSNFileEnvironment, localRecoveryMigrationDSN(t, runtimeDSN(t, config, "matrix_iam_authentication_recovery_login", processDBPassword))},
		{"MATRIX_MIGRATION_IAM_WORKER_DSN_FILE", localRecoveryMigrationDSN(t, runtimeDSN(t, config, "matrix_iam_worker_login", processDBPassword))},
		{"MATRIX_MIGRATION_IAM_RECOVERY_DSN_FILE", localRecoveryMigrationDSN(t, runtimeDSN(t, config, localRecoveryProcessLogin, processDBPassword))},
		{installationv1.TOTPBackupCustodyMigrationDSNFileEnvironment, localRecoveryMigrationDSN(t, runtimeDSN(t, config, "matrix_iam_backup_custody_login", processDBPassword))},
		{"MATRIX_MIGRATION_IAM_NOTIFICATION_DSN_FILE", localRecoveryMigrationDSN(t, runtimeDSN(t, config, "matrix_iam_notification_worker_login", processDBPassword))},
	} {
		migrationEnvironment = append(migrationEnvironment, value.name+"="+writeProtectedFile(t, temporary, value.name, []byte(value.dsn)))
	}
	var children []*childProcess
	sensitive := []string{initialAdminPassword, changedAdminPassword, initialReaderPassword, changedReaderPassword, processDBPassword}
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
			t.Fatalf("actual IAM%d migrator failed", sourceSchema)
		}
	}
	bootstrapDocument := processBootstrap(t)
	bootstrapDocument.InstallationID = "mxi-44504450445044504450445044504450"
	bootstrapDocument.Administrator.Password = processSecret(t, initialAdminPassword)
	bootstrap, err := iamv1.EncodeBootstrapDocument(bootstrapDocument)
	if err != nil {
		t.Fatal(err)
	}
	bootstrapPath := writeProtectedFile(t, temporary, "iam-bootstrap", bootstrap)
	clear(bootstrap)
	address := freeAddress(t)
	endpoint := "http://" + address
	// Both exact executables support the same existing key-custody contract.
	environment := []string{"MATRIX_IAM_DATABASE_DSN_FILE=" + writeProtectedFile(t, temporary, "iam-api-dsn", []byte(apiDSN)),
		"MATRIX_IAM_BOOTSTRAP_FILE=" + bootstrapPath, "MATRIX_IAM_LISTEN_ADDRESS=" + address,
		"MATRIX_IAM_CURSOR_KEY_FILE=" + writeProtectedFile(t, temporary, "iam-cursor-key", []byte(strings.Repeat("37", 32))),
		"MATRIX_IAM_ACCESS_KEY_WRAPPING_KEYRING_FILE=" + writeProcessAccessKeyWrapping(t, temporary, bootstrapDocument)}
	{
		digest, err := iamv1.BootstrapDigest(bootstrapDocument)
		if err != nil {
			t.Fatal(err)
		}
		mail := iamv1.EmailVerificationKeyring{APIVersion: iamv1.APIVersion, Kind: "EmailVerificationKeyring", Purpose: iamv1.EmailVerificationWrappingPurpose,
			Scope:          iamv1.SecurityMailInstallationScope{InstallationID: bootstrapDocument.InstallationID, BootstrapDigest: digest},
			KeysetRevision: 1, ActiveKeyID: "process-mail", Keys: []iamv1.EmailVerificationWrappingKey{{KeyID: "process-mail", FormatVersion: 1,
				KeyMaterial: processSecret(t, base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x63}, 32)))}}}
		encoded, err := iamv1.EncodeEmailVerificationKeyring(mail)
		if err != nil {
			t.Fatal(err)
		}
		environment = append(environment, "MATRIX_IAM_EMAIL_VERIFICATION_KEYRING_FILE="+writeProtectedFile(t, temporary, "iam-email-keyring.json", encoded))
		clear(encoded)
	}
	start := func(binary string, version uint64) *childProcess {
		t.Helper()
		currentEnvironment := append([]string(nil), environment...)
		currentEnvironment = append(currentEnvironment, "MATRIX_IAM_TOTP_KEYRING_FILE="+writeProcessTOTPKeyring(t, temporary, bootstrapDocument))
		child := startChild(t, root, binary, currentEnvironment)
		children = append(children, child)
		waitHTTPStatus(t, ctx, child, endpoint+"/ready", http.StatusOK)
		assertRuntimeProcessLogins(t, ctx, admin, "matrix_iam_api_login")
		response := performJSON(t, http.MethodGet, endpoint+"/ready", "", nil)
		var readiness iamv1.Readiness
		if response.Status != http.StatusOK || json.Unmarshal(response.Body, &readiness) != nil || readiness.SchemaVersion != version {
			t.Fatalf("session executable readiness schema=%d status=%d, expected schema=%d", readiness.SchemaVersion, response.Status, version)
		}
		return child
	}
	old := start(oldBinary, sourceSchema)
	primary := loginIAM(t, endpoint, "admin", initialAdminPassword, "own-upgrade-root-login")
	changePasswordIAM(t, endpoint, primary.Credential, initialAdminPassword, changedAdminPassword, "own-upgrade-root-password")
	legacyResetUser := createIAMUser(t, endpoint, primary.Credential, "retained.reset", "Retained reset", initialReaderPassword, "retained-reset-user")
	legacyReset := performJSON(t, http.MethodPost, endpoint+"/v1/users/"+string(legacyResetUser.ID)+":reset-password", primary.Credential,
		map[string]any{"initialPassword": "Retained-Reset-Password-83!", "resourceVersion": legacyResetUser.ResourceVersion, "requestId": "retained-reset-command"})
	var legacyResetResult iamv1.User
	if legacyReset.Status != http.StatusOK || json.Unmarshal(legacyReset.Body, &legacyResetResult) != nil || legacyResetResult.ResourceVersion != legacyResetUser.ResourceVersion+1 {
		t.Fatal("actual predecessor did not produce a real reset fact")
	}
	member := createIAMUser(t, endpoint, primary.Credential, "retained.sessions", "Retained sessions", initialReaderPassword, "own-upgrade-user")
	oldGrant := createIAMPolicyAttachment(t, endpoint, primary.Credential, member.ID, iamv1.SystemPolicyPaaSViewer, "retained-old-viewer")
	revokeIAMPolicyAttachment(t, endpoint, primary.Credential, oldGrant.ID, oldGrant.ResourceVersion, "retained-old-viewer-revoke")
	realm := member.LoginName + "@" + string(member.AccountID)
	a := loginIAM(t, endpoint, realm, initialReaderPassword, "own-upgrade-first")
	changePasswordIAM(t, endpoint, a.Credential, initialReaderPassword, changedReaderPassword, "own-upgrade-password")
	b := loginIAM(t, endpoint, realm, changedReaderPassword, "own-upgrade-second")
	ended := loginIAM(t, endpoint, realm, changedReaderPassword, "own-upgrade-ended")
	unknown := loginIAM(t, endpoint, realm, changedReaderPassword, "own-upgrade-unknown")
	revokeIAMSession(t, endpoint, primary.Credential, ended.Session.ID, "own-upgrade-old-revocation")
	selfEnded := loginIAM(t, endpoint, realm, changedReaderPassword, "own-upgrade-old-self-target")
	oldIntent := iamv1.RevokeSessionRequest{RequestID: "own-upgrade-old-self"}
	oldPath := endpoint + "/v1/auth/sessions/" + string(selfEnded.Session.ID) + ":revoke"
	oldResponse := performJSON(t, http.MethodPost, oldPath, a.Credential, oldIntent)
	var oldCompleted iamv1.RevokeOwnSessionResponse
	if oldResponse.Status != http.StatusOK || json.Unmarshal(oldResponse.Body, &oldCompleted) != nil ||
		iamv1.ValidateRevokeOwnSessionResponse(oldCompleted) != nil || oldCompleted.Outcome != "APPLIED" {
		t.Fatal("actual predecessor did not commit an individual self reduction")
	}
	// Missing lineage is a negative storage fixture, not proof that a newer
	// executable issued a historical NULL-generation session.
	if _, err := admin.Exec(ctx, "UPDATE iam.sessions SET credential_version=NULL WHERE tenant_id=$1 AND id=$2", member.AccountID, unknown.Session.ID); err != nil {
		t.Fatal(err)
	}
	if response := performJSON(t, http.MethodGet, endpoint+"/v1/auth/me", unknown.Credential, nil); response.Status != http.StatusUnauthorized {
		t.Fatal("predecessor accepted unknown credential lineage")
	}
	forcedUser := createIAMUser(t, endpoint, primary.Credential, "retained.forced", "Retained forced change", initialReaderPassword, "own-upgrade-forced-user")
	forcedA := loginIAM(t, endpoint, forcedUser.LoginName+"@"+string(forcedUser.AccountID), initialReaderPassword, "own-upgrade-forced-a")
	forcedB := loginIAM(t, endpoint, forcedUser.LoginName+"@"+string(forcedUser.AccountID), initialReaderPassword, "own-upgrade-forced-b")
	for _, session := range []loginResult{primary, a, b, ended, unknown, forcedA, forcedB, selfEnded} {
		sensitive = append(sensitive, session.Credential)
	}
	// Quiescent copies retain the exact predecessor rows and schema without
	// modifying this live-session fixture or manufacturing legacy receipts.
	// Complete this before MFA callbacks capture the long-lived observer.
	old.stop()
	if err := admin.Close(ctx); err != nil {
		t.Fatal("close predecessor observer before isolated database copies")
	}
	provePredecessorAuthenticationRecovery(t, ctx, root, baseline, temporary, config, bootstrapDocument.InstallationID)
	admin, err = pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal("reconnect predecessor observer")
	}
	old = start(oldBinary, sourceSchema)
	var mailState func() []byte
	var oldVerification iamv1.NotificationContactVerification
	{
		response := performJSON(t, http.MethodPost, endpoint+"/v1/auth/notification-contact/verifications", a.Credential,
			map[string]any{"requestId": "retained-contact", "email": "retained@matrix.test", "password": changedReaderPassword})
		if response.Status != http.StatusOK || json.Unmarshal(response.Body, &oldVerification) != nil {
			t.Fatal("actual predecessor did not create its first-contact verification", response.Status)
		}
		mailState = func() []byte {
			t.Helper()
			var state []byte
			if err := admin.QueryRow(ctx, `SELECT jsonb_build_object(
			 'contacts',(SELECT jsonb_agg(to_jsonb(c) ORDER BY tenant_id,user_id) FROM iam.notification_contacts c),
			 'verifications',(SELECT jsonb_agg(to_jsonb(v) ORDER BY tenant_id,id) FROM iam.notification_contact_verifications v),
			 'notifications',(SELECT jsonb_agg(to_jsonb(n) ORDER BY tenant_id,id) FROM iam.security_notifications n))`).Scan(&state); err != nil {
				t.Fatal("read retained notification invariants", err)
			}
			return state
		}
	}
	exerciseRetainedSettings := prepareRetainedSecuritySettingsProcesses(t, ctx, admin, endpoint, primary.Credential, &sensitive)
	assertRetainedMFA, recoverRetainedMFA := prepareRetainedMFAProcesses(t, ctx, admin, endpoint, primary.Credential, &sensitive, true)
	sessionCheck, sessionAuthenticate := prepareRetainedMFAProcesses(t, ctx, admin, endpoint, primary.Credential, &sensitive, false)
	{
		// Both tenants' real predecessor ceremonies and original qualification
		// survive under forced RLS, including the deferred history proofs.
		response := performJSON(t, http.MethodPost, endpoint+"/v1/accounts", primary.Credential, map[string]any{
			"id": "retained-challenge-second", "displayName": "Retained challenge second account", "rootLoginName": "retained.challenge.root",
			"rootDisplayName": "Retained challenge root", "initialPassword": initialReaderPassword, "requestId": "challenge-second-account",
		})
		if response.Status != http.StatusCreated {
			t.Fatal("actual predecessor did not create the second challenge owner", response.Status)
		}
		secondRoot := loginIAM(t, endpoint, "retained.challenge.root", initialReaderPassword, "challenge-second-root-login")
		sensitive = append(sensitive, secondRoot.Credential)
		changePasswordIAM(t, endpoint, secondRoot.Credential, initialReaderPassword, changedReaderPassword, "challenge-second-root-password")
		secondCheck, secondRecover := prepareRetainedMFAProcesses(t, ctx, admin, endpoint, secondRoot.Credential, &sensitive, true)
		firstCheck, firstRecover := assertRetainedMFA, recoverRetainedMFA
		assertRetainedMFA = func() { firstCheck(); secondCheck(); sessionCheck() }
		recoverRetainedMFA = func() func() {
			firstCompleted, secondCompleted, sessionCompleted := firstRecover(), secondRecover(), sessionAuthenticate()
			return func() { firstCompleted(); secondCompleted(); sessionCompleted() }
		}
	}
	originalMail := mailState()
	defer clear(originalMail)
	var originalIAMProfileRevision uint64
	var originalIAMProfileDocument, originalIAMProfileDigest string
	if err := admin.QueryRow(ctx, `SELECT p.revision,p.canonical_document,p.content_digest FROM iam.authorization_profiles p
	 JOIN iam.authorization_profile_heads h ON (h.product,h.revision)=(p.product,p.revision) WHERE h.product='iam'`).Scan(
		&originalIAMProfileRevision, &originalIAMProfileDocument, &originalIAMProfileDigest); err != nil {
		t.Fatal("read actual predecessor IAM product declaration", err)
	}
	identityState := func() []byte {
		t.Helper()
		var state []byte
		if err := admin.QueryRow(ctx, `SELECT jsonb_build_object(
		 'bootstrap',(SELECT jsonb_agg(jsonb_build_array(singleton,installation_id,content_digest,organization_id,administrator_principal_id,applied_at)) FROM iam.bootstrap_receipts),
		 'accounts',(SELECT jsonb_agg(jsonb_build_array(id,status,resource_version,created_at,updated_at,security_settings_version,mfa_required_for_users,security_settings_updated_at) ORDER BY id) FROM iam.accounts),
		 'settingsChanges',(SELECT jsonb_agg(to_jsonb(c)-'previous_password_settings'-'password_settings' ORDER BY tenant_id,expected_version) FROM iam.account_security_settings_changes c),
		 'credentials',(SELECT jsonb_agg(jsonb_build_array(tenant_id,principal_id,password_hash,credential_version,changed_at) ORDER BY tenant_id,principal_id) FROM iam.user_credentials),
		 'users',(SELECT jsonb_agg(jsonb_build_array(tenant_id,id,status,must_change_password,resource_version) ORDER BY tenant_id,id) FROM iam.principals),
		 'attachments',(SELECT jsonb_agg(jsonb_build_array(tenant_id,id,target_id,policy_id,authority_scope,installation_id,resource_version,revoked_at) ORDER BY tenant_id,id) FROM iam.policy_attachments),
		 'selfCompletions',(SELECT jsonb_agg(to_jsonb(r) ORDER BY tenant_id,user_id,request_id) FROM iam.session_self_revocations r),
		 'factors',(SELECT jsonb_agg(to_jsonb(f)-'removal_id' ORDER BY tenant_id,id) FROM iam.totp_authenticators f),
		 'mfaStates',(SELECT jsonb_agg(to_jsonb(m)-'removal_id' ORDER BY tenant_id,user_id) FROM iam.user_mfa_states m),
		 'batches',(SELECT jsonb_agg(to_jsonb(b)-'revocation_removal_id' ORDER BY tenant_id,id) FROM iam.mfa_recovery_batches b),
		 'codes',(SELECT jsonb_agg(to_jsonb(c) ORDER BY tenant_id,id) FROM iam.mfa_recovery_codes c),
		 'recoveries',(SELECT jsonb_agg(to_jsonb(r) ORDER BY tenant_id,id) FROM iam.authenticator_recoveries r),
		 'challenges',(SELECT jsonb_agg(to_jsonb(c)-'password_reset_required_event_id' ORDER BY tenant_id,id) FROM iam.authentication_challenges c),
		 'proofs',(SELECT jsonb_agg(to_jsonb(p)-'password_settings' ORDER BY tenant_id,id) FROM iam.step_ups p),
		 'otpAttempts',(SELECT jsonb_agg(to_jsonb(a) ORDER BY tenant_id,user_id) FROM iam.totp_attempts a),
		 'sessions',(SELECT jsonb_agg(to_jsonb(s) ORDER BY tenant_id,id) FROM iam.sessions s))`).Scan(&state); err != nil {
			t.Fatal("read retained session/credential invariants", err)
		}
		return state
	}
	originalState := identityState()
	var originalFacts []auditv1.Event
	rows, err := admin.Query(ctx, "SELECT event_document FROM iam.audit_outbox ORDER BY tenant_id,event_id")
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var encoded []byte
		var event auditv1.Event
		if rows.Scan(&encoded) != nil || json.Unmarshal(encoded, &event) != nil {
			t.Fatal("decode original session predecessor fact")
		}
		originalFacts = append(originalFacts, event)
	}
	rows.Close()
	if rows.Err() != nil || len(originalFacts) == 0 {
		t.Fatal("predecessor facts missing")
	}
	old.stop()
	// Exercise rollback once at the current late cutover boundary, not once
	// per discarded historical schema. The nontransactional sequence proves
	// that this deliberate fault, rather than an unrelated error, was reached.
	if _, err := admin.Exec(ctx, `CREATE SEQUENCE public.iam_predecessor_fault_seen;
	 CREATE FUNCTION public.iam_predecessor_fault() RETURNS event_trigger LANGUAGE plpgsql SECURITY DEFINER
	 SET search_path=pg_catalog,pg_temp AS $body$ BEGIN
	 IF EXISTS(SELECT 1 FROM pg_event_trigger_ddl_commands() WHERE schema_name='iam' AND object_type='function'
	 AND object_identity LIKE 'iam.reopen_authentication_recovery(%') THEN
	 PERFORM nextval('public.iam_predecessor_fault_seen');
	 RAISE EXCEPTION USING ERRCODE='P0017',MESSAGE='injected predecessor cutover failure'; END IF; END $body$;
	 CREATE EVENT TRIGGER iam_predecessor_fault ON ddl_command_end EXECUTE FUNCTION public.iam_predecessor_fault()`); err != nil {
		t.Fatal("install isolated late cutover fault")
	}
	failed := iammigration.Up(ctx, admin)
	if _, err := admin.Exec(ctx, "ROLLBACK"); err != nil {
		t.Fatal("finish rejected predecessor cutover")
	}
	var untouched bool
	if failed == nil {
		t.Fatal("injected predecessor cutover unexpectedly succeeded")
	}
	if err := admin.QueryRow(ctx, `SELECT (SELECT is_called FROM public.iam_predecessor_fault_seen)
	 AND (SELECT schema_version=$1 FROM iam.readiness())
	 AND to_regclass('iam.authenticator_removals') IS NULL
	 AND NOT EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid='iam.user_credentials'::regclass
	 AND attname IN ('password_history','password_history_digest','password_changed_at') AND NOT attisdropped)
	 AND to_regprocedure('iam.guard_password_history()') IS NULL
	 AND to_regprocedure('iam.require_password_reset(text,text,text,bigint,text,text,bigint,bigint,jsonb)') IS NULL
	 AND NOT EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid='iam.authentication_challenges'::regclass
	 AND attname='password_reset_required_event_id' AND NOT attisdropped)
	 AND NOT EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid='iam.accounts'::regclass AND attname='password_settings' AND NOT attisdropped)
	 AND NOT EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid='iam.account_security_settings_changes'::regclass
	 AND attname IN ('previous_password_settings','password_settings') AND NOT attisdropped)
	 AND NOT EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid='iam.user_mfa_states'::regclass
	 AND attname='removal_id' AND NOT attisdropped)
	 AND to_regprocedure('iam.remove_totp_authenticator(text,text,text,text,text,bigint,text,text,jsonb)') IS NULL
	 AND iam.authentication_recovery_contract_ready()
	 AND to_regprocedure('iam.prepare_authentication_recovery_close(jsonb,text)') IS NOT NULL
	 AND to_regprocedure('iam.reopen_authentication_recovery(jsonb,text,jsonb,jsonb)') IS NOT NULL`, sourceSchema).Scan(&untouched); err != nil || !untouched ||
		!bytes.Equal(originalState, identityState()) || !bytes.Equal(originalMail, mailState()) {
		t.Fatal("failed cutover partially changed retained authority")
	}
	if _, err := admin.Exec(ctx, `DROP EVENT TRIGGER iam_predecessor_fault;
	 DROP FUNCTION public.iam_predecessor_fault(); DROP SEQUENCE public.iam_predecessor_fault_seen`); err != nil {
		t.Fatal("remove owned cutover fault")
	}
	for range 2 {
		for _, action := range []string{"apply", "verify"} {
			child := startChild(t, root, currentMigrator, migrationEnvironment, action)
			children = append(children, child)
			if err := child.wait(30 * time.Second); err != nil {
				t.Fatal("actual current migrator rejected retained own-session data")
			}
		}
	}
	var shape bool
	if err := admin.QueryRow(ctx, `SELECT schema_version=51 AND iam.password_history_contract_ready() AND iam.account_security_settings_contract_ready() AND iam.login_session_contract_ready() AND iam.password_attempt_contract_ready()
	 AND iam.authentication_recovery_contract_ready()
	 AND to_regprocedure('iam.close_authentication_recovery(jsonb,text,jsonb)') IS NULL
	 AND NOT EXISTS(SELECT 1 FROM iam.user_credentials c WHERE c.password_history<>'[]'::jsonb
	 OR c.password_changed_at IS NOT NULL OR NOT iam.valid_password_history(c.password_history,c.password_history_digest,c.credential_version,c.password_changed_at))
	 AND NOT EXISTS(SELECT 1 FROM iam.accounts WHERE password_settings IS DISTINCT FROM iam.default_password_settings())
	 AND NOT EXISTS(SELECT 1 FROM iam.step_ups WHERE password_settings IS NOT NULL)
	 AND NOT EXISTS(SELECT 1 FROM iam.account_security_settings_changes WHERE password_settings IS NOT NULL OR previous_password_settings IS NOT NULL)
	 AND to_regprocedure('iam.close_authentication_recovery(jsonb,text,jsonb,jsonb,text)') IS NOT NULL
	 AND to_regprocedure('iam.reconcile_authentication_recovery(jsonb,text,jsonb,jsonb)') IS NULL
	 AND to_regprocedure('iam.reconcile_authentication_recovery(jsonb,text,jsonb,jsonb,jsonb)') IS NOT NULL
	 AND to_regprocedure('iam.reopen_authentication_recovery(jsonb,text,jsonb)') IS NULL
	 AND to_regprocedure('iam.reopen_authentication_recovery(jsonb,text,jsonb,jsonb)') IS NOT NULL
	 AND iam.totp_authentication_contract_ready()
	 AND to_regprocedure('iam.require_password_reset(text,text,text,bigint,text,text,bigint,bigint,jsonb)') IS NOT NULL
	 AND NOT EXISTS(SELECT 1 FROM iam.authentication_challenges WHERE password_reset_required_event_id IS NOT NULL)
	 AND NOT EXISTS(SELECT 1 FROM iam.audit_outbox WHERE event_document->>'action'='iam.user.password-reset-required')
	 AND to_regprocedure('iam.remove_totp_authenticator(text,text,text,text,text,bigint,text,text,jsonb)') IS NOT NULL
	 AND to_regprocedure('iam.read_authenticator_removal(text,text,text,text)') IS NOT NULL
	 AND NOT EXISTS(SELECT 1 FROM iam.authenticator_removals)
	 AND NOT EXISTS(SELECT 1 FROM iam.user_mfa_states WHERE removal_id IS NOT NULL OR enrollment_state='REMOVED')
	 AND NOT EXISTS(SELECT 1 FROM iam.totp_authenticators WHERE removal_id IS NOT NULL)
	 AND NOT EXISTS(SELECT 1 FROM iam.mfa_recovery_batches WHERE revocation_removal_id IS NOT NULL)
	 AND to_regprocedure('iam.start_totp_replacement(text,text,text,text,text,bigint,text,text,text,text,bytea,bytea)') IS NOT NULL
	 AND NOT EXISTS(SELECT 1 FROM iam.totp_authenticators WHERE replacement_step_up_id IS NOT NULL OR replacement_contact_revision IS NOT NULL)
	 AND NOT EXISTS(SELECT 1 FROM iam.mfa_recovery_batches WHERE revocation_replacement_factor_id IS NOT NULL)
	 AND to_regprocedure('iam.revoke_session(text,text,text,text,jsonb)') IS NULL
	 AND to_regprocedure('iam.revoke_session(text,text,text,text,jsonb,text)') IS NOT NULL
	 AND (SELECT cardinality(proallargtypes)=25 AND proargnames[25]='credential_generation' FROM pg_proc WHERE oid='iam.lookup_session(text)'::regprocedure)
	 AND (SELECT proargnames=ARRAY['submitted_tenant_id','submitted_user_id','submitted_actor_session_id','submitted_audit_event','revoked_count','completed_at','applied']
	      AND proallargtypes=ARRAY['text'::regtype,'text'::regtype,'text'::regtype,'jsonb'::regtype,'bigint'::regtype,'timestamptz'::regtype,'boolean'::regtype]::oid[]
	      FROM pg_proc WHERE oid='iam.revoke_other_sessions(text,text,text,jsonb)'::regprocedure)
	 FROM iam.readiness()`).Scan(&shape); err != nil || !shape {
		t.Fatal("retained database did not replace the exact Session ABI", err)
	}
	current := start(currentBinary, currentSchema)
	if !bytes.Equal(originalState, identityState()) {
		t.Fatal("migration or equal bootstrap changed original identity/credential state")
	}
	legacyResetPath := fmt.Sprintf("/v1/users/%s/password-resets/retained-reset-command?resourceVersion=%d", legacyResetUser.ID, legacyResetUser.ResourceVersion)
	if response := performJSON(t, http.MethodGet, endpoint+legacyResetPath, primary.Credential, nil); response.Status != http.StatusNotFound {
		t.Fatal("migration invented a reset completion from an old outbox fact")
	}
	legacyRetry := performJSON(t, http.MethodPost, endpoint+"/v1/users/"+string(legacyResetUser.ID)+":reset-password", primary.Credential,
		map[string]any{"initialPassword": "Retained-Reset-Another-Password-94!", "resourceVersion": legacyResetResult.ResourceVersion, "requestId": "retained-reset-command"})
	if legacyRetry.Status != http.StatusConflict || !bytes.Equal(originalState, identityState()) {
		t.Fatal("old reset intent was reused at a newer target version")
	}
	var inventedReset bool
	if err := admin.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM iam.user_password_reset_completions)").Scan(&inventedReset); err != nil || inventedReset {
		t.Fatal("legacy reset was backfilled or retried into a new completion", err)
	}
	if err := admin.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM iam.authorization_profiles WHERE product='iam' AND revision=$1
	 AND canonical_document=$2 AND content_digest=$3)
	 AND EXISTS(SELECT 1 FROM iam.authorization_profile_heads WHERE product='iam' AND revision=7)
	 AND (SELECT count(*)=2 FROM iam.account_security_settings_changes)
	 AND EXISTS(SELECT 1 FROM iam.accounts WHERE id='retained-settings-account' AND security_settings_version=3 AND NOT mfa_required_for_users)
	 AND NOT EXISTS(SELECT 1 FROM iam.accounts WHERE id<>'retained-settings-account' AND (security_settings_version<>1 OR mfa_required_for_users
	 OR security_settings_updated_at IS DISTINCT FROM created_at))`, originalIAMProfileRevision, originalIAMProfileDocument, originalIAMProfileDigest).Scan(&shape); err != nil || !shape {
		t.Fatal("replacement migration rewrote the old product declaration or invented configuration history", err)
	}
	assertRetainedMFA()
	oldContactBearer := a.Credential
	assertRetainedMail := func() {
		t.Helper()
		if !bytes.Equal(originalMail, mailState()) {
			t.Fatal("migration/restart rewrote pending notification or verification material")
		}
		response := performJSON(t, http.MethodGet, endpoint+"/v1/auth/notification-contact/verifications/"+oldVerification.ID, oldContactBearer, nil)
		if response.Status != http.StatusOK {
			t.Fatal("retained first-contact intent lost its original qualified Session", response.Status)
		}
	}
	assertRetainedMail()
	for _, session := range []loginResult{primary, a, b, forcedA, forcedB} {
		if response := performJSON(t, http.MethodGet, endpoint+"/v1/auth/sessions", session.Credential, nil); response.Status != http.StatusOK {
			t.Fatal("predecessor Session lost its actual account qualification")
		}
	}
	oldResponse = performJSON(t, http.MethodPost, oldPath, a.Credential, oldIntent)
	var retainedCompletion iamv1.RevokeOwnSessionResponse
	if oldResponse.Status != http.StatusOK || json.Unmarshal(oldResponse.Body, &retainedCompletion) != nil ||
		retainedCompletion.Outcome != "EQUAL_REPLAY" || retainedCompletion.Revocation != oldCompleted.Revocation {
		t.Fatal("original qualified caller lost its immutable completion")
	}
	list := func(session loginResult, want int) iamv1.SessionList {
		t.Helper()
		response := performJSON(t, http.MethodGet, endpoint+"/v1/auth/sessions", session.Credential, nil)
		var page iamv1.SessionList
		if response.Status != http.StatusOK || json.Unmarshal(response.Body, &page) != nil || iamv1.ValidateSessionList(page) != nil ||
			page.CurrentSessionID != session.Session.ID || page.UserID != session.Session.PrincipalID || page.AccountID != session.Session.AccountID || len(page.Items) != want {
			t.Fatal("retained session directory lost its actual identity or live membership")
		}
		return page
	}
	list(a, 2)
	list(forcedA, 2)
	for _, session := range []loginResult{ended, unknown, selfEnded} {
		if response := performJSON(t, http.MethodGet, endpoint+"/v1/auth/sessions", session.Credential, nil); response.Status != http.StatusUnauthorized {
			t.Fatal("migration revived ended or unknown-lineage session")
		}
	}
	if response := performJSON(t, http.MethodPost, endpoint+"/v1/auth/sessions/"+string(ended.Session.ID)+":revoke", a.Credential, iamv1.RevokeSessionRequest{RequestID: "own-upgrade-adopt-old-end"}); response.Status != http.StatusConflict {
		t.Fatal("old administrator revocation became a new self completion")
	}
	newCaller := loginIAM(t, endpoint, realm, changedReaderPassword, "own-upgrade-new-caller")
	sensitive = append(sensitive, newCaller.Credential)
	oldResponse = performJSON(t, http.MethodPost, oldPath, newCaller.Credential, oldIntent)
	if oldResponse.Status != http.StatusConflict {
		t.Fatal("a new Session adopted another caller's original completion")
	}
	if response := performJSON(t, http.MethodPost, endpoint+"/v1/auth/logout", newCaller.Credential, iamv1.LogoutRequest{RequestID: "own-upgrade-new-caller-exit"}); response.Status != http.StatusOK {
		t.Fatal("new comparison caller did not end its own Session")
	}
	request := iamv1.RevokeSessionRequest{RequestID: "own-upgrade-self"}
	path := endpoint + "/v1/auth/sessions/" + string(b.Session.ID) + ":revoke"
	response := performJSON(t, http.MethodPost, path, a.Credential, request)
	var completed iamv1.RevokeOwnSessionResponse
	if response.Status != http.StatusOK || json.Unmarshal(response.Body, &completed) != nil || completed.Outcome != "APPLIED" {
		t.Fatal("retained user could not end another original session")
	}
	bulkPath := endpoint + "/v1/auth/sessions:revoke-others"
	bulkRequest := iamv1.RevokeSessionRequest{RequestID: "own-upgrade-forced-bulk"}
	response = performJSON(t, http.MethodPost, bulkPath, forcedA.Credential, bulkRequest)
	var bulkCompleted iamv1.RevokeOtherSessionsResponse
	if response.Status != http.StatusOK || json.Unmarshal(response.Body, &bulkCompleted) != nil || iamv1.ValidateRevokeOtherSessionsResponse(bulkCompleted) != nil ||
		bulkCompleted.Outcome != "APPLIED" || bulkCompleted.RevokedCount != 1 || bulkCompleted.CurrentSessionID != forcedA.Session.ID {
		t.Fatal("retained forced-change user lost bulk self reduction")
	}
	later := loginIAM(t, endpoint, forcedUser.LoginName+"@"+string(forcedUser.AccountID), initialReaderPassword, "own-upgrade-later")
	sensitive = append(sensitive, later.Credential)
	var stillForced bool
	if err := admin.QueryRow(ctx, "SELECT must_change_password FROM iam.principals WHERE tenant_id=$1 AND id=$2", forcedUser.AccountID, forcedUser.ID).Scan(&stillForced); err != nil || !stillForced {
		t.Fatal("self reduction upgraded a retained temporary session")
	}
	completedState := identityState()
	for range 2 {
		response := performJSON(t, http.MethodPost, endpoint+"/v1/auth/login", "", map[string]any{"loginName": realm, "password": "Wrong-Retained-Password-71!", "requestId": "retained-budget"})
		if response.Status != http.StatusUnauthorized {
			t.Fatal("retained wrong password was not rejected")
		}
	}
	var attemptState []byte
	if err := admin.QueryRow(ctx, "SELECT to_jsonb(b) FROM iam.password_attempts b WHERE tenant_id=$1 AND principal_id=$2", member.AccountID, member.ID).Scan(&attemptState); err != nil {
		t.Fatal(err)
	}
	current.stop()
	if err := iammigration.Up(ctx, admin); err != nil {
		t.Fatal("replay completed own-session schema", err)
	}
	current = start(currentBinary, currentSchema)
	if !bytes.Equal(completedState, identityState()) {
		t.Fatal("restart/schema replay changed completed session state")
	}
	assertRetainedMail()
	var afterAttempt []byte
	if err := admin.QueryRow(ctx, "SELECT to_jsonb(b) FROM iam.password_attempts b WHERE tenant_id=$1 AND principal_id=$2", member.AccountID, member.ID).Scan(&afterAttempt); err != nil || !bytes.Equal(attemptState, afterAttempt) {
		t.Fatal("actual process restart/schema replay refunded guesses", err)
	}
	list(a, 1)
	list(forcedA, 2)
	response = performJSON(t, http.MethodPost, bulkPath, forcedA.Credential, bulkRequest)
	var bulkReplay iamv1.RevokeOtherSessionsResponse
	if response.Status != http.StatusOK || json.Unmarshal(response.Body, &bulkReplay) != nil || bulkReplay.Outcome != "EQUAL_REPLAY" {
		t.Fatal("retained bulk completion was lost on restart")
	}
	bulkReplay.Outcome = "APPLIED"
	if bulkReplay != bulkCompleted {
		t.Fatal("restart repeated the bulk set instead of returning the original count/time")
	}
	list(later, 2)
	if response := performJSON(t, http.MethodGet, endpoint+"/v1/auth/sessions", forcedB.Credential, nil); response.Status != http.StatusUnauthorized {
		t.Fatal("restart revived the original bulk target")
	}
	response = performJSON(t, http.MethodPost, path, a.Credential, request)
	var replay iamv1.RevokeOwnSessionResponse
	if response.Status != http.StatusOK || json.Unmarshal(response.Body, &replay) != nil || replay.Outcome != "EQUAL_REPLAY" || replay.Revocation != completed.Revocation {
		t.Fatal("retained session replay changed original completion")
	}
	var completions int
	if err := admin.QueryRow(ctx, "SELECT count(*) FROM iam.session_self_revocations WHERE request_id=$1", request.RequestID).Scan(&completions); err != nil || completions != 1 {
		t.Fatal("retained session replay duplicated completion")
	}
	if err := admin.QueryRow(ctx, `SELECT (SELECT count(*) FROM iam.session_other_revocations WHERE request_id=$1 AND revoked_count=1)+
	 (SELECT count(*) FROM iam.session_other_revocation_targets WHERE request_id=$1)`, bulkRequest.RequestID).Scan(&completions); err != nil || completions != 2 {
		t.Fatal("restart lost or duplicated bulk completion/target evidence")
	}
	{
		assertSettings := exerciseRetainedSettings()
		assertRetainedMFA()
		assertRecovered := recoverRetainedMFA()
		current.stop()
		for _, action := range []string{"apply", "verify"} {
			child := startChild(t, root, currentMigrator, migrationEnvironment, action)
			children = append(children, child)
			if err := child.wait(30 * time.Second); err != nil {
				t.Fatal("actual migrator rejected completed recovery history")
			}
		}
		current = start(currentBinary, currentSchema)
		assertRecovered()
		assertSettings()
	}
	for _, event := range originalFacts {
		var encoded []byte
		var retained auditv1.Event
		if err := admin.QueryRow(ctx, "SELECT event_document FROM iam.audit_outbox WHERE event_id=$1", event.EventID).Scan(&encoded); err != nil || json.Unmarshal(encoded, &retained) != nil {
			t.Fatal("original predecessor fact disappeared")
		}
		before, beforeDigest, err := auditv1.CanonicalizeEvent(auditv1.SourceIAM, event)
		after, afterDigest, afterErr := auditv1.CanonicalizeEvent(auditv1.SourceIAM, retained)
		if err != nil || afterErr != nil || before != after || beforeDigest != afterDigest {
			t.Fatal("retained predecessor canonical bytes changed")
		}
		if response := performJSON(t, http.MethodPost, endpoint+"/v1/audit-producer:resolve", iamServiceCredential, iamv1.ResolveAuditProducerRequest{Event: retained}); response.Status != http.StatusOK {
			t.Fatal("original predecessor fact lost its exact historical proof")
		}
	}
	// A real first write after cutover retires the known old verifier without
	// inventing its age or earlier passwords. Keep the verifier only in private
	// comparison state, never a failure message or public response.
	var priorPassword []byte
	if err := admin.QueryRow(ctx, `SELECT to_jsonb(c) FROM iam.user_credentials c WHERE tenant_id=$1 AND principal_id=$2`,
		forcedUser.AccountID, forcedUser.ID).Scan(&priorPassword); err != nil {
		t.Fatal("read retained password before its first current write")
	}
	defer clear(priorPassword)
	const firstCurrentPassword = "Retained-New-Password-History-73!"
	sensitive = append(sensitive, firstCurrentPassword)
	changePasswordIAM(t, endpoint, forcedA.Credential, initialReaderPassword, firstCurrentPassword, "own-upgrade-first-password-history")
	var truthfulHistory bool
	if err := admin.QueryRow(ctx, `SELECT c.credential_version=($3::jsonb->>'credential_version')::bigint+1
	 AND c.password_changed_at=c.changed_at AND c.password_changed_at IS NOT NULL
	 AND jsonb_array_length(c.password_history)=1 AND c.password_history->0->'changedAt'='null'::jsonb
	 AND c.password_history->0->>'hash'=$3::jsonb->>'password_hash'
	 AND (c.password_history->0->>'generation')::bigint=($3::jsonb->>'credential_version')::bigint
	 AND iam.valid_password_history(c.password_history,c.password_history_digest,c.credential_version,c.password_changed_at)
	 FROM iam.user_credentials c WHERE tenant_id=$1 AND principal_id=$2`, forcedUser.AccountID, forcedUser.ID, string(priorPassword)).Scan(&truthfulHistory); err != nil || !truthfulHistory {
		t.Fatal("first current write invented an old password age/history or lost its original verifier", err)
	}
	// Product catalog evolution is a current authorization invariant, not a
	// reason to retain the document-only IAM21 upgrade fixture. Keep its real
	// binary authorization check on the current authority after the cutover.
	profileRequest, err := iamv1.NewAuthorizationRequest(iamv1.ActionPaaSApplicationCreate,
		iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "collection"}, iamv1.AuthorizationResourceCollection,
		iamv1.AuthorizationCollectionCreate, "retained-profile-business", "retained-profile-business")
	if err != nil {
		t.Fatal(err)
	}
	profileResponse := performJSONWithHeaders(t, http.MethodPost, endpoint+"/v1/authorize", paasServiceCredential, "", profileRequest,
		map[string]string{"Matrix-Subject-Credential": primary.Credential})
	var profileDecision iamv1.AuthorizationDecision
	if profileResponse.Status != http.StatusOK || json.Unmarshal(profileResponse.Body, &profileDecision) != nil ||
		iamv1.CheckAuthorizationDecisionForRequest(profileDecision, profileRequest) != nil || !profileDecision.Allowed || profileDecision.Subject == nil {
		t.Fatal("current authority did not issue the product-profile fixture's exact decision")
	}
	profileFact := auditv1.Event{APIVersion: auditv1.APIVersion, Kind: "AuditEvent", EventID: "retained-profile-business-event",
		TenantID: auditv1.TenantID(profileDecision.TenantID), Actor: auditv1.ActorReference{Type: auditv1.ActorUser, ID: auditv1.ActorID(profileDecision.Subject.ID)},
		IAMDecisionID: auditv1.DecisionID(profileDecision.ID), Action: auditv1.ActionPaaSApplicationCreated,
		Target: auditv1.TargetReference{Kind: auditv1.TargetApplication, ID: "retained-profile-app"}, Result: auditv1.ResultSucceeded,
		RequestDigest: "sha256:" + strings.Repeat("1", 64), RequestID: profileDecision.RequestID, CorrelationID: "retained-profile-business",
		OperationID: "retained-profile-operation", OccurredAt: profileDecision.DecidedAt.Add(time.Microsecond)}
	proveFrozenFamilyProfileAdvance(t, ctx, admin, root, temporary, endpoint, primary.Credential, a.Credential,
		migrationEnvironment, func(binary string) *childProcess { return start(binary, currentSchema) }, current, profileFact)
	current.stop()
	t.Logf("actual IAM%d -> IAM%d migrator/runtime retained original Session/Challenge qualification; factor removal/rebind/recovery, forced bulk reduction, shared attempts, exact replay, original receipt/canonical/proof and restart; no release compatibility claim", sourceSchema, currentSchema)
}

func provePredecessorAuthenticationRecovery(t *testing.T, ctx context.Context, root, baseline, temporary string, config *pgx.ConnConfig, installationID string) {
	t.Helper()
	if !strings.HasPrefix(config.Database, "matrix_iam_upgrade_predecessor_") {
		t.Fatal("historical recovery requires the owned predecessor database")
	}
	controlConfig := config.Copy()
	controlConfig.Database = "postgres"
	control, err := pgx.ConnectConfig(ctx, controlConfig)
	if err != nil {
		t.Fatal("connect private predecessor database controller")
	}
	defer control.Close(context.Background())
	suffix := sha256.Sum256([]byte(config.Database))
	var databases []*pgx.Conn
	var configs []*pgx.ConnConfig
	for _, scope := range []string{"source", "target", "unreconciled"} {
		name := "matrix_iam_old_recovery_" + scope + "_" + hex.EncodeToString(suffix[:10])
		if _, err := control.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()+" TEMPLATE "+pgx.Identifier{config.Database}.Sanitize()); err != nil {
			t.Fatal("copy quiescent predecessor database", err)
		}
		defer func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, err := control.Exec(cleanup, "DROP DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
				t.Error("remove owned predecessor recovery copy", err)
			}
		}()
		copyConfig := config.Copy()
		copyConfig.Database = name
		database, err := pgx.ConnectConfig(ctx, copyConfig)
		if err != nil {
			t.Fatal("connect predecessor recovery copy")
		}
		defer database.Close(context.Background())
		databases, configs = append(databases, database), append(configs, copyConfig)
	}
	oldBinary := buildAuthorityBinary(t, ctx, baseline, temporary, "predecessor-private-recovery", "./app/service/iam/cmd/matrix-iam-authentication-recovery")
	currentBinary := buildAuthorityBinary(t, ctx, root, temporary, "current-private-recovery", "./app/service/iam/cmd/matrix-iam-authentication-recovery")
	backupBinary := buildAuthorityBinary(t, ctx, baseline, temporary, "predecessor-backup-custody", "./app/service/iam/cmd/matrix-iam-backup-custody")
	backupDSN := writeProtectedFile(t, temporary, "predecessor-backup-dsn", []byte(runtimeDSN(t, configs[0], "matrix_iam_backup_custody_login", processDBPassword)))
	backupProcess, lease := startTOTPBackupProcess(t, ctx, baseline, backupBinary, backupDSN)
	if lease.Custody.InstallationID != installationID || lease.AuthenticationStateDigest == "" ||
		backupProcess.finish(t, installationv1.TOTPBackupCustodyReleaseFrame) != installationv1.TOTPBackupCustodyExitSuccess {
		t.Fatal("actual predecessor did not issue its original bounded security qualification")
	}
	// This is retained executable/receipt evidence, not a signed backup or
	// cross-profile release admission. The release commitments are fixtures.
	intent := installationv1.AuthenticationRecoveryIntent{
		APIVersion: installationv1.AuthenticationRecoveryAPIVersion, Kind: installationv1.AuthenticationRecoveryIntentKind,
		Purpose: installationv1.AuthenticationRecoveryPurpose, InstallationID: installationID, Epoch: 1,
		CommandID: "cmd-" + strings.Repeat("7", 32), BackupID: "backup-" + strings.Repeat("8", 32),
		BackupDigest: "sha256:" + strings.Repeat("9", 64), TOTPCustodyDigest: lease.CustodyDigest,
		AuthenticationStateDigest: lease.AuthenticationStateDigest,
		SourceReleaseID:           "matrix-v0.0.0-retained-source-0123456789ab", SourceReleaseDigest: "sha256:" + strings.Repeat("b", 64),
		TargetReleaseID: "matrix-v0.0.0-retained-target-0123456789ab", TargetReleaseDigest: "sha256:" + strings.Repeat("c", 64),
	}
	encodedIntent, err := installationv1.EncodeAuthenticationRecoveryIntent(intent)
	if err != nil {
		t.Fatal(err)
	}
	intentFile := installationv1.AuthenticationRecoveryIntentFileEnvironment + "=" + writeProtectedFile(t, temporary, "predecessor-recovery-intent", encodedIntent)
	dsnFiles := make([]string, len(configs))
	for index, copyConfig := range configs {
		dsnFiles[index] = installationv1.AuthenticationRecoveryDatabaseDSNFileEnvironment + "=" + writeProtectedFile(t, temporary,
			fmt.Sprintf("predecessor-recovery-dsn-%d", index), []byte(runtimeDSN(t, copyConfig, "matrix_iam_authentication_recovery_login", processDBPassword)))
	}
	envelopeBytes := invokeAuthenticationRecoveryProcess(t, ctx, baseline, oldBinary, "close", []string{dsnFiles[0], intentFile}, 0)
	envelope, err := installationv1.DecodeAuthenticationRecoveryClosureEnvelope(bytes.NewReader(envelopeBytes))
	if err != nil || installationv1.ValidateAuthenticationRecoveryClosureEnvelopeForIntent(envelope, intent, lease.Custody.BootstrapDigest) != nil {
		t.Fatal("predecessor did not issue its original snapshot and closure")
	}
	closure := envelope.Closure
	closureBytes, err := installationv1.EncodeAuthenticationRecoveryClosure(closure)
	if err != nil {
		t.Fatal(err)
	}
	snapshotBytes, err := installationv1.EncodeAuthenticationRecoverySecuritySnapshot(envelope.SecuritySnapshot)
	if err != nil {
		t.Fatal(err)
	}
	closureDigest, err := installationv1.AuthenticationRecoveryClosureDigest(closure)
	if err != nil {
		t.Fatal(err)
	}
	closureFile := installationv1.AuthenticationRecoveryClosureFileEnvironment + "=" + writeProtectedFile(t, temporary, "predecessor-recovery-closure", closureBytes)
	snapshotFile := installationv1.AuthenticationRecoverySecuritySnapshotFileEnvironment + "=" + writeProtectedFile(t, temporary, "predecessor-recovery-snapshot", snapshotBytes)
	if result := invokeAuthenticationRecoveryProcess(t, ctx, baseline, oldBinary, "reconcile", []string{dsnFiles[1], closureFile, snapshotFile}, 0); !bytes.Equal(result, closureBytes) {
		t.Fatal("predecessor reconciliation changed its source closure")
	}
	completionBytes := invokeAuthenticationRecoveryProcess(t, ctx, baseline, oldBinary, "reopen", []string{dsnFiles[1], closureFile, snapshotFile}, 0)
	completion, err := installationv1.DecodeAuthenticationRecoveryCompletion(bytes.NewReader(completionBytes))
	if err != nil || completion.SecuritySnapshotDigest != closure.SecuritySnapshotDigest || completion.ClosureDigest != closureDigest {
		t.Fatal("predecessor did not commit its original completion")
	}
	history := func(database *pgx.Conn) []byte {
		t.Helper()
		var encoded []byte
		if err := database.QueryRow(ctx, `SELECT jsonb_build_object(
		 'state',(SELECT to_jsonb(s) FROM iam.authentication_recovery_state s),
		 'closures',(SELECT jsonb_agg(to_jsonb(c) ORDER BY command_id) FROM iam.authentication_recovery_closures c),
		 'reconciliations',(SELECT jsonb_agg(to_jsonb(r) ORDER BY command_id) FROM iam.authentication_recovery_reconciliations r),
		 'completions',(SELECT jsonb_agg(to_jsonb(c) ORDER BY command_id) FROM iam.authentication_recovery_completions c),
		 'floors',(SELECT jsonb_agg(to_jsonb(f) ORDER BY tenant_id,user_id) FROM iam.authentication_recovery_attempt_floors f),
		 'credentials',(SELECT jsonb_agg(jsonb_build_array(tenant_id,principal_id,password_hash,credential_version,changed_at) ORDER BY tenant_id,principal_id) FROM iam.user_credentials),
		 'sessions',(SELECT jsonb_agg(to_jsonb(s) ORDER BY tenant_id,id) FROM iam.sessions s),
		 'factors',(SELECT jsonb_agg(to_jsonb(f)-'removal_id' ORDER BY tenant_id,id) FROM iam.totp_authenticators f),
		 'facts',(SELECT jsonb_agg(event_document ORDER BY event_id) FROM iam.audit_outbox))`).Scan(&encoded); err != nil {
			t.Fatal("read original private recovery history")
		}
		return encoded
	}
	for index, database := range databases {
		original := history(database)
		defer clear(original)
		if index == 0 {
			// A still-CLOSED predecessor is not an admissible migration source:
			// the verifier must not turn an interrupted recovery into READY.
			if err := iammigration.Up(ctx, database); err == nil {
				t.Fatal("migration admitted a predecessor's unfinished closed recovery")
			}
			if _, err := database.Exec(ctx, "ROLLBACK"); err != nil {
				t.Fatal("finish rejected closed-source migration")
			}
			var closed bool
			if err := database.QueryRow(ctx, `SELECT schema_version=45 AND NOT ready
			 AND to_regclass('iam.authenticator_removals') IS NULL
			 AND EXISTS(SELECT 1 FROM iam.authentication_recovery_closures WHERE security_snapshot_document IS NOT NULL)
			 AND to_regclass('iam.authentication_recovery_attempt_floors') IS NOT NULL
			 AND to_regprocedure('iam.reopen_authentication_recovery(jsonb,text,jsonb,jsonb)') IS NOT NULL
			 FROM iam.readiness()`).Scan(&closed); err != nil || !closed || !bytes.Equal(original, history(database)) {
				t.Fatal("failed closed-source migration changed authority or historical receipt", err)
			}
			continue
		}
		for range 2 {
			if err := iammigration.Up(ctx, database); err != nil {
				t.Fatal("upgrade actual predecessor recovery history", err)
			}
			if err := iammigration.Verify(ctx, database); err != nil {
				t.Fatal("verify actual predecessor recovery history", err)
			}
		}
		var unchanged bool
		if err := database.QueryRow(ctx, `SELECT
		 (SELECT schema_version=51 AND ready FROM iam.readiness())
		 AND NOT EXISTS(SELECT 1 FROM iam.authenticator_removals)
		 AND NOT EXISTS(SELECT 1 FROM iam.user_credentials c WHERE c.password_history<>'[]'::jsonb
		 OR c.password_changed_at IS NOT NULL OR NOT iam.valid_password_history(c.password_history,c.password_history_digest,c.credential_version,c.password_changed_at))
		 AND (SELECT state='OPEN' AND epoch=$1 FROM iam.authentication_recovery_state)`, 2-index).Scan(&unchanged); err != nil || !unchanged || !bytes.Equal(original, history(database)) {
			t.Fatal("migration altered historical receipts or invented recovery qualification", err)
		}
		passwordState := func() []byte {
			t.Helper()
			var result []byte
			if err := database.QueryRow(ctx, `SELECT jsonb_agg(jsonb_build_array(tenant_id,principal_id,
			 password_history,password_history_digest,password_changed_at) ORDER BY tenant_id,principal_id)
			 FROM iam.user_credentials`).Scan(&result); err != nil {
				t.Fatal("read newly initialized password history")
			}
			return result
		}
		originalPasswords := passwordState()
		defer clear(originalPasswords)
		invokeAuthenticationRecoveryProcess(t, ctx, root, currentBinary, "close", []string{dsnFiles[index], intentFile}, installationv1.AuthenticationRecoveryExitConflict)
		for _, mode := range []string{"reconcile", "reopen"} {
			environment := []string{dsnFiles[index], closureFile, snapshotFile}
			if index == 1 {
				// An exact already-completed receipt is historical evidence,
				// not permission to re-run credential/fence changes.
				want := closureBytes
				if mode == "reopen" {
					want = completionBytes
				}
				if replay := invokeAuthenticationRecoveryProcess(t, ctx, root, currentBinary, mode, environment, 0); !bytes.Equal(replay, want) {
					t.Fatal("migration changed original snapshot-bound completion bytes")
				}
			} else {
				// The same authentic old snapshot cannot authorize first-time
				// restoration under the new qualification projection.
				invokeAuthenticationRecoveryProcess(t, ctx, root, currentBinary, mode, environment, installationv1.AuthenticationRecoveryExitConflict)
			}
			if !bytes.Equal(original, history(database)) || !bytes.Equal(originalPasswords, passwordState()) {
				t.Fatal("old snapshot replay changed current security state or history")
			}
		}
	}
	t.Log("actual IAM45 backup/recovery executables produced snapshot-bound SOURCE/RESTORED receipts; CLOSED migration refused atomically; OPEN double migration and exact completed replay preserved full history/floors without inventing password history/age; authentic old snapshot could not authorize new close/reconcile/reopen under the current qualification projection")
}

// A fixed predecessor executable, not fixture DML or today's implementation,
// creates every positive factor, saved code, challenge and MFA Session here.
// The one supported predecessor, not DML, creates the old MFA-only settings
// lineage. Independent factors avoid sharing or rewinding an OTP counter.
func prepareRetainedSecuritySettingsProcesses(t *testing.T, ctx context.Context, admin *pgx.Conn, endpoint, platform string, sensitive *[]string) func() func() {
	t.Helper()
	const tenant, path = "retained-settings-account", "/v1/account/security-settings"
	const initial, password = "Retained-Settings-Initial-73!", "Retained-Settings-Current-81!"
	*sensitive = append(*sensitive, initial, password)
	secret := func(value iamv1.Secret) string {
		material := value.CopyBytes()
		defer clear(material)
		*sensitive = append(*sensitive, string(material))
		return string(material)
	}
	call := func(method, route, bearer string, body any, want int, result any) {
		t.Helper()
		response := performJSON(t, method, endpoint+route, bearer, body)
		if response.Status != want {
			t.Fatalf("retained settings %s %s status=%d want=%d", method, route, response.Status, want)
		}
		if result != nil && json.Unmarshal(response.Body, result) != nil {
			t.Fatalf("invalid retained settings response: %s %s", method, route)
		}
	}
	call(http.MethodPost, "/v1/accounts", platform, map[string]any{"id": tenant, "displayName": "Retained settings",
		"rootLoginName": "retained.settings.root", "rootDisplayName": "Retained settings root", "initialPassword": initial,
		"requestId": "retained-settings-account"}, http.StatusCreated, nil)
	owner := loginIAM(t, endpoint, "retained.settings.root", initial, "retained-settings-root-login")
	*sensitive = append(*sensitive, owner.Credential)
	changePasswordIAM(t, endpoint, owner.Credential, initial, password, "retained-settings-root-password")
	user := createIAMUser(t, endpoint, owner.Credential, "retained.settings.member", "Retained settings member", initial, "retained-settings-member")
	var policy iamv1.PolicyDetail
	call(http.MethodPost, "/v1/policies", owner.Credential, iamv1.CreatePolicyRequest{DisplayName: "Retained settings operator", RequestID: "retained-settings-policy",
		Document: iamv1.PolicyDocument{LanguageVersion: iamv1.PolicyLanguageVersion, Scope: iamv1.AuthorityScopeTenant,
			Statements: []iamv1.PolicyStatement{{SID: "settings", Effect: iamv1.PolicyAllow,
				Actions:   []iamv1.Action{iamv1.ActionIAMSecuritySettingsRead, iamv1.ActionIAMSecuritySettingsUpdate},
				Resources: []iamv1.PolicyResourceSelector{{Kind: iamv1.ResourceAccount, Match: iamv1.PolicyResourceExact, ID: tenant}}}}}}, http.StatusCreated, &policy)
	for _, id := range []iamv1.PrincipalID{owner.Session.PrincipalID, user.ID} {
		createIAMPolicyAttachment(t, endpoint, owner.Credential, id, policy.Policy.ID, "retained-settings-grant-"+string(id))
	}
	member := loginIAM(t, endpoint, user.LoginName+"@"+tenant, initial, "retained-settings-member-login")
	*sensitive = append(*sensitive, member.Credential)
	changePasswordIAM(t, endpoint, member.Credential, initial, password, "retained-settings-member-password")
	// This actual predecessor has no password_changed_at. A separate ordinary
	// password-only USER keeps that genuinely unknown age across migration;
	// no positive fixture resets a timestamp or invents old authentication.
	ageUser := createIAMUser(t, endpoint, owner.Credential, "retained.password.age", "Retained password age", initial, "retained-age-create")
	ageRealm := ageUser.LoginName + "@" + tenant
	ageSession := loginIAM(t, endpoint, ageRealm, initial, "retained-age-initial-login")
	*sensitive = append(*sensitive, ageSession.Credential)
	changePasswordIAM(t, endpoint, ageSession.Credential, initial, password, "retained-age-old-password")
	boundAgeUser := createIAMUser(t, endpoint, owner.Credential, "retained.password.bound-age", "Retained bound password age", initial, "retained-bound-age-create")
	boundAgeRealm := boundAgeUser.LoginName + "@" + tenant
	boundAgeSession := loginIAM(t, endpoint, boundAgeRealm, initial, "retained-bound-age-initial-login")
	*sensitive = append(*sensitive, boundAgeSession.Credential)
	changePasswordIAM(t, endpoint, boundAgeSession.Credential, initial, password, "retained-bound-age-old-password")
	// Dedicated real predecessor identities keep late-failure reservations
	// charged without borrowing another USER's budget or waiting out its lease.
	faultUser := createIAMUser(t, endpoint, owner.Credential, "retained.password.fault", "Password-only fault", initial, "retained-fault-create")
	faultRealm := faultUser.LoginName + "@" + tenant
	faultSession := loginIAM(t, endpoint, faultRealm, initial, "retained-fault-initial")
	*sensitive = append(*sensitive, faultSession.Credential)
	changePasswordIAM(t, endpoint, faultSession.Credential, initial, password, "retained-fault-password")
	boundFaultUser := createIAMUser(t, endpoint, owner.Credential, "retained.password.bound-fault", "Bound password fault", initial, "retained-bound-fault-create")
	boundFaultRealm := boundFaultUser.LoginName + "@" + tenant
	boundFaultSession := loginIAM(t, endpoint, boundFaultRealm, initial, "retained-bound-fault-initial")
	*sensitive = append(*sensitive, boundFaultSession.Credential)
	changePasswordIAM(t, endpoint, boundFaultSession.Credential, initial, password, "retained-bound-fault-password")
	// The two expiry modes are independent product paths. Give their positive
	// factor proofs independent real counters, rather than spending another
	// mode's future OTP window or extending the predecessor gate deadline.
	boundAdminUser := createIAMUser(t, endpoint, owner.Credential, "retained.password.bound-admin", "Bound administrator reset", initial, "retained-bound-admin-create")
	boundAdminRealm := boundAdminUser.LoginName + "@" + tenant
	boundAdminSession := loginIAM(t, endpoint, boundAdminRealm, initial, "retained-bound-admin-initial")
	*sensitive = append(*sensitive, boundAdminSession.Credential)
	changePasswordIAM(t, endpoint, boundAdminSession.Credential, initial, password, "retained-bound-admin-password")
	var resetRaceUsers [2]iamv1.User
	for index := range resetRaceUsers {
		prefix := fmt.Sprintf("retained-expiry-race-%d", index)
		user := createIAMUser(t, endpoint, owner.Credential, prefix, "Expiry reset race", initial, prefix+"-create")
		first := loginIAM(t, endpoint, user.LoginName+"@"+tenant, initial, prefix+"-login")
		*sensitive = append(*sensitive, first.Credential)
		changePasswordIAM(t, endpoint, first.Credential, initial, password, prefix+"-password")
		resetRaceUsers[index] = user
	}
	type settingsActor struct {
		first        loginResult
		realm        string
		factor, seed string
	}
	actors := []settingsActor{
		{first: owner, realm: "retained.settings.root"},
		{first: member, realm: user.LoginName + "@" + tenant},
		{first: boundAgeSession, realm: boundAgeRealm},
		{first: boundFaultSession, realm: boundFaultRealm},
		{first: boundAdminSession, realm: boundAdminRealm},
	}
	bindActor := func(i int) {
		t.Helper()
		a := &actors[i]
		prefix := fmt.Sprintf("retained-settings-%d", i)
		var contact iamv1.NotificationContactVerification
		call(http.MethodPost, "/v1/auth/notification-contact/verifications", a.first.Credential,
			map[string]string{"email": prefix + "@matrix.test", "password": password, "requestId": prefix + "-contact"}, http.StatusOK, &contact)
		code := readProcessContactCode(t, ctx, admin, contact)
		*sensitive = append(*sensitive, code)
		call(http.MethodPost, "/v1/auth/notification-contact/verifications/"+contact.ID+":confirm", a.first.Credential,
			map[string]string{"requestId": prefix + "-contact-confirm", "code": code}, http.StatusOK, nil)
		var enrollment iamv1.StartTOTPEnrollmentResponse
		call(http.MethodPost, "/v1/auth/totp/enrollments", a.first.Credential,
			map[string]any{"requestId": prefix + "-enroll", "password": password, "expectedFactorRevision": 1}, http.StatusOK, &enrollment)
		if enrollment.Provisioning == nil {
			t.Fatal("predecessor settings operator has no real provisioning")
		}
		a.factor, a.seed = enrollment.Enrollment.ID, secret(enrollment.Provisioning.Seed)
		secret(enrollment.Provisioning.URI)
		code, _ = processTOTPCode(t, ctx, admin, a.seed, -1, true)
		*sensitive = append(*sensitive, code)
		var bound iamv1.ConfirmTOTPEnrollmentResponse
		call(http.MethodPost, "/v1/auth/totp/enrollments/"+a.factor+":confirm", a.first.Credential,
			map[string]string{"requestId": prefix + "-bound", "code": code}, http.StatusOK, &bound)
		if len(bound.RecoveryCodes) != 10 || bound.Enrollment.State != "CONFIRMED" {
			t.Fatal("predecessor settings factor was not actually bound")
		}
		for _, material := range bound.RecoveryCodes {
			secret(material)
		}
	}
	for i := range actors {
		bindActor(i)
	}
	nextCode := func(index int) string {
		t.Helper()
		var consumed int64
		if err := admin.QueryRow(ctx, "SELECT last_consumed_step FROM iam.totp_authenticators WHERE tenant_id=$1 AND id=$2", tenant, actors[index].factor).Scan(&consumed); err != nil {
			t.Fatal("read retained settings OTP consumption")
		}
		code, _ := processTOTPCode(t, ctx, admin, actors[index].seed, consumed, false)
		*sensitive = append(*sensitive, code)
		return code
	}
	login := func(index int, request string) string {
		t.Helper()
		var challenge, authenticated iamv1.LoginResponse
		call(http.MethodPost, "/v1/auth/login", "", map[string]string{"loginName": actors[index].realm, "password": password, "requestId": request}, http.StatusOK, &challenge)
		if challenge.Outcome != iamv1.LoginChallengeRequired || challenge.Challenge == nil || challenge.Challenge.NextStep != "TOTP" {
			t.Fatal("retained settings login bypassed its actual factor")
		}
		call(http.MethodPost, "/v1/auth/challenges/"+challenge.Challenge.ID+":verify", "",
			map[string]string{"requestId": request + "-verify", "challengeCredential": secret(challenge.ChallengeCredential), "code": nextCode(index)}, http.StatusOK, &authenticated)
		if authenticated.Outcome != iamv1.LoginAuthenticated || !authenticated.Credential.Present() {
			t.Fatal("retained settings login did not issue an actual MFA Session")
		}
		return secret(authenticated.Credential)
	}
	// These minimal wire values belong only to the fixed predecessor fixture.
	// The current public request must never acquire an optional-password bypass.
	oldProof := func(index int, bearer, command string, version uint64, required bool) string {
		t.Helper()
		var proof struct{ ID, State string }
		call(http.MethodPost, "/v1/auth/step-up", bearer, map[string]any{"requestId": command, "operation": iamv1.StepUpUpdateSecuritySettings,
			"expectedFactorRevision": 2, "securitySettings": map[string]any{"expectedResourceVersion": version, "mfa": iamv1.AccountMFASettings{RequiredForUsers: required}}}, http.StatusOK, &proof)
		call(http.MethodPost, "/v1/auth/step-up/"+proof.ID+":verify", bearer,
			map[string]string{"requestId": command + "-proof", "password": password, "code": nextCode(index)}, http.StatusOK, &proof)
		if proof.ID == "" || proof.State != "PROVED" {
			t.Fatal("predecessor settings intent lacks real password/OTP proof")
		}
		return proof.ID
	}
	var completions [2]iamv1.AccountSecuritySettingsChange
	for index := range actors[:2] {
		command := fmt.Sprintf("retained-settings-change-%d", index)
		bearer := login(index, command+"-login")
		version, required := uint64(index+1), index == 0
		proofID := oldProof(index, bearer, command, version, required)
		var result struct {
			Outcome string
			Change  iamv1.AccountSecuritySettingsChange
		}
		call(http.MethodPut, path, bearer, map[string]any{"requestId": command, "stepUpId": proofID, "expectedResourceVersion": version,
			"mfa": iamv1.AccountMFASettings{RequiredForUsers: required}}, http.StatusOK, &result)
		if result.Outcome != "APPLIED" || result.Change.Settings.Password != nil || !result.Change.CallerSessionEnded || result.Change.Settings.ResourceVersion != version+1 {
			t.Fatal("old executable did not commit its exact MFA-only settings history")
		}
		completions[index] = result.Change
		call(http.MethodGet, "/v1/auth/me", bearer, nil, http.StatusUnauthorized, nil)
	}
	const pendingCommand = "retained-settings-unfinished"
	caller := login(1, "retained-settings-version-three")
	pendingID := oldProof(1, caller, pendingCommand, 3, true)
	oldHistory := func() []byte {
		t.Helper()
		var result []byte
		if err := admin.QueryRow(ctx, `SELECT jsonb_build_object(
		 'changes',(SELECT jsonb_agg(to_jsonb(c)-'previous_password_settings'-'password_settings' ORDER BY expected_version)
		   FROM iam.account_security_settings_changes c WHERE tenant_id=$1 AND expected_version<3),
		 'proofs',(SELECT jsonb_agg(to_jsonb(p)-'password_settings' ORDER BY id) FROM iam.step_ups p
		   WHERE tenant_id=$1 AND request_id IN ('retained-settings-change-0','retained-settings-change-1')),
		 'unfinished',(SELECT to_jsonb(p)-'password_settings' FROM iam.step_ups p WHERE tenant_id=$1 AND id=$2))`, tenant, pendingID).Scan(&result); err != nil {
			t.Fatal("read immutable predecessor settings lineage", err)
		}
		return result
	}
	original := oldHistory()
	t.Cleanup(func() { clear(original) })
	assertHistory := func() {
		t.Helper()
		after := oldHistory()
		defer clear(after)
		if !bytes.Equal(original, after) {
			t.Fatal("upgrade/replay changed original settings facts or operation proof")
		}
		var unchanged bool
		if err := admin.QueryRow(ctx, `SELECT (SELECT count(*)=2 FROM iam.account_security_settings_changes WHERE tenant_id=$1 AND expected_version<3
		 AND password_settings IS NULL AND previous_password_settings IS NULL)
		 AND (SELECT count(*)=3 FROM iam.step_ups WHERE tenant_id=$1 AND password_settings IS NULL
		 AND request_id IN ('retained-settings-change-0','retained-settings-change-1',$2))`, tenant, pendingCommand).Scan(&unchanged); err != nil || !unchanged {
			t.Fatal("migration invented password commitments for old settings history", err)
		}
	}
	return func() func() {
		t.Helper()
		assertHistory()
		call(http.MethodGet, "/v1/auth/me", caller, nil, http.StatusOK, nil)
		var live bool
		if err := admin.QueryRow(ctx, `SELECT state='PROVED' AND expires_at>clock_timestamp() AND consumed_at IS NULL AND password_settings IS NULL
		 FROM iam.step_ups WHERE tenant_id=$1 AND id=$2`, tenant, pendingID).Scan(&live); err != nil || !live {
			t.Fatal("old settings negative must use a still-live, genuinely proved intent", err)
		}
		var historical iamv1.AccountSecuritySettingsChange
		call(http.MethodGet, path+"/changes/"+completions[1].RequestID, caller, nil, http.StatusOK, &historical)
		if !reflect.DeepEqual(historical, completions[1]) || historical.Settings.Password != nil {
			t.Fatal("current completion reader rewrote the predecessor response")
		}
		call(http.MethodGet, "/v1/auth/step-up/by-request/"+pendingCommand, caller, nil, http.StatusServiceUnavailable, nil)
		defaultRules := iamv1.AccountPasswordSettings{ExpiryMode: iamv1.PasswordExpiryChange, MinimumLength: 15, HistoryCount: 1}
		call(http.MethodPut, path, caller, iamv1.UpdateAccountSecuritySettingsRequest{RequestID: pendingCommand, StepUpID: pendingID,
			ExpectedResourceVersion: 3, MFA: iamv1.AccountMFASettings{RequiredForUsers: true}, Password: defaultRules}, http.StatusUnauthorized, nil)
		assertHistory()
		var clean bool
		if err := admin.QueryRow(ctx, `SELECT (SELECT security_settings_version=3 AND NOT mfa_required_for_users AND password_settings=iam.default_password_settings() FROM iam.accounts WHERE id=$1)
		 AND NOT EXISTS(SELECT 1 FROM iam.account_security_settings_changes WHERE tenant_id=$1 AND expected_version>=3)
		 AND NOT EXISTS(SELECT 1 FROM iam.audit_outbox WHERE tenant_id=$1 AND event_document->>'action'='iam.security-settings.updated' AND event_document->>'requestId'=$2)
		 AND EXISTS(SELECT 1 FROM iam.totp_attempts WHERE tenant_id=$1 AND user_id=$3 AND used_attempts=5 AND state='SUCCEEDED')`, tenant, pendingCommand, user.ID).Scan(&clean); err != nil || !clean {
			t.Fatal("old unbound proof caused partial settings effects", err)
		}
		// The second operator really spent five OTP attempts in the predecessor.
		// Neither upgrade nor a new purpose refunds that ten-minute budget. Use
		// the other independently qualified operator, not a counter reset or an
		// increased gate timeout, for the new successful settings mutation.
		freshCaller := login(0, "retained-settings-current-root")
		const windowInitial, windowCurrent = "Retained-Window-Initial-Password-531!", "Retained-Window-Current-Password-729!"
		*sensitive = append(*sensitive, windowInitial, windowCurrent)
		windowUser := createIAMUser(t, endpoint, freshCaller, "retained.password.window", "Retained password window", windowInitial, "retained-window-create")
		windowRealm := windowUser.LoginName + "@" + tenant
		windowSession := loginIAM(t, endpoint, windowRealm, windowInitial, "retained-window-initial-login")
		*sensitive = append(*sensitive, windowSession.Credential)
		changePasswordIAM(t, endpoint, windowSession.Credential, windowInitial, windowCurrent, "retained-window-password")
		// The original operator has spent its real OTP budget. A separately
		// authorized, newly changed USER performs the later mode transition;
		// no timer, guess counter or old authentication is reset for the gate.
		modeUser := createIAMUser(t, endpoint, freshCaller, "retained.password.mode", "Password mode operator", initial, "retained-mode-create")
		createIAMPolicyAttachment(t, endpoint, freshCaller, modeUser.ID, policy.Policy.ID, "retained-mode-grant")
		modeFirst := loginIAM(t, endpoint, modeUser.LoginName+"@"+tenant, initial, "retained-mode-login")
		*sensitive = append(*sensitive, modeFirst.Credential)
		changePasswordIAM(t, endpoint, modeFirst.Credential, initial, password, "retained-mode-password")
		resetOperator := createIAMUser(t, endpoint, freshCaller, "retained.expiry.operator", "Explicit expiry reset operator", initial, "retained-expiry-operator-create")
		var resetPolicy iamv1.PolicyDetail
		call(http.MethodPost, "/v1/policies", freshCaller, iamv1.CreatePolicyRequest{DisplayName: "Explicit two-user password reset", RequestID: "retained-expiry-reset-policy",
			Document: iamv1.PolicyDocument{LanguageVersion: iamv1.PolicyLanguageVersion, Scope: iamv1.AuthorityScopeTenant,
				Statements: []iamv1.PolicyStatement{{SID: "reset", Effect: iamv1.PolicyAllow,
					Actions: []iamv1.Action{iamv1.ActionIAMUserRead, iamv1.ActionIAMUserPasswordReset},
					Resources: []iamv1.PolicyResourceSelector{
						{Kind: iamv1.ResourceUser, Match: iamv1.PolicyResourceExact, ID: string(resetRaceUsers[0].ID)},
						{Kind: iamv1.ResourceUser, Match: iamv1.PolicyResourceExact, ID: string(resetRaceUsers[1].ID)},
					}}}}}, http.StatusCreated, &resetPolicy)
		createIAMPolicyAttachment(t, endpoint, freshCaller, resetOperator.ID, resetPolicy.Policy.ID, "retained-expiry-operator-grant")
		resetOperatorRealm := resetOperator.LoginName + "@" + tenant
		resetOperatorFirst := loginIAM(t, endpoint, resetOperatorRealm, initial, "retained-expiry-operator-login")
		*sensitive = append(*sensitive, resetOperatorFirst.Credential)
		changePasswordIAM(t, endpoint, resetOperatorFirst.Credential, initial, password, "retained-expiry-operator-password")
		modeIndex := len(actors)
		actors = append(actors, settingsActor{first: modeFirst, realm: modeUser.LoginName + "@" + tenant})
		bindActor(modeIndex)
		const command = "retained-settings-password-only"
		rules := iamv1.AccountPasswordSettings{ExpiryMode: iamv1.PasswordExpiryAdminReset, MaxAgeDays: 1, MinimumLength: 24, HistoryCount: 0}
		var proof iamv1.StepUp
		call(http.MethodPost, "/v1/auth/step-up", freshCaller, iamv1.StartStepUpRequest{RequestID: command, Operation: iamv1.StepUpUpdateSecuritySettings, ExpectedFactorRevision: 2,
			SecuritySettings: &iamv1.SecuritySettingsUpdateIntent{ExpectedResourceVersion: 3, MFA: iamv1.AccountMFASettings{}, Password: &rules}}, http.StatusOK, &proof)
		call(http.MethodPost, "/v1/auth/step-up/"+proof.ID+":verify", freshCaller,
			map[string]string{"requestId": command + "-proof", "password": password, "code": nextCode(0)}, http.StatusOK, &proof)
		var applied iamv1.UpdateAccountSecuritySettingsResponse
		call(http.MethodPut, path, freshCaller, iamv1.UpdateAccountSecuritySettingsRequest{RequestID: command, StepUpID: proof.ID, ExpectedResourceVersion: 3,
			MFA: iamv1.AccountMFASettings{}, Password: rules}, http.StatusOK, &applied)
		if applied.Outcome != "APPLIED" || !applied.Change.CallerSessionEnded || applied.Change.Settings.ResourceVersion != 4 ||
			applied.Change.Settings.MFA.RequiredForUsers || applied.Change.Settings.Password == nil || *applied.Change.Settings.Password != rules {
			t.Fatal("new password-only settings did not continue the actual predecessor lineage")
		}
		call(http.MethodGet, "/v1/auth/me", caller, nil, http.StatusUnauthorized, nil)
		call(http.MethodGet, "/v1/auth/me", freshCaller, nil, http.StatusUnauthorized, nil)
		call(http.MethodGet, "/v1/auth/me", windowSession.Credential, nil, http.StatusUnauthorized, nil)
		var unknownAge bool
		if err := admin.QueryRow(ctx, `SELECT c.password_changed_at IS NULL AND NOT p.must_change_password
			AND m.enrollment_state='NEVER_BOUND' AND m.revision=1
			FROM iam.user_credentials c JOIN iam.principals p ON (p.tenant_id,p.id)=(c.tenant_id,c.principal_id)
			JOIN iam.user_mfa_states m ON (m.tenant_id,m.user_id)=(c.tenant_id,c.principal_id)
			WHERE c.tenant_id=$1 AND c.principal_id=$2`, tenant, ageUser.ID).Scan(&unknownAge); err != nil || !unknownAge {
			t.Fatal("retained ordinary USER did not preserve its real unknown password age", err)
		}
		// A nontransactional sequence proves the real request reached the final
		// outbox write; it is not authentication state or a fabricated success.
		if _, err := admin.Exec(ctx, `CREATE SEQUENCE public.retained_expiry_fault_seen;
		 CREATE FUNCTION public.retained_expiry_fault() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fault$
		 BEGIN
		 IF NEW.event_document->>'requestId' IN ('retained-reset-fault-password','retained-reset-fault-bound','retained-age-fault-change') THEN
		   PERFORM nextval('public.retained_expiry_fault_seen');
		   RAISE EXCEPTION 'retained expiry outbox fault' USING ERRCODE='P0001';
		 END IF;
		 RETURN NEW; END $fault$;
		 CREATE TRIGGER retained_expiry_fault BEFORE INSERT ON iam.audit_outbox
		 FOR EACH ROW EXECUTE FUNCTION public.retained_expiry_fault()`); err != nil {
			t.Fatal("install isolated expiry outbox fault", err)
		}
		defer func() {
			cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			if _, err := admin.Exec(cleanup, `DROP TRIGGER retained_expiry_fault ON iam.audit_outbox;
			 DROP FUNCTION public.retained_expiry_fault(); DROP SEQUENCE public.retained_expiry_fault_seen`); err != nil {
				t.Error("remove isolated expiry outbox fault", err)
			}
		}()
		securityState := func(id iamv1.PrincipalID) []byte {
			t.Helper()
			// Reservation charges survive failure; compare authentication effects
			// here and assert the exact challenge charge separately below.
			var state []byte
			if err := admin.QueryRow(ctx, `SELECT jsonb_build_object('credential',to_jsonb(c),'principal',to_jsonb(p),
			 'mfa',(SELECT to_jsonb(m) FROM iam.user_mfa_states m WHERE tenant_id=$1 AND user_id=$2),
			 'factors',(SELECT jsonb_agg(to_jsonb(f) ORDER BY id) FROM iam.totp_authenticators f WHERE tenant_id=$1 AND user_id=$2),
			 'challenges',(SELECT jsonb_agg(to_jsonb(ch)-'attempts' ORDER BY id) FROM iam.authentication_challenges ch WHERE tenant_id=$1 AND user_id=$2),
			 'sessions',(SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM iam.sessions s WHERE tenant_id=$1 AND principal_id=$2),
			 'facts',(SELECT jsonb_agg(event_document ORDER BY event_id) FROM iam.audit_outbox WHERE tenant_id=$1 AND event_document#>>'{actor,id}'=$2))
			 FROM iam.user_credentials c JOIN iam.principals p ON (p.tenant_id,p.id)=(c.tenant_id,c.principal_id)
			 WHERE c.tenant_id=$1 AND c.principal_id=$2`, tenant, id).Scan(&state); err != nil {
				t.Fatal("read atomic expiry state", err)
			}
			return state
		}
		assertUnchanged := func(id iamv1.PrincipalID, before []byte) {
			t.Helper()
			after := securityState(id)
			defer clear(after)
			if !bytes.Equal(before, after) {
				t.Fatal("outbox failure partially changed expiry credentials, factor, challenge, Session or facts")
			}
		}
		beforePasswordFault := securityState(faultUser.ID)
		defer clear(beforePasswordFault)
		call(http.MethodPost, "/v1/auth/login", "", map[string]string{"loginName": faultRealm, "password": password, "requestId": "retained-reset-fault-password"}, http.StatusServiceUnavailable, nil)
		assertUnchanged(faultUser.ID, beforePasswordFault)
		var boundFault iamv1.LoginResponse
		call(http.MethodPost, "/v1/auth/login", "", map[string]string{"loginName": boundFaultRealm, "password": password, "requestId": "retained-reset-fault-login"}, http.StatusOK, &boundFault)
		if boundFault.Challenge == nil || boundFault.Challenge.NextStep != "TOTP" {
			t.Fatal("bound fault must use an actual pending TOTP challenge")
		}
		beforeBoundFault := securityState(boundFaultUser.ID)
		defer clear(beforeBoundFault)
		call(http.MethodPost, "/v1/auth/challenges/"+boundFault.Challenge.ID+":verify", "",
			map[string]string{"requestId": "retained-reset-fault-bound", "challengeCredential": secret(boundFault.ChallengeCredential), "code": nextCode(3)}, http.StatusServiceUnavailable, nil)
		assertUnchanged(boundFaultUser.ID, beforeBoundFault)
		var charged bool
		if err := admin.QueryRow(ctx, `SELECT (SELECT is_called AND last_value=2 FROM public.retained_expiry_fault_seen)
		 AND EXISTS(SELECT 1 FROM iam.password_attempts WHERE tenant_id=$1 AND principal_id=$2 AND state='RESERVED' AND used_attempts>0 AND completed_at IS NULL)
		 AND EXISTS(SELECT 1 FROM iam.totp_attempts WHERE tenant_id=$1 AND user_id=$3 AND state='RESERVED' AND used_attempts>0 AND completed_at IS NULL)
		 AND EXISTS(SELECT 1 FROM iam.authentication_challenges WHERE tenant_id=$1 AND id=$4 AND user_id=$3 AND attempts=1 AND state='PENDING')`,
			tenant, faultUser.ID, boundFaultUser.ID, boundFault.Challenge.ID).Scan(&charged); err != nil || !charged {
			t.Fatal("late failure was not reached or refunded a committed authentication reservation", err)
		}
		passwordState := func() []byte {
			t.Helper()
			var value []byte
			if err := admin.QueryRow(ctx, `SELECT jsonb_agg(jsonb_build_object('credential',to_jsonb(c),'principal',to_jsonb(p)) ORDER BY p.id)
			 FROM iam.user_credentials c JOIN iam.principals p ON (p.tenant_id,p.id)=(c.tenant_id,c.principal_id)
			 WHERE c.tenant_id=$1 AND c.principal_id IN ($2,$3)`, tenant, ageUser.ID, boundAdminUser.ID).Scan(&value); err != nil {
				t.Fatal("read expiry credential boundary", err)
			}
			return value
		}
		beforeDenial := passwordState()
		defer clear(beforeDenial)
		call(http.MethodPost, "/v1/auth/login", "", map[string]string{"loginName": ageRealm, "password": initial, "requestId": "retained-reset-wrong-password"}, http.StatusUnauthorized, nil)
		var terminal iamv1.LoginResponse
		call(http.MethodPost, "/v1/auth/login", "", map[string]string{"loginName": ageRealm, "password": password, "requestId": "retained-reset-password-only"}, http.StatusOK, &terminal)
		if terminal != (iamv1.LoginResponse{Outcome: iamv1.LoginAdminResetRequired, PasswordResetReason: iamv1.PasswordResetAgeUnknown}) {
			t.Fatal("password-only administrator instruction issued authority or misreported unknown age")
		}
		var resetChallenge iamv1.LoginResponse
		call(http.MethodPost, "/v1/auth/login", "", map[string]string{"loginName": boundAdminRealm, "password": password, "requestId": "retained-reset-bound-login"}, http.StatusOK, &resetChallenge)
		if resetChallenge.Outcome != iamv1.LoginChallengeRequired || resetChallenge.Challenge == nil || resetChallenge.Challenge.NextStep != "TOTP" {
			t.Fatal("administrator-reset mode bypassed bound TOTP")
		}
		resetCredential := secret(resetChallenge.ChallengeCredential)
		resetPath := "/v1/auth/challenges/" + resetChallenge.Challenge.ID
		call(http.MethodPost, resetPath+":password", "", map[string]string{"requestId": "retained-reset-not-self-change", "challengeCredential": resetCredential, "newPassword": windowCurrent}, http.StatusUnauthorized, nil)
		resetCode := nextCode(4)
		call(http.MethodPost, resetPath+":verify", "", map[string]string{"requestId": "retained-reset-bound-proof", "challengeCredential": resetCredential, "code": resetCode}, http.StatusOK, &terminal)
		if terminal != (iamv1.LoginResponse{Outcome: iamv1.LoginAdminResetRequired, PasswordResetReason: iamv1.PasswordResetAgeUnknown}) {
			t.Fatal("bound administrator instruction issued authority or misreported unknown age")
		}
		call(http.MethodPost, resetPath+":verify", "", map[string]string{"requestId": "retained-reset-bound-repeat", "challengeCredential": resetCredential, "code": resetCode}, http.StatusUnauthorized, nil)
		var resetReplay iamv1.LoginResponse
		call(http.MethodPost, "/v1/auth/login", "", map[string]string{"loginName": boundAdminRealm, "password": password, "requestId": "retained-reset-bound-relogin"}, http.StatusOK, &resetReplay)
		if resetReplay.Challenge == nil {
			t.Fatal("bound repeat login did not require proof")
		}
		call(http.MethodPost, "/v1/auth/challenges/"+resetReplay.Challenge.ID+":verify", "",
			map[string]string{"requestId": "retained-reset-reused-otp", "challengeCredential": secret(resetReplay.ChallengeCredential), "code": resetCode}, http.StatusUnauthorized, nil)
		afterDenial := passwordState()
		defer clear(afterDenial)
		if !bytes.Equal(beforeDenial, afterDenial) {
			t.Fatal("reset instruction changed credentials or principal state")
		}
		denialHistory := func() []byte {
			t.Helper()
			var value []byte
			if err := admin.QueryRow(ctx, `SELECT jsonb_agg(event_document ORDER BY event_id) FROM iam.audit_outbox
			 WHERE tenant_id=$1 AND event_document->>'action'='iam.user.password-reset-required'`, tenant).Scan(&value); err != nil {
				t.Fatal("read reset denial history", err)
			}
			return value
		}
		var denialFacts []auditv1.Event
		denials := denialHistory()
		t.Cleanup(func() { clear(denials) })
		if json.Unmarshal(denials, &denialFacts) != nil || len(denialFacts) != 2 {
			t.Fatal("wrong password or repeated OTP wrote a terminal denial")
		}
		for _, fact := range denialFacts {
			if auditv1.ValidateEventForSource(auditv1.SourceIAM, fact) != nil || fact.Result != auditv1.ResultDenied {
				t.Fatal("terminal denial is not a closed IAM fact")
			}
		}
		var deniedAtomically bool
		if err := admin.QueryRow(ctx, `SELECT c.state='CONSUMED' AND c.session_id IS NULL AND c.issuance_event_id IS NULL
			AND c.password_challenge_id IS NULL AND c.verified_step=f.last_consumed_step AND f.state='ACTIVE'
			AND c.mfa_revision=f.bound_revision AND o.event_document->>'requestId'='retained-reset-bound-proof'
			AND NOT EXISTS(SELECT 1 FROM iam.sessions s WHERE s.tenant_id=c.tenant_id AND s.principal_id IN ($3,$4) AND s.security_settings_version=4)
			AND EXISTS(SELECT 1 FROM iam.password_attempts p WHERE p.tenant_id=c.tenant_id AND p.principal_id=$3 AND p.state='SUCCEEDED' AND p.used_attempts>0)
			FROM iam.authentication_challenges c JOIN iam.totp_authenticators f ON (f.tenant_id,f.id)=(c.tenant_id,c.factor_id)
			JOIN iam.audit_outbox o ON (o.tenant_id,o.event_id)=(c.tenant_id,c.password_reset_required_event_id)
			WHERE c.tenant_id=$1 AND c.id=$2`, tenant, resetChallenge.Challenge.ID, ageUser.ID, boundAdminUser.ID).Scan(&deniedAtomically); err != nil || !deniedAtomically {
			t.Fatal("terminal lost its consumed origin, retained budget or exact denial association", err)
		}
		modeCaller := login(modeIndex, "retained-mode-current")
		rules.ExpiryMode = iamv1.PasswordExpiryChange
		const modeCommand = "retained-mode-change"
		call(http.MethodPost, "/v1/auth/step-up", modeCaller, iamv1.StartStepUpRequest{RequestID: modeCommand, Operation: iamv1.StepUpUpdateSecuritySettings, ExpectedFactorRevision: 2,
			SecuritySettings: &iamv1.SecuritySettingsUpdateIntent{ExpectedResourceVersion: 4, MFA: iamv1.AccountMFASettings{}, Password: &rules}}, http.StatusOK, &proof)
		call(http.MethodPost, "/v1/auth/step-up/"+proof.ID+":verify", modeCaller,
			map[string]string{"requestId": modeCommand + "-proof", "password": password, "code": nextCode(modeIndex)}, http.StatusOK, &proof)
		// Hold the real settings transaction after it owns the Account lock.
		// A live old challenge with an unused, valid OTP must wait behind it;
		// after commit, its old version must fail before consuming that proof.
		raceCode := nextCode(4)
		otpState := func() []byte {
			t.Helper()
			var state []byte
			if err := admin.QueryRow(ctx, `SELECT jsonb_build_object('attempt',to_jsonb(a),'factor',to_jsonb(f))
			 FROM iam.totp_attempts a JOIN iam.totp_authenticators f ON (f.tenant_id,f.user_id)=(a.tenant_id,a.user_id)
			 WHERE a.tenant_id=$1 AND a.user_id=$2 AND f.id=$3`, tenant, boundAdminUser.ID, actors[4].factor).Scan(&state); err != nil {
				t.Fatal("read settings race authentication state", err)
			}
			return state
		}
		beforeSettingsRace := otpState()
		defer clear(beforeSettingsRace)
		if _, err := admin.Exec(ctx, `CREATE FUNCTION public.retained_expiry_barrier() RETURNS trigger LANGUAGE plpgsql AS $barrier$
		 BEGIN IF (NEW.event_document->>'requestId',NEW.event_document->>'action') IN
		 (('retained-mode-change','iam.security-settings.updated'),('retained-expiry-reset-first','iam.user.password-reset'),
		 ('retained-expiry-change-first','iam.user.password-changed'))
		 THEN PERFORM pg_advisory_xact_lock_shared(54857,31); END IF; RETURN NEW; END $barrier$;
		 CREATE TRIGGER retained_expiry_barrier BEFORE INSERT ON iam.audit_outbox FOR EACH ROW EXECUTE FUNCTION public.retained_expiry_barrier()`); err != nil {
			t.Fatal("install isolated expiry race barrier", err)
		}
		defer func() {
			cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			if _, err := admin.Exec(cleanup, `DROP TRIGGER retained_expiry_barrier ON iam.audit_outbox; DROP FUNCTION public.retained_expiry_barrier()`); err != nil {
				t.Error("remove isolated settings race barrier", err)
			}
		}()
		type raceResult struct {
			processResponse
			err error
		}
		startRequest := func(method, route, bearer string, body any) <-chan raceResult {
			t.Helper()
			encoded, err := json.Marshal(body)
			if err != nil {
				t.Fatal("encode settings race request", err)
			}
			request, err := http.NewRequestWithContext(ctx, method, endpoint+route, bytes.NewReader(encoded))
			if err != nil {
				t.Fatal("construct settings race request", err)
			}
			request.Header.Set("Content-Type", "application/json")
			if bearer != "" {
				request.Header.Set("Authorization", "Bearer "+bearer)
			}
			result := make(chan raceResult, 1)
			go func() {
				defer clear(encoded)
				response, err := processHTTPClient().Do(request)
				if err != nil {
					result <- raceResult{err: err}
					return
				}
				defer response.Body.Close()
				data, err := io.ReadAll(io.LimitReader(response.Body, 2*1024*1024))
				result <- raceResult{processResponse: processResponse{Status: response.StatusCode, Body: data}, err: err}
			}()
			return result
		}
		waitForLock := func(condition func() bool) {
			t.Helper()
			wait, stop := context.WithTimeout(ctx, 2*time.Second)
			defer stop()
			ticker := time.NewTicker(10 * time.Millisecond)
			defer ticker.Stop()
			for !condition() {
				select {
				case <-ticker.C:
				case <-wait.Done():
					t.Fatal("real settings/authentication lock ordering was not observed")
				}
			}
		}
		orderedRequests := func(first, second func() <-chan raceResult) (raceResult, raceResult) {
			t.Helper()
			if _, err := admin.Exec(ctx, "SELECT pg_advisory_lock(54857,31)"); err != nil {
				t.Fatal("hold expiry race commit", err)
			}
			var once sync.Once
			release := func() {
				once.Do(func() {
					cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
					defer stop()
					if _, err := admin.Exec(cleanup, "SELECT pg_advisory_unlock(54857,31)"); err != nil {
						t.Error("release expiry race commit", err)
					}
				})
			}
			defer release()
			firstResult := first()
			var writerPID int32
			waitForLock(func() bool {
				if err := admin.QueryRow(ctx, `SELECT COALESCE(min(pid),0) FROM pg_locks WHERE locktype='advisory' AND NOT granted
				 AND database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND classid=54857 AND objid=31`).Scan(&writerPID); err != nil {
					t.Fatal("observe expiry transaction barrier", err)
				}
				return writerPID != 0
			})
			secondResult := second()
			waitForLock(func() bool {
				var blocked bool
				if err := admin.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity
				 WHERE datname=current_database() AND $1=ANY(pg_blocking_pids(pid)))`, writerPID).Scan(&blocked); err != nil {
					t.Fatal("observe competing expiry request waiting for the writer", err)
				}
				return blocked
			})
			release()
			return <-firstResult, <-secondResult
		}
		modeResponse, staleResponse := orderedRequests(func() <-chan raceResult {
			return startRequest(http.MethodPut, path, modeCaller, iamv1.UpdateAccountSecuritySettingsRequest{RequestID: modeCommand, StepUpID: proof.ID, ExpectedResourceVersion: 4,
				MFA: iamv1.AccountMFASettings{}, Password: rules})
		}, func() <-chan raceResult {
			return startRequest(http.MethodPost, "/v1/auth/challenges/"+resetReplay.Challenge.ID+":verify", "",
				map[string]string{"requestId": "retained-reset-settings-race", "challengeCredential": secret(resetReplay.ChallengeCredential), "code": raceCode})
		})
		if modeResponse.err != nil || modeResponse.Status != http.StatusOK || json.Unmarshal(modeResponse.Body, &applied) != nil ||
			staleResponse.err != nil || staleResponse.Status != http.StatusUnauthorized {
			t.Fatalf("settings/authentication race: settings status=%d transportFailed=%t, stale status=%d transportFailed=%t",
				modeResponse.Status, modeResponse.err != nil, staleResponse.Status, staleResponse.err != nil)
		}
		afterSettingsRace := otpState()
		defer clear(afterSettingsRace)
		if !bytes.Equal(beforeSettingsRace, afterSettingsRace) {
			t.Fatal("stale authentication consumed an OTP or budget after waiting for changed settings")
		}
		if applied.Outcome != "APPLIED" || applied.Change.Settings.ResourceVersion != 5 {
			t.Fatal("explicit expiry mode change did not advance current settings")
		}
		// Prove this factor before independent password-only work. Its next
		// real OTP window can elapse during that work and the actual restart;
		// neither the production verifier nor the gate deadline is shortened.
		const ageReplacement = "Retained-Unknown-Age-Replaced-Password-964!"
		*sensitive = append(*sensitive, ageReplacement)
		var boundAgeLogin, boundAgeStage iamv1.LoginResponse
		call(http.MethodPost, "/v1/auth/login", "", map[string]string{"loginName": boundAgeRealm, "password": password, "requestId": "retained-bound-age-login"}, http.StatusOK, &boundAgeLogin)
		if boundAgeLogin.Outcome != iamv1.LoginChallengeRequired || boundAgeLogin.Challenge == nil || boundAgeLogin.Challenge.NextStep != "TOTP" {
			t.Fatal("unknown age bypassed the actual existing factor")
		}
		boundAgeCredential := secret(boundAgeLogin.ChallengeCredential)
		boundAgePath := "/v1/auth/challenges/" + boundAgeLogin.Challenge.ID
		call(http.MethodPost, boundAgePath+":password", "", map[string]string{"requestId": "retained-bound-age-early", "challengeCredential": boundAgeCredential, "newPassword": ageReplacement}, http.StatusUnauthorized, nil)
		call(http.MethodPost, boundAgePath+":verify", "", map[string]string{"requestId": "retained-bound-age-proof", "challengeCredential": boundAgeCredential, "code": nextCode(2)}, http.StatusOK, &boundAgeStage)
		if boundAgeStage.Outcome != iamv1.LoginChallengeRequired || boundAgeStage.Challenge == nil || boundAgeStage.Challenge.Purpose != "LOGIN" ||
			boundAgeStage.Challenge.NextStep != "PASSWORD_CHANGE" || boundAgeStage.Credential.Present() || boundAgeStage.Session != (iamv1.Session{}) {
			t.Fatal("expired bound login did not require its real OTP successor")
		}
		boundAgeStageCredential := secret(boundAgeStage.ChallengeCredential)
		var boundAgeChanged iamv1.ChallengePasswordChangeResponse
		call(http.MethodPost, "/v1/auth/challenges/"+boundAgeStage.Challenge.ID+":password", "",
			map[string]string{"requestId": "retained-bound-age-replacement", "challengeCredential": boundAgeStageCredential, "newPassword": ageReplacement}, http.StatusOK, &boundAgeChanged)
		if boundAgeChanged.NextStep != "REAUTHENTICATE" {
			t.Fatal("bound expiry replacement issued a Session")
		}
		var boundAgeReauthentication iamv1.LoginResponse
		call(http.MethodPost, "/v1/auth/login", "", map[string]string{"loginName": boundAgeRealm, "password": ageReplacement, "requestId": "retained-bound-age-new-login"}, http.StatusOK, &boundAgeReauthentication)
		if boundAgeReauthentication.Challenge == nil || boundAgeReauthentication.Challenge.NextStep != "TOTP" || boundAgeReauthentication.Credential.Present() {
			t.Fatal("expiry replacement removed the original factor requirement")
		}
		boundAgeReauthCredential := secret(boundAgeReauthentication.ChallengeCredential)
		resetAccess := loginIAM(t, endpoint, resetOperatorRealm, password, "retained-expiry-operator-current")
		*sensitive = append(*sensitive, resetAccess.Credential)
		var resetRaceChecks []func()
		for index, user := range resetRaceUsers {
			const resetPassword = "Retained-Expiry-Administrator-Reset-732!"
			const changedPassword = "Retained-Expiry-Challenge-Winner-651!"
			*sensitive = append(*sensitive, resetPassword, changedPassword)
			resetWins := index == 0
			prefix := fmt.Sprintf("retained-expiry-race-%d", index)
			var access iamv1.UserAccess
			call(http.MethodGet, "/v1/users/"+string(user.ID), resetAccess.Credential, nil, http.StatusOK, &access)
			var generation int64
			var unknown bool
			if err := admin.QueryRow(ctx, "SELECT credential_version,password_changed_at IS NULL FROM iam.user_credentials WHERE tenant_id=$1 AND principal_id=$2",
				tenant, user.ID).Scan(&generation, &unknown); err != nil || !unknown {
				t.Fatal("reset race requires genuine predecessor password age", err)
			}
			var challenge iamv1.LoginResponse
			call(http.MethodPost, "/v1/auth/login", "", map[string]string{"loginName": user.LoginName + "@" + tenant, "password": password, "requestId": prefix + "-challenge"}, http.StatusOK, &challenge)
			if challenge.Challenge == nil || challenge.Challenge.Purpose != "LOGIN" || challenge.Challenge.NextStep != "PASSWORD_CHANGE" || challenge.Credential.Present() {
				t.Fatal("reset race did not start with a real restricted expiry challenge")
			}
			challengeCredential := secret(challenge.ChallengeCredential)
			challengePath := "/v1/auth/challenges/" + challenge.Challenge.ID
			resetRequest, changeRequest := "retained-expiry-reset-first", "retained-expiry-change-stale"
			if !resetWins {
				resetRequest, changeRequest = "retained-expiry-reset-stale", "retained-expiry-change-first"
			}
			reset := func() <-chan raceResult {
				return startRequest(http.MethodPost, "/v1/users/"+string(user.ID)+":reset-password", resetAccess.Credential,
					map[string]any{"requestId": resetRequest, "resourceVersion": access.User.ResourceVersion, "initialPassword": resetPassword})
			}
			change := func() <-chan raceResult {
				return startRequest(http.MethodPost, challengePath+":password", "",
					map[string]string{"requestId": changeRequest, "challengeCredential": challengeCredential, "newPassword": changedPassword})
			}
			var resetResult, changeResult raceResult
			if resetWins {
				resetResult, changeResult = orderedRequests(reset, change)
			} else {
				changeResult, resetResult = orderedRequests(change, reset)
			}
			wantReset, wantChange := http.StatusOK, http.StatusUnauthorized
			// Reset fences the original challenge by generation/version; it need
			// not rewrite the immutable source into a synthetic completion.
			winnerPassword, expectedState, winnerRequest, winnerAction := resetPassword, "PENDING", resetRequest, "iam.user.password-reset"
			if !resetWins {
				wantReset, wantChange = http.StatusConflict, http.StatusOK
				winnerPassword, expectedState, winnerRequest, winnerAction = changedPassword, "CONSUMED", changeRequest, "iam.user.password-changed"
			}
			if resetResult.err != nil || changeResult.err != nil || resetResult.Status != wantReset || changeResult.Status != wantChange {
				t.Fatalf("expiry reset ordering %d: reset status=%d transportFailed=%t, change status=%d transportFailed=%t",
					index, resetResult.Status, resetResult.err != nil, changeResult.Status, changeResult.err != nil)
			}
			var atomic bool
			if err := admin.QueryRow(ctx, `SELECT c.credential_version=$3+1 AND c.password_changed_at IS NOT NULL
			 AND p.resource_version=$4+1 AND p.must_change_password=$5
			 AND ch.state=$6 AND ch.password_reset_required_event_id IS NULL AND ch.session_id IS NULL
			 AND ch.credential_generation=$3 AND ch.credential_generation<c.credential_version
			 AND (ch.password_changed_event_id IS NULL)=$5
			 AND NOT EXISTS(SELECT 1 FROM iam.sessions WHERE tenant_id=$1 AND principal_id=$2 AND credential_version>$3)
			 AND (SELECT count(*)=1 FROM iam.audit_outbox WHERE tenant_id=$1 AND event_document->>'requestId' IN ($7,$8)
			   AND event_document->>'action' IN ('iam.user.password-reset','iam.user.password-changed'))
			 AND EXISTS(SELECT 1 FROM iam.audit_outbox WHERE tenant_id=$1 AND event_document->>'requestId'=$9 AND event_document->>'action'=$10
			   AND event_document#>>'{target,id}'=$2 AND event_document->>'result'='SUCCEEDED')
			 AND ((SELECT count(*) FROM iam.user_password_reset_completions WHERE tenant_id=$1 AND user_id=$2 AND request_id=$7)=CASE WHEN $5 THEN 1 ELSE 0 END)
			 FROM iam.user_credentials c JOIN iam.principals p ON (p.tenant_id,p.id)=(c.tenant_id,c.principal_id)
			 JOIN iam.authentication_challenges ch ON (ch.tenant_id,ch.user_id)=(c.tenant_id,c.principal_id) AND ch.id=$11
			 WHERE c.tenant_id=$1 AND c.principal_id=$2`, tenant, user.ID, generation, access.User.ResourceVersion, resetWins,
				expectedState, resetRequest, changeRequest, winnerRequest, winnerAction, challenge.Challenge.ID).Scan(&atomic); err != nil || !atomic {
				t.Fatal("expiry/reset competition lost its single credential generation, exact completion or fact", err)
			}
			call(http.MethodPost, challengePath+":password", "", map[string]string{"requestId": prefix + "-replay", "challengeCredential": challengeCredential, "newPassword": changedPassword}, http.StatusUnauthorized, nil)
			var authenticated iamv1.LoginResponse
			call(http.MethodPost, "/v1/auth/login", "", map[string]string{"loginName": user.LoginName + "@" + tenant, "password": winnerPassword, "requestId": prefix + "-winner-login"}, http.StatusOK, &authenticated)
			if authenticated.Outcome != iamv1.LoginAuthenticated || !authenticated.Credential.Present() || authenticated.MustChangePassword != resetWins {
				t.Fatal("expiry/reset winner password or forced-change requirement was not preserved")
			}
			secret(authenticated.Credential)
			retainedState := securityState(user.ID)
			t.Cleanup(func() { clear(retainedState) })
			resetRaceChecks = append(resetRaceChecks, func() {
				call(http.MethodPost, challengePath+":password", "", map[string]string{"requestId": prefix + "-restart-replay", "challengeCredential": challengeCredential, "newPassword": changedPassword}, http.StatusUnauthorized, nil)
				assertUnchanged(user.ID, retainedState)
			})
		}
		call(http.MethodPost, "/v1/auth/login", "", map[string]string{"loginName": ageRealm, "password": initial, "requestId": "retained-age-wrong-password"}, http.StatusUnauthorized, nil)
		var ageLogin iamv1.LoginResponse
		call(http.MethodPost, "/v1/auth/login", "", map[string]string{"loginName": ageRealm, "password": password, "requestId": "retained-age-current-login"}, http.StatusOK, &ageLogin)
		if ageLogin.Outcome != iamv1.LoginChallengeRequired || ageLogin.Challenge == nil || ageLogin.Challenge.Purpose != "LOGIN" ||
			ageLogin.Challenge.NextStep != "PASSWORD_CHANGE" || ageLogin.Credential.Present() || ageLogin.Session != (iamv1.Session{}) {
			t.Fatal("unknown password age did not enter the exact password-only restricted ceremony")
		}
		ageCredential := secret(ageLogin.ChallengeCredential)
		agePath := "/v1/auth/challenges/" + ageLogin.Challenge.ID
		call(http.MethodGet, "/v1/auth/me", ageSession.Credential, nil, http.StatusUnauthorized, nil)
		call(http.MethodGet, "/v1/auth/me", ageCredential, nil, http.StatusUnauthorized, nil)
		call(http.MethodPost, agePath+":verify", "", map[string]string{"requestId": "retained-age-not-totp", "challengeCredential": ageCredential, "code": "000000"}, http.StatusUnauthorized, nil)
		call(http.MethodPost, agePath+":enroll", "", map[string]string{"requestId": "retained-age-not-enrollment", "challengeCredential": ageCredential}, http.StatusUnauthorized, nil)
		var ageRequirements iamv1.PasswordRequirements
		call(http.MethodPost, agePath+"/password-requirements", "", map[string]string{"challengeCredential": ageCredential}, http.StatusOK, &ageRequirements)
		if ageRequirements.Source != "ACCOUNT" || ageRequirements.SettingsVersion != 5 || ageRequirements.Password != rules {
			t.Fatal("restricted password-only ceremony observed another authority's requirements")
		}
		var passwordOrigin bool
		if err := admin.QueryRow(ctx, `SELECT ch.factor_id IS NULL AND ch.source_challenge_id IS NULL AND ch.verified_step IS NULL
			AND ch.purpose='LOGIN' AND ch.next_step='PASSWORD_CHANGE' AND ch.state='PENDING' AND ch.security_settings_version=5
			AND ch.credential_generation=c.credential_version AND ch.mfa_revision=1 AND ch.session_id IS NULL
			AND a.attempt_id=ch.password_attempt_id AND a.attempt_sequence=ch.password_attempt_sequence AND a.state='SUCCEEDED' AND a.purpose='LOGIN'
			AND NOT EXISTS(SELECT 1 FROM iam.sessions s WHERE s.tenant_id=ch.tenant_id AND s.principal_id=ch.user_id
				AND (s.issued_at>=ch.created_at OR (s.status='ACTIVE' AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp()
					AND s.security_settings_version=ch.security_settings_version AND s.credential_version=ch.credential_generation)))
			AND NOT EXISTS(SELECT 1 FROM iam.totp_attempts a WHERE a.tenant_id=ch.tenant_id AND a.user_id=ch.user_id)
			FROM iam.authentication_challenges ch JOIN iam.user_credentials c ON (c.tenant_id,c.principal_id)=(ch.tenant_id,ch.user_id)
			JOIN iam.password_attempts a ON (a.tenant_id,a.principal_id)=(ch.tenant_id,ch.user_id)
			WHERE ch.tenant_id=$1 AND ch.id=$2`, tenant, ageLogin.Challenge.ID).Scan(&passwordOrigin); err != nil || !passwordOrigin {
			t.Fatal("password-only challenge invented a factor, Session or upstream OTP proof", err)
		}
		beforeChangeFault := securityState(ageUser.ID)
		defer clear(beforeChangeFault)
		call(http.MethodPost, agePath+":password", "", map[string]string{"requestId": "retained-age-fault-change", "challengeCredential": ageCredential, "newPassword": ageReplacement}, http.StatusServiceUnavailable, nil)
		assertUnchanged(ageUser.ID, beforeChangeFault)
		if err := admin.QueryRow(ctx, `SELECT (SELECT is_called AND last_value=3 FROM public.retained_expiry_fault_seen)
		 AND EXISTS(SELECT 1 FROM iam.authentication_challenges WHERE tenant_id=$1 AND id=$2 AND attempts=0 AND state='PENDING')`,
			tenant, ageLogin.Challenge.ID).Scan(&charged); err != nil || !charged {
			t.Fatal("restricted password change did not reach its final outbox failure", err)
		}
		var ageChanged iamv1.ChallengePasswordChangeResponse
		call(http.MethodPost, agePath+":password", "", map[string]string{"requestId": "retained-age-replacement", "challengeCredential": ageCredential, "newPassword": ageReplacement}, http.StatusOK, &ageChanged)
		if ageChanged.NextStep != "REAUTHENTICATE" {
			t.Fatal("password-only completion bypassed normal reauthentication")
		}
		call(http.MethodPost, agePath+":password", "", map[string]string{"requestId": "retained-age-replay", "challengeCredential": ageCredential, "newPassword": password}, http.StatusUnauthorized, nil)
		call(http.MethodPost, "/v1/auth/login", "", map[string]string{"loginName": ageRealm, "password": password, "requestId": "retained-age-old-password-rejected"}, http.StatusUnauthorized, nil)
		ageCurrent := loginIAM(t, endpoint, ageRealm, ageReplacement, "retained-age-fresh-login")
		*sensitive = append(*sensitive, ageCurrent.Credential)
		windowSession = loginIAM(t, endpoint, windowRealm, windowCurrent, "retained-window-current-login")
		*sensitive = append(*sensitive, windowSession.Credential)
		var requirements iamv1.PasswordRequirements
		call(http.MethodGet, "/v1/auth/password-requirements", windowSession.Credential, nil, http.StatusOK, &requirements)
		if requirements.Source != "ACCOUNT" || requirements.SettingsVersion != 5 || requirements.Password != rules {
			t.Fatal("history-zero fixture does not use current ordinary Account rules")
		}
		// Zero skips additional history, never the current verifier. Prove the
		// distinction against real HTTP writes, not just a rules projection.
		changePasswordIAM(t, endpoint, windowSession.Credential, windowCurrent, windowInitial, "retained-window-zero-reuse")
		windowState := func() []byte {
			t.Helper()
			var state []byte
			if err := admin.QueryRow(ctx, `SELECT jsonb_build_object('credential',to_jsonb(c),
			 'sessions',(SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM iam.sessions s WHERE tenant_id=$1 AND principal_id=$2),
			 'facts',(SELECT jsonb_agg(event_document ORDER BY event_id) FROM iam.audit_outbox WHERE tenant_id=$1 AND event_document#>>'{actor,id}'=$2))
			 FROM iam.user_credentials c WHERE tenant_id=$1 AND principal_id=$2`, tenant, windowUser.ID).Scan(&state); err != nil {
				t.Fatal("read zero-window password effects", err)
			}
			return state
		}
		retainedWindow := windowState()
		t.Cleanup(func() { clear(retainedWindow) })
		call(http.MethodPost, "/v1/auth/password", windowSession.Credential, map[string]string{
			"requestId": "retained-window-current-rejected", "currentPassword": windowInitial, "newPassword": windowInitial}, http.StatusUnprocessableEntity, nil)
		return func() {
			t.Helper()
			assertHistory()
			for _, check := range resetRaceChecks {
				check()
			}
			observedDenials := denialHistory()
			defer clear(observedDenials)
			if !bytes.Equal(denials, observedDenials) {
				t.Fatal("mode change, password replacement or restart rewrote terminal denial history")
			}
			for _, fact := range denialFacts {
				var resolved iamv1.AuditProducerAuthorization
				call(http.MethodPost, "/v1/audit-producer:resolve", iamServiceCredential, iamv1.ResolveAuditProducerRequest{Event: fact}, http.StatusOK, &resolved)
				_, expectedDigest, err := auditv1.CanonicalizeEvent(auditv1.SourceIAM, fact)
				if err != nil || resolved.ContentDigest != expectedDigest || resolved.TenantID != tenant || resolved.InstallationID != "" {
					t.Fatal("historical reset denial was reauthorized against today's password or policy")
				}
				forged := fact
				forged.RequestID = "forged-reset-denial"
				call(http.MethodPost, "/v1/audit-producer:resolve", iamServiceCredential, iamv1.ResolveAuditProducerRequest{Event: forged}, http.StatusForbidden, nil)
			}
			call(http.MethodPost, resetPath+":verify", "", map[string]string{"requestId": "retained-reset-restart-repeat", "challengeCredential": resetCredential, "code": resetCode}, http.StatusUnauthorized, nil)
			call(http.MethodGet, "/v1/auth/me", ageCurrent.Credential, nil, http.StatusOK, nil)
			call(http.MethodGet, "/v1/auth/me", ageSession.Credential, nil, http.StatusUnauthorized, nil)
			call(http.MethodPost, agePath+"/password-requirements", "", map[string]string{"challengeCredential": ageCredential}, http.StatusUnauthorized, nil)
			call(http.MethodGet, "/v1/auth/me", boundAgeSession.Credential, nil, http.StatusUnauthorized, nil)
			call(http.MethodPost, "/v1/auth/challenges/"+boundAgeStage.Challenge.ID+":password", "",
				map[string]string{"requestId": "retained-bound-age-replay", "challengeCredential": boundAgeStageCredential, "newPassword": password}, http.StatusUnauthorized, nil)
			var boundAgeCurrent iamv1.LoginResponse
			call(http.MethodPost, "/v1/auth/challenges/"+boundAgeReauthentication.Challenge.ID+":verify", "",
				map[string]string{"requestId": "retained-bound-age-new-proof", "challengeCredential": boundAgeReauthCredential, "code": nextCode(2)}, http.StatusOK, &boundAgeCurrent)
			if boundAgeCurrent.Outcome != iamv1.LoginAuthenticated || !boundAgeCurrent.Credential.Present() {
				t.Fatal("restart lost the independently proved post-replacement login")
			}
			secret(boundAgeCurrent.Credential)
			var ageRetained bool
			if err := admin.QueryRow(ctx, `SELECT ch.state='CONSUMED' AND ch.factor_id IS NULL AND ch.source_challenge_id IS NULL AND ch.verified_step IS NULL
				AND ch.completed_at=$3 AND c.password_changed_at=$3 AND c.credential_version=ch.credential_generation+1
				AND o.event_document->>'action'='iam.user.password-changed' AND o.event_document->>'requestId'='retained-age-replacement'
				AND s.authentication_method='PASSWORD' AND s.expires_at<=c.password_changed_at+interval '86400 seconds'
				FROM iam.authentication_challenges ch JOIN iam.user_credentials c ON (c.tenant_id,c.principal_id)=(ch.tenant_id,ch.user_id)
				JOIN iam.audit_outbox o ON (o.tenant_id,o.event_id)=(ch.tenant_id,ch.password_changed_event_id)
				JOIN iam.sessions s ON (s.tenant_id,s.principal_id)=(ch.tenant_id,ch.user_id) AND s.id=$4
				WHERE ch.tenant_id=$1 AND ch.id=$2`, tenant, ageLogin.Challenge.ID, ageChanged.ChangedAt, ageCurrent.Session.ID).Scan(&ageRetained); err != nil || !ageRetained {
				t.Fatal("replay/restart lost password-only completion or manufactured MFA assurance", err)
			}
			observedWindow := windowState()
			defer clear(observedWindow)
			if !bytes.Equal(retainedWindow, observedWindow) {
				t.Fatal("current password rejection or replay changed zero-window security state")
			}
			call(http.MethodGet, "/v1/auth/me", windowSession.Credential, nil, http.StatusOK, nil)
			var intact bool
			if err := admin.QueryRow(ctx, `SELECT (SELECT security_settings_version=5 AND NOT mfa_required_for_users
			 AND password_settings->>'minimumLength'='24' AND password_settings->>'historyCount'='0' FROM iam.accounts WHERE id=$1)
			 AND (SELECT count(*)=4 FROM iam.account_security_settings_changes WHERE tenant_id=$1)
			 AND EXISTS(SELECT 1 FROM iam.account_security_settings_changes c JOIN iam.step_ups p ON (p.tenant_id,p.id)=(c.tenant_id,c.step_up_id)
			 JOIN iam.audit_outbox o ON (o.tenant_id,o.event_id)=(c.tenant_id,c.event_id)
			 JOIN iam.security_notifications n ON (n.tenant_id,n.event_id)=(c.tenant_id,c.event_id)
			 WHERE c.tenant_id=$1 AND c.request_id=$2 AND c.expected_version=3 AND c.previous_required_for_users=c.required_for_users
			 AND c.previous_password_settings=iam.default_password_settings() AND p.state='CONSUMED' AND p.password_settings=c.password_settings
			 AND n.kind='SECURITY_SETTINGS_CHANGED' AND o.event_document->>'requestId'=$2)`, tenant, command).Scan(&intact); err != nil || !intact {
				t.Fatal("replay lost version continuity, password-only completion, proof, notice or audit", err)
			}
			call(http.MethodGet, "/v1/auth/me", caller, nil, http.StatusUnauthorized, nil)
			call(http.MethodGet, "/v1/auth/me", freshCaller, nil, http.StatusUnauthorized, nil)
			t.Log("actual predecessor settings versions 2/3 preserved; unfinished proof rejected; version 4 ADMIN_RESET consumes real password/TOTP with only immutable denial, version 5 CHANGE_PASSWORD and UNKNOWN-age replacement survive replay/restart without synthetic authority")
		}
	}
}

func prepareRetainedMFAProcesses(t *testing.T, ctx context.Context, admin *pgx.Conn, endpoint, root string, sensitive *[]string, recoveryHistory bool) (func(), func() func()) {
	t.Helper()
	const initial, password = "Retained-MFA-Initial-Password-73!", "Retained-MFA-Changed-Password-91!"
	*sensitive = append(*sensitive, initial, password)
	secret := func(value iamv1.Secret) string {
		material := value.CopyBytes()
		defer clear(material)
		*sensitive = append(*sensitive, string(material))
		return string(material)
	}
	call := func(method, path, bearer string, body any, want int, result any) {
		t.Helper()
		response := performJSON(t, method, endpoint+path, bearer, body)
		if response.Status != want {
			t.Fatalf("retained MFA %s %s status=%d want=%d", method, path, response.Status, want)
		}
		if result != nil && iamv1.DecodeRequest(bytes.NewReader(response.Body), result) != nil {
			t.Fatalf("invalid retained MFA response: %s %s (%T)", method, path, result)
		}
	}
	name := "retained.mfa"
	if !recoveryHistory {
		name += ".session"
	}
	user := createIAMUser(t, endpoint, root, name, "Retained MFA", initial, "retained-mfa-user-"+name)
	realm := user.LoginName + "@" + string(user.AccountID)
	first := loginIAM(t, endpoint, realm, initial, "retained-mfa-initial")
	changePasswordIAM(t, endpoint, first.Credential, initial, password, "retained-mfa-initial-password")
	*sensitive = append(*sensitive, first.Credential)
	var contact iamv1.NotificationContactVerification
	call(http.MethodPost, "/v1/auth/notification-contact/verifications", first.Credential,
		map[string]string{"email": "retained-mfa@matrix.test", "password": password, "requestId": "retained-mfa-contact"}, http.StatusOK, &contact)
	contactCode := readProcessContactCode(t, ctx, admin, contact)
	*sensitive = append(*sensitive, contactCode)
	call(http.MethodPost, "/v1/auth/notification-contact/verifications/"+contact.ID+":confirm", first.Credential,
		map[string]string{"requestId": "retained-mfa-contact-confirm", "code": contactCode}, http.StatusOK, nil)
	var enrollment iamv1.StartTOTPEnrollmentResponse
	call(http.MethodPost, "/v1/auth/totp/enrollments", first.Credential,
		map[string]any{"requestId": "retained-mfa-enroll", "password": password, "expectedFactorRevision": 1}, http.StatusOK, &enrollment)
	if enrollment.Outcome != "APPLIED" || enrollment.Provisioning == nil || enrollment.Enrollment.Purpose != "INITIAL" ||
		enrollment.Enrollment.State != "PENDING" || enrollment.Enrollment.RequestID != "retained-mfa-enroll" ||
		!enrollment.Provisioning.Seed.Present() || !enrollment.Provisioning.URI.Present() {
		t.Fatal("old executable did not issue original provisioning")
	}
	seed := secret(enrollment.Provisioning.Seed)
	secret(enrollment.Provisioning.URI)
	code, step := processTOTPCode(t, ctx, admin, seed, -1, true)
	*sensitive = append(*sensitive, code)
	var bound iamv1.ConfirmTOTPEnrollmentResponse
	call(http.MethodPost, "/v1/auth/totp/enrollments/"+enrollment.Enrollment.ID+":confirm", first.Credential,
		map[string]string{"requestId": "retained-mfa-bound", "code": code}, http.StatusOK, &bound)
	if len(bound.RecoveryCodes) != 10 || bound.NextStep != "REAUTHENTICATE" || bound.Enrollment.State != "CONFIRMED" ||
		bound.Enrollment.Purpose != "INITIAL" || bound.Enrollment.ID != enrollment.Enrollment.ID {
		t.Fatal("old executable did not issue its original recovery batch")
	}
	for _, value := range bound.RecoveryCodes {
		secret(value)
	}
	login := func(request string) iamv1.LoginResponse {
		t.Helper()
		var result iamv1.LoginResponse
		call(http.MethodPost, "/v1/auth/login", "", map[string]string{"loginName": realm, "password": password, "requestId": request}, http.StatusOK, &result)
		if iamv1.ValidateLoginResponse(result) != nil || result.Outcome != iamv1.LoginChallengeRequired || result.Challenge.NextStep != "TOTP" {
			t.Fatal("retained MFA password proof became a Session")
		}
		secret(result.ChallengeCredential)
		return result
	}
	snapshot := func() []byte {
		t.Helper()
		// Preserve all original fields. The newly added removal columns are
		// checked independently for absent, then exact, immutable provenance.
		var state []byte
		if err := admin.QueryRow(ctx, `SELECT jsonb_build_object(
			'state',(SELECT to_jsonb(m)-'removal_id' FROM iam.user_mfa_states m WHERE tenant_id=$1 AND user_id=$2),
			'factors',(SELECT jsonb_agg(to_jsonb(f)-'removal_id' ORDER BY id) FROM iam.totp_authenticators f WHERE tenant_id=$1 AND user_id=$2),
			'batches',(SELECT jsonb_agg(to_jsonb(b)-'revocation_removal_id' ORDER BY id) FROM iam.mfa_recovery_batches b WHERE tenant_id=$1 AND user_id=$2),
			'codes',(SELECT jsonb_agg(to_jsonb(c) ORDER BY c.id) FROM iam.mfa_recovery_codes c
				JOIN iam.mfa_recovery_batches b ON (b.tenant_id,b.id)=(c.tenant_id,c.batch_id) WHERE b.tenant_id=$1 AND b.user_id=$2),
			'challenges',(SELECT jsonb_agg(to_jsonb(c)-'password_reset_required_event_id' ORDER BY id) FROM iam.authentication_challenges c WHERE tenant_id=$1 AND user_id=$2),
			'recoveries',(SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM iam.authenticator_recoveries r WHERE tenant_id=$1 AND user_id=$2),
			'attempt',(SELECT to_jsonb(a) FROM iam.totp_attempts a WHERE tenant_id=$1 AND user_id=$2),
			'sessions',(SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM iam.sessions s WHERE tenant_id=$1 AND principal_id=$2),
			'proofs',(SELECT jsonb_agg(to_jsonb(p)-'password_settings' ORDER BY id) FROM iam.step_ups p WHERE tenant_id=$1 AND user_id=$2),
			'notices',(SELECT jsonb_agg(to_jsonb(n) ORDER BY id) FROM iam.security_notifications n WHERE tenant_id=$1 AND user_id=$2))`, user.AccountID, user.ID).Scan(&state); err != nil {
			t.Fatal("read original MFA authority invariants", err)
		}
		return state
	}
	oldBearer := first.Credential
	if !recoveryHistory {
		challenge := login("retained-mfa-old-login")
		code, consumedStep := processTOTPCode(t, ctx, admin, seed, step, false)
		*sensitive = append(*sensitive, code)
		var authenticated iamv1.LoginResponse
		call(http.MethodPost, "/v1/auth/challenges/"+challenge.Challenge.ID+":verify", "",
			map[string]string{"requestId": "retained-mfa-old-verify", "challengeCredential": secret(challenge.ChallengeCredential), "code": code}, http.StatusOK, &authenticated)
		if authenticated.Outcome != iamv1.LoginAuthenticated || !authenticated.Credential.Present() {
			t.Fatal("old executable did not issue an actual MFA Session")
		}
		oldBearer = secret(authenticated.Credential)
		pending := login("retained-mfa-old-pending")
		original := snapshot()
		t.Cleanup(func() { clear(original) })
		assertRetained := func() {
			t.Helper()
			after := snapshot()
			defer clear(after)
			if !bytes.Equal(original, after) {
				t.Fatal("migration changed original qualified MFA history")
			}
			var intact bool
			if err := admin.QueryRow(ctx, `SELECT
			 (SELECT status='ACTIVE' AND authentication_method='PASSWORD_TOTP' AND mfa_revision=2 AND security_settings_version=1
			  FROM iam.sessions WHERE tenant_id=$1 AND principal_id=$2 AND id=$3)
			 AND (SELECT state='ACTIVE' AND last_consumed_step=$4 FROM iam.totp_authenticators WHERE tenant_id=$1 AND user_id=$2 AND id=$5)
			 AND (SELECT state='PENDING' AND purpose='LOGIN' AND security_settings_version=1 FROM iam.authentication_challenges WHERE tenant_id=$1 AND id=$6)`,
				user.AccountID, user.ID, authenticated.Session.ID, consumedStep, enrollment.Enrollment.ID, pending.Challenge.ID).Scan(&intact); err != nil || !intact {
				t.Fatal("migration changed actual MFA consumption or original qualification", err)
			}
			call(http.MethodGet, "/v1/auth/me", oldBearer, nil, http.StatusOK, nil)
		}
		return assertRetained, func() func() {
			// This proof is made against a genuine predecessor factor, batch
			// and Session. No migration/DML creates removal authority.
			const request = "retained-mfa-removal"
			var proof iamv1.StepUp
			call(http.MethodPost, "/v1/auth/step-up", oldBearer,
				iamv1.StartStepUpRequest{RequestID: request, Operation: iamv1.StepUpRemoveTOTP, ExpectedFactorRevision: 2}, http.StatusOK, &proof)
			code, _ := processTOTPCode(t, ctx, admin, seed, consumedStep, false)
			*sensitive = append(*sensitive, code)
			call(http.MethodPost, "/v1/auth/step-up/"+proof.ID+":verify", oldBearer,
				map[string]string{"requestId": "retained-mfa-removal-proof", "password": password, "code": code}, http.StatusOK, &proof)
			removalIntent := iamv1.RemoveTOTPRequest{RequestID: request, StepUpID: proof.ID, ExpectedFactorRevision: 2}
			var removed iamv1.RemoveTOTPResponse
			call(http.MethodPost, "/v1/auth/totp:remove", oldBearer, removalIntent, http.StatusOK, &removed)
			if removed.Outcome != "APPLIED" || removed.NextStep != "REAUTHENTICATE" || removed.Removal.FactorID != enrollment.Enrollment.ID || removed.Removal.FactorRevision != 3 {
				t.Fatal("migrated factor did not support a new exact removal intent")
			}
			call(http.MethodGet, "/v1/auth/me", oldBearer, nil, http.StatusUnauthorized, nil)
			passwordLogin := loginIAM(t, endpoint, realm, password, "retained-mfa-password-login")
			*sensitive = append(*sensitive, passwordLogin.Credential)
			var passwordOnly bool
			if err := admin.QueryRow(ctx, `SELECT status='ACTIVE' AND authentication_method='PASSWORD' AND mfa_revision=3
			 FROM iam.sessions WHERE tenant_id=$1 AND principal_id=$2 AND id=$3`, user.AccountID, user.ID, passwordLogin.Session.ID).Scan(&passwordOnly); err != nil || !passwordOnly {
				t.Fatal("removal did not issue a genuine password-only login")
			}
			var prepared iamv1.StartTOTPEnrollmentResponse
			call(http.MethodPost, "/v1/auth/totp/enrollments", passwordLogin.Credential,
				map[string]any{"requestId": "retained-mfa-rebind", "password": password, "expectedFactorRevision": 3}, http.StatusOK, &prepared)
			if prepared.Outcome != "APPLIED" || prepared.Provisioning == nil || prepared.Enrollment.Purpose != "INITIAL" {
				t.Fatal("genuine retained removal could not start normal new-factor enrollment")
			}
			newSeed := secret(prepared.Provisioning.Seed)
			secret(prepared.Provisioning.URI)
			code, newStep := processTOTPCode(t, ctx, admin, newSeed, -1, true)
			*sensitive = append(*sensitive, code)
			var rebound iamv1.ConfirmTOTPEnrollmentResponse
			call(http.MethodPost, "/v1/auth/totp/enrollments/"+prepared.Enrollment.ID+":confirm", passwordLogin.Credential,
				map[string]string{"requestId": "retained-mfa-rebind-confirm", "code": code}, http.StatusOK, &rebound)
			if rebound.Enrollment.State != "CONFIRMED" || len(rebound.RecoveryCodes) != 10 || rebound.NextStep != "REAUTHENTICATE" {
				t.Fatal("retained factor removal/rebind did not complete atomically")
			}
			for _, material := range rebound.RecoveryCodes {
				secret(material)
			}
			fresh := login("retained-mfa-rebind-login")
			code, _ = processTOTPCode(t, ctx, admin, newSeed, newStep, false)
			*sensitive = append(*sensitive, code)
			var result iamv1.LoginResponse
			call(http.MethodPost, "/v1/auth/challenges/"+fresh.Challenge.ID+":verify", "",
				map[string]string{"requestId": "retained-mfa-rebind-login-proof", "challengeCredential": secret(fresh.ChallengeCredential), "code": code}, http.StatusOK, &result)
			if result.Outcome != iamv1.LoginAuthenticated || !result.Credential.Present() {
				t.Fatal("removal/rebind of a retained factor did not permit normal new-factor login")
			}
			bearer := secret(result.Credential)
			completed := snapshot()
			t.Cleanup(func() { clear(completed) })
			return func() {
				after := snapshot()
				defer clear(after)
				if !bytes.Equal(completed, after) {
					t.Fatal("schema/bootstrap/restart changed factor history or revived old qualification")
				}
				var retained bool
				if err := admin.QueryRow(ctx, `SELECT
				 (SELECT state='REVOKED' FROM iam.totp_authenticators WHERE tenant_id=$1 AND user_id=$2 AND id=$3)
				 AND (SELECT state='ACTIVE' AND bound_revision=4 AND removal_id=$7 FROM iam.totp_authenticators WHERE tenant_id=$1 AND user_id=$2 AND id=$4)
				 AND (SELECT count(*)=1 FROM iam.mfa_recovery_batches WHERE tenant_id=$1 AND user_id=$2 AND factor_id=$3 AND revoked_at IS NOT NULL AND revocation_removal_id=$7)
				 AND (SELECT count(*)=1 FROM iam.mfa_recovery_batches WHERE tenant_id=$1 AND user_id=$2 AND factor_id=$4 AND revoked_at IS NULL)
				 AND (SELECT state='CONSUMED' FROM iam.step_ups WHERE tenant_id=$1 AND user_id=$2 AND id=$5)
				 AND (SELECT state<>'PENDING' FROM iam.authentication_challenges WHERE tenant_id=$1 AND user_id=$2 AND id=$6)
				 AND (SELECT enrollment_state='BOUND' AND factor_id=$4 AND revision=4 AND removal_id IS NULL FROM iam.user_mfa_states WHERE tenant_id=$1 AND user_id=$2)
				 AND (SELECT count(*)=1 FROM iam.authenticator_removals WHERE tenant_id=$1 AND user_id=$2 AND id=$7 AND step_up_id=$5 AND factor_id=$3 AND revision=3)`,
					user.AccountID, user.ID, enrollment.Enrollment.ID, prepared.Enrollment.ID, proof.ID, pending.Challenge.ID, removed.Removal.ID).Scan(&retained); err != nil || !retained {
					t.Fatal("replay lost original removal proof/factor/batch/challenge lineage", err)
				}
				call(http.MethodGet, "/v1/auth/me", oldBearer, nil, http.StatusUnauthorized, nil)
				call(http.MethodGet, "/v1/auth/me", passwordLogin.Credential, nil, http.StatusUnauthorized, nil)
				call(http.MethodGet, "/v1/auth/me", bearer, nil, http.StatusOK, nil)
				var metadata iamv1.AuthenticatorRemoval
				call(http.MethodGet, "/v1/auth/totp/removals/by-request/"+request, bearer, nil, http.StatusOK, &metadata)
				if !reflect.DeepEqual(metadata, removed.Removal) {
					t.Fatal("restart changed the retained removal completion")
				}
				var replay iamv1.RemoveTOTPResponse
				call(http.MethodPost, "/v1/auth/totp:remove", bearer, removalIntent, http.StatusOK, &replay)
				if replay.Outcome != "EQUAL_REPLAY" || replay.NextStep != "" || !reflect.DeepEqual(replay.Removal, removed.Removal) || !bytes.Equal(completed, snapshot()) {
					t.Fatal("original removal replay changed the new factor or Session")
				}
				call(http.MethodPost, "/v1/auth/challenges/"+pending.Challenge.ID+":verify", "",
					map[string]string{"requestId": "retained-mfa-obsolete-login", "challengeCredential": secret(pending.ChallengeCredential), "code": "111111"}, http.StatusUnauthorized, nil)
				_, event := findIAMEvent(t, ctx, admin, auditv1.ActionIAMAuthenticatorRemoved, string(user.ID))
				call(http.MethodPost, "/v1/audit-producer:resolve", iamServiceCredential, iamv1.ResolveAuditProducerRequest{Event: event}, http.StatusOK, nil)
				t.Log("actual predecessor factor/batch/Session supported current removal/rebind; schema/bootstrap/restart and exact completed replay retained terminal old qualification, new factor and immutable removal")
			}
		}
	}
	pending := login("retained-mfa-old-pending")
	startRecovery := func() iamv1.StartAuthenticatorRecoveryResponse {
		t.Helper()
		var started iamv1.StartAuthenticatorRecoveryResponse
		call(http.MethodPost, "/v1/auth/challenges/"+pending.Challenge.ID+":recover", "",
			map[string]string{"requestId": "retained-mfa-recover", "challengeCredential": secret(pending.ChallengeCredential), "recoveryCode": secret(bound.RecoveryCodes[0])}, http.StatusOK, &started)
		if !started.Recovery.ExpiresAt.Equal(pending.Challenge.ExpiresAt) || started.Challenge.Purpose != "RECOVERY" {
			t.Fatal("recovery changed the original challenge lifetime or purpose")
		}
		secret(started.ChallengeCredential)
		secret(started.Provisioning.Seed)
		secret(started.Provisioning.URI)
		return started
	}
	originalRecovery := startRecovery()
	original := snapshot()
	t.Cleanup(func() { clear(original) })
	assertRetained := func() {
		t.Helper()
		after := snapshot()
		defer clear(after)
		if !bytes.Equal(original, after) {
			t.Fatal("migration/bootstrap/restart changed retained MFA authority or consumed-step evidence")
		}
		var shape bool
		if err := admin.QueryRow(ctx, `SELECT
				(SELECT state='STARTED' AND challenge_id=$4 FROM iam.authenticator_recoveries WHERE tenant_id=$1 AND user_id=$2 AND id=$3)
				AND (SELECT purpose='RECOVERY' AND next_step='ENROLLMENT' AND state='PENDING' AND recovery_id=$3
				 FROM iam.authentication_challenges WHERE tenant_id=$1 AND user_id=$2 AND id=$4)
				AND NOT EXISTS(SELECT 1 FROM iam.authentication_challenges WHERE tenant_id=$1 AND user_id=$2
				 AND purpose IS DISTINCT FROM CASE WHEN next_step='ENROLLMENT' THEN 'RECOVERY' ELSE 'LOGIN' END)
				AND NOT EXISTS(SELECT 1 FROM iam.step_ups WHERE tenant_id=$1 AND user_id=$2)
				AND NOT EXISTS(SELECT 1 FROM iam.recovery_code_regenerations WHERE tenant_id=$1 AND user_id=$2)`,
			user.AccountID, user.ID, originalRecovery.Recovery.ID, originalRecovery.Challenge.ID).Scan(&shape); err != nil || !shape {
			t.Fatal("actual predecessor recovery lost its exact purpose or gained new authority", err)
		}
		call(http.MethodGet, "/v1/auth/me", oldBearer, nil, http.StatusUnauthorized, nil)
	}
	recoverOriginal := func() func() {
		t.Helper()
		call(http.MethodGet, "/v1/auth/me", oldBearer, nil, http.StatusUnauthorized, nil)
		// The predecessor proved the original recovery's current settings qualification.
		// Continue that exact bounded intent, without consuming another code or
		// granting a new deadline merely because the executable changed.
		started := originalRecovery
		newSeed := secret(started.Provisioning.Seed)
		secret(started.Provisioning.URI)
		code, step := processTOTPCode(t, ctx, admin, newSeed, -1, true)
		*sensitive = append(*sensitive, code)
		var completed iamv1.ConfirmAuthenticatorRecoveryResponse
		call(http.MethodPost, "/v1/auth/challenges/"+started.Challenge.ID+":confirm-recovery", "",
			map[string]string{"requestId": "retained-mfa-confirm", "challengeCredential": secret(started.ChallengeCredential), "code": code}, http.StatusOK, &completed)
		for _, value := range completed.RecoveryCodes {
			secret(value)
		}
		fresh := login("retained-mfa-new-login")
		code, _ = processTOTPCode(t, ctx, admin, newSeed, step, false)
		*sensitive = append(*sensitive, code)
		var result iamv1.LoginResponse
		call(http.MethodPost, "/v1/auth/challenges/"+fresh.Challenge.ID+":verify", "",
			map[string]string{"requestId": "retained-mfa-new-verify", "challengeCredential": secret(fresh.ChallengeCredential), "code": code}, http.StatusOK, &result)
		if result.Outcome != iamv1.LoginAuthenticated || !result.Credential.Present() {
			t.Fatal("original saved code did not lead to a new-factor login")
		}
		newBearer := secret(result.Credential)
		completedState := snapshot()
		t.Cleanup(func() { clear(completedState) })
		t.Log("actual predecessor recovery retained its original qualification/deadline; original pending intent completed and normal new-factor login succeeded without consuming another saved code")
		return func() {
			t.Helper()
			after := snapshot()
			defer clear(after)
			if !bytes.Equal(completedState, after) {
				t.Fatal("schema/bootstrap replay changed completed recovery or resurrected old authentication")
			}
			var retained bool
			if err := admin.QueryRow(ctx, `SELECT
				(SELECT state='COMPLETED' AND completed_at=$4 FROM iam.authenticator_recoveries WHERE tenant_id=$1 AND user_id=$2 AND id=$3)
				AND (SELECT count(*) FROM iam.mfa_recovery_codes WHERE tenant_id=$1 AND recovery_id=$3 AND consumed_at IS NOT NULL)=1
				AND (SELECT count(*) FROM iam.mfa_recovery_batches WHERE tenant_id=$1 AND user_id=$2 AND revocation_recovery_id=$3 AND revoked_at IS NOT NULL)=1
				AND NOT EXISTS(SELECT 1 FROM iam.mfa_recovery_batches WHERE tenant_id=$1 AND user_id=$2 AND (regeneration_id IS NOT NULL OR revocation_regeneration_id IS NOT NULL OR revocation_replacement_factor_id IS NOT NULL))
				AND NOT EXISTS(SELECT 1 FROM iam.step_ups WHERE tenant_id=$1 AND user_id=$2)
				AND NOT EXISTS(SELECT 1 FROM iam.recovery_code_regenerations WHERE tenant_id=$1 AND user_id=$2)`,
				user.AccountID, user.ID, completed.Recovery.ID, completed.Recovery.CompletedAt).Scan(&retained); err != nil || !retained {
				t.Fatal("schema replay lost exact recovery completion or original code/batch termination", err)
			}
			call(http.MethodGet, "/v1/auth/me", oldBearer, nil, http.StatusUnauthorized, nil)
			call(http.MethodGet, "/v1/auth/me", newBearer, nil, http.StatusOK, nil)
			call(http.MethodPost, "/v1/auth/challenges/"+pending.Challenge.ID+":recover", "",
				map[string]string{"requestId": "retained-mfa-recover", "challengeCredential": secret(pending.ChallengeCredential), "recoveryCode": secret(bound.RecoveryCodes[0])}, http.StatusUnauthorized, nil)
			t.Log("current migration/verify/bootstrap/restart after recovery preserved exact completion, consumed code and terminated batch; old MFA bearer/source challenge remained rejected")
		}
	}
	return assertRetained, recoverOriginal
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
	t.Logf("source-built Profile r%d: old family frozen; new publication does not select; explicit selection grants; restart/revocation hold; not a production PaaS inspect endpoint or release-upgrade gate", profile.Revision)
}

// This gate builds the accepted old executable from fixed Git objects in its
// own temporary directory. Old source is never a product/runtime dependency.
func extractFixedAuthoritySource(t *testing.T, ctx context.Context, root, temporary, fixedCommit string) string {
	t.Helper()
	command := exec.CommandContext(ctx, "git", "archive", "--format=zip", fixedCommit, "go.mod", "go.sum", "api", "app/service/iam", "app/service/paas", "app/service/internal")
	command.Dir = root
	archive, err := command.Output()
	if err != nil || len(archive) > 32<<20 {
		t.Fatal("cannot read bounded fixed authority source archive")
	}
	reader, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(temporary, "authority-baseline")
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
	testIndependentAuthorityProcesses(t, authorityProcessFull)
}

type authorityProcessMode uint8

const (
	authorityProcessFull authorityProcessMode = iota
	authorityProcessBrowser
	authorityProcessCapacity
	authorityProcessPasswordCapacity
)

// An opt-in bounded observation, not a production SLO or an open-loop load
// generator. The ordinary security gate retains its entire original flow.
func TestIAMCapacityProcesses(t *testing.T) {
	if os.Getenv("MATRIX_IAM_CAPACITY_POSTGRES_TEST_DSN") == "" {
		t.Skip("set MATRIX_IAM_CAPACITY_POSTGRES_TEST_DSN to a separate disposable PG18 database")
	}
	assertIAMCapacityLimits(t)
	testIndependentAuthorityProcesses(t, authorityProcessCapacity)
}

func TestIAMPasswordHistoryCapacityProcesses(t *testing.T) {
	if os.Getenv("MATRIX_IAM_PASSWORD_HISTORY_CAPACITY_POSTGRES_TEST_DSN") == "" {
		t.Skip("set MATRIX_IAM_PASSWORD_HISTORY_CAPACITY_POSTGRES_TEST_DSN to a separate disposable PG18 database")
	}
	assertIAMCapacityLimits(t)
	testIndependentAuthorityProcesses(t, authorityProcessPasswordCapacity)
}

// This opt-in fixture is for observed browser acceptance, not an unattended
// substitute for TestIndependentIAMAuditAndPaaSProcesses or signed APISIX gates.
func TestIAMConsoleBrowser(t *testing.T) {
	if os.Getenv("MATRIX_IAM_CONSOLE_BROWSER") != "1" {
		t.Skip("set MATRIX_IAM_CONSOLE_BROWSER=1 for the bounded local browser fixture")
	}
	testIndependentAuthorityProcesses(t, authorityProcessBrowser)
}

func testIndependentAuthorityProcesses(t *testing.T, mode authorityProcessMode) {
	variable, prefix := authorityProcessDSN, "matrix_authority_process_"
	if mode == authorityProcessCapacity {
		variable, prefix = "MATRIX_IAM_CAPACITY_POSTGRES_TEST_DSN", "matrix_authority_process_capacity_"
	} else if mode == authorityProcessPasswordCapacity {
		variable, prefix = "MATRIX_IAM_PASSWORD_HISTORY_CAPACITY_POSTGRES_TEST_DSN", "matrix_authority_process_password_capacity_"
	}
	dsn := os.Getenv(variable)
	if dsn == "" {
		t.Skipf("set %s to a clean disposable PostgreSQL 18 database", variable)
	}
	duration := 6 * time.Minute
	if mode == authorityProcessBrowser {
		duration = 30 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()
	root := repositoryRoot(t)
	adminConfig, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse authority process DSN: %v", err)
	}
	if !strings.HasPrefix(adminConfig.Database, prefix) {
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
	iamWrappingKeyPath := writeProcessAccessKeyWrapping(t, temporary, bootstrap)
	iamTOTPKeyPath := writeProcessTOTPKeyring(t, temporary, bootstrap)
	iamEmailKeyPath := writeProcessEmailVerificationKeyring(t, temporary, bootstrap)

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
		"MATRIX_IAM_ACCESS_KEY_WRAPPING_KEYRING_FILE=" + iamWrappingKeyPath,
		"MATRIX_IAM_TOTP_KEYRING_FILE=" + iamTOTPKeyPath,
		"MATRIX_IAM_EMAIL_VERIFICATION_KEYRING_FILE=" + iamEmailKeyPath,
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

	for _, variable := range []string{"MATRIX_IAM_ACCESS_KEY_WRAPPING_KEYRING_FILE", "MATRIX_IAM_TOTP_KEYRING_FILE"} {
		for _, candidate := range []string{"", filepath.Join(temporary, "missing-keyring"),
			writeProtectedFile(t, temporary, "invalid-keyring", []byte("{}"))} {
			environment := []string{}
			for _, entry := range iamEnvironment {
				if !strings.HasPrefix(entry, variable+"=") {
					environment = append(environment, entry)
				}
			}
			if candidate != "" {
				environment = append(environment, variable+"="+candidate)
			}
			invalid := start(binaries.iam, environment)
			if err := invalid.wait(10 * time.Second); err == nil || errors.Is(err, errProcessWaitTimeout) {
				t.Fatal("IAM network process accepted missing/invalid wrapping file", variable)
			}
			var effects int
			if err := admin.QueryRow(ctx, `SELECT (SELECT count(*) FROM iam.bootstrap_receipts)+(SELECT count(*) FROM iam.access_key_wrapping_registry)+(SELECT count(*) FROM iam.totp_wrapping_registry)+(SELECT count(*) FROM iam.audit_outbox)`).Scan(&effects); err != nil || effects != 0 {
				t.Fatal("invalid wrapping startup changed installation state", variable, err)
			}
		}
	}
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
	sourceProfile := installationrelease.AuthoritySchemas{IAM: 51, Audit: 28, PaaS: 2}
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
	if mode == authorityProcessBrowser {
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
	replicaEnvironment := []string{
		"MATRIX_IAM_DATABASE_DSN_FILE=" + replicaDSNPath,
		"MATRIX_IAM_BOOTSTRAP_FILE=" + bootstrapPath,
		"MATRIX_IAM_LISTEN_ADDRESS=" + replicaAddress,
		"MATRIX_IAM_CURSOR_KEY_FILE=" + iamCursorKeyPath,
		"MATRIX_IAM_ACCESS_KEY_WRAPPING_KEYRING_FILE=" + iamWrappingKeyPath,
		"MATRIX_IAM_TOTP_KEYRING_FILE=" + iamTOTPKeyPath,
		"MATRIX_IAM_EMAIL_VERIFICATION_KEYRING_FILE=" + iamEmailKeyPath,
	}
	replicaProcess := start(binaries.iam, replicaEnvironment)
	waitHTTPStatus(t, ctx, replicaProcess, replicaEndpoint+"/ready", http.StatusOK)
	assertRuntimeProcessLogins(t, ctx, admin, replicaLogin)
	if mode == authorityProcessCapacity {
		sensitive = append(sensitive, measureIAMCapacity(t, ctx, admin, iamEndpoint, replicaEndpoint, auditEndpoint, paasEndpoint, adminLogin.Credential)...)
		return
	}
	if mode == authorityProcessPasswordCapacity {
		sensitive = append(sensitive, measureIAMPasswordHistoryCapacity(t, ctx, admin, iamEndpoint, replicaEndpoint, auditEndpoint, adminLogin.Credential)...)
		return
	}
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
	sensitive = append(sensitive, proveSecuritySettingsMutationProcesses(t, ctx, admin, iamEndpoint, replicaEndpoint, auditEndpoint, paasEndpoint, adminLogin.Credential,
		func() {
			iamProcess.stop()
			replicaProcess.stop()
			iamProcess = start(binaries.iam, iamEnvironment)
			replicaProcess = start(binaries.iam, replicaEnvironment)
			waitHTTPStatus(t, ctx, iamProcess, iamEndpoint+"/ready", http.StatusOK)
			waitHTTPStatus(t, ctx, replicaProcess, replicaEndpoint+"/ready", http.StatusOK)
			assertRuntimeProcessLogins(t, ctx, admin, iamAPILogin, replicaLogin)
		}, func(work func()) {
			dispatcher.stop()
			work()
			dispatcher = start(binaries.dispatcher, iamDispatcherEnvironment(iamCredentialPath, "iam-audit-worker-settings"))
			waitHTTPStatus(t, ctx, dispatcher, "http://"+iamDispatcherAddress+"/ready", http.StatusOK)
		})...)
	// A syntactically valid file from the same installation must still match
	// the permanent registry. Use a separate free address: a bind conflict with
	// the healthy replicas must never masquerade as the expected startup denial.
	keyringBytes, err := os.ReadFile(iamWrappingKeyPath)
	if err != nil {
		t.Fatal("read own process keyring fixture")
	}
	keyring, err := iamv1.DecodeAccessKeyWrappingKeyring(bytes.NewReader(keyringBytes))
	clear(keyringBytes)
	if err != nil {
		t.Fatal("decode own process keyring fixture")
	}
	const keyCustodyState = `SELECT jsonb_build_object(
	 'registry',(SELECT jsonb_agg(to_jsonb(r) ORDER BY wrapping_key_id) FROM iam.access_key_wrapping_registry r),
	 'keys',(SELECT jsonb_agg(to_jsonb(k) ORDER BY id) FROM iam.access_keys k),
	 'intents',(SELECT jsonb_agg(to_jsonb(i) ORDER BY actor_id,request_id) FROM iam.access_key_intents i))::text`
	var originalCustody string
	var registryCount int
	if err := admin.QueryRow(ctx, "SELECT count(*) FROM iam.access_key_wrapping_registry").Scan(&registryCount); err != nil || registryCount != 1 {
		t.Fatal("process gate has no committed wrapping history")
	}
	if err := admin.QueryRow(ctx, keyCustodyState).Scan(&originalCustody); err != nil {
		t.Fatal("read original process custody")
	}
	for _, variant := range []string{"material", "wrapping-id"} {
		changed := keyring
		changed.Keys = append([]iamv1.AccessKeyWrappingKey(nil), keyring.Keys...)
		if variant == "material" {
			material := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x58}, 32))
			sensitive = append(sensitive, material)
			changed.Keys[0].KeyMaterial = processSecret(t, material)
		} else {
			changed.ActiveWrappingKeyID, changed.Keys[0].WrappingKeyID = "process-replacement-wrapping", "process-replacement-wrapping"
		}
		encoded, err := iamv1.EncodeAccessKeyWrappingKeyring(changed)
		if err != nil {
			t.Fatal("encode mismatched process custody")
		}
		path := writeProtectedFile(t, temporary, "mismatched-wrapping-"+variant, encoded)
		clear(encoded)
		environment := []string{}
		for _, entry := range iamEnvironment {
			if !strings.HasPrefix(entry, "MATRIX_IAM_ACCESS_KEY_WRAPPING_KEYRING_FILE=") && !strings.HasPrefix(entry, "MATRIX_IAM_LISTEN_ADDRESS=") {
				environment = append(environment, entry)
			}
		}
		environment = append(environment, "MATRIX_IAM_ACCESS_KEY_WRAPPING_KEYRING_FILE="+path, "MATRIX_IAM_LISTEN_ADDRESS="+freeAddress(t))
		invalid := start(binaries.iam, environment)
		if err := invalid.wait(10 * time.Second); err == nil || errors.Is(err, errProcessWaitTimeout) {
			t.Fatal("IAM process accepted material inconsistent with committed key history")
		}
		var currentCustody string
		if err := admin.QueryRow(ctx, keyCustodyState).Scan(&currentCustody); err != nil || currentCustody != originalCustody {
			t.Fatal("invalid process startup changed permanent key custody")
		}
	}
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
	if response := performJSON(t, http.MethodGet, iamEndpoint+"/v1/auth/me", developerLogin.Credential, nil); response.Status != http.StatusUnauthorized {
		t.Fatal("platform protection grant preserved the developer's original Session")
	}
	developerLogin = loginIAM(t, iamEndpoint, "paas.developer@organization-process", changedDeveloperPassword, "request-developer-after-platform-grant")
	sensitive = append(sensitive, developerLogin.Credential)
	platformDecisions = append(platformDecisions,
		assertPlatformAuthorization(t, iamEndpoint, developerLogin.Credential, string(developer.ID), "request-platform-developer-granted", true),
	)
	assertPlatformAuditAccess(t, auditEndpoint, developerLogin.Credential, http.StatusOK)
	queryAudit(t, auditEndpoint, developerLogin.Credential, auditv1.QueryRecordsRequest{PageSize: 10}, http.StatusForbidden)
	revokeIAMPolicyAttachment(t, iamEndpoint, adminLogin.Credential, platformBinding.ID, 1, "request-revoke-platform-operator")
	if response := performJSON(t, http.MethodGet, replicaEndpoint+"/v1/auth/me", developerLogin.Credential, nil); response.Status != http.StatusUnauthorized {
		t.Fatal("platform protection revocation preserved the developer's privileged Session")
	}
	developerLogin = loginIAM(t, replicaEndpoint, "paas.developer@organization-process", changedDeveloperPassword, "request-developer-after-platform-revocation")
	sensitive = append(sensitive, developerLogin.Credential)
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
	policyHistory := queryAudit(t, auditEndpoint, adminLogin.Credential, auditv1.QueryRecordsRequest{PageSize: 100, Action: auditv1.ActionIAMPolicyCreated}, http.StatusOK)
	publications := 0
	for _, record := range policyHistory.Records {
		if record.Event.TenantID != auditv1.TenantID(customPolicy.Policy.AccountID) {
			t.Fatal("policy history crossed tenant scope")
		}
		if record.Event.Target.ID == string(customPolicy.Policy.ID) {
			publications++
			if record.Source != auditv1.SourceIAM || record.Event.RequestID != customRequest.RequestID || record.Event.Result != auditv1.ResultSucceeded {
				t.Fatal("custom policy publication lost its immutable provenance")
			}
		}
	}
	if policyHistory.TenantID != auditv1.TenantID(customPolicy.Policy.AccountID) || policyHistory.NextCursor != "" || publications != 1 {
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
	const postLocalRecoveryPassword = "Local-Process-Post-Recovery-Password-96!"
	adminLogin, verifyHistoricalRecovery, recoverySecrets = proveLocalCredentialRecoveryProcesses(t, ctx, admin, root, temporary, binaries.localRecovery, iamEndpoint, auditEndpoint, paasEndpoint, bootstrap, adminLogin, postLocalRecoveryPassword,
		func(admit func()) {
			auditProcess.stop()
			admit()
			auditProcess = start(binaries.audit, auditEnvironment)
			waitHTTPStatus(t, ctx, auditProcess, auditEndpoint+"/ready", http.StatusOK)
		})
	sensitive = append(sensitive, recoverySecrets...)
	revokeIAMPolicyAttachment(t, iamEndpoint, adminLogin.Credential, "bootstrap-platform-operator-binding", 1, "request-revoke-bootstrap-platform")
	verifyHistoricalRecovery()
	if response := performJSON(t, http.MethodGet, replicaEndpoint+"/v1/auth/me", adminLogin.Credential, nil); response.Status != http.StatusUnauthorized {
		t.Fatal("platform protection revocation left the original Session usable")
	}
	adminLogin = loginIAM(t, iamEndpoint, "admin", postLocalRecoveryPassword, "request-admin-after-platform-revocation")
	sensitive = append(sensitive, adminLogin.Credential)
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
	// A real new IAM process advances the nonsecret registration. The two
	// existing processes keep their original file snapshots: direct requests,
	// not only readiness, must fail until they consume matching material.
	// The earlier outage scenario deliberately stopped this replica.
	replicaProcess = start(binaries.iam, replicaEnvironment)
	waitHTTPStatus(t, ctx, replicaProcess, replicaEndpoint+"/ready", http.StatusOK)
	sensitive = append(sensitive, proveTOTPProcesses(t, ctx, admin, iamEndpoint, replicaEndpoint, auditEndpoint, paasEndpoint, adminLogin.Credential,
		func() {
			iamProcess.stop()
			replicaProcess.stop()
			iamProcess = start(binaries.iam, iamEnvironment)
			replicaProcess = start(binaries.iam, replicaEnvironment)
			waitHTTPStatus(t, ctx, iamProcess, iamEndpoint+"/ready", http.StatusOK)
			waitHTTPStatus(t, ctx, replicaProcess, replicaEndpoint+"/ready", http.StatusOK)
			assertRuntimeProcessLogins(t, ctx, admin, iamAPILogin, replicaLogin)
		}, func(work func()) {
			dispatcher.stop()
			work()
			dispatcher = start(binaries.dispatcher, iamDispatcherEnvironment(iamCredentialPath, "iam-audit-worker-mfa"))
			waitHTTPStatus(t, ctx, dispatcher, "http://"+iamDispatcherAddress+"/ready", http.StatusOK)
		})...)
	for _, endpoint := range []string{iamEndpoint, replicaEndpoint} {
		if response := performJSON(t, http.MethodGet, endpoint+"/v1/auth/sessions", adminLogin.Credential, nil); response.Status != http.StatusOK {
			t.Fatalf("TOTP drift fixture lacks a working Session: %d", response.Status)
		}
	}
	totpBytes, err := os.ReadFile(iamTOTPKeyPath)
	if err != nil {
		t.Fatal("read own TOTP process fixture")
	}
	totpKeyring, err := iamv1.DecodeTOTPKeyring(bytes.NewReader(totpBytes))
	clear(totpBytes)
	if err != nil {
		t.Fatal("decode own TOTP process fixture")
	}
	totpKeyring.KeysetRevision++
	totpBytes, err = iamv1.EncodeTOTPKeyring(totpKeyring)
	if err != nil {
		t.Fatal("encode next TOTP process fixture")
	}
	nextTOTPPath := writeProtectedFile(t, temporary, "iam-totp-keyring-next.json", totpBytes)
	clear(totpBytes)
	nextAddress := freeAddress(t)
	nextEnvironment := append([]string(nil), iamEnvironment...)
	for i, entry := range nextEnvironment {
		if strings.HasPrefix(entry, "MATRIX_IAM_TOTP_KEYRING_FILE=") {
			nextEnvironment[i] = "MATRIX_IAM_TOTP_KEYRING_FILE=" + nextTOTPPath
		}
		if strings.HasPrefix(entry, "MATRIX_IAM_LISTEN_ADDRESS=") {
			nextEnvironment[i] = "MATRIX_IAM_LISTEN_ADDRESS=" + nextAddress
		}
	}
	nextProcess := start(binaries.iam, nextEnvironment)
	nextEndpoint := "http://" + nextAddress
	waitHTTPStatus(t, ctx, nextProcess, nextEndpoint+"/ready", http.StatusOK)
	for _, endpoint := range []string{iamEndpoint, replicaEndpoint} {
		response := performJSON(t, http.MethodPost, endpoint+"/v1/auth/login", "", struct {
			LoginName string `json:"loginName"`
			Password  string `json:"password"`
			RequestID string `json:"requestId"`
		}{
			LoginName: "admin", Password: postLocalRecoveryPassword, RequestID: "process-stale-totp-login"})
		if response.Status != http.StatusServiceUnavailable {
			t.Fatalf("stale TOTP process accepted direct login: %d", response.Status)
		}
		response = performJSON(t, http.MethodGet, endpoint+"/v1/auth/sessions", adminLogin.Credential, nil)
		if response.Status != http.StatusServiceUnavailable {
			t.Fatalf("stale TOTP process accepted existing Session: %d", response.Status)
		}
	}
	if response := performJSON(t, http.MethodGet, nextEndpoint+"/v1/auth/sessions", adminLogin.Credential, nil); response.Status != http.StatusOK {
		t.Fatalf("matching TOTP process lost existing Session: %d", response.Status)
	}
	nextProcess.stop()
	iamProcess.stop()
	replicaProcess.stop()
	for _, environment := range [][]string{iamEnvironment, replicaEnvironment} {
		for i, entry := range environment {
			if strings.HasPrefix(entry, "MATRIX_IAM_TOTP_KEYRING_FILE=") {
				environment[i] = "MATRIX_IAM_TOTP_KEYRING_FILE=" + nextTOTPPath
			}
		}
	}
	iamProcess = start(binaries.iam, iamEnvironment)
	replicaProcess = start(binaries.iam, replicaEnvironment)
	waitHTTPStatus(t, ctx, iamProcess, iamEndpoint+"/ready", http.StatusOK)
	waitHTTPStatus(t, ctx, replicaProcess, replicaEndpoint+"/ready", http.StatusOK)
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

type iamCapacityCall struct {
	lane     string
	request  *http.Request
	status   int
	verify   func([]byte) (string, bool) // optional newly issued test secret, validity
	interval time.Duration               // independent lane's planned start interval; zero is unpaced
	confirm  bool                        // next mutation requires this response to be verified
}

type iamCapacitySchedule uint8

const (
	iamCapacityPaired iamCapacitySchedule = iota
	iamCapacityIndependent
)

type iamCapacityResult struct {
	index     int
	status    int
	body      []byte
	started   time.Time
	completed time.Time
	scheduled time.Time // absent for unpaced closed-loop requests
	failed    bool
	confirm   chan bool // optional bounded acknowledgment; never a retry or new authority
}

func makeIAMCapacityCall(t *testing.T, ctx context.Context, lane, method, server, path, bearer string,
	body any, status int, verify func([]byte) (string, bool)) iamCapacityCall {
	t.Helper()
	var encoded []byte
	if body != nil {
		var err error
		encoded, err = json.Marshal(body)
		if err != nil {
			t.Fatal("capacity request encoding failed")
		}
	}
	request, err := http.NewRequestWithContext(ctx, method, server+path, bytes.NewReader(encoded))
	if err != nil {
		t.Fatal("capacity request construction failed")
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	return iamCapacityCall{lane: lane, request: request, status: status, verify: verify}
}

func measureIAMPasswordHistoryCapacity(t *testing.T, ctx context.Context, database *pgx.Conn, endpoint, replica, auditEndpoint, platform string) []string {
	t.Helper()
	const initial, ownerPassword, peerPassword = "Capacity-History-Initial-63!", "Capacity-History-Owner-74!", "Capacity-History-Peer-85!"
	passwordAt := func(index int) string { return fmt.Sprintf("Capacity-History-Actual-%03d-96!", index) }
	type accountFixture struct {
		id       iamv1.AccountID
		rootName string
		root     loginResult
		user     iamv1.User
		login    loginResult
	}
	secrets := []string{initial, ownerPassword, peerPassword}
	accounts := make([]accountFixture, 2)
	for index := range accounts {
		account := &accounts[index]
		account.id = iamv1.AccountID(fmt.Sprintf("account-history-capacity-%d", index))
		account.rootName = fmt.Sprintf("history.capacity.root.%d", index)
		response := performJSON(t, http.MethodPost, endpoint+"/v1/accounts", platform, map[string]any{
			"id": account.id, "displayName": "Password history capacity", "rootLoginName": account.rootName,
			"rootDisplayName": "Capacity owner", "initialPassword": initial, "requestId": "history-capacity-open-" + string(account.id)})
		var created iamv1.Account
		if response.Status != http.StatusCreated || iamv1.DecodeRequest(bytes.NewReader(response.Body), &created) != nil || created.ID != account.id {
			t.Fatal("history capacity requires real independent accounts")
		}
		account.root = loginIAM(t, endpoint, account.rootName, initial, "history-capacity-owner-login")
		changePasswordIAM(t, endpoint, account.root.Credential, initial, ownerPassword, "history-capacity-owner-password")
		account.user = createIAMUser(t, endpoint, account.root.Credential, "capacity.member", "Measured ordinary user", initial, "history-capacity-member")
		account.login = loginIAM(t, endpoint, "capacity.member@"+string(account.id), initial, "history-capacity-member-login")
		password := peerPassword
		if index == 0 {
			password = passwordAt(0)
		}
		changePasswordIAM(t, endpoint, account.login.Credential, initial, password, "history-capacity-member-password")
		secrets = append(secrets, account.root.Credential, account.login.Credential, password)
	}
	actor, peer := &accounts[0], &accounts[1]
	for index := 1; index < 24; index++ {
		password := passwordAt(index)
		secrets = append(secrets, password)
		changePasswordIAM(t, endpoint, actor.login.Credential, passwordAt(index-1), password, fmt.Sprintf("history-capacity-build-%d", index))
	}
	secrets = append(secrets, configureIAMCapacityHistory(t, ctx, database, endpoint, replica, actor.id, actor.root.Credential)...)
	// Changing settings ends old qualification. Obtain fresh sessions through
	// normal login, never rewrite their stored settings version for the load.
	actor.root = loginIAM(t, endpoint, actor.rootName, ownerPassword, "history-capacity-owner-current")
	actor.login = loginIAM(t, endpoint, "capacity.member@"+string(actor.id), passwordAt(23), "history-capacity-current")
	secrets = append(secrets, actor.root.Credential, actor.login.Credential)
	for _, server := range []string{endpoint, replica} {
		response := performJSON(t, http.MethodGet, server+"/v1/auth/password-requirements", actor.login.Credential, nil)
		var requirements iamv1.PasswordRequirements
		if response.Status != http.StatusOK || iamv1.DecodeRequest(bytes.NewReader(response.Body), &requirements) != nil ||
			iamv1.ValidatePasswordRequirements(requirements) != nil || requirements.Source != "ACCOUNT" || requirements.SettingsVersion != 2 || requirements.Password.HistoryCount != 24 {
			t.Fatal("history capacity does not exercise ordinary-user full history rules")
		}
	}
	var generation int64
	var fullHistory bool
	if err := database.QueryRow(ctx, `SELECT credential_version,jsonb_array_length(password_history)=24
		AND iam.valid_password_history(password_history,password_history_digest,credential_version,password_changed_at)
		FROM iam.user_credentials WHERE tenant_id=$1 AND principal_id=$2`, actor.id, actor.user.ID).Scan(&generation, &fullHistory); err != nil || !fullHistory {
		t.Fatal("history capacity setup did not create 24 actual verifiers")
	}
	// A single full-history control distinguishes the serial verifier cost from
	// cross-account interference. Its original five-second deadline is unchanged.
	secrets = append(secrets, passwordAt(24))
	control := makeIAMCapacityCall(t, ctx, "full-history-control", http.MethodPost, endpoint, "/v1/auth/password", actor.login.Credential,
		map[string]any{"currentPassword": passwordAt(23), "newPassword": passwordAt(24), "requestId": "history-capacity-single", "revokeOtherSessions": true},
		http.StatusOK, func(body []byte) (string, bool) {
			var response iamv1.ChangePasswordResponse
			return "", iamv1.DecodeRequest(bytes.NewReader(body), &response) == nil && iamv1.ValidateChangePasswordResponse(response) == nil
		})
	controlTransport := http.DefaultTransport.(*http.Transport).Clone()
	controlTransport.Proxy = nil
	controlTransport.MaxConnsPerHost = 1
	defer controlTransport.CloseIdleConnections()
	controlClient := &http.Client{Transport: controlTransport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	controlResults, err := dispatchIAMCapacityCalls(ctx, controlClient, time.Now(), 1, iamCapacityIndependent, []iamCapacityCall{control})
	if err != nil {
		t.Fatal("history control schedule failed")
	}
	controlResult, received := <-controlResults
	_, valid := control.verify(controlResult.body)
	clear(controlResult.body)
	t.Logf("IAM_HISTORY_CONTROL elapsedMS=%.3f status=%d transportFailure=%t valid=%t", float64(controlResult.completed.Sub(controlResult.started))/float64(time.Millisecond), controlResult.status, controlResult.failed, valid)
	if !received || controlResult.failed || controlResult.status != http.StatusOK || !valid {
		t.Fatal("single full-history password change exceeded or failed its unchanged HTTP budget; dependent workload not issued")
	}
	generation++
	old := loginIAM(t, replica, "capacity.member@"+string(actor.id), passwordAt(24), "history-capacity-other-session")
	secrets = append(secrets, old.Credential)
	var issued []loginResult
	seenSessions, seenCredentials := map[iamv1.SessionID]bool{}, map[string]bool{}
	loginCall := func(stage string, index int) iamCapacityCall {
		return makeIAMCapacityCall(t, ctx, "peer-login", http.MethodPost, endpoint, "/v1/auth/login", "", map[string]string{
			"loginName": "capacity.member@" + string(peer.id), "password": peerPassword, "requestId": fmt.Sprintf("history-capacity-%s-peer-%d", stage, index)},
			http.StatusOK, func(body []byte) (string, bool) {
				var response iamv1.LoginResponse
				if iamv1.DecodeRequest(bytes.NewReader(body), &response) != nil || iamv1.ValidateLoginResponse(response) != nil || response.Outcome != iamv1.LoginAuthenticated ||
					response.MustChangePassword || response.Session.AccountID != peer.id || response.Session.PrincipalID != peer.user.ID || seenSessions[response.Session.ID] {
					return "", false
				}
				material := response.Credential.CopyBytes()
				defer clear(material)
				credential := string(material)
				if seenCredentials[credential] {
					return credential, false
				}
				seenSessions[response.Session.ID], seenCredentials[credential] = true, true
				issued = append(issued, loginResult{Session: response.Session, Credential: credential})
				return credential, true
			})
	}
	for _, pressured := range []bool{false, true} {
		stage, concurrency := "history-login-control", 1
		if pressured {
			stage, concurrency = "history-change-interference", 2
		}
		var calls []iamCapacityCall
		for index := range 100 {
			if pressured {
				current, next := passwordAt(24+index), passwordAt(25+index)
				secrets = append(secrets, next)
				change := makeIAMCapacityCall(t, ctx, "full-history-change", http.MethodPost, endpoint, "/v1/auth/password", actor.login.Credential,
					map[string]any{"currentPassword": current, "newPassword": next, "requestId": fmt.Sprintf("history-capacity-change-%d", index), "revokeOtherSessions": true},
					http.StatusOK, func(body []byte) (string, bool) {
						var response iamv1.ChangePasswordResponse
						return "", iamv1.DecodeRequest(bytes.NewReader(body), &response) == nil && iamv1.ValidateChangePasswordResponse(response) == nil && !response.BootstrapFileRetirable
					})
				// A lost/rejected result does not authorize the next precomputed
				// password. Stop only this dependent lane and report it incomplete.
				change.confirm = true
				calls = append(calls, change)
			}
			calls = append(calls, loginCall(stage, index))
		}
		waitAllIAMOutboxDelivered(t, ctx, database)
		secrets = append(secrets, runIAMCapacityStage(t, ctx, database, stage, concurrency, iamCapacityIndependent, calls)...)
	}
	if len(issued) != 200 {
		t.Fatal("history capacity omitted a peer login outcome")
	}
	for _, session := range issued {
		response := performJSON(t, http.MethodGet, replica+"/v1/auth/me", session.Credential, nil)
		var identity iamv1.CurrentIdentity
		if response.Status != http.StatusOK || iamv1.DecodeRequest(bytes.NewReader(response.Body), &identity) != nil ||
			iamv1.ValidateCurrentIdentity(identity) != nil || identity.Account.ID != peer.id || identity.User.ID != peer.user.ID || identity.User.MustChangePassword {
			t.Fatal("history workload lost a peer session on the other IAM replica")
		}
	}
	var exact bool
	if err := database.QueryRow(ctx, `SELECT c.credential_version=$3+100 AND jsonb_array_length(c.password_history)=24
		AND iam.valid_password_history(c.password_history,c.password_history_digest,c.credential_version,c.password_changed_at)
		AND (SELECT count(*)=24 AND bool_and((h.value->>'generation')::bigint=c.credential_version-h.ordinality)
		  FROM jsonb_array_elements(c.password_history) WITH ORDINALITY h(value,ordinality))
		AND (SELECT count(*)=1 FROM iam.sessions s WHERE s.tenant_id=$1 AND s.principal_id=$2 AND s.status='ACTIVE')
		AND EXISTS(SELECT 1 FROM iam.sessions s WHERE s.tenant_id=$1 AND s.id=$4 AND s.status='ACTIVE' AND s.credential_version=c.credential_version)
		AND EXISTS(SELECT 1 FROM iam.sessions s WHERE s.tenant_id=$1 AND s.id=$5 AND s.status='REVOKED')
		AND (SELECT count(*)=100 AND count(DISTINCT event_document->>'requestId')=100
		  AND bool_and(event_document->'actor'->>'id'=$2 AND event_document->'target'->>'id'=$2 AND event_document->>'result'=$6)
		  FROM iam.audit_outbox WHERE tenant_id=$1 AND event_document->>'action'='iam.user.password-changed'
		  AND event_document->>'requestId' LIKE 'history-capacity-change-%')
		FROM iam.user_credentials c WHERE tenant_id=$1 AND principal_id=$2`, actor.id, actor.user.ID, generation, actor.login.Session.ID, old.Session.ID, auditv1.ResultSucceeded).Scan(&exact); err != nil || !exact {
		t.Fatal("measured full-history changes lost exact credential/session/history/fact effects")
	}
	response := performJSON(t, http.MethodGet, replica+"/v1/auth/me", old.Credential, nil)
	if response.Status != http.StatusUnauthorized {
		t.Fatal("full-history change preserved an explicitly revoked old session")
	}
	response = performJSON(t, http.MethodGet, replica+"/v1/auth/me", actor.login.Credential, nil)
	var current iamv1.CurrentIdentity
	if response.Status != http.StatusOK || iamv1.DecodeRequest(bytes.NewReader(response.Body), &current) != nil || current.User.ID != actor.user.ID || current.Account.ID != actor.id {
		t.Fatal("full-history change lost the actual retained current session")
	}
	waitAllIAMOutboxDelivered(t, ctx, database)
	for _, account := range accounts {
		verification := verifyAudit(t, auditEndpoint, account.root.Credential)
		if verification.State != auditv1.VerificationVerified || !verification.Complete || verification.TenantID != auditv1.TenantID(account.id) {
			t.Fatal("history capacity workload lost its actual audit chain")
		}
	}
	waitAllIAMOutboxDelivered(t, ctx, database)
	if err := database.QueryRow(ctx, `SELECT count(*)>0 AND count(record.event_id)=count(*)
		AND bool_and(record.event_document=outbox.event_document)
		FROM iam.audit_outbox outbox LEFT JOIN audit.records record ON record.source='IAM' AND record.event_id=outbox.event_id`).Scan(&exact); err != nil || !exact {
		t.Fatal("history capacity workload lost a committed final audit fact")
	}
	assertRuntimeProcessLogins(t, ctx, database, iamAPILogin, "matrix_authority_process_iam_replica", iamWorkerLogin, auditRuntimeLogin, paasAPILogin, paasWorkerLogin)
	assertAuthorityPlaintextAbsent(t, ctx, database, secrets...)
	return secrets
}

// Only authenticated HTTP establishes the rule. Read-only access to the
// synthetic envelope/clock is test observation, not a settings or MFA bypass.
func configureIAMCapacityHistory(t *testing.T, ctx context.Context, database *pgx.Conn, endpoint, replica string, account iamv1.AccountID, owner string) []string {
	t.Helper()
	const initial, password = "Capacity-Settings-Initial-73!", "Capacity-Settings-Current-81!"
	secrets := []string{initial, password}
	secret := func(value iamv1.Secret) string {
		material := value.CopyBytes()
		defer clear(material)
		secrets = append(secrets, string(material))
		return string(material)
	}
	call := func(method, path, bearer string, body, result any, status int) {
		t.Helper()
		response := performJSON(t, method, endpoint+path, bearer, body)
		if response.Status != status || (result != nil && iamv1.DecodeRequest(bytes.NewReader(response.Body), result) != nil) {
			t.Fatalf("history settings setup %s %s status=%d want=%d", method, path, response.Status, status)
		}
	}
	user := createIAMUser(t, endpoint, owner, "capacity.settings", "Capacity settings operator", initial, "history-capacity-operator")
	var policy iamv1.PolicyDetail
	call(http.MethodPost, "/v1/policies", owner, iamv1.CreatePolicyRequest{DisplayName: "Capacity settings only", RequestID: "history-capacity-policy",
		Document: iamv1.PolicyDocument{LanguageVersion: iamv1.PolicyLanguageVersion, Scope: iamv1.AuthorityScopeTenant,
			Statements: []iamv1.PolicyStatement{{SID: "settings", Effect: iamv1.PolicyAllow, Actions: []iamv1.Action{iamv1.ActionIAMSecuritySettingsUpdate},
				Resources: []iamv1.PolicyResourceSelector{{Kind: iamv1.ResourceAccount, Match: iamv1.PolicyResourceExact, ID: string(account)}}}}}}, &policy, http.StatusCreated)
	createIAMPolicyAttachment(t, endpoint, owner, user.ID, policy.Policy.ID, "history-capacity-settings-grant")
	realm := "capacity.settings@" + string(account)
	first := loginIAM(t, endpoint, realm, initial, "history-capacity-operator-login")
	secrets = append(secrets, first.Credential)
	changePasswordIAM(t, endpoint, first.Credential, initial, password, "history-capacity-operator-password")
	var contact iamv1.NotificationContactVerification
	call(http.MethodPost, "/v1/auth/notification-contact/verifications", first.Credential,
		map[string]string{"email": "capacity@matrix.test", "password": password, "requestId": "history-capacity-contact"}, &contact, http.StatusOK)
	contactCode := readProcessContactCode(t, ctx, database, contact)
	secrets = append(secrets, contactCode)
	call(http.MethodPost, "/v1/auth/notification-contact/verifications/"+contact.ID+":confirm", first.Credential,
		map[string]string{"requestId": "history-capacity-contact-confirm", "code": contactCode}, nil, http.StatusOK)
	var enrollment iamv1.StartTOTPEnrollmentResponse
	call(http.MethodPost, "/v1/auth/totp/enrollments", first.Credential,
		map[string]any{"requestId": "history-capacity-enroll", "password": password, "expectedFactorRevision": 1}, &enrollment, http.StatusOK)
	if enrollment.Provisioning == nil {
		t.Fatal("capacity settings operator did not receive a real factor")
	}
	seed := secret(enrollment.Provisioning.Seed)
	secret(enrollment.Provisioning.URI)
	secrets = append(secrets, url.QueryEscape(seed))
	code, previous := processTOTPCode(t, ctx, database, seed, -1, true)
	secrets = append(secrets, code)
	var bound iamv1.ConfirmTOTPEnrollmentResponse
	call(http.MethodPost, "/v1/auth/totp/enrollments/"+enrollment.Enrollment.ID+":confirm", first.Credential,
		map[string]string{"requestId": "history-capacity-bind", "code": code}, &bound, http.StatusOK)
	for _, recovery := range bound.RecoveryCodes {
		secret(recovery)
	}
	var challenge, authenticated iamv1.LoginResponse
	call(http.MethodPost, "/v1/auth/login", "", map[string]string{"loginName": realm, "password": password, "requestId": "history-capacity-qualified"}, &challenge, http.StatusOK)
	if challenge.Outcome != iamv1.LoginChallengeRequired || challenge.Challenge == nil || challenge.Challenge.NextStep != "TOTP" {
		t.Fatal("capacity operator bypassed real MFA login")
	}
	code, previous = processTOTPCode(t, ctx, database, seed, previous, false)
	secrets = append(secrets, code)
	call(http.MethodPost, "/v1/auth/challenges/"+challenge.Challenge.ID+":verify", "",
		map[string]string{"requestId": "history-capacity-qualified-verify", "challengeCredential": secret(challenge.ChallengeCredential), "code": code}, &authenticated, http.StatusOK)
	if authenticated.Outcome != iamv1.LoginAuthenticated {
		t.Fatal("capacity settings operator lacks a real authenticated session")
	}
	caller := secret(authenticated.Credential)
	rules := iamv1.AccountPasswordSettings{ExpiryMode: iamv1.PasswordExpiryChange, MinimumLength: 15, HistoryCount: 24}
	var proof iamv1.StepUp
	call(http.MethodPost, "/v1/auth/step-up", caller, iamv1.StartStepUpRequest{RequestID: "history-capacity-settings", Operation: iamv1.StepUpUpdateSecuritySettings, ExpectedFactorRevision: 2,
		SecuritySettings: &iamv1.SecuritySettingsUpdateIntent{ExpectedResourceVersion: 1, MFA: iamv1.AccountMFASettings{}, Password: &rules}}, &proof, http.StatusOK)
	code, _ = processTOTPCode(t, ctx, database, seed, previous, false)
	secrets = append(secrets, code)
	call(http.MethodPost, "/v1/auth/step-up/"+proof.ID+":verify", caller,
		map[string]string{"requestId": "history-capacity-proof", "password": password, "code": code}, &proof, http.StatusOK)
	response := performJSON(t, http.MethodPut, replica+"/v1/account/security-settings", caller, iamv1.UpdateAccountSecuritySettingsRequest{
		RequestID: "history-capacity-settings", StepUpID: proof.ID, ExpectedResourceVersion: 1, MFA: iamv1.AccountMFASettings{}, Password: rules})
	var applied iamv1.UpdateAccountSecuritySettingsResponse
	if response.Status != http.StatusOK || iamv1.DecodeRequest(bytes.NewReader(response.Body), &applied) != nil || applied.Outcome != "APPLIED" ||
		applied.Change.Settings.Password == nil || *applied.Change.Settings.Password != rules || applied.Change.Settings.MFA.RequiredForUsers || applied.Change.Settings.ResourceVersion != 2 {
		t.Fatal("capacity history rule was not changed by its real operation-bound proof")
	}
	return secrets
}

func measureIAMCapacity(t *testing.T, ctx context.Context, database *pgx.Conn, endpoint, replica, auditEndpoint, paasEndpoint, platformBearer string) []string {
	t.Helper()
	const (
		initial = "Capacity-Initial-Password-63!"
		changed = "Capacity-Changed-Password-74!"
		wrong   = "Capacity-Incorrect-Password-85!"
	)
	type accountFixture struct {
		id          iamv1.AccountID
		root        string
		simple      iamv1.User
		complex     iamv1.User
		simpleLogin loginResult
		groupLogin  loginResult
		attachment  iamv1.PolicyAttachment
	}
	accounts := make([]accountFixture, 2)
	secrets := []string{initial, changed, wrong}
	// Deny deliberately omits public authority data. Check its real ownership
	// against immutable stored evidence after timing, never widen the response.
	type observedDecision struct {
		ID        string                      `json:"id"`
		AccountID iamv1.AccountID             `json:"tenant_id"`
		UserID    iamv1.PrincipalID           `json:"principal_id"`
		Document  iamv1.AuthorizationDecision `json:"document"`
	}
	var decisions []observedDecision
	var plannedDecisions int
	var issuedLogins []struct {
		login  loginResult
		server string
	}
	issuedSessions := make(map[iamv1.SessionID]bool)
	issuedCredentials := make(map[string]bool)
	var plannedLogins int
	for index := range accounts {
		account := &accounts[index]
		account.id = iamv1.AccountID(fmt.Sprintf("account-capacity-%d", index))
		rootName := fmt.Sprintf("capacity.root.%d", index)
		opened := performJSON(t, http.MethodPost, endpoint+"/v1/accounts", platformBearer, map[string]any{
			"id": account.id, "displayName": "Capacity account", "rootLoginName": rootName,
			"rootDisplayName": "Capacity owner", "initialPassword": initial, "requestId": "capacity-open-" + string(account.id),
		})
		var created iamv1.Account
		if opened.Status != http.StatusCreated || json.Unmarshal(opened.Body, &created) != nil || iamv1.ValidateAccount(created) != nil || created.ID != account.id {
			t.Fatal("capacity account was not created through the real authority")
		}
		owner := loginIAM(t, endpoint, rootName, initial, "capacity-root-login-"+string(account.id))
		changePasswordIAM(t, endpoint, owner.Credential, initial, changed, "capacity-root-password-"+string(account.id))
		account.root = owner.Credential
		secrets = append(secrets, owner.Credential)
		account.simple = createIAMUser(t, endpoint, account.root, "capacity.simple", "Simple capacity user", initial, "capacity-simple-create")
		account.complex = createIAMUser(t, endpoint, account.root, "capacity.group", "Group capacity user", initial, "capacity-group-create")
		account.simpleLogin = loginIAM(t, endpoint, "capacity.simple@"+string(account.id), initial, "capacity-simple-login")
		account.groupLogin = loginIAM(t, replica, "capacity.group@"+string(account.id), initial, "capacity-group-login")
		changePasswordIAM(t, endpoint, account.simpleLogin.Credential, initial, changed, "capacity-simple-password")
		changePasswordIAM(t, replica, account.groupLogin.Credential, initial, changed, "capacity-group-password")
		secrets = append(secrets, account.simpleLogin.Credential, account.groupLogin.Credential)
		account.attachment = createIAMPolicyAttachment(t, endpoint, account.root, account.simple.ID, iamv1.SystemPolicyPaaSViewer, "capacity-simple-attach")
		for groupIndex := range 8 {
			requestID := fmt.Sprintf("capacity-group-%d", groupIndex)
			response := performJSON(t, http.MethodPost, endpoint+"/v1/groups", account.root,
				iamv1.CreateGroupRequest{Name: fmt.Sprintf("Capacity group %d", groupIndex), RequestID: requestID})
			var group iamv1.Group
			if response.Status != http.StatusCreated || json.Unmarshal(response.Body, &group) != nil || iamv1.ValidateGroup(group) != nil || group.AccountID != account.id {
				t.Fatal("capacity group creation lost its authority")
			}
			response = performJSON(t, http.MethodPost, endpoint+"/v1/groups/"+string(group.ID)+"/memberships", account.root,
				iamv1.CreateGroupMembershipRequest{UserID: account.complex.ID, RequestID: requestID + "-join"})
			var membership iamv1.GroupMembership
			if response.Status != http.StatusOK || json.Unmarshal(response.Body, &membership) != nil || iamv1.ValidateGroupMembership(membership) != nil || membership.UserID != account.complex.ID || membership.GroupID != group.ID || membership.AccountID != account.id {
				t.Fatal("capacity group membership was not actually established")
			}
			document := iamv1.PolicyDocument{LanguageVersion: iamv1.PolicyLanguageVersion, Scope: iamv1.AuthorityScopeTenant,
				Statements: []iamv1.PolicyStatement{
					{SID: "scoped-reader", Effect: iamv1.PolicyAllow, Actions: []iamv1.Action{iamv1.ActionPaaSApplicationRead},
						Resources: []iamv1.PolicyResourceSelector{{Kind: iamv1.ResourceApplication, Match: iamv1.PolicyResourcePrefixInAuthority, ID: "capacity-"}},
						Conditions: []iamv1.PolicyCondition{
							{Key: iamv1.ConditionIAMAccountID, Operator: iamv1.PolicyStringEquals, Values: []string{string(account.id)}},
							{Key: iamv1.ConditionIAMPrincipalID, Operator: iamv1.PolicyStringEquals, Values: []string{string(account.complex.ID)}},
						}},
					{SID: "explicit-deny", Effect: iamv1.PolicyDeny, Actions: []iamv1.Action{iamv1.ActionPaaSApplicationRead},
						Resources: []iamv1.PolicyResourceSelector{{Kind: iamv1.ResourceApplication, Match: iamv1.PolicyResourceExact, ID: "capacity-blocked"}}},
				}}
			response = performJSON(t, http.MethodPost, endpoint+"/v1/policies", account.root,
				iamv1.CreatePolicyRequest{DisplayName: fmt.Sprintf("Capacity policy %d", groupIndex), Document: document, RequestID: requestID + "-policy"})
			var policy iamv1.PolicyDetail
			if response.Status != http.StatusCreated || json.Unmarshal(response.Body, &policy) != nil || iamv1.ValidatePolicyDetail(policy) != nil || policy.Policy.AccountID != account.id {
				t.Fatal("capacity custom policy did not compile in its account")
			}
			response = performJSON(t, http.MethodPost, endpoint+"/v1/policy-attachments", account.root,
				iamv1.CreatePolicyAttachmentRequest{Target: iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetGroup, ID: string(group.ID)}, PolicyID: policy.Policy.ID, PolicyResourceVersion: policy.Policy.ResourceVersion, RequestID: requestID + "-attach"})
			var attachment iamv1.PolicyAttachment
			if response.Status != http.StatusOK || json.Unmarshal(response.Body, &attachment) != nil || iamv1.ValidatePolicyAttachment(attachment) != nil || attachment.PolicyID != policy.Policy.ID || attachment.Target.ID != string(group.ID) {
				t.Fatal("capacity group policy was not actually attached")
			}
		}
		boundaryDocument := iamv1.PolicyDocument{LanguageVersion: iamv1.PolicyLanguageVersion, Scope: iamv1.AuthorityScopeTenant,
			Statements: []iamv1.PolicyStatement{{SID: "upper-bound", Effect: iamv1.PolicyAllow, Actions: []iamv1.Action{iamv1.ActionPaaSApplicationRead},
				Resources: []iamv1.PolicyResourceSelector{
					{Kind: iamv1.ResourceApplication, Match: iamv1.PolicyResourceExact, ID: "capacity-selected"},
					{Kind: iamv1.ResourceApplication, Match: iamv1.PolicyResourceExact, ID: "capacity-blocked"},
				}}}}
		response := performJSON(t, http.MethodPost, endpoint+"/v1/policies", account.root,
			iamv1.CreatePolicyRequest{DisplayName: "Capacity upper bound", Document: boundaryDocument, RequestID: "capacity-boundary-policy"})
		var policy iamv1.PolicyDetail
		if response.Status != http.StatusCreated || json.Unmarshal(response.Body, &policy) != nil || iamv1.ValidatePolicyDetail(policy) != nil {
			t.Fatal("capacity upper bound publication failed")
		}
		boundaryPath := endpoint + "/v1/users/" + string(account.complex.ID) + "/permission-boundary"
		response = performJSON(t, http.MethodGet, boundaryPath, account.root, nil)
		var boundary iamv1.UserPermissionBoundary
		if response.Status != http.StatusOK || json.Unmarshal(response.Body, &boundary) != nil || iamv1.ValidateUserPermissionBoundary(boundary) != nil || boundary.Policy != nil {
			t.Fatal("capacity user had an unexpected upper bound")
		}
		response = performJSON(t, http.MethodPut, boundaryPath, account.root,
			iamv1.SetUserPermissionBoundaryRequest{PolicyID: policy.Policy.ID, PolicyResourceVersion: policy.Policy.ResourceVersion, ResourceVersion: boundary.ResourceVersion, RequestID: "capacity-boundary-set"})
		if response.Status != http.StatusOK {
			t.Fatal("capacity upper bound was not applied")
		}
		for _, server := range []string{endpoint, replica} {
			response = performJSON(t, http.MethodGet, server+"/v1/auth/me", account.groupLogin.Credential, nil)
			var identity iamv1.CurrentIdentity
			if response.Status != http.StatusOK || json.Unmarshal(response.Body, &identity) != nil || iamv1.ValidateCurrentIdentity(identity) != nil || len(identity.PolicySources) != 8 || identity.PermissionBoundary.Policy == nil || identity.PermissionBoundary.Policy.PolicyID != policy.Policy.ID {
				t.Fatal("capacity fixture is not exercising the actual group/boundary sources")
			}
			for _, source := range identity.PolicySources {
				if source.Kind != iamv1.PolicyGrantGroup || source.Membership == nil || source.Membership.UserID != account.complex.ID {
					t.Fatal("capacity fixture replaced group inheritance with direct permission")
				}
			}
		}
		for _, id := range []paasv1.ResourceID{"capacity-selected", "capacity-blocked", "capacity-beyond"} {
			operation := createPaaSApplication(t, paasEndpoint, account.root, id, string(id), "create-"+string(id), http.StatusCreated)
			if operation.Scope.TenantID != paasv1.TenantID(account.id) {
				t.Fatal("capacity resource setup changed its tenant")
			}
		}
		getPaaSApplication(t, paasEndpoint, account.simpleLogin.Credential, "capacity-selected", http.StatusOK)
		getPaaSApplication(t, paasEndpoint, account.groupLogin.Credential, "capacity-selected", http.StatusOK)
		getPaaSApplication(t, paasEndpoint, account.groupLogin.Credential, "capacity-blocked", http.StatusForbidden)
		getPaaSApplication(t, paasEndpoint, account.groupLogin.Credential, "capacity-beyond", http.StatusForbidden)
	}
	t.Log("IAM capacity workload: two measured accounts, four ordinary users, sixteen inherited groups/policies, two upper bounds and six persisted applications; management load adds one hundred empty groups")
	loginCall := func(account accountFixture, server, id string, incorrect bool) iamCapacityCall {
		password, status, lane := changed, http.StatusOK, "login-"+string(account.id)
		if incorrect {
			password, status, lane = wrong, http.StatusUnauthorized, "wrong-password-"+string(account.id)
		} else {
			plannedLogins++
		}
		return makeIAMCapacityCall(t, ctx, lane, http.MethodPost, server, "/v1/auth/login", "", map[string]string{
			"loginName": "capacity.simple@" + string(account.id), "password": password, "requestId": id,
		}, status, func(body []byte) (string, bool) {
			if incorrect {
				var problem iamv1.Problem
				return "", json.Unmarshal(body, &problem) == nil && problem.Status == http.StatusUnauthorized && !bytes.Contains(body, []byte(`"credential"`)) && !bytes.Contains(body, []byte(password))
			}
			var value struct {
				Session            iamv1.Session `json:"session"`
				Credential         string        `json:"credential"`
				MustChangePassword bool          `json:"mustChangePassword"`
			}
			valid := json.Unmarshal(body, &value) == nil && iamv1.ValidateSession(value.Session) == nil && value.Session.AccountID == account.id && value.Session.PrincipalID == account.simple.ID && value.Session.Status == iamv1.SessionActive && value.Session.RevokedAt == nil && !value.MustChangePassword && strings.HasPrefix(value.Credential, "mx1.") && !issuedSessions[value.Session.ID] && !issuedCredentials[value.Credential]
			if valid {
				other := replica
				if server == replica {
					other = endpoint
				}
				issuedSessions[value.Session.ID], issuedCredentials[value.Credential] = true, true
				issuedLogins = append(issuedLogins, struct {
					login  loginResult
					server string
				}{login: loginResult{Session: value.Session, Credential: value.Credential}, server: other})
			}
			return value.Credential, valid
		})
	}
	policyCall := func(account accountFixture, server, id, resource string, complex, allowed bool) iamCapacityCall {
		plannedDecisions++
		user, bearer, kind := account.simple, account.simpleLogin.Credential, "simple"
		if complex {
			user, bearer, kind = account.complex, account.groupLogin.Credential, "group-boundary"
		}
		request, err := iamv1.NewAuthorizationRequest(iamv1.ActionPaaSApplicationRead,
			iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: resource}, iamv1.AuthorizationResourceInstance, "", id, id)
		if err != nil {
			t.Fatal("capacity authorization request is outside the product declaration")
		}
		call := makeIAMCapacityCall(t, ctx, kind+"-"+string(account.id), http.MethodPost, server, "/v1/authorize", paasServiceCredential, request, http.StatusOK, func(body []byte) (string, bool) {
			var decision iamv1.AuthorizationDecision
			valid := json.Unmarshal(body, &decision) == nil && capacityDecisionMatches(decision, request, account.id, user.ID, allowed)
			if valid {
				decisions = append(decisions, observedDecision{ID: string(decision.ID), AccountID: account.id, UserID: user.ID, Document: decision})
			}
			return "", valid
		})
		call.request.Header.Set("Matrix-Subject-Credential", bearer)
		return call
	}
	servers := []string{endpoint, replica}
	for _, concurrency := range []int{1, 2} {
		for _, kind := range []string{"login", "simple", "group-boundary"} {
			stage := fmt.Sprintf("%s-c%d", kind, concurrency)
			calls := make([]iamCapacityCall, 0, 200)
			for index := range 200 {
				account, server := accounts[index%2], servers[(index/2)%2]
				id := fmt.Sprintf("capacity-%s-%d", stage, index)
				if kind == "login" {
					calls = append(calls, loginCall(account, server, id, false))
				} else {
					resource := "capacity-selected"
					if kind == "group-boundary" {
						resource = []string{"capacity-selected", "capacity-blocked", "capacity-beyond"}[(index/2)%3]
					}
					calls = append(calls, policyCall(account, server, id, resource, kind == "group-boundary", resource == "capacity-selected"))
				}
			}
			waitAllIAMOutboxDelivered(t, ctx, database)
			secrets = append(secrets, runIAMCapacityStage(t, ctx, database, stage, concurrency, iamCapacityPaired, calls)...)
		}
	}
	for _, kind := range []string{"business-read", "management-mix", "wrong-password-mix"} {
		calls := make([]iamCapacityCall, 0, 200)
		for index := range 200 {
			account, server := accounts[index%2], servers[(index/2)%2]
			id := fmt.Sprintf("capacity-%s-%d", kind, index)
			switch {
			case kind == "business-read":
				calls = append(calls, makeIAMCapacityCall(t, ctx, kind+"-"+string(account.id), http.MethodGet, paasEndpoint, "/v1/applications/capacity-selected", account.simpleLogin.Credential, nil, http.StatusOK, func(body []byte) (string, bool) {
					var application paasv1.Application
					return "", json.Unmarshal(body, &application) == nil && paasv1.ValidateApplication(application) == nil && application.Metadata.ID == "capacity-selected" && application.Metadata.Scope.TenantID == paasv1.TenantID(account.id)
				}))
			case kind == "management-mix" && index%2 == 0:
				calls = append(calls, makeIAMCapacityCall(t, ctx, "management-"+string(account.id), http.MethodPost, server, "/v1/groups", account.root, iamv1.CreateGroupRequest{Name: fmt.Sprintf("Capacity new group %d", index), RequestID: id}, http.StatusCreated, func(body []byte) (string, bool) {
					var group iamv1.Group
					return "", json.Unmarshal(body, &group) == nil && iamv1.ValidateGroup(group) == nil && group.AccountID == account.id && group.Name == fmt.Sprintf("Capacity new group %d", index)
				}))
			case kind == "wrong-password-mix" && index%2 == 0:
				calls = append(calls, loginCall(account, server, id, true))
			default:
				calls = append(calls, policyCall(account, server, id, "capacity-selected", true, true))
			}
		}
		waitAllIAMOutboxDelivered(t, ctx, database)
		secrets = append(secrets, runIAMCapacityStage(t, ctx, database, kind, 2, iamCapacityPaired, calls)...)
	}
	// A control and an independently progressing peer remove the paired
	// client's barrier. This is bounded interference evidence, not admission
	// control, open-loop saturation or a tenant fairness guarantee.
	for _, pressured := range []bool{false, true} {
		stage, concurrency := "independent-control", 1
		if pressured {
			stage, concurrency = "independent-wrong-password", 2
		}
		var calls []iamCapacityCall
		for index := range 100 {
			server := servers[index%2]
			if pressured {
				calls = append(calls, loginCall(accounts[0], server, fmt.Sprintf("capacity-%s-pressure-%d", stage, index), true))
			}
			call := policyCall(accounts[1], server, fmt.Sprintf("capacity-%s-probe-%d", stage, index), "capacity-selected", true, true)
			call.interval = 100 * time.Millisecond
			calls = append(calls, call)
		}
		waitAllIAMOutboxDelivered(t, ctx, database)
		secrets = append(secrets, runIAMCapacityStage(t, ctx, database, stage, concurrency, iamCapacityIndependent, calls)...)
	}
	// A successful write is followed by new requests through both real replicas;
	// measured Deny is expected service work, never counted as an HTTP failure.
	revokeIAMPolicyAttachment(t, replica, accounts[0].root, accounts[0].attachment.ID, accounts[0].attachment.ResourceVersion, "capacity-revoke-simple")
	calls := make([]iamCapacityCall, 0, 200)
	for index := range 200 {
		calls = append(calls, policyCall(accounts[index%2], servers[(index/2)%2], fmt.Sprintf("capacity-revoked-%d", index), "capacity-selected", false, index%2 != 0))
	}
	secrets = append(secrets, runIAMCapacityStage(t, ctx, database, "post-revocation", 2, iamCapacityPaired, calls)...)
	// A well-formed login response is not enough: every measured credential
	// must authenticate its actual USER on the other process. These reads are
	// deliberately outside all timed stages and confer no business permission.
	if plannedLogins == 0 || len(issuedLogins) != plannedLogins {
		t.Fatal("capacity login observation lost or reused an issued session")
	}
	for _, issued := range issuedLogins {
		response := performJSON(t, http.MethodGet, issued.server+"/v1/auth/me", issued.login.Credential, nil)
		var identity iamv1.CurrentIdentity
		if response.Status != http.StatusOK || json.Unmarshal(response.Body, &identity) != nil || iamv1.ValidateCurrentIdentity(identity) != nil || identity.Account.ID != issued.login.Session.AccountID || identity.User.ID != issued.login.Session.PrincipalID || identity.IdentityKind != iamv1.IdentityUser || identity.User.MustChangePassword {
			t.Fatal("a measured login credential could not authenticate its actual USER on the other IAM process")
		}
	}
	for _, account := range accounts {
		for _, resource := range []paasv1.ResourceID{"capacity-selected", "capacity-blocked", "capacity-beyond"} {
			getPaaSApplication(t, paasEndpoint, account.root, resource, http.StatusOK)
		}
	}
	assertRuntimeProcessLogins(t, ctx, database, iamAPILogin, "matrix_authority_process_iam_replica", iamWorkerLogin, auditRuntimeLogin, paasAPILogin, paasWorkerLogin)
	waitAllIAMOutboxDelivered(t, ctx, database)
	waitAllPaaSOutboxDelivered(t, ctx, database)
	encodedDecisions, err := json.Marshal(decisions)
	if err != nil || plannedDecisions == 0 || len(decisions) != plannedDecisions {
		t.Fatal("capacity observation lost a request-bound authorization result")
	}
	var recorded int
	var confined bool
	if err := database.QueryRow(ctx, `WITH expected AS (
		SELECT * FROM jsonb_to_recordset($1::jsonb) AS e(id text,tenant_id text,principal_id text,document jsonb))
		SELECT count(*),COALESCE(bool_and(d.principal_id=e.principal_id AND d.document::jsonb=e.document
			AND d.allowed=(e.document->>'allowed')::boolean AND d.request_id=e.document->>'requestId'
			AND d.action_name=e.document->>'action' AND d.target_kind=e.document->'resource'->>'kind'
			AND d.target_id=e.document->'resource'->>'id'),false)
		FROM expected e JOIN iam.authorization_decisions d ON d.tenant_id=e.tenant_id AND d.id=e.id`, string(encodedDecisions)).Scan(&recorded, &confined); err != nil || !confined || recorded != len(decisions) {
		t.Fatal("measured Allow/Deny did not preserve its exact private account/actor/request evidence")
	}
	for _, account := range accounts {
		verification := verifyAudit(t, auditEndpoint, account.root)
		if verification.State != auditv1.VerificationVerified || !verification.Complete || verification.TenantID != auditv1.TenantID(account.id) {
			t.Fatal("capacity load did not preserve its account audit chain")
		}
	}
	// Chain verification itself commits an authorization fact. Include those
	// final facts before stopping producers, not just the measured requests.
	waitAllIAMOutboxDelivered(t, ctx, database)
	var outboxCount, recordCount int
	var sameFacts bool
	if err := database.QueryRow(ctx, `SELECT (SELECT count(*) FROM iam.audit_outbox),count(record.event_id),
		COALESCE(bool_and(record.event_document=outbox.event_document),false)
		FROM iam.audit_outbox outbox LEFT JOIN audit.records record
		ON record.source='IAM' AND record.event_id=outbox.event_id`).Scan(&outboxCount, &recordCount, &sameFacts); err != nil || outboxCount == 0 || recordCount != outboxCount || !sameFacts {
		t.Fatal("capacity load lost, duplicated or rewrote a committed IAM audit fact")
	}
	return secrets
}

func capacityCgroupNumber(t *testing.T, name string) uint64 {
	t.Helper()
	content, err := os.ReadFile("/sys/fs/cgroup/" + name)
	if err != nil {
		t.Fatal("capacity observation requires its own readable cgroup v2 counters")
	}
	value, err := strconv.ParseUint(strings.TrimSpace(string(content)), 10, 64)
	if err != nil {
		t.Fatal("capacity observation requires a finite cgroup counter/limit")
	}
	return value
}

func assertIAMCapacityLimits(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Fatal("capacity observation requires a bounded Linux runner")
	}
	content, err := os.ReadFile("/sys/fs/cgroup/cpu.max")
	parts := strings.Fields(string(content))
	if err != nil || len(parts) != 2 {
		t.Fatal("capacity observation has no cgroup CPU ceiling")
	}
	quota, quotaErr := strconv.ParseUint(parts[0], 10, 64)
	period, periodErr := strconv.ParseUint(parts[1], 10, 64)
	if quotaErr != nil || periodErr != nil || quota == 0 || period == 0 || period > 1_000_000_000 || quota > 2*period || runtime.GOMAXPROCS(0) != 2 {
		t.Fatal("capacity runner exceeds the fixed two-CPU budget")
	}
	memory, pids := capacityCgroupNumber(t, "memory.max"), capacityCgroupNumber(t, "pids.max")
	if memory == 0 || memory > 1536*1024*1024 || pids == 0 || pids > 256 {
		t.Fatal("capacity runner exceeds the fixed memory/PID budget")
	}
	t.Logf("IAM_CAPACITY_LIMITS go=%s cpu_quota=%d cpu_period=%d memory_max=%d pids_max=%d gomaxprocs=2; test client and authority executables share these limits; PostgreSQL is separately bounded", runtime.Version(), quota, period, memory, pids)
}

func capacityCPU(t *testing.T) map[string]uint64 {
	t.Helper()
	content, err := os.ReadFile("/sys/fs/cgroup/cpu.stat")
	if err != nil {
		t.Fatal("capacity CPU observation is unavailable")
	}
	result := make(map[string]uint64)
	for _, line := range strings.Split(string(content), "\n") {
		parts := strings.Fields(line)
		if len(parts) != 2 || (parts[0] != "usage_usec" && parts[0] != "nr_throttled" && parts[0] != "throttled_usec") {
			continue
		}
		value, err := strconv.ParseUint(parts[1], 10, 64)
		if err != nil {
			t.Fatal("invalid capacity CPU counter")
		}
		result[parts[0]] = value
	}
	if len(result) != 3 {
		t.Fatal("capacity CPU observation is incomplete")
	}
	return result
}

func capacityPercentile(values []time.Duration, percentile int) time.Duration {
	if len(values) == 0 || percentile < 1 || percentile > 100 {
		return 0
	}
	ordered := append([]time.Duration(nil), values...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })
	return ordered[(len(ordered)*percentile+99)/100-1]
}

func capacityDecisionMatches(decision iamv1.AuthorizationDecision, request iamv1.AuthorizationRequest, account iamv1.AccountID, user iamv1.PrincipalID, allowed bool) bool {
	if iamv1.ValidateAuthorizationDecision(decision) != nil || decision.Allowed != allowed || decision.RequestID != request.RequestID || decision.CorrelationID != request.CorrelationID || decision.Action != request.Action || decision.Resource != request.Resource || decision.Profile == nil || *decision.Profile != request.Profile || decision.ResourceMode != request.ResourceMode || decision.CollectionUsage != request.CollectionUsage {
		return false
	}
	if !allowed {
		return decision.TenantID == "" && decision.InstallationID == "" && decision.Subject == nil
	}
	return decision.TenantID == account && decision.InstallationID == "" && decision.Subject != nil && decision.Subject.Type == iamv1.SubjectUser && decision.Subject.ID == string(user) && decision.Subject.RoleSession == nil && decision.Subject.AccessKeyID == ""
}

func TestIAMCapacityDecisionAttribution(t *testing.T) {
	request, err := iamv1.NewAuthorizationRequest(iamv1.ActionPaaSApplicationRead,
		iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "capacity-selected"}, iamv1.AuthorizationResourceInstance, "", "capacity-request", "capacity-correlation")
	if err != nil {
		t.Fatal(err)
	}
	for _, allowed := range []bool{false, true} {
		decision := func() iamv1.AuthorizationDecision {
			profile := request.Profile
			value := iamv1.AuthorizationDecision{APIVersion: iamv1.APIVersion, Kind: "AuthorizationDecision", ID: "capacity-decision", Allowed: allowed,
				Reason: iamv1.DecisionDenied, Action: request.Action, Resource: request.Resource, RequestID: request.RequestID, CorrelationID: request.CorrelationID,
				DecidedAt: time.Unix(1_800_000_000, 0).UTC(), Profile: &profile, ResourceMode: request.ResourceMode}
			if allowed {
				value.Reason, value.TenantID = iamv1.DecisionAllowed, "capacity-account"
				value.Subject = &iamv1.Subject{Type: iamv1.SubjectUser, ID: "capacity-user"}
			}
			return value
		}
		if !capacityDecisionMatches(decision(), request, "capacity-account", "capacity-user", allowed) {
			t.Fatal("a valid current Allow or authority-free Deny was discarded")
		}
		for _, mutate := range []func(*iamv1.AuthorizationDecision){
			func(d *iamv1.AuthorizationDecision) { d.Allowed = !allowed },
			func(d *iamv1.AuthorizationDecision) { d.TenantID = "another-account" },
			func(d *iamv1.AuthorizationDecision) {
				d.Subject = &iamv1.Subject{Type: iamv1.SubjectUser, ID: "another-user"}
			},
			func(d *iamv1.AuthorizationDecision) { d.RequestID = "another-request" },
			func(d *iamv1.AuthorizationDecision) { d.CorrelationID = "another-correlation" },
			func(d *iamv1.AuthorizationDecision) { d.Resource.ID = "another-resource" },
			func(d *iamv1.AuthorizationDecision) { d.Profile = nil },
		} {
			value := decision()
			mutate(&value)
			if capacityDecisionMatches(value, request, "capacity-account", "capacity-user", allowed) {
				t.Fatal("a wrong decision or leaked Deny identity was counted as valid work")
			}
		}
	}
}

func TestIAMCapacityPercentiles(t *testing.T) {
	values := make([]time.Duration, 100)
	for index := range values {
		values[index] = time.Duration(100-index) * time.Millisecond
	}
	for _, percentile := range []int{50, 95, 99, 100} {
		if capacityPercentile(values, percentile) != time.Duration(percentile)*time.Millisecond {
			t.Fatal("capacity percentiles omitted a tail sample")
		}
	}
	if values[0] != 100*time.Millisecond || capacityPercentile(nil, 99) != 0 || capacityPercentile([]time.Duration{5 * time.Second}, 99) != 5*time.Second {
		t.Fatal("capacity observations were mutated or an error-duration sample was lost")
	}
}

// Only scheduling and HTTP transport run concurrently. Response verification
// stays on the receiving test goroutine, including immutable evidence capture.
func dispatchIAMCapacityCalls(ctx context.Context, client *http.Client, started time.Time, concurrency int, schedule iamCapacitySchedule, calls []iamCapacityCall) (<-chan iamCapacityResult, error) {
	if concurrency < 1 || concurrency > 2 || len(calls) == 0 || len(calls) > 200 || (schedule != iamCapacityPaired && schedule != iamCapacityIndependent) {
		return nil, errors.New("invalid capacity workload budget")
	}
	lanes := make(map[string][]int)
	for index, call := range calls {
		if call.request == nil || call.lane == "" || call.interval < 0 || call.interval > 100*time.Millisecond || (schedule == iamCapacityPaired && (call.interval != 0 || call.confirm)) {
			return nil, errors.New("invalid capacity request schedule")
		}
		indexes := lanes[call.lane]
		if len(indexes) > 0 && calls[indexes[0]].interval != call.interval {
			return nil, errors.New("inconsistent capacity lane interval")
		}
		lanes[call.lane] = append(indexes, index)
	}
	if schedule == iamCapacityIndependent && len(lanes) != concurrency {
		return nil, errors.New("independent capacity lanes exceed worker budget")
	}
	results := make(chan iamCapacityResult, concurrency)
	execute := func(index int, scheduled time.Time) bool {
		if !scheduled.IsZero() {
			if delay := time.Until(scheduled); delay > 0 {
				timer := time.NewTimer(delay)
				defer timer.Stop()
				select {
				case <-timer.C:
				case <-ctx.Done():
					return false
				}
			}
		}
		if ctx.Err() != nil {
			return false
		}
		result := iamCapacityResult{index: index, scheduled: scheduled, started: time.Now()}
		if calls[index].confirm {
			result.confirm = make(chan bool, 1)
		}
		response, err := client.Do(calls[index].request.Clone(ctx))
		if err != nil {
			result.failed = true
		} else {
			result.status = response.StatusCode
			result.body, err = io.ReadAll(io.LimitReader(response.Body, 2*1024*1024+1))
			closeErr := response.Body.Close()
			result.failed = err != nil || closeErr != nil || len(result.body) > 2*1024*1024
		}
		result.completed = time.Now()
		select {
		case results <- result:
			if result.confirm != nil {
				select {
				case accepted := <-result.confirm:
					return accepted
				case <-ctx.Done():
					return false
				}
			}
			return true
		case <-ctx.Done():
			clear(result.body)
			return false
		}
	}
	go func() {
		defer close(results)
		var workers sync.WaitGroup
		if schedule == iamCapacityIndependent {
			for _, indexes := range lanes {
				workers.Go(func() {
					for ordinal, index := range indexes {
						var scheduled time.Time
						if calls[index].interval > 0 {
							scheduled = started.Add(time.Duration(ordinal) * calls[index].interval)
						}
						if !execute(index, scheduled) {
							return
						}
					}
				})
			}
			workers.Wait()
			return
		}
		for offset := 0; offset < len(calls) && ctx.Err() == nil; offset += concurrency {
			for index := offset; index < min(offset+concurrency, len(calls)); index++ {
				workers.Go(func() { execute(index, time.Time{}) })
			}
			workers.Wait()
		}
	}()
	return results, nil
}

func TestIAMCapacityScheduling(t *testing.T) {
	t.Run("dependent-mutation", func(t *testing.T) {
		for _, outcome := range []string{"accepted", "rejected", "malformed", "unknown", "cancelled"} {
			t.Run(outcome, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				var nextInvoked atomic.Int32
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/first" {
						switch outcome {
						case "rejected":
							w.WriteHeader(http.StatusConflict)
						case "malformed":
							w.WriteHeader(http.StatusOK)
						case "unknown":
							connection, _, err := w.(http.Hijacker).Hijack()
							if err != nil {
								t.Error("test could not interrupt mutation response")
								return
							}
							_ = connection.Close()
						default:
							w.WriteHeader(http.StatusOK)
							_, _ = io.WriteString(w, "accepted")
						}
						return
					}
					if r.URL.Path == "/next" {
						nextInvoked.Add(1)
					}
					w.WriteHeader(http.StatusNoContent)
				}))
				defer server.Close()
				var calls []iamCapacityCall
				for index, path := range []string{"first", "peer", "next", "peer"} {
					request, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+"/"+path, nil)
					if err != nil {
						t.Fatal(err)
					}
					lane := "peer"
					if index%2 == 0 {
						lane = "mutation"
					}
					calls = append(calls, iamCapacityCall{lane: lane, request: request, confirm: index == 0})
				}
				results, err := dispatchIAMCapacityCalls(ctx, server.Client(), time.Now(), 2, iamCapacityIndependent, calls)
				if err != nil {
					t.Fatal(err)
				}
				var first iamCapacityResult
				var seen [4]bool
				for !seen[0] || !seen[1] || !seen[3] {
					select {
					case result, ok := <-results:
						if !ok || result.index == 2 || seen[result.index] {
							t.Fatal("dependent work advanced before confirmation or lost its independent peer")
						}
						seen[result.index] = true
						if result.index == 0 {
							first = result
						} else if result.failed || result.status != http.StatusNoContent {
							t.Fatal("unrelated peer failed while mutation awaited confirmation")
						}
					case <-ctx.Done():
						t.Fatal("dependent schedule or peer failed to make progress")
					}
				}
				if nextInvoked.Load() != 0 || first.confirm == nil {
					t.Fatal("next mutation was issued without a verified predecessor")
				}
				accepted := !first.failed && first.status == http.StatusOK && string(first.body) == "accepted"
				clear(first.body)
				if outcome == "cancelled" {
					cancel()
				} else {
					first.confirm <- accepted
				}
				for result := range results {
					if outcome != "accepted" || result.index != 2 || seen[2] || result.failed || result.status != http.StatusNoContent {
						t.Fatal("failed or unknown mutation permitted dependent work")
					}
					seen[2] = true
				}
				var expectedInvocations int32
				if outcome == "accepted" {
					expectedInvocations = 1
				}
				if seen[2] != (outcome == "accepted") || nextInvoked.Load() != expectedInvocations {
					t.Fatal("dependent schedule did not preserve the exact confirmed outcome")
				}
			})
		}
	})
	for _, schedule := range []iamCapacitySchedule{iamCapacityPaired, iamCapacityIndependent} {
		t.Run(fmt.Sprint(schedule), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			pressureStarted, releasePressure := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(releasePressure) }) }
			var active, peak atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				now := active.Add(1)
				defer active.Add(-1)
				for observed := peak.Load(); now > observed; observed = peak.Load() {
					if peak.CompareAndSwap(observed, now) {
						break
					}
				}
				if r.URL.Path == "/pressure-0" {
					close(pressureStarted)
					select {
					case <-releasePressure:
					case <-r.Context().Done():
						return
					}
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			defer server.Close()
			defer release()
			var calls []iamCapacityCall
			for _, path := range []string{"pressure-0", "probe-0", "pressure-1", "probe-1"} {
				request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/"+path, nil)
				if err != nil {
					t.Fatal(err)
				}
				calls = append(calls, iamCapacityCall{lane: strings.Split(path, "-")[0], request: request})
			}
			results, err := dispatchIAMCapacityCalls(ctx, server.Client(), time.Now(), 2, schedule, calls)
			if err != nil {
				t.Fatal(err)
			}
			select {
			case <-pressureStarted:
			case <-ctx.Done():
				t.Fatal("pressure request did not start")
			}
			var seen [4]bool
			observe := func(result iamCapacityResult) {
				if result.index < 0 || result.index >= len(seen) || seen[result.index] || result.failed || result.status != http.StatusNoContent || result.completed.Before(result.started) {
					t.Fatal("capacity dispatcher lost, duplicated or misreported a request")
				}
				seen[result.index] = true
			}
			// Independent probes must finish twice while the peer is held.
			// Paired mode must keep the original batch barrier instead.
			for needed := 1; needed <= 1+int(schedule); needed++ {
				select {
				case result := <-results:
					if result.index != needed*2-1 {
						t.Fatal("capacity probe acquired its peer's completion")
					}
					observe(result)
				case <-ctx.Done():
					t.Fatal("normal lane could not progress under the declared schedule")
				}
			}
			if schedule == iamCapacityPaired {
				select {
				case <-results:
					t.Fatal("paired schedule removed the existing batch barrier")
				case <-time.After(20 * time.Millisecond):
				}
			}
			release()
			for result := range results {
				observe(result)
			}
			if ctx.Err() != nil || peak.Load() > 2 || seen != [4]bool{true, true, true, true} {
				t.Fatal("capacity schedule exceeded concurrency or omitted a sample")
			}
		})
	}
	t.Run("pace-and-cancel", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var invoked atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { invoked.Add(1); w.WriteHeader(http.StatusNoContent) }))
		defer server.Close()
		var calls []iamCapacityCall
		for range 3 {
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			calls = append(calls, iamCapacityCall{lane: "probe", request: request, interval: 20 * time.Millisecond})
		}
		started := time.Now()
		results, err := dispatchIAMCapacityCalls(ctx, server.Client(), started, 1, iamCapacityIndependent, calls)
		if err != nil {
			t.Fatal(err)
		}
		count := 0
		for result := range results {
			if result.index != count || result.scheduled != started.Add(time.Duration(count)*20*time.Millisecond) || result.started.Before(result.scheduled) || result.failed || result.status != http.StatusNoContent {
				t.Fatal("paced request was sent early, reordered or silently lost")
			}
			count++
		}
		if count != 3 {
			t.Fatal("paced lane did not account for all samples")
		}
		cancelled, stop := context.WithCancel(ctx)
		results, err = dispatchIAMCapacityCalls(cancelled, server.Client(), time.Now().Add(time.Second), 1, iamCapacityIndependent, calls)
		if err != nil {
			t.Fatal(err)
		}
		stop()
		if _, ok := <-results; ok || invoked.Load() != 3 {
			t.Fatal("cancelled pacing leaked another request")
		}
		for _, invalid := range []struct {
			concurrency int
			schedule    iamCapacitySchedule
			calls       []iamCapacityCall
		}{
			{0, iamCapacityIndependent, calls}, {3, iamCapacityIndependent, calls}, {1, 99, calls},
			{1, iamCapacityIndependent, nil}, {2, iamCapacityIndependent, calls}, {1, iamCapacityPaired, calls},
			{1, iamCapacityIndependent, make([]iamCapacityCall, 201)},
		} {
			if _, err := dispatchIAMCapacityCalls(ctx, server.Client(), time.Now(), invalid.concurrency, invalid.schedule, invalid.calls); err == nil {
				t.Fatal("invalid capacity budget started work")
			}
		}
	})
}

func runIAMCapacityStage(t *testing.T, ctx context.Context, database *pgx.Conn, name string, concurrency int, schedule iamCapacitySchedule, calls []iamCapacityCall) []string {
	t.Helper()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type laneResult struct {
		latencies                []time.Duration
		failures                 int
		statuses                 map[int]int
		errors                   map[string]int
		starts                   []time.Time
		first, last              time.Time
		lags, scheduledLatencies []time.Duration
		interval                 time.Duration
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.MaxConnsPerHost, transport.MaxIdleConnsPerHost, transport.MaxIdleConns = 2, 2, 4
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	lanes := make(map[string]*laneResult)
	planned := make(map[string]int)
	for _, call := range calls {
		planned[call.lane]++
	}
	accounted := false
	defer func() {
		if accounted {
			return
		}
		// A deadline must not erase observations that already arrived. Missing
		// responses are UNKNOWN, not proof that a request did not execute or
		// commit. Partial percentiles describe observed responses only.
		names := make([]string, 0, len(planned))
		for name := range planned {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, laneName := range names {
			observation := map[string]any{
				"stage": name, "lane": laneName, "completion": "INCOMPLETE",
				"plannedSamples": planned[laneName], "observedSamples": 0,
				"unobservedOutcomes": planned[laneName], "failures": 0,
				"statusCounts": map[int]int{}, "errorCounts": map[string]int{},
				"observedP50MS": nil, "observedP95MS": nil, "observedP99MS": nil, "observedMaxMS": nil,
			}
			if lane := lanes[laneName]; lane != nil {
				observation["observedSamples"] = len(lane.latencies)
				observation["unobservedOutcomes"] = planned[laneName] - len(lane.latencies)
				observation["failures"], observation["statusCounts"], observation["errorCounts"] = lane.failures, lane.statuses, lane.errors
				if len(lane.latencies) != 0 {
					for metric, percentile := range map[string]int{"observedP50MS": 50, "observedP95MS": 95, "observedP99MS": 99, "observedMaxMS": 100} {
						observation[metric] = float64(capacityPercentile(lane.latencies, percentile)) / float64(time.Millisecond)
					}
				}
			}
			encoded, err := json.Marshal(observation)
			if err != nil {
				t.Log("incomplete capacity observation encoding failed")
				continue
			}
			t.Logf("IAM_CAPACITY_INCOMPLETE %s", encoded)
		}
	}()
	var secrets []string
	var samples, peakConnections, peakActive, peakLockWaiting, peakOutbox int
	sample := func() {
		var connections, active, locked, perLogin, backlog int
		err := database.QueryRow(ctx, `WITH observed AS (
			SELECT state,wait_event_type,count(*) OVER (PARTITION BY usename) AS per_login
			FROM pg_stat_activity WHERE datname=current_database() AND application_name=ANY($1))
			SELECT count(*),count(*) FILTER (WHERE state='active'),
			count(*) FILTER (WHERE state='active' AND wait_event_type='Lock'),COALESCE(max(per_login),0),
			(SELECT count(*) FROM iam.audit_outbox WHERE status <> 'DELIVERED') FROM observed`,
			[]string{"matrix-authority-process:" + iamAPILogin, "matrix-authority-process:matrix_authority_process_iam_replica"}).Scan(&connections, &active, &locked, &perLogin, &backlog)
		if err != nil || perLogin > 2 || connections > 4 {
			t.Fatal("capacity database observation failed or runtime connection ceiling was exceeded")
		}
		samples++
		peakConnections, peakActive, peakLockWaiting, peakOutbox = max(peakConnections, connections), max(peakActive, active), max(peakLockWaiting, locked), max(peakOutbox, backlog)
	}
	sample()
	cpuStart := capacityCPU(t)
	started := time.Now()
	results, err := dispatchIAMCapacityCalls(ctx, client, started, concurrency, schedule, calls)
	if err != nil {
		t.Fatal(err)
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for remaining := len(calls); remaining > 0; {
		select {
		case result, ok := <-results:
			if !ok {
				t.Fatal("capacity schedule ended without accounting for every request")
			}
			remaining--
			call := calls[result.index]
			lane := lanes[call.lane]
			if lane == nil {
				lane = &laneResult{statuses: make(map[int]int), errors: make(map[string]int), interval: call.interval}
				lanes[call.lane] = lane
			}
			lane.latencies = append(lane.latencies, result.completed.Sub(result.started))
			lane.starts = append(lane.starts, result.started)
			if lane.first.IsZero() || result.started.Before(lane.first) {
				lane.first = result.started
			}
			if result.completed.After(lane.last) {
				lane.last = result.completed
			}
			if !result.scheduled.IsZero() {
				lane.lags = append(lane.lags, result.started.Sub(result.scheduled))
				lane.scheduledLatencies = append(lane.scheduledLatencies, result.completed.Sub(result.scheduled))
			}
			lane.statuses[result.status]++
			secret, valid := call.verify(result.body)
			if secret != "" {
				secrets = append(secrets, secret)
			}
			accepted := !result.failed && result.status == call.status && valid
			if !accepted {
				lane.failures++
				reason := "response-contract"
				if result.failed {
					reason = "transport-or-body"
				} else if result.status != call.status {
					reason = "unexpected-status"
				}
				lane.errors[reason]++
			}
			clear(result.body)
			if result.confirm != nil {
				result.confirm <- accepted
			}
		case <-ticker.C:
			sample()
		case <-ctx.Done():
			t.Fatal("capacity workload exceeded the original process-fixture deadline")
		}
	}
	accounted = true
	elapsed := time.Since(started)
	sample()
	cpuEnd := capacityCPU(t)
	for key, before := range cpuStart {
		if cpuEnd[key] < before {
			t.Fatal("capacity counter reset during one stage")
		}
		cpuEnd[key] -= before
	}
	names := make([]string, 0, len(lanes))
	for lane := range lanes {
		names = append(names, lane)
	}
	sort.Strings(names)
	for _, laneName := range names {
		lane := lanes[laneName]
		load := "closed-loop-paired-batches"
		if schedule == iamCapacityIndependent {
			load = "closed-loop-independent-lanes"
		}
		observation := map[string]any{
			"stage": name, "lane": laneName, "concurrency": concurrency, "load": load,
			"samples": len(lane.latencies), "failures": lane.failures, "statusCounts": lane.statuses, "errorCounts": lane.errors,
			"elapsedMS": float64(elapsed) / float64(time.Millisecond), "verifiedRequestsPerSecond": float64(len(lane.latencies)-lane.failures) / elapsed.Seconds(),
			"p50MS":              float64(capacityPercentile(lane.latencies, 50)) / float64(time.Millisecond),
			"p95MS":              float64(capacityPercentile(lane.latencies, 95)) / float64(time.Millisecond),
			"p99MS":              float64(capacityPercentile(lane.latencies, 99)) / float64(time.Millisecond),
			"maxMS":              float64(capacityPercentile(lane.latencies, 100)) / float64(time.Millisecond),
			"samplingIntervalMS": 100, "databaseSamples": samples, "observedIAMConnectionsPeak": peakConnections,
			"observedIAMActivePeak": peakActive, "observedIAMLockWaitingPeak": peakLockWaiting, "observedIAMOutboxPeak": peakOutbox,
			"poolWaitDuration": nil, "lockWaitDuration": nil, "runnerCPUChange": cpuEnd,
			"runnerMemoryCurrentBytes": capacityCgroupNumber(t, "memory.current"), "runnerMemoryPeakBytes": capacityCgroupNumber(t, "memory.peak"),
		}
		if schedule == iamCapacityIndependent {
			observation["laneStartMS"] = float64(lane.first.Sub(started)) / float64(time.Millisecond)
			observation["laneEndMS"] = float64(lane.last.Sub(started)) / float64(time.Millisecond)
			observation["laneVerifiedRequestsPerSecond"] = float64(len(lane.latencies)-lane.failures) / lane.last.Sub(lane.first).Seconds()
			observation["plannedIntervalMS"], observation["schedulingLagP99MS"], observation["scheduledCompletionP99MS"] = nil, nil, nil
			if len(lane.lags) != 0 {
				observation["plannedIntervalMS"] = float64(lane.interval) / float64(time.Millisecond)
				for _, metric := range []struct {
					name   string
					values []time.Duration
				}{
					{"schedulingLag", lane.lags}, {"scheduledCompletion", lane.scheduledLatencies},
				} {
					for _, percentile := range []int{50, 95, 99, 100} {
						observation[fmt.Sprintf("%sP%dMS", metric.name, percentile)] = float64(capacityPercentile(metric.values, percentile)) / float64(time.Millisecond)
					}
				}
			}
			observation["samplesStartedDuringPeerWindow"] = nil
			for peerName, peer := range lanes {
				if peerName == laneName {
					continue
				}
				var overlap int
				for _, begin := range lane.starts {
					if !begin.Before(peer.first) && begin.Before(peer.last) {
						overlap++
					}
				}
				observation["samplesStartedDuringPeerWindow"] = overlap
				if overlap == 0 {
					t.Errorf("independent capacity stage %s lane %s never overlapped its peer", name, laneName)
				}
			}
		}
		encoded, err := json.Marshal(observation)
		if err != nil {
			t.Fatal("capacity observation encoding failed")
		}
		t.Logf("IAM_CAPACITY %s", encoded)
		if lane.failures != 0 || len(lane.latencies) != 100 {
			t.Errorf("capacity stage %s lane %s: samples=%d failures=%d; no retries or samples discarded", name, laneName, len(lane.latencies), lane.failures)
		}
	}
	return secrets
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
		t.Fatalf("IAM password change request=%s status=%d", requestID, response.Status)
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

func proveAccessKeyProcesses(t *testing.T, ctx context.Context, database *pgx.Conn, endpoint, replica, auditEndpoint, home, customer string,
	withAuditOutage func(func()), restartIAM func()) []string {
	t.Helper()
	call := func(server, method, path, bearer string, body any, status int, result any) {
		t.Helper()
		response := performJSON(t, method, server+path, bearer, body)
		if response.Status != status || result != nil && iamv1.DecodeRequest(bytes.NewReader(response.Body), result) != nil {
			t.Fatalf("AccessKey process %s %s status=%d want=%d", method, path, response.Status, status)
		}
	}
	type accountFixture struct {
		owner, manager, targetBearer, path string
		target                             iamv1.User
		grant                              iamv1.PolicyAttachment
		key                                iamv1.CreateAccessKeyResponse
		intent                             iamv1.CreateAccessKeyRequest
	}
	accounts := []accountFixture{{owner: home}, {owner: customer}}
	sensitive := []string{}
	for index := range accounts {
		account := &accounts[index]
		prefix := fmt.Sprintf("program-%d", index)
		manager := createIAMUser(t, endpoint, account.owner, "program.manager", "Program manager", initialReaderPassword, prefix+"-manager")
		target := createIAMUser(t, endpoint, account.owner, "program.user", "Program user", initialReaderPassword, prefix+"-user")
		for _, user := range []iamv1.User{manager, target} {
			login := loginIAM(t, endpoint, user.LoginName+"@"+string(user.AccountID), initialReaderPassword, prefix+"-"+string(user.ID)+"-login")
			changePasswordIAM(t, endpoint, login.Credential, initialReaderPassword, changedReaderPassword, prefix+"-"+string(user.ID)+"-password")
			sensitive = append(sensitive, login.Credential)
			if user.ID == manager.ID {
				account.manager = login.Credential
			} else {
				account.targetBearer = login.Credential
			}
		}
		var current iamv1.CurrentIdentity
		call(endpoint, http.MethodGet, "/v1/auth/me", account.targetBearer, nil, http.StatusOK, &current)
		account.target = current.User
		account.path = "/v1/users/" + string(target.ID) + "/access-keys"
		call(endpoint, http.MethodGet, account.path, account.manager, nil, http.StatusForbidden, nil)
		rule := func(sid string, actions []iamv1.Action, kind iamv1.ResourceKind) iamv1.PolicyStatement {
			return iamv1.PolicyStatement{SID: sid, Effect: iamv1.PolicyAllow, Actions: actions, Resources: []iamv1.PolicyResourceSelector{{Kind: kind, Match: iamv1.PolicyResourceAnyInAuthority}}}
		}
		var policy iamv1.PolicyDetail
		call(endpoint, http.MethodPost, "/v1/policies", account.owner, iamv1.CreatePolicyRequest{DisplayName: prefix + " key manager", RequestID: prefix + "-policy",
			Document: iamv1.PolicyDocument{LanguageVersion: "1", Scope: iamv1.AuthorityScopeTenant, Statements: []iamv1.PolicyStatement{
				rule("user", []iamv1.Action{iamv1.ActionIAMAccessKeyList, iamv1.ActionIAMAccessKeyCreate}, iamv1.ResourceUser),
				rule("key", []iamv1.Action{iamv1.ActionIAMAccessKeyRead, iamv1.ActionIAMAccessKeySetStatus, iamv1.ActionIAMAccessKeyDelete}, iamv1.ResourceAccessKey)}}}, http.StatusCreated, &policy)
		account.grant = createIAMPolicyAttachment(t, endpoint, account.owner, manager.ID, policy.Policy.ID, prefix+"-grant")
		var directory iamv1.AccessKeyList
		call(replica, http.MethodGet, account.path, account.manager, nil, http.StatusOK, &directory)
		if iamv1.ValidateAccessKeyList(directory) != nil || len(directory.Items) != 0 || !directory.Capabilities[0].Available {
			t.Fatal("program key directory differs")
		}
		account.intent = iamv1.CreateAccessKeyRequest{UserResourceVersion: directory.UserResourceVersion, RequestID: prefix + "-create"}
		call(endpoint, http.MethodPost, account.path, account.manager, account.intent, http.StatusCreated, &account.key)
		if iamv1.ValidateCreateAccessKeyResponse(account.key) != nil || account.key.Key.UserID != target.ID {
			t.Fatal("program key creation differs")
		}
		secret := account.key.Secret.CopyBytes()
		sensitive = append(sensitive, string(secret))
		clear(secret)
		var replay iamv1.CreateAccessKeyResponse
		call(replica, http.MethodPost, account.path, account.manager, account.intent, http.StatusOK, &replay)
		if replay.Secret.Present() || replay.Key != account.key.Key || replay.Outcome != "EQUAL_REPLAY" {
			t.Fatal("replica repeated one-time secret")
		}
	}
	a, b := &accounts[0], &accounts[1]
	if a.target.AccountID == b.target.AccountID || a.target.LoginName != b.target.LoginName {
		t.Fatal("two-realm program fixture is invalid")
	}
	call(endpoint, http.MethodGet, b.path+"/"+string(b.key.Key.ID), a.manager, nil, http.StatusForbidden, nil)
	call(replica, http.MethodGet, a.path+"/"+string(a.key.Key.ID), b.manager, nil, http.StatusForbidden, nil)
	call(endpoint, http.MethodPost, b.path, a.manager, b.intent, http.StatusForbidden, nil)
	call(replica, http.MethodGet, a.path+"?accountId="+string(b.target.AccountID), a.manager, nil, http.StatusBadRequest, nil)
	secret := a.key.Secret.CopyBytes()
	call(endpoint, http.MethodGet, a.path, string(secret), nil, http.StatusUnauthorized, nil)
	call(endpoint, http.MethodGet, "/v1/account/security-settings", string(secret), nil, http.StatusUnauthorized, nil)
	call(endpoint, http.MethodGet, "/v1/users/"+string(a.target.ID)+"/password-resets/key-cannot-query?resourceVersion=1", string(secret), nil, http.StatusUnauthorized, nil)
	clear(secret)
	// Exercise the actual internal RPC in both IAM executables, without
	// pretending a fixture is a product PEP or enabling a source Profile.
	sign := func(account *accountFixture, requestID string) iamv1.AccessKeyAuthorizationRequest {
		t.Helper()
		request, err := iamv1.NewAuthorizationRequest(iamv1.ActionPaaSApplicationRead,
			iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "program-signed-application"}, iamv1.AuthorizationResourceInstance, "", requestID, requestID)
		if err != nil {
			t.Fatal(err)
		}
		var now time.Time
		if err := database.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&now); err != nil {
			t.Fatal(err)
		}
		nonce := make([]byte, 16)
		if _, err := rand.Read(nonce); err != nil {
			t.Fatal("generate process signature nonce")
		}
		bodyHash := sha256.Sum256(nil)
		signed := iamv1.AccessKeySignedRequest{Parameters: iamv1.AccessKeySignatureParameters{
			AccessKeyID: account.key.Key.ID, InstallationID: "installation-process", Audience: iamv1.ProductPaaS, SignedAt: now.Unix(),
			Nonce: processSecret(t, base64.RawURLEncoding.EncodeToString(nonce))},
			HTTP: iamv1.AccessKeyHTTPRequest{Method: http.MethodGet, Scheme: "https", Authority: "program-process.invalid:443",
				EscapedPath: "/api/paas/v1/applications/program-signed-application", BodyDigest: "sha256:" + hex.EncodeToString(bodyHash[:])}}
		canonical, err := iamv1.AccessKeySigningBytes(signed.Parameters, signed.HTTP)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(canonical)
		secret := account.key.Secret.CopyBytes()
		defer clear(secret)
		material, err := base64.RawURLEncoding.DecodeString(string(bytes.TrimPrefix(secret, []byte("mak1."))))
		if err != nil || len(material) != 32 {
			t.Fatal("decode process signature material")
		}
		defer clear(material)
		mac := hmac.New(sha256.New, material)
		_, _ = mac.Write(canonical)
		signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
		signed.Signature = processSecret(t, signature)
		sensitive = append(sensitive, base64.RawURLEncoding.EncodeToString(nonce), signature)
		return iamv1.AccessKeyAuthorizationRequest{Authorization: request, SignedRequest: signed}
	}
	encode := func(request iamv1.AccessKeyAuthorizationRequest) []byte {
		t.Helper()
		body, err := iamv1.EncodeAccessKeyAuthorizationRequest(request)
		if err != nil {
			t.Fatal("encode process signing request")
		}
		t.Cleanup(func() { clear(body) })
		return body
	}
	counts := func(key iamv1.AccessKeyID) [3]int {
		t.Helper()
		var values [3]int
		if err := database.QueryRow(ctx, `SELECT
		 (SELECT count(*) FROM iam.access_key_authorization_evidence WHERE access_key_id=$1),
		 (SELECT count(*) FROM iam.authorization_decisions WHERE access_key_id=$1),
		 (SELECT count(*) FROM iam.audit_outbox WHERE event_document#>>'{actor,accessKeyId}'=$1)`, key).Scan(&values[0], &values[1], &values[2]); err != nil {
			t.Fatal("read signed process completion", err)
		}
		return values
	}
	denied := map[iamv1.AccessKeyID]map[iamv1.DecisionID]bool{}
	checkDeny := func(request iamv1.AccessKeyAuthorizationRequest, response processResponse) {
		t.Helper()
		result, err := iamv1.DecodeAccessKeyAuthorization(bytes.NewReader(response.Body))
		if response.Status != http.StatusOK || err != nil || iamv1.CheckAccessKeyAuthorizationForRequest(result, request) != nil ||
			result.Decision.Allowed || result.Decision.Subject != nil || result.Decision.TenantID != "" {
			t.Fatalf("signed process did not return exact sanitized Deny: status=%d", response.Status)
		}
		key := request.SignedRequest.Parameters.AccessKeyID
		if denied[key] == nil {
			denied[key] = map[iamv1.DecisionID]bool{}
		}
		if denied[key][result.Decision.ID] {
			t.Fatal("duplicate signed process decision")
		}
		denied[key][result.Decision.ID] = true
		for _, value := range sensitive {
			if bytes.Contains(response.Body, []byte(value)) {
				t.Fatal("signed process response disclosed private material")
			}
		}
	}
	invoke := func(server string, request iamv1.AccessKeyAuthorizationRequest, status int) processResponse {
		t.Helper()
		response := performJSON(t, http.MethodPost, server+"/v1/authorize:access-key", paasServiceCredential, json.RawMessage(encode(request)))
		if response.Status != status {
			t.Fatalf("signed process status=%d want=%d", response.Status, status)
		}
		if status == http.StatusOK {
			checkDeny(request, response)
		}
		return response
	}
	var restartReplay iamv1.AccessKeyAuthorizationRequest
	for index := range accounts {
		account := &accounts[index]
		prefix := fmt.Sprintf("program-signature-%d", index)
		createIAMPolicyAttachment(t, endpoint, account.owner, account.target.ID, iamv1.SystemPolicyPaaSDeveloper, prefix+"-grant")
		request := sign(account, prefix+"-deny")
		loginRequest := request.Authorization
		loginRequest.RequestID, loginRequest.CorrelationID = prefix+"-login", prefix+"-login"
		loginResponse := performJSONWithHeaders(t, http.MethodPost, endpoint+"/v1/authorize", paasServiceCredential, "", loginRequest,
			map[string]string{"Matrix-Subject-Credential": account.targetBearer})
		var loginDecision iamv1.AuthorizationDecision
		if loginResponse.Status != http.StatusOK || iamv1.DecodeRequest(bytes.NewReader(loginResponse.Body), &loginDecision) != nil ||
			iamv1.CheckAuthorizationDecisionForRequest(loginDecision, loginRequest) != nil || !loginDecision.Allowed ||
			loginDecision.Subject == nil || loginDecision.Subject.AccessKeyID != "" {
			t.Fatal("signature fixture must have a real login-authorized positive control")
		}
		before := counts(account.key.Key.ID)
		wrongMAC := request
		wrongMAC.SignedRequest.Signature = processSecret(t, base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
		invoke(endpoint, wrongMAC, http.StatusUnauthorized)
		for _, caller := range []string{account.targetBearer, auditServiceCredential, verifierCredential} {
			response := performJSON(t, http.MethodPost, replica+"/v1/authorize:access-key", caller, json.RawMessage(encode(request)))
			if response.Status != http.StatusUnauthorized {
				t.Fatal("invalid product service reached signed authorization")
			}
		}
		if counts(account.key.Key.ID) != before {
			t.Fatal("bad signature/service allocated signed authority")
		}
		invoke(endpoint, request, http.StatusOK)
		invoke(replica, request, http.StatusConflict)
		if index == 0 {
			restartReplay = request
		}
	}
	// A common nonce competes across two actual executables and runtime logins.
	concurrent := sign(b, "program-signed-race")
	raceBody := encode(concurrent)
	type wireResult struct {
		response processResponse
		err      error
	}
	send := func(server string, body []byte) wireResult {
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, server+"/v1/authorize:access-key", bytes.NewReader(body))
		if err != nil {
			return wireResult{err: err}
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Authorization", "Bearer "+paasServiceCredential)
		response, err := processHTTPClient().Do(request)
		if err != nil {
			return wireResult{err: err}
		}
		defer response.Body.Close()
		encoded, err := io.ReadAll(io.LimitReader(response.Body, iamv1.MaxRequestBytes+1))
		return wireResult{response: processResponse{Status: response.StatusCode, Body: encoded}, err: err}
	}
	started := make(chan struct{})
	responses := make(chan wireResult, 2)
	for _, server := range []string{endpoint, replica} {
		go func() { <-started; responses <- send(server, raceBody) }()
	}
	close(started)
	statuses := map[int]int{}
	for range 2 {
		response := <-responses
		if response.err != nil {
			t.Fatal("signed replica race transport failed")
		}
		statuses[response.response.Status]++
		if response.response.Status == http.StatusOK {
			checkDeny(concurrent, response.response)
		}
	}
	if statuses[http.StatusOK] != 1 || statuses[http.StatusConflict] != 1 {
		t.Fatal("signed nonce was not consumed once across executables")
	}
	// Drop a real RPC reply after IAM has committed. A retry on the other
	// executable must reject, not return the old decision as a reusable permit.
	unknown := sign(b, "program-signed-response-lost")
	unknownBody := encode(unknown)
	completed := make(chan wireResult, 1)
	var calls atomic.Int64
	lostReply := httptest.NewUnstartedServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) != 1 {
			panic(http.ErrAbortHandler)
		}
		completed <- send(endpoint, unknownBody)
		panic(http.ErrAbortHandler)
	}))
	lostReply.Config.ReadHeaderTimeout, lostReply.Config.WriteTimeout = 5*time.Second, 10*time.Second
	lostReply.Start()
	transport := &http.Transport{DisableKeepAlives: true, MaxConnsPerHost: 1}
	lostClient := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	lostRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, lostReply.URL, nil)
	if err != nil {
		t.Fatal("build unknown-result request")
	}
	lostResponse, lostErr := lostClient.Do(lostRequest)
	if lostResponse != nil {
		_ = lostResponse.Body.Close()
	}
	transport.CloseIdleConnections()
	lostReply.Close()
	if lostErr == nil || calls.Load() != 1 {
		t.Fatal("did not lose exactly one committed signing response")
	}
	select {
	case result := <-completed:
		if result.err != nil {
			t.Fatal("unknown result did not reach IAM")
		}
		checkDeny(unknown, result.response)
	default:
		t.Fatal("unknown result was not observed after real IAM completion")
	}
	invoke(replica, unknown, http.StatusConflict)
	deletedPacket := sign(b, "program-signed-deleted-material")
	waitAllIAMOutboxDelivered(t, ctx, database)
	withAuditOutage(func() {
		invoke(replica, sign(b, "program-signed-outage"), http.StatusOK)
		keyPath := b.path + "/" + string(b.key.Key.ID)
		for index, status := range []iamv1.AccessKeyStatus{iamv1.AccessKeyDisabled, iamv1.AccessKeyEnabled, iamv1.AccessKeyDisabled} {
			var changed iamv1.SetAccessKeyStatusResponse
			call(replica, http.MethodPost, keyPath+":set-status", b.manager, iamv1.SetAccessKeyStatusRequest{AccessKeyResourceVersion: uint64(index + 1), Status: status, RequestID: fmt.Sprintf("program-status-%d", index)}, http.StatusOK, &changed)
			if changed.Key.ResourceVersion != uint64(index+2) || changed.Key.Status != status {
				t.Fatal("program status CAS differs")
			}
		}
		call(endpoint, http.MethodPost, keyPath+":delete", b.manager, iamv1.DeleteAccessKeyRequest{AccessKeyResourceVersion: 4, RequestID: "program-delete"}, http.StatusOK, nil)
		invoke(endpoint, deletedPacket, http.StatusUnauthorized)
		for index := range 2 {
			intent := b.intent
			intent.RequestID = fmt.Sprintf("program-cascade-create-%d", index)
			var created iamv1.CreateAccessKeyResponse
			call(replica, http.MethodPost, b.path, b.manager, intent, http.StatusCreated, &created)
			secret := created.Secret.CopyBytes()
			sensitive = append(sensitive, string(secret))
			clear(secret)
		}
		var disabled iamv1.User
		userPath := "/v1/users/" + string(b.target.ID)
		call(endpoint, http.MethodPost, userPath+":set-status", b.owner, iamv1.SetUserStatusRequest{ResourceVersion: b.target.ResourceVersion, Status: iamv1.PrincipalDisabled, RequestID: "program-target-disable"}, http.StatusOK, &disabled)
		call(endpoint, http.MethodPost, userPath+":delete", b.owner, iamv1.DeleteUserRequest{ResourceVersion: disabled.ResourceVersion, RequestID: "program-target-delete"}, http.StatusOK, nil)
		revokeIAMPolicyAttachment(t, endpoint, b.owner, b.grant.ID, b.grant.ResourceVersion, "program-manager-revoke")
		call(replica, http.MethodPost, b.path, b.manager, b.intent, http.StatusForbidden, nil)
		waitIAMOutboxRetry(t, ctx, database)
	})
	waitAllIAMOutboxDelivered(t, ctx, database)
	for action, count := range map[auditv1.Action]int{auditv1.ActionIAMAccessKeyCreated: 3, auditv1.ActionIAMAccessKeyDisabled: 2, auditv1.ActionIAMAccessKeyEnabled: 1, auditv1.ActionIAMAccessKeyDeleted: 3} {
		page := queryAudit(t, auditEndpoint, b.owner, auditv1.QueryRecordsRequest{PageSize: 100, Action: action}, http.StatusOK)
		if len(page.Records) != count || page.TenantID != auditv1.TenantID(b.target.AccountID) {
			t.Fatalf("AccessKey historical delivery action=%s count=%d want=%d", action, len(page.Records), count)
		}
		for _, record := range page.Records {
			if record.Event.IAMDecisionID == "" || record.Event.Actor.Type != auditv1.ActorUser || record.Event.Target.Kind != auditv1.TargetAccessKey || record.Event.TenantID != page.TenantID {
				t.Fatal("program fact lost actual decision/tenant/USER")
			}
			encoded, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			for _, secret := range sensitive {
				if bytes.Contains(encoded, []byte(secret)) {
					t.Fatal("program audit leaked material")
				}
			}
		}
	}
	page := queryAudit(t, auditEndpoint, b.owner, auditv1.QueryRecordsRequest{PageSize: 1, Action: auditv1.ActionIAMAccessKeyCreated}, http.StatusOK)
	if page.NextCursor == "" {
		t.Fatal("program audit cursor fixture is empty")
	}
	queryAudit(t, auditEndpoint, a.owner, auditv1.QueryRecordsRequest{PageSize: 1, Action: auditv1.ActionIAMAccessKeyCreated, Cursor: page.NextCursor}, http.StatusUnprocessableEntity)
	if chain := verifyAudit(t, auditEndpoint, b.owner); !chain.Complete || chain.State != auditv1.VerificationVerified {
		t.Fatal("program history chain failed")
	}
	var remaining int
	if err := database.QueryRow(ctx, `SELECT count(*) FROM iam.access_keys WHERE tenant_id=$1 AND user_id=$2 AND (deleted_at IS NULL OR ciphertext IS NOT NULL)`, b.target.AccountID, b.target.ID).Scan(&remaining); err != nil || remaining != 0 {
		t.Fatal("user deletion retained usable program material", err)
	}
	restartIAM()
	invoke(endpoint, restartReplay, http.StatusConflict)
	invoke(endpoint, deletedPacket, http.StatusUnauthorized)
	invoke(endpoint, sign(a, "program-signed-after-restart"), http.StatusOK)
	waitAllIAMOutboxDelivered(t, ctx, database)
	for index := range accounts {
		account := &accounts[index]
		key := account.key.Key.ID
		want := len(denied[key])
		if counts(key) != [3]int{want, want, want} {
			t.Fatal("signed processes left partial/duplicate private evidence or facts")
		}
		actor := auditv1.ActorReference{Type: auditv1.ActorUser, ID: auditv1.ActorID(account.target.ID), AccessKeyID: string(key)}
		query := auditv1.QueryRecordsRequest{PageSize: 100, Action: auditv1.ActionIAMAuthorizationDecided, Actor: &actor}
		page := queryAudit(t, auditEndpoint, account.owner, query, http.StatusOK)
		if len(page.Records) != want || page.TenantID != auditv1.TenantID(account.target.AccountID) || want == 0 {
			t.Fatal("signed historical facts did not survive deletion/outage/restart")
		}
		for _, record := range page.Records {
			if record.Event.Actor != actor || !denied[key][iamv1.DecisionID(record.Event.IAMDecisionID)] {
				t.Fatal("signed Audit history lost original USER/key/decision attribution")
			}
			duplicate := performJSON(t, http.MethodPost, auditEndpoint+"/v1/events", iamServiceCredential, record.Event)
			var retained auditv1.IngestionResult
			if duplicate.Status != http.StatusOK || iamv1.DecodeRequest(bytes.NewReader(duplicate.Body), &retained) != nil ||
				auditv1.ValidateIngestionResult(retained) != nil || retained.Outcome != auditv1.IngestionDuplicate || retained.Record.RecordHash != record.RecordHash {
				t.Fatal("signed historical replay did not preserve the original hash")
			}
		}
		other := &accounts[1-index]
		if len(queryAudit(t, auditEndpoint, other.owner, query, http.StatusOK).Records) != 0 {
			t.Fatal("another account read key-attributed Audit facts")
		}
		forged := page.Records[0].Event
		forged.Actor.AccessKeyID = string(other.key.Key.ID)
		if response := performJSON(t, http.MethodPost, auditEndpoint+"/v1/events", iamServiceCredential, forged); response.Status != http.StatusForbidden {
			t.Fatal("historical producer accepted another key's attribution")
		}
		if chain := verifyAudit(t, auditEndpoint, account.owner); !chain.Complete || chain.State != auditv1.VerificationVerified {
			t.Fatal("signed facts broke the mixed tenant Audit chain")
		}
	}
	var replay iamv1.CreateAccessKeyResponse
	call(endpoint, http.MethodPost, a.path, a.manager, a.intent, http.StatusOK, &replay)
	if replay.Secret.Present() || replay.Key != a.key.Key || replay.Outcome != "EQUAL_REPLAY" {
		t.Fatal("restart repeated one-time program secret")
	}
	return sensitive
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
	proveAccountSecuritySettingsProcesses(t, ctx, admin, endpoint, replicaEndpoint, auditEndpoint, bearer, primary.Credential, childLogin, restartIAM)
	sensitive := append(resourceSecrets, initial, changed, primary.Credential, childLogin.Credential)
	sensitive = append(sensitive, proveGroupResourceProcesses(t, ctx, admin, endpoint, replicaEndpoint, auditEndpoint, paasEndpoint, bearer, primary.Credential, withAuditOutage, restartIAM)...)
	roleOperator := loginIAM(t, endpoint, "customer.primary", changed, "process-role-operator-login")
	sensitive = append(sensitive, roleOperator.Credential)
	sensitive = append(sensitive, proveRoleManagementProcesses(t, ctx, admin, endpoint, replicaEndpoint, auditEndpoint, paasEndpoint, bearer, primary.Credential, roleOperator.Credential, withAuditOutage, restartIAM)...)
	sensitive = append(sensitive, proveAccessKeyProcesses(t, ctx, admin, endpoint, replicaEndpoint, auditEndpoint, bearer, primary.Credential, withAuditOutage, restartIAM)...)
	sensitive = append(sensitive, proveOwnSessionProcesses(t, ctx, admin, endpoint, replicaEndpoint, auditEndpoint, paasEndpoint, bearer, primary.Credential, withAuditOutage, restartIAM)...)
	sensitive = append(sensitive, proveOtherSessionProcesses(t, ctx, admin, endpoint, replicaEndpoint, auditEndpoint, paasEndpoint, primary.Credential, withAuditOutage, restartIAM)...)
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
	// Recovery must not let a forced-change session restore the just-retired
	// credential, even through another real IAM process after a restart.
	recoverySecurityState := func() string {
		t.Helper()
		var state string
		if err := admin.QueryRow(ctx, `SELECT jsonb_build_object(
		 'principal',to_jsonb(p),'credential',to_jsonb(c),
		 'sessions',(SELECT jsonb_agg(to_jsonb(s) ORDER BY s.id) FROM iam.sessions s WHERE s.tenant_id=p.tenant_id AND s.principal_id=p.id),
		 'facts',(SELECT jsonb_agg(e.event_document ORDER BY e.event_id) FROM iam.audit_outbox e
		   WHERE e.tenant_id=p.tenant_id AND e.event_document->>'action'='iam.user.password-changed' AND e.event_document#>>'{target,id}'=p.id))::text
		 FROM iam.principals p JOIN iam.user_credentials c ON c.tenant_id=p.tenant_id AND c.principal_id=p.id
		 WHERE p.tenant_id=$1 AND p.id=$2`, crossTenantID, account.RootIdentity.PrincipalID).Scan(&state); err != nil {
			t.Fatal("read original-root credential invariants")
		}
		return state // The private comparison value is never logged.
	}
	beforeRejectedReuse := recoverySecurityState()
	reused := performJSON(t, http.MethodPost, replicaEndpoint+"/v1/auth/password", primary.Credential, map[string]any{
		"currentPassword": recoveryPassword, "newPassword": changed, "requestId": "request-recovered-primary-history-rejected"})
	if reused.Status != http.StatusUnprocessableEntity || recoverySecurityState() != beforeRejectedReuse {
		t.Fatal("recovered primary reused its retired password or changed credential/session/facts")
	}
	const replacementPassword = "Customer-Process-Post-Recovery-Password-79!"
	sensitive = append(sensitive, replacementPassword)
	changePasswordIAM(t, endpoint, primary.Credential, recoveryPassword, replacementPassword, "request-recovered-primary-password")
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
	creatorDeletions := 0
	for _, record := range deletionRecords.Records {
		if record.Event.TenantID != crossTenantID {
			t.Fatal("user deletion query crossed tenant scope")
		}
		if record.Event.Target.ID == string(child.ID) {
			creatorDeletions++
		}
	}
	if deletionRecords.TenantID != crossTenantID || deletionRecords.NextCursor != "" || creatorDeletions != 1 {
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

// This gate runs the actual IAM replicas, PaaS and Audit executables. Only the
// contact-code transport is a synthetic custody fixture; real SMTP/Maildir
// delivery remains the existing notification integration gate's evidence.
func proveTOTPProcesses(t *testing.T, ctx context.Context, admin *pgx.Conn, endpoint, replica, auditEndpoint, paasEndpoint, root string,
	restartIAM func(), withDispatcherStopped func(func())) []string {
	t.Helper()
	const initial, password = "Process-MFA-Initial-Password-63!", "Process-MFA-Changed-Password-84!"
	const reset, final = "Process-MFA-Reset-Password-76!", "Process-MFA-Final-Password-97!"
	sensitive := []string{initial, password, reset, final}
	secret := func(value iamv1.Secret) string {
		material := value.CopyBytes()
		defer clear(material)
		sensitive = append(sensitive, string(material))
		return string(material)
	}
	call := func(at, method, path, bearer string, body any, want int, result any) processResponse {
		t.Helper()
		response := performJSON(t, method, at+path, bearer, body)
		if response.Status != want {
			t.Fatalf("MFA process %s %s status=%d want=%d", method, path, response.Status, want)
		}
		if result != nil && iamv1.DecodeRequest(bytes.NewReader(response.Body), result) != nil {
			t.Fatal("invalid MFA process response")
		}
		return response
	}
	user := createIAMUser(t, endpoint, root, "mfa.process", "Process MFA", initial, "process-mfa-user")
	for _, policy := range []iamv1.PolicyID{iamv1.SystemPolicyPaaSDeveloper, iamv1.SystemPolicyAuditReader} {
		createIAMPolicyAttachment(t, endpoint, root, user.ID, policy, "process-mfa-"+string(policy))
	}
	realm := "mfa.process@" + string(user.AccountID)
	first := loginIAM(t, endpoint, realm, initial, "process-mfa-initial-login")
	changePasswordIAM(t, endpoint, first.Credential, initial, password, "process-mfa-initial-change")
	other := loginIAM(t, replica, realm, password, "process-mfa-other-login")
	sensitive = append(sensitive, first.Credential, other.Credential)
	var state iamv1.AuthenticatorState
	call(endpoint, http.MethodGet, "/v1/auth/authenticators", first.Credential, nil, http.StatusOK, &state)
	if state.EnrollmentState != "NEVER_BOUND" || state.FactorRevision != 1 {
		t.Fatal("new process USER lacks its proven unbound state")
	}
	enrollRequest := map[string]any{"requestId": "process-mfa-enroll", "password": password, "expectedFactorRevision": state.FactorRevision}
	const passwordBudget = `SELECT to_jsonb(a)::text FROM iam.password_attempts a WHERE tenant_id=$1 AND principal_id=$2`
	var beforeContact, afterContact string
	if err := admin.QueryRow(ctx, passwordBudget, user.AccountID, user.ID).Scan(&beforeContact); err != nil {
		t.Fatal("read original process password budget")
	}
	call(replica, http.MethodPost, "/v1/auth/totp/enrollments", first.Credential, enrollRequest, http.StatusForbidden, nil)
	if err := admin.QueryRow(ctx, passwordBudget, user.AccountID, user.ID).Scan(&afterContact); err != nil || afterContact != beforeContact {
		t.Fatal("missing contact changed or stranded the password attempt")
	}
	call(endpoint, http.MethodGet, "/v1/auth/me", first.Credential, nil, http.StatusOK, nil)
	var verification iamv1.NotificationContactVerification
	call(endpoint, http.MethodPost, "/v1/auth/notification-contact/verifications", first.Credential,
		map[string]string{"email": "receiver@matrix.test", "password": password, "requestId": "process-mfa-contact"}, http.StatusOK, &verification)
	code := readProcessContactCode(t, ctx, admin, verification)
	sensitive = append(sensitive, code)
	call(replica, http.MethodPost, "/v1/auth/notification-contact/verifications/"+verification.ID+":confirm", first.Credential,
		map[string]string{"requestId": "process-mfa-contact-confirm", "code": code}, http.StatusOK, nil)
	var started iamv1.StartTOTPEnrollmentResponse
	call(endpoint, http.MethodPost, "/v1/auth/totp/enrollments", first.Credential, enrollRequest, http.StatusOK, &started)
	if started.Outcome != "APPLIED" || started.Provisioning == nil || started.Enrollment.State != "PENDING" {
		t.Fatal("process enrollment did not issue its one-time provisioning")
	}
	seed := secret(started.Provisioning.Seed)
	secret(started.Provisioning.URI)
	factor := started.Enrollment.ID
	var replay iamv1.StartTOTPEnrollmentResponse
	call(replica, http.MethodPost, "/v1/auth/totp/enrollments", first.Credential, enrollRequest, http.StatusOK, &replay)
	if replay.Outcome != "EQUAL_REPLAY" || replay.Provisioning != nil || replay.Enrollment != started.Enrollment {
		t.Fatal("replica enrollment replay changed the original or reissued a secret")
	}
	nextCode := func(previous int64, initialBinding bool) (string, int64) {
		t.Helper()
		candidate, step := processTOTPCode(t, ctx, admin, seed, previous, initialBinding)
		sensitive = append(sensitive, candidate)
		return candidate, step
	}
	challenge := func(at, pass, request string) iamv1.LoginResponse {
		t.Helper()
		var result iamv1.LoginResponse
		response := call(at, http.MethodPost, "/v1/auth/login", "", map[string]string{"loginName": realm, "password": pass, "requestId": request}, http.StatusOK, &result)
		if iamv1.ValidateLoginResponse(result) != nil || result.Outcome != iamv1.LoginChallengeRequired || result.Challenge.NextStep != "TOTP" ||
			bytes.Contains(response.Body, []byte(`"session"`)) || bytes.Contains(response.Body, []byte(`"mustChangePassword"`)) {
			t.Fatal("bound password issued or implied a login Session")
		}
		secret(result.ChallengeCredential)
		return result
	}
	verifyRequest := func(value iamv1.LoginResponse, code, request string) map[string]string {
		return map[string]string{"requestId": request, "challengeCredential": secret(value.ChallengeCredential), "code": code}
	}
	var boundEvent auditv1.Event
	withDispatcherStopped(func() {
		confirmation, _ := nextCode(-1, true)
		intent := map[string]string{"requestId": "process-mfa-confirm", "code": confirmation}
		lost := loseIAMCompletion(t, ctx, http.MethodPost, endpoint, "/v1/auth/totp/enrollments/"+factor+":confirm", first.Credential, intent)
		var confirmed iamv1.ConfirmTOTPEnrollmentResponse
		if iamv1.DecodeRequest(bytes.NewReader(lost.Body), &confirmed) != nil || confirmed.NextStep != "REAUTHENTICATE" || confirmed.Enrollment.State != "CONFIRMED" || len(confirmed.RecoveryCodes) != 10 {
			t.Fatal("lost reply did not follow an actual MFA binding completion")
		}
		for _, recovery := range confirmed.RecoveryCodes {
			secret(recovery)
		}
		clear(lost.Body)
		var step int64
		if err := admin.QueryRow(ctx, "SELECT last_consumed_step FROM iam.totp_authenticators WHERE tenant_id=$1 AND id=$2", user.AccountID, factor).Scan(&step); err != nil {
			t.Fatal("read committed factor consumption")
		}
		for _, bearer := range []string{first.Credential, other.Credential} {
			call(replica, http.MethodGet, "/v1/auth/me", bearer, nil, http.StatusUnauthorized, nil)
			getPaaSApplication(t, paasEndpoint, bearer, "application-process", http.StatusUnauthorized)
			queryAudit(t, auditEndpoint, bearer, auditv1.QueryRecordsRequest{PageSize: 1}, http.StatusUnauthorized)
		}
		call(replica, http.MethodPost, "/v1/auth/totp/enrollments/"+factor+":confirm", first.Credential, intent, http.StatusUnauthorized, nil)
		a, b := challenge(endpoint, password, "process-mfa-login-a"), challenge(replica, password, "process-mfa-login-b")
		for _, at := range []string{endpoint, replica} {
			call(at, http.MethodGet, "/v1/auth/me", secret(a.ChallengeCredential), nil, http.StatusUnauthorized, nil)
			call(at, http.MethodGet, "/v1/auth/sessions", secret(a.ChallengeCredential), nil, http.StatusUnauthorized, nil)
		}
		getPaaSApplication(t, paasEndpoint, secret(a.ChallengeCredential), "application-process", http.StatusUnauthorized)
		queryAudit(t, auditEndpoint, secret(a.ChallengeCredential), auditv1.QueryRecordsRequest{PageSize: 1}, http.StatusUnauthorized)
		candidate, _ := nextCode(step, false)
		var responses [2]processResponse
		requests := []map[string]string{verifyRequest(a, candidate, "process-mfa-race-a"), verifyRequest(b, candidate, "process-mfa-race-b")}
		var workers sync.WaitGroup
		for i, entry := range []struct {
			at    string
			value iamv1.LoginResponse
		}{{endpoint, a}, {replica, b}} {
			workers.Add(1)
			go func() {
				defer workers.Done()
				responses[i] = performJSON(t, http.MethodPost, entry.at+"/v1/auth/challenges/"+entry.value.Challenge.ID+":verify", "", requests[i])
			}()
		}
		workers.Wait()
		var authenticated iamv1.LoginResponse
		success, rejected := 0, 0
		for _, response := range responses {
			if response.Status == http.StatusOK {
				success++
				if iamv1.DecodeRequest(bytes.NewReader(response.Body), &authenticated) != nil || iamv1.ValidateLoginResponse(authenticated) != nil || authenticated.Outcome != iamv1.LoginAuthenticated {
					t.Fatal("invalid MFA process Session")
				}
			} else if response.Status == http.StatusUnauthorized {
				rejected++
			}
		}
		if success != 1 || rejected != 1 {
			t.Fatalf("cross-process OTP success=%d rejection=%d", success, rejected)
		}
		bearer := secret(authenticated.Credential)
		var actual bool
		if err := admin.QueryRow(ctx, `SELECT authentication_method='PASSWORD_TOTP' AND authenticated_at IS NOT NULL AND mfa_revision=2
			FROM iam.sessions WHERE tenant_id=$1 AND id=$2`, user.AccountID, authenticated.Session.ID).Scan(&actual); err != nil || !actual {
			t.Fatal("Session lacks actual MFA ceremony")
		}
		call(replica, http.MethodGet, "/v1/auth/me", bearer, nil, http.StatusOK, nil)
		getPaaSApplication(t, paasEndpoint, bearer, "application-process", http.StatusOK)
		queryAudit(t, auditEndpoint, bearer, auditv1.QueryRecordsRequest{PageSize: 1}, http.StatusOK)
		restartIAM()
		call(endpoint, http.MethodGet, "/v1/auth/me", bearer, nil, http.StatusOK, nil)
		var retained iamv1.TOTPEnrollment
		call(replica, http.MethodGet, "/v1/auth/totp/enrollments/by-request/process-mfa-enroll", bearer, nil, http.StatusOK, &retained)
		if !reflect.DeepEqual(retained, confirmed.Enrollment) {
			t.Fatal("restart changed the original binding completion")
		}
		// Reset cannot remove the factor or turn the limited password phase
		// into a Session. The real password completion also loses its TCP reply.
		var access iamv1.UserAccess
		call(endpoint, http.MethodGet, "/v1/users/"+string(user.ID), root, nil, http.StatusOK, &access)
		resetIntent := map[string]any{"initialPassword": reset, "resourceVersion": access.User.ResourceVersion, "requestId": "process-mfa-reset"}
		resetResult := loseIAMCompletion(t, ctx, http.MethodPost, endpoint, "/v1/users/"+string(user.ID)+":reset-password", root, resetIntent)
		clear(resetResult.Body)
		resetCompletionPath := fmt.Sprintf("/v1/users/%s/password-resets/process-mfa-reset?resourceVersion=%d", user.ID, access.User.ResourceVersion)
		var resetCompletion iamv1.UserPasswordResetCompletion
		call(replica, http.MethodGet, resetCompletionPath, root, nil, http.StatusOK, &resetCompletion)
		if iamv1.ValidateUserPasswordResetCompletion(resetCompletion) != nil || resetCompletion.UserID != user.ID ||
			resetCompletion.AccountID != user.AccountID || resetCompletion.RequestID != "process-mfa-reset" ||
			resetCompletion.ExpectedResourceVersion != access.User.ResourceVersion {
			t.Fatal("lost reset reply was not confirmed by exact historical metadata on the peer")
		}
		_, resetFact := findIAMEvent(t, ctx, admin, auditv1.ActionIAMUserPasswordReset, string(user.ID))
		if string(resetFact.EventID) != resetCompletion.EventID || resetFact.Actor.ID != auditv1.ActorID(resetCompletion.ActorPrincipalID) ||
			!resetFact.OccurredAt.Equal(resetCompletion.OccurredAt) || resetFact.RequestID != resetCompletion.RequestID {
			t.Fatal("reset completion does not bind its original outbox fact")
		}
		call(replica, http.MethodGet, "/v1/auth/me", bearer, nil, http.StatusUnauthorized, nil)
		// Neither the consumed winner nor the unfinished losing challenge can
		// survive reset. These rejections must precede any new OTP reservation.
		call(endpoint, http.MethodPost, "/v1/auth/challenges/"+a.Challenge.ID+":verify", "", requests[0], http.StatusUnauthorized, nil)
		call(replica, http.MethodPost, "/v1/auth/challenges/"+b.Challenge.ID+":verify", "", requests[1], http.StatusUnauthorized, nil)
		forced := challenge(replica, reset, "process-mfa-forced-login")
		if err := admin.QueryRow(ctx, "SELECT last_consumed_step FROM iam.totp_authenticators WHERE tenant_id=$1 AND id=$2", user.AccountID, factor).Scan(&step); err != nil {
			t.Fatal("read forced process OTP consumption")
		}
		fresh, _ := nextCode(step, false)
		var passwordPhase iamv1.LoginResponse
		call(endpoint, http.MethodPost, "/v1/auth/challenges/"+forced.Challenge.ID+":verify", "", verifyRequest(forced, fresh, "process-mfa-forced-verify"), http.StatusOK, &passwordPhase)
		if iamv1.ValidateLoginResponse(passwordPhase) != nil || passwordPhase.Outcome != iamv1.LoginChallengeRequired || passwordPhase.Challenge.NextStep != "PASSWORD_CHANGE" ||
			passwordPhase.Challenge.ID == forced.Challenge.ID || !passwordPhase.Challenge.ExpiresAt.Equal(forced.Challenge.ExpiresAt) {
			t.Fatal("forced change lacks its distinct bounded challenge")
		}
		passwordIntent := map[string]string{"requestId": "process-mfa-forced-password", "challengeCredential": secret(passwordPhase.ChallengeCredential), "newPassword": final}
		result := loseIAMCompletion(t, ctx, http.MethodPost, replica, "/v1/auth/challenges/"+passwordPhase.Challenge.ID+":password", "", passwordIntent)
		var changed iamv1.ChallengePasswordChangeResponse
		if iamv1.DecodeRequest(bytes.NewReader(result.Body), &changed) != nil || changed.NextStep != "REAUTHENTICATE" {
			t.Fatal("lost password completion did not require normal reauthentication")
		}
		clear(result.Body)
		restartIAM()
		var afterResetRestart iamv1.UserPasswordResetCompletion
		call(endpoint, http.MethodGet, resetCompletionPath, root, nil, http.StatusOK, &afterResetRestart)
		if afterResetRestart != resetCompletion {
			t.Fatal("restart or later forced password change rewrote original reset completion")
		}
		call(endpoint, http.MethodPost, "/v1/auth/challenges/"+passwordPhase.Challenge.ID+":password", "", passwordIntent, http.StatusUnauthorized, nil)
		call(replica, http.MethodPost, "/v1/auth/login", "", map[string]string{"loginName": realm, "password": reset, "requestId": "process-mfa-old-password"}, http.StatusUnauthorized, nil)
		newChallenge := challenge(endpoint, final, "process-mfa-final-login")
		if err := admin.QueryRow(ctx, "SELECT last_consumed_step FROM iam.totp_authenticators WHERE tenant_id=$1 AND id=$2", user.AccountID, factor).Scan(&step); err != nil {
			t.Fatal("read final process OTP consumption")
		}
		fresh, _ = nextCode(step, false)
		call(replica, http.MethodPost, "/v1/auth/challenges/"+newChallenge.Challenge.ID+":verify", "", verifyRequest(newChallenge, fresh, "process-mfa-final-verify"), http.StatusOK, &authenticated)
		if iamv1.ValidateLoginResponse(authenticated) != nil || authenticated.Outcome != iamv1.LoginAuthenticated {
			t.Fatal("new password and fresh factor did not authenticate")
		}
		bearer = secret(authenticated.Credential)
		getPaaSApplication(t, paasEndpoint, bearer, "application-process", http.StatusOK)
		call(endpoint, http.MethodGet, "/v1/users/"+string(user.ID), root, nil, http.StatusOK, &access)
		call(endpoint, http.MethodPost, "/v1/users/"+string(user.ID)+":set-status", root,
			iamv1.SetUserStatusRequest{Status: iamv1.PrincipalDisabled, ResourceVersion: access.User.ResourceVersion, RequestID: "process-mfa-disable"}, http.StatusOK, nil)
		call(replica, http.MethodGet, "/v1/auth/me", bearer, nil, http.StatusUnauthorized, nil)
		getPaaSApplication(t, paasEndpoint, bearer, "application-process", http.StatusUnauthorized)
		queryAudit(t, auditEndpoint, bearer, auditv1.QueryRecordsRequest{PageSize: 1}, http.StatusUnauthorized)
		call(replica, http.MethodGet, resetCompletionPath, root, nil, http.StatusOK, &afterResetRestart)
		if afterResetRestart != resetCompletion {
			t.Fatal("disabled target hid or rewrote original reset completion")
		}
		_, boundEvent = findIAMEvent(t, ctx, admin, auditv1.ActionIAMAuthenticatorBound, string(user.ID))
		assertAuditEventCount(t, ctx, admin, string(boundEvent.EventID), 0)
	})
	waitAllIAMOutboxDelivered(t, ctx, admin)
	page := queryAudit(t, auditEndpoint, root, auditv1.QueryRecordsRequest{PageSize: 100, Action: auditv1.ActionIAMAuthenticatorBound}, http.StatusOK)
	if len(page.Records) != 1 || page.Records[0].Event != boundEvent || page.Records[0].Source != auditv1.SourceIAM {
		t.Fatal("historical binding lost immutable USER attribution")
	}
	for i := 0; i < 2; i++ {
		response := performJSON(t, http.MethodPost, auditEndpoint+"/v1/events", iamServiceCredential, boundEvent)
		var replay auditv1.IngestionResult
		if response.Status != http.StatusOK || json.Unmarshal(response.Body, &replay) != nil || replay.Outcome != auditv1.IngestionDuplicate || replay.Record != page.Records[0] {
			t.Fatal("binding replay changed original Audit record")
		}
	}
	forged := boundEvent
	forged.RequestID = "process-mfa-forged-fact"
	call(auditEndpoint, http.MethodPost, "/v1/events", iamServiceCredential, forged, http.StatusForbidden, nil)
	if verification := verifyAudit(t, auditEndpoint, root); verification.State != auditv1.VerificationVerified || !verification.Complete {
		t.Fatal("MFA facts broke original tenant chain")
	}
	t.Log("actual IAM replicas/PaaS/Audit: binding, administrator reset and forced-password commits survived lost TCP replies/restart; exact reset completion remained after later change/disable; one cross-process OTP success; disabled USER history delivered once")
	sensitive = append(sensitive, proveTOTPRecoveryProcesses(t, ctx, admin, endpoint, replica, auditEndpoint, paasEndpoint, root, restartIAM, withDispatcherStopped)...)
	sensitive = append(sensitive, proveRecoveryCodeRegenerationProcesses(t, ctx, admin, endpoint, replica, auditEndpoint, root, restartIAM, withDispatcherStopped)...)
	for _, operation := range []iamv1.StepUpOperation{iamv1.StepUpReplaceTOTP, iamv1.StepUpRemoveTOTP} {
		sensitive = append(sensitive, proveTOTPFactorMutationProcesses(t, ctx, admin, endpoint, replica, auditEndpoint, paasEndpoint, root, restartIAM, withDispatcherStopped, operation)...)
	}
	return sensitive
}

// A new ordinary USER retains the real five-attempt budget: initial binding,
// login, old-factor proof, replacement/rebinding confirmation and new-factor
// login. The lost body is evidence only, never a source for client retry.
func proveTOTPFactorMutationProcesses(t *testing.T, ctx context.Context, admin *pgx.Conn, endpoint, replica, auditEndpoint, paasEndpoint, root string,
	restartIAM func(), withDispatcherStopped func(func()), operation iamv1.StepUpOperation) []string {
	t.Helper()
	const initial, password = "Replacement-Process-Initial-Password-53!", "Replacement-Process-Current-Password-91!"
	const confirmation = "process-totp-replace-confirm"
	name, command := "replacement", "process-totp-replace"
	if operation == iamv1.StepUpRemoveTOTP {
		name, command = "removal", "process-totp-remove"
	} else if operation != iamv1.StepUpReplaceTOTP {
		t.Fatal("unsupported process factor mutation")
	}
	sensitive := []string{initial, password}
	secret := func(value iamv1.Secret) string {
		material := value.CopyBytes()
		defer clear(material)
		sensitive = append(sensitive, string(material))
		return string(material)
	}
	call := func(at, method, path, bearer string, body any, want int, result any) processResponse {
		t.Helper()
		response := performJSON(t, method, at+path, bearer, body)
		if response.Status != want {
			t.Fatalf("%s process %s %s status=%d want=%d", name, method, path, response.Status, want)
		}
		if result != nil && iamv1.DecodeRequest(bytes.NewReader(response.Body), result) != nil {
			t.Fatal("invalid replacement process response")
		}
		return response
	}
	codeFor := func(seed string, previous int64, initialBinding bool) (string, int64) {
		t.Helper()
		code, step := processTOTPCode(t, ctx, admin, seed, previous, initialBinding)
		sensitive = append(sensitive, code)
		return code, step
	}
	user := createIAMUser(t, endpoint, root, name+".process", "Process factor "+name, initial, "process-"+name+"-user")
	for _, policy := range []iamv1.PolicyID{iamv1.SystemPolicyPaaSDeveloper, iamv1.SystemPolicyAuditReader} {
		createIAMPolicyAttachment(t, endpoint, root, user.ID, policy, "process-"+name+"-"+string(policy))
	}
	realm := user.LoginName + "@" + string(user.AccountID)
	first := loginIAM(t, endpoint, realm, initial, "process-replacement-first-login")
	sensitive = append(sensitive, first.Credential)
	changePasswordIAM(t, endpoint, first.Credential, initial, password, "process-replacement-password")
	var contact iamv1.NotificationContactVerification
	call(endpoint, http.MethodPost, "/v1/auth/notification-contact/verifications", first.Credential,
		map[string]string{"email": "receiver@matrix.test", "password": password, "requestId": "process-replacement-contact"}, http.StatusOK, &contact)
	contactCode := readProcessContactCode(t, ctx, admin, contact)
	sensitive = append(sensitive, contactCode)
	call(replica, http.MethodPost, "/v1/auth/notification-contact/verifications/"+contact.ID+":confirm", first.Credential,
		map[string]string{"requestId": "process-replacement-contact-confirm", "code": contactCode}, http.StatusOK, nil)
	var enrollment iamv1.StartTOTPEnrollmentResponse
	call(endpoint, http.MethodPost, "/v1/auth/totp/enrollments", first.Credential,
		map[string]any{"requestId": "process-replacement-enroll", "password": password, "expectedFactorRevision": 1}, http.StatusOK, &enrollment)
	if enrollment.Outcome != "APPLIED" || enrollment.Provisioning == nil || enrollment.Enrollment.Purpose != "INITIAL" {
		t.Fatal("replacement lacks an actual initial factor")
	}
	oldSeed, oldFactor := secret(enrollment.Provisioning.Seed), enrollment.Enrollment.ID
	secret(enrollment.Provisioning.URI)
	code, step := codeFor(oldSeed, -1, true)
	var bound iamv1.ConfirmTOTPEnrollmentResponse
	call(replica, http.MethodPost, "/v1/auth/totp/enrollments/"+oldFactor+":confirm", first.Credential,
		map[string]string{"requestId": "process-replacement-bind", "code": code}, http.StatusOK, &bound)
	if bound.NextStep != "REAUTHENTICATE" || len(bound.RecoveryCodes) != 10 {
		t.Fatal("replacement fixture did not establish its original saved-code batch")
	}
	for _, material := range bound.RecoveryCodes {
		secret(material)
	}
	login := func(seed string, previous int64, request string) (string, int64) {
		t.Helper()
		var challenge, authenticated iamv1.LoginResponse
		call(endpoint, http.MethodPost, "/v1/auth/login", "",
			map[string]string{"loginName": realm, "password": password, "requestId": request}, http.StatusOK, &challenge)
		if iamv1.ValidateLoginResponse(challenge) != nil || challenge.Outcome != iamv1.LoginChallengeRequired || challenge.Challenge.NextStep != "TOTP" {
			t.Fatal("replacement USER bypassed normal factor login")
		}
		code, step := codeFor(seed, previous, false)
		call(replica, http.MethodPost, "/v1/auth/challenges/"+challenge.Challenge.ID+":verify", "",
			map[string]string{"requestId": request + "-proof", "challengeCredential": secret(challenge.ChallengeCredential), "code": code}, http.StatusOK, &authenticated)
		if iamv1.ValidateLoginResponse(authenticated) != nil || authenticated.Outcome != iamv1.LoginAuthenticated {
			t.Fatal("replacement Session lacks a real password and factor ceremony")
		}
		return secret(authenticated.Credential), step
	}
	bearer, step := login(oldSeed, step, "process-replacement-login")
	getPaaSApplication(t, paasEndpoint, bearer, "application-process", http.StatusOK)
	queryAudit(t, auditEndpoint, bearer, auditv1.QueryRecordsRequest{PageSize: 1}, http.StatusOK)
	var roleBearer string
	if operation == iamv1.StepUpRemoveTOTP {
		// Earn an actual derived capability before the removal proof. A new
		// password login or factor binding must never revive this old source.
		var role iamv1.Role
		call(endpoint, http.MethodPost, "/v1/roles", root, iamv1.CreateRoleRequest{
			Name: "Removal source qualification", Tags: []iamv1.RoleTag{}, RequestID: "process-removal-role",
			TrustPolicy: iamv1.TrustPolicyDocument{LanguageVersion: "1", Statements: []iamv1.TrustPolicyStatement{{SID: "source", Effect: iamv1.PolicyAllow,
				Principals: []iamv1.TrustPrincipal{{Type: iamv1.PrincipalUser, ID: user.ID}}}}}}, http.StatusCreated, &role)
		rolePath := "/v1/roles/" + string(role.ID)
		call(endpoint, http.MethodPost, "/v1/policy-attachments", root, iamv1.CreatePolicyAttachmentRequest{
			Target: iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetRole, ID: string(role.ID)}, PolicyID: iamv1.SystemPolicyPaaSViewer,
			PolicyResourceVersion: 1, RequestID: "process-removal-role-permission"}, http.StatusOK, nil)
		var boundary iamv1.RolePermissionBoundary
		call(endpoint, http.MethodPut, rolePath+"/permission-boundary", root, iamv1.SetRolePermissionBoundaryRequest{
			PolicyID: iamv1.SystemPolicyPaaSViewer, PolicyResourceVersion: 1, ResourceVersion: role.ResourceVersion,
			RequestID: "process-removal-role-boundary"}, http.StatusOK, &boundary)
		var assumePolicy iamv1.PolicyDetail
		call(endpoint, http.MethodPost, "/v1/policies", root, iamv1.CreatePolicyRequest{
			DisplayName: "Assume removal source role", RequestID: "process-removal-assume-policy",
			Document: iamv1.PolicyDocument{LanguageVersion: iamv1.PolicyLanguageVersion, Scope: iamv1.AuthorityScopeTenant,
				Statements: []iamv1.PolicyStatement{{SID: "assume", Effect: iamv1.PolicyAllow, Actions: []iamv1.Action{iamv1.ActionIAMRoleAssume},
					Resources: []iamv1.PolicyResourceSelector{{Kind: iamv1.ResourceRole, Match: iamv1.PolicyResourceExact, ID: string(role.ID)}}}}}}, http.StatusCreated, &assumePolicy)
		createIAMPolicyAttachment(t, endpoint, root, user.ID, assumePolicy.Policy.ID, "process-removal-assume-grant")
		var assumed iamv1.AssumeRoleResponse
		call(replica, http.MethodPost, rolePath+":assume", bearer,
			iamv1.AssumeRoleRequest{ResourceVersion: boundary.ResourceVersion, RequestID: "process-removal-role-session"}, http.StatusOK, &assumed)
		if iamv1.ValidateAssumeRoleResponse(assumed) != nil || assumed.Outcome != "APPLIED" {
			t.Fatal("removal source RoleSession was not issued")
		}
		roleBearer = secret(assumed.Credential)
		getPaaSApplication(t, paasEndpoint, roleBearer, "application-process", http.StatusOK)
	}
	var proof iamv1.StepUp
	call(endpoint, http.MethodPost, "/v1/auth/step-up", bearer,
		iamv1.StartStepUpRequest{RequestID: command, Operation: operation, ExpectedFactorRevision: 2}, http.StatusOK, &proof)
	code, _ = codeFor(oldSeed, step, false)
	call(replica, http.MethodPost, "/v1/auth/step-up/"+proof.ID+":verify", bearer,
		map[string]string{"requestId": "process-replacement-prove", "password": password, "code": code}, http.StatusOK, &proof)
	if proof.State != "PROVED" {
		t.Fatal("replacement lacks a fresh old-factor operation proof")
	}
	if operation == iamv1.StepUpRemoveTOTP {
		intent := iamv1.RemoveTOTPRequest{RequestID: command, StepUpID: proof.ID, ExpectedFactorRevision: 2}
		path := "/v1/auth/totp/removals/by-request/" + command
		var removedEvent auditv1.Event
		withDispatcherStopped(func() {
			lost := loseIAMCompletion(t, ctx, http.MethodPost, replica, "/v1/auth/totp:remove", bearer, intent)
			var completed iamv1.RemoveTOTPResponse
			if iamv1.DecodeRequest(bytes.NewReader(lost.Body), &completed) != nil || iamv1.ValidateRemoveTOTPResponse(completed) != nil ||
				completed.Outcome != "APPLIED" || completed.NextStep != "REAUTHENTICATE" || completed.Removal.FactorID != oldFactor || completed.Removal.FactorRevision != 3 {
				t.Fatal("lost TCP reply did not follow one actual factor removal")
			}
			clear(lost.Body)
			var intact bool
			if err := admin.QueryRow(ctx, `SELECT
				(SELECT enrollment_state='REMOVED' AND revision=3 AND factor_id IS NULL AND removal_id=$3 FROM iam.user_mfa_states WHERE tenant_id=$1 AND user_id=$2)
				AND (SELECT count(*)=1 FROM iam.authenticator_removals WHERE tenant_id=$1 AND user_id=$2 AND id=$3 AND step_up_id=$4 AND factor_id=$5)
				AND (SELECT state='CONSUMED' FROM iam.step_ups WHERE tenant_id=$1 AND user_id=$2 AND id=$4)
				AND (SELECT state='REVOKED' FROM iam.totp_authenticators WHERE tenant_id=$1 AND id=$5)
				AND (SELECT count(*)=1 FROM iam.mfa_recovery_batches WHERE tenant_id=$1 AND user_id=$2 AND factor_id=$5 AND revoked_at IS NOT NULL AND revocation_removal_id=$3)
				AND NOT EXISTS(SELECT 1 FROM iam.sessions WHERE tenant_id=$1 AND principal_id=$2 AND revoked_at IS NULL)
				AND NOT EXISTS(SELECT 1 FROM iam.authentication_challenges WHERE tenant_id=$1 AND user_id=$2 AND state='PENDING')
				AND (SELECT count(*)=1 FROM iam.audit_outbox WHERE tenant_id=$1 AND event_document->>'action'='iam.authenticator.removed' AND event_document#>>'{actor,id}'=$2)
				AND (SELECT count(*)=1 FROM iam.security_notifications WHERE tenant_id=$1 AND user_id=$2 AND kind='AUTHENTICATOR_REMOVED')`,
				user.AccountID, user.ID, completed.Removal.ID, proof.ID, oldFactor).Scan(&intact); err != nil || !intact {
				t.Fatal("lost removal lacked its atomic factor, batch, proof, Session or fact closure", err)
			}
			restartIAM()
			for _, at := range []string{endpoint, replica} {
				call(at, http.MethodGet, "/v1/auth/me", bearer, nil, http.StatusUnauthorized, nil)
				call(at, http.MethodPost, "/v1/auth/totp:remove", bearer, intent, http.StatusUnauthorized, nil)
			}
			getPaaSApplication(t, paasEndpoint, bearer, "application-process", http.StatusUnauthorized)
			getPaaSApplication(t, paasEndpoint, roleBearer, "application-process", http.StatusUnauthorized)
			queryAudit(t, auditEndpoint, bearer, auditv1.QueryRecordsRequest{PageSize: 1}, http.StatusUnauthorized)
			var authenticated iamv1.LoginResponse
			call(endpoint, http.MethodPost, "/v1/auth/login", "", map[string]string{
				"loginName": realm, "password": password, "requestId": "process-removal-new-login"}, http.StatusOK, &authenticated)
			if iamv1.ValidateLoginResponse(authenticated) != nil || authenticated.Outcome != iamv1.LoginAuthenticated || authenticated.MustChangePassword {
				t.Fatal("removed USER could not normally authenticate with the unchanged password")
			}
			current := secret(authenticated.Credential)
			if err := admin.QueryRow(ctx, `SELECT authentication_method='PASSWORD' AND mfa_revision=3 AND credential_version=2 AND status='ACTIVE'
				FROM iam.sessions WHERE tenant_id=$1 AND principal_id=$2 AND id=$3`, user.AccountID, user.ID, authenticated.Session.ID).Scan(&intact); err != nil || !intact {
				t.Fatal("new removal Session inherited an old MFA ceremony", err)
			}
			var metadata iamv1.AuthenticatorRemoval
			readback := call(replica, http.MethodGet, path, current, nil, http.StatusOK, &metadata)
			if metadata != completed.Removal || bytes.Contains(readback.Body, []byte("recoveryCodes")) || bytes.Contains(readback.Body, []byte("provisioning")) {
				t.Fatal("new login did not recover exactly the nonsecret original removal")
			}
			var replay iamv1.RemoveTOTPResponse
			call(endpoint, http.MethodPost, "/v1/auth/totp:remove", current, intent, http.StatusOK, &replay)
			if iamv1.ValidateRemoveTOTPResponse(replay) != nil || replay.Outcome != "EQUAL_REPLAY" || replay.Removal != metadata || replay.NextStep != "" {
				t.Fatal("removal replay re-executed the original logout or changed completion")
			}
			changed := intent
			changed.StepUpID += "-different"
			call(replica, http.MethodPost, "/v1/auth/totp:remove", current, changed, http.StatusConflict, nil)
			call(endpoint, http.MethodGet, "/v1/auth/me", current, nil, http.StatusOK, nil)
			getPaaSApplication(t, paasEndpoint, current, "application-process", http.StatusOK)
			getPaaSApplication(t, paasEndpoint, roleBearer, "application-process", http.StatusUnauthorized)
			queryAudit(t, auditEndpoint, current, auditv1.QueryRecordsRequest{PageSize: 1}, http.StatusOK)
			var rebound iamv1.StartTOTPEnrollmentResponse
			call(replica, http.MethodPost, "/v1/auth/totp/enrollments", current, map[string]any{
				"requestId": "process-removal-rebind", "password": password, "expectedFactorRevision": 3}, http.StatusOK, &rebound)
			if rebound.Provisioning == nil || rebound.Enrollment.ID == oldFactor || rebound.Enrollment.FactorRevision != 3 {
				t.Fatal("process rebind did not issue an independent factor from removal history")
			}
			newSeed, newFactor := secret(rebound.Provisioning.Seed), rebound.Enrollment.ID
			secret(rebound.Provisioning.URI)
			code, newStep := codeFor(newSeed, -1, true)
			var confirmed iamv1.ConfirmTOTPEnrollmentResponse
			call(endpoint, http.MethodPost, "/v1/auth/totp/enrollments/"+newFactor+":confirm", current,
				map[string]string{"requestId": "process-removal-rebind-confirm", "code": code}, http.StatusOK, &confirmed)
			if confirmed.NextStep != "REAUTHENTICATE" || len(confirmed.RecoveryCodes) != 10 {
				t.Fatal("rebind did not end the PASSWORD Session and create new recovery material")
			}
			for _, material := range confirmed.RecoveryCodes {
				secret(material)
			}
			call(replica, http.MethodGet, "/v1/auth/me", current, nil, http.StatusUnauthorized, nil)
			current, _ = login(newSeed, newStep, "process-removal-rebound-login")
			restartIAM()
			call(replica, http.MethodPost, "/v1/auth/totp:remove", current, intent, http.StatusOK, &replay)
			call(endpoint, http.MethodGet, path, current, nil, http.StatusOK, &metadata)
			if replay.Outcome != "EQUAL_REPLAY" || replay.NextStep != "" || replay.Removal != completed.Removal || metadata != completed.Removal {
				t.Fatal("restart or rebound identity changed original removal completion")
			}
			if err := admin.QueryRow(ctx, `SELECT
				(SELECT enrollment_state='BOUND' AND revision=4 AND factor_id=$3 AND removal_id IS NULL FROM iam.user_mfa_states WHERE tenant_id=$1 AND user_id=$2)
				AND (SELECT state='ACTIVE' AND removal_id=$4 AND enrollment_revision=3 AND bound_revision=4 FROM iam.totp_authenticators WHERE tenant_id=$1 AND id=$3)
				AND (SELECT state='REVOKED' FROM iam.totp_authenticators WHERE tenant_id=$1 AND id=$5)
				AND (SELECT count(*)=1 FROM iam.authenticator_removals WHERE tenant_id=$1 AND user_id=$2)
				AND (SELECT count(*)=1 FROM iam.mfa_recovery_batches WHERE tenant_id=$1 AND user_id=$2 AND factor_id=$3 AND revoked_at IS NULL)
				AND (SELECT count(*)=1 FROM iam.sessions WHERE tenant_id=$1 AND principal_id=$2 AND status='ACTIVE' AND revoked_at IS NULL AND authentication_method='PASSWORD_TOTP' AND mfa_revision=4)
				AND (SELECT count(*)=1 FROM iam.security_notifications WHERE tenant_id=$1 AND user_id=$2 AND kind='AUTHENTICATOR_REMOVED')`,
				user.AccountID, user.ID, newFactor, completed.Removal.ID, oldFactor).Scan(&intact); err != nil || !intact {
				t.Fatal("historical replay lost rebind lineage or revoked the new MFA Session", err)
			}
			getPaaSApplication(t, paasEndpoint, current, "application-process", http.StatusOK)
			getPaaSApplication(t, paasEndpoint, roleBearer, "application-process", http.StatusUnauthorized)
			_, removedEvent = findIAMEvent(t, ctx, admin, auditv1.ActionIAMAuthenticatorRemoved, string(user.ID))
			if auditv1.ValidateEventForSource(auditv1.SourceIAM, removedEvent) != nil || removedEvent.RequestID != command {
				t.Fatal("removal lost the original USER security fact")
			}
			assertAuditEventCount(t, ctx, admin, string(removedEvent.EventID), 0)
			var access iamv1.UserAccess
			call(endpoint, http.MethodGet, "/v1/users/"+string(user.ID), root, nil, http.StatusOK, &access)
			call(endpoint, http.MethodPost, "/v1/users/"+string(user.ID)+":set-status", root,
				iamv1.SetUserStatusRequest{Status: iamv1.PrincipalDisabled, ResourceVersion: access.User.ResourceVersion, RequestID: "process-removal-disable"}, http.StatusOK, nil)
			call(replica, http.MethodGet, path, current, nil, http.StatusUnauthorized, nil)
			getPaaSApplication(t, paasEndpoint, current, "application-process", http.StatusUnauthorized)
			queryAudit(t, auditEndpoint, current, auditv1.QueryRecordsRequest{PageSize: 1}, http.StatusUnauthorized)
		})
		waitAllIAMOutboxDelivered(t, ctx, admin)
		page := queryAudit(t, auditEndpoint, root, auditv1.QueryRecordsRequest{PageSize: 100, Action: auditv1.ActionIAMAuthenticatorRemoved}, http.StatusOK)
		if len(page.Records) != 1 || page.Records[0].Event != removedEvent || page.Records[0].Source != auditv1.SourceIAM {
			t.Fatal("disabled USER removal history was lost or duplicated")
		}
		for range 2 {
			var duplicate auditv1.IngestionResult
			call(auditEndpoint, http.MethodPost, "/v1/events", iamServiceCredential, removedEvent, http.StatusOK, &duplicate)
			if duplicate.Outcome != auditv1.IngestionDuplicate || duplicate.Record != page.Records[0] {
				t.Fatal("removal replay changed the original Audit bytes or chain position")
			}
		}
		forged := removedEvent
		forged.RequestID += "-forged"
		call(auditEndpoint, http.MethodPost, "/v1/events", iamServiceCredential, forged, http.StatusForbidden, nil)
		forged = removedEvent
		forged.TenantID = "account-process-security-settings"
		call(auditEndpoint, http.MethodPost, "/v1/events", iamServiceCredential, forged, http.StatusForbidden, nil)
		if verification := verifyAudit(t, auditEndpoint, root); verification.State != auditv1.VerificationVerified || !verification.Complete {
			t.Fatal("removal broke the original tenant Audit chain")
		}
		t.Log("actual IAM replicas/PaaS/Audit: committed removal survived TCP loss/restart; new PASSWORD login recovered original completion; rebind and new MFA Session survived historical replay; disabled USER history delivered once (not SMTP)")
		return sensitive
	}
	intent := iamv1.StartTOTPReplacementRequest{RequestID: command, StepUpID: proof.ID, ExpectedFactorRevision: 2}
	var prepared iamv1.StartTOTPEnrollmentResponse
	call(endpoint, http.MethodPost, "/v1/auth/totp/enrollments:replace", bearer, intent, http.StatusOK, &prepared)
	if prepared.Outcome != "APPLIED" || prepared.Provisioning == nil || prepared.Enrollment.Purpose != "REPLACEMENT" ||
		prepared.Enrollment.State != "PENDING" || !prepared.Enrollment.ExpiresAt.Equal(proof.ExpiresAt) {
		t.Fatal("replacement preparation lost its purpose or renewed the original proof deadline")
	}
	newSeed, newFactor := secret(prepared.Provisioning.Seed), prepared.Enrollment.ID
	secret(prepared.Provisioning.URI)
	var replay iamv1.StartTOTPEnrollmentResponse
	call(replica, http.MethodPost, "/v1/auth/totp/enrollments:replace", bearer, intent, http.StatusOK, &replay)
	if replay.Outcome != "EQUAL_REPLAY" || replay.Provisioning != nil || !reflect.DeepEqual(replay.Enrollment, prepared.Enrollment) {
		t.Fatal("replacement preparation replay disclosed a seed or changed its intent")
	}
	var state iamv1.AuthenticatorState
	call(replica, http.MethodGet, "/v1/auth/authenticators", bearer, nil, http.StatusOK, &state)
	if state.EnrollmentState != "BOUND" || state.FactorID != oldFactor || state.FactorRevision != 2 {
		t.Fatal("pending replacement changed the current authenticator")
	}
	var intact bool
	if err := admin.QueryRow(ctx, `SELECT
		(SELECT state='ACTIVE' FROM iam.totp_authenticators WHERE tenant_id=$1 AND id=$3)
		AND (SELECT count(*)=1 FROM iam.mfa_recovery_batches WHERE tenant_id=$1 AND user_id=$2 AND factor_id=$3 AND revoked_at IS NULL)
		AND (SELECT state='CONSUMED' FROM iam.step_ups WHERE tenant_id=$1 AND user_id=$2 AND id=$4)`,
		user.AccountID, user.ID, oldFactor, proof.ID).Scan(&intact); err != nil || !intact {
		t.Fatal("preparation retired the old factor/batch or failed to consume the exact proof")
	}
	var replacedEvent auditv1.Event
	withDispatcherStopped(func() {
		code, newStep := codeFor(newSeed, -1, true)
		confirmIntent := map[string]string{"requestId": confirmation, "code": code}
		path := "/v1/auth/totp/enrollments/" + newFactor + ":confirm"
		lost := loseIAMCompletion(t, ctx, http.MethodPost, replica, path, bearer, confirmIntent)
		var completed iamv1.ConfirmTOTPEnrollmentResponse
		if iamv1.DecodeRequest(bytes.NewReader(lost.Body), &completed) != nil || completed.Enrollment.State != "CONFIRMED" ||
			completed.Enrollment.Purpose != "REPLACEMENT" || completed.NextStep != "REAUTHENTICATE" || len(completed.RecoveryCodes) != 10 {
			t.Fatal("lost TCP reply did not follow one actual factor replacement")
		}
		for _, material := range completed.RecoveryCodes {
			secret(material)
		}
		completed.RecoveryCodes = nil
		clear(lost.Body)
		if err := admin.QueryRow(ctx, `SELECT
			(SELECT state='REVOKED' AND revoked_at IS NOT NULL FROM iam.totp_authenticators WHERE tenant_id=$1 AND id=$3)
			AND (SELECT state='ACTIVE' AND bound_revision=3 FROM iam.totp_authenticators WHERE tenant_id=$1 AND id=$4)
			AND (SELECT enrollment_state='BOUND' AND factor_id=$4 AND revision=3 FROM iam.user_mfa_states WHERE tenant_id=$1 AND user_id=$2)
			AND (SELECT count(*)=1 FROM iam.mfa_recovery_batches WHERE tenant_id=$1 AND user_id=$2 AND factor_id=$3 AND revoked_at IS NOT NULL AND revocation_replacement_factor_id=$4)
			AND (SELECT count(*)=1 FROM iam.mfa_recovery_batches WHERE tenant_id=$1 AND user_id=$2 AND factor_id=$4 AND revoked_at IS NULL)
			AND (SELECT count(*)=10 FROM iam.mfa_recovery_codes c JOIN iam.mfa_recovery_batches b ON (b.tenant_id,b.id)=(c.tenant_id,c.batch_id) WHERE b.tenant_id=$1 AND b.user_id=$2 AND b.factor_id=$4)
			AND NOT EXISTS(SELECT 1 FROM iam.sessions WHERE tenant_id=$1 AND principal_id=$2 AND revoked_at IS NULL)
			AND NOT EXISTS(SELECT 1 FROM iam.authentication_challenges WHERE tenant_id=$1 AND user_id=$2 AND state='PENDING')
			AND (SELECT count(*)=1 FROM iam.audit_outbox WHERE tenant_id=$1 AND event_document->>'action'='iam.authenticator.replaced' AND event_document->'actor'->>'id'=$2)
			AND (SELECT count(*)=1 FROM iam.security_notifications WHERE tenant_id=$1 AND user_id=$2 AND kind='AUTHENTICATOR_REPLACED')`,
			user.AccountID, user.ID, oldFactor, newFactor).Scan(&intact); err != nil || !intact {
			t.Fatal("lost replacement did not atomically switch factors, batch, sessions and facts")
		}
		restartIAM()
		for _, at := range []string{endpoint, replica} {
			call(at, http.MethodGet, "/v1/auth/me", bearer, nil, http.StatusUnauthorized, nil)
			call(at, http.MethodPost, path, bearer, confirmIntent, http.StatusUnauthorized, nil)
		}
		getPaaSApplication(t, paasEndpoint, bearer, "application-process", http.StatusUnauthorized)
		queryAudit(t, auditEndpoint, bearer, auditv1.QueryRecordsRequest{PageSize: 1}, http.StatusUnauthorized)
		// The caller already received the new seed before confirmation. Only
		// a normal new-factor login can read metadata; lost codes stay lost.
		current, _ := login(newSeed, newStep, "process-replacement-new-login")
		var metadata iamv1.TOTPEnrollment
		readback := call(endpoint, http.MethodGet, "/v1/auth/totp/enrollments/by-request/"+command, current, nil, http.StatusOK, &metadata)
		if !reflect.DeepEqual(metadata, completed.Enrollment) || bytes.Contains(readback.Body, []byte("recoveryCodes")) || bytes.Contains(readback.Body, []byte("provisioning")) {
			t.Fatal("replacement readback changed completion or recovered secret material")
		}
		call(replica, http.MethodPost, path, current, confirmIntent, http.StatusUnauthorized, nil)
		call(replica, http.MethodGet, "/v1/auth/authenticators", current, nil, http.StatusOK, &state)
		if state.FactorID != newFactor || state.FactorRevision != 3 || state.EnrollmentState != "BOUND" {
			t.Fatal("restart did not retain the confirmed replacement")
		}
		getPaaSApplication(t, paasEndpoint, current, "application-process", http.StatusOK)
		queryAudit(t, auditEndpoint, current, auditv1.QueryRecordsRequest{PageSize: 1}, http.StatusOK)
		_, replacedEvent = findIAMEvent(t, ctx, admin, auditv1.ActionIAMAuthenticatorReplaced, string(user.ID))
		if auditv1.ValidateEventForSource(auditv1.SourceIAM, replacedEvent) != nil || replacedEvent.RequestID != confirmation {
			t.Fatal("replacement lost the exact original USER fact")
		}
		assertAuditEventCount(t, ctx, admin, string(replacedEvent.EventID), 0)
		var access iamv1.UserAccess
		call(endpoint, http.MethodGet, "/v1/users/"+string(user.ID), root, nil, http.StatusOK, &access)
		call(endpoint, http.MethodPost, "/v1/users/"+string(user.ID)+":set-status", root,
			iamv1.SetUserStatusRequest{Status: iamv1.PrincipalDisabled, ResourceVersion: access.User.ResourceVersion, RequestID: "process-replacement-disable"}, http.StatusOK, nil)
		call(replica, http.MethodGet, "/v1/auth/me", current, nil, http.StatusUnauthorized, nil)
		getPaaSApplication(t, paasEndpoint, current, "application-process", http.StatusUnauthorized)
	})
	waitAllIAMOutboxDelivered(t, ctx, admin)
	page := queryAudit(t, auditEndpoint, root, auditv1.QueryRecordsRequest{PageSize: 100, Action: auditv1.ActionIAMAuthenticatorReplaced}, http.StatusOK)
	if len(page.Records) != 1 || page.Records[0].Event != replacedEvent || page.Records[0].Source != auditv1.SourceIAM {
		t.Fatal("disabled USER replacement history changed or was not delivered exactly once")
	}
	for range 2 {
		var duplicate auditv1.IngestionResult
		call(auditEndpoint, http.MethodPost, "/v1/events", iamServiceCredential, replacedEvent, http.StatusOK, &duplicate)
		if duplicate.Outcome != auditv1.IngestionDuplicate || duplicate.Record != page.Records[0] {
			t.Fatal("replacement replay changed the immutable Audit record")
		}
	}
	forged := replacedEvent
	forged.RequestID = "process-replacement-forged"
	call(auditEndpoint, http.MethodPost, "/v1/events", iamServiceCredential, forged, http.StatusForbidden, nil)
	forged = replacedEvent
	forged.TenantID = "account-process-security-settings"
	call(auditEndpoint, http.MethodPost, "/v1/events", iamServiceCredential, forged, http.StatusForbidden, nil)
	if verification := verifyAudit(t, auditEndpoint, root); verification.State != auditv1.VerificationVerified || !verification.Complete {
		t.Fatal("replacement fact broke the original tenant chain")
	}
	t.Log("actual IAM replicas/PaaS/Audit: replacement survived committed TCP loss/restart; new-factor login read metadata without lost codes; old Sessions rejected; disabled USER history/replay preserved (not SMTP)")
	return sensitive
}

// Use an independently enrolled USER for these positive command boundaries.
// The existing login race and forced-password gate keeps its complete flow;
// successful OTPs and both racing attempts still consume the shared budget.
func proveRecoveryCodeRegenerationProcesses(t *testing.T, ctx context.Context, admin *pgx.Conn, endpoint, replica, auditEndpoint, root string,
	restartIAM func(), withDispatcherStopped func(func())) []string {
	t.Helper()
	const initial, password = "StepUp-Process-Initial-Password-43!", "StepUp-Process-Current-Password-82!"
	sensitive := []string{initial, password}
	secret := func(value iamv1.Secret) string {
		material := value.CopyBytes()
		defer clear(material)
		sensitive = append(sensitive, string(material))
		return string(material)
	}
	call := func(at, method, path, bearer string, body any, want int, result any) processResponse {
		t.Helper()
		response := performJSON(t, method, at+path, bearer, body)
		if response.Status != want {
			t.Fatalf("operation-proof process %s %s status=%d want=%d", method, path, response.Status, want)
		}
		if result != nil && iamv1.DecodeRequest(bytes.NewReader(response.Body), result) != nil {
			t.Fatal("invalid operation-proof process response")
		}
		return response
	}
	user := createIAMUser(t, endpoint, root, "stepup.process", "Process operation proof", initial, "process-step-up-user")
	defer func() {
		if !t.Failed() {
			return
		}
		observe, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		var budgets string
		if err := admin.QueryRow(observe, `SELECT jsonb_build_object(
			'password',(SELECT jsonb_build_object('purpose',purpose,'state',state,'used',used_attempts,
				'windowExpired',window_started_at+interval '60 seconds'<=clock_timestamp(),
				'reservationExpired',expires_at<=clock_timestamp()) FROM iam.password_attempts WHERE tenant_id=$1 AND principal_id=$2),
			'otp',(SELECT jsonb_build_object('purpose',purpose,'state',state,'used',used_attempts,
				'windowExpired',window_started_at+interval '10 minutes'<=clock_timestamp(),
				'reservationExpired',expires_at<=clock_timestamp()) FROM iam.totp_attempts WHERE tenant_id=$1 AND user_id=$2)
			)::text`, user.AccountID, user.ID).Scan(&budgets); err == nil {
			t.Log("nonsecret operation-proof attempt diagnostics:", budgets)
		}
	}()
	realm := user.LoginName + "@" + string(user.AccountID)
	first := loginIAM(t, endpoint, realm, initial, "process-step-up-first-login")
	sensitive = append(sensitive, first.Credential)
	changePasswordIAM(t, endpoint, first.Credential, initial, password, "process-step-up-password")
	var contact iamv1.NotificationContactVerification
	call(endpoint, http.MethodPost, "/v1/auth/notification-contact/verifications", first.Credential,
		map[string]string{"email": "receiver@matrix.test", "password": password, "requestId": "process-step-up-contact"}, http.StatusOK, &contact)
	contactCode := readProcessContactCode(t, ctx, admin, contact)
	sensitive = append(sensitive, contactCode)
	call(replica, http.MethodPost, "/v1/auth/notification-contact/verifications/"+contact.ID+":confirm", first.Credential,
		map[string]string{"requestId": "process-step-up-contact-confirm", "code": contactCode}, http.StatusOK, nil)
	var enrollment iamv1.StartTOTPEnrollmentResponse
	call(endpoint, http.MethodPost, "/v1/auth/totp/enrollments", first.Credential,
		map[string]any{"requestId": "process-step-up-enroll", "password": password, "expectedFactorRevision": 1}, http.StatusOK, &enrollment)
	if enrollment.Outcome != "APPLIED" || enrollment.Provisioning == nil {
		t.Fatal("operation proof lacks real enrollment")
	}
	seed, factor := secret(enrollment.Provisioning.Seed), enrollment.Enrollment.ID
	secret(enrollment.Provisioning.URI)
	nextCode := func(previous int64, initialBinding bool) (string, int64) {
		t.Helper()
		candidate, step := processTOTPCode(t, ctx, admin, seed, previous, initialBinding)
		sensitive = append(sensitive, candidate)
		return candidate, step
	}
	code, step := nextCode(-1, true)
	var bound iamv1.ConfirmTOTPEnrollmentResponse
	call(replica, http.MethodPost, "/v1/auth/totp/enrollments/"+factor+":confirm", first.Credential,
		map[string]string{"requestId": "process-step-up-bind", "code": code}, http.StatusOK, &bound)
	for _, material := range bound.RecoveryCodes {
		secret(material)
	}
	var challenge, authenticated iamv1.LoginResponse
	call(endpoint, http.MethodPost, "/v1/auth/login", "",
		map[string]string{"loginName": realm, "password": password, "requestId": "process-step-up-login"}, http.StatusOK, &challenge)
	if challenge.Outcome != iamv1.LoginChallengeRequired || challenge.Challenge == nil || challenge.Challenge.NextStep != "TOTP" {
		t.Fatal("bound operation-proof USER bypassed MFA")
	}
	code, step = nextCode(step, false)
	call(replica, http.MethodPost, "/v1/auth/challenges/"+challenge.Challenge.ID+":verify", "",
		map[string]string{"requestId": "process-step-up-login-proof", "challengeCredential": secret(challenge.ChallengeCredential), "code": code}, http.StatusOK, &authenticated)
	if authenticated.Outcome != iamv1.LoginAuthenticated {
		t.Fatal("operation-proof Session lacks an actual ceremony")
	}
	bearer := secret(authenticated.Credential)
	var state iamv1.AuthenticatorState
	var regenerationEvents []auditv1.Event
	withDispatcherStopped(func() {
		// All three command boundaries lose an actual TCP response after IAM
		// has committed. Public readback uses the original command identity;
		// captured secret output is only retained for leak checks, never replay.
		const regenerateCommand = "process-step-up-regenerate"
		stepUpIntent := map[string]any{"requestId": regenerateCommand, "operation": "RECOVERY_CODES_REGENERATE", "expectedFactorRevision": 2}
		lostStepUp := loseIAMCompletion(t, ctx, http.MethodPost, endpoint, "/v1/auth/step-up", bearer, stepUpIntent)
		var committedProof iamv1.StepUp
		if iamv1.DecodeRequest(bytes.NewReader(lostStepUp.Body), &committedProof) != nil || committedProof.State != "PENDING" {
			t.Fatal("lost operation-proof start did not commit its original intent")
		}
		clear(lostStepUp.Body)
		restartIAM()
		var proof iamv1.StepUp
		call(replica, http.MethodGet, "/v1/auth/step-up/by-request/"+regenerateCommand, bearer, nil, http.StatusOK, &proof)
		if !reflect.DeepEqual(proof, committedProof) {
			t.Fatal("proof readback changed the original intent or deadline")
		}
		if err := admin.QueryRow(ctx, "SELECT last_consumed_step FROM iam.totp_authenticators WHERE tenant_id=$1 AND id=$2", user.AccountID, factor).Scan(&step); err != nil {
			t.Fatal("read operation-proof OTP consumption")
		}
		proofCode, _ := nextCode(step, false)
		proofIntent := map[string]string{"requestId": "process-step-up-prove", "password": password, "code": proofCode}
		lostProof := loseIAMCompletion(t, ctx, http.MethodPost, replica, "/v1/auth/step-up/"+proof.ID+":verify", bearer, proofIntent)
		if iamv1.DecodeRequest(bytes.NewReader(lostProof.Body), &committedProof) != nil || committedProof.State != "PROVED" {
			t.Fatal("lost operation-proof verification was not an actual proof")
		}
		clear(lostProof.Body)
		restartIAM()
		call(endpoint, http.MethodGet, "/v1/auth/step-up/by-request/"+regenerateCommand, bearer, nil, http.StatusOK, &proof)
		if !reflect.DeepEqual(proof, committedProof) {
			t.Fatal("restart changed proved metadata or extended its deadline")
		}
		call(replica, http.MethodPost, "/v1/auth/step-up/"+proof.ID+":verify", bearer, proofIntent, http.StatusConflict, nil)
		regenerateIntent := iamv1.RegenerateRecoveryCodesRequest{RequestID: regenerateCommand, StepUpID: proof.ID, ExpectedFactorRevision: 2}
		lostRegeneration := loseIAMCompletion(t, ctx, http.MethodPost, endpoint, "/v1/auth/recovery-codes:regenerate", bearer, regenerateIntent)
		var regenerated iamv1.RegenerateRecoveryCodesResponse
		if iamv1.DecodeRequest(bytes.NewReader(lostRegeneration.Body), &regenerated) != nil || regenerated.Outcome != "APPLIED" || len(regenerated.RecoveryCodes) != 10 {
			t.Fatal("lost regeneration did not commit one new ten-code batch")
		}
		for _, material := range regenerated.RecoveryCodes {
			secret(material)
		}
		regenerated.RecoveryCodes = nil
		clear(lostRegeneration.Body)
		restartIAM()
		var completed iamv1.RecoveryCodeRegeneration
		readback := call(replica, http.MethodGet, "/v1/auth/recovery-codes/regenerations/by-request/"+regenerateCommand, bearer, nil, http.StatusOK, &completed)
		if completed != regenerated.Regeneration || bytes.Contains(readback.Body, []byte("recoveryCodes")) {
			t.Fatal("regeneration readback changed the original result or disclosed codes")
		}
		var repeated iamv1.RegenerateRecoveryCodesResponse
		call(endpoint, http.MethodPost, "/v1/auth/recovery-codes:regenerate", bearer, regenerateIntent, http.StatusOK, &repeated)
		if repeated.Outcome != "EQUAL_REPLAY" || len(repeated.RecoveryCodes) != 0 || repeated.Regeneration != completed {
			t.Fatal("regeneration replay reissued codes or changed original completion")
		}
		call(replica, http.MethodGet, "/v1/auth/step-up/by-request/"+regenerateCommand, bearer, nil, http.StatusOK, &proof)
		if proof.State != "CONSUMED" || proof.ConsumedAt == nil {
			t.Fatal("regeneration did not consume its exact proved operation")
		}
		// A client that lost its ten codes must explicitly prove a NEW intent.
		// A regenerated batch is accepted only through its closed provenance.
		const replacementCommand = "process-step-up-regenerate-replacement"
		call(endpoint, http.MethodPost, "/v1/auth/step-up", bearer,
			map[string]any{"requestId": replacementCommand, "operation": "RECOVERY_CODES_REGENERATE", "expectedFactorRevision": 2}, http.StatusOK, &proof)
		if err := admin.QueryRow(ctx, "SELECT last_consumed_step FROM iam.totp_authenticators WHERE tenant_id=$1 AND id=$2", user.AccountID, factor).Scan(&step); err != nil {
			t.Fatal("read replacement-proof OTP consumption")
		}
		proofCode, _ = nextCode(step, false)
		call(replica, http.MethodPost, "/v1/auth/step-up/"+proof.ID+":verify", bearer,
			map[string]string{"requestId": "process-step-up-replacement-proof", "password": password, "code": proofCode}, http.StatusOK, &proof)
		call(endpoint, http.MethodPost, "/v1/auth/recovery-codes:regenerate", bearer,
			iamv1.RegenerateRecoveryCodesRequest{RequestID: replacementCommand, StepUpID: proof.ID, ExpectedFactorRevision: 2}, http.StatusOK, &regenerated)
		if regenerated.Outcome != "APPLIED" || len(regenerated.RecoveryCodes) != 10 || regenerated.Regeneration.ID == completed.ID {
			t.Fatal("new proof did not generate an independent replacement batch")
		}
		for _, material := range regenerated.RecoveryCodes {
			secret(material)
		}
		call(replica, http.MethodGet, "/v1/auth/me", bearer, nil, http.StatusOK, nil)
		call(endpoint, http.MethodGet, "/v1/auth/authenticators", bearer, nil, http.StatusOK, &state)
		if state.EnrollmentState != "BOUND" || state.FactorRevision != 2 {
			t.Fatal("regeneration changed the original factor or its revision")
		}
		for _, command := range []string{regenerateCommand, replacementCommand} {
			var encoded []byte
			if err := admin.QueryRow(ctx, `SELECT event_document FROM iam.audit_outbox WHERE tenant_id=$1
				AND event_document->>'action'='iam.recovery-codes.regenerated' AND event_document->>'requestId'=$2`, user.AccountID, command).Scan(&encoded); err != nil {
				t.Fatal("read committed regeneration fact", err)
			}
			var event auditv1.Event
			if json.Unmarshal(encoded, &event) != nil || auditv1.ValidateEventForSource(auditv1.SourceIAM, event) != nil || event.Target.ID != string(user.ID) {
				t.Fatal("regeneration lacks its closed original USER fact")
			}
			regenerationEvents = append(regenerationEvents, event)
			assertAuditEventCount(t, ctx, admin, string(event.EventID), 0)
		}
		var access iamv1.UserAccess
		call(endpoint, http.MethodGet, "/v1/users/"+string(user.ID), root, nil, http.StatusOK, &access)
		call(endpoint, http.MethodPost, "/v1/users/"+string(user.ID)+":set-status", root,
			iamv1.SetUserStatusRequest{Status: iamv1.PrincipalDisabled, ResourceVersion: access.User.ResourceVersion, RequestID: "process-step-up-disable"}, http.StatusOK, nil)
		call(replica, http.MethodGet, "/v1/auth/me", bearer, nil, http.StatusUnauthorized, nil)
	})
	waitAllIAMOutboxDelivered(t, ctx, admin)
	regenerationPage := queryAudit(t, auditEndpoint, root, auditv1.QueryRecordsRequest{PageSize: 100, Action: auditv1.ActionIAMRecoveryCodesRegenerated}, http.StatusOK)
	if len(regenerationPage.Records) != len(regenerationEvents) || len(regenerationEvents) != 2 {
		t.Fatal("disabled USER regeneration history was not delivered exactly once")
	}
	for _, event := range regenerationEvents {
		var original *auditv1.AuditRecord
		for index := range regenerationPage.Records {
			if regenerationPage.Records[index].Event == event && regenerationPage.Records[index].Source == auditv1.SourceIAM {
				original = &regenerationPage.Records[index]
			}
		}
		if original == nil {
			t.Fatal("regeneration delivery changed its original historical fact")
		}
		for attempt := 0; attempt < 2; attempt++ {
			var duplicate auditv1.IngestionResult
			call(auditEndpoint, http.MethodPost, "/v1/events", iamServiceCredential, event, http.StatusOK, &duplicate)
			if duplicate.Outcome != auditv1.IngestionDuplicate || duplicate.Record != *original {
				t.Fatal("regeneration replay changed the immutable Audit record")
			}
		}
		forged := event
		forged.RequestID = "process-step-up-forged-regeneration"
		call(auditEndpoint, http.MethodPost, "/v1/events", iamServiceCredential, forged, http.StatusForbidden, nil)
	}
	if verification := verifyAudit(t, auditEndpoint, root); verification.State != auditv1.VerificationVerified || !verification.Complete {
		t.Fatal("regeneration facts broke original tenant chain")
	}
	t.Log("actual IAM replicas/Audit: original step-up start, proof and regeneration survived committed TCP loss/restart; new explicit proof replaced lost codes; disabled USER history/replay preserved")
	return sensitive
}

// Account-wide qualification must not invalidate another scenario's callers.
// The new Account is created through the actual platform API, never by DML.
func proveSecuritySettingsMutationProcesses(t *testing.T, ctx context.Context, admin *pgx.Conn, endpoint, replica, auditEndpoint, paasEndpoint, platform string,
	restartIAM func(), withDispatcherStopped func(func())) []string {
	t.Helper()
	const tenant = "account-process-security-settings"
	const initial, password = "Settings-Process-Initial-Password-73!", "Settings-Process-Current-Password-81!"
	const rootName, memberName = "settings.primary.process", "settings.operator"
	const path, command = "/v1/account/security-settings", "process-settings-update"
	sensitive := []string{initial, password}
	secret := func(value iamv1.Secret) string {
		material := value.CopyBytes()
		defer clear(material)
		sensitive = append(sensitive, string(material))
		return string(material)
	}
	call := func(at, method, route, bearer string, body any, want int, result any) processResponse {
		t.Helper()
		response := performJSON(t, method, at+route, bearer, body)
		if response.Status != want {
			t.Fatalf("settings process %s %s status=%d want=%d", method, route, response.Status, want)
		}
		if result != nil && iamv1.DecodeRequest(bytes.NewReader(response.Body), result) != nil {
			t.Fatal("invalid settings process response")
		}
		return response
	}
	var account iamv1.Account
	call(endpoint, http.MethodPost, "/v1/accounts", platform, map[string]any{
		"id": tenant, "displayName": "Settings process account", "rootLoginName": rootName, "rootDisplayName": "Settings root",
		"initialPassword": initial, "requestId": "process-settings-account"}, http.StatusCreated, &account)
	owner := loginIAM(t, endpoint, rootName, initial, "process-settings-owner-login")
	sensitive = append(sensitive, owner.Credential)
	changePasswordIAM(t, endpoint, owner.Credential, initial, password, "process-settings-owner-password")
	user := createIAMUser(t, endpoint, owner.Credential, memberName, "Settings operator", initial, "process-settings-operator")
	var policy iamv1.PolicyDetail
	call(endpoint, http.MethodPost, "/v1/policies", owner.Credential, iamv1.CreatePolicyRequest{
		DisplayName: "Settings operator", RequestID: "process-settings-operator-policy",
		Document: iamv1.PolicyDocument{LanguageVersion: iamv1.PolicyLanguageVersion, Scope: iamv1.AuthorityScopeTenant,
			Statements: []iamv1.PolicyStatement{{SID: "settings", Effect: iamv1.PolicyAllow,
				Actions:   []iamv1.Action{iamv1.ActionIAMSecuritySettingsRead, iamv1.ActionIAMSecuritySettingsUpdate},
				Resources: []iamv1.PolicyResourceSelector{{Kind: iamv1.ResourceAccount, Match: iamv1.PolicyResourceExact, ID: tenant}}}}}}, http.StatusCreated, &policy)
	attachment := createIAMPolicyAttachment(t, endpoint, owner.Credential, user.ID, policy.Policy.ID, "process-settings-operator-grant")
	for _, id := range []iamv1.PolicyID{iamv1.SystemPolicyPaaSDeveloper, iamv1.SystemPolicyAuditReader} {
		createIAMPolicyAttachment(t, endpoint, owner.Credential, user.ID, id, "process-settings-"+string(id))
	}
	realm := memberName + "@" + tenant
	first := loginIAM(t, endpoint, realm, initial, "process-settings-first-login")
	sensitive = append(sensitive, first.Credential)
	changePasswordIAM(t, endpoint, first.Credential, initial, password, "process-settings-password")
	operation := createPaaSApplication(t, paasEndpoint, first.Credential, "application-settings-process", "settings-owned", "process-settings-resource", http.StatusCreated)
	if string(operation.Scope.TenantID) != tenant {
		t.Fatal("settings fixture resource lost Account ownership")
	}
	var contact iamv1.NotificationContactVerification
	call(endpoint, http.MethodPost, "/v1/auth/notification-contact/verifications", first.Credential,
		map[string]string{"email": "settings@matrix.test", "password": password, "requestId": "process-settings-contact"}, http.StatusOK, &contact)
	contactCode := readProcessContactCode(t, ctx, admin, contact)
	sensitive = append(sensitive, contactCode)
	call(replica, http.MethodPost, "/v1/auth/notification-contact/verifications/"+contact.ID+":confirm", first.Credential,
		map[string]string{"requestId": "process-settings-contact-confirm", "code": contactCode}, http.StatusOK, nil)
	var enrollment iamv1.StartTOTPEnrollmentResponse
	call(endpoint, http.MethodPost, "/v1/auth/totp/enrollments", first.Credential,
		map[string]any{"requestId": "process-settings-enroll", "password": password, "expectedFactorRevision": 1}, http.StatusOK, &enrollment)
	if enrollment.Provisioning == nil {
		t.Fatal("settings operator lacks actual factor provisioning")
	}
	seed := secret(enrollment.Provisioning.Seed)
	sensitive = append(sensitive, secret(enrollment.Provisioning.URI), url.QueryEscape(seed))
	code, _ := processTOTPCode(t, ctx, admin, seed, -1, true)
	sensitive = append(sensitive, code)
	var bound iamv1.ConfirmTOTPEnrollmentResponse
	call(replica, http.MethodPost, "/v1/auth/totp/enrollments/"+enrollment.Enrollment.ID+":confirm", first.Credential,
		map[string]string{"requestId": "process-settings-bind", "code": code}, http.StatusOK, &bound)
	for _, recovery := range bound.RecoveryCodes {
		secret(recovery)
	}
	nextCode := func() string {
		t.Helper()
		var consumed int64
		if err := admin.QueryRow(ctx, "SELECT last_consumed_step FROM iam.totp_authenticators WHERE tenant_id=$1 AND id=$2", tenant, enrollment.Enrollment.ID).Scan(&consumed); err != nil {
			t.Fatal("read settings authenticator consumption")
		}
		code, _ := processTOTPCode(t, ctx, admin, seed, consumed, false)
		sensitive = append(sensitive, code)
		return code
	}
	login := func(request string) string {
		t.Helper()
		var challenge, authenticated iamv1.LoginResponse
		call(endpoint, http.MethodPost, "/v1/auth/login", "", map[string]string{"loginName": realm, "password": password, "requestId": request}, http.StatusOK, &challenge)
		if challenge.Outcome != iamv1.LoginChallengeRequired || challenge.Challenge == nil || challenge.Challenge.Purpose != "LOGIN" || challenge.Challenge.NextStep != "TOTP" {
			t.Fatal("settings operator bypassed MFA login")
		}
		call(replica, http.MethodPost, "/v1/auth/challenges/"+challenge.Challenge.ID+":verify", "",
			map[string]string{"requestId": request + "-verify", "challengeCredential": secret(challenge.ChallengeCredential), "code": nextCode()}, http.StatusOK, &authenticated)
		if authenticated.Outcome != iamv1.LoginAuthenticated {
			t.Fatal("settings operator lacks authenticated Session")
		}
		return secret(authenticated.Credential)
	}
	caller := login("process-settings-qualified")
	getPaaSApplication(t, paasEndpoint, caller, "application-settings-process", http.StatusOK)
	// A RoleSession must retain its actual source Session's qualification,
	// not only the USER's current factor state or the Role's live permission.
	var role iamv1.Role
	call(endpoint, http.MethodPost, "/v1/roles", owner.Credential, iamv1.CreateRoleRequest{
		Name: "Settings source qualification", Tags: []iamv1.RoleTag{}, RequestID: "process-settings-role",
		TrustPolicy: iamv1.TrustPolicyDocument{LanguageVersion: "1", Statements: []iamv1.TrustPolicyStatement{{SID: "source", Effect: iamv1.PolicyAllow,
			Principals: []iamv1.TrustPrincipal{{Type: iamv1.PrincipalUser, ID: user.ID}}}}}}, http.StatusCreated, &role)
	rolePath := "/v1/roles/" + string(role.ID)
	call(endpoint, http.MethodPost, "/v1/policy-attachments", owner.Credential, iamv1.CreatePolicyAttachmentRequest{
		Target: iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetRole, ID: string(role.ID)}, PolicyID: iamv1.SystemPolicyPaaSViewer,
		PolicyResourceVersion: 1, RequestID: "process-settings-role-permission"}, http.StatusOK, nil)
	var boundary iamv1.RolePermissionBoundary
	call(endpoint, http.MethodPut, rolePath+"/permission-boundary", owner.Credential, iamv1.SetRolePermissionBoundaryRequest{
		PolicyID: iamv1.SystemPolicyPaaSViewer, PolicyResourceVersion: 1, ResourceVersion: role.ResourceVersion,
		RequestID: "process-settings-role-boundary"}, http.StatusOK, &boundary)
	var assumePolicy iamv1.PolicyDetail
	call(endpoint, http.MethodPost, "/v1/policies", owner.Credential, iamv1.CreatePolicyRequest{
		DisplayName: "Assume settings source role", RequestID: "process-settings-assume-policy",
		Document: iamv1.PolicyDocument{LanguageVersion: iamv1.PolicyLanguageVersion, Scope: iamv1.AuthorityScopeTenant,
			Statements: []iamv1.PolicyStatement{{SID: "assume", Effect: iamv1.PolicyAllow, Actions: []iamv1.Action{iamv1.ActionIAMRoleAssume},
				Resources: []iamv1.PolicyResourceSelector{{Kind: iamv1.ResourceRole, Match: iamv1.PolicyResourceExact, ID: string(role.ID)}}}}}}, http.StatusCreated, &assumePolicy)
	createIAMPolicyAttachment(t, endpoint, owner.Credential, user.ID, assumePolicy.Policy.ID, "process-settings-assume-grant")
	var assumed iamv1.AssumeRoleResponse
	call(replica, http.MethodPost, rolePath+":assume", caller,
		iamv1.AssumeRoleRequest{ResourceVersion: boundary.ResourceVersion, RequestID: "process-settings-role-session"}, http.StatusOK, &assumed)
	if iamv1.ValidateAssumeRoleResponse(assumed) != nil || assumed.Outcome != "APPLIED" {
		t.Fatal("settings source RoleSession was not issued")
	}
	roleCredential := secret(assumed.Credential)
	getPaaSApplication(t, paasEndpoint, roleCredential, "application-settings-process", http.StatusOK)
	var proof iamv1.StepUp
	call(endpoint, http.MethodPost, "/v1/auth/step-up", caller, iamv1.StartStepUpRequest{RequestID: command, Operation: iamv1.StepUpUpdateSecuritySettings, ExpectedFactorRevision: 2,
		SecuritySettings: &iamv1.SecuritySettingsUpdateIntent{Password: &iamv1.AccountPasswordSettings{ExpiryMode: iamv1.PasswordExpiryChange, MinimumLength: 15, HistoryCount: 1}, ExpectedResourceVersion: 1, MFA: iamv1.AccountMFASettings{RequiredForUsers: true}}}, http.StatusOK, &proof)
	call(replica, http.MethodPost, "/v1/auth/step-up/"+proof.ID+":verify", caller,
		map[string]string{"requestId": "process-settings-proof", "password": password, "code": nextCode()}, http.StatusOK, &proof)
	intent := iamv1.UpdateAccountSecuritySettingsRequest{Password: iamv1.AccountPasswordSettings{ExpiryMode: iamv1.PasswordExpiryChange, MinimumLength: 15, HistoryCount: 1}, RequestID: command, StepUpID: proof.ID, ExpectedResourceVersion: 1, MFA: iamv1.AccountMFASettings{RequiredForUsers: true}}
	var fact auditv1.Event
	withDispatcherStopped(func() {
		lost := loseIAMCompletion(t, ctx, http.MethodPut, endpoint, path, caller, intent)
		var applied iamv1.UpdateAccountSecuritySettingsResponse
		if lost.Status != http.StatusOK || iamv1.DecodeRequest(bytes.NewReader(lost.Body), &applied) != nil || applied.Outcome != "APPLIED" ||
			!applied.Change.CallerSessionEnded || applied.Change.Settings.ResourceVersion != 2 {
			t.Fatal("lost settings reply did not follow real commit")
		}
		clear(lost.Body)
		for _, at := range []string{endpoint, replica} {
			call(at, http.MethodGet, "/v1/auth/me", caller, nil, http.StatusUnauthorized, nil)
			call(at, http.MethodPut, path, caller, intent, http.StatusUnauthorized, nil)
		}
		getPaaSApplication(t, paasEndpoint, caller, "application-settings-process", http.StatusUnauthorized)
		getPaaSApplication(t, paasEndpoint, roleCredential, "application-settings-process", http.StatusUnauthorized)
		queryAudit(t, auditEndpoint, caller, auditv1.QueryRecordsRequest{PageSize: 1}, http.StatusUnauthorized)
		restartIAM()
		call(replica, http.MethodGet, "/v1/auth/me", caller, nil, http.StatusUnauthorized, nil)
		fresh := login("process-settings-after-restart")
		getPaaSApplication(t, paasEndpoint, roleCredential, "application-settings-process", http.StatusUnauthorized)
		var completion iamv1.AccountSecuritySettingsChange
		call(replica, http.MethodGet, path+"/changes/"+command, fresh, nil, http.StatusOK, &completion)
		if !reflect.DeepEqual(completion, applied.Change) {
			t.Fatal("restart lost original settings completion")
		}
		var replay iamv1.UpdateAccountSecuritySettingsResponse
		call(endpoint, http.MethodPut, path, fresh, intent, http.StatusOK, &replay)
		if replay.Outcome != "EQUAL_REPLAY" || !reflect.DeepEqual(replay.Change, completion) {
			t.Fatal("settings retry changed original result")
		}
		call(replica, http.MethodGet, "/v1/auth/me", fresh, nil, http.StatusOK, nil)
		variant := intent
		variant.MFA.RequiredForUsers = false
		call(endpoint, http.MethodPut, path, fresh, variant, http.StatusConflict, nil)
		owner = loginIAM(t, endpoint, rootName, password, "process-settings-owner-reauth")
		sensitive = append(sensitive, owner.Credential)
		getPaaSApplication(t, paasEndpoint, owner.Credential, "application-settings-process", http.StatusOK)
		revokeIAMPolicyAttachment(t, endpoint, owner.Credential, attachment.ID, attachment.ResourceVersion, "process-settings-revoke-before-delivery")
		call(replica, http.MethodGet, path+"/changes/"+command, fresh, nil, http.StatusForbidden, nil)
		call(endpoint, http.MethodPut, path, fresh, intent, http.StatusForbidden, nil)
		var access iamv1.UserAccess
		call(endpoint, http.MethodGet, "/v1/users/"+string(user.ID), owner.Credential, nil, http.StatusOK, &access)
		call(replica, http.MethodPost, "/v1/users/"+string(user.ID)+":set-status", owner.Credential,
			iamv1.SetUserStatusRequest{Status: iamv1.PrincipalDisabled, ResourceVersion: access.User.ResourceVersion, RequestID: "process-settings-disable-before-delivery"}, http.StatusOK, nil)
		call(endpoint, http.MethodGet, "/v1/auth/me", fresh, nil, http.StatusUnauthorized, nil)
		var encoded []byte
		if err := admin.QueryRow(ctx, `SELECT event_document FROM iam.audit_outbox WHERE tenant_id=$1 AND event_document->>'action'='iam.security-settings.updated'
			AND event_document->>'requestId'=$2`, tenant, command).Scan(&encoded); err != nil {
			t.Fatal("settings fact absent after original Session invalidation", err)
		}
		if json.Unmarshal(encoded, &fact) != nil || auditv1.ValidateEventForSource(auditv1.SourceIAM, fact) != nil || fact.Actor.ID != auditv1.ActorID(user.ID) ||
			fact.Target.Kind != auditv1.TargetAccount || fact.Target.ID != tenant || fact.IAMDecisionID == "" {
			t.Fatal("settings fact lost original authority attribution")
		}
		var noticePreserved bool
		if err := admin.QueryRow(ctx, `SELECT count(*)=1 FROM iam.security_notifications
			WHERE tenant_id=$1 AND id=$2 AND event_id=$2 AND user_id=$3 AND kind='SECURITY_SETTINGS_CHANGED'
			AND state='PENDING' AND email='settings@matrix.test' AND contact_revision=1`, tenant, fact.EventID, user.ID).Scan(&noticePreserved); err != nil || !noticePreserved {
			t.Fatal("settings notice was lost or redirected after replay and actor disable", err)
		}
		assertAuditEventCount(t, ctx, admin, string(fact.EventID), 0)
	})
	waitAllIAMOutboxDelivered(t, ctx, admin)
	page := queryAudit(t, auditEndpoint, owner.Credential, auditv1.QueryRecordsRequest{PageSize: 100, Action: auditv1.ActionIAMSecuritySettingsUpdated}, http.StatusOK)
	if len(page.Records) != 1 || page.Records[0].Event != fact || page.Records[0].Source != auditv1.SourceIAM {
		t.Fatal("disabled settings actor lost its original audit fact")
	}
	other := queryAudit(t, auditEndpoint, platform, auditv1.QueryRecordsRequest{PageSize: 100, Action: auditv1.ActionIAMSecuritySettingsUpdated}, http.StatusOK)
	if len(other.Records) != 0 {
		t.Fatal("settings event escaped tenant chain")
	}
	var duplicate auditv1.IngestionResult
	call(auditEndpoint, http.MethodPost, "/v1/events", iamServiceCredential, fact, http.StatusOK, &duplicate)
	if duplicate.Outcome != auditv1.IngestionDuplicate || duplicate.Record != page.Records[0] {
		t.Fatal("settings event replay changed historical record")
	}
	for _, mutate := range []func(*auditv1.Event){
		func(event *auditv1.Event) { event.TenantID = "organization-process" },
		func(event *auditv1.Event) { event.RequestID = "different-settings-command" },
		func(event *auditv1.Event) { event.Target.ID = "different-account" },
	} {
		forged := fact
		mutate(&forged)
		call(auditEndpoint, http.MethodPost, "/v1/events", iamServiceCredential, forged, http.StatusForbidden, nil)
	}
	if chain := verifyAudit(t, auditEndpoint, owner.Credential); chain.State != auditv1.VerificationVerified || !chain.Complete || string(chain.TenantID) != tenant {
		t.Fatal("settings event broke tenant history")
	}
	getPaaSApplication(t, paasEndpoint, owner.Credential, "application-settings-process", http.StatusOK)
	t.Log("actual IAM replicas/PaaS/Audit: settings commit survived lost PUT reply/restart; exact completion after normal MFA login, original/current permission separation, disabled actor history and tenant chain preserved")
	return sensitive
}

func proveTOTPRecoveryProcesses(t *testing.T, ctx context.Context, admin *pgx.Conn, endpoint, replica, auditEndpoint, paasEndpoint, root string,
	restartIAM func(), withDispatcherStopped func(func())) []string {
	t.Helper()
	const initial, password = "Recovery-Process-Initial-Password-67!", "Recovery-Process-Changed-Password-89!"
	sensitive := []string{initial, password}
	secret := func(value iamv1.Secret) string {
		material := value.CopyBytes()
		defer clear(material)
		sensitive = append(sensitive, string(material))
		return string(material)
	}
	call := func(at, method, path, bearer string, body any, want int, result any) processResponse {
		t.Helper()
		response := performJSON(t, method, at+path, bearer, body)
		if response.Status != want {
			t.Fatalf("recovery process %s %s status=%d want=%d", method, path, response.Status, want)
		}
		if result != nil && iamv1.DecodeRequest(bytes.NewReader(response.Body), result) != nil {
			t.Fatal("invalid recovery process response")
		}
		return response
	}
	user := createIAMUser(t, endpoint, root, "mfa.recovery.process", "Process MFA recovery", initial, "process-recovery-user")
	for _, policy := range []iamv1.PolicyID{iamv1.SystemPolicyPaaSDeveloper, iamv1.SystemPolicyAuditReader} {
		createIAMPolicyAttachment(t, endpoint, root, user.ID, policy, "process-recovery-"+string(policy))
	}
	realm := user.LoginName + "@" + string(user.AccountID)
	first := loginIAM(t, endpoint, realm, initial, "process-recovery-initial-login")
	changePasswordIAM(t, endpoint, first.Credential, initial, password, "process-recovery-initial-change")
	sensitive = append(sensitive, first.Credential)
	var verification iamv1.NotificationContactVerification
	call(endpoint, http.MethodPost, "/v1/auth/notification-contact/verifications", first.Credential,
		map[string]string{"email": "recovery@matrix.test", "password": password, "requestId": "process-recovery-contact"}, http.StatusOK, &verification)
	contactCode := readProcessContactCode(t, ctx, admin, verification)
	sensitive = append(sensitive, contactCode)
	call(replica, http.MethodPost, "/v1/auth/notification-contact/verifications/"+verification.ID+":confirm", first.Credential,
		map[string]string{"requestId": "process-recovery-contact-confirm", "code": contactCode}, http.StatusOK, nil)
	var enrollment iamv1.StartTOTPEnrollmentResponse
	call(endpoint, http.MethodPost, "/v1/auth/totp/enrollments", first.Credential,
		map[string]any{"requestId": "process-recovery-enroll", "password": password, "expectedFactorRevision": 1}, http.StatusOK, &enrollment)
	if enrollment.Outcome != "APPLIED" || enrollment.Provisioning == nil {
		t.Fatal("recovery fixture lacks an actual first binding")
	}
	seed := secret(enrollment.Provisioning.Seed)
	secret(enrollment.Provisioning.URI)
	code, _ := processTOTPCode(t, ctx, admin, seed, -1, true)
	sensitive = append(sensitive, code)
	var bound iamv1.ConfirmTOTPEnrollmentResponse
	call(replica, http.MethodPost, "/v1/auth/totp/enrollments/"+enrollment.Enrollment.ID+":confirm", first.Credential,
		map[string]string{"requestId": "process-recovery-bound", "code": code}, http.StatusOK, &bound)
	if bound.NextStep != "REAUTHENTICATE" || len(bound.RecoveryCodes) != 10 {
		t.Fatal("recovery fixture lacks its original client-held batch")
	}
	for _, material := range bound.RecoveryCodes {
		secret(material)
	}
	login := func(at, request, next string) iamv1.LoginResponse {
		t.Helper()
		var result iamv1.LoginResponse
		call(at, http.MethodPost, "/v1/auth/login", "", map[string]string{"loginName": realm, "password": password, "requestId": request}, http.StatusOK, &result)
		if iamv1.ValidateLoginResponse(result) != nil || result.Outcome != iamv1.LoginChallengeRequired || result.Challenge.NextStep != next {
			t.Fatal("recovery password proof issued a Session or wrong purpose")
		}
		secret(result.ChallengeCredential)
		return result
	}
	inspect := func(proof iamv1.LoginResponse, expected iamv1.AuthenticatorRecovery, state string) {
		t.Helper()
		var actual iamv1.AuthenticatorRecovery
		call(replica, http.MethodPost, "/v1/auth/challenges/"+proof.Challenge.ID+":recovery-result", "",
			map[string]string{"requestId": expected.RequestID, "challengeCredential": secret(proof.ChallengeCredential)}, http.StatusOK, &actual)
		expected.State = state
		if !reflect.DeepEqual(actual, expected) {
			t.Fatal("recovery inspection changed original metadata or deadline")
		}
	}
	var facts []auditv1.Event
	withDispatcherStopped(func() {
		original := login(endpoint, "process-recovery-login", "TOTP")
		intent := map[string]string{"requestId": "process-recovery-lost-start", "challengeCredential": secret(original.ChallengeCredential), "recoveryCode": secret(bound.RecoveryCodes[0])}
		lost := loseIAMCompletion(t, ctx, http.MethodPost, endpoint, "/v1/auth/challenges/"+original.Challenge.ID+":recover", "", intent)
		var committed iamv1.StartAuthenticatorRecoveryResponse
		if iamv1.DecodeRequest(bytes.NewReader(lost.Body), &committed) != nil {
			t.Fatal("lost start did not follow committed recovery")
		}
		clear(lost.Body)
		// Capture only for leak checks and negative assertions. The client lost
		// these secrets; it must never continue using this captured provisioning.
		secret(committed.Provisioning.Seed)
		secret(committed.Provisioning.URI)
		secret(committed.ChallengeCredential)
		if !committed.Recovery.ExpiresAt.Equal(original.Challenge.ExpiresAt) {
			t.Fatal("lost start extended its password proof")
		}
		restartIAM()
		call(replica, http.MethodPost, "/v1/auth/challenges/"+original.Challenge.ID+":recover", "", intent, http.StatusUnauthorized, nil)
		for _, bearer := range []string{first.Credential, secret(original.ChallengeCredential), secret(committed.ChallengeCredential)} {
			call(replica, http.MethodGet, "/v1/auth/me", bearer, nil, http.StatusUnauthorized, nil)
			getPaaSApplication(t, paasEndpoint, bearer, "application-process", http.StatusUnauthorized)
			queryAudit(t, auditEndpoint, bearer, auditv1.QueryRecordsRequest{PageSize: 1}, http.StatusUnauthorized)
		}
		pending := login(replica, "process-recovery-inspect-login", "RECOVER")
		inspect(pending, committed.Recovery, "STARTED")
		// A distinct explicit intent consumes another original code. Neither
		// restart nor inspecting the first completion refunds the first code.
		var replacement iamv1.StartAuthenticatorRecoveryResponse
		call(endpoint, http.MethodPost, "/v1/auth/challenges/"+pending.Challenge.ID+":recover", "",
			map[string]string{"requestId": "process-recovery-replacement", "challengeCredential": secret(pending.ChallengeCredential), "recoveryCode": secret(bound.RecoveryCodes[1])}, http.StatusOK, &replacement)
		if replacement.Recovery.ID == committed.Recovery.ID || replacement.Challenge.ID == committed.Challenge.ID ||
			!replacement.Recovery.ExpiresAt.Equal(pending.Challenge.ExpiresAt) {
			t.Fatal("replacement reused lost authority or extended its new password proof")
		}
		newSeed := secret(replacement.Provisioning.Seed)
		secret(replacement.Provisioning.URI)
		newCredential := secret(replacement.ChallengeCredential)
		restartIAM()
		call(endpoint, http.MethodPost, "/v1/auth/challenges/"+committed.Challenge.ID+":confirm-recovery", "",
			map[string]string{"requestId": "process-recovery-superseded", "challengeCredential": secret(committed.ChallengeCredential), "code": "000000"}, http.StatusUnauthorized, nil)
		code, step := processTOTPCode(t, ctx, admin, newSeed, -1, true)
		sensitive = append(sensitive, code)
		confirm := map[string]string{"requestId": "process-recovery-confirm", "challengeCredential": newCredential, "code": code}
		lost = loseIAMCompletion(t, ctx, http.MethodPost, replica, "/v1/auth/challenges/"+replacement.Challenge.ID+":confirm-recovery", "", confirm)
		var completed iamv1.ConfirmAuthenticatorRecoveryResponse
		if iamv1.DecodeRequest(bytes.NewReader(lost.Body), &completed) != nil || completed.NextStep != "REAUTHENTICATE" ||
			completed.Recovery.ID != replacement.Recovery.ID || len(completed.RecoveryCodes) != 10 {
			t.Fatal("lost confirmation did not follow the original recovery completion")
		}
		for _, material := range completed.RecoveryCodes {
			secret(material) // Evidence only, never reused for authentication.
		}
		clear(lost.Body)
		restartIAM()
		call(endpoint, http.MethodPost, "/v1/auth/challenges/"+replacement.Challenge.ID+":confirm-recovery", "", confirm, http.StatusUnauthorized, nil)
		fresh := login(endpoint, "process-recovery-final-login", "TOTP")
		superseded := committed.Recovery
		superseded.CompletedAt = &replacement.Recovery.CreatedAt
		inspect(fresh, superseded, "SUPERSEDED")
		inspect(fresh, completed.Recovery, "COMPLETED")
		freshCode, _ := processTOTPCode(t, ctx, admin, newSeed, step, false)
		sensitive = append(sensitive, freshCode)
		var authenticated iamv1.LoginResponse
		call(replica, http.MethodPost, "/v1/auth/challenges/"+fresh.Challenge.ID+":verify", "",
			map[string]string{"requestId": "process-recovery-final-verify", "challengeCredential": secret(fresh.ChallengeCredential), "code": freshCode}, http.StatusOK, &authenticated)
		if iamv1.ValidateLoginResponse(authenticated) != nil || authenticated.Outcome != iamv1.LoginAuthenticated {
			t.Fatal("new factor and current password cannot authenticate after restart")
		}
		bearer := secret(authenticated.Credential)
		getPaaSApplication(t, paasEndpoint, bearer, "application-process", http.StatusOK)
		queryAudit(t, auditEndpoint, bearer, auditv1.QueryRecordsRequest{PageSize: 1}, http.StatusOK)
		var intact bool
		if err := admin.QueryRow(ctx, `SELECT
			(SELECT authentication_method='PASSWORD_TOTP' AND mfa_revision=5 FROM iam.sessions WHERE tenant_id=$1 AND id=$3)
			AND (SELECT count(*) FROM iam.mfa_recovery_codes c JOIN iam.mfa_recovery_batches b ON (b.tenant_id,b.id)=(c.tenant_id,c.batch_id)
				WHERE b.tenant_id=$1 AND b.user_id=$2 AND c.consumed_at IS NOT NULL)=2
			AND (SELECT count(*) FROM iam.mfa_recovery_batches WHERE tenant_id=$1 AND user_id=$2 AND revoked_at IS NULL)=1
			AND (SELECT count(*) FROM iam.mfa_recovery_batches WHERE tenant_id=$1 AND user_id=$2 AND revoked_at IS NOT NULL)=1
			AND (SELECT used_attempts=5 FROM iam.totp_attempts WHERE tenant_id=$1 AND user_id=$2)
			AND (SELECT count(*) FROM iam.security_notifications WHERE tenant_id=$1 AND user_id=$2 AND verification_id=$4
				AND email='recovery@matrix.test' AND contact_revision=1 AND kind IN ('RECOVERY_STARTED','AUTHENTICATOR_RECOVERED'))=3`,
			user.AccountID, user.ID, authenticated.Session.ID, verification.ID).Scan(&intact); err != nil || !intact {
			t.Fatal("process recovery changed its original code, budget, Session fact or notification binding", err)
		}
		var access iamv1.UserAccess
		call(endpoint, http.MethodGet, "/v1/users/"+string(user.ID), root, nil, http.StatusOK, &access)
		call(endpoint, http.MethodPost, "/v1/users/"+string(user.ID)+":set-status", root,
			iamv1.SetUserStatusRequest{Status: iamv1.PrincipalDisabled, ResourceVersion: access.User.ResourceVersion, RequestID: "process-recovery-disable"}, http.StatusOK, nil)
		call(replica, http.MethodGet, "/v1/auth/me", bearer, nil, http.StatusUnauthorized, nil)
		getPaaSApplication(t, paasEndpoint, bearer, "application-process", http.StatusUnauthorized)
		queryAudit(t, auditEndpoint, bearer, auditv1.QueryRecordsRequest{PageSize: 1}, http.StatusUnauthorized)
		rows, err := admin.Query(ctx, `SELECT event_document FROM iam.audit_outbox WHERE tenant_id=$1 AND event_document#>>'{actor,id}'=$2
			AND event_document->>'action' IN ('iam.authenticator.recovery-started','iam.authenticator.recovered')`, user.AccountID, user.ID)
		if err != nil {
			t.Fatal("read original process recovery facts")
		}
		for rows.Next() {
			var document []byte
			var event auditv1.Event
			if rows.Scan(&document) != nil || auditv1.DecodeRequest(bytes.NewReader(document), &event) != nil ||
				auditv1.ValidateEventForSource(auditv1.SourceIAM, event) != nil {
				rows.Close()
				t.Fatal("invalid original process recovery fact")
			}
			facts = append(facts, event)
		}
		err = rows.Err()
		rows.Close()
		if err != nil || len(facts) != 3 {
			t.Fatal("recovery did not commit exactly three original facts")
		}
		for _, event := range facts {
			assertAuditEventCount(t, ctx, admin, string(event.EventID), 0)
		}
	})
	waitAllIAMOutboxDelivered(t, ctx, admin)
	for _, event := range facts {
		page := queryAudit(t, auditEndpoint, root, auditv1.QueryRecordsRequest{PageSize: 10, Action: event.Action}, http.StatusOK)
		var original *auditv1.AuditRecord
		for i := range page.Records {
			if page.Records[i].Event.Equal(event) {
				original = &page.Records[i]
			}
		}
		if original == nil || original.Source != auditv1.SourceIAM || event.Actor.Type != auditv1.ActorUser || event.Actor.ID != auditv1.ActorID(user.ID) ||
			event.Target.Kind != auditv1.TargetPrincipal || event.Target.ID != string(user.ID) || event.TenantID != auditv1.TenantID(user.AccountID) {
			t.Fatal("disabled USER history lost original recovery attribution")
		}
		var replay auditv1.IngestionResult
		call(auditEndpoint, http.MethodPost, "/v1/events", iamServiceCredential, event, http.StatusOK, &replay)
		if replay.Outcome != auditv1.IngestionDuplicate || !reflect.DeepEqual(replay.Record, *original) {
			t.Fatal("recovery replay changed its immutable Audit record")
		}
		forged := event
		forged.RequestID = "process-recovery-forged-fact"
		call(auditEndpoint, http.MethodPost, "/v1/events", iamServiceCredential, forged, http.StatusForbidden, nil)
		assertAuditEventCount(t, ctx, admin, string(event.EventID), 1)
	}
	if verification := verifyAudit(t, auditEndpoint, root); verification.State != auditv1.VerificationVerified || !verification.Complete {
		t.Fatal("recovery facts broke original tenant chain")
	}
	t.Log("actual IAM pair: recovery start/confirmation TCP loss, restart, original-code supersession, new-factor login and disabled-USER historical proof/replay passed; contact/notice delivery is not SMTP evidence")
	return sensitive
}

// Select a client code in the documented skew window using the real clock.
// Never mutate the server clock, factor consumption or challenge deadline.
func processTOTPCode(t *testing.T, ctx context.Context, admin *pgx.Conn, seed string, previous int64, initialBinding bool) (string, int64) {
	t.Helper()
	deadline := time.Now().Add(65 * time.Second)
	for time.Now().Before(deadline) {
		var now time.Time
		if err := admin.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&now); err != nil {
			t.Fatal("read actual TOTP process clock")
		}
		step := now.Unix() / 30
		if initialBinding {
			step--
		}
		if step <= previous {
			step = previous + 1
		}
		if step <= now.Unix()/30+1 {
			candidate, err := hotp.GenerateCode(seed, uint64(step))
			if err != nil {
				t.Fatal("generate synthetic process authenticator code")
			}
			// Adjacent decimal collisions are a security rejection, not a
			// reliable positive fixture. Wait for a distinct valid window.
			collision := false
			for old := max(int64(0), now.Unix()/30-1); old <= min(previous, now.Unix()/30+1); old++ {
				used, err := hotp.GenerateCode(seed, uint64(old))
				if err != nil {
					t.Fatal("generate consumed process authenticator code")
				}
				collision = collision || used == candidate
			}
			if !collision {
				return candidate, step
			}
		}
		select {
		case <-ctx.Done():
			t.Fatal("TOTP process deadline")
		case <-time.After(50 * time.Millisecond):
		}
	}
	t.Fatal("real clock did not reach a fresh TOTP window")
	return "", 0
}

// Only this synthetic fixture knows its own wrapping key. Reuse the public
// cipher-context owner and standard primitives to obtain the HTTP-issued
// contact code. This is NOT SMTP delivery or a production recovery endpoint.
func readProcessContactCode(t *testing.T, ctx context.Context, admin *pgx.Conn, verification iamv1.NotificationContactVerification) string {
	t.Helper()
	binding := iamv1.EmailVerificationBinding{AccountID: verification.AccountID, UserID: verification.UserID, VerificationID: verification.ID}
	var keyID string
	var nonce, ciphertext []byte
	if err := admin.QueryRow(ctx, `SELECT installation_id,bootstrap_digest,email,credential_generation,contact_revision,issued_at,expires_at,key_id,nonce,ciphertext
		FROM iam.notification_contact_verifications WHERE tenant_id=$1 AND id=$2`, verification.AccountID, verification.ID).Scan(&binding.InstallationID, &binding.BootstrapDigest, &binding.Recipient, &binding.CredentialGeneration, &binding.ContactRevision, &binding.IssuedAt, &binding.ExpiresAt, &keyID, &nonce, &ciphertext); err != nil {
		t.Fatal("read synthetic process contact envelope")
	}
	binding.IssuedAt, binding.ExpiresAt = binding.IssuedAt.UTC(), binding.ExpiresAt.UTC()
	info, aad, err := iamv1.EmailVerificationCipherContext(binding, keyID)
	defer clear(info)
	defer clear(aad)
	if err != nil || keyID != "process-mail" {
		t.Fatal("invalid process contact binding")
	}
	key, err := hkdf.Key(sha256.New, bytes.Repeat([]byte{0x63}, 32), []byte("matrix.iam.email-verification.hkdf-sha256.v1"), string(info), 32)
	defer clear(key)
	if err != nil {
		t.Fatal("derive synthetic process contact key")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal("create synthetic process contact cipher")
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		t.Fatal("create synthetic process contact AEAD")
	}
	plaintext, err := aead.Open(nil, nil, append(nonce, ciphertext...), aad)
	defer clear(plaintext)
	if err != nil || len(plaintext) != 8 {
		t.Fatal("open synthetic process contact code")
	}
	return string(plaintext)
}

// The real IAM process commits the command before this proxy aborts only the
// TCP response. The captured result is test evidence, never a client retry.
func loseIAMCompletion(t *testing.T, ctx context.Context, method, endpoint, path, bearer string, intent any) processResponse {
	t.Helper()
	target, err := url.Parse(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	transport := &http.Transport{DisableKeepAlives: true, MaxConnsPerHost: 1}
	proxy.Transport = transport
	completed := make(chan processResponse, 1)
	proxy.ModifyResponse = func(response *http.Response) error {
		body, err := io.ReadAll(io.LimitReader(response.Body, 8193))
		_ = response.Body.Close()
		result := processResponse{Status: response.StatusCode, Body: body}
		if err != nil || len(body) > 8192 {
			result = processResponse{}
		}
		completed <- result
		return errors.New("synthetic lost IAM completion")
	}
	proxy.ErrorHandler = func(http.ResponseWriter, *http.Request, error) { panic(http.ErrAbortHandler) }
	lost := httptest.NewUnstartedServer(proxy)
	lost.Config.ReadHeaderTimeout, lost.Config.WriteTimeout = 5*time.Second, 10*time.Second
	lost.Start()
	defer lost.Close()
	defer transport.CloseIdleConnections()
	body, err := json.Marshal(intent)
	defer clear(body)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequestWithContext(ctx, method, lost.URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	request.Header.Set("Content-Type", "application/json")
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	response, lostErr := client.Do(request)
	if response != nil {
		_ = response.Body.Close()
	}
	if lostErr == nil {
		t.Fatal("client received a supposedly lost completion")
	}
	select {
	case result := <-completed:
		if result.Status != http.StatusOK || len(result.Body) == 0 {
			t.Fatalf("lost response did not follow an actual successful IAM command (status=%d)", result.Status)
		}
		return result
	case <-time.After(10 * time.Second):
		t.Fatal("lost reply did not reach IAM")
	case <-ctx.Done():
		t.Fatal("lost reply gate expired")
	}
	return processResponse{}
}

// These are real application resources, database-service records and reserved
// quota. The local provisioner gate separately proves a running engine.
func proveOwnSessionProcesses(t *testing.T, ctx context.Context, admin *pgx.Conn, endpoint, replicaEndpoint, auditEndpoint, paasEndpoint, homeBearer, ownerBearer string,
	withAuditOutage func(func()), restartIAM func()) []string {
	t.Helper()
	user := createIAMUser(t, endpoint, ownerBearer, "session.owner", "Session owner", initialDeveloperPassword, "process-own-user")
	realm := user.LoginName + "@" + string(user.AccountID)
	a := loginIAM(t, endpoint, realm, initialDeveloperPassword, "process-own-login-a")
	b := loginIAM(t, replicaEndpoint, realm, initialDeveloperPassword, "process-own-login-b")
	c := loginIAM(t, replicaEndpoint, realm, initialDeveloperPassword, "process-own-login-c")
	sensitive := []string{a.Credential, b.Credential, c.Credential}
	call := func(method, base, path, bearer string, body any, want int, result any) {
		t.Helper()
		response := performJSON(t, method, base+path, bearer, body)
		if response.Status != want {
			t.Fatalf("own-session process %s status=%d want=%d", path, response.Status, want)
		}
		if result != nil {
			reflect.ValueOf(result).Elem().SetZero()
			decoder := json.NewDecoder(bytes.NewReader(response.Body))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(result); err != nil {
				t.Fatal("invalid own-session response", err)
			}
		}
	}
	var page iamv1.SessionList
	call(http.MethodGet, replicaEndpoint, "/v1/auth/sessions", a.Credential, nil, http.StatusOK, &page)
	if iamv1.ValidateSessionList(page) != nil || page.CurrentSessionID != a.Session.ID || page.UserID != user.ID || len(page.Items) != 3 {
		t.Fatal("replica directory lost actual caller/owner")
	}
	call(http.MethodGet, endpoint, "/v1/auth/sessions", iamServiceCredential, nil, http.StatusUnauthorized, nil)
	intent := iamv1.RevokeSessionRequest{RequestID: "process-own-lost-reply"}
	path := "/v1/auth/sessions/" + string(b.Session.ID) + ":revoke"
	call(http.MethodPost, endpoint, path, homeBearer, intent, http.StatusForbidden, nil)
	var original iamv1.RevokeOwnSessionResponse
	var fact auditv1.Event
	var originalBytes, originalDigest string
	withAuditOutage(func() {
		response := loseIAMCompletion(t, ctx, http.MethodPost, endpoint, path, a.Credential, intent)
		if json.Unmarshal(response.Body, &original) != nil {
			t.Fatal("lost single-session reply was not a valid completion")
		}
		if iamv1.ValidateRevokeOwnSessionResponse(original) != nil || original.Outcome != "APPLIED" {
			t.Fatal("lost reply did not follow a committed self revocation")
		}
		call(http.MethodGet, replicaEndpoint, "/v1/auth/sessions", b.Credential, nil, http.StatusUnauthorized, nil)
		call(http.MethodGet, replicaEndpoint, "/v1/auth/sessions", a.Credential, nil, http.StatusOK, &page)
		if len(page.Items) != 2 {
			t.Fatal("self revocation ended an unrelated login")
		}
		call(http.MethodPost, replicaEndpoint, path, c.Credential, intent, http.StatusConflict, nil)
		var encoded []byte
		if err := admin.QueryRow(ctx, `SELECT event_document FROM iam.audit_outbox WHERE tenant_id=$1 AND event_document->>'requestId'=$2`, user.AccountID, intent.RequestID).Scan(&encoded); err != nil || json.Unmarshal(encoded, &fact) != nil {
			t.Fatal("missing committed self fact", err)
		}
		var err error
		originalBytes, originalDigest, err = auditv1.CanonicalizeEvent(auditv1.SourceIAM, fact)
		if err != nil {
			t.Fatal(err)
		}
		restartIAM()
		var replay iamv1.RevokeOwnSessionResponse
		call(http.MethodPost, endpoint, path, a.Credential, intent, http.StatusOK, &replay)
		if replay.Outcome != "EQUAL_REPLAY" || replay.Revocation != original.Revocation {
			t.Fatal("restart changed original self completion")
		}
		call(http.MethodPost, replicaEndpoint, path, a.Credential, iamv1.RevokeSessionRequest{RequestID: "process-own-different-intent"}, http.StatusConflict, nil)
		call(http.MethodPost, endpoint, "/v1/auth/logout", a.Credential, iamv1.LogoutRequest{RequestID: "process-own-exit-a"}, http.StatusOK, nil)
		call(http.MethodPost, replicaEndpoint, path, a.Credential, intent, http.StatusUnauthorized, nil)
	})
	waitAllIAMOutboxDelivered(t, ctx, admin)
	assertAuditEventCount(t, ctx, admin, string(fact.EventID), 1)
	pageOfFacts := queryAudit(t, auditEndpoint, ownerBearer, auditv1.QueryRecordsRequest{PageSize: 100, Action: auditv1.ActionIAMSessionRevoked}, http.StatusOK)
	matched := 0
	for _, record := range pageOfFacts.Records {
		if record.Event.EventID == fact.EventID {
			canonical, digest, err := auditv1.CanonicalizeEvent(auditv1.SourceIAM, record.Event)
			if err != nil || canonical != originalBytes || digest != originalDigest {
				t.Fatal("delayed delivery changed original self fact", err)
			}
			matched++
		}
	}
	if matched != 1 {
		t.Fatal("original self fact was not visible exactly once")
	}
	changePasswordIAM(t, endpoint, c.Credential, initialDeveloperPassword, changedDeveloperPassword, "process-own-password")
	createIAMPolicyAttachment(t, endpoint, ownerBearer, user.ID, iamv1.SystemPolicyPaaSDeveloper, "process-own-paas")
	d := loginIAM(t, replicaEndpoint, realm, changedDeveloperPassword, "process-own-login-d")
	sensitive = append(sensitive, d.Credential)
	operation := createPaaSApplication(t, paasEndpoint, c.Credential, "application-own-session", "own-session", "process-own-application", http.StatusCreated)
	getPaaSApplication(t, paasEndpoint, d.Credential, operation.Target.ID, http.StatusOK)
	call(http.MethodPost, replicaEndpoint, "/v1/auth/sessions/"+string(d.Session.ID)+":revoke", c.Credential, iamv1.RevokeSessionRequest{RequestID: "process-own-end-d"}, http.StatusOK, nil)
	getPaaSApplication(t, paasEndpoint, d.Credential, operation.Target.ID, http.StatusUnauthorized)
	getPaaSApplication(t, paasEndpoint, c.Credential, operation.Target.ID, http.StatusOK)
	call(http.MethodPost, endpoint, "/v1/auth/logout", c.Credential, iamv1.LogoutRequest{RequestID: "process-own-exit-c"}, http.StatusOK, nil)
	getPaaSApplication(t, paasEndpoint, ownerBearer, operation.Target.ID, http.StatusOK)
	var tenant, creator string
	if err := admin.QueryRow(ctx, `SELECT tenant_id,document#>>'{requestedBy,id}' FROM paas.operations WHERE id=$1`, operation.ID).Scan(&tenant, &creator); err != nil || tenant != string(user.AccountID) || creator != string(user.ID) {
		t.Fatal("session termination changed accepted Operation ownership", err)
	}
	waitAllIAMOutboxDelivered(t, ctx, admin)
	waitAllPaaSOutboxDelivered(t, ctx, admin)
	chain := verifyAudit(t, auditEndpoint, ownerBearer)
	if chain.State != auditv1.VerificationVerified || !chain.Complete {
		t.Fatal("session lifecycle broke its tenant chain")
	}
	return sensitive
}

func proveOtherSessionProcesses(t *testing.T, ctx context.Context, admin *pgx.Conn, endpoint, replicaEndpoint, auditEndpoint, paasEndpoint, ownerBearer string,
	withAuditOutage func(func()), restartIAM func()) []string {
	t.Helper()
	user := createIAMUser(t, endpoint, ownerBearer, "bulk.session.owner", "Bulk session owner", initialDeveloperPassword, "process-bulk-user")
	realm := user.LoginName + "@" + string(user.AccountID)
	a := loginIAM(t, endpoint, realm, initialDeveloperPassword, "process-bulk-a")
	changePasswordIAM(t, endpoint, a.Credential, initialDeveloperPassword, changedDeveloperPassword, "process-bulk-password")
	createIAMPolicyAttachment(t, endpoint, ownerBearer, user.ID, iamv1.SystemPolicyPaaSDeveloper, "process-bulk-paas")
	b := loginIAM(t, replicaEndpoint, realm, changedDeveloperPassword, "process-bulk-b")
	c := loginIAM(t, endpoint, realm, changedDeveloperPassword, "process-bulk-c")
	sensitive := []string{a.Credential, b.Credential, c.Credential}
	operation := createPaaSApplication(t, paasEndpoint, b.Credential, "application-bulk-session", "bulk-session", "process-bulk-application", http.StatusCreated)
	getPaaSApplication(t, paasEndpoint, c.Credential, operation.Target.ID, http.StatusOK)
	call := func(method, base, path, bearer string, body any, want int, result any) {
		t.Helper()
		response := performJSON(t, method, base+path, bearer, body)
		if response.Status != want {
			t.Fatalf("bulk session process %s status=%d want=%d", path, response.Status, want)
		}
		if result != nil {
			reflect.ValueOf(result).Elem().SetZero()
			decoder := json.NewDecoder(bytes.NewReader(response.Body))
			decoder.DisallowUnknownFields()
			if decoder.Decode(result) != nil {
				t.Fatal("invalid bulk session process response")
			}
		}
	}
	const path = "/v1/auth/sessions:revoke-others"
	intent := iamv1.RevokeSessionRequest{RequestID: "process-bulk-lost-reply"}
	call(http.MethodPost, endpoint, path, iamServiceCredential, intent, http.StatusUnauthorized, nil)
	var original iamv1.RevokeOtherSessionsResponse
	var fact auditv1.Event
	var originalBytes, originalDigest string
	withAuditOutage(func() {
		response := loseIAMCompletion(t, ctx, http.MethodPost, endpoint, path, a.Credential, intent)
		if json.Unmarshal(response.Body, &original) != nil || iamv1.ValidateRevokeOtherSessionsResponse(original) != nil || original.Outcome != "APPLIED" ||
			original.AccountID != user.AccountID || original.UserID != user.ID || original.CurrentSessionID != a.Session.ID || original.RevokedCount != 2 {
			t.Fatal("lost bulk reply did not reflect the committed set")
		}
		for _, ended := range []loginResult{b, c} {
			call(http.MethodGet, replicaEndpoint, "/v1/auth/sessions", ended.Credential, nil, http.StatusUnauthorized, nil)
			getPaaSApplication(t, paasEndpoint, ended.Credential, operation.Target.ID, http.StatusUnauthorized)
		}
		getPaaSApplication(t, paasEndpoint, a.Credential, operation.Target.ID, http.StatusOK)
		later := loginIAM(t, replicaEndpoint, realm, changedDeveloperPassword, "process-bulk-later")
		sensitive = append(sensitive, later.Credential)
		call(http.MethodPost, endpoint, path, later.Credential, intent, http.StatusConflict, nil)
		var encoded []byte
		if err := admin.QueryRow(ctx, `SELECT event_document FROM iam.audit_outbox WHERE tenant_id=$1 AND event_document->>'requestId'=$2
		 AND event_document->>'action'='iam.session.others-revoked'`, user.AccountID, intent.RequestID).Scan(&encoded); err != nil || json.Unmarshal(encoded, &fact) != nil {
			t.Fatal("bulk completion did not have its original outbox fact", err)
		}
		var err error
		originalBytes, originalDigest, err = auditv1.CanonicalizeEvent(auditv1.SourceIAM, fact)
		if err != nil {
			t.Fatal(err)
		}
		restartIAM()
		var replay iamv1.RevokeOtherSessionsResponse
		call(http.MethodPost, replicaEndpoint, path, a.Credential, intent, http.StatusOK, &replay)
		if replay.Outcome != "EQUAL_REPLAY" {
			t.Fatal("restart lost the bulk intent")
		}
		replay.Outcome = "APPLIED"
		if replay != original {
			t.Fatal("restart changed the original bulk count/time")
		}
		getPaaSApplication(t, paasEndpoint, later.Credential, operation.Target.ID, http.StatusOK)
		call(http.MethodPost, endpoint, "/v1/auth/logout", a.Credential, iamv1.LogoutRequest{RequestID: "process-bulk-exit"}, http.StatusOK, nil)
		call(http.MethodPost, replicaEndpoint, path, a.Credential, intent, http.StatusUnauthorized, nil)
		var access iamv1.UserAccess
		call(http.MethodGet, endpoint, "/v1/users/"+string(user.ID), ownerBearer, nil, http.StatusOK, &access)
		call(http.MethodPost, endpoint, "/v1/users/"+string(user.ID)+":set-status", ownerBearer,
			iamv1.SetUserStatusRequest{Status: iamv1.PrincipalDisabled, ResourceVersion: access.User.ResourceVersion, RequestID: "process-bulk-disable"}, http.StatusOK, nil)
		call(http.MethodGet, replicaEndpoint, "/v1/auth/sessions", later.Credential, nil, http.StatusUnauthorized, nil)
		// Current identity is now unavailable; that cannot invalidate the IAM
		// producer's proof of its already committed immutable security fact.
	})
	waitAllIAMOutboxDelivered(t, ctx, admin)
	waitAllPaaSOutboxDelivered(t, ctx, admin)
	assertAuditEventCount(t, ctx, admin, string(fact.EventID), 1)
	page := queryAudit(t, auditEndpoint, ownerBearer, auditv1.QueryRecordsRequest{PageSize: 100, Action: auditv1.ActionIAMOtherSessionsRevoked}, http.StatusOK)
	matched := 0
	for _, record := range page.Records {
		if record.Event.EventID == fact.EventID {
			canonical, digest, err := auditv1.CanonicalizeEvent(auditv1.SourceIAM, record.Event)
			if err != nil || canonical != originalBytes || digest != originalDigest {
				t.Fatal("delayed bulk fact changed its canonical history", err)
			}
			matched++
		}
	}
	if matched != 1 {
		t.Fatal("bulk history was not queried exactly once after actor disablement")
	}
	var completionCount, targetCount int
	if err := admin.QueryRow(ctx, `SELECT
	 (SELECT count(*) FROM iam.session_other_revocations WHERE tenant_id=$1 AND user_id=$2 AND request_id=$3 AND revoked_count=2),
	 (SELECT count(*) FROM iam.session_other_revocation_targets WHERE tenant_id=$1 AND user_id=$2 AND request_id=$3)`, user.AccountID, user.ID, intent.RequestID).Scan(&completionCount, &targetCount); err != nil || completionCount != 1 || targetCount != 2 {
		t.Fatal("restart/replay altered the sealed bulk set", err)
	}
	getPaaSApplication(t, paasEndpoint, ownerBearer, operation.Target.ID, http.StatusOK)
	var tenant, creator string
	if err := admin.QueryRow(ctx, `SELECT tenant_id,document#>>'{requestedBy,id}' FROM paas.operations WHERE id=$1`, operation.ID).Scan(&tenant, &creator); err != nil || tenant != string(user.AccountID) || creator != string(user.ID) {
		t.Fatal("bulk termination or identity disablement changed accepted Operation ownership", err)
	}
	chain := verifyAudit(t, auditEndpoint, ownerBearer)
	if chain.State != auditv1.VerificationVerified || !chain.Complete {
		t.Fatal("bulk session lifecycle broke the complete tenant chain")
	}
	return sensitive
}

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
	var sourcePolicy iamv1.PolicyDetail
	roleCredential := ""
	var administrativelyIssued iamv1.AssumeRoleResponse
	adminRoleCredential := ""
	discoveryCursor := ""
	hiddenRoles := map[iamv1.RoleID]bool{}
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
		for index := range iamv1.RoleDiscoveryPageSize {
			var hidden iamv1.Role
			call(http.MethodPost, iamEndpoint, "/v1/roles", roleBearer, iamv1.CreateRoleRequest{Name: fmt.Sprintf("Private discovery %02d", index),
				Tags: []iamv1.RoleTag{}, TrustPolicy: empty, RequestID: fmt.Sprintf("process-discovery-hidden-%02d", index)}, http.StatusCreated, &hidden)
			hiddenRoles[hidden.ID] = true
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
		call(http.MethodPost, iamEndpoint, "/v1/policies", roleBearer, iamv1.CreatePolicyRequest{DisplayName: "Self role assumption only", RequestID: "process-self-assume-policy",
			Document: iamv1.PolicyDocument{LanguageVersion: iamv1.PolicyLanguageVersion, Scope: iamv1.AuthorityScopeTenant,
				Statements: []iamv1.PolicyStatement{{SID: "assume", Effect: iamv1.PolicyAllow, Actions: []iamv1.Action{iamv1.ActionIAMRoleAssume},
					Resources: []iamv1.PolicyResourceSelector{{Kind: iamv1.ResourceRole, Match: iamv1.PolicyResourceAnyInAuthority}}}}}}, http.StatusCreated, &sourcePolicy)
		var sourceGrant iamv1.PolicyAttachment
		call(http.MethodPost, iamEndpoint, "/v1/policy-attachments", roleBearer, iamv1.CreatePolicyAttachmentRequest{
			Target: iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetUser, ID: string(user.ID)}, PolicyID: sourcePolicy.Policy.ID,
			PolicyResourceVersion: sourcePolicy.Policy.ResourceVersion, RequestID: "process-role-assume-grant"}, http.StatusOK, &sourceGrant)
		call(http.MethodGet, iamEndpoint, "/v1/roles", member.Credential, nil, http.StatusForbidden, nil)
		call(http.MethodGet, replicaEndpoint, path, member.Credential, nil, http.StatusForbidden, nil)
		var first, second iamv1.AssumableRoleList
		call(http.MethodGet, iamEndpoint, "/v1/auth/assumable-roles", member.Credential, nil, http.StatusOK, &first)
		discoveryCursor = first.NextAfter
		if discoveryCursor == "" || first.AccountID != tenant || first.SourceUserID != user.ID {
			t.Fatal("self discovery did not return its bounded private continuation")
		}
		call(http.MethodGet, replicaEndpoint, "/v1/auth/assumable-roles?after="+discoveryCursor, member.Credential, nil, http.StatusOK, &second)
		if second.NextAfter != "" || len(first.Items)+len(second.Items) != 1 {
			t.Fatal("replica discovery omitted or duplicated an eligible role")
		}
		for _, item := range append(first.Items, second.Items...) {
			if item.RoleID != role.ID || item.AccountID != tenant || !item.Capability.Available || item.ResourceVersion != boundary.ResourceVersion {
				t.Fatal("self discovery leaked a filtered role or changed current eligibility")
			}
		}
		call(http.MethodGet, replicaEndpoint, "/v1/auth/assumable-roles?after="+discoveryCursor, homeBearer, nil, http.StatusUnprocessableEntity, nil)
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
		call(http.MethodGet, replicaEndpoint, "/v1/account/security-settings", roleCredential, nil, http.StatusUnauthorized, nil)
		call(http.MethodGet, replicaEndpoint, "/v1/users/"+string(member.Session.PrincipalID)+"/password-resets/role-cannot-query?resourceVersion=1", roleCredential, nil, http.StatusUnauthorized, nil)
		call(http.MethodPost, replicaEndpoint, "/v1/auth/sessions:revoke-others", roleCredential,
			iamv1.RevokeSessionRequest{RequestID: "process-role-cannot-end-user-logins"}, http.StatusUnauthorized, nil)
		call(http.MethodGet, iamEndpoint, "/v1/auth/sessions", member.Credential, nil, http.StatusOK, nil)
		for _, endpoint := range []string{iamEndpoint, replicaEndpoint} {
			var current iamv1.CurrentRoleIdentity
			call(http.MethodGet, endpoint, "/v1/auth/role-session", roleCredential, nil, http.StatusOK, &current)
			if iamv1.ValidateCurrentRoleIdentity(current) != nil || !reflect.DeepEqual(current.Session, issued.Session) ||
				current.Role.ID != role.ID || current.Role.Name != role.Name || current.SourceUser.ID != user.ID ||
				current.SourceUser.LoginName != user.LoginName || current.SourceUser.DisplayName != user.DisplayName {
				t.Fatal("replica current role display identity differs")
			}
		}
		getPaaSApplication(t, paasEndpoint, roleCredential, operation.Target.ID, http.StatusOK)
		createPaaSApplication(t, paasEndpoint, roleCredential, "application-readonly-role-denied", "readonly-role-denied", "readonly-role-create", http.StatusForbidden)
		assertPaaSApplicationAbsent(t, ctx, admin, "application-readonly-role-denied")
		// Separate issuance retains the original source self-revocation gate.
		assume.RequestID = "process-admin-session-issue"
		call(http.MethodPost, replicaEndpoint, path+":assume", member.Credential, assume, http.StatusOK, &administrativelyIssued)
		adminBytes := administrativelyIssued.Credential.CopyBytes()
		adminRoleCredential = string(adminBytes)
		clear(adminBytes)
		getPaaSApplication(t, paasEndpoint, adminRoleCredential, operation.Target.ID, http.StatusOK)
		managedPath := path + "/sessions/" + string(administrativelyIssued.Session.ID)
		call(http.MethodGet, replicaEndpoint, path+"/sessions", member.Credential, nil, http.StatusForbidden, nil)
		call(http.MethodGet, replicaEndpoint, managedPath, homeBearer, nil, http.StatusForbidden, nil)
		var managedPage iamv1.RoleSessionList
		call(http.MethodGet, iamEndpoint, path+"/sessions", roleBearer, nil, http.StatusOK, &managedPage)
		if len(managedPage.Items) != 2 || managedPage.AccountID != tenant || managedPage.RoleID != role.ID {
			t.Fatal("real session directory lost role ownership")
		}
		var administrativeRevocation, administrativeReplay iamv1.RevokeRoleSessionResponse
		adminIntent := iamv1.RevokeRoleSessionRequest{RequestID: "process-admin-session-revoke"}
		call(http.MethodPost, replicaEndpoint, managedPath+":revoke", roleBearer, adminIntent, http.StatusOK, &administrativeRevocation)
		call(http.MethodPost, iamEndpoint, managedPath+":revoke", roleBearer, adminIntent, http.StatusOK, &administrativeReplay)
		if administrativeRevocation.Outcome != "APPLIED" || administrativeReplay.Outcome != "EQUAL_REPLAY" || !reflect.DeepEqual(administrativeRevocation.Session, administrativeReplay.Session) {
			t.Fatal("replicas changed administrative terminal intent")
		}
		for _, endpoint := range []string{iamEndpoint, replicaEndpoint} {
			var precise iamv1.RoleSessionAccess
			call(http.MethodGet, endpoint, managedPath, roleBearer, nil, http.StatusOK, &precise)
			if precise.Item.Lifecycle != iamv1.RoleSessionRevoked || precise.Item.RevokeCapability.Available {
				t.Fatal("replica observation retained revoked capability")
			}
			call(http.MethodGet, endpoint, "/v1/auth/role-session", adminRoleCredential, nil, http.StatusUnauthorized, nil)
		}
		getPaaSApplication(t, paasEndpoint, adminRoleCredential, operation.Target.ID, http.StatusUnauthorized)
		call(http.MethodPost, replicaEndpoint, "/v1/policy-attachments/"+string(sourceGrant.ID)+":revoke", roleBearer,
			iamv1.RevokePolicyAttachmentRequest{ResourceVersion: sourceGrant.ResourceVersion, RequestID: "process-role-assume-revoke"}, http.StatusOK, nil)
		for _, endpoint := range []string{iamEndpoint, replicaEndpoint} {
			call(http.MethodGet, endpoint, "/v1/auth/role-session", roleCredential, nil, http.StatusUnauthorized, nil)
			call(http.MethodGet, endpoint, "/v1/auth/assumable-roles?after="+discoveryCursor, member.Credential, nil, http.StatusUnprocessableEntity, nil)
			var current iamv1.AssumableRoleList
			call(http.MethodGet, endpoint, "/v1/auth/assumable-roles", member.Credential, nil, http.StatusOK, &current)
			if len(current.Items) != 0 {
				t.Fatal("replica discovery retained revoked source permission")
			}
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
	policyQuery := auditv1.QueryRecordsRequest{PageSize: 100, Action: auditv1.ActionIAMPolicyCreated}
	policyFacts := 0
	for pages := 0; ; pages++ {
		if pages == 16 {
			t.Fatal("policy history exceeded the process fixture's bounded directory")
		}
		policyHistory := queryAudit(t, auditEndpoint, ownerBearer, policyQuery, http.StatusOK)
		if policyHistory.TenantID != tenant {
			t.Fatal("policy history crossed tenant authority")
		}
		for _, record := range policyHistory.Records {
			if record.Event.Target.ID != string(sourcePolicy.Policy.ID) {
				continue
			}
			policyFacts++
			if record.Source != auditv1.SourceIAM || record.Event.RequestID != "process-self-assume-policy" || record.Event.Actor.ID != auditv1.ActorID(actor.User.ID) {
				t.Fatal("self assumption policy lost its precise immutable tenant provenance")
			}
		}
		if policyHistory.NextCursor == "" {
			break
		}
		policyQuery.Cursor = policyHistory.NextCursor
	}
	if policyFacts != 1 {
		t.Fatal("self assumption policy fact was missing or duplicated")
	}
	for _, action := range []auditv1.Action{auditv1.ActionIAMRoleCreated, auditv1.ActionIAMRoleUpdated, auditv1.ActionIAMRoleDisabled, auditv1.ActionIAMRoleEnabled, auditv1.ActionIAMRoleTrustSet, auditv1.ActionIAMRoleDeleted,
		auditv1.ActionIAMRolePermissionBoundarySet, auditv1.ActionIAMRolePermissionBoundaryRemoved} {
		page := queryAudit(t, auditEndpoint, ownerBearer, auditv1.QueryRecordsRequest{PageSize: 100, Action: action}, http.StatusOK)
		expected := 1
		if action == auditv1.ActionIAMRoleCreated {
			expected += len(hiddenRoles)
		}
		if page.TenantID != tenant || len(page.Records) != expected || page.NextCursor != "" {
			t.Fatalf("role action %s did not append exactly the submitted tenant facts", action)
		}
		var event auditv1.Event
		seen := map[string]bool{}
		for _, record := range page.Records {
			fact := record.Event
			if record.Source != auditv1.SourceIAM || fact.Target.Kind != auditv1.TargetRole || fact.Actor.Type != auditv1.ActorUser ||
				fact.Actor.ID != auditv1.ActorID(actor.User.ID) || fact.IAMDecisionID == "" || fact.InstallationID != "" || seen[fact.Target.ID] {
				t.Fatal("role fact changed current tenant, USER or final target proof")
			}
			seen[fact.Target.ID] = true
			if fact.Target.ID == string(role.ID) {
				event = fact
			} else if action != auditv1.ActionIAMRoleCreated || !hiddenRoles[iamv1.RoleID(fact.Target.ID)] {
				t.Fatal("role history included an unsubmitted target")
			}
		}
		if event.EventID == "" {
			t.Fatal("original role history was lost among private discovery candidates")
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
	for _, action := range []auditv1.Action{auditv1.ActionIAMRoleSessionIssued, auditv1.ActionIAMRoleSessionRevoked, auditv1.ActionIAMRoleSessionAdminRevoked} {
		page := queryAudit(t, auditEndpoint, ownerBearer, auditv1.QueryRecordsRequest{PageSize: 100, Action: action}, http.StatusOK)
		expected := 1
		if action == auditv1.ActionIAMRoleSessionIssued {
			expected = 2
		}
		if page.TenantID != tenant || len(page.Records) != expected {
			t.Fatal("role issuance fact did not reach its tenant chain", action)
		}
		for _, record := range page.Records {
			event := record.Event
			expectedActor, expectedSession := auditv1.ActorID(user.ID), string(issued.Session.ID)
			if action == auditv1.ActionIAMRoleSessionAdminRevoked {
				expectedActor, expectedSession = auditv1.ActorID(actor.User.ID), string(administrativelyIssued.Session.ID)
			}
			if action == auditv1.ActionIAMRoleSessionIssued && event.Target.ID == string(administrativelyIssued.Session.ID) {
				expectedSession = event.Target.ID
			}
			if event.Actor.Type != auditv1.ActorUser || event.Actor.ID != expectedActor || event.Target.Kind != auditv1.TargetRoleSession ||
				event.Target.ID != expectedSession || (event.IAMDecisionID != "") != (action != auditv1.ActionIAMRoleSessionRevoked) {
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
	}
	restartIAM()
	for _, endpoint := range []string{iamEndpoint, replicaEndpoint} {
		call(http.MethodGet, endpoint, "/v1/roles/"+string(role.ID), ownerBearer, nil, http.StatusForbidden, nil)
		call(http.MethodPost, endpoint, "/v1/roles", ownerBearer, create, http.StatusConflict, nil)
		call(http.MethodGet, endpoint, "/v1/roles/"+string(home.ID), homeBearer, nil, http.StatusOK, nil)
		call(http.MethodGet, endpoint, "/v1/auth/me", roleBearer, nil, http.StatusUnauthorized, nil)
		var terminal iamv1.RoleSessionAccess
		call(http.MethodGet, endpoint, "/v1/roles/"+string(role.ID)+"/sessions/"+string(administrativelyIssued.Session.ID), ownerBearer, nil, http.StatusOK, &terminal)
		if terminal.Item.Lifecycle != iamv1.RoleSessionRevoked || terminal.Item.Session.ID != administrativelyIssued.Session.ID {
			t.Fatal("restart or role tombstone lost the administrative terminal record")
		}
		call(http.MethodGet, endpoint, "/v1/auth/role-session", adminRoleCredential, nil, http.StatusUnauthorized, nil)
	}
	currentSource := loginIAM(t, replicaEndpoint, "role.candidate@"+tenant, changedDeveloperPassword, "process-role-source-relogin")
	call(http.MethodGet, iamEndpoint, "/v1/auth/assumable-roles?after="+discoveryCursor, currentSource.Credential, nil, http.StatusUnprocessableEntity, nil)
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
	sensitive := []string{member.Credential, roleCredential, adminRoleCredential, currentSource.Credential}
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

func proveAccountSecuritySettingsProcesses(t *testing.T, ctx context.Context, database *pgx.Conn, endpoint, replica, auditEndpoint, platform, owner string, member loginResult, restartIAM func()) {
	t.Helper()
	const path = "/v1/account/security-settings"
	const requirementsPath = "/v1/auth/password-requirements"
	readRequirements := func(address, credential, source string) iamv1.PasswordRequirements {
		t.Helper()
		response := performJSON(t, http.MethodGet, address+requirementsPath, credential, nil)
		var result iamv1.PasswordRequirements
		if response.Status != http.StatusOK || json.Unmarshal(response.Body, &result) != nil ||
			result.Source != source || result.SettingsVersion != 1 || result.Password != (iamv1.AccountPasswordSettings{ExpiryMode: iamv1.PasswordExpiryChange, MinimumLength: 15, HistoryCount: 1}) {
			t.Fatal("real process did not return this identity's effective password rules")
		}
		return result
	}
	for _, address := range []string{endpoint, replica} {
		readRequirements(address, platform, "PROTECTED_IDENTITY")
		readRequirements(address, owner, "PROTECTED_IDENTITY")
		readRequirements(address, member.Credential, "ACCOUNT")
		if response := performJSON(t, http.MethodGet, address+requirementsPath+"?userId="+string(member.Session.PrincipalID), owner, nil); response.Status != http.StatusBadRequest {
			t.Fatal("real self requirements endpoint accepts another USER selector")
		}
		if response := performJSON(t, http.MethodGet, address+requirementsPath, "", nil); response.Status != http.StatusUnauthorized {
			t.Fatal("password rules disclosed before authentication")
		}
	}
	for _, credential := range []string{platform, owner, member.Credential} {
		if response := performJSON(t, http.MethodGet, endpoint+path, credential, nil); response.Status != http.StatusForbidden {
			t.Fatal("existing runtime policy automatically gained security settings read")
		}
	}
	response := performJSON(t, http.MethodPost, endpoint+"/v1/policies", owner, iamv1.CreatePolicyRequest{
		DisplayName: "Process settings reader", RequestID: "process-settings-policy",
		Document: iamv1.PolicyDocument{LanguageVersion: iamv1.PolicyLanguageVersion, Scope: iamv1.AuthorityScopeTenant,
			Statements: []iamv1.PolicyStatement{{SID: "settings", Effect: iamv1.PolicyAllow, Actions: []iamv1.Action{iamv1.ActionIAMSecuritySettingsRead},
				Resources: []iamv1.PolicyResourceSelector{{Kind: iamv1.ResourceAccount, Match: iamv1.PolicyResourceExact, ID: string(member.Session.AccountID)}}}}}})
	var policy iamv1.PolicyDetail
	if response.Status != http.StatusCreated || json.Unmarshal(response.Body, &policy) != nil {
		t.Fatal("real process could not publish settings policy")
	}
	attachment := createIAMPolicyAttachment(t, endpoint, owner, member.Session.PrincipalID, policy.Policy.ID, "process-settings-grant")
	var initial iamv1.AccountSecuritySettings
	for _, address := range []string{endpoint, replica} {
		response := performJSON(t, http.MethodGet, address+path, member.Credential, nil)
		var settings iamv1.AccountSecuritySettings
		if response.Status != http.StatusOK || json.Unmarshal(response.Body, &settings) != nil || iamv1.ValidateAccountSecuritySettings(settings) != nil ||
			settings.AccountID != member.Session.AccountID || settings.MFA.RequiredForUsers || settings.ResourceVersion != 1 {
			t.Fatal("independent settings replica did not read the actual same Account")
		}
		if initial.AccountID != "" && !reflect.DeepEqual(settings, initial) {
			t.Fatal("independent settings replicas disagree")
		}
		initial = settings
	}
	var decisionID string
	if err := database.QueryRow(ctx, `SELECT id FROM iam.authorization_decisions WHERE tenant_id=$1 AND principal_id=$2
		AND action_name='iam.security-settings.read' AND allowed ORDER BY decided_at,id LIMIT 1`, member.Session.AccountID, member.Session.PrincipalID).Scan(&decisionID); err != nil {
		t.Fatal("real settings request lost its original authority decision")
	}
	restartIAM()
	response = performJSON(t, http.MethodGet, endpoint+path, member.Credential, nil)
	var after iamv1.AccountSecuritySettings
	if response.Status != http.StatusOK || json.Unmarshal(response.Body, &after) != nil || !reflect.DeepEqual(after, initial) {
		t.Fatal("settings or original grant changed after IAM process restart")
	}
	readRequirements(endpoint, member.Credential, "ACCOUNT")
	revokeIAMPolicyAttachment(t, replica, owner, attachment.ID, attachment.ResourceVersion, "process-settings-revoke")
	for _, address := range []string{endpoint, replica} {
		if response := performJSON(t, http.MethodGet, address+path, member.Credential, nil); response.Status != http.StatusForbidden {
			t.Fatal("another process retained revoked settings permission")
		}
		readRequirements(address, member.Credential, "ACCOUNT")
	}
	waitAllIAMOutboxDelivered(t, ctx, database)
	page := queryAudit(t, auditEndpoint, owner, auditv1.QueryRecordsRequest{PageSize: 100, Action: auditv1.ActionIAMAuthorizationDecided,
		Actor: &auditv1.ActorReference{Type: auditv1.ActorUser, ID: auditv1.ActorID(member.Session.PrincipalID)}}, http.StatusOK)
	found := false
	for _, record := range page.Records {
		if record.Event.IAMDecisionID == auditv1.DecisionID(decisionID) {
			found = record.Event.TenantID == auditv1.TenantID(member.Session.AccountID)
		}
	}
	if !found {
		t.Fatal("settings historical decision failed real producer proof/outbox/Audit delivery after revocation")
	}
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
	oldPlatformCredential := platform.Credential
	createIAMPolicyAttachment(t, iamEndpoint, homeBearer, platformUser.ID, iamv1.SystemPolicyPlatformOperator, "request-resource-platform-role")
	if response := performJSON(t, http.MethodGet, iamEndpoint+"/v1/auth/me", oldPlatformCredential, nil); response.Status != http.StatusUnauthorized {
		t.Fatal("platform protection grant left the original Session usable")
	}
	platform = loginIAM(t, iamEndpoint, "resource.platform@organization-process", changedDeveloperPassword, "request-resource-platform-reauthenticated")
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
	return tenants[1].quota, tenants[1].shared, append(applicationValues, home.Credential, oldPlatformCredential, platform.Credential)
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
	// This gate starts with a clean database; every synthetic TOTP seed is
	// generated by its real IAM process. An immutable fact already committed
	// before the first seed cannot disclose a later random code through an ID.
	// Bind that exception to the whole original event, not an ID-shaped string
	// or a caller timestamp. All long credentials and free-form fields still
	// receive the normal scan, including in copies delivered to Audit later.
	beforeOTP := make(map[string]struct{})
	earlier, err := admin.Query(ctx, `SELECT o.event_document FROM iam.audit_outbox o
		WHERE o.created_at < (SELECT min(created_at) FROM iam.totp_authenticators)
		AND (o.event_document->>'occurredAt')::timestamptz < (SELECT min(created_at) FROM iam.totp_authenticators)`)
	if err != nil {
		t.Fatal("read synthetic OTP chronology")
	}
	for earlier.Next() {
		var raw []byte
		var event auditv1.Event
		if earlier.Scan(&raw) != nil || auditv1.DecodeRequest(bytes.NewReader(raw), &event) != nil {
			t.Fatal("invalid original pre-OTP event")
		}
		_, digest, err := auditv1.CanonicalizeEvent(auditv1.SourceIAM, event)
		if err != nil {
			t.Fatal("invalid pre-OTP event source")
		}
		beforeOTP[digest] = struct{}{}
	}
	earlier.Close()
	if earlier.Err() != nil {
		t.Fatal("incomplete synthetic OTP chronology")
	}
	rows, err := admin.Query(ctx, `SELECT 'iam.outbox',event_document::text FROM iam.audit_outbox
		UNION ALL SELECT 'paas.outbox',document::text FROM paas.audit_outbox
		UNION ALL SELECT 'paas.operation',document::text FROM paas.operations
		UNION ALL SELECT 'managedservice.outbox',document::text FROM managedservice.audit_outbox
		UNION ALL SELECT 'managedservice.operation',row_to_json(o)::text FROM managedservice.operations o
		UNION ALL SELECT 'audit.document',event_document::text FROM audit.records
		UNION ALL SELECT 'audit.canonical',canonical_document FROM audit.records
		UNION ALL SELECT 'iam.local-recovery',row_to_json(r)::text FROM iam.local_credential_recoveries r`)
	if err != nil {
		t.Fatal("inspect authority plaintext storage")
	}
	defer rows.Close()
	for rows.Next() {
		var source, document string
		if rows.Scan(&source, &document) != nil {
			t.Fatal("read authority plaintext inspection")
		}
		location, err := authorityPlaintextLocation(document, beforeOTP, plaintexts...)
		if err != nil {
			t.Fatal("invalid authority plaintext inspection")
		}
		if location != "" {
			var event auditv1.Event
			if json.Unmarshal([]byte(document), &event) == nil && auditv1.ValidateEvent(event) == nil {
				t.Fatalf("authority stored plaintext credential: source=%s location=%s action=%s targetKind=%s", source, location, event.Action, event.Target.Kind)
			}
			t.Fatalf("authority stored plaintext credential: source=%s location=%s", source, location)
		}
	}
	if rows.Err() != nil {
		t.Fatal("authority plaintext inspection incomplete")
	}
}

// Decode strings before scanning: JSON escapes must not hide a credential,
// and SQL LIKE metacharacters in a credential are literal, not wildcards.
// A six-digit substring in a contract-valid Audit requestDigest is not
// disclosure. Exact pre-seed events may also contain that later code in an
// already published identifier. Neither exception applies to arbitrary text,
// an exact code value, a changed event or any longer credential.
// Diagnostic paths contain only fixed contract field names. Unknown keys and
// array positions are redacted: neither a leaked key nor its value may enter
// the failure message, including low-entropy OTPs and their fingerprints.
func authorityPlaintextLocation(document string, beforeOTP map[string]struct{}, plaintexts ...string) (string, error) {
	for _, plaintext := range plaintexts {
		if plaintext == "" {
			return "", errors.New("empty plaintext inspection input")
		}
	}
	decoder := json.NewDecoder(strings.NewReader(document))
	decoder.UseNumber()
	var value any
	if decoder.Decode(&value) != nil || decoder.Decode(new(any)) != io.EOF {
		return "", errors.New("invalid plaintext inspection document")
	}
	matchKind := "credential"
	contains := func(text string, unrelatedCode bool) bool {
		for _, plaintext := range plaintexts {
			if !strings.Contains(text, plaintext) {
				continue
			}
			if len(plaintext) == 6 && strings.IndexFunc(plaintext, func(r rune) bool { return r < '0' || r > '9' }) == -1 {
				if unrelatedCode && text != plaintext {
					continue
				}
				matchKind = "six-digit-substring"
				if text == plaintext {
					matchKind = "six-digit-value"
				}
			}
			return true
		}
		return false
	}
	var inspect func(any, bool, bool, string) string
	inspect = func(value any, unrelatedCode, earlierIdentity bool, path string) string {
		switch item := value.(type) {
		case map[string]any:
			validEvent, earlierEvent := false, false
			if item["apiVersion"] == auditv1.APIVersion && item["kind"] == "AuditEvent" {
				encoded, err := json.Marshal(item)
				var event auditv1.Event
				validEvent = err == nil && auditv1.DecodeRequest(bytes.NewReader(encoded), &event) == nil && auditv1.ValidateEvent(event) == nil
				if validEvent {
					_, digest, err := auditv1.CanonicalizeEvent(auditv1.SourceIAM, event)
					_, known := beforeOTP[digest]
					earlierEvent = err == nil && known
				}
			}
			for key, child := range item {
				if contains(key, false) {
					return path + ".[key]"
				}
				field := "[member]"
				switch key {
				case "apiVersion", "kind", "eventId", "tenantId", "installationId", "actor", "type", "id", "action", "target", "result",
					"requestDigest", "requestId", "correlationId", "occurredAt", "iamDecisionId", "operationId", "data":
					field = key
				}
				ignoreCode := (validEvent && key == "requestDigest") ||
					(earlierEvent && (key == "eventId" || key == "iamDecisionId")) || (earlierIdentity && key == "id")
				if location := inspect(child, ignoreCode, earlierEvent && (key == "actor" || key == "target"), path+"."+field); location != "" {
					return location
				}
			}
		case []any:
			for _, child := range item {
				if location := inspect(child, false, false, path+"[*]"); location != "" {
					return location
				}
			}
		case string:
			if contains(item, unrelatedCode) {
				return path
			}
		case json.Number:
			if contains(item.String(), false) {
				return path
			}
		}
		return ""
	}
	location := inspect(value, false, false, "$")
	if location != "" {
		location += " (" + matchKind + ")"
	}
	return location, nil
}

func TestAuthorityPlaintextInspection(t *testing.T) {
	code := "123456"
	event := auditv1.Event{APIVersion: auditv1.APIVersion, Kind: "AuditEvent", EventID: "event-secret-inspection", TenantID: "account-one",
		Actor: auditv1.ActorReference{Type: auditv1.ActorUser, ID: "user-one"}, Action: auditv1.ActionIAMAuthenticatorBound,
		Target: auditv1.TargetReference{Kind: auditv1.TargetPrincipal, ID: "user-one"}, Result: auditv1.ResultSucceeded,
		RequestDigest: "sha256:" + strings.Repeat("a", 58) + code, RequestID: "request-one", CorrelationID: "request-one",
		OccurredAt: time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC)}
	canonical, _, err := auditv1.CanonicalizeEvent(auditv1.SourceIAM, event)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, document, plaintext string
		present, invalid          bool
	}{
		{"code-in-request-digest", string(encoded), code, false, false},
		{"code-in-canonical-request-digest", canonical, code, false, false},
		{"plaintext-code", `{"code":"123456"}`, code, true, false},
		{"numeric-code", `{"code":123456}`, code, true, false},
		{"embedded-code", `{"message":"received code 123456"}`, code, true, false},
		{"nested-code", `{"items":[{"code":"123456"}]}`, code, true, false},
		{"key-disclosure", `{"123456":"value"}`, code, true, false},
		{"nested-secret-key", `{"secret-123456":{"value":"123456"}}`, code, true, false},
		{"nested-array-secret-key", `{"items":[{"secret-123456":"123456"}]}`, code, true, false},
		{"escaped-string", `{"password":"literal\u005fpercent%password"}`, "literal_percent%password", true, false},
		{"literal-not-wildcard", `{"password":"literalXpercentYpassword"}`, "literal_percent%password", false, false},
		{"digest-in-another-field", `{"password":"` + event.RequestDigest + `"}`, code, true, false},
		{"unproved-digest-shape", `{"requestDigest":"` + event.RequestDigest + `"}`, code, true, false},
		{"malformed-audit-digest", strings.Replace(string(encoded), event.RequestDigest, "sha256:"+code, 1), code, true, false},
		{"additional-audit-disclosure", strings.Replace(string(encoded), `"request-one"`, `"request-123456"`, 1), code, true, false},
		{"full-digest-material", string(encoded), event.RequestDigest, true, false},
		{"empty-input", `{}`, "", false, true},
		{"invalid-json", `{"code":`, code, false, true},
		{"trailing-json", `{} {}`, code, false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			location, err := authorityPlaintextLocation(test.document, nil, test.plaintext)
			present := location != ""
			if (err != nil) != test.invalid || present != test.present {
				t.Fatalf("plaintext inspection: present=%t invalid=%t", present, err != nil)
			}
			if test.plaintext != "" && strings.Contains(location, test.plaintext) {
				t.Fatal("plaintext inspection diagnostic disclosed its input")
			}
		})
	}
	t.Run("pre-seed-identifier-provenance", func(t *testing.T) {
		prior := event
		prior.Target.ID = "principal-" + strings.Repeat("a", 26) + code
		prior.Actor.ID = auditv1.ActorID(prior.Target.ID)
		original, err := json.Marshal(prior)
		if err != nil {
			t.Fatal(err)
		}
		canonical, digest, err := auditv1.CanonicalizeEvent(auditv1.SourceIAM, prior)
		if err != nil {
			t.Fatal(err)
		}
		known := map[string]struct{}{digest: {}}
		for _, test := range []struct {
			name, document, plaintext string
			proof                     map[string]struct{}
			present                   bool
		}{
			{"original-before-seed", string(original), code, known, false},
			{"exact-canonical-copy", canonical, code, known, false},
			{"same-id-without-origin", string(original), code, nil, true},
			{"changed-request", strings.Replace(string(original), "request-one", "request-other", 1), code, known, true},
			{"changed-time", strings.Replace(string(original), "2026-09-24", "2026-09-25", 1), code, known, true},
			{"unknown-field", strings.TrimSuffix(string(original), "}") + `,"extra":"123456"}`, code, known, true},
			{"outer-disclosure", `{"event":` + string(original) + `,"message":"123456"}`, code, known, true},
			{"not-a-short-code", string(original), prior.Target.ID, known, true},
		} {
			t.Run(test.name, func(t *testing.T) {
				location, err := authorityPlaintextLocation(test.document, test.proof, test.plaintext)
				if err != nil || (location != "") != test.present || strings.Contains(location, test.plaintext) {
					t.Fatal("pre-seed origin widened the plaintext exception")
				}
			})
		}
		for _, field := range []string{"target", "request"} {
			current := prior
			if field == "target" {
				current.Target.ID = code
				current.Actor.ID = auditv1.ActorID(code)
			} else {
				current.RequestID = "request-" + code
			}
			_, commitment, err := auditv1.CanonicalizeEvent(auditv1.SourceIAM, current)
			encoded, marshalErr := json.Marshal(current)
			location, scanErr := authorityPlaintextLocation(string(encoded), map[string]struct{}{commitment: {}}, code)
			if err != nil || marshalErr != nil || scanErr != nil || location == "" {
				t.Fatal("pre-seed origin exempted exact code or request text")
			}
		}
	})
}

func assertProcessOutputsSanitized(
	t *testing.T,
	children []*childProcess,
	plaintexts ...string,
) {
	t.Helper()
	plaintexts = append(plaintexts, base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x57}, 32)),
		base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x74}, 32)))
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
		{"matrix_iam_authentication_recovery_login", "matrix_iam_authentication_recovery"},
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
		{"matrix_iam_authentication_recovery_login", "SELECT * FROM audit.readiness()"},
		{"matrix_iam_authentication_recovery_login", "SELECT * FROM paas.readiness()"},
		{"matrix_iam_authentication_recovery_login", "SELECT * FROM iam.bootstrap_status()"},
		{"matrix_iam_authentication_recovery_login", "SET ROLE matrix_iam_api"},
		{"matrix_iam_authentication_recovery_login", "SET ROLE matrix_iam_worker"},
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
	value.Host = net.JoinHostPort(admin.Host, strconv.Itoa(int(admin.Port)))
	value.Path, value.RawPath = "/"+admin.Database, ""
	query := value.Query()
	for _, selector := range []string{"user", "password", "host", "hostaddr", "port", "dbname", "database"} {
		query.Del(selector)
	}
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
			t.Fatalf("running authority %s did not use its bounded non-superuser database login (connections=%d confined=%t queryError=%t)", user, connections, confined, err != nil)
		}
	}
}

// Synthetic test custody, never an installation generator. The caller passes
// this file only to IAM network executables with this exact custody contract,
// never to an older unsupported predecessor, migrator, local-recovery entry,
// dispatcher or product service.
func writeProcessAccessKeyWrapping(t *testing.T, directory string, bootstrap iamv1.BootstrapDocument) string {
	t.Helper()
	digest, err := iamv1.BootstrapDigest(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	keyring := iamv1.AccessKeyWrappingKeyring{APIVersion: iamv1.APIVersion, Kind: "AccessKeyWrappingKeyring", Purpose: iamv1.AccessKeyWrappingPurpose,
		Scope: iamv1.AccessKeyWrappingScope{InstallationID: bootstrap.InstallationID, BootstrapDigest: digest}, ActiveWrappingKeyID: "process-wrapping",
		Keys: []iamv1.AccessKeyWrappingKey{{WrappingKeyID: "process-wrapping", FormatVersion: 1,
			KeyMaterial: processSecret(t, base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x57}, 32)))}}}
	encoded, err := iamv1.EncodeAccessKeyWrappingKeyring(keyring)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	return writeProtectedFile(t, directory, "iam-access-key-wrapping.json", encoded)
}

func writeProcessTOTPKeyring(t *testing.T, directory string, bootstrap iamv1.BootstrapDocument) string {
	t.Helper()
	digest, err := iamv1.BootstrapDigest(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	keyring := iamv1.TOTPKeyring{APIVersion: iamv1.APIVersion, Kind: "TOTPKeyring", Purpose: iamv1.TOTPWrappingPurpose,
		Scope:          iamv1.TOTPWrappingScope{InstallationID: bootstrap.InstallationID, BootstrapDigest: digest},
		KeysetRevision: 1, ActiveKeyID: "process-totp", Keys: []iamv1.TOTPWrappingKey{{KeyID: "process-totp", FormatVersion: 1,
			KeyMaterial: processSecret(t, base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x74}, 32)))}}}
	encoded, err := iamv1.EncodeTOTPKeyring(keyring)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	return writeProtectedFile(t, directory, "iam-totp-keyring.json", encoded)
}

func writeProcessEmailVerificationKeyring(t *testing.T, directory string, bootstrap iamv1.BootstrapDocument) string {
	t.Helper()
	digest, err := iamv1.BootstrapDigest(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	keyring := iamv1.EmailVerificationKeyring{APIVersion: iamv1.APIVersion, Kind: "EmailVerificationKeyring", Purpose: iamv1.EmailVerificationWrappingPurpose,
		Scope:          iamv1.SecurityMailInstallationScope{InstallationID: bootstrap.InstallationID, BootstrapDigest: digest},
		KeysetRevision: 1, ActiveKeyID: "process-mail", Keys: []iamv1.EmailVerificationWrappingKey{{KeyID: "process-mail", FormatVersion: 1,
			KeyMaterial: processSecret(t, base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x63}, 32)))}}}
	encoded, err := iamv1.EncodeEmailVerificationKeyring(keyring)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	return writeProtectedFile(t, directory, "iam-email-keyring.json", encoded)
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
