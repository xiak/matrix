package integration

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	installationv1 "github.com/xiak/matrix/api/adapter/installation/v1"
	auditv1 "github.com/xiak/matrix/api/audit/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	iampostgres "github.com/xiak/matrix/app/service/iam/internal/data/postgres"
	"github.com/xiak/matrix/app/service/iam/internal/usecase/authenticationrecovery"
	"github.com/xiak/matrix/app/service/iam/internal/usecase/identityaccess"
	iammigration "github.com/xiak/matrix/app/service/iam/migration"
)

const authenticationRecoveryTestRole = "matrix_iam_authentication_recovery_test"

// TestIAMAuthenticationRecoveryPostgres proves the database half of a
// destructive restore with two independent authorities. The restored database
// deliberately starts from the pre-close state: installation custody must
// reconcile the exact source closure before any API transaction can run, and
// only the matching one-shot reopen may make it usable again.
//
// This is not the installation backup/restore acceptance gate. That later gate
// must run the signed processes and a real populated dump. Keeping this focused
// gate separate makes the IAM transaction and its least-privilege identity
// independently reproducible on PostgreSQL 18.
func TestIAMAuthenticationRecoveryPostgres(t *testing.T) {
	const (
		sourceEnvironment   = "MATRIX_IAM_AUTHENTICATION_RECOVERY_SOURCE_POSTGRES_TEST_DSN"
		restoredEnvironment = "MATRIX_IAM_AUTHENTICATION_RECOVERY_RESTORED_POSTGRES_TEST_DSN"
	)
	sourceDSN, restoredDSN := os.Getenv(sourceEnvironment), os.Getenv(restoredEnvironment)
	if sourceDSN == "" || restoredDSN == "" {
		t.Skipf("set %s and %s to distinct clean disposable PostgreSQL 18 databases", sourceEnvironment, restoredEnvironment)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	sourceAdmin, sourceConfig := openAuthenticationRecoveryDatabase(t, ctx, sourceDSN, "matrix_iam_auth_recovery_source_")
	defer sourceAdmin.Close(context.Background())
	restoredAdmin, restoredConfig := openAuthenticationRecoveryDatabase(t, ctx, restoredDSN, "matrix_iam_auth_recovery_restored_")
	defer restoredAdmin.Close(context.Background())
	if sourceConfig.Database == restoredConfig.Database && sourceConfig.Host == restoredConfig.Host && sourceConfig.Port == restoredConfig.Port {
		t.Fatal("authentication recovery source and restored authorities are the same database")
	}

	for _, database := range []*pgx.Conn{sourceAdmin, restoredAdmin} {
		assertIAMPostgres18(t, ctx, database)
		assertCleanIAMSchema(t, ctx, database)
		applyIAMSchema(t, ctx, database)
		createIAMHTTPRole(t, ctx, database)
		createAuthenticationRecoveryTestRoles(t, ctx, database)
	}

	document := iamHTTPBootstrap(t)
	document.InstallationID = "mxi-" + strings.Repeat("1", 32)
	sourceAPI := authenticationRecoveryAPI(t, ctx, sourceDSN, document)
	restoredAPI := authenticationRecoveryAPI(t, ctx, restoredDSN, document)
	sourceStatus, err := bootstrapIAMWithTOTP(t, ctx, sourceAPI, document)
	if err != nil {
		t.Fatal("bootstrap source authentication authority", err)
	}
	restoredStatus, err := bootstrapIAMWithTOTP(t, ctx, restoredAPI, document)
	if err != nil {
		t.Fatal("bootstrap restored authentication authority", err)
	}
	if sourceStatus.State != restoredStatus.State ||
		sourceStatus.InstallationID != restoredStatus.InstallationID ||
		sourceStatus.AccountID != restoredStatus.AccountID ||
		sourceStatus.ContentDigest != restoredStatus.ContentDigest {
		t.Fatal("source and restored bootstrap identities differ")
	}
	sourceCredential, _ := prepareAuthenticationRecoveryIdentity(t, ctx, sourceAPI, sourceAdmin, document, false)
	restoredCredential, restoredSession := prepareAuthenticationRecoveryIdentity(t, ctx, restoredAPI, restoredAdmin, document, true)
	before := readAuthenticationRecoverySecurityState(t, ctx, restoredAdmin, document, restoredSession)
	if before.activeSessions == 0 || before.accessKeys != 1 || before.retainedFactors != 0 ||
		before.passwordReserved != 1 {
		t.Fatal("restored pre-close replay fixture is incomplete")
	}

	sourceLocal := localRecoveryWorkflow(t, ctx, sourceDSN, localRecoveryTestRole, nil)
	restoredLocal := localRecoveryWorkflow(t, ctx, restoredDSN, localRecoveryTestRole, nil)
	localAuthority := authenticationRecoveryLocalAuthority(t, document, restoredStatus.ContentDigest)
	if inspection, err := sourceLocal.InspectLocalCredentialRecovery(ctx, localAuthority, nil); err != nil || inspection.State != "ELIGIBLE" {
		t.Fatalf("source local credential recovery was not initially eligible: %v", err)
	}
	if inspection, err := restoredLocal.InspectLocalCredentialRecovery(ctx, localAuthority, nil); err != nil || inspection.State != "ELIGIBLE" {
		t.Fatalf("restored local credential recovery was not initially eligible: %v", err)
	}
	assertAuthenticationAuthorityOpen(t, ctx, sourceAPI, sourceCredential)
	assertAuthenticationAuthorityOpen(t, ctx, restoredAPI, restoredCredential)
	assertAuthenticationRecoveryDatabaseBoundary(t, ctx, sourceAdmin, sourceConfig)
	assertAuthenticationRecoveryDatabaseBoundary(t, ctx, restoredAdmin, restoredConfig)

	sourceRecovery := authenticationRecoveryWorkflow(t, ctx, sourceDSN)
	restoredRecovery := authenticationRecoveryWorkflow(t, ctx, restoredDSN)
	intent := authenticationRecoveryIntent(document.InstallationID)
	closure := closeAuthenticationConcurrently(t, ctx, sourceRecovery, intent)
	if installationv1.ValidateAuthenticationRecoveryClosureForIntent(closure, intent) != nil {
		t.Fatal("source close returned an invalid installation closure")
	}
	assertAuthenticationAuthorityClosed(t, ctx, sourceAPI, sourceCredential)
	if _, err := sourceLocal.InspectLocalCredentialRecovery(ctx, localAuthority, nil); !errors.Is(err, identityaccess.ErrForbidden) {
		t.Fatalf("source local credential recovery bypassed CLOSED: %v", err)
	}
	if err := iammigration.Verify(ctx, sourceAdmin); err == nil {
		t.Fatal("source migration verification reported CLOSED authority ready")
	}
	if _, err := sourceRecovery.Reconcile(ctx, closure); !errors.Is(err, authenticationrecovery.ErrConflict) {
		t.Fatalf("source authority was reconciled as a restored authority: %v", err)
	}

	changedIntent := intent
	changedIntent.BackupDigest = digestForAuthenticationRecovery('9')
	if _, err := sourceRecovery.Close(ctx, changedIntent); !errors.Is(err, authenticationrecovery.ErrConflict) {
		t.Fatalf("close command accepted another intent: %v", err)
	}
	assertAuthenticationAuthorityOpen(t, ctx, restoredAPI, restoredCredential)
	reconciled := reconcileAuthenticationConcurrently(t, ctx, restoredRecovery, closure)
	if reconciled != closure {
		t.Fatal("restored authority changed the protected source closure")
	}
	assertAuthenticationAuthorityClosed(t, ctx, restoredAPI, restoredCredential)
	if _, err := restoredLocal.InspectLocalCredentialRecovery(ctx, localAuthority, nil); !errors.Is(err, identityaccess.ErrForbidden) {
		t.Fatalf("restored local credential recovery bypassed reconciled CLOSED: %v", err)
	}
	if err := iammigration.Verify(ctx, restoredAdmin); err == nil {
		t.Fatal("restored migration verification reported reconciled CLOSED authority ready")
	}
	assertAuthenticationRecoveryClosedFacts(t, ctx, sourceAdmin, restoredAdmin, closure)

	changedClosure := closure
	changedClosure.BackupDigest = digestForAuthenticationRecovery('8')
	if _, err := restoredRecovery.Reopen(ctx, changedClosure); !errors.Is(err, authenticationrecovery.ErrConflict) {
		t.Fatalf("reopen accepted a changed closure: %v", err)
	}
	insertPreparationRecoveryFactor(t, ctx, restoredAdmin, document)
	withFactor := readAuthenticationRecoverySecurityState(t, ctx, restoredAdmin, document, restoredSession)
	if withFactor.retainedFactors != 1 {
		t.Fatal("preparation recovery factor fixture was not retained")
	}
	if _, err := restoredRecovery.Reopen(ctx, closure); !errors.Is(err, authenticationrecovery.ErrConflict) {
		t.Fatalf("preparation authority reopened retained MFA state: %v", err)
	}
	afterRejectedFactor := readAuthenticationRecoverySecurityState(t, ctx, restoredAdmin, document, restoredSession)
	if afterRejectedFactor.credentialGeneration != before.credentialGeneration ||
		afterRejectedFactor.completions != 0 || afterRejectedFactor.accessKeyFences != 0 ||
		afterRejectedFactor.activeSessions != before.activeSessions {
		t.Fatalf("retained MFA rejection partially changed authentication state: before=%+v after=%+v", before, afterRejectedFactor)
	}
	removePreparationRecoveryFactor(t, ctx, restoredAdmin, document)
	completion := reopenAuthenticationConcurrently(t, ctx, restoredRecovery, closure)
	if installationv1.ValidateAuthenticationRecoveryCompletionForClosure(completion, closure) != nil {
		t.Fatal("restored reopen returned an invalid completion")
	}
	if replay, err := restoredRecovery.Reopen(ctx, closure); err != nil || replay != completion {
		t.Fatalf("equal reopen replay changed its completion: %v", err)
	}
	if err := iammigration.Verify(ctx, restoredAdmin); err != nil {
		t.Fatal("reopened IAM schema did not verify", err)
	}
	if readiness, err := restoredAPI.Readiness(ctx); err != nil || readiness.State != iamv1.ReadinessReady {
		t.Fatalf("reopened IAM authority is not ready: %v", err)
	}
	if _, err := restoredAPI.CurrentIdentity(ctx, restoredCredential); !errors.Is(err, identityaccess.ErrUnauthenticated) {
		t.Fatalf("restored pre-recovery Session survived reopen: %v", err)
	}
	login, err := restoredAPI.Login(ctx, iamv1.LoginRequest{LoginName: "admin", Password: iamHTTPSecret(t, changedAdminPassword), RequestID: "auth-recovery-after-reopen"})
	if err != nil || login.MustChangePassword || !login.Credential.Present() {
		t.Fatalf("authorized identity was not usable after reopen: %v", err)
	}
	if _, err := restoredAPI.CurrentIdentity(ctx, login.Credential); err != nil {
		t.Fatal("new post-recovery Session is unusable", err)
	}

	after := readAuthenticationRecoverySecurityState(t, ctx, restoredAdmin, document, restoredSession)
	if after.credentialGeneration != before.credentialGeneration+1 || after.activeSessions != 1 ||
		after.restoredSessionStatus != "REVOKED" || after.retainedFactors != 0 ||
		after.accessKeyFences != before.accessKeys ||
		after.closures != 1 || after.reconciliations != 1 || after.completions != 1 ||
		after.passwordReserved != 0 || after.passwordAbandoned != 1 {
		t.Fatalf("reopen replay fencing differs: before=%+v after=%+v", before, after)
	}
	assertAuthenticationRecoveryAuditFacts(t, ctx, sourceAdmin, restoredAdmin)
	assertAuthenticationRecoveryHistoryImmutable(t, ctx, restoredAdmin)
	assertAuthenticationAuthorityClosed(t, ctx, sourceAPI, sourceCredential)
	if _, err := sourceRecovery.Reopen(ctx, closure); !errors.Is(err, authenticationrecovery.ErrConflict) {
		t.Fatalf("source authority reopened without restored reconciliation: %v", err)
	}
}

func openAuthenticationRecoveryDatabase(t *testing.T, ctx context.Context, dsn, prefix string) (*pgx.Conn, *pgx.ConnConfig) {
	t.Helper()
	config, err := pgx.ParseConfig(dsn)
	if err != nil || !strings.HasPrefix(config.Database, prefix) {
		t.Fatalf("authentication recovery gate requires an own %s database", prefix)
	}
	config.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	database, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal("connect authentication recovery database")
	}
	return database, config
}

func createAuthenticationRecoveryTestRoles(t *testing.T, ctx context.Context, database *pgx.Conn) {
	t.Helper()
	statement := `DO $roles$ BEGIN
        IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='` + authenticationRecoveryTestRole + `') THEN
            CREATE ROLE ` + authenticationRecoveryTestRole + ` LOGIN PASSWORD '` + iamHTTPTestPassword + `'
                NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
        END IF;
        IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='` + localRecoveryTestRole + `') THEN
            CREATE ROLE ` + localRecoveryTestRole + ` LOGIN PASSWORD '` + iamHTTPTestPassword + `'
                NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
        END IF;
    END $roles$;
    GRANT matrix_iam_authentication_recovery TO ` + authenticationRecoveryTestRole + `;
    GRANT matrix_iam_credential_recovery TO ` + localRecoveryTestRole
	if _, err := database.Exec(ctx, statement); err != nil {
		t.Fatal("create purpose-specific authentication recovery test logins", err)
	}
}

func authenticationRecoveryAPI(t *testing.T, ctx context.Context, dsn string, document iamv1.BootstrapDocument) *identityaccess.Authority {
	t.Helper()
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.User, config.ConnConfig.Password = iamHTTPTestRole, iamHTTPTestPassword
	config.ConnConfig.RuntimeParams["application_name"] = "matrix-authentication-recovery-api-test"
	config.MaxConns = 2
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	repository, err := iampostgres.NewRepository(pool)
	if err != nil {
		t.Fatal(err)
	}
	totp, accessKeys := iamHTTPTOTPKeyring(t, document), iamHTTPAccessKeyWrapping(t, document)
	service, err := identityaccess.NewAuthority(repository, identityaccess.Config{
		CursorKey:         bytes.Repeat([]byte{0x39}, 32),
		TOTPKeyring:       &totp,
		AccessKeyWrapping: &accessKeys,
	})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func authenticationRecoveryWorkflow(t *testing.T, ctx context.Context, dsn string) *authenticationrecovery.Service {
	t.Helper()
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.User, config.ConnConfig.Password = authenticationRecoveryTestRole, iamHTTPTestPassword
	config.ConnConfig.RuntimeParams["application_name"] = "matrix-authentication-recovery-purpose-test"
	config.MaxConns = 2
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := pool.Ping(ctx); err != nil {
		t.Fatal("purpose-specific authentication recovery login failed")
	}
	repository, err := iampostgres.NewRepository(pool)
	if err != nil {
		t.Fatal(err)
	}
	service, err := authenticationrecovery.NewService(repository, authenticationrecovery.Config{})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func prepareAuthenticationRecoveryIdentity(t *testing.T, ctx context.Context, service *identityaccess.Authority, database *pgx.Conn, document iamv1.BootstrapDocument, createReplayMaterial bool) (iamv1.Secret, iamv1.SessionID) {
	t.Helper()
	login, err := service.Login(ctx, iamv1.LoginRequest{LoginName: document.Administrator.LoginName, Password: document.Administrator.Password, RequestID: "auth-recovery-initial-login"})
	if err != nil || !login.MustChangePassword || !login.Credential.Present() {
		t.Fatalf("login recovery fixture: %v", err)
	}
	if _, err := service.ChangePassword(ctx, login.Credential, iamv1.ChangePasswordRequest{
		CurrentPassword: document.Administrator.Password,
		NewPassword:     iamHTTPSecret(t, changedAdminPassword),
		RequestID:       "auth-recovery-initial-password-change",
	}); err != nil {
		t.Fatal("change recovery fixture password", err)
	}
	if createReplayMaterial {
		keyUser, err := service.CreateUser(ctx, login.Credential, iamv1.CreateUserRequest{
			LoginName:       "auth-recovery-key-user",
			DisplayName:     "Authentication recovery key user",
			InitialPassword: iamHTTPSecret(t, initialDeveloperPassword),
			RequestID:       "auth-recovery-key-user-create",
		})
		if err != nil {
			t.Fatal("create recovery fixture AccessKey user", err)
		}
		keyLogin, err := service.Login(ctx, iamv1.LoginRequest{
			LoginName: "auth-recovery-key-user@" + string(document.Organization.ID),
			Password:  iamHTTPSecret(t, initialDeveloperPassword),
			RequestID: "auth-recovery-key-user-login",
		})
		if err != nil || !keyLogin.MustChangePassword {
			t.Fatalf("login recovery fixture AccessKey user: %v", err)
		}
		if _, err := service.ChangePassword(ctx, keyLogin.Credential, iamv1.ChangePasswordRequest{
			CurrentPassword: iamHTTPSecret(t, initialDeveloperPassword),
			NewPassword:     iamHTTPSecret(t, changedDeveloperPassword),
			RequestID:       "auth-recovery-key-user-password",
		}); err != nil {
			t.Fatal("change recovery fixture AccessKey user password", err)
		}
		policy, err := service.CreatePolicy(ctx, login.Credential, iamv1.CreatePolicyRequest{
			DisplayName: "Authentication recovery AccessKey fixture",
			RequestID:   "auth-recovery-key-policy",
			Document: iamv1.PolicyDocument{
				LanguageVersion: "1",
				Scope:           iamv1.AuthorityScopeTenant,
				Statements: []iamv1.PolicyStatement{{
					SID:       "recovery-key-fixture",
					Effect:    iamv1.PolicyAllow,
					Actions:   []iamv1.Action{iamv1.ActionIAMAccessKeyList, iamv1.ActionIAMAccessKeyCreate},
					Resources: []iamv1.PolicyResourceSelector{{Kind: iamv1.ResourceUser, Match: iamv1.PolicyResourceAnyInAuthority}},
				}},
			},
		})
		if err != nil {
			t.Fatal("create recovery fixture AccessKey policy", err)
		}
		if _, err := service.CreatePolicyAttachment(ctx, login.Credential, iamv1.CreatePolicyAttachmentRequest{
			Target:                iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetUser, ID: string(keyUser.ID)},
			PolicyID:              policy.Policy.ID,
			PolicyResourceVersion: policy.Policy.ResourceVersion,
			RequestID:             "auth-recovery-key-policy-attachment",
		}); err != nil {
			t.Fatal("attach recovery fixture AccessKey policy", err)
		}
		keyLogin, err = service.Login(ctx, iamv1.LoginRequest{
			LoginName: "auth-recovery-key-user@" + string(document.Organization.ID),
			Password:  iamHTTPSecret(t, changedDeveloperPassword),
			RequestID: "auth-recovery-key-policy-login",
		})
		if err != nil || keyLogin.MustChangePassword || !keyLogin.Credential.Present() {
			t.Fatalf("refresh recovery fixture authorization: %v", err)
		}
		directory, err := service.ListAccessKeys(ctx, keyLogin.Credential, keyUser.ID, "auth-recovery-key-list")
		if err != nil {
			t.Fatal("list recovery fixture AccessKeys", err)
		}
		created, err := service.CreateAccessKey(ctx, keyLogin.Credential, keyUser.ID, iamv1.CreateAccessKeyRequest{
			UserResourceVersion: directory.UserResourceVersion,
			RequestID:           "auth-recovery-key-create",
		})
		if err != nil || created.Outcome != "APPLIED" || !created.Secret.Present() {
			t.Fatalf("create recovery fixture AccessKey: %v", err)
		}
		seedAuthenticationRecoveryPendingPassword(t, ctx, database, document)
	}
	return login.Credential, login.Session.ID
}

func seedAuthenticationRecoveryPendingPassword(t *testing.T, ctx context.Context, database *pgx.Conn, document iamv1.BootstrapDocument) {
	t.Helper()
	config := database.Config().Copy()
	config.User, config.Password = iamHTTPTestRole, iamHTTPTestPassword
	config.RuntimeParams["application_name"] = "matrix-authentication-recovery-pending-work-test"
	connection, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal("connect recovery pending-work fixture")
	}
	defer connection.Close(context.Background())
	tx, err := connection.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, "SELECT set_config('matrix.iam_tenant_id',$1,true)", document.Organization.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SELECT iam.reserve_password_attempt($1,NULL,NULL,NULL,'auth-recovery-pending-password','LOGIN',NULL)`,
		"auth-recovery-key-user@"+string(document.Organization.ID)); err != nil {
		t.Fatal("reserve recovery password attempt", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func authenticationRecoveryLocalAuthority(t *testing.T, document iamv1.BootstrapDocument, bootstrapDigest string) iamv1.LocalCredentialRecoveryAuthority {
	t.Helper()
	return iamv1.LocalCredentialRecoveryAuthority{
		APIVersion: iamv1.APIVersion,
		Kind:       "LocalCredentialRecoveryAuthority",
		Purpose:    iamv1.LocalCredentialRecoveryPurpose,
		Scope: iamv1.LocalCredentialRecoveryScope{
			InstallationID:  document.InstallationID,
			BootstrapDigest: bootstrapDigest,
			AccountID:       document.Organization.ID,
			PrincipalID:     document.Administrator.ID,
		},
		CapabilityKey: iamHTTPSecret(t, base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x41}, 32))),
	}
}

func authenticationRecoveryIntent(installationID string) installationv1.AuthenticationRecoveryIntent {
	return installationv1.AuthenticationRecoveryIntent{
		APIVersion:          installationv1.AuthenticationRecoveryAPIVersion,
		Kind:                installationv1.AuthenticationRecoveryIntentKind,
		Purpose:             installationv1.AuthenticationRecoveryPurpose,
		InstallationID:      installationID,
		Epoch:               1,
		CommandID:           "cmd-" + strings.Repeat("2", 32),
		BackupID:            "backup-" + strings.Repeat("3", 32),
		BackupDigest:        digestForAuthenticationRecovery('4'),
		SourceReleaseID:     "matrix-v0.3.0-authprep-aaaaaaaaaaaa",
		SourceReleaseDigest: digestForAuthenticationRecovery('5'),
		TargetReleaseID:     "matrix-v0.4.0-authmfa-bbbbbbbbbbbb",
		TargetReleaseDigest: digestForAuthenticationRecovery('6'),
		TOTPCustodyDigest:   digestForAuthenticationRecovery('7'),
	}
}

func digestForAuthenticationRecovery(value byte) string {
	return "sha256:" + strings.Repeat(string(value), 64)
}

func closeAuthenticationConcurrently(t *testing.T, ctx context.Context, service *authenticationrecovery.Service, intent installationv1.AuthenticationRecoveryIntent) installationv1.AuthenticationRecoveryClosure {
	t.Helper()
	var results [2]installationv1.AuthenticationRecoveryClosure
	var failures [2]error
	var wait sync.WaitGroup
	for index := range results {
		wait.Add(1)
		go func() {
			defer wait.Done()
			results[index], failures[index] = service.Close(ctx, intent)
		}()
	}
	wait.Wait()
	if failures[0] != nil || failures[1] != nil || results[0] != results[1] {
		t.Fatalf("concurrent equal close was not one result: %v %v", failures[0], failures[1])
	}
	return results[0]
}

func reconcileAuthenticationConcurrently(t *testing.T, ctx context.Context, service *authenticationrecovery.Service, closure installationv1.AuthenticationRecoveryClosure) installationv1.AuthenticationRecoveryClosure {
	t.Helper()
	var results [2]installationv1.AuthenticationRecoveryClosure
	var failures [2]error
	var wait sync.WaitGroup
	for index := range results {
		wait.Add(1)
		go func() {
			defer wait.Done()
			results[index], failures[index] = service.Reconcile(ctx, closure)
		}()
	}
	wait.Wait()
	if failures[0] != nil || failures[1] != nil || results[0] != results[1] {
		t.Fatalf("concurrent equal reconciliation was not one result: %v %v", failures[0], failures[1])
	}
	return results[0]
}

func reopenAuthenticationConcurrently(t *testing.T, ctx context.Context, service *authenticationrecovery.Service, closure installationv1.AuthenticationRecoveryClosure) installationv1.AuthenticationRecoveryCompletion {
	t.Helper()
	var results [2]installationv1.AuthenticationRecoveryCompletion
	var failures [2]error
	var wait sync.WaitGroup
	for index := range results {
		wait.Add(1)
		go func() {
			defer wait.Done()
			results[index], failures[index] = service.Reopen(ctx, closure)
		}()
	}
	wait.Wait()
	if failures[0] != nil || failures[1] != nil || results[0] != results[1] {
		t.Fatalf("concurrent equal reopen was not one result: %v %v", failures[0], failures[1])
	}
	return results[0]
}

func assertAuthenticationAuthorityOpen(t *testing.T, ctx context.Context, service *identityaccess.Authority, credential iamv1.Secret) {
	t.Helper()
	if readiness, err := service.Readiness(ctx); err != nil || readiness.State != iamv1.ReadinessReady {
		t.Fatalf("authentication authority is not open: %v", err)
	}
	if _, err := service.CurrentIdentity(ctx, credential); err != nil {
		t.Fatalf("open authority rejected its Session: %v", err)
	}
}

func assertAuthenticationAuthorityClosed(t *testing.T, ctx context.Context, service *identityaccess.Authority, credential iamv1.Secret) {
	t.Helper()
	if _, err := service.Readiness(ctx); !errors.Is(err, identityaccess.ErrUnauthenticated) {
		t.Fatalf("closed authority served readiness: %v", err)
	}
	if _, err := service.CurrentIdentity(ctx, credential); !errors.Is(err, identityaccess.ErrUnauthenticated) {
		t.Fatalf("closed authority authenticated a Session: %v", err)
	}
}

func insertPreparationRecoveryFactor(t *testing.T, ctx context.Context, database *pgx.Conn, document iamv1.BootstrapDocument) {
	t.Helper()
	tx, err := database.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, "SET LOCAL ROLE matrix_iam_owner"); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, "SELECT set_config('matrix.iam_tenant_id',$1,true)", document.Organization.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO iam.totp_authenticators(
      id,tenant_id,user_id,installation_id,key_id,format_version,nonce,ciphertext,state,last_consumed_step,created_at)
      VALUES('auth-recovery-retained-factor',$1,$2,$3,'totp-http',1,$4,$5,'REVOKED',-1,transaction_timestamp())`,
		document.Organization.ID, document.Administrator.ID, document.InstallationID, bytes.Repeat([]byte{0x11}, 12), bytes.Repeat([]byte{0x22}, 36)); err != nil {
		t.Fatal("insert retained preparation MFA fixture", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func removePreparationRecoveryFactor(t *testing.T, ctx context.Context, database *pgx.Conn, document iamv1.BootstrapDocument) {
	t.Helper()
	tx, err := database.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, "ALTER TABLE iam.totp_authenticators DISABLE TRIGGER cannot_delete"); err != nil {
		t.Fatal("disable immutable fixture trigger", err)
	}
	if _, err := tx.Exec(ctx, "SET LOCAL ROLE matrix_iam_owner"); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, "SELECT set_config('matrix.iam_tenant_id',$1,true)", document.Organization.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, "DELETE FROM iam.totp_authenticators WHERE tenant_id=$1 AND id='auth-recovery-retained-factor'", document.Organization.ID); err != nil {
		t.Fatal("remove retained preparation MFA fixture", err)
	}
	if _, err := tx.Exec(ctx, "RESET ROLE"); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, "ALTER TABLE iam.totp_authenticators ENABLE ALWAYS TRIGGER cannot_delete"); err != nil {
		t.Fatal("restore immutable fixture trigger", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

type authenticationRecoverySecurityState struct {
	credentialGeneration  int64
	activeSessions        int
	accessKeys            int
	retainedFactors       int
	accessKeyFences       int
	closures              int
	reconciliations       int
	completions           int
	passwordReserved      int
	passwordAbandoned     int
	restoredSessionStatus string
}

func readAuthenticationRecoverySecurityState(t *testing.T, ctx context.Context, database *pgx.Conn, document iamv1.BootstrapDocument, session iamv1.SessionID) authenticationRecoverySecurityState {
	t.Helper()
	var result authenticationRecoverySecurityState
	err := database.QueryRow(ctx, `SELECT
      (SELECT credential_version FROM iam.user_credentials WHERE tenant_id=$1 AND principal_id=$2),
      (SELECT count(*) FROM iam.sessions WHERE tenant_id=$1 AND status='ACTIVE'),
      (SELECT count(*) FROM iam.access_keys WHERE tenant_id=$1),
	  (SELECT count(*) FROM iam.totp_authenticators),
      (SELECT count(*) FROM iam.authentication_recovery_access_key_fences),
      (SELECT count(*) FROM iam.authentication_recovery_closures),
      (SELECT count(*) FROM iam.authentication_recovery_reconciliations),
      (SELECT count(*) FROM iam.authentication_recovery_completions),
	  (SELECT count(*) FROM iam.password_attempts WHERE state='RESERVED'),
	  (SELECT count(*) FROM iam.password_attempts WHERE state='ABANDONED'),
      (SELECT status FROM iam.sessions WHERE tenant_id=$1 AND id=$3)`,
		document.Organization.ID, document.Administrator.ID, session).Scan(
		&result.credentialGeneration, &result.activeSessions, &result.accessKeys, &result.retainedFactors,
		&result.accessKeyFences, &result.closures,
		&result.reconciliations, &result.completions, &result.passwordReserved, &result.passwordAbandoned,
		&result.restoredSessionStatus)
	if err != nil {
		t.Fatal("read authentication recovery security state", err)
	}
	return result
}

func assertAuthenticationRecoveryClosedFacts(t *testing.T, ctx context.Context, source, restored *pgx.Conn, closure installationv1.AuthenticationRecoveryClosure) {
	t.Helper()
	action := string(auditv1.ActionIAMAuthenticationRecoveryClosed)
	var sourceDocument, restoredDocument string
	if err := source.QueryRow(ctx, `SELECT event_document::text FROM iam.audit_outbox WHERE event_document->>'action'=$1`, action).Scan(&sourceDocument); err != nil {
		t.Fatal("read source closed fact", err)
	}
	if err := restored.QueryRow(ctx, `SELECT event_document::text FROM iam.audit_outbox WHERE event_document->>'action'=$1`, action).Scan(&restoredDocument); err != nil {
		t.Fatal("read reconciled closed fact", err)
	}
	if sourceDocument != restoredDocument || !strings.Contains(sourceDocument, closure.CommandID) {
		t.Fatal("restored authority did not reproduce the exact source closed fact")
	}
}

func assertAuthenticationRecoveryAuditFacts(t *testing.T, ctx context.Context, source, restored *pgx.Conn) {
	t.Helper()
	var sourceCount, restoredCount int
	if err := source.QueryRow(ctx, `SELECT count(*) FROM iam.audit_outbox WHERE event_document->>'action' LIKE 'iam.authentication-recovery.%'`).Scan(&sourceCount); err != nil {
		t.Fatal(err)
	}
	if err := restored.QueryRow(ctx, `SELECT count(*) FROM iam.audit_outbox WHERE event_document->>'action' LIKE 'iam.authentication-recovery.%'
      AND event_document#>>'{actor,type}'='SYSTEM' AND event_document#>>'{actor,id}'='iam-authentication-recovery'
      AND event_document#>>'{target,kind}'='INSTALLATION' AND event_document#>>'{target,id}'=event_document->>'installationId'`).Scan(&restoredCount); err != nil {
		t.Fatal(err)
	}
	if sourceCount != 1 || restoredCount != 3 {
		t.Fatalf("authentication recovery fact cardinality source=%d restored=%d", sourceCount, restoredCount)
	}
}

func assertAuthenticationRecoveryDatabaseBoundary(t *testing.T, ctx context.Context, database *pgx.Conn, adminConfig *pgx.ConnConfig) {
	t.Helper()
	config := adminConfig.Copy()
	config.User, config.Password = authenticationRecoveryTestRole, iamHTTPTestPassword
	connection, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal("connect authentication recovery boundary probe")
	}
	defer connection.Close(context.Background())
	var sessionUser, currentUser string
	if err := connection.QueryRow(ctx, "SELECT session_user,current_user").Scan(&sessionUser, &currentUser); err != nil || sessionUser != authenticationRecoveryTestRole || currentUser != authenticationRecoveryTestRole {
		t.Fatal("authentication recovery boundary probe used another login")
	}
	for _, attack := range []string{
		"SELECT * FROM iam.authentication_recovery_state",
		"SELECT * FROM iam.bootstrap_receipts",
		"SELECT * FROM iam.sessions",
		"SET ROLE matrix_iam_owner",
		"SET ROLE matrix_iam_api",
		"SELECT * FROM iam.readiness()",
	} {
		_, attackErr := connection.Exec(ctx, attack)
		var databaseError *pgconn.PgError
		if !errors.As(attackErr, &databaseError) || databaseError.Code != "42501" {
			t.Fatalf("purpose-specific authentication recovery login crossed boundary with %q: %v", attack, attackErr)
		}
	}
	var executableFunctions, tableCapabilities int
	err = database.QueryRow(ctx, `SELECT
      (SELECT count(*) FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
        WHERE n.nspname='iam' AND has_function_privilege($1,p.oid,'EXECUTE')),
      (SELECT count(*) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname='iam' AND c.relkind IN ('r','p','v','m','S')
          AND has_table_privilege($1,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'))`, authenticationRecoveryTestRole).
		Scan(&executableFunctions, &tableCapabilities)
	if err != nil || executableFunctions != 3 || tableCapabilities != 0 {
		t.Fatalf("authentication recovery login capabilities functions=%d tables=%d: %v", executableFunctions, tableCapabilities, err)
	}
}

func assertAuthenticationRecoveryHistoryImmutable(t *testing.T, ctx context.Context, database *pgx.Conn) {
	t.Helper()
	for _, table := range []string{
		"authentication_recovery_closures",
		"authentication_recovery_reconciliations",
		"authentication_recovery_completions",
		"authentication_recovery_access_key_fences",
	} {
		for _, attack := range []string{
			fmt.Sprintf("UPDATE iam.%s SET command_id=command_id", table),
			fmt.Sprintf("DELETE FROM iam.%s", table),
			fmt.Sprintf("TRUNCATE iam.%s CASCADE", table),
		} {
			tx, err := database.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(ctx, "SET LOCAL ROLE matrix_iam_owner"); err != nil {
				t.Fatal(err)
			}
			_, attackErr := tx.Exec(ctx, attack)
			_ = tx.Rollback(ctx)
			var databaseError *pgconn.PgError
			if !errors.As(attackErr, &databaseError) || databaseError.Code != "42501" {
				t.Fatalf("IAM owner changed authentication recovery history with %q: %v", attack, attackErr)
			}
		}
	}
	tx, err := database.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, "SET LOCAL ROLE matrix_iam_owner"); err != nil {
		t.Fatal(err)
	}
	_, attackErr := tx.Exec(ctx, "UPDATE iam.authentication_recovery_state SET epoch=epoch")
	_ = tx.Rollback(ctx)
	var databaseError *pgconn.PgError
	if !errors.As(attackErr, &databaseError) || databaseError.Code != "42501" {
		t.Fatalf("IAM owner rewrote authentication recovery state: %v", attackErr)
	}
}
