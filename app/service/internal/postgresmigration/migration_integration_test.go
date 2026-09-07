package postgresmigration_test

import (
	"context"
	"encoding/json"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	auditmigration "github.com/xiak/matrix/app/service/audit/migration"
	devopsmigration "github.com/xiak/matrix/app/service/devops/migration"
	iammigration "github.com/xiak/matrix/app/service/iam/migration"
	paasmigration "github.com/xiak/matrix/app/service/paas/migration"
)

const migrationIntegrationDSN = "MATRIX_POSTGRES_MIGRATION_TEST_DSN"

func TestPlatformMigrationIntegration(t *testing.T) {
	adminDSN := os.Getenv(migrationIntegrationDSN)
	if adminDSN == "" {
		t.Skipf("set %s to a clean disposable PostgreSQL 18 database", migrationIntegrationDSN)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	adminConfig, err := pgx.ParseConfig(adminDSN)
	if err != nil {
		t.Fatal("parse migration integration database configuration")
	}
	if !strings.HasPrefix(adminConfig.Database, "matrix_migration_") {
		t.Fatalf("migration integration database %q is unsafe", adminConfig.Database)
	}
	admin, err := pgx.ConnectConfig(ctx, adminConfig)
	if err != nil {
		t.Fatal("connect migration integration database")
	}
	defer admin.Close(context.Background())
	var clean bool
	if err := admin.QueryRow(
		ctx,
		`SELECT to_regnamespace('iam') IS NULL
		        AND to_regnamespace('audit') IS NULL
		        AND to_regnamespace('paas') IS NULL
		        AND to_regnamespace('delivery') IS NULL
		        AND NOT EXISTS (
		            SELECT 1 FROM pg_catalog.pg_roles
		             WHERE rolname IN (
		                'matrix_iam_api_login', 'matrix_iam_worker_login',
		                'matrix_audit_runtime_login',
		                'matrix_paas_api_login', 'matrix_paas_worker_login',
		                'matrix_devops_api_login', 'matrix_devops_worker_login'
		             )
		        )`,
	).Scan(&clean); err != nil || !clean {
		t.Fatal("migration integration database is not clean")
	}

	iamAPI := runtimeDSN(t, adminDSN, "matrix_iam_api_login", "mxp1.iam-api-00000000000000000000000000000000000")
	iamWorker := runtimeDSN(t, adminDSN, "matrix_iam_worker_login", "mxp1.iam-worker-00000000000000000000000000000000")
	auditRuntime := runtimeDSN(t, adminDSN, "matrix_audit_runtime_login", "mxp1.audit-runtime-00000000000000000000000000000")
	paasAPI := runtimeDSN(t, adminDSN, "matrix_paas_api_login", "mxp1.paas-api-0000000000000000000000000000000000")
	paasWorker := runtimeDSN(t, adminDSN, "matrix_paas_worker_login", "mxp1.paas-worker-0000000000000000000000000000000")
	devopsAPI := runtimeDSN(t, adminDSN, "matrix_devops_api_login", "mxp1.devops-api-000000000000000000000000000000")
	devopsWorker := runtimeDSN(t, adminDSN, "matrix_devops_worker_login", "mxp1.devops-worker-0000000000000000000000000000")

	for attempt := 1; attempt <= 2; attempt++ {
		if err := iammigration.Apply(ctx, adminDSN, iamAPI, iamWorker); err != nil {
			t.Fatalf("apply IAM migration attempt %d: %v", attempt, err)
		}
		if err := auditmigration.Apply(ctx, adminDSN, auditRuntime); err != nil {
			t.Fatalf("apply Audit migration attempt %d: %v", attempt, err)
		}
		if err := paasmigration.Apply(ctx, adminDSN, paasAPI, paasWorker); err != nil {
			t.Fatalf("apply PaaS migration attempt %d: %v", attempt, err)
		}
		if err := devopsmigration.Apply(ctx, adminDSN, devopsAPI, devopsWorker); err != nil {
			t.Fatalf("apply DevOps migration attempt %d: %v", attempt, err)
		}
	}
	if err := iammigration.VerifyInstalled(ctx, adminDSN, iamAPI, iamWorker); err != nil {
		t.Fatalf("verify installed IAM migration: %v", err)
	}
	if err := auditmigration.VerifyInstalled(ctx, adminDSN, auditRuntime); err != nil {
		t.Fatalf("verify installed Audit migration: %v", err)
	}
	if err := paasmigration.VerifyInstalled(ctx, adminDSN, paasAPI, paasWorker); err != nil {
		t.Fatalf("verify installed PaaS migration: %v", err)
	}
	if err := devopsmigration.VerifyInstalled(ctx, adminDSN, devopsAPI, devopsWorker); err != nil {
		t.Fatalf("verify installed DevOps migration: %v", err)
	}
	assertLegacyIAMPlatformEnrollment(t, ctx, admin, adminDSN, iamAPI, iamWorker)

	for _, runtime := range []struct {
		dsn     string
		allowed string
		denied  []string
	}{
		{iamAPI, "iam", []string{"audit", "delivery", "paas"}},
		{iamWorker, "iam", []string{"audit", "delivery", "paas"}},
		{auditRuntime, "audit", []string{"delivery", "iam", "paas"}},
		{paasAPI, "paas", []string{"audit", "delivery", "iam"}},
		{paasWorker, "paas", []string{"audit", "delivery", "iam"}},
		{devopsAPI, "delivery", []string{"audit", "iam", "paas"}},
		{devopsWorker, "delivery", []string{"audit", "iam", "paas"}},
	} {
		assertSchemaBoundary(t, ctx, runtime.dsn, runtime.allowed, runtime.denied)
	}

	wrongPassword := "mxp1.wrong-000000000000000000000000000000000000"
	wrongIAMAPI := runtimeDSN(t, adminDSN, "matrix_iam_api_login", wrongPassword)
	err = iammigration.VerifyInstalled(ctx, adminDSN, wrongIAMAPI, iamWorker)
	if err == nil || strings.Contains(err.Error(), wrongPassword) {
		t.Fatalf("wrong runtime credential verification error = %v", err)
	}
}

func assertLegacyIAMPlatformEnrollment(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	adminDSN, apiDSN, workerDSN string,
) {
	t.Helper()
	credentialText := "mx1.PlatformLegacyUpgradeCredential000000000000001"
	credential, err := iamv1.NewSecret(credentialText)
	if err != nil {
		t.Fatalf("create legacy-upgrade platform credential: %v", err)
	}
	binding := iammigration.PlatformServiceBinding{
		InstallationID: "installation-legacy-upgrade",
		Credential:     credential,
	}
	if err := iammigration.ApplyForInstallation(
		ctx, adminDSN, apiDSN, workerDSN, binding,
	); err != nil {
		t.Fatalf("apply platform binding before IAM bootstrap: %v", err)
	}
	var platformCount int
	if err := admin.QueryRow(
		ctx,
		"SELECT count(*) FROM iam.service_credentials WHERE purpose = 'PLATFORM'",
	).Scan(&platformCount); err != nil || platformCount != 0 {
		t.Fatalf("uninitialized platform credential count=%d err=%v", platformCount, err)
	}

	seedLegacyIAMAuthority(t, ctx, admin, binding.InstallationID)
	legacyReceipt := "sha256:" + strings.Repeat("4", 64)
	for attempt := 1; attempt <= 2; attempt++ {
		if err := iammigration.ApplyForInstallation(
			ctx, adminDSN, apiDSN, workerDSN, binding,
		); err != nil {
			t.Fatalf("enroll legacy platform service attempt %d: %v", attempt, err)
		}
	}
	if err := iammigration.VerifyInstalledForInstallation(
		ctx, adminDSN, apiDSN, workerDSN, binding,
	); err != nil {
		t.Fatalf("verify legacy platform service: %v", err)
	}
	var receipt string
	var expansionEvents int
	if err := admin.QueryRow(
		ctx,
		`SELECT
		    (SELECT count(*) FROM iam.service_credentials WHERE purpose = 'PLATFORM'),
		    (SELECT content_digest FROM iam.bootstrap_receipts WHERE singleton),
		    (SELECT count(*) FROM iam.audit_outbox
		      WHERE event_document#>>'{actor,id}' = 'iam-migration'
		        AND event_document->>'action' = 'iam.bootstrap.applied')`,
	).Scan(&platformCount, &receipt, &expansionEvents); err != nil ||
		platformCount != 1 || receipt != legacyReceipt || expansionEvents != 1 {
		t.Fatalf(
			"legacy platform enrollment count=%d receipt=%q events=%d err=%v",
			platformCount, receipt, expansionEvents, err,
		)
	}
	var eventDocument []byte
	if err := admin.QueryRow(
		ctx,
		`SELECT event_document FROM iam.audit_outbox
		  WHERE event_document#>>'{actor,id}' = 'iam-migration'
		    AND event_document->>'action' = 'iam.bootstrap.applied'`,
	).Scan(&eventDocument); err != nil {
		t.Fatalf("read platform expansion Audit event: %v", err)
	}
	var event auditv1.Event
	decodeErr := json.Unmarshal(eventDocument, &event)
	validationErr := auditv1.ValidateEventForSource(auditv1.SourceIAM, event)
	if decodeErr != nil || validationErr != nil ||
		event.Action != auditv1.ActionIAMBootstrapApplied ||
		event.Target.ID != binding.InstallationID {
		t.Fatalf(
			"platform expansion Audit event=%#v decode=%v validation=%v",
			event, decodeErr, validationErr,
		)
	}
	assertLegacyIAMDatabaseReplay(t, ctx, apiDSN, binding.InstallationID, legacyReceipt)

	wrongText := "mx1.WrongPlatformLegacyCredential00000000000000001"
	wrongCredential, err := iamv1.NewSecret(wrongText)
	if err != nil {
		t.Fatalf("create wrong platform credential: %v", err)
	}
	err = iammigration.VerifyInstalledForInstallation(
		ctx,
		adminDSN,
		apiDSN,
		workerDSN,
		iammigration.PlatformServiceBinding{
			InstallationID: binding.InstallationID,
			Credential:     wrongCredential,
		},
	)
	if err == nil || strings.Contains(err.Error(), wrongText) {
		t.Fatalf("wrong platform credential verification error=%v", err)
	}
}

func assertLegacyIAMDatabaseReplay(
	t *testing.T,
	ctx context.Context,
	apiDSN, installationID, contentDigest string,
) {
	t.Helper()
	api, err := pgx.Connect(ctx, apiDSN)
	if err != nil {
		t.Fatalf("connect legacy-replay IAM API identity: %v", err)
	}
	defer api.Close(context.Background())
	legacyServices := `[
	  {"purpose":"IAM","principalId":"service-iam","lookupDigest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","verificationDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1"},
	  {"purpose":"PAAS","principalId":"service-paas","lookupDigest":"sha256:2222222222222222222222222222222222222222222222222222222222222222","verificationDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2"},
	  {"purpose":"AUDIT","principalId":"service-audit","lookupDigest":"sha256:3333333333333333333333333333333333333333333333333333333333333333","verificationDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa3"},
	  {"purpose":"INSTALLATION_VERIFIER","principalId":"service-installation-verifier","lookupDigest":"sha256:5555555555555555555555555555555555555555555555555555555555555555","verificationDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa5"}
	]`
	var outcome string
	err = api.QueryRow(
		ctx,
		`SELECT iam.apply_bootstrap(
		    $1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10::jsonb
		)`,
		installationID,
		contentDigest,
		"organization-legacy-upgrade",
		"Legacy Organization",
		"principal-admin",
		"admin",
		"Legacy Administrator",
		"$matrix-iam-v1$argon2id$v=19$"+strings.Repeat("A", 80),
		legacyServices,
		`{}`,
	).Scan(&outcome)
	if err != nil || outcome != "EQUAL_REPLAY" {
		t.Fatalf("legacy IAM database replay outcome=%q err=%v", outcome, err)
	}
}

func seedLegacyIAMAuthority(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	installationID string,
) {
	t.Helper()
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatalf("start legacy IAM fixture transaction: %v", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(context.Background())
		}
	}()
	statements := []string{
		"ALTER TABLE iam.service_credentials DROP CONSTRAINT service_credentials_values_valid",
		`ALTER TABLE iam.service_credentials
		 ADD CONSTRAINT service_credentials_values_valid CHECK (
		    purpose IN ('IAM', 'PAAS', 'AUDIT', 'INSTALLATION_VERIFIER')
		    AND lookup_digest COLLATE "C" ~ '^sha256:[0-9a-f]{64}$'
		    AND verification_digest COLLATE "C" ~ '^sha256:[0-9a-f]{64}$'
		    AND lookup_digest <> verification_digest
		    AND (revoked_at IS NULL OR revoked_at >= created_at)
		 )`,
	}
	for _, statement := range statements {
		if _, err := tx.Exec(ctx, statement); err != nil {
			t.Fatalf("install legacy IAM constraint fixture: %v", err)
		}
	}
	now := time.Date(2026, 9, 7, 9, 10, 11, 123000, time.UTC)
	organizationID := "organization-legacy-upgrade"
	if _, err := tx.Exec(
		ctx,
		`INSERT INTO iam.organizations (
		    id, display_name, status, resource_version, created_at, updated_at
		 ) VALUES ($1, 'Legacy Organization', 'ACTIVE', 1, $2, $2)`,
		organizationID,
		now,
	); err != nil {
		t.Fatalf("seed legacy IAM organization: %v", err)
	}
	if _, err := tx.Exec(
		ctx,
		`INSERT INTO iam.principals (
		    tenant_id, id, principal_type, login_name, display_name, status,
		    must_change_password, resource_version, created_at, updated_at
		 ) VALUES ($1, 'principal-admin', 'USER', 'admin', 'Legacy Administrator',
		           'ACTIVE', true, 1, $2, $2)`,
		organizationID,
		now,
	); err != nil {
		t.Fatalf("seed legacy IAM administrator: %v", err)
	}
	passwordHash := "$matrix-iam-v1$argon2id$v=19$" + strings.Repeat("A", 80)
	if _, err := tx.Exec(
		ctx,
		`INSERT INTO iam.user_credentials (
		    tenant_id, principal_id, password_hash, changed_at
		 ) VALUES ($1, 'principal-admin', $2, $3)`,
		organizationID,
		passwordHash,
		now,
	); err != nil {
		t.Fatalf("seed legacy IAM administrator credential: %v", err)
	}
	if _, err := tx.Exec(
		ctx,
		`INSERT INTO iam.login_index (login_name, tenant_id, principal_id)
		 VALUES ('admin', $1, 'principal-admin')`,
		organizationID,
	); err != nil {
		t.Fatalf("seed legacy IAM login index: %v", err)
	}
	if _, err := tx.Exec(
		ctx,
		`INSERT INTO iam.role_bindings (
		    tenant_id, id, principal_id, role_name, resource_version,
		    created_at, updated_at
		 ) VALUES ($1, 'bootstrap-admin-binding', 'principal-admin',
		           'ORGANIZATION_ADMIN', 1, $2, $2)`,
		organizationID,
		now,
	); err != nil {
		t.Fatalf("seed legacy IAM administrator binding: %v", err)
	}
	services := []struct {
		purpose     string
		principalID string
		digit       string
	}{
		{"IAM", "service-iam", "1"},
		{"PAAS", "service-paas", "2"},
		{"AUDIT", "service-audit", "3"},
		{"INSTALLATION_VERIFIER", "service-installation-verifier", "5"},
	}
	for _, service := range services {
		lookupDigest := "sha256:" + strings.Repeat(service.digit, 64)
		verificationDigest := "sha256:" + strings.Repeat(strings.ToUpper(service.digit), 64)
		if service.digit == strings.ToUpper(service.digit) {
			verificationDigest = "sha256:" + strings.Repeat("a", 63) + service.digit
		}
		if _, err := tx.Exec(
			ctx,
			`INSERT INTO iam.principals (
			    tenant_id, id, principal_type, display_name, status,
			    must_change_password, resource_version, created_at, updated_at
			 ) VALUES ($1, $2, 'SERVICE_ACCOUNT', $3, 'ACTIVE', false, 1, $4, $4)`,
			organizationID,
			service.principalID,
			service.purpose,
			now,
		); err != nil {
			t.Fatalf("seed legacy IAM %s principal: %v", service.purpose, err)
		}
		if _, err := tx.Exec(
			ctx,
			`INSERT INTO iam.service_credentials (
			    tenant_id, principal_id, purpose, lookup_digest,
			    verification_digest, created_at
			 ) VALUES ($1, $2, $3, $4, $5, $6)`,
			organizationID,
			service.principalID,
			service.purpose,
			lookupDigest,
			verificationDigest,
			now,
		); err != nil {
			t.Fatalf("seed legacy IAM %s credential: %v", service.purpose, err)
		}
		if _, err := tx.Exec(
			ctx,
			`INSERT INTO iam.service_credential_index (
			    lookup_digest, tenant_id, principal_id
			 ) VALUES ($1, $2, $3)`,
			lookupDigest,
			organizationID,
			service.principalID,
		); err != nil {
			t.Fatalf("seed legacy IAM %s credential index: %v", service.purpose, err)
		}
		if service.purpose == "INSTALLATION_VERIFIER" {
			if _, err := tx.Exec(
				ctx,
				`INSERT INTO iam.role_bindings (
				    tenant_id, id, principal_id, role_name, resource_version,
				    created_at, updated_at
				 ) VALUES ($1, 'bootstrap-verifier-binding', $2,
				           'INSTALLATION_VERIFIER', 1, $3, $3)`,
				organizationID,
				service.principalID,
				now,
			); err != nil {
				t.Fatalf("seed legacy IAM verifier binding: %v", err)
			}
		}
	}
	if _, err := tx.Exec(
		ctx,
		`INSERT INTO iam.bootstrap_receipts (
		    installation_id, content_digest, organization_id,
		    administrator_principal_id, applied_at
		 ) VALUES ($1, $2, $3, 'principal-admin', $4)`,
		installationID,
		"sha256:"+strings.Repeat("4", 64),
		organizationID,
		now,
	); err != nil {
		t.Fatalf("seed legacy IAM bootstrap receipt: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit legacy IAM fixture: %v", err)
	}
	committed = true
}

func runtimeDSN(t *testing.T, adminDSN, role, password string) string {
	t.Helper()
	value, err := url.Parse(adminDSN)
	if err != nil || value.Scheme != "postgresql" {
		t.Fatal("parse migration integration DSN")
	}
	value.User = url.UserPassword(role, password)
	return value.String()
}

func assertSchemaBoundary(
	t *testing.T,
	ctx context.Context,
	dsn string,
	allowed string,
	denied []string,
) {
	t.Helper()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect runtime login for %s", allowed)
	}
	defer connection.Close(context.Background())
	for _, schema := range append([]string{allowed}, denied...) {
		var admitted bool
		if err := connection.QueryRow(
			ctx,
			"SELECT pg_catalog.has_schema_privilege(current_user, $1, 'USAGE')",
			schema,
		).Scan(&admitted); err != nil {
			t.Fatalf("inspect runtime schema boundary for %s", allowed)
		}
		if admitted != (schema == allowed) {
			t.Fatalf("runtime schema boundary allowed=%s schema=%s admitted=%t", allowed, schema, admitted)
		}
	}
}
