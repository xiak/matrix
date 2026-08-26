package postgresmigration_test

import (
	"context"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	auditmigration "github.com/xiak/matrix/app/service/audit/migration"
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
		        AND to_regnamespace('managedservice') IS NULL
		        AND NOT EXISTS (
		            SELECT 1 FROM pg_catalog.pg_roles
		             WHERE rolname IN (
		                'matrix_iam_api_login', 'matrix_iam_worker_login',
		                'matrix_audit_runtime_login',
		                'matrix_paas_api_login', 'matrix_paas_worker_login'
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

	for _, runtime := range []struct {
		dsn     string
		allowed []string
		denied  []string
	}{
		{iamAPI, []string{"iam"}, []string{"audit", "paas", "managedservice"}},
		{iamWorker, []string{"iam"}, []string{"audit", "paas", "managedservice"}},
		{auditRuntime, []string{"audit"}, []string{"iam", "paas", "managedservice"}},
		{paasAPI, []string{"managedservice", "paas"}, []string{"iam", "audit"}},
		{paasWorker, []string{"managedservice", "paas"}, []string{"iam", "audit"}},
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
	allowed []string,
	denied []string,
) {
	t.Helper()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect runtime login for %v", allowed)
	}
	defer connection.Close(context.Background())
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, schema := range allowed {
		allowedSet[schema] = struct{}{}
	}
	for _, schema := range append(append([]string(nil), allowed...), denied...) {
		var admitted bool
		if err := connection.QueryRow(
			ctx,
			"SELECT pg_catalog.has_schema_privilege(current_user, $1, 'USAGE')",
			schema,
		).Scan(&admitted); err != nil {
			t.Fatalf("inspect runtime schema boundary for %v", allowed)
		}
		_, expected := allowedSet[schema]
		if admitted != expected {
			t.Fatalf("runtime schema boundary allowed=%v schema=%s admitted=%t", allowed, schema, admitted)
		}
	}
}
