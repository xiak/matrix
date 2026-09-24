package migrationprocess

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestRunAdmitsOnlyFixedActionsAndExactSecretFiles(t *testing.T) {
	environments := []string{
		"MATRIX_MIGRATION_DATABASE_DSN_FILE",
		"MATRIX_MIGRATION_TEST_RUNTIME_DSN_FILE",
	}
	want := []string{
		"postgresql://matrix:admin@postgres:5432/matrix?sslmode=disable",
		"postgresql://matrix_test:runtime@postgres:5432/matrix?sslmode=disable",
	}
	for index, environment := range environments {
		path := filepath.Join(t.TempDir(), "dsn")
		if err := os.WriteFile(path, []byte(want[index]), 0o600); err != nil {
			t.Fatalf("write migration DSN fixture: %v", err)
		}
		t.Setenv(environment, path)
	}
	var applied, verified []string
	configuration := Configuration{
		DSNFileEnvironments: environments,
		Apply: func(_ context.Context, values []string) error {
			applied = slices.Clone(values)
			return nil
		},
		Verify: func(_ context.Context, values []string) error {
			verified = slices.Clone(values)
			return nil
		},
	}
	if err := Run(context.Background(), []string{"apply"}, configuration); err != nil ||
		!slices.Equal(applied, want) || verified != nil {
		t.Fatalf("apply invocation values=%q verified=%q err=%v", applied, verified, err)
	}
	if err := Run(context.Background(), []string{"verify"}, configuration); err != nil ||
		!slices.Equal(verified, want) {
		t.Fatalf("verify invocation values=%q err=%v", verified, err)
	}
	if err := Run(context.Background(), []string{"remove"}, configuration); err == nil {
		t.Fatal("unsupported migration process action was accepted")
	}
	invalid := configuration
	invalid.DSNFileEnvironments = slices.Clone(environments)
	slices.Reverse(invalid.DSNFileEnvironments)
	if err := Run(context.Background(), []string{"apply"}, invalid); err == nil {
		t.Fatalf("unsorted migration configuration error = %v", err)
	}
}

func TestRunBoundsSevenPurposeSeparatedFiles(t *testing.T) {
	environments := []string{
		"MATRIX_MIGRATION_DATABASE_DSN_FILE",
		"MATRIX_MIGRATION_IAM_API_DSN_FILE",
		"MATRIX_MIGRATION_IAM_AUTHENTICATION_RECOVERY_DSN_FILE",
		"MATRIX_MIGRATION_IAM_BACKUP_CUSTODY_DSN_FILE",
		"MATRIX_MIGRATION_IAM_NOTIFICATION_DSN_FILE",
		"MATRIX_MIGRATION_IAM_RECOVERY_DSN_FILE",
		"MATRIX_MIGRATION_IAM_WORKER_DSN_FILE",
	}
	want := make([]string, len(environments))
	for index, environment := range environments {
		want[index] = "synthetic-purpose:" + environment
		path := filepath.Join(t.TempDir(), "private-dsn")
		if err := os.WriteFile(path, []byte(want[index]), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv(environment, path)
	}
	var calls int
	action := func(_ context.Context, values []string) error {
		if !slices.Equal(values, want) {
			t.Fatal("purpose-specific file order changed")
		}
		calls++
		return nil
	}
	configuration := Configuration{DSNFileEnvironments: environments, Apply: action, Verify: action}
	for _, name := range []string{"apply", "verify"} {
		if err := Run(t.Context(), []string{name}, configuration); err != nil {
			t.Fatal("seven fixed private files were rejected", err)
		}
	}
	for _, invalid := range [][]string{
		append(slices.Clone(environments), "MATRIX_MIGRATION_TEST_EXTRA_DSN_FILE"),
		{environments[0], environments[1], environments[1], environments[3], environments[4], environments[5]},
		{environments[0], environments[2], environments[1], environments[3], environments[4], environments[5]},
	} {
		configuration.DSNFileEnvironments = invalid
		if err := Run(t.Context(), []string{"apply"}, configuration); err == nil {
			t.Fatal("unbounded, duplicate or reordered purpose configuration accepted")
		}
	}
	configuration.DSNFileEnvironments = environments
	t.Setenv(environments[2], "")
	if err := Run(t.Context(), []string{"apply"}, configuration); err == nil || calls != 2 {
		t.Fatal("missing required capability file reached migration")
	}
}
