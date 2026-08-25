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
