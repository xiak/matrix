package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	installationv1 "github.com/xiak/matrix/api/adapter/installation/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	iammigration "github.com/xiak/matrix/app/service/iam/migration"
	"github.com/xiak/matrix/app/service/internal/migrationprocess"
	"github.com/xiak/matrix/app/service/internal/processconfig"
)

var dsnFileEnvironments = []string{
	"MATRIX_MIGRATION_DATABASE_DSN_FILE",
	"MATRIX_MIGRATION_IAM_ACCESS_ANALYSIS_DSN_FILE",
	"MATRIX_MIGRATION_IAM_API_DSN_FILE",
	installationv1.AuthenticationRecoveryMigrationDSNFileEnvironment,
	installationv1.TOTPBackupCustodyMigrationDSNFileEnvironment,
	"MATRIX_MIGRATION_IAM_NOTIFICATION_DSN_FILE",
	"MATRIX_MIGRATION_IAM_RECOVERY_DSN_FILE",
	"MATRIX_MIGRATION_IAM_WORKER_DSN_FILE",
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "matrix IAM migration failed")
		os.Exit(1)
	}
}

func run(ctx context.Context, arguments []string) error {
	catalog, err := readAuthorizationProfileReleaseCatalog()
	if err != nil {
		return err
	}
	return migrationprocess.Run(ctx, arguments, migrationprocess.Configuration{
		DSNFileEnvironments: dsnFileEnvironments,
		Apply: func(ctx context.Context, values []string) error {
			return iammigration.ApplyReleaseWithAccessAnalysis(ctx, values[0], values[2], values[7], values[6], values[4], values[5], values[3], values[1], catalog)
		},
		Verify: func(ctx context.Context, values []string) error {
			return iammigration.VerifyInstalledReleaseWithAccessAnalysis(ctx, values[0], values[2], values[7], values[6], values[4], values[5], values[3], values[1], catalog)
		},
	})
}

func readAuthorizationProfileReleaseCatalog() (iamv1.AuthorizationProfileReleaseCatalog, error) {
	path := os.Getenv(installationv1.IAMAuthorizationProfilesMigrationFileEnvironment)
	if path == "" {
		return iamv1.AuthorizationProfileReleaseCatalog{}, fmt.Errorf("IAM authorization profile release catalog is unavailable")
	}
	encoded, err := processconfig.ReadFile(path, iamv1.MaxAuthorizationProfileReleaseCatalogBytes, false)
	if err != nil {
		return iamv1.AuthorizationProfileReleaseCatalog{}, fmt.Errorf("IAM authorization profile release catalog is unavailable")
	}
	defer clear(encoded)
	catalog, err := iamv1.DecodeAuthorizationProfileReleaseCatalog(bytes.NewReader(encoded))
	if err != nil {
		return iamv1.AuthorizationProfileReleaseCatalog{}, fmt.Errorf("IAM authorization profile release catalog is invalid")
	}
	return catalog, nil
}
