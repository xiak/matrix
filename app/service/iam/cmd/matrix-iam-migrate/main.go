package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
	iammigration "github.com/xiak/matrix/app/service/iam/migration"
	"github.com/xiak/matrix/app/service/internal/migrationprocess"
	"github.com/xiak/matrix/app/service/internal/processconfig"
)

const (
	installationIDEnvironment         = "MATRIX_MIGRATION_INSTALLATION_ID"
	platformCredentialFileEnvironment = "MATRIX_MIGRATION_PLATFORM_IAM_CREDENTIAL_FILE"
	maximumPlatformCredentialBytes    = 16 * 1024
)

var dsnFileEnvironments = []string{
	"MATRIX_MIGRATION_DATABASE_DSN_FILE",
	"MATRIX_MIGRATION_IAM_API_DSN_FILE",
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
	binding, err := loadPlatformServiceBinding()
	if err != nil {
		return err
	}
	return migrationprocess.Run(ctx, arguments, migrationprocess.Configuration{
		DSNFileEnvironments: dsnFileEnvironments,
		Apply: func(ctx context.Context, values []string) error {
			return iammigration.ApplyForInstallation(ctx, values[0], values[1], values[2], binding)
		},
		Verify: func(ctx context.Context, values []string) error {
			return iammigration.VerifyInstalledForInstallation(
				ctx, values[0], values[1], values[2], binding,
			)
		},
	})
}

func loadPlatformServiceBinding() (iammigration.PlatformServiceBinding, error) {
	installationID := os.Getenv(installationIDEnvironment)
	credentialPath := os.Getenv(platformCredentialFileEnvironment)
	if iamv1.ValidateID("installationId", installationID) != nil || credentialPath == "" {
		return iammigration.PlatformServiceBinding{}, errors.New("migration process configuration is incomplete")
	}
	credentialBytes, err := processconfig.ReadFile(
		credentialPath,
		maximumPlatformCredentialBytes,
		true,
	)
	if err != nil {
		return iammigration.PlatformServiceBinding{}, errors.New("migration process configuration is invalid")
	}
	credential, secretErr := iamv1.NewSecret(string(credentialBytes))
	clear(credentialBytes)
	if secretErr != nil {
		return iammigration.PlatformServiceBinding{}, errors.New("migration process configuration is invalid")
	}
	return iammigration.PlatformServiceBinding{
		InstallationID: installationID,
		Credential:     credential,
	}, nil
}
