package main

import (
	"bytes"
	"context"
	"errors"
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

const (
	installationIDEnvironment         = "MATRIX_MIGRATION_INSTALLATION_ID"
	platformCredentialFileEnvironment = "MATRIX_MIGRATION_PLATFORM_IAM_CREDENTIAL_FILE"
	devopsCredentialFileEnvironment   = "MATRIX_MIGRATION_DEVOPS_IAM_CREDENTIAL_FILE"
	maximumReleaseCredentialBytes     = 16 * 1024
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
	catalog, err := readProductAuthorizationReleaseCatalog()
	if err != nil {
		return err
	}
	installationID, bindings, err := loadReleaseServiceBindings()
	if err != nil {
		return err
	}
	return migrationprocess.Run(ctx, arguments, migrationprocess.Configuration{
		DSNFileEnvironments: dsnFileEnvironments,
		Apply: func(ctx context.Context, values []string) error {
			return iammigration.ApplyReleaseWithAccessAnalysisForInstallation(
				ctx, values[0], values[2], values[7], values[6], values[4], values[5], values[3], values[1],
				catalog, installationID, bindings,
			)
		},
		Verify: func(ctx context.Context, values []string) error {
			return iammigration.VerifyInstalledReleaseWithAccessAnalysisForInstallation(
				ctx, values[0], values[2], values[7], values[6], values[4], values[5], values[3], values[1],
				catalog, installationID, bindings,
			)
		},
	})
}

func loadReleaseServiceBindings() (string, []iammigration.ReleaseServiceBinding, error) {
	installationID := os.Getenv(installationIDEnvironment)
	if iamv1.ValidateID("installationId", installationID) != nil {
		return "", nil, errors.New("migration process configuration is incomplete")
	}
	platform, err := loadReleaseServiceCredential(platformCredentialFileEnvironment)
	if err != nil {
		return "", nil, err
	}
	bindings := []iammigration.ReleaseServiceBinding{{
		Purpose: iamv1.ServicePlatform, Credential: platform,
	}}
	if os.Getenv(devopsCredentialFileEnvironment) != "" {
		devops, err := loadReleaseServiceCredential(devopsCredentialFileEnvironment)
		if err != nil {
			return "", nil, err
		}
		bindings = append(bindings, iammigration.ReleaseServiceBinding{
			Purpose: iamv1.ServiceDevOps, Credential: devops,
		})
	}
	return installationID, bindings, nil
}

func loadReleaseServiceCredential(environment string) (iamv1.Secret, error) {
	credentialPath := os.Getenv(environment)
	if credentialPath == "" {
		return iamv1.Secret{}, errors.New("migration process configuration is incomplete")
	}
	credentialBytes, err := processconfig.ReadFile(
		credentialPath, maximumReleaseCredentialBytes, true,
	)
	if err != nil {
		return iamv1.Secret{}, errors.New("migration process configuration is invalid")
	}
	credential, secretErr := iamv1.NewSecret(string(credentialBytes))
	clear(credentialBytes)
	if secretErr != nil {
		return iamv1.Secret{}, errors.New("migration process configuration is invalid")
	}
	return credential, nil
}

func readProductAuthorizationReleaseCatalog() (iamv1.ProductAuthorizationReleaseCatalog, error) {
	path := os.Getenv(installationv1.IAMProductAuthorizationMigrationFileEnvironment)
	if path == "" {
		return iamv1.ProductAuthorizationReleaseCatalog{}, fmt.Errorf("IAM product authorization release catalog is unavailable")
	}
	encoded, err := processconfig.ReadFile(path, iamv1.MaxProductAuthorizationReleaseCatalogBytes, false)
	if err != nil {
		return iamv1.ProductAuthorizationReleaseCatalog{}, fmt.Errorf("IAM product authorization release catalog is unavailable")
	}
	defer clear(encoded)
	catalog, err := iamv1.DecodeProductAuthorizationReleaseCatalog(bytes.NewReader(encoded))
	if err != nil {
		return iamv1.ProductAuthorizationReleaseCatalog{}, fmt.Errorf("IAM product authorization release catalog is invalid")
	}
	return catalog, nil
}
