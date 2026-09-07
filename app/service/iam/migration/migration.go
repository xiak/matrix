// Package migration is IAM's operational PostgreSQL migration boundary.
// Embedded schema content remains owned by IAM while installation and
// cross-process acceptance consume these behavior-level functions.
package migration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/iam/internal/authority"
	iammigrations "github.com/xiak/matrix/app/service/iam/internal/data/postgres/migrations"
	"github.com/xiak/matrix/app/service/internal/postgresmigration"
)

const (
	platformPrincipalID      = iamv1.PrincipalID("service-platform")
	maximumMigrationDSNBytes = 16 * 1024
)

type PlatformServiceBinding struct {
	InstallationID string
	Credential     iamv1.Secret
}

func Bootstrap(ctx context.Context, executor postgresmigration.Executor) error {
	return postgresmigration.Bootstrap(ctx, executor, iammigrations.Source())
}

func Up(ctx context.Context, executor postgresmigration.Executor) error {
	return postgresmigration.Up(ctx, executor, iammigrations.Source())
}

func Verify(ctx context.Context, executor postgresmigration.Executor) error {
	return postgresmigration.Verify(ctx, executor, iammigrations.Source())
}

func Apply(ctx context.Context, adminDSN, apiDSN, workerDSN string) error {
	return postgresmigration.Apply(ctx, adminDSN, iammigrations.Source(), []postgresmigration.Login{
		{Name: "matrix_iam_api_login", Group: "matrix_iam_api", DSN: apiDSN},
		{Name: "matrix_iam_worker_login", Group: "matrix_iam_worker", DSN: workerDSN},
	})
}

func VerifyInstalled(ctx context.Context, adminDSN, apiDSN, workerDSN string) error {
	return postgresmigration.VerifyInstalled(
		ctx, adminDSN, iammigrations.Source(),
		[]postgresmigration.Login{
			{Name: "matrix_iam_api_login", Group: "matrix_iam_api", DSN: apiDSN},
			{Name: "matrix_iam_worker_login", Group: "matrix_iam_worker", DSN: workerDSN},
		},
	)
}

// ApplyForInstallation applies the IAM schema and then converges the one
// platform service credential needed by the product-discovery API. A database
// without a bootstrap receipt is intentionally left untouched: the current
// five-service bootstrap will seed it when IAM first starts.
func ApplyForInstallation(
	ctx context.Context,
	adminDSN, apiDSN, workerDSN string,
	binding PlatformServiceBinding,
) error {
	arguments, err := platformServiceArguments(binding)
	if err != nil {
		return err
	}
	if err := Apply(ctx, adminDSN, apiDSN, workerDSN); err != nil {
		return err
	}
	outcome, err := executePlatformServiceFunction(
		ctx,
		adminDSN,
		"SELECT iam.ensure_platform_service($1, $2, $3, $4, $5)",
		arguments.installationID,
		string(platformPrincipalID),
		arguments.lookupDigest,
		arguments.verificationDigest,
		arguments.requestDigest,
	)
	if err != nil || (outcome != "UNINITIALIZED" && outcome != "APPLIED" && outcome != "EQUAL_REPLAY") {
		return errors.New("IAM platform service enrollment failed")
	}
	verified, err := verifyPlatformService(ctx, adminDSN, arguments)
	if err != nil || (outcome == "UNINITIALIZED" && verified != "UNINITIALIZED") ||
		(outcome != "UNINITIALIZED" && verified != "READY") {
		return errors.New("IAM platform service enrollment verification failed")
	}
	return nil
}

// VerifyInstalledForInstallation rechecks both the schema/login boundary and
// the exact installation-bound platform credential without mutating state.
func VerifyInstalledForInstallation(
	ctx context.Context,
	adminDSN, apiDSN, workerDSN string,
	binding PlatformServiceBinding,
) error {
	arguments, err := platformServiceArguments(binding)
	if err != nil {
		return err
	}
	if err := VerifyInstalled(ctx, adminDSN, apiDSN, workerDSN); err != nil {
		return err
	}
	outcome, err := verifyPlatformService(ctx, adminDSN, arguments)
	if err != nil || (outcome != "UNINITIALIZED" && outcome != "READY") {
		return errors.New("IAM platform service verification failed")
	}
	return nil
}

type platformServiceDigests struct {
	installationID     string
	lookupDigest       string
	verificationDigest string
	requestDigest      string
}

func platformServiceArguments(binding PlatformServiceBinding) (platformServiceDigests, error) {
	if iamv1.ValidateID("installationId", binding.InstallationID) != nil ||
		!binding.Credential.Present() {
		return platformServiceDigests{}, errors.New("IAM platform service binding is invalid")
	}
	lookupDigest, err := authority.LookupCredentialDigest(
		authority.CredentialService,
		binding.Credential,
	)
	if err != nil {
		return platformServiceDigests{}, errors.New("IAM platform service binding is invalid")
	}
	verificationDigest, err := authority.DigestCredential(
		authority.CredentialService,
		string(platformPrincipalID),
		binding.Credential,
	)
	if err != nil {
		return platformServiceDigests{}, errors.New("IAM platform service binding is invalid")
	}
	request := sha256.New()
	_, _ = request.Write([]byte("matrix-iam-platform-service-enrollment-v1\x00"))
	_, _ = request.Write([]byte(binding.InstallationID))
	_, _ = request.Write([]byte{'\x00'})
	_, _ = request.Write([]byte(platformPrincipalID))
	_, _ = request.Write([]byte{'\x00'})
	_, _ = request.Write([]byte(lookupDigest))
	_, _ = request.Write([]byte{'\x00'})
	_, _ = request.Write([]byte(verificationDigest))
	return platformServiceDigests{
		installationID:     binding.InstallationID,
		lookupDigest:       lookupDigest,
		verificationDigest: verificationDigest,
		requestDigest:      "sha256:" + hex.EncodeToString(request.Sum(nil)),
	}, nil
}

func verifyPlatformService(
	ctx context.Context,
	adminDSN string,
	arguments platformServiceDigests,
) (string, error) {
	return executePlatformServiceFunction(
		ctx,
		adminDSN,
		"SELECT iam.verify_platform_service($1, $2, $3, $4)",
		arguments.installationID,
		string(platformPrincipalID),
		arguments.lookupDigest,
		arguments.verificationDigest,
	)
}

func executePlatformServiceFunction(
	ctx context.Context,
	adminDSN string,
	statement string,
	arguments ...any,
) (string, error) {
	if ctx == nil || len(adminDSN) == 0 || len(adminDSN) > maximumMigrationDSNBytes ||
		strings.ContainsAny(adminDSN, "\x00\r\n") {
		return "", errors.New("IAM platform service database configuration is invalid")
	}
	config, err := pgx.ParseConfig(adminDSN)
	if err != nil || config.User == "" || config.Password == "" || config.Host == "" ||
		config.Port == 0 || config.Database == "" {
		return "", errors.New("IAM platform service database configuration is invalid")
	}
	connection, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		return "", errors.New("IAM platform service database is unavailable")
	}
	defer connection.Close(context.Background())
	var serverVersion int
	var locked bool
	if err := connection.QueryRow(
		ctx,
		`SELECT pg_catalog.current_setting('server_version_num')::integer,
		        pg_catalog.pg_try_advisory_lock(
		            pg_catalog.hashtextextended('matrix:postgres-migration:iam', 0)
		        )`,
	).Scan(&serverVersion, &locked); err != nil || serverVersion < 180000 ||
		serverVersion >= 190000 || !locked {
		return "", errors.New("IAM platform service migration lock is unavailable")
	}
	var outcome string
	if err := connection.QueryRow(ctx, statement, arguments...).Scan(&outcome); err != nil {
		return "", errors.New("IAM platform service database operation failed")
	}
	return outcome, nil
}
