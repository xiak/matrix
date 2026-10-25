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

const maximumMigrationDSNBytes = 16 * 1024

var releaseServicePurposes = []iamv1.ServicePurpose{
	iamv1.ServicePlatform,
	iamv1.ServiceDevOps,
}

// ReleaseServiceBinding is one installation-owned credential whose service
// identity is selected by the authenticated release. DEVOPS remains outside
// the fixed Foundation bootstrap inventory and is supplied only when selected.
type ReleaseServiceBinding struct {
	Purpose    iamv1.ServicePurpose
	Credential iamv1.Secret
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

// BootstrapRelease applies IAM bootstrap while binding the migration to the
// exact additional product catalog authenticated by the release owner.
func BootstrapRelease(ctx context.Context, executor postgresmigration.Executor, catalog iamv1.ProductAuthorizationReleaseCatalog) error {
	return postgresmigration.Bootstrap(ctx, executor, releaseSource(catalog))
}

// UpRelease applies IAM schema/data evolution and the authenticated additional
// product catalog in IAM's existing atomic transaction.
func UpRelease(ctx context.Context, executor postgresmigration.Executor, catalog iamv1.ProductAuthorizationReleaseCatalog) error {
	return postgresmigration.Up(ctx, executor, releaseSource(catalog))
}

// VerifyRelease verifies the installed IAM state against the same exact
// release catalog. It does not accept a runtime or tenant-selected registry.
func VerifyRelease(ctx context.Context, executor postgresmigration.Executor, catalog iamv1.ProductAuthorizationReleaseCatalog) error {
	return postgresmigration.Verify(ctx, executor, releaseSource(catalog))
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

// ApplyForInstallation retains the focused three-login migration boundary used
// by authority-process tests while also converging the release-selected service
// identities. Product releases use ApplyReleaseWithAccessAnalysisForInstallation.
func ApplyForInstallation(
	ctx context.Context,
	adminDSN, apiDSN, workerDSN, installationID string,
	bindings []ReleaseServiceBinding,
) error {
	arguments, err := releaseServiceArguments(installationID, bindings)
	if err != nil {
		return err
	}
	if err := Apply(ctx, adminDSN, apiDSN, workerDSN); err != nil {
		return err
	}
	return convergeReleaseServices(ctx, adminDSN, arguments)
}

func VerifyInstalledForInstallation(
	ctx context.Context,
	adminDSN, apiDSN, workerDSN, installationID string,
	bindings []ReleaseServiceBinding,
) error {
	arguments, err := releaseServiceArguments(installationID, bindings)
	if err != nil {
		return err
	}
	if err := VerifyInstalled(ctx, adminDSN, apiDSN, workerDSN); err != nil {
		return err
	}
	return verifyReleaseServices(ctx, adminDSN, arguments)
}

// ApplyWithLocalRecovery provisions separate installation-private recovery
// and backup-custody logins. Migration performs neither operational effect.
// Schema-only/runtime consumers of Apply do not acquire these capabilities.
func ApplyWithLocalRecovery(ctx context.Context, adminDSN, apiDSN, workerDSN, recoveryDSN, custodyDSN string) error {
	return postgresmigration.Apply(ctx, adminDSN, iammigrations.Source(), localRecoveryLogins(apiDSN, workerDSN, recoveryDSN, custodyDSN))
}

func VerifyInstalledWithLocalRecovery(ctx context.Context, adminDSN, apiDSN, workerDSN, recoveryDSN, custodyDSN string) error {
	return postgresmigration.VerifyInstalled(ctx, adminDSN, iammigrations.Source(), localRecoveryLogins(apiDSN, workerDSN, recoveryDSN, custodyDSN))
}

// Explicit notification provisioning does not add capabilities to existing
// API/Audit/custody/recovery logins. The earlier entry has real installation
// consumers which do not enable mail; it is not an implicit optional DSN.
func ApplyWithNotificationDelivery(ctx context.Context, adminDSN, apiDSN, workerDSN, recoveryDSN, custodyDSN, notificationDSN string) error {
	return postgresmigration.Apply(ctx, adminDSN, iammigrations.Source(), notificationDeliveryLogins(apiDSN, workerDSN, recoveryDSN, custodyDSN, notificationDSN))
}

func VerifyInstalledWithNotificationDelivery(ctx context.Context, adminDSN, apiDSN, workerDSN, recoveryDSN, custodyDSN, notificationDSN string) error {
	return postgresmigration.VerifyInstalled(ctx, adminDSN, iammigrations.Source(), notificationDeliveryLogins(apiDSN, workerDSN, recoveryDSN, custodyDSN, notificationDSN))
}

// ApplyWithAuthenticationRecovery provisions the final purpose-only login
// used to close, reconcile and reopen IAM around an authenticated database
// restore. It never performs a recovery effect during migration.
func ApplyWithAuthenticationRecovery(
	ctx context.Context,
	adminDSN, apiDSN, workerDSN, recoveryDSN, custodyDSN, notificationDSN, authenticationRecoveryDSN string,
) error {
	return postgresmigration.Apply(ctx, adminDSN, iammigrations.Source(),
		authenticationRecoveryLogins(apiDSN, workerDSN, recoveryDSN, custodyDSN, notificationDSN, authenticationRecoveryDSN))
}

func VerifyInstalledWithAuthenticationRecovery(
	ctx context.Context,
	adminDSN, apiDSN, workerDSN, recoveryDSN, custodyDSN, notificationDSN, authenticationRecoveryDSN string,
) error {
	return postgresmigration.VerifyInstalled(ctx, adminDSN, iammigrations.Source(),
		authenticationRecoveryLogins(apiDSN, workerDSN, recoveryDSN, custodyDSN, notificationDSN, authenticationRecoveryDSN))
}

// ApplyReleaseWithAccessAnalysis is the complete production installation
// boundary. The release catalog changes immutable registry data only; it does
// not alter the purpose-only database login inventory.
func ApplyReleaseWithAccessAnalysis(
	ctx context.Context,
	adminDSN, apiDSN, workerDSN, recoveryDSN, custodyDSN, notificationDSN, authenticationRecoveryDSN, accessAnalysisDSN string,
	catalog iamv1.ProductAuthorizationReleaseCatalog,
) error {
	return postgresmigration.Apply(ctx, adminDSN, releaseSource(catalog),
		accessAnalysisLogins(apiDSN, workerDSN, recoveryDSN, custodyDSN, notificationDSN, authenticationRecoveryDSN, accessAnalysisDSN))
}

// VerifyInstalledReleaseWithAccessAnalysis verifies the same production
// login inventory and authenticated product registry without applying state.
func VerifyInstalledReleaseWithAccessAnalysis(
	ctx context.Context,
	adminDSN, apiDSN, workerDSN, recoveryDSN, custodyDSN, notificationDSN, authenticationRecoveryDSN, accessAnalysisDSN string,
	catalog iamv1.ProductAuthorizationReleaseCatalog,
) error {
	return postgresmigration.VerifyInstalled(ctx, adminDSN, releaseSource(catalog),
		accessAnalysisLogins(apiDSN, workerDSN, recoveryDSN, custodyDSN, notificationDSN, authenticationRecoveryDSN, accessAnalysisDSN))
}

// ApplyReleaseWithAccessAnalysisForInstallation is the complete product
// release migration boundary: the authenticated catalog, purpose-only database
// roles and release-selected service principals are all bound to one invocation.
func ApplyReleaseWithAccessAnalysisForInstallation(
	ctx context.Context,
	adminDSN, apiDSN, workerDSN, recoveryDSN, custodyDSN, notificationDSN, authenticationRecoveryDSN, accessAnalysisDSN string,
	catalog iamv1.ProductAuthorizationReleaseCatalog,
	installationID string,
	bindings []ReleaseServiceBinding,
) error {
	arguments, err := releaseServiceArguments(installationID, bindings)
	if err != nil {
		return err
	}
	if err := ApplyReleaseWithAccessAnalysis(
		ctx, adminDSN, apiDSN, workerDSN, recoveryDSN, custodyDSN,
		notificationDSN, authenticationRecoveryDSN, accessAnalysisDSN, catalog,
	); err != nil {
		return err
	}
	return convergeReleaseServices(ctx, adminDSN, arguments)
}

func VerifyInstalledReleaseWithAccessAnalysisForInstallation(
	ctx context.Context,
	adminDSN, apiDSN, workerDSN, recoveryDSN, custodyDSN, notificationDSN, authenticationRecoveryDSN, accessAnalysisDSN string,
	catalog iamv1.ProductAuthorizationReleaseCatalog,
	installationID string,
	bindings []ReleaseServiceBinding,
) error {
	arguments, err := releaseServiceArguments(installationID, bindings)
	if err != nil {
		return err
	}
	if err := VerifyInstalledReleaseWithAccessAnalysis(
		ctx, adminDSN, apiDSN, workerDSN, recoveryDSN, custodyDSN,
		notificationDSN, authenticationRecoveryDSN, accessAnalysisDSN, catalog,
	); err != nil {
		return err
	}
	return verifyReleaseServices(ctx, adminDSN, arguments)
}

type releaseServiceDigests struct {
	installationID     string
	purpose            iamv1.ServicePurpose
	principalID        iamv1.PrincipalID
	lookupDigest       string
	verificationDigest string
	requestDigest      string
}

func releaseServiceArguments(
	installationID string,
	bindings []ReleaseServiceBinding,
) ([]releaseServiceDigests, error) {
	if iamv1.ValidateID("installationId", installationID) != nil ||
		len(bindings) == 0 || len(bindings) > len(releaseServicePurposes) {
		return nil, errors.New("IAM release service bindings are invalid")
	}
	result := make([]releaseServiceDigests, 0, len(bindings))
	for index, binding := range bindings {
		if binding.Purpose != releaseServicePurposes[index] || !binding.Credential.Present() {
			return nil, errors.New("IAM release service bindings are invalid")
		}
		principalID, valid := releaseServicePrincipalID(binding.Purpose)
		if !valid {
			return nil, errors.New("IAM release service bindings are invalid")
		}
		lookupDigest, err := authority.LookupCredentialDigest(authority.CredentialService, binding.Credential)
		if err != nil {
			return nil, errors.New("IAM release service bindings are invalid")
		}
		verificationDigest, err := authority.DigestCredential(
			authority.CredentialService, string(principalID), binding.Credential,
		)
		if err != nil {
			return nil, errors.New("IAM release service bindings are invalid")
		}
		request := sha256.New()
		_, _ = request.Write([]byte("matrix-iam-release-service-enrollment-v1\x00"))
		_, _ = request.Write([]byte(installationID))
		_, _ = request.Write([]byte{'\x00'})
		_, _ = request.Write([]byte(binding.Purpose))
		_, _ = request.Write([]byte{'\x00'})
		_, _ = request.Write([]byte(principalID))
		_, _ = request.Write([]byte{'\x00'})
		_, _ = request.Write([]byte(lookupDigest))
		_, _ = request.Write([]byte{'\x00'})
		_, _ = request.Write([]byte(verificationDigest))
		result = append(result, releaseServiceDigests{
			installationID: installationID,
			purpose:        binding.Purpose, principalID: principalID,
			lookupDigest: lookupDigest, verificationDigest: verificationDigest,
			requestDigest: "sha256:" + hex.EncodeToString(request.Sum(nil)),
		})
	}
	return result, nil
}

func releaseServicePrincipalID(purpose iamv1.ServicePurpose) (iamv1.PrincipalID, bool) {
	switch purpose {
	case iamv1.ServicePlatform:
		return "service-platform", true
	case iamv1.ServiceDevOps:
		return "service-devops", true
	default:
		return "", false
	}
}

func convergeReleaseServices(
	ctx context.Context,
	adminDSN string,
	arguments []releaseServiceDigests,
) error {
	for _, service := range arguments {
		outcome, err := executeReleaseServiceFunction(
			ctx, adminDSN,
			"SELECT iam.ensure_release_service($1, $2, $3, $4, $5)",
			service.installationID, string(service.purpose), service.lookupDigest,
			service.verificationDigest, service.requestDigest,
		)
		if err != nil || (outcome != "UNINITIALIZED" && outcome != "APPLIED" && outcome != "EQUAL_REPLAY") {
			return errors.New("IAM release service enrollment failed")
		}
		verified, err := verifyReleaseService(ctx, adminDSN, service)
		if err != nil || (outcome == "UNINITIALIZED" && verified != "UNINITIALIZED") ||
			(outcome != "UNINITIALIZED" && verified != "READY") {
			return errors.New("IAM release service enrollment verification failed")
		}
	}
	return nil
}

func verifyReleaseServices(
	ctx context.Context,
	adminDSN string,
	arguments []releaseServiceDigests,
) error {
	for _, service := range arguments {
		outcome, err := verifyReleaseService(ctx, adminDSN, service)
		if err != nil || (outcome != "UNINITIALIZED" && outcome != "READY") {
			return errors.New("IAM release service verification failed")
		}
	}
	return nil
}

func verifyReleaseService(
	ctx context.Context,
	adminDSN string,
	arguments releaseServiceDigests,
) (string, error) {
	return executeReleaseServiceFunction(
		ctx, adminDSN,
		"SELECT iam.verify_release_service($1, $2, $3, $4)",
		arguments.installationID, string(arguments.purpose),
		arguments.lookupDigest, arguments.verificationDigest,
	)
}

func executeReleaseServiceFunction(
	ctx context.Context,
	adminDSN string,
	statement string,
	arguments ...any,
) (string, error) {
	if ctx == nil || len(adminDSN) == 0 || len(adminDSN) > maximumMigrationDSNBytes ||
		strings.ContainsAny(adminDSN, "\x00\r\n") {
		return "", errors.New("IAM release service database configuration is invalid")
	}
	config, err := pgx.ParseConfig(adminDSN)
	if err != nil || config.User == "" || config.Password == "" || config.Host == "" ||
		config.Port == 0 || config.Database == "" {
		return "", errors.New("IAM release service database configuration is invalid")
	}
	connection, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		return "", errors.New("IAM release service database is unavailable")
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
		return "", errors.New("IAM release service migration lock is unavailable")
	}
	var outcome string
	if err := connection.QueryRow(ctx, statement, arguments...).Scan(&outcome); err != nil {
		return "", errors.New("IAM release service database operation failed")
	}
	return outcome, nil
}

func releaseSource(catalog iamv1.ProductAuthorizationReleaseCatalog) postgresmigration.Source {
	return iammigrations.SourceWithProductAuthorization(catalog)
}

func accessAnalysisLogins(apiDSN, workerDSN, recoveryDSN, custodyDSN, notificationDSN, authenticationRecoveryDSN, accessAnalysisDSN string) []postgresmigration.Login {
	logins := authenticationRecoveryLogins(apiDSN, workerDSN, recoveryDSN, custodyDSN, notificationDSN, authenticationRecoveryDSN)
	return append([]postgresmigration.Login{{Name: "matrix_iam_access_analysis_worker_login", Group: "matrix_iam_access_analysis_worker", DSN: accessAnalysisDSN}}, logins...)
}

func authenticationRecoveryLogins(apiDSN, workerDSN, recoveryDSN, custodyDSN, notificationDSN, authenticationRecoveryDSN string) []postgresmigration.Login {
	logins := notificationDeliveryLogins(apiDSN, workerDSN, recoveryDSN, custodyDSN, notificationDSN)
	return append(append(logins[:1:1], postgresmigration.Login{
		Name: "matrix_iam_authentication_recovery_login", Group: "matrix_iam_authentication_recovery", DSN: authenticationRecoveryDSN,
	}), logins[1:]...)
}

func notificationDeliveryLogins(apiDSN, workerDSN, recoveryDSN, custodyDSN, notificationDSN string) []postgresmigration.Login {
	logins := localRecoveryLogins(apiDSN, workerDSN, recoveryDSN, custodyDSN)
	// Maintain the existing sorted login inventory, adding one closed purpose.
	return append(append(logins[:3:3], postgresmigration.Login{Name: "matrix_iam_notification_worker_login", Group: "matrix_iam_notification_worker", DSN: notificationDSN}), logins[3])
}

func localRecoveryLogins(apiDSN, workerDSN, recoveryDSN, custodyDSN string) []postgresmigration.Login {
	return []postgresmigration.Login{
		{Name: "matrix_iam_api_login", Group: "matrix_iam_api", DSN: apiDSN},
		{Name: "matrix_iam_backup_custody_login", Group: "matrix_iam_backup_custody", DSN: custodyDSN},
		{Name: "matrix_iam_credential_recovery_login", Group: "matrix_iam_credential_recovery", DSN: recoveryDSN},
		{Name: "matrix_iam_worker_login", Group: "matrix_iam_worker", DSN: workerDSN},
	}
}
