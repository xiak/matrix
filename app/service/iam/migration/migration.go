// Package migration is IAM's operational PostgreSQL migration boundary.
// Embedded schema content remains owned by IAM while installation and
// cross-process acceptance consume these behavior-level functions.
package migration

import (
	"context"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
	iammigrations "github.com/xiak/matrix/app/service/iam/internal/data/postgres/migrations"
	"github.com/xiak/matrix/app/service/internal/postgresmigration"
)

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
