// Package migration is IAM's operational PostgreSQL migration boundary.
// Embedded schema content remains owned by IAM while installation and
// cross-process acceptance consume these behavior-level functions.
package migration

import (
	"context"

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

// ApplyWithAuthenticationRecovery provisions the final purpose-only login
// used to close, reconcile and reopen IAM around an authenticated database
// restore. It never performs a recovery effect during migration.
func ApplyWithAuthenticationRecovery(
	ctx context.Context,
	adminDSN, apiDSN, workerDSN, recoveryDSN, custodyDSN, authenticationRecoveryDSN string,
) error {
	return postgresmigration.Apply(ctx, adminDSN, iammigrations.Source(),
		authenticationRecoveryLogins(apiDSN, workerDSN, recoveryDSN, custodyDSN, authenticationRecoveryDSN))
}

func VerifyInstalledWithAuthenticationRecovery(
	ctx context.Context,
	adminDSN, apiDSN, workerDSN, recoveryDSN, custodyDSN, authenticationRecoveryDSN string,
) error {
	return postgresmigration.VerifyInstalled(ctx, adminDSN, iammigrations.Source(),
		authenticationRecoveryLogins(apiDSN, workerDSN, recoveryDSN, custodyDSN, authenticationRecoveryDSN))
}

func authenticationRecoveryLogins(apiDSN, workerDSN, recoveryDSN, custodyDSN, authenticationRecoveryDSN string) []postgresmigration.Login {
	logins := localRecoveryLogins(apiDSN, workerDSN, recoveryDSN, custodyDSN)
	return append(append(logins[:1:1], postgresmigration.Login{
		Name: "matrix_iam_authentication_recovery_login", Group: "matrix_iam_authentication_recovery", DSN: authenticationRecoveryDSN,
	}), logins[1:]...)
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

func notificationDeliveryLogins(apiDSN, workerDSN, recoveryDSN, custodyDSN, notificationDSN string) []postgresmigration.Login {
	logins := localRecoveryLogins(apiDSN, workerDSN, recoveryDSN, custodyDSN)
	// Maintain the existing sorted login inventory, adding one closed purpose.
	return append(append(logins[:3:3], postgresmigration.Login{Name: "matrix_iam_notification_worker_login", Group: "matrix_iam_notification_worker", DSN: notificationDSN}), logins[3])
}

// ApplyWithAuthenticationRecoveryAndNotificationDelivery provisions both
// independent purpose-only capabilities without adding either capability to
// an existing runtime, custody, or credential-recovery login.
func ApplyWithAuthenticationRecoveryAndNotificationDelivery(
	ctx context.Context,
	adminDSN, apiDSN, workerDSN, recoveryDSN, custodyDSN, authenticationRecoveryDSN, notificationDSN string,
) error {
	return postgresmigration.Apply(ctx, adminDSN, iammigrations.Source(),
		authenticationRecoveryAndNotificationLogins(apiDSN, workerDSN, recoveryDSN, custodyDSN, authenticationRecoveryDSN, notificationDSN))
}

func VerifyInstalledWithAuthenticationRecoveryAndNotificationDelivery(
	ctx context.Context,
	adminDSN, apiDSN, workerDSN, recoveryDSN, custodyDSN, authenticationRecoveryDSN, notificationDSN string,
) error {
	return postgresmigration.VerifyInstalled(ctx, adminDSN, iammigrations.Source(),
		authenticationRecoveryAndNotificationLogins(apiDSN, workerDSN, recoveryDSN, custodyDSN, authenticationRecoveryDSN, notificationDSN))
}

func authenticationRecoveryAndNotificationLogins(
	apiDSN, workerDSN, recoveryDSN, custodyDSN, authenticationRecoveryDSN, notificationDSN string,
) []postgresmigration.Login {
	logins := authenticationRecoveryLogins(apiDSN, workerDSN, recoveryDSN, custodyDSN, authenticationRecoveryDSN)
	return append(append(logins[:4:4], postgresmigration.Login{
		Name: "matrix_iam_notification_worker_login", Group: "matrix_iam_notification_worker", DSN: notificationDSN,
	}), logins[4:]...)
}

func localRecoveryLogins(apiDSN, workerDSN, recoveryDSN, custodyDSN string) []postgresmigration.Login {
	return []postgresmigration.Login{
		{Name: "matrix_iam_api_login", Group: "matrix_iam_api", DSN: apiDSN},
		{Name: "matrix_iam_backup_custody_login", Group: "matrix_iam_backup_custody", DSN: custodyDSN},
		{Name: "matrix_iam_credential_recovery_login", Group: "matrix_iam_credential_recovery", DSN: recoveryDSN},
		{Name: "matrix_iam_worker_login", Group: "matrix_iam_worker", DSN: workerDSN},
	}
}
