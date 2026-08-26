// Package migration is Application PaaS's operational PostgreSQL migration
// boundary.
package migration

import (
	"context"

	"github.com/xiak/matrix/app/service/internal/postgresmigration"
	paasmigrations "github.com/xiak/matrix/app/service/paas/internal/apphosting/data/postgres/migrations"
	managedservicemigrations "github.com/xiak/matrix/app/service/paas/internal/managedservice/data/postgres/migrations"
)

func Up(ctx context.Context, executor postgresmigration.Executor) error {
	return postgresmigration.Up(ctx, executor, source())
}

func Verify(ctx context.Context, executor postgresmigration.Executor) error {
	return postgresmigration.Verify(ctx, executor, source())
}

func Apply(ctx context.Context, adminDSN, apiDSN, workerDSN string) error {
	return postgresmigration.Apply(ctx, adminDSN, source(), []postgresmigration.Login{
		{Name: "matrix_paas_api_login", Group: "matrix_paas_api", DSN: apiDSN},
		{Name: "matrix_paas_worker_login", Group: "matrix_paas_worker", DSN: workerDSN},
	})
}

func VerifyInstalled(ctx context.Context, adminDSN, apiDSN, workerDSN string) error {
	return postgresmigration.VerifyInstalled(
		ctx, adminDSN, source(),
		[]postgresmigration.Login{
			{Name: "matrix_paas_api_login", Group: "matrix_paas_api", DSN: apiDSN},
			{Name: "matrix_paas_worker_login", Group: "matrix_paas_worker", DSN: workerDSN},
		},
	)
}

func source() postgresmigration.Source {
	apphosting := paasmigrations.Source()
	managedservice := managedservicemigrations.Source()
	return postgresmigration.Source{
		Context:   "paas",
		UpSQL:     apphosting.UpSQL + "\n" + managedservice.UpSQL,
		VerifySQL: apphosting.VerifySQL + "\n" + managedservice.VerifySQL,
	}
}
