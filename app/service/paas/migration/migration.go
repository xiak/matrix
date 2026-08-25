// Package migration is Application PaaS's operational PostgreSQL migration
// boundary.
package migration

import (
	"context"

	"github.com/xiak/matrix/app/service/internal/postgresmigration"
	paasmigrations "github.com/xiak/matrix/app/service/paas/internal/apphosting/data/postgres/migrations"
)

func Up(ctx context.Context, executor postgresmigration.Executor) error {
	return postgresmigration.Up(ctx, executor, paasmigrations.Source())
}

func Verify(ctx context.Context, executor postgresmigration.Executor) error {
	return postgresmigration.Verify(ctx, executor, paasmigrations.Source())
}

func Apply(ctx context.Context, adminDSN, apiDSN, workerDSN string) error {
	return postgresmigration.Apply(ctx, adminDSN, paasmigrations.Source(), []postgresmigration.Login{
		{Name: "matrix_paas_api_login", Group: "matrix_paas_api", DSN: apiDSN},
		{Name: "matrix_paas_worker_login", Group: "matrix_paas_worker", DSN: workerDSN},
	})
}

func VerifyInstalled(ctx context.Context, adminDSN, apiDSN, workerDSN string) error {
	return postgresmigration.VerifyInstalled(
		ctx, adminDSN, paasmigrations.Source(),
		[]postgresmigration.Login{
			{Name: "matrix_paas_api_login", Group: "matrix_paas_api", DSN: apiDSN},
			{Name: "matrix_paas_worker_login", Group: "matrix_paas_worker", DSN: workerDSN},
		},
	)
}
