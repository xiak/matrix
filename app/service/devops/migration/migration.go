// Package migration is Matrix DevOps's operational PostgreSQL migration boundary.
package migration

import (
	"context"

	devopsmigrations "github.com/xiak/matrix/app/service/devops/internal/delivery/data/postgres/migrations"
	"github.com/xiak/matrix/app/service/internal/postgresmigration"
)

func Bootstrap(ctx context.Context, executor postgresmigration.Executor) error {
	return postgresmigration.Bootstrap(ctx, executor, devopsmigrations.Source())
}

func Up(ctx context.Context, executor postgresmigration.Executor) error {
	return postgresmigration.Up(ctx, executor, devopsmigrations.Source())
}

func Verify(ctx context.Context, executor postgresmigration.Executor) error {
	return postgresmigration.Verify(ctx, executor, devopsmigrations.Source())
}

func Apply(
	ctx context.Context,
	adminDSN, apiDSN, sourceFetcherDSN, sourceObserverDSN, workerDSN string,
) error {
	return postgresmigration.Apply(ctx, adminDSN, devopsmigrations.Source(), []postgresmigration.Login{
		{Name: "matrix_devops_api_login", Group: "matrix_devops_api", DSN: apiDSN},
		{Name: "matrix_devops_source_fetcher_login", Group: "matrix_devops_source_fetcher", DSN: sourceFetcherDSN},
		{Name: "matrix_devops_source_observer_login", Group: "matrix_devops_source_observer", DSN: sourceObserverDSN},
		{Name: "matrix_devops_worker_login", Group: "matrix_devops_worker", DSN: workerDSN},
	})
}

func VerifyInstalled(
	ctx context.Context,
	adminDSN, apiDSN, sourceFetcherDSN, sourceObserverDSN, workerDSN string,
) error {
	return postgresmigration.VerifyInstalled(ctx, adminDSN, devopsmigrations.Source(), []postgresmigration.Login{
		{Name: "matrix_devops_api_login", Group: "matrix_devops_api", DSN: apiDSN},
		{Name: "matrix_devops_source_fetcher_login", Group: "matrix_devops_source_fetcher", DSN: sourceFetcherDSN},
		{Name: "matrix_devops_source_observer_login", Group: "matrix_devops_source_observer", DSN: sourceObserverDSN},
		{Name: "matrix_devops_worker_login", Group: "matrix_devops_worker", DSN: workerDSN},
	})
}
