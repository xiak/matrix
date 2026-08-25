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
