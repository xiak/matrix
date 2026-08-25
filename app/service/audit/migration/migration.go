// Package migration is Audit's operational PostgreSQL migration boundary.
package migration

import (
	"context"

	auditmigrations "github.com/xiak/matrix/app/service/audit/internal/data/postgres/migrations"
	"github.com/xiak/matrix/app/service/internal/postgresmigration"
)

func Bootstrap(ctx context.Context, executor postgresmigration.Executor) error {
	return postgresmigration.Bootstrap(ctx, executor, auditmigrations.Source())
}

func Up(ctx context.Context, executor postgresmigration.Executor) error {
	return postgresmigration.Up(ctx, executor, auditmigrations.Source())
}

func Verify(ctx context.Context, executor postgresmigration.Executor) error {
	return postgresmigration.Verify(ctx, executor, auditmigrations.Source())
}

func Apply(ctx context.Context, adminDSN, runtimeDSN string) error {
	return postgresmigration.Apply(ctx, adminDSN, auditmigrations.Source(), []postgresmigration.Login{
		{Name: "matrix_audit_runtime_login", Group: "matrix_audit_runtime", DSN: runtimeDSN},
	})
}

func VerifyInstalled(ctx context.Context, adminDSN, runtimeDSN string) error {
	return postgresmigration.VerifyInstalled(
		ctx, adminDSN, auditmigrations.Source(),
		[]postgresmigration.Login{
			{Name: "matrix_audit_runtime_login", Group: "matrix_audit_runtime", DSN: runtimeDSN},
		},
	)
}
