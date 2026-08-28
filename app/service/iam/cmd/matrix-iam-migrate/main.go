package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	iammigration "github.com/xiak/matrix/app/service/iam/migration"
	"github.com/xiak/matrix/app/service/internal/migrationprocess"
)

var dsnFileEnvironments = []string{
	"MATRIX_MIGRATION_DATABASE_DSN_FILE",
	"MATRIX_MIGRATION_IAM_API_DSN_FILE",
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
	return migrationprocess.Run(ctx, arguments, migrationprocess.Configuration{
		DSNFileEnvironments: dsnFileEnvironments,
		Apply: func(ctx context.Context, values []string) error {
			return iammigration.ApplyWithLocalRecovery(ctx, values[0], values[1], values[3], values[2])
		},
		Verify: func(ctx context.Context, values []string) error {
			return iammigration.VerifyInstalledWithLocalRecovery(ctx, values[0], values[1], values[3], values[2])
		},
	})
}
