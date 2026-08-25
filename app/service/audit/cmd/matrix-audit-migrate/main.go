package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	auditmigration "github.com/xiak/matrix/app/service/audit/migration"
	"github.com/xiak/matrix/app/service/internal/migrationprocess"
)

var dsnFileEnvironments = []string{
	"MATRIX_MIGRATION_AUDIT_RUNTIME_DSN_FILE",
	"MATRIX_MIGRATION_DATABASE_DSN_FILE",
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "matrix Audit migration failed")
		os.Exit(1)
	}
}

func run(ctx context.Context, arguments []string) error {
	return migrationprocess.Run(ctx, arguments, migrationprocess.Configuration{
		DSNFileEnvironments: dsnFileEnvironments,
		Apply: func(ctx context.Context, values []string) error {
			return auditmigration.Apply(ctx, values[1], values[0])
		},
		Verify: func(ctx context.Context, values []string) error {
			return auditmigration.VerifyInstalled(ctx, values[1], values[0])
		},
	})
}
