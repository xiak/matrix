package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spf13/cobra"

	installationv1 "github.com/xiak/matrix/api/adapter/installation/v1"
	iampostgres "github.com/xiak/matrix/app/service/iam/internal/data/postgres"
	"github.com/xiak/matrix/app/service/iam/internal/usecase/authenticationrecovery"
	"github.com/xiak/matrix/app/service/internal/processconfig"
)

const recoveryLogin = "matrix_iam_authentication_recovery_login"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Getenv); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, errorCode(err))
		os.Exit(exitCode(err))
	}
}

func errorCode(err error) string {
	switch {
	case errors.Is(err, authenticationrecovery.ErrInvalidArgument):
		return installationv1.AuthenticationRecoveryErrorInvalid
	case errors.Is(err, authenticationrecovery.ErrForbidden):
		return installationv1.AuthenticationRecoveryErrorForbidden
	case errors.Is(err, authenticationrecovery.ErrConflict):
		return installationv1.AuthenticationRecoveryErrorConflict
	default:
		return installationv1.AuthenticationRecoveryErrorUnavailable
	}
}

func exitCode(err error) int {
	if err == nil {
		return installationv1.AuthenticationRecoveryExitSuccess
	}
	switch errorCode(err) {
	case installationv1.AuthenticationRecoveryErrorInvalid:
		return installationv1.AuthenticationRecoveryExitInvalid
	case installationv1.AuthenticationRecoveryErrorForbidden:
		return installationv1.AuthenticationRecoveryExitForbidden
	case installationv1.AuthenticationRecoveryErrorConflict:
		return installationv1.AuthenticationRecoveryExitConflict
	default:
		return installationv1.AuthenticationRecoveryExitUnavailable
	}
}

func run(ctx context.Context, arguments []string, output io.Writer, getenv func(string) string) error {
	if ctx == nil || output == nil || getenv == nil || len(arguments) != 1 {
		return authenticationrecovery.ErrInvalidArgument
	}
	mode := arguments[0]
	if mode != installationv1.AuthenticationRecoveryCloseCommand &&
		mode != installationv1.AuthenticationRecoveryReconcileCommand &&
		mode != installationv1.AuthenticationRecoveryReopenCommand {
		return authenticationrecovery.ErrInvalidArgument
	}
	command := &cobra.Command{
		Use:           "matrix-iam-authentication-recovery close|reconcile|reopen",
		SilenceErrors: true, SilenceUsage: true, DisableFlagParsing: true,
		Args: cobra.ExactArgs(1),
		RunE: func(command *cobra.Command, values []string) error {
			return execute(command.Context(), values[0], output, getenv)
		},
	}
	command.SetArgs(arguments)
	command.SetOut(io.Discard)
	command.SetErr(io.Discard)
	return command.ExecuteContext(ctx)
}

func execute(ctx context.Context, mode string, output io.Writer, getenv func(string) string) error {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	intentPath := getenv(installationv1.AuthenticationRecoveryIntentFileEnvironment)
	closurePath := getenv(installationv1.AuthenticationRecoveryClosureFileEnvironment)
	if mode == installationv1.AuthenticationRecoveryCloseCommand {
		if intentPath == "" || closurePath != "" {
			return authenticationrecovery.ErrInvalidArgument
		}
	} else if closurePath == "" || intentPath != "" {
		return authenticationrecovery.ErrInvalidArgument
	}

	var intent installationv1.AuthenticationRecoveryIntent
	var closure installationv1.AuthenticationRecoveryClosure
	path := closurePath
	if mode == installationv1.AuthenticationRecoveryCloseCommand {
		path = intentPath
	}
	encoded, err := processconfig.ReadFile(path, installationv1.MaximumAuthenticationRecoveryBytes, true)
	if err != nil {
		return authenticationrecovery.ErrInvalidArgument
	}
	defer clear(encoded)
	if mode == installationv1.AuthenticationRecoveryCloseCommand {
		intent, err = installationv1.DecodeAuthenticationRecoveryIntent(bytes.NewReader(encoded))
	} else {
		closure, err = installationv1.DecodeAuthenticationRecoveryClosure(bytes.NewReader(encoded))
	}
	if err != nil {
		return authenticationrecovery.ErrInvalidArgument
	}

	dsn, err := processconfig.ReadText(getenv(installationv1.AuthenticationRecoveryDatabaseDSNFileEnvironment), 16*1024, true)
	if err != nil {
		return authenticationrecovery.ErrInvalidArgument
	}
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil || config.ConnConfig.User != recoveryLogin || config.ConnConfig.Password == "" {
		return authenticationrecovery.ErrForbidden
	}
	config.MaxConns, config.MinConns = 1, 0
	config.ConnConfig.ConnectTimeout = 10 * time.Second
	config.ConnConfig.RuntimeParams["application_name"] = "matrix-iam-authentication-recovery"
	config.ConnConfig.RuntimeParams["statement_timeout"] = "15000"
	config.ConnConfig.RuntimeParams["lock_timeout"] = "5000"
	config.ConnConfig.RuntimeParams["default_transaction_isolation"] = "serializable"
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return authenticationrecovery.ErrUnavailable
	}
	defer pool.Close()
	if err := verifyRecoveryLogin(ctx, pool); err != nil {
		return err
	}
	repository, err := iampostgres.NewRepository(pool)
	if err != nil {
		return authenticationrecovery.ErrUnavailable
	}
	workflow, err := authenticationrecovery.NewService(repository, authenticationrecovery.Config{})
	if err != nil {
		return authenticationrecovery.ErrUnavailable
	}
	var result []byte
	switch mode {
	case installationv1.AuthenticationRecoveryCloseCommand:
		value, runErr := workflow.Close(ctx, intent)
		if runErr != nil {
			return runErr
		}
		result, err = installationv1.EncodeAuthenticationRecoveryClosure(value)
	case installationv1.AuthenticationRecoveryReconcileCommand:
		value, runErr := workflow.Reconcile(ctx, closure)
		if runErr != nil {
			return runErr
		}
		result, err = installationv1.EncodeAuthenticationRecoveryClosure(value)
	case installationv1.AuthenticationRecoveryReopenCommand:
		value, runErr := workflow.Reopen(ctx, closure)
		if runErr != nil {
			return runErr
		}
		result, err = installationv1.EncodeAuthenticationRecoveryCompletion(value)
	}
	if err != nil {
		return authenticationrecovery.ErrUnavailable
	}
	if _, err := output.Write(result); err != nil {
		// The transaction may have committed. Installation observes the exact
		// sealed command instead of allocating another epoch or intent.
		return authenticationrecovery.ErrUnavailable
	}
	return nil
}

func verifyRecoveryLogin(ctx context.Context, pool *pgxpool.Pool) error {
	var sessionUser, currentUser string
	var restricted bool
	err := pool.QueryRow(ctx, `SELECT session_user,current_user,
        own.rolcanlogin AND NOT own.rolsuper AND NOT own.rolcreatedb AND NOT own.rolcreaterole
        AND NOT own.rolreplication AND NOT own.rolbypassrls
        AND pg_catalog.pg_has_role(session_user,'matrix_iam_authentication_recovery','USAGE')
        AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_roles AS other
            WHERE other.rolname NOT IN (session_user,'matrix_iam_authentication_recovery')
              AND pg_catalog.pg_has_role(session_user,other.oid,'MEMBER'))
        AND has_schema_privilege(session_user,'iam','USAGE')
        AND NOT has_schema_privilege(session_user,'iam','CREATE')
        AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c WHERE c.relnamespace='iam'::regnamespace
            AND c.relkind IN ('r','p','v','m','f')
            AND has_table_privilege(session_user,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'))
        AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p WHERE p.pronamespace='iam'::regnamespace
            AND p.oid NOT IN (to_regprocedure('iam.close_authentication_recovery(jsonb,text,jsonb)'),
                to_regprocedure('iam.reconcile_authentication_recovery(jsonb,text,jsonb,jsonb)'),
                to_regprocedure('iam.reopen_authentication_recovery(jsonb,text,jsonb)'))
            AND has_function_privilege(session_user,p.oid,'EXECUTE'))
        FROM pg_catalog.pg_roles AS own WHERE own.rolname=session_user`).Scan(&sessionUser, &currentUser, &restricted)
	if err != nil {
		return authenticationrecovery.ErrUnavailable
	}
	if !restricted || sessionUser != recoveryLogin || currentUser != recoveryLogin {
		return authenticationrecovery.ErrForbidden
	}
	return nil
}
