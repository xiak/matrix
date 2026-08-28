package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spf13/cobra"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
	iampostgres "github.com/xiak/matrix/app/service/iam/internal/data/postgres"
	"github.com/xiak/matrix/app/service/iam/internal/usecase/identityaccess"
	"github.com/xiak/matrix/app/service/internal/processconfig"
)

const (
	databaseFileEnvironment  = "MATRIX_IAM_LOCAL_RECOVERY_DATABASE_DSN_FILE"
	authorityFileEnvironment = "MATRIX_IAM_LOCAL_RECOVERY_AUTHORITY_FILE"
	requestFileEnvironment   = "MATRIX_IAM_LOCAL_RECOVERY_REQUEST_FILE"
	recoveryLogin            = "matrix_iam_credential_recovery_login"
)

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
	case errors.Is(err, identityaccess.ErrInvalidArgument):
		return "IAM_LOCAL_RECOVERY_INVALID"
	case errors.Is(err, identityaccess.ErrForbidden):
		return "IAM_LOCAL_RECOVERY_FORBIDDEN"
	case errors.Is(err, identityaccess.ErrConflict):
		return "IAM_LOCAL_RECOVERY_CONFLICT"
	default:
		return "IAM_LOCAL_RECOVERY_UNAVAILABLE"
	}
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	switch errorCode(err) {
	case "IAM_LOCAL_RECOVERY_INVALID":
		return 2
	case "IAM_LOCAL_RECOVERY_FORBIDDEN":
		return 3
	case "IAM_LOCAL_RECOVERY_CONFLICT":
		return 4
	default:
		return 6
	}
}

func run(ctx context.Context, arguments []string, output io.Writer, getenv func(string) string) error {
	if ctx == nil || output == nil || getenv == nil || len(arguments) != 1 ||
		(arguments[0] != "inspect" && arguments[0] != "apply") {
		return identityaccess.ErrInvalidArgument
	}
	command := &cobra.Command{
		Use: "matrix-iam-local-recovery inspect|apply", SilenceErrors: true, SilenceUsage: true,
		DisableFlagParsing: true, Args: cobra.ExactArgs(1),
		RunE: func(command *cobra.Command, arguments []string) error {
			return execute(command.Context(), arguments[0], output, getenv)
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
	encoded, err := processconfig.ReadFile(getenv(authorityFileEnvironment), iamv1.MaxLocalCredentialRecoveryBytes, true)
	if err != nil {
		return identityaccess.ErrInvalidArgument
	}
	local, err := iamv1.DecodeLocalCredentialRecoveryAuthority(bytes.NewReader(encoded))
	clear(encoded)
	if err != nil {
		return identityaccess.ErrInvalidArgument
	}
	var request iamv1.LocalCredentialRecoveryRequest
	var query *iamv1.LocalCredentialRecoveryReceiptQuery
	if path := getenv(requestFileEnvironment); path != "" {
		encoded, err := processconfig.ReadFile(path, iamv1.MaxLocalCredentialRecoveryBytes, true)
		if err != nil {
			return identityaccess.ErrInvalidArgument
		}
		defer clear(encoded)
		if mode == "apply" {
			request, err = iamv1.DecodeLocalCredentialRecoveryRequest(bytes.NewReader(encoded))
			if err != nil {
				return identityaccess.ErrInvalidArgument
			}
			if _, err := iamv1.VerifyLocalCredentialRecoveryRequest(local, request); err != nil {
				return identityaccess.ErrForbidden
			}
		} else {
			query = new(iamv1.LocalCredentialRecoveryReceiptQuery)
			if iamv1.DecodeRequest(bytes.NewReader(encoded), query) != nil || iamv1.ValidateLocalCredentialRecoveryReceiptQuery(*query) != nil {
				return identityaccess.ErrInvalidArgument
			}
		}
	} else if mode == "apply" {
		return identityaccess.ErrInvalidArgument
	}
	dsn, err := processconfig.ReadText(getenv(databaseFileEnvironment), 16*1024, true)
	if err != nil {
		return identityaccess.ErrInvalidArgument
	}
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil || config.ConnConfig.User != recoveryLogin || config.ConnConfig.Password == "" {
		return identityaccess.ErrForbidden
	}
	config.MaxConns, config.MinConns = 1, 0
	config.ConnConfig.ConnectTimeout = 10 * time.Second
	config.ConnConfig.RuntimeParams["application_name"] = "matrix-iam-local-recovery"
	config.ConnConfig.RuntimeParams["statement_timeout"] = "15000"
	config.ConnConfig.RuntimeParams["lock_timeout"] = "5000"
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return identityaccess.ErrUnavailable
	}
	defer pool.Close()
	if err := verifyRecoveryLogin(ctx, pool); err != nil {
		return err
	}
	repository, err := iampostgres.NewRepository(pool)
	if err != nil {
		return identityaccess.ErrUnavailable
	}
	workflow, err := identityaccess.NewAuthority(repository, identityaccess.Config{})
	if err != nil {
		return identityaccess.ErrUnavailable
	}
	var result any
	if mode == "inspect" {
		result, err = workflow.InspectLocalCredentialRecovery(ctx, local, query)
	} else {
		result, err = workflow.RecoverLocalCredentials(ctx, local, request)
	}
	if err != nil {
		return err
	}
	if err := json.NewEncoder(output).Encode(result); err != nil {
		// The transaction may have committed. Installation resolves this unknown
		// outcome through the sealed command/commitment receipt query.
		return identityaccess.ErrUnavailable
	}
	return nil
}

func verifyRecoveryLogin(ctx context.Context, pool *pgxpool.Pool) error {
	var sessionUser, currentUser string
	var restricted bool
	err := pool.QueryRow(ctx, `SELECT session_user,current_user,
        own.rolcanlogin AND NOT own.rolsuper AND NOT own.rolcreatedb AND NOT own.rolcreaterole
        AND NOT own.rolreplication AND NOT own.rolbypassrls
        AND pg_catalog.pg_has_role(session_user,'matrix_iam_credential_recovery','USAGE')
        AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_roles AS other
            WHERE other.rolname NOT IN (session_user,'matrix_iam_credential_recovery')
              AND pg_catalog.pg_has_role(session_user,other.oid,'MEMBER'))
        FROM pg_catalog.pg_roles AS own WHERE own.rolname=session_user`).Scan(&sessionUser, &currentUser, &restricted)
	if err != nil {
		return identityaccess.ErrUnavailable
	}
	if !restricted || sessionUser != recoveryLogin || currentUser != recoveryLogin {
		return identityaccess.ErrForbidden
	}
	return nil
}
