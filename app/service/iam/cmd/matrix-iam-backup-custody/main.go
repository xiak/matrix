package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	installationv1 "github.com/xiak/matrix/api/adapter/installation/v1"
	iampostgres "github.com/xiak/matrix/app/service/iam/internal/data/postgres"
	"github.com/xiak/matrix/app/service/internal/processconfig"
)

var errInvalid = errors.New(installationv1.TOTPBackupCustodyErrorInvalid)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Getenv); err != nil {
		code, text := failure(err)
		_, _ = fmt.Fprintln(os.Stderr, text)
		os.Exit(code)
	}
}

func failure(err error) (int, string) {
	switch {
	case errors.Is(err, errInvalid):
		return installationv1.TOTPBackupCustodyExitInvalid, installationv1.TOTPBackupCustodyErrorInvalid
	case errors.Is(err, iampostgres.ErrBackupCustodyForbidden):
		return installationv1.TOTPBackupCustodyExitForbidden, installationv1.TOTPBackupCustodyErrorForbidden
	default:
		return installationv1.TOTPBackupCustodyExitUnavailable, installationv1.TOTPBackupCustodyErrorUnavailable
	}
}

func run(ctx context.Context, arguments []string, input io.ReadCloser, output io.Writer, getenv func(string) string) error {
	if ctx == nil || input == nil || output == nil || getenv == nil || len(arguments) != 1 || arguments[0] != installationv1.TOTPBackupCustodySnapshotCommand {
		return errInvalid
	}
	defer input.Close()
	ctx, cancel := context.WithTimeout(ctx, time.Duration(installationv1.TOTPBackupSnapshotLeaseMaximumSeconds)*time.Second)
	defer cancel()
	path := getenv(installationv1.TOTPBackupCustodyDatabaseDSNFileEnvironment)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || runtime.GOOS != "windows" && info.Mode() != 0o600 {
		return errInvalid
	}
	dsn, err := processconfig.ReadText(path, 16*1024, true)
	if err != nil {
		return errInvalid
	}
	config, err := parseBackupConfig(dsn)
	if err != nil {
		return err
	}
	snapshot, err := iampostgres.OpenTOTPBackupSnapshot(ctx, config)
	if err != nil {
		return err
	}
	defer snapshot.Close()
	encoded, err := installationv1.EncodeTOTPBackupSnapshotLease(snapshot.Lease())
	if err != nil {
		return iampostgres.ErrBackupCustodyUnavailable
	}
	line := append(encoded, '\n')
	if written, err := output.Write(line); err != nil || written != len(line) {
		return iampostgres.ErrBackupCustodyUnavailable
	}
	if err := awaitRelease(ctx, input); err != nil {
		return err
	}
	return snapshot.Close()
}

func parseBackupConfig(dsn string) (*pgx.ConnConfig, error) {
	// An explicit complete URI prevents PG* environment defaults/passfiles from
	// becoming another credential or target selector for this FILE-only entry.
	uri, err := url.Parse(dsn)
	if err != nil || (uri.Scheme != "postgres" && uri.Scheme != "postgresql") || uri.User == nil ||
		uri.Hostname() == "" || uri.Port() == "" || len(uri.Path) < 2 || uri.Fragment != "" {
		return nil, errInvalid
	}
	password, explicitPassword := uri.User.Password()
	if uri.User.Username() == "" || !explicitPassword || password == "" || uri.Query().Has("service") || uri.Query().Has("passfile") {
		return nil, errInvalid
	}
	// Installed DSNs share the existing pool-aware grammar. Parse its options,
	// but create only one connection: pool_* options are not PostgreSQL GUCs.
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, errInvalid
	}
	return config.ConnConfig, nil
}

func awaitRelease(ctx context.Context, input io.ReadCloser) error {
	defer input.Close()
	result := make(chan error, 1)
	go func() {
		encoded, err := io.ReadAll(io.LimitReader(input, int64(len(installationv1.TOTPBackupCustodyReleaseFrame)+1)))
		if err != nil || string(encoded) != installationv1.TOTPBackupCustodyReleaseFrame {
			result <- errInvalid
			return
		}
		result <- nil
	}()
	select {
	case <-ctx.Done():
		return iampostgres.ErrBackupCustodyUnavailable
	case err := <-result:
		if ctx.Err() != nil {
			return iampostgres.ErrBackupCustodyUnavailable
		}
		return err
	}
}
