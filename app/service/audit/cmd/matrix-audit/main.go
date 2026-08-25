package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/jackc/pgx/v5/pgxpool"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
	iamhttp "github.com/xiak/matrix/app/service/audit/internal/data/iamhttp"
	auditpostgres "github.com/xiak/matrix/app/service/audit/internal/data/postgres"
	audithttp "github.com/xiak/matrix/app/service/audit/internal/service/nethttp"
	"github.com/xiak/matrix/app/service/audit/internal/usecase/auditlog"
	"github.com/xiak/matrix/app/service/internal/processconfig"
	"github.com/xiak/matrix/app/service/internal/processhttp"
)

const (
	databaseDSNFileEnvironment       = "MATRIX_AUDIT_DATABASE_DSN_FILE"
	iamEndpointEnvironment           = "MATRIX_AUDIT_IAM_ENDPOINT"
	serviceCredentialFileEnvironment = "MATRIX_AUDIT_SERVICE_CREDENTIAL_FILE"
	cursorKeyFileEnvironment         = "MATRIX_AUDIT_CURSOR_KEY_FILE"
	listenAddressEnvironment         = "MATRIX_AUDIT_LISTEN_ADDRESS"
)

type configuration struct {
	databaseDSNFile       string
	iamEndpoint           string
	serviceCredentialFile string
	cursorKeyFile         string
	listenAddress         string
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "matrix Audit process failed")
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	config, err := loadConfiguration()
	if err != nil {
		return err
	}
	dsn, err := processconfig.ReadText(config.databaseDSNFile, 16*1024, true)
	if err != nil {
		return err
	}
	poolConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return errors.New("Audit database configuration is invalid")
	}
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return errors.New("Audit database pool cannot start")
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return errors.New("Audit database is unavailable")
	}
	credentialText, err := processconfig.ReadText(
		config.serviceCredentialFile,
		16*1024,
		true,
	)
	if err != nil {
		return err
	}
	credential, err := iamv1.NewSecret(credentialText)
	credentialText = ""
	if err != nil {
		return errors.New("Audit service credential is invalid")
	}
	cursorText, err := processconfig.ReadText(config.cursorKeyFile, 64, true)
	if err != nil {
		return err
	}
	cursorKey, err := hex.DecodeString(cursorText)
	cursorText = ""
	if err != nil || len(cursorKey) != 32 {
		clear(cursorKey)
		return errors.New("Audit cursor key is invalid")
	}
	iamClient, err := iamhttp.NewClient(iamhttp.Config{
		Endpoint: config.iamEndpoint, ServiceCredential: credential,
	})
	if err != nil {
		clear(cursorKey)
		return err
	}
	repository, err := auditpostgres.NewRepository(pool)
	if err != nil {
		clear(cursorKey)
		return err
	}
	workflow, err := auditlog.NewService(repository, iamClient, auditlog.Config{CursorKey: cursorKey})
	clear(cursorKey)
	if err != nil {
		return err
	}
	handler, err := audithttp.NewHandler(workflow, audithttp.Config{})
	if err != nil {
		return err
	}
	return processhttp.Serve(ctx, config.listenAddress, handler)
}

func loadConfiguration() (configuration, error) {
	config := configuration{
		databaseDSNFile:       os.Getenv(databaseDSNFileEnvironment),
		iamEndpoint:           os.Getenv(iamEndpointEnvironment),
		serviceCredentialFile: os.Getenv(serviceCredentialFileEnvironment),
		cursorKeyFile:         os.Getenv(cursorKeyFileEnvironment),
		listenAddress:         os.Getenv(listenAddressEnvironment),
	}
	if config.databaseDSNFile == "" || config.iamEndpoint == "" ||
		config.serviceCredentialFile == "" || config.cursorKeyFile == "" ||
		config.listenAddress == "" {
		return configuration{}, errors.New("Audit process configuration is incomplete")
	}
	return config, nil
}
