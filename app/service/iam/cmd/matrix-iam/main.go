package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/jackc/pgx/v5/pgxpool"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
	iampostgres "github.com/xiak/matrix/app/service/iam/internal/data/postgres"
	iamhttp "github.com/xiak/matrix/app/service/iam/internal/service/nethttp"
	"github.com/xiak/matrix/app/service/iam/internal/usecase/identityaccess"
	"github.com/xiak/matrix/app/service/internal/processconfig"
	"github.com/xiak/matrix/app/service/internal/processhttp"
)

const (
	databaseDSNFileEnvironment = "MATRIX_IAM_DATABASE_DSN_FILE"
	bootstrapFileEnvironment   = "MATRIX_IAM_BOOTSTRAP_FILE"
	listenAddressEnvironment   = "MATRIX_IAM_LISTEN_ADDRESS"
)

type configuration struct {
	databaseDSNFile string
	bootstrapFile   string
	listenAddress   string
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "matrix IAM process failed")
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
		return errors.New("IAM database configuration is invalid")
	}
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return errors.New("IAM database pool cannot start")
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return errors.New("IAM database is unavailable")
	}
	repository, err := iampostgres.NewRepository(pool)
	if err != nil {
		return err
	}
	workflow, err := identityaccess.NewAuthority(repository, identityaccess.Config{})
	if err != nil {
		return err
	}
	schema, err := workflow.Readiness(ctx)
	if err != nil || schema.SchemaVersion != identityaccess.SchemaVersion {
		return errors.New("IAM schema is incompatible")
	}
	bootstrapBytes, err := processconfig.ReadFile(
		config.bootstrapFile,
		iamv1.MaxBootstrapBytes,
		true,
	)
	if err != nil {
		return err
	}
	document, err := iamv1.DecodeBootstrapDocument(bytes.NewReader(bootstrapBytes))
	clear(bootstrapBytes)
	if err != nil {
		return errors.New("IAM bootstrap document is invalid")
	}
	if _, err := workflow.Bootstrap(ctx, document); err != nil {
		document = iamv1.BootstrapDocument{}
		return errors.New("IAM bootstrap cannot converge")
	}
	document = iamv1.BootstrapDocument{}
	handler, err := iamhttp.NewHandler(workflow, iamhttp.Config{})
	if err != nil {
		return err
	}
	return processhttp.Serve(ctx, config.listenAddress, handler)
}

func loadConfiguration() (configuration, error) {
	config := configuration{
		databaseDSNFile: os.Getenv(databaseDSNFileEnvironment),
		bootstrapFile:   os.Getenv(bootstrapFileEnvironment),
		listenAddress:   os.Getenv(listenAddressEnvironment),
	}
	if config.databaseDSNFile == "" || config.bootstrapFile == "" ||
		config.listenAddress == "" {
		return configuration{}, errors.New("IAM process configuration is incomplete")
	}
	return config, nil
}
