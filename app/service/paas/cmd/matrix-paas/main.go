package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/jackc/pgx/v5/pgxpool"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/internal/processconfig"
	"github.com/xiak/matrix/app/service/internal/processhttp"
	iamhttp "github.com/xiak/matrix/app/service/paas/internal/apphosting/data/iamhttp"
	paaspostgres "github.com/xiak/matrix/app/service/paas/internal/apphosting/data/postgres"
	paashttp "github.com/xiak/matrix/app/service/paas/internal/apphosting/service/nethttp"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/applicationlifecycle"
)

const (
	databaseDSNFileEnvironment       = "MATRIX_PAAS_DATABASE_DSN_FILE"
	iamEndpointEnvironment           = "MATRIX_PAAS_IAM_ENDPOINT"
	serviceCredentialFileEnvironment = "MATRIX_PAAS_SERVICE_CREDENTIAL_FILE"
	listenAddressEnvironment         = "MATRIX_PAAS_LISTEN_ADDRESS"
)

type configuration struct {
	databaseDSNFile       string
	iamEndpoint           string
	serviceCredentialFile string
	listenAddress         string
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "matrix PaaS process failed")
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
		return errors.New("PaaS database configuration is invalid")
	}
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return errors.New("PaaS database pool cannot start")
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return errors.New("PaaS database is unavailable")
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
		return errors.New("PaaS service credential is invalid")
	}
	authorizer, err := iamhttp.NewClient(iamhttp.Config{
		Endpoint: config.iamEndpoint, ServiceCredential: credential,
	})
	if err != nil {
		return err
	}
	repository, err := paaspostgres.NewApplicationRepository(pool)
	if err != nil {
		return err
	}
	workflow, err := applicationlifecycle.NewUsecase(
		repository,
		applicationlifecycle.Config{MaxTransactionAttempts: 5},
	)
	if err != nil {
		return err
	}
	handler, err := paashttp.NewHandler(authorizer, workflow, paashttp.Config{
		Readiness: func(readinessContext context.Context) (paasv1.Readiness, error) {
			readiness, err := repository.Readiness(readinessContext)
			if err != nil || readiness.State != paasv1.ReadinessReady {
				return readiness, err
			}
			if err := authorizer.Ready(readinessContext); err != nil {
				readiness.State = paasv1.ReadinessNotReady
			}
			return readiness, nil
		},
	})
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
		listenAddress:         os.Getenv(listenAddressEnvironment),
	}
	if config.databaseDSNFile == "" || config.iamEndpoint == "" ||
		config.serviceCredentialFile == "" || config.listenAddress == "" {
		return configuration{}, errors.New("PaaS process configuration is incomplete")
	}
	return config, nil
}
