package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/jackc/pgx/v5/pgxpool"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/data/gitea"
	iamhttp "github.com/xiak/matrix/app/service/devops/internal/delivery/data/iamhttp"
	devopspostgres "github.com/xiak/matrix/app/service/devops/internal/delivery/data/postgres"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/data/sourcecredentialfile"
	devopshttp "github.com/xiak/matrix/app/service/devops/internal/delivery/service/nethttp"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/pipelineconfiguration"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/runadmission"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/runcontrol"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/sourceingress"
	"github.com/xiak/matrix/app/service/devops/sourcecredential"
	"github.com/xiak/matrix/app/service/internal/processconfig"
	"github.com/xiak/matrix/app/service/internal/processhttp"
)

const (
	databaseDSNFileEnvironment       = "MATRIX_DEVOPS_DATABASE_DSN_FILE"
	iamEndpointEnvironment           = "MATRIX_DEVOPS_IAM_ENDPOINT"
	serviceCredentialFileEnvironment = "MATRIX_DEVOPS_SERVICE_CREDENTIAL_FILE"
	webhookSecretRootEnvironment     = "MATRIX_DEVOPS_WEBHOOK_SECRET_ROOT"
	listenAddressEnvironment         = "MATRIX_DEVOPS_LISTEN_ADDRESS"
)

type configuration struct {
	databaseDSNFile       string
	iamEndpoint           string
	serviceCredentialFile string
	webhookSecretRoot     string
	listenAddress         string
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "matrix DevOps process failed")
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
	dsn = ""
	if err != nil {
		return errors.New("DevOps database configuration is invalid")
	}
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return errors.New("DevOps database pool cannot start")
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return errors.New("DevOps database is unavailable")
	}
	credentialText, err := processconfig.ReadText(config.serviceCredentialFile, 16*1024, true)
	if err != nil {
		return err
	}
	credential, err := iamv1.NewSecret(credentialText)
	credentialText = ""
	if err != nil {
		return errors.New("DevOps service credential is invalid")
	}
	authorizer, err := iamhttp.NewClient(iamhttp.Config{
		Endpoint: config.iamEndpoint, ServiceCredential: credential,
	})
	if err != nil {
		return err
	}
	repository, err := devopspostgres.NewControlPlaneRepository(pool)
	if err != nil {
		return err
	}
	workflow, err := pipelineconfiguration.NewUsecase(
		repository, pipelineconfiguration.Config{MaxTransactionAttempts: 5},
	)
	if err != nil {
		return err
	}
	runController, err := runcontrol.NewService(
		repository, runcontrol.Config{MaxTransactionAttempts: 5},
	)
	if err != nil {
		return err
	}
	admission, err := runadmission.NewUsecase(
		repository, runadmission.Config{MaxTransactionAttempts: 5},
	)
	if err != nil {
		return err
	}
	secretResolver, err := sourcecredentialfile.NewResolver(
		sourcecredential.PurposeWebhook, config.webhookSecretRoot,
	)
	if err != nil {
		return err
	}
	ingress, err := sourceingress.NewUsecase(
		repository, secretResolver, admission, gitea.NewAdapter(),
	)
	if err != nil {
		return err
	}
	handler, err := devopshttp.NewHandler(authorizer, workflow, devopshttp.Config{
		SourceIngress: ingress, RunControl: runController,
		Readiness: func(readinessContext context.Context) (devopsv1.Readiness, error) {
			readiness, checkErr := repository.Readiness(readinessContext)
			if checkErr != nil || readiness.State != devopsv1.ReadinessReady {
				return readiness, checkErr
			}
			if checkErr := authorizer.Ready(readinessContext); checkErr != nil {
				readiness.State = devopsv1.ReadinessNotReady
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
		webhookSecretRoot:     os.Getenv(webhookSecretRootEnvironment),
		listenAddress:         os.Getenv(listenAddressEnvironment),
	}
	if config.databaseDSNFile == "" || config.iamEndpoint == "" ||
		config.serviceCredentialFile == "" || config.webhookSecretRoot == "" ||
		config.listenAddress == "" {
		return configuration{}, errors.New("DevOps process configuration is incomplete")
	}
	return config, nil
}
