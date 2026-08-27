package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
	managedservicev1 "github.com/xiak/matrix/api/managedservice/v1"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/internal/processconfig"
	"github.com/xiak/matrix/app/service/internal/processhttp"
	iamhttp "github.com/xiak/matrix/app/service/paas/internal/apphosting/data/iamhttp"
	paaspostgres "github.com/xiak/matrix/app/service/paas/internal/apphosting/data/postgres"
	paashttp "github.com/xiak/matrix/app/service/paas/internal/apphosting/service/nethttp"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/applicationlifecycle"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/executionadmission"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/verifyinstallation"
	managedserviceiam "github.com/xiak/matrix/app/service/paas/internal/managedservice/data/iamhttp"
	managedservicepostgres "github.com/xiak/matrix/app/service/paas/internal/managedservice/data/postgres"
	"github.com/xiak/matrix/app/service/paas/internal/managedservice/domain"
	managedservicehttp "github.com/xiak/matrix/app/service/paas/internal/managedservice/service/nethttp"
	managedserviceusecase "github.com/xiak/matrix/app/service/paas/internal/managedservice/usecase"
)

const (
	databaseDSNFileEnvironment       = "MATRIX_PAAS_DATABASE_DSN_FILE"
	iamEndpointEnvironment           = "MATRIX_PAAS_IAM_ENDPOINT"
	serviceCredentialFileEnvironment = "MATRIX_PAAS_SERVICE_CREDENTIAL_FILE"
	listenAddressEnvironment         = "MATRIX_PAAS_LISTEN_ADDRESS"
	installationIDEnvironment        = "MATRIX_PAAS_INSTALLATION_ID"
	releaseIDEnvironment             = "MATRIX_PAAS_RELEASE_ID"
	verificationDigestEnvironment    = "MATRIX_PAAS_VERIFICATION_ARTIFACT_DIGEST"
	nodeConnectionsFileEnvironment   = "MATRIX_PAAS_NODE_CONNECTIONS_FILE"
)

type configuration struct {
	databaseDSNFile       string
	iamEndpoint           string
	serviceCredentialFile string
	listenAddress         string
	installationID        string
	releaseID             string
	verificationDigest    string
	nodeConnectionsFile   string
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
		Endpoint: config.iamEndpoint, ServiceCredential: credential, InstallationID: config.installationID,
	})
	if err != nil {
		return err
	}
	managedServiceAuthorizer, err := managedserviceiam.NewClient(managedserviceiam.Config{
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
	installationVerifier, err := verifyinstallation.NewService(
		authorizer,
		workflow,
		verifyinstallation.Config{
			InstallationID: config.installationID,
			ReleaseID:      config.releaseID,
			ArtifactDigest: config.verificationDigest,
		},
	)
	if err != nil {
		return err
	}
	bindings, closeBindings, err := loadNodeBindings(config.nodeConnectionsFile, config.installationID)
	if err != nil {
		return err
	}
	defer closeBindings()
	executionRepository, err := paaspostgres.NewExecutionAdmissionRepository(pool)
	if err != nil {
		return err
	}
	execution, err := executionadmission.New(executionRepository, executionadmission.Config{
		InstallationID: config.installationID, Bindings: bindings, ObservationTimeout: 5 * time.Second,
		MaximumObservationAge: 15 * time.Second, MaxTransactionAttempts: 5,
	})
	if err != nil {
		return err
	}
	refreshContext, stopRefresh := context.WithCancel(ctx)
	refreshDone := make(chan struct{})
	go func() {
		defer close(refreshDone)
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			_ = execution.Refresh(refreshContext)
			select {
			case <-refreshContext.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	defer func() { stopRefresh(); <-refreshDone }()
	apphostingHandler, err := paashttp.NewHandler(authorizer, workflow, execution, installationVerifier, paashttp.Config{
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
	managedServiceRepository, err := managedservicepostgres.NewRepository(pool)
	if err != nil {
		return err
	}
	inspectedAt := time.Now().UTC().Truncate(time.Microsecond)
	managedServiceWorkflow, err := managedserviceusecase.NewService(
		managedServiceRepository,
		managedserviceusecase.Config{
			Catalog: domain.DefaultCatalog(),
			Region: managedservicev1.Region{
				ID: "local-primary", DisplayName: "本机主区域",
				Profile: managedservicev1.RegionLocalMachine,
				State:   managedservicev1.RegionReady, InspectedAt: &inspectedAt,
				Capacity: managedservicev1.RegionCapacity{
					CPUMillicores: 4000, MemoryMiB: 8192, StorageGiB: 100,
				},
			},
		},
	)
	if err != nil {
		return err
	}
	managedServiceHandler, err := managedservicehttp.NewHandler(
		managedServiceAuthorizer, managedServiceWorkflow, managedservicehttp.Config{},
	)
	if err != nil {
		return err
	}
	handler := http.NewServeMux()
	handler.Handle("/managed-services/", managedServiceHandler)
	handler.Handle("/", apphostingHandler)
	return processhttp.Serve(ctx, config.listenAddress, handler)
}

func loadConfiguration() (configuration, error) {
	config := configuration{
		databaseDSNFile:       os.Getenv(databaseDSNFileEnvironment),
		iamEndpoint:           os.Getenv(iamEndpointEnvironment),
		serviceCredentialFile: os.Getenv(serviceCredentialFileEnvironment),
		listenAddress:         os.Getenv(listenAddressEnvironment),
		installationID:        os.Getenv(installationIDEnvironment),
		releaseID:             os.Getenv(releaseIDEnvironment),
		verificationDigest:    os.Getenv(verificationDigestEnvironment),
		nodeConnectionsFile:   os.Getenv(nodeConnectionsFileEnvironment),
	}
	if config.databaseDSNFile == "" || config.iamEndpoint == "" ||
		config.serviceCredentialFile == "" || config.listenAddress == "" ||
		config.installationID == "" || config.releaseID == "" ||
		config.verificationDigest == "" {
		return configuration{}, errors.New("PaaS process configuration is incomplete")
	}
	return config, nil
}
