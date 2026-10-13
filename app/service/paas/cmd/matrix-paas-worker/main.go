package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	apphostingv1 "github.com/xiak/matrix/api/adapter/apphosting/v1"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
	composeadapter "github.com/xiak/matrix/app/adapter/apphosting/compose"
	localmachineadapter "github.com/xiak/matrix/app/adapter/infrastructure/localmachine"
	localelasticsearchadapter "github.com/xiak/matrix/app/adapter/managedservice/localelasticsearch"
	localmysqladapter "github.com/xiak/matrix/app/adapter/managedservice/localmysql"
	localpostgresadapter "github.com/xiak/matrix/app/adapter/managedservice/localpostgres"
	localrabbitmqadapter "github.com/xiak/matrix/app/adapter/managedservice/localrabbitmq"
	"github.com/xiak/matrix/app/service/internal/processconfig"
	"github.com/xiak/matrix/app/service/internal/processhttp"
	paaspostgres "github.com/xiak/matrix/app/service/paas/internal/apphosting/data/postgres"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/domain/placement"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/createplacement"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/operationqueue"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/reconciledeployment"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/refreshexecutionprofile"
	managedservicepostgres "github.com/xiak/matrix/app/service/paas/internal/managedservice/data/postgres"
	"github.com/xiak/matrix/app/service/paas/internal/managedservice/domain"
	"github.com/xiak/matrix/app/service/paas/internal/managedservice/usecase/reconcileinstallation"
)

const (
	databaseDSNFileEnvironment           = "MATRIX_PAAS_WORKER_DATABASE_DSN_FILE"
	workerIDEnvironment                  = "MATRIX_PAAS_WORKER_ID"
	bindingRefEnvironment                = "MATRIX_PAAS_WORKER_BINDING_REF"
	bindingRootEnvironment               = "MATRIX_PAAS_WORKER_BINDING_ROOT"
	secretRootEnvironment                = "MATRIX_PAAS_WORKER_SECRET_ROOT"
	artifactCatalogEnvironment           = "MATRIX_PAAS_WORKER_ARTIFACT_CATALOG_FILE"
	executionTenantEnvironment           = "MATRIX_PAAS_WORKER_EXECUTION_TENANT_ID"
	machineBindingEnvironment            = "MATRIX_PAAS_WORKER_MACHINE_BINDING_REF"
	listenAddressEnvironment             = "MATRIX_PAAS_WORKER_LISTEN_ADDRESS"
	managedPostgresImageEnvironment      = "MATRIX_PAAS_WORKER_MANAGED_POSTGRES_IMAGE"
	managedMySQLImageEnvironment         = "MATRIX_PAAS_WORKER_MANAGED_MYSQL_IMAGE"
	managedElasticsearchImageEnvironment = "MATRIX_PAAS_WORKER_MANAGED_ELASTICSEARCH_IMAGE"
	managedRabbitMQImageEnvironment      = "MATRIX_PAAS_WORKER_MANAGED_RABBITMQ_IMAGE"
	pollInterval                         = 250 * time.Millisecond
	executionTargetRefresh               = time.Minute
	executionTargetMaximumAge            = 5 * time.Minute
	executionTargetTimeout               = 5 * time.Second
	operationLeaseDuration               = 30 * time.Second
	effectTimeout                        = 20 * time.Second
	reconcileBackoff                     = time.Second
	maximumOperationAttempts             = 10
	placementDecisionTTL                 = 5 * time.Minute
	pendingCapacityClaimTTL              = 10 * time.Minute
	maximumArtifactCatalogBytes          = 1024 * 1024
)

type configuration struct {
	databaseDSNFile           string
	workerID                  string
	bindingRef                string
	bindingRoot               string
	secretRoot                string
	artifactCatalog           string
	executionTenant           paasv1.TenantID
	machineBinding            string
	listenAddress             string
	managedPostgresImage      string
	managedMySQLImage         string
	managedElasticsearchImage string
	managedRabbitMQImage      string
}

type workerFailureStage string

const (
	workerFailureConfiguration           workerFailureStage = "PAAS_WORKER_CONFIGURATION"
	workerFailureDatabaseInput           workerFailureStage = "PAAS_WORKER_DATABASE_INPUT"
	workerFailureDatabase                workerFailureStage = "PAAS_WORKER_DATABASE"
	workerFailureExecutionProfile        workerFailureStage = "PAAS_WORKER_EXECUTION_PROFILE"
	workerFailureExecutionProfileRefresh workerFailureStage = "PAAS_WORKER_EXECUTION_PROFILE_REFRESH"
	workerFailureArtifactCatalog         workerFailureStage = "PAAS_WORKER_ARTIFACT_CATALOG"
	workerFailureSecretResolver          workerFailureStage = "PAAS_WORKER_SECRET_RESOLVER"
	workerFailureComposeRuntime          workerFailureStage = "PAAS_WORKER_COMPOSE_RUNTIME"
	workerFailureManagedService          workerFailureStage = "PAAS_WORKER_MANAGED_SERVICE"
	workerFailureDeploymentWorker        workerFailureStage = "PAAS_WORKER_DEPLOYMENT_WORKER"
	workerFailureReadinessDatabase       workerFailureStage = "PAAS_WORKER_READINESS_DATABASE"
	workerFailureReadinessArtifact       workerFailureStage = "PAAS_WORKER_READINESS_ARTIFACT"
	workerFailureReadinessCompose        workerFailureStage = "PAAS_WORKER_READINESS_COMPOSE"
	workerFailureReadinessExecution      workerFailureStage = "PAAS_WORKER_READINESS_EXECUTION_PROFILE"
	workerFailureReadinessManagedService workerFailureStage = "PAAS_WORKER_READINESS_MANAGED_SERVICE"
	workerFailureProcess                 workerFailureStage = "PAAS_WORKER_PROCESS"
	workerFailureManagedServiceCycle     workerFailureStage = "PAAS_WORKER_MANAGED_SERVICE_CYCLE"
	workerFailureDeploymentCycle         workerFailureStage = "PAAS_WORKER_DEPLOYMENT_CYCLE"
	workerFailureExecutionRefreshCycle   workerFailureStage = "PAAS_WORKER_EXECUTION_PROFILE_REFRESH_CYCLE"
	workerFailureUnexpected              workerFailureStage = "PAAS_WORKER_UNEXPECTED"
)

type workerFailure struct {
	stage workerFailureStage
}

func (failure *workerFailure) Error() string {
	return string(failure.stage)
}

func failWorker(stage workerFailureStage) error {
	return &workerFailure{stage: stage}
}

func workerFailureCode(err error) workerFailureStage {
	var failure *workerFailure
	if errors.As(err, &failure) && failure != nil && failure.stage != "" {
		return failure.stage
	}
	return workerFailureUnexpected
}

var localExecutionProfileIDs = refreshexecutionprofile.IDs{
	PoolID:   "execution-pool-local",
	TargetID: "execution-target-local",
	PolicyID: "placement-policy-local",
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "matrix PaaS worker failed: %s\n", workerFailureCode(err))
		os.Exit(1)
	}
}

func run(ctx context.Context) (result error) {
	stage := workerFailureConfiguration
	defer func() {
		if result == nil {
			return
		}
		var failure *workerFailure
		if !errors.As(result, &failure) {
			result = failWorker(stage)
		}
	}()
	config, err := loadConfiguration()
	if err != nil {
		return err
	}
	stage = workerFailureDatabaseInput
	dsn, err := processconfig.ReadText(config.databaseDSNFile, 16*1024, true)
	if err != nil {
		return err
	}
	stage = workerFailureDatabase
	poolConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return errors.New("PaaS worker database configuration is invalid")
	}
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return errors.New("PaaS worker database pool cannot start")
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return errors.New("PaaS worker database is unavailable")
	}
	stage = workerFailureExecutionProfile
	executionProfile, err := newLocalExecutionProfile(config, pool)
	if err != nil {
		return err
	}
	stage = workerFailureExecutionProfileRefresh
	if err := executionProfile.Refresh(ctx); err != nil {
		return errors.New("PaaS local execution profile cannot start")
	}

	stage = workerFailureArtifactCatalog
	catalogContent, err := processconfig.ReadFile(
		config.artifactCatalog,
		maximumArtifactCatalogBytes,
		false,
	)
	if err != nil {
		return err
	}
	catalog, err := apphostingv1.DecodeArtifactCatalog(catalogContent)
	clear(catalogContent)
	if err != nil {
		return err
	}
	artifacts, err := composeadapter.NewCatalogArtifactResolver(catalog)
	if err != nil {
		return err
	}
	stage = workerFailureSecretResolver
	secrets, err := composeadapter.NewFileSecretResolver(config.secretRoot)
	if err != nil {
		return err
	}
	stage = workerFailureComposeRuntime
	runtime := composeadapter.NewLocalRuntime()
	executor, err := composeadapter.New(composeadapter.Config{
		BindingRef: config.bindingRef, BindingRoot: config.bindingRoot,
		Artifacts: artifacts, Secrets: secrets, Runtime: runtime,
	})
	if err != nil {
		return err
	}
	stage = workerFailureManagedService
	managedServiceRepository, err := managedservicepostgres.NewRepository(pool)
	if err != nil {
		return err
	}
	managedPostgres, err := localpostgresadapter.New(localpostgresadapter.Config{
		Root:    filepath.Join(config.bindingRoot, "managed-postgres"),
		ImageID: config.managedPostgresImage, Runtime: runtime,
	})
	if err != nil {
		return err
	}
	managedMySQL, err := localmysqladapter.New(localmysqladapter.Config{
		Root:    filepath.Join(config.bindingRoot, "managed-mysql"),
		ImageID: config.managedMySQLImage, Runtime: runtime,
	})
	if err != nil {
		return err
	}
	managedElasticsearch, err := localelasticsearchadapter.New(localelasticsearchadapter.Config{
		Root:    filepath.Join(config.bindingRoot, "managed-elasticsearch"),
		ImageID: config.managedElasticsearchImage, Runtime: runtime,
	})
	if err != nil {
		return err
	}
	managedRabbitMQ, err := localrabbitmqadapter.New(localrabbitmqadapter.Config{
		Root:    filepath.Join(config.bindingRoot, "managed-rabbitmq"),
		ImageID: config.managedRabbitMQImage, Runtime: runtime,
	})
	if err != nil {
		return err
	}
	providerRegistry, err := reconcileinstallation.NewProviderRegistry(
		domain.DefaultCatalog(),
		map[string]reconcileinstallation.Provisioner{
			domain.PostgreSQLOfferingID:    managedPostgres,
			domain.MySQLOfferingID:         managedMySQL,
			domain.ElasticsearchOfferingID: managedElasticsearch,
			domain.RabbitMQOfferingID:      managedRabbitMQ,
		},
	)
	if err != nil {
		return err
	}
	managedServiceWorker, err := reconcileinstallation.NewService(
		managedServiceRepository,
		providerRegistry,
		reconcileinstallation.Config{
			Catalog: domain.DefaultCatalog(), LeaseDuration: 3 * time.Minute,
			EffectTimeout: 2 * time.Minute, RetryBackoff: 2 * time.Second,
			MaximumAttempts: 10,
		},
	)
	if err != nil {
		return err
	}

	stage = workerFailureDeploymentWorker
	queueRepository, err := paaspostgres.NewOperationQueueRepository(pool)
	if err != nil {
		return err
	}
	queue, err := operationqueue.NewQueue(
		queueRepository,
		operationqueue.Config{LeaseDuration: operationLeaseDuration},
	)
	if err != nil {
		return err
	}
	planner, err := placement.NewV1Planner(placementDecisionTTL)
	if err != nil {
		return err
	}
	placementRepository, err := paaspostgres.NewPlacementRepository(pool)
	if err != nil {
		return err
	}
	placementUsecase, err := createplacement.NewUsecase(
		planner,
		placementRepository,
		createplacement.Config{
			PendingReservationTTL:  pendingCapacityClaimTTL,
			MaxTransactionAttempts: 5,
		},
	)
	if err != nil {
		return err
	}
	executionRepository, err := paaspostgres.NewDeploymentExecutionRepository(pool)
	if err != nil {
		return err
	}
	worker, err := reconciledeployment.NewWorker(
		queue,
		placementUsecase,
		executionRepository,
		executor,
		reconciledeployment.Config{
			BindingRef: config.bindingRef, EffectTimeout: effectTimeout,
			ReconcileBackoff: reconcileBackoff, MaxAttempts: maximumOperationAttempts,
			Clock: func() time.Time {
				return time.Now().UTC().Truncate(time.Microsecond)
			},
		},
	)
	if err != nil {
		return err
	}
	readiness := func(readinessContext context.Context) error {
		state, checkErr := queueRepository.Readiness(readinessContext)
		if checkErr != nil || state.State != paasv1.ReadinessReady ||
			paasv1.ValidateReadiness(state) != nil {
			return failWorker(workerFailureReadinessDatabase)
		}
		if checkErr := artifacts.Ready(readinessContext); checkErr != nil {
			return failWorker(workerFailureReadinessArtifact)
		}
		if checkErr := runtime.Ready(readinessContext); checkErr != nil {
			return failWorker(workerFailureReadinessCompose)
		}
		if checkErr := executionProfile.Ready(readinessContext); checkErr != nil {
			return failWorker(workerFailureReadinessExecution)
		}
		if checkErr := managedServiceWorker.Ready(readinessContext); checkErr != nil {
			return failWorker(workerFailureReadinessManagedService)
		}
		return nil
	}
	if err := readiness(ctx); err != nil {
		return err
	}
	handler, err := processhttp.NewReadinessHandler(readiness)
	if err != nil {
		return err
	}
	stage = workerFailureProcess
	return processhttp.ServeWithBackground(
		ctx,
		config.listenAddress,
		handler,
		func(workerContext context.Context) error {
			preferManagedService := true
			return runWorkerLoop(
				workerContext,
				func(cycleContext context.Context, workerID string) (bool, error) {
					managedFirst := preferManagedService
					first, second := managedServiceWorker.ProcessNext, worker.ProcessNext
					if !preferManagedService {
						first, second = worker.ProcessNext, managedServiceWorker.ProcessNext
					}
					preferManagedService = !preferManagedService
					processed, cycleErr := first(cycleContext, workerID)
					if cycleErr != nil {
						if managedFirst {
							return false, failWorker(workerFailureManagedServiceCycle)
						}
						return false, failWorker(workerFailureDeploymentCycle)
					}
					if processed {
						return true, nil
					}
					processed, cycleErr = second(cycleContext, workerID)
					if cycleErr != nil {
						if managedFirst {
							return false, failWorker(workerFailureDeploymentCycle)
						}
						return false, failWorker(workerFailureManagedServiceCycle)
					}
					return processed, nil
				},
				func(refreshContext context.Context) error {
					if refreshErr := executionProfile.Refresh(refreshContext); refreshErr != nil {
						return failWorker(workerFailureExecutionRefreshCycle)
					}
					return nil
				},
				config.workerID,
			)
		},
	)
}

func newLocalExecutionProfile(
	config configuration,
	pool *pgxpool.Pool,
) (*refreshexecutionprofile.Service, error) {
	binding, err := localmachineadapter.NewMachineBinding(
		localmachineadapter.MachineBindingSpec{
			ID: config.machineBinding, Kind: localmachineadapter.BindingLocal,
			Labels: map[string]string{"location": "local"},
			AllowedIsolationGuarantees: []paasv1.IsolationGuarantee{
				paasv1.IsolationWorkload,
			},
			StoragePath: config.bindingRoot,
		},
	)
	if err != nil {
		return nil, errors.New("PaaS worker machine binding is invalid")
	}
	bindings, err := localmachineadapter.NewStaticBindingResolver(binding)
	if err != nil {
		return nil, errors.New("PaaS worker machine binding cannot start")
	}
	infrastructure, err := localmachineadapter.New(localmachineadapter.Config{
		Bindings: bindings, LocalProbe: localmachineadapter.NewDockerHostProbe(),
	})
	if err != nil {
		return nil, errors.New("PaaS worker infrastructure adapter cannot start")
	}
	repository, err := paaspostgres.NewExecutionProfileRepository(pool)
	if err != nil {
		return nil, err
	}
	return refreshexecutionprofile.New(
		infrastructure,
		repository,
		refreshexecutionprofile.Config{
			TenantID: config.executionTenant, IDs: localExecutionProfileIDs,
			MachineBindingRef:      config.machineBinding,
			ObservationTimeout:     executionTargetTimeout,
			MaximumObservationAge:  executionTargetMaximumAge,
			MaxTransactionAttempts: 5,
		},
	)
}

func runWorkerLoop(
	ctx context.Context,
	processNext func(context.Context, string) (bool, error),
	refreshExecutionTarget func(context.Context) error,
	workerID string,
) error {
	if ctx == nil || processNext == nil || refreshExecutionTarget == nil {
		return errors.New("PaaS worker loop configuration is invalid")
	}
	nextRefresh := time.Now().Add(executionTargetRefresh)
	for {
		if !time.Now().Before(nextRefresh) {
			if err := refreshExecutionTarget(ctx); err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return errors.New("PaaS execution target refresh failed")
			}
			nextRefresh = time.Now().Add(executionTargetRefresh)
		}
		processed, err := processNext(ctx, workerID)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var failure *workerFailure
			if errors.As(err, &failure) {
				return failure
			}
			return errors.New("PaaS reconciliation cycle failed")
		}
		if processed {
			continue
		}
		wait := pollInterval
		if untilRefresh := time.Until(nextRefresh); untilRefresh < wait {
			wait = untilRefresh
		}
		if wait <= 0 {
			continue
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return nil
		case <-timer.C:
		}
	}
}

func loadConfiguration() (configuration, error) {
	config := configuration{
		databaseDSNFile:           os.Getenv(databaseDSNFileEnvironment),
		workerID:                  os.Getenv(workerIDEnvironment),
		bindingRef:                os.Getenv(bindingRefEnvironment),
		bindingRoot:               os.Getenv(bindingRootEnvironment),
		secretRoot:                os.Getenv(secretRootEnvironment),
		artifactCatalog:           os.Getenv(artifactCatalogEnvironment),
		executionTenant:           paasv1.TenantID(os.Getenv(executionTenantEnvironment)),
		machineBinding:            os.Getenv(machineBindingEnvironment),
		listenAddress:             os.Getenv(listenAddressEnvironment),
		managedPostgresImage:      os.Getenv(managedPostgresImageEnvironment),
		managedMySQLImage:         os.Getenv(managedMySQLImageEnvironment),
		managedElasticsearchImage: os.Getenv(managedElasticsearchImageEnvironment),
		managedRabbitMQImage:      os.Getenv(managedRabbitMQImageEnvironment),
	}
	if config.databaseDSNFile == "" || config.workerID == "" ||
		config.bindingRef == "" || config.bindingRoot == "" ||
		config.secretRoot == "" || config.artifactCatalog == "" ||
		config.executionTenant == "" || config.machineBinding == "" ||
		config.listenAddress == "" || config.managedPostgresImage == "" ||
		config.managedMySQLImage == "" || config.managedElasticsearchImage == "" ||
		config.managedRabbitMQImage == "" {
		return configuration{}, errors.New("PaaS worker configuration is incomplete")
	}
	if paasv1.ValidateID("workerId", config.workerID) != nil ||
		paasv1.ValidateID("bindingRef", config.bindingRef) != nil ||
		paasv1.ValidateID("executionTenantId", string(config.executionTenant)) != nil ||
		paasv1.ValidateID("machineBindingRef", config.machineBinding) != nil {
		return configuration{}, errors.New("PaaS worker identity configuration is invalid")
	}
	return config, nil
}
