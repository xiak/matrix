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
	executionTargetRefreshBackoff        = time.Second
	executionProfileStartupAttempts      = 6
	executionProfileStartupBackoff       = time.Second
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
	workerFailureExecutionObserveTimeout workerFailureStage = "PAAS_WORKER_EXECUTION_PROFILE_OBSERVE_TIMEOUT"
	workerFailureExecutionEngineTimeout  workerFailureStage = "PAAS_WORKER_EXECUTION_PROFILE_DOCKER_ENGINE_TIMEOUT"
	workerFailureExecutionComposeTimeout workerFailureStage = "PAAS_WORKER_EXECUTION_PROFILE_COMPOSE_PLUGIN_TIMEOUT"
	workerFailureExecutionObserveDown    workerFailureStage = "PAAS_WORKER_EXECUTION_PROFILE_OBSERVE_UNAVAILABLE"
	workerFailureExecutionObserveReject  workerFailureStage = "PAAS_WORKER_EXECUTION_PROFILE_OBSERVE_REJECTED"
	workerFailureExecutionValidate       workerFailureStage = "PAAS_WORKER_EXECUTION_PROFILE_VALIDATE"
	workerFailureExecutionLoad           workerFailureStage = "PAAS_WORKER_EXECUTION_PROFILE_LOAD"
	workerFailureExecutionBuild          workerFailureStage = "PAAS_WORKER_EXECUTION_PROFILE_BUILD"
	workerFailureExecutionSave           workerFailureStage = "PAAS_WORKER_EXECUTION_PROFILE_SAVE"
	workerFailureExecutionTransaction    workerFailureStage = "PAAS_WORKER_EXECUTION_PROFILE_TRANSACTION"
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
	if err := refreshExecutionProfileAtStartup(
		ctx,
		executionProfileStartupAttempts,
		executionProfileStartupBackoff,
		func(refreshContext context.Context) error {
			if refreshErr := executionProfile.Refresh(refreshContext); refreshErr != nil {
				return failWorker(executionProfileRefreshFailure(refreshErr))
			}
			return nil
		},
	); err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return err
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
						return failWorker(executionProfileRefreshFailure(refreshErr))
					}
					return nil
				},
				config.workerID,
				executionTargetRefresh,
				executionTargetRefreshBackoff,
			)
		},
	)
}

func executionProfileRefreshFailure(err error) workerFailureStage {
	var adapterFault paasv1.AdapterFault
	adapterClass := paasv1.AdapterErrorClass("")
	if errors.As(err, &adapterFault) {
		adapterClass = adapterFault.Normalized.Class
	}
	stage := refreshexecutionprofile.ClassifyRefreshFailure(err)
	if stage == refreshexecutionprofile.RefreshFailureObserve && adapterClass == paasv1.AdapterErrorTimeout {
		var probeFailure localmachineadapter.ProbeFailure
		if errors.As(err, &probeFailure) && probeFailure.Kind == localmachineadapter.ProbeFailureTimeout {
			switch probeFailure.ID {
			case string(localmachineadapter.ProbeDockerEngine):
				return workerFailureExecutionEngineTimeout
			case string(localmachineadapter.ProbeComposePlugin):
				return workerFailureExecutionComposeTimeout
			}
		}
	}
	return executionProfileRefreshStageFailure(
		stage,
		adapterClass,
	)
}

func executionProfileRefreshStageFailure(
	stage refreshexecutionprofile.RefreshFailureStage,
	adapterClass paasv1.AdapterErrorClass,
) workerFailureStage {
	switch stage {
	case refreshexecutionprofile.RefreshFailureObserve:
		switch adapterClass {
		case paasv1.AdapterErrorTimeout:
			return workerFailureExecutionObserveTimeout
		case paasv1.AdapterErrorRateLimited,
			paasv1.AdapterErrorTransient,
			paasv1.AdapterErrorUnavailable:
			return workerFailureExecutionObserveDown
		case paasv1.AdapterErrorValidation,
			paasv1.AdapterErrorConflict,
			paasv1.AdapterErrorPermissionDenied,
			paasv1.AdapterErrorQuotaExceeded,
			paasv1.AdapterErrorNotFound:
			return workerFailureExecutionObserveReject
		default:
			return workerFailureExecutionProfileRefresh
		}
	case refreshexecutionprofile.RefreshFailureValidate:
		return workerFailureExecutionValidate
	case refreshexecutionprofile.RefreshFailureLoad:
		return workerFailureExecutionLoad
	case refreshexecutionprofile.RefreshFailureBuild:
		return workerFailureExecutionBuild
	case refreshexecutionprofile.RefreshFailureSave:
		return workerFailureExecutionSave
	case refreshexecutionprofile.RefreshFailureTransaction:
		return workerFailureExecutionTransaction
	default:
		return workerFailureExecutionProfileRefresh
	}
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

func refreshExecutionProfileAtStartup(
	ctx context.Context,
	attempts int,
	backoff time.Duration,
	refresh func(context.Context) error,
) error {
	if ctx == nil || refresh == nil || attempts < 1 || backoff <= 0 {
		return errors.New("PaaS execution profile startup retry configuration is invalid")
	}
	for attempt := 1; attempt <= attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := refresh(ctx)
		if err == nil || !retryableExecutionProfileRefreshFailure(err) || attempt == attempts {
			return err
		}
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
	return errors.New("PaaS execution profile startup retry is unavailable")
}

func retryableExecutionProfileRefreshFailure(err error) bool {
	var failure *workerFailure
	if !errors.As(err, &failure) || failure == nil {
		return false
	}
	switch failure.stage {
	case workerFailureExecutionEngineTimeout,
		workerFailureExecutionComposeTimeout,
		workerFailureExecutionObserveTimeout,
		workerFailureExecutionObserveDown:
		return true
	default:
		return false
	}
}

func runWorkerLoop(
	ctx context.Context,
	processNext func(context.Context, string) (bool, error),
	refreshExecutionTarget func(context.Context) error,
	workerID string,
	refreshInterval time.Duration,
	refreshBackoff time.Duration,
) error {
	if ctx == nil || processNext == nil || refreshExecutionTarget == nil ||
		refreshInterval <= 0 || refreshBackoff <= 0 {
		return errors.New("PaaS worker loop configuration is invalid")
	}
	nextRefresh := time.Now().Add(refreshInterval)
	refreshBlocked := false
	for {
		if !time.Now().Before(nextRefresh) {
			if err := refreshExecutionTarget(ctx); err != nil {
				if ctx.Err() != nil {
					return nil
				}
				if retryableExecutionProfileRefreshFailure(err) {
					refreshBlocked = true
					nextRefresh = time.Now().Add(refreshBackoff)
				} else {
					var failure *workerFailure
					if errors.As(err, &failure) {
						return failure
					}
					return errors.New("PaaS execution target refresh failed")
				}
			} else {
				refreshBlocked = false
				nextRefresh = time.Now().Add(refreshInterval)
			}
		}
		if refreshBlocked {
			wait := time.Until(nextRefresh)
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
				continue
			}
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
