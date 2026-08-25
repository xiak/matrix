package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	apphostingv1 "github.com/xiak/matrix/api/adapter/apphosting/v1"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
	composeadapter "github.com/xiak/matrix/app/adapter/apphosting/compose"
	localmachineadapter "github.com/xiak/matrix/app/adapter/infrastructure/localmachine"
	"github.com/xiak/matrix/app/service/internal/processconfig"
	"github.com/xiak/matrix/app/service/internal/processhttp"
	paaspostgres "github.com/xiak/matrix/app/service/paas/internal/apphosting/data/postgres"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/domain/placement"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/createplacement"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/operationqueue"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/reconciledeployment"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/refreshexecutionprofile"
)

const (
	databaseDSNFileEnvironment  = "MATRIX_PAAS_WORKER_DATABASE_DSN_FILE"
	workerIDEnvironment         = "MATRIX_PAAS_WORKER_ID"
	bindingRefEnvironment       = "MATRIX_PAAS_WORKER_BINDING_REF"
	bindingRootEnvironment      = "MATRIX_PAAS_WORKER_BINDING_ROOT"
	secretRootEnvironment       = "MATRIX_PAAS_WORKER_SECRET_ROOT"
	artifactCatalogEnvironment  = "MATRIX_PAAS_WORKER_ARTIFACT_CATALOG_FILE"
	executionTenantEnvironment  = "MATRIX_PAAS_WORKER_EXECUTION_TENANT_ID"
	machineBindingEnvironment   = "MATRIX_PAAS_WORKER_MACHINE_BINDING_REF"
	listenAddressEnvironment    = "MATRIX_PAAS_WORKER_LISTEN_ADDRESS"
	pollInterval                = 250 * time.Millisecond
	executionTargetRefresh      = time.Minute
	executionTargetMaximumAge   = 5 * time.Minute
	executionTargetTimeout      = 5 * time.Second
	operationLeaseDuration      = 30 * time.Second
	effectTimeout               = 20 * time.Second
	reconcileBackoff            = time.Second
	maximumOperationAttempts    = 10
	placementDecisionTTL        = 5 * time.Minute
	pendingCapacityClaimTTL     = 10 * time.Minute
	maximumArtifactCatalogBytes = 1024 * 1024
)

type configuration struct {
	databaseDSNFile string
	workerID        string
	bindingRef      string
	bindingRoot     string
	secretRoot      string
	artifactCatalog string
	executionTenant paasv1.TenantID
	machineBinding  string
	listenAddress   string
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
		_, _ = fmt.Fprintln(os.Stderr, "matrix PaaS worker failed")
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
	executionProfile, err := newLocalExecutionProfile(config, pool)
	if err != nil {
		return err
	}
	if err := executionProfile.Refresh(ctx); err != nil {
		return errors.New("PaaS local execution profile cannot start")
	}

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
	secrets, err := composeadapter.NewFileSecretResolver(config.secretRoot)
	if err != nil {
		return err
	}
	runtime := composeadapter.NewLocalRuntime()
	executor, err := composeadapter.New(composeadapter.Config{
		BindingRef: config.bindingRef, BindingRoot: config.bindingRoot,
		Artifacts: artifacts, Secrets: secrets, Runtime: runtime,
	})
	if err != nil {
		return err
	}

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
			return errors.New("PaaS worker database readiness failed")
		}
		if checkErr := artifacts.Ready(readinessContext); checkErr != nil {
			return errors.New("PaaS worker artifact readiness failed")
		}
		if checkErr := runtime.Ready(readinessContext); checkErr != nil {
			return errors.New("PaaS worker Compose readiness failed")
		}
		if checkErr := executionProfile.Ready(readinessContext); checkErr != nil {
			return errors.New("PaaS worker execution profile readiness failed")
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
	return processhttp.ServeWithBackground(
		ctx,
		config.listenAddress,
		handler,
		func(workerContext context.Context) error {
			return runWorkerLoop(
				workerContext,
				worker.ProcessNext,
				executionProfile.Refresh,
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
			return errors.New("PaaS Deployment reconciliation cycle failed")
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
		databaseDSNFile: os.Getenv(databaseDSNFileEnvironment),
		workerID:        os.Getenv(workerIDEnvironment),
		bindingRef:      os.Getenv(bindingRefEnvironment),
		bindingRoot:     os.Getenv(bindingRootEnvironment),
		secretRoot:      os.Getenv(secretRootEnvironment),
		artifactCatalog: os.Getenv(artifactCatalogEnvironment),
		executionTenant: paasv1.TenantID(os.Getenv(executionTenantEnvironment)),
		machineBinding:  os.Getenv(machineBindingEnvironment),
		listenAddress:   os.Getenv(listenAddressEnvironment),
	}
	if config.databaseDSNFile == "" || config.workerID == "" ||
		config.bindingRef == "" || config.bindingRoot == "" ||
		config.secretRoot == "" || config.artifactCatalog == "" ||
		config.executionTenant == "" || config.machineBinding == "" ||
		config.listenAddress == "" {
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
