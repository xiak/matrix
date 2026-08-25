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

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	composeadapter "github.com/xiak/matrix/app/adapter/apphosting/compose"
	"github.com/xiak/matrix/app/service/internal/processconfig"
	"github.com/xiak/matrix/app/service/internal/processhttp"
	paaspostgres "github.com/xiak/matrix/app/service/paas/internal/apphosting/data/postgres"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/domain/placement"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/createplacement"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/operationqueue"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/reconciledeployment"
)

const (
	databaseDSNFileEnvironment  = "MATRIX_PAAS_WORKER_DATABASE_DSN_FILE"
	workerIDEnvironment         = "MATRIX_PAAS_WORKER_ID"
	bindingRefEnvironment       = "MATRIX_PAAS_WORKER_BINDING_REF"
	bindingRootEnvironment      = "MATRIX_PAAS_WORKER_BINDING_ROOT"
	secretRootEnvironment       = "MATRIX_PAAS_WORKER_SECRET_ROOT"
	artifactCatalogEnvironment  = "MATRIX_PAAS_WORKER_ARTIFACT_CATALOG_FILE"
	listenAddressEnvironment    = "MATRIX_PAAS_WORKER_LISTEN_ADDRESS"
	pollInterval                = 250 * time.Millisecond
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
	listenAddress   string
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

	catalogContent, err := processconfig.ReadFile(
		config.artifactCatalog,
		maximumArtifactCatalogBytes,
		false,
	)
	if err != nil {
		return err
	}
	catalog, err := composeadapter.DecodeArtifactCatalog(catalogContent)
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
			return runWorkerLoop(workerContext, worker.ProcessNext, config.workerID)
		},
	)
}

func runWorkerLoop(
	ctx context.Context,
	processNext func(context.Context, string) (bool, error),
	workerID string,
) error {
	if ctx == nil || processNext == nil {
		return errors.New("PaaS worker loop configuration is invalid")
	}
	for {
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
		timer := time.NewTimer(pollInterval)
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
		listenAddress:   os.Getenv(listenAddressEnvironment),
	}
	if config.databaseDSNFile == "" || config.workerID == "" ||
		config.bindingRef == "" || config.bindingRoot == "" ||
		config.secretRoot == "" || config.artifactCatalog == "" ||
		config.listenAddress == "" {
		return configuration{}, errors.New("PaaS worker configuration is incomplete")
	}
	if paasv1.ValidateID("workerId", config.workerID) != nil ||
		paasv1.ValidateID("bindingRef", config.bindingRef) != nil {
		return configuration{}, errors.New("PaaS worker identity configuration is invalid")
	}
	return config, nil
}
