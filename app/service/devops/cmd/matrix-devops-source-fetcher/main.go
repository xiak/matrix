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

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/data/gitea"
	devopspostgres "github.com/xiak/matrix/app/service/devops/internal/delivery/data/postgres"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/data/sourcearchivefile"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/data/sourcecredentialfile"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/data/sourcetrustfile"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/sourceacquisition"
	"github.com/xiak/matrix/app/service/devops/sourcecredential"
	"github.com/xiak/matrix/app/service/internal/processconfig"
	"github.com/xiak/matrix/app/service/internal/processhttp"
)

const (
	databaseDSNFileEnvironment = "MATRIX_DEVOPS_SOURCE_FETCHER_DATABASE_DSN_FILE"
	fetchRootEnvironment       = "MATRIX_DEVOPS_SOURCE_FETCHER_FETCH_ROOT"
	archiveRootEnvironment     = "MATRIX_DEVOPS_SOURCE_FETCHER_ARCHIVE_ROOT"
	trustRootEnvironment       = "MATRIX_DEVOPS_SOURCE_FETCHER_TRUST_ROOT"
	workerIDEnvironment        = "MATRIX_DEVOPS_SOURCE_FETCHER_WORKER_ID"
	listenAddressEnvironment   = "MATRIX_DEVOPS_SOURCE_FETCHER_LISTEN_ADDRESS"
	pollInterval               = 250 * time.Millisecond
)

type configuration struct {
	databaseDSNFile string
	fetchRoot       string
	archiveRoot     string
	trustRoot       string
	workerID        string
	listenAddress   string
}

type fetchOutcome struct {
	result sourceacquisition.Result
	err    error
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "matrix DevOps source fetcher failed")
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
		return errors.New("DevOps source fetcher database configuration is invalid")
	}
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return errors.New("DevOps source fetcher database pool cannot start")
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return errors.New("DevOps source fetcher database is unavailable")
	}

	credentials, err := sourcecredentialfile.NewResolver(
		sourcecredential.PurposeFetch, config.fetchRoot,
	)
	if err != nil {
		return err
	}
	trust, err := sourcetrustfile.NewResolver(config.trustRoot)
	if err != nil {
		return err
	}
	provider, err := gitea.NewFetcher(credentials, trust)
	if err != nil {
		return err
	}
	archives, err := sourcearchivefile.New(config.archiveRoot)
	if err != nil {
		return err
	}
	repository, err := devopspostgres.NewSourceAcquisitionRepository(pool)
	if err != nil {
		return err
	}
	fetcher, err := sourceacquisition.NewService(
		repository,
		provider,
		archives,
		sourceacquisition.Config{
			WorkerID:      config.workerID,
			LeaseDuration: sourceacquisition.LeaseDuration,
			Deadline:      sourceacquisition.AcquisitionDeadline,
		},
	)
	if err != nil {
		return err
	}
	if _, err := fetcher.Heartbeat(ctx); err != nil {
		return errors.New("DevOps source fetcher heartbeat cannot start")
	}
	readiness := func(readinessContext context.Context) error {
		state, checkErr := fetcher.Readiness(readinessContext)
		if checkErr != nil || state.State != devopsv1.ReadinessReady ||
			devopsv1.ValidateReadiness(state) != nil {
			return errors.New("DevOps source fetcher database readiness failed")
		}
		return nil
	}
	handler, err := processhttp.NewReadinessHandler(readiness)
	if err != nil {
		return err
	}
	return processhttp.ServeWithBackground(
		ctx,
		config.listenAddress,
		handler,
		func(fetchContext context.Context) error {
			return runAcquisitionLoop(
				fetchContext,
				fetcher.FetchOnce,
				fetcher.Heartbeat,
				sourceacquisition.HeartbeatInterval,
				pollInterval,
			)
		},
	)
}

func runAcquisitionLoop(
	ctx context.Context,
	fetchOnce func(context.Context) (sourceacquisition.Result, error),
	heartbeat func(context.Context) (time.Time, error),
	heartbeatInterval time.Duration,
	idlePollInterval time.Duration,
) error {
	if ctx == nil || fetchOnce == nil || heartbeat == nil ||
		heartbeatInterval <= 0 || idlePollInterval <= 0 {
		return errors.New("DevOps source fetcher loop configuration is invalid")
	}
	loopContext, cancel := context.WithCancel(ctx)
	defer cancel()
	heartbeats := time.NewTicker(heartbeatInterval)
	defer heartbeats.Stop()
	idle := time.NewTimer(time.Hour)
	if !idle.Stop() {
		<-idle.C
	}
	defer idle.Stop()
	outcomes := make(chan fetchOutcome, 1)
	working := false
	startFetch := func() {
		working = true
		go func() {
			result, err := fetchOnce(loopContext)
			outcomes <- fetchOutcome{result: result, err: err}
		}()
	}
	startFetch()
	for {
		select {
		case <-ctx.Done():
			cancel()
			if working {
				<-outcomes
			}
			return nil
		case <-heartbeats.C:
			if _, err := heartbeat(loopContext); err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return errors.New("DevOps source fetcher heartbeat failed")
			}
		case <-idle.C:
			startFetch()
		case outcome := <-outcomes:
			working = false
			if outcome.err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return errors.New("DevOps source acquisition cycle failed")
			}
			if outcome.result.Claimed {
				startFetch()
				continue
			}
			idle.Reset(idlePollInterval)
		}
	}
}

func loadConfiguration() (configuration, error) {
	config := configuration{
		databaseDSNFile: os.Getenv(databaseDSNFileEnvironment),
		fetchRoot:       os.Getenv(fetchRootEnvironment),
		archiveRoot:     os.Getenv(archiveRootEnvironment),
		trustRoot:       os.Getenv(trustRootEnvironment),
		workerID:        os.Getenv(workerIDEnvironment),
		listenAddress:   os.Getenv(listenAddressEnvironment),
	}
	if config.databaseDSNFile == "" || config.fetchRoot == "" ||
		config.archiveRoot == "" || config.trustRoot == "" || config.workerID == "" ||
		config.listenAddress == "" {
		return configuration{}, errors.New("DevOps source fetcher configuration is incomplete")
	}
	if devopsv1.ValidateID("sourceFetcher.workerId", config.workerID) != nil {
		return configuration{}, errors.New("DevOps source fetcher identity is invalid")
	}
	return config, nil
}
