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
	"github.com/xiak/matrix/app/service/devops/internal/delivery/data/sourcecredentialfile"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/sourceobservation"
	"github.com/xiak/matrix/app/service/devops/sourcecredential"
	"github.com/xiak/matrix/app/service/internal/processconfig"
	"github.com/xiak/matrix/app/service/internal/processhttp"
)

const (
	databaseDSNFileEnvironment = "MATRIX_DEVOPS_SOURCE_OBSERVER_DATABASE_DSN_FILE"
	webhookRootEnvironment     = "MATRIX_DEVOPS_SOURCE_OBSERVER_WEBHOOK_ROOT"
	fetchRootEnvironment       = "MATRIX_DEVOPS_SOURCE_OBSERVER_FETCH_ROOT"
	reportRootEnvironment      = "MATRIX_DEVOPS_SOURCE_OBSERVER_REPORT_ROOT"
	workerIDEnvironment        = "MATRIX_DEVOPS_SOURCE_OBSERVER_WORKER_ID"
	listenAddressEnvironment   = "MATRIX_DEVOPS_SOURCE_OBSERVER_LISTEN_ADDRESS"
	pollInterval               = 250 * time.Millisecond
)

type configuration struct {
	databaseDSNFile string
	webhookRoot     string
	fetchRoot       string
	reportRoot      string
	workerID        string
	listenAddress   string
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "matrix DevOps source observer failed")
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
		return errors.New("DevOps source observer database configuration is invalid")
	}
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return errors.New("DevOps source observer database pool cannot start")
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return errors.New("DevOps source observer database is unavailable")
	}

	webhook, err := sourcecredentialfile.NewResolver(
		sourcecredential.PurposeWebhook, config.webhookRoot,
	)
	if err != nil {
		return err
	}
	fetch, err := sourcecredentialfile.NewResolver(
		sourcecredential.PurposeFetch, config.fetchRoot,
	)
	if err != nil {
		return err
	}
	report, err := sourcecredentialfile.NewResolver(
		sourcecredential.PurposeReport, config.reportRoot,
	)
	if err != nil {
		return err
	}
	provider, err := gitea.NewObserver(webhook, fetch, report)
	if err != nil {
		return err
	}
	repository, err := devopspostgres.NewSourceObservationRepository(pool)
	if err != nil {
		return err
	}
	observer, err := sourceobservation.NewService(
		repository,
		provider,
		sourceobservation.Config{
			WorkerID: config.workerID, LeaseDuration: sourceobservation.LeaseDuration,
		},
	)
	if err != nil {
		return err
	}
	if _, err := observer.Heartbeat(ctx); err != nil {
		return errors.New("DevOps source observer heartbeat cannot start")
	}
	readiness := func(readinessContext context.Context) error {
		state, checkErr := observer.Readiness(readinessContext)
		if checkErr != nil || state.State != devopsv1.ReadinessReady ||
			devopsv1.ValidateReadiness(state) != nil {
			return errors.New("DevOps source observer database readiness failed")
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
		func(observationContext context.Context) error {
			return runObservationLoop(
				observationContext,
				observer.ObserveOnce,
				observer.Heartbeat,
				time.Now,
			)
		},
	)
}

func runObservationLoop(
	ctx context.Context,
	observeOnce func(context.Context) (sourceobservation.Result, error),
	heartbeat func(context.Context) (time.Time, error),
	now func() time.Time,
) error {
	if ctx == nil || observeOnce == nil || heartbeat == nil || now == nil {
		return errors.New("DevOps source observer loop configuration is invalid")
	}
	nextHeartbeat := now().Add(sourceobservation.HeartbeatInterval)
	for {
		if !now().Before(nextHeartbeat) {
			if _, err := heartbeat(ctx); err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return errors.New("DevOps source observer heartbeat failed")
			}
			nextHeartbeat = now().Add(sourceobservation.HeartbeatInterval)
		}
		result, err := observeOnce(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return errors.New("DevOps source observation cycle failed")
		}
		if result.Claimed {
			if _, err := heartbeat(ctx); err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return errors.New("DevOps source observer heartbeat failed")
			}
			nextHeartbeat = now().Add(sourceobservation.HeartbeatInterval)
			continue
		}
		wait := pollInterval
		if untilHeartbeat := nextHeartbeat.Sub(now()); untilHeartbeat < wait {
			wait = untilHeartbeat
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
		webhookRoot:     os.Getenv(webhookRootEnvironment),
		fetchRoot:       os.Getenv(fetchRootEnvironment),
		reportRoot:      os.Getenv(reportRootEnvironment),
		workerID:        os.Getenv(workerIDEnvironment),
		listenAddress:   os.Getenv(listenAddressEnvironment),
	}
	if config.databaseDSNFile == "" || config.webhookRoot == "" ||
		config.fetchRoot == "" || config.reportRoot == "" ||
		config.workerID == "" || config.listenAddress == "" {
		return configuration{}, errors.New("DevOps source observer configuration is incomplete")
	}
	if devopsv1.ValidateID("sourceObserver.workerId", config.workerID) != nil {
		return configuration{}, errors.New("DevOps source observer identity is invalid")
	}
	return config, nil
}
