// matrix-devops-check-reporter is the only process that may turn one stored
// build receipt into one provider-visible terminal check. It owns no webhook,
// fetch, archive, executor, runner, IAM, Audit, PaaS, or Docker authority.
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
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/checkreporting"
	"github.com/xiak/matrix/app/service/devops/sourcecredential"
	"github.com/xiak/matrix/app/service/internal/processconfig"
	"github.com/xiak/matrix/app/service/internal/processhttp"
)

const (
	databaseDSNFileEnvironment = "MATRIX_DEVOPS_CHECK_REPORTER_DATABASE_DSN_FILE"
	reportRootEnvironment      = "MATRIX_DEVOPS_CHECK_REPORTER_REPORT_ROOT"
	workerIDEnvironment        = "MATRIX_DEVOPS_CHECK_REPORTER_WORKER_ID"
	listenAddressEnvironment   = "MATRIX_DEVOPS_CHECK_REPORTER_LISTEN_ADDRESS"
	pollInterval               = 250 * time.Millisecond
)

type configuration struct {
	databaseDSNFile string
	reportRoot      string
	workerID        string
	listenAddress   string
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "matrix DevOps check reporter failed")
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	if ctx == nil {
		return errors.New("DevOps check reporter context is required")
	}
	config, err := loadConfiguration()
	if err != nil {
		return err
	}
	dsn, err := processconfig.ReadText(config.databaseDSNFile, 16*1024, true)
	if err != nil {
		return errors.New("DevOps check reporter database configuration is unavailable")
	}
	poolConfig, err := pgxpool.ParseConfig(dsn)
	dsn = ""
	if err != nil {
		return errors.New("DevOps check reporter database configuration is invalid")
	}
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return errors.New("DevOps check reporter database pool cannot start")
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return errors.New("DevOps check reporter database is unavailable")
	}

	credentials, err := sourcecredentialfile.NewResolver(
		sourcecredential.PurposeReport, config.reportRoot,
	)
	if err != nil {
		return errors.New("DevOps check reporter credential boundary is unavailable")
	}
	reporter, err := gitea.NewCheckReporter(credentials)
	if err != nil {
		return err
	}
	repository, err := devopspostgres.NewCheckReportingRepository(pool)
	if err != nil {
		return err
	}
	service, err := checkreporting.NewService(
		repository,
		reporter,
		checkreporting.Config{
			WorkerID:      config.workerID,
			LeaseDuration: checkreporting.LeaseDuration,
			Deadline:      checkreporting.ProviderDeadline,
			RetryDelay:    checkreporting.ReconciliationDelay,
			Now:           time.Now,
		},
	)
	if err != nil {
		return err
	}
	if _, err := service.Heartbeat(ctx); err != nil {
		return errors.New("DevOps check reporter heartbeat cannot start")
	}
	readiness := func(readinessContext context.Context) error {
		state, checkErr := service.Readiness(readinessContext)
		if checkErr != nil || state.State != devopsv1.ReadinessReady ||
			devopsv1.ValidateReadiness(state) != nil {
			return errors.New("DevOps check reporter database readiness failed")
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
		func(reporterContext context.Context) error {
			return runReportLoop(
				reporterContext,
				service.ReportOnce,
				service.Heartbeat,
				time.Now,
			)
		},
	)
}

func runReportLoop(
	ctx context.Context,
	reportOnce func(context.Context) (checkreporting.Result, error),
	heartbeat func(context.Context) (time.Time, error),
	now func() time.Time,
) error {
	if ctx == nil || reportOnce == nil || heartbeat == nil || now == nil {
		return errors.New("DevOps check reporter loop configuration is invalid")
	}
	nextHeartbeat := now().Add(checkreporting.HeartbeatInterval)
	for {
		if !now().Before(nextHeartbeat) {
			if _, err := heartbeat(ctx); err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return errors.New("DevOps check reporter heartbeat failed")
			}
			nextHeartbeat = now().Add(checkreporting.HeartbeatInterval)
		}
		result, err := reportOnce(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return errors.New("DevOps check reporting cycle failed")
		}
		if result.Claimed {
			if _, err := heartbeat(ctx); err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return errors.New("DevOps check reporter heartbeat failed")
			}
			nextHeartbeat = now().Add(checkreporting.HeartbeatInterval)
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
		reportRoot:      os.Getenv(reportRootEnvironment),
		workerID:        os.Getenv(workerIDEnvironment),
		listenAddress:   os.Getenv(listenAddressEnvironment),
	}
	if config.databaseDSNFile == "" || config.reportRoot == "" ||
		config.workerID == "" || config.listenAddress == "" {
		return configuration{}, errors.New("DevOps check reporter configuration is incomplete")
	}
	if devopsv1.ValidateID("checkReporter.workerId", config.workerID) != nil {
		return configuration{}, errors.New("DevOps check reporter identity is invalid")
	}
	return config, nil
}
