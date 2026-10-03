package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	iampostgres "github.com/xiak/matrix/app/service/iam/internal/data/postgres"
	"github.com/xiak/matrix/app/service/iam/internal/usecase/accessanalysis"
	"github.com/xiak/matrix/app/service/internal/processconfig"
	"github.com/xiak/matrix/app/service/internal/processhttp"
)

const (
	databaseFileEnvironment  = "MATRIX_IAM_ACCESS_ANALYSIS_DATABASE_DSN_FILE"
	workerIDEnvironment      = "MATRIX_IAM_ACCESS_ANALYSIS_WORKER_ID"
	listenAddressEnvironment = "MATRIX_IAM_ACCESS_ANALYSIS_LISTEN_ADDRESS"
	databaseLogin            = "matrix_iam_access_analysis_worker_login"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "matrix IAM access analysis worker failed")
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	workerID, listenAddress := os.Getenv(workerIDEnvironment), os.Getenv(listenAddressEnvironment)
	if iamv1.ValidateID("workerId", workerID) != nil || listenAddress == "" {
		return errors.New("access analysis process configuration unavailable")
	}
	poolConfig, err := databaseConfig(os.Getenv(databaseFileEnvironment))
	if err != nil {
		return err
	}
	poolConfig.MaxConns, poolConfig.MinConns = 3, 0
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return errors.New("access analysis database unavailable")
	}
	defer pool.Close()
	repository, err := iampostgres.NewAccessAnalysisRepository(pool)
	if err != nil {
		return err
	}
	scanner, err := accessanalysis.NewScanner(repository, accessanalysis.NewRandomID, workerID)
	if err != nil {
		return err
	}
	if err := scanner.Ready(ctx); err != nil {
		return errors.New("access analysis authority unavailable")
	}
	handler, err := processhttp.NewReadinessHandler(scanner.Ready)
	if err != nil {
		return err
	}
	return processhttp.ServeWithBackground(ctx, listenAddress, handler, func(ctx context.Context) error {
		return runScanLoops(ctx, scanner)
	})
}

func databaseConfig(path string) (*pgxpool.Config, error) {
	dsn, err := processconfig.ReadText(path, 16*1024, true)
	if err != nil {
		return nil, errors.New("access analysis database configuration unavailable")
	}
	configuration, err := pgxpool.ParseConfig(dsn)
	dsn = ""
	if err != nil || configuration.ConnConfig.User != databaseLogin {
		return nil, errors.New("access analysis database identity invalid")
	}
	return configuration, nil
}

func runScanLoops(ctx context.Context, scanner *accessanalysis.Scanner) error {
	if scanner == nil {
		return accessanalysis.ErrUnavailable
	}
	var workers sync.WaitGroup
	for range 2 {
		workers.Go(func() {
			for ctx.Err() == nil {
				cycle, cancel := context.WithTimeout(ctx, 90*time.Second)
				result, err := scanner.ScanOnce(cycle)
				cancel()
				if ctx.Err() != nil {
					return
				}
				if err != nil {
					_, _ = fmt.Fprintln(os.Stderr, "IAM_ACCESS_ANALYSIS_CYCLE_UNAVAILABLE")
				}
				if err == nil && result.Claimed {
					continue
				}
				timer := time.NewTimer(time.Second)
				select {
				case <-ctx.Done():
					timer.Stop()
					return
				case <-timer.C:
				}
			}
		})
	}
	workers.Wait()
	return nil
}
