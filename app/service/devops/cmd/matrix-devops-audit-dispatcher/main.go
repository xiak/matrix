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
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	audithttp "github.com/xiak/matrix/app/service/devops/internal/delivery/data/audithttp"
	devopspostgres "github.com/xiak/matrix/app/service/devops/internal/delivery/data/postgres"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/auditdispatch"
	"github.com/xiak/matrix/app/service/internal/processconfig"
	"github.com/xiak/matrix/app/service/internal/processhttp"
)

const (
	databaseDSNFileEnvironment = "MATRIX_DEVOPS_AUDIT_DATABASE_DSN_FILE"
	auditEndpointEnvironment   = "MATRIX_DEVOPS_AUDIT_ENDPOINT"
	credentialFileEnvironment  = "MATRIX_DEVOPS_AUDIT_CREDENTIAL_FILE"
	workerIDEnvironment        = "MATRIX_DEVOPS_AUDIT_WORKER_ID"
	listenAddressEnvironment   = "MATRIX_DEVOPS_AUDIT_LISTEN_ADDRESS"
	pollInterval               = 250 * time.Millisecond
)

type configuration struct {
	databaseDSNFile string
	auditEndpoint   string
	credentialFile  string
	workerID        string
	listenAddress   string
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "matrix DevOps Audit dispatcher failed")
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
		return errors.New("DevOps Audit database configuration is invalid")
	}
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return errors.New("DevOps Audit database pool cannot start")
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return errors.New("DevOps Audit database is unavailable")
	}
	credentialText, err := processconfig.ReadText(config.credentialFile, 16*1024, true)
	if err != nil {
		return err
	}
	credential, err := iamv1.NewSecret(credentialText)
	credentialText = ""
	if err != nil {
		return errors.New("DevOps Audit producer credential is invalid")
	}
	ingestor, err := audithttp.NewClient(audithttp.Config{
		Endpoint: config.auditEndpoint, Credential: credential,
	})
	if err != nil {
		return err
	}
	repository, err := devopspostgres.NewAuditOutboxRepository(pool)
	if err != nil {
		return err
	}
	dispatcher, err := auditdispatch.NewUsecase(repository, ingestor, auditdispatch.Config{
		WorkerID: config.workerID, LeaseDuration: 15 * time.Second,
		DeliveryTimeout: 5 * time.Second, InitialBackoff: time.Second,
		MaxBackoff: time.Minute, MaxAttempts: 10,
	})
	if err != nil {
		return err
	}
	readiness := func(readinessContext context.Context) error {
		state, checkErr := dispatcher.Readiness(readinessContext)
		if checkErr != nil || state.State != devopsv1.ReadinessReady {
			return errors.New("DevOps Audit dispatcher database readiness failed")
		}
		if checkErr := ingestor.Ready(readinessContext); checkErr != nil {
			return errors.New("DevOps Audit dispatcher target readiness failed")
		}
		return nil
	}
	handler, err := processhttp.NewReadinessHandler(readiness)
	if err != nil {
		return err
	}
	return processhttp.ServeWithBackground(
		ctx, config.listenAddress, handler,
		func(dispatchContext context.Context) error {
			return runDispatchLoop(dispatchContext, dispatcher)
		},
	)
}

func runDispatchLoop(ctx context.Context, dispatcher *auditdispatch.Usecase) error {
	for {
		result, err := dispatcher.DispatchOnce(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return errors.New("DevOps Audit dispatch cycle failed")
		}
		if result.Claimed {
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
		auditEndpoint:   os.Getenv(auditEndpointEnvironment),
		credentialFile:  os.Getenv(credentialFileEnvironment),
		workerID:        os.Getenv(workerIDEnvironment),
		listenAddress:   os.Getenv(listenAddressEnvironment),
	}
	if config.databaseDSNFile == "" || config.auditEndpoint == "" ||
		config.credentialFile == "" || config.workerID == "" || config.listenAddress == "" {
		return configuration{}, errors.New("DevOps Audit dispatcher configuration is incomplete")
	}
	return config, nil
}
