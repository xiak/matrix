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

	iamv1 "github.com/xiak/matrix/api/iam/v1"
	audithttp "github.com/xiak/matrix/app/service/iam/internal/data/audithttp"
	iampostgres "github.com/xiak/matrix/app/service/iam/internal/data/postgres"
	"github.com/xiak/matrix/app/service/iam/internal/usecase/auditdispatch"
	"github.com/xiak/matrix/app/service/internal/processconfig"
)

const (
	databaseDSNFileEnvironment = "MATRIX_IAM_AUDIT_DATABASE_DSN_FILE"
	auditEndpointEnvironment   = "MATRIX_IAM_AUDIT_ENDPOINT"
	credentialFileEnvironment  = "MATRIX_IAM_AUDIT_CREDENTIAL_FILE"
	workerIDEnvironment        = "MATRIX_IAM_AUDIT_WORKER_ID"
	pollInterval               = 250 * time.Millisecond
)

type configuration struct {
	databaseDSNFile string
	auditEndpoint   string
	credentialFile  string
	workerID        string
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "matrix IAM Audit dispatcher failed")
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
		return errors.New("IAM Audit database configuration is invalid")
	}
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return errors.New("IAM Audit database pool cannot start")
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return errors.New("IAM Audit database is unavailable")
	}
	credentialText, err := processconfig.ReadText(config.credentialFile, 16*1024, true)
	if err != nil {
		return err
	}
	credential, err := iamv1.NewSecret(credentialText)
	credentialText = ""
	if err != nil {
		return errors.New("IAM Audit producer credential is invalid")
	}
	ingestor, err := audithttp.NewClient(audithttp.Config{
		Endpoint: config.auditEndpoint, Credential: credential,
	})
	if err != nil {
		return err
	}
	repository, err := iampostgres.NewAuditOutboxRepository(pool)
	if err != nil {
		return err
	}
	dispatcher, err := auditdispatch.NewUsecase(repository, ingestor, auditdispatch.Config{
		WorkerID:        config.workerID,
		LeaseDuration:   15 * time.Second,
		DeliveryTimeout: 5 * time.Second,
		InitialBackoff:  time.Second,
		MaxBackoff:      time.Minute,
		MaxAttempts:     10,
	})
	if err != nil {
		return err
	}
	for {
		result, err := dispatcher.DispatchOnce(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return errors.New("IAM Audit dispatch cycle failed")
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
	}
	if config.databaseDSNFile == "" || config.auditEndpoint == "" ||
		config.credentialFile == "" || config.workerID == "" {
		return configuration{}, errors.New("IAM Audit dispatcher configuration is incomplete")
	}
	return config, nil
}
