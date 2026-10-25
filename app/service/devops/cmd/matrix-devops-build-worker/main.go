// matrix-devops-build-worker owns the table-blind VERIFY lease, read-only
// source archive access, and the executor gateway's exact admin identity. It
// has no provider, reporter, IAM, Audit, PaaS, runner, or Docker authority.
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
	"github.com/xiak/matrix/app/service/devops/internal/delivery/data/executorgatewayhttp"
	devopspostgres "github.com/xiak/matrix/app/service/devops/internal/delivery/data/postgres"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/data/sourcearchivefile"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/buildexecution"
	"github.com/xiak/matrix/app/service/internal/processconfig"
	"github.com/xiak/matrix/app/service/internal/processhttp"
	"github.com/xiak/matrix/app/service/internal/processmtls"
)

const (
	databaseDSNFileEnvironment = "MATRIX_DEVOPS_BUILD_WORKER_DATABASE_DSN_FILE"
	archiveRootEnvironment     = "MATRIX_DEVOPS_BUILD_WORKER_SOURCE_ARCHIVE_ROOT"
	workerIDEnvironment        = "MATRIX_DEVOPS_BUILD_WORKER_ID"
	listenAddressEnvironment   = "MATRIX_DEVOPS_BUILD_WORKER_LISTEN_ADDRESS"
	gatewayOriginEnvironment   = "MATRIX_DEVOPS_BUILD_WORKER_GATEWAY_ORIGIN"
	gatewayNameEnvironment     = "MATRIX_DEVOPS_BUILD_WORKER_GATEWAY_SERVER_NAME"
	clientCertEnvironment      = "MATRIX_DEVOPS_BUILD_WORKER_CLIENT_CERT_FILE"
	clientKeyEnvironment       = "MATRIX_DEVOPS_BUILD_WORKER_CLIENT_KEY_FILE"
	serverCAEnvironment        = "MATRIX_DEVOPS_BUILD_WORKER_SERVER_CA_FILE"
	clientIdentityEnvironment  = "MATRIX_DEVOPS_BUILD_WORKER_CLIENT_IDENTITY"
	pollInterval               = 250 * time.Millisecond
)

type configuration struct {
	databaseDSNFile string
	archiveRoot     string
	workerID        string
	listenAddress   string
	gatewayOrigin   string
	gatewayName     string
	clientCertFile  string
	clientKeyFile   string
	serverCAFile    string
	clientIdentity  string
}

type buildOutcome struct {
	result buildexecution.Result
	err    error
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "matrix DevOps build worker failed")
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	if ctx == nil {
		return errors.New("DevOps build worker context is required")
	}
	config, err := loadConfiguration()
	if err != nil {
		return err
	}
	dsn, err := processconfig.ReadText(config.databaseDSNFile, 16*1024, true)
	if err != nil {
		return errors.New("DevOps build worker database configuration is unavailable")
	}
	poolConfig, err := pgxpool.ParseConfig(dsn)
	dsn = ""
	if err != nil {
		return errors.New("DevOps build worker database configuration is invalid")
	}
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return errors.New("DevOps build worker database pool cannot start")
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return errors.New("DevOps build worker database is unavailable")
	}

	archives, err := sourcearchivefile.New(config.archiveRoot)
	if err != nil {
		return errors.New("DevOps build worker source archive boundary is unavailable")
	}
	credentials, err := processmtls.LoadClientCredentials(
		config.clientCertFile,
		config.clientKeyFile,
		config.serverCAFile,
		config.clientIdentity,
		time.Now(),
	)
	if err != nil {
		return errors.New("DevOps build worker mTLS identity is unavailable")
	}
	executor, err := executorgatewayhttp.NewAdminClient(
		config.gatewayOrigin,
		config.gatewayName,
		credentials.Certificate,
		credentials.ServerRoots,
	)
	if err != nil {
		return errors.New("DevOps build worker executor gateway is invalid")
	}
	repository, err := devopspostgres.NewBuildExecutionRepository(pool)
	if err != nil {
		return err
	}
	worker, err := buildexecution.NewService(
		repository,
		archives,
		executor,
		executor,
		buildexecution.Config{
			WorkerID:      config.workerID,
			LeaseDuration: buildexecution.LeaseDuration,
			Deadline:      buildexecution.ExecutionDeadline,
			CancelGrace:   buildexecution.CancellationGrace,
		},
	)
	if err != nil {
		return err
	}
	if _, err := worker.Heartbeat(ctx); err != nil {
		return errors.New("DevOps build worker heartbeat cannot start")
	}
	readiness := func(readinessContext context.Context) error {
		state, checkErr := worker.Readiness(readinessContext)
		if checkErr != nil || state.State != devopsv1.ReadinessReady ||
			devopsv1.ValidateReadiness(state) != nil {
			return errors.New("DevOps build worker database readiness failed")
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
		func(workerContext context.Context) error {
			return runBuildLoop(
				workerContext,
				worker.BuildOnce,
				worker.Heartbeat,
				buildexecution.HeartbeatInterval,
				pollInterval,
			)
		},
	)
}

func runBuildLoop(
	ctx context.Context,
	buildOnce func(context.Context) (buildexecution.Result, error),
	heartbeat func(context.Context) (time.Time, error),
	heartbeatInterval time.Duration,
	idlePollInterval time.Duration,
) error {
	if ctx == nil || buildOnce == nil || heartbeat == nil ||
		heartbeatInterval <= 0 || idlePollInterval <= 0 {
		return errors.New("DevOps build worker loop configuration is invalid")
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
	outcomes := make(chan buildOutcome, 1)
	startBuild := func() {
		go func() {
			result, err := buildOnce(loopContext)
			outcomes <- buildOutcome{result: result, err: err}
		}()
	}
	startBuild()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-heartbeats.C:
			if _, err := heartbeat(loopContext); err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return errors.New("DevOps build worker heartbeat failed")
			}
		case <-idle.C:
			startBuild()
		case outcome := <-outcomes:
			if outcome.err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return errors.New("DevOps build execution cycle failed")
			}
			if outcome.result.Claimed {
				startBuild()
				continue
			}
			idle.Reset(idlePollInterval)
		}
	}
}

func loadConfiguration() (configuration, error) {
	config := configuration{
		databaseDSNFile: os.Getenv(databaseDSNFileEnvironment),
		archiveRoot:     os.Getenv(archiveRootEnvironment),
		workerID:        os.Getenv(workerIDEnvironment),
		listenAddress:   os.Getenv(listenAddressEnvironment),
		gatewayOrigin:   os.Getenv(gatewayOriginEnvironment),
		gatewayName:     os.Getenv(gatewayNameEnvironment),
		clientCertFile:  os.Getenv(clientCertEnvironment),
		clientKeyFile:   os.Getenv(clientKeyEnvironment),
		serverCAFile:    os.Getenv(serverCAEnvironment),
		clientIdentity:  os.Getenv(clientIdentityEnvironment),
	}
	if config.databaseDSNFile == "" || config.archiveRoot == "" ||
		config.workerID == "" || config.listenAddress == "" ||
		config.gatewayOrigin == "" || config.gatewayName == "" ||
		config.clientCertFile == "" || config.clientKeyFile == "" ||
		config.serverCAFile == "" || config.clientIdentity == "" {
		return configuration{}, errors.New("DevOps build worker configuration is incomplete")
	}
	if devopsv1.ValidateID("buildWorker.workerId", config.workerID) != nil {
		return configuration{}, errors.New("DevOps build worker identity is invalid")
	}
	return config, nil
}
