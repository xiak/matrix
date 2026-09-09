//go:build linux

package postgres_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	devopsbuildv1 "github.com/xiak/matrix/api/adapter/devopsbuild/v1"
	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/data/executorgatewayhttp"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/data/executorspoolfile"
	devopspostgres "github.com/xiak/matrix/app/service/devops/internal/delivery/data/postgres"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/data/runnerjournalfile"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/data/sourcearchivefile"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/domain"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/port"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/sourcearchive"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/pipelineconfiguration"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/runadmission"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/runcontrol"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/sourceacquisition"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/sourceobservation"
	devopsmigration "github.com/xiak/matrix/app/service/devops/migration"
)

const (
	executionProcessDSNEnvironment          = "MATRIX_DEVOPS_EXECUTION_PROCESS_TEST_DSN"
	executionProcessDockerSocketEnvironment = "MATRIX_DEVOPS_EXECUTION_PROCESS_DOCKER_SOCKET"
	executionProcessGatewayEnvironment      = "MATRIX_DEVOPS_EXECUTION_PROCESS_GATEWAY_BINARY"
	executionProcessBuildWorkerEnvironment  = "MATRIX_DEVOPS_EXECUTION_PROCESS_BUILD_WORKER_BINARY"
	executionProcessRunnerEnvironment       = "MATRIX_DEVOPS_EXECUTION_PROCESS_RUNNER_BINARY"

	executionProcessGatewayName     = "executor-gateway.matrix.test"
	executionProcessAdminIdentity   = "spiffe://matrix.test/devops/build-worker"
	executionProcessRunnerNamespace = "spiffe://matrix.test/devops/runners"
	executionProcessRunnerIdentity  = "spiffe://matrix.test/devops/runners/node-one"
	executionProcessWorkerID        = "build-worker-process-gate"
	executionProcessStopTimeout     = 45 * time.Second
)

// TestBuildWorkerGatewayAndRunnerProcessesRecoverExternalEffects is the
// opt-in Gate B process journey from a PostgreSQL VERIFY intent to one real
// Docker/runsc receipt. It crashes the build worker after durable submission
// and the runner while its sandbox effect is running, then proves fenced,
// observe-before-retry recovery through fresh operating-system processes.
func TestBuildWorkerGatewayAndRunnerProcessesRecoverExternalEffects(t *testing.T) {
	adminDSN := os.Getenv(executionProcessDSNEnvironment)
	if adminDSN == "" {
		t.Skipf("set %s to a clean disposable PostgreSQL 18 database", executionProcessDSNEnvironment)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()

	dockerSocket := requiredExecutionProcessSocket(t)
	binaries := executionProcessBinaries{
		gateway:     requiredExecutionProcessBinary(t, executionProcessGatewayEnvironment),
		buildWorker: requiredExecutionProcessBinary(t, executionProcessBuildWorkerEnvironment),
		runner:      requiredExecutionProcessBinary(t, executionProcessRunnerEnvironment),
	}
	adminConfig, err := pgx.ParseConfig(adminDSN)
	if err != nil || !strings.HasPrefix(adminConfig.Database, "matrix_devops_process_") {
		t.Fatal("DevOps execution process database configuration is unsafe")
	}
	admin, err := pgx.ConnectConfig(ctx, adminConfig)
	if err != nil {
		t.Fatal("connect DevOps execution process database")
	}
	defer admin.Close(context.Background())
	assertCleanExecutionProcessDatabase(t, ctx, admin)

	apiPassword := "mxp1.process-api-000000000000000000000000000000"
	reporterPassword := "mxp1.process-reporter-00000000000000000000000000"
	fetcherPassword := "mxp1.process-fetcher-000000000000000000000000000"
	observerPassword := "mxp1.process-observer-00000000000000000000000000"
	workerPassword := "mxp1.process-worker-0000000000000000000000000000"
	apiDSN := runtimeDSN(t, adminDSN, "matrix_devops_api_login", apiPassword)
	reporterDSN := runtimeDSN(t, adminDSN, "matrix_devops_check_reporter_login", reporterPassword)
	fetcherDSN := runtimeDSN(t, adminDSN, "matrix_devops_source_fetcher_login", fetcherPassword)
	observerDSN := runtimeDSN(t, adminDSN, "matrix_devops_source_observer_login", observerPassword)
	workerDSN := runtimeDSN(t, adminDSN, "matrix_devops_worker_login", workerPassword)
	for attempt := 1; attempt <= 2; attempt++ {
		if err := devopsmigration.Apply(
			ctx, adminDSN, apiDSN, reporterDSN, fetcherDSN, observerDSN, workerDSN,
		); err != nil {
			t.Fatalf("apply execution process migration attempt %d: %v", attempt, err)
		}
	}
	if err := devopsmigration.VerifyInstalled(
		ctx, adminDSN, apiDSN, reporterDSN, fetcherDSN, observerDSN, workerDSN,
	); err != nil {
		t.Fatalf("verify execution process migration: %v", err)
	}

	temporary := t.TempDir()
	chmodExact(t, temporary, 0o700)
	archiveRoot := makeExecutionProcessDirectory(t, temporary, "source-archives", 0o700)
	spoolRoot := makeExecutionProcessDirectory(t, temporary, "executor-spool", 0o700)
	runnerStorage := makeExecutionProcessDirectory(t, temporary, "runner-storage", 0o700)
	journalRoot := makeExecutionProcessDirectory(t, runnerStorage, "journal", 0o700)
	workspaceRoot := makeExecutionProcessDirectory(t, runnerStorage, "workspaces", 0o700)
	credentialRoot := makeExecutionProcessDirectory(t, temporary, "runner-credentials", 0o700)

	apiPool := openExecutionProcessPool(t, ctx, apiDSN)
	defer apiPool.Close()
	observerPool := openExecutionProcessPool(t, ctx, observerDSN)
	defer observerPool.Close()
	fetcherPool := openExecutionProcessPool(t, ctx, fetcherDSN)
	defer fetcherPool.Close()
	controlRepository, err := devopspostgres.NewControlPlaneRepository(apiPool)
	if err != nil {
		t.Fatal(err)
	}
	configuration, err := pipelineconfiguration.NewUsecase(
		controlRepository, pipelineconfiguration.Config{MaxTransactionAttempts: 5},
	)
	if err != nil {
		t.Fatal(err)
	}
	runController, err := runcontrol.NewService(
		controlRepository, runcontrol.Config{MaxTransactionAttempts: 5},
	)
	if err != nil {
		t.Fatal(err)
	}
	run := seedExecutionProcessRun(
		t, ctx, configuration, controlRepository, observerPool, fetcherPool, archiveRoot,
	)

	pki := newExecutionProcessPKI(t)
	serverCertificatePath := writeExecutionProcessFile(
		t, temporary, "gateway-server.crt", pki.serverCertificate, 0o644,
	)
	serverKeyPath := writeExecutionProcessFile(
		t, temporary, "gateway-server.key", pki.serverKey, 0o600,
	)
	adminCAPath := writeExecutionProcessFile(t, temporary, "admin-ca.crt", pki.adminCA, 0o644)
	runnerCAPath := writeExecutionProcessFile(t, temporary, "runner-ca.crt", pki.runnerCA, 0o644)
	adminCertificatePath := writeExecutionProcessFile(
		t, temporary, "build-worker.crt", pki.adminCertificate, 0o644,
	)
	adminKeyPath := writeExecutionProcessFile(
		t, temporary, "build-worker.key", pki.adminKey, 0o600,
	)
	serverCAPath := writeExecutionProcessFile(t, temporary, "server-ca.crt", pki.serverCA, 0o644)
	writeExecutionProcessFile(t, credentialRoot, "client.crt", pki.runnerCertificate, 0o400)
	writeExecutionProcessFile(t, credentialRoot, "client.key", pki.runnerKey, 0o400)
	writeExecutionProcessFile(t, credentialRoot, "server-ca.pem", pki.serverCA, 0o400)
	chmodExact(t, credentialRoot, 0o500)
	workerDSNPath := writeExecutionProcessFile(
		t, temporary, "build-worker-dsn", []byte(workerDSN), 0o600,
	)

	adminAddress := reserveExecutionProcessAddress(t)
	runnerAddress := reserveDistinctExecutionProcessAddress(t, adminAddress)
	gatewayReadinessAddress := reserveDistinctExecutionProcessAddress(
		t, adminAddress, runnerAddress,
	)
	workerReadinessAddress := reserveDistinctExecutionProcessAddress(
		t, adminAddress, runnerAddress, gatewayReadinessAddress,
	)
	runnerReadinessAddress := reserveDistinctExecutionProcessAddress(
		t, adminAddress, runnerAddress, gatewayReadinessAddress, workerReadinessAddress,
	)
	gatewayEnvironment := []string{
		"MATRIX_DEVOPS_EXECUTOR_GATEWAY_SPOOL_ROOT=" + spoolRoot,
		"MATRIX_DEVOPS_EXECUTOR_GATEWAY_ADMIN_LISTEN_ADDRESS=" + adminAddress,
		"MATRIX_DEVOPS_EXECUTOR_GATEWAY_RUNNER_LISTEN_ADDRESS=" + runnerAddress,
		"MATRIX_DEVOPS_EXECUTOR_GATEWAY_READINESS_LISTEN_ADDRESS=" + gatewayReadinessAddress,
		"MATRIX_DEVOPS_EXECUTOR_GATEWAY_SERVER_CERT_FILE=" + serverCertificatePath,
		"MATRIX_DEVOPS_EXECUTOR_GATEWAY_SERVER_KEY_FILE=" + serverKeyPath,
		"MATRIX_DEVOPS_EXECUTOR_GATEWAY_ADMIN_CLIENT_CA_FILE=" + adminCAPath,
		"MATRIX_DEVOPS_EXECUTOR_GATEWAY_ADMIN_CLIENT_IDENTITY=" + executionProcessAdminIdentity,
		"MATRIX_DEVOPS_EXECUTOR_GATEWAY_RUNNER_CLIENT_CA_FILE=" + runnerCAPath,
		"MATRIX_DEVOPS_EXECUTOR_GATEWAY_RUNNER_NAMESPACE=" + executionProcessRunnerNamespace,
	}
	workerEnvironment := []string{
		"MATRIX_DEVOPS_BUILD_WORKER_DATABASE_DSN_FILE=" + workerDSNPath,
		"MATRIX_DEVOPS_BUILD_WORKER_SOURCE_ARCHIVE_ROOT=" + archiveRoot,
		"MATRIX_DEVOPS_BUILD_WORKER_ID=" + executionProcessWorkerID,
		"MATRIX_DEVOPS_BUILD_WORKER_LISTEN_ADDRESS=" + workerReadinessAddress,
		"MATRIX_DEVOPS_BUILD_WORKER_GATEWAY_ORIGIN=https://" + adminAddress,
		"MATRIX_DEVOPS_BUILD_WORKER_GATEWAY_SERVER_NAME=" + executionProcessGatewayName,
		"MATRIX_DEVOPS_BUILD_WORKER_CLIENT_CERT_FILE=" + adminCertificatePath,
		"MATRIX_DEVOPS_BUILD_WORKER_CLIENT_KEY_FILE=" + adminKeyPath,
		"MATRIX_DEVOPS_BUILD_WORKER_SERVER_CA_FILE=" + serverCAPath,
		"MATRIX_DEVOPS_BUILD_WORKER_CLIENT_IDENTITY=" + executionProcessAdminIdentity,
	}
	runnerEnvironment := []string{
		"MATRIX_DEVOPS_RUNNER_JOURNAL_ROOT=" + journalRoot,
		"MATRIX_DEVOPS_RUNNER_WORKSPACE_ROOT=" + workspaceRoot,
		"MATRIX_DEVOPS_RUNNER_STORAGE_ROOT=" + runnerStorage,
		"MATRIX_DEVOPS_RUNNER_DOCKER_SOCKET=" + dockerSocket,
		"MATRIX_DEVOPS_RUNNER_LISTEN_ADDRESS=" + runnerReadinessAddress,
		"MATRIX_DEVOPS_RUNNER_GATEWAY_ORIGIN=https://" + runnerAddress,
		"MATRIX_DEVOPS_RUNNER_GATEWAY_SERVER_NAME=" + executionProcessGatewayName,
		"MATRIX_DEVOPS_RUNNER_CLIENT_IDENTITY=" + executionProcessRunnerIdentity,
		"MATRIX_DEVOPS_RUNNER_NAMESPACE=" + executionProcessRunnerNamespace,
		"CREDENTIALS_DIRECTORY=" + credentialRoot,
	}

	docker := newExecutionProcessDockerClient(t, dockerSocket)
	children := make([]*executionProcessChild, 0, 5)
	t.Cleanup(func() {
		for index := len(children) - 1; index >= 0; index-- {
			children[index].stop()
		}
		docker.removeExecutionProcessContainers(t)
		assertExecutionProcessOutputSafe(
			t,
			children,
			apiPassword,
			reporterPassword,
			fetcherPassword,
			observerPassword,
			workerPassword,
			string(pki.serverKey),
			string(pki.adminKey),
			string(pki.runnerKey),
		)
	})
	start := func(binary string, environment []string) *executionProcessChild {
		child := startExecutionProcess(t, binary, environment)
		children = append(children, child)
		return child
	}

	gateway := start(binaries.gateway, gatewayEnvironment)
	waitExecutionProcessHTTPStatus(
		t, ctx, gateway, "http://"+gatewayReadinessAddress+"/ready", http.StatusOK,
	)
	waitExecutionProcessTCP(t, ctx, gateway, adminAddress)
	waitExecutionProcessTCP(t, ctx, gateway, runnerAddress)

	firstWorker := start(binaries.buildWorker, workerEnvironment)
	waitExecutionProcessHTTPStatus(
		t, ctx, firstWorker, "http://"+workerReadinessAddress+"/ready", http.StatusOK,
	)
	executionID, firstWorkerFence := waitExecutionProcessSubmission(
		t, ctx, admin, spoolRoot, run.ID, firstWorker,
	)
	firstWorker.crash(t)
	expireExecutionProcessBuildLease(t, ctx, admin, run.ID, firstWorkerFence)

	secondWorker := start(binaries.buildWorker, workerEnvironment)
	waitExecutionProcessHTTPStatus(
		t, ctx, secondWorker, "http://"+workerReadinessAddress+"/ready", http.StatusOK,
	)
	waitExecutionProcessBuildFence(
		t, ctx, admin, run.ID, firstWorkerFence+1, secondWorker,
	)

	firstRunner := start(binaries.runner, runnerEnvironment)
	containerID := waitExecutionProcessContainerRunning(t, ctx, docker, firstRunner)
	firstRunner.crash(t)
	containers := docker.gateContainers(t)
	if len(containers) != 1 || containers[0].ID != containerID {
		t.Fatalf("runner crash did not retain the exact sandbox effect: %#v", containers)
	}

	secondRunner := start(binaries.runner, runnerEnvironment)
	completed := waitExecutionProcessRunReporting(
		t, ctx, runController, run.ID, gateway, secondWorker, secondRunner,
	)
	waitExecutionProcessHTTPStatus(
		t, ctx, secondRunner, "http://"+runnerReadinessAddress+"/ready", http.StatusOK,
	)
	if completed.Status.Reason != "" || completed.Status.CompletedAt != nil ||
		completed.Status.Stage != devopsv1.PipelineRunStageReport {
		t.Fatalf("recovered execution run=%#v", completed)
	}
	if residual := docker.gateContainers(t); len(residual) != 0 {
		t.Fatalf("recovered runner left containers: %#v", residual)
	}

	secondRunner.stop()
	if residual := docker.probeContainers(t); len(residual) != 0 {
		t.Fatalf("stopped runner left isolation probes: %#v", residual)
	}
	secondWorker.stop()
	gateway.stop()
	assertExecutionProcessEvidence(
		t, ctx, admin, runController, spoolRoot, journalRoot,
		executionID, run.ID, firstWorkerFence,
	)
}

type executionProcessBinaries struct {
	gateway     string
	buildWorker string
	runner      string
}

func requiredExecutionProcessBinary(t *testing.T, environment string) string {
	t.Helper()
	value := os.Getenv(environment)
	info, err := os.Stat(value)
	if err != nil || value == "" || !filepath.IsAbs(value) || filepath.Clean(value) != value ||
		!info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		t.Fatalf("%s must name one absolute executable regular file", environment)
	}
	return value
}

func requiredExecutionProcessSocket(t *testing.T) string {
	t.Helper()
	value := os.Getenv(executionProcessDockerSocketEnvironment)
	info, err := os.Lstat(value)
	if err != nil || value == "" || !filepath.IsAbs(value) || filepath.Clean(value) != value ||
		info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("%s must name one absolute Unix socket", executionProcessDockerSocketEnvironment)
	}
	return value
}

func assertCleanExecutionProcessDatabase(t *testing.T, ctx context.Context, admin *pgx.Conn) {
	t.Helper()
	var clean bool
	err := admin.QueryRow(ctx, `SELECT to_regnamespace('delivery') IS NULL AND NOT EXISTS (
		SELECT 1 FROM pg_catalog.pg_roles WHERE rolname IN (
			'matrix_devops_api_login', 'matrix_devops_check_reporter_login',
			'matrix_devops_worker_login', 'matrix_devops_source_fetcher_login',
			'matrix_devops_source_observer_login'
		)
	)`).Scan(&clean)
	if err != nil || !clean {
		t.Fatal("DevOps execution process database is not clean")
	}
}

func openExecutionProcessPool(t *testing.T, ctx context.Context, dsn string) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Fatal(err)
	}
	return pool
}

func seedExecutionProcessRun(
	t *testing.T,
	ctx context.Context,
	configuration *pipelineconfiguration.Usecase,
	controlRepository *devopspostgres.ControlPlaneRepository,
	observerPool *pgxpool.Pool,
	fetcherPool *pgxpool.Pool,
	archiveRoot string,
) devopsv1.PipelineRun {
	t.Helper()
	projectID := devopsv1.ResourceID("project-process-gate")
	connectionID := devopsv1.ResourceID("connection-process-gate")
	bindingID := devopsv1.ResourceID("binding-process-gate")
	pipelineID := devopsv1.ResourceID("pipeline-process-gate")
	if _, err := configuration.CreateProject(ctx, pipelineconfiguration.CreateProjectCommand{
		Authorization: auth(iamv1.ActionDevOpsProjectCreate, iamv1.ResourceDevOpsProject, projectID),
		Request: devopsv1.CreateDevOpsProjectRequest{
			ID: projectID, Name: "process-gate-project",
		},
		IdempotencyKey: "create-project-process-gate",
	}); err != nil {
		t.Fatal(err)
	}
	_, err := configuration.CreateSourceConnection(
		ctx,
		pipelineconfiguration.CreateSourceConnectionCommand{
			Authorization: auth(
				iamv1.ActionDevOpsSourceConnectionCreate,
				iamv1.ResourceSourceConnection,
				connectionID,
			),
			Request: devopsv1.CreateSourceConnectionRequest{
				ID: connectionID, Name: "process-gate-source",
				Spec: devopsv1.SourceConnectionSpec{
					AdapterID:           "source-adapter-gitea-v1",
					EndpointOrigin:      "https://gitea.process.example",
					WebhookSecretRef:    "process-webhook-secret",
					FetchCredentialRef:  "process-fetch-secret",
					ReportCredentialRef: "process-report-secret",
				},
			},
			IdempotencyKey: "create-connection-process-gate",
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	bindingRequest := bindingRequest(bindingID, projectID, connectionID, "matrix/process-gate")
	bindingRequest.Spec.TrustedDefaultBranch = "main"
	if _, err := configuration.CreateRepositoryBinding(
		ctx,
		pipelineconfiguration.CreateRepositoryBindingCommand{
			Authorization: auth(
				iamv1.ActionDevOpsRepositoryBindingCreate,
				iamv1.ResourceRepositoryBinding,
				bindingID,
			),
			Request: bindingRequest, IdempotencyKey: "create-binding-process-gate",
		},
	); err != nil {
		t.Fatal(err)
	}
	pipeline, err := configuration.CreatePipeline(
		ctx,
		pipelineconfiguration.CreatePipelineCommand{
			Authorization: auth(
				iamv1.ActionDevOpsPipelineCreate, iamv1.ResourcePipeline, pipelineID,
			),
			Request: devopsv1.CreatePipelineRequest{
				ID: pipelineID, Name: "process-gate-pipeline", ProjectID: projectID,
				Draft: draft(bindingID),
			},
			IdempotencyKey: "create-pipeline-process-gate",
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := configuration.ActivatePipeline(
		ctx,
		pipelineconfiguration.ActivatePipelineCommand{
			Authorization: auth(
				iamv1.ActionDevOpsPipelineActivate, iamv1.ResourcePipeline, pipelineID,
			),
			PipelineID: pipelineID, ExpectedResourceVersion: pipeline.Value.Metadata.ResourceVersion,
			IdempotencyKey: "activate-pipeline-process-gate",
		},
	); err != nil {
		t.Fatal(err)
	}

	observer, err := devopspostgres.NewSourceObservationRepository(observerPool)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := observer.Heartbeat(ctx, "source-observer-process-gate"); err != nil {
		t.Fatal(err)
	}
	connectionLease, found, err := observer.Claim(
		ctx, "source-observer-process-gate", sourceobservation.LeaseDuration,
	)
	if err != nil || !found || connectionLease.Kind != sourceobservation.WorkSourceConnection {
		t.Fatalf("claim process source connection=%#v found=%t err=%v", connectionLease, found, err)
	}
	observedConnection, err := observer.CompleteSourceConnection(
		ctx,
		connectionLease,
		domain.SourceConnectionHealthObservation{
			Health: devopsv1.SourceConnectionReady,
			Reason: devopsv1.SourceConnectionReasonObserved,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	bindingLease, found, err := observer.Claim(
		ctx, "source-observer-process-gate", sourceobservation.LeaseDuration,
	)
	if err != nil || !found || bindingLease.Kind != sourceobservation.WorkRepositoryBinding ||
		bindingLease.ResourceID != bindingID {
		t.Fatalf("claim process repository binding=%#v found=%t err=%v", bindingLease, found, err)
	}
	if _, err := observer.CompleteRepositoryBinding(
		ctx,
		bindingLease,
		domain.RepositoryBindingHealthObservation{
			Health: devopsv1.RepositoryBindingReady,
			Reason: devopsv1.RepositoryBindingReasonObserved,
		},
	); err != nil {
		t.Fatal(err)
	}

	admission, err := runadmission.NewUsecase(
		controlRepository, runadmission.Config{MaxTransactionAttempts: 5},
	)
	if err != nil {
		t.Fatal(err)
	}
	command := sourceAdmissionCommand(
		connectionID,
		observedConnection.Metadata.ResourceVersion,
		bindingRequest.Spec.ExternalRepositoryID,
		"123e4567-e89b-42d3-a456-000000000701",
	)
	command.Change.TrustedBaseBranch = "main"
	admitted, err := admission.Admit(ctx, command)
	if err != nil || admitted.Replayed || len(admitted.Admission.Runs) != 1 {
		t.Fatalf("admit process execution run=%#v err=%v", admitted, err)
	}

	fetcher, err := devopspostgres.NewSourceAcquisitionRepository(fetcherPool)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fetcher.Heartbeat(ctx, "source-fetcher-process-gate"); err != nil {
		t.Fatal(err)
	}
	fetchCommand, found, err := fetcher.Claim(
		ctx, "source-fetcher-process-gate", sourceacquisition.LeaseDuration,
	)
	if err != nil || !found || fetchCommand.Lease.Run.ID != admitted.Admission.Runs[0].ID {
		t.Fatalf("claim process source fetch=%#v found=%t err=%v", fetchCommand, found, err)
	}
	store, err := sourcearchivefile.New(archiveRoot)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := store.Publish(
		ctx,
		fetchCommand,
		func(destination io.Writer) (sourcearchive.Content, error) {
			return sourcearchive.Write(ctx, destination, executionProcessSourceFiles())
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	ready, err := fetcher.Complete(ctx, sourceacquisition.Completion{
		Command: fetchCommand, State: devopsv1.PipelineRunVerifying, Receipt: &receipt,
	})
	if err != nil || ready.Status.State != devopsv1.PipelineRunVerifying ||
		ready.Status.Stage != devopsv1.PipelineRunStageVerify {
		t.Fatalf("publish process source archive=%#v err=%v", ready, err)
	}
	return ready
}

func executionProcessSourceFiles() []sourcearchive.File {
	return []sourcearchive.File{
		executionProcessSourceFile("calc.go", `package processgate

func Add(left, right int) int { return left + right }
`),
		executionProcessSourceFile("calc_test.go", `package processgate

import (
	"testing"
	"time"
)

func TestRestartBoundary(t *testing.T) {
	time.Sleep(8 * time.Second)
	if Add(19, 23) != 42 {
		t.Fatal("unexpected sum")
	}
}
`),
		executionProcessSourceFile("go.mod", `module example.invalid/matrixprocessgate

go 1.26.0
`),
	}
}

func executionProcessSourceFile(path, content string) sourcearchive.File {
	payload := []byte(content)
	return sourcearchive.File{
		Path: path, Size: int64(len(payload)),
		Open: func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(payload)), nil
		},
	}
}

type executionProcessPKI struct {
	serverCA          []byte
	serverCertificate []byte
	serverKey         []byte
	adminCA           []byte
	adminCertificate  []byte
	adminKey          []byte
	runnerCA          []byte
	runnerCertificate []byte
	runnerKey         []byte
}

func newExecutionProcessPKI(t *testing.T) executionProcessPKI {
	t.Helper()
	now := time.Now()
	serverCA, serverCAKey, serverCAPEM := executionProcessCA(t, "server-ca", 1, now)
	adminCA, adminCAKey, adminCAPEM := executionProcessCA(t, "admin-ca", 2, now)
	runnerCA, runnerCAKey, runnerCAPEM := executionProcessCA(t, "runner-ca", 3, now)
	serverPEM, serverKey := executionProcessLeaf(
		t, serverCA, serverCAKey, 4, now,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		[]string{executionProcessGatewayName}, "",
	)
	adminPEM, adminKey := executionProcessLeaf(
		t, adminCA, adminCAKey, 5, now,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		nil, executionProcessAdminIdentity,
	)
	runnerPEM, runnerKey := executionProcessLeaf(
		t, runnerCA, runnerCAKey, 6, now,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		nil, executionProcessRunnerIdentity,
	)
	return executionProcessPKI{
		serverCA: serverCAPEM, serverCertificate: serverPEM, serverKey: serverKey,
		adminCA: adminCAPEM, adminCertificate: adminPEM, adminKey: adminKey,
		runnerCA: runnerCAPEM, runnerCertificate: runnerPEM, runnerKey: runnerKey,
	}
}

func executionProcessCA(
	t *testing.T,
	name string,
	serial int64,
	now time.Time,
) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	encoded, err := x509.CreateCertificate(
		rand.Reader, template, template, &key.PublicKey, key,
	)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: encoded})
}

func executionProcessLeaf(
	t *testing.T,
	issuer *x509.Certificate,
	issuerKey *ecdsa.PrivateKey,
	serial int64,
	now time.Time,
	usage []x509.ExtKeyUsage,
	dnsNames []string,
	spiffeIdentity string,
) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), NotBefore: now.Add(-time.Hour),
		NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: usage, DNSNames: dnsNames,
	}
	if spiffeIdentity != "" {
		identity, err := url.Parse(spiffeIdentity)
		if err != nil {
			t.Fatal(err)
		}
		template.URIs = []*url.URL{identity}
	}
	encoded, err := x509.CreateCertificate(
		rand.Reader, template, issuer, &key.PublicKey, issuerKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: encoded}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
}

func makeExecutionProcessDirectory(
	t *testing.T,
	parent string,
	name string,
	mode os.FileMode,
) string {
	t.Helper()
	path := filepath.Join(parent, name)
	if err := os.Mkdir(path, mode); err != nil {
		t.Fatal(err)
	}
	chmodExact(t, path, mode)
	return path
}

func chmodExact(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm() != mode.Perm() {
		t.Fatalf("mode for %s=%v err=%v want=%v", path, info.Mode().Perm(), err, mode.Perm())
	}
}

func writeExecutionProcessFile(
	t *testing.T,
	root string,
	name string,
	content []byte,
	mode os.FileMode,
) string {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.WriteFile(path, content, mode); err != nil {
		t.Fatal(err)
	}
	chmodExact(t, path, mode)
	return path
}

func reserveExecutionProcessAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

func reserveDistinctExecutionProcessAddress(t *testing.T, existing ...string) string {
	t.Helper()
	for {
		candidate := reserveExecutionProcessAddress(t)
		distinct := true
		for _, value := range existing {
			if candidate == value {
				distinct = false
				break
			}
		}
		if distinct {
			return candidate
		}
	}
}

type executionProcessChild struct {
	command *exec.Cmd
	done    chan error
	stdout  synchronizedExecutionProcessBuffer
	stderr  synchronizedExecutionProcessBuffer
	mutex   sync.Mutex
	exited  bool
	err     error
}

type synchronizedExecutionProcessBuffer struct {
	mutex sync.Mutex
	bytes.Buffer
}

func (buffer *synchronizedExecutionProcessBuffer) Write(value []byte) (int, error) {
	buffer.mutex.Lock()
	defer buffer.mutex.Unlock()
	return buffer.Buffer.Write(value)
}

func (buffer *synchronizedExecutionProcessBuffer) String() string {
	buffer.mutex.Lock()
	defer buffer.mutex.Unlock()
	return buffer.Buffer.String()
}

func startExecutionProcess(
	t *testing.T,
	binary string,
	environment []string,
) *executionProcessChild {
	t.Helper()
	child := &executionProcessChild{done: make(chan error, 1)}
	child.command = exec.Command(binary)
	child.command.Env = append([]string{"PATH=/usr/bin:/bin"}, environment...)
	child.command.Stdout = &child.stdout
	child.command.Stderr = &child.stderr
	if err := child.command.Start(); err != nil {
		t.Fatalf("start execution process %s: %v", filepath.Base(binary), err)
	}
	go func() { child.done <- child.command.Wait() }()
	return child
}

func (child *executionProcessChild) poll() (bool, error) {
	child.mutex.Lock()
	defer child.mutex.Unlock()
	if child.exited {
		return true, child.err
	}
	select {
	case child.err = <-child.done:
		child.exited = true
		return true, child.err
	default:
		return false, nil
	}
}

func (child *executionProcessChild) wait(timeout time.Duration) error {
	child.mutex.Lock()
	if child.exited {
		err := child.err
		child.mutex.Unlock()
		return err
	}
	child.mutex.Unlock()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case err := <-child.done:
		child.mutex.Lock()
		child.exited = true
		child.err = err
		child.mutex.Unlock()
		return err
	case <-timer.C:
		return fmt.Errorf("execution process wait timed out")
	}
}

func (child *executionProcessChild) crash(t *testing.T) {
	t.Helper()
	if exited, _ := child.poll(); exited {
		t.Fatalf("execution process exited before crash: %s", child.output())
	}
	if err := child.command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := child.wait(10 * time.Second); err == nil {
		t.Fatal("crashed execution process exited successfully")
	}
}

func (child *executionProcessChild) stop() {
	if child == nil {
		return
	}
	if exited, _ := child.poll(); exited {
		return
	}
	if child.command == nil || child.command.Process == nil {
		return
	}
	_ = child.command.Process.Signal(syscall.SIGTERM)
	if err := child.wait(executionProcessStopTimeout); err != nil {
		if exited, _ := child.poll(); !exited {
			_ = child.command.Process.Kill()
			_ = child.wait(5 * time.Second)
		}
	}
}

func (child *executionProcessChild) output() string {
	return child.stdout.String() + child.stderr.String()
}

func waitExecutionProcessHTTPStatus(
	t *testing.T,
	ctx context.Context,
	child *executionProcessChild,
	endpoint string,
	want int,
) {
	t.Helper()
	client := &http.Client{
		Timeout:   2 * time.Second,
		Transport: &http.Transport{Proxy: nil, DisableCompression: true},
	}
	defer client.CloseIdleConnections()
	for {
		if exited, err := child.poll(); exited {
			t.Fatalf("execution process exited before readiness: %v output=%q", err, child.output())
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := client.Do(request)
		if err == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1024))
			_ = response.Body.Close()
			if response.StatusCode == want {
				return
			}
		}
		waitExecutionProcessPoll(t, ctx)
	}
}

func waitExecutionProcessTCP(
	t *testing.T,
	ctx context.Context,
	child *executionProcessChild,
	address string,
) {
	t.Helper()
	for {
		if exited, err := child.poll(); exited {
			t.Fatalf("execution process exited before listener: %v output=%q", err, child.output())
		}
		connection, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", address)
		if err == nil {
			_ = connection.Close()
			return
		}
		waitExecutionProcessPoll(t, ctx)
	}
}

func waitExecutionProcessSubmission(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	spoolRoot string,
	runID devopsv1.ResourceID,
	worker *executionProcessChild,
) (string, uint64) {
	t.Helper()
	for {
		if exited, err := worker.poll(); exited {
			t.Fatalf("build worker exited before submission: %v output=%q", err, worker.output())
		}
		executionID := soleExecutionProcessSpoolID(t, spoolRoot)
		var owner string
		var fence uint64
		err := admin.QueryRow(
			ctx,
			`SELECT lease_owner, fencing_token FROM delivery.pipeline_run_tasks
			  WHERE run_id = $1 AND stage = 'VERIFY' AND status = 'INTENT'`,
			runID,
		).Scan(&owner, &fence)
		if err == nil && executionID != "" && owner == executionProcessWorkerID && fence == 1 {
			return executionID, fence
		}
		waitExecutionProcessPoll(t, ctx)
	}
}

func soleExecutionProcessSpoolID(t *testing.T, root string) string {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	var executionID string
	for _, entry := range entries {
		if !entry.IsDir() || len(entry.Name()) != 64 {
			continue
		}
		if _, err := hex.DecodeString(entry.Name()); err != nil {
			continue
		}
		if _, err := os.Stat(filepath.Join(root, entry.Name(), "submission.json")); err != nil {
			continue
		}
		if executionID != "" {
			t.Fatal("executor spool contains multiple executions")
		}
		executionID = "sha256:" + entry.Name()
	}
	return executionID
}

func expireExecutionProcessBuildLease(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	runID devopsv1.ResourceID,
	fence uint64,
) {
	t.Helper()
	result, err := admin.Exec(
		ctx,
		`UPDATE delivery.pipeline_run_tasks
		    SET lease_expires_at = GREATEST(
		            last_claimed_at + interval '1 microsecond',
		            transaction_timestamp() - interval '1 microsecond'
		        ),
		        updated_at = transaction_timestamp()
		  WHERE run_id = $1 AND stage = 'VERIFY' AND status = 'INTENT'
		    AND lease_owner = $2 AND fencing_token = $3`,
		runID,
		executionProcessWorkerID,
		int64(fence),
	)
	if err != nil || result.RowsAffected() != 1 {
		t.Fatalf("expire build worker process lease rows=%d err=%v", result.RowsAffected(), err)
	}
}

func waitExecutionProcessBuildFence(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	runID devopsv1.ResourceID,
	want uint64,
	worker *executionProcessChild,
) {
	t.Helper()
	for {
		if exited, err := worker.poll(); exited {
			t.Fatalf("recovery build worker exited: %v output=%q", err, worker.output())
		}
		var owner string
		var fence uint64
		err := admin.QueryRow(
			ctx,
			`SELECT lease_owner, fencing_token FROM delivery.pipeline_run_tasks
			  WHERE run_id = $1 AND stage = 'VERIFY' AND status = 'INTENT'`,
			runID,
		).Scan(&owner, &fence)
		if err == nil && owner == executionProcessWorkerID && fence >= want {
			return
		}
		waitExecutionProcessPoll(t, ctx)
	}
}

type executionProcessDockerClient struct {
	client *http.Client
}

type executionProcessContainer struct {
	ID    string `json:"Id"`
	State string `json:"State"`
}

func newExecutionProcessDockerClient(
	t *testing.T,
	socket string,
) *executionProcessDockerClient {
	t.Helper()
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		},
		DisableCompression: true,
	}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	t.Cleanup(client.CloseIdleConnections)
	return &executionProcessDockerClient{client: client}
}

func (docker *executionProcessDockerClient) gateContainers(
	t *testing.T,
) []executionProcessContainer {
	return docker.containersWithLabel(t, "com.xiak.matrix.devops.effect")
}

func (docker *executionProcessDockerClient) probeContainers(
	t *testing.T,
) []executionProcessContainer {
	return docker.containersWithLabel(t, "com.xiak.matrix.devops.probe")
}

func (docker *executionProcessDockerClient) containersWithLabel(
	t *testing.T,
	label string,
) []executionProcessContainer {
	t.Helper()
	filters := url.QueryEscape(`{"label":["` + label + `"]}`)
	request, err := http.NewRequest(
		http.MethodGet,
		"http://matrix-docker/v1.46/containers/json?all=1&filters="+filters,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	response, err := docker.client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("Docker container list status=%d", response.StatusCode)
	}
	var containers []executionProcessContainer
	if err := json.NewDecoder(io.LimitReader(response.Body, 1024*1024)).Decode(&containers); err != nil {
		t.Fatal(err)
	}
	return containers
}

func waitExecutionProcessContainerRunning(
	t *testing.T,
	ctx context.Context,
	docker *executionProcessDockerClient,
	runner *executionProcessChild,
) string {
	t.Helper()
	for {
		if exited, err := runner.poll(); exited {
			t.Fatalf("runner exited before sandbox effect: %v output=%q", err, runner.output())
		}
		containers := docker.gateContainers(t)
		if len(containers) == 1 && containers[0].State == "running" {
			return containers[0].ID
		}
		if len(containers) > 1 {
			t.Fatalf("runner created multiple sandbox effects: %#v", containers)
		}
		waitExecutionProcessPoll(t, ctx)
	}
}

func (docker *executionProcessDockerClient) removeExecutionProcessContainers(t *testing.T) {
	t.Helper()
	containers := append(docker.gateContainers(t), docker.probeContainers(t)...)
	for _, container := range containers {
		request, err := http.NewRequest(
			http.MethodDelete,
			"http://matrix-docker/v1.46/containers/"+url.PathEscape(container.ID)+"?force=1&v=1",
			nil,
		)
		if err != nil {
			t.Errorf("create Docker cleanup request: %v", err)
			continue
		}
		response, err := docker.client.Do(request)
		if err != nil {
			t.Errorf("remove Docker cleanup container: %v", err)
			continue
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1024))
		_ = response.Body.Close()
		if response.StatusCode != http.StatusNoContent && response.StatusCode != http.StatusNotFound {
			t.Errorf("remove Docker cleanup container status=%d", response.StatusCode)
		}
	}
	residual := append(docker.gateContainers(t), docker.probeContainers(t)...)
	if len(residual) != 0 {
		t.Errorf("Docker cleanup left execution process containers: %#v", residual)
	}
}

func waitExecutionProcessRunReporting(
	t *testing.T,
	ctx context.Context,
	controller *runcontrol.Service,
	runID devopsv1.ResourceID,
	children ...*executionProcessChild,
) devopsv1.PipelineRun {
	t.Helper()
	for {
		for _, child := range children {
			if exited, err := child.poll(); exited {
				t.Fatalf("execution process exited before receipt: %v output=%q", err, child.output())
			}
		}
		run, err := controller.Get(ctx, runcontrol.GetQuery{
			Authorization: auth(
				iamv1.ActionDevOpsRunRead, iamv1.ResourcePipelineRun, runID,
			),
			RunID: runID,
		})
		if err != nil {
			t.Fatal(err)
		}
		if run.Status.State == devopsv1.PipelineRunReporting {
			return run
		}
		if run.Status.CompletedAt != nil || run.Status.State == devopsv1.PipelineRunFailed ||
			run.Status.State == devopsv1.PipelineRunCancelled {
			t.Fatalf("execution process run terminated before REPORT: %#v", run)
		}
		waitExecutionProcessPoll(t, ctx)
	}
}

func assertExecutionProcessEvidence(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	controller *runcontrol.Service,
	spoolRoot string,
	journalRoot string,
	executionID string,
	runID devopsv1.ResourceID,
	firstWorkerFence uint64,
) {
	t.Helper()
	var receiptDocument []byte
	if err := admin.QueryRow(
		ctx,
		`SELECT document FROM delivery.build_receipts WHERE run_id = $1`,
		runID,
	).Scan(&receiptDocument); err != nil {
		t.Fatal(err)
	}
	var receipt devopsbuildv1.Receipt
	if err := json.Unmarshal(receiptDocument, &receipt); err != nil {
		t.Fatal(err)
	}
	var receiptCount, reportTaskCount int
	var verifyTaskStatus string
	var workerFence uint64
	if err := admin.QueryRow(
		ctx,
		`SELECT
			(SELECT count(*) FROM delivery.build_receipts WHERE run_id = $1),
			(SELECT count(*) FROM delivery.pipeline_run_tasks
			  WHERE run_id = $1 AND stage = 'REPORT'),
			(SELECT status FROM delivery.pipeline_run_tasks
			  WHERE run_id = $1 AND stage = 'VERIFY'),
			(SELECT fencing_token FROM delivery.pipeline_run_tasks
			  WHERE run_id = $1 AND stage = 'VERIFY')`,
		runID,
	).Scan(&receiptCount, &reportTaskCount, &verifyTaskStatus, &workerFence); err != nil {
		t.Fatal(err)
	}
	if receiptCount != 1 || reportTaskCount != 0 ||
		verifyTaskStatus != "COMPLETED" || workerFence <= firstWorkerFence ||
		receipt.Conclusion != devopsbuildv1.ConclusionPassed ||
		receipt.Steps[0].Conclusion != devopsbuildv1.StepConclusionPassed ||
		receipt.Steps[1].Conclusion != devopsbuildv1.StepConclusionPassed {
		t.Fatalf(
			"execution process persistence receipt=%#v count=%d report=%d verify=%s fence=%d",
			receipt, receiptCount, reportTaskCount, verifyTaskStatus, workerFence,
		)
	}

	spool, err := executorspoolfile.New(spoolRoot)
	if err != nil {
		t.Fatal(err)
	}
	request, err := spool.Request(ctx, executionID)
	if err != nil || devopsbuildv1.ValidateReceipt(request, receipt) != nil {
		t.Fatalf("execution process spool request=%#v receipt=%#v err=%v", request, receipt, err)
	}
	observation, err := spool.Observe(ctx, request)
	if err != nil || observation.State != devopsbuildv1.ExecutionTerminal ||
		observation.Receipt == nil || *observation.Receipt != receipt {
		t.Fatalf("execution process spool observation=%#v err=%v", observation, err)
	}

	runnerID, err := executorgatewayhttp.RunnerID(executionProcessRunnerIdentity)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := runnerjournalfile.New(journalRoot, runnerID)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := journal.Entries(ctx)
	if err != nil || len(entries) != 1 || entries[0].Phase != port.RunnerJournalAcknowledged ||
		entries[0].Assignment.FencingToken < 2 || entries[0].Receipt == nil ||
		*entries[0].Receipt != receipt {
		t.Fatalf("execution process journal=%#v err=%v", entries, err)
	}

	var logs strings.Builder
	after := uint64(0)
	for {
		page, err := controller.Logs(ctx, runcontrol.LogQuery{
			Authorization: auth(
				iamv1.ActionDevOpsLogRead, iamv1.ResourcePipelineRun, runID,
			),
			RunID: runID, AfterSequence: after,
		})
		if err != nil {
			t.Fatal(err)
		}
		for _, chunk := range page.Chunks {
			logs.WriteString(chunk.Content)
		}
		if !page.HasMore {
			break
		}
		if page.NextSequence <= after {
			t.Fatalf("execution process log cursor did not advance: %#v", page)
		}
		after = page.NextSequence
	}
	if !strings.Contains(logs.String(), "example.invalid/matrixprocessgate") ||
		strings.Contains(logs.String(), spoolRoot) || strings.Contains(logs.String(), journalRoot) {
		t.Fatalf("execution process normalized logs are invalid: %q", logs.String())
	}
}

func assertExecutionProcessOutputSafe(
	t *testing.T,
	children []*executionProcessChild,
	sensitive ...string,
) {
	t.Helper()
	for _, child := range children {
		output := child.output()
		for _, value := range sensitive {
			if value != "" && strings.Contains(output, value) {
				t.Errorf("execution process output leaked protected input")
			}
		}
	}
}

func waitExecutionProcessPoll(t *testing.T, ctx context.Context) {
	t.Helper()
	timer := time.NewTimer(25 * time.Millisecond)
	select {
	case <-ctx.Done():
		if !timer.Stop() {
			<-timer.C
		}
		t.Fatal(ctx.Err())
	case <-timer.C:
	}
}
