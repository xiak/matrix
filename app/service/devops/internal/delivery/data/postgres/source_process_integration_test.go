//go:build linux

package postgres_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	devopsbuildv1 "github.com/xiak/matrix/api/adapter/devopsbuild/v1"
	auditv1 "github.com/xiak/matrix/api/audit/v1"
	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	auditmigration "github.com/xiak/matrix/app/service/audit/migration"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/data/executorgatewayhttp"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/data/gitea"
	devopspostgres "github.com/xiak/matrix/app/service/devops/internal/delivery/data/postgres"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/data/sourcearchivefile"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/sourcearchive"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/checkreporting"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/pipelineconfiguration"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/runcontrol"
	devopsmigration "github.com/xiak/matrix/app/service/devops/migration"
	"github.com/xiak/matrix/app/service/devops/sourcecredential"
	"github.com/xiak/matrix/app/service/devops/sourcetrust"
	iammigration "github.com/xiak/matrix/app/service/iam/migration"
)

const (
	sourceProcessDSNEnvironment             = "MATRIX_DEVOPS_SOURCE_PROCESS_TEST_DSN"
	sourceProcessGiteaUpstreamEnvironment   = "MATRIX_DEVOPS_SOURCE_PROCESS_TEST_GITEA_UPSTREAM"
	sourceProcessGiteaEndpointEnvironment   = "MATRIX_DEVOPS_SOURCE_PROCESS_TEST_GITEA_ENDPOINT"
	sourceProcessAPIEnvironment             = "MATRIX_DEVOPS_SOURCE_PROCESS_API_BINARY"
	sourceProcessIAMEnvironment             = "MATRIX_DEVOPS_SOURCE_PROCESS_IAM_BINARY"
	sourceProcessAuditAPIEnvironment        = "MATRIX_DEVOPS_SOURCE_PROCESS_AUDIT_API_BINARY"
	sourceProcessAuditDispatcherEnvironment = "MATRIX_DEVOPS_SOURCE_PROCESS_AUDIT_DISPATCHER_BINARY"
	sourceProcessReporterEnvironment        = "MATRIX_DEVOPS_SOURCE_PROCESS_REPORTER_BINARY"
	sourceProcessObserverEnvironment        = "MATRIX_DEVOPS_SOURCE_PROCESS_OBSERVER_BINARY"
	sourceProcessFetcherEnvironment         = "MATRIX_DEVOPS_SOURCE_PROCESS_FETCHER_BINARY"

	sourceProcessFixtureUsername = "matrixobserver"
	sourceProcessFixturePassword = "MatrixObserver-Test-2026!"
	sourceProcessWebhookSecret   = "source-process-webhook-secret-00000001"
	sourceProcessTenantID        = devopsv1.TenantID("tenant-source-process")
	sourceProcessConnectionID    = devopsv1.ResourceID("connection-source-process")
	sourceProcessBindingID       = devopsv1.ResourceID("binding-source-process")
	sourceProcessPipelineID      = devopsv1.ResourceID("pipeline-source-process")
	sourceProcessDeliveryID      = "123e4567-e89b-42d3-a456-000000000702"
	sourceProcessServiceSecret   = "mx1.SourceProcessDevOpsServiceCredential000000001"
	sourceProcessIAMSecret       = "mx1.SourceProcessIAMCredential00000000000000000001"
	sourceProcessPlatformSecret  = "mx1.SourceProcessPlatformCredential00000000000001"
	sourceProcessPaaSSecret      = "mx1.SourceProcessPaaSCredential00000000000000001"
	sourceProcessAuditSecret     = "mx1.SourceProcessAuditCredential00000000000000001"
	sourceProcessVerifierSecret  = "mx1.SourceProcessVerifierCredential00000000000001"
	sourceProcessAdminPassword   = "Source-Process-Initial-Administrator-Password-73!"
	sourceProcessInstallationID  = "installation-source-process"
)

// TestSignedGiteaChangeRecoversThroughSourceFetcherProcess is the opt-in Gate B
// source subjourney. A real Gitea change crosses the physical DevOps HTTP
// process, backed by the physical IAM authority, and becomes one signed
// admission and one archive. The first source-
// fetcher is killed after publishing that archive but before PostgreSQL can
// acknowledge it; a replacement observes the immutable effect under a larger
// fence without another provider fetch. The same run crosses the physical
// mTLS gateway/build-worker/runsc runner and check-reporter boundaries, with
// crash recovery after both sandbox submission and Gitea status creation.
// Finally, the physical Audit service accepts one event before the first
// dispatcher dies; a replacement replays it idempotently and drains the exact
// immutable facts without another external outcome.
func TestSignedGiteaChangeRecoversThroughSourceFetcherProcess(t *testing.T) {
	adminDSN := os.Getenv(sourceProcessDSNEnvironment)
	if adminDSN == "" {
		t.Skipf("set %s to a clean disposable PostgreSQL 18 database", sourceProcessDSNEnvironment)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	apiBinary := requiredExecutionProcessBinary(t, sourceProcessAPIEnvironment)
	iamBinary := requiredExecutionProcessBinary(t, sourceProcessIAMEnvironment)
	auditAPIBinary := requiredExecutionProcessBinary(t, sourceProcessAuditAPIEnvironment)
	auditDispatcherBinary := requiredExecutionProcessBinary(
		t, sourceProcessAuditDispatcherEnvironment,
	)
	reporterBinary := requiredExecutionProcessBinary(t, sourceProcessReporterEnvironment)
	observerBinary := requiredExecutionProcessBinary(t, sourceProcessObserverEnvironment)
	fetcherBinary := requiredExecutionProcessBinary(t, sourceProcessFetcherEnvironment)
	dockerSocket := requiredExecutionProcessSocket(t)
	executionBinaries := executionProcessBinaries{
		gateway: requiredExecutionProcessBinary(t, executionProcessGatewayEnvironment),
		buildWorker: requiredExecutionProcessBinary(
			t, executionProcessBuildWorkerEnvironment,
		),
		runner: requiredExecutionProcessBinary(t, executionProcessRunnerEnvironment),
	}
	upstream := requireSourceProcessUpstream(t, os.Getenv(sourceProcessGiteaUpstreamEnvironment))
	providerEndpoint := requireSourceProcessEndpoint(
		t, os.Getenv(sourceProcessGiteaEndpointEnvironment),
	)
	adminConfig, err := pgx.ParseConfig(adminDSN)
	if err != nil || !strings.HasPrefix(adminConfig.Database, "matrix_devops_source_process_") {
		t.Fatal("DevOps source process database configuration is unsafe")
	}
	admin, err := pgx.ConnectConfig(ctx, adminConfig)
	if err != nil {
		t.Fatal("connect DevOps source process database")
	}
	defer admin.Close(context.Background())
	assertCleanSourceProcessDatabase(t, ctx, admin)

	apiPassword := "mxp1.source-process-api-000000000000000000000000"
	reporterPassword := "mxp1.source-process-reporter-0000000000000000000"
	fetcherPassword := "mxp1.source-process-fetcher-00000000000000000000"
	observerPassword := "mxp1.source-process-observer-0000000000000000000"
	workerPassword := "mxp1.source-process-worker-000000000000000000000"
	iamAPIPassword := "mxp1.source-process-iam-api-000000000000000000000"
	iamWorkerPassword := "mxp1.source-process-iam-worker-00000000000000000"
	auditRuntimePassword := "mxp1.source-process-audit-runtime-000000000000000"
	apiDSN := runtimeDSN(t, adminDSN, "matrix_devops_api_login", apiPassword)
	reporterDSN := runtimeDSN(t, adminDSN, "matrix_devops_check_reporter_login", reporterPassword)
	fetcherDSN := runtimeDSN(t, adminDSN, "matrix_devops_source_fetcher_login", fetcherPassword)
	observerDSN := runtimeDSN(t, adminDSN, "matrix_devops_source_observer_login", observerPassword)
	workerDSN := runtimeDSN(t, adminDSN, "matrix_devops_worker_login", workerPassword)
	iamAPIDSN := runtimeDSN(t, adminDSN, "matrix_iam_api_login", iamAPIPassword)
	iamWorkerDSN := runtimeDSN(t, adminDSN, "matrix_iam_worker_login", iamWorkerPassword)
	auditRuntimeDSN := runtimeDSN(
		t, adminDSN, "matrix_audit_runtime_login", auditRuntimePassword,
	)
	for attempt := 1; attempt <= 2; attempt++ {
		if err := iammigration.Apply(ctx, adminDSN, iamAPIDSN, iamWorkerDSN); err != nil {
			t.Fatalf("apply source process IAM migration attempt %d: %v", attempt, err)
		}
		if err := auditmigration.Apply(ctx, adminDSN, auditRuntimeDSN); err != nil {
			t.Fatalf("apply source process Audit migration attempt %d: %v", attempt, err)
		}
		if err := devopsmigration.Apply(
			ctx, adminDSN, apiDSN, reporterDSN, fetcherDSN, observerDSN, workerDSN,
		); err != nil {
			t.Fatalf("apply source process migration attempt %d: %v", attempt, err)
		}
	}
	if err := iammigration.VerifyInstalled(ctx, adminDSN, iamAPIDSN, iamWorkerDSN); err != nil {
		t.Fatalf("verify source process IAM migration: %v", err)
	}
	if err := auditmigration.VerifyInstalled(ctx, adminDSN, auditRuntimeDSN); err != nil {
		t.Fatalf("verify source process Audit migration: %v", err)
	}
	if err := devopsmigration.VerifyInstalled(
		ctx, adminDSN, apiDSN, reporterDSN, fetcherDSN, observerDSN, workerDSN,
	); err != nil {
		t.Fatalf("verify source process migration: %v", err)
	}

	temporary := t.TempDir()
	chmodExact(t, temporary, 0o700)
	webhookRoot := makeExecutionProcessDirectory(t, temporary, "source-webhooks", 0o700)
	fetchRoot := makeExecutionProcessDirectory(t, temporary, "source-fetch", 0o700)
	reportRoot := makeExecutionProcessDirectory(t, temporary, "source-report", 0o700)
	archiveRoot := makeExecutionProcessDirectory(t, temporary, "source-archives", 0o700)
	endpoint, provider, providerCalls := newSourceProcessProvider(
		t, upstream, providerEndpoint,
	)
	scope := devopsv1.ResourceScope{TenantID: sourceProcessTenantID}
	trustRoot := makeExecutionProcessDirectory(t, temporary, "source-trust", 0o700)
	trustDirectoryName, err := sourcetrust.DirectoryName(scope, endpoint)
	if err != nil {
		t.Fatalf("derive source process trust directory: %v", err)
	}
	trustDirectory := makeExecutionProcessDirectory(
		t, trustRoot, trustDirectoryName, 0o700,
	)
	trustBundle, err := sourcetrust.Canonicalize(
		pem.EncodeToMemory(&pem.Block{
			Type: "CERTIFICATE", Bytes: provider.Certificate().Raw,
		}),
		time.Now().UTC(),
	)
	if err != nil {
		t.Fatalf("canonicalize source process provider root: %v", err)
	}
	writeExecutionProcessFile(
		t, trustDirectory, sourcetrust.BundleFilename, trustBundle, 0o600,
	)
	clear(trustBundle)
	repository := provisionSourceProcessRepository(t, upstream)
	change := provisionSourceProcessChange(t, upstream, repository)
	fetchCredential := provisionSourceProcessToken(
		t, upstream, "source-process-fetch", []string{"read:repository", "read:user"},
	)
	reportCredential := provisionSourceProcessToken(
		t, upstream, "source-process-report", []string{"write:repository", "read:user"},
	)
	writeSourceProcessCredential(
		t, webhookRoot, sourcecredential.PurposeWebhook, scope,
		"source-process-webhook", sourceProcessWebhookSecret,
	)
	writeSourceProcessCredential(
		t, fetchRoot, sourcecredential.PurposeFetch, scope,
		"source-process-fetch", fetchCredential.value,
	)
	writeSourceProcessCredential(
		t, reportRoot, sourcecredential.PurposeReport, scope,
		"source-process-report", reportCredential.value,
	)

	apiPool := openExecutionProcessPool(t, ctx, apiDSN)
	defer apiPool.Close()
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
	configureSourceProcess(t, ctx, configuration, endpoint, repository)
	runController, err := runcontrol.NewService(
		controlRepository, runcontrol.Config{MaxTransactionAttempts: 5},
	)
	if err != nil {
		t.Fatal(err)
	}

	apiDSNPath := writeExecutionProcessFile(
		t, temporary, "source-api-dsn", []byte(apiDSN), 0o600,
	)
	reporterDSNPath := writeExecutionProcessFile(
		t, temporary, "source-reporter-dsn", []byte(reporterDSN), 0o600,
	)
	workerDSNPath := writeExecutionProcessFile(
		t, temporary, "source-worker-dsn", []byte(workerDSN), 0o600,
	)
	observerDSNPath := writeExecutionProcessFile(
		t, temporary, "source-observer-dsn", []byte(observerDSN), 0o600,
	)
	fetcherDSNPath := writeExecutionProcessFile(
		t, temporary, "source-fetcher-dsn", []byte(fetcherDSN), 0o600,
	)
	devopsServiceCredentialPath := writeExecutionProcessFile(
		t, temporary, "source-api-service-credential",
		[]byte(sourceProcessServiceSecret), 0o600,
	)
	iamDSNPath := writeExecutionProcessFile(
		t, temporary, "source-iam-dsn", []byte(iamAPIDSN), 0o600,
	)
	auditRuntimeDSNPath := writeExecutionProcessFile(
		t, temporary, "source-audit-dsn", []byte(auditRuntimeDSN), 0o600,
	)
	auditServiceCredentialPath := writeExecutionProcessFile(
		t, temporary, "source-audit-service-credential",
		[]byte(sourceProcessAuditSecret), 0o600,
	)
	bootstrapBytes, err := iamv1.EncodeBootstrapDocument(sourceProcessBootstrap(t))
	if err != nil {
		t.Fatalf("encode source process IAM bootstrap: %v", err)
	}
	bootstrapPath := writeExecutionProcessFile(
		t, temporary, "source-iam-bootstrap.json", bootstrapBytes, 0o600,
	)
	clear(bootstrapBytes)
	cursorKeyPath := writeExecutionProcessFile(
		t, temporary, "source-audit-cursor-key",
		[]byte(hex.EncodeToString(bytes.Repeat([]byte{0x73}, 32))), 0o600,
	)

	iamAddress := reserveExecutionProcessAddress(t)
	auditAPIAddress := reserveDistinctExecutionProcessAddress(t, iamAddress)
	observerAddress := reserveDistinctExecutionProcessAddress(t, iamAddress, auditAPIAddress)
	bootstrapReporterAddress := reserveDistinctExecutionProcessAddress(
		t, iamAddress, auditAPIAddress, observerAddress,
	)
	firstFetcherAddress := reserveDistinctExecutionProcessAddress(
		t, iamAddress, auditAPIAddress, observerAddress, bootstrapReporterAddress,
	)
	secondFetcherAddress := reserveDistinctExecutionProcessAddress(
		t, iamAddress, auditAPIAddress, observerAddress, bootstrapReporterAddress,
		firstFetcherAddress,
	)
	apiAddress := reserveDistinctExecutionProcessAddress(
		t, iamAddress, auditAPIAddress, observerAddress, bootstrapReporterAddress,
		firstFetcherAddress, secondFetcherAddress,
	)
	firstRecoveryReporterAddress := reserveDistinctExecutionProcessAddress(
		t, iamAddress, auditAPIAddress, observerAddress, bootstrapReporterAddress, firstFetcherAddress,
		secondFetcherAddress, apiAddress,
	)
	secondRecoveryReporterAddress := reserveDistinctExecutionProcessAddress(
		t, iamAddress, auditAPIAddress, observerAddress, bootstrapReporterAddress, firstFetcherAddress,
		secondFetcherAddress, apiAddress, firstRecoveryReporterAddress,
	)
	firstAuditDispatcherAddress := reserveDistinctExecutionProcessAddress(
		t, iamAddress, auditAPIAddress, observerAddress, bootstrapReporterAddress, firstFetcherAddress,
		secondFetcherAddress, apiAddress, firstRecoveryReporterAddress,
		secondRecoveryReporterAddress,
	)
	secondAuditDispatcherAddress := reserveDistinctExecutionProcessAddress(
		t, iamAddress, auditAPIAddress, observerAddress, bootstrapReporterAddress, firstFetcherAddress,
		secondFetcherAddress, apiAddress, firstRecoveryReporterAddress,
		secondRecoveryReporterAddress, firstAuditDispatcherAddress,
	)
	iamEndpoint := "http://" + iamAddress
	auditEndpoint := "http://" + auditAPIAddress
	auditProxy := newSourceProcessAuditProxy(t, auditEndpoint)
	children := make([]*executionProcessChild, 0, 10)
	t.Cleanup(func() {
		for index := len(children) - 1; index >= 0; index-- {
			children[index].stop()
		}
		assertSourceProcessOutputSafe(t, children, []string{
			sourceProcessWebhookSecret, fetchCredential.value, reportCredential.value,
			sourceProcessServiceSecret, sourceProcessIAMSecret, sourceProcessPlatformSecret,
			sourceProcessPaaSSecret, sourceProcessAuditSecret, sourceProcessVerifierSecret,
			sourceProcessAdminPassword, apiPassword, reporterPassword, fetcherPassword,
			observerPassword, workerPassword, iamAPIPassword, iamWorkerPassword,
			auditRuntimePassword, temporary,
		})
	})
	start := func(binary string, environment []string) *executionProcessChild {
		child := startExecutionProcess(t, binary, environment)
		children = append(children, child)
		return child
	}
	iamProcess := start(iamBinary, []string{
		"MATRIX_IAM_DATABASE_DSN_FILE=" + iamDSNPath,
		"MATRIX_IAM_BOOTSTRAP_FILE=" + bootstrapPath,
		"MATRIX_IAM_LISTEN_ADDRESS=" + iamAddress,
	})
	waitExecutionProcessHTTPStatus(t, ctx, iamProcess, iamEndpoint+"/ready", http.StatusOK)
	enrollSourceProcessDevOpsService(
		t, ctx, adminDSN, iamAPIDSN, iamWorkerDSN,
	)
	assertSourceProcessDevOpsIdentity(t, ctx, iamEndpoint, sourceProcessServiceSecret)
	auditProcess := start(auditAPIBinary, []string{
		"MATRIX_AUDIT_DATABASE_DSN_FILE=" + auditRuntimeDSNPath,
		"MATRIX_AUDIT_IAM_ENDPOINT=" + iamEndpoint,
		"MATRIX_AUDIT_SERVICE_CREDENTIAL_FILE=" + auditServiceCredentialPath,
		"MATRIX_AUDIT_CURSOR_KEY_FILE=" + cursorKeyPath,
		"MATRIX_AUDIT_LISTEN_ADDRESS=" + auditAPIAddress,
	})
	waitExecutionProcessHTTPStatus(
		t, ctx, auditProcess, auditEndpoint+"/ready", http.StatusOK,
	)
	observerEnvironment := []string{
		"MATRIX_DEVOPS_SOURCE_OBSERVER_DATABASE_DSN_FILE=" + observerDSNPath,
		"MATRIX_DEVOPS_SOURCE_OBSERVER_WEBHOOK_ROOT=" + webhookRoot,
		"MATRIX_DEVOPS_SOURCE_OBSERVER_FETCH_ROOT=" + fetchRoot,
		"MATRIX_DEVOPS_SOURCE_OBSERVER_REPORT_ROOT=" + reportRoot,
		"MATRIX_DEVOPS_SOURCE_OBSERVER_TRUST_ROOT=" + trustRoot,
		"MATRIX_DEVOPS_SOURCE_OBSERVER_WORKER_ID=source-observer-process",
		"MATRIX_DEVOPS_SOURCE_OBSERVER_LISTEN_ADDRESS=" + observerAddress,
	}
	observer := start(observerBinary, observerEnvironment)
	waitExecutionProcessHTTPStatus(
		t, ctx, observer, "http://"+observerAddress+"/ready", http.StatusOK,
	)
	waitSourceProcessConfigurationReady(t, ctx, configuration, observer)

	bootstrapReporter := start(reporterBinary, sourceProcessReporterEnvironmentValues(
		reporterDSNPath, reportRoot, trustRoot,
		"source-reporter-process-bootstrap", bootstrapReporterAddress,
	))
	waitExecutionProcessHTTPStatus(
		t, ctx, bootstrapReporter,
		"http://"+bootstrapReporterAddress+"/ready", http.StatusOK,
	)
	firstFetcherEnvironment := sourceProcessFetcherEnvironmentValues(
		fetcherDSNPath, fetchRoot, archiveRoot, trustRoot,
		"source-fetcher-process-first", firstFetcherAddress,
	)
	assertSourceProcessFetcherEnvironment(
		t, firstFetcherEnvironment, webhookRoot, reportRoot,
		sourceProcessWebhookSecret, fetchCredential.value, reportCredential.value,
		"SSL_CERT_FILE=",
	)
	firstFetcher := start(fetcherBinary, firstFetcherEnvironment)
	waitExecutionProcessHTTPStatus(
		t, ctx, firstFetcher, "http://"+firstFetcherAddress+"/ready", http.StatusOK,
	)
	api := start(apiBinary, []string{
		"MATRIX_DEVOPS_DATABASE_DSN_FILE=" + apiDSNPath,
		"MATRIX_DEVOPS_IAM_ENDPOINT=" + iamEndpoint,
		"MATRIX_DEVOPS_SERVICE_CREDENTIAL_FILE=" + devopsServiceCredentialPath,
		"MATRIX_DEVOPS_WEBHOOK_SECRET_ROOT=" + webhookRoot,
		"MATRIX_DEVOPS_LISTEN_ADDRESS=" + apiAddress,
	})
	apiEndpoint := "http://" + apiAddress
	waitExecutionProcessHTTPStatus(t, ctx, api, apiEndpoint+"/ready", http.StatusOK)

	body := sourceProcessWebhookBody(t, endpoint, repository, change)
	webhookEndpoint := apiEndpoint + "/v1/source-ingress/" + string(sourceProcessTenantID) +
		"/" + string(sourceProcessConnectionID)
	postSourceProcessWebhook(
		t, ctx, webhookEndpoint, body, strings.Repeat("0", sha256.Size*2),
		http.StatusUnauthorized,
	)

	lock, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	lockOpen := true
	t.Cleanup(func() {
		if lockOpen {
			_ = lock.Rollback(context.Background())
		}
	})
	if _, err := lock.Exec(ctx, "LOCK TABLE delivery.source_archives IN ACCESS EXCLUSIVE MODE"); err != nil {
		t.Fatal(err)
	}
	correlationID := postSourceProcessWebhook(
		t, ctx, webhookEndpoint, body,
		sourceProcessSignature(body, sourceProcessWebhookSecret), http.StatusNoContent,
	)
	postSourceProcessWebhook(
		t, ctx, webhookEndpoint, body,
		sourceProcessSignature(body, sourceProcessWebhookSecret), http.StatusNoContent,
	)
	changedBody := append(append([]byte(nil), body...), '\n')
	postSourceProcessWebhook(
		t, ctx, webhookEndpoint, changedBody,
		sourceProcessSignature(changedBody, sourceProcessWebhookSecret), http.StatusConflict,
	)
	run := readSourceProcessRun(t, ctx, admin)
	waitSourceProcessArchive(t, ctx, archiveRoot, firstFetcher)
	if providerCalls.uploadPacks.Load() != 1 {
		t.Fatalf(
			"source process provider upload-pack requests=%d want=1",
			providerCalls.uploadPacks.Load(),
		)
	}
	firstFetcher.crash(t)
	if err := lock.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	lockOpen = false
	assertSourceProcessUnacknowledged(t, ctx, admin, run.ID)
	expireSourceProcessLease(t, ctx, admin, run.ID)

	secondFetcherEnvironment := sourceProcessFetcherEnvironmentValues(
		fetcherDSNPath, fetchRoot, archiveRoot, trustRoot,
		"source-fetcher-process-second", secondFetcherAddress,
	)
	secondFetcher := start(fetcherBinary, secondFetcherEnvironment)
	waitExecutionProcessHTTPStatus(
		t, ctx, secondFetcher, "http://"+secondFetcherAddress+"/ready", http.StatusOK,
	)
	completed := waitSourceProcessVerifying(
		t, ctx, runController, run.ID, secondFetcher,
	)
	if completed.Input != run.Input || completed.InputDigest != run.InputDigest ||
		completed.Status.Stage != devopsv1.PipelineRunStageVerify ||
		completed.Status.State != devopsv1.PipelineRunVerifying {
		t.Fatalf("source process completed run=%#v", completed)
	}
	secondFetcher.stop()
	observer.stop()
	bootstrapReporter.stop()
	reporting := recoverExecutionProcessRun(
		t, ctx, admin, executionBinaries, dockerSocket, workerDSN, archiveRoot,
		temporary, runController, completed,
		[]string{
			sourceProcessWebhookSecret, fetchCredential.value, reportCredential.value,
			sourceProcessServiceSecret, sourceProcessAuditSecret, workerPassword,
		},
	)
	if reporting.Input != run.Input || reporting.InputDigest != run.InputDigest ||
		reporting.Status.Stage != devopsv1.PipelineRunStageReport ||
		reporting.Status.State != devopsv1.PipelineRunReporting {
		t.Fatalf("source process reporting run=%#v", reporting)
	}
	reportLock, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	reportLockOpen := true
	t.Cleanup(func() {
		if reportLockOpen {
			_ = reportLock.Rollback(context.Background())
		}
	})
	if _, err := reportLock.Exec(
		ctx, "LOCK TABLE delivery.check_receipts IN SHARE MODE",
	); err != nil {
		t.Fatal(err)
	}
	firstRecoveryReporter := start(
		reporterBinary,
		sourceProcessReporterEnvironmentValues(
			reporterDSNPath, reportRoot, trustRoot,
			"source-reporter-process-first", firstRecoveryReporterAddress,
		),
	)
	waitExecutionProcessHTTPStatus(
		t, ctx, firstRecoveryReporter,
		"http://"+firstRecoveryReporterAddress+"/ready", http.StatusOK,
	)
	waitSourceProcessProviderStatusCreate(t, ctx, firstRecoveryReporter, providerCalls)
	firstRecoveryReporter.crash(t)
	if err := reportLock.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	reportLockOpen = false
	assertSourceProcessReportUnacknowledged(t, ctx, admin, run.ID)
	expireSourceProcessReportLease(t, ctx, admin, run.ID)
	secondRecoveryReporter := start(
		reporterBinary,
		sourceProcessReporterEnvironmentValues(
			reporterDSNPath, reportRoot, trustRoot,
			"source-reporter-process-second", secondRecoveryReporterAddress,
		),
	)
	waitExecutionProcessHTTPStatus(
		t, ctx, secondRecoveryReporter,
		"http://"+secondRecoveryReporterAddress+"/ready", http.StatusOK,
	)
	terminal := waitSourceProcessSucceeded(
		t, ctx, runController, run.ID, secondRecoveryReporter,
	)
	providerStatusID := assertSourceProcessProviderStatus(
		t, upstream, repository, change, terminal,
	)
	if providerCalls.statusCreates.Load() != 1 || providerCalls.statusReads.Load() != 1 {
		t.Fatalf(
			"source process provider status creates=%d reads=%d want=1/1",
			providerCalls.statusCreates.Load(), providerCalls.statusReads.Load(),
		)
	}
	expectedAudits := readSourceProcessPendingAudits(t, ctx, admin)
	firstAuditDispatcher := start(auditDispatcherBinary, []string{
		"MATRIX_DEVOPS_AUDIT_DATABASE_DSN_FILE=" + workerDSNPath,
		"MATRIX_DEVOPS_AUDIT_ENDPOINT=" + auditProxy.server.URL,
		"MATRIX_DEVOPS_AUDIT_CREDENTIAL_FILE=" + devopsServiceCredentialPath,
		"MATRIX_DEVOPS_AUDIT_WORKER_ID=source-audit-process-first",
		"MATRIX_DEVOPS_AUDIT_LISTEN_ADDRESS=" + firstAuditDispatcherAddress,
	})
	waitExecutionProcessHTTPStatus(
		t, ctx, firstAuditDispatcher,
		"http://"+firstAuditDispatcherAddress+"/ready", http.StatusOK,
	)
	crashedAuditEvent := waitSourceProcessAuditCommit(
		t, ctx, admin, firstAuditDispatcher, auditProxy, expectedAudits,
	)
	firstAuditDispatcher.crash(t)
	expireSourceProcessAuditLease(t, ctx, admin, crashedAuditEvent)
	secondAuditDispatcher := start(auditDispatcherBinary, []string{
		"MATRIX_DEVOPS_AUDIT_DATABASE_DSN_FILE=" + workerDSNPath,
		"MATRIX_DEVOPS_AUDIT_ENDPOINT=" + auditProxy.server.URL,
		"MATRIX_DEVOPS_AUDIT_CREDENTIAL_FILE=" + devopsServiceCredentialPath,
		"MATRIX_DEVOPS_AUDIT_WORKER_ID=source-audit-process-second",
		"MATRIX_DEVOPS_AUDIT_LISTEN_ADDRESS=" + secondAuditDispatcherAddress,
	})
	waitExecutionProcessHTTPStatus(
		t, ctx, secondAuditDispatcher,
		"http://"+secondAuditDispatcherAddress+"/ready", http.StatusOK,
	)
	deliveredAudits := waitSourceProcessAuditDelivery(
		t, ctx, admin, secondAuditDispatcher, auditProxy, expectedAudits,
		crashedAuditEvent,
	)
	secondAuditDispatcher.stop()
	assertSourceProcessRunAudits(t, deliveredAudits, run, correlationID)
	assertSourceProcessEvidence(
		t, ctx, admin, archiveRoot, run, terminal, repository, correlationID,
		providerCalls.uploadPacks.Load(), providerCalls.statusCreates.Load(),
		providerCalls.statusReads.Load(),
		providerStatusID,
		[]string{
			sourceProcessWebhookSecret, fetchCredential.value, reportCredential.value,
			sourceProcessServiceSecret, sourceProcessIAMSecret,
			sourceProcessPlatformSecret, sourceProcessPaaSSecret,
			sourceProcessAuditSecret, sourceProcessVerifierSecret,
			sourceProcessAdminPassword,
		},
	)
}

type sourceProcessRepository struct {
	ID            int64  `json:"id"`
	FullName      string `json:"full_name"`
	DefaultBranch string `json:"default_branch"`
}

type sourceProcessChange struct {
	Number     uint64
	HeadCommit string
	BaseCommit string
}

type sourceProcessToken struct {
	value string
}

type sourceProcessProviderCalls struct {
	uploadPacks   atomic.Int64
	statusCreates atomic.Int64
	statusReads   atomic.Int64
}

func assertCleanSourceProcessDatabase(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
) {
	t.Helper()
	assertCleanExecutionProcessDatabase(t, ctx, admin)
	var clean bool
	err := admin.QueryRow(ctx, `SELECT
		to_regnamespace('iam') IS NULL
		AND to_regnamespace('audit') IS NULL
		AND NOT EXISTS (
			SELECT 1 FROM pg_catalog.pg_roles WHERE rolname IN (
				'matrix_iam_api_login', 'matrix_iam_worker_login',
				'matrix_audit_runtime_login'
			)
		)`).Scan(&clean)
	if err != nil || !clean {
		t.Fatal("joined source process database is not clean")
	}
}

func sourceProcessSecret(t *testing.T, value string) iamv1.Secret {
	t.Helper()
	secret, err := iamv1.NewSecret(value)
	if err != nil {
		t.Fatal("create source process secret")
	}
	return secret
}

func sourceProcessBootstrap(t *testing.T) iamv1.BootstrapDocument {
	t.Helper()
	service := func(
		purpose iamv1.ServicePurpose,
		principalID iamv1.PrincipalID,
		credential string,
	) iamv1.BootstrapServiceCredential {
		return iamv1.BootstrapServiceCredential{
			Purpose: purpose, PrincipalID: principalID,
			Credential: sourceProcessSecret(t, credential),
		}
	}
	return iamv1.BootstrapDocument{
		APIVersion: iamv1.APIVersion, Kind: "IAMBootstrap",
		InstallationID: sourceProcessInstallationID,
		Organization: iamv1.InitialOrganization{
			ID:          iamv1.OrganizationID(sourceProcessTenantID),
			DisplayName: "Source Process Organization",
		},
		Administrator: iamv1.InitialAdministrator{
			ID: "principal-source-process-admin", LoginName: "source.admin",
			DisplayName: "Source Process Administrator",
			Password:    sourceProcessSecret(t, sourceProcessAdminPassword),
		},
		Services: []iamv1.BootstrapServiceCredential{
			service(iamv1.ServiceIAM, "service-iam", sourceProcessIAMSecret),
			service(iamv1.ServicePlatform, "service-platform", sourceProcessPlatformSecret),
			service(iamv1.ServicePaaS, "service-paas", sourceProcessPaaSSecret),
			service(iamv1.ServiceAudit, "service-audit", sourceProcessAuditSecret),
			service(
				iamv1.ServiceInstallationVerifier,
				"service-verifier",
				sourceProcessVerifierSecret,
			),
		},
	}
}

func enrollSourceProcessDevOpsService(
	t *testing.T,
	ctx context.Context,
	adminDSN string,
	iamAPIDSN string,
	iamWorkerDSN string,
) {
	t.Helper()
	bindings := []iammigration.ReleaseServiceBinding{
		{Purpose: iamv1.ServicePlatform, Credential: sourceProcessSecret(t, sourceProcessPlatformSecret)},
		{Purpose: iamv1.ServiceDevOps, Credential: sourceProcessSecret(t, sourceProcessServiceSecret)},
	}
	for attempt := 1; attempt <= 2; attempt++ {
		if err := iammigration.ApplyForInstallation(
			ctx, adminDSN, iamAPIDSN, iamWorkerDSN,
			sourceProcessInstallationID, bindings,
		); err != nil {
			t.Fatalf("enroll source process DevOps service attempt %d: %v", attempt, err)
		}
	}
	if err := iammigration.VerifyInstalledForInstallation(
		ctx, adminDSN, iamAPIDSN, iamWorkerDSN,
		sourceProcessInstallationID, bindings,
	); err != nil {
		t.Fatalf("verify source process DevOps service: %v", err)
	}
}

func assertSourceProcessDevOpsIdentity(
	t *testing.T,
	ctx context.Context,
	iamEndpoint string,
	credential string,
) {
	t.Helper()
	request, err := http.NewRequestWithContext(
		ctx, http.MethodGet, iamEndpoint+"/v1/service-identity", nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+credential)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	defer transport.CloseIdleConnections()
	response, err := (&http.Client{Transport: transport, Timeout: 5 * time.Second}).Do(request)
	if err != nil {
		t.Fatalf("read physical IAM DevOps identity: %v", err)
	}
	defer response.Body.Close()
	var identity iamv1.ServiceIdentity
	if response.StatusCode != http.StatusOK ||
		!strings.HasPrefix(response.Header.Get("Content-Type"), "application/json") ||
		iamv1.DecodeRequest(response.Body, &identity) != nil ||
		iamv1.ValidateServiceIdentity(identity) != nil ||
		identity.OrganizationID != iamv1.OrganizationID(sourceProcessTenantID) ||
		identity.PrincipalID != "service-devops" || identity.Purpose != iamv1.ServiceDevOps {
		t.Fatalf("physical IAM DevOps identity status=%d identity=%#v", response.StatusCode, identity)
	}
}

func postSourceProcessWebhook(
	t *testing.T,
	ctx context.Context,
	endpoint string,
	body []byte,
	signature string,
	wantStatus int,
) string {
	t.Helper()
	request, err := http.NewRequestWithContext(
		ctx, http.MethodPost, endpoint, bytes.NewReader(body),
	)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Gitea-Event", "pull_request")
	request.Header.Set("X-Gitea-Delivery", sourceProcessDeliveryID)
	request.Header.Set("X-Gitea-Signature", signature)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	result, err := client.Do(request)
	if err != nil {
		t.Fatalf("invoke physical DevOps source ingress: %v", err)
	}
	defer result.Body.Close()
	document, err := io.ReadAll(io.LimitReader(result.Body, 64*1024+1))
	if err != nil || len(document) > 64*1024 {
		t.Fatalf("read physical DevOps source ingress response: %v", err)
	}
	requestID := result.Header.Get("Matrix-Request-ID")
	if devopsv1.ValidateID("requestId", requestID) != nil {
		t.Fatal("physical DevOps source ingress omitted its request identity")
	}
	if result.StatusCode != wantStatus {
		t.Fatalf(
			"physical DevOps source ingress status=%d want=%d body=%s",
			result.StatusCode, wantStatus, document,
		)
	}
	if wantStatus == http.StatusNoContent {
		if len(document) != 0 || result.Header.Get("Content-Type") != "" {
			t.Fatalf("physical DevOps source ingress success envelope is not empty")
		}
		return requestID
	}
	var problem devopsv1.Problem
	if result.Header.Get("Content-Type") != "application/problem+json" ||
		json.Unmarshal(document, &problem) != nil || devopsv1.ValidateProblem(problem) != nil {
		t.Fatalf("physical DevOps source ingress problem=%s", document)
	}
	wantCode := devopsv1.ErrorUnauthenticated
	if wantStatus == http.StatusConflict {
		wantCode = devopsv1.ErrorConflict
	}
	if problem.Code != wantCode || problem.TraceID != requestID {
		t.Fatalf("physical DevOps source ingress problem=%#v", problem)
	}
	return requestID
}

func readSourceProcessRun(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
) devopsv1.PipelineRun {
	t.Helper()
	var document []byte
	var count int
	if err := admin.QueryRow(
		ctx,
		`SELECT document, count(*) OVER ()
		   FROM delivery.pipeline_runs
		  WHERE tenant_id = $1
		  ORDER BY id
		  LIMIT 1`,
		sourceProcessTenantID,
	).Scan(&document, &count); err != nil || count != 1 {
		t.Fatalf("read physical DevOps admitted run count=%d err=%v", count, err)
	}
	var run devopsv1.PipelineRun
	if json.Unmarshal(document, &run) != nil || devopsv1.ValidatePipelineRun(run) != nil {
		t.Fatalf("physical DevOps admitted run=%s", document)
	}
	return run
}

func requireSourceProcessUpstream(t *testing.T, value string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(value)
	if err != nil || parsed == nil {
		t.Fatalf("%s must be one canonical loopback HTTP origin", sourceProcessGiteaUpstreamEnvironment)
	}
	address := net.ParseIP(parsed.Hostname())
	if parsed.Scheme != "http" || parsed.User != nil || parsed.Path != "" ||
		parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Port() == "" ||
		address == nil || !address.IsLoopback() || parsed.String() != value {
		t.Fatalf("%s must be one canonical loopback HTTP origin", sourceProcessGiteaUpstreamEnvironment)
	}
	return parsed
}

func requireSourceProcessEndpoint(t *testing.T, value string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(value)
	if err != nil || parsed == nil {
		t.Fatalf("%s must be one canonical loopback HTTPS origin", sourceProcessGiteaEndpointEnvironment)
	}
	address := net.ParseIP(parsed.Hostname())
	if parsed.Scheme != "https" || parsed.User != nil || parsed.Path != "" ||
		parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Port() == "" ||
		address == nil || !address.IsLoopback() || parsed.String() != value {
		t.Fatalf("%s must be one canonical loopback HTTPS origin", sourceProcessGiteaEndpointEnvironment)
	}
	return parsed
}

func newSourceProcessProvider(
	t *testing.T,
	upstream *url.URL,
	endpoint *url.URL,
) (string, *httptest.Server, *sourceProcessProviderCalls) {
	t.Helper()
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	originalDirector := proxy.Director
	calls := &sourceProcessProviderCalls{}
	proxy.Director = func(request *http.Request) {
		incomingHost := request.Host
		originalDirector(request)
		request.Header.Set("X-Forwarded-Host", incomingHost)
		request.Header.Set("X-Forwarded-Proto", "https")
	}
	handler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		statusCreate := request.Method == http.MethodPost &&
			strings.Contains(request.URL.Path, "/statuses/")
		statusRead := request.Method == http.MethodGet &&
			strings.Contains(request.URL.Path, "/statuses/")
		if request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/git-upload-pack") {
			calls.uploadPacks.Add(1)
		}
		proxy.ServeHTTP(response, request)
		if statusCreate {
			calls.statusCreates.Add(1)
		}
		if statusRead {
			calls.statusReads.Add(1)
		}
	})
	server := httptest.NewUnstartedServer(handler)
	if err := server.Listener.Close(); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", endpoint.Host)
	if err != nil {
		t.Fatalf("listen on source process provider endpoint: %v", err)
	}
	server.Listener = listener
	server.StartTLS()
	t.Cleanup(server.Close)
	if server.URL != endpoint.String() {
		t.Fatalf("source process provider endpoint=%q want=%q", server.URL, endpoint)
	}
	return server.URL, server, calls
}

type sourceProcessAuditProxy struct {
	server         *httptest.Server
	upstream       string
	client         *http.Client
	firstCommitted chan auditv1.EventID
	mutex          sync.Mutex
	blocked        bool
	posts          int
	accepted       int
	duplicates     int
	failure        string
}

type sourceProcessAuditProxySnapshot struct {
	posts      int
	accepted   int
	duplicates int
	failure    string
}

func newSourceProcessAuditProxy(
	t *testing.T,
	upstream string,
) *sourceProcessAuditProxy {
	t.Helper()
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	proxy := &sourceProcessAuditProxy{
		upstream: upstream,
		client: &http.Client{
			Transport: transport,
		},
		firstCommitted: make(chan auditv1.EventID, 1),
	}
	proxy.server = httptest.NewServer(http.HandlerFunc(proxy.serveHTTP))
	t.Cleanup(func() {
		proxy.server.Close()
		transport.CloseIdleConnections()
	})
	return proxy
}

func (proxy *sourceProcessAuditProxy) serveHTTP(
	response http.ResponseWriter,
	request *http.Request,
) {
	target := proxy.upstream + request.URL.RequestURI()
	forward, err := http.NewRequestWithContext(
		request.Context(), request.Method, target, request.Body,
	)
	if err != nil {
		proxy.recordFailure("Audit recovery proxy could not create its upstream request")
		http.Error(response, "unavailable", http.StatusServiceUnavailable)
		return
	}
	forward.Header = request.Header.Clone()
	upstreamResponse, err := proxy.client.Do(forward)
	if err != nil {
		proxy.recordFailure("Audit recovery proxy could not reach the physical Audit service")
		http.Error(response, "unavailable", http.StatusServiceUnavailable)
		return
	}
	defer upstreamResponse.Body.Close()
	document, err := io.ReadAll(io.LimitReader(upstreamResponse.Body, 2*1024*1024+1))
	if err != nil || len(document) > 2*1024*1024 {
		proxy.recordFailure("Audit recovery proxy received an invalid upstream response")
		http.Error(response, "unavailable", http.StatusServiceUnavailable)
		return
	}
	defer clear(document)

	block := false
	var eventID auditv1.EventID
	if request.Method == http.MethodPost && request.URL.Path == "/v1/events" &&
		request.URL.RawQuery == "" {
		var result auditv1.IngestionResult
		if auditv1.DecodeRequest(bytes.NewReader(document), &result) != nil ||
			auditv1.ValidateIngestionResult(result) != nil ||
			result.Record.Source != auditv1.SourceDevOps {
			proxy.recordFailure("physical Audit returned an invalid ingestion receipt")
		} else {
			eventID = result.Record.Event.EventID
			proxy.mutex.Lock()
			proxy.posts++
			switch {
			case upstreamResponse.StatusCode == http.StatusCreated &&
				result.Outcome == auditv1.IngestionAccepted:
				proxy.accepted++
				if !proxy.blocked {
					proxy.blocked = true
					block = true
				}
			case upstreamResponse.StatusCode == http.StatusOK &&
				result.Outcome == auditv1.IngestionDuplicate:
				proxy.duplicates++
			default:
				if proxy.failure == "" {
					proxy.failure = "physical Audit returned an unexpected ingestion outcome"
				}
			}
			proxy.mutex.Unlock()
		}
	}
	if block {
		select {
		case proxy.firstCommitted <- eventID:
		default:
		}
		<-request.Context().Done()
		return
	}
	for name, values := range upstreamResponse.Header {
		for _, value := range values {
			response.Header().Add(name, value)
		}
	}
	response.WriteHeader(upstreamResponse.StatusCode)
	_, _ = response.Write(document)
}

func (proxy *sourceProcessAuditProxy) recordFailure(value string) {
	proxy.mutex.Lock()
	defer proxy.mutex.Unlock()
	if proxy.failure == "" {
		proxy.failure = value
	}
}

func (proxy *sourceProcessAuditProxy) snapshot() sourceProcessAuditProxySnapshot {
	proxy.mutex.Lock()
	defer proxy.mutex.Unlock()
	return sourceProcessAuditProxySnapshot{
		posts: proxy.posts, accepted: proxy.accepted,
		duplicates: proxy.duplicates, failure: proxy.failure,
	}
}

func provisionSourceProcessRepository(
	t *testing.T,
	upstream *url.URL,
) sourceProcessRepository {
	t.Helper()
	var version struct {
		Version string `json:"version"`
	}
	sourceProcessFixtureRequest(
		t, upstream, http.MethodGet, "/api/v1/version", nil, http.StatusOK, &version,
	)
	if version.Version != gitea.SupportedVersion {
		t.Fatalf("source process Gitea version=%q want=%q", version.Version, gitea.SupportedVersion)
	}
	name := "source-process-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	var repository sourceProcessRepository
	sourceProcessFixtureRequest(
		t, upstream, http.MethodPost, "/api/v1/user/repos",
		map[string]any{
			"name": name, "private": true, "auto_init": true, "default_branch": "main",
		},
		http.StatusCreated, &repository,
	)
	if repository.ID < 1 || repository.FullName != sourceProcessFixtureUsername+"/"+name ||
		repository.DefaultBranch != "main" {
		t.Fatalf("source process Gitea repository=%#v", repository)
	}
	t.Cleanup(func() {
		sourceProcessFixtureRequest(
			t, upstream, http.MethodDelete,
			"/api/v1/repos/"+sourceProcessFixtureUsername+"/"+name,
			nil, http.StatusNoContent, nil,
		)
	})
	return repository
}

func provisionSourceProcessChange(
	t *testing.T,
	upstream *url.URL,
	repository sourceProcessRepository,
) sourceProcessChange {
	t.Helper()
	prefix := "/api/v1/repos/" + repository.FullName
	for _, file := range []struct {
		path    string
		content string
	}{
		{
			path: "calc.go",
			content: `package processgate

func Add(left, right int) int { return left + right }
`,
		},
		{
			path: "calc_test.go",
			content: `package processgate

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
`,
		},
		{
			path: "go.mod",
			content: `module example.invalid/matrixprocessgate

go 1.26.0
`,
		},
	} {
		sourceProcessFixtureRequest(
			t, upstream, http.MethodPost, prefix+"/contents/"+file.path,
			map[string]any{
				"branch":  "main",
				"content": base64.StdEncoding.EncodeToString([]byte(file.content)),
				"message": "add " + file.path + " fixture",
			},
			http.StatusCreated, nil,
		)
	}
	var base struct {
		Commit struct {
			ID string `json:"id"`
		} `json:"commit"`
	}
	sourceProcessFixtureRequest(
		t, upstream, http.MethodGet, prefix+"/branches/main", nil, http.StatusOK, &base,
	)
	if !sourceProcessSHA1(base.Commit.ID) {
		t.Fatal("source process base commit is invalid")
	}
	sourceProcessFixtureRequest(
		t, upstream, http.MethodPost, prefix+"/contents/source.txt",
		map[string]any{
			"branch": "main", "new_branch": "feature/source-process",
			"content": base64.StdEncoding.EncodeToString([]byte("source process recovery\n")),
			"message": "add source process fixture",
		},
		http.StatusCreated, nil,
	)
	var pull struct {
		Number int64 `json:"number"`
		Head   struct {
			SHA string `json:"sha"`
		} `json:"head"`
		Base struct {
			SHA string `json:"sha"`
		} `json:"base"`
	}
	sourceProcessFixtureRequest(
		t, upstream, http.MethodPost, prefix+"/pulls",
		map[string]any{
			"base": "main", "head": "feature/source-process", "title": "source process fixture",
		},
		http.StatusCreated, &pull,
	)
	if pull.Number < 1 || uint64(pull.Number) > devopsv1.MaximumContractInteger ||
		!sourceProcessSHA1(pull.Head.SHA) || pull.Base.SHA != base.Commit.ID {
		t.Fatalf("source process Gitea pull=%#v", pull)
	}
	return sourceProcessChange{
		Number: uint64(pull.Number), HeadCommit: pull.Head.SHA, BaseCommit: pull.Base.SHA,
	}
}

func provisionSourceProcessToken(
	t *testing.T,
	upstream *url.URL,
	prefix string,
	scopes []string,
) sourceProcessToken {
	t.Helper()
	name := prefix + "-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	var document struct {
		Name string `json:"name"`
		SHA1 string `json:"sha1"`
	}
	sourceProcessFixtureRequest(
		t, upstream, http.MethodPost,
		"/api/v1/users/"+sourceProcessFixtureUsername+"/tokens",
		map[string]any{"name": name, "scopes": scopes}, http.StatusCreated, &document,
	)
	if document.Name != name || len(document.SHA1) < 32 || len(document.SHA1) > 256 {
		t.Fatal("source process Gitea token response is invalid")
	}
	t.Cleanup(func() {
		sourceProcessFixtureRequest(
			t, upstream, http.MethodDelete,
			"/api/v1/users/"+sourceProcessFixtureUsername+"/tokens/"+url.PathEscape(name),
			nil, http.StatusNoContent, nil,
		)
	})
	return sourceProcessToken{value: document.SHA1}
}

func sourceProcessFixtureRequest(
	t *testing.T,
	upstream *url.URL,
	method string,
	requestPath string,
	body any,
	wantStatus int,
	target any,
) {
	t.Helper()
	var content []byte
	var err error
	if body != nil {
		content, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	defer clear(content)
	request, err := http.NewRequest(
		method, strings.TrimSuffix(upstream.String(), "/")+requestPath, bytes.NewReader(content),
	)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set(
		"Authorization", "Basic "+base64.StdEncoding.EncodeToString(
			[]byte(sourceProcessFixtureUsername+":"+sourceProcessFixturePassword),
		),
	)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := (&http.Client{Timeout: 5 * time.Second}).Do(request)
	if err != nil {
		t.Fatalf("call source process Gitea fixture: %v", err)
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, 64*1024+1))
	if err != nil || len(responseBody) > 64*1024 || response.StatusCode != wantStatus {
		clear(responseBody)
		t.Fatalf("source process Gitea fixture status=%d want=%d", response.StatusCode, wantStatus)
	}
	defer clear(responseBody)
	if target != nil && json.Unmarshal(responseBody, target) != nil {
		t.Fatal("decode source process Gitea fixture response")
	}
}

func sourceProcessSHA1(value string) bool {
	if len(value) != 40 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && strings.ToLower(value) == value
}

func writeSourceProcessCredential(
	t *testing.T,
	root string,
	purpose sourcecredential.Purpose,
	scope devopsv1.ResourceScope,
	reference devopsv1.ResourceID,
	value string,
) {
	t.Helper()
	directoryName, err := sourcecredential.DirectoryName(purpose, scope, reference)
	if err != nil {
		t.Fatal(err)
	}
	directory := makeExecutionProcessDirectory(t, root, directoryName, 0o700)
	material, err := sourcecredential.NewMaterial(purpose, []byte(value), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer material.Clear()
	content, err := sourcecredential.Encode(purpose, material)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(content)
	writeExecutionProcessFile(
		t, directory, sourcecredential.MaterialFilename, content, 0o600,
	)
}

func configureSourceProcess(
	t *testing.T,
	ctx context.Context,
	configuration *pipelineconfiguration.Usecase,
	endpoint string,
	repository sourceProcessRepository,
) {
	t.Helper()
	projectID := devopsv1.ResourceID("project-source-process")
	if _, err := configuration.CreateProject(ctx, pipelineconfiguration.CreateProjectCommand{
		Authorization: authForTenant(
			sourceProcessTenantID, iamv1.ActionDevOpsProjectCreate,
			iamv1.ResourceDevOpsProject, projectID,
		),
		Request:        devopsv1.CreateDevOpsProjectRequest{ID: projectID, Name: "source-process"},
		IdempotencyKey: "create-project-source-process",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := configuration.CreateSourceConnection(
		ctx,
		pipelineconfiguration.CreateSourceConnectionCommand{
			Authorization: authForTenant(
				sourceProcessTenantID, iamv1.ActionDevOpsSourceConnectionCreate,
				iamv1.ResourceSourceConnection, sourceProcessConnectionID,
			),
			Request: devopsv1.CreateSourceConnectionRequest{
				ID: sourceProcessConnectionID, Name: "source-process",
				Spec: devopsv1.SourceConnectionSpec{
					AdapterID: gitea.AdapterID, EndpointOrigin: endpoint,
					WebhookSecretRef:    "source-process-webhook",
					FetchCredentialRef:  "source-process-fetch",
					ReportCredentialRef: "source-process-report",
				},
			},
			IdempotencyKey: "create-connection-source-process",
		},
	); err != nil {
		t.Fatal(err)
	}
	binding := devopsv1.CreateRepositoryBindingRequest{
		ID: sourceProcessBindingID, Name: "source-process",
		ProjectID: projectID,
		Spec: devopsv1.RepositoryBindingSpec{
			SourceConnectionID:   sourceProcessConnectionID,
			ExternalRepositoryID: devopsv1.ResourceID(strconv.FormatInt(repository.ID, 10)),
			RepositoryPath:       repository.FullName, TrustedDefaultBranch: repository.DefaultBranch,
		},
	}
	if _, err := configuration.CreateRepositoryBinding(
		ctx,
		pipelineconfiguration.CreateRepositoryBindingCommand{
			Authorization: authForTenant(
				sourceProcessTenantID, iamv1.ActionDevOpsRepositoryBindingCreate,
				iamv1.ResourceRepositoryBinding, sourceProcessBindingID,
			),
			Request: binding, IdempotencyKey: "create-binding-source-process",
		},
	); err != nil {
		t.Fatal(err)
	}
	pipeline, err := configuration.CreatePipeline(
		ctx,
		pipelineconfiguration.CreatePipelineCommand{
			Authorization: authForTenant(
				sourceProcessTenantID, iamv1.ActionDevOpsPipelineCreate,
				iamv1.ResourcePipeline, sourceProcessPipelineID,
			),
			Request: devopsv1.CreatePipelineRequest{
				ID: sourceProcessPipelineID, Name: "source-process", ProjectID: projectID,
				Draft: draft(sourceProcessBindingID),
			},
			IdempotencyKey: "create-pipeline-source-process",
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := configuration.ActivatePipeline(
		ctx,
		pipelineconfiguration.ActivatePipelineCommand{
			Authorization: authForTenant(
				sourceProcessTenantID, iamv1.ActionDevOpsPipelineActivate,
				iamv1.ResourcePipeline, sourceProcessPipelineID,
			),
			PipelineID:              sourceProcessPipelineID,
			ExpectedResourceVersion: pipeline.Value.Metadata.ResourceVersion,
			IdempotencyKey:          "activate-pipeline-source-process",
		},
	); err != nil {
		t.Fatal(err)
	}
}

func waitSourceProcessConfigurationReady(
	t *testing.T,
	ctx context.Context,
	configuration *pipelineconfiguration.Usecase,
	observer *executionProcessChild,
) {
	t.Helper()
	for {
		if exited, err := observer.poll(); exited {
			t.Fatalf("source observer exited before readiness: %v output=%q", err, observer.output())
		}
		connection, connectionErr := configuration.GetSourceConnection(
			ctx,
			pipelineconfiguration.GetSourceConnectionQuery{
				Authorization: authForTenant(
					sourceProcessTenantID, iamv1.ActionDevOpsSourceConnectionRead,
					iamv1.ResourceSourceConnection, sourceProcessConnectionID,
				),
				SourceConnectionID: sourceProcessConnectionID,
			},
		)
		binding, bindingErr := configuration.GetRepositoryBinding(
			ctx,
			pipelineconfiguration.GetRepositoryBindingQuery{
				Authorization: authForTenant(
					sourceProcessTenantID, iamv1.ActionDevOpsRepositoryBindingRead,
					iamv1.ResourceRepositoryBinding, sourceProcessBindingID,
				),
				RepositoryBindingID: sourceProcessBindingID,
			},
		)
		if connectionErr == nil && bindingErr == nil &&
			connection.Status.Health == devopsv1.SourceConnectionReady &&
			connection.Status.Reason == devopsv1.SourceConnectionReasonObserved &&
			binding.Status.Health == devopsv1.RepositoryBindingReady &&
			binding.Status.Reason == devopsv1.RepositoryBindingReasonObserved {
			return
		}
		waitExecutionProcessPoll(t, ctx)
	}
}

func sourceProcessWebhookBody(
	t *testing.T,
	endpoint string,
	repository sourceProcessRepository,
	change sourceProcessChange,
) []byte {
	t.Helper()
	repositoryDocument := map[string]any{
		"id": repository.ID, "full_name": repository.FullName,
		"url":                endpoint + "/api/v1/repos/" + repository.FullName,
		"html_url":           endpoint + "/" + repository.FullName,
		"clone_url":          endpoint + "/" + repository.FullName + ".git",
		"object_format_name": "sha1",
	}
	document := map[string]any{
		"action": "opened", "number": change.Number,
		"repository": repositoryDocument,
		"pull_request": map[string]any{
			"number": change.Number,
			"base": map[string]any{
				"ref": repository.DefaultBranch, "sha": change.BaseCommit,
				"repo_id": repository.ID, "repo": repositoryDocument,
			},
			"head": map[string]any{
				"ref": "feature/source-process", "sha": change.HeadCommit,
				"repo_id": repository.ID,
			},
		},
	}
	body, err := json.Marshal(document)
	if err != nil || len(body) == 0 {
		t.Fatal("encode source process webhook")
	}
	return body
}

func sourceProcessSignature(body []byte, secret string) string {
	digest := hmac.New(sha256.New, []byte(secret))
	_, _ = digest.Write(body)
	return hex.EncodeToString(digest.Sum(nil))
}

func sourceProcessReporterEnvironmentValues(
	dsnPath string,
	reportRoot string,
	trustRoot string,
	workerID string,
	listenAddress string,
) []string {
	return []string{
		"MATRIX_DEVOPS_CHECK_REPORTER_DATABASE_DSN_FILE=" + dsnPath,
		"MATRIX_DEVOPS_CHECK_REPORTER_REPORT_ROOT=" + reportRoot,
		"MATRIX_DEVOPS_CHECK_REPORTER_TRUST_ROOT=" + trustRoot,
		"MATRIX_DEVOPS_CHECK_REPORTER_WORKER_ID=" + workerID,
		"MATRIX_DEVOPS_CHECK_REPORTER_LISTEN_ADDRESS=" + listenAddress,
	}
}

func sourceProcessFetcherEnvironmentValues(
	dsnPath string,
	fetchRoot string,
	archiveRoot string,
	trustRoot string,
	workerID string,
	listenAddress string,
) []string {
	return []string{
		"MATRIX_DEVOPS_SOURCE_FETCHER_DATABASE_DSN_FILE=" + dsnPath,
		"MATRIX_DEVOPS_SOURCE_FETCHER_FETCH_ROOT=" + fetchRoot,
		"MATRIX_DEVOPS_SOURCE_FETCHER_ARCHIVE_ROOT=" + archiveRoot,
		"MATRIX_DEVOPS_SOURCE_FETCHER_TRUST_ROOT=" + trustRoot,
		"MATRIX_DEVOPS_SOURCE_FETCHER_WORKER_ID=" + workerID,
		"MATRIX_DEVOPS_SOURCE_FETCHER_LISTEN_ADDRESS=" + listenAddress,
	}
}

func assertSourceProcessFetcherEnvironment(
	t *testing.T,
	environment []string,
	forbidden ...string,
) {
	t.Helper()
	joined := strings.Join(environment, "\n")
	for _, value := range forbidden {
		if value != "" && strings.Contains(joined, value) {
			t.Fatal("source fetcher process received forbidden authority")
		}
	}
}

func waitSourceProcessArchive(
	t *testing.T,
	ctx context.Context,
	root string,
	fetcher *executionProcessChild,
) {
	t.Helper()
	for {
		if exited, err := fetcher.poll(); exited {
			t.Fatalf("source fetcher exited before archive publication: %v output=%q", err, fetcher.output())
		}
		entries, err := os.ReadDir(root)
		if err != nil {
			t.Fatal(err)
		}
		published := 0
		for _, entry := range entries {
			if entry.IsDir() && !strings.HasPrefix(entry.Name(), ".staging-") {
				published++
			}
		}
		if published == 1 {
			return
		}
		if published > 1 {
			t.Fatalf("source process published %d archives", published)
		}
		waitExecutionProcessPoll(t, ctx)
	}
}

func assertSourceProcessUnacknowledged(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	runID devopsv1.ResourceID,
) {
	t.Helper()
	var status, owner string
	var fence uint64
	var archives int
	err := admin.QueryRow(
		ctx,
		`SELECT task.status, task.lease_owner, task.fencing_token,
		        (SELECT count(*) FROM delivery.source_archives WHERE run_id = $1)
		   FROM delivery.pipeline_run_tasks AS task
		  WHERE task.run_id = $1 AND task.stage = 'FETCH'`,
		runID,
	).Scan(&status, &owner, &fence, &archives)
	if err != nil || status != "INTENT" || owner != "source-fetcher-process-first" ||
		fence != 1 || archives != 0 {
		t.Fatalf(
			"source process pre-recovery status=%q owner=%q fence=%d archives=%d err=%v",
			status, owner, fence, archives, err,
		)
	}
}

func expireSourceProcessLease(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	runID devopsv1.ResourceID,
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
		  WHERE run_id = $1 AND stage = 'FETCH' AND status = 'INTENT'
		    AND fencing_token = 1`,
		runID,
	)
	if err != nil || result.RowsAffected() != 1 {
		t.Fatalf("expire source process lease rows=%d err=%v", result.RowsAffected(), err)
	}
}

func waitSourceProcessVerifying(
	t *testing.T,
	ctx context.Context,
	runs *runcontrol.Service,
	runID devopsv1.ResourceID,
	fetcher *executionProcessChild,
) devopsv1.PipelineRun {
	t.Helper()
	for {
		if exited, err := fetcher.poll(); exited {
			t.Fatalf("replacement source fetcher exited: %v output=%q", err, fetcher.output())
		}
		run, err := runs.Get(ctx, runcontrol.GetQuery{
			Authorization: authForTenant(
				sourceProcessTenantID, iamv1.ActionDevOpsRunRead,
				iamv1.ResourcePipelineRun, runID,
			),
			RunID: runID,
		})
		if err == nil && run.Status.State == devopsv1.PipelineRunVerifying {
			return run
		}
		if err != nil {
			t.Fatalf("read source process run: %v", err)
		}
		if run.Status.State == devopsv1.PipelineRunFailed ||
			run.Status.State == devopsv1.PipelineRunCancelled ||
			run.Status.State == devopsv1.PipelineRunManualIntervention {
			t.Fatalf("source process run terminated before VERIFY: %#v", run)
		}
		waitExecutionProcessPoll(t, ctx)
	}
}

func waitSourceProcessProviderStatusCreate(
	t *testing.T,
	ctx context.Context,
	reporter *executionProcessChild,
	calls *sourceProcessProviderCalls,
) {
	t.Helper()
	for {
		creates := calls.statusCreates.Load()
		if creates == 1 {
			return
		}
		if creates > 1 {
			t.Fatalf("source process provider status creates=%d want=1", creates)
		}
		if exited, err := reporter.poll(); exited {
			t.Fatalf(
				"first check reporter exited before provider status creation: %v output=%q",
				err, reporter.output(),
			)
		}
		waitExecutionProcessPoll(t, ctx)
	}
}

func assertSourceProcessReportUnacknowledged(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	runID devopsv1.ResourceID,
) {
	t.Helper()
	var runState, runStage, taskStatus, owner string
	var fence uint64
	var receipts int
	err := admin.QueryRow(
		ctx,
		`SELECT run.state, run.stage, task.status, task.lease_owner,
		        task.fencing_token,
		        (SELECT count(*) FROM delivery.check_receipts
		          WHERE tenant_id = run.tenant_id AND run_id = run.id)
		   FROM delivery.pipeline_runs AS run
		   JOIN delivery.pipeline_run_tasks AS task
		     ON task.tenant_id = run.tenant_id AND task.run_id = run.id
		  WHERE run.tenant_id = $1 AND run.id = $2 AND task.stage = 'REPORT'`,
		sourceProcessTenantID,
		runID,
	).Scan(&runState, &runStage, &taskStatus, &owner, &fence, &receipts)
	if err != nil || runState != "REPORTING" || runStage != "REPORT" ||
		taskStatus != "INTENT" || owner != "source-reporter-process-first" ||
		fence != 1 || receipts != 0 {
		t.Fatalf(
			"source process unacknowledged report run=%s/%s task=%s/%s/%d receipts=%d err=%v",
			runState, runStage, taskStatus, owner, fence, receipts, err,
		)
	}
}

func expireSourceProcessReportLease(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	runID devopsv1.ResourceID,
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
		  WHERE tenant_id = $1 AND run_id = $2 AND stage = 'REPORT'
		    AND status = 'INTENT' AND fencing_token = 1`,
		sourceProcessTenantID,
		runID,
	)
	if err != nil || result.RowsAffected() != 1 {
		t.Fatalf(
			"expire source process report lease rows=%d err=%v",
			result.RowsAffected(), err,
		)
	}
}

func waitSourceProcessSucceeded(
	t *testing.T,
	ctx context.Context,
	runs *runcontrol.Service,
	runID devopsv1.ResourceID,
	reporter *executionProcessChild,
) devopsv1.PipelineRun {
	t.Helper()
	for {
		if exited, err := reporter.poll(); exited {
			t.Fatalf("check reporter exited before terminal status: %v output=%q", err, reporter.output())
		}
		run, err := runs.Get(ctx, runcontrol.GetQuery{
			Authorization: authForTenant(
				sourceProcessTenantID, iamv1.ActionDevOpsRunRead,
				iamv1.ResourcePipelineRun, runID,
			),
			RunID: runID,
		})
		if err != nil {
			t.Fatalf("read source process terminal run: %v", err)
		}
		if run.Status.State == devopsv1.PipelineRunSucceeded {
			if run.Status.Stage != devopsv1.PipelineRunStageReport ||
				run.Status.Reason != devopsv1.PipelineRunReasonCompleted ||
				run.Status.CompletedAt == nil {
				t.Fatalf("source process terminal run=%#v", run)
			}
			return run
		}
		if run.Status.State == devopsv1.PipelineRunFailed ||
			run.Status.State == devopsv1.PipelineRunCancelled ||
			run.Status.State == devopsv1.PipelineRunManualIntervention {
			t.Fatalf("source process report terminated unexpectedly: %#v", run)
		}
		waitExecutionProcessPoll(t, ctx)
	}
}

type sourceProcessProviderStatus struct {
	ID          int64  `json:"id"`
	Status      string `json:"status"`
	TargetURL   string `json:"target_url"`
	Description string `json:"description"`
	Context     string `json:"context"`
}

func assertSourceProcessProviderStatus(
	t *testing.T,
	upstream *url.URL,
	repository sourceProcessRepository,
	change sourceProcessChange,
	run devopsv1.PipelineRun,
) uint64 {
	t.Helper()
	var statuses []sourceProcessProviderStatus
	sourceProcessFixtureRequest(
		t,
		upstream,
		http.MethodGet,
		"/api/v1/repos/"+repository.FullName+"/statuses/"+change.HeadCommit+
			"?limit=50&page=1&sort=leastindex",
		nil,
		http.StatusOK,
		&statuses,
	)
	wantContext := "matrix/" + string(sourceProcessPipelineID) + "/" + string(run.ID)
	if len(statuses) != 1 || statuses[0].ID < 1 ||
		uint64(statuses[0].ID) > devopsv1.MaximumContractInteger ||
		statuses[0].Status != string(checkreporting.CheckSuccess) ||
		statuses[0].Description != checkreporting.PassedDescription ||
		statuses[0].Context != wantContext || statuses[0].TargetURL != "" {
		t.Fatalf("source process provider statuses=%#v", statuses)
	}
	return uint64(statuses[0].ID)
}

func readSourceProcessPendingAudits(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
) map[auditv1.EventID]auditv1.Event {
	t.Helper()
	rows, err := admin.Query(
		ctx,
		`SELECT status, attempts, document
		   FROM delivery.audit_outbox
		  WHERE tenant_id = $1
		  ORDER BY event_id`,
		sourceProcessTenantID,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	events := make(map[auditv1.EventID]auditv1.Event)
	for rows.Next() {
		var status string
		var attempts int
		var document []byte
		if err := rows.Scan(&status, &attempts, &document); err != nil {
			t.Fatal(err)
		}
		var event auditv1.Event
		if status != "PENDING" || attempts != 0 || json.Unmarshal(document, &event) != nil ||
			auditv1.ValidateEventForSource(auditv1.SourceDevOps, event) != nil {
			t.Fatalf("source process pending Audit status=%q attempts=%d document=%s", status, attempts, document)
		}
		if _, duplicate := events[event.EventID]; duplicate {
			t.Fatalf("source process duplicate Audit event %q", event.EventID)
		}
		events[event.EventID] = event
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(events) < 3 {
		t.Fatalf("source process pending Audit events=%d want at least 3", len(events))
	}
	return events
}

func waitSourceProcessAuditCommit(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	dispatcher *executionProcessChild,
	proxy *sourceProcessAuditProxy,
	expected map[auditv1.EventID]auditv1.Event,
) auditv1.EventID {
	t.Helper()
	for {
		select {
		case eventID := <-proxy.firstCommitted:
			want, found := expected[eventID]
			if !found {
				t.Fatalf("physical Audit committed unexpected event %q", eventID)
			}
			snapshot := proxy.snapshot()
			if snapshot.failure != "" || snapshot.posts != 1 ||
				snapshot.accepted != 1 || snapshot.duplicates != 0 {
				t.Fatalf("physical Audit first commit proxy=%#v", snapshot)
			}
			var status, owner string
			var attempts int
			var fence int64
			var storedDocument []byte
			err := admin.QueryRow(
				ctx,
				`SELECT outbox.status, outbox.lease_owner, outbox.attempts,
				        outbox.fencing_token, record.event_document
				   FROM delivery.audit_outbox AS outbox
				   JOIN audit.records AS record
				     ON record.tenant_id = outbox.tenant_id
				    AND record.source = 'DEVOPS'
				    AND record.event_id = outbox.event_id
				  WHERE outbox.tenant_id = $1 AND outbox.event_id = $2`,
				sourceProcessTenantID,
				eventID,
			).Scan(&status, &owner, &attempts, &fence, &storedDocument)
			var stored auditv1.Event
			if err != nil || status != "LEASED" ||
				owner != "source-audit-process-first" || attempts != 1 || fence != 1 ||
				json.Unmarshal(storedDocument, &stored) != nil || stored != want {
				t.Fatalf(
					"physical Audit unacknowledged commit event=%q status=%s owner=%s attempts=%d fence=%d stored=%#v err=%v",
					eventID, status, owner, attempts, fence, stored, err,
				)
			}
			return eventID
		default:
		}
		if exited, err := dispatcher.poll(); exited {
			t.Fatalf(
				"first Audit dispatcher exited before physical commit: %v output=%q",
				err, dispatcher.output(),
			)
		}
		if failure := proxy.snapshot().failure; failure != "" {
			t.Fatal(failure)
		}
		waitExecutionProcessPoll(t, ctx)
	}
}

func expireSourceProcessAuditLease(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	eventID auditv1.EventID,
) {
	t.Helper()
	result, err := admin.Exec(
		ctx,
		`UPDATE delivery.audit_outbox
		    SET lease_expires_at = GREATEST(
		            created_at + interval '1 microsecond',
		            transaction_timestamp() - interval '1 microsecond'
		        ),
		        updated_at = transaction_timestamp()
		  WHERE tenant_id = $1 AND event_id = $2 AND status = 'LEASED'
		    AND lease_owner = 'source-audit-process-first'
		    AND attempts = 1 AND fencing_token = 1`,
		sourceProcessTenantID,
		eventID,
	)
	if err != nil || result.RowsAffected() != 1 {
		t.Fatalf("expire source process Audit lease rows=%d err=%v", result.RowsAffected(), err)
	}
}

func waitSourceProcessAuditDelivery(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	dispatcher *executionProcessChild,
	proxy *sourceProcessAuditProxy,
	expected map[auditv1.EventID]auditv1.Event,
	crashedEvent auditv1.EventID,
) []auditv1.Event {
	t.Helper()
	for {
		if exited, err := dispatcher.poll(); exited {
			t.Fatalf("Audit dispatcher exited before delivery: %v output=%q", err, dispatcher.output())
		}
		snapshot := proxy.snapshot()
		if snapshot.failure != "" {
			t.Fatal(snapshot.failure)
		}
		var total, delivered, attempts, deadLetters, leased int64
		err := admin.QueryRow(
			ctx,
			`SELECT count(*),
			        count(*) FILTER (WHERE status = 'DELIVERED'),
			        COALESCE(sum(attempts), 0),
			        count(*) FILTER (WHERE status = 'DEAD_LETTER'),
			        count(*) FILTER (WHERE status = 'LEASED')
			   FROM delivery.audit_outbox
			  WHERE tenant_id = $1`,
			sourceProcessTenantID,
		).Scan(&total, &delivered, &attempts, &deadLetters, &leased)
		if err != nil || total != int64(len(expected)) || deadLetters != 0 ||
			attempts > int64(len(expected)+1) {
			t.Fatalf(
				"source process Audit total=%d delivered=%d attempts=%d dead=%d leased=%d err=%v",
				total, delivered, attempts, deadLetters, leased, err,
			)
		}
		if delivered == total && leased == 0 && attempts == total+1 {
			if snapshot.posts != len(expected)+1 || snapshot.accepted != len(expected) ||
				snapshot.duplicates != 1 {
				t.Fatalf("source process Audit recovery proxy=%#v", snapshot)
			}
			events := readSourceProcessAuditRecords(t, ctx, admin)
			if len(events) != len(expected) {
				t.Fatalf("physical Audit records=%d want=%d", len(events), len(expected))
			}
			seen := make(map[auditv1.EventID]struct{}, len(events))
			for _, event := range events {
				want, found := expected[event.EventID]
				if !found || event != want {
					t.Fatalf("source process delivered unexpected Audit event=%#v", event)
				}
				if _, duplicate := seen[event.EventID]; duplicate {
					t.Fatalf("source process delivered duplicate Audit event %q", event.EventID)
				}
				seen[event.EventID] = struct{}{}
			}
			var crashedAttempts int
			var crashedFence int64
			if err := admin.QueryRow(
				ctx,
				`SELECT attempts, fencing_token FROM delivery.audit_outbox
				  WHERE tenant_id = $1 AND event_id = $2 AND status = 'DELIVERED'`,
				sourceProcessTenantID,
				crashedEvent,
			).Scan(&crashedAttempts, &crashedFence); err != nil ||
				crashedAttempts != 2 || crashedFence != 2 {
				t.Fatalf(
					"recovered Audit event=%q attempts=%d fence=%d err=%v",
					crashedEvent, crashedAttempts, crashedFence, err,
				)
			}
			return events
		}
		waitExecutionProcessPoll(t, ctx)
	}
}

func readSourceProcessAuditRecords(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
) []auditv1.Event {
	t.Helper()
	rows, err := admin.Query(
		ctx,
		`SELECT event_document
		   FROM audit.records
		  WHERE tenant_id = $1 AND source = 'DEVOPS'
		  ORDER BY sequence`,
		sourceProcessTenantID,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var events []auditv1.Event
	for rows.Next() {
		var document []byte
		if err := rows.Scan(&document); err != nil {
			t.Fatal(err)
		}
		var event auditv1.Event
		if json.Unmarshal(document, &event) != nil ||
			auditv1.ValidateEventForSource(auditv1.SourceDevOps, event) != nil {
			t.Fatalf("physical Audit record=%s", document)
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return events
}

func assertSourceProcessRunAudits(
	t *testing.T,
	events []auditv1.Event,
	run devopsv1.PipelineRun,
	correlationID string,
) {
	t.Helper()
	counts := map[auditv1.Action]int{}
	for _, event := range events {
		if auditv1.ValidateEventForSource(auditv1.SourceDevOps, event) != nil {
			t.Fatalf("source process delivered invalid Audit event=%#v", event)
		}
		switch event.Action {
		case auditv1.ActionDevOpsSourceEventAdmitted:
			counts[event.Action]++
			if event.Target.ID != string(run.Input.SourceEventID) ||
				event.RequestID != correlationID || event.CorrelationID != correlationID {
				t.Fatalf("source process admitted Audit event=%#v", event)
			}
		case auditv1.ActionDevOpsPipelineRunCreated:
			counts[event.Action]++
			if event.Target.ID != string(run.ID) || event.RequestID != correlationID ||
				event.CorrelationID != correlationID {
				t.Fatalf("source process created Audit event=%#v", event)
			}
		case auditv1.ActionDevOpsPipelineRunCompleted:
			counts[event.Action]++
			if event.Target.ID != string(run.ID) ||
				event.Actor != (auditv1.ActorReference{
					Type: auditv1.ActorSystem, ID: "system-devops-run-worker",
				}) || event.IAMDecisionID != "" ||
				event.Result != auditv1.ResultSucceeded ||
				event.Outcome != auditv1.OutcomeSucceeded ||
				event.Reason != auditv1.ReasonCompleted ||
				event.CorrelationID != string(run.ID) {
				t.Fatalf("source process terminal Audit event=%#v", event)
			}
		}
	}
	if counts[auditv1.ActionDevOpsSourceEventAdmitted] != 1 ||
		counts[auditv1.ActionDevOpsPipelineRunCreated] != 1 ||
		counts[auditv1.ActionDevOpsPipelineRunCompleted] != 1 {
		t.Fatalf("source process run Audit action counts=%#v", counts)
	}
}

func assertSourceProcessEvidence(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	archiveRoot string,
	run devopsv1.PipelineRun,
	terminal devopsv1.PipelineRun,
	repository sourceProcessRepository,
	correlationID string,
	uploadPacks int64,
	statusCreates int64,
	statusReads int64,
	providerStatusID uint64,
	secrets []string,
) {
	t.Helper()
	if uploadPacks != 1 || statusCreates != 1 || statusReads != 1 {
		t.Fatalf(
			"source process provider upload-packs=%d status-creates=%d status-reads=%d want=1/1/1",
			uploadPacks, statusCreates, statusReads,
		)
	}
	if terminal.ID != run.ID || terminal.Input != run.Input ||
		terminal.InputDigest != run.InputDigest ||
		terminal.Status.State != devopsv1.PipelineRunSucceeded ||
		terminal.Status.Stage != devopsv1.PipelineRunStageReport ||
		terminal.Status.Reason != devopsv1.PipelineRunReasonCompleted ||
		terminal.Status.CompletedAt == nil {
		t.Fatalf("source process terminal evidence=%#v", terminal)
	}
	var status string
	var owner *string
	var fence uint64
	var archiveDocument []byte
	err := admin.QueryRow(
		ctx,
		`SELECT task.status, task.lease_owner, task.fencing_token,
		        jsonb_build_object(
		          'tenantId', archive.tenant_id,
		          'runId', archive.run_id,
		          'commandId', archive.command_id,
		          'inputDigest', archive.input_digest,
		          'headCommit', archive.head_commit,
		          'trustedBaseCommit', archive.trusted_base_commit,
		          'mediaType', archive.media_type,
		          'archiveDigest', archive.archive_digest,
		          'archiveBytes', archive.archive_bytes,
		          'expandedBytes', archive.expanded_bytes,
		          'pathCount', archive.path_count
		        )
		   FROM delivery.pipeline_run_tasks AS task
		   JOIN delivery.source_archives AS archive
		     ON archive.tenant_id = task.tenant_id AND archive.run_id = task.run_id
		  WHERE task.tenant_id = $1 AND task.run_id = $2 AND task.stage = 'FETCH'`,
		sourceProcessTenantID, run.ID,
	).Scan(&status, &owner, &fence, &archiveDocument)
	if err != nil || status != "COMPLETED" || owner != nil || fence != 2 {
		t.Fatalf(
			"source process task status=%q owner=%v fence=%d err=%v",
			status, owner, fence, err,
		)
	}
	var receipt sourcearchive.Receipt
	if json.Unmarshal(archiveDocument, &receipt) != nil || sourcearchive.ValidateReceipt(receipt) != nil ||
		receipt.RunID != run.ID || receipt.InputDigest != run.InputDigest ||
		receipt.HeadCommit != run.Input.Change.HeadCommit ||
		receipt.TrustedBaseCommit != run.Input.Change.TrustedBaseCommit {
		t.Fatalf("source process archive receipt=%s", archiveDocument)
	}
	store, err := sourcearchivefile.New(archiveRoot)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := store.Open(ctx, receipt)
	if err != nil {
		t.Fatal(err)
	}
	archive, readErr := io.ReadAll(io.LimitReader(reader, sourcearchive.MaximumArchiveBytes+1))
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil || int64(len(archive)) != receipt.ArchiveBytes {
		t.Fatalf("read source process archive: read=%v close=%v", readErr, closeErr)
	}
	defer clear(archive)
	files := readSourceProcessArchive(t, archive)
	if string(files["source.txt"]) != "source process recovery\n" ||
		string(files["go.mod"]) != "module example.invalid/matrixprocessgate\n\ngo 1.26.0\n" ||
		len(files) != 5 {
		t.Fatalf("source process archive paths=%v", sourceProcessMapKeys(files))
	}
	for name := range files {
		if strings.Contains(strings.ToLower(name), ".git") {
			t.Fatalf("source process archive contains Git metadata path %q", name)
		}
	}
	if !strings.Contains(repository.FullName, "/source-process-") {
		t.Fatal("source process repository identity changed")
	}

	var verifyStatus, reportStatus string
	var verifyOwner, reportOwner *string
	var verifyFence, reportFence uint64
	var buildDocument, checkDocument []byte
	err = admin.QueryRow(
		ctx,
		`SELECT verify.status, verify.lease_owner, verify.fencing_token,
		        report.status, report.lease_owner, report.fencing_token,
		        build.document, check_receipt.document
		   FROM delivery.pipeline_run_tasks AS verify
		   JOIN delivery.pipeline_run_tasks AS report
		     ON report.tenant_id = verify.tenant_id AND report.run_id = verify.run_id
		    AND report.stage = 'REPORT'
		   JOIN delivery.build_receipts AS build
		     ON build.tenant_id = verify.tenant_id AND build.run_id = verify.run_id
		   JOIN delivery.check_receipts AS check_receipt
		     ON check_receipt.tenant_id = verify.tenant_id
		    AND check_receipt.run_id = verify.run_id
		  WHERE verify.tenant_id = $1 AND verify.run_id = $2
		    AND verify.stage = 'VERIFY'`,
		sourceProcessTenantID,
		run.ID,
	).Scan(
		&verifyStatus, &verifyOwner, &verifyFence,
		&reportStatus, &reportOwner, &reportFence,
		&buildDocument, &checkDocument,
	)
	if err != nil || verifyStatus != "COMPLETED" || verifyOwner != nil || verifyFence != 2 ||
		reportStatus != "COMPLETED" || reportOwner != nil || reportFence != 2 {
		t.Fatalf(
			"source process verify=%s/%v/%d report=%s/%v/%d err=%v",
			verifyStatus, verifyOwner, verifyFence, reportStatus, reportOwner, reportFence, err,
		)
	}
	runnerID, err := executorgatewayhttp.RunnerID(executionProcessRunnerIdentity)
	if err != nil {
		t.Fatal(err)
	}
	var buildReceipt devopsbuildv1.Receipt
	if json.Unmarshal(buildDocument, &buildReceipt) != nil ||
		devopsbuildv1.ValidateReceiptShape(buildReceipt) != nil ||
		buildReceipt.TenantID != sourceProcessTenantID || buildReceipt.RunID != run.ID ||
		buildReceipt.CommandID != string(run.ID)+":verify:1" ||
		buildReceipt.InputDigest != run.InputDigest ||
		buildReceipt.SourceArchiveDigest != receipt.ArchiveDigest ||
		buildReceipt.PipelineRevisionID != run.Input.PipelineRevisionID ||
		buildReceipt.PipelineRevisionDigest != run.Input.PipelineRevisionDigest ||
		buildReceipt.ExecutorID != runnerID ||
		buildReceipt.Conclusion != devopsbuildv1.ConclusionPassed {
		t.Fatalf("source process build receipt=%s", buildDocument)
	}
	var checkReceipt checkreporting.Receipt
	if json.Unmarshal(checkDocument, &checkReceipt) != nil ||
		checkReceipt.TenantID != sourceProcessTenantID || checkReceipt.RunID != run.ID ||
		checkReceipt.CommandID != string(run.ID)+":report:1" ||
		checkReceipt.InputDigest != run.InputDigest || checkReceipt.AdapterID != gitea.AdapterID ||
		checkReceipt.SourceConnectionID != sourceProcessConnectionID ||
		checkReceipt.RepositoryBindingID != sourceProcessBindingID ||
		checkReceipt.RepositoryBindingDigest != run.Input.RepositoryBindingDigest ||
		checkReceipt.HeadCommit != run.Input.Change.HeadCommit ||
		checkReceipt.PipelineRevisionID != run.Input.PipelineRevisionID ||
		checkReceipt.PipelineRevisionDigest != run.Input.PipelineRevisionDigest ||
		checkReceipt.BuildReceiptDigest != buildReceipt.ContentDigest ||
		checkReceipt.ProviderStatusID != providerStatusID ||
		devopsv1.ValidateDigest("checkReceipt.requestDigest", checkReceipt.RequestDigest) != nil ||
		checkReceipt.ContentDigest != checkreporting.DigestReceipt(checkReceipt) {
		t.Fatalf("source process check receipt=%s", checkDocument)
	}

	var sourceEvents, pipelineRuns, admittedFacts, createdFacts, completedFacts, terminalOperations int
	err = admin.QueryRow(
		ctx,
		`SELECT
		   (SELECT count(*) FROM delivery.source_events WHERE tenant_id = $1),
		   (SELECT count(*) FROM delivery.pipeline_runs WHERE tenant_id = $1),
		   (SELECT count(*) FROM delivery.audit_outbox
		     WHERE tenant_id = $1 AND document->>'action' = $2
		       AND document->>'correlationId' = $4 AND status = 'DELIVERED'),
		   (SELECT count(*) FROM delivery.audit_outbox
		     WHERE tenant_id = $1 AND document->>'action' = $3
		       AND document->>'correlationId' = $4 AND status = 'DELIVERED'),
		   (SELECT count(*) FROM delivery.audit_outbox
		     WHERE tenant_id = $1 AND document->>'action' = $5
		       AND document->>'correlationId' = $6 AND status = 'DELIVERED'),
		   (SELECT count(*) FROM delivery.audit_operations
		     WHERE tenant_id = $1 AND operation_kind = 'PIPELINE_RUN_TERMINAL'
		       AND target_id = $6)`,
		sourceProcessTenantID,
		auditv1.ActionDevOpsSourceEventAdmitted,
		auditv1.ActionDevOpsPipelineRunCreated,
		correlationID,
		auditv1.ActionDevOpsPipelineRunCompleted,
		run.ID,
	).Scan(
		&sourceEvents, &pipelineRuns, &admittedFacts, &createdFacts,
		&completedFacts, &terminalOperations,
	)
	if err != nil || sourceEvents != 1 || pipelineRuns != 1 ||
		admittedFacts != 1 || createdFacts != 1 || completedFacts != 1 ||
		terminalOperations != 1 {
		t.Fatalf(
			"source process evidence events=%d runs=%d admitted=%d created=%d completed=%d terminal=%d err=%v",
			sourceEvents, pipelineRuns, admittedFacts, createdFacts, completedFacts,
			terminalOperations, err,
		)
	}
	assertSourceProcessDatabaseSafe(t, ctx, admin, secrets)
	for _, content := range files {
		for _, secret := range secrets {
			if strings.Contains(string(content), secret) {
				t.Fatal("source process archive leaked protected material")
			}
		}
	}
}

func readSourceProcessArchive(t *testing.T, document []byte) map[string][]byte {
	t.Helper()
	compressed, err := gzip.NewReader(bytes.NewReader(document))
	if err != nil {
		t.Fatal(err)
	}
	defer compressed.Close()
	reader := tar.NewReader(compressed)
	files := make(map[string][]byte)
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || header == nil || header.Typeflag != tar.TypeReg {
			t.Fatalf("read source process archive header=%#v err=%v", header, err)
		}
		content, err := io.ReadAll(io.LimitReader(reader, sourcearchive.MaximumExpandedBytes+1))
		if err != nil || int64(len(content)) != header.Size {
			t.Fatalf("read source process archive file %q err=%v", header.Name, err)
		}
		files[header.Name] = content
	}
	return files
}

func sourceProcessMapKeys(values map[string][]byte) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	return keys
}

func assertSourceProcessDatabaseSafe(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	secrets []string,
) {
	t.Helper()
	rows, err := admin.Query(
		ctx,
		`WITH documents(document) AS (
		   SELECT document FROM delivery.projects
		   UNION ALL SELECT document FROM delivery.source_connections
		   UNION ALL SELECT document FROM delivery.repository_bindings
		   UNION ALL SELECT document FROM delivery.repository_binding_revisions
		   UNION ALL SELECT document FROM delivery.pipelines
		   UNION ALL SELECT document FROM delivery.pipeline_revisions
		   UNION ALL SELECT document FROM delivery.source_events
		   UNION ALL SELECT document FROM delivery.pipeline_runs
		   UNION ALL SELECT document FROM delivery.build_receipts
		   UNION ALL SELECT document FROM delivery.check_receipts
		   UNION ALL SELECT document FROM delivery.mutations
		   UNION ALL SELECT result_document FROM delivery.mutations
		   UNION ALL SELECT document FROM delivery.audit_outbox
		 )
		 SELECT document::text FROM documents`,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var document string
		if err := rows.Scan(&document); err != nil {
			t.Fatal(err)
		}
		for _, secret := range secrets {
			if strings.Contains(document, secret) {
				t.Fatal("source process database leaked protected material")
			}
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
}

func assertSourceProcessOutputSafe(
	t *testing.T,
	children []*executionProcessChild,
	protected []string,
) {
	t.Helper()
	for _, child := range children {
		output := child.output()
		for _, value := range protected {
			if value != "" && strings.Contains(output, value) {
				t.Errorf("source process output leaked protected input")
			}
		}
	}
}
