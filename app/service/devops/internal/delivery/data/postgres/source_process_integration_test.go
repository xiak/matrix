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
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/data/gitea"
	devopspostgres "github.com/xiak/matrix/app/service/devops/internal/delivery/data/postgres"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/data/sourcearchivefile"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/data/sourcecredentialfile"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/sourcearchive"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/pipelineconfiguration"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/runadmission"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/runcontrol"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/sourceingress"
	devopsmigration "github.com/xiak/matrix/app/service/devops/migration"
	"github.com/xiak/matrix/app/service/devops/sourcecredential"
)

const (
	sourceProcessDSNEnvironment           = "MATRIX_DEVOPS_SOURCE_PROCESS_TEST_DSN"
	sourceProcessGiteaUpstreamEnvironment = "MATRIX_DEVOPS_SOURCE_PROCESS_TEST_GITEA_UPSTREAM"
	sourceProcessGiteaEndpointEnvironment = "MATRIX_DEVOPS_SOURCE_PROCESS_TEST_GITEA_ENDPOINT"
	sourceProcessObserverEnvironment      = "MATRIX_DEVOPS_SOURCE_PROCESS_OBSERVER_BINARY"
	sourceProcessFetcherEnvironment       = "MATRIX_DEVOPS_SOURCE_PROCESS_FETCHER_BINARY"

	sourceProcessFixtureUsername = "matrixobserver"
	sourceProcessFixturePassword = "MatrixObserver-Test-2026!"
	sourceProcessWebhookSecret   = "source-process-webhook-secret-00000001"
	sourceProcessTenantID        = devopsv1.TenantID("tenant-source-process")
	sourceProcessConnectionID    = devopsv1.ResourceID("connection-source-process")
	sourceProcessBindingID       = devopsv1.ResourceID("binding-source-process")
	sourceProcessPipelineID      = devopsv1.ResourceID("pipeline-source-process")
	sourceProcessDeliveryID      = "123e4567-e89b-42d3-a456-000000000702"
	sourceProcessCorrelationID   = "correlation-source-process"
)

// TestSignedGiteaChangeRecoversThroughSourceFetcherProcess is the opt-in Gate B
// source subjourney. A real Gitea change becomes one signed admission and one
// archive. The first source-fetcher is killed after publishing that archive
// but before PostgreSQL can acknowledge it; a replacement must observe the
// immutable effect under a larger fence without another provider fetch.
func TestSignedGiteaChangeRecoversThroughSourceFetcherProcess(t *testing.T) {
	adminDSN := os.Getenv(sourceProcessDSNEnvironment)
	if adminDSN == "" {
		t.Skipf("set %s to a clean disposable PostgreSQL 18 database", sourceProcessDSNEnvironment)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()

	observerBinary := requiredExecutionProcessBinary(t, sourceProcessObserverEnvironment)
	fetcherBinary := requiredExecutionProcessBinary(t, sourceProcessFetcherEnvironment)
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
	assertCleanExecutionProcessDatabase(t, ctx, admin)

	apiPassword := "mxp1.source-process-api-000000000000000000000000"
	reporterPassword := "mxp1.source-process-reporter-0000000000000000000"
	fetcherPassword := "mxp1.source-process-fetcher-00000000000000000000"
	observerPassword := "mxp1.source-process-observer-0000000000000000000"
	workerPassword := "mxp1.source-process-worker-000000000000000000000"
	apiDSN := runtimeDSN(t, adminDSN, "matrix_devops_api_login", apiPassword)
	reporterDSN := runtimeDSN(t, adminDSN, "matrix_devops_check_reporter_login", reporterPassword)
	fetcherDSN := runtimeDSN(t, adminDSN, "matrix_devops_source_fetcher_login", fetcherPassword)
	observerDSN := runtimeDSN(t, adminDSN, "matrix_devops_source_observer_login", observerPassword)
	workerDSN := runtimeDSN(t, adminDSN, "matrix_devops_worker_login", workerPassword)
	for attempt := 1; attempt <= 2; attempt++ {
		if err := devopsmigration.Apply(
			ctx, adminDSN, apiDSN, reporterDSN, fetcherDSN, observerDSN, workerDSN,
		); err != nil {
			t.Fatalf("apply source process migration attempt %d: %v", attempt, err)
		}
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
	endpoint, provider, uploadPacks := newSourceProcessProvider(
		t, upstream, providerEndpoint,
	)
	caPath := writeExecutionProcessFile(
		t, temporary, "provider-ca.pem",
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: provider.Certificate().Raw}),
		0o600,
	)
	repository := provisionSourceProcessRepository(t, upstream)
	change := provisionSourceProcessChange(t, upstream, repository)
	fetchCredential := provisionSourceProcessToken(
		t, upstream, "source-process-fetch", []string{"read:repository", "read:user"},
	)
	reportCredential := provisionSourceProcessToken(
		t, upstream, "source-process-report", []string{"write:repository", "read:user"},
	)
	scope := devopsv1.ResourceScope{TenantID: sourceProcessTenantID}
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

	observerDSNPath := writeExecutionProcessFile(
		t, temporary, "source-observer-dsn", []byte(observerDSN), 0o600,
	)
	fetcherDSNPath := writeExecutionProcessFile(
		t, temporary, "source-fetcher-dsn", []byte(fetcherDSN), 0o600,
	)
	observerAddress := reserveExecutionProcessAddress(t)
	firstFetcherAddress := reserveDistinctExecutionProcessAddress(t, observerAddress)
	secondFetcherAddress := reserveDistinctExecutionProcessAddress(
		t, observerAddress, firstFetcherAddress,
	)
	children := make([]*executionProcessChild, 0, 3)
	t.Cleanup(func() {
		for index := len(children) - 1; index >= 0; index-- {
			children[index].stop()
		}
		assertSourceProcessOutputSafe(t, children, []string{
			sourceProcessWebhookSecret, fetchCredential.value, reportCredential.value,
			apiPassword, reporterPassword, fetcherPassword, observerPassword,
			workerPassword, temporary,
		})
	})
	start := func(binary string, environment []string) *executionProcessChild {
		child := startExecutionProcess(t, binary, environment)
		children = append(children, child)
		return child
	}
	observerEnvironment := []string{
		"MATRIX_DEVOPS_SOURCE_OBSERVER_DATABASE_DSN_FILE=" + observerDSNPath,
		"MATRIX_DEVOPS_SOURCE_OBSERVER_WEBHOOK_ROOT=" + webhookRoot,
		"MATRIX_DEVOPS_SOURCE_OBSERVER_FETCH_ROOT=" + fetchRoot,
		"MATRIX_DEVOPS_SOURCE_OBSERVER_REPORT_ROOT=" + reportRoot,
		"MATRIX_DEVOPS_SOURCE_OBSERVER_WORKER_ID=source-observer-process",
		"MATRIX_DEVOPS_SOURCE_OBSERVER_LISTEN_ADDRESS=" + observerAddress,
		"SSL_CERT_FILE=" + caPath,
	}
	observer := start(observerBinary, observerEnvironment)
	waitExecutionProcessHTTPStatus(
		t, ctx, observer, "http://"+observerAddress+"/ready", http.StatusOK,
	)
	waitSourceProcessConfigurationReady(t, ctx, configuration, observer)

	webhookResolver, err := sourcecredentialfile.NewResolver(
		sourcecredential.PurposeWebhook, webhookRoot,
	)
	if err != nil {
		t.Fatal(err)
	}
	admission, err := runadmission.NewUsecase(
		controlRepository, runadmission.Config{MaxTransactionAttempts: 5},
	)
	if err != nil {
		t.Fatal(err)
	}
	ingress, err := sourceingress.NewUsecase(
		controlRepository, webhookResolver, admission, gitea.NewAdapter(),
	)
	if err != nil {
		t.Fatal(err)
	}
	body := sourceProcessWebhookBody(t, endpoint, repository, change)
	command := sourceingress.Command{
		Scope: scope, SourceConnectionID: sourceProcessConnectionID,
		ProviderEvent: "pull_request", DeliveryID: sourceProcessDeliveryID,
		Signature: sourceProcessSignature(body, sourceProcessWebhookSecret), Body: body,
		RequestID: "request-source-process", CorrelationID: sourceProcessCorrelationID,
	}
	forged := command
	forged.Signature = strings.Repeat("0", sha256.Size*2)
	if _, err := ingress.Receive(ctx, forged); !errors.Is(err, sourceingress.ErrUnauthenticated) {
		t.Fatalf("forged source process signature error=%v", err)
	}
	firstAdmission, err := ingress.Receive(ctx, command)
	if err != nil || firstAdmission.Replayed || len(firstAdmission.Admission.Runs) != 1 {
		t.Fatalf("source process admission=%#v err=%v", firstAdmission, err)
	}
	equalAdmission, err := ingress.Receive(ctx, command)
	if err != nil || !equalAdmission.Replayed || len(equalAdmission.Admission.Runs) != 1 ||
		equalAdmission.Admission.Runs[0] != firstAdmission.Admission.Runs[0] {
		t.Fatalf("source process equal replay=%#v err=%v", equalAdmission, err)
	}
	changedCommand := command
	changedCommand.Body = append(append([]byte(nil), body...), '\n')
	changedCommand.Signature = sourceProcessSignature(changedCommand.Body, sourceProcessWebhookSecret)
	if _, err := ingress.Receive(ctx, changedCommand); !errors.Is(err, runadmission.ErrReplayConflict) {
		t.Fatalf("source process changed replay error=%v", err)
	}
	run := firstAdmission.Admission.Runs[0]

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
	firstFetcherEnvironment := sourceProcessFetcherEnvironmentValues(
		fetcherDSNPath, fetchRoot, archiveRoot, caPath,
		"source-fetcher-process-first", firstFetcherAddress,
	)
	assertSourceProcessFetcherEnvironment(
		t, firstFetcherEnvironment, webhookRoot, reportRoot,
		sourceProcessWebhookSecret, fetchCredential.value, reportCredential.value,
	)
	firstFetcher := start(fetcherBinary, firstFetcherEnvironment)
	waitSourceProcessArchive(t, ctx, archiveRoot, firstFetcher)
	if uploadPacks.Load() != 1 {
		t.Fatalf("source process provider upload-pack requests=%d want=1", uploadPacks.Load())
	}
	firstFetcher.crash(t)
	if err := lock.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	lockOpen = false
	assertSourceProcessUnacknowledged(t, ctx, admin, run.ID)
	expireSourceProcessLease(t, ctx, admin, run.ID)

	secondFetcherEnvironment := sourceProcessFetcherEnvironmentValues(
		fetcherDSNPath, fetchRoot, archiveRoot, caPath,
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
	assertSourceProcessEvidence(
		t, ctx, admin, archiveRoot, run, repository, uploadPacks.Load(),
		[]string{sourceProcessWebhookSecret, fetchCredential.value, reportCredential.value},
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
) (string, *httptest.Server, *atomic.Int64) {
	t.Helper()
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	originalDirector := proxy.Director
	uploadPacks := &atomic.Int64{}
	proxy.Director = func(request *http.Request) {
		incomingHost := request.Host
		originalDirector(request)
		request.Header.Set("X-Forwarded-Host", incomingHost)
		request.Header.Set("X-Forwarded-Proto", "https")
	}
	handler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/git-upload-pack") {
			uploadPacks.Add(1)
		}
		proxy.ServeHTTP(response, request)
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
	return server.URL, server, uploadPacks
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

func sourceProcessFetcherEnvironmentValues(
	dsnPath string,
	fetchRoot string,
	archiveRoot string,
	caPath string,
	workerID string,
	listenAddress string,
) []string {
	return []string{
		"MATRIX_DEVOPS_SOURCE_FETCHER_DATABASE_DSN_FILE=" + dsnPath,
		"MATRIX_DEVOPS_SOURCE_FETCHER_FETCH_ROOT=" + fetchRoot,
		"MATRIX_DEVOPS_SOURCE_FETCHER_ARCHIVE_ROOT=" + archiveRoot,
		"MATRIX_DEVOPS_SOURCE_FETCHER_WORKER_ID=" + workerID,
		"MATRIX_DEVOPS_SOURCE_FETCHER_LISTEN_ADDRESS=" + listenAddress,
		"SSL_CERT_FILE=" + caPath,
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

func assertSourceProcessEvidence(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	archiveRoot string,
	run devopsv1.PipelineRun,
	repository sourceProcessRepository,
	uploadPacks int64,
	secrets []string,
) {
	t.Helper()
	if uploadPacks != 1 {
		t.Fatalf("source process provider upload-pack requests=%d want=1", uploadPacks)
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
	if string(files["source.txt"]) != "source process recovery\n" || len(files) != 2 {
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

	var sourceEvents, pipelineRuns, admittedFacts, createdFacts int
	err = admin.QueryRow(
		ctx,
		`SELECT
		   (SELECT count(*) FROM delivery.source_events WHERE tenant_id = $1),
		   (SELECT count(*) FROM delivery.pipeline_runs WHERE tenant_id = $1),
		   (SELECT count(*) FROM delivery.audit_outbox
		     WHERE tenant_id = $1 AND document->>'action' = $2
		       AND document->>'correlationId' = $4),
		   (SELECT count(*) FROM delivery.audit_outbox
		     WHERE tenant_id = $1 AND document->>'action' = $3
		       AND document->>'correlationId' = $4)`,
		sourceProcessTenantID,
		auditv1.ActionDevOpsSourceEventAdmitted,
		auditv1.ActionDevOpsPipelineRunCreated,
		sourceProcessCorrelationID,
	).Scan(&sourceEvents, &pipelineRuns, &admittedFacts, &createdFacts)
	if err != nil || sourceEvents != 1 || pipelineRuns != 1 ||
		admittedFacts != 1 || createdFacts != 1 {
		t.Fatalf(
			"source process evidence events=%d runs=%d admitted=%d created=%d err=%v",
			sourceEvents, pipelineRuns, admittedFacts, createdFacts, err,
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
