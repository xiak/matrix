package gitea

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/domain"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/sourcearchive"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/runlifecycle"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/sourceacquisition"
	"github.com/xiak/matrix/app/service/devops/sourcecredential"
)

const (
	realObserverUpstreamEnvironment = "MATRIX_DEVOPS_GITEA_OBSERVER_TEST_UPSTREAM"
	realObserverEndpointEnvironment = "MATRIX_DEVOPS_GITEA_OBSERVER_TEST_ENDPOINT"
	realFixtureUsername             = "matrixobserver"
	realFixturePassword             = "MatrixObserver-Test-2026!"
)

// TestRealGitea1273Observer is an opt-in protocol gate for the pinned,
// disposable provider fixture. The HTTPS proxy exists only because the
// production SourceConnection contract rejects plaintext provider origins.
func TestRealGitea1273Observer(t *testing.T) {
	upstream, endpointText, server := realProviderFixture(t)

	repository := provisionRealRepository(t, upstream)
	fetch := provisionRealToken(
		t, upstream, "observer-fetch", []string{"read:repository", "read:user"},
	)
	report := provisionRealToken(
		t, upstream, "observer-report", []string{"write:repository", "read:user"},
	)
	client := server.Client()
	client.Timeout = requestTimeout
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return errors.New("provider redirects are not permitted")
	}
	observer, err := newObserver(
		staticCredentialResolver{
			purpose: sourcecredential.PurposeWebhook, value: observerWebhook,
		},
		staticCredentialResolver{
			purpose: sourcecredential.PurposeFetch, value: fetch.value,
		},
		staticCredentialResolver{
			purpose: sourcecredential.PurposeReport, value: report.value,
		},
		client,
	)
	if err != nil {
		t.Fatal(err)
	}
	connection := observerConnection(endpointText)
	connectionObservation, err := observer.ObserveSourceConnection(
		context.Background(), connection,
	)
	if err != nil || connectionObservation.Health != devopsv1.SourceConnectionReady ||
		connectionObservation.Reason != devopsv1.SourceConnectionReasonObserved {
		t.Fatalf("real Gitea connection observation=%#v err=%v", connectionObservation, err)
	}
	binding := realObserverBinding(t, connection, repository)
	bindingObservation, err := observer.ObserveRepositoryBinding(
		context.Background(), connection, binding,
	)
	if err != nil || bindingObservation.Health != devopsv1.RepositoryBindingReady ||
		bindingObservation.Reason != devopsv1.RepositoryBindingReasonObserved {
		t.Fatalf("real Gitea binding observation=%#v err=%v", bindingObservation, err)
	}
}

// TestRealGitea1273SourceFetcher proves the production smart-HTTP adapter
// against the pinned disposable provider. It is opt-in for the same fixture as
// TestRealGitea1273Observer.
func TestRealGitea1273SourceFetcher(t *testing.T) {
	upstream, endpointText, server := realProviderFixture(t)
	repository := provisionRealRepository(t, upstream)
	change := provisionRealChange(t, upstream, repository)
	fetch := provisionRealToken(
		t, upstream, "source-fetch", []string{"read:repository"},
	)
	client := server.Client()
	client.Timeout = sourceacquisition.AcquisitionDeadline
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return errors.New("provider redirects are not permitted")
	}
	fetcher, err := newFetcher(
		staticCredentialResolver{purpose: sourcecredential.PurposeFetch, value: fetch.value},
		client,
	)
	if err != nil {
		t.Fatal(err)
	}
	command := realSourceCommand(t, endpointText, repository, change)
	var archive bytes.Buffer
	content, err := fetcher.Fetch(context.Background(), command, &archive)
	if err != nil {
		t.Fatalf("real Gitea source fetch: %v", err)
	}
	inspected, err := sourcearchive.Inspect(context.Background(), bytes.NewReader(archive.Bytes()))
	if err != nil || inspected != content {
		t.Fatalf("real source archive=%#v inspected=%#v err=%v", content, inspected, err)
	}
	files := readArchiveFiles(t, archive.Bytes())
	if string(files["source.txt"]) != "source acquisition\n" || len(files) != 2 {
		t.Fatalf("real source archive files=%v", mapKeys(files))
	}
	for name := range files {
		if strings.Contains(strings.ToLower(name), ".git") {
			t.Fatalf("real source archive leaked Git metadata path %q", name)
		}
	}
}

func realProviderFixture(t *testing.T) (*url.URL, string, *httptest.Server) {
	t.Helper()
	upstreamText := os.Getenv(realObserverUpstreamEnvironment)
	endpointText := os.Getenv(realObserverEndpointEnvironment)
	if upstreamText == "" || endpointText == "" {
		t.Skipf("set %s and %s for a disposable Gitea %s fixture",
			realObserverUpstreamEnvironment, realObserverEndpointEnvironment,
			SupportedVersion,
		)
	}
	upstream := requireLoopbackOrigin(t, upstreamText, "http")
	endpoint := requireLoopbackOrigin(t, endpointText, "https")
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	originalDirector := proxy.Director
	proxy.Director = func(request *http.Request) {
		originalDirector(request)
		request.Header.Set("X-Forwarded-Host", endpoint.Host)
		request.Header.Set("X-Forwarded-Proto", "https")
	}
	server := httptest.NewUnstartedServer(proxy)
	if err := server.Listener.Close(); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", endpoint.Host)
	if err != nil {
		t.Fatalf("listen on Gitea observer test endpoint: %v", err)
	}
	server.Listener = listener
	server.StartTLS()
	t.Cleanup(server.Close)
	if server.URL != endpointText {
		t.Fatalf("Gitea test endpoint=%q want=%q", server.URL, endpointText)
	}
	return upstream, endpointText, server
}

type realRepository struct {
	ID            int64  `json:"id"`
	FullName      string `json:"full_name"`
	DefaultBranch string `json:"default_branch"`
}

type realToken struct {
	Name  string `json:"name"`
	value string
}

type realChange struct {
	Number     uint64
	HeadCommit string
	BaseCommit string
}

type realBranch struct {
	Commit struct {
		ID string `json:"id"`
	} `json:"commit"`
}

type realPullRequest struct {
	Number int64 `json:"number"`
	Head   struct {
		SHA string `json:"sha"`
	} `json:"head"`
	Base struct {
		SHA string `json:"sha"`
	} `json:"base"`
}

func provisionRealRepository(t *testing.T, upstream *url.URL) realRepository {
	t.Helper()
	name := "observer-fixture"
	var repository realRepository
	realFixtureRequest(
		t, upstream, http.MethodPost, "/api/v1/user/repos",
		map[string]any{
			"name": name, "private": true, "auto_init": true,
			"default_branch": "main",
		},
		http.StatusCreated, &repository,
	)
	if repository.ID < 1 || repository.FullName != realFixtureUsername+"/"+name ||
		repository.DefaultBranch != "main" {
		t.Fatalf("real Gitea repository=%#v", repository)
	}
	t.Cleanup(func() {
		realFixtureRequest(
			t, upstream, http.MethodDelete,
			"/api/v1/repos/"+realFixtureUsername+"/"+name,
			nil, http.StatusNoContent, nil,
		)
	})
	return repository
}

func provisionRealChange(
	t *testing.T,
	upstream *url.URL,
	repository realRepository,
) realChange {
	t.Helper()
	requestPrefix := "/api/v1/repos/" + realFixtureUsername + "/" +
		strings.TrimPrefix(repository.FullName, realFixtureUsername+"/")
	var base realBranch
	realFixtureRequest(
		t, upstream, http.MethodGet, requestPrefix+"/branches/main",
		nil, http.StatusOK, &base,
	)
	if !validSHA1(base.Commit.ID) {
		t.Fatal("real Gitea base commit is invalid")
	}
	realFixtureRequest(
		t, upstream, http.MethodPost, requestPrefix+"/branches",
		map[string]any{
			"new_branch_name": "feature/source-fetch",
			"old_branch_name": "main",
		},
		http.StatusCreated, nil,
	)
	realFixtureRequest(
		t, upstream, http.MethodPost, requestPrefix+"/contents/source.txt",
		map[string]any{
			"branch":  "feature/source-fetch",
			"content": base64.StdEncoding.EncodeToString([]byte("source acquisition\n")),
			"message": "add source fixture",
		},
		http.StatusCreated, nil,
	)
	var pull realPullRequest
	realFixtureRequest(
		t, upstream, http.MethodPost, requestPrefix+"/pulls",
		map[string]any{
			"base": "main", "head": "feature/source-fetch",
			"title": "source acquisition fixture",
		},
		http.StatusCreated, &pull,
	)
	if pull.Number < 1 || uint64(pull.Number) > devopsv1.MaximumContractInteger ||
		!validSHA1(pull.Head.SHA) || pull.Base.SHA != base.Commit.ID {
		t.Fatalf("real Gitea pull request=%#v", pull)
	}
	return realChange{
		Number: uint64(pull.Number), HeadCommit: pull.Head.SHA, BaseCommit: pull.Base.SHA,
	}
}

func provisionRealToken(
	t *testing.T,
	upstream *url.URL,
	prefix string,
	scopes []string,
) realToken {
	t.Helper()
	name := fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
	var document struct {
		Name string `json:"name"`
		SHA1 string `json:"sha1"`
	}
	realFixtureRequest(
		t, upstream, http.MethodPost,
		"/api/v1/users/"+realFixtureUsername+"/tokens",
		map[string]any{"name": name, "scopes": scopes}, http.StatusCreated,
		&document,
	)
	if document.Name != name || len(document.SHA1) < 32 || len(document.SHA1) > 256 {
		t.Fatal("real Gitea token response is invalid")
	}
	t.Cleanup(func() {
		realFixtureRequest(
			t, upstream, http.MethodDelete,
			"/api/v1/users/"+realFixtureUsername+"/tokens/"+url.PathEscape(name),
			nil, http.StatusNoContent, nil,
		)
	})
	return realToken{Name: name, value: document.SHA1}
}

func realFixtureRequest(
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
		method, strings.TrimSuffix(upstream.String(), "/")+requestPath,
		bytes.NewReader(content),
	)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set(
		"Authorization", "Basic "+base64.StdEncoding.EncodeToString(
			[]byte(realFixtureUsername+":"+realFixturePassword),
		),
	)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := (&http.Client{Timeout: requestTimeout}).Do(request)
	if err != nil {
		t.Fatalf("call disposable Gitea fixture: %v", err)
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, maximumResponseBody+1))
	if err != nil || len(responseBody) > maximumResponseBody || response.StatusCode != wantStatus {
		clear(responseBody)
		t.Fatalf("disposable Gitea fixture status=%d want=%d", response.StatusCode, wantStatus)
	}
	defer clear(responseBody)
	if target != nil && json.Unmarshal(responseBody, target) != nil {
		t.Fatal("decode disposable Gitea fixture response")
	}
}

func requireLoopbackOrigin(t *testing.T, text, scheme string) *url.URL {
	t.Helper()
	value, err := url.Parse(text)
	address := net.ParseIP(value.Hostname())
	if err != nil || value.Scheme != scheme || value.User != nil ||
		value.Path != "" || value.RawQuery != "" || value.Fragment != "" ||
		value.Port() == "" || address == nil || !address.IsLoopback() ||
		value.String() != text {
		t.Fatalf("Gitea observer test %s origin is unsafe", scheme)
	}
	return value
}

func realObserverBinding(
	t *testing.T,
	connection devopsv1.SourceConnection,
	repository realRepository,
) devopsv1.RepositoryBinding {
	t.Helper()
	project := devopsv1.DevOpsProject{
		APIVersion: devopsv1.APIVersion, Kind: "DevOpsProject",
		Metadata: devopsv1.ResourceMetadata{
			ID: "project-real-gitea", Name: "project-real-gitea",
			Scope: connection.Metadata.Scope, ResourceVersion: 1,
			CreatedAt: connection.Metadata.CreatedAt,
			UpdatedAt: connection.Metadata.CreatedAt,
		},
	}
	binding, err := domain.NewRepositoryBinding(
		devopsv1.CreateRepositoryBindingRequest{
			ID: "binding-real-gitea", Name: "binding-real-gitea",
			ProjectID: project.Metadata.ID,
			Spec: devopsv1.RepositoryBindingSpec{
				SourceConnectionID: connection.Metadata.ID,
				ExternalRepositoryID: devopsv1.ResourceID(
					strconv.FormatInt(repository.ID, 10),
				),
				RepositoryPath:       repository.FullName,
				TrustedDefaultBranch: repository.DefaultBranch,
			},
		},
		project, connection, connection.Metadata.CreatedAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	return binding
}

func realSourceCommand(
	t *testing.T,
	endpoint string,
	repository realRepository,
	change realChange,
) sourceacquisition.Command {
	t.Helper()
	connection := observerConnection(endpoint)
	binding := realObserverBinding(t, connection, repository)
	binding.Status.Health = devopsv1.RepositoryBindingReady
	binding.Status.Reason = devopsv1.RepositoryBindingReasonObserved
	project := devopsv1.DevOpsProject{
		APIVersion: devopsv1.APIVersion, Kind: "DevOpsProject",
		Metadata: devopsv1.ResourceMetadata{
			ID: binding.ProjectID, Name: "project-real-gitea",
			Scope: connection.Metadata.Scope, ResourceVersion: 1,
			CreatedAt: connection.Metadata.CreatedAt,
			UpdatedAt: connection.Metadata.CreatedAt,
		},
	}
	pipeline, err := domain.NewPipeline(devopsv1.CreatePipelineRequest{
		ID: "pipeline-real-gitea", Name: "pipeline-real-gitea", ProjectID: project.Metadata.ID,
		Draft: devopsv1.PipelineDraftSpec{
			RepositoryBindingID: binding.Metadata.ID, TriggerPolicy: devopsv1.TriggerChange,
			VerificationProfile: devopsv1.VerificationGo126OfflineV1,
			DependencyEgress:    devopsv1.DependencyEgressNone,
			ReporterPolicy:      devopsv1.ReporterChangeCheckV1,
		},
	}, project, binding, connection.Metadata.CreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	activation, err := domain.ActivatePipeline(
		pipeline, pipeline.Metadata.ResourceVersion,
		devopsv1.SubjectRef{Kind: devopsv1.SubjectUser, ID: "user-real-gitea"},
		binding, connection.Metadata.CreatedAt.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	normalized := domain.NormalizedChange{
		Scope: connection.Metadata.Scope, SourceConnectionID: connection.Metadata.ID,
		VerifiedSourceConnectionVersion: connection.Metadata.ResourceVersion,
		ExternalRepositoryID:            binding.Spec.ExternalRepositoryID,
		TrustedBaseBranch:               binding.Spec.TrustedDefaultBranch,
		DeliveryID:                      "123e4567-e89b-42d3-a456-426614174001",
		CanonicalPayloadDigest:          "sha256:" + strings.Repeat("b", 64),
		Change: devopsv1.ChangeIdentity{
			Number: change.Number, Action: devopsv1.ChangeOpened,
			HeadCommit: change.HeadCommit, TrustedBaseCommit: change.BaseCommit,
		},
	}
	event, err := domain.NewSourceEvent(
		normalized, connection, binding, connection.Metadata.CreatedAt.Add(2*time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	run, err := domain.NewPipelineRun(event, activation.Pipeline, activation.Revision)
	if err != nil {
		t.Fatal(err)
	}
	run, err = domain.AdvancePipelineRun(
		run, devopsv1.PipelineRunFetching, "", run.UpdatedAt.Add(time.Microsecond),
	)
	if err != nil {
		t.Fatal(err)
	}
	intent := runlifecycle.TaskIntent{
		RunID: run.ID, InputDigest: run.InputDigest,
		Stage: devopsv1.PipelineRunStageFetch, Attempt: 1,
	}
	intent.CommandID = runlifecycle.TaskCommandID(intent.RunID, intent.Stage, intent.Attempt)
	return sourceacquisition.Command{
		Lease: runlifecycle.Lease{
			TenantID: run.Scope.TenantID, Run: run, Intent: intent,
			Mode: runlifecycle.ClaimExecute, WorkerID: "source-fetcher-real", FencingToken: 1,
			LeaseExpiresAt: run.UpdatedAt.Add(sourceacquisition.LeaseDuration),
		},
		Connection: connection, BindingRevision: binding,
		Revision: activation.Revision, Event: event,
	}
}

func readArchiveFiles(t *testing.T, document []byte) map[string][]byte {
	t.Helper()
	gzipReader, err := gzip.NewReader(bytes.NewReader(document))
	if err != nil {
		t.Fatal(err)
	}
	defer gzipReader.Close()
	tarReader := tar.NewReader(gzipReader)
	files := make(map[string][]byte)
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || header == nil || header.Typeflag != tar.TypeReg {
			t.Fatalf("read source archive header=%#v err=%v", header, err)
		}
		content, err := io.ReadAll(io.LimitReader(tarReader, sourcearchive.MaximumExpandedBytes+1))
		if err != nil || int64(len(content)) != header.Size {
			t.Fatalf("read source archive file %q err=%v", header.Name, err)
		}
		files[header.Name] = content
	}
	return files
}

func mapKeys(values map[string][]byte) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	return keys
}
