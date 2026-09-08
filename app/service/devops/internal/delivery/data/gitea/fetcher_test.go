package gitea

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-git/go-billy/v5"
	"github.com/go-git/go-billy/v5/memfs"
	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/storage/memory"
	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/domain"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/sourcearchive"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/runlifecycle"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/sourceacquisition"
	"github.com/xiak/matrix/app/service/devops/sourcecredential"
)

const fetcherToken = "fetch-token-000000000000000000001"

func TestFetcherRejectsRedirectWithoutForwardingCredential(t *testing.T) {
	var redirectedRequests atomic.Int64
	target := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirectedRequests.Add(1)
	}))
	defer target.Close()

	var initialRequests atomic.Int64
	origin := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		initialRequests.Add(1)
		username, password, ok := request.BasicAuth()
		if !ok || username != gitAuthenticationUsername || password != fetcherToken {
			t.Error("initial Git request omitted its purpose-bound credential")
		}
		if request.URL.User != nil || request.URL.Path != "/matrix/service.git/info/refs" ||
			request.URL.RawQuery != "service=git-upload-pack" {
			t.Errorf("unexpected Git request URL %#v", request.URL)
		}
		http.Redirect(response, request, target.URL+"/stolen", http.StatusFound)
	}))
	defer origin.Close()
	client := origin.Client()
	client.Timeout = sourceacquisition.AcquisitionDeadline
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return errors.New("redirect rejected")
	}
	fetcher, err := newFetcher(
		staticCredentialResolver{purpose: sourcecredential.PurposeFetch, value: fetcherToken},
		client,
	)
	if err != nil {
		t.Fatal(err)
	}
	command := fetchCommand(t, origin.URL, strings.Repeat("1", 40), strings.Repeat("2", 40))
	if _, err := fetcher.Fetch(context.Background(), command, io.Discard); !errors.Is(err, sourceacquisition.ErrSourceUnavailable) {
		t.Fatalf("redirect fetch error=%v", err)
	}
	if initialRequests.Load() != 1 || redirectedRequests.Load() != 0 {
		t.Fatalf("requests initial=%d redirected=%d", initialRequests.Load(), redirectedRequests.Load())
	}
}

func TestFetcherRejectsUnsupportedObjectFormatBeforeCredentialLookup(t *testing.T) {
	resolver := &countingCredentialResolver{}
	fetcher, err := NewFetcher(resolver)
	if err != nil {
		t.Fatal(err)
	}
	command := fetchCommand(
		t,
		"https://git.example.com",
		strings.Repeat("1", 64),
		strings.Repeat("2", 64),
	)
	if _, err := fetcher.Fetch(context.Background(), command, io.Discard); !errors.Is(err, sourceacquisition.ErrSourceUnavailable) {
		t.Fatalf("SHA-256 fetch error=%v", err)
	}
	if resolver.calls != 0 {
		t.Fatalf("unsupported repository resolved %d credentials", resolver.calls)
	}
	if objectFormatMatches("sha256", strings.Repeat("1", 64)) {
		t.Fatal("Gitea v0.1 ingress accepted a SHA-256 repository")
	}
}

func TestArchiveCommitWalksBlobsWithoutCheckoutAndRejectsSymlinks(t *testing.T) {
	storage := memory.NewStorage()
	filesystem := memfs.New()
	repository, err := git.Init(storage, filesystem)
	if err != nil {
		t.Fatal(err)
	}
	if err := filesystem.MkdirAll("cmd/matrix", 0o755); err != nil {
		t.Fatal(err)
	}
	writeBillyFile(t, filesystem, "README.md", "matrix\n", 0o644)
	writeBillyFile(t, filesystem, "cmd/matrix/main.go", "package main\n", 0o755)
	worktree, err := repository.Worktree()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := worktree.Add("README.md"); err != nil {
		t.Fatal(err)
	}
	if _, err := worktree.Add("cmd/matrix/main.go"); err != nil {
		t.Fatal(err)
	}
	commitHash, err := worktree.Commit("fixture", &git.CommitOptions{
		Author: &object.Signature{
			Name: "Matrix", Email: "matrix@example.com",
			When: time.Unix(0, 0).UTC(),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	commit, err := repository.CommitObject(commitHash)
	if err != nil {
		t.Fatal(err)
	}
	var archive bytes.Buffer
	content, err := archiveCommit(context.Background(), repository, commit, &archive)
	if err != nil || content.PathCount != 2 ||
		content.ExpandedBytes != int64(len("matrix\n")+len("package main\n")) {
		t.Fatalf("archive content=%#v err=%v", content, err)
	}
	inspected, err := sourcearchive.Inspect(context.Background(), bytes.NewReader(archive.Bytes()))
	if err != nil || inspected != content {
		t.Fatalf("inspected=%#v want=%#v err=%v", inspected, content, err)
	}
	assertArchiveModes(t, archive.Bytes(), map[string]int64{
		"README.md": 0o644, "cmd/matrix/main.go": 0o755,
	})

	if err := filesystem.Symlink("README.md", "source-link"); err != nil {
		t.Skipf("in-memory filesystem cannot create a symlink: %v", err)
	}
	if _, err := worktree.Add("source-link"); err != nil {
		t.Fatal(err)
	}
	symlinkHash, err := worktree.Commit("symlink", &git.CommitOptions{
		Author: &object.Signature{
			Name: "Matrix", Email: "matrix@example.com",
			When: time.Unix(1, 0).UTC(),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	symlinkCommit, err := repository.CommitObject(symlinkHash)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := archiveCommit(context.Background(), repository, symlinkCommit, io.Discard); !errors.Is(err, sourceacquisition.ErrSourceUnavailable) {
		t.Fatalf("symlink tree error=%v", err)
	}
}

func TestClosedGitTransportRejectsEveryUnapprovedRequestShape(t *testing.T) {
	called := 0
	transport := &closedGitTransport{
		base: roundTripperFunc(func(*http.Request) (*http.Response, error) {
			called++
			return &http.Response{
				StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("response")),
				ContentLength: 8,
			}, nil
		}),
		endpointOrigin: "https://git.example.com", repositoryPath: "/matrix/service.git",
	}
	requests := []string{
		"http://git.example.com/matrix/service.git/info/refs?service=git-upload-pack",
		"https://other.example.com/matrix/service.git/info/refs?service=git-upload-pack",
		"https://git.example.com/matrix/other.git/info/refs?service=git-upload-pack",
		"https://git.example.com/matrix/service.git/info/refs?service=git-receive-pack",
	}
	for _, rawURL := range requests {
		request, err := http.NewRequest(http.MethodGet, rawURL, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := transport.RoundTrip(request); !errors.Is(err, sourceacquisition.ErrSourceUnavailable) {
			t.Fatalf("request %q error=%v", rawURL, err)
		}
	}
	if called != 0 {
		t.Fatalf("unapproved transport called its network boundary %d times", called)
	}
}

type countingCredentialResolver struct {
	calls int
}

func (resolver *countingCredentialResolver) Resolve(
	context.Context,
	devopsv1.ResourceScope,
	devopsv1.ResourceID,
) (sourcecredential.Material, error) {
	resolver.calls++
	return sourcecredential.NewMaterial(sourcecredential.PurposeFetch, []byte(fetcherToken), nil)
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (function roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func writeBillyFile(
	t *testing.T,
	filesystem billy.Filesystem,
	name, content string,
	mode os.FileMode,
) {
	t.Helper()
	file, err := filesystem.OpenFile(name, os.O_CREATE|os.O_TRUNC|os.O_RDWR, mode)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(file, content); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func assertArchiveModes(t *testing.T, document []byte, want map[string]int64) {
	t.Helper()
	gzipReader, err := gzip.NewReader(bytes.NewReader(document))
	if err != nil {
		t.Fatal(err)
	}
	defer gzipReader.Close()
	tarReader := tar.NewReader(gzipReader)
	got := make(map[string]int64)
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		got[header.Name] = header.Mode
	}
	for name, mode := range want {
		if got[name] != mode {
			t.Fatalf("archive mode %s=%#o want=%#o", name, got[name], mode)
		}
	}
}

func fetchCommand(
	t *testing.T,
	endpointOrigin, headCommit, baseCommit string,
) sourceacquisition.Command {
	t.Helper()
	base := time.Date(2026, 9, 8, 1, 2, 3, 0, time.UTC)
	scope := devopsv1.ResourceScope{TenantID: "organization-acme"}
	project, err := domain.NewDevOpsProject(devopsv1.CreateDevOpsProjectRequest{
		ID: "devops-project-platform", Name: "platform",
	}, scope, base)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := domain.NewSourceConnection(devopsv1.CreateSourceConnectionRequest{
		ID: "source-connection-primary", Name: "primary",
		Spec: devopsv1.SourceConnectionSpec{
			AdapterID: AdapterID, EndpointOrigin: endpointOrigin,
			WebhookSecretRef: "webhook-secret", FetchCredentialRef: "fetch-secret",
			ReportCredentialRef: "report-secret",
		},
	}, scope, base)
	if err != nil {
		t.Fatal(err)
	}
	connection.Status.Health = devopsv1.SourceConnectionReady
	connection.Status.Reason = devopsv1.SourceConnectionReasonObserved
	binding, err := domain.NewRepositoryBinding(devopsv1.CreateRepositoryBindingRequest{
		ID: "repository-binding-api", Name: "api", ProjectID: project.Metadata.ID,
		Spec: devopsv1.RepositoryBindingSpec{
			SourceConnectionID: connection.Metadata.ID, ExternalRepositoryID: "42",
			RepositoryPath: "matrix/service", TrustedDefaultBranch: "main",
		},
	}, project, connection, base)
	if err != nil {
		t.Fatal(err)
	}
	binding.Status.Health = devopsv1.RepositoryBindingReady
	binding.Status.Reason = devopsv1.RepositoryBindingReasonObserved
	pipeline, err := domain.NewPipeline(devopsv1.CreatePipelineRequest{
		ID: "pipeline-source", Name: "pipeline-source", ProjectID: project.Metadata.ID,
		Draft: devopsv1.PipelineDraftSpec{
			RepositoryBindingID: binding.Metadata.ID, TriggerPolicy: devopsv1.TriggerChange,
			VerificationProfile: devopsv1.VerificationGo126OfflineV1,
			DependencyEgress:    devopsv1.DependencyEgressNone,
			ReporterPolicy:      devopsv1.ReporterChangeCheckV1,
		},
	}, project, binding, base)
	if err != nil {
		t.Fatal(err)
	}
	activation, err := domain.ActivatePipeline(
		pipeline, pipeline.Metadata.ResourceVersion,
		devopsv1.SubjectRef{Kind: devopsv1.SubjectUser, ID: "user-alice"},
		binding, base.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	change := domain.NormalizedChange{
		Scope: scope, SourceConnectionID: connection.Metadata.ID,
		VerifiedSourceConnectionVersion: connection.Metadata.ResourceVersion,
		ExternalRepositoryID:            binding.Spec.ExternalRepositoryID,
		TrustedBaseBranch:               binding.Spec.TrustedDefaultBranch,
		DeliveryID:                      "123e4567-e89b-42d3-a456-426614174000",
		CanonicalPayloadDigest:          "sha256:" + strings.Repeat("a", 64),
		Change: devopsv1.ChangeIdentity{
			Number: 42, Action: devopsv1.ChangeOpened,
			HeadCommit: headCommit, TrustedBaseCommit: baseCommit,
		},
	}
	event, err := domain.NewSourceEvent(change, connection, binding, base.Add(2*time.Minute))
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
			TenantID: scope.TenantID, Run: run, Intent: intent,
			Mode: runlifecycle.ClaimExecute, WorkerID: "source-fetcher-one", FencingToken: 1,
			LeaseExpiresAt: run.UpdatedAt.Add(sourceacquisition.LeaseDuration),
		},
		Connection: connection, BindingRevision: binding,
		Revision: activation.Revision, Event: event,
	}
}
