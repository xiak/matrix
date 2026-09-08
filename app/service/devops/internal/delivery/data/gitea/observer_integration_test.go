package gitea

import (
	"bytes"
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
	defer server.Close()
	if server.URL != endpointText {
		t.Fatalf("Gitea test endpoint=%q want=%q", server.URL, endpointText)
	}

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

type realRepository struct {
	ID            int64  `json:"id"`
	FullName      string `json:"full_name"`
	DefaultBranch string `json:"default_branch"`
}

type realToken struct {
	Name  string `json:"name"`
	value string
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
