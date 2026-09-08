package gitea

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/domain"
	"github.com/xiak/matrix/app/service/devops/sourcecredential"
)

const (
	observerWebhook = "observer-webhook-secret-0000000001"
	observerFetch   = "observer-fetch-token-000000000000001"
	observerReport  = "observer-report-token-0000000000001"
)

func TestObserverProvesFixedGiteaConnectionAndRepositoryPermissions(t *testing.T) {
	server := newObserverServer(t, observerServerMode{})
	defer server.Close()
	observer := observerForServer(t, server)
	connection := observerConnection(server.URL)

	connectionObservation, err := observer.ObserveSourceConnection(context.Background(), connection)
	if err != nil || connectionObservation.Health != devopsv1.SourceConnectionReady ||
		connectionObservation.Reason != devopsv1.SourceConnectionReasonObserved {
		t.Fatalf("connection observation=%#v err=%v", connectionObservation, err)
	}
	binding := observerBinding(t, connection)
	bindingObservation, err := observer.ObserveRepositoryBinding(
		context.Background(), connection, binding,
	)
	if err != nil || bindingObservation.Health != devopsv1.RepositoryBindingReady ||
		bindingObservation.Reason != devopsv1.RepositoryBindingReasonObserved {
		t.Fatalf("binding observation=%#v err=%v", bindingObservation, err)
	}
}

func TestConnectionObservationFailsClosedWithNormalizedReasons(t *testing.T) {
	tests := []struct {
		name          string
		mode          observerServerMode
		resolverError error
		reason        devopsv1.SourceConnectionHealthReason
	}{
		{name: "secret", resolverError: errors.New("private path unavailable"), reason: devopsv1.SourceConnectionReasonSecretUnavailable},
		{name: "unsupported version", mode: observerServerMode{version: "1.28.0"}, reason: devopsv1.SourceConnectionReasonProviderUnsupported},
		{name: "credential rejected", mode: observerServerMode{rejectUser: true}, reason: devopsv1.SourceConnectionReasonCredentialRejected},
		{name: "ambiguous JSON", mode: observerServerMode{duplicateVersion: true}, reason: devopsv1.SourceConnectionReasonProviderUnavailable},
		{name: "redirect", mode: observerServerMode{redirectVersion: true}, reason: devopsv1.SourceConnectionReasonProviderUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := newObserverServer(t, test.mode)
			defer server.Close()
			observer := observerForServer(t, server)
			if test.resolverError != nil {
				observer.webhook = staticCredentialResolver{purpose: sourcecredential.PurposeWebhook, err: test.resolverError}
			}
			observation, err := observer.ObserveSourceConnection(
				context.Background(), observerConnection(server.URL),
			)
			if err != nil || observation.Health != devopsv1.SourceConnectionUnavailable ||
				observation.Reason != test.reason {
				t.Fatalf("observation=%#v err=%v", observation, err)
			}
		})
	}
}

func TestRepositoryObservationDistinguishesIdentityAndPermissions(t *testing.T) {
	tests := []struct {
		name   string
		mode   observerServerMode
		reason devopsv1.RepositoryBindingHealthReason
	}{
		{name: "missing repository", mode: observerServerMode{missingRepository: true}, reason: devopsv1.RepositoryBindingReasonRepositoryUnavailable},
		{name: "identity mismatch", mode: observerServerMode{mismatchIdentity: true}, reason: devopsv1.RepositoryBindingReasonIdentityMismatch},
		{name: "fetch denied", mode: observerServerMode{denyFetch: true}, reason: devopsv1.RepositoryBindingReasonFetchPermissionDenied},
		{name: "report denied", mode: observerServerMode{denyReport: true}, reason: devopsv1.RepositoryBindingReasonReportPermissionDenied},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := newObserverServer(t, test.mode)
			defer server.Close()
			observer := observerForServer(t, server)
			connection := observerConnection(server.URL)
			observation, err := observer.ObserveRepositoryBinding(
				context.Background(), connection, observerBinding(t, connection),
			)
			if err != nil || observation.Health != devopsv1.RepositoryBindingUnavailable ||
				observation.Reason != test.reason {
				t.Fatalf("observation=%#v err=%v", observation, err)
			}
		})
	}
}

func TestObserverRequestDeadlineAndCancellationDoNotBecomeHealthFacts(t *testing.T) {
	server := newObserverServer(t, observerServerMode{delay: 100 * time.Millisecond})
	defer server.Close()
	observer := observerForServer(t, server)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := observer.ObserveSourceConnection(ctx, observerConnection(server.URL)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cancelled observation error=%v", err)
	}
}

type staticCredentialResolver struct {
	purpose sourcecredential.Purpose
	value   string
	err     error
}

func (resolver staticCredentialResolver) Resolve(
	context.Context,
	devopsv1.ResourceScope,
	devopsv1.ResourceID,
) (sourcecredential.Material, error) {
	if resolver.err != nil {
		return sourcecredential.Material{}, resolver.err
	}
	return sourcecredential.NewMaterial(resolver.purpose, []byte(resolver.value), nil)
}

type observerServerMode struct {
	version           string
	rejectUser        bool
	duplicateVersion  bool
	redirectVersion   bool
	missingRepository bool
	mismatchIdentity  bool
	denyFetch         bool
	denyReport        bool
	delay             time.Duration
}

func newObserverServer(t *testing.T, mode observerServerMode) *httptest.Server {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if mode.delay > 0 {
			timer := time.NewTimer(mode.delay)
			defer timer.Stop()
			select {
			case <-request.Context().Done():
				return
			case <-timer.C:
			}
		}
		response.Header().Set("Content-Type", "application/json; charset=utf-8")
		switch request.URL.Path {
		case "/api/v1/version":
			if request.Header.Get("Authorization") != "" {
				t.Error("version probe carried a credential")
			}
			if mode.redirectVersion {
				http.Redirect(response, request, "/other", http.StatusFound)
				return
			}
			version := mode.version
			if version == "" {
				version = SupportedVersion
			}
			if mode.duplicateVersion {
				_, _ = fmt.Fprintf(response, `{"version":%q,"Version":%q}`, version, version)
				return
			}
			_, _ = fmt.Fprintf(response, `{"version":%q}`, version)
		case "/api/v1/user":
			if mode.rejectUser {
				response.WriteHeader(http.StatusUnauthorized)
				return
			}
			token := strings.TrimPrefix(request.Header.Get("Authorization"), "token ")
			if token != observerFetch && token != observerReport {
				response.WriteHeader(http.StatusUnauthorized)
				return
			}
			_, _ = fmt.Fprintf(response, `{"id":1,"login":%q}`, token[:8])
		case "/api/v1/repos/matrix/service":
			if mode.missingRepository {
				response.WriteHeader(http.StatusNotFound)
				return
			}
			token := strings.TrimPrefix(request.Header.Get("Authorization"), "token ")
			pull := token == observerFetch && !mode.denyFetch || token == observerReport
			push := token == observerReport && !mode.denyReport
			fullName := "matrix/service"
			if mode.mismatchIdentity {
				fullName = "matrix/other"
			}
			_, _ = fmt.Fprintf(response,
				`{"id":42,"full_name":%q,"url":%q,"html_url":%q,"clone_url":%q,"default_branch":"main","permissions":{"pull":%t,"push":%t}}`,
				fullName, serverURL(request)+"/api/v1/repos/matrix/service",
				serverURL(request)+"/matrix/service", serverURL(request)+"/matrix/service.git",
				pull, push,
			)
		default:
			response.WriteHeader(http.StatusNotFound)
		}
	}))
	return server
}

func observerForServer(t *testing.T, server *httptest.Server) *Observer {
	t.Helper()
	client := server.Client()
	client.Timeout = requestTimeout
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return errors.New("redirect rejected")
	}
	observer, err := newObserver(
		staticCredentialResolver{purpose: sourcecredential.PurposeWebhook, value: observerWebhook},
		staticCredentialResolver{purpose: sourcecredential.PurposeFetch, value: observerFetch},
		staticCredentialResolver{purpose: sourcecredential.PurposeReport, value: observerReport},
		client,
	)
	if err != nil {
		t.Fatal(err)
	}
	return observer
}

func observerConnection(endpoint string) devopsv1.SourceConnection {
	connection := validConnection()
	connection.Spec.EndpointOrigin = endpoint
	return connection
}

func observerBinding(t *testing.T, connection devopsv1.SourceConnection) devopsv1.RepositoryBinding {
	t.Helper()
	project := devopsv1.DevOpsProject{
		APIVersion: devopsv1.APIVersion, Kind: "DevOpsProject",
		Metadata: devopsv1.ResourceMetadata{
			ID: "project-gitea", Name: "project-gitea", Scope: connection.Metadata.Scope,
			ResourceVersion: 1, CreatedAt: connection.Metadata.CreatedAt,
			UpdatedAt: connection.Metadata.CreatedAt,
		},
	}
	binding, err := domain.NewRepositoryBinding(
		devopsv1.CreateRepositoryBindingRequest{
			ID: "binding-gitea", Name: "binding-gitea", ProjectID: project.Metadata.ID,
			Spec: devopsv1.RepositoryBindingSpec{
				SourceConnectionID:   connection.Metadata.ID,
				ExternalRepositoryID: "42", RepositoryPath: "matrix/service",
				TrustedDefaultBranch: "main",
			},
		},
		project, connection, connection.Metadata.CreatedAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	return binding
}

func serverURL(request *http.Request) string {
	return "https://" + request.Host
}
