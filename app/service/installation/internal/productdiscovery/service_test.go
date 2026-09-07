package productdiscovery

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	installationv1 "github.com/xiak/matrix/api/installation/v1"
	"github.com/xiak/matrix/app/service/installation/internal/releasetest"
)

func TestListAuthorizesAndProjectsOnlySignedProducts(t *testing.T) {
	now := discoveryTime()
	authorizer := &recordingAuthorizer{}
	observer := &recordingObserver{observations: map[installationv1.ProductID]ProductObservation{
		installationv1.ProductApplicationPaaS: {
			State: installationv1.ProductReady, ObservedAt: now,
		},
	}}
	service := newTestService(t, authorizer, observer, now)
	result, err := service.List(context.Background(), "Bearer credential", "request-products")
	if err != nil {
		t.Fatal(err)
	}
	if result.ReleaseID != releasetest.Manifest().Release.ID ||
		result.ReleaseVersion != "v0.1.0" ||
		len(result.Products) != 1 ||
		result.Products[0].ID != installationv1.ProductApplicationPaaS ||
		result.Products[0].RouteKey != "paas" ||
		result.Products[0].State != installationv1.ProductReady {
		t.Fatalf("installed product projection = %#v", result)
	}
	if authorizer.request.InstallationID != "installation-example" ||
		authorizer.request.RequestID != "request-products" ||
		authorizer.request.Credential != "Bearer credential" {
		t.Fatalf("authorization request = %#v", authorizer.request)
	}
	if !slices.Equal(observer.observed, []installationv1.ProductID{
		installationv1.ProductApplicationPaaS,
	}) {
		t.Fatalf("observed products = %v", observer.observed)
	}
}

func TestListNormalizesUnavailableAndStaleProductObservation(t *testing.T) {
	now := discoveryTime()
	for name, observation := range map[string]ProductObservation{
		"unavailable": {},
		"stale": {
			State: installationv1.ProductReady, ObservedAt: now.Add(-maximumObservationAge - time.Microsecond),
		},
	} {
		t.Run(name, func(t *testing.T) {
			observer := &recordingObserver{observations: map[installationv1.ProductID]ProductObservation{
				installationv1.ProductApplicationPaaS: observation,
			}}
			if name == "unavailable" {
				observer.err = errors.New("native dependency details")
			}
			service := newTestService(t, &recordingAuthorizer{}, observer, now)
			result, err := service.List(context.Background(), "Bearer credential", "request-products")
			if err != nil {
				t.Fatal(err)
			}
			product := result.Products[0]
			if name == "unavailable" &&
				(product.State != installationv1.ProductUnavailable ||
					product.Reason != installationv1.ReasonDependencyUnavailable) {
				t.Fatalf("unavailable product = %#v", product)
			}
			if name == "stale" &&
				(product.State != installationv1.ProductDegraded ||
					product.Reason != installationv1.ReasonObservationStale) {
				t.Fatalf("stale product = %#v", product)
			}
		})
	}
}

func TestListFailsBeforeObservationWhenAuthorizationFails(t *testing.T) {
	authorizer := &recordingAuthorizer{err: ErrPermissionDenied}
	observer := &recordingObserver{}
	service := newTestService(t, authorizer, observer, discoveryTime())
	_, err := service.List(context.Background(), "Bearer denied", "request-denied")
	if !errors.Is(err, ErrPermissionDenied) || len(observer.observed) != 0 {
		t.Fatalf("authorization failure = %v observations=%v", err, observer.observed)
	}
}

func TestReadinessBindsSignedReleaseAndIAM(t *testing.T) {
	now := discoveryTime()
	authorizer := &recordingAuthorizer{}
	service := newTestService(t, authorizer, &recordingObserver{}, now)
	ready := service.Readiness(context.Background())
	if ready.State != installationv1.ReadinessReady ||
		ready.ReleaseID != releasetest.Manifest().Release.ID {
		t.Fatalf("ready discovery = %#v", ready)
	}
	authorizer.readyErr = errors.New("IAM unavailable")
	notReady := service.Readiness(context.Background())
	if notReady.State != installationv1.ReadinessNotReady || notReady.ReleaseID != "" {
		t.Fatalf("not-ready discovery = %#v", notReady)
	}
}

func newTestService(
	t *testing.T,
	authorizer Authorizer,
	observer ProductObserver,
	now time.Time,
) *Service {
	t.Helper()
	service, err := NewService(releasetest.Manifest(), authorizer, observer, Config{
		InstallationID: "installation-example",
		Now:            func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

type recordingAuthorizer struct {
	request  AuthorizationRequest
	err      error
	readyErr error
}

func (value *recordingAuthorizer) Ready(context.Context) error {
	return value.readyErr
}

func (value *recordingAuthorizer) Authorize(
	_ context.Context,
	request AuthorizationRequest,
) error {
	value.request = request
	return value.err
}

type recordingObserver struct {
	observations map[installationv1.ProductID]ProductObservation
	observed     []installationv1.ProductID
	err          error
}

func (value *recordingObserver) Observe(
	_ context.Context,
	id installationv1.ProductID,
) (ProductObservation, error) {
	value.observed = append(value.observed, id)
	return value.observations[id], value.err
}

func discoveryTime() time.Time {
	return time.Date(2026, 9, 7, 3, 4, 5, 0, time.UTC)
}
