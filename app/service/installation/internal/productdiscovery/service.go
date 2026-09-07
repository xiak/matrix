// Package productdiscovery owns the installation use case that projects the
// signed release product inventory and live product readiness to an
// authenticated Matrix user.
package productdiscovery

import (
	"context"
	"errors"
	"time"

	installationv1 "github.com/xiak/matrix/api/installation/v1"
	"github.com/xiak/matrix/app/service/installation/release"
)

var (
	ErrInvalidArgument          = errors.New("product discovery input is invalid")
	ErrUnauthenticated          = errors.New("product discovery authentication failed")
	ErrPermissionDenied         = errors.New("product discovery authorization denied")
	ErrAuthorizationUnavailable = errors.New("product discovery authorization is unavailable")
	ErrUnavailable              = errors.New("product discovery is unavailable")
)

const maximumObservationAge = 30 * time.Second

type AuthorizationRequest struct {
	Credential     string
	InstallationID string
	RequestID      string
}

type Authorizer interface {
	Ready(context.Context) error
	Authorize(context.Context, AuthorizationRequest) error
}

type ProductObservation struct {
	State      installationv1.ProductState
	Reason     installationv1.ProductReason
	ObservedAt time.Time
}

type ProductObserver interface {
	Observe(context.Context, installationv1.ProductID) (ProductObservation, error)
}

type Config struct {
	InstallationID string
	Now            func() time.Time
}

type Service struct {
	installationID string
	releaseID      string
	releaseVersion string
	products       []release.Product
	authorizer     Authorizer
	observer       ProductObserver
	now            func() time.Time
}

func NewService(
	manifest release.Manifest,
	authorizer Authorizer,
	observer ProductObserver,
	config Config,
) (*Service, error) {
	if authorizer == nil || observer == nil ||
		release.ValidateManifest(manifest) != nil ||
		config.InstallationID == "" {
		return nil, ErrInvalidArgument
	}
	now := config.Now
	if now == nil {
		now = time.Now
	}
	products := append([]release.Product(nil), manifest.Products...)
	return &Service{
		installationID: config.InstallationID,
		releaseID:      manifest.Release.ID,
		releaseVersion: manifest.Release.Version,
		products:       products,
		authorizer:     authorizer,
		observer:       observer,
		now:            now,
	}, nil
}

func (service *Service) List(
	ctx context.Context,
	credential string,
	requestID string,
) (installationv1.InstalledProductList, error) {
	if service == nil || ctx == nil || credential == "" || requestID == "" {
		return installationv1.InstalledProductList{}, ErrInvalidArgument
	}
	if err := service.authorizer.Authorize(ctx, AuthorizationRequest{
		Credential: credential, InstallationID: service.installationID, RequestID: requestID,
	}); err != nil {
		return installationv1.InstalledProductList{}, err
	}
	observedAt := service.now().UTC().Truncate(time.Microsecond)
	if !validClockTime(observedAt) {
		return installationv1.InstalledProductList{}, ErrUnavailable
	}
	products := make([]installationv1.InstalledProduct, 0, len(service.products))
	for _, declared := range service.products {
		id := installationv1.ProductID(declared.ID)
		observation, err := service.observer.Observe(ctx, id)
		if err != nil || invalidObservation(observation, observedAt) {
			observation = ProductObservation{
				State:      installationv1.ProductUnavailable,
				Reason:     installationv1.ReasonDependencyUnavailable,
				ObservedAt: observedAt,
			}
		} else if observedAt.Sub(observation.ObservedAt) > maximumObservationAge {
			observation.State = installationv1.ProductDegraded
			observation.Reason = installationv1.ReasonObservationStale
		}
		products = append(products, installationv1.InstalledProduct{
			ID: id, Version: declared.Version, RouteKey: declared.RouteKey,
			State: observation.State, Reason: observation.Reason,
			ObservedAt: observation.ObservedAt,
		})
	}
	result := installationv1.InstalledProductList{
		APIVersion:     installationv1.APIVersion,
		Kind:           "InstalledProductList",
		ReleaseID:      service.releaseID,
		ReleaseVersion: service.releaseVersion,
		Products:       products,
		ObservedAt:     observedAt,
	}
	if installationv1.ValidateInstalledProductList(result) != nil {
		return installationv1.InstalledProductList{}, ErrUnavailable
	}
	return result, nil
}

func (service *Service) Readiness(ctx context.Context) installationv1.Readiness {
	checkedAt := time.Now().UTC().Truncate(time.Microsecond)
	if service != nil && service.now != nil {
		checkedAt = service.now().UTC().Truncate(time.Microsecond)
	}
	result := installationv1.Readiness{
		APIVersion: installationv1.APIVersion,
		Kind:       "Readiness",
		State:      installationv1.ReadinessNotReady,
		CheckedAt:  checkedAt,
	}
	if service == nil || ctx == nil || !validClockTime(checkedAt) ||
		service.authorizer.Ready(ctx) != nil {
		return result
	}
	result.State = installationv1.ReadinessReady
	result.ReleaseID = service.releaseID
	if installationv1.ValidateReadiness(result) != nil {
		return installationv1.Readiness{
			APIVersion: installationv1.APIVersion,
			Kind:       "Readiness",
			State:      installationv1.ReadinessNotReady,
			CheckedAt:  checkedAt,
		}
	}
	return result
}

func invalidObservation(value ProductObservation, now time.Time) bool {
	product := installationv1.InstalledProduct{
		ID: installationv1.ProductApplicationPaaS, Version: "v0.1.0",
		RouteKey: "paas", State: value.State, Reason: value.Reason,
		ObservedAt: value.ObservedAt,
	}
	return installationv1.ValidateInstalledProduct(product) != nil ||
		value.ObservedAt.After(now)
}

func validClockTime(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC &&
		value == value.Round(0) && value.Nanosecond()%1_000 == 0
}
