package reconcileinstallation

import (
	"context"
	"errors"
	"slices"

	managedserviceadapterv1 "github.com/xiak/matrix/api/adapter/managedservice/v1"
	"github.com/xiak/matrix/app/service/paas/internal/managedservice/domain"
)

// ProviderRegistry closes the mapping between a released offering and the
// provider that can produce its real effect. A catalog entry without a
// provider, or an unlisted provider, is rejected before the worker starts.
type ProviderRegistry struct {
	providers map[string]Provisioner
	order     []string
}

func NewProviderRegistry(
	catalog domain.Catalog,
	providers map[string]Provisioner,
) (*ProviderRegistry, error) {
	offerings := catalog.List()
	if len(offerings) == 0 || len(providers) != len(offerings) {
		return nil, errors.New("managed-service provider registry does not match its catalog")
	}
	copy := make(map[string]Provisioner, len(providers))
	order := make([]string, 0, len(offerings))
	for _, offering := range offerings {
		provider, exists := providers[offering.ID]
		if !exists || provider == nil {
			return nil, errors.New("managed-service provider registry does not match its catalog")
		}
		copy[offering.ID] = provider
		order = append(order, offering.ID)
	}
	slices.Sort(order)
	return &ProviderRegistry{providers: copy, order: order}, nil
}

func (registry *ProviderRegistry) Ensure(
	ctx context.Context,
	request managedserviceadapterv1.ProvisionRequest,
) (managedserviceadapterv1.ProvisionResult, error) {
	if registry == nil || ctx == nil ||
		managedserviceadapterv1.ValidateProvisionRequest(request) != nil {
		return managedserviceadapterv1.ProvisionResult{}, errors.New("managed-service provider request is invalid")
	}
	provider, exists := registry.providers[request.OfferingID]
	if !exists {
		return managedserviceadapterv1.ProvisionResult{}, errors.New("managed-service provider is not registered")
	}
	return provider.Ensure(ctx, request)
}

func (registry *ProviderRegistry) Ready(ctx context.Context) error {
	if registry == nil || ctx == nil {
		return errors.New("managed-service provider registry is unavailable")
	}
	for _, offeringID := range registry.order {
		if err := registry.providers[offeringID].Ready(ctx); err != nil {
			return errors.New("managed-service provider is unavailable")
		}
	}
	return nil
}
