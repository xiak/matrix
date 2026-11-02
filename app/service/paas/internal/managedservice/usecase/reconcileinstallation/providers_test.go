package reconcileinstallation

import (
	"context"
	"testing"

	managedserviceadapterv1 "github.com/xiak/matrix/api/adapter/managedservice/v1"
	managedservicev1 "github.com/xiak/matrix/api/managedservice/v1"
	"github.com/xiak/matrix/app/service/paas/internal/managedservice/domain"
)

func TestProviderRegistryRequiresAndRoutesEveryReleasedOffering(t *testing.T) {
	catalog := domain.DefaultCatalog()
	providers := map[string]managedserviceadapterv1.Provisioner{}
	for _, offering := range catalog.List() {
		providers[offering.ID] = &registryProvider{result: managedserviceadapterv1.ProvisionResult{
			Endpoint: "127.0.0.1:25432", CredentialReference: "credential-" + offering.ID,
		}}
	}
	mysql := providers[managedservicev1.MySQLOfferingID].(*registryProvider)
	postgres := providers[managedservicev1.PostgreSQLOfferingID].(*registryProvider)
	registry, err := NewProviderRegistry(catalog, providers)
	if err != nil {
		t.Fatalf("new provider registry: %v", err)
	}
	request := registryProvisionRequest(managedservicev1.MySQLOfferingID, "8.4", "mysql-small")
	result, err := registry.Ensure(context.Background(), request)
	if err != nil || result != mysql.result || mysql.calls != 1 || postgres.calls != 0 {
		t.Fatalf("route result=%#v err=%v mysql=%d postgres=%d", result, err, mysql.calls, postgres.calls)
	}
	deprovision := managedserviceadapterv1.DeprovisionRequest{
		TenantID: request.TenantID, InstallationID: request.InstallationID,
		OperationID: "operation-delete", OfferingID: request.OfferingID,
		EngineVersion: request.EngineVersion, RegionID: request.RegionID,
	}
	if err := registry.Delete(context.Background(), deprovision); err != nil || mysql.deleteCalls != 1 ||
		mysql.deleteRequest != deprovision || postgres.deleteCalls != 0 {
		t.Fatalf("delete route err=%v mysql=%#v postgres=%#v", err, mysql, postgres)
	}
	if err := registry.Ready(context.Background()); err != nil {
		t.Fatal(err)
	}
	for id, value := range providers {
		if value.(*registryProvider).readyCalls != 1 {
			t.Fatalf("provider %s was not checked", id)
		}
	}
}

func TestProviderRegistryRejectsMissingExtraAndUnknownProviders(t *testing.T) {
	catalog := domain.DefaultCatalog()
	provider := &registryProvider{}
	providers := map[string]managedserviceadapterv1.Provisioner{}
	for _, offering := range catalog.List() {
		providers[offering.ID] = provider
	}
	for _, offering := range catalog.List() {
		id := offering.ID
		delete(providers, id)
		if _, err := NewProviderRegistry(catalog, providers); err == nil {
			t.Fatal("missing provider accepted")
		}
		providers[id] = provider
	}
	providers["unreleased"] = provider
	if _, err := NewProviderRegistry(catalog, providers); err == nil {
		t.Fatal("unreleased provider accepted")
	}
	delete(providers, "unreleased")
	registry, err := NewProviderRegistry(catalog, providers)
	if err != nil {
		t.Fatal(err)
	}
	request := registryProvisionRequest("unknown-product", "1", "unknown-small")
	if _, err := registry.Ensure(context.Background(), request); err == nil || provider.calls != 0 {
		t.Fatal("unknown product reached a provider")
	}
}

func registryProvisionRequest(offeringID, version, shapeID string) managedserviceadapterv1.ProvisionRequest {
	return managedserviceadapterv1.ProvisionRequest{
		TenantID: "organization-test", InstallationID: "service-primary",
		OperationID: "operation-test", OfferingID: offeringID,
		EngineVersion: version, RegionID: "local-primary",
		QuotaShape: managedservicev1.QuotaShape{
			ID: shapeID, DisplayName: "开发型",
			CPUMillicores: 500, MemoryMiB: 1024, StorageGiB: 10,
		},
	}
}

type registryProvider struct {
	result        managedserviceadapterv1.ProvisionResult
	error         error
	calls         int
	deleteCalls   int
	deleteRequest managedserviceadapterv1.DeprovisionRequest
	readyCalls    int
}

func (provider *registryProvider) Ensure(
	_ context.Context,
	_ managedserviceadapterv1.ProvisionRequest,
) (managedserviceadapterv1.ProvisionResult, error) {
	provider.calls++
	return provider.result, provider.error
}

func (provider *registryProvider) Delete(
	_ context.Context,
	request managedserviceadapterv1.DeprovisionRequest,
) error {
	provider.deleteCalls++
	provider.deleteRequest = request
	return provider.error
}

func (provider *registryProvider) Ready(context.Context) error {
	provider.readyCalls++
	return provider.error
}
