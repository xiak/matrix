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
	postgres := &registryProvider{result: managedserviceadapterv1.ProvisionResult{
		Endpoint: "127.0.0.1:25432", CredentialReference: "credential-postgres",
	}}
	mysql := &registryProvider{result: managedserviceadapterv1.ProvisionResult{
		Endpoint: "127.0.0.1:23306", CredentialReference: "credential-mysql",
	}}
	elasticsearch := &registryProvider{result: managedserviceadapterv1.ProvisionResult{
		Endpoint: "http://127.0.0.1:29200", CredentialReference: "credential-elasticsearch",
	}}
	rabbitmq := &registryProvider{result: managedserviceadapterv1.ProvisionResult{
		Endpoint: "amqp://127.0.0.1:25672/matrix", CredentialReference: "credential-rabbitmq",
	}}
	registry, err := NewProviderRegistry(catalog, map[string]Provisioner{
		managedservicev1.PostgreSQLOfferingID:    postgres,
		managedservicev1.MySQLOfferingID:         mysql,
		managedservicev1.ElasticsearchOfferingID: elasticsearch,
		managedservicev1.RabbitMQOfferingID:      rabbitmq,
	})
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
	if err := registry.Ready(context.Background()); err != nil || mysql.readyCalls != 1 || postgres.readyCalls != 1 ||
		elasticsearch.readyCalls != 1 || rabbitmq.readyCalls != 1 {
		t.Fatalf("registry readiness err=%v mysql=%d postgres=%d elasticsearch=%d rabbitmq=%d",
			err, mysql.readyCalls, postgres.readyCalls, elasticsearch.readyCalls, rabbitmq.readyCalls)
	}
}

func TestProviderRegistryRejectsMissingExtraAndUnknownProviders(t *testing.T) {
	catalog := domain.DefaultCatalog()
	provider := &registryProvider{}
	for name, providers := range map[string]map[string]Provisioner{
		"missing": {managedservicev1.PostgreSQLOfferingID: provider},
		"extra": {
			managedservicev1.PostgreSQLOfferingID:    provider,
			managedservicev1.MySQLOfferingID:         provider,
			managedservicev1.ElasticsearchOfferingID: provider,
			managedservicev1.RabbitMQOfferingID:      provider,
			"unreleased":                             provider,
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewProviderRegistry(catalog, providers); err == nil {
				t.Fatal("provider/catalog mismatch was accepted")
			}
		})
	}
	registry, err := NewProviderRegistry(catalog, map[string]Provisioner{
		managedservicev1.PostgreSQLOfferingID:    provider,
		managedservicev1.MySQLOfferingID:         provider,
		managedservicev1.ElasticsearchOfferingID: provider,
		managedservicev1.RabbitMQOfferingID:      provider,
	})
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
