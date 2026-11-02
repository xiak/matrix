package domain

import (
	"testing"

	managedservicev1 "github.com/xiak/matrix/api/managedservice/v1"
)

func TestDefaultCatalogContainsOnlyImplementedProvidersAndIsDefensivelyCopied(t *testing.T) {
	catalog := DefaultCatalog()
	definitions := catalog.ListServices()
	offerings := catalog.List()
	expected := map[string]string{
		PostgreSQLOfferingID:    managedservicev1.PostgreSQLServiceID,
		MySQLOfferingID:         managedservicev1.MySQLServiceID,
		ElasticsearchOfferingID: managedservicev1.ElasticsearchServiceID,
		RabbitMQOfferingID:      managedservicev1.RabbitMQServiceID,
		LogstashOfferingID:      managedservicev1.LogstashServiceID,
	}
	if len(definitions) != len(expected) || len(offerings) != len(expected) {
		t.Fatal("released service and offering inventories disagree")
	}
	for _, offering := range offerings {
		if expected[offering.ID] != offering.Service.ID {
			t.Fatalf("unimplemented or mismatched offering %q", offering.ID)
		}
		definition, found := catalog.ResolveService(offering.Service.ID)
		if !found || referenceOf(definition) != offering.Service {
			t.Fatal("offering does not bind the exact current service definition")
		}
	}
	definitions[0].DisplayName = "forged"
	if current, found := catalog.ResolveService(managedservicev1.ElasticsearchServiceID); !found || current.DisplayName == "forged" {
		t.Fatal("caller mutated the service-definition catalog")
	}
	originalShape := offerings[0].QuotaShapes[0]
	offerings[0].QuotaShapes[0].ID = "forged"
	_, shape, found := catalog.Resolve(offerings[0].ID, originalShape.ID)
	if !found || shape != originalShape {
		t.Fatal("caller mutated the catalog")
	}
}

func TestCatalogRejectsBrokenReferencesAndDuplicatesButAcceptsArbitraryServiceNames(t *testing.T) {
	base := DefaultCatalog()
	definition := base.ListServices()[0]
	offering := base.List()[0]
	offering.Service.ID = "other-service"
	if _, err := NewCatalog([]managedservicev1.ServiceDefinition{definition}, []managedservicev1.ServiceOffering{offering}); err == nil {
		t.Fatal("offering with an unknown service reference was accepted")
	}
	offering = base.List()[0]
	if _, err := NewCatalog([]managedservicev1.ServiceDefinition{definition}, []managedservicev1.ServiceOffering{offering, offering}); err == nil {
		t.Fatal("duplicate offering was accepted")
	}

	arbitrary := newDefinition("vector-search", "Vector search", "A synthetic contract fixture.")
	offering = base.List()[0]
	offering.ID = "vector-search-1"
	offering.Service = referenceOf(arbitrary)
	offering.EngineFamily = "vector-search"
	offering.EngineVersion = "1"
	if _, err := NewCatalog([]managedservicev1.ServiceDefinition{arbitrary}, []managedservicev1.ServiceOffering{offering}); err != nil {
		t.Fatalf("arbitrary service required a name branch: %v", err)
	}
}
