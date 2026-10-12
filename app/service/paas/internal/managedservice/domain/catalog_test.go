package domain

import (
	"testing"

	managedservicev1 "github.com/xiak/matrix/api/managedservice/v1"
)

func TestDefaultCatalogContainsOnlyImplementedProvidersAndIsDefensivelyCopied(t *testing.T) {
	catalog := DefaultCatalog()
	definitions := catalog.ListServices()
	offerings := catalog.List()
	if len(definitions) != 4 || len(offerings) != 4 ||
		offerings[0].ID != ElasticsearchOfferingID || offerings[0].Service.ID != managedservicev1.ElasticsearchServiceID ||
		offerings[1].ID != MySQLOfferingID || offerings[1].Service.ID != managedservicev1.MySQLServiceID ||
		offerings[2].ID != PostgreSQLOfferingID || offerings[2].Service.ID != managedservicev1.PostgreSQLServiceID ||
		offerings[3].ID != RabbitMQOfferingID || offerings[3].Service.ID != managedservicev1.RabbitMQServiceID {
		t.Fatalf("unexpected catalog: %#v", offerings)
	}
	definitions[0].DisplayName = "forged"
	if current, found := catalog.ResolveService(managedservicev1.ElasticsearchServiceID); !found || current.DisplayName == "forged" {
		t.Fatal("caller mutated the service-definition catalog")
	}
	offerings[0].QuotaShapes[0].ID = "forged"
	_, shape, found := catalog.Resolve(PostgreSQLOfferingID, "pg-medium")
	if !found || shape.ID != "pg-medium" {
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
