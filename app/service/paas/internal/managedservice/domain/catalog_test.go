package domain

import (
	"testing"

	managedservicev1 "github.com/xiak/matrix/api/managedservice/v1"
)

func TestDefaultCatalogContainsOnlyImplementedProvidersAndIsDefensivelyCopied(t *testing.T) {
	catalog := DefaultCatalog()
	offerings := catalog.List()
	if len(offerings) != 4 ||
		offerings[0].ID != ElasticsearchOfferingID || offerings[0].Kind != managedservicev1.OfferingElasticsearch ||
		offerings[1].ID != MySQLOfferingID || offerings[1].Kind != managedservicev1.OfferingMySQL ||
		offerings[2].ID != PostgreSQLOfferingID || offerings[2].Kind != managedservicev1.OfferingPostgreSQL ||
		offerings[3].ID != RabbitMQOfferingID || offerings[3].Kind != managedservicev1.OfferingRabbitMQ {
		t.Fatalf("unexpected catalog: %#v", offerings)
	}
	offerings[0].QuotaShapes[0].ID = "forged"
	_, shape, found := catalog.Resolve(PostgreSQLOfferingID, "pg-medium")
	if !found || shape.ID != "pg-medium" {
		t.Fatal("caller mutated the catalog")
	}
}

func TestCatalogRejectsUnknownAndDuplicateProducts(t *testing.T) {
	offering := DefaultCatalog().List()[0]
	offering.ID = "unknown-product"
	offering.Kind = "UNKNOWN"
	if _, err := NewCatalog([]managedservicev1.ServiceOffering{offering}); err == nil {
		t.Fatal("unknown offering was accepted")
	}
	offering = DefaultCatalog().List()[0]
	if _, err := NewCatalog([]managedservicev1.ServiceOffering{offering, offering}); err == nil {
		t.Fatal("duplicate offering was accepted")
	}
}
