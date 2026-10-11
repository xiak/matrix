package domain

import (
	"testing"

	managedservicev1 "github.com/xiak/matrix/api/managedservice/v1"
)

func TestDefaultCatalogContainsOnlyImplementedProvidersAndIsDefensivelyCopied(t *testing.T) {
	catalog := DefaultCatalog()
	offerings := catalog.List()
	if len(offerings) != 2 || offerings[0].ID != MySQLOfferingID ||
		offerings[0].Kind != managedservicev1.OfferingMySQL ||
		offerings[1].ID != PostgreSQLOfferingID ||
		offerings[1].Kind != managedservicev1.OfferingPostgreSQL {
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
