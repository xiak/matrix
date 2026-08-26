package domain

import (
	"testing"

	managedservicev1 "github.com/xiak/matrix/api/managedservice/v1"
)

func TestDefaultCatalogIsClosedAndDefensivelyCopied(t *testing.T) {
	catalog := DefaultCatalog()
	offerings := catalog.List()
	if len(offerings) != 1 || offerings[0].ID != PostgreSQLOfferingID ||
		offerings[0].Kind != managedservicev1.OfferingPostgreSQL {
		t.Fatalf("unexpected catalog: %#v", offerings)
	}
	offerings[0].QuotaShapes[0].ID = "forged"
	_, shape, found := catalog.Resolve(PostgreSQLOfferingID, "pg-medium")
	if !found || shape.ID != "pg-medium" {
		t.Fatal("caller mutated the catalog")
	}
}

func TestCatalogRejectsSpeculativeProducts(t *testing.T) {
	offering := DefaultCatalog().List()[0]
	offering.ID = "mysql-9"
	if _, err := NewCatalog([]managedservicev1.ServiceOffering{offering}); err == nil {
		t.Fatal("unsupported offering was accepted")
	}
}
