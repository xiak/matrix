package managedservicev1

import (
	"strings"
	"testing"
	"time"
)

func TestRequestsRejectNativeAndTenantFieldsAtDecodeBoundary(t *testing.T) {
	for _, body := range []string{
		`{"offeringId":"postgresql-18","quotaShapeId":"pg-small","instanceCount":1,"price":1}`,
		`{"id":"postgres-primary","name":"Postgres","offeringId":"postgresql-18","quotaEntitlementId":"quota-1","regionId":"local-primary","organizationId":"forged"}`,
		`{"id":"postgres-primary","name":"Postgres","offeringId":"postgresql-18","quotaEntitlementId":"quota-1","regionId":"local-primary","image":"postgres:latest"}`,
	} {
		var destination any
		if strings.Contains(body, `"instanceCount"`) {
			destination = &ActivateQuotaRequest{}
		} else {
			destination = &CreateInstallationRequest{}
		}
		if err := DecodeRequest(strings.NewReader(body), destination); err == nil {
			t.Fatalf("unknown field was accepted: %s", body)
		}
	}
}

func TestServiceInstallationPhaseContract(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	value := ServiceInstallation{
		ID: "postgres-primary", Name: "Postgres primary", OfferingID: "postgresql-18",
		EngineVersion: "18", QuotaEntitlementID: "quota-1", RegionID: "local-primary",
		Phase: InstallationPending, CreatedAt: now,
		Operation: InstallationOperation{ID: "operation-1", Phase: InstallationPending, ObservedAt: now},
	}
	if err := ValidateServiceInstallation(value); err != nil {
		t.Fatalf("pending installation rejected: %v", err)
	}
	endpoint, credential := "127.0.0.1:55432", "credential-postgres-primary"
	value.Phase = InstallationReady
	value.Operation.Phase = InstallationReady
	value.Endpoint = &endpoint
	value.CredentialReference = &credential
	if err := ValidateServiceInstallation(value); err != nil {
		t.Fatalf("ready installation rejected: %v", err)
	}
	value.Endpoint = nil
	if err := ValidateServiceInstallation(value); err == nil {
		t.Fatal("ready installation without endpoint was accepted")
	}
}

func TestQuotaUsageCannotExceedPurchasedCount(t *testing.T) {
	value := QuotaEntitlement{
		ID: "quota-1", OfferingID: "postgresql-18", QuotaShapeID: "pg-small",
		PurchasedCount: 1, ReservedCount: 1, ConsumedCount: 1, ResourceVersion: 1,
		ActivatedAt: time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC),
	}
	if err := ValidateQuotaEntitlement(value); err == nil {
		t.Fatal("over-consumed quota was accepted")
	}
}
