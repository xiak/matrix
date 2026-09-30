package managedservicev1

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
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

func TestServiceRoleBindingContractHasNoAuthoritySelectors(t *testing.T) {
	template := iamv1.ServiceRoleTemplateReference{
		ID: "managedservice.installation-reader", Version: 1,
		ContentDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	request := BindServiceRoleRequest{Template: template}
	if err := ValidateBindServiceRoleRequest(request); err != nil {
		t.Fatalf("valid bind request rejected: %v", err)
	}
	for _, body := range []string{
		`{"template":{"id":"managedservice.installation-reader","version":1,"contentDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"accountId":"forged"}`,
		`{"template":{"id":"managedservice.installation-reader","version":1,"contentDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"roleId":"forged"}`,
		`{"template":{"id":"managedservice.installation-reader","version":1,"contentDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"installationId":"forged"}`,
		`{"template":{"id":"managedservice.installation-reader","version":1,"contentDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"purpose":"PAAS"}`,
	} {
		var decoded BindServiceRoleRequest
		if err := DecodeRequest(strings.NewReader(body), &decoded); err == nil {
			t.Fatalf("authority selector accepted: %s", body)
		}
	}
	now := time.Date(2026, 9, 30, 8, 0, 0, 0, time.UTC)
	receipt := ServiceRoleBindingReceipt{
		Kind: "ServiceRoleBindingReceipt", ServiceInstallationID: "postgres-primary",
		BindingID: "binding-one", RoleID: "role-one", Template: template,
		Status: iamv1.WorkloadRoleBindingActive, ResourceVersion: 1, CreatedAt: now,
	}
	if err := ValidateServiceRoleBindingReceipt(receipt); err != nil {
		t.Fatalf("valid binding receipt rejected: %v", err)
	}
	encoded, err := json.Marshal(receipt)
	if err != nil || strings.Contains(string(encoded), "accountId") || strings.Contains(string(encoded), "servicePrincipal") {
		t.Fatalf("receipt leaked authority selector: %s err=%v", encoded, err)
	}
}
