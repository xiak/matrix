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
		`{"service":{"id":"postgresql","revision":1,"contentDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"tenantId":"forged"}`,
		`{"offeringId":"postgresql-18","quotaShapeId":"pg-small","instanceCount":1,"price":1}`,
		`{"id":"postgres-primary","name":"Postgres","offeringId":"postgresql-18","quotaEntitlementId":"quota-1","regionId":"local-primary","organizationId":"forged"}`,
		`{"id":"postgres-primary","name":"Postgres","offeringId":"postgresql-18","quotaEntitlementId":"quota-1","regionId":"local-primary","image":"postgres:latest"}`,
	} {
		var destination any
		if strings.Contains(body, `"service"`) {
			destination = &ActivateServiceRequest{}
		} else if strings.Contains(body, `"instanceCount"`) {
			destination = &ActivateQuotaRequest{}
		} else {
			destination = &CreateInstallationRequest{}
		}
		if err := DecodeRequest(strings.NewReader(body), destination); err == nil {
			t.Fatalf("unknown field was accepted: %s", body)
		}
	}
}

func TestServiceDefinitionCanonicalContractIgnoresDisplayAndAvailability(t *testing.T) {
	definition := ServiceDefinition{
		ID: "vector-search", DisplayName: "Vector search", Description: "Managed vector search.",
		Revision: 1, ActivationPrerequisite: ServiceActivationPermissionOnly,
		State: ServiceDefinitionAvailable,
	}
	document, digest, err := CanonicalizeServiceDefinition(definition)
	if err != nil || document == "" || digest == "" {
		t.Fatalf("canonicalize service definition: document=%q digest=%q err=%v", document, digest, err)
	}
	definition.ContentDigest = digest
	if err := ValidateServiceDefinition(definition); err != nil {
		t.Fatalf("valid service definition rejected: %v", err)
	}
	changedDisplay := definition
	changedDisplay.DisplayName = "Renamed vector search"
	changedDisplay.Description = "Updated non-authoritative display metadata."
	changedDisplay.State = ServiceDefinitionUnavailable
	_, changedDigest, err := CanonicalizeServiceDefinition(changedDisplay)
	if err != nil || changedDigest != digest || ValidateServiceDefinition(changedDisplay) != nil {
		t.Fatal("display metadata or availability reinterpreted the activation contract")
	}
	changedRevision := definition
	changedRevision.Revision++
	if _, changedDigest, err = CanonicalizeServiceDefinition(changedRevision); err != nil || changedDigest == digest {
		t.Fatal("contract revision did not change the service definition digest")
	}
	unsupported := definition
	unsupported.ActivationPrerequisite = "ROOT_ONLY"
	if _, _, err = CanonicalizeServiceDefinition(unsupported); err == nil || ValidateServiceDefinition(unsupported) == nil {
		t.Fatal("unsupported activation prerequisite was accepted")
	}
}

func TestServiceDefinitionListRequiresExactActivationCapability(t *testing.T) {
	definition := ServiceDefinition{
		ID: "vector-search", DisplayName: "Vector search", Description: "Managed vector search.",
		Revision: 1, ActivationPrerequisite: ServiceActivationPermissionOnly,
		State: ServiceDefinitionAvailable,
	}
	_, definition.ContentDigest, _ = CanonicalizeServiceDefinition(definition)
	available := ServiceDefinitionList{
		Kind: "ServiceDefinitionList", Items: []ServiceDefinition{definition},
		ActivationCapability: iamv1.ActionCapability{
			Action: iamv1.ActionManagedServiceActivationActivate,
			Resource: iamv1.ResourceReference{
				Kind: iamv1.ResourceServiceActivation, ID: "collection",
			},
			Available: true,
		},
	}
	if err := ValidateServiceDefinitionList(available); err != nil {
		t.Fatalf("available service definition list rejected: %v", err)
	}
	unavailable := available
	unavailable.ActivationCapability.Available = false
	unavailable.ActivationCapability.RestrictionReason = iamv1.CapabilityAuthorityRequired
	if err := ValidateServiceDefinitionList(unavailable); err != nil {
		t.Fatalf("unavailable service definition list rejected: %v", err)
	}
	for name, mutate := range map[string]func(*ServiceDefinitionList){
		"wrong action": func(value *ServiceDefinitionList) {
			value.ActivationCapability.Action = iamv1.ActionManagedServiceActivationRead
		},
		"wrong resource": func(value *ServiceDefinitionList) {
			value.ActivationCapability.Resource.ID = definition.ID
		},
		"missing denied reason": func(value *ServiceDefinitionList) {
			value.ActivationCapability.Available = false
		},
		"restricted allowed capability": func(value *ServiceDefinitionList) {
			value.ActivationCapability.RestrictionReason = iamv1.CapabilityAuthorityRequired
		},
		"unsorted definitions": func(value *ServiceDefinitionList) {
			second := definition
			second.ID = "relational-database"
			_, second.ContentDigest, _ = CanonicalizeServiceDefinition(second)
			value.Items = []ServiceDefinition{definition, second}
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := available
			candidate.Items = append([]ServiceDefinition(nil), available.Items...)
			mutate(&candidate)
			if ValidateServiceDefinitionList(candidate) == nil {
				t.Fatal("invalid service definition list accepted")
			}
		})
	}
}

func TestServiceActivationRequiresExactDefinitionReference(t *testing.T) {
	now := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	activation := ServiceActivation{
		Service: ServiceDefinitionReference{
			ID: "postgresql", Revision: 1,
			ContentDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
		ResourceVersion: 1, ActivatedAt: now,
	}
	if err := ValidateServiceActivation(activation); err != nil {
		t.Fatalf("valid service activation rejected: %v", err)
	}
	activation.Service.ContentDigest = ""
	if ValidateServiceActivation(activation) == nil || ValidateActivateServiceRequest(ActivateServiceRequest{Service: activation.Service}) == nil {
		t.Fatal("activation without an exact service definition digest was accepted")
	}
}

func TestServiceInstallationPhaseContract(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	value := ServiceInstallation{
		ID: "postgres-primary", Name: "Postgres primary", OfferingID: "postgresql-18",
		EngineVersion: "18", QuotaEntitlementID: "quota-1", RegionID: "local-primary",
		Phase: InstallationPending, ResourceVersion: 1, CreatedAt: now,
		Operation: InstallationOperation{ID: "operation-1", Kind: InstallationOperationProvision, Phase: InstallationPending, ObservedAt: now},
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
	unbind := UnbindServiceRoleRequest{ResourceVersion: 1}
	if ValidateUnbindServiceRoleRequest(unbind) != nil {
		t.Fatal("valid unbind request rejected")
	}
	for _, body := range []string{
		`{"resourceVersion":1,"accountId":"forged"}`,
		`{"resourceVersion":1,"roleId":"forged"}`,
		`{"resourceVersion":1,"template":{"id":"forged"}}`,
		`{"resourceVersion":1,"workloadId":"forged"}`,
	} {
		var decoded UnbindServiceRoleRequest
		if err := DecodeRequest(strings.NewReader(body), &decoded); err == nil {
			t.Fatalf("unbind authority selector accepted: %s", body)
		}
	}
	revokedAt := now.Add(time.Minute)
	unbinding := ServiceRoleUnbindingReceipt{
		Kind: "ServiceRoleUnbindingReceipt", ServiceInstallationID: receipt.ServiceInstallationID,
		BindingID: receipt.BindingID, RoleID: receipt.RoleID, Template: template,
		Status: iamv1.WorkloadRoleBindingRevoked, ResourceVersion: 2,
		CreatedAt: now, RevokedAt: revokedAt,
	}
	if err := ValidateServiceRoleUnbindingReceipt(unbinding); err != nil {
		t.Fatalf("valid unbinding receipt rejected: %v", err)
	}
	if encoded, err = json.Marshal(unbinding); err != nil || strings.Contains(string(encoded), "accountId") ||
		strings.Contains(string(encoded), "servicePrincipal") {
		t.Fatalf("unbinding receipt leaked authority selector: %s err=%v", encoded, err)
	}
}
