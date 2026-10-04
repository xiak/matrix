package port

import (
	"testing"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
)

func TestManagedServiceAuthorizationUsesRegisteredProfile(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		action   iamv1.Action
		resource iamv1.ResourceKind
		mode     iamv1.AuthorizationResourceMode
		usage    iamv1.AuthorizationCollectionUsage
		id       string
	}{
		{"offering list", AuthorizeOfferingRead, ResourceServiceOffering, iamv1.AuthorizationResourceCollection, iamv1.AuthorizationCollectionList, "collection"},
		{"offering instance", AuthorizeOfferingRead, ResourceServiceOffering, iamv1.AuthorizationResourceInstance, "", "postgresql-18"},
		{"region list", AuthorizeRegionRead, ResourceRegion, iamv1.AuthorizationResourceCollection, iamv1.AuthorizationCollectionList, "collection"},
		{"quota create", AuthorizeQuotaEntitlementActivate, ResourceQuotaEntitlement, iamv1.AuthorizationResourceCollection, iamv1.AuthorizationCollectionCreate, "collection"},
		{"quota instance", AuthorizeQuotaEntitlementRead, ResourceQuotaEntitlement, iamv1.AuthorizationResourceInstance, "", "quota-one"},
		{"installation create", AuthorizeInstallationCreate, ResourceServiceInstallation, iamv1.AuthorizationResourceCollection, iamv1.AuthorizationCollectionCreate, "collection"},
		{"installation instance", AuthorizeInstallationRead, ResourceServiceInstallation, iamv1.AuthorizationResourceInstance, "", "database-one"},
		{"installation service Role bind", AuthorizeInstallationRoleBind, ResourceServiceInstallation, iamv1.AuthorizationResourceInstance, "", "database-one"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := AuthorizationRequest{
				Credential: "Bearer subject", Action: test.action,
				Resource:     ResourceReference{Kind: test.resource, ID: test.id},
				ResourceMode: test.mode, CollectionUsage: test.usage, RequestID: "request-one",
			}
			if err := ValidateAuthorizationRequest(request); err != nil {
				t.Fatalf("registered request rejected: %v", err)
			}
		})
	}
}

func TestManagedServiceAuthorizationRejectsOtherOrChangedProfiles(t *testing.T) {
	t.Parallel()
	valid := AuthorizationRequest{
		Credential: "Bearer subject", Action: AuthorizeInstallationRead,
		Resource:     ResourceReference{Kind: ResourceServiceInstallation, ID: "database-one"},
		ResourceMode: iamv1.AuthorizationResourceInstance, RequestID: "request-one",
	}
	attacks := map[string]func(*AuthorizationRequest){
		"other product": func(value *AuthorizationRequest) {
			value.Action = iamv1.ActionPaaSApplicationRead
			value.Resource.Kind = iamv1.ResourceApplication
		},
		"wrong resource": func(value *AuthorizationRequest) {
			value.Resource.Kind = ResourceQuotaEntitlement
		},
		"undeclared list shape": func(value *AuthorizationRequest) {
			value.Action = AuthorizeInstallationCreate
			value.ResourceMode = iamv1.AuthorizationResourceCollection
			value.CollectionUsage = iamv1.AuthorizationCollectionList
			value.Resource.ID = "collection"
		},
		"caller collection id": func(value *AuthorizationRequest) {
			value.ResourceMode = iamv1.AuthorizationResourceCollection
			value.CollectionUsage = iamv1.AuthorizationCollectionList
			value.Resource.ID = "database-one"
		},
		"invalid request identity": func(value *AuthorizationRequest) {
			value.RequestID = ""
		},
	}
	for name, mutate := range attacks {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if ValidateAuthorizationRequest(candidate) == nil {
				t.Fatal("profile attack accepted")
			}
		})
	}
}

func TestManagedServiceAuthorizationBatchIsBoundToExactOrderedCandidates(t *testing.T) {
	request := AuthorizationBatchRequest{Credential: "Bearer subject", Requests: []AuthorizationRequest{
		{Credential: "Bearer subject", Action: AuthorizeOfferingRead, Resource: ResourceReference{Kind: ResourceServiceOffering, ID: "offering-a"}, ResourceMode: iamv1.AuthorizationResourceInstance, RequestID: "request-a", CorrelationID: "correlation-list"},
		{Credential: "Bearer subject", Action: AuthorizeOfferingRead, Resource: ResourceReference{Kind: ResourceServiceOffering, ID: "offering-b"}, ResourceMode: iamv1.AuthorizationResourceInstance, RequestID: "request-b", CorrelationID: "correlation-list"},
	}}
	result := AuthorizationBatch{TenantID: "account-one", SubjectType: SubjectUser, SubjectID: "user-one", Items: []AuthorizationBatchItem{
		{Resource: request.Requests[0].Resource, Allowed: true, DecisionID: "decision-a", RequestID: "request-a"},
		{Resource: request.Requests[1].Resource, Allowed: false, DecisionID: "decision-b", RequestID: "request-b"},
	}}
	if ValidateAuthorizationBatchRequest(request) != nil || ValidateAuthorizationBatchForRequest(result, request) != nil {
		t.Fatal("valid mixed product batch rejected")
	}
	for name, mutate := range map[string]func(*AuthorizationBatchRequest){
		"credential mismatch": func(value *AuthorizationBatchRequest) { value.Requests[1].Credential = "Bearer other" },
		"duplicate request":   func(value *AuthorizationBatchRequest) { value.Requests[1].RequestID = value.Requests[0].RequestID },
		"reordered resource": func(value *AuthorizationBatchRequest) {
			value.Requests[0], value.Requests[1] = value.Requests[1], value.Requests[0]
		},
		"different correlation": func(value *AuthorizationBatchRequest) { value.Requests[1].CorrelationID = "correlation-other" },
		"undeclared action": func(value *AuthorizationBatchRequest) {
			for index := range value.Requests {
				value.Requests[index].Action = AuthorizeRegionRead
				value.Requests[index].Resource.Kind = ResourceRegion
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := request
			candidate.Requests = append([]AuthorizationRequest(nil), request.Requests...)
			mutate(&candidate)
			if ValidateAuthorizationBatchRequest(candidate) == nil {
				t.Fatal("invalid product batch accepted")
			}
		})
	}
	changed := result
	changed.Items = append([]AuthorizationBatchItem(nil), result.Items...)
	changed.Items[1].Resource.ID = "offering-other"
	if ValidateAuthorizationBatchForRequest(changed, request) == nil {
		t.Fatal("substituted product batch response accepted")
	}
}
