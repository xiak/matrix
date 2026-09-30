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
