package port

import (
	"reflect"
	"testing"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

func TestAppHostingAuthorizationUsesRegisteredPaaSProfile(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		action   iamv1.Action
		resource string
		mode     iamv1.AuthorizationResourceMode
		usage    iamv1.AuthorizationCollectionUsage
		id       paasv1.ResourceID
	}{
		{"application create", AuthorizeApplicationCreate, ResourceApplication, iamv1.AuthorizationResourceCollection, iamv1.AuthorizationCollectionCreate, "collection"},
		{"application read", AuthorizeApplicationRead, ResourceApplication, iamv1.AuthorizationResourceInstance, "", "application-one"},
		{"application label set", AuthorizeApplicationLabelSet, ResourceApplication, iamv1.AuthorizationResourceInstance, "", "application-one"},
		{"application label delete", AuthorizeApplicationLabelDelete, ResourceApplication, iamv1.AuthorizationResourceInstance, "", "application-one"},
		{"configuration create", AuthorizeConfigurationCreate, ResourceConfiguration, iamv1.AuthorizationResourceCollection, iamv1.AuthorizationCollectionCreate, "collection"},
		{"configuration read", AuthorizeConfigurationRead, ResourceConfiguration, iamv1.AuthorizationResourceInstance, "", "configuration-one"},
		{"configuration revision create", AuthorizeConfigurationRevisionCreate, ResourceConfigurationRevision, iamv1.AuthorizationResourceCollection, iamv1.AuthorizationCollectionCreate, "collection"},
		{"configuration revision read", AuthorizeConfigurationRevisionRead, ResourceConfigurationRevision, iamv1.AuthorizationResourceInstance, "", "configuration-revision-one"},
		{"application revision create", AuthorizeApplicationRevisionCreate, ResourceApplicationRevision, iamv1.AuthorizationResourceCollection, iamv1.AuthorizationCollectionCreate, "collection"},
		{"application revision read", AuthorizeApplicationRevisionRead, ResourceApplicationRevision, iamv1.AuthorizationResourceInstance, "", "application-revision-one"},
		{"deployment create", AuthorizeDeploymentCreate, ResourceDeployment, iamv1.AuthorizationResourceCollection, iamv1.AuthorizationCollectionCreate, "collection"},
		{"deployment update", AuthorizeDeploymentUpdate, ResourceDeployment, iamv1.AuthorizationResourceInstance, "", "deployment-one"},
		{"deployment stop", AuthorizeDeploymentStop, ResourceDeployment, iamv1.AuthorizationResourceInstance, "", "deployment-one"},
		{"deployment rollback", AuthorizeDeploymentRollback, ResourceDeployment, iamv1.AuthorizationResourceInstance, "", "deployment-one"},
		{"deployment read", AuthorizeDeploymentRead, ResourceDeployment, iamv1.AuthorizationResourceInstance, "", "deployment-one"},
		{"operation read", AuthorizeOperationRead, ResourceOperation, iamv1.AuthorizationResourceInstance, "", "operation-one"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := AuthorizationRequest{
				Credential: "Bearer subject", Action: test.action,
				Resource:     paasv1.ResourceRef{Kind: test.resource, ID: test.id},
				ResourceMode: test.mode, CollectionUsage: test.usage,
				SourceIP: "192.0.2.23", RequestID: "request-one",
			}
			iamRequest, err := NewIAMAuthorizationRequest(request)
			if err != nil || ValidateAuthorizationRequest(request) != nil {
				t.Fatalf("registered request rejected: request=%#v err=%v", iamRequest, err)
			}
			profile, known := iamv1.LookupAuthorizationProfile(iamv1.ProductPaaS)
			if !known || iamv1.CheckAuthorizationProfileReference(profile, iamRequest.Profile) != nil ||
				iamRequest.Action != test.action || iamRequest.NetworkContext == nil ||
				iamRequest.NetworkContext.SourceIP != "192.0.2.23" {
				t.Fatalf("request did not bind the current PaaS profile: %#v", iamRequest)
			}
		})
	}
}

func TestApplicationCreateAuthorizationBindsOnlyProfileDeclaredLabels(t *testing.T) {
	request := AuthorizationRequest{
		Credential: "Bearer subject", Action: AuthorizeApplicationCreate,
		Resource:     paasv1.ResourceRef{Kind: ResourceApplication, ID: "collection"},
		ResourceMode: iamv1.AuthorizationResourceCollection, CollectionUsage: iamv1.AuthorizationCollectionCreate,
		SourceIP: "192.0.2.23", RequestID: "request-tags",
		RequestLabels: map[string]string{"environment": "production", "team": "payments", "1-metadata": "retained"},
	}
	iamRequest, err := NewIAMAuthorizationRequest(request)
	expected := []iamv1.AuthorizationTag{{Key: "environment", Value: "production"}}
	if err != nil || !reflect.DeepEqual(iamRequest.RequestTags, expected) {
		t.Fatalf("trusted labels were not bound by the PaaS Profile: request=%#v err=%v", iamRequest, err)
	}
	authorization := Authorization{
		TenantID: "tenant-a", Subject: paasv1.SubjectRef{Type: paasv1.SubjectUser, ID: "user-a"},
		DecisionID: "decision-tags", RequestID: request.RequestID, RequestTags: expected,
	}
	if ValidateAuthorizationForRequest(authorization, request) != nil ||
		ValidateAuthorizationTagsForAction(authorization, AuthorizeApplicationCreate, request.RequestLabels) != nil {
		t.Fatal("exact PEP/IAM/use-case label binding was rejected")
	}
	changed := request
	changed.RequestLabels = map[string]string{"environment": "staging", "team": "payments"}
	if ValidateAuthorizationForRequest(authorization, changed) == nil ||
		ValidateAuthorizationTagsForAction(authorization, AuthorizeApplicationCreate, changed.RequestLabels) == nil {
		t.Fatal("an authorization decision was reused with changed labels")
	}
	read := request
	read.Action, read.ResourceMode, read.CollectionUsage = AuthorizeApplicationRead, iamv1.AuthorizationResourceInstance, ""
	read.Resource.ID = "application-one"
	if ValidateAuthorizationRequest(read) == nil {
		t.Fatal("request labels leaked into an undeclared product action")
	}
}

func TestApplicationReadAuthorizationBindsOnlyProfileDeclaredResourceLabels(t *testing.T) {
	request := AuthorizationRequest{
		Credential: "Bearer subject", Action: AuthorizeApplicationRead,
		Resource:     paasv1.ResourceRef{Kind: ResourceApplication, ID: "application-one"},
		ResourceMode: iamv1.AuthorizationResourceInstance,
		SourceIP:     "192.0.2.23", RequestID: "request-resource-tags",
		ResourceLabels: map[string]string{"environment": "production", "team": "payments", "1-metadata": "retained"},
	}
	iamRequest, err := NewIAMAuthorizationRequest(request)
	expected := []iamv1.AuthorizationTag{{Key: "environment", Value: "production"}}
	if err != nil || iamRequest.RequestTags != nil || !reflect.DeepEqual(iamRequest.ResourceTags, expected) {
		t.Fatalf("stored resource labels were not bound by the PaaS Profile: request=%#v err=%v", iamRequest, err)
	}
	authorization := Authorization{
		TenantID: "tenant-a", Subject: paasv1.SubjectRef{Type: paasv1.SubjectUser, ID: "user-a"},
		DecisionID: "decision-resource-tags", RequestID: request.RequestID, ResourceTags: expected,
	}
	if ValidateAuthorizationForRequest(authorization, request) != nil ||
		ValidateAuthorizationResourceTagsForAction(authorization, AuthorizeApplicationRead, request.ResourceLabels) != nil {
		t.Fatal("exact PEP/IAM/read resource label binding was rejected")
	}
	changed := request
	changed.ResourceLabels = map[string]string{"environment": "staging", "team": "payments"}
	if ValidateAuthorizationForRequest(authorization, changed) == nil ||
		ValidateAuthorizationResourceTagsForAction(authorization, AuthorizeApplicationRead, changed.ResourceLabels) == nil {
		t.Fatal("an authorization decision was reused with changed resource labels")
	}
	create := request
	create.Action, create.ResourceMode, create.CollectionUsage = AuthorizeApplicationCreate, iamv1.AuthorizationResourceCollection, iamv1.AuthorizationCollectionCreate
	create.Resource.ID = "collection"
	if ValidateAuthorizationRequest(create) == nil {
		t.Fatal("resource labels leaked into an undeclared product action")
	}
}

func TestApplicationLabelMutationAuthorizationBindsCurrentAndRequestedLabels(t *testing.T) {
	for _, action := range []iamv1.Action{AuthorizeApplicationLabelSet, AuthorizeApplicationLabelDelete} {
		request := AuthorizationRequest{
			Credential: "Bearer subject", Action: action,
			Resource:     paasv1.ResourceRef{Kind: ResourceApplication, ID: "application-one"},
			ResourceMode: iamv1.AuthorizationResourceInstance,
			SourceIP:     "192.0.2.23", RequestID: "request-label-mutation",
			ResourceLabels: map[string]string{"environment": "production", "team": "payments"},
			RequestLabels:  map[string]string{"environment": "staging", "team": "payments"},
		}
		iamRequest, err := NewIAMAuthorizationRequest(request)
		current := []iamv1.AuthorizationTag{{Key: "environment", Value: "production"}}
		target := []iamv1.AuthorizationTag{{Key: "environment", Value: "staging"}}
		if err != nil || !reflect.DeepEqual(iamRequest.ResourceTags, current) ||
			!reflect.DeepEqual(iamRequest.RequestTags, target) {
			t.Fatalf("label mutation did not bind current and requested labels: action=%s request=%#v err=%v", action, iamRequest, err)
		}
		authorization := Authorization{TenantID: "tenant-a", Subject: paasv1.SubjectRef{Type: paasv1.SubjectUser, ID: "user-a"},
			DecisionID: "decision-label-mutation", RequestID: request.RequestID,
			ResourceTags: current, RequestTags: target}
		if ValidateAuthorizationForRequest(authorization, request) != nil ||
			ValidateAuthorizationResourceTagsForAction(authorization, action, request.ResourceLabels) != nil ||
			ValidateAuthorizationTagsForAction(authorization, action, request.RequestLabels) != nil {
			t.Fatal("exact current and requested label evidence was rejected", action)
		}
		changed := request
		changed.RequestLabels = map[string]string{"environment": "restricted"}
		if ValidateAuthorizationForRequest(authorization, changed) == nil ||
			ValidateAuthorizationTagsForAction(authorization, action, changed.RequestLabels) == nil {
			t.Fatal("label mutation reused a decision for another target", action)
		}
	}
}

func TestAuthorizationSubjectContextIsProfileBoundAndSelectorFree(t *testing.T) {
	profile, known := iamv1.LookupAuthorizationProfile(iamv1.ProductPaaS)
	if !known {
		t.Fatal("PaaS Profile is missing")
	}
	_, digest, err := iamv1.CanonicalizeAuthorizationProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	context := AuthorizationSubjectContext{
		TenantID: "tenant-a",
		Subject:  paasv1.SubjectRef{Type: paasv1.SubjectUser, ID: "user-a"},
		Profile: iamv1.AuthorizationProfileReference{
			Product: profile.Product, Revision: profile.Revision, ContentDigest: digest,
		},
	}
	if ValidateSubjectResolutionRequest(SubjectResolutionRequest{Credential: "Bearer subject"}) != nil ||
		ValidateAuthorizationSubjectContext(context) != nil {
		t.Fatalf("current selector-free subject context was rejected: %#v", context)
	}
	changed := context
	changed.Profile.Revision--
	if ValidateAuthorizationSubjectContext(changed) == nil {
		t.Fatal("stale product Profile was accepted for resource preloading")
	}
	changed = context
	changed.Subject.Type = paasv1.SubjectServiceAccount
	if ValidateAuthorizationSubjectContext(changed) == nil {
		t.Fatal("service account was accepted as an apphosting business subject")
	}
	authorization := Authorization{
		TenantID: "tenant-a", Subject: context.Subject,
		DecisionID: "decision-a", RequestID: "request-a",
	}
	if ValidateAuthorizationForSubjectContext(authorization, context) != nil {
		t.Fatal("unchanged authorization subject context was rejected")
	}
	authorization.Subject.ID = "user-b"
	if ValidateAuthorizationForSubjectContext(authorization, context) == nil {
		t.Fatal("authorization was rebound to another subject after resource preloading")
	}
}

func TestAppHostingAuthorizationRejectsOtherPEPSurfacesAndChangedShapes(t *testing.T) {
	t.Parallel()
	valid := AuthorizationRequest{
		Credential: "Bearer subject", Action: AuthorizeDeploymentRead,
		Resource:     paasv1.ResourceRef{Kind: ResourceDeployment, ID: "deployment-one"},
		ResourceMode: iamv1.AuthorizationResourceInstance,
		SourceIP:     "2001:db8::23", RequestID: "request-one",
	}
	attacks := map[string]func(*AuthorizationRequest){
		"platform action from same product": func(value *AuthorizationRequest) {
			value.Action = iamv1.ActionPaaSPlatformOperationRead
			value.Resource.Kind = ResourceOperation
			value.Resource.ID = "operation-one"
		},
		"other product": func(value *AuthorizationRequest) {
			value.Action = iamv1.ActionManagedServiceInstallationRead
		},
		"wrong resource": func(value *AuthorizationRequest) {
			value.Resource.Kind = ResourceApplication
		},
		"undeclared create shape": func(value *AuthorizationRequest) {
			value.Action = AuthorizeDeploymentCreate
		},
		"caller collection id": func(value *AuthorizationRequest) {
			value.ResourceMode = iamv1.AuthorizationResourceCollection
			value.CollectionUsage = iamv1.AuthorizationCollectionList
		},
		"forwarded address syntax": func(value *AuthorizationRequest) {
			value.SourceIP = "for=192.0.2.23"
		},
		"invalid request identity": func(value *AuthorizationRequest) {
			value.RequestID = ""
		},
	}
	for name, mutate := range attacks {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if _, err := NewIAMAuthorizationRequest(candidate); err == nil ||
				ValidateAuthorizationRequest(candidate) == nil {
				t.Fatal("PEP surface attack accepted")
			}
		})
	}
}
