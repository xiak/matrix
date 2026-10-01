package port

import (
	"reflect"
	"strings"
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

func TestAccessKeyAdmissionIsLimitedToDeclaredGraphAndInstanceActions(t *testing.T) {
	nonce, err := iamv1.NewSecret("AAAAAAAAAAAAAAAAAAAAAA")
	if err != nil {
		t.Fatal(err)
	}
	signature, err := iamv1.NewSecret("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if err != nil {
		t.Fatal(err)
	}
	request := AccessKeyAuthorizationRequest{
		Action:       AuthorizeApplicationCreate,
		Resource:     paasv1.ResourceRef{Kind: ResourceApplication, ID: "collection"},
		ResourceMode: iamv1.AuthorizationResourceCollection, CollectionUsage: iamv1.AuthorizationCollectionCreate,
		SourceIP: "192.0.2.23", RequestID: "request-key",
		RequestLabels: map[string]string{"environment": "production"},
		SignedRequest: iamv1.AccessKeySignedRequest{
			Parameters: iamv1.AccessKeySignatureParameters{AccessKeyID: "key-one", InstallationID: "installation-one",
				Audience: iamv1.ProductPaaS, SignedAt: 1800000000, Nonce: nonce},
			HTTP: iamv1.AccessKeyHTTPRequest{Method: "POST", Scheme: "https", Authority: "api.example.test:443",
				EscapedPath: "/api/paas/v1/applications", ContentType: "application/json", IdempotencyKey: "create-key",
				BodyDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
			Signature: signature,
		},
	}
	if ValidateAccessKeyAuthorizationRequest(request) != nil {
		t.Fatal("declared AccessKey create was rejected")
	}
	result := Authorization{TenantID: "tenant-a",
		Subject:    paasv1.SubjectRef{Type: paasv1.SubjectUser, ID: "user-a", AccessKeyID: "key-one"},
		DecisionID: "decision-key", RequestID: request.RequestID,
		RequestTags: []iamv1.AuthorizationTag{{Key: "environment", Value: "production"}}}
	if ValidateAccessKeyAuthorizationForRequest(result, request) != nil {
		t.Fatal("exact AccessKey result was rejected")
	}
	changed := result
	changed.Subject.AccessKeyID = "key-two"
	if ValidateAccessKeyAuthorizationForRequest(changed, request) == nil {
		t.Fatal("another AccessKey was accepted as the signed credential")
	}
	for _, candidate := range []struct {
		action       iamv1.Action
		resourceKind string
		path         string
	}{
		{AuthorizeConfigurationCreate, ResourceConfiguration, "/api/paas/v1/configurations"},
		{AuthorizeConfigurationRevisionCreate, ResourceConfigurationRevision, "/api/paas/v1/configuration-revisions"},
		{AuthorizeApplicationRevisionCreate, ResourceApplicationRevision, "/api/paas/v1/application-revisions"},
		{AuthorizeDeploymentCreate, ResourceDeployment, "/api/paas/v1/deployments"},
	} {
		creation := request
		creation.Action = candidate.action
		creation.Resource = paasv1.ResourceRef{Kind: candidate.resourceKind, ID: "collection"}
		creation.RequestLabels = nil
		creation.SignedRequest.HTTP.EscapedPath = candidate.path
		if ValidateAccessKeyAuthorizationRequest(creation) != nil {
			t.Fatal("declared immutable resource graph creation rejected", candidate.action)
		}
	}
	read := request
	read.Action, read.ResourceMode, read.CollectionUsage = AuthorizeApplicationRead, iamv1.AuthorizationResourceInstance, ""
	read.Resource.ID = "application-one"
	read.RequestLabels = nil
	read.SignedRequest.HTTP.Method = "GET"
	read.SignedRequest.HTTP.EscapedPath = "/api/paas/v1/applications/application-one"
	read.SignedRequest.HTTP.ContentType = ""
	read.SignedRequest.HTTP.IdempotencyKey = ""
	read.SignedRequest.HTTP.BodyDigest = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	read.ResourceLabels = map[string]string{"environment": "production"}
	if ValidateAccessKeyAuthorizationRequest(read) != nil {
		t.Fatal("declared tagged Application read rejected")
	}
	for _, candidate := range []struct {
		action       iamv1.Action
		resourceKind string
		resourceID   paasv1.ResourceID
		path         string
	}{
		{AuthorizeConfigurationRead, ResourceConfiguration, "configuration-one", "/api/paas/v1/configurations/configuration-one"},
		{AuthorizeConfigurationRevisionRead, ResourceConfigurationRevision, "configuration-revision-one", "/api/paas/v1/configuration-revisions/configuration-revision-one"},
		{AuthorizeApplicationRevisionRead, ResourceApplicationRevision, "application-revision-one", "/api/paas/v1/application-revisions/application-revision-one"},
		{AuthorizeDeploymentRead, ResourceDeployment, "deployment-one", "/api/paas/v1/deployments/deployment-one"},
		{AuthorizeOperationRead, ResourceOperation, "operation-one", "/api/paas/v1/operations/operation-one"},
	} {
		instanceRead := read
		instanceRead.Action = candidate.action
		instanceRead.Resource = paasv1.ResourceRef{Kind: candidate.resourceKind, ID: candidate.resourceID}
		instanceRead.ResourceLabels = nil
		instanceRead.SignedRequest.HTTP.EscapedPath = candidate.path
		if ValidateAccessKeyAuthorizationRequest(instanceRead) != nil {
			t.Fatal("declared instance read rejected", candidate.action)
		}
	}
	for _, candidate := range []struct {
		action iamv1.Action
		method string
		path   string
	}{
		{AuthorizeDeploymentUpdate, "PUT", "/api/paas/v1/deployments/deployment-one"},
		{AuthorizeDeploymentStop, "PUT", "/api/paas/v1/deployments/deployment-one"},
		{AuthorizeDeploymentRollback, "POST", "/api/paas/v1/deployments/deployment-one/rollback"},
	} {
		mutation := read
		mutation.Action = candidate.action
		mutation.Resource = paasv1.ResourceRef{Kind: ResourceDeployment, ID: "deployment-one"}
		mutation.ResourceLabels = nil
		mutation.SignedRequest.HTTP.Method = candidate.method
		mutation.SignedRequest.HTTP.EscapedPath = candidate.path
		mutation.SignedRequest.HTTP.ContentType = "application/json"
		mutation.SignedRequest.HTTP.IdempotencyKey = "mutate-deployment-one"
		mutation.SignedRequest.HTTP.IfMatch = `"7"`
		mutation.SignedRequest.HTTP.BodyDigest = "sha256:" + strings.Repeat("b", 64)
		if ValidateAccessKeyAuthorizationRequest(mutation) != nil {
			t.Fatal("declared Deployment mutation rejected", candidate.action)
		}
	}
	for _, candidate := range []struct {
		action      iamv1.Action
		method      string
		contentType string
		bodyDigest  string
	}{
		{AuthorizeApplicationLabelSet, "PUT", "application/json", "sha256:" + strings.Repeat("c", 64)},
		{AuthorizeApplicationLabelDelete, "DELETE", "", "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
	} {
		mutation := read
		mutation.Action = candidate.action
		mutation.Resource = paasv1.ResourceRef{Kind: ResourceApplication, ID: "application-one"}
		mutation.ResourceLabels = map[string]string{"environment": "production"}
		mutation.RequestLabels = map[string]string{"environment": "staging"}
		mutation.SignedRequest.HTTP.Method = candidate.method
		mutation.SignedRequest.HTTP.EscapedPath = "/api/paas/v1/applications/application-one/labels/environment"
		mutation.SignedRequest.HTTP.ContentType = candidate.contentType
		mutation.SignedRequest.HTTP.IdempotencyKey = "mutate-application-label"
		mutation.SignedRequest.HTTP.IfMatch = `"7"`
		mutation.SignedRequest.HTTP.BodyDigest = candidate.bodyDigest
		if ValidateAccessKeyAuthorizationRequest(mutation) != nil {
			t.Fatal("declared Application label mutation rejected", candidate.action)
		}
	}
	undeclared := read
	undeclared.Action = iamv1.ActionPaaSExecutionTargetDrain
	undeclared.Resource = paasv1.ResourceRef{Kind: string(iamv1.ResourceExecutionTarget), ID: "execution-target-one"}
	undeclared.ResourceLabels = nil
	undeclared.SignedRequest.HTTP.Method = "POST"
	undeclared.SignedRequest.HTTP.EscapedPath = "/api/paas/v1/execution-targets/execution-target-one:drain"
	if ValidateAccessKeyAuthorizationRequest(undeclared) == nil {
		t.Fatal("undeclared platform target mutation borrowed tenant AccessKey admission")
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
