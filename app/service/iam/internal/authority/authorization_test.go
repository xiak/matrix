package authority

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
)

func TestSessionAuthenticationUsesBindingDigestRevocationAndDatabaseTime(t *testing.T) {
	now := authorityTestTime()
	context := authoritySubject(now, iamv1.SystemPolicyPaaSDeveloper)
	entropy := bytes.NewReader(bytes.Repeat([]byte{0x44}, 32))
	issued, err := NewCredentialIssuer(entropy).Issue(CredentialSession, string(context.Session.ID))
	if err != nil {
		t.Fatalf("issue session credential: %v", err)
	}
	if err := AuthenticateSession(context.Session, issued.VerificationDigest, issued.Credential, now); err != nil {
		t.Fatalf("authenticate active session: %v", err)
	}
	wrong := authoritySecret(t, "mx1.BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")
	if err := AuthenticateSession(context.Session, issued.VerificationDigest, wrong, now); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("wrong session credential error = %v", err)
	}
	expired := context.Session
	expired.ExpiresAt = now
	if err := AuthenticateSession(expired, issued.VerificationDigest, issued.Credential, now); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("expired session error = %v", err)
	}
	revokedAt := now.Add(-time.Minute)
	revoked := context.Session
	revoked.Status = iamv1.SessionRevoked
	revoked.RevokedAt = &revokedAt
	if err := AuthenticateSession(revoked, issued.VerificationDigest, issued.Credential, now); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("revoked session error = %v", err)
	}
}

func TestSystemPolicyAllowsCurrentBindingAndDeniesWithoutAuthorityLeak(t *testing.T) {
	now := authorityTestTime()
	context := authoritySubject(now, iamv1.SystemPolicyPaaSDeveloper)
	request := boundAuthorizationRequest(t, iamv1.AuthorizationRequest{
		Action:    iamv1.ActionPaaSDeploymentCreate,
		Resource:  iamv1.ResourceReference{Kind: iamv1.ResourceDeployment, ID: "collection"},
		RequestID: "request-authorize", CorrelationID: "correlation-authorize",
	}, iamv1.AuthorizationResourceCollection, iamv1.AuthorizationCollectionCreate)
	allowed, err := Decide(context, iamv1.ServicePaaS, request, "decision-allowed", now)
	if err != nil || !allowed.Allowed || allowed.TenantID != context.Organization.ID ||
		allowed.Subject == nil || allowed.Subject.ID != context.Principal.ID {
		t.Fatalf("developer decision = %#v err=%v", allowed, err)
	}

	request = boundAuthorizationRequest(t, iamv1.AuthorizationRequest{Action: iamv1.ActionIAMUserCreate,
		Resource:  iamv1.ResourceReference{Kind: iamv1.ResourceAccount, ID: "organization-example"},
		RequestID: "request-denied", CorrelationID: "correlation-denied"}, iamv1.AuthorizationResourceInstance, "")
	denied, err := Decide(context, iamv1.ServicePaaS, request, "decision-denied", now)
	if err != nil || denied.Allowed || denied.TenantID != "" || denied.Subject != nil {
		t.Fatalf("denied decision = %#v err=%v", denied, err)
	}
	encoded, err := json.Marshal(denied)
	if err != nil {
		t.Fatalf("encode denied decision: %v", err)
	}
	if bytes.Contains(encoded, []byte(`"tenantId"`)) || bytes.Contains(encoded, []byte(`"installationId"`)) || bytes.Contains(encoded, []byte("principal-developer")) {
		t.Fatalf("denied decision leaked authority context: %s", encoded)
	}
	if iamv1.CheckAuthorizationDecisionForRequest(denied.AuthorizationDecision, request) != nil {
		t.Fatal("denial did not preserve the caller's complete request binding")
	}

	context.Policies = nil
	request = boundAuthorizationRequest(t, iamv1.AuthorizationRequest{Action: iamv1.ActionPaaSDeploymentCreate,
		Resource:  iamv1.ResourceReference{Kind: iamv1.ResourceDeployment, ID: "collection"},
		RequestID: "request-revoked", CorrelationID: "correlation-revoked"}, iamv1.AuthorizationResourceCollection, iamv1.AuthorizationCollectionCreate)
	afterRevocation, err := Decide(context, iamv1.ServicePaaS, request, "decision-after-revocation", now)
	if err != nil || afterRevocation.Allowed {
		t.Fatalf("decision after binding revocation = %#v err=%v", afterRevocation, err)
	}

	context = authoritySubject(now, iamv1.SystemPolicyAccountAdministrator)
	context.Principal.MustChangePassword = true
	mustChange, err := Decide(context, iamv1.ServicePaaS, request, "decision-must-change", now)
	if err != nil || mustChange.Allowed {
		t.Fatalf("initial administrator used PaaS before password change: decision=%#v err=%v", mustChange, err)
	}
}

func TestInstallationVerifierServiceCanAuthorizeOnlyItsFixedAction(t *testing.T) {
	now := authorityTestTime()
	identity := iamv1.ServiceIdentity{
		InstallationID: "installation-example",
		APIVersion:     iamv1.APIVersion,
		Kind:           "ServiceIdentity",
		AccountID:      "organization-example",
		PrincipalID:    "service-installation-verifier",
		Purpose:        iamv1.ServiceInstallationVerifier,
	}
	request := boundAuthorizationRequest(t, iamv1.AuthorizationRequest{
		Action: iamv1.ActionInstallationVerify,
		Resource: iamv1.ResourceReference{
			Kind: iamv1.ResourceInstallation, ID: "installation-example",
		},
		RequestID: "request-installation-verify", CorrelationID: "correlation-installation-verify",
	}, iamv1.AuthorizationResourceInstance, "")
	allowed, err := DecideService(
		identity,
		authorityServicePolicies(now, identity, iamv1.SystemPolicyInstallationVerifier),
		request,
		"decision-installation-verify",
		now,
	)
	if err != nil || !allowed.Allowed || allowed.TenantID != identity.AccountID ||
		allowed.Subject == nil || allowed.Subject.Type != iamv1.PrincipalServiceAccount ||
		allowed.Subject.ID != identity.PrincipalID {
		t.Fatalf("installation verifier decision=%#v err=%v", allowed, err)
	}

	withoutRole, err := DecideService(
		identity, nil, request, "decision-installation-without-policy", now,
	)
	if err != nil || withoutRole.Allowed || withoutRole.Subject != nil || withoutRole.TenantID != "" {
		t.Fatalf("unbound installation verifier decision=%#v err=%v", withoutRole, err)
	}
	identity.Purpose = iamv1.ServicePaaS
	wrongPurpose, err := DecideService(
		identity,
		authorityServicePolicies(now, identity, iamv1.SystemPolicyInstallationVerifier),
		request,
		"decision-installation-wrong-purpose",
		now,
	)
	if err != nil || wrongPurpose.Allowed {
		t.Fatalf("wrong-purpose verifier decision=%#v err=%v", wrongPurpose, err)
	}
}

func attachedSystemPolicyAllows(t *testing.T, policyID iamv1.PolicyID, action iamv1.Action) bool {
	t.Helper()
	definition, known := iamv1.LookupActionDefinition(action)
	if !known {
		t.Fatal("unknown test action")
	}
	if _, err := SystemPolicyVersion(policyID); err != nil {
		return false
	}
	request := declaredAuthorizationRequest(t, iamv1.AuthorizationRequest{Action: action,
		Resource:  iamv1.ResourceReference{Kind: definition.ResourceKind, ID: "resource-example"},
		RequestID: "request-policy", CorrelationID: "correlation-policy"})
	now := authorityTestTime()
	var decision AuthorizationEvaluation
	var err error
	if policyID == iamv1.SystemPolicyInstallationVerifier {
		identity := iamv1.ServiceIdentity{APIVersion: iamv1.APIVersion, Kind: "ServiceIdentity",
			InstallationID: "installation-example", AccountID: "organization-example",
			PrincipalID: "service-example", Purpose: definition.CallingService}
		if request.Action == iamv1.ActionInstallationVerify {
			request.Resource.ID = identity.InstallationID
		}
		decision, err = DecideService(identity, authorityServicePolicies(now, identity, policyID), request, "decision-policy", now)
	} else {
		subject := authoritySubject(now, policyID)
		subject.InstallationID = "installation-example"
		decision, err = Decide(subject, definition.CallingService, request, "decision-policy", now)
	}
	if err != nil {
		t.Fatal(err)
	}
	return decision.Allowed
}

func TestEveryIAMActionHasSystemPolicyAndUniqueServiceAuthority(t *testing.T) {
	policies := testSystemPolicyIDs
	services := iamv1.AllServicePurposes()
	for _, action := range iamv1.AllActions() {
		owners := 0
		for _, policyID := range policies {
			if attachedSystemPolicyAllows(t, policyID, action) {
				owners++
			}
		}
		if owners == 0 {
			t.Fatalf("IAM action %q has no system policy authority", action)
		}
		serviceOwners := 0
		for _, service := range services {
			if ServiceCanRequest(service, action) {
				serviceOwners++
			}
		}
		if serviceOwners != 1 {
			t.Fatalf("IAM action %q has %d service owners, want exactly one", action, serviceOwners)
		}
	}
	if attachedSystemPolicyAllows(t, iamv1.SystemPolicyInstallationVerifier, iamv1.ActionPaaSDeploymentRead) ||
		attachedSystemPolicyAllows(t, iamv1.SystemPolicyAuditReader, iamv1.ActionPaaSApplicationRead) ||
		attachedSystemPolicyAllows(t, iamv1.PolicyID("customer.missing"), iamv1.ActionPaaSApplicationRead) {
		t.Fatal("least-privilege policies accepted authority outside their catalog")
	}
	if ServiceCanRequest(iamv1.ServiceIAM, iamv1.ActionPaaSApplicationRead) {
		t.Fatal("IAM was allowed to request PaaS authorization")
	}
}

func TestRetiredRoleActionsCannotObtainNewDecisions(t *testing.T) {
	now := authorityTestTime()
	for _, definition := range iamv1.AllRecordedActionDefinitions() {
		if _, current := iamv1.LookupActionDefinition(definition.Action); current {
			continue
		}
		request := iamv1.AuthorizationRequest{Action: definition.Action,
			Resource:  iamv1.ResourceReference{Kind: definition.ResourceKind, ID: "target-one"},
			RequestID: "retired-request", CorrelationID: "retired-correlation"}
		for _, purpose := range iamv1.AllServicePurposes() {
			if ServiceCanRequest(purpose, definition.Action) {
				t.Fatal("service admitted a retired action")
			}
			for _, policyID := range []iamv1.PolicyID{iamv1.SystemPolicyAccountAdministrator, iamv1.SystemPolicyPlatformOperator} {
				subject := authoritySubject(now, policyID)
				subject.InstallationID = "installation-example"
				decision, err := Decide(subject, purpose, request, "retired-decision", now)
				if !errors.Is(err, ErrInvalidAuthorizationRequest) || decision.Allowed || len(decision.PolicyEvidence) != 0 {
					t.Fatalf("retired action %s yielded current authority: %v", definition.Action, err)
				}
			}
		}
	}
}

func TestDeclaredModesBindBothDecisionsAndRejectUntrustedProfileContexts(t *testing.T) {
	now := authorityTestTime()
	for _, profile := range iamv1.AllAuthorizationProfiles() {
		for _, action := range profile.Actions {
			for _, shape := range action.ResourceShapes {
				t.Run(fmt.Sprintf("%s/%s/%s", action.Action, shape.Mode, shape.CollectionUsage), func(t *testing.T) {
					// The same spelling can be a real instance; mode, not ID, controls interpretation.
					request := boundAuthorizationRequest(t, iamv1.AuthorizationRequest{Action: action.Action,
						Resource:  iamv1.ResourceReference{Kind: action.ResourceKind, ID: "collection"},
						RequestID: "mode-request", CorrelationID: "mode-correlation"}, shape.Mode, shape.CollectionUsage)
					for _, granted := range []bool{false, true} {
						subject := authoritySubject(now)
						subject.InstallationID = "installation-example"
						if granted {
							subject.Policies = authoritySubject(now, iamv1.SystemPolicyAccountAdministrator, iamv1.SystemPolicyPlatformOperator).Policies
						}
						var decision AuthorizationEvaluation
						var err error
						if action.Scope == iamv1.AuthorityScopeInstallationProbe {
							identity := iamv1.ServiceIdentity{APIVersion: iamv1.APIVersion, Kind: "ServiceIdentity", AccountID: subject.Organization.ID,
								InstallationID: "collection", PrincipalID: "service-verifier", Purpose: iamv1.ServiceInstallationVerifier}
							var policies []AttachedPolicy
							if granted {
								policies = authorityServicePolicies(now, identity, iamv1.SystemPolicyInstallationVerifier)
							}
							decision, err = DecideService(identity, policies, request, "mode-decision", now)
						} else {
							decision, err = Decide(subject, profile.CallingService, request, "mode-decision", now)
						}
						if err != nil || decision.Allowed != granted || iamv1.CheckAuthorizationDecisionForRequest(decision.AuthorizationDecision, request) != nil {
							t.Fatalf("granted=%v binding=%+v err=%v", granted, decision.AuthorizationDecision, err)
						}
					}
				})
			}
		}
	}
	request := boundAuthorizationRequest(t, iamv1.AuthorizationRequest{Action: iamv1.ActionPaaSApplicationRead,
		Resource:  iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "collection"},
		RequestID: "trusted-request", CorrelationID: "trusted-correlation"}, iamv1.AuthorizationResourceInstance, "")
	for name, mutate := range map[string]func(*iamv1.AuthorizationRequest){
		"missing profile":     func(r *iamv1.AuthorizationRequest) { r.Profile = iamv1.AuthorizationProfileReference{} },
		"unknown profile":     func(r *iamv1.AuthorizationRequest) { r.Profile.Product = "unknown" },
		"noncurrent revision": func(r *iamv1.AuthorizationRequest) { r.Profile.Revision++ },
		"wrong digest":        func(r *iamv1.AuthorizationRequest) { r.Profile.ContentDigest = "sha256:" + strings.Repeat("0", 64) },
		"missing mode":        func(r *iamv1.AuthorizationRequest) { r.ResourceMode = "" },
		"undeclared collection": func(r *iamv1.AuthorizationRequest) {
			r.ResourceMode = iamv1.AuthorizationResourceCollection
			r.CollectionUsage = iamv1.AuthorizationCollectionList
		},
		"instance usage":      func(r *iamv1.AuthorizationRequest) { r.CollectionUsage = iamv1.AuthorizationCollectionCreate },
		"missing correlation": func(r *iamv1.AuthorizationRequest) { r.CorrelationID = "" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := request
			mutate(&changed)
			decision, err := Decide(authoritySubject(now, iamv1.SystemPolicyPaaSDeveloper), iamv1.ServicePaaS, changed, "invalid-context", now)
			if !errors.Is(err, ErrInvalidAuthorizationRequest) || decision.ID != "" || decision.Profile != nil || len(decision.PolicyEvidence) != 0 {
				t.Fatalf("invalid context became ordinary decision: %+v err=%v", decision, err)
			}
		})
	}
}

func TestCatalogConfinementIsEnforcedByActualDecisions(t *testing.T) {
	now := authorityTestTime()
	for _, definition := range iamv1.AllActionDefinitions() {
		t.Run(string(definition.Action), func(t *testing.T) {
			request := declaredAuthorizationRequest(t, iamv1.AuthorizationRequest{Action: definition.Action,
				Resource:  iamv1.ResourceReference{Kind: definition.ResourceKind, ID: "resource-example"},
				RequestID: "request-catalog", CorrelationID: "correlation-catalog"})
			for _, service := range iamv1.AllServicePurposes() {
				var decision AuthorizationEvaluation
				var err error
				if definition.AuthorityScope == iamv1.AuthorityScopeInstallationProbe {
					identity := iamv1.ServiceIdentity{APIVersion: iamv1.APIVersion, Kind: "ServiceIdentity",
						InstallationID: "installation-example", AccountID: "organization-example",
						PrincipalID: "service-example", Purpose: service}
					request.Resource.ID = identity.InstallationID
					decision, err = DecideService(identity, authorityServicePolicies(now, identity, iamv1.SystemPolicyInstallationVerifier), request, "decision-catalog", now)
				} else {
					context := authoritySubject(now, iamv1.SystemPolicyAccountAdministrator, iamv1.SystemPolicyPlatformOperator)
					context.InstallationID = "installation-example"
					decision, err = Decide(context, service, request, "decision-catalog", now)
				}
				wantAllowed := service == definition.CallingService
				if err != nil || decision.Allowed != wantAllowed {
					t.Fatalf("caller=%s decision=%+v err=%v", service, decision, err)
				}
				if !wantAllowed {
					if decision.Subject != nil || decision.TenantID != "" || decision.InstallationID != "" {
						t.Fatal("wrong-service denial leaked authority context")
					}
					continue
				}
				if definition.AuthorityScope == iamv1.AuthorityScopeInstallation {
					if decision.InstallationID != "installation-example" || decision.TenantID != "" || decision.Subject.Type != iamv1.PrincipalUser {
						t.Fatal("platform action lost its installation/user authority")
					}
				} else if decision.TenantID != "organization-example" || decision.InstallationID != "" {
					t.Fatal("tenant/probe decision changed its bound home tenant")
				}
				if definition.AuthorityScope == iamv1.AuthorityScopeInstallationProbe && decision.Subject.Type != iamv1.PrincipalServiceAccount {
					t.Fatal("probe no longer identifies the authenticated service")
				}
			}
			context := authoritySubject(now, iamv1.SystemPolicyAccountAdministrator, iamv1.SystemPolicyPlatformOperator)
			context.InstallationID = "installation-example"
			request.Resource.Kind = iamv1.ResourceApplication
			if definition.ResourceKind == request.Resource.Kind {
				request.Resource.Kind = iamv1.ResourceOrganization
			}
			if _, err := Decide(context, definition.CallingService, request, "decision-mismatched-resource", now); !errors.Is(err, ErrInvalidAuthorizationRequest) {
				t.Fatalf("action with another registered resource kind: %v", err)
			}
		})
	}
	for _, service := range iamv1.AllServicePurposes() {
		for _, action := range []iamv1.Action{"iam.principal.unknown", "paas.unregistered.execute", "managedservice.unregistered.read", "installation.verify.other"} {
			if ServiceCanRequest(service, action) {
				t.Fatalf("prefix-only admission: %s/%s", service, action)
			}
		}
	}
}

func policyVersionForTest(t *testing.T, id iamv1.PolicyID, effect iamv1.PolicyEffect, action iamv1.Action, match iamv1.PolicyResourceMatch, resourceID string) iamv1.PolicyVersion {
	t.Helper()
	definition, known := iamv1.LookupActionDefinition(action)
	if !known {
		t.Fatal("invalid test action")
	}
	document := iamv1.PolicyDocument{LanguageVersion: iamv1.PolicyLanguageVersion, Scope: definition.AuthorityScope,
		Statements: []iamv1.PolicyStatement{{SID: "statement", Effect: effect, Actions: []iamv1.Action{action}, Resources: []iamv1.PolicyResourceSelector{{Kind: definition.ResourceKind, Match: match, ID: resourceID}}}}}
	version := iamv1.PolicyVersion{PolicyID: id, ID: "version-one", Document: document}
	compilePolicyVersionForTest(t, &version)
	return version
}

func TestUserBoundaryIntersectsAllGrantsWithoutGrantingAuthority(t *testing.T) {
	now := authorityTestTime()
	request := boundAuthorizationRequest(t, iamv1.AuthorizationRequest{Action: iamv1.ActionPaaSApplicationRead,
		Resource: iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "application-prod"}, RequestID: "boundary-test", CorrelationID: "boundary-test"}, iamv1.AuthorizationResourceInstance, "")
	for _, test := range []struct {
		name     string
		grants   bool
		boundary bool
		effect   iamv1.PolicyEffect
		resource string
		want     bool
	}{
		{"no grants and no boundary", false, false, iamv1.PolicyAllow, "application-prod", false},
		{"boundary alone", false, true, iamv1.PolicyAllow, "application-prod", false},
		{"unbounded grants", true, false, iamv1.PolicyAllow, "application-prod", true},
		{"intersection", true, true, iamv1.PolicyAllow, "application-prod", true},
		{"different resource", true, true, iamv1.PolicyAllow, "application-other", false},
		{"explicit boundary deny", true, true, iamv1.PolicyDeny, "application-prod", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			subject := authoritySubject(now)
			if test.grants {
				subject.Policies = authoritySubject(now, iamv1.SystemPolicyPaaSDeveloper, iamv1.SystemPolicyPaaSViewer).Policies
			}
			if test.boundary {
				version := policyVersionForTest(t, "policy-boundary", test.effect, request.Action, iamv1.PolicyResourceExact, test.resource)
				subject.Boundary = userBoundaryForTest(subject, version)
			}
			decision, err := Decide(subject, iamv1.ServicePaaS, request, "decision-boundary", now)
			if err != nil || decision.Allowed != test.want {
				t.Fatalf("allowed=%v err=%v", decision.Allowed, err)
			}
			if !test.grants && len(decision.PolicyEvidence) != 0 {
				t.Fatal("boundary synthesized a positive attachment")
			}
			if test.boundary && (decision.BoundaryEvidence.Version == nil || decision.BoundaryEvidence.Version.PolicyID != "policy-boundary") {
				t.Fatal("nonmatching boundary lost its version proof")
			}
			encoded, err := json.Marshal(decision)
			if err != nil || bytes.Contains(encoded, []byte("boundaryId")) || bytes.Contains(encoded, []byte("policy-boundary")) {
				t.Fatal("private boundary evidence leaked")
			}
		})
	}
}

func TestFamilyPolicyUsesVerifiedResolvedActionsForAllowAndDeny(t *testing.T) {
	allow := policyVersionForTest(t, "family-allow", iamv1.PolicyAllow, iamv1.ActionPaaSApplicationRead, iamv1.PolicyResourceAnyInAuthority, "")
	allow.Document.Statements[0].Actions = []iamv1.Action{"paas.application.*"}
	compilePolicyVersionForTest(t, &allow)
	deny := policyVersionForTest(t, "family-deny", iamv1.PolicyDeny, iamv1.ActionPaaSApplicationRead, iamv1.PolicyResourceExact, "blocked-application")
	deny.Document.Statements[0].Actions = []iamv1.Action{"paas.application.*"}
	compilePolicyVersionForTest(t, &deny)
	context := policyContextForTest(authorityTestTime())
	for _, id := range []string{"allowed-application", "blocked-application"} {
		request := policyEvaluationRequestForTest(t, iamv1.ActionPaaSApplicationRead, iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: id})
		for _, versions := range [][]iamv1.PolicyVersion{{allow, deny}, {deny, allow}} {
			result, err := evaluatePolicies(context, versions, request)
			if err != nil || result.Allowed != (id == "allowed-application") || result.ExplicitDeny != (id == "blocked-application") {
				t.Fatalf("family effect/resource composition failed: allowed=%v deny=%v err=%v", result.Allowed, result.ExplicitDeny, err)
			}
		}
	}
	request := boundAuthorizationRequest(t, iamv1.AuthorizationRequest{Action: iamv1.ActionPaaSApplicationCreate,
		Resource: iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "collection"}, RequestID: "family-create", CorrelationID: "family-create"},
		iamv1.AuthorizationResourceCollection, iamv1.AuthorizationCollectionCreate)
	if result, err := evaluatePolicies(context, []iamv1.PolicyVersion{allow}, request); err != nil || !result.Allowed {
		t.Fatal("resolved create action was replaced by author-string matching", err)
	}
	request = policyEvaluationRequestForTest(t, iamv1.ActionPaaSDeploymentCreate, iamv1.ResourceReference{Kind: iamv1.ResourceDeployment, ID: "collection"})
	if result, err := evaluatePolicies(context, []iamv1.PolicyVersion{allow}, request); err != nil || result.Allowed {
		t.Fatal("family evaluation leaked into another action family", err)
	}
}

func TestUserBoundarySeparatesPlatformAuthorityAndEvaluatesCurrentConditions(t *testing.T) {
	now := authorityTestTime()
	subject := authoritySubject(now, iamv1.SystemPolicyPaaSDeveloper, iamv1.SystemPolicyPlatformOperator)
	version := policyVersionForTest(t, "policy-boundary", iamv1.PolicyAllow, iamv1.ActionPaaSApplicationRead, iamv1.PolicyResourcePrefixInAuthority, "application-prod")
	version.Document.Statements[0].Conditions = []iamv1.PolicyCondition{
		{Key: iamv1.ConditionIAMPrincipalID, Operator: iamv1.PolicyStringEquals, Values: []string{string(subject.Principal.ID)}},
		{Key: iamv1.ConditionIAMCurrentTime, Operator: iamv1.PolicyDateLessThan, Values: []string{now.Add(time.Minute).Format(time.RFC3339)}},
	}
	compilePolicyVersionForTest(t, &version)
	subject.Boundary = userBoundaryForTest(subject, version)
	request := boundAuthorizationRequest(t, iamv1.AuthorizationRequest{Action: iamv1.ActionPaaSApplicationRead, Resource: iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "application-prod-api"}, RequestID: "boundary-condition", CorrelationID: "boundary-condition"}, iamv1.AuthorizationResourceInstance, "")
	for _, offset := range []time.Duration{0, time.Minute} {
		result, err := Decide(subject, iamv1.ServicePaaS, request, "decision-condition", now.Add(offset))
		if err != nil || result.Allowed != (offset == 0) || result.BoundaryEvidence.Version == nil {
			t.Fatal("boundary condition/time proof differs")
		}
	}
	request.Action, request.Resource = iamv1.ActionPaaSExecutionTargetRead, iamv1.ResourceReference{Kind: iamv1.ResourceExecutionTarget, ID: "target-example"}
	result, err := Decide(subject, iamv1.ServicePaaS, request, "decision-platform", now.Add(time.Minute))
	if err != nil || !result.Allowed || result.BoundaryEvidence.State != "NOT_APPLICABLE" {
		t.Fatal("tenant boundary restricted independent platform authority")
	}
	subject.Boundary.AccountID = "foreign"
	if result, err := Decide(subject, iamv1.ServicePaaS, request, "decision-corrupt", now); !errors.Is(err, ErrAuthorityUnavailable) || result.Allowed {
		t.Fatal("platform decision bypassed identity integrity")
	}
}

func TestUserBoundaryCorruptionCannotBecomeUnbounded(t *testing.T) {
	now := authorityTestTime()
	request := boundAuthorizationRequest(t, iamv1.AuthorizationRequest{Action: iamv1.ActionPaaSApplicationRead, Resource: iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "application-prod"}, RequestID: "boundary-invalid", CorrelationID: "boundary-invalid"}, iamv1.AuthorizationResourceInstance, "")
	for _, test := range []struct {
		name   string
		mutate func(*SubjectContext)
	}{
		{"missing", func(s *SubjectContext) { s.Boundary = nil }},
		{"unknown state", func(s *SubjectContext) { s.Boundary.State = "UNKNOWN" }},
		{"foreign account", func(s *SubjectContext) { s.Boundary.AccountID = "other" }},
		{"foreign user", func(s *SubjectContext) { s.Boundary.UserID = "other" }},
		{"stale user revision", func(s *SubjectContext) { s.Boundary.UserResourceVersion++ }},
		{"false none", func(s *SubjectContext) { s.Boundary.State = "NONE" }},
		{"missing policy", func(s *SubjectContext) { s.Boundary.Policy = nil }},
		{"wrong default", func(s *SubjectContext) { s.Boundary.Policy.DefaultVersionID = "different" }},
		{"foreign policy", func(s *SubjectContext) { s.Boundary.Policy.AccountID = "other" }},
		{"retired policy", func(s *SubjectContext) { s.Boundary.Policy.Status = iamv1.PolicyRetired }},
		{"corrupt digest", func(s *SubjectContext) { s.Boundary.Version.ContentDigest = "sha256:" + strings.Repeat("0", 64) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := authoritySubject(now, iamv1.SystemPolicyPaaSDeveloper)
			s.Boundary = userBoundaryForTest(s, policyVersionForTest(t, "policy-boundary", iamv1.PolicyAllow, request.Action, iamv1.PolicyResourceAnyInAuthority, ""))
			test.mutate(&s)
			result, err := Decide(s, iamv1.ServicePaaS, request, "decision-invalid", now)
			if !errors.Is(err, ErrAuthorityUnavailable) || result.Allowed {
				t.Fatal("corrupt boundary allowed or silently denied instead of failing closed")
			}
		})
	}
}

func userBoundaryForTest(subject SubjectContext, version iamv1.PolicyVersion) *ResolvedUserBoundary {
	policy := iamv1.Policy{APIVersion: iamv1.APIVersion, Kind: "Policy", ID: version.PolicyID, Management: iamv1.PolicyCustomerManaged,
		AccountID: subject.Organization.ID, DisplayName: "Boundary", Scope: iamv1.AuthorityScopeTenant, Status: iamv1.PolicyActive,
		DefaultVersionID: version.ID, ResourceVersion: 1, CreatedAt: subject.Principal.CreatedAt, UpdatedAt: subject.Principal.UpdatedAt}
	return &ResolvedUserBoundary{State: "BOUND", AccountID: subject.Organization.ID, UserID: subject.Principal.ID, UserResourceVersion: subject.Principal.ResourceVersion,
		BoundaryID: "boundary-example", ResourceVersion: 1, Policy: &policy, Version: &version, Profiles: iamv1.AllAuthorizationProfiles()}
}

func TestIdentityConditionsUseTheAuthenticatedSubjectAndExactSetSemantics(t *testing.T) {
	now := authorityTestTime()
	for _, test := range []struct {
		name     string
		operator iamv1.PolicyConditionOperator
		values   []string
		allow    bool
	}{
		{"any equals", iamv1.PolicyStringEquals, []string{"another-user", "principal-developer"}, true},
		{"case sensitive", iamv1.PolicyStringEquals, []string{"Principal-developer"}, false},
		{"all not equals", iamv1.PolicyStringNotEquals, []string{"another-user", "third-user"}, true},
		{"one excluded value", iamv1.PolicyStringNotEquals, []string{"another-user", "principal-developer"}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			context := authoritySubject(now, iamv1.SystemPolicyPaaSViewer)
			row := &context.Policies[0]
			row.Version = policyVersionForTest(t, "policy-identity", iamv1.PolicyAllow, iamv1.ActionPaaSApplicationRead, iamv1.PolicyResourceAnyInAuthority, "")
			row.Policy.ID, row.Attachment.PolicyID = row.Version.PolicyID, row.Version.PolicyID
			row.Policy.Management, row.Policy.AccountID = iamv1.PolicyCustomerManaged, context.Organization.ID
			row.Policy.DefaultVersionID = row.Version.ID
			row.Version.Document.Statements[0].Conditions = []iamv1.PolicyCondition{
				{Key: iamv1.ConditionIAMAccountID, Operator: iamv1.PolicyStringEquals, Values: []string{string(context.Organization.ID)}},
				{Key: iamv1.ConditionIAMPrincipalID, Operator: test.operator, Values: test.values},
				{Key: iamv1.ConditionIAMCurrentTime, Operator: iamv1.PolicyDateLessThan, Values: []string{now.Add(time.Minute).Format(time.RFC3339Nano)}},
			}
			refresh := func() {
				t.Helper()
				compilePolicyVersionForTest(t, &row.Version)
			}
			refresh()
			request := boundAuthorizationRequest(t, iamv1.AuthorizationRequest{Action: iamv1.ActionPaaSApplicationRead, Resource: iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "identity-app"}, RequestID: "identity-read", CorrelationID: "identity-read"}, iamv1.AuthorizationResourceInstance, "")
			decision, err := Decide(context, iamv1.ServicePaaS, request, "decision-identity", now)
			if err != nil || decision.Allowed != test.allow {
				t.Fatalf("actual identity decision allowed=%t want=%t err=%v", decision.Allowed, test.allow, err)
			}
			row.Attachment.Target = iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetGroup, ID: "group-identity"}
			row.Membership = &iamv1.GroupMembership{APIVersion: iamv1.APIVersion, Kind: "GroupMembership", ID: "membership-identity",
				AccountID: context.Organization.ID, GroupID: "group-identity", UserID: context.Principal.ID, CreatedBy: context.Principal.ID,
				ResourceVersion: 1, CreatedAt: now, UpdatedAt: now}
			decision, err = Decide(context, iamv1.ServicePaaS, request, "decision-group-identity", now)
			if err != nil || decision.Allowed != test.allow || test.allow && (len(decision.PolicyEvidence) != 1 || decision.PolicyEvidence[0].MembershipID != row.Membership.ID) {
				t.Fatal("group conditions substituted the group for its authenticated user or lost inheritance proof")
			}
			row.Version.Document.Statements[0].Conditions[0].Values = []string{"another-account"}
			refresh()
			if decision, err := Decide(context, iamv1.ServicePaaS, request, "decision-account", now); err != nil || decision.Allowed {
				t.Fatal("identity condition ignored current account")
			}
		})
	}
}

func TestIdentityConditionDenyAndMissingAuthorityFailClosed(t *testing.T) {
	context := policyContextForTest(authorityTestTime())
	plain := policyVersionForTest(t, "policy-plain", iamv1.PolicyAllow, iamv1.ActionPaaSApplicationRead, iamv1.PolicyResourceAnyInAuthority, "")
	conditional := policyVersionForTest(t, "policy-conditional-deny", iamv1.PolicyDeny, iamv1.ActionPaaSApplicationRead, iamv1.PolicyResourceAnyInAuthority, "")
	resource := iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "identity-app"}
	for _, operator := range []iamv1.PolicyConditionOperator{iamv1.PolicyStringEquals, iamv1.PolicyStringNotEquals} {
		values := []string{string(context.subject.ID)}
		if operator == iamv1.PolicyStringNotEquals {
			values = []string{"another-user", "third-user"}
		}
		conditional.Document.Statements[0].Conditions = []iamv1.PolicyCondition{{Key: iamv1.ConditionIAMPrincipalID, Operator: operator, Values: values}}
		compilePolicyVersionForTest(t, &conditional)
		for _, versions := range [][]iamv1.PolicyVersion{{plain, conditional}, {conditional, plain}} {
			decision, err := evaluatePolicies(context, versions, policyEvaluationRequestForTest(t, iamv1.ActionPaaSApplicationRead, resource))
			if err != nil || decision.Allowed || !decision.ExplicitDeny || len(decision.MatchedVersions) != 2 {
				t.Fatal("identity Deny lost across sources")
			}
			for _, invalid := range []policyEvaluationContext{
				{databaseTime: context.databaseTime, subject: context.subject},
				{databaseTime: context.databaseTime, accountID: context.accountID, subject: iamv1.Subject{Type: iamv1.PrincipalUser}},
				{databaseTime: context.databaseTime, accountID: context.accountID, subject: iamv1.Subject{Type: iamv1.PrincipalServiceAccount, ID: context.subject.ID}},
			} {
				decision, err := evaluatePolicies(invalid, versions, policyEvaluationRequestForTest(t, iamv1.ActionPaaSApplicationRead, resource))
				if !errors.Is(err, ErrInvalidPolicyState) || decision.Allowed || len(decision.MatchedVersions) != 0 {
					t.Fatal("missing/unsupported identity bypassed a condition through another Allow")
				}
			}
		}
	}
}

func TestPolicyTimeWindowsUseOneAuthorityClockAndDenyAcrossSources(t *testing.T) {
	now := authorityTestTime()
	plain := policyVersionForTest(t, "policy-plain", iamv1.PolicyAllow, iamv1.ActionPaaSApplicationRead, iamv1.PolicyResourceAnyInAuthority, "")
	window := policyVersionForTest(t, "policy-window", iamv1.PolicyAllow, iamv1.ActionPaaSApplicationRead, iamv1.PolicyResourceAnyInAuthority, "")
	window.Document.Statements[0].Conditions = []iamv1.PolicyCondition{
		{Key: iamv1.ConditionIAMCurrentTime, Operator: iamv1.PolicyDateGreaterThanEquals, Values: []string{now.Format(time.RFC3339Nano)}},
		{Key: iamv1.ConditionIAMCurrentTime, Operator: iamv1.PolicyDateLessThan, Values: []string{now.Add(time.Minute).Format(time.RFC3339Nano)}},
	}
	refresh := func(version *iamv1.PolicyVersion) {
		t.Helper()
		compilePolicyVersionForTest(t, version)
	}
	refresh(&window)
	resource := iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "time-window-application"}
	for _, test := range []struct {
		offset time.Duration
		allow  bool
	}{
		{-time.Microsecond, false}, {0, true}, {time.Second, true}, {time.Minute - time.Microsecond, true}, {time.Minute, false}, {2 * time.Minute, false},
	} {
		result, err := evaluatePolicies(policyContextForTest(now.Add(test.offset)), []iamv1.PolicyVersion{window}, policyEvaluationRequestForTest(t, iamv1.ActionPaaSApplicationRead, resource))
		if err != nil || result.Allowed != test.allow || (len(result.MatchedVersions) > 0) != test.allow {
			t.Fatalf("window offset=%s allowed=%t err=%v", test.offset, result.Allowed, err)
		}
	}
	window.Document.Statements[0].Effect = iamv1.PolicyDeny
	refresh(&window)
	for _, versions := range [][]iamv1.PolicyVersion{{plain, window}, {window, plain}} {
		result, err := evaluatePolicies(policyContextForTest(now), versions, policyEvaluationRequestForTest(t, iamv1.ActionPaaSApplicationRead, resource))
		if err != nil || result.Allowed || !result.ExplicitDeny || len(result.MatchedVersions) != 2 {
			t.Fatal("conditional deny lost to another source")
		}
		result, err = evaluatePolicies(policyContextForTest(now.Add(time.Minute)), versions, policyEvaluationRequestForTest(t, iamv1.ActionPaaSApplicationRead, resource))
		if err != nil || !result.Allowed || result.ExplicitDeny || len(result.MatchedVersions) != 1 {
			t.Fatal("expired deny still matched")
		}
	}
	for _, invalid := range []time.Time{{}, now.Add(time.Nanosecond), now.In(time.FixedZone("caller", 3600))} {
		if result, err := evaluatePolicies(policyContextForTest(invalid), []iamv1.PolicyVersion{plain, window}, policyEvaluationRequestForTest(t, iamv1.ActionPaaSApplicationRead, resource)); err == nil || result.Allowed {
			t.Fatal("missing/invalid authority time allowed")
		}
	}
	context := authoritySubject(now, iamv1.SystemPolicyPaaSViewer)
	context.Policies[0].Version = window
	context.Policies[0].Policy.ID, context.Policies[0].Attachment.PolicyID = window.PolicyID, window.PolicyID
	context.Policies[0].Policy.Management, context.Policies[0].Policy.AccountID = iamv1.PolicyCustomerManaged, context.Organization.ID
	context.Policies[0].Policy.DefaultVersionID = window.ID
	window.Document.Statements[0].Effect = iamv1.PolicyAllow
	refresh(&window)
	context.Policies[0].Version = window
	request := boundAuthorizationRequest(t, iamv1.AuthorizationRequest{Action: iamv1.ActionPaaSApplicationRead, Resource: resource, RequestID: "request-time", CorrelationID: "request-time"}, iamv1.AuthorizationResourceInstance, "")
	for _, offset := range []time.Duration{0, time.Minute} {
		result, err := Decide(context, iamv1.ServicePaaS, request, "decision-time", now.Add(offset))
		if err != nil || result.Allowed != (offset == 0) || !result.DecidedAt.Equal(now.Add(offset)) {
			t.Fatal("actual decision ignored authoritative time")
		}
	}
	context.Policies[0].Version.Document.Statements[0].Conditions[0].Key = "caller.current-time"
	if result, err := Decide(context, iamv1.ServicePaaS, request, "decision-corrupt-time", now); !errors.Is(err, ErrAuthorityUnavailable) || result.Allowed {
		t.Fatal("unknown condition source was silently ignored")
	}
}

func TestResourcePrefixEvaluationIsLiteralAndDenyFirst(t *testing.T) {
	allow := policyVersionForTest(t, "policy-prefix-allow", iamv1.PolicyAllow, iamv1.ActionPaaSApplicationRead, "PREFIX_IN_AUTHORITY", "application-prod-")
	deny := policyVersionForTest(t, "policy-prefix-deny", iamv1.PolicyDeny, iamv1.ActionPaaSApplicationRead, "PREFIX_IN_AUTHORITY", "application-prod-private")
	for _, test := range []struct {
		id              string
		allowed, denied bool
	}{
		{"application-prod-", true, false},
		{"application-prod-api", true, false},
		{"application-prod", false, false},
		{"Application-prod-api", false, false},
		{"application-dev-api", false, false},
		{"application-prod-private", false, true},
		{"application-prod-private-api", false, true},
	} {
		for _, versions := range [][]iamv1.PolicyVersion{{allow, deny}, {deny, allow}} {
			result, err := evaluatePolicies(policyContextForTest(authorityTestTime()), versions, policyEvaluationRequestForTest(t, iamv1.ActionPaaSApplicationRead, iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: test.id}))
			if err != nil || result.Allowed != test.allowed || result.ExplicitDeny != test.denied {
				t.Fatalf("prefix evaluation id=%s allowed=%v deny=%v err=%v", test.id, result.Allowed, result.ExplicitDeny, err)
			}
		}
	}
	longPrefix := strings.Repeat("r", 127)
	longVersion := policyVersionForTest(t, "policy-long-prefix", iamv1.PolicyAllow, iamv1.ActionPaaSApplicationRead, iamv1.PolicyResourcePrefixInAuthority, longPrefix)
	for _, id := range []string{longPrefix, longPrefix + "z", longPrefix[:126], longPrefix[:126] + "Rz"} {
		result, err := evaluatePolicies(policyContextForTest(authorityTestTime()), []iamv1.PolicyVersion{longVersion}, policyEvaluationRequestForTest(t, iamv1.ActionPaaSApplicationRead, iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: id}))
		if err != nil || result.Allowed != (id == longPrefix || id == longPrefix+"z") {
			t.Fatal("maximum-length literal prefix comparison differs")
		}
	}
}

func TestPolicyEvaluationDefaultsToDenyAndExplicitDenyWins(t *testing.T) {
	allow := policyVersionForTest(t, "policy-allow", iamv1.PolicyAllow, iamv1.ActionPaaSApplicationRead, iamv1.PolicyResourceAnyInAuthority, "")
	deny := policyVersionForTest(t, "policy-deny", iamv1.PolicyDeny, iamv1.ActionPaaSApplicationRead, iamv1.PolicyResourceExact, "application-protected")
	for _, test := range []struct {
		name                  string
		policies              []iamv1.PolicyVersion
		resourceID            string
		allowed, explicitDeny bool
		matched               int
	}{
		{"no grant", nil, "application-open", false, false, 0},
		{"allow", []iamv1.PolicyVersion{allow}, "application-open", true, false, 1},
		{"unmatched deny", []iamv1.PolicyVersion{deny}, "application-open", false, false, 0},
		{"allow without matching deny", []iamv1.PolicyVersion{allow, deny}, "application-open", true, false, 1},
		{"deny last", []iamv1.PolicyVersion{allow, deny}, "application-protected", false, true, 2},
		{"deny first", []iamv1.PolicyVersion{deny, allow}, "application-protected", false, true, 2},
		{"inherited duplicate", []iamv1.PolicyVersion{allow, allow}, "application-open", true, false, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			result, err := evaluatePolicies(policyContextForTest(authorityTestTime()), test.policies, policyEvaluationRequestForTest(t, iamv1.ActionPaaSApplicationRead, iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: test.resourceID}))
			if err != nil || result.Allowed != test.allowed || result.ExplicitDeny != test.explicitDeny || len(result.MatchedVersions) != test.matched {
				t.Fatalf("evaluation=%+v err=%v", result, err)
			}
		})
	}
	if result, err := evaluatePolicies(policyContextForTest(authorityTestTime()), []iamv1.PolicyVersion{allow}, policyEvaluationRequestForTest(t, iamv1.ActionPaaSApplicationCreate, iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "application-open"})); err != nil || result.Allowed {
		t.Fatal("read permission allowed a write")
	}
}

func TestAttachedPolicyEvaluationRequiresCurrentOwnedRelationships(t *testing.T) {
	now := authorityTestTime()
	version := policyVersionForTest(t, "policy-reader", iamv1.PolicyAllow, iamv1.ActionPaaSApplicationRead, iamv1.PolicyResourceAnyInAuthority, "")
	row := AttachedPolicy{
		Profiles: iamv1.AllAuthorizationProfiles(),
		Policy: iamv1.Policy{APIVersion: iamv1.APIVersion, Kind: "Policy", ID: version.PolicyID, Management: iamv1.PolicyCustomerManaged,
			AccountID: "account-a", DisplayName: "Reader", Scope: iamv1.AuthorityScopeTenant, Status: iamv1.PolicyActive,
			DefaultVersionID: version.ID, ResourceVersion: 1, CreatedAt: now, UpdatedAt: now},
		Version: version,
		Attachment: iamv1.PolicyAttachment{APIVersion: iamv1.APIVersion, Kind: "PolicyAttachment", ID: "attachment-a", AccountID: "account-a",
			Target: iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetUser, ID: "user-a"}, PolicyID: version.PolicyID,
			Scope: iamv1.AuthorityScopeTenant, ResourceVersion: 7, CreatedAt: now, UpdatedAt: now},
	}
	subject := iamv1.Subject{Type: iamv1.PrincipalUser, ID: "user-a"}
	resource := iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "application-a"}
	result, evidence, err := EvaluateAttachedPolicies(authorityTestTime(), "account-a", "installation-a", subject, []AttachedPolicy{row}, policyEvaluationRequestForTest(t, iamv1.ActionPaaSApplicationRead, resource))
	if err != nil || !result.Allowed || len(evidence) != 1 || evidence[0].AttachmentID != row.Attachment.ID ||
		evidence[0].ResourceVersion != 7 || evidence[0].MembershipID != "" || evidence[0].MembershipResourceVersion != 0 ||
		evidence[0].Version.ContentDigest != version.ContentDigest {
		t.Fatal("valid attachment lost its authority evidence")
	}
	membership := iamv1.GroupMembership{APIVersion: iamv1.APIVersion, Kind: "GroupMembership", ID: "membership-a",
		AccountID: "account-a", GroupID: "group-a", UserID: subject.ID, CreatedBy: "user-admin",
		ResourceVersion: 1, CreatedAt: now, UpdatedAt: now}
	groupRow := row
	groupRow.Attachment.ID = "attachment-group"
	groupRow.Attachment.Target = iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetGroup, ID: string(membership.GroupID)}
	groupRow.Membership = &membership
	result, evidence, err = EvaluateAttachedPolicies(authorityTestTime(), "account-a", "installation-a", subject, []AttachedPolicy{groupRow}, policyEvaluationRequestForTest(t, iamv1.ActionPaaSApplicationRead, resource))
	if err != nil || !result.Allowed || len(evidence) != 1 || evidence[0].AttachmentID != groupRow.Attachment.ID ||
		evidence[0].MembershipID != membership.ID || evidence[0].MembershipResourceVersion != membership.ResourceVersion {
		t.Fatal("valid group inheritance lost its membership evidence")
	}
	for name, mutate := range map[string]func(*AttachedPolicy){
		"foreign membership account": func(v *AttachedPolicy) { v.Membership.AccountID = "account-b" },
		"foreign membership user":    func(v *AttachedPolicy) { v.Membership.UserID = "user-b" },
		"foreign membership group":   func(v *AttachedPolicy) { v.Membership.GroupID = "group-b" },
		"removed membership": func(v *AttachedPolicy) {
			v.Membership.RemovedAt, v.Membership.RemovedBy = &now, "user-admin"
			v.Membership.ResourceVersion, v.Membership.UpdatedAt = 2, now
		},
		"group platform scope": func(v *AttachedPolicy) {
			v.Attachment.Scope, v.Attachment.InstallationID = iamv1.AuthorityScopeInstallation, "installation-a"
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := groupRow
			membershipCopy := *groupRow.Membership
			changed.Membership = &membershipCopy
			mutate(&changed)
			result, evidence, err := EvaluateAttachedPolicies(authorityTestTime(), "account-a", "installation-a", subject, []AttachedPolicy{changed}, policyEvaluationRequestForTest(t, iamv1.ActionPaaSApplicationRead, resource))
			if !errors.Is(err, ErrInvalidPolicyState) || result.Allowed || len(evidence) != 0 {
				t.Fatal("invalid group relationship produced a partial decision")
			}
		})
	}
	serviceSubject := iamv1.Subject{Type: iamv1.PrincipalServiceAccount, ID: subject.ID}
	if result, evidence, err := EvaluateAttachedPolicies(authorityTestTime(), "account-a", "installation-a", serviceSubject, []AttachedPolicy{groupRow}, policyEvaluationRequestForTest(t, iamv1.ActionPaaSApplicationRead, resource)); !errors.Is(err, ErrInvalidPolicyState) || result.Allowed || len(evidence) != 0 {
		t.Fatal("service identity inherited a user group policy")
	}
	for name, mutate := range map[string]func(*AttachedPolicy){
		"foreign attachment account": func(v *AttachedPolicy) { v.Attachment.AccountID = "account-b" },
		"foreign policy owner":       func(v *AttachedPolicy) { v.Policy.AccountID = "account-b" },
		"foreign user":               func(v *AttachedPolicy) { v.Attachment.Target.ID = "user-b" },
		"user service confusion":     func(v *AttachedPolicy) { v.Attachment.Target.Kind = iamv1.PolicyTargetService },
		"unproved group inheritance": func(v *AttachedPolicy) { v.Attachment.Target.Kind = iamv1.PolicyTargetGroup },
		"unproved role session":      func(v *AttachedPolicy) { v.Attachment.Target.Kind = iamv1.PolicyTargetRole },
		"retired policy":             func(v *AttachedPolicy) { v.Policy.Status = iamv1.PolicyRetired },
		"revoked attachment":         func(v *AttachedPolicy) { v.Attachment.RevokedAt = &now },
		"foreign policy reference":   func(v *AttachedPolicy) { v.Attachment.PolicyID = "policy-b" },
		"foreign version owner":      func(v *AttachedPolicy) { v.Version.PolicyID = "policy-b" },
		"nondefault version":         func(v *AttachedPolicy) { v.Policy.DefaultVersionID = "version-next" },
		"wrong digest":               func(v *AttachedPolicy) { v.Version.ContentDigest = "sha256:" + strings.Repeat("0", 64) },
		"mixed scope": func(v *AttachedPolicy) {
			v.Attachment.Scope, v.Attachment.InstallationID = iamv1.AuthorityScopeInstallation, "installation-a"
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := row
			changed.Attachment.ID = "attachment-b"
			mutate(&changed)
			result, evidence, err := EvaluateAttachedPolicies(authorityTestTime(), "account-a", "installation-a", subject, []AttachedPolicy{row, changed}, policyEvaluationRequestForTest(t, iamv1.ActionPaaSApplicationRead, resource))
			if !errors.Is(err, ErrInvalidPolicyState) || result.Allowed || len(evidence) != 0 {
				t.Fatal("invalid current relationship produced a partial decision")
			}
		})
	}
	if result, evidence, err := EvaluateAttachedPolicies(authorityTestTime(), "account-a", "installation-a", subject, nil, policyEvaluationRequestForTest(t, iamv1.ActionPaaSApplicationRead, resource)); err != nil || result.Allowed || len(evidence) != 0 {
		t.Fatal("empty policy authority granted permission")
	}
	if result, _, err := EvaluateAttachedPolicies(authorityTestTime(), "account-a", "installation-a", subject, []AttachedPolicy{row, row}, policyEvaluationRequestForTest(t, iamv1.ActionPaaSApplicationRead, resource)); !errors.Is(err, ErrInvalidPolicyState) || result.Allowed {
		t.Fatal("duplicate attachment identity accepted")
	}
	if result, evidence, err := EvaluateAttachedPolicies(authorityTestTime(), "account-a", "installation-a", subject, make([]AttachedPolicy, MaxEvaluationPolicies+1), policyEvaluationRequestForTest(t, iamv1.ActionPaaSApplicationRead, resource)); !errors.Is(err, ErrInvalidPolicyState) || result.Allowed || len(evidence) != 0 {
		t.Fatal("attachment work budget was not enforced")
	}
	deny := row
	deny.Version = policyVersionForTest(t, "policy-deny", iamv1.PolicyDeny, iamv1.ActionPaaSApplicationRead, iamv1.PolicyResourceAnyInAuthority, "")
	deny.Policy.ID, deny.Policy.DefaultVersionID = deny.Version.PolicyID, deny.Version.ID
	deny.Attachment.ID, deny.Attachment.PolicyID = "attachment-b", deny.Version.PolicyID
	result, evidence, err = EvaluateAttachedPolicies(authorityTestTime(), "account-a", "installation-a", subject, []AttachedPolicy{deny, row}, policyEvaluationRequestForTest(t, iamv1.ActionPaaSApplicationRead, resource))
	if err != nil || result.Allowed || !result.ExplicitDeny || len(evidence) != 2 || evidence[0].AttachmentID != row.Attachment.ID || evidence[1].Version.PolicyID != deny.Policy.ID {
		t.Fatal("deny or the exact attachment/content evidence was lost")
	}
	_, reversed, err := EvaluateAttachedPolicies(authorityTestTime(), "account-a", "installation-a", subject, []AttachedPolicy{row, deny}, policyEvaluationRequestForTest(t, iamv1.ActionPaaSApplicationRead, resource))
	if err != nil || !slices.Equal(evidence, reversed) {
		t.Fatal("source order changed immutable policy evidence")
	}
	changedDefault := row
	changedDefault.Version = policyVersionForTest(t, row.Policy.ID, iamv1.PolicyDeny, iamv1.ActionPaaSApplicationRead, iamv1.PolicyResourceAnyInAuthority, "")
	changedDefault.Version.ID = "version-new-default"
	changedDefault.Policy.DefaultVersionID = changedDefault.Version.ID
	changedDefault.Policy.ResourceVersion++
	result, evidence, err = EvaluateAttachedPolicies(authorityTestTime(), "account-a", "installation-a", subject, []AttachedPolicy{changedDefault}, policyEvaluationRequestForTest(t, iamv1.ActionPaaSApplicationRead, resource))
	if err != nil || result.Allowed || !result.ExplicitDeny || len(evidence) != 1 || evidence[0].Version.VersionID != changedDefault.Version.ID {
		t.Fatal("current default content did not govern the unchanged attachment")
	}
	platform, err := SystemPolicyVersion(iamv1.SystemPolicyPlatformOperator)
	if err != nil {
		t.Fatal(err)
	}
	row.Policy.ID, row.Policy.Management, row.Policy.AccountID = platform.PolicyID, iamv1.PolicySystemManaged, ""
	row.Policy.Scope, row.Policy.DefaultVersionID, row.Version = platform.Document.Scope, platform.ID, platform
	row.Attachment.PolicyID, row.Attachment.Scope, row.Attachment.InstallationID = platform.PolicyID, platform.Document.Scope, "installation-a"
	platformResource := iamv1.ResourceReference{Kind: iamv1.ResourceExecutionTarget, ID: "host-a"}
	for _, installation := range []string{"", "installation-b", "installation-a"} {
		result, _, err := EvaluateAttachedPolicies(authorityTestTime(), "account-a", installation, subject, []AttachedPolicy{row}, policyEvaluationRequestForTest(t, iamv1.ActionPaaSExecutionTargetRead, platformResource))
		if installation == "installation-a" {
			if err != nil || !result.Allowed {
				t.Fatal("sealed platform attachment rejected")
			}
		} else if !errors.Is(err, ErrInvalidPolicyState) || result.Allowed {
			t.Fatal("platform attachment escaped its installation")
		}
	}
}

func TestSystemPoliciesPublishIndependentContentBoundVersions(t *testing.T) {
	for _, id := range []iamv1.PolicyID{iamv1.SystemPolicyAccountAdministrator, iamv1.SystemPolicyPlatformOperator,
		iamv1.SystemPolicyPaaSDeveloper, iamv1.SystemPolicyPaaSViewer, iamv1.SystemPolicyAuditReader, iamv1.SystemPolicyInstallationVerifier} {
		t.Run(string(id), func(t *testing.T) {
			original, err := SystemPolicyVersion(id)
			if err != nil || iamv1.ValidatePolicyVersion(original) != nil {
				t.Fatalf("invalid system policy: %v", err)
			}
			before, digest, err := iamv1.CanonicalizePolicyCompilation(original.Document, *original.Compilation, iamv1.AllAuthorizationProfiles())
			if err != nil || string(original.ID) != "version-"+digest[len("sha256:"):] {
				t.Fatal("version does not identify its content")
			}
			original.Document.Statements[0].Effect = iamv1.PolicyDeny
			original.Document.Statements[0].Resources[0].Match = iamv1.PolicyResourceExact
			original.Document.Statements[0].Resources[0].ID = "resource-changed"
			if iamv1.ValidatePolicyVersion(original) == nil {
				t.Fatal("changed content retained the old digest")
			}
			fresh, err := SystemPolicyVersion(id)
			if err != nil {
				t.Fatal(err)
			}
			after, afterDigest, err := iamv1.CanonicalizePolicyCompilation(fresh.Document, *fresh.Compilation, iamv1.AllAuthorizationProfiles())
			if err != nil || before != after || digest != afterDigest {
				t.Fatal("caller mutated published system policy content")
			}
		})
	}
	if _, err := SystemPolicyVersion("system.unregistered"); !errors.Is(err, ErrInvalidPolicyState) {
		t.Fatal("unknown system policy became authority")
	}
}

func BenchmarkPolicyEvaluation(b *testing.B) {
	for _, count := range []int{1, 16, 64} {
		b.Run(fmt.Sprintf("policies-%d", count), func(b *testing.B) {
			version, err := SystemPolicyVersion(iamv1.SystemPolicyPaaSDeveloper)
			if err != nil {
				b.Fatal(err)
			}
			policies := make([]iamv1.PolicyVersion, count)
			for i := range policies {
				policies[i] = version
				policies[i].PolicyID = iamv1.PolicyID(fmt.Sprintf("policy-%d", i))
			}
			resource := iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "application-example"}
			request := policyEvaluationRequestForTest(b, iamv1.ActionPaaSApplicationRead, resource)
			context := policyContextForTest(authorityTestTime())
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(iterations *testing.PB) {
				for iterations.Next() {
					result, err := evaluatePolicies(context, policies, request)
					if err != nil || !result.Allowed || len(result.MatchedVersions) != count {
						b.Error("invalid evaluation")
					}
				}
			})
		})
	}
}

func TestPolicyEvaluationBoundsTotalWorkAndOrdersEvidence(t *testing.T) {
	first := policyVersionForTest(t, "policy-a", iamv1.PolicyAllow, iamv1.ActionPaaSApplicationRead, iamv1.PolicyResourceAnyInAuthority, "")
	last := policyVersionForTest(t, "policy-z", iamv1.PolicyDeny, iamv1.ActionPaaSApplicationRead, iamv1.PolicyResourceAnyInAuthority, "")
	resource := iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "application-one"}
	left, err := evaluatePolicies(policyContextForTest(authorityTestTime()), []iamv1.PolicyVersion{last, first}, policyEvaluationRequestForTest(t, iamv1.ActionPaaSApplicationRead, resource))
	if err != nil {
		t.Fatal(err)
	}
	right, err := evaluatePolicies(policyContextForTest(authorityTestTime()), []iamv1.PolicyVersion{first, last}, policyEvaluationRequestForTest(t, iamv1.ActionPaaSApplicationRead, resource))
	if err != nil || !slices.Equal(left.MatchedVersions, right.MatchedVersions) || left.Allowed || right.Allowed || !right.ExplicitDeny {
		t.Fatal("source order changed authority evidence")
	}
	large := first
	large.Document.Statements = make([]iamv1.PolicyStatement, iamv1.MaxPolicyStatements)
	for i := range large.Document.Statements {
		large.Document.Statements[i] = first.Document.Statements[0]
		large.Document.Statements[i].SID = fmt.Sprintf("statement-%d", i)
	}
	compilePolicyVersionForTest(t, &large)
	versions := make([]iamv1.PolicyVersion, MaxEvaluationStatements/iamv1.MaxPolicyStatements)
	for i := range versions {
		versions[i] = large
		versions[i].PolicyID = iamv1.PolicyID(fmt.Sprintf("policy-%d", i))
	}
	if result, err := evaluatePolicies(policyContextForTest(authorityTestTime()), versions, policyEvaluationRequestForTest(t, iamv1.ActionPaaSApplicationRead, resource)); err != nil || !result.Allowed {
		t.Fatalf("valid bounded snapshot rejected: %v", err)
	}
	versions = append(versions, last)
	if result, err := evaluatePolicies(policyContextForTest(authorityTestTime()), versions, policyEvaluationRequestForTest(t, iamv1.ActionPaaSApplicationRead, resource)); !errors.Is(err, ErrInvalidPolicyState) || result.Allowed || len(result.MatchedVersions) != 0 {
		t.Fatal("aggregate statement limit returned partial authority")
	}
}

func TestPolicyEvaluationSeparatesScopesAndFailsClosedOnCorruptSnapshots(t *testing.T) {
	tenant := policyVersionForTest(t, "policy-tenant", iamv1.PolicyAllow, iamv1.ActionPaaSApplicationRead, iamv1.PolicyResourceAnyInAuthority, "")
	platform := policyVersionForTest(t, "policy-platform", iamv1.PolicyAllow, iamv1.ActionPaaSExecutionTargetRead, iamv1.PolicyResourceAnyInAuthority, "")
	probe := policyVersionForTest(t, "policy-probe", iamv1.PolicyAllow, iamv1.ActionInstallationVerify, iamv1.PolicyResourceAnyInAuthority, "")
	request := iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "application-one"}
	if result, err := evaluatePolicies(policyContextForTest(authorityTestTime()), []iamv1.PolicyVersion{platform, probe}, policyEvaluationRequestForTest(t, iamv1.ActionPaaSApplicationRead, request)); err != nil || result.Allowed {
		t.Fatal("platform/probe policy granted tenant resource access")
	}
	if result, err := evaluatePolicies(policyContextForTest(authorityTestTime()), []iamv1.PolicyVersion{tenant, platform, probe}, policyEvaluationRequestForTest(t, iamv1.ActionPaaSApplicationRead, request)); err != nil || !result.Allowed || len(result.MatchedVersions) != 1 || result.MatchedVersions[0].PolicyID != tenant.PolicyID {
		t.Fatal("unrelated scope changed tenant permission/evidence")
	}
	conflicting := tenant
	conflicting.ID = "version-two"
	invalid := platform
	invalid.ContentDigest = "sha256:invalid"
	for name, policies := range map[string][]iamv1.PolicyVersion{
		"conflicting effective versions":        {tenant, conflicting},
		"allow cannot hide invalid other scope": {tenant, invalid},
		"invalid first":                         {invalid, tenant},
		"too many policies":                     make([]iamv1.PolicyVersion, MaxEvaluationPolicies+1),
	} {
		t.Run(name, func(t *testing.T) {
			result, err := evaluatePolicies(policyContextForTest(authorityTestTime()), policies, policyEvaluationRequestForTest(t, iamv1.ActionPaaSApplicationRead, request))
			if !errors.Is(err, ErrInvalidPolicyState) || result.Allowed || result.ExplicitDeny || len(result.MatchedVersions) != 0 {
				t.Fatalf("invalid authority returned a partial result: %+v %v", result, err)
			}
		})
	}
	for _, resource := range []iamv1.ResourceReference{{Kind: iamv1.ResourcePrincipal, ID: "application-one"}, {Kind: iamv1.ResourceApplication, ID: "*"}} {
		if result, err := evaluatePolicies(policyContextForTest(authorityTestTime()), []iamv1.PolicyVersion{tenant}, policyEvaluationRequestForTest(t, iamv1.ActionPaaSApplicationRead, resource)); !errors.Is(err, ErrInvalidAuthorizationRequest) || result.Allowed {
			t.Fatal("malformed request acquired authority")
		}
	}
	if result, err := evaluatePolicies(policyContextForTest(authorityTestTime()), []iamv1.PolicyVersion{tenant}, policyEvaluationRequestForTest(t, "paas.unregistered.read", request)); !errors.Is(err, ErrInvalidAuthorizationRequest) || result.Allowed {
		t.Fatal("unknown action acquired authority")
	}
}

func TestManagedServiceUsesTheExistingClosedPaaSSystemPolicyMatrix(t *testing.T) {
	readActions := []iamv1.Action{
		iamv1.ActionManagedServiceOfferingRead,
		iamv1.ActionManagedServiceRegionRead,
		iamv1.ActionManagedServiceQuotaEntitlementRead,
		iamv1.ActionManagedServiceInstallationRead,
	}
	for _, action := range readActions {
		if !attachedSystemPolicyAllows(t, iamv1.SystemPolicyAccountAdministrator, action) ||
			!attachedSystemPolicyAllows(t, iamv1.SystemPolicyPaaSDeveloper, action) ||
			!attachedSystemPolicyAllows(t, iamv1.SystemPolicyPaaSViewer, action) ||
			!ServiceCanRequest(iamv1.ServicePaaS, action) {
			t.Fatalf("managed-service read action %q is not mapped to the system policies", action)
		}
	}
	for _, action := range []iamv1.Action{
		iamv1.ActionManagedServiceQuotaEntitlementActivate,
		iamv1.ActionManagedServiceInstallationCreate,
	} {
		if !attachedSystemPolicyAllows(t, iamv1.SystemPolicyAccountAdministrator, action) ||
			!attachedSystemPolicyAllows(t, iamv1.SystemPolicyPaaSDeveloper, action) ||
			attachedSystemPolicyAllows(t, iamv1.SystemPolicyPaaSViewer, action) ||
			!ServiceCanRequest(iamv1.ServicePaaS, action) {
			t.Fatalf("managed-service mutation action %q has an invalid policy mapping", action)
		}
	}
}

func TestPlatformAuthorityRequiresAnExplicitPolicyAndInstallationBinding(t *testing.T) {
	now := authorityTestTime()
	for _, action := range iamv1.AllActions() {
		if !iamv1.IsPlatformAction(action) {
			if attachedSystemPolicyAllows(t, iamv1.SystemPolicyPlatformOperator, action) {
				t.Fatalf("platform operator received unrelated authority %s", action)
			}
			continue
		}
		t.Run(string(action), func(t *testing.T) {
			kind, _ := iamv1.ResourceKindForAction(action)
			request := declaredAuthorizationRequest(t, iamv1.AuthorizationRequest{Action: action,
				Resource:  iamv1.ResourceReference{Kind: kind, ID: "resource-example"},
				RequestID: "request-platform", CorrelationID: "request-platform"})
			service := iamv1.ServicePaaS
			if ServiceCanRequest(iamv1.ServiceIAM, action) {
				service = iamv1.ServiceIAM
			} else if ServiceCanRequest(iamv1.ServiceAudit, action) {
				service = iamv1.ServiceAudit
			}
			for _, policyID := range testSystemPolicyIDs {
				if policyID == iamv1.SystemPolicyInstallationVerifier {
					continue // Probe authority belongs to a service, never a user.
				}
				context := authoritySubject(now, policyID)
				context.InstallationID = "installation-example"
				decision, err := Decide(context, service, request, "decision-platform", now)
				if err != nil || decision.Allowed != (policyID == iamv1.SystemPolicyPlatformOperator) {
					t.Fatalf("policy=%s decision=%+v error=%v", policyID, decision, err)
				}
				if decision.Allowed {
					if decision.InstallationID != context.InstallationID || decision.TenantID != "" || decision.Subject == nil {
						t.Fatal("platform decision was not bound exclusively to the installation")
					}
				} else if decision.InstallationID != "" || decision.TenantID != "" || decision.Subject != nil {
					t.Fatal("denied platform decision exposed authority")
				}
			}
			for _, mutation := range []func(*SubjectContext){
				func(context *SubjectContext) { context.InstallationID = "" },
				func(context *SubjectContext) { context.Principal.MustChangePassword = true },
				func(context *SubjectContext) { context.Policies = nil },
			} {
				context := authoritySubject(now, iamv1.SystemPolicyPlatformOperator)
				context.InstallationID = "installation-example"
				mutation(&context)
				decision, err := Decide(context, service, request, "decision-platform-denied", now)
				if (err != nil && !errors.Is(err, ErrAuthorityUnavailable)) || decision.Allowed {
					t.Fatalf("incomplete or revoked platform authority accepted: decision=%+v error=%v", decision, err)
				}
			}
		})
	}
}

func TestAccountUserCommandsRemainAccountAdministratorOnly(t *testing.T) {
	for _, action := range []iamv1.Action{iamv1.ActionIAMAccountAliasSet, iamv1.ActionIAMUserList, iamv1.ActionIAMUserSetStatus, iamv1.ActionIAMUserPasswordReset} {
		for _, policyID := range testSystemPolicyIDs {
			if attachedSystemPolicyAllows(t, policyID, action) != (policyID == iamv1.SystemPolicyAccountAdministrator) {
				t.Errorf("unexpected authority %s/%s", policyID, action)
			}
		}
	}
}

func TestAuthorizationDeniesAServiceOutsideItsProductBoundary(t *testing.T) {
	now := authorityTestTime()
	context := authoritySubject(now, iamv1.SystemPolicyPaaSDeveloper)
	request := boundAuthorizationRequest(t, iamv1.AuthorizationRequest{
		Action: iamv1.ActionPaaSDeploymentCreate,
		Resource: iamv1.ResourceReference{
			Kind: iamv1.ResourceDeployment, ID: "collection",
		},
		RequestID: "request-authorize", CorrelationID: "correlation-authorize",
	}, iamv1.AuthorizationResourceCollection, iamv1.AuthorizationCollectionCreate)
	decision, err := Decide(context, iamv1.ServiceAudit, request, "decision-wrong-service", now)
	if err != nil || decision.Allowed {
		t.Fatalf("cross-service decision = %#v err=%v", decision, err)
	}
	if _, err := Decide(context, "UNKNOWN", request, "decision-unknown-service", now); !errors.Is(err, ErrAuthorityUnavailable) {
		t.Fatalf("unknown calling service error = %v", err)
	}
}

func TestAuthorizationFailsClosedOnInconsistentOrInactiveAuthority(t *testing.T) {
	now := authorityTestTime()
	request := boundAuthorizationRequest(t, iamv1.AuthorizationRequest{
		Action:    iamv1.ActionPaaSApplicationRead,
		Resource:  iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "application-example"},
		RequestID: "request-authorize", CorrelationID: "correlation-authorize",
	}, iamv1.AuthorizationResourceInstance, "")
	context := authoritySubject(now, iamv1.SystemPolicyPaaSViewer)
	context.Session.AccountID = "organization-other"
	if _, err := Decide(context, iamv1.ServicePaaS, request, "decision-mismatch", now); !errors.Is(err, ErrAuthorityUnavailable) {
		t.Fatalf("inconsistent authority error = %v", err)
	}
	context = authoritySubject(now, iamv1.SystemPolicyPaaSViewer)
	context.Organization.Status = iamv1.AccountDisabled
	if _, err := Decide(context, iamv1.ServicePaaS, request, "decision-disabled", now); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("disabled organization error = %v", err)
	}
	context = authoritySubject(now, iamv1.SystemPolicyPaaSViewer, iamv1.SystemPolicyPaaSViewer)
	if _, err := Decide(context, iamv1.ServicePaaS, request, "decision-duplicate-policy", now); !errors.Is(err, ErrAuthorityUnavailable) {
		t.Fatalf("duplicate binding state error = %v", err)
	}
}

func authoritySubject(now time.Time, policyIDs ...iamv1.PolicyID) SubjectContext {
	createdAt := now.Add(-time.Hour)
	return SubjectContext{
		Organization: iamv1.Organization{
			APIVersion: iamv1.APIVersion, Kind: "Organization", ID: "organization-example",
			DisplayName: "Example Organization", Status: iamv1.AccountActive,
			ResourceVersion: 1, CreatedAt: createdAt, UpdatedAt: createdAt,
		},
		Principal: iamv1.Principal{
			APIVersion: iamv1.APIVersion, Kind: "Principal", ID: "principal-developer",
			AccountID: "organization-example", Type: iamv1.PrincipalUser,
			LoginName: "developer", DisplayName: "Example Developer", Status: iamv1.PrincipalActive,
			ResourceVersion: 1, CreatedAt: createdAt, UpdatedAt: createdAt,
		},
		Session: iamv1.Session{
			APIVersion: iamv1.APIVersion, Kind: "Session", ID: "session-example",
			AccountID: "organization-example", PrincipalID: "principal-developer",
			Status: iamv1.SessionActive, IssuedAt: createdAt, ExpiresAt: now.Add(time.Hour),
		},
		Policies:       authorityPolicies(now, "organization-example", iamv1.Subject{Type: iamv1.PrincipalUser, ID: "principal-developer"}, "installation-example", policyIDs...),
		Boundary:       &ResolvedUserBoundary{State: "NONE", AccountID: "organization-example", UserID: "principal-developer", UserResourceVersion: 1},
		InstallationID: "installation-example",
	}
}

var testSystemPolicyIDs = []iamv1.PolicyID{
	iamv1.SystemPolicyAccountAdministrator,
	iamv1.SystemPolicyPlatformOperator,
	iamv1.SystemPolicyPaaSDeveloper,
	iamv1.SystemPolicyPaaSViewer,
	iamv1.SystemPolicyAuditReader,
	iamv1.SystemPolicyInstallationVerifier,
}

func authorityServicePolicies(now time.Time, identity iamv1.ServiceIdentity, policyIDs ...iamv1.PolicyID) []AttachedPolicy {
	return authorityPolicies(now, identity.AccountID, iamv1.Subject{Type: iamv1.PrincipalServiceAccount, ID: identity.PrincipalID}, identity.InstallationID, policyIDs...)
}

func authorityPolicies(now time.Time, account iamv1.AccountID, subject iamv1.Subject, installation string, policyIDs ...iamv1.PolicyID) []AttachedPolicy {
	result := make([]AttachedPolicy, 0, len(policyIDs))
	for _, policyID := range policyIDs {
		version, err := SystemPolicyVersion(policyID)
		if err != nil {
			panic("invalid system policy fixture")
		}
		created := now.Add(-time.Hour)
		policy := iamv1.Policy{APIVersion: iamv1.APIVersion, Kind: "Policy", ID: version.PolicyID,
			Management: iamv1.PolicySystemManaged, DisplayName: string(policyID), Scope: version.Document.Scope,
			Status: iamv1.PolicyActive, DefaultVersionID: version.ID, ResourceVersion: 1, CreatedAt: created, UpdatedAt: created}
		attachment := iamv1.PolicyAttachment{APIVersion: iamv1.APIVersion, Kind: "PolicyAttachment",
			ID: iamv1.PolicyAttachmentID("attachment-" + string(version.PolicyID)), AccountID: account,
			Target:   iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyAttachmentTargetKind(subject.Type), ID: string(subject.ID)},
			PolicyID: version.PolicyID, Scope: version.Document.Scope, ResourceVersion: 1, CreatedAt: created, UpdatedAt: created}
		if attachment.Scope != iamv1.AuthorityScopeTenant {
			attachment.InstallationID = installation
		}
		result = append(result, AttachedPolicy{Policy: policy, Version: version, Attachment: attachment, Profiles: iamv1.AllAuthorizationProfiles()})
	}
	return result
}

func authorityTestTime() time.Time {
	return time.Date(2026, 8, 25, 4, 5, 6, 0, time.UTC)
}

func policyContextForTest(now time.Time) policyEvaluationContext {
	result := policyEvaluationContext{databaseTime: now, accountID: "organization-example", subject: iamv1.Subject{Type: iamv1.PrincipalUser, ID: "principal-developer"}, profiles: make(map[iamv1.AuthorizationProfileReference]iamv1.AuthorizationProfile)}
	if result.includeProfiles(iamv1.AllAuthorizationProfiles()) != nil {
		panic("invalid source profiles")
	}
	return result
}

func boundAuthorizationRequest(t testing.TB, request iamv1.AuthorizationRequest, mode iamv1.AuthorizationResourceMode, usage iamv1.AuthorizationCollectionUsage) iamv1.AuthorizationRequest {
	t.Helper()
	result, err := iamv1.NewAuthorizationRequest(request.Action, request.Resource, mode, usage, request.RequestID, request.CorrelationID)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

// Catalog-wide authority tests need a declared target for each action. Tests
// that distinguish modes supply the shape explicitly instead of this fixture.
func declaredAuthorizationRequest(t testing.TB, request iamv1.AuthorizationRequest) iamv1.AuthorizationRequest {
	t.Helper()
	definition, known := iamv1.LookupActionDefinition(request.Action)
	if !known {
		t.Fatal("unknown fixture action")
	}
	profile, known := iamv1.LookupAuthorizationProfile(definition.Product)
	if !known {
		t.Fatal("unknown fixture product")
	}
	for _, action := range profile.Actions {
		if action.Action != request.Action {
			continue
		}
		shape := action.ResourceShapes[0]
		if shape.Mode == iamv1.AuthorizationResourceCollection {
			request.Resource.ID = "collection"
		}
		return boundAuthorizationRequest(t, request, shape.Mode, shape.CollectionUsage)
	}
	t.Fatal("missing declared fixture shape")
	return iamv1.AuthorizationRequest{}
}

func policyEvaluationRequestForTest(t testing.TB, action iamv1.Action, resource iamv1.ResourceReference) iamv1.AuthorizationRequest {
	t.Helper()
	request := iamv1.AuthorizationRequest{Action: action, Resource: iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "fixture"}, RequestID: "policy-test", CorrelationID: "policy-test"}
	definition, found := iamv1.LookupActionDefinition(action)
	if !found {
		request.Action = iamv1.ActionPaaSApplicationRead
		request = declaredAuthorizationRequest(t, request)
		request.Action = action
		request.Resource = resource
		return request
	}
	request.Resource.Kind = definition.ResourceKind
	request = declaredAuthorizationRequest(t, request)
	request.Resource.Kind = resource.Kind
	if request.ResourceMode == iamv1.AuthorizationResourceInstance {
		request.Resource.ID = resource.ID
	}
	return request
}

func compilePolicyVersionForTest(t *testing.T, version *iamv1.PolicyVersion) {
	t.Helper()
	profiles := iamv1.AllAuthorizationProfiles()
	compilation, err := iamv1.CompilePolicyDocument(version.Document, profiles)
	if err != nil {
		t.Fatal(err)
	}
	_, digest, err := iamv1.CanonicalizePolicyCompilation(version.Document, compilation, profiles)
	if err != nil {
		t.Fatal(err)
	}
	version.ContractVersion, version.Compilation, version.ContentDigest = iamv1.PolicyVersionCompiledContract, &compilation, digest
}

func TestCurrentEvaluationUsesFrozenInterpretationBeforeNonmatchingDeny(t *testing.T) {
	request := policyEvaluationRequestForTest(t, iamv1.ActionPaaSApplicationRead, iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "selected-app"})
	allow := policyVersionForTest(t, "policy-allow", iamv1.PolicyAllow, request.Action, iamv1.PolicyResourceAnyInAuthority, "")
	for _, test := range []struct {
		name    string
		change  func(*iamv1.AuthorizationProfile, *iamv1.PolicyDocument)
		invalid bool
	}{
		{"same meaning in another revision", func(_ *iamv1.AuthorizationProfile, _ *iamv1.PolicyDocument) {}, false},
		{"different producer", func(p *iamv1.AuthorizationProfile, _ *iamv1.PolicyDocument) { p.CallingService = "OTHER_PRODUCER" }, true},
		{"different resource kind", func(p *iamv1.AuthorizationProfile, d *iamv1.PolicyDocument) {
			p.Actions[0].ResourceKind = "OTHER_RESOURCE"
			d.Statements[0].Resources[0].Kind = "OTHER_RESOURCE"
		}, true},
		{"different result kind", func(p *iamv1.AuthorizationProfile, _ *iamv1.PolicyDocument) {
			p.Actions[0].ResultResourceKind = "OTHER_RESULT"
		}, true},
		{"collection cannot become instance", func(p *iamv1.AuthorizationProfile, _ *iamv1.PolicyDocument) {
			p.Actions[0].ResourceShapes = []iamv1.AuthorizationResourceShape{{Mode: iamv1.AuthorizationResourceCollection, CollectionUsage: iamv1.AuthorizationCollectionList}}
		}, true},
		{"unused prefix capability removed", func(p *iamv1.AuthorizationProfile, _ *iamv1.PolicyDocument) {
			p.Actions[0].ResourceShapes[0].PrefixAllowed = false
		}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			profile, _ := iamv1.LookupAuthorizationProfile(iamv1.ProductPaaS)
			for _, action := range profile.Actions {
				if action.Action == request.Action {
					profile.Actions = []iamv1.AuthorizationProfileAction{action}
					break
				}
			}
			profile.Revision = 2
			document := iamv1.PolicyDocument{LanguageVersion: iamv1.PolicyLanguageVersion, Scope: iamv1.AuthorityScopeTenant,
				Statements: []iamv1.PolicyStatement{{SID: "unmatched-deny", Effect: iamv1.PolicyDeny, Actions: []iamv1.Action{request.Action},
					Resources: []iamv1.PolicyResourceSelector{{Kind: request.Resource.Kind, Match: iamv1.PolicyResourceExact, ID: "not-selected"}}}}}
			test.change(&profile, &document)
			compilation, err := iamv1.CompilePolicyDocument(document, []iamv1.AuthorizationProfile{profile})
			if err != nil {
				t.Fatal("fixture must be valid in its original declaration", err)
			}
			_, digest, err := iamv1.CanonicalizePolicyCompilation(document, compilation, []iamv1.AuthorizationProfile{profile})
			if err != nil {
				t.Fatal(err)
			}
			deny := iamv1.PolicyVersion{PolicyID: "policy-old-deny", ID: "version-frozen", Document: document, ContentDigest: digest,
				ContractVersion: iamv1.PolicyVersionCompiledContract, Compilation: &compilation}
			context := policyContextForTest(authorityTestTime())
			if context.includeProfiles([]iamv1.AuthorizationProfile{profile}) != nil {
				t.Fatal("invalid frozen profile")
			}
			for _, versions := range [][]iamv1.PolicyVersion{{allow, deny}, {deny, allow}} {
				result, err := evaluatePolicies(context, versions, request)
				if test.invalid {
					if !errors.Is(err, ErrInvalidPolicyState) || result.Allowed || len(result.MatchedVersions) != 0 {
						t.Fatal("changed interpretation was ignored behind a nonmatching Deny")
					}
				} else if err != nil || !result.Allowed || result.ExplicitDeny {
					t.Fatal("unchanged interpretation rejected", err)
				}
			}
			delete(context.profiles, compilation.Profiles[0])
			if result, err := evaluatePolicies(context, []iamv1.PolicyVersion{allow, deny}, request); !errors.Is(err, ErrInvalidPolicyState) || result.Allowed {
				t.Fatal("missing frozen archive fell back to the current head")
			}
		})
	}
}

func TestLegacySystemInterpretationDoesNotAdmitUnprovedCustomerVersions(t *testing.T) {
	current, err := SystemPolicyVersion(iamv1.SystemPolicyAccountAdministrator)
	if err != nil {
		t.Fatal(err)
	}
	// The supported predecessor's exact content is interpreted against its
	// archived IAM revision, not reconstructed from newly added Role actions.
	legacyDocument := current.Document
	legacyDocument.Statements = slices.Clone(current.Document.Statements)
	oldIAM := iamv1.HistoricalAuthorizationProfiles()[0]
	oldActions := make(map[iamv1.Action]bool, len(oldIAM.Actions))
	for _, action := range oldIAM.Actions {
		oldActions[action.Action] = true
	}
	for index := range legacyDocument.Statements {
		legacyDocument.Statements[index].Actions = slices.DeleteFunc(slices.Clone(legacyDocument.Statements[index].Actions), func(action iamv1.Action) bool {
			return strings.HasPrefix(string(action), "iam.") && !oldActions[action]
		})
		legacyDocument.Statements[index].Resources = slices.DeleteFunc(slices.Clone(legacyDocument.Statements[index].Resources), func(resource iamv1.PolicyResourceSelector) bool { return resource.Kind == iamv1.ResourceRole })
	}
	_, digest, err := iamv1.CanonicalizePolicyDocument(legacyDocument)
	if err != nil {
		t.Fatal(err)
	}
	legacy := iamv1.PolicyVersion{PolicyID: current.PolicyID, ID: iamv1.PolicyVersionID("version-" + strings.TrimPrefix(digest, "sha256:")),
		Document: legacyDocument, ContentDigest: digest, ContractVersion: iamv1.PolicyVersionLegacyContract}
	if _, known := LegacySystemPolicyReferences(legacy); !known {
		t.Fatal("fixed legacy seed changed without an interpretation decision")
	}
	context := policyContextForTest(authorityTestTime())
	if context.includeProfiles([]iamv1.AuthorizationProfile{oldIAM}) != nil {
		t.Fatal("invalid fixed legacy profile")
	}
	request := policyEvaluationRequestForTest(t, iamv1.ActionIAMPolicyCreate, iamv1.ResourceReference{Kind: iamv1.ResourceAccount, ID: string(context.accountID)})
	if result, err := evaluatePolicies(context, []iamv1.PolicyVersion{legacy}, request); err != nil || !result.Allowed {
		t.Fatal("exact legacy SYSTEM ceiling unavailable", err)
	}
	roleRequest := policyEvaluationRequestForTest(t, iamv1.ActionIAMRoleCreate, iamv1.ResourceReference{Kind: iamv1.ResourceAccount, ID: string(context.accountID)})
	if result, err := evaluatePolicies(context, []iamv1.PolicyVersion{legacy}, roleRequest); err != nil || result.Allowed {
		t.Fatal("new product registration expanded the exact old SYSTEM policy", err)
	}
	if result, err := evaluatePolicies(context, []iamv1.PolicyVersion{current}, roleRequest); err != nil || !result.Allowed {
		t.Fatal("new source policy does not explicitly contain Role management", err)
	}
	for _, id := range []iamv1.PolicyID{"customer-unproved", "system.unproved"} {
		unknown := legacy
		unknown.PolicyID = id
		if result, err := evaluatePolicies(context, []iamv1.PolicyVersion{current, unknown}, request); !errors.Is(err, ErrInvalidPolicyState) || result.Allowed {
			t.Fatal("a real legacy-shaped row or another Allow fabricated provenance")
		}
	}
	context.profiles = nil
	if result, err := evaluatePolicies(context, []iamv1.PolicyVersion{legacy}, request); !errors.Is(err, ErrInvalidPolicyState) || result.Allowed {
		t.Fatal("legacy interpretation fell back to current capabilities")
	}
	if legacy.Compilation != nil || legacy.ContentDigest != digest {
		t.Fatal("legacy interpretation rewrote original content")
	}
}
