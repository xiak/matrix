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
	request := iamv1.AuthorizationRequest{
		Action:    iamv1.ActionPaaSDeploymentCreate,
		Resource:  iamv1.ResourceReference{Kind: iamv1.ResourceDeployment, ID: "deployment-example"},
		RequestID: "request-authorize", CorrelationID: "correlation-authorize",
	}
	allowed, err := Decide(context, iamv1.ServicePaaS, request, "decision-allowed", now)
	if err != nil || !allowed.Allowed || allowed.TenantID != context.Organization.ID ||
		allowed.Subject == nil || allowed.Subject.ID != context.Principal.ID {
		t.Fatalf("developer decision = %#v err=%v", allowed, err)
	}

	request.Action = iamv1.ActionIAMPrincipalCreate
	request.Resource.Kind = iamv1.ResourceOrganization
	denied, err := Decide(context, iamv1.ServicePaaS, request, "decision-denied", now)
	if err != nil || denied.Allowed || denied.TenantID != "" || denied.Subject != nil {
		t.Fatalf("denied decision = %#v err=%v", denied, err)
	}
	encoded, err := json.Marshal(denied)
	if err != nil {
		t.Fatalf("encode denied decision: %v", err)
	}
	if bytes.Contains(encoded, []byte("organization-example")) || bytes.Contains(encoded, []byte("principal-developer")) {
		t.Fatalf("denied decision leaked authority context: %s", encoded)
	}

	context.Policies = nil
	request.Action = iamv1.ActionPaaSDeploymentCreate
	request.Resource.Kind = iamv1.ResourceDeployment
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
		OrganizationID: "organization-example",
		PrincipalID:    "service-installation-verifier",
		Purpose:        iamv1.ServiceInstallationVerifier,
	}
	request := iamv1.AuthorizationRequest{
		Action: iamv1.ActionInstallationVerify,
		Resource: iamv1.ResourceReference{
			Kind: iamv1.ResourceInstallation, ID: "installation-example",
		},
		RequestID: "request-installation-verify", CorrelationID: "correlation-installation-verify",
	}
	allowed, err := DecideService(
		identity,
		authorityServicePolicies(now, identity, iamv1.SystemPolicyInstallationVerifier),
		request,
		"decision-installation-verify",
		now,
	)
	if err != nil || !allowed.Allowed || allowed.TenantID != identity.OrganizationID ||
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
	request := iamv1.AuthorizationRequest{Action: action,
		Resource:  iamv1.ResourceReference{Kind: definition.ResourceKind, ID: "resource-example"},
		RequestID: "request-policy", CorrelationID: "correlation-policy"}
	now := authorityTestTime()
	var decision AuthorizationEvaluation
	var err error
	if policyID == iamv1.SystemPolicyInstallationVerifier {
		identity := iamv1.ServiceIdentity{APIVersion: iamv1.APIVersion, Kind: "ServiceIdentity",
			InstallationID: "installation-example", OrganizationID: "organization-example",
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

func TestCatalogConfinementIsEnforcedByActualDecisions(t *testing.T) {
	now := authorityTestTime()
	for _, definition := range iamv1.AllActionDefinitions() {
		t.Run(string(definition.Action), func(t *testing.T) {
			request := iamv1.AuthorizationRequest{Action: definition.Action,
				Resource:  iamv1.ResourceReference{Kind: definition.ResourceKind, ID: "resource-example"},
				RequestID: "request-catalog", CorrelationID: "correlation-catalog"}
			for _, service := range iamv1.AllServicePurposes() {
				var decision AuthorizationEvaluation
				var err error
				if definition.AuthorityScope == iamv1.AuthorityScopeInstallationProbe {
					identity := iamv1.ServiceIdentity{APIVersion: iamv1.APIVersion, Kind: "ServiceIdentity",
						InstallationID: "installation-example", OrganizationID: "organization-example",
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
	_, digest, err := iamv1.CanonicalizePolicyDocument(document)
	if err != nil {
		t.Fatal(err)
	}
	return iamv1.PolicyVersion{PolicyID: id, ID: "version-one", Document: document, ContentDigest: digest}
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
			result, err := EvaluatePolicies(test.policies, iamv1.ActionPaaSApplicationRead, iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: test.resourceID})
			if err != nil || result.Allowed != test.allowed || result.ExplicitDeny != test.explicitDeny || len(result.MatchedVersions) != test.matched {
				t.Fatalf("evaluation=%+v err=%v", result, err)
			}
		})
	}
	if result, err := EvaluatePolicies([]iamv1.PolicyVersion{allow}, iamv1.ActionPaaSApplicationCreate, iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "application-open"}); err != nil || result.Allowed {
		t.Fatal("read permission allowed a write")
	}
}

func TestAttachedPolicyEvaluationRequiresCurrentOwnedRelationships(t *testing.T) {
	now := authorityTestTime()
	version := policyVersionForTest(t, "policy-reader", iamv1.PolicyAllow, iamv1.ActionPaaSApplicationRead, iamv1.PolicyResourceAnyInAuthority, "")
	row := AttachedPolicy{
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
	result, evidence, err := EvaluateAttachedPolicies("account-a", "installation-a", subject, []AttachedPolicy{row}, iamv1.ActionPaaSApplicationRead, resource)
	if err != nil || !result.Allowed || len(evidence) != 1 || evidence[0].AttachmentID != row.Attachment.ID ||
		evidence[0].ResourceVersion != 7 || evidence[0].Version.ContentDigest != version.ContentDigest {
		t.Fatal("valid attachment lost its authority evidence")
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
			result, evidence, err := EvaluateAttachedPolicies("account-a", "installation-a", subject, []AttachedPolicy{row, changed}, iamv1.ActionPaaSApplicationRead, resource)
			if !errors.Is(err, ErrInvalidPolicyState) || result.Allowed || len(evidence) != 0 {
				t.Fatal("invalid current relationship produced a partial decision")
			}
		})
	}
	if result, evidence, err := EvaluateAttachedPolicies("account-a", "installation-a", subject, nil, iamv1.ActionPaaSApplicationRead, resource); err != nil || result.Allowed || len(evidence) != 0 {
		t.Fatal("empty policy authority granted permission")
	}
	if result, _, err := EvaluateAttachedPolicies("account-a", "installation-a", subject, []AttachedPolicy{row, row}, iamv1.ActionPaaSApplicationRead, resource); !errors.Is(err, ErrInvalidPolicyState) || result.Allowed {
		t.Fatal("duplicate attachment identity accepted")
	}
	if result, evidence, err := EvaluateAttachedPolicies("account-a", "installation-a", subject, make([]AttachedPolicy, MaxEvaluationPolicies+1), iamv1.ActionPaaSApplicationRead, resource); !errors.Is(err, ErrInvalidPolicyState) || result.Allowed || len(evidence) != 0 {
		t.Fatal("attachment work budget was not enforced")
	}
	deny := row
	deny.Version = policyVersionForTest(t, "policy-deny", iamv1.PolicyDeny, iamv1.ActionPaaSApplicationRead, iamv1.PolicyResourceAnyInAuthority, "")
	deny.Policy.ID, deny.Policy.DefaultVersionID = deny.Version.PolicyID, deny.Version.ID
	deny.Attachment.ID, deny.Attachment.PolicyID = "attachment-b", deny.Version.PolicyID
	result, evidence, err = EvaluateAttachedPolicies("account-a", "installation-a", subject, []AttachedPolicy{deny, row}, iamv1.ActionPaaSApplicationRead, resource)
	if err != nil || result.Allowed || !result.ExplicitDeny || len(evidence) != 2 || evidence[0].AttachmentID != row.Attachment.ID || evidence[1].Version.PolicyID != deny.Policy.ID {
		t.Fatal("deny or the exact attachment/content evidence was lost")
	}
	_, reversed, err := EvaluateAttachedPolicies("account-a", "installation-a", subject, []AttachedPolicy{row, deny}, iamv1.ActionPaaSApplicationRead, resource)
	if err != nil || !slices.Equal(evidence, reversed) {
		t.Fatal("source order changed immutable policy evidence")
	}
	changedDefault := row
	changedDefault.Version = policyVersionForTest(t, row.Policy.ID, iamv1.PolicyDeny, iamv1.ActionPaaSApplicationRead, iamv1.PolicyResourceAnyInAuthority, "")
	changedDefault.Version.ID = "version-new-default"
	changedDefault.Policy.DefaultVersionID = changedDefault.Version.ID
	changedDefault.Policy.ResourceVersion++
	result, evidence, err = EvaluateAttachedPolicies("account-a", "installation-a", subject, []AttachedPolicy{changedDefault}, iamv1.ActionPaaSApplicationRead, resource)
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
		result, _, err := EvaluateAttachedPolicies("account-a", installation, subject, []AttachedPolicy{row}, iamv1.ActionPaaSExecutionTargetRead, platformResource)
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
			before, digest, err := iamv1.CanonicalizePolicyDocument(original.Document)
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
			after, afterDigest, err := iamv1.CanonicalizePolicyDocument(fresh.Document)
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
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(iterations *testing.PB) {
				for iterations.Next() {
					result, err := EvaluatePolicies(policies, iamv1.ActionPaaSApplicationRead, resource)
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
	left, err := EvaluatePolicies([]iamv1.PolicyVersion{last, first}, iamv1.ActionPaaSApplicationRead, resource)
	if err != nil {
		t.Fatal(err)
	}
	right, err := EvaluatePolicies([]iamv1.PolicyVersion{first, last}, iamv1.ActionPaaSApplicationRead, resource)
	if err != nil || !slices.Equal(left.MatchedVersions, right.MatchedVersions) || left.Allowed || right.Allowed || !right.ExplicitDeny {
		t.Fatal("source order changed authority evidence")
	}
	large := first
	large.Document.Statements = make([]iamv1.PolicyStatement, iamv1.MaxPolicyStatements)
	for i := range large.Document.Statements {
		large.Document.Statements[i] = first.Document.Statements[0]
		large.Document.Statements[i].SID = fmt.Sprintf("statement-%d", i)
	}
	_, large.ContentDigest, err = iamv1.CanonicalizePolicyDocument(large.Document)
	if err != nil {
		t.Fatal(err)
	}
	versions := make([]iamv1.PolicyVersion, MaxEvaluationStatements/iamv1.MaxPolicyStatements)
	for i := range versions {
		versions[i] = large
		versions[i].PolicyID = iamv1.PolicyID(fmt.Sprintf("policy-%d", i))
	}
	if result, err := EvaluatePolicies(versions, iamv1.ActionPaaSApplicationRead, resource); err != nil || !result.Allowed {
		t.Fatalf("valid bounded snapshot rejected: %v", err)
	}
	versions = append(versions, last)
	if result, err := EvaluatePolicies(versions, iamv1.ActionPaaSApplicationRead, resource); !errors.Is(err, ErrInvalidPolicyState) || result.Allowed || len(result.MatchedVersions) != 0 {
		t.Fatal("aggregate statement limit returned partial authority")
	}
}

func TestPolicyEvaluationSeparatesScopesAndFailsClosedOnCorruptSnapshots(t *testing.T) {
	tenant := policyVersionForTest(t, "policy-tenant", iamv1.PolicyAllow, iamv1.ActionPaaSApplicationRead, iamv1.PolicyResourceAnyInAuthority, "")
	platform := policyVersionForTest(t, "policy-platform", iamv1.PolicyAllow, iamv1.ActionPaaSExecutionTargetRead, iamv1.PolicyResourceAnyInAuthority, "")
	probe := policyVersionForTest(t, "policy-probe", iamv1.PolicyAllow, iamv1.ActionInstallationVerify, iamv1.PolicyResourceAnyInAuthority, "")
	request := iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "application-one"}
	if result, err := EvaluatePolicies([]iamv1.PolicyVersion{platform, probe}, iamv1.ActionPaaSApplicationRead, request); err != nil || result.Allowed {
		t.Fatal("platform/probe policy granted tenant resource access")
	}
	if result, err := EvaluatePolicies([]iamv1.PolicyVersion{tenant, platform, probe}, iamv1.ActionPaaSApplicationRead, request); err != nil || !result.Allowed || len(result.MatchedVersions) != 1 || result.MatchedVersions[0].PolicyID != tenant.PolicyID {
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
			result, err := EvaluatePolicies(policies, iamv1.ActionPaaSApplicationRead, request)
			if !errors.Is(err, ErrInvalidPolicyState) || result.Allowed || result.ExplicitDeny || len(result.MatchedVersions) != 0 {
				t.Fatalf("invalid authority returned a partial result: %+v %v", result, err)
			}
		})
	}
	for _, resource := range []iamv1.ResourceReference{{Kind: iamv1.ResourcePrincipal, ID: "application-one"}, {Kind: iamv1.ResourceApplication, ID: "*"}} {
		if result, err := EvaluatePolicies([]iamv1.PolicyVersion{tenant}, iamv1.ActionPaaSApplicationRead, resource); !errors.Is(err, ErrInvalidAuthorizationRequest) || result.Allowed {
			t.Fatal("malformed request acquired authority")
		}
	}
	if result, err := EvaluatePolicies([]iamv1.PolicyVersion{tenant}, "paas.unregistered.read", request); !errors.Is(err, ErrInvalidAuthorizationRequest) || result.Allowed {
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
			request := iamv1.AuthorizationRequest{Action: action,
				Resource:  iamv1.ResourceReference{Kind: kind, ID: "resource-example"},
				RequestID: "request-platform", CorrelationID: "request-platform"}
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

func TestTenantAccountCommandsRemainOrganizationAdminOnly(t *testing.T) {
	for _, action := range []iamv1.Action{iamv1.ActionIAMAccountAliasSet, iamv1.ActionIAMPrincipalList, iamv1.ActionIAMPrincipalSetStatus, iamv1.ActionIAMPasswordReset} {
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
	request := iamv1.AuthorizationRequest{
		Action: iamv1.ActionPaaSDeploymentCreate,
		Resource: iamv1.ResourceReference{
			Kind: iamv1.ResourceDeployment, ID: "deployment-example",
		},
		RequestID: "request-authorize", CorrelationID: "correlation-authorize",
	}
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
	request := iamv1.AuthorizationRequest{
		Action:    iamv1.ActionPaaSApplicationRead,
		Resource:  iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "application-example"},
		RequestID: "request-authorize", CorrelationID: "correlation-authorize",
	}
	context := authoritySubject(now, iamv1.SystemPolicyPaaSViewer)
	context.Session.OrganizationID = "organization-other"
	if _, err := Decide(context, iamv1.ServicePaaS, request, "decision-mismatch", now); !errors.Is(err, ErrAuthorityUnavailable) {
		t.Fatalf("inconsistent authority error = %v", err)
	}
	context = authoritySubject(now, iamv1.SystemPolicyPaaSViewer)
	context.Organization.Status = iamv1.OrganizationDisabled
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
			DisplayName: "Example Organization", Status: iamv1.OrganizationActive,
			ResourceVersion: 1, CreatedAt: createdAt, UpdatedAt: createdAt,
		},
		Principal: iamv1.Principal{
			APIVersion: iamv1.APIVersion, Kind: "Principal", ID: "principal-developer",
			OrganizationID: "organization-example", Type: iamv1.PrincipalUser,
			LoginName: "developer", DisplayName: "Example Developer", Status: iamv1.PrincipalActive,
			ResourceVersion: 1, CreatedAt: createdAt, UpdatedAt: createdAt,
		},
		Session: iamv1.Session{
			APIVersion: iamv1.APIVersion, Kind: "Session", ID: "session-example",
			OrganizationID: "organization-example", PrincipalID: "principal-developer",
			Status: iamv1.SessionActive, IssuedAt: createdAt, ExpiresAt: now.Add(time.Hour),
		},
		Policies:       authorityPolicies(now, "organization-example", iamv1.Subject{Type: iamv1.PrincipalUser, ID: "principal-developer"}, "installation-example", policyIDs...),
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
	return authorityPolicies(now, identity.OrganizationID, iamv1.Subject{Type: iamv1.PrincipalServiceAccount, ID: identity.PrincipalID}, identity.InstallationID, policyIDs...)
}

func authorityPolicies(now time.Time, account iamv1.OrganizationID, subject iamv1.Subject, installation string, policyIDs ...iamv1.PolicyID) []AttachedPolicy {
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
		result = append(result, AttachedPolicy{Policy: policy, Version: version, Attachment: attachment})
	}
	return result
}

func authorityTestTime() time.Time {
	return time.Date(2026, 8, 25, 4, 5, 6, 0, time.UTC)
}
