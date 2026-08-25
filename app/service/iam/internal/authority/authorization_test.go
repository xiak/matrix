package authority

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
	"time"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
)

func TestSessionAuthenticationUsesBindingDigestRevocationAndDatabaseTime(t *testing.T) {
	now := authorityTestTime()
	context := authoritySubject(now, iamv1.RolePaaSDeveloper)
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

func TestFixedRBACAllowsCurrentBindingAndDeniesWithoutAuthorityLeak(t *testing.T) {
	now := authorityTestTime()
	context := authoritySubject(now, iamv1.RolePaaSDeveloper)
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

	context.Roles = nil
	request.Action = iamv1.ActionPaaSDeploymentCreate
	request.Resource.Kind = iamv1.ResourceDeployment
	afterRevocation, err := Decide(context, iamv1.ServicePaaS, request, "decision-after-revocation", now)
	if err != nil || afterRevocation.Allowed {
		t.Fatalf("decision after binding revocation = %#v err=%v", afterRevocation, err)
	}

	context = authoritySubject(now, iamv1.RoleOrganizationAdmin)
	context.Principal.MustChangePassword = true
	mustChange, err := Decide(context, iamv1.ServicePaaS, request, "decision-must-change", now)
	if err != nil || mustChange.Allowed {
		t.Fatalf("initial administrator used PaaS before password change: decision=%#v err=%v", mustChange, err)
	}
}

func TestInstallationVerifierServiceCanAuthorizeOnlyItsFixedAction(t *testing.T) {
	now := authorityTestTime()
	identity := iamv1.ServiceIdentity{
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
		[]iamv1.BuiltinRole{iamv1.RoleInstallationVerifier},
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
		identity, nil, request, "decision-installation-without-role", now,
	)
	if err != nil || withoutRole.Allowed || withoutRole.Subject != nil || withoutRole.TenantID != "" {
		t.Fatalf("unbound installation verifier decision=%#v err=%v", withoutRole, err)
	}
	identity.Purpose = iamv1.ServicePaaS
	wrongPurpose, err := DecideService(
		identity,
		[]iamv1.BuiltinRole{iamv1.RoleInstallationVerifier},
		request,
		"decision-installation-wrong-purpose",
		now,
	)
	if err != nil || wrongPurpose.Allowed {
		t.Fatalf("wrong-purpose verifier decision=%#v err=%v", wrongPurpose, err)
	}
}

func TestEveryIAMActionHasOnlyFixedRoleAuthority(t *testing.T) {
	roles := iamv1.AllBuiltinRoles()
	services := iamv1.AllServicePurposes()
	for _, action := range iamv1.AllActions() {
		owners := 0
		for _, role := range roles {
			if RoleAllows(role, action) {
				owners++
			}
		}
		if owners == 0 {
			t.Fatalf("IAM action %q has no built-in role authority", action)
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
	if RoleAllows(iamv1.RoleInstallationVerifier, iamv1.ActionPaaSDeploymentRead) ||
		RoleAllows(iamv1.RoleAuditReader, iamv1.ActionPaaSApplicationRead) ||
		RoleAllows(iamv1.BuiltinRole("CUSTOM"), iamv1.ActionPaaSApplicationRead) {
		t.Fatal("fixed least-privilege roles accepted authority outside their catalog")
	}
	if ServiceCanRequest(iamv1.ServiceAPISIX, iamv1.ActionPaaSApplicationRead) {
		t.Fatal("APISIX was allowed to request product authorization")
	}
}

func TestAuthorizationDeniesAServiceOutsideItsProductBoundary(t *testing.T) {
	now := authorityTestTime()
	context := authoritySubject(now, iamv1.RolePaaSDeveloper)
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
	context := authoritySubject(now, iamv1.RolePaaSViewer)
	context.Session.OrganizationID = "organization-other"
	if _, err := Decide(context, iamv1.ServicePaaS, request, "decision-mismatch", now); !errors.Is(err, ErrAuthorityUnavailable) {
		t.Fatalf("inconsistent authority error = %v", err)
	}
	context = authoritySubject(now, iamv1.RolePaaSViewer)
	context.Organization.Status = iamv1.OrganizationDisabled
	if _, err := Decide(context, iamv1.ServicePaaS, request, "decision-disabled", now); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("disabled organization error = %v", err)
	}
	context = authoritySubject(now, iamv1.RolePaaSViewer, iamv1.RolePaaSViewer)
	if _, err := Decide(context, iamv1.ServicePaaS, request, "decision-duplicate-role", now); !errors.Is(err, ErrAuthorityUnavailable) {
		t.Fatalf("duplicate binding state error = %v", err)
	}
}

func authoritySubject(now time.Time, roles ...iamv1.BuiltinRole) SubjectContext {
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
		Roles: append([]iamv1.BuiltinRole(nil), roles...),
	}
}

func authorityTestTime() time.Time {
	return time.Date(2026, 8, 25, 4, 5, 6, 0, time.UTC)
}
