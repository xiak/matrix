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

func TestRoleTrustChecksTheSelectedCarrierWithoutGrantingBusinessAuthority(t *testing.T) {
	now := authorityTestTime()
	fixture := func() (SubjectContext, iamv1.Role, iamv1.RoleTrustVersion) {
		source := authoritySubject(now) // Deliberately no identity-policy Allow.
		role := iamv1.Role{APIVersion: iamv1.APIVersion, Kind: "Role", ID: "role-reader", AccountID: source.Organization.ID,
			Name: "reader", Tags: []iamv1.RoleTag{}, Management: iamv1.RoleCustomerManaged, Status: iamv1.RoleActive,
			MaxSessionDurationSeconds: 3600, ResourceVersion: 1, CurrentTrustVersionID: "trust-a",
			CreatedAt: now.Add(-time.Minute), UpdatedAt: now.Add(-time.Minute)}
		document := iamv1.TrustPolicyDocument{LanguageVersion: "1", Statements: []iamv1.TrustPolicyStatement{
			{SID: "allow-user", Effect: iamv1.PolicyAllow, Principals: []iamv1.TrustPrincipal{{Type: iamv1.PrincipalUser, ID: source.Principal.ID}}},
		}}
		_, digest, err := iamv1.CanonicalizeTrustPolicyDocument(document)
		if err != nil {
			t.Fatal(err)
		}
		version := iamv1.RoleTrustVersion{APIVersion: iamv1.APIVersion, Kind: "RoleTrustVersion", ID: role.CurrentTrustVersionID,
			AccountID: role.AccountID, RoleID: role.ID, Document: document, ContentDigest: digest, CreatedAt: role.CreatedAt}
		return source, role, version
	}
	source, role, version := fixture()
	if allowed, err := RoleTrustAllowsUser(source, role, version, now); err != nil || !allowed {
		t.Fatalf("valid selected carrier rejected: %v", err)
	}
	request := policyEvaluationRequestForTest(t, iamv1.ActionPaaSApplicationRead, iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "application-one"})
	if decision, err := Decide(source, iamv1.ServicePaaS, request, "decision-no-inherited-role", now); err != nil || decision.Allowed {
		t.Fatal("trust matching changed the source user's business authority")
	}
	for _, effect := range []iamv1.PolicyEffect{iamv1.PolicyAllow, iamv1.PolicyDeny} {
		source, role, version = fixture()
		version.Document.Statements = append(version.Document.Statements, iamv1.TrustPolicyStatement{SID: "second", Effect: effect,
			Principals: []iamv1.TrustPrincipal{{Type: iamv1.PrincipalUser, ID: source.Principal.ID}}})
		for _, reverse := range []bool{false, true} {
			if reverse {
				slices.Reverse(version.Document.Statements)
			}
			_, version.ContentDigest, _ = iamv1.CanonicalizeTrustPolicyDocument(version.Document)
			allowed, err := RoleTrustAllowsUser(source, role, version, now)
			if err != nil || allowed != (effect == iamv1.PolicyAllow) {
				t.Fatal("carrier evaluation depended on statement order or missed Deny")
			}
		}
	}
	for name, change := range map[string]func(*SubjectContext, *iamv1.Role, *iamv1.RoleTrustVersion){
		"empty trust": func(_ *SubjectContext, _ *iamv1.Role, v *iamv1.RoleTrustVersion) {
			v.Document.Statements = []iamv1.TrustPolicyStatement{}
		},
		"other user": func(_ *SubjectContext, _ *iamv1.Role, v *iamv1.RoleTrustVersion) {
			v.Document.Statements[0].Principals[0].ID = "other-user"
		},
		"disabled role": func(_ *SubjectContext, r *iamv1.Role, _ *iamv1.RoleTrustVersion) { r.Status = iamv1.RoleDisabled },
		"forced user": func(s *SubjectContext, _ *iamv1.Role, _ *iamv1.RoleTrustVersion) {
			s.Principal.MustChangePassword = true
		},
		"service with same ID": func(s *SubjectContext, _ *iamv1.Role, _ *iamv1.RoleTrustVersion) {
			s.Principal.Type, s.Principal.LoginName = iamv1.PrincipalServiceAccount, ""
		},
	} {
		t.Run(name, func(t *testing.T) {
			s, r, v := fixture()
			change(&s, &r, &v)
			_, v.ContentDigest, _ = iamv1.CanonicalizeTrustPolicyDocument(v.Document)
			if allowed, err := RoleTrustAllowsUser(s, r, v, now); err != nil || allowed {
				t.Fatalf("untrusted carrier: allowed=%v err=%v", allowed, err)
			}
		})
	}
	for name, change := range map[string]func(*SubjectContext, *iamv1.Role, *iamv1.RoleTrustVersion){
		"account suspended": func(s *SubjectContext, _ *iamv1.Role, _ *iamv1.RoleTrustVersion) {
			s.Organization.Status = iamv1.AccountDisabled
		},
		"user disabled": func(s *SubjectContext, _ *iamv1.Role, _ *iamv1.RoleTrustVersion) {
			s.Principal.Status = iamv1.PrincipalDisabled
		},
		"source expires now": func(s *SubjectContext, _ *iamv1.Role, _ *iamv1.RoleTrustVersion) { s.Session.ExpiresAt = now },
		"source revoked": func(s *SubjectContext, _ *iamv1.Role, _ *iamv1.RoleTrustVersion) {
			revoked := now.Add(-time.Second)
			s.Session.Status, s.Session.RevokedAt = iamv1.SessionRevoked, &revoked
		},
		"role account":       func(_ *SubjectContext, r *iamv1.Role, _ *iamv1.RoleTrustVersion) { r.AccountID = "other-account" },
		"trust account":      func(_ *SubjectContext, _ *iamv1.Role, v *iamv1.RoleTrustVersion) { v.AccountID = "other-account" },
		"trust role":         func(_ *SubjectContext, _ *iamv1.Role, v *iamv1.RoleTrustVersion) { v.RoleID = "other-role" },
		"unselected version": func(_ *SubjectContext, _ *iamv1.Role, v *iamv1.RoleTrustVersion) { v.ID = "trust-old" },
		"trust digest": func(_ *SubjectContext, _ *iamv1.Role, v *iamv1.RoleTrustVersion) {
			v.ContentDigest = "sha256:" + strings.Repeat("0", 64)
		},
		"missing trust": func(_ *SubjectContext, _ *iamv1.Role, v *iamv1.RoleTrustVersion) { v.Document.Statements = nil },
		"trust chronology": func(_ *SubjectContext, r *iamv1.Role, v *iamv1.RoleTrustVersion) {
			v.CreatedAt = r.UpdatedAt.Add(time.Microsecond)
		},
		"unsupported after allow": func(_ *SubjectContext, _ *iamv1.Role, v *iamv1.RoleTrustVersion) {
			v.Document.Statements = append(v.Document.Statements, iamv1.TrustPolicyStatement{SID: "invalid", Effect: iamv1.PolicyAllow,
				Principals: []iamv1.TrustPrincipal{{Type: iamv1.PrincipalServiceAccount, ID: "service-account"}}})
		},
	} {
		t.Run(name, func(t *testing.T) {
			s, r, v := fixture()
			change(&s, &r, &v)
			if allowed, err := RoleTrustAllowsUser(s, r, v, now); err == nil || allowed {
				t.Fatal("corrupt or inactive carrier state did not fail closed")
			}
		})
	}
}

func TestRoleSessionDeadlineCannotExtendAnyIssuanceLimit(t *testing.T) {
	now := authorityTestTime()
	for _, sample := range []struct {
		requested, maximum uint32
		remaining, want    time.Duration
	}{
		{3600, 43200, 12 * time.Hour, time.Hour},
		{43200, 60, time.Hour, time.Minute},
		{60, 43200, time.Microsecond, time.Microsecond},
		{43200, 43200, 12 * time.Hour, 12 * time.Hour},
		{3600, 3600, time.Hour, time.Hour},
	} {
		deadline, err := RoleSessionDeadline(now, sample.requested, sample.maximum, now.Add(sample.remaining))
		if err != nil || !deadline.Equal(now.Add(sample.want)) {
			t.Fatalf("deadline differs from the shortest exact bound: %v", err)
		}
	}
	for _, duration := range []uint32{0, 1, 59, 43201, ^uint32(0)} {
		if _, err := RoleSessionDeadline(now, duration, 3600, now.Add(time.Hour)); !errors.Is(err, ErrInvalidRoleSessionRequest) {
			t.Fatal("invalid requested duration accepted")
		}
		if _, err := RoleSessionDeadline(now, 60, duration, now.Add(time.Hour)); !errors.Is(err, ErrAuthorityUnavailable) {
			t.Fatal("corrupt role duration accepted")
		}
	}
	for _, expiry := range []time.Time{time.Time{}, now, now.Add(-time.Microsecond), now.Add(time.Hour + time.Nanosecond), now.Add(time.Hour).In(time.FixedZone("other", 3600))} {
		if _, err := RoleSessionDeadline(now, 3600, 3600, expiry); err == nil {
			t.Fatal("invalid or expired source bound accepted")
		}
	}
	if _, err := RoleSessionDeadline(now.Add(time.Nanosecond), 3600, 3600, now.Add(time.Hour)); !errors.Is(err, ErrAuthorityUnavailable) {
		t.Fatal("non-authoritative clock accepted")
	}
}

func roleSessionContextForTest(now time.Time) RoleSessionContext {
	source := authoritySubject(now, iamv1.SystemPolicyAccountAdministrator)
	role := iamv1.Role{APIVersion: iamv1.APIVersion, Kind: "Role", ID: "role-reader", AccountID: source.Organization.ID,
		Name: "reader", Tags: []iamv1.RoleTag{}, Management: iamv1.RoleCustomerManaged, Status: iamv1.RoleActive,
		MaxSessionDurationSeconds: 3600, ResourceVersion: 1, CurrentTrustVersionID: "trust-reader", CreatedAt: now.Add(-time.Minute), UpdatedAt: now.Add(-time.Minute)}
	trust := iamv1.RoleTrustVersion{APIVersion: iamv1.APIVersion, Kind: "RoleTrustVersion", ID: role.CurrentTrustVersionID, AccountID: role.AccountID,
		RoleID: role.ID, CreatedAt: role.CreatedAt, Document: iamv1.TrustPolicyDocument{LanguageVersion: "1", Statements: []iamv1.TrustPolicyStatement{{SID: "user", Effect: iamv1.PolicyAllow,
			Principals: []iamv1.TrustPrincipal{{Type: iamv1.PrincipalUser, ID: source.Principal.ID}}}}}}
	_, trust.ContentDigest, _ = iamv1.CanonicalizeTrustPolicyDocument(trust.Document)
	limit := authorityPolicies(now, role.AccountID, iamv1.Subject{Type: iamv1.SubjectRole, ID: string(role.ID)}, "", iamv1.SystemPolicyPaaSViewer)[0]
	return RoleSessionContext{Source: source, SourceSessionID: source.Session.ID, Role: role, Trust: trust,
		AuthorityContractVersion: 2, SourceAuthorizationGeneration: 1, SourceGroupGenerations: []RoleSourceGroupGeneration{},
		CredentialGeneration: 1, SecurityGeneration: 1, AssumeDecisionID: "assume-original",
		Session: iamv1.RoleSession{APIVersion: iamv1.APIVersion, Kind: "RoleSession", ID: "role-session-one", AccountID: role.AccountID,
			RoleID: role.ID, SourceUserID: source.Principal.ID, Status: iamv1.SessionActive, IssuedAt: now, ExpiresAt: now.Add(30 * time.Minute)},
		Boundary: &ResolvedRoleBoundary{BoundaryID: "role-ceiling", ResourceVersion: 1, Policy: limit.Policy, Version: limit.Version, Profiles: limit.Profiles}}
}

func TestRoleSessionAuthenticationRechecksTheCurrentSource(t *testing.T) {
	now := authorityTestTime()
	fixture := func() RoleSessionContext { return roleSessionContextForTest(now) }
	issued, err := NewCredentialIssuer(nil).Issue(CredentialRoleSession, "role-session-one")
	if err != nil {
		t.Fatal(err)
	}
	if err := AuthenticateRoleSession(fixture(), issued.VerificationDigest, issued.Credential, now); err != nil {
		t.Fatal("current role rejected", err)
	}
	for name, change := range map[string]func(*RoleSessionContext){
		"missing authority contract": func(v *RoleSessionContext) { v.AuthorityContractVersion = 0 },
		"legacy authority contract":  func(v *RoleSessionContext) { v.AuthorityContractVersion = 1 },
		"future authority contract":  func(v *RoleSessionContext) { v.AuthorityContractVersion = 3 },
		"missing source generation":  func(v *RoleSessionContext) { v.SourceAuthorizationGeneration = 0 },
		"missing complete groups":    func(v *RoleSessionContext) { v.SourceGroupGenerations = nil },
		"missing boundary":           func(v *RoleSessionContext) { v.Boundary = nil },
		"wrong account":              func(v *RoleSessionContext) { v.Session.AccountID = "another-account" },
		"wrong role":                 func(v *RoleSessionContext) { v.Session.RoleID = "another-role" },
		"wrong source user":          func(v *RoleSessionContext) { v.Session.SourceUserID = "another-user" },
		"wrong source session":       func(v *RoleSessionContext) { v.SourceSessionID = "another-session" },
		"future issue":               func(v *RoleSessionContext) { v.Session.IssuedAt = now.Add(time.Second) },
		"expired":                    func(v *RoleSessionContext) { v.Session.IssuedAt = now.Add(-time.Minute); v.Session.ExpiresAt = now },
		"exceeds source":             func(v *RoleSessionContext) { v.Session.ExpiresAt = v.Source.Session.ExpiresAt.Add(time.Second) },
		"revoked":                    func(v *RoleSessionContext) { v.Session.Status = iamv1.SessionRevoked; v.Session.RevokedAt = &now },
		"account disabled":           func(v *RoleSessionContext) { v.Source.Organization.Status = iamv1.AccountDisabled },
		"source disabled":            func(v *RoleSessionContext) { v.Source.Principal.Status = iamv1.PrincipalDisabled },
		"source forced change":       func(v *RoleSessionContext) { v.Source.Principal.MustChangePassword = true },
		"source session revoked": func(v *RoleSessionContext) {
			v.Source.Session.Status = iamv1.SessionRevoked
			v.Source.Session.RevokedAt = &now
		},
		"source no assume":         func(v *RoleSessionContext) { v.Source.Policies = nil },
		"role disabled":            func(v *RoleSessionContext) { v.Role.Status = iamv1.RoleDisabled },
		"different selected trust": func(v *RoleSessionContext) { v.Role.CurrentTrustVersionID = "different-trust" },
	} {
		t.Run(name, func(t *testing.T) {
			value := fixture()
			change(&value)
			if AuthenticateRoleSession(value, issued.VerificationDigest, issued.Credential, now) == nil {
				t.Fatal("inactive or inconsistent role authenticated")
			}
		})
	}
	for _, purpose := range []CredentialType{CredentialSession, CredentialService} {
		digest, err := DigestCredential(purpose, "role-session-one", issued.Credential)
		if err != nil || AuthenticateRoleSession(fixture(), digest, issued.Credential, now) == nil {
			t.Fatal("role accepted another credential purpose")
		}
	}
	value := fixture()
	version := policyVersionForTest(t, iamv1.SystemPolicyAccountAdministrator, iamv1.PolicyAllow, iamv1.ActionIAMRoleAssume, iamv1.PolicyResourceExact, string(value.Role.ID))
	version.Document.Statements[0].Conditions = []iamv1.PolicyCondition{{Key: iamv1.ConditionIAMCurrentTime, Operator: iamv1.PolicyDateLessThan, Values: []string{now.Add(time.Second).Format(time.RFC3339Nano)}}}
	compilePolicyVersionForTest(t, &version)
	value.Source.Policies[0].Version = version
	value.Source.Policies[0].Policy.DefaultVersionID = version.ID
	if err := AuthenticateRoleSession(value, issued.VerificationDigest, issued.Credential, now); err != nil {
		t.Fatal("current conditional assume rejected", err)
	}
	if err := AuthenticateRoleSession(value, issued.VerificationDigest, issued.Credential, now.Add(time.Second)); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("unchanged revision cached an expired source Allow", err)
	}
}

func TestRoleSourceAuthorityRequiresCompleteBoundedEvidence(t *testing.T) {
	groups := make([]RoleSourceGroupGeneration, 100)
	for i := range groups {
		groups[i] = RoleSourceGroupGeneration{GroupID: iamv1.GroupID(fmt.Sprintf("group-%03d", i)),
			MembershipID: iamv1.GroupMembershipID(fmt.Sprintf("membership-%03d", i)), MembershipResourceVersion: 1, AuthorizationGeneration: 9007199254740991}
	}
	if ValidateRoleSourceAuthority(2, 9007199254740991, groups) != nil || ValidateRoleSourceAuthority(2, 1, []RoleSourceGroupGeneration{}) != nil {
		t.Fatal("complete source authority at either budget boundary was rejected")
	}
	for name, mutate := range map[string]func(*RoleSessionContext){
		"oversized generation":        func(v *RoleSessionContext) { v.SourceAuthorizationGeneration = 9007199254740992 },
		"oversized groups":            func(v *RoleSessionContext) { v.SourceGroupGenerations = append(v.SourceGroupGenerations, groups[0]) },
		"missing group":               func(v *RoleSessionContext) { v.SourceGroupGenerations[0].GroupID = "" },
		"missing membership":          func(v *RoleSessionContext) { v.SourceGroupGenerations[0].MembershipID = "" },
		"removed membership revision": func(v *RoleSessionContext) { v.SourceGroupGenerations[0].MembershipResourceVersion = 2 },
		"missing membership revision": func(v *RoleSessionContext) { v.SourceGroupGenerations[0].MembershipResourceVersion = 0 },
		"missing group generation":    func(v *RoleSessionContext) { v.SourceGroupGenerations[0].AuthorizationGeneration = 0 },
		"oversized group generation":  func(v *RoleSessionContext) { v.SourceGroupGenerations[0].AuthorizationGeneration = 9007199254740992 },
		"duplicate group":             func(v *RoleSessionContext) { v.SourceGroupGenerations[1].GroupID = v.SourceGroupGenerations[0].GroupID },
		"unordered groups": func(v *RoleSessionContext) {
			v.SourceGroupGenerations[0], v.SourceGroupGenerations[1] = v.SourceGroupGenerations[1], v.SourceGroupGenerations[0]
		},
	} {
		t.Run(name, func(t *testing.T) {
			value := roleSessionContextForTest(authorityTestTime())
			value.SourceGroupGenerations = slices.Clone(groups)
			mutate(&value)
			if !errors.Is(ValidateRoleSourceAuthority(value.AuthorityContractVersion, value.SourceAuthorizationGeneration, value.SourceGroupGenerations), ErrAuthorityUnavailable) {
				t.Fatal("incomplete source authority remained current")
			}
		})
	}
}

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

func TestRoleDecisionIntersectsThreeSourcesWithoutUserPermissionInheritance(t *testing.T) {
	now := authorityTestTime()
	request := policyEvaluationRequestForTest(t, iamv1.ActionPaaSApplicationRead, iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "application-prod"})
	grant := func(value *RoleSessionContext, version iamv1.PolicyVersion) {
		row := authorityPolicies(now, value.Session.AccountID, iamv1.Subject{Type: iamv1.SubjectRole, ID: string(value.Role.ID)}, "", iamv1.SystemPolicyPaaSViewer)[0]
		row.Policy.ID, row.Policy.DefaultVersionID = version.PolicyID, version.ID
		row.Policy.Management, row.Policy.AccountID = iamv1.PolicyCustomerManaged, value.Session.AccountID
		row.Attachment.ID, row.Attachment.PolicyID = iamv1.PolicyAttachmentID("attachment-"+string(version.PolicyID)), version.PolicyID
		row.Version = version
		value.Policies = append(value.Policies, row)
	}
	restriction := func(value *RoleSessionContext, effect iamv1.PolicyEffect, resource string) {
		version := policyVersionForTest(t, "test-document-only", effect, request.Action, iamv1.PolicyResourceExact, resource)
		value.SessionPolicy = &ResolvedSessionPolicy{Document: version.Document, Compilation: *version.Compilation,
			ContentDigest: version.ContentDigest, Profiles: iamv1.AllAuthorizationProfiles()}
	}
	for _, test := range []struct {
		name        string
		change      func(*RoleSessionContext)
		want        bool
		unavailable bool
	}{
		{"role and boundary", func(*RoleSessionContext) {}, true, false},
		{"source administrator is not a role grant", func(v *RoleSessionContext) { v.Policies = nil }, false, false},
		{"source only has assume", func(v *RoleSessionContext) {
			version := policyVersionForTest(t, iamv1.SystemPolicyAccountAdministrator, iamv1.PolicyAllow, iamv1.ActionIAMRoleAssume, iamv1.PolicyResourceExact, string(v.Role.ID))
			v.Source.Policies[0].Version = version
			v.Source.Policies[0].Policy.DefaultVersionID = version.ID
		}, true, false},
		{"mandatory boundary missing", func(v *RoleSessionContext) { v.Boundary = nil }, false, true},
		{"boundary misses resource", func(v *RoleSessionContext) {
			version := policyVersionForTest(t, v.Boundary.Policy.ID, iamv1.PolicyAllow, request.Action, iamv1.PolicyResourceExact, "other-resource")
			v.Boundary.Version = version
			v.Boundary.Policy.DefaultVersionID = version.ID
		}, false, false},
		{"boundary deny", func(v *RoleSessionContext) {
			version := policyVersionForTest(t, v.Boundary.Policy.ID, iamv1.PolicyDeny, request.Action, iamv1.PolicyResourceAnyInAuthority, "")
			v.Boundary.Version = version
			v.Boundary.Policy.DefaultVersionID = version.ID
		}, false, false},
		{"session intersection", func(v *RoleSessionContext) { restriction(v, iamv1.PolicyAllow, request.Resource.ID) }, true, false},
		{"session misses resource", func(v *RoleSessionContext) { restriction(v, iamv1.PolicyAllow, "other-resource") }, false, false},
		{"session deny", func(v *RoleSessionContext) { restriction(v, iamv1.PolicyDeny, request.Resource.ID) }, false, false},
		{"role deny wins over both ceilings", func(v *RoleSessionContext) {
			grant(v, policyVersionForTest(t, "role-explicit-deny", iamv1.PolicyDeny, request.Action, iamv1.PolicyResourceExact, request.Resource.ID))
			restriction(v, iamv1.PolicyAllow, request.Resource.ID)
		}, false, false},
		{"corrupt restriction cannot disappear", func(v *RoleSessionContext) {
			restriction(v, iamv1.PolicyAllow, request.Resource.ID)
			v.SessionPolicy.ContentDigest = "sha256:" + strings.Repeat("0", 64)
		}, false, true},
		{"corrupt private generation", func(v *RoleSessionContext) { v.CredentialGeneration = 0 }, false, true},
		{"missing issuance decision", func(v *RoleSessionContext) { v.AssumeDecisionID = "" }, false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			value := roleSessionContextForTest(now)
			grant(&value, policyVersionForTest(t, "role-read", iamv1.PolicyAllow, request.Action, iamv1.PolicyResourceAnyInAuthority, ""))
			test.change(&value)
			result, err := DecideRole(value, iamv1.ServicePaaS, request, "role-business-decision", now)
			if result.Allowed != test.want || (errors.Is(err, ErrAuthorityUnavailable) != test.unavailable) || (!test.unavailable && err != nil) {
				t.Fatalf("allowed=%v error=%v", result.Allowed, err)
			}
			if err != nil {
				return
			}
			if result.RoleEvidence == nil || result.RoleEvidence.AssumeDecisionID != value.AssumeDecisionID || result.RoleEvidence.SourceSessionID != value.Source.Session.ID ||
				result.BoundaryEvidence.State != "NOT_APPLICABLE" || result.RoleEvidence.Boundary.Version.VersionID != value.Boundary.Version.ID ||
				result.RoleEvidence.AuthorityContractVersion != 2 || result.RoleEvidence.SourceAuthorizationGeneration != value.SourceAuthorizationGeneration ||
				result.RoleEvidence.SourceGroupGenerations == nil || !slices.Equal(result.RoleEvidence.SourceGroupGenerations, value.SourceGroupGenerations) {
				t.Fatal("role provenance was dropped or confused with USER boundary")
			}
			for _, evidence := range result.PolicyEvidence {
				if evidence.Version.PolicyID == iamv1.SystemPolicyAccountAdministrator || evidence.Version.PolicyID == iamv1.SystemPolicyPaaSViewer || evidence.MembershipID != "" {
					t.Fatal("a source USER or ceiling became a positive role attachment")
				}
			}
			if test.want && (result.Subject == nil || result.Subject.Type != iamv1.SubjectRole || result.Subject.ID != string(value.Role.ID) ||
				result.Subject.RoleSession == nil || result.Subject.RoleSession.SessionID != value.Session.ID || result.Subject.RoleSession.SourceUserID != value.Source.Principal.ID) {
				t.Fatal("public subject is not the exact ROLE lineage")
			}
			encoded, err := json.Marshal(result)
			if err != nil || bytes.Contains(encoded, []byte("sourceSessionId")) || bytes.Contains(encoded, []byte("credentialGeneration")) || bytes.Contains(encoded, []byte("boundaryId")) || bytes.Contains(encoded, []byte("assumeDecisionId")) ||
				bytes.Contains(encoded, []byte("sourceAuthorizationGeneration")) || bytes.Contains(encoded, []byte("sourceGroupGenerations")) || bytes.Contains(encoded, []byte("authorityContractVersion")) {
				t.Fatal("private proof leaked into decision")
			}
			if !test.want && (result.Subject != nil || result.TenantID != "" || result.InstallationID != "") {
				t.Fatal("Deny leaked authority")
			}
		})
	}
}

func TestRoleDecisionUsesRoleIdentityAndRejectsUndeclaredProducts(t *testing.T) {
	now := authorityTestTime()
	value := roleSessionContextForTest(now)
	value.Policies = authorityPolicies(now, value.Session.AccountID, iamv1.Subject{Type: iamv1.SubjectRole, ID: string(value.Role.ID)}, "", iamv1.SystemPolicyPaaSViewer)
	request := policyEvaluationRequestForTest(t, iamv1.ActionPaaSApplicationRead, iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "application-prod"})
	for _, expected := range []string{string(value.Role.ID), string(value.Source.Principal.ID), "another-role"} {
		version := policyVersionForTest(t, value.Policies[0].Policy.ID, iamv1.PolicyAllow, request.Action, iamv1.PolicyResourceAnyInAuthority, "")
		version.Document.Statements[0].Conditions = []iamv1.PolicyCondition{
			{Key: iamv1.ConditionIAMPrincipalID, Operator: iamv1.PolicyStringEquals, Values: []string{expected}},
			{Key: iamv1.ConditionIAMAccountID, Operator: iamv1.PolicyStringEquals, Values: []string{string(value.Session.AccountID)}},
			{Key: iamv1.ConditionIAMCurrentTime, Operator: iamv1.PolicyDateLessThan, Values: []string{now.Add(time.Second).Format(time.RFC3339)}},
		}
		compilePolicyVersionForTest(t, &version)
		value.Policies[0].Version, value.Policies[0].Policy.DefaultVersionID = version, version.ID
		for _, offset := range []time.Duration{0, time.Second} {
			result, err := DecideRole(value, iamv1.ServicePaaS, request, "role-conditions", now.Add(offset))
			if err != nil || result.Allowed != (expected == string(value.Role.ID) && offset == 0) {
				t.Fatal("role conditions used source USER identity or stale time", err)
			}
		}
	}
	for _, action := range []iamv1.Action{iamv1.ActionIAMRoleRead, iamv1.ActionPaaSExecutionTargetRead, iamv1.ActionInstallationVerify, iamv1.ActionManagedServiceOfferingRead} {
		definition, _ := iamv1.LookupActionDefinition(action)
		request := policyEvaluationRequestForTest(t, action, iamv1.ResourceReference{Kind: definition.ResourceKind, ID: "target-one"})
		result, err := DecideRole(value, definition.CallingService, request, "role-unsupported", now)
		if err != nil || result.Allowed || result.RoleEvidence == nil {
			t.Fatal("ROLE gained an undeclared management/platform/probe/product capability", action, err)
		}
	}
	if result, err := DecideRole(value, iamv1.ServiceAudit, request, "role-wrong-producer", now); err != nil || result.Allowed {
		t.Fatal("wrong producer authorized a role", err)
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
		allowed.Subject == nil || allowed.Subject.ID != string(context.Principal.ID) {
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
		allowed.Subject == nil || allowed.Subject.Type != iamv1.SubjectServiceAccount ||
		allowed.Subject.ID != string(identity.PrincipalID) {
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

func TestEveryIAMActionHasUniqueServiceAuthority(t *testing.T) {
	services := iamv1.AllServicePurposes()
	for _, action := range iamv1.AllActions() {
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

func TestAccessKeyActionsRequireExplicitCurrentPolicy(t *testing.T) {
	now := authorityTestTime()
	for _, action := range []iamv1.Action{iamv1.ActionIAMAccessKeyList, iamv1.ActionIAMAccessKeyCreate,
		iamv1.ActionIAMAccessKeyRead, iamv1.ActionIAMAccessKeySetStatus, iamv1.ActionIAMAccessKeyDelete} {
		t.Run(string(action), func(t *testing.T) {
			for _, policyID := range testSystemPolicyIDs {
				if attachedSystemPolicyAllows(t, policyID, action) {
					t.Fatalf("existing system policy %s implicitly acquired %s", policyID, action)
				}
			}
			definition, _ := iamv1.LookupActionDefinition(action)
			request := declaredAuthorizationRequest(t, iamv1.AuthorizationRequest{Action: action,
				Resource:  iamv1.ResourceReference{Kind: definition.ResourceKind, ID: "key-target"},
				RequestID: "explicit-key-policy", CorrelationID: "explicit-key-policy"})
			subject := authoritySubject(now)
			for _, granted := range []bool{false, true} {
				if granted {
					subject.Policies = authorityPoliciesForAction(t, now, action)
				}
				decision, err := Decide(subject, iamv1.ServiceIAM, request, "explicit-key-decision", now)
				if err != nil || decision.Allowed != granted || (granted && len(decision.PolicyEvidence) != 1) {
					t.Fatalf("explicit grant=%t allowed=%t err=%v", granted, decision.Allowed, err)
				}
			}
		})
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
							subject.Policies = authorityPoliciesForAction(t, now, action.Action)
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
					context := authoritySubject(now)
					context.Policies = authorityPoliciesForAction(t, now, definition.Action)
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
					if decision.InstallationID != "installation-example" || decision.TenantID != "" || decision.Subject.Type != iamv1.SubjectUser {
						t.Fatal("platform action lost its installation/user authority")
					}
				} else if decision.TenantID != "organization-example" || decision.InstallationID != "" {
					t.Fatal("tenant/probe decision changed its bound home tenant")
				}
				if definition.AuthorityScope == iamv1.AuthorityScopeInstallationProbe && decision.Subject.Type != iamv1.SubjectServiceAccount {
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

func TestAccessKeyContextHasNoLoginSessionAndRejectsInconsistentAuthority(t *testing.T) {
	now := authorityTestTime()
	fixture := func() AccessKeyContext {
		user := authoritySubject(now, iamv1.SystemPolicyPaaSViewer)
		return AccessKeyContext{Organization: user.Organization, Principal: user.Principal,
			RootUserID: "principal-root", InstallationID: user.InstallationID, Policies: user.Policies, Boundary: user.Boundary,
			Key: iamv1.AccessKey{APIVersion: iamv1.APIVersion, Kind: "AccessKey", ID: "access-key-context", AccountID: user.Organization.ID,
				UserID: user.Principal.ID, Status: iamv1.AccessKeyEnabled, ResourceVersion: 1, CreatedAt: now.Add(-time.Minute), UpdatedAt: now.Add(-time.Minute)}}
	}
	request := policyEvaluationRequestForTest(t, iamv1.ActionPaaSApplicationRead, iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "application-key"})
	if eligible, err := accessKeyEligibility(fixture(), now, now.Unix()); err != nil || !eligible {
		t.Fatal("coherent ordinary key metadata is not eligible for later MAC/PDP checks", err)
	}
	// Platform protection is independent of the effective policy directory.
	// A RETIRED policy disappears from that projection, not attachment history.
	protected := fixture()
	protected.HasUnrevokedPlatformAttachment = true
	if eligible, err := accessKeyEligibility(protected, now, now.Unix()); err != nil || eligible {
		t.Fatal("filtered platform policy erased the unrevoked-attachment protection", err)
	}
	// The current release still declares LOGIN_SESSION only. Even a coherent
	// key context with a matching USER grant must not widen that declaration.
	for name, change := range map[string]func(*AccessKeyContext){
		"current user":   func(*AccessKeyContext) {},
		"paused account": func(v *AccessKeyContext) { v.Organization.Status = iamv1.AccountDisabled },
		"disabled user":  func(v *AccessKeyContext) { v.Principal.Status = iamv1.PrincipalDisabled },
		"forced change":  func(v *AccessKeyContext) { v.Principal.MustChangePassword = true },
		"root identity":  func(v *AccessKeyContext) { v.RootUserID = v.Principal.ID },
		"no user grant":  func(v *AccessKeyContext) { v.Policies = nil },
		"disabled key":   func(v *AccessKeyContext) { v.Key.Status, v.Key.ResourceVersion = iamv1.AccessKeyDisabled, 2 },
		"bounded identity": func(v *AccessKeyContext) {
			v.Boundary = userBoundaryForTest(authoritySubject(now), policyVersionForTest(t, "key-ceiling", iamv1.PolicyAllow, request.Action, iamv1.PolicyResourceAnyInAuthority, ""))
		},
		"platform identity": func(v *AccessKeyContext) {
			v.HasUnrevokedPlatformAttachment = true
			v.Policies = authoritySubject(now, iamv1.SystemPolicyPaaSViewer, iamv1.SystemPolicyPlatformOperator).Policies
		},
		"retired platform policy": func(v *AccessKeyContext) { v.HasUnrevokedPlatformAttachment = true },
	} {
		t.Run(name, func(t *testing.T) {
			value := fixture()
			change(&value)
			for _, signedAt := range []int64{now.Unix(), now.Unix() - 301, now.Unix() + 31} {
				result, err := DecideAccessKey(value, iamv1.ServicePaaS, request, "decision-key-context", now, signedAt)
				if err != nil || result.Allowed || result.ID != "decision-key-context" || result.Subject != nil || result.TenantID != "" || result.InstallationID != "" ||
					result.PolicyEvidence == nil || iamv1.CheckAuthorizationDecisionForRequest(result.AuthorizationDecision, request) != nil {
					t.Fatal("known restricted carrier did not remain a bound, sanitized Deny", err)
				}
			}
		})
	}
	for name, change := range map[string]func(*AccessKeyContext){
		"missing owner":     func(v *AccessKeyContext) { v.RootUserID = "" },
		"missing install":   func(v *AccessKeyContext) { v.InstallationID = "" },
		"wrong user tenant": func(v *AccessKeyContext) { v.Principal.AccountID = "other-account" },
		"wrong key tenant":  func(v *AccessKeyContext) { v.Key.AccountID = "other-account" },
		"wrong key user":    func(v *AccessKeyContext) { v.Key.UserID = "other-user" },
		"service identity":  func(v *AccessKeyContext) { v.Principal.Type, v.Principal.LoginName = iamv1.PrincipalServiceAccount, "" },
		"missing key":       func(v *AccessKeyContext) { v.Key = iamv1.AccessKey{} },
		"invalid key state": func(v *AccessKeyContext) { v.Key.Status = "DELETED" },
		"invalid key CAS":   func(v *AccessKeyContext) { v.Key.ResourceVersion = 0 },
		"future key":        func(v *AccessKeyContext) { v.Key.ResourceVersion, v.Key.UpdatedAt = 2, now.Add(time.Second) },
		"key before user": func(v *AccessKeyContext) {
			v.Key.CreatedAt, v.Key.UpdatedAt = v.Principal.CreatedAt.Add(-time.Second), v.Principal.CreatedAt.Add(-time.Second)
		},
		"user before tenant": func(v *AccessKeyContext) { v.Principal.CreatedAt = v.Organization.CreatedAt.Add(-time.Second) },
		"missing boundary":   func(v *AccessKeyContext) { v.Boundary = nil },
		"wrong ceiling user": func(v *AccessKeyContext) { v.Boundary.UserID = "other-user" },
		"old ceiling CAS":    func(v *AccessKeyContext) { v.Boundary.UserResourceVersion++ },
		"contradictory protection snapshot": func(v *AccessKeyContext) {
			v.Policies = authoritySubject(now, iamv1.SystemPolicyPaaSViewer, iamv1.SystemPolicyPlatformOperator).Policies
		},
		"hidden platform attachment": func(v *AccessKeyContext) {
			v.HasUnrevokedPlatformAttachment = true
			v.Policies = authoritySubject(now, iamv1.SystemPolicyPaaSViewer, iamv1.SystemPolicyPlatformOperator).Policies
			v.Policies[1].Attachment.AccountID = "other-account"
		},
	} {
		t.Run(name, func(t *testing.T) {
			value := fixture()
			change(&value)
			result, err := DecideAccessKey(value, iamv1.ServicePaaS, request, "decision-key-corrupt", now, now.Unix())
			if !errors.Is(err, ErrAuthorityUnavailable) || result.ID != "" {
				t.Fatal("corrupt authority was disguised as a completed Deny", err)
			}
		})
	}
	for _, signedAt := range []int64{0, -1, 253402300800} {
		if result, err := DecideAccessKey(fixture(), iamv1.ServicePaaS, request, "decision-key-invalid", now, signedAt); !errors.Is(err, ErrInvalidAuthorizationRequest) || result.ID != "" {
			t.Fatal("malformed timestamp became a completed decision")
		}
	}
}

func TestPolicyEvaluationDoesNotInferProgramAccessFromUserSupport(t *testing.T) {
	now := authorityTestTime()
	request := policyEvaluationRequestForTest(t, iamv1.ActionPaaSApplicationRead, iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "application-program"})
	user := authoritySubject(now, iamv1.SystemPolicyPaaSViewer)
	subject := iamv1.Subject{Type: iamv1.SubjectUser, ID: string(user.Principal.ID)}
	if result, _, err := EvaluateAttachedPolicies(now, user.Organization.ID, user.InstallationID, subject, user.Policies, request); err != nil || !result.Allowed {
		t.Fatal("fixture does not prove a current login-user grant", err)
	}
	subject.AccessKeyID = "access-key-program"
	if result, _, err := EvaluateAttachedPolicies(now, user.Organization.ID, user.InstallationID, subject, user.Policies, request); !errors.Is(err, errUnsupportedPolicySubject) || result.Allowed {
		t.Fatal("USER capability implicitly enabled an undeclared AccessKey carrier", err)
	}
	for _, bounded := range []bool{false, true} {
		boundary := user.Boundary
		if bounded {
			boundary = userBoundaryForTest(user, policyVersionForTest(t, "key-boundary", iamv1.PolicyAllow, request.Action, iamv1.PolicyResourceAnyInAuthority, ""))
		}
		result, err := decide(user.Organization.ID, user.InstallationID, subject, false, user.Policies, boundary, iamv1.ServicePaaS, request, "decision-key-unsupported", now)
		if err != nil || result.Allowed || result.Subject != nil || result.TenantID != "" || result.InstallationID != "" || result.Reason != iamv1.DecisionDenied {
			t.Fatal("unsupported current carrier did not produce a sanitized Deny", err)
		}
		if bounded && (result.BoundaryEvidence.State != "BOUND" || result.BoundaryEvidence.Version == nil || *result.BoundaryEvidence.Version != (iamv1.PolicyVersionReference{PolicyID: boundary.Policy.ID, VersionID: boundary.Version.ID, ContentDigest: boundary.Version.ContentDigest})) {
			t.Fatal("carrier rejection discarded the current boundary provenance")
		}
	}
}

func TestPolicyEvaluationChecksSubjectCapabilityBeforeUnmatchedEffects(t *testing.T) {
	now := authorityTestTime()
	request := policyEvaluationRequestForTest(t, iamv1.ActionPaaSApplicationRead, iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "requested-application"})
	allow := policyVersionForTest(t, "policy-current-allow", iamv1.PolicyAllow, request.Action, iamv1.PolicyResourceAnyInAuthority, "")
	for _, effect := range []iamv1.PolicyEffect{iamv1.PolicyAllow, iamv1.PolicyDeny} {
		for _, types := range [][]iamv1.SubjectType{{iamv1.SubjectRole}, {iamv1.SubjectUser, iamv1.SubjectRole}} {
			profile, found := iamv1.LookupAuthorizationProfile(iamv1.ProductPaaS)
			if !found {
				t.Fatal("PaaS source declaration missing")
			}
			profile.Revision++
			for index := range profile.Actions {
				if profile.Actions[index].Action == request.Action {
					profile.Actions[index].SubjectTypes = types
				}
			}
			version := policyVersionForTest(t, "policy-frozen-subject", effect, request.Action, iamv1.PolicyResourceExact, "unmatched-application")
			compilation, err := iamv1.CompilePolicyDocument(version.Document, []iamv1.AuthorizationProfile{profile})
			if err != nil {
				t.Fatal(err)
			}
			_, version.ContentDigest, err = iamv1.CanonicalizePolicyCompilation(version.Document, compilation, []iamv1.AuthorizationProfile{profile})
			if err != nil {
				t.Fatal(err)
			}
			version.Compilation = &compilation
			context := policyContextForTest(now)
			if context.includeProfiles([]iamv1.AuthorizationProfile{profile}) != nil {
				t.Fatal("valid frozen declaration could not be loaded")
			}
			for _, versions := range [][]iamv1.PolicyVersion{{allow, version}, {version, allow}} {
				result, err := evaluatePolicies(context, versions, request)
				if len(types) == 1 {
					if !errors.Is(err, ErrInvalidPolicyState) || result.Allowed {
						t.Fatal("unmatched effect bypassed frozen subject incompatibility")
					}
				} else if err != nil || !result.Allowed {
					t.Fatal("USER-compatible expansion invalidated an otherwise current grant", err)
				}
			}
		}
	}
	context := policyContextForTest(now)
	context.subject.Type = iamv1.SubjectServiceAccount
	for _, versions := range [][]iamv1.PolicyVersion{nil, {allow}} {
		if result, err := evaluatePolicies(context, versions, request); !errors.Is(err, errUnsupportedPolicySubject) || result.Allowed {
			t.Fatal("business request bypassed current subject admission")
		}
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
				{databaseTime: context.databaseTime, accountID: context.accountID, subject: iamv1.Subject{Type: iamv1.SubjectUser}},
				{databaseTime: context.databaseTime, accountID: context.accountID, subject: iamv1.Subject{Type: iamv1.SubjectServiceAccount, ID: context.subject.ID}},
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
	subject := iamv1.Subject{Type: iamv1.SubjectUser, ID: "user-a"}
	resource := iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "application-a"}
	result, evidence, err := EvaluateAttachedPolicies(authorityTestTime(), "account-a", "installation-a", subject, []AttachedPolicy{row}, policyEvaluationRequestForTest(t, iamv1.ActionPaaSApplicationRead, resource))
	if err != nil || !result.Allowed || len(evidence) != 1 || evidence[0].AttachmentID != row.Attachment.ID ||
		evidence[0].ResourceVersion != 7 || evidence[0].MembershipID != "" || evidence[0].MembershipResourceVersion != 0 ||
		evidence[0].Version.ContentDigest != version.ContentDigest {
		t.Fatal("valid attachment lost its authority evidence")
	}
	membership := iamv1.GroupMembership{APIVersion: iamv1.APIVersion, Kind: "GroupMembership", ID: "membership-a",
		AccountID: "account-a", GroupID: "group-a", UserID: iamv1.PrincipalID(subject.ID), CreatedBy: "user-admin",
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
	serviceSubject := iamv1.Subject{Type: iamv1.SubjectServiceAccount, ID: subject.ID}
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
		Policies:       authorityPolicies(now, "organization-example", iamv1.Subject{Type: iamv1.SubjectUser, ID: "principal-developer"}, "installation-example", policyIDs...),
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
	return authorityPolicies(now, identity.AccountID, iamv1.Subject{Type: iamv1.SubjectServiceAccount, ID: string(identity.PrincipalID)}, identity.InstallationID, policyIDs...)
}

// Catalog/shape tests supply an explicit grant rather than treating a new
// registered action as an automatic expansion of existing system defaults.
func authorityPoliciesForAction(t *testing.T, now time.Time, action iamv1.Action) []AttachedPolicy {
	t.Helper()
	definition, known := iamv1.LookupActionDefinition(action)
	if !known {
		t.Fatal("unknown fixture action")
	}
	subject := authoritySubject(now, iamv1.SystemPolicyPlatformOperator)
	if definition.AuthorityScope != iamv1.AuthorityScopeTenant {
		return subject.Policies // Non-tenant policies remain system-owned.
	}
	version := policyVersionForTest(t, "explicit-action", iamv1.PolicyAllow, action, iamv1.PolicyResourceAnyInAuthority, "")
	return []AttachedPolicy{{
		Profiles: iamv1.AllAuthorizationProfiles(), Version: version,
		Policy: iamv1.Policy{APIVersion: iamv1.APIVersion, Kind: "Policy", ID: version.PolicyID,
			Management: iamv1.PolicyCustomerManaged, AccountID: subject.Organization.ID, DisplayName: "Explicit action",
			Scope: iamv1.AuthorityScopeTenant, Status: iamv1.PolicyActive, DefaultVersionID: version.ID,
			ResourceVersion: 1, CreatedAt: now, UpdatedAt: now},
		Attachment: iamv1.PolicyAttachment{APIVersion: iamv1.APIVersion, Kind: "PolicyAttachment", ID: "explicit-attachment",
			AccountID: subject.Organization.ID, Target: iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetUser, ID: string(subject.Principal.ID)},
			PolicyID: version.PolicyID, Scope: iamv1.AuthorityScopeTenant, ResourceVersion: 1, CreatedAt: now, UpdatedAt: now},
	}}
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
	result := policyEvaluationContext{databaseTime: now, accountID: "organization-example", subject: iamv1.Subject{Type: iamv1.SubjectUser, ID: "principal-developer"}, profiles: make(map[iamv1.AuthorizationProfileReference]iamv1.AuthorizationProfile)}
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
		legacyDocument.Statements[index].Resources = slices.DeleteFunc(slices.Clone(legacyDocument.Statements[index].Resources), func(resource iamv1.PolicyResourceSelector) bool {
			return resource.Kind == iamv1.ResourceRole || resource.Kind == iamv1.ResourceRoleSession
		})
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
	if context.includeProfiles(iamv1.HistoricalAuthorizationProfiles()) != nil {
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
