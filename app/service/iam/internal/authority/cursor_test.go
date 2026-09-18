package authority

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
)

func TestOwnLoginSessionCursorBindsTheCallerAndCredentialGeneration(t *testing.T) {
	now := authorityTestTime()
	codec, _ := NewCursorCodec(bytes.Repeat([]byte{0x63}, 32))
	replica, _ := NewCursorCodec(bytes.Repeat([]byte{0x63}, 32))
	subject := authoritySubject(now)
	subject.Principal.MustChangePassword = true
	query := DirectoryQuery{InstallationID: subject.InstallationID, LoginSessions: &LoginSessionDirectoryRevision{CredentialGeneration: 9}}
	cursor, err := codec.Encode(subject, query, "session-last", now)
	if err != nil {
		t.Fatal("restricted user without business grants cannot continue own sessions", err)
	}
	if position, err := replica.Decode(cursor, subject, query, now.Add(time.Minute)); err != nil || position != "session-last" {
		t.Fatal("own session page did not continue across instances", err)
	}
	for name, change := range map[string]func(*SubjectContext, *DirectoryQuery){
		"generation":    func(_ *SubjectContext, q *DirectoryQuery) { q.LoginSessions.CredentialGeneration++ },
		"no generation": func(_ *SubjectContext, q *DirectoryQuery) { q.LoginSessions.CredentialGeneration = 0 },
		"session":       func(s *SubjectContext, _ *DirectoryQuery) { s.Session.ID = "another-login" },
		"user":          func(s *SubjectContext, _ *DirectoryQuery) { s.Principal.ID = "another-user" },
		"account":       func(s *SubjectContext, _ *DirectoryQuery) { s.Organization.ID = "another-account" },
		"installation":  func(_ *SubjectContext, q *DirectoryQuery) { q.InstallationID = "another-installation" },
		"revoked": func(s *SubjectContext, _ *DirectoryQuery) {
			s.Session.Status = iamv1.SessionRevoked
			s.Session.RevokedAt = &now
		},
		"disabled":         func(s *SubjectContext, _ *DirectoryQuery) { s.Principal.Status = iamv1.PrincipalDisabled },
		"mixed management": func(_ *SubjectContext, q *DirectoryQuery) { q.Action = iamv1.ActionIAMUserList },
		"mixed discovery": func(_ *SubjectContext, q *DirectoryQuery) {
			q.AssumableRoles = &RoleDiscoveryRevision{CredentialGeneration: 9, DirectoryRevision: 1}
		},
	} {
		t.Run(name, func(t *testing.T) {
			changedSubject, changedQuery := subject, query
			revision := *query.LoginSessions
			changedQuery.LoginSessions = &revision
			change(&changedSubject, &changedQuery)
			if _, err := replica.Decode(cursor, changedSubject, changedQuery, now); !errors.Is(err, ErrInvalidCursor) {
				t.Fatal("changed own-session authority accepted continuation", err)
			}
		})
	}
	if _, err := replica.Decode(cursor, subject, query, now.Add(cursorLifetime)); !errors.Is(err, ErrInvalidCursor) {
		t.Fatal("expired own-session cursor accepted")
	}
}

func TestSelfRoleCursorHidesFilteredPositionAndBindsCurrentSnapshot(t *testing.T) {
	now := authorityTestTime()
	key := bytes.Repeat([]byte{0x75}, 32)
	codec, _ := NewCursorCodec(key)
	replica, _ := NewCursorCodec(key)
	subject := authoritySubject(now, iamv1.SystemPolicyAccountAdministrator, iamv1.SystemPolicyPaaSViewer)
	query := DirectoryQuery{InstallationID: subject.InstallationID, AssumableRoles: &RoleDiscoveryRevision{CredentialGeneration: 3, DirectoryRevision: 17}}
	position := "role-filtered-from-this-user-"
	position += strings.Repeat("x", 128-len(position))
	cursor, err := codec.Encode(subject, query, position, now)
	if err != nil || iamv1.ValidateRoleDiscoveryCursor(cursor) != nil || iamv1.ValidatePageCursor(cursor) == nil {
		t.Fatal("self cursor rejected bounded position", err)
	}
	envelope, err := base64.RawURLEncoding.Strict().DecodeString(cursor[4:])
	if err != nil || bytes.Contains(envelope, []byte(position)) || bytes.Contains(envelope, []byte("role-filtered")) {
		t.Fatal("self cursor disclosed a filtered role position")
	}
	for _, verifier := range []CursorCodec{codec, replica} {
		if after, err := verifier.Decode(cursor, subject, query, now.Add(time.Minute)); err != nil || after != position {
			t.Fatal("self cursor did not continue on another authority instance", err)
		}
	}
	// Empty pages still need continuation even when no candidate is assumable.
	// Self discovery cannot be conditioned on the management list/read action.
	ordinary := subject
	ordinary.Policies = nil
	self, err := codec.Encode(ordinary, query, "role-not-returned", now)
	if err != nil {
		t.Fatal("self discovery incorrectly required a management grant", err)
	}
	if after, err := replica.Decode(self, ordinary, query, now); err != nil || after != "role-not-returned" {
		t.Fatal("sparse self page could not continue", err)
	}
	management := DirectoryQuery{InstallationID: query.InstallationID, Action: iamv1.ActionIAMRoleList,
		Resource: iamv1.ResourceReference{Kind: iamv1.ResourceAccount, ID: string(subject.Organization.ID)}}
	if _, err := codec.Encode(ordinary, management, "role-not-returned", now); !errors.Is(err, ErrInvalidCursor) {
		t.Fatal("self discovery bypassed management authorization")
	}
	listed, err := codec.Encode(subject, management, position, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := codec.Decode(listed, subject, query, now); !errors.Is(err, ErrInvalidCursor) {
		t.Fatal("management cursor was accepted as private self continuation")
	}
	if _, err := codec.Decode(cursor, subject, management, now); !errors.Is(err, ErrInvalidCursor) {
		t.Fatal("self cursor was accepted as management continuation")
	}
	for name, change := range map[string]func(*SubjectContext, *DirectoryQuery){
		"credential generation": func(_ *SubjectContext, q *DirectoryQuery) { q.AssumableRoles.CredentialGeneration++ },
		"directory ABA":         func(_ *SubjectContext, q *DirectoryQuery) { q.AssumableRoles.DirectoryRevision += 2 },
		"source session":        func(s *SubjectContext, _ *DirectoryQuery) { s.Session.ID = "another-session" },
		"account revision":      func(s *SubjectContext, _ *DirectoryQuery) { s.Organization.ResourceVersion++ },
		"unmatched source removed": func(s *SubjectContext, _ *DirectoryQuery) {
			s.Policies = slices.DeleteFunc(s.Policies, func(row AttachedPolicy) bool { return row.Policy.ID == iamv1.SystemPolicyPaaSViewer })
		},
		"policy revision ABA": func(s *SubjectContext, _ *DirectoryQuery) { s.Policies[0].Policy.ResourceVersion += 2 },
		"attachment identity": func(s *SubjectContext, _ *DirectoryQuery) { s.Policies[0].Attachment.ID = "reattached-source" },
		"boundary identity": func(s *SubjectContext, _ *DirectoryQuery) {
			s.Boundary = userBoundaryForTest(*s, policyVersionForTest(t, "self-boundary", iamv1.PolicyAllow, iamv1.ActionIAMRoleAssume, iamv1.PolicyResourceAnyInAuthority, ""))
		},
		"forced password": func(s *SubjectContext, _ *DirectoryQuery) { s.Principal.MustChangePassword = true },
		"foreign account": func(s *SubjectContext, _ *DirectoryQuery) {
			s.Organization.ID, s.Principal.AccountID, s.Session.AccountID = "other-account", "other-account", "other-account"
			s.Boundary.AccountID = "other-account"
		},
		"foreign user": func(s *SubjectContext, _ *DirectoryQuery) {
			s.Principal.ID, s.Session.PrincipalID, s.Boundary.UserID = "other-user", "other-user", "other-user"
		},
		"zero generation":   func(_ *SubjectContext, q *DirectoryQuery) { q.AssumableRoles.CredentialGeneration = 0 },
		"zero watermark":    func(_ *SubjectContext, q *DirectoryQuery) { q.AssumableRoles.DirectoryRevision = 0 },
		"mixed purpose":     func(_ *SubjectContext, q *DirectoryQuery) { q.Action = iamv1.ActionIAMRoleList },
		"resource selector": func(_ *SubjectContext, q *DirectoryQuery) { q.Resource = management.Resource },
	} {
		t.Run(name, func(t *testing.T) {
			current := authoritySubject(now, iamv1.SystemPolicyAccountAdministrator, iamv1.SystemPolicyPaaSViewer)
			revision := *query.AssumableRoles
			changed := query
			changed.AssumableRoles = &revision
			change(&current, &changed)
			if after, err := codec.Decode(cursor, current, changed, now); !errors.Is(err, ErrInvalidCursor) || after != "" {
				t.Fatal("changed self authority disclosed a continuation position")
			}
		})
	}
	for index := range envelope {
		envelope[index] ^= 1
		forged := "ir1." + base64.RawURLEncoding.EncodeToString(envelope)
		if after, err := codec.Decode(forged, subject, query, now); !errors.Is(err, ErrInvalidCursor) || after != "" {
			t.Fatalf("changed self cursor byte %d passed", index)
		}
		envelope[index] ^= 1
	}
	if _, err := codec.Decode(cursor, subject, query, now.Add(cursorLifetime)); !errors.Is(err, ErrInvalidCursor) {
		t.Fatal("self continuation outlived its bounded expiry")
	}
}

func TestRoleSessionDirectoryCursorBindsAuthorityFiltersAndTerminalRevision(t *testing.T) {
	now := authorityTestTime()
	codec, _ := NewCursorCodec(bytes.Repeat([]byte{0x2c}, 32))
	subject := authoritySubject(now, iamv1.SystemPolicyAccountAdministrator)
	query := DirectoryQuery{InstallationID: subject.InstallationID, Action: iamv1.ActionIAMRoleSessionList, Resource: iamv1.ResourceReference{Kind: iamv1.ResourceRole, ID: "role-a"},
		RoleSessions: &RoleSessionDirectoryQuery{Revision: RoleSessionDirectoryRevision{CredentialGeneration: 3, DirectoryRevision: 12, UserAuthorizationGeneration: 7, Groups: []RoleSourceGroupGeneration{}}, Filter: iamv1.RoleSessionFilter{Lifecycle: "ALL"}}}
	cursor, err := codec.Encode(subject, query, "session-last-scanned", now)
	if err != nil {
		t.Fatal(err)
	}
	if after, err := codec.Decode(cursor, subject, query, now.Add(time.Second)); err != nil || after != "session-last-scanned" {
		t.Fatal("session directory could not continue", err)
	}
	for name, change := range map[string]func(*DirectoryQuery){
		"another role":               func(q *DirectoryQuery) { q.Resource.ID = "role-b" },
		"changed filter":             func(q *DirectoryQuery) { q.RoleSessions.Filter.Lifecycle = "REVOKED" },
		"source filter":              func(q *DirectoryQuery) { q.RoleSessions.Filter.SourceUserID = "user-b" },
		"session filter":             func(q *DirectoryQuery) { q.RoleSessions.Filter.SessionID = "session-b" },
		"new issuance or revocation": func(q *DirectoryQuery) { q.RoleSessions.Revision.DirectoryRevision++ },
		"credential change":          func(q *DirectoryQuery) { q.RoleSessions.Revision.CredentialGeneration++ },
		"temporary deny restored":    func(q *DirectoryQuery) { q.RoleSessions.Revision.UserAuthorizationGeneration += 2 },
		"empty group became denial source": func(q *DirectoryQuery) {
			q.RoleSessions.Revision.Groups = []RoleSourceGroupGeneration{{GroupID: "group-a", MembershipID: "membership-a", MembershipResourceVersion: 1, AuthorizationGeneration: 2}}
		},
		"no generation":          func(q *DirectoryQuery) { q.RoleSessions.Revision.CredentialGeneration = 0 },
		"missing group snapshot": func(q *DirectoryQuery) { q.RoleSessions.Revision.Groups = nil },
		"unnormalized filter":    func(q *DirectoryQuery) { q.RoleSessions.Filter.Lifecycle = "" },
		"unproved lifecycle":     func(q *DirectoryQuery) { q.RoleSessions.Filter.Lifecycle = "USABLE" },
		"different purpose":      func(q *DirectoryQuery) { q.Action = iamv1.ActionIAMRoleRead },
		"mixed self purpose": func(q *DirectoryQuery) {
			q.AssumableRoles = &RoleDiscoveryRevision{CredentialGeneration: 3, DirectoryRevision: 12}
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := query
			detail := *query.RoleSessions
			changed.RoleSessions = &detail
			change(&changed)
			if after, err := codec.Decode(cursor, subject, changed, now); !errors.Is(err, ErrInvalidCursor) || after != "" {
				t.Fatal("changed management binding disclosed continuation")
			}
		})
	}
	noPermission := subject
	noPermission.Policies = nil
	if _, err := codec.Decode(cursor, noPermission, query, now); !errors.Is(err, ErrInvalidCursor) {
		t.Fatal("directory revision became a permit")
	}
}

func TestDirectoryCursorCannotBypassExpiredPolicyConditions(t *testing.T) {
	now := authorityTestTime()
	codec, err := NewCursorCodec(bytes.Repeat([]byte{0x36}, 32))
	if err != nil {
		t.Fatal(err)
	}
	subject := authoritySubject(now, iamv1.SystemPolicyAccountAdministrator)
	row := &subject.Policies[0]
	row.Policy.ID, row.Version.PolicyID, row.Attachment.PolicyID = "timed-directory-policy", "timed-directory-policy", "timed-directory-policy"
	row.Policy.Management, row.Policy.AccountID = iamv1.PolicyCustomerManaged, subject.Organization.ID
	row.Version.Document.Statements[0].Conditions = []iamv1.PolicyCondition{{Key: iamv1.ConditionIAMCurrentTime, Operator: iamv1.PolicyDateLessThan, Values: []string{now.Add(10 * time.Second).Format(time.RFC3339Nano)}}}
	compilePolicyVersionForTest(t, &row.Version)
	query := DirectoryQuery{InstallationID: subject.InstallationID, Action: iamv1.ActionIAMGroupList, Resource: iamv1.ResourceReference{Kind: iamv1.ResourceAccount, ID: string(subject.Organization.ID)}}
	cursor, err := codec.Encode(subject, query, "group-last", now)
	if err != nil {
		t.Fatal(err)
	}
	if after, err := codec.Decode(cursor, subject, query, now.Add(9*time.Second)); err != nil || after != "group-last" {
		t.Fatal("valid timed cursor rejected")
	}
	if _, err := codec.Decode(cursor, subject, query, now.Add(10*time.Second)); !errors.Is(err, ErrInvalidCursor) {
		t.Fatal("cursor continued after granting policy expired")
	}
}

func TestResourcePrefixCannotGrantDirectoryAccessOrPreserveStaleCursor(t *testing.T) {
	now := authorityTestTime()
	codec, err := NewCursorCodec(bytes.Repeat([]byte{0x38}, 32))
	if err != nil {
		t.Fatal(err)
	}
	subject := authoritySubject(now, iamv1.SystemPolicyAccountAdministrator)
	prefix := authoritySubject(now, iamv1.SystemPolicyPaaSViewer).Policies[0]
	prefix.Version = policyVersionForTest(t, "prefix-cursor-policy", iamv1.PolicyAllow, iamv1.ActionPaaSApplicationRead, iamv1.PolicyResourcePrefixInAuthority, "application-")
	prefix.Policy.ID, prefix.Attachment.PolicyID = prefix.Version.PolicyID, prefix.Version.PolicyID
	prefix.Policy.DefaultVersionID = prefix.Version.ID
	prefix.Policy.Management, prefix.Policy.AccountID = iamv1.PolicyCustomerManaged, subject.Organization.ID
	query := DirectoryQuery{InstallationID: subject.InstallationID, Action: iamv1.ActionIAMGroupList, Resource: iamv1.ResourceReference{Kind: iamv1.ResourceAccount, ID: string(subject.Organization.ID)}}
	onlyPrefix := subject
	onlyPrefix.Policies = []AttachedPolicy{prefix}
	if _, err := codec.Encode(onlyPrefix, query, "group-last", now); !errors.Is(err, ErrInvalidCursor) {
		t.Fatal("application prefix granted directory authority")
	}
	subject.Policies = append(subject.Policies, prefix)
	cursor, err := codec.Encode(subject, query, "group-last", now)
	if err != nil {
		t.Fatal(err)
	}
	changed := &subject.Policies[len(subject.Policies)-1]
	changed.Version.Document.Statements[0].Resources[0].ID = "application-other-"
	changed.Version.ID, changed.Policy.DefaultVersionID = "prefix-next-version", "prefix-next-version"
	changed.Policy.ResourceVersion++
	compilePolicyVersionForTest(t, &changed.Version)
	if _, err := codec.Decode(cursor, subject, query, now); !errors.Is(err, ErrInvalidCursor) {
		t.Fatal("cursor retained stale prefix policy snapshot")
	}
	if _, err := codec.Encode(subject, query, "group-last", now); err != nil {
		t.Fatal("independent current directory grant lost after prefix change")
	}
}

func TestDirectoryCursorRechecksBoundaryAndBindsItsDefaultRevision(t *testing.T) {
	now := authorityTestTime()
	codec, err := NewCursorCodec(bytes.Repeat([]byte{0x45}, 32))
	if err != nil {
		t.Fatal(err)
	}
	subject := authoritySubject(now, iamv1.SystemPolicyAccountAdministrator)
	query := DirectoryQuery{InstallationID: subject.InstallationID, Action: iamv1.ActionIAMGroupList, Resource: iamv1.ResourceReference{Kind: iamv1.ResourceAccount, ID: string(subject.Organization.ID)}}
	subject.Boundary = userBoundaryForTest(subject, policyVersionForTest(t, "policy-boundary", iamv1.PolicyAllow, query.Action, iamv1.PolicyResourceAnyInAuthority, ""))
	cursor, err := codec.Encode(subject, query, "group-last", now)
	if err != nil {
		t.Fatal(err)
	}
	subject.Boundary.Policy.ResourceVersion++
	subject.Boundary.Policy.DefaultVersionID = "version-next"
	subject.Boundary.Version.ID = "version-next"
	if _, err := codec.Decode(cursor, subject, query, now); !errors.Is(err, ErrInvalidCursor) {
		t.Fatal("old cursor retained changed boundary default")
	}
	if _, err := codec.Encode(subject, query, "group-last", now); err != nil {
		t.Fatal("equally allowed new snapshot rejected")
	}
	subject.Boundary.Version.Document.Statements[0].Effect = iamv1.PolicyDeny
	compilePolicyVersionForTest(t, subject.Boundary.Version)
	if _, err := codec.Encode(subject, query, "group-last", now); !errors.Is(err, ErrInvalidCursor) {
		t.Fatal("directory bypassed boundary deny")
	}
}

func TestDirectoryCursorRechecksIdentityConditionsAfterDefaultChange(t *testing.T) {
	now := authorityTestTime()
	codec, err := NewCursorCodec(bytes.Repeat([]byte{0x37}, 32))
	if err != nil {
		t.Fatal(err)
	}
	subject := authoritySubject(now, iamv1.SystemPolicyAccountAdministrator)
	row := &subject.Policies[0]
	row.Policy.ID, row.Version.PolicyID, row.Attachment.PolicyID = "identity-directory-policy", "identity-directory-policy", "identity-directory-policy"
	row.Policy.Management, row.Policy.AccountID = iamv1.PolicyCustomerManaged, subject.Organization.ID
	row.Version.Document.Statements[0].Conditions = []iamv1.PolicyCondition{{Key: iamv1.ConditionIAMPrincipalID, Operator: iamv1.PolicyStringEquals, Values: []string{string(subject.Principal.ID)}}}
	compilePolicyVersionForTest(t, &row.Version)
	query := DirectoryQuery{InstallationID: subject.InstallationID, Action: iamv1.ActionIAMGroupList, Resource: iamv1.ResourceReference{Kind: iamv1.ResourceAccount, ID: string(subject.Organization.ID)}}
	cursor, err := codec.Encode(subject, query, "group-last", now)
	if err != nil {
		t.Fatal(err)
	}
	if after, err := codec.Decode(cursor, subject, query, now); err != nil || after != "group-last" {
		t.Fatal("matching identity cursor rejected")
	}
	row.Version.ID, row.Policy.DefaultVersionID = "version-identity-excluded", "version-identity-excluded"
	row.Policy.ResourceVersion++
	row.Version.Document.Statements[0].Conditions[0].Operator = iamv1.PolicyStringNotEquals
	compilePolicyVersionForTest(t, &row.Version)
	if _, err := codec.Encode(subject, query, "group-last", now); !errors.Is(err, ErrInvalidCursor) {
		t.Fatal("excluded identity issued a cursor")
	}
	if _, err := codec.Decode(cursor, subject, query, now); !errors.Is(err, ErrInvalidCursor) {
		t.Fatal("old cursor bypassed current identity conditions")
	}
}

func TestDirectoryCursorBindsCurrentAuthorityAndQuery(t *testing.T) {
	now := authorityTestTime()
	key := bytes.Repeat([]byte{0x35}, 32)
	codec, err := NewCursorCodec(key)
	if err != nil {
		t.Fatal(err)
	}
	subject := authoritySubject(now, iamv1.SystemPolicyAccountAdministrator, iamv1.SystemPolicyPlatformOperator, iamv1.SystemPolicyPaaSViewer)
	query := DirectoryQuery{InstallationID: subject.InstallationID, Action: iamv1.ActionIAMGroupList, Resource: iamv1.ResourceReference{Kind: iamv1.ResourceAccount, ID: string(subject.Organization.ID)}}
	cursor, err := codec.Encode(subject, query, "group-last", now)
	if err != nil || iamv1.ValidatePageCursor(cursor) != nil || cursor == "group-last" {
		t.Fatalf("encode bounded opaque cursor: %v", err)
	}
	// The input key can be cleared, a new process can use the same persisted key,
	// and database row order cannot change the authority binding.
	replica, _ := NewCursorCodec(key)
	clear(key)
	slices.Reverse(subject.Policies)
	for _, candidate := range []CursorCodec{codec, replica} {
		if after, err := candidate.Decode(cursor, subject, query, now.Add(time.Minute)); err != nil || after != "group-last" {
			t.Fatalf("replica/current source order changed continuation: %v", err)
		}
	}
	for _, kind := range []string{"principal", "account", "installation"} {
		t.Run("equally authorized other "+kind, func(t *testing.T) {
			other := authoritySubject(now, iamv1.SystemPolicyAccountAdministrator)
			other.InstallationID = ""
			originalQuery := DirectoryQuery{InstallationID: "installation-example", Action: query.Action, Resource: query.Resource}
			original, err := codec.Encode(other, originalQuery, "group-last", now)
			if err != nil {
				t.Fatal(err)
			}
			changedQuery := originalQuery
			switch kind {
			case "principal":
				other.Principal.ID, other.Session.PrincipalID, other.Session.ID = "principal-other", "principal-other", "session-other"
				other.Boundary.UserID = "principal-other"
				other.Policies[0].Attachment.Target.ID = "principal-other"
			case "account":
				other.Organization.ID, other.Principal.AccountID, other.Session.AccountID = "account-other", "account-other", "account-other"
				other.Boundary.AccountID = "account-other"
				other.Policies[0].Attachment.AccountID = "account-other"
				changedQuery.Resource.ID = "account-other"
			case "installation":
				changedQuery.InstallationID = "installation-other"
			}
			if _, err := codec.Encode(other, changedQuery, "group-last", now); err != nil {
				t.Fatal("other context is not independently valid")
			}
			if after, err := codec.Decode(original, other, changedQuery, now); !errors.Is(err, ErrInvalidCursor) || after != "" {
				t.Fatal("equally authorized identity reused another cursor")
			}
		})
	}
	for name, change := range map[string]func(*SubjectContext, *DirectoryQuery){
		"installation":     func(s *SubjectContext, _ *DirectoryQuery) { s.InstallationID = "another-installation" },
		"account revision": func(s *SubjectContext, _ *DirectoryQuery) { s.Organization.ResourceVersion++ },
		"credential lineage": func(s *SubjectContext, _ *DirectoryQuery) {
			s.Principal.ResourceVersion++
			s.Boundary.UserResourceVersion = s.Principal.ResourceVersion
		},
		"another session": func(s *SubjectContext, _ *DirectoryQuery) { s.Session.ID = "another-session" },
		"session expiry":  func(s *SubjectContext, _ *DirectoryQuery) { s.Session.ExpiresAt = s.Session.ExpiresAt.Add(time.Minute) },
		"session revoked": func(s *SubjectContext, _ *DirectoryQuery) {
			s.Session.Status = iamv1.SessionRevoked
			s.Session.RevokedAt = &now
		},
		"user disabled":       func(s *SubjectContext, _ *DirectoryQuery) { s.Principal.Status = iamv1.PrincipalDisabled },
		"account suspended":   func(s *SubjectContext, _ *DirectoryQuery) { s.Organization.Status = iamv1.AccountDisabled },
		"forced change":       func(s *SubjectContext, _ *DirectoryQuery) { s.Principal.MustChangePassword = true },
		"different directory": func(_ *SubjectContext, q *DirectoryQuery) { q.Action = iamv1.ActionIAMUserList },
		"different resource":  func(_ *SubjectContext, q *DirectoryQuery) { q.Resource.ID = "another-account" },
		"unsupported action":  func(_ *SubjectContext, q *DirectoryQuery) { q.Action = iamv1.ActionIAMGroupCreate },
		"attachment revision": func(s *SubjectContext, _ *DirectoryQuery) { s.Policies[0].Attachment.ResourceVersion++ },
		"policy revision":     func(s *SubjectContext, _ *DirectoryQuery) { s.Policies[0].Policy.ResourceVersion++ },
		"source removed with other allow": func(s *SubjectContext, _ *DirectoryQuery) {
			s.Policies = slices.DeleteFunc(s.Policies, func(row AttachedPolicy) bool { return row.Policy.ID == iamv1.SystemPolicyPaaSViewer })
		},
		"regranted source": func(s *SubjectContext, _ *DirectoryQuery) { s.Policies[0].Attachment.ID = "attachment-regranted" },
	} {
		t.Run(name, func(t *testing.T) {
			encoded, _ := json.Marshal(subject)
			var current SubjectContext
			if err := json.Unmarshal(encoded, &current); err != nil {
				t.Fatal(err)
			}
			currentQuery := query
			change(&current, &currentQuery)
			if after, err := codec.Decode(cursor, current, currentQuery, now); !errors.Is(err, ErrInvalidCursor) || after != "" {
				t.Fatalf("changed scope/authority disclosed a boundary: %v", err)
			}
		})
	}
	for _, at := range []time.Time{now.Add(-time.Microsecond), now.Add(cursorLifetime), now.Add(time.Hour)} {
		if after, err := codec.Decode(cursor, subject, query, at); !errors.Is(err, ErrInvalidCursor) || after != "" {
			t.Fatal("cursor accepted outside its time window")
		}
	}
	other, _ := NewCursorCodec(bytes.Repeat([]byte{0x46}, 32))
	if after, err := other.Decode(cursor, subject, query, now); !errors.Is(err, ErrInvalidCursor) || after != "" {
		t.Fatal("another key accepted the cursor")
	}
	var absent CursorCodec
	if _, err := absent.Encode(subject, query, "group-last", now); !errors.Is(err, ErrInvalidCursorKey) {
		t.Fatal("zero codec could sign")
	}
	if _, err := absent.Decode(cursor, subject, query, now); !errors.Is(err, ErrInvalidCursorKey) {
		t.Fatal("zero codec could decode")
	}
}

func TestDirectoryCursorRejectsTamperingAndBindsMembership(t *testing.T) {
	now := authorityTestTime()
	codec, _ := NewCursorCodec(bytes.Repeat([]byte{0x57}, 32))
	subject := authoritySubject(now, iamv1.SystemPolicyAccountAdministrator)
	row := &subject.Policies[0]
	row.Attachment.Target = iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetGroup, ID: "group-admins"}
	row.Membership = &iamv1.GroupMembership{APIVersion: iamv1.APIVersion, Kind: "GroupMembership", ID: "membership-original", AccountID: subject.Organization.ID,
		GroupID: "group-admins", UserID: subject.Principal.ID, CreatedBy: "principal-root", ResourceVersion: 1, CreatedAt: now.Add(-time.Minute), UpdatedAt: now.Add(-time.Minute)}
	query := DirectoryQuery{InstallationID: subject.InstallationID, Action: iamv1.ActionIAMGroupMembershipList, Resource: iamv1.ResourceReference{Kind: iamv1.ResourceGroup, ID: "group-managed"}}
	// The installation owning the key does not confer platform permission on
	// an ordinary tenant subject, whose platform context remains empty.
	subject.InstallationID = ""
	cursor, err := codec.Encode(subject, query, "membership-last", now)
	if err != nil {
		t.Fatal(err)
	}
	if after, err := codec.Decode(cursor, subject, query, now); err != nil || after != "membership-last" {
		t.Fatal("valid group source failed")
	}
	row.Membership.ResourceVersion++
	if _, err := codec.Decode(cursor, subject, query, now); !errors.Is(err, ErrInvalidCursor) {
		t.Fatal("membership revision was not bound")
	}
	row.Membership.ResourceVersion--
	row.Membership.ID = "membership-new-join"
	if _, err := codec.Decode(cursor, subject, query, now); !errors.Is(err, ErrInvalidCursor) {
		t.Fatal("rejoin resurrected old cursor")
	}
	row.Membership.ID = "membership-original"
	differentGroup := query
	differentGroup.Resource.ID = "group-other"
	if _, err := codec.Decode(cursor, subject, differentGroup, now); !errors.Is(err, ErrInvalidCursor) {
		t.Fatal("another group accepted cursor")
	}
	for _, invalid := range []string{"", "group-last", cursor + "=", "ic2." + cursor[4:], cursor + "\n", "ic1." + strings.Repeat("x", iamv1.MaxPageCursorBytes), "ic1.A", cursor[:len(cursor)-1]} {
		if after, err := codec.Decode(invalid, subject, query, now); !errors.Is(err, ErrInvalidCursor) || after != "" {
			t.Fatal("malformed cursor disclosed a boundary")
		}
	}
	encoded, _ := base64.RawURLEncoding.DecodeString(cursor[4:])
	for index := range encoded {
		encoded[index] ^= 1
		forged := "ic1." + base64.RawURLEncoding.EncodeToString(encoded)
		if after, err := codec.Decode(forged, subject, query, now); !errors.Is(err, ErrInvalidCursor) || after != "" {
			t.Fatalf("changed byte %d passed", index)
		}
		encoded[index] ^= 1
	}
	subject.Session.ExpiresAt = now.Add(time.Minute)
	short, err := codec.Encode(subject, query, "membership-last", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := codec.Decode(short, subject, query, now.Add(time.Minute)); !errors.Is(err, ErrInvalidCursor) {
		t.Fatal("cursor survived its session")
	}
	for _, key := range [][]byte{nil, {}, make([]byte, 31), make([]byte, 33)} {
		if _, err := NewCursorCodec(key); !errors.Is(err, ErrInvalidCursorKey) {
			t.Fatal("invalid key accepted")
		}
	}
}

func TestRoleDirectoryCursorsBindTheirExactCurrentAuthority(t *testing.T) {
	now := authorityTestTime()
	codec, _ := NewCursorCodec(bytes.Repeat([]byte{0x64}, 32))
	subject := authoritySubject(now, iamv1.SystemPolicyAccountAdministrator)
	queries := []DirectoryQuery{
		{InstallationID: subject.InstallationID, Action: iamv1.ActionIAMRoleList, Resource: iamv1.ResourceReference{Kind: iamv1.ResourceAccount, ID: string(subject.Organization.ID)}},
		{InstallationID: subject.InstallationID, Action: iamv1.ActionIAMRoleRead, Resource: iamv1.ResourceReference{Kind: iamv1.ResourceRole, ID: "role-one"}},
	}
	for _, query := range queries {
		t.Run(string(query.Action), func(t *testing.T) {
			cursor, err := codec.Encode(subject, query, "last-item", now)
			if err != nil {
				t.Fatal("authorized role directory could not continue", err)
			}
			if after, err := codec.Decode(cursor, subject, query, now); err != nil || after != "last-item" {
				t.Fatal("role directory lost its boundary", err)
			}
			for _, other := range []DirectoryQuery{
				{InstallationID: query.InstallationID, Action: iamv1.ActionIAMRoleRead, Resource: iamv1.ResourceReference{Kind: iamv1.ResourceRole, ID: "role-two"}},
				{InstallationID: query.InstallationID, Action: iamv1.ActionIAMUserList, Resource: queries[0].Resource},
				{InstallationID: query.InstallationID, Action: iamv1.ActionIAMRoleList, Resource: queries[1].Resource},
				{InstallationID: query.InstallationID, Action: iamv1.ActionIAMRoleRead, Resource: queries[0].Resource},
			} {
				if _, err := codec.Decode(cursor, subject, other, now); !errors.Is(err, ErrInvalidCursor) {
					t.Fatal("role cursor crossed directory/resource authority")
				}
			}
			denied := subject
			denied.Policies = nil
			if _, err := codec.Decode(cursor, denied, query, now); !errors.Is(err, ErrInvalidCursor) {
				t.Fatal("cursor retained revoked role read authority")
			}
		})
	}
}
