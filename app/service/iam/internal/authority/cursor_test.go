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
