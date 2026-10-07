package nethttp

import (
	"errors"
	"strings"
	"testing"
	"time"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/port"
)

func TestApplicationCursorBindsInstallationAccountSubjectAndProfile(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	codec, err := newApplicationCursorCodec(key)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.October, 7, 1, 2, 3, 4_000, time.UTC)
	subject := testApplicationCursorSubject(t)
	cursor, err := codec.encode("installation-a", subject, "application-hidden", now)
	if err != nil || paasv1.ValidateApplicationCursor(cursor) != nil || strings.Contains(cursor, "application-hidden") {
		t.Fatalf("encode cursor=%q err=%v", cursor, err)
	}
	after, err := codec.decode(cursor, "installation-a", subject, now.Add(time.Minute))
	if err != nil || after != "application-hidden" {
		t.Fatalf("decode after=%q err=%v", after, err)
	}

	role := subject
	role.Subject = paasv1.SubjectRef{Type: paasv1.SubjectRole, ID: "role-a", RoleSession: &paasv1.RoleSessionReference{
		SessionID: "role-session-a", SourceUserID: "user-a",
	}}
	roleCursor, err := codec.encode("installation-a", role, "application-z", now)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*port.AuthorizationSubjectContext, *string){
		"installation": func(_ *port.AuthorizationSubjectContext, installation *string) { *installation = "installation-b" },
		"account":      func(v *port.AuthorizationSubjectContext, _ *string) { v.TenantID = "account-b" },
		"role":         func(v *port.AuthorizationSubjectContext, _ *string) { v.Subject.ID = "role-b" },
		"session": func(v *port.AuthorizationSubjectContext, _ *string) {
			v.Subject.RoleSession.SessionID = "role-session-b"
		},
		"source":  func(v *port.AuthorizationSubjectContext, _ *string) { v.Subject.RoleSession.SourceUserID = "user-b" },
		"profile": func(v *port.AuthorizationSubjectContext, _ *string) { v.Profile.Revision++ },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := role
			lineage := *role.Subject.RoleSession
			candidate.Subject.RoleSession = &lineage
			installation := "installation-a"
			mutate(&candidate, &installation)
			if _, err := codec.decode(roleCursor, installation, candidate, now.Add(time.Minute)); !errors.Is(err, errInvalidApplicationCursor) {
				t.Fatalf("changed binding err=%v", err)
			}
		})
	}
}

func TestApplicationCursorFailsClosedForKeyTamperAndTime(t *testing.T) {
	for _, key := range [][]byte{nil, make([]byte, 31), make([]byte, 33)} {
		if _, err := newApplicationCursorCodec(key); !errors.Is(err, errInvalidApplicationCursorKey) {
			t.Fatalf("invalid key length=%d err=%v", len(key), err)
		}
	}
	key := []byte("0123456789abcdef0123456789abcdef")
	codec, _ := newApplicationCursorCodec(key)
	subject := testApplicationCursorSubject(t)
	now := time.Date(2026, time.October, 7, 1, 2, 3, 0, time.UTC)
	cursor, err := codec.encode("installation-a", subject, "application-a", now)
	if err != nil {
		t.Fatal(err)
	}
	changed := cursor[:len(cursor)-1] + "A"
	if changed == cursor {
		changed = cursor[:len(cursor)-1] + "B"
	}
	other, _ := newApplicationCursorCodec([]byte("abcdef0123456789abcdef0123456789"))
	for name, value := range map[string]struct {
		codec applicationCursorCodec
		wire  string
		now   time.Time
	}{
		"tampered":   {codec, changed, now.Add(time.Minute)},
		"wrong key":  {other, cursor, now.Add(time.Minute)},
		"expired":    {codec, cursor, now.Add(applicationCursorLifetime)},
		"future":     {codec, cursor, now.Add(-time.Microsecond)},
		"raw id":     {codec, "application-a", now.Add(time.Minute)},
		"other kind": {codec, "ic1.foreign", now.Add(time.Minute)},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := value.codec.decode(value.wire, "installation-a", subject, value.now); !errors.Is(err, errInvalidApplicationCursor) {
				t.Fatalf("invalid cursor err=%v", err)
			}
		})
	}
	if _, err := codec.encode("installation-a", subject, "", now); !errors.Is(err, errInvalidApplicationCursor) {
		t.Fatalf("empty position err=%v", err)
	}
}

func testApplicationCursorSubject(t *testing.T) port.AuthorizationSubjectContext {
	t.Helper()
	profile, known := iamv1.LookupAuthorizationProfile(iamv1.ProductPaaS)
	if !known {
		t.Fatal("PaaS profile is missing")
	}
	_, digest, err := iamv1.CanonicalizeAuthorizationProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	return port.AuthorizationSubjectContext{
		TenantID: "account-a",
		Subject:  paasv1.SubjectRef{Type: paasv1.SubjectUser, ID: "user-a", AccessKeyID: "access-key-a"},
		Profile:  iamv1.AuthorizationProfileReference{Product: profile.Product, Revision: profile.Revision, ContentDigest: digest},
	}
}
