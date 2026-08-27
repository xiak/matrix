package authority

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
)

func TestCursorIsOpaqueTenantAndFilterBound(t *testing.T) {
	key := bytes.Repeat([]byte{0x5a}, 32)
	codec, err := NewCursorCodec(key)
	if err != nil {
		t.Fatalf("create cursor codec: %v", err)
	}
	from := time.Date(2026, 8, 25, 0, 0, 0, 0, time.UTC)
	to := from.Add(24*time.Hour - time.Microsecond)
	query := auditv1.QueryRecordsRequest{
		PageSize: 50, From: &from, To: &to,
		Action: auditv1.ActionPaaSDeploymentCreated,
		Actor:  &auditv1.ActorReference{Type: auditv1.ActorUser, ID: "principal-example"},
	}
	cursor, err := codec.Encode(TenantChain("organization-example"), query, 42)
	if err != nil {
		t.Fatalf("encode cursor: %v", err)
	}
	queryWithCursor := query
	queryWithCursor.Cursor = cursor
	if err := auditv1.ValidateQueryRecordsRequest(queryWithCursor); err != nil {
		t.Fatalf("encoded cursor violates Audit contract: %v", err)
	}
	sequence, err := codec.Decode(cursor, TenantChain("organization-example"), query)
	if err != nil || sequence != 42 {
		t.Fatalf("decode cursor: sequence=%d err=%v", sequence, err)
	}
	parts := strings.Split(string(cursor), ".")
	payload, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode cursor payload: %v", err)
	}
	if bytes.Contains(payload, []byte("organization-example")) || strings.Contains(string(cursor), "organization-example") {
		t.Fatal("cursor exposes tenant identity")
	}

	if _, err := codec.Decode(cursor, TenantChain("organization-other"), query); !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("cross-tenant cursor error = %v", err)
	}
	changed := query
	changed.PageSize++
	if _, err := codec.Decode(cursor, TenantChain("organization-example"), changed); !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("cross-filter cursor error = %v", err)
	}
	otherCodec, _ := NewCursorCodec(bytes.Repeat([]byte{0x6b}, 32))
	if _, err := otherCodec.Decode(cursor, TenantChain("organization-example"), query); !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("cursor signed by another key error = %v", err)
	}
}

func TestCursorRejectsTamperingUnboundedInputAndInvalidKeys(t *testing.T) {
	if _, err := NewCursorCodec(bytes.Repeat([]byte{0x5a}, 31)); !errors.Is(err, ErrInvalidCursorKey) {
		t.Fatalf("short cursor key error = %v", err)
	}
	codec, _ := NewCursorCodec(bytes.Repeat([]byte{0x5a}, 32))
	query := auditv1.QueryRecordsRequest{PageSize: 20}
	cursor, err := codec.Encode(TenantChain("organization-example"), query, 42)
	if err != nil {
		t.Fatalf("encode cursor: %v", err)
	}
	tampered := []byte(cursor)
	if tampered[len(tampered)-1] == 'A' {
		tampered[len(tampered)-1] = 'B'
	} else {
		tampered[len(tampered)-1] = 'A'
	}
	if _, err := codec.Decode(auditv1.Cursor(tampered), TenantChain("organization-example"), query); !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("tampered cursor error = %v", err)
	}
	query.PageSize = auditv1.MaxPageSize + 1
	if _, err := codec.Encode(TenantChain("organization-example"), query, 42); !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("unbounded filter cursor error = %v", err)
	}
	if _, err := codec.Decode("organization-example:42", TenantChain("organization-example"), auditv1.QueryRecordsRequest{PageSize: 20}); !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("transparent unsigned cursor error = %v", err)
	}
}

func TestCursorCannotCrossAuthorityNamespaceOrInstallation(t *testing.T) {
	codec, _ := NewCursorCodec(bytes.Repeat([]byte{0x5a}, 32))
	query := auditv1.QueryRecordsRequest{PageSize: 20}
	platform := InstallationChain("same-authority")
	cursor, err := codec.Encode(platform, query, 42)
	if err != nil {
		t.Fatal(err)
	}
	if sequence, err := codec.Decode(cursor, platform, query); err != nil || sequence != 42 {
		t.Fatalf("installation cursor failed: sequence=%d err=%v", sequence, err)
	}
	for _, other := range []ChainID{TenantChain("same-authority"), InstallationChain("another-installation")} {
		if _, err := codec.Decode(cursor, other, query); !errors.Is(err, ErrInvalidCursor) {
			t.Fatalf("installation cursor crossed into %s: %v", other, err)
		}
	}
	tenantCursor, _ := codec.Encode(TenantChain("same-authority"), query, 42)
	if _, err := codec.Decode(tenantCursor, platform, query); !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("tenant cursor crossed into installation: %v", err)
	}
}
