package installationv1

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
)

func TestTOTPBackupSnapshotLeaseHasOneCanonicalNonSecretForm(t *testing.T) {
	value := totpBackupSnapshotLeaseFixture(t)
	want := `{"apiVersion":"installation.matrix.xiak.com/v1","kind":"IAMTOTPBackupSnapshotLease","purpose":"IAM_TOTP_BACKUP_CUSTODY","snapshotId":"00000003-0000001B-1","custody":{"apiVersion":"installation.matrix.xiak.com/v1","kind":"IAMTOTPBackupCustody","purpose":"IAM_TOTP_BACKUP_CUSTODY","installationId":"mxi-0123456789abcdef0123456789abcdef","bootstrapDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","keysetRevision":2,"requiredKeys":[{"keyId":"totp-wrapping-v1","formatVersion":1,"commitment":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},{"keyId":"totp-wrapping-v2","formatVersion":1,"commitment":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}]},"custodyDigest":"sha256:3fb262321b4b154d5e348be95553c5ffd3990a3964769cea130c0b9f90b0e108"}`

	encoded, err := EncodeTOTPBackupSnapshotLease(value)
	if err != nil || string(encoded) != want {
		t.Fatalf("encode TOTP backup lease = %q / %v", encoded, err)
	}
	decoded, err := DecodeTOTPBackupSnapshotLease(bytes.NewReader(encoded))
	if err != nil || !reflect.DeepEqual(decoded, value) {
		t.Fatalf("decode TOTP backup lease = %#v / %v", decoded, err)
	}
	if strings.Contains(string(encoded), "keyMaterial") || strings.Contains(string(encoded), "seed") {
		t.Fatal("TOTP backup lease exposed secret material")
	}
}

func TestTOTPBackupCustodyProcessProtocolIsClosedAndBounded(t *testing.T) {
	if TOTPBackupCustodySnapshotCommand != "snapshot" ||
		TOTPBackupCustodyDatabaseDSNFileEnvironment != "MATRIX_IAM_BACKUP_CUSTODY_DATABASE_DSN_FILE" ||
		TOTPBackupCustodyMigrationDSNFileEnvironment != "MATRIX_MIGRATION_IAM_BACKUP_CUSTODY_DSN_FILE" ||
		TOTPBackupCustodyReleaseFrame != "RELEASE\n" || len(TOTPBackupCustodyReleaseFrame) != 8 ||
		TOTPBackupSnapshotLeaseMaximumSeconds != 600 {
		t.Fatal("TOTP backup custody process protocol drifted")
	}
	exits := map[int]string{
		TOTPBackupCustodyExitSuccess:     "",
		TOTPBackupCustodyExitInvalid:     TOTPBackupCustodyErrorInvalid,
		TOTPBackupCustodyExitForbidden:   TOTPBackupCustodyErrorForbidden,
		TOTPBackupCustodyExitUnavailable: TOTPBackupCustodyErrorUnavailable,
	}
	if len(exits) != 4 || exits[0] != "" || exits[2] != "IAM_BACKUP_CUSTODY_INVALID" ||
		exits[3] != "IAM_BACKUP_CUSTODY_FORBIDDEN" || exits[6] != "IAM_BACKUP_CUSTODY_UNAVAILABLE" {
		t.Fatal("TOTP backup custody exit protocol is ambiguous")
	}
	for exitCode, errorCode := range exits {
		if exitCode == TOTPBackupCustodyExitSuccess {
			continue
		}
		if errorCode == "" || strings.ContainsAny(errorCode, " \t\r\n") {
			t.Fatalf("exit %d has an unsafe stable error code %q", exitCode, errorCode)
		}
	}
}

func TestTOTPBackupCustodyDigestBindsScopeRevisionAndRequiredKeysOnly(t *testing.T) {
	lease := totpBackupSnapshotLeaseFixture(t)
	digest, err := TOTPBackupCustodyDigest(lease.Custody)
	if err != nil || digest != lease.CustodyDigest {
		t.Fatalf("custody digest = %q / %v", digest, err)
	}

	changedSnapshot := lease
	changedSnapshot.SnapshotID = "00000004-0000002C-2"
	if err := ValidateTOTPBackupSnapshotLease(changedSnapshot); err != nil {
		t.Fatalf("ephemeral snapshot changed persistent custody evidence: %v", err)
	}
	changedDigest, err := TOTPBackupCustodyDigest(changedSnapshot.Custody)
	if err != nil || changedDigest != digest {
		t.Fatalf("snapshot identifier entered custody digest = %q / %v", changedDigest, err)
	}

	changes := map[string]func(*TOTPBackupCustody){
		"installation": func(v *TOTPBackupCustody) { v.InstallationID = "mxi-fedcba9876543210fedcba9876543210" },
		"bootstrap": func(v *TOTPBackupCustody) {
			v.BootstrapDigest = "sha256:" + strings.Repeat("d", 64)
		},
		"revision": func(v *TOTPBackupCustody) { v.KeysetRevision++ },
		"key": func(v *TOTPBackupCustody) {
			v.RequiredKeys = append([]TOTPBackupRequiredKey(nil), v.RequiredKeys...)
			v.RequiredKeys[0].KeyID = "totp-wrapping-v0"
		},
		"format": func(v *TOTPBackupCustody) {
			v.RequiredKeys = append([]TOTPBackupRequiredKey(nil), v.RequiredKeys...)
			v.RequiredKeys[0].FormatVersion = 2
		},
		"commitment": func(v *TOTPBackupCustody) {
			v.RequiredKeys = append([]TOTPBackupRequiredKey(nil), v.RequiredKeys...)
			v.RequiredKeys[0].Commitment = "sha256:" + strings.Repeat("e", 64)
		},
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			changed := lease.Custody
			change(&changed)
			changedDigest, err := TOTPBackupCustodyDigest(changed)
			if name == "format" {
				if !errors.Is(err, ErrInvalidTOTPBackupCustody) || changedDigest != "" {
					t.Fatalf("unknown format produced custody digest = %q / %v", changedDigest, err)
				}
				return
			}
			if err != nil || changedDigest == digest {
				t.Fatalf("changed custody digest = %q / %v", changedDigest, err)
			}
		})
	}
}

func TestTOTPBackupCustodyRejectsAmbiguousOrUnboundedRequirements(t *testing.T) {
	base := totpBackupSnapshotLeaseFixture(t).Custody
	changes := map[string]func(*TOTPBackupCustody){
		"version":      func(v *TOTPBackupCustody) { v.APIVersion = "installation.matrix.xiak.com/v2" },
		"kind":         func(v *TOTPBackupCustody) { v.Kind = "TOTPKeyset" },
		"purpose":      func(v *TOTPBackupCustody) { v.Purpose = iamv1.TOTPWrappingPurpose },
		"installation": func(v *TOTPBackupCustody) { v.InstallationID = "mxi-other" },
		"bootstrap":    func(v *TOTPBackupCustody) { v.BootstrapDigest = "sha256:short" },
		"zero revision": func(v *TOTPBackupCustody) {
			v.KeysetRevision = 0
		},
		"large revision": func(v *TOTPBackupCustody) {
			v.KeysetRevision = iamv1.MaxTOTPKeysetRevision + 1
		},
		"missing requirements": func(v *TOTPBackupCustody) {
			v.RequiredKeys = nil
		},
		"duplicate": func(v *TOTPBackupCustody) {
			v.RequiredKeys = append([]TOTPBackupRequiredKey(nil), v.RequiredKeys...)
			v.RequiredKeys[1] = v.RequiredKeys[0]
		},
		"unsorted": func(v *TOTPBackupCustody) {
			v.RequiredKeys = append([]TOTPBackupRequiredKey(nil), v.RequiredKeys...)
			v.RequiredKeys[0], v.RequiredKeys[1] = v.RequiredKeys[1], v.RequiredKeys[0]
		},
		"invalid key": func(v *TOTPBackupCustody) {
			v.RequiredKeys = append([]TOTPBackupRequiredKey(nil), v.RequiredKeys...)
			v.RequiredKeys[0].KeyID = "../key"
		},
		"invalid format": func(v *TOTPBackupCustody) {
			v.RequiredKeys = append([]TOTPBackupRequiredKey(nil), v.RequiredKeys...)
			v.RequiredKeys[0].FormatVersion = 0
		},
		"invalid commitment": func(v *TOTPBackupCustody) {
			v.RequiredKeys = append([]TOTPBackupRequiredKey(nil), v.RequiredKeys...)
			v.RequiredKeys[0].Commitment = "sha256:" + strings.Repeat("g", 64)
		},
		"too many": func(v *TOTPBackupCustody) {
			v.RequiredKeys = make([]TOTPBackupRequiredKey, iamv1.MaxTOTPWrappingKeys+1)
			for index := range v.RequiredKeys {
				v.RequiredKeys[index] = TOTPBackupRequiredKey{
					KeyID: "key-" + string(rune('a'+index)), FormatVersion: 1,
					Commitment: "sha256:" + strings.Repeat(string(rune('a'+index)), 64),
				}
			}
		},
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			value := base
			change(&value)
			if err := ValidateTOTPBackupCustody(value); !errors.Is(err, ErrInvalidTOTPBackupCustody) {
				t.Fatalf("validate changed custody = %v", err)
			}
			if digest, err := TOTPBackupCustodyDigest(value); !errors.Is(err, ErrInvalidTOTPBackupCustody) || digest != "" {
				t.Fatalf("digest changed custody = %q / %v", digest, err)
			}
		})
	}

	empty := base
	empty.RequiredKeys = []TOTPBackupRequiredKey{}
	if err := ValidateTOTPBackupCustody(empty); err != nil {
		t.Fatalf("explicit empty requirement set was not representable: %v", err)
	}
	if digest, err := TOTPBackupCustodyDigest(empty); err != nil || digest == "" {
		t.Fatalf("digest explicit empty requirement set = %q / %v", digest, err)
	}
}

func TestTOTPBackupSnapshotLeaseRejectsExpiredShapeOrChangedCustody(t *testing.T) {
	base := totpBackupSnapshotLeaseFixture(t)
	changes := map[string]func(*TOTPBackupSnapshotLease){
		"version": func(v *TOTPBackupSnapshotLease) { v.APIVersion = "installation.matrix.xiak.com/v2" },
		"kind":    func(v *TOTPBackupSnapshotLease) { v.Kind = "IAMTOTPBackupCustody" },
		"purpose": func(v *TOTPBackupSnapshotLease) { v.Purpose = "IAM_TOTP_SEED_WRAPPING" },
		"empty snapshot": func(v *TOTPBackupSnapshotLease) {
			v.SnapshotID = ""
		},
		"lowercase snapshot": func(v *TOTPBackupSnapshotLease) {
			v.SnapshotID = "00000003-0000001b-1"
		},
		"snapshot injection": func(v *TOTPBackupSnapshotLease) {
			v.SnapshotID = "00000003-0000001B-1 --"
		},
		"changed custody": func(v *TOTPBackupSnapshotLease) {
			v.Custody.KeysetRevision++
		},
		"invalid digest": func(v *TOTPBackupSnapshotLease) {
			v.CustodyDigest = "sha256:" + strings.Repeat("f", 64)
		},
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			value := base
			value.Custody.RequiredKeys = append([]TOTPBackupRequiredKey(nil), base.Custody.RequiredKeys...)
			change(&value)
			if err := ValidateTOTPBackupSnapshotLease(value); !errors.Is(err, ErrInvalidTOTPBackupSnapshotLease) {
				t.Fatalf("validate changed lease = %v", err)
			}
			if encoded, err := EncodeTOTPBackupSnapshotLease(value); !errors.Is(err, ErrInvalidTOTPBackupSnapshotLease) || len(encoded) != 0 {
				t.Fatalf("encode changed lease = %q / %v", encoded, err)
			}
		})
	}
}

func TestTOTPBackupSnapshotLeaseRejectsAmbiguousJSON(t *testing.T) {
	canonical, err := EncodeTOTPBackupSnapshotLease(totpBackupSnapshotLeaseFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	variants := map[string]string{
		"unknown": strings.Replace(string(canonical), `"snapshotId":`, `"extra":true,"snapshotId":`, 1),
		"duplicate": strings.Replace(
			string(canonical), `"snapshotId":"00000003-0000001B-1"`,
			`"snapshotId":"00000003-0000001B-1","snapshotId":"00000003-0000001B-1"`, 1,
		),
		"null":       strings.Replace(string(canonical), `"snapshotId":"00000003-0000001B-1"`, `"snapshotId":null`, 1),
		"whitespace": " " + string(canonical),
		"newline":    string(canonical) + "\n",
		"trailing":   string(canonical) + `{}`,
	}
	for name, input := range variants {
		t.Run(name, func(t *testing.T) {
			value, err := DecodeTOTPBackupSnapshotLease(strings.NewReader(input))
			if !errors.Is(err, ErrInvalidTOTPBackupSnapshotLease) || !reflect.DeepEqual(value, TOTPBackupSnapshotLease{}) {
				t.Fatalf("decode ambiguous lease = %#v / %v", value, err)
			}
		})
	}
	value, err := DecodeTOTPBackupSnapshotLease(strings.NewReader(strings.Repeat("x", int(MaximumTOTPBackupCustodyBytes)+1)))
	if !errors.Is(err, ErrInvalidTOTPBackupSnapshotLease) || !reflect.DeepEqual(value, TOTPBackupSnapshotLease{}) {
		t.Fatalf("decode oversized lease = %#v / %v", value, err)
	}
	if value, err = DecodeTOTPBackupSnapshotLease(nil); !errors.Is(err, ErrInvalidTOTPBackupSnapshotLease) || !reflect.DeepEqual(value, TOTPBackupSnapshotLease{}) {
		t.Fatalf("decode nil lease = %#v / %v", value, err)
	}
}

func FuzzTOTPBackupSnapshotLeaseCanonicalBytes(f *testing.F) {
	seed, err := EncodeTOTPBackupSnapshotLease(totpBackupSnapshotLeaseFixture(f))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Fuzz(func(t *testing.T, source []byte) {
		value, err := DecodeTOTPBackupSnapshotLease(bytes.NewReader(source))
		if err != nil {
			if !reflect.DeepEqual(value, TOTPBackupSnapshotLease{}) {
				t.Fatal("invalid lease returned data")
			}
			return
		}
		canonical, err := EncodeTOTPBackupSnapshotLease(value)
		if err != nil || !bytes.Equal(source, canonical) {
			t.Fatal("accepted lease was not canonical")
		}
	})
}

func totpBackupSnapshotLeaseFixture(t testing.TB) TOTPBackupSnapshotLease {
	t.Helper()
	custody := TOTPBackupCustody{
		APIVersion: TOTPBackupCustodyAPIVersion, Kind: TOTPBackupCustodyKind,
		Purpose:         TOTPBackupCustodyPurpose,
		InstallationID:  "mxi-0123456789abcdef0123456789abcdef",
		BootstrapDigest: "sha256:" + strings.Repeat("a", 64), KeysetRevision: 2,
		RequiredKeys: []TOTPBackupRequiredKey{
			{KeyID: "totp-wrapping-v1", FormatVersion: 1, Commitment: "sha256:" + strings.Repeat("b", 64)},
			{KeyID: "totp-wrapping-v2", FormatVersion: 1, Commitment: "sha256:" + strings.Repeat("c", 64)},
		},
	}
	digest, err := TOTPBackupCustodyDigest(custody)
	if err != nil {
		t.Fatal(err)
	}
	return TOTPBackupSnapshotLease{
		APIVersion: TOTPBackupCustodyAPIVersion, Kind: TOTPBackupSnapshotLeaseKind,
		Purpose: TOTPBackupCustodyPurpose, SnapshotID: "00000003-0000001B-1",
		Custody: custody, CustodyDigest: digest,
	}
}
