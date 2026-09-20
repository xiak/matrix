package installationv1

import (
	"bytes"
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"
)

func TestAuthenticationRecoveryClosureHasOneCanonicalClosedForm(t *testing.T) {
	value := authenticationRecoveryClosureFixture()
	want := `{"apiVersion":"installation.matrix.xiak.com/v1","kind":"IAMAuthenticationRecoveryClosure","purpose":"IAM_AUTHENTICATION_BACKUP_RECOVERY","installationId":"mxi-0123456789abcdef0123456789abcdef","epoch":7,"state":"CLOSED","commandId":"cmd-0123456789abcdef0123456789abcdef","backupId":"backup-fedcba9876543210fedcba9876543210","backupDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","recoveryIntentDigest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","totpCustodyDigest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}`

	encoded, err := EncodeAuthenticationRecoveryClosure(value)
	if err != nil || string(encoded) != want {
		t.Fatalf("encode closure = %q / %v", encoded, err)
	}
	decoded, err := DecodeAuthenticationRecoveryClosure(bytes.NewReader(encoded))
	if err != nil || !reflect.DeepEqual(decoded, value) {
		t.Fatalf("decode closure = %#v / %v", decoded, err)
	}
	if decoded.State != AuthenticationRecoveryStateClosed {
		t.Fatal("recovery closure exposed a non-closed state")
	}
}

func TestAuthenticationRecoveryClosureRejectsOpenOrAmbiguousInput(t *testing.T) {
	canonical, err := EncodeAuthenticationRecoveryClosure(authenticationRecoveryClosureFixture())
	if err != nil {
		t.Fatal(err)
	}
	variants := map[string]string{
		"open":       strings.Replace(string(canonical), `"state":"CLOSED"`, `"state":"OPEN"`, 1),
		"unknown":    strings.Replace(string(canonical), `"epoch":7`, `"extra":true,"epoch":7`, 1),
		"duplicate":  strings.Replace(string(canonical), `"epoch":7`, `"epoch":7,"epoch":7`, 1),
		"null":       strings.Replace(string(canonical), `"state":"CLOSED"`, `"state":null`, 1),
		"whitespace": " " + string(canonical),
		"newline":    string(canonical) + "\n",
		"reordered": strings.Replace(
			string(canonical),
			`"apiVersion":"installation.matrix.xiak.com/v1","kind":"IAMAuthenticationRecoveryClosure"`,
			`"kind":"IAMAuthenticationRecoveryClosure","apiVersion":"installation.matrix.xiak.com/v1"`, 1,
		),
		"trailing": string(canonical) + `{}`,
	}
	for name, input := range variants {
		t.Run(name, func(t *testing.T) {
			value, err := DecodeAuthenticationRecoveryClosure(strings.NewReader(input))
			if !errors.Is(err, ErrInvalidAuthenticationRecoveryClosure) || value != (AuthenticationRecoveryClosure{}) {
				t.Fatalf("decode ambiguous closure = %#v / %v", value, err)
			}
		})
	}
	value, err := DecodeAuthenticationRecoveryClosure(strings.NewReader(strings.Repeat("x", int(MaximumAuthenticationRecoveryBytes)+1)))
	if !errors.Is(err, ErrInvalidAuthenticationRecoveryClosure) || value != (AuthenticationRecoveryClosure{}) {
		t.Fatalf("decode oversized closure = %#v / %v", value, err)
	}
	if value, err = DecodeAuthenticationRecoveryClosure(nil); !errors.Is(err, ErrInvalidAuthenticationRecoveryClosure) || value != (AuthenticationRecoveryClosure{}) {
		t.Fatalf("decode nil closure = %#v / %v", value, err)
	}
}

func TestAuthenticationRecoveryClosureRejectsChangedIdentityOrEvidence(t *testing.T) {
	for name, change := range map[string]func(*AuthenticationRecoveryClosure){
		"version":      func(v *AuthenticationRecoveryClosure) { v.APIVersion = "installation.matrix.xiak.com/v2" },
		"kind":         func(v *AuthenticationRecoveryClosure) { v.Kind = "AuthenticationRecoveryState" },
		"purpose":      func(v *AuthenticationRecoveryClosure) { v.Purpose = "IAM_TOTP_SEED_WRAPPING" },
		"installation": func(v *AuthenticationRecoveryClosure) { v.InstallationID = "mxi-other" },
		"zero epoch":   func(v *AuthenticationRecoveryClosure) { v.Epoch = 0 },
		"large epoch":  func(v *AuthenticationRecoveryClosure) { v.Epoch = uint64(math.MaxInt64) + 1 },
		"state":        func(v *AuthenticationRecoveryClosure) { v.State = "OPEN" },
		"command":      func(v *AuthenticationRecoveryClosure) { v.CommandID = "cmd-other" },
		"backup":       func(v *AuthenticationRecoveryClosure) { v.BackupID = "backup-other" },
		"backup digest": func(v *AuthenticationRecoveryClosure) {
			v.BackupDigest = "sha256:" + strings.Repeat("A", 64)
		},
		"intent digest": func(v *AuthenticationRecoveryClosure) {
			v.RecoveryIntentDigest = "sha256:" + strings.Repeat("b", 63)
		},
		"custody digest": func(v *AuthenticationRecoveryClosure) {
			v.TOTPCustodyDigest = "sha256:" + strings.Repeat("g", 64)
		},
	} {
		t.Run(name, func(t *testing.T) {
			value := authenticationRecoveryClosureFixture()
			change(&value)
			if err := ValidateAuthenticationRecoveryClosure(value); !errors.Is(err, ErrInvalidAuthenticationRecoveryClosure) {
				t.Fatalf("validate changed closure = %v", err)
			}
			if encoded, err := EncodeAuthenticationRecoveryClosure(value); !errors.Is(err, ErrInvalidAuthenticationRecoveryClosure) || len(encoded) != 0 {
				t.Fatalf("encode changed closure = %q / %v", encoded, err)
			}
		})
	}
}

func FuzzAuthenticationRecoveryClosureCanonicalBytes(f *testing.F) {
	seed, err := EncodeAuthenticationRecoveryClosure(authenticationRecoveryClosureFixture())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Fuzz(func(t *testing.T, source []byte) {
		value, err := DecodeAuthenticationRecoveryClosure(bytes.NewReader(source))
		if err != nil {
			if value != (AuthenticationRecoveryClosure{}) {
				t.Fatal("invalid closure returned data")
			}
			return
		}
		canonical, err := EncodeAuthenticationRecoveryClosure(value)
		if err != nil || !bytes.Equal(source, canonical) {
			t.Fatal("accepted closure was not canonical")
		}
	})
}

func authenticationRecoveryClosureFixture() AuthenticationRecoveryClosure {
	return AuthenticationRecoveryClosure{
		APIVersion: AuthenticationRecoveryAPIVersion, Kind: AuthenticationRecoveryClosureKind,
		Purpose:        AuthenticationRecoveryPurpose,
		InstallationID: "mxi-0123456789abcdef0123456789abcdef", Epoch: 7,
		State:                AuthenticationRecoveryStateClosed,
		CommandID:            "cmd-0123456789abcdef0123456789abcdef",
		BackupID:             "backup-fedcba9876543210fedcba9876543210",
		BackupDigest:         "sha256:" + strings.Repeat("a", 64),
		RecoveryIntentDigest: "sha256:" + strings.Repeat("b", 64),
		TOTPCustodyDigest:    "sha256:" + strings.Repeat("c", 64),
	}
}
