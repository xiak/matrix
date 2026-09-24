package installationv1

import (
	"bytes"
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestAuthenticationRecoveryProcessBoundaryIsClosed(t *testing.T) {
	commands := map[string]bool{
		AuthenticationRecoveryCloseCommand:     true,
		AuthenticationRecoveryReconcileCommand: true,
		AuthenticationRecoveryReopenCommand:    true,
	}
	if len(commands) != 3 || !commands["close"] || !commands["reconcile"] || !commands["reopen"] {
		t.Fatal("authentication recovery commands are ambiguous")
	}
	environments := map[string]bool{
		AuthenticationRecoveryDatabaseDSNFileEnvironment:  true,
		AuthenticationRecoveryMigrationDSNFileEnvironment: true,
		AuthenticationRecoveryIntentFileEnvironment:       true,
		AuthenticationRecoveryClosureFileEnvironment:      true,
	}
	if len(environments) != 4 ||
		!environments["MATRIX_IAM_AUTHENTICATION_RECOVERY_DATABASE_DSN_FILE"] ||
		!environments["MATRIX_MIGRATION_IAM_AUTHENTICATION_RECOVERY_DSN_FILE"] ||
		!environments["MATRIX_IAM_AUTHENTICATION_RECOVERY_INTENT_FILE"] ||
		!environments["MATRIX_IAM_AUTHENTICATION_RECOVERY_CLOSURE_FILE"] {
		t.Fatal("authentication recovery file environments are ambiguous")
	}
	if AuthenticationRecoveryExitSuccess != 0 || AuthenticationRecoveryExitInvalid != 2 ||
		AuthenticationRecoveryExitForbidden != 3 || AuthenticationRecoveryExitConflict != 4 ||
		AuthenticationRecoveryExitUnavailable != 6 ||
		AuthenticationRecoveryErrorInvalid != "IAM_AUTHENTICATION_RECOVERY_INVALID" ||
		AuthenticationRecoveryErrorForbidden != "IAM_AUTHENTICATION_RECOVERY_FORBIDDEN" ||
		AuthenticationRecoveryErrorConflict != "IAM_AUTHENTICATION_RECOVERY_CONFLICT" ||
		AuthenticationRecoveryErrorUnavailable != "IAM_AUTHENTICATION_RECOVERY_UNAVAILABLE" {
		t.Fatal("authentication recovery exit protocol is ambiguous")
	}
}

func TestAuthenticationRecoveryClosureHasOneCanonicalClosedForm(t *testing.T) {
	value := authenticationRecoveryClosureFixture()
	want := `{"apiVersion":"installation.matrix.xiak.com/v1","kind":"IAMAuthenticationRecoveryClosure","purpose":"IAM_AUTHENTICATION_BACKUP_RECOVERY","installationId":"mxi-0123456789abcdef0123456789abcdef","epoch":7,"state":"CLOSED","commandId":"cmd-0123456789abcdef0123456789abcdef","backupId":"backup-fedcba9876543210fedcba9876543210","backupDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","recoveryIntentDigest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","totpCustodyDigest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","closedAt":"2026-09-21T02:03:04.000005Z"}`

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
		"zero close time": func(v *AuthenticationRecoveryClosure) { v.ClosedAt = time.Time{} },
		"local close time": func(v *AuthenticationRecoveryClosure) {
			v.ClosedAt = v.ClosedAt.In(time.FixedZone("local", 8*60*60))
		},
		"nanosecond close time": func(v *AuthenticationRecoveryClosure) {
			v.ClosedAt = v.ClosedAt.Add(time.Nanosecond)
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

func TestAuthenticationRecoveryCompletionBindsOneClosure(t *testing.T) {
	closure := authenticationRecoveryClosureFixture()
	digest, err := AuthenticationRecoveryClosureDigest(closure)
	if err != nil {
		t.Fatal(err)
	}
	const wantDigest = "sha256:6eb93f0d126a956481b488dfd0e3c78568c9ad99f796ba70fb9b1558d2735c48"
	if digest != wantDigest {
		t.Fatalf("closure digest = %q, want %q", digest, wantDigest)
	}
	completion := authenticationRecoveryCompletionFixture()
	completion.ClosureDigest = digest
	if err := ValidateAuthenticationRecoveryCompletionForClosure(completion, closure); err != nil {
		t.Fatalf("bind completion to closure: %v", err)
	}
	encoded, err := EncodeAuthenticationRecoveryCompletion(completion)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeAuthenticationRecoveryCompletion(bytes.NewReader(encoded))
	if err != nil || !reflect.DeepEqual(decoded, completion) {
		t.Fatalf("decode completion = %#v / %v", decoded, err)
	}

	for name, change := range map[string]func(*AuthenticationRecoveryCompletion){
		"version":      func(v *AuthenticationRecoveryCompletion) { v.APIVersion = "installation.matrix.xiak.com/v2" },
		"kind":         func(v *AuthenticationRecoveryCompletion) { v.Kind = "AuthenticationRecoveryResult" },
		"purpose":      func(v *AuthenticationRecoveryCompletion) { v.Purpose = "IAM_TOTP_SEED_WRAPPING" },
		"installation": func(v *AuthenticationRecoveryCompletion) { v.InstallationID = "mxi-other" },
		"epoch":        func(v *AuthenticationRecoveryCompletion) { v.Epoch++ },
		"state":        func(v *AuthenticationRecoveryCompletion) { v.State = "OPEN" },
		"command":      func(v *AuthenticationRecoveryCompletion) { v.CommandID = "cmd-other" },
		"digest":       func(v *AuthenticationRecoveryCompletion) { v.ClosureDigest = "sha256:" + strings.Repeat("d", 64) },
		"before close": func(v *AuthenticationRecoveryCompletion) { v.CompletedAt = closure.ClosedAt.Add(-time.Microsecond) },
		"equal close":  func(v *AuthenticationRecoveryCompletion) { v.CompletedAt = closure.ClosedAt },
		"local time": func(v *AuthenticationRecoveryCompletion) {
			v.CompletedAt = v.CompletedAt.In(time.FixedZone("local", 8*60*60))
		},
		"nanosecond": func(v *AuthenticationRecoveryCompletion) { v.CompletedAt = v.CompletedAt.Add(time.Nanosecond) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := completion
			change(&changed)
			if err := ValidateAuthenticationRecoveryCompletionForClosure(changed, closure); !errors.Is(err, ErrInvalidAuthenticationRecoveryCompletion) {
				t.Fatalf("changed completion admitted: %v", err)
			}
		})
	}
}

func TestAuthenticationRecoveryCompletionRejectsAmbiguousInput(t *testing.T) {
	closure := authenticationRecoveryClosureFixture()
	digest, err := AuthenticationRecoveryClosureDigest(closure)
	if err != nil {
		t.Fatal(err)
	}
	completion := authenticationRecoveryCompletionFixture()
	completion.ClosureDigest = digest
	canonical, err := EncodeAuthenticationRecoveryCompletion(completion)
	if err != nil {
		t.Fatal(err)
	}
	variants := []string{
		" " + string(canonical),
		string(canonical) + "\n",
		strings.Replace(string(canonical), `"epoch":7`, `"epoch":7,"epoch":7`, 1),
		strings.Replace(string(canonical), `"state":"REOPENED"`, `"state":"REOPENED","extra":true`, 1),
	}
	for _, input := range variants {
		value, err := DecodeAuthenticationRecoveryCompletion(strings.NewReader(input))
		if !errors.Is(err, ErrInvalidAuthenticationRecoveryCompletion) || value != (AuthenticationRecoveryCompletion{}) {
			t.Fatalf("decode ambiguous completion = %#v / %v", value, err)
		}
	}
}

func TestAuthenticationRecoveryIntentDigestBindsExactAuthenticatedTuple(t *testing.T) {
	intent := authenticationRecoveryIntentFixture()
	wantBytes := `{"apiVersion":"installation.matrix.xiak.com/v1","kind":"IAMAuthenticationRecoveryIntent","purpose":"IAM_AUTHENTICATION_BACKUP_RECOVERY","installationId":"mxi-0123456789abcdef0123456789abcdef","epoch":7,"commandId":"cmd-0123456789abcdef0123456789abcdef","backupId":"backup-fedcba9876543210fedcba9876543210","backupDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sourceReleaseId":"matrix-v1.2.3-a1b2c3d4e5f6","sourceReleaseDigest":"sha256:2222222222222222222222222222222222222222222222222222222222222222","targetReleaseId":"matrix-v1.2.3-0f1e2d3c4b5a","targetReleaseDigest":"sha256:3333333333333333333333333333333333333333333333333333333333333333","totpCustodyDigest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}`
	encoded, err := EncodeAuthenticationRecoveryIntent(intent)
	if err != nil || string(encoded) != wantBytes {
		t.Fatalf("encode recovery intent = %q / %v", encoded, err)
	}
	decoded, err := DecodeAuthenticationRecoveryIntent(bytes.NewReader(encoded))
	if err != nil || !reflect.DeepEqual(decoded, intent) {
		t.Fatalf("decode recovery intent = %#v / %v", decoded, err)
	}
	digest, err := AuthenticationRecoveryIntentDigest(intent)
	if err != nil {
		t.Fatal(err)
	}
	const want = "sha256:8545d17c2b3ad05ca4f0523205412be65029d2dce2abcb4f4b93b7cbf7d162ab"
	if digest != want {
		t.Fatalf("recovery intent digest = %q, want %q", digest, want)
	}
	closure := authenticationRecoveryClosureFixture()
	closure.RecoveryIntentDigest = digest
	if err := ValidateAuthenticationRecoveryClosureForIntent(closure, intent); err != nil {
		t.Fatalf("match closure to authenticated intent: %v", err)
	}

	changes := map[string]func(*AuthenticationRecoveryIntent){
		"installation": func(v *AuthenticationRecoveryIntent) { v.InstallationID = "mxi-fedcba9876543210fedcba9876543210" },
		"epoch":        func(v *AuthenticationRecoveryIntent) { v.Epoch++ },
		"command":      func(v *AuthenticationRecoveryIntent) { v.CommandID = "cmd-fedcba9876543210fedcba9876543210" },
		"backup":       func(v *AuthenticationRecoveryIntent) { v.BackupID = "backup-0123456789abcdef0123456789abcdef" },
		"backup digest": func(v *AuthenticationRecoveryIntent) {
			v.BackupDigest = "sha256:" + strings.Repeat("d", 64)
		},
		"source release": func(v *AuthenticationRecoveryIntent) { v.SourceReleaseID = "matrix-v1.2.2-abcdef123456" },
		"source manifest": func(v *AuthenticationRecoveryIntent) {
			v.SourceReleaseDigest = "sha256:" + strings.Repeat("e", 64)
		},
		"target release": func(v *AuthenticationRecoveryIntent) { v.TargetReleaseID = "matrix-v1.2.4-fedcba654321" },
		"target manifest": func(v *AuthenticationRecoveryIntent) {
			v.TargetReleaseDigest = "sha256:" + strings.Repeat("f", 64)
		},
		"custody": func(v *AuthenticationRecoveryIntent) {
			v.TOTPCustodyDigest = "sha256:" + strings.Repeat("1", 64)
		},
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			changed := intent
			change(&changed)
			changedDigest, err := AuthenticationRecoveryIntentDigest(changed)
			if err != nil || changedDigest == digest {
				t.Fatalf("changed intent digest = %q / %v", changedDigest, err)
			}
			if err := ValidateAuthenticationRecoveryClosureForIntent(closure, changed); !errors.Is(err, ErrInvalidAuthenticationRecoveryClosure) {
				t.Fatalf("closure admitted changed intent: %v", err)
			}
		})
	}
}

func TestAuthenticationRecoveryIntentRejectsAmbiguousInput(t *testing.T) {
	canonical, err := EncodeAuthenticationRecoveryIntent(authenticationRecoveryIntentFixture())
	if err != nil {
		t.Fatal(err)
	}
	variants := []string{
		" " + string(canonical),
		string(canonical) + "\n",
		strings.Replace(string(canonical), `"epoch":7`, `"epoch":7,"epoch":7`, 1),
		strings.Replace(string(canonical), `"epoch":7`, `"extra":true,"epoch":7`, 1),
		strings.Replace(string(canonical),
			`"apiVersion":"installation.matrix.xiak.com/v1","kind":"IAMAuthenticationRecoveryIntent"`,
			`"kind":"IAMAuthenticationRecoveryIntent","apiVersion":"installation.matrix.xiak.com/v1"`, 1),
	}
	for _, input := range variants {
		value, err := DecodeAuthenticationRecoveryIntent(strings.NewReader(input))
		if !errors.Is(err, ErrInvalidAuthenticationRecoveryIntent) || value != (AuthenticationRecoveryIntent{}) {
			t.Fatalf("decode ambiguous intent = %#v / %v", value, err)
		}
	}
	value, err := DecodeAuthenticationRecoveryIntent(strings.NewReader(strings.Repeat("x", int(MaximumAuthenticationRecoveryBytes)+1)))
	if !errors.Is(err, ErrInvalidAuthenticationRecoveryIntent) || value != (AuthenticationRecoveryIntent{}) {
		t.Fatalf("decode oversized intent = %#v / %v", value, err)
	}
}

func TestAuthenticationRecoveryIntentRejectsUnauthenticatedShapes(t *testing.T) {
	for name, change := range map[string]func(*AuthenticationRecoveryIntent){
		"version": func(v *AuthenticationRecoveryIntent) { v.APIVersion = "installation.matrix.xiak.com/v2" },
		"kind":    func(v *AuthenticationRecoveryIntent) { v.Kind = "RecoveryIntent" },
		"purpose": func(v *AuthenticationRecoveryIntent) { v.Purpose = "IAM_TOTP_SEED_WRAPPING" },
		"installation": func(v *AuthenticationRecoveryIntent) {
			v.InstallationID = "mxi-other"
		},
		"zero epoch":  func(v *AuthenticationRecoveryIntent) { v.Epoch = 0 },
		"large epoch": func(v *AuthenticationRecoveryIntent) { v.Epoch = uint64(math.MaxInt64) + 1 },
		"command":     func(v *AuthenticationRecoveryIntent) { v.CommandID = "cmd-other" },
		"backup":      func(v *AuthenticationRecoveryIntent) { v.BackupID = "backup-other" },
		"backup digest": func(v *AuthenticationRecoveryIntent) {
			v.BackupDigest = "sha256:" + strings.Repeat("a", 63)
		},
		"source release": func(v *AuthenticationRecoveryIntent) { v.SourceReleaseID = "release-source" },
		"source digest":  func(v *AuthenticationRecoveryIntent) { v.SourceReleaseDigest = "caller-sha" },
		"target release": func(v *AuthenticationRecoveryIntent) { v.TargetReleaseID = "release-target" },
		"target digest":  func(v *AuthenticationRecoveryIntent) { v.TargetReleaseDigest = "caller-sha" },
		"custody":        func(v *AuthenticationRecoveryIntent) { v.TOTPCustodyDigest = "" },
	} {
		t.Run(name, func(t *testing.T) {
			value := authenticationRecoveryIntentFixture()
			change(&value)
			if err := ValidateAuthenticationRecoveryIntent(value); !errors.Is(err, ErrInvalidAuthenticationRecoveryIntent) {
				t.Fatalf("validate changed intent = %v", err)
			}
			if digest, err := AuthenticationRecoveryIntentDigest(value); !errors.Is(err, ErrInvalidAuthenticationRecoveryIntent) || digest != "" {
				t.Fatalf("digest changed intent = %q / %v", digest, err)
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

func FuzzAuthenticationRecoveryIntentCanonicalBytes(f *testing.F) {
	seed, err := EncodeAuthenticationRecoveryIntent(authenticationRecoveryIntentFixture())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Fuzz(func(t *testing.T, source []byte) {
		value, err := DecodeAuthenticationRecoveryIntent(bytes.NewReader(source))
		if err != nil {
			if value != (AuthenticationRecoveryIntent{}) {
				t.Fatal("invalid intent returned data")
			}
			return
		}
		canonical, err := EncodeAuthenticationRecoveryIntent(value)
		if err != nil || !bytes.Equal(source, canonical) {
			t.Fatal("accepted intent was not canonical")
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
		ClosedAt:             time.Date(2026, 9, 21, 2, 3, 4, 5_000, time.UTC),
	}
}

func authenticationRecoveryCompletionFixture() AuthenticationRecoveryCompletion {
	return AuthenticationRecoveryCompletion{
		APIVersion: AuthenticationRecoveryAPIVersion, Kind: AuthenticationRecoveryCompletionKind,
		Purpose:        AuthenticationRecoveryPurpose,
		InstallationID: "mxi-0123456789abcdef0123456789abcdef", Epoch: 7,
		State:         AuthenticationRecoveryStateReopened,
		CommandID:     "cmd-0123456789abcdef0123456789abcdef",
		ClosureDigest: "sha256:" + strings.Repeat("d", 64),
		CompletedAt:   time.Date(2026, 9, 21, 2, 4, 5, 6_000, time.UTC),
	}
}

func authenticationRecoveryIntentFixture() AuthenticationRecoveryIntent {
	return AuthenticationRecoveryIntent{
		APIVersion: AuthenticationRecoveryAPIVersion, Kind: AuthenticationRecoveryIntentKind,
		Purpose:        AuthenticationRecoveryPurpose,
		InstallationID: "mxi-0123456789abcdef0123456789abcdef", Epoch: 7,
		CommandID:       "cmd-0123456789abcdef0123456789abcdef",
		BackupID:        "backup-fedcba9876543210fedcba9876543210",
		BackupDigest:    "sha256:" + strings.Repeat("a", 64),
		SourceReleaseID: "matrix-v1.2.3-a1b2c3d4e5f6", SourceReleaseDigest: "sha256:" + strings.Repeat("2", 64),
		TargetReleaseID: "matrix-v1.2.3-0f1e2d3c4b5a", TargetReleaseDigest: "sha256:" + strings.Repeat("3", 64),
		TOTPCustodyDigest: "sha256:" + strings.Repeat("c", 64),
	}
}
