package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	installationv1 "github.com/xiak/matrix/api/adapter/installation/v1"
	"github.com/xiak/matrix/app/service/iam/internal/usecase/authenticationrecovery"
)

func TestAuthenticationRecoveryProcessHasOnlyFixedModesAndStableFailures(t *testing.T) {
	for _, arguments := range [][]string{
		nil,
		{"recover"},
		{"close", "other"},
		{"reconcile", "--tenant", "other"},
		{"--help"},
		{"--database-dsn", "secret"},
	} {
		var output bytes.Buffer
		err := run(context.Background(), arguments, &output, func(string) string {
			t.Fatal("invalid invocation read private configuration")
			return ""
		})
		if !errors.Is(err, authenticationrecovery.ErrInvalidArgument) || output.Len() != 0 {
			t.Fatalf("invalid mode result: %v", err)
		}
	}

	for _, candidate := range []struct {
		err  error
		code int
		text string
	}{
		{authenticationrecovery.ErrInvalidArgument, installationv1.AuthenticationRecoveryExitInvalid, installationv1.AuthenticationRecoveryErrorInvalid},
		{authenticationrecovery.ErrForbidden, installationv1.AuthenticationRecoveryExitForbidden, installationv1.AuthenticationRecoveryErrorForbidden},
		{authenticationrecovery.ErrConflict, installationv1.AuthenticationRecoveryExitConflict, installationv1.AuthenticationRecoveryErrorConflict},
		{authenticationrecovery.ErrUnavailable, installationv1.AuthenticationRecoveryExitUnavailable, installationv1.AuthenticationRecoveryErrorUnavailable},
		{errors.New("native sensitive material"), installationv1.AuthenticationRecoveryExitUnavailable, installationv1.AuthenticationRecoveryErrorUnavailable},
		{context.DeadlineExceeded, installationv1.AuthenticationRecoveryExitUnavailable, installationv1.AuthenticationRecoveryErrorUnavailable},
	} {
		if exitCode(candidate.err) != candidate.code || errorCode(candidate.err) != candidate.text {
			t.Fatal("unstable authentication recovery error classification")
		}
	}
	if exitCode(nil) != installationv1.AuthenticationRecoveryExitSuccess {
		t.Fatal("success exit code is nonzero")
	}
}

func TestAuthenticationRecoveryRejectsAmbiguousProtectedInputBeforeDatabaseAccess(t *testing.T) {
	intent := installationv1.AuthenticationRecoveryIntent{
		APIVersion:          installationv1.AuthenticationRecoveryAPIVersion,
		Kind:                installationv1.AuthenticationRecoveryIntentKind,
		Purpose:             installationv1.AuthenticationRecoveryPurpose,
		InstallationID:      "mxi-0123456789abcdef0123456789abcdef",
		Epoch:               7,
		CommandID:           "cmd-0123456789abcdef0123456789abcdef",
		BackupID:            "backup-fedcba9876543210fedcba9876543210",
		BackupDigest:        "sha256:" + strings.Repeat("a", 64),
		SourceReleaseID:     "matrix-v1.2.3-a1b2c3d4e5f6",
		SourceReleaseDigest: "sha256:" + strings.Repeat("b", 64),
		TargetReleaseID:     "matrix-v1.2.3-0f1e2d3c4b5a",
		TargetReleaseDigest: "sha256:" + strings.Repeat("c", 64),
		TOTPCustodyDigest:   "sha256:" + strings.Repeat("d", 64),
	}
	encoded, err := installationv1.EncodeAuthenticationRecoveryIntent(intent)
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, '\n')
	path := filepath.Join(t.TempDir(), "intent.json")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	clear(encoded)

	var output bytes.Buffer
	err = run(context.Background(), []string{installationv1.AuthenticationRecoveryCloseCommand}, &output, func(name string) string {
		switch name {
		case installationv1.AuthenticationRecoveryIntentFileEnvironment:
			return path
		case installationv1.AuthenticationRecoveryClosureFileEnvironment, installationv1.AuthenticationRecoverySecuritySnapshotFileEnvironment:
			return ""
		default:
			t.Fatal("ambiguous protected input reached database configuration")
			return ""
		}
	})
	if !errors.Is(err, authenticationrecovery.ErrInvalidArgument) || output.Len() != 0 {
		t.Fatalf("ambiguous protected input result: %v", err)
	}
}

func TestAuthenticationRecoveryRejectsConflictingProtectedFiles(t *testing.T) {
	for _, mode := range []string{
		installationv1.AuthenticationRecoveryCloseCommand,
		installationv1.AuthenticationRecoveryReconcileCommand,
		installationv1.AuthenticationRecoveryReopenCommand,
	} {
		var output bytes.Buffer
		err := run(context.Background(), []string{mode}, &output, func(name string) string {
			switch name {
			case installationv1.AuthenticationRecoveryIntentFileEnvironment,
				installationv1.AuthenticationRecoveryClosureFileEnvironment, installationv1.AuthenticationRecoverySecuritySnapshotFileEnvironment:
				return "both-present"
			default:
				t.Fatal("conflicting protected files reached database configuration")
				return ""
			}
		})
		if !errors.Is(err, authenticationrecovery.ErrInvalidArgument) || output.Len() != 0 {
			t.Fatalf("conflicting files for %s: %v", mode, err)
		}
	}
}

func TestAuthenticationRecoveryRequiresMatchingSnapshotFileBeforeDatabaseAccess(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	closedAt := time.Date(2026, 9, 25, 4, 5, 6, 0, time.UTC)
	snapshot := installationv1.AuthenticationRecoverySecuritySnapshot{
		APIVersion: installationv1.AuthenticationRecoveryAPIVersion, Kind: installationv1.AuthenticationRecoverySecuritySnapshotKind,
		Purpose: installationv1.AuthenticationRecoveryPurpose, InstallationID: "mxi-0123456789abcdef0123456789abcdef",
		BootstrapDigest: digest, Epoch: 1, CommandID: "cmd-0123456789abcdef0123456789abcdef",
		RecoveryIntentDigest: digest, ClosedAt: closedAt, AuthenticationStateDigest: digest,
		Accounts: []installationv1.AuthenticationRecoveryAccountReplay{{AccountID: "account", Users: []installationv1.AuthenticationRecoveryUserReplay{{UserID: "root", LastConsumedStep: -1}}}},
	}
	snapshotDigest, err := installationv1.AuthenticationRecoverySecuritySnapshotDigest(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	closure := installationv1.AuthenticationRecoveryClosure{
		APIVersion: installationv1.AuthenticationRecoveryAPIVersion, Kind: installationv1.AuthenticationRecoveryClosureKind,
		Purpose: installationv1.AuthenticationRecoveryPurpose, InstallationID: snapshot.InstallationID, Epoch: snapshot.Epoch,
		State: installationv1.AuthenticationRecoveryStateClosed, CommandID: snapshot.CommandID,
		BackupID: "backup-0123456789abcdef0123456789abcdef", BackupDigest: digest,
		RecoveryIntentDigest: digest, TOTPCustodyDigest: digest, ClosedAt: closedAt, SecuritySnapshotDigest: snapshotDigest,
	}
	closureBytes, err := installationv1.EncodeAuthenticationRecoveryClosure(closure)
	if err != nil {
		t.Fatal(err)
	}
	snapshotBytes, err := installationv1.EncodeAuthenticationRecoverySecuritySnapshot(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{installationv1.AuthenticationRecoveryReconcileCommand, installationv1.AuthenticationRecoveryReopenCommand} {
		for _, attack := range []string{"valid", "missing-path", "missing-file", "oversized", "truncated", "noncanonical", "unbound"} {
			t.Run(mode+"/"+attack, func(t *testing.T) {
				directory := t.TempDir()
				closurePath, snapshotPath := filepath.Join(directory, "closure.json"), filepath.Join(directory, "snapshot.json")
				if err := os.WriteFile(closurePath, closureBytes, 0o600); err != nil {
					t.Fatal(err)
				}
				candidate := append([]byte(nil), snapshotBytes...)
				switch attack {
				case "missing-path":
					snapshotPath = ""
				case "oversized":
					candidate = bytes.Repeat([]byte(" "), int(installationv1.MaximumAuthenticationRecoverySecuritySnapshotBytes)+1)
				case "truncated":
					candidate = candidate[:len(candidate)-1]
				case "noncanonical":
					candidate = append(candidate, '\n')
				case "unbound":
					candidate = bytes.ReplaceAll(candidate, []byte(`"userId":"root"`), []byte(`"userId":"other"`))
				}
				if attack != "missing-file" && snapshotPath != "" {
					if err := os.WriteFile(snapshotPath, candidate, 0o600); err != nil {
						t.Fatal(err)
					}
				}
				var output bytes.Buffer
				reachedDatabaseConfig := false
				err := run(t.Context(), []string{mode}, &output, func(name string) string {
					switch name {
					case installationv1.AuthenticationRecoveryIntentFileEnvironment:
						return ""
					case installationv1.AuthenticationRecoveryClosureFileEnvironment:
						return closurePath
					case installationv1.AuthenticationRecoverySecuritySnapshotFileEnvironment:
						return snapshotPath
					case installationv1.AuthenticationRecoveryDatabaseDSNFileEnvironment:
						reachedDatabaseConfig = true
						return "" // Positive FILE control; never open a real database.
					default:
						t.Fatal("invalid recovery snapshot reached database configuration")
						return ""
					}
				})
				if !errors.Is(err, authenticationrecovery.ErrInvalidArgument) || output.Len() != 0 {
					t.Fatalf("snapshot rejection differs: %v", err)
				}
				if reachedDatabaseConfig != (attack == "valid") {
					t.Fatal("protected FILE validation did not isolate invalid snapshots before database configuration")
				}
			})
		}
	}
}
