package localmachine

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	installationv1 "github.com/xiak/matrix/api/adapter/installation/v1"
	"github.com/xiak/matrix/app/service/installation/internal/layout"
	"github.com/xiak/matrix/app/service/installation/internal/platformcommand"
	"github.com/xiak/matrix/app/service/installation/release"
)

func TestBackupCustodyLeaseOutputCannotBlockAtItsMaximum(t *testing.T) {
	output := newBoundedLeaseOutput()
	maximum := int(installationv1.MaximumTOTPBackupCustodyBytes) + 1
	if written, err := output.Write(bytes.Repeat([]byte{'x'}, maximum)); err != nil || written != maximum {
		t.Fatalf("fill bounded output: written=%d err=%v", written, err)
	}
	select {
	case <-output.ready:
	default:
		t.Fatal("bounded output did not wake a consumer after exhausting its frame")
	}
	content, exceeded := output.snapshot()
	if len(content) != maximum || !exceeded {
		t.Fatal("unterminated maximum frame was not rejected")
	}
}

func TestTOTPBackupCustodyProcessUsesOneBoundedLeaseAndExactRelease(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("local-machine backup custody process targets Linux")
	}
	plan, expectation := configuredPlatformStartFixture(t)
	installation, err := verifiedInstallationConfiguration(plan)
	if err != nil {
		t.Fatal(err)
	}
	runtimeBoundary := newPlatformStartRuntime(plan, expectation)
	runtimeBoundary.started = true
	process, lease, err := startTOTPBackupCustody(
		t.Context(), runtimeBoundary, runtimeBoundary, plan, installation,
		"backup-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	)
	if err != nil || process == nil ||
		installationv1.ValidateTOTPBackupSnapshotLease(lease) != nil {
		t.Fatalf("start custody process: %#v / %v", lease, err)
	}
	if err := process.release(); err != nil {
		t.Fatalf("release custody process: %v", err)
	}
	if runtimeBoundary.backupCustodyRuns != 1 || runtimeBoundary.backupCustodyReleases != 1 {
		t.Fatalf("custody process runs=%d releases=%d", runtimeBoundary.backupCustodyRuns, runtimeBoundary.backupCustodyReleases)
	}
}

func TestBackupCustodyFailureRemovesUnpublishedPartialArtifacts(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("local-machine backup custody process targets Linux")
	}
	for index, mode := range []string{"invalid", "premature", "release-failure", "dump-failure"} {
		t.Run(mode, func(t *testing.T) {
			plan, expectation := configuredPlatformStartFixture(t)
			runtimeBoundary := newPlatformStartRuntime(plan, expectation)
			runtimeBoundary.started = true
			runtimeBoundary.backupCustodyMode = mode
			effects := &Effects{runtime: runtimeBoundary, entropy: rand.Reader}
			backupID := "backup-" + strings.Repeat(string(rune('a'+index)), 32)
			err := effects.CreateBackup(t.Context(), platformcommand.BackupPlan{
				InstalledPlan: installedPlanFrom(plan), BackupID: backupID,
				CreatedAt: time.Date(2026, 9, 20, 8, index, 0, 0, time.UTC),
			})
			if err == nil {
				t.Fatal("broken custody lifecycle published a backup")
			}
			for _, name := range []string{backupID, "." + backupID + ".partial"} {
				_, statErr := os.Lstat(filepath.Join(plan.Root, filepath.FromSlash(layout.BackupDirectory), name))
				if !errors.Is(statErr, os.ErrNotExist) {
					t.Fatalf("broken custody lifecycle retained %s: %v", name, statErr)
				}
			}
			if mode == "dump-failure" {
				if runtimeBoundary.backupStreams != 1 || runtimeBoundary.backupCustodyRuns != 1 ||
					runtimeBoundary.backupCustodyAborts != 1 || runtimeBoundary.backupCustodyReleases != 0 {
					t.Fatal("interrupted dump did not abort its exact held snapshot")
				}
				runtimeBoundary.backupCustodyMode = ""
				if err := effects.CreateBackup(t.Context(), platformcommand.BackupPlan{
					InstalledPlan: installedPlanFrom(plan), BackupID: backupID,
					CreatedAt: time.Date(2026, 9, 20, 8, index, 0, 0, time.UTC),
				}); err != nil {
					t.Fatalf("resume fixed backup after interrupted dump: %v", err)
				}
				if runtimeBoundary.backupStreams != 2 || runtimeBoundary.backupCustodyRuns != 2 ||
					runtimeBoundary.backupCustodyAborts != 1 || runtimeBoundary.backupCustodyReleases != 1 {
					t.Fatal("backup retry reused a failed snapshot or omitted its release")
				}
				if _, err := effects.InspectBackup(t.Context(), installedPlanFrom(plan), backupID); err != nil {
					t.Fatalf("resumed backup is not authenticated: %v", err)
				}
			}
		})
	}
}

func TestPublishedAccessKeyBackupVersionRemainsDecodableWithoutTOTPClaim(t *testing.T) {
	manifest := backupManifest{
		APIVersion: accessKeyBackupAPIVersion,
		Kind:       backupKind,
		Database:   release.CurrentDatabaseProfile(),
		AccessKeyWrapping: &backupAccessKeyWrapping{
			WrappingKeyID: "access-wrapping-v1",
			Commitment:    "sha256:" + strings.Repeat("a", 64),
		},
	}
	if profile, err := manifest.databaseProfile(); err != nil || profile != release.CurrentDatabaseProfile() {
		t.Fatalf("decode published access-key backup profile: %#v / %v", profile, err)
	}
	if _, err := sealBackupManifest(manifest, make([]byte, sha256.Size)); err != nil {
		t.Fatalf("seal published access-key backup shape: %v", err)
	}
	manifest.TOTPBackupCustody = &backupTOTPBackupCustody{}
	if _, err := manifest.databaseProfile(); err == nil {
		t.Fatal("published access-key backup version accepted a retroactive TOTP field")
	}
}

func TestAuthenticationStateBackupVersionCannotRetrofitHistoricalManifests(t *testing.T) {
	custody := installationv1.TOTPBackupCustody{
		APIVersion:      installationv1.TOTPBackupCustodyAPIVersion,
		Kind:            installationv1.TOTPBackupCustodyKind,
		Purpose:         installationv1.TOTPBackupCustodyPurpose,
		InstallationID:  "mxi-0123456789abcdef0123456789abcdef",
		BootstrapDigest: "sha256:" + strings.Repeat("a", 64),
		KeysetRevision:  1,
		RequiredKeys:    []installationv1.TOTPBackupRequiredKey{},
	}
	custodyDigest, err := installationv1.TOTPBackupCustodyDigest(custody)
	if err != nil {
		t.Fatal(err)
	}
	manifest := backupManifest{
		APIVersion: authenticationStateBackupAPIVersion,
		Kind:       backupKind,
		Database:   release.CurrentDatabaseProfile(),
		AccessKeyWrapping: &backupAccessKeyWrapping{
			WrappingKeyID: "access-wrapping-v1",
			Commitment:    "sha256:" + strings.Repeat("b", 64),
		},
		TOTPBackupCustody:         &backupTOTPBackupCustody{Custody: custody, CustodyDigest: custodyDigest},
		AuthenticationStateDigest: "sha256:" + strings.Repeat("c", 64),
	}
	if profile, err := manifest.databaseProfile(); err != nil || profile != release.CurrentDatabaseProfile() {
		t.Fatalf("v5 authentication state backup profile = %#v / %v", profile, err)
	}
	key := make([]byte, sha256.Size)
	v5, err := sealBackupManifest(manifest, key)
	if err != nil || !bytes.Contains(v5, []byte(`"authenticationStateDigest"`)) {
		t.Fatalf("v5 authentication state commitment was not sealed: %v", err)
	}
	for name, change := range map[string]func(*backupManifest){
		"missing v5 commitment":     func(value *backupManifest) { value.AuthenticationStateDigest = "" },
		"malformed v5 commitment":   func(value *backupManifest) { value.AuthenticationStateDigest = "sha256:short" },
		"retroactive v4 commitment": func(value *backupManifest) { value.APIVersion = backupAPIVersion },
	} {
		t.Run(name, func(t *testing.T) {
			changed := manifest
			change(&changed)
			if _, err := changed.databaseProfile(); err == nil {
				t.Fatal("ambiguous authentication state commitment was accepted")
			}
			if _, err := sealBackupManifest(changed, key); err == nil {
				t.Fatal("ambiguous authentication state commitment was sealed")
			}
		})
	}
	manifest.APIVersion = backupAPIVersion
	manifest.AuthenticationStateDigest = ""
	v4, err := sealBackupManifest(manifest, key)
	if err != nil || bytes.Contains(v4, []byte(`"authenticationStateDigest"`)) {
		t.Fatalf("historical v4 bytes acquired a new field: %v", err)
	}
}

func TestAutomaticAuthenticationRestoreRequiresTheCurrentBackupProof(t *testing.T) {
	v4 := backupManifest{APIVersion: backupAPIVersion}
	v5 := backupManifest{
		APIVersion:                authenticationStateBackupAPIVersion,
		AuthenticationStateDigest: "sha256:" + strings.Repeat("a", 64),
	}
	if err := requireAuthenticationStateBackupForRecovery(backupAPIVersion, v4); err != nil {
		t.Fatalf("historical v4 release rejected its own backup: %v", err)
	}
	if err := requireAuthenticationStateBackupForRecovery(authenticationStateBackupAPIVersion, v4); !errors.Is(err, platformcommand.ErrEffectPrecondition) {
		t.Fatalf("v5 release accepted a v4 identity backup: %v", err)
	}
	if err := requireAuthenticationStateBackupForRecovery(authenticationStateBackupAPIVersion, v5); err != nil {
		t.Fatalf("v5 release rejected its committed backup: %v", err)
	}
	v5.AuthenticationStateDigest = ""
	if err := requireAuthenticationStateBackupForRecovery(authenticationStateBackupAPIVersion, v5); !errors.Is(err, platformcommand.ErrEffectPrecondition) {
		t.Fatalf("v5 release accepted a missing state proof: %v", err)
	}
	if err := requireAuthenticationStateBackupForRecovery("installation.matrix.xiak.com/unknown", v4); !errors.Is(err, platformcommand.ErrEffectVerification) {
		t.Fatalf("unknown current backup version was admitted: %v", err)
	}
}

func TestTOTPBackupCustodyProcessFailsClosedOnProtocolAndLifecycleDrift(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("local-machine backup custody process targets Linux")
	}
	plan, expectation := configuredPlatformStartFixture(t)
	installation, err := verifiedInstallationConfiguration(plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"invalid", "extra", "premature", "release-failure", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			runtimeBoundary := newPlatformStartRuntime(plan, expectation)
			runtimeBoundary.started = true
			runtimeBoundary.backupCustodyMode = mode
			ctx := t.Context()
			if mode == "timeout" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 25*time.Millisecond)
				defer cancel()
			}
			process, _, startErr := startTOTPBackupCustody(
				ctx, runtimeBoundary, runtimeBoundary, plan, installation,
				"backup-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			)
			if startErr == nil && process != nil {
				startErr = process.release()
			}
			if startErr == nil ||
				(!errors.Is(startErr, platformcommand.ErrEffectVerification) &&
					!errors.Is(startErr, platformcommand.ErrEffectUnavailable)) {
				t.Fatalf("protocol mode %q did not fail closed: %v", mode, startErr)
			}
		})
	}
}

func TestBackupTOTPKeyringMustRemainASupersetOfSealedCustody(t *testing.T) {
	plan := newInstallPlan(t)
	if err := stageInstallation(plan, rand.Reader); err != nil {
		t.Fatal(err)
	}
	lease, err := platformTestTOTPBackupLease(plan)
	if err != nil {
		t.Fatal(err)
	}
	value := backupManifest{APIVersion: backupAPIVersion, TOTPBackupCustody: &backupTOTPBackupCustody{
		Custody: lease.Custody, CustodyDigest: lease.CustodyDigest,
	}}
	if err := verifyBackupTOTPBackupCustody(plan.Root, plan.InstallationID, value); err != nil {
		t.Fatalf("verify exact custody: %v", err)
	}
	v5 := value
	v5.APIVersion = authenticationStateBackupAPIVersion
	v5.AuthenticationStateDigest = "sha256:" + strings.Repeat("c", 64)
	if err := verifyBackupTOTPBackupCustody(plan.Root, plan.InstallationID, v5); err != nil {
		t.Fatalf("verify v5 custody from the same installation: %v", err)
	}

	changed := value
	changed.TOTPBackupCustody = &backupTOTPBackupCustody{
		Custody: value.TOTPBackupCustody.Custody,
	}
	changed.TOTPBackupCustody.Custody.RequiredKeys = append(
		[]installationv1.TOTPBackupRequiredKey(nil),
		value.TOTPBackupCustody.Custody.RequiredKeys...,
	)
	changed.TOTPBackupCustody.Custody.RequiredKeys[0].Commitment = "sha256:" + strings.Repeat("f", 64)
	changed.TOTPBackupCustody.CustodyDigest, err = installationv1.TOTPBackupCustodyDigest(changed.TOTPBackupCustody.Custody)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyBackupTOTPBackupCustody(plan.Root, plan.InstallationID, changed); err == nil {
		t.Fatal("changed required wrapping key commitment was accepted")
	}

	changed = value
	changed.TOTPBackupCustody = &backupTOTPBackupCustody{Custody: value.TOTPBackupCustody.Custody}
	changed.TOTPBackupCustody.Custody.KeysetRevision++
	changed.TOTPBackupCustody.CustodyDigest, err = installationv1.TOTPBackupCustodyDigest(changed.TOTPBackupCustody.Custody)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyBackupTOTPBackupCustody(plan.Root, plan.InstallationID, changed); err == nil {
		t.Fatal("custody from a future keyset revision was accepted")
	}
}
