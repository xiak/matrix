package authorityprocess

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	installationv1 "github.com/xiak/matrix/api/adapter/installation/v1"
	auditv1 "github.com/xiak/matrix/api/audit/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	iammigration "github.com/xiak/matrix/app/service/iam/migration"
)

// This is the existing process owner's non-HTTP, one-shot backup boundary.
// It uses the actual helper, restricted login and PostgreSQL dump/restore tools,
// not a simulated lease or a second process-test framework.
func TestIAMTOTPBackupProcesses(t *testing.T) {
	dsn := os.Getenv("MATRIX_IAM_TOTP_BACKUP_PROCESS_POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Skip("set MATRIX_IAM_TOTP_BACKUP_PROCESS_POSTGRES_TEST_DSN to an isolated PostgreSQL 18 database")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()
	config, err := pgx.ParseConfig(dsn)
	if err != nil || !strings.HasPrefix(config.Database, "matrix_iam_totp_backup_process_") {
		t.Fatal("backup process gate requires its own database")
	}
	config.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	admin, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())
	assertPostgres18(t, ctx, admin)
	assertCleanSchemas(t, ctx, admin)
	temporary, root := t.TempDir(), repositoryRoot(t)
	iamBinary := buildAuthorityBinary(t, ctx, root, temporary, "iam-for-backup", "./app/service/iam/cmd/matrix-iam")
	backupBinary := buildAuthorityBinary(t, ctx, root, temporary, "iam-backup-custody", "./app/service/iam/cmd/matrix-iam-backup-custody")
	recoveryBinary := buildAuthorityBinary(t, ctx, root, temporary, "iam-authentication-recovery", "./app/service/iam/cmd/matrix-iam-authentication-recovery")
	migrator := buildAuthorityBinary(t, ctx, root, temporary, "iam-backup-migrate", "./app/service/iam/cmd/matrix-iam-migrate")
	const apiLogin = "matrix_iam_api_login"
	var migrationEnvironment []string
	for _, value := range []struct{ environment, login string }{
		{"MATRIX_MIGRATION_DATABASE_DSN_FILE", ""},
		{"MATRIX_MIGRATION_IAM_ACCESS_ANALYSIS_DSN_FILE", "matrix_iam_access_analysis_worker_login"},
		{"MATRIX_MIGRATION_IAM_API_DSN_FILE", apiLogin},
		{installationv1.AuthenticationRecoveryMigrationDSNFileEnvironment, "matrix_iam_authentication_recovery_login"},
		{"MATRIX_MIGRATION_IAM_WORKER_DSN_FILE", "matrix_iam_worker_login"},
		{"MATRIX_MIGRATION_IAM_RECOVERY_DSN_FILE", localRecoveryProcessLogin},
		{installationv1.TOTPBackupCustodyMigrationDSNFileEnvironment, "matrix_iam_backup_custody_login"},
		{"MATRIX_MIGRATION_IAM_NOTIFICATION_DSN_FILE", "matrix_iam_notification_worker_login"},
	} {
		valueDSN := dsn
		if value.login != "" {
			valueDSN = localRecoveryMigrationDSN(t, runtimeDSN(t, config, value.login, processDBPassword))
		}
		migrationEnvironment = append(migrationEnvironment, value.environment+"="+writeProtectedFile(t, temporary, value.environment, []byte(valueDSN)))
	}
	for _, action := range []string{"apply", "apply", "verify"} {
		child := startChild(t, root, migrator, migrationEnvironment, action)
		if err := child.wait(30 * time.Second); err != nil {
			t.Fatal("actual backup-capability migration failed")
		}
		assertProcessOutputsSanitized(t, []*childProcess{child}, config.Password, processDBPassword)
	}
	bootstrap := processBootstrap(t)
	bootstrap.InstallationID = "mxi-102030405060708090a0b0c0d0e0f000"
	bootstrapBytes, err := iamv1.EncodeBootstrapDocument(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	bootstrapFile := writeProtectedFile(t, temporary, "bootstrap", bootstrapBytes)
	clear(bootstrapBytes)
	iamDSN := writeProtectedFile(t, temporary, "api-dsn", []byte(runtimeDSN(t, config, apiLogin, processDBPassword)))
	backupDSN := writeProtectedFile(t, temporary, "backup-dsn", []byte(runtimeDSN(t, config, "matrix_iam_backup_custody_login", processDBPassword)))
	address := freeAddress(t)
	iamEnvironment := []string{
		"MATRIX_IAM_DATABASE_DSN_FILE=" + iamDSN, "MATRIX_IAM_BOOTSTRAP_FILE=" + bootstrapFile,
		"MATRIX_IAM_LISTEN_ADDRESS=" + address,
		"MATRIX_IAM_CURSOR_KEY_FILE=" + writeProtectedFile(t, temporary, "cursor", []byte(strings.Repeat("35", 32))),
		"MATRIX_IAM_ACCESS_KEY_WRAPPING_KEYRING_FILE=" + writeProcessAccessKeyWrapping(t, temporary, bootstrap),
		"MATRIX_IAM_TOTP_KEYRING_FILE=" + writeProcessTOTPKeyring(t, temporary, bootstrap),
	}
	network := startChild(t, root, iamBinary, iamEnvironment)
	defer network.stop()
	waitHTTPStatus(t, ctx, network, "http://"+address+"/ready", http.StatusOK)
	version := runTOTPPostgresTool(t, ctx, config, "pg_dump", nil, "--version")
	if !strings.Contains(string(version), "(PostgreSQL) 18.") {
		t.Fatal("backup gate requires PostgreSQL 18 client")
	}
	insertRetained := func(id, state string) {
		t.Helper()
		// Deliberately opaque negative fixtures: this gate proves retaining all
		// ciphertext references, not enrollment or successful seed decryption.
		if _, err := admin.Exec(ctx, `INSERT INTO iam.totp_authenticators
		 (id,tenant_id,user_id,installation_id,key_id,format_version,nonce,ciphertext,state,last_consumed_step,created_at)
		 VALUES($1,$2,$3,$4,'process-totp',1,$5,$6,$7,-1,clock_timestamp())`, id, bootstrap.Organization.ID,
			bootstrap.Administrator.ID, bootstrap.InstallationID, bytes.Repeat([]byte{0x21}, 12), bytes.Repeat([]byte{0x34}, 36), state); err != nil {
			t.Fatal(err)
		}
	}
	var priorQualification string
	var oldQualification, restoredBearer string
	var recoveryDump []byte
	var recoveryLease installationv1.TOTPBackupSnapshotLease
	for phase := 0; phase < 2; phase++ {
		child, lease := startTOTPBackupProcess(t, ctx, root, backupBinary, backupDSN)
		if len(lease.Custody.RequiredKeys) != phase || lease.Custody.KeysetRevision != 1 || lease.Custody.InstallationID != bootstrap.InstallationID {
			t.Fatal("helper lease did not report actual reference scope")
		}
		var live int
		if err := admin.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database()
		 AND usename='matrix_iam_backup_custody_login' AND application_name='matrix-iam-backup-custody' AND state='idle in transaction'`).Scan(&live); err != nil || live != 1 {
			t.Fatal("helper did not hold an actual restricted snapshot", err)
		}
		if phase == 0 {
			oldQualification = lease.AuthenticationStateDigest
			// Commit a real password generation change after the exporter has
			// sampled its authority. The dump must retain the earlier credential
			// and its exact qualification digest, not the current source state.
			primary := loginIAM(t, "http://"+address, "admin", initialAdminPassword, "backup-process-login")
			restoredBearer = primary.Credential
			changePasswordIAM(t, "http://"+address, primary.Credential, initialAdminPassword, changedAdminPassword, "backup-process-password")
			network.stop()
			assertProcessOutputsSanitized(t, []*childProcess{network}, processDBPassword, initialAdminPassword, changedAdminPassword)
			// Keep a genuine, independently exported source for the recovery
			// workflow before adding unknown-provenance retention fixtures.
			// Those must remain backed up, but must not start a healthy IAM.
			clean, cleanLease := startTOTPBackupProcess(t, ctx, root, backupBinary, backupDSN)
			recoveryLease = cleanLease
			recoveryDump = runTOTPPostgresTool(t, ctx, config, "pg_dump", nil, "--format=custom", "--schema=iam", "--snapshot="+cleanLease.SnapshotID)
			if exit := clean.finish(t, installationv1.TOTPBackupCustodyReleaseFrame); exit != installationv1.TOTPBackupCustodyExitSuccess {
				t.Fatal("clean recovery source snapshot failed to release", exit)
			}
			insertRetained("backup-process-revoked", "REVOKED")
		} else {
			if lease.AuthenticationStateDigest == priorQualification {
				t.Fatal("fresh helper did not observe committed credential qualification")
			}
			insertRetained("backup-process-pending", "PENDING")
		}
		priorQualification = lease.AuthenticationStateDigest
		dump := runTOTPPostgresTool(t, ctx, config, "pg_dump", nil, "--format=custom", "--schema=iam", "--snapshot="+lease.SnapshotID)
		if len(dump) == 0 || len(dump) > 2<<20 {
			t.Fatal("invalid bounded snapshot dump")
		}
		proveTOTPImportedDump(t, ctx, admin, config, dump, lease, phase, root, backupBinary, temporary)
		if exit := child.finish(t, installationv1.TOTPBackupCustodyReleaseFrame); exit != installationv1.TOTPBackupCustodyExitSuccess {
			t.Fatal("normal helper rollback/close failed", exit)
		}
		tx, err := admin.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
		if err != nil {
			t.Fatal(err)
		}
		_, err = tx.Exec(ctx, "SET TRANSACTION SNAPSHOT '"+lease.SnapshotID+"'")
		_ = tx.Rollback(context.Background())
		if err == nil {
			t.Fatal("completed helper left reusable snapshot")
		}
	}
	for _, frame := range []string{"", "RELEASE", "release\n", "RELEASE\nextra"} {
		child, _ := startTOTPBackupProcess(t, ctx, root, backupBinary, backupDSN)
		if exit := child.finish(t, frame); exit != installationv1.TOTPBackupCustodyExitInvalid {
			t.Fatal("invalid control frame succeeded", exit)
		}
	}
	child, _ := startTOTPBackupProcess(t, ctx, root, backupBinary, backupDSN)
	if _, err := admin.Exec(ctx, `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=current_database()
	 AND usename='matrix_iam_backup_custody_login' AND application_name='matrix-iam-backup-custody'`); err != nil {
		t.Fatal(err)
	}
	if exit := child.finish(t, installationv1.TOTPBackupCustodyReleaseFrame); exit != installationv1.TOTPBackupCustodyExitUnavailable {
		t.Fatal("lost transaction was successful closure", exit)
	}
	interrupted, interruptedLease := startTOTPBackupProcess(t, ctx, root, backupBinary, backupDSN)
	if err := interrupted.command.Process.Kill(); err != nil {
		t.Fatal("interrupt own snapshot helper", err)
	}
	select {
	case err := <-interrupted.done:
		interrupted.exited = true
		if err == nil {
			t.Fatal("interrupted exporter reported successful release")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("interrupted exporter remained running")
	}
	_ = interrupted.stdin.Close()
	for deadline := time.Now().Add(5 * time.Second); ; {
		var live int
		if err := admin.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database()
		 AND application_name='matrix-iam-backup-custody'`).Scan(&live); err != nil {
			t.Fatal(err)
		}
		if live == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("interrupted helper retained its database transaction")
		}
		time.Sleep(20 * time.Millisecond)
	}
	interruptedView, err := admin.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatal(err)
	}
	_, err = interruptedView.Exec(ctx, "SET TRANSACTION SNAPSHOT '"+interruptedLease.SnapshotID+"'")
	_ = interruptedView.Rollback(context.Background())
	if err == nil {
		t.Fatal("interrupted helper's lease could still be imported")
	}
	for _, path := range []string{iamDSN, writeProtectedFile(t, temporary, "admin-dsn", []byte(dsn))} {
		command := exec.CommandContext(ctx, backupBinary, installationv1.TOTPBackupCustodySnapshotCommand)
		command.Dir = root
		command.Env = append(os.Environ(), installationv1.TOTPBackupCustodyDatabaseDSNFileEnvironment+"="+path, "GOMAXPROCS=2", "GOMEMLIMIT=512MiB")
		command.Stdin = strings.NewReader(installationv1.TOTPBackupCustodyReleaseFrame)
		output, err := command.CombinedOutput()
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != installationv1.TOTPBackupCustodyExitForbidden || string(output) != installationv1.TOTPBackupCustodyErrorForbidden+"\n" {
			t.Fatal("non-dedicated credential entered backup")
		}
	}
	var live int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND application_name='matrix-iam-backup-custody'`).Scan(&live); err != nil || live != 0 {
		t.Fatal("helper leaked a database lease", err)
	}
	if err := iammigration.Verify(ctx, admin); err != nil {
		t.Fatal(err)
	}
	unknownHistory := startChild(t, root, iamBinary, iamEnvironment)
	defer unknownHistory.stop()
	var startupExit *exec.ExitError
	if err := unknownHistory.wait(10 * time.Second); !errors.As(err, &startupExit) || startupExit.ExitCode() != 1 ||
		strings.TrimSpace(unknownHistory.stderr.String()) != "matrix IAM process failed" {
		t.Fatal("unknown retained MFA provenance was accepted by a restarted authority")
	}
	assertProcessOutputsSanitized(t, []*childProcess{unknownHistory}, processDBPassword, initialAdminPassword, changedAdminPassword, restoredBearer)
	// The opaque backup-retention fixtures have no valid enrollment source.
	// Restore the earlier genuine source instead of deleting or legitimizing
	// them to make a running authority accept unknown MFA history.
	databaseHash := sha256.Sum256([]byte(config.Database + "-clean-recovery-source"))
	sourceName := "matrix_iam_auth_dump_" + hex.EncodeToString(databaseHash[:10])
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{sourceName}.Sanitize()); err != nil {
		t.Fatal("create clean recovery source", err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if _, err := admin.Exec(cleanup, "DROP DATABASE "+pgx.Identifier{sourceName}.Sanitize()); err != nil {
			t.Error("remove own clean recovery source", err)
		}
	}()
	cleanConfig := config.Copy()
	cleanConfig.Database = sourceName
	cleanSource, err := pgx.ConnectConfig(ctx, cleanConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanSource.Close(context.Background())
	runTOTPPostgresTool(t, ctx, cleanConfig, "pg_restore", recoveryDump, "--exit-on-error")
	cleanEnvironment := append([]string(nil), iamEnvironment...)
	cleanEnvironment[0] = "MATRIX_IAM_DATABASE_DSN_FILE=" + writeProtectedFile(t, temporary, "clean-api-dsn", []byte(runtimeDSN(t, cleanConfig, apiLogin, processDBPassword)))
	proveAuthenticationRecoveryProcesses(t, ctx, root, temporary, iamBinary, recoveryBinary, cleanSource, cleanConfig,
		cleanEnvironment, "http://"+address, recoveryDump, recoveryLease, oldQualification, restoredBearer, bootstrap)
	t.Log("actual backup and recovery binaries, retained full dump, strict files/roles, lost output and original replay passed; not signed installation or real MFA enrollment acceptance")
}

func proveAuthenticationRecoveryProcesses(t *testing.T, ctx context.Context, root, temporary, iamBinary, recoveryBinary string,
	source *pgx.Conn, config *pgx.ConnConfig, iamEnvironment []string, sourceEndpoint string, dump []byte,
	lease installationv1.TOTPBackupSnapshotLease, oldQualification, restoredBearer string, bootstrap iamv1.BootstrapDocument) {
	t.Helper()
	const recoveryLogin = "matrix_iam_authentication_recovery_login"
	backupDigest := sha256.Sum256(dump)
	// Release identities are fixture commitments, not signed release admission.
	intent := installationv1.AuthenticationRecoveryIntent{
		APIVersion: installationv1.AuthenticationRecoveryAPIVersion, Kind: installationv1.AuthenticationRecoveryIntentKind,
		Purpose: installationv1.AuthenticationRecoveryPurpose, InstallationID: bootstrap.InstallationID, Epoch: 1,
		CommandID: "cmd-" + strings.Repeat("1", 32), BackupID: "backup-" + strings.Repeat("2", 32),
		BackupDigest:    "sha256:" + hex.EncodeToString(backupDigest[:]),
		SourceReleaseID: "matrix-v0.0.0-recovery-source-0123456789ab", SourceReleaseDigest: "sha256:" + strings.Repeat("3", 64),
		TargetReleaseID: "matrix-v0.0.0-recovery-target-0123456789ab", TargetReleaseDigest: "sha256:" + strings.Repeat("4", 64),
		TOTPCustodyDigest: lease.CustodyDigest, AuthenticationStateDigest: lease.AuthenticationStateDigest,
	}
	encodeIntent := func(value installationv1.AuthenticationRecoveryIntent) string {
		t.Helper()
		encoded, err := installationv1.EncodeAuthenticationRecoveryIntent(value)
		if err != nil {
			t.Fatal(err)
		}
		return writeProtectedFile(t, temporary, "recovery-intent-"+value.AuthenticationStateDigest[7:]+".json", encoded)
	}
	recoveryDSN := writeProtectedFile(t, temporary, "source-authentication-recovery-dsn", []byte(runtimeDSN(t, config, recoveryLogin, processDBPassword)))
	closeEnvironment := []string{installationv1.AuthenticationRecoveryDatabaseDSNFileEnvironment + "=" + recoveryDSN,
		installationv1.AuthenticationRecoveryIntentFileEnvironment + "=" + encodeIntent(intent)}
	assertOpenWithoutRecovery := func(database *pgx.Conn) {
		t.Helper()
		var unchanged bool
		if err := database.QueryRow(ctx, `SELECT state='OPEN' AND epoch=0
		 AND NOT EXISTS(SELECT 1 FROM iam.authentication_recovery_closures)
		 AND NOT EXISTS(SELECT 1 FROM iam.authentication_recovery_completions)
		 AND NOT EXISTS(SELECT 1 FROM iam.audit_outbox WHERE event_document->>'action' LIKE 'iam.authentication-recovery.%')
		 FROM iam.authentication_recovery_state WHERE singleton`).Scan(&unchanged); err != nil || !unchanged {
			t.Fatal("rejected recovery process changed authority, receipt or successful outbox", err)
		}
	}
	for _, login := range []string{"matrix_iam_api_login", "matrix_iam_worker_login", "matrix_iam_backup_custody_login"} {
		environment := append([]string(nil), closeEnvironment...)
		environment[0] = installationv1.AuthenticationRecoveryDatabaseDSNFileEnvironment + "=" +
			writeProtectedFile(t, temporary, "recovery-wrong-"+login, []byte(runtimeDSN(t, config, login, processDBPassword)))
		invokeAuthenticationRecoveryProcess(t, ctx, root, recoveryBinary, "inspect", environment, installationv1.AuthenticationRecoveryExitForbidden)
		invokeAuthenticationRecoveryProcess(t, ctx, root, recoveryBinary, "close", environment, installationv1.AuthenticationRecoveryExitForbidden)
	}
	stale := intent
	stale.AuthenticationStateDigest = oldQualification
	staleEnvironment := append([]string(nil), closeEnvironment...)
	staleEnvironment[1] = installationv1.AuthenticationRecoveryIntentFileEnvironment + "=" + encodeIntent(stale)
	invokeAuthenticationRecoveryProcess(t, ctx, root, recoveryBinary, "inspect", staleEnvironment, installationv1.AuthenticationRecoveryExitConflict)
	invokeAuthenticationRecoveryProcess(t, ctx, root, recoveryBinary, "close", staleEnvironment, installationv1.AuthenticationRecoveryExitConflict)
	inspectionBytes := invokeAuthenticationRecoveryProcess(t, ctx, root, recoveryBinary, "inspect", closeEnvironment, 0)
	inspection, err := installationv1.DecodeAuthenticationRecoveryInspection(bytes.NewReader(inspectionBytes))
	var bootstrapDigest string
	if err := source.QueryRow(ctx, "SELECT content_digest FROM iam.bootstrap_receipts WHERE singleton").Scan(&bootstrapDigest); err != nil {
		t.Fatal("read sealed recovery installation", err)
	}
	if err != nil || installationv1.ValidateAuthenticationRecoveryInspectionForIntent(inspection, intent, bootstrapDigest) != nil {
		t.Fatal("independent inspection did not return the exact bounded eligibility", err)
	}
	assertOpenWithoutRecovery(source)
	network := startChild(t, root, iamBinary, iamEnvironment)
	defer network.stop()
	waitHTTPStatus(t, ctx, network, sourceEndpoint+"/ready", http.StatusOK)
	if response := performJSON(t, http.MethodGet, sourceEndpoint+"/v1/auth/me", restoredBearer, nil); response.Status != http.StatusOK {
		t.Fatal("pre-close real retained Session is not valid", response.Status)
	}
	// Close the consumer's read end before execution. The real binary must
	// commit before its stdout write fails; installation would see UNKNOWN.
	func() {
		blocker, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal("connect private recovery lock holder", err)
		}
		defer blocker.Close(context.Background())
		transaction, err := blocker.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer transaction.Rollback(context.Background())
		if _, err := transaction.Exec(ctx, "SELECT 1 FROM iam.authentication_recovery_state WHERE singleton FOR UPDATE"); err != nil {
			t.Fatal(err)
		}
		loseAuthenticationRecoveryOutput(t, ctx, root, recoveryBinary, "close", closeEnvironment, func() {
			waiting, stop := context.WithTimeout(ctx, 4*time.Second)
			defer stop()
			ticker := time.NewTicker(10 * time.Millisecond)
			defer ticker.Stop()
			for {
				// The observer remains in autocommit: the lock-holder's cached
				// statistics snapshot is not evidence of a new process login.
				var blocked int
				if err := source.QueryRow(waiting, `WITH RECURSIVE waits(pid,blocker) AS (
				 SELECT pid,unnest(pg_blocking_pids(pid)) FROM pg_stat_activity
				 WHERE datname=current_database() AND usename=$1 AND application_name='matrix-iam-authentication-recovery'
				 UNION SELECT pid,unnest(pg_blocking_pids(blocker)) FROM waits)
				 SELECT count(DISTINCT pid) FROM waits WHERE blocker=$2`, recoveryLogin, blocker.PgConn().PID()).Scan(&blocked); err != nil {
					t.Fatal("observe actual private recovery process login and lock dependency", err)
				}
				if blocked == 1 {
					break
				}
				select {
				case <-ticker.C:
				case <-waiting.Done():
					t.Fatal("private recovery process did not reach the held lock within its production timeout")
				}
			}
			if err := transaction.Commit(ctx); err != nil {
				t.Fatal(err)
			}
		})
	}()
	var closed bool
	if err := source.QueryRow(ctx, `SELECT state='CLOSED' AND epoch=1 AND active_command_id=$1
	 AND (SELECT count(*) FROM iam.authentication_recovery_closures)=1
	 AND EXISTS(SELECT 1 FROM iam.authentication_recovery_closures WHERE command_id=$1
	   AND origin='SOURCE' AND security_snapshot_document IS NOT NULL)
	 AND NOT EXISTS(SELECT 1 FROM iam.authentication_recovery_completions)
	 AND (SELECT count(*) FROM iam.audit_outbox WHERE event_document->>'action' LIKE 'iam.authentication-recovery.%')=1
	 FROM iam.authentication_recovery_state WHERE singleton`, intent.CommandID).Scan(&closed); err != nil || !closed {
		t.Fatal("lost close output was not preceded by the actual committed snapshot and closed fact", err)
	}
	encodedEnvelope := invokeAuthenticationRecoveryProcess(t, ctx, root, recoveryBinary, "close", closeEnvironment, 0)
	envelope, err := installationv1.DecodeAuthenticationRecoveryClosureEnvelope(bytes.NewReader(encodedEnvelope))
	if err != nil || installationv1.ValidateAuthenticationRecoveryClosureEnvelopeForIntent(envelope, intent, lease.Custody.BootstrapDigest) != nil {
		t.Fatal("restarted close process did not return its original committed envelope", err)
	}
	if replay := invokeAuthenticationRecoveryProcess(t, ctx, root, recoveryBinary, "close", closeEnvironment, 0); !bytes.Equal(replay, encodedEnvelope) {
		t.Fatal("new close process sampled another snapshot or changed receipt bytes")
	}
	invokeAuthenticationRecoveryProcess(t, ctx, root, recoveryBinary, "inspect", closeEnvironment, installationv1.AuthenticationRecoveryExitConflict)
	waitHTTPStatus(t, ctx, network, sourceEndpoint+"/ready", http.StatusServiceUnavailable)
	if response := performJSON(t, http.MethodGet, sourceEndpoint+"/v1/auth/me", restoredBearer, nil); response.Status != http.StatusUnauthorized {
		t.Fatal("live API bypassed committed private close", response.Status)
	}
	network.stop()
	assertProcessOutputsSanitized(t, []*childProcess{network}, processDBPassword, initialAdminPassword, changedAdminPassword, restoredBearer)
	closureBytes, err := installationv1.EncodeAuthenticationRecoveryClosure(envelope.Closure)
	if err != nil {
		t.Fatal(err)
	}
	snapshotBytes, err := installationv1.EncodeAuthenticationRecoverySecuritySnapshot(envelope.SecuritySnapshot)
	if err != nil {
		t.Fatal(err)
	}
	closureFile := writeProtectedFile(t, temporary, "recovery-closure.json", closureBytes)
	snapshotFile := writeProtectedFile(t, temporary, "recovery-snapshot.json", snapshotBytes)
	closedEnvironment := []string{installationv1.AuthenticationRecoveryDatabaseDSNFileEnvironment + "=" + recoveryDSN,
		installationv1.AuthenticationRecoveryClosureFileEnvironment + "=" + closureFile,
		installationv1.AuthenticationRecoverySecuritySnapshotFileEnvironment + "=" + snapshotFile}
	invokeAuthenticationRecoveryProcess(t, ctx, root, recoveryBinary, "reopen", closedEnvironment, installationv1.AuthenticationRecoveryExitConflict)

	databaseHash := sha256.Sum256([]byte(config.Database + "-authentication-recovery"))
	name := "matrix_iam_auth_dump_" + hex.EncodeToString(databaseHash[:10])
	if _, err := source.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		t.Fatal("create private recovery target", err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if _, err := source.Exec(cleanup, "DROP DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
			t.Error("remove private recovery target", err)
		}
	}()
	targetConfig := config.Copy()
	targetConfig.Database = name
	target, err := pgx.ConnectConfig(ctx, targetConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close(context.Background())
	runTOTPPostgresTool(t, ctx, targetConfig, "pg_restore", dump, "--exit-on-error")
	var originalGeneration int64
	if err := target.QueryRow(ctx, "SELECT credential_version FROM iam.user_credentials WHERE tenant_id=$1 AND principal_id=$2",
		bootstrap.Organization.ID, bootstrap.Administrator.ID).Scan(&originalGeneration); err != nil {
		t.Fatal(err)
	}
	restoredEnvironment := append([]string(nil), closedEnvironment...)
	restoredEnvironment[0] = installationv1.AuthenticationRecoveryDatabaseDSNFileEnvironment + "=" +
		writeProtectedFile(t, temporary, "target-authentication-recovery-dsn", []byte(runtimeDSN(t, targetConfig, recoveryLogin, processDBPassword)))
	invokeAuthenticationRecoveryProcess(t, ctx, root, recoveryBinary, "reconcile", restoredEnvironment[:2], installationv1.AuthenticationRecoveryExitInvalid)
	badSnapshot := envelope.SecuritySnapshot
	badSnapshot.AuthenticationStateDigest = "sha256:" + strings.Repeat("f", 64)
	badBytes, err := installationv1.EncodeAuthenticationRecoverySecuritySnapshot(badSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	badEnvironment := append([]string(nil), restoredEnvironment...)
	badEnvironment[2] = installationv1.AuthenticationRecoverySecuritySnapshotFileEnvironment + "=" + writeProtectedFile(t, temporary, "recovery-bad-snapshot.json", badBytes)
	invokeAuthenticationRecoveryProcess(t, ctx, root, recoveryBinary, "reconcile", badEnvironment, installationv1.AuthenticationRecoveryExitInvalid)
	assertOpenWithoutRecovery(target)
	for range 2 {
		if reconciled := invokeAuthenticationRecoveryProcess(t, ctx, root, recoveryBinary, "reconcile", restoredEnvironment, 0); !bytes.Equal(reconciled, closureBytes) {
			t.Fatal("independent reconcile changed original closure")
		}
	}
	loseAuthenticationRecoveryOutput(t, ctx, root, recoveryBinary, "reopen", restoredEnvironment, nil)
	// Inspect before any replay can hide a failure to commit the first command.
	var once bool
	if err := target.QueryRow(ctx, `SELECT state='OPEN' AND epoch=1
	 AND (SELECT count(*) FROM iam.authentication_recovery_closures)=1
	 AND (SELECT count(*) FROM iam.authentication_recovery_reconciliations)=1
	 AND (SELECT count(*) FROM iam.authentication_recovery_completions)=1
	 AND (SELECT count(*) FROM iam.audit_outbox WHERE event_document->>'action' LIKE 'iam.authentication-recovery.%')=3
	 AND (SELECT credential_version FROM iam.user_credentials WHERE tenant_id=$1 AND principal_id=$2)=$3+1
	 FROM iam.authentication_recovery_state WHERE singleton`, bootstrap.Organization.ID, bootstrap.Administrator.ID, originalGeneration).Scan(&once); err != nil || !once {
		t.Fatal("lost reopen output was not preceded by exactly one committed credential fence and completion", err)
	}
	completionBytes := invokeAuthenticationRecoveryProcess(t, ctx, root, recoveryBinary, "reopen", restoredEnvironment, 0)
	completion, err := installationv1.DecodeAuthenticationRecoveryCompletion(bytes.NewReader(completionBytes))
	if err != nil || installationv1.ValidateAuthenticationRecoveryCompletionForClosure(completion, envelope.Closure) != nil {
		t.Fatal("original reopen completion unavailable", err)
	}
	targetAddress := freeAddress(t)
	targetEnvironment := append([]string(nil), iamEnvironment...)
	for index, entry := range targetEnvironment {
		if strings.HasPrefix(entry, "MATRIX_IAM_DATABASE_DSN_FILE=") {
			targetEnvironment[index] = "MATRIX_IAM_DATABASE_DSN_FILE=" + writeProtectedFile(t, temporary, "target-api-dsn", []byte(runtimeDSN(t, targetConfig, "matrix_iam_api_login", processDBPassword)))
		}
		if strings.HasPrefix(entry, "MATRIX_IAM_LISTEN_ADDRESS=") {
			targetEnvironment[index] = "MATRIX_IAM_LISTEN_ADDRESS=" + targetAddress
		}
	}
	endpoint := "http://" + targetAddress
	var newBearer string
	for round := 0; round < 2; round++ {
		restarted := startChild(t, root, iamBinary, targetEnvironment)
		defer restarted.stop()
		waitHTTPStatus(t, ctx, restarted, endpoint+"/ready", http.StatusOK)
		if response := performJSON(t, http.MethodGet, endpoint+"/v1/auth/me", restoredBearer, nil); response.Status != http.StatusUnauthorized {
			t.Fatal("restart revived pre-recovery Session", response.Status)
		}
		if response := performJSON(t, http.MethodPost, endpoint+"/v1/auth/login", "", map[string]string{"loginName": "admin", "password": initialAdminPassword, "requestId": fmt.Sprintf("recovery-old-password-%d", round)}); response.Status != http.StatusUnauthorized {
			t.Fatal("bootstrap replay revived old password", response.Status)
		}
		if round == 0 {
			newBearer = loginIAM(t, endpoint, "admin", changedAdminPassword, "recovery-fresh-login").Credential
		}
		if replay := invokeAuthenticationRecoveryProcess(t, ctx, root, recoveryBinary, "reopen", restoredEnvironment, 0); !bytes.Equal(replay, completionBytes) {
			t.Fatal("restarted private process changed historical completion")
		}
		if response := performJSON(t, http.MethodGet, endpoint+"/v1/auth/me", newBearer, nil); response.Status != http.StatusOK {
			t.Fatal("completion replay revoked new post-recovery Session", response.Status)
		}
		rows, err := target.Query(ctx, "SELECT event_document FROM iam.audit_outbox WHERE event_document->>'action' LIKE 'iam.authentication-recovery.%' ORDER BY event_id")
		if err != nil {
			t.Fatal(err)
		}
		var events []auditv1.Event
		for rows.Next() {
			var raw []byte
			var event auditv1.Event
			if err := rows.Scan(&raw); err != nil {
				rows.Close()
				t.Fatal(err)
			}
			if json.Unmarshal(raw, &event) != nil {
				rows.Close()
				t.Fatal("invalid stored recovery fact")
			}
			events = append(events, event)
		}
		rows.Close()
		if rows.Err() != nil || len(events) != 3 {
			t.Fatal("incomplete recovery fact set", rows.Err())
		}
		for _, event := range events {
			response := performJSON(t, http.MethodPost, endpoint+"/v1/audit-producer:resolve", iamServiceCredential, iamv1.ResolveAuditProducerRequest{Event: event})
			var proof iamv1.AuditProducerAuthorization
			_, digest, err := auditv1.CanonicalizeEvent(auditv1.SourceIAM, event)
			if err != nil || response.Status != http.StatusOK || json.Unmarshal(response.Body, &proof) != nil || iamv1.ValidateAuditProducerAuthorization(proof) != nil ||
				proof.Producer.Purpose != iamv1.ServiceIAM || proof.InstallationID != bootstrap.InstallationID || proof.TenantID != "" || proof.ContentDigest != digest {
				t.Fatal("committed recovery fact lost HTTP producer proof", response.Status)
			}
		}
		restarted.stop()
		assertProcessOutputsSanitized(t, []*childProcess{restarted}, processDBPassword, initialAdminPassword, changedAdminPassword, restoredBearer, newBearer)
	}
	if err := iammigration.Verify(ctx, target); err != nil {
		t.Fatal("restored process schema did not verify", err)
	}
}

func invokeAuthenticationRecoveryProcess(t *testing.T, ctx context.Context, root, binary, mode string, environment []string, want int) []byte {
	t.Helper()
	child := startChild(t, root, binary, environment, mode)
	defer child.stop()
	err := child.wait(50 * time.Second)
	code := 0
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			t.Fatal("authentication recovery process did not finish")
		}
		code = exit.ExitCode()
	}
	codes := map[int]string{0: "", 2: installationv1.AuthenticationRecoveryErrorInvalid, 3: installationv1.AuthenticationRecoveryErrorForbidden, 4: installationv1.AuthenticationRecoveryErrorConflict, 6: installationv1.AuthenticationRecoveryErrorUnavailable}
	expected, known := codes[code]
	if !known || code != want || strings.TrimSpace(child.stderr.String()) != expected || (code != 0 && child.stdout.Len() != 0) || int64(child.stdout.Len()) > installationv1.MaximumAuthenticationRecoveryEnvelopeBytes {
		t.Fatalf("authentication recovery %s violated its closed output/exit contract: exit=%d want=%d", mode, code, want)
	}
	if ctx.Err() != nil {
		t.Fatal("authentication recovery process gate context expired")
	}
	return append([]byte(nil), child.stdout.Bytes()...)
}

func loseAuthenticationRecoveryOutput(t *testing.T, ctx context.Context, root, binary, mode string, environment []string, observe func()) {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	command := exec.CommandContext(ctx, binary, mode)
	command.Dir = root
	command.Env = append(append(os.Environ(), environment...), "GOMAXPROCS=2", "GOMEMLIMIT=512MiB")
	command.Stdout = writer
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatal("start private recovery with disconnected output", err)
	}
	waited := false
	defer func() {
		if !waited {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	}()
	if observe != nil {
		observe()
	}
	err = command.Wait()
	waited = true
	var exit *exec.ExitError
	if !errors.As(err, &exit) || ctx.Err() != nil {
		t.Fatal("broken response pipe did not produce an unknown process outcome")
	}
	if message := strings.TrimSpace(stderr.String()); message != "" && message != installationv1.AuthenticationRecoveryErrorUnavailable {
		t.Fatal("lost recovery output exposed non-sanitized error")
	}
}

type totpSnapshotProcess struct {
	command *exec.Cmd
	stdin   io.WriteCloser
	stdout  *os.File
	reader  *bufio.Reader
	stderr  bytes.Buffer
	done    chan error
	exited  bool
}

func startTOTPBackupProcess(t *testing.T, ctx context.Context, root, binary, dsnFile string) (*totpSnapshotProcess, installationv1.TOTPBackupSnapshotLease) {
	t.Helper()
	child := &totpSnapshotProcess{done: make(chan error, 1)}
	child.command = exec.CommandContext(ctx, binary, installationv1.TOTPBackupCustodySnapshotCommand)
	child.command.Dir = root
	child.command.Env = append(os.Environ(), installationv1.TOTPBackupCustodyDatabaseDSNFileEnvironment+"="+dsnFile, "GOMAXPROCS=2", "GOMEMLIMIT=512MiB")
	var err error
	child.stdin, err = child.command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var output *os.File
	child.stdout, output, err = os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	child.command.Stdout, child.command.Stderr = output, &child.stderr
	if err := child.command.Start(); err != nil {
		t.Fatal(err)
	}
	_ = output.Close()
	go func() { child.done <- child.command.Wait() }()
	t.Cleanup(func() {
		if !child.exited {
			_ = child.command.Process.Kill()
			<-child.done
		}
		_ = child.stdin.Close()
		_ = child.stdout.Close()
	})
	child.reader = bufio.NewReader(io.LimitReader(child.stdout, installationv1.MaximumTOTPBackupCustodyBytes+2))
	line, err := child.reader.ReadBytes('\n')
	if err != nil || len(line) < 2 || int64(len(line)) > installationv1.MaximumTOTPBackupCustodyBytes+1 {
		t.Fatal("helper failed to produce bounded lease")
	}
	lease, err := installationv1.DecodeTOTPBackupSnapshotLease(bytes.NewReader(line[:len(line)-1]))
	if err != nil {
		t.Fatal("helper emitted invalid lease")
	}
	return child, lease
}

func (child *totpSnapshotProcess) finish(t *testing.T, frame string) int {
	t.Helper()
	written, err := io.WriteString(child.stdin, frame)
	if err != nil || written != len(frame) {
		t.Fatal("write control frame failed", err)
	}
	if err := child.stdin.Close(); err != nil {
		t.Fatal("close control frame failed", err)
	}
	var result error
	select {
	case result = <-child.done:
		child.exited = true
	case <-time.After(10 * time.Second):
		t.Fatal("snapshot helper did not close")
	}
	extra, err := io.ReadAll(child.reader)
	if err != nil || len(extra) != 0 {
		t.Fatal("helper emitted extra stdout")
	}
	code := 0
	if result != nil {
		var exit *exec.ExitError
		if !errors.As(result, &exit) {
			t.Fatal("unknown helper failure")
		}
		code = exit.ExitCode()
	}
	expected := ""
	switch code {
	case installationv1.TOTPBackupCustodyExitSuccess:
	case installationv1.TOTPBackupCustodyExitInvalid:
		expected = installationv1.TOTPBackupCustodyErrorInvalid + "\n"
	case installationv1.TOTPBackupCustodyExitForbidden:
		expected = installationv1.TOTPBackupCustodyErrorForbidden + "\n"
	case installationv1.TOTPBackupCustodyExitUnavailable:
		expected = installationv1.TOTPBackupCustodyErrorUnavailable + "\n"
	default:
		t.Fatal("unfrozen helper exit code", code)
	}
	if child.stderr.String() != expected {
		t.Fatal("helper stderr escaped fixed sanitized code")
	}
	return code
}

func runTOTPPostgresTool(t *testing.T, ctx context.Context, config *pgx.ConnConfig, name string, input []byte, args ...string) []byte {
	t.Helper()
	host, port := config.Host, strconv.Itoa(int(config.Port))
	var command *exec.Cmd
	container := os.Getenv("MATRIX_IAM_BACKUP_POSTGRES_CONTAINER")
	if container != "" {
		label := os.Getenv("MATRIX_IAM_BACKUP_POSTGRES_TASK")
		if label == "" || len(container) != 64 || strings.ContainsAny(container, "\r\n /\\") {
			t.Fatal("missing owned PostgreSQL container")
		}
		check := exec.CommandContext(ctx, "docker", "inspect", "--format", `{{ index .Config.Labels "matrix.task" }}`, container)
		actual, err := check.Output()
		if err != nil || strings.TrimSpace(string(actual)) != label {
			t.Fatal("PostgreSQL tool target is not the task's container")
		}
		host, port = "127.0.0.1", "5432"
		command = exec.CommandContext(ctx, "docker", append([]string{"exec", "-i", "-e", "PGPASSWORD", container, name}, args...)...)
	} else {
		binary := name
		if runtime.GOOS == "windows" {
			binary += ".exe"
		}
		if directory := os.Getenv("MATRIX_IAM_BACKUP_PG_BIN"); directory != "" {
			binary = filepath.Join(directory, binary)
		}
		command = exec.CommandContext(ctx, binary, args...)
	}
	if len(args) != 1 || args[0] != "--version" {
		command.Args = append(command.Args, "--host="+host, "--port="+port, "--username="+config.User, "--dbname="+config.Database, "--no-password")
	}
	command.Env = append(os.Environ(), "PGPASSWORD="+config.Password)
	command.Stdin = bytes.NewReader(input)
	output, err := command.Output()
	if err != nil {
		t.Fatalf("actual PostgreSQL %s failed (output suppressed)", name)
	}
	return output
}

func proveTOTPImportedDump(t *testing.T, ctx context.Context, admin *pgx.Conn, config *pgx.ConnConfig, dump []byte, lease installationv1.TOTPBackupSnapshotLease, wantFactors int, root, backupBinary, temporary string) {
	t.Helper()
	digest := sha256.Sum256([]byte(config.Database + fmt.Sprint(wantFactors)))
	name := "matrix_iam_totp_dump_" + hex.EncodeToString(digest[:10])
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		t.Fatal("create unique dump verification database", err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := admin.Exec(cleanup, "DROP DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
			t.Error("remove own dump verification database", err)
		}
	}()
	target := config.Copy()
	target.Database = name
	connection, err := pgx.ConnectConfig(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(context.Background())
	runTOTPPostgresTool(t, ctx, target, "pg_restore", dump, "--exit-on-error")
	var factors, revision int
	if err := connection.QueryRow(ctx, `SELECT (SELECT count(*) FROM iam.totp_authenticators),(SELECT max(revision) FROM iam.totp_keysets)`).Scan(&factors, &revision); err != nil || factors != wantFactors || uint64(revision) != lease.Custody.KeysetRevision {
		t.Fatal("pg_dump did not import the leased snapshot", err)
	}
	rows, err := connection.Query(ctx, `SELECT k.key_id,k.format_version,k.material_commitment FROM iam.totp_wrapping_registry k
	 WHERE EXISTS(SELECT 1 FROM iam.totp_authenticators f WHERE (f.installation_id,f.key_id)=(k.installation_id,k.key_id))
	 ORDER BY k.key_id COLLATE "C"`)
	if err != nil {
		t.Fatal(err)
	}
	index := 0
	for rows.Next() {
		var key installationv1.TOTPBackupRequiredKey
		if err := rows.Scan(&key.KeyID, &key.FormatVersion, &key.Commitment); err != nil || index >= len(lease.Custody.RequiredKeys) || key != lease.Custody.RequiredKeys[index] {
			rows.Close()
			t.Fatal("dump material requirements differ from lease", err)
		}
		index++
	}
	rows.Close()
	if rows.Err() != nil || index != len(lease.Custody.RequiredKeys) {
		t.Fatal("dump requirement summary is incomplete")
	}
	// The restored full IAM schema must retain actual owners, RLS and grants.
	// Re-run the real helper through its private login, not administrative SQL.
	restoredDSN := writeProtectedFile(t, temporary, name+"-backup-dsn", []byte(runtimeDSN(t, target, "matrix_iam_backup_custody_login", processDBPassword)))
	child, restoredLease := startTOTPBackupProcess(t, ctx, root, backupBinary, restoredDSN)
	var restoredExporter int
	if err := connection.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database()
	 AND usename='matrix_iam_backup_custody_login' AND application_name='matrix-iam-backup-custody'
	 AND state='idle in transaction'`).Scan(&restoredExporter); err != nil || restoredExporter != 1 {
		t.Fatal("restored helper did not hold the target database snapshot", err)
	}
	if restoredLease.AuthenticationStateDigest != lease.AuthenticationStateDigest || restoredLease.CustodyDigest != lease.CustodyDigest {
		t.Fatal("full restored dump diverged from leased authentication or material proof")
	}
	if exit := child.finish(t, installationv1.TOTPBackupCustodyReleaseFrame); exit != installationv1.TOTPBackupCustodyExitSuccess {
		t.Fatal("restored helper failed to release its snapshot", exit)
	}
}
