package authorityprocess

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	migrator := buildAuthorityBinary(t, ctx, root, temporary, "iam-backup-migrate", "./app/service/iam/cmd/matrix-iam-migrate")
	const apiLogin = "matrix_iam_api_login"
	var migrationEnvironment []string
	for _, value := range []struct{ environment, login string }{
		{"MATRIX_MIGRATION_DATABASE_DSN_FILE", ""},
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
	cursorPath, accessKeyWrappingPath := writeProcessIAMPrivateAuthority(t, temporary, bootstrap)
	address := freeAddress(t)
	network := startChild(t, root, iamBinary, []string{
		"MATRIX_IAM_DATABASE_DSN_FILE=" + iamDSN, "MATRIX_IAM_BOOTSTRAP_FILE=" + bootstrapFile,
		"MATRIX_IAM_LISTEN_ADDRESS=" + address,
		"MATRIX_IAM_CURSOR_KEY_FILE=" + cursorPath,
		"MATRIX_IAM_ACCESS_KEY_WRAPPING_KEYRING_FILE=" + accessKeyWrappingPath,
		"MATRIX_IAM_TOTP_KEYRING_FILE=" + writeProcessTOTPKeyring(t, temporary, bootstrap),
	})
	defer network.stop()
	waitHTTPStatus(t, ctx, network, "http://"+address+"/ready", http.StatusOK)
	network.stop()
	assertProcessOutputsSanitized(t, []*childProcess{network}, processDBPassword, initialAdminPassword)
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
			insertRetained("backup-process-revoked", "REVOKED")
		} else {
			insertRetained("backup-process-pending", "PENDING")
		}
		dump := runTOTPPostgresTool(t, ctx, config, "pg_dump", nil, "--format=custom", "--no-owner", "--no-privileges",
			"--section=pre-data", "--section=data", "--table=iam.totp_wrapping_registry", "--table=iam.totp_keysets",
			"--table=iam.totp_authenticators", "--snapshot="+lease.SnapshotID)
		if len(dump) == 0 || len(dump) > 2<<20 {
			t.Fatal("invalid bounded snapshot dump")
		}
		proveTOTPImportedDump(t, ctx, admin, config, dump, lease, phase)
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
	t.Log("actual dedicated helper, live snapshot pg_dump/import, retained references, strict release/EOF, rejected roles and failed closure passed; not signed backup/reopen acceptance")
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

func proveTOTPImportedDump(t *testing.T, ctx context.Context, admin *pgx.Conn, config *pgx.ConnConfig, dump []byte, lease installationv1.TOTPBackupSnapshotLease, wantFactors int) {
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
	if _, err := connection.Exec(ctx, "CREATE SCHEMA iam"); err != nil {
		t.Fatal(err)
	}
	runTOTPPostgresTool(t, ctx, target, "pg_restore", dump, "--exit-on-error", "--no-owner", "--no-privileges")
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
}
