package authorityprocess

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

const (
	authorityProcessDSN = "MATRIX_AUTHORITY_PROCESS_POSTGRES_TEST_DSN"

	iamAPILogin       = "matrix_authority_process_iam_api"
	iamWorkerLogin    = "matrix_authority_process_iam_worker"
	auditRuntimeLogin = "matrix_authority_process_audit_runtime"
	paasAPILogin      = "matrix_authority_process_paas_api"
	paasWorkerLogin   = "matrix_authority_process_paas_worker"
	processDBPassword = "matrix-authority-process-test-only"

	initialAdminPassword     = "Initial-Process-Admin-Password-49!"
	changedAdminPassword     = "Changed-Process-Admin-Password-73!"
	initialReaderPassword    = "Initial-Process-Reader-Password-84!"
	changedReaderPassword    = "Changed-Process-Reader-Password-95!"
	initialDeveloperPassword = "Initial-Process-Developer-Password-57!"
	changedDeveloperPassword = "Changed-Process-Developer-Password-61!"

	iamServiceCredential   = "mx1.ProcessIAMServiceCredential00000000000000001"
	paasServiceCredential  = "mx1.ProcessPaaSServiceCredential0000000000000001"
	auditServiceCredential = "mx1.ProcessAuditServiceCredential000000000000001"
)

func TestIndependentIAMAuditAndPaaSProcesses(t *testing.T) {
	dsn := os.Getenv(authorityProcessDSN)
	if dsn == "" {
		t.Skipf("set %s to a clean disposable PostgreSQL 18 database", authorityProcessDSN)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	root := repositoryRoot(t)
	adminConfig, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse authority process DSN: %v", err)
	}
	if !strings.HasPrefix(adminConfig.Database, "matrix_authority_process_") {
		t.Fatalf("refusing authority process database %q", adminConfig.Database)
	}
	adminConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	admin, err := pgx.ConnectConfig(ctx, adminConfig)
	if err != nil {
		t.Fatalf("connect authority process database: %v", err)
	}
	defer func() { _ = admin.Close(context.Background()) }()
	assertPostgres18(t, ctx, admin)
	assertCleanSchemas(t, ctx, admin)
	applyPlatformSchemas(t, ctx, admin, root)
	createProcessLogins(t, ctx, admin)
	assertCrossSchemaIsolation(t, ctx, adminConfig)

	temporary := t.TempDir()
	binaries := buildAuthorityBinaries(t, ctx, root, temporary)
	bootstrap := processBootstrap(t)
	bootstrapBytes, err := iamv1.EncodeBootstrapDocument(bootstrap)
	if err != nil {
		t.Fatalf("encode authority process bootstrap: %v", err)
	}
	bootstrapPath := writeProtectedFile(t, temporary, "iam-bootstrap.json", bootstrapBytes)
	clear(bootstrapBytes)
	changedBootstrap := bootstrap
	changedBootstrap.Organization.DisplayName = "Changed Organization"
	changedBytes, err := iamv1.EncodeBootstrapDocument(changedBootstrap)
	if err != nil {
		t.Fatalf("encode changed authority bootstrap: %v", err)
	}
	changedBootstrapPath := writeProtectedFile(t, temporary, "iam-bootstrap-changed.json", changedBytes)
	clear(changedBytes)
	iamDSNPath := writeProtectedFile(
		t,
		temporary,
		"iam-dsn",
		[]byte(runtimeDSN(adminConfig, iamAPILogin, processDBPassword)),
	)
	iamWorkerDSNPath := writeProtectedFile(
		t,
		temporary,
		"iam-worker-dsn",
		[]byte(runtimeDSN(adminConfig, iamWorkerLogin, processDBPassword)),
	)
	auditDSNPath := writeProtectedFile(
		t,
		temporary,
		"audit-dsn",
		[]byte(runtimeDSN(adminConfig, auditRuntimeLogin, processDBPassword)),
	)
	paasDSNPath := writeProtectedFile(
		t,
		temporary,
		"paas-dsn",
		[]byte(runtimeDSN(adminConfig, paasAPILogin, processDBPassword)),
	)
	paasWorkerDSNPath := writeProtectedFile(
		t,
		temporary,
		"paas-worker-dsn",
		[]byte(runtimeDSN(adminConfig, paasWorkerLogin, processDBPassword)),
	)
	auditCredentialPath := writeProtectedFile(
		t,
		temporary,
		"audit-service-credential",
		[]byte(auditServiceCredential),
	)
	iamCredentialPath := writeProtectedFile(
		t,
		temporary,
		"iam-service-credential",
		[]byte(iamServiceCredential),
	)
	paasCredentialPath := writeProtectedFile(
		t,
		temporary,
		"paas-service-credential",
		[]byte(paasServiceCredential),
	)
	wrongCredentialPath := writeProtectedFile(
		t,
		temporary,
		"wrong-iam-service-credential",
		[]byte("mx1.ProcessWrongIAMCredential000000000000000001"),
	)
	cursorKeyPath := writeProtectedFile(
		t,
		temporary,
		"audit-cursor-key",
		[]byte(hex.EncodeToString(bytes.Repeat([]byte{0x6a}, 32))),
	)

	iamAddress := freeAddress(t)
	auditAddress := freeAddress(t)
	paasAddress := freeAddress(t)
	iamEndpoint := "http://" + iamAddress
	auditEndpoint := "http://" + auditAddress
	paasEndpoint := "http://" + paasAddress
	iamEnvironment := []string{
		"MATRIX_IAM_DATABASE_DSN_FILE=" + iamDSNPath,
		"MATRIX_IAM_BOOTSTRAP_FILE=" + bootstrapPath,
		"MATRIX_IAM_LISTEN_ADDRESS=" + iamAddress,
	}
	auditEnvironment := []string{
		"MATRIX_AUDIT_DATABASE_DSN_FILE=" + auditDSNPath,
		"MATRIX_AUDIT_IAM_ENDPOINT=" + iamEndpoint,
		"MATRIX_AUDIT_SERVICE_CREDENTIAL_FILE=" + auditCredentialPath,
		"MATRIX_AUDIT_CURSOR_KEY_FILE=" + cursorKeyPath,
		"MATRIX_AUDIT_LISTEN_ADDRESS=" + auditAddress,
	}
	iamDispatcherEnvironment := func(credentialPath string, workerID string) []string {
		return []string{
			"MATRIX_IAM_AUDIT_DATABASE_DSN_FILE=" + iamWorkerDSNPath,
			"MATRIX_IAM_AUDIT_ENDPOINT=" + auditEndpoint,
			"MATRIX_IAM_AUDIT_CREDENTIAL_FILE=" + credentialPath,
			"MATRIX_IAM_AUDIT_WORKER_ID=" + workerID,
		}
	}
	paasEnvironment := []string{
		"MATRIX_PAAS_DATABASE_DSN_FILE=" + paasDSNPath,
		"MATRIX_PAAS_IAM_ENDPOINT=" + iamEndpoint,
		"MATRIX_PAAS_SERVICE_CREDENTIAL_FILE=" + paasCredentialPath,
		"MATRIX_PAAS_LISTEN_ADDRESS=" + paasAddress,
	}
	paasDispatcherEnvironment := func(credentialPath string, workerID string) []string {
		return []string{
			"MATRIX_PAAS_AUDIT_DATABASE_DSN_FILE=" + paasWorkerDSNPath,
			"MATRIX_PAAS_AUDIT_ENDPOINT=" + auditEndpoint,
			"MATRIX_PAAS_AUDIT_CREDENTIAL_FILE=" + credentialPath,
			"MATRIX_PAAS_AUDIT_WORKER_ID=" + workerID,
		}
	}
	children := make([]*childProcess, 0)
	sensitive := []string{
		initialAdminPassword,
		changedAdminPassword,
		initialReaderPassword,
		changedReaderPassword,
		initialDeveloperPassword,
		changedDeveloperPassword,
		"Initial-Outage-User-Password-68!",
		"Initial-Dead-Letter-Password-79!",
		iamServiceCredential,
		paasServiceCredential,
		auditServiceCredential,
		"mx1.ProcessWrongIAMCredential000000000000000001",
		"mx1.ProcessAPISIXCredential0000000000000000001",
		"mx1.ProcessVerifierCredential0000000000000001",
	}
	start := func(binary string, environment []string) *childProcess {
		child := startChild(t, root, binary, environment)
		children = append(children, child)
		return child
	}
	defer func() {
		for _, child := range children {
			child.stop()
		}
		assertProcessOutputsSanitized(t, children, sensitive...)
	}()

	iamProcess := start(binaries.iam, iamEnvironment)
	waitHTTPStatus(t, ctx, iamProcess, iamEndpoint+"/ready", http.StatusOK)
	iamProcess.stop()
	iamProcess = start(binaries.iam, iamEnvironment)
	waitHTTPStatus(t, ctx, iamProcess, iamEndpoint+"/ready", http.StatusOK)
	iamProcess.stop()
	changedEnvironment := append([]string(nil), iamEnvironment...)
	changedEnvironment[1] = "MATRIX_IAM_BOOTSTRAP_FILE=" + changedBootstrapPath
	changedProcess := start(binaries.iam, changedEnvironment)
	if err := changedProcess.wait(30 * time.Second); err == nil ||
		errors.Is(err, errProcessWaitTimeout) {
		t.Fatal("changed IAM bootstrap process succeeded")
	}
	iamProcess = start(binaries.iam, iamEnvironment)
	waitHTTPStatus(t, ctx, iamProcess, iamEndpoint+"/ready", http.StatusOK)
	assertIAMWeakLoginRejected(t, iamEndpoint)

	auditProcess := start(binaries.audit, auditEnvironment)
	waitHTTPStatus(t, ctx, auditProcess, auditEndpoint+"/ready", http.StatusOK)
	dispatcher := start(
		binaries.dispatcher,
		iamDispatcherEnvironment(iamCredentialPath, "iam-audit-worker-a"),
	)
	waitAllIAMOutboxDelivered(t, ctx, admin)
	assertIAMEventsStoredOnce(t, ctx, admin)
	paasProcess := start(binaries.paas, paasEnvironment)
	waitHTTPStatus(t, ctx, paasProcess, paasEndpoint+"/ready", http.StatusOK)
	paasDispatcher := start(
		binaries.paasDispatcher,
		paasDispatcherEnvironment(paasCredentialPath, "paas-audit-worker-a"),
	)

	adminLogin := loginIAM(t, iamEndpoint, "admin", initialAdminPassword, "request-admin-login")
	sensitive = append(sensitive, adminLogin.Credential)
	changePasswordIAM(
		t,
		iamEndpoint,
		adminLogin.Credential,
		initialAdminPassword,
		changedAdminPassword,
		"request-admin-password",
	)
	assertCrossTenantIAMBindingRejected(t, ctx, admin, iamEndpoint, adminLogin.Credential)
	waitAllIAMOutboxDelivered(t, ctx, admin)
	adminPage := queryAudit(t, auditEndpoint, adminLogin.Credential, auditv1.QueryRecordsRequest{PageSize: 200}, http.StatusOK)
	if adminPage.TenantID != "organization-process" || len(adminPage.Records) < 3 {
		t.Fatalf("administrator Audit page tenant=%s records=%d", adminPage.TenantID, len(adminPage.Records))
	}
	assertAuditQueryConfinement(t, auditEndpoint, adminLogin.Credential)
	developer := createIAMUser(
		t,
		iamEndpoint,
		adminLogin.Credential,
		"paas.developer",
		"PaaS Developer",
		initialDeveloperPassword,
		"request-create-developer",
	)
	developerBinding := putIAMBinding(
		t,
		iamEndpoint,
		adminLogin.Credential,
		developer.ID,
		iamv1.RolePaaSDeveloper,
		"request-bind-developer",
	)
	developerLogin := loginIAM(
		t,
		iamEndpoint,
		"paas.developer",
		initialDeveloperPassword,
		"request-developer-login",
	)
	sensitive = append(sensitive, developerLogin.Credential)
	changePasswordIAM(
		t,
		iamEndpoint,
		developerLogin.Credential,
		initialDeveloperPassword,
		changedDeveloperPassword,
		"request-developer-password",
	)
	developerOperation := createPaaSApplication(
		t,
		paasEndpoint,
		developerLogin.Credential,
		"application-process",
		"process-application",
		"create-application-process",
		http.StatusCreated,
	)
	if developerOperation.Scope != (paasv1.ResourceScope{
		Kind: paasv1.AuthorityTenant, TenantID: "organization-process",
	}) || developerOperation.RequestedBy != (paasv1.SubjectRef{
		Type: paasv1.SubjectUser, ID: string(developer.ID),
	}) {
		t.Fatalf("PaaS did not preserve exact IAM authority: %#v", developerOperation)
	}
	waitAllIAMOutboxDelivered(t, ctx, admin)
	waitAllPaaSOutboxDelivered(t, ctx, admin)
	assertPaaSAuditFact(
		t,
		ctx,
		admin,
		auditv1.ActionPaaSApplicationCreated,
		"application-process",
		string(developer.ID),
	)
	revokeIAMBinding(
		t,
		iamEndpoint,
		adminLogin.Credential,
		developerBinding.ID,
		"request-revoke-developer-binding",
	)
	deniedBefore := countAuditFacts(
		t,
		ctx,
		admin,
		auditv1.SourceIAM,
		auditv1.ActionIAMAuthorizationDecided,
		auditv1.ResultDenied,
	)
	createPaaSApplication(
		t,
		paasEndpoint,
		developerLogin.Credential,
		"application-denied",
		"denied-application",
		"create-application-denied",
		http.StatusForbidden,
	)
	assertPaaSApplicationAbsent(t, ctx, admin, "application-denied")
	waitAllIAMOutboxDelivered(t, ctx, admin)
	if deniedAfter := countAuditFacts(
		t,
		ctx,
		admin,
		auditv1.SourceIAM,
		auditv1.ActionIAMAuthorizationDecided,
		auditv1.ResultDenied,
	); deniedAfter != deniedBefore+1 {
		t.Fatalf("denied IAM Audit facts before=%d after=%d", deniedBefore, deniedAfter)
	}
	putIAMBinding(
		t,
		iamEndpoint,
		adminLogin.Credential,
		developer.ID,
		iamv1.RolePaaSDeveloper,
		"request-rebind-developer",
	)
	createPaaSConfiguration(
		t,
		paasEndpoint,
		developerLogin.Credential,
		"configuration-process",
		"process-configuration",
		"application-process",
		"create-configuration-process",
		http.StatusCreated,
	)
	waitAllIAMOutboxDelivered(t, ctx, admin)
	waitAllPaaSOutboxDelivered(t, ctx, admin)
	expireIAMSession(t, ctx, admin, developerLogin.Session.ID)
	getPaaSApplication(
		t,
		paasEndpoint,
		developerLogin.Credential,
		"application-process",
		http.StatusUnauthorized,
	)

	reader := createIAMUser(
		t,
		iamEndpoint,
		adminLogin.Credential,
		"audit.reader",
		"Audit Reader",
		initialReaderPassword,
		"request-create-reader",
	)
	binding := putIAMBinding(
		t,
		iamEndpoint,
		adminLogin.Credential,
		reader.ID,
		iamv1.RoleAuditReader,
		"request-bind-reader",
	)
	readerLogin := loginIAM(
		t,
		iamEndpoint,
		"audit.reader",
		initialReaderPassword,
		"request-reader-login",
	)
	sensitive = append(sensitive, readerLogin.Credential)
	changePasswordIAM(
		t,
		iamEndpoint,
		readerLogin.Credential,
		initialReaderPassword,
		changedReaderPassword,
		"request-reader-password",
	)
	createPaaSApplication(
		t,
		paasEndpoint,
		readerLogin.Credential,
		"application-reader-denied",
		"reader-denied-application",
		"create-application-reader-denied",
		http.StatusForbidden,
	)
	assertPaaSApplicationAbsent(t, ctx, admin, "application-reader-denied")
	queryAudit(t, auditEndpoint, readerLogin.Credential, auditv1.QueryRecordsRequest{PageSize: 10}, http.StatusOK)
	revokeIAMBinding(
		t,
		iamEndpoint,
		adminLogin.Credential,
		binding.ID,
		"request-revoke-reader-binding",
	)
	queryAudit(t, auditEndpoint, readerLogin.Credential, auditv1.QueryRecordsRequest{PageSize: 10}, http.StatusForbidden)
	putIAMBinding(
		t,
		iamEndpoint,
		adminLogin.Credential,
		reader.ID,
		iamv1.RoleAuditReader,
		"request-rebind-reader",
	)
	queryAudit(t, auditEndpoint, readerLogin.Credential, auditv1.QueryRecordsRequest{PageSize: 10}, http.StatusOK)
	revokeIAMSession(
		t,
		iamEndpoint,
		adminLogin.Credential,
		readerLogin.Session.ID,
		"request-revoke-reader-session",
	)
	queryAudit(t, auditEndpoint, readerLogin.Credential, auditv1.QueryRecordsRequest{PageSize: 10}, http.StatusUnauthorized)
	waitAllIAMOutboxDelivered(t, ctx, admin)
	verification := verifyAudit(t, auditEndpoint, adminLogin.Credential)
	if verification.TenantID != "organization-process" ||
		verification.State != auditv1.VerificationVerified || verification.RecordCount < 1 {
		t.Fatalf("cross-process Audit verification=%#v", verification)
	}
	assertAuditAccessRecorded(t, ctx, admin, auditv1.ActionAuditRecordsRead, "principal-admin")
	assertAuditAccessRecorded(t, ctx, admin, auditv1.ActionAuditIntegrityVerified, "principal-admin")
	iamProcess.stop()
	waitHTTPStatus(t, ctx, paasProcess, paasEndpoint+"/ready", http.StatusServiceUnavailable)
	createPaaSApplication(
		t,
		paasEndpoint,
		adminLogin.Credential,
		"application-iam-unavailable",
		"iam-unavailable-application",
		"create-application-iam-unavailable",
		http.StatusServiceUnavailable,
	)
	assertPaaSApplicationAbsent(t, ctx, admin, "application-iam-unavailable")
	queryAudit(
		t,
		auditEndpoint,
		adminLogin.Credential,
		auditv1.QueryRecordsRequest{PageSize: 10},
		http.StatusServiceUnavailable,
	)
	iamProcess = start(binaries.iam, iamEnvironment)
	waitHTTPStatus(t, ctx, iamProcess, iamEndpoint+"/ready", http.StatusOK)
	waitHTTPStatus(t, ctx, paasProcess, paasEndpoint+"/ready", http.StatusOK)
	paasProcess.stop()
	wrongPaaSEnvironment := append([]string(nil), paasEnvironment...)
	wrongPaaSEnvironment[2] = "MATRIX_PAAS_SERVICE_CREDENTIAL_FILE=" + wrongCredentialPath
	paasProcess = start(binaries.paas, wrongPaaSEnvironment)
	waitHTTPStatus(t, ctx, paasProcess, paasEndpoint+"/ready", http.StatusServiceUnavailable)
	createPaaSApplication(
		t,
		paasEndpoint,
		adminLogin.Credential,
		"application-wrong-service",
		"wrong-service-application",
		"create-application-wrong-service",
		http.StatusUnauthorized,
	)
	assertPaaSApplicationAbsent(t, ctx, admin, "application-wrong-service")
	paasProcess.stop()
	paasProcess = start(binaries.paas, paasEnvironment)
	waitHTTPStatus(t, ctx, paasProcess, paasEndpoint+"/ready", http.StatusOK)

	auditProcess.stop()
	outageUser := createIAMUser(
		t,
		iamEndpoint,
		adminLogin.Credential,
		"outage.user",
		"Outage User",
		"Initial-Outage-User-Password-68!",
		"request-create-outage-user",
	)
	createPaaSApplication(
		t,
		paasEndpoint,
		adminLogin.Credential,
		"application-audit-outage",
		"audit-outage-application",
		"create-application-audit-outage",
		http.StatusCreated,
	)
	waitIAMOutboxRetry(t, ctx, admin)
	waitPaaSOutboxRetry(t, ctx, admin)
	auditProcess = start(binaries.audit, auditEnvironment)
	waitHTTPStatus(t, ctx, auditProcess, auditEndpoint+"/ready", http.StatusOK)
	waitAllIAMOutboxDelivered(t, ctx, admin)
	waitAllPaaSOutboxDelivered(t, ctx, admin)
	outageEventID, outageEvent := findIAMEvent(
		t,
		ctx,
		admin,
		auditv1.ActionIAMPrincipalCreated,
		string(outageUser.ID),
	)
	var attemptsBefore int
	if err := admin.QueryRow(
		ctx,
		"SELECT attempts FROM iam.audit_outbox WHERE event_id = $1",
		outageEventID,
	).Scan(&attemptsBefore); err != nil {
		t.Fatalf("inspect IAM duplicate fixture: %v", err)
	}
	if _, err := admin.Exec(
		ctx,
		`UPDATE iam.audit_outbox
		    SET status = 'RETRY', worker_id = NULL, lease_expires_at = NULL,
		        next_attempt_at = transaction_timestamp(), error_code = NULL,
		        updated_at = transaction_timestamp()
		  WHERE event_id = $1 AND status = 'DELIVERED'`,
		outageEventID,
	); err != nil {
		t.Fatalf("inject IAM duplicate delivery: %v", err)
	}
	waitIAMEventDelivered(t, ctx, admin, outageEventID, attemptsBefore+1)
	assertAuditEventCount(t, ctx, admin, outageEventID, 1)
	changedEvent := outageEvent
	changedEvent.RequestID = "request-changed-replay"
	response := performJSON(
		t,
		http.MethodPost,
		auditEndpoint+"/v1/events",
		iamServiceCredential,
		changedEvent,
	)
	if response.Status != http.StatusConflict {
		t.Fatalf("changed Audit replay status=%d", response.Status)
	}
	assertAuditEventCount(t, ctx, admin, outageEventID, 1)
	paasEventID, paasEvent := findPaaSEvent(
		t,
		ctx,
		admin,
		auditv1.ActionPaaSApplicationCreated,
		"application-audit-outage",
	)
	var paasAttemptsBefore int
	if err := admin.QueryRow(
		ctx,
		"SELECT attempts FROM paas.audit_outbox WHERE event_id = $1",
		paasEventID,
	).Scan(&paasAttemptsBefore); err != nil {
		t.Fatalf("inspect PaaS duplicate fixture: %v", err)
	}
	if _, err := admin.Exec(
		ctx,
		`UPDATE paas.audit_outbox
		    SET status = 'RETRY', lease_owner = NULL, lease_expires_at = NULL,
		        available_at = transaction_timestamp(), last_error_code = NULL,
		        delivered_at = NULL, updated_at = transaction_timestamp()
		  WHERE event_id = $1 AND status = 'DELIVERED'`,
		paasEventID,
	); err != nil {
		t.Fatalf("inject PaaS duplicate delivery: %v", err)
	}
	waitPaaSEventDelivered(t, ctx, admin, paasEventID, paasAttemptsBefore+1)
	assertAuditSourceEventCount(t, ctx, admin, auditv1.SourcePaaS, paasEventID, 1)
	changedPaaSEvent := paasEvent
	changedPaaSEvent.RequestID = "request-changed-paas-replay"
	response = performJSON(
		t,
		http.MethodPost,
		auditEndpoint+"/v1/events",
		paasServiceCredential,
		changedPaaSEvent,
	)
	if response.Status != http.StatusConflict {
		t.Fatalf("changed PaaS Audit replay status=%d", response.Status)
	}
	assertAuditSourceEventCount(t, ctx, admin, auditv1.SourcePaaS, paasEventID, 1)

	waitAllIAMOutboxDelivered(t, ctx, admin)
	waitAllPaaSOutboxDelivered(t, ctx, admin)
	paasDispatcher.stop()
	createPaaSApplication(
		t,
		paasEndpoint,
		adminLogin.Credential,
		"application-dead-letter",
		"dead-letter-application",
		"create-application-dead-letter",
		http.StatusCreated,
	)
	wrongPaaSDispatcher := start(
		binaries.paasDispatcher,
		paasDispatcherEnvironment(wrongCredentialPath, "paas-audit-worker-wrong"),
	)
	waitPaaSDeadLetter(t, ctx, admin)
	waitHTTPStatus(t, ctx, paasProcess, paasEndpoint+"/ready", http.StatusServiceUnavailable)
	wrongPaaSDispatcher.stop()

	dispatcher.stop()
	createIAMUser(
		t,
		iamEndpoint,
		adminLogin.Credential,
		"deadletter.user",
		"Dead Letter User",
		"Initial-Dead-Letter-Password-79!",
		"request-create-deadletter-user",
	)
	wrongDispatcher := start(
		binaries.dispatcher,
		iamDispatcherEnvironment(wrongCredentialPath, "iam-audit-worker-wrong"),
	)
	waitIAMDeadLetter(t, ctx, admin)
	waitHTTPStatus(t, ctx, iamProcess, iamEndpoint+"/ready", http.StatusServiceUnavailable)
	wrongDispatcher.stop()
	assertAuthorityPlaintextAbsent(
		t,
		ctx,
		admin,
		initialAdminPassword,
		changedAdminPassword,
		initialReaderPassword,
		changedReaderPassword,
		initialDeveloperPassword,
		changedDeveloperPassword,
		iamServiceCredential,
		paasServiceCredential,
		auditServiceCredential,
		adminLogin.Credential,
		readerLogin.Credential,
		developerLogin.Credential,
	)
}

type binarySet struct {
	iam            string
	audit          string
	dispatcher     string
	paas           string
	paasDispatcher string
}

func buildAuthorityBinaries(
	t *testing.T,
	ctx context.Context,
	root string,
	temporary string,
) binarySet {
	t.Helper()
	suffix := ""
	if runtime.GOOS == "windows" {
		suffix = ".exe"
	}
	build := func(name, packagePath string) string {
		path := filepath.Join(temporary, name+suffix)
		command := exec.CommandContext(ctx, "go", "build", "-o", path, packagePath)
		command.Dir = root
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("build %s: %v\n%s", name, err, output)
		}
		return path
	}
	return binarySet{
		iam:            build("matrix-iam", "./app/service/iam/cmd/matrix-iam"),
		audit:          build("matrix-audit", "./app/service/audit/cmd/matrix-audit"),
		dispatcher:     build("matrix-iam-audit-dispatcher", "./app/service/iam/cmd/matrix-iam-audit-dispatcher"),
		paas:           build("matrix-paas", "./app/service/paas/cmd/matrix-paas"),
		paasDispatcher: build("matrix-paas-audit-dispatcher", "./app/service/paas/cmd/matrix-paas-audit-dispatcher"),
	}
}

type childProcess struct {
	command *exec.Cmd
	done    chan error
	stdout  bytes.Buffer
	stderr  bytes.Buffer
	exited  bool
	err     error
}

var errProcessWaitTimeout = errors.New("authority process wait timed out")

func startChild(
	t *testing.T,
	root string,
	binary string,
	environment []string,
) *childProcess {
	t.Helper()
	child := &childProcess{done: make(chan error, 1)}
	child.command = exec.Command(binary)
	child.command.Dir = root
	child.command.Env = append(os.Environ(), environment...)
	child.command.Stdout = &child.stdout
	child.command.Stderr = &child.stderr
	if err := child.command.Start(); err != nil {
		t.Fatalf("start authority process: %v", err)
	}
	go func() { child.done <- child.command.Wait() }()
	return child
}

func (child *childProcess) poll() (bool, error) {
	if child.exited {
		return true, child.err
	}
	select {
	case child.err = <-child.done:
		child.exited = true
		return true, child.err
	default:
		return false, nil
	}
}

func (child *childProcess) wait(timeout time.Duration) error {
	if child.exited {
		return child.err
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case child.err = <-child.done:
		child.exited = true
		return child.err
	case <-timer.C:
		return errProcessWaitTimeout
	}
}

func (child *childProcess) stop() {
	if child == nil || child.exited || child.command == nil || child.command.Process == nil {
		return
	}
	_ = child.command.Process.Kill()
	_ = child.wait(10 * time.Second)
}

func (child *childProcess) output() string {
	return child.stdout.String() + child.stderr.String()
}

func waitHTTPStatus(
	t *testing.T,
	ctx context.Context,
	child *childProcess,
	endpoint string,
	want int,
) {
	t.Helper()
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		if exited, err := child.poll(); exited {
			t.Fatalf("authority process exited before HTTP status %d: %v output=%q", want, err, child.output())
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			t.Fatalf("create authority readiness request: %v", err)
		}
		response, err := processHTTPClient().Do(request)
		if err == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64*1024))
			_ = response.Body.Close()
			if response.StatusCode == want {
				return
			}
		}
		select {
		case <-ctx.Done():
			t.Fatalf("authority readiness context: %v", ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
	t.Fatalf("authority endpoint %s did not return %d", endpoint, want)
}

type processResponse struct {
	Status int
	Body   []byte
}

func performJSON(
	t *testing.T,
	method string,
	endpoint string,
	bearer string,
	body any,
) processResponse {
	t.Helper()
	return performJSONWithIdempotency(t, method, endpoint, bearer, "", body)
}

func performJSONWithIdempotency(
	t *testing.T,
	method string,
	endpoint string,
	bearer string,
	idempotencyKey string,
	body any,
) processResponse {
	t.Helper()
	var encoded []byte
	var err error
	if body != nil {
		encoded, err = json.Marshal(body)
		if err != nil {
			t.Fatalf("encode authority HTTP request: %v", err)
		}
	}
	request, err := http.NewRequest(method, endpoint, bytes.NewReader(encoded))
	if err != nil {
		t.Fatalf("create authority HTTP request: %v", err)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	if idempotencyKey != "" {
		request.Header.Set("Idempotency-Key", idempotencyKey)
	}
	response, err := processHTTPClient().Do(request)
	if err != nil {
		t.Fatalf("call authority HTTP endpoint: %v", err)
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, 2*1024*1024))
	if err != nil {
		t.Fatalf("read authority HTTP response: %v", err)
	}
	return processResponse{Status: response.StatusCode, Body: responseBody}
}

var authorityHTTPClient = newProcessHTTPClient()

func processHTTPClient() *http.Client {
	return authorityHTTPClient
}

func newProcessHTTPClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

type loginResult struct {
	Session    iamv1.Session
	Credential string
}

func loginIAM(
	t *testing.T,
	endpoint string,
	loginName string,
	password string,
	requestID string,
) loginResult {
	t.Helper()
	response := performJSON(t, http.MethodPost, endpoint+"/v1/auth/login", "", struct {
		LoginName string `json:"loginName"`
		Password  string `json:"password"`
		RequestID string `json:"requestId"`
	}{LoginName: loginName, Password: password, RequestID: requestID})
	if response.Status != http.StatusOK {
		t.Fatalf("IAM login %s status=%d", loginName, response.Status)
	}
	var wire struct {
		Session    iamv1.Session `json:"session"`
		Credential string        `json:"credential"`
	}
	if err := json.Unmarshal(response.Body, &wire); err != nil ||
		iamv1.ValidateSession(wire.Session) != nil || wire.Credential == "" {
		t.Fatalf("decode IAM login for %s: %v", loginName, err)
	}
	return loginResult{Session: wire.Session, Credential: wire.Credential}
}

func assertIAMWeakLoginRejected(t *testing.T, endpoint string) {
	t.Helper()
	const weakPassword = "weak"
	response := performJSON(t, http.MethodPost, endpoint+"/v1/auth/login", "", struct {
		LoginName string `json:"loginName"`
		Password  string `json:"password"`
		RequestID string `json:"requestId"`
	}{LoginName: "admin", Password: weakPassword, RequestID: "request-weak-login"})
	if response.Status != http.StatusUnauthorized ||
		bytes.Contains(response.Body, []byte(weakPassword)) {
		t.Fatalf("weak IAM login status=%d body=%s", response.Status, response.Body)
	}
}

func changePasswordIAM(
	t *testing.T,
	endpoint string,
	bearer string,
	current string,
	next string,
	requestID string,
) {
	t.Helper()
	response := performJSON(t, http.MethodPost, endpoint+"/v1/auth/password", bearer, struct {
		CurrentPassword string `json:"currentPassword"`
		NewPassword     string `json:"newPassword"`
		RequestID       string `json:"requestId"`
	}{CurrentPassword: current, NewPassword: next, RequestID: requestID})
	if response.Status != http.StatusOK {
		t.Fatalf("IAM password change status=%d", response.Status)
	}
}

func createIAMUser(
	t *testing.T,
	endpoint string,
	bearer string,
	loginName string,
	displayName string,
	password string,
	requestID string,
) iamv1.Principal {
	t.Helper()
	response := performJSON(t, http.MethodPost, endpoint+"/v1/principals", bearer, struct {
		LoginName       string `json:"loginName"`
		DisplayName     string `json:"displayName"`
		InitialPassword string `json:"initialPassword"`
		RequestID       string `json:"requestId"`
	}{LoginName: loginName, DisplayName: displayName, InitialPassword: password, RequestID: requestID})
	if response.Status != http.StatusCreated {
		t.Fatalf("create IAM user %s status=%d", loginName, response.Status)
	}
	var principal iamv1.Principal
	if err := json.Unmarshal(response.Body, &principal); err != nil ||
		iamv1.ValidatePrincipal(principal) != nil {
		t.Fatalf("decode IAM user %s: %v", loginName, err)
	}
	return principal
}

func putIAMBinding(
	t *testing.T,
	endpoint string,
	bearer string,
	principalID iamv1.PrincipalID,
	role iamv1.BuiltinRole,
	requestID string,
) iamv1.RoleBinding {
	t.Helper()
	response := performJSON(t, http.MethodPost, endpoint+"/v1/role-bindings", bearer, iamv1.PutRoleBindingRequest{
		PrincipalID: principalID, Role: role, RequestID: requestID,
	})
	if response.Status != http.StatusOK {
		t.Fatalf("put IAM binding status=%d", response.Status)
	}
	var binding iamv1.RoleBinding
	if err := json.Unmarshal(response.Body, &binding); err != nil ||
		iamv1.ValidateRoleBinding(binding) != nil {
		t.Fatalf("decode IAM binding: %v", err)
	}
	return binding
}

func revokeIAMBinding(
	t *testing.T,
	endpoint string,
	bearer string,
	bindingID iamv1.RoleBindingID,
	requestID string,
) {
	t.Helper()
	response := performJSON(
		t,
		http.MethodPost,
		endpoint+"/v1/role-bindings/"+string(bindingID)+":revoke",
		bearer,
		iamv1.RevokeRoleBindingRequest{RequestID: requestID},
	)
	if response.Status != http.StatusOK {
		t.Fatalf("revoke IAM binding status=%d", response.Status)
	}
}

func revokeIAMSession(
	t *testing.T,
	endpoint string,
	bearer string,
	sessionID iamv1.SessionID,
	requestID string,
) {
	t.Helper()
	response := performJSON(
		t,
		http.MethodPost,
		endpoint+"/v1/sessions/"+string(sessionID)+":revoke",
		bearer,
		iamv1.RevokeSessionRequest{RequestID: requestID},
	)
	if response.Status != http.StatusOK {
		t.Fatalf("revoke IAM session status=%d", response.Status)
	}
}

func expireIAMSession(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	sessionID iamv1.SessionID,
) {
	t.Helper()
	var expired bool
	if err := admin.QueryRow(
		ctx,
		`UPDATE iam.sessions
		    SET expires_at = issued_at + interval '1 microsecond'
		  WHERE tenant_id = 'organization-process'
		    AND id = $1
		    AND status = 'ACTIVE'
		RETURNING expires_at < transaction_timestamp()`,
		sessionID,
	).Scan(&expired); err != nil {
		t.Fatalf("expire IAM session: %v", err)
	}
	if !expired {
		t.Fatal("IAM session fixture did not expire in database time")
	}
}

func assertCrossTenantIAMBindingRejected(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	endpoint string,
	bearer string,
) {
	t.Helper()
	const (
		crossTenantID    = "organization-process-cross-tenant"
		crossPrincipalID = "principal-process-cross-tenant"
	)
	if _, err := admin.Exec(
		ctx,
		`INSERT INTO iam.organizations (
			id, display_name, status, resource_version, created_at, updated_at
		) VALUES (
			$1, 'Process Cross Tenant', 'ACTIVE', 1,
			transaction_timestamp(), transaction_timestamp()
		);
		INSERT INTO iam.principals (
			tenant_id, id, principal_type, login_name, display_name, status,
			must_change_password, resource_version, created_at, updated_at
		) VALUES (
			$1, $2, 'USER', 'process.cross.tenant', 'Process Cross Tenant User',
			'ACTIVE', true, 1, transaction_timestamp(), transaction_timestamp()
		);`,
		crossTenantID,
		crossPrincipalID,
	); err != nil {
		t.Fatalf("insert cross-tenant IAM process fixture: %v", err)
	}
	response := performJSON(
		t,
		http.MethodPost,
		endpoint+"/v1/role-bindings",
		bearer,
		iamv1.PutRoleBindingRequest{
			PrincipalID: crossPrincipalID,
			Role:        iamv1.RolePaaSDeveloper,
			RequestID:   "request-process-cross-tenant-binding",
		},
	)
	if response.Status != http.StatusForbidden ||
		bytes.Contains(response.Body, []byte(crossPrincipalID)) ||
		bytes.Contains(response.Body, []byte("role binding principal")) {
		t.Fatalf("cross-tenant IAM binding status=%d body=%s", response.Status, response.Body)
	}
	var bindings int
	if err := admin.QueryRow(
		ctx,
		"SELECT count(*) FROM iam.role_bindings WHERE tenant_id = $1",
		crossTenantID,
	).Scan(&bindings); err != nil {
		t.Fatalf("inspect cross-tenant IAM process bindings: %v", err)
	}
	if bindings != 0 {
		t.Fatalf("cross-tenant IAM process bindings=%d want=0", bindings)
	}
}

func createPaaSApplication(
	t *testing.T,
	endpoint string,
	bearer string,
	id paasv1.ResourceID,
	name string,
	idempotencyKey string,
	status int,
) paasv1.Operation {
	t.Helper()
	response := performJSONWithIdempotency(
		t,
		http.MethodPost,
		endpoint+"/v1/applications",
		bearer,
		idempotencyKey,
		paasv1.CreateApplicationRequest{ID: id, Name: name},
	)
	if response.Status != status {
		t.Fatalf("create PaaS application %s status=%d want=%d", id, response.Status, status)
	}
	if status != http.StatusCreated && status != http.StatusOK {
		return paasv1.Operation{}
	}
	var operation paasv1.Operation
	if err := json.Unmarshal(response.Body, &operation); err != nil ||
		paasv1.ValidateOperation(operation) != nil ||
		operation.Action != paasv1.OperationCreateApplication ||
		operation.Target != (paasv1.ResourceRef{Kind: "Application", ID: id}) {
		t.Fatalf("decode PaaS application operation: operation=%#v err=%v", operation, err)
	}
	return operation
}

func createPaaSConfiguration(
	t *testing.T,
	endpoint string,
	bearer string,
	id paasv1.ResourceID,
	name string,
	applicationID paasv1.ResourceID,
	idempotencyKey string,
	status int,
) {
	t.Helper()
	response := performJSONWithIdempotency(
		t,
		http.MethodPost,
		endpoint+"/v1/configurations",
		bearer,
		idempotencyKey,
		paasv1.CreateConfigurationRequest{
			ID: id, Name: name, ApplicationID: applicationID,
		},
	)
	if response.Status != status {
		t.Fatalf("create PaaS configuration %s status=%d want=%d", id, response.Status, status)
	}
	if status != http.StatusCreated && status != http.StatusOK {
		return
	}
	var operation paasv1.Operation
	if err := json.Unmarshal(response.Body, &operation); err != nil ||
		paasv1.ValidateOperation(operation) != nil ||
		operation.Action != paasv1.OperationCreateConfiguration ||
		operation.Target != (paasv1.ResourceRef{Kind: "Configuration", ID: id}) {
		t.Fatalf("decode PaaS configuration operation: operation=%#v err=%v", operation, err)
	}
}

func getPaaSApplication(
	t *testing.T,
	endpoint string,
	bearer string,
	id paasv1.ResourceID,
	status int,
) {
	t.Helper()
	response := performJSON(
		t,
		http.MethodGet,
		endpoint+"/v1/applications/"+string(id),
		bearer,
		nil,
	)
	if response.Status != status {
		t.Fatalf("get PaaS application %s status=%d want=%d", id, response.Status, status)
	}
	if status != http.StatusOK {
		return
	}
	var application paasv1.Application
	if err := json.Unmarshal(response.Body, &application); err != nil ||
		paasv1.ValidateApplication(application) != nil || application.Metadata.ID != id {
		t.Fatalf("decode PaaS application: application=%#v err=%v", application, err)
	}
}

func queryAudit(
	t *testing.T,
	endpoint string,
	bearer string,
	request auditv1.QueryRecordsRequest,
	status int,
) auditv1.RecordPage {
	t.Helper()
	response := performJSON(t, http.MethodPost, endpoint+"/v1/records:query", bearer, request)
	if response.Status != status {
		t.Fatalf("query Audit status=%d want=%d", response.Status, status)
	}
	if status != http.StatusOK {
		return auditv1.RecordPage{}
	}
	var page auditv1.RecordPage
	if err := json.Unmarshal(response.Body, &page); err != nil ||
		auditv1.ValidateRecordPage(page) != nil {
		t.Fatalf("decode Audit page: %v", err)
	}
	return page
}

func assertAuditQueryConfinement(t *testing.T, endpoint string, bearer string) {
	t.Helper()
	first := queryAudit(
		t,
		endpoint,
		bearer,
		auditv1.QueryRecordsRequest{PageSize: 1},
		http.StatusOK,
	)
	if first.NextCursor == "" {
		t.Fatal("Audit query confinement fixture did not produce a cursor")
	}
	changedFilter := performJSON(
		t,
		http.MethodPost,
		endpoint+"/v1/records:query",
		bearer,
		auditv1.QueryRecordsRequest{
			PageSize: 1,
			Cursor:   first.NextCursor,
			Action:   auditv1.ActionIAMBootstrapApplied,
		},
	)
	if changedFilter.Status != http.StatusUnprocessableEntity {
		t.Fatalf("cross-filter Audit cursor status=%d", changedFilter.Status)
	}
	const crossTenantID = "organization-process-cross-tenant"
	tenantSelector := performJSON(
		t,
		http.MethodPost,
		endpoint+"/v1/records:query",
		bearer,
		struct {
			PageSize int    `json:"pageSize"`
			TenantID string `json:"tenantId"`
		}{PageSize: 10, TenantID: crossTenantID},
	)
	if tenantSelector.Status != http.StatusBadRequest ||
		bytes.Contains(tenantSelector.Body, []byte(crossTenantID)) {
		t.Fatalf("tenant-selecting Audit query status=%d body=%s", tenantSelector.Status, tenantSelector.Body)
	}
}

func verifyAudit(
	t *testing.T,
	endpoint string,
	bearer string,
) auditv1.ChainVerification {
	t.Helper()
	response := performJSON(
		t,
		http.MethodPost,
		endpoint+"/v1/integrity:verify",
		bearer,
		auditv1.VerifyChainRequest{FromSequence: 1, MaximumRecords: auditv1.MaxVerifyRecords},
	)
	if response.Status != http.StatusOK {
		t.Fatalf("verify Audit status=%d", response.Status)
	}
	var verification auditv1.ChainVerification
	if err := json.Unmarshal(response.Body, &verification); err != nil ||
		auditv1.ValidateChainVerification(verification) != nil {
		t.Fatalf("decode Audit verification: %v", err)
	}
	return verification
}

func waitAllIAMOutboxDelivered(t *testing.T, ctx context.Context, admin *pgx.Conn) {
	t.Helper()
	waitDatabase(t, ctx, "IAM Audit outbox delivery", func() (bool, error) {
		var outstanding int
		err := admin.QueryRow(
			ctx,
			"SELECT count(*) FROM iam.audit_outbox WHERE status <> 'DELIVERED'",
		).Scan(&outstanding)
		return outstanding == 0, err
	})
}

func waitIAMOutboxRetry(t *testing.T, ctx context.Context, admin *pgx.Conn) {
	t.Helper()
	waitDatabase(t, ctx, "IAM Audit outage retry", func() (bool, error) {
		var retries int
		err := admin.QueryRow(
			ctx,
			"SELECT count(*) FROM iam.audit_outbox WHERE status = 'RETRY' AND attempts >= 1",
		).Scan(&retries)
		return retries > 0, err
	})
}

func waitIAMDeadLetter(t *testing.T, ctx context.Context, admin *pgx.Conn) {
	t.Helper()
	waitDatabase(t, ctx, "IAM Audit dead letter", func() (bool, error) {
		var dead int
		err := admin.QueryRow(
			ctx,
			"SELECT count(*) FROM iam.audit_outbox WHERE status = 'DEAD_LETTER'",
		).Scan(&dead)
		return dead > 0, err
	})
}

func waitIAMEventDelivered(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	eventID string,
	minimumAttempts int,
) {
	t.Helper()
	waitDatabase(t, ctx, "IAM Audit duplicate delivery", func() (bool, error) {
		var status string
		var attempts int
		err := admin.QueryRow(
			ctx,
			"SELECT status, attempts FROM iam.audit_outbox WHERE event_id = $1",
			eventID,
		).Scan(&status, &attempts)
		return status == "DELIVERED" && attempts >= minimumAttempts, err
	})
}

func waitAllPaaSOutboxDelivered(t *testing.T, ctx context.Context, admin *pgx.Conn) {
	t.Helper()
	waitDatabase(t, ctx, "PaaS Audit outbox delivery", func() (bool, error) {
		var outstanding int
		err := admin.QueryRow(
			ctx,
			"SELECT count(*) FROM paas.audit_outbox WHERE status <> 'DELIVERED'",
		).Scan(&outstanding)
		return outstanding == 0, err
	})
}

func waitPaaSOutboxRetry(t *testing.T, ctx context.Context, admin *pgx.Conn) {
	t.Helper()
	waitDatabase(t, ctx, "PaaS Audit outage retry", func() (bool, error) {
		var retries int
		err := admin.QueryRow(
			ctx,
			"SELECT count(*) FROM paas.audit_outbox WHERE status = 'RETRY' AND attempts >= 1",
		).Scan(&retries)
		return retries > 0, err
	})
}

func waitPaaSDeadLetter(t *testing.T, ctx context.Context, admin *pgx.Conn) {
	t.Helper()
	waitDatabase(t, ctx, "PaaS Audit dead letter", func() (bool, error) {
		var dead int
		err := admin.QueryRow(
			ctx,
			"SELECT count(*) FROM paas.audit_outbox WHERE status = 'DEAD_LETTER'",
		).Scan(&dead)
		return dead > 0, err
	})
}

func waitPaaSEventDelivered(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	eventID string,
	minimumAttempts int,
) {
	t.Helper()
	waitDatabase(t, ctx, "PaaS Audit duplicate delivery", func() (bool, error) {
		var status string
		var attempts int
		err := admin.QueryRow(
			ctx,
			"SELECT status, attempts FROM paas.audit_outbox WHERE event_id = $1",
			eventID,
		).Scan(&status, &attempts)
		return status == "DELIVERED" && attempts >= minimumAttempts, err
	})
}

func waitDatabase(
	t *testing.T,
	ctx context.Context,
	description string,
	condition func() (bool, error),
) {
	t.Helper()
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		ready, err := condition()
		if err != nil {
			t.Fatalf("inspect %s: %v", description, err)
		}
		if ready {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("wait for %s: %v", description, ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
	t.Fatalf("timed out waiting for %s", description)
}

func findIAMEvent(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	action auditv1.Action,
	targetID string,
) (string, auditv1.Event) {
	t.Helper()
	var eventID string
	var document []byte
	if err := admin.QueryRow(
		ctx,
		`SELECT event_id, event_document
		   FROM iam.audit_outbox
		  WHERE event_document->>'action' = $1
		    AND event_document#>>'{target,id}' = $2`,
		string(action),
		targetID,
	).Scan(&eventID, &document); err != nil {
		t.Fatalf("find IAM Audit event: %v", err)
	}
	defer clear(document)
	var event auditv1.Event
	if err := auditv1.DecodeRequest(bytes.NewReader(document), &event); err != nil ||
		auditv1.ValidateEventForSource(auditv1.SourceIAM, event) != nil {
		t.Fatalf("decode IAM Audit event: %v", err)
	}
	return eventID, event
}

func findPaaSEvent(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	action auditv1.Action,
	targetID string,
) (string, auditv1.Event) {
	t.Helper()
	var eventID string
	var document []byte
	if err := admin.QueryRow(
		ctx,
		`SELECT outbox.event_id, record.event_document
		   FROM paas.audit_outbox AS outbox
		   JOIN audit.records AS record
		     ON record.source = 'PAAS' AND record.event_id = outbox.event_id
		  WHERE outbox.document->>'action' = $1
		    AND outbox.document#>>'{target,id}' = $2`,
		string(action),
		targetID,
	).Scan(&eventID, &document); err != nil {
		t.Fatalf("find PaaS Audit event: %v", err)
	}
	defer clear(document)
	var event auditv1.Event
	if err := auditv1.DecodeRequest(bytes.NewReader(document), &event); err != nil ||
		auditv1.ValidateEventForSource(auditv1.SourcePaaS, event) != nil {
		t.Fatalf("decode PaaS Audit event: %v", err)
	}
	return eventID, event
}

func assertIAMEventsStoredOnce(t *testing.T, ctx context.Context, admin *pgx.Conn) {
	t.Helper()
	var outbox, records int
	if err := admin.QueryRow(
		ctx,
		`SELECT
			(SELECT count(*) FROM iam.audit_outbox),
			(SELECT count(*) FROM audit.records WHERE source = 'IAM')`,
	).Scan(&outbox, &records); err != nil {
		t.Fatalf("inspect initial IAM Audit delivery: %v", err)
	}
	if outbox != 1 || records != 1 {
		t.Fatalf("initial IAM Audit outbox=%d records=%d", outbox, records)
	}
}

func assertAuditEventCount(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	eventID string,
	want int,
) {
	t.Helper()
	assertAuditSourceEventCount(t, ctx, admin, auditv1.SourceIAM, eventID, want)
}

func assertAuditSourceEventCount(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	source auditv1.Source,
	eventID string,
	want int,
) {
	t.Helper()
	var count int
	if err := admin.QueryRow(
		ctx,
		"SELECT count(*) FROM audit.records WHERE source = $1 AND event_id = $2",
		string(source),
		eventID,
	).Scan(&count); err != nil {
		t.Fatalf("count Audit event %s: %v", eventID, err)
	}
	if count != want {
		t.Fatalf("Audit event %s count=%d want=%d", eventID, count, want)
	}
}

func assertPaaSAuditFact(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	action auditv1.Action,
	targetID string,
	actorID string,
) {
	t.Helper()
	var count int
	if err := admin.QueryRow(
		ctx,
		`SELECT count(*)
		   FROM paas.audit_outbox AS outbox
		   JOIN iam.authorization_decisions AS decision
		     ON decision.tenant_id = outbox.tenant_id
		    AND decision.id = outbox.document->>'iamDecisionId'
		   JOIN audit.records AS record
		     ON record.source = 'PAAS'
		    AND record.event_id = outbox.event_id
		  WHERE outbox.document->>'action' = $1
		    AND outbox.document#>>'{target,id}' = $2
		    AND outbox.document#>>'{actor,id}' = $3
		    AND decision.allowed
		    AND decision.principal_id = $3
		    AND record.event_document->>'iamDecisionId' = decision.id
		    AND record.event_document#>>'{actor,id}' = decision.principal_id`,
		string(action),
		targetID,
		actorID,
	).Scan(&count); err != nil {
		t.Fatalf("inspect PaaS Audit fact: %v", err)
	}
	if count != 1 {
		t.Fatalf("PaaS Audit fact action=%s target=%s actor=%s count=%d", action, targetID, actorID, count)
	}
}

func countAuditFacts(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	source auditv1.Source,
	action auditv1.Action,
	result auditv1.Result,
) int {
	t.Helper()
	var count int
	if err := admin.QueryRow(
		ctx,
		`SELECT count(*)
		   FROM audit.records
		  WHERE source = $1
		    AND event_document->>'action' = $2
		    AND event_document->>'result' = $3`,
		string(source),
		string(action),
		string(result),
	).Scan(&count); err != nil {
		t.Fatalf("count Audit facts source=%s action=%s result=%s: %v", source, action, result, err)
	}
	return count
}

func assertAuditAccessRecorded(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	action auditv1.Action,
	actorID string,
) {
	t.Helper()
	var count int
	if err := admin.QueryRow(
		ctx,
		`SELECT count(*)
		   FROM audit.records
		  WHERE tenant_id = 'organization-process'
		    AND source = 'AUDIT'
		    AND event_document->>'action' = $1
		    AND event_document#>>'{actor,id}' = $2`,
		string(action),
		actorID,
	).Scan(&count); err != nil {
		t.Fatalf("inspect Audit access fact: %v", err)
	}
	if count < 1 {
		t.Fatalf("Audit access fact action=%s actor=%s count=%d", action, actorID, count)
	}
}

func assertPaaSApplicationAbsent(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	id paasv1.ResourceID,
) {
	t.Helper()
	var count int
	if err := admin.QueryRow(
		ctx,
		"SELECT count(*) FROM paas.applications WHERE id = $1",
		id,
	).Scan(&count); err != nil {
		t.Fatalf("inspect absent PaaS application %s: %v", id, err)
	}
	if count != 0 {
		t.Fatalf("denied PaaS application %s was persisted", id)
	}
}

func assertAuthorityPlaintextAbsent(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	plaintexts ...string,
) {
	t.Helper()
	for _, plaintext := range plaintexts {
		var present bool
		if err := admin.QueryRow(
			ctx,
			`SELECT
				EXISTS (
					SELECT 1 FROM iam.audit_outbox
					 WHERE event_document::text LIKE '%' || $1 || '%'
				)
				OR EXISTS (
					SELECT 1 FROM paas.audit_outbox
					 WHERE document::text LIKE '%' || $1 || '%'
				)
				OR EXISTS (
					SELECT 1 FROM paas.operations
					 WHERE document::text LIKE '%' || $1 || '%'
				)
				OR EXISTS (
					SELECT 1 FROM audit.records
					 WHERE event_document::text LIKE '%' || $1 || '%'
					    OR canonical_document LIKE '%' || $1 || '%'
				)`,
			plaintext,
		).Scan(&present); err != nil {
			t.Fatalf("inspect authority plaintext storage: %v", err)
		}
		if present {
			t.Fatal("authority stored plaintext credential")
		}
	}
}

func assertProcessOutputsSanitized(
	t *testing.T,
	children []*childProcess,
	plaintexts ...string,
) {
	t.Helper()
	for _, child := range children {
		output := child.output()
		for _, plaintext := range plaintexts {
			if strings.Contains(output, plaintext) {
				t.Fatal("authority process output leaked credential material")
			}
		}
	}
}

func processBootstrap(t *testing.T) iamv1.BootstrapDocument {
	t.Helper()
	service := func(
		purpose iamv1.ServicePurpose,
		principalID string,
		credential string,
	) iamv1.BootstrapServiceCredential {
		return iamv1.BootstrapServiceCredential{
			Purpose: purpose, PrincipalID: iamv1.PrincipalID(principalID),
			Credential: processSecret(t, credential),
		}
	}
	return iamv1.BootstrapDocument{
		APIVersion:     iamv1.APIVersion,
		Kind:           "IAMBootstrap",
		InstallationID: "installation-process",
		Organization: iamv1.InitialOrganization{
			ID: "organization-process", DisplayName: "Process Organization",
		},
		Administrator: iamv1.InitialAdministrator{
			ID: "principal-admin", LoginName: "admin", DisplayName: "Administrator",
			Password: processSecret(t, initialAdminPassword),
		},
		Services: []iamv1.BootstrapServiceCredential{
			service(iamv1.ServiceIAM, "service-iam", iamServiceCredential),
			service(iamv1.ServicePaaS, "service-paas", paasServiceCredential),
			service(iamv1.ServiceAudit, "service-audit", auditServiceCredential),
			service(iamv1.ServiceAPISIX, "service-apisix", "mx1.ProcessAPISIXCredential0000000000000000001"),
			service(iamv1.ServiceInstallationVerifier, "service-verifier", "mx1.ProcessVerifierCredential0000000000000001"),
		},
	}
}

func processSecret(t *testing.T, plaintext string) iamv1.Secret {
	t.Helper()
	secret, err := iamv1.NewSecret(plaintext)
	if err != nil {
		t.Fatalf("create authority process secret: %v", err)
	}
	return secret
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve authority process test source")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", ".."))
}

func assertPostgres18(t *testing.T, ctx context.Context, admin *pgx.Conn) {
	t.Helper()
	var version int
	if err := admin.QueryRow(ctx, "SELECT current_setting('server_version_num')::integer").Scan(&version); err != nil {
		t.Fatalf("read authority process PostgreSQL version: %v", err)
	}
	if version < 180000 || version >= 190000 {
		t.Fatalf("PostgreSQL version=%d want major 18", version)
	}
}

func assertCleanSchemas(t *testing.T, ctx context.Context, admin *pgx.Conn) {
	t.Helper()
	var iamExists, auditExists, paasExists bool
	if err := admin.QueryRow(
		ctx,
		`SELECT to_regnamespace('iam') IS NOT NULL,
		        to_regnamespace('audit') IS NOT NULL,
		        to_regnamespace('paas') IS NOT NULL`,
	).Scan(&iamExists, &auditExists, &paasExists); err != nil {
		t.Fatalf("inspect platform process schemas: %v", err)
	}
	if iamExists || auditExists || paasExists {
		t.Fatal("platform process integration database is not clean")
	}
}

func applyPlatformSchemas(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	root string,
) {
	t.Helper()
	authorityPath := func(service string, file string) string {
		return filepath.Join(
			root,
			"app", "service", service, "internal", "data", "postgres",
			"migrations", "000001_authority", file,
		)
	}
	paasPath := func(file string) string {
		return filepath.Join(
			root,
			"app", "service", "paas", "internal", "apphosting", "data", "postgres",
			"migrations", "000001_placement_core", file,
		)
	}
	for _, path := range []string{
		authorityPath("iam", "bootstrap.sql"),
		authorityPath("audit", "bootstrap.sql"),
		authorityPath("iam", "up.sql"),
		authorityPath("audit", "up.sql"),
		paasPath("up.sql"),
		authorityPath("iam", "verify.sql"),
		authorityPath("audit", "verify.sql"),
		paasPath("verify.sql"),
	} {
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read platform process migration: %v", err)
		}
		if _, err := admin.Exec(ctx, string(source)); err != nil {
			t.Fatalf("apply platform process migration %s: %v", filepath.Base(path), err)
		}
	}
}

func createProcessLogins(t *testing.T, ctx context.Context, admin *pgx.Conn) {
	t.Helper()
	for _, binding := range []struct {
		login string
		group string
	}{
		{iamAPILogin, "matrix_iam_api"},
		{iamWorkerLogin, "matrix_iam_worker"},
		{auditRuntimeLogin, "matrix_audit_runtime"},
		{paasAPILogin, "matrix_paas_api"},
		{paasWorkerLogin, "matrix_paas_worker"},
	} {
		statement := fmt.Sprintf(`DO $matrix_process_role$
		BEGIN
			IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = %s) THEN
				CREATE ROLE %s LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE
					NOREPLICATION NOBYPASSRLS;
			END IF;
		END
		$matrix_process_role$;
		ALTER ROLE %s PASSWORD %s;
		GRANT %s TO %s;`,
			quoteLiteral(binding.login),
			pgx.Identifier{binding.login}.Sanitize(),
			pgx.Identifier{binding.login}.Sanitize(),
			quoteLiteral(processDBPassword),
			pgx.Identifier{binding.group}.Sanitize(),
			pgx.Identifier{binding.login}.Sanitize(),
		)
		if _, err := admin.Exec(ctx, statement); err != nil {
			t.Fatalf("create authority process login %s: %v", binding.login, err)
		}
	}
}

func assertCrossSchemaIsolation(
	t *testing.T,
	ctx context.Context,
	adminConfig *pgx.ConnConfig,
) {
	t.Helper()
	for _, attack := range []struct {
		login string
		query string
	}{
		{paasAPILogin, "SELECT * FROM iam.bootstrap_status()"},
		{paasAPILogin, "SELECT * FROM audit.readiness()"},
		{paasWorkerLogin, "SELECT * FROM audit.readiness()"},
		{iamAPILogin, "SELECT * FROM paas.readiness()"},
		{iamWorkerLogin, "SELECT * FROM paas.audit_outbox_snapshot()"},
		{auditRuntimeLogin, "SELECT * FROM iam.bootstrap_status()"},
		{auditRuntimeLogin, "SELECT * FROM paas.readiness()"},
	} {
		config := adminConfig.Copy()
		config.User = attack.login
		config.Password = processDBPassword
		connection, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatalf("connect cross-schema attack role %s: %v", attack.login, err)
		}
		_, attackErr := connection.Exec(ctx, attack.query)
		_ = connection.Close(context.Background())
		var postgresError *pgconn.PgError
		if !errors.As(attackErr, &postgresError) || postgresError.Code != "42501" {
			t.Fatalf("cross-schema attack role=%s was not denied", attack.login)
		}
	}
}

func quoteLiteral(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

func runtimeDSN(admin *pgx.ConnConfig, user string, password string) string {
	config := admin.Copy()
	config.User = user
	config.Password = password
	config.DefaultQueryExecMode = pgx.QueryExecModeCacheStatement
	return config.ConnString()
}

func writeProtectedFile(
	t *testing.T,
	root string,
	name string,
	value []byte,
) string {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.WriteFile(path, value, 0o600); err != nil {
		t.Fatalf("write authority process input %s: %v", name, err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatalf("protect authority process input %s: %v", name, err)
		}
	}
	return path
}

func freeAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve authority process address: %v", err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("release authority process address: %v", err)
	}
	return address
}
