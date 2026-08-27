package authorityprocess

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	managedservicev1 "github.com/xiak/matrix/api/managedservice/v1"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
	auditmigration "github.com/xiak/matrix/app/service/audit/migration"
	iammigration "github.com/xiak/matrix/app/service/iam/migration"
	installationrelease "github.com/xiak/matrix/app/service/installation/release"
	paasmigration "github.com/xiak/matrix/app/service/paas/migration"
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
	verifierCredential     = "mx1.ProcessVerifierCredential0000000000000001"
)

func TestRuntimeDSNBindsLeastPrivilegeLogin(t *testing.T) {
	admin, err := pgx.ParseConfig("postgres://migration:admin-password@127.0.0.1:5432/matrix_authority_process_unit?sslmode=disable&user=postgres&password=query-admin")
	if err != nil {
		t.Fatal(err)
	}
	dsn := runtimeDSN(t, admin, paasAPILogin, "runtime-password-with-&?#-characters")
	parsed, err := pgxpool.ParseConfig(dsn)
	if err != nil || parsed.ConnConfig.User != paasAPILogin || parsed.ConnConfig.Password != "runtime-password-with-&?#-characters" || parsed.ConnConfig.Database != admin.Database || parsed.ConnConfig.Host != admin.Host || parsed.ConnConfig.Port != admin.Port || parsed.MaxConns != 2 || parsed.ConnConfig.RuntimeParams["application_name"] != "matrix-authority-process:"+paasAPILogin {
		t.Fatal("process DSN retained a migration credential or lost its bounded target")
	}
	if admin.User != "postgres" || admin.Password != "query-admin" {
		t.Fatal("runtime DSN mutated migration configuration")
	}
}

func TestIAMRetainedAccountProcessUpgrade(t *testing.T) {
	const variable = "MATRIX_IAM_UPGRADE_POSTGRES_TEST_DSN"
	dsn := os.Getenv(variable)
	if dsn == "" {
		t.Skipf("set %s to a clean disposable PostgreSQL 18 database", variable)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	config, err := pgx.ParseConfig(dsn)
	if err != nil || !strings.HasPrefix(config.Database, "matrix_iam_upgrade_") {
		t.Fatal("IAM upgrade requires its own matrix_iam_upgrade_ database")
	}
	config.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	admin, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admin.Close(context.Background()) }()
	assertPostgres18(t, ctx, admin)
	assertCleanSchemas(t, ctx, admin)
	if err := iammigration.Bootstrap(ctx, admin); err != nil {
		t.Fatal(err)
	}
	root, temporary := repositoryRoot(t), t.TempDir()
	baselineRoot := extractFixedIAMSource(t, ctx, root, temporary)
	oldSQL, err := os.ReadFile(filepath.Join(baselineRoot, "app/service/iam/internal/data/postgres/migrations/000001_authority/up.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, string(oldSQL)); err != nil {
		t.Fatalf("apply fixed single-tenant IAM schema: %v", err)
	}
	createProcessLogin(t, ctx, admin, iamAPILogin, "matrix_iam_api")
	oldBinary := buildAuthorityBinary(t, ctx, baselineRoot, temporary, "matrix-iam-baseline", "./app/service/iam/cmd/matrix-iam")
	currentBinary := buildAuthorityBinary(t, ctx, root, temporary, "matrix-iam-upgrade", "./app/service/iam/cmd/matrix-iam")
	bootstrapBytes, err := iamv1.EncodeBootstrapDocument(processBootstrap(t))
	if err != nil {
		t.Fatal(err)
	}
	bootstrapPath := writeProtectedFile(t, temporary, "iam-bootstrap.json", bootstrapBytes)
	clear(bootstrapBytes)
	dsnPath := writeProtectedFile(t, temporary, "iam-dsn", []byte(runtimeDSN(t, config, iamAPILogin, processDBPassword)))
	address := freeAddress(t)
	endpoint := "http://" + address
	environment := []string{"MATRIX_IAM_DATABASE_DSN_FILE=" + dsnPath, "MATRIX_IAM_BOOTSTRAP_FILE=" + bootstrapPath, "MATRIX_IAM_LISTEN_ADDRESS=" + address}
	var children []*childProcess
	defer func() {
		for _, child := range children {
			child.stop()
		}
		assertProcessOutputsSanitized(t, children, initialAdminPassword, changedAdminPassword, initialReaderPassword, changedReaderPassword)
	}()
	start := func(binary string) *childProcess {
		child := startChild(t, root, binary, environment)
		children = append(children, child)
		waitHTTPStatus(t, ctx, child, endpoint+"/ready", http.StatusOK)
		assertRuntimeProcessLogins(t, ctx, admin, iamAPILogin)
		return child
	}
	old := start(oldBinary)
	administrator := loginIAM(t, endpoint, "admin", initialAdminPassword, "request-upgrade-admin-login")
	changePasswordIAM(t, endpoint, administrator.Credential, initialAdminPassword, changedAdminPassword, "request-upgrade-admin-password")
	user := createIAMUser(t, endpoint, administrator.Credential, "retained.viewer", "Retained viewer", initialReaderPassword, "request-upgrade-member")
	member := loginIAM(t, endpoint, "retained.viewer", initialReaderPassword, "request-upgrade-member-login")
	changePasswordIAM(t, endpoint, member.Credential, initialReaderPassword, changedReaderPassword, "request-upgrade-member-password")
	binding := putIAMBinding(t, endpoint, administrator.Credential, user.ID, iamv1.RolePaaSViewer, "request-upgrade-role")
	revokeIAMBinding(t, endpoint, administrator.Credential, binding.ID, "request-upgrade-role-revoke")
	revokeIAMSession(t, endpoint, administrator.Credential, member.Session.ID, "request-upgrade-session-revoke")
	revokeIAMBinding(t, endpoint, administrator.Credential, "bootstrap-platform-operator-binding", "request-upgrade-platform-revoke")
	old.stop()
	rows, err := admin.Query(ctx, "SELECT event_id,event_document FROM iam.audit_outbox")
	if err != nil {
		t.Fatal(err)
	}
	retained := map[string]auditv1.Event{}
	for rows.Next() {
		var id string
		var raw []byte
		var event auditv1.Event
		if rows.Scan(&id, &raw) != nil || json.Unmarshal(raw, &event) != nil {
			rows.Close()
			t.Fatal("decode retained IAM fact")
		}
		event.OccurredAt = event.OccurredAt.UTC()
		retained[id] = event
	}
	rows.Close()
	if rows.Err() != nil || len(retained) == 0 {
		t.Fatal("old installation has no retained facts")
	}
	unmigrated := startChild(t, root, currentBinary, environment)
	children = append(children, unmigrated)
	if err := unmigrated.wait(10 * time.Second); err == nil || errors.Is(err, errProcessWaitTimeout) {
		t.Fatal("current IAM served an unmigrated authority schema")
	}
	for attempt := 0; attempt < 2; attempt++ {
		if err := iammigration.Up(ctx, admin); err != nil {
			t.Fatalf("upgrade populated IAM: %v", err)
		}
		if err := iammigration.Verify(ctx, admin); err != nil {
			t.Fatal(err)
		}
	}
	current := start(currentBinary)
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			current.stop()
			current = start(currentBinary)
		}
		if got := performJSON(t, http.MethodGet, endpoint+"/v1/auth/me", member.Credential, nil); got.Status != http.StatusUnauthorized {
			t.Fatal("upgrade/restart revived a revoked session")
		}
		primary := loginIAM(t, endpoint, "admin", changedAdminPassword, "request-upgrade-retained-primary")
		identityResponse := performJSON(t, http.MethodGet, endpoint+"/v1/auth/me", primary.Credential, nil)
		var identity iamv1.CurrentIdentity
		if identityResponse.Status != http.StatusOK || json.Unmarshal(identityResponse.Body, &identity) != nil || identity.Account.PrimaryPrincipalID != "principal-admin" || identity.Principal.MustChangePassword {
			t.Fatal("upgrade replaced primary ownership or credentials")
		}
		assertPlatformAuthorization(t, endpoint, primary.Credential, "principal-admin", "request-upgrade-platform-denied", false)
		child := loginIAM(t, endpoint, "retained.viewer@organization-process", changedReaderPassword, "request-upgrade-retained-child")
		childResponse := performJSON(t, http.MethodGet, endpoint+"/v1/auth/me", child.Credential, nil)
		var childIdentity iamv1.CurrentIdentity
		if childResponse.Status != http.StatusOK || json.Unmarshal(childResponse.Body, &childIdentity) != nil || childIdentity.Principal.ID != user.ID || len(childIdentity.Roles) != 0 {
			t.Fatal("upgrade changed member identity or revived a revoked role")
		}
		serviceResponse := performJSON(t, http.MethodGet, endpoint+"/v1/service-identity", paasServiceCredential, nil)
		var service iamv1.ServiceIdentity
		if serviceResponse.Status != http.StatusOK || json.Unmarshal(serviceResponse.Body, &service) != nil || iamv1.ValidateServiceIdentity(service) != nil || service.InstallationID != "installation-process" {
			t.Fatal("upgraded service lost sealed installation")
		}
		for id, event := range retained {
			var raw []byte
			var stored auditv1.Event
			if err := admin.QueryRow(ctx, "SELECT event_document FROM iam.audit_outbox WHERE event_id=$1", id).Scan(&raw); err != nil || json.Unmarshal(raw, &stored) != nil {
				t.Fatal("upgrade lost IAM fact")
			}
			stored.OccurredAt = stored.OccurredAt.UTC()
			before, digest, beforeErr := auditv1.CanonicalizeEvent(auditv1.SourceIAM, event)
			after, _, afterErr := auditv1.CanonicalizeEvent(auditv1.SourceIAM, stored)
			if beforeErr != nil || afterErr != nil || before != after {
				t.Fatal("upgrade rewrote canonical IAM evidence")
			}
			proofResponse := performJSON(t, http.MethodPost, endpoint+"/v1/audit-producer:resolve", iamServiceCredential, iamv1.ResolveAuditProducerRequest{Event: event})
			var proof iamv1.AuditProducerAuthorization
			if proofResponse.Status != http.StatusOK || json.Unmarshal(proofResponse.Body, &proof) != nil || proof.ContentDigest != digest {
				t.Fatal("retained committed IAM fact cannot be delivered after upgrade")
			}
		}
	}
}

// This gate builds the accepted old executable from fixed Git objects in its
// own temporary directory. Old source is never a product/runtime dependency.
func extractFixedIAMSource(t *testing.T, ctx context.Context, root, temporary string) string {
	t.Helper()
	command := exec.CommandContext(ctx, "git", "archive", "--format=zip", "9fd45b03ea398828fa3e74bf99961d2348c68299", "go.mod", "go.sum", "api", "app/service/iam", "app/service/internal")
	command.Dir = root
	archive, err := command.Output()
	if err != nil || len(archive) > 32<<20 {
		t.Fatal("cannot read bounded fixed IAM source archive")
	}
	reader, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(temporary, "iam-baseline")
	for _, entry := range reader.File {
		path := filepath.FromSlash(entry.Name)
		if !filepath.IsLocal(path) || entry.UncompressedSize64 > 8<<20 {
			t.Fatal("unsafe fixed source entry")
		}
		target := filepath.Join(destination, path)
		if entry.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o700); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			t.Fatal(err)
		}
		source, err := entry.Open()
		if err != nil {
			t.Fatal(err)
		}
		content, readErr := io.ReadAll(io.LimitReader(source, 8<<20))
		closeErr := source.Close()
		if readErr != nil || closeErr != nil {
			t.Fatal("cannot extract fixed source entry")
		}
		if err := os.WriteFile(target, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return destination
}

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
	applyPlatformSchemas(t, ctx, admin)
	createProcessLogins(t, ctx, admin)
	assertCrossSchemaIsolation(t, ctx, adminConfig)
	seedProcessExecutionProfile(t, ctx, adminConfig)

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
		[]byte(runtimeDSN(t, adminConfig, iamAPILogin, processDBPassword)),
	)
	iamWorkerDSNPath := writeProtectedFile(
		t,
		temporary,
		"iam-worker-dsn",
		[]byte(runtimeDSN(t, adminConfig, iamWorkerLogin, processDBPassword)),
	)
	auditDSNPath := writeProtectedFile(
		t,
		temporary,
		"audit-dsn",
		[]byte(runtimeDSN(t, adminConfig, auditRuntimeLogin, processDBPassword)),
	)
	paasDSNPath := writeProtectedFile(
		t,
		temporary,
		"paas-dsn",
		[]byte(runtimeDSN(t, adminConfig, paasAPILogin, processDBPassword)),
	)
	paasWorkerDSNPath := writeProtectedFile(
		t,
		temporary,
		"paas-worker-dsn",
		[]byte(runtimeDSN(t, adminConfig, paasWorkerLogin, processDBPassword)),
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
	iamDispatcherAddress := freeAddress(t)
	paasDispatcherAddress := freeAddress(t)
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
			"MATRIX_IAM_AUDIT_LISTEN_ADDRESS=" + iamDispatcherAddress,
		}
	}
	paasEnvironment := []string{
		"MATRIX_PAAS_DATABASE_DSN_FILE=" + paasDSNPath,
		"MATRIX_PAAS_IAM_ENDPOINT=" + iamEndpoint,
		"MATRIX_PAAS_SERVICE_CREDENTIAL_FILE=" + paasCredentialPath,
		"MATRIX_PAAS_LISTEN_ADDRESS=" + paasAddress,
		"MATRIX_PAAS_INSTALLATION_ID=" + bootstrap.InstallationID,
		"MATRIX_PAAS_RELEASE_ID=matrix-v0.1.0-process",
		"MATRIX_PAAS_VERIFICATION_ARTIFACT_DIGEST=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	paasDispatcherEnvironment := func(credentialPath string, workerID string) []string {
		return []string{
			"MATRIX_PAAS_AUDIT_DATABASE_DSN_FILE=" + paasWorkerDSNPath,
			"MATRIX_PAAS_AUDIT_ENDPOINT=" + auditEndpoint,
			"MATRIX_PAAS_AUDIT_CREDENTIAL_FILE=" + credentialPath,
			"MATRIX_PAAS_AUDIT_WORKER_ID=" + workerID,
			"MATRIX_PAAS_AUDIT_LISTEN_ADDRESS=" + paasDispatcherAddress,
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
		verifierCredential,
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
	waitHTTPStatus(t, ctx, dispatcher, "http://"+iamDispatcherAddress+"/ready", http.StatusOK)
	waitAllIAMOutboxDelivered(t, ctx, admin)
	assertIAMEventsStoredOnce(t, ctx, admin)
	paasProcess := start(binaries.paas, paasEnvironment)
	waitHTTPStatus(t, ctx, paasProcess, paasEndpoint+"/ready", http.StatusOK)
	profile := installationrelease.CurrentDatabaseProfile().Authorities
	for _, authority := range []struct {
		name, endpoint string
		version        uint64
	}{
		{"IAM", iamEndpoint, profile.IAM},
		{"Audit", auditEndpoint, profile.Audit},
		{"PaaS", paasEndpoint, profile.PaaS},
	} {
		response := performJSON(t, http.MethodGet, authority.endpoint+"/ready", "", nil)
		var readiness struct {
			SchemaVersion uint64 `json:"schemaVersion"`
		}
		if response.Status != http.StatusOK || json.Unmarshal(response.Body, &readiness) != nil || readiness.SchemaVersion != authority.version {
			t.Fatalf("%s runtime schema=%d does not match release profile=%d (status=%d)", authority.name, readiness.SchemaVersion, authority.version, response.Status)
		}
	}
	paasDispatcher := start(
		binaries.paasDispatcher,
		paasDispatcherEnvironment(paasCredentialPath, "paas-audit-worker-a"),
	)
	waitHTTPStatus(t, ctx, paasDispatcher, "http://"+paasDispatcherAddress+"/ready", http.StatusOK)
	assertRuntimeProcessLogins(t, ctx, admin, iamAPILogin, iamWorkerLogin, auditRuntimeLogin, paasAPILogin, paasWorkerLogin)
	paasInstallationVerification := verifyPaaSInstallation(
		t,
		paasEndpoint,
		verifierCredential,
		paasv1.VerifyInstallationRequest{
			InstallationID: bootstrap.InstallationID,
			ReleaseID:      "matrix-v0.1.0-process",
		},
	)
	if paasInstallationVerification.State != paasv1.InstallationVerificationPending {
		t.Fatalf("fixed PaaS installation verification=%#v", paasInstallationVerification)
	}
	waitAllIAMOutboxDelivered(t, ctx, admin)
	waitAllPaaSOutboxDelivered(t, ctx, admin)
	auditInstallationVerification := verifyAuditInstallation(
		t,
		auditEndpoint,
		verifierCredential,
		auditv1.VerifyInstallationRequest{
			InstallationID: bootstrap.InstallationID,
			OperationID:    auditv1.OperationID(paasInstallationVerification.OperationID),
			DeploymentID:   string(paasInstallationVerification.DeploymentID),
		},
	)
	if auditInstallationVerification.State != auditv1.InstallationVerificationVerified ||
		auditInstallationVerification.OperationID != auditv1.OperationID(paasInstallationVerification.OperationID) ||
		auditInstallationVerification.DeploymentID != string(paasInstallationVerification.DeploymentID) {
		t.Fatalf("fixed Audit installation verification=%#v", auditInstallationVerification)
	}
	assertAuditAccessRecorded(t, ctx, admin, auditv1.ActionAuditIntegrityVerified, "service-verifier")

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
	platformDecisions := []iamv1.AuthorizationDecision{
		assertPlatformAuthorization(t, iamEndpoint, adminLogin.Credential, "principal-admin", "request-platform-admin", true),
	}
	sensitive = append(sensitive, proveTenantAccountProcesses(t, ctx, admin, iamEndpoint, auditEndpoint, paasEndpoint, adminLogin.Credential,
		func(admit func()) {
			auditProcess.stop()
			admit()
			auditProcess = start(binaries.audit, auditEnvironment)
			waitHTTPStatus(t, ctx, auditProcess, auditEndpoint+"/ready", http.StatusOK)
		}, func() {
			iamProcess.stop()
			iamProcess = start(binaries.iam, iamEnvironment)
			waitHTTPStatus(t, ctx, iamProcess, iamEndpoint+"/ready", http.StatusOK)
		})...)
	platformAuditRecord := ingestPlatformAuditFixture(t, auditEndpoint, platformDecisions[0])
	assertPlatformAuditAccess(t, auditEndpoint, adminLogin.Credential, http.StatusOK)
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
		"paas.developer@organization-process",
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
	platformDecisions = append(platformDecisions,
		assertPlatformAuthorization(t, iamEndpoint, developerLogin.Credential, string(developer.ID), "request-platform-developer-denied", false),
	)
	assertPlatformAuditAccess(t, auditEndpoint, developerLogin.Credential, http.StatusForbidden)
	platformBinding := putIAMBinding(t, iamEndpoint, adminLogin.Credential, developer.ID,
		iamv1.RolePlatformOperator, "request-bind-platform-operator")
	platformDecisions = append(platformDecisions,
		assertPlatformAuthorization(t, iamEndpoint, developerLogin.Credential, string(developer.ID), "request-platform-developer-granted", true),
	)
	assertPlatformAuditAccess(t, auditEndpoint, developerLogin.Credential, http.StatusOK)
	queryAudit(t, auditEndpoint, developerLogin.Credential, auditv1.QueryRecordsRequest{PageSize: 10}, http.StatusForbidden)
	revokeIAMBinding(t, iamEndpoint, adminLogin.Credential, platformBinding.ID, "request-revoke-platform-operator")
	platformDecisions = append(platformDecisions,
		assertPlatformAuthorization(t, iamEndpoint, developerLogin.Credential, string(developer.ID), "request-platform-developer-revoked", false),
	)
	assertPlatformAuditAccess(t, auditEndpoint, developerLogin.Credential, http.StatusForbidden)
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
		"audit.reader@organization-process",
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
	revokeIAMBinding(t, iamEndpoint, adminLogin.Credential, "bootstrap-platform-operator-binding", "request-revoke-bootstrap-platform")
	platformDecisions = append(platformDecisions,
		assertPlatformAuthorization(t, iamEndpoint, adminLogin.Credential, "principal-admin", "request-platform-admin-revoked", false),
	)
	assertPlatformAuditAccess(t, auditEndpoint, adminLogin.Credential, http.StatusForbidden)
	selfGrant := performJSON(t, http.MethodPost, iamEndpoint+"/v1/role-bindings", adminLogin.Credential,
		iamv1.PutRoleBindingRequest{PrincipalID: "principal-admin", Role: iamv1.RolePlatformOperator, RequestID: "request-platform-self-grant"})
	if selfGrant.Status != http.StatusForbidden {
		t.Fatalf("organization administrator restored its platform authority: status=%d", selfGrant.Status)
	}
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
	platformDecisions = append(platformDecisions,
		assertPlatformAuthorization(t, iamEndpoint, adminLogin.Credential, "principal-admin", "request-platform-admin-restarted", false),
	)
	assertPlatformAuditAccess(t, auditEndpoint, adminLogin.Credential, http.StatusForbidden)
	waitAllIAMOutboxDelivered(t, ctx, admin)
	assertPlatformDecisionAuditFacts(t, ctx, admin, platformDecisions)
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
	platformReplay := performJSON(t, http.MethodPost, auditEndpoint+"/v1/events", paasServiceCredential, platformAuditRecord.Event)
	var platformDuplicate auditv1.IngestionResult
	if platformReplay.Status != http.StatusOK || json.Unmarshal(platformReplay.Body, &platformDuplicate) != nil ||
		auditv1.ValidateIngestionResult(platformDuplicate) != nil || platformDuplicate.Record != platformAuditRecord ||
		platformDuplicate.Outcome != auditv1.IngestionDuplicate {
		t.Fatal("Audit restart changed the retained platform record or equal replay")
	}
	assertPlatformAuditAccess(t, auditEndpoint, adminLogin.Credential, http.StatusForbidden)
	assertPlatformAuditStoredFacts(t, ctx, admin)
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
	if response.Status != http.StatusForbidden {
		t.Fatalf("unproved IAM fact replay status=%d", response.Status)
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
	if response.Status != http.StatusForbidden {
		t.Fatalf("uncorrelated PaaS fact replay status=%d", response.Status)
	}
	changedPaaSEvent = paasEvent
	changedPaaSEvent.RequestDigest = "sha256:" + strings.Repeat("e", 64)
	response = performJSON(t, http.MethodPost, auditEndpoint+"/v1/events", paasServiceCredential, changedPaaSEvent)
	if response.Status != http.StatusConflict {
		t.Fatalf("authority-valid changed payload replay status=%d", response.Status)
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
	if _, err := admin.Exec(ctx, `UPDATE iam.service_credentials SET revoked_at=transaction_timestamp()
		WHERE tenant_id='organization-process' AND purpose='IAM' AND revoked_at IS NULL`); err != nil {
		t.Fatal(err)
	}
	response = performJSON(t, http.MethodPost, auditEndpoint+"/v1/events", iamServiceCredential, outageEvent)
	if response.Status != http.StatusUnauthorized {
		t.Fatalf("revoked producer credential reused historical proof: status=%d", response.Status)
	}
	assertAuditEventCount(t, ctx, admin, outageEventID, 1)
	assertAuthorityPlaintextAbsent(t, ctx, admin, sensitive...)
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
	build := func(name, packagePath string) string {
		return buildAuthorityBinary(t, ctx, root, temporary, name, packagePath)
	}
	return binarySet{
		iam:            build("matrix-iam", "./app/service/iam/cmd/matrix-iam"),
		audit:          build("matrix-audit", "./app/service/audit/cmd/matrix-audit"),
		dispatcher:     build("matrix-iam-audit-dispatcher", "./app/service/iam/cmd/matrix-iam-audit-dispatcher"),
		paas:           build("matrix-paas", "./app/service/paas/cmd/matrix-paas"),
		paasDispatcher: build("matrix-paas-audit-dispatcher", "./app/service/paas/cmd/matrix-paas-audit-dispatcher"),
	}
}

func buildAuthorityBinary(t *testing.T, ctx context.Context, root, temporary, name, packagePath string) string {
	t.Helper()
	suffix := ""
	if runtime.GOOS == "windows" {
		suffix = ".exe"
	}
	path := filepath.Join(temporary, name+suffix)
	command := exec.CommandContext(ctx, "go", "build", "-p", "2", "-o", path, packagePath)
	command.Dir = root
	command.Env = append(os.Environ(), "GOMAXPROCS=2", "GOMEMLIMIT=512MiB")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", name, err, output)
	}
	return path
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
	child.command.Env = append(append(os.Environ(), environment...), "GOMAXPROCS=2", "GOMEMLIMIT=512MiB")
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
	return performJSONWithHeaders(t, method, endpoint, bearer, idempotencyKey, body, nil)
}

func performJSONWithHeaders(t *testing.T, method, endpoint, bearer, idempotencyKey string, body any, headers map[string]string) processResponse {
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
	for name, value := range headers {
		request.Header.Set(name, value)
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

func assertPlatformAuthorization(
	t *testing.T,
	endpoint, credential, principalID, requestID string,
	allowed bool,
) iamv1.AuthorizationDecision {
	t.Helper()
	resource := iamv1.ResourceReference{Kind: iamv1.ResourceExecutionTarget, ID: "execution-target-process"}
	body, err := json.Marshal(iamv1.AuthorizationRequest{
		Action: iamv1.ActionPaaSExecutionTargetRegister, Resource: resource,
		RequestID: requestID, CorrelationID: requestID,
	})
	if err != nil {
		t.Fatalf("encode platform authorization request: %v", err)
	}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, endpoint+"/v1/authorize", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create platform authorization request: %v", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+paasServiceCredential)
	request.Header.Set("Matrix-Subject-Credential", credential)
	response, err := processHTTPClient().Do(request)
	if err != nil {
		t.Fatalf("request platform authorization: %v", err)
	}
	defer response.Body.Close()
	var decision iamv1.AuthorizationDecision
	if response.StatusCode != http.StatusOK ||
		iamv1.DecodeRequest(response.Body, &decision) != nil ||
		iamv1.ValidateAuthorizationDecision(decision) != nil ||
		decision.Allowed != allowed || decision.TenantID != "" ||
		decision.RequestID != requestID || decision.Action != iamv1.ActionPaaSExecutionTargetRegister ||
		decision.Resource != resource {
		t.Fatalf("invalid platform authorization: status=%d allowed=%t request=%s", response.StatusCode, allowed, requestID)
	}
	if allowed && (decision.InstallationID != "installation-process" || decision.Subject == nil ||
		decision.Subject.Type != iamv1.PrincipalUser || string(decision.Subject.ID) != principalID) {
		t.Fatal("platform authorization lost the exact installation or user identity")
	}
	return decision
}

func ingestPlatformAuditFixture(t *testing.T, endpoint string, decision iamv1.AuthorizationDecision) auditv1.AuditRecord {
	t.Helper()
	// This tests the authenticated producer/Audit boundary, not host admission
	// or a PaaS Operation; those effects have their own real-runtime gates.
	event := auditv1.Event{
		APIVersion: auditv1.APIVersion, Kind: "AuditEvent", EventID: "event-platform-process",
		InstallationID: decision.InstallationID,
		Actor:          auditv1.ActorReference{Type: auditv1.ActorUser, ID: auditv1.ActorID(decision.Subject.ID)},
		IAMDecisionID:  auditv1.DecisionID(decision.ID), Action: auditv1.ActionPaaSExecutionTargetRegistered,
		Target: auditv1.TargetReference{Kind: auditv1.TargetExecutionTarget, ID: decision.Resource.ID},
		Result: auditv1.ResultSucceeded, RequestDigest: "sha256:" + strings.Repeat("1", 64),
		RequestID: decision.RequestID, CorrelationID: decision.RequestID,
		OperationID: "operation-platform-audit-fixture", OccurredAt: decision.DecidedAt,
	}
	response := performJSON(t, http.MethodPost, endpoint+"/v1/events", paasServiceCredential, event)
	var result auditv1.IngestionResult
	if response.Status != http.StatusCreated || json.Unmarshal(response.Body, &result) != nil ||
		auditv1.ValidateIngestionResult(result) != nil || result.Record.Event != event {
		t.Fatalf("platform Audit ingestion failed: status=%d", response.Status)
	}
	wrong := event
	wrong.EventID, wrong.InstallationID = "event-wrong-platform", "another-installation"
	if got := performJSON(t, http.MethodPost, endpoint+"/v1/events", paasServiceCredential, wrong); got.Status != http.StatusForbidden {
		t.Fatalf("wrong installation Audit ingestion status=%d", got.Status)
	}
	if got := performJSON(t, http.MethodPost, endpoint+"/v1/events", iamServiceCredential, event); got.Status != http.StatusForbidden {
		t.Fatalf("wrong producer purpose emitted platform PaaS event: status=%d", got.Status)
	}
	return result.Record
}

func assertPlatformAuditAccess(t *testing.T, endpoint, credential string, status int) {
	t.Helper()
	for _, query := range []struct {
		path string
		body any
	}{
		{"/v1/platform/records:query", auditv1.QueryRecordsRequest{PageSize: 20}},
		{"/v1/platform/integrity:verify", auditv1.VerifyChainRequest{FromSequence: 1, MaximumRecords: 20}},
	} {
		response := performJSON(t, http.MethodPost, endpoint+query.path, credential, query.body)
		if response.Status != status {
			t.Fatalf("platform Audit %s status=%d want=%d", query.path, response.Status, status)
		}
		if status != http.StatusOK {
			continue
		}
		if query.path == "/v1/platform/records:query" {
			var page auditv1.RecordPage
			if json.Unmarshal(response.Body, &page) != nil || auditv1.ValidateRecordPage(page) != nil ||
				page.InstallationID != "installation-process" || page.TenantID != "" || len(page.Records) == 0 {
				t.Fatal("platform Audit query lost installation authority")
			}
		} else {
			var verification auditv1.ChainVerification
			if json.Unmarshal(response.Body, &verification) != nil || auditv1.ValidateChainVerification(verification) != nil ||
				verification.InstallationID != "installation-process" || verification.TenantID != "" || verification.RecordCount == 0 {
				t.Fatal("platform Audit verification lost installation authority")
			}
		}
	}
}

func assertPlatformAuditStoredFacts(t *testing.T, ctx context.Context, admin *pgx.Conn) {
	t.Helper()
	var records, matched int
	if err := admin.QueryRow(ctx, `SELECT count(*), count(*) FILTER (
		WHERE decision.allowed AND record.tenant_id IS NULL
		  AND decision.document->>'installationId' = record.installation_id
		  AND NOT (decision.document ? 'tenantId')
		  AND record.event_document#>>'{actor,id}' = decision.principal_id
		  AND record.event_document->>'requestId' = decision.request_id)
		FROM audit.records AS record LEFT JOIN iam.authorization_decisions AS decision
		  ON decision.id = record.event_document->>'iamDecisionId'
		WHERE record.installation_id = 'installation-process'`).Scan(&records, &matched); err != nil {
		t.Fatal(err)
	}
	if records < 5 || matched != records {
		t.Fatalf("platform facts lost immutable IAM correlation: records=%d matched=%d", records, matched)
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

func proveTenantAccountProcesses(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	endpoint string,
	auditEndpoint string,
	paasEndpoint string,
	bearer string,
	withAuditOutage func(func()),
	restartIAM func(),
) []string {
	t.Helper()
	const (
		crossTenantID = "organization-process-customer"
		initial       = "Customer-Process-Initial-Password-48!"
		changed       = "Customer-Process-Changed-Password-59!"
	)
	opened := performJSON(t, http.MethodPost, endpoint+"/v1/organizations", bearer, map[string]any{
		"id": crossTenantID, "displayName": "Process customer", "administratorLoginName": "customer.primary",
		"administratorDisplayName": "Customer owner", "initialPassword": initial, "requestId": "request-open-customer",
	})
	var account iamv1.OrganizationAccount
	if opened.Status != http.StatusCreated || json.Unmarshal(opened.Body, &account) != nil || iamv1.ValidateOrganizationAccount(account) != nil {
		t.Fatalf("tenant HTTP onboarding status=%d", opened.Status)
	}
	primary := loginIAM(t, endpoint, "customer.primary", initial, "request-customer-login")
	changePasswordIAM(t, endpoint, primary.Credential, initial, changed, "request-customer-password")
	alias := performJSON(t, http.MethodPost, endpoint+"/v1/organization:alias", primary.Credential, iamv1.SetAccountAliasRequest{
		Alias: "process-company", ResourceVersion: account.Organization.ResourceVersion, RequestID: "request-customer-alias",
	})
	if alias.Status != http.StatusOK {
		t.Fatalf("customer alias status=%d", alias.Status)
	}
	child := createIAMUser(t, endpoint, primary.Credential, "account.user", "Customer developer", initial, "request-customer-user")
	putIAMBinding(t, endpoint, primary.Credential, child.ID, iamv1.RolePaaSDeveloper, "request-customer-role")
	childLogin := loginIAM(t, endpoint, "account.user@process-company", initial, "request-customer-child-login")
	changePasswordIAM(t, endpoint, childLogin.Credential, initial, changed, "request-customer-child-password")
	operation := createPaaSApplication(t, paasEndpoint, childLogin.Credential, "application-customer-only", "customer-only", "create-customer-application", http.StatusCreated)
	if operation.Scope.TenantID != crossTenantID || operation.RequestedBy.ID != string(child.ID) {
		t.Fatal("new tenant PaaS mutation lost its IAM identity")
	}
	getPaaSApplication(t, paasEndpoint, childLogin.Credential, "application-customer-only", http.StatusOK)
	getPaaSApplication(t, paasEndpoint, bearer, "application-customer-only", http.StatusNotFound)
	response := performJSON(
		t,
		http.MethodPost,
		endpoint+"/v1/role-bindings",
		bearer,
		iamv1.PutRoleBindingRequest{
			PrincipalID: child.ID,
			Role:        iamv1.RoleAuditReader,
			RequestID:   "request-process-cross-tenant-binding",
		},
	)
	if response.Status != http.StatusForbidden ||
		bytes.Contains(response.Body, []byte(child.ID)) ||
		bytes.Contains(response.Body, []byte("role binding principal")) {
		t.Fatalf("cross-tenant IAM binding status=%d body=%s", response.Status, response.Body)
	}
	var unauthorizedBindings int
	if err := admin.QueryRow(ctx,
		"SELECT count(*) FROM iam.role_bindings WHERE principal_id=$1 AND role_name='AUDIT_READER'",
		child.ID).Scan(&unauthorizedBindings); err != nil || unauthorizedBindings != 0 {
		t.Fatalf("cross-tenant IAM attack created bindings=%d err=%v", unauthorizedBindings, err)
	}
	waitAllIAMOutboxDelivered(t, ctx, admin)
	waitAllPaaSOutboxDelivered(t, ctx, admin)
	for _, action := range []auditv1.Action{auditv1.ActionIAMAccountAliasSet, auditv1.ActionIAMPrincipalCreated, auditv1.ActionPaaSApplicationCreated} {
		page := queryAudit(t, auditEndpoint, primary.Credential, auditv1.QueryRecordsRequest{PageSize: 100, Action: action}, http.StatusOK)
		if page.TenantID != crossTenantID || len(page.Records) != 1 || page.Records[0].Event.TenantID != crossTenantID {
			t.Fatalf("new tenant audit action=%s was not delivered exactly once within its account", action)
		}
		other := queryAudit(t, auditEndpoint, bearer, auditv1.QueryRecordsRequest{PageSize: 100, Action: action}, http.StatusOK)
		for _, record := range other.Records {
			if record.Event.TenantID != "organization-process" {
				t.Fatal("bootstrap owner read another tenant's audit")
			}
		}
	}
	page := queryAudit(t, auditEndpoint, primary.Credential, auditv1.QueryRecordsRequest{PageSize: 1}, http.StatusOK)
	if page.NextCursor == "" {
		t.Fatal("new tenant audit page has no continuation")
	}
	queryAudit(t, auditEndpoint, bearer, auditv1.QueryRecordsRequest{PageSize: 1, Cursor: page.NextCursor}, http.StatusUnprocessableEntity)
	chain := verifyAudit(t, auditEndpoint, primary.Credential)
	if chain.TenantID != crossTenantID || chain.State != auditv1.VerificationVerified || !chain.Complete {
		t.Fatal("new tenant audit chain failed verification")
	}
	userProducer := performJSON(t, http.MethodPost, auditEndpoint+"/v1/events", primary.Credential, page.Records[0].Event)
	if userProducer.Status != http.StatusUnauthorized {
		t.Fatal("tenant owner gained audit producer authority")
	}
	retainedQuota, retainedDatabase, resourceSecrets := proveTenantResourceProcesses(t, ctx, admin, endpoint, auditEndpoint, paasEndpoint, bearer, primary.Credential, childLogin)
	sensitive := append(resourceSecrets, initial, changed, primary.Credential, childLogin.Credential)
	readAccount := func(id string) iamv1.OrganizationAccount {
		t.Helper()
		response := performJSON(t, http.MethodGet, endpoint+"/v1/organizations/"+id, bearer, nil)
		var account iamv1.OrganizationAccount
		if response.Status != http.StatusOK || json.Unmarshal(response.Body, &account) != nil || iamv1.ValidateOrganizationAccount(account) != nil {
			t.Fatalf("platform tenant detail status=%d", response.Status)
		}
		return account
	}
	setStatus := func(id string, status iamv1.OrganizationStatus, expected int) {
		t.Helper()
		current := readAccount(id)
		response := performJSON(t, http.MethodPost, endpoint+"/v1/organizations/"+id+":set-status", bearer, iamv1.SetOrganizationStatusRequest{Status: status, ResourceVersion: current.Organization.ResourceVersion, RequestID: "request-process-tenant-status"})
		if response.Status != expected {
			t.Fatalf("set tenant status=%d want=%d", response.Status, expected)
		}
	}
	setStatus("organization-process", iamv1.OrganizationDisabled, http.StatusForbidden)
	var retainedApplication string
	if err := admin.QueryRow(ctx, "SELECT document::text FROM paas.applications WHERE tenant_id=$1 AND id='application-customer-only'", crossTenantID).Scan(&retainedApplication); err != nil {
		t.Fatal(err)
	}
	withAuditOutage(func() {
		createPaaSApplication(t, paasEndpoint, childLogin.Credential, "application-before-tenant-pause", "before-tenant-pause", "create-before-tenant-pause", http.StatusCreated)
		setStatus(crossTenantID, iamv1.OrganizationDisabled, http.StatusOK)
		createPaaSApplication(t, paasEndpoint, childLogin.Credential, "application-after-tenant-pause", "after-tenant-pause", "create-after-tenant-pause", http.StatusUnauthorized)
		assertPaaSApplicationAbsent(t, ctx, admin, "application-after-tenant-pause")
	})
	waitAllIAMOutboxDelivered(t, ctx, admin)
	waitAllPaaSOutboxDelivered(t, ctx, admin)
	_, historical := findPaaSEvent(t, ctx, admin, auditv1.ActionPaaSApplicationCreated, "application-before-tenant-pause")
	if historical.TenantID != crossTenantID || historical.Actor.ID != auditv1.ActorID(child.ID) {
		t.Fatal("paused tenant historical outbox lost identity")
	}
	replayed := performJSON(t, http.MethodPost, auditEndpoint+"/v1/events", paasServiceCredential, historical)
	var replay auditv1.IngestionResult
	if replayed.Status != http.StatusOK || json.Unmarshal(replayed.Body, &replay) != nil || replay.Outcome != auditv1.IngestionDuplicate {
		t.Fatal("suspended tenant lost committed historical audit delivery")
	}
	for _, credential := range []string{primary.Credential, childLogin.Credential} {
		if response := performJSON(t, http.MethodGet, endpoint+"/v1/auth/me", credential, nil); response.Status != http.StatusUnauthorized {
			t.Fatal("tenant suspension missed IAM")
		}
		getPaaSApplication(t, paasEndpoint, credential, "application-customer-only", http.StatusUnauthorized)
		queryAudit(t, auditEndpoint, credential, auditv1.QueryRecordsRequest{PageSize: 10}, http.StatusUnauthorized)
		for _, path := range []string{"/quota-entitlements/" + retainedQuota.ID, "/service-installations/" + retainedDatabase.ID, "/service-installations/" + retainedDatabase.ID + "/operation"} {
			if response := performJSON(t, http.MethodGet, paasEndpoint+"/managed-services/v1"+path, credential, nil); response.Status != http.StatusUnauthorized {
				t.Fatal("tenant suspension missed managed-service resource or Operation access")
			}
		}
	}
	const recoveryPassword = "Primary-Process-Recovered-Password-68!"
	current := readAccount(crossTenantID)
	recovery := performJSON(t, http.MethodPost, endpoint+"/v1/organizations/"+crossTenantID+":recover-administrator", bearer, map[string]any{
		"principalId": account.PrimaryPrincipalID, "initialPassword": recoveryPassword, "resourceVersion": current.Organization.ResourceVersion, "requestId": "request-process-primary-recovery"})
	if recovery.Status != http.StatusOK {
		t.Fatalf("recover paused tenant primary status=%d", recovery.Status)
	}
	restartIAM()
	if readAccount(crossTenantID).Organization.Status != iamv1.OrganizationDisabled {
		t.Fatal("recovery or equal-bootstrap restart revived tenant")
	}
	if response := performJSON(t, http.MethodPost, endpoint+"/v1/auth/login", "", map[string]any{"loginName": "customer.primary", "password": recoveryPassword, "requestId": "request-paused-primary-login"}); response.Status != http.StatusUnauthorized {
		t.Fatal("recovered primary bypassed tenant suspension")
	}
	setStatus(crossTenantID, iamv1.OrganizationActive, http.StatusOK)
	getPaaSApplication(t, paasEndpoint, childLogin.Credential, "application-customer-only", http.StatusUnauthorized)
	if response := performJSON(t, http.MethodPost, endpoint+"/v1/auth/login", "", map[string]any{"loginName": "customer.primary", "password": changed, "requestId": "request-old-primary-login"}); response.Status != http.StatusUnauthorized {
		t.Fatal("primary recovery retained old password")
	}
	primary = loginIAM(t, endpoint, "customer.primary", recoveryPassword, "request-recovered-primary-login")
	sensitive = append(sensitive, recoveryPassword, primary.Credential)
	createPaaSApplication(t, paasEndpoint, primary.Credential, "application-before-recovery-change", "before-recovery-change", "create-before-recovery-change", http.StatusForbidden)
	changePasswordIAM(t, endpoint, primary.Credential, recoveryPassword, changed, "request-recovered-primary-password")
	getPaaSApplication(t, paasEndpoint, primary.Credential, "application-customer-only", http.StatusOK)
	getPaaSApplication(t, paasEndpoint, bearer, "application-customer-only", http.StatusNotFound)
	childLogin = loginIAM(t, endpoint, "account.user@process-company", changed, "request-resumed-child-login")
	sensitive = append(sensitive, childLogin.Credential)
	memberDisabled := performJSON(t, http.MethodPost, endpoint+"/v1/principals/"+string(child.ID)+":set-status", primary.Credential, iamv1.SetPrincipalStatusRequest{Status: iamv1.PrincipalDisabled, ResourceVersion: 2, RequestID: "request-process-creator-disabled"})
	if memberDisabled.Status != http.StatusOK {
		t.Fatalf("disable resource creator status=%d", memberDisabled.Status)
	}
	getPaaSApplication(t, paasEndpoint, childLogin.Credential, "application-customer-only", http.StatusUnauthorized)
	getPaaSApplication(t, paasEndpoint, primary.Credential, "application-customer-only", http.StatusOK)
	assertManagedServiceRetained(t, paasEndpoint, primary.Credential, retainedQuota, retainedDatabase)
	var retainedManagedActor string
	if err := admin.QueryRow(ctx, "SELECT requested_by_id FROM managedservice.operations WHERE tenant_id=$1 AND id=$2", crossTenantID, retainedDatabase.Operation.ID).Scan(&retainedManagedActor); err != nil || retainedManagedActor != string(child.ID) {
		t.Fatal("identity lifecycle changed database Operation tenant or creator")
	}
	var unchanged bool
	if err := admin.QueryRow(ctx, "SELECT document::text=$2 FROM paas.applications WHERE tenant_id=$1 AND id='application-customer-only'", crossTenantID, retainedApplication).Scan(&unchanged); err != nil || !unchanged {
		t.Fatal("identity lifecycle changed tenant resource ownership or content")
	}
	operationResponse := performJSON(t, http.MethodGet, paasEndpoint+"/v1/operations/"+string(operation.ID), primary.Credential, nil)
	var retainedOperation paasv1.Operation
	if operationResponse.Status != http.StatusOK || json.Unmarshal(operationResponse.Body, &retainedOperation) != nil || retainedOperation.Scope.TenantID != crossTenantID || retainedOperation.RequestedBy.ID != string(child.ID) {
		t.Fatal("creator suspension changed accepted Operation ownership")
	}
	if response := performJSON(t, http.MethodGet, paasEndpoint+"/v1/operations/"+string(operation.ID), bearer, nil); response.Status != http.StatusNotFound {
		t.Fatal("platform identity read another tenant's Operation")
	}
	waitAllIAMOutboxDelivered(t, ctx, admin)
	for _, action := range []auditv1.Action{auditv1.ActionIAMTenantCreated, auditv1.ActionIAMTenantDisabled, auditv1.ActionIAMTenantEnabled, auditv1.ActionIAMTenantAdministratorRecovered} {
		response := performJSON(t, http.MethodPost, auditEndpoint+"/v1/platform/records:query", bearer, auditv1.QueryRecordsRequest{PageSize: 100, Action: action})
		var records auditv1.RecordPage
		if response.Status != http.StatusOK || json.Unmarshal(response.Body, &records) != nil || len(records.Records) != 1 || records.InstallationID != "installation-process" || records.TenantID != "" {
			t.Fatalf("lifecycle platform audit action=%s status=%d", action, response.Status)
		}
		event := records.Records[0].Event
		if action == auditv1.ActionIAMTenantAdministratorRecovered && (event.Target.TenantID != crossTenantID || event.Target.ID != string(account.PrimaryPrincipalID)) {
			t.Fatal("delivered recovery fact substituted its primary tenant")
		}
	}
	assertPlatformAuditAccess(t, auditEndpoint, primary.Credential, http.StatusForbidden)
	chain = verifyAudit(t, auditEndpoint, primary.Credential)
	if chain.TenantID != crossTenantID || !chain.Complete {
		t.Fatal("recovery broke original tenant audit chain")
	}
	setStatus(crossTenantID, iamv1.OrganizationDisabled, http.StatusOK)
	restartIAM()
	getPaaSApplication(t, paasEndpoint, primary.Credential, "application-customer-only", http.StatusUnauthorized)
	if readAccount(crossTenantID).Organization.Status != iamv1.OrganizationDisabled {
		t.Fatal("restart revived paused tenant access")
	}
	return sensitive
}

// These are real application resources, database-service records and reserved
// quota. The local provisioner gate separately proves a running engine.
func proveTenantResourceProcesses(t *testing.T, ctx context.Context, admin *pgx.Conn, iamEndpoint, auditEndpoint, paasEndpoint, homeBearer, customerBearer string, customer loginResult) (managedservicev1.QuotaEntitlement, managedservicev1.ServiceInstallation, []string) {
	t.Helper()
	base := paasEndpoint + "/managed-services/v1"
	homeUser := createIAMUser(t, iamEndpoint, homeBearer, "account.user", "Home resource member", initialDeveloperPassword, "request-home-resource-member")
	home := loginIAM(t, iamEndpoint, "account.user@organization-process", initialDeveloperPassword, "request-home-resource-login")
	changePasswordIAM(t, iamEndpoint, home.Credential, initialDeveloperPassword, changedDeveloperPassword, "request-home-resource-password")
	developerBinding := putIAMBinding(t, iamEndpoint, homeBearer, homeUser.ID, iamv1.RolePaaSDeveloper, "request-home-resource-role")
	platformUser := createIAMUser(t, iamEndpoint, homeBearer, "resource.platform", "Platform only", initialDeveloperPassword, "request-resource-platform-member")
	platform := loginIAM(t, iamEndpoint, "resource.platform@organization-process", initialDeveloperPassword, "request-resource-platform-login")
	changePasswordIAM(t, iamEndpoint, platform.Credential, initialDeveloperPassword, changedDeveloperPassword, "request-resource-platform-password")
	putIAMBinding(t, iamEndpoint, homeBearer, platformUser.ID, iamv1.RolePlatformOperator, "request-resource-platform-role")
	tenants := []struct {
		id, owner, member string
		memberID          iamv1.PrincipalID
		quota             managedservicev1.QuotaEntitlement
		shared, unique    managedservicev1.ServiceInstallation
	}{
		{id: "organization-process", owner: homeBearer, member: home.Credential, memberID: homeUser.ID},
		{id: "organization-process-customer", owner: customerBearer, member: customer.Credential, memberID: customer.Session.PrincipalID},
	}
	assertStatus := func(response processResponse, status int, action string) {
		t.Helper()
		if response.Status != status {
			t.Fatalf("managed-service %s status=%d want=%d", action, response.Status, status)
		}
	}
	activation := managedservicev1.ActivateQuotaRequest{OfferingID: "postgresql-18", QuotaShapeID: "pg-small", InstanceCount: 2}
	for i := range tenants {
		tenant := &tenants[i]
		response := performJSONWithIdempotency(t, http.MethodPost, base+"/quota-entitlements", tenant.member, "shared-tenant-quota-key", activation)
		assertStatus(response, http.StatusCreated, "activate quota")
		if json.Unmarshal(response.Body, &tenant.quota) != nil || managedservicev1.ValidateQuotaEntitlement(tenant.quota) != nil {
			t.Fatal("invalid real quota")
		}
		replay := performJSONWithIdempotency(t, http.MethodPost, base+"/quota-entitlements", tenant.member, "shared-tenant-quota-key", activation)
		assertStatus(replay, http.StatusOK, "quota replay")
		var replayed managedservicev1.QuotaEntitlement
		if json.Unmarshal(replay.Body, &replayed) != nil || replayed.ID != tenant.quota.ID {
			t.Fatal("tenant quota replay changed identity")
		}
		changed := activation
		changed.InstanceCount = 3
		assertStatus(performJSONWithIdempotency(t, http.MethodPost, base+"/quota-entitlements", tenant.member, "shared-tenant-quota-key", changed), http.StatusConflict, "changed quota replay")
		for j, target := range []*managedservicev1.ServiceInstallation{&tenant.shared, &tenant.unique} {
			id := "postgres-shared-id"
			if j == 1 {
				id = "postgres-only-" + tenant.id
			}
			command := managedservicev1.CreateInstallationRequest{ID: id, Name: "Database for " + tenant.id, OfferingID: "postgresql-18", QuotaEntitlementID: tenant.quota.ID, RegionID: "local-primary"}
			key := fmt.Sprintf("shared-installation-key-%d", j)
			response := performJSONWithIdempotency(t, http.MethodPost, base+"/service-installations", tenant.member, key, command)
			assertStatus(response, http.StatusAccepted, "create installation")
			if json.Unmarshal(response.Body, target) != nil || managedservicev1.ValidateServiceInstallation(*target) != nil || target.ID != id || target.QuotaEntitlementID != tenant.quota.ID || target.Phase != managedservicev1.InstallationPending || target.Endpoint != nil || target.CredentialReference != nil {
				t.Fatal("database acceptance fabricated provisioning or changed its quota identity")
			}
			replay := performJSONWithIdempotency(t, http.MethodPost, base+"/service-installations", tenant.member, key, command)
			assertStatus(replay, http.StatusOK, "installation replay")
			var replayed managedservicev1.ServiceInstallation
			if json.Unmarshal(replay.Body, &replayed) != nil || replayed.Operation.ID != target.Operation.ID {
				t.Fatal("installation replay changed Operation")
			}
			command.Name = "Changed accepted installation"
			assertStatus(performJSONWithIdempotency(t, http.MethodPost, base+"/service-installations", tenant.member, key, command), http.StatusConflict, "changed installation replay")
		}
		full := managedservicev1.CreateInstallationRequest{ID: "postgres-over-quota", Name: "Over quota", OfferingID: "postgresql-18", QuotaEntitlementID: tenant.quota.ID, RegionID: "local-primary"}
		assertStatus(performJSONWithIdempotency(t, http.MethodPost, base+"/service-installations", tenant.member, "over-quota-key", full), http.StatusConflict, "quota exhausted")
	}
	if tenants[0].quota.ID == tenants[1].quota.ID || tenants[0].shared.Operation.ID == tenants[1].shared.Operation.ID {
		t.Fatal("cross-tenant idempotency merged independent quota or Operations")
	}
	for i := range tenants {
		tenant, other := &tenants[i], &tenants[1-i]
		for _, path := range []string{"/quota-entitlements/" + other.quota.ID, "/service-installations/" + other.unique.ID, "/service-installations/" + other.unique.ID + "/operation"} {
			assertStatus(performJSON(t, http.MethodGet, base+path, tenant.member, nil), http.StatusNotFound, "foreign resource ID")
		}
		foreign := managedservicev1.CreateInstallationRequest{ID: "postgres-foreign-quota", Name: "Foreign quota", OfferingID: "postgresql-18", QuotaEntitlementID: other.quota.ID, RegionID: "local-primary"}
		assertStatus(performJSONWithIdempotency(t, http.MethodPost, base+"/service-installations", tenant.member, "foreign-quota-key", foreign), http.StatusNotFound, "foreign quota reservation")
		for _, field := range []string{"tenantId", "organizationId", "requestedBy"} {
			body := map[string]any{"offeringId": "postgresql-18", "quotaShapeId": "pg-small", "instanceCount": 1, field: other.id}
			assertStatus(performJSONWithIdempotency(t, http.MethodPost, base+"/quota-entitlements", tenant.member, "forged-"+field, body), http.StatusBadRequest, "forged authority body")
		}
		for _, path := range []string{"/quota-entitlements", "/service-installations", "/service-installations/" + tenant.shared.ID + "/operation"} {
			for _, query := range []string{"?tenantId=" + other.id, "?cursor=" + other.unique.ID, "?after=" + other.quota.ID} {
				assertStatus(performJSON(t, http.MethodGet, base+path+query, tenant.member, nil), http.StatusBadRequest, "unsupported selector or cursor")
			}
			assertStatus(performJSON(t, http.MethodGet, base+path, platform.Credential, nil), http.StatusForbidden, "platform-only tenant read")
		}
		response := performJSONWithHeaders(t, http.MethodGet, base+"/service-installations/"+tenant.shared.ID, tenant.member, "", nil,
			map[string]string{"X-Tenant-ID": other.id, "Matrix-Tenant-ID": other.id, "Matrix-Subject-Credential": other.member})
		assertStatus(response, http.StatusOK, "caller header isolation")
		var current managedservicev1.ServiceInstallation
		if json.Unmarshal(response.Body, &current) != nil || current.Name != tenant.shared.Name || current.Operation.ID != tenant.shared.Operation.ID {
			t.Fatal("tenant headers selected the other same-ID database")
		}
		response = performJSON(t, http.MethodGet, base+"/service-installations", tenant.owner, nil)
		var list managedservicev1.ServiceInstallationList
		if response.Status != http.StatusOK || json.Unmarshal(response.Body, &list) != nil || len(list.Items) != 2 {
			t.Fatal("tenant service directory changed after cross-tenant or quota attacks")
		}
		for _, item := range list.Items {
			if item.QuotaEntitlementID != tenant.quota.ID || item.Name != tenant.shared.Name {
				t.Fatal("service directory exposed foreign tenant data")
			}
		}
		response = performJSON(t, http.MethodGet, base+"/quota-entitlements", tenant.owner, nil)
		var quotas managedservicev1.QuotaEntitlementList
		if response.Status != http.StatusOK || json.Unmarshal(response.Body, &quotas) != nil || len(quotas.Items) != 1 || quotas.Items[0].ID != tenant.quota.ID || quotas.Items[0].PurchasedCount != 2 || quotas.Items[0].ReservedCount != 2 || quotas.Items[0].ConsumedCount != 0 {
			t.Fatal("quota replay/attack left a partial reservation or exposed another tenant")
		}
		tenant.quota = quotas.Items[0]
		assertManagedServiceRetained(t, paasEndpoint, tenant.owner, tenant.quota, tenant.shared)
	}
	applicationValues := proveApplicationTenantProcesses(t, ctx, admin, paasEndpoint, home, customer, platform.Credential)
	assertStatus(performJSONWithIdempotency(t, http.MethodPost, base+"/quota-entitlements", platform.Credential, "platform-quota-attempt", activation), http.StatusForbidden, "platform-only tenant write")
	revokeIAMBinding(t, iamEndpoint, homeBearer, developerBinding.ID, "request-resource-developer-revoked")
	viewerBinding := putIAMBinding(t, iamEndpoint, homeBearer, homeUser.ID, iamv1.RolePaaSViewer, "request-resource-viewer")
	assertStatus(performJSON(t, http.MethodGet, base+"/service-installations", home.Credential, nil), http.StatusOK, "viewer read")
	assertStatus(performJSONWithIdempotency(t, http.MethodPost, base+"/quota-entitlements", home.Credential, "viewer-quota-attempt", activation), http.StatusForbidden, "viewer write")
	getPaaSApplication(t, paasEndpoint, home.Credential, "application-shared-id", http.StatusOK)
	createPaaSApplication(t, paasEndpoint, home.Credential, "application-viewer-denied", "viewer-denied", "viewer-application-attempt", http.StatusForbidden)
	assertPaaSApplicationAbsent(t, ctx, admin, "application-viewer-denied")
	revokeIAMBinding(t, iamEndpoint, homeBearer, viewerBinding.ID, "request-resource-viewer-revoked")
	assertStatus(performJSON(t, http.MethodGet, base+"/service-installations", home.Credential, nil), http.StatusForbidden, "next-request role revocation")
	getPaaSApplication(t, paasEndpoint, home.Credential, "application-shared-id", http.StatusForbidden)
	waitAllIAMOutboxDelivered(t, ctx, admin)
	waitAllPaaSOutboxDelivered(t, ctx, admin)
	for _, tenant := range tenants {
		for _, action := range []auditv1.Action{auditv1.ActionManagedServiceQuotaEntitlementActivated, auditv1.ActionManagedServiceInstallationCreated} {
			page := queryAudit(t, auditEndpoint, tenant.owner, auditv1.QueryRecordsRequest{PageSize: 100, Action: action}, http.StatusOK)
			expected := 1
			if action == auditv1.ActionManagedServiceInstallationCreated {
				expected = 2
			}
			if page.TenantID != auditv1.TenantID(tenant.id) || len(page.Records) != expected {
				t.Fatal("managed-service audit replay or tenant isolation failed")
			}
			for _, record := range page.Records {
				if record.Source != auditv1.SourcePaaS || record.Event.Actor.ID != auditv1.ActorID(tenant.memberID) || record.Event.IAMDecisionID == "" || record.Event.TenantID != auditv1.TenantID(tenant.id) {
					t.Fatal("managed-service fact lost its original tenant/actor/authority")
				}
			}
		}
	}
	return tenants[1].quota, tenants[1].shared, append(applicationValues, home.Credential, platform.Credential)
}

func proveApplicationTenantProcesses(t *testing.T, ctx context.Context, admin *pgx.Conn, endpoint string, home, customer loginResult, platformCredential string) []string {
	t.Helper()
	tenants := []struct {
		login      loginResult
		operations []paasv1.Operation
		value      string
	}{
		{login: home}, {login: customer},
	}
	assertStatus := func(response processResponse, expected int, boundary string) {
		t.Helper()
		if response.Status != expected {
			t.Fatalf("application tenant %s status=%d want=%d", boundary, response.Status, expected)
		}
	}
	for i := range tenants {
		tenant := &tenants[i]
		id, credential := string(tenant.login.Session.OrganizationID), tenant.login.Credential
		tenant.value = "private-configuration-for-" + id + "-end"
		shared := createPaaSApplication(t, endpoint, credential, "application-shared-id", "application-"+id, "shared-application-key", http.StatusCreated)
		unique := createPaaSApplication(t, endpoint, credential, paasv1.ResourceID("application-only-"+id), "only-"+id, "unique-application-key", http.StatusCreated)
		replay := createPaaSApplication(t, endpoint, credential, shared.Target.ID, "application-"+id, "shared-application-key", http.StatusOK)
		if replay.ID != shared.ID {
			t.Fatal("tenant application replay changed its Operation")
		}
		createPaaSApplication(t, endpoint, credential, shared.Target.ID, "changed-accepted-application", "shared-application-key", http.StatusConflict)
		configuration := createPaaSConfiguration(t, endpoint, credential, "configuration-shared-id", "configuration-"+id, shared.Target.ID, "shared-configuration-key", http.StatusCreated)
		uniqueConfiguration := createPaaSConfiguration(t, endpoint, credential, paasv1.ResourceID("configuration-only-"+id), "only-"+id, unique.Target.ID, "unique-configuration-key", http.StatusCreated)
		configurationReplay := createPaaSConfiguration(t, endpoint, credential, configuration.Target.ID, "configuration-"+id, shared.Target.ID, "shared-configuration-key", http.StatusOK)
		if configurationReplay.ID != configuration.ID {
			t.Fatal("tenant configuration replay changed its Operation")
		}
		createPaaSConfiguration(t, endpoint, credential, configuration.Target.ID, "changed-accepted-configuration", shared.Target.ID, "shared-configuration-key", http.StatusConflict)
		values := map[string]string{"TENANT_MARKER": tenant.value}
		request := paasv1.CreateConfigurationRevisionRequest{ID: "configuration-revision-shared-id", Name: "values-" + id,
			Spec: paasv1.ConfigurationRevisionSpec{ConfigurationID: configuration.Target.ID, Values: values, ContentDigest: paasv1.ConfigurationValuesDigest(values)}}
		response := performJSONWithIdempotency(t, http.MethodPost, endpoint+"/v1/configuration-revisions", credential, "shared-configuration-revision-key", request)
		assertStatus(response, http.StatusCreated, "create configuration revision")
		var revision paasv1.Operation
		if json.Unmarshal(response.Body, &revision) != nil || paasv1.ValidateOperation(revision) != nil || revision.Action != paasv1.OperationCreateConfigurationRevision || revision.Target.ID != request.ID {
			t.Fatal("configuration revision did not produce its real Operation")
		}
		tenant.operations = []paasv1.Operation{shared, unique, configuration, uniqueConfiguration, revision}
		for _, operation := range tenant.operations {
			if operation.Scope != (paasv1.ResourceScope{Kind: paasv1.AuthorityTenant, TenantID: paasv1.TenantID(id)}) || operation.RequestedBy != (paasv1.SubjectRef{Type: paasv1.SubjectUser, ID: string(tenant.login.Session.PrincipalID)}) {
				t.Fatal("application resource lost its current IAM tenant or actor")
			}
		}
	}
	for i := range tenants {
		tenant, other := &tenants[i], &tenants[1-i]
		id, credential := string(tenant.login.Session.OrganizationID), tenant.login.Credential
		shared := tenant.operations[0]
		if shared.ID == other.operations[0].ID {
			t.Fatal("same-key application requests merged two tenants")
		}
		headers := map[string]string{"X-Tenant-ID": string(other.login.Session.OrganizationID), "Matrix-Tenant-ID": string(other.login.Session.OrganizationID), "Matrix-Subject-Credential": other.login.Credential}
		response := performJSONWithHeaders(t, http.MethodGet, endpoint+"/v1/applications/"+string(shared.Target.ID)+"?tenantId="+string(other.login.Session.OrganizationID), credential, "", nil, headers)
		assertStatus(response, http.StatusOK, "same-ID header and URL confinement")
		var application paasv1.Application
		if json.Unmarshal(response.Body, &application) != nil || paasv1.ValidateApplication(application) != nil || application.Metadata.Scope != shared.Scope || application.Metadata.Name != "application-"+id {
			t.Fatal("caller selectors chose the other same-ID application")
		}
		response = performJSONWithHeaders(t, http.MethodGet, endpoint+"/v1/configurations/configuration-shared-id", credential, "", nil, headers)
		var configuration paasv1.Configuration
		if response.Status != http.StatusOK || json.Unmarshal(response.Body, &configuration) != nil || paasv1.ValidateConfiguration(configuration) != nil || configuration.Metadata.Scope != shared.Scope || configuration.ApplicationID != shared.Target.ID || configuration.Metadata.Name != "configuration-"+id {
			t.Fatal("same-ID configuration crossed tenant ownership")
		}
		response = performJSONWithHeaders(t, http.MethodGet, endpoint+"/v1/configuration-revisions/configuration-revision-shared-id", credential, "", nil, headers)
		var revision paasv1.ConfigurationRevision
		if response.Status != http.StatusOK || json.Unmarshal(response.Body, &revision) != nil || paasv1.ValidateConfigurationRevision(revision) != nil || revision.Metadata.Scope != shared.Scope || revision.Spec.Values["TENANT_MARKER"] != tenant.value || bytes.Contains(response.Body, []byte(other.value)) {
			t.Fatal("same-ID configuration revision exposed another tenant's values")
		}
		for _, path := range []string{"/applications/" + string(other.operations[1].Target.ID), "/configurations/" + string(other.operations[3].Target.ID)} {
			assertStatus(performJSONWithHeaders(t, http.MethodGet, endpoint+"/v1"+path, credential, "", nil, headers), http.StatusNotFound, "foreign resource")
		}
		for j, operation := range tenant.operations {
			response := performJSONWithHeaders(t, http.MethodGet, endpoint+"/v1/operations/"+string(operation.ID), credential, "", nil, headers)
			var current paasv1.Operation
			if response.Status != http.StatusOK || json.Unmarshal(response.Body, &current) != nil || !reflect.DeepEqual(current, operation) {
				t.Fatal("Operation read changed its tenant, actor or accepted resource")
			}
			assertStatus(performJSON(t, http.MethodGet, endpoint+"/v1/operations/"+string(other.operations[j].ID), credential, nil), http.StatusNotFound, "foreign Operation")
			assertStatus(performJSON(t, http.MethodGet, endpoint+"/v1/operations/"+string(operation.ID), platformCredential, nil), http.StatusForbidden, "platform-only Operation read")
		}
		for _, path := range []string{"/applications/application-shared-id", "/configurations/configuration-shared-id", "/configuration-revisions/configuration-revision-shared-id"} {
			assertStatus(performJSON(t, http.MethodGet, endpoint+"/v1"+path, platformCredential, nil), http.StatusForbidden, "platform-only tenant read")
		}
		createPaaSConfiguration(t, endpoint, credential, "configuration-foreign-reference", "foreign-application", other.operations[1].Target.ID, "foreign-application-reference", http.StatusNotFound)
		foreign := paasv1.CreateConfigurationRevisionRequest{ID: "configuration-revision-foreign-reference", Name: "foreign-configuration", Spec: paasv1.ConfigurationRevisionSpec{ConfigurationID: other.operations[3].Target.ID, Values: revision.Spec.Values, ContentDigest: revision.Spec.ContentDigest}}
		assertStatus(performJSONWithIdempotency(t, http.MethodPost, endpoint+"/v1/configuration-revisions", credential, "foreign-configuration-reference", foreign), http.StatusNotFound, "foreign configuration reference")
		for _, field := range []string{"tenantId", "organizationId", "requestedBy"} {
			request := map[string]any{"id": "application-forged-" + field, "name": "forged-authority", field: string(other.login.Session.OrganizationID)}
			assertStatus(performJSONWithIdempotency(t, http.MethodPost, endpoint+"/v1/applications", credential, "forged-application-"+field, request), http.StatusBadRequest, "authority body selector")
		}
		var partial int
		if err := admin.QueryRow(ctx, `SELECT
			(SELECT count(*) FROM paas.applications WHERE tenant_id=$1 AND id=ANY($2::text[])) +
			(SELECT count(*) FROM paas.configurations WHERE tenant_id=$1 AND id='configuration-foreign-reference') +
			(SELECT count(*) FROM paas.configuration_revisions WHERE tenant_id=$1 AND id='configuration-revision-foreign-reference') +
			(SELECT count(*) FROM paas.operations WHERE tenant_id=$1 AND target_id=ANY($2::text[])) +
			(SELECT count(*) FROM paas.audit_outbox WHERE tenant_id=$1 AND document#>>'{target,id}'=ANY($2::text[]))`,
			id, []string{"configuration-foreign-reference", "configuration-revision-foreign-reference", "application-forged-tenantId", "application-forged-organizationId", "application-forged-requestedBy"}).Scan(&partial); err != nil || partial != 0 {
			t.Fatalf("rejected tenant attack left resource/Operation/outbox changes=%d err=%v", partial, err)
		}
	}
	createPaaSApplication(t, endpoint, platformCredential, "application-platform-denied", "platform-denied", "platform-application-attempt", http.StatusForbidden)
	assertPaaSApplicationAbsent(t, ctx, admin, "application-platform-denied")
	waitAllIAMOutboxDelivered(t, ctx, admin)
	waitAllPaaSOutboxDelivered(t, ctx, admin)
	for _, tenant := range tenants {
		for _, operation := range tenant.operations {
			action := map[paasv1.OperationAction]auditv1.Action{
				paasv1.OperationCreateApplication:           auditv1.ActionPaaSApplicationCreated,
				paasv1.OperationCreateConfiguration:         auditv1.ActionPaaSConfigurationCreated,
				paasv1.OperationCreateConfigurationRevision: auditv1.ActionPaaSConfigurationRevisionCreated,
			}[operation.Action]
			assertPaaSAuditFact(t, ctx, admin, action, string(operation.Target.ID), operation.RequestedBy.ID)
		}
		var leaked bool
		if err := admin.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM audit.records WHERE event_document::text LIKE '%' || $1 || '%')", tenant.value).Scan(&leaked); err != nil || leaked {
			t.Fatal("configuration values entered the Audit contract")
		}
	}
	return []string{tenants[0].value, tenants[1].value}
}

func assertManagedServiceRetained(t *testing.T, endpoint, bearer string, quota managedservicev1.QuotaEntitlement, installation managedservicev1.ServiceInstallation) {
	t.Helper()
	base := endpoint + "/managed-services/v1"
	for _, resource := range []struct {
		path  string
		value any
	}{
		{"/quota-entitlements/" + quota.ID, quota},
		{"/service-installations/" + installation.ID, installation},
		{"/service-installations/" + installation.ID + "/operation", installation.Operation},
	} {
		response := performJSON(t, http.MethodGet, base+resource.path, bearer, nil)
		encoded, err := json.Marshal(resource.value)
		var expected, actual any
		if err != nil || response.Status != http.StatusOK || json.Unmarshal(encoded, &expected) != nil || json.Unmarshal(response.Body, &actual) != nil || !reflect.DeepEqual(actual, expected) {
			t.Fatal("identity lifecycle changed retained quota, database service or Operation")
		}
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
) paasv1.Operation {
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
		return paasv1.Operation{}
	}
	var operation paasv1.Operation
	if err := json.Unmarshal(response.Body, &operation); err != nil ||
		paasv1.ValidateOperation(operation) != nil ||
		operation.Action != paasv1.OperationCreateConfiguration ||
		operation.Target != (paasv1.ResourceRef{Kind: "Configuration", ID: id}) {
		t.Fatalf("decode PaaS configuration operation: operation=%#v err=%v", operation, err)
	}
	return operation
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

func verifyPaaSInstallation(
	t *testing.T,
	endpoint string,
	bearer string,
	request paasv1.VerifyInstallationRequest,
) paasv1.InstallationVerification {
	t.Helper()
	response := performJSONWithIdempotency(
		t,
		http.MethodPost,
		endpoint+"/v1/installation:verify",
		bearer,
		"verify-process-installation",
		request,
	)
	if response.Status != http.StatusOK {
		t.Fatalf("verify PaaS installation status=%d body=%s", response.Status, response.Body)
	}
	var verification paasv1.InstallationVerification
	if err := json.Unmarshal(response.Body, &verification); err != nil ||
		paasv1.ValidateInstallationVerification(verification) != nil {
		t.Fatalf("decode PaaS installation verification: %v", err)
	}
	return verification
}

func verifyAuditInstallation(
	t *testing.T,
	endpoint string,
	bearer string,
	request auditv1.VerifyInstallationRequest,
) auditv1.InstallationVerification {
	t.Helper()
	response := performJSON(
		t,
		http.MethodPost,
		endpoint+"/v1/installation:verify",
		bearer,
		request,
	)
	if response.Status != http.StatusOK {
		t.Fatalf("verify installation Audit status=%d body=%s", response.Status, response.Body)
	}
	var verification auditv1.InstallationVerification
	if err := json.Unmarshal(response.Body, &verification); err != nil ||
		auditv1.ValidateInstallationVerification(verification) != nil {
		t.Fatalf("decode installation Audit verification: %v", err)
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
			"SELECT (SELECT count(*) FROM paas.audit_outbox WHERE status <> 'DELIVERED') + (SELECT count(*) FROM managedservice.audit_outbox WHERE status <> 'DELIVERED')",
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
		    AND record.event_document#>>'{actor,id}' = decision.principal_id
		    AND record.event_document->>'tenantId' = outbox.tenant_id
		    AND record.event_document#>>'{target,id}' = outbox.document#>>'{target,id}'
		    AND record.event_document->>'operationId' = outbox.operation_id`,
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

func assertPlatformDecisionAuditFacts(t *testing.T, ctx context.Context, admin *pgx.Conn, decisions []iamv1.AuthorizationDecision) {
	t.Helper()
	for _, decision := range decisions {
		expectedResult := auditv1.ResultDenied
		if decision.Allowed {
			expectedResult = auditv1.ResultAllowed
		}
		var count int
		if err := admin.QueryRow(ctx, `SELECT count(*)
			FROM iam.authorization_decisions AS decision
			JOIN iam.audit_outbox AS outbox
			  ON outbox.tenant_id = decision.tenant_id
			 AND outbox.event_document->>'iamDecisionId' = decision.id
			JOIN audit.records AS record
			  ON record.source = 'IAM' AND record.event_id = outbox.event_id
			WHERE decision.tenant_id = 'organization-process'
			  AND decision.id = $1 AND decision.request_id = $2
			  AND decision.allowed = $3
			  AND outbox.event_document->>'action' = 'iam.authorization.decided'
			  AND outbox.event_document#>>'{target,id}' = decision.id
			  AND outbox.event_document#>>'{actor,id}' = decision.principal_id
			  AND outbox.event_document->>'result' = $4
			  AND record.tenant_id = decision.tenant_id
			  AND record.event_document = outbox.event_document`,
			string(decision.ID), decision.RequestID, decision.Allowed, string(expectedResult),
		).Scan(&count); err != nil {
			t.Fatalf("inspect platform authorization Audit fact: %v", err)
		}
		if count != 1 {
			t.Fatalf("platform decision %s has %d correlated Audit facts", decision.ID, count)
		}
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
					SELECT 1 FROM managedservice.audit_outbox
					 WHERE document::text LIKE '%' || $1 || '%'
				)
				OR EXISTS (
					SELECT 1 FROM managedservice.operations AS operation
					 WHERE row_to_json(operation)::text LIKE '%' || $1 || '%'
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
			service(iamv1.ServiceInstallationVerifier, "service-verifier", verifierCredential),
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
) {
	t.Helper()
	if err := iammigration.Bootstrap(ctx, admin); err != nil {
		t.Fatalf("bootstrap platform IAM schema: %v", err)
	}
	if err := auditmigration.Bootstrap(ctx, admin); err != nil {
		t.Fatalf("bootstrap platform Audit schema: %v", err)
	}
	if err := iammigration.Up(ctx, admin); err != nil {
		t.Fatalf("apply platform IAM schema: %v", err)
	}
	if err := auditmigration.Up(ctx, admin); err != nil {
		t.Fatalf("apply platform Audit schema: %v", err)
	}
	if err := paasmigration.Up(ctx, admin); err != nil {
		t.Fatalf("apply platform PaaS schema: %v", err)
	}
	if err := iammigration.Verify(ctx, admin); err != nil {
		t.Fatalf("verify platform IAM schema: %v", err)
	}
	if err := auditmigration.Verify(ctx, admin); err != nil {
		t.Fatalf("verify platform Audit schema: %v", err)
	}
	if err := paasmigration.Verify(ctx, admin); err != nil {
		t.Fatalf("verify platform PaaS schema: %v", err)
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
		createProcessLogin(t, ctx, admin, binding.login, binding.group)
	}
}

func createProcessLogin(t *testing.T, ctx context.Context, admin *pgx.Conn, login, group string) {
	t.Helper()
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
		quoteLiteral(login),
		pgx.Identifier{login}.Sanitize(),
		pgx.Identifier{login}.Sanitize(),
		quoteLiteral(processDBPassword),
		pgx.Identifier{group}.Sanitize(),
		pgx.Identifier{login}.Sanitize(),
	)
	if _, err := admin.Exec(ctx, statement); err != nil {
		t.Fatalf("create authority process login %s: %v", login, err)
	}
}

func seedProcessExecutionProfile(
	t *testing.T,
	ctx context.Context,
	adminConfig *pgx.ConnConfig,
) {
	t.Helper()
	config := adminConfig.Copy()
	config.User = paasWorkerLogin
	config.Password = processDBPassword
	config.DefaultQueryExecMode = pgx.QueryExecModeCacheStatement
	connection, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatalf("connect PaaS worker execution-profile fixture: %v", err)
	}
	defer func() { _ = connection.Close(context.Background()) }()
	transaction, err := connection.BeginTx(ctx, pgx.TxOptions{
		IsoLevel: pgx.Serializable, AccessMode: pgx.ReadWrite,
	})
	if err != nil {
		t.Fatalf("begin PaaS execution-profile fixture: %v", err)
	}
	defer func() { _ = transaction.Rollback(context.Background()) }()
	var tenantSetting string
	var observedAt time.Time
	if err := transaction.QueryRow(
		ctx,
		"SELECT set_config('matrix.tenant_id', $1, true), transaction_timestamp()",
		"organization-process",
	).Scan(&tenantSetting, &observedAt); err != nil || tenantSetting != "organization-process" {
		t.Fatalf("bind PaaS execution-profile tenant: setting=%q err=%v", tenantSetting, err)
	}
	observedAt = observedAt.UTC().Truncate(time.Microsecond)
	platformScope := paasv1.ResourceScope{Kind: paasv1.AuthorityPlatform}
	tenantScope := paasv1.ResourceScope{
		Kind: paasv1.AuthorityTenant, TenantID: "organization-process",
	}
	pool := paasv1.ExecutionPool{
		APIVersion: paasv1.APIVersion,
		Kind:       "ExecutionPool",
		Metadata: paasv1.ResourceMetadata{
			ID: "execution-pool-local", Name: "local", Scope: platformScope,
			Labels:          map[string]string{"matrix-profile": "local-compose"},
			ResourceVersion: 1, CreatedAt: observedAt, UpdatedAt: observedAt,
		},
		Spec: paasv1.ExecutionPoolSpec{
			ExecutionTargetSelector: paasv1.LabelSelector{MatchLabels: map[string]string{
				"matrix-profile": "local-compose",
			}},
			AllowedIsolationGuarantees: []paasv1.IsolationGuarantee{paasv1.IsolationWorkload},
		},
		Status: paasv1.ExecutionPoolStatus{
			Phase: paasv1.ExecutionPoolReady, ExecutionTargetCount: 1,
			ReadyExecutionTargetCount: 1, ObservedAt: observedAt,
		},
	}
	capacity := paasv1.Capacity{
		CPUMillis: 8000, MemoryBytes: 16 * 1024 * 1024 * 1024,
		StorageBytes: 100 * 1024 * 1024 * 1024, WorkloadSlots: 8,
	}
	target := paasv1.ExecutionTarget{
		APIVersion: paasv1.APIVersion,
		Kind:       "ExecutionTarget",
		Metadata: paasv1.ResourceMetadata{
			ID: "execution-target-local", Name: "local", Scope: platformScope,
			Labels: map[string]string{
				"matrix-profile":             "local-compose",
				"matrix-machine-fingerprint": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			ResourceVersion: 1, CreatedAt: observedAt, UpdatedAt: observedAt,
		},
		Spec: paasv1.ExecutionTargetSpec{
			ExecutionPoolID: "execution-pool-local",
			InfrastructureAdapter: paasv1.AdapterRef{
				Kind: paasv1.AdapterInfrastructure, Name: "localmachine", ContractVersion: "v1",
			},
			DeploymentExecutor: paasv1.AdapterRef{
				Kind: paasv1.AdapterDeploymentExecutor, Name: "compose", ContractVersion: "v1",
			},
			DesiredState: paasv1.ExecutionTargetActive,
		},
		Status: paasv1.ExecutionTargetStatus{
			Health:   paasv1.ExecutionTargetHealthReady,
			Capacity: capacity, Allocatable: capacity,
			SupportedIsolationGuarantees: []paasv1.IsolationGuarantee{paasv1.IsolationWorkload},
			ObservedAt:                   observedAt,
		},
	}
	policy := paasv1.PlacementPolicy{
		APIVersion: paasv1.APIVersion,
		Kind:       "PlacementPolicy",
		Metadata: paasv1.ResourceMetadata{
			ID: "placement-policy-local", Name: "default-local", Scope: tenantScope,
			Labels: map[string]string{
				"matrix-profile": "local-compose", "purpose": "default",
			},
			ResourceVersion: 1, CreatedAt: observedAt, UpdatedAt: observedAt,
		},
		Spec: paasv1.PlacementPolicySpec{
			RequiredIsolationGuarantee: paasv1.IsolationWorkload,
			EligibleExecutionPoolIDs:   []paasv1.ResourceID{"execution-pool-local"},
			ExecutionTargetSelector: paasv1.LabelSelector{MatchLabels: map[string]string{
				"matrix-profile": "local-compose",
			}},
			Strategy: paasv1.PlacementFirstFit,
		},
	}
	for name, validation := range map[string]error{
		"pool":   paasv1.ValidateExecutionPool(pool),
		"target": paasv1.ValidateExecutionTarget(target),
		"policy": paasv1.ValidatePlacementPolicy(policy),
	} {
		if validation != nil {
			t.Fatalf("validate PaaS %s execution-profile fixture: %v", name, validation)
		}
	}
	poolDocument, err := json.Marshal(pool)
	if err != nil {
		t.Fatalf("encode PaaS pool fixture: %v", err)
	}
	targetDocument, err := json.Marshal(target)
	if err != nil {
		t.Fatalf("encode PaaS target fixture: %v", err)
	}
	policyDocument, err := json.Marshal(policy)
	if err != nil {
		t.Fatalf("encode PaaS policy fixture: %v", err)
	}
	var reconciled bool
	if err := transaction.QueryRow(
		ctx,
		`SELECT paas.reconcile_local_execution_profile(
		     0, $1::jsonb, 0, $2::jsonb, 0, $3::jsonb
		 )`,
		poolDocument,
		targetDocument,
		policyDocument,
	).Scan(&reconciled); err != nil || !reconciled {
		t.Fatalf("reconcile PaaS execution-profile fixture: reconciled=%t err=%v", reconciled, err)
	}
	if err := transaction.Commit(ctx); err != nil {
		t.Fatalf("commit PaaS execution-profile fixture: %v", err)
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

func runtimeDSN(t *testing.T, admin *pgx.ConnConfig, user string, password string) string {
	t.Helper()
	// ConnString returns the original parse input, not changes to Config fields.
	value, err := url.Parse(admin.ConnString())
	if err != nil || (value.Scheme != "postgres" && value.Scheme != "postgresql") || value.Host == "" {
		t.Fatal("authority process gate requires an explicit PostgreSQL URL")
	}
	value.User = url.UserPassword(user, password)
	query := value.Query()
	query.Del("user")
	query.Del("password")
	query.Set("application_name", "matrix-authority-process:"+user)
	query.Set("pool_max_conns", "2")
	value.RawQuery = query.Encode()
	return value.String()
}

func assertRuntimeProcessLogins(t *testing.T, ctx context.Context, admin *pgx.Conn, users ...string) {
	t.Helper()
	for _, user := range users {
		config, err := pgxpool.ParseConfig(runtimeDSN(t, admin.Config(), user, processDBPassword))
		if err != nil {
			t.Fatal("parse authority process identity probe")
		}
		// The probe must not satisfy the independent running-process assertion.
		config.ConnConfig.RuntimeParams["application_name"] += ":identity-probe"
		probe, err := pgx.ConnectConfig(ctx, config.ConnConfig)
		if err != nil {
			t.Fatalf("connect authority identity probe for %s", user)
		}
		var sessionUser, currentUser string
		var limited bool
		probeErr := probe.QueryRow(ctx, `SELECT session_user, current_user, NOT rolsuper AND NOT rolbypassrls
            FROM pg_roles WHERE rolname=current_user`).Scan(&sessionUser, &currentUser, &limited)
		_ = probe.Close(context.Background())
		if probeErr != nil || sessionUser != user || currentUser != user || !limited {
			t.Fatalf("authority identity probe for %s used an unexpected or privileged role", user)
		}
		var connections int
		var confined bool
		if err := admin.QueryRow(ctx, `SELECT count(*), COALESCE(bool_and(activity.usename=$2 AND NOT role.rolsuper AND NOT role.rolbypassrls),false)
            FROM pg_stat_activity AS activity JOIN pg_roles AS role ON role.rolname=activity.usename
			WHERE activity.datname=current_database() AND activity.application_name=$1`, "matrix-authority-process:"+user, user).Scan(&connections, &confined); err != nil || connections == 0 || connections > 2 || !confined {
			t.Fatalf("running authority %s did not use its bounded non-superuser database login", user)
		}
	}
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
