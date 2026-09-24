package authorityprocess

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
)

const localRecoveryProcessLogin = "matrix_iam_credential_recovery_login"

func localRecoveryMigrationDSN(t *testing.T, dsn string) string {
	t.Helper()
	// The migration authenticates a direct connection, not a pgxpool. Keep
	// the process-only pool bound out of PostgreSQL startup parameters.
	parsed, err := url.Parse(dsn)
	if err != nil {
		t.Fatal("parse local recovery migration DSN")
	}
	query := parsed.Query()
	query.Del("pool_max_conns")
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

// The existing process owner exercises the separate local executable, not a
// production debug endpoint or a substitute in-process recovery implementation.
func proveLocalCredentialRecoveryProcesses(t *testing.T, ctx context.Context, admin *pgx.Conn, root, temporary, binary, iamEndpoint, auditEndpoint, paasEndpoint string,
	bootstrap iamv1.BootstrapDocument, original loginResult, withAuditUnavailable func(func())) (loginResult, func(), []string) {
	t.Helper()
	const password = "Local-Process-Recovered-Password-94!"
	local := localRecoveryProcessAuthority(t, bootstrap)
	encoded, err := iamv1.EncodeLocalCredentialRecoveryAuthority(local)
	if err != nil {
		t.Fatal(err)
	}
	authorityPath := writeProtectedFile(t, temporary, "local-recovery-authority.json", encoded)
	clear(encoded)
	dsnPath := writeProtectedFile(t, temporary, "local-recovery-dsn", []byte(runtimeDSN(t, admin.Config(), localRecoveryProcessLogin, processDBPassword)))
	environment := []string{"MATRIX_IAM_LOCAL_RECOVERY_AUTHORITY_FILE=" + authorityPath, "MATRIX_IAM_LOCAL_RECOVERY_DATABASE_DSN_FILE=" + dsnPath, "MATRIX_IAM_LOCAL_RECOVERY_REQUEST_FILE="}
	inspect := func(path string, want int) iamv1.LocalCredentialRecoveryInspection {
		env := append([]string(nil), environment...)
		env[2] = "MATRIX_IAM_LOCAL_RECOVERY_REQUEST_FILE=" + path
		output := invokeLocalRecoveryProcess(t, ctx, root, binary, "inspect", env, want, nil)
		if want != 0 {
			return iamv1.LocalCredentialRecoveryInspection{}
		}
		var result iamv1.LocalCredentialRecoveryInspection
		if iamv1.DecodeRequest(bytes.NewReader(output), &result) != nil || iamv1.ValidateLocalCredentialRecoveryInspection(result) != nil || result.Scope != local.Scope {
			t.Fatal("local process inspection lost its sealed authority")
		}
		return result
	}
	eligible := inspect("", 0)
	if eligible.State != "ELIGIBLE" || eligible.Expected == nil {
		t.Fatal("original platform primary was not locally eligible")
	}
	request, err := iamv1.SignLocalCredentialRecoveryRequest(local, iamv1.LocalCredentialRecoveryRequest{APIVersion: iamv1.APIVersion, Kind: "LocalCredentialRecoveryRequest", Purpose: iamv1.LocalCredentialRecoveryPurpose,
		CommandID: "local-process-recovery", Scope: local.Scope, Expected: *eligible.Expected, NewPassword: processSecret(t, password)})
	if err != nil {
		t.Fatal(err)
	}
	commitment, err := iamv1.VerifyLocalCredentialRecoveryRequest(local, request)
	if err != nil {
		t.Fatal(err)
	}
	requestPath := writeLocalRecoveryProcessIntent(t, temporary, "local-recovery-request.json", request)
	apply := func(path string, want int, observe func()) iamv1.LocalCredentialRecoveryResult {
		env := append([]string(nil), environment...)
		env[2] = "MATRIX_IAM_LOCAL_RECOVERY_REQUEST_FILE=" + path
		output := invokeLocalRecoveryProcess(t, ctx, root, binary, "apply", env, want, observe)
		if want != 0 {
			return iamv1.LocalCredentialRecoveryResult{}
		}
		var result iamv1.LocalCredentialRecoveryResult
		if iamv1.DecodeRequest(bytes.NewReader(output), &result) != nil || iamv1.ValidateLocalCredentialRecoveryResult(result) != nil || result.Scope != local.Scope {
			t.Fatal("local process returned invalid completion")
		}
		return result
	}
	altered := request
	altered.NewPassword = processSecret(t, "Tampered-Local-Process-Password-95!")
	tamperedPath := writeLocalRecoveryProcessIntent(t, temporary, "local-recovery-tampered.json", altered)
	apply(tamperedPath, 3, nil)
	wrongDSN := writeProtectedFile(t, temporary, "local-recovery-online-dsn", []byte(runtimeDSN(t, admin.Config(), iamAPILogin, processDBPassword)))
	wrongEnvironment := append([]string(nil), environment...)
	wrongEnvironment[1] = "MATRIX_IAM_LOCAL_RECOVERY_DATABASE_DSN_FILE=" + wrongDSN
	invokeLocalRecoveryProcess(t, ctx, root, binary, "inspect", wrongEnvironment, 3, nil)
	var applied iamv1.LocalCredentialRecoveryResult
	var recovered loginResult
	withAuditUnavailable(func() {
		// A held real binding lock makes the short-lived process observable.
		// No database state is changed by this test-only scheduling barrier.
		lock, err := admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer lock.Rollback(ctx)
		if _, err := lock.Exec(ctx, "SELECT id FROM iam.policy_attachments WHERE tenant_id=$1 AND id=$2 FOR UPDATE", local.Scope.AccountID, request.Expected.PlatformBindingID); err != nil {
			t.Fatal(err)
		}
		applied = apply(requestPath, 0, func() {
			observation, cancel := context.WithTimeout(ctx, 4*time.Second)
			defer cancel()
			probeConfig := admin.Config().Copy()
			probe, err := pgx.ConnectConfig(observation, probeConfig)
			if err != nil {
				t.Fatal("connect local process observation")
			}
			defer probe.Close(ctx)
			waitDatabase(t, observation, "purpose-only local recovery process", func() (bool, error) {
				var count int
				var confined bool
				err := probe.QueryRow(observation, `SELECT count(*),COALESCE(bool_and(activity.usename=$1 AND NOT role.rolsuper AND NOT role.rolbypassrls AND activity.wait_event_type='Lock'),false)
					FROM pg_stat_activity activity JOIN pg_roles role ON role.rolname=activity.usename
					WHERE activity.datname=current_database() AND activity.application_name='matrix-iam-local-recovery'`, localRecoveryProcessLogin).Scan(&count, &confined)
				return count == 1 && confined, err
			})
			if err := lock.Commit(ctx); err != nil {
				t.Fatal("release local recovery scheduling lock")
			}
		})
		if applied.State != "APPLIED" || applied.InputCommitment != commitment || applied.PreviousCredentialGeneration != request.Expected.CredentialGeneration || applied.CredentialGeneration != request.Expected.CredentialGeneration+1 || applied.RevokedSessions < 1 {
			t.Fatal("local process did not commit exactly one credential replacement")
		}
		if got := performJSON(t, http.MethodGet, iamEndpoint+"/v1/auth/me", original.Credential, nil); got.Status != http.StatusUnauthorized {
			t.Fatal("local process retained the old primary bearer")
		}
		if got := performJSON(t, http.MethodPost, iamEndpoint+"/v1/auth/login", "", map[string]any{"loginName": "admin", "password": changedAdminPassword, "requestId": "old-password-after-local"}); got.Status != http.StatusUnauthorized {
			t.Fatal("local process retained the previous password")
		}
		recovered = loginIAM(t, iamEndpoint, "admin", password, "local-process-temporary-login")
		createPaaSApplication(t, paasEndpoint, recovered.Credential, "local-recovery-forced-denied", "local-recovery-forced-denied", "local-recovery-forced-denied", http.StatusForbidden)
		assertPlatformAuthorization(t, iamEndpoint, recovered.Credential, "principal-admin", "local-recovery-forced-platform-denied", false)
		changePasswordIAM(t, iamEndpoint, recovered.Credential, password, changedAdminPassword, "local-process-forced-change")
		assertPlatformAuthorization(t, iamEndpoint, recovered.Credential, "principal-admin", "local-recovery-normal-platform-allowed", true)
	})
	// Treat the apply reply as lost: only the sealed command/commitment query
	// supplies the completion and original expected values to a resumed caller.
	query := iamv1.LocalCredentialRecoveryReceiptQuery{APIVersion: iamv1.APIVersion, Kind: "LocalCredentialRecoveryReceiptQuery", CommandID: request.CommandID, InputCommitment: commitment}
	queryBytes, _ := json.Marshal(query)
	queryPath := writeProtectedFile(t, temporary, "local-recovery-receipt-query.json", queryBytes)
	completed := inspect(queryPath, 0)
	if completed.State != "COMPLETED" || completed.Expected == nil || *completed.Expected != request.Expected || completed.Result == nil || *completed.Result != applied {
		t.Fatal("lost apply reply could not be recovered from exact historical receipt")
	}
	if err := os.Remove(requestPath); err != nil {
		t.Fatal("remove completed test intent secret")
	}
	completed = inspect(queryPath, 0)
	if completed.Result == nil || *completed.Result != applied {
		t.Fatal("receipt confirmation required a deleted password/capability file")
	}
	altered, err = iamv1.SignLocalCredentialRecoveryRequest(local, altered)
	if err != nil {
		t.Fatal(err)
	}
	changedPath := writeLocalRecoveryProcessIntent(t, temporary, "local-recovery-changed-input.json", altered)
	apply(changedPath, 4, nil)
	missing := query
	missing.CommandID = "local-process-never-committed"
	missingBytes, _ := json.Marshal(missing)
	missingPath := writeProtectedFile(t, temporary, "local-recovery-not-found.json", missingBytes)
	if result := inspect(missingPath, 0); result.State != "NOT_FOUND" || result.Expected != nil || result.Result != nil {
		t.Fatal("NOT_FOUND inspection issued a new intent")
	}
	waitAllIAMOutboxDelivered(t, ctx, admin)
	eventID, event := findIAMEvent(t, ctx, admin, auditv1.ActionIAMInstallationPrimaryCredentialsRecovered, string(local.Scope.PrincipalID))
	if eventID != string(applied.AuditEventID) || event.InstallationID != local.Scope.InstallationID || event.TenantID != "" || event.Actor != (auditv1.ActorReference{Type: auditv1.ActorSystem, ID: iamv1.LocalCredentialRecoveryActor}) || event.Target.TenantID != auditv1.TenantID(local.Scope.AccountID) || event.IAMDecisionID != "" {
		t.Fatal("local completion did not deliver its exact single security fact")
	}
	assertAuditEventCount(t, ctx, admin, eventID, 1)
	filtered := performJSON(t, http.MethodPost, auditEndpoint+"/v1/platform/records:query", recovered.Credential,
		auditv1.QueryRecordsRequest{PageSize: 10, Action: event.Action, Actor: &event.Actor})
	var page auditv1.RecordPage
	if filtered.Status != http.StatusOK || json.Unmarshal(filtered.Body, &page) != nil || auditv1.ValidateRecordPage(page) != nil ||
		page.InstallationID != local.Scope.InstallationID || page.TenantID != "" || len(page.Records) != 1 ||
		page.Records[0].Source != auditv1.SourceIAM || page.Records[0].Event.EventID != event.EventID {
		t.Fatal("platform query could not select the exact local recovery action and SYSTEM actor")
	}
	assertPlatformAuditAccess(t, auditEndpoint, recovered.Credential, http.StatusOK)
	// Current producer evidence is mandatory even for this SYSTEM action.
	for _, credential := range []string{paasServiceCredential, auditServiceCredential, verifierCredential, recovered.Credential} {
		if response := performJSON(t, http.MethodPost, auditEndpoint+"/v1/events", credential, event); response.Status != http.StatusForbidden && response.Status != http.StatusUnauthorized {
			t.Fatal("non-IAM producer appended local recovery fact")
		}
	}
	for _, mutate := range []func(*auditv1.Event){
		func(e *auditv1.Event) { e.Target.ID = "service-iam" },
		func(e *auditv1.Event) { e.Target.TenantID = "tenant-forged" },
		func(e *auditv1.Event) { e.RequestID = "command-forged" },
	} {
		forged := event
		mutate(&forged)
		if response := performJSON(t, http.MethodPost, auditEndpoint+"/v1/events", iamServiceCredential, forged); response.Status != http.StatusForbidden {
			t.Fatal("IAM producer accepted an uncommitted local recovery fact")
		}
	}
	verifyHistorical := func() {
		inspect("", 3) // revoked platform binding cannot issue another intent
		// An old copy retained by an operator is an adversarial replay fixture,
		// not a resume path that manufactures a fresh expected generation.
		oldCopy := writeLocalRecoveryProcessIntent(t, temporary, "local-recovery-old-copy.json", request)
		result := apply(oldCopy, 0, nil)
		if err := os.Remove(oldCopy); err != nil {
			t.Fatal("remove historical test intent copy")
		}
		if result.State != "EQUAL_REPLAY" {
			t.Fatal("old local command applied again after platform revocation")
		}
		result.State = "APPLIED"
		if result != applied {
			t.Fatal("historical replay changed completion metadata")
		}
		completed := inspect(queryPath, 0)
		if completed.Result == nil || *completed.Result != applied {
			t.Fatal("revocation/restart erased local completion")
		}
		response := performJSON(t, http.MethodPost, auditEndpoint+"/v1/events", iamServiceCredential, event)
		var duplicate auditv1.IngestionResult
		if response.Status != http.StatusOK || json.Unmarshal(response.Body, &duplicate) != nil || duplicate.Outcome != auditv1.IngestionDuplicate {
			t.Fatal("historical local fact could not replay after user revocation/restart")
		}
		assertAuditEventCount(t, ctx, admin, eventID, 1)
		if response := performJSON(t, http.MethodPost, iamEndpoint+"/v1/auth/login", "", map[string]any{"loginName": "admin", "password": password, "requestId": "old-local-password-after-replay"}); response.Status != http.StatusUnauthorized {
			t.Fatal("old replay replaced a later password")
		}
	}
	secrets := []string{password, string(local.CapabilityKey.CopyBytes()), string(request.Capability.CopyBytes()), string(altered.Capability.CopyBytes()), recovered.Credential}
	return recovered, verifyHistorical, secrets
}

func localRecoveryProcessAuthority(t *testing.T, bootstrap iamv1.BootstrapDocument) iamv1.LocalCredentialRecoveryAuthority {
	t.Helper()
	digest, err := iamv1.BootstrapDigest(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	return iamv1.LocalCredentialRecoveryAuthority{APIVersion: iamv1.APIVersion, Kind: "LocalCredentialRecoveryAuthority", Purpose: iamv1.LocalCredentialRecoveryPurpose,
		Scope:         iamv1.LocalCredentialRecoveryScope{InstallationID: bootstrap.InstallationID, BootstrapDigest: digest, AccountID: bootstrap.Organization.ID, PrincipalID: bootstrap.Administrator.ID},
		CapabilityKey: processSecret(t, base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x6d}, 32)))}
}

func writeLocalRecoveryProcessIntent(t *testing.T, temporary, name string, request iamv1.LocalCredentialRecoveryRequest) string {
	t.Helper()
	encoded, err := iamv1.EncodeLocalCredentialRecoveryRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	return writeProtectedFile(t, temporary, name, encoded)
}

func invokeLocalRecoveryProcess(t *testing.T, ctx context.Context, root, binary, mode string, environment []string, want int, observe func()) []byte {
	t.Helper()
	child := startChild(t, root, binary, environment, mode)
	defer child.stop()
	if observe != nil {
		observe()
	}
	err := child.wait(50 * time.Second)
	code := 0
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatal("local recovery process did not finish with a stable result")
		}
		code = exitErr.ExitCode()
	}
	if code != want {
		t.Fatalf("local recovery %s exit=%d want=%d", mode, code, want)
	}
	codes := map[int]string{0: "", 2: "IAM_LOCAL_RECOVERY_INVALID", 3: "IAM_LOCAL_RECOVERY_FORBIDDEN", 4: "IAM_LOCAL_RECOVERY_CONFLICT", 6: "IAM_LOCAL_RECOVERY_UNAVAILABLE"}
	if strings.TrimSpace(child.stderr.String()) != codes[code] || code != 0 && child.stdout.Len() != 0 || child.stdout.Len() > iamv1.MaxLocalCredentialRecoveryBytes {
		t.Fatal("local recovery output violated its closed sanitized contract")
	}
	if ctx.Err() != nil {
		t.Fatal("local recovery gate context expired")
	}
	return append([]byte(nil), child.stdout.Bytes()...)
}
