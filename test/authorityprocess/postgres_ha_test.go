package authorityprocess

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/installation/test/postgresqlha"
)

const postgresHAAuthorityAcceptance = "MATRIX_POSTGRES_HA_AUTHORITY_ACCEPTANCE"

// TestIAMPostgreSQLFailoverProcesses proves that current IAM and Audit
// processes consume the controlled PostgreSQL failover fixture. The fixture is
// not a product topology or automatic election mechanism; signed deployment
// support remains an installation acceptance boundary.
func TestIAMPostgreSQLFailoverProcesses(t *testing.T) {
	if os.Getenv(postgresHAAuthorityAcceptance) != "1" {
		t.Skip("set MATRIX_POSTGRES_HA_AUTHORITY_ACCEPTANCE=1 in the isolated PostgreSQL HA gate")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	baseTask := os.Getenv("MATRIX_POSTGRES_HA_TASK")
	fixture, err := postgresqlha.Start(ctx, postgresqlha.Config{
		ImageID: os.Getenv("MATRIX_POSTGRES_HA_IMAGE_ID"),
		TaskID:  baseTask + "-authority",
	})
	if err != nil {
		t.Fatal("start authority PostgreSQL HA fixture", err)
	}
	t.Cleanup(func() {
		cleanup, cleanupCancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cleanupCancel()
		if err := fixture.Close(cleanup); err != nil {
			t.Error("clean authority PostgreSQL HA fixture", err)
		}
	})

	adminConfig, err := pgx.ParseConfig(fixture.EndpointDSN())
	if err != nil {
		t.Fatal("parse authority PostgreSQL HA endpoint", err)
	}
	adminConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	admin, err := pgx.ConnectConfig(ctx, adminConfig)
	if err != nil {
		t.Fatal("connect authority PostgreSQL HA endpoint", err)
	}
	defer func() {
		if admin != nil {
			_ = admin.Close(context.Background())
		}
	}()
	assertPostgres18(t, ctx, admin)
	assertCleanSchemas(t, ctx, admin)
	applyPlatformSchemas(t, ctx, admin)
	createProcessLogins(t, ctx, admin)
	const replicaLogin = "matrix_postgres_ha_iam_replica"
	createProcessLogin(t, ctx, admin, replicaLogin, "matrix_iam_api")

	root := repositoryRoot(t)
	temporary := t.TempDir()
	iamBinary := buildAuthorityBinary(t, ctx, root, temporary, "matrix-iam-ha", "./app/service/iam/cmd/matrix-iam")
	auditBinary := buildAuthorityBinary(t, ctx, root, temporary, "matrix-audit-ha", "./app/service/audit/cmd/matrix-audit")
	dispatcherBinary := buildAuthorityBinary(t, ctx, root, temporary, "matrix-iam-audit-dispatcher-ha", "./app/service/iam/cmd/matrix-iam-audit-dispatcher")

	bootstrap := processBootstrap(t)
	bootstrapBytes, err := iamv1.EncodeBootstrapDocument(bootstrap)
	if err != nil {
		t.Fatal("encode authority HA bootstrap", err)
	}
	bootstrapPath := writeProtectedFile(t, temporary, "iam-bootstrap.json", bootstrapBytes)
	clear(bootstrapBytes)
	iamDSNPath := writeProtectedFile(t, temporary, "iam-dsn", []byte(runtimeDSN(t, adminConfig, iamAPILogin, processDBPassword)))
	replicaDSNPath := writeProtectedFile(t, temporary, "iam-replica-dsn", []byte(runtimeDSN(t, adminConfig, replicaLogin, processDBPassword)))
	iamWorkerDSNPath := writeProtectedFile(t, temporary, "iam-worker-dsn", []byte(runtimeDSN(t, adminConfig, iamWorkerLogin, processDBPassword)))
	auditDSNPath := writeProtectedFile(t, temporary, "audit-dsn", []byte(runtimeDSN(t, adminConfig, auditRuntimeLogin, processDBPassword)))
	iamCredentialPath := writeProtectedFile(t, temporary, "iam-service-credential", []byte(iamServiceCredential))
	auditCredentialPath := writeProtectedFile(t, temporary, "audit-service-credential", []byte(auditServiceCredential))
	iamCursorKeyPath := writeProtectedFile(t, temporary, "iam-cursor-key", []byte(strings.Repeat("35", 32)))
	auditCursorKeyPath := writeProtectedFile(t, temporary, "audit-cursor-key", []byte(hex.EncodeToString(bytes.Repeat([]byte{0x6a}, 32))))
	iamWrappingKeyPath := writeProcessAccessKeyWrapping(t, temporary, bootstrap)
	iamTOTPKeyPath := writeProcessTOTPKeyring(t, temporary, bootstrap)
	iamEmailKeyPath := writeProcessEmailVerificationKeyring(t, temporary, bootstrap)
	auditEdgeAssertion := strings.Repeat("2", 64)
	auditEdgeAssertionPath := writeProtectedFile(t, temporary, "audit-edge-assertion", []byte(auditEdgeAssertion))

	iamAddress := freeAddress(t)
	replicaAddress := freeAddress(t)
	auditAddress := freeAddress(t)
	dispatcherAddress := freeAddress(t)
	iamEndpoint := "http://" + iamAddress
	replicaEndpoint := "http://" + replicaAddress
	auditEndpoint := "http://" + auditAddress
	commonIAM := []string{
		"MATRIX_IAM_BOOTSTRAP_FILE=" + bootstrapPath,
		"MATRIX_IAM_CURSOR_KEY_FILE=" + iamCursorKeyPath,
		"MATRIX_IAM_ACCESS_KEY_WRAPPING_KEYRING_FILE=" + iamWrappingKeyPath,
		"MATRIX_IAM_TOTP_KEYRING_FILE=" + iamTOTPKeyPath,
		"MATRIX_IAM_EMAIL_VERIFICATION_KEYRING_FILE=" + iamEmailKeyPath,
	}
	iamEnvironment := append([]string{
		"MATRIX_IAM_DATABASE_DSN_FILE=" + iamDSNPath,
		"MATRIX_IAM_LISTEN_ADDRESS=" + iamAddress,
	}, commonIAM...)
	replicaEnvironment := append([]string{
		"MATRIX_IAM_DATABASE_DSN_FILE=" + replicaDSNPath,
		"MATRIX_IAM_LISTEN_ADDRESS=" + replicaAddress,
	}, commonIAM...)
	auditEnvironment := []string{
		"MATRIX_AUDIT_DATABASE_DSN_FILE=" + auditDSNPath,
		"MATRIX_AUDIT_IAM_ENDPOINT=" + iamEndpoint,
		"MATRIX_AUDIT_SERVICE_CREDENTIAL_FILE=" + auditCredentialPath,
		"MATRIX_AUDIT_CURSOR_KEY_FILE=" + auditCursorKeyPath,
		"MATRIX_AUDIT_LISTEN_ADDRESS=" + auditAddress,
		"MATRIX_AUDIT_INSTALLATION_ID=" + bootstrap.InstallationID,
		"MATRIX_AUDIT_NORTHBOUND_ORIGIN=https://api.matrix.test:443",
		"MATRIX_AUDIT_EDGE_ASSERTION_FILE=" + auditEdgeAssertionPath,
	}
	dispatcherEnvironment := []string{
		"MATRIX_IAM_AUDIT_DATABASE_DSN_FILE=" + iamWorkerDSNPath,
		"MATRIX_IAM_AUDIT_ENDPOINT=" + auditEndpoint,
		"MATRIX_IAM_AUDIT_CREDENTIAL_FILE=" + iamCredentialPath,
		"MATRIX_IAM_AUDIT_WORKER_ID=iam-postgres-ha-worker",
		"MATRIX_IAM_AUDIT_LISTEN_ADDRESS=" + dispatcherAddress,
	}

	children := make([]*childProcess, 0, 5)
	sensitive := []string{
		initialAdminPassword, changedAdminPassword,
		initialReaderPassword, changedReaderPassword,
		iamServiceCredential, auditServiceCredential, auditEdgeAssertion,
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

	iamProcess := start(iamBinary, iamEnvironment)
	waitHTTPStatus(t, ctx, iamProcess, iamEndpoint+"/ready", http.StatusOK)
	replicaProcess := start(iamBinary, replicaEnvironment)
	waitHTTPStatus(t, ctx, replicaProcess, replicaEndpoint+"/ready", http.StatusOK)
	auditProcess := start(auditBinary, auditEnvironment)
	waitHTTPStatus(t, ctx, auditProcess, auditEndpoint+"/ready", http.StatusOK)
	dispatcher := start(dispatcherBinary, dispatcherEnvironment)
	waitHTTPStatus(t, ctx, dispatcher, "http://"+dispatcherAddress+"/ready", http.StatusOK)
	waitAllIAMOutboxDelivered(t, ctx, admin)

	owner := loginIAM(t, iamEndpoint, "admin", initialAdminPassword, "ha-owner-login")
	sensitive = append(sensitive, owner.Credential)
	changePasswordIAM(t, iamEndpoint, owner.Credential, initialAdminPassword, changedAdminPassword, "ha-owner-password")
	member := createIAMUser(t, replicaEndpoint, owner.Credential, "ha.viewer", "HA viewer", initialReaderPassword, "ha-viewer-create")
	attachment := createIAMPolicyAttachment(t, iamEndpoint, owner.Credential, member.ID, iamv1.SystemPolicyPaaSViewer, "ha-viewer-grant")
	memberLogin := loginIAM(t, replicaEndpoint, member.LoginName+"@"+string(member.AccountID), initialReaderPassword, "ha-viewer-login")
	sensitive = append(sensitive, memberLogin.Credential)
	changePasswordIAM(t, replicaEndpoint, memberLogin.Credential, initialReaderPassword, changedReaderPassword, "ha-viewer-password")
	assertHAAuthorization(t, replicaEndpoint, memberLogin.Credential, "ha-before-revoke", true)
	waitAllIAMOutboxDelivered(t, ctx, admin)

	// Keep the revoke and its immutable completion pending in the source outbox
	// so the database transition must retain and later deliver the exact fact.
	dispatcher.stop()
	revokeIAMPolicyAttachment(t, replicaEndpoint, owner.Credential, attachment.ID, attachment.ResourceVersion, "ha-viewer-revoke")
	assertHAAuthorization(t, iamEndpoint, memberLogin.Credential, "ha-after-revoke", false)
	created := readHAPolicyAttachmentChange(t, iamEndpoint, owner.Credential, "ha-viewer-grant")
	revoked := readHAPolicyAttachmentChange(t, replicaEndpoint, owner.Credential, "ha-viewer-revoke")
	var pending int
	if err := admin.QueryRow(ctx, "SELECT count(*) FROM iam.audit_outbox WHERE status <> 'DELIVERED'").Scan(&pending); err != nil || pending == 0 {
		t.Fatal("revocation did not leave a real pending IAM Audit fact", err)
	}

	checkpoint, err := fixture.ConfirmedCheckpoint(ctx)
	if err != nil {
		t.Fatal("confirm authority PostgreSQL checkpoint", err)
	}
	if err := admin.Close(ctx); err != nil {
		t.Fatal("close pre-failover administrative connection", err)
	}
	admin = nil

	observation, sawUnavailable, err := failoverWhileDenying(
		ctx, fixture, checkpoint, replicaEndpoint, memberLogin.Credential,
	)
	if err != nil {
		t.Fatal("fail over authority PostgreSQL", err)
	}
	if !sawUnavailable {
		t.Fatal("authority process never exposed a bounded failure-closed interval during database failover")
	}
	waitHTTPStatus(t, ctx, iamProcess, iamEndpoint+"/ready", http.StatusOK)
	waitHTTPStatus(t, ctx, replicaProcess, replicaEndpoint+"/ready", http.StatusOK)
	waitHTTPStatus(t, ctx, auditProcess, auditEndpoint+"/ready", http.StatusOK)
	if time.Since(observation.FailureDetectedAt) > 60*time.Second {
		t.Fatal("authority processes exceeded the bounded post-failover recovery observation")
	}

	admin, err = pgx.ConnectConfig(ctx, adminConfig)
	if err != nil {
		t.Fatal("reconnect authority PostgreSQL endpoint after failover", err)
	}
	assertRuntimeProcessLogins(t, ctx, admin, iamAPILogin, replicaLogin, auditRuntimeLogin)
	assertHAAuthorization(t, iamEndpoint, memberLogin.Credential, "ha-after-failover-a", false)
	assertHAAuthorization(t, replicaEndpoint, memberLogin.Credential, "ha-after-failover-b", false)
	if current := readHAPolicyAttachmentChange(t, replicaEndpoint, owner.Credential, "ha-viewer-grant"); !reflect.DeepEqual(current, created) {
		t.Fatal("PostgreSQL failover changed the original attachment completion")
	}
	if current := readHAPolicyAttachmentChange(t, iamEndpoint, owner.Credential, "ha-viewer-revoke"); !reflect.DeepEqual(current, revoked) {
		t.Fatal("PostgreSQL failover changed the original revocation completion")
	}
	if err := admin.QueryRow(ctx, "SELECT count(*) FROM iam.audit_outbox WHERE status <> 'DELIVERED'").Scan(&pending); err != nil || pending == 0 {
		t.Fatal("PostgreSQL failover lost the pending IAM Audit fact", err)
	}

	// A fresh worker resumes the physical-owner lease after failover. The old
	// worker process is never reused as evidence of a completed delivery.
	dispatcherAddress = freeAddress(t)
	dispatcherEnvironment[len(dispatcherEnvironment)-1] = "MATRIX_IAM_AUDIT_LISTEN_ADDRESS=" + dispatcherAddress
	dispatcher = start(dispatcherBinary, dispatcherEnvironment)
	waitHTTPStatus(t, ctx, dispatcher, "http://"+dispatcherAddress+"/ready", http.StatusOK)
	assertRuntimeProcessLogin(t, ctx, admin, iamWorkerLogin, 2)
	waitAllIAMOutboxDelivered(t, ctx, admin)
	assertHAOutboxStoredOnce(t, ctx, admin)
	chain := verifyAudit(t, auditEndpoint, owner.Credential)
	if chain.State != auditv1.VerificationVerified || !chain.Complete || chain.TenantID != auditv1.TenantID(member.AccountID) {
		t.Fatal("PostgreSQL failover changed the tenant Audit chain")
	}

	if err := fixture.RejoinFencedPrimary(ctx); err != nil {
		t.Fatal("rejoin fenced PostgreSQL primary", err)
	}
	if err := fixture.AssertSinglePrimary(ctx); err != nil {
		t.Fatal("prove single PostgreSQL primary after rejoin", err)
	}
	assertHAAuthorization(t, replicaEndpoint, memberLogin.Credential, "ha-after-rejoin", false)
	t.Logf("IAM_POSTGRES_HA confirmed_rpo_bytes=%d database_rto_ms=%d authority_recovery_ms=%d",
		observation.ConfirmedRPOBytes,
		observation.RTO.Milliseconds(),
		time.Since(observation.FailureDetectedAt).Milliseconds(),
	)
}

func assertHAAuthorization(t *testing.T, endpoint, subject, requestID string, allowed bool) {
	t.Helper()
	request, err := iamv1.NewAuthorizationRequest(
		iamv1.ActionPaaSApplicationRead,
		iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "application-postgres-ha"},
		iamv1.AuthorizationResourceInstance,
		"",
		requestID,
		requestID,
	)
	if err != nil {
		t.Fatal("construct authority HA authorization", err)
	}
	response := performJSONWithHeaders(t, http.MethodPost, endpoint+"/v1/authorize", paasServiceCredential, "", request,
		map[string]string{"Matrix-Subject-Credential": subject})
	var decision iamv1.AuthorizationDecision
	if response.Status != http.StatusOK || json.Unmarshal(response.Body, &decision) != nil ||
		iamv1.ValidateAuthorizationDecision(decision) != nil || decision.Allowed != allowed {
		t.Fatalf("authority HA authorization allowed=%v want=%v status=%d", decision.Allowed, allowed, response.Status)
	}
}

func readHAPolicyAttachmentChange(t *testing.T, endpoint, bearer, requestID string) iamv1.PolicyAttachmentChange {
	t.Helper()
	response := performJSON(t, http.MethodGet,
		endpoint+"/v1/policy-attachment-changes/by-request/"+requestID, bearer, nil)
	var change iamv1.PolicyAttachmentChange
	if response.Status != http.StatusOK || json.Unmarshal(response.Body, &change) != nil ||
		iamv1.ValidatePolicyAttachmentChange(change) != nil || change.RequestID != requestID {
		t.Fatalf("read authority HA attachment completion %s status=%d", requestID, response.Status)
	}
	return change
}

type postgresHAFailoverResult struct {
	observation postgresqlha.FailoverObservation
	err         error
}

func failoverWhileDenying(
	ctx context.Context,
	fixture *postgresqlha.Fixture,
	checkpoint postgresqlha.Checkpoint,
	endpoint string,
	subject string,
) (postgresqlha.FailoverObservation, bool, error) {
	result := make(chan postgresHAFailoverResult, 1)
	go func() {
		observation, failoverErr := fixture.ControlledFailover(ctx, checkpoint)
		result <- postgresHAFailoverResult{observation: observation, err: failoverErr}
	}()

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	client := &http.Client{Transport: transport, Timeout: 750 * time.Millisecond}
	defer transport.CloseIdleConnections()
	var unavailable bool
	var probeErr error
	var sequence uint64
	for {
		select {
		case completed := <-result:
			return completed.observation, unavailable, errors.Join(completed.err, probeErr)
		default:
		}
		if probeErr != nil {
			select {
			case completed := <-result:
				return completed.observation, unavailable, errors.Join(completed.err, probeErr)
			case <-ctx.Done():
				return postgresqlha.FailoverObservation{}, unavailable, errors.Join(ctx.Err(), probeErr)
			case <-time.After(10 * time.Millisecond):
			}
			continue
		}
		sequence++
		requestID := fmt.Sprintf("ha-during-failover-%d", sequence)
		authorization, requestErr := iamv1.NewAuthorizationRequest(
			iamv1.ActionPaaSApplicationRead,
			iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "application-postgres-ha"},
			iamv1.AuthorizationResourceInstance,
			"",
			requestID,
			requestID,
		)
		if requestErr != nil {
			probeErr = requestErr
			continue
		}
		body, requestErr := json.Marshal(authorization)
		if requestErr != nil {
			probeErr = requestErr
			continue
		}
		probeCtx, cancel := context.WithTimeout(ctx, 750*time.Millisecond)
		httpRequest, requestErr := http.NewRequestWithContext(
			probeCtx, http.MethodPost, endpoint+"/v1/authorize", bytes.NewReader(body),
		)
		if requestErr != nil {
			clear(body)
			cancel()
			probeErr = requestErr
			continue
		}
		httpRequest.Header.Set("Content-Type", "application/json")
		httpRequest.Header.Set("Authorization", "Bearer "+paasServiceCredential)
		httpRequest.Header.Set("Matrix-Subject-Credential", subject)
		response, callErr := client.Do(httpRequest)
		clear(body)
		if callErr != nil {
			cancel()
			unavailable = true
		} else {
			responseBody, readErr := io.ReadAll(io.LimitReader(response.Body, 1024*1024))
			closeErr := response.Body.Close()
			cancel()
			if readErr != nil || closeErr != nil {
				unavailable = true
			} else if response.StatusCode == http.StatusServiceUnavailable {
				unavailable = true
			} else if response.StatusCode == http.StatusOK {
				var decision iamv1.AuthorizationDecision
				if json.Unmarshal(responseBody, &decision) != nil || iamv1.ValidateAuthorizationDecision(decision) != nil || decision.Allowed {
					probeErr = errors.New("database failover returned an invalid or stale Allow decision")
				}
			} else {
				probeErr = fmt.Errorf("database failover returned unexpected IAM status %d", response.StatusCode)
			}
			clear(responseBody)
		}
		select {
		case completed := <-result:
			return completed.observation, unavailable, errors.Join(completed.err, probeErr)
		case <-ctx.Done():
			return postgresqlha.FailoverObservation{}, unavailable, errors.Join(ctx.Err(), probeErr)
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func assertHAOutboxStoredOnce(t *testing.T, ctx context.Context, admin *pgx.Conn) {
	t.Helper()
	var outbox, joined, distinct int
	if err := admin.QueryRow(ctx, `
SELECT count(*),count(record.event_id),count(DISTINCT record.event_id)
  FROM iam.audit_outbox AS outbox
  LEFT JOIN audit.records AS record
    ON record.source='IAM' AND record.event_id=outbox.event_id`).Scan(&outbox, &joined, &distinct); err != nil {
		t.Fatal("inspect post-failover IAM Audit delivery", err)
	}
	if outbox == 0 || joined != outbox || distinct != outbox {
		t.Fatalf("post-failover IAM Audit outbox=%d joined=%d distinct=%d", outbox, joined, distinct)
	}
}
