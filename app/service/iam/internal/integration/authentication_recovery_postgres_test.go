package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp/hotp"

	installationv1 "github.com/xiak/matrix/api/adapter/installation/v1"
	auditv1 "github.com/xiak/matrix/api/audit/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/iam/internal/authority"
	iampostgres "github.com/xiak/matrix/app/service/iam/internal/data/postgres"
	"github.com/xiak/matrix/app/service/iam/internal/usecase/authenticationrecovery"
	"github.com/xiak/matrix/app/service/iam/internal/usecase/identityaccess"
	iammigration "github.com/xiak/matrix/app/service/iam/migration"
)

const authenticationRecoveryTestRole = "matrix_iam_authentication_recovery_test"

// The close half is independently executable while installation owns the
// destructive restore. This gate uses real qualification changes and the
// production Go/SQL transaction, not two independently bootstrapped databases
// as a substitute for retained-state recovery.
func TestIAMAuthenticationRecoveryClosePostgres(t *testing.T) {
	dsn := os.Getenv("MATRIX_IAM_AUTHENTICATION_RECOVERY_CLOSE_POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Skip("set MATRIX_IAM_AUTHENTICATION_RECOVERY_CLOSE_POSTGRES_TEST_DSN to its own PostgreSQL 18 database")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	database, config := openAuthenticationRecoveryDatabase(t, ctx, dsn, "matrix_iam_auth_recovery_close_")
	defer database.Close(context.Background())
	assertIAMPostgres18(t, ctx, database)
	assertCleanIAMSchema(t, ctx, database)
	applyIAMSchema(t, ctx, database)
	createIAMHTTPRole(t, ctx, database)
	createAuthenticationRecoveryTestRoles(t, ctx, database)
	createAuthenticationRecoveryBackupRole(t, ctx, database)
	document := iamHTTPBootstrap(t)
	document.InstallationID = "mxi-" + strings.Repeat("c", 32)
	api, _ := authenticationRecoveryAPI(t, ctx, dsn, document)
	status, err := bootstrapIAMWithTOTP(t, ctx, api, document)
	if err != nil {
		t.Fatal(err)
	}
	login, err := api.Login(ctx, iamv1.LoginRequest{LoginName: document.Administrator.LoginName, Password: document.Administrator.Password, RequestID: "close-root-login"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := api.ChangePassword(ctx, login.Credential, iamv1.ChangePasswordRequest{CurrentPassword: document.Administrator.Password,
		NewPassword: iamHTTPSecret(t, changedAdminPassword), RequestID: "close-root-password"}); err != nil {
		t.Fatal(err)
	}
	if _, err := api.CreateAccount(ctx, login.Credential, iamv1.CreateAccountRequest{ID: "close-account-b", DisplayName: "Close account B",
		RootLoginName: "close-root-b", RootDisplayName: "Close root B", InitialPassword: iamHTTPSecret(t, "Close-Other-Password-639!"), RequestID: "close-account-create"}); err != nil {
		t.Fatal(err)
	}
	readLeaseAt := func(zone string) installationv1.TOTPBackupSnapshotLease {
		t.Helper()
		backup := config.Copy()
		backup.User, backup.Password = "matrix_iam_backup_custody_login", "matrix-authority-process-test-only"
		if zone != "" {
			backup.RuntimeParams["timezone"] = zone
		}
		snapshot, err := iampostgres.OpenTOTPBackupSnapshot(ctx, backup)
		if err != nil {
			t.Fatal(err)
		}
		lease := snapshot.Lease()
		if err := snapshot.Close(); err != nil {
			t.Fatal(err)
		}
		return lease
	}
	readLease := func() installationv1.TOTPBackupSnapshotLease { return readLeaseAt("") }
	t.Run("password-age-timezone", func(t *testing.T) {
		// Both reads use the restricted production snapshot path after a real
		// password change. Connection formatting cannot change qualification.
		utc, local := readLeaseAt("UTC"), readLeaseAt("Asia/Shanghai")
		if utc.AuthenticationStateDigest != local.AuthenticationStateDigest || utc.CustodyDigest != local.CustodyDigest {
			t.Fatal("the same password age/history changed qualification with connection timezone")
		}
	})
	assertNoClose := func() {
		t.Helper()
		var state string
		var epoch, closures, facts int
		if err := database.QueryRow(ctx, `SELECT state,epoch,(SELECT count(*) FROM iam.authentication_recovery_closures),
	 (SELECT count(*) FROM iam.audit_outbox WHERE event_document->>'action'='iam.authentication-recovery.closed')
	 FROM iam.authentication_recovery_state WHERE singleton`).Scan(&state, &epoch, &closures, &facts); err != nil || state != "OPEN" || epoch != 0 || closures != 0 || facts != 0 {
			t.Fatal("rejected/uncommitted close changed authority state", err)
		}
	}
	waitBlocked := func(t *testing.T, role string, leader int32, peer ...uint32) {
		t.Helper()
		var peerPID uint32
		if len(peer) != 0 {
			peerPID = peer[0]
		}
		waiting, stop := context.WithTimeout(ctx, 5*time.Second)
		defer stop()
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			var blocked bool
			// PostgreSQL may queue another row-lock waiter between this peer
			// and the leader. Follow the actual dependency, not queue order.
			if err := database.QueryRow(waiting, `WITH RECURSIVE waits(pid,blocker) AS (
			 SELECT pid,unnest(pg_blocking_pids(pid)) FROM pg_stat_activity WHERE datname=current_database() AND usename=$1 AND ($3::bigint=0 OR pid=$3)
			 UNION SELECT pid,unnest(pg_blocking_pids(blocker)) FROM waits)
			 SELECT EXISTS(SELECT 1 FROM waits WHERE blocker=$2)`, role, leader, peerPID).Scan(&blocked); err != nil {
				t.Fatal("observe actual authentication barrier dependency", err)
			}
			if blocked {
				return
			}
			select {
			case <-ticker.C:
			case <-waiting.Done():
				t.Fatal("peer did not wait on authentication barrier")
			}
		}
	}
	workflow, _ := authenticationRecoveryWorkflow(t, ctx, dsn)
	assertStaleQualification := func(t *testing.T, before installationv1.TOTPBackupSnapshotLease) {
		t.Helper()
		if after := readLease(); after.AuthenticationStateDigest == before.AuthenticationStateDigest {
			t.Fatal("current qualification change was absent from backup proof")
		}
		stale := authenticationRecoveryIntent(document.InstallationID)
		stale.AuthenticationStateDigest, stale.TOTPCustodyDigest = before.AuthenticationStateDigest, before.CustodyDigest
		if _, err := workflow.Inspect(ctx, stale); !errors.Is(err, authenticationrecovery.ErrConflict) {
			t.Fatal("prior qualification backup was treated as new recovery eligibility", err)
		}
		if _, err := workflow.Close(ctx, stale); !errors.Is(err, authenticationrecovery.ErrConflict) {
			t.Fatal("prior qualification backup was allowed to close source authentication", err)
		}
		assertNoClose()
	}
	// Distinct current authorization sources must invalidate a previously
	// qualified backup, not merely password or USER generation changes.
	// All mutations below use the real authority; no projection rows are
	// edited directly and failed close must leave the source fully OPEN.
	member, err := api.CreateUser(ctx, login.Credential, iamv1.CreateUserRequest{LoginName: "close-permission-user",
		DisplayName: "Close permission user", InitialPassword: iamHTTPSecret(t, "Close-Permission-Password-627!"), RequestID: "close-permission-user"})
	if err != nil {
		t.Fatal(err)
	}
	policyDocument := iamv1.PolicyDocument{LanguageVersion: "1", Scope: iamv1.AuthorityScopeTenant,
		Statements: []iamv1.PolicyStatement{{SID: "read", Effect: iamv1.PolicyAllow, Actions: []iamv1.Action{iamv1.ActionIAMAccessKeyList},
			Resources: []iamv1.PolicyResourceSelector{{Kind: iamv1.ResourceUser, Match: iamv1.PolicyResourceAnyInAuthority}}}}}
	policy, err := api.CreatePolicy(ctx, login.Credential, iamv1.CreatePolicyRequest{DisplayName: "Recovery current authority",
		Document: policyDocument, RequestID: "close-permission-policy"})
	if err != nil {
		t.Fatal(err)
	}
	attachment, err := api.CreatePolicyAttachment(ctx, login.Credential, iamv1.CreatePolicyAttachmentRequest{
		Target: iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetUser, ID: string(member.ID)}, PolicyID: policy.Policy.ID,
		PolicyResourceVersion: policy.Policy.ResourceVersion, RequestID: "close-permission-attachment"})
	if err != nil {
		t.Fatal(err)
	}
	group, err := api.CreateGroup(ctx, login.Credential, iamv1.CreateGroupRequest{Name: "Recovery authority group", RequestID: "close-permission-group"})
	if err != nil {
		t.Fatal(err)
	}
	membership, err := api.CreateGroupMembership(ctx, login.Credential, group.ID, iamv1.CreateGroupMembershipRequest{
		UserID: member.ID, RequestID: "close-permission-membership"})
	if err != nil {
		t.Fatal(err)
	}
	role, err := api.CreateRole(ctx, login.Credential, iamv1.CreateRoleRequest{Name: "Recovery authority role", Tags: []iamv1.RoleTag{},
		TrustPolicy: iamv1.TrustPolicyDocument{LanguageVersion: "1", Statements: []iamv1.TrustPolicyStatement{{SID: "source", Effect: iamv1.PolicyAllow,
			Principals: []iamv1.TrustPrincipal{{Type: iamv1.PrincipalUser, ID: member.ID}}}}}, RequestID: "close-permission-role"})
	if err != nil {
		t.Fatal(err)
	}
	var nextVersion iamv1.PolicyVersionDetail
	for _, change := range []struct {
		name  string
		apply func() error
	}{
		{"policy-publication", func() error {
			denied := policyDocument
			denied.Statements = append([]iamv1.PolicyStatement(nil), policyDocument.Statements...)
			denied.Statements[0].Effect = iamv1.PolicyDeny
			nextVersion, err = api.CreatePolicyVersion(ctx, login.Credential, policy.Policy.ID, iamv1.CreatePolicyVersionRequest{
				Document: denied, ResourceVersion: policy.Policy.ResourceVersion, RequestID: "close-policy-publication"})
			return err
		}},
		{"policy-default", func() error {
			policy, err = api.SetDefaultPolicyVersion(ctx, login.Credential, policy.Policy.ID, iamv1.SetDefaultPolicyVersionRequest{
				VersionID: nextVersion.Version.ID, ResourceVersion: nextVersion.Policy.ResourceVersion, RequestID: "close-policy-default"})
			return err
		}},
		{"attachment-revocation", func() error {
			_, err := api.RevokePolicyAttachment(ctx, login.Credential, attachment.ID, iamv1.RevokePolicyAttachmentRequest{
				ResourceVersion: attachment.ResourceVersion, RequestID: "close-attachment-revocation"})
			return err
		}},
		{"group-removal", func() error {
			_, err := api.RemoveGroupMembership(ctx, login.Credential, group.ID, membership.ID, iamv1.RemoveGroupMembershipRequest{
				ResourceVersion: membership.ResourceVersion, RequestID: "close-group-removal"})
			return err
		}},
		{"user-boundary", func() error {
			current, err := api.GetUserPermissionBoundary(ctx, login.Credential, member.ID, "close-boundary-current")
			if err != nil {
				return err
			}
			_, err = api.SetUserPermissionBoundary(ctx, login.Credential, member.ID, iamv1.SetUserPermissionBoundaryRequest{
				PolicyID: policy.Policy.ID, PolicyResourceVersion: policy.Policy.ResourceVersion,
				ResourceVersion: current.ResourceVersion, RequestID: "close-user-boundary"})
			return err
		}},
		{"role-trust", func() error {
			_, err := api.SetRoleTrustPolicy(ctx, login.Credential, role.ID, iamv1.SetRoleTrustPolicyRequest{
				Document:        iamv1.TrustPolicyDocument{LanguageVersion: "1", Statements: []iamv1.TrustPolicyStatement{}},
				ResourceVersion: role.ResourceVersion, RequestID: "close-role-trust"})
			return err
		}},
	} {
		if !t.Run("qualification-"+change.name, func(t *testing.T) {
			before := readLease()
			if err := change.apply(); err != nil {
				t.Fatal("real authority change failed", err)
			}
			assertStaleQualification(t, before)
		}) {
			t.FailNow()
		}
	}
	if !t.Run("qualification-contact-and-factor", func(t *testing.T) {
		if err := api.RegisterEmailVerificationKeyset(ctx); err != nil {
			t.Fatal("register actual notification verification custody", err)
		}
		initialPassword := iamHTTPSecret(t, "Close-Factor-Password-673!")
		user, err := api.CreateUser(ctx, login.Credential, iamv1.CreateUserRequest{LoginName: "close-factor-user",
			DisplayName: "Close factor user", InitialPassword: initialPassword, RequestID: "close-factor-user"})
		if err != nil {
			t.Fatal(err)
		}
		userLogin, err := api.Login(ctx, iamv1.LoginRequest{LoginName: user.LoginName + "@" + string(user.AccountID),
			Password: initialPassword, RequestID: "close-factor-login"})
		if err != nil {
			t.Fatal(err)
		}
		password := iamHTTPSecret(t, changedDeveloperPassword)
		if _, err := api.ChangePassword(ctx, userLogin.Credential, iamv1.ChangePasswordRequest{CurrentPassword: initialPassword,
			NewPassword: password, RequestID: "close-factor-password"}); err != nil {
			t.Fatal(err)
		}
		beforeContact := readLease()
		verification, err := api.StartNotificationVerification(ctx, userLogin.Credential, iamv1.StartNotificationContactVerificationRequest{
			Email: "close-factor@matrix.test", Password: password, RequestID: "close-factor-contact-start"})
		if err != nil {
			t.Fatal(err)
		}
		if readLease().AuthenticationStateDigest != beforeContact.AuthenticationStateDigest {
			t.Fatal("unverified contact changed effective backup qualification")
		}
		protector, err := authority.NewEmailVerificationProtector(authenticationRecoveryEmailKeyring(t, document))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := api.ConfirmNotificationContact(ctx, userLogin.Credential, verification.ID, iamv1.ConfirmNotificationContactVerificationRequest{
			Code: iamNotificationStorageCode(t, ctx, database, protector, verification), RequestID: "close-factor-contact-confirm"}); err != nil {
			t.Fatal(err)
		}
		assertStaleQualification(t, beforeContact)

		beforeBinding := readLease()
		state, err := api.AuthenticatorState(ctx, userLogin.Credential)
		if err != nil || state.EnrollmentState != "NEVER_BOUND" {
			t.Fatal("factor fixture is not an actual first enrollment", err)
		}
		enrollment, err := api.StartTOTPEnrollment(ctx, userLogin.Credential, iamv1.StartTOTPEnrollmentRequest{
			Password: password, ExpectedFactorRevision: state.FactorRevision, RequestID: "close-factor-enroll"})
		if err != nil || enrollment.Provisioning == nil {
			t.Fatal("start real factor enrollment", err)
		}
		if readLease().AuthenticationStateDigest != beforeBinding.AuthenticationStateDigest {
			t.Fatal("pending enrollment changed effective backup qualification")
		}
		factor := authenticationRecoveryMFAFixture{seed: enrollment.Provisioning.Seed, factorID: enrollment.Enrollment.ID, loginName: user.LoginName}
		bound, err := api.ConfirmTOTPEnrollment(ctx, userLogin.Credential, enrollment.Enrollment.ID, iamv1.ConfirmTOTPEnrollmentRequest{
			RequestID: "close-factor-confirm", Code: authenticationRecoveryFreshTOTP(t, ctx, database, user.AccountID, factor, 0)})
		if err != nil || bound.Enrollment.State != "CONFIRMED" {
			t.Fatal("confirm real factor enrollment", err)
		}
		assertStaleQualification(t, beforeBinding)

		beforeReplacement := readLease()
		current := authenticationRecoveryMFALogin(t, ctx, api, database, document, factor, "close-factor", 0)
		if readLease().AuthenticationStateDigest != beforeReplacement.AuthenticationStateDigest {
			t.Fatal("normal MFA login or OTP consumption invalidated backup qualification")
		}
		state, err = api.AuthenticatorState(ctx, current.Credential)
		if err != nil || state.EnrollmentState != "BOUND" {
			t.Fatal(err)
		}
		proof, err := api.StartStepUp(ctx, current.Credential, iamv1.StartStepUpRequest{RequestID: "close-factor-replace",
			Operation: iamv1.StepUpReplaceTOTP, ExpectedFactorRevision: state.FactorRevision})
		if err != nil {
			t.Fatal(err)
		}
		proof, err = api.VerifyStepUp(ctx, current.Credential, proof.ID, iamv1.VerifyStepUpRequest{RequestID: "close-factor-replace-proof",
			Password: password, Code: authenticationRecoveryFreshTOTP(t, ctx, database, user.AccountID, factor, 0)})
		if err != nil || proof.State != "PROVED" {
			t.Fatal("prove real replacement intent", err)
		}
		replacement, err := api.StartTOTPReplacement(ctx, current.Credential, iamv1.StartTOTPReplacementRequest{
			RequestID: proof.RequestID, StepUpID: proof.ID, ExpectedFactorRevision: proof.ExpectedFactorRevision})
		if err != nil || replacement.Provisioning == nil {
			t.Fatal("prepare real factor replacement", err)
		}
		if readLease().AuthenticationStateDigest != beforeReplacement.AuthenticationStateDigest {
			t.Fatal("step-up or pending replacement invalidated unchanged effective qualification")
		}
		nextFactor := authenticationRecoveryMFAFixture{seed: replacement.Provisioning.Seed, factorID: replacement.Enrollment.ID, loginName: user.LoginName}
		replaced, err := api.ConfirmTOTPEnrollment(ctx, current.Credential, replacement.Enrollment.ID, iamv1.ConfirmTOTPEnrollmentRequest{
			RequestID: "close-factor-replaced", Code: authenticationRecoveryFreshTOTP(t, ctx, database, user.AccountID, nextFactor, 0)})
		if err != nil || replaced.Enrollment.State != "CONFIRMED" {
			t.Fatal("commit real factor replacement", err)
		}
		assertStaleQualification(t, beforeReplacement)
		var lineage bool
		if err := database.QueryRow(ctx, `SELECT
		 (SELECT state='REVOKED' AND revoked_at IS NOT NULL FROM iam.totp_authenticators WHERE tenant_id=$1 AND id=$2)
		 AND (SELECT enrollment_state='BOUND' AND factor_id=$3 FROM iam.user_mfa_states WHERE tenant_id=$1 AND user_id=$4)
		 AND (SELECT count(*)=1 FROM iam.audit_outbox WHERE tenant_id=$1 AND event_document->>'action'='iam.authenticator.replaced'
		   AND event_document#>>'{actor,id}'=$4)`, user.AccountID, factor.factorID, nextFactor.factorID, user.ID).Scan(&lineage); err != nil || !lineage {
			t.Fatal("replacement rejection lost actual factor lineage or immutable success fact", err)
		}
	}) {
		t.FailNow()
	}
	lease := readLease()
	intent := authenticationRecoveryIntent(document.InstallationID)
	intent.AuthenticationStateDigest, intent.TOTPCustodyDigest = lease.AuthenticationStateDigest, lease.CustodyDigest
	inspection, err := workflow.Inspect(ctx, intent)
	if err != nil || installationv1.ValidateAuthenticationRecoveryInspectionForIntent(inspection, intent, status.ContentDigest) != nil {
		t.Fatal("current new recovery intent was not eligible", err)
	}
	encodedInspectIntent, err := installationv1.EncodeAuthenticationRecoveryIntent(intent)
	if err != nil {
		t.Fatal(err)
	}
	inspectDigest, err := installationv1.AuthenticationRecoveryIntentDigest(intent)
	if err != nil {
		t.Fatal(err)
	}
	inspectConfig := config.Copy()
	inspectConfig.User, inspectConfig.Password = authenticationRecoveryTestRole, iamHTTPTestPassword
	inspectConnection, err := pgx.ConnectConfig(ctx, inspectConfig)
	if err != nil {
		t.Fatal(err)
	}
	var deniedInspection []byte
	readCommittedErr := inspectConnection.QueryRow(ctx,
		"SELECT iam.inspect_new_authentication_recovery($1::jsonb,$2)", string(encodedInspectIntent), inspectDigest).
		Scan(&deniedInspection)
	var contextError *pgconn.PgError
	if !errors.As(readCommittedErr, &contextError) || contextError.Code != "42501" {
		_ = inspectConnection.Close(context.Background())
		t.Fatal("new recovery inspection accepted a default isolation transaction", readCommittedErr)
	}
	readOnlyTx, err := inspectConnection.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable, AccessMode: pgx.ReadOnly})
	if err != nil {
		_ = inspectConnection.Close(context.Background())
		t.Fatal(err)
	}
	readOnlyErr := readOnlyTx.QueryRow(ctx,
		"SELECT iam.inspect_new_authentication_recovery($1::jsonb,$2)", string(encodedInspectIntent), inspectDigest).
		Scan(&deniedInspection)
	_ = readOnlyTx.Rollback(ctx)
	var readOnlyDatabaseError *pgconn.PgError
	if !errors.As(readOnlyErr, &readOnlyDatabaseError) || readOnlyDatabaseError.Code != "42501" {
		_ = inspectConnection.Close(context.Background())
		t.Fatal("new recovery inspection accepted a read-only transaction", readOnlyErr)
	}
	foreignIntent := intent
	foreignIntent.InstallationID = "mxi-" + strings.Repeat("d", 32)
	encodedForeign, err := installationv1.EncodeAuthenticationRecoveryIntent(foreignIntent)
	if err != nil {
		_ = inspectConnection.Close(context.Background())
		t.Fatal(err)
	}
	foreignDigest, err := installationv1.AuthenticationRecoveryIntentDigest(foreignIntent)
	if err != nil {
		_ = inspectConnection.Close(context.Background())
		t.Fatal(err)
	}
	foreignTx, err := inspectConnection.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable, AccessMode: pgx.ReadWrite})
	if err != nil {
		_ = inspectConnection.Close(context.Background())
		t.Fatal(err)
	}
	foreignErr := foreignTx.QueryRow(ctx,
		"SELECT iam.inspect_new_authentication_recovery($1::jsonb,$2)", string(encodedForeign), foreignDigest).
		Scan(&deniedInspection)
	_ = foreignTx.Rollback(ctx)
	var foreignDatabaseError *pgconn.PgError
	if !errors.As(foreignErr, &foreignDatabaseError) || foreignDatabaseError.Code != "42501" {
		_ = inspectConnection.Close(context.Background())
		t.Fatal("new recovery inspection accepted another installation", foreignErr)
	}
	inspectTx, err := inspectConnection.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable, AccessMode: pgx.ReadWrite})
	if err != nil {
		_ = inspectConnection.Close(context.Background())
		t.Fatal(err)
	}
	var boundedInspection []byte
	if err := inspectTx.QueryRow(ctx, "SELECT iam.inspect_new_authentication_recovery($1::jsonb,$2)",
		string(encodedInspectIntent), inspectDigest).Scan(&boundedInspection); err != nil {
		_ = inspectTx.Rollback(ctx)
		_ = inspectConnection.Close(context.Background())
		t.Fatal("purpose-only SQL inspection failed", err)
	}
	if err := inspectTx.Rollback(ctx); err != nil {
		_ = inspectConnection.Close(context.Background())
		t.Fatal(err)
	}
	if err := inspectConnection.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	var inspectionFields map[string]json.RawMessage
	if err := json.Unmarshal(boundedInspection, &inspectionFields); err != nil {
		t.Fatal(err)
	}
	allowedFields := map[string]bool{
		"apiVersion": true, "kind": true, "purpose": true, "state": true, "installationId": true,
		"bootstrapDigest": true, "epoch": true, "commandId": true, "recoveryIntentDigest": true,
		"authenticationStateDigest": true,
	}
	if len(inspectionFields) != len(allowedFields) {
		t.Fatal("purpose-only SQL inspection exposed a private or incomplete projection")
	}
	for field := range inspectionFields {
		if !allowedFields[field] {
			t.Fatal("purpose-only SQL inspection exposed a private field", field)
		}
	}
	var directInspection installationv1.AuthenticationRecoveryInspection
	if err := json.Unmarshal(boundedInspection, &directInspection); err != nil ||
		installationv1.ValidateAuthenticationRecoveryInspectionForIntent(directInspection, intent, status.ContentDigest) != nil {
		t.Fatal("purpose-only SQL inspection returned a different intent", err)
	}
	var apiCanInspect, workerCanInspect, credentialRecoveryCanInspect, backupCustodyCanInspect, notificationCanInspect bool
	if err := database.QueryRow(ctx, `SELECT
	    has_function_privilege('matrix_iam_api','iam.inspect_new_authentication_recovery(jsonb,text)','EXECUTE'),
	    has_function_privilege('matrix_iam_worker','iam.inspect_new_authentication_recovery(jsonb,text)','EXECUTE'),
	    has_function_privilege('matrix_iam_credential_recovery','iam.inspect_new_authentication_recovery(jsonb,text)','EXECUTE'),
	    has_function_privilege('matrix_iam_backup_custody','iam.inspect_new_authentication_recovery(jsonb,text)','EXECUTE'),
	    has_function_privilege('matrix_iam_notification_worker','iam.inspect_new_authentication_recovery(jsonb,text)','EXECUTE')`).
		Scan(&apiCanInspect, &workerCanInspect, &credentialRecoveryCanInspect, &backupCustodyCanInspect, &notificationCanInspect); err != nil ||
		apiCanInspect || workerCanInspect || credentialRecoveryCanInspect || backupCustodyCanInspect || notificationCanInspect {
		t.Fatal("another IAM runtime purpose gained recovery inspection", err)
	}
	if err := iammigration.Verify(ctx, database); err != nil {
		t.Fatal("untampered inspection migration did not verify", err)
	}
	t.Run("wrong purpose grant fails migration verification", func(t *testing.T) {
		transaction, err := database.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer transaction.Rollback(context.Background())
		if _, err := transaction.Exec(ctx, `GRANT EXECUTE ON FUNCTION iam.inspect_new_authentication_recovery(jsonb,text)
			TO matrix_iam_worker`); err != nil {
			t.Fatal(err)
		}
		if err := iammigration.Verify(ctx, transaction); err == nil {
			t.Fatal("migration accepted recovery inspection granted to the worker")
		}
	})
	assertNoClose()
	if !t.Run("writer-before-close", func(t *testing.T) {
		observe, release := holdIAMRequest(t, ctx, database, "close-new-password", true, auditv1.ActionIAMUserPasswordChanged)
		defer release()
		request := iamv1.ChangePasswordRequest{CurrentPassword: iamHTTPSecret(t, changedAdminPassword),
			NewPassword: iamHTTPSecret(t, "Close-New-Root-Password-497!"), RequestID: "close-new-password"}
		writer := make(chan error, 1)
		go func() { _, err := api.ChangePassword(ctx, login.Credential, request); writer <- err }()
		leader := observe()
		closed := make(chan error, 1)
		go func() {
			value, err := workflow.Close(ctx, intent)
			if value.Closure.CommandID != "" {
				err = errors.New("uncommitted old snapshot escaped")
			}
			closed <- err
		}()
		waitBlocked(t, authenticationRecoveryTestRole, leader)
		release()
		if err := <-writer; err != nil {
			t.Fatal("leading password change failed", err)
		}
		if err := <-closed; !errors.Is(err, authenticationrecovery.ErrConflict) {
			t.Fatal("old backup qualification was accepted", err)
		}
	}) {
		t.FailNow()
	}
	assertNoClose()
	// A real password change retires the previous generation's guess window.
	// Seed a real failed attempt on the new credential for snapshot tampering;
	// an old-generation attempt is history, not a current replay budget.
	if _, err := api.Login(ctx, iamv1.LoginRequest{LoginName: "admin", Password: iamHTTPSecret(t, "Close-Wrong-Password-497!"),
		RequestID: "close-current-generation-failure"}); !errors.Is(err, identityaccess.ErrUnauthenticated) {
		t.Fatal("current-generation wrong password was not rejected", err)
	}
	lease = readLease()
	intent.CommandID = "cmd-" + strings.Repeat("d", 32)
	intent.AuthenticationStateDigest, intent.TOTPCustodyDigest = lease.AuthenticationStateDigest, lease.CustodyDigest
	for _, damage := range []string{
		"ALTER FUNCTION iam.inspect_new_authentication_recovery(jsonb,text) SECURITY INVOKER",
		"ALTER FUNCTION iam.inspect_new_authentication_recovery(jsonb,text) STABLE",
		"ALTER FUNCTION iam.inspect_new_authentication_recovery(jsonb,text) SET search_path=public",
		"REVOKE EXECUTE ON FUNCTION iam.inspect_new_authentication_recovery(jsonb,text) FROM matrix_iam_authentication_recovery",
		"GRANT EXECUTE ON FUNCTION iam.inspect_new_authentication_recovery(jsonb,text) TO matrix_iam_api",
		"ALTER TABLE iam.authentication_recovery_closures DROP COLUMN security_snapshot_document CASCADE",
		"ALTER TABLE iam.authentication_recovery_closures ALTER COLUMN security_snapshot_document SET DEFAULT '{}'::jsonb",
		"ALTER TABLE iam.authentication_recovery_closures DROP CONSTRAINT authentication_recovery_snapshot_shape",
		"GRANT EXECUTE ON FUNCTION iam.prepare_authentication_recovery_close(jsonb,text) TO matrix_iam_api",
		"ALTER FUNCTION iam.prepare_authentication_recovery_close(jsonb,text) SECURITY INVOKER",
		"ALTER FUNCTION iam.assert_authentication_recovery_snapshot(jsonb,jsonb) SECURITY DEFINER",
		"GRANT EXECUTE ON FUNCTION iam.assert_authentication_recovery_snapshot(jsonb,jsonb) TO matrix_iam_authentication_recovery",
		"ALTER FUNCTION iam.reconcile_authentication_recovery(jsonb,text,jsonb,jsonb,jsonb) SECURITY INVOKER",
		"CREATE FUNCTION iam.reopen_authentication_recovery(jsonb,text,jsonb) RETURNS jsonb LANGUAGE sql AS 'SELECT NULL::jsonb'",
		"ALTER TABLE iam.authentication_recovery_attempt_floors NO FORCE ROW LEVEL SECURITY",
		"ALTER TABLE iam.authentication_recovery_attempt_floors DISABLE TRIGGER authentication_attempt_floor_owned",
		"ALTER TABLE iam.authentication_recovery_attempt_floors DISABLE TRIGGER authentication_attempt_floor_no_truncate",
		"ALTER TABLE iam.authentication_recovery_attempt_floors DROP CONSTRAINT authentication_recovery_password_floor_valid",
		"ALTER TABLE iam.authentication_recovery_attempt_floors DROP CONSTRAINT authentication_recovery_totp_floor_valid",
		"ALTER TABLE iam.authentication_recovery_attempt_floors ALTER COLUMN password_sequence SET DEFAULT 1",
		"ALTER TABLE iam.authentication_recovery_attempt_floors DROP CONSTRAINT authentication_recovery_attempt_floors_command_id_fkey",
		"ALTER POLICY tenant_isolation ON iam.authentication_recovery_attempt_floors USING (true)",
		"GRANT SELECT ON iam.authentication_recovery_attempt_floors TO matrix_iam_api",
		"GRANT SELECT(password_sequence) ON iam.authentication_recovery_attempt_floors TO matrix_iam_api",
		"ALTER FUNCTION iam.guard_authentication_recovery_attempt_floor() SECURITY DEFINER",
		"GRANT EXECUTE ON FUNCTION iam.guard_authentication_recovery_attempt_floor() TO matrix_iam_authentication_recovery",
	} {
		tx, err := database.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, damage); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatal("inject private shape fault", err)
		}
		var ready bool
		err = tx.QueryRow(ctx, "SELECT iam.authentication_recovery_contract_ready()").Scan(&ready)
		_ = tx.Rollback(ctx)
		if err != nil || ready {
			t.Fatal("damaged recovery ABI remained ready", damage, err)
		}
	}
	encodedIntent, err := installationv1.EncodeAuthenticationRecoveryIntent(intent)
	if err != nil {
		t.Fatal(err)
	}
	intentDigest, err := installationv1.AuthenticationRecoveryIntentDigest(intent)
	if err != nil {
		t.Fatal(err)
	}
	privateConfig := config.Copy()
	privateConfig.User, privateConfig.Password = authenticationRecoveryTestRole, iamHTTPTestPassword
	private, err := pgx.ConnectConfig(ctx, privateConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer private.Close(context.Background())
	tx, err := private.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable, AccessMode: pgx.ReadWrite})
	if err != nil {
		t.Fatal(err)
	}
	var prepared []byte
	if err := tx.QueryRow(ctx, "SELECT iam.prepare_authentication_recovery_close($1::jsonb,$2)", string(encodedIntent), intentDigest).Scan(&prepared); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal("prepare current authority", err)
	}
	var snapshot installationv1.AuthenticationRecoverySecuritySnapshot
	if json.Unmarshal(prepared, &snapshot) != nil || installationv1.ValidateAuthenticationRecoverySecuritySnapshot(snapshot) != nil || len(snapshot.Accounts) != 2 {
		_ = tx.Rollback(ctx)
		t.Fatal("prepare omitted actual Account or returned invalid replay state")
	}
	budgetPath := ""
	for accountIndex, account := range snapshot.Accounts {
		for userIndex, user := range account.Users {
			if user.PasswordAttempts != nil {
				budgetPath = fmt.Sprintf("{accounts,%d,users,%d,passwordAttempts}", accountIndex, userIndex)
			}
		}
	}
	if budgetPath == "" {
		_ = tx.Rollback(ctx)
		t.Fatal("actual password history was omitted from snapshot")
	}
	for _, variant := range []string{
		"jsonb_set($3::jsonb,'{accounts}',($3::jsonb->'accounts')-0)",
		"jsonb_set($3::jsonb,'{accounts,0,users}','[]'::jsonb)",
		"jsonb_set($3::jsonb,'{accounts,0,users,0,lastConsumedStep}','0'::jsonb)",
		"jsonb_set($3::jsonb,'" + budgetPath + "','null'::jsonb)",
	} {
		if _, err := tx.Exec(ctx, "SAVEPOINT forged_snapshot"); err != nil {
			t.Fatal(err)
		}
		_, attackErr := tx.Exec(ctx, "SELECT iam.close_authentication_recovery($1::jsonb,$2,'{}'::jsonb,"+variant+",$4)",
			string(encodedIntent), intentDigest, string(prepared), "sha256:"+strings.Repeat("f", 64))
		if _, err := tx.Exec(ctx, "ROLLBACK TO SAVEPOINT forged_snapshot"); err != nil {
			t.Fatal(err)
		}
		var rejected *pgconn.PgError
		if !errors.As(attackErr, &rejected) || rejected.Code != "23505" {
			_ = tx.Rollback(ctx)
			t.Fatal("tampered snapshot passed exact authority comparison", variant, attackErr)
		}
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	assertNoClose()
	if _, err := database.Exec(ctx, `CREATE FUNCTION iam.test_reject_authentication_close() RETURNS trigger LANGUAGE plpgsql AS $body$
	 BEGIN IF NEW.event_document->>'action'='iam.authentication-recovery.closed' THEN RAISE EXCEPTION 'test close write fault'; END IF; RETURN NEW; END $body$;
	 REVOKE ALL ON FUNCTION iam.test_reject_authentication_close() FROM PUBLIC;
	 CREATE TRIGGER test_close_write_fault BEFORE INSERT ON iam.audit_outbox FOR EACH ROW EXECUTE FUNCTION iam.test_reject_authentication_close()`); err != nil {
		t.Fatal(err)
	}
	if _, err := workflow.Close(ctx, intent); !errors.Is(err, authenticationrecovery.ErrUnavailable) {
		t.Fatal("injected close write fault did not abort", err)
	}
	assertNoClose()
	if _, err := database.Exec(ctx, "DROP TRIGGER test_close_write_fault ON iam.audit_outbox; DROP FUNCTION iam.test_reject_authentication_close()"); err != nil {
		t.Fatal(err)
	}
	var results [2]installationv1.AuthenticationRecoveryClosureEnvelope
	var failures [2]error
	if !t.Run("close-before-writer", func(t *testing.T) {
		var generation int64
		if err := database.QueryRow(ctx, "SELECT credential_version FROM iam.user_credentials WHERE tenant_id=$1 AND principal_id=$2", document.Organization.ID, document.Administrator.ID).Scan(&generation); err != nil {
			t.Fatal(err)
		}
		observe, release := holdIAMRequest(t, ctx, database, intent.CommandID, true, auditv1.ActionIAMAuthenticationRecoveryClosed)
		defer release()
		// A new inspection holds the same live qualification barrier, but
		// commits no closure. The later close must independently acquire it.
		inspectionTx, err := private.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable, AccessMode: pgx.ReadWrite})
		if err != nil {
			t.Fatal(err)
		}
		defer inspectionTx.Rollback(context.Background())
		var inspected []byte
		if err := inspectionTx.QueryRow(ctx, "SELECT iam.inspect_new_authentication_recovery($1::jsonb,$2)",
			string(encodedIntent), intentDigest).Scan(&inspected); err != nil {
			t.Fatal("leading inspection rejected current qualification", err)
		}
		var wait sync.WaitGroup
		wait.Add(1)
		go func() { defer wait.Done(); results[0], failures[0] = workflow.Close(ctx, intent) }()
		waitBlocked(t, authenticationRecoveryTestRole, int32(private.PgConn().PID()))
		assertNoClose()
		if err := inspectionTx.Commit(ctx); err != nil {
			t.Fatal("leading inspection did not commit without effects", err)
		}
		leader := observe()
		lateInspection := make(chan error, 1)
		go func() {
			tx, err := private.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable, AccessMode: pgx.ReadWrite})
			if err == nil {
				var output []byte
				err = tx.QueryRow(ctx, "SELECT iam.inspect_new_authentication_recovery($1::jsonb,$2)",
					string(encodedIntent), intentDigest).Scan(&output)
				_ = tx.Rollback(context.Background())
			}
			lateInspection <- err
		}()
		waitBlocked(t, authenticationRecoveryTestRole, leader, private.PgConn().PID())
		request := iamv1.ChangePasswordRequest{CurrentPassword: iamHTTPSecret(t, "Close-New-Root-Password-497!"),
			NewPassword: iamHTTPSecret(t, "Close-Rejected-Password-719!"), RequestID: "close-late-password"}
		writer := make(chan error, 1)
		go func() { _, err := api.ChangePassword(ctx, login.Credential, request); writer <- err }()
		waitBlocked(t, iamHTTPTestRole, leader)
		wait.Add(1)
		go func() { defer wait.Done(); results[1], failures[1] = workflow.Close(ctx, intent) }()
		waitBlocked(t, authenticationRecoveryTestRole, leader)
		release()
		wait.Wait()
		var retryableInspection *pgconn.PgError
		if err := <-lateInspection; !errors.As(err, &retryableInspection) || retryableInspection.Code != "40001" {
			t.Fatal("in-flight inspection escaped the committed close barrier", err)
		}
		if err := <-writer; !errors.Is(err, identityaccess.ErrUnauthenticated) {
			t.Fatal("late password change escaped CLOSED authority", err)
		}
		var unchanged bool
		if err := database.QueryRow(ctx, `SELECT credential_version=$3 AND NOT EXISTS(SELECT 1 FROM iam.audit_outbox
		 WHERE event_document->>'action'='iam.user.password-changed' AND event_document->>'requestId'='close-late-password')
		 FROM iam.user_credentials WHERE tenant_id=$1 AND principal_id=$2`, document.Organization.ID, document.Administrator.ID, generation).Scan(&unchanged); err != nil || !unchanged {
			t.Fatal("rejected password change partially changed credentials or success fact", err)
		}
	}) {
		t.FailNow()
	}
	if failures[0] != nil || failures[1] != nil {
		t.Fatal("concurrent close failed", failures[0], failures[1])
	}
	if _, err := workflow.Inspect(ctx, intent); !errors.Is(err, authenticationrecovery.ErrConflict) {
		t.Fatal("completed close receipt was replayed as new eligibility", err)
	}
	first, err := installationv1.EncodeAuthenticationRecoveryClosureEnvelope(results[0])
	if err != nil {
		t.Fatal(err)
	}
	second, err := installationv1.EncodeAuthenticationRecoveryClosureEnvelope(results[1])
	if err != nil || !bytes.Equal(first, second) {
		t.Fatal("equal close did not return original exact snapshot", err)
	}
	if installationv1.ValidateAuthenticationRecoveryClosureEnvelopeForIntent(results[0], intent, status.ContentDigest) != nil {
		t.Fatal("close escaped sealed installation/intent")
	}
	stored, err := installationv1.EncodeAuthenticationRecoverySecuritySnapshot(results[0].SecuritySnapshot)
	if err != nil {
		t.Fatal(err)
	}
	var matches bool
	if err := database.QueryRow(ctx, `SELECT security_snapshot_document=$1::jsonb AND closure_document->>'securitySnapshotDigest'=$2
	 FROM iam.authentication_recovery_closures WHERE command_id=$3`, string(stored), results[0].Closure.SecuritySnapshotDigest, intent.CommandID).Scan(&matches); err != nil || !matches {
		t.Fatal("snapshot and closure were not stored atomically", err)
	}
	assertAuthenticationAuthorityClosed(t, ctx, api, login.Credential)
	assertAuthenticationRecoveryDatabaseBoundary(t, ctx, database, config)
	assertAuthenticationRecoveryHistoryImmutable(t, ctx, database, "authentication_recovery_closures")
	t.Log("real qualification mismatch/no effect, prepare rollback, outbox fault rollback, exact concurrent close and immutable snapshot passed; reconcile/reopen not covered")
}

// The target comes from an actual pg_dump of the private helper's RR snapshot,
// including owners, ACLs and RLS. It is never a second bootstrap that merely
// resembles the source. This proves IAM's transaction boundary, not the
// installer's signed profile, persistent files or all-instance isolation.
func TestIAMAuthenticationRecoveryCapacityPostgres(t *testing.T) {
	cases := []struct {
		name, environment      string
		manyAccounts, overflow bool
	}{
		{"wide-account", "MATRIX_IAM_AUTHENTICATION_RECOVERY_CAPACITY_POSTGRES_TEST_DSN", false, false},
		{"many-accounts", "MATRIX_IAM_AUTHENTICATION_RECOVERY_ACCOUNTS_POSTGRES_TEST_DSN", true, false},
		{"overflow", "MATRIX_IAM_AUTHENTICATION_RECOVERY_OVERFLOW_POSTGRES_TEST_DSN", false, true},
	}
	configured := 0
	for _, item := range cases {
		if os.Getenv(item.environment) != "" {
			configured++
		}
	}
	if configured == 0 {
		t.Skip("set all three authentication recovery capacity DSNs to distinct PostgreSQL 18 databases")
	}
	if configured != len(cases) {
		t.Fatal("authentication recovery capacity requires all three isolated databases")
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
			defer cancel()
			dsn := os.Getenv(item.environment)
			database, config := openAuthenticationRecoveryDatabase(t, ctx, dsn, "matrix_iam_auth_recovery_capacity_")
			defer database.Close(context.Background())
			assertIAMPostgres18(t, ctx, database)
			assertCleanIAMSchema(t, ctx, database)
			applyIAMSchema(t, ctx, database)
			createIAMHTTPRole(t, ctx, database)
			createAuthenticationRecoveryTestRoles(t, ctx, database)
			createAuthenticationRecoveryBackupRole(t, ctx, database)
			document := iamHTTPBootstrap(t)
			document.InstallationID = "mxi-" + strings.Repeat("a", 32)
			api, closeAPI := authenticationRecoveryAPI(t, ctx, dsn, document)
			if _, err := bootstrapIAMWithTOTP(t, ctx, api, document); err != nil {
				t.Fatal(err)
			}
			businessUsers := 0
			if !item.manyAccounts && !item.overflow {
				businessUsers = prepareAuthenticationRecoveryCapacityBusiness(t, ctx, api, database, document)
			}
			closeAPI()
			backupConfig := config.Copy()
			backupConfig.User, backupConfig.Password = "matrix_iam_backup_custody_login", "matrix-authority-process-test-only"
			intent := authenticationRecoveryIntent(document.InstallationID)
			if item.overflow {
				// A real earlier lease supplies valid intent input. The later
				// overflow must fail in SQL, not the Go request-shape validator.
				original, err := iampostgres.OpenTOTPBackupSnapshot(ctx, backupConfig)
				if err != nil {
					t.Fatal("open pre-overflow backup snapshot", err)
				}
				lease := original.Lease()
				intent.AuthenticationStateDigest, intent.TOTPCustodyDigest = lease.AuthenticationStateDigest, lease.CustodyDigest
				if err := original.Close(); err != nil {
					t.Fatal(err)
				}
			}
			// Synthetic, constraint-valid projection capacity only: copy the real
			// bootstrap verifier without spending thousands of password hashes.
			// This does not claim Account creation throughput or legacy provenance.
			if item.manyAccounts {
				if _, err := database.Exec(ctx, `
				 INSERT INTO iam.accounts(id,display_name,status,resource_version,created_at,updated_at)
				 SELECT 'capacity-account-'||lpad(g::text,111,'0'),'Capacity account','ACTIVE',1,clock_timestamp(),clock_timestamp()
				 FROM generate_series(1,$1::integer) g;
				 INSERT INTO iam.principals(tenant_id,id,principal_type,login_name,display_name,status,must_change_password,resource_version,created_at,updated_at)
				 SELECT a.id,'capacity-user-'||lpad(g::text,114,'0'),'USER','capacity-root-'||g::text,'Capacity root','ACTIVE',true,1,a.created_at,a.updated_at
				 FROM generate_series(1,$1::integer) g JOIN iam.accounts a ON a.id='capacity-account-'||lpad(g::text,111,'0');
				 INSERT INTO iam.login_index(tenant_id,login_name,principal_id)
				 SELECT tenant_id,login_name,id FROM iam.principals WHERE tenant_id LIKE 'capacity-account-%';
				 INSERT INTO iam.account_roots(account_id,principal_id,login_name)
				 SELECT tenant_id,id,login_name FROM iam.principals WHERE tenant_id LIKE 'capacity-account-%';
				 INSERT INTO iam.user_credentials(tenant_id,principal_id,password_hash,changed_at)
				 SELECT p.tenant_id,p.id,c.password_hash,p.created_at FROM iam.principals p
				 CROSS JOIN iam.user_credentials c WHERE p.tenant_id LIKE 'capacity-account-%' AND c.tenant_id=$2 AND c.principal_id=$3`,
					installationv1.MaximumAuthenticationRecoverySnapshotItems/2-1, document.Organization.ID, document.Administrator.ID); err != nil {
					t.Fatal("create bounded multi-account projection fixture", err)
				}
			} else {
				users := installationv1.MaximumAuthenticationRecoverySnapshotItems - 2 - businessUsers
				if item.overflow {
					users++
				}
				if _, err := database.Exec(ctx, `
				 INSERT INTO iam.principals(tenant_id,id,principal_type,login_name,display_name,status,must_change_password,resource_version,created_at,updated_at)
				 SELECT $1,'capacity-user-'||lpad(g::text,114,'0'),'USER','capacity-user-'||g::text,'Capacity user','ACTIVE',true,1,clock_timestamp(),clock_timestamp()
				 FROM generate_series(1,$2::integer) g;
				 INSERT INTO iam.login_index(tenant_id,login_name,principal_id)
				 SELECT tenant_id,login_name,id FROM iam.principals WHERE tenant_id=$1 AND id LIKE 'capacity-user-%';
				 INSERT INTO iam.user_credentials(tenant_id,principal_id,password_hash,changed_at)
				 SELECT p.tenant_id,p.id,c.password_hash,p.created_at FROM iam.principals p CROSS JOIN iam.user_credentials c
				 WHERE p.tenant_id=$1 AND p.id LIKE 'capacity-user-%' AND c.tenant_id=$1 AND c.principal_id=$3`,
					document.Organization.ID, users, document.Administrator.ID); err != nil {
					t.Fatal("create bounded wide-account projection fixture", err)
				}
			}
			var expectedItems int
			if err := database.QueryRow(ctx, `SELECT (SELECT count(*) FROM iam.accounts)+(SELECT count(*) FROM iam.principals WHERE principal_type='USER')`).Scan(&expectedItems); err != nil {
				t.Fatal(err)
			}
			wantItems := installationv1.MaximumAuthenticationRecoverySnapshotItems
			if item.overflow {
				wantItems++
			}
			if expectedItems != wantItems {
				t.Fatal("capacity fixture does not reach the exact transport boundary")
			}
			// Actual users have changed their first password; synthetic rows
			// have not. Preserve each subject's own generation, not a uniform
			// fixture assumption that would mask a reset during restore.
			generations := func(connection *pgx.Conn, advancement int64) string {
				t.Helper()
				var document string
				if err := connection.QueryRow(ctx, `SELECT jsonb_agg(jsonb_build_array(tenant_id,principal_id,credential_version-$1)
				 ORDER BY tenant_id COLLATE "C",principal_id COLLATE "C")::text FROM iam.user_credentials`, advancement).Scan(&document); err != nil {
					t.Fatal("read complete credential generations", err)
				}
				return document
			}
			originalGenerations := generations(database, 0)
			bounded, boundedCancel := context.WithTimeout(ctx, 45*time.Second)
			defer boundedCancel()
			start := time.Now()
			exported, err := iampostgres.OpenTOTPBackupSnapshot(bounded, backupConfig)
			backupDuration := time.Since(start)
			var dump []byte
			if item.overflow {
				if !errors.Is(err, iampostgres.ErrBackupCustodyUnavailable) || exported != nil {
					t.Fatal("overflow produced a truncated or plausible backup lease", err)
				}
			} else if err != nil {
				t.Fatal("maximum complete backup projection unavailable", err)
			}
			if exported != nil {
				defer exported.Close()
				lease := exported.Lease()
				intent.AuthenticationStateDigest, intent.TOTPCustodyDigest = lease.AuthenticationStateDigest, lease.CustodyDigest
				dump = runAuthenticationRecoveryPostgresTool(t, bounded, config, "pg_dump", nil, "--format=custom", "--schema=iam", "--snapshot="+lease.SnapshotID)
				if err := exported.Close(); err != nil {
					t.Fatal(err)
				}
			}
			workflow, closeWorkflow := authenticationRecoveryWorkflow(t, ctx, dsn)
			defer closeWorkflow()
			start = time.Now()
			envelope, err := workflow.Close(bounded, intent)
			closeDuration := time.Since(start)
			if item.overflow {
				if !errors.Is(err, authenticationrecovery.ErrUnavailable) || envelope.Closure.CommandID != "" {
					t.Fatal("overflow close yielded a seal or was not rejected by the projection bound", err)
				}
				var noEffects bool
				if err := database.QueryRow(ctx, `SELECT state='OPEN' AND epoch=0
				 AND NOT EXISTS(SELECT 1 FROM iam.authentication_recovery_closures)
				 AND NOT EXISTS(SELECT 1 FROM iam.audit_outbox WHERE event_document->>'action' LIKE 'iam.authentication-recovery.%')
				 FROM iam.authentication_recovery_state WHERE singleton`).Scan(&noEffects); err != nil || !noEffects {
					t.Fatal("overflow close advanced a barrier, receipt or success fact", err)
				}
				return
			}
			if err != nil {
				t.Fatal("maximum complete close unavailable within production bounds", err)
			}
			items := len(envelope.SecuritySnapshot.Accounts)
			for _, account := range envelope.SecuritySnapshot.Accounts {
				items += len(account.Users)
			}
			encoded, err := installationv1.EncodeAuthenticationRecoverySecuritySnapshot(envelope.SecuritySnapshot)
			if err != nil || items != expectedItems {
				t.Fatal("maximum snapshot was incomplete or unencodable", err)
			}
			decoded, err := installationv1.DecodeAuthenticationRecoverySecuritySnapshot(bytes.NewReader(encoded))
			if err != nil || !reflect.DeepEqual(decoded, envelope.SecuritySnapshot) {
				t.Fatal("maximum snapshot canonical round-trip changed membership", err)
			}
			closeWorkflow()
			// Retain all owners/RLS/ACLs from this exact pre-close snapshot.
			// A source receipt cannot be used to reopen the source in place.
			targetHash := sha256.Sum256([]byte(config.Database))
			targetName := fmt.Sprintf("matrix_iam_auth_capacity_restore_%x", targetHash[:10])
			if _, err := database.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{targetName}.Sanitize()); err != nil {
				t.Fatal("create own capacity restore target", err)
			}
			defer func() {
				cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
				defer stop()
				if _, err := database.Exec(cleanup, "DROP DATABASE "+pgx.Identifier{targetName}.Sanitize()); err != nil {
					t.Error("remove own capacity restore target", err)
				}
			}()
			targetConfig := config.Copy()
			targetConfig.Database = targetName
			target, err := pgx.ConnectConfig(ctx, targetConfig)
			if err != nil {
				t.Fatal(err)
			}
			defer target.Close(context.Background())
			runAuthenticationRecoveryPostgresTool(t, ctx, targetConfig, "pg_restore", dump, "--exit-on-error")
			if generations(target, 0) != originalGenerations {
				t.Fatal("capacity restore did not retain every original credential generation")
			}
			// Copy the parsed configuration, not ConnString(): pgx retains the
			// original DSN string even when its Database field has changed.
			targetPoolConfig, err := pgxpool.ParseConfig(dsn)
			if err != nil {
				t.Fatal(err)
			}
			targetPoolConfig.ConnConfig.Database = targetName
			recovery, closeRecovery := authenticationRecoveryWorkflowConfig(t, ctx, targetPoolConfig)
			defer closeRecovery()
			reconcileContext, stopReconcile := context.WithTimeout(ctx, 45*time.Second)
			start = time.Now()
			reconciled, err := recovery.Reconcile(reconcileContext, envelope.Closure, decoded)
			reconcileDuration := time.Since(start)
			stopReconcile()
			if err != nil || reconciled != envelope.Closure {
				t.Fatal("maximum restored snapshot could not reconcile within production bounds", err)
			}
			reopenContext, stopReopen := context.WithTimeout(ctx, 45*time.Second)
			start = time.Now()
			completion, err := recovery.Reopen(reopenContext, envelope.Closure, decoded)
			reopenDuration := time.Since(start)
			stopReopen()
			if err != nil || installationv1.ValidateAuthenticationRecoveryCompletionForClosure(completion, envelope.Closure) != nil {
				t.Fatal("maximum restored snapshot could not reopen within production bounds", err)
			}
			if replay, err := recovery.Reopen(ctx, envelope.Closure, decoded); err != nil || replay != completion {
				t.Fatal("capacity completion replay changed its original result", err)
			}
			if generations(target, 1) != originalGenerations {
				t.Fatal("capacity reopen or replay did not advance each original generation exactly once")
			}
			var complete bool
			if err := target.QueryRow(ctx, `SELECT state='OPEN' AND epoch=1
			 AND (SELECT count(*) FROM iam.user_credentials)=$1
			 AND (SELECT count(*) FROM iam.authentication_recovery_attempt_floors)=$1
			 AND (SELECT count(*) FROM iam.authentication_recovery_completions)=1
			 AND (SELECT count(*) FROM iam.audit_outbox WHERE event_document->>'action' LIKE 'iam.authentication-recovery.%')=3
			 FROM iam.authentication_recovery_state WHERE singleton`, items-len(decoded.Accounts)).Scan(&complete); err != nil || !complete {
				t.Fatal("capacity recovery omitted a USER or repeated a fence/completion", err)
			}
			if err := iammigration.Verify(ctx, target); err != nil {
				t.Fatal("complete capacity restore failed its current schema verifier", err)
			}
			if businessUsers > 0 {
				if err := target.QueryRow(ctx, `SELECT
				 (SELECT count(*)=$1 FROM iam.user_mfa_states WHERE enrollment_state='BOUND')
				 AND (SELECT count(*)=$1 FROM iam.totp_authenticators WHERE state='ACTIVE')
				 AND (SELECT count(*)=$1 FROM iam.mfa_recovery_batches WHERE revoked_at IS NULL)
				 AND (SELECT count(*)=$1 FROM iam.authentication_recovery_code_fences)
				 AND NOT EXISTS(SELECT 1 FROM iam.sessions WHERE revoked_at IS NULL)
				 AND (SELECT count(*)=$1 FROM iam.notification_contacts)
				 AND (SELECT count(*)=8 FROM iam.groups WHERE deleted_at IS NULL)
				 AND (SELECT count(*)=$1*8 FROM iam.group_memberships WHERE removed_at IS NULL)
				 AND (SELECT count(*)=8 FROM iam.policies WHERE owner_tenant_id IS NOT NULL)
				 AND (SELECT count(*)=16 FROM iam.policy_versions v JOIN iam.policies p ON p.id=v.policy_id WHERE p.owner_tenant_id IS NOT NULL)
				 AND (SELECT count(*)=$1 FROM iam.user_permission_boundaries WHERE revoked_at IS NULL)`, businessUsers).Scan(&complete); err != nil || !complete {
					t.Fatal("restored bounded business fixture lost current MFA or policy qualifications", err)
				}
			}
			t.Logf("complete accounts=%d items=%d realMFAUsers=%d canonicalBytes=%d backup=%s close=%s reconcile=%s reopen=%s; mixed/sparse retained-state gate, not API provisioning throughput or full-MFA maximum capacity",
				len(decoded.Accounts), items, businessUsers, len(encoded), backupDuration, closeDuration, reconcileDuration, reopenDuration)
		})
	}
}

// This corpus adds real credential, contact, factor and policy provenance to
// the transport-bound fixture. The remaining thousands of users stay explicitly
// synthetic; copying encrypted MFA rows would not prove a valid dense workload.
func prepareAuthenticationRecoveryCapacityBusiness(t *testing.T, ctx context.Context, api *identityaccess.Authority, database *pgx.Conn, document iamv1.BootstrapDocument) int {
	const users = 16
	t.Helper()
	if err := api.RegisterEmailVerificationKeyset(ctx); err != nil {
		t.Fatal("register capacity email custody", err)
	}
	admin, _, _ := prepareAuthenticationRecoveryIdentity(t, ctx, api, database, document, false)
	groups := make([]iamv1.Group, 8)
	var boundary iamv1.Policy
	for index := range groups {
		prefix := fmt.Sprintf("recovery-capacity-group-%d", index)
		policyDocument := iamv1.PolicyDocument{LanguageVersion: "1", Scope: iamv1.AuthorityScopeTenant,
			Statements: []iamv1.PolicyStatement{{SID: prefix, Effect: iamv1.PolicyAllow, Actions: []iamv1.Action{iamv1.ActionIAMAccessKeyList},
				Resources: []iamv1.PolicyResourceSelector{{Kind: iamv1.ResourceUser, Match: iamv1.PolicyResourceAnyInAuthority}}}}}
		policy, err := api.CreatePolicy(ctx, admin, iamv1.CreatePolicyRequest{DisplayName: prefix,
			Document: policyDocument, RequestID: prefix + "-policy"})
		if err != nil {
			t.Fatal("create real capacity policy", err)
		}
		// Preserve a real non-default revision as well as the selected Allow.
		policyDocument.Statements[0].Effect = iamv1.PolicyDeny
		version, err := api.CreatePolicyVersion(ctx, admin, policy.Policy.ID, iamv1.CreatePolicyVersionRequest{
			Document: policyDocument, ResourceVersion: policy.Policy.ResourceVersion, RequestID: prefix + "-version"})
		if err != nil {
			t.Fatal("create real capacity policy history", err)
		}
		boundary = version.Policy
		groups[index], err = api.CreateGroup(ctx, admin, iamv1.CreateGroupRequest{Name: prefix, RequestID: prefix + "-create"})
		if err != nil {
			t.Fatal("create real capacity group", err)
		}
		if _, err := api.CreatePolicyAttachment(ctx, admin, iamv1.CreatePolicyAttachmentRequest{
			Target:   iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetGroup, ID: string(groups[index].ID)},
			PolicyID: boundary.ID, PolicyResourceVersion: boundary.ResourceVersion, RequestID: prefix + "-attach"}); err != nil {
			t.Fatal("attach real capacity group policy", err)
		}
	}
	for index := 0; index < users; index++ {
		prefix := fmt.Sprintf("recovery-capacity-member-%02d", index)
		user, err := api.CreateUser(ctx, admin, iamv1.CreateUserRequest{LoginName: prefix, DisplayName: prefix,
			InitialPassword: iamHTTPSecret(t, initialDeveloperPassword), RequestID: prefix + "-create"})
		if err != nil {
			t.Fatal("create real capacity user", err)
		}
		login, err := api.Login(ctx, iamv1.LoginRequest{LoginName: prefix + "@" + string(document.Organization.ID),
			Password: iamHTTPSecret(t, initialDeveloperPassword), RequestID: prefix + "-login"})
		if err != nil || !login.MustChangePassword {
			t.Fatal("login real initial capacity credential", err)
		}
		if _, err := api.ChangePassword(ctx, login.Credential, iamv1.ChangePasswordRequest{
			CurrentPassword: iamHTTPSecret(t, initialDeveloperPassword), NewPassword: iamHTTPSecret(t, changedDeveloperPassword),
			RequestID: prefix + "-password"}); err != nil {
			t.Fatal("change real capacity credential", err)
		}
		for index, group := range groups {
			if _, err := api.CreateGroupMembership(ctx, admin, group.ID, iamv1.CreateGroupMembershipRequest{
				UserID: user.ID, RequestID: fmt.Sprintf("%s-join-%d", prefix, index)}); err != nil {
				t.Fatal("join real capacity group", err)
			}
		}
		current, err := api.GetUserPermissionBoundary(ctx, admin, user.ID, prefix+"-boundary-read")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := api.SetUserPermissionBoundary(ctx, admin, user.ID, iamv1.SetUserPermissionBoundaryRequest{
			PolicyID: boundary.ID, PolicyResourceVersion: boundary.ResourceVersion, ResourceVersion: current.ResourceVersion,
			RequestID: prefix + "-boundary"}); err != nil {
			t.Fatal("set real capacity user boundary", err)
		}
		if _, err := api.ListAccessKeys(ctx, login.Credential, user.ID, prefix+"-authorized-list"); err != nil {
			t.Fatal("capacity source user could not use actual group/boundary authorization", err)
		}
		enrollAuthenticationRecoveryTOTP(t, ctx, api, database, document, login.Credential, user.LoginName)
	}
	return users
}

func TestIAMAuthenticationRecoveryPostgres(t *testing.T) {
	const (
		sourceEnvironment   = "MATRIX_IAM_AUTHENTICATION_RECOVERY_SOURCE_POSTGRES_TEST_DSN"
		restoredEnvironment = "MATRIX_IAM_AUTHENTICATION_RECOVERY_RESTORED_POSTGRES_TEST_DSN"
		repeatedEnvironment = "MATRIX_IAM_AUTHENTICATION_RECOVERY_REPEATED_POSTGRES_TEST_DSN"
	)
	sourceDSN, restoredDSN, repeatedDSN := os.Getenv(sourceEnvironment), os.Getenv(restoredEnvironment), os.Getenv(repeatedEnvironment)
	if sourceDSN == "" && restoredDSN == "" && repeatedDSN == "" {
		t.Skipf("set %s, %s and %s to distinct clean disposable PostgreSQL 18 databases", sourceEnvironment, restoredEnvironment, repeatedEnvironment)
	}
	if sourceDSN == "" || restoredDSN == "" || repeatedDSN == "" {
		t.Fatal("authentication recovery requires all three explicitly isolated databases")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	sourceAdmin, sourceConfig := openAuthenticationRecoveryDatabase(t, ctx, sourceDSN, "matrix_iam_auth_recovery_source_")
	defer sourceAdmin.Close(context.Background())
	restoredAdmin, restoredConfig := openAuthenticationRecoveryDatabase(t, ctx, restoredDSN, "matrix_iam_auth_recovery_restored_")
	defer restoredAdmin.Close(context.Background())
	repeatedAdmin, repeatedConfig := openAuthenticationRecoveryDatabase(t, ctx, repeatedDSN, "matrix_iam_auth_recovery_repeated_")
	defer repeatedAdmin.Close(context.Background())
	configs := []*pgx.ConnConfig{sourceConfig, restoredConfig, repeatedConfig}
	for i, current := range configs {
		for _, other := range configs[:i] {
			if current.Database == other.Database && current.Host == other.Host && current.Port == other.Port {
				t.Fatal("authentication recovery authorities share a database")
			}
		}
	}

	for _, database := range []*pgx.Conn{sourceAdmin, restoredAdmin, repeatedAdmin} {
		assertIAMPostgres18(t, ctx, database)
		assertCleanIAMSchema(t, ctx, database)
	}
	applyIAMSchema(t, ctx, sourceAdmin)
	createIAMHTTPRole(t, ctx, sourceAdmin)
	createAuthenticationRecoveryTestRoles(t, ctx, sourceAdmin)
	createAuthenticationRecoveryBackupRole(t, ctx, sourceAdmin)

	document := iamHTTPBootstrap(t)
	document.InstallationID = "mxi-" + strings.Repeat("1", 32)
	sourceAPI, closeSourceAPI := authenticationRecoveryAPI(t, ctx, sourceDSN, document)
	sourceStatus, err := bootstrapIAMWithTOTP(t, ctx, sourceAPI, document)
	if err != nil {
		t.Fatal("bootstrap source authentication authority", err)
	}
	if err := sourceAPI.RegisterEmailVerificationKeyset(ctx); err != nil {
		t.Fatal("register source email verification custody", err)
	}
	sourceCredential, restoredSession, restoredMFA := prepareAuthenticationRecoveryIdentity(t, ctx, sourceAPI, sourceAdmin, document, true)
	replayUser, err := sourceAPI.CreateUser(ctx, sourceCredential, iamv1.CreateUserRequest{
		LoginName: "auth-recovery-replay-user", DisplayName: "Recovery OTP replay boundary", InitialPassword: iamHTTPSecret(t, initialDeveloperPassword),
		RequestID: "auth-recovery-replay-user-create",
	})
	if err != nil {
		t.Fatal("create recovery OTP replay subject", err)
	}
	replayLogin, err := sourceAPI.Login(ctx, iamv1.LoginRequest{LoginName: replayUser.LoginName + "@" + string(document.Organization.ID),
		Password: iamHTTPSecret(t, initialDeveloperPassword), RequestID: "auth-recovery-replay-initial-login"})
	if err != nil || !replayLogin.MustChangePassword || !replayLogin.Credential.Present() {
		t.Fatal("login recovery OTP replay subject", err)
	}
	if _, err := sourceAPI.ChangePassword(ctx, replayLogin.Credential, iamv1.ChangePasswordRequest{
		CurrentPassword: iamHTTPSecret(t, initialDeveloperPassword), NewPassword: iamHTTPSecret(t, changedDeveloperPassword),
		RequestID: "auth-recovery-replay-password",
	}); err != nil {
		t.Fatal("change recovery OTP replay subject password", err)
	}
	replayMFA := enrollAuthenticationRecoveryTOTP(t, ctx, sourceAPI, sourceAdmin, document, replayLogin.Credential, replayUser.LoginName)
	budgetUser, err := sourceAPI.CreateUser(ctx, sourceCredential, iamv1.CreateUserRequest{
		LoginName: "auth-recovery-budget-user", DisplayName: "Recovery attempt boundary", InitialPassword: iamHTTPSecret(t, initialDeveloperPassword),
		RequestID: "auth-recovery-budget-user-create",
	})
	if err != nil {
		t.Fatal("create recovery attempt subject", err)
	}
	// Carry a real completed removal through the same RR dump and two
	// restores. An absent active factor alone must never earn this state.
	removedUser, err := sourceAPI.CreateUser(ctx, sourceCredential, iamv1.CreateUserRequest{
		LoginName: "auth-recovery-removed-user", DisplayName: "Recovery removed factor lineage",
		InitialPassword: iamHTTPSecret(t, initialDeveloperPassword), RequestID: "auth-recovery-removed-user-create",
	})
	if err != nil {
		t.Fatal("create actual removal recovery subject", err)
	}
	removedLogin, err := sourceAPI.Login(ctx, iamv1.LoginRequest{LoginName: removedUser.LoginName + "@" + string(removedUser.AccountID),
		Password: iamHTTPSecret(t, initialDeveloperPassword), RequestID: "auth-recovery-removed-initial-login"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sourceAPI.ChangePassword(ctx, removedLogin.Credential, iamv1.ChangePasswordRequest{
		CurrentPassword: iamHTTPSecret(t, initialDeveloperPassword), NewPassword: iamHTTPSecret(t, changedDeveloperPassword),
		RequestID: "auth-recovery-removed-password"}); err != nil {
		t.Fatal(err)
	}
	removedFactor := enrollAuthenticationRecoveryTOTP(t, ctx, sourceAPI, sourceAdmin, document, removedLogin.Credential, removedUser.LoginName)
	removedLogin = authenticationRecoveryMFALogin(t, ctx, sourceAPI, sourceAdmin, document, removedFactor, "removed-user", 0)
	removeProof, err := sourceAPI.StartStepUp(ctx, removedLogin.Credential, iamv1.StartStepUpRequest{
		RequestID: "auth-recovery-remove", Operation: iamv1.StepUpRemoveTOTP, ExpectedFactorRevision: 2})
	if err != nil {
		t.Fatal(err)
	}
	removeProof, err = sourceAPI.VerifyStepUp(ctx, removedLogin.Credential, removeProof.ID, iamv1.VerifyStepUpRequest{
		RequestID: "auth-recovery-remove-proof", Password: iamHTTPSecret(t, changedDeveloperPassword),
		Code: authenticationRecoveryFreshTOTP(t, ctx, sourceAdmin, removedUser.AccountID, removedFactor, 0)})
	if err != nil || removeProof.State != "PROVED" {
		t.Fatal("prove actual pre-backup removal", err)
	}
	removeRequest := iamv1.RemoveTOTPRequest{RequestID: removeProof.RequestID, StepUpID: removeProof.ID, ExpectedFactorRevision: 2}
	removal, err := sourceAPI.RemoveTOTP(ctx, removedLogin.Credential, removeRequest)
	if err != nil || removal.Outcome != "APPLIED" || removal.Removal.FactorRevision != 3 {
		t.Fatal("commit actual pre-backup removal", err)
	}
	assertRestoredRemoval := func(service *identityaccess.Authority, database *pgx.Conn, phase string) {
		t.Helper()
		if _, err := service.CurrentIdentity(ctx, removedLogin.Credential); !errors.Is(err, identityaccess.ErrUnauthenticated) {
			t.Fatal("restore revived the removal source Session", err)
		}
		fresh, err := service.Login(ctx, iamv1.LoginRequest{LoginName: removedUser.LoginName + "@" + string(removedUser.AccountID),
			Password: iamHTTPSecret(t, changedDeveloperPassword), RequestID: "auth-recovery-removed-login-" + phase})
		if err != nil || fresh.Outcome != iamv1.LoginAuthenticated {
			t.Fatal("restored legal REMOVED user could not authenticate normally", err)
		}
		state, err := service.AuthenticatorState(ctx, fresh.Credential)
		if err != nil || state.EnrollmentState != "REMOVED" || state.FactorRevision != 3 || state.FactorID != "" {
			t.Fatal("restore inferred another enrollment qualification", err)
		}
		replay, err := service.RemoveTOTP(ctx, fresh.Credential, removeRequest)
		if err != nil || replay.Outcome != "EQUAL_REPLAY" || replay.Removal != removal.Removal || replay.NextStep != "" {
			t.Fatal("restore changed removal completion or re-executed it", err)
		}
		var preserved bool
		if err := database.QueryRow(ctx, `SELECT
		 (SELECT count(*)=1 FROM iam.authenticator_removals WHERE tenant_id=$1 AND user_id=$2)
		 AND (SELECT state='REVOKED' AND revoked_at=$4 FROM iam.totp_authenticators WHERE tenant_id=$1 AND id=$3)
		 AND NOT EXISTS(SELECT 1 FROM iam.mfa_recovery_batches WHERE tenant_id=$1 AND user_id=$2 AND revoked_at IS NULL)
		 AND (SELECT authentication_method='PASSWORD' AND mfa_revision=3 AND status='ACTIVE' FROM iam.sessions WHERE tenant_id=$1 AND id=$5)`,
			removedUser.AccountID, removedUser.ID, removedFactor.factorID, removal.Removal.RemovedAt, fresh.Session.ID).Scan(&preserved); err != nil || !preserved {
			t.Fatal("restore revived factor/batch or mislabelled a password Session", err)
		}
		if _, err := service.Logout(ctx, fresh.Credential, iamv1.LogoutRequest{RequestID: "auth-recovery-removed-logout-" + phase}); err != nil {
			t.Fatal(err)
		}
	}
	backupConfig := sourceConfig.Copy()
	backupConfig.User, backupConfig.Password = "matrix_iam_backup_custody_login", "matrix-authority-process-test-only"
	exported, err := iampostgres.OpenTOTPBackupSnapshot(ctx, backupConfig)
	if err != nil {
		t.Fatal("export actual authentication backup snapshot", err)
	}
	t.Cleanup(func() { _ = exported.Close() })
	lease := exported.Lease()
	dump := runAuthenticationRecoveryPostgresTool(t, ctx, sourceConfig, "pg_dump", nil, "--format=custom", "--schema=iam", "--snapshot="+lease.SnapshotID)
	if err := exported.Close(); err != nil {
		t.Fatal("release authentication backup snapshot", err)
	}
	// This real post-backup login consumes a future-window code with attempts
	// still available. Its later rejection must not be masked by exhaustion.
	replayMFA.login = authenticationRecoveryMFALogin(t, ctx, sourceAPI, sourceAdmin, document, replayMFA, "source-replay-user", 1)
	for attempt := 0; attempt < 4; attempt++ {
		_, err := sourceAPI.Login(ctx, iamv1.LoginRequest{LoginName: budgetUser.LoginName + "@" + string(document.Organization.ID),
			Password: iamHTTPSecret(t, "Incorrect-Recovery-Password-739!"), RequestID: fmt.Sprintf("auth-recovery-source-failed-%d", attempt)})
		if !errors.Is(err, identityaccess.ErrUnauthenticated) {
			t.Fatal("source failed password was not rejected", err)
		}
	}
	runAuthenticationRecoveryPostgresTool(t, ctx, restoredConfig, "pg_restore", dump, "--exit-on-error")
	assertAuthenticationRecoveryDecisionArchive(t, ctx, sourceAdmin, restoredAdmin)
	restoredAPI, closeRestoredAPI := authenticationRecoveryAPI(t, ctx, restoredDSN, document)
	restoredCredential := sourceCredential
	before := readAuthenticationRecoverySecurityState(t, ctx, restoredAdmin, document, restoredSession)
	if before.activeSessions == 0 || before.accessKeys != 1 || before.recoveryBatches != 3 || before.factorStep < 0 ||
		before.passwordReserved != 1 || before.totpReserved != 1 || before.challengePending != 1 {
		t.Fatal("restored pre-close replay fixture is incomplete")
	}

	sourceLocal := localRecoveryWorkflow(t, ctx, sourceDSN, localRecoveryTestRole, nil)
	restoredLocal := localRecoveryWorkflow(t, ctx, restoredDSN, localRecoveryTestRole, nil)
	localAuthority := authenticationRecoveryLocalAuthority(t, document, sourceStatus.ContentDigest)
	if inspection, err := sourceLocal.InspectLocalCredentialRecovery(ctx, localAuthority, nil); err != nil || inspection.State != "ELIGIBLE" {
		t.Fatalf("source local credential recovery was not initially eligible: %v", err)
	}
	if inspection, err := restoredLocal.InspectLocalCredentialRecovery(ctx, localAuthority, nil); err != nil || inspection.State != "ELIGIBLE" {
		t.Fatalf("restored local credential recovery was not initially eligible: %v", err)
	}
	assertAuthenticationAuthorityOpen(t, ctx, sourceAPI, sourceCredential)
	assertAuthenticationAuthorityOpen(t, ctx, restoredAPI, restoredCredential)
	assertAuthenticationRecoveryDatabaseBoundary(t, ctx, sourceAdmin, sourceConfig)
	assertAuthenticationRecoveryDatabaseBoundary(t, ctx, restoredAdmin, restoredConfig)

	sourceRecovery, closeSourceRecovery := authenticationRecoveryWorkflow(t, ctx, sourceDSN)
	restoredRecovery, closeRestoredRecovery := authenticationRecoveryWorkflow(t, ctx, restoredDSN)
	intent := authenticationRecoveryIntent(document.InstallationID)
	intent.AuthenticationStateDigest = lease.AuthenticationStateDigest
	intent.TOTPCustodyDigest = lease.CustodyDigest
	envelope := closeAuthenticationConcurrently(t, ctx, sourceRecovery, intent)
	closure, snapshot := envelope.Closure, envelope.SecuritySnapshot
	if installationv1.ValidateAuthenticationRecoveryClosureForIntent(closure, intent) != nil {
		t.Fatal("source close returned an invalid installation closure")
	}
	assertAuthenticationAuthorityClosed(t, ctx, sourceAPI, sourceCredential)
	if _, err := sourceLocal.InspectLocalCredentialRecovery(ctx, localAuthority, nil); !errors.Is(err, identityaccess.ErrForbidden) {
		t.Fatalf("source local credential recovery bypassed CLOSED: %v", err)
	}
	if err := iammigration.Verify(ctx, sourceAdmin); err == nil {
		t.Fatal("source migration verification reported CLOSED authority ready")
	}
	if _, err := sourceRecovery.Reconcile(ctx, closure, snapshot); !errors.Is(err, authenticationrecovery.ErrConflict) {
		t.Fatalf("source authority was reconciled as a restored authority: %v", err)
	}

	changedIntent := intent
	changedIntent.BackupDigest = digestForAuthenticationRecovery('9')
	if _, err := sourceRecovery.Close(ctx, changedIntent); !errors.Is(err, authenticationrecovery.ErrConflict) {
		t.Fatalf("close command accepted another intent: %v", err)
	}
	if _, err := sourceRecovery.Reopen(ctx, closure, snapshot); !errors.Is(err, authenticationrecovery.ErrConflict) {
		t.Fatalf("source authority reopened without restored reconciliation: %v", err)
	}
	// Release completed source clients before backup/projection consumers open
	// connections; bounded test resources are part of the runtime gate.
	closeSourceAPI()
	closeSourceRecovery()
	assertAuthenticationAuthorityOpen(t, ctx, restoredAPI, restoredCredential)
	for _, attack := range []string{"qualification", "account", "user", "factor", "omitted-user"} {
		candidateBytes, err := installationv1.EncodeAuthenticationRecoverySecuritySnapshot(snapshot)
		if err != nil {
			t.Fatal(err)
		}
		candidate, err := installationv1.DecodeAuthenticationRecoverySecuritySnapshot(bytes.NewReader(candidateBytes))
		if err != nil {
			t.Fatal(err)
		}
		switch attack {
		case "qualification":
			candidate.AuthenticationStateDigest = digestForAuthenticationRecovery('f')
		case "account":
			candidate.Accounts[0].AccountID = "other-restored-account"
		case "user":
			candidate.Accounts[0].Users[0].UserID = "000-other-user"
		case "factor":
			for i := range candidate.Accounts[0].Users {
				if candidate.Accounts[0].Users[i].FactorID != "" {
					candidate.Accounts[0].Users[i].FactorID = "other-factor"
					break
				}
			}
		case "omitted-user":
			if len(candidate.Accounts[0].Users) < 2 {
				t.Fatal("subject omission fixture requires populated account")
			}
			candidate.Accounts[0].Users = candidate.Accounts[0].Users[1:]
		}
		forged := closure
		forged.SecuritySnapshotDigest, err = installationv1.AuthenticationRecoverySecuritySnapshotDigest(candidate)
		if err != nil {
			t.Fatal("snapshot attack is not a valid contract fixture", attack, err)
		}
		if _, err := restoredRecovery.Reconcile(ctx, forged, candidate); !errors.Is(err, authenticationrecovery.ErrConflict) {
			t.Fatalf("restored %s accepted self-consistent but false snapshot scope: %v", attack, err)
		}
		var effects int
		if err := restoredAdmin.QueryRow(ctx, `SELECT
		 (SELECT count(*) FROM iam.authentication_recovery_closures)+(SELECT count(*) FROM iam.authentication_recovery_reconciliations)
		 +(SELECT count(*) FROM iam.audit_outbox WHERE event_document->>'action' LIKE 'iam.authentication-recovery.%')
		 +(SELECT epoch::integer FROM iam.authentication_recovery_state WHERE singleton)`).Scan(&effects); err != nil || effects != 0 {
			t.Fatal("rejected snapshot left partial restored effects", err)
		}
	}
	reconciled := reconcileAuthenticationConcurrently(t, ctx, restoredRecovery, closure, snapshot)
	if reconciled != closure {
		t.Fatal("restored authority changed the protected source closure")
	}
	assertAuthenticationAuthorityClosed(t, ctx, restoredAPI, restoredCredential)
	if _, err := restoredAPI.RegenerateRecoveryCodes(ctx, restoredMFA.login.Credential, authenticationRecoveryRegenerationRequest(restoredMFA)); !errors.Is(err, identityaccess.ErrUnauthenticated) {
		t.Fatalf("online regeneration bypassed reconciled CLOSED: %v", err)
	}
	if _, err := restoredLocal.InspectLocalCredentialRecovery(ctx, localAuthority, nil); !errors.Is(err, identityaccess.ErrForbidden) {
		t.Fatalf("restored local credential recovery bypassed reconciled CLOSED: %v", err)
	}
	if err := iammigration.Verify(ctx, restoredAdmin); err == nil {
		t.Fatal("restored migration verification reported reconciled CLOSED authority ready")
	}
	assertAuthenticationRecoveryClosedFacts(t, ctx, sourceAdmin, restoredAdmin, closure)

	changedClosure := closure
	changedClosure.BackupDigest = digestForAuthenticationRecovery('8')
	if _, err := restoredRecovery.Reopen(ctx, changedClosure, snapshot); !errors.Is(err, authenticationrecovery.ErrConflict) {
		t.Fatalf("reopen accepted a changed closure: %v", err)
	}
	beforeFault := readAuthenticationRecoverySecurityState(t, ctx, restoredAdmin, document, restoredSession)
	if _, err := restoredAdmin.Exec(ctx, `CREATE FUNCTION iam.test_reject_recovery_floor() RETURNS trigger LANGUAGE plpgsql AS $body$
	 BEGIN RAISE EXCEPTION 'injected recovery floor write failure'; END $body$;
	 CREATE TRIGGER test_recovery_floor_fault AFTER INSERT ON iam.authentication_recovery_attempt_floors
	 FOR EACH ROW EXECUTE FUNCTION iam.test_reject_recovery_floor()`); err != nil {
		t.Fatal("install recovery floor write fault", err)
	}
	if result, err := restoredRecovery.Reopen(ctx, closure, snapshot); !errors.Is(err, authenticationrecovery.ErrUnavailable) || result.CommandID != "" {
		t.Fatal("failed floor write exposed a completion", err)
	}
	if afterFault := readAuthenticationRecoverySecurityState(t, ctx, restoredAdmin, document, restoredSession); afterFault != beforeFault {
		t.Fatal("failed floor write partially changed credentials, attempts, sessions, factors or completion")
	}
	var floorEffects int
	if err := restoredAdmin.QueryRow(ctx, `SELECT (SELECT count(*) FROM iam.authentication_recovery_attempt_floors)
	 +(SELECT count(*) FROM iam.audit_outbox WHERE event_document->>'action'='iam.authentication-recovery.reopened')`).Scan(&floorEffects); err != nil || floorEffects != 0 {
		t.Fatal("failed floor write left replay floors or success outbox", err)
	}
	assertAuthenticationAuthorityClosed(t, ctx, restoredAPI, restoredCredential)
	if _, err := restoredAdmin.Exec(ctx, "DROP TRIGGER test_recovery_floor_fault ON iam.authentication_recovery_attempt_floors; DROP FUNCTION iam.test_reject_recovery_floor()"); err != nil {
		t.Fatal(err)
	}
	passwordState := func() string {
		t.Helper()
		var result string
		if err := restoredAdmin.QueryRow(ctx, `SELECT jsonb_agg(jsonb_build_array(tenant_id,principal_id,
			password_hash,password_changed_at,password_history,encode(password_history_digest,'hex')) ORDER BY tenant_id,principal_id)::text
			FROM iam.user_credentials`).Scan(&result); err != nil {
			t.Fatal("read bounded password-state evidence")
		}
		return result // Private verifier evidence is never printed or put in a receipt.
	}
	originalPasswords := passwordState()
	completion := reopenAuthenticationConcurrently(t, ctx, restoredRecovery, closure, snapshot)
	if installationv1.ValidateAuthenticationRecoveryCompletionForClosure(completion, closure) != nil {
		t.Fatal("restored reopen returned an invalid completion")
	}
	if replay, err := restoredRecovery.Reopen(ctx, closure, snapshot); err != nil || replay != completion {
		t.Fatalf("equal reopen replay changed its completion: %v", err)
	}
	if passwordState() != originalPasswords {
		t.Fatal("authentication generation fence or exact replay invented a password change, age or history")
	}
	if err := iammigration.Verify(ctx, restoredAdmin); err != nil {
		t.Fatal("reopened IAM schema did not verify", err)
	}
	if readiness, err := restoredAPI.Readiness(ctx); err != nil || readiness.State != iamv1.ReadinessReady {
		t.Fatalf("reopened IAM authority is not ready: %v", err)
	}
	nextLease, nextDump := assertAuthenticationRecoveryFloorCarry(t, ctx, restoredConfig, restoredAdmin, document, intent, snapshot)
	budgetPeer, closeBudgetPeer := authenticationRecoveryAPI(t, ctx, restoredDSN, document)
	assertAuthenticationRecoveryPasswordBudget(t, ctx, []*identityaccess.Authority{restoredAPI, budgetPeer}, restoredAdmin, document.Organization.ID, budgetUser, snapshot)
	closeBudgetPeer()
	if _, err := restoredAPI.CurrentIdentity(ctx, restoredCredential); !errors.Is(err, identityaccess.ErrUnauthenticated) {
		t.Fatalf("restored pre-recovery Session survived reopen: %v", err)
	}
	login, err := restoredAPI.Login(ctx, iamv1.LoginRequest{LoginName: "admin", Password: iamHTTPSecret(t, changedAdminPassword), RequestID: "auth-recovery-after-reopen"})
	if err != nil || login.MustChangePassword || !login.Credential.Present() {
		t.Fatalf("authorized identity was not usable after reopen: %v", err)
	}
	if _, err := restoredAPI.CurrentIdentity(ctx, login.Credential); err != nil {
		t.Fatal("new post-recovery Session is unusable", err)
	}

	after := readAuthenticationRecoverySecurityState(t, ctx, restoredAdmin, document, restoredSession)
	if after.credentialGeneration != before.credentialGeneration+1 || after.activeSessions != 1 ||
		after.restoredSessionStatus != "REVOKED" || after.factorStep < completion.CompletedAt.Unix()/30 ||
		after.codeFences != before.recoveryBatches || after.accessKeyFences != before.accessKeys ||
		after.closures != 1 || after.reconciliations != 1 || after.completions != 1 ||
		after.passwordReserved != 0 || after.totpReserved != 0 || after.challengePending != 0 ||
		after.passwordAbandoned != 1 || after.totpAbandoned != 1 || after.challengeCancelled != 1 {
		t.Fatalf("reopen replay fencing differs: before=%+v after=%+v", before, after)
	}
	assertAuthenticationRecoveryAuditFacts(t, ctx, sourceAdmin, restoredAdmin)
	assertAuthenticationRecoveryHistoryImmutable(t, ctx, restoredAdmin)
	assertRestoredRemoval(restoredAPI, restoredAdmin, "first")
	otpPeer, closeOTPPeer := authenticationRecoveryAPI(t, ctx, restoredDSN, document)
	assertAuthenticationRecoveryOTPReplay(t, ctx, restoredAPI, restoredAdmin, document, replayMFA, snapshot)
	assertAuthenticationRecoveryStepUpFenced(t, ctx, []*identityaccess.Authority{restoredAPI, otpPeer}, restoredAdmin, document, restoredMFA, snapshot)
	closeOTPPeer()
	// Finished authorities must release their real connection/process budgets
	// before the next restore, not linger until the outer test cleanup.
	closeRestoredAPI()
	assertAuthenticationRecoveryRepeated(t, ctx, restoredRecovery, closeRestoredRecovery, restoredAdmin, repeatedAdmin, repeatedConfig, repeatedDSN,
		document, budgetUser, restoredMFA, intent, completion, snapshot, nextLease, nextDump)
	repeatedAPI, closeRepeatedAPI := authenticationRecoveryAPI(t, ctx, repeatedDSN, document)
	assertRestoredRemoval(repeatedAPI, repeatedAdmin, "repeated")
	closeRepeatedAPI()
}

func assertAuthenticationRecoveryFloorCarry(t *testing.T, ctx context.Context, config *pgx.ConnConfig, database *pgx.Conn,
	document iamv1.BootstrapDocument, previous installationv1.AuthenticationRecoveryIntent, source installationv1.AuthenticationRecoverySecuritySnapshot) (installationv1.TOTPBackupSnapshotLease, []byte) {
	t.Helper()
	backup := config.Copy()
	backup.User, backup.Password = "matrix_iam_backup_custody_login", "matrix-authority-process-test-only"
	exported, err := iampostgres.OpenTOTPBackupSnapshot(ctx, backup)
	if err != nil {
		t.Fatal("next backup rejected reopened authentication state", err)
	}
	lease := exported.Lease()
	dump := runAuthenticationRecoveryPostgresTool(t, ctx, config, "pg_dump", nil, "--format=custom", "--schema=iam", "--snapshot="+lease.SnapshotID)
	if err := exported.Close(); err != nil {
		t.Fatal(err)
	}
	previous.CommandID, previous.Epoch = "cmd-"+strings.Repeat("e", 32), source.Epoch+1
	previous.AuthenticationStateDigest, previous.TOTPCustodyDigest = lease.AuthenticationStateDigest, lease.CustodyDigest
	encoded, err := installationv1.EncodeAuthenticationRecoveryIntent(previous)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := installationv1.AuthenticationRecoveryIntentDigest(previous)
	if err != nil {
		t.Fatal(err)
	}
	privateConfig := config.Copy()
	privateConfig.User, privateConfig.Password = authenticationRecoveryTestRole, iamHTTPTestPassword
	private, err := pgx.ConnectConfig(ctx, privateConfig)
	if err != nil {
		t.Fatal("open next recovery projection reader", err)
	}
	defer private.Close(context.Background())
	tx, err := private.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable, AccessMode: pgx.ReadWrite})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	var raw []byte
	if err := tx.QueryRow(ctx, "SELECT iam.prepare_authentication_recovery_close($1::jsonb,$2)", string(encoded), digest).Scan(&raw); err != nil {
		t.Fatal("prepare next recovery from actual new backup qualification", err)
	}
	var next installationv1.AuthenticationRecoverySecuritySnapshot
	if json.Unmarshal(raw, &next) != nil || installationv1.ValidateAuthenticationRecoverySecuritySnapshot(next) != nil || len(next.Accounts) != len(source.Accounts) {
		t.Fatal("next recovery projection lost its complete subject set")
	}
	for index, account := range source.Accounts {
		candidate := next.Accounts[index]
		if candidate.AccountID != account.AccountID || len(candidate.Users) != len(account.Users) {
			t.Fatal("next recovery projection changed account/user membership")
		}
		for userIndex, original := range account.Users {
			user := candidate.Users[userIndex]
			if user.UserID != original.UserID || user.FactorID != original.FactorID || user.LastConsumedStep < original.LastConsumedStep ||
				!reflect.DeepEqual(user.PasswordAttempts, original.PasswordAttempts) || !reflect.DeepEqual(user.TOTPAttempts, original.TOTPAttempts) {
				t.Fatal("next recovery projection refunded an unconsumed source budget or factor step")
			}
		}
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	var unchanged bool
	if err := database.QueryRow(ctx, `SELECT state='OPEN' AND epoch=$1 AND (SELECT count(*) FROM iam.authentication_recovery_closures)=1
	 AND NOT EXISTS(SELECT 1 FROM iam.password_attempts WHERE tenant_id=$2 AND principal_id IN (
	   SELECT id FROM iam.principals WHERE tenant_id=$2 AND login_name='auth-recovery-budget-user'))
	 FROM iam.authentication_recovery_state WHERE singleton`, source.Epoch, document.Organization.ID).Scan(&unchanged); err != nil || !unchanged {
		t.Fatal("floor materialization/next prepare fabricated an attempt or advanced recovery", err)
	}
	return lease, dump
}

func assertAuthenticationRecoveryRepeated(t *testing.T, ctx context.Context, source *authenticationrecovery.Service, closeSource func(),
	sourceDatabase, database *pgx.Conn, config *pgx.ConnConfig, dsn string, document iamv1.BootstrapDocument,
	budgetUser iamv1.User, mfa authenticationRecoveryMFAFixture, intent installationv1.AuthenticationRecoveryIntent,
	firstCompletion installationv1.AuthenticationRecoveryCompletion, firstSnapshot installationv1.AuthenticationRecoverySecuritySnapshot,
	lease installationv1.TOTPBackupSnapshotLease, dump []byte) {
	t.Helper()
	intent.CommandID, intent.Epoch = "cmd-"+strings.Repeat("e", 32), firstSnapshot.Epoch+1
	intent.AuthenticationStateDigest, intent.TOTPCustodyDigest = lease.AuthenticationStateDigest, lease.CustodyDigest
	envelope, err := source.Close(ctx, intent)
	if err != nil {
		t.Fatal("second source close rejected unchanged qualification after real password/OTP consumption", err)
	}
	closeSource()
	var password, otp, mfaPassword *installationv1.AuthenticationRecoveryAttemptWindow
	var consumedStep int64
	for _, account := range envelope.SecuritySnapshot.Accounts {
		for _, user := range account.Users {
			if account.AccountID == string(document.Organization.ID) && user.UserID == string(budgetUser.ID) {
				password = user.PasswordAttempts
			}
			if user.FactorID == mfa.factorID {
				otp, consumedStep = user.TOTPAttempts, user.LastConsumedStep
				mfaPassword = user.PasswordAttempts
			}
		}
	}
	if password == nil || password.UsedAttempts != 5 || otp == nil || otp.UsedAttempts != 5 {
		t.Fatal("second close omitted actual source password/OTP debits")
	}
	runAuthenticationRecoveryPostgresTool(t, ctx, config, "pg_restore", dump, "--exit-on-error")
	var retained string
	if err := database.QueryRow(ctx, "SELECT completion_document::text FROM iam.authentication_recovery_completions WHERE command_id=$1", firstCompletion.CommandID).Scan(&retained); err != nil {
		t.Fatal("second actual restore lost first completion", err)
	}
	var original string
	if err := sourceDatabase.QueryRow(ctx, "SELECT completion_document::text FROM iam.authentication_recovery_completions WHERE command_id=$1", firstCompletion.CommandID).Scan(&original); err != nil || retained != original {
		t.Fatal("second actual restore rewrote first completion", err)
	}
	workflow, _ := authenticationRecoveryWorkflow(t, ctx, dsn)
	if _, err := workflow.Reconcile(ctx, envelope.Closure, envelope.SecuritySnapshot); err != nil {
		t.Fatal("second recovery could not reconcile retained floors/history", err)
	}
	completion := reopenAuthenticationConcurrently(t, ctx, workflow, envelope.Closure, envelope.SecuritySnapshot)
	if installationv1.ValidateAuthenticationRecoveryCompletionForClosure(completion, envelope.Closure) != nil {
		t.Fatal("second recovery returned an invalid completion")
	}
	if old, err := workflow.Reopen(ctx, firstSnapshotClosure(t, ctx, database, firstCompletion.CommandID), firstSnapshot); err != nil || old != firstCompletion {
		t.Fatal("original completion replay after second recovery changed history", err)
	}
	var sourceFloorApplied, originalPasswordWindow bool
	if err := database.QueryRow(ctx, `SELECT f.last_consumed_step=$2 AND f.last_consumed_step>floor(extract(epoch FROM clock_timestamp())/30)::bigint,
	 clock_timestamp()<$3::timestamptz+interval '60 seconds' FROM iam.totp_authenticators f WHERE f.id=$1`,
		mfa.factorID, consumedStep, password.WindowStartedAt).Scan(&sourceFloorApplied, &originalPasswordWindow); err != nil || !sourceFloorApplied || !originalPasswordWindow {
		t.Fatal("second restore missed original password window or did not preserve source future OTP step", err)
	}
	// Two real password-authenticated challenges above can exhaust this MFA
	// USER's older password window. Observe its natural end before isolating
	// the still-live ten-minute OTP budget; never interpret a password refusal
	// as an OTP refusal or reset a counter to prepare this scenario. The other
	// USER's later password window is independently checked below.
	if mfaPassword != nil && mfaPassword.UsedAttempts == 5 {
		for {
			var now time.Time
			if err := database.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&now); err != nil {
				t.Fatal(err)
			}
			remaining := mfaPassword.WindowStartedAt.Add(time.Minute).Sub(now)
			if remaining <= 0 {
				break
			}
			if remaining > time.Minute {
				t.Fatal("restored MFA password budget has a future window")
			}
			timer := time.NewTimer(remaining)
			select {
			case <-ctx.Done():
				timer.Stop()
				t.Fatal(ctx.Err())
			case <-timer.C:
			}
		}
	}
	for index := 0; index < 2; index++ {
		peer, closePeer := authenticationRecoveryAPI(t, ctx, dsn, document)
		if index > 0 {
			if err := iammigration.Up(ctx, database); err != nil {
				t.Fatal("replay populated second-recovery schema", err)
			}
		}
		if _, err := peer.Login(ctx, iamv1.LoginRequest{LoginName: budgetUser.LoginName + "@" + string(document.Organization.ID),
			Password: iamHTTPSecret(t, initialDeveloperPassword), RequestID: fmt.Sprintf("repeated-exhausted-password-%d", index)}); !errors.Is(err, identityaccess.ErrUnauthenticated) {
			t.Fatal("second recovery refunded exhausted password budget, even for a correct password", err)
		}
		challenge, err := peer.Login(ctx, iamv1.LoginRequest{LoginName: "auth-recovery-key-user@" + string(document.Organization.ID),
			Password: iamHTTPSecret(t, changedDeveloperPassword), RequestID: fmt.Sprintf("repeated-otp-challenge-%d", index)})
		if err != nil || challenge.Outcome != iamv1.LoginChallengeRequired || challenge.Challenge == nil {
			t.Fatal("second recovery bypassed or could not begin password/TOTP login", err)
		}
		var now time.Time
		if err := database.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&now); err != nil {
			t.Fatal(err)
		}
		code, err := hotp.GenerateCode(string(mfa.seed.CopyBytes()), uint64(now.Unix()/30+1))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := peer.VerifyAuthenticationChallenge(ctx, challenge.Challenge.ID, iamv1.VerifyAuthenticationChallengeRequest{
			RequestID: fmt.Sprintf("repeated-exhausted-otp-%d", index), ChallengeCredential: challenge.ChallengeCredential,
			Code: iamHTTPSecret(t, code),
		}); !errors.Is(err, identityaccess.ErrUnauthenticated) {
			t.Fatal("second recovery/challenge/schema replay refunded exhausted OTP budget", err)
		}
		var unchanged bool
		if err := database.QueryRow(ctx, `SELECT pw.password_sequence=$3 AND pw.password_used_attempts=5
		 AND pw.password_window_started_at=$4 AND pw.password_generation=c.credential_version
		 AND NOT EXISTS(SELECT 1 FROM iam.password_attempts p WHERE p.tenant_id=$1 AND p.principal_id=$2)
		 AND EXISTS(SELECT 1 FROM iam.authentication_recovery_attempt_floors f
		   WHERE f.tenant_id=$1 AND f.totp_sequence=$5 AND f.totp_used_attempts=5 AND f.totp_window_started_at=$6
		     AND NOT EXISTS(SELECT 1 FROM iam.totp_attempts a WHERE a.tenant_id=f.tenant_id AND a.user_id=f.user_id AND a.sequence>=$5))
		 AND (SELECT state='PENDING' AND attempts=0 FROM iam.authentication_challenges WHERE tenant_id=$1 AND id=$7)
		 AND (SELECT count(*) FROM iam.authentication_recovery_completions)=2
		 FROM iam.authentication_recovery_attempt_floors pw JOIN iam.user_credentials c
		 ON c.tenant_id=pw.tenant_id AND c.principal_id=pw.user_id WHERE pw.tenant_id=$1 AND pw.user_id=$2`,
			document.Organization.ID, budgetUser.ID, password.Sequence, password.WindowStartedAt, otp.Sequence, otp.WindowStartedAt, challenge.Challenge.ID).Scan(&unchanged); err != nil || !unchanged {
			t.Fatal("second recovery manufactured attempts, reset windows/sequences or replayed completion", err)
		}
		closePeer()
	}
	// A restore's mechanical generation advance must not refund a guessing
	// budget. A genuinely reset password is a different credential, however:
	// its still-unexpired old floor must remain history, not lock it out.
	current, closeCurrent := authenticationRecoveryAPI(t, ctx, dsn, document)
	defer closeCurrent()
	root, err := current.Login(ctx, iamv1.LoginRequest{LoginName: document.Administrator.LoginName,
		Password: iamHTTPSecret(t, changedAdminPassword), RequestID: "repeated-reset-root-login"})
	if err != nil || root.Outcome != iamv1.LoginAuthenticated || !root.Credential.Present() {
		t.Fatal("authenticate current administrator for real credential replacement", err)
	}
	user, err := current.GetUser(ctx, root.Credential, budgetUser.ID, "repeated-reset-read-user")
	if err != nil {
		t.Fatal(err)
	}
	var floorBefore string
	var floorGeneration uint64
	if err := database.QueryRow(ctx, `SELECT row_to_json(f)::text,password_generation FROM iam.authentication_recovery_attempt_floors f
	 WHERE tenant_id=$1 AND user_id=$2`, document.Organization.ID, budgetUser.ID).Scan(&floorBefore, &floorGeneration); err != nil {
		t.Fatal("read immutable exhausted-password floor before genuine reset", err)
	}
	replacement := iamHTTPSecret(t, "Recovery-Reset-New-Password-936!")
	if _, err := current.ResetUserPassword(ctx, root.Credential, budgetUser.ID, iamv1.ResetUserPasswordRequest{
		InitialPassword: replacement, ResourceVersion: user.User.ResourceVersion, RequestID: "repeated-genuine-reset",
	}); err != nil {
		t.Fatal("current administrator could not reset a genuinely exhausted credential", err)
	}
	fresh, err := current.Login(ctx, iamv1.LoginRequest{LoginName: budgetUser.LoginName + "@" + string(document.Organization.ID),
		Password: replacement, RequestID: "repeated-genuine-reset-login"})
	if err != nil || !fresh.MustChangePassword || !fresh.Credential.Present() {
		t.Fatal("old-generation restore floor blocked the genuinely new password", err)
	}
	var newCredential bool
	if err := database.QueryRow(ctx, `SELECT c.credential_version=$3+1 AND a.credential_version=c.credential_version
	 AND a.state='SUCCEEDED' AND a.used_attempts=0 AND a.attempt_sequence=$4+1
	 AND clock_timestamp()<$5::timestamptz+interval '60 seconds'
	 FROM iam.user_credentials c JOIN iam.password_attempts a ON a.tenant_id=c.tenant_id AND a.principal_id=c.principal_id
	 WHERE c.tenant_id=$1 AND c.principal_id=$2`, document.Organization.ID, budgetUser.ID, floorGeneration,
		password.Sequence, password.WindowStartedAt).Scan(&newCredential); err != nil || !newCredential {
		t.Fatal("reset login did not use a new generation within the still-exhausted original window", err)
	}
	if _, err := current.ChangePassword(ctx, fresh.Credential, iamv1.ChangePasswordRequest{CurrentPassword: replacement,
		NewPassword: iamHTTPSecret(t, "Recovery-Changed-New-Password-973!"), RequestID: "repeated-genuine-forced-change"}); err != nil {
		t.Fatal("old restore floor blocked legitimate forced password change", err)
	}
	if replay, err := workflow.Reopen(ctx, envelope.Closure, envelope.SecuritySnapshot); err != nil || replay != completion {
		t.Fatal("old recovery completion changed after legitimate credential replacement", err)
	}
	if identity, err := current.CurrentIdentity(ctx, fresh.Credential); err != nil || identity.User.MustChangePassword {
		t.Fatal("old completion revoked or re-forced the legitimately retained current Session", err)
	}
	var floorAfter string
	if err := database.QueryRow(ctx, `SELECT row_to_json(f)::text FROM iam.authentication_recovery_attempt_floors f
	 WHERE tenant_id=$1 AND user_id=$2`, document.Organization.ID, budgetUser.ID).Scan(&floorAfter); err != nil || floorAfter != floorBefore {
		t.Fatal("genuine reset/change rewrote the sealed old-generation floor", err)
	}
	if err := database.QueryRow(ctx, `SELECT c.credential_version=$3+2 AND s.credential_version=c.credential_version AND s.status='ACTIVE'
	 AND a.state='SUCCEEDED' AND a.used_attempts=0 AND a.attempt_sequence=$4+2
	 AND (SELECT count(*) FROM iam.authentication_recovery_completions)=2
	 FROM iam.user_credentials c JOIN iam.password_attempts a ON a.tenant_id=c.tenant_id AND a.principal_id=c.principal_id
	 JOIN iam.sessions s ON s.tenant_id=c.tenant_id AND s.principal_id=c.principal_id AND s.id=$5
	 WHERE c.tenant_id=$1 AND c.principal_id=$2`, document.Organization.ID, budgetUser.ID, floorGeneration, password.Sequence,
		fresh.Session.ID).Scan(&newCredential); err != nil || !newCredential {
		t.Fatal("genuine change or old completion replay broke generation/sequence/session invariants", err)
	}
	closeCurrent()
	if err := iammigration.Verify(ctx, database); err != nil {
		t.Fatal("second recovery schema/retained evidence did not verify", err)
	}
	t.Log("two actual RR dumps/restores preserve source debits/future OTP step across schema replay/two authorities; genuine reset/change advances credentials without rewriting the floor or replaying completion")
}

func firstSnapshotClosure(t *testing.T, ctx context.Context, database *pgx.Conn, commandID string) installationv1.AuthenticationRecoveryClosure {
	t.Helper()
	var raw []byte
	if err := database.QueryRow(ctx, "SELECT closure_document FROM iam.authentication_recovery_closures WHERE command_id=$1", commandID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var closure installationv1.AuthenticationRecoveryClosure
	if json.Unmarshal(raw, &closure) != nil || installationv1.ValidateAuthenticationRecoveryClosure(closure) != nil {
		t.Fatal("original closure history is invalid")
	}
	return closure
}

func assertAuthenticationRecoveryPasswordBudget(t *testing.T, ctx context.Context, peers []*identityaccess.Authority, database *pgx.Conn,
	account iamv1.AccountID, user iamv1.User, snapshot installationv1.AuthenticationRecoverySecuritySnapshot) {
	t.Helper()
	var original *installationv1.AuthenticationRecoveryAttemptWindow
	for _, owner := range snapshot.Accounts {
		for _, subject := range owner.Users {
			if owner.AccountID == string(account) && subject.UserID == string(user.ID) {
				original = subject.PasswordAttempts
			}
		}
	}
	if original == nil || original.UsedAttempts != 4 {
		t.Fatal("source snapshot did not retain four actual failed password attempts")
	}
	if len(peers) != 2 {
		t.Fatal("password recovery concurrency needs two authorities")
	}
	// Observe from autocommit, not the lock-holding transaction's cached
	// activity snapshot, which can omit a newly connected second authority.
	observer, err := pgx.ConnectConfig(ctx, database.Config())
	if err != nil {
		t.Fatal("connect password lock observer", err)
	}
	defer observer.Close(context.Background())
	blocker, err := database.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback(context.Background())
	if _, err := blocker.Exec(ctx, "SELECT 1 FROM iam.principals WHERE tenant_id=$1 AND id=$2 FOR UPDATE", account, user.ID); err != nil {
		t.Fatal(err)
	}
	var blockerPID int32
	if err := blocker.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&blockerPID); err != nil {
		t.Fatal(err)
	}
	results := make(chan error, len(peers))
	password := iamHTTPSecret(t, "Incorrect-Recovery-Password-739!")
	for index, peer := range peers {
		go func() {
			_, err := peer.Login(ctx, iamv1.LoginRequest{LoginName: user.LoginName + "@" + string(account), Password: password,
				RequestID: fmt.Sprintf("auth-recovery-restored-race-%d", index)})
			results <- err
		}()
	}
	assertAuthenticationRecoveryUserWaiters(t, ctx, observer, blockerPID, len(peers))
	if err := blocker.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	for range peers {
		if err := <-results; !errors.Is(err, identityaccess.ErrUnauthenticated) {
			t.Fatal("concurrent restored wrong password was not rejected", err)
		}
	}
	for attempt, peer := range peers {
		var withinWindow bool
		if err := database.QueryRow(ctx, "SELECT clock_timestamp() < $1::timestamptz+interval '60 seconds'", original.WindowStartedAt).Scan(&withinWindow); err != nil || !withinWindow {
			t.Fatal("password restore assertion missed the original real window", err)
		}
		_, err := peer.Login(ctx, iamv1.LoginRequest{LoginName: user.LoginName + "@" + string(account), Password: password,
			RequestID: fmt.Sprintf("auth-recovery-restored-failed-%d", attempt)})
		if !errors.Is(err, identityaccess.ErrUnauthenticated) {
			t.Fatal("restored wrong password was not rejected", err)
		}
		var used int
		var sequence uint64
		var window time.Time
		if err := database.QueryRow(ctx, `SELECT used_attempts,attempt_sequence,window_started_at FROM iam.password_attempts WHERE tenant_id=$1 AND principal_id=$2`, account, user.ID).
			Scan(&used, &sequence, &window); err != nil {
			t.Fatal(err)
		}
		if used != 5 || sequence != original.Sequence+1 || !window.Equal(original.WindowStartedAt) {
			t.Fatalf("restore refunded password attempts or reset the original window: used=%d sequence=%d", used, sequence)
		}
	}
}

func assertAuthenticationRecoveryUserWaiters(t *testing.T, ctx context.Context, observer *pgx.Conn, blockerPID int32, count int) {
	t.Helper()
	waiting, stop := context.WithTimeout(ctx, 5*time.Second)
	defer stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var blocked int
		if err := observer.QueryRow(waiting, `WITH RECURSIVE waits(pid,blocker) AS (
		 SELECT pid,unnest(pg_blocking_pids(pid)) FROM pg_stat_activity WHERE datname=current_database() AND usename=$1
		 UNION SELECT pid,unnest(pg_blocking_pids(blocker)) FROM waits)
		 SELECT count(DISTINCT pid) FROM waits WHERE blocker=$2`, iamHTTPTestRole, blockerPID).Scan(&blocked); err != nil {
			t.Fatal("observe authentication reservations behind the real USER lock", err)
		}
		if blocked == count {
			return
		}
		select {
		case <-ticker.C:
		case <-waiting.Done():
			t.Fatal("both authentication peers did not reach the real USER lock")
		}
	}
}

func assertAuthenticationRecoveryOTPReplay(t *testing.T, ctx context.Context, service *identityaccess.Authority, database *pgx.Conn,
	document iamv1.BootstrapDocument, mfa authenticationRecoveryMFAFixture, snapshot installationv1.AuthenticationRecoverySecuritySnapshot) {
	t.Helper()
	var subject installationv1.AuthenticationRecoveryUserReplay
	for _, account := range snapshot.Accounts {
		for _, user := range account.Users {
			if account.AccountID == string(document.Organization.ID) && user.FactorID == mfa.factorID {
				subject = user
			}
		}
	}
	if subject.TOTPAttempts == nil || subject.TOTPAttempts.UsedAttempts != 2 || !mfa.login.Credential.Present() {
		t.Fatal("OTP replay fixture lacks a real successful source login and remaining attempts")
	}
	challenge, err := service.Login(ctx, iamv1.LoginRequest{LoginName: mfa.loginName + "@" + string(document.Organization.ID),
		Password: iamHTTPSecret(t, changedDeveloperPassword), RequestID: "auth-recovery-unexhausted-replay-login"})
	if err != nil || challenge.Challenge == nil || challenge.Outcome != iamv1.LoginChallengeRequired {
		t.Fatal("restored OTP replay subject could not start a real login", err)
	}
	passcode, err := hotp.GenerateCode(string(mfa.seed.CopyBytes()), uint64(subject.LastConsumedStep))
	if err != nil {
		t.Fatal(err)
	}
	code := iamHTTPSecret(t, passcode)
	var now time.Time
	var retainedStep int64
	if err := database.QueryRow(ctx, `SELECT clock_timestamp(),last_consumed_step FROM iam.totp_authenticators
	 WHERE tenant_id=$1 AND id=$2`, document.Organization.ID, mfa.factorID).Scan(&now, &retainedStep); err != nil {
		t.Fatal(err)
	}
	if step, err := authority.VerifyTOTP(mfa.seed, code, now.UTC(), -1); err != nil || step != subject.LastConsumedStep || retainedStep != subject.LastConsumedStep {
		t.Fatal("source replay code is no longer in the real accepted window or lost its source step", err)
	}
	if result, err := service.VerifyAuthenticationChallenge(ctx, challenge.Challenge.ID, iamv1.VerifyAuthenticationChallengeRequest{
		RequestID: "auth-recovery-unexhausted-replay-verify", ChallengeCredential: challenge.ChallengeCredential, Code: code,
	}); !errors.Is(err, identityaccess.ErrUnauthenticated) || result.Credential.Present() {
		t.Fatal("still-valid source-consumed OTP was accepted after actual backup restore", err)
	}
	var debited bool
	if err := database.QueryRow(ctx, `SELECT clock_timestamp(),a.state='REJECTED' AND a.used_attempts=$3+1 AND a.sequence=$4+1
	 AND a.window_started_at=$5 AND f.last_consumed_step=$6
	 AND (SELECT state='PENDING' AND attempts=1 FROM iam.authentication_challenges WHERE tenant_id=$1 AND id=$7)
	 AND NOT EXISTS(SELECT 1 FROM iam.sessions WHERE tenant_id=$1 AND principal_id=$2 AND status='ACTIVE')
	 FROM iam.totp_attempts a JOIN iam.totp_authenticators f ON f.tenant_id=a.tenant_id AND f.user_id=a.user_id AND f.id=$8
	 WHERE a.tenant_id=$1 AND a.user_id=$2`, document.Organization.ID, subject.UserID,
		subject.TOTPAttempts.UsedAttempts, subject.TOTPAttempts.Sequence, subject.TOTPAttempts.WindowStartedAt,
		subject.LastConsumedStep, challenge.Challenge.ID, mfa.factorID).Scan(&now, &debited); err != nil || !debited {
		t.Fatal("replay rejection did not debit a non-exhausted real attempt or changed factor/session authority", err)
	}
	if _, err := authority.VerifyTOTP(mfa.seed, code, now.UTC(), -1); err != nil {
		t.Fatal("OTP replay assertion crossed the validity window", err)
	}
	t.Log("source-consumed OTP remained valid after restore and was rejected with real attempt 2→3, unchanged factor step and no session")
}

func createAuthenticationRecoveryBackupRole(t *testing.T, ctx context.Context, database *pgx.Conn) {
	t.Helper()
	if _, err := database.Exec(ctx, `DO $role$ BEGIN
	 IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='matrix_iam_backup_custody_login') THEN
	 CREATE ROLE matrix_iam_backup_custody_login LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
	 END IF; END $role$;
	 ALTER ROLE matrix_iam_backup_custody_login PASSWORD 'matrix-authority-process-test-only';
	 GRANT matrix_iam_backup_custody TO matrix_iam_backup_custody_login;`); err != nil {
		t.Fatal("create authentication backup purpose login", err)
	}
}

func assertAuthenticationRecoveryDecisionArchive(t *testing.T, ctx context.Context, source, restored *pgx.Conn) {
	t.Helper()
	const history = `SELECT COALESCE(jsonb_agg(jsonb_build_array(tenant_id,id,document,policy_evidence,boundary_evidence,
	 role_evidence,contract_version) ORDER BY tenant_id,id),'[]'::jsonb)::text FROM iam.authorization_decisions`
	var original, retained string
	if err := source.QueryRow(ctx, history).Scan(&original); err != nil {
		t.Fatal(err)
	}
	if err := restored.QueryRow(ctx, history).Scan(&retained); err != nil {
		t.Fatal(err)
	}
	if original == "[]" || retained != original {
		t.Fatal("actual restored decision history differs or is empty")
	}
	for _, query := range []string{
		"SELECT jsonb_agg(to_jsonb(r) ORDER BY installation_id)::text FROM iam.bootstrap_receipts r",
		"SELECT jsonb_agg(to_jsonb(p) ORDER BY product,revision)::text FROM iam.authorization_profiles p",
	} {
		if err := source.QueryRow(ctx, query).Scan(&original); err != nil {
			t.Fatal(err)
		}
		if err := restored.QueryRow(ctx, query).Scan(&retained); err != nil {
			t.Fatal(err)
		}
		if original == "" || original != retained {
			t.Fatal("actual restored bootstrap/archive bytes differ")
		}
	}
	if err := iammigration.Verify(ctx, restored); err != nil {
		t.Fatal("actual restored IAM failed verification", err)
	}
	// Keep every row-local field coherent; only the archived action binding is
	// wrong. The private insertion trigger must reject even owner-level writes.
	const forgedDecision = `INSERT INTO iam.authorization_decisions SELECT candidate.* FROM
	 (SELECT to_jsonb(d)||jsonb_build_object('id','decision-restore-forged','action_name','iam.unknown.read',
	   'document',d.document||jsonb_build_object('id','decision-restore-forged','action','iam.unknown.read')) AS document
	  FROM iam.authorization_decisions d WHERE d.contract_version IN (4,5,6) ORDER BY d.contract_version DESC,d.tenant_id,d.id LIMIT 1) original
	 CROSS JOIN LATERAL jsonb_populate_record(NULL::iam.authorization_decisions,original.document) candidate`
	tx, err := restored.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(ctx, forgedDecision)
	_ = tx.Rollback(ctx)
	var rejected *pgconn.PgError
	if !errors.As(err, &rejected) || rejected.Code != "23514" || rejected.Message != "authorization decision archived profile conflicts" {
		t.Fatal("archive-mismatched insertion was not rejected by the relationship invariant")
	}
	// A corrupted retained row cannot pass merely because the trigger has been
	// restored correctly. This deliberately damages only a rolled-back fixture.
	tx, err = restored.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(ctx, "ALTER TABLE iam.authorization_decisions DISABLE TRIGGER authorization_decision_profile_is_bound"); err != nil {
		t.Fatal(err)
	}
	if tag, err := tx.Exec(ctx, forgedDecision); err != nil || tag.RowsAffected() != 1 {
		t.Fatal("retained corruption fixture was not inserted", err)
	}
	if _, err := tx.Exec(ctx, "SET CONSTRAINTS ALL IMMEDIATE"); err != nil {
		t.Fatal("retained corruption violated an unrelated completion invariant", err)
	}
	if _, err := tx.Exec(ctx, "ALTER TABLE iam.authorization_decisions ENABLE ALWAYS TRIGGER authorization_decision_profile_is_bound"); err != nil {
		t.Fatal(err)
	}
	var shapeReady bool
	if err := tx.QueryRow(ctx, "SELECT iam.authorization_decision_contract_ready()").Scan(&shapeReady); err != nil || !shapeReady {
		t.Fatal("retained corruption fixture did not restore the exact protected schema", err)
	}
	// The operational adapter intentionally sanitizes database failures. Do
	// not require it to disclose private SQL errors just for this assertion.
	if err := iammigration.Verify(ctx, tx); err == nil {
		t.Fatal("restored relationship verifier accepted a corrupted historical decision")
	}
	_ = tx.Rollback(ctx)
	if err := iammigration.Verify(ctx, restored); err != nil {
		t.Fatal("rollback did not restore verified original decision history", err)
	}
	for _, mutation := range []string{
		"ALTER TABLE iam.authorization_decisions DROP CONSTRAINT authorization_decisions_profile_fk",
		"ALTER TABLE iam.authorization_decisions DISABLE TRIGGER authorization_decision_profile_is_bound",
		"ALTER FUNCTION iam.guard_authorization_decision_profile() SECURITY DEFINER",
		"GRANT EXECUTE ON FUNCTION iam.guard_authorization_decision_profile() TO matrix_iam_api",
	} {
		tx, err := restored.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, mutation); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatal(err)
		}
		var ready bool
		err = tx.QueryRow(ctx, "SELECT ready FROM iam.readiness()").Scan(&ready)
		_ = tx.Rollback(ctx)
		if err != nil || ready {
			t.Fatal("readiness accepted missing archive relationship protection", err)
		}
	}
}

// Use the existing backup fixture's bounded PostgreSQL installation, never a
// guessed container or a shared server. No DSN, dump or stderr is logged.
func runAuthenticationRecoveryPostgresTool(t *testing.T, ctx context.Context, config *pgx.ConnConfig, name string, input []byte, args ...string) []byte {
	t.Helper()
	host, port := config.Host, strconv.Itoa(int(config.Port))
	var command *exec.Cmd
	if container := os.Getenv("MATRIX_IAM_BACKUP_POSTGRES_CONTAINER"); container != "" {
		label := os.Getenv("MATRIX_IAM_BACKUP_POSTGRES_TASK")
		if label == "" || len(container) != 64 || strings.ContainsAny(container, "\r\n /\\") {
			t.Fatal("missing owned PostgreSQL tool container")
		}
		actual, err := exec.CommandContext(ctx, "docker", "inspect", "--format", `{{ index .Config.Labels "matrix.task" }}`, container).Output()
		if err != nil || strings.TrimSpace(string(actual)) != label {
			t.Fatal("PostgreSQL tool container ownership differs")
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
	command.Args = append(command.Args, "--host="+host, "--port="+port, "--username="+config.User, "--dbname="+config.Database, "--no-password")
	command.Env = append(os.Environ(), "PGPASSWORD="+config.Password)
	command.Stdin = bytes.NewReader(input)
	output, err := command.Output()
	if err != nil {
		var failure *exec.ExitError
		if errors.As(err, &failure) {
			// Only schema identifiers and closed error categories are useful.
			// Never emit the failing SQL, COPY input, DETAIL or raw stderr.
			identifiers := regexp.MustCompile(`(?:relation|table|schema|role|constraint|trigger|type) "[A-Za-z0-9_.]+"`).FindAll(failure.Stderr, 8)
			var categories []string
			for _, category := range []string{"permission denied", "does not exist", "already exists", "violates check constraint", "row-level security", "invalid input", "authentication recovery", "statement timeout", "foreign key"} {
				if bytes.Contains(failure.Stderr, []byte(category)) {
					categories = append(categories, category)
				}
			}
			t.Fatalf("actual authentication recovery %s failed: categories=%v identifiers=%q (other output suppressed)", name, categories, identifiers)
		}
		t.Fatalf("actual authentication recovery %s could not run (output suppressed)", name)
	}
	return output
}

func openAuthenticationRecoveryDatabase(t *testing.T, ctx context.Context, dsn, prefix string) (*pgx.Conn, *pgx.ConnConfig) {
	t.Helper()
	config, err := pgx.ParseConfig(dsn)
	if err != nil || !strings.HasPrefix(config.Database, prefix) {
		t.Fatalf("authentication recovery gate requires an own %s database", prefix)
	}
	config.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	database, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal("connect authentication recovery database")
	}
	return database, config
}

func createAuthenticationRecoveryTestRoles(t *testing.T, ctx context.Context, database *pgx.Conn) {
	t.Helper()
	statement := `DO $roles$ BEGIN
        IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='` + authenticationRecoveryTestRole + `') THEN
            CREATE ROLE ` + authenticationRecoveryTestRole + ` LOGIN PASSWORD '` + iamHTTPTestPassword + `'
                NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
        END IF;
        IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='` + localRecoveryTestRole + `') THEN
            CREATE ROLE ` + localRecoveryTestRole + ` LOGIN PASSWORD '` + iamHTTPTestPassword + `'
                NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
        END IF;
    END $roles$;
    GRANT matrix_iam_authentication_recovery TO ` + authenticationRecoveryTestRole + `;
    GRANT matrix_iam_credential_recovery TO ` + localRecoveryTestRole
	if _, err := database.Exec(ctx, statement); err != nil {
		t.Fatal("create purpose-specific authentication recovery test logins", err)
	}
}

func authenticationRecoveryAPI(t *testing.T, ctx context.Context, dsn string, document iamv1.BootstrapDocument) (*identityaccess.Authority, func()) {
	t.Helper()
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.User, config.ConnConfig.Password = iamHTTPTestRole, iamHTTPTestPassword
	config.ConnConfig.RuntimeParams["application_name"] = "matrix-authentication-recovery-api-test"
	config.MaxConns = 2
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	repository, err := iampostgres.NewRepository(pool)
	if err != nil {
		t.Fatal(err)
	}
	totp, accessKeys := iamHTTPTOTPKeyring(t, document), iamHTTPAccessKeyWrapping(t, document)
	email := authenticationRecoveryEmailKeyring(t, document)
	service, err := identityaccess.NewAuthority(repository, identityaccess.Config{
		CursorKey:                bytes.Repeat([]byte{0x39}, 32),
		TOTPKeyring:              &totp,
		AccessKeyWrapping:        &accessKeys,
		EmailVerificationKeyring: &email,
	})
	if err != nil {
		t.Fatal(err)
	}
	return service, pool.Close
}

func authenticationRecoveryWorkflow(t *testing.T, ctx context.Context, dsn string) (*authenticationrecovery.Service, func()) {
	t.Helper()
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	return authenticationRecoveryWorkflowConfig(t, ctx, config)
}

func authenticationRecoveryWorkflowConfig(t *testing.T, ctx context.Context, configuration *pgxpool.Config) (*authenticationrecovery.Service, func()) {
	t.Helper()
	config := configuration.Copy()
	config.ConnConfig.User, config.ConnConfig.Password = authenticationRecoveryTestRole, iamHTTPTestPassword
	config.ConnConfig.RuntimeParams["application_name"] = "matrix-authentication-recovery-purpose-test"
	config.ConnConfig.RuntimeParams["statement_timeout"] = "15000"
	config.MaxConns = 2
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := pool.Ping(ctx); err != nil {
		t.Fatal("purpose-specific authentication recovery login failed")
	}
	repository, err := iampostgres.NewRepository(pool)
	if err != nil {
		t.Fatal(err)
	}
	service, err := authenticationrecovery.NewService(repository, authenticationrecovery.Config{})
	if err != nil {
		t.Fatal(err)
	}
	return service, pool.Close
}

type authenticationRecoveryMFAFixture struct {
	seed      iamv1.Secret
	factorID  string
	loginName string
	login     iamv1.LoginResponse
	proof     iamv1.StepUp
}

func prepareAuthenticationRecoveryIdentity(t *testing.T, ctx context.Context, service *identityaccess.Authority, database *pgx.Conn, document iamv1.BootstrapDocument, createReplayMaterial bool) (iamv1.Secret, iamv1.SessionID, authenticationRecoveryMFAFixture) {
	t.Helper()
	var mfa authenticationRecoveryMFAFixture
	login, err := service.Login(ctx, iamv1.LoginRequest{LoginName: document.Administrator.LoginName, Password: document.Administrator.Password, RequestID: "auth-recovery-initial-login"})
	if err != nil || !login.MustChangePassword || !login.Credential.Present() {
		t.Fatalf("login recovery fixture: %v", err)
	}
	if _, err := service.ChangePassword(ctx, login.Credential, iamv1.ChangePasswordRequest{
		CurrentPassword: document.Administrator.Password,
		NewPassword:     iamHTTPSecret(t, changedAdminPassword),
		RequestID:       "auth-recovery-initial-password-change",
	}); err != nil {
		t.Fatal("change recovery fixture password", err)
	}
	if createReplayMaterial {
		keyUser, err := service.CreateUser(ctx, login.Credential, iamv1.CreateUserRequest{
			LoginName:       "auth-recovery-key-user",
			DisplayName:     "Authentication recovery key user",
			InitialPassword: iamHTTPSecret(t, initialDeveloperPassword),
			RequestID:       "auth-recovery-key-user-create",
		})
		if err != nil {
			t.Fatal("create recovery fixture AccessKey user", err)
		}
		keyLogin, err := service.Login(ctx, iamv1.LoginRequest{
			LoginName: "auth-recovery-key-user@" + string(document.Organization.ID),
			Password:  iamHTTPSecret(t, initialDeveloperPassword),
			RequestID: "auth-recovery-key-user-login",
		})
		if err != nil || !keyLogin.MustChangePassword {
			t.Fatalf("login recovery fixture AccessKey user: %v", err)
		}
		if _, err := service.ChangePassword(ctx, keyLogin.Credential, iamv1.ChangePasswordRequest{
			CurrentPassword: iamHTTPSecret(t, initialDeveloperPassword),
			NewPassword:     iamHTTPSecret(t, changedDeveloperPassword),
			RequestID:       "auth-recovery-key-user-password",
		}); err != nil {
			t.Fatal("change recovery fixture AccessKey user password", err)
		}
		policy, err := service.CreatePolicy(ctx, login.Credential, iamv1.CreatePolicyRequest{
			DisplayName: "Authentication recovery AccessKey fixture",
			RequestID:   "auth-recovery-key-policy",
			Document: iamv1.PolicyDocument{
				LanguageVersion: "1",
				Scope:           iamv1.AuthorityScopeTenant,
				Statements: []iamv1.PolicyStatement{{
					SID:       "recovery-key-fixture",
					Effect:    iamv1.PolicyAllow,
					Actions:   []iamv1.Action{iamv1.ActionIAMAccessKeyList, iamv1.ActionIAMAccessKeyCreate},
					Resources: []iamv1.PolicyResourceSelector{{Kind: iamv1.ResourceUser, Match: iamv1.PolicyResourceAnyInAuthority}},
				}},
			},
		})
		if err != nil {
			t.Fatal("create recovery fixture AccessKey policy", err)
		}
		group, err := service.CreateGroup(ctx, login.Credential, iamv1.CreateGroupRequest{
			Name: "Authentication recovery business users", RequestID: "auth-recovery-key-group",
		})
		if err != nil {
			t.Fatal("create recovery fixture authorization group", err)
		}
		if _, err := service.CreateGroupMembership(ctx, login.Credential, group.ID, iamv1.CreateGroupMembershipRequest{
			UserID: keyUser.ID, RequestID: "auth-recovery-key-membership",
		}); err != nil {
			t.Fatal("join recovery fixture authorization group", err)
		}
		if _, err := service.CreatePolicyAttachment(ctx, login.Credential, iamv1.CreatePolicyAttachmentRequest{
			Target:                iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetGroup, ID: string(group.ID)},
			PolicyID:              policy.Policy.ID,
			PolicyResourceVersion: policy.Policy.ResourceVersion,
			RequestID:             "auth-recovery-key-policy-attachment",
		}); err != nil {
			t.Fatal("attach recovery fixture group policy", err)
		}
		keyLogin, err = service.Login(ctx, iamv1.LoginRequest{
			LoginName: "auth-recovery-key-user@" + string(document.Organization.ID),
			Password:  iamHTTPSecret(t, changedDeveloperPassword),
			RequestID: "auth-recovery-key-policy-login",
		})
		if err != nil || keyLogin.MustChangePassword || !keyLogin.Credential.Present() {
			t.Fatalf("refresh recovery fixture authorization: %v", err)
		}
		directory, err := service.ListAccessKeys(ctx, keyLogin.Credential, keyUser.ID, "auth-recovery-key-list")
		if err != nil {
			t.Fatal("list recovery fixture AccessKeys", err)
		}
		created, err := service.CreateAccessKey(ctx, keyLogin.Credential, keyUser.ID, iamv1.CreateAccessKeyRequest{
			UserResourceVersion: directory.UserResourceVersion,
			RequestID:           "auth-recovery-key-create",
		})
		if err != nil || created.Outcome != "APPLIED" || !created.Secret.Present() {
			t.Fatalf("create recovery fixture AccessKey: %v", err)
		}
		// The group still allows create. This narrower current boundary must
		// continue to deny it after recovery, while preserving list access.
		limited, err := service.CreatePolicy(ctx, login.Credential, iamv1.CreatePolicyRequest{
			DisplayName: "Recovery business read ceiling", RequestID: "auth-recovery-key-boundary-policy",
			Document: iamv1.PolicyDocument{LanguageVersion: "1", Scope: iamv1.AuthorityScopeTenant,
				Statements: []iamv1.PolicyStatement{{SID: "list-only", Effect: iamv1.PolicyAllow,
					Actions:   []iamv1.Action{iamv1.ActionIAMAccessKeyList},
					Resources: []iamv1.PolicyResourceSelector{{Kind: iamv1.ResourceUser, Match: iamv1.PolicyResourceAnyInAuthority}}}}},
		})
		if err != nil {
			t.Fatal("create narrower recovery fixture boundary", err)
		}
		boundary, err := service.GetUserPermissionBoundary(ctx, login.Credential, keyUser.ID, "auth-recovery-key-boundary-read")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := service.SetUserPermissionBoundary(ctx, login.Credential, keyUser.ID, iamv1.SetUserPermissionBoundaryRequest{
			PolicyID: limited.Policy.ID, PolicyResourceVersion: limited.Policy.ResourceVersion,
			ResourceVersion: boundary.ResourceVersion, RequestID: "auth-recovery-key-boundary",
		}); err != nil {
			t.Fatal("set recovery fixture user boundary", err)
		}
		mfa = enrollAuthenticationRecoveryTOTP(t, ctx, service, database, document, keyLogin.Credential, keyUser.LoginName)
		mfa.login = authenticationRecoveryMFALogin(t, ctx, service, database, document, mfa, "before-close", 0)
		state, err := service.AuthenticatorState(ctx, mfa.login.Credential)
		if err != nil || state.EnrollmentState != "BOUND" {
			t.Fatalf("read before-close MFA qualification: %v", err)
		}
		mfa.proof, err = service.StartStepUp(ctx, mfa.login.Credential, iamv1.StartStepUpRequest{
			RequestID: "auth-recovery-pending-regeneration", Operation: iamv1.StepUpRegenerateRecoveryCodes,
			ExpectedFactorRevision: state.FactorRevision,
		})
		if err != nil {
			t.Fatal("start before-close operation proof", err)
		}
		mfa.proof, err = service.VerifyStepUp(ctx, mfa.login.Credential, mfa.proof.ID, iamv1.VerifyStepUpRequest{
			RequestID: "auth-recovery-before-close-proof", Password: iamHTTPSecret(t, changedDeveloperPassword),
			Code: authenticationRecoveryFreshTOTP(t, ctx, database, document.Organization.ID, mfa, 0),
		})
		if err != nil || mfa.proof.State != "PROVED" {
			t.Fatalf("prove before-close regeneration: %v", err)
		}
		seedAuthenticationRecoveryPendingWork(t, ctx, service, database, document, keyUser.ID)
	}
	return login.Credential, login.Session.ID, mfa
}

func authenticationRecoveryEmailKeyring(t *testing.T, document iamv1.BootstrapDocument) iamv1.EmailVerificationKeyring {
	t.Helper()
	digest, err := iamv1.BootstrapDigest(document)
	if err != nil {
		t.Fatal(err)
	}
	return iamv1.EmailVerificationKeyring{
		APIVersion:     iamv1.APIVersion,
		Kind:           "EmailVerificationKeyring",
		Purpose:        iamv1.EmailVerificationWrappingPurpose,
		Scope:          iamv1.SecurityMailInstallationScope{InstallationID: document.InstallationID, BootstrapDigest: digest},
		KeysetRevision: 1,
		ActiveKeyID:    "auth-recovery-email",
		Keys: []iamv1.EmailVerificationWrappingKey{{
			KeyID:         "auth-recovery-email",
			FormatVersion: 1,
			KeyMaterial:   iamHTTPSecret(t, base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x63}, 32))),
		}},
	}
}

func enrollAuthenticationRecoveryTOTP(t *testing.T, ctx context.Context, service *identityaccess.Authority, database *pgx.Conn, document iamv1.BootstrapDocument, credential iamv1.Secret, loginName string) authenticationRecoveryMFAFixture {
	t.Helper()
	password := iamHTTPSecret(t, changedDeveloperPassword)
	pending, err := service.StartNotificationVerification(ctx, credential, iamv1.StartNotificationContactVerificationRequest{
		Email:     loginName + "@matrix.test",
		Password:  password,
		RequestID: loginName + "-email-start",
	})
	if err != nil {
		t.Fatal("start recovery fixture email verification", err)
	}
	binding := iamv1.EmailVerificationBinding{AccountID: pending.AccountID, UserID: pending.UserID, VerificationID: pending.ID}
	sealed := authority.SealedEmailVerificationCode{FormatVersion: 1}
	if err := database.QueryRow(ctx, `SELECT installation_id,bootstrap_digest,email,credential_generation,contact_revision,issued_at,expires_at,key_id,nonce,ciphertext
      FROM iam.notification_contact_verifications WHERE tenant_id=$1 AND id=$2`, pending.AccountID, pending.ID).Scan(
		&binding.InstallationID, &binding.BootstrapDigest, &binding.Recipient, &binding.CredentialGeneration,
		&binding.ContactRevision, &binding.IssuedAt, &binding.ExpiresAt, &sealed.KeyID, &sealed.Nonce, &sealed.Ciphertext); err != nil {
		t.Fatal("read recovery fixture email challenge", err)
	}
	binding.IssuedAt, binding.ExpiresAt = binding.IssuedAt.UTC(), binding.ExpiresAt.UTC()
	protector, err := authority.NewEmailVerificationProtector(authenticationRecoveryEmailKeyring(t, document))
	if err != nil {
		t.Fatal(err)
	}
	code, err := protector.Open(binding, sealed)
	if err != nil {
		t.Fatal("open recovery fixture email code", err)
	}
	if _, err := service.ConfirmNotificationContact(ctx, credential, pending.ID, iamv1.ConfirmNotificationContactVerificationRequest{
		Code: code, RequestID: loginName + "-email-confirm",
	}); err != nil {
		t.Fatal("confirm recovery fixture email", err)
	}
	state, err := service.AuthenticatorState(ctx, credential)
	if err != nil || state.EnrollmentState != "NEVER_BOUND" {
		t.Fatalf("read recovery fixture authenticator state: %v", err)
	}
	started, err := service.StartTOTPEnrollment(ctx, credential, iamv1.StartTOTPEnrollmentRequest{
		RequestID: loginName + "-totp-start", Password: password, ExpectedFactorRevision: state.FactorRevision,
	})
	if err != nil || started.Provisioning == nil || !started.Provisioning.Seed.Present() {
		t.Fatalf("start recovery fixture TOTP enrollment: %v", err)
	}
	var now time.Time
	if err := database.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&now); err != nil {
		t.Fatal(err)
	}
	if remainder := now.Unix() % 30; remainder >= 27 {
		timer := time.NewTimer(time.Duration(31-remainder) * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			t.Fatal(ctx.Err())
		case <-timer.C:
		}
		if err := database.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&now); err != nil {
			t.Fatal(err)
		}
	}
	totpCode, err := hotp.GenerateCode(string(started.Provisioning.Seed.CopyBytes()), uint64(now.Unix()/30))
	if err != nil {
		t.Fatal(err)
	}
	confirmed, err := service.ConfirmTOTPEnrollment(ctx, credential, started.Enrollment.ID, iamv1.ConfirmTOTPEnrollmentRequest{
		RequestID: loginName + "-totp-confirm", Code: iamHTTPSecret(t, totpCode),
	})
	if err != nil || confirmed.Enrollment.State != "CONFIRMED" || len(confirmed.RecoveryCodes) != 10 {
		t.Fatalf("confirm recovery fixture TOTP enrollment: %v", err)
	}
	return authenticationRecoveryMFAFixture{seed: started.Provisioning.Seed, factorID: started.Enrollment.ID, loginName: loginName}
}

func authenticationRecoveryRegenerationRequest(mfa authenticationRecoveryMFAFixture) iamv1.RegenerateRecoveryCodesRequest {
	return iamv1.RegenerateRecoveryCodesRequest{RequestID: mfa.proof.RequestID, StepUpID: mfa.proof.ID, ExpectedFactorRevision: mfa.proof.ExpectedFactorRevision}
}

func authenticationRecoveryFreshTOTP(t *testing.T, ctx context.Context, database *pgx.Conn, account iamv1.AccountID, mfa authenticationRecoveryMFAFixture, offset int64) iamv1.Secret {
	t.Helper()
	if offset < 0 || offset > 1 {
		t.Fatal("TOTP fixture offset must stay inside the production skew")
	}
	deadline := time.Now().Add(35 * time.Second)
	for {
		var now time.Time
		var consumed int64
		if err := database.QueryRow(ctx, `SELECT clock_timestamp(),last_consumed_step FROM iam.totp_authenticators WHERE tenant_id=$1 AND id=$2`, account, mfa.factorID).Scan(&now, &consumed); err != nil {
			t.Fatal("observe actual TOTP step", err)
		}
		// A +1 source code leaves a real future high-water mark. Start early
		// in the window so the subsequent real restore can prove it, without
		// changing the clock, production skew or factor state directly.
		if now.Unix()/30+offset > consumed && now.Unix()%30 < 27 && (offset == 0 || now.Unix()%30 < 12) {
			code, err := hotp.GenerateCode(string(mfa.seed.CopyBytes()), uint64(now.Unix()/30+offset))
			if err != nil {
				t.Fatal("compute actual fresh TOTP", err)
			}
			return iamHTTPSecret(t, code)
		}
		if time.Now().After(deadline) {
			t.Fatal("actual TOTP step did not advance within one production window")
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			t.Fatal(ctx.Err())
		case <-timer.C:
		}
	}
}

func authenticationRecoveryMFALogin(t *testing.T, ctx context.Context, service *identityaccess.Authority, database *pgx.Conn, document iamv1.BootstrapDocument, mfa authenticationRecoveryMFAFixture, phase string, offset int64) iamv1.LoginResponse {
	t.Helper()
	challenge, err := service.Login(ctx, iamv1.LoginRequest{
		LoginName: mfa.loginName + "@" + string(document.Organization.ID), Password: iamHTTPSecret(t, changedDeveloperPassword),
		RequestID: "auth-recovery-mfa-login-" + phase,
	})
	if err != nil || challenge.Outcome != iamv1.LoginChallengeRequired || challenge.Challenge == nil {
		t.Fatalf("password-only login bypassed MFA %s: %v", phase, err)
	}
	login, err := service.VerifyAuthenticationChallenge(ctx, challenge.Challenge.ID, iamv1.VerifyAuthenticationChallengeRequest{
		RequestID: "auth-recovery-mfa-verify-" + phase, ChallengeCredential: challenge.ChallengeCredential,
		Code: authenticationRecoveryFreshTOTP(t, ctx, database, document.Organization.ID, mfa, offset),
	})
	if err != nil || login.Outcome != iamv1.LoginAuthenticated || !login.Credential.Present() {
		t.Fatalf("fresh MFA login %s failed: %v", phase, err)
	}
	return login
}

func authenticationRecoveryConcurrentMFALogin(t *testing.T, ctx context.Context, peers []*identityaccess.Authority, database *pgx.Conn,
	document iamv1.BootstrapDocument, mfa authenticationRecoveryMFAFixture, snapshot installationv1.AuthenticationRecoverySecuritySnapshot) iamv1.LoginResponse {
	t.Helper()
	if len(peers) != 2 {
		t.Fatal("restored OTP last-slot race requires two authorities")
	}
	var subject installationv1.AuthenticationRecoveryUserReplay
	for _, account := range snapshot.Accounts {
		for _, user := range account.Users {
			if account.AccountID == string(document.Organization.ID) && user.FactorID == mfa.factorID {
				subject = user
			}
		}
	}
	if subject.TOTPAttempts == nil || subject.TOTPAttempts.UsedAttempts != 4 {
		t.Fatal("original sealed snapshot must leave exactly one real OTP attempt")
	}
	challenges := make([]iamv1.LoginResponse, len(peers))
	for index, peer := range peers {
		challenge, err := peer.Login(ctx, iamv1.LoginRequest{LoginName: mfa.loginName + "@" + string(document.Organization.ID),
			Password: iamHTTPSecret(t, changedDeveloperPassword), RequestID: fmt.Sprintf("auth-recovery-last-slot-challenge-%d", index)})
		if err != nil || challenge.Outcome != iamv1.LoginChallengeRequired || challenge.Challenge == nil {
			t.Fatal("create real challenge for restored final OTP slot", err)
		}
		challenges[index] = challenge
	}
	if challenges[0].Challenge.ID == challenges[1].Challenge.ID {
		t.Fatal("OTP peers unexpectedly share a challenge")
	}
	code := authenticationRecoveryFreshTOTP(t, ctx, database, document.Organization.ID, mfa, 1)
	observer, err := pgx.ConnectConfig(ctx, database.Config())
	if err != nil {
		t.Fatal("connect OTP lock observer", err)
	}
	defer observer.Close(context.Background())
	blocker, err := database.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback(context.Background())
	if _, err := blocker.Exec(ctx, "SELECT 1 FROM iam.principals WHERE tenant_id=$1 AND id=$2 FOR UPDATE", document.Organization.ID, subject.UserID); err != nil {
		t.Fatal(err)
	}
	var blockerPID int32
	if err := blocker.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&blockerPID); err != nil {
		t.Fatal(err)
	}
	type result struct {
		response iamv1.LoginResponse
		err      error
	}
	results := make(chan result, len(peers))
	for index, peer := range peers {
		go func() {
			challenge := challenges[index]
			response, err := peer.VerifyAuthenticationChallenge(ctx, challenge.Challenge.ID, iamv1.VerifyAuthenticationChallengeRequest{
				RequestID: fmt.Sprintf("auth-recovery-last-slot-verify-%d", index), ChallengeCredential: challenge.ChallengeCredential, Code: code,
			})
			results <- result{response, err}
		}()
	}
	assertAuthenticationRecoveryUserWaiters(t, ctx, observer, blockerPID, len(peers))
	if err := blocker.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	var login iamv1.LoginResponse
	successes, refusals := 0, 0
	for range peers {
		result := <-results
		if result.err == nil && result.response.Outcome == iamv1.LoginAuthenticated && result.response.Credential.Present() {
			login = result.response
			successes++
		} else if errors.Is(result.err, identityaccess.ErrUnauthenticated) && !result.response.Credential.Present() {
			refusals++
		} else {
			t.Fatal("unexpected restored OTP competition result", result.err)
		}
	}
	if successes != 1 || refusals != 1 {
		t.Fatalf("last restored OTP slot issued %d Sessions and rejected %d requests", successes, refusals)
	}
	var final bool
	if err := database.QueryRow(ctx, `SELECT a.state='SUCCEEDED' AND a.used_attempts=5 AND a.sequence=$3+1
	 AND a.window_started_at=$4 AND clock_timestamp()<$4::timestamptz+interval '10 minutes'
	 AND f.last_consumed_step>$5
	 AND (SELECT count(*)=2 AND sum(attempts)=1 AND count(*) FILTER (WHERE state='CONSUMED')=1
	   AND count(*) FILTER (WHERE state='PENDING')=1 FROM iam.authentication_challenges WHERE tenant_id=$1 AND id IN ($6,$7))
	 AND (SELECT count(*)=1 AND bool_and(id=$8) FROM iam.sessions WHERE tenant_id=$1 AND principal_id=$2 AND status='ACTIVE')
	 AND (SELECT count(*)=1 FROM iam.audit_outbox WHERE event_document->>'action'='iam.session.issued'
	   AND event_document->'target'->>'id'=$8)
	 FROM iam.totp_attempts a JOIN iam.totp_authenticators f ON f.tenant_id=a.tenant_id AND f.user_id=a.user_id AND f.id=$9
	 WHERE a.tenant_id=$1 AND a.user_id=$2`, document.Organization.ID, subject.UserID, subject.TOTPAttempts.Sequence,
		subject.TOTPAttempts.WindowStartedAt, subject.LastConsumedStep, challenges[0].Challenge.ID, challenges[1].Challenge.ID,
		login.Session.ID, mfa.factorID).Scan(&final); err != nil || !final {
		t.Fatal("concurrent OTP login did not preserve source budget, exact Session/fact or challenge accounting", err)
	}
	for index, peer := range peers {
		if _, err := peer.CurrentIdentity(ctx, login.Credential); err != nil {
			t.Fatal("winning MFA Session is not valid on both authorities", err)
		}
		directory, err := peer.ListAccessKeys(ctx, login.Credential, iamv1.PrincipalID(subject.UserID), fmt.Sprintf("reopened-business-key-list-%d", index))
		if err != nil || directory.AccountID != document.Organization.ID || string(directory.UserID) != subject.UserID || len(directory.Items) != 1 {
			t.Fatal("restored group/boundary permissions did not allow the original business resource", err)
		}
		if result, err := peer.CreateAccessKey(ctx, login.Credential, iamv1.PrincipalID(subject.UserID), iamv1.CreateAccessKeyRequest{
			UserResourceVersion: directory.UserResourceVersion, RequestID: fmt.Sprintf("reopened-business-boundary-denied-%d", index),
		}); !errors.Is(err, identityaccess.ErrForbidden) || result.Secret.Present() || result.Outcome != "" {
			t.Fatal("restored narrower boundary did not constrain the group's create permission", err)
		}
		var originalKeyStillFenced bool
		if err := database.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM iam.authentication_recovery_access_key_fences f
		 JOIN iam.access_keys k ON k.id=f.access_key_id WHERE k.tenant_id=$1 AND k.user_id=$2 AND f.access_key_id=$3 AND f.command_id=$4)`,
			document.Organization.ID, subject.UserID, directory.Items[0].Key.ID, snapshot.CommandID).Scan(&originalKeyStillFenced); err != nil || !originalKeyStillFenced {
			t.Fatal("business resource access lost the original AccessKey recovery fence", err)
		}
		if _, err := peer.GetUser(ctx, login.Credential, document.Administrator.ID, fmt.Sprintf("reopened-business-user-denied-%d", index)); !errors.Is(err, identityaccess.ErrForbidden) {
			t.Fatal("ordinary recovered user acquired ungranted user-management permission", err)
		}
		if _, err := peer.ListAccounts(ctx, login.Credential, "", fmt.Sprintf("reopened-business-platform-denied-%d", index)); !errors.Is(err, identityaccess.ErrForbidden) {
			t.Fatal("ordinary recovered user acquired platform account-directory permission", err)
		}
	}
	var noExtraKey bool
	if err := database.QueryRow(ctx, `SELECT (SELECT count(*) FROM iam.access_keys)=1
	 AND (SELECT count(*) FROM iam.audit_outbox WHERE event_document->>'action'='iam.access-key.created')=1`).Scan(&noExtraKey); err != nil || !noExtraKey {
		t.Fatal("denied post-recovery boundary operation created a partial Key or success fact", err)
	}
	t.Log("two current challenges blocked on the restored USER; source OTP budget4→5 admitted exactly one MFA Session/fact; both authorities allow group list but enforce the narrower create boundary, deny user/platform management and preserve the Key fence")
	return login
}

func assertAuthenticationRecoveryStepUpFenced(t *testing.T, ctx context.Context, peers []*identityaccess.Authority, database *pgx.Conn,
	document iamv1.BootstrapDocument, mfa authenticationRecoveryMFAFixture, snapshot installationv1.AuthenticationRecoverySecuritySnapshot) {
	t.Helper()
	service := peers[0]
	if _, err := service.RegenerateRecoveryCodes(ctx, mfa.login.Credential, authenticationRecoveryRegenerationRequest(mfa)); !errors.Is(err, identityaccess.ErrUnauthenticated) {
		t.Fatalf("pre-restore proved operation survived its revoked Session: %v", err)
	}
	login := authenticationRecoveryConcurrentMFALogin(t, ctx, peers, database, document, mfa, snapshot)
	if _, err := service.RegenerateRecoveryCodes(ctx, login.Credential, authenticationRecoveryRegenerationRequest(mfa)); !errors.Is(err, identityaccess.ErrUnauthenticated) {
		t.Fatalf("new Session consumed a pre-restore proof: %v", err)
	}
	if _, err := service.StartStepUp(ctx, login.Credential, iamv1.StartStepUpRequest{
		RequestID: "auth-recovery-fenced-batch-regeneration", Operation: iamv1.StepUpRegenerateRecoveryCodes,
		ExpectedFactorRevision: mfa.proof.ExpectedFactorRevision,
	}); !errors.Is(err, identityaccess.ErrUnauthenticated) {
		t.Fatalf("new proof treated a permanently fenced batch as current recovery authority: %v", err)
	}
	var state string
	var consumed bool
	var completions, regeneratedBatches, regenerationFacts, regenerationNotices int
	if err := database.QueryRow(ctx, `SELECT state,consumed_at IS NOT NULL,
      (SELECT count(*) FROM iam.recovery_code_regenerations),
      (SELECT count(*) FROM iam.mfa_recovery_batches WHERE regeneration_id IS NOT NULL),
      (SELECT count(*) FROM iam.audit_outbox WHERE event_document->>'action'='iam.recovery-codes.regenerated'),
      (SELECT count(*) FROM iam.security_notifications WHERE kind='RECOVERY_CODES_REGENERATED')
      FROM iam.step_ups WHERE tenant_id=$1 AND id=$2`, document.Organization.ID, mfa.proof.ID).
		Scan(&state, &consumed, &completions, &regeneratedBatches, &regenerationFacts, &regenerationNotices); err != nil {
		t.Fatal("read fenced operation history", err)
	}
	if state != "PROVED" || consumed || completions != 0 || regeneratedBatches != 0 || regenerationFacts != 0 || regenerationNotices != 0 {
		t.Fatal("rejected post-restore regeneration partially changed proof, batch, fact or notification")
	}
	if err := iammigration.Up(ctx, database); err != nil {
		t.Fatal("replay restored schema", err)
	}
	if _, err := service.StartStepUp(ctx, login.Credential, iamv1.StartStepUpRequest{
		RequestID: "auth-recovery-fenced-batch-after-replay", Operation: iamv1.StepUpRegenerateRecoveryCodes,
		ExpectedFactorRevision: mfa.proof.ExpectedFactorRevision,
	}); !errors.Is(err, identityaccess.ErrUnauthenticated) {
		t.Fatalf("equal schema replay erased the permanent recovery-code fence: %v", err)
	}
}

func seedAuthenticationRecoveryPendingWork(t *testing.T, ctx context.Context, service *identityaccess.Authority, database *pgx.Conn, document iamv1.BootstrapDocument, user iamv1.PrincipalID) {
	t.Helper()
	challenge, err := service.Login(ctx, iamv1.LoginRequest{
		LoginName: "auth-recovery-key-user@" + string(document.Organization.ID),
		Password:  iamHTTPSecret(t, changedDeveloperPassword),
		RequestID: "auth-recovery-pending-challenge",
	})
	if err != nil || challenge.Outcome != iamv1.LoginChallengeRequired || challenge.Challenge == nil || !challenge.ChallengeCredential.Present() {
		t.Fatalf("create recovery fixture authentication challenge: %v", err)
	}
	config := database.Config().Copy()
	config.User, config.Password = iamHTTPTestRole, iamHTTPTestPassword
	config.RuntimeParams["application_name"] = "matrix-authentication-recovery-pending-work-test"
	connection, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal("connect recovery pending-work fixture")
	}
	defer connection.Close(context.Background())
	tx, err := connection.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, "SELECT set_config('matrix.iam_tenant_id',$1,true)", document.Organization.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SELECT iam.reserve_password_attempt($1,NULL,NULL,NULL,'auth-recovery-pending-password','LOGIN',NULL)`,
		"auth-recovery-key-user@"+string(document.Organization.ID)); err != nil {
		t.Fatal("reserve recovery password attempt", err)
	}
	if _, err := tx.Exec(ctx, `SELECT iam.reserve_totp_attempt($1,$2,NULL,$3,'LOGIN','auth-recovery-pending-totp')`,
		document.Organization.ID, user, challenge.Challenge.ID); err != nil {
		t.Fatal("reserve recovery TOTP attempt", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func authenticationRecoveryLocalAuthority(t *testing.T, document iamv1.BootstrapDocument, bootstrapDigest string) iamv1.LocalCredentialRecoveryAuthority {
	t.Helper()
	return iamv1.LocalCredentialRecoveryAuthority{
		APIVersion: iamv1.APIVersion,
		Kind:       "LocalCredentialRecoveryAuthority",
		Purpose:    iamv1.LocalCredentialRecoveryPurpose,
		Scope: iamv1.LocalCredentialRecoveryScope{
			InstallationID:  document.InstallationID,
			BootstrapDigest: bootstrapDigest,
			AccountID:       document.Organization.ID,
			PrincipalID:     document.Administrator.ID,
		},
		CapabilityKey: iamHTTPSecret(t, base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x41}, 32))),
	}
}

func authenticationRecoveryIntent(installationID string) installationv1.AuthenticationRecoveryIntent {
	return installationv1.AuthenticationRecoveryIntent{
		APIVersion:          installationv1.AuthenticationRecoveryAPIVersion,
		Kind:                installationv1.AuthenticationRecoveryIntentKind,
		Purpose:             installationv1.AuthenticationRecoveryPurpose,
		InstallationID:      installationID,
		Epoch:               1,
		CommandID:           "cmd-" + strings.Repeat("2", 32),
		BackupID:            "backup-" + strings.Repeat("3", 32),
		BackupDigest:        digestForAuthenticationRecovery('4'),
		SourceReleaseID:     "matrix-v0.3.0-authprep-aaaaaaaaaaaa",
		SourceReleaseDigest: digestForAuthenticationRecovery('5'),
		TargetReleaseID:     "matrix-v0.4.0-authmfa-bbbbbbbbbbbb",
		TargetReleaseDigest: digestForAuthenticationRecovery('6'),
		TOTPCustodyDigest:   digestForAuthenticationRecovery('7'),
	}
}

func digestForAuthenticationRecovery(value byte) string {
	return "sha256:" + strings.Repeat(string(value), 64)
}

func closeAuthenticationConcurrently(t *testing.T, ctx context.Context, service *authenticationrecovery.Service, intent installationv1.AuthenticationRecoveryIntent) installationv1.AuthenticationRecoveryClosureEnvelope {
	t.Helper()
	var results [2]installationv1.AuthenticationRecoveryClosureEnvelope
	var failures [2]error
	var wait sync.WaitGroup
	for index := range results {
		wait.Add(1)
		go func() {
			defer wait.Done()
			results[index], failures[index] = service.Close(ctx, intent)
		}()
	}
	wait.Wait()
	first, firstErr := installationv1.EncodeAuthenticationRecoveryClosureEnvelope(results[0])
	second, secondErr := installationv1.EncodeAuthenticationRecoveryClosureEnvelope(results[1])
	if failures[0] != nil || failures[1] != nil || firstErr != nil || secondErr != nil || !bytes.Equal(first, second) {
		t.Fatalf("concurrent equal close was not one result: %v %v", failures[0], failures[1])
	}
	return results[0]
}

func reconcileAuthenticationConcurrently(t *testing.T, ctx context.Context, service *authenticationrecovery.Service, closure installationv1.AuthenticationRecoveryClosure, snapshot installationv1.AuthenticationRecoverySecuritySnapshot) installationv1.AuthenticationRecoveryClosure {
	t.Helper()
	var results [2]installationv1.AuthenticationRecoveryClosure
	var failures [2]error
	var wait sync.WaitGroup
	for index := range results {
		wait.Add(1)
		go func() {
			defer wait.Done()
			results[index], failures[index] = service.Reconcile(ctx, closure, snapshot)
		}()
	}
	wait.Wait()
	if failures[0] != nil || failures[1] != nil || results[0] != results[1] {
		t.Fatalf("concurrent equal reconciliation was not one result: %v %v", failures[0], failures[1])
	}
	return results[0]
}

func reopenAuthenticationConcurrently(t *testing.T, ctx context.Context, service *authenticationrecovery.Service, closure installationv1.AuthenticationRecoveryClosure, snapshot installationv1.AuthenticationRecoverySecuritySnapshot) installationv1.AuthenticationRecoveryCompletion {
	t.Helper()
	var results [2]installationv1.AuthenticationRecoveryCompletion
	var failures [2]error
	var wait sync.WaitGroup
	for index := range results {
		wait.Add(1)
		go func() {
			defer wait.Done()
			results[index], failures[index] = service.Reopen(ctx, closure, snapshot)
		}()
	}
	wait.Wait()
	if failures[0] != nil || failures[1] != nil || results[0] != results[1] {
		t.Fatalf("concurrent equal reopen was not one result: %v %v", failures[0], failures[1])
	}
	return results[0]
}

func assertAuthenticationAuthorityOpen(t *testing.T, ctx context.Context, service *identityaccess.Authority, credential iamv1.Secret) {
	t.Helper()
	if readiness, err := service.Readiness(ctx); err != nil || readiness.State != iamv1.ReadinessReady {
		t.Fatalf("authentication authority is not open: %v", err)
	}
	if _, err := service.CurrentIdentity(ctx, credential); err != nil {
		t.Fatalf("open authority rejected its Session: %v", err)
	}
}

func assertAuthenticationAuthorityClosed(t *testing.T, ctx context.Context, service *identityaccess.Authority, credential iamv1.Secret) {
	t.Helper()
	if _, err := service.Readiness(ctx); !errors.Is(err, identityaccess.ErrUnauthenticated) {
		t.Fatalf("closed authority served readiness: %v", err)
	}
	if _, err := service.CurrentIdentity(ctx, credential); !errors.Is(err, identityaccess.ErrUnauthenticated) {
		t.Fatalf("closed authority authenticated a Session: %v", err)
	}
}

type authenticationRecoverySecurityState struct {
	credentialGeneration  int64
	factorStep            int64
	activeSessions        int
	accessKeys            int
	recoveryBatches       int
	codeFences            int
	accessKeyFences       int
	closures              int
	reconciliations       int
	completions           int
	passwordReserved      int
	passwordAbandoned     int
	totpReserved          int
	totpAbandoned         int
	challengePending      int
	challengeCancelled    int
	restoredSessionStatus string
}

func readAuthenticationRecoverySecurityState(t *testing.T, ctx context.Context, database *pgx.Conn, document iamv1.BootstrapDocument, session iamv1.SessionID) authenticationRecoverySecurityState {
	t.Helper()
	var result authenticationRecoverySecurityState
	err := database.QueryRow(ctx, `SELECT
      (SELECT credential_version FROM iam.user_credentials WHERE tenant_id=$1 AND principal_id=$2),
	  COALESCE((SELECT max(last_consumed_step) FROM iam.totp_authenticators WHERE tenant_id=$1 AND state='ACTIVE'),-1),
      (SELECT count(*) FROM iam.sessions WHERE tenant_id=$1 AND status='ACTIVE'),
      (SELECT count(*) FROM iam.access_keys WHERE tenant_id=$1),
      (SELECT count(*) FROM iam.mfa_recovery_batches WHERE tenant_id=$1),
      (SELECT count(*) FROM iam.authentication_recovery_code_fences),
      (SELECT count(*) FROM iam.authentication_recovery_access_key_fences),
      (SELECT count(*) FROM iam.authentication_recovery_closures),
      (SELECT count(*) FROM iam.authentication_recovery_reconciliations),
      (SELECT count(*) FROM iam.authentication_recovery_completions),
	  (SELECT count(*) FROM iam.password_attempts WHERE state='RESERVED'),
	  (SELECT count(*) FROM iam.password_attempts WHERE state='ABANDONED'),
	  (SELECT count(*) FROM iam.totp_attempts WHERE state='RESERVED'),
	  (SELECT count(*) FROM iam.totp_attempts WHERE state='ABANDONED'),
	  (SELECT count(*) FROM iam.authentication_challenges WHERE state='PENDING'),
	  (SELECT count(*) FROM iam.authentication_challenges WHERE state='CANCELLED'),
      (SELECT status FROM iam.sessions WHERE tenant_id=$1 AND id=$3)`,
		document.Organization.ID, document.Administrator.ID, session).Scan(
		&result.credentialGeneration, &result.factorStep, &result.activeSessions, &result.accessKeys,
		&result.recoveryBatches, &result.codeFences, &result.accessKeyFences, &result.closures,
		&result.reconciliations, &result.completions, &result.passwordReserved, &result.passwordAbandoned,
		&result.totpReserved, &result.totpAbandoned, &result.challengePending, &result.challengeCancelled,
		&result.restoredSessionStatus)
	if err != nil {
		t.Fatal("read authentication recovery security state", err)
	}
	return result
}

func assertAuthenticationRecoveryClosedFacts(t *testing.T, ctx context.Context, source, restored *pgx.Conn, closure installationv1.AuthenticationRecoveryClosure) {
	t.Helper()
	action := string(auditv1.ActionIAMAuthenticationRecoveryClosed)
	var sourceDocument, restoredDocument string
	if err := source.QueryRow(ctx, `SELECT event_document::text FROM iam.audit_outbox WHERE event_document->>'action'=$1`, action).Scan(&sourceDocument); err != nil {
		t.Fatal("read source closed fact", err)
	}
	if err := restored.QueryRow(ctx, `SELECT event_document::text FROM iam.audit_outbox WHERE event_document->>'action'=$1`, action).Scan(&restoredDocument); err != nil {
		t.Fatal("read reconciled closed fact", err)
	}
	if sourceDocument != restoredDocument || !strings.Contains(sourceDocument, closure.CommandID) {
		t.Fatal("restored authority did not reproduce the exact source closed fact")
	}
}

func assertAuthenticationRecoveryAuditFacts(t *testing.T, ctx context.Context, source, restored *pgx.Conn) {
	t.Helper()
	var sourceCount, restoredCount int
	if err := source.QueryRow(ctx, `SELECT count(*) FROM iam.audit_outbox WHERE event_document->>'action' LIKE 'iam.authentication-recovery.%'`).Scan(&sourceCount); err != nil {
		t.Fatal(err)
	}
	if err := restored.QueryRow(ctx, `SELECT count(*) FROM iam.audit_outbox WHERE event_document->>'action' LIKE 'iam.authentication-recovery.%'
      AND event_document#>>'{actor,type}'='SYSTEM' AND event_document#>>'{actor,id}'='iam-authentication-recovery'
      AND event_document#>>'{target,kind}'='INSTALLATION' AND event_document#>>'{target,id}'=event_document->>'installationId'`).Scan(&restoredCount); err != nil {
		t.Fatal(err)
	}
	if sourceCount != 1 || restoredCount != 3 {
		t.Fatalf("authentication recovery fact cardinality source=%d restored=%d", sourceCount, restoredCount)
	}
}

func assertAuthenticationRecoveryDatabaseBoundary(t *testing.T, ctx context.Context, database *pgx.Conn, adminConfig *pgx.ConnConfig) {
	t.Helper()
	config := adminConfig.Copy()
	config.User, config.Password = authenticationRecoveryTestRole, iamHTTPTestPassword
	connection, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal("connect authentication recovery boundary probe")
	}
	defer connection.Close(context.Background())
	var sessionUser, currentUser string
	if err := connection.QueryRow(ctx, "SELECT session_user,current_user").Scan(&sessionUser, &currentUser); err != nil || sessionUser != authenticationRecoveryTestRole || currentUser != authenticationRecoveryTestRole {
		t.Fatal("authentication recovery boundary probe used another login")
	}
	for _, attack := range []string{
		"SELECT * FROM iam.authentication_recovery_state",
		"SELECT * FROM iam.authentication_recovery_attempt_floors",
		"UPDATE iam.authentication_recovery_attempt_floors SET password_used_attempts=0",
		"SELECT iam.guard_authentication_recovery_attempt_floor()",
		"SELECT * FROM iam.bootstrap_receipts",
		"SELECT * FROM iam.sessions",
		"SET ROLE matrix_iam_owner",
		"SET ROLE matrix_iam_api",
		"SELECT * FROM iam.readiness()",
	} {
		_, attackErr := connection.Exec(ctx, attack)
		var databaseError *pgconn.PgError
		if !errors.As(attackErr, &databaseError) || databaseError.Code != "42501" {
			t.Fatalf("purpose-specific authentication recovery login crossed boundary with %q: %v", attack, attackErr)
		}
	}
	var executableFunctions, tableCapabilities int
	err = database.QueryRow(ctx, `SELECT
      (SELECT count(*) FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
        WHERE n.nspname='iam' AND has_function_privilege($1,p.oid,'EXECUTE')),
      (SELECT count(*) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname='iam' AND c.relkind IN ('r','p','v','m','S')
          AND has_table_privilege($1,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'))`, authenticationRecoveryTestRole).
		Scan(&executableFunctions, &tableCapabilities)
	if err != nil || executableFunctions != 5 || tableCapabilities != 0 {
		t.Fatalf("authentication recovery login capabilities functions=%d tables=%d: %v", executableFunctions, tableCapabilities, err)
	}
}

func assertAuthenticationRecoveryHistoryImmutable(t *testing.T, ctx context.Context, database *pgx.Conn, tables ...string) {
	t.Helper()
	if len(tables) == 0 {
		tables = []string{
			"authentication_recovery_closures",
			"authentication_recovery_reconciliations",
			"authentication_recovery_completions",
			"authentication_recovery_code_fences",
			"authentication_recovery_access_key_fences",
		}
	}
	for _, table := range tables {
		var exists bool
		if err := database.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM iam."+pgx.Identifier{table}.Sanitize()+")").Scan(&exists); err != nil || !exists {
			t.Fatal("history immutability requires actual retained records", table, err)
		}
		for _, attack := range []string{
			fmt.Sprintf("UPDATE iam.%s SET command_id=command_id", table),
			fmt.Sprintf("DELETE FROM iam.%s", table),
			fmt.Sprintf("TRUNCATE iam.%s CASCADE", table),
		} {
			tx, err := database.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(ctx, "SET LOCAL ROLE matrix_iam_owner"); err != nil {
				t.Fatal(err)
			}
			_, attackErr := tx.Exec(ctx, attack)
			_ = tx.Rollback(ctx)
			var databaseError *pgconn.PgError
			if !errors.As(attackErr, &databaseError) || databaseError.Code != "42501" {
				t.Fatalf("IAM owner changed authentication recovery history with %q: %v", attack, attackErr)
			}
		}
	}
	tx, err := database.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, "SET LOCAL ROLE matrix_iam_owner"); err != nil {
		t.Fatal(err)
	}
	_, attackErr := tx.Exec(ctx, "UPDATE iam.authentication_recovery_state SET epoch=epoch")
	_ = tx.Rollback(ctx)
	var databaseError *pgconn.PgError
	if !errors.As(attackErr, &databaseError) || databaseError.Code != "42501" {
		t.Fatalf("IAM owner rewrote authentication recovery state: %v", attackErr)
	}
}
