package integration

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	iampostgres "github.com/xiak/matrix/app/service/iam/internal/data/postgres"
	iamhttp "github.com/xiak/matrix/app/service/iam/internal/service/nethttp"
	"github.com/xiak/matrix/app/service/iam/internal/usecase/identityaccess"
	iammigration "github.com/xiak/matrix/app/service/iam/migration"
)

const localRecoveryTestRole = "matrix_iam_http_test_recovery"

func TestIAMLocalCredentialRecoveryPostgres(t *testing.T) {
	const environment = "MATRIX_IAM_RECOVERY_POSTGRES_TEST_DSN"
	dsn := os.Getenv(environment)
	if dsn == "" {
		t.Skipf("set %s to a clean disposable PostgreSQL 18 database", environment)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	config, err := pgx.ParseConfig(dsn)
	if err != nil || !strings.HasPrefix(config.Database, "matrix_iam_recovery_") {
		t.Fatal("local recovery gate requires its own matrix_iam_recovery_ database")
	}
	config.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	database, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal("connect local recovery test database")
	}
	defer database.Close(context.Background())
	assertIAMPostgres18(t, ctx, database)
	assertCleanIAMSchema(t, ctx, database)
	applyIAMSchema(t, ctx, database)
	createIAMHTTPRole(t, ctx, database)
	if _, err := database.Exec(ctx, `DO $role$ BEGIN
        IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='`+localRecoveryTestRole+`') THEN
            CREATE ROLE `+localRecoveryTestRole+` LOGIN PASSWORD '`+iamHTTPTestPassword+`'
                NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
        END IF;
        END $role$; GRANT matrix_iam_credential_recovery TO `+localRecoveryTestRole); err != nil {
		t.Fatal(err)
	}
	api := localRecoveryWorkflow(t, ctx, dsn, iamHTTPTestRole)
	local := localRecoveryWorkflow(t, ctx, dsn, localRecoveryTestRole)
	document := iamHTTPBootstrap(t)
	status, err := api.Bootstrap(ctx, document)
	if err != nil {
		t.Fatal(err)
	}
	assertLocalRecoveryDatabaseBoundary(t, ctx, database, config)
	handler, err := iamhttp.NewHandler(api, iamhttp.Config{})
	if err != nil {
		t.Fatal(err)
	}
	capabilityKey := iamHTTPSecret(t, base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x7a}, 32)))
	authority := iamv1.LocalCredentialRecoveryAuthority{APIVersion: iamv1.APIVersion, Kind: "LocalCredentialRecoveryAuthority", Purpose: iamv1.LocalCredentialRecoveryPurpose,
		Scope: iamv1.LocalCredentialRecoveryScope{InstallationID: document.InstallationID, BootstrapDigest: status.ContentDigest, OrganizationID: document.Organization.ID, PrincipalID: document.Administrator.ID}, CapabilityKey: capabilityKey}
	initial := localRecoveryLogin(t, handler, "admin", adminPassword, true)
	primary := localRecoveryChangePassword(t, handler, initial, adminPassword, changedAdminPassword)
	_ = localRecoveryLogin(t, handler, "admin", changedAdminPassword, false)
	request := localRecoveryRequest(t, ctx, local, authority, "local-recovery-first", "Recovered-Primary-Password-43!")
	before := readLocalRecoveryState(t, ctx, database, authority.Scope)
	assertLocalRecoveryClosedSQLFact(t, ctx, database, authority, request, before.passwordHash)
	if _, err := api.InspectLocalCredentialRecovery(ctx, authority, nil); !errors.Is(err, identityaccess.ErrForbidden) {
		t.Fatalf("API identity acquired local inspection: %v", err)
	}
	if _, err := api.RecoverLocalCredentials(ctx, authority, request); !errors.Is(err, identityaccess.ErrForbidden) {
		t.Fatalf("API identity acquired offline recovery: %v", err)
	}
	worker := localRecoveryWorkflow(t, ctx, dsn, iamHTTPWorkerRole)
	if _, err := worker.RecoverLocalCredentials(ctx, authority, request); !errors.Is(err, identityaccess.ErrForbidden) {
		t.Fatalf("worker acquired offline recovery: %v", err)
	}
	if before != readLocalRecoveryState(t, ctx, database, authority.Scope) {
		t.Fatal("runtime-role refusal changed credential state")
	}

	for name, mutate := range map[string]func(*iamv1.LocalCredentialRecoveryAuthority, *iamv1.LocalCredentialRecoveryRequest){
		"installation": func(a *iamv1.LocalCredentialRecoveryAuthority, r *iamv1.LocalCredentialRecoveryRequest) {
			a.Scope.InstallationID = "installation-other"
			r.Scope = a.Scope
		},
		"bootstrap": func(a *iamv1.LocalCredentialRecoveryAuthority, r *iamv1.LocalCredentialRecoveryRequest) {
			a.Scope.BootstrapDigest = "sha256:" + strings.Repeat("f", 64)
			r.Scope = a.Scope
		},
		"tenant": func(a *iamv1.LocalCredentialRecoveryAuthority, r *iamv1.LocalCredentialRecoveryRequest) {
			a.Scope.OrganizationID = "organization-other"
			r.Scope = a.Scope
		},
		"primary": func(a *iamv1.LocalCredentialRecoveryAuthority, r *iamv1.LocalCredentialRecoveryRequest) {
			a.Scope.PrincipalID = "service-iam"
			r.Scope = a.Scope
		},
		"binding": func(_ *iamv1.LocalCredentialRecoveryAuthority, r *iamv1.LocalCredentialRecoveryRequest) {
			r.Expected.PlatformBindingID = "binding-other"
		},
		"generation": func(_ *iamv1.LocalCredentialRecoveryAuthority, r *iamv1.LocalCredentialRecoveryRequest) {
			r.Expected.CredentialGeneration++
		},
		"principal version": func(_ *iamv1.LocalCredentialRecoveryAuthority, r *iamv1.LocalCredentialRecoveryRequest) {
			r.Expected.PrincipalResourceVersion++
		},
		"organization version": func(_ *iamv1.LocalCredentialRecoveryAuthority, r *iamv1.LocalCredentialRecoveryRequest) {
			r.Expected.OrganizationResourceVersion++
		},
		"binding version": func(_ *iamv1.LocalCredentialRecoveryAuthority, r *iamv1.LocalCredentialRecoveryRequest) {
			r.Expected.PlatformBindingResourceVersion++
		},
	} {
		t.Run(name, func(t *testing.T) {
			a, r := authority, request
			mutate(&a, &r)
			r, err = iamv1.SignLocalCredentialRecoveryRequest(a, r)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = local.RecoverLocalCredentials(ctx, a, r); !errors.Is(err, identityaccess.ErrForbidden) && !errors.Is(err, identityaccess.ErrConflict) {
				t.Fatalf("invalid recovery accepted: %v", err)
			}
			if before != readLocalRecoveryState(t, ctx, database, authority.Scope) {
				t.Fatal("rejected intent partially changed security state")
			}
		})
	}
	for _, corruption := range []string{"primary-disabled", "organization-disabled", "not-owner", "not-user"} {
		t.Run(corruption, func(t *testing.T) {
			// Privileged fixture corruption is an attack, never the supported
			// credential recovery entry. Restore only the injected fixture field.
			var damage, restore string
			switch corruption {
			case "primary-disabled":
				damage = `UPDATE iam.principals SET status='DISABLED' WHERE tenant_id=$1 AND id=$2`
				restore = `UPDATE iam.principals SET status='ACTIVE' WHERE tenant_id=$1 AND id=$2`
			case "organization-disabled":
				damage = `UPDATE iam.organizations SET status='DISABLED' WHERE id=$1 AND $2::text IS NOT NULL`
				restore = `UPDATE iam.organizations SET status='ACTIVE' WHERE id=$1 AND $2::text IS NOT NULL`
			case "not-owner":
				damage = `UPDATE iam.login_index SET account_owner=false WHERE tenant_id=$1 AND principal_id=$2`
				restore = `UPDATE iam.login_index SET account_owner=true WHERE tenant_id=$1 AND principal_id=$2`
			case "not-user":
				damage = `UPDATE iam.principals SET principal_type='SERVICE_ACCOUNT',login_name=NULL WHERE tenant_id=$1 AND id=$2`
				restore = `UPDATE iam.principals SET principal_type='USER',login_name='admin' WHERE tenant_id=$1 AND id=$2`
			}
			if _, err := database.Exec(ctx, damage, authority.Scope.OrganizationID, authority.Scope.PrincipalID); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if _, err := database.Exec(ctx, restore, authority.Scope.OrganizationID, authority.Scope.PrincipalID); err != nil {
					t.Fatal(err)
				}
			}()
			damaged := readLocalRecoveryState(t, ctx, database, authority.Scope)
			if _, err := local.InspectLocalCredentialRecovery(ctx, authority, nil); !errors.Is(err, identityaccess.ErrForbidden) {
				t.Fatalf("ineligible inspection: %v", err)
			}
			if _, err := local.RecoverLocalCredentials(ctx, authority, request); !errors.Is(err, identityaccess.ErrForbidden) {
				t.Fatalf("ineligible apply: %v", err)
			}
			if damaged != readLocalRecoveryState(t, ctx, database, authority.Scope) {
				t.Fatal("recovery enabled/repaired ineligible identity")
			}
		})
	}
	result, err := local.RecoverLocalCredentials(ctx, authority, request)
	if err != nil || result.State != "APPLIED" || result.PreviousCredentialGeneration != before.generation || result.CredentialGeneration != before.generation+1 {
		t.Fatalf("local recovery failed: %v", err)
	}
	after := readLocalRecoveryState(t, ctx, database, authority.Scope)
	if after.generation != before.generation+1 || after.principalVersion != before.principalVersion+1 || !after.mustChange ||
		after.activeSessions != 0 || after.bindings != before.bindings || after.passwordHash == before.passwordHash ||
		after.organizationStatus != before.organizationStatus || after.principalStatus != before.principalStatus ||
		after.organizationVersion != before.organizationVersion || !after.owner || after.services != before.services ||
		after.facts != before.facts+1 || after.receipts != before.receipts+1 || result.RevokedSessions != before.activeSessions {
		t.Fatal("recovery did not make exactly its atomic security transition")
	}
	if response := performIAMRequest(handler, http.MethodGet, "/v1/auth/me", primary, nil); response.Code != http.StatusUnauthorized {
		t.Fatal("local recovery retained a previous session")
	}
	assertLocalRecoveryReplay(t, ctx, local, authority, request, result)
	for _, attack := range []string{
		`UPDATE iam.local_credential_recoveries SET input_commitment='sha256:'||repeat('f',64)`,
		`DELETE FROM iam.local_credential_recoveries`,
		`TRUNCATE iam.local_credential_recoveries`,
	} {
		tx, err := database.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `SET LOCAL ROLE matrix_iam_owner; SELECT set_config('matrix.iam_tenant_id',$1,true)`, string(authority.Scope.OrganizationID)); err != nil {
			t.Fatal(err)
		}
		_, attackErr := tx.Exec(ctx, attack)
		_ = tx.Rollback(ctx)
		var pgErr *pgconn.PgError
		if !errors.As(attackErr, &pgErr) || pgErr.Code != "42501" {
			t.Fatal("IAM owner changed immutable local completion")
		}
	}
	assertLocalRecoveryReplay(t, ctx, local, authority, request, result)
	changed := request
	changed.NewPassword = iamHTTPSecret(t, "Substituted-Primary-Password-53!")
	changed, err = iamv1.SignLocalCredentialRecoveryRequest(authority, changed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := local.RecoverLocalCredentials(ctx, authority, changed); !errors.Is(err, identityaccess.ErrConflict) {
		t.Fatalf("command accepted another input commitment: %v", err)
	}
	if after != readLocalRecoveryState(t, ctx, database, authority.Scope) {
		t.Fatal("changed replay mutated completed recovery")
	}
	temporary := localRecoveryLogin(t, handler, "admin", "Recovered-Primary-Password-43!", true)
	otherTemporary := localRecoveryLogin(t, handler, "admin", "Recovered-Primary-Password-43!", true)
	assertPlatformDecisionHTTP(t, handler, temporary, paasCredential, false)
	primary = localRecoveryChangePassword(t, handler, temporary, "Recovered-Primary-Password-43!", changedAdminPassword)
	assertPlatformDecisionHTTP(t, handler, primary, paasCredential, true)
	if response := performIAMRequest(handler, http.MethodGet, "/v1/auth/me", otherTemporary, nil); response.Code != http.StatusUnauthorized {
		t.Fatal("forced change promoted another recovery-password session")
	}
	stable := readLocalRecoveryState(t, ctx, database, authority.Scope)
	assertLocalRecoveryReplay(t, ctx, local, authority, request, result)
	if stable != readLocalRecoveryState(t, ctx, database, authority.Scope) {
		t.Fatal("historical recovery replay overwrote a later password")
	}

	// A separate normally provisioned platform USER can race revocation without
	// relying on the recovered primary's now-revoked bearer.
	created := performIAMRequest(handler, http.MethodPost, "/v1/principals", primary, []byte(`{"loginName":"recovery.operator","displayName":"Recovery operator","initialPassword":"Other-Operator-Initial-91!","requestId":"create-recovery-operator"}`))
	var operator iamv1.Principal
	if created.Code != http.StatusCreated || json.Unmarshal(created.Body.Bytes(), &operator) != nil {
		t.Fatal("create separate platform operator")
	}
	operatorSession := localRecoveryLogin(t, handler, "recovery.operator@"+string(authority.Scope.OrganizationID), "Other-Operator-Initial-91!", true)
	operatorSession = localRecoveryChangePassword(t, handler, operatorSession, "Other-Operator-Initial-91!", "Other-Operator-Changed-92!")
	bindingBody, _ := json.Marshal(iamv1.PutRoleBindingRequest{PrincipalID: operator.ID, Role: iamv1.RolePlatformOperator, RequestID: "grant-recovery-operator"})
	if response := performIAMRequest(handler, http.MethodPost, "/v1/role-bindings", primary, bindingBody); response.Code != http.StatusOK {
		t.Fatal("grant separate platform operator")
	}
	adminBindingBody, _ := json.Marshal(iamv1.PutRoleBindingRequest{PrincipalID: operator.ID, Role: iamv1.RoleOrganizationAdmin, RequestID: "grant-recovery-organization-admin"})
	if response := performIAMRequest(handler, http.MethodPost, "/v1/role-bindings", primary, adminBindingBody); response.Code != http.StatusOK {
		t.Fatal("grant independent organization administrator")
	}
	for _, action := range []string{"reset", "recover", "grant", "login"} {
		t.Run(action+" races local recovery", func(t *testing.T) {
			const replacement = "Recovery-Parallel-Protected-Password-88!"
			r := localRecoveryRequest(t, ctx, local, authority, "recovery-versus-"+action, replacement)
			prior := readLocalRecoveryState(t, ctx, database, authority.Scope)
			path, credential := "", operatorSession
			var body any
			switch action {
			case "reset":
				path = "/v1/principals/" + string(authority.Scope.PrincipalID) + ":reset-password"
				body = map[string]any{"initialPassword": "Forbidden-Online-Password-89!", "resourceVersion": r.Expected.PrincipalResourceVersion, "requestId": "online-reset-versus-local"}
			case "recover":
				path = "/v1/organizations/" + string(authority.Scope.OrganizationID) + ":recover-administrator"
				body = map[string]any{"principalId": authority.Scope.PrincipalID, "initialPassword": "Forbidden-Online-Password-89!", "resourceVersion": r.Expected.OrganizationResourceVersion, "requestId": "online-recovery-versus-local"}
			case "grant":
				path = "/v1/role-bindings"
				body = iamv1.PutRoleBindingRequest{PrincipalID: authority.Scope.PrincipalID, Role: iamv1.RolePlatformOperator, RequestID: "platform-grant-versus-local"}
			case "login":
				path, credential = "/v1/auth/login", ""
				body = map[string]any{"loginName": "admin", "password": changedAdminPassword, "requestId": "old-login-versus-local"}
			}
			encoded, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			start := make(chan struct{})
			recoverErr := make(chan error, 1)
			type response struct {
				status     int
				credential string
			}
			peer := make(chan response, 1)
			go func() { <-start; _, err := local.RecoverLocalCredentials(ctx, authority, r); recoverErr <- err }()
			go func() {
				<-start
				result := performIAMRequest(handler, http.MethodPost, path, credential, encoded)
				var login struct {
					Credential string `json:"credential"`
				}
				_ = json.Unmarshal(result.Body.Bytes(), &login)
				peer <- response{result.Code, login.Credential}
			}()
			close(start)
			if err := <-recoverErr; err != nil {
				t.Fatalf("local recovery race: %v", err)
			}
			other := <-peer
			switch action {
			case "reset", "recover":
				if other.status != http.StatusForbidden {
					t.Fatalf("online interface took over platform primary: %d", other.status)
				}
			case "grant":
				// Recovery-first makes the target password-change-only, so even
				// an equal platform grant must then be refused by its own rules.
				if other.status != http.StatusOK && other.status != http.StatusForbidden {
					t.Fatalf("authorized binding grant did not serialize: %d", other.status)
				}
			case "login":
				if other.status != http.StatusOK && other.status != http.StatusUnauthorized {
					t.Fatalf("old-password login race status=%d", other.status)
				}
				if other.credential != "" && performIAMRequest(handler, http.MethodGet, "/v1/auth/me", other.credential, nil).Code != http.StatusUnauthorized {
					t.Fatal("pre-recovery credential issued a surviving session")
				}
			}
			next := readLocalRecoveryState(t, ctx, database, authority.Scope)
			if next.generation != prior.generation+1 || next.activeSessions != 0 || next.bindings != prior.bindings || next.facts != prior.facts+1 || next.receipts != prior.receipts+1 || next.services != prior.services {
				t.Fatal("racing operation altered local recovery's closed effects")
			}
			primary = localRecoveryChangePassword(t, handler, localRecoveryLogin(t, handler, "admin", replacement, true), replacement, changedAdminPassword)
		})
	}

	for _, sameIntent := range []bool{false, true} {
		name := "distinct concurrent intents"
		if sameIntent {
			name = "duplicate concurrent intent"
		}
		t.Run(name, func(t *testing.T) {
			first := localRecoveryRequest(t, ctx, local, authority, fmt.Sprintf("parallel-recovery-%t-a", sameIntent), "Parallel-Recovered-Password-83!")
			second := first
			if !sameIntent {
				second.CommandID = fmt.Sprintf("parallel-recovery-%t-b", sameIntent)
				second, err = iamv1.SignLocalCredentialRecoveryRequest(authority, second)
				if err != nil {
					t.Fatal(err)
				}
			}
			prior := readLocalRecoveryState(t, ctx, database, authority.Scope)
			start := make(chan struct{})
			type outcome struct {
				result iamv1.LocalCredentialRecoveryResult
				err    error
			}
			outcomes := make(chan outcome, 2)
			for _, candidate := range []iamv1.LocalCredentialRecoveryRequest{first, second} {
				go func(r iamv1.LocalCredentialRecoveryRequest) {
					<-start
					result, err := local.RecoverLocalCredentials(ctx, authority, r)
					outcomes <- outcome{result, err}
				}(candidate)
			}
			close(start)
			applied, replayed, conflicts := 0, 0, 0
			for range 2 {
				outcome := <-outcomes
				switch {
				case errors.Is(outcome.err, identityaccess.ErrConflict):
					conflicts++
				case outcome.err != nil:
					t.Fatalf("parallel recovery: %v", outcome.err)
				case outcome.result.State == "APPLIED":
					applied++
				case outcome.result.State == "EQUAL_REPLAY":
					replayed++
				}
			}
			if applied != 1 || sameIntent && replayed != 1 || !sameIntent && conflicts != 1 {
				t.Fatalf("parallel outcomes applied=%d replayed=%d conflicts=%d", applied, replayed, conflicts)
			}
			next := readLocalRecoveryState(t, ctx, database, authority.Scope)
			if next.generation != prior.generation+1 || next.activeSessions != 0 || next.facts != prior.facts+1 || next.receipts != prior.receipts+1 || next.bindings != prior.bindings {
				t.Fatal("parallel recovery broke single-application invariants")
			}
			primary = localRecoveryChangePassword(t, handler, localRecoveryLogin(t, handler, "admin", "Parallel-Recovered-Password-83!", true), "Parallel-Recovered-Password-83!", changedAdminPassword)
		})
	}
	t.Run("password change races recovery", func(t *testing.T) {
		r := localRecoveryRequest(t, ctx, local, authority, "recovery-versus-password", "Racing-Recovered-Password-84!")
		prior := readLocalRecoveryState(t, ctx, database, authority.Scope)
		start := make(chan struct{})
		recoveryErr := make(chan error, 1)
		passwordStatus := make(chan int, 1)
		go func() { <-start; _, err := local.RecoverLocalCredentials(ctx, authority, r); recoveryErr <- err }()
		go func() {
			<-start
			response := performIAMRequest(handler, http.MethodPost, "/v1/auth/password", primary, []byte(`{"currentPassword":"`+changedAdminPassword+`","newPassword":"Racing-Daily-Password-85!","requestId":"daily-versus-recovery"}`))
			passwordStatus <- response.Code
		}()
		close(start)
		recoverErr, changeStatus := <-recoveryErr, <-passwordStatus
		next := readLocalRecoveryState(t, ctx, database, authority.Scope)
		if next.generation != prior.generation+1 {
			t.Fatal("concurrent change/recovery lost a credential generation")
		}
		if recoverErr == nil {
			if changeStatus == http.StatusOK || next.activeSessions != 0 {
				t.Fatal("old password change survived local recovery")
			}
			primary = localRecoveryChangePassword(t, handler, localRecoveryLogin(t, handler, "admin", "Racing-Recovered-Password-84!", true), "Racing-Recovered-Password-84!", changedAdminPassword)
		} else {
			if !errors.Is(recoverErr, identityaccess.ErrConflict) || changeStatus != http.StatusOK {
				t.Fatalf("change/recovery did not serialize: recovery=%v status=%d", recoverErr, changeStatus)
			}
			primary = localRecoveryChangePassword(t, handler, primary, "Racing-Daily-Password-85!", changedAdminPassword)
		}
	})
	t.Run("logout races recovery", func(t *testing.T) {
		r := localRecoveryRequest(t, ctx, local, authority, "recovery-versus-logout", "Logout-Recovered-Password-86!")
		start := make(chan struct{})
		recoverErr := make(chan error, 1)
		logout := make(chan int, 1)
		go func() { <-start; _, err := local.RecoverLocalCredentials(ctx, authority, r); recoverErr <- err }()
		go func() {
			<-start
			logout <- performIAMRequest(handler, http.MethodPost, "/v1/auth/logout", primary, []byte(`{"requestId":"logout-versus-recovery"}`)).Code
		}()
		close(start)
		if err := <-recoverErr; err != nil {
			t.Fatal(err)
		}
		code := <-logout
		if code != http.StatusOK && code != http.StatusUnauthorized {
			t.Fatalf("logout race status=%d", code)
		}
		if readLocalRecoveryState(t, ctx, database, authority.Scope).activeSessions != 0 {
			t.Fatal("logout/recovery retained a session")
		}
		primary = localRecoveryChangePassword(t, handler, localRecoveryLogin(t, handler, "admin", "Logout-Recovered-Password-86!", true), "Logout-Recovered-Password-86!", changedAdminPassword)
	})

	observer, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal("connect local recovery lock observer")
	}
	defer observer.Close(context.Background())
	for _, recoveryFirst := range []bool{true, false} {
		t.Run(fmt.Sprintf("revoke race recovery-first=%t", recoveryFirst), func(t *testing.T) {
			r := localRecoveryRequest(t, ctx, local, authority, fmt.Sprintf("recovery-versus-revoke-%t", recoveryFirst), "Revoked-Recovered-Password-87!")
			uncommitted := r
			uncommitted.CommandID = fmt.Sprintf("issued-before-terminal-revoke-%t", recoveryFirst)
			uncommitted, err = iamv1.SignLocalCredentialRecoveryRequest(authority, uncommitted)
			if err != nil {
				t.Fatal(err)
			}
			prior := readLocalRecoveryState(t, ctx, database, authority.Scope)
			// Hold only a fixture row lock, never write credentials or bindings.
			// Recovery-first has already locked the binding when it waits for the
			// organization. Revoke-first queues on the binding before recovery.
			// Both paths still execute the real transactions and HTTP authority.
			blocker, err := database.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer blocker.Rollback(context.Background())
			lockQuery := "SELECT id FROM iam.role_bindings WHERE tenant_id=$1 AND id=$2 FOR UPDATE"
			lockTarget := string(r.Expected.PlatformBindingID)
			if recoveryFirst {
				lockQuery = "SELECT id FROM iam.organizations WHERE id=$1 AND $2::text IS NOT NULL FOR UPDATE"
				lockTarget = string(authority.Scope.OrganizationID)
			}
			if _, err := blocker.Exec(ctx, lockQuery, authority.Scope.OrganizationID, lockTarget); err != nil {
				t.Fatal(err)
			}
			recoverErr := make(chan error, 1)
			revocation := make(chan int, 1)
			recover := func() { _, err := local.RecoverLocalCredentials(ctx, authority, r); recoverErr <- err }
			revoke := func() {
				revocation <- performIAMRequest(handler, http.MethodPost, "/v1/role-bindings/"+string(r.Expected.PlatformBindingID)+":revoke", operatorSession, []byte(fmt.Sprintf(`{"requestId":"revoke-versus-recovery-%t"}`, recoveryFirst))).Code
			}
			if recoveryFirst {
				go recover()
				waitForLocalRecoveryLock(t, ctx, observer, localRecoveryTestRole)
				go revoke()
				waitForLocalRecoveryLock(t, ctx, observer, iamHTTPTestRole)
			} else {
				go revoke()
				waitForLocalRecoveryLock(t, ctx, observer, iamHTTPTestRole)
				go recover()
				waitForLocalRecoveryLock(t, ctx, observer, localRecoveryTestRole)
			}
			if err := blocker.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
			recoveryOutcome, revokeStatus := <-recoverErr, <-revocation
			if revokeStatus != http.StatusOK {
				t.Fatalf("platform revocation race status=%d", revokeStatus)
			}
			next := readLocalRecoveryState(t, ctx, database, authority.Scope)
			if recoveryFirst {
				if recoveryOutcome != nil || next.generation != prior.generation+1 || next.facts != prior.facts+1 || next.activeSessions != 0 {
					t.Fatal("recovery-first outcome is not atomic")
				}
			} else if !errors.Is(recoveryOutcome, identityaccess.ErrForbidden) || next.generation != prior.generation || next.facts != prior.facts {
				t.Fatalf("revoke-first outcome changed credentials: %v", recoveryOutcome)
			}
			if _, err := local.InspectLocalCredentialRecovery(ctx, authority, nil); !errors.Is(err, identityaccess.ErrForbidden) {
				t.Fatalf("revoked platform authority remained eligible: %v", err)
			}
			if _, err := local.RecoverLocalCredentials(ctx, authority, uncommitted); !errors.Is(err, identityaccess.ErrForbidden) {
				t.Fatalf("uncommitted intent repaired terminal revoked authority: %v", err)
			}
			assertLocalRecoveryReplay(t, ctx, local, authority, request, result)
			if next != readLocalRecoveryState(t, ctx, database, authority.Scope) {
				t.Fatal("old completed recovery changed revoked state")
			}
			if _, err := api.Bootstrap(ctx, document); err != nil {
				t.Fatal(err)
			}
			applyIAMSchema(t, ctx, database)
			applyIAMSchema(t, ctx, database)
			if next != readLocalRecoveryState(t, ctx, database, authority.Scope) {
				t.Fatal("bootstrap/schema replay revived credentials or platform authority")
			}
			assertLocalRecoveryReplay(t, ctx, local, authority, request, result)
			if recoveryFirst {
				// Reset the next race only through normal forced password change and
				// explicit grant by the separate still-authorized platform operator.
				primary = localRecoveryChangePassword(t, handler, localRecoveryLogin(t, handler, "admin", "Revoked-Recovered-Password-87!", true), "Revoked-Recovered-Password-87!", changedAdminPassword)
				body, _ := json.Marshal(iamv1.PutRoleBindingRequest{PrincipalID: authority.Scope.PrincipalID, Role: iamv1.RolePlatformOperator, RequestID: "explicit-regrant-for-next-recovery-race"})
				if response := performIAMRequest(handler, http.MethodPost, "/v1/role-bindings", operatorSession, body); response.Code != http.StatusOK {
					t.Fatal("explicit authorized platform grant failed")
				}
			}
		})
	}
	assertIAMSecretsAbsent(t, ctx, database, "Recovered-Primary-Password-43!", string(capabilityKey.CopyBytes()), string(request.Capability.CopyBytes()))
	var leaked bool
	if err := database.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM iam.local_credential_recoveries WHERE completed_result::text LIKE '%$matrix-iam-v1$%' OR completed_result::text LIKE '%'||$1||'%')`, string(request.Capability.CopyBytes())).Scan(&leaked); err != nil || leaked {
		t.Fatal("local receipt leaked private recovery material")
	}
}

func waitForLocalRecoveryLock(t *testing.T, ctx context.Context, observer *pgx.Conn, user string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var blocked bool
		if err := observer.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity
            WHERE datname=current_database() AND usename=$1 AND state='active'
              AND wait_event_type='Lock' AND cardinality(pg_blocking_pids(pid))>0)`, user).Scan(&blocked); err != nil {
			t.Fatal("observe bounded local recovery lock")
		}
		if blocked {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("local recovery transaction did not reach the expected database lock")
		case <-ticker.C:
		}
	}
}

func assertLocalRecoveryClosedSQLFact(t *testing.T, ctx context.Context, database *pgx.Conn, local iamv1.LocalCredentialRecoveryAuthority, request iamv1.LocalCredentialRecoveryRequest, passwordHash string) {
	t.Helper()
	scope, _ := json.Marshal(request.Scope)
	expected, _ := json.Marshal(request.Expected)
	commitment, err := iamv1.VerifyLocalCredentialRecoveryRequest(local, request)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*auditv1.Event){
		"actor":           func(e *auditv1.Event) { e.Actor.Type = auditv1.ActorUser },
		"system id":       func(e *auditv1.Event) { e.Actor.ID = "installation-verifier" },
		"action":          func(e *auditv1.Event) { e.Action = auditv1.ActionIAMTenantAdministratorRecovered },
		"namespace":       func(e *auditv1.Event) { e.Target.TenantID = "another-tenant" },
		"principal":       func(e *auditv1.Event) { e.Target.ID = "service-iam" },
		"installation":    func(e *auditv1.Event) { e.InstallationID = "another-installation" },
		"decision":        func(e *auditv1.Event) { e.IAMDecisionID = "fabricated-decision" },
		"operation":       func(e *auditv1.Event) { e.OperationID = "fabricated-operation" },
		"request":         func(e *auditv1.Event) { e.RequestID = "another-command" },
		"missing binding": nil,
	} {
		t.Run("database fact "+name, func(t *testing.T) {
			tx, err := database.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if mutate == nil {
				if _, err := tx.Exec(ctx, "DELETE FROM iam.role_bindings WHERE tenant_id=$1 AND id=$2", request.Scope.OrganizationID, request.Expected.PlatformBindingID); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := tx.Exec(ctx, "SET LOCAL ROLE matrix_iam_credential_recovery"); err != nil {
				t.Fatal(err)
			}
			var now time.Time
			if err := tx.QueryRow(ctx, "SELECT transaction_timestamp()").Scan(&now); err != nil {
				t.Fatal(err)
			}
			event := auditv1.Event{APIVersion: auditv1.APIVersion, Kind: "AuditEvent", EventID: "event-local-recovery-attack",
				InstallationID: request.Scope.InstallationID, Actor: auditv1.ActorReference{Type: auditv1.ActorSystem, ID: iamv1.LocalCredentialRecoveryActor},
				Action: auditv1.ActionIAMInstallationPrimaryCredentialsRecovered, Target: auditv1.TargetReference{Kind: auditv1.TargetPrincipal, ID: string(request.Scope.PrincipalID), TenantID: auditv1.TenantID(request.Scope.OrganizationID)},
				Result: auditv1.ResultSucceeded, RequestDigest: "sha256:" + strings.Repeat("d", 64), RequestID: request.CommandID, CorrelationID: request.CommandID, OccurredAt: now.UTC()}
			if mutate != nil {
				mutate(&event)
			}
			encoded, _ := json.Marshal(event)
			_, attackErr := tx.Exec(ctx, "SELECT iam.recover_local_credentials($1::jsonb,$2::jsonb,$3,$4,$5,$6::jsonb)", string(scope), string(expected), request.CommandID, commitment, passwordHash, string(encoded))
			_ = tx.Rollback(ctx)
			var pgErr *pgconn.PgError
			if !errors.As(attackErr, &pgErr) {
				t.Fatal("local SQL recovery did not reject an unauthorized security fact")
			}
			if pgErr.Code != "22023" && pgErr.Code != "42501" {
				t.Fatalf("local SQL rejection did not exercise the security boundary: code=%s", pgErr.Code)
			}
		})
	}
}

func localRecoveryWorkflow(t *testing.T, ctx context.Context, dsn, user string) *identityaccess.Authority {
	t.Helper()
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.User, config.ConnConfig.Password = user, iamHTTPTestPassword
	config.MaxConns = 2
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := pool.Ping(ctx); err != nil {
		t.Fatal("purpose-specific IAM test login failed")
	}
	repository, err := iampostgres.NewRepository(pool)
	if err != nil {
		t.Fatal(err)
	}
	workflow, err := identityaccess.NewAuthority(repository, identityaccess.Config{})
	if err != nil {
		t.Fatal(err)
	}
	return workflow
}

func localRecoveryRequest(t *testing.T, ctx context.Context, workflow *identityaccess.Authority, authority iamv1.LocalCredentialRecoveryAuthority, command, password string) iamv1.LocalCredentialRecoveryRequest {
	t.Helper()
	inspection, err := workflow.InspectLocalCredentialRecovery(ctx, authority, nil)
	if err != nil || inspection.Expected == nil {
		t.Fatalf("inspect local recovery: %v", err)
	}
	request, err := iamv1.SignLocalCredentialRecoveryRequest(authority, iamv1.LocalCredentialRecoveryRequest{APIVersion: iamv1.APIVersion, Kind: "LocalCredentialRecoveryRequest", Purpose: iamv1.LocalCredentialRecoveryPurpose,
		CommandID: command, Scope: authority.Scope, Expected: *inspection.Expected, NewPassword: iamHTTPSecret(t, password)})
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func localRecoveryLogin(t *testing.T, handler http.Handler, login, password string, forced bool) string {
	t.Helper()
	encoded, _ := json.Marshal(map[string]string{"loginName": login, "password": password, "requestId": "local-recovery-login"})
	response := performIAMRequest(handler, http.MethodPost, "/v1/auth/login", "", encoded)
	var result struct {
		Credential         string `json:"credential"`
		MustChangePassword bool   `json:"mustChangePassword"`
	}
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &result) != nil || result.Credential == "" || result.MustChangePassword != forced {
		t.Fatalf("local recovery login status=%d forced=%t", response.Code, result.MustChangePassword)
	}
	return result.Credential
}

func localRecoveryChangePassword(t *testing.T, handler http.Handler, bearer, previous, next string) string {
	t.Helper()
	encoded, _ := json.Marshal(map[string]string{"currentPassword": previous, "newPassword": next, "requestId": "local-recovery-password-change"})
	response := performIAMRequest(handler, http.MethodPost, "/v1/auth/password", bearer, encoded)
	if response.Code != http.StatusOK {
		t.Fatalf("local recovery password replacement status=%d", response.Code)
	}
	return bearer
}

type localRecoveryState struct {
	generation, organizationVersion, principalVersion, activeSessions, facts, receipts uint64
	passwordHash, bindings, sessions, services, organizationStatus, principalStatus    string
	mustChange, owner                                                                  bool
}

func readLocalRecoveryState(t *testing.T, ctx context.Context, database *pgx.Conn, scope iamv1.LocalCredentialRecoveryScope) localRecoveryState {
	t.Helper()
	var result localRecoveryState
	err := database.QueryRow(ctx, `SELECT c.credential_version,c.password_hash,p.resource_version,p.must_change_password,p.status,o.status,o.resource_version,
        (SELECT account_owner FROM iam.login_index l WHERE l.tenant_id=p.tenant_id AND l.principal_id=p.id),
        (SELECT jsonb_agg(jsonb_build_array(principal_id,purpose,lookup_digest,verification_digest,revoked_at) ORDER BY principal_id)::text FROM iam.service_credentials sc WHERE sc.tenant_id=p.tenant_id),
        (SELECT count(*) FROM iam.sessions s WHERE s.tenant_id=p.tenant_id AND s.principal_id=p.id AND s.status='ACTIVE'),
        (SELECT COALESCE(jsonb_agg(jsonb_build_array(id,status,resource_version,credential_version,revoked_at) ORDER BY id),'[]'::jsonb)::text FROM iam.sessions s WHERE s.tenant_id=p.tenant_id AND s.principal_id=p.id),
        (SELECT COALESCE(jsonb_agg(jsonb_build_array(id,role_name,resource_version,revoked_at) ORDER BY id),'[]'::jsonb)::text FROM iam.role_bindings b WHERE b.tenant_id=p.tenant_id AND b.principal_id=p.id),
        (SELECT count(*) FROM iam.audit_outbox WHERE event_document->>'action'=$3),
        (SELECT count(*) FROM iam.local_credential_recoveries)
        FROM iam.principals p JOIN iam.user_credentials c ON c.tenant_id=p.tenant_id AND c.principal_id=p.id
        JOIN iam.organizations o ON o.id=p.tenant_id WHERE p.tenant_id=$1 AND p.id=$2`, scope.OrganizationID, scope.PrincipalID, auditv1.ActionIAMInstallationPrimaryCredentialsRecovered).
		Scan(&result.generation, &result.passwordHash, &result.principalVersion, &result.mustChange, &result.principalStatus, &result.organizationStatus, &result.organizationVersion, &result.owner, &result.services,
			&result.activeSessions, &result.sessions, &result.bindings, &result.facts, &result.receipts)
	if err != nil {
		t.Fatal("read local recovery security invariants")
	}
	return result
}

func assertLocalRecoveryDatabaseBoundary(t *testing.T, ctx context.Context, database *pgx.Conn, adminConfig *pgx.ConnConfig) {
	t.Helper()
	for _, user := range []string{localRecoveryTestRole, iamHTTPTestRole, iamHTTPWorkerRole} {
		config := adminConfig.Copy()
		config.User, config.Password = user, iamHTTPTestPassword
		connection, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal("connect restricted recovery boundary probe")
		}
		var sessionUser, currentUser string
		if err := connection.QueryRow(ctx, "SELECT session_user,current_user").Scan(&sessionUser, &currentUser); err != nil || sessionUser != user || currentUser != user {
			t.Fatal("recovery boundary probe used another login")
		}
		attacks := []string{"SELECT * FROM iam.local_credential_recoveries", "SELECT * FROM iam.user_credentials", "UPDATE iam.principals SET must_change_password=false", "SET ROLE matrix_iam_owner", "SET ROLE matrix_iam_migrator"}
		if user == localRecoveryTestRole {
			attacks = append(attacks, "SET ROLE matrix_iam_api", "SET ROLE matrix_iam_worker", "SELECT * FROM iam.lookup_login('admin')", "SELECT * FROM iam.bootstrap_status()", "SELECT * FROM iam.claim_audit_event('recovery-attacker',30)")
		}
		for _, attack := range attacks {
			_, err := connection.Exec(ctx, attack)
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
				t.Fatalf("purpose-specific login %s crossed database boundary", user)
			}
		}
		_ = connection.Close(ctx)
	}
	for _, damage := range []string{
		"ALTER FUNCTION iam.inspect_local_credential_recovery(jsonb,text,text) SECURITY INVOKER",
		"ALTER FUNCTION iam.recover_local_credentials(jsonb,jsonb,text,text,text,jsonb) SECURITY INVOKER",
		"ALTER TABLE iam.local_credential_recoveries NO FORCE ROW LEVEL SECURITY",
		"ALTER TABLE iam.local_credential_recoveries DISABLE TRIGGER local_recovery_receipts_are_immutable",
	} {
		tx, err := database.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, damage); err != nil {
			t.Fatal(err)
		}
		var ready bool
		if err := tx.QueryRow(ctx, "SELECT ready FROM iam.readiness()").Scan(&ready); err != nil || ready {
			t.Fatal("incompatible recovery function/protection remained READY")
		}
		if err := iammigration.Verify(ctx, tx); err == nil {
			t.Fatal("incompatible recovery function/protection passed migration verification")
		}
		_ = tx.Rollback(ctx)
	}
	for _, damage := range []string{
		"GRANT pg_read_all_data TO matrix_iam_credential_recovery",
		"GRANT matrix_iam_credential_recovery TO matrix_iam_api",
	} {
		tx, err := database.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, damage); err != nil {
			t.Fatal(err)
		}
		if err := iammigration.Verify(ctx, tx); err == nil {
			t.Fatal("shared or overprivileged recovery authority passed migration verification")
		}
		_ = tx.Rollback(ctx)
	}
	if err := iammigration.Verify(ctx, database); err != nil {
		t.Fatal("read-only attacks damaged restored recovery schema")
	}
}

func assertLocalRecoveryReplay(t *testing.T, ctx context.Context, workflow *identityaccess.Authority, authority iamv1.LocalCredentialRecoveryAuthority, request iamv1.LocalCredentialRecoveryRequest, original iamv1.LocalCredentialRecoveryResult) {
	t.Helper()
	result, err := workflow.RecoverLocalCredentials(ctx, authority, request)
	if err != nil || result.State != "EQUAL_REPLAY" {
		t.Fatalf("equal local recovery replay: %v", err)
	}
	result.State = "APPLIED"
	if result != original {
		t.Fatal("local recovery replay changed historical completion")
	}
	query := &iamv1.LocalCredentialRecoveryReceiptQuery{APIVersion: iamv1.APIVersion, Kind: "LocalCredentialRecoveryReceiptQuery", CommandID: request.CommandID, InputCommitment: original.InputCommitment}
	inspection, err := workflow.InspectLocalCredentialRecovery(ctx, authority, query)
	if err != nil || inspection.State != "COMPLETED" || inspection.Expected == nil || *inspection.Expected != request.Expected || inspection.Result == nil || *inspection.Result != original {
		t.Fatalf("read original completion without current eligibility: %v", err)
	}
	query.CommandID = "not-yet-committed-command"
	inspection, err = workflow.InspectLocalCredentialRecovery(ctx, authority, query)
	if err != nil || inspection.State != "NOT_FOUND" || inspection.Expected != nil || inspection.Result != nil {
		t.Fatalf("missing receipt granted fresh expected state: %v", err)
	}
}
