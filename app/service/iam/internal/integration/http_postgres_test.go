package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
	iampostgres "github.com/xiak/matrix/app/service/iam/internal/data/postgres"
	iamhttp "github.com/xiak/matrix/app/service/iam/internal/service/nethttp"
	"github.com/xiak/matrix/app/service/iam/internal/usecase/identityaccess"
	iammigration "github.com/xiak/matrix/app/service/iam/migration"
)

const (
	iamHTTPPostgresDSN       = "MATRIX_IAM_HTTP_POSTGRES_TEST_DSN"
	iamHTTPTestRole          = "matrix_iam_http_test_api"
	iamHTTPTestPassword      = "matrix-iam-http-test-only"
	adminPassword            = "Initial-Admin-Password-49!"
	changedAdminPassword     = "Changed-Admin-Password-73!"
	initialDeveloperPassword = "Initial-Developer-Password-84!"
	changedDeveloperPassword = "Changed-Developer-Password-95!"
	paasCredential           = "mx1.PaaSHTTPIntegrationCredential000000000000001"
	auditCredential          = "mx1.AuditHTTPIntegrationCredential00000000000001"
	verifierCredential       = "mx1.VerifierHTTPIntegrationCredential0000000001"
)

func TestIAMHTTPPostgresVerticalSlice(t *testing.T) {
	dsn := os.Getenv(iamHTTPPostgresDSN)
	if dsn == "" {
		t.Skipf("set %s to a clean disposable PostgreSQL 18 database", iamHTTPPostgresDSN)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	adminConfig, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse IAM HTTP PostgreSQL DSN: %v", err)
	}
	if !strings.HasPrefix(adminConfig.Database, "matrix_iam_") {
		t.Fatalf("refusing IAM HTTP database %q without matrix_iam_ prefix", adminConfig.Database)
	}
	adminConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	admin, err := pgx.ConnectConfig(ctx, adminConfig)
	if err != nil {
		t.Fatalf("connect IAM HTTP PostgreSQL: %v", err)
	}
	defer func() { _ = admin.Close(context.Background()) }()
	assertIAMPostgres18(t, ctx, admin)
	assertCleanIAMSchema(t, ctx, admin)
	applyIAMSchema(t, ctx, admin)
	createIAMHTTPRole(t, ctx, admin)

	poolConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse IAM HTTP pool DSN: %v", err)
	}
	poolConfig.ConnConfig.User = iamHTTPTestRole
	poolConfig.ConnConfig.Password = iamHTTPTestPassword
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		t.Fatalf("open IAM HTTP runtime pool: %v", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("ping IAM HTTP runtime pool: %v", err)
	}
	repository, err := iampostgres.NewRepository(pool)
	if err != nil {
		t.Fatalf("create IAM PostgreSQL repository: %v", err)
	}
	sequence := 0
	workflow, err := identityaccess.NewAuthority(repository, identityaccess.Config{
		SessionLifetime: time.Hour,
		NewID: func(prefix string) (string, error) {
			sequence++
			return fmt.Sprintf("%s-http-%d", prefix, sequence), nil
		},
	})
	if err != nil {
		t.Fatalf("create IAM HTTP workflow: %v", err)
	}
	document := iamHTTPBootstrap(t)
	status, err := workflow.Bootstrap(ctx, document)
	if err != nil || status.State != iamv1.BootstrapReady {
		t.Fatalf("bootstrap IAM HTTP authority: status=%#v err=%v", status, err)
	}
	replayed, err := workflow.Bootstrap(ctx, document)
	if err != nil || replayed.ContentDigest != status.ContentDigest || replayed.AppliedAt == nil ||
		status.AppliedAt == nil || *replayed.AppliedAt != *status.AppliedAt {
		t.Fatalf("replay IAM HTTP bootstrap: status=%#v err=%v", replayed, err)
	}
	handler, err := iamhttp.NewHandler(workflow, iamhttp.Config{
		NewRequestID: func() (string, error) { return "request-http-integration", nil },
	})
	if err != nil {
		t.Fatalf("create IAM HTTP handler: %v", err)
	}

	ready := performIAMRequest(handler, http.MethodGet, "/ready", "", nil)
	if ready.Code != http.StatusOK {
		t.Fatalf("IAM readiness status=%d body=%s", ready.Code, ready.Body.String())
	}
	identity := performIAMRequest(handler, http.MethodGet, "/v1/service-identity", paasCredential, nil)
	if identity.Code != http.StatusOK {
		t.Fatalf("IAM service identity status=%d body=%s", identity.Code, identity.Body.String())
	}
	var serviceIdentity iamv1.ServiceIdentity
	if err := json.Unmarshal(identity.Body.Bytes(), &serviceIdentity); err != nil ||
		serviceIdentity.Purpose != iamv1.ServicePaaS || serviceIdentity.PrincipalID != "service-paas" {
		t.Fatalf("IAM service identity=%#v err=%v", serviceIdentity, err)
	}
	verificationBody := []byte(`{"action":"installation.verify","resource":{"kind":"INSTALLATION","id":"installation-http-integration"},"requestId":"request-installation-verify","correlationId":"correlation-installation-verify"}`)
	verification := performIAMRequest(
		handler, http.MethodPost, "/v1/installation:verify", verifierCredential, verificationBody,
	)
	var verificationDecision iamv1.AuthorizationDecision
	if verification.Code != http.StatusOK ||
		json.Unmarshal(verification.Body.Bytes(), &verificationDecision) != nil ||
		!verificationDecision.Allowed || verificationDecision.Subject == nil ||
		verificationDecision.Subject.Type != iamv1.PrincipalServiceAccount ||
		verificationDecision.Subject.ID != "service-verifier" {
		t.Fatalf(
			"IAM installation verification status=%d decision=%#v body=%s",
			verification.Code, verificationDecision, verification.Body.String(),
		)
	}
	verificationBody = []byte(`{"action":"installation.verify","resource":{"kind":"INSTALLATION","id":"installation-other"},"requestId":"request-installation-other","correlationId":"correlation-installation-other"}`)
	verification = performIAMRequest(
		handler, http.MethodPost, "/v1/installation:verify", verifierCredential, verificationBody,
	)
	if verification.Code != http.StatusOK ||
		json.Unmarshal(verification.Body.Bytes(), &verificationDecision) != nil ||
		verificationDecision.Allowed {
		t.Fatalf(
			"IAM cross-installation verification status=%d decision=%#v body=%s",
			verification.Code, verificationDecision, verification.Body.String(),
		)
	}

	loginBody := []byte(`{"loginName":"admin","password":"` + adminPassword + `","requestId":"request-login"}`)
	login := performIAMRequest(handler, http.MethodPost, "/v1/auth/login", "", loginBody)
	if login.Code != http.StatusOK {
		t.Fatalf("IAM login status=%d body=%s", login.Code, login.Body.String())
	}
	var loginWire struct {
		Credential string `json:"credential"`
	}
	if err := json.Unmarshal(login.Body.Bytes(), &loginWire); err != nil || loginWire.Credential == "" {
		t.Fatalf("decode IAM login credential: value=%q err=%v", loginWire.Credential, err)
	}
	var loginResult iamv1.LoginResponse
	if err := iamv1.DecodeRequest(bytes.NewReader(login.Body.Bytes()), &loginResult); err != nil {
		t.Fatalf("decode IAM login response contract: %v", err)
	}
	authorizeBody := []byte(`{"action":"paas.application.create","resource":{"kind":"APPLICATION","id":"application-example"},"requestId":"request-authorize","correlationId":"correlation-authorize"}`)
	authorize := performIAMRequestWithSubject(handler, authorizeBody, paasCredential, loginWire.Credential)
	if authorize.Code != http.StatusOK {
		t.Fatalf("IAM authorize status=%d body=%s", authorize.Code, authorize.Body.String())
	}
	var decision iamv1.AuthorizationDecision
	if err := json.Unmarshal(authorize.Body.Bytes(), &decision); err != nil || decision.Allowed {
		t.Fatalf("initial administrator decision=%#v err=%v, want audited deny", decision, err)
	}
	password := performIAMRequest(
		handler,
		http.MethodPost,
		"/v1/auth/password",
		loginWire.Credential,
		[]byte(`{"currentPassword":"`+adminPassword+`","newPassword":"`+changedAdminPassword+`","requestId":"request-admin-password"}`),
	)
	if password.Code != http.StatusOK {
		t.Fatalf("IAM administrator password status=%d body=%s", password.Code, password.Body.String())
	}
	var passwordResult iamv1.ChangePasswordResponse
	if err := json.Unmarshal(password.Body.Bytes(), &passwordResult); err != nil ||
		!passwordResult.BootstrapFileRetirable {
		t.Fatalf("IAM administrator password response=%#v err=%v", passwordResult, err)
	}
	oldPasswordLogin := performIAMRequest(handler, http.MethodPost, "/v1/auth/login", "", loginBody)
	if oldPasswordLogin.Code != http.StatusUnauthorized {
		t.Fatalf("IAM replaced password login status=%d body=%s", oldPasswordLogin.Code, oldPasswordLogin.Body.String())
	}
	weakPassword := performIAMRequest(
		handler,
		http.MethodPost,
		"/v1/auth/password",
		loginWire.Credential,
		[]byte(`{"currentPassword":"`+changedAdminPassword+`","newPassword":"weak","requestId":"request-weak-password"}`),
	)
	if weakPassword.Code != http.StatusUnprocessableEntity ||
		bytes.Contains(weakPassword.Body.Bytes(), []byte("weak")) {
		t.Fatalf("IAM weak password status=%d body=%s", weakPassword.Code, weakPassword.Body.String())
	}
	authorizeBody = []byte(`{"action":"paas.application.create","resource":{"kind":"APPLICATION","id":"application-example"},"requestId":"request-authorize-allowed","correlationId":"correlation-authorize-allowed"}`)
	authorize = performIAMRequestWithSubject(handler, authorizeBody, paasCredential, loginWire.Credential)
	if authorize.Code != http.StatusOK {
		t.Fatalf("IAM allowed authorize status=%d body=%s", authorize.Code, authorize.Body.String())
	}
	if err := json.Unmarshal(authorize.Body.Bytes(), &decision); err != nil || !decision.Allowed ||
		decision.TenantID != "organization-http-integration" {
		t.Fatalf("administrator allowed decision=%#v err=%v", decision, err)
	}
	insertCrossTenantPrincipal(t, ctx, admin)
	crossTenantBinding := performIAMRequest(
		handler,
		http.MethodPost,
		"/v1/role-bindings",
		loginWire.Credential,
		[]byte(`{"principalId":"principal-cross-tenant","role":"PAAS_DEVELOPER","requestId":"request-cross-tenant-binding"}`),
	)
	if crossTenantBinding.Code != http.StatusForbidden ||
		bytes.Contains(crossTenantBinding.Body.Bytes(), []byte("role binding principal")) {
		t.Fatalf("IAM cross-tenant binding status=%d body=%s", crossTenantBinding.Code, crossTenantBinding.Body.String())
	}

	createUser := performIAMRequest(
		handler,
		http.MethodPost,
		"/v1/principals",
		loginWire.Credential,
		[]byte(`{"loginName":"developer","displayName":"Platform Developer","initialPassword":"`+initialDeveloperPassword+`","requestId":"request-create-developer"}`),
	)
	if createUser.Code != http.StatusCreated {
		t.Fatalf("IAM create user status=%d body=%s", createUser.Code, createUser.Body.String())
	}
	var developer iamv1.Principal
	if err := json.Unmarshal(createUser.Body.Bytes(), &developer); err != nil ||
		developer.LoginName != "developer" || !developer.MustChangePassword {
		t.Fatalf("IAM created user=%#v err=%v", developer, err)
	}
	putBindingBody, err := json.Marshal(iamv1.PutRoleBindingRequest{
		PrincipalID: developer.ID,
		Role:        iamv1.RolePaaSDeveloper,
		RequestID:   "request-bind-developer",
	})
	if err != nil {
		t.Fatalf("encode IAM role binding request: %v", err)
	}
	putBinding := performIAMRequest(
		handler, http.MethodPost, "/v1/role-bindings", loginWire.Credential, putBindingBody,
	)
	if putBinding.Code != http.StatusOK {
		t.Fatalf("IAM put binding status=%d body=%s", putBinding.Code, putBinding.Body.String())
	}
	var binding iamv1.RoleBinding
	if err := json.Unmarshal(putBinding.Body.Bytes(), &binding); err != nil ||
		binding.PrincipalID != developer.ID || binding.Role != iamv1.RolePaaSDeveloper {
		t.Fatalf("IAM role binding=%#v err=%v", binding, err)
	}

	developerLogin := performIAMRequest(
		handler,
		http.MethodPost,
		"/v1/auth/login",
		"",
		[]byte(`{"loginName":"developer","password":"`+initialDeveloperPassword+`","requestId":"request-login-developer"}`),
	)
	if developerLogin.Code != http.StatusOK {
		t.Fatalf("IAM developer login status=%d body=%s", developerLogin.Code, developerLogin.Body.String())
	}
	var developerWire struct {
		Session    iamv1.Session `json:"session"`
		Credential string        `json:"credential"`
	}
	if err := json.Unmarshal(developerLogin.Body.Bytes(), &developerWire); err != nil ||
		developerWire.Credential == "" {
		t.Fatalf("decode IAM developer login=%#v err=%v", developerWire.Session, err)
	}
	developerAuthorizeBody := []byte(`{"action":"paas.application.create","resource":{"kind":"APPLICATION","id":"application-developer"},"requestId":"request-developer-before-password","correlationId":"correlation-developer-before-password"}`)
	developerAuthorize := performIAMRequestWithSubject(
		handler, developerAuthorizeBody, paasCredential, developerWire.Credential,
	)
	if developerAuthorize.Code != http.StatusOK {
		t.Fatalf("IAM initial developer authorize status=%d body=%s", developerAuthorize.Code, developerAuthorize.Body.String())
	}
	if err := json.Unmarshal(developerAuthorize.Body.Bytes(), &decision); err != nil || decision.Allowed {
		t.Fatalf("initial developer decision=%#v err=%v, want deny", decision, err)
	}
	developerPassword := performIAMRequest(
		handler,
		http.MethodPost,
		"/v1/auth/password",
		developerWire.Credential,
		[]byte(`{"currentPassword":"`+initialDeveloperPassword+`","newPassword":"`+changedDeveloperPassword+`","requestId":"request-developer-password"}`),
	)
	if developerPassword.Code != http.StatusOK {
		t.Fatalf("IAM developer password status=%d body=%s", developerPassword.Code, developerPassword.Body.String())
	}
	if err := json.Unmarshal(developerPassword.Body.Bytes(), &passwordResult); err != nil ||
		passwordResult.BootstrapFileRetirable {
		t.Fatalf("IAM developer password response=%#v err=%v", passwordResult, err)
	}
	deniedUser := performIAMRequest(
		handler,
		http.MethodPost,
		"/v1/principals",
		developerWire.Credential,
		[]byte(`{"loginName":"denied.user","displayName":"Denied User","initialPassword":"Denied-User-Password-68!","requestId":"request-denied-user"}`),
	)
	if deniedUser.Code != http.StatusForbidden ||
		bytes.Contains(deniedUser.Body.Bytes(), []byte("Denied-User-Password")) {
		t.Fatalf("IAM denied role action status=%d body=%s", deniedUser.Code, deniedUser.Body.String())
	}
	developerAuthorizeBody = []byte(`{"action":"paas.application.create","resource":{"kind":"APPLICATION","id":"application-developer"},"requestId":"request-developer-allowed","correlationId":"correlation-developer-allowed"}`)
	developerAuthorize = performIAMRequestWithSubject(
		handler, developerAuthorizeBody, paasCredential, developerWire.Credential,
	)
	if developerAuthorize.Code != http.StatusOK {
		t.Fatalf("IAM developer authorize status=%d body=%s", developerAuthorize.Code, developerAuthorize.Body.String())
	}
	if err := json.Unmarshal(developerAuthorize.Body.Bytes(), &decision); err != nil ||
		!decision.Allowed || decision.Subject == nil || decision.Subject.ID != developer.ID {
		t.Fatalf("developer allowed decision=%#v err=%v", decision, err)
	}

	revokeBinding := performIAMRequest(
		handler,
		http.MethodPost,
		"/v1/role-bindings/"+string(binding.ID)+":revoke",
		loginWire.Credential,
		[]byte(`{"requestId":"request-revoke-developer-binding"}`),
	)
	if revokeBinding.Code != http.StatusOK {
		t.Fatalf("IAM revoke binding status=%d body=%s", revokeBinding.Code, revokeBinding.Body.String())
	}
	developerAuthorizeBody = []byte(`{"action":"paas.application.create","resource":{"kind":"APPLICATION","id":"application-developer"},"requestId":"request-developer-after-binding","correlationId":"correlation-developer-after-binding"}`)
	developerAuthorize = performIAMRequestWithSubject(
		handler, developerAuthorizeBody, paasCredential, developerWire.Credential,
	)
	if developerAuthorize.Code != http.StatusOK {
		t.Fatalf("IAM post-revocation authorize status=%d body=%s", developerAuthorize.Code, developerAuthorize.Body.String())
	}
	if err := json.Unmarshal(developerAuthorize.Body.Bytes(), &decision); err != nil || decision.Allowed {
		t.Fatalf("role-revoked decision=%#v err=%v, want deny", decision, err)
	}
	revokeSession := performIAMRequest(
		handler,
		http.MethodPost,
		"/v1/sessions/"+string(developerWire.Session.ID)+":revoke",
		loginWire.Credential,
		[]byte(`{"requestId":"request-revoke-developer-session"}`),
	)
	if revokeSession.Code != http.StatusOK {
		t.Fatalf("IAM revoke session status=%d body=%s", revokeSession.Code, revokeSession.Body.String())
	}
	developerAuthorize = performIAMRequestWithSubject(
		handler, developerAuthorizeBody, paasCredential, developerWire.Credential,
	)
	if developerAuthorize.Code != http.StatusUnauthorized {
		t.Fatalf("IAM revoked session authorize status=%d body=%s", developerAuthorize.Code, developerAuthorize.Body.String())
	}
	verifierRevocation := performIAMRequest(
		handler,
		http.MethodPost,
		"/v1/role-bindings/bootstrap-verifier-binding:revoke",
		loginWire.Credential,
		[]byte(`{"requestId":"request-revoke-verifier-binding"}`),
	)
	if verifierRevocation.Code != http.StatusOK {
		t.Fatalf(
			"IAM verifier role revocation status=%d body=%s",
			verifierRevocation.Code, verifierRevocation.Body.String(),
		)
	}
	verificationBody = []byte(`{"action":"installation.verify","resource":{"kind":"INSTALLATION","id":"installation-http-integration"},"requestId":"request-installation-revoked","correlationId":"correlation-installation-revoked"}`)
	verification = performIAMRequest(
		handler, http.MethodPost, "/v1/installation:verify", verifierCredential, verificationBody,
	)
	if verification.Code != http.StatusOK ||
		json.Unmarshal(verification.Body.Bytes(), &verificationDecision) != nil ||
		verificationDecision.Allowed {
		t.Fatalf(
			"IAM revoked verifier status=%d decision=%#v body=%s",
			verification.Code, verificationDecision, verification.Body.String(),
		)
	}
	wrongService := performIAMRequestWithSubject(handler, authorizeBody, "wrong-service-credential", loginWire.Credential)
	if wrongService.Code != http.StatusUnauthorized {
		t.Fatalf("wrong service credential status=%d body=%s", wrongService.Code, wrongService.Body.String())
	}
	logout := performIAMRequest(
		handler,
		http.MethodPost,
		"/v1/auth/logout",
		loginWire.Credential,
		[]byte(`{"requestId":"request-admin-logout"}`),
	)
	if logout.Code != http.StatusOK {
		t.Fatalf("IAM administrator logout status=%d body=%s", logout.Code, logout.Body.String())
	}

	assertIAMSecretsAbsent(
		t,
		ctx,
		admin,
		paasCredential,
		auditCredential,
		verifierCredential,
		adminPassword,
		changedAdminPassword,
		initialDeveloperPassword,
		changedDeveloperPassword,
		loginWire.Credential,
		developerWire.Credential,
	)
	var sessions, decisions, outbox int
	if err := admin.QueryRow(
		ctx,
		`SELECT
			(SELECT count(*) FROM iam.sessions),
			(SELECT count(*) FROM iam.authorization_decisions),
			(SELECT count(*) FROM iam.audit_outbox)`,
	).Scan(&sessions, &decisions, &outbox); err != nil {
		t.Fatalf("inspect IAM HTTP facts: %v", err)
	}
	if sessions != 2 || decisions != 14 || outbox != 25 {
		t.Fatalf("IAM HTTP facts sessions=%d decisions=%d outbox=%d", sessions, decisions, outbox)
	}
	var crossTenantBindings int
	if err := admin.QueryRow(
		ctx,
		"SELECT count(*) FROM iam.role_bindings WHERE tenant_id = 'organization-cross-tenant'",
	).Scan(&crossTenantBindings); err != nil {
		t.Fatalf("inspect cross-tenant role bindings: %v", err)
	}
	if crossTenantBindings != 0 {
		t.Fatalf("cross-tenant role bindings=%d want=0", crossTenantBindings)
	}
	var deniedUsers int
	if err := admin.QueryRow(
		ctx,
		"SELECT count(*) FROM iam.login_index WHERE login_name = 'denied.user'",
	).Scan(&deniedUsers); err != nil {
		t.Fatalf("inspect denied IAM user: %v", err)
	}
	if deniedUsers != 0 {
		t.Fatalf("denied IAM users=%d want=0", deniedUsers)
	}
}

func insertCrossTenantPrincipal(t *testing.T, ctx context.Context, admin *pgx.Conn) {
	t.Helper()
	if _, err := admin.Exec(
		ctx,
		`INSERT INTO iam.organizations (
			id, display_name, status, resource_version, created_at, updated_at
		) VALUES (
			'organization-cross-tenant', 'Cross Tenant', 'ACTIVE', 1,
			transaction_timestamp(), transaction_timestamp()
		);
		INSERT INTO iam.principals (
			tenant_id, id, principal_type, login_name, display_name, status,
			must_change_password, resource_version, created_at, updated_at
		) VALUES (
			'organization-cross-tenant', 'principal-cross-tenant', 'USER',
			'cross.tenant', 'Cross Tenant User', 'ACTIVE', true, 1,
			transaction_timestamp(), transaction_timestamp()
		);`,
	); err != nil {
		t.Fatalf("insert cross-tenant IAM fixture: %v", err)
	}
}

func performIAMRequest(
	handler http.Handler,
	method string,
	target string,
	bearer string,
	body []byte,
) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, target, bytes.NewReader(body))
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func performIAMRequestWithSubject(
	handler http.Handler,
	body []byte,
	serviceCredential string,
	subjectCredential string,
) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "/v1/authorize", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+serviceCredential)
	request.Header.Set("Matrix-Subject-Credential", subjectCredential)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func assertIAMPostgres18(t *testing.T, ctx context.Context, admin *pgx.Conn) {
	t.Helper()
	var version int
	if err := admin.QueryRow(ctx, "SELECT current_setting('server_version_num')::integer").Scan(&version); err != nil {
		t.Fatalf("read PostgreSQL version: %v", err)
	}
	if version < 180000 || version >= 190000 {
		t.Fatalf("PostgreSQL version=%d want major 18", version)
	}
}

func assertCleanIAMSchema(t *testing.T, ctx context.Context, admin *pgx.Conn) {
	t.Helper()
	var exists bool
	if err := admin.QueryRow(ctx, "SELECT to_regnamespace('iam') IS NOT NULL").Scan(&exists); err != nil {
		t.Fatalf("inspect IAM schema: %v", err)
	}
	if exists {
		t.Fatal("IAM HTTP integration database is not clean")
	}
}

func applyIAMSchema(t *testing.T, ctx context.Context, admin *pgx.Conn) {
	t.Helper()
	if err := iammigration.Bootstrap(ctx, admin); err != nil {
		t.Fatalf("bootstrap IAM migration: %v", err)
	}
	if err := iammigration.Up(ctx, admin); err != nil {
		t.Fatalf("apply IAM migration: %v", err)
	}
	if err := iammigration.Verify(ctx, admin); err != nil {
		t.Fatalf("verify IAM migration: %v", err)
	}
}

func createIAMHTTPRole(t *testing.T, ctx context.Context, admin *pgx.Conn) {
	t.Helper()
	statement := `DO $matrix_iam_http_role$
	BEGIN
		IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = '` + iamHTTPTestRole + `') THEN
			CREATE ROLE ` + iamHTTPTestRole + ` LOGIN PASSWORD '` + iamHTTPTestPassword + `'
				NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
		END IF;
	END
	$matrix_iam_http_role$;
	GRANT matrix_iam_api TO ` + iamHTTPTestRole + `;`
	if _, err := admin.Exec(ctx, statement); err != nil {
		t.Fatalf("create IAM HTTP runtime role: %v", err)
	}
}

func assertIAMSecretsAbsent(t *testing.T, ctx context.Context, admin *pgx.Conn, plaintexts ...string) {
	t.Helper()
	for _, plaintext := range plaintexts {
		var servicePlaintext, passwordPlaintext, sessionPlaintext, auditPlaintext bool
		if err := admin.QueryRow(
			ctx,
			`SELECT
				EXISTS (
					SELECT 1 FROM iam.service_credentials
					 WHERE lookup_digest = $1 OR verification_digest = $1
				),
				EXISTS (SELECT 1 FROM iam.user_credentials WHERE password_hash = $1),
				EXISTS (SELECT 1 FROM iam.sessions WHERE verification_digest = $1),
				EXISTS (
					SELECT 1 FROM iam.audit_outbox
					 WHERE event_document::text LIKE '%' || $1 || '%'
				)`,
			plaintext,
		).Scan(&servicePlaintext, &passwordPlaintext, &sessionPlaintext, &auditPlaintext); err != nil {
			t.Fatalf("inspect IAM secret storage: %v", err)
		}
		if servicePlaintext || passwordPlaintext || sessionPlaintext || auditPlaintext {
			t.Fatalf(
				"IAM stored plaintext service=%t password=%t session=%t audit=%t",
				servicePlaintext,
				passwordPlaintext,
				sessionPlaintext,
				auditPlaintext,
			)
		}
	}
}

func iamHTTPBootstrap(t *testing.T) iamv1.BootstrapDocument {
	t.Helper()
	service := func(purpose iamv1.ServicePurpose, id, credential string) iamv1.BootstrapServiceCredential {
		return iamv1.BootstrapServiceCredential{
			Purpose:     purpose,
			PrincipalID: iamv1.PrincipalID(id),
			Credential:  iamHTTPSecret(t, credential),
		}
	}
	return iamv1.BootstrapDocument{
		APIVersion:     iamv1.APIVersion,
		Kind:           "IAMBootstrap",
		InstallationID: "installation-http-integration",
		Organization: iamv1.InitialOrganization{
			ID:          "organization-http-integration",
			DisplayName: "HTTP Integration Organization",
		},
		Administrator: iamv1.InitialAdministrator{
			ID:          "principal-admin",
			LoginName:   "admin",
			DisplayName: "Initial Administrator",
			Password:    iamHTTPSecret(t, adminPassword),
		},
		Services: []iamv1.BootstrapServiceCredential{
			service(iamv1.ServiceIAM, "service-iam", "mx1.IAMHTTPIntegrationCredential0000000000000001"),
			service(iamv1.ServicePaaS, "service-paas", paasCredential),
			service(iamv1.ServiceAudit, "service-audit", auditCredential),
			service(iamv1.ServiceAPISIX, "service-apisix", "mx1.APISIXHTTPIntegrationCredential000000000001"),
			service(iamv1.ServiceInstallationVerifier, "service-verifier", verifierCredential),
		},
	}
}

func iamHTTPSecret(t *testing.T, value string) iamv1.Secret {
	t.Helper()
	secret, err := iamv1.NewSecret(value)
	if err != nil {
		t.Fatalf("create IAM HTTP secret: %v", err)
	}
	return secret
}
