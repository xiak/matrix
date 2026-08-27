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
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
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
	iamProducerCredential    = "mx1.IAMHTTPIntegrationCredential0000000000000001"
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
	poolConfig.MaxConns = 4
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
	var sequence atomic.Int64
	workflow, err := identityaccess.NewAuthority(repository, identityaccess.Config{
		SessionLifetime: time.Hour,
		NewID: func(prefix string) (string, error) {
			return fmt.Sprintf("%s-http-%d", prefix, sequence.Add(1)), nil
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
	if !loginResult.MustChangePassword {
		t.Fatal("initial administrator login did not publish the password-change requirement")
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
	managedServiceAuthorizeBody := []byte(`{"action":"managedservice.offering.read","resource":{"kind":"SERVICE_OFFERING","id":"collection"},"requestId":"request-managedservice-offering","correlationId":"correlation-managedservice-offering"}`)
	managedServiceAuthorize := performIAMRequestWithSubject(
		handler, managedServiceAuthorizeBody, paasCredential, loginWire.Credential,
	)
	if managedServiceAuthorize.Code != http.StatusOK {
		t.Fatalf(
			"IAM managed-service authorize status=%d body=%s",
			managedServiceAuthorize.Code,
			managedServiceAuthorize.Body.String(),
		)
	}
	if err := json.Unmarshal(managedServiceAuthorize.Body.Bytes(), &decision); err != nil ||
		!decision.Allowed || decision.Action != iamv1.ActionManagedServiceOfferingRead ||
		decision.Resource.Kind != iamv1.ResourceServiceOffering ||
		decision.TenantID != "organization-http-integration" {
		t.Fatalf("managed-service administrator decision=%#v err=%v", decision, err)
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
		[]byte(`{"loginName":"developer@organization-http-integration","password":"`+initialDeveloperPassword+`","requestId":"request-login-developer"}`),
	)
	if developerLogin.Code != http.StatusOK {
		t.Fatalf("IAM developer login status=%d body=%s", developerLogin.Code, developerLogin.Body.String())
	}
	var developerWire struct {
		Session            iamv1.Session `json:"session"`
		Credential         string        `json:"credential"`
		MustChangePassword bool          `json:"mustChangePassword"`
	}
	if err := json.Unmarshal(developerLogin.Body.Bytes(), &developerWire); err != nil ||
		developerWire.Credential == "" || !developerWire.MustChangePassword {
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
	assertPlatformAuthorityHTTP(t, ctx, handler, admin, loginWire.Credential, developerWire.Credential, developer.ID)
	if _, err := workflow.Bootstrap(ctx, document); err != nil {
		t.Fatalf("replay bootstrap after platform role revocation: %v", err)
	}
	applyIAMSchema(t, ctx, admin)
	assertPlatformDecisionHTTP(t, handler, loginWire.Credential, paasCredential, false)

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
	t.Run("tenant accounts and subusers", func(t *testing.T) {
		proveTenantAccounts(t, ctx, handler, admin, loginWire.Credential)
	})
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
	var decisionsHaveAudit bool
	if err := admin.QueryRow(
		ctx,
		`SELECT
			NOT EXISTS (
				SELECT 1 FROM iam.authorization_decisions AS decision
				WHERE (SELECT count(*) FROM iam.audit_outbox AS event
					WHERE event.tenant_id = decision.tenant_id
					AND event.event_document->>'action' = 'iam.authorization.decided'
					AND event.event_document->>'iamDecisionId' = decision.id
					AND event.event_document#>>'{actor,id}' = decision.principal_id
					AND event.event_document->>'requestId' = decision.request_id
					AND event.event_document->>'result' = CASE WHEN decision.allowed THEN 'ALLOWED' ELSE 'DENIED' END
				) <> 1
			)`,
	).Scan(&decisionsHaveAudit); err != nil {
		t.Fatalf("inspect IAM HTTP facts: %v", err)
	}
	if !decisionsHaveAudit {
		t.Fatal("not every IAM decision has an exact Audit fact")
	}
	var managedServiceFacts int
	if err := admin.QueryRow(
		ctx,
		`SELECT count(*)
		   FROM iam.authorization_decisions AS decision
		   JOIN iam.audit_outbox AS outbox
		     ON outbox.tenant_id = decision.tenant_id
		    AND outbox.event_document->>'iamDecisionId' = decision.id
		  WHERE decision.action_name = 'managedservice.offering.read'
		    AND decision.target_kind = 'SERVICE_OFFERING'
		    AND decision.target_id = 'collection'
		    AND decision.allowed`,
	).Scan(&managedServiceFacts); err != nil {
		t.Fatalf("inspect managed-service authorization facts: %v", err)
	}
	if managedServiceFacts != 1 {
		t.Fatalf("managed-service authorization facts=%d want=1", managedServiceFacts)
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

func proveTenantAccounts(t *testing.T, ctx context.Context, handler http.Handler, admin *pgx.Conn, root string) {
	t.Helper()
	const tenantA = "organization-http-integration"
	const tenantB = "organization-customer-b"
	const primaryBPassword = "Customer-B-Initial-Password-48!"
	const primaryBChanged = "Customer-B-Changed-Password-59!"
	const childPassword = "Account-Child-Initial-Password-74!"
	const childChangedA = "Account-A-Changed-Password-85!"
	const childChangedB = "Account-B-Changed-Password-96!"
	const resetPassword = "Account-Child-Reset-Password-63!"

	request := func(method, path, bearer string, body any, expected int) *httptest.ResponseRecorder {
		t.Helper()
		var encoded []byte
		var err error
		if body != nil {
			encoded, err = json.Marshal(body)
		}
		if err != nil {
			t.Fatalf("encode account test request: %v", err)
		}
		response := performIAMRequest(handler, method, path, bearer, encoded)
		if response.Code != expected {
			t.Fatalf("%s %s: status=%d want=%d body=%s", method, path, response.Code, expected, response.Body.String())
		}
		if response.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("account response is cacheable")
		}
		return response
	}
	identity := func(bearer string) iamv1.CurrentIdentity {
		t.Helper()
		response := request(http.MethodGet, "/v1/auth/me", bearer, nil, http.StatusOK)
		var result iamv1.CurrentIdentity
		if json.Unmarshal(response.Body.Bytes(), &result) != nil || iamv1.ValidateCurrentIdentity(result) != nil {
			t.Fatal("invalid current identity")
		}
		return result
	}
	login := func(name, password string, expected int) string {
		t.Helper()
		response := request(http.MethodPost, "/v1/auth/login", "", map[string]any{"loginName": name, "password": password, "requestId": "request-account-login"}, expected)
		if expected != http.StatusOK {
			return ""
		}
		var result struct {
			Credential string `json:"credential"`
		}
		if json.Unmarshal(response.Body.Bytes(), &result) != nil || result.Credential == "" {
			t.Fatal("login did not issue a credential")
		}
		return result.Credential
	}
	passwordChange := func(bearer, previous, next string) {
		request(http.MethodPost, "/v1/auth/password", bearer, map[string]any{"currentPassword": previous, "newPassword": next, "requestId": "request-account-password"}, http.StatusOK)
	}
	createUser := func(bearer, name string, role iamv1.BuiltinRole, expected int) iamv1.Principal {
		t.Helper()
		body := map[string]any{"loginName": name, "displayName": "Account test user", "initialPassword": childPassword, "requestId": "request-account-user"}
		if role != "" {
			body["initialRole"] = role
		}
		response := request(http.MethodPost, "/v1/principals", bearer, body, expected)
		var result iamv1.Principal
		if expected == http.StatusCreated && (json.Unmarshal(response.Body.Bytes(), &result) != nil || iamv1.ValidatePrincipal(result) != nil) {
			t.Fatal("invalid created user")
		}
		return result
	}
	setAlias := func(bearer, alias string, version uint64, expected int) iamv1.OrganizationAccount {
		t.Helper()
		response := request(http.MethodPost, "/v1/organization:alias", bearer, map[string]any{"alias": alias, "resourceVersion": version, "requestId": "request-account-alias"}, expected)
		var result iamv1.OrganizationAccount
		if expected == http.StatusOK && (json.Unmarshal(response.Body.Bytes(), &result) != nil || iamv1.ValidateOrganizationAccount(result) != nil) {
			t.Fatal("invalid account alias response")
		}
		return result
	}
	assertPaasDecision := func(bearer string, action iamv1.Action, expected bool, tenant string) {
		t.Helper()
		kind, _ := iamv1.ResourceKindForAction(action)
		body, _ := json.Marshal(iamv1.AuthorizationRequest{Action: action, Resource: iamv1.ResourceReference{Kind: kind, ID: "shared-account-resource"}, RequestID: "request-account-paas", CorrelationID: "request-account-paas"})
		response := performIAMRequestWithSubject(handler, body, paasCredential, bearer)
		var result iamv1.AuthorizationDecision
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &result) != nil || result.Allowed != expected || (expected && string(result.TenantID) != tenant) {
			t.Fatalf("account-bound decision status=%d allowed=%t tenant=%s", response.Code, result.Allowed, result.TenantID)
		}
	}
	rootIdentity := identity(root)
	if !rootIdentity.CanCreateOrganizations || rootIdentity.Account.PrimaryPrincipalID != "principal-admin" {
		t.Fatal("bootstrap identity not recognized")
	}
	newTenantBody := map[string]any{"id": tenantB, "displayName": "Customer B", "administratorLoginName": "customer.admin", "administratorDisplayName": "Customer administrator", "initialPassword": primaryBPassword, "requestId": "request-account-create"}
	opened := request(http.MethodPost, "/v1/organizations", root, newTenantBody, http.StatusCreated)
	var tenant iamv1.OrganizationAccount
	if json.Unmarshal(opened.Body.Bytes(), &tenant) != nil || tenant.Organization.ID != tenantB {
		t.Fatal("tenant onboarding did not create the requested account")
	}
	request(http.MethodPost, "/v1/organizations", root, newTenantBody, http.StatusConflict)
	primaryB := login("customer.admin", primaryBPassword, http.StatusOK)
	if identity(primaryB).CanCreateOrganizations {
		t.Fatal("new primary inherited platform account-opening capability")
	}
	passwordChange(primaryB, primaryBPassword, primaryBChanged)
	t.Run("event-bound historical producer authority", func(t *testing.T) {
		proveHistoricalProducerHTTP(t, ctx, handler, admin, map[string]string{tenantA: root, tenantB: primaryB})
	})
	request(http.MethodPost, "/v1/audit-producer:resolve", paasCredential,
		map[string]any{"organizationId": tenantB}, http.StatusBadRequest)
	request(http.MethodGet, "/v1/organizations", primaryB, nil, http.StatusForbidden)
	request(http.MethodPost, "/v1/organizations", primaryB, newTenantBody, http.StatusForbidden)
	setAlias(root, "customer-a", rootIdentity.Account.Organization.ResourceVersion, http.StatusOK)
	setAlias(primaryB, "customer-b", 1, http.StatusOK)
	setAlias(primaryB, "customer-a", 2, http.StatusConflict)
	setAlias(primaryB, tenantA, 2, http.StatusConflict)
	setAlias(root, "stale-alias", 1, http.StatusConflict)
	createUser(root, "bad.verifier", iamv1.RoleInstallationVerifier, http.StatusUnprocessableEntity)

	childA := createUser(root, "shared.user", iamv1.RolePaaSViewer, http.StatusCreated)
	childB := createUser(primaryB, "shared.user", "", http.StatusCreated)
	if childA.ID == childB.ID || childA.OrganizationID != tenantA || childB.OrganizationID != tenantB {
		t.Fatal("same-name child identities were not isolated")
	}
	createUser(root, "shared.user", "", http.StatusConflict)
	login("shared.user", childPassword, http.StatusUnauthorized)
	login("shared.user@unknown-tenant", childPassword, http.StatusUnauthorized)
	login("customer.admin@customer-b", primaryBChanged, http.StatusUnauthorized)
	childSessionA := login("shared.user@customer-a", childPassword, http.StatusOK)
	childSessionB := login("shared.user@"+tenantB, childPassword, http.StatusOK)
	passwordChange(childSessionA, childPassword, childChangedA)
	passwordChange(childSessionB, childPassword, childChangedB)
	login("shared.user@customer-b", childChangedA, http.StatusUnauthorized)
	if id := identity(childSessionA); id.Principal.ID != childA.ID || id.Account.Organization.ID != tenantA || id.CanCreateOrganizations {
		t.Fatal("wrong tenant or platform capability in child identity")
	}
	if len(identity(childSessionB).Roles) != 0 {
		t.Fatal("new child gained implicit business permissions")
	}
	assertPaasDecision(childSessionA, iamv1.ActionManagedServiceInstallationRead, true, tenantA)
	assertPaasDecision(childSessionA, iamv1.ActionManagedServiceInstallationCreate, false, "")
	assertPaasDecision(childSessionB, iamv1.ActionManagedServiceInstallationRead, false, "")
	request(http.MethodGet, "/v1/principals", childSessionA, nil, http.StatusForbidden)
	setAlias(childSessionA, "forged-alias", 2, http.StatusForbidden)
	request(http.MethodPost, "/v1/role-bindings", childSessionA, map[string]any{"principalId": childA.ID, "role": "ORGANIZATION_ADMIN", "requestId": "request-escalate"}, http.StatusForbidden)

	listResponse := request(http.MethodGet, "/v1/principals", root, nil, http.StatusOK)
	var users iamv1.PrincipalList
	if json.Unmarshal(listResponse.Body.Bytes(), &users) != nil || iamv1.ValidatePrincipalList(users) != nil {
		t.Fatal("invalid tenant directory")
	}
	var childBinding iamv1.RoleBindingID
	for _, entry := range users.Items {
		if entry.Principal.OrganizationID != tenantA || entry.Principal.Type != iamv1.PrincipalUser {
			t.Fatal("directory leaked a different tenant or service identity")
		}
		if entry.Principal.ID == childA.ID {
			if len(entry.RoleBindings) != 1 || entry.RoleBindings[0].Role != iamv1.RolePaaSViewer {
				t.Fatal("initial user role was not atomic")
			}
			childBinding = entry.RoleBindings[0].ID
		}
	}
	if childBinding == "" {
		t.Fatal("created child missing from directory")
	}
	request(http.MethodPost, "/v1/role-bindings", root, map[string]any{"principalId": childB.ID, "role": "ORGANIZATION_ADMIN", "requestId": "request-cross-tenant-role"}, http.StatusForbidden)
	request(http.MethodPost, "/v1/role-bindings/"+string(childBinding)+":revoke", primaryB, map[string]any{"requestId": "request-cross-tenant-revoke"}, http.StatusForbidden)
	for _, target := range []string{string(childB.ID), "principal-admin", "service-paas"} {
		request(http.MethodPost, "/v1/principals/"+target+":set-status", root, map[string]any{"status": "DISABLED", "resourceVersion": 1, "requestId": "request-protected-status"}, http.StatusForbidden)
		request(http.MethodPost, "/v1/principals/"+target+":reset-password", root, map[string]any{"initialPassword": resetPassword, "resourceVersion": 1, "requestId": "request-protected-password"}, http.StatusForbidden)
	}
	request(http.MethodPost, "/v1/role-bindings/bootstrap-admin-binding:revoke", root, map[string]any{"requestId": "request-primary-binding"}, http.StatusForbidden)
	request(http.MethodPost, "/v1/role-bindings/primary-admin-binding:revoke", primaryB, map[string]any{"requestId": "request-primary-binding"}, http.StatusForbidden)
	for _, path := range []string{"/v1/principals?tenantId=" + tenantB, "/v1/principals?after=x&after=y", "/v1/principals?after=", "/v1/organizations?organizationId=" + tenantB, "/v1/auth/me?tenantId=" + tenantB} {
		request(http.MethodGet, path, root, nil, http.StatusBadRequest)
	}
	request(http.MethodPost, "/v1/organization:alias", root, map[string]any{"alias": "forged", "tenantId": tenantB, "resourceVersion": 2, "requestId": "request-forged-alias"}, http.StatusBadRequest)
	request(http.MethodGet, "/v1/principals?after="+string(childB.ID), root, nil, http.StatusOK)

	delegated := createUser(root, "delegated.admin", iamv1.RoleOrganizationAdmin, http.StatusCreated)
	delegatedSession := login("delegated.admin@customer-a", childPassword, http.StatusOK)
	passwordChange(delegatedSession, childPassword, childChangedA)
	if identity(delegatedSession).CanCreateOrganizations {
		t.Fatal("assignable administrator role granted platform access")
	}
	request(http.MethodGet, "/v1/organizations", delegatedSession, nil, http.StatusForbidden)
	request(http.MethodPost, "/v1/organizations", delegatedSession, newTenantBody, http.StatusForbidden)
	request(http.MethodPost, "/v1/principals/"+string(delegated.ID)+":set-status", delegatedSession, map[string]any{"status": "DISABLED", "resourceVersion": 2, "requestId": "request-self-disable"}, http.StatusForbidden)
	setAlias(delegatedSession, "customer-a-new", 2, http.StatusOK)
	login("shared.user@customer-a", childChangedA, http.StatusUnauthorized)
	login("shared.user@customer-a-new", childChangedA, http.StatusOK)
	login("shared.user@"+tenantA, childChangedA, http.StatusOK)
	if identity(childSessionA).Account.Organization.ID != tenantA {
		t.Fatal("alias change altered existing session authority")
	}
	setAlias(primaryB, "customer-a", 2, http.StatusConflict)
	newTenantBody["id"] = "customer-a"
	newTenantBody["administratorLoginName"] = "collision.admin"
	request(http.MethodPost, "/v1/organizations", root, newTenantBody, http.StatusConflict)
	setAlias(root, "customer-a", 3, http.StatusOK)
	login("shared.user@customer-a-new", childChangedA, http.StatusUnauthorized)
	login("shared.user@customer-a", childChangedA, http.StatusOK)

	request(http.MethodPost, "/v1/role-bindings/"+string(childBinding)+":revoke", root, map[string]any{"requestId": "request-child-revoke"}, http.StatusOK)
	assertPaasDecision(childSessionA, iamv1.ActionManagedServiceInstallationRead, false, "")
	grant := request(http.MethodPost, "/v1/role-bindings", primaryB, map[string]any{"principalId": childB.ID, "role": "PAAS_DEVELOPER", "requestId": "request-child-grant"}, http.StatusOK)
	if bytes.Contains(grant.Body.Bytes(), []byte(tenantA)) {
		t.Fatal("grant selected the wrong tenant")
	}
	assertPaasDecision(childSessionB, iamv1.ActionManagedServiceInstallationCreate, true, tenantB)

	statusPath := "/v1/principals/" + string(childA.ID) + ":set-status"
	request(http.MethodPost, statusPath, root, map[string]any{"status": "DISABLED", "resourceVersion": 1, "requestId": "request-stale-status"}, http.StatusConflict)
	request(http.MethodPost, statusPath, root, map[string]any{"status": "DISABLED", "resourceVersion": 2, "requestId": "request-disable"}, http.StatusOK)
	request(http.MethodGet, "/v1/auth/me", childSessionA, nil, http.StatusUnauthorized)
	login("shared.user@customer-a", childChangedA, http.StatusUnauthorized)
	request(http.MethodPost, statusPath, root, map[string]any{"status": "ACTIVE", "resourceVersion": 3, "requestId": "request-enable"}, http.StatusOK)
	request(http.MethodGet, "/v1/auth/me", childSessionA, nil, http.StatusUnauthorized)
	activeOne := login("shared.user@customer-a", childChangedA, http.StatusOK)
	activeTwo := login("shared.user@"+tenantA, childChangedA, http.StatusOK)
	request(http.MethodPost, "/v1/principals/"+string(childA.ID)+":reset-password", root, map[string]any{"initialPassword": resetPassword, "resourceVersion": 4, "requestId": "request-reset"}, http.StatusOK)
	for _, bearer := range []string{activeOne, activeTwo} {
		request(http.MethodGet, "/v1/auth/me", bearer, nil, http.StatusUnauthorized)
	}
	login("shared.user@customer-a", childChangedA, http.StatusUnauthorized)
	resetSession := login("shared.user@customer-a", resetPassword, http.StatusOK)
	if !identity(resetSession).Principal.MustChangePassword {
		t.Fatal("reset password did not restrict the next login")
	}
	assertPaasDecision(resetSession, iamv1.ActionManagedServiceInstallationRead, false, "")
	if identity(childSessionB).Principal.ID != childB.ID {
		t.Fatal("reset leaked across tenants")
	}

	// Reapply against populated multi-tenant state; no user, alias, session, or
	// authority identity may be replaced by bootstrap re-initialization.
	applyIAMSchema(t, ctx, admin)
	if identity(root).Account.LoginAlias == nil || *identity(root).Account.LoginAlias != "customer-a" || identity(primaryB).Account.Organization.ID != tenantB {
		t.Fatal("migration replay did not preserve account state")
	}
	login("shared.user@customer-b", childChangedB, http.StatusOK)
	beforePaging := request(http.MethodGet, "/v1/principals", primaryB, nil, http.StatusOK)
	var existingUsers iamv1.PrincipalList
	if json.Unmarshal(beforePaging.Body.Bytes(), &existingUsers) != nil || existingUsers.NextAfter != "" {
		t.Fatal("unable to establish the directory before pagination")
	}
	expectedUsers := map[iamv1.PrincipalID]bool{}
	for _, entry := range existingUsers.Items {
		expectedUsers[entry.Principal.ID] = true
	}
	for i := 0; i < 101; i++ {
		created := createUser(primaryB, fmt.Sprintf("page.user.%03d", i), "", http.StatusCreated)
		expectedUsers[created.ID] = true
	}
	pageOne := request(http.MethodGet, "/v1/principals", primaryB, nil, http.StatusOK)
	var first, second iamv1.PrincipalList
	if json.Unmarshal(pageOne.Body.Bytes(), &first) != nil || len(first.Items) != 100 || first.NextAfter == "" {
		t.Fatal("principal page is not bounded")
	}
	pageTwo := request(http.MethodGet, "/v1/principals?after="+first.NextAfter, primaryB, nil, http.StatusOK)
	if json.Unmarshal(pageTwo.Body.Bytes(), &second) != nil || len(second.Items) > 100 || second.NextAfter != "" {
		t.Fatal("principal continuation is incomplete")
	}
	seen := map[iamv1.PrincipalID]bool{}
	for _, entry := range append(first.Items, second.Items...) {
		if seen[entry.Principal.ID] || entry.Principal.OrganizationID != tenantB || !expectedUsers[entry.Principal.ID] {
			t.Fatal("directory cursor duplicated or crossed tenants")
		}
		seen[entry.Principal.ID] = true
	}
	if len(seen) != len(expectedUsers) {
		t.Fatal("directory lost users across pages")
	}
	accountPage := request(http.MethodGet, "/v1/organizations", root, nil, http.StatusOK)
	var accounts iamv1.OrganizationAccountList
	if json.Unmarshal(accountPage.Body.Bytes(), &accounts) != nil || len(accounts.Items) != 2 {
		t.Fatal("failed onboarding left a partial tenant")
	}
	// Two account administrators cannot acquire the same alias concurrently.
	startAliasRace := make(chan struct{})
	aliasResults := make(chan int, 2)
	for _, actor := range []string{root, primaryB} {
		version := identity(actor).Account.Organization.ResourceVersion
		body, err := json.Marshal(iamv1.SetAccountAliasRequest{Alias: "concurrent-company", ResourceVersion: version, RequestID: "request-alias-race"})
		if err != nil {
			t.Fatal(err)
		}
		go func(bearer string, encoded []byte) {
			<-startAliasRace
			aliasResults <- performIAMRequest(handler, http.MethodPost, "/v1/organization:alias", bearer, encoded).Code
		}(actor, body)
	}
	close(startAliasRace)
	firstStatus, secondStatus := <-aliasResults, <-aliasResults
	if !((firstStatus == http.StatusOK && secondStatus == http.StatusConflict) || (secondStatus == http.StatusOK && firstStatus == http.StatusConflict)) {
		t.Fatalf("concurrent alias acquisition statuses=%d,%d", firstStatus, secondStatus)
	}
	for _, actor := range []struct{ bearer, alias string }{{root, "customer-a"}, {primaryB, "customer-b"}} {
		setAlias(actor.bearer, actor.alias, identity(actor.bearer).Account.Organization.ResourceVersion, http.StatusOK)
	}

	for _, action := range []string{"iam.organization.created", "iam.account-alias.set", "iam.principal.status-set", "iam.password.reset"} {
		var correlated bool
		if err := admin.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM iam.audit_outbox AS event JOIN iam.authorization_decisions AS decision ON decision.tenant_id=event.tenant_id AND decision.id=event.event_document->>'iamDecisionId' WHERE event.event_document->>'action'=$1 AND decision.allowed)`, action).Scan(&correlated); err != nil || !correlated {
			t.Fatalf("account mutation %s lacks atomic audit decision: %v", action, err)
		}
	}
	assertIAMSecretsAbsent(t, ctx, admin, primaryBPassword, primaryBChanged, childPassword, childChangedA, childChangedB, resetPassword, primaryB, childSessionA, childSessionB, activeOne, activeTwo, resetSession)
}

func proveHistoricalProducerHTTP(t *testing.T, ctx context.Context, handler http.Handler, database *pgx.Conn, tenants map[string]string) {
	t.Helper()
	post := func(path, bearer string, body any, status int) *httptest.ResponseRecorder {
		t.Helper()
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		response := performIAMRequest(handler, http.MethodPost, path, bearer, encoded)
		if response.Code != status {
			t.Fatalf("proof path=%s status=%d want=%d body=%s", path, response.Code, status, response.Body.String())
		}
		return response
	}
	resolve := func(credential string, event auditv1.Event, status int) {
		t.Helper()
		response := post("/v1/audit-producer:resolve", credential, iamv1.ResolveAuditProducerRequest{Event: event}, status)
		if status != http.StatusOK {
			return
		}
		var proof iamv1.AuditProducerAuthorization
		contract, _ := auditv1.ContractForAction(event.Action)
		_, digest, err := auditv1.CanonicalizeEvent(contract.Source, event)
		if json.Unmarshal(response.Body.Bytes(), &proof) != nil || iamv1.ValidateAuditProducerAuthorization(proof) != nil || err != nil ||
			proof.TenantID != iamv1.OrganizationID(event.TenantID) || proof.InstallationID != event.InstallationID || proof.ContentDigest != digest ||
			proof.Producer.OrganizationID != "organization-http-integration" || proof.Producer.InstallationID != "installation-http-integration" {
			t.Fatal("producer proof lost event, installation or credential binding")
		}
	}
	const initial = "Proof-Actor-Initial-Password-93!"
	const changed = "Proof-Actor-Changed-Password-84!"
	for tenant, root := range tenants {
		created := post("/v1/principals", root, map[string]any{"loginName": "proof.actor", "displayName": "Proof actor", "initialPassword": initial, "initialRole": iamv1.RoleOrganizationAdmin, "requestId": "request-proof-actor"}, http.StatusCreated)
		var principal iamv1.Principal
		if json.Unmarshal(created.Body.Bytes(), &principal) != nil {
			t.Fatal("decode proof actor")
		}
		loggedIn := post("/v1/auth/login", "", map[string]any{"loginName": "proof.actor@" + tenant, "password": initial, "requestId": "request-proof-login"}, http.StatusOK)
		var session struct {
			Credential string `json:"credential"`
		}
		if json.Unmarshal(loggedIn.Body.Bytes(), &session) != nil {
			t.Fatal("decode proof login")
		}
		post("/v1/auth/password", session.Credential, map[string]any{"currentPassword": initial, "newPassword": changed, "requestId": "request-proof-password"}, http.StatusOK)
		var historical []struct {
			credential string
			event      auditv1.Event
		}
		for _, producer := range []struct {
			credential  string
			action      iamv1.Action
			eventAction auditv1.Action
			kind        iamv1.ResourceKind
			targetKind  auditv1.TargetKind
			target      string
		}{
			{paasCredential, iamv1.ActionPaaSApplicationCreate, auditv1.ActionPaaSApplicationCreated, iamv1.ResourceApplication, auditv1.TargetApplication, "collection"},
			{auditCredential, iamv1.ActionAuditRecordRead, auditv1.ActionAuditRecordsRead, iamv1.ResourceAuditRecord, auditv1.TargetAuditRecords, "records"},
		} {
			body, _ := json.Marshal(iamv1.AuthorizationRequest{Action: producer.action, Resource: iamv1.ResourceReference{Kind: producer.kind, ID: producer.target}, RequestID: "request-proof-business", CorrelationID: "correlation-proof-business"})
			response := performIAMRequestWithSubject(handler, body, producer.credential, session.Credential)
			var decision iamv1.AuthorizationDecision
			if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &decision) != nil || !decision.Allowed || decision.Subject == nil {
				t.Fatal("proof actor lacked real original authority")
			}
			event := auditv1.Event{APIVersion: auditv1.APIVersion, Kind: "AuditEvent", EventID: auditv1.EventID("event-" + string(decision.ID)), TenantID: auditv1.TenantID(tenant),
				Actor: auditv1.ActorReference{Type: auditv1.ActorUser, ID: auditv1.ActorID(principal.ID)}, IAMDecisionID: auditv1.DecisionID(decision.ID), Action: producer.eventAction,
				Target: auditv1.TargetReference{Kind: producer.targetKind, ID: producer.target}, Result: auditv1.ResultSucceeded, RequestDigest: "sha256:" + strings.Repeat("a", 64),
				RequestID: decision.RequestID, CorrelationID: "correlation-proof-business", OccurredAt: decision.DecidedAt.Add(time.Microsecond)}
			if producer.credential == paasCredential {
				event.Target.ID = "application-proof"
				event.OperationID = "operation-proof"
			}
			resolve(producer.credential, event, http.StatusOK)
			for _, attack := range []func(*auditv1.Event){
				func(e *auditv1.Event) { e.TenantID = "unknown-account" },
				func(e *auditv1.Event) {
					for other := range tenants {
						if other != tenant {
							e.TenantID = auditv1.TenantID(other)
							break
						}
					}
				},
				func(e *auditv1.Event) { e.Actor.ID = "principal-forged" },
				func(e *auditv1.Event) { e.IAMDecisionID = "decision-forged" },
				func(e *auditv1.Event) { e.RequestID = "request-forged" },
				func(e *auditv1.Event) { e.CorrelationID = "correlation-forged" },
				func(e *auditv1.Event) { e.OccurredAt = decision.DecidedAt.Add(-time.Microsecond) },
			} {
				forged := event
				attack(&forged)
				resolve(producer.credential, forged, http.StatusForbidden)
			}
			resolve(verifierCredential, event, http.StatusForbidden)
			resolve(root, event, http.StatusUnauthorized)
			otherProducer := paasCredential
			if otherProducer == producer.credential {
				otherProducer = auditCredential
			}
			resolve(otherProducer, event, http.StatusForbidden)
			historical = append(historical, struct {
				credential string
				event      auditv1.Event
			}{producer.credential, event})
		}
		post("/v1/auth/logout", session.Credential, map[string]any{"requestId": "request-proof-logout"}, http.StatusOK)
		post("/v1/principals/"+string(principal.ID)+":set-status", root, map[string]any{"status": "DISABLED", "resourceVersion": 2, "requestId": "request-proof-disable"}, http.StatusOK)
		for _, fact := range historical {
			resolve(fact.credential, fact.event, http.StatusOK)
		}
		if response := performIAMRequest(handler, http.MethodGet, "/v1/auth/me", session.Credential, nil); response.Code != http.StatusUnauthorized {
			t.Fatal("historical proof revived revoked session")
		}
	}
	rows, err := database.Query(ctx, `SELECT DISTINCT ON (event_document->>'action') event_document FROM iam.audit_outbox ORDER BY event_document->>'action',event_id`)
	if err != nil {
		t.Fatal(err)
	}
	var ownFacts []auditv1.Event
	for rows.Next() {
		var raw []byte
		var event auditv1.Event
		if rows.Scan(&raw) != nil || json.Unmarshal(raw, &event) != nil {
			rows.Close()
			t.Fatal("decode own committed IAM fact")
		}
		event.OccurredAt = event.OccurredAt.UTC()
		ownFacts = append(ownFacts, event)
	}
	rows.Close()
	if rows.Err() != nil || len(ownFacts) == 0 {
		t.Fatal("missing committed IAM evidence")
	}
	for _, event := range ownFacts {
		resolve(iamProducerCredential, event, http.StatusOK)
		forged := event
		forged.RequestDigest = "sha256:" + strings.Repeat("b", 64)
		resolve(iamProducerCredential, forged, http.StatusForbidden)
	}
	assertIAMSecretsAbsent(t, ctx, database, initial, changed)
}

func assertPlatformAuthorityHTTP(t *testing.T, ctx context.Context, handler http.Handler, database *pgx.Conn, administrator, member string, memberID iamv1.PrincipalID) {
	t.Helper()
	put := func(actor string, principalID iamv1.PrincipalID, role iamv1.BuiltinRole, expected int) iamv1.RoleBinding {
		t.Helper()
		body, err := json.Marshal(iamv1.PutRoleBindingRequest{PrincipalID: principalID, Role: role, RequestID: "request-platform-role-put"})
		if err != nil {
			t.Fatal(err)
		}
		response := performIAMRequest(handler, http.MethodPost, "/v1/role-bindings", actor, body)
		if response.Code != expected {
			t.Fatalf("platform role grant status=%d expected=%d body=%s", response.Code, expected, response.Body.String())
		}
		var binding iamv1.RoleBinding
		if expected == http.StatusOK && (json.Unmarshal(response.Body.Bytes(), &binding) != nil || iamv1.ValidateRoleBinding(binding) != nil) {
			t.Fatal("platform role grant returned an invalid binding")
		}
		return binding
	}
	revoke := func(actor string, id iamv1.RoleBindingID, expected int) {
		t.Helper()
		response := performIAMRequest(handler, http.MethodPost, "/v1/role-bindings/"+string(id)+":revoke", actor,
			[]byte(`{"requestId":"request-platform-role-revoke"}`))
		if response.Code != expected {
			t.Fatalf("platform role revocation status=%d expected=%d body=%s", response.Code, expected, response.Body.String())
		}
	}
	assertPlatformDecisionHTTP(t, handler, administrator, paasCredential, true)
	assertPlatformDecisionHTTP(t, handler, administrator, auditCredential, false)
	assertPlatformDecisionHTTP(t, handler, member, paasCredential, false)
	organizationBinding := put(administrator, memberID, iamv1.RoleOrganizationAdmin, http.StatusOK)
	assertPlatformDecisionHTTP(t, handler, member, paasCredential, false)
	put(member, memberID, iamv1.RolePlatformOperator, http.StatusForbidden)
	revoke(member, "bootstrap-platform-operator-binding", http.StatusForbidden)
	put(administrator, "service-paas", iamv1.RolePlatformOperator, http.StatusForbidden)
	platformBinding := put(administrator, memberID, iamv1.RolePlatformOperator, http.StatusOK)
	assertPlatformDecisionHTTP(t, handler, member, paasCredential, true)
	for _, command := range []struct{ suffix, body string }{
		{":set-status", `{"status":"DISABLED","resourceVersion":2,"requestId":"request-protect-platform-status"}`},
		{":reset-password", `{"initialPassword":"Platform-Reset-Attack-Password-39!","resourceVersion":2,"requestId":"request-protect-platform-password"}`},
	} {
		response := performIAMRequest(handler, http.MethodPost, "/v1/principals/"+string(memberID)+command.suffix, administrator, []byte(command.body))
		if response.Code != http.StatusForbidden {
			t.Fatalf("tenant command took over platform identity: status=%d", response.Code)
		}
	}
	assertPlatformDecisionHTTP(t, handler, member, paasCredential, true)
	revoke(administrator, platformBinding.ID, http.StatusOK)
	revoke(administrator, platformBinding.ID, http.StatusOK)
	assertPlatformDecisionHTTP(t, handler, member, paasCredential, false)
	t.Run("platform grant serializes with credential mutations", func(t *testing.T) {
		provePlatformCredentialProtection(t, ctx, handler, database, administrator, member)
	})
	revoke(administrator, organizationBinding.ID, http.StatusOK)
	revoke(administrator, "bootstrap-platform-operator-binding", http.StatusOK)
	assertPlatformDecisionHTTP(t, handler, administrator, paasCredential, false)
}

func provePlatformCredentialProtection(t *testing.T, ctx context.Context, handler http.Handler, database *pgx.Conn, operator, tenantAdministrator string) {
	t.Helper()
	const initial = "Platform-Race-Initial-Password-36!"
	const changed = "Platform-Race-Changed-Password-47!"
	const reset = "Platform-Race-Reset-Password-58!"
	request := func(path, bearer string, body any) *httptest.ResponseRecorder {
		t.Helper()
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		return performIAMRequest(handler, http.MethodPost, path, bearer, encoded)
	}
	for _, mutation := range []string{"reset-password", "set-status", "legacy-disabled"} {
		t.Run(mutation, func(t *testing.T) {
			created := request("/v1/principals", operator, map[string]any{
				"loginName": "platform.race." + mutation, "displayName": "Platform race user",
				"initialPassword": initial, "requestId": "request-race-create-" + mutation,
			})
			var principal iamv1.Principal
			if created.Code != http.StatusCreated || json.Unmarshal(created.Body.Bytes(), &principal) != nil {
				t.Fatalf("create platform race user status=%d", created.Code)
			}
			grantBody := map[string]any{"principalId": principal.ID, "role": iamv1.RolePlatformOperator, "requestId": "request-race-grant-" + mutation}
			if response := request("/v1/role-bindings", operator, grantBody); response.Code != http.StatusForbidden {
				t.Fatal("unconfirmed initial password gained platform authority")
			}
			login := request("/v1/auth/login", "", map[string]any{
				"loginName": principal.LoginName + "@" + string(principal.OrganizationID), "password": initial, "requestId": "request-race-login-" + mutation,
			})
			var session struct {
				Credential string `json:"credential"`
			}
			if login.Code != http.StatusOK || json.Unmarshal(login.Body.Bytes(), &session) != nil || session.Credential == "" {
				t.Fatalf("login platform race user status=%d", login.Code)
			}
			if response := request("/v1/auth/password", session.Credential, map[string]any{
				"currentPassword": initial, "newPassword": changed, "requestId": "request-race-password-" + mutation,
			}); response.Code != http.StatusOK {
				t.Fatalf("initialize platform race user status=%d", response.Code)
			}
			if mutation == "legacy-disabled" {
				if response := request("/v1/role-bindings", operator, grantBody); response.Code != http.StatusOK {
					t.Fatalf("grant legacy platform fixture status=%d", response.Code)
				}
				// Model a disabled platform user from an older installation. New
				// tenant commands cannot create this state or recover its credentials.
				var version uint64
				if err := database.QueryRow(ctx, `UPDATE iam.principals SET status='DISABLED',resource_version=resource_version+1
					WHERE tenant_id=$1 AND id=$2 RETURNING resource_version`, principal.OrganizationID, principal.ID).Scan(&version); err != nil {
					t.Fatal(err)
				}
				for _, body := range []map[string]any{
					{"status": "ACTIVE", "resourceVersion": version, "requestId": "request-disabled-platform-enable"},
					{"initialPassword": reset, "resourceVersion": version, "requestId": "request-disabled-platform-reset"},
				} {
					suffix := ":set-status"
					if _, ok := body["initialPassword"]; ok {
						suffix = ":reset-password"
					}
					if response := request("/v1/principals/"+string(principal.ID)+suffix, tenantAdministrator, body); response.Code != http.StatusForbidden {
						t.Fatalf("tenant administrator recovered a disabled platform identity: %d", response.Code)
					}
				}
				return
			}
			changeBody := map[string]any{"resourceVersion": 2, "requestId": "request-race-change-" + mutation}
			if mutation == "reset-password" {
				changeBody["initialPassword"] = reset
			} else {
				changeBody["status"] = "DISABLED"
			}
			grantJSON, _ := json.Marshal(grantBody)
			changeJSON, _ := json.Marshal(changeBody)
			start := make(chan struct{})
			grants, changes := make(chan int, 1), make(chan int, 1)
			go func() {
				<-start
				grants <- performIAMRequest(handler, http.MethodPost, "/v1/role-bindings", operator, grantJSON).Code
			}()
			go func() {
				<-start
				changes <- performIAMRequest(handler, http.MethodPost, "/v1/principals/"+string(principal.ID)+":"+mutation, tenantAdministrator, changeJSON).Code
			}()
			close(start)
			grantStatus, changeStatus := <-grants, <-changes
			if !((grantStatus == http.StatusOK && changeStatus == http.StatusForbidden) ||
				(grantStatus == http.StatusForbidden && changeStatus == http.StatusOK)) {
				t.Fatalf("platform grant/mutation race statuses=%d/%d", grantStatus, changeStatus)
			}
			var activePlatform bool
			var status string
			var mustChange bool
			if err := database.QueryRow(ctx, `SELECT p.status,p.must_change_password,
				EXISTS(SELECT 1 FROM iam.role_bindings AS b WHERE b.tenant_id=p.tenant_id AND b.principal_id=p.id AND b.role_name='PLATFORM_OPERATOR' AND b.revoked_at IS NULL)
				FROM iam.principals AS p WHERE p.tenant_id=$1 AND p.id=$2`, principal.OrganizationID, principal.ID).Scan(&status, &mustChange, &activePlatform); err != nil {
				t.Fatal(err)
			}
			if activePlatform != (grantStatus == http.StatusOK) || activePlatform && (status != "ACTIVE" || mustChange) {
				t.Fatal("platform grant raced past disabled or replaced credentials")
			}
		})
	}
	assertIAMSecretsAbsent(t, ctx, database, initial, changed, reset)
}

func assertPlatformDecisionHTTP(t *testing.T, handler http.Handler, subject, caller string, allowed bool) {
	t.Helper()
	body := []byte(`{"action":"paas.execution-target.register","resource":{"kind":"EXECUTION_TARGET","id":"target-example"},"requestId":"request-node-register","correlationId":"request-node-register"}`)
	response := performIAMRequestWithSubject(handler, body, caller, subject)
	var decision iamv1.AuthorizationDecision
	if response.Code != http.StatusOK || iamv1.DecodeRequest(bytes.NewReader(response.Body.Bytes()), &decision) != nil ||
		iamv1.ValidateAuthorizationDecision(decision) != nil || decision.Allowed != allowed || decision.TenantID != "" {
		t.Fatalf("platform authorization status=%d allowed=%t body=%s", response.Code, allowed, response.Body.String())
	}
	if allowed && (decision.InstallationID != "installation-http-integration" || decision.Subject == nil) {
		t.Fatal("platform decision lost the sealed installation identity")
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
			service(iamv1.ServiceIAM, "service-iam", iamProducerCredential),
			service(iamv1.ServicePaaS, "service-paas", paasCredential),
			service(iamv1.ServiceAudit, "service-audit", auditCredential),
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
