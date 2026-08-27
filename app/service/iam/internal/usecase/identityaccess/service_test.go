package identityaccess

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/iam/internal/authority"
)

func TestIAMCoreUsecasesBindCredentialsAndRecordClosedAuthorization(t *testing.T) {
	repository := &coreRepository{transaction: newCoreTransaction()}
	sequence := 0
	service, err := NewAuthority(repository, Config{
		SessionLifetime: time.Hour,
		NewID: func(prefix string) (string, error) {
			sequence++
			return fmt.Sprintf("%s-test-%d", prefix, sequence), nil
		},
	})
	if err != nil {
		t.Fatalf("create IAM authority: %v", err)
	}
	document := coreBootstrap(t)
	status, err := service.Bootstrap(context.Background(), document)
	if err != nil || status.State != iamv1.BootstrapReady {
		t.Fatalf("bootstrap IAM: status=%#v err=%v", status, err)
	}
	replayed, err := service.Bootstrap(context.Background(), document)
	if err != nil || replayed != status {
		t.Fatalf("replay IAM bootstrap: status=%#v err=%v", replayed, err)
	}

	paasCredential := coreServiceCredential(t, document, iamv1.ServicePaaS)
	storedStatus, err := service.BootstrapStatus(context.Background(), paasCredential)
	if err != nil || storedStatus != status {
		t.Fatalf("read IAM bootstrap status: status=%#v err=%v", storedStatus, err)
	}
	identity, err := service.ServiceIdentity(context.Background(), paasCredential)
	if err != nil || identity.Purpose != iamv1.ServicePaaS || identity.PrincipalID != "service-paas" {
		t.Fatalf("resolve PaaS service identity: identity=%#v err=%v", identity, err)
	}
	verifierCredential := coreServiceCredential(t, document, iamv1.ServiceInstallationVerifier)
	verificationRequest := iamv1.AuthorizationRequest{
		Action: iamv1.ActionInstallationVerify,
		Resource: iamv1.ResourceReference{
			Kind: iamv1.ResourceInstallation, ID: document.InstallationID,
		},
		RequestID: "request-installation-verify", CorrelationID: "correlation-installation-verify",
	}
	verificationDecision, err := service.VerifyInstallation(
		context.Background(), verifierCredential, verificationRequest,
	)
	if err != nil || !verificationDecision.Allowed || verificationDecision.Subject == nil ||
		verificationDecision.Subject.Type != iamv1.PrincipalServiceAccount ||
		verificationDecision.Subject.ID != "service-verifier" {
		t.Fatalf("installation verification decision=%#v err=%v", verificationDecision, err)
	}
	verificationRequest.Resource.ID = "installation-other"
	verificationRequest.RequestID = "request-installation-other"
	verificationRequest.CorrelationID = verificationRequest.RequestID
	verificationDecision, err = service.VerifyInstallation(
		context.Background(), verifierCredential, verificationRequest,
	)
	if err != nil || verificationDecision.Allowed {
		t.Fatalf("cross-installation verification decision=%#v err=%v", verificationDecision, err)
	}
	verificationRequest.Resource.ID = document.InstallationID

	wrongPassword := coreSecret(t, "Wrong-Admin-Password-73!")
	if _, err := service.Login(context.Background(), iamv1.LoginRequest{
		LoginName: "admin", Password: wrongPassword, RequestID: "request-login-wrong",
	}); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("wrong password error = %v, want unauthenticated", err)
	}
	login, err := service.Login(context.Background(), iamv1.LoginRequest{
		LoginName: "admin",
		Password:  document.Administrator.Password,
		RequestID: "request-login",
	})
	if err != nil {
		t.Fatalf("log in initial administrator: %v", err)
	}
	if !login.MustChangePassword {
		t.Fatal("initial administrator login did not require a password change")
	}
	request := iamv1.AuthorizationRequest{
		Action:        iamv1.ActionPaaSApplicationCreate,
		Resource:      iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "application-example"},
		RequestID:     "request-authorize-before-password",
		CorrelationID: "correlation-authorize-before-password",
	}
	decision, err := service.Authorize(
		context.Background(),
		paasCredential,
		login.Credential,
		request,
	)
	if err != nil || decision.Allowed {
		t.Fatalf("initial administrator decision = %#v err=%v, want deny", decision, err)
	}

	changed, err := service.ChangePassword(context.Background(), login.Credential, iamv1.ChangePasswordRequest{
		CurrentPassword: document.Administrator.Password,
		NewPassword:     coreSecret(t, "Changed-Admin-Password-73!"),
		RequestID:       "request-admin-password-change",
	})
	if err != nil || !changed.BootstrapFileRetirable || changed.ChangedAt != repository.transaction.now {
		t.Fatalf("change bootstrap administrator password: response=%#v err=%v", changed, err)
	}
	request.RequestID = "request-authorize-allowed"
	request.CorrelationID = "correlation-authorize-allowed"
	decision, err = service.Authorize(
		context.Background(),
		paasCredential,
		login.Credential,
		request,
	)
	if err != nil || !decision.Allowed || decision.TenantID != "organization-example" ||
		decision.Subject == nil || decision.Subject.ID != "principal-admin" {
		t.Fatalf("PaaS decision = %#v err=%v, want allowed", decision, err)
	}

	request.RequestID = "request-authorize-wrong-service"
	request.CorrelationID = "correlation-authorize-wrong-service"
	decision, err = service.Authorize(
		context.Background(),
		coreServiceCredential(t, document, iamv1.ServiceAudit),
		login.Credential,
		request,
	)
	if err != nil || decision.Allowed {
		t.Fatalf("Audit-to-PaaS decision = %#v err=%v, want deny", decision, err)
	}

	created, err := service.CreateUser(context.Background(), login.Credential, iamv1.CreateUserRequest{
		LoginName:       "developer",
		DisplayName:     "Platform Developer",
		InitialPassword: coreSecret(t, "Initial-Developer-Password-84!"),
		RequestID:       "request-create-developer",
	})
	if err != nil || created.LoginName != "developer" || !created.MustChangePassword {
		t.Fatalf("create organization user: principal=%#v err=%v", created, err)
	}
	binding, err := service.PutRoleBinding(context.Background(), login.Credential, iamv1.PutRoleBindingRequest{
		PrincipalID: created.ID,
		Role:        iamv1.RolePaaSDeveloper,
		RequestID:   "request-bind-developer",
	})
	if err != nil || binding.PrincipalID != created.ID || binding.Role != iamv1.RolePaaSDeveloper {
		t.Fatalf("bind organization user: binding=%#v err=%v", binding, err)
	}
	developerLogin, err := service.Login(context.Background(), iamv1.LoginRequest{
		LoginName: "developer@organization-example",
		Password:  coreSecret(t, "Initial-Developer-Password-84!"),
		RequestID: "request-login-developer",
	})
	if err != nil {
		t.Fatalf("log in organization user: %v", err)
	}
	if !developerLogin.MustChangePassword {
		t.Fatal("initial organization user login did not require a password change")
	}
	request.RequestID = "request-developer-before-password"
	request.CorrelationID = request.RequestID
	decision, err = service.Authorize(context.Background(), paasCredential, developerLogin.Credential, request)
	if err != nil || decision.Allowed {
		t.Fatalf("initial developer decision=%#v err=%v, want deny", decision, err)
	}
	developerPassword, err := service.ChangePassword(
		context.Background(),
		developerLogin.Credential,
		iamv1.ChangePasswordRequest{
			CurrentPassword: coreSecret(t, "Initial-Developer-Password-84!"),
			NewPassword:     coreSecret(t, "Changed-Developer-Password-95!"),
			RequestID:       "request-developer-password-change",
		},
	)
	if err != nil || developerPassword.BootstrapFileRetirable {
		t.Fatalf("change organization user password: response=%#v err=%v", developerPassword, err)
	}
	request.RequestID = "request-developer-allowed"
	request.CorrelationID = request.RequestID
	decision, err = service.Authorize(context.Background(), paasCredential, developerLogin.Credential, request)
	if err != nil || !decision.Allowed || decision.Subject == nil || decision.Subject.ID != created.ID {
		t.Fatalf("developer decision=%#v err=%v, want allowed", decision, err)
	}
	revokedBinding, err := service.RevokeRoleBinding(
		context.Background(),
		login.Credential,
		binding.ID,
		iamv1.RevokeRoleBindingRequest{RequestID: "request-revoke-developer-binding"},
	)
	if err != nil || revokedBinding.ID != string(binding.ID) || revokedBinding.ResourceVersion != 2 {
		t.Fatalf("revoke developer binding: revocation=%#v err=%v", revokedBinding, err)
	}
	request.RequestID = "request-developer-after-binding-revoke"
	request.CorrelationID = request.RequestID
	decision, err = service.Authorize(context.Background(), paasCredential, developerLogin.Credential, request)
	if err != nil || decision.Allowed {
		t.Fatalf("revoked-role decision=%#v err=%v, want deny", decision, err)
	}
	revokedSession, err := service.RevokeSession(
		context.Background(),
		login.Credential,
		developerLogin.Session.ID,
		iamv1.RevokeSessionRequest{RequestID: "request-revoke-developer-session"},
	)
	if err != nil || revokedSession.ID != string(developerLogin.Session.ID) {
		t.Fatalf("revoke developer session: revocation=%#v err=%v", revokedSession, err)
	}
	request.RequestID = "request-developer-after-session-revoke"
	request.CorrelationID = request.RequestID
	if _, err := service.Authorize(context.Background(), paasCredential, developerLogin.Credential, request); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("revoked developer session error=%v, want unauthenticated", err)
	}
	verifierRevocation, err := service.RevokeRoleBinding(
		context.Background(),
		login.Credential,
		"bootstrap-verifier-binding",
		iamv1.RevokeRoleBindingRequest{RequestID: "request-revoke-verifier-binding"},
	)
	if err != nil || verifierRevocation.ID != "bootstrap-verifier-binding" {
		t.Fatalf("revoke installation verifier binding: revocation=%#v err=%v", verifierRevocation, err)
	}
	verificationRequest.RequestID = "request-installation-after-role-revoke"
	verificationRequest.CorrelationID = verificationRequest.RequestID
	verificationDecision, err = service.VerifyInstallation(
		context.Background(), verifierCredential, verificationRequest,
	)
	if err != nil || verificationDecision.Allowed {
		t.Fatalf("revoked installation verifier decision=%#v err=%v", verificationDecision, err)
	}
	logout, err := service.Logout(
		context.Background(), login.Credential, iamv1.LogoutRequest{RequestID: "request-admin-logout"},
	)
	if err != nil || logout.RevokedAt != repository.transaction.now {
		t.Fatalf("logout administrator: response=%#v err=%v", logout, err)
	}
	if len(repository.transaction.authorizations) != 14 {
		t.Fatalf("stored authorization decisions=%d want=14", len(repository.transaction.authorizations))
	}
	for _, mutation := range repository.transaction.authorizations {
		if mutation.AuditEvent.IAMDecisionID != auditv1.DecisionID(mutation.Decision.ID) ||
			mutation.AuditEvent.Target.ID != string(mutation.Decision.ID) ||
			mutation.AuditEvent.TenantID != "organization-example" {
			t.Fatalf("authorization Audit fact differs from decision: %#v", mutation)
		}
	}
	readiness, err := service.Readiness(context.Background())
	if err != nil || readiness.State != iamv1.ReadinessReady || readiness.CheckedAt != repository.transaction.now {
		t.Fatalf("IAM readiness = %#v err=%v", readiness, err)
	}
}

type coreRepository struct {
	transaction *coreTransaction
}

func (repository *coreRepository) WithinTransaction(
	ctx context.Context,
	callback func(context.Context, Transaction) error,
) error {
	return callback(ctx, repository.transaction)
}

type coreTransaction struct {
	Transaction
	now                time.Time
	status             iamv1.BootstrapStatus
	contentDigest      string
	organization       iamv1.Organization
	principal          iamv1.Principal
	services           map[string]ServiceCredential
	sessions           map[string]SessionCredential
	authorizations     []AuthorizationMutation
	passwords          map[iamv1.PrincipalID]authority.PasswordHash
	users              map[iamv1.PrincipalID]iamv1.Principal
	bindings           map[iamv1.RoleBindingID]iamv1.RoleBinding
	bindingRevocations map[iamv1.RoleBindingID]iamv1.Revocation
}

func newCoreTransaction() *coreTransaction {
	return &coreTransaction{
		now:                time.Date(2026, 8, 26, 8, 9, 10, 123000, time.UTC),
		services:           make(map[string]ServiceCredential),
		sessions:           make(map[string]SessionCredential),
		passwords:          make(map[iamv1.PrincipalID]authority.PasswordHash),
		users:              make(map[iamv1.PrincipalID]iamv1.Principal),
		bindings:           make(map[iamv1.RoleBindingID]iamv1.RoleBinding),
		bindingRevocations: make(map[iamv1.RoleBindingID]iamv1.Revocation),
	}
}

func (transaction *coreTransaction) TransactionTime(context.Context) (time.Time, error) {
	return transaction.now, nil
}

func (transaction *coreTransaction) BootstrapStatus(context.Context) (iamv1.BootstrapStatus, error) {
	if transaction.status.State == "" {
		return iamv1.BootstrapStatus{
			APIVersion: iamv1.APIVersion,
			Kind:       "BootstrapStatus",
			State:      iamv1.BootstrapUninitialized,
		}, nil
	}
	return transaction.status, nil
}

func (transaction *coreTransaction) ApplyBootstrap(
	_ context.Context,
	mutation BootstrapMutation,
) (authority.BootstrapOutcome, error) {
	if transaction.contentDigest != "" {
		if transaction.contentDigest != mutation.ContentDigest {
			return "", ErrConflict
		}
		return authority.BootstrapEqualReplay, nil
	}
	transaction.contentDigest = mutation.ContentDigest
	appliedAt := transaction.now
	transaction.status = iamv1.BootstrapStatus{
		APIVersion:     iamv1.APIVersion,
		Kind:           "BootstrapStatus",
		State:          iamv1.BootstrapReady,
		InstallationID: mutation.InstallationID,
		OrganizationID: mutation.Organization.ID,
		ContentDigest:  mutation.ContentDigest,
		AppliedAt:      &appliedAt,
	}
	transaction.organization = iamv1.Organization{
		APIVersion:      iamv1.APIVersion,
		Kind:            "Organization",
		ID:              mutation.Organization.ID,
		DisplayName:     mutation.Organization.DisplayName,
		Status:          iamv1.OrganizationActive,
		ResourceVersion: 1,
		CreatedAt:       transaction.now,
		UpdatedAt:       transaction.now,
	}
	transaction.principal = iamv1.Principal{
		APIVersion:         iamv1.APIVersion,
		Kind:               "Principal",
		ID:                 mutation.Administrator.ID,
		OrganizationID:     mutation.Organization.ID,
		Type:               iamv1.PrincipalUser,
		LoginName:          mutation.Administrator.LoginName,
		DisplayName:        mutation.Administrator.DisplayName,
		Status:             iamv1.PrincipalActive,
		MustChangePassword: true,
		ResourceVersion:    1,
		CreatedAt:          transaction.now,
		UpdatedAt:          transaction.now,
	}
	transaction.passwords[mutation.Administrator.ID] = mutation.Administrator.PasswordHash
	transaction.users[mutation.Administrator.ID] = transaction.principal
	transaction.bindings["bootstrap-admin-binding"] = iamv1.RoleBinding{
		APIVersion: iamv1.APIVersion, Kind: "RoleBinding", ID: "bootstrap-admin-binding",
		OrganizationID: mutation.Organization.ID, PrincipalID: mutation.Administrator.ID,
		Role: iamv1.RoleOrganizationAdmin, ResourceVersion: 1,
		CreatedAt: transaction.now, UpdatedAt: transaction.now,
	}
	transaction.bindings["bootstrap-platform-operator-binding"] = iamv1.RoleBinding{
		APIVersion: iamv1.APIVersion, Kind: "RoleBinding", ID: "bootstrap-platform-operator-binding",
		OrganizationID: mutation.Organization.ID, PrincipalID: mutation.Administrator.ID,
		Role: iamv1.RolePlatformOperator, ResourceVersion: 1,
		CreatedAt: transaction.now, UpdatedAt: transaction.now,
	}
	for _, service := range mutation.Services {
		transaction.services[service.LookupDigest] = ServiceCredential{
			Identity: iamv1.ServiceIdentity{
				APIVersion:     iamv1.APIVersion,
				Kind:           "ServiceIdentity",
				OrganizationID: mutation.Organization.ID,
				PrincipalID:    service.PrincipalID,
				Purpose:        service.Purpose,
			},
			VerificationDigest: service.VerificationDigest,
		}
		if service.Purpose == iamv1.ServiceInstallationVerifier {
			transaction.bindings["bootstrap-verifier-binding"] = iamv1.RoleBinding{
				APIVersion: iamv1.APIVersion, Kind: "RoleBinding", ID: "bootstrap-verifier-binding",
				OrganizationID: mutation.Organization.ID, PrincipalID: service.PrincipalID,
				Role: iamv1.RoleInstallationVerifier, ResourceVersion: 1,
				CreatedAt: transaction.now, UpdatedAt: transaction.now,
			}
		}
	}
	return authority.BootstrapApply, nil
}

func (transaction *coreTransaction) LookupLogin(
	_ context.Context,
	loginName string,
) (LoginAccount, bool, error) {
	localName, suffix, qualified := strings.Cut(loginName, "@")
	for principalID, principal := range transaction.users {
		primary := principalID == transaction.principal.ID
		if principal.LoginName != localName || qualified == primary || (qualified && suffix != string(principal.OrganizationID)) {
			continue
		}
		return LoginAccount{
			OrganizationID:     principal.OrganizationID,
			PrincipalID:        principalID,
			PasswordHash:       transaction.passwords[principalID],
			OrganizationStatus: transaction.organization.Status,
			PrincipalStatus:    principal.Status,
			MustChangePassword: principal.MustChangePassword,
		}, true, nil
	}
	return LoginAccount{}, false, nil
}

func (transaction *coreTransaction) IssueSession(
	_ context.Context,
	mutation SessionMutation,
) (iamv1.Session, error) {
	principal, found := transaction.users[mutation.Session.PrincipalID]
	if !found {
		return iamv1.Session{}, ErrUnauthenticated
	}
	roles := make([]iamv1.BuiltinRole, 0)
	for _, binding := range transaction.bindings {
		if _, revoked := transaction.bindingRevocations[binding.ID]; revoked {
			continue
		}
		if binding.PrincipalID == principal.ID {
			roles = append(roles, binding.Role)
		}
	}
	transaction.sessions[mutation.LookupDigest] = SessionCredential{
		Subject: authority.SubjectContext{
			Organization:           transaction.organization,
			Principal:              principal,
			Session:                mutation.Session,
			Roles:                  roles,
			BootstrapAdministrator: principal.ID == transaction.principal.ID,
		},
		VerificationDigest: mutation.VerificationDigest,
	}
	return mutation.Session, nil
}

func (transaction *coreTransaction) LookupSession(
	_ context.Context,
	lookupDigest string,
) (SessionCredential, bool, error) {
	binding, found := transaction.sessions[lookupDigest]
	if !found {
		return SessionCredential{}, false, nil
	}
	if binding.Subject.Session.Status != iamv1.SessionActive {
		return SessionCredential{}, false, nil
	}
	principal, found := transaction.users[binding.Subject.Principal.ID]
	if !found {
		return SessionCredential{}, false, nil
	}
	binding.Subject.Principal = principal
	binding.Subject.Roles = nil
	for _, roleBinding := range transaction.bindings {
		if _, revoked := transaction.bindingRevocations[roleBinding.ID]; revoked {
			continue
		}
		if roleBinding.PrincipalID == principal.ID {
			binding.Subject.Roles = append(binding.Subject.Roles, roleBinding.Role)
		}
	}
	return binding, true, nil
}

func (transaction *coreTransaction) LookupPassword(
	_ context.Context,
	organizationID iamv1.OrganizationID,
	principalID iamv1.PrincipalID,
) (authority.PasswordHash, bool, error) {
	if organizationID != transaction.organization.ID {
		return "", false, nil
	}
	password, found := transaction.passwords[principalID]
	return password, found, nil
}

func (transaction *coreTransaction) LookupService(
	_ context.Context,
	lookupDigest string,
) (ServiceCredential, bool, error) {
	binding, found := transaction.services[lookupDigest]
	return binding, found, nil
}

func (transaction *coreTransaction) LookupServiceRoles(
	_ context.Context,
	organizationID iamv1.OrganizationID,
	principalID iamv1.PrincipalID,
) ([]iamv1.BuiltinRole, error) {
	if organizationID != transaction.organization.ID {
		return nil, ErrUnavailable
	}
	roles := make([]iamv1.BuiltinRole, 0)
	for _, binding := range transaction.bindings {
		if _, revoked := transaction.bindingRevocations[binding.ID]; revoked {
			continue
		}
		if binding.OrganizationID == organizationID && binding.PrincipalID == principalID {
			roles = append(roles, binding.Role)
		}
	}
	return roles, nil
}

func (transaction *coreTransaction) RecordAuthorization(
	_ context.Context,
	mutation AuthorizationMutation,
) error {
	transaction.authorizations = append(transaction.authorizations, mutation)
	return nil
}

func (transaction *coreTransaction) ChangePassword(
	_ context.Context,
	mutation PasswordMutation,
) (iamv1.ChangePasswordResponse, error) {
	if transaction.passwords[mutation.PrincipalID] != mutation.ExpectedPasswordHash {
		return iamv1.ChangePasswordResponse{}, ErrRetryableTransaction
	}
	transaction.passwords[mutation.PrincipalID] = mutation.NewPasswordHash
	principal := transaction.users[mutation.PrincipalID]
	principal.MustChangePassword = false
	principal.ResourceVersion++
	principal.UpdatedAt = transaction.now
	transaction.users[mutation.PrincipalID] = principal
	if mutation.PrincipalID == transaction.principal.ID {
		transaction.principal = principal
	}
	return iamv1.ChangePasswordResponse{
		ChangedAt: transaction.now, BootstrapFileRetirable: mutation.PrincipalID == transaction.principal.ID,
	}, nil
}

func (transaction *coreTransaction) RevokeSession(
	_ context.Context,
	mutation SessionRevocationMutation,
) (iamv1.Revocation, bool, error) {
	for lookup, binding := range transaction.sessions {
		if binding.Subject.Session.ID != mutation.SessionID {
			continue
		}
		if binding.Subject.Session.Status == iamv1.SessionRevoked {
			return iamv1.Revocation{
				APIVersion: iamv1.APIVersion, Kind: "Revocation", ID: string(mutation.SessionID),
				ResourceVersion: 2, RevokedAt: *binding.Subject.Session.RevokedAt,
			}, false, nil
		}
		revokedAt := transaction.now
		binding.Subject.Session.Status = iamv1.SessionRevoked
		binding.Subject.Session.RevokedAt = &revokedAt
		transaction.sessions[lookup] = binding
		return iamv1.Revocation{
			APIVersion: iamv1.APIVersion, Kind: "Revocation", ID: string(mutation.SessionID),
			ResourceVersion: 2, RevokedAt: revokedAt,
		}, true, nil
	}
	return iamv1.Revocation{}, false, ErrForbidden
}

func (transaction *coreTransaction) CreateUser(
	_ context.Context,
	mutation UserMutation,
) (iamv1.Principal, error) {
	for _, existing := range transaction.users {
		if existing.LoginName == mutation.Principal.LoginName {
			return iamv1.Principal{}, ErrConflict
		}
	}
	transaction.users[mutation.Principal.ID] = mutation.Principal
	transaction.passwords[mutation.Principal.ID] = mutation.PasswordHash
	return mutation.Principal, nil
}

func (transaction *coreTransaction) PutRoleBinding(
	_ context.Context,
	mutation RoleBindingMutation,
) (iamv1.RoleBinding, bool, error) {
	if _, found := transaction.users[mutation.Binding.PrincipalID]; !found {
		return iamv1.RoleBinding{}, false, ErrForbidden
	}
	for _, existing := range transaction.bindings {
		if _, revoked := transaction.bindingRevocations[existing.ID]; revoked {
			continue
		}
		if existing.PrincipalID == mutation.Binding.PrincipalID && existing.Role == mutation.Binding.Role {
			return existing, false, nil
		}
	}
	transaction.bindings[mutation.Binding.ID] = mutation.Binding
	return mutation.Binding, true, nil
}

func (transaction *coreTransaction) LookupRoleBindingRole(
	_ context.Context,
	organizationID iamv1.OrganizationID,
	bindingID iamv1.RoleBindingID,
) (iamv1.BuiltinRole, bool, error) {
	binding, found := transaction.bindings[bindingID]
	if !found || binding.OrganizationID != organizationID {
		return "", false, nil
	}
	return binding.Role, true, nil
}

func (transaction *coreTransaction) RevokeRoleBinding(
	_ context.Context,
	mutation RoleBindingRevocationMutation,
) (iamv1.Revocation, bool, error) {
	if revoked, found := transaction.bindingRevocations[mutation.RoleBindingID]; found {
		return revoked, false, nil
	}
	binding, found := transaction.bindings[mutation.RoleBindingID]
	if !found {
		return iamv1.Revocation{}, false, ErrForbidden
	}
	revocation := iamv1.Revocation{
		APIVersion: iamv1.APIVersion, Kind: "Revocation", ID: string(binding.ID),
		ResourceVersion: binding.ResourceVersion + 1, RevokedAt: transaction.now,
	}
	transaction.bindingRevocations[mutation.RoleBindingID] = revocation
	return revocation, true, nil
}

func (transaction *coreTransaction) Readiness(context.Context) (ReadinessSnapshot, error) {
	return ReadinessSnapshot{
		Ready:         transaction.status.State == iamv1.BootstrapReady,
		SchemaVersion: 1,
		CheckedAt:     transaction.now,
	}, nil
}

func coreBootstrap(t *testing.T) iamv1.BootstrapDocument {
	t.Helper()
	service := func(purpose iamv1.ServicePurpose, principalID, credential string) iamv1.BootstrapServiceCredential {
		return iamv1.BootstrapServiceCredential{
			Purpose:     purpose,
			PrincipalID: iamv1.PrincipalID(principalID),
			Credential:  coreSecret(t, credential),
		}
	}
	return iamv1.BootstrapDocument{
		APIVersion:     iamv1.APIVersion,
		Kind:           "IAMBootstrap",
		InstallationID: "installation-example",
		Organization:   iamv1.InitialOrganization{ID: "organization-example", DisplayName: "Example Organization"},
		Administrator: iamv1.InitialAdministrator{
			ID:          "principal-admin",
			LoginName:   "admin",
			DisplayName: "Initial Administrator",
			Password:    coreSecret(t, "Initial-Admin-Password-49!"),
		},
		Services: []iamv1.BootstrapServiceCredential{
			service(iamv1.ServiceIAM, "service-iam", "mx1.IAMCoreCredential00000000000000000000001"),
			service(iamv1.ServicePaaS, "service-paas", "mx1.PaaSCoreCredential0000000000000000000001"),
			service(iamv1.ServiceAudit, "service-audit", "mx1.AuditCoreCredential000000000000000000001"),
			service(iamv1.ServiceInstallationVerifier, "service-verifier", "mx1.VerifierCoreCredential000000000000000001"),
		},
	}
}

func coreServiceCredential(
	t *testing.T,
	document iamv1.BootstrapDocument,
	purpose iamv1.ServicePurpose,
) iamv1.Secret {
	t.Helper()
	for _, service := range document.Services {
		if service.Purpose == purpose {
			return service.Credential
		}
	}
	t.Fatalf("bootstrap service purpose %q is absent", purpose)
	return iamv1.Secret{}
}

func coreSecret(t *testing.T, value string) iamv1.Secret {
	t.Helper()
	secret, err := iamv1.NewSecret(value)
	if err != nil {
		t.Fatalf("create IAM test secret: %v", err)
	}
	return secret
}
