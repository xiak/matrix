package identityaccess

import (
	"context"
	"errors"
	"fmt"
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

	paasCredential := document.Services[1].Credential
	storedStatus, err := service.BootstrapStatus(context.Background(), paasCredential)
	if err != nil || storedStatus != status {
		t.Fatalf("read IAM bootstrap status: status=%#v err=%v", storedStatus, err)
	}
	identity, err := service.ServiceIdentity(context.Background(), paasCredential)
	if err != nil || identity.Purpose != iamv1.ServicePaaS || identity.PrincipalID != "service-paas" {
		t.Fatalf("resolve PaaS service identity: identity=%#v err=%v", identity, err)
	}

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

	repository.transaction.mustChangePassword = false
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
		document.Services[2].Credential,
		login.Credential,
		request,
	)
	if err != nil || decision.Allowed {
		t.Fatalf("Audit-to-PaaS decision = %#v err=%v, want deny", decision, err)
	}
	if len(repository.transaction.authorizations) != 3 {
		t.Fatalf("stored authorization decisions=%d want=3", len(repository.transaction.authorizations))
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
	now                time.Time
	status             iamv1.BootstrapStatus
	contentDigest      string
	account            LoginAccount
	organization       iamv1.Organization
	principal          iamv1.Principal
	mustChangePassword bool
	services           map[string]ServiceCredential
	sessions           map[string]SessionCredential
	authorizations     []AuthorizationMutation
}

func newCoreTransaction() *coreTransaction {
	return &coreTransaction{
		now:      time.Date(2026, 8, 26, 8, 9, 10, 123000, time.UTC),
		services: make(map[string]ServiceCredential),
		sessions: make(map[string]SessionCredential),
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
	transaction.mustChangePassword = true
	transaction.account = LoginAccount{
		OrganizationID:     mutation.Organization.ID,
		PrincipalID:        mutation.Administrator.ID,
		PasswordHash:       mutation.Administrator.PasswordHash,
		OrganizationStatus: iamv1.OrganizationActive,
		PrincipalStatus:    iamv1.PrincipalActive,
		MustChangePassword: true,
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
	}
	return authority.BootstrapApply, nil
}

func (transaction *coreTransaction) LookupLogin(
	_ context.Context,
	loginName string,
) (LoginAccount, bool, error) {
	if loginName != transaction.principal.LoginName {
		return LoginAccount{}, false, nil
	}
	return transaction.account, true, nil
}

func (transaction *coreTransaction) IssueSession(
	_ context.Context,
	mutation SessionMutation,
) (iamv1.Session, error) {
	transaction.sessions[mutation.LookupDigest] = SessionCredential{
		Subject: authority.SubjectContext{
			Organization: transaction.organization,
			Principal:    transaction.principal,
			Session:      mutation.Session,
			Roles:        []iamv1.BuiltinRole{iamv1.RoleOrganizationAdmin},
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
	binding.Subject.Principal.MustChangePassword = transaction.mustChangePassword
	return binding, true, nil
}

func (transaction *coreTransaction) LookupService(
	_ context.Context,
	lookupDigest string,
) (ServiceCredential, bool, error) {
	binding, found := transaction.services[lookupDigest]
	return binding, found, nil
}

func (transaction *coreTransaction) RecordAuthorization(
	_ context.Context,
	mutation AuthorizationMutation,
) error {
	transaction.authorizations = append(transaction.authorizations, mutation)
	return nil
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
			service(iamv1.ServiceAPISIX, "service-apisix", "mx1.APISIXCoreCredential0000000000000000001"),
			service(iamv1.ServiceInstallationVerifier, "service-verifier", "mx1.VerifierCoreCredential000000000000000001"),
		},
	}
}

func coreSecret(t *testing.T, value string) iamv1.Secret {
	t.Helper()
	secret, err := iamv1.NewSecret(value)
	if err != nil {
		t.Fatalf("create IAM test secret: %v", err)
	}
	return secret
}
