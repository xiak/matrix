package identityaccess

import (
	"context"
	"errors"
	"time"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/iam/internal/authority"
)

var (
	ErrInvalidArgument      = errors.New("IAM argument is invalid")
	ErrUnauthenticated      = errors.New("IAM authentication failed")
	ErrForbidden            = errors.New("IAM authorization denied")
	ErrConflict             = errors.New("IAM state conflicts with the request")
	ErrUnavailable          = errors.New("IAM authority is unavailable")
	ErrRetryableTransaction = errors.New("IAM transaction is retryable")
)

type Config struct {
	SessionLifetime        time.Duration
	MaxTransactionAttempts int
	NewID                  func(prefix string) (string, error)
}

type Repository interface {
	WithinTransaction(
		context.Context,
		func(context.Context, Transaction) error,
	) error
}

type Transaction interface {
	TransactionTime(context.Context) (time.Time, error)
	BootstrapStatus(context.Context) (iamv1.BootstrapStatus, error)
	ApplyBootstrap(context.Context, BootstrapMutation) (authority.BootstrapOutcome, error)
	LookupLogin(context.Context, string) (LoginAccount, bool, error)
	IssueSession(context.Context, SessionMutation) (iamv1.Session, error)
	LookupSession(context.Context, string) (SessionCredential, bool, error)
	LookupPassword(context.Context, iamv1.OrganizationID, iamv1.PrincipalID) (authority.PasswordHash, bool, error)
	LookupService(context.Context, string) (ServiceCredential, bool, error)
	RecordAuthorization(context.Context, AuthorizationMutation) error
	ChangePassword(context.Context, PasswordMutation) (iamv1.ChangePasswordResponse, error)
	RevokeSession(context.Context, SessionRevocationMutation) (iamv1.Revocation, bool, error)
	CreateUser(context.Context, UserMutation) (iamv1.Principal, error)
	PutRoleBinding(context.Context, RoleBindingMutation) (iamv1.RoleBinding, bool, error)
	RevokeRoleBinding(context.Context, RoleBindingRevocationMutation) (iamv1.Revocation, bool, error)
	Readiness(context.Context) (ReadinessSnapshot, error)
}

type BootstrapAdministrator struct {
	ID           iamv1.PrincipalID
	LoginName    string
	DisplayName  string
	PasswordHash authority.PasswordHash
}

type BootstrapService struct {
	Purpose            iamv1.ServicePurpose `json:"purpose"`
	PrincipalID        iamv1.PrincipalID    `json:"principalId"`
	LookupDigest       string               `json:"lookupDigest"`
	VerificationDigest string               `json:"verificationDigest"`
}

type BootstrapMutation struct {
	InstallationID string
	ContentDigest  string
	Organization   iamv1.InitialOrganization
	Administrator  BootstrapAdministrator
	Services       []BootstrapService
	AuditEvent     auditv1.Event
}

type LoginAccount struct {
	OrganizationID     iamv1.OrganizationID
	PrincipalID        iamv1.PrincipalID
	PasswordHash       authority.PasswordHash
	OrganizationStatus iamv1.OrganizationStatus
	PrincipalStatus    iamv1.PrincipalStatus
	MustChangePassword bool
}

type SessionMutation struct {
	Session            iamv1.Session
	LookupDigest       string
	VerificationDigest string
	AuditEvent         auditv1.Event
}

type SessionCredential struct {
	Subject            authority.SubjectContext
	VerificationDigest string
}

type ServiceCredential struct {
	Identity           iamv1.ServiceIdentity
	VerificationDigest string
}

type AuthorizationMutation struct {
	OrganizationID iamv1.OrganizationID
	PrincipalID    iamv1.PrincipalID
	Decision       iamv1.AuthorizationDecision
	AuditEvent     auditv1.Event
}

type PasswordMutation struct {
	OrganizationID       iamv1.OrganizationID
	PrincipalID          iamv1.PrincipalID
	ExpectedPasswordHash authority.PasswordHash
	NewPasswordHash      authority.PasswordHash
	AuditEvent           auditv1.Event
}

type SessionRevocationMutation struct {
	OrganizationID   iamv1.OrganizationID
	SessionID        iamv1.SessionID
	ActorPrincipalID iamv1.PrincipalID
	DecisionID       iamv1.DecisionID
	AuditEvent       auditv1.Event
}

type UserMutation struct {
	Principal        iamv1.Principal
	PasswordHash     authority.PasswordHash
	ActorPrincipalID iamv1.PrincipalID
	DecisionID       iamv1.DecisionID
	AuditEvent       auditv1.Event
}

type RoleBindingMutation struct {
	Binding          iamv1.RoleBinding
	ActorPrincipalID iamv1.PrincipalID
	DecisionID       iamv1.DecisionID
	AuditEvent       auditv1.Event
}

type RoleBindingRevocationMutation struct {
	OrganizationID   iamv1.OrganizationID
	RoleBindingID    iamv1.RoleBindingID
	ActorPrincipalID iamv1.PrincipalID
	DecisionID       iamv1.DecisionID
	AuditEvent       auditv1.Event
}

type ReadinessSnapshot struct {
	Ready         bool
	SchemaVersion uint64
	CheckedAt     time.Time
}

type Authority struct {
	repository  Repository
	config      Config
	passwords   *authority.PasswordHasher
	credentials *authority.CredentialIssuer
}
