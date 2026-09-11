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
	LookupPassword(context.Context, iamv1.AccountID, iamv1.PrincipalID) (authority.PasswordHash, bool, error)
	LookupService(context.Context, string) (ServiceCredential, bool, error)
	ReadAuditEvidence(context.Context, iamv1.ServiceIdentity, auditv1.Event) (AuditEvidence, bool, error)
	LookupServicePolicies(
		context.Context,
		iamv1.AccountID,
		iamv1.PrincipalID,
	) ([]authority.AttachedPolicy, error)
	RecordAuthorization(context.Context, AuthorizationMutation) error
	ChangePassword(context.Context, PasswordMutation) (iamv1.ChangePasswordResponse, error)
	RevokeSession(context.Context, SessionRevocationMutation) (iamv1.Revocation, bool, error)
	CreateUser(context.Context, UserMutation) (iamv1.User, error)
	LookupPolicy(context.Context, iamv1.AccountID, iamv1.PolicyID) (iamv1.Policy, bool, error)
	LookupPolicyAttachment(context.Context, iamv1.AccountID, iamv1.PolicyAttachmentID) (iamv1.PolicyAttachment, bool, error)
	CreatePolicyAttachment(context.Context, PolicyAttachmentMutation) (iamv1.PolicyAttachment, error)
	RevokePolicyAttachment(context.Context, PolicyAttachmentRevocationMutation) (iamv1.Revocation, bool, error)
	ReadAccount(context.Context, iamv1.AccountID, iamv1.PrincipalID) (iamv1.Account, error)
	ListUsers(context.Context, AccountRead) (iamv1.UserList, error)
	ListPolicies(context.Context, AccountRead, iamv1.AuthorityScope) (iamv1.PolicyList, error)
	ListAccounts(context.Context, AccountRead) (AccountManagementPage, error)
	ReadAccountAsPlatform(context.Context, AccountRead, iamv1.AccountID) (AccountManagementSnapshot, error)
	ReadAccountRoot(context.Context, AccountRead, iamv1.AccountID) (iamv1.RootIdentity, error)
	CreateAccount(context.Context, AccountMutation) (iamv1.Account, error)
	SetAccountStatus(context.Context, AccountStatusMutation) (iamv1.Account, error)
	RecoverRootCredentials(context.Context, RootCredentialRecovery) (iamv1.Account, error)
	InspectLocalCredentialRecovery(context.Context, iamv1.LocalCredentialRecoveryScope, *iamv1.LocalCredentialRecoveryReceiptQuery) (iamv1.LocalCredentialRecoveryInspection, error)
	RecoverLocalCredentials(context.Context, LocalCredentialRecoveryMutation) (iamv1.LocalCredentialRecoveryResult, error)
	SetAccountAlias(context.Context, AccountAliasMutation) (iamv1.Account, error)
	ChangeUser(context.Context, UserChange) (iamv1.User, error)
	Readiness(context.Context) (ReadinessSnapshot, error)
}

type AccountRead struct {
	AccountID        iamv1.AccountID
	ActorPrincipalID iamv1.PrincipalID
	DecisionID       iamv1.DecisionID
	After            string
}

// AccountManagementSnapshot carries only target facts required to project
// management availability. They are not public authorization grants; every
// command rechecks the same facts under its transaction locks.
type AccountManagementSnapshot struct {
	Account                      iamv1.Account
	SystemAccount                bool
	RootHasInstallationAuthority bool
}

type AccountManagementPage struct {
	Items     []AccountManagementSnapshot
	NextAfter string
}

type AccountMutation struct {
	ActorAccountID   iamv1.AccountID
	ActorPrincipalID iamv1.PrincipalID
	DecisionID       iamv1.DecisionID
	Account          iamv1.InitialOrganization
	Root             BootstrapAdministrator
	AuditEvent       auditv1.Event
}

type AccountAliasMutation struct {
	AccountID        iamv1.AccountID
	ActorPrincipalID iamv1.PrincipalID
	DecisionID       iamv1.DecisionID
	Alias            string
	ResourceVersion  uint64
	AuditEvent       auditv1.Event
}

type AccountStatusMutation struct {
	ActorAccountID   iamv1.AccountID
	ActorPrincipalID iamv1.PrincipalID
	DecisionID       iamv1.DecisionID
	AccountID        iamv1.AccountID
	Status           iamv1.AccountStatus
	ResourceVersion  uint64
	AuditEvent       auditv1.Event
}

type RootCredentialRecovery struct {
	ActorAccountID   iamv1.AccountID
	ActorPrincipalID iamv1.PrincipalID
	DecisionID       iamv1.DecisionID
	AccountID        iamv1.AccountID
	PrincipalID      iamv1.PrincipalID
	ResourceVersion  uint64
	PasswordHash     authority.PasswordHash
	AttachmentID     iamv1.PolicyAttachmentID
	AuditEvent       auditv1.Event
}

// The local entry authenticates this mutation with installation-private
// authority, never a USER decision or an existing service credential.
type LocalCredentialRecoveryMutation struct {
	Scope           iamv1.LocalCredentialRecoveryScope
	Expected        iamv1.LocalCredentialRecoveryExpected
	CommandID       string
	InputCommitment string
	PasswordHash    authority.PasswordHash
	AuditEvent      auditv1.Event
}

type UserChange struct {
	AccountID        iamv1.AccountID
	ActorPrincipalID iamv1.PrincipalID
	PrincipalID      iamv1.PrincipalID
	DecisionID       iamv1.DecisionID
	ResourceVersion  uint64
	Status           *iamv1.PrincipalStatus
	PasswordHash     *authority.PasswordHash
	AuditEvent       auditv1.Event
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
	AccountID          iamv1.AccountID
	PrincipalID        iamv1.PrincipalID
	PasswordHash       authority.PasswordHash
	AccountStatus      iamv1.AccountStatus
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
	AccountID      iamv1.AccountID
	PrincipalID    iamv1.PrincipalID
	Decision       iamv1.AuthorizationDecision
	PolicyEvidence []authority.PolicyAttachmentEvidence
	AuditEvent     auditv1.Event
}

type PasswordMutation struct {
	AccountID            iamv1.AccountID
	PrincipalID          iamv1.PrincipalID
	SessionID            iamv1.SessionID
	RevokeOtherSessions  bool
	ExpectedPasswordHash authority.PasswordHash
	NewPasswordHash      authority.PasswordHash
	AuditEvent           auditv1.Event
}

type SessionRevocationMutation struct {
	AccountID        iamv1.AccountID
	SessionID        iamv1.SessionID
	ActorPrincipalID iamv1.PrincipalID
	DecisionID       iamv1.DecisionID
	AuditEvent       auditv1.Event
}

type UserMutation struct {
	User             iamv1.User
	PasswordHash     authority.PasswordHash
	ActorPrincipalID iamv1.PrincipalID
	DecisionID       iamv1.DecisionID
	AuditEvent       auditv1.Event
}

type PolicyAttachmentMutation struct {
	Attachment            iamv1.PolicyAttachment
	PolicyResourceVersion uint64
	ActorPrincipalID      iamv1.PrincipalID
	DecisionID            iamv1.DecisionID
	AuditEvent            auditv1.Event
}

type PolicyAttachmentRevocationMutation struct {
	AccountID        iamv1.AccountID
	AttachmentID     iamv1.PolicyAttachmentID
	ResourceVersion  uint64
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
