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
	ErrOverloaded           = errors.New("IAM authentication work is at capacity")
	ErrVerificationRejected = errors.New("IAM address verification was rejected")
	ErrRetryableTransaction = errors.New("IAM transaction is retryable")
)

type Config struct {
	SessionLifetime          time.Duration
	MaxTransactionAttempts   int
	NewID                    func(prefix string) (string, error)
	CursorKey                []byte
	AccessKeyWrapping        *iamv1.AccessKeyWrappingKeyring
	TOTPKeyring              *iamv1.TOTPKeyring
	EmailVerificationKeyring *iamv1.EmailVerificationKeyring
}

type Repository interface {
	WithinTransaction(
		context.Context,
		func(context.Context, Transaction) error,
	) error
}

type Transaction interface {
	TransactionTime(context.Context) (time.Time, error)
	CheckCurrentAuthorizationProfiles(context.Context) error
	ReadAccessKeyCustody(context.Context) (AccessKeyCustody, error)
	RegisterTOTPKeyset(context.Context, TOTPKeysetRegistration) error
	ReadTOTPCustody(context.Context) (TOTPCustody, error)
	RegisterEmailVerificationKeyset(context.Context, authority.EmailVerificationKeyset) error
	ReadEmailVerificationKeyset(context.Context) (*authority.EmailVerificationKeyset, error)
	ReadNotificationContact(context.Context, NotificationContactSubject) (iamv1.NotificationContact, error)
	ReadNotificationVerification(context.Context, NotificationContactSubject, string) (iamv1.NotificationContactVerification, error)
	StartNotificationVerification(context.Context, NotificationVerificationStart) (iamv1.NotificationContactVerification, error)
	ReserveNotificationConfirmation(context.Context, NotificationContactSubject, string, string) (NotificationConfirmationAttempt, bool, error)
	RejectNotificationConfirmation(context.Context, NotificationConfirmationAttempt) error
	ConfirmNotificationContact(context.Context, NotificationConfirmation) (iamv1.NotificationContactVerification, error)
	LookupAccessKey(context.Context, string, iamv1.AccessKeyID, string, iamv1.ProductID) (AccessKeyCredential, bool, error)
	ReadAccessKeys(context.Context, AccessKeyRead) (AccessKeyDirectory, error)
	ReserveAccessKey(context.Context, AccessKeyReservation) (AccessKeyReservationResult, error)
	CompleteAccessKey(context.Context, AccessKeyCompletion) (AccessKeyMutationResult, error)
	ChangeAccessKey(context.Context, AccessKeyChange) (AccessKeyMutationResult, error)
	LookupAuthorizationProfile(context.Context, iamv1.AuthorizationProfileReference) (iamv1.AuthorizationProfile, bool, error)
	BootstrapStatus(context.Context) (iamv1.BootstrapStatus, error)
	ApplyBootstrap(context.Context, BootstrapMutation) (authority.BootstrapOutcome, error)
	ReservePasswordAttempt(context.Context, PasswordAttemptRequest) (PasswordAttempt, bool, error)
	RejectPasswordAttempt(context.Context, PasswordAttempt) error
	ReadLoginAuthenticationState(context.Context, iamv1.AccountID, iamv1.PrincipalID) (LoginAuthenticationState, error)
	ReadAuthenticatorState(context.Context, iamv1.Session) (iamv1.AuthenticatorState, error)
	StartTOTPEnrollment(context.Context, TOTPEnrollmentStart) (TOTPEnrollmentStartResult, error)
	ReadTOTPEnrollment(context.Context, iamv1.Session, string) (iamv1.TOTPEnrollment, error)
	ReadTOTPEnrollmentByRequest(context.Context, iamv1.Session, string) (iamv1.TOTPEnrollment, error)
	CancelTOTPEnrollment(context.Context, iamv1.Session, string) (iamv1.TOTPEnrollment, error)
	ConfirmTOTPEnrollment(context.Context, TOTPEnrollmentConfirmation) (iamv1.TOTPEnrollment, error)
	CreateLoginChallenge(context.Context, LoginChallengeCreation) (iamv1.AuthenticationChallenge, error)
	LookupAuthenticationChallenge(context.Context, string) (AuthenticationChallengeCredential, bool, error)
	ReserveTOTPAttempt(context.Context, TOTPAttempt) (TOTPAttempt, bool, error)
	ReadTOTPAttempt(context.Context, TOTPAttempt) (TOTPVerification, error)
	RejectTOTPAttempt(context.Context, TOTPAttempt) error
	CompleteLoginChallenge(context.Context, LoginChallengeCompletion) (iamv1.Session, error)
	BeginPasswordChallenge(context.Context, PasswordChallengeCreation) (iamv1.AuthenticationChallenge, error)
	ReadPasswordChallenge(context.Context, AuthenticationChallengeCredential) (ChallengePasswordMaterial, error)
	ChangeChallengePassword(context.Context, ChallengePasswordMutation) (iamv1.ChallengePasswordChangeResponse, error)
	IssueSession(context.Context, SessionMutation) (iamv1.Session, error)
	LookupSession(context.Context, string) (SessionCredential, bool, error)
	ListOwnSessions(context.Context, OwnSessionRead) ([]iamv1.Session, error)
	LookupRoleSession(context.Context, string) (RoleSessionCredential, bool, error)
	LookupRoleSessionForExit(context.Context, string) (RoleSessionExitCredential, bool, error)
	ExitRoleSession(context.Context, string, auditv1.Event) (iamv1.RoleSession, error)
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
	RevokeOtherSessions(context.Context, OtherSessionRevocationMutation) (iamv1.RevokeOtherSessionsResponse, error)
	CreateUser(context.Context, UserMutation) (iamv1.User, error)
	LookupPolicy(context.Context, iamv1.AccountID, iamv1.PolicyID) (iamv1.Policy, bool, error)
	LookupPolicyAttachment(context.Context, iamv1.AccountID, iamv1.PolicyAttachmentID) (iamv1.PolicyAttachment, bool, error)
	CreatePolicyAttachment(context.Context, PolicyAttachmentMutation) (iamv1.PolicyAttachment, error)
	RevokePolicyAttachment(context.Context, PolicyAttachmentRevocationMutation) (iamv1.Revocation, bool, error)
	ReadAccount(context.Context, iamv1.AccountID, iamv1.PrincipalID) (iamv1.Account, error)
	ListUsers(context.Context, AccountRead) (iamv1.UserList, error)
	ReadUser(context.Context, AccountRead, iamv1.PrincipalID) (iamv1.UserAccess, error)
	ListGroups(context.Context, AccountRead) (iamv1.GroupList, error)
	ReadGroup(context.Context, GroupRead) (iamv1.GroupAccess, error)
	ListRoles(context.Context, AccountRead) (iamv1.RoleList, error)
	ReadRole(context.Context, RoleRead) (iamv1.RoleAccess, error)
	ReadRoleDiscoveryRevision(context.Context, RoleDiscoveryRead) (authority.RoleDiscoveryRevision, error)
	ReadRoleCandidates(context.Context, RoleDiscoveryRead) (RoleCandidates, error)
	ReadRolePermissionBoundary(context.Context, RoleRead) (iamv1.RolePermissionBoundary, error)
	ReadRoleAssumption(context.Context, RoleAssumptionRead) (RoleAssumption, error)
	IssueRoleSession(context.Context, RoleSessionIssuance) (iamv1.RoleSession, error)
	ReadRoleSessionByRequest(context.Context, RoleAssumptionRead) (iamv1.RoleSession, bool, error)
	RevokeRoleSessionByRequest(context.Context, RoleSessionRevocation) (iamv1.RoleSession, error)
	PrepareRoleSessionManagement(context.Context, RoleSessionManagementTarget, bool) (authority.RoleSessionDirectoryRevision, error)
	ListManagedRoleSessions(context.Context, RoleSessionManagementRead) (ManagedRoleSessionPage, error)
	ReadManagedRoleSession(context.Context, RoleSessionManagementRead) (ManagedRoleSession, error)
	RevokeManagedRoleSession(context.Context, RoleSessionAdministrativeRevocation) (iamv1.RevokeRoleSessionResponse, error)
	ChangeRolePermissionBoundary(context.Context, RoleBoundaryMutation) (iamv1.RolePermissionBoundary, error)
	CreateRole(context.Context, RoleCreation) (iamv1.Role, error)
	UpdateRole(context.Context, RoleProfileMutation) (iamv1.Role, error)
	SetRoleStatus(context.Context, RoleStatusMutation) (iamv1.Role, error)
	SetRoleTrustPolicy(context.Context, RoleTrustMutation) (iamv1.Role, error)
	DeleteRole(context.Context, RoleMutation) (iamv1.RoleDeletion, error)
	ListRoleTrustVersions(context.Context, RoleRead) (iamv1.RoleTrustVersionList, error)
	ReadRoleTrustVersion(context.Context, RoleRead, iamv1.RoleTrustVersionID) (iamv1.RoleTrustVersion, error)
	CreateGroup(context.Context, GroupMutation) (iamv1.Group, error)
	UpdateGroup(context.Context, GroupProfileMutation) (iamv1.Group, error)
	DeleteGroup(context.Context, GroupDeletionMutation) (iamv1.GroupDeletion, error)
	ListGroupMemberships(context.Context, GroupRead) (iamv1.GroupMembershipList, error)
	CreateGroupMembership(context.Context, GroupMembershipMutation) (iamv1.GroupMembership, error)
	RemoveGroupMembership(context.Context, GroupMembershipRemovalMutation) (iamv1.GroupMembership, bool, error)
	ListPolicies(context.Context, AccountRead, iamv1.AuthorityScope) (iamv1.PolicyList, error)
	ReadPolicy(context.Context, AccountRead, iamv1.PolicyID) (iamv1.PolicyDetail, error)
	ReadUserPermissionBoundary(context.Context, AccountRead, iamv1.PrincipalID) (iamv1.UserPermissionBoundary, error)
	ChangeUserPermissionBoundary(context.Context, UserBoundaryMutation) (iamv1.UserPermissionBoundary, error)
	CreatePolicy(context.Context, PolicyCreation) (iamv1.PolicyDetail, error)
	ListPolicyVersions(context.Context, AccountRead, iamv1.PolicyID) (iamv1.PolicyVersionList, error)
	ReadPolicyVersion(context.Context, AccountRead, iamv1.PolicyID, iamv1.PolicyVersionID) (iamv1.PolicyVersionDetail, error)
	CreatePolicyVersion(context.Context, PolicyVersionCreation) (iamv1.PolicyVersionDetail, error)
	DeletePolicyVersion(context.Context, PolicyVersionDeletion) (iamv1.PolicyDetail, error)
	SetDefaultPolicyVersion(context.Context, PolicyDefaultSelection) (iamv1.PolicyDetail, error)
	UpdatePolicy(context.Context, PolicyUpdate) (iamv1.PolicyDetail, error)
	DeletePolicy(context.Context, PolicyDeletion) (iamv1.Policy, error)
	ListAccounts(context.Context, AccountRead) (AccountManagementPage, error)
	ReadAccountAsPlatform(context.Context, AccountRead, iamv1.AccountID) (AccountManagementSnapshot, error)
	ReadAccountRoot(context.Context, AccountRead, iamv1.AccountID) (iamv1.RootIdentity, error)
	CreateAccount(context.Context, AccountMutation) (iamv1.Account, error)
	SetAccountStatus(context.Context, AccountStatusMutation) (iamv1.Account, error)
	RecoverRootCredentials(context.Context, RootCredentialRecovery) (iamv1.Account, error)
	InspectLocalCredentialRecovery(context.Context, iamv1.LocalCredentialRecoveryScope, *iamv1.LocalCredentialRecoveryReceiptQuery) (iamv1.LocalCredentialRecoveryInspection, error)
	RecoverLocalCredentials(context.Context, LocalCredentialRecoveryMutation) (iamv1.LocalCredentialRecoveryResult, error)
	SetAccountAlias(context.Context, AccountAliasMutation) (iamv1.Account, error)
	UpdateUser(context.Context, UserProfileMutation) (iamv1.User, error)
	DeleteUser(context.Context, UserDeletionMutation) (iamv1.UserDeletion, error)
	ChangeUser(context.Context, UserChange) (iamv1.User, error)
	Readiness(context.Context) (ReadinessSnapshot, error)
}

type AccountRead struct {
	AccountID        iamv1.AccountID
	ActorPrincipalID iamv1.PrincipalID
	DecisionID       iamv1.DecisionID
	After            string
}

// Private, nonsecret custody evidence; never a caller-selected installation.
type AccessKeyCustody struct {
	InstallationID  string `json:"installationId"`
	BootstrapDigest string `json:"bootstrapDigest"`
	Keys            []struct {
		WrappingKeyID      string `json:"wrappingKeyId"`
		MaterialCommitment string `json:"materialCommitment"`
	} `json:"keys"`
}

type AccessKeyRead struct {
	AccountID      iamv1.AccountID
	ActorID        iamv1.PrincipalID
	ActorSessionID iamv1.SessionID
	UserID         iamv1.PrincipalID
	KeyID          iamv1.AccessKeyID
	DecisionID     iamv1.DecisionID
}

type AccessKeyDirectory struct {
	UserResourceVersion uint64                `json:"userResourceVersion"`
	UserStatus          iamv1.PrincipalStatus `json:"userStatus"`
	MustChangePassword  bool                  `json:"mustChangePassword"`
	Keys                []iamv1.AccessKey     `json:"keys"`
}

type AccessKeyReservation struct {
	AccessKeyRead
	ExpectedUserVersion uint64
	InstallationID      string
	WrappingKeyID       string
	MaterialCommitment  string
	RequestID           string
	RequestDigest       string
}

type AccessKeyReservationResult struct {
	Outcome string           `json:"outcome"`
	Key     *iamv1.AccessKey `json:"key,omitempty"`
}

type AccessKeyCompletion struct {
	AccessKeyRead
	Material   authority.SealedAccessKeySecret
	AuditEvent auditv1.Event
}

type AccessKeyChange struct {
	AccessKeyRead
	ExpectedVersion uint64
	Status          iamv1.AccessKeyStatus // Empty only for irreversible deletion.
	AuditEvent      auditv1.Event
}

type AccessKeyMutationResult struct {
	Outcome  string                   `json:"outcome"`
	Key      *iamv1.AccessKey         `json:"key,omitempty"`
	Deletion *iamv1.AccessKeyDeletion `json:"deletion,omitempty"`
}

type GroupRead struct {
	AccountRead
	GroupID iamv1.GroupID
}

type RoleRead struct {
	AccountRead
	RoleID iamv1.RoleID
}

// Private authenticated references, not public account/user/session selectors.
// RoleID selects one already-authorized management detail; otherwise After is
// the decoded self-directory position. Neither is an issuance request ID.
type RoleDiscoveryRead struct {
	AccountID        iamv1.AccountID
	ActorPrincipalID iamv1.PrincipalID
	ActorSessionID   iamv1.SessionID
	RoleID           iamv1.RoleID
	After            string
}

type RoleCandidate struct {
	Role     iamv1.Role
	Trust    iamv1.RoleTrustVersion
	Boundary *authority.ResolvedRoleBoundary
}

type RoleCandidates struct {
	Revision  authority.RoleDiscoveryRevision
	Items     []RoleCandidate
	NextAfter string
}

type RoleCreation struct {
	Role             iamv1.Role
	TrustVersion     iamv1.RoleTrustVersion
	ActorPrincipalID iamv1.PrincipalID
	ActorSessionID   iamv1.SessionID
	DecisionID       iamv1.DecisionID
	AuditEvent       auditv1.Event
}

// RoleMutation carries the exact authenticated writer and expected revision,
// not a caller-selected tenant/session or a reusable authorization permit.
type RoleMutation struct {
	AccountID        iamv1.AccountID
	RoleID           iamv1.RoleID
	ActorPrincipalID iamv1.PrincipalID
	ActorSessionID   iamv1.SessionID
	DecisionID       iamv1.DecisionID
	ResourceVersion  uint64
	AuditEvent       auditv1.Event
}

type RoleBoundaryMutation struct {
	RoleMutation
	PolicyID              iamv1.PolicyID
	PolicyResourceVersion uint64
	BoundaryID            string
}

// Only the authenticated login bearer supplies these private references.
type RoleAssumptionRead struct {
	AccountID        iamv1.AccountID
	ActorPrincipalID iamv1.PrincipalID
	ActorSessionID   iamv1.SessionID
	RoleID           iamv1.RoleID
	RequestID        string
}

type RoleSessionReceipt struct {
	Session              iamv1.RoleSession `json:"session"`
	SourceSessionID      iamv1.SessionID   `json:"sourceSessionId"`
	CredentialGeneration uint64            `json:"credentialGeneration"`
	RequestDigest        string            `json:"requestDigest"`
}

type RoleAssumption struct {
	Role                 iamv1.Role
	Trust                iamv1.RoleTrustVersion
	CredentialGeneration uint64
	SecurityGeneration   uint64
	Existing             *RoleSessionReceipt
}

type RoleSessionIssuance struct {
	RoleAssumptionRead
	Session                iamv1.RoleSession
	ExpectedRoleVersion    uint64
	CredentialGeneration   uint64
	SecurityGeneration     uint64
	DurationSeconds        uint32
	RequestDigest          string
	SessionPolicyCanonical string
	SessionPolicyDigest    string
	LookupDigest           string
	VerificationDigest     string
	DecisionID             iamv1.DecisionID
	AuditEvent             auditv1.Event
}

type RoleSessionRevocation struct {
	RoleAssumptionRead
	AuditEvent auditv1.Event
}

type RoleSessionManagementTarget struct {
	AccountID        iamv1.AccountID
	ActorPrincipalID iamv1.PrincipalID
	ActorSessionID   iamv1.SessionID
	RoleID           iamv1.RoleID
	SessionID        iamv1.RoleSessionID
}

type RoleSessionManagementRead struct {
	RoleSessionManagementTarget
	DecisionID iamv1.DecisionID
	After      string
	Filter     iamv1.RoleSessionFilter
}

type ManagedRoleSession struct {
	Session    iamv1.RoleSession           `json:"session"`
	SourceUser iamv1.RoleSourceUserDisplay `json:"sourceUser"`
}

type ManagedRoleSessionPage struct {
	Items     []ManagedRoleSession `json:"items"`
	NextAfter string               `json:"nextAfter"`
}

type RoleSessionAdministrativeRevocation struct {
	RoleSessionManagementTarget
	DecisionID iamv1.DecisionID
	AuditEvent auditv1.Event
}

// Possession permits only irreversible self-exit, even after business access
// has expired or been revoked. This is not a current authentication context.
type RoleSessionExitCredential struct {
	Session            iamv1.RoleSession `json:"session"`
	VerificationDigest string            `json:"verificationDigest"`
}

type RoleProfileMutation struct {
	RoleMutation
	Name                      string
	Description               string
	Tags                      []iamv1.RoleTag
	MaxSessionDurationSeconds uint32
}

type RoleStatusMutation struct {
	RoleMutation
	Status iamv1.RoleStatus
}

type RoleTrustMutation struct {
	RoleMutation
	TrustVersion iamv1.RoleTrustVersion
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

type UserProfileMutation struct {
	AccountID        iamv1.AccountID
	ActorPrincipalID iamv1.PrincipalID
	PrincipalID      iamv1.PrincipalID
	DecisionID       iamv1.DecisionID
	DisplayName      string
	ResourceVersion  uint64
	AuditEvent       auditv1.Event
}

type UserDeletionMutation struct {
	AccountID        iamv1.AccountID
	ActorPrincipalID iamv1.PrincipalID
	PrincipalID      iamv1.PrincipalID
	DecisionID       iamv1.DecisionID
	ResourceVersion  uint64
	AuditEvent       auditv1.Event
}

type GroupMutation struct {
	Group            iamv1.Group
	ActorPrincipalID iamv1.PrincipalID
	DecisionID       iamv1.DecisionID
	AuditEvent       auditv1.Event
}

type GroupProfileMutation struct {
	AccountID        iamv1.AccountID
	ActorPrincipalID iamv1.PrincipalID
	GroupID          iamv1.GroupID
	Name             string
	Description      string
	ResourceVersion  uint64
	DecisionID       iamv1.DecisionID
	AuditEvent       auditv1.Event
}

type GroupDeletionMutation struct {
	AccountID        iamv1.AccountID
	ActorPrincipalID iamv1.PrincipalID
	GroupID          iamv1.GroupID
	ResourceVersion  uint64
	DecisionID       iamv1.DecisionID
	AuditEvent       auditv1.Event
}

type GroupMembershipMutation struct {
	Membership       iamv1.GroupMembership
	ActorPrincipalID iamv1.PrincipalID
	DecisionID       iamv1.DecisionID
	AuditEvent       auditv1.Event
}

type GroupMembershipRemovalMutation struct {
	AccountID        iamv1.AccountID
	ActorPrincipalID iamv1.PrincipalID
	GroupID          iamv1.GroupID
	MembershipID     iamv1.GroupMembershipID
	ResourceVersion  uint64
	DecisionID       iamv1.DecisionID
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

// LoginName or the authenticated Session tuple, never both. Only the service
// generates ID; a public request ID is not an authentication-attempt identity.
type PasswordAttemptRequest struct {
	ID           string
	LoginName    string
	AccountID    iamv1.AccountID
	UserID       iamv1.PrincipalID
	SessionID    iamv1.SessionID
	Purpose      PasswordAttemptPurpose
	IntentDigest string
}

type PasswordAttemptPurpose string

const (
	PasswordAttemptLogin               PasswordAttemptPurpose = "LOGIN"
	PasswordAttemptChange              PasswordAttemptPurpose = "PASSWORD_CHANGE"
	PasswordAttemptNotificationContact PasswordAttemptPurpose = "NOTIFICATION_CONTACT_VERIFY"
	PasswordAttemptTOTPEnrollment      PasswordAttemptPurpose = "TOTP_ENROLLMENT"
)

// Private, bounded authority snapshot. Success may only be consumed by the
// final session/password transaction, not converted to a reusable permit.
type PasswordAttempt struct {
	ID                   string
	Sequence             uint64
	AccountID            iamv1.AccountID
	PrincipalID          iamv1.PrincipalID
	SessionID            iamv1.SessionID
	PasswordHash         authority.PasswordHash
	CredentialGeneration uint64
	MustChangePassword   bool
	ExpiresAt            time.Time
	Purpose              PasswordAttemptPurpose
	IntentDigest         string
}

func (PasswordAttempt) String() string               { return "[REDACTED]" }
func (PasswordAttempt) GoString() string             { return "identityaccess.PasswordAttempt{[REDACTED]}" }
func (PasswordAttempt) MarshalJSON() ([]byte, error) { return nil, ErrUnavailable }
func (*PasswordAttempt) UnmarshalJSON([]byte) error  { return ErrUnavailable }

type SessionMutation struct {
	AttemptID          string
	AttemptSequence    uint64
	Session            iamv1.Session
	LookupDigest       string
	VerificationDigest string
	AuditEvent         auditv1.Event
}

type SessionCredential struct {
	Subject              authority.SubjectContext
	VerificationDigest   string
	CredentialGeneration uint64
}

type OwnSessionRead struct {
	AccountID        iamv1.AccountID
	UserID           iamv1.PrincipalID
	CurrentSessionID iamv1.SessionID
	After            string
}

type RoleSessionCredential struct {
	Subject            authority.RoleSessionContext
	VerificationDigest string
}

type ServiceCredential struct {
	Identity           iamv1.ServiceIdentity
	VerificationDigest string
}

// Private locked credential input, not public metadata or a login Session.
// Usable material never travels to products or ordinary JSON encoders.
type AccessKeyCredential struct {
	Subject            authority.AccessKeyContext
	Material           authority.SealedAccessKeySecret
	MaterialCommitment string
}

func (AccessKeyCredential) String() string               { return "[REDACTED]" }
func (AccessKeyCredential) GoString() string             { return "identityaccess.AccessKeyCredential{[REDACTED]}" }
func (AccessKeyCredential) MarshalJSON() ([]byte, error) { return nil, ErrUnavailable }
func (*AccessKeyCredential) UnmarshalJSON([]byte) error  { return ErrUnavailable }

type AuthorizationMutation struct {
	AccountID iamv1.AccountID
	Subject   iamv1.Subject
	// Request is the original validated input, not reconstructed from Decision.
	Request           iamv1.AuthorizationRequest
	Decision          iamv1.AuthorizationDecision
	PolicyEvidence    []authority.PolicyAttachmentEvidence
	BoundaryEvidence  authority.UserBoundaryEvidence
	RoleEvidence      *authority.RoleAuthorizationEvidence
	AccessKeyEvidence *AccessKeyAuthorizationEvidence
	AuditEvent        auditv1.Event
}

// Only the successful MAC path constructs this private, once-only evidence.
// SQL resolves the service's full immutable identity from ServiceLookupDigest.
type AccessKeyAuthorizationEvidence struct {
	AccessKeyID         iamv1.AccessKeyID `json:"accessKeyId"`
	ResourceVersion     uint64            `json:"resourceVersion"`
	FormatVersion       uint8             `json:"formatVersion"`
	WrappingKeyID       string            `json:"wrappingKeyId"`
	MaterialCommitment  string            `json:"materialCommitment"`
	InstallationID      string            `json:"installationId"`
	ServiceLookupDigest string            `json:"serviceLookupDigest"`
	Audience            iamv1.ProductID   `json:"audience"`
	SignedRequestDigest string            `json:"signedRequestDigest"`
	NonceDigest         string            `json:"nonceDigest"`
	SignedAt            int64             `json:"signedAt"`
}

func (AccessKeyAuthorizationEvidence) String() string { return "[REDACTED]" }
func (AccessKeyAuthorizationEvidence) GoString() string {
	return "identityaccess.AccessKeyAuthorizationEvidence{[REDACTED]}"
}
func (AccessKeyAuthorizationEvidence) MarshalJSON() ([]byte, error) { return nil, ErrUnavailable }
func (*AccessKeyAuthorizationEvidence) UnmarshalJSON([]byte) error  { return ErrUnavailable }

type UserBoundaryMutation struct {
	AccountID             iamv1.AccountID
	ActorPrincipalID      iamv1.PrincipalID
	SessionID             iamv1.SessionID
	DecisionID            iamv1.DecisionID
	UserID                iamv1.PrincipalID
	ResourceVersion       uint64
	PolicyID              iamv1.PolicyID
	PolicyResourceVersion uint64
	BoundaryID            string
	AuditEvent            auditv1.Event
}

type PasswordMutation struct {
	AttemptID            string
	AttemptSequence      uint64
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
	ActorSessionID   iamv1.SessionID
	DecisionID       iamv1.DecisionID
	AuditEvent       auditv1.Event
}

type OtherSessionRevocationMutation struct {
	AccountID      iamv1.AccountID
	UserID         iamv1.PrincipalID
	ActorSessionID iamv1.SessionID
	AuditEvent     auditv1.Event
}

type UserMutation struct {
	User             iamv1.User
	PasswordHash     authority.PasswordHash
	ActorPrincipalID iamv1.PrincipalID
	DecisionID       iamv1.DecisionID
	AuditEvent       auditv1.Event
}

type PolicyCreation struct {
	Policy           iamv1.Policy
	Version          iamv1.PolicyVersion
	ActorPrincipalID iamv1.PrincipalID
	DecisionID       iamv1.DecisionID
	AuditEvent       auditv1.Event
}

type PolicyVersionCreation struct {
	AccountID        iamv1.AccountID
	ActorPrincipalID iamv1.PrincipalID
	DecisionID       iamv1.DecisionID
	Version          iamv1.PolicyVersion
	ResourceVersion  uint64
	AuditEvent       auditv1.Event
}

type PolicyDefaultSelection struct {
	AccountID        iamv1.AccountID
	ActorPrincipalID iamv1.PrincipalID
	DecisionID       iamv1.DecisionID
	PolicyID         iamv1.PolicyID
	VersionID        iamv1.PolicyVersionID
	ResourceVersion  uint64
	AuditEvent       auditv1.Event
}

type PolicyVersionDeletion struct {
	AccountID        iamv1.AccountID
	ActorPrincipalID iamv1.PrincipalID
	DecisionID       iamv1.DecisionID
	PolicyID         iamv1.PolicyID
	VersionID        iamv1.PolicyVersionID
	ResourceVersion  uint64
	AuditEvent       auditv1.Event
}

type PolicyUpdate struct {
	AccountID        iamv1.AccountID
	ActorPrincipalID iamv1.PrincipalID
	DecisionID       iamv1.DecisionID
	PolicyID         iamv1.PolicyID
	DisplayName      string
	ResourceVersion  uint64
	AuditEvent       auditv1.Event
}

type PolicyDeletion struct {
	AccountID        iamv1.AccountID
	ActorPrincipalID iamv1.PrincipalID
	DecisionID       iamv1.DecisionID
	PolicyID         iamv1.PolicyID
	ResourceVersion  uint64
	AuditEvent       auditv1.Event
}

type PolicyAttachmentMutation struct {
	Attachment            iamv1.PolicyAttachment
	PolicyResourceVersion uint64
	ActorPrincipalID      iamv1.PrincipalID
	ActorSessionID        iamv1.SessionID
	DecisionID            iamv1.DecisionID
	AuditEvent            auditv1.Event
}

type PolicyAttachmentRevocationMutation struct {
	AccountID        iamv1.AccountID
	AttachmentID     iamv1.PolicyAttachmentID
	ResourceVersion  uint64
	ActorPrincipalID iamv1.PrincipalID
	ActorSessionID   iamv1.SessionID
	DecisionID       iamv1.DecisionID
	AuditEvent       auditv1.Event
}

type ReadinessSnapshot struct {
	Ready         bool
	SchemaVersion uint64
	CheckedAt     time.Time
}

type Authority struct {
	repository   Repository
	config       Config
	passwords    *authority.PasswordHasher
	credentials  *authority.CredentialIssuer
	cursors      *authority.CursorCodec
	accessKeys   *accessKeyWrapping
	totp         *TOTPKeysetRegistration
	totpSeeds    *authority.TOTPSeedProtector
	email        *authority.EmailVerificationProtector
	passwordWork chan struct{}
}
