package iamv1

import (
	"time"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
)

type AccountID string
type PrincipalID string
type GroupID string
type GroupMembershipID string
type RoleBindingID string
type SessionID string
type DecisionID string
type AccessKeyID string

type Subject struct {
	Type        SubjectType           `json:"type"`
	ID          string                `json:"id"`
	RoleSession *RoleSessionReference `json:"roleSession,omitempty"`
	AccessKeyID AccessKeyID           `json:"accessKeyId,omitempty"`
}

// RoleSessionReference is the public actor lineage, not the private source
// login session, trust revision, credential generation or authority evidence.
type RoleSessionReference struct {
	SessionID    RoleSessionID `json:"sessionId"`
	SourceUserID PrincipalID   `json:"sourceUserId"`
}

type ResourceReference struct {
	Kind ResourceKind `json:"kind"`
	ID   string       `json:"id"`
}

type Organization struct {
	APIVersion      string        `json:"apiVersion"`
	Kind            string        `json:"kind"`
	ID              AccountID     `json:"id"`
	DisplayName     string        `json:"displayName"`
	Status          AccountStatus `json:"status"`
	ResourceVersion uint64        `json:"resourceVersion"`
	CreatedAt       time.Time     `json:"createdAt"`
	UpdatedAt       time.Time     `json:"updatedAt"`
}

type Principal struct {
	APIVersion         string          `json:"apiVersion"`
	Kind               string          `json:"kind"`
	ID                 PrincipalID     `json:"id"`
	AccountID          AccountID       `json:"organizationId"`
	Type               PrincipalType   `json:"type"`
	LoginName          string          `json:"loginName,omitempty"`
	DisplayName        string          `json:"displayName"`
	Status             PrincipalStatus `json:"status"`
	MustChangePassword bool            `json:"mustChangePassword,omitempty"`
	ResourceVersion    uint64          `json:"resourceVersion"`
	CreatedAt          time.Time       `json:"createdAt"`
	UpdatedAt          time.Time       `json:"updatedAt"`
}

type Session struct {
	APIVersion  string        `json:"apiVersion"`
	Kind        string        `json:"kind"`
	ID          SessionID     `json:"id"`
	AccountID   AccountID     `json:"organizationId"`
	PrincipalID PrincipalID   `json:"principalId"`
	Status      SessionStatus `json:"status"`
	IssuedAt    time.Time     `json:"issuedAt"`
	ExpiresAt   time.Time     `json:"expiresAt"`
	RevokedAt   *time.Time    `json:"revokedAt,omitempty"`
}

type InitialOrganization struct {
	ID          AccountID `json:"id"`
	DisplayName string    `json:"displayName"`
}

type InitialAdministrator struct {
	ID          PrincipalID `json:"id"`
	LoginName   string      `json:"loginName"`
	DisplayName string      `json:"displayName"`
	Password    Secret      `json:"password"`
}

type BootstrapServiceCredential struct {
	Purpose     ServicePurpose `json:"purpose"`
	PrincipalID PrincipalID    `json:"principalId"`
	Credential  Secret         `json:"credential"`
}

// BootstrapDocument is the exact restrictive installer-owned seed file. Its
// ordinary JSON marshaling fails because it contains Secret values; callers
// must use EncodeBootstrapDocument deliberately.
type BootstrapDocument struct {
	APIVersion     string                       `json:"apiVersion"`
	Kind           string                       `json:"kind"`
	InstallationID string                       `json:"installationId"`
	Organization   InitialOrganization          `json:"organization"`
	Administrator  InitialAdministrator         `json:"administrator"`
	Services       []BootstrapServiceCredential `json:"services"`
}

type BootstrapStatus struct {
	APIVersion     string         `json:"apiVersion"`
	Kind           string         `json:"kind"`
	State          BootstrapState `json:"state"`
	InstallationID string         `json:"installationId,omitempty"`
	AccountID      AccountID      `json:"organizationId,omitempty"`
	ContentDigest  string         `json:"contentDigest,omitempty"`
	AppliedAt      *time.Time     `json:"appliedAt,omitempty"`
}

// ServiceIdentity is the identity bound to the current authenticated service
// credential. The endpoint exposing it accepts no identity or tenant selector.
type ServiceIdentity struct {
	APIVersion     string         `json:"apiVersion"`
	Kind           string         `json:"kind"`
	InstallationID string         `json:"installationId"`
	AccountID      AccountID      `json:"organizationId"`
	PrincipalID    PrincipalID    `json:"principalId"`
	Purpose        ServicePurpose `json:"purpose"`
}

type ResolveAuditProducerRequest struct {
	Event auditv1.Event `json:"event"`
}

// AuditProducerAuthorization binds one append to the current producer and the
// historical event's scope and canonical digest. It is never a reusable permit.
type AuditProducerAuthorization struct {
	APIVersion     string          `json:"apiVersion"`
	Kind           string          `json:"kind"`
	Producer       ServiceIdentity `json:"producer"`
	TenantID       AccountID       `json:"tenantId,omitempty"`
	InstallationID string          `json:"installationId,omitempty"`
	ContentDigest  string          `json:"contentDigest"`
}

type LoginRequest struct {
	LoginName string `json:"loginName"`
	Password  Secret `json:"password"`
	RequestID string `json:"requestId"`
}

// The challenge credential is accepted only in this private request body,
// never as a generic bearer. The path ID is a reference, not authentication.
type VerifyAuthenticationChallengeRequest struct {
	RequestID           string `json:"requestId"`
	ChallengeCredential Secret `json:"challengeCredential"`
	Code                Secret `json:"code"`
}

// ChallengePasswordChangeRequest consumes only a password-change challenge
// reached through the actual password and TOTP ceremony, never a Session.
type ChallengePasswordChangeRequest struct {
	RequestID           string `json:"requestId"`
	ChallengeCredential Secret `json:"challengeCredential"`
	NewPassword         Secret `json:"newPassword"`
}

type ChallengePasswordChangeResponse struct {
	NextStep  string    `json:"nextStep"`
	ChangedAt time.Time `json:"changedAt"`
}

type LoginOutcome string

const (
	LoginAuthenticated     LoginOutcome = "AUTHENTICATED"
	LoginChallengeRequired LoginOutcome = "CHALLENGE_REQUIRED"
)

// AuthenticationChallenge describes the next restricted authentication step,
// never an identity or permission. LOGIN may require TOTP then a separately
// credentialed PASSWORD_CHANGE; enrollment, recovery and step-up are not LOGIN.
type AuthenticationChallenge struct {
	APIVersion string    `json:"apiVersion"`
	Kind       string    `json:"kind"`
	ID         string    `json:"id"`
	Purpose    string    `json:"purpose"`
	NextStep   string    `json:"nextStep"`
	ExpiresAt  time.Time `json:"expiresAt"`
}

// AuthenticatorState is a projection of the authenticated USER, not a
// selectable identity, account security policy or inferred permission.
type AuthenticatorState struct {
	APIVersion      string `json:"apiVersion"`
	Kind            string `json:"kind"`
	EnrollmentState string `json:"enrollmentState"`
	FactorRevision  uint64 `json:"factorRevision"`
	FactorID        string `json:"factorId,omitempty"`
}

type TOTPEnrollment struct {
	APIVersion     string     `json:"apiVersion"`
	Kind           string     `json:"kind"`
	ID             string     `json:"id"`
	RequestID      string     `json:"requestId"`
	FactorRevision uint64     `json:"factorRevision"`
	State          string     `json:"state"`
	CreatedAt      time.Time  `json:"createdAt"`
	ExpiresAt      time.Time  `json:"expiresAt"`
	CompletedAt    *time.Time `json:"completedAt,omitempty"`
}

type StartTOTPEnrollmentRequest struct {
	RequestID              string `json:"requestId"`
	Password               Secret `json:"password"`
	ExpectedFactorRevision uint64 `json:"expectedFactorRevision"`
}

type TOTPProvisioning struct {
	Seed Secret `json:"seed"`
	URI  Secret `json:"uri"`
}

// Only APPLIED contains provisioning. An equal replay cannot recover a seed.
type StartTOTPEnrollmentResponse struct {
	Outcome      string            `json:"outcome"`
	Enrollment   TOTPEnrollment    `json:"enrollment"`
	Provisioning *TOTPProvisioning `json:"provisioning,omitempty"`
}

type ConfirmTOTPEnrollmentRequest struct {
	RequestID string `json:"requestId"`
	Code      Secret `json:"code"`
}

// The binding has committed before this response. Saving codes is not another
// transaction, and closing a page cannot undo the binding or revive a session.
type ConfirmTOTPEnrollmentResponse struct {
	Enrollment    TOTPEnrollment `json:"enrollment"`
	NextStep      string         `json:"nextStep"`
	RecoveryCodes []Secret       `json:"recoveryCodes"`
}

// Recovery has already consumed one code and ended the lost factor. It is
// not a Session, ordinary first enrollment, or permission to change identity.
type AuthenticatorRecovery struct {
	APIVersion  string     `json:"apiVersion"`
	Kind        string     `json:"kind"`
	ID          string     `json:"id"`
	RequestID   string     `json:"requestId"`
	State       string     `json:"state"`
	CreatedAt   time.Time  `json:"createdAt"`
	ExpiresAt   time.Time  `json:"expiresAt"`
	CompletedAt *time.Time `json:"completedAt,omitempty"`
}

type StartAuthenticatorRecoveryRequest struct {
	RequestID           string `json:"requestId"`
	ChallengeCredential Secret `json:"challengeCredential"`
	RecoveryCode        Secret `json:"recoveryCode"`
}

// Only the first committed response discloses the new ceremony's secrets.
// Inspection returns AuthenticatorRecovery alone, never this response.
type StartAuthenticatorRecoveryResponse struct {
	Recovery            AuthenticatorRecovery   `json:"recovery"`
	Challenge           AuthenticationChallenge `json:"challenge"`
	ChallengeCredential Secret                  `json:"challengeCredential"`
	Provisioning        TOTPProvisioning        `json:"provisioning"`
}

type InspectAuthenticatorRecoveryRequest struct {
	RequestID           string `json:"requestId"`
	ChallengeCredential Secret `json:"challengeCredential"`
}

type ConfirmAuthenticatorRecoveryResponse struct {
	Recovery      AuthenticatorRecovery `json:"recovery"`
	NextStep      string                `json:"nextStep"`
	RecoveryCodes []Secret              `json:"recoveryCodes"`
}

// LoginResponse is a disjoint result. Only AUTHENTICATED contains a Session;
// CHALLENGE_REQUIRED contains no login bearer or password-change entitlement.
// Ordinary JSON marshaling is forbidden; use EncodeLoginResponse.
type LoginResponse struct {
	Outcome             LoginOutcome             `json:"outcome"`
	Session             Session                  `json:"session,omitempty"`
	Credential          Secret                   `json:"credential,omitempty"`
	MustChangePassword  bool                     `json:"mustChangePassword,omitempty"`
	Challenge           *AuthenticationChallenge `json:"challenge,omitempty"`
	ChallengeCredential Secret                   `json:"challengeCredential,omitempty"`
}

type LogoutRequest struct {
	RequestID string `json:"requestId"`
}

type LogoutResponse struct {
	RevokedAt time.Time `json:"revokedAt"`
}

type ChangePasswordRequest struct {
	CurrentPassword Secret `json:"currentPassword"`
	NewPassword     Secret `json:"newPassword"`
	RequestID       string `json:"requestId"`
	// Omission defaults to true. Required password replacement always revokes
	// other sessions, even if the caller submits false.
	RevokeOtherSessions *bool `json:"revokeOtherSessions,omitempty"`
}

type ChangePasswordResponse struct {
	ChangedAt              time.Time `json:"changedAt"`
	BootstrapFileRetirable bool      `json:"bootstrapFileRetirable"`
}

type CreateUserRequest struct {
	LoginName       string `json:"loginName"`
	DisplayName     string `json:"displayName"`
	InitialPassword Secret `json:"initialPassword"`
	RequestID       string `json:"requestId"`
}

// RootIdentity is the immutable relation from an account to its original
// controlling USER principal. It has no second credential or identity ID.
type RootIdentity struct {
	PrincipalID PrincipalID `json:"principalId"`
	LoginName   string      `json:"loginName"`
}

// Account is the non-secret resource and security ownership boundary. Its
// login alias is independent of the immutable root login name.
type Account struct {
	APIVersion      string        `json:"apiVersion"`
	Kind            string        `json:"kind"`
	ID              AccountID     `json:"id"`
	DisplayName     string        `json:"displayName"`
	Status          AccountStatus `json:"status"`
	RootIdentity    RootIdentity  `json:"rootIdentity"`
	LoginAlias      *string       `json:"loginAlias"`
	ResourceVersion uint64        `json:"resourceVersion"`
	CreatedAt       time.Time     `json:"createdAt"`
	UpdatedAt       time.Time     `json:"updatedAt"`
}

// User is the manageable account-local USER projection. Service identities
// and the account root are not members of the user directory.
type User struct {
	APIVersion         string          `json:"apiVersion"`
	Kind               string          `json:"kind"`
	ID                 PrincipalID     `json:"id"`
	AccountID          AccountID       `json:"accountId"`
	LoginName          string          `json:"loginName"`
	DisplayName        string          `json:"displayName"`
	Status             PrincipalStatus `json:"status"`
	MustChangePassword bool            `json:"mustChangePassword,omitempty"`
	ResourceVersion    uint64          `json:"resourceVersion"`
	CreatedAt          time.Time       `json:"createdAt"`
	UpdatedAt          time.Time       `json:"updatedAt"`
}

// AccessKey is non-secret program-credential metadata. ENABLED is not a
// permission or proof that the current account/user permits authentication.
type AccessKey struct {
	APIVersion      string          `json:"apiVersion"`
	Kind            string          `json:"kind"`
	ID              AccessKeyID     `json:"id"`
	AccountID       AccountID       `json:"accountId"`
	UserID          PrincipalID     `json:"userId"`
	Status          AccessKeyStatus `json:"status"`
	ResourceVersion uint64          `json:"resourceVersion"`
	CreatedAt       time.Time       `json:"createdAt"`
	UpdatedAt       time.Time       `json:"updatedAt"`
}

type AccessKeyAccess struct {
	Key          AccessKey          `json:"key"`
	Capabilities []ActionCapability `json:"capabilities"`
}

// This complete, bounded user directory has no cursor. Its user revision
// supplies create's CAS without requiring an unrelated user.read permission.
type AccessKeyList struct {
	APIVersion          string             `json:"apiVersion"`
	Kind                string             `json:"kind"`
	AccountID           AccountID          `json:"accountId"`
	UserID              PrincipalID        `json:"userId"`
	UserResourceVersion uint64             `json:"userResourceVersion"`
	Capabilities        []ActionCapability `json:"capabilities"`
	Items               []AccessKeyAccess  `json:"items"`
}

type CreateAccessKeyRequest struct {
	UserResourceVersion uint64 `json:"userResourceVersion"`
	RequestID           string `json:"requestId"`
}

type SetAccessKeyStatusRequest struct {
	AccessKeyResourceVersion uint64          `json:"accessKeyResourceVersion"`
	Status                   AccessKeyStatus `json:"status"`
	RequestID                string          `json:"requestId"`
}

type DeleteAccessKeyRequest struct {
	AccessKeyResourceVersion uint64 `json:"accessKeyResourceVersion"`
	RequestID                string `json:"requestId"`
}

// Only the explicit creation encoder may emit Secret. An equal replay is
// the original creation receipt, not the current key's availability.
type CreateAccessKeyResponse struct {
	Outcome string    `json:"outcome"`
	Key     AccessKey `json:"key"`
	Secret  Secret    `json:"secret,omitempty"`
}

type SetAccessKeyStatusResponse struct {
	Outcome string    `json:"outcome"`
	Key     AccessKey `json:"key"`
}

// Deletion preserves attribution, never recoverable material or a status
// that could be changed back to ENABLED.
type AccessKeyDeletion struct {
	APIVersion      string      `json:"apiVersion"`
	Kind            string      `json:"kind"`
	ID              AccessKeyID `json:"id"`
	AccountID       AccountID   `json:"accountId"`
	UserID          PrincipalID `json:"userId"`
	ResourceVersion uint64      `json:"resourceVersion"`
	DeletedAt       time.Time   `json:"deletedAt"`
}

type DeleteAccessKeyResponse struct {
	Outcome  string            `json:"outcome"`
	Deletion AccessKeyDeletion `json:"deletion"`
}

// Group is an account-local collection of users. It never authenticates,
// owns resources, or becomes an authorization subject by itself.
type Group struct {
	APIVersion      string    `json:"apiVersion"`
	Kind            string    `json:"kind"`
	ID              GroupID   `json:"id"`
	AccountID       AccountID `json:"accountId"`
	Name            string    `json:"name"`
	Description     string    `json:"description,omitempty"`
	ResourceVersion uint64    `json:"resourceVersion"`
	CreatedAt       time.Time `json:"createdAt"`
	UpdatedAt       time.Time `json:"updatedAt"`
}

// GroupMembership is one versioned, account-confined USER-to-Group relation.
// Removal is terminal; re-adding the user creates a new relation identity.
type GroupMembership struct {
	APIVersion      string            `json:"apiVersion"`
	Kind            string            `json:"kind"`
	ID              GroupMembershipID `json:"id"`
	AccountID       AccountID         `json:"accountId"`
	GroupID         GroupID           `json:"groupId"`
	UserID          PrincipalID       `json:"userId"`
	CreatedBy       PrincipalID       `json:"createdBy"`
	RemovedBy       PrincipalID       `json:"removedBy,omitempty"`
	ResourceVersion uint64            `json:"resourceVersion"`
	CreatedAt       time.Time         `json:"createdAt"`
	UpdatedAt       time.Time         `json:"updatedAt"`
	RemovedAt       *time.Time        `json:"removedAt,omitempty"`
}

// ActionCapability is an actor-relative, non-authoritative UI projection for
// one exact action/resource pair. A command must always authenticate,
// authorize and recheck target invariants again in its own transaction.
type ActionCapability struct {
	Action            Action                `json:"action"`
	Resource          ResourceReference     `json:"resource"`
	Available         bool                  `json:"available"`
	RestrictionReason CapabilityRestriction `json:"restrictionReason,omitempty"`
}

type CurrentIdentity struct {
	APIVersion         string                 `json:"apiVersion"`
	Kind               string                 `json:"kind"`
	Account            Account                `json:"account"`
	User               User                   `json:"user"`
	IdentityKind       IdentityKind           `json:"identityKind"`
	PolicySources      []PolicyGrantSource    `json:"policySources"`
	PermissionBoundary UserPermissionBoundary `json:"permissionBoundary"`
	Capabilities       []ActionCapability     `json:"capabilities"`
}

type UserAccess struct {
	User              User               `json:"user"`
	PolicyAttachments []PolicyAttachment `json:"policyAttachments"`
	Capabilities      []ActionCapability `json:"capabilities"`
}

type UserList struct {
	APIVersion string       `json:"apiVersion"`
	Kind       string       `json:"kind"`
	Items      []UserAccess `json:"items"`
	NextAfter  string       `json:"nextAfter,omitempty"`
}

type GroupAccess struct {
	Group             Group              `json:"group"`
	PolicyAttachments []PolicyAttachment `json:"policyAttachments"`
	Capabilities      []ActionCapability `json:"capabilities"`
}

type GroupList struct {
	APIVersion string        `json:"apiVersion"`
	Kind       string        `json:"kind"`
	Items      []GroupAccess `json:"items"`
	NextAfter  string        `json:"nextAfter,omitempty"`
}

type GroupMembershipAccess struct {
	Membership   GroupMembership    `json:"membership"`
	Capabilities []ActionCapability `json:"capabilities"`
}

type GroupMembershipList struct {
	APIVersion string                  `json:"apiVersion"`
	Kind       string                  `json:"kind"`
	AccountID  AccountID               `json:"accountId"`
	GroupID    GroupID                 `json:"groupId"`
	Items      []GroupMembershipAccess `json:"items"`
	NextAfter  string                  `json:"nextAfter,omitempty"`
}

type AccountAccess struct {
	Account      Account            `json:"account"`
	Capabilities []ActionCapability `json:"capabilities"`
}

type AccountList struct {
	APIVersion string          `json:"apiVersion"`
	Kind       string          `json:"kind"`
	Items      []AccountAccess `json:"items"`
	NextAfter  string          `json:"nextAfter,omitempty"`
}

type CreateAccountRequest struct {
	ID              AccountID `json:"id"`
	DisplayName     string    `json:"displayName"`
	RootLoginName   string    `json:"rootLoginName"`
	RootDisplayName string    `json:"rootDisplayName"`
	InitialPassword Secret    `json:"initialPassword"`
	RequestID       string    `json:"requestId"`
}

type SetAccountAliasRequest struct {
	Alias           string `json:"alias"`
	ResourceVersion uint64 `json:"resourceVersion"`
	RequestID       string `json:"requestId"`
}

type SetUserStatusRequest struct {
	Status          PrincipalStatus `json:"status"`
	ResourceVersion uint64          `json:"resourceVersion"`
	RequestID       string          `json:"requestId"`
}

type UpdateUserRequest struct {
	DisplayName     string `json:"displayName"`
	ResourceVersion uint64 `json:"resourceVersion"`
	RequestID       string `json:"requestId"`
}

type DeleteUserRequest struct {
	ResourceVersion uint64 `json:"resourceVersion"`
	RequestID       string `json:"requestId"`
}

type CreateGroupRequest struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	RequestID   string `json:"requestId"`
}

type UpdateGroupRequest struct {
	Name            string `json:"name"`
	Description     string `json:"description,omitempty"`
	ResourceVersion uint64 `json:"resourceVersion"`
	RequestID       string `json:"requestId"`
}

type DeleteGroupRequest struct {
	ResourceVersion uint64 `json:"resourceVersion"`
	RequestID       string `json:"requestId"`
}

type GroupDeletion struct {
	APIVersion               string    `json:"apiVersion"`
	Kind                     string    `json:"kind"`
	AccountID                AccountID `json:"accountId"`
	ID                       GroupID   `json:"id"`
	Name                     string    `json:"name"`
	ResourceVersion          uint64    `json:"resourceVersion"`
	RemovedMemberships       uint32    `json:"removedMemberships"`
	RevokedPolicyAttachments uint32    `json:"revokedPolicyAttachments"`
	DeletedAt                time.Time `json:"deletedAt"`
}

type CreateGroupMembershipRequest struct {
	UserID    PrincipalID `json:"userId"`
	RequestID string      `json:"requestId"`
}

type RemoveGroupMembershipRequest struct {
	ResourceVersion uint64 `json:"resourceVersion"`
	RequestID       string `json:"requestId"`
}

// UserDeletion is the non-secret receipt for an irreversible user tombstone.
// The login name and principal ID remain reserved and cannot be recreated.
type UserDeletion struct {
	APIVersion      string      `json:"apiVersion"`
	Kind            string      `json:"kind"`
	AccountID       AccountID   `json:"accountId"`
	ID              PrincipalID `json:"id"`
	LoginName       string      `json:"loginName"`
	ResourceVersion uint64      `json:"resourceVersion"`
	DeletedAt       time.Time   `json:"deletedAt"`
}

type SetAccountStatusRequest struct {
	Status          AccountStatus `json:"status"`
	ResourceVersion uint64        `json:"resourceVersion"`
	RequestID       string        `json:"requestId"`
}

// Recovery always targets the account's immutable root relation. It cannot
// select a replacement owner.
type RecoverRootCredentialsRequest struct {
	InitialPassword Secret `json:"initialPassword"`
	ResourceVersion uint64 `json:"resourceVersion"`
	RequestID       string `json:"requestId"`
}

type ResetUserPasswordRequest struct {
	InitialPassword Secret `json:"initialPassword"`
	ResourceVersion uint64 `json:"resourceVersion"`
	RequestID       string `json:"requestId"`
}

type RevokeSessionRequest struct {
	RequestID string `json:"requestId"`
}

type Revocation struct {
	APIVersion      string    `json:"apiVersion"`
	Kind            string    `json:"kind"`
	ID              string    `json:"id"`
	ResourceVersion uint64    `json:"resourceVersion"`
	RevokedAt       time.Time `json:"revokedAt"`
}

// AuthorizationRequest contains no tenant or subject field. IAM derives both
// from the subject credential and authenticates the calling service
// independently at the HTTP boundary.
type AuthorizationRequest struct {
	Action          Action                        `json:"action"`
	Resource        ResourceReference             `json:"resource"`
	Profile         AuthorizationProfileReference `json:"profile"`
	ResourceMode    AuthorizationResourceMode     `json:"resourceMode"`
	CollectionUsage AuthorizationCollectionUsage  `json:"collectionUsage,omitempty"`
	RequestID       string                        `json:"requestId"`
	CorrelationID   string                        `json:"correlationId"`
}

type AuthorizationDecision struct {
	APIVersion string         `json:"apiVersion"`
	Kind       string         `json:"kind"`
	ID         DecisionID     `json:"id"`
	Allowed    bool           `json:"allowed"`
	Reason     DecisionReason `json:"reason"`
	TenantID   AccountID      `json:"tenantId,omitempty"`
	// Platform decisions bind the installed authority and omit tenantId. The
	// principal's home organization is not ownership of a platform resource.
	InstallationID string            `json:"installationId,omitempty"`
	Subject        *Subject          `json:"subject,omitempty"`
	Action         Action            `json:"action"`
	Resource       ResourceReference `json:"resource"`
	RequestID      string            `json:"requestId"`
	DecidedAt      time.Time         `json:"decidedAt"`
	// Only the protected historical loader may decode absent binding fields.
	// Current decisions, including Deny, always carry the complete binding.
	Profile         *AuthorizationProfileReference `json:"profile,omitempty"`
	ResourceMode    AuthorizationResourceMode      `json:"resourceMode,omitempty"`
	CollectionUsage AuthorizationCollectionUsage   `json:"collectionUsage,omitempty"`
	CorrelationID   string                         `json:"correlationId,omitempty"`
}

type Readiness struct {
	APIVersion    string         `json:"apiVersion"`
	Kind          string         `json:"kind"`
	State         ReadinessState `json:"state"`
	SchemaVersion uint64         `json:"schemaVersion"`
	CheckedAt     time.Time      `json:"checkedAt"`
}

type Problem struct {
	Type      string `json:"type"`
	Title     string `json:"title"`
	Status    int    `json:"status"`
	Code      string `json:"code"`
	Detail    string `json:"detail,omitempty"`
	RequestID string `json:"requestId"`
}
