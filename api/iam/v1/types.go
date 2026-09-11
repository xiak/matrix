package iamv1

import (
	"time"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
)

type AccountID string
type PrincipalID string
type RoleBindingID string
type SessionID string
type DecisionID string

type Subject struct {
	Type PrincipalType `json:"type"`
	ID   PrincipalID   `json:"id"`
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

// LoginResponse contains the one-time plaintext session credential. Ordinary
// JSON marshaling is intentionally forbidden; use EncodeLoginResponse.
type LoginResponse struct {
	Session            Session `json:"session"`
	Credential         Secret  `json:"credential"`
	MustChangePassword bool    `json:"mustChangePassword"`
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

type CurrentIdentity struct {
	APIVersion        string             `json:"apiVersion"`
	Kind              string             `json:"kind"`
	Account           Account            `json:"account"`
	User              User               `json:"user"`
	IdentityKind      IdentityKind       `json:"identityKind"`
	PolicyAttachments []PolicyAttachment `json:"policyAttachments"`
	CanCreateAccounts bool               `json:"canCreateAccounts"`
}

type UserAccess struct {
	User              User               `json:"user"`
	PolicyAttachments []PolicyAttachment `json:"policyAttachments"`
}

type UserList struct {
	APIVersion string       `json:"apiVersion"`
	Kind       string       `json:"kind"`
	Items      []UserAccess `json:"items"`
	NextAfter  string       `json:"nextAfter,omitempty"`
}

type AccountList struct {
	APIVersion string    `json:"apiVersion"`
	Kind       string    `json:"kind"`
	Items      []Account `json:"items"`
	NextAfter  string    `json:"nextAfter,omitempty"`
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
	Action        Action            `json:"action"`
	Resource      ResourceReference `json:"resource"`
	RequestID     string            `json:"requestId"`
	CorrelationID string            `json:"correlationId"`
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
