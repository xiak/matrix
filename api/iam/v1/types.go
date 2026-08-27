package iamv1

import "time"

type OrganizationID string
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
	APIVersion      string             `json:"apiVersion"`
	Kind            string             `json:"kind"`
	ID              OrganizationID     `json:"id"`
	DisplayName     string             `json:"displayName"`
	Status          OrganizationStatus `json:"status"`
	ResourceVersion uint64             `json:"resourceVersion"`
	CreatedAt       time.Time          `json:"createdAt"`
	UpdatedAt       time.Time          `json:"updatedAt"`
}

type Principal struct {
	APIVersion         string          `json:"apiVersion"`
	Kind               string          `json:"kind"`
	ID                 PrincipalID     `json:"id"`
	OrganizationID     OrganizationID  `json:"organizationId"`
	Type               PrincipalType   `json:"type"`
	LoginName          string          `json:"loginName,omitempty"`
	DisplayName        string          `json:"displayName"`
	Status             PrincipalStatus `json:"status"`
	MustChangePassword bool            `json:"mustChangePassword,omitempty"`
	ResourceVersion    uint64          `json:"resourceVersion"`
	CreatedAt          time.Time       `json:"createdAt"`
	UpdatedAt          time.Time       `json:"updatedAt"`
}

type RoleBinding struct {
	APIVersion      string         `json:"apiVersion"`
	Kind            string         `json:"kind"`
	ID              RoleBindingID  `json:"id"`
	OrganizationID  OrganizationID `json:"organizationId"`
	PrincipalID     PrincipalID    `json:"principalId"`
	Role            BuiltinRole    `json:"role"`
	ResourceVersion uint64         `json:"resourceVersion"`
	CreatedAt       time.Time      `json:"createdAt"`
	UpdatedAt       time.Time      `json:"updatedAt"`
}

type Session struct {
	APIVersion     string         `json:"apiVersion"`
	Kind           string         `json:"kind"`
	ID             SessionID      `json:"id"`
	OrganizationID OrganizationID `json:"organizationId"`
	PrincipalID    PrincipalID    `json:"principalId"`
	Status         SessionStatus  `json:"status"`
	IssuedAt       time.Time      `json:"issuedAt"`
	ExpiresAt      time.Time      `json:"expiresAt"`
	RevokedAt      *time.Time     `json:"revokedAt,omitempty"`
}

type InitialOrganization struct {
	ID          OrganizationID `json:"id"`
	DisplayName string         `json:"displayName"`
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
	OrganizationID OrganizationID `json:"organizationId,omitempty"`
	ContentDigest  string         `json:"contentDigest,omitempty"`
	AppliedAt      *time.Time     `json:"appliedAt,omitempty"`
}

// ServiceIdentity is the identity bound to the current authenticated service
// credential. The endpoint exposing it accepts no identity or tenant selector.
type ServiceIdentity struct {
	APIVersion     string         `json:"apiVersion"`
	Kind           string         `json:"kind"`
	OrganizationID OrganizationID `json:"organizationId"`
	PrincipalID    PrincipalID    `json:"principalId"`
	Purpose        ServicePurpose `json:"purpose"`
}

type ResolveAuditProducerRequest struct {
	OrganizationID OrganizationID `json:"organizationId"`
}

// AuditProducerAuthorization permits only appending a closed event for the
// verified organization. It is not a user or resource authorization decision.
type AuditProducerAuthorization struct {
	APIVersion     string          `json:"apiVersion"`
	Kind           string          `json:"kind"`
	Producer       ServiceIdentity `json:"producer"`
	OrganizationID OrganizationID  `json:"organizationId"`
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
}

type ChangePasswordResponse struct {
	ChangedAt              time.Time `json:"changedAt"`
	BootstrapFileRetirable bool      `json:"bootstrapFileRetirable"`
}

type CreateUserRequest struct {
	LoginName       string       `json:"loginName"`
	DisplayName     string       `json:"displayName"`
	InitialPassword Secret       `json:"initialPassword"`
	InitialRole     *BuiltinRole `json:"initialRole,omitempty"`
	RequestID       string       `json:"requestId"`
}

// OrganizationAccount is the non-secret account boundary used for login and
// tenant administration. The alias is independent of the primary login name.
type OrganizationAccount struct {
	Organization       Organization `json:"organization"`
	PrimaryPrincipalID PrincipalID  `json:"primaryPrincipalId"`
	PrimaryLoginName   string       `json:"primaryLoginName"`
	LoginAlias         *string      `json:"loginAlias"`
}

type CurrentIdentity struct {
	APIVersion             string              `json:"apiVersion"`
	Kind                   string              `json:"kind"`
	Account                OrganizationAccount `json:"account"`
	Principal              Principal           `json:"principal"`
	Roles                  []BuiltinRole       `json:"roles"`
	CanCreateOrganizations bool                `json:"canCreateOrganizations"`
}

type PrincipalAccess struct {
	Principal    Principal     `json:"principal"`
	RoleBindings []RoleBinding `json:"roleBindings"`
}

type PrincipalList struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Items      []PrincipalAccess `json:"items"`
	NextAfter  string            `json:"nextAfter,omitempty"`
}

type OrganizationAccountList struct {
	APIVersion string                `json:"apiVersion"`
	Kind       string                `json:"kind"`
	Items      []OrganizationAccount `json:"items"`
	NextAfter  string                `json:"nextAfter,omitempty"`
}

type CreateOrganizationRequest struct {
	ID                       OrganizationID `json:"id"`
	DisplayName              string         `json:"displayName"`
	AdministratorLoginName   string         `json:"administratorLoginName"`
	AdministratorDisplayName string         `json:"administratorDisplayName"`
	InitialPassword          Secret         `json:"initialPassword"`
	RequestID                string         `json:"requestId"`
}

type SetAccountAliasRequest struct {
	Alias           string `json:"alias"`
	ResourceVersion uint64 `json:"resourceVersion"`
	RequestID       string `json:"requestId"`
}

type SetPrincipalStatusRequest struct {
	Status          PrincipalStatus `json:"status"`
	ResourceVersion uint64          `json:"resourceVersion"`
	RequestID       string          `json:"requestId"`
}

type ResetUserPasswordRequest struct {
	InitialPassword Secret `json:"initialPassword"`
	ResourceVersion uint64 `json:"resourceVersion"`
	RequestID       string `json:"requestId"`
}

type PutRoleBindingRequest struct {
	PrincipalID PrincipalID `json:"principalId"`
	Role        BuiltinRole `json:"role"`
	RequestID   string      `json:"requestId"`
}

type RevokeRoleBindingRequest struct {
	RequestID string `json:"requestId"`
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
	TenantID   OrganizationID `json:"tenantId,omitempty"`
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
