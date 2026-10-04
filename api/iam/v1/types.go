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
	SessionID                RoleSessionID `json:"sessionId"`
	SourceUserID             PrincipalID   `json:"sourceUserId,omitempty"`
	SourceServicePrincipalID PrincipalID   `json:"sourceServicePrincipalId,omitempty"`
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

// SessionList observes the authenticated user's live login sessions. A session
// reference is not a bearer, a physical device, or proof of online activity.
type SessionList struct {
	APIVersion       string      `json:"apiVersion"`
	Kind             string      `json:"kind"`
	AccountID        AccountID   `json:"accountId"`
	UserID           PrincipalID `json:"userId"`
	CurrentSessionID SessionID   `json:"currentSessionId"`
	ObservedAt       time.Time   `json:"observedAt"`
	Items            []Session   `json:"items"`
	NextCursor       string      `json:"nextCursor,omitempty"`
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

// ChallengePasswordChangeRequest consumes only a PASSWORD_CHANGE challenge:
// LOGIN has already proved TOTP; ENROLLMENT has proved the initial password
// under a required first-factor setup. Neither ceremony is a Session.
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
	LoginAuthenticated      LoginOutcome = "AUTHENTICATED"
	LoginChallengeRequired  LoginOutcome = "CHALLENGE_REQUIRED"
	LoginAdminResetRequired LoginOutcome = "ADMIN_RESET_REQUIRED"
)

// Unknown age is not evidence that a password has actually expired. Neither
// reason grants a Session or the authority to reset a password.
type PasswordResetReason string

const (
	PasswordResetExpired    PasswordResetReason = "EXPIRED"
	PasswordResetAgeUnknown PasswordResetReason = "AGE_UNKNOWN"
)

// AuthenticationChallenge describes the next restricted authentication step,
// never an identity or permission. LOGIN may require TOTP then a separately
// credentialed PASSWORD_CHANGE. ENROLLMENT permits only first-factor setup
// (after any required password change), not login, recovery or step-up authority.
type AuthenticationChallenge struct {
	APIVersion string    `json:"apiVersion"`
	Kind       string    `json:"kind"`
	ID         string    `json:"id"`
	Purpose    string    `json:"purpose"`
	NextStep   string    `json:"nextStep"`
	ExpiresAt  time.Time `json:"expiresAt"`
}

// EnrollmentChallengeState is an observation held by one restricted
// ENROLLMENT credential. A required password change exposes no contact or
// factor state. It never contains a Session, provisioning or another secret.
type EnrollmentChallengeState struct {
	Challenge           AuthenticationChallenge `json:"challenge"`
	NotificationContact *NotificationContact    `json:"notificationContact,omitempty"`
	Enrollment          *TOTPEnrollment         `json:"enrollment,omitempty"`
}

type InspectEnrollmentChallengeRequest struct {
	ChallengeCredential Secret `json:"challengeCredential"`
}

// The factor revision and USER are taken from locked challenge authority,
// not supplied by the client. This is not the normal Session enrollment API.
type StartChallengeTOTPEnrollmentRequest struct {
	RequestID           string `json:"requestId"`
	ChallengeCredential Secret `json:"challengeCredential"`
}

type PasswordExpiryMode string

const (
	PasswordExpiryChange     PasswordExpiryMode = "CHANGE_PASSWORD"
	PasswordExpiryAdminReset PasswordExpiryMode = "ADMIN_RESET"
)

// AccountPasswordSettings governs password admission and lifetime, not the
// stored-secret verifier, an authorization Policy or a selectable hash profile.
type AccountPasswordSettings struct {
	MinimumLength    int                `json:"minimumLength"`
	RequireLowercase bool               `json:"requireLowercase"`
	RequireUppercase bool               `json:"requireUppercase"`
	RequireDigit     bool               `json:"requireDigit"`
	RequireSymbol    bool               `json:"requireSymbol"`
	HistoryCount     int                `json:"historyCount"`
	MaxAgeDays       int                `json:"maxAgeDays"`
	ExpiryMode       PasswordExpiryMode `json:"expiryMode"`
}

// PasswordRequirements describes this authenticated USER's current rules.
// It is an observation, not a permit or another user's security settings.
type PasswordRequirements struct {
	APIVersion       string                  `json:"apiVersion"`
	Kind             string                  `json:"kind"`
	Password         AccountPasswordSettings `json:"password"`
	MaximumLength    int                     `json:"maximumLength"`
	MaximumUTF8Bytes int                     `json:"maximumUTF8Bytes"`
	SettingsVersion  uint64                  `json:"settingsVersion"`
	Source           string                  `json:"source"`
}

// Only the original live LOGIN/ENROLLMENT PASSWORD_CHANGE capability is
// accepted. The path ID alone never authenticates or selects a USER.
type ChallengePasswordRequirementsRequest struct {
	ChallengeCredential Secret `json:"challengeCredential"`
}

// AccountMFASettings governs ordinary USER login requirements, not whether
// a particular USER has a factor or a Session actually authenticated with it.
// Protected root/installation identities have their own non-tenant boundary.
type AccountMFASettings struct {
	RequiredForUsers bool `json:"requiredForUsers"`
}

// AccountSessionSettings governs the maximum inactivity window sealed into a
// newly issued login Session. It does not extend the Session's absolute
// expiration and is not evidence of user presence or authentication strength.
type AccountSessionSettings struct {
	IdleTimeoutMinutes int `json:"idleTimeoutMinutes"`
}

// AccessKeyNetworkRestrictions is an explicit allow list for one enforcement
// layer. An empty, non-nil list means this layer is unrestricted. Account and
// individual AccessKey layers are evaluated independently and both must pass.
type AccessKeyNetworkRestrictions struct {
	AllowedSourceCIDRs []string `json:"allowedSourceCidrs"`
}

type AccountSecuritySettings struct {
	APIVersion      string             `json:"apiVersion"`
	Kind            string             `json:"kind"`
	AccountID       AccountID          `json:"accountId"`
	ResourceVersion uint64             `json:"resourceVersion"`
	MFA             AccountMFASettings `json:"mfa"`
	// Missing only in immutable completions from before password settings.
	// Current settings must always contain the complete explicit value.
	Password *AccountPasswordSettings `json:"password,omitempty"`
	// Missing only in immutable completions from before idle-session settings.
	// Current settings must always contain the complete explicit value.
	Session *AccountSessionSettings `json:"session,omitempty"`
	// Missing only in immutable completions from before AccessKey network
	// governance. It never governs login Sessions or RoleSessions.
	AccessKeyNetwork *AccessKeyNetworkRestrictions `json:"accessKeyNetwork,omitempty"`
	UpdatedAt        time.Time                     `json:"updatedAt"`
}

// SecuritySettingsUpdateIntent is the exact nonsecret target of a settings
// operation-bound proof. It is not a policy, identity selector or permit.
type SecuritySettingsUpdateIntent struct {
	ExpectedResourceVersion uint64             `json:"expectedResourceVersion"`
	MFA                     AccountMFASettings `json:"mfa"`
	// Only a retained CONSUMED proof may lack the original password segment.
	Password *AccountPasswordSettings `json:"password,omitempty"`
	// Only a retained CONSUMED proof may lack the original session segment.
	Session *AccountSessionSettings `json:"session,omitempty"`
	// Only a retained CONSUMED proof from before network governance may lack it.
	AccessKeyNetwork *AccessKeyNetworkRestrictions `json:"accessKeyNetwork,omitempty"`
}

type UpdateAccountSecuritySettingsRequest struct {
	RequestID               string                       `json:"requestId"`
	StepUpID                string                       `json:"stepUpId"`
	ExpectedResourceVersion uint64                       `json:"expectedResourceVersion"`
	MFA                     AccountMFASettings           `json:"mfa"`
	Password                AccountPasswordSettings      `json:"password"`
	Session                 AccountSessionSettings       `json:"session"`
	AccessKeyNetwork        AccessKeyNetworkRestrictions `json:"accessKeyNetwork"`
}

// This is an immutable historical completion. CallerSessionEnded describes
// the original calling Session, never the Session reading this result now.
// RequestID is its sole command reference; it does not grant lookup access.
type AccountSecuritySettingsChange struct {
	APIVersion              string                  `json:"apiVersion"`
	Kind                    string                  `json:"kind"`
	RequestID               string                  `json:"requestId"`
	ExpectedResourceVersion uint64                  `json:"expectedResourceVersion"`
	Settings                AccountSecuritySettings `json:"settings"`
	CallerSessionEnded      bool                    `json:"callerSessionEnded"`
}

type UpdateAccountSecuritySettingsResponse struct {
	Outcome string                        `json:"outcome"`
	Change  AccountSecuritySettingsChange `json:"change"`
}

// SessionActivity is the nonsecret server observation returned after an
// explicit foreground interaction touches the possessed login Session. It is
// not a bearer, an authorization permit, or a claim that a human is present.
type SessionActivity struct {
	APIVersion        string      `json:"apiVersion"`
	Kind              string      `json:"kind"`
	SessionID         SessionID   `json:"sessionId"`
	AccountID         AccountID   `json:"accountId"`
	UserID            PrincipalID `json:"userId"`
	LastActivityAt    time.Time   `json:"lastActivityAt"`
	IdleExpiresAt     time.Time   `json:"idleExpiresAt"`
	AbsoluteExpiresAt time.Time   `json:"absoluteExpiresAt"`
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
	Purpose        string     `json:"purpose"`
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

// Replacement is held by the original effective login Session and an exact
// TOTP_REPLACE proof. Neither ID can select another identity or act as a bearer.
type StartTOTPReplacementRequest struct {
	RequestID              string `json:"requestId"`
	StepUpID               string `json:"stepUpId"`
	ExpectedFactorRevision uint64 `json:"expectedFactorRevision"`
}

// The caller is selected only by its current login Session. These identifiers
// bind one removal intent; neither is authentication or execution authority.
type RemoveTOTPRequest struct {
	RequestID              string `json:"requestId"`
	StepUpID               string `json:"stepUpId"`
	ExpectedFactorRevision uint64 `json:"expectedFactorRevision"`
}

// AuthenticatorRemoval observes an immutable completion, not today's factor
// state. FactorRevision is the revision after removal. No secret or reusable
// proof is disclosed, including when observed after a later enrollment.
type AuthenticatorRemoval struct {
	APIVersion     string    `json:"apiVersion"`
	Kind           string    `json:"kind"`
	ID             string    `json:"id"`
	RequestID      string    `json:"requestId"`
	FactorID       string    `json:"factorId"`
	FactorRevision uint64    `json:"factorRevision"`
	RemovedAt      time.Time `json:"removedAt"`
}

// Only APPLIED requires a fresh login. EQUAL_REPLAY observes the original
// completion and must not instruct the client to end a newer Session.
type RemoveTOTPResponse struct {
	Outcome  string               `json:"outcome"`
	Removal  AuthenticatorRemoval `json:"removal"`
	NextStep string               `json:"nextStep,omitempty"`
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

type StepUpOperation string

const (
	StepUpRegenerateRecoveryCodes    StepUpOperation = "RECOVERY_CODES_REGENERATE"
	StepUpUpdateSecuritySettings     StepUpOperation = "SECURITY_SETTINGS_UPDATE"
	StepUpReplaceTOTP                StepUpOperation = "TOTP_REPLACE"
	StepUpRemoveTOTP                 StepUpOperation = "TOTP_REMOVE"
	StepUpReplaceNotificationContact StepUpOperation = "NOTIFICATION_CONTACT_REPLACE"
)

// StepUp is non-secret metadata for one operation bound to its original login
// Session. Neither its ID nor PROVED state is a bearer or a permission decision.
type StepUp struct {
	APIVersion             string                                `json:"apiVersion"`
	Kind                   string                                `json:"kind"`
	ID                     string                                `json:"id"`
	RequestID              string                                `json:"requestId"`
	Operation              StepUpOperation                       `json:"operation"`
	ExpectedFactorRevision uint64                                `json:"expectedFactorRevision"`
	SecuritySettings       *SecuritySettingsUpdateIntent         `json:"securitySettings,omitempty"`
	NotificationContact    *NotificationContactReplacementIntent `json:"notificationContact,omitempty"`
	State                  string                                `json:"state"`
	CreatedAt              time.Time                             `json:"createdAt"`
	ExpiresAt              time.Time                             `json:"expiresAt"`
	ProvedAt               *time.Time                            `json:"provedAt,omitempty"`
	ConsumedAt             *time.Time                            `json:"consumedAt,omitempty"`
}

// RequestID is the intended sensitive command's identity, not a target selector.
type StartStepUpRequest struct {
	RequestID              string                                `json:"requestId"`
	Operation              StepUpOperation                       `json:"operation"`
	ExpectedFactorRevision uint64                                `json:"expectedFactorRevision"`
	SecuritySettings       *SecuritySettingsUpdateIntent         `json:"securitySettings,omitempty"`
	NotificationContact    *NotificationContactReplacementIntent `json:"notificationContact,omitempty"`
}

// The original login bearer is still required; this request cannot authenticate
// by an ID alone or exchange a LOGIN/RECOVERY challenge for a proved operation.
type VerifyStepUpRequest struct {
	RequestID string `json:"requestId"`
	Password  Secret `json:"password"`
	Code      Secret `json:"code"`
}

type RegenerateRecoveryCodesRequest struct {
	RequestID              string `json:"requestId"`
	StepUpID               string `json:"stepUpId"`
	ExpectedFactorRevision uint64 `json:"expectedFactorRevision"`
}

// This immutable completion can be inspected after a new normal login. It does
// not disclose a batch verifier, a saved code, or usable step-up authority.
type RecoveryCodeRegeneration struct {
	APIVersion     string    `json:"apiVersion"`
	Kind           string    `json:"kind"`
	ID             string    `json:"id"`
	RequestID      string    `json:"requestId"`
	FactorID       string    `json:"factorId"`
	FactorRevision uint64    `json:"factorRevision"`
	CreatedAt      time.Time `json:"createdAt"`
}

// APPLIED returns exactly ten new codes once. EQUAL_REPLAY has only completion
// metadata; no null/empty code placeholder or new session is part of that result.
type RegenerateRecoveryCodesResponse struct {
	Outcome       string                   `json:"outcome"`
	Regeneration  RecoveryCodeRegeneration `json:"regeneration"`
	RecoveryCodes []Secret                 `json:"recoveryCodes,omitempty"`
}

// LoginResponse is a disjoint result. Only AUTHENTICATED contains a Session;
// CHALLENGE_REQUIRED contains only its purpose-limited challenge capability.
// ADMIN_RESET_REQUIRED contains only a reason, never an authentication capability.
// Ordinary JSON marshaling is forbidden; use EncodeLoginResponse.
type LoginResponse struct {
	Outcome             LoginOutcome             `json:"outcome"`
	Session             Session                  `json:"session,omitempty"`
	Credential          Secret                   `json:"credential,omitempty"`
	MustChangePassword  bool                     `json:"mustChangePassword,omitempty"`
	Challenge           *AuthenticationChallenge `json:"challenge,omitempty"`
	ChallengeCredential Secret                   `json:"challengeCredential,omitempty"`
	PasswordResetReason PasswordResetReason      `json:"passwordResetReason,omitempty"`
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
	APIVersion          string                       `json:"apiVersion"`
	Kind                string                       `json:"kind"`
	ID                  AccessKeyID                  `json:"id"`
	AccountID           AccountID                    `json:"accountId"`
	UserID              PrincipalID                  `json:"userId"`
	Status              AccessKeyStatus              `json:"status"`
	NetworkRestrictions AccessKeyNetworkRestrictions `json:"networkRestrictions"`
	ResourceVersion     uint64                       `json:"resourceVersion"`
	CreatedAt           time.Time                    `json:"createdAt"`
	UpdatedAt           time.Time                    `json:"updatedAt"`
}

// AccessKeyAuthorizationObservation is the latest valid-MAC authorization
// evaluated by IAM. It is historical evidence, never a current permit.
type AccessKeyAuthorizationObservation struct {
	EvaluatedAt time.Time `json:"evaluatedAt"`
	Allowed     bool      `json:"allowed"`
	Product     ProductID `json:"product"`
	Action      Action    `json:"action"`
	SourceIP    string    `json:"sourceIp"`
}

type AccessKeyUsageSummary struct {
	ObservedAt        time.Time                          `json:"observedAt"`
	LastAuthorization *AccessKeyAuthorizationObservation `json:"lastAuthorization,omitempty"`
}

type AccessKeyAccess struct {
	Key          AccessKey             `json:"key"`
	Usage        AccessKeyUsageSummary `json:"usage"`
	Capabilities []ActionCapability    `json:"capabilities"`
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
	UserResourceVersion uint64                       `json:"userResourceVersion"`
	NetworkRestrictions AccessKeyNetworkRestrictions `json:"networkRestrictions"`
	RequestID           string                       `json:"requestId"`
}

type SetAccessKeyStatusRequest struct {
	AccessKeyResourceVersion uint64          `json:"accessKeyResourceVersion"`
	Status                   AccessKeyStatus `json:"status"`
	RequestID                string          `json:"requestId"`
}

type SetAccessKeyNetworkRestrictionsRequest struct {
	AccessKeyResourceVersion uint64                       `json:"accessKeyResourceVersion"`
	NetworkRestrictions      AccessKeyNetworkRestrictions `json:"networkRestrictions"`
	RequestID                string                       `json:"requestId"`
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

type SetAccessKeyNetworkRestrictionsResponse struct {
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

// UserPasswordResetCompletion identifies one committed administrator reset.
// It is neither a password-input commitment nor proof of current password
// validity, user eligibility, Audit delivery or permission to repeat the reset.
type UserPasswordResetCompletion struct {
	APIVersion               string      `json:"apiVersion"`
	Kind                     string      `json:"kind"`
	AccountID                AccountID   `json:"accountId"`
	ActorPrincipalID         PrincipalID `json:"actorPrincipalId"`
	UserID                   PrincipalID `json:"userId"`
	RequestID                string      `json:"requestId"`
	ExpectedResourceVersion  uint64      `json:"expectedResourceVersion"`
	ResultingResourceVersion uint64      `json:"resultingResourceVersion"`
	EventID                  string      `json:"eventId"`
	OccurredAt               time.Time   `json:"occurredAt"`
}

type RevokeSessionRequest struct {
	RequestID string `json:"requestId"`
}

type RevokeOwnSessionResponse struct {
	Outcome    string     `json:"outcome"`
	Revocation Revocation `json:"revocation"`
}

// RevokeOtherSessionsResponse describes one completed self-reduction intent,
// including an empty set. It never grants permission to repeat its effects.
type RevokeOtherSessionsResponse struct {
	APIVersion       string      `json:"apiVersion"`
	Kind             string      `json:"kind"`
	Outcome          string      `json:"outcome"`
	AccountID        AccountID   `json:"accountId"`
	UserID           PrincipalID `json:"userId"`
	CurrentSessionID SessionID   `json:"currentSessionId"`
	RequestID        string      `json:"requestId"`
	RevokedCount     uint64      `json:"revokedCount"`
	CompletedAt      time.Time   `json:"completedAt"`
}

type Revocation struct {
	APIVersion      string    `json:"apiVersion"`
	Kind            string    `json:"kind"`
	ID              string    `json:"id"`
	ResourceVersion uint64    `json:"resourceVersion"`
	RevokedAt       time.Time `json:"revokedAt"`
}

// AuthorizationNetworkContext is established by the authenticated product
// service from its trusted network boundary. It is not a caller attribute map
// and cannot select an account, subject, product, or resource.
type AuthorizationNetworkContext struct {
	SourceIP string `json:"sourceIp"`
}

// AuthorizationTag is a product-owned, Profile-declared authorization fact.
// It is not a Principal/Role tag and cannot be supplied as a generic caller
// attribute. Collections are canonical, strictly key-sorted and duplicate-free.
type AuthorizationTag struct {
	Key   string `json:"key"`
	Value string `json:"value"`
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
	NetworkContext  *AuthorizationNetworkContext  `json:"networkContext,omitempty"`
	RequestTags     []AuthorizationTag            `json:"requestTags,omitempty"`
	ResourceTags    []AuthorizationTag            `json:"resourceTags,omitempty"`
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
	NetworkContext  *AuthorizationNetworkContext   `json:"networkContext,omitempty"`
	RequestTags     []AuthorizationTag             `json:"requestTags,omitempty"`
	ResourceTags    []AuthorizationTag             `json:"resourceTags,omitempty"`
	CorrelationID   string                         `json:"correlationId,omitempty"`
}

// ResolveAuthorizationSubjectRequest asks IAM to authenticate the service and
// one transient USER/ROLE bearer for an exact current product Profile. It has
// deliberately no Account, Subject, Action, resource or tag selector.
type ResolveAuthorizationSubjectRequest struct {
	Profile AuthorizationProfileReference `json:"profile"`
}

// AuthorizationSubjectContext is identity context for a product's protected
// resource lookup. It is not an authorization decision or reusable permit.
type AuthorizationSubjectContext struct {
	APIVersion string                        `json:"apiVersion"`
	Kind       string                        `json:"kind"`
	TenantID   AccountID                     `json:"tenantId"`
	Subject    Subject                       `json:"subject"`
	Profile    AuthorizationProfileReference `json:"profile"`
}

// MaxAuthorizationBatchItems keeps a maximally sized current request and
// response within the common 64 KiB strict IAM transport limit.
const MaxAuthorizationBatchItems = 50

// AuthorizationBatchRequest is a bounded transport for independent exact
// instance decisions. It carries no account, subject or candidate attributes.
type AuthorizationBatchRequest struct {
	Requests []AuthorizationRequest `json:"requests"`
}

// AuthorizationBatchDecision binds every item to one authentication and
// transaction snapshot. TenantID and Subject identify that context; they are
// not a permit for a denied item or for any resource outside Decisions.
type AuthorizationBatchDecision struct {
	APIVersion     string                        `json:"apiVersion"`
	Kind           string                        `json:"kind"`
	TenantID       AccountID                     `json:"tenantId"`
	Subject        Subject                       `json:"subject"`
	Profile        AuthorizationProfileReference `json:"profile"`
	Action         Action                        `json:"action"`
	ResourceKind   ResourceKind                  `json:"resourceKind"`
	NetworkContext *AuthorizationNetworkContext  `json:"networkContext,omitempty"`
	CorrelationID  string                        `json:"correlationId"`
	DecidedAt      time.Time                     `json:"decidedAt"`
	Decisions      []AuthorizationDecision       `json:"decisions"`
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
