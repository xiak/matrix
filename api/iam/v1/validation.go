package iamv1

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
)

var (
	idPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	loginPattern  = regexp.MustCompile(`^[a-z][a-z0-9._-]{2,63}$`)
	aliasPattern  = regexp.MustCompile(`^[a-z][a-z0-9-]{1,61}[a-z0-9]$`)
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	problemCode   = regexp.MustCompile(`^[a-z][a-z0-9.]{2,127}$`)
)

func ValidateID(name, value string) error {
	if !idPattern.MatchString(value) {
		return fmt.Errorf("%s is invalid", name)
	}
	return nil
}

func ValidateDigest(name, value string) error {
	if !digestPattern.MatchString(value) {
		return fmt.Errorf("%s is invalid", name)
	}
	return nil
}

func ValidateBootstrapDocument(value BootstrapDocument) error {
	var problems []error
	if value.APIVersion != APIVersion || value.Kind != "IAMBootstrap" {
		problems = append(problems, errors.New("bootstrap type metadata is invalid"))
	}
	problems = append(problems,
		ValidateID("installationId", value.InstallationID),
		ValidateID("organization.id", string(value.Organization.ID)),
		validateText("organization.displayName", value.Organization.DisplayName, 1, 128),
		ValidateID("administrator.id", string(value.Administrator.ID)),
		validateLoginName(value.Administrator.LoginName),
		validateText("administrator.displayName", value.Administrator.DisplayName, 1, 128),
	)
	if !value.Administrator.Password.Present() {
		problems = append(problems, ErrInvalidSecret)
	}
	expected := AllServicePurposes()
	if len(value.Services) != len(expected) {
		problems = append(problems, errors.New("bootstrap service inventory is invalid"))
	} else {
		seen := make(map[ServicePurpose]struct{}, len(value.Services))
		for index, service := range value.Services {
			if service.Purpose != expected[index] {
				problems = append(problems, errors.New("bootstrap service order is invalid"))
			}
			if _, duplicate := seen[service.Purpose]; duplicate {
				problems = append(problems, errors.New("bootstrap service is duplicated"))
			}
			seen[service.Purpose] = struct{}{}
			problems = append(problems, ValidateID("service.principalId", string(service.PrincipalID)))
			if !service.Credential.Present() {
				problems = append(problems, ErrInvalidSecret)
			}
		}
	}
	return errors.Join(problems...)
}

func ValidateServiceIdentity(value ServiceIdentity) error {
	var problems []error
	if value.APIVersion != APIVersion || value.Kind != "ServiceIdentity" {
		problems = append(problems, errors.New("service identity type metadata is invalid"))
	}
	problems = append(problems,
		ValidateID("serviceIdentity.installationId", value.InstallationID),
		ValidateID("serviceIdentity.organizationId", string(value.AccountID)),
		ValidateID("serviceIdentity.principalId", string(value.PrincipalID)),
	)
	if !knownServicePurpose(value.Purpose) {
		problems = append(problems, errors.New("service identity purpose is invalid"))
	}
	return errors.Join(problems...)
}

func ValidateResolveAuditProducerRequest(value ResolveAuditProducerRequest) error {
	return auditv1.ValidateEvent(value.Event)
}

func ValidateAuditProducerAuthorization(value AuditProducerAuthorization) error {
	if value.APIVersion != APIVersion || value.Kind != "AuditProducerAuthorization" ||
		(value.Producer.Purpose != ServiceIAM && value.Producer.Purpose != ServicePaaS && value.Producer.Purpose != ServiceAudit) {
		return errors.New("audit producer authorization is invalid")
	}
	if (value.TenantID == "") == (value.InstallationID == "") ||
		(value.InstallationID != "" && value.InstallationID != value.Producer.InstallationID) {
		return errors.New("audit producer scope is invalid")
	}
	scope := value.InstallationID
	if value.TenantID != "" {
		scope = string(value.TenantID)
	}
	return errors.Join(ValidateServiceIdentity(value.Producer), ValidateID("scope", scope), ValidateDigest("contentDigest", value.ContentDigest))
}

func ValidateBootstrapStatus(value BootstrapStatus) error {
	if value.APIVersion != APIVersion || value.Kind != "BootstrapStatus" {
		return errors.New("bootstrap status type metadata is invalid")
	}
	switch value.State {
	case BootstrapUninitialized:
		if value.InstallationID != "" || value.AccountID != "" ||
			value.ContentDigest != "" || value.AppliedAt != nil {
			return errors.New("uninitialized bootstrap status contains initialized data")
		}
		return nil
	case BootstrapReady:
		var problems []error
		problems = append(problems,
			ValidateID("installationId", value.InstallationID),
			ValidateID("organizationId", string(value.AccountID)),
			ValidateDigest("contentDigest", value.ContentDigest),
		)
		if value.AppliedAt == nil {
			problems = append(problems, errors.New("appliedAt is required"))
		} else {
			problems = append(problems, validateTime("appliedAt", *value.AppliedAt))
		}
		return errors.Join(problems...)
	default:
		return errors.New("bootstrap state is invalid")
	}
}

func ValidateLoginRequest(value LoginRequest) error {
	var problems []error
	problems = append(problems, ValidateLoginIdentifier(value.LoginName), ValidateID("requestId", value.RequestID))
	if !value.Password.Present() {
		problems = append(problems, ErrInvalidSecret)
	}
	return errors.Join(problems...)
}

func ValidateLoginResponse(value LoginResponse) error {
	var problems []error
	problems = append(problems, ValidateSession(value.Session))
	if !value.Credential.Present() {
		problems = append(problems, ErrInvalidSecret)
	}
	return errors.Join(problems...)
}

func ValidateLogoutRequest(value LogoutRequest) error {
	return ValidateID("requestId", value.RequestID)
}

func ValidateLogoutResponse(value LogoutResponse) error {
	return validateTime("revokedAt", value.RevokedAt)
}

func ValidateChangePasswordRequest(value ChangePasswordRequest) error {
	var problems []error
	if !value.CurrentPassword.Present() || !value.NewPassword.Present() {
		problems = append(problems, ErrInvalidSecret)
	}
	if value.CurrentPassword.reveal() == value.NewPassword.reveal() {
		problems = append(problems, errors.New("new password must differ from current password"))
	}
	problems = append(problems, ValidateID("requestId", value.RequestID))
	return errors.Join(problems...)
}

func ValidateChangePasswordResponse(value ChangePasswordResponse) error {
	return validateTime("changedAt", value.ChangedAt)
}

func ValidateCreateUserRequest(value CreateUserRequest) error {
	var problems []error
	problems = append(problems,
		validateLoginName(value.LoginName),
		validateText("displayName", value.DisplayName, 1, 128),
		ValidateID("requestId", value.RequestID),
	)
	if !value.InitialPassword.Present() {
		problems = append(problems, ErrInvalidSecret)
	}
	return errors.Join(problems...)
}

func ValidateRevokeSessionRequest(value RevokeSessionRequest) error {
	return ValidateID("requestId", value.RequestID)
}

func ValidateRevocation(value Revocation) error {
	var problems []error
	if value.APIVersion != APIVersion || value.Kind != "Revocation" {
		problems = append(problems, errors.New("revocation type metadata is invalid"))
	}
	problems = append(problems,
		ValidateID("revocation.id", value.ID),
		validatePositiveVersion(value.ResourceVersion),
		validateTime("revocation.revokedAt", value.RevokedAt),
	)
	return errors.Join(problems...)
}

func ValidateAuthorizationRequest(value AuthorizationRequest) error {
	var problems []error
	if checkSourceProfileTarget(value.Profile, value.Action, value.Resource, value.ResourceMode, value.CollectionUsage) != nil {
		problems = append(problems, errors.New("authorization action is invalid"))
	}
	problems = append(problems,
		validateResourceForAction(value.Action, value.Resource),
		ValidateID("requestId", value.RequestID),
		ValidateID("correlationId", value.CorrelationID),
	)
	return errors.Join(problems...)
}

// ValidateAuthorizationDecision is the current response contract. Historical
// loaders must first authenticate the stored row's contract version and use the
// explicit frozen-profile or legacy validator, never infer it from missing JSON.
func ValidateAuthorizationDecision(value AuthorizationDecision) error {
	if value.Profile == nil {
		return errors.New("authorization decision has no product binding")
	}
	if checkSourceProfileTarget(*value.Profile, value.Action, value.Resource, value.ResourceMode, value.CollectionUsage) != nil ||
		ValidateID("correlationId", value.CorrelationID) != nil {
		return errors.New("authorization decision product binding is invalid")
	}
	if value.Allowed && value.Subject != nil &&
		checkValidatedProfileSubjectCredential(sourceProfileCommitments[value.Profile.Product].profile, value.Action, *value.Subject) != nil {
		return errors.New("authorization decision subject capability is invalid")
	}
	definition, known := LookupActionDefinition(value.Action)
	if !known {
		return errors.New("authorization decision action is not declared")
	}
	return validateAuthorizationDecision(value, definition)
}

// This validates immutable evidence against explicit declaration bytes; it does
// not establish that a producer or caller is entitled to select that profile.
func ValidateAuthorizationDecisionForProfile(value AuthorizationDecision, profile AuthorizationProfile) error {
	if value.Profile == nil || CheckAuthorizationProfileTarget(profile, *value.Profile, value.Action, value.Resource, value.ResourceMode, value.CollectionUsage) != nil ||
		ValidateID("correlationId", value.CorrelationID) != nil {
		return errors.New("authorization decision product binding is invalid")
	}
	if value.Allowed && value.Subject != nil && checkValidatedProfileSubjectCredential(profile, value.Action, *value.Subject) != nil {
		return errors.New("authorization decision subject capability is invalid")
	}
	for _, action := range profile.Actions {
		if action.Action == value.Action {
			return validateAuthorizationDecision(value, authorizationProfileActionDefinition(profile, action))
		}
	}
	return errors.New("authorization decision action is not declared")
}

// Legacy syntax is only usable for an existing immutable row whose protected
// database metadata says contract1. This function alone is not legacy admission.
func ValidateLegacyAuthorizationDecision(value AuthorizationDecision) error {
	definition, known := lookupRecordedActionDefinition(value.Action)
	if !known || value.Resource.Kind != definition.ResourceKind || value.Profile != nil || value.ResourceMode != "" || value.CollectionUsage != "" || value.CorrelationID != "" ||
		value.Subject != nil && value.Subject.AccessKeyID != "" {
		return errors.New("legacy decision contains an invalid or current binding")
	}
	return validateAuthorizationDecision(value, definition)
}

func validateAuthorizationDecision(value AuthorizationDecision, definition ActionDefinition) error {
	var problems []error
	if value.APIVersion != APIVersion || value.Kind != "AuthorizationDecision" {
		problems = append(problems, errors.New("authorization decision type metadata is invalid"))
	}
	problems = append(problems,
		ValidateID("id", string(value.ID)),
		ValidateID("resource.id", value.Resource.ID),
		ValidateID("requestId", value.RequestID),
		validateTime("decidedAt", value.DecidedAt),
	)
	if value.Allowed {
		if value.Reason != DecisionAllowed || value.Subject == nil {
			problems = append(problems, errors.New("allowed decision is incomplete"))
		} else {
			problems = append(problems, ValidateSubject(*value.Subject))
		}
		if definition.AuthorityScope == AuthorityScopeInstallation {
			problems = append(problems, ValidateID("installationId", value.InstallationID))
			if value.TenantID != "" || value.Subject != nil && (value.Subject.Type != SubjectUser || value.Subject.AccessKeyID != "") {
				problems = append(problems, errors.New("platform decision contains invalid authority"))
			}
		} else {
			problems = append(problems, ValidateID("tenantId", string(value.TenantID)))
			if value.InstallationID != "" {
				problems = append(problems, errors.New("tenant decision contains platform authority"))
			}
		}
	} else if value.Reason != DecisionDenied || value.Subject != nil || value.TenantID != "" || value.InstallationID != "" {
		problems = append(problems, errors.New("denied decision exposes authority data"))
	}
	return errors.Join(problems...)
}

func ValidateSubject(value Subject) error {
	var problems []error
	if value.Type != SubjectUser && value.Type != SubjectServiceAccount && value.Type != SubjectRole {
		problems = append(problems, errors.New("subject type is invalid"))
	}
	problems = append(problems, ValidateID("subject.id", value.ID))
	if value.Type == SubjectRole {
		if value.RoleSession == nil {
			problems = append(problems, errors.New("role subject has no session reference"))
		} else {
			problems = append(problems, ValidateID("roleSession.sessionId", string(value.RoleSession.SessionID)),
				ValidateID("roleSession.sourceUserId", string(value.RoleSession.SourceUserID)))
		}
	} else if value.RoleSession != nil {
		problems = append(problems, errors.New("non-role subject contains role session"))
	}
	if value.AccessKeyID != "" {
		if value.Type != SubjectUser {
			problems = append(problems, errors.New("non-user subject contains access key lineage"))
		}
		problems = append(problems, ValidateID("subject.accessKeyId", string(value.AccessKeyID)))
	}
	return errors.Join(problems...)
}

func ValidateOrganization(value Organization) error {
	var problems []error
	if value.APIVersion != APIVersion || value.Kind != "Organization" {
		problems = append(problems, errors.New("organization type metadata is invalid"))
	}
	if value.Status != AccountActive && value.Status != AccountDisabled {
		problems = append(problems, errors.New("organization status is invalid"))
	}
	problems = append(problems,
		ValidateID("organization.id", string(value.ID)),
		validateText("organization.displayName", value.DisplayName, 1, 128),
		validatePositiveVersion(value.ResourceVersion),
		validateChronology(value.CreatedAt, value.UpdatedAt),
	)
	return errors.Join(problems...)
}

func ValidatePrincipal(value Principal) error {
	var problems []error
	if value.APIVersion != APIVersion || value.Kind != "Principal" {
		problems = append(problems, errors.New("principal type metadata is invalid"))
	}
	if value.Type != PrincipalUser && value.Type != PrincipalServiceAccount {
		problems = append(problems, errors.New("principal type is invalid"))
	}
	if value.Status != PrincipalActive && value.Status != PrincipalDisabled {
		problems = append(problems, errors.New("principal status is invalid"))
	}
	problems = append(problems,
		ValidateID("principal.id", string(value.ID)),
		ValidateID("principal.organizationId", string(value.AccountID)),
		validateText("principal.displayName", value.DisplayName, 1, 128),
		validatePositiveVersion(value.ResourceVersion),
		validateChronology(value.CreatedAt, value.UpdatedAt),
	)
	if value.Type == PrincipalUser {
		problems = append(problems, validateLoginName(value.LoginName))
	} else if value.LoginName != "" || value.MustChangePassword {
		problems = append(problems, errors.New("service principal contains user fields"))
	}
	return errors.Join(problems...)
}

func ValidateSession(value Session) error {
	var problems []error
	if value.APIVersion != APIVersion || value.Kind != "Session" {
		problems = append(problems, errors.New("session type metadata is invalid"))
	}
	if value.Status != SessionActive && value.Status != SessionRevoked && value.Status != SessionExpired {
		problems = append(problems, errors.New("session status is invalid"))
	}
	problems = append(problems,
		ValidateID("session.id", string(value.ID)),
		ValidateID("session.organizationId", string(value.AccountID)),
		ValidateID("session.principalId", string(value.PrincipalID)),
		validateTime("session.issuedAt", value.IssuedAt),
		validateTime("session.expiresAt", value.ExpiresAt),
	)
	if !value.ExpiresAt.After(value.IssuedAt) {
		problems = append(problems, errors.New("session expiration is invalid"))
	}
	if value.Status == SessionRevoked {
		if value.RevokedAt == nil {
			problems = append(problems, errors.New("revoked session requires revokedAt"))
		} else {
			problems = append(problems, validateTime("session.revokedAt", *value.RevokedAt))
		}
	} else if value.RevokedAt != nil {
		problems = append(problems, errors.New("non-revoked session contains revokedAt"))
	}
	return errors.Join(problems...)
}

func ValidateSessionList(value SessionList) error {
	if value.APIVersion != APIVersion || value.Kind != "SessionList" || value.Items == nil || len(value.Items) > DirectoryPageSize ||
		ValidateID("accountId", string(value.AccountID)) != nil || ValidateID("userId", string(value.UserID)) != nil ||
		ValidateID("currentSessionId", string(value.CurrentSessionID)) != nil || validateTime("observedAt", value.ObservedAt) != nil {
		return errors.New("session list is invalid")
	}
	var previous SessionID
	for _, item := range value.Items {
		if ValidateSession(item) != nil || item.AccountID != value.AccountID || item.PrincipalID != value.UserID ||
			item.ID <= previous || item.Status != SessionActive || item.IssuedAt.After(value.ObservedAt) || !value.ObservedAt.Before(item.ExpiresAt) {
			return errors.New("session observation is invalid")
		}
		previous = item.ID
	}
	if value.NextCursor != "" && (len(value.Items) != DirectoryPageSize || ValidatePageCursor(value.NextCursor) != nil) {
		return errors.New("session continuation is invalid")
	}
	return nil
}

func ValidateRevokeOwnSessionResponse(value RevokeOwnSessionResponse) error {
	if value.Outcome != "APPLIED" && value.Outcome != "EQUAL_REPLAY" {
		return errors.New("session revocation outcome is invalid")
	}
	return ValidateRevocation(value.Revocation)
}

func ValidateRevokeOtherSessionsResponse(value RevokeOtherSessionsResponse) error {
	if value.APIVersion != APIVersion || value.Kind != "OtherSessionsRevocation" ||
		(value.Outcome != "APPLIED" && value.Outcome != "EQUAL_REPLAY") || value.RevokedCount > 9007199254740991 {
		return errors.New("other session revocation is invalid")
	}
	return errors.Join(ValidateID("accountId", string(value.AccountID)), ValidateID("userId", string(value.UserID)),
		ValidateID("currentSessionId", string(value.CurrentSessionID)), ValidateID("requestId", value.RequestID),
		validateTime("completedAt", value.CompletedAt))
}

func ValidateReadiness(value Readiness) error {
	var problems []error
	if value.APIVersion != APIVersion || value.Kind != "Readiness" {
		problems = append(problems, errors.New("readiness type metadata is invalid"))
	}
	if value.State != ReadinessReady && value.State != ReadinessNotReady {
		problems = append(problems, errors.New("readiness state is invalid"))
	}
	problems = append(problems, validatePositiveVersion(value.SchemaVersion), validateTime("checkedAt", value.CheckedAt))
	return errors.Join(problems...)
}

func ValidateProblem(value Problem) error {
	var problems []error
	parsed, err := url.Parse(value.Type)
	if err != nil || !parsed.IsAbs() || parsed.Scheme != "https" {
		problems = append(problems, errors.New("problem type is invalid"))
	}
	if value.Status < 400 || value.Status > 599 {
		problems = append(problems, errors.New("problem status is invalid"))
	}
	if !problemCode.MatchString(value.Code) {
		problems = append(problems, errors.New("problem code is invalid"))
	}
	problems = append(problems,
		validateText("problem.title", value.Title, 1, 128),
		validateText("problem.requestId", value.RequestID, 1, 128),
	)
	if value.Detail != "" {
		problems = append(problems, validateText("problem.detail", value.Detail, 1, 256))
	}
	return errors.Join(problems...)
}

func knownAction(value Action) bool {
	_, known := LookupActionDefinition(value)
	return known
}

func knownServicePurpose(value ServicePurpose) bool {
	for _, candidate := range allServicePurposes {
		if value == candidate {
			return true
		}
	}
	return false
}

func validateResourceForAction(action Action, resource ResourceReference) error {
	if err := ValidateID("resource.id", resource.ID); err != nil {
		return err
	}
	expected, known := ResourceKindForAction(action)
	if !known {
		return errors.New("authorization action is invalid")
	}
	if resource.Kind != expected {
		return errors.New("authorization action and resource kind differ")
	}
	return nil
}

// ResourceKindForAction reads the shared catalog for domain validation and
// contract generation; resource ownership still requires product enforcement.
func ResourceKindForAction(action Action) (ResourceKind, bool) {
	definition, known := LookupActionDefinition(action)
	return definition.ResourceKind, known
}

// ValidateLoginIdentifier accepts a root login or one qualified account user
// name. It deliberately does not normalize case, whitespace, Unicode, or DNS.
func ValidateLoginIdentifier(value string) error {
	name, namespace, qualified := strings.Cut(value, "@")
	if err := validateLoginName(name); err != nil {
		return err
	}
	if qualified && (strings.Contains(namespace, "@") || ValidateID("account", namespace) != nil) {
		return errors.New("loginName is invalid")
	}
	return nil
}

func ValidateAccountAlias(value string) error {
	if !aliasPattern.MatchString(value) {
		return errors.New("account alias is invalid")
	}
	return nil
}

func ValidateCreateAccountRequest(value CreateAccountRequest) error {
	var secretError error
	if !value.InitialPassword.Present() {
		secretError = ErrInvalidSecret
	}
	return errors.Join(
		ValidateID("account.id", string(value.ID)),
		validateText("displayName", value.DisplayName, 1, 128),
		validateLoginName(value.RootLoginName),
		validateText("rootDisplayName", value.RootDisplayName, 1, 128),
		ValidateID("requestId", value.RequestID), secretError,
	)
}

func ValidateSetAccountAliasRequest(value SetAccountAliasRequest) error {
	return errors.Join(ValidateAccountAlias(value.Alias),
		validatePositiveVersion(value.ResourceVersion), ValidateID("requestId", value.RequestID))
}

func ValidateSetUserStatusRequest(value SetUserStatusRequest) error {
	if value.Status != PrincipalActive && value.Status != PrincipalDisabled {
		return errors.New("user status is invalid")
	}
	return errors.Join(validatePositiveVersion(value.ResourceVersion), ValidateID("requestId", value.RequestID))
}

func ValidateUpdateUserRequest(value UpdateUserRequest) error {
	return errors.Join(validateText("displayName", value.DisplayName, 1, 128),
		validatePositiveVersion(value.ResourceVersion), ValidateID("requestId", value.RequestID))
}

func ValidateDeleteUserRequest(value DeleteUserRequest) error {
	return errors.Join(validatePositiveVersion(value.ResourceVersion), ValidateID("requestId", value.RequestID))
}

func ValidateUserDeletion(value UserDeletion) error {
	if value.APIVersion != APIVersion || value.Kind != "UserDeletion" {
		return errors.New("user deletion type metadata is invalid")
	}
	return errors.Join(ValidateID("accountId", string(value.AccountID)), ValidateID("userId", string(value.ID)),
		validateLoginName(value.LoginName), validatePositiveVersion(value.ResourceVersion), validateTime("deletedAt", value.DeletedAt))
}

func ValidateSetAccountStatusRequest(value SetAccountStatusRequest) error {
	if value.Status != AccountActive && value.Status != AccountDisabled {
		return errors.New("account status is invalid")
	}
	return errors.Join(validatePositiveVersion(value.ResourceVersion), ValidateID("requestId", value.RequestID))
}

func ValidateRecoverRootCredentialsRequest(value RecoverRootCredentialsRequest) error {
	if !value.InitialPassword.Present() {
		return ErrInvalidSecret
	}
	return errors.Join(validatePositiveVersion(value.ResourceVersion), ValidateID("requestId", value.RequestID))
}

func ValidateResetUserPasswordRequest(value ResetUserPasswordRequest) error {
	if !value.InitialPassword.Present() {
		return ErrInvalidSecret
	}
	return errors.Join(validatePositiveVersion(value.ResourceVersion), ValidateID("requestId", value.RequestID))
}

func ValidateRootIdentity(value RootIdentity) error {
	return errors.Join(ValidateID("rootIdentity.principalId", string(value.PrincipalID)),
		validateLoginName(value.LoginName))
}

func ValidateAccount(value Account) error {
	var aliasError error
	if value.LoginAlias != nil {
		aliasError = ValidateAccountAlias(*value.LoginAlias)
	}
	if value.APIVersion != APIVersion || value.Kind != "Account" ||
		(value.Status != AccountActive && value.Status != AccountDisabled) {
		return errors.New("account is invalid")
	}
	return errors.Join(ValidateID("account.id", string(value.ID)),
		validateText("account.displayName", value.DisplayName, 1, 128),
		ValidateRootIdentity(value.RootIdentity), validatePositiveVersion(value.ResourceVersion),
		validateChronology(value.CreatedAt, value.UpdatedAt), aliasError)
}

func ValidateUser(value User) error {
	if value.APIVersion != APIVersion || value.Kind != "User" ||
		(value.Status != PrincipalActive && value.Status != PrincipalDisabled) {
		return errors.New("user is invalid")
	}
	return errors.Join(ValidateID("user.id", string(value.ID)), ValidateID("user.accountId", string(value.AccountID)),
		validateLoginName(value.LoginName), validateText("user.displayName", value.DisplayName, 1, 128),
		validatePositiveVersion(value.ResourceVersion), validateChronology(value.CreatedAt, value.UpdatedAt))
}

func ValidateAccessKey(value AccessKey) error {
	if value.APIVersion != APIVersion || value.Kind != "AccessKey" ||
		(value.Status != AccessKeyEnabled && value.Status != AccessKeyDisabled) ||
		(value.ResourceVersion == 1 && (value.Status != AccessKeyEnabled || !value.CreatedAt.Equal(value.UpdatedAt))) {
		return errors.New("access key metadata is invalid")
	}
	return errors.Join(ValidateID("accessKey.id", string(value.ID)), ValidateID("accessKey.accountId", string(value.AccountID)),
		ValidateID("accessKey.userId", string(value.UserID)), validatePositiveVersion(value.ResourceVersion), validateChronology(value.CreatedAt, value.UpdatedAt))
}

func ValidateAccessKeyAccess(value AccessKeyAccess) error {
	if err := ValidateAccessKey(value.Key); err != nil {
		return err
	}
	expected := make(map[string]struct{}, 3)
	for _, action := range []Action{ActionIAMAccessKeyRead, ActionIAMAccessKeySetStatus, ActionIAMAccessKeyDelete} {
		expected[capabilityKey(action, ResourceReference{Kind: ResourceAccessKey, ID: string(value.Key.ID)})] = struct{}{}
	}
	return validateCapabilities(value.Capabilities, expected)
}

func ValidateAccessKeyList(value AccessKeyList) error {
	if value.APIVersion != APIVersion || value.Kind != "AccessKeyList" || value.Items == nil || len(value.Items) > MaxUserAccessKeys {
		return errors.New("access key list is invalid")
	}
	if err := errors.Join(ValidateID("accountId", string(value.AccountID)), ValidateID("userId", string(value.UserID)), validatePositiveVersion(value.UserResourceVersion)); err != nil {
		return err
	}
	expected := map[string]struct{}{capabilityKey(ActionIAMAccessKeyCreate, ResourceReference{Kind: ResourceUser, ID: string(value.UserID)}): {}}
	if err := validateCapabilities(value.Capabilities, expected); err != nil {
		return err
	}
	var previous AccessKeyID
	for _, item := range value.Items {
		if ValidateAccessKeyAccess(item) != nil || item.Key.AccountID != value.AccountID || item.Key.UserID != value.UserID || item.Key.ID <= previous {
			return errors.New("access key list contains an unbound or duplicate entry")
		}
		previous = item.Key.ID
	}
	return nil
}

func ValidateCreateAccessKeyRequest(value CreateAccessKeyRequest) error {
	return errors.Join(validatePositiveVersion(value.UserResourceVersion), ValidateID("requestId", value.RequestID))
}

func ValidateSetAccessKeyStatusRequest(value SetAccessKeyStatusRequest) error {
	if value.Status != AccessKeyEnabled && value.Status != AccessKeyDisabled {
		return errors.New("access key status is invalid")
	}
	return ValidateDeleteAccessKeyRequest(DeleteAccessKeyRequest{AccessKeyResourceVersion: value.AccessKeyResourceVersion, RequestID: value.RequestID})
}

func ValidateDeleteAccessKeyRequest(value DeleteAccessKeyRequest) error {
	if value.AccessKeyResourceVersion == 9007199254740991 {
		return errors.New("access key resource version cannot advance")
	}
	return errors.Join(validatePositiveVersion(value.AccessKeyResourceVersion), ValidateID("requestId", value.RequestID))
}

func ValidateCreateAccessKeyResponse(value CreateAccessKeyResponse) error {
	if ValidateAccessKey(value.Key) != nil || value.Key.ResourceVersion != 1 || value.Key.Status != AccessKeyEnabled ||
		(value.Outcome != "APPLIED" && value.Outcome != "EQUAL_REPLAY") ||
		(value.Outcome == "APPLIED" && !value.Secret.Present()) ||
		(value.Outcome == "EQUAL_REPLAY" && value.Secret.reveal() != "") {
		return errors.New("access key creation result is invalid")
	}
	return nil
}

func ValidateSetAccessKeyStatusResponse(value SetAccessKeyStatusResponse) error {
	if value.Outcome != "APPLIED" && value.Outcome != "EQUAL_REPLAY" {
		return errors.New("access key change result is invalid")
	}
	if value.Key.ResourceVersion < 2 {
		return errors.New("access key change result has no mutation")
	}
	return ValidateAccessKey(value.Key)
}

func ValidateAccessKeyDeletion(value AccessKeyDeletion) error {
	if value.APIVersion != APIVersion || value.Kind != "AccessKeyDeletion" || value.ResourceVersion < 2 {
		return errors.New("access key deletion is invalid")
	}
	return errors.Join(ValidateID("accessKey.id", string(value.ID)), ValidateID("accessKey.accountId", string(value.AccountID)),
		ValidateID("accessKey.userId", string(value.UserID)), validatePositiveVersion(value.ResourceVersion), validateTime("deletedAt", value.DeletedAt))
}

func ValidateDeleteAccessKeyResponse(value DeleteAccessKeyResponse) error {
	if value.Outcome != "APPLIED" && value.Outcome != "EQUAL_REPLAY" {
		return errors.New("access key deletion result is invalid")
	}
	return ValidateAccessKeyDeletion(value.Deletion)
}

func ValidateGroup(value Group) error {
	var descriptionError error
	if value.Description != "" {
		descriptionError = validateText("group.description", value.Description, 1, 512)
	}
	if value.APIVersion != APIVersion || value.Kind != "Group" {
		return errors.New("group is invalid")
	}
	return errors.Join(ValidateID("group.id", string(value.ID)), ValidateID("group.accountId", string(value.AccountID)),
		validateText("group.name", value.Name, 1, 64), descriptionError,
		validatePositiveVersion(value.ResourceVersion), validateChronology(value.CreatedAt, value.UpdatedAt))
}

func ValidateGroupMembership(value GroupMembership) error {
	if value.APIVersion != APIVersion || value.Kind != "GroupMembership" {
		return errors.New("group membership is invalid")
	}
	problems := []error{
		ValidateID("membership.id", string(value.ID)), ValidateID("membership.accountId", string(value.AccountID)),
		ValidateID("membership.groupId", string(value.GroupID)), ValidateID("membership.userId", string(value.UserID)),
		ValidateID("membership.createdBy", string(value.CreatedBy)), validatePositiveVersion(value.ResourceVersion),
		validateChronology(value.CreatedAt, value.UpdatedAt),
	}
	if value.RemovedAt == nil {
		if value.RemovedBy != "" || value.ResourceVersion != 1 || !value.UpdatedAt.Equal(value.CreatedAt) {
			problems = append(problems, errors.New("active membership contains removal state"))
		}
	} else {
		problems = append(problems, ValidateID("membership.removedBy", string(value.RemovedBy)), validateTime("membership.removedAt", *value.RemovedAt))
		if value.ResourceVersion < 2 || !value.RemovedAt.Equal(value.UpdatedAt) || value.RemovedAt.Before(value.CreatedAt) {
			problems = append(problems, errors.New("removed membership chronology is invalid"))
		}
	}
	return errors.Join(problems...)
}

func ValidateCreateGroupRequest(value CreateGroupRequest) error {
	var descriptionError error
	if value.Description != "" {
		descriptionError = validateText("description", value.Description, 1, 512)
	}
	return errors.Join(validateText("name", value.Name, 1, 64), descriptionError, ValidateID("requestId", value.RequestID))
}

func ValidateUpdateGroupRequest(value UpdateGroupRequest) error {
	return errors.Join(ValidateCreateGroupRequest(CreateGroupRequest{Name: value.Name, Description: value.Description, RequestID: value.RequestID}),
		validatePositiveVersion(value.ResourceVersion))
}

func ValidateDeleteGroupRequest(value DeleteGroupRequest) error {
	return errors.Join(validatePositiveVersion(value.ResourceVersion), ValidateID("requestId", value.RequestID))
}

func ValidateGroupDeletion(value GroupDeletion) error {
	if value.APIVersion != APIVersion || value.Kind != "GroupDeletion" {
		return errors.New("group deletion is invalid")
	}
	return errors.Join(ValidateID("groupDeletion.accountId", string(value.AccountID)), ValidateID("groupDeletion.id", string(value.ID)),
		validateText("groupDeletion.name", value.Name, 1, 64), validatePositiveVersion(value.ResourceVersion),
		validateTime("groupDeletion.deletedAt", value.DeletedAt))
}

func ValidateCreateGroupMembershipRequest(value CreateGroupMembershipRequest) error {
	return errors.Join(ValidateID("userId", string(value.UserID)), ValidateID("requestId", value.RequestID))
}

func ValidateRemoveGroupMembershipRequest(value RemoveGroupMembershipRequest) error {
	return errors.Join(validatePositiveVersion(value.ResourceVersion), ValidateID("requestId", value.RequestID))
}

func ValidateActionCapability(value ActionCapability) error {
	if value.Available {
		if value.RestrictionReason != "" {
			return errors.New("available capability has a restriction")
		}
	} else if !knownCapabilityRestriction(value.RestrictionReason) {
		return errors.New("unavailable capability has no known restriction")
	}
	return validateResourceForAction(value.Action, value.Resource)
}

func knownCapabilityRestriction(value CapabilityRestriction) bool {
	for _, known := range allCapabilityRestrictions {
		if value == known {
			return true
		}
	}
	return false
}

func capabilityKey(action Action, resource ResourceReference) string {
	return string(action) + "\x00" + string(resource.Kind) + "\x00" + resource.ID
}

func validateCapabilities(values []ActionCapability, expected map[string]struct{}) error {
	if values == nil || len(values) != len(expected) {
		return errors.New("capability set is incomplete")
	}
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		key := capabilityKey(value.Action, value.Resource)
		if ValidateActionCapability(value) != nil || seen[key] {
			return errors.New("capability is invalid or duplicated")
		}
		if _, required := expected[key]; !required {
			return errors.New("capability does not belong to its projection")
		}
		seen[key] = true
	}
	return nil
}

func expectedCapabilitySet(values ...struct {
	Action   Action
	Resource ResourceReference
}) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[capabilityKey(value.Action, value.Resource)] = struct{}{}
	}
	return result
}

func ValidateCurrentIdentity(value CurrentIdentity) error {
	if ValidateUserPermissionBoundary(value.PermissionBoundary) != nil || value.PermissionBoundary.AccountID != value.Account.ID ||
		value.PermissionBoundary.UserID != value.User.ID || value.PermissionBoundary.ResourceVersion != value.User.ResourceVersion ||
		(value.IdentityKind == IdentityRoot && value.PermissionBoundary.Policy != nil) {
		return errors.New("current identity boundary is invalid")
	}
	if value.APIVersion != APIVersion || value.Kind != "CurrentIdentity" ||
		value.PolicySources == nil || len(value.PolicySources) > 256 ||
		value.User.AccountID != value.Account.ID {
		return errors.New("current identity is invalid")
	}
	expectedKind := IdentityUser
	if value.User.ID == value.Account.RootIdentity.PrincipalID {
		expectedKind = IdentityRoot
	}
	if value.IdentityKind != expectedKind {
		return errors.New("current identity kind is invalid")
	}
	seen := map[PolicyAttachmentID]bool{}
	var previous PolicyAttachmentID
	for _, source := range value.PolicySources {
		attachment := source.Attachment
		if ValidatePolicyGrantSource(source) != nil || seen[attachment.ID] || attachment.ID <= previous ||
			attachment.AccountID != value.Account.ID ||
			(source.Kind == PolicyGrantDirect && attachment.Target.ID != string(value.User.ID)) ||
			(source.Kind == PolicyGrantGroup && (value.IdentityKind == IdentityRoot || source.Membership.AccountID != value.Account.ID || source.Membership.UserID != value.User.ID)) {
			return errors.New("current policy sources are invalid")
		}
		seen[attachment.ID] = true
		previous = attachment.ID
	}
	expected := expectedCapabilitySet(
		struct {
			Action   Action
			Resource ResourceReference
		}{ActionIAMAccountCreate, ResourceReference{Kind: ResourceAccount, ID: "collection"}},
		struct {
			Action   Action
			Resource ResourceReference
		}{ActionIAMAccountRead, ResourceReference{Kind: ResourceAccount, ID: "collection"}},
		struct {
			Action   Action
			Resource ResourceReference
		}{ActionIAMAccountAliasSet, ResourceReference{Kind: ResourceAccount, ID: string(value.Account.ID)}},
		struct {
			Action   Action
			Resource ResourceReference
		}{ActionIAMUserList, ResourceReference{Kind: ResourceAccount, ID: string(value.Account.ID)}},
		struct {
			Action   Action
			Resource ResourceReference
		}{ActionIAMUserCreate, ResourceReference{Kind: ResourceAccount, ID: string(value.Account.ID)}},
		struct {
			Action   Action
			Resource ResourceReference
		}{ActionIAMPolicyList, ResourceReference{Kind: ResourceAccount, ID: string(value.Account.ID)}},
		struct {
			Action   Action
			Resource ResourceReference
		}{ActionIAMGroupList, ResourceReference{Kind: ResourceAccount, ID: string(value.Account.ID)}},
		struct {
			Action   Action
			Resource ResourceReference
		}{ActionIAMGroupCreate, ResourceReference{Kind: ResourceAccount, ID: string(value.Account.ID)}},
		struct {
			Action   Action
			Resource ResourceReference
		}{ActionIAMRoleList, ResourceReference{Kind: ResourceAccount, ID: string(value.Account.ID)}},
		struct {
			Action   Action
			Resource ResourceReference
		}{ActionIAMRoleCreate, ResourceReference{Kind: ResourceAccount, ID: string(value.Account.ID)}},
	)
	if validateCapabilities(value.Capabilities, expected) != nil {
		return errors.New("current identity capabilities are invalid")
	}
	return errors.Join(ValidateAccount(value.Account), ValidateUser(value.User))
}

const DirectoryPageSize = 100
const MaxPageCursorBytes = 384

// ValidatePageCursor checks only the public bounded opaque envelope. Signature,
// current authority, query and expiry are verified exclusively by IAM.
func ValidatePageCursor(value string) error {
	return validateCursorEnvelope(value, "ic1.")
}

// Self discovery has a distinct confidential cursor kind; management cursors
// cannot be used to supply its private scan position (or vice versa).
func ValidateRoleDiscoveryCursor(value string) error {
	return validateCursorEnvelope(value, "ir1.")
}

func validateCursorEnvelope(value, prefix string) error {
	if len(value) <= 4 || len(value) > MaxPageCursorBytes || value[:4] != prefix {
		return errors.New("IAM page cursor is invalid")
	}
	for _, character := range value[4:] {
		if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || character == '-' || character == '_') {
			return errors.New("IAM page cursor is invalid")
		}
	}
	return nil
}

func ValidateUserList(value UserList) error {
	if value.APIVersion != APIVersion || value.Kind != "UserList" || value.Items == nil || len(value.Items) > 100 {
		return errors.New("user list is invalid")
	}
	var previous string
	var account AccountID
	for _, item := range value.Items {
		if ValidateUserAccess(item) != nil || string(item.User.ID) <= previous {
			return errors.New("user list item is invalid")
		}
		previous = string(item.User.ID)
		if account != "" && item.User.AccountID != account {
			return errors.New("user directory contains multiple accounts")
		}
		account = item.User.AccountID
	}
	if value.NextAfter != "" && (len(value.Items) != DirectoryPageSize || ValidatePageCursor(value.NextAfter) != nil) {
		return errors.New("user page boundary is invalid")
	}
	return nil
}

func ValidateUserAccess(value UserAccess) error {
	if ValidateUser(value.User) != nil || value.PolicyAttachments == nil || len(value.PolicyAttachments) > 256 {
		return errors.New("user access is invalid")
	}
	attachments := map[PolicyAttachmentID]bool{}
	policies := map[PolicyID]bool{}
	for _, attachment := range value.PolicyAttachments {
		if ValidatePolicyAttachment(attachment) != nil || attachment.RevokedAt != nil ||
			attachment.AccountID != value.User.AccountID || attachment.Target.Kind != PolicyTargetUser ||
			attachment.Target.ID != string(value.User.ID) || attachments[attachment.ID] || policies[attachment.PolicyID] {
			return errors.New("user policy attachment is invalid")
		}
		attachments[attachment.ID] = true
		policies[attachment.PolicyID] = true
	}
	expected := expectedCapabilitySet(
		struct {
			Action   Action
			Resource ResourceReference
		}{ActionIAMUserRead, ResourceReference{Kind: ResourceUser, ID: string(value.User.ID)}},
		struct {
			Action   Action
			Resource ResourceReference
		}{ActionIAMUserUpdate, ResourceReference{Kind: ResourceUser, ID: string(value.User.ID)}},
		struct {
			Action   Action
			Resource ResourceReference
		}{ActionIAMUserDelete, ResourceReference{Kind: ResourceUser, ID: string(value.User.ID)}},
		struct {
			Action   Action
			Resource ResourceReference
		}{ActionIAMUserPermissionBoundarySet, ResourceReference{Kind: ResourceUser, ID: string(value.User.ID)}},
		struct {
			Action   Action
			Resource ResourceReference
		}{ActionIAMUserPermissionBoundaryRemove, ResourceReference{Kind: ResourceUser, ID: string(value.User.ID)}},
		struct {
			Action   Action
			Resource ResourceReference
		}{ActionIAMUserSetStatus, ResourceReference{Kind: ResourceUser, ID: string(value.User.ID)}},
		struct {
			Action   Action
			Resource ResourceReference
		}{ActionIAMUserPasswordReset, ResourceReference{Kind: ResourceUser, ID: string(value.User.ID)}},
		struct {
			Action   Action
			Resource ResourceReference
		}{ActionIAMPolicyAttachmentCreate, ResourceReference{Kind: ResourceUser, ID: string(value.User.ID)}},
		struct {
			Action   Action
			Resource ResourceReference
		}{ActionIAMPlatformPolicyAttachmentCreate, ResourceReference{Kind: ResourceUser, ID: string(value.User.ID)}},
	)
	for _, attachment := range value.PolicyAttachments {
		action := ActionIAMPolicyAttachmentRevoke
		if attachment.Scope == AuthorityScopeInstallation {
			action = ActionIAMPlatformPolicyAttachmentRevoke
		}
		expected[capabilityKey(action, ResourceReference{Kind: ResourcePolicyAttachment, ID: string(attachment.ID)})] = struct{}{}
	}
	if validateCapabilities(value.Capabilities, expected) != nil {
		return errors.New("user capabilities are invalid")
	}
	return nil
}

func ValidateGroupAccess(value GroupAccess) error {
	if ValidateGroup(value.Group) != nil || value.PolicyAttachments == nil || len(value.PolicyAttachments) > 256 {
		return errors.New("group access is invalid")
	}
	attachments := map[PolicyAttachmentID]bool{}
	policies := map[PolicyID]bool{}
	expected := expectedCapabilitySet(
		struct {
			Action   Action
			Resource ResourceReference
		}{ActionIAMGroupRead, ResourceReference{Kind: ResourceGroup, ID: string(value.Group.ID)}},
		struct {
			Action   Action
			Resource ResourceReference
		}{ActionIAMGroupUpdate, ResourceReference{Kind: ResourceGroup, ID: string(value.Group.ID)}},
		struct {
			Action   Action
			Resource ResourceReference
		}{ActionIAMGroupDelete, ResourceReference{Kind: ResourceGroup, ID: string(value.Group.ID)}},
		struct {
			Action   Action
			Resource ResourceReference
		}{ActionIAMGroupMembershipList, ResourceReference{Kind: ResourceGroup, ID: string(value.Group.ID)}},
		struct {
			Action   Action
			Resource ResourceReference
		}{ActionIAMGroupMembershipCreate, ResourceReference{Kind: ResourceGroup, ID: string(value.Group.ID)}},
		struct {
			Action   Action
			Resource ResourceReference
		}{ActionIAMGroupPolicyAttachmentCreate, ResourceReference{Kind: ResourceGroup, ID: string(value.Group.ID)}},
	)
	for _, attachment := range value.PolicyAttachments {
		if ValidatePolicyAttachment(attachment) != nil || attachment.RevokedAt != nil || attachment.Scope != AuthorityScopeTenant ||
			attachment.AccountID != value.Group.AccountID || attachment.Target.Kind != PolicyTargetGroup ||
			attachment.Target.ID != string(value.Group.ID) || attachments[attachment.ID] || policies[attachment.PolicyID] {
			return errors.New("group policy attachment is invalid")
		}
		attachments[attachment.ID] = true
		policies[attachment.PolicyID] = true
		expected[capabilityKey(ActionIAMGroupPolicyAttachmentRevoke,
			ResourceReference{Kind: ResourcePolicyAttachment, ID: string(attachment.ID)})] = struct{}{}
	}
	return validateCapabilities(value.Capabilities, expected)
}

func ValidateGroupList(value GroupList) error {
	if value.APIVersion != APIVersion || value.Kind != "GroupList" || value.Items == nil || len(value.Items) > 100 {
		return errors.New("group list is invalid")
	}
	var previous GroupID
	var account AccountID
	for _, item := range value.Items {
		if ValidateGroupAccess(item) != nil || item.Group.ID <= previous || (account != "" && item.Group.AccountID != account) {
			return errors.New("group list item is invalid")
		}
		previous, account = item.Group.ID, item.Group.AccountID
	}
	if value.NextAfter != "" && (len(value.Items) != DirectoryPageSize || ValidatePageCursor(value.NextAfter) != nil) {
		return errors.New("group page boundary is invalid")
	}
	return nil
}

func ValidateGroupMembershipAccess(value GroupMembershipAccess) error {
	if ValidateGroupMembership(value.Membership) != nil || value.Membership.RemovedAt != nil {
		return errors.New("group membership access is invalid")
	}
	expected := expectedCapabilitySet(struct {
		Action   Action
		Resource ResourceReference
	}{ActionIAMGroupMembershipRemove, ResourceReference{Kind: ResourceGroupMembership, ID: string(value.Membership.ID)}})
	if validateCapabilities(value.Capabilities, expected) != nil {
		return errors.New("group membership capabilities are invalid")
	}
	return nil
}

func ValidateGroupMembershipList(value GroupMembershipList) error {
	if value.APIVersion != APIVersion || value.Kind != "GroupMembershipList" ||
		ValidateID("accountId", string(value.AccountID)) != nil || ValidateID("groupId", string(value.GroupID)) != nil ||
		value.Items == nil || len(value.Items) > 100 {
		return errors.New("group membership list is invalid")
	}
	var previous GroupMembershipID
	for _, item := range value.Items {
		membership := item.Membership
		if ValidateGroupMembershipAccess(item) != nil || membership.AccountID != value.AccountID ||
			membership.GroupID != value.GroupID || membership.ID <= previous {
			return errors.New("group membership list item is invalid")
		}
		previous = membership.ID
	}
	if value.NextAfter != "" && (len(value.Items) != DirectoryPageSize || ValidatePageCursor(value.NextAfter) != nil) {
		return errors.New("group membership page boundary is invalid")
	}
	return nil
}

func ValidateAccountList(value AccountList) error {
	if value.APIVersion != APIVersion || value.Kind != "AccountList" || value.Items == nil || len(value.Items) > 100 {
		return errors.New("account list is invalid")
	}
	var previous string
	for _, item := range value.Items {
		if ValidateAccountAccess(item) != nil || string(item.Account.ID) <= previous {
			return errors.New("account list item is invalid")
		}
		previous = string(item.Account.ID)
	}
	if value.NextAfter != "" && (len(value.Items) != DirectoryPageSize || ValidatePageCursor(value.NextAfter) != nil) {
		return errors.New("account page boundary is invalid")
	}
	return nil
}

func ValidateAccountAccess(value AccountAccess) error {
	expected := expectedCapabilitySet(
		struct {
			Action   Action
			Resource ResourceReference
		}{ActionIAMAccountSetStatus, ResourceReference{Kind: ResourceAccount, ID: string(value.Account.ID)}},
		struct {
			Action   Action
			Resource ResourceReference
		}{ActionIAMAccountRootCredentialsRecover, ResourceReference{Kind: ResourceAccount, ID: string(value.Account.ID)}},
	)
	return errors.Join(ValidateAccount(value.Account), validateCapabilities(value.Capabilities, expected))
}

func validateLoginName(value string) error {
	if !loginPattern.MatchString(value) {
		return errors.New("loginName is invalid")
	}
	return nil
}

func validateText(name, value string, minimum, maximum int) error {
	if !utf8.ValidString(value) || len(value) < minimum || len(value) > maximum || strings.TrimSpace(value) != value {
		return fmt.Errorf("%s is invalid", name)
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return fmt.Errorf("%s is invalid", name)
		}
	}
	return nil
}

func validateTime(name string, value time.Time) error {
	if value.IsZero() || value.Location() != time.UTC || value != value.Round(0) || value.Nanosecond()%1_000 != 0 {
		return fmt.Errorf("%s must use UTC microsecond precision", name)
	}
	return nil
}

func validateChronology(createdAt, updatedAt time.Time) error {
	var problems []error
	problems = append(problems, validateTime("createdAt", createdAt), validateTime("updatedAt", updatedAt))
	if updatedAt.Before(createdAt) {
		problems = append(problems, errors.New("updatedAt precedes createdAt"))
	}
	return errors.Join(problems...)
}

func validatePositiveVersion(value uint64) error {
	if value == 0 || value > 9007199254740991 {
		return errors.New("resource version is invalid")
	}
	return nil
}
