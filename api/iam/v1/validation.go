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
	if !knownAction(value.Action) {
		problems = append(problems, errors.New("authorization action is invalid"))
	}
	problems = append(problems,
		validateResourceForAction(value.Action, value.Resource),
		ValidateID("requestId", value.RequestID),
		ValidateID("correlationId", value.CorrelationID),
	)
	return errors.Join(problems...)
}

// ValidateAuthorizationDecision validates immutable evidence, including exact
// published retired actions. It does not admit a new authorization request;
// that boundary must use ValidateAuthorizationRequest and the current catalog.
func ValidateAuthorizationDecision(value AuthorizationDecision) error {
	var problems []error
	definition, known := lookupRecordedActionDefinition(value.Action)
	if !known || value.Resource.Kind != definition.ResourceKind {
		problems = append(problems, errors.New("recorded action and resource kind are invalid"))
	}
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
			if value.TenantID != "" || value.Subject != nil && value.Subject.Type != PrincipalUser {
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
	if value.Type != PrincipalUser && value.Type != PrincipalServiceAccount {
		problems = append(problems, errors.New("subject type is invalid"))
	}
	problems = append(problems, ValidateID("subject.id", string(value.ID)))
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
	switch value {
	case CapabilityAuthorityRequired,
		CapabilityCurrentCredentialChangeRequired,
		CapabilitySelfProtected,
		CapabilityRootIdentityProtected,
		CapabilityInstallationAuthorityProtected,
		CapabilitySystemAccountProtected,
		CapabilityTargetDisabled,
		CapabilityTargetCredentialChangeRequired:
		return true
	default:
		return false
	}
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
	if value.APIVersion != APIVersion || value.Kind != "CurrentIdentity" ||
		value.PolicyAttachments == nil || len(value.PolicyAttachments) > 256 ||
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
	for _, attachment := range value.PolicyAttachments {
		if ValidatePolicyAttachment(attachment) != nil || attachment.RevokedAt != nil || seen[attachment.ID] ||
			attachment.AccountID != value.Account.ID || attachment.Target.Kind != PolicyTargetUser ||
			attachment.Target.ID != string(value.User.ID) {
			return errors.New("current policy attachments are invalid")
		}
		seen[attachment.ID] = true
	}
	expected := expectedCapabilitySet(
		struct {
			Action   Action
			Resource ResourceReference
		}{ActionIAMAccountCreate, ResourceReference{Kind: ResourceAccount, ID: "accounts"}},
		struct {
			Action   Action
			Resource ResourceReference
		}{ActionIAMAccountRead, ResourceReference{Kind: ResourceAccount, ID: "accounts"}},
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
	)
	if validateCapabilities(value.Capabilities, expected) != nil {
		return errors.New("current identity capabilities are invalid")
	}
	return errors.Join(ValidateAccount(value.Account), ValidateUser(value.User))
}

func ValidateUserList(value UserList) error {
	if value.APIVersion != APIVersion || value.Kind != "UserList" || value.Items == nil || len(value.Items) > 100 {
		return errors.New("user list is invalid")
	}
	var previous string
	var account AccountID
	for _, item := range value.Items {
		if ValidateUser(item.User) != nil || string(item.User.ID) <= previous ||
			item.PolicyAttachments == nil || len(item.PolicyAttachments) > 256 {
			return errors.New("user list item is invalid")
		}
		previous = string(item.User.ID)
		if account != "" && item.User.AccountID != account {
			return errors.New("user directory contains multiple accounts")
		}
		account = item.User.AccountID
		attachments := map[PolicyAttachmentID]bool{}
		policies := map[PolicyID]bool{}
		for _, attachment := range item.PolicyAttachments {
			if ValidatePolicyAttachment(attachment) != nil || attachment.RevokedAt != nil ||
				attachment.AccountID != item.User.AccountID || attachment.Target.Kind != PolicyTargetUser ||
				attachment.Target.ID != string(item.User.ID) || attachments[attachment.ID] || policies[attachment.PolicyID] {
				return errors.New("user policy attachment is invalid")
			}
			attachments[attachment.ID] = true
			policies[attachment.PolicyID] = true
		}
		expected := expectedCapabilitySet(
			struct {
				Action   Action
				Resource ResourceReference
			}{ActionIAMUserSetStatus, ResourceReference{Kind: ResourceUser, ID: string(item.User.ID)}},
			struct {
				Action   Action
				Resource ResourceReference
			}{ActionIAMUserPasswordReset, ResourceReference{Kind: ResourceUser, ID: string(item.User.ID)}},
			struct {
				Action   Action
				Resource ResourceReference
			}{ActionIAMPolicyAttachmentCreate, ResourceReference{Kind: ResourceUser, ID: string(item.User.ID)}},
			struct {
				Action   Action
				Resource ResourceReference
			}{ActionIAMPlatformPolicyAttachmentCreate, ResourceReference{Kind: ResourceUser, ID: string(item.User.ID)}},
		)
		for _, attachment := range item.PolicyAttachments {
			action := ActionIAMPolicyAttachmentRevoke
			if attachment.Scope == AuthorityScopeInstallation {
				action = ActionIAMPlatformPolicyAttachmentRevoke
			}
			expected[capabilityKey(action, ResourceReference{Kind: ResourcePolicyAttachment, ID: string(attachment.ID)})] = struct{}{}
		}
		if validateCapabilities(item.Capabilities, expected) != nil {
			return errors.New("user capabilities are invalid")
		}
	}
	if value.NextAfter != "" && (previous == "" || value.NextAfter != previous) {
		return errors.New("user page boundary is invalid")
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
	if value.NextAfter != "" && (previous == "" || value.NextAfter != previous) {
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
