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
		ValidateID("serviceIdentity.organizationId", string(value.OrganizationID)),
		ValidateID("serviceIdentity.principalId", string(value.PrincipalID)),
	)
	if !knownServicePurpose(value.Purpose) {
		problems = append(problems, errors.New("service identity purpose is invalid"))
	}
	return errors.Join(problems...)
}

func ValidateResolveAuditProducerRequest(value ResolveAuditProducerRequest) error {
	return ValidateID("organizationId", string(value.OrganizationID))
}

func ValidateAuditProducerAuthorization(value AuditProducerAuthorization) error {
	if value.APIVersion != APIVersion || value.Kind != "AuditProducerAuthorization" ||
		(value.Producer.Purpose != ServiceIAM && value.Producer.Purpose != ServicePaaS && value.Producer.Purpose != ServiceAudit) {
		return errors.New("audit producer authorization is invalid")
	}
	return errors.Join(ValidateServiceIdentity(value.Producer), ValidateID("organizationId", string(value.OrganizationID)))
}

func ValidateBootstrapStatus(value BootstrapStatus) error {
	if value.APIVersion != APIVersion || value.Kind != "BootstrapStatus" {
		return errors.New("bootstrap status type metadata is invalid")
	}
	switch value.State {
	case BootstrapUninitialized:
		if value.InstallationID != "" || value.OrganizationID != "" ||
			value.ContentDigest != "" || value.AppliedAt != nil {
			return errors.New("uninitialized bootstrap status contains initialized data")
		}
		return nil
	case BootstrapReady:
		var problems []error
		problems = append(problems,
			ValidateID("installationId", value.InstallationID),
			ValidateID("organizationId", string(value.OrganizationID)),
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
	if value.InitialRole != nil && !UserAssignableRole(*value.InitialRole) {
		problems = append(problems, errors.New("initial role is invalid"))
	}
	return errors.Join(problems...)
}

func ValidatePutRoleBindingRequest(value PutRoleBindingRequest) error {
	var problems []error
	problems = append(problems,
		ValidateID("principalId", string(value.PrincipalID)),
		ValidateID("requestId", value.RequestID),
	)
	if !UserAssignableRole(value.Role) {
		problems = append(problems, errors.New("role is invalid"))
	}
	return errors.Join(problems...)
}

func ValidateRevokeRoleBindingRequest(value RevokeRoleBindingRequest) error {
	return ValidateID("requestId", value.RequestID)
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

func ValidateAuthorizationDecision(value AuthorizationDecision) error {
	var problems []error
	if value.APIVersion != APIVersion || value.Kind != "AuthorizationDecision" {
		problems = append(problems, errors.New("authorization decision type metadata is invalid"))
	}
	problems = append(problems,
		ValidateID("id", string(value.ID)),
		validateResourceForAction(value.Action, value.Resource),
		ValidateID("requestId", value.RequestID),
		validateTime("decidedAt", value.DecidedAt),
	)
	if value.Allowed {
		if value.Reason != DecisionAllowed || value.Subject == nil {
			problems = append(problems, errors.New("allowed decision is incomplete"))
		} else {
			problems = append(problems, ValidateSubject(*value.Subject))
		}
		problems = append(problems, ValidateID("tenantId", string(value.TenantID)))
	} else if value.Reason != DecisionDenied || value.Subject != nil || value.TenantID != "" {
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
	if value.Status != OrganizationActive && value.Status != OrganizationDisabled {
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
		ValidateID("principal.organizationId", string(value.OrganizationID)),
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

func ValidateRoleBinding(value RoleBinding) error {
	var problems []error
	if value.APIVersion != APIVersion || value.Kind != "RoleBinding" {
		problems = append(problems, errors.New("role binding type metadata is invalid"))
	}
	if !knownRole(value.Role) {
		problems = append(problems, errors.New("role is invalid"))
	}
	problems = append(problems,
		ValidateID("roleBinding.id", string(value.ID)),
		ValidateID("roleBinding.organizationId", string(value.OrganizationID)),
		ValidateID("roleBinding.principalId", string(value.PrincipalID)),
		validatePositiveVersion(value.ResourceVersion),
		validateChronology(value.CreatedAt, value.UpdatedAt),
	)
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
		ValidateID("session.organizationId", string(value.OrganizationID)),
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
	for _, candidate := range allActions {
		if value == candidate {
			return true
		}
	}
	return false
}

func knownRole(value BuiltinRole) bool {
	for _, candidate := range allBuiltinRoles {
		if value == candidate {
			return true
		}
	}
	return false
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

// ResourceKindForAction is the single action-to-resource catalog used by
// domain validation and contract generation.
func ResourceKindForAction(action Action) (ResourceKind, bool) {
	switch action {
	case ActionIAMPrincipalCreate, ActionIAMPrincipalList,
		ActionIAMOrganizationCreate, ActionIAMOrganizationRead, ActionIAMAccountAliasSet:
		return ResourceOrganization, true
	case ActionIAMPrincipalRead, ActionIAMRoleBindingPut,
		ActionIAMPrincipalSetStatus, ActionIAMPasswordReset:
		return ResourcePrincipal, true
	case ActionIAMRoleBindingRevoke:
		return ResourceRoleBinding, true
	case ActionIAMSessionRevoke:
		return ResourceSession, true
	case ActionPaaSApplicationCreate, ActionPaaSApplicationRead:
		return ResourceApplication, true
	case ActionPaaSConfigurationCreate, ActionPaaSConfigurationRead:
		return ResourceConfiguration, true
	case ActionPaaSConfigurationRevisionCreate, ActionPaaSConfigurationRevisionRead:
		return ResourceConfigurationRevision, true
	case ActionPaaSApplicationRevisionCreate, ActionPaaSApplicationRevisionRead:
		return ResourceApplicationRevision, true
	case ActionPaaSDeploymentCreate, ActionPaaSDeploymentUpdate,
		ActionPaaSDeploymentRollback, ActionPaaSDeploymentStop, ActionPaaSDeploymentRead:
		return ResourceDeployment, true
	case ActionPaaSOperationRead:
		return ResourceOperation, true
	case ActionManagedServiceOfferingRead:
		return ResourceServiceOffering, true
	case ActionManagedServiceRegionRead:
		return ResourceRegion, true
	case ActionManagedServiceQuotaEntitlementActivate,
		ActionManagedServiceQuotaEntitlementRead:
		return ResourceQuotaEntitlement, true
	case ActionManagedServiceInstallationCreate,
		ActionManagedServiceInstallationRead:
		return ResourceServiceInstallation, true
	case ActionAuditRecordRead:
		return ResourceAuditRecord, true
	case ActionAuditIntegrityVerify:
		return ResourceAuditChain, true
	case ActionInstallationVerify:
		return ResourceInstallation, true
	default:
		return "", false
	}
}

// ValidateLoginIdentifier accepts a primary login or one qualified subaccount
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

func UserAssignableRole(role BuiltinRole) bool {
	return knownRole(role) && role != RoleInstallationVerifier
}

func ValidateCreateOrganizationRequest(value CreateOrganizationRequest) error {
	var secretError error
	if !value.InitialPassword.Present() {
		secretError = ErrInvalidSecret
	}
	return errors.Join(
		ValidateID("organization.id", string(value.ID)),
		validateText("displayName", value.DisplayName, 1, 128),
		validateLoginName(value.AdministratorLoginName),
		validateText("administratorDisplayName", value.AdministratorDisplayName, 1, 128),
		ValidateID("requestId", value.RequestID), secretError,
	)
}

func ValidateSetAccountAliasRequest(value SetAccountAliasRequest) error {
	return errors.Join(ValidateAccountAlias(value.Alias),
		validatePositiveVersion(value.ResourceVersion), ValidateID("requestId", value.RequestID))
}

func ValidateSetPrincipalStatusRequest(value SetPrincipalStatusRequest) error {
	if value.Status != PrincipalActive && value.Status != PrincipalDisabled {
		return errors.New("principal status is invalid")
	}
	return errors.Join(validatePositiveVersion(value.ResourceVersion), ValidateID("requestId", value.RequestID))
}

func ValidateResetUserPasswordRequest(value ResetUserPasswordRequest) error {
	if !value.InitialPassword.Present() {
		return ErrInvalidSecret
	}
	return errors.Join(validatePositiveVersion(value.ResourceVersion), ValidateID("requestId", value.RequestID))
}

func ValidateOrganizationAccount(value OrganizationAccount) error {
	var aliasError error
	if value.LoginAlias != nil {
		aliasError = ValidateAccountAlias(*value.LoginAlias)
	}
	return errors.Join(ValidateOrganization(value.Organization),
		ValidateID("primaryPrincipalId", string(value.PrimaryPrincipalID)),
		validateLoginName(value.PrimaryLoginName), aliasError)
}

func ValidateCurrentIdentity(value CurrentIdentity) error {
	if value.APIVersion != APIVersion || value.Kind != "CurrentIdentity" ||
		value.Principal.Type != PrincipalUser || value.Roles == nil ||
		value.Principal.OrganizationID != value.Account.Organization.ID ||
		(value.CanCreateOrganizations && (value.Principal.ID != value.Account.PrimaryPrincipalID || value.Principal.MustChangePassword)) {
		return errors.New("current identity is invalid")
	}
	seen := map[BuiltinRole]bool{}
	for _, role := range value.Roles {
		if !UserAssignableRole(role) || seen[role] {
			return errors.New("current roles are invalid")
		}
		seen[role] = true
	}
	if value.CanCreateOrganizations && !seen[RoleOrganizationAdmin] {
		return errors.New("account-opening capability is invalid")
	}
	return errors.Join(ValidateOrganizationAccount(value.Account), ValidatePrincipal(value.Principal))
}

func ValidatePrincipalList(value PrincipalList) error {
	if value.APIVersion != APIVersion || value.Kind != "PrincipalList" || value.Items == nil || len(value.Items) > 100 {
		return errors.New("principal list is invalid")
	}
	var previous string
	var tenant OrganizationID
	for _, item := range value.Items {
		if ValidatePrincipal(item.Principal) != nil || item.Principal.Type != PrincipalUser ||
			string(item.Principal.ID) <= previous || item.RoleBindings == nil {
			return errors.New("principal list item is invalid")
		}
		previous = string(item.Principal.ID)
		if tenant != "" && item.Principal.OrganizationID != tenant {
			return errors.New("principal directory contains multiple tenants")
		}
		tenant = item.Principal.OrganizationID
		roles := map[BuiltinRole]bool{}
		for _, binding := range item.RoleBindings {
			if ValidateRoleBinding(binding) != nil || !UserAssignableRole(binding.Role) ||
				binding.OrganizationID != item.Principal.OrganizationID || binding.PrincipalID != item.Principal.ID || roles[binding.Role] {
				return errors.New("principal role binding is invalid")
			}
			roles[binding.Role] = true
		}
	}
	if value.NextAfter != "" && (previous == "" || value.NextAfter != previous) {
		return errors.New("principal page boundary is invalid")
	}
	return nil
}

func ValidateOrganizationAccountList(value OrganizationAccountList) error {
	if value.APIVersion != APIVersion || value.Kind != "OrganizationAccountList" || value.Items == nil || len(value.Items) > 100 {
		return errors.New("organization list is invalid")
	}
	var previous string
	for _, item := range value.Items {
		if ValidateOrganizationAccount(item) != nil || string(item.Organization.ID) <= previous {
			return errors.New("organization list item is invalid")
		}
		previous = string(item.Organization.ID)
	}
	if value.NextAfter != "" && (previous == "" || value.NextAfter != previous) {
		return errors.New("organization page boundary is invalid")
	}
	return nil
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
