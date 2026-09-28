package identityaccess

import (
	"cmp"
	"context"
	"errors"
	"slices"
	"strconv"
	"time"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/iam/internal/authority"
)

var ErrSecuritySettingsChangeNotFound = errors.New("security settings change was not found")

type SecuritySettingsMutation struct {
	Session    iamv1.Session
	DecisionID iamv1.DecisionID
	Request    iamv1.UpdateAccountSecuritySettingsRequest
	AuditEvent auditv1.Event
}

func (service *Authority) CurrentIdentity(ctx context.Context, credential iamv1.Secret) (iamv1.CurrentIdentity, error) {
	var result iamv1.CurrentIdentity
	err := service.withinTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		now, err := transactionTime(ctx, tx)
		if err != nil {
			return err
		}
		binding, err := service.authenticateSession(ctx, tx, credential, now)
		if err != nil {
			return err
		}
		if err := tx.CheckCurrentAuthorizationProfiles(ctx); err != nil {
			return err
		}
		subject := binding.Subject
		account, err := tx.ReadAccount(ctx, subject.Organization.ID, subject.Principal.ID)
		if err != nil {
			return err
		}
		sources := make([]iamv1.PolicyGrantSource, 0, len(subject.Policies))
		for _, row := range subject.Policies {
			source := iamv1.PolicyGrantSource{Kind: iamv1.PolicyGrantDirect, Attachment: row.Attachment}
			if row.Membership != nil {
				source.Kind, source.Membership = iamv1.PolicyGrantGroup, row.Membership
			}
			sources = append(sources, source)
		}
		user, err := userFromPrincipal(subject.Principal)
		if err != nil {
			return err
		}
		identityKind := iamv1.IdentityUser
		if account.RootIdentity.PrincipalID == user.ID {
			identityKind = iamv1.IdentityRoot
		}
		capabilities, err := currentIdentityCapabilities(binding, identityKind == iamv1.IdentityRoot, now)
		if err != nil {
			return err
		}
		result = iamv1.CurrentIdentity{APIVersion: iamv1.APIVersion, Kind: "CurrentIdentity", Account: account,
			User: user, IdentityKind: identityKind, PolicySources: sources, Capabilities: capabilities}
		result.PermissionBoundary = iamv1.UserPermissionBoundary{APIVersion: iamv1.APIVersion, Kind: "UserPermissionBoundary", AccountID: account.ID, UserID: user.ID, ResourceVersion: user.ResourceVersion}
		if subject.Boundary.Version != nil {
			result.PermissionBoundary.Policy = &iamv1.PolicyVersionReference{PolicyID: subject.Boundary.Version.PolicyID, VersionID: subject.Boundary.Version.ID, ContentDigest: subject.Boundary.Version.ContentDigest}
		}
		return nil
	})
	if err != nil {
		return iamv1.CurrentIdentity{}, err
	}
	if iamv1.ValidateCurrentIdentity(result) != nil {
		return iamv1.CurrentIdentity{}, ErrUnavailable
	}
	return result, nil
}

func projectCapability(subject SessionCredential, action iamv1.Action, resource iamv1.ResourceReference, mode iamv1.AuthorizationResourceMode, usage iamv1.AuthorizationCollectionUsage, now time.Time) (iamv1.ActionCapability, error) {
	request, err := iamv1.NewAuthorizationRequest(action, resource, mode, usage, "capability-projection", "capability-projection")
	if err != nil {
		return iamv1.ActionCapability{}, ErrUnavailable
	}
	evaluation, err := authority.Decide(subject.Subject, iamv1.ServiceIAM, request, "capability-projection", now)
	if err != nil {
		return iamv1.ActionCapability{}, ErrUnavailable
	}
	result := iamv1.ActionCapability{Action: action, Resource: resource, Available: evaluation.Allowed}
	if !result.Available {
		result.RestrictionReason = iamv1.CapabilityAuthorityRequired
		if subject.Subject.Principal.MustChangePassword {
			result.RestrictionReason = iamv1.CapabilityCurrentCredentialChangeRequired
		}
	}
	return result, nil
}

func restrictCapability(value *iamv1.ActionCapability, reason iamv1.CapabilityRestriction) {
	if value.Available {
		value.Available = false
		value.RestrictionReason = reason
	}
}

func currentIdentityCapabilities(subject SessionCredential, root bool, now time.Time) ([]iamv1.ActionCapability, error) {
	account := iamv1.ResourceReference{Kind: iamv1.ResourceAccount, ID: string(subject.Subject.Organization.ID)}
	requests := []struct {
		action   iamv1.Action
		resource iamv1.ResourceReference
		mode     iamv1.AuthorizationResourceMode
		usage    iamv1.AuthorizationCollectionUsage
	}{
		{iamv1.ActionIAMAccountCreate, iamv1.ResourceReference{Kind: iamv1.ResourceAccount, ID: "collection"}, iamv1.AuthorizationResourceCollection, iamv1.AuthorizationCollectionCreate},
		{iamv1.ActionIAMAccountRead, iamv1.ResourceReference{Kind: iamv1.ResourceAccount, ID: "collection"}, iamv1.AuthorizationResourceCollection, iamv1.AuthorizationCollectionList},
		{iamv1.ActionIAMAccountAliasSet, account, iamv1.AuthorizationResourceInstance, ""},
		{iamv1.ActionIAMUserList, account, iamv1.AuthorizationResourceInstance, ""},
		{iamv1.ActionIAMUserCreate, account, iamv1.AuthorizationResourceInstance, ""},
		{iamv1.ActionIAMPolicyList, account, iamv1.AuthorizationResourceInstance, ""},
		{iamv1.ActionIAMGroupList, account, iamv1.AuthorizationResourceInstance, ""},
		{iamv1.ActionIAMGroupCreate, account, iamv1.AuthorizationResourceInstance, ""},
		{iamv1.ActionIAMRoleList, account, iamv1.AuthorizationResourceInstance, ""},
		{iamv1.ActionIAMRoleCreate, account, iamv1.AuthorizationResourceInstance, ""},
	}
	result := make([]iamv1.ActionCapability, 0, len(requests))
	for _, request := range requests {
		capability, err := projectCapability(subject, request.action, request.resource, request.mode, request.usage, now)
		if err != nil {
			return nil, err
		}
		if request.action == iamv1.ActionIAMRoleCreate && !root {
			restrictCapability(&capability, iamv1.CapabilityAuthorityRequired)
		}
		result = append(result, capability)
	}
	return result, nil
}

// This boundary keeps authenticated tenant derivation, denied-decision Audit,
// and the admitted account workflow in the same serializable transaction.
func withAccountAuthorization[T any](service *Authority, ctx context.Context, credential iamv1.Secret,
	action iamv1.Action, mode iamv1.AuthorizationResourceMode, usage iamv1.AuthorizationCollectionUsage, target iamv1.ResourceReference, requestID string,
	apply func(context.Context, Transaction, SessionCredential, iamv1.AuthorizationDecision, time.Time) (T, error)) (T, error) {
	var result T
	denied := false
	err := service.withinTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		denied = false
		now, err := transactionTime(ctx, tx)
		if err != nil {
			return err
		}
		subject, err := service.authenticateSession(ctx, tx, credential, now)
		if err != nil {
			return err
		}
		resource := target
		if resource.ID == "" {
			resource.ID = string(subject.Subject.Organization.ID)
		}
		decision, err := service.managementDecision(ctx, tx, subject, action, resource, mode, usage, requestID, now)
		if err != nil {
			return err
		}
		if !decision.Allowed {
			denied = true
			return nil
		}
		result, err = apply(ctx, tx, subject, decision, now)
		return err
	})
	if err != nil {
		var zero T
		return zero, err
	}
	if denied {
		var zero T
		return zero, ErrForbidden
	}
	return result, nil
}

func (service *Authority) directoryPosition(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, after string, now time.Time) (string, authority.DirectoryQuery, error) {
	var query authority.DirectoryQuery
	if service.cursors == nil {
		return "", query, ErrUnavailable
	}
	status, err := tx.BootstrapStatus(ctx)
	if err != nil || iamv1.ValidateBootstrapStatus(status) != nil || status.State != iamv1.BootstrapReady {
		return "", query, ErrUnavailable
	}
	query = authority.DirectoryQuery{InstallationID: status.InstallationID, Action: decision.Action, Resource: decision.Resource}
	if after == "" {
		return "", query, nil
	}
	position, err := service.cursors.Decode(after, subject.Subject, query, now)
	if err != nil {
		return "", query, ErrInvalidArgument
	}
	return position, query, nil
}

func (service *Authority) sealDirectoryPage(subject SessionCredential, query authority.DirectoryQuery, position string, now time.Time) (string, error) {
	if service.cursors == nil {
		return "", ErrUnavailable
	}
	if position == "" {
		return "", nil
	}
	value, err := service.cursors.Encode(subject.Subject, query, position, now)
	if err != nil {
		return "", ErrUnavailable
	}
	return value, nil
}

func (service *Authority) ListUsers(ctx context.Context, credential iamv1.Secret, after, requestID string) (iamv1.UserList, error) {
	if iamv1.ValidateID("requestId", requestID) != nil || (after != "" && iamv1.ValidatePageCursor(after) != nil) {
		return iamv1.UserList{}, ErrInvalidArgument
	}
	return withAccountAuthorization(service, ctx, credential, iamv1.ActionIAMUserList, iamv1.AuthorizationResourceInstance, "",
		iamv1.ResourceReference{Kind: iamv1.ResourceAccount}, requestID,
		func(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, now time.Time) (iamv1.UserList, error) {
			position, query, err := service.directoryPosition(ctx, tx, subject, decision, after, now)
			if err != nil {
				return iamv1.UserList{}, err
			}
			result, err := tx.ListUsers(ctx, AccountRead{AccountID: subject.Subject.Organization.ID, ActorPrincipalID: subject.Subject.Principal.ID, DecisionID: decision.ID, After: position})
			if err != nil {
				return iamv1.UserList{}, err
			}
			account, err := tx.ReadAccount(ctx, subject.Subject.Organization.ID, subject.Subject.Principal.ID)
			if err != nil {
				return iamv1.UserList{}, err
			}
			for index := range result.Items {
				result.Items[index].Capabilities, err = userCapabilities(subject, account, result.Items[index], now)
				if err != nil {
					return iamv1.UserList{}, err
				}
			}
			result.NextAfter, err = service.sealDirectoryPage(subject, query, result.NextAfter, now)
			if err != nil || iamv1.ValidateUserList(result) != nil {
				return iamv1.UserList{}, ErrUnavailable
			}
			return result, nil
		})
}

func (service *Authority) GetUser(ctx context.Context, credential iamv1.Secret, id iamv1.PrincipalID, requestID string) (iamv1.UserAccess, error) {
	if iamv1.ValidateID("userId", string(id)) != nil || iamv1.ValidateID("requestId", requestID) != nil {
		return iamv1.UserAccess{}, ErrInvalidArgument
	}
	return withAccountAuthorization(service, ctx, credential, iamv1.ActionIAMUserRead, iamv1.AuthorizationResourceInstance, "",
		iamv1.ResourceReference{Kind: iamv1.ResourceUser, ID: string(id)}, requestID,
		func(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, now time.Time) (iamv1.UserAccess, error) {
			result, err := tx.ReadUser(ctx, AccountRead{AccountID: subject.Subject.Organization.ID,
				ActorPrincipalID: subject.Subject.Principal.ID, DecisionID: decision.ID}, id)
			if err != nil {
				return iamv1.UserAccess{}, err
			}
			account, err := tx.ReadAccount(ctx, subject.Subject.Organization.ID, subject.Subject.Principal.ID)
			if err != nil {
				return iamv1.UserAccess{}, err
			}
			result.Capabilities, err = userCapabilities(subject, account, result, now)
			if err != nil || iamv1.ValidateUserAccess(result) != nil {
				return iamv1.UserAccess{}, ErrUnavailable
			}
			return result, nil
		})
}

func userCapabilities(subject SessionCredential, account iamv1.Account, target iamv1.UserAccess, now time.Time) ([]iamv1.ActionCapability, error) {
	if iamv1.ValidateAccount(account) != nil || account.ID != subject.Subject.Organization.ID || target.User.AccountID != account.ID {
		return nil, ErrUnavailable
	}
	user := iamv1.ResourceReference{Kind: iamv1.ResourceUser, ID: string(target.User.ID)}
	requests := []struct {
		action   iamv1.Action
		resource iamv1.ResourceReference
	}{
		{iamv1.ActionIAMUserRead, user},
		{iamv1.ActionIAMUserUpdate, user},
		{iamv1.ActionIAMUserDelete, user},
		{iamv1.ActionIAMUserPermissionBoundarySet, user},
		{iamv1.ActionIAMUserPermissionBoundaryRemove, user},
		{iamv1.ActionIAMUserSetStatus, user},
		{iamv1.ActionIAMUserPasswordReset, user},
		{iamv1.ActionIAMPolicyAttachmentCreate, user},
		{iamv1.ActionIAMPlatformPolicyAttachmentCreate, user},
	}
	for _, attachment := range target.PolicyAttachments {
		action := iamv1.ActionIAMPolicyAttachmentRevoke
		if attachment.Scope == iamv1.AuthorityScopeInstallation {
			action = iamv1.ActionIAMPlatformPolicyAttachmentRevoke
		}
		requests = append(requests, struct {
			action   iamv1.Action
			resource iamv1.ResourceReference
		}{action, iamv1.ResourceReference{Kind: iamv1.ResourcePolicyAttachment, ID: string(attachment.ID)}})
	}
	hasInstallationAuthority := false
	for _, attachment := range target.PolicyAttachments {
		hasInstallationAuthority = hasInstallationAuthority || attachment.Scope == iamv1.AuthorityScopeInstallation
	}
	result := make([]iamv1.ActionCapability, 0, len(requests))
	for _, request := range requests {
		capability, err := projectCapability(subject, request.action, request.resource, iamv1.AuthorizationResourceInstance, "", now)
		if err != nil {
			return nil, err
		}
		switch request.action {
		case iamv1.ActionIAMUserPermissionBoundarySet, iamv1.ActionIAMUserPermissionBoundaryRemove:
			if target.User.ID == account.RootIdentity.PrincipalID {
				restrictCapability(&capability, iamv1.CapabilityRootIdentityProtected)
			} else if subject.Subject.Principal.ID != account.RootIdentity.PrincipalID {
				restrictCapability(&capability, iamv1.CapabilityAuthorityRequired)
			}
		case iamv1.ActionIAMUserSetStatus, iamv1.ActionIAMUserPasswordReset:
			if target.User.ID == subject.Subject.Principal.ID {
				restrictCapability(&capability, iamv1.CapabilitySelfProtected)
			} else if hasInstallationAuthority {
				restrictCapability(&capability, iamv1.CapabilityInstallationAuthorityProtected)
			}
		case iamv1.ActionIAMUserDelete:
			if target.User.ID == subject.Subject.Principal.ID {
				restrictCapability(&capability, iamv1.CapabilitySelfProtected)
			} else if hasInstallationAuthority {
				restrictCapability(&capability, iamv1.CapabilityInstallationAuthorityProtected)
			} else if target.User.Status != iamv1.PrincipalDisabled {
				restrictCapability(&capability, iamv1.CapabilityTargetMustBeDisabled)
			}
		case iamv1.ActionIAMPolicyAttachmentCreate, iamv1.ActionIAMPlatformPolicyAttachmentCreate:
			if target.User.Status != iamv1.PrincipalActive {
				restrictCapability(&capability, iamv1.CapabilityTargetDisabled)
			} else if request.action == iamv1.ActionIAMPlatformPolicyAttachmentCreate && target.User.MustChangePassword {
				restrictCapability(&capability, iamv1.CapabilityTargetCredentialChangeRequired)
			}
		}
		result = append(result, capability)
	}
	return result, nil
}

func (service *Authority) AccountSecuritySettings(ctx context.Context, credential iamv1.Secret, requestID string) (iamv1.AccountSecuritySettings, error) {
	if iamv1.ValidateID("requestId", requestID) != nil {
		return iamv1.AccountSecuritySettings{}, ErrInvalidArgument
	}
	return withAccountAuthorization(service, ctx, credential, iamv1.ActionIAMSecuritySettingsRead, iamv1.AuthorizationResourceInstance, "",
		iamv1.ResourceReference{Kind: iamv1.ResourceAccount}, requestID,
		func(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, now time.Time) (iamv1.AccountSecuritySettings, error) {
			result, err := tx.ReadAccountSecuritySettings(ctx, AccountRead{AccountID: subject.Subject.Organization.ID,
				ActorPrincipalID: subject.Subject.Principal.ID, DecisionID: decision.ID})
			if err != nil {
				return iamv1.AccountSecuritySettings{}, err
			}
			if iamv1.ValidateAccountSecuritySettings(result) != nil || result.AccountID != subject.Subject.Organization.ID || result.UpdatedAt.After(now) {
				return iamv1.AccountSecuritySettings{}, ErrUnavailable
			}
			return result, nil
		})
}

func (service *Authority) UpdateAccountSecuritySettings(ctx context.Context, credential iamv1.Secret, request iamv1.UpdateAccountSecuritySettingsRequest) (iamv1.UpdateAccountSecuritySettingsResponse, error) {
	if iamv1.ValidateUpdateAccountSecuritySettingsRequest(request) != nil {
		return iamv1.UpdateAccountSecuritySettingsResponse{}, ErrInvalidArgument
	}
	digest, err := digestSanitized("security-settings-update", request)
	if err != nil {
		return iamv1.UpdateAccountSecuritySettingsResponse{}, err
	}
	var result iamv1.UpdateAccountSecuritySettingsResponse
	denied := false
	err = service.withinTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		denied, result = false, iamv1.UpdateAccountSecuritySettingsResponse{}
		now, err := transactionTime(ctx, tx)
		if err != nil {
			return err
		}
		subject, err := service.authenticateSession(ctx, tx, credential, now)
		if err != nil {
			return err
		}
		// Lookup derives the Account, but does not grant authority. Take its
		// exclusive mutation lock before the USER/policy locks in the decision;
		// the database rechecks this same Session under that lock.
		if err := tx.LockAccountSecuritySettings(ctx, subject.Subject.Session); err != nil {
			return err
		}
		decision, err := service.managementDecision(ctx, tx, subject, iamv1.ActionIAMSecuritySettingsUpdate,
			iamv1.ResourceReference{Kind: iamv1.ResourceAccount, ID: string(subject.Subject.Organization.ID)},
			iamv1.AuthorizationResourceInstance, "", request.RequestID, now)
		if err != nil {
			return err
		}
		if !decision.Allowed {
			denied = true
			return nil
		}
		event, err := service.newManagementEvent(subject, auditv1.ActionIAMSecuritySettingsUpdated, auditv1.TargetAccount,
			string(subject.Subject.Organization.ID), decision.ID, digest, request.RequestID, now)
		if err != nil {
			return err
		}
		result, err = tx.UpdateAccountSecuritySettings(ctx, SecuritySettingsMutation{Session: subject.Subject.Session, DecisionID: decision.ID, Request: request, AuditEvent: event})
		if err != nil {
			return err
		}
		if iamv1.ValidateUpdateAccountSecuritySettingsResponse(result) != nil || result.Change.RequestID != request.RequestID ||
			result.Change.ExpectedResourceVersion != request.ExpectedResourceVersion || result.Change.Settings.AccountID != subject.Subject.Organization.ID ||
			result.Change.Settings.MFA != request.MFA || result.Change.Settings.UpdatedAt.After(now) ||
			(result.Outcome == "APPLIED" && !result.Change.Settings.UpdatedAt.Equal(now)) {
			return ErrUnavailable
		}
		return nil
	})
	if err != nil {
		return iamv1.UpdateAccountSecuritySettingsResponse{}, err
	}
	if denied {
		return iamv1.UpdateAccountSecuritySettingsResponse{}, ErrForbidden
	}
	return result, nil
}

func (service *Authority) SecuritySettingsChange(ctx context.Context, credential iamv1.Secret, commandID, requestID string) (iamv1.AccountSecuritySettingsChange, error) {
	if iamv1.ValidateID("commandId", commandID) != nil || iamv1.ValidateID("requestId", requestID) != nil {
		return iamv1.AccountSecuritySettingsChange{}, ErrInvalidArgument
	}
	return withAccountAuthorization(service, ctx, credential, iamv1.ActionIAMSecuritySettingsRead, iamv1.AuthorizationResourceInstance, "",
		iamv1.ResourceReference{Kind: iamv1.ResourceAccount}, requestID,
		func(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, now time.Time) (iamv1.AccountSecuritySettingsChange, error) {
			result, err := tx.ReadSecuritySettingsChange(ctx, AccountRead{AccountID: subject.Subject.Organization.ID,
				ActorPrincipalID: subject.Subject.Principal.ID, DecisionID: decision.ID}, commandID)
			if err != nil {
				return iamv1.AccountSecuritySettingsChange{}, err
			}
			if iamv1.ValidateAccountSecuritySettingsChange(result) != nil || result.RequestID != commandID ||
				result.Settings.AccountID != subject.Subject.Organization.ID || result.Settings.UpdatedAt.After(now) {
				return iamv1.AccountSecuritySettingsChange{}, ErrUnavailable
			}
			return result, nil
		})
}

func (service *Authority) ListAuthorizationProfiles(ctx context.Context, credential iamv1.Secret, requestID string) (iamv1.AuthorizationProfileList, error) {
	if iamv1.ValidateID("requestId", requestID) != nil {
		return iamv1.AuthorizationProfileList{}, ErrInvalidArgument
	}
	return withAccountAuthorization(service, ctx, credential, iamv1.ActionIAMPolicyList, iamv1.AuthorizationResourceInstance, "",
		iamv1.ResourceReference{Kind: iamv1.ResourceAccount}, requestID,
		func(_ context.Context, _ Transaction, subject SessionCredential, _ iamv1.AuthorizationDecision, _ time.Time) (iamv1.AuthorizationProfileList, error) {
			// managementDecision has locked and checked the COMPLETE registry
			// against this source in the same transaction. Never expose source
			// constants from an anonymous or registry-unavailable fast path.
			profiles := iamv1.AllAuthorizationProfiles()
			slices.SortFunc(profiles, func(left, right iamv1.AuthorizationProfile) int {
				return cmp.Compare(left.Product, right.Product)
			})
			result := iamv1.AuthorizationProfileList{APIVersion: iamv1.APIVersion, Kind: "AuthorizationProfileList",
				AccountID: subject.Subject.Organization.ID, Items: make([]iamv1.AuthorizationProfileEntry, 0, len(profiles))}
			for _, profile := range profiles {
				_, digest, err := iamv1.CanonicalizeAuthorizationProfile(profile)
				if err != nil {
					return iamv1.AuthorizationProfileList{}, ErrUnavailable
				}
				result.Items = append(result.Items, iamv1.AuthorizationProfileEntry{Profile: profile, ContentDigest: digest})
			}
			if iamv1.ValidateAuthorizationProfileList(result) != nil {
				return iamv1.AuthorizationProfileList{}, ErrUnavailable
			}
			return result, nil
		})
}

func (service *Authority) ListPolicies(ctx context.Context, credential iamv1.Secret, platform bool, requestID string) (iamv1.PolicyList, error) {
	if iamv1.ValidateID("requestId", requestID) != nil {
		return iamv1.PolicyList{}, ErrInvalidArgument
	}
	var result iamv1.PolicyList
	denied := false
	err := service.withinTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		denied = false
		now, err := transactionTime(ctx, tx)
		if err != nil {
			return err
		}
		subject, err := service.authenticateSession(ctx, tx, credential, now)
		if err != nil {
			return err
		}
		action, scope := iamv1.ActionIAMPolicyList, iamv1.AuthorityScopeTenant
		target := iamv1.ResourceReference{Kind: iamv1.ResourceAccount, ID: string(subject.Subject.Organization.ID)}
		if platform {
			action, scope = iamv1.ActionIAMPlatformPolicyList, iamv1.AuthorityScopeInstallation
			target = iamv1.ResourceReference{Kind: iamv1.ResourceInstallation, ID: subject.Subject.InstallationID}
			if target.ID == "" {
				return ErrForbidden
			}
		}
		decision, err := service.managementDecision(ctx, tx, subject, action, target, iamv1.AuthorizationResourceInstance, "", requestID, now)
		if err != nil {
			return err
		}
		if !decision.Allowed {
			denied = true
			return nil
		}
		result, err = tx.ListPolicies(ctx, AccountRead{AccountID: subject.Subject.Organization.ID,
			ActorPrincipalID: subject.Subject.Principal.ID, DecisionID: decision.ID}, scope)
		return err
	})
	if err != nil {
		return iamv1.PolicyList{}, err
	}
	if denied {
		return iamv1.PolicyList{}, ErrForbidden
	}
	if iamv1.ValidatePolicyList(result) != nil {
		return iamv1.PolicyList{}, ErrUnavailable
	}
	return result, nil
}

func (service *Authority) GetPolicy(ctx context.Context, credential iamv1.Secret, id iamv1.PolicyID, requestID string) (iamv1.PolicyDetail, error) {
	if iamv1.ValidateID("policyId", string(id)) != nil || iamv1.ValidateID("requestId", requestID) != nil {
		return iamv1.PolicyDetail{}, ErrInvalidArgument
	}
	return withAccountAuthorization(service, ctx, credential, iamv1.ActionIAMPolicyRead, iamv1.AuthorizationResourceInstance, "",
		iamv1.ResourceReference{Kind: iamv1.ResourcePolicy, ID: string(id)}, requestID,
		func(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, now time.Time) (iamv1.PolicyDetail, error) {
			return tx.ReadPolicy(ctx, AccountRead{AccountID: subject.Subject.Organization.ID,
				ActorPrincipalID: subject.Subject.Principal.ID, DecisionID: decision.ID}, id)
		})
}

func (service *Authority) GetUserPermissionBoundary(ctx context.Context, credential iamv1.Secret, user iamv1.PrincipalID, requestID string) (iamv1.UserPermissionBoundary, error) {
	if iamv1.ValidateID("userId", string(user)) != nil || iamv1.ValidateID("requestId", requestID) != nil {
		return iamv1.UserPermissionBoundary{}, ErrInvalidArgument
	}
	return withAccountAuthorization(service, ctx, credential, iamv1.ActionIAMUserRead, iamv1.AuthorizationResourceInstance, "", iamv1.ResourceReference{Kind: iamv1.ResourceUser, ID: string(user)}, requestID,
		func(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, _ time.Time) (iamv1.UserPermissionBoundary, error) {
			return tx.ReadUserPermissionBoundary(ctx, AccountRead{AccountID: subject.Subject.Organization.ID, ActorPrincipalID: subject.Subject.Principal.ID, DecisionID: decision.ID}, user)
		})
}

func (service *Authority) SetUserPermissionBoundary(ctx context.Context, credential iamv1.Secret, user iamv1.PrincipalID, request iamv1.SetUserPermissionBoundaryRequest) (iamv1.UserPermissionBoundary, error) {
	if iamv1.ValidateSetUserPermissionBoundaryRequest(request) != nil {
		return iamv1.UserPermissionBoundary{}, ErrInvalidArgument
	}
	return service.changeUserPermissionBoundary(ctx, credential, user, request)
}

func (service *Authority) RemoveUserPermissionBoundary(ctx context.Context, credential iamv1.Secret, user iamv1.PrincipalID, request iamv1.RemoveUserPermissionBoundaryRequest) (iamv1.UserPermissionBoundary, error) {
	if iamv1.ValidateRemoveUserPermissionBoundaryRequest(request) != nil {
		return iamv1.UserPermissionBoundary{}, ErrInvalidArgument
	}
	return service.changeUserPermissionBoundary(ctx, credential, user, iamv1.SetUserPermissionBoundaryRequest{ResourceVersion: request.ResourceVersion, RequestID: request.RequestID})
}

func (service *Authority) changeUserPermissionBoundary(ctx context.Context, credential iamv1.Secret, user iamv1.PrincipalID, request iamv1.SetUserPermissionBoundaryRequest) (iamv1.UserPermissionBoundary, error) {
	if iamv1.ValidateID("userId", string(user)) != nil {
		return iamv1.UserPermissionBoundary{}, ErrInvalidArgument
	}
	action, fact := iamv1.ActionIAMUserPermissionBoundarySet, auditv1.ActionIAMUserPermissionBoundarySet
	if request.PolicyID == "" {
		action, fact = iamv1.ActionIAMUserPermissionBoundaryRemove, auditv1.ActionIAMUserPermissionBoundaryRemoved
	}
	requestDigest, err := digestSanitized(string(action), struct {
		UserID  iamv1.PrincipalID                      `json:"userId"`
		Request iamv1.SetUserPermissionBoundaryRequest `json:"request"`
	}{user, request})
	if err != nil {
		return iamv1.UserPermissionBoundary{}, err
	}
	return withAccountAuthorization(service, ctx, credential, action, iamv1.AuthorizationResourceInstance, "", iamv1.ResourceReference{Kind: iamv1.ResourceUser, ID: string(user)}, request.RequestID,
		func(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, now time.Time) (iamv1.UserPermissionBoundary, error) {
			if err := requirePolicyPublisher(ctx, tx, subject); err != nil {
				return iamv1.UserPermissionBoundary{}, err
			}
			boundaryID := ""
			if request.PolicyID != "" {
				digest, err := digestSanitized("user-boundary-identity", struct {
					AccountID iamv1.AccountID   `json:"accountId"`
					ActorID   iamv1.PrincipalID `json:"actorId"`
					RequestID string            `json:"requestId"`
				}{subject.Subject.Organization.ID, subject.Subject.Principal.ID, request.RequestID})
				if err != nil {
					return iamv1.UserPermissionBoundary{}, err
				}
				boundaryID = "boundary-" + digest[len("sha256:"):]
			}
			event, err := service.newManagementEvent(subject, fact, auditv1.TargetUser, string(user), decision.ID, requestDigest, request.RequestID, now)
			if err != nil {
				return iamv1.UserPermissionBoundary{}, err
			}
			return tx.ChangeUserPermissionBoundary(ctx, UserBoundaryMutation{AccountID: subject.Subject.Organization.ID, ActorPrincipalID: subject.Subject.Principal.ID,
				SessionID: subject.Subject.Session.ID, DecisionID: decision.ID, UserID: user, ResourceVersion: request.ResourceVersion, PolicyID: request.PolicyID, PolicyResourceVersion: request.PolicyResourceVersion, BoundaryID: boundaryID, AuditEvent: event})
		})
}

func (service *Authority) CreatePolicy(ctx context.Context, credential iamv1.Secret, request iamv1.CreatePolicyRequest) (iamv1.PolicyDetail, error) {
	if iamv1.ValidateCreatePolicyRequest(request) != nil {
		return iamv1.PolicyDetail{}, ErrInvalidArgument
	}
	return withAccountAuthorization(service, ctx, credential, iamv1.ActionIAMPolicyCreate, iamv1.AuthorizationResourceInstance, "",
		iamv1.ResourceReference{Kind: iamv1.ResourceAccount}, request.RequestID,
		func(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, now time.Time) (iamv1.PolicyDetail, error) {
			account, err := tx.ReadAccount(ctx, subject.Subject.Organization.ID, subject.Subject.Principal.ID)
			if err != nil {
				return iamv1.PolicyDetail{}, err
			}
			// Publication starts root-only, in addition to the ordinary PDP. It
			// does not turn the root relation into a second policy evaluator.
			if account.RootIdentity.PrincipalID != subject.Subject.Principal.ID {
				return iamv1.PolicyDetail{}, ErrForbidden
			}
			if err := tx.CheckCurrentAuthorizationProfiles(ctx); err != nil {
				return iamv1.PolicyDetail{}, err
			}
			compilation, err := iamv1.CompilePolicyDocument(request.Document, iamv1.AllAuthorizationProfiles())
			if err != nil {
				return iamv1.PolicyDetail{}, ErrInvalidArgument
			}
			_, contentDigest, err := iamv1.CanonicalizePolicyCompilation(request.Document, compilation, iamv1.AllAuthorizationProfiles())
			if err != nil {
				return iamv1.PolicyDetail{}, ErrInvalidArgument
			}
			requestDigest, err := digestSanitized("policy-create", struct {
				DisplayName   string `json:"displayName"`
				ContentDigest string `json:"contentDigest"`
				RequestID     string `json:"requestId"`
			}{request.DisplayName, contentDigest, request.RequestID})
			if err != nil {
				return iamv1.PolicyDetail{}, err
			}
			identityDigest, err := digestSanitized("policy-identity", struct {
				AccountID iamv1.AccountID   `json:"accountId"`
				ActorID   iamv1.PrincipalID `json:"actorId"`
				RequestID string            `json:"requestId"`
			}{account.ID, subject.Subject.Principal.ID, request.RequestID})
			if err != nil {
				return iamv1.PolicyDetail{}, err
			}
			id := iamv1.PolicyID("policy-" + identityDigest[len("sha256:"):])
			version := iamv1.PolicyVersion{PolicyID: id, ID: iamv1.PolicyVersionID("version-" + contentDigest[len("sha256:"):]),
				Document: request.Document, ContentDigest: contentDigest, ContractVersion: iamv1.PolicyVersionCompiledContract, Compilation: &compilation}
			policy := iamv1.Policy{APIVersion: iamv1.APIVersion, Kind: "Policy", ID: id,
				Management: iamv1.PolicyCustomerManaged, AccountID: account.ID, DisplayName: request.DisplayName,
				Scope: iamv1.AuthorityScopeTenant, Status: iamv1.PolicyActive, DefaultVersionID: version.ID,
				ResourceVersion: 1, CreatedAt: now, UpdatedAt: now}
			event, err := service.newManagementEvent(subject, auditv1.ActionIAMPolicyCreated, auditv1.TargetPolicy,
				string(id), decision.ID, requestDigest, request.RequestID, now)
			if err != nil {
				return iamv1.PolicyDetail{}, err
			}
			return tx.CreatePolicy(ctx, PolicyCreation{Policy: policy, Version: version,
				ActorPrincipalID: subject.Subject.Principal.ID, DecisionID: decision.ID, AuditEvent: event})
		})
}

func (service *Authority) ListPolicyVersions(ctx context.Context, credential iamv1.Secret, id iamv1.PolicyID, requestID string) (iamv1.PolicyVersionList, error) {
	if iamv1.ValidateID("policyId", string(id)) != nil || iamv1.ValidateID("requestId", requestID) != nil {
		return iamv1.PolicyVersionList{}, ErrInvalidArgument
	}
	return withAccountAuthorization(service, ctx, credential, iamv1.ActionIAMPolicyVersionList, iamv1.AuthorizationResourceInstance, "",
		iamv1.ResourceReference{Kind: iamv1.ResourcePolicy, ID: string(id)}, requestID,
		func(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, now time.Time) (iamv1.PolicyVersionList, error) {
			return tx.ListPolicyVersions(ctx, AccountRead{AccountID: subject.Subject.Organization.ID, ActorPrincipalID: subject.Subject.Principal.ID, DecisionID: decision.ID}, id)
		})
}

func (service *Authority) GetPolicyVersion(ctx context.Context, credential iamv1.Secret, id iamv1.PolicyID, version iamv1.PolicyVersionID, requestID string) (iamv1.PolicyVersionDetail, error) {
	if iamv1.ValidateID("policyId", string(id)) != nil || iamv1.ValidateID("versionId", string(version)) != nil || iamv1.ValidateID("requestId", requestID) != nil {
		return iamv1.PolicyVersionDetail{}, ErrInvalidArgument
	}
	return withAccountAuthorization(service, ctx, credential, iamv1.ActionIAMPolicyVersionRead, iamv1.AuthorizationResourceInstance, "",
		iamv1.ResourceReference{Kind: iamv1.ResourcePolicy, ID: string(id)}, requestID,
		func(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, now time.Time) (iamv1.PolicyVersionDetail, error) {
			return tx.ReadPolicyVersion(ctx, AccountRead{AccountID: subject.Subject.Organization.ID, ActorPrincipalID: subject.Subject.Principal.ID, DecisionID: decision.ID}, id, version)
		})
}

func requirePolicyPublisher(ctx context.Context, tx Transaction, subject SessionCredential) error {
	account, err := tx.ReadAccount(ctx, subject.Subject.Organization.ID, subject.Subject.Principal.ID)
	if err != nil {
		return err
	}
	if account.RootIdentity.PrincipalID != subject.Subject.Principal.ID {
		return ErrForbidden
	}
	return nil
}

func (service *Authority) CreatePolicyVersion(ctx context.Context, credential iamv1.Secret, id iamv1.PolicyID, request iamv1.CreatePolicyVersionRequest) (iamv1.PolicyVersionDetail, error) {
	if iamv1.ValidateID("policyId", string(id)) != nil || iamv1.ValidateCreatePolicyVersionRequest(request) != nil {
		return iamv1.PolicyVersionDetail{}, ErrInvalidArgument
	}
	return withAccountAuthorization(service, ctx, credential, iamv1.ActionIAMPolicyVersionCreate, iamv1.AuthorizationResourceInstance, "",
		iamv1.ResourceReference{Kind: iamv1.ResourcePolicy, ID: string(id)}, request.RequestID,
		func(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, now time.Time) (iamv1.PolicyVersionDetail, error) {
			if err := requirePolicyPublisher(ctx, tx, subject); err != nil {
				return iamv1.PolicyVersionDetail{}, err
			}
			if err := tx.CheckCurrentAuthorizationProfiles(ctx); err != nil {
				return iamv1.PolicyVersionDetail{}, err
			}
			compilation, err := iamv1.CompilePolicyDocument(request.Document, iamv1.AllAuthorizationProfiles())
			if err != nil {
				return iamv1.PolicyVersionDetail{}, ErrInvalidArgument
			}
			_, digest, err := iamv1.CanonicalizePolicyCompilation(request.Document, compilation, iamv1.AllAuthorizationProfiles())
			if err != nil {
				return iamv1.PolicyVersionDetail{}, ErrInvalidArgument
			}
			requestDigest, err := digestSanitized("policy-version-create", struct {
				PolicyID        iamv1.PolicyID `json:"policyId"`
				ContentDigest   string         `json:"contentDigest"`
				ResourceVersion uint64         `json:"resourceVersion"`
				RequestID       string         `json:"requestId"`
			}{id, digest, request.ResourceVersion, request.RequestID})
			if err != nil {
				return iamv1.PolicyVersionDetail{}, err
			}
			event, err := service.newManagementEvent(subject, auditv1.ActionIAMPolicyVersionCreated, auditv1.TargetPolicy, string(id), decision.ID, requestDigest, request.RequestID, now)
			if err != nil {
				return iamv1.PolicyVersionDetail{}, err
			}
			// A publication is distinct from its content. Re-publishing retired
			// content must not revive the old version identity.
			version := iamv1.PolicyVersion{PolicyID: id, ID: iamv1.PolicyVersionID("version-" + digest[len("sha256:"):] + "-" + strconv.FormatUint(request.ResourceVersion+1, 10)), Document: request.Document, ContentDigest: digest,
				ContractVersion: iamv1.PolicyVersionCompiledContract, Compilation: &compilation}
			return tx.CreatePolicyVersion(ctx, PolicyVersionCreation{AccountID: subject.Subject.Organization.ID, ActorPrincipalID: subject.Subject.Principal.ID,
				DecisionID: decision.ID, Version: version, ResourceVersion: request.ResourceVersion, AuditEvent: event})
		})
}

func (service *Authority) DeletePolicyVersion(ctx context.Context, credential iamv1.Secret, id iamv1.PolicyID, version iamv1.PolicyVersionID, request iamv1.DeletePolicyVersionRequest) (iamv1.PolicyDetail, error) {
	if iamv1.ValidateID("policyId", string(id)) != nil || iamv1.ValidateID("versionId", string(version)) != nil || iamv1.ValidateDeletePolicyVersionRequest(request) != nil {
		return iamv1.PolicyDetail{}, ErrInvalidArgument
	}
	requestDigest, err := digestSanitized("policy-version-delete", struct {
		PolicyID  iamv1.PolicyID                   `json:"policyId"`
		VersionID iamv1.PolicyVersionID            `json:"versionId"`
		Request   iamv1.DeletePolicyVersionRequest `json:"request"`
	}{id, version, request})
	if err != nil {
		return iamv1.PolicyDetail{}, err
	}
	return withAccountAuthorization(service, ctx, credential, iamv1.ActionIAMPolicyVersionDelete, iamv1.AuthorizationResourceInstance, "", iamv1.ResourceReference{Kind: iamv1.ResourcePolicy, ID: string(id)}, request.RequestID,
		func(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, now time.Time) (iamv1.PolicyDetail, error) {
			if err := requirePolicyPublisher(ctx, tx, subject); err != nil {
				return iamv1.PolicyDetail{}, err
			}
			event, err := service.newManagementEvent(subject, auditv1.ActionIAMPolicyVersionDeleted, auditv1.TargetPolicy, string(id), decision.ID, requestDigest, request.RequestID, now)
			if err != nil {
				return iamv1.PolicyDetail{}, err
			}
			return tx.DeletePolicyVersion(ctx, PolicyVersionDeletion{AccountID: subject.Subject.Organization.ID, ActorPrincipalID: subject.Subject.Principal.ID, DecisionID: decision.ID, PolicyID: id, VersionID: version, ResourceVersion: request.ResourceVersion, AuditEvent: event})
		})
}

func (service *Authority) SetDefaultPolicyVersion(ctx context.Context, credential iamv1.Secret, id iamv1.PolicyID, request iamv1.SetDefaultPolicyVersionRequest) (iamv1.PolicyDetail, error) {
	if iamv1.ValidateID("policyId", string(id)) != nil || iamv1.ValidateSetDefaultPolicyVersionRequest(request) != nil {
		return iamv1.PolicyDetail{}, ErrInvalidArgument
	}
	requestDigest, err := digestSanitized("policy-set-default-version", struct {
		PolicyID        iamv1.PolicyID        `json:"policyId"`
		VersionID       iamv1.PolicyVersionID `json:"versionId"`
		ResourceVersion uint64                `json:"resourceVersion"`
		RequestID       string                `json:"requestId"`
	}{id, request.VersionID, request.ResourceVersion, request.RequestID})
	if err != nil {
		return iamv1.PolicyDetail{}, err
	}
	return withAccountAuthorization(service, ctx, credential, iamv1.ActionIAMPolicySetDefaultVersion, iamv1.AuthorizationResourceInstance, "",
		iamv1.ResourceReference{Kind: iamv1.ResourcePolicy, ID: string(id)}, request.RequestID,
		func(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, now time.Time) (iamv1.PolicyDetail, error) {
			if err := requirePolicyPublisher(ctx, tx, subject); err != nil {
				return iamv1.PolicyDetail{}, err
			}
			event, err := service.newManagementEvent(subject, auditv1.ActionIAMPolicyDefaultVersionSet, auditv1.TargetPolicy, string(id), decision.ID, requestDigest, request.RequestID, now)
			if err != nil {
				return iamv1.PolicyDetail{}, err
			}
			return tx.SetDefaultPolicyVersion(ctx, PolicyDefaultSelection{AccountID: subject.Subject.Organization.ID, ActorPrincipalID: subject.Subject.Principal.ID,
				DecisionID: decision.ID, PolicyID: id, VersionID: request.VersionID, ResourceVersion: request.ResourceVersion, AuditEvent: event})
		})
}

func (service *Authority) UpdatePolicy(ctx context.Context, credential iamv1.Secret, id iamv1.PolicyID, request iamv1.UpdatePolicyRequest) (iamv1.PolicyDetail, error) {
	if iamv1.ValidateID("policyId", string(id)) != nil || iamv1.ValidateUpdatePolicyRequest(request) != nil {
		return iamv1.PolicyDetail{}, ErrInvalidArgument
	}
	requestDigest, err := digestSanitized("policy-update", struct {
		PolicyID iamv1.PolicyID            `json:"policyId"`
		Request  iamv1.UpdatePolicyRequest `json:"request"`
	}{id, request})
	if err != nil {
		return iamv1.PolicyDetail{}, err
	}
	return withAccountAuthorization(service, ctx, credential, iamv1.ActionIAMPolicyUpdate, iamv1.AuthorizationResourceInstance, "",
		iamv1.ResourceReference{Kind: iamv1.ResourcePolicy, ID: string(id)}, request.RequestID,
		func(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, now time.Time) (iamv1.PolicyDetail, error) {
			if err := requirePolicyPublisher(ctx, tx, subject); err != nil {
				return iamv1.PolicyDetail{}, err
			}
			event, err := service.newManagementEvent(subject, auditv1.ActionIAMPolicyUpdated, auditv1.TargetPolicy, string(id), decision.ID, requestDigest, request.RequestID, now)
			if err != nil {
				return iamv1.PolicyDetail{}, err
			}
			return tx.UpdatePolicy(ctx, PolicyUpdate{AccountID: subject.Subject.Organization.ID, ActorPrincipalID: subject.Subject.Principal.ID,
				DecisionID: decision.ID, PolicyID: id, DisplayName: request.DisplayName, ResourceVersion: request.ResourceVersion, AuditEvent: event})
		})
}

func (service *Authority) DeletePolicy(ctx context.Context, credential iamv1.Secret, id iamv1.PolicyID, request iamv1.DeletePolicyRequest) (iamv1.Policy, error) {
	if iamv1.ValidateID("policyId", string(id)) != nil || iamv1.ValidateDeletePolicyRequest(request) != nil {
		return iamv1.Policy{}, ErrInvalidArgument
	}
	requestDigest, err := digestSanitized("policy-delete", struct {
		PolicyID iamv1.PolicyID            `json:"policyId"`
		Request  iamv1.DeletePolicyRequest `json:"request"`
	}{id, request})
	if err != nil {
		return iamv1.Policy{}, err
	}
	return withAccountAuthorization(service, ctx, credential, iamv1.ActionIAMPolicyDelete, iamv1.AuthorizationResourceInstance, "", iamv1.ResourceReference{Kind: iamv1.ResourcePolicy, ID: string(id)}, request.RequestID,
		func(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, now time.Time) (iamv1.Policy, error) {
			if err := requirePolicyPublisher(ctx, tx, subject); err != nil {
				return iamv1.Policy{}, err
			}
			event, err := service.newManagementEvent(subject, auditv1.ActionIAMPolicyDeleted, auditv1.TargetPolicy, string(id), decision.ID, requestDigest, request.RequestID, now)
			if err != nil {
				return iamv1.Policy{}, err
			}
			return tx.DeletePolicy(ctx, PolicyDeletion{AccountID: subject.Subject.Organization.ID, ActorPrincipalID: subject.Subject.Principal.ID, DecisionID: decision.ID, PolicyID: id, ResourceVersion: request.ResourceVersion, AuditEvent: event})
		})
}

func (service *Authority) ListAccounts(ctx context.Context, credential iamv1.Secret, after, requestID string) (iamv1.AccountList, error) {
	if iamv1.ValidateID("requestId", requestID) != nil || (after != "" && iamv1.ValidatePageCursor(after) != nil) {
		return iamv1.AccountList{}, ErrInvalidArgument
	}
	return withAccountAuthorization(service, ctx, credential, iamv1.ActionIAMAccountRead, iamv1.AuthorizationResourceCollection, iamv1.AuthorizationCollectionList,
		iamv1.ResourceReference{Kind: iamv1.ResourceAccount, ID: "collection"}, requestID,
		func(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, now time.Time) (iamv1.AccountList, error) {
			position, query, err := service.directoryPosition(ctx, tx, subject, decision, after, now)
			if err != nil {
				return iamv1.AccountList{}, err
			}
			page, err := tx.ListAccounts(ctx, AccountRead{AccountID: subject.Subject.Organization.ID, ActorPrincipalID: subject.Subject.Principal.ID, DecisionID: decision.ID, After: position})
			if err != nil {
				return iamv1.AccountList{}, err
			}
			result := iamv1.AccountList{APIVersion: iamv1.APIVersion, Kind: "AccountList", NextAfter: page.NextAfter,
				Items: make([]iamv1.AccountAccess, 0, len(page.Items))}
			for _, item := range page.Items {
				access, err := accountAccess(subject, item, now)
				if err != nil {
					return iamv1.AccountList{}, err
				}
				result.Items = append(result.Items, access)
			}
			result.NextAfter, err = service.sealDirectoryPage(subject, query, result.NextAfter, now)
			if err != nil || iamv1.ValidateAccountList(result) != nil {
				return iamv1.AccountList{}, ErrUnavailable
			}
			return result, nil
		})
}

func (service *Authority) GetAccount(ctx context.Context, credential iamv1.Secret, id iamv1.AccountID, requestID string) (iamv1.AccountAccess, error) {
	if iamv1.ValidateID("accountId", string(id)) != nil || iamv1.ValidateID("requestId", requestID) != nil {
		return iamv1.AccountAccess{}, ErrInvalidArgument
	}
	return withAccountAuthorization(service, ctx, credential, iamv1.ActionIAMAccountRead, iamv1.AuthorizationResourceInstance, "",
		iamv1.ResourceReference{Kind: iamv1.ResourceAccount, ID: string(id)}, requestID,
		func(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, now time.Time) (iamv1.AccountAccess, error) {
			account, err := tx.ReadAccountAsPlatform(ctx, AccountRead{AccountID: subject.Subject.Organization.ID, ActorPrincipalID: subject.Subject.Principal.ID, DecisionID: decision.ID}, id)
			if err != nil {
				return iamv1.AccountAccess{}, err
			}
			return accountAccess(subject, account, now)
		})
}

func accountAccess(subject SessionCredential, target AccountManagementSnapshot, now time.Time) (iamv1.AccountAccess, error) {
	resource := iamv1.ResourceReference{Kind: iamv1.ResourceAccount, ID: string(target.Account.ID)}
	status, err := projectCapability(subject, iamv1.ActionIAMAccountSetStatus, resource, iamv1.AuthorizationResourceInstance, "", now)
	if err != nil {
		return iamv1.AccountAccess{}, err
	}
	if target.SystemAccount {
		restrictCapability(&status, iamv1.CapabilitySystemAccountProtected)
	}
	recovery, err := projectCapability(subject, iamv1.ActionIAMAccountRootCredentialsRecover, resource, iamv1.AuthorizationResourceInstance, "", now)
	if err != nil {
		return iamv1.AccountAccess{}, err
	}
	if target.RootHasInstallationAuthority {
		restrictCapability(&recovery, iamv1.CapabilityInstallationAuthorityProtected)
	}
	result := iamv1.AccountAccess{Account: target.Account, Capabilities: []iamv1.ActionCapability{status, recovery}}
	if iamv1.ValidateAccountAccess(result) != nil {
		return iamv1.AccountAccess{}, ErrUnavailable
	}
	return result, nil
}

func (service *Authority) CreateAccount(ctx context.Context, credential iamv1.Secret, request iamv1.CreateAccountRequest) (iamv1.Account, error) {
	if iamv1.ValidateCreateAccountRequest(request) != nil || authority.ValidatePassword(request.InitialPassword) != nil {
		return iamv1.Account{}, ErrInvalidArgument
	}
	digest, err := digestSanitized("account-create", struct {
		ID                                          iamv1.AccountID
		DisplayName, LoginName, RootName, RequestID string
	}{
		request.ID, request.DisplayName, request.RootLoginName, request.RootDisplayName, request.RequestID})
	if err != nil {
		return iamv1.Account{}, err
	}
	return withAccountAuthorization(service, ctx, credential, iamv1.ActionIAMAccountCreate, iamv1.AuthorizationResourceCollection, iamv1.AuthorizationCollectionCreate,
		iamv1.ResourceReference{Kind: iamv1.ResourceAccount, ID: "collection"}, request.RequestID,
		func(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, now time.Time) (iamv1.Account, error) {
			hash, err := service.passwords.Hash(request.InitialPassword)
			if err != nil {
				return iamv1.Account{}, ErrUnavailable
			}
			id, err := service.config.NewID("principal")
			if err != nil {
				return iamv1.Account{}, ErrUnavailable
			}
			event, err := service.newTenantLifecycleEvent(subject, decision, auditv1.ActionIAMAccountCreated,
				auditv1.TargetReference{Kind: auditv1.TargetAccount, ID: string(request.ID)}, digest, request.RequestID, now)
			if err != nil {
				return iamv1.Account{}, err
			}
			return tx.CreateAccount(ctx, AccountMutation{ActorAccountID: subject.Subject.Organization.ID, ActorPrincipalID: subject.Subject.Principal.ID,
				DecisionID: decision.ID, Account: iamv1.InitialOrganization{ID: request.ID, DisplayName: request.DisplayName},
				Root: BootstrapAdministrator{ID: iamv1.PrincipalID(id), LoginName: request.RootLoginName, DisplayName: request.RootDisplayName, PasswordHash: hash}, AuditEvent: event})
		})
}

func (service *Authority) SetAccountStatus(ctx context.Context, credential iamv1.Secret, id iamv1.AccountID, request iamv1.SetAccountStatusRequest) (iamv1.Account, error) {
	if iamv1.ValidateID("accountId", string(id)) != nil || iamv1.ValidateSetAccountStatusRequest(request) != nil {
		return iamv1.Account{}, ErrInvalidArgument
	}
	digest, err := digestSanitized("account-status", struct {
		ID      iamv1.AccountID
		Request iamv1.SetAccountStatusRequest
	}{id, request})
	if err != nil {
		return iamv1.Account{}, err
	}
	return withAccountAuthorization(service, ctx, credential, iamv1.ActionIAMAccountSetStatus, iamv1.AuthorizationResourceInstance, "",
		iamv1.ResourceReference{Kind: iamv1.ResourceAccount, ID: string(id)}, request.RequestID,
		func(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, now time.Time) (iamv1.Account, error) {
			action := auditv1.ActionIAMAccountDisabled
			if request.Status == iamv1.AccountActive {
				action = auditv1.ActionIAMAccountEnabled
			}
			event, err := service.newTenantLifecycleEvent(subject, decision, action,
				auditv1.TargetReference{Kind: auditv1.TargetAccount, ID: string(id)}, digest, request.RequestID, now)
			if err != nil {
				return iamv1.Account{}, err
			}
			return tx.SetAccountStatus(ctx, AccountStatusMutation{
				ActorAccountID: subject.Subject.Organization.ID, ActorPrincipalID: subject.Subject.Principal.ID,
				DecisionID: decision.ID, AccountID: id, Status: request.Status, ResourceVersion: request.ResourceVersion, AuditEvent: event,
			})
		})
}

func (service *Authority) RecoverRootCredentials(ctx context.Context, credential iamv1.Secret, id iamv1.AccountID, request iamv1.RecoverRootCredentialsRequest) (iamv1.Account, error) {
	if iamv1.ValidateID("accountId", string(id)) != nil || iamv1.ValidateRecoverRootCredentialsRequest(request) != nil || authority.ValidatePassword(request.InitialPassword) != nil {
		return iamv1.Account{}, ErrInvalidArgument
	}
	digest, err := digestSanitized("account-root-credentials-recover", struct {
		AccountID       iamv1.AccountID
		ResourceVersion uint64
		RequestID       string
	}{id, request.ResourceVersion, request.RequestID})
	if err != nil {
		return iamv1.Account{}, err
	}
	return withAccountAuthorization(service, ctx, credential, iamv1.ActionIAMAccountRootCredentialsRecover, iamv1.AuthorizationResourceInstance, "",
		iamv1.ResourceReference{Kind: iamv1.ResourceAccount, ID: string(id)}, request.RequestID,
		func(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, now time.Time) (iamv1.Account, error) {
			root, err := tx.ReadAccountRoot(ctx, AccountRead{AccountID: subject.Subject.Organization.ID,
				ActorPrincipalID: subject.Subject.Principal.ID, DecisionID: decision.ID}, id)
			if err != nil {
				return iamv1.Account{}, err
			}
			hash, err := service.passwords.Hash(request.InitialPassword)
			if err != nil {
				return iamv1.Account{}, ErrUnavailable
			}
			attachmentID, err := service.config.NewID("attachment")
			if err != nil {
				return iamv1.Account{}, ErrUnavailable
			}
			event, err := service.newTenantLifecycleEvent(subject, decision, auditv1.ActionIAMAccountRootCredentialsRecovered,
				auditv1.TargetReference{Kind: auditv1.TargetUser, ID: string(root.PrincipalID), TenantID: auditv1.TenantID(id)}, digest, request.RequestID, now)
			if err != nil {
				return iamv1.Account{}, err
			}
			return tx.RecoverRootCredentials(ctx, RootCredentialRecovery{
				ActorAccountID: subject.Subject.Organization.ID, ActorPrincipalID: subject.Subject.Principal.ID,
				DecisionID: decision.ID, AccountID: id, PrincipalID: root.PrincipalID,
				ResourceVersion: request.ResourceVersion, PasswordHash: hash, AttachmentID: iamv1.PolicyAttachmentID(attachmentID), AuditEvent: event,
			})
		})
}

func (service *Authority) newTenantLifecycleEvent(subject SessionCredential, decision iamv1.AuthorizationDecision, action auditv1.Action,
	target auditv1.TargetReference, digest, requestID string, now time.Time) (auditv1.Event, error) {
	if !decision.Allowed || decision.InstallationID == "" || decision.InstallationID != subject.Subject.InstallationID {
		return auditv1.Event{}, ErrUnavailable
	}
	eventID, err := service.config.NewID("event")
	if err != nil {
		return auditv1.Event{}, ErrUnavailable
	}
	return newAuditEvent(eventID, "", decision.InstallationID,
		auditv1.ActorReference{Type: auditv1.ActorUser, ID: auditv1.ActorID(subject.Subject.Principal.ID)},
		action, target, auditv1.ResultSucceeded, decision.ID, digest, requestID, requestID, now)
}

func (service *Authority) SetAccountAlias(ctx context.Context, credential iamv1.Secret, request iamv1.SetAccountAliasRequest) (iamv1.Account, error) {
	if iamv1.ValidateSetAccountAliasRequest(request) != nil {
		return iamv1.Account{}, ErrInvalidArgument
	}
	digest, err := digestSanitized("account-alias-set", request)
	if err != nil {
		return iamv1.Account{}, err
	}
	return withAccountAuthorization(service, ctx, credential, iamv1.ActionIAMAccountAliasSet, iamv1.AuthorizationResourceInstance, "",
		iamv1.ResourceReference{Kind: iamv1.ResourceAccount}, request.RequestID,
		func(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, now time.Time) (iamv1.Account, error) {
			event, err := service.newManagementEvent(subject, auditv1.ActionIAMAccountAliasUpdated, auditv1.TargetAccount, string(subject.Subject.Organization.ID), decision.ID, digest, request.RequestID, now)
			if err != nil {
				return iamv1.Account{}, err
			}
			return tx.SetAccountAlias(ctx, AccountAliasMutation{AccountID: subject.Subject.Organization.ID, ActorPrincipalID: subject.Subject.Principal.ID,
				DecisionID: decision.ID, Alias: request.Alias, ResourceVersion: request.ResourceVersion, AuditEvent: event})
		})
}

func (service *Authority) SetUserStatus(ctx context.Context, credential iamv1.Secret, id iamv1.PrincipalID, request iamv1.SetUserStatusRequest) (iamv1.User, error) {
	if iamv1.ValidateID("userId", string(id)) != nil || iamv1.ValidateSetUserStatusRequest(request) != nil {
		return iamv1.User{}, ErrInvalidArgument
	}
	digest, err := digestSanitized("principal-status", struct {
		ID      iamv1.PrincipalID
		Request iamv1.SetUserStatusRequest
	}{id, request})
	if err != nil {
		return iamv1.User{}, err
	}
	return service.changeUser(ctx, credential, id, request.ResourceVersion, &request.Status, iamv1.Secret{}, iamv1.ActionIAMUserSetStatus, auditv1.ActionIAMUserStatusSet, digest, request.RequestID)
}

func (service *Authority) UpdateUser(ctx context.Context, credential iamv1.Secret, id iamv1.PrincipalID, request iamv1.UpdateUserRequest) (iamv1.User, error) {
	if iamv1.ValidateID("userId", string(id)) != nil || iamv1.ValidateUpdateUserRequest(request) != nil {
		return iamv1.User{}, ErrInvalidArgument
	}
	digest, err := digestSanitized("user-profile-update", struct {
		ID      iamv1.PrincipalID
		Request iamv1.UpdateUserRequest
	}{id, request})
	if err != nil {
		return iamv1.User{}, err
	}
	return withAccountAuthorization(service, ctx, credential, iamv1.ActionIAMUserUpdate, iamv1.AuthorizationResourceInstance, "",
		iamv1.ResourceReference{Kind: iamv1.ResourceUser, ID: string(id)}, request.RequestID,
		func(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, now time.Time) (iamv1.User, error) {
			event, err := service.newManagementEvent(subject, auditv1.ActionIAMUserUpdated, auditv1.TargetUser,
				string(id), decision.ID, digest, request.RequestID, now)
			if err != nil {
				return iamv1.User{}, err
			}
			return tx.UpdateUser(ctx, UserProfileMutation{AccountID: subject.Subject.Organization.ID,
				ActorPrincipalID: subject.Subject.Principal.ID, PrincipalID: id, DecisionID: decision.ID,
				DisplayName: request.DisplayName, ResourceVersion: request.ResourceVersion, AuditEvent: event})
		})
}

func (service *Authority) DeleteUser(ctx context.Context, credential iamv1.Secret, id iamv1.PrincipalID, request iamv1.DeleteUserRequest) (iamv1.UserDeletion, error) {
	if iamv1.ValidateID("userId", string(id)) != nil || iamv1.ValidateDeleteUserRequest(request) != nil {
		return iamv1.UserDeletion{}, ErrInvalidArgument
	}
	digest, err := digestSanitized("user-delete", struct {
		ID      iamv1.PrincipalID
		Request iamv1.DeleteUserRequest
	}{id, request})
	if err != nil {
		return iamv1.UserDeletion{}, err
	}
	return withAccountAuthorization(service, ctx, credential, iamv1.ActionIAMUserDelete, iamv1.AuthorizationResourceInstance, "",
		iamv1.ResourceReference{Kind: iamv1.ResourceUser, ID: string(id)}, request.RequestID,
		func(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, now time.Time) (iamv1.UserDeletion, error) {
			event, err := service.newManagementEvent(subject, auditv1.ActionIAMUserDeleted, auditv1.TargetUser,
				string(id), decision.ID, digest, request.RequestID, now)
			if err != nil {
				return iamv1.UserDeletion{}, err
			}
			return tx.DeleteUser(ctx, UserDeletionMutation{AccountID: subject.Subject.Organization.ID,
				ActorPrincipalID: subject.Subject.Principal.ID, PrincipalID: id, DecisionID: decision.ID,
				ResourceVersion: request.ResourceVersion, AuditEvent: event})
		})
}

func (service *Authority) ResetUserPassword(ctx context.Context, credential iamv1.Secret, id iamv1.PrincipalID, request iamv1.ResetUserPasswordRequest) (iamv1.User, error) {
	if iamv1.ValidateID("userId", string(id)) != nil || iamv1.ValidateResetUserPasswordRequest(request) != nil || authority.ValidatePassword(request.InitialPassword) != nil {
		return iamv1.User{}, ErrInvalidArgument
	}
	digest, err := digestSanitized("principal-password-reset", struct {
		ID              iamv1.PrincipalID
		ResourceVersion uint64
		RequestID       string
	}{id, request.ResourceVersion, request.RequestID})
	if err != nil {
		return iamv1.User{}, err
	}
	return service.changeUser(ctx, credential, id, request.ResourceVersion, nil, request.InitialPassword, iamv1.ActionIAMUserPasswordReset, auditv1.ActionIAMUserPasswordReset, digest, request.RequestID)
}

func (service *Authority) changeUser(ctx context.Context, credential iamv1.Secret, id iamv1.PrincipalID, version uint64, status *iamv1.PrincipalStatus,
	password iamv1.Secret, action iamv1.Action, auditAction auditv1.Action, digest, requestID string) (iamv1.User, error) {
	return withAccountAuthorization(service, ctx, credential, action, iamv1.AuthorizationResourceInstance, "", iamv1.ResourceReference{Kind: iamv1.ResourceUser, ID: string(id)}, requestID,
		func(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, now time.Time) (iamv1.User, error) {
			event, err := service.newManagementEvent(subject, auditAction, auditv1.TargetUser, string(id), decision.ID, digest, requestID, now)
			if err != nil {
				return iamv1.User{}, err
			}
			mutation := UserChange{AccountID: subject.Subject.Organization.ID, ActorPrincipalID: subject.Subject.Principal.ID, PrincipalID: id,
				DecisionID: decision.ID, ResourceVersion: version, Status: status, AuditEvent: event}
			if password.Present() {
				hash, err := service.passwords.Hash(password)
				if err != nil {
					return iamv1.User{}, ErrUnavailable
				}
				mutation.PasswordHash = &hash
			}
			return tx.ChangeUser(ctx, mutation)
		})
}

func userFromPrincipal(value iamv1.Principal) (iamv1.User, error) {
	if iamv1.ValidatePrincipal(value) != nil || value.Type != iamv1.PrincipalUser {
		return iamv1.User{}, ErrUnavailable
	}
	result := iamv1.User{APIVersion: iamv1.APIVersion, Kind: "User", ID: value.ID, AccountID: value.AccountID,
		LoginName: value.LoginName, DisplayName: value.DisplayName, Status: value.Status,
		MustChangePassword: value.MustChangePassword, ResourceVersion: value.ResourceVersion,
		CreatedAt: value.CreatedAt, UpdatedAt: value.UpdatedAt}
	if iamv1.ValidateUser(result) != nil {
		return iamv1.User{}, ErrUnavailable
	}
	return result, nil
}
