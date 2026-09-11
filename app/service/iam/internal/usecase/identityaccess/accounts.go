package identityaccess

import (
	"context"
	"time"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/iam/internal/authority"
)

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
		subject := binding.Subject
		account, err := tx.ReadAccount(ctx, subject.Organization.ID, subject.Principal.ID)
		if err != nil {
			return err
		}
		// This conservative UI hint is evaluated at the exact directory target;
		// it is not a permit and the eventual command makes its own decision.
		hint, err := authority.Decide(subject, iamv1.ServiceIAM, iamv1.AuthorizationRequest{
			Action:    iamv1.ActionIAMAccountCreate,
			Resource:  iamv1.ResourceReference{Kind: iamv1.ResourceAccount, ID: "accounts"},
			RequestID: "current-identity-hint", CorrelationID: "current-identity-hint"}, "current-identity-hint", now)
		if err != nil {
			return ErrUnavailable
		}
		attachments := make([]iamv1.PolicyAttachment, 0, len(subject.Policies))
		for _, row := range subject.Policies {
			attachments = append(attachments, row.Attachment)
		}
		user, err := userFromPrincipal(subject.Principal)
		if err != nil {
			return err
		}
		identityKind := iamv1.IdentityUser
		if account.RootIdentity.PrincipalID == user.ID {
			identityKind = iamv1.IdentityRoot
		}
		result = iamv1.CurrentIdentity{APIVersion: iamv1.APIVersion, Kind: "CurrentIdentity", Account: account,
			User: user, IdentityKind: identityKind, PolicyAttachments: attachments, CanCreateAccounts: hint.Allowed}
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

// This boundary keeps authenticated tenant derivation, denied-decision Audit,
// and the admitted account workflow in the same serializable transaction.
func withAccountAuthorization[T any](service *Authority, ctx context.Context, credential iamv1.Secret,
	action iamv1.Action, target iamv1.ResourceReference, requestID string,
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
		decision, err := service.managementDecision(ctx, tx, subject, action, resource, requestID, now)
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

func (service *Authority) ListUsers(ctx context.Context, credential iamv1.Secret, after, requestID string) (iamv1.UserList, error) {
	if iamv1.ValidateID("requestId", requestID) != nil || (after != "" && iamv1.ValidateID("after", after) != nil) {
		return iamv1.UserList{}, ErrInvalidArgument
	}
	return withAccountAuthorization(service, ctx, credential, iamv1.ActionIAMUserList,
		iamv1.ResourceReference{Kind: iamv1.ResourceAccount}, requestID,
		func(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, _ time.Time) (iamv1.UserList, error) {
			return tx.ListUsers(ctx, AccountRead{AccountID: subject.Subject.Organization.ID, ActorPrincipalID: subject.Subject.Principal.ID, DecisionID: decision.ID, After: after})
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
		decision, err := service.managementDecision(ctx, tx, subject, action, target, requestID, now)
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

func (service *Authority) ListAccounts(ctx context.Context, credential iamv1.Secret, after, requestID string) (iamv1.AccountList, error) {
	if iamv1.ValidateID("requestId", requestID) != nil || (after != "" && iamv1.ValidateID("after", after) != nil) {
		return iamv1.AccountList{}, ErrInvalidArgument
	}
	return withAccountAuthorization(service, ctx, credential, iamv1.ActionIAMAccountRead,
		iamv1.ResourceReference{Kind: iamv1.ResourceAccount, ID: "accounts"}, requestID,
		func(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, _ time.Time) (iamv1.AccountList, error) {
			return tx.ListAccounts(ctx, AccountRead{AccountID: subject.Subject.Organization.ID, ActorPrincipalID: subject.Subject.Principal.ID, DecisionID: decision.ID, After: after})
		})
}

func (service *Authority) GetAccount(ctx context.Context, credential iamv1.Secret, id iamv1.AccountID, requestID string) (iamv1.Account, error) {
	if iamv1.ValidateID("accountId", string(id)) != nil || iamv1.ValidateID("requestId", requestID) != nil {
		return iamv1.Account{}, ErrInvalidArgument
	}
	return withAccountAuthorization(service, ctx, credential, iamv1.ActionIAMAccountRead,
		iamv1.ResourceReference{Kind: iamv1.ResourceAccount, ID: string(id)}, requestID,
		func(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, _ time.Time) (iamv1.Account, error) {
			return tx.ReadAccountAsPlatform(ctx, AccountRead{AccountID: subject.Subject.Organization.ID, ActorPrincipalID: subject.Subject.Principal.ID, DecisionID: decision.ID}, id)
		})
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
	return withAccountAuthorization(service, ctx, credential, iamv1.ActionIAMAccountCreate,
		iamv1.ResourceReference{Kind: iamv1.ResourceAccount, ID: string(request.ID)}, request.RequestID,
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
	return withAccountAuthorization(service, ctx, credential, iamv1.ActionIAMAccountSetStatus,
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
	return withAccountAuthorization(service, ctx, credential, iamv1.ActionIAMAccountRootCredentialsRecover,
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
	return withAccountAuthorization(service, ctx, credential, iamv1.ActionIAMAccountAliasSet,
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
	return withAccountAuthorization(service, ctx, credential, action, iamv1.ResourceReference{Kind: iamv1.ResourceUser, ID: string(id)}, requestID,
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
