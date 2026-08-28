package identityaccess

import (
	"context"
	"slices"
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
		result = iamv1.CurrentIdentity{APIVersion: iamv1.APIVersion, Kind: "CurrentIdentity", Account: account,
			Principal: subject.Principal, Roles: append([]iamv1.BuiltinRole{}, subject.Roles...),
			CanCreateOrganizations: subject.InstallationID != "" && !subject.Principal.MustChangePassword && slices.Contains(subject.Roles, iamv1.RolePlatformOperator)}
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

func (service *Authority) ListPrincipals(ctx context.Context, credential iamv1.Secret, after, requestID string) (iamv1.PrincipalList, error) {
	if iamv1.ValidateID("requestId", requestID) != nil || (after != "" && iamv1.ValidateID("after", after) != nil) {
		return iamv1.PrincipalList{}, ErrInvalidArgument
	}
	return withAccountAuthorization(service, ctx, credential, iamv1.ActionIAMPrincipalList,
		iamv1.ResourceReference{Kind: iamv1.ResourceOrganization}, requestID,
		func(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, _ time.Time) (iamv1.PrincipalList, error) {
			return tx.ListPrincipals(ctx, AccountRead{OrganizationID: subject.Subject.Organization.ID, ActorPrincipalID: subject.Subject.Principal.ID, DecisionID: decision.ID, After: after})
		})
}

func (service *Authority) ListAccounts(ctx context.Context, credential iamv1.Secret, after, requestID string) (iamv1.OrganizationAccountList, error) {
	if iamv1.ValidateID("requestId", requestID) != nil || (after != "" && iamv1.ValidateID("after", after) != nil) {
		return iamv1.OrganizationAccountList{}, ErrInvalidArgument
	}
	return withAccountAuthorization(service, ctx, credential, iamv1.ActionIAMOrganizationRead,
		iamv1.ResourceReference{Kind: iamv1.ResourceOrganization, ID: "organizations"}, requestID,
		func(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, _ time.Time) (iamv1.OrganizationAccountList, error) {
			return tx.ListAccounts(ctx, AccountRead{OrganizationID: subject.Subject.Organization.ID, ActorPrincipalID: subject.Subject.Principal.ID, DecisionID: decision.ID, After: after})
		})
}

func (service *Authority) ReadOrganization(ctx context.Context, credential iamv1.Secret, id iamv1.OrganizationID, requestID string) (iamv1.OrganizationAccount, error) {
	if iamv1.ValidateID("organizationId", string(id)) != nil || iamv1.ValidateID("requestId", requestID) != nil {
		return iamv1.OrganizationAccount{}, ErrInvalidArgument
	}
	return withAccountAuthorization(service, ctx, credential, iamv1.ActionIAMOrganizationRead,
		iamv1.ResourceReference{Kind: iamv1.ResourceOrganization, ID: string(id)}, requestID,
		func(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, _ time.Time) (iamv1.OrganizationAccount, error) {
			return tx.ReadOrganization(ctx, AccountRead{OrganizationID: subject.Subject.Organization.ID, ActorPrincipalID: subject.Subject.Principal.ID, DecisionID: decision.ID}, id)
		})
}

func (service *Authority) CreateOrganization(ctx context.Context, credential iamv1.Secret, request iamv1.CreateOrganizationRequest) (iamv1.OrganizationAccount, error) {
	if iamv1.ValidateCreateOrganizationRequest(request) != nil || authority.ValidatePassword(request.InitialPassword) != nil {
		return iamv1.OrganizationAccount{}, ErrInvalidArgument
	}
	digest, err := digestSanitized("organization-create", struct {
		ID                                                   iamv1.OrganizationID
		DisplayName, LoginName, AdministratorName, RequestID string
	}{
		request.ID, request.DisplayName, request.AdministratorLoginName, request.AdministratorDisplayName, request.RequestID})
	if err != nil {
		return iamv1.OrganizationAccount{}, err
	}
	return withAccountAuthorization(service, ctx, credential, iamv1.ActionIAMOrganizationCreate,
		iamv1.ResourceReference{Kind: iamv1.ResourceOrganization, ID: string(request.ID)}, request.RequestID,
		func(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, now time.Time) (iamv1.OrganizationAccount, error) {
			hash, err := service.passwords.Hash(request.InitialPassword)
			if err != nil {
				return iamv1.OrganizationAccount{}, ErrUnavailable
			}
			id, err := service.config.NewID("principal")
			if err != nil {
				return iamv1.OrganizationAccount{}, ErrUnavailable
			}
			event, err := service.newTenantLifecycleEvent(subject, decision, auditv1.ActionIAMTenantCreated,
				auditv1.TargetReference{Kind: auditv1.TargetOrganization, ID: string(request.ID)}, digest, request.RequestID, now)
			if err != nil {
				return iamv1.OrganizationAccount{}, err
			}
			return tx.CreateOrganization(ctx, OrganizationMutation{ActorOrganizationID: subject.Subject.Organization.ID, ActorPrincipalID: subject.Subject.Principal.ID,
				DecisionID: decision.ID, Organization: iamv1.InitialOrganization{ID: request.ID, DisplayName: request.DisplayName},
				Administrator: BootstrapAdministrator{ID: iamv1.PrincipalID(id), LoginName: request.AdministratorLoginName, DisplayName: request.AdministratorDisplayName, PasswordHash: hash}, AuditEvent: event})
		})
}

func (service *Authority) SetOrganizationStatus(ctx context.Context, credential iamv1.Secret, id iamv1.OrganizationID, request iamv1.SetOrganizationStatusRequest) (iamv1.OrganizationAccount, error) {
	if iamv1.ValidateID("organizationId", string(id)) != nil || iamv1.ValidateSetOrganizationStatusRequest(request) != nil {
		return iamv1.OrganizationAccount{}, ErrInvalidArgument
	}
	digest, err := digestSanitized("organization-status", struct {
		ID      iamv1.OrganizationID
		Request iamv1.SetOrganizationStatusRequest
	}{id, request})
	if err != nil {
		return iamv1.OrganizationAccount{}, err
	}
	return withAccountAuthorization(service, ctx, credential, iamv1.ActionIAMOrganizationSetStatus,
		iamv1.ResourceReference{Kind: iamv1.ResourceOrganization, ID: string(id)}, request.RequestID,
		func(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, now time.Time) (iamv1.OrganizationAccount, error) {
			action := auditv1.ActionIAMTenantDisabled
			if request.Status == iamv1.OrganizationActive {
				action = auditv1.ActionIAMTenantEnabled
			}
			event, err := service.newTenantLifecycleEvent(subject, decision, action,
				auditv1.TargetReference{Kind: auditv1.TargetOrganization, ID: string(id)}, digest, request.RequestID, now)
			if err != nil {
				return iamv1.OrganizationAccount{}, err
			}
			return tx.SetOrganizationStatus(ctx, OrganizationStatusMutation{
				ActorOrganizationID: subject.Subject.Organization.ID, ActorPrincipalID: subject.Subject.Principal.ID,
				DecisionID: decision.ID, OrganizationID: id, Status: request.Status, ResourceVersion: request.ResourceVersion, AuditEvent: event,
			})
		})
}

func (service *Authority) RecoverOrganizationAdministrator(ctx context.Context, credential iamv1.Secret, id iamv1.OrganizationID, request iamv1.RecoverOrganizationAdministratorRequest) (iamv1.OrganizationAccount, error) {
	if iamv1.ValidateID("organizationId", string(id)) != nil || iamv1.ValidateRecoverOrganizationAdministratorRequest(request) != nil || authority.ValidatePassword(request.InitialPassword) != nil {
		return iamv1.OrganizationAccount{}, ErrInvalidArgument
	}
	digest, err := digestSanitized("organization-administrator-recover", struct {
		OrganizationID  iamv1.OrganizationID
		PrincipalID     iamv1.PrincipalID
		ResourceVersion uint64
		RequestID       string
	}{id, request.PrincipalID, request.ResourceVersion, request.RequestID})
	if err != nil {
		return iamv1.OrganizationAccount{}, err
	}
	return withAccountAuthorization(service, ctx, credential, iamv1.ActionIAMOrganizationAdministratorRecover,
		iamv1.ResourceReference{Kind: iamv1.ResourcePrincipal, ID: string(request.PrincipalID)}, request.RequestID,
		func(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, now time.Time) (iamv1.OrganizationAccount, error) {
			hash, err := service.passwords.Hash(request.InitialPassword)
			if err != nil {
				return iamv1.OrganizationAccount{}, ErrUnavailable
			}
			bindingID, err := service.config.NewID("binding")
			if err != nil {
				return iamv1.OrganizationAccount{}, ErrUnavailable
			}
			event, err := service.newTenantLifecycleEvent(subject, decision, auditv1.ActionIAMTenantAdministratorRecovered,
				auditv1.TargetReference{Kind: auditv1.TargetPrincipal, ID: string(request.PrincipalID), TenantID: auditv1.TenantID(id)}, digest, request.RequestID, now)
			if err != nil {
				return iamv1.OrganizationAccount{}, err
			}
			return tx.RecoverOrganizationAdministrator(ctx, OrganizationAdministratorRecovery{
				ActorOrganizationID: subject.Subject.Organization.ID, ActorPrincipalID: subject.Subject.Principal.ID,
				DecisionID: decision.ID, OrganizationID: id, PrincipalID: request.PrincipalID,
				ResourceVersion: request.ResourceVersion, PasswordHash: hash, BindingID: iamv1.RoleBindingID(bindingID), AuditEvent: event,
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

func (service *Authority) SetAccountAlias(ctx context.Context, credential iamv1.Secret, request iamv1.SetAccountAliasRequest) (iamv1.OrganizationAccount, error) {
	if iamv1.ValidateSetAccountAliasRequest(request) != nil {
		return iamv1.OrganizationAccount{}, ErrInvalidArgument
	}
	digest, err := digestSanitized("account-alias-set", request)
	if err != nil {
		return iamv1.OrganizationAccount{}, err
	}
	return withAccountAuthorization(service, ctx, credential, iamv1.ActionIAMAccountAliasSet,
		iamv1.ResourceReference{Kind: iamv1.ResourceOrganization}, request.RequestID,
		func(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, now time.Time) (iamv1.OrganizationAccount, error) {
			event, err := service.newManagementEvent(subject, auditv1.ActionIAMAccountAliasSet, auditv1.TargetOrganization, string(subject.Subject.Organization.ID), decision.ID, digest, request.RequestID, now)
			if err != nil {
				return iamv1.OrganizationAccount{}, err
			}
			return tx.SetAccountAlias(ctx, AccountAliasMutation{OrganizationID: subject.Subject.Organization.ID, ActorPrincipalID: subject.Subject.Principal.ID,
				DecisionID: decision.ID, Alias: request.Alias, ResourceVersion: request.ResourceVersion, AuditEvent: event})
		})
}

func (service *Authority) SetPrincipalStatus(ctx context.Context, credential iamv1.Secret, id iamv1.PrincipalID, request iamv1.SetPrincipalStatusRequest) (iamv1.Principal, error) {
	if iamv1.ValidateID("principalId", string(id)) != nil || iamv1.ValidateSetPrincipalStatusRequest(request) != nil {
		return iamv1.Principal{}, ErrInvalidArgument
	}
	digest, err := digestSanitized("principal-status", struct {
		ID      iamv1.PrincipalID
		Request iamv1.SetPrincipalStatusRequest
	}{id, request})
	if err != nil {
		return iamv1.Principal{}, err
	}
	return service.changeSubaccount(ctx, credential, id, request.ResourceVersion, &request.Status, iamv1.Secret{}, iamv1.ActionIAMPrincipalSetStatus, auditv1.ActionIAMPrincipalStatusSet, digest, request.RequestID)
}

func (service *Authority) ResetUserPassword(ctx context.Context, credential iamv1.Secret, id iamv1.PrincipalID, request iamv1.ResetUserPasswordRequest) (iamv1.Principal, error) {
	if iamv1.ValidateID("principalId", string(id)) != nil || iamv1.ValidateResetUserPasswordRequest(request) != nil || authority.ValidatePassword(request.InitialPassword) != nil {
		return iamv1.Principal{}, ErrInvalidArgument
	}
	digest, err := digestSanitized("principal-password-reset", struct {
		ID              iamv1.PrincipalID
		ResourceVersion uint64
		RequestID       string
	}{id, request.ResourceVersion, request.RequestID})
	if err != nil {
		return iamv1.Principal{}, err
	}
	return service.changeSubaccount(ctx, credential, id, request.ResourceVersion, nil, request.InitialPassword, iamv1.ActionIAMPasswordReset, auditv1.ActionIAMPasswordReset, digest, request.RequestID)
}

func (service *Authority) changeSubaccount(ctx context.Context, credential iamv1.Secret, id iamv1.PrincipalID, version uint64, status *iamv1.PrincipalStatus,
	password iamv1.Secret, action iamv1.Action, auditAction auditv1.Action, digest, requestID string) (iamv1.Principal, error) {
	return withAccountAuthorization(service, ctx, credential, action, iamv1.ResourceReference{Kind: iamv1.ResourcePrincipal, ID: string(id)}, requestID,
		func(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, now time.Time) (iamv1.Principal, error) {
			event, err := service.newManagementEvent(subject, auditAction, auditv1.TargetPrincipal, string(id), decision.ID, digest, requestID, now)
			if err != nil {
				return iamv1.Principal{}, err
			}
			mutation := SubaccountMutation{OrganizationID: subject.Subject.Organization.ID, ActorPrincipalID: subject.Subject.Principal.ID, PrincipalID: id,
				DecisionID: decision.ID, ResourceVersion: version, Status: status, AuditEvent: event}
			if password.Present() {
				hash, err := service.passwords.Hash(password)
				if err != nil {
					return iamv1.Principal{}, ErrUnavailable
				}
				mutation.PasswordHash = &hash
			}
			return tx.ChangeSubaccount(ctx, mutation)
		})
}

func (service *Authority) putInitialRole(ctx context.Context, tx Transaction, subject SessionCredential, principal iamv1.PrincipalID, role iamv1.BuiltinRole, requestID string, now time.Time) error {
	request := iamv1.PutRoleBindingRequest{PrincipalID: principal, Role: role, RequestID: requestID}
	decision, err := service.managementDecision(ctx, tx, subject, iamv1.ActionIAMRoleBindingPut, iamv1.ResourceReference{Kind: iamv1.ResourcePrincipal, ID: string(principal)}, requestID, now)
	if err != nil {
		return err
	}
	if !decision.Allowed {
		return ErrForbidden
	}
	id, err := service.config.NewID("binding")
	if err != nil {
		return ErrUnavailable
	}
	digest, err := digestSanitized("role-binding-put", request)
	if err != nil {
		return err
	}
	event, err := service.newManagementEvent(subject, auditv1.ActionIAMRoleBindingPut, auditv1.TargetRoleBinding, id, decision.ID, digest, requestID, now)
	if err != nil {
		return err
	}
	_, _, err = tx.PutRoleBinding(ctx, RoleBindingMutation{ActorPrincipalID: subject.Subject.Principal.ID, DecisionID: decision.ID, AuditEvent: event,
		Binding: iamv1.RoleBinding{APIVersion: iamv1.APIVersion, Kind: "RoleBinding", ID: iamv1.RoleBindingID(id), OrganizationID: subject.Subject.Organization.ID,
			PrincipalID: principal, Role: role, ResourceVersion: 1, CreatedAt: now, UpdatedAt: now}})
	return err
}
