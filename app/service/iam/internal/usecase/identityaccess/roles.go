package identityaccess

import (
	"context"
	"time"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
)

func roleRoot(ctx context.Context, tx Transaction, subject SessionCredential) (bool, error) {
	account, err := tx.ReadAccount(ctx, subject.Subject.Organization.ID, subject.Subject.Principal.ID)
	if err != nil {
		return false, err
	}
	if iamv1.ValidateAccount(account) != nil || account.ID != subject.Subject.Organization.ID {
		return false, ErrUnavailable
	}
	return account.RootIdentity.PrincipalID == subject.Subject.Principal.ID, nil
}

func roleCapabilities(subject SessionCredential, role iamv1.Role, attachments []iamv1.PolicyAttachment, root bool, now time.Time) ([]iamv1.ActionCapability, error) {
	result := make([]iamv1.ActionCapability, 0, 6+len(attachments))
	for _, action := range []iamv1.Action{iamv1.ActionIAMRoleRead, iamv1.ActionIAMRoleUpdate, iamv1.ActionIAMRoleSetStatus,
		iamv1.ActionIAMRoleDelete, iamv1.ActionIAMRoleTrustSet, iamv1.ActionIAMRolePolicyAttachmentCreate} {
		capability, err := projectCapability(subject, action, iamv1.ResourceReference{Kind: iamv1.ResourceRole, ID: string(role.ID)}, iamv1.AuthorizationResourceInstance, "", now)
		if err != nil {
			return nil, err
		}
		if action != iamv1.ActionIAMRoleRead && !root {
			restrictCapability(&capability, iamv1.CapabilityAuthorityRequired)
		}
		result = append(result, capability)
	}
	for _, attachment := range attachments {
		capability, err := projectCapability(subject, iamv1.ActionIAMRolePolicyAttachmentRevoke,
			iamv1.ResourceReference{Kind: iamv1.ResourcePolicyAttachment, ID: string(attachment.ID)}, iamv1.AuthorizationResourceInstance, "", now)
		if err != nil {
			return nil, err
		}
		if !root {
			restrictCapability(&capability, iamv1.CapabilityAuthorityRequired)
		}
		result = append(result, capability)
	}
	return result, nil
}

func (service *Authority) ListRoles(ctx context.Context, credential iamv1.Secret, after, requestID string) (iamv1.RoleList, error) {
	if iamv1.ValidateID("requestId", requestID) != nil || (after != "" && iamv1.ValidatePageCursor(after) != nil) {
		return iamv1.RoleList{}, ErrInvalidArgument
	}
	return withAccountAuthorization(service, ctx, credential, iamv1.ActionIAMRoleList, iamv1.AuthorizationResourceInstance, "",
		iamv1.ResourceReference{Kind: iamv1.ResourceAccount}, requestID,
		func(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, now time.Time) (iamv1.RoleList, error) {
			position, query, err := service.directoryPosition(ctx, tx, subject, decision, after, now)
			if err != nil {
				return iamv1.RoleList{}, err
			}
			root, err := roleRoot(ctx, tx, subject)
			if err != nil {
				return iamv1.RoleList{}, err
			}
			result, err := tx.ListRoles(ctx, AccountRead{AccountID: subject.Subject.Organization.ID, ActorPrincipalID: subject.Subject.Principal.ID, DecisionID: decision.ID, After: position})
			if err != nil {
				return iamv1.RoleList{}, err
			}
			for index := range result.Items {
				result.Items[index].Capabilities, err = roleCapabilities(subject, result.Items[index].Role, nil, root, now)
				if err != nil {
					return iamv1.RoleList{}, err
				}
			}
			result.NextAfter, err = service.sealDirectoryPage(subject, query, result.NextAfter, now)
			if err != nil || iamv1.ValidateRoleList(result) != nil {
				return iamv1.RoleList{}, ErrUnavailable
			}
			return result, nil
		})
}

func withRoleRead[T any](service *Authority, ctx context.Context, credential iamv1.Secret, id iamv1.RoleID, requestID string,
	read func(context.Context, Transaction, SessionCredential, iamv1.AuthorizationDecision, time.Time) (T, error)) (T, error) {
	if iamv1.ValidateID("roleId", string(id)) != nil || iamv1.ValidateID("requestId", requestID) != nil {
		var zero T
		return zero, ErrInvalidArgument
	}
	return withAccountAuthorization(service, ctx, credential, iamv1.ActionIAMRoleRead, iamv1.AuthorizationResourceInstance, "",
		iamv1.ResourceReference{Kind: iamv1.ResourceRole, ID: string(id)}, requestID, read)
}

func (service *Authority) GetRole(ctx context.Context, credential iamv1.Secret, id iamv1.RoleID, requestID string) (iamv1.RoleAccess, error) {
	return withRoleRead(service, ctx, credential, id, requestID,
		func(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, now time.Time) (iamv1.RoleAccess, error) {
			root, err := roleRoot(ctx, tx, subject)
			if err != nil {
				return iamv1.RoleAccess{}, err
			}
			result, err := tx.ReadRole(ctx, RoleRead{AccountRead: AccountRead{AccountID: subject.Subject.Organization.ID, ActorPrincipalID: subject.Subject.Principal.ID, DecisionID: decision.ID}, RoleID: id})
			if err != nil {
				return iamv1.RoleAccess{}, err
			}
			result.Capabilities, err = roleCapabilities(subject, result.Role, result.PolicyAttachments, root, now)
			if err != nil || iamv1.ValidateRoleAccess(result) != nil {
				return iamv1.RoleAccess{}, ErrUnavailable
			}
			return result, nil
		})
}

func roleTrustIdentity(subject SessionCredential, role iamv1.RoleID, requestID string) (iamv1.RoleTrustVersionID, error) {
	digest, err := digestSanitized("role-trust-identity", struct {
		AccountID iamv1.AccountID   `json:"accountId"`
		ActorID   iamv1.PrincipalID `json:"actorId"`
		RoleID    iamv1.RoleID      `json:"roleId"`
		RequestID string            `json:"requestId"`
	}{subject.Subject.Organization.ID, subject.Subject.Principal.ID, role, requestID})
	if err != nil {
		return "", err
	}
	return iamv1.RoleTrustVersionID("trust-" + digest[len("sha256:"):]), nil
}

func (service *Authority) CreateRole(ctx context.Context, credential iamv1.Secret, request iamv1.CreateRoleRequest) (iamv1.Role, error) {
	if iamv1.ValidateCreateRoleRequest(request) != nil {
		return iamv1.Role{}, ErrInvalidArgument
	}
	digest, err := digestSanitized("role-create", request)
	if err != nil {
		return iamv1.Role{}, err
	}
	return withAccountAuthorization(service, ctx, credential, iamv1.ActionIAMRoleCreate, iamv1.AuthorizationResourceInstance, "",
		iamv1.ResourceReference{Kind: iamv1.ResourceAccount}, request.RequestID,
		func(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, now time.Time) (iamv1.Role, error) {
			root, err := roleRoot(ctx, tx, subject)
			if err != nil {
				return iamv1.Role{}, err
			}
			if !root {
				return iamv1.Role{}, ErrForbidden
			}
			identityDigest, err := digestSanitized("role-identity", struct {
				AccountID iamv1.AccountID   `json:"accountId"`
				ActorID   iamv1.PrincipalID `json:"actorId"`
				RequestID string            `json:"requestId"`
			}{subject.Subject.Organization.ID, subject.Subject.Principal.ID, request.RequestID})
			if err != nil {
				return iamv1.Role{}, err
			}
			id := iamv1.RoleID("role-" + identityDigest[len("sha256:"):])
			trustID, err := roleTrustIdentity(subject, id, request.RequestID)
			if err != nil {
				return iamv1.Role{}, err
			}
			_, trustDigest, err := iamv1.CanonicalizeTrustPolicyDocument(request.TrustPolicy)
			if err != nil {
				return iamv1.Role{}, ErrInvalidArgument
			}
			duration := iamv1.DefaultRoleSessionDurationSeconds
			if request.MaxSessionDurationSeconds != nil {
				duration = *request.MaxSessionDurationSeconds
			}
			role := iamv1.Role{APIVersion: iamv1.APIVersion, Kind: "Role", ID: id, AccountID: subject.Subject.Organization.ID,
				Name: request.Name, Description: request.Description, Tags: request.Tags, Management: iamv1.RoleCustomerManaged,
				Status: iamv1.RoleActive, MaxSessionDurationSeconds: duration, ResourceVersion: 1, CurrentTrustVersionID: trustID, CreatedAt: now, UpdatedAt: now}
			trust := iamv1.RoleTrustVersion{APIVersion: iamv1.APIVersion, Kind: "RoleTrustVersion", ID: trustID, AccountID: role.AccountID,
				RoleID: id, Document: request.TrustPolicy, ContentDigest: trustDigest, CreatedAt: now}
			event, err := service.newManagementEvent(subject, auditv1.ActionIAMRoleCreated, auditv1.TargetRole, string(id), decision.ID, digest, request.RequestID, now)
			if err != nil {
				return iamv1.Role{}, err
			}
			return tx.CreateRole(ctx, RoleCreation{Role: role, TrustVersion: trust, ActorPrincipalID: subject.Subject.Principal.ID,
				ActorSessionID: subject.Subject.Session.ID, DecisionID: decision.ID, AuditEvent: event})
		})
}

// Every Role write passes the same current PDP plus original-root boundary.
// The adapter rechecks that writer's exact session under the database locks.
func withRoleMutation[T any](service *Authority, ctx context.Context, credential iamv1.Secret, id iamv1.RoleID, revision uint64,
	action iamv1.Action, fact auditv1.Action, requestID, digest string,
	apply func(context.Context, Transaction, SessionCredential, RoleMutation, time.Time) (T, error)) (T, error) {
	return withAccountAuthorization(service, ctx, credential, action, iamv1.AuthorizationResourceInstance, "",
		iamv1.ResourceReference{Kind: iamv1.ResourceRole, ID: string(id)}, requestID,
		func(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, now time.Time) (T, error) {
			var zero T
			root, err := roleRoot(ctx, tx, subject)
			if err != nil {
				return zero, err
			}
			if !root {
				return zero, ErrForbidden
			}
			event, err := service.newManagementEvent(subject, fact, auditv1.TargetRole, string(id), decision.ID, digest, requestID, now)
			if err != nil {
				return zero, err
			}
			return apply(ctx, tx, subject, RoleMutation{AccountID: subject.Subject.Organization.ID, RoleID: id,
				ActorPrincipalID: subject.Subject.Principal.ID, ActorSessionID: subject.Subject.Session.ID,
				DecisionID: decision.ID, ResourceVersion: revision, AuditEvent: event}, now)
		})
}

func (service *Authority) UpdateRole(ctx context.Context, credential iamv1.Secret, id iamv1.RoleID, request iamv1.UpdateRoleRequest) (iamv1.Role, error) {
	if iamv1.ValidateID("roleId", string(id)) != nil || iamv1.ValidateUpdateRoleRequest(request) != nil {
		return iamv1.Role{}, ErrInvalidArgument
	}
	digest, err := digestSanitized("role-update", struct {
		ID      iamv1.RoleID
		Request iamv1.UpdateRoleRequest
	}{id, request})
	if err != nil {
		return iamv1.Role{}, err
	}
	return withRoleMutation(service, ctx, credential, id, request.ResourceVersion, iamv1.ActionIAMRoleUpdate, auditv1.ActionIAMRoleUpdated, request.RequestID, digest,
		func(ctx context.Context, tx Transaction, _ SessionCredential, mutation RoleMutation, _ time.Time) (iamv1.Role, error) {
			return tx.UpdateRole(ctx, RoleProfileMutation{RoleMutation: mutation, Name: request.Name, Description: request.Description,
				Tags: request.Tags, MaxSessionDurationSeconds: request.MaxSessionDurationSeconds})
		})
}

func (service *Authority) SetRoleStatus(ctx context.Context, credential iamv1.Secret, id iamv1.RoleID, request iamv1.SetRoleStatusRequest) (iamv1.Role, error) {
	if iamv1.ValidateID("roleId", string(id)) != nil || iamv1.ValidateSetRoleStatusRequest(request) != nil {
		return iamv1.Role{}, ErrInvalidArgument
	}
	digest, err := digestSanitized("role-status", struct {
		ID      iamv1.RoleID
		Request iamv1.SetRoleStatusRequest
	}{id, request})
	if err != nil {
		return iamv1.Role{}, err
	}
	fact := auditv1.ActionIAMRoleDisabled
	if request.Status == iamv1.RoleActive {
		fact = auditv1.ActionIAMRoleEnabled
	}
	return withRoleMutation(service, ctx, credential, id, request.ResourceVersion, iamv1.ActionIAMRoleSetStatus, fact, request.RequestID, digest,
		func(ctx context.Context, tx Transaction, _ SessionCredential, mutation RoleMutation, _ time.Time) (iamv1.Role, error) {
			return tx.SetRoleStatus(ctx, RoleStatusMutation{RoleMutation: mutation, Status: request.Status})
		})
}

func (service *Authority) SetRoleTrustPolicy(ctx context.Context, credential iamv1.Secret, id iamv1.RoleID, request iamv1.SetRoleTrustPolicyRequest) (iamv1.Role, error) {
	if iamv1.ValidateID("roleId", string(id)) != nil || iamv1.ValidateSetRoleTrustPolicyRequest(request) != nil {
		return iamv1.Role{}, ErrInvalidArgument
	}
	digest, err := digestSanitized("role-trust-set", struct {
		ID      iamv1.RoleID
		Request iamv1.SetRoleTrustPolicyRequest
	}{id, request})
	if err != nil {
		return iamv1.Role{}, err
	}
	return withRoleMutation(service, ctx, credential, id, request.ResourceVersion, iamv1.ActionIAMRoleTrustSet, auditv1.ActionIAMRoleTrustSet, request.RequestID, digest,
		func(ctx context.Context, tx Transaction, subject SessionCredential, mutation RoleMutation, now time.Time) (iamv1.Role, error) {
			trustID, err := roleTrustIdentity(subject, id, request.RequestID)
			if err != nil {
				return iamv1.Role{}, err
			}
			_, digest, err := iamv1.CanonicalizeTrustPolicyDocument(request.Document)
			if err != nil {
				return iamv1.Role{}, ErrInvalidArgument
			}
			return tx.SetRoleTrustPolicy(ctx, RoleTrustMutation{RoleMutation: mutation, TrustVersion: iamv1.RoleTrustVersion{
				APIVersion: iamv1.APIVersion, Kind: "RoleTrustVersion", ID: trustID, AccountID: mutation.AccountID,
				RoleID: id, Document: request.Document, ContentDigest: digest, CreatedAt: now}})
		})
}

func (service *Authority) DeleteRole(ctx context.Context, credential iamv1.Secret, id iamv1.RoleID, request iamv1.DeleteRoleRequest) (iamv1.RoleDeletion, error) {
	if iamv1.ValidateID("roleId", string(id)) != nil || iamv1.ValidateDeleteRoleRequest(request) != nil {
		return iamv1.RoleDeletion{}, ErrInvalidArgument
	}
	digest, err := digestSanitized("role-delete", struct {
		ID      iamv1.RoleID
		Request iamv1.DeleteRoleRequest
	}{id, request})
	if err != nil {
		return iamv1.RoleDeletion{}, err
	}
	return withRoleMutation(service, ctx, credential, id, request.ResourceVersion, iamv1.ActionIAMRoleDelete, auditv1.ActionIAMRoleDeleted, request.RequestID, digest,
		func(ctx context.Context, tx Transaction, _ SessionCredential, mutation RoleMutation, _ time.Time) (iamv1.RoleDeletion, error) {
			return tx.DeleteRole(ctx, mutation)
		})
}

func (service *Authority) ListRoleTrustVersions(ctx context.Context, credential iamv1.Secret, id iamv1.RoleID, after, requestID string) (iamv1.RoleTrustVersionList, error) {
	if after != "" && iamv1.ValidatePageCursor(after) != nil {
		return iamv1.RoleTrustVersionList{}, ErrInvalidArgument
	}
	return withRoleRead(service, ctx, credential, id, requestID,
		func(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, now time.Time) (iamv1.RoleTrustVersionList, error) {
			position, query, err := service.directoryPosition(ctx, tx, subject, decision, after, now)
			if err != nil {
				return iamv1.RoleTrustVersionList{}, err
			}
			result, err := tx.ListRoleTrustVersions(ctx, RoleRead{AccountRead: AccountRead{AccountID: subject.Subject.Organization.ID, ActorPrincipalID: subject.Subject.Principal.ID, DecisionID: decision.ID, After: position}, RoleID: id})
			if err != nil {
				return iamv1.RoleTrustVersionList{}, err
			}
			result.NextAfter, err = service.sealDirectoryPage(subject, query, result.NextAfter, now)
			if err != nil || iamv1.ValidateRoleTrustVersionList(result) != nil {
				return iamv1.RoleTrustVersionList{}, ErrUnavailable
			}
			return result, nil
		})
}

func (service *Authority) GetRoleTrustVersion(ctx context.Context, credential iamv1.Secret, id iamv1.RoleID, versionID iamv1.RoleTrustVersionID, requestID string) (iamv1.RoleTrustVersion, error) {
	if iamv1.ValidateID("trustVersionId", string(versionID)) != nil {
		return iamv1.RoleTrustVersion{}, ErrInvalidArgument
	}
	return withRoleRead(service, ctx, credential, id, requestID,
		func(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, _ time.Time) (iamv1.RoleTrustVersion, error) {
			return tx.ReadRoleTrustVersion(ctx, RoleRead{AccountRead: AccountRead{AccountID: subject.Subject.Organization.ID, ActorPrincipalID: subject.Subject.Principal.ID, DecisionID: decision.ID}, RoleID: id}, versionID)
		})
}
