package identityaccess

import (
	"context"
	"time"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
)

func (service *Authority) ListGroups(ctx context.Context, credential iamv1.Secret, after, requestID string) (iamv1.GroupList, error) {
	if iamv1.ValidateID("requestId", requestID) != nil || (after != "" && iamv1.ValidatePageCursor(after) != nil) {
		return iamv1.GroupList{}, ErrInvalidArgument
	}
	return withAccountAuthorization(service, ctx, credential, iamv1.ActionIAMGroupList,
		iamv1.ResourceReference{Kind: iamv1.ResourceAccount}, requestID,
		func(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, now time.Time) (iamv1.GroupList, error) {
			position, query, err := service.directoryPosition(ctx, tx, subject, decision, after, now)
			if err != nil {
				return iamv1.GroupList{}, err
			}
			result, err := tx.ListGroups(ctx, AccountRead{AccountID: subject.Subject.Organization.ID,
				ActorPrincipalID: subject.Subject.Principal.ID, DecisionID: decision.ID, After: position})
			if err != nil {
				return iamv1.GroupList{}, err
			}
			for index := range result.Items {
				result.Items[index].Capabilities, err = groupCapabilities(subject, result.Items[index], now)
				if err != nil {
					return iamv1.GroupList{}, err
				}
			}
			result.NextAfter, err = service.sealDirectoryPage(subject, query, result.NextAfter, now)
			if err != nil || iamv1.ValidateGroupList(result) != nil {
				return iamv1.GroupList{}, ErrUnavailable
			}
			return result, nil
		})
}

func (service *Authority) GetGroup(ctx context.Context, credential iamv1.Secret, id iamv1.GroupID, requestID string) (iamv1.GroupAccess, error) {
	if iamv1.ValidateID("groupId", string(id)) != nil || iamv1.ValidateID("requestId", requestID) != nil {
		return iamv1.GroupAccess{}, ErrInvalidArgument
	}
	return withAccountAuthorization(service, ctx, credential, iamv1.ActionIAMGroupRead,
		iamv1.ResourceReference{Kind: iamv1.ResourceGroup, ID: string(id)}, requestID,
		func(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, now time.Time) (iamv1.GroupAccess, error) {
			result, err := tx.ReadGroup(ctx, GroupRead{AccountRead: AccountRead{AccountID: subject.Subject.Organization.ID,
				ActorPrincipalID: subject.Subject.Principal.ID, DecisionID: decision.ID}, GroupID: id})
			if err != nil {
				return iamv1.GroupAccess{}, err
			}
			result.Capabilities, err = groupCapabilities(subject, result, now)
			if err != nil || iamv1.ValidateGroupAccess(result) != nil {
				return iamv1.GroupAccess{}, ErrUnavailable
			}
			return result, nil
		})
}

func groupCapabilities(subject SessionCredential, target iamv1.GroupAccess, now time.Time) ([]iamv1.ActionCapability, error) {
	group := iamv1.ResourceReference{Kind: iamv1.ResourceGroup, ID: string(target.Group.ID)}
	requests := []struct {
		action   iamv1.Action
		resource iamv1.ResourceReference
	}{
		{iamv1.ActionIAMGroupRead, group},
		{iamv1.ActionIAMGroupUpdate, group},
		{iamv1.ActionIAMGroupDelete, group},
		{iamv1.ActionIAMGroupMembershipList, group},
		{iamv1.ActionIAMGroupMembershipCreate, group},
		{iamv1.ActionIAMGroupPolicyAttachmentCreate, group},
	}
	for _, attachment := range target.PolicyAttachments {
		requests = append(requests, struct {
			action   iamv1.Action
			resource iamv1.ResourceReference
		}{iamv1.ActionIAMGroupPolicyAttachmentRevoke,
			iamv1.ResourceReference{Kind: iamv1.ResourcePolicyAttachment, ID: string(attachment.ID)}})
	}
	result := make([]iamv1.ActionCapability, 0, len(requests))
	for _, request := range requests {
		capability, err := projectCapability(subject, request.action, request.resource, now)
		if err != nil {
			return nil, err
		}
		result = append(result, capability)
	}
	return result, nil
}

func (service *Authority) CreateGroup(ctx context.Context, credential iamv1.Secret, request iamv1.CreateGroupRequest) (iamv1.Group, error) {
	if iamv1.ValidateCreateGroupRequest(request) != nil {
		return iamv1.Group{}, ErrInvalidArgument
	}
	digest, err := digestSanitized("group-create", request)
	if err != nil {
		return iamv1.Group{}, err
	}
	return withAccountAuthorization(service, ctx, credential, iamv1.ActionIAMGroupCreate,
		iamv1.ResourceReference{Kind: iamv1.ResourceAccount}, request.RequestID,
		func(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, now time.Time) (iamv1.Group, error) {
			identityDigest, err := digestSanitized("group-identity", struct {
				AccountID iamv1.AccountID   `json:"accountId"`
				ActorID   iamv1.PrincipalID `json:"actorId"`
				RequestID string            `json:"requestId"`
			}{subject.Subject.Organization.ID, subject.Subject.Principal.ID, request.RequestID})
			if err != nil {
				return iamv1.Group{}, ErrUnavailable
			}
			id := "group-" + identityDigest[len("sha256:"):]
			group := iamv1.Group{APIVersion: iamv1.APIVersion, Kind: "Group", ID: iamv1.GroupID(id),
				AccountID: subject.Subject.Organization.ID, Name: request.Name, Description: request.Description,
				ResourceVersion: 1, CreatedAt: now, UpdatedAt: now}
			event, err := service.newManagementEvent(subject, auditv1.ActionIAMGroupCreated, auditv1.TargetGroup,
				id, decision.ID, digest, request.RequestID, now)
			if err != nil {
				return iamv1.Group{}, err
			}
			return tx.CreateGroup(ctx, GroupMutation{Group: group, ActorPrincipalID: subject.Subject.Principal.ID,
				DecisionID: decision.ID, AuditEvent: event})
		})
}

func (service *Authority) UpdateGroup(ctx context.Context, credential iamv1.Secret, id iamv1.GroupID, request iamv1.UpdateGroupRequest) (iamv1.Group, error) {
	if iamv1.ValidateID("groupId", string(id)) != nil || iamv1.ValidateUpdateGroupRequest(request) != nil {
		return iamv1.Group{}, ErrInvalidArgument
	}
	digest, err := digestSanitized("group-update", struct {
		ID      iamv1.GroupID            `json:"id"`
		Request iamv1.UpdateGroupRequest `json:"request"`
	}{id, request})
	if err != nil {
		return iamv1.Group{}, err
	}
	return withAccountAuthorization(service, ctx, credential, iamv1.ActionIAMGroupUpdate,
		iamv1.ResourceReference{Kind: iamv1.ResourceGroup, ID: string(id)}, request.RequestID,
		func(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, now time.Time) (iamv1.Group, error) {
			event, err := service.newManagementEvent(subject, auditv1.ActionIAMGroupUpdated, auditv1.TargetGroup,
				string(id), decision.ID, digest, request.RequestID, now)
			if err != nil {
				return iamv1.Group{}, err
			}
			return tx.UpdateGroup(ctx, GroupProfileMutation{AccountID: subject.Subject.Organization.ID,
				ActorPrincipalID: subject.Subject.Principal.ID, GroupID: id, Name: request.Name,
				Description: request.Description, ResourceVersion: request.ResourceVersion,
				DecisionID: decision.ID, AuditEvent: event})
		})
}

func (service *Authority) DeleteGroup(ctx context.Context, credential iamv1.Secret, id iamv1.GroupID, request iamv1.DeleteGroupRequest) (iamv1.GroupDeletion, error) {
	if iamv1.ValidateID("groupId", string(id)) != nil || iamv1.ValidateDeleteGroupRequest(request) != nil {
		return iamv1.GroupDeletion{}, ErrInvalidArgument
	}
	digest, err := digestSanitized("group-delete", struct {
		ID      iamv1.GroupID            `json:"id"`
		Request iamv1.DeleteGroupRequest `json:"request"`
	}{id, request})
	if err != nil {
		return iamv1.GroupDeletion{}, err
	}
	result, err := withAccountAuthorization(service, ctx, credential, iamv1.ActionIAMGroupDelete,
		iamv1.ResourceReference{Kind: iamv1.ResourceGroup, ID: string(id)}, request.RequestID,
		func(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, now time.Time) (iamv1.GroupDeletion, error) {
			event, err := service.newManagementEvent(subject, auditv1.ActionIAMGroupDeleted, auditv1.TargetGroup,
				string(id), decision.ID, digest, request.RequestID, now)
			if err != nil {
				return iamv1.GroupDeletion{}, err
			}
			return tx.DeleteGroup(ctx, GroupDeletionMutation{AccountID: subject.Subject.Organization.ID,
				ActorPrincipalID: subject.Subject.Principal.ID, GroupID: id, ResourceVersion: request.ResourceVersion,
				DecisionID: decision.ID, AuditEvent: event})
		})
	if err != nil {
		return iamv1.GroupDeletion{}, err
	}
	if iamv1.ValidateGroupDeletion(result) != nil {
		return iamv1.GroupDeletion{}, ErrUnavailable
	}
	return result, nil
}

func (service *Authority) ListGroupMemberships(ctx context.Context, credential iamv1.Secret, groupID iamv1.GroupID, after, requestID string) (iamv1.GroupMembershipList, error) {
	if iamv1.ValidateID("groupId", string(groupID)) != nil || iamv1.ValidateID("requestId", requestID) != nil ||
		(after != "" && iamv1.ValidatePageCursor(after) != nil) {
		return iamv1.GroupMembershipList{}, ErrInvalidArgument
	}
	return withAccountAuthorization(service, ctx, credential, iamv1.ActionIAMGroupMembershipList,
		iamv1.ResourceReference{Kind: iamv1.ResourceGroup, ID: string(groupID)}, requestID,
		func(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, now time.Time) (iamv1.GroupMembershipList, error) {
			position, query, err := service.directoryPosition(ctx, tx, subject, decision, after, now)
			if err != nil {
				return iamv1.GroupMembershipList{}, err
			}
			result, err := tx.ListGroupMemberships(ctx, GroupRead{AccountRead: AccountRead{AccountID: subject.Subject.Organization.ID,
				ActorPrincipalID: subject.Subject.Principal.ID, DecisionID: decision.ID, After: position}, GroupID: groupID})
			if err != nil {
				return iamv1.GroupMembershipList{}, err
			}
			for index := range result.Items {
				membership := result.Items[index].Membership
				capability, err := projectCapability(subject, iamv1.ActionIAMGroupMembershipRemove,
					iamv1.ResourceReference{Kind: iamv1.ResourceGroupMembership, ID: string(membership.ID)}, now)
				if err != nil {
					return iamv1.GroupMembershipList{}, err
				}
				result.Items[index].Capabilities = []iamv1.ActionCapability{capability}
			}
			result.NextAfter, err = service.sealDirectoryPage(subject, query, result.NextAfter, now)
			if err != nil || iamv1.ValidateGroupMembershipList(result) != nil {
				return iamv1.GroupMembershipList{}, ErrUnavailable
			}
			return result, nil
		})
}

func (service *Authority) CreateGroupMembership(ctx context.Context, credential iamv1.Secret, groupID iamv1.GroupID, request iamv1.CreateGroupMembershipRequest) (iamv1.GroupMembership, error) {
	if iamv1.ValidateID("groupId", string(groupID)) != nil || iamv1.ValidateCreateGroupMembershipRequest(request) != nil {
		return iamv1.GroupMembership{}, ErrInvalidArgument
	}
	digest, err := digestSanitized("group-membership-create", struct {
		GroupID iamv1.GroupID                      `json:"groupId"`
		Request iamv1.CreateGroupMembershipRequest `json:"request"`
	}{groupID, request})
	if err != nil {
		return iamv1.GroupMembership{}, err
	}
	return withAccountAuthorization(service, ctx, credential, iamv1.ActionIAMGroupMembershipCreate,
		iamv1.ResourceReference{Kind: iamv1.ResourceGroup, ID: string(groupID)}, request.RequestID,
		func(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, now time.Time) (iamv1.GroupMembership, error) {
			if request.UserID == subject.Subject.Principal.ID {
				return iamv1.GroupMembership{}, ErrForbidden
			}
			identityDigest, err := digestSanitized("group-membership-identity", struct {
				AccountID iamv1.AccountID   `json:"accountId"`
				ActorID   iamv1.PrincipalID `json:"actorId"`
				RequestID string            `json:"requestId"`
			}{subject.Subject.Organization.ID, subject.Subject.Principal.ID, request.RequestID})
			if err != nil {
				return iamv1.GroupMembership{}, ErrUnavailable
			}
			id := "membership-" + identityDigest[len("sha256:"):]
			membership := iamv1.GroupMembership{APIVersion: iamv1.APIVersion, Kind: "GroupMembership",
				ID: iamv1.GroupMembershipID(id), AccountID: subject.Subject.Organization.ID, GroupID: groupID,
				UserID: request.UserID, CreatedBy: subject.Subject.Principal.ID,
				ResourceVersion: 1, CreatedAt: now, UpdatedAt: now}
			event, err := service.newManagementEvent(subject, auditv1.ActionIAMGroupMembershipCreated,
				auditv1.TargetGroupMembership, id, decision.ID, digest, request.RequestID, now)
			if err != nil {
				return iamv1.GroupMembership{}, err
			}
			return tx.CreateGroupMembership(ctx, GroupMembershipMutation{Membership: membership,
				ActorPrincipalID: subject.Subject.Principal.ID, DecisionID: decision.ID, AuditEvent: event})
		})
}

func (service *Authority) RemoveGroupMembership(ctx context.Context, credential iamv1.Secret, groupID iamv1.GroupID,
	membershipID iamv1.GroupMembershipID, request iamv1.RemoveGroupMembershipRequest,
) (iamv1.GroupMembership, error) {
	if iamv1.ValidateID("groupId", string(groupID)) != nil || iamv1.ValidateID("membershipId", string(membershipID)) != nil ||
		iamv1.ValidateRemoveGroupMembershipRequest(request) != nil {
		return iamv1.GroupMembership{}, ErrInvalidArgument
	}
	digest, err := digestSanitized("group-membership-remove", struct {
		GroupID      iamv1.GroupID                      `json:"groupId"`
		MembershipID iamv1.GroupMembershipID            `json:"membershipId"`
		Request      iamv1.RemoveGroupMembershipRequest `json:"request"`
	}{groupID, membershipID, request})
	if err != nil {
		return iamv1.GroupMembership{}, err
	}
	result, err := withAccountAuthorization(service, ctx, credential, iamv1.ActionIAMGroupMembershipRemove,
		iamv1.ResourceReference{Kind: iamv1.ResourceGroupMembership, ID: string(membershipID)}, request.RequestID,
		func(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, now time.Time) (iamv1.GroupMembership, error) {
			event, err := service.newManagementEvent(subject, auditv1.ActionIAMGroupMembershipRemoved,
				auditv1.TargetGroupMembership, string(membershipID), decision.ID, digest, request.RequestID, now)
			if err != nil {
				return iamv1.GroupMembership{}, err
			}
			stored, _, err := tx.RemoveGroupMembership(ctx, GroupMembershipRemovalMutation{
				AccountID: subject.Subject.Organization.ID, ActorPrincipalID: subject.Subject.Principal.ID,
				GroupID: groupID, MembershipID: membershipID, ResourceVersion: request.ResourceVersion,
				DecisionID: decision.ID, AuditEvent: event})
			return stored, err
		})
	if err != nil {
		return iamv1.GroupMembership{}, err
	}
	if iamv1.ValidateGroupMembership(result) != nil || result.RemovedAt == nil {
		return iamv1.GroupMembership{}, ErrUnavailable
	}
	return result, nil
}
