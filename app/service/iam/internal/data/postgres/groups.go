package postgres

import (
	"context"
	"encoding/json"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/iam/internal/usecase/identityaccess"
)

func normalizeGroup(value *iamv1.Group) {
	value.CreatedAt = value.CreatedAt.UTC()
	value.UpdatedAt = value.UpdatedAt.UTC()
}

func decodeGroup(encoded []byte) (iamv1.Group, error) {
	var result iamv1.Group
	if json.Unmarshal(encoded, &result) != nil {
		return iamv1.Group{}, identityaccess.ErrUnavailable
	}
	normalizeGroup(&result)
	if iamv1.ValidateGroup(result) != nil {
		return iamv1.Group{}, identityaccess.ErrUnavailable
	}
	return result, nil
}

func normalizeGroupAccess(value *iamv1.GroupAccess, account iamv1.AccountID) error {
	normalizeGroup(&value.Group)
	if iamv1.ValidateGroup(value.Group) != nil || value.Group.AccountID != account || len(value.Capabilities) != 0 {
		return identityaccess.ErrUnavailable
	}
	attachments := make(map[iamv1.PolicyAttachmentID]bool, len(value.PolicyAttachments))
	policies := make(map[iamv1.PolicyID]bool, len(value.PolicyAttachments))
	for index := range value.PolicyAttachments {
		attachment := &value.PolicyAttachments[index]
		attachment.CreatedAt, attachment.UpdatedAt = attachment.CreatedAt.UTC(), attachment.UpdatedAt.UTC()
		if iamv1.ValidatePolicyAttachment(*attachment) != nil || attachment.RevokedAt != nil ||
			attachment.AccountID != account || attachment.Scope != iamv1.AuthorityScopeTenant ||
			attachment.Target.Kind != iamv1.PolicyTargetGroup || attachment.Target.ID != string(value.Group.ID) ||
			attachments[attachment.ID] || policies[attachment.PolicyID] {
			return identityaccess.ErrUnavailable
		}
		attachments[attachment.ID], policies[attachment.PolicyID] = true, true
	}
	return nil
}

func decodeGroupMembership(encoded []byte) (iamv1.GroupMembership, error) {
	var result iamv1.GroupMembership
	if json.Unmarshal(encoded, &result) != nil {
		return iamv1.GroupMembership{}, identityaccess.ErrUnavailable
	}
	result.CreatedAt, result.UpdatedAt = result.CreatedAt.UTC(), result.UpdatedAt.UTC()
	if result.RemovedAt != nil {
		removed := result.RemovedAt.UTC()
		result.RemovedAt = &removed
	}
	if iamv1.ValidateGroupMembership(result) != nil {
		return iamv1.GroupMembership{}, identityaccess.ErrUnavailable
	}
	return result, nil
}

func marshalGroupEvent(event auditv1.Event) ([]byte, error) {
	if auditv1.ValidateEventForSource(auditv1.SourceIAM, event) != nil {
		return nil, identityaccess.ErrInvalidArgument
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		return nil, identityaccess.ErrUnavailable
	}
	return encoded, nil
}

func (value *transaction) ListGroups(ctx context.Context, read identityaccess.AccountRead) (iamv1.GroupList, error) {
	var encoded []byte
	if err := value.tx.QueryRow(ctx, "SELECT iam.list_groups($1,$2,$3,$4)", read.AccountID, read.ActorPrincipalID, read.DecisionID, read.After).Scan(&encoded); err != nil {
		return iamv1.GroupList{}, mapAuthorizationDatabaseError("list IAM groups", err)
	}
	result := iamv1.GroupList{APIVersion: iamv1.APIVersion, Kind: "GroupList"}
	if json.Unmarshal(encoded, &result.Items) != nil || len(result.Items) > 101 {
		return iamv1.GroupList{}, identityaccess.ErrUnavailable
	}
	if len(result.Items) > 100 {
		result.Items = result.Items[:100]
		result.NextAfter = string(result.Items[99].Group.ID)
	}
	for index := range result.Items {
		if normalizeGroupAccess(&result.Items[index], read.AccountID) != nil ||
			(index > 0 && result.Items[index-1].Group.ID >= result.Items[index].Group.ID) {
			return iamv1.GroupList{}, identityaccess.ErrUnavailable
		}
	}
	return result, nil
}

func (value *transaction) ReadGroup(ctx context.Context, read identityaccess.GroupRead) (iamv1.GroupAccess, error) {
	var encoded []byte
	if err := value.tx.QueryRow(ctx, "SELECT iam.read_group($1,$2,$3,$4)", read.AccountID, read.ActorPrincipalID, read.DecisionID, read.GroupID).Scan(&encoded); err != nil {
		return iamv1.GroupAccess{}, mapAuthorizationDatabaseError("read IAM group", err)
	}
	var result iamv1.GroupAccess
	if json.Unmarshal(encoded, &result) != nil || normalizeGroupAccess(&result, read.AccountID) != nil || result.Group.ID != read.GroupID {
		return iamv1.GroupAccess{}, identityaccess.ErrUnavailable
	}
	return result, nil
}

func (value *transaction) CreateGroup(ctx context.Context, mutation identityaccess.GroupMutation) (iamv1.Group, error) {
	if iamv1.ValidateGroup(mutation.Group) != nil {
		return iamv1.Group{}, identityaccess.ErrInvalidArgument
	}
	event, err := marshalGroupEvent(mutation.AuditEvent)
	if err != nil {
		return iamv1.Group{}, err
	}
	defer clear(event)
	var encoded []byte
	err = value.tx.QueryRow(ctx, "SELECT iam.create_group($1,$2,$3,$4,$5,$6,$7::jsonb)", mutation.Group.AccountID,
		mutation.ActorPrincipalID, mutation.DecisionID, mutation.Group.ID, mutation.Group.Name, mutation.Group.Description, event).Scan(&encoded)
	if err != nil {
		return iamv1.Group{}, mapAuthorizationDatabaseError("create IAM group", err)
	}
	return decodeGroup(encoded)
}

func (value *transaction) UpdateGroup(ctx context.Context, mutation identityaccess.GroupProfileMutation) (iamv1.Group, error) {
	event, err := marshalGroupEvent(mutation.AuditEvent)
	if err != nil {
		return iamv1.Group{}, err
	}
	defer clear(event)
	var encoded []byte
	err = value.tx.QueryRow(ctx, "SELECT iam.update_group($1,$2,$3,$4,$5,$6,$7,$8::jsonb)", mutation.AccountID,
		mutation.ActorPrincipalID, mutation.DecisionID, mutation.GroupID, mutation.Name, mutation.Description,
		mutation.ResourceVersion, event).Scan(&encoded)
	if err != nil {
		return iamv1.Group{}, mapAuthorizationDatabaseError("update IAM group", err)
	}
	result, err := decodeGroup(encoded)
	if err != nil || result.ID != mutation.GroupID || result.ResourceVersion != mutation.ResourceVersion+1 {
		return iamv1.Group{}, identityaccess.ErrUnavailable
	}
	return result, nil
}

func (value *transaction) DeleteGroup(ctx context.Context, mutation identityaccess.GroupDeletionMutation) (iamv1.GroupDeletion, error) {
	event, err := marshalGroupEvent(mutation.AuditEvent)
	if err != nil {
		return iamv1.GroupDeletion{}, err
	}
	defer clear(event)
	var encoded []byte
	err = value.tx.QueryRow(ctx, "SELECT iam.delete_group($1,$2,$3,$4,$5,$6::jsonb)", mutation.AccountID,
		mutation.ActorPrincipalID, mutation.DecisionID, mutation.GroupID, mutation.ResourceVersion, event).Scan(&encoded)
	if err != nil {
		return iamv1.GroupDeletion{}, mapAuthorizationDatabaseError("delete IAM group", err)
	}
	var result iamv1.GroupDeletion
	if json.Unmarshal(encoded, &result) != nil {
		return iamv1.GroupDeletion{}, identityaccess.ErrUnavailable
	}
	result.DeletedAt = result.DeletedAt.UTC()
	if iamv1.ValidateGroupDeletion(result) != nil || result.ID != mutation.GroupID || result.AccountID != mutation.AccountID ||
		result.ResourceVersion != mutation.ResourceVersion+1 {
		return iamv1.GroupDeletion{}, identityaccess.ErrUnavailable
	}
	return result, nil
}

func (value *transaction) ListGroupMemberships(ctx context.Context, read identityaccess.GroupRead) (iamv1.GroupMembershipList, error) {
	var encoded []byte
	if err := value.tx.QueryRow(ctx, "SELECT iam.list_group_memberships($1,$2,$3,$4,$5)", read.AccountID,
		read.ActorPrincipalID, read.DecisionID, read.GroupID, read.After).Scan(&encoded); err != nil {
		return iamv1.GroupMembershipList{}, mapAuthorizationDatabaseError("list IAM group memberships", err)
	}
	var rows []json.RawMessage
	if json.Unmarshal(encoded, &rows) != nil || len(rows) > 101 {
		return iamv1.GroupMembershipList{}, identityaccess.ErrUnavailable
	}
	result := iamv1.GroupMembershipList{APIVersion: iamv1.APIVersion, Kind: "GroupMembershipList",
		AccountID: read.AccountID, GroupID: read.GroupID, Items: make([]iamv1.GroupMembershipAccess, 0, min(100, len(rows)))}
	for index, row := range rows {
		if index == 100 {
			result.NextAfter = string(result.Items[99].Membership.ID)
			break
		}
		membership, err := decodeGroupMembership(row)
		if err != nil || membership.RemovedAt != nil || membership.AccountID != read.AccountID || membership.GroupID != read.GroupID ||
			(index > 0 && result.Items[index-1].Membership.ID >= membership.ID) {
			return iamv1.GroupMembershipList{}, identityaccess.ErrUnavailable
		}
		result.Items = append(result.Items, iamv1.GroupMembershipAccess{Membership: membership})
	}
	return result, nil
}

func (value *transaction) CreateGroupMembership(ctx context.Context, mutation identityaccess.GroupMembershipMutation) (iamv1.GroupMembership, error) {
	if iamv1.ValidateGroupMembership(mutation.Membership) != nil || mutation.Membership.RemovedAt != nil {
		return iamv1.GroupMembership{}, identityaccess.ErrInvalidArgument
	}
	event, err := marshalGroupEvent(mutation.AuditEvent)
	if err != nil {
		return iamv1.GroupMembership{}, err
	}
	defer clear(event)
	var encoded []byte
	err = value.tx.QueryRow(ctx, "SELECT iam.create_group_membership($1,$2,$3,$4,$5,$6,$7::jsonb)",
		mutation.Membership.AccountID, mutation.ActorPrincipalID, mutation.DecisionID, mutation.Membership.ID,
		mutation.Membership.GroupID, mutation.Membership.UserID, event).Scan(&encoded)
	if err != nil {
		return iamv1.GroupMembership{}, mapAuthorizationDatabaseError("create IAM group membership", err)
	}
	return decodeGroupMembership(encoded)
}

func (value *transaction) RemoveGroupMembership(ctx context.Context, mutation identityaccess.GroupMembershipRemovalMutation) (iamv1.GroupMembership, bool, error) {
	event, err := marshalGroupEvent(mutation.AuditEvent)
	if err != nil {
		return iamv1.GroupMembership{}, false, err
	}
	defer clear(event)
	var encoded []byte
	var applied bool
	err = value.tx.QueryRow(ctx, "SELECT * FROM iam.remove_group_membership($1,$2,$3,$4,$5,$6,$7::jsonb)",
		mutation.AccountID, mutation.ActorPrincipalID, mutation.DecisionID, mutation.GroupID, mutation.MembershipID,
		mutation.ResourceVersion, event).Scan(&encoded, &applied)
	if err != nil {
		return iamv1.GroupMembership{}, false, mapAuthorizationDatabaseError("remove IAM group membership", err)
	}
	result, err := decodeGroupMembership(encoded)
	if err != nil || result.AccountID != mutation.AccountID || result.GroupID != mutation.GroupID || result.ID != mutation.MembershipID || result.RemovedAt == nil {
		return iamv1.GroupMembership{}, false, identityaccess.ErrUnavailable
	}
	return result, applied, nil
}
