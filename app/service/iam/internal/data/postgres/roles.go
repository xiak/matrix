package postgres

import (
	"context"
	"encoding/json"
	"reflect"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/iam/internal/usecase/identityaccess"
)

type roleMetadata struct {
	Name                      string          `json:"name"`
	Description               string          `json:"description"`
	Tags                      []iamv1.RoleTag `json:"tags"`
	MaxSessionDurationSeconds uint32          `json:"maxSessionDurationSeconds"`
}

func normalizeRole(role *iamv1.Role) {
	role.CreatedAt, role.UpdatedAt = role.CreatedAt.UTC(), role.UpdatedAt.UTC()
}

func decodeRole(encoded []byte, account iamv1.AccountID, id iamv1.RoleID, revision uint64) (iamv1.Role, error) {
	var result iamv1.Role
	if json.Unmarshal(encoded, &result) != nil {
		return iamv1.Role{}, identityaccess.ErrUnavailable
	}
	normalizeRole(&result)
	if iamv1.ValidateRole(result) != nil || result.AccountID != account || result.ID != id || result.ResourceVersion != revision {
		return iamv1.Role{}, identityaccess.ErrUnavailable
	}
	return result, nil
}

func encodeRoleTrust(version iamv1.RoleTrustVersion) ([]byte, error) {
	if iamv1.ValidateRoleTrustVersion(version) != nil {
		return nil, identityaccess.ErrInvalidArgument
	}
	canonical, digest, err := iamv1.CanonicalizeTrustPolicyDocument(version.Document)
	if err != nil {
		return nil, identityaccess.ErrInvalidArgument
	}
	return json.Marshal(struct {
		CanonicalDocument string `json:"canonicalDocument"`
		ContentDigest     string `json:"contentDigest"`
	}{canonical, digest})
}

func (value *transaction) ListRoles(ctx context.Context, read identityaccess.AccountRead) (iamv1.RoleList, error) {
	var encoded []byte
	if err := value.tx.QueryRow(ctx, "SELECT iam.list_roles($1,$2,$3,$4)", read.AccountID, read.ActorPrincipalID, read.DecisionID, read.After).Scan(&encoded); err != nil {
		return iamv1.RoleList{}, mapAuthorizationDatabaseError("list IAM roles", err)
	}
	result := iamv1.RoleList{APIVersion: iamv1.APIVersion, Kind: "RoleList", AccountID: read.AccountID}
	if int64(len(encoded)) > iamv1.MaxRoleListBytes || json.Unmarshal(encoded, &result.Items) != nil || result.Items == nil || len(result.Items) > 101 {
		return iamv1.RoleList{}, identityaccess.ErrUnavailable
	}
	previous := read.After
	for index := range result.Items {
		item := &result.Items[index]
		normalizeRole(&item.Role)
		if iamv1.ValidateRole(item.Role) != nil || item.Role.AccountID != read.AccountID || string(item.Role.ID) <= previous || len(item.Capabilities) != 0 {
			return iamv1.RoleList{}, identityaccess.ErrUnavailable
		}
		previous = string(item.Role.ID)
	}
	if len(result.Items) > iamv1.DirectoryPageSize {
		result.Items = result.Items[:iamv1.DirectoryPageSize]
		result.NextAfter = string(result.Items[iamv1.DirectoryPageSize-1].Role.ID)
	}
	return result, nil
}

func (value *transaction) ReadRole(ctx context.Context, read identityaccess.RoleRead) (iamv1.RoleAccess, error) {
	var encoded []byte
	if err := value.tx.QueryRow(ctx, "SELECT iam.read_role($1,$2,$3,$4)", read.AccountID, read.ActorPrincipalID, read.DecisionID, read.RoleID).Scan(&encoded); err != nil {
		return iamv1.RoleAccess{}, mapAuthorizationDatabaseError("read IAM role", err)
	}
	var result iamv1.RoleAccess
	if int64(len(encoded)) > iamv1.MaxRoleAccessBytes || json.Unmarshal(encoded, &result) != nil {
		return iamv1.RoleAccess{}, identityaccess.ErrUnavailable
	}
	normalizeRole(&result.Role)
	result.TrustVersion.CreatedAt = result.TrustVersion.CreatedAt.UTC()
	if iamv1.ValidateRole(result.Role) != nil || result.Role.AccountID != read.AccountID || result.Role.ID != read.RoleID ||
		iamv1.ValidateRoleTrustVersion(result.TrustVersion) != nil || result.TrustVersion.AccountID != read.AccountID || result.TrustVersion.RoleID != read.RoleID ||
		result.TrustVersion.ID != result.Role.CurrentTrustVersionID || result.PolicyAttachments == nil || len(result.PolicyAttachments) > 256 || len(result.Capabilities) != 0 {
		return iamv1.RoleAccess{}, identityaccess.ErrUnavailable
	}
	attachments, policies := map[iamv1.PolicyAttachmentID]bool{}, map[iamv1.PolicyID]bool{}
	for index := range result.PolicyAttachments {
		attachment := &result.PolicyAttachments[index]
		attachment.CreatedAt, attachment.UpdatedAt = attachment.CreatedAt.UTC(), attachment.UpdatedAt.UTC()
		if iamv1.ValidatePolicyAttachment(*attachment) != nil || attachment.AccountID != read.AccountID || attachment.Target.Kind != iamv1.PolicyTargetRole ||
			attachment.Target.ID != string(read.RoleID) || attachment.Scope != iamv1.AuthorityScopeTenant || attachment.RevokedAt != nil || attachments[attachment.ID] || policies[attachment.PolicyID] {
			return iamv1.RoleAccess{}, identityaccess.ErrUnavailable
		}
		attachments[attachment.ID], policies[attachment.PolicyID] = true, true
	}
	return result, nil
}

func (value *transaction) CreateRole(ctx context.Context, mutation identityaccess.RoleCreation) (iamv1.Role, error) {
	role := mutation.Role
	if iamv1.ValidateID("actorSessionId", string(mutation.ActorSessionID)) != nil || iamv1.ValidateRole(role) != nil || mutation.TrustVersion.AccountID != role.AccountID || mutation.TrustVersion.RoleID != role.ID || mutation.TrustVersion.ID != role.CurrentTrustVersionID {
		return iamv1.Role{}, identityaccess.ErrInvalidArgument
	}
	trust, err := encodeRoleTrust(mutation.TrustVersion)
	if err != nil {
		return iamv1.Role{}, err
	}
	metadata, err := json.Marshal(roleMetadata{role.Name, role.Description, role.Tags, role.MaxSessionDurationSeconds})
	if err != nil {
		return iamv1.Role{}, identityaccess.ErrInvalidArgument
	}
	event, err := marshalManagementEvent(mutation.AuditEvent)
	if err != nil {
		return iamv1.Role{}, err
	}
	defer clear(event)
	var encoded []byte
	err = value.tx.QueryRow(ctx, "SELECT iam.create_role($1,$2,$3,$4,$5,$6::jsonb,$7::jsonb,$8::jsonb,$9)", role.AccountID,
		mutation.ActorPrincipalID, mutation.DecisionID, role.ID, mutation.TrustVersion.ID, metadata, trust, event, mutation.ActorSessionID).Scan(&encoded)
	if err != nil {
		return iamv1.Role{}, mapAuthorizationDatabaseError("create IAM role", err)
	}
	result, err := decodeRole(encoded, role.AccountID, role.ID, 1)
	if err != nil || result.CurrentTrustVersionID != role.CurrentTrustVersionID || result.Status != iamv1.RoleActive ||
		result.Name != role.Name || result.Description != role.Description || !reflect.DeepEqual(result.Tags, role.Tags) || result.MaxSessionDurationSeconds != role.MaxSessionDurationSeconds {
		return iamv1.Role{}, identityaccess.ErrUnavailable
	}
	return result, nil
}

func (value *transaction) UpdateRole(ctx context.Context, mutation identityaccess.RoleProfileMutation) (iamv1.Role, error) {
	if iamv1.ValidateID("actorSessionId", string(mutation.ActorSessionID)) != nil {
		return iamv1.Role{}, identityaccess.ErrInvalidArgument
	}
	metadata, err := json.Marshal(roleMetadata{mutation.Name, mutation.Description, mutation.Tags, mutation.MaxSessionDurationSeconds})
	if err != nil {
		return iamv1.Role{}, identityaccess.ErrInvalidArgument
	}
	event, err := marshalManagementEvent(mutation.AuditEvent)
	if err != nil {
		return iamv1.Role{}, err
	}
	defer clear(event)
	var encoded []byte
	err = value.tx.QueryRow(ctx, "SELECT iam.update_role($1,$2,$3,$4,$5,$6::jsonb,$7::jsonb,$8)", mutation.AccountID,
		mutation.ActorPrincipalID, mutation.DecisionID, mutation.RoleID, mutation.ResourceVersion, metadata, event, mutation.ActorSessionID).Scan(&encoded)
	if err != nil {
		return iamv1.Role{}, mapAuthorizationDatabaseError("update IAM role", err)
	}
	result, err := decodeRole(encoded, mutation.AccountID, mutation.RoleID, mutation.ResourceVersion+1)
	if err != nil || result.Name != mutation.Name || result.Description != mutation.Description || !reflect.DeepEqual(result.Tags, mutation.Tags) || result.MaxSessionDurationSeconds != mutation.MaxSessionDurationSeconds {
		return iamv1.Role{}, identityaccess.ErrUnavailable
	}
	return result, nil
}

func (value *transaction) SetRoleStatus(ctx context.Context, mutation identityaccess.RoleStatusMutation) (iamv1.Role, error) {
	if iamv1.ValidateID("actorSessionId", string(mutation.ActorSessionID)) != nil {
		return iamv1.Role{}, identityaccess.ErrInvalidArgument
	}
	event, err := marshalManagementEvent(mutation.AuditEvent)
	if err != nil {
		return iamv1.Role{}, err
	}
	defer clear(event)
	var encoded []byte
	err = value.tx.QueryRow(ctx, "SELECT iam.set_role_status($1,$2,$3,$4,$5,$6,$7::jsonb,$8)", mutation.AccountID,
		mutation.ActorPrincipalID, mutation.DecisionID, mutation.RoleID, mutation.ResourceVersion, mutation.Status, event, mutation.ActorSessionID).Scan(&encoded)
	if err != nil {
		return iamv1.Role{}, mapAuthorizationDatabaseError("set IAM role status", err)
	}
	result, err := decodeRole(encoded, mutation.AccountID, mutation.RoleID, mutation.ResourceVersion+1)
	if err != nil || result.Status != mutation.Status {
		return iamv1.Role{}, identityaccess.ErrUnavailable
	}
	return result, nil
}

func (value *transaction) SetRoleTrustPolicy(ctx context.Context, mutation identityaccess.RoleTrustMutation) (iamv1.Role, error) {
	if iamv1.ValidateID("actorSessionId", string(mutation.ActorSessionID)) != nil || mutation.TrustVersion.AccountID != mutation.AccountID || mutation.TrustVersion.RoleID != mutation.RoleID {
		return iamv1.Role{}, identityaccess.ErrInvalidArgument
	}
	trust, err := encodeRoleTrust(mutation.TrustVersion)
	if err != nil {
		return iamv1.Role{}, err
	}
	event, err := marshalManagementEvent(mutation.AuditEvent)
	if err != nil {
		return iamv1.Role{}, err
	}
	defer clear(event)
	var encoded []byte
	err = value.tx.QueryRow(ctx, "SELECT iam.set_role_trust_policy($1,$2,$3,$4,$5,$6,$7::jsonb,$8::jsonb,$9)", mutation.AccountID,
		mutation.ActorPrincipalID, mutation.DecisionID, mutation.RoleID, mutation.TrustVersion.ID, mutation.ResourceVersion, trust, event, mutation.ActorSessionID).Scan(&encoded)
	if err != nil {
		return iamv1.Role{}, mapAuthorizationDatabaseError("set IAM role trust", err)
	}
	result, err := decodeRole(encoded, mutation.AccountID, mutation.RoleID, mutation.ResourceVersion+1)
	if err != nil || result.CurrentTrustVersionID != mutation.TrustVersion.ID {
		return iamv1.Role{}, identityaccess.ErrUnavailable
	}
	return result, nil
}

func (value *transaction) DeleteRole(ctx context.Context, mutation identityaccess.RoleMutation) (iamv1.RoleDeletion, error) {
	if iamv1.ValidateID("actorSessionId", string(mutation.ActorSessionID)) != nil {
		return iamv1.RoleDeletion{}, identityaccess.ErrInvalidArgument
	}
	event, err := marshalManagementEvent(mutation.AuditEvent)
	if err != nil {
		return iamv1.RoleDeletion{}, err
	}
	defer clear(event)
	var encoded []byte
	err = value.tx.QueryRow(ctx, "SELECT iam.delete_role($1,$2,$3,$4,$5,$6::jsonb,$7)", mutation.AccountID,
		mutation.ActorPrincipalID, mutation.DecisionID, mutation.RoleID, mutation.ResourceVersion, event, mutation.ActorSessionID).Scan(&encoded)
	if err != nil {
		return iamv1.RoleDeletion{}, mapAuthorizationDatabaseError("delete IAM role", err)
	}
	var result iamv1.RoleDeletion
	if json.Unmarshal(encoded, &result) != nil {
		return iamv1.RoleDeletion{}, identityaccess.ErrUnavailable
	}
	result.DeletedAt = result.DeletedAt.UTC()
	if iamv1.ValidateRoleDeletion(result) != nil || result.ID != mutation.RoleID || result.AccountID != mutation.AccountID || result.ResourceVersion != mutation.ResourceVersion+1 {
		return iamv1.RoleDeletion{}, identityaccess.ErrUnavailable
	}
	return result, nil
}

func (value *transaction) ListRoleTrustVersions(ctx context.Context, read identityaccess.RoleRead) (iamv1.RoleTrustVersionList, error) {
	var encoded []byte
	if err := value.tx.QueryRow(ctx, "SELECT iam.list_role_trust_versions($1,$2,$3,$4,$5)", read.AccountID, read.ActorPrincipalID, read.DecisionID, read.RoleID, read.After).Scan(&encoded); err != nil {
		return iamv1.RoleTrustVersionList{}, mapAuthorizationDatabaseError("list IAM role trust", err)
	}
	result := iamv1.RoleTrustVersionList{APIVersion: iamv1.APIVersion, Kind: "RoleTrustVersionList", AccountID: read.AccountID, RoleID: read.RoleID}
	if int64(len(encoded)) > iamv1.MaxRoleListBytes || json.Unmarshal(encoded, &result.Items) != nil || result.Items == nil || len(result.Items) > 101 {
		return iamv1.RoleTrustVersionList{}, identityaccess.ErrUnavailable
	}
	previous := read.After
	for index := range result.Items {
		item := &result.Items[index]
		item.CreatedAt = item.CreatedAt.UTC()
		if iamv1.ValidateRoleTrustVersion(*item) != nil || item.AccountID != read.AccountID || item.RoleID != read.RoleID || string(item.ID) <= previous {
			return iamv1.RoleTrustVersionList{}, identityaccess.ErrUnavailable
		}
		previous = string(item.ID)
	}
	if len(result.Items) > iamv1.DirectoryPageSize {
		result.Items = result.Items[:iamv1.DirectoryPageSize]
		result.NextAfter = string(result.Items[iamv1.DirectoryPageSize-1].ID)
	}
	return result, nil
}

func (value *transaction) ReadRoleTrustVersion(ctx context.Context, read identityaccess.RoleRead, id iamv1.RoleTrustVersionID) (iamv1.RoleTrustVersion, error) {
	var encoded []byte
	if err := value.tx.QueryRow(ctx, "SELECT iam.read_role_trust_version($1,$2,$3,$4,$5)", read.AccountID, read.ActorPrincipalID, read.DecisionID, read.RoleID, id).Scan(&encoded); err != nil {
		return iamv1.RoleTrustVersion{}, mapAuthorizationDatabaseError("read IAM role trust", err)
	}
	var result iamv1.RoleTrustVersion
	if json.Unmarshal(encoded, &result) != nil {
		return iamv1.RoleTrustVersion{}, identityaccess.ErrUnavailable
	}
	result.CreatedAt = result.CreatedAt.UTC()
	if iamv1.ValidateRoleTrustVersion(result) != nil || result.ID != id || result.AccountID != read.AccountID || result.RoleID != read.RoleID {
		return iamv1.RoleTrustVersion{}, identityaccess.ErrUnavailable
	}
	return result, nil
}
