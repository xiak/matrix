package postgres

import (
	"bytes"
	"context"
	"encoding/json"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/iam/internal/usecase/identityaccess"
)

func (value *transaction) ReadUserPermissionBoundary(ctx context.Context, read identityaccess.AccountRead, user iamv1.PrincipalID) (iamv1.UserPermissionBoundary, error) {
	var encoded []byte
	if err := value.tx.QueryRow(ctx, "SELECT iam.read_user_permission_boundary($1,$2,$3,$4)", read.AccountID, read.ActorPrincipalID, read.DecisionID, user).Scan(&encoded); err != nil {
		return iamv1.UserPermissionBoundary{}, mapAuthorizationDatabaseError("read IAM user boundary", err)
	}
	return decodeUserPermissionBoundary(encoded, read.AccountID, user)
}

func (value *transaction) ChangeUserPermissionBoundary(ctx context.Context, mutation identityaccess.UserBoundaryMutation) (iamv1.UserPermissionBoundary, error) {
	if auditv1.ValidateEventForSource(auditv1.SourceIAM, mutation.AuditEvent) != nil {
		return iamv1.UserPermissionBoundary{}, identityaccess.ErrInvalidArgument
	}
	event, err := json.Marshal(mutation.AuditEvent)
	if err != nil {
		return iamv1.UserPermissionBoundary{}, identityaccess.ErrUnavailable
	}
	defer clear(event)
	var encoded []byte
	if err = value.tx.QueryRow(ctx, "SELECT iam.change_user_permission_boundary($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10)",
		mutation.AccountID, mutation.ActorPrincipalID, mutation.DecisionID, mutation.UserID, mutation.ResourceVersion, mutation.PolicyID, mutation.PolicyResourceVersion, mutation.BoundaryID, event, mutation.SessionID).Scan(&encoded); err != nil {
		return iamv1.UserPermissionBoundary{}, mapAuthorizationDatabaseError("change IAM user boundary", err)
	}
	result, err := decodeUserPermissionBoundary(encoded, mutation.AccountID, mutation.UserID)
	if err != nil || result.ResourceVersion != mutation.ResourceVersion+1 || (mutation.PolicyID == "") != (result.Policy == nil) ||
		(result.Policy != nil && result.Policy.PolicyID != mutation.PolicyID) {
		return iamv1.UserPermissionBoundary{}, identityaccess.ErrUnavailable
	}
	return result, nil
}

func decodeUserPermissionBoundary(encoded []byte, account iamv1.AccountID, user iamv1.PrincipalID) (iamv1.UserPermissionBoundary, error) {
	defer clear(encoded)
	var result iamv1.UserPermissionBoundary
	if iamv1.DecodeRequest(bytes.NewReader(encoded), &result) != nil || iamv1.ValidateUserPermissionBoundary(result) != nil || result.AccountID != account || result.UserID != user {
		return iamv1.UserPermissionBoundary{}, identityaccess.ErrUnavailable
	}
	return result, nil
}

func normalizeAccount(value *iamv1.Account) {
	value.CreatedAt = value.CreatedAt.UTC()
	value.UpdatedAt = value.UpdatedAt.UTC()
}

func normalizeUser(value *iamv1.User) {
	value.CreatedAt = value.CreatedAt.UTC()
	value.UpdatedAt = value.UpdatedAt.UTC()
}

func normalizeUserAccess(value *iamv1.UserAccess, account iamv1.AccountID) error {
	normalizeUser(&value.User)
	if iamv1.ValidateUser(value.User) != nil || value.User.AccountID != account || value.Capabilities != nil {
		return identityaccess.ErrUnavailable
	}
	attachments := make(map[iamv1.PolicyAttachmentID]bool, len(value.PolicyAttachments))
	policies := make(map[iamv1.PolicyID]bool, len(value.PolicyAttachments))
	for index := range value.PolicyAttachments {
		attachment := &value.PolicyAttachments[index]
		attachment.CreatedAt = attachment.CreatedAt.UTC()
		attachment.UpdatedAt = attachment.UpdatedAt.UTC()
		if iamv1.ValidatePolicyAttachment(*attachment) != nil || attachment.RevokedAt != nil ||
			attachment.AccountID != value.User.AccountID || attachment.Target.Kind != iamv1.PolicyTargetUser ||
			attachment.Target.ID != string(value.User.ID) || attachments[attachment.ID] || policies[attachment.PolicyID] {
			return identityaccess.ErrUnavailable
		}
		attachments[attachment.ID] = true
		policies[attachment.PolicyID] = true
	}
	return nil
}

func (value *transaction) ReadAccount(ctx context.Context, tenant iamv1.AccountID, principal iamv1.PrincipalID) (iamv1.Account, error) {
	var encoded []byte
	if err := value.tx.QueryRow(ctx, "SELECT iam.read_account($1,$2)", tenant, principal).Scan(&encoded); err != nil {
		return iamv1.Account{}, mapSubjectDatabaseError("read IAM account", err)
	}
	return decodeAccount(encoded)
}

func decodeAccount(encoded []byte) (iamv1.Account, error) {
	var result iamv1.Account
	if json.Unmarshal(encoded, &result) != nil {
		return result, identityaccess.ErrUnavailable
	}
	normalizeAccount(&result)
	if iamv1.ValidateAccount(result) != nil {
		return iamv1.Account{}, identityaccess.ErrUnavailable
	}
	return result, nil
}

type accountManagementWire struct {
	Account                      iamv1.Account `json:"account"`
	SystemAccount                *bool         `json:"systemAccount"`
	RootHasInstallationAuthority *bool         `json:"rootHasInstallationAuthority"`
}

func decodeAccountManagement(encoded []byte) (identityaccess.AccountManagementSnapshot, error) {
	var wire accountManagementWire
	if json.Unmarshal(encoded, &wire) != nil || wire.SystemAccount == nil || wire.RootHasInstallationAuthority == nil {
		return identityaccess.AccountManagementSnapshot{}, identityaccess.ErrUnavailable
	}
	normalizeAccount(&wire.Account)
	if iamv1.ValidateAccount(wire.Account) != nil {
		return identityaccess.AccountManagementSnapshot{}, identityaccess.ErrUnavailable
	}
	return identityaccess.AccountManagementSnapshot{Account: wire.Account, SystemAccount: *wire.SystemAccount,
		RootHasInstallationAuthority: *wire.RootHasInstallationAuthority}, nil
}

func (value *transaction) ReadAccountAsPlatform(ctx context.Context, read identityaccess.AccountRead, id iamv1.AccountID) (identityaccess.AccountManagementSnapshot, error) {
	var encoded []byte
	if err := value.tx.QueryRow(ctx, "SELECT iam.read_account_as_platform($1,$2,$3,$4)", read.AccountID, read.ActorPrincipalID, read.DecisionID, id).Scan(&encoded); err != nil {
		return identityaccess.AccountManagementSnapshot{}, mapAuthorizationDatabaseError("read IAM account", err)
	}
	result, err := decodeAccountManagement(encoded)
	if err != nil || result.Account.ID != id {
		return identityaccess.AccountManagementSnapshot{}, identityaccess.ErrUnavailable
	}
	return result, nil
}

func (value *transaction) ReadAccountRoot(ctx context.Context, read identityaccess.AccountRead, id iamv1.AccountID) (iamv1.RootIdentity, error) {
	var encoded []byte
	if err := value.tx.QueryRow(ctx, "SELECT iam.read_account_root($1,$2,$3,$4)", read.AccountID, read.ActorPrincipalID, read.DecisionID, id).Scan(&encoded); err != nil {
		return iamv1.RootIdentity{}, mapAuthorizationDatabaseError("read IAM account root", err)
	}
	var result iamv1.RootIdentity
	if json.Unmarshal(encoded, &result) != nil || iamv1.ValidateRootIdentity(result) != nil {
		return iamv1.RootIdentity{}, identityaccess.ErrUnavailable
	}
	return result, nil
}

func (value *transaction) SetAccountStatus(ctx context.Context, mutation identityaccess.AccountStatusMutation) (iamv1.Account, error) {
	event, err := json.Marshal(mutation.AuditEvent)
	if err != nil {
		return iamv1.Account{}, identityaccess.ErrUnavailable
	}
	defer clear(event)
	var encoded []byte
	err = value.tx.QueryRow(ctx, "SELECT iam.set_account_status($1,$2,$3,$4,$5,$6,$7::jsonb)",
		mutation.ActorAccountID, mutation.ActorPrincipalID, mutation.DecisionID, mutation.AccountID,
		mutation.Status, mutation.ResourceVersion, event).Scan(&encoded)
	if err != nil {
		return iamv1.Account{}, mapAuthorizationDatabaseError("set IAM account status", err)
	}
	result, err := decodeAccount(encoded)
	if err != nil || result.ID != mutation.AccountID || result.Status != mutation.Status {
		return iamv1.Account{}, identityaccess.ErrUnavailable
	}
	return result, nil
}

func (value *transaction) RecoverRootCredentials(ctx context.Context, mutation identityaccess.RootCredentialRecovery) (iamv1.Account, error) {
	event, err := json.Marshal(mutation.AuditEvent)
	if err != nil {
		return iamv1.Account{}, identityaccess.ErrUnavailable
	}
	defer clear(event)
	var encoded []byte
	err = value.tx.QueryRow(ctx, "SELECT iam.recover_root_credentials($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb)",
		mutation.ActorAccountID, mutation.ActorPrincipalID, mutation.DecisionID, mutation.AccountID,
		mutation.PrincipalID, mutation.ResourceVersion, string(mutation.PasswordHash), mutation.AttachmentID, event).Scan(&encoded)
	if err != nil {
		return iamv1.Account{}, mapAuthorizationDatabaseError("recover IAM account root credentials", err)
	}
	result, err := decodeAccount(encoded)
	if err != nil || result.ID != mutation.AccountID || result.RootIdentity.PrincipalID != mutation.PrincipalID {
		return iamv1.Account{}, identityaccess.ErrUnavailable
	}
	return result, nil
}

func (value *transaction) ListUsers(ctx context.Context, read identityaccess.AccountRead) (iamv1.UserList, error) {
	var encoded []byte
	if err := value.tx.QueryRow(ctx, "SELECT iam.list_users($1,$2,$3,$4)", read.AccountID, read.ActorPrincipalID, read.DecisionID, read.After).Scan(&encoded); err != nil {
		return iamv1.UserList{}, mapAuthorizationDatabaseError("list IAM users", err)
	}
	result := iamv1.UserList{APIVersion: iamv1.APIVersion, Kind: "UserList"}
	if json.Unmarshal(encoded, &result.Items) != nil || len(result.Items) > 101 {
		return result, identityaccess.ErrUnavailable
	}
	for i := range result.Items {
		item := &result.Items[i]
		if normalizeUserAccess(item, read.AccountID) != nil || string(item.User.ID) <= read.After ||
			(i > 0 && result.Items[i-1].User.ID >= item.User.ID) {
			return iamv1.UserList{}, identityaccess.ErrUnavailable
		}
	}
	if len(result.Items) > 100 {
		result.Items = result.Items[:100]
		result.NextAfter = string(result.Items[99].User.ID)
	}
	return result, nil
}

func (value *transaction) ReadUser(ctx context.Context, read identityaccess.AccountRead, id iamv1.PrincipalID) (iamv1.UserAccess, error) {
	var encoded []byte
	if err := value.tx.QueryRow(ctx, "SELECT iam.read_user($1,$2,$3,$4)", read.AccountID, read.ActorPrincipalID, read.DecisionID, id).Scan(&encoded); err != nil {
		return iamv1.UserAccess{}, mapAuthorizationDatabaseError("read IAM user", err)
	}
	var result iamv1.UserAccess
	if json.Unmarshal(encoded, &result) != nil || normalizeUserAccess(&result, read.AccountID) != nil || result.User.ID != id {
		return iamv1.UserAccess{}, identityaccess.ErrUnavailable
	}
	return result, nil
}

func decodePolicyDetail(encoded []byte, account iamv1.AccountID, id iamv1.PolicyID) (iamv1.PolicyDetail, error) {
	var result iamv1.PolicyDetail
	if json.Unmarshal(encoded, &result) != nil {
		return iamv1.PolicyDetail{}, identityaccess.ErrUnavailable
	}
	result.Policy.CreatedAt, result.Policy.UpdatedAt = result.Policy.CreatedAt.UTC(), result.Policy.UpdatedAt.UTC()
	if iamv1.ValidatePolicyDetail(result) != nil || result.Policy.ID != id ||
		(result.Policy.AccountID != "" && result.Policy.AccountID != account) {
		return iamv1.PolicyDetail{}, identityaccess.ErrUnavailable
	}
	return result, nil
}

func (value *transaction) ReadPolicy(ctx context.Context, read identityaccess.AccountRead, id iamv1.PolicyID) (iamv1.PolicyDetail, error) {
	var encoded []byte
	if err := value.tx.QueryRow(ctx, "SELECT iam.read_policy($1,$2,$3,$4)", read.AccountID, read.ActorPrincipalID, read.DecisionID, id).Scan(&encoded); err != nil {
		return iamv1.PolicyDetail{}, mapAuthorizationDatabaseError("read IAM policy", err)
	}
	return decodePolicyDetail(encoded, read.AccountID, id)
}

func (value *transaction) CreatePolicy(ctx context.Context, mutation identityaccess.PolicyCreation) (iamv1.PolicyDetail, error) {
	if iamv1.ValidatePolicy(mutation.Policy) != nil || mutation.Policy.Management != iamv1.PolicyCustomerManaged ||
		iamv1.ValidatePolicyVersion(mutation.Version) != nil || mutation.Version.PolicyID != mutation.Policy.ID ||
		mutation.Version.ID != mutation.Policy.DefaultVersionID || mutation.Version.Document.Scope != mutation.Policy.Scope {
		return iamv1.PolicyDetail{}, identityaccess.ErrInvalidArgument
	}
	canonical, digest, err := iamv1.CanonicalizePolicyDocument(mutation.Version.Document)
	if err != nil || digest != mutation.Version.ContentDigest {
		return iamv1.PolicyDetail{}, identityaccess.ErrInvalidArgument
	}
	if auditv1.ValidateEventForSource(auditv1.SourceIAM, mutation.AuditEvent) != nil {
		return iamv1.PolicyDetail{}, identityaccess.ErrInvalidArgument
	}
	event, err := json.Marshal(mutation.AuditEvent)
	if err != nil {
		return iamv1.PolicyDetail{}, identityaccess.ErrUnavailable
	}
	defer clear(event)
	var encoded []byte
	err = value.tx.QueryRow(ctx, "SELECT iam.create_policy($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb)",
		mutation.Policy.AccountID, mutation.ActorPrincipalID, mutation.DecisionID, mutation.Policy.ID,
		mutation.Policy.DisplayName, mutation.Version.ID, canonical, digest, event).Scan(&encoded)
	if err != nil {
		return iamv1.PolicyDetail{}, mapAuthorizationDatabaseError("create IAM policy", err)
	}
	return decodePolicyDetail(encoded, mutation.Policy.AccountID, mutation.Policy.ID)
}

func decodePolicyVersionDetail(encoded []byte, account iamv1.AccountID, policy iamv1.PolicyID, version iamv1.PolicyVersionID) (iamv1.PolicyVersionDetail, error) {
	var result iamv1.PolicyVersionDetail
	if json.Unmarshal(encoded, &result) != nil {
		return result, identityaccess.ErrUnavailable
	}
	result.Policy.CreatedAt, result.Policy.UpdatedAt = result.Policy.CreatedAt.UTC(), result.Policy.UpdatedAt.UTC()
	if iamv1.ValidatePolicyVersionDetail(result) != nil || result.Policy.AccountID != account || result.Policy.ID != policy || result.Version.ID != version {
		return iamv1.PolicyVersionDetail{}, identityaccess.ErrUnavailable
	}
	return result, nil
}

func (value *transaction) ListPolicyVersions(ctx context.Context, read identityaccess.AccountRead, id iamv1.PolicyID) (iamv1.PolicyVersionList, error) {
	var encoded []byte
	if err := value.tx.QueryRow(ctx, "SELECT iam.list_policy_versions($1,$2,$3,$4)", read.AccountID, read.ActorPrincipalID, read.DecisionID, id).Scan(&encoded); err != nil {
		return iamv1.PolicyVersionList{}, mapAuthorizationDatabaseError("list IAM policy versions", err)
	}
	var result iamv1.PolicyVersionList
	if json.Unmarshal(encoded, &result) != nil {
		return result, identityaccess.ErrUnavailable
	}
	result.Policy.CreatedAt, result.Policy.UpdatedAt = result.Policy.CreatedAt.UTC(), result.Policy.UpdatedAt.UTC()
	if iamv1.ValidatePolicyVersionList(result) != nil || result.Policy.ID != id || result.Policy.AccountID != read.AccountID {
		return iamv1.PolicyVersionList{}, identityaccess.ErrUnavailable
	}
	return result, nil
}

func (value *transaction) ReadPolicyVersion(ctx context.Context, read identityaccess.AccountRead, id iamv1.PolicyID, version iamv1.PolicyVersionID) (iamv1.PolicyVersionDetail, error) {
	var encoded []byte
	if err := value.tx.QueryRow(ctx, "SELECT iam.read_policy_version($1,$2,$3,$4,$5)", read.AccountID, read.ActorPrincipalID, read.DecisionID, id, version).Scan(&encoded); err != nil {
		return iamv1.PolicyVersionDetail{}, mapAuthorizationDatabaseError("read IAM policy version", err)
	}
	return decodePolicyVersionDetail(encoded, read.AccountID, id, version)
}

func (value *transaction) CreatePolicyVersion(ctx context.Context, mutation identityaccess.PolicyVersionCreation) (iamv1.PolicyVersionDetail, error) {
	canonical, digest, err := iamv1.CanonicalizePolicyDocument(mutation.Version.Document)
	if err != nil || digest != mutation.Version.ContentDigest || iamv1.ValidatePolicyVersion(mutation.Version) != nil ||
		iamv1.ValidateCreatePolicyVersionRequest(iamv1.CreatePolicyVersionRequest{Document: mutation.Version.Document, ResourceVersion: mutation.ResourceVersion, RequestID: mutation.AuditEvent.RequestID}) != nil ||
		auditv1.ValidateEventForSource(auditv1.SourceIAM, mutation.AuditEvent) != nil {
		return iamv1.PolicyVersionDetail{}, identityaccess.ErrInvalidArgument
	}
	event, err := json.Marshal(mutation.AuditEvent)
	if err != nil {
		return iamv1.PolicyVersionDetail{}, identityaccess.ErrUnavailable
	}
	defer clear(event)
	var encoded []byte
	err = value.tx.QueryRow(ctx, "SELECT iam.create_policy_version($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb)",
		mutation.AccountID, mutation.ActorPrincipalID, mutation.DecisionID, mutation.Version.PolicyID, mutation.ResourceVersion, mutation.Version.ID, canonical, digest, event).Scan(&encoded)
	if err != nil {
		return iamv1.PolicyVersionDetail{}, mapAuthorizationDatabaseError("create IAM policy version", err)
	}
	return decodePolicyVersionDetail(encoded, mutation.AccountID, mutation.Version.PolicyID, mutation.Version.ID)
}

func (value *transaction) DeletePolicyVersion(ctx context.Context, mutation identityaccess.PolicyVersionDeletion) (iamv1.PolicyDetail, error) {
	if iamv1.ValidateDeletePolicyVersionRequest(iamv1.DeletePolicyVersionRequest{ResourceVersion: mutation.ResourceVersion, RequestID: mutation.AuditEvent.RequestID}) != nil || auditv1.ValidateEventForSource(auditv1.SourceIAM, mutation.AuditEvent) != nil {
		return iamv1.PolicyDetail{}, identityaccess.ErrInvalidArgument
	}
	event, err := json.Marshal(mutation.AuditEvent)
	if err != nil {
		return iamv1.PolicyDetail{}, identityaccess.ErrUnavailable
	}
	defer clear(event)
	var encoded []byte
	err = value.tx.QueryRow(ctx, "SELECT iam.delete_policy_version($1,$2,$3,$4,$5,$6,$7::jsonb)", mutation.AccountID, mutation.ActorPrincipalID, mutation.DecisionID, mutation.PolicyID, mutation.VersionID, mutation.ResourceVersion, event).Scan(&encoded)
	if err != nil {
		return iamv1.PolicyDetail{}, mapAuthorizationDatabaseError("delete IAM policy version", err)
	}
	result, err := decodePolicyDetail(encoded, mutation.AccountID, mutation.PolicyID)
	if err != nil || result.Policy.ResourceVersion != mutation.ResourceVersion+1 || result.Policy.DefaultVersionID == mutation.VersionID {
		return iamv1.PolicyDetail{}, identityaccess.ErrUnavailable
	}
	return result, nil
}

func (value *transaction) SetDefaultPolicyVersion(ctx context.Context, mutation identityaccess.PolicyDefaultSelection) (iamv1.PolicyDetail, error) {
	if iamv1.ValidateSetDefaultPolicyVersionRequest(iamv1.SetDefaultPolicyVersionRequest{VersionID: mutation.VersionID, ResourceVersion: mutation.ResourceVersion, RequestID: mutation.AuditEvent.RequestID}) != nil ||
		auditv1.ValidateEventForSource(auditv1.SourceIAM, mutation.AuditEvent) != nil {
		return iamv1.PolicyDetail{}, identityaccess.ErrInvalidArgument
	}
	event, err := json.Marshal(mutation.AuditEvent)
	if err != nil {
		return iamv1.PolicyDetail{}, identityaccess.ErrUnavailable
	}
	defer clear(event)
	var encoded []byte
	err = value.tx.QueryRow(ctx, "SELECT iam.set_default_policy_version($1,$2,$3,$4,$5,$6,$7::jsonb)",
		mutation.AccountID, mutation.ActorPrincipalID, mutation.DecisionID, mutation.PolicyID, mutation.ResourceVersion, mutation.VersionID, event).Scan(&encoded)
	if err != nil {
		return iamv1.PolicyDetail{}, mapAuthorizationDatabaseError("set IAM default policy version", err)
	}
	return decodePolicyDetail(encoded, mutation.AccountID, mutation.PolicyID)
}

func (value *transaction) UpdatePolicy(ctx context.Context, mutation identityaccess.PolicyUpdate) (iamv1.PolicyDetail, error) {
	if iamv1.ValidateUpdatePolicyRequest(iamv1.UpdatePolicyRequest{DisplayName: mutation.DisplayName, ResourceVersion: mutation.ResourceVersion, RequestID: mutation.AuditEvent.RequestID}) != nil ||
		auditv1.ValidateEventForSource(auditv1.SourceIAM, mutation.AuditEvent) != nil {
		return iamv1.PolicyDetail{}, identityaccess.ErrInvalidArgument
	}
	event, err := json.Marshal(mutation.AuditEvent)
	if err != nil {
		return iamv1.PolicyDetail{}, identityaccess.ErrUnavailable
	}
	defer clear(event)
	var encoded []byte
	err = value.tx.QueryRow(ctx, "SELECT iam.update_policy($1,$2,$3,$4,$5,$6,$7::jsonb)",
		mutation.AccountID, mutation.ActorPrincipalID, mutation.DecisionID, mutation.PolicyID, mutation.ResourceVersion, mutation.DisplayName, event).Scan(&encoded)
	if err != nil {
		return iamv1.PolicyDetail{}, mapAuthorizationDatabaseError("update IAM policy", err)
	}
	return decodePolicyDetail(encoded, mutation.AccountID, mutation.PolicyID)
}

func (value *transaction) DeletePolicy(ctx context.Context, mutation identityaccess.PolicyDeletion) (iamv1.Policy, error) {
	if iamv1.ValidateDeletePolicyRequest(iamv1.DeletePolicyRequest{ResourceVersion: mutation.ResourceVersion, RequestID: mutation.AuditEvent.RequestID}) != nil || auditv1.ValidateEventForSource(auditv1.SourceIAM, mutation.AuditEvent) != nil {
		return iamv1.Policy{}, identityaccess.ErrInvalidArgument
	}
	event, err := json.Marshal(mutation.AuditEvent)
	if err != nil {
		return iamv1.Policy{}, identityaccess.ErrUnavailable
	}
	defer clear(event)
	var encoded []byte
	err = value.tx.QueryRow(ctx, "SELECT iam.delete_policy($1,$2,$3,$4,$5,$6::jsonb)", mutation.AccountID, mutation.ActorPrincipalID, mutation.DecisionID, mutation.PolicyID, mutation.ResourceVersion, event).Scan(&encoded)
	if err != nil {
		return iamv1.Policy{}, mapAuthorizationDatabaseError("delete IAM policy", err)
	}
	var result iamv1.Policy
	if json.Unmarshal(encoded, &result) != nil {
		return result, identityaccess.ErrUnavailable
	}
	result.CreatedAt, result.UpdatedAt = result.CreatedAt.UTC(), result.UpdatedAt.UTC()
	if iamv1.ValidatePolicy(result) != nil || result.ID != mutation.PolicyID || result.AccountID != mutation.AccountID || result.Management != iamv1.PolicyCustomerManaged || result.Status != iamv1.PolicyRetired || result.ResourceVersion != mutation.ResourceVersion+1 {
		return iamv1.Policy{}, identityaccess.ErrUnavailable
	}
	return result, nil
}

func (value *transaction) ListPolicies(ctx context.Context, read identityaccess.AccountRead, scope iamv1.AuthorityScope) (iamv1.PolicyList, error) {
	var encoded []byte
	if err := value.tx.QueryRow(ctx, "SELECT iam.list_policies($1,$2,$3,$4)", read.AccountID, read.ActorPrincipalID, read.DecisionID, scope).Scan(&encoded); err != nil {
		return iamv1.PolicyList{}, mapAuthorizationDatabaseError("list IAM policies", err)
	}
	var result iamv1.PolicyList
	if json.Unmarshal(encoded, &result) != nil {
		return iamv1.PolicyList{}, identityaccess.ErrUnavailable
	}
	for index := range result.Items {
		result.Items[index].CreatedAt = result.Items[index].CreatedAt.UTC()
		result.Items[index].UpdatedAt = result.Items[index].UpdatedAt.UTC()
	}
	if iamv1.ValidatePolicyList(result) != nil || result.AccountID != read.AccountID || result.Scope != scope {
		return iamv1.PolicyList{}, identityaccess.ErrUnavailable
	}
	return result, nil
}

func (value *transaction) ListAccounts(ctx context.Context, read identityaccess.AccountRead) (identityaccess.AccountManagementPage, error) {
	var encoded []byte
	if err := value.tx.QueryRow(ctx, "SELECT iam.list_accounts($1,$2,$3,$4)", read.AccountID, read.ActorPrincipalID, read.DecisionID, read.After).Scan(&encoded); err != nil {
		return identityaccess.AccountManagementPage{}, mapAuthorizationDatabaseError("list IAM accounts", err)
	}
	var rows []json.RawMessage
	if json.Unmarshal(encoded, &rows) != nil || len(rows) > 101 {
		return identityaccess.AccountManagementPage{}, identityaccess.ErrUnavailable
	}
	result := identityaccess.AccountManagementPage{Items: make([]identityaccess.AccountManagementSnapshot, 0, len(rows))}
	for _, row := range rows {
		item, err := decodeAccountManagement(row)
		if err != nil || string(item.Account.ID) <= read.After ||
			(len(result.Items) > 0 && result.Items[len(result.Items)-1].Account.ID >= item.Account.ID) {
			return identityaccess.AccountManagementPage{}, identityaccess.ErrUnavailable
		}
		result.Items = append(result.Items, item)
	}
	if len(result.Items) > 100 {
		result.Items = result.Items[:100]
		result.NextAfter = string(result.Items[99].Account.ID)
	}
	return result, nil
}

func (value *transaction) CreateAccount(ctx context.Context, mutation identityaccess.AccountMutation) (iamv1.Account, error) {
	event, err := json.Marshal(mutation.AuditEvent)
	if err != nil {
		return iamv1.Account{}, identityaccess.ErrUnavailable
	}
	defer clear(event)
	var encoded []byte
	err = value.tx.QueryRow(ctx, `SELECT iam.create_account($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb)`,
		mutation.ActorAccountID, mutation.ActorPrincipalID, mutation.DecisionID,
		mutation.Account.ID, mutation.Account.DisplayName, mutation.Root.ID,
		mutation.Root.LoginName, mutation.Root.DisplayName, string(mutation.Root.PasswordHash), event).Scan(&encoded)
	if err != nil {
		return iamv1.Account{}, mapAuthorizationDatabaseError("create IAM account", err)
	}
	return decodeAccount(encoded)
}

func (value *transaction) SetAccountAlias(ctx context.Context, mutation identityaccess.AccountAliasMutation) (iamv1.Account, error) {
	event, err := json.Marshal(mutation.AuditEvent)
	if err != nil {
		return iamv1.Account{}, identityaccess.ErrUnavailable
	}
	defer clear(event)
	var encoded []byte
	err = value.tx.QueryRow(ctx, `SELECT iam.set_account_alias($1,$2,$3,$4,$5,$6::jsonb)`,
		mutation.AccountID, mutation.ActorPrincipalID, mutation.DecisionID, mutation.Alias, mutation.ResourceVersion, event).Scan(&encoded)
	if err != nil {
		return iamv1.Account{}, mapAuthorizationDatabaseError("set IAM account alias", err)
	}
	return decodeAccount(encoded)
}

func (value *transaction) UpdateUser(ctx context.Context, mutation identityaccess.UserProfileMutation) (iamv1.User, error) {
	event, err := json.Marshal(mutation.AuditEvent)
	if err != nil {
		return iamv1.User{}, identityaccess.ErrUnavailable
	}
	defer clear(event)
	var encoded []byte
	err = value.tx.QueryRow(ctx, `SELECT iam.update_user($1,$2,$3,$4,$5,$6,$7::jsonb)`,
		mutation.AccountID, mutation.ActorPrincipalID, mutation.DecisionID, mutation.PrincipalID,
		mutation.DisplayName, mutation.ResourceVersion, event).Scan(&encoded)
	if err != nil {
		return iamv1.User{}, mapAuthorizationDatabaseError("update IAM user", err)
	}
	var result iamv1.User
	if json.Unmarshal(encoded, &result) != nil {
		return iamv1.User{}, identityaccess.ErrUnavailable
	}
	normalizeUser(&result)
	if iamv1.ValidateUser(result) != nil || result.AccountID != mutation.AccountID || result.ID != mutation.PrincipalID ||
		result.DisplayName != mutation.DisplayName || result.ResourceVersion != mutation.ResourceVersion+1 {
		return iamv1.User{}, identityaccess.ErrUnavailable
	}
	return result, nil
}

func (value *transaction) DeleteUser(ctx context.Context, mutation identityaccess.UserDeletionMutation) (iamv1.UserDeletion, error) {
	event, err := json.Marshal(mutation.AuditEvent)
	if err != nil {
		return iamv1.UserDeletion{}, identityaccess.ErrUnavailable
	}
	defer clear(event)
	var encoded []byte
	err = value.tx.QueryRow(ctx, `SELECT iam.delete_user($1,$2,$3,$4,$5,$6::jsonb)`,
		mutation.AccountID, mutation.ActorPrincipalID, mutation.DecisionID, mutation.PrincipalID,
		mutation.ResourceVersion, event).Scan(&encoded)
	if err != nil {
		return iamv1.UserDeletion{}, mapAuthorizationDatabaseError("delete IAM user", err)
	}
	var result iamv1.UserDeletion
	if json.Unmarshal(encoded, &result) != nil {
		return iamv1.UserDeletion{}, identityaccess.ErrUnavailable
	}
	result.DeletedAt = result.DeletedAt.UTC()
	if iamv1.ValidateUserDeletion(result) != nil || result.AccountID != mutation.AccountID ||
		result.ID != mutation.PrincipalID || result.ResourceVersion != mutation.ResourceVersion+1 {
		return iamv1.UserDeletion{}, identityaccess.ErrUnavailable
	}
	return result, nil
}

func (value *transaction) ChangeUser(ctx context.Context, mutation identityaccess.UserChange) (iamv1.User, error) {
	event, err := json.Marshal(mutation.AuditEvent)
	if err != nil {
		return iamv1.User{}, identityaccess.ErrUnavailable
	}
	defer clear(event)
	var encoded []byte
	var status, hash any
	if mutation.Status != nil {
		status = string(*mutation.Status)
	}
	if mutation.PasswordHash != nil {
		hash = string(*mutation.PasswordHash)
	}
	err = value.tx.QueryRow(ctx, `SELECT iam.change_user($1,$2,$3,$4,$5,$6,$7,$8::jsonb)`,
		mutation.AccountID, mutation.ActorPrincipalID, mutation.DecisionID, mutation.PrincipalID,
		mutation.ResourceVersion, status, hash, event).Scan(&encoded)
	if err != nil {
		return iamv1.User{}, mapAuthorizationDatabaseError("change IAM user", err)
	}
	var result iamv1.User
	if json.Unmarshal(encoded, &result) != nil {
		return result, identityaccess.ErrUnavailable
	}
	normalizeUser(&result)
	if iamv1.ValidateUser(result) != nil || result.AccountID != mutation.AccountID || result.ID != mutation.PrincipalID {
		return iamv1.User{}, identityaccess.ErrUnavailable
	}
	return result, nil
}
