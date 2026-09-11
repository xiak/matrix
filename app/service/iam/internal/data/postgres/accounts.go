package postgres

import (
	"context"
	"encoding/json"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/iam/internal/usecase/identityaccess"
)

func normalizeAccount(value *iamv1.Account) {
	value.CreatedAt = value.CreatedAt.UTC()
	value.UpdatedAt = value.UpdatedAt.UTC()
}

func normalizeUser(value *iamv1.User) {
	value.CreatedAt = value.CreatedAt.UTC()
	value.UpdatedAt = value.UpdatedAt.UTC()
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

func (value *transaction) ReadAccountAsPlatform(ctx context.Context, read identityaccess.AccountRead, id iamv1.AccountID) (iamv1.Account, error) {
	var encoded []byte
	if err := value.tx.QueryRow(ctx, "SELECT iam.read_account_as_platform($1,$2,$3,$4)", read.AccountID, read.ActorPrincipalID, read.DecisionID, id).Scan(&encoded); err != nil {
		return iamv1.Account{}, mapAuthorizationDatabaseError("read IAM account", err)
	}
	result, err := decodeAccount(encoded)
	if err != nil || result.ID != id {
		return iamv1.Account{}, identityaccess.ErrUnavailable
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
	if len(result.Items) > 100 {
		result.Items = result.Items[:100]
		result.NextAfter = string(result.Items[99].User.ID)
	}
	for i := range result.Items {
		item := &result.Items[i]
		normalizeUser(&item.User)
		if item.User.AccountID != read.AccountID {
			return iamv1.UserList{}, identityaccess.ErrUnavailable
		}
		for j := range item.PolicyAttachments {
			item.PolicyAttachments[j].CreatedAt = item.PolicyAttachments[j].CreatedAt.UTC()
			item.PolicyAttachments[j].UpdatedAt = item.PolicyAttachments[j].UpdatedAt.UTC()
		}
	}
	if iamv1.ValidateUserList(result) != nil {
		return iamv1.UserList{}, identityaccess.ErrUnavailable
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

func (value *transaction) ListAccounts(ctx context.Context, read identityaccess.AccountRead) (iamv1.AccountList, error) {
	var encoded []byte
	if err := value.tx.QueryRow(ctx, "SELECT iam.list_accounts($1,$2,$3,$4)", read.AccountID, read.ActorPrincipalID, read.DecisionID, read.After).Scan(&encoded); err != nil {
		return iamv1.AccountList{}, mapAuthorizationDatabaseError("list IAM accounts", err)
	}
	result := iamv1.AccountList{APIVersion: iamv1.APIVersion, Kind: "AccountList"}
	if json.Unmarshal(encoded, &result.Items) != nil || len(result.Items) > 101 {
		return result, identityaccess.ErrUnavailable
	}
	if len(result.Items) > 100 {
		result.Items = result.Items[:100]
		result.NextAfter = string(result.Items[99].ID)
	}
	for i := range result.Items {
		normalizeAccount(&result.Items[i])
	}
	if iamv1.ValidateAccountList(result) != nil {
		return iamv1.AccountList{}, identityaccess.ErrUnavailable
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
