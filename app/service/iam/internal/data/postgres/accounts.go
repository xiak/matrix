package postgres

import (
	"context"
	"encoding/json"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/iam/internal/usecase/identityaccess"
)

func normalizeAccount(value *iamv1.OrganizationAccount) {
	value.Organization.CreatedAt = value.Organization.CreatedAt.UTC()
	value.Organization.UpdatedAt = value.Organization.UpdatedAt.UTC()
}

func normalizePrincipal(value *iamv1.Principal) {
	value.CreatedAt = value.CreatedAt.UTC()
	value.UpdatedAt = value.UpdatedAt.UTC()
}

func (value *transaction) ReadAccount(ctx context.Context, tenant iamv1.OrganizationID, principal iamv1.PrincipalID) (iamv1.OrganizationAccount, error) {
	var encoded []byte
	if err := value.tx.QueryRow(ctx, "SELECT iam.read_account($1,$2)", tenant, principal).Scan(&encoded); err != nil {
		return iamv1.OrganizationAccount{}, mapSubjectDatabaseError("read IAM account", err)
	}
	return decodeAccount(encoded)
}

func decodeAccount(encoded []byte) (iamv1.OrganizationAccount, error) {
	var result iamv1.OrganizationAccount
	if json.Unmarshal(encoded, &result) != nil {
		return result, identityaccess.ErrUnavailable
	}
	normalizeAccount(&result)
	if iamv1.ValidateOrganizationAccount(result) != nil {
		return iamv1.OrganizationAccount{}, identityaccess.ErrUnavailable
	}
	return result, nil
}

func (value *transaction) ListPrincipals(ctx context.Context, read identityaccess.AccountRead) (iamv1.PrincipalList, error) {
	var encoded []byte
	if err := value.tx.QueryRow(ctx, "SELECT iam.list_principals($1,$2,$3,$4)", read.OrganizationID, read.ActorPrincipalID, read.DecisionID, read.After).Scan(&encoded); err != nil {
		return iamv1.PrincipalList{}, mapAuthorizationDatabaseError("list IAM principals", err)
	}
	result := iamv1.PrincipalList{APIVersion: iamv1.APIVersion, Kind: "PrincipalList"}
	if json.Unmarshal(encoded, &result.Items) != nil || len(result.Items) > 101 {
		return result, identityaccess.ErrUnavailable
	}
	if len(result.Items) > 100 {
		result.Items = result.Items[:100]
		result.NextAfter = string(result.Items[99].Principal.ID)
	}
	for i := range result.Items {
		item := &result.Items[i]
		normalizePrincipal(&item.Principal)
		if item.Principal.OrganizationID != read.OrganizationID {
			return iamv1.PrincipalList{}, identityaccess.ErrUnavailable
		}
		for j := range item.RoleBindings {
			item.RoleBindings[j].CreatedAt = item.RoleBindings[j].CreatedAt.UTC()
			item.RoleBindings[j].UpdatedAt = item.RoleBindings[j].UpdatedAt.UTC()
		}
	}
	if iamv1.ValidatePrincipalList(result) != nil {
		return iamv1.PrincipalList{}, identityaccess.ErrUnavailable
	}
	return result, nil
}

func (value *transaction) ListAccounts(ctx context.Context, read identityaccess.AccountRead) (iamv1.OrganizationAccountList, error) {
	var encoded []byte
	if err := value.tx.QueryRow(ctx, "SELECT iam.list_accounts($1,$2,$3,$4)", read.OrganizationID, read.ActorPrincipalID, read.DecisionID, read.After).Scan(&encoded); err != nil {
		return iamv1.OrganizationAccountList{}, mapAuthorizationDatabaseError("list IAM accounts", err)
	}
	result := iamv1.OrganizationAccountList{APIVersion: iamv1.APIVersion, Kind: "OrganizationAccountList"}
	if json.Unmarshal(encoded, &result.Items) != nil || len(result.Items) > 101 {
		return result, identityaccess.ErrUnavailable
	}
	if len(result.Items) > 100 {
		result.Items = result.Items[:100]
		result.NextAfter = string(result.Items[99].Organization.ID)
	}
	for i := range result.Items {
		normalizeAccount(&result.Items[i])
	}
	if iamv1.ValidateOrganizationAccountList(result) != nil {
		return iamv1.OrganizationAccountList{}, identityaccess.ErrUnavailable
	}
	return result, nil
}

func (value *transaction) CreateOrganization(ctx context.Context, mutation identityaccess.OrganizationMutation) (iamv1.OrganizationAccount, error) {
	event, err := json.Marshal(mutation.AuditEvent)
	if err != nil {
		return iamv1.OrganizationAccount{}, identityaccess.ErrUnavailable
	}
	defer clear(event)
	var encoded []byte
	err = value.tx.QueryRow(ctx, `SELECT iam.create_organization($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb)`,
		mutation.ActorOrganizationID, mutation.ActorPrincipalID, mutation.DecisionID,
		mutation.Organization.ID, mutation.Organization.DisplayName, mutation.Administrator.ID,
		mutation.Administrator.LoginName, mutation.Administrator.DisplayName, string(mutation.Administrator.PasswordHash), event).Scan(&encoded)
	if err != nil {
		return iamv1.OrganizationAccount{}, mapAuthorizationDatabaseError("create IAM organization", err)
	}
	return decodeAccount(encoded)
}

func (value *transaction) SetAccountAlias(ctx context.Context, mutation identityaccess.AccountAliasMutation) (iamv1.OrganizationAccount, error) {
	event, err := json.Marshal(mutation.AuditEvent)
	if err != nil {
		return iamv1.OrganizationAccount{}, identityaccess.ErrUnavailable
	}
	defer clear(event)
	var encoded []byte
	err = value.tx.QueryRow(ctx, `SELECT iam.set_account_alias($1,$2,$3,$4,$5,$6::jsonb)`,
		mutation.OrganizationID, mutation.ActorPrincipalID, mutation.DecisionID, mutation.Alias, mutation.ResourceVersion, event).Scan(&encoded)
	if err != nil {
		return iamv1.OrganizationAccount{}, mapAuthorizationDatabaseError("set IAM account alias", err)
	}
	return decodeAccount(encoded)
}

func (value *transaction) ChangeSubaccount(ctx context.Context, mutation identityaccess.SubaccountMutation) (iamv1.Principal, error) {
	event, err := json.Marshal(mutation.AuditEvent)
	if err != nil {
		return iamv1.Principal{}, identityaccess.ErrUnavailable
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
	err = value.tx.QueryRow(ctx, `SELECT iam.change_subaccount($1,$2,$3,$4,$5,$6,$7,$8::jsonb)`,
		mutation.OrganizationID, mutation.ActorPrincipalID, mutation.DecisionID, mutation.PrincipalID,
		mutation.ResourceVersion, status, hash, event).Scan(&encoded)
	if err != nil {
		return iamv1.Principal{}, mapAuthorizationDatabaseError("change IAM subaccount", err)
	}
	var result iamv1.Principal
	if json.Unmarshal(encoded, &result) != nil {
		return result, identityaccess.ErrUnavailable
	}
	normalizePrincipal(&result)
	if iamv1.ValidatePrincipal(result) != nil || result.OrganizationID != mutation.OrganizationID || result.ID != mutation.PrincipalID {
		return iamv1.Principal{}, identityaccess.ErrUnavailable
	}
	return result, nil
}
