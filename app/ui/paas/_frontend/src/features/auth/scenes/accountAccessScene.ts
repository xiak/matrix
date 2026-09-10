import type { Account, AccountIdentity, AccountUser, DirectoryPage } from "../domain/accounts";

export function buildAccountAccessScene(identity: AccountIdentity, users: DirectoryPage<AccountUser> | null, accounts: DirectoryPage<Account> | null) {
  const account = identity.account;
  const primary = identity.principal.id === account.primaryPrincipalId ? identity.principal :
    users?.items.find(({ principal }) => principal.id === account.primaryPrincipalId)?.principal;
  return {
    accountId: account.organization.id,
    accountName: account.organization.displayName,
    accountVersion: account.organization.resourceVersion,
    loginAlias: account.loginAlias,
    primaryLoginName: account.primaryLoginName,
    identityLabel: identity.principal.displayName,
    principalId: identity.principal.id,
    loginName: identity.principal.loginName,
    isPrimary: identity.principal.id === account.primaryPrincipalId,
    roles: identity.roles,
    canManage: !identity.principal.mustChangePassword && identity.roles.includes("ORGANIZATION_ADMIN"),
    canCreateOrganizations: identity.canCreateOrganizations,
    // Owner metadata is separate from child grant/key/copy targets. Group
    // membership explicitly combines the owner with the child directory.
    primaryUser: {
      id: account.primaryPrincipalId, accountType: "primary" as const,
      loginName: account.primaryLoginName, name: primary?.displayName ?? null,
      isCurrent: identity.principal.id === account.primaryPrincipalId,
      state: primary ? primary.status === "DISABLED" ? "disabled" as const : primary.mustChangePassword ? "passwordChangeRequired" as const : "active" as const : null
    },
    users: users?.items.filter(({ principal }) => principal.id !== account.primaryPrincipalId).map(({ principal, roleBindings }) => ({
      accountType: "subuser" as const,
      id: principal.id, name: principal.displayName, loginName: principal.loginName,
      source: principal.source ?? "local",
      qualifiedName: `${principal.loginName}@${account.loginAlias ?? account.organization.id}`,
      protected: principal.id === identity.principal.id,
      enabled: principal.status === "ACTIVE", resourceVersion: principal.resourceVersion,
      state: principal.status === "DISABLED" ? "disabled" as const : principal.mustChangePassword ? "passwordChangeRequired" as const : "active" as const,
      bindings: roleBindings
    })) ?? [],
    nextUserPage: users?.nextAfter ?? null,
    directoryComplete: !users?.nextAfter,
    accounts: accounts?.items.map((entry) => ({ id: entry.organization.id, name: entry.organization.displayName, loginAlias: entry.loginAlias, primaryLoginName: entry.primaryLoginName })) ?? [],
    nextAccountPage: accounts?.nextAfter ?? null
  };
}

export type AccountAccessScene = ReturnType<typeof buildAccountAccessScene>;
export type AccountUserScene = AccountAccessScene["users"][number];
