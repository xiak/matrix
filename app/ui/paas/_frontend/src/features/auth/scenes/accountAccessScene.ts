import type { Account, AccountIdentity, AccountUser, DirectoryPage, UserRole } from "../domain/accounts";

export const roleLabels: Record<UserRole, string> = {
  ORGANIZATION_ADMIN: "租户管理员", PAAS_DEVELOPER: "服务开发者", PAAS_VIEWER: "只读用户", AUDIT_READER: "审计只读"
};

export const roleDescriptions: Record<UserRole, string> = {
  ORGANIZATION_ADMIN: "管理本租户的用户、授权、别名、PaaS 资源与审计记录；不能开通新租户或访问其他租户资源。",
  PAAS_DEVELOPER: "查看本租户的 PaaS 资源，激活配额、创建服务实例，以及管理应用部署；不能管理账号或授权。",
  PAAS_VIEWER: "只读查看本租户的 PaaS 资源、配额与运行状态；不能创建或修改资源。",
  AUDIT_READER: "读取和校验本租户的审计记录；不会同时获得 PaaS 资源或用户管理权限。"
};

export function buildAccountAccessScene(identity: AccountIdentity, users: DirectoryPage<AccountUser> | null, accounts: DirectoryPage<Account> | null) {
  const account = identity.account;
  return {
    accountId: account.organization.id,
    accountName: account.organization.displayName,
    accountVersion: account.organization.resourceVersion,
    loginAlias: account.loginAlias,
    primaryLoginName: account.primaryLoginName,
    identityLabel: identity.principal.displayName,
    isPrimary: identity.principal.id === account.primaryPrincipalId,
    roles: identity.roles.map((role) => roleLabels[role]),
    canManage: !identity.principal.mustChangePassword && identity.roles.includes("ORGANIZATION_ADMIN"),
    canCreateOrganizations: identity.canCreateOrganizations,
    users: users?.items.filter(({ principal }) => principal.id !== account.primaryPrincipalId).map(({ principal, roleBindings }) => ({
      id: principal.id, name: principal.displayName, loginName: principal.loginName,
      qualifiedName: `${principal.loginName}@${account.loginAlias ?? account.organization.id}`,
      protected: principal.id === identity.principal.id,
      enabled: principal.status === "ACTIVE", resourceVersion: principal.resourceVersion,
      statusLabel: principal.status === "DISABLED" ? "已禁用" : principal.mustChangePassword ? "待修改初始密码" : "正常",
      bindings: roleBindings.map((binding) => ({ ...binding, label: roleLabels[binding.role] }))
    })) ?? [],
    nextUserPage: users?.nextAfter ?? null,
    accounts: accounts?.items.map((entry) => ({ id: entry.organization.id, name: entry.organization.displayName, loginAlias: entry.loginAlias, primaryLoginName: entry.primaryLoginName })) ?? [],
    nextAccountPage: accounts?.nextAfter ?? null
  };
}

export type AccountAccessScene = ReturnType<typeof buildAccountAccessScene>;
export type AccountUserScene = AccountAccessScene["users"][number];
