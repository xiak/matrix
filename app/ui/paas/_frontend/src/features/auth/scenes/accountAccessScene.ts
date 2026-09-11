import type { Account, AccountIdentity, AccountUser, DirectoryPage, PolicyDirectory } from "../domain/accounts";

export function buildAccountAccessScene(
  identity: AccountIdentity,
  users: DirectoryPage<AccountUser> | null,
  accounts: DirectoryPage<Account> | null,
  tenantPolicies: PolicyDirectory | null,
  platformPolicies: PolicyDirectory | null
) {
  const account = identity.account;
  const policies = [...(tenantPolicies?.items ?? []), ...(platformPolicies?.items ?? [])];
  if (new Set(policies.map((policy) => policy.id)).size !== policies.length) throw new Error("INVALID_IAM_POLICY_DIRECTORY");
  const byID = new Map(policies.map((policy) => [policy.id, policy]));
  const describeAttachment = (attachment: AccountIdentity["policyAttachments"][number]) => {
    const policy = byID.get(attachment.policyId);
    return {
      ...attachment,
      label: policy?.displayName ?? attachment.policyId,
      policyStatus: policy?.status ?? null,
      policyResourceVersion: policy?.resourceVersion ?? null
    };
  };
  return {
    accountId: account.organization.id,
    accountName: account.organization.displayName,
    accountVersion: account.organization.resourceVersion,
    loginAlias: account.loginAlias,
    primaryLoginName: account.primaryLoginName,
    identityLabel: identity.principal.displayName,
    isPrimary: identity.principal.id === account.primaryPrincipalId,
    identityAttachments: identity.policyAttachments.map(describeAttachment),
    canManage: users !== null,
    canCreateOrganizations: accounts !== null,
    canViewPolicies: tenantPolicies !== null || platformPolicies !== null,
    tenantPoliciesAvailable: tenantPolicies !== null,
    platformPoliciesAvailable: platformPolicies !== null,
    policies: policies.map((policy) => ({
      ...policy,
      ownerLabel: policy.management === "SYSTEM" ? "系统管理" : "本租户管理",
      scopeLabel: policy.scope === "INSTALLATION" ? "平台安装" : "当前租户",
      statusLabel: policy.status === "ACTIVE" ? "可关联" : "已停用"
    })),
    users: users?.items.filter(({ principal }) => principal.id !== account.primaryPrincipalId).map(({ principal, policyAttachments }) => ({
      id: principal.id, name: principal.displayName, loginName: principal.loginName,
      qualifiedName: `${principal.loginName}@${account.loginAlias ?? account.organization.id}`,
      credentialProtection: policyAttachments.some((attachment) => attachment.scope === "INSTALLATION") ? "platform" : principal.id === identity.principal.id ? "self" : null,
      enabled: principal.status === "ACTIVE", resourceVersion: principal.resourceVersion,
      statusLabel: principal.status === "DISABLED" ? "已禁用" : principal.mustChangePassword ? "待修改初始密码" : "正常",
      attachments: policyAttachments.map(describeAttachment)
    })) ?? [],
    nextUserPage: users?.nextAfter ?? null,
    accounts: accounts?.items.map((entry) => ({
      id: entry.organization.id, name: entry.organization.displayName, loginAlias: entry.loginAlias,
      primaryLoginName: entry.primaryLoginName, primaryPrincipalId: entry.primaryPrincipalId,
      enabled: entry.organization.status === "ACTIVE", resourceVersion: entry.organization.resourceVersion
    })) ?? [],
    nextAccountPage: accounts?.nextAfter ?? null
  };
}

export type AccountAccessScene = ReturnType<typeof buildAccountAccessScene>;
export type AccountUserScene = AccountAccessScene["users"][number];
export type TenantAccountScene = AccountAccessScene["accounts"][number];
