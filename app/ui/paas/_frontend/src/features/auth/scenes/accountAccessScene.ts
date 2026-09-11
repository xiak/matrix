import type { Account, AccountIdentity, DirectoryPage, PolicyDirectory, UserAccess } from "../domain/accounts";

export function buildAccountAccessScene(
  identity: AccountIdentity,
  users: DirectoryPage<UserAccess> | null,
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
    accountId: account.id,
    accountName: account.displayName,
    accountVersion: account.resourceVersion,
    loginAlias: account.loginAlias,
    rootLoginName: account.rootIdentity.loginName,
    identityLabel: identity.user.displayName,
    isRoot: identity.identityKind === "ROOT_IDENTITY",
    identityAttachments: identity.policyAttachments.map(describeAttachment),
    canManage: users !== null,
    canCreateAccounts: accounts !== null,
    canViewPolicies: tenantPolicies !== null || platformPolicies !== null,
    tenantPoliciesAvailable: tenantPolicies !== null,
    platformPoliciesAvailable: platformPolicies !== null,
    policies: policies.map((policy) => ({
      ...policy,
      ownerLabel: policy.management === "SYSTEM" ? "系统管理" : "本租户管理",
      scopeLabel: policy.scope === "INSTALLATION" ? "平台安装" : "当前租户",
      statusLabel: policy.status === "ACTIVE" ? "可关联" : "已停用"
    })),
    users: users?.items.map(({ user, policyAttachments }) => ({
      id: user.id, name: user.displayName, loginName: user.loginName,
      qualifiedName: `${user.loginName}@${account.loginAlias ?? account.id}`,
      credentialProtection: policyAttachments.some((attachment) => attachment.scope === "INSTALLATION") ? "platform" : user.id === identity.user.id ? "self" : null,
      enabled: user.status === "ACTIVE", resourceVersion: user.resourceVersion,
      statusLabel: user.status === "DISABLED" ? "已禁用" : user.mustChangePassword ? "待修改初始密码" : "正常",
      attachments: policyAttachments.map(describeAttachment)
    })) ?? [],
    nextUserPage: users?.nextAfter ?? null,
    accounts: accounts?.items.map((entry) => ({
      id: entry.id, name: entry.displayName, loginAlias: entry.loginAlias,
      rootLoginName: entry.rootIdentity.loginName, rootPrincipalId: entry.rootIdentity.principalId,
      enabled: entry.status === "ACTIVE", resourceVersion: entry.resourceVersion
    })) ?? [],
    nextAccountPage: accounts?.nextAfter ?? null
  };
}

export type AccountAccessScene = ReturnType<typeof buildAccountAccessScene>;
export type AccountUserScene = AccountAccessScene["users"][number];
export type TenantAccountScene = AccountAccessScene["accounts"][number];
