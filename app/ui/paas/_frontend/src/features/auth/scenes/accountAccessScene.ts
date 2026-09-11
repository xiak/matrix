import type { AccountAccess, AccountIdentity, ActionCapability, DirectoryPage, IamAction, PolicyDirectory, UserAccess } from "../domain/accounts";

export function findActionCapability(
  capabilities: ActionCapability[], action: IamAction, kind: ActionCapability["resource"]["kind"], id: string
): ActionCapability | null {
  return capabilities.find((item) => item.action === action && item.resource.kind === kind && item.resource.id === id) ?? null;
}

export function buildAccountAccessScene(
  identity: AccountIdentity,
  users: DirectoryPage<UserAccess> | null,
  accounts: DirectoryPage<AccountAccess> | null,
  tenantPolicies: PolicyDirectory | null,
  platformPolicies: PolicyDirectory | null
) {
  const account = identity.account;
  const policies = [...(tenantPolicies?.items ?? []), ...(platformPolicies?.items ?? [])];
  if (new Set(policies.map((policy) => policy.id)).size !== policies.length) throw new Error("INVALID_IAM_POLICY_DIRECTORY");
  const byID = new Map(policies.map((policy) => [policy.id, policy]));
  const identityCapability = (action: IamAction, id = account.id) =>
    findActionCapability(identity.capabilities, action, "ACCOUNT", id);
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
    canManage: identityCapability("iam.user.list")?.available === true && users !== null,
    canCreateUsers: identityCapability("iam.user.create")?.available === true,
    canSetAlias: identityCapability("iam.account.alias-set")?.available === true,
    canReadAccounts: identityCapability("iam.account.read", "accounts")?.available === true && accounts !== null,
    canCreateAccounts: identityCapability("iam.account.create", "accounts")?.available === true,
    canViewPolicies: tenantPolicies !== null || platformPolicies !== null,
    tenantPoliciesAvailable: tenantPolicies !== null,
    platformPoliciesAvailable: platformPolicies !== null,
    policies: policies.map((policy) => ({
      ...policy,
      ownerLabel: policy.management === "SYSTEM" ? "系统管理" : "本租户管理",
      scopeLabel: policy.scope === "INSTALLATION" ? "平台安装" : "当前租户",
      statusLabel: policy.status === "ACTIVE" ? "可关联" : "已停用"
    })),
    users: users?.items.map(({ user, policyAttachments, capabilities }) => {
      const userCapability = (action: IamAction) => findActionCapability(capabilities, action, "USER", user.id);
      const statusCapability = userCapability("iam.user.set-status");
      const resetCapability = userCapability("iam.user.reset-password");
      const tenantAttachCapability = userCapability("iam.policy-attachment.create");
      const platformAttachCapability = userCapability("iam.platform-policy-attachment.create");
      return {
      id: user.id, name: user.displayName, loginName: user.loginName,
      qualifiedName: `${user.loginName}@${account.loginAlias ?? account.id}`,
      enabled: user.status === "ACTIVE", resourceVersion: user.resourceVersion,
      statusLabel: user.status === "DISABLED" ? "已禁用" : user.mustChangePassword ? "待修改初始密码" : "正常",
      canSetStatus: statusCapability?.available === true,
      statusRestrictionReason: statusCapability?.restrictionReason ?? null,
      canResetPassword: resetCapability?.available === true,
      passwordRestrictionReason: resetCapability?.restrictionReason ?? null,
      canAttachTenantPolicy: tenantAttachCapability?.available === true,
      tenantAttachmentRestrictionReason: tenantAttachCapability?.restrictionReason ?? null,
      canAttachPlatformPolicy: platformAttachCapability?.available === true,
      platformAttachmentRestrictionReason: platformAttachCapability?.restrictionReason ?? null,
      attachments: policyAttachments.map((attachment) => {
        const action = attachment.scope === "INSTALLATION" ? "iam.platform-policy-attachment.revoke" : "iam.policy-attachment.revoke";
        const revoke = findActionCapability(capabilities, action, "POLICY_ATTACHMENT", attachment.id);
        return { ...describeAttachment(attachment), canRevoke: revoke?.available === true,
          revokeRestrictionReason: revoke?.restrictionReason ?? null };
      })
    }; }) ?? [],
    nextUserPage: users?.nextAfter ?? null,
    accounts: accounts?.items.map(({ account: entry, capabilities }) => ({
      id: entry.id, name: entry.displayName, loginAlias: entry.loginAlias,
      rootLoginName: entry.rootIdentity.loginName, rootPrincipalId: entry.rootIdentity.principalId,
      enabled: entry.status === "ACTIVE", resourceVersion: entry.resourceVersion,
      canSetStatus: findActionCapability(capabilities, "iam.account.set-status", "ACCOUNT", entry.id)?.available === true,
      statusRestrictionReason: findActionCapability(capabilities, "iam.account.set-status", "ACCOUNT", entry.id)?.restrictionReason ?? null,
      canRecoverRoot: findActionCapability(capabilities, "iam.account.recover-root-credentials", "ACCOUNT", entry.id)?.available === true,
      recoveryRestrictionReason: findActionCapability(capabilities, "iam.account.recover-root-credentials", "ACCOUNT", entry.id)?.restrictionReason ?? null
    })) ?? [],
    nextAccountPage: accounts?.nextAfter ?? null
  };
}

export type AccountAccessScene = ReturnType<typeof buildAccountAccessScene>;
export type AccountUserScene = AccountAccessScene["users"][number];
export type TenantAccountScene = AccountAccessScene["accounts"][number];
