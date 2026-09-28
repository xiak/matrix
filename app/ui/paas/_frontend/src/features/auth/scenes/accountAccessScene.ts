import { can, type AccountAccess, type AccountIdentity, type DirectoryPage, type Policy, type UserAccess } from "../domain/accounts";

export function buildAccountAccessScene(identity: AccountIdentity, users: DirectoryPage<UserAccess> | null,
  accounts: DirectoryPage<AccountAccess> | null, policies: Policy[]) {
  const account = identity.account;
  const policyNames = new Map(policies.map((policy) => [policy.id, policy.displayName]));
  const user = identity.user;
  return {
    accountId: account.id,
    accountName: account.displayName,
    accountVersion: account.resourceVersion,
    loginAlias: account.loginAlias,
    primaryLoginName: account.rootIdentity.loginName,
    identityLabel: user.displayName,
    isPrimary: identity.identityKind === "ROOT_IDENTITY",
    authorityLabels: identity.policySources.map(({ attachment }) => policyNames.get(attachment.policyId) ?? attachment.policyId),
    canListUsers: can(identity.capabilities, "iam.user.list", "ACCOUNT", account.id),
    canCreateUsers: can(identity.capabilities, "iam.user.create", "ACCOUNT", account.id),
    canSetAlias: can(identity.capabilities, "iam.account.alias-set", "ACCOUNT", account.id),
    canListAccounts: can(identity.capabilities, "iam.account.read", "ACCOUNT", "collection"),
    canCreateAccounts: can(identity.capabilities, "iam.account.create", "ACCOUNT", "collection"),
    users: users?.items.map(({ user: member, policyAttachments, capabilities }) => ({
      id: member.id, name: member.displayName, loginName: member.loginName,
      qualifiedName: `${member.loginName}@${account.loginAlias ?? account.id}`,
      enabled: member.status === "ACTIVE", resourceVersion: member.resourceVersion,
      statusLabel: member.status === "DISABLED" ? "已禁用" : member.mustChangePassword ? "待修改初始密码" : "正常",
      canSetStatus: can(capabilities, "iam.user.set-status", "USER", member.id),
      canResetPassword: can(capabilities, "iam.user.reset-password", "USER", member.id),
      canAttachPolicy: can(capabilities, "iam.policy-attachment.create", "USER", member.id),
      attachments: policyAttachments.map((attachment) => ({
        ...attachment, label: policyNames.get(attachment.policyId) ?? attachment.policyId,
        canRevoke: can(capabilities, attachment.scope === "INSTALLATION" ? "iam.platform-policy-attachment.revoke" :
          "iam.policy-attachment.revoke", "POLICY_ATTACHMENT", attachment.id)
      }))
    })) ?? [],
    nextUserPage: users?.nextAfter ?? null,
    accounts: accounts?.items.map(({ account: entry, capabilities }) => ({
      id: entry.id, name: entry.displayName, loginAlias: entry.loginAlias,
      primaryLoginName: entry.rootIdentity.loginName, primaryPrincipalId: entry.rootIdentity.principalId,
      enabled: entry.status === "ACTIVE", resourceVersion: entry.resourceVersion,
      canSetStatus: can(capabilities, "iam.account.set-status", "ACCOUNT", entry.id),
      canRecoverRoot: can(capabilities, "iam.account.recover-root-credentials", "ACCOUNT", entry.id)
    })) ?? [],
    nextAccountPage: accounts?.nextAfter ?? null,
    policies
  };
}

export type AccountAccessScene = ReturnType<typeof buildAccountAccessScene>;
export type AccountUserScene = AccountAccessScene["users"][number];
export type TenantAccountScene = AccountAccessScene["accounts"][number];
