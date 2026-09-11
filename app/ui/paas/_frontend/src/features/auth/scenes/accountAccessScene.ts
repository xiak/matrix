import type {
  AccountAccess,
  AccountIdentity,
  ActionCapability,
  CapabilityRestriction,
  DirectoryPage,
  IamAction,
  PolicyDirectory,
  UserAccess,
  UserPolicyAttachment
} from "../domain/accounts";

export function findActionCapability(
  capabilities: ActionCapability[],
  action: IamAction,
  kind: ActionCapability["resource"]["kind"],
  id: string
): ActionCapability | null {
  return capabilities.find((item) => item.action === action && item.resource.kind === kind && item.resource.id === id) ?? null;
}

function credentialProtection(...reasons: Array<CapabilityRestriction | null>): "platform" | "self" | null {
  if (reasons.includes("INSTALLATION_AUTHORITY_PROTECTED")) return "platform";
  if (reasons.includes("SELF_PROTECTED")) return "self";
  return null;
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
  const policyById = new Map(policies.map((policy) => [policy.id, policy]));
  const identityCapability = (action: IamAction, id = account.id) =>
    findActionCapability(identity.capabilities, action, "ACCOUNT", id);
  const describeAttachment = (attachment: UserPolicyAttachment) => {
    const policy = policyById.get(attachment.policyId);
    return {
      ...attachment,
      label: policy?.displayName ?? attachment.policyId,
      policyStatus: policy?.status ?? null,
      policyResourceVersion: policy?.resourceVersion ?? null
    };
  };
  const rootIsCurrent = identity.identityKind === "ROOT_IDENTITY";

  return {
    accountId: account.id,
    accountName: account.displayName,
    accountVersion: account.resourceVersion,
    accountEnabled: account.status === "ACTIVE",
    loginAlias: account.loginAlias,
    rootLoginName: account.rootIdentity.loginName,
    identityLabel: identity.user.displayName,
    currentUserId: identity.user.id,
    currentLoginName: identity.user.loginName,
    identityKind: identity.identityKind,
    isRoot: rootIsCurrent,
    identityAttachments: identity.policyAttachments.map(describeAttachment),
    canListUsers: identityCapability("iam.user.list")?.available === true && users !== null,
    canCreateUsers: identityCapability("iam.user.create")?.available === true,
    createUsersRestrictionReason: identityCapability("iam.user.create")?.restrictionReason ?? null,
    canSetAlias: identityCapability("iam.account.alias-set")?.available === true,
    setAliasRestrictionReason: identityCapability("iam.account.alias-set")?.restrictionReason ?? null,
    canReadAccounts: identityCapability("iam.account.read", "accounts")?.available === true && accounts !== null,
    canCreateAccounts: identityCapability("iam.account.create", "accounts")?.available === true,
    createAccountsRestrictionReason: identityCapability("iam.account.create", "accounts")?.restrictionReason ?? null,
    canViewPolicies: (identityCapability("iam.policy.list")?.available === true && tenantPolicies !== null) || platformPolicies !== null,
    tenantPoliciesAvailable: tenantPolicies !== null,
    platformPoliciesAvailable: platformPolicies !== null,
    policies: policies.map((policy) => ({
      ...policy,
      owner: policy.management === "SYSTEM" ? "system" as const : "tenant" as const,
      scopeKind: policy.scope === "INSTALLATION" ? "platform" as const : "tenant" as const,
      available: policy.status === "ACTIVE"
    })),
    accountOwner: {
      id: account.rootIdentity.principalId,
      accountType: "primary" as const,
      loginName: account.rootIdentity.loginName,
      name: rootIsCurrent ? identity.user.displayName : null,
      isCurrent: rootIsCurrent,
      state: rootIsCurrent
        ? identity.user.status === "DISABLED" ? "disabled" as const : identity.user.mustChangePassword ? "passwordChangeRequired" as const : "active" as const
        : null,
      attachments: rootIsCurrent ? identity.policyAttachments.map(describeAttachment) : []
    },
    users: users?.items.map(({ user, policyAttachments, capabilities }) => {
      const userCapability = (action: IamAction) => findActionCapability(capabilities, action, "USER", user.id);
      const statusCapability = userCapability("iam.user.set-status");
      const resetCapability = userCapability("iam.user.reset-password");
      const tenantAttachCapability = userCapability("iam.policy-attachment.create");
      const platformAttachCapability = userCapability("iam.platform-policy-attachment.create");
      const protection = credentialProtection(statusCapability?.restrictionReason ?? null, resetCapability?.restrictionReason ?? null);
      return {
        accountType: "subuser" as const,
        id: user.id,
        name: user.displayName,
        loginName: user.loginName,
        source: "local" as const,
        qualifiedName: `${user.loginName}@${account.loginAlias ?? account.id}`,
        protected: protection !== null,
        credentialProtection: protection,
        enabled: user.status === "ACTIVE",
        resourceVersion: user.resourceVersion,
        state: user.status === "DISABLED" ? "disabled" as const : user.mustChangePassword ? "passwordChangeRequired" as const : "active" as const,
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
          return {
            ...describeAttachment(attachment),
            canRevoke: revoke?.available === true,
            revokeRestrictionReason: revoke?.restrictionReason ?? null
          };
        })
      };
    }) ?? [],
    nextUserPage: users?.nextAfter ?? null,
    directoryComplete: users !== null && !users.nextAfter,
    accounts: accounts?.items.map(({ account: entry, capabilities }) => ({
      id: entry.id,
      name: entry.displayName,
      loginAlias: entry.loginAlias,
      rootLoginName: entry.rootIdentity.loginName,
      rootPrincipalId: entry.rootIdentity.principalId,
      enabled: entry.status === "ACTIVE",
      resourceVersion: entry.resourceVersion,
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
export type AccountTenantScene = AccountAccessScene["accounts"][number];
export type TenantAccountScene = AccountAccessScene["accounts"][number];
