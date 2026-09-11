import type { Account, AccountIdentity, AccountUser, DirectoryPage, PolicyDirectory, UserPolicyAttachment } from "../domain/accounts";

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
  const policyById = new Map(policies.map((policy) => [policy.id, policy]));
  const describeAttachment = (attachment: UserPolicyAttachment) => {
    const policy = policyById.get(attachment.policyId);
    return {
      ...attachment,
      label: policy?.displayName ?? attachment.policyId,
      policyStatus: policy?.status ?? null,
      policyResourceVersion: policy?.resourceVersion ?? null
    };
  };
  const primaryRecord = identity.principal.id === account.primaryPrincipalId
    ? { principal: identity.principal, policyAttachments: identity.policyAttachments }
    : users?.items.find(({ principal }) => principal.id === account.primaryPrincipalId);
  const primary = primaryRecord?.principal;

  return {
    accountId: account.organization.id,
    accountName: account.organization.displayName,
    accountVersion: account.organization.resourceVersion,
    accountEnabled: account.organization.status === "ACTIVE",
    loginAlias: account.loginAlias,
    primaryLoginName: account.primaryLoginName,
    identityLabel: identity.principal.displayName,
    principalId: identity.principal.id,
    loginName: identity.principal.loginName,
    isPrimary: identity.principal.id === account.primaryPrincipalId,
    identityAttachments: identity.policyAttachments.map(describeAttachment),
    canManage: users !== null,
    canCreateOrganizations: accounts !== null,
    canViewPolicies: tenantPolicies !== null || platformPolicies !== null,
    tenantPoliciesAvailable: tenantPolicies !== null,
    platformPoliciesAvailable: platformPolicies !== null,
    policies: policies.map((policy) => ({
      ...policy,
      owner: policy.management === "SYSTEM" ? "system" as const : "tenant" as const,
      scopeKind: policy.scope === "INSTALLATION" ? "platform" as const : "tenant" as const,
      available: policy.status === "ACTIVE"
    })),
    primaryUser: {
      id: account.primaryPrincipalId,
      accountType: "primary" as const,
      loginName: account.primaryLoginName,
      name: primary?.displayName ?? null,
      isCurrent: identity.principal.id === account.primaryPrincipalId,
      state: primary ? primary.status === "DISABLED" ? "disabled" as const : primary.mustChangePassword ? "passwordChangeRequired" as const : "active" as const : null,
      attachments: primaryRecord?.policyAttachments.map(describeAttachment) ?? []
    },
    users: users?.items.filter(({ principal }) => principal.id !== account.primaryPrincipalId).map(({ principal, policyAttachments }) => {
      const credentialProtection = policyAttachments.some((attachment) => attachment.scope === "INSTALLATION") ? "platform" as const : principal.id === identity.principal.id ? "self" as const : null;
      return {
        accountType: "subuser" as const,
        id: principal.id,
        name: principal.displayName,
        loginName: principal.loginName,
        source: principal.source ?? "local" as const,
        qualifiedName: `${principal.loginName}@${account.loginAlias ?? account.organization.id}`,
        protected: credentialProtection !== null,
        credentialProtection,
        enabled: principal.status === "ACTIVE",
        resourceVersion: principal.resourceVersion,
        state: principal.status === "DISABLED" ? "disabled" as const : principal.mustChangePassword ? "passwordChangeRequired" as const : "active" as const,
        attachments: policyAttachments.map(describeAttachment)
      };
    }) ?? [],
    nextUserPage: users?.nextAfter ?? null,
    directoryComplete: users !== null && !users.nextAfter,
    accounts: accounts?.items.map((entry) => ({
      id: entry.organization.id,
      name: entry.organization.displayName,
      loginAlias: entry.loginAlias,
      primaryLoginName: entry.primaryLoginName,
      primaryPrincipalId: entry.primaryPrincipalId,
      enabled: entry.organization.status === "ACTIVE",
      resourceVersion: entry.organization.resourceVersion
    })) ?? [],
    nextAccountPage: accounts?.nextAfter ?? null
  };
}

export type AccountAccessScene = ReturnType<typeof buildAccountAccessScene>;
export type AccountUserScene = AccountAccessScene["users"][number];
export type TenantAccountScene = AccountAccessScene["accounts"][number];
