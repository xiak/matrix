import { HttpProblem } from "@/infrastructure/http/jsonRequest";
import type {
  Account,
  AccountAccess,
  AccountCommand,
  AccountIdentity,
  AccountPolicy,
  ActionCapability,
  CapabilityRestriction,
  DirectoryPage,
  IamAction,
  PolicyDirectory,
  PolicyScope,
  User,
  UserAccess,
  UserPolicyAttachment
} from "../domain/accounts";
import { enterprisePrincipalId, previewUserPrincipalId, type AccessWorkspace } from "../domain/accessWorkspace";
import { AccessWorkspaceError } from "../domain/accessWorkspaceError";
import { applyUserBatch } from "../domain/userBatch";
import type { AccountRepository, IamRepository, LoginResult } from "./iamRepository";
import { createPreviewAccessWorkspace } from "./previewAccessWorkspace";

export const previewCredential = "matrix-ux-preview-memory-only";
const previewAt = "2026-09-08T09:00:00Z";

let account: Account = {
  id: "org-xiak",
  displayName: "Xiak 科技",
  status: "ACTIVE",
  rootIdentity: { principalId: "principal-admin", loginName: "admin" },
  loginAlias: "xiak-cloud",
  resourceVersion: 7
};

let users: User[] = [
  {
    id: "principal-lin", accountId: "org-xiak", loginName: "lin", displayName: "林工程师", status: "ACTIVE", mustChangePassword: false, resourceVersion: 3
  },
  {
    id: "principal-chen", accountId: "org-xiak", loginName: "chen", displayName: "陈审计员", status: "ACTIVE", mustChangePassword: false, resourceVersion: 2
  },
  ...[
    { loginName: "qiao", displayName: "乔发布工程师" },
    { loginName: "wu", displayName: "吴新同事" }
  ].map(({ loginName, displayName }) => ({
    id: `principal-${loginName}`, accountId: "org-xiak", loginName, displayName, status: "ACTIVE" as const, mustChangePassword: false, resourceVersion: 1
  }))
];

let accounts: Account[] = [
  account,
  {
    id: "org-sandbox",
    displayName: "体验沙箱",
    status: "ACTIVE",
    rootIdentity: { principalId: "principal-sandbox-admin", loginName: "sandbox-admin" },
    loginAlias: "sandbox",
    resourceVersion: 1
  }
];
let userPlatformPolicies: Record<string, string[]> = {};

function requirePreviewCredential(credential: string): void {
  if (credential !== previewCredential) throw new Error("INVALID_PREVIEW_CREDENTIAL");
}

const initialPreviewState = structuredClone({ account, users, accounts, userPlatformPolicies });
const workspace = createPreviewAccessWorkspace(account.id, () => users.map((user) => user.id), account.rootIdentity.principalId);

function loginResult(): LoginResult {
  return {
    credential: previewCredential,
    mustChangePassword: false,
    session: {
      id: "session-ux-preview",
      organizationId: account.id,
      principalId: account.rootIdentity.principalId,
      status: "ACTIVE",
      issuedAt: "2026-09-07T01:00:00Z",
      expiresAt: "2099-09-07T01:00:00Z"
    }
  };
}

export const previewIamRepository: IamRepository = {
  async login() { return loginResult(); },
  async changePassword(credential) { requirePreviewCredential(credential); },
  async logout(credential) {
    requirePreviewCredential(credential);
    workspace.reset();
    const initial = structuredClone(initialPreviewState);
    account = initial.account;
    users = initial.users;
    accounts = initial.accounts;
    userPlatformPolicies = initial.userPlatformPolicies;
  }
};

function policyAttachment(principalId: string, policyId: string, scope: PolicyScope = "TENANT"): UserPolicyAttachment {
  return {
    id: `attachment-${principalId}-${policyId}`,
    accountId: account.id,
    target: { kind: "USER", id: principalId },
    policyId,
    scope,
    installationId: scope === "INSTALLATION" ? "matrix-preview" : null,
    resourceVersion: 1,
    createdAt: previewAt,
    updatedAt: previewAt
  };
}

function capability(
  action: IamAction,
  kind: ActionCapability["resource"]["kind"],
  id: string,
  restrictionReason: CapabilityRestriction | null = null
): ActionCapability {
  return { action, resource: { kind, id }, available: restrictionReason === null, restrictionReason };
}

function rootUser(): User {
  return {
    id: account.rootIdentity.principalId,
    accountId: account.id,
    loginName: account.rootIdentity.loginName,
    displayName: "平台管理员",
    status: "ACTIVE",
    mustChangePassword: false,
    resourceVersion: 5
  };
}

function currentIdentity(): AccountIdentity {
  const user = rootUser();
  return {
    account,
    user,
    identityKind: "ROOT_IDENTITY",
    policyAttachments: [],
    capabilities: [
      capability("iam.account.create", "ACCOUNT", "accounts"),
      capability("iam.account.read", "ACCOUNT", "accounts"),
      capability("iam.account.alias-set", "ACCOUNT", account.id),
      capability("iam.user.list", "ACCOUNT", account.id),
      capability("iam.user.create", "ACCOUNT", account.id),
      capability("iam.policy.list", "ACCOUNT", account.id)
    ],
  };
}

function page<T>(items: T[]): DirectoryPage<T> {
  return { items: structuredClone(items), nextAfter: null };
}

function updateUser(userId: string, update: (user: User) => User): void {
  users = users.map((user) => user.id === userId ? update(user) : user);
}

function tenantPolicyDirectory(source: AccessWorkspace): PolicyDirectory {
  const items: AccountPolicy[] = source.policies.map((policy): AccountPolicy => ({
    id: policy.id,
    management: policy.kind === "system" ? "SYSTEM" : "CUSTOMER",
    accountId: policy.kind === "system" ? null : account.id,
    displayName: policy.name,
    scope: "TENANT",
    status: "ACTIVE",
    defaultVersionId: String(policy.defaultVersion),
    resourceVersion: Math.max(1, policy.lastVersion),
    createdAt: policy.createdAt,
    updatedAt: policy.updatedAt
  })).sort((left, right) => left.id.localeCompare(right.id));
  return { accountId: account.id, scope: "TENANT", installationId: null, items };
}

function platformPolicyDirectory(): PolicyDirectory {
  return {
    accountId: account.id,
    scope: "INSTALLATION",
    installationId: "matrix-preview",
    items: [{
      id: "system.matrix-installation-admin",
      management: "SYSTEM",
      accountId: null,
      displayName: "MatrixInstallationAdministrator",
      scope: "INSTALLATION",
      status: "ACTIVE",
      defaultVersionId: "1",
      resourceVersion: 1,
      createdAt: previewAt,
      updatedAt: previewAt
    }]
  };
}

function usersWithAttachments(source: AccessWorkspace): UserAccess[] {
  return users.map((user) => {
    const policyAttachments = [
      ...(source.userPolicies[user.id] ?? []).map((policyId) => policyAttachment(user.id, policyId)),
      ...(userPlatformPolicies[user.id] ?? []).map((policyId) => policyAttachment(user.id, policyId, "INSTALLATION"))
    ];
    const hasInstallationAuthority = policyAttachments.some((attachment) => attachment.scope === "INSTALLATION");
    return {
      user,
      policyAttachments,
      capabilities: [
      capability("iam.user.set-status", "USER", user.id),
      capability("iam.user.reset-password", "USER", user.id),
      capability("iam.policy-attachment.create", "USER", user.id, user.status === "DISABLED" ? "TARGET_DISABLED" : null),
      capability("iam.platform-policy-attachment.create", "USER", user.id,
        user.status === "DISABLED" ? "TARGET_DISABLED" : user.mustChangePassword ? "TARGET_CREDENTIAL_CHANGE_REQUIRED" : null),
      ...policyAttachments.map((attachment) => capability(
        attachment.scope === "INSTALLATION" ? "iam.platform-policy-attachment.revoke" : "iam.policy-attachment.revoke",
        "POLICY_ATTACHMENT",
        attachment.id
      ))
      ].map((item) => hasInstallationAuthority && (item.action === "iam.user.set-status" || item.action === "iam.user.reset-password")
        ? { ...item, available: false, restrictionReason: "INSTALLATION_AUTHORITY_PROTECTED" as const }
        : item)
    };
  });
}

function accountsWithCapabilities(): AccountAccess[] {
  return accounts.map((entry) => ({
    account: entry,
    capabilities: [
      capability("iam.account.set-status", "ACCOUNT", entry.id, entry.id === account.id ? "SYSTEM_ACCOUNT_PROTECTED" : null),
      capability("iam.account.recover-root-credentials", "ACCOUNT", entry.id, entry.id === account.id ? "INSTALLATION_AUTHORITY_PROTECTED" : null)
    ]
  }));
}

export const previewAccountRepository: AccountRepository = {
  async executeUserBatch(credential, command) {
    requirePreviewCredential(credential);
    const result = workspace.transact((source) => applyUserBatch(source, usersWithAttachments(source), currentIdentity(), command, { id: crypto.randomUUID(), at: new Date().toISOString(), canListUsers: true }));
    users = result.users.map((entry) => entry.user);
    return { workspace: result.workspace };
  },
  workspace: {
    async read(credential) { requirePreviewCredential(credential); return workspace.read(credential); },
    async execute(credential, command) {
      requirePreviewCredential(credential);
      if (command.kind === "create-subuser" && (users.some((user) => user.loginName === command.loginName) || account.rootIdentity.loginName === command.loginName)) throw new AccessWorkspaceError("duplicate");
      const result = await workspace.execute(credential, command);
      if (command.kind === "create-subuser") users.push({
        id: previewUserPrincipalId(command.loginName), accountId: account.id, loginName: command.loginName,
        displayName: command.displayName.trim(), status: "ACTIVE",
        mustChangePassword: command.profile.consoleAccess && command.profile.passwordResetRequired, resourceVersion: 1
      });
      if (command.kind === "import-enterprise-members") {
        for (const memberId of command.memberIds) {
          const principalId = enterprisePrincipalId(command.id, memberId);
          const member = result.workspace.enterpriseMembers.find((entry) => entry.id === memberId)!;
          if (!users.some((entry) => entry.id === principalId)) users.push({
            id: principalId, accountId: account.id, loginName: `wecom.${command.id.slice(0, 8)}.${memberId}`,
            displayName: member.name, status: "ACTIVE", mustChangePassword: false, resourceVersion: 1
          });
        }
      }
      if (command.kind === "delete-user") {
        users = users.filter((user) => user.id !== command.principalId);
        delete userPlatformPolicies[command.principalId];
      }
      if (command.kind === "update-user") updateUser(command.principalId, (user) => ({ ...user, displayName: command.displayName.trim(), resourceVersion: user.resourceVersion + 1 }));
      return result;
    }
  },
  async currentIdentity(credential) {
    requirePreviewCredential(credential);
    return structuredClone(currentIdentity());
  },
  async listUsers(credential) {
    requirePreviewCredential(credential);
    return page(usersWithAttachments(await workspace.read(credential)));
  },
  async listPolicies(credential, platform) {
    requirePreviewCredential(credential);
    return structuredClone(platform ? platformPolicyDirectory() : tenantPolicyDirectory(await workspace.read(credential)));
  },
  async listAccounts(credential) {
    requirePreviewCredential(credential);
    return page(accountsWithCapabilities());
  },
  async execute(credential, command: AccountCommand) {
    requirePreviewCredential(credential);
    if ((command.kind === "set-status" || command.kind === "reset-password" || command.kind === "create-policy-attachment") && command.userId === account.rootIdentity.principalId) throw new HttpProblem(403, "ROOT_IDENTITY_PROTECTED");
    if (command.kind === "create-user") {
      if (users.some((user) => user.loginName === command.loginName) || account.rootIdentity.loginName === command.loginName) throw new HttpProblem(409, "PREVIEW_NAME_CONFLICT");
      if (!/^[a-z][a-z0-9._-]{2,63}$/.test(command.loginName) || !command.displayName.trim() || command.initialPassword.length < 14) throw new HttpProblem(422, "PREVIEW_INVALID_USER");
      users = [...users, {
        id: `principal-${command.loginName}`, accountId: account.id, loginName: command.loginName,
        displayName: command.displayName, status: "ACTIVE", mustChangePassword: true, resourceVersion: 1
      }];
      return;
    }
    if (command.kind === "create-account") {
      if (accounts.some((entry) => entry.id === command.id)) throw new HttpProblem(409, "PREVIEW_NAME_CONFLICT");
      accounts = [...accounts, {
        id: command.id, displayName: command.displayName, status: "ACTIVE",
        rootIdentity: { principalId: `principal-${command.id}-root`, loginName: command.rootLoginName },
        loginAlias: null, resourceVersion: 1
      }];
      return;
    }
    if (command.kind === "set-account-status") {
      const existing = accounts.find((entry) => entry.id === command.accountId);
      if (!existing || existing.resourceVersion !== command.resourceVersion) throw new HttpProblem(409, "PREVIEW_STALE_ACCOUNT");
      if (existing.id === account.id) throw new HttpProblem(403, "SYSTEM_ACCOUNT_PROTECTED");
      const next = { ...existing, status: command.status, resourceVersion: existing.resourceVersion + 1 };
      accounts = accounts.map((entry) => entry.id === command.accountId ? next : entry);
      return;
    }
    if (command.kind === "recover-root-credentials") {
      const existing = accounts.find((entry) => entry.id === command.accountId);
      if (!existing || existing.resourceVersion !== command.resourceVersion || command.initialPassword.length < 14) throw new HttpProblem(409, "PREVIEW_RECOVERY_CONFLICT");
      if (existing.id === account.id) throw new HttpProblem(403, "INSTALLATION_AUTHORITY_PROTECTED");
      const next = { ...existing, resourceVersion: existing.resourceVersion + 1 };
      accounts = accounts.map((entry) => entry.id === command.accountId ? next : entry);
      return;
    }
    if (command.kind === "set-alias") {
      account = { ...account, loginAlias: command.alias, resourceVersion: account.resourceVersion + 1 };
      accounts = accounts.map((entry) => entry.id === account.id ? account : entry);
      return;
    }
    if (command.kind === "set-status") {
      updateUser(command.userId, (user) => ({ ...user, status: command.status, resourceVersion: user.resourceVersion + 1 }));
      return;
    }
    if (command.kind === "reset-password") {
      updateUser(command.userId, (user) => ({ ...user, mustChangePassword: true, resourceVersion: user.resourceVersion + 1 }));
      return;
    }
    const snapshot = await workspace.read(credential);
    if (command.kind === "create-policy-attachment") {
      const tenantPolicy = snapshot.policies.find((entry) => entry.id === command.policyId);
      const platformPolicy = platformPolicyDirectory().items.find((entry) => entry.id === command.policyId);
      const user = users.find((entry) => entry.id === command.userId);
      const policy = tenantPolicy ?? platformPolicy;
      if (!policy || !user) throw new HttpProblem(403, "PREVIEW_UNKNOWN_POLICY_OR_USER");
      const resourceVersion = tenantPolicy ? Math.max(1, tenantPolicy.lastVersion) : platformPolicy!.resourceVersion;
      if (resourceVersion !== command.policyResourceVersion) throw new HttpProblem(409, "PREVIEW_POLICY_CHANGED");
      const selected = tenantPolicy ? snapshot.userPolicies[command.userId] ?? [] : userPlatformPolicies[command.userId] ?? [];
      if (selected.includes(command.policyId)) throw new HttpProblem(409, "PREVIEW_ATTACHMENT_EXISTS");
      if (tenantPolicy) await workspace.execute(credential, { kind: "set-user-policies", principalId: command.userId, policyIds: [...selected, command.policyId] });
      else userPlatformPolicies = { ...userPlatformPolicies, [command.userId]: [...selected, command.policyId] };
      return;
    }
    const match = users.flatMap((user) => [
      ...(snapshot.userPolicies[user.id] ?? []).map((policyId) => ({ user, policyId, attachment: policyAttachment(user.id, policyId) })),
      ...(userPlatformPolicies[user.id] ?? []).map((policyId) => ({ user, policyId, attachment: policyAttachment(user.id, policyId, "INSTALLATION") }))
    ]).find((entry) => entry.attachment.id === command.attachmentId);
    if (!match || match.attachment.resourceVersion !== command.resourceVersion) throw new HttpProblem(409, "PREVIEW_ATTACHMENT_CHANGED");
    if (match.attachment.scope === "INSTALLATION") userPlatformPolicies = { ...userPlatformPolicies, [match.user.id]: (userPlatformPolicies[match.user.id] ?? []).filter((policyId) => policyId !== match.policyId) };
    else await workspace.execute(credential, { kind: "set-user-policies", principalId: match.user.id, policyIds: (snapshot.userPolicies[match.user.id] ?? []).filter((policyId) => policyId !== match.policyId) });
  }
};
