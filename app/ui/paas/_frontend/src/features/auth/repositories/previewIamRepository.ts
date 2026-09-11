import { HttpProblem } from "@/infrastructure/http/jsonRequest";
import type {
  Account,
  AccountCommand,
  AccountIdentity,
  AccountPolicy,
  AccountUser,
  DirectoryPage,
  PolicyDirectory,
  PolicyScope,
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
  organization: { id: "org-xiak", displayName: "Xiak 科技", status: "ACTIVE", resourceVersion: 7 },
  primaryPrincipalId: "principal-admin",
  primaryLoginName: "admin",
  loginAlias: "xiak-cloud"
};

let users: AccountUser[] = [
  {
    principal: { id: "principal-lin", organizationId: "org-xiak", loginName: "lin", displayName: "林工程师", status: "ACTIVE", mustChangePassword: false, resourceVersion: 3 },
    policyAttachments: []
  },
  {
    principal: { id: "principal-chen", organizationId: "org-xiak", loginName: "chen", displayName: "陈审计员", status: "ACTIVE", mustChangePassword: false, resourceVersion: 2 },
    policyAttachments: []
  },
  ...[
    { loginName: "qiao", displayName: "乔发布工程师" },
    { loginName: "wu", displayName: "吴新同事" }
  ].map(({ loginName, displayName }) => ({
    principal: { id: `principal-${loginName}`, organizationId: "org-xiak", loginName, displayName, status: "ACTIVE" as const, mustChangePassword: false, resourceVersion: 1 },
    policyAttachments: []
  }))
];

let accounts: Account[] = [
  account,
  {
    organization: { id: "org-sandbox", displayName: "体验沙箱", status: "ACTIVE", resourceVersion: 1 },
    primaryPrincipalId: "principal-sandbox-admin",
    primaryLoginName: "sandbox-admin",
    loginAlias: "sandbox"
  }
];

function requirePreviewCredential(credential: string): void {
  if (credential !== previewCredential) throw new Error("INVALID_PREVIEW_CREDENTIAL");
}

const initialPreviewState = structuredClone({ account, users, accounts });
const workspace = createPreviewAccessWorkspace(account.organization.id, () => users.map((user) => user.principal.id), account.primaryPrincipalId);

function loginResult(): LoginResult {
  return {
    credential: previewCredential,
    mustChangePassword: false,
    session: {
      id: "session-ux-preview",
      organizationId: account.organization.id,
      principalId: account.primaryPrincipalId,
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
  }
};

function policyAttachment(principalId: string, policyId: string, scope: PolicyScope = "TENANT"): UserPolicyAttachment {
  return {
    id: `attachment-${principalId}-${policyId}`,
    accountId: account.organization.id,
    target: { kind: "USER", id: principalId },
    policyId,
    scope,
    installationId: scope === "INSTALLATION" ? "matrix-preview" : null,
    resourceVersion: 1,
    createdAt: previewAt,
    updatedAt: previewAt
  };
}

function currentIdentity(): AccountIdentity {
  return {
    account,
    principal: {
      id: account.primaryPrincipalId,
      organizationId: account.organization.id,
      loginName: account.primaryLoginName,
      displayName: "平台管理员",
      status: "ACTIVE",
      mustChangePassword: false,
      resourceVersion: 5
    },
    policyAttachments: [
      policyAttachment(account.primaryPrincipalId, "policy-admin"),
      policyAttachment(account.primaryPrincipalId, "system.matrix-installation-admin", "INSTALLATION")
    ],
    canCreateOrganizations: true
  };
}

function page<T>(items: T[]): DirectoryPage<T> {
  return { items: structuredClone(items), nextAfter: null };
}

function updateUser(principalId: string, update: (user: AccountUser) => AccountUser): void {
  users = users.map((user) => user.principal.id === principalId ? update(user) : user);
}

function tenantPolicyDirectory(source: AccessWorkspace): PolicyDirectory {
  const items: AccountPolicy[] = source.policies.map((policy): AccountPolicy => ({
    id: policy.id,
    management: policy.kind === "system" ? "SYSTEM" : "CUSTOMER",
    accountId: policy.kind === "system" ? null : account.organization.id,
    displayName: policy.name,
    scope: "TENANT",
    status: "ACTIVE",
    defaultVersionId: String(policy.defaultVersion),
    resourceVersion: Math.max(1, policy.lastVersion),
    createdAt: policy.createdAt,
    updatedAt: policy.updatedAt
  })).sort((left, right) => left.id.localeCompare(right.id));
  return { accountId: account.organization.id, scope: "TENANT", installationId: null, items };
}

function platformPolicyDirectory(): PolicyDirectory {
  return {
    accountId: account.organization.id,
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

function usersWithAttachments(source: AccessWorkspace): AccountUser[] {
  return users.map((user) => ({
    ...user,
    policyAttachments: (source.userPolicies[user.principal.id] ?? []).map((policyId) => policyAttachment(user.principal.id, policyId))
  }));
}

export const previewAccountRepository: AccountRepository = {
  async executeUserBatch(credential, command) {
    requirePreviewCredential(credential);
    const result = workspace.transact((source) => applyUserBatch(source, usersWithAttachments(source), currentIdentity(), command, { id: crypto.randomUUID(), at: new Date().toISOString(), canManage: true }));
    users = result.users.map((user) => ({ ...user, policyAttachments: [] }));
    return { workspace: result.workspace };
  },
  workspace: {
    async read(credential) { requirePreviewCredential(credential); return workspace.read(credential); },
    async execute(credential, command) {
      requirePreviewCredential(credential);
      if (command.kind === "create-subuser" && (users.some((user) => user.principal.loginName === command.loginName) || account.primaryLoginName === command.loginName)) throw new AccessWorkspaceError("duplicate");
      const result = await workspace.execute(credential, command);
      if (command.kind === "create-subuser") users.push({
        principal: { id: previewUserPrincipalId(command.loginName), organizationId: account.organization.id, loginName: command.loginName, displayName: command.displayName.trim(), status: "ACTIVE", mustChangePassword: command.profile.consoleAccess && command.profile.passwordResetRequired, resourceVersion: 1 },
        policyAttachments: []
      });
      if (command.kind === "import-enterprise-members") {
        for (const memberId of command.memberIds) {
          const principalId = enterprisePrincipalId(command.id, memberId);
          const member = result.workspace.enterpriseMembers.find((entry) => entry.id === memberId)!;
          if (!users.some((entry) => entry.principal.id === principalId)) users.push({
            principal: { id: principalId, organizationId: account.organization.id, loginName: `wecom.${command.id.slice(0, 8)}.${memberId}`, displayName: member.name, source: "wecom", status: "ACTIVE", mustChangePassword: false, resourceVersion: 1 },
            policyAttachments: []
          });
        }
      }
      if (command.kind === "delete-user") users = users.filter((user) => user.principal.id !== command.principalId);
      if (command.kind === "update-user") updateUser(command.principalId, (user) => ({ ...user, principal: { ...user.principal, displayName: command.displayName.trim(), resourceVersion: user.principal.resourceVersion + 1 } }));
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
    return page(accounts);
  },
  async execute(credential, command: AccountCommand) {
    requirePreviewCredential(credential);
    if ((command.kind === "set-status" || command.kind === "reset-password" || command.kind === "create-policy-attachment") && command.principalId === account.primaryPrincipalId) throw new HttpProblem(403, "PREVIEW_PROTECTED_PRIMARY");
    if (command.kind === "revoke-policy-attachment" && currentIdentity().policyAttachments.some((attachment) => attachment.id === command.attachmentId)) throw new HttpProblem(403, "PREVIEW_PROTECTED_PRIMARY");
    if (command.kind === "create-user") {
      if (users.some((user) => user.principal.loginName === command.loginName) || account.primaryLoginName === command.loginName) throw new HttpProblem(409, "PREVIEW_NAME_CONFLICT");
      if (!/^[a-z][a-z0-9._-]{2,63}$/.test(command.loginName) || !command.displayName.trim() || command.initialPassword.length < 14) throw new HttpProblem(422, "PREVIEW_INVALID_USER");
      users = [...users, {
        principal: { id: `principal-${command.loginName}`, organizationId: account.organization.id, loginName: command.loginName, displayName: command.displayName, status: "ACTIVE", mustChangePassword: true, resourceVersion: 1 },
        policyAttachments: []
      }];
      return;
    }
    if (command.kind === "create-organization") {
      if (accounts.some((entry) => entry.organization.id === command.id)) throw new HttpProblem(409, "PREVIEW_NAME_CONFLICT");
      accounts = [...accounts, {
        organization: { id: command.id, displayName: command.displayName, status: "ACTIVE", resourceVersion: 1 },
        primaryPrincipalId: `principal-${command.id}-admin`,
        primaryLoginName: command.administratorLoginName,
        loginAlias: null
      }];
      return;
    }
    if (command.kind === "set-organization-status") {
      const existing = accounts.find((entry) => entry.organization.id === command.organizationId);
      if (!existing || existing.organization.resourceVersion !== command.resourceVersion) throw new HttpProblem(409, "PREVIEW_STALE_ORGANIZATION");
      const next = { ...existing, organization: { ...existing.organization, status: command.status, resourceVersion: existing.organization.resourceVersion + 1 } };
      accounts = accounts.map((entry) => entry.organization.id === command.organizationId ? next : entry);
      if (command.organizationId === account.organization.id) account = next;
      return;
    }
    if (command.kind === "recover-primary") {
      const existing = accounts.find((entry) => entry.organization.id === command.organizationId);
      if (!existing || existing.primaryPrincipalId !== command.principalId || existing.organization.resourceVersion !== command.resourceVersion || command.initialPassword.length < 14) throw new HttpProblem(409, "PREVIEW_RECOVERY_CONFLICT");
      const next = { ...existing, organization: { ...existing.organization, resourceVersion: existing.organization.resourceVersion + 1 } };
      accounts = accounts.map((entry) => entry.organization.id === command.organizationId ? next : entry);
      if (command.organizationId === account.organization.id) account = next;
      return;
    }
    if (command.kind === "set-alias") {
      account = { ...account, loginAlias: command.alias, organization: { ...account.organization, resourceVersion: account.organization.resourceVersion + 1 } };
      accounts = accounts.map((entry) => entry.organization.id === account.organization.id ? account : entry);
      return;
    }
    if (command.kind === "set-status") {
      updateUser(command.principalId, (user) => ({ ...user, principal: { ...user.principal, status: command.status, resourceVersion: user.principal.resourceVersion + 1 } }));
      return;
    }
    if (command.kind === "reset-password") {
      updateUser(command.principalId, (user) => ({ ...user, principal: { ...user.principal, mustChangePassword: true, resourceVersion: user.principal.resourceVersion + 1 } }));
      return;
    }
    const snapshot = await workspace.read(credential);
    if (command.kind === "create-policy-attachment") {
      const policy = snapshot.policies.find((entry) => entry.id === command.policyId);
      const user = users.find((entry) => entry.principal.id === command.principalId);
      if (!policy || !user) throw new HttpProblem(403, "PREVIEW_UNKNOWN_POLICY_OR_USER");
      if (Math.max(1, policy.lastVersion) !== command.policyResourceVersion) throw new HttpProblem(409, "PREVIEW_POLICY_CHANGED");
      const selected = snapshot.userPolicies[command.principalId] ?? [];
      if (selected.includes(command.policyId)) throw new HttpProblem(409, "PREVIEW_ATTACHMENT_EXISTS");
      await workspace.execute(credential, { kind: "set-user-policies", principalId: command.principalId, policyIds: [...selected, command.policyId] });
      return;
    }
    const match = users.flatMap((user) => (snapshot.userPolicies[user.principal.id] ?? []).map((policyId) => ({ user, policyId, attachment: policyAttachment(user.principal.id, policyId) }))).find((entry) => entry.attachment.id === command.attachmentId);
    if (!match || match.attachment.resourceVersion !== command.resourceVersion) throw new HttpProblem(409, "PREVIEW_ATTACHMENT_CHANGED");
    await workspace.execute(credential, { kind: "set-user-policies", principalId: match.user.principal.id, policyIds: (snapshot.userPolicies[match.user.principal.id] ?? []).filter((policyId) => policyId !== match.policyId) });
  }
};
