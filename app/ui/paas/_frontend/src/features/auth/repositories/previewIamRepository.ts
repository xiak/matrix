import type {
  Account,
  AccountCommand,
  AccountIdentity,
  AccountUser,
  DirectoryPage,
  UserRoleBinding
} from "../domain/accounts";
import type {
  AccountRepository,
  IamRepository,
  LoginResult
} from "./iamRepository";
import { createPreviewAccessWorkspace } from "./previewAccessWorkspace";
import { enterprisePrincipalId, previewUserPrincipalId } from "../domain/accessWorkspace";
import { AccessWorkspaceError } from "../domain/accessWorkspaceError";
import { HttpProblem } from "@/infrastructure/http/jsonRequest";
import { applyUserBatch } from "../domain/userBatch";

export const previewCredential = "matrix-ux-preview-memory-only";

let account: Account = {
  organization: {
    id: "org-xiak",
    displayName: "Xiak 科技",
    status: "ACTIVE",
    resourceVersion: 7
  },
  primaryPrincipalId: "principal-admin",
  primaryLoginName: "admin",
  loginAlias: "xiak-cloud"
};

let users: AccountUser[] = [
  {
    principal: {
      id: "principal-lin",
      organizationId: "org-xiak",
      loginName: "lin",
      displayName: "林工程师",
      status: "ACTIVE",
      mustChangePassword: false,
      resourceVersion: 3
    },
    roleBindings: [{
      id: "binding-lin-developer",
      principalId: "principal-lin",
      organizationId: "org-xiak",
      role: "PAAS_DEVELOPER"
    }]
  },
  {
    principal: {
      id: "principal-chen",
      organizationId: "org-xiak",
      loginName: "chen",
      displayName: "陈审计员",
      status: "ACTIVE",
      mustChangePassword: false,
      resourceVersion: 2
    },
    roleBindings: [{
      id: "binding-chen-audit",
      principalId: "principal-chen",
      organizationId: "org-xiak",
      role: "AUDIT_READER"
    }]
  }
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
  async login() {
    return loginResult();
  },
  async changePassword(credential) {
    requirePreviewCredential(credential);
  },
  async logout(credential) {
    requirePreviewCredential(credential);
    workspace.reset();
    const initial = structuredClone(initialPreviewState);
    account = initial.account; users = initial.users; accounts = initial.accounts;
  }
};

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
    roles: ["ORGANIZATION_ADMIN"],
    canCreateOrganizations: true
  };
}

function page<T>(items: T[]): DirectoryPage<T> {
  return { items: structuredClone(items), nextAfter: null };
}

function updateUser(principalId: string, update: (user: AccountUser) => AccountUser): void {
  users = users.map((user) => user.principal.id === principalId ? update(user) : user);
}

export const previewAccountRepository: AccountRepository = {
  async executeUserBatch(credential, command) {
    requirePreviewCredential(credential);
    const result = workspace.transact((source) => applyUserBatch(source, users, currentIdentity(), command, { id: crypto.randomUUID(), at: new Date().toISOString() }));
    users = result.users;
    return { workspace: result.workspace };
  },
  workspace: {
    async read(credential) { requirePreviewCredential(credential); return workspace.read(credential); },
    async execute(credential, command) {
      requirePreviewCredential(credential);
      if (command.kind === "create-subuser" && (users.some((user) => user.principal.loginName === command.loginName) || account.primaryLoginName === command.loginName)) throw new AccessWorkspaceError("duplicate");
      const result = await workspace.execute(credential, command);
      if (command.kind === "create-subuser") users.push({
        principal: { id: previewUserPrincipalId(command.loginName), organizationId: account.organization.id, loginName: command.loginName, displayName: command.displayName.trim(), status: "ACTIVE", mustChangePassword: command.profile.consoleAccess && command.profile.passwordResetRequired, resourceVersion: 1 }, roleBindings: []
      });
      if (command.kind === "import-enterprise-members") {
        for (const memberId of command.memberIds) {
          const principalId = enterprisePrincipalId(command.id, memberId);
          const member = result.workspace.enterpriseMembers.find((entry) => entry.id === memberId)!;
          if (!users.some((entry) => entry.principal.id === principalId)) users.push({ principal: { id: principalId, organizationId: account.organization.id, loginName: "wecom." + command.id.slice(0, 8) + "." + memberId, displayName: member.name, source: "wecom", status: "ACTIVE", mustChangePassword: false, resourceVersion: 1 }, roleBindings: [] });
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
    return page(users);
  },
  async listAccounts(credential) {
    requirePreviewCredential(credential);
    return page(accounts);
  },
  async execute(credential, command: AccountCommand) {
    requirePreviewCredential(credential);
    if ("principalId" in command && command.principalId === account.primaryPrincipalId) throw new HttpProblem(403, "PREVIEW_PROTECTED_PRIMARY");
    if (command.kind === "create-user") {
      if (users.some((user) => user.principal.loginName === command.loginName) || account.primaryLoginName === command.loginName) throw new HttpProblem(409, "PREVIEW_NAME_CONFLICT");
      if (!/^[a-z][a-z0-9._-]{2,63}$/.test(command.loginName) || !command.displayName.trim() || command.initialPassword.length < 14) throw new HttpProblem(422, "PREVIEW_INVALID_USER");
      const principalId = `principal-${command.loginName}`;
      const roleBindings: UserRoleBinding[] = command.initialRole ? [{
        id: `binding-${command.loginName}-${command.initialRole.toLowerCase()}`,
        principalId,
        organizationId: account.organization.id,
        role: command.initialRole
      }] : [];
      users = [...users, {
        principal: {
          id: principalId,
          organizationId: account.organization.id,
          loginName: command.loginName,
          displayName: command.displayName,
          status: "ACTIVE",
          mustChangePassword: true,
          resourceVersion: 1
        },
        roleBindings
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
    if (command.kind === "set-alias") {
      account = { ...account, loginAlias: command.alias, organization: { ...account.organization, resourceVersion: account.organization.resourceVersion + 1 } };
      accounts = accounts.map((entry) => entry.organization.id === account.organization.id ? account : entry);
      return;
    }
    if (command.kind === "set-status") {
      updateUser(command.principalId, (user) => ({
        ...user,
        principal: { ...user.principal, status: command.status, resourceVersion: user.principal.resourceVersion + 1 }
      }));
      return;
    }
    if (command.kind === "reset-password") {
      updateUser(command.principalId, (user) => ({
        ...user,
        principal: { ...user.principal, mustChangePassword: true, resourceVersion: user.principal.resourceVersion + 1 }
      }));
      return;
    }
    if (command.kind === "grant-role") {
      updateUser(command.principalId, (user) => ({
        ...user,
        roleBindings: [...user.roleBindings.filter((binding) => binding.role !== command.role), {
          id: `binding-${command.principalId}-${command.role.toLowerCase()}`,
          principalId: command.principalId,
          organizationId: account.organization.id,
          role: command.role
        }]
      }));
      return;
    }
    if (!users.some((user) => user.roleBindings.some((binding) => binding.id === command.bindingId))) throw new HttpProblem(403, "PREVIEW_PROTECTED_OR_UNKNOWN_BINDING");
    users = users.map((user) => ({
      ...user,
      roleBindings: user.roleBindings.filter((binding) => binding.id !== command.bindingId)
    }));
  }
};
