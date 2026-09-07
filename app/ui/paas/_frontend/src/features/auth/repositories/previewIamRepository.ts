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
    if (command.kind === "create-user") {
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
        roleBindings: [...user.roleBindings, {
          id: `binding-${command.principalId}-${command.role.toLowerCase()}`,
          principalId: command.principalId,
          organizationId: account.organization.id,
          role: command.role
        }]
      }));
      return;
    }
    users = users.map((user) => ({
      ...user,
      roleBindings: user.roleBindings.filter((binding) => binding.id !== command.bindingId)
    }));
  }
};
