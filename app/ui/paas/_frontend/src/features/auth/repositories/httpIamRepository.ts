import { requestJSON, requestToken } from "@/infrastructure/http/jsonRequest";
import { userRoles, type Account, type AccountIdentity, type AccountPrincipal, type AccountUser, type DirectoryPage, type IdentityRole, type UserRole, type UserRoleBinding } from "../domain/accounts";
import type {
  ChangePasswordCommand,
  AccountRepository,
  IamRepository,
  LoginCommand,
  LoginResult
} from "./iamRepository";

type LoginWire = {
  session?: {
    id?: unknown;
    organizationId?: unknown;
    principalId?: unknown;
    status?: unknown;
    issuedAt?: unknown;
    expiresAt?: unknown;
  };
  credential?: unknown;
  mustChangePassword?: unknown;
};

function accountRecord(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("INVALID_IAM_RESPONSE");
  return value as Record<string, unknown>;
}

function accountText(value: unknown): string {
  if (typeof value !== "string" || !value.length) throw new Error("INVALID_IAM_RESPONSE");
  return value;
}

function accountVersion(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1) throw new Error("INVALID_IAM_RESPONSE");
  return value;
}

function accountStatus(value: unknown): "ACTIVE" | "DISABLED" {
  if (value !== "ACTIVE" && value !== "DISABLED") throw new Error("INVALID_IAM_RESPONSE");
  return value;
}

function parseIdentityRole(value: unknown): IdentityRole {
  if (value !== "PLATFORM_OPERATOR" && !userRoles.includes(value as UserRole)) throw new Error("INVALID_IAM_RESPONSE");
  return value as IdentityRole;
}

function requireAccountKind(wire: Record<string, unknown>, kind: string) {
  if (wire.apiVersion !== "iam.matrix.xiak.com/v1" || wire.kind !== kind) throw new Error("INVALID_IAM_RESPONSE");
}

function parseAccount(value: unknown): Account {
  const wire = accountRecord(value);
  const organization = accountRecord(wire.organization);
  requireAccountKind(organization, "Organization");
  if (wire.loginAlias !== null && (typeof wire.loginAlias !== "string" || !/^[a-z][a-z0-9-]{1,61}[a-z0-9]$/.test(wire.loginAlias))) throw new Error("INVALID_IAM_RESPONSE");
  return {
    organization: { id: accountText(organization.id), displayName: accountText(organization.displayName), status: accountStatus(organization.status), resourceVersion: accountVersion(organization.resourceVersion) },
    primaryPrincipalId: accountText(wire.primaryPrincipalId), primaryLoginName: accountText(wire.primaryLoginName), loginAlias: wire.loginAlias
  };
}

function parseAccountPrincipal(value: unknown): AccountPrincipal {
  const wire = accountRecord(value);
  requireAccountKind(wire, "Principal");
  if (wire.type !== "USER" || (wire.mustChangePassword !== undefined && typeof wire.mustChangePassword !== "boolean")) throw new Error("INVALID_IAM_RESPONSE");
  return { id: accountText(wire.id), organizationId: accountText(wire.organizationId), loginName: accountText(wire.loginName),
    displayName: accountText(wire.displayName), status: accountStatus(wire.status), mustChangePassword: wire.mustChangePassword === true, resourceVersion: accountVersion(wire.resourceVersion) };
}

function parseRoleBinding(value: unknown): UserRoleBinding {
  const wire = accountRecord(value);
  requireAccountKind(wire, "RoleBinding");
  return { id: accountText(wire.id), principalId: accountText(wire.principalId), organizationId: accountText(wire.organizationId), role: parseIdentityRole(wire.role) };
}

function parseAccountIdentity(value: unknown): AccountIdentity {
  const wire = accountRecord(value);
  requireAccountKind(wire, "CurrentIdentity");
  if (!Array.isArray(wire.roles) || typeof wire.canCreateOrganizations !== "boolean") throw new Error("INVALID_IAM_RESPONSE");
  const account = parseAccount(wire.account);
  const principal = parseAccountPrincipal(wire.principal);
  const roles = wire.roles.map(parseIdentityRole);
  if (account.organization.id !== principal.organizationId || new Set(roles).size !== roles.length ||
      (wire.canCreateOrganizations && (principal.mustChangePassword || !roles.includes("PLATFORM_OPERATOR")))) throw new Error("INVALID_IAM_RESPONSE");
  return { account, principal, roles, canCreateOrganizations: wire.canCreateOrganizations };
}

function accountPage<T>(value: unknown, kind: string, parse: (item: unknown) => T): DirectoryPage<T> {
  const wire = accountRecord(value);
  requireAccountKind(wire, kind);
  if (!Array.isArray(wire.items) || wire.items.length > 100) throw new Error("INVALID_IAM_RESPONSE");
  return { items: wire.items.map(parse), nextAfter: wire.nextAfter === undefined ? null : accountText(wire.nextAfter) };
}

function accountHeaders(credential: string): HeadersInit { return { Authorization: `Bearer ${credential}` }; }

export const httpAccountRepository: AccountRepository = {
  async currentIdentity(credential) {
    return parseAccountIdentity(await requestJSON<unknown>("/api/iam/v1/auth/me", { headers: accountHeaders(credential) }));
  },
  async listUsers(credential, after) {
    return accountPage<AccountUser>(await requestJSON<unknown>(`/api/iam/v1/principals${after ? `?after=${encodeURIComponent(after)}` : ""}`, { headers: accountHeaders(credential) }), "PrincipalList", (value) => {
      const wire = accountRecord(value);
      if (!Array.isArray(wire.roleBindings)) throw new Error("INVALID_IAM_RESPONSE");
      const principal = parseAccountPrincipal(wire.principal);
      const roleBindings = wire.roleBindings.map(parseRoleBinding);
      if (roleBindings.some((binding) => binding.principalId !== principal.id || binding.organizationId !== principal.organizationId) ||
          new Set(roleBindings.map((binding) => binding.role)).size !== roleBindings.length) throw new Error("INVALID_IAM_RESPONSE");
      return { principal, roleBindings };
    });
  },
  async listAccounts(credential, after) {
    return accountPage(await requestJSON<unknown>(`/api/iam/v1/organizations${after ? `?after=${encodeURIComponent(after)}` : ""}`, { headers: accountHeaders(credential) }), "OrganizationAccountList", parseAccount);
  },
  async execute(credential, command) {
    const requestId = requestToken("ui-account-");
    let path: string;
    let body: object;
    switch (command.kind) {
      case "create-user": path = "/api/iam/v1/principals"; body = { loginName: command.loginName, displayName: command.displayName, initialPassword: command.initialPassword, initialRole: command.initialRole }; break;
      case "create-organization": path = "/api/iam/v1/organizations"; body = { id: command.id, displayName: command.displayName, administratorLoginName: command.administratorLoginName, administratorDisplayName: command.administratorDisplayName, initialPassword: command.initialPassword }; break;
      case "set-organization-status": path = `/api/iam/v1/organizations/${encodeURIComponent(command.organizationId)}:set-status`; body = { status: command.status, resourceVersion: command.resourceVersion }; break;
      case "recover-primary": path = `/api/iam/v1/organizations/${encodeURIComponent(command.organizationId)}:recover-administrator`; body = { principalId: command.principalId, initialPassword: command.initialPassword, resourceVersion: command.resourceVersion }; break;
      case "set-alias": path = "/api/iam/v1/organization:alias"; body = { alias: command.alias, resourceVersion: command.resourceVersion }; break;
      case "set-status": path = `/api/iam/v1/principals/${encodeURIComponent(command.principalId)}:set-status`; body = { status: command.status, resourceVersion: command.resourceVersion }; break;
      case "reset-password": path = `/api/iam/v1/principals/${encodeURIComponent(command.principalId)}:reset-password`; body = { initialPassword: command.initialPassword, resourceVersion: command.resourceVersion }; break;
      case "grant-role": path = "/api/iam/v1/role-bindings"; body = { principalId: command.principalId, role: command.role }; break;
      case "revoke-role": path = `/api/iam/v1/role-bindings/${encodeURIComponent(command.bindingId)}:revoke`; body = {}; break;
    }
    const result = await requestJSON<unknown>(path, { method: "POST", headers: { ...accountHeaders(credential), "Content-Type": "application/json" }, body: JSON.stringify({ ...body, requestId }) });
    if (command.kind === "create-organization" || command.kind === "set-alias" || command.kind === "set-organization-status" || command.kind === "recover-primary") {
      const account = parseAccount(result);
      if (command.kind === "create-organization" && (account.organization.id !== command.id || account.primaryLoginName !== command.administratorLoginName)) throw new Error("INVALID_IAM_RESPONSE");
      if (command.kind === "set-alias" && (account.loginAlias !== command.alias || account.organization.resourceVersion <= command.resourceVersion)) throw new Error("INVALID_IAM_RESPONSE");
      if ((command.kind === "set-organization-status" || command.kind === "recover-primary") &&
          (account.organization.id !== command.organizationId || account.organization.resourceVersion <= command.resourceVersion)) throw new Error("INVALID_IAM_RESPONSE");
      if (command.kind === "set-organization-status" && account.organization.status !== command.status) throw new Error("INVALID_IAM_RESPONSE");
      if (command.kind === "recover-primary" && account.primaryPrincipalId !== command.principalId) throw new Error("INVALID_IAM_RESPONSE");
      return;
    }
    if (command.kind === "grant-role") {
      const binding = parseRoleBinding(result);
      if (binding.principalId !== command.principalId || binding.role !== command.role) throw new Error("INVALID_IAM_RESPONSE");
      return;
    }
    if (command.kind === "revoke-role") {
      const wire = accountRecord(result);
      requireAccountKind(wire, "Revocation");
      if (wire.id !== command.bindingId) throw new Error("INVALID_IAM_RESPONSE");
      return;
    }
    const principal = parseAccountPrincipal(result);
    if (command.kind === "create-user" && principal.loginName !== command.loginName) throw new Error("INVALID_IAM_RESPONSE");
    if (command.kind !== "create-user" && (principal.id !== command.principalId || principal.resourceVersion <= command.resourceVersion)) throw new Error("INVALID_IAM_RESPONSE");
    if (command.kind === "set-status" && principal.status !== command.status) throw new Error("INVALID_IAM_RESPONSE");
    if ((command.kind === "create-user" || command.kind === "reset-password") && !principal.mustChangePassword) throw new Error("INVALID_IAM_RESPONSE");
  }
};

type ChangePasswordWire = {
  changedAt?: unknown;
  bootstrapFileRetirable?: unknown;
};

function parseLogin(value: LoginWire): LoginResult {
  const session = value.session;
  if (
    !session ||
    typeof session.id !== "string" ||
    typeof session.organizationId !== "string" ||
    typeof session.principalId !== "string" ||
    session.status !== "ACTIVE" ||
    typeof session.issuedAt !== "string" ||
    typeof session.expiresAt !== "string" ||
    typeof value.credential !== "string" ||
    value.credential.length === 0 ||
    typeof value.mustChangePassword !== "boolean"
  ) {
    throw new Error("INVALID_IAM_RESPONSE");
  }

  return {
    credential: value.credential,
    mustChangePassword: value.mustChangePassword,
    session: {
      id: session.id,
      organizationId: session.organizationId,
      principalId: session.principalId,
      status: "ACTIVE",
      issuedAt: session.issuedAt,
      expiresAt: session.expiresAt
    }
  };
}

export const httpIamRepository: IamRepository = {
  async login(command: LoginCommand): Promise<LoginResult> {
    const wire = await requestJSON<LoginWire>("/api/iam/v1/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        loginName: command.loginName,
        password: command.password,
        requestId: requestToken("ui-login-")
      })
    });
    return parseLogin(wire);
  },

  async changePassword(
    credential: string,
    command: ChangePasswordCommand
  ): Promise<void> {
    const wire = await requestJSON<ChangePasswordWire>("/api/iam/v1/auth/password", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${credential}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        currentPassword: command.currentPassword,
        newPassword: command.newPassword,
        revokeOtherSessions: command.revokeOtherSessions,
        requestId: requestToken("ui-password-")
      })
    });
    if (
      typeof wire.changedAt !== "string" ||
      typeof wire.bootstrapFileRetirable !== "boolean"
    ) {
      throw new Error("INVALID_IAM_RESPONSE");
    }
  },

  async logout(credential: string): Promise<void> {
    await requestJSON<unknown>("/api/iam/v1/auth/logout", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${credential}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ requestId: requestToken("ui-logout-") })
    });
  }
};
