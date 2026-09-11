import { requestJSON, requestToken } from "@/infrastructure/http/jsonRequest";
import type {
  Account,
  AccountIdentity,
  AccountPolicy,
  AccountPrincipal,
  AccountUser,
  DirectoryPage,
  PolicyDirectory,
  PolicyManagement,
  PolicyScope,
  PolicyStatus,
  UserPolicyAttachment
} from "../domain/accounts";
import type { ChangePasswordCommand, AccountRepository, IamRepository, LoginCommand, LoginResult } from "./iamRepository";

type LoginWire = {
  session?: { id?: unknown; organizationId?: unknown; principalId?: unknown; status?: unknown; issuedAt?: unknown; expiresAt?: unknown };
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

function accountTimestamp(value: unknown): string {
  const result = accountText(value);
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$/.test(result) || Number.isNaN(Date.parse(result))) throw new Error("INVALID_IAM_RESPONSE");
  return result;
}

function accountStatus(value: unknown): "ACTIVE" | "DISABLED" {
  if (value !== "ACTIVE" && value !== "DISABLED") throw new Error("INVALID_IAM_RESPONSE");
  return value;
}

function policyScope(value: unknown): PolicyScope {
  if (value !== "TENANT" && value !== "INSTALLATION") throw new Error("INVALID_IAM_RESPONSE");
  return value;
}

function exactKeys(wire: Record<string, unknown>, required: string[], optional: string[] = []) {
  const allowed = new Set([...required, ...optional]);
  if (required.some((key) => !(key in wire)) || Object.keys(wire).some((key) => !allowed.has(key))) throw new Error("INVALID_IAM_RESPONSE");
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
    organization: {
      id: accountText(organization.id),
      displayName: accountText(organization.displayName),
      status: accountStatus(organization.status),
      resourceVersion: accountVersion(organization.resourceVersion)
    },
    primaryPrincipalId: accountText(wire.primaryPrincipalId),
    primaryLoginName: accountText(wire.primaryLoginName),
    loginAlias: wire.loginAlias
  };
}

function parseAccountPrincipal(value: unknown): AccountPrincipal {
  const wire = accountRecord(value);
  requireAccountKind(wire, "Principal");
  if (wire.type !== "USER" || (wire.mustChangePassword !== undefined && typeof wire.mustChangePassword !== "boolean")) throw new Error("INVALID_IAM_RESPONSE");
  return {
    id: accountText(wire.id),
    organizationId: accountText(wire.organizationId),
    loginName: accountText(wire.loginName),
    displayName: accountText(wire.displayName),
    status: accountStatus(wire.status),
    mustChangePassword: wire.mustChangePassword === true,
    resourceVersion: accountVersion(wire.resourceVersion)
  };
}

function parsePolicyAttachment(value: unknown): UserPolicyAttachment {
  const wire = accountRecord(value);
  exactKeys(wire, ["apiVersion", "kind", "id", "accountId", "target", "policyId", "scope", "resourceVersion", "createdAt", "updatedAt"], ["installationId"]);
  requireAccountKind(wire, "PolicyAttachment");
  const target = accountRecord(wire.target);
  exactKeys(target, ["kind", "id"]);
  const scope = policyScope(wire.scope);
  if (target.kind !== "USER" || (scope === "TENANT" && wire.installationId !== undefined) || (scope === "INSTALLATION" && typeof wire.installationId !== "string")) throw new Error("INVALID_IAM_RESPONSE");
  return {
    id: accountText(wire.id),
    accountId: accountText(wire.accountId),
    target: { kind: "USER", id: accountText(target.id) },
    policyId: accountText(wire.policyId),
    scope,
    installationId: scope === "INSTALLATION" ? accountText(wire.installationId) : null,
    resourceVersion: accountVersion(wire.resourceVersion),
    createdAt: accountTimestamp(wire.createdAt),
    updatedAt: accountTimestamp(wire.updatedAt)
  };
}

function parsePolicy(value: unknown): AccountPolicy {
  const wire = accountRecord(value);
  exactKeys(wire, ["apiVersion", "kind", "id", "management", "displayName", "scope", "status", "defaultVersionId", "resourceVersion", "createdAt", "updatedAt"], ["accountId"]);
  requireAccountKind(wire, "Policy");
  const management = wire.management as PolicyManagement;
  const status = wire.status as PolicyStatus;
  const scope = policyScope(wire.scope);
  if (
    (management !== "SYSTEM" && management !== "CUSTOMER") ||
    (status !== "ACTIVE" && status !== "RETIRED") ||
    (management === "SYSTEM" && (wire.accountId !== undefined || !String(wire.id).startsWith("system."))) ||
    (management === "CUSTOMER" && (typeof wire.accountId !== "string" || scope !== "TENANT" || String(wire.id).startsWith("system.")))
  ) throw new Error("INVALID_IAM_RESPONSE");
  return {
    id: accountText(wire.id),
    management,
    accountId: management === "CUSTOMER" ? accountText(wire.accountId) : null,
    displayName: accountText(wire.displayName),
    scope,
    status,
    defaultVersionId: accountText(wire.defaultVersionId),
    resourceVersion: accountVersion(wire.resourceVersion),
    createdAt: accountTimestamp(wire.createdAt),
    updatedAt: accountTimestamp(wire.updatedAt)
  };
}

function parsePolicyDirectory(value: unknown, expectedScope: PolicyScope): PolicyDirectory {
  const wire = accountRecord(value);
  exactKeys(wire, ["apiVersion", "kind", "accountId", "scope", "items"], ["installationId"]);
  requireAccountKind(wire, "PolicyList");
  if (
    wire.scope !== expectedScope ||
    !Array.isArray(wire.items) ||
    wire.items.length > 256 ||
    (expectedScope === "TENANT" && wire.installationId !== undefined) ||
    (expectedScope === "INSTALLATION" && typeof wire.installationId !== "string")
  ) throw new Error("INVALID_IAM_RESPONSE");
  const accountId = accountText(wire.accountId);
  const items = wire.items.map(parsePolicy);
  if (
    items.some((policy) => policy.scope !== expectedScope || (policy.accountId !== null && policy.accountId !== accountId)) ||
    items.some((policy, index) => index > 0 && items[index - 1]!.id >= policy.id) ||
    new Set(items.map((policy) => policy.id)).size !== items.length
  ) throw new Error("INVALID_IAM_RESPONSE");
  return { accountId, scope: expectedScope, installationId: expectedScope === "INSTALLATION" ? accountText(wire.installationId) : null, items };
}

function parseAccountIdentity(value: unknown): AccountIdentity {
  const wire = accountRecord(value);
  exactKeys(wire, ["apiVersion", "kind", "account", "principal", "policyAttachments", "canCreateOrganizations"]);
  requireAccountKind(wire, "CurrentIdentity");
  if (!Array.isArray(wire.policyAttachments) || wire.policyAttachments.length > 256 || typeof wire.canCreateOrganizations !== "boolean") throw new Error("INVALID_IAM_RESPONSE");
  const account = parseAccount(wire.account);
  const principal = parseAccountPrincipal(wire.principal);
  const policyAttachments = wire.policyAttachments.map(parsePolicyAttachment);
  if (
    account.organization.id !== principal.organizationId ||
    policyAttachments.some((attachment) => attachment.accountId !== principal.organizationId || attachment.target.id !== principal.id) ||
    new Set(policyAttachments.map((attachment) => attachment.id)).size !== policyAttachments.length ||
    new Set(policyAttachments.map((attachment) => attachment.policyId)).size !== policyAttachments.length ||
    (wire.canCreateOrganizations && (principal.mustChangePassword || !policyAttachments.some((attachment) => attachment.scope === "INSTALLATION")))
  ) throw new Error("INVALID_IAM_RESPONSE");
  return { account, principal, policyAttachments, canCreateOrganizations: wire.canCreateOrganizations };
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
      exactKeys(wire, ["principal", "policyAttachments"]);
      if (!Array.isArray(wire.policyAttachments) || wire.policyAttachments.length > 256) throw new Error("INVALID_IAM_RESPONSE");
      const principal = parseAccountPrincipal(wire.principal);
      const policyAttachments = wire.policyAttachments.map(parsePolicyAttachment);
      if (
        policyAttachments.some((attachment) => attachment.target.id !== principal.id || attachment.accountId !== principal.organizationId) ||
        new Set(policyAttachments.map((attachment) => attachment.id)).size !== policyAttachments.length ||
        new Set(policyAttachments.map((attachment) => attachment.policyId)).size !== policyAttachments.length
      ) throw new Error("INVALID_IAM_RESPONSE");
      return { principal, policyAttachments };
    });
  },
  async listPolicies(credential, platform) {
    return parsePolicyDirectory(await requestJSON<unknown>(platform ? "/api/iam/v1/platform-policies" : "/api/iam/v1/policies", { headers: accountHeaders(credential) }), platform ? "INSTALLATION" : "TENANT");
  },
  async listAccounts(credential, after) {
    return accountPage(await requestJSON<unknown>(`/api/iam/v1/organizations${after ? `?after=${encodeURIComponent(after)}` : ""}`, { headers: accountHeaders(credential) }), "OrganizationAccountList", parseAccount);
  },
  async execute(credential, command) {
    const requestId = requestToken("ui-account-");
    let path: string;
    let body: object;
    switch (command.kind) {
      case "create-user": path = "/api/iam/v1/principals"; body = { loginName: command.loginName, displayName: command.displayName, initialPassword: command.initialPassword }; break;
      case "create-organization": path = "/api/iam/v1/organizations"; body = { id: command.id, displayName: command.displayName, administratorLoginName: command.administratorLoginName, administratorDisplayName: command.administratorDisplayName, initialPassword: command.initialPassword }; break;
      case "set-organization-status": path = `/api/iam/v1/organizations/${encodeURIComponent(command.organizationId)}:set-status`; body = { status: command.status, resourceVersion: command.resourceVersion }; break;
      case "recover-primary": path = `/api/iam/v1/organizations/${encodeURIComponent(command.organizationId)}:recover-administrator`; body = { principalId: command.principalId, initialPassword: command.initialPassword, resourceVersion: command.resourceVersion }; break;
      case "set-alias": path = "/api/iam/v1/organization:alias"; body = { alias: command.alias, resourceVersion: command.resourceVersion }; break;
      case "set-status": path = `/api/iam/v1/principals/${encodeURIComponent(command.principalId)}:set-status`; body = { status: command.status, resourceVersion: command.resourceVersion }; break;
      case "reset-password": path = `/api/iam/v1/principals/${encodeURIComponent(command.principalId)}:reset-password`; body = { initialPassword: command.initialPassword, resourceVersion: command.resourceVersion }; break;
      case "create-policy-attachment": path = "/api/iam/v1/policy-attachments"; body = { target: { kind: "USER", id: command.principalId }, policyId: command.policyId, policyResourceVersion: command.policyResourceVersion }; break;
      case "revoke-policy-attachment": path = `/api/iam/v1/policy-attachments/${encodeURIComponent(command.attachmentId)}:revoke`; body = { resourceVersion: command.resourceVersion }; break;
    }
    const result = await requestJSON<unknown>(path, { method: "POST", headers: { ...accountHeaders(credential), "Content-Type": "application/json" }, body: JSON.stringify({ ...body, requestId }) });
    if (command.kind === "create-organization" || command.kind === "set-alias" || command.kind === "set-organization-status" || command.kind === "recover-primary") {
      const parsed = parseAccount(result);
      if (command.kind === "create-organization" && (parsed.organization.id !== command.id || parsed.primaryLoginName !== command.administratorLoginName)) throw new Error("INVALID_IAM_RESPONSE");
      if (command.kind === "set-alias" && (parsed.loginAlias !== command.alias || parsed.organization.resourceVersion <= command.resourceVersion)) throw new Error("INVALID_IAM_RESPONSE");
      if ((command.kind === "set-organization-status" || command.kind === "recover-primary") && (parsed.organization.id !== command.organizationId || parsed.organization.resourceVersion <= command.resourceVersion)) throw new Error("INVALID_IAM_RESPONSE");
      if (command.kind === "set-organization-status" && parsed.organization.status !== command.status) throw new Error("INVALID_IAM_RESPONSE");
      if (command.kind === "recover-primary" && parsed.primaryPrincipalId !== command.principalId) throw new Error("INVALID_IAM_RESPONSE");
      return;
    }
    if (command.kind === "create-policy-attachment") {
      const attachment = parsePolicyAttachment(result);
      if (attachment.target.id !== command.principalId || attachment.policyId !== command.policyId) throw new Error("INVALID_IAM_RESPONSE");
      return;
    }
    if (command.kind === "revoke-policy-attachment") {
      const wire = accountRecord(result);
      exactKeys(wire, ["apiVersion", "kind", "id", "resourceVersion", "revokedAt"]);
      requireAccountKind(wire, "Revocation");
      if (wire.id !== command.attachmentId || accountVersion(wire.resourceVersion) <= command.resourceVersion) throw new Error("INVALID_IAM_RESPONSE");
      accountTimestamp(wire.revokedAt);
      return;
    }
    const principal = parseAccountPrincipal(result);
    if (command.kind === "create-user" && principal.loginName !== command.loginName) throw new Error("INVALID_IAM_RESPONSE");
    if (command.kind !== "create-user" && (principal.id !== command.principalId || principal.resourceVersion <= command.resourceVersion)) throw new Error("INVALID_IAM_RESPONSE");
    if (command.kind === "set-status" && principal.status !== command.status) throw new Error("INVALID_IAM_RESPONSE");
    if ((command.kind === "create-user" || command.kind === "reset-password") && !principal.mustChangePassword) throw new Error("INVALID_IAM_RESPONSE");
  }
};

type ChangePasswordWire = { changedAt?: unknown; bootstrapFileRetirable?: unknown };

function parseLogin(value: LoginWire): LoginResult {
  const session = value.session;
  if (!session || typeof session.id !== "string" || typeof session.organizationId !== "string" || typeof session.principalId !== "string" || session.status !== "ACTIVE" || typeof session.issuedAt !== "string" || typeof session.expiresAt !== "string" || typeof value.credential !== "string" || !value.credential || typeof value.mustChangePassword !== "boolean") throw new Error("INVALID_IAM_RESPONSE");
  return {
    credential: value.credential,
    mustChangePassword: value.mustChangePassword,
    session: { id: session.id, organizationId: session.organizationId, principalId: session.principalId, status: "ACTIVE", issuedAt: session.issuedAt, expiresAt: session.expiresAt }
  };
}

export const httpIamRepository: IamRepository = {
  async login(command: LoginCommand): Promise<LoginResult> {
    const wire = await requestJSON<LoginWire>("/api/iam/v1/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ loginName: command.loginName, password: command.password, requestId: requestToken("ui-login-") })
    });
    return parseLogin(wire);
  },
  async changePassword(credential: string, command: ChangePasswordCommand): Promise<void> {
    const wire = await requestJSON<ChangePasswordWire>("/api/iam/v1/auth/password", {
      method: "POST",
      headers: { Authorization: `Bearer ${credential}`, "Content-Type": "application/json" },
      body: JSON.stringify({ currentPassword: command.currentPassword, newPassword: command.newPassword, revokeOtherSessions: command.revokeOtherSessions, requestId: requestToken("ui-password-") })
    });
    if (typeof wire.changedAt !== "string" || typeof wire.bootstrapFileRetirable !== "boolean") throw new Error("INVALID_IAM_RESPONSE");
  },
  async logout(credential: string): Promise<void> {
    await requestJSON<unknown>("/api/iam/v1/auth/logout", {
      method: "POST",
      headers: { Authorization: `Bearer ${credential}`, "Content-Type": "application/json" },
      body: JSON.stringify({ requestId: requestToken("ui-logout-") })
    });
  }
};
