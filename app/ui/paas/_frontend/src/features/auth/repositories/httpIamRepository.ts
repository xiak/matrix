import { requestJSON, requestToken } from "@/infrastructure/http/jsonRequest";
import type {
  Account,
  AccountAccess,
  AccountIdentity,
  AccountPolicy,
  ActionCapability,
  CapabilityRestriction,
  DirectoryPage,
  IamAction,
  PolicyDirectory,
  PolicyManagement,
  PolicyScope,
  PolicyStatus,
  User,
  UserAccess,
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

const capabilityActions = new Set<IamAction>([
  "iam.account.create", "iam.account.read", "iam.account.set-status", "iam.account.recover-root-credentials",
  "iam.account.alias-set", "iam.user.list", "iam.user.create", "iam.policy.list", "iam.user.set-status",
  "iam.user.reset-password", "iam.policy-attachment.create", "iam.platform-policy-attachment.create",
  "iam.policy-attachment.revoke", "iam.platform-policy-attachment.revoke"
]);

const capabilityRestrictions = new Set<CapabilityRestriction>([
  "AUTHORITY_REQUIRED", "CURRENT_CREDENTIAL_CHANGE_REQUIRED", "SELF_PROTECTED", "ROOT_IDENTITY_PROTECTED",
  "INSTALLATION_AUTHORITY_PROTECTED", "SYSTEM_ACCOUNT_PROTECTED", "TARGET_DISABLED",
  "TARGET_CREDENTIAL_CHANGE_REQUIRED"
]);

function capabilityResourceKind(action: IamAction): ActionCapability["resource"]["kind"] {
  if (action === "iam.user.set-status" || action === "iam.user.reset-password" ||
      action === "iam.policy-attachment.create" || action === "iam.platform-policy-attachment.create") return "USER";
  if (action === "iam.policy-attachment.revoke" || action === "iam.platform-policy-attachment.revoke") return "POLICY_ATTACHMENT";
  return "ACCOUNT";
}

function parseCapability(value: unknown): ActionCapability {
  const wire = accountRecord(value);
  exactKeys(wire, ["action", "resource", "available"], ["restrictionReason"]);
  if (typeof wire.action !== "string" || !capabilityActions.has(wire.action as IamAction) || typeof wire.available !== "boolean") {
    throw new Error("INVALID_IAM_RESPONSE");
  }
  const action = wire.action as IamAction;
  const resource = accountRecord(wire.resource);
  exactKeys(resource, ["kind", "id"]);
  const reason = wire.restrictionReason;
  if (resource.kind !== capabilityResourceKind(action) || typeof resource.id !== "string" || !resource.id.length ||
      (wire.available && reason !== undefined) ||
      (!wire.available && (typeof reason !== "string" || !capabilityRestrictions.has(reason as CapabilityRestriction)))) {
    throw new Error("INVALID_IAM_RESPONSE");
  }
  return {
    action,
    resource: { kind: resource.kind as ActionCapability["resource"]["kind"], id: resource.id },
    available: wire.available,
    restrictionReason: wire.available ? null : reason as CapabilityRestriction
  };
}

function capabilityKey(value: Pick<ActionCapability, "action" | "resource">): string {
  return `${value.action}\u0000${value.resource.kind}\u0000${value.resource.id}`;
}

function parseCapabilities(value: unknown, expected: Array<Pick<ActionCapability, "action" | "resource">>): ActionCapability[] {
  if (!Array.isArray(value) || value.length !== expected.length) throw new Error("INVALID_IAM_RESPONSE");
  const capabilities = value.map(parseCapability);
  const actual = new Set(capabilities.map(capabilityKey));
  if (actual.size !== capabilities.length || expected.some((item) => !actual.has(capabilityKey(item)))) {
    throw new Error("INVALID_IAM_RESPONSE");
  }
  return capabilities;
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
  exactKeys(wire, ["apiVersion", "kind", "id", "displayName", "status", "rootIdentity", "loginAlias", "resourceVersion", "createdAt", "updatedAt"]);
  requireAccountKind(wire, "Account");
  const root = accountRecord(wire.rootIdentity);
  exactKeys(root, ["principalId", "loginName"]);
  if (wire.loginAlias !== null && (typeof wire.loginAlias !== "string" || !/^[a-z][a-z0-9-]{1,61}[a-z0-9]$/.test(wire.loginAlias))) throw new Error("INVALID_IAM_RESPONSE");
  accountTimestamp(wire.createdAt);
  accountTimestamp(wire.updatedAt);
  return {
    id: accountText(wire.id),
    displayName: accountText(wire.displayName),
    status: accountStatus(wire.status),
    rootIdentity: { principalId: accountText(root.principalId), loginName: accountText(root.loginName) },
    loginAlias: wire.loginAlias,
    resourceVersion: accountVersion(wire.resourceVersion)
  };
}

function parseUser(value: unknown): User {
  const wire = accountRecord(value);
  exactKeys(wire, ["apiVersion", "kind", "id", "accountId", "loginName", "displayName", "status", "resourceVersion", "createdAt", "updatedAt"], ["mustChangePassword"]);
  requireAccountKind(wire, "User");
  if (wire.mustChangePassword !== undefined && typeof wire.mustChangePassword !== "boolean") throw new Error("INVALID_IAM_RESPONSE");
  accountTimestamp(wire.createdAt);
  accountTimestamp(wire.updatedAt);
  return {
    id: accountText(wire.id),
    accountId: accountText(wire.accountId),
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
  exactKeys(wire, ["apiVersion", "kind", "account", "user", "identityKind", "policyAttachments", "capabilities"]);
  requireAccountKind(wire, "CurrentIdentity");
  if (!Array.isArray(wire.policyAttachments) || wire.policyAttachments.length > 256 ||
      (wire.identityKind !== "ROOT_IDENTITY" && wire.identityKind !== "USER")) throw new Error("INVALID_IAM_RESPONSE");
  const account = parseAccount(wire.account);
  const user = parseUser(wire.user);
  const policyAttachments = wire.policyAttachments.map(parsePolicyAttachment);
  const accountResource = { kind: "ACCOUNT" as const, id: account.id };
  const capabilities = parseCapabilities(wire.capabilities, [
    { action: "iam.account.create", resource: { kind: "ACCOUNT", id: "accounts" } },
    { action: "iam.account.read", resource: { kind: "ACCOUNT", id: "accounts" } },
    { action: "iam.account.alias-set", resource: accountResource },
    { action: "iam.user.list", resource: accountResource },
    { action: "iam.user.create", resource: accountResource },
    { action: "iam.policy.list", resource: accountResource }
  ]);
  if (
    account.id !== user.accountId ||
    (wire.identityKind === "ROOT_IDENTITY") !== (account.rootIdentity.principalId === user.id) ||
    policyAttachments.some((attachment) => attachment.accountId !== user.accountId || attachment.target.id !== user.id) ||
    new Set(policyAttachments.map((attachment) => attachment.id)).size !== policyAttachments.length ||
    new Set(policyAttachments.map((attachment) => attachment.policyId)).size !== policyAttachments.length
  ) throw new Error("INVALID_IAM_RESPONSE");
  return { account, user, identityKind: wire.identityKind, policyAttachments, capabilities };
}

function parseUserAccess(value: unknown): UserAccess {
  const wire = accountRecord(value);
  exactKeys(wire, ["user", "policyAttachments", "capabilities"]);
  if (!Array.isArray(wire.policyAttachments) || wire.policyAttachments.length > 256) throw new Error("INVALID_IAM_RESPONSE");
  const user = parseUser(wire.user);
  const policyAttachments = wire.policyAttachments.map(parsePolicyAttachment);
  if (
    policyAttachments.some((attachment) => attachment.target.id !== user.id || attachment.accountId !== user.accountId) ||
    new Set(policyAttachments.map((attachment) => attachment.id)).size !== policyAttachments.length ||
    new Set(policyAttachments.map((attachment) => attachment.policyId)).size !== policyAttachments.length
  ) throw new Error("INVALID_IAM_RESPONSE");
  const capabilities = parseCapabilities(wire.capabilities, [
    { action: "iam.user.set-status", resource: { kind: "USER", id: user.id } },
    { action: "iam.user.reset-password", resource: { kind: "USER", id: user.id } },
    { action: "iam.policy-attachment.create", resource: { kind: "USER", id: user.id } },
    { action: "iam.platform-policy-attachment.create", resource: { kind: "USER", id: user.id } },
    ...policyAttachments.map((attachment) => ({
      action: attachment.scope === "INSTALLATION" ? "iam.platform-policy-attachment.revoke" as const : "iam.policy-attachment.revoke" as const,
      resource: { kind: "POLICY_ATTACHMENT" as const, id: attachment.id }
    }))
  ]);
  return { user, policyAttachments, capabilities };
}

function parseAccountAccess(value: unknown): AccountAccess {
  const wire = accountRecord(value);
  exactKeys(wire, ["account", "capabilities"]);
  const account = parseAccount(wire.account);
  const capabilities = parseCapabilities(wire.capabilities, [
    { action: "iam.account.set-status", resource: { kind: "ACCOUNT", id: account.id } },
    { action: "iam.account.recover-root-credentials", resource: { kind: "ACCOUNT", id: account.id } }
  ]);
  return { account, capabilities };
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
    return accountPage<UserAccess>(await requestJSON<unknown>(`/api/iam/v1/users${after ? `?after=${encodeURIComponent(after)}` : ""}`, { headers: accountHeaders(credential) }), "UserList", parseUserAccess);
  },
  async listPolicies(credential, platform) {
    return parsePolicyDirectory(await requestJSON<unknown>(platform ? "/api/iam/v1/platform-policies" : "/api/iam/v1/policies", { headers: accountHeaders(credential) }), platform ? "INSTALLATION" : "TENANT");
  },
  async listAccounts(credential, after) {
    return accountPage<AccountAccess>(await requestJSON<unknown>(`/api/iam/v1/accounts${after ? `?after=${encodeURIComponent(after)}` : ""}`, { headers: accountHeaders(credential) }), "AccountList", parseAccountAccess);
  },
  async execute(credential, command) {
    const requestId = requestToken("ui-account-");
    let path: string;
    let body: object;
    switch (command.kind) {
      case "create-user": path = "/api/iam/v1/users"; body = { loginName: command.loginName, displayName: command.displayName, initialPassword: command.initialPassword }; break;
      case "create-account": path = "/api/iam/v1/accounts"; body = { id: command.id, displayName: command.displayName, rootLoginName: command.rootLoginName, rootDisplayName: command.rootDisplayName, initialPassword: command.initialPassword }; break;
      case "set-account-status": path = `/api/iam/v1/accounts/${encodeURIComponent(command.accountId)}:set-status`; body = { status: command.status, resourceVersion: command.resourceVersion }; break;
      case "recover-root-credentials": path = `/api/iam/v1/accounts/${encodeURIComponent(command.accountId)}:recover-root-credentials`; body = { initialPassword: command.initialPassword, resourceVersion: command.resourceVersion }; break;
      case "set-alias": path = "/api/iam/v1/account:alias"; body = { alias: command.alias, resourceVersion: command.resourceVersion }; break;
      case "set-status": path = `/api/iam/v1/users/${encodeURIComponent(command.userId)}:set-status`; body = { status: command.status, resourceVersion: command.resourceVersion }; break;
      case "reset-password": path = `/api/iam/v1/users/${encodeURIComponent(command.userId)}:reset-password`; body = { initialPassword: command.initialPassword, resourceVersion: command.resourceVersion }; break;
      case "create-policy-attachment": path = "/api/iam/v1/policy-attachments"; body = { target: { kind: "USER", id: command.userId }, policyId: command.policyId, policyResourceVersion: command.policyResourceVersion }; break;
      case "revoke-policy-attachment": path = `/api/iam/v1/policy-attachments/${encodeURIComponent(command.attachmentId)}:revoke`; body = { resourceVersion: command.resourceVersion }; break;
    }
    const result = await requestJSON<unknown>(path, { method: "POST", headers: { ...accountHeaders(credential), "Content-Type": "application/json" }, body: JSON.stringify({ ...body, requestId }) });
    if (command.kind === "create-account" || command.kind === "set-alias" || command.kind === "set-account-status" || command.kind === "recover-root-credentials") {
      const parsed = parseAccount(result);
      if (command.kind === "create-account" && (parsed.id !== command.id || parsed.rootIdentity.loginName !== command.rootLoginName)) throw new Error("INVALID_IAM_RESPONSE");
      if (command.kind === "set-alias" && (parsed.loginAlias !== command.alias || parsed.resourceVersion <= command.resourceVersion)) throw new Error("INVALID_IAM_RESPONSE");
      if ((command.kind === "set-account-status" || command.kind === "recover-root-credentials") && (parsed.id !== command.accountId || parsed.resourceVersion <= command.resourceVersion)) throw new Error("INVALID_IAM_RESPONSE");
      if (command.kind === "set-account-status" && parsed.status !== command.status) throw new Error("INVALID_IAM_RESPONSE");
      return;
    }
    if (command.kind === "create-policy-attachment") {
      const attachment = parsePolicyAttachment(result);
      if (attachment.target.id !== command.userId || attachment.policyId !== command.policyId) throw new Error("INVALID_IAM_RESPONSE");
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
    const user = parseUser(result);
    if (command.kind === "create-user" && user.loginName !== command.loginName) throw new Error("INVALID_IAM_RESPONSE");
    if (command.kind !== "create-user" && (user.id !== command.userId || user.resourceVersion <= command.resourceVersion)) throw new Error("INVALID_IAM_RESPONSE");
    if (command.kind === "set-status" && user.status !== command.status) throw new Error("INVALID_IAM_RESPONSE");
    if ((command.kind === "create-user" || command.kind === "reset-password") && !user.mustChangePassword) throw new Error("INVALID_IAM_RESPONSE");
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
