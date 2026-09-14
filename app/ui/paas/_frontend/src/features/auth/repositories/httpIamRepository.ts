import { requestJSON, requestToken } from "@/infrastructure/http/jsonRequest";
import type {
  Account,
  AccountAccess,
  AccountIdentity,
  AccountPolicy,
  ActionCapability,
  CapabilityRestriction,
  DirectoryPage,
  Group,
  GroupAccess,
  GroupDeletion,
  GroupMembership,
  GroupMembershipPage,
  GroupPolicyAttachment,
  IamAction,
  PolicyDirectory,
  PolicyManagement,
  PolicyGrantSource,
  PolicyScope,
  PolicyStatus,
  User,
  UserAccess,
  UserPolicyAttachment
} from "../domain/accounts";
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

function accountIdentifier(value: unknown): string {
  const result = accountText(value);
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(result)) throw new Error("INVALID_IAM_RESPONSE");
  return result;
}

function groupText(value: unknown, minimum: number, maximum: number): string {
  if (typeof value !== "string" || value.trim() !== value || /\p{Cc}/u.test(value) ||
      Array.from(value).length < minimum || Array.from(value).length > maximum) throw new Error("INVALID_IAM_RESPONSE");
  return value;
}

function accountVersion(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1) throw new Error("INVALID_IAM_RESPONSE");
  return value;
}

function accountTimestamp(value: unknown): string {
  const result = accountText(value);
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$/.test(result) || Number.isNaN(Date.parse(result)) ||
      new Date(result).toISOString().slice(0, 19) !== result.slice(0, 19)) {
    throw new Error("INVALID_IAM_RESPONSE");
  }
  return result;
}

function chronologicalTimestamps(created: unknown, updated: unknown) {
  const createdAt = accountTimestamp(created), updatedAt = accountTimestamp(updated);
  const order = (value: string) => value.slice(0, 19) + "." + value.slice(19, -1).slice(1).padEnd(6, "0");
  if (order(updatedAt) < order(createdAt)) throw new Error("INVALID_IAM_RESPONSE");
  return { createdAt, updatedAt };
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
  "iam.account.alias-set", "iam.user.list", "iam.user.create", "iam.policy.list", "iam.user.read",
  "iam.group.list", "iam.group.create", "iam.group.read", "iam.group.update", "iam.group.delete",
  "iam.group-membership.list", "iam.group-membership.create", "iam.group-membership.remove",
  "iam.group-policy-attachment.create", "iam.group-policy-attachment.revoke",
  "iam.user.update", "iam.user.delete", "iam.user.set-status",
  "iam.user.reset-password", "iam.policy-attachment.create", "iam.platform-policy-attachment.create",
  "iam.policy-attachment.revoke", "iam.platform-policy-attachment.revoke"
]);

const capabilityRestrictions = new Set<CapabilityRestriction>([
  "AUTHORITY_REQUIRED", "CURRENT_CREDENTIAL_CHANGE_REQUIRED", "SELF_PROTECTED", "ROOT_IDENTITY_PROTECTED",
  "INSTALLATION_AUTHORITY_PROTECTED", "SYSTEM_ACCOUNT_PROTECTED", "TARGET_DISABLED",
  "TARGET_CREDENTIAL_CHANGE_REQUIRED", "TARGET_MUST_BE_DISABLED"
]);

function capabilityResourceKind(action: IamAction): ActionCapability["resource"]["kind"] {
  if (action === "iam.user.read" || action === "iam.user.update" || action === "iam.user.delete" ||
      action === "iam.user.set-status" || action === "iam.user.reset-password" ||
      action === "iam.policy-attachment.create" || action === "iam.platform-policy-attachment.create") return "USER";
  if (action === "iam.policy-attachment.revoke" || action === "iam.platform-policy-attachment.revoke" || action === "iam.group-policy-attachment.revoke") return "POLICY_ATTACHMENT";
  if (action === "iam.group.read" || action === "iam.group.update" || action === "iam.group.delete" ||
      action === "iam.group-membership.list" || action === "iam.group-membership.create" || action === "iam.group-policy-attachment.create") return "GROUP";
  if (action === "iam.group-membership.remove") return "GROUP_MEMBERSHIP";
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
  return { action, resource: { kind: resource.kind as ActionCapability["resource"]["kind"], id: resource.id }, available: wire.available,
    restrictionReason: wire.available ? null : reason as CapabilityRestriction };
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
  if (required.some((key) => !(key in wire)) || Object.keys(wire).some((key) => !allowed.has(key))) {
    throw new Error("INVALID_IAM_RESPONSE");
  }
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
    id: accountText(wire.id), displayName: accountText(wire.displayName), status: accountStatus(wire.status),
    rootIdentity: { principalId: accountText(root.principalId), loginName: accountText(root.loginName) },
    loginAlias: wire.loginAlias, resourceVersion: accountVersion(wire.resourceVersion)
  };
}

function parseUser(value: unknown): User {
  const wire = accountRecord(value);
  exactKeys(wire, ["apiVersion", "kind", "id", "accountId", "loginName", "displayName", "status", "resourceVersion", "createdAt", "updatedAt"], ["mustChangePassword"]);
  requireAccountKind(wire, "User");
  if (wire.mustChangePassword !== undefined && typeof wire.mustChangePassword !== "boolean") throw new Error("INVALID_IAM_RESPONSE");
  accountTimestamp(wire.createdAt);
  accountTimestamp(wire.updatedAt);
  return { id: accountText(wire.id), accountId: accountText(wire.accountId), loginName: accountText(wire.loginName),
    displayName: accountText(wire.displayName), status: accountStatus(wire.status), mustChangePassword: wire.mustChangePassword === true, resourceVersion: accountVersion(wire.resourceVersion) };
}

function parseAttachment(value: unknown): Omit<UserPolicyAttachment, "target"> & { target: { kind: "USER" | "GROUP"; id: string } } {
  const wire = accountRecord(value);
  exactKeys(wire, ["apiVersion", "kind", "id", "accountId", "target", "policyId", "scope", "resourceVersion", "createdAt", "updatedAt"], ["installationId"]);
  requireAccountKind(wire, "PolicyAttachment");
  const target = accountRecord(wire.target);
  exactKeys(target, ["kind", "id"]);
  const scope = policyScope(wire.scope);
  if ((target.kind !== "USER" && target.kind !== "GROUP") || (target.kind === "GROUP" && scope !== "TENANT") || (scope === "TENANT" && wire.installationId !== undefined) ||
      (scope === "INSTALLATION" && typeof wire.installationId !== "string")) throw new Error("INVALID_IAM_RESPONSE");
  return {
    id: accountIdentifier(wire.id), accountId: accountIdentifier(wire.accountId),
    target: { kind: target.kind, id: accountIdentifier(target.id) }, policyId: accountIdentifier(wire.policyId), scope,
    installationId: scope === "INSTALLATION" ? accountIdentifier(wire.installationId) : null,
    resourceVersion: accountVersion(wire.resourceVersion), ...chronologicalTimestamps(wire.createdAt, wire.updatedAt)
  };
}

function parsePolicyAttachment(value: unknown): UserPolicyAttachment {
  const attachment = parseAttachment(value);
  if (attachment.target.kind !== "USER") throw new Error("INVALID_IAM_RESPONSE");
  return { ...attachment, target: { kind: "USER", id: attachment.target.id } };
}

function parseGroupPolicyAttachment(value: unknown): GroupPolicyAttachment {
  const attachment = parseAttachment(value);
  if (attachment.target.kind !== "GROUP" || attachment.scope !== "TENANT") {
    throw new Error("INVALID_IAM_RESPONSE");
  }
  return { ...attachment, scope: "TENANT", installationId: null, target: { kind: "GROUP", id: attachment.target.id } };
}

function parseGroupMembership(value: unknown): GroupMembership {
  const member = accountRecord(value);
  exactKeys(member, ["apiVersion", "kind", "id", "accountId", "groupId", "userId", "createdBy", "resourceVersion", "createdAt", "updatedAt"], ["removedAt", "removedBy"]);
  requireAccountKind(member, "GroupMembership");
  const membership: GroupMembership = {
    id: accountIdentifier(member.id), accountId: accountIdentifier(member.accountId), groupId: accountIdentifier(member.groupId),
    userId: accountIdentifier(member.userId), createdBy: accountIdentifier(member.createdBy), resourceVersion: accountVersion(member.resourceVersion),
    ...chronologicalTimestamps(member.createdAt, member.updatedAt)
  };
  if (member.removedAt === undefined) {
    if (member.removedBy !== undefined || membership.resourceVersion !== 1 || membership.updatedAt !== membership.createdAt) throw new Error("INVALID_IAM_RESPONSE");
  } else {
    membership.removedAt = accountTimestamp(member.removedAt);
    membership.removedBy = accountIdentifier(member.removedBy);
    if (membership.resourceVersion < 2 || membership.removedAt !== membership.updatedAt) throw new Error("INVALID_IAM_RESPONSE");
  }
  return membership;
}

function parsePolicyGrantSource(value: unknown): PolicyGrantSource {
  const wire = accountRecord(value);
  if (wire.kind === "DIRECT") {
    exactKeys(wire, ["kind", "attachment"]);
    return { kind: "DIRECT", attachment: parsePolicyAttachment(wire.attachment) };
  }
  if (wire.kind !== "GROUP") throw new Error("INVALID_IAM_RESPONSE");
  exactKeys(wire, ["kind", "attachment", "membership"]);
  const attachment = parseGroupPolicyAttachment(wire.attachment);
  const membership = parseGroupMembership(wire.membership);
  if (membership.removedAt !== undefined ||
      membership.accountId !== attachment.accountId || membership.groupId !== attachment.target.id) throw new Error("INVALID_IAM_RESPONSE");
  return { kind: "GROUP", membership, attachment };
}

function parseGroup(value: unknown): Group {
  const wire = accountRecord(value);
  exactKeys(wire, ["apiVersion", "kind", "id", "accountId", "name", "resourceVersion", "createdAt", "updatedAt"], ["description"]);
  requireAccountKind(wire, "Group");
  return { id: accountIdentifier(wire.id), accountId: accountIdentifier(wire.accountId), name: groupText(wire.name, 1, 64),
    description: wire.description === undefined ? "" : groupText(wire.description, 0, 512), resourceVersion: accountVersion(wire.resourceVersion),
    ...chronologicalTimestamps(wire.createdAt, wire.updatedAt) };
}

function parseGroupAccess(value: unknown, accountId: string): GroupAccess {
  const wire = accountRecord(value);
  exactKeys(wire, ["group", "policyAttachments", "capabilities"]);
  const group = parseGroup(wire.group);
  if (group.accountId !== accountId || !Array.isArray(wire.policyAttachments) || wire.policyAttachments.length > 256) throw new Error("INVALID_IAM_RESPONSE");
  const policyAttachments = wire.policyAttachments.map(parseGroupPolicyAttachment);
  if (policyAttachments.some((attachment) => attachment.accountId !== accountId || attachment.target.id !== group.id) ||
      new Set(policyAttachments.map((attachment) => attachment.id)).size !== policyAttachments.length ||
      new Set(policyAttachments.map((attachment) => attachment.policyId)).size !== policyAttachments.length) throw new Error("INVALID_IAM_RESPONSE");
  const resource = { kind: "GROUP" as const, id: group.id };
  const capabilities = parseCapabilities(wire.capabilities, [
    { action: "iam.group.read", resource }, { action: "iam.group.update", resource }, { action: "iam.group.delete", resource },
    { action: "iam.group-membership.list", resource }, { action: "iam.group-membership.create", resource },
    { action: "iam.group-policy-attachment.create", resource },
    ...policyAttachments.map((attachment) => ({ action: "iam.group-policy-attachment.revoke" as const,
      resource: { kind: "POLICY_ATTACHMENT" as const, id: attachment.id } }))
  ]);
  return { group, policyAttachments, capabilities };
}

function parseGroupMembershipPage(value: unknown, accountId: string, groupId: string, after?: string): GroupMembershipPage {
  const wire = accountRecord(value);
  exactKeys(wire, ["apiVersion", "kind", "accountId", "groupId", "items"], ["nextAfter"]);
  requireAccountKind(wire, "GroupMembershipList");
  if (wire.accountId !== accountId || wire.groupId !== groupId || !Array.isArray(wire.items) || wire.items.length > 100) throw new Error("INVALID_IAM_RESPONSE");
  const items = wire.items.map((value) => {
    const item = accountRecord(value);
    exactKeys(item, ["membership", "capabilities"]);
    const membership = parseGroupMembership(item.membership);
    if (membership.accountId !== accountId || membership.groupId !== groupId || membership.removedAt !== undefined) throw new Error("INVALID_IAM_RESPONSE");
    const capabilities = parseCapabilities(item.capabilities, [{ action: "iam.group-membership.remove",
      resource: { kind: "GROUP_MEMBERSHIP", id: membership.id } }]);
    return { membership, capabilities };
  });
  const nextAfter = orderedDirectoryPage(items.map((item) => item.membership.id), wire.nextAfter, after);
  if (new Set(items.map((item) => item.membership.userId)).size !== items.length) throw new Error("INVALID_IAM_RESPONSE");
  return { accountId, groupId, items, nextAfter };
}

function pageCursor(value: unknown): string {
  if (typeof value !== "string" || value.length <= 4 || value.length > 384 || !value.startsWith("ic1.") || /[^A-Za-z0-9_-]/.test(value.slice(4))) throw new Error("INVALID_IAM_RESPONSE");
  return value;
}

function pageQuery(after?: string): string {
  return after === undefined ? "" : `?after=${encodeURIComponent(pageCursor(after))}`;
}

function orderedDirectoryPage(ids: string[], next: unknown, after?: string): string | null {
  if (ids.some((id, index) => id <= (index === 0 ? "" : ids[index - 1]!))) throw new Error("INVALID_IAM_RESPONSE");
  if (next === undefined) return null;
  if (ids.length !== 100 || next === after) throw new Error("INVALID_IAM_RESPONSE");
  return pageCursor(next);
}

function postAccount(credential: string, path: string, body: Record<string, unknown>): Promise<unknown> {
  return requestJSON<unknown>(path, { method: "POST", headers: { ...accountHeaders(credential), "Content-Type": "application/json" }, body: JSON.stringify(body) });
}

function parsePolicy(value: unknown): AccountPolicy {
  const wire = accountRecord(value);
  exactKeys(wire, ["apiVersion", "kind", "id", "management", "displayName", "scope", "status", "defaultVersionId", "resourceVersion", "createdAt", "updatedAt"], ["accountId"]);
  requireAccountKind(wire, "Policy");
  const management = wire.management as PolicyManagement;
  const status = wire.status as PolicyStatus;
  const scope = policyScope(wire.scope);
  if ((management !== "SYSTEM" && management !== "CUSTOMER") || (status !== "ACTIVE" && status !== "RETIRED") ||
      (management === "SYSTEM" && (wire.accountId !== undefined || !String(wire.id).startsWith("system."))) ||
      (management === "CUSTOMER" && (typeof wire.accountId !== "string" || scope !== "TENANT" || String(wire.id).startsWith("system.")))) {
    throw new Error("INVALID_IAM_RESPONSE");
  }
  return {
    id: accountText(wire.id), management, accountId: management === "CUSTOMER" ? accountText(wire.accountId) : null,
    displayName: accountText(wire.displayName), scope, status, defaultVersionId: accountText(wire.defaultVersionId),
    resourceVersion: accountVersion(wire.resourceVersion), createdAt: accountTimestamp(wire.createdAt), updatedAt: accountTimestamp(wire.updatedAt)
  };
}

function parsePolicyDirectory(value: unknown, expectedScope: PolicyScope): PolicyDirectory {
  const wire = accountRecord(value);
  exactKeys(wire, ["apiVersion", "kind", "accountId", "scope", "items"], ["installationId"]);
  requireAccountKind(wire, "PolicyList");
  if (wire.scope !== expectedScope || !Array.isArray(wire.items) || wire.items.length > 256 ||
      (expectedScope === "TENANT" && wire.installationId !== undefined) ||
      (expectedScope === "INSTALLATION" && typeof wire.installationId !== "string")) throw new Error("INVALID_IAM_RESPONSE");
  const accountId = accountText(wire.accountId);
  const items = wire.items.map(parsePolicy);
  if (items.some((policy) => policy.scope !== expectedScope || (policy.accountId !== null && policy.accountId !== accountId)) ||
      items.some((policy, index) => index > 0 && items[index - 1]!.id >= policy.id) ||
      new Set(items.map((policy) => policy.id)).size !== items.length) throw new Error("INVALID_IAM_RESPONSE");
  return { accountId, scope: expectedScope, installationId: expectedScope === "INSTALLATION" ? accountText(wire.installationId) : null, items };
}

function parseAccountIdentity(value: unknown): AccountIdentity {
  const wire = accountRecord(value);
  exactKeys(wire, ["apiVersion", "kind", "account", "user", "identityKind", "policySources", "capabilities"]);
  requireAccountKind(wire, "CurrentIdentity");
  if (!Array.isArray(wire.policySources) || wire.policySources.length > 256 ||
      (wire.identityKind !== "ROOT_IDENTITY" && wire.identityKind !== "USER")) throw new Error("INVALID_IAM_RESPONSE");
  const account = parseAccount(wire.account);
  const user = parseUser(wire.user);
  const policySources = wire.policySources.map(parsePolicyGrantSource);
  const accountResource = { kind: "ACCOUNT" as const, id: account.id };
  const capabilities = parseCapabilities(wire.capabilities, [
    { action: "iam.account.create", resource: { kind: "ACCOUNT", id: "accounts" } },
    { action: "iam.account.read", resource: { kind: "ACCOUNT", id: "accounts" } },
    { action: "iam.account.alias-set", resource: accountResource },
    { action: "iam.user.list", resource: accountResource },
    { action: "iam.user.create", resource: accountResource },
    { action: "iam.policy.list", resource: accountResource },
    { action: "iam.group.list", resource: accountResource },
    { action: "iam.group.create", resource: accountResource }
  ]);
  if (account.id !== user.accountId ||
      (wire.identityKind === "ROOT_IDENTITY") !== (account.rootIdentity.principalId === user.id) ||
      policySources.some((source) => source.attachment.accountId !== user.accountId ||
        (source.kind === "DIRECT" ? source.attachment.target.id !== user.id : source.membership.userId !== user.id || wire.identityKind !== "USER")) ||
      policySources.some((source, index) => index > 0 && policySources[index - 1]!.attachment.id >= source.attachment.id)) {
    throw new Error("INVALID_IAM_RESPONSE");
  }
  return { account, user, identityKind: wire.identityKind, policySources, capabilities };
}

function parseUserAccess(value: unknown): UserAccess {
  const wire = accountRecord(value);
  exactKeys(wire, ["user", "policyAttachments", "capabilities"]);
  if (!Array.isArray(wire.policyAttachments) || wire.policyAttachments.length > 256) throw new Error("INVALID_IAM_RESPONSE");
  const user = parseUser(wire.user);
  const policyAttachments = wire.policyAttachments.map(parsePolicyAttachment);
  if (policyAttachments.some((attachment) => attachment.target.id !== user.id || attachment.accountId !== user.accountId) ||
      new Set(policyAttachments.map((attachment) => attachment.id)).size !== policyAttachments.length ||
      new Set(policyAttachments.map((attachment) => attachment.policyId)).size !== policyAttachments.length) throw new Error("INVALID_IAM_RESPONSE");
  const capabilities = parseCapabilities(wire.capabilities, [
    { action: "iam.user.read", resource: { kind: "USER", id: user.id } },
    { action: "iam.user.update", resource: { kind: "USER", id: user.id } },
    { action: "iam.user.delete", resource: { kind: "USER", id: user.id } },
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

function accountPage<T>(value: unknown, kind: string, parse: (item: unknown) => T, identifier: (item: T) => string, after?: string): DirectoryPage<T> {
  const wire = accountRecord(value);
  exactKeys(wire, ["apiVersion", "kind", "items"], ["nextAfter"]);
  requireAccountKind(wire, kind);
  if (!Array.isArray(wire.items) || wire.items.length > 100) throw new Error("INVALID_IAM_RESPONSE");
  const items = wire.items.map(parse);
  return { items, nextAfter: orderedDirectoryPage(items.map(identifier), wire.nextAfter, after) };
}

function accountHeaders(credential: string): HeadersInit { return { Authorization: `Bearer ${credential}` }; }

export const httpAccountRepository: AccountRepository = {
  async currentIdentity(credential) {
    return parseAccountIdentity(await requestJSON<unknown>("/api/iam/v1/auth/me", { headers: accountHeaders(credential) }));
  },
  async listUsers(credential, after) {
    return accountPage<UserAccess>(await requestJSON<unknown>(`/api/iam/v1/users${pageQuery(after)}`, { headers: accountHeaders(credential) }), "UserList", parseUserAccess, (item) => item.user.id, after);
  },
  async listPolicies(credential, platform) {
    return parsePolicyDirectory(await requestJSON<unknown>(
      platform ? "/api/iam/v1/platform-policies" : "/api/iam/v1/policies",
      { headers: accountHeaders(credential) }
    ), platform ? "INSTALLATION" : "TENANT");
  },
  async listAccounts(credential, after) {
    return accountPage(await requestJSON<unknown>(`/api/iam/v1/accounts${pageQuery(after)}`, { headers: accountHeaders(credential) }), "AccountList", parseAccountAccess, (item) => item.account.id, after);
  },
  async listGroups(credential, accountId, after) {
    const wire = accountRecord(await requestJSON<unknown>(`/api/iam/v1/groups${pageQuery(after)}`, { headers: accountHeaders(credential) }));
    exactKeys(wire, ["apiVersion", "kind", "items"], ["nextAfter"]);
    requireAccountKind(wire, "GroupList");
    if (!Array.isArray(wire.items) || wire.items.length > 100) throw new Error("INVALID_IAM_RESPONSE");
    const items = wire.items.map((item) => parseGroupAccess(item, accountId));
    return { items, nextAfter: orderedDirectoryPage(items.map((item) => item.group.id), wire.nextAfter, after) };
  },
  async getGroup(credential, accountId, groupId) {
    const access = parseGroupAccess(await requestJSON<unknown>(`/api/iam/v1/groups/${encodeURIComponent(groupId)}`, { headers: accountHeaders(credential) }), accountId);
    if (access.group.id !== groupId) throw new Error("INVALID_IAM_RESPONSE");
    return access;
  },
  async createGroup(credential, accountId, command) {
    const group = parseGroup(await postAccount(credential, "/api/iam/v1/groups", {
      name: command.name, description: command.description, requestId: command.requestId
    }));
    if (group.accountId !== accountId || group.name !== command.name || group.description !== (command.description ?? "") ||
        group.resourceVersion !== 1 || group.updatedAt !== group.createdAt) throw new Error("INVALID_IAM_RESPONSE");
    return group;
  },
  async updateGroup(credential, accountId, groupId, command) {
    const group = parseGroup(await postAccount(credential, `/api/iam/v1/groups/${encodeURIComponent(groupId)}:update`, {
      name: command.name, description: command.description, resourceVersion: command.resourceVersion, requestId: command.requestId
    }));
    if (group.accountId !== accountId || group.id !== groupId || group.name !== command.name || group.description !== (command.description ?? "") ||
        group.resourceVersion !== command.resourceVersion + 1) throw new Error("INVALID_IAM_RESPONSE");
    return group;
  },
  async deleteGroup(credential, accountId, groupId, command) {
    const wire = accountRecord(await postAccount(credential, `/api/iam/v1/groups/${encodeURIComponent(groupId)}:delete`, {
      resourceVersion: command.resourceVersion, requestId: command.requestId
    }));
    exactKeys(wire, ["apiVersion", "kind", "accountId", "id", "name", "resourceVersion", "removedMemberships", "revokedPolicyAttachments", "deletedAt"]);
    requireAccountKind(wire, "GroupDeletion");
    const count = (value: unknown) => {
      if (typeof value !== "number" || !Number.isInteger(value) || value < 0 || value > 4294967295) throw new Error("INVALID_IAM_RESPONSE");
      return value;
    };
    const result: GroupDeletion = { id: accountIdentifier(wire.id), accountId: accountIdentifier(wire.accountId), name: groupText(wire.name, 1, 64),
      resourceVersion: accountVersion(wire.resourceVersion), deletedAt: accountTimestamp(wire.deletedAt),
      removedMemberships: count(wire.removedMemberships), revokedPolicyAttachments: count(wire.revokedPolicyAttachments) };
    if (result.id !== groupId || result.accountId !== accountId || result.resourceVersion !== command.resourceVersion + 1) throw new Error("INVALID_IAM_RESPONSE");
    return result;
  },
  async listGroupMemberships(credential, accountId, groupId, after) {
    return parseGroupMembershipPage(await requestJSON<unknown>(`/api/iam/v1/groups/${encodeURIComponent(groupId)}/memberships${pageQuery(after)}`,
      { headers: accountHeaders(credential) }), accountId, groupId, after);
  },
  async createGroupMembership(credential, accountId, groupId, command) {
    const membership = parseGroupMembership(await postAccount(credential, `/api/iam/v1/groups/${encodeURIComponent(groupId)}/memberships`, {
      userId: command.userId, requestId: command.requestId
    }));
    if (membership.accountId !== accountId || membership.groupId !== groupId || membership.userId !== command.userId || membership.removedAt !== undefined) {
      throw new Error("INVALID_IAM_RESPONSE");
    }
    return membership;
  },
  async removeGroupMembership(credential, accountId, groupId, membershipId, command) {
    const membership = parseGroupMembership(await postAccount(credential, `/api/iam/v1/groups/${encodeURIComponent(groupId)}/memberships/${encodeURIComponent(membershipId)}:remove`, {
      resourceVersion: command.resourceVersion, requestId: command.requestId
    }));
    if (membership.accountId !== accountId || membership.groupId !== groupId || membership.id !== membershipId || membership.removedAt === undefined ||
        membership.resourceVersion !== command.resourceVersion + 1) throw new Error("INVALID_IAM_RESPONSE");
    return membership;
  },
  async createGroupPolicyAttachment(credential, accountId, groupId, command) {
    const attachment = parseGroupPolicyAttachment(await postAccount(credential, "/api/iam/v1/policy-attachments", {
      target: { kind: "GROUP", id: groupId }, policyId: command.policyId, policyResourceVersion: command.policyResourceVersion, requestId: command.requestId
    }));
    if (attachment.accountId !== accountId || attachment.target.id !== groupId || attachment.policyId !== command.policyId) throw new Error("INVALID_IAM_RESPONSE");
    return attachment;
  },
  async revokePolicyAttachment(credential, attachmentId, command) {
    const wire = accountRecord(await postAccount(credential, `/api/iam/v1/policy-attachments/${encodeURIComponent(attachmentId)}:revoke`, {
      resourceVersion: command.resourceVersion, requestId: command.requestId
    }));
    exactKeys(wire, ["apiVersion", "kind", "id", "resourceVersion", "revokedAt"]);
    requireAccountKind(wire, "Revocation");
    const result = { id: accountIdentifier(wire.id), resourceVersion: accountVersion(wire.resourceVersion), revokedAt: accountTimestamp(wire.revokedAt) };
    if (result.id !== attachmentId || result.resourceVersion !== command.resourceVersion + 1) throw new Error("INVALID_IAM_RESPONSE");
    return result;
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
      case "update-user": path = `/api/iam/v1/users/${encodeURIComponent(command.userId)}:update`; body = { displayName: command.displayName, resourceVersion: command.resourceVersion }; break;
      case "delete-user": path = `/api/iam/v1/users/${encodeURIComponent(command.userId)}:delete`; body = { resourceVersion: command.resourceVersion }; break;
      case "set-status": path = `/api/iam/v1/users/${encodeURIComponent(command.userId)}:set-status`; body = { status: command.status, resourceVersion: command.resourceVersion }; break;
      case "reset-password": path = `/api/iam/v1/users/${encodeURIComponent(command.userId)}:reset-password`; body = { initialPassword: command.initialPassword, resourceVersion: command.resourceVersion }; break;
      case "create-policy-attachment": path = "/api/iam/v1/policy-attachments"; body = { target: { kind: "USER", id: command.userId }, policyId: command.policyId, policyResourceVersion: command.policyResourceVersion }; break;
      case "revoke-policy-attachment": path = `/api/iam/v1/policy-attachments/${encodeURIComponent(command.attachmentId)}:revoke`; body = { resourceVersion: command.resourceVersion }; break;
    }
    const result = await requestJSON<unknown>(path, { method: "POST", headers: { ...accountHeaders(credential), "Content-Type": "application/json" }, body: JSON.stringify({ ...body, requestId }) });
    if (command.kind === "create-account" || command.kind === "set-alias" || command.kind === "set-account-status" || command.kind === "recover-root-credentials") {
      const account = parseAccount(result);
      if (command.kind === "create-account" && (account.id !== command.id || account.rootIdentity.loginName !== command.rootLoginName)) throw new Error("INVALID_IAM_RESPONSE");
      if (command.kind === "set-alias" && (account.loginAlias !== command.alias || account.resourceVersion <= command.resourceVersion)) throw new Error("INVALID_IAM_RESPONSE");
      if ((command.kind === "set-account-status" || command.kind === "recover-root-credentials") &&
          (account.id !== command.accountId || account.resourceVersion <= command.resourceVersion)) throw new Error("INVALID_IAM_RESPONSE");
      if (command.kind === "set-account-status" && account.status !== command.status) throw new Error("INVALID_IAM_RESPONSE");
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
    if (command.kind === "delete-user") {
      const wire = accountRecord(result);
      exactKeys(wire, ["apiVersion", "kind", "accountId", "id", "loginName", "resourceVersion", "deletedAt"]);
      requireAccountKind(wire, "UserDeletion");
      if (wire.id !== command.userId || typeof wire.accountId !== "string" || !wire.accountId.length ||
          typeof wire.loginName !== "string" || !wire.loginName.length || accountVersion(wire.resourceVersion) !== command.resourceVersion + 1) {
        throw new Error("INVALID_IAM_RESPONSE");
      }
      accountTimestamp(wire.deletedAt);
      return;
    }
    const user = parseUser(result);
    if (command.kind === "create-user" && user.loginName !== command.loginName) throw new Error("INVALID_IAM_RESPONSE");
    if (command.kind !== "create-user" && (user.id !== command.userId || user.resourceVersion <= command.resourceVersion)) throw new Error("INVALID_IAM_RESPONSE");
    if (command.kind === "update-user" && user.displayName !== command.displayName) throw new Error("INVALID_IAM_RESPONSE");
    if (command.kind === "set-status" && user.status !== command.status) throw new Error("INVALID_IAM_RESPONSE");
    if ((command.kind === "create-user" || command.kind === "reset-password") && !user.mustChangePassword) throw new Error("INVALID_IAM_RESPONSE");
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
