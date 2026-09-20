import { requestJSON, requestToken } from "@/infrastructure/http/jsonRequest";
import type {
  Account,
  AccountAccess,
  AccountIdentity,
  AccountPolicy,
  ActionCapability,
  AuthorizationAuthorityScope,
  AuthorizationProfile,
  AuthorizationProfileAction,
  AuthorizationProfileCondition,
  AuthorizationProfileDirectory,
  AuthorizationResourceShape,
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
  PolicyGrantSource,
  PolicyManagement,
  PolicyScope,
  PolicyStatus,
  User,
  UserAccess,
  UserPolicyAttachment,
  UserPermissionBoundary
} from "../domain/accounts";
import type { AuthenticationChallenge, LoginResult, OtherSessionsRevocation, OwnSessionPage, OwnSessionRevocation, SessionSummary } from "../domain/session";
import type { AccessKeyAccess, AccessKeyCreation, AccessKeyDeletion, AccessKeyDirectory, AccessKeyStatus, AccessKeyStatusChange, ManagedAccessKey } from "../domain/accessKeys";
import type { ChangePasswordCommand, AccountRepository, IamRepository, LoginCommand } from "./iamRepository";

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
      new Date(result).toISOString().slice(0, 19) !== result.slice(0, 19)) throw new Error("INVALID_IAM_RESPONSE");
  return result;
}

function timestampOrder(value: string): string {
  return value.slice(0, 19) + "." + value.slice(19, -1).slice(1).padEnd(6, "0");
}

function chronologicalTimestamps(created: unknown, updated: unknown) {
  const createdAt = accountTimestamp(created);
  const updatedAt = accountTimestamp(updated);
  if (timestampOrder(updatedAt) < timestampOrder(createdAt)) throw new Error("INVALID_IAM_RESPONSE");
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
  "iam.user.permission-boundary.set", "iam.user.permission-boundary.remove",
  "iam.user.reset-password", "iam.policy-attachment.create", "iam.platform-policy-attachment.create",
  "iam.policy-attachment.revoke", "iam.platform-policy-attachment.revoke",
  "iam.access-key.list", "iam.access-key.create", "iam.access-key.read", "iam.access-key.set-status", "iam.access-key.delete"
]);

const capabilityRestrictions = new Set<CapabilityRestriction>([
  "AUTHORITY_REQUIRED", "CURRENT_CREDENTIAL_CHANGE_REQUIRED", "SELF_PROTECTED", "ROOT_IDENTITY_PROTECTED",
  "INSTALLATION_AUTHORITY_PROTECTED", "SYSTEM_ACCOUNT_PROTECTED", "TARGET_DISABLED",
  "TARGET_CREDENTIAL_CHANGE_REQUIRED", "TARGET_MUST_BE_DISABLED", "ACCESS_KEY_LIMIT_REACHED", "RESOURCE_VERSION_EXHAUSTED"
]);

function capabilityResourceKind(action: IamAction): ActionCapability["resource"]["kind"] {
  if (action === "iam.access-key.read" || action === "iam.access-key.set-status" || action === "iam.access-key.delete") return "ACCESS_KEY";
  if (action === "iam.user.read" || action === "iam.user.update" || action === "iam.user.delete" ||
      action === "iam.user.permission-boundary.set" || action === "iam.user.permission-boundary.remove" ||
      action === "iam.user.set-status" || action === "iam.user.reset-password" ||
      action === "iam.policy-attachment.create" || action === "iam.platform-policy-attachment.create" ||
      action === "iam.access-key.list" || action === "iam.access-key.create") return "USER";
  if (action === "iam.policy-attachment.revoke" || action === "iam.platform-policy-attachment.revoke" ||
      action === "iam.group-policy-attachment.revoke") return "POLICY_ATTACHMENT";
  if (action === "iam.group.read" || action === "iam.group.update" || action === "iam.group.delete" ||
      action === "iam.group-membership.list" || action === "iam.group-membership.create" ||
      action === "iam.group-policy-attachment.create") return "GROUP";
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

function parseAttachment(value: unknown): Omit<UserPolicyAttachment, "target"> & {
  target: { kind: "USER" | "GROUP"; id: string };
} {
  const wire = accountRecord(value);
  exactKeys(wire, ["apiVersion", "kind", "id", "accountId", "target", "policyId", "scope", "resourceVersion", "createdAt", "updatedAt"], ["installationId"]);
  requireAccountKind(wire, "PolicyAttachment");
  const target = accountRecord(wire.target);
  exactKeys(target, ["kind", "id"]);
  const scope = policyScope(wire.scope);
  if ((target.kind !== "USER" && target.kind !== "GROUP") ||
      (target.kind === "GROUP" && scope !== "TENANT") ||
      (scope === "TENANT" && wire.installationId !== undefined) ||
      (scope === "INSTALLATION" && typeof wire.installationId !== "string")) throw new Error("INVALID_IAM_RESPONSE");
  return {
    id: accountIdentifier(wire.id),
    accountId: accountIdentifier(wire.accountId),
    target: { kind: target.kind, id: accountIdentifier(target.id) },
    policyId: accountIdentifier(wire.policyId),
    scope,
    installationId: scope === "INSTALLATION" ? accountIdentifier(wire.installationId) : null,
    resourceVersion: accountVersion(wire.resourceVersion),
    ...chronologicalTimestamps(wire.createdAt, wire.updatedAt)
  };
}

function parsePolicyAttachment(value: unknown): UserPolicyAttachment {
  const attachment = parseAttachment(value);
  if (attachment.target.kind !== "USER") throw new Error("INVALID_IAM_RESPONSE");
  return { ...attachment, target: { kind: "USER", id: attachment.target.id } };
}

function parseGroupPolicyAttachment(value: unknown): GroupPolicyAttachment {
  const attachment = parseAttachment(value);
  if (attachment.target.kind !== "GROUP" || attachment.scope !== "TENANT") throw new Error("INVALID_IAM_RESPONSE");
  return {
    ...attachment,
    scope: "TENANT",
    installationId: null,
    target: { kind: "GROUP", id: attachment.target.id }
  };
}

function parseGroupMembership(value: unknown): GroupMembership {
  const wire = accountRecord(value);
  exactKeys(
    wire,
    ["apiVersion", "kind", "id", "accountId", "groupId", "userId", "createdBy", "resourceVersion", "createdAt", "updatedAt"],
    ["removedAt", "removedBy"]
  );
  requireAccountKind(wire, "GroupMembership");
  const membership: GroupMembership = {
    id: accountIdentifier(wire.id),
    accountId: accountIdentifier(wire.accountId),
    groupId: accountIdentifier(wire.groupId),
    userId: accountIdentifier(wire.userId),
    createdBy: accountIdentifier(wire.createdBy),
    resourceVersion: accountVersion(wire.resourceVersion),
    ...chronologicalTimestamps(wire.createdAt, wire.updatedAt)
  };
  if (wire.removedAt === undefined) {
    if (wire.removedBy !== undefined || membership.resourceVersion !== 1 || membership.updatedAt !== membership.createdAt) {
      throw new Error("INVALID_IAM_RESPONSE");
    }
  } else {
    membership.removedAt = accountTimestamp(wire.removedAt);
    membership.removedBy = accountIdentifier(wire.removedBy);
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
  if (membership.removedAt !== undefined || membership.accountId !== attachment.accountId ||
      membership.groupId !== attachment.target.id) throw new Error("INVALID_IAM_RESPONSE");
  return { kind: "GROUP", membership, attachment };
}

function parseGroup(value: unknown): Group {
  const wire = accountRecord(value);
  exactKeys(wire, ["apiVersion", "kind", "id", "accountId", "name", "resourceVersion", "createdAt", "updatedAt"], ["description"]);
  requireAccountKind(wire, "Group");
  return {
    id: accountIdentifier(wire.id),
    accountId: accountIdentifier(wire.accountId),
    name: groupText(wire.name, 1, 64),
    description: wire.description === undefined ? "" : groupText(wire.description, 0, 512),
    resourceVersion: accountVersion(wire.resourceVersion),
    ...chronologicalTimestamps(wire.createdAt, wire.updatedAt)
  };
}

function parseManagedAccessKey(value: unknown): ManagedAccessKey {
  const wire = accountRecord(value);
  exactKeys(wire, ["apiVersion", "kind", "id", "accountId", "userId", "status", "resourceVersion", "createdAt", "updatedAt"]);
  requireAccountKind(wire, "AccessKey");
  if (wire.status !== "ENABLED" && wire.status !== "DISABLED") throw new Error("INVALID_IAM_RESPONSE");
  const resourceVersion = accountVersion(wire.resourceVersion);
  if (resourceVersion === 1 && wire.status !== "ENABLED") throw new Error("INVALID_IAM_RESPONSE");
  return {
    id: accountIdentifier(wire.id),
    accountId: accountIdentifier(wire.accountId),
    userId: accountIdentifier(wire.userId),
    status: wire.status,
    resourceVersion,
    ...chronologicalTimestamps(wire.createdAt, wire.updatedAt)
  };
}

function accessKeyCapabilities(accessKeyId: string): Array<Pick<ActionCapability, "action" | "resource">> {
  return (["iam.access-key.read", "iam.access-key.set-status", "iam.access-key.delete"] as const).map((action) => ({
    action,
    resource: { kind: "ACCESS_KEY" as const, id: accessKeyId }
  }));
}

function parseAccessKeyAccess(value: unknown, accountId: string, userId: string, accessKeyId?: string): AccessKeyAccess {
  const wire = accountRecord(value);
  exactKeys(wire, ["key", "capabilities"]);
  const key = parseManagedAccessKey(wire.key);
  if (key.accountId !== accountId || key.userId !== userId || (accessKeyId !== undefined && key.id !== accessKeyId)) {
    throw new Error("INVALID_IAM_RESPONSE");
  }
  return { key, capabilities: parseCapabilities(wire.capabilities, accessKeyCapabilities(key.id)) };
}

function parseAccessKeyDirectory(value: unknown, accountId: string, userId: string): AccessKeyDirectory {
  const wire = accountRecord(value);
  exactKeys(wire, ["apiVersion", "kind", "accountId", "userId", "userResourceVersion", "capabilities", "items"]);
  requireAccountKind(wire, "AccessKeyList");
  if (wire.accountId !== accountId || wire.userId !== userId || !Array.isArray(wire.items) || wire.items.length > 2) {
    throw new Error("INVALID_IAM_RESPONSE");
  }
  const items = wire.items.map((item) => parseAccessKeyAccess(item, accountId, userId));
  if (items.some((item, index) => index > 0 && items[index - 1]!.key.id >= item.key.id)) throw new Error("INVALID_IAM_RESPONSE");
  return {
    accountId,
    userId,
    userResourceVersion: accountVersion(wire.userResourceVersion),
    capabilities: parseCapabilities(wire.capabilities, [{ action: "iam.access-key.create", resource: { kind: "USER", id: userId } }]),
    items
  };
}

function parseAccessKeyCreation(value: unknown, accountId: string, userId: string): AccessKeyCreation {
  const wire = accountRecord(value);
  if (wire.outcome === "APPLIED") {
    exactKeys(wire, ["outcome", "key", "secret"]);
    if (typeof wire.secret !== "string" || wire.secret.length < 1 || wire.secret.length > 16384) throw new Error("INVALID_IAM_RESPONSE");
    const key = parseManagedAccessKey(wire.key);
    if (key.accountId !== accountId || key.userId !== userId || key.resourceVersion !== 1 || key.status !== "ENABLED") throw new Error("INVALID_IAM_RESPONSE");
    return { outcome: "APPLIED", key, secret: wire.secret };
  }
  if (wire.outcome !== "EQUAL_REPLAY") throw new Error("INVALID_IAM_RESPONSE");
  exactKeys(wire, ["outcome", "key"]);
  const key = parseManagedAccessKey(wire.key);
  if (key.accountId !== accountId || key.userId !== userId || key.resourceVersion !== 1 || key.status !== "ENABLED") throw new Error("INVALID_IAM_RESPONSE");
  return { outcome: "EQUAL_REPLAY", key };
}

function parseAccessKeyStatusChange(value: unknown, accountId: string, userId: string, accessKeyId: string, commandVersion: number, status: AccessKeyStatus): AccessKeyStatusChange {
  const wire = accountRecord(value);
  exactKeys(wire, ["outcome", "key"]);
  if (wire.outcome !== "APPLIED" && wire.outcome !== "EQUAL_REPLAY") throw new Error("INVALID_IAM_RESPONSE");
  const key = parseManagedAccessKey(wire.key);
  if (key.accountId !== accountId || key.userId !== userId || key.id !== accessKeyId || key.status !== status || key.resourceVersion !== commandVersion + 1) {
    throw new Error("INVALID_IAM_RESPONSE");
  }
  return { outcome: wire.outcome, key };
}

function parseAccessKeyDeletion(value: unknown, accountId: string, userId: string, accessKeyId: string, commandVersion: number): AccessKeyDeletion {
  const wire = accountRecord(value);
  exactKeys(wire, ["outcome", "deletion"]);
  if (wire.outcome !== "APPLIED" && wire.outcome !== "EQUAL_REPLAY") throw new Error("INVALID_IAM_RESPONSE");
  const deletion = accountRecord(wire.deletion);
  exactKeys(deletion, ["apiVersion", "kind", "id", "accountId", "userId", "resourceVersion", "deletedAt"]);
  requireAccountKind(deletion, "AccessKeyDeletion");
  const result = {
    id: accountIdentifier(deletion.id),
    accountId: accountIdentifier(deletion.accountId),
    userId: accountIdentifier(deletion.userId),
    resourceVersion: accountVersion(deletion.resourceVersion),
    deletedAt: accountTimestamp(deletion.deletedAt)
  };
  if (result.accountId !== accountId || result.userId !== userId || result.id !== accessKeyId || result.resourceVersion !== commandVersion + 1) {
    throw new Error("INVALID_IAM_RESPONSE");
  }
  return { outcome: wire.outcome, deletion: result };
}

function parseGroupAccess(value: unknown, accountId: string): GroupAccess {
  const wire = accountRecord(value);
  exactKeys(wire, ["group", "policyAttachments", "capabilities"]);
  const group = parseGroup(wire.group);
  if (group.accountId !== accountId || !Array.isArray(wire.policyAttachments) || wire.policyAttachments.length > 256) {
    throw new Error("INVALID_IAM_RESPONSE");
  }
  const policyAttachments = wire.policyAttachments.map(parseGroupPolicyAttachment);
  if (policyAttachments.some((attachment) => attachment.accountId !== accountId || attachment.target.id !== group.id) ||
      new Set(policyAttachments.map((attachment) => attachment.id)).size !== policyAttachments.length ||
      new Set(policyAttachments.map((attachment) => attachment.policyId)).size !== policyAttachments.length) {
    throw new Error("INVALID_IAM_RESPONSE");
  }
  const resource = { kind: "GROUP" as const, id: group.id };
  const capabilities = parseCapabilities(wire.capabilities, [
    { action: "iam.group.read", resource },
    { action: "iam.group.update", resource },
    { action: "iam.group.delete", resource },
    { action: "iam.group-membership.list", resource },
    { action: "iam.group-membership.create", resource },
    { action: "iam.group-policy-attachment.create", resource },
    ...policyAttachments.map((attachment) => ({
      action: "iam.group-policy-attachment.revoke" as const,
      resource: { kind: "POLICY_ATTACHMENT" as const, id: attachment.id }
    }))
  ]);
  return { group, policyAttachments, capabilities };
}

function pageCursor(value: unknown): string {
  if (typeof value !== "string" || value.length <= 4 || value.length > 384 || !value.startsWith("ic1.") || /[^A-Za-z0-9_-]/.test(value.slice(4))) throw new Error("INVALID_IAM_RESPONSE");
  return value;
}

function pageQuery(after?: string): string {
  return after === undefined ? "" : `?after=${encodeURIComponent(pageCursor(after))}`;
}

function parseOwnSession(value: unknown): SessionSummary {
  const wire = accountRecord(value);
  exactKeys(wire, ["apiVersion", "kind", "id", "organizationId", "principalId", "status", "issuedAt", "expiresAt"]);
  requireAccountKind(wire, "Session");
  if (wire.status !== "ACTIVE") throw new Error("INVALID_IAM_RESPONSE");
  const issuedAt = accountTimestamp(wire.issuedAt);
  const expiresAt = accountTimestamp(wire.expiresAt);
  if (timestampOrder(issuedAt) >= timestampOrder(expiresAt)) throw new Error("INVALID_IAM_RESPONSE");
  return {
    id: accountIdentifier(wire.id),
    organizationId: accountIdentifier(wire.organizationId),
    principalId: accountIdentifier(wire.principalId),
    status: "ACTIVE",
    issuedAt,
    expiresAt
  };
}

function parseOwnSessionPage(value: unknown): OwnSessionPage {
  const wire = accountRecord(value);
  exactKeys(wire, ["apiVersion", "kind", "accountId", "userId", "currentSessionId", "observedAt", "items"], ["nextCursor"]);
  requireAccountKind(wire, "SessionList");
  if (!Array.isArray(wire.items) || wire.items.length > 100) throw new Error("INVALID_IAM_RESPONSE");
  const accountId = accountIdentifier(wire.accountId);
  const userId = accountIdentifier(wire.userId);
  const currentSessionId = accountIdentifier(wire.currentSessionId);
  const observedAt = accountTimestamp(wire.observedAt);
  const observedOrder = timestampOrder(observedAt);
  const items = wire.items.map(parseOwnSession);
  if (items.some((item, index) =>
    item.organizationId !== accountId ||
    item.principalId !== userId ||
    (index > 0 && items[index - 1]!.id >= item.id) ||
    timestampOrder(item.issuedAt) > observedOrder ||
    timestampOrder(item.expiresAt) <= observedOrder
  )) throw new Error("INVALID_IAM_RESPONSE");
  const nextCursor = wire.nextCursor === undefined ? null : pageCursor(wire.nextCursor);
  if (nextCursor && items.length !== 100) throw new Error("INVALID_IAM_RESPONSE");
  return { accountId, userId, currentSessionId, observedAt, items, nextCursor };
}

function parseOwnSessionRevocation(value: unknown, targetSessionId: string): OwnSessionRevocation {
  const wire = accountRecord(value);
  exactKeys(wire, ["outcome", "revocation"]);
  if (wire.outcome !== "APPLIED" && wire.outcome !== "EQUAL_REPLAY") throw new Error("INVALID_IAM_RESPONSE");
  const revocation = accountRecord(wire.revocation);
  exactKeys(revocation, ["apiVersion", "kind", "id", "resourceVersion", "revokedAt"]);
  requireAccountKind(revocation, "Revocation");
  const id = accountIdentifier(revocation.id);
  if (id !== targetSessionId) throw new Error("INVALID_IAM_RESPONSE");
  return {
    outcome: wire.outcome,
    revocation: {
      id,
      resourceVersion: accountVersion(revocation.resourceVersion),
      revokedAt: accountTimestamp(revocation.revokedAt)
    }
  };
}

function parseOtherSessionsRevocation(value: unknown, requestId: string): OtherSessionsRevocation {
  const wire = accountRecord(value);
  exactKeys(wire, [
    "apiVersion", "kind", "outcome", "accountId", "userId", "currentSessionId",
    "requestId", "revokedCount", "completedAt"
  ]);
  requireAccountKind(wire, "OtherSessionsRevocation");
  if (wire.outcome !== "APPLIED" && wire.outcome !== "EQUAL_REPLAY") throw new Error("INVALID_IAM_RESPONSE");
  if (wire.requestId !== requestId) throw new Error("INVALID_IAM_RESPONSE");
  if (typeof wire.revokedCount !== "number" || !Number.isSafeInteger(wire.revokedCount) || wire.revokedCount < 0) {
    throw new Error("INVALID_IAM_RESPONSE");
  }
  return {
    outcome: wire.outcome,
    accountId: accountIdentifier(wire.accountId),
    userId: accountIdentifier(wire.userId),
    currentSessionId: accountIdentifier(wire.currentSessionId),
    requestId,
    revokedCount: wire.revokedCount,
    completedAt: accountTimestamp(wire.completedAt)
  };
}

function orderedDirectoryPage(ids: string[], next: unknown, after?: string): string | null {
  if (ids.some((id, index) => id <= (index === 0 ? "" : ids[index - 1]!))) throw new Error("INVALID_IAM_RESPONSE");
  if (next === undefined) return null;
  if (ids.length !== 100 || next === after) throw new Error("INVALID_IAM_RESPONSE");
  return pageCursor(next);
}

function parseGroupMembershipPage(value: unknown, accountId: string, groupId: string, after?: string): GroupMembershipPage {
  const wire = accountRecord(value);
  exactKeys(wire, ["apiVersion", "kind", "accountId", "groupId", "items"], ["nextAfter"]);
  requireAccountKind(wire, "GroupMembershipList");
  if (wire.accountId !== accountId || wire.groupId !== groupId || !Array.isArray(wire.items) || wire.items.length > 100) {
    throw new Error("INVALID_IAM_RESPONSE");
  }
  const items = wire.items.map((value) => {
    const item = accountRecord(value);
    exactKeys(item, ["membership", "capabilities"]);
    const membership = parseGroupMembership(item.membership);
    if (membership.accountId !== accountId || membership.groupId !== groupId || membership.removedAt !== undefined) {
      throw new Error("INVALID_IAM_RESPONSE");
    }
    const capabilities = parseCapabilities(item.capabilities, [{
      action: "iam.group-membership.remove",
      resource: { kind: "GROUP_MEMBERSHIP", id: membership.id }
    }]);
    return { membership, capabilities };
  });
  const nextAfter = orderedDirectoryPage(items.map((item) => item.membership.id), wire.nextAfter, after);
  if (new Set(items.map((item) => item.membership.userId)).size !== items.length) throw new Error("INVALID_IAM_RESPONSE");
  return { accountId, groupId, items, nextAfter };
}

function postAccount(credential: string, path: string, body: Record<string, unknown>): Promise<unknown> {
  return requestJSON<unknown>(path, {
    method: "POST",
    headers: { ...accountHeaders(credential), "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });
}

function authorizationIdentifier(value: unknown, upper: boolean): string {
  const text = accountText(value);
  const pattern = upper ? /^[A-Z][A-Z0-9_-]{0,63}$/ : /^[a-z][a-z0-9_-]{0,63}$/;
  if (!pattern.test(text)) throw new Error("INVALID_IAM_RESPONSE");
  return text;
}

function parseAuthorizationCondition(value: unknown): AuthorizationProfileCondition {
  const wire = accountRecord(value);
  exactKeys(wire, ["key", "valueType", "source"]);
  if (wire.key === "iam.current-time" && wire.valueType === "TIME" && wire.source === "IAM_TRANSACTION_TIME") {
    return { key: wire.key, valueType: wire.valueType, source: wire.source };
  }
  if ((wire.key === "iam.account-id" || wire.key === "iam.principal-id") &&
      wire.valueType === "STRING" && wire.source === "IAM_AUTHENTICATED_IDENTITY") {
    return { key: wire.key, valueType: wire.valueType, source: wire.source };
  }
  throw new Error("INVALID_IAM_RESPONSE");
}

function parseAuthorizationShape(value: unknown, scope: AuthorizationAuthorityScope): AuthorizationResourceShape {
  const wire = accountRecord(value);
  exactKeys(wire, ["mode", "prefixAllowed"], ["collectionUsage"]);
  if (typeof wire.prefixAllowed !== "boolean") throw new Error("INVALID_IAM_RESPONSE");
  if (wire.mode === "INSTANCE") {
    if (wire.collectionUsage !== undefined || (scope !== "TENANT" && wire.prefixAllowed)) throw new Error("INVALID_IAM_RESPONSE");
    return { mode: "INSTANCE", prefixAllowed: wire.prefixAllowed };
  }
  if (wire.mode !== "COLLECTION" || wire.prefixAllowed ||
      (wire.collectionUsage !== "COLLECTION_LIST" && wire.collectionUsage !== "COLLECTION_CREATE")) {
    throw new Error("INVALID_IAM_RESPONSE");
  }
  return { mode: "COLLECTION", prefixAllowed: false, collectionUsage: wire.collectionUsage };
}

function parseAuthorizationAction(value: unknown, product: string): AuthorizationProfileAction {
  const wire = accountRecord(value);
  exactKeys(wire, ["action", "resourceKind", "scope", "resourceShapes"], ["conditions", "resultResourceKind"]);
  const action = accountText(wire.action);
  const parts = action.split(".");
  if (!/^[a-z][a-z0-9_-]{0,63}(\.[a-z][a-z0-9_-]{0,63}){1,4}$/.test(action) || action.length > 128 || parts[0] !== product) {
    throw new Error("INVALID_IAM_RESPONSE");
  }
  if (wire.scope !== "TENANT" && wire.scope !== "INSTALLATION" && wire.scope !== "INSTALLATION_PROBE") {
    throw new Error("INVALID_IAM_RESPONSE");
  }
  const scope = wire.scope as AuthorizationAuthorityScope;
  if (!Array.isArray(wire.resourceShapes) || wire.resourceShapes.length < 1 || wire.resourceShapes.length > 3) {
    throw new Error("INVALID_IAM_RESPONSE");
  }
  const resourceShapes = wire.resourceShapes.map((shape) => parseAuthorizationShape(shape, scope));
  const shapeKeys = resourceShapes.map((shape) => `${shape.mode}:${shape.collectionUsage ?? ""}`);
  if (new Set(shapeKeys).size !== shapeKeys.length) throw new Error("INVALID_IAM_RESPONSE");

  const conditionValues = wire.conditions === undefined || wire.conditions === null ? [] : wire.conditions;
  if (!Array.isArray(conditionValues) || conditionValues.length > 3 || (scope !== "TENANT" && conditionValues.length)) {
    throw new Error("INVALID_IAM_RESPONSE");
  }
  const conditions = conditionValues.map(parseAuthorizationCondition);
  if (new Set(conditions.map((condition) => condition.key)).size !== conditions.length) throw new Error("INVALID_IAM_RESPONSE");

  const resultResourceKind = wire.resultResourceKind === undefined ? undefined : authorizationIdentifier(wire.resultResourceKind, true);
  if (resourceShapes.some((shape) => shape.collectionUsage === "COLLECTION_LIST") && resultResourceKind !== undefined ||
      resourceShapes.some((shape) => shape.collectionUsage === "COLLECTION_CREATE") && resultResourceKind === undefined) {
    throw new Error("INVALID_IAM_RESPONSE");
  }
  return {
    action,
    resourceKind: authorizationIdentifier(wire.resourceKind, true),
    scope,
    resourceShapes,
    ...(conditions.length ? { conditions } : {}),
    ...(resultResourceKind === undefined ? {} : { resultResourceKind })
  };
}

function parseAuthorizationProfile(value: unknown): AuthorizationProfile {
  const wire = accountRecord(value);
  exactKeys(wire, ["apiVersion", "kind", "product", "revision", "callingService", "actions"]);
  requireAccountKind(wire, "AuthorizationProfile");
  const product = authorizationIdentifier(wire.product, false);
  if (!Array.isArray(wire.actions) || wire.actions.length < 1 || wire.actions.length > 128) throw new Error("INVALID_IAM_RESPONSE");
  const actions = wire.actions.map((action) => parseAuthorizationAction(action, product));
  if (new Set(actions.map((action) => action.action)).size !== actions.length) throw new Error("INVALID_IAM_RESPONSE");
  return {
    product,
    revision: accountVersion(wire.revision),
    callingService: authorizationIdentifier(wire.callingService, true),
    actions
  };
}

function parseAuthorizationProfileDirectory(value: unknown): AuthorizationProfileDirectory {
  const wire = accountRecord(value);
  exactKeys(wire, ["apiVersion", "kind", "accountId", "items"]);
  requireAccountKind(wire, "AuthorizationProfileList");
  if (!Array.isArray(wire.items) || wire.items.length < 1 || wire.items.length > 16) throw new Error("INVALID_IAM_RESPONSE");
  const items = wire.items.map((value) => {
    const entry = accountRecord(value);
    exactKeys(entry, ["profile", "contentDigest"]);
    if (typeof entry.contentDigest !== "string" || !/^sha256:[a-f0-9]{64}$/.test(entry.contentDigest)) {
      throw new Error("INVALID_IAM_RESPONSE");
    }
    return { profile: parseAuthorizationProfile(entry.profile), contentDigest: entry.contentDigest };
  });
  if (items.some((entry, index) => index > 0 && items[index - 1]!.profile.product >= entry.profile.product)) {
    throw new Error("INVALID_IAM_RESPONSE");
  }
  return { accountId: accountIdentifier(wire.accountId), items };
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

function parseUserPermissionBoundary(value: unknown, accountId: string, userId: string): UserPermissionBoundary {
  const wire = accountRecord(value);
  exactKeys(wire, ["apiVersion", "kind", "accountId", "userId", "resourceVersion", "policy"]);
  requireAccountKind(wire, "UserPermissionBoundary");
  if (accountIdentifier(wire.accountId) !== accountId || accountIdentifier(wire.userId) !== userId) throw new Error("INVALID_IAM_RESPONSE");
  const resourceVersion = accountVersion(wire.resourceVersion);
  if (wire.policy === null) return { accountId, userId, resourceVersion, policy: null };
  const policy = accountRecord(wire.policy);
  exactKeys(policy, ["policyId", "versionId", "contentDigest"]);
  if (typeof policy.contentDigest !== "string" || !/^sha256:[a-f0-9]{64}$/.test(policy.contentDigest)) throw new Error("INVALID_IAM_RESPONSE");
  return { accountId, userId, resourceVersion, policy: {
    policyId: accountIdentifier(policy.policyId),
    versionId: accountIdentifier(policy.versionId),
    contentDigest: policy.contentDigest
  } };
}

function parseAccountIdentity(value: unknown): AccountIdentity {
  const wire = accountRecord(value);
  exactKeys(wire, ["apiVersion", "kind", "account", "user", "identityKind", "policySources", "permissionBoundary", "capabilities"]);
  requireAccountKind(wire, "CurrentIdentity");
  if (!Array.isArray(wire.policySources) || wire.policySources.length > 256 ||
      (wire.identityKind !== "ROOT_IDENTITY" && wire.identityKind !== "USER")) throw new Error("INVALID_IAM_RESPONSE");
  const account = parseAccount(wire.account);
  const user = parseUser(wire.user);
  const permissionBoundary = parseUserPermissionBoundary(wire.permissionBoundary, account.id, user.id);
  const policySources = wire.policySources.map(parsePolicyGrantSource);
  const accountResource = { kind: "ACCOUNT" as const, id: account.id };
  const capabilities = parseCapabilities(wire.capabilities, [
    { action: "iam.account.create", resource: { kind: "ACCOUNT", id: "collection" } },
    { action: "iam.account.read", resource: { kind: "ACCOUNT", id: "collection" } },
    { action: "iam.account.alias-set", resource: accountResource },
    { action: "iam.user.list", resource: accountResource },
    { action: "iam.user.create", resource: accountResource },
    { action: "iam.policy.list", resource: accountResource },
    { action: "iam.group.list", resource: accountResource },
    { action: "iam.group.create", resource: accountResource }
  ]);
  if (
    account.id !== user.accountId ||
    permissionBoundary.resourceVersion !== user.resourceVersion ||
    (wire.identityKind === "ROOT_IDENTITY" && permissionBoundary.policy !== null) ||
    (wire.identityKind === "ROOT_IDENTITY") !== (account.rootIdentity.principalId === user.id) ||
    policySources.some((source) => source.attachment.accountId !== user.accountId ||
      (source.kind === "DIRECT"
        ? source.attachment.target.id !== user.id
        : source.membership.userId !== user.id || wire.identityKind !== "USER")) ||
    policySources.some((source, index) => index > 0 && policySources[index - 1]!.attachment.id >= source.attachment.id)
  ) throw new Error("INVALID_IAM_RESPONSE");
  return { account, user, identityKind: wire.identityKind, policySources, permissionBoundary, capabilities };
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
    { action: "iam.user.read", resource: { kind: "USER", id: user.id } },
    { action: "iam.user.update", resource: { kind: "USER", id: user.id } },
    { action: "iam.user.delete", resource: { kind: "USER", id: user.id } },
    { action: "iam.user.permission-boundary.set", resource: { kind: "USER", id: user.id } },
    { action: "iam.user.permission-boundary.remove", resource: { kind: "USER", id: user.id } },
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
  accessKeys: {
    async list(credential, accountId, userId) {
      const target = accountIdentifier(userId);
      return parseAccessKeyDirectory(await requestJSON<unknown>(
        `/api/iam/v1/users/${encodeURIComponent(target)}/access-keys`,
        { headers: accountHeaders(credential) }
      ), accountIdentifier(accountId), target);
    },
    async read(credential, accountId, userId, accessKeyId) {
      const target = accountIdentifier(userId);
      const keyId = accountIdentifier(accessKeyId);
      return parseAccessKeyAccess(await requestJSON<unknown>(
        `/api/iam/v1/users/${encodeURIComponent(target)}/access-keys/${encodeURIComponent(keyId)}`,
        { headers: accountHeaders(credential) }
      ), accountIdentifier(accountId), target, keyId);
    },
    async create(credential, accountId, userId, command) {
      const target = accountIdentifier(userId);
      const userResourceVersion = accountVersion(command.userResourceVersion);
      return parseAccessKeyCreation(await postAccount(
        credential,
        `/api/iam/v1/users/${encodeURIComponent(target)}/access-keys`,
        { userResourceVersion, requestId: accountIdentifier(command.requestId) }
      ), accountIdentifier(accountId), target);
    },
    async setStatus(credential, accountId, userId, accessKeyId, command) {
      const target = accountIdentifier(userId);
      const keyId = accountIdentifier(accessKeyId);
      const accessKeyResourceVersion = accountVersion(command.accessKeyResourceVersion);
      if (accessKeyResourceVersion === Number.MAX_SAFE_INTEGER || (command.status !== "ENABLED" && command.status !== "DISABLED")) {
        throw new Error("INVALID_IAM_REQUEST");
      }
      return parseAccessKeyStatusChange(await postAccount(
        credential,
        `/api/iam/v1/users/${encodeURIComponent(target)}/access-keys/${encodeURIComponent(keyId)}:set-status`,
        { accessKeyResourceVersion, requestId: accountIdentifier(command.requestId), status: command.status }
      ), accountIdentifier(accountId), target, keyId, accessKeyResourceVersion, command.status);
    },
    async delete(credential, accountId, userId, accessKeyId, command) {
      const target = accountIdentifier(userId);
      const keyId = accountIdentifier(accessKeyId);
      const accessKeyResourceVersion = accountVersion(command.accessKeyResourceVersion);
      if (accessKeyResourceVersion === Number.MAX_SAFE_INTEGER) throw new Error("INVALID_IAM_REQUEST");
      return parseAccessKeyDeletion(await postAccount(
        credential,
        `/api/iam/v1/users/${encodeURIComponent(target)}/access-keys/${encodeURIComponent(keyId)}:delete`,
        { accessKeyResourceVersion, requestId: accountIdentifier(command.requestId) }
      ), accountIdentifier(accountId), target, keyId, accessKeyResourceVersion);
    }
  },
  permissionBoundaries: {
    async read(credential, accountId, userId) {
      return parseUserPermissionBoundary(await requestJSON<unknown>(
        `/api/iam/v1/users/${encodeURIComponent(accountIdentifier(userId))}/permission-boundary`,
        { headers: accountHeaders(credential) }
      ), accountId, userId);
    },
    async set(credential, accountId, userId, command) {
      const resourceVersion = accountVersion(command.resourceVersion);
      if (resourceVersion === Number.MAX_SAFE_INTEGER) throw new Error("INVALID_IAM_REQUEST");
      const result = parseUserPermissionBoundary(await requestJSON<unknown>(
        `/api/iam/v1/users/${encodeURIComponent(accountIdentifier(userId))}/permission-boundary`, {
          method: "PUT", headers: { ...accountHeaders(credential), "Content-Type": "application/json" },
          body: JSON.stringify({ policyId: accountIdentifier(command.policyId), policyResourceVersion: accountVersion(command.policyResourceVersion), resourceVersion, requestId: accountIdentifier(command.requestId) })
        }
      ), accountId, userId);
      if (result.resourceVersion !== resourceVersion + 1 || result.policy?.policyId !== command.policyId) throw new Error("INVALID_IAM_RESPONSE");
      return result;
    },
    async remove(credential, accountId, userId, command) {
      const resourceVersion = accountVersion(command.resourceVersion);
      if (resourceVersion === Number.MAX_SAFE_INTEGER) throw new Error("INVALID_IAM_REQUEST");
      const result = parseUserPermissionBoundary(await requestJSON<unknown>(
        `/api/iam/v1/users/${encodeURIComponent(accountIdentifier(userId))}/permission-boundary`, {
          method: "DELETE", headers: { ...accountHeaders(credential), "Content-Type": "application/json" },
          body: JSON.stringify({ resourceVersion, requestId: accountIdentifier(command.requestId) })
        }
      ), accountId, userId);
      if (result.resourceVersion !== resourceVersion + 1 || result.policy !== null) throw new Error("INVALID_IAM_RESPONSE");
      return result;
    }
  },
  async currentIdentity(credential) {
    return parseAccountIdentity(await requestJSON<unknown>("/api/iam/v1/auth/me", { headers: accountHeaders(credential) }));
  },
  async listUsers(credential, after) {
    return accountPage<UserAccess>(await requestJSON<unknown>(`/api/iam/v1/users${pageQuery(after)}`, { headers: accountHeaders(credential) }), "UserList", parseUserAccess, (item) => item.user.id, after);
  },
  async getUser(credential, userId) {
    const access = parseUserAccess(await requestJSON<unknown>(`/api/iam/v1/users/${encodeURIComponent(userId)}`, { headers: accountHeaders(credential) }));
    if (access.user.id !== userId) throw new Error("INVALID_IAM_RESPONSE");
    return access;
  },
  async listPolicies(credential, platform) {
    return parsePolicyDirectory(await requestJSON<unknown>(platform ? "/api/iam/v1/platform-policies" : "/api/iam/v1/policies", { headers: accountHeaders(credential) }), platform ? "INSTALLATION" : "TENANT");
  },
  async listAuthorizationProfiles(credential) {
    return parseAuthorizationProfileDirectory(await requestJSON<unknown>("/api/iam/v1/authorization-profiles", { headers: accountHeaders(credential) }));
  },
  async listAccounts(credential, after) {
    return accountPage<AccountAccess>(await requestJSON<unknown>(`/api/iam/v1/accounts${pageQuery(after)}`, { headers: accountHeaders(credential) }), "AccountList", parseAccountAccess, (item) => item.account.id, after);
  },
  async listGroups(credential, accountId, after) {
    const wire = accountRecord(await requestJSON<unknown>(
      `/api/iam/v1/groups${pageQuery(after)}`,
      { headers: accountHeaders(credential) }
    ));
    exactKeys(wire, ["apiVersion", "kind", "items"], ["nextAfter"]);
    requireAccountKind(wire, "GroupList");
    if (!Array.isArray(wire.items) || wire.items.length > 100) throw new Error("INVALID_IAM_RESPONSE");
    const items = wire.items.map((item) => parseGroupAccess(item, accountId));
    return { items, nextAfter: orderedDirectoryPage(items.map((item) => item.group.id), wire.nextAfter, after) };
  },
  async getGroup(credential, accountId, groupId) {
    const access = parseGroupAccess(await requestJSON<unknown>(
      `/api/iam/v1/groups/${encodeURIComponent(groupId)}`,
      { headers: accountHeaders(credential) }
    ), accountId);
    if (access.group.id !== groupId) throw new Error("INVALID_IAM_RESPONSE");
    return access;
  },
  async createGroup(credential, accountId, command) {
    const group = parseGroup(await postAccount(credential, "/api/iam/v1/groups", {
      name: command.name,
      description: command.description,
      requestId: command.requestId
    }));
    if (group.accountId !== accountId || group.name !== command.name || group.description !== (command.description ?? "") ||
        group.resourceVersion !== 1 || group.updatedAt !== group.createdAt) throw new Error("INVALID_IAM_RESPONSE");
    return group;
  },
  async updateGroup(credential, accountId, groupId, command) {
    const group = parseGroup(await postAccount(credential, `/api/iam/v1/groups/${encodeURIComponent(groupId)}:update`, {
      name: command.name,
      description: command.description,
      resourceVersion: command.resourceVersion,
      requestId: command.requestId
    }));
    if (group.accountId !== accountId || group.id !== groupId || group.name !== command.name ||
        group.description !== (command.description ?? "") || group.resourceVersion !== command.resourceVersion + 1) {
      throw new Error("INVALID_IAM_RESPONSE");
    }
    return group;
  },
  async deleteGroup(credential, accountId, groupId, command) {
    const wire = accountRecord(await postAccount(credential, `/api/iam/v1/groups/${encodeURIComponent(groupId)}:delete`, {
      resourceVersion: command.resourceVersion,
      requestId: command.requestId
    }));
    exactKeys(wire, ["apiVersion", "kind", "accountId", "id", "name", "resourceVersion", "removedMemberships", "revokedPolicyAttachments", "deletedAt"]);
    requireAccountKind(wire, "GroupDeletion");
    const count = (value: unknown) => {
      if (typeof value !== "number" || !Number.isInteger(value) || value < 0 || value > 4294967295) {
        throw new Error("INVALID_IAM_RESPONSE");
      }
      return value;
    };
    const result: GroupDeletion = {
      id: accountIdentifier(wire.id),
      accountId: accountIdentifier(wire.accountId),
      name: groupText(wire.name, 1, 64),
      resourceVersion: accountVersion(wire.resourceVersion),
      removedMemberships: count(wire.removedMemberships),
      revokedPolicyAttachments: count(wire.revokedPolicyAttachments),
      deletedAt: accountTimestamp(wire.deletedAt)
    };
    if (result.id !== groupId || result.accountId !== accountId || result.resourceVersion !== command.resourceVersion + 1) {
      throw new Error("INVALID_IAM_RESPONSE");
    }
    return result;
  },
  async listGroupMemberships(credential, accountId, groupId, after) {
    return parseGroupMembershipPage(await requestJSON<unknown>(
      `/api/iam/v1/groups/${encodeURIComponent(groupId)}/memberships${pageQuery(after)}`,
      { headers: accountHeaders(credential) }
    ), accountId, groupId, after);
  },
  async createGroupMembership(credential, accountId, groupId, command) {
    const membership = parseGroupMembership(await postAccount(
      credential,
      `/api/iam/v1/groups/${encodeURIComponent(groupId)}/memberships`,
      { userId: command.userId, requestId: command.requestId }
    ));
    if (membership.accountId !== accountId || membership.groupId !== groupId || membership.userId !== command.userId ||
        membership.removedAt !== undefined) throw new Error("INVALID_IAM_RESPONSE");
    return membership;
  },
  async removeGroupMembership(credential, accountId, groupId, membershipId, command) {
    const membership = parseGroupMembership(await postAccount(
      credential,
      `/api/iam/v1/groups/${encodeURIComponent(groupId)}/memberships/${encodeURIComponent(membershipId)}:remove`,
      { resourceVersion: command.resourceVersion, requestId: command.requestId }
    ));
    if (membership.accountId !== accountId || membership.groupId !== groupId || membership.id !== membershipId ||
        membership.removedAt === undefined || membership.resourceVersion !== command.resourceVersion + 1) {
      throw new Error("INVALID_IAM_RESPONSE");
    }
    return membership;
  },
  async createGroupPolicyAttachment(credential, accountId, groupId, command) {
    const attachment = parseGroupPolicyAttachment(await postAccount(credential, "/api/iam/v1/policy-attachments", {
      target: { kind: "GROUP", id: groupId },
      policyId: command.policyId,
      policyResourceVersion: command.policyResourceVersion,
      requestId: command.requestId
    }));
    if (attachment.accountId !== accountId || attachment.target.id !== groupId || attachment.policyId !== command.policyId) {
      throw new Error("INVALID_IAM_RESPONSE");
    }
    return attachment;
  },
  async revokePolicyAttachment(credential, attachmentId, command) {
    const wire = accountRecord(await postAccount(
      credential,
      `/api/iam/v1/policy-attachments/${encodeURIComponent(attachmentId)}:revoke`,
      { resourceVersion: command.resourceVersion, requestId: command.requestId }
    ));
    exactKeys(wire, ["apiVersion", "kind", "id", "resourceVersion", "revokedAt"]);
    requireAccountKind(wire, "Revocation");
    const result = {
      id: accountIdentifier(wire.id),
      resourceVersion: accountVersion(wire.resourceVersion),
      revokedAt: accountTimestamp(wire.revokedAt)
    };
    if (result.id !== attachmentId || result.resourceVersion !== command.resourceVersion + 1) {
      throw new Error("INVALID_IAM_RESPONSE");
    }
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
    if (command.kind === "delete-user") {
      const wire = accountRecord(result);
      exactKeys(wire, ["apiVersion", "kind", "accountId", "id", "loginName", "resourceVersion", "deletedAt"]);
      requireAccountKind(wire, "UserDeletion");
      if (
        wire.id !== command.userId ||
        typeof wire.accountId !== "string" || !wire.accountId.length ||
        typeof wire.loginName !== "string" || !wire.loginName.length ||
        accountVersion(wire.resourceVersion) !== command.resourceVersion + 1
      ) throw new Error("INVALID_IAM_RESPONSE");
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

type ChangePasswordWire = { changedAt?: unknown; bootstrapFileRetirable?: unknown };

function parseActiveSession(value: unknown): SessionSummary {
  const wire = accountRecord(value);
  exactKeys(wire, ["apiVersion", "kind", "id", "organizationId", "principalId", "status", "issuedAt", "expiresAt"]);
  requireAccountKind(wire, "Session");
  if (wire.status !== "ACTIVE") throw new Error("INVALID_IAM_RESPONSE");
  const issuedAt = accountTimestamp(wire.issuedAt);
  const expiresAt = accountTimestamp(wire.expiresAt);
  if (timestampOrder(expiresAt) <= timestampOrder(issuedAt)) throw new Error("INVALID_IAM_RESPONSE");
  return {
    id: accountIdentifier(wire.id),
    organizationId: accountIdentifier(wire.organizationId),
    principalId: accountIdentifier(wire.principalId),
    status: "ACTIVE",
    issuedAt,
    expiresAt
  };
}

function parseAuthenticationChallenge(value: unknown): AuthenticationChallenge {
  const wire = accountRecord(value);
  exactKeys(wire, ["apiVersion", "kind", "id", "purpose", "nextStep", "expiresAt"]);
  requireAccountKind(wire, "AuthenticationChallenge");
  if (wire.purpose !== "LOGIN" || (wire.nextStep !== "TOTP" && wire.nextStep !== "PASSWORD_CHANGE")) {
    throw new Error("INVALID_IAM_RESPONSE");
  }
  return {
    id: accountIdentifier(wire.id),
    purpose: "LOGIN",
    nextStep: wire.nextStep,
    expiresAt: accountTimestamp(wire.expiresAt)
  };
}

function parseLogin(value: unknown): LoginResult {
  const wire = accountRecord(value);
  if (wire.outcome === "AUTHENTICATED") {
    exactKeys(wire, ["outcome", "session", "credential", "mustChangePassword"]);
    if (typeof wire.credential !== "string" || !wire.credential || typeof wire.mustChangePassword !== "boolean") {
      throw new Error("INVALID_IAM_RESPONSE");
    }
    return {
      outcome: "AUTHENTICATED",
      credential: wire.credential,
      mustChangePassword: wire.mustChangePassword,
      session: parseActiveSession(wire.session)
    };
  }
  if (wire.outcome === "CHALLENGE_REQUIRED") {
    exactKeys(wire, ["outcome", "challenge", "challengeCredential"]);
    if (typeof wire.challengeCredential !== "string" || !wire.challengeCredential) throw new Error("INVALID_IAM_RESPONSE");
    return {
      outcome: "CHALLENGE_REQUIRED",
      challenge: parseAuthenticationChallenge(wire.challenge),
      challengeCredential: wire.challengeCredential
    };
  }
  throw new Error("INVALID_IAM_RESPONSE");
}

export const httpIamRepository: IamRepository = {
  async login(command: LoginCommand): Promise<LoginResult> {
    const wire = await requestJSON<unknown>("/api/iam/v1/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ loginName: command.loginName, password: command.password, requestId: requestToken("ui-login-") })
    });
    const result = parseLogin(wire);
    if (result.outcome === "CHALLENGE_REQUIRED" && result.challenge.nextStep !== "TOTP") {
      throw new Error("INVALID_IAM_RESPONSE");
    }
    return result;
  },
  authenticationChallenges: {
    async verify(command) {
      const wire = await requestJSON<unknown>(`/api/iam/v1/auth/challenges/${encodeURIComponent(accountIdentifier(command.challengeId))}:verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          requestId: requestToken("ui-login-challenge-"),
          challengeCredential: command.challengeCredential,
          code: command.code
        })
      });
      const result = parseLogin(wire);
      if (result.outcome === "CHALLENGE_REQUIRED" && result.challenge.nextStep !== "PASSWORD_CHANGE") {
        throw new Error("INVALID_IAM_RESPONSE");
      }
      return result;
    },
    async changePassword(command) {
      const wire = accountRecord(await requestJSON<unknown>(`/api/iam/v1/auth/challenges/${encodeURIComponent(accountIdentifier(command.challengeId))}:password`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          requestId: requestToken("ui-login-password-"),
          challengeCredential: command.challengeCredential,
          newPassword: command.newPassword
        })
      }));
      exactKeys(wire, ["nextStep", "changedAt"]);
      if (wire.nextStep !== "REAUTHENTICATE") throw new Error("INVALID_IAM_RESPONSE");
      return { nextStep: "REAUTHENTICATE", changedAt: accountTimestamp(wire.changedAt) };
    }
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
  },
  sessions: {
    async list(credential: string, after?: string): Promise<OwnSessionPage> {
      return parseOwnSessionPage(await requestJSON<unknown>(
        `/api/iam/v1/auth/sessions${pageQuery(after)}`,
        { headers: accountHeaders(credential) }
      ));
    },
    async revoke(credential: string, targetSessionId: string, requestId: string): Promise<OwnSessionRevocation> {
      const target = accountIdentifier(targetSessionId);
      const request = accountIdentifier(requestId);
      const value = await requestJSON<unknown>(`/api/iam/v1/auth/sessions/${encodeURIComponent(target)}:revoke`, {
        method: "POST",
        headers: { ...accountHeaders(credential), "Content-Type": "application/json" },
        body: JSON.stringify({ requestId: request })
      });
      return parseOwnSessionRevocation(value, target);
    },
    async revokeOthers(credential: string, requestId: string): Promise<OtherSessionsRevocation> {
      const request = accountIdentifier(requestId);
      const value = await requestJSON<unknown>("/api/iam/v1/auth/sessions:revoke-others", {
        method: "POST",
        headers: { ...accountHeaders(credential), "Content-Type": "application/json" },
        body: JSON.stringify({ requestId: request })
      });
      return parseOtherSessionsRevocation(value, request);
    }
  }
};
