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
import type {
  AuthenticationChallenge,
  AuthenticatorRecovery,
  AuthenticatorRecoveryConfirmation,
  AuthenticatorRecoveryStart,
  LoginResult,
  OtherSessionsRevocation,
  OwnSessionPage,
  OwnSessionRevocation,
  SessionSummary
} from "../domain/session";
import type { AccessKeyAccess, AccessKeyCreation, AccessKeyDeletion, AccessKeyDirectory, AccessKeyStatus, AccessKeyStatusChange, ManagedAccessKey } from "../domain/accessKeys";
import type { AuthenticatorState, NotificationContact, NotificationContactVerification, NotificationDeliveryObservation, TOTPEnrollment, TOTPEnrollmentConfirmation, TOTPEnrollmentStart } from "../domain/personalSecurity";
import type { ChangePasswordCommand, AccountRepository, IamRepository, LoginCommand } from "./iamRepository";
import type { Role, RoleAccess, RoleCapability, RoleCapabilityAction, RoleDirectory, RoleListing, RolePolicyAttachment, RoleTrustDocument, RoleTrustVersion } from "../domain/roles";

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

function timestampMicros(value: string): bigint {
  const wholeSeconds = Date.parse(`${value.slice(0, 19)}Z`);
  const fractionalMicros = value.slice(19, -1).slice(1).padEnd(6, "0");
  return BigInt(wholeSeconds) * 1_000n + BigInt(fractionalMicros || "0");
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
  "iam.role.list", "iam.role.create",
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

function securityMailAddress(value: unknown): string {
  if (typeof value !== "string" || value.length > 254) throw new Error("INVALID_IAM_RESPONSE");
  const separator = value.indexOf("@");
  if (separator <= 0 || separator !== value.lastIndexOf("@")) throw new Error("INVALID_IAM_RESPONSE");
  const local = value.slice(0, separator);
  const domain = value.slice(separator + 1);
  if (local.length > 64 || local.startsWith(".") || local.endsWith(".") || local.includes("..") ||
      !/^[A-Za-z0-9.!#$%&'*+\-/=?^_`{|}~]+$/.test(local) || domain !== domain.toLowerCase() ||
      domain.length > 253 || !domain.includes(".") || domain.split(".").some((label) =>
        !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) throw new Error("INVALID_IAM_RESPONSE");
  return value;
}

function parseNotificationContact(value: unknown): NotificationContact {
  const wire = accountRecord(value);
  requireAccountKind(wire, "NotificationContact");
  const accountId = accountIdentifier(wire.accountId);
  const userId = accountIdentifier(wire.userId);
  if (wire.state === "NONE") {
    exactKeys(wire, ["apiVersion", "kind", "accountId", "userId", "state", "resourceVersion"], ["pendingVerificationId"]);
    if (wire.resourceVersion !== 0) throw new Error("INVALID_IAM_RESPONSE");
    return {
      accountId,
      userId,
      state: "NONE",
      resourceVersion: 0,
      pendingVerificationId: wire.pendingVerificationId === undefined ? null : accountIdentifier(wire.pendingVerificationId)
    };
  }
  if (wire.state !== "VERIFIED") throw new Error("INVALID_IAM_RESPONSE");
  exactKeys(wire, ["apiVersion", "kind", "accountId", "userId", "state", "resourceVersion", "email", "verifiedAt"]);
  return {
    accountId,
    userId,
    state: "VERIFIED",
    resourceVersion: accountVersion(wire.resourceVersion),
    email: securityMailAddress(wire.email),
    verifiedAt: accountTimestamp(wire.verifiedAt),
    pendingVerificationId: null
  };
}

function parseNotificationDelivery(value: unknown, issuedAt: string): NotificationDeliveryObservation {
  const wire = accountRecord(value);
  exactKeys(wire, ["state", "attempts", "updatedAt"], ["lastOutcome", "lastSmtpCode"]);
  const states = new Set(["PENDING", "IN_FLIGHT", "RETRY_WAIT", "ACCEPTED", "FAILED", "EXPIRED"]);
  const outcomes = new Set(["ACCEPTED", "REJECTED", "UNKNOWN", "UNAVAILABLE"]);
  if (typeof wire.state !== "string" || !states.has(wire.state) || typeof wire.attempts !== "number" ||
      !Number.isInteger(wire.attempts) || wire.attempts < 0 || wire.attempts > 5) throw new Error("INVALID_IAM_RESPONSE");
  const attempts = wire.attempts;
  const lastOutcome = wire.lastOutcome === undefined ? null : wire.lastOutcome;
  const lastSmtpCode = wire.lastSmtpCode === undefined ? null : wire.lastSmtpCode;
  if (lastOutcome !== null && (typeof lastOutcome !== "string" || !outcomes.has(lastOutcome)) ||
      lastSmtpCode !== null && (typeof lastSmtpCode !== "number" || !Number.isInteger(lastSmtpCode) || lastSmtpCode < 1 || lastSmtpCode > 599)) {
    throw new Error("INVALID_IAM_RESPONSE");
  }
  if (wire.state === "PENDING" && (attempts !== 0 || lastOutcome !== null) ||
      wire.state !== "PENDING" && wire.state !== "EXPIRED" && attempts === 0 ||
      wire.state === "IN_FLIGHT" && (attempts === 1 ? lastOutcome !== null : lastOutcome === null) ||
      wire.state === "RETRY_WAIT" && attempts >= 5 || wire.state === "EXPIRED" && attempts >= 5 ||
      lastOutcome === null && (lastSmtpCode !== null || attempts > 1 || wire.state === "EXPIRED" && attempts !== 0 || wire.state === "RETRY_WAIT" || wire.state === "ACCEPTED" || wire.state === "FAILED") ||
      lastOutcome === "ACCEPTED" && (wire.state !== "ACCEPTED" || lastSmtpCode !== 250) ||
      lastOutcome === "REJECTED" && (lastSmtpCode === null || lastSmtpCode < 400 || wire.state === "ACCEPTED" ||
        lastSmtpCode >= 500 && wire.state !== "FAILED" || lastSmtpCode < 500 && wire.state === "FAILED" && attempts !== 5) ||
      (lastOutcome === "UNKNOWN" || lastOutcome === "UNAVAILABLE") && (lastSmtpCode !== null || wire.state === "ACCEPTED" || wire.state === "FAILED" && attempts !== 5)) {
    throw new Error("INVALID_IAM_RESPONSE");
  }
  const updatedAt = accountTimestamp(wire.updatedAt);
  if (timestampOrder(updatedAt) < timestampOrder(issuedAt)) throw new Error("INVALID_IAM_RESPONSE");
  return { state: wire.state as NotificationDeliveryObservation["state"], attempts, lastOutcome: lastOutcome as NotificationDeliveryObservation["lastOutcome"], lastSmtpCode, updatedAt };
}

function parseNotificationVerification(value: unknown): NotificationContactVerification {
  const wire = accountRecord(value);
  exactKeys(wire, ["apiVersion", "kind", "id", "accountId", "userId", "requestId", "email", "state", "issuedAt", "expiresAt", "delivery"], ["completedAt"]);
  requireAccountKind(wire, "NotificationContactVerification");
  if (wire.state !== "PENDING" && wire.state !== "VERIFIED" && wire.state !== "CANCELLED" && wire.state !== "EXPIRED") throw new Error("INVALID_IAM_RESPONSE");
  const issuedAt = accountTimestamp(wire.issuedAt);
  const expiresAt = accountTimestamp(wire.expiresAt);
  if (timestampMicros(expiresAt) - timestampMicros(issuedAt) !== 10n * 60n * 1_000_000n) throw new Error("INVALID_IAM_RESPONSE");
  const completedAt = wire.completedAt === undefined ? null : accountTimestamp(wire.completedAt);
  if (wire.state === "PENDING") {
    if (completedAt !== null) throw new Error("INVALID_IAM_RESPONSE");
  } else if (completedAt === null || timestampOrder(completedAt) < timestampOrder(issuedAt) ||
      wire.state === "VERIFIED" && timestampOrder(completedAt) >= timestampOrder(expiresAt) ||
      wire.state === "EXPIRED" && timestampOrder(completedAt) !== timestampOrder(expiresAt)) throw new Error("INVALID_IAM_RESPONSE");
  return {
    id: accountIdentifier(wire.id),
    accountId: accountIdentifier(wire.accountId),
    userId: accountIdentifier(wire.userId),
    requestId: accountIdentifier(wire.requestId),
    email: securityMailAddress(wire.email),
    state: wire.state,
    issuedAt,
    expiresAt,
    completedAt,
    delivery: parseNotificationDelivery(wire.delivery, issuedAt)
  };
}

function parseAuthenticatorState(value: unknown): AuthenticatorState {
  const wire = accountRecord(value);
  requireAccountKind(wire, "AuthenticatorState");
  if (wire.enrollmentState === "NEVER_BOUND") {
    exactKeys(wire, ["apiVersion", "kind", "enrollmentState", "factorRevision"]);
    if (wire.factorRevision !== 1) throw new Error("INVALID_IAM_RESPONSE");
    return { enrollmentState: "NEVER_BOUND", factorRevision: 1, factorId: null };
  }
  if (wire.enrollmentState === "BOUND") {
    exactKeys(wire, ["apiVersion", "kind", "enrollmentState", "factorRevision", "factorId"]);
    const factorRevision = accountVersion(wire.factorRevision);
    if (factorRevision <= 1) throw new Error("INVALID_IAM_RESPONSE");
    return { enrollmentState: "BOUND", factorRevision, factorId: accountIdentifier(wire.factorId) };
  }
  if (wire.enrollmentState !== "RECOVERY_REQUIRED") throw new Error("INVALID_IAM_RESPONSE");
  exactKeys(wire, ["apiVersion", "kind", "enrollmentState", "factorRevision"], ["factorId"]);
  return {
    enrollmentState: "RECOVERY_REQUIRED",
    factorRevision: accountVersion(wire.factorRevision),
    factorId: wire.factorId === undefined ? null : accountIdentifier(wire.factorId)
  };
}

function parseTOTPEnrollment(value: unknown): TOTPEnrollment {
  const wire = accountRecord(value);
  exactKeys(wire, ["apiVersion", "kind", "id", "requestId", "factorRevision", "state", "createdAt", "expiresAt"], ["completedAt"]);
  requireAccountKind(wire, "TOTPEnrollment");
  if (wire.state !== "PENDING" && wire.state !== "CONFIRMED" && wire.state !== "CANCELLED" && wire.state !== "EXPIRED") throw new Error("INVALID_IAM_RESPONSE");
  const createdAt = accountTimestamp(wire.createdAt);
  const expiresAt = accountTimestamp(wire.expiresAt);
  if (timestampMicros(expiresAt) - timestampMicros(createdAt) !== 5n * 60n * 1_000_000n) throw new Error("INVALID_IAM_RESPONSE");
  const completedAt = wire.completedAt === undefined ? null : accountTimestamp(wire.completedAt);
  if (wire.state === "PENDING") {
    if (completedAt !== null) throw new Error("INVALID_IAM_RESPONSE");
  } else if (completedAt === null || timestampOrder(completedAt) < timestampOrder(createdAt) ||
      wire.state === "CONFIRMED" && timestampOrder(completedAt) >= timestampOrder(expiresAt)) throw new Error("INVALID_IAM_RESPONSE");
  return {
    id: accountIdentifier(wire.id),
    requestId: accountIdentifier(wire.requestId),
    factorRevision: (() => { const revision = accountVersion(wire.factorRevision); if (revision > 9_007_199_254_740_990) throw new Error("INVALID_IAM_RESPONSE"); return revision; })(),
    state: wire.state,
    createdAt,
    expiresAt,
    completedAt
  };
}

function parseTOTPEnrollmentStart(value: unknown): TOTPEnrollmentStart {
  const wire = accountRecord(value);
  if (wire.outcome === "APPLIED") {
    exactKeys(wire, ["outcome", "enrollment", "provisioning"]);
    const enrollment = parseTOTPEnrollment(wire.enrollment);
    const provisioning = accountRecord(wire.provisioning);
    exactKeys(provisioning, ["seed", "uri"]);
    if (enrollment.state !== "PENDING" || typeof provisioning.seed !== "string" || !provisioning.seed || provisioning.seed.length > 16384 ||
        typeof provisioning.uri !== "string" || !provisioning.uri || provisioning.uri.length > 16384) throw new Error("INVALID_IAM_RESPONSE");
    return { outcome: "APPLIED", enrollment, provisioning: { seed: provisioning.seed, uri: provisioning.uri } };
  }
  if (wire.outcome !== "EQUAL_REPLAY") throw new Error("INVALID_IAM_RESPONSE");
  exactKeys(wire, ["outcome", "enrollment"]);
  return { outcome: "EQUAL_REPLAY", enrollment: parseTOTPEnrollment(wire.enrollment) };
}

function parseTOTPEnrollmentConfirmation(value: unknown, enrollmentId: string): TOTPEnrollmentConfirmation {
  const wire = accountRecord(value);
  exactKeys(wire, ["enrollment", "nextStep", "recoveryCodes"]);
  const enrollment = parseTOTPEnrollment(wire.enrollment);
  if (enrollment.id !== enrollmentId || enrollment.state !== "CONFIRMED" || wire.nextStep !== "REAUTHENTICATE" ||
      !Array.isArray(wire.recoveryCodes) || wire.recoveryCodes.length !== 10 ||
      wire.recoveryCodes.some((code) => typeof code !== "string" || !code || code.length > 16384) ||
      new Set(wire.recoveryCodes).size !== wire.recoveryCodes.length) throw new Error("INVALID_IAM_RESPONSE");
  return { enrollment, nextStep: "REAUTHENTICATE", recoveryCodes: wire.recoveryCodes as string[] };
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

const roleCapabilityActions = new Set<RoleCapabilityAction>([
  "iam.role.read", "iam.role.update", "iam.role.set-status", "iam.role.delete", "iam.role-trust.set",
  "iam.role-policy-attachment.create", "iam.role-policy-attachment.revoke",
  "iam.role.permission-boundary.set", "iam.role.permission-boundary.remove", "iam.role.assume"
]);

function roleCapabilityResourceKind(action: RoleCapabilityAction): RoleCapability["resource"]["kind"] {
  return action === "iam.role-policy-attachment.revoke" ? "POLICY_ATTACHMENT" : "ROLE";
}

function parseRoleCapability(value: unknown): RoleCapability {
  const wire = accountRecord(value);
  exactKeys(wire, ["action", "resource", "available"], ["restrictionReason"]);
  if (typeof wire.action !== "string" || !roleCapabilityActions.has(wire.action as RoleCapabilityAction) || typeof wire.available !== "boolean") {
    throw new Error("INVALID_IAM_RESPONSE");
  }
  const action = wire.action as RoleCapabilityAction;
  const resource = accountRecord(wire.resource);
  exactKeys(resource, ["kind", "id"]);
  const reason = wire.restrictionReason;
  if (resource.kind !== roleCapabilityResourceKind(action) || typeof resource.id !== "string" || !resource.id.length ||
      (wire.available && reason !== undefined) ||
      (!wire.available && (typeof reason !== "string" || !capabilityRestrictions.has(reason as CapabilityRestriction)))) {
    throw new Error("INVALID_IAM_RESPONSE");
  }
  return {
    action,
    resource: { kind: resource.kind as RoleCapability["resource"]["kind"], id: accountIdentifier(resource.id) },
    available: wire.available,
    restrictionReason: wire.available ? null : reason as CapabilityRestriction
  };
}

function roleCapabilityKey(value: Pick<RoleCapability, "action" | "resource">): string {
  return `${value.action}\u0000${value.resource.kind}\u0000${value.resource.id}`;
}

function parseRoleCapabilities(value: unknown, expected: Array<Pick<RoleCapability, "action" | "resource">>): RoleCapability[] {
  if (!Array.isArray(value) || value.length !== expected.length) throw new Error("INVALID_IAM_RESPONSE");
  const capabilities = value.map(parseRoleCapability);
  const actual = new Set(capabilities.map(roleCapabilityKey));
  if (actual.size !== capabilities.length || expected.some((item) => !actual.has(roleCapabilityKey(item)))) {
    throw new Error("INVALID_IAM_RESPONSE");
  }
  return capabilities;
}

function parseRoleTag(value: unknown): { key: string; value: string } {
  const wire = accountRecord(value);
  exactKeys(wire, ["key", "value"]);
  return { key: groupText(wire.key, 1, 64), value: groupText(wire.value, 0, 256) };
}

function parseRole(value: unknown): Role {
  const wire = accountRecord(value);
  exactKeys(wire, [
    "apiVersion", "kind", "id", "accountId", "name", "description", "tags", "management", "status",
    "maxSessionDurationSeconds", "resourceVersion", "currentTrustVersionId", "createdAt", "updatedAt"
  ]);
  requireAccountKind(wire, "Role");
  if (wire.management !== "CUSTOMER" || (wire.status !== "ACTIVE" && wire.status !== "DISABLED") ||
      !Array.isArray(wire.tags) || wire.tags.length > 50 || typeof wire.maxSessionDurationSeconds !== "number" ||
      !Number.isSafeInteger(wire.maxSessionDurationSeconds) || wire.maxSessionDurationSeconds < 60 || wire.maxSessionDurationSeconds > 43200) {
    throw new Error("INVALID_IAM_RESPONSE");
  }
  const tags = wire.tags.map(parseRoleTag);
  if (new Set(tags.map((tag) => tag.key)).size !== tags.length ||
      tags.reduce((size, tag) => size + tag.key.length + tag.value.length, String(wire.name).length + String(wire.description).length) > 4096) {
    throw new Error("INVALID_IAM_RESPONSE");
  }
  return {
    id: accountIdentifier(wire.id),
    accountId: accountIdentifier(wire.accountId),
    name: groupText(wire.name, 1, 64),
    description: groupText(wire.description, 0, 512),
    tags,
    management: "CUSTOMER",
    status: wire.status,
    maxSessionDurationSeconds: wire.maxSessionDurationSeconds,
    resourceVersion: accountVersion(wire.resourceVersion),
    currentTrustVersionId: accountIdentifier(wire.currentTrustVersionId),
    ...chronologicalTimestamps(wire.createdAt, wire.updatedAt)
  };
}

function roleCapabilities(roleId: string): Array<Pick<RoleCapability, "action" | "resource">> {
  const resource = { kind: "ROLE" as const, id: roleId };
  return ([
    "iam.role.read", "iam.role.update", "iam.role.set-status", "iam.role.delete", "iam.role-trust.set",
    "iam.role-policy-attachment.create", "iam.role.permission-boundary.set", "iam.role.permission-boundary.remove"
  ] as const).map((action) => ({ action, resource }));
}

function parseRoleListing(value: unknown, accountId: string): RoleListing {
  const wire = accountRecord(value);
  exactKeys(wire, ["role", "capabilities"]);
  const role = parseRole(wire.role);
  if (role.accountId !== accountId) throw new Error("INVALID_IAM_RESPONSE");
  return { role, capabilities: parseRoleCapabilities(wire.capabilities, roleCapabilities(role.id)) };
}

function parseRoleDirectory(value: unknown, accountId: string, after?: string): RoleDirectory {
  const wire = accountRecord(value);
  exactKeys(wire, ["apiVersion", "kind", "accountId", "items"], ["nextAfter"]);
  requireAccountKind(wire, "RoleList");
  if (accountIdentifier(wire.accountId) !== accountId || !Array.isArray(wire.items) || wire.items.length > 100) {
    throw new Error("INVALID_IAM_RESPONSE");
  }
  const items = wire.items.map((item) => parseRoleListing(item, accountId));
  const nextAfter = orderedDirectoryPage(items.map((item) => item.role.id), wire.nextAfter, after);
  if (nextAfter && items.length !== 100) throw new Error("INVALID_IAM_RESPONSE");
  if (new TextEncoder().encode(JSON.stringify(wire)).length > 4 * 1024 * 1024) throw new Error("INVALID_IAM_RESPONSE");
  return { accountId, items, nextAfter };
}

function parseRolePolicyAttachment(value: unknown, accountId: string, roleId: string): RolePolicyAttachment {
  const wire = accountRecord(value);
  exactKeys(wire, ["apiVersion", "kind", "id", "accountId", "target", "policyId", "scope", "resourceVersion", "createdAt", "updatedAt"], ["installationId"]);
  requireAccountKind(wire, "PolicyAttachment");
  const target = accountRecord(wire.target);
  exactKeys(target, ["kind", "id"]);
  if (wire.accountId !== accountId || target.kind !== "ROLE" || target.id !== roleId || wire.scope !== "TENANT" || wire.installationId !== undefined) {
    throw new Error("INVALID_IAM_RESPONSE");
  }
  return {
    id: accountIdentifier(wire.id), accountId, target: { kind: "ROLE", id: roleId },
    policyId: accountIdentifier(wire.policyId), scope: "TENANT", resourceVersion: accountVersion(wire.resourceVersion),
    ...chronologicalTimestamps(wire.createdAt, wire.updatedAt)
  };
}

function parseRoleTrustDocument(value: unknown): RoleTrustDocument {
  const wire = accountRecord(value);
  exactKeys(wire, ["languageVersion", "statements"]);
  if (wire.languageVersion !== "1" || !Array.isArray(wire.statements) || wire.statements.length > 8) throw new Error("INVALID_IAM_RESPONSE");
  const statements = wire.statements.map((entry) => {
    const statement = accountRecord(entry);
    exactKeys(statement, ["sid", "effect", "principals"]);
    if ((statement.effect !== "ALLOW" && statement.effect !== "DENY") || !Array.isArray(statement.principals) ||
        !statement.principals.length || statement.principals.length > 32) throw new Error("INVALID_IAM_RESPONSE");
    const principals = statement.principals.map((entry) => {
      const principal = accountRecord(entry);
      exactKeys(principal, ["type", "id"]);
      if (principal.type !== "USER") throw new Error("INVALID_IAM_RESPONSE");
      return { type: "USER" as const, id: accountIdentifier(principal.id) };
    });
    if (new Set(principals.map((principal) => principal.id)).size !== principals.length) throw new Error("INVALID_IAM_RESPONSE");
    return { sid: accountIdentifier(statement.sid), effect: statement.effect as "ALLOW" | "DENY", principals };
  });
  if (new Set(statements.map((statement) => statement.sid)).size !== statements.length ||
      statements.reduce((count, statement) => count + statement.principals.length, 0) > 256) throw new Error("INVALID_IAM_RESPONSE");
  const document = { languageVersion: "1" as const, statements };
  if (new TextEncoder().encode(JSON.stringify(document)).length > 16 * 1024) throw new Error("INVALID_IAM_RESPONSE");
  return document;
}

function parseRoleTrustVersion(value: unknown): RoleTrustVersion {
  const wire = accountRecord(value);
  exactKeys(wire, ["apiVersion", "kind", "id", "accountId", "roleId", "document", "contentDigest", "createdAt"]);
  requireAccountKind(wire, "RoleTrustVersion");
  if (typeof wire.contentDigest !== "string" || !/^sha256:[a-f0-9]{64}$/.test(wire.contentDigest)) throw new Error("INVALID_IAM_RESPONSE");
  return {
    id: accountIdentifier(wire.id), accountId: accountIdentifier(wire.accountId), roleId: accountIdentifier(wire.roleId),
    document: parseRoleTrustDocument(wire.document), contentDigest: wire.contentDigest, createdAt: accountTimestamp(wire.createdAt)
  };
}

function canonicalRoleTrust(document: RoleTrustDocument): string {
  const compare = (left: string, right: string) => left < right ? -1 : left > right ? 1 : 0;
  return JSON.stringify({
    languageVersion: document.languageVersion,
    statements: [...document.statements].sort((left, right) => compare(left.sid, right.sid)).map((statement) => ({
      sid: statement.sid,
      effect: statement.effect,
      principals: [...statement.principals].sort((left, right) => compare(left.id, right.id)).map((principal) => ({ type: principal.type, id: principal.id }))
    }))
  });
}

async function verifyRoleTrustDigest(version: RoleTrustVersion): Promise<void> {
  const source = new TextEncoder().encode(`matrix.iam.role-trust.v1\u0000${canonicalRoleTrust(version.document)}`);
  const digest = await crypto.subtle.digest("SHA-256", source);
  const actual = `sha256:${Array.from(new Uint8Array(digest), (value) => value.toString(16).padStart(2, "0")).join("")}`;
  if (actual !== version.contentDigest) throw new Error("INVALID_IAM_RESPONSE");
}

function parseRoleAccess(value: unknown, accountId: string, roleId: string): RoleAccess {
  const wire = accountRecord(value);
  exactKeys(wire, ["role", "trustVersion", "policyAttachments", "capabilities"]);
  const role = parseRole(wire.role);
  const trustVersion = parseRoleTrustVersion(wire.trustVersion);
  if (role.id !== roleId || role.accountId !== accountId || trustVersion.accountId !== accountId || trustVersion.roleId !== roleId ||
      trustVersion.id !== role.currentTrustVersionId || timestampOrder(trustVersion.createdAt) < timestampOrder(role.createdAt) ||
      timestampOrder(trustVersion.createdAt) > timestampOrder(role.updatedAt) || !Array.isArray(wire.policyAttachments) || wire.policyAttachments.length > 256) {
    throw new Error("INVALID_IAM_RESPONSE");
  }
  const policyAttachments = wire.policyAttachments.map((attachment) => parseRolePolicyAttachment(attachment, accountId, roleId));
  if (new Set(policyAttachments.map((attachment) => attachment.id)).size !== policyAttachments.length ||
      new Set(policyAttachments.map((attachment) => attachment.policyId)).size !== policyAttachments.length) throw new Error("INVALID_IAM_RESPONSE");
  const resource = { kind: "ROLE" as const, id: roleId };
  const capabilities = parseRoleCapabilities(wire.capabilities, [
    ...roleCapabilities(roleId),
    { action: "iam.role.assume", resource },
    ...policyAttachments.map((attachment) => ({ action: "iam.role-policy-attachment.revoke" as const, resource: { kind: "POLICY_ATTACHMENT" as const, id: attachment.id } }))
  ]);
  if (new TextEncoder().encode(JSON.stringify(wire)).length > 512 * 1024) throw new Error("INVALID_IAM_RESPONSE");
  return { role, trustVersion, policyAttachments, capabilities };
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
    { action: "iam.group.create", resource: accountResource },
    { action: "iam.role.list", resource: accountResource },
    { action: "iam.role.create", resource: accountResource }
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
  roles: {
    async list(credential, accountId, after) {
      return parseRoleDirectory(await requestJSON<unknown>(
        `/api/iam/v1/roles${pageQuery(after)}`,
        { headers: accountHeaders(credential) }
      ), accountIdentifier(accountId), after);
    },
    async read(credential, accountId, roleId) {
      const target = accountIdentifier(roleId);
      const access = parseRoleAccess(await requestJSON<unknown>(
        `/api/iam/v1/roles/${encodeURIComponent(target)}`,
        { headers: accountHeaders(credential) }
      ), accountIdentifier(accountId), target);
      await verifyRoleTrustDigest(access.trustVersion);
      return access;
    }
  },
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
  const base = {
    id: accountIdentifier(wire.id),
    expiresAt: accountTimestamp(wire.expiresAt)
  };
  if (wire.purpose === "LOGIN" &&
      (wire.nextStep === "TOTP" || wire.nextStep === "PASSWORD_CHANGE" || wire.nextStep === "RECOVER")) {
    return { ...base, purpose: "LOGIN", nextStep: wire.nextStep };
  }
  if (wire.purpose === "RECOVERY" && wire.nextStep === "ENROLLMENT") {
    return { ...base, purpose: "RECOVERY", nextStep: "ENROLLMENT" };
  }
  throw new Error("INVALID_IAM_RESPONSE");
}

function parseAuthenticatorRecovery(value: unknown, expectedRequestId?: string): AuthenticatorRecovery {
  const wire = accountRecord(value);
  const terminal = wire.state === "COMPLETED" || wire.state === "SUPERSEDED" || wire.state === "EXPIRED";
  exactKeys(
    wire,
    terminal
      ? ["apiVersion", "kind", "id", "requestId", "state", "createdAt", "expiresAt", "completedAt"]
      : ["apiVersion", "kind", "id", "requestId", "state", "createdAt", "expiresAt"]
  );
  requireAccountKind(wire, "AuthenticatorRecovery");
  if (wire.state !== "STARTED" && !terminal) throw new Error("INVALID_IAM_RESPONSE");
  const requestId = accountIdentifier(wire.requestId);
  if (expectedRequestId !== undefined && requestId !== accountIdentifier(expectedRequestId)) {
    throw new Error("INVALID_IAM_RESPONSE");
  }
  const createdAt = accountTimestamp(wire.createdAt);
  const expiresAt = accountTimestamp(wire.expiresAt);
  const createdMicros = timestampMicros(createdAt);
  const expiresMicros = timestampMicros(expiresAt);
  if (expiresMicros <= createdMicros || expiresMicros - createdMicros > 300_000_000n) {
    throw new Error("INVALID_IAM_RESPONSE");
  }
  const recovery: AuthenticatorRecovery = {
    id: accountIdentifier(wire.id),
    requestId,
    state: wire.state as AuthenticatorRecovery["state"],
    createdAt,
    expiresAt
  };
  if (terminal) {
    const completedAt = accountTimestamp(wire.completedAt);
    const completedMicros = timestampMicros(completedAt);
    if (completedMicros < createdMicros ||
        (wire.state === "COMPLETED" && completedMicros >= expiresMicros) ||
        (wire.state === "EXPIRED" && completedMicros < expiresMicros)) {
      throw new Error("INVALID_IAM_RESPONSE");
    }
    recovery.completedAt = completedAt;
  }
  return recovery;
}

function responseSecret(value: unknown): string {
  const result = accountText(value);
  if (result.length > 16_384) throw new Error("INVALID_IAM_RESPONSE");
  return result;
}

function parseAuthenticatorRecoveryStart(value: unknown, requestId: string): AuthenticatorRecoveryStart {
  const wire = accountRecord(value);
  exactKeys(wire, ["recovery", "challenge", "challengeCredential", "provisioning"]);
  const recovery = parseAuthenticatorRecovery(wire.recovery, requestId);
  const challenge = parseAuthenticationChallenge(wire.challenge);
  const provisioning = accountRecord(wire.provisioning);
  exactKeys(provisioning, ["seed", "uri"]);
  if (recovery.state !== "STARTED" || challenge.purpose !== "RECOVERY" ||
      challenge.nextStep !== "ENROLLMENT" || challenge.expiresAt !== recovery.expiresAt) {
    throw new Error("INVALID_IAM_RESPONSE");
  }
  return {
    recovery: { ...recovery, state: "STARTED" },
    challenge,
    challengeCredential: responseSecret(wire.challengeCredential),
    provisioning: { seed: responseSecret(provisioning.seed), uri: responseSecret(provisioning.uri) }
  };
}

function parseAuthenticatorRecoveryConfirmation(
  value: unknown,
  recoveryRequestId: string
): AuthenticatorRecoveryConfirmation {
  const wire = accountRecord(value);
  exactKeys(wire, ["recovery", "nextStep", "recoveryCodes"]);
  const recovery = parseAuthenticatorRecovery(wire.recovery, recoveryRequestId);
  if (wire.nextStep !== "REAUTHENTICATE" || recovery.state !== "COMPLETED" || !recovery.completedAt ||
      !Array.isArray(wire.recoveryCodes) || wire.recoveryCodes.length !== 10) {
    throw new Error("INVALID_IAM_RESPONSE");
  }
  const recoveryCodes = wire.recoveryCodes.map(responseSecret);
  if (new Set(recoveryCodes).size !== recoveryCodes.length) throw new Error("INVALID_IAM_RESPONSE");
  return {
    recovery: { ...recovery, state: "COMPLETED", completedAt: recovery.completedAt },
    nextStep: "REAUTHENTICATE",
    recoveryCodes
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
    const challenge = parseAuthenticationChallenge(wire.challenge);
    if (challenge.purpose !== "LOGIN") throw new Error("INVALID_IAM_RESPONSE");
    return {
      outcome: "CHALLENGE_REQUIRED",
      challenge,
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
    if (result.outcome === "CHALLENGE_REQUIRED" && result.challenge.nextStep === "PASSWORD_CHANGE") {
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
    },
    async startRecovery(command) {
      const requestId = accountIdentifier(command.requestId);
      const wire = await requestJSON<unknown>(`/api/iam/v1/auth/challenges/${encodeURIComponent(accountIdentifier(command.challengeId))}:recover`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          requestId,
          challengeCredential: responseSecret(command.challengeCredential),
          recoveryCode: responseSecret(command.recoveryCode)
        })
      });
      return parseAuthenticatorRecoveryStart(wire, requestId);
    },
    async confirmRecovery(command) {
      if (!/^[0-9]{6}$/.test(command.code)) throw new Error("INVALID_IAM_RESPONSE");
      const wire = await requestJSON<unknown>(`/api/iam/v1/auth/challenges/${encodeURIComponent(accountIdentifier(command.challengeId))}:confirm-recovery`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          requestId: accountIdentifier(command.requestId),
          challengeCredential: responseSecret(command.challengeCredential),
          code: command.code
        })
      });
      return parseAuthenticatorRecoveryConfirmation(wire, command.recoveryRequestId);
    },
    async inspectRecovery(command) {
      const requestId = accountIdentifier(command.requestId);
      return parseAuthenticatorRecovery(await requestJSON<unknown>(
        `/api/iam/v1/auth/challenges/${encodeURIComponent(accountIdentifier(command.challengeId))}:recovery-result`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            requestId,
            challengeCredential: responseSecret(command.challengeCredential)
          })
        }
      ), requestId);
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
  personalSecurity: {
    async notificationContact(credential) {
      return parseNotificationContact(await requestJSON<unknown>("/api/iam/v1/auth/notification-contact", {
        headers: accountHeaders(credential)
      }));
    },
    async startNotificationVerification(credential, command) {
      const password = accountText(command.password);
      const email = securityMailAddress(command.email);
      const requestId = accountIdentifier(command.requestId);
      const verification = parseNotificationVerification(await requestJSON<unknown>("/api/iam/v1/auth/notification-contact/verifications", {
        method: "POST",
        headers: { ...accountHeaders(credential), "Content-Type": "application/json" },
        body: JSON.stringify({ email, password, requestId })
      }));
      if (verification.email !== email || verification.requestId !== requestId) throw new Error("INVALID_IAM_RESPONSE");
      return verification;
    },
    async notificationVerification(credential, verificationId) {
      const target = accountIdentifier(verificationId);
      const verification = parseNotificationVerification(await requestJSON<unknown>(
        `/api/iam/v1/auth/notification-contact/verifications/${encodeURIComponent(target)}`,
        { headers: accountHeaders(credential) }
      ));
      if (verification.id !== target) throw new Error("INVALID_IAM_RESPONSE");
      return verification;
    },
    async confirmNotificationVerification(credential, verificationId, command) {
      if (!/^[0-9]{8}$/.test(command.code)) throw new Error("INVALID_IAM_RESPONSE");
      const target = accountIdentifier(verificationId);
      const verification = parseNotificationVerification(await requestJSON<unknown>(
        `/api/iam/v1/auth/notification-contact/verifications/${encodeURIComponent(target)}:confirm`,
        {
          method: "POST",
          headers: { ...accountHeaders(credential), "Content-Type": "application/json" },
          body: JSON.stringify({ code: command.code, requestId: accountIdentifier(command.requestId) })
        }
      ));
      if (verification.id !== target) throw new Error("INVALID_IAM_RESPONSE");
      return verification;
    },
    async authenticatorState(credential) {
      return parseAuthenticatorState(await requestJSON<unknown>("/api/iam/v1/auth/authenticators", {
        headers: accountHeaders(credential)
      }));
    },
    async startTOTPEnrollment(credential, command) {
      const expectedFactorRevision = accountVersion(command.expectedFactorRevision);
      if (expectedFactorRevision > 9_007_199_254_740_990) throw new Error("INVALID_IAM_RESPONSE");
      const requestId = accountIdentifier(command.requestId);
      const result = parseTOTPEnrollmentStart(await requestJSON<unknown>("/api/iam/v1/auth/totp/enrollments", {
        method: "POST",
        headers: { ...accountHeaders(credential), "Content-Type": "application/json" },
        body: JSON.stringify({
          requestId,
          password: accountText(command.password),
          expectedFactorRevision
        })
      }));
      if (result.enrollment.requestId !== requestId || result.enrollment.factorRevision !== expectedFactorRevision) throw new Error("INVALID_IAM_RESPONSE");
      return result;
    },
    async totpEnrollment(credential, enrollmentId) {
      const target = accountIdentifier(enrollmentId);
      const enrollment = parseTOTPEnrollment(await requestJSON<unknown>(
        `/api/iam/v1/auth/totp/enrollments/${encodeURIComponent(target)}`,
        { headers: accountHeaders(credential) }
      ));
      if (enrollment.id !== target) throw new Error("INVALID_IAM_RESPONSE");
      return enrollment;
    },
    async totpEnrollmentByRequest(credential, requestId) {
      const target = accountIdentifier(requestId);
      const enrollment = parseTOTPEnrollment(await requestJSON<unknown>(
        `/api/iam/v1/auth/totp/enrollments/by-request/${encodeURIComponent(target)}`,
        { headers: accountHeaders(credential) }
      ));
      if (enrollment.requestId !== target) throw new Error("INVALID_IAM_RESPONSE");
      return enrollment;
    },
    async cancelTOTPEnrollment(credential, enrollmentId) {
      const target = accountIdentifier(enrollmentId);
      const enrollment = parseTOTPEnrollment(await requestJSON<unknown>(
        `/api/iam/v1/auth/totp/enrollments/${encodeURIComponent(target)}`,
        { method: "DELETE", headers: accountHeaders(credential) }
      ));
      if (enrollment.id !== target || (enrollment.state !== "CANCELLED" && enrollment.state !== "EXPIRED")) throw new Error("INVALID_IAM_RESPONSE");
      return enrollment;
    },
    async confirmTOTPEnrollment(credential, enrollmentId, command) {
      const target = accountIdentifier(enrollmentId);
      const code = accountText(command.code);
      return parseTOTPEnrollmentConfirmation(await requestJSON<unknown>(
        `/api/iam/v1/auth/totp/enrollments/${encodeURIComponent(target)}:confirm`,
        {
          method: "POST",
          headers: { ...accountHeaders(credential), "Content-Type": "application/json" },
          body: JSON.stringify({ requestId: accountIdentifier(command.requestId), code })
        }
      ), target);
    }
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
