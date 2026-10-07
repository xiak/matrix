"use client";

import { createContext, useCallback, useContext, useEffect, useLayoutEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { HttpProblem, requestToken } from "@/infrastructure/http/jsonRequest";
import { useSession, useSessionCredential } from "./SessionProvider";
import type {
  AccountCommand,
  AccountPolicyDetail,
  AccountPolicyDocument,
  AccountPolicyVersionDirectory,
  AccountSecuritySettingsChange,
  AccountSecuritySettings,
  AccountPolicy,
  AuthorizationProfileDirectory,
  CapabilityRestriction,
  DirectoryPage,
  Group,
  GroupAccess,
  GroupDeletion,
  GroupMembership,
  GroupMembershipPage,
  GroupPolicyAttachment,
  PolicyAttachmentChange,
  PolicyAttachmentChangeExpectation,
  PolicyAttachmentChangeOperationExpectation,
  PolicyAttachmentRevocation,
  RolePolicyAttachment,
  PasswordResetRequestIdentity,
  UserPasswordResetCompletion,
  UserPermissionBoundary,
  SecuritySettingsUpdateIntent
} from "../domain/accounts";
import type { ServiceLinkedRoleAccess, ServiceLinkedRoleDirectory, ServiceRoleTemplateDirectory } from "../domain/serviceAuthorization";
import { type AccessWorkspace, type AccessWorkspaceCommand, type PendingAccountRuleChange } from "../domain/accessWorkspace";
import { AccessWorkspaceError } from "../domain/accessWorkspaceError";
import type { AccountRepository } from "../repositories/iamRepository";
import type { AccessKeyAccess, AccessKeyCreation, AccessKeyDeletion, AccessKeyDirectory, AccessKeyNetworkChange, AccessKeyStatus, AccessKeyStatusChange } from "../domain/accessKeys";
import { accessKeyNetworkRestrictionsEqual, accessKeyNetworkRestrictionsValid, type AccessKeyNetworkRestrictions } from "../domain/accessKeyNetwork";
import { httpAccountRepository } from "../repositories/httpIamRepository";
import { buildAccountAccessScene, buildAccountTenantScene, buildAccountUserScene, findActionCapability, type AccountAccessScene, type AccountUserScene } from "../scenes/accountAccessScene";
import { userBatchDisabledReason, type UserBatchCommand } from "../domain/userBatch";
import type { CreateRoleCommand, CreateRolePolicyAttachmentCommand, DeleteRoleCommand, RemoveRolePermissionBoundaryCommand, Role, RoleAccess, RoleDeletion, RoleDirectory, RolePermissionBoundary, RoleSessionAccess, RoleSessionDirectory, RoleSessionFilter, RoleSessionListing, RoleSessionRevocation, RoleTrustVersionDirectory, SetRolePermissionBoundaryCommand, SetRoleStatusCommand, SetRoleTrustPolicyCommand, UpdateRoleCommand } from "../domain/roles";
import type { AccessAnalyzer, AccessAnalyzerDirectory, AccessFinding, AccessFindingDirectory, AccessFindingDispositionCommand, AccessFindingStatusFilter, CreateAccessAnalyzerCommand, SetAccessDispositionCommand, UpdateAccessAnalyzerCommand } from "../domain/accessAnalysis";
import type { AccountSecurityReport, AccountSecurityReportCreation, AccountSecurityReportDownload } from "../domain/securityReports";
import type { SecurityStepUp } from "../domain/personalSecurity";

type AccountError = "expired" | "forbidden" | "conflict" | "invalid" | "unavailable";
type WorkspaceExecutionError = AccessWorkspaceError["code"] | AccountError;

export type UserBoundarySnapshot = {
  user: AccountUserScene;
  boundary: UserPermissionBoundary;
  policies: AccountPolicy[];
  policiesAvailable: boolean;
};
export type UserBoundaryClient = {
  accountId: string;
  load(userId: string): Promise<UserBoundarySnapshot>;
  set(userId: string, command: { policyId: string; policyResourceVersion: number; resourceVersion: number; requestId: string }): Promise<UserPermissionBoundary>;
  remove(userId: string, command: { resourceVersion: number; requestId: string }): Promise<UserPermissionBoundary>;
};

export type GroupAccessClient = {
  accountId: string;
  actorPrincipalId: string;
  canList: boolean;
  listRestrictionReason: CapabilityRestriction | null;
  canCreate: boolean;
  createRestrictionReason: CapabilityRestriction | null;
  list(after?: string): Promise<DirectoryPage<GroupAccess>>;
  get(groupId: string): Promise<GroupAccess>;
  create(command: { name: string; description?: string; requestId: string }): Promise<Group>;
  update(groupId: string, command: { name: string; description?: string; resourceVersion: number; requestId: string }): Promise<Group>;
  delete(groupId: string, command: { resourceVersion: number; requestId: string }): Promise<GroupDeletion>;
  listMemberships(groupId: string, after?: string): Promise<GroupMembershipPage>;
  createMembership(groupId: string, command: { userId: string; requestId: string }): Promise<GroupMembership>;
  removeMembership(groupId: string, membershipId: string, command: { resourceVersion: number; requestId: string }): Promise<GroupMembership>;
  createPolicyAttachment(groupId: string, command: { policyId: string; policyResourceVersion: number; requestId: string }): Promise<GroupPolicyAttachment>;
  revokePolicyAttachment(attachmentId: string, command: { resourceVersion: number; requestId: string }): Promise<PolicyAttachmentRevocation>;
  inspectPolicyAttachmentChange(expectation: PolicyAttachmentChangeOperationExpectation): Promise<PolicyAttachmentChange>;
};

export type AuthorizationProfileLoad =
  | { status: "ready"; directory: AuthorizationProfileDirectory }
  | { status: "forbidden" | "routeUnavailable" | "unavailable" | "expired" };

export type AuthorizationProfileClient = {
  accountId: string;
  preview: boolean;
  load(): Promise<AuthorizationProfileLoad>;
};

export type ServiceRoleTemplateLoad =
  | { status: "ready"; directory: ServiceRoleTemplateDirectory }
  | { status: "forbidden" | "routeUnavailable" | "unavailable" | "expired" };

export type ServiceRoleTemplateClient = {
  sessionRevision: number;
  load(): Promise<ServiceRoleTemplateLoad>;
};

export type ServiceLinkedRoleDirectoryLoad =
  | { status: "ready"; directory: ServiceLinkedRoleDirectory }
  | { status: "forbidden" | "routeUnavailable" | "unavailable" | "expired" };

export type ServiceLinkedRoleAccessLoad =
  | { status: "ready"; access: ServiceLinkedRoleAccess }
  | { status: "forbidden" | "routeUnavailable" | "unavailable" | "expired" };

export type ServiceLinkedRoleClient = {
  accountId: string;
  sessionRevision: number;
  list(after?: string): Promise<ServiceLinkedRoleDirectoryLoad>;
  read(roleId: string, after?: string): Promise<ServiceLinkedRoleAccessLoad>;
};

type AccountPolicyReadFailure = { status: "forbidden" | "routeUnavailable" | "unavailable" | "expired" };
export type AccountPolicyReadLoad = { status: "ready"; detail: AccountPolicyDetail } | AccountPolicyReadFailure;
export type AccountPolicyVersionDirectoryLoad = { status: "ready"; directory: AccountPolicyVersionDirectory } | AccountPolicyReadFailure;

export type PolicyCreateIntent = {
  accountId: string;
  displayName: string;
  documentJSON: string;
  requestId: string;
  phase: "submitting" | "unknown";
};

export type PolicyCreateResult =
  | { status: "applied"; detail: AccountPolicyDetail }
  | { status: "rejected"; reason: "forbidden" | "conflict" | "invalid" | "expired" | "routeUnavailable" }
  | { status: "unknown" | "blocked" };

export type PolicyCreateClient = {
  pending: PolicyCreateIntent | null;
  begin(input: { displayName: string; document: AccountPolicyDocument }): Promise<PolicyCreateResult>;
  retry(): Promise<PolicyCreateResult>;
  acknowledge(): boolean;
};

export type AccountPolicyReadClient = {
  accountId: string;
  sessionRevision: number;
  read(policyId: string): Promise<AccountPolicyReadLoad>;
  listVersions?(policyId: string): Promise<AccountPolicyVersionDirectoryLoad>;
  readVersion?(policyId: string, versionId: string): Promise<AccountPolicyReadLoad>;
};

type PolicyVersionMutationBase = {
  policyId: string;
  expectedDefaultVersionId: string;
  resourceVersion: number;
};

export type PolicyVersionMutationInput = PolicyVersionMutationBase & (
  | { kind: "publish"; document: AccountPolicyDocument }
  | { kind: "set-default" | "retire"; versionId: string }
);

export type PolicyVersionMutationIntent = PolicyVersionMutationBase & (
  | { kind: "publish"; documentJSON: string }
  | { kind: "set-default" | "retire"; versionId: string }
) & {
  accountId: string;
  requestId: string;
  phase: "submitting" | "unknown" | "observing";
  observation: { resourceVersion: number; defaultVersionId: string; versionIds: string[] } | null;
  observationError: "forbidden" | "expired" | "unavailable" | null;
};

export type PolicyVersionMutationResult =
  | { status: "applied"; detail: AccountPolicyDetail }
  | { status: "rejected"; reason: "forbidden" | "conflict" | "invalid" | "notFound" | "expired" }
  | { status: "unknown" | "blocked" };

export type PolicyVersionMutationClient = {
  pending: PolicyVersionMutationIntent | null;
  canPublish: boolean;
  begin(input: PolicyVersionMutationInput): Promise<PolicyVersionMutationResult>;
  retry(): Promise<PolicyVersionMutationResult>;
  observe(): Promise<boolean>;
  acknowledge(): boolean;
};

export type AccountSecuritySettingsLoad =
  | { status: "ready"; settings: AccountSecuritySettings }
  | { status: "forbidden" | "routeUnavailable" | "unavailable" | "expired" };

export type AccountSecuritySettingsMutationState =
  | "STEP_UP_UNKNOWN"
  | "PENDING"
  | "VERIFICATION_UNKNOWN"
  | "PROVED"
  | "APPLY_UNKNOWN"
  | "COMPLETED"
  | "EXPIRED";

export type AccountSecuritySettingsMutationIntent = Readonly<{
  accountId: string;
  actorId: string;
  requestId: string;
  expectedFactorRevision: number;
  state: AccountSecuritySettingsMutationState;
  settings: SecuritySettingsUpdateIntent;
  stepUp: SecurityStepUp | null;
}>;

export type AccountSecuritySettingsUpdateClient = {
  intent: AccountSecuritySettingsMutationIntent | null;
  begin(current: AccountSecuritySettings, accessKeyNetwork: AccessKeyNetworkRestrictions, expectedFactorRevision: number): Promise<SecurityStepUp>;
  retryStepUp(): Promise<SecurityStepUp>;
  inspectStepUp(): Promise<SecurityStepUp>;
  verifyStepUp(command: { requestId: string; password: string; code: string }): Promise<SecurityStepUp>;
  apply(): Promise<AccountSecuritySettingsChange>;
  inspectChange(): Promise<AccountSecuritySettingsChange>;
  clear(requestId: string): boolean;
};

export type AccountSecuritySettingsClient = {
  accountId: string;
  principalId: string;
  sessionId: string;
  sessionRevision: number;
  update?: AccountSecuritySettingsUpdateClient;
  load(): Promise<AccountSecuritySettingsLoad>;
};

export type AccessKeyClient = {
  accountId: string;
  list(userId: string): Promise<AccessKeyDirectory>;
  read(userId: string, accessKeyId: string): Promise<AccessKeyAccess>;
  create(userId: string, command: { userResourceVersion: number; networkRestrictions: AccessKeyNetworkRestrictions; requestId: string }): Promise<AccessKeyCreation>;
  acknowledgeIssued(requestId: string, accessKeyId: string): boolean;
  setStatus(userId: string, accessKeyId: string, command: { accessKeyResourceVersion: number; requestId: string; status: AccessKeyStatus }): Promise<AccessKeyStatusChange>;
  setNetworkRestrictions(userId: string, accessKeyId: string, command: { accessKeyResourceVersion: number; networkRestrictions: AccessKeyNetworkRestrictions; requestId: string }): Promise<AccessKeyNetworkChange>;
  delete(userId: string, accessKeyId: string, command: { accessKeyResourceVersion: number; requestId: string }): Promise<AccessKeyDeletion>;
};

export type AccessAnalysisClient = {
  accountId: string;
  sessionRevision: number;
  listAnalyzers(after?: string): Promise<AccessAnalyzerDirectory>;
  readAnalyzer(analyzerId: string): Promise<AccessAnalyzer>;
  createAnalyzer(command: CreateAccessAnalyzerCommand): Promise<AccessAnalyzer>;
  updateAnalyzer(analyzerId: string, command: UpdateAccessAnalyzerCommand): Promise<AccessAnalyzer>;
  setDisposition(analyzerId: string, command: SetAccessDispositionCommand): Promise<AccessAnalyzer>;
  listFindings(analyzerId: string, status: AccessFindingStatusFilter, after?: string): Promise<AccessFindingDirectory>;
  readFinding(analyzerId: string, findingId: string): Promise<AccessFinding>;
  archiveFinding(analyzerId: string, findingId: string, command: AccessFindingDispositionCommand): Promise<AccessFinding>;
  unarchiveFinding(analyzerId: string, findingId: string, command: AccessFindingDispositionCommand): Promise<AccessFinding>;
};

export type SecurityReportClient = {
  accountId: string;
  sessionRevision: number;
  create(command: { formatVersion: 1; requestId: string }): Promise<AccountSecurityReportCreation>;
  read(reportId: string): Promise<AccountSecurityReport>;
  download(reportId: string): Promise<AccountSecurityReportDownload>;
};

export type AccessKeyCreateIntent = Readonly<{
  accountId: string;
  actorId: string;
  userId: string;
  userResourceVersion: number;
  networkRestrictions: AccessKeyNetworkRestrictions;
  requestId: string;
} & ({ phase: "unknown" } | { phase: "recovered"; keyId: string })>;

export type RoleAccessClient = {
  accountId: string;
  actorPrincipalId: string;
  sessionRevision: number;
  canCreate: boolean;
  createRestrictionReason: CapabilityRestriction | null;
  list(after?: string): Promise<RoleDirectory>;
  read(roleId: string): Promise<RoleAccess>;
  readPermissionBoundary(roleId: string): Promise<RolePermissionBoundary>;
  listTenantPolicies(): Promise<{ items: AccountPolicy[]; available: boolean }>;
  setPermissionBoundary(roleId: string, command: SetRolePermissionBoundaryCommand): Promise<RolePermissionBoundary>;
  removePermissionBoundary(roleId: string, command: RemoveRolePermissionBoundaryCommand): Promise<RolePermissionBoundary>;
  listTrustVersions(roleId: string, after?: string): Promise<RoleTrustVersionDirectory>;
  create(command: CreateRoleCommand): Promise<Role>;
  update(roleId: string, command: UpdateRoleCommand): Promise<Role>;
  setStatus(roleId: string, command: SetRoleStatusCommand): Promise<Role>;
  setTrustPolicy(roleId: string, command: SetRoleTrustPolicyCommand): Promise<Role>;
  delete(roleId: string, command: DeleteRoleCommand): Promise<RoleDeletion>;
  createPolicyAttachment(roleId: string, command: CreateRolePolicyAttachmentCommand): Promise<RolePolicyAttachment>;
  revokePolicyAttachment(attachmentId: string, command: { resourceVersion: number; requestId: string }): Promise<PolicyAttachmentRevocation>;
  inspectPolicyAttachmentChange(expectation: PolicyAttachmentChangeOperationExpectation): Promise<PolicyAttachmentChange>;
  listSessions(roleId: string, filter: RoleSessionFilter, after?: string): Promise<RoleSessionDirectory>;
  readSession(roleId: string, sessionId: string): Promise<RoleSessionAccess>;
  revokeSession(roleId: string, sessionId: string, requestId: string): Promise<RoleSessionRevocation>;
};

export type RoleSessionRevokeIntent = {
  accountId: string;
  roleId: string;
  item: RoleSessionListing;
  requestId: string;
  phase: "confirm" | "submitting" | "unknown" | "checking";
  open: boolean;
  observation?: RoleSessionListing;
};

type UserPolicyChangeBase = {
  accountId: string;
  actorId: string;
  userId: string;
  userQualifiedName: string;
  policyId: string;
  policyDisplayName: string;
  policyScope: "INSTALLATION" | "TENANT";
  requestId: string;
  phase: "review" | "submitting" | "unknown" | "checking" | "confirmed" | "conflict" | "rejected";
  lookupStatus: "unchecked" | "stillUnknown" | "forbidden" | "unavailable" | "expired" | "confirmed";
  completion: PolicyAttachmentChange | null;
  error: AccountError | null;
};
export type UserPolicyChangeIntent = UserPolicyChangeBase & (
  | { kind: "attach"; defaultVersionId: string; policyResourceVersion: number }
  | { kind: "revoke"; attachmentId: string; attachmentResourceVersion: number }
);

export type PolicyDirectoryView = { query: string; kind: string; service: string; category: string; sort: string; page: number; pageSize: number };
export const defaultPolicyDirectoryView: PolicyDirectoryView = { query: "", kind: "all", service: "all", category: "all", sort: "name", page: 1, pageSize: 10 };
export type UserDirectoryView = { query: string; state: string; role: string };
const defaultUserDirectoryView: UserDirectoryView = { query: "", state: "all", role: "all" };

export type PasswordResetUnknown = PasswordResetRequestIdentity & Readonly<{
  userQualifiedName: string;
}>;
export type PasswordResetLookup =
  | { requestId: string; status: "confirmed"; completion: UserPasswordResetCompletion }
  | { requestId: string; status: "unresolved" | "denied" | "unavailable" };

const passwordResetUnknownStoragePrefix = "matrix-iam-user-reset-unknown:v1:";
const accessKeyCreateStoragePrefix = "matrix-iam-access-key-create:v1:";
const accountSecuritySettingsStoragePrefix = "matrix-iam-account-security-settings:v1:";
const userPolicyChangeStoragePrefix = "matrix-iam-user-policy-change:v1:";

function userPolicyChangeStorageKey(accountId: string, actorId: string): string {
  return userPolicyChangeStoragePrefix + encodeURIComponent(accountId) + ":" + encodeURIComponent(actorId);
}

function readUserPolicyChangeIntent(accountId: string, actorId: string): UserPolicyChangeIntent | null {
  try {
    const raw = window.sessionStorage.getItem(userPolicyChangeStorageKey(accountId, actorId));
    if (!raw || raw.length > 8192) return null;
    const value: unknown = JSON.parse(raw);
    if (!value || typeof value !== "object" || Array.isArray(value)) return null;
    const record = value as Record<string, unknown>;
    const common = ["kind", "accountId", "actorId", "userId", "userQualifiedName", "policyId", "policyDisplayName", "policyScope", "requestId", "phase", "lookupStatus", "completion", "error"];
    const specific = record.kind === "attach" ? ["defaultVersionId", "policyResourceVersion"] :
      record.kind === "revoke" ? ["attachmentId", "attachmentResourceVersion"] : null;
    if (!specific || Object.keys(record).length !== common.length + specific.length ||
        [...common, ...specific].some((field) => !Object.hasOwn(record, field)) ||
        record.accountId !== accountId || record.actorId !== actorId || record.phase !== "unknown" ||
        !["unchecked", "stillUnknown", "forbidden", "unavailable", "expired"].includes(String(record.lookupStatus)) ||
        record.completion !== null || record.error !== null ||
        typeof record.userId !== "string" || !record.userId || record.userId.length > 256 ||
        typeof record.userQualifiedName !== "string" || !record.userQualifiedName || record.userQualifiedName.length > 512 ||
        typeof record.policyId !== "string" || !record.policyId || record.policyId.length > 256 ||
        typeof record.policyDisplayName !== "string" || !record.policyDisplayName || record.policyDisplayName.length > 256 ||
        (record.policyScope !== "TENANT" && record.policyScope !== "INSTALLATION") ||
        typeof record.requestId !== "string" || !new RegExp(`^ui-user-${record.kind === "attach" ? "attachment" : "revocation"}-[0-9a-f]{32}$`).test(record.requestId)) return null;
    if (record.kind === "attach") {
      if (typeof record.defaultVersionId !== "string" || !record.defaultVersionId || record.defaultVersionId.length > 256 ||
          typeof record.policyResourceVersion !== "number" || !Number.isSafeInteger(record.policyResourceVersion) ||
          record.policyResourceVersion < 1 || record.policyResourceVersion >= Number.MAX_SAFE_INTEGER) return null;
    } else if (typeof record.attachmentId !== "string" || !record.attachmentId || record.attachmentId.length > 256 ||
        typeof record.attachmentResourceVersion !== "number" || !Number.isSafeInteger(record.attachmentResourceVersion) ||
        record.attachmentResourceVersion < 1 || record.attachmentResourceVersion >= Number.MAX_SAFE_INTEGER) return null;
    return record as UserPolicyChangeIntent;
  } catch { return null; }
}

function storeUserPolicyChangeIntent(intent: UserPolicyChangeIntent): void {
  const reminder: UserPolicyChangeIntent = { ...intent, phase: "unknown", completion: null, error: null,
    lookupStatus: intent.lookupStatus === "confirmed" ? "unchecked" : intent.lookupStatus };
  try { window.sessionStorage.setItem(userPolicyChangeStorageKey(intent.accountId, intent.actorId), JSON.stringify(reminder)); }
  catch { /* The in-memory lock remains active while this tab is alive. */ }
}

function clearUserPolicyChangeIntent(intent: UserPolicyChangeIntent): void {
  try { window.sessionStorage.removeItem(userPolicyChangeStorageKey(intent.accountId, intent.actorId)); }
  catch { /* Storage loss cannot prove the original relationship command failed. */ }
}

function sameSecuritySettingsIntent(left: SecuritySettingsUpdateIntent, right: SecuritySettingsUpdateIntent): boolean {
  return left.expectedResourceVersion === right.expectedResourceVersion &&
    left.mfa.requiredForUsers === right.mfa.requiredForUsers &&
    left.password.minimumLength === right.password.minimumLength &&
    left.password.requireLowercase === right.password.requireLowercase &&
    left.password.requireUppercase === right.password.requireUppercase &&
    left.password.requireDigit === right.password.requireDigit &&
    left.password.requireSymbol === right.password.requireSymbol &&
    left.password.historyCount === right.password.historyCount &&
    left.password.maxAgeDays === right.password.maxAgeDays &&
    left.password.expiryMode === right.password.expiryMode &&
    left.session.idleTimeoutMinutes === right.session.idleTimeoutMinutes &&
    accessKeyNetworkRestrictionsEqual(left.accessKeyNetwork, right.accessKeyNetwork);
}

function validSecuritySettingsIntent(value: unknown): value is SecuritySettingsUpdateIntent {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  if (Object.keys(record).length !== 5 || !["expectedResourceVersion", "mfa", "password", "session", "accessKeyNetwork"].every((field) => Object.hasOwn(record, field)) ||
      typeof record.expectedResourceVersion !== "number" || !Number.isSafeInteger(record.expectedResourceVersion) || record.expectedResourceVersion < 1 ||
      !record.mfa || typeof record.mfa !== "object" || Array.isArray(record.mfa) ||
      !record.password || typeof record.password !== "object" || Array.isArray(record.password) ||
      !record.session || typeof record.session !== "object" || Array.isArray(record.session) ||
      !record.accessKeyNetwork || typeof record.accessKeyNetwork !== "object" || Array.isArray(record.accessKeyNetwork)) return false;
  const mfa = record.mfa as Record<string, unknown>;
  const password = record.password as Record<string, unknown>;
  const session = record.session as Record<string, unknown>;
  const passwordFields = ["minimumLength", "requireLowercase", "requireUppercase", "requireDigit", "requireSymbol", "historyCount", "maxAgeDays", "expiryMode"];
  return Object.keys(mfa).length === 1 && typeof mfa.requiredForUsers === "boolean" &&
    Object.keys(password).length === passwordFields.length && passwordFields.every((field) => Object.hasOwn(password, field)) &&
    typeof password.minimumLength === "number" && Number.isSafeInteger(password.minimumLength) && password.minimumLength >= 1 &&
    typeof password.requireLowercase === "boolean" && typeof password.requireUppercase === "boolean" &&
    typeof password.requireDigit === "boolean" && typeof password.requireSymbol === "boolean" &&
    typeof password.historyCount === "number" && Number.isSafeInteger(password.historyCount) && password.historyCount >= 0 &&
    typeof password.maxAgeDays === "number" && Number.isSafeInteger(password.maxAgeDays) && password.maxAgeDays >= 0 &&
    (password.expiryMode === "CHANGE_PASSWORD" || password.expiryMode === "ADMIN_RESET") &&
    Object.keys(session).length === 1 && typeof session.idleTimeoutMinutes === "number" &&
    Number.isSafeInteger(session.idleTimeoutMinutes) && session.idleTimeoutMinutes >= 1 &&
    accessKeyNetworkRestrictionsValid(record.accessKeyNetwork as AccessKeyNetworkRestrictions);
}

function validSecurityStepUp(value: unknown, requestId: string, expectedFactorRevision: number, settings: SecuritySettingsUpdateIntent): value is SecurityStepUp {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  const fields = ["id", "requestId", "operation", "expectedFactorRevision", "securitySettings", "state", "createdAt", "expiresAt", "provedAt", "consumedAt"];
  if (Object.keys(record).length !== fields.length || fields.some((field) => !Object.hasOwn(record, field)) ||
      typeof record.id !== "string" || !record.id || record.requestId !== requestId ||
      record.operation !== "SECURITY_SETTINGS_UPDATE" || record.expectedFactorRevision !== expectedFactorRevision ||
      !validSecuritySettingsIntent(record.securitySettings) || !sameSecuritySettingsIntent(record.securitySettings, settings) ||
      !["PENDING", "PROVED", "CONSUMED", "EXPIRED"].includes(String(record.state)) ||
      typeof record.createdAt !== "string" || !Number.isFinite(Date.parse(record.createdAt)) ||
      typeof record.expiresAt !== "string" || !Number.isFinite(Date.parse(record.expiresAt)) || Date.parse(record.createdAt) > Date.parse(record.expiresAt) ||
      record.provedAt !== null && (typeof record.provedAt !== "string" || !Number.isFinite(Date.parse(record.provedAt))) ||
      record.consumedAt !== null && (typeof record.consumedAt !== "string" || !Number.isFinite(Date.parse(record.consumedAt)))) return false;
  return true;
}

function accountSecuritySettingsStorageKey(accountId: string, actorId: string): string {
  return accountSecuritySettingsStoragePrefix + encodeURIComponent(accountId) + ":" + encodeURIComponent(actorId);
}

function readAccountSecuritySettingsIntent(accountId: string, actorId: string): AccountSecuritySettingsMutationIntent | null {
  try {
    const raw = window.sessionStorage.getItem(accountSecuritySettingsStorageKey(accountId, actorId));
    if (!raw || raw.length > 16384) return null;
    const value: unknown = JSON.parse(raw);
    if (!value || typeof value !== "object" || Array.isArray(value)) return null;
    const record = value as Record<string, unknown>;
    const fields = ["accountId", "actorId", "requestId", "expectedFactorRevision", "state", "settings", "stepUp"];
    if (Object.keys(record).length !== fields.length || fields.some((field) => !Object.hasOwn(record, field)) ||
        record.accountId !== accountId || record.actorId !== actorId ||
        typeof record.requestId !== "string" || !/^ui-account-security-settings-[0-9a-f]{32}$/.test(record.requestId) ||
        typeof record.expectedFactorRevision !== "number" || !Number.isSafeInteger(record.expectedFactorRevision) || record.expectedFactorRevision < 1 ||
        !["STEP_UP_UNKNOWN", "PENDING", "VERIFICATION_UNKNOWN", "PROVED", "APPLY_UNKNOWN", "COMPLETED", "EXPIRED"].includes(String(record.state)) ||
        !validSecuritySettingsIntent(record.settings)) return null;
    const state = record.state as AccountSecuritySettingsMutationState;
    if (state === "STEP_UP_UNKNOWN" ? record.stepUp !== null :
      !validSecurityStepUp(record.stepUp, record.requestId, record.expectedFactorRevision, record.settings)) return null;
    return record as AccountSecuritySettingsMutationIntent;
  } catch { return null; }
}

function storeAccountSecuritySettingsIntent(intent: AccountSecuritySettingsMutationIntent): void {
  try { window.sessionStorage.setItem(accountSecuritySettingsStorageKey(intent.accountId, intent.actorId), JSON.stringify(intent)); }
  catch { /* The in-memory lock remains authoritative while this tab is alive. */ }
}

function clearAccountSecuritySettingsIntent(intent: AccountSecuritySettingsMutationIntent): void {
  try { window.sessionStorage.removeItem(accountSecuritySettingsStorageKey(intent.accountId, intent.actorId)); }
  catch { /* Retaining an old reminder is safer than silently unlocking an unresolved write. */ }
}

function accessKeyCreateStorageKey(accountId: string, actorId: string): string {
  return accessKeyCreateStoragePrefix + encodeURIComponent(accountId) + ":" + encodeURIComponent(actorId);
}
function readAccessKeyCreateIntent(accountId: string, actorId: string): AccessKeyCreateIntent | null {
  try {
    const raw = window.sessionStorage.getItem(accessKeyCreateStorageKey(accountId, actorId));
    if (!raw || raw.length > 2048) return null;
    const value: unknown = JSON.parse(raw);
    if (!value || typeof value !== "object" || Array.isArray(value)) return null;
    const record = value as Record<string, unknown>;
    const base = ["accountId", "actorId", "userId", "userResourceVersion", "networkRestrictions", "requestId", "phase"];
    if (record.accountId !== accountId || record.actorId !== actorId ||
      typeof record.userId !== "string" || !record.userId || record.userId.length > 256 ||
      typeof record.userResourceVersion !== "number" || !Number.isSafeInteger(record.userResourceVersion) || record.userResourceVersion < 1 ||
      !record.networkRestrictions || typeof record.networkRestrictions !== "object" || Array.isArray(record.networkRestrictions) ||
      !accessKeyNetworkRestrictionsValid(record.networkRestrictions as AccessKeyNetworkRestrictions) ||
      typeof record.requestId !== "string" || !/^ui-access-key-create-[0-9a-f]{32}$/.test(record.requestId) ||
      (record.phase !== "unknown" && record.phase !== "recovered") ||
      Object.keys(record).length !== base.length + (record.phase === "recovered" ? 1 : 0) ||
      base.some((field) => !Object.hasOwn(record, field)) ||
      (record.phase === "recovered" && (typeof record.keyId !== "string" || !record.keyId || record.keyId.length > 256))) return null;
    return record as AccessKeyCreateIntent;
  } catch { return null; }
}
function storeAccessKeyCreateIntent(intent: AccessKeyCreateIntent): void {
  try { window.sessionStorage.setItem(accessKeyCreateStorageKey(intent.accountId, intent.actorId), JSON.stringify(intent)); }
  catch { /* The in-memory lock remains active if tab storage is unavailable. */ }
}
function clearAccessKeyCreateIntent(intent: AccessKeyCreateIntent): void {
  try { window.sessionStorage.removeItem(accessKeyCreateStorageKey(intent.accountId, intent.actorId)); }
  catch { /* Storage loss does not prove the original request was not applied. */ }
}
function passwordResetUnknownStorageKey(accountId: string, actorId: string): string {
  return passwordResetUnknownStoragePrefix + encodeURIComponent(accountId) + ":" + encodeURIComponent(actorId);
}
function readPasswordResetUnknown(accountId: string, actorId: string): PasswordResetUnknown | null {
  try {
    const raw = window.sessionStorage.getItem(passwordResetUnknownStorageKey(accountId, actorId));
    if (!raw || raw.length > 2048) return null;
    const value: unknown = JSON.parse(raw);
    if (!value || typeof value !== "object" || Array.isArray(value)) return null;
    const record = value as Record<string, unknown>;
    const fields = ["accountId", "actorId", "userId", "userQualifiedName", "resourceVersion", "requestId"];
    if (Object.keys(record).length !== fields.length || fields.some((field) => !Object.hasOwn(record, field))) return null;
    if (record.accountId !== accountId || record.actorId !== actorId ||
      typeof record.userId !== "string" || !record.userId || record.userId.length > 256 ||
      typeof record.userQualifiedName !== "string" || !record.userQualifiedName || record.userQualifiedName.length > 512 ||
      typeof record.resourceVersion !== "number" || !Number.isSafeInteger(record.resourceVersion) || record.resourceVersion < 1 || record.resourceVersion > Number.MAX_SAFE_INTEGER - 1 ||
      typeof record.requestId !== "string" || !/^ui-user-reset-[0-9a-f]{32}$/.test(record.requestId)) return null;
    return record as PasswordResetUnknown;
  } catch { return null; }
}
function storePasswordResetUnknown(intent: PasswordResetUnknown): void {
  try { window.sessionStorage.setItem(passwordResetUnknownStorageKey(intent.accountId, intent.actorId), JSON.stringify(intent)); }
  catch { /* The visible in-memory warning remains; tab storage is only a best-effort reminder. */ }
}
function clearPasswordResetUnknown(intent: PasswordResetUnknown): void {
  try { window.sessionStorage.removeItem(passwordResetUnknownStorageKey(intent.accountId, intent.actorId)); }
  catch { /* A stale reminder is safer than treating storage loss as proof of completion. */ }
}

type AccountAccess = {
  supportsUserBatch: boolean;
  executeUserBatch(command: UserBatchCommand): Promise<boolean>;
  policyDirectoryView: { read(): PolicyDirectoryView; remember(value: PolicyDirectoryView): void };
  userDirectoryView: { read(): UserDirectoryView; remember(value: UserDirectoryView): void };
  workspace: AccessWorkspace | null;
  workspaceError: WorkspaceExecutionError | null;
  executeWorkspace(command: AccessWorkspaceCommand, onError?: (error: WorkspaceExecutionError) => void): Promise<{ issuedKey?: { id: string; secret: string }; recoveryCodes?: string[] } | null>;
  clearWorkspaceError(): void;
  clearFeedback(): void;
  groups: GroupAccessClient | null;
  permissionBoundaries: UserBoundaryClient | null;
  authorizationProfiles: AuthorizationProfileClient | null;
  serviceRoleTemplates: ServiceRoleTemplateClient | null;
  serviceLinkedRoles: ServiceLinkedRoleClient | null;
  policyRead: AccountPolicyReadClient | null;
  policyCreate: PolicyCreateClient | null;
  policyVersionMutation: PolicyVersionMutationClient | null;
  accountSecuritySettings: AccountSecuritySettingsClient | null;
  accessAnalysis: AccessAnalysisClient | null;
  securityReports: SecurityReportClient | null;
  accessKeys: AccessKeyClient | null;
  accessKeyCreateIntent: AccessKeyCreateIntent | null;
  roles: RoleAccessClient | null;
  roleSessionRevokeIntent: RoleSessionRevokeIntent | null;
  changeRoleSessionRevokeIntent(expectedRequestId: string | null, next: RoleSessionRevokeIntent | null): void;
  userPolicyChangeIntent: UserPolicyChangeIntent | null;
  beginUserPolicyAttachment(user: AccountUserScene, policyId: string): boolean;
  beginUserPolicyRevocation(user: AccountUserScene, attachmentId: string): boolean;
  submitUserPolicyChange(requestId: string): Promise<boolean>;
  inspectUserPolicyChange(requestId: string): Promise<boolean>;
  endUserPolicyChange(requestId: string): boolean;
  scene: AccountAccessScene | null;
  loading: boolean;
  busy: boolean;
  error: AccountError | null;
  success: "completed" | null;
  reload(): void;
  usersPage(after: string): void;
  accountsPage(after: string): void;
  loadUser(userId: string): Promise<AccountUserScene>;
  passwordResetUnknown: PasswordResetUnknown | null;
  passwordResetLookup: PasswordResetLookup | null;
  resetUserPassword(user: AccountUserScene, initialPassword: string): Promise<"applied" | "rejected" | "unknown">;
  lookupUnknownPasswordReset(requestId: string): Promise<void>;
  acknowledgeUnknownPasswordReset(requestId: string): boolean;
  execute(command: Exclude<AccountCommand, { kind: "reset-password" }>): Promise<boolean>;
};

const AccountAccessContext = createContext<AccountAccess | null>(null);
type AccountCapabilities = Pick<AccountAccessScene, "canListUsers" | "canListGroups" | "canListRoles" | "canReadAccounts" | "canCreateAccounts" | "canViewPolicies"> & { hasPreviewWorkspace: boolean; supportsLiveRoles: boolean };
const AccountCapabilitiesContext = createContext<AccountCapabilities | null>(null);

export function accountError(error: unknown): AccountError {
  if (error instanceof HttpProblem) {
    if (error.status === 401) return "expired";
    if (error.status === 403) return "forbidden";
    if (error.status === 409) return "conflict";
    if (error.status === 422 || error.status === 400) return "invalid";
  }
  return "unavailable";
}

async function readWhenAuthorized<T>(read: () => Promise<T>): Promise<T | null> {
  try {
    return await read();
  } catch (error) {
    if (error instanceof HttpProblem && error.status === 403) return null;
    throw error;
  }
}

function accountCommandAvailable(scene: AccountAccessScene, command: AccountCommand): boolean {
  if (command.kind === "create-user") return scene.canCreateUsers;
  if (command.kind === "create-account") return scene.canCreateAccounts;
  if (command.kind === "set-alias") return scene.canSetAlias;
  if (command.kind === "set-account-status" || command.kind === "recover-root-credentials") {
    const account = scene.accounts.find((item) => item.id === command.accountId);
    return command.kind === "set-account-status" ? account?.canSetStatus === true : account?.canRecoverRoot === true;
  }
  const user = scene.users.find((item) => item.id === command.userId);
  if (!user) return false;
  if (command.kind === "update-user") return user.canUpdate;
  if (command.kind === "delete-user") return user.canDelete;
  if (command.kind === "set-status") return user.canSetStatus;
  if (command.kind === "reset-password") return user.canResetPassword;
  const policy = scene.policies.find((item) => item.id === command.policyId);
  if (!policy || policy.status !== "ACTIVE" || policy.resourceVersion !== command.policyResourceVersion) return false;
  return policy.scope === "INSTALLATION" ? user.canAttachPlatformPolicy : user.canAttachTenantPolicy;
}

export function AccountAccessProvider({ children, repository = httpAccountRepository, active = true }: { children: ReactNode; repository?: AccountRepository; active?: boolean }) {
  const credential = useSessionCredential();
  const session = useSession();
  const expireSession = session.expire;
  const tenantId = session.current?.session.organizationId;
  const principalId = session.current?.session.principalId;
  const sessionId = session.current?.session.id;
  const sessionRevision = session.sessionRevision;
  const [scene, setScene] = useState<AccountAccessScene | null>(null);
  const [workspace, setWorkspace] = useState<AccessWorkspace | null>(null);
  const [workspaceError, setWorkspaceError] = useState<AccountAccess["workspaceError"]>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<AccountError | null>(null);
  const [success, setSuccess] = useState<"completed" | null>(null);
  const [revision, setRevision] = useState(0);
  const mutationPending = useRef(false);
  const directoryRequest = useRef({ users: 0, accounts: 0 });
  // View context survives list/detail navigation, not account/session changes.
  // Keeping it outside React state avoids rerendering the shell on each keystroke.
  const viewSession = useMemo(() => ({ credential, tenantId, principalId, sessionRevision }), [credential, tenantId, principalId, sessionRevision]);
  const currentViewSession = useRef(viewSession);
  const verifiedIdentitySession = useRef<typeof viewSession | null>(null);
  useLayoutEffect(() => { currentViewSession.current = viewSession; }, [viewSession]);
  const [storedRoleSessionRevokeIntent, setStoredRoleSessionRevokeIntent] = useState<{ session: typeof viewSession; intent: RoleSessionRevokeIntent } | null>(null);
  const roleSessionRevokeIntent = storedRoleSessionRevokeIntent?.session === viewSession ? storedRoleSessionRevokeIntent.intent : null;
  const userPolicyChangeIdentityKey = active && tenantId && principalId && !repository.workspace
    ? userPolicyChangeStorageKey(tenantId, principalId) : null;
  const [storedUserPolicyChange, setStoredUserPolicyChange] = useState<{
    session: typeof viewSession;
    intent: UserPolicyChangeIntent | null;
  }>(() => ({
    session: viewSession,
    intent: userPolicyChangeIdentityKey && typeof window !== "undefined" && tenantId && principalId
      ? readUserPolicyChangeIntent(tenantId, principalId) : null
  }));
  if (storedUserPolicyChange.session !== viewSession) {
    const restored = userPolicyChangeIdentityKey && typeof window !== "undefined" && tenantId && principalId
      ? readUserPolicyChangeIntent(tenantId, principalId) : null;
    setStoredUserPolicyChange({ session: viewSession, intent: restored });
  }
  const userPolicyChangeIntent = storedUserPolicyChange.session === viewSession ? storedUserPolicyChange.intent : null;
  const userPolicyChangeRef = useRef<{ session: typeof viewSession; intent: UserPolicyChangeIntent } | null>(
    userPolicyChangeIntent ? { session: viewSession, intent: userPolicyChangeIntent } : null
  );
  useLayoutEffect(() => {
    userPolicyChangeRef.current = userPolicyChangeIntent ? { session: viewSession, intent: userPolicyChangeIntent } : null;
  }, [userPolicyChangeIntent, viewSession]);
  const passwordResetUnknownRef = useRef<{ session: typeof viewSession; intent: PasswordResetUnknown } | null>(null);
  const [storedPasswordResetUnknown, setStoredPasswordResetUnknown] = useState<typeof passwordResetUnknownRef.current>(null);
  const passwordResetUnknown = storedPasswordResetUnknown?.session === viewSession ? storedPasswordResetUnknown.intent : null;
  const [storedPasswordResetLookup, setStoredPasswordResetLookup] = useState<{ session: typeof viewSession; result: PasswordResetLookup } | null>(null);
  const accessKeyCreateRef = useRef<{ session: typeof viewSession; intent: AccessKeyCreateIntent } | null>(null);
  const accessKeyCreateSubmitting = useRef<{ session: typeof viewSession; requestId: string } | null>(null);
  const accessKeyIssuedRef = useRef<{ session: typeof viewSession; requestId: string; accessKeyId: string } | null>(null);
  const [storedAccessKeyCreate, setStoredAccessKeyCreate] = useState<typeof accessKeyCreateRef.current>(null);
  const accessKeyCreateIntent = storedAccessKeyCreate?.session === viewSession ? storedAccessKeyCreate.intent : null;
  const securitySettingsIntentRef = useRef<AccountSecuritySettingsMutationIntent | null>(null);
  const securitySettingsIdentityKey = active && tenantId && principalId && !repository.workspace
    ? accountSecuritySettingsStorageKey(tenantId, principalId) : null;
  const [storedSecuritySettingsIntent, setStoredSecuritySettingsIntent] = useState<{
    identityKey: string | null;
    intent: AccountSecuritySettingsMutationIntent | null;
  }>({ identityKey: null, intent: null });
  if (storedSecuritySettingsIntent.identityKey !== securitySettingsIdentityKey) {
    const restored = securitySettingsIdentityKey && typeof window !== "undefined" && tenantId && principalId
      ? readAccountSecuritySettingsIntent(tenantId, principalId) : null;
    setStoredSecuritySettingsIntent({ identityKey: securitySettingsIdentityKey, intent: restored });
  }
  const securitySettingsIntent = storedSecuritySettingsIntent.identityKey === securitySettingsIdentityKey
    ? storedSecuritySettingsIntent.intent : null;
  useLayoutEffect(() => { securitySettingsIntentRef.current = securitySettingsIntent; }, [securitySettingsIntent]);
  const securitySettingsMutationPending = useRef<string | null>(null);
  const passwordResetLookup = storedPasswordResetLookup?.session === viewSession && storedPasswordResetLookup.result.requestId === passwordResetUnknown?.requestId
    ? storedPasswordResetLookup.result : null;
  useEffect(() => {
    const stored = passwordResetUnknownRef.current;
    if (!stored || stored.session === viewSession) return;
    passwordResetUnknownRef.current = null;
    setStoredPasswordResetUnknown(null);
    setStoredPasswordResetLookup(null);
  }, [viewSession]);
  useEffect(() => {
    if (accessKeyCreateRef.current?.session === viewSession) return;
    accessKeyCreateRef.current = null;
    accessKeyIssuedRef.current = null;
    setStoredAccessKeyCreate(null);
  }, [viewSession]);
  const rememberSecuritySettingsIntent = useCallback((expectedRequestId: string | null, next: AccountSecuritySettingsMutationIntent | null): boolean => {
    if (currentViewSession.current !== viewSession || !tenantId || !principalId || !securitySettingsIdentityKey) return false;
    const current = securitySettingsIntentRef.current;
    if (expectedRequestId === null) {
      if (current || !next || next.accountId !== tenantId || next.actorId !== principalId) return false;
    } else if (!current || current.requestId !== expectedRequestId || next && (
      next.requestId !== current.requestId || next.accountId !== current.accountId || next.actorId !== current.actorId ||
      next.expectedFactorRevision !== current.expectedFactorRevision || !sameSecuritySettingsIntent(next.settings, current.settings)
    )) return false;
    securitySettingsIntentRef.current = next;
    setStoredSecuritySettingsIntent({ identityKey: securitySettingsIdentityKey, intent: next });
    if (next) storeAccountSecuritySettingsIntent(next);
    else if (current) clearAccountSecuritySettingsIntent(current);
    return true;
  }, [principalId, securitySettingsIdentityKey, tenantId, viewSession]);
  const rememberUserPolicyChange = useCallback((expectedRequestId: string | null, next: UserPolicyChangeIntent | null): boolean => {
    if (currentViewSession.current !== viewSession) return false;
    const stored = userPolicyChangeRef.current;
    const current = stored?.session === viewSession ? stored.intent : null;
    if (expectedRequestId === null) {
      if (current || !next || next.accountId !== tenantId || next.actorId !== principalId) return false;
    } else if (!current || current.requestId !== expectedRequestId || next && (
      next.requestId !== current.requestId || next.accountId !== current.accountId || next.actorId !== current.actorId || next.kind !== current.kind || next.userId !== current.userId ||
      next.userQualifiedName !== current.userQualifiedName || next.policyId !== current.policyId ||
      next.policyDisplayName !== current.policyDisplayName || next.policyScope !== current.policyScope ||
      (next.kind === "attach" && current.kind === "attach" ?
        next.policyResourceVersion !== current.policyResourceVersion || next.defaultVersionId !== current.defaultVersionId :
        next.kind === "revoke" && current.kind === "revoke" ?
          next.attachmentId !== current.attachmentId || next.attachmentResourceVersion !== current.attachmentResourceVersion : true)
    )) return false;
    userPolicyChangeRef.current = next ? { session: viewSession, intent: next } : null;
    setStoredUserPolicyChange({ session: viewSession, intent: next });
    if (next && (next.phase === "submitting" || next.phase === "unknown" || next.phase === "checking")) storeUserPolicyChangeIntent(next);
    else if (current) clearUserPolicyChangeIntent(current);
    return true;
  }, [principalId, tenantId, viewSession]);
  const policyCreateRef = useRef<{ session: typeof viewSession; intent: PolicyCreateIntent } | null>(null);
  const [storedPolicyCreate, setStoredPolicyCreate] = useState<typeof policyCreateRef.current>(null);
  const policyCreateIntent = storedPolicyCreate?.session === viewSession ? storedPolicyCreate.intent : null;
  const rememberPolicyCreate = useCallback((expectedRequestId: string | null, next: PolicyCreateIntent | null): boolean => {
    if (currentViewSession.current !== viewSession) return false;
    const stored = policyCreateRef.current;
    const current = stored?.session === viewSession ? stored.intent : null;
    if (expectedRequestId === null) {
      if (current || !next || next.accountId !== tenantId) return false;
    } else if (!current || current.requestId !== expectedRequestId || next && (
      next.accountId !== current.accountId || next.requestId !== current.requestId ||
      next.displayName !== current.displayName || next.documentJSON !== current.documentJSON
    )) return false;
    const updated = next ? { session: viewSession, intent: next } : null;
    policyCreateRef.current = updated;
    setStoredPolicyCreate(updated);
    return true;
  }, [tenantId, viewSession]);
  const versionMutationRef = useRef<{ session: typeof viewSession; intent: PolicyVersionMutationIntent } | null>(null);
  const [storedVersionMutation, setStoredVersionMutation] = useState<typeof versionMutationRef.current>(null);
  const versionMutationIntent = storedVersionMutation?.session === viewSession ? storedVersionMutation.intent : null;
  const rememberVersionMutation = useCallback((expectedRequestId: string | null, next: PolicyVersionMutationIntent | null): boolean => {
    if (currentViewSession.current !== viewSession) return false;
    const stored = versionMutationRef.current;
    const current = stored?.session === viewSession ? stored.intent : null;
    if (expectedRequestId === null) {
      if (current || !next || next.accountId !== tenantId) return false;
    } else {
      if (!current || current.requestId !== expectedRequestId) return false;
      if (next && (
        next.requestId !== current.requestId || next.accountId !== current.accountId || next.policyId !== current.policyId ||
        next.kind !== current.kind || next.resourceVersion !== current.resourceVersion ||
        (next.kind === "publish" && current.kind === "publish" ? next.documentJSON !== current.documentJSON :
          next.kind !== "publish" && current.kind !== "publish" ? next.versionId !== current.versionId : true) ||
        next.expectedDefaultVersionId !== current.expectedDefaultVersionId
      )) return false;
    }
    const updated = next ? { session: viewSession, intent: next } : null;
    versionMutationRef.current = updated;
    setStoredVersionMutation(updated);
    return true;
  }, [tenantId, viewSession]);
  const changeRoleSessionRevokeIntent = useCallback((expectedRequestId: string | null, next: RoleSessionRevokeIntent | null) => {
    setStoredRoleSessionRevokeIntent((stored) => {
      const current = stored?.session === viewSession ? stored.intent : null;
      if (expectedRequestId === null) {
        if (current || !next || next.accountId !== tenantId || next.item.session.accountId !== tenantId || next.item.session.roleId !== next.roleId) return stored;
        return { session: viewSession, intent: next };
      }
      if (!current || current.requestId !== expectedRequestId) return stored;
      if (next && (
        next.requestId !== current.requestId || next.accountId !== current.accountId || next.roleId !== current.roleId ||
        next.item.session.id !== current.item.session.id || next.item.session.accountId !== current.item.session.accountId || next.item.session.roleId !== current.item.session.roleId
      )) return stored;
      return next ? { session: viewSession, intent: next } : null;
    });
  }, [tenantId, viewSession]);
  const unrecoverableAccountRule = useRef<{ session: typeof viewSession; intent: PendingAccountRuleChange } | null>(null);
  const storedPolicyView = useRef<{ session: typeof viewSession; view: PolicyDirectoryView } | null>(null);
  const policyDirectoryView = useMemo(() => ({
    read() { const stored = storedPolicyView.current; return stored?.session === viewSession ? stored.view : { ...defaultPolicyDirectoryView }; },
    remember(view: PolicyDirectoryView) { storedPolicyView.current = { session: viewSession, view: { ...view } }; }
  }), [viewSession]);
  const clearWorkspaceError = useCallback(() => setWorkspaceError(null), []);
  const protectedMutation = useCallback(<T,>(request: () => Promise<T>): Promise<T> => {
    if (workspace?.personalMfa.reauthenticationRequired) {
      setWorkspaceError("reauthenticationRequired");
      return Promise.reject(new AccessWorkspaceError("reauthenticationRequired"));
    }
    return request();
  }, [workspace?.personalMfa.reauthenticationRequired]);
  const storedUserView = useRef<{ session: typeof viewSession; view: UserDirectoryView } | null>(null);
  const userDirectoryView = useMemo(() => ({
    read() { const stored = storedUserView.current; return stored?.session === viewSession ? stored.view : { ...defaultUserDirectoryView }; },
    remember(view: UserDirectoryView) { storedUserView.current = { session: viewSession, view: { ...view } }; }
  }), [viewSession]);
  const clearFeedback = useCallback(() => { setWorkspaceError(null); setSuccess(null); }, []);
  const canListUsers = Boolean(scene?.canListUsers);
  const canListGroups = Boolean(scene?.canListGroups);
  const canListRoles = Boolean(scene?.canListRoles);
  const canReadAccounts = Boolean(scene?.canReadAccounts);
  const canCreateAccounts = Boolean(scene?.canCreateAccounts);
  const canViewPolicies = Boolean(scene?.canViewPolicies);
  const hasPreviewWorkspace = Boolean(repository.workspace);
  const supportsLiveRoles = Boolean(repository.roles);
  // Navigation observes permission changes, not every form's pending/error state.
  const capabilities = useMemo(() => ({ canListUsers, canListGroups, canListRoles, canReadAccounts, canCreateAccounts, canViewPolicies, hasPreviewWorkspace, supportsLiveRoles }), [canCreateAccounts, canListGroups, canListRoles, canListUsers, canReadAccounts, canViewPolicies, hasPreviewWorkspace, supportsLiveRoles]);

  useEffect(() => {
    if (!active || !credential || !tenantId) return;
    if (unrecoverableAccountRule.current?.session !== viewSession) unrecoverableAccountRule.current = null;
    let mounted = true;
    directoryRequest.current.users += 1;
    directoryRequest.current.accounts += 1;
    async function read() {
      const identity = await repository.currentIdentity(credential!);
      if (identity.account.id !== tenantId || identity.user.id !== principalId) throw new Error("INVALID_IAM_IDENTITY");
      const currentCapability = (action: Parameters<typeof findActionCapability>[1], id = identity.account.id) =>
        findActionCapability(identity.capabilities, action, "ACCOUNT", id)?.available === true;
      const [users, accounts, tenantPolicies, platformPolicies] = await Promise.all([
        currentCapability("iam.user.list") ? readWhenAuthorized(() => repository.listUsers(credential!)) : null,
        currentCapability("iam.account.read", "collection") ? readWhenAuthorized(() => repository.listAccounts(credential!)) : null,
        currentCapability("iam.policy.list") ? readWhenAuthorized(() => repository.listPolicies(credential!, false)) : null,
        readWhenAuthorized(() => repository.listPolicies(credential!, true))
      ]);
      // The advanced workspace is an explicit preview capability. Do not fetch its
      // larger graph unless the live directory boundary has authorized management.
      let extension = users !== null && repository.workspace ? await repository.workspace.read(credential!) : null;
      const localLock = unrecoverableAccountRule.current?.session === viewSession ? unrecoverableAccountRule.current.intent : null;
      if (extension && localLock) {
        if (extension.pendingAccountRuleChange && extension.pendingAccountRuleChange.requestId !== localLock.requestId) throw new Error("INVALID_PREVIEW_RECOVERY_STATE");
        extension = { ...extension, pendingAccountRuleChange: extension.pendingAccountRuleChange ?? localLock };
      }
      if (users?.items.some((entry) => entry.user.accountId !== tenantId || entry.user.id === identity.account.rootIdentity.principalId)) throw new Error("INVALID_IAM_TENANT");
      if (tenantPolicies && tenantPolicies.accountId !== tenantId) throw new Error("INVALID_IAM_TENANT");
      if (platformPolicies && platformPolicies.accountId !== tenantId) throw new Error("INVALID_IAM_TENANT");
      if (extension && (extension.accountId !== tenantId || extension.mode !== "preview")) throw new Error("INVALID_IAM_TENANT");
      return { scene: buildAccountAccessScene(identity, users, accounts, tenantPolicies, platformPolicies), extension };
    }
    read().then((loaded) => { if (mounted && currentViewSession.current === viewSession) {
      verifiedIdentitySession.current = viewSession;
      if (!repository.workspace && loaded.scene.accountId === tenantId && loaded.scene.currentUserId === principalId &&
        passwordResetUnknownRef.current?.session !== viewSession) {
        const intent = readPasswordResetUnknown(tenantId, principalId);
        if (intent) {
          const stored = { session: viewSession, intent };
          passwordResetUnknownRef.current = stored;
          setStoredPasswordResetUnknown(stored);
        }
      }
      if (!repository.workspace && loaded.scene.accountId === tenantId && loaded.scene.currentUserId === principalId &&
        accessKeyCreateRef.current?.session !== viewSession) {
        const intent = readAccessKeyCreateIntent(tenantId, principalId);
        if (intent) {
          const stored = { session: viewSession, intent };
          accessKeyCreateRef.current = stored;
          setStoredAccessKeyCreate(stored);
        }
      }
      setScene(loaded.scene); setWorkspace(loaded.extension); setError(null);
    } },
      (failure: unknown) => { if (mounted && currentViewSession.current === viewSession) { verifiedIdentitySession.current = null; setScene(null); setWorkspace(null); setError(accountError(failure)); } })
      .finally(() => { if (mounted) setLoading(false); });
    return () => { mounted = false; };
  }, [active, credential, principalId, repository, revision, tenantId, viewSession]);

  const loadUser = useCallback(async (userId: string): Promise<AccountUserScene> => {
    if (!active || !credential || !scene || !userId || userId === scene.accountOwner.id) throw new Error("INVALID_IAM_USER_TARGET");
    const access = await repository.getUser(credential, userId);
    if (access.user.id !== userId || access.user.accountId !== tenantId) throw new Error("INVALID_IAM_TENANT");
    return buildAccountUserScene({ id: scene.accountId, loginAlias: scene.loginAlias }, scene.policies, access);
  }, [active, credential, repository, scene, tenantId]);

  const inspectPolicyAttachmentChange = useCallback(async (expectation: PolicyAttachmentChangeOperationExpectation): Promise<PolicyAttachmentChange> => {
    const read = repository.readPolicyAttachmentChange;
    if (!active || !credential || !scene || scene.accountId !== tenantId || scene.currentUserId !== principalId || !read) {
      throw new Error("IAM_POLICY_ATTACHMENT_COMPLETION_UNAVAILABLE");
    }
    const bound: PolicyAttachmentChangeExpectation = {
      ...expectation,
      accountId: scene.accountId,
      actorPrincipalId: scene.currentUserId
    };
    try {
      return await read(credential, bound);
    } catch (failure) {
      if (failure instanceof HttpProblem && failure.status === 401 && expireSession(credential, sessionRevision)) {
        setScene(null); setWorkspace(null); setWorkspaceError(null); setSuccess(null); setError("expired");
      }
      throw failure;
    }
  }, [active, credential, expireSession, principalId, repository, scene, sessionRevision, tenantId]);

  const groups = useMemo<GroupAccessClient | null>(() => {
    if (!active || !credential || !scene || scene.accountId !== tenantId) return null;
    const accountId = scene.accountId;
    return {
      accountId,
      actorPrincipalId: scene.currentUserId,
      canList: scene.canListGroups,
      listRestrictionReason: scene.listGroupsRestrictionReason,
      canCreate: scene.canCreateGroups,
      createRestrictionReason: scene.createGroupsRestrictionReason,
      list: (after) => repository.listGroups(credential, accountId, after),
      get: (groupId) => repository.getGroup(credential, accountId, groupId),
      create: (command) => protectedMutation(() => repository.createGroup(credential, accountId, command)),
      update: (groupId, command) => protectedMutation(() => repository.updateGroup(credential, accountId, groupId, command)),
      delete: (groupId, command) => protectedMutation(() => repository.deleteGroup(credential, accountId, groupId, command)),
      listMemberships: (groupId, after) => repository.listGroupMemberships(credential, accountId, groupId, after),
      createMembership: (groupId, command) => protectedMutation(() => repository.createGroupMembership(credential, accountId, groupId, command)),
      removeMembership: (groupId, membershipId, command) => protectedMutation(() => repository.removeGroupMembership(credential, accountId, groupId, membershipId, command)),
      createPolicyAttachment: (groupId, command) => protectedMutation(() => repository.createGroupPolicyAttachment(credential, accountId, groupId, command)),
      revokePolicyAttachment: (attachmentId, command) => protectedMutation(() => repository.revokePolicyAttachment(credential, attachmentId, command)),
      inspectPolicyAttachmentChange
    };
  }, [active, credential, inspectPolicyAttachmentChange, protectedMutation, repository, scene, tenantId]);

  const permissionBoundaries = useMemo<UserBoundaryClient | null>(() => {
    const boundaryRepository = repository.permissionBoundaries;
    if (!active || !credential || !scene || scene.accountId !== tenantId || !boundaryRepository) return null;
    const accountId = scene.accountId;
    const target = (userId: string) => {
      if (!userId || userId === scene.accountOwner.id) throw new Error("INVALID_IAM_USER_TARGET");
      return userId;
    };
    const scoped = async <T,>(request: Promise<T>): Promise<T> => {
      try { return await request; }
      catch (failure) {
        if (failure instanceof HttpProblem && failure.status === 401 && expireSession(credential)) {
          setScene(null); setWorkspace(null); setWorkspaceError(null); setSuccess(null); setError("expired");
        }
        throw failure;
      }
    };
    return {
      accountId,
      load: (userId) => scoped((async () => {
        const access = await repository.getUser(credential, target(userId));
        if (access.user.id !== userId || access.user.accountId !== accountId) throw new Error("INVALID_IAM_TENANT");
        const boundary = await boundaryRepository.read(credential, accountId, userId);
        if (boundary.accountId !== accountId || boundary.userId !== userId) throw new Error("INVALID_IAM_TENANT");
        if (boundary.resourceVersion !== access.user.resourceVersion) throw new HttpProblem(409, "IAM_USER_REVISION_CHANGED");
        const directory = scene.tenantPoliciesAvailable ? await readWhenAuthorized(() => repository.listPolicies(credential, false)) : null;
        if (directory && (directory.accountId !== accountId || directory.scope !== "TENANT")) throw new Error("INVALID_IAM_TENANT");
        const policies = directory?.items ?? [];
        return { user: buildAccountUserScene({ id: accountId, loginAlias: scene.loginAlias }, policies, access), boundary, policies, policiesAvailable: directory !== null };
      })()),
      set: (userId, command) => protectedMutation(() => scoped(boundaryRepository.set(credential, accountId, target(userId), command))),
      remove: (userId, command) => protectedMutation(() => scoped(boundaryRepository.remove(credential, accountId, target(userId), command)))
    };
  }, [active, credential, expireSession, protectedMutation, repository, scene, tenantId]);

  const authorizationProfiles = useMemo<AuthorizationProfileClient | null>(() => {
    if (!active || !credential || !scene || scene.accountId !== tenantId || !scene.canViewPolicies) return null;
    const accountId = scene.accountId;
    return {
      accountId,
      preview: Boolean(repository.workspace),
      async load() {
        try {
          const directory = await repository.listAuthorizationProfiles(credential);
          if (directory.accountId !== accountId) throw new Error("INVALID_IAM_TENANT");
          return { status: "ready", directory };
        } catch (failure) {
          if (failure instanceof HttpProblem) {
            if (failure.status === 401) {
              if (expireSession(credential)) {
                setScene(null); setWorkspace(null); setWorkspaceError(null); setSuccess(null); setError("expired");
              }
              return { status: "expired" };
            }
            if (failure.status === 403) return { status: "forbidden" };
            if (failure.status === 404) return { status: "routeUnavailable" };
          }
          return { status: "unavailable" };
        }
      }
    };
  }, [active, credential, expireSession, repository, scene, tenantId]);

  const serviceRoleTemplates = useMemo<ServiceRoleTemplateClient | null>(() => {
    const read = repository.listServiceRoleTemplates;
    if (!active || !credential || !scene || scene.accountId !== tenantId || repository.workspace || !read) return null;
    return {
      sessionRevision,
      async load() {
        try {
          return { status: "ready", directory: await read(credential) };
        } catch (failure) {
          if (failure instanceof HttpProblem) {
            if (failure.status === 401) {
              if (expireSession(credential, sessionRevision)) {
                setScene(null); setWorkspace(null); setWorkspaceError(null); setSuccess(null); setError("expired");
              }
              return { status: "expired" };
            }
            if (failure.status === 403) return { status: "forbidden" };
            if (failure.status === 404) return { status: "routeUnavailable" };
          }
          return { status: "unavailable" };
        }
      }
    };
  }, [active, credential, expireSession, repository, scene, sessionRevision, tenantId]);

  const serviceLinkedRoles = useMemo<ServiceLinkedRoleClient | null>(() => {
    const list = repository.listServiceLinkedRoles;
    const read = repository.getServiceLinkedRole;
    if (!active || !credential || !scene || scene.accountId !== tenantId || repository.workspace || !list || !read) return null;
    const accountId = scene.accountId;
    const failed = (failure: unknown): Exclude<ServiceLinkedRoleDirectoryLoad, { status: "ready" }> => {
      if (failure instanceof HttpProblem) {
        if (failure.status === 401) {
          if (expireSession(credential, sessionRevision)) {
            setScene(null); setWorkspace(null); setWorkspaceError(null); setSuccess(null); setError("expired");
          }
          return { status: "expired" };
        }
        if (failure.status === 403) return { status: "forbidden" };
        if (failure.status === 404) return { status: "routeUnavailable" };
      }
      return { status: "unavailable" };
    };
    return {
      accountId,
      sessionRevision,
      async list(after) {
        try { return { status: "ready", directory: await list(credential, accountId, after) }; }
        catch (failure) { return failed(failure); }
      },
      async read(roleId, after) {
        try { return { status: "ready", access: await read(credential, accountId, roleId, after) }; }
        catch (failure) { return failed(failure); }
      }
    };
  }, [active, credential, expireSession, repository, scene, sessionRevision, tenantId]);

  const policyRead = useMemo<AccountPolicyReadClient | null>(() => {
    if (!active || !credential || !scene || scene.accountId !== tenantId || !scene.canViewPolicies || !repository.readPolicy || repository.workspace) return null;
    const accountId = scene.accountId;
    const readFailure = (failure: unknown): AccountPolicyReadFailure => {
      if (failure instanceof HttpProblem) {
        if (failure.status === 401) {
          if (expireSession(credential, sessionRevision)) {
            setScene(null); setWorkspace(null); setWorkspaceError(null); setSuccess(null); setError("expired");
          }
          return { status: "expired" };
        }
        if (failure.status === 403) return { status: "forbidden" };
        if (failure.status === 404) return { status: "routeUnavailable" };
      }
      return { status: "unavailable" };
    };
    return {
      accountId, sessionRevision,
      async read(policyId) {
        try {
          const detail = await repository.readPolicy!(credential, accountId, policyId);
          if (detail.policy.id !== policyId || detail.policy.scope !== "TENANT" ||
              detail.policy.accountId !== null && detail.policy.accountId !== accountId ||
              detail.version.policyId !== policyId || detail.version.versionId !== detail.policy.defaultVersionId) throw new Error("INVALID_IAM_RESPONSE");
          return { status: "ready", detail };
        } catch (failure) { return readFailure(failure); }
      },
      listVersions: repository.listPolicyVersions ? async (policyId) => {
        try {
          const directory = await repository.listPolicyVersions!(credential, accountId, policyId);
          if (directory.policy.id !== policyId || directory.policy.management !== "CUSTOMER" ||
              directory.policy.accountId !== accountId || directory.policy.scope !== "TENANT" ||
              directory.policy.status !== "ACTIVE" || !directory.items.some((item) => item.versionId === directory.policy.defaultVersionId)) {
            throw new Error("INVALID_IAM_RESPONSE");
          }
          return { status: "ready", directory };
        } catch (failure) { return readFailure(failure); }
      } : undefined,
      readVersion: repository.readPolicyVersion ? async (policyId, versionId) => {
        try {
          const detail = await repository.readPolicyVersion!(credential, accountId, policyId, versionId);
          if (detail.policy.id !== policyId || detail.policy.management !== "CUSTOMER" ||
              detail.policy.accountId !== accountId || detail.policy.scope !== "TENANT" ||
              detail.policy.status !== "ACTIVE" || detail.version.policyId !== policyId || detail.version.versionId !== versionId) {
            throw new Error("INVALID_IAM_RESPONSE");
          }
          return { status: "ready", detail };
        } catch (failure) { return readFailure(failure); }
      } : undefined
    };
  }, [active, credential, expireSession, repository, scene, sessionRevision, tenantId]);

  const policyCreate = useMemo<PolicyCreateClient | null>(() => {
    if (!active || !credential || !scene || scene.accountId !== tenantId || repository.workspace || !repository.createPolicy) return null;
    const accountId = scene.accountId;
    const expire = () => {
      if (expireSession(credential, sessionRevision)) {
        setScene(null); setWorkspace(null); setWorkspaceError(null); setSuccess(null); setError("expired");
      }
    };
    const attempt = async (intent: PolicyCreateIntent, retrying: boolean): Promise<PolicyCreateResult> => {
      try {
        const detail = await repository.createPolicy!(credential, accountId, {
          displayName: intent.displayName, document: JSON.parse(intent.documentJSON) as AccountPolicyDocument, requestId: intent.requestId
        });
        if (!rememberPolicyCreate(intent.requestId, null)) return { status: "blocked" };
        setScene((current) => current?.accountId === accountId ? { ...current,
          policies: current.policies.some((policy) => policy.id === detail.policy.id) ? current.policies : [...current.policies,
            { ...detail.policy, owner: "tenant" as const, scopeKind: "tenant" as const, available: true }]
        } : current);
        return { status: "applied", detail };
      } catch (failure) {
        if (policyCreateRef.current?.session !== viewSession || policyCreateRef.current.intent.requestId !== intent.requestId) return { status: "blocked" };
        if (!retrying && failure instanceof HttpProblem && [400, 401, 403, 404, 409, 413, 415, 422].includes(failure.status)) {
          rememberPolicyCreate(intent.requestId, null);
          if (failure.status === 401) expire();
          return { status: "rejected", reason: failure.status === 401 ? "expired" : failure.status === 403 ? "forbidden" :
            failure.status === 404 ? "routeUnavailable" : failure.status === 409 ? "conflict" : "invalid" };
        }
        rememberPolicyCreate(intent.requestId, { ...intent, phase: "unknown" });
        if (failure instanceof HttpProblem && failure.status === 401) expire();
        return { status: "unknown" };
      }
    };
    return {
      pending: policyCreateIntent,
      begin(input) {
        if (!input.displayName.trim() || input.document.scope !== "TENANT") return Promise.resolve({ status: "blocked" });
        const intent: PolicyCreateIntent = { accountId, displayName: input.displayName.trim(),
          documentJSON: JSON.stringify(input.document), requestId: requestToken("ui-policy-create-"), phase: "submitting" };
        if (!rememberPolicyCreate(null, intent)) return Promise.resolve({ status: "blocked" });
        return attempt(intent, false);
      },
      retry() {
        const current = policyCreateRef.current;
        if (current?.session !== viewSession || current.intent.phase !== "unknown") return Promise.resolve({ status: "blocked" });
        const intent = { ...current.intent, phase: "submitting" as const };
        if (!rememberPolicyCreate(intent.requestId, intent)) return Promise.resolve({ status: "blocked" });
        return attempt(intent, true);
      },
      acknowledge() {
        const current = policyCreateRef.current;
        return current?.session === viewSession && current.intent.phase === "unknown" && rememberPolicyCreate(current.intent.requestId, null);
      }
    };
  }, [active, credential, expireSession, policyCreateIntent, rememberPolicyCreate, repository, scene, sessionRevision, tenantId, viewSession]);

  const policyVersionMutation = useMemo<PolicyVersionMutationClient | null>(() => {
    if (!active || !credential || !scene || scene.accountId !== tenantId || repository.workspace ||
        !repository.setDefaultPolicyVersion || !repository.retirePolicyVersion || !repository.readPolicy || !repository.listPolicyVersions) return null;
    const accountId = scene.accountId;
    const owned = (intent: PolicyVersionMutationIntent) => {
      const stored = versionMutationRef.current;
      return stored?.session === viewSession && stored.intent.requestId === intent.requestId;
    };
    const expire = () => {
      if (expireSession(credential, sessionRevision)) {
        setScene(null); setWorkspace(null); setWorkspaceError(null); setSuccess(null); setError("expired");
      }
    };
    const attempt = async (intent: PolicyVersionMutationIntent, retrying: boolean): Promise<PolicyVersionMutationResult> => {
      try {
        const detail = intent.kind === "publish"
          ? await repository.createPolicyVersion!(credential, accountId, intent.policyId, {
            document: JSON.parse(intent.documentJSON) as AccountPolicyDocument,
            resourceVersion: intent.resourceVersion, expectedDefaultVersionId: intent.expectedDefaultVersionId, requestId: intent.requestId
          })
          : intent.kind === "set-default" ? await repository.setDefaultPolicyVersion!(credential, accountId, intent.policyId, {
            versionId: intent.versionId, resourceVersion: intent.resourceVersion, requestId: intent.requestId
          })
          : await repository.retirePolicyVersion!(credential, accountId, intent.policyId, intent.versionId, {
            resourceVersion: intent.resourceVersion, expectedDefaultVersionId: intent.expectedDefaultVersionId, requestId: intent.requestId
          });
        if (!rememberVersionMutation(intent.requestId, null)) return { status: "blocked" };
        setScene((current) => current?.accountId === accountId ? { ...current,
          policies: current.policies.map((policy) => policy.id === intent.policyId ? { ...policy, ...detail.policy } : policy)
        } : current);
        return { status: "applied", detail };
      } catch (failure) {
        if (!owned(intent)) return { status: "blocked" };
        if (!retrying && failure instanceof HttpProblem && [400, 401, 403, 404, 409, 413, 415, 422].includes(failure.status)) {
          rememberVersionMutation(intent.requestId, null);
          if (failure.status === 401) expire();
          return { status: "rejected", reason: failure.status === 401 ? "expired" : failure.status === 403 ? "forbidden" : failure.status === 404 ? "notFound" : failure.status === 409 ? "conflict" : "invalid" };
        }
        rememberVersionMutation(intent.requestId, { ...intent, phase: "unknown", observation: null, observationError: null });
        if (failure instanceof HttpProblem && failure.status === 401) expire();
        return { status: "unknown" };
      }
    };
    return {
      pending: versionMutationIntent,
      canPublish: Boolean(repository.createPolicyVersion),
      begin(input) {
        if (input.kind === "publish" && !repository.createPolicyVersion ||
            input.kind === "retire" && input.versionId === input.expectedDefaultVersionId ||
            input.kind === "set-default" && input.versionId === input.expectedDefaultVersionId ||
            !scene.policies.some((policy) => policy.id === input.policyId && policy.management === "CUSTOMER" && policy.accountId === accountId && policy.scope === "TENANT" && policy.status === "ACTIVE")) {
          return Promise.resolve({ status: "blocked" });
        }
        const subject = input.kind === "publish" ? { kind: "publish" as const, documentJSON: JSON.stringify(input.document) } :
          { kind: input.kind, versionId: input.versionId };
        const intent: PolicyVersionMutationIntent = { ...subject, policyId: input.policyId,
          expectedDefaultVersionId: input.expectedDefaultVersionId, resourceVersion: input.resourceVersion,
          accountId, requestId: requestToken("ui-policy-version-"),
          phase: "submitting", observation: null, observationError: null };
        if (!rememberVersionMutation(null, intent)) return Promise.resolve({ status: "blocked" });
        return attempt(intent, false);
      },
      retry() {
        const current = versionMutationRef.current;
        if (current?.session !== viewSession || current.intent.phase !== "unknown") return Promise.resolve({ status: "blocked" });
        const intent = { ...current.intent, phase: "submitting" as const, observation: null, observationError: null };
        if (!rememberVersionMutation(intent.requestId, intent)) return Promise.resolve({ status: "blocked" });
        return attempt(intent, true);
      },
      async observe() {
        const current = versionMutationRef.current;
        if (current?.session !== viewSession || current.intent.phase !== "unknown") return false;
        const intent = { ...current.intent, phase: "observing" as const, observation: null, observationError: null };
        if (!rememberVersionMutation(intent.requestId, intent)) return false;
        try {
          const detail = await repository.readPolicy!(credential, accountId, intent.policyId);
          const directory = await repository.listPolicyVersions!(credential, accountId, intent.policyId);
          if (detail.policy.id !== intent.policyId || directory.policy.id !== intent.policyId ||
              detail.policy.accountId !== accountId || directory.policy.accountId !== accountId ||
              detail.policy.management !== "CUSTOMER" || directory.policy.management !== "CUSTOMER" ||
              detail.policy.scope !== "TENANT" || directory.policy.scope !== "TENANT" ||
              detail.policy.status !== "ACTIVE" || directory.policy.status !== "ACTIVE" ||
              detail.policy.resourceVersion !== directory.policy.resourceVersion ||
              detail.policy.defaultVersionId !== directory.policy.defaultVersionId ||
              detail.version.versionId !== detail.policy.defaultVersionId ||
              !directory.items.some((item) => item.versionId === directory.policy.defaultVersionId)) throw new Error("INVALID_IAM_RESPONSE");
          return rememberVersionMutation(intent.requestId, { ...intent, phase: "unknown", observation: {
            resourceVersion: detail.policy.resourceVersion, defaultVersionId: detail.policy.defaultVersionId,
            versionIds: directory.items.map((item) => item.versionId)
          }, observationError: null });
        } catch (failure) {
          const observationError = failure instanceof HttpProblem && failure.status === 403 ? "forbidden" :
            failure instanceof HttpProblem && failure.status === 401 ? "expired" : "unavailable";
          rememberVersionMutation(intent.requestId, { ...intent, phase: "unknown", observation: null, observationError });
          if (observationError === "expired") expire();
          return false;
        }
      },
      acknowledge() {
        const current = versionMutationRef.current;
        if (current?.session !== viewSession || current.intent.phase !== "unknown" || !current.intent.observation) return false;
        return rememberVersionMutation(current.intent.requestId, null);
      }
    };
  }, [active, credential, expireSession, rememberVersionMutation, repository, scene, sessionRevision, tenantId, versionMutationIntent, viewSession]);

  const accountSecuritySettings = useMemo<AccountSecuritySettingsClient | null>(() => {
    const reader = repository.accountSecuritySettings;
    if (!active || !credential || !scene || scene.accountId !== tenantId || !principalId || !sessionId || !reader) return null;
    const accountId = scene.accountId;
    const updater = reader.update;
    const mutationIntent = securitySettingsIntent?.accountId === accountId && securitySettingsIntent.actorId === principalId
      ? securitySettingsIntent : null;
    const knownStartRejection = (failure: unknown) => failure instanceof HttpProblem && [400, 401, 403, 409, 413, 415, 422, 429].includes(failure.status);
    const expireCurrent = () => {
      if (expireSession(credential, sessionRevision)) {
        setScene(null); setWorkspace(null); setWorkspaceError(null); setSuccess(null); setError("expired");
      }
    };
    const requireMutation = () => {
      const current = securitySettingsIntentRef.current;
      if (currentViewSession.current !== viewSession || !current || current.accountId !== accountId || current.actorId !== principalId) {
        throw new Error("INVALID_IAM_STATE");
      }
      return current;
    };
    const replaceMutation = (current: AccountSecuritySettingsMutationIntent, next: AccountSecuritySettingsMutationIntent) => {
      if (!rememberSecuritySettingsIntent(current.requestId, next)) throw new Error("STALE_IAM_SESSION");
    };
    const validateStepUp = (value: SecurityStepUp, current: AccountSecuritySettingsMutationIntent) => {
      if (!validSecurityStepUp(value, current.requestId, current.expectedFactorRevision, current.settings)) {
        throw new Error("INVALID_IAM_RESPONSE");
      }
      return value;
    };
    const startStepUp = async (current: AccountSecuritySettingsMutationIntent) => {
      if (!updater || current.state !== "STEP_UP_UNKNOWN") throw new Error("INVALID_IAM_STATE");
      const stepUp = validateStepUp(await updater.startStepUp(credential, {
        requestId: current.requestId,
        expectedFactorRevision: current.expectedFactorRevision,
        intent: current.settings
      }), current);
      replaceMutation(current, { ...current, state: "PENDING", stepUp });
      return stepUp;
    };
    return {
      accountId, principalId, sessionId, sessionRevision,
      update: updater ? {
        intent: mutationIntent,
        async begin(current, accessKeyNetwork, expectedFactorRevision) {
          if (securitySettingsIntentRef.current || currentViewSession.current !== viewSession || current.accountId !== accountId ||
              !Number.isSafeInteger(expectedFactorRevision) || expectedFactorRevision < 1 ||
              !accessKeyNetworkRestrictionsValid(accessKeyNetwork) ||
              accessKeyNetworkRestrictionsEqual(current.accessKeyNetwork, accessKeyNetwork)) throw new Error("INVALID_IAM_STATE");
          const settings: SecuritySettingsUpdateIntent = {
            expectedResourceVersion: current.resourceVersion,
            mfa: { ...current.mfa },
            password: { ...current.password },
            session: { ...current.session },
            accessKeyNetwork: { allowedSourceCidrs: [...accessKeyNetwork.allowedSourceCidrs] }
          };
          const pending: AccountSecuritySettingsMutationIntent = {
            accountId,
            actorId: principalId,
            requestId: requestToken("ui-account-security-settings-"),
            expectedFactorRevision,
            state: "STEP_UP_UNKNOWN",
            settings,
            stepUp: null
          };
          if (!rememberSecuritySettingsIntent(null, pending)) throw new Error("STALE_IAM_SESSION");
          securitySettingsMutationPending.current = pending.requestId;
          try { return await startStepUp(pending); }
          catch (failure) {
            const stored = securitySettingsIntentRef.current as AccountSecuritySettingsMutationIntent | null;
            if (knownStartRejection(failure) && stored?.requestId === pending.requestId) {
              rememberSecuritySettingsIntent(pending.requestId, null);
              if (failure instanceof HttpProblem && failure.status === 401) expireCurrent();
            }
            throw failure;
          } finally {
            if (securitySettingsMutationPending.current === pending.requestId) securitySettingsMutationPending.current = null;
          }
        },
        async retryStepUp() {
          const current = requireMutation();
          if (securitySettingsMutationPending.current) throw new Error("INVALID_IAM_STATE");
          securitySettingsMutationPending.current = current.requestId;
          try { return await startStepUp(current); }
          catch (failure) {
            if (knownStartRejection(failure) && securitySettingsIntentRef.current?.requestId === current.requestId) {
              rememberSecuritySettingsIntent(current.requestId, null);
              if (failure instanceof HttpProblem && failure.status === 401) expireCurrent();
            }
            throw failure;
          } finally {
            if (securitySettingsMutationPending.current === current.requestId) securitySettingsMutationPending.current = null;
          }
        },
        async inspectStepUp() {
          const current = requireMutation();
          if (securitySettingsMutationPending.current || current.state === "COMPLETED") throw new Error("INVALID_IAM_STATE");
          securitySettingsMutationPending.current = current.requestId;
          try {
            const stepUp = validateStepUp(await updater.stepUpByRequest(
              credential, current.requestId, current.expectedFactorRevision, current.settings
            ), current);
            const state: AccountSecuritySettingsMutationState = stepUp.state === "PENDING" ? "PENDING"
              : stepUp.state === "PROVED" ? "PROVED" : stepUp.state === "CONSUMED" ? "APPLY_UNKNOWN" : "EXPIRED";
            replaceMutation(current, { ...current, state, stepUp });
            return stepUp;
          } catch (failure) {
            if (failure instanceof HttpProblem && failure.status === 401) expireCurrent();
            throw failure;
          } finally {
            if (securitySettingsMutationPending.current === current.requestId) securitySettingsMutationPending.current = null;
          }
        },
        async verifyStepUp(command) {
          const current = requireMutation();
          if (securitySettingsMutationPending.current || current.state !== "PENDING" || !current.stepUp) throw new Error("INVALID_IAM_STATE");
          replaceMutation(current, { ...current, state: "VERIFICATION_UNKNOWN" });
          securitySettingsMutationPending.current = current.requestId;
          try {
            // Password/TOTP rejection and an invalid bearer intentionally share
            // 401. A verification request alone cannot expire the login Session.
            const stepUp = validateStepUp(await updater.verifyStepUp(
              credential, current.stepUp.id, current.requestId, current.expectedFactorRevision, current.settings, command
            ), current);
            replaceMutation({ ...current, state: "VERIFICATION_UNKNOWN" }, {
              ...current, state: stepUp.state === "PROVED" ? "PROVED" : "EXPIRED", stepUp
            });
            return stepUp;
          } catch (failure) {
            if (failure instanceof HttpProblem && [400, 401, 413, 415, 422, 429].includes(failure.status) &&
                securitySettingsIntentRef.current?.requestId === current.requestId) {
              replaceMutation({ ...current, state: "VERIFICATION_UNKNOWN" }, current);
            }
            throw failure;
          } finally {
            if (securitySettingsMutationPending.current === current.requestId) securitySettingsMutationPending.current = null;
          }
        },
        async apply() {
          const current = requireMutation();
          if (securitySettingsMutationPending.current || current.state !== "PROVED" || !current.stepUp) throw new Error("INVALID_IAM_STATE");
          const unknown = { ...current, state: "APPLY_UNKNOWN" as const };
          replaceMutation(current, unknown);
          securitySettingsMutationPending.current = current.requestId;
          try {
            const result = await updater.apply(credential, accountId, {
              requestId: current.requestId,
              stepUpId: current.stepUp.id,
              intent: current.settings
            });
            const completed = { ...unknown, state: "COMPLETED" as const };
            replaceMutation(unknown, completed);
            expireCurrent();
            return result.change;
          } catch (failure) {
            // Once PUT was dispatched, every failure is outcome-unknown. Keep
            // the original request and frozen full intent for authoritative lookup.
            if (failure instanceof HttpProblem && failure.status === 401) expireCurrent();
            throw failure;
          } finally {
            if (securitySettingsMutationPending.current === current.requestId) securitySettingsMutationPending.current = null;
          }
        },
        async inspectChange() {
          const current = requireMutation();
          if (securitySettingsMutationPending.current || current.state !== "APPLY_UNKNOWN") throw new Error("INVALID_IAM_STATE");
          securitySettingsMutationPending.current = current.requestId;
          try {
            const change = await updater.changeByRequest(credential, accountId, current.requestId, current.settings);
            replaceMutation(current, { ...current, state: "COMPLETED" });
            return change;
          } catch (failure) {
            if (failure instanceof HttpProblem && failure.status === 401) expireCurrent();
            throw failure;
          } finally {
            if (securitySettingsMutationPending.current === current.requestId) securitySettingsMutationPending.current = null;
          }
        },
        clear(requestId) {
          const current = securitySettingsIntentRef.current;
          if (!current || current.requestId !== requestId || current.accountId !== accountId || current.actorId !== principalId ||
              current.state !== "COMPLETED" && current.state !== "EXPIRED" || securitySettingsMutationPending.current) return false;
          return rememberSecuritySettingsIntent(requestId, null);
        }
      } : undefined,
      async load() {
        try {
          const settings = await reader.read(credential, accountId);
          if (settings.accountId !== accountId) throw new Error("INVALID_IAM_TENANT");
          return { status: "ready", settings };
        } catch (failure) {
          if (failure instanceof HttpProblem) {
            if (failure.status === 401) {
              if (expireSession(credential, sessionRevision)) {
                setScene(null); setWorkspace(null); setWorkspaceError(null); setSuccess(null); setError("expired");
              }
              return { status: "expired" };
            }
            if (failure.status === 403) return { status: "forbidden" };
            if (failure.status === 404) return { status: "routeUnavailable" };
          }
          return { status: "unavailable" };
        }
      }
    };
  }, [active, credential, expireSession, principalId, rememberSecuritySettingsIntent, repository, scene, securitySettingsIntent, sessionId, sessionRevision, tenantId, viewSession]);

  const accessAnalysis = useMemo<AccessAnalysisClient | null>(() => {
    const analysisRepository = repository.accessAnalysis;
    if (!active || !credential || !scene || scene.accountId !== tenantId || !analysisRepository || repository.workspace) return null;
    const accountId = scene.accountId;
    const scoped = async <T,>(request: Promise<T>): Promise<T> => {
      try { return await request; }
      catch (failure) {
        if (failure instanceof HttpProblem && failure.status === 401 && expireSession(credential, sessionRevision)) {
          setScene(null); setWorkspace(null); setWorkspaceError(null); setSuccess(null); setError("expired");
        }
        throw failure;
      }
    };
    return {
      accountId,
      sessionRevision,
      listAnalyzers: (after) => scoped(analysisRepository.listAnalyzers(credential, accountId, after)),
      readAnalyzer: (analyzerId) => scoped(analysisRepository.readAnalyzer(credential, accountId, analyzerId)),
      createAnalyzer: (command) => scoped(analysisRepository.createAnalyzer(credential, accountId, command)),
      updateAnalyzer: (analyzerId, command) => scoped(analysisRepository.updateAnalyzer(credential, accountId, analyzerId, command)),
      setDisposition: (analyzerId, command) => scoped(analysisRepository.setDisposition(credential, accountId, analyzerId, command)),
      listFindings: (analyzerId, status, after) => scoped(analysisRepository.listFindings(credential, accountId, analyzerId, status, after)),
      readFinding: (analyzerId, findingId) => scoped(analysisRepository.readFinding(credential, accountId, analyzerId, findingId)),
      archiveFinding: (analyzerId, findingId, command) => scoped(analysisRepository.archiveFinding(credential, accountId, analyzerId, findingId, command)),
      unarchiveFinding: (analyzerId, findingId, command) => scoped(analysisRepository.unarchiveFinding(credential, accountId, analyzerId, findingId, command))
    };
  }, [active, credential, expireSession, repository, scene, sessionRevision, tenantId]);

  const securityReports = useMemo<SecurityReportClient | null>(() => {
    const reportRepository = repository.securityReports;
    if (!active || !credential || !scene || scene.accountId !== tenantId || !reportRepository || repository.workspace) return null;
    const accountId = scene.accountId;
    const scoped = async <T,>(request: Promise<T>): Promise<T> => {
      try { return await request; }
      catch (failure) {
        if (failure instanceof HttpProblem && failure.status === 401 && expireSession(credential, sessionRevision)) {
          setScene(null); setWorkspace(null); setWorkspaceError(null); setSuccess(null); setError("expired");
        }
        throw failure;
      }
    };
    return {
      accountId,
      sessionRevision,
      create: (command) => scoped(reportRepository.create(credential, accountId, command)),
      read: (reportId) => scoped(reportRepository.read(credential, accountId, reportId)),
      download: (reportId) => scoped(reportRepository.download(credential, accountId, reportId))
    };
  }, [active, credential, expireSession, repository, scene, sessionRevision, tenantId]);

  const accessKeys = useMemo<AccessKeyClient | null>(() => {
    const keyRepository = repository.accessKeys;
    if (!active || !credential || !principalId || !scene || scene.accountId !== tenantId || !keyRepository || !scene.canListUsers) return null;
    const accountId = scene.accountId;
    const target = (userId: string) => {
      if (!userId || userId === scene.accountOwner.id || !scene.users.some((user) => user.id === userId)) throw new Error("INVALID_IAM_USER_TARGET");
      return userId;
    };
    const scoped = async <T,>(request: Promise<T>): Promise<T> => {
      try { return await request; }
      catch (failure) {
        if (failure instanceof HttpProblem && failure.status === 401 && expireSession(credential)) {
          setScene(null); setWorkspace(null); setWorkspaceError(null); setSuccess(null); setError("expired");
        }
        throw failure;
      }
    };
    return {
      accountId,
      list: (userId) => scoped(keyRepository.list(credential, accountId, target(userId))),
      read: (userId, accessKeyId) => scoped(keyRepository.read(credential, accountId, target(userId), accessKeyId)),
      create: async (userId, command) => {
        target(userId);
        if (!Number.isSafeInteger(command.userResourceVersion) || command.userResourceVersion < 1 ||
          !/^ui-access-key-create-[0-9a-f]{32}$/.test(command.requestId)) throw new HttpProblem(400, "INVALID_ACCESS_KEY_CREATE_INTENT");
        if (accessKeyCreateSubmitting.current?.session === viewSession) throw new HttpProblem(409, "ACCESS_KEY_CREATE_IN_FLIGHT");
        const pending = accessKeyCreateRef.current?.session === viewSession ? accessKeyCreateRef.current.intent : null;
        if (pending && (pending.phase !== "unknown" || pending.userId !== userId || pending.userResourceVersion !== command.userResourceVersion ||
          !accessKeyNetworkRestrictionsEqual(pending.networkRestrictions, command.networkRestrictions) || pending.requestId !== command.requestId)) {
          throw new HttpProblem(409, "ACCESS_KEY_CREATE_INTENT_LOCKED");
        }
        const intent: AccessKeyCreateIntent = pending ?? {
          accountId, actorId: principalId, userId, userResourceVersion: command.userResourceVersion,
          networkRestrictions: command.networkRestrictions,
          requestId: command.requestId, phase: "unknown"
        };
        if (!pending) {
          const stored = { session: viewSession, intent };
          accessKeyCreateRef.current = stored;
          setStoredAccessKeyCreate(stored);
          storeAccessKeyCreateIntent(intent);
        }
        const submission = { session: viewSession, requestId: command.requestId };
        accessKeyCreateSubmitting.current = submission;
        try {
          const result = await scoped(keyRepository.create(credential, accountId, userId, command));
          if (currentViewSession.current === viewSession && accessKeyCreateRef.current?.intent.requestId === intent.requestId) {
            const recovered: AccessKeyCreateIntent = { ...intent, phase: "recovered", keyId: result.key.id };
            const stored = { session: viewSession, intent: recovered };
            accessKeyCreateRef.current = stored;
            setStoredAccessKeyCreate(stored);
            storeAccessKeyCreateIntent(recovered);
            accessKeyIssuedRef.current = result.outcome === "APPLIED"
              ? { session: viewSession, requestId: intent.requestId, accessKeyId: result.key.id } : null;
          }
          return result;
        } catch (failure) {
          if (!pending && failure instanceof HttpProblem && [400, 401, 403, 404, 409, 413, 415, 422].includes(failure.status) &&
            currentViewSession.current === viewSession && accessKeyCreateRef.current?.intent.requestId === intent.requestId) {
            clearAccessKeyCreateIntent(intent);
            accessKeyCreateRef.current = null;
            setStoredAccessKeyCreate(null);
          }
          throw failure;
        } finally { if (accessKeyCreateSubmitting.current === submission) accessKeyCreateSubmitting.current = null; }
      },
      acknowledgeIssued: (requestId, accessKeyId) => {
        const issued = accessKeyIssuedRef.current;
        const pending = accessKeyCreateRef.current?.session === viewSession ? accessKeyCreateRef.current.intent : null;
        if (currentViewSession.current !== viewSession || issued?.session !== viewSession || issued.requestId !== requestId ||
          issued.accessKeyId !== accessKeyId || pending?.phase !== "recovered" || pending.requestId !== requestId || pending.keyId !== accessKeyId) return false;
        clearAccessKeyCreateIntent(pending);
        accessKeyIssuedRef.current = null;
        accessKeyCreateRef.current = null;
        setStoredAccessKeyCreate(null);
        return true;
      },
      setStatus: (userId, accessKeyId, command) => scoped(keyRepository.setStatus(credential, accountId, target(userId), accessKeyId, command)),
      setNetworkRestrictions: (userId, accessKeyId, command) => scoped(keyRepository.setNetworkRestrictions(credential, accountId, target(userId), accessKeyId, command)),
      delete: async (userId, accessKeyId, command) => {
        const result = await scoped(keyRepository.delete(credential, accountId, target(userId), accessKeyId, command));
        const pending = accessKeyCreateRef.current?.session === viewSession ? accessKeyCreateRef.current.intent : null;
        if (pending?.phase === "recovered" && pending.userId === userId && pending.keyId === accessKeyId && currentViewSession.current === viewSession) {
          clearAccessKeyCreateIntent(pending);
          accessKeyIssuedRef.current = null;
          accessKeyCreateRef.current = null;
          setStoredAccessKeyCreate(null);
        }
        return result;
      }
    };
  }, [active, credential, expireSession, principalId, repository, scene, tenantId, viewSession]);

  const roles = useMemo<RoleAccessClient | null>(() => {
    const roleRepository = repository.roles;
    if (!active || !credential || !scene || scene.accountId !== tenantId || !roleRepository || (!scene.canListRoles && !scene.canCreateRoles)) return null;
    const accountId = scene.accountId;
    const scoped = async <T,>(request: Promise<T>): Promise<T> => {
      try { return await request; }
      catch (failure) {
        if (failure instanceof HttpProblem && failure.status === 401 && expireSession(credential, sessionRevision)) {
          setScene(null); setWorkspace(null); setWorkspaceError(null); setSuccess(null); setError("expired");
        }
        throw failure;
      }
    };
    return {
      accountId,
      actorPrincipalId: scene.currentUserId,
      sessionRevision,
      canCreate: scene.canCreateRoles,
      createRestrictionReason: scene.createRolesRestrictionReason,
      list: (after) => scoped(roleRepository.list(credential, accountId, after)),
      read: (roleId) => scoped(roleRepository.read(credential, accountId, roleId)),
      readPermissionBoundary: (roleId) => scoped(roleRepository.readPermissionBoundary(credential, accountId, roleId)),
      listTenantPolicies: () => scoped((async () => {
        if (!scene.tenantPoliciesAvailable) return { items: [], available: false };
        const directory = await readWhenAuthorized(() => repository.listPolicies(credential, false));
        if (!directory) return { items: [], available: false };
        if (directory.accountId !== accountId || directory.scope !== "TENANT" || directory.installationId !== null) throw new Error("INVALID_IAM_TENANT");
        return { items: directory.items, available: true };
      })()),
      setPermissionBoundary: (roleId, command) => protectedMutation(() => scoped(roleRepository.setPermissionBoundary(credential, accountId, roleId, command))),
      removePermissionBoundary: (roleId, command) => protectedMutation(() => scoped(roleRepository.removePermissionBoundary(credential, accountId, roleId, command))),
      listTrustVersions: (roleId, after) => scoped(roleRepository.listTrustVersions(credential, accountId, roleId, after)),
      create: (command) => protectedMutation(() => scoped(roleRepository.create(credential, accountId, command))),
      update: (roleId, command) => protectedMutation(() => scoped(roleRepository.update(credential, accountId, roleId, command))),
      setStatus: (roleId, command) => protectedMutation(() => scoped(roleRepository.setStatus(credential, accountId, roleId, command))),
      setTrustPolicy: (roleId, command) => protectedMutation(() => scoped(roleRepository.setTrustPolicy(credential, accountId, roleId, command))),
      delete: (roleId, command) => protectedMutation(() => scoped(roleRepository.delete(credential, accountId, roleId, command))),
      createPolicyAttachment: (roleId, command) => protectedMutation(() => scoped(roleRepository.createPolicyAttachment(credential, accountId, roleId, command))),
      revokePolicyAttachment: (attachmentId, command) => protectedMutation(() => scoped(repository.revokePolicyAttachment(credential, attachmentId, command))),
      inspectPolicyAttachmentChange,
      listSessions: (roleId, filter, after) => scoped(roleRepository.listSessions(credential, accountId, roleId, filter, after)),
      readSession: (roleId, sessionId) => scoped(roleRepository.readSession(credential, accountId, roleId, sessionId)),
      revokeSession: (roleId, sessionId, requestId) => scoped(roleRepository.revokeSession(credential, accountId, roleId, sessionId, requestId))
    };
  }, [active, credential, expireSession, inspectPolicyAttachmentChange, protectedMutation, repository, scene, sessionRevision, tenantId]);

  const loadUsersPage = useCallback(async (after: string) => {
    if (!active || !credential || !scene || loading || mutationPending.current) return;
    const source = scene;
    const request = ++directoryRequest.current.users;
    setLoading(true); setError(null); setSuccess(null);
    try {
      const users = await repository.listUsers(credential, after || undefined);
      if (request !== directoryRequest.current.users) return;
      if (users.items.some((entry) => entry.user.accountId !== tenantId || entry.user.id === source.accountOwner.id)) throw new Error("INVALID_IAM_TENANT");
      const items = users.items.map((entry) => buildAccountUserScene({ id: source.accountId, loginAlias: source.loginAlias }, source.policies, entry));
      setScene((current) => current?.accountId === source.accountId ? {
        ...current,
        users: items,
        nextUserPage: users.nextAfter,
        directoryComplete: !after && !users.nextAfter
      } : current);
    } catch (failure) {
      if (request === directoryRequest.current.users) setError(accountError(failure));
    } finally {
      if (request === directoryRequest.current.users) setLoading(false);
    }
  }, [active, credential, loading, repository, scene, tenantId]);

  const loadAccountsPage = useCallback(async (after: string) => {
    if (!active || !credential || !scene || loading || mutationPending.current) return;
    const source = scene;
    const request = ++directoryRequest.current.accounts;
    setLoading(true); setError(null); setSuccess(null);
    try {
      const accounts = await repository.listAccounts(credential, after || undefined);
      if (request !== directoryRequest.current.accounts) return;
      setScene((current) => current?.accountId === source.accountId ? {
        ...current,
        accounts: accounts.items.map(buildAccountTenantScene),
        nextAccountPage: accounts.nextAfter
      } : current);
    } catch (failure) {
      if (request === directoryRequest.current.accounts) setError(accountError(failure));
    } finally {
      if (request === directoryRequest.current.accounts) setLoading(false);
    }
  }, [active, credential, loading, repository, scene]);

  const beginUserPolicyAttachment = useCallback((user: AccountUserScene, policyId: string): boolean => {
    if (!active || !credential || !scene || loading || mutationPending.current || !tenantId || !principalId) return false;
    const policy = scene.policies.find((item) => item.id === policyId);
    if (user.accountId !== tenantId || user.id === scene.accountOwner.id || !policy || policy.status !== "ACTIVE" ||
      !(policy.scope === "INSTALLATION" ? user.canAttachPlatformPolicy : user.canAttachTenantPolicy)) return false;
    return rememberUserPolicyChange(null, {
      kind: "attach", accountId: tenantId, actorId: principalId, userId: user.id, userQualifiedName: user.qualifiedName,
      policyId, policyDisplayName: policy.displayName, policyScope: policy.scope,
      defaultVersionId: policy.defaultVersionId, policyResourceVersion: policy.resourceVersion,
      requestId: requestToken("ui-user-attachment-"), phase: "review", lookupStatus: "unchecked", completion: null, error: null
    });
  }, [active, credential, loading, principalId, rememberUserPolicyChange, scene, tenantId]);

  const beginUserPolicyRevocation = useCallback((user: AccountUserScene, attachmentId: string): boolean => {
    if (!active || !credential || !scene || loading || mutationPending.current || !tenantId || !principalId || user.accountId !== tenantId) return false;
    const attachment = user.attachments.find((item) => item.id === attachmentId);
    if (!attachment || !attachment.canRevoke || attachment.accountId !== tenantId || attachment.target.id !== user.id) return false;
    return rememberUserPolicyChange(null, {
      kind: "revoke", accountId: tenantId, actorId: principalId, userId: user.id, userQualifiedName: user.qualifiedName,
      policyId: attachment.policyId, policyDisplayName: attachment.label, policyScope: attachment.scope,
      attachmentId: attachment.id, attachmentResourceVersion: attachment.resourceVersion,
      requestId: requestToken("ui-user-revocation-"), phase: "review", lookupStatus: "unchecked", completion: null, error: null
    });
  }, [active, credential, loading, principalId, rememberUserPolicyChange, scene, tenantId]);

  const submitUserPolicyChange = useCallback(async (requestId: string): Promise<boolean> => {
    const stored = userPolicyChangeRef.current;
    const intent = stored?.session === viewSession && stored.intent.requestId === requestId ? stored.intent : null;
    if (!active || !credential || !scene || !intent || intent.accountId !== tenantId || loading || mutationPending.current ||
      (intent.phase !== "review" && intent.phase !== "unknown")) return false;
    // First submission must still match the selected directory revision. UNKNOWN
    // recovery replays the frozen command even if a later directory read changed.
    if (intent.kind === "attach" && intent.phase === "review" && !scene.policies.some((policy) => policy.id === intent.policyId &&
      policy.status === "ACTIVE" && policy.resourceVersion === intent.policyResourceVersion)) {
      rememberUserPolicyChange(requestId, { ...intent, phase: "conflict", error: "conflict" });
      return false;
    }
    if (!rememberUserPolicyChange(requestId, { ...intent, phase: "submitting", completion: null, error: null })) return false;
    mutationPending.current = true;
    setBusy(true); setError(null); setSuccess(null);
    try {
      if (intent.kind === "attach") await repository.execute(credential, {
        kind: "create-policy-attachment", userId: intent.userId, policyId: intent.policyId,
        policyResourceVersion: intent.policyResourceVersion, requestId: intent.requestId
      });
      else await repository.revokePolicyAttachment(credential, intent.attachmentId, {
        resourceVersion: intent.attachmentResourceVersion, requestId: intent.requestId
      });
      if (currentViewSession.current !== viewSession) return false;
      rememberUserPolicyChange(requestId, null);
      setSuccess("completed"); setLoading(true); setRevision((current) => current + 1);
      return true;
    } catch (failure) {
      if (currentViewSession.current !== viewSession) return false;
      const reason = accountError(failure);
      rememberUserPolicyChange(requestId, {
        ...intent, phase: reason === "unavailable" ? "unknown" : reason === "conflict" ? "conflict" : "rejected",
        lookupStatus: reason === "unavailable" ? intent.lookupStatus : "unchecked", completion: null, error: reason
      });
      return false;
    } finally { mutationPending.current = false; setBusy(false); }
  }, [active, credential, loading, rememberUserPolicyChange, repository, scene, tenantId, viewSession]);

  const inspectUserPolicyChange = useCallback(async (requestId: string): Promise<boolean> => {
    const stored = userPolicyChangeRef.current;
    const intent = stored?.session === viewSession && stored.intent.requestId === requestId ? stored.intent : null;
    const read = repository.readPolicyAttachmentChange;
    if (!active || !credential || !scene || !intent || intent.phase !== "unknown" || intent.accountId !== tenantId ||
        intent.actorId !== principalId || loading || mutationPending.current) return false;
    if (!read) {
      rememberUserPolicyChange(requestId, { ...intent, lookupStatus: "unavailable", completion: null, error: "unavailable" });
      return false;
    }
    const expectation: PolicyAttachmentChangeExpectation = intent.kind === "attach" ? {
      operation: "CREATE", accountId: intent.accountId, actorPrincipalId: intent.actorId, requestId: intent.requestId,
      target: { kind: "USER", id: intent.userId }, policyId: intent.policyId, policyResourceVersion: intent.policyResourceVersion
    } : {
      operation: "REVOKE", accountId: intent.accountId, actorPrincipalId: intent.actorId, requestId: intent.requestId,
      attachmentId: intent.attachmentId, expectedResourceVersion: intent.attachmentResourceVersion
    };
    if (!rememberUserPolicyChange(requestId, { ...intent, phase: "checking", completion: null, error: null })) return false;
    mutationPending.current = true;
    setBusy(true); setError(null); setSuccess(null);
    try {
      const completion = await read(credential, expectation);
      if (currentViewSession.current !== viewSession) return false;
      rememberUserPolicyChange(requestId, { ...intent, phase: "confirmed", lookupStatus: "confirmed", completion, error: null });
      setLoading(true); setRevision((current) => current + 1);
      return true;
    } catch (failure) {
      if (currentViewSession.current !== viewSession) return false;
      const status = failure instanceof HttpProblem && failure.status === 404 ? "stillUnknown" :
        failure instanceof HttpProblem && failure.status === 403 ? "forbidden" :
          failure instanceof HttpProblem && failure.status === 401 ? "expired" : "unavailable";
      rememberUserPolicyChange(requestId, { ...intent, phase: "unknown", lookupStatus: status, completion: null,
        error: status === "forbidden" ? "forbidden" : status === "expired" ? "expired" : "unavailable" });
      if (status === "expired" && expireSession(credential, sessionRevision)) {
        setScene(null); setWorkspace(null); setWorkspaceError(null); setSuccess(null); setError("expired");
      }
      return false;
    } finally { mutationPending.current = false; setBusy(false); }
  }, [active, credential, expireSession, loading, principalId, rememberUserPolicyChange, repository, scene, sessionRevision, tenantId, viewSession]);

  const endUserPolicyChange = useCallback((requestId: string): boolean => {
    const stored = userPolicyChangeRef.current;
    const intent = stored?.session === viewSession && stored.intent.requestId === requestId ? stored.intent : null;
    if (!intent || intent.phase === "submitting" || intent.phase === "checking" || intent.phase === "unknown" ||
        !rememberUserPolicyChange(requestId, null)) return false;
    if (intent.phase !== "review") {
      directoryRequest.current.users += 1;
      directoryRequest.current.accounts += 1;
      setLoading(true);
      setRevision((current) => current + 1);
    }
    return true;
  }, [rememberUserPolicyChange, viewSession]);

  const value = useMemo<AccountAccess>(() => ({
    supportsUserBatch: Boolean(repository.executeUserBatch),
    async executeUserBatch(command) {
      if (!active || !credential || !scene || !workspace || !repository.executeUserBatch || loading || mutationPending.current) return false;
      if (workspace.personalMfa.reauthenticationRequired) { setWorkspaceError("reauthenticationRequired"); return false; }
      const targets = command.targets.map((target) => {
        const user = scene.users.find((entry) => entry.id === target.id);
        return {
          id: target.id,
          enabled: target.id === scene.accountOwner.id ? null : user?.enabled ?? null,
          canSetStatus: user?.canSetStatus ?? false,
          canAttachPolicy: user?.canAttachTenantPolicy ?? false,
          protected: user?.protected ?? true
        };
      });
      const unavailable = command.targets.some((target) => target.id !== scene.accountOwner.id && !scene.users.some((user) => user.id === target.id && user.resourceVersion === target.resourceVersion));
      if (unavailable || userBatchDisabledReason(command.action, { targets, rootId: scene.accountOwner.id, actorId: scene.currentUserId, canListUsers: scene.canListUsers, supported: true })) { setWorkspaceError("ineligibleUsers"); return false; }
      mutationPending.current = true;
      setBusy(true); setWorkspaceError(null); setSuccess(null);
      try {
        const result = await repository.executeUserBatch(credential, command);
        if (result.workspace.accountId !== tenantId || result.workspace.mode !== "preview") throw new Error("INVALID_IAM_TENANT");
        setWorkspace(result.workspace); setSuccess("completed");
        setLoading(true); setRevision((current) => current + 1);
        return true;
      } catch (failure) { setWorkspaceError(failure instanceof AccessWorkspaceError ? failure.code : accountError(failure)); return false; }
      finally { mutationPending.current = false; setBusy(false); }
    },
    policyDirectoryView,
    userDirectoryView,
    groups,
    permissionBoundaries,
    authorizationProfiles,
    serviceRoleTemplates,
    serviceLinkedRoles,
    policyRead,
    policyCreate,
    policyVersionMutation,
    accessAnalysis,
    securityReports,
    accessKeys,
    accessKeyCreateIntent: accessKeyCreateIntent?.accountId === tenantId ? accessKeyCreateIntent : null,
    roles,
    roleSessionRevokeIntent: roleSessionRevokeIntent?.accountId === tenantId ? roleSessionRevokeIntent : null,
    changeRoleSessionRevokeIntent,
    userPolicyChangeIntent: userPolicyChangeIntent?.accountId === tenantId ? userPolicyChangeIntent : null,
    beginUserPolicyAttachment, beginUserPolicyRevocation, submitUserPolicyChange, inspectUserPolicyChange, endUserPolicyChange,
    workspace, workspaceError,
    clearWorkspaceError, clearFeedback,
    async executeWorkspace(command, onError) {
      if (!active || !credential || !scene?.canListUsers || !repository.workspace || loading || mutationPending.current) return null;
      if (workspace?.personalMfa.reauthenticationRequired) { setWorkspaceError("reauthenticationRequired"); return null; }
      if ("principalId" in command && command.principalId === scene.accountOwner.id) { setWorkspaceError("forbidden"); return null; }
      mutationPending.current = true;
      setBusy(true); setWorkspaceError(null); setSuccess(null);
      try {
        const result = await repository.workspace.execute(credential, command);
        if (result.workspace.accountId !== tenantId || result.workspace.mode !== "preview") throw new Error("INVALID_IAM_TENANT");
        setWorkspace(result.workspace);
        if (command.kind === "create-subuser" || command.kind === "delete-user" || command.kind === "update-user" || command.kind === "import-enterprise-members") { setLoading(true); setRevision((current) => current + 1); }
        if (!(command.kind === "save-account-rule" && command.responseMode === "response-lost") &&
            command.kind !== "verify-personal-notification-address" &&
            command.kind !== "begin-personal-notification-replacement" &&
            command.kind !== "confirm-personal-notification-replacement" &&
            command.kind !== "inspect-personal-notification-replacement") {
          setSuccess("completed");
        }
        return { issuedKey: result.issuedKey, recoveryCodes: result.recoveryCodes };
      } catch (failure) {
        const code = failure instanceof AccessWorkspaceError ? failure.code : accountError(failure);
        if (command.kind === "save-account-rule" && code === "unavailable") {
          const unknownIntent: PendingAccountRuleChange = {
            requestId: command.requestId,
            baselineRuleVersion: command.expectedRuleVersion,
            baselineLoginProtection: command.expectedLoginProtection,
            requestedLoginProtection: command.loginProtection,
            status: "UNKNOWN" as const
          };
          try {
            const recovered = await repository.workspace.execute(credential, {
              kind: "remember-account-rule-change-unknown",
              requestId: command.requestId,
              expectedRuleVersion: command.expectedRuleVersion,
              expectedLoginProtection: command.expectedLoginProtection,
              loginProtection: command.loginProtection
            });
            if (recovered.workspace.accountId !== tenantId || recovered.workspace.mode !== "preview") throw new Error("INVALID_IAM_TENANT");
            unrecoverableAccountRule.current = null;
            setWorkspace(recovered.workspace);
          } catch {
            // The preview journal is the durable owner. Keep a provider-level lock
            // if that isolated journal is itself unavailable; never unlock on error.
            const unrecoverable = { ...unknownIntent, status: "UNRECOVERABLE" as const };
            unrecoverableAccountRule.current = { session: viewSession, intent: unrecoverable };
            setWorkspace((current) => current ? { ...current, pendingAccountRuleChange: unrecoverable } : current);
          }
        }
        setWorkspaceError(code);
        onError?.(code);
        return null;
      } finally { mutationPending.current = false; setBusy(false); }
    },
    accountSecuritySettings, scene, loading, busy, error, success,
    reload() { directoryRequest.current.users += 1; directoryRequest.current.accounts += 1; setLoading(true); setRevision((current) => current + 1); },
    usersPage(after) { void loadUsersPage(after); },
    accountsPage(after) { void loadAccountsPage(after); },
    loadUser,
    passwordResetUnknown,
    passwordResetLookup,
    async resetUserPassword(user, initialPassword) {
      if (!active || !credential || !tenantId || !principalId || loading || mutationPending.current) return "rejected";
      if (passwordResetUnknownRef.current?.session === viewSession) return "unknown";
      if (workspace?.personalMfa.reauthenticationRequired) { setWorkspaceError("reauthenticationRequired"); return "rejected"; }
      const command: Extract<AccountCommand, { kind: "reset-password" }> = {
        kind: "reset-password", userId: user.id, resourceVersion: user.resourceVersion,
        initialPassword, requestId: requestToken("ui-user-reset-")
      };
      if (!scene || verifiedIdentitySession.current !== viewSession || scene.accountId !== tenantId || scene.currentUserId !== principalId || !accountCommandAvailable(scene, command)) { setError("forbidden"); return "rejected"; }
      mutationPending.current = true;
      setBusy(true); setError(null); setSuccess(null);
      try {
        await repository.execute(credential, command);
        if (currentViewSession.current !== viewSession) return "rejected";
        setSuccess("completed");
        setLoading(true); setRevision((current) => current + 1);
        return "applied";
      } catch (failure) {
        if (currentViewSession.current !== viewSession) return "rejected";
        if (failure instanceof HttpProblem && [400, 401, 403, 409, 422].includes(failure.status)) {
          setError(accountError(failure));
          return "rejected";
        }
        const stored = { session: viewSession, intent: {
          accountId: tenantId, actorId: principalId, userId: user.id, userQualifiedName: user.qualifiedName,
          resourceVersion: user.resourceVersion, requestId: command.requestId
        } };
        passwordResetUnknownRef.current = stored;
        setStoredPasswordResetUnknown(stored);
        setStoredPasswordResetLookup(null);
        if (!repository.workspace) storePasswordResetUnknown(stored.intent);
        return "unknown";
      } finally { mutationPending.current = false; setBusy(false); }
    },
    async lookupUnknownPasswordReset(requestId) {
      const stored = passwordResetUnknownRef.current;
      if (!active || !credential || !tenantId || !principalId || loading || mutationPending.current ||
          stored?.session !== viewSession || stored.intent.requestId !== requestId ||
          stored.intent.accountId !== tenantId || stored.intent.actorId !== principalId ||
          verifiedIdentitySession.current !== viewSession) return;
      mutationPending.current = true;
      setBusy(true);
      try {
        const completion = await repository.readPasswordResetCompletion(credential, stored.intent);
        if (currentViewSession.current !== viewSession || passwordResetUnknownRef.current !== stored) return;
        setStoredPasswordResetLookup({ session: viewSession, result: { requestId, status: "confirmed", completion } });
      } catch (failure) {
        if (currentViewSession.current !== viewSession || passwordResetUnknownRef.current !== stored) return;
        const status = failure instanceof HttpProblem && failure.status === 404 ? "unresolved"
          : failure instanceof HttpProblem && [401, 403].includes(failure.status) ? "denied" : "unavailable";
        setStoredPasswordResetLookup({ session: viewSession, result: { requestId, status } });
      } finally { mutationPending.current = false; setBusy(false); }
    },
    acknowledgeUnknownPasswordReset(requestId) {
      const stored = passwordResetUnknownRef.current;
      if (stored?.session !== viewSession || stored.intent.requestId !== requestId || mutationPending.current ||
          passwordResetLookup?.requestId !== requestId || passwordResetLookup.status !== "confirmed") return false;
      if (!repository.workspace) clearPasswordResetUnknown(stored.intent);
      passwordResetUnknownRef.current = null;
      setStoredPasswordResetUnknown(null);
      setStoredPasswordResetLookup(null);
      return true;
    },
    async execute(command) {
      if (!active || !credential || loading || mutationPending.current) return false;
      if (workspace?.personalMfa.reauthenticationRequired) { setWorkspaceError("reauthenticationRequired"); return false; }
      if (!scene || !accountCommandAvailable(scene, command)) { setError("forbidden"); return false; }
      mutationPending.current = true;
      setBusy(true); setError(null); setSuccess(null);
      try {
        await repository.execute(credential, command);
        setSuccess("completed");
        setLoading(true); setRevision((current) => current + 1);
        return true;
      } catch (failure) { setError(accountError(failure)); return false; }
      finally { mutationPending.current = false; setBusy(false); }
    }
  }), [active, busy, credential, error, loading, repository, scene, success, tenantId, principalId, viewSession, workspace, workspaceError, clearWorkspaceError, clearFeedback, groups, permissionBoundaries, authorizationProfiles, serviceRoleTemplates, serviceLinkedRoles, policyRead, policyCreate, policyVersionMutation, accountSecuritySettings, accessAnalysis, securityReports, accessKeys, accessKeyCreateIntent, roles, roleSessionRevokeIntent, changeRoleSessionRevokeIntent, userPolicyChangeIntent, passwordResetUnknown, passwordResetLookup, beginUserPolicyAttachment, beginUserPolicyRevocation, submitUserPolicyChange, inspectUserPolicyChange, endUserPolicyChange, loadUser, loadUsersPage, loadAccountsPage, policyDirectoryView, userDirectoryView]);

  return <AccountCapabilitiesContext.Provider value={capabilities}>
    <AccountAccessContext.Provider value={value}>{children}</AccountAccessContext.Provider>
  </AccountCapabilitiesContext.Provider>;
}

export function useAccountCapabilities(): AccountCapabilities {
  const value = useContext(AccountCapabilitiesContext);
  if (!value) throw new Error("useAccountCapabilities must be used inside AccountAccessProvider");
  return value;
}

export function useAccountAccess(): AccountAccess {
  const value = useContext(AccountAccessContext);
  if (!value) throw new Error("useAccountAccess must be used inside AccountAccessProvider");
  return value;
}

/** Shared workspace primitives may receive an explicit operation controller. */
export function useOptionalAccountAccess(): AccountAccess | null {
  return useContext(AccountAccessContext);
}
