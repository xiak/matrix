import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { Profiler, useRef, useState } from "react";
import userEvent from "@testing-library/user-event";
import { LocaleProvider, useLocalePreference } from "@/i18n/LocaleProvider";
import { UnsavedChangesProvider, useLeaveConfirmation } from "@ui/xiak";
import { afterEach, describe, expect, it, vi } from "vitest";
import { HttpProblem } from "@/infrastructure/http/jsonRequest";
import { SessionProvider, useSession } from "../application/SessionProvider";
import { AccountAccessProvider, useAccountAccess, useAccountCapabilities, type RoleAccessClient, type RoleSessionRevokeIntent, type UserManagementClient } from "../application/AccountAccessProvider";
import type { Account, AccountAccess, AccountAccessView, AccountIdentity, AccountPolicy, AccountPolicyAccess, AccountPolicyDetail, AccountPolicyDocument, AccountPolicyVersion, AccountSecuritySettings, ActionCapability, AuthorizationProfileDirectory, CapabilityRestriction, IamAction, PolicyAttachmentChangeExpectation, PolicyDirectory, SecuritySettingsUpdateIntent, User, UserAccess, UserDeletion, UserDeletionIntent, UserPolicyAttachment, UserPermissionBoundary } from "../domain/accounts";
import type { AccountLifecycleCompletion, AccountLifecycleIntent, UserManagementIntent, UserManagementCompletion } from "../domain/accounts";
import type { AuthenticatorState, NotificationContact, SecurityStepUp } from "../domain/personalSecurity";
import type { AccountRepository, IamRepository } from "../repositories/iamRepository";
import { httpIamRepository } from "../repositories/httpIamRepository";
import type { RoleAccess, RoleCapabilityAction, RoleDirectory } from "../domain/roles";
import { AccountAccessRenderer } from "./AccountAccessRenderer";
import { LiveRoleCreationWizard } from "./LiveRoleCreationWizard";
import { LoginRenderer } from "./LoginRenderer";
import { buildAccountAccessScene, type AccountDirectoryKind } from "../scenes/accountAccessScene";
import { AccountUserAccessMethods, type AccountUserDetailTab } from "./AccountUserWorkspace";
import { readUserManagementIntent, writeUserManagementIntent } from "../repositories/userManagementRecoveryStorage";
import { readUserDeletionIntents, userDeletionStorageKey } from "../repositories/userDeletionRecoveryStorage";

const navigation = vi.hoisted(() => ({ replace: vi.fn() }));
vi.mock("next/navigation", () => ({ useRouter: () => navigation }));
const credential = "account-test-only-memory-credential";
const timestamp = "2026-09-11T08:00:00Z";
function replacementFixtures() {
  const verified = { accountId: account.id, userId: rootUser.id, state: "VERIFIED" as const, resourceVersion: 1, email: "old@example.com", verifiedAt: timestamp, pendingVerificationId: null };
  const pendingStepUp: SecurityStepUp = {
    id: "step-up-replace-contact", requestId: "replace-contact-request", operation: "NOTIFICATION_CONTACT_REPLACE",
    expectedFactorRevision: 3, notificationContact: { expectedResourceVersion: 1, email: "new@example.com" },
    state: "PENDING", createdAt: timestamp, expiresAt: "2026-09-11T08:02:00Z", provedAt: null, consumedAt: null
  };
  const pendingVerification = {
    id: "verification-replace-contact", accountId: account.id, userId: rootUser.id, requestId: "replace-contact-request",
    purpose: "REPLACEMENT" as const, expectedResourceVersion: 1, email: "new@example.com", state: "PENDING" as const,
    issuedAt: timestamp, expiresAt: "2026-09-11T08:10:00Z", completedAt: null,
    delivery: { state: "ACCEPTED" as const, attempts: 1, lastOutcome: "ACCEPTED" as const, lastSmtpCode: 250, updatedAt: timestamp }
  };
  return { verified, pendingStepUp, pendingVerification };
}
const account: Account = { id: "tenant-a", displayName: "Team A", status: "ACTIVE", rootIdentity: { principalId: "primary-a", loginName: "admin" }, loginAlias: null, resourceVersion: 1 };
const rootUser: User = { id: "primary-a", accountId: "tenant-a", loginName: "admin", displayName: "Account owner", status: "ACTIVE", resourceVersion: 2, mustChangePassword: false };
const tenantPolicy: AccountPolicy = { id: "system.paas-viewer", management: "SYSTEM", accountId: null, displayName: "ReadOnlyAccess", scope: "TENANT", status: "ACTIVE", defaultVersionId: "version-1", resourceVersion: 3, createdAt: timestamp, updatedAt: timestamp };
const platformPolicy: AccountPolicy = { ...tenantPolicy, id: "system.platform-admin", displayName: "PlatformAdministrator", scope: "INSTALLATION", resourceVersion: 2 };
const attachment = (principalId: string, policy: AccountPolicy): UserPolicyAttachment => ({ id: `attachment-${principalId}-${policy.id}`, accountId: "tenant-a", target: { kind: "USER", id: principalId }, policyId: policy.id, scope: policy.scope, installationId: policy.scope === "INSTALLATION" ? "installation-a" : null, resourceVersion: 1, createdAt: timestamp, updatedAt: timestamp });
const directory = (platform: boolean): PolicyDirectory => ({ accountId: "tenant-a", scope: platform ? "INSTALLATION" : "TENANT", installationId: platform ? "installation-a" : null, items: [platform ? platformPolicy : tenantPolicy] });
const profileDirectory = (): AuthorizationProfileDirectory => ({ accountId: account.id, items: [{
  profile: { product: "paas", revision: 1, callingService: "PAAS", actions: [{ action: "paas.application.read", resourceKind: "APPLICATION", scope: "TENANT", resourceShapes: [{ mode: "INSTANCE", prefixAllowed: true }], conditions: [{ key: "iam.account-id", valueType: "STRING", source: "IAM_AUTHENTICATED_IDENTITY" }] }] },
  contentDigest: `sha256:${"a".repeat(64)}`
}] });
const tenantPolicyDetail: AccountPolicyDetail = { policy: tenantPolicy, version: {
  policyId: tenantPolicy.id, versionId: tenantPolicy.defaultVersionId, contentDigest: `sha256:${"a".repeat(64)}`, contractVersion: 1,
  document: { languageVersion: "1", scope: "TENANT", statements: [{ sid: "read-applications", effect: "ALLOW",
    actions: ["paas.application.read"], resources: [{ kind: "APPLICATION", match: "ANY_IN_AUTHORITY" }] }] }
} };
const capability = (action: IamAction, kind: ActionCapability["resource"]["kind"], id: string, reason: CapabilityRestriction | null = null): ActionCapability => ({ action, resource: { kind, id }, available: reason === null, restrictionReason: reason });
const currentCapabilities = (available = true, accessKeyUserId = rootUser.id, accessKeyAvailable = available): ActionCapability[] => [
  capability("iam.account.create", "ACCOUNT", "collection", available ? null : "AUTHORITY_REQUIRED"),
  capability("iam.account.read", "ACCOUNT", "collection", available ? null : "AUTHORITY_REQUIRED"),
  capability("iam.account.alias-set", "ACCOUNT", account.id, available ? null : "AUTHORITY_REQUIRED"),
  capability("iam.user.list", "ACCOUNT", account.id, available ? null : "AUTHORITY_REQUIRED"),
  capability("iam.user.create", "ACCOUNT", account.id, available ? null : "AUTHORITY_REQUIRED"),
  capability("iam.policy.list", "ACCOUNT", account.id, available ? null : "AUTHORITY_REQUIRED"),
  capability("iam.group.list", "ACCOUNT", account.id, available ? null : "AUTHORITY_REQUIRED"),
  capability("iam.group.create", "ACCOUNT", account.id, available ? null : "AUTHORITY_REQUIRED"),
  capability("iam.role.list", "ACCOUNT", account.id, available ? null : "AUTHORITY_REQUIRED"),
  capability("iam.role.create", "ACCOUNT", account.id, available ? null : "AUTHORITY_REQUIRED"),
  capability("iam.access-key.list", "USER", accessKeyUserId, accessKeyAvailable ? null : "AUTHORITY_REQUIRED"),
  capability("iam.access-analyzer.list", "ACCOUNT", account.id, available ? null : "AUTHORITY_REQUIRED"),
  capability("iam.access-analyzer.create", "ACCOUNT", account.id, available ? null : "AUTHORITY_REQUIRED"),
  capability("iam.security-report.create", "ACCOUNT", account.id, available ? null : "AUTHORITY_REQUIRED"),
  capability("iam.service-role-template.list", "ACCOUNT", account.id, available ? null : "AUTHORITY_REQUIRED"),
  capability("iam.service-linked-role.list", "ACCOUNT", account.id, available ? null : "AUTHORITY_REQUIRED"),
  capability("iam.security-settings.read", "ACCOUNT", account.id, available ? null : "AUTHORITY_REQUIRED"),
  capability("iam.security-settings.update", "ACCOUNT", account.id, available ? null : "AUTHORITY_REQUIRED"),
  capability("iam.policy.create", "ACCOUNT", account.id, available ? null : "AUTHORITY_REQUIRED")
];
const policyCapabilities = (policyId: string): ActionCapability[] => [
  "iam.policy.update", "iam.policy.delete", "iam.policy-version.list", "iam.policy-version.read",
  "iam.policy-version.create", "iam.policy-version.delete", "iam.policy.set-default-version"
].map((action) => capability(action as IamAction, "POLICY", policyId));
const policyAccess = (detail: AccountPolicyDetail) => ({ detail, capabilities: policyCapabilities(detail.policy.id) });
const userCapabilities = (user: User, attachments: UserPolicyAttachment[] = [], reason: CapabilityRestriction | null = null): ActionCapability[] => [
  capability("iam.user.read", "USER", user.id, reason),
  capability("iam.user.update", "USER", user.id, reason),
  capability("iam.user.permission-boundary.set", "USER", user.id, reason),
  capability("iam.user.permission-boundary.remove", "USER", user.id, reason),
  capability("iam.user.delete", "USER", user.id, reason ?? (user.status === "ACTIVE" ? "TARGET_MUST_BE_DISABLED" : null)),
  capability("iam.user.set-status", "USER", user.id, reason),
  capability("iam.user.reset-password", "USER", user.id, reason),
  capability("iam.policy-attachment.create", "USER", user.id),
  capability("iam.platform-policy-attachment.create", "USER", user.id),
  ...attachments.map((item) => capability(item.scope === "INSTALLATION" ? "iam.platform-policy-attachment.revoke" : "iam.policy-attachment.revoke", "POLICY_ATTACHMENT", item.id))
];
const accountAccess = (value: Account): AccountAccess => ({ account: value, capabilities: [
  capability("iam.account.set-status", "ACCOUNT", value.id),
  capability("iam.account.recover-root-credentials", "ACCOUNT", value.id)
] });
const identity: AccountIdentity = {
  account, user: rootUser, identityKind: "ROOT_IDENTITY", policySources: [], permissionBoundary: { accountId: account.id, userId: rootUser.id, resourceVersion: rootUser.resourceVersion, policy: null }, capabilities: currentCapabilities()
};
const accountSecuritySettings: AccountSecuritySettings = {
  accountId: account.id,
  resourceVersion: 4,
  mfa: { requiredForUsers: true },
  password: { minimumLength: 15, requireLowercase: true, requireUppercase: true, requireDigit: true, requireSymbol: true, historyCount: 3, maxAgeDays: 90, expiryMode: "CHANGE_PASSWORD" },
  session: { idleTimeoutMinutes: 30 },
  accessKeyNetwork: { allowedSourceCidrs: [] },
  updatedAt: timestamp
};
const childUser: User = { ...rootUser, id: "child-a", loginName: "developer", displayName: "Developer A" };
const child: UserAccess = { user: childUser, policyAttachments: [attachment("child-a", tenantPolicy)], capabilities: userCapabilities(childUser, [attachment("child-a", tenantPolicy)]) };
const storedUserDeletion = (overrides: Partial<UserDeletionIntent> = {}): UserDeletionIntent => ({
  format: 1,
  accountId: account.id,
  actorPrincipalId: rootUser.id,
  userId: childUser.id,
  loginName: childUser.loginName,
  expectedResourceVersion: childUser.resourceVersion,
  commandRequestId: `ui-user-delete-${"a".repeat(32)}`,
  ...overrides
});
const managedRole = {
  id: "role-reviewer", accountId: account.id, name: "ProductionLogReviewer", description: "Review production logs during an incident",
  tags: [{ key: "team", value: "operations" }], management: "CUSTOMER" as const, status: "ACTIVE" as const,
  maxSessionDurationSeconds: 3600, resourceVersion: 3, currentTrustVersionId: "trust-reviewer-v2", createdAt: timestamp, updatedAt: timestamp
};
const managedRoleActions: RoleCapabilityAction[] = [
  "iam.role.read", "iam.role.update", "iam.role.set-status", "iam.role.delete", "iam.role-trust.set",
  "iam.role-policy-attachment.create", "iam.role.permission-boundary.set", "iam.role.permission-boundary.remove", "iam.role-session.list"
];
const managedRoleCapabilities = managedRoleActions.map((action) => ({
  action, resource: { kind: "ROLE" as const, id: managedRole.id }, available: action !== "iam.role.delete",
  restrictionReason: action === "iam.role.delete" ? "AUTHORITY_REQUIRED" as const : null
}));
const managedRoleDirectory: RoleDirectory = { accountId: account.id, items: [{ role: managedRole, capabilities: managedRoleCapabilities }], nextAfter: null };
const managedRoleAccess: RoleAccess = {
  role: managedRole,
  trustVersion: {
    id: managedRole.currentTrustVersionId, accountId: account.id, roleId: managedRole.id, createdAt: timestamp,
    contentDigest: `sha256:${"a".repeat(64)}`,
    document: { languageVersion: "1", statements: [{ sid: "incident-review", effect: "ALLOW", principals: [{ type: "USER", id: childUser.id }] }] }
  },
  policyAttachments: [],
  capabilities: [...managedRoleCapabilities, {
    action: "iam.role.assume", resource: { kind: "ROLE", id: managedRole.id }, available: false, restrictionReason: "AUTHORITY_REQUIRED"
  }]
};
const unusedLiveRoleRepositoryMutations = () => ({
  update: vi.fn().mockRejectedValue(new Error("unused role update")),
  setStatus: vi.fn().mockRejectedValue(new Error("unused role status")),
  setTrustPolicy: vi.fn().mockRejectedValue(new Error("unused role trust")),
  delete: vi.fn().mockRejectedValue(new Error("unused role delete")),
  createPolicyAttachment: vi.fn().mockRejectedValue(new Error("unused role attachment"))
});
const managedRoleSession = {
  id: "rs1.incident-review", accountId: account.id, roleId: managedRole.id, sourceUserId: childUser.id, status: "ACTIVE" as const,
  issuedAt: timestamp, expiresAt: "2026-09-21T09:00:00Z", revokedAt: null
};
const managedRoleSessionItem = {
  session: managedRoleSession,
  source: { type: "USER" as const, user: { id: childUser.id, loginName: childUser.loginName, displayName: childUser.displayName } },
  lifecycle: "UNREVOKED" as const,
  revokeCapability: { action: "iam.role-session.revoke" as const, resource: { kind: "ROLE_SESSION" as const, id: managedRoleSession.id }, available: true, restrictionReason: null }
};

function iam(overrides: Partial<IamRepository> = {}, id = "primary-a"): IamRepository {
  return {
    login: vi.fn().mockResolvedValue({ credential, mustChangePassword: false, session: { id: "session-test", organizationId: "tenant-a", principalId: id, status: "ACTIVE", issuedAt: "2026-08-27T00:00:00Z", expiresAt: "2099-08-27T00:00:00Z" } }),
    changePassword: vi.fn(), logout: vi.fn(), ...overrides
  };
}

function accounts(overrides: Partial<AccountRepository> = {}): AccountRepository {
  return {
    currentIdentity: vi.fn().mockResolvedValue(structuredClone(identity)),
    listUsers: vi.fn().mockResolvedValue({ items: [child], nextAfter: null }),
    getUser: vi.fn().mockResolvedValue(structuredClone(child)),
    deleteUser: vi.fn().mockRejectedValue(new Error("unused user delete")),
    listPolicies: vi.fn().mockImplementation(async (_credential: string, platform: boolean) => directory(platform)),
    listAuthorizationProfiles: vi.fn().mockResolvedValue(profileDirectory()),
    listAccounts: vi.fn().mockResolvedValue({ items: [accountAccess(identity.account)], nextAfter: null }),
    readPasswordResetCompletion: vi.fn().mockRejectedValue(new HttpProblem(404, "RESET_RESULT_UNOBSERVED")),
    userManagement: { submit: vi.fn(async (_credential: string, intent: UserManagementIntent) => ({ ...childUser, resourceVersion: intent.expectedResourceVersion + 1,
      ...(intent.operation === "USER_UPDATE" ? { displayName: intent.intendedDisplayName } : { status: intent.intendedStatus }) })), readCompletion: vi.fn().mockRejectedValue(new HttpProblem(404, "UNOBSERVED")) },
    execute: vi.fn().mockResolvedValue(undefined),
    revokePolicyAttachment: vi.fn().mockResolvedValue({ id: "attachment-child-a-system.paas-viewer", resourceVersion: 2, revokedAt: "2026-08-27T00:00:00Z" }),
    ...overrides
  } as AccountRepository;
}

function liveAnalysis(): NonNullable<AccountRepository["accessAnalysis"]> {
  return {
    listAnalyzers: vi.fn().mockResolvedValue({ accountId: account.id, items: [], nextAfter: null }),
    readAnalyzer: vi.fn(), createAnalyzer: vi.fn(), updateAnalyzer: vi.fn(), setDisposition: vi.fn(),
    listFindings: vi.fn(), readFinding: vi.fn(), archiveFinding: vi.fn(), unarchiveFinding: vi.fn()
  };
}

function DirectoryGuardProbe({ view }: { view: AccountAccessView }) {
  const session = useSession();
  const access = useAccountAccess();
  const [exactReady, setExactReady] = useState(false);
  const [initiallyAdmitted, setInitiallyAdmitted] = useState(false);
  const [result, setResult] = useState("");
  const retainedCommand = useRef<UserManagementClient | null>(null);
  const originalUserCommand: UserManagementIntent = { format: 1, accountId: account.id, actorPrincipalId: identity.user.id, userId: childUser.id, operation: "USER_SET_STATUS", expectedResourceVersion: childUser.resourceVersion, intendedStatus: "DISABLED", commandRequestId: "directory-owner-command" };
  return <>
    <button onClick={() => void session.login("admin", "password")}>login-directory-probe</button>
    <button onClick={() => void access.loadUser(childUser.id).then(() => { retainedCommand.current = access.userManagement; setInitiallyAdmitted(Boolean(access.userManagement?.canBegin(originalUserCommand))); setExactReady(true); }).catch(() => { setInitiallyAdmitted(false); setExactReady(false); })}>read-exact-user</button>
    <button onClick={() => access.usersPage("next-user-page")}>read-next-user-page</button>
    <button disabled={access.loading} onClick={() => void access.retryDirectory("users")}>retry-user-directory</button>
    <button onClick={() => { const client = retainedCommand.current ?? access.userManagement; if (!client) setResult("false"); else void client.submit(originalUserCommand).then(() => setResult("true"), () => setResult("false")); }}>attempt-old-user-command</button>
    <output aria-label="exact-user-ready">{String(exactReady)}</output>
    <output aria-label="exact-user-initially-admitted">{String(initiallyAdmitted)}</output>
    <output aria-label="old-user-command-result">{result}</output>
    <AccountAccessRenderer view={view} onNavigate={() => {}} />
  </>;
}

async function openDirectoryGuard(repository: AccountRepository, view: AccountAccessView) {
  const user = userEvent.setup({ delay: null });
  render(<LocaleProvider><SessionProvider repository={iam()}><AccountAccessProvider repository={repository}>
    <DirectoryGuardProbe view={view} />
  </AccountAccessProvider></SessionProvider></LocaleProvider>);
  await user.click(screen.getByRole("button", { name: "login-directory-probe" }));
  return user;
}

function liveAccountLifecycle(overrides: Partial<NonNullable<AccountRepository["accountLifecycle"]>> = {}): NonNullable<AccountRepository["accountLifecycle"]> {
  let current = structuredClone(account);
  return {
    readCompletion: vi.fn().mockRejectedValue(new HttpProblem(404, "ORIGINAL_ACCOUNT_COMPLETION_UNOBSERVED")),
    list: vi.fn().mockImplementation(async () => ({ items: [accountAccess(current)], nextAfter: null })),
    read: vi.fn().mockImplementation(async (_credential: string, accountId: string) => {
      if (accountId !== current.id) throw new HttpProblem(404, "ACCOUNT_NOT_FOUND");
      return accountAccess(structuredClone(current));
    }),
    create: vi.fn().mockImplementation(async (_credential: string, command) => {
      current = { id: command.id, displayName: command.displayName, status: "ACTIVE", rootIdentity: { principalId: `root-${command.id}`, loginName: command.rootLoginName }, loginAlias: null, resourceVersion: 1 };
      return structuredClone(current);
    }),
    setStatus: vi.fn().mockImplementation(async (_credential: string, accountId: string, command) => {
      if (accountId !== current.id || command.resourceVersion !== current.resourceVersion) throw new HttpProblem(409, "IAM_CONFLICT");
      current = { ...current, status: command.status, resourceVersion: current.resourceVersion + 1 };
      return structuredClone(current);
    }),
    recoverRootCredentials: vi.fn().mockImplementation(async (_credential: string, accountId: string, command) => {
      if (accountId !== current.id || command.resourceVersion !== current.resourceVersion) throw new HttpProblem(409, "IAM_CONFLICT");
      current = { ...current, resourceVersion: current.resourceVersion + 1 };
      return structuredClone(current);
    }),
    ...overrides
  };
}

function lifecycleCompletion(intent: AccountLifecycleIntent, rootRecoveryStatus: Account["status"] = "ACTIVE"): AccountLifecycleCompletion {
  const base = { actorAccountId: intent.actorAccountId, actorPrincipalId: intent.actorPrincipalId, accountId: intent.accountId,
    commandRequestId: intent.commandRequestId, eventId: "account-completion-event", occurredAt: "2026-10-15T00:00:00Z" };
  if (intent.operation === "ACCOUNT_CREATE") return { ...base, operation: intent.operation, expectedResourceVersion: 0,
    resultingResourceVersion: 1, status: "ACTIVE", rootPrincipalId: "created-account-root" };
  if (intent.operation === "ACCOUNT_SET_STATUS") return { ...base, operation: intent.operation,
    expectedResourceVersion: intent.expectedResourceVersion, resultingResourceVersion: intent.expectedResourceVersion + 1, status: intent.intendedStatus };
  return { ...base, operation: intent.operation, expectedResourceVersion: intent.expectedResourceVersion,
    resultingResourceVersion: intent.expectedResourceVersion + 1, status: rootRecoveryStatus, rootPrincipalId: account.rootIdentity.principalId };
}

function originalAccountStatusIntent(): AccountLifecycleIntent {
  return { format: 1, actorAccountId: account.id, actorPrincipalId: rootUser.id, operation: "ACCOUNT_SET_STATUS", accountId: account.id,
    commandRequestId: "original-account-status-command", expectedResourceVersion: 1, intendedStatus: "DISABLED" };
}

async function importAccountSummary(user: ReturnType<typeof userEvent.setup>, summary: string) {
  const trigger = screen.getByText("恢复原账号操作", { selector: "summary" });
  if (!trigger.closest("details")?.open) await user.click(trigger);
  fireEvent.change(screen.getByLabelText("原账号操作非敏感摘要"), { target: { value: summary } });
  await user.click(screen.getByRole("button", { name: "带入摘要并只读检查" }));
}

function livePolicyVersions() {
  let policy: AccountPolicy = { ...tenantPolicy, id: "customer.logs", management: "CUSTOMER", accountId: account.id,
    displayName: "LogBoundary", defaultVersionId: "version-logs", resourceVersion: 4 };
  const current: AccountPolicyVersion = { ...tenantPolicyDetail.version, policyId: policy.id, versionId: policy.defaultVersionId };
  const earlier: AccountPolicyVersion = { ...current, versionId: "version-a", contentDigest: `sha256:${"b".repeat(64)}`,
    document: { ...current.document, statements: [{ ...current.document.statements[0]!, actions: ["paas.application.delete"] }] } };
  let versions = [earlier, current];
  const readPolicy = vi.fn(async () => policyAccess({ policy: structuredClone(policy), version: structuredClone(versions.find((item) => item.versionId === policy.defaultVersionId)!) }));
  const listPolicyVersions = vi.fn(async () => ({ policy: structuredClone(policy), items: structuredClone(versions) }));
  const createPolicyVersion = vi.fn(async (_credential: string, _accountId: string, _policyId: string,
    command: { document: AccountPolicyDocument; resourceVersion: number; expectedDefaultVersionId: string; requestId: string }) => {
    if (command.resourceVersion !== policy.resourceVersion || command.expectedDefaultVersionId !== policy.defaultVersionId) throw new HttpProblem(409, "IAM_CONFLICT");
    const version: AccountPolicyVersion = { ...current, versionId: "version-new", document: structuredClone(command.document),
      contentDigest: `sha256:${"c".repeat(64)}` };
    versions = [...versions, version].sort((left, right) => left.versionId.localeCompare(right.versionId));
    policy = { ...policy, resourceVersion: policy.resourceVersion + 1 };
    return { policy: structuredClone(policy), version: structuredClone(version) };
  });
  const setDefaultPolicyVersion = vi.fn(async (_credential: string, _accountId: string, _policyId: string,
    command: { versionId: string; resourceVersion: number; requestId: string }) => {
    if (command.resourceVersion !== policy.resourceVersion) throw new HttpProblem(409, "IAM_CONFLICT");
    policy = { ...policy, defaultVersionId: command.versionId, resourceVersion: policy.resourceVersion + 1 };
    return { policy: structuredClone(policy), version: structuredClone(versions.find((item) => item.versionId === policy.defaultVersionId)!) };
  });
  const retirePolicyVersion = vi.fn(async (_credential: string, _accountId: string, _policyId: string, versionId: string,
    command: { resourceVersion: number; expectedDefaultVersionId: string; requestId: string }) => {
    if (command.resourceVersion !== policy.resourceVersion || versionId === policy.defaultVersionId) throw new HttpProblem(409, "IAM_CONFLICT");
    versions = versions.filter((item) => item.versionId !== versionId);
    policy = { ...policy, resourceVersion: policy.resourceVersion + 1 };
    return { policy: structuredClone(policy), version: structuredClone(versions.find((item) => item.versionId === policy.defaultVersionId)!) };
  });
  const repository = accounts({ readPolicy, listPolicyVersions, readPolicyVersion: vi.fn(async (_credential, _accountId, _policyId, versionId) =>
    ({ policy: structuredClone(policy), version: structuredClone(versions.find((item) => item.versionId === versionId)!) })),
  createPolicyVersion, setDefaultPolicyVersion, retirePolicyVersion,
  listPolicies: vi.fn(async (_credential: string, platform: boolean) => platform ? directory(true) : { ...directory(false), items: [structuredClone(policy)] }) });
  return { repository, readPolicy, listPolicyVersions, createPolicyVersion, setDefaultPolicyVersion, retirePolicyVersion };
}

function livePolicyMetadata() {
  let policy: AccountPolicy = { ...tenantPolicy, id: "customer.logs", management: "CUSTOMER", accountId: account.id,
    displayName: "LogBoundary", defaultVersionId: "version-logs", resourceVersion: 4 };
  const version = { ...tenantPolicyDetail.version, policyId: policy.id, versionId: policy.defaultVersionId };
  const readPolicy = vi.fn(async (_credential: string, _accountId: string, id: string) => policyAccess(id === tenantPolicy.id
    ? structuredClone(tenantPolicyDetail) : { policy: structuredClone(policy), version: structuredClone(version) }));
  const updatePolicy = vi.fn(async (_credential: string, _accountId: string, _source: { policy: AccountPolicy; contentDigest: string }, command: { displayName: string; resourceVersion: number; requestId: string }) => {
    if (command.resourceVersion !== policy.resourceVersion) throw new HttpProblem(409, "STALE");
    policy = { ...policy, displayName: command.displayName, resourceVersion: policy.resourceVersion + 1 };
    return { policy: structuredClone(policy), version: structuredClone(version) };
  });
  const deletePolicy = vi.fn(async (_credential: string, _accountId: string, _source: AccountPolicy, command: { resourceVersion: number; requestId: string }) => {
    if (command.resourceVersion !== policy.resourceVersion) throw new HttpProblem(409, "STALE");
    policy = { ...policy, status: "RETIRED", resourceVersion: policy.resourceVersion + 1 };
    return structuredClone(policy);
  });
  const listPolicies = vi.fn(async (_credential: string, platform: boolean) => platform ? directory(true) :
    { ...directory(false), items: [tenantPolicy, ...(policy.status === "ACTIVE" ? [structuredClone(policy)] : [])] });
  const repository = accounts({ readPolicy, updatePolicy, deletePolicy, listPolicies });
  return { repository, readPolicy, updatePolicy, deletePolicy, listPolicies, version };
}

const originalPolicyLocks = Object.getOwnPropertyDescriptor(navigator, "locks");
function enablePolicyLocks() {
  const held = new Set<string>();
  Object.defineProperty(navigator, "locks", { configurable: true, value: { request: async (name: string, _options: LockOptions, run: (lock: Lock | null) => unknown) => {
    if (held.has(name)) return run(null);
    held.add(name); try { return await run({ name, mode: "exclusive" }); } finally { held.delete(name); }
  } } });
}

function boundaryFixture() {
  const target = structuredClone(child);
  let boundary: UserPermissionBoundary = { accountId: account.id, userId: target.user.id, resourceVersion: target.user.resourceVersion, policy: null };
  let policies = [structuredClone(tenantPolicy), { ...tenantPolicy, id: "customer.logs", management: "CUSTOMER" as const, accountId: account.id, displayName: "LogBoundary", resourceVersion: 4, defaultVersionId: "version-logs" }];
  const reference = (policyId: string) => {
    const policy = policies.find((item) => item.id === policyId)!;
    return { policyId, versionId: policy.defaultVersionId, contentDigest: `sha256:${"a".repeat(64)}` };
  };
  const boundaries = {
    read: vi.fn(async () => structuredClone(boundary)),
    set: vi.fn(async (_credential: string, _accountId: string, _userId: string, command: { policyId: string; policyResourceVersion: number; resourceVersion: number; requestId: string }) => {
      if (command.resourceVersion !== target.user.resourceVersion) throw new HttpProblem(409, "IAM_CONFLICT");
      target.user.resourceVersion += 1;
      boundary = { ...boundary, resourceVersion: target.user.resourceVersion, policy: reference(command.policyId) };
      return structuredClone(boundary);
    }),
    remove: vi.fn(async (_credential: string, _accountId: string, _userId: string, command: { resourceVersion: number; requestId: string }) => {
      if (command.resourceVersion !== target.user.resourceVersion) throw new HttpProblem(409, "IAM_CONFLICT");
      target.user.resourceVersion += 1;
      boundary = { ...boundary, resourceVersion: target.user.resourceVersion, policy: null };
      return structuredClone(boundary);
    })
  };
  const repository = accounts({
    permissionBoundaries: boundaries,
    getUser: vi.fn(async () => structuredClone(target)),
    listPolicies: vi.fn(async (_credential: string, platform: boolean) => platform ? directory(true) : { ...directory(false), items: structuredClone(policies) })
  });
  return { repository, boundaries,
    advance() { target.user.resourceVersion += 1; boundary.resourceVersion = target.user.resourceVersion; policies = policies.map((policy) => ({ ...policy, resourceVersion: policy.resourceVersion + 1 })); },
    readOnly() { target.capabilities = target.capabilities.map((capability) => capability.action.includes("permission-boundary") ? { ...capability, available: false, restrictionReason: "AUTHORITY_REQUIRED" } : capability); }
  };
}

async function openBoundary(fixture: ReturnType<typeof boundaryFixture>) {
  const result = await openAccess(fixture.repository);
  await screen.findByText("Developer A");
  await result.user.click(screen.getByRole("button", { name: "查看用户 developer" }));
  await screen.findByRole("region", { name: "权限边界" });
  return result;
}

async function chooseBoundary(user: ReturnType<typeof userEvent.setup>, label: string) {
  await user.click(screen.getByRole("button", { name: "修改权限边界" }));
  await user.click(screen.getByRole("combobox", { name: "权限边界" }));
  await user.click(screen.getByRole("option", { name: label }));
  await user.click(screen.getByRole("button", { name: "审阅变更" }));
}

function LanguageSwitch() {
  const { locale, setLocale } = useLocalePreference();
  return <button onClick={() => setLocale(locale === "en" ? "zh-CN" : "en")}>Switch language</button>;
}

const capabilityCommit = vi.fn();
function CapabilityProbe() {
  const capabilities = useAccountCapabilities();
  return <Profiler id="navigation-capabilities" onRender={capabilityCommit}>
    <output data-testid="can-manage">{String(capabilities.canListUsers)}</output>
    <output data-testid="can-read-accounts">{String(capabilities.canReadAccounts)}</output>
  </Profiler>;
}

function AuthorityRefreshProbe() {
  const access = useAccountAccess();
  return <button disabled={access.loading} onClick={access.reload}>recheck-test-authority</button>;
}

const accountSwitchIntent: RoleSessionRevokeIntent = {
  accountId: account.id,
  roleId: managedRole.id,
  item: managedRoleSessionItem,
  requestId: "ui-role-session-revoke-account-switch",
  phase: "unknown",
  open: false
};

function AccountIntentProbe() {
  const session = useSession();
  const access = useAccountAccess();
  return <>
    <button onClick={() => void session.login("admin-a", "password-a")}>login-a</button>
    <button onClick={() => void session.logout()}>logout</button>
    <button onClick={() => void session.login("admin-b", "password-b")}>login-b</button>
    <button onClick={() => access.changeRoleSessionRevokeIntent(null, accountSwitchIntent)}>remember-revoke</button>
    <button onClick={() => access.changeRoleSessionRevokeIntent(accountSwitchIntent.requestId, { ...accountSwitchIntent, phase: "checking" })}>late-old-update</button>
    <button onClick={() => { const target = access.scene?.users[0]; if (target) access.beginUserPolicyAttachment(target, platformPolicy.id); }}>begin-attachment</button>
    <button onClick={() => { if (access.userPolicyChangeIntent) void access.submitUserPolicyChange(access.userPolicyChangeIntent.requestId); }}>submit-attachment</button>
    <output aria-label="active-account">{access.scene?.accountId ?? "none"}</output>
    <output aria-label="pending-revoke">{access.roleSessionRevokeIntent?.requestId ?? "none"}</output>
    <output aria-label="pending-attachment">{access.userPolicyChangeIntent?.requestId ?? "none"}</output>
    <output aria-label="attachment-success">{access.success ?? "none"}</output>
  </>;
}

function DirectUserPolicyOwnerProbe() {
  const access = useAccountAccess();
  const [readResult, setReadResult] = useState("idle");
  const [attachResult, setAttachResult] = useState("idle");
  const [revokeResult, setRevokeResult] = useState("idle");
  const [submitResult, setSubmitResult] = useState("idle");
  const [inspectResult, setInspectResult] = useState("idle");
  const [endResult, setEndResult] = useState("idle");
  const target = access.scene?.users[0];
  const intent = access.userPolicyChangeIntent;
  return <>
    <button onClick={() => void access.loadUser(childUser.id).then(() => setReadResult("ready"), () => setReadResult("error"))}>direct-read-user</button>
    <button onClick={() => setAttachResult(String(Boolean(target && access.beginUserPolicyAttachment(target, platformPolicy.id))))}>direct-begin-attachment</button>
    <button onClick={() => setRevokeResult(String(Boolean(target && access.beginUserPolicyRevocation(target, target.attachments[0]?.id ?? "missing"))))}>direct-begin-revocation</button>
    <button onClick={() => void access.submitUserPolicyChange(intent?.requestId ?? "missing").then((result) => setSubmitResult(String(result)))}>direct-submit-attachment</button>
    <button onClick={() => void access.inspectUserPolicyChange(intent?.requestId ?? "missing").then((result) => setInspectResult(String(result)))}>direct-inspect-attachment</button>
    <button onClick={() => setEndResult(String(access.endUserPolicyChange(intent?.requestId ?? "missing")))}>direct-end-attachment</button>
    <output aria-label="direct-owner-ready">{String(access.userPolicyChangeReady)}</output>
    <output aria-label="direct-read-result">{readResult}</output>
    <output aria-label="direct-attach-result">{attachResult}</output>
    <output aria-label="direct-revoke-result">{revokeResult}</output>
    <output aria-label="direct-submit-result">{submitResult}</output>
    <output aria-label="direct-inspect-result">{inspectResult}</output>
    <output aria-label="direct-end-result">{endResult}</output>
    <output aria-label="direct-policy-intent">{intent ? `${intent.phase}:${intent.requestId}` : "none"}</output>
  </>;
}

function AuthenticatedUserPolicyOwnerProbe({ repository }: { repository: AccountRepository }) {
  const session = useSession();
  return session.phase === "authenticated"
    ? <AccountAccessProvider repository={repository}><DirectUserPolicyOwnerProbe /></AccountAccessProvider>
    : <LoginRenderer />;
}

async function openDirectUserPolicyOwnerProbe(repository: AccountRepository) {
  const user = userEvent.setup({ delay: null });
  const tree = (activeRepository: AccountRepository) => <LocaleProvider><SessionProvider repository={iam()}><AuthenticatedUserPolicyOwnerProbe repository={activeRepository} /></SessionProvider></LocaleProvider>;
  const view = render(tree(repository));
  await user.click(screen.getByLabelText("密码", { exact: true }));
  await user.paste("Only-Test-Password-49!");
  await user.click(screen.getByRole("button", { name: "登录控制台" }));
  await waitFor(() => expect(repository.currentIdentity).toHaveBeenCalledWith(credential));
  await waitFor(() => expect(screen.getByLabelText("direct-owner-ready").textContent).toBe("true"));
  return { user, replaceRepository: (next: AccountRepository) => view.rerender(tree(next)) };
}

const originalKeyRequestId = `ui-access-key-create-${"a".repeat(32)}`;
const originalKeyStatusRequestId = `ui-access-key-status-${"a".repeat(32)}`;
const originalKeyNetworkRequestId = `ui-access-key-network-${"b".repeat(32)}`;
const originalKeyDeleteRequestId = `ui-access-key-delete-${"d".repeat(32)}`;
const replacementKeyDeleteRequestId = `ui-access-key-delete-${"e".repeat(32)}`;
function AccessKeyIntentProbe() {
  const session = useSession();
  const access = useAccountAccess();
  const [visible, setVisible] = useState(true);
  const client = access.accessKeys;
  return <>
    <button onClick={() => void session.login("admin", "password")}>login-key-probe</button>
    <button onClick={() => setVisible((current) => !current)}>toggle-key-view</button>
    <output aria-label="key-probe-session">{`${session.phase}:${access.scene?.accountId ?? "none"}:${access.loading}:${access.error ?? "none"}`}</output>
    {visible ? <>
      <button disabled={!client} onClick={() => { if (client) void client.create(childUser.id, { userResourceVersion: childUser.resourceVersion, networkRestrictions: { allowedSourceCidrs: [] }, requestId: originalKeyRequestId }).catch(() => {}); }}>create-original-key</button>
      <button disabled={!client} onClick={() => { if (client) void client.create(childUser.id, { userResourceVersion: childUser.resourceVersion, networkRestrictions: { allowedSourceCidrs: [] }, requestId: `ui-access-key-create-${"b".repeat(32)}` }).catch(() => {}); }}>create-new-key</button>
      <button disabled={!client} onClick={() => { if (client) void client.create("child-b", { userResourceVersion: 2, networkRestrictions: { allowedSourceCidrs: [] }, requestId: `ui-access-key-create-${"c".repeat(32)}` }).catch(() => {}); }}>create-other-user-key</button>
      <button disabled={!client} onClick={() => { client?.acknowledgeIssued(originalKeyRequestId, "mak1.lost-secret"); }}>acknowledge-issued-key</button>
      <button disabled={!client} onClick={() => { if (client) void client.setStatus(childUser.id, "mak1.lost-secret", { accessKeyResourceVersion: 2, status: "DISABLED", requestId: originalKeyStatusRequestId }).catch(() => {}); }}>disable-key</button>
      <button disabled={!client} onClick={() => { if (client) void client.setNetworkRestrictions(childUser.id, "mak1.lost-secret", { accessKeyResourceVersion: 2, networkRestrictions: { allowedSourceCidrs: ["203.0.113.0/24"] }, requestId: originalKeyNetworkRequestId }).catch(() => {}); }}>restrict-key-network</button>
      <button disabled={!client} onClick={() => { if (client) void client.delete(childUser.id, "mak1.lost-secret", { accessKeyResourceVersion: 2, requestId: originalKeyDeleteRequestId }).catch(() => {}); }}>retire-recovered-key</button>
      <button disabled={!client} onClick={() => { if (client) void client.delete(childUser.id, "mak1.lost-secret", { accessKeyResourceVersion: 2, requestId: replacementKeyDeleteRequestId }).catch(() => {}); }}>retire-recovered-key-new-intent</button>
      <button disabled={!client} onClick={() => { client?.acknowledgeMutation(originalKeyStatusRequestId); client?.acknowledgeMutation(originalKeyNetworkRequestId); client?.acknowledgeMutation(originalKeyDeleteRequestId); }}>acknowledge-key-mutation</button>
      <output aria-label="key-recovery-error">{String(access.accessKeyRecoveryError)}</output>
      <output aria-label="key-create-intent">{access.accessKeyCreateIntent ? `${access.accessKeyCreateIntent.phase}:${access.accessKeyCreateIntent.userId}:${access.accessKeyCreateIntent.requestId}` : "none"}</output>
      <output aria-label="key-mutation-intent">{access.accessKeyMutationIntent ? `${access.accessKeyMutationIntent.phase}:${access.accessKeyMutationIntent.operation}:${access.accessKeyMutationIntent.userId}:${access.accessKeyMutationIntent.requestId}` : "none"}</output>
    </> : null}
  </>;
}

function SecuritySettingsIntentProbe({ proposed = { expectedResourceVersion: accountSecuritySettings.resourceVersion, mfa: accountSecuritySettings.mfa, password: accountSecuritySettings.password, session: accountSecuritySettings.session, accessKeyNetwork: { allowedSourceCidrs: ["10.0.0.0/8"] } } }: { proposed?: SecuritySettingsUpdateIntent }) {
  const session = useSession();
  const access = useAccountAccess();
  const update = access.accountSecuritySettings?.update;
  const intent = update?.intent;
  return <>
    <button onClick={() => void session.login("admin", "password")}>login-settings-probe</button>
    <button onClick={access.reload}>reload-settings-access</button>
    <output aria-label="settings-probe-session">{session.phase}</output>
    <output aria-label="settings-sign-in-notice">{session.signInNotice ? `${session.signInNotice.kind}:${session.signInNotice.requestId}` : "none"}</output>
    <output aria-label="settings-can-update">{String(access.accountSecuritySettings?.canUpdate ?? false)}</output>
    <button disabled={!update || Boolean(intent)} onClick={() => { if (update) void update.begin(accountSecuritySettings, proposed, 7).catch(() => {}); }}>begin-settings</button>
    <button disabled={!update || intent?.state !== "STEP_UP_UNKNOWN"} onClick={() => { if (update) void update.retryStepUp().catch(() => {}); }}>retry-settings-step-up</button>
    <button disabled={!update || intent?.state !== "PENDING"} onClick={() => { if (update) void update.verifyStepUp({ requestId: `ui-account-security-settings-verify-${"b".repeat(32)}`, password: "test-password", code: "123456" }).catch(() => {}); }}>verify-settings-step-up</button>
    <button disabled={!update || intent?.state !== "PROVED"} onClick={() => { if (update) void update.apply().catch(() => {}); }}>apply-settings</button>
    <button disabled={!update || intent?.state !== "APPLY_UNKNOWN"} onClick={() => { if (update) void update.inspectChange().catch(() => {}); }}>inspect-settings</button>
    <button disabled={!update || !intent} onClick={() => { if (update && intent) update.clear(intent.requestId); }}>clear-settings</button>
    <output aria-label="settings-intent">{intent ? `${intent.state}:${intent.requestId}:${intent.settings.expectedResourceVersion}:${intent.settings.accessKeyNetwork.allowedSourceCidrs.join(",")}` : "none"}</output>
  </>;
}

function ReadClassificationProbe() {
  const session = useSession();
  const access = useAccountAccess();
  const [serviceRole, setServiceRole] = useState("idle");
  const [policy, setPolicy] = useState("idle");
  const [profiles, setProfiles] = useState("idle");
  const [templates, setTemplates] = useState("idle");
  const [settings, setSettings] = useState("idle");
  return <>
    <button onClick={() => void session.login("admin", "password")}>login-read-classification</button>
    <button disabled={!access.serviceLinkedRoles} onClick={() => void access.serviceLinkedRoles?.read("missing-role").then((result) => setServiceRole(result.status))}>read-service-role</button>
    <button disabled={!access.policyRead} onClick={() => void access.policyRead?.read("missing-policy").then((result) => setPolicy(result.status))}>read-policy</button>
    <button disabled={!access.authorizationProfiles} onClick={() => void access.authorizationProfiles?.load().then((result) => setProfiles(result.status))}>read-profiles</button>
    <button disabled={!access.serviceRoleTemplates} onClick={() => void access.serviceRoleTemplates?.load().then((result) => setTemplates(result.status))}>read-templates</button>
    <button disabled={!access.accountSecuritySettings} onClick={() => void access.accountSecuritySettings?.load().then((result) => setSettings(result.status))}>read-settings</button>
    <output aria-label="service-role-read-status">{serviceRole}</output>
    <output aria-label="policy-read-status">{policy}</output>
    <output aria-label="profile-read-status">{profiles}</output>
    <output aria-label="template-read-status">{templates}</output>
    <output aria-label="settings-read-status">{settings}</output>
  </>;
}

function AuthenticatedAccess({ repository, initialView, initialEntityId, initialUserTab, active = true }: { repository: AccountRepository; initialView: AccountAccessView; initialEntityId?: string; initialUserTab?: AccountUserDetailTab; active?: boolean }) {
  const requestLeave = useLeaveConfirmation();
  const session = useSession();
  const [view, setView] = useState(initialView);
  const [entityId, setEntityId] = useState<string | undefined>(initialEntityId);
  const [userTab, setUserTab] = useState<AccountUserDetailTab | undefined>(initialUserTab);
  return session.phase === "authenticated" ? <AccountAccessProvider repository={repository} active={active}><CapabilityProbe /><AuthorityRefreshProbe /><nav>{(["overview", "users", "settings", "policies", "roles", "tenants"] as const).map((target) => <button data-testid={"nav-" + target} aria-current={view === target ? "page" : undefined} key={target} onClick={() => requestLeave(() => { setView(target); setEntityId(undefined); setUserTab(undefined); })}>{target}</button>)}</nav><AccountAccessRenderer view={view} entityId={entityId} userTab={userTab} onNavigate={(next, id, _method, nextUserTab) => requestLeave(() => { setView(next); setEntityId(id); setUserTab(nextUserTab); })} /></AccountAccessProvider> : <LoginRenderer />;
}

async function openAccess(repository = accounts(), iamRepository = iam(), initialView: AccountAccessView = "users", expectedCredential = credential, initialEntityId?: string, initialUserTab?: AccountUserDetailTab) {
  const user = userEvent.setup({ delay: null });
  const tree = (activeRepository: AccountRepository, active = true) => <LocaleProvider><LanguageSwitch /><SessionProvider repository={iamRepository}><UnsavedChangesProvider><AuthenticatedAccess repository={activeRepository} initialView={initialView} initialEntityId={initialEntityId} initialUserTab={initialUserTab} active={active} /></UnsavedChangesProvider></SessionProvider></LocaleProvider>;
  const view = render(tree(repository));
  // These feature tests need an authenticated Session, not a keystroke-by-
  // keystroke login journey; the qualified-login owner covers that separately.
  await user.click(screen.getByLabelText("密码", { exact: true }));
  await user.paste("Only-Test-Password-49!");
  await user.click(screen.getByRole("button", { name: "登录控制台" }));
  await waitFor(() => expect(repository.currentIdentity).toHaveBeenCalledWith(expectedCredential));
  return { user, view, repository, replaceRepository: (next: AccountRepository) => view.rerender(tree(next)), setAccessActive: (active: boolean) => view.rerender(tree(repository, active)) };
}

async function invokeMoreAction(user: ReturnType<typeof userEvent.setup>, label: string) {
  await user.click(await screen.findByRole("button", { name: "更多操作" }));
  await user.click(within(await screen.findByRole("menu", { name: "更多操作" })).getByRole("menuitem", { name: label }));
}

async function reviewLiveNewUser(user: ReturnType<typeof userEvent.setup>) {
  await user.click(await screen.findByRole("button", { name: "创建用户" }));
  await user.type(screen.getByLabelText(/^子用户名/), "live.new");
  await user.type(screen.getByLabelText(/^用户显示名称/), "Live New User");
  await user.type(screen.getByLabelText(/^初始密码/), "Initial-password-for-browser-1!");
  await user.click(screen.getByRole("button", { name: "下一步" }));
  expect(screen.queryByRole("table", { name: /策略/ })).toBeNull();
  await user.click(screen.getByRole("combobox", { name: "权限边界" }));
  await user.click(screen.getByRole("option", { name: "主账号显式不设置权限边界" }));
  await user.click(screen.getByRole("button", { name: "下一步" }));
  expect(screen.getByText(`live.new@${account.id}`)).toBeTruthy();
  expect(document.body.textContent).not.toContain("Initial-password-for-browser-1!");
}

afterEach(() => {
  cleanup(); vi.clearAllMocks(); vi.unstubAllGlobals(); localStorage.clear(); sessionStorage.clear();
  if (originalPolicyLocks) Object.defineProperty(navigator, "locks", originalPolicyLocks); else Reflect.deleteProperty(navigator, "locks");
});

describe("qualified login", () => {
  it("returns a primary user to the originally requested console page", async () => {
    const repository = iam();
    const user = userEvent.setup();
    render(<LocaleProvider><SessionProvider repository={repository}><LoginRenderer returnTo="/console/resources/" /></SessionProvider></LocaleProvider>);
    await user.type(screen.getByLabelText("密码", { exact: true }), "Only-Test-Password-49!");
    await user.click(screen.getByRole("button", { name: "登录控制台" }));
    await waitFor(() => expect(navigation.replace).toHaveBeenCalledWith("/console/resources/", { scroll: false }));
  });

  it("uses one text identifier, clears secrets on mode change, and preserves IAM's account namespace", async () => {
    const repository = iam();
    const user = userEvent.setup();
    render(<LocaleProvider><SessionProvider repository={repository}><LoginRenderer /></SessionProvider></LocaleProvider>);
    await user.type(screen.getByLabelText("密码", { exact: true }), "Previous-mode-secret-49!");
    await user.click(screen.getByRole("tab", { name: "IAM 子账号" }));
    expect((screen.getByLabelText("密码", { exact: true }) as HTMLInputElement).value).toBe("");
    const field = screen.getByLabelText("子账号登录名") as HTMLInputElement;
    expect(field.type).toBe("text");
    await user.type(field, "developer@tenant-a");
    await user.type(screen.getByLabelText("密码", { exact: true }), "Only-Test-Password-49!");
    await user.click(screen.getByRole("button", { name: "登录控制台" }));
    await waitFor(() => expect(repository.login).toHaveBeenCalledWith({ loginName: "developer@tenant-a", password: "Only-Test-Password-49!" }));
    expect(navigation.replace).toHaveBeenCalledWith("/console/", { scroll: false });
    expect(localStorage.length + sessionStorage.length).toBe(0);
  });

  it("does not submit an unqualified child or leak prior authentication errors between modes", async () => {
    const repository = iam({ login: vi.fn().mockRejectedValue(new HttpProblem(401, "private upstream")) });
    const user = userEvent.setup();
    render(<LocaleProvider><SessionProvider repository={repository}><LoginRenderer /></SessionProvider></LocaleProvider>);
    await user.type(screen.getByLabelText("密码", { exact: true }), "Wrong-Password-49!");
    await user.click(screen.getByRole("button", { name: "登录控制台" }));
    await screen.findByRole("alert");
    await user.click(screen.getByRole("tab", { name: "IAM 子账号" }));
    expect(screen.queryByRole("alert")).toBeNull();
    await user.type(screen.getByLabelText("子账号登录名"), "developer");
    await user.type(screen.getByLabelText("密码", { exact: true }), "Only-Test-Password-49!");
    await user.click(screen.getByRole("button", { name: "登录控制台" }));
    expect(screen.getByRole("alert").textContent).toContain("主账号ID或别名");
    expect(repository.login).toHaveBeenCalledTimes(1);
  });
});

describe("account access", () => {
  it("mounts the destination identity immediately and limits first-load feedback to its data region", async () => {
    let resolveIdentity!: (value: AccountIdentity) => void;
    const repository = accounts({
      currentIdentity: vi.fn(() => new Promise<AccountIdentity>((resolve) => { resolveIdentity = resolve; }))
    });
    await openAccess(repository, iam(), "users");

    expect(screen.getByRole("heading", { level: 1, name: "用户" })).toBeTruthy();
    expect(screen.getByText("正在读取 IAM 账号信息…").closest('[role="status"]')).toBeTruthy();
    expect(screen.queryByRole("table", { name: "租户用户列表" })).toBeNull();

    await act(async () => resolveIdentity(structuredClone(identity)));
    expect(await screen.findByRole("table", { name: "租户用户列表" })).toBeTruthy();
    expect(screen.queryByText("正在读取 IAM 账号信息…")).toBeNull();
  });

  it("changes a live user boundary through selection, review and confirmation without changing grants", async () => {
    const f = boundaryFixture();
    const { user } = await openBoundary(f);
    expect(screen.queryByRole("dialog")).toBeNull();
    await chooseBoundary(user, "ReadOnlyAccess · system.paas-viewer");
    expect(f.boundaries.set).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "确认变更" }));
    await screen.findByText("权限边界变更已确认，用户状态已重新读取。");
    const boundarySummary = screen.getByRole("region", { name: "权限边界" });
    expect(within(boundarySummary).getByText("ReadOnlyAccess", { exact: true })).toBeTruthy();
    expect(within(boundarySummary).getByText(tenantPolicy.id, { selector: "code" })).toBeTruthy();
    expect(f.boundaries.set).toHaveBeenLastCalledWith(credential, account.id, childUser.id, { policyId: tenantPolicy.id, policyResourceVersion: tenantPolicy.resourceVersion, resourceVersion: childUser.resourceVersion, requestId: expect.any(String) });
    await chooseBoundary(user, "LogBoundary · customer.logs");
    await user.click(screen.getByRole("button", { name: "确认变更" }));
    await screen.findByText("customer.logs", { exact: true });
    await chooseBoundary(user, "未设置租户权限边界");
    await user.click(screen.getByRole("button", { name: "确认变更" }));
    await screen.findByText("未设置租户权限边界");
    expect(f.boundaries.remove).toHaveBeenCalledWith(credential, account.id, childUser.id, { resourceVersion: childUser.resourceVersion + 2, requestId: expect.any(String) });
    expect(f.repository.execute).not.toHaveBeenCalled();
    expect(f.repository.currentIdentity).toHaveBeenCalledTimes(1);
  });

  it("owns keyboard focus while entering and leaving the inline boundary editor", async () => {
    const f = boundaryFixture();
    const { user } = await openBoundary(f);
    const edit = screen.getByRole("button", { name: "修改权限边界" });
    edit.focus();
    await user.keyboard("{Enter}");
    await waitFor(() => expect(document.activeElement).toBe(screen.getByRole("combobox", { name: "权限边界" })));
    await user.click(screen.getByRole("combobox", { name: "权限边界" }));
    await user.click(screen.getByRole("option", { name: "ReadOnlyAccess · system.paas-viewer" }));
    await user.click(screen.getByRole("button", { name: "审阅变更" }));
    await user.click(screen.getByRole("button", { name: "返回选择" }));
    await waitFor(() => expect(document.activeElement).toBe(screen.getByRole("combobox", { name: "权限边界" })));
    const cancel = screen.getByRole("button", { name: "取消" });
    cancel.focus();
    await user.keyboard("{Enter}");
    await waitFor(() => expect(document.activeElement).toBe(screen.getByRole("button", { name: "修改权限边界" })));
    expect(f.boundaries.set).not.toHaveBeenCalled();
    expect(f.boundaries.remove).not.toHaveBeenCalled();
  });

  it("keeps the exact live boundary request and review after an uncertain outcome", async () => {
    const f = boundaryFixture();
    f.boundaries.set.mockRejectedValueOnce(new HttpProblem(503, "IAM_UNAVAILABLE"));
    const { user } = await openBoundary(f);
    await chooseBoundary(user, "LogBoundary · customer.logs");
    await user.click(screen.getByRole("button", { name: "确认变更" }));
    await screen.findByText(/请求结果尚未确认/);
    expect((screen.getByRole("button", { name: "返回选择" }) as HTMLButtonElement).disabled).toBe(true);
    await user.click(screen.getByRole("button", { name: "重试原请求" }));
    await screen.findByText("权限边界变更已确认，用户状态已重新读取。");
    expect(f.boundaries.set.mock.calls[0]).toEqual(f.boundaries.set.mock.calls[1]);
  });

  it("does not resubmit an acknowledged boundary change when the follow-up read fails", async () => {
    const f = boundaryFixture();
    const { user } = await openBoundary(f);
    await chooseBoundary(user, "LogBoundary · customer.logs");
    f.boundaries.read.mockRejectedValueOnce(new HttpProblem(503, "IAM_UNAVAILABLE"));
    await user.click(screen.getByRole("button", { name: "确认变更" }));
    await screen.findByText(/边界变更已确认，但暂无法重新读取/);
    expect(screen.getByText("customer.logs", { exact: true })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "重试读取" }));
    await screen.findByText("权限边界变更已确认，用户状态已重新读取。");
    expect(f.boundaries.set).toHaveBeenCalledTimes(1);
  });

  it("retains a stale boundary selection but requires fresh revisions and a new explicit review", async () => {
    const f = boundaryFixture();
    const { user } = await openBoundary(f);
    await chooseBoundary(user, "LogBoundary · customer.logs");
    f.advance();
    await user.click(screen.getByRole("button", { name: "确认变更" }));
    await screen.findByText(/用户或策略版本已变化/);
    await user.click(screen.getByRole("button", { name: "重新读取并审阅" }));
    const selection = await screen.findByRole("combobox", { name: "权限边界" });
    expect(selection.textContent).toContain("LogBoundary");
    expect(f.boundaries.set).toHaveBeenCalledTimes(1);
    await user.click(screen.getByRole("button", { name: "审阅变更" }));
    await user.click(screen.getByRole("button", { name: "确认变更" }));
    await screen.findByText("权限边界变更已确认，用户状态已重新读取。");
    const first = f.boundaries.set.mock.calls[0]![3], second = f.boundaries.set.mock.calls[1]![3];
    expect(second.resourceVersion).toBe(first.resourceVersion + 1);
    expect(second.policyResourceVersion).toBe(first.policyResourceVersion + 1);
    expect(second.requestId).not.toBe(first.requestId);
  });

  it("expires sensitive live boundary state on 401 rather than leaving an editable private page", async () => {
    const f = boundaryFixture();
    f.boundaries.set.mockRejectedValueOnce(new HttpProblem(401, "IAM_EXPIRED"));
    const { user, view } = await openBoundary(f);
    await chooseBoundary(user, "LogBoundary · customer.logs");
    await user.click(screen.getByRole("button", { name: "确认变更" }));
    await screen.findByRole("button", { name: "登录控制台" });
    expect(screen.queryByRole("region", { name: "权限边界" })).toBeNull();
    expect(view.container.textContent).not.toContain(credential);
    expect(JSON.stringify([Object.entries(localStorage), Object.entries(sessionStorage)])).not.toContain(credential);
    expect(JSON.stringify([Object.entries(localStorage), Object.entries(sessionStorage)])).not.toContain("customer.logs");
  });

  it("does not offer boundary mutations when both authoritative capabilities are unavailable", async () => {
    const f = boundaryFixture(); f.readOnly();
    await openBoundary(f);
    expect(screen.queryByRole("button", { name: "修改权限边界" })).toBeNull();
    expect(screen.getByText(/当前身份没有此用户的边界变更权限/)).toBeTruthy();
    expect(f.boundaries.set).not.toHaveBeenCalled();
    expect(f.boundaries.remove).not.toHaveBeenCalled();
  });
  it("keeps owner identity separate from child targets and never infers identity type from policy names", () => {
    const namedAdministrator = { ...tenantPolicy, id: "customer.administrator", management: "CUSTOMER" as const, accountId: "tenant-a", displayName: "TenantAdministrator" };
    const adminAttachment = attachment("child-a", namedAdministrator);
    const adminChild: UserAccess = { ...child, policyAttachments: [adminAttachment], capabilities: userCapabilities(child.user, [adminAttachment]) };
    const tenantDirectory = { ...directory(false), items: [namedAdministrator, tenantPolicy].sort((left, right) => left.id.localeCompare(right.id)) };
    const scene = buildAccountAccessScene(identity, { items: [adminChild], nextAfter: null }, null, tenantDirectory, directory(true));
    expect(scene.accountOwner).toMatchObject({ id: "primary-a", accountType: "primary", name: "Account owner", state: "active" });
    expect(scene.users).toHaveLength(1);
    expect(scene.users[0]).toMatchObject({ id: "child-a", accountType: "subuser", attachments: [{ policyId: "customer.administrator" }] });
    const actingChild: AccountIdentity = { ...identity, user: child.user, identityKind: "USER", permissionBoundary: { accountId: account.id, userId: child.user.id, resourceVersion: child.user.resourceVersion, policy: null }, policySources: child.policyAttachments.map((attachment) => ({ kind: "DIRECT" as const, attachment })), capabilities: currentCapabilities(false) };
    const selfProtected: UserAccess = { ...child, capabilities: userCapabilities(child.user, child.policyAttachments, "SELF_PROTECTED") };
    const pageWithoutOwner = buildAccountAccessScene(actingChild, { items: [selfProtected], nextAfter: "later" }, null, directory(false), null);
    expect(pageWithoutOwner.accountOwner).toMatchObject({ id: "primary-a", loginName: "admin", name: null, state: null, isCurrent: false });
    expect(pageWithoutOwner.accountOwner.name).not.toBe(actingChild.user.displayName);
    expect(pageWithoutOwner.users[0]?.protected).toBe(true);
  });

  it("shows a read-only resource owner with separate identity, access and permission details", async () => {
    const { user, repository } = await openAccess();
    const owner = within(await screen.findByRole("region", { name: "账号所有者" }));
    expect(owner.getByText("主账号")).toBeTruthy();
    expect(owner.getByText("账号所有者")).toBeTruthy();
    expect(owner.getByText("账号管理与恢复权能")).toBeTruthy();
    expect(owner.queryByText("未授权")).toBeNull();
    expect(owner.queryByRole("button", { name: "管理 admin" })).toBeNull();
    await user.click(owner.getByRole("button", { name: "查看用户 admin" }));
    expect(await screen.findByRole("heading", { name: "admin" })).toBeTruthy();
    expect(screen.getByRole("tab", { name: "身份信息" }).getAttribute("aria-selected")).toBe("true");
    expect(screen.getByText("primary-a")).toBeTruthy();
    await user.click(screen.getByRole("tab", { name: "权限策略" }));
    expect(screen.getByText(/具体业务资源操作取决于产品能力和当前安全条件/)).toBeTruthy();
    for (const name of ["禁用用户", "授予角色", "删除", "重置密码", "关联策略"]) expect(screen.queryByRole("button", { name })).toBeNull();
    await user.click(screen.getByRole("tab", { name: "访问方式" }));
    expect(screen.getByText(/当前页面不提供主账号密钥创建或密码重置/)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Switch language" }));
    expect(screen.getByRole("tab", { name: "Access methods" }).getAttribute("aria-selected")).toBe("true");
    expect(repository.execute).not.toHaveBeenCalled();
  });

  it("filters subusers without hiding the separately projected account owner", async () => {
    const adminChild: UserAccess = child;
    const ungrantedUser: User = { ...child.user, id: "ungranted", loginName: "new.user" };
    const ungranted: UserAccess = { user: ungrantedUser, policyAttachments: [], capabilities: userCapabilities(ungrantedUser) };
    const { user } = await openAccess(accounts({ listUsers: vi.fn().mockResolvedValue({ items: [adminChild, ungranted], nextAfter: null }) }));
    const admin = within((await screen.findByRole("button", { name: "查看用户 developer" })).closest("tr")!);
    expect(admin.getByText("IAM 子用户")).toBeTruthy();
    expect(admin.getByText("ReadOnlyAccess")).toBeTruthy();
    expect(admin.queryByText("主账号")).toBeNull();
    const userTable = screen.getByRole("table", { name: "租户用户列表" });
    expect(userTable.getAttribute("data-mobile-layout")).toBe("stack");
    expect(admin.getByText("ReadOnlyAccess").closest("td")?.getAttribute("data-label")).toBe("直接关联策略");
    expect(admin.getByText("控制台访问").closest("td")?.getAttribute("data-label")).toBe("访问方式");
    await user.click(screen.getByRole("button", { name: "筛选" }));
    await user.click(screen.getByRole("combobox", { name: "筛选策略来源" }));
    await user.click(screen.getByRole("option", { name: "无直接关联策略" }));
    expect(screen.getByRole("button", { name: "查看用户 new.user" })).toBeTruthy();
    expect(within(screen.getByRole("region", { name: "账号所有者" })).getByRole("button", { name: "查看用户 admin" })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "清除筛选" }));
    expect(within(screen.getByRole("table", { name: "租户用户列表" })).getAllByRole("row")).toHaveLength(3);
  });

  it("never calls a group-inherited user ungranted when the direct attachment list is empty", async () => {
    const member: AccountIdentity = { ...identity, user: childUser, identityKind: "USER",
      permissionBoundary: { accountId: account.id, userId: childUser.id, resourceVersion: childUser.resourceVersion, policy: null },
      policySources: [{ kind: "GROUP", attachment: { ...attachment("child-a", tenantPolicy), scope: "TENANT", installationId: null, target: { kind: "GROUP", id: "group-operations" } },
        membership: { id: "membership-group-child", accountId: account.id, groupId: "group-operations", userId: childUser.id, createdBy: rootUser.id, resourceVersion: 1, createdAt: timestamp, updatedAt: timestamp } }] };
    const withoutDirect: UserAccess = { ...child, policyAttachments: [], capabilities: userCapabilities(childUser) };
    const repository = accounts({ currentIdentity: vi.fn().mockResolvedValue(member), listUsers: vi.fn().mockResolvedValue({ items: [withoutDirect], nextAfter: null }) });
    const { user } = await openAccess(repository, iam({}, childUser.id));
    const table = await screen.findByRole("table", { name: "租户用户列表" });
    expect(within(table).getByText("无直接关联策略")).toBeTruthy();
    expect(screen.queryByText("未授权", { exact: true })).toBeNull();
    expect(screen.getByText(/用户仍可能通过用户组继承权限/)).toBeTruthy();
    await user.click(screen.getByTestId("nav-overview"));
    expect(await screen.findByText("无直接策略的子用户")).toBeTruthy();
    expect(screen.getByText(/group-operations/)).toBeTruthy();
    expect(screen.queryByText("未授权", { exact: true })).toBeNull();
    expect(repository.getUser).not.toHaveBeenCalled();
    expect(repository.listUsers).toHaveBeenCalledTimes(1);
    expect(repository.execute).not.toHaveBeenCalled();
  });

  it.each((["users", "accounts", "tenantPolicies", "platformPolicies"] as const).flatMap((kind) =>
    (["503", "protocol"] as const).map((failure) => ({ kind, failure }))
  ))("isolates the $kind directory's $failure without hiding independent access analysis", async ({ kind, failure }) => {
    const unavailable = failure === "503" ? new HttpProblem(503, "PRIVATE_DIRECTORY_DIAGNOSTIC") : new Error("INVALID_IAM_RESPONSE");
    const analysis = liveAnalysis();
    const repository = accounts({
      listUsers: kind === "users" ? vi.fn().mockRejectedValue(unavailable) : vi.fn().mockResolvedValue({ items: [child], nextAfter: null }),
      listAccounts: kind === "accounts" ? vi.fn().mockRejectedValue(unavailable) : vi.fn().mockResolvedValue({ items: [accountAccess(account)], nextAfter: null }),
      listPolicies: vi.fn(async (_credential: string, platform: boolean) => {
        if (kind === (platform ? "platformPolicies" : "tenantPolicies")) throw unavailable;
        return directory(platform);
      }),
      accessAnalysis: analysis
    });
    await openAccess(repository, iam(), "access-analysis");
    await waitFor(() => expect(analysis.listAnalyzers).toHaveBeenCalledExactlyOnceWith(credential, account.id, undefined));
    expect(screen.getByRole("heading", { name: "访问分析" })).toBeTruthy();
    expect(screen.queryByText(/PRIVATE_DIRECTORY_DIAGNOSTIC|INVALID_IAM_RESPONSE/)).toBeNull();
    expect(repository.currentIdentity).toHaveBeenCalledTimes(1);
    expect(repository.listUsers).toHaveBeenCalledTimes(1);
    expect(repository.listAccounts).toHaveBeenCalledTimes(1);
    expect(repository.listPolicies).toHaveBeenCalledTimes(2);
    expect(repository.getUser).not.toHaveBeenCalled();
    expect(repository.execute).not.toHaveBeenCalled();
  });

  it("shows a failed user read rather than an empty table and retries only that directory", async () => {
    const repository = accounts({ listUsers: vi.fn().mockRejectedValueOnce(new HttpProblem(503, "IAM_UNAVAILABLE"))
      .mockResolvedValue({ items: [child], nextAfter: null }) });
    const { user } = await openAccess(repository);
    expect(await screen.findByText("用户目录暂时不可用")).toBeTruthy();
    expect(screen.queryByRole("table", { name: "租户用户列表" })).toBeNull();
    expect(screen.queryByRole("button", { name: "查看用户 developer" })).toBeNull();
    await user.click(screen.getByRole("button", { name: "重试读取目录" }));
    expect(await screen.findByRole("button", { name: "查看用户 developer" })).toBeTruthy();
    expect(repository.listUsers).toHaveBeenCalledTimes(2);
    expect(repository.currentIdentity).toHaveBeenCalledTimes(1);
    expect(repository.listAccounts).toHaveBeenCalledTimes(1);
    expect(repository.listPolicies).toHaveBeenCalledTimes(2);
    expect(repository.getUser).not.toHaveBeenCalled();
    expect(repository.execute).not.toHaveBeenCalled();
  });

  it("does not re-read an already mounted Analyzer when an unrelated directory recovers", async () => {
    const analysis = liveAnalysis();
    const repository = accounts({ accessAnalysis: analysis, listUsers: vi.fn()
      .mockRejectedValueOnce(new HttpProblem(503, "IAM_UNAVAILABLE")).mockResolvedValue({ items: [child], nextAfter: null }) });
    const user = await openDirectoryGuard(repository, "access-analysis");
    await waitFor(() => expect(analysis.listAnalyzers).toHaveBeenCalledTimes(1));
    await user.click(screen.getByRole("button", { name: "retry-user-directory" }));
    await waitFor(() => expect(repository.listUsers).toHaveBeenCalledTimes(2));
    await waitFor(() => expect(screen.getByRole("button", { name: "retry-user-directory" })).toHaveProperty("disabled", false));
    expect(analysis.listAnalyzers).toHaveBeenCalledTimes(1);
    expect(repository.currentIdentity).toHaveBeenCalledTimes(1);
    expect(repository.listPolicies).toHaveBeenCalledTimes(2);
    expect(repository.execute).not.toHaveBeenCalled();
  });

  it("freezes Analyzer writes while rechecking the same Session and rereads exact authority after success", async () => {
    const liveAnalyzer = {
      id: "analyzer-unused", accountId: account.id, type: "UNUSED_ACCESS" as const, status: "ACTIVE" as const,
      unusedAccessAgeDays: 90, disposition: { mode: "REVIEW_ONLY" as const, findingDelayDays: 0 },
      resourceVersion: 1, createdAt: timestamp, updatedAt: timestamp
    };
    const writable = { analyzer: liveAnalyzer, capabilities: [
      capability("iam.access-analyzer.update", "ACCESS_ANALYZER", liveAnalyzer.id)
    ] };
    const revoked = { analyzer: liveAnalyzer, capabilities: [{
      ...capability("iam.access-analyzer.update", "ACCESS_ANALYZER", liveAnalyzer.id),
      available: false, restrictionReason: "AUTHORITY_REQUIRED" as const
    }] };
    let finishRefresh!: (value: AccountIdentity) => void;
    const pendingRefresh = new Promise<AccountIdentity>((resolve) => { finishRefresh = resolve; });
    const currentIdentity = vi.fn()
      .mockResolvedValueOnce(structuredClone(identity))
      .mockReturnValueOnce(pendingRefresh);
    const updateAnalyzer = vi.fn();
    const analysis = liveAnalysis();
    let finishExactRefresh!: (value: typeof revoked) => void;
    const pendingExactRefresh = new Promise<typeof revoked>((resolve) => { finishExactRefresh = resolve; });
    analysis.listAnalyzers = vi.fn().mockResolvedValue({ accountId: account.id, items: [liveAnalyzer], nextAfter: null });
    analysis.readAnalyzer = vi.fn().mockResolvedValueOnce(writable).mockReturnValueOnce(pendingExactRefresh);
    analysis.updateAnalyzer = updateAnalyzer;
    const repository = accounts({ currentIdentity, accessAnalysis: analysis });
    const { user } = await openAccess(repository, iam(), "access-analysis");

    await user.click(await screen.findByRole("tab", { name: "分析规则" }));
    const window = screen.getByRole("spinbutton", { name: "完整观测窗口" });
    await user.clear(window);
    await user.type(window, "30");
    expect(screen.getByRole("button", { name: "保存分析规则" })).toHaveProperty("disabled", false);

    await user.click(screen.getByRole("button", { name: "recheck-test-authority" }));
    await waitFor(() => expect(currentIdentity).toHaveBeenCalledTimes(2));
    expect(screen.getByRole("heading", { name: "访问分析" })).toBeTruthy();
    expect((screen.getByRole("spinbutton", { name: "完整观测窗口" }) as HTMLInputElement).value).toBe("30");
    expect(screen.getByRole("button", { name: "保存分析规则" })).toHaveProperty("disabled", true);
    await user.click(screen.getByRole("button", { name: "保存分析规则" }));
    expect(updateAnalyzer).not.toHaveBeenCalled();

    await act(async () => { finishRefresh(structuredClone(identity)); await pendingRefresh; });
    await waitFor(() => expect(analysis.readAnalyzer).toHaveBeenCalledTimes(2));
    expect(screen.getByRole("button", { name: "保存分析规则" })).toHaveProperty("disabled", true);
    await user.click(screen.getByRole("button", { name: "保存分析规则" }));
    expect(updateAnalyzer).not.toHaveBeenCalled();
    await act(async () => { finishExactRefresh(revoked); await pendingExactRefresh; });
    expect(analysis.listAnalyzers).toHaveBeenCalledTimes(2);
    expect(screen.getByRole("tab", { name: "分析规则" }).getAttribute("data-state")).toBe("active");
    expect((screen.getByRole("spinbutton", { name: "完整观测窗口" }) as HTMLInputElement).value).toBe("30");
    expect(screen.getByRole("button", { name: "保存分析规则" })).toHaveProperty("disabled", true);
    expect(updateAnalyzer).not.toHaveBeenCalled();
  });

  it("rereads the current exact Policy after an explicit same-session authority refresh", async () => {
    let finishRefresh!: (value: AccountIdentity) => void;
    const pendingRefresh = new Promise<AccountIdentity>((resolve) => { finishRefresh = resolve; });
    const currentIdentity = vi.fn().mockResolvedValueOnce(structuredClone(identity)).mockReturnValueOnce(pendingRefresh);
    let finishPolicy!: (value: AccountPolicyAccess) => void;
    const pendingPolicy = new Promise<AccountPolicyAccess>((resolve) => { finishPolicy = resolve; });
    const readPolicy = vi.fn().mockResolvedValueOnce(policyAccess(tenantPolicyDetail)).mockReturnValueOnce(pendingPolicy);
    const repository = accounts({ currentIdentity, readPolicy });
    const { user } = await openAccess(repository, iam(), "policies", credential, tenantPolicy.id);
    await waitFor(() => expect(readPolicy).toHaveBeenCalledTimes(1));
    expect(screen.getByRole("heading", { name: tenantPolicy.displayName })).toBeTruthy();

    await user.click(screen.getByRole("button", { name: "recheck-test-authority" }));
    await waitFor(() => expect(currentIdentity).toHaveBeenCalledTimes(2));
    expect(screen.getByRole("heading", { name: tenantPolicy.displayName })).toBeTruthy();
    await act(async () => { finishRefresh(structuredClone(identity)); await pendingRefresh; });
    await waitFor(() => expect(readPolicy).toHaveBeenCalledTimes(2));
    expect(screen.getByRole("heading", { name: tenantPolicy.displayName })).toBeTruthy();
    await act(async () => { finishPolicy({ detail: tenantPolicyDetail, capabilities: [] }); await pendingPolicy; });
    expect(readPolicy).toHaveBeenLastCalledWith(credential, account.id, tenantPolicy.id);
  });

  it("keeps a reviewed Policy rename frozen through identity and exact-target reauthorization, then enables only the current exact capability", async () => {
    enablePolicyLocks();
    const fixture = livePolicyMetadata();
    const initial = await fixture.readPolicy(credential, account.id, "customer.logs");
    fixture.readPolicy.mockReset();
    let finishIdentity!: (value: AccountIdentity) => void;
    const pendingIdentity = new Promise<AccountIdentity>((resolve) => { finishIdentity = resolve; });
    fixture.repository.currentIdentity = vi.fn().mockResolvedValueOnce(structuredClone(identity)).mockReturnValueOnce(pendingIdentity);
    let finishExact!: (value: AccountPolicyAccess) => void;
    const pendingExact = new Promise<AccountPolicyAccess>((resolve) => { finishExact = resolve; });
    fixture.readPolicy.mockResolvedValueOnce(initial).mockReturnValueOnce(pendingExact);
    const { user } = await openAccess(fixture.repository, iam(), "policies");
    await user.click(await screen.findByRole("button", { name: "LogBoundary" }));
    await invokeMoreAction(user, "修改显示名");
    fireEvent.change(screen.getByRole("textbox", { name: "新显示名" }), { target: { value: "Refresh-safe name" } });
    await user.click(screen.getByRole("button", { name: "审阅修改" }));
    const confirm = screen.getByRole("button", { name: "确认修改显示名" });
    expect(confirm).toHaveProperty("disabled", false);

    await user.click(screen.getByRole("button", { name: "recheck-test-authority" }));
    await waitFor(() => expect(fixture.repository.currentIdentity).toHaveBeenCalledTimes(2));
    expect(screen.getByRole("group", { name: "审阅显示名修改 · LogBoundary" })).toBeTruthy();
    expect(screen.getByText("Refresh-safe name")).toBeTruthy();
    expect(confirm).toHaveProperty("disabled", true);
    await act(async () => { finishIdentity(structuredClone(identity)); await pendingIdentity; });
    await waitFor(() => expect(fixture.readPolicy).toHaveBeenCalledTimes(2));
    expect(confirm).toHaveProperty("disabled", true);
    await act(async () => { finishExact(initial); await pendingExact; });
    await waitFor(() => expect(confirm).toHaveProperty("disabled", false));
    await user.click(confirm);
    await waitFor(() => expect(fixture.updatePolicy).toHaveBeenCalledTimes(1));
  });

  it.each(["revoked", "failed"] as const)("preserves a reviewed Policy rename but blocks it when the fresh exact read is %s", async (outcome) => {
    enablePolicyLocks();
    const fixture = livePolicyMetadata();
    const initial = await fixture.readPolicy(credential, account.id, "customer.logs");
    fixture.readPolicy.mockReset();
    fixture.repository.currentIdentity = vi.fn().mockResolvedValue(structuredClone(identity));
    fixture.readPolicy.mockResolvedValueOnce(initial);
    if (outcome === "revoked") fixture.readPolicy.mockResolvedValueOnce({ detail: initial.detail, capabilities: initial.capabilities.map((item) =>
      item.action === "iam.policy.update" ? { ...item, available: false, restrictionReason: "AUTHORITY_REQUIRED" as const } : item) });
    else fixture.readPolicy.mockRejectedValueOnce(new HttpProblem(503, "IAM_UNAVAILABLE"));
    const { user } = await openAccess(fixture.repository, iam(), "policies");
    await user.click(await screen.findByRole("button", { name: "LogBoundary" }));
    await invokeMoreAction(user, "修改显示名");
    fireEvent.change(screen.getByRole("textbox", { name: "新显示名" }), { target: { value: "Still local" } });
    await user.click(screen.getByRole("button", { name: "审阅修改" }));
    await user.click(screen.getByRole("button", { name: "recheck-test-authority" }));
    await waitFor(() => expect(fixture.readPolicy).toHaveBeenCalledTimes(2));
    const group = screen.getByRole("group", { name: "审阅显示名修改 · LogBoundary" });
    expect(within(group).getByText("Still local")).toBeTruthy();
    expect(within(group).getByRole("button", { name: "确认修改显示名" })).toHaveProperty("disabled", true);
    expect(fixture.updatePolicy).not.toHaveBeenCalled();
  });

  it("keeps a reviewed policy draft visible but blocks creation until permission recheck completes", async () => {
    let finishRefresh!: (value: AccountIdentity) => void;
    const pendingRefresh = new Promise<AccountIdentity>((resolve) => { finishRefresh = resolve; });
    const currentIdentity = vi.fn()
      .mockResolvedValueOnce(structuredClone(identity))
      .mockReturnValueOnce(pendingRefresh);
    const createPolicy = vi.fn().mockResolvedValue(tenantPolicyDetail);
    const repository = accounts({ currentIdentity, createPolicy });
    const { user } = await openAccess(repository, iam(), "policies");
    await user.click(await screen.findByRole("button", { name: "新建自定义策略" }));
    fireEvent.change(screen.getByRole("textbox", { name: "策略名称" }), { target: { value: "Refresh-safe policy" } });
    fireEvent.change(screen.getByRole("textbox", { name: "策略声明 JSON" }), { target: { value: JSON.stringify(tenantPolicyDetail.version.document) } });
    await user.click(screen.getByRole("button", { name: "审阅策略" }));
    expect(screen.getByRole("heading", { name: "审阅新策略" })).toBeTruthy();

    await user.click(screen.getByRole("button", { name: "recheck-test-authority" }));
    await waitFor(() => expect(currentIdentity).toHaveBeenCalledTimes(2));
    expect(screen.getByRole("heading", { name: "审阅新策略" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "确认创建" })).toHaveProperty("disabled", true);
    await user.click(screen.getByRole("button", { name: "确认创建" }));
    expect(createPolicy).not.toHaveBeenCalled();

    await act(async () => { finishRefresh(structuredClone(identity)); await pendingRefresh; });
    await waitFor(() => expect(screen.getByRole("button", { name: "确认创建" })).toHaveProperty("disabled", false));
    expect(screen.getByRole("heading", { name: "审阅新策略" })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "确认创建" }));
    await waitFor(() => expect(createPolicy).toHaveBeenCalledTimes(1));
  });

  it.each(["503", "protocol"])("clears old User rows and exact-target command snapshots after a fresh %s directory failure", async (failure) => {
    const unavailable = failure === "503" ? new HttpProblem(503, "IAM_UNAVAILABLE") : new Error("INVALID_IAM_RESPONSE");
    const repository = accounts({ listUsers: vi.fn().mockResolvedValueOnce({ items: [child], nextAfter: "next-user-page" }).mockRejectedValue(unavailable) });
    const user = await openDirectoryGuard(repository, "users");
    await screen.findByRole("button", { name: "查看用户 developer" });
    await user.click(screen.getByRole("button", { name: "read-exact-user" }));
    await waitFor(() => expect(screen.getByLabelText("exact-user-ready").textContent).toBe("true"));
    expect(screen.getByLabelText("exact-user-initially-admitted").textContent).toBe("true");
    await user.click(screen.getByRole("button", { name: "read-next-user-page" }));
    await screen.findByText("用户目录暂时不可用");
    expect(screen.queryByRole("table", { name: "租户用户列表" })).toBeNull();
    expect(screen.queryByRole("button", { name: "查看用户 developer" })).toBeNull();
    await user.click(screen.getByRole("button", { name: "attempt-old-user-command" }));
    await waitFor(() => expect(screen.getByLabelText("old-user-command-result").textContent).toBe("false"));
    expect(repository.userManagement!.submit).not.toHaveBeenCalled();
    expect(repository.getUser).toHaveBeenCalledTimes(1);
    expect(repository.execute).not.toHaveBeenCalled();
  });

  it("does not let a pre-failure exact User read reintroduce capabilities after the directory fails", async () => {
    let finish!: (value: UserAccess) => void;
    const repository = accounts({
      getUser: vi.fn(() => new Promise<UserAccess>((resolve) => { finish = resolve; })),
      listUsers: vi.fn().mockResolvedValueOnce({ items: [child], nextAfter: "next-user-page" }).mockRejectedValue(new HttpProblem(503, "IAM_UNAVAILABLE"))
    });
    const user = await openDirectoryGuard(repository, "users");
    await screen.findByRole("button", { name: "查看用户 developer" });
    await user.click(screen.getByRole("button", { name: "read-exact-user" }));
    await waitFor(() => expect(repository.getUser).toHaveBeenCalledTimes(1));
    await user.click(screen.getByRole("button", { name: "read-next-user-page" }));
    await screen.findByText("用户目录暂时不可用");
    await act(async () => { finish(structuredClone(child)); });
    expect(screen.getByLabelText("exact-user-ready").textContent).toBe("false");
    await user.click(screen.getByRole("button", { name: "attempt-old-user-command" }));
    await waitFor(() => expect(screen.getByLabelText("old-user-command-result").textContent).toBe("false"));
    expect(repository.execute).not.toHaveBeenCalled();
  });

  it.each(["tenantPolicies", "platformPolicies"] as const)("retries the failed %s source without reloading the healthy directory or identity", async (kind: AccountDirectoryKind) => {
    const platformFailure = kind === "platformPolicies";
    let fail = true;
    const listPolicies = vi.fn(async (_credential: string, platform: boolean) => {
      if (platform === platformFailure && fail) throw new HttpProblem(503, "IAM_UNAVAILABLE");
      return directory(platform);
    });
    const repository = accounts({ listPolicies });
    const { user } = await openAccess(repository, iam(), "policies");
    await screen.findByText(platformFailure ? "平台策略目录暂时不可用" : "租户策略目录暂时不可用");
    fail = false;
    await user.click(screen.getByRole("button", { name: "重试读取目录" }));
    await screen.findByText("ReadOnlyAccess", { exact: true });
    expect(listPolicies).toHaveBeenCalledTimes(3);
    expect(listPolicies).toHaveBeenLastCalledWith(credential, platformFailure);
    expect(repository.currentIdentity).toHaveBeenCalledTimes(1);
    expect(repository.listUsers).toHaveBeenCalledTimes(1);
    expect(repository.listAccounts).toHaveBeenCalledTimes(1);
    expect(repository.execute).not.toHaveBeenCalled();
  });

  it("keeps report and personal/account settings entry points independent of unavailable directories", async () => {
    const repository = accounts({ listUsers: vi.fn().mockRejectedValue(new HttpProblem(503, "IAM_UNAVAILABLE")),
      listAccounts: vi.fn().mockRejectedValue(new Error("INVALID_IAM_RESPONSE")),
      listPolicies: vi.fn().mockRejectedValue(new HttpProblem(503, "IAM_UNAVAILABLE")),
      securityReports: { create: vi.fn(), read: vi.fn(), download: vi.fn() } });
    const { user } = await openAccess(repository, iam(), "security-reports");
    expect(await screen.findByRole("button", { name: "生成当前账号安全报告" })).toBeTruthy();
    await user.click(screen.getByTestId("nav-settings"));
    expect(await screen.findByRole("button", { name: "保存别名" })).toBeTruthy();
    expect(repository.currentIdentity).toHaveBeenCalledTimes(1);
    expect(repository.securityReports?.create).not.toHaveBeenCalled();
    expect(repository.execute).not.toHaveBeenCalled();
  });

  it.each(["503", "protocol"])("keeps a mandatory identity %s failure global and starts no optional reads", async (failure) => {
    const analysis = liveAnalysis();
    const repository = accounts({ currentIdentity: vi.fn().mockRejectedValue(failure === "503" ? new HttpProblem(503, "PRIVATE_IDENTITY_DIAGNOSTIC") : new Error("INVALID_IAM_IDENTITY")), accessAnalysis: analysis });
    await openAccess(repository, iam(), "access-analysis");
    await screen.findByRole("alert");
    expect(repository.listUsers).not.toHaveBeenCalled();
    expect(repository.listAccounts).not.toHaveBeenCalled();
    expect(repository.listPolicies).not.toHaveBeenCalled();
    expect(analysis.listAnalyzers).not.toHaveBeenCalled();
    expect(screen.queryByText(/PRIVATE_IDENTITY_DIAGNOSTIC|INVALID_IAM_IDENTITY/)).toBeNull();
    expect(repository.execute).not.toHaveBeenCalled();
  });

  it("keeps exact User and boundary facts readable when their optional fresh policy directory fails", async () => {
    const fixture = boundaryFixture();
    const read = fixture.repository.listPolicies;
    let tenantReads = 0;
    fixture.repository.listPolicies = vi.fn(async (credential: string, platform: boolean) => {
      if (!platform && ++tenantReads > 1) throw new HttpProblem(503, "IAM_UNAVAILABLE");
      return read(credential, platform);
    });
    await openBoundary(fixture);
    expect(await screen.findByText("用户资料")).toBeTruthy();
    expect(screen.queryByText("对象不可用")).toBeNull();
    expect(fixture.repository.getUser).toHaveBeenCalledTimes(1);
    expect(fixture.boundaries.read).toHaveBeenCalledTimes(1);
    expect(fixture.repository.execute).not.toHaveBeenCalled();
  });

  it("labels missing access switches as unreported instead of claiming login and API access are not integrated", () => {
    const scene = buildAccountAccessScene(identity, { items: [child], nextAfter: null }, null, directory(false), directory(true));
    render(<LocaleProvider><AccountUserAccessMethods user={scene.users[0]!} workspace={null} /></LocaleProvider>);
    expect(screen.getAllByText("开关状态未提供")).toHaveLength(2);
    expect(screen.queryByText("当前未接入")).toBeNull();
    expect(document.querySelectorAll("[data-enabled]")).toHaveLength(0);
  });

  it("keeps navigation out of mutation renders and preserves unrelated exact capabilities", async () => {
    let finish!: () => void;
    const repository = accounts({ execute: vi.fn(() => new Promise<void>((resolve) => { finish = resolve; })) });
    const { user } = await openAccess(repository, iam(), "settings");
    await screen.findByRole("button", { name: "保存别名" });
    await user.type(screen.getByLabelText(/^主账号别名/), "acme");
    expect(screen.getByTestId("can-manage").textContent).toBe("true");
    capabilityCommit.mockClear();
    await user.click(screen.getByRole("button", { name: "保存别名" }));
    expect(screen.getByRole("button", { name: "正在保存…" })).toBeTruthy();
    expect(capabilityCommit).not.toHaveBeenCalled();
    vi.mocked(repository.listUsers).mockRejectedValue(new HttpProblem(403, "FORBIDDEN"));
    await act(async () => { finish(); });
    await waitFor(() => expect(screen.getByTestId("can-manage").textContent).toBe("false"));
    expect(screen.getByTestId("can-read-accounts").textContent).toBe("true");
    expect(capabilityCommit).toHaveBeenCalled();
    expect(screen.getByRole("button", { name: "保存别名" })).toBeTruthy();
  });

  it("loads the real current-account MFA rule only in settings and keeps read denial local", async () => {
    const read = vi.fn().mockRejectedValue(new HttpProblem(403, "IAM_AUTHORIZATION_DENIED"));
    const repository = accounts({ accountSecuritySettings: { read } });
    const { user } = await openAccess(repository, iam(), "users");
    await screen.findByRole("table", { name: "租户用户列表" });
    expect(read).not.toHaveBeenCalled();
    await user.click(screen.getByTestId("nav-settings"));
    expect(await screen.findByText(/没有查看账号安全规则的权限/)).toBeTruthy();
    expect(read).toHaveBeenCalledWith(credential, account.id);
    expect(screen.getByTestId("nav-settings").getAttribute("aria-current")).toBe("page");
    expect(screen.queryByText("用户可选")).toBeNull();
  });

  it("keeps security-settings read and update authority independent", async () => {
    const update = { startStepUp: vi.fn(), stepUpByRequest: vi.fn(), verifyStepUp: vi.fn(), apply: vi.fn(), changeByRequest: vi.fn() };
    const readDeniedIdentity = structuredClone(identity);
    readDeniedIdentity.capabilities = readDeniedIdentity.capabilities.map((item) => item.action === "iam.security-settings.read"
      ? { ...item, available: false, restrictionReason: "AUTHORITY_REQUIRED" as const } : item);
    const deniedRead = vi.fn().mockResolvedValue(accountSecuritySettings);
    await openAccess(accounts({ currentIdentity: vi.fn().mockResolvedValue(readDeniedIdentity),
      accountSecuritySettings: { read: deniedRead, update } }), iam(), "settings");
    expect(await screen.findByText(/没有查看账号安全规则的权限/)).toBeTruthy();
    expect(deniedRead).not.toHaveBeenCalled();
    expect(update.startStepUp).not.toHaveBeenCalled();
    cleanup();

    const updateDeniedIdentity = structuredClone(identity);
    updateDeniedIdentity.capabilities = updateDeniedIdentity.capabilities.map((item) => item.action === "iam.security-settings.update"
      ? { ...item, available: false, restrictionReason: "AUTHORITY_REQUIRED" as const } : item);
    const readable = vi.fn().mockResolvedValue(accountSecuritySettings);
    await openAccess(accounts({ currentIdentity: vi.fn().mockResolvedValue(updateDeniedIdentity),
      accountSecuritySettings: { read: readable, update } }), iam(), "settings");
    expect(await screen.findByText(/可以查看账号安全规则，但不能修改/)).toBeTruthy();
    expect(readable).toHaveBeenCalledWith(credential, account.id);
    expect(screen.queryByRole("button", { name: "编辑安全规则" })).toBeNull();
    expect(update.startStepUp).not.toHaveBeenCalled();
  });

  it("expires the credential on a real account-rule 401 instead of treating it as read denial", async () => {
    const read = vi.fn().mockRejectedValue(new HttpProblem(401, "IAM_SESSION_EXPIRED"));
    await openAccess(accounts({ accountSecuritySettings: { read } }), iam(), "settings");
    expect(await screen.findByRole("button", { name: "登录控制台" })).toBeTruthy();
    expect(screen.queryByText(/没有查看账号安全规则的权限/)).toBeNull();
  });

  it.each(["mfa", "password", "password-lowercase", "password-uppercase", "password-digit", "password-symbol", "password-history", "password-age", "password-expiry", "session", "network"])("starts one frozen full-settings proof for an independent %s change without requiring a network delta", async (field) => {
    const proposed: SecuritySettingsUpdateIntent = { expectedResourceVersion: 4, mfa: structuredClone(accountSecuritySettings.mfa),
      password: structuredClone(accountSecuritySettings.password), session: structuredClone(accountSecuritySettings.session), accessKeyNetwork: { allowedSourceCidrs: [] } };
    if (field === "mfa") proposed.mfa.requiredForUsers = false;
    if (field === "password") proposed.password.minimumLength = 21;
    if (field === "password-lowercase") proposed.password.requireLowercase = !proposed.password.requireLowercase;
    if (field === "password-uppercase") proposed.password.requireUppercase = !proposed.password.requireUppercase;
    if (field === "password-digit") proposed.password.requireDigit = !proposed.password.requireDigit;
    if (field === "password-symbol") proposed.password.requireSymbol = !proposed.password.requireSymbol;
    if (field === "password-history") proposed.password.historyCount += 1;
    if (field === "password-age") proposed.password.maxAgeDays = 0;
    if (field === "password-expiry") proposed.password.expiryMode = "ADMIN_RESET";
    if (field === "session") proposed.session.idleTimeoutMinutes = 20;
    if (field === "network") proposed.accessKeyNetwork.allowedSourceCidrs = ["10.0.0.0/8"];
    const expected = structuredClone(proposed);
    const startStepUp = vi.fn(async (_credential: string, command: { requestId: string; expectedFactorRevision: number; intent: SecuritySettingsUpdateIntent }): Promise<SecurityStepUp> => ({
      id: "step-up-full-settings", requestId: command.requestId, operation: "SECURITY_SETTINGS_UPDATE", expectedFactorRevision: command.expectedFactorRevision,
      securitySettings: structuredClone(command.intent), state: "PENDING", createdAt: timestamp, expiresAt: "2026-09-11T08:02:00Z", provedAt: null, consumedAt: null
    }));
    const update = { startStepUp, stepUpByRequest: vi.fn(), verifyStepUp: vi.fn(), apply: vi.fn(), changeByRequest: vi.fn() };
    const repository = accounts({ accountSecuritySettings: { read: vi.fn().mockResolvedValue(accountSecuritySettings), update } });
    const user = userEvent.setup({ delay: null });
    render(<LocaleProvider><SessionProvider repository={iam()}><AccountAccessProvider repository={repository}><SecuritySettingsIntentProbe proposed={proposed} /></AccountAccessProvider></SessionProvider></LocaleProvider>);
    await user.click(screen.getByRole("button", { name: "login-settings-probe" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "begin-settings" }).hasAttribute("disabled")).toBe(false));
    await user.click(screen.getByRole("button", { name: "begin-settings" }));
    await waitFor(() => expect(screen.getByLabelText("settings-intent").textContent).toMatch(/^PENDING:/));
    proposed.password.minimumLength = 30;
    expect(startStepUp).toHaveBeenCalledExactlyOnceWith(credential, { requestId: expect.stringMatching(/^ui-account-security-settings-/), expectedFactorRevision: 7, intent: expected });
    expect(update.apply).not.toHaveBeenCalled();
  });

  it.each(["unchanged", "missing-mfa", "missing-password", "missing-session", "missing-network", "length-low", "length-high", "history-high", "age-high", "expiry", "idle-low", "fraction", "wrong-version", "unsafe-version", "extra-field"])("rejects a %s full-settings target before any step-up or write", async (variant) => {
    const proposed: Record<string, unknown> = { expectedResourceVersion: 4, mfa: structuredClone(accountSecuritySettings.mfa), password: structuredClone(accountSecuritySettings.password),
      session: { idleTimeoutMinutes: variant === "unchanged" ? 30 : 20 }, accessKeyNetwork: { allowedSourceCidrs: [] } };
    if (variant.startsWith("missing-")) delete proposed[variant.slice(8) === "network" ? "accessKeyNetwork" : variant.slice(8)];
    const password = proposed.password as Record<string, unknown>;
    if (variant === "length-low") password.minimumLength = 14;
    if (variant === "length-high") password.minimumLength = 129;
    if (variant === "history-high") password.historyCount = 25;
    if (variant === "age-high") password.maxAgeDays = 366;
    if (variant === "expiry") password.expiryMode = "UNKNOWN";
    if (variant === "idle-low") proposed.session = { idleTimeoutMinutes: 4 };
    if (variant === "fraction") proposed.session = { idleTimeoutMinutes: 20.5 };
    if (variant === "wrong-version") proposed.expectedResourceVersion = 5;
    if (variant === "unsafe-version") proposed.expectedResourceVersion = Number.MAX_SAFE_INTEGER;
    if (variant === "extra-field") proposed.permit = true;
    const update = { startStepUp: vi.fn(), stepUpByRequest: vi.fn(), verifyStepUp: vi.fn(), apply: vi.fn(), changeByRequest: vi.fn() };
    const repository = accounts({ accountSecuritySettings: { read: vi.fn().mockResolvedValue(accountSecuritySettings), update } });
    const user = userEvent.setup({ delay: null });
    render(<LocaleProvider><SessionProvider repository={iam()}><AccountAccessProvider repository={repository}><SecuritySettingsIntentProbe proposed={proposed as unknown as SecuritySettingsUpdateIntent} /></AccountAccessProvider></SessionProvider></LocaleProvider>);
    await user.click(screen.getByRole("button", { name: "login-settings-probe" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "begin-settings" }).hasAttribute("disabled")).toBe(false));
    await user.click(screen.getByRole("button", { name: "begin-settings" }));
    expect(screen.getByLabelText("settings-intent").textContent).toBe("none"); expect(update.startStepUp).not.toHaveBeenCalled(); expect(update.apply).not.toHaveBeenCalled(); expect(sessionStorage.length).toBe(0);
  });

  it("does not commit a late security-settings proof after its provider has unmounted", async () => {
    let release!: (value: SecurityStepUp) => void;
    const startStepUp = vi.fn<(credential: string, command: { requestId: string; expectedFactorRevision: number; intent: SecuritySettingsUpdateIntent }) => Promise<SecurityStepUp>>(() => new Promise<SecurityStepUp>((resolve) => { release = resolve; }));
    const update = { startStepUp, stepUpByRequest: vi.fn(), verifyStepUp: vi.fn(), apply: vi.fn(), changeByRequest: vi.fn() };
    const repository = accounts({ accountSecuritySettings: { read: vi.fn().mockResolvedValue(accountSecuritySettings), update } });
    const user = userEvent.setup({ delay: null });
    const view = render(<LocaleProvider><SessionProvider repository={iam()}><AccountAccessProvider repository={repository}><SecuritySettingsIntentProbe /></AccountAccessProvider></SessionProvider></LocaleProvider>);
    await user.click(screen.getByRole("button", { name: "login-settings-probe" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "begin-settings" }).hasAttribute("disabled")).toBe(false));
    await user.click(screen.getByRole("button", { name: "begin-settings" })); await waitFor(() => expect(startStepUp).toHaveBeenCalledOnce());
    const command = startStepUp.mock.calls[0]![1]; view.unmount();
    await act(async () => { release({ id: "late-step-up", requestId: command.requestId, operation: "SECURITY_SETTINGS_UPDATE",
      expectedFactorRevision: command.expectedFactorRevision, securitySettings: command.intent, state: "PENDING",
      createdAt: timestamp, expiresAt: "2026-09-11T08:02:00Z", provedAt: null, consumedAt: null }); });
    const stored = Array.from({ length: sessionStorage.length }, (_, index) => JSON.parse(sessionStorage.getItem(sessionStorage.key(index)!)!)).find((entry: { requestId?: string }) => entry.requestId === command.requestId);
    expect(stored).toMatchObject({ requestId: command.requestId, state: "STEP_UP_UNKNOWN", stepUp: null, settings: command.intent });
    expect(update.apply).not.toHaveBeenCalled(); expect(update.verifyStepUp).not.toHaveBeenCalled();
  });

  it("persists one frozen full-settings intent, replays the exact step-up, ends the caller Session, and recovers completion after login", async () => {
    const pendingStepUp = (command: { requestId: string; expectedFactorRevision: number; intent: SecuritySettingsUpdateIntent }, state: SecurityStepUp["state"]): SecurityStepUp => ({
      id: "step-up-settings-one", requestId: command.requestId, operation: "SECURITY_SETTINGS_UPDATE",
      expectedFactorRevision: command.expectedFactorRevision, securitySettings: structuredClone(command.intent), state,
      createdAt: timestamp, expiresAt: "2026-09-11T08:05:00Z",
      provedAt: state === "PROVED" || state === "CONSUMED" ? "2026-09-11T08:01:00Z" : null,
      consumedAt: state === "CONSUMED" ? "2026-09-11T08:02:00Z" : null
    });
    const startStepUp = vi.fn()
      .mockRejectedValueOnce(new HttpProblem(503, "IAM_UNAVAILABLE"))
      .mockImplementation(async (_credential, command) => pendingStepUp(command, "PENDING"));
    const verifyStepUp = vi.fn(async (_credential, _stepUpId, _originalRequestId, _expectedFactorRevision, _intent, command) => {
      const original = startStepUp.mock.calls[1]![1];
      expect(command.password).toBe("test-password");
      expect(command.code).toBe("123456");
      return pendingStepUp(original, "PROVED");
    });
    const apply = vi.fn(async (_credential, _accountId, command) => ({ outcome: "APPLIED" as const, change: {
      requestId: command.requestId,
      expectedResourceVersion: command.intent.expectedResourceVersion,
      settings: { ...structuredClone(accountSecuritySettings), resourceVersion: 5, accessKeyNetwork: structuredClone(command.intent.accessKeyNetwork) },
      callerSessionEnded: true as const
    } }));
    const repository = accounts({ accountSecuritySettings: {
      read: vi.fn().mockResolvedValue(structuredClone(accountSecuritySettings)),
      update: {
        startStepUp,
        stepUpByRequest: vi.fn(),
        verifyStepUp,
        apply,
        changeByRequest: vi.fn()
      }
    } });
    const auth = iam();
    const user = userEvent.setup();
    const tree = () => <LocaleProvider><SessionProvider repository={auth}><AccountAccessProvider repository={repository}><SecuritySettingsIntentProbe /></AccountAccessProvider></SessionProvider></LocaleProvider>;

    const first = render(tree());
    await user.click(screen.getByRole("button", { name: "login-settings-probe" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "begin-settings" }).hasAttribute("disabled")).toBe(false));
    await user.click(screen.getByRole("button", { name: "begin-settings" }));
    await waitFor(() => expect(screen.getByLabelText("settings-intent").textContent).toMatch(/^STEP_UP_UNKNOWN:ui-account-security-settings-[0-9a-f]{32}:4:10\.0\.0\.0\/8$/));
    expect(sessionStorage.length).toBe(1);
    const stored = sessionStorage.getItem(sessionStorage.key(0)!);
    expect(stored).not.toContain("test-password");
    first.unmount();

    render(tree());
    await user.click(screen.getByRole("button", { name: "login-settings-probe" }));
    await waitFor(() => expect(screen.getByLabelText("settings-intent").textContent).toContain("STEP_UP_UNKNOWN"));
    await user.click(screen.getByRole("button", { name: "retry-settings-step-up" }));
    await waitFor(() => expect(screen.getByLabelText("settings-intent").textContent).toContain("PENDING"));
    expect(startStepUp).toHaveBeenCalledTimes(2);
    expect(startStepUp.mock.calls[0]![1]).toEqual(startStepUp.mock.calls[1]![1]);
    expect(startStepUp.mock.calls[1]![1].intent).toEqual({
      expectedResourceVersion: 4,
      mfa: accountSecuritySettings.mfa,
      password: accountSecuritySettings.password,
      session: accountSecuritySettings.session,
      accessKeyNetwork: { allowedSourceCidrs: ["10.0.0.0/8"] }
    });

    await user.click(screen.getByRole("button", { name: "verify-settings-step-up" }));
    await waitFor(() => expect(screen.getByLabelText("settings-intent").textContent).toContain("PROVED"));
    expect(JSON.stringify(sessionStorage)).not.toContain("test-password");
    await user.click(screen.getByRole("button", { name: "apply-settings" }));
    await waitFor(() => expect(screen.getByLabelText("settings-probe-session").textContent).toBe("anonymous"));
    expect(screen.getByLabelText("settings-sign-in-notice").textContent).toBe(`SECURITY_SETTINGS_UPDATED:${startStepUp.mock.calls[1]![1].requestId}`);
    expect(apply).toHaveBeenCalledWith(credential, account.id, expect.objectContaining({
      requestId: startStepUp.mock.calls[1]![1].requestId,
      stepUpId: "step-up-settings-one",
      intent: startStepUp.mock.calls[1]![1].intent
    }));

    await user.click(screen.getByRole("button", { name: "login-settings-probe" }));
    await waitFor(() => expect(screen.getByLabelText("settings-intent").textContent).toContain("COMPLETED"));
    await user.click(screen.getByRole("button", { name: "clear-settings" }));
    await waitFor(() => expect(screen.getByLabelText("settings-intent").textContent).toBe("none"));
    expect(sessionStorage.length).toBe(0);
  });

  it("keeps an unknown account-rule PUT locked and resolves only the original request after login", async () => {
    const provedStepUp = (command: { requestId: string; expectedFactorRevision: number; intent: SecuritySettingsUpdateIntent }): SecurityStepUp => ({
      id: "step-up-settings-unknown", requestId: command.requestId, operation: "SECURITY_SETTINGS_UPDATE",
      expectedFactorRevision: command.expectedFactorRevision, securitySettings: structuredClone(command.intent), state: "PROVED",
      createdAt: timestamp, expiresAt: "2026-09-11T08:05:00Z", provedAt: "2026-09-11T08:01:00Z", consumedAt: null
    });
    const startStepUp = vi.fn(async (_credential, command) => ({ ...provedStepUp(command), state: "PENDING" as const, provedAt: null }));
    const verifyStepUp = vi.fn(async () => {
      const original = startStepUp.mock.calls[0]![1];
      return provedStepUp(original);
    });
    const apply = vi.fn().mockRejectedValue(new HttpProblem(503, "IAM_UNAVAILABLE"));
    const completedChange = {
      requestId: "placeholder",
      expectedResourceVersion: accountSecuritySettings.resourceVersion,
      settings: { ...structuredClone(accountSecuritySettings), resourceVersion: 5, accessKeyNetwork: { allowedSourceCidrs: ["10.0.0.0/8"] } },
      callerSessionEnded: true as const
    };
    const changeByRequest = vi.fn()
      .mockRejectedValueOnce(new HttpProblem(404, "IAM_CHANGE_NOT_FOUND"))
      .mockImplementation(async (_credential, _accountId, requestId, intent) => ({ ...completedChange, requestId, expectedResourceVersion: intent.expectedResourceVersion }));
    const repository = accounts({ accountSecuritySettings: {
      read: vi.fn().mockResolvedValue(structuredClone(accountSecuritySettings)),
      update: { startStepUp, stepUpByRequest: vi.fn(), verifyStepUp, apply, changeByRequest }
    } });
    const auth = iam();
    const user = userEvent.setup();
    const tree = () => <LocaleProvider><SessionProvider repository={auth}><AccountAccessProvider repository={repository}><SecuritySettingsIntentProbe /></AccountAccessProvider></SessionProvider></LocaleProvider>;

    render(tree());
    await user.click(screen.getByRole("button", { name: "login-settings-probe" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "begin-settings" }).hasAttribute("disabled")).toBe(false));
    await user.click(screen.getByRole("button", { name: "begin-settings" }));
    await waitFor(() => expect(screen.getByLabelText("settings-intent").textContent).toContain("PENDING"));
    await user.click(screen.getByRole("button", { name: "verify-settings-step-up" }));
    await waitFor(() => expect(screen.getByLabelText("settings-intent").textContent).toContain("PROVED"));
    await user.click(screen.getByRole("button", { name: "apply-settings" }));
    await waitFor(() => expect(screen.getByLabelText("settings-intent").textContent).toContain("APPLY_UNKNOWN"));
    const originalRequestId = startStepUp.mock.calls[0]![1].requestId;
    expect(apply).toHaveBeenCalledTimes(1);
    expect(sessionStorage.getItem(sessionStorage.key(0)!)).toContain(originalRequestId);

    await user.click(screen.getByRole("button", { name: "login-settings-probe" }));
    await waitFor(() => expect(screen.getByLabelText("settings-intent").textContent).toContain("APPLY_UNKNOWN"));
    await user.click(screen.getByRole("button", { name: "inspect-settings" }));
    await waitFor(() => expect(changeByRequest).toHaveBeenCalledTimes(1));
    expect(screen.getByLabelText("settings-intent").textContent).toContain("APPLY_UNKNOWN");
    expect(apply).toHaveBeenCalledTimes(1);

    await user.click(screen.getByRole("button", { name: "inspect-settings" }));
    await waitFor(() => expect(screen.getByLabelText("settings-intent").textContent).toContain("COMPLETED"));
    expect(changeByRequest).toHaveBeenNthCalledWith(2, credential, account.id, originalRequestId, startStepUp.mock.calls[0]![1].intent);
    expect(screen.getByLabelText("settings-probe-session").textContent).toBe("authenticated");
    expect(screen.getByLabelText("settings-sign-in-notice").textContent).toBe("none");
    expect(sessionStorage.getItem(sessionStorage.key(0)!)).toContain('"state":"COMPLETED"');
    expect(apply).toHaveBeenCalledTimes(1);
  });

  it("retains account-rule recovery evidence after update authority is revoked and closes new writes", async () => {
    const revokedIdentity = structuredClone(identity);
    revokedIdentity.capabilities = revokedIdentity.capabilities.map((item) => item.action === "iam.security-settings.update"
      ? { ...item, available: false, restrictionReason: "AUTHORITY_REQUIRED" as const }
      : item);
    const currentIdentity = vi.fn()
      .mockResolvedValueOnce(structuredClone(identity))
      .mockResolvedValue(structuredClone(revokedIdentity));
    const startStepUp = vi.fn(async (_credential: string, command: { requestId: string; expectedFactorRevision: number; intent: SecuritySettingsUpdateIntent }) => ({
      id: "step-up-settings-revoked", requestId: command.requestId, operation: "SECURITY_SETTINGS_UPDATE" as const,
      expectedFactorRevision: command.expectedFactorRevision, securitySettings: structuredClone(command.intent), state: "PENDING" as const,
      createdAt: timestamp, expiresAt: "2026-09-11T08:05:00Z", provedAt: null, consumedAt: null
    }));
    const verifyStepUp = vi.fn(async () => {
      const original = startStepUp.mock.calls[0]![1];
      return {
        id: "step-up-settings-revoked", requestId: original.requestId, operation: "SECURITY_SETTINGS_UPDATE" as const,
        expectedFactorRevision: original.expectedFactorRevision, securitySettings: structuredClone(original.intent), state: "PROVED" as const,
        createdAt: timestamp, expiresAt: "2026-09-11T08:05:00Z", provedAt: "2026-09-11T08:01:00Z", consumedAt: null
      };
    });
    const apply = vi.fn().mockRejectedValue(new HttpProblem(503, "IAM_UNAVAILABLE"));
    const changeByRequest = vi.fn(async (_credential: string, _accountId: string, requestId: string, settings: SecuritySettingsUpdateIntent) => ({
      requestId,
      expectedResourceVersion: settings.expectedResourceVersion,
      settings: { ...structuredClone(accountSecuritySettings), resourceVersion: 5, accessKeyNetwork: structuredClone(settings.accessKeyNetwork) },
      callerSessionEnded: true as const
    }));
    const repository = accounts({
      currentIdentity,
      accountSecuritySettings: {
        read: vi.fn().mockResolvedValue(structuredClone(accountSecuritySettings)),
        update: { startStepUp, stepUpByRequest: vi.fn(), verifyStepUp, apply, changeByRequest }
      }
    });
    const user = userEvent.setup();
    render(<LocaleProvider><SessionProvider repository={iam()}><AccountAccessProvider repository={repository}><SecuritySettingsIntentProbe /></AccountAccessProvider></SessionProvider></LocaleProvider>);
    await user.click(screen.getByRole("button", { name: "login-settings-probe" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "begin-settings" }).hasAttribute("disabled")).toBe(false));
    await user.click(screen.getByRole("button", { name: "begin-settings" }));
    await waitFor(() => expect(screen.getByLabelText("settings-intent").textContent).toContain("PENDING"));
    await user.click(screen.getByRole("button", { name: "verify-settings-step-up" }));
    await waitFor(() => expect(screen.getByLabelText("settings-intent").textContent).toContain("PROVED"));
    await user.click(screen.getByRole("button", { name: "apply-settings" }));
    await waitFor(() => expect(screen.getByLabelText("settings-intent").textContent).toContain("APPLY_UNKNOWN"));

    await user.click(screen.getByRole("button", { name: "reload-settings-access" }));
    await waitFor(() => expect(currentIdentity).toHaveBeenCalledTimes(2));
    await waitFor(() => expect(screen.getByLabelText("settings-can-update").textContent).toBe("false"));
    expect(screen.getByLabelText("settings-intent").textContent).toContain("APPLY_UNKNOWN");
    expect(screen.getByRole("button", { name: "inspect-settings" }).hasAttribute("disabled")).toBe(false);
    expect(apply).toHaveBeenCalledTimes(1);

    await user.click(screen.getByRole("button", { name: "inspect-settings" }));
    await waitFor(() => expect(screen.getByLabelText("settings-intent").textContent).toContain("COMPLETED"));
    await user.click(screen.getByRole("button", { name: "clear-settings" }));
    await waitFor(() => expect(screen.getByLabelText("settings-intent").textContent).toBe("none"));
    expect(screen.getByRole("button", { name: "begin-settings" }).hasAttribute("disabled")).toBe(true);
    expect(apply).toHaveBeenCalledTimes(1);
  });

  it("switches a settings draft and an existing safe error without reloading IAM", async () => {
    const repository = accounts({ execute: vi.fn().mockRejectedValue(new HttpProblem(409, "PRIVATE UPSTREAM DETAIL")) });
    const { user } = await openAccess(repository);
    await screen.findByText("Developer A");
    await user.click(screen.getByTestId("nav-settings"));
    await user.type(screen.getByLabelText("主账号别名", { exact: true }), "team-new");
    await user.click(screen.getByRole("button", { name: "Switch language" }));
    expect(screen.getByTestId("nav-settings").getAttribute("aria-current")).toBe("page");
    expect((screen.getByLabelText("Primary account alias", { exact: true }) as HTMLInputElement).value).toBe("team-new");
    await user.click(screen.getByRole("button", { name: "Save alias" }));
    expect((await screen.findByRole("alert")).textContent).toContain("The name is taken or reserved");
    await user.click(screen.getByRole("button", { name: "Switch language" }));
    expect(screen.getByRole("alert").textContent).toContain("名称已被占用或保留");
    expect(screen.getByRole("alert").textContent).not.toContain("PRIVATE UPSTREAM");
    expect((screen.getByLabelText("主账号别名", { exact: true }) as HTMLInputElement).value).toBe("team-new");
    expect(repository.currentIdentity).toHaveBeenCalledTimes(1);
  });

  it("localizes content-area user management and focuses the new destination", async () => {
    const { user } = await openAccess();
    await screen.findByText("Developer A");
    await user.click(screen.getByRole("button", { name: "Switch language" }));
    const trigger = screen.getByRole("button", { name: "View user developer" });
    await user.click(trigger);
    const heading = await screen.findByRole("heading", { name: "developer" });
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(document.activeElement).toBe(heading);
    const region = screen.getByRole("region", { name: "Identity and access" });
    expect(region.textContent).not.toMatch(/\p{Script=Han}/u);
    expect(within(region).getByRole("button", { name: "Revoke policy ReadOnlyAccess" })).toBeTruthy();
    expect((within(region).getByRole("button", { name: "Review attachment" }) as HTMLButtonElement).disabled).toBe(true);
    await user.click(within(region).getByRole("button", { name: "Reset password" }));
    expect(document.activeElement).toBe(within(region).getByLabelText("Initial password"));
    expect(region.textContent).not.toMatch(/\p{Script=Han}/u);
    await user.click(screen.getByRole("button", { name: "Back to list" }));
    expect(await screen.findByRole("table", { name: "Tenant users" })).toBeTruthy();
    await user.click(screen.getByTestId("nav-roles"));
    expect(screen.getByText("This capability is not connected")).toBeTruthy();
    await user.click(screen.getByTestId("nav-policies"));
    expect(screen.getByRole("table", { name: "Policy metadata directory" })).toBeTruthy();
    await user.click(screen.getByTestId("nav-tenants"));
    expect(screen.getByRole("table", { name: "Tenant accounts" })).toBeTruthy();
  });

  it("opens account lifecycle management from the object name without adding an operation column", async () => {
    const repository = accounts();
    const { user } = await openAccess(repository, iam(), "tenants");
    const table = await screen.findByRole("table", { name: "租户账号列表" });
    expect(table.getAttribute("data-mobile-layout")).toBe("stack");
    const firstRow = within(table).getByRole("row", { name: /Team A/ });
    expect(within(firstRow).getByRole("cell", { name: /Team A/ }).getAttribute("data-label")).toBe("租户");
    expect(within(firstRow).getByRole("cell", { name: "admin" }).getAttribute("data-label")).toBe("主账号登录名");
    expect(within(firstRow).getByRole("cell", { name: "未设置" }).getAttribute("data-label")).toBe("主账号别名");
    expect(within(firstRow).getByRole("cell", { name: "正常" }).getAttribute("data-label")).toBe("状态");
    expect(within(table).queryByRole("columnheader", { name: "操作" })).toBeNull();
    await user.click(within(table).getByRole("button", { name: "Team A" }));
    expect(screen.getByRole("heading", { name: "Team A" })).toBeTruthy();
    expect(screen.queryByRole("table", { name: "租户账号列表" })).toBeNull();
    await user.click(screen.getByRole("button", { name: "停用账户" }));
    await user.click(screen.getByRole("button", { name: "确认停用账户" }));
    await waitFor(() => expect(repository.execute).toHaveBeenCalledWith(credential, {
      kind: "set-account-status",
      accountId: "tenant-a",
      status: "DISABLED",
      resourceVersion: 1
    }));
  });

  it("separates deferred organization guardrails from the live tenant lifecycle", async () => {
    const repository = accounts();
    const { user } = await openAccess(repository, iam(), "tenants");
    expect(await screen.findByRole("table", { name: "租户账号列表" })).toBeTruthy();
    await user.click(screen.getByRole("tab", { name: "组织治理预览" }));
    const preview = screen.getByRole("region", { name: "组织目录与权限护栏" });
    expect(within(preview).getByText(/不创建组织节点、不移动账号、不发布策略/)).toBeTruthy();
    expect(within(preview).getByText(/只能收窄权限，不能产生 Allow/)).toBeTruthy();
    expect(within(preview).getByText(/租户列表不能被解释成组织树/)).toBeTruthy();
    expect(within(preview).getByText(/护栏通过不等于获准/)).toBeTruthy();
    expect(within(preview).queryByRole("button")).toBeNull();
    expect(repository.execute).not.toHaveBeenCalled();
    expect(screen.queryByRole("table", { name: "租户账号列表" })).toBeNull();
    await user.click(screen.getByRole("tab", { name: "租户账号" }));
    expect(screen.getByRole("table", { name: "租户账号列表" })).toBeTruthy();
  });

  it("opens tenant creation in the content area and restores the create action", async () => {
    const { user } = await openAccess(accounts(), iam(), "tenants");
    await user.click(await screen.findByRole("button", { name: "开通租户" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(screen.getByRole("heading", { level: 1, name: "开通租户账号" })).toBe(document.activeElement);
    expect(screen.getByRole("form", { name: "开通租户账号" })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "返回列表" }));
    expect(screen.getByRole("table", { name: "租户账号列表" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "开通租户" })).toBe(document.activeElement);
  });

  it("keeps the live account detail shell stable while exact target capabilities load", async () => {
    let resolveRead!: (value: AccountAccess) => void;
    const pendingRead = new Promise<AccountAccess>((resolve) => { resolveRead = resolve; });
    const lifecycle = liveAccountLifecycle({ read: vi.fn().mockReturnValue(pendingRead) });
    const { user } = await openAccess(accounts({ accountLifecycle: lifecycle }), iam(), "tenants");
    await user.click(await screen.findByRole("button", { name: "Team A" }));

    expect(screen.getByRole("heading", { name: "Team A" })).toBeTruthy();
    expect(screen.getByText("正在重新鉴权并读取目标账户…")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "停用账户" })).toBeNull();

    resolveRead(accountAccess(structuredClone(account)));
    expect(await screen.findByRole("button", { name: "停用账户" })).toBeTruthy();
    expect(lifecycle.read).toHaveBeenCalledWith(credential, account.id);
  });

  it("locks an unknown account status result to the original completion lookup without repeating the write", async () => {
    const disabled = { ...account, status: "DISABLED" as const, resourceVersion: 2 };
    const read = vi.fn()
      .mockResolvedValueOnce(accountAccess(structuredClone(account)))
      .mockResolvedValue(accountAccess(structuredClone(disabled)));
    const setStatus = vi.fn().mockRejectedValue(new HttpProblem(503, "IAM_UNAVAILABLE"));
    const readCompletion = vi.fn(async (_credential: string, intent: AccountLifecycleIntent) => lifecycleCompletion(intent));
    const lifecycle = liveAccountLifecycle({ read, setStatus, readCompletion });
    const { user } = await openAccess(accounts({ accountLifecycle: lifecycle }), iam(), "tenants");
    await user.click(await screen.findByRole("button", { name: "Team A" }));
    await user.click(await screen.findByRole("button", { name: "停用账户" }));
    await user.click(screen.getByRole("button", { name: "确认停用账户" }));

    expect(await screen.findByText("原操作结果未知")).toBeTruthy();
    const original = setStatus.mock.calls[0]![2];
    expect(original).toMatchObject({ status: "DISABLED", resourceVersion: 1, requestId: expect.any(String) });
    await user.click(screen.getByRole("button", { name: "只读检查原账号操作" }));
    expect(await screen.findByText("已确认原操作完成")).toBeTruthy();
    expect(screen.getByText("已确认原操作完成")).toBe(document.activeElement);
    expect(setStatus).toHaveBeenCalledTimes(1);
    expect(readCompletion).toHaveBeenCalledExactlyOnceWith(credential, expect.objectContaining({
      commandRequestId: original.requestId, accountId: account.id, operation: "ACCOUNT_SET_STATUS", expectedResourceVersion: 1, intendedStatus: "DISABLED"
    }));
    expect(read).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole("button", { name: "恢复账户访问" })).toBeNull();
    await user.click(screen.getByRole("button", { name: "已知晓并关闭" }));
    expect(screen.getByText("恢复原账号操作", { selector: "summary" })).toBe(document.activeElement);
    await user.click(await screen.findByRole("button", { name: "Team A" }));
    expect(await screen.findByRole("button", { name: "恢复账户访问" })).toBeTruthy();
    expect(read).toHaveBeenCalledTimes(2);

    await user.click(screen.getByTestId("nav-roles"));
    await user.click(screen.getByTestId("nav-tenants"));
    const row = within(await screen.findByRole("table", { name: "租户账号列表" })).getByRole("row", { name: /Team A/ });
    expect(within(row).getByText("已停用")).toBeTruthy();
  });

  it.each(["ACCOUNT_CREATE", "ACCOUNT_SET_STATUS", "ACCOUNT_ROOT_CREDENTIALS_RECOVER"] as const)(
    "recovers %s in a separate clean session through the original non-sensitive summary and no write", async (operation) => {
      const secret = "Lifecycle-Password-Only-Test-49!";
      const fail = vi.fn(async (...args: unknown[]) => {
        const command = args[args.length - 1] as { requestId: string };
        const saved = Array.from({ length: localStorage.length }, (_, index) => localStorage.getItem(localStorage.key(index)!)!).join("\n");
        expect(saved).toContain(command.requestId);
        expect(saved).not.toContain(secret);
        expect(saved).not.toContain(credential);
        throw new HttpProblem(503, "COMMITTED_RESPONSE_WAS_NOT_OBSERVED");
      });
      const firstLifecycle = liveAccountLifecycle(operation === "ACCOUNT_CREATE" ? { create: fail }
        : operation === "ACCOUNT_SET_STATUS" ? { setStatus: fail }
          : { recoverRootCredentials: fail, read: vi.fn().mockResolvedValue(accountAccess({ ...account, status: "DISABLED", resourceVersion: 3 })) });
      const first = await openAccess(accounts({ accountLifecycle: firstLifecycle }), iam(), "tenants");
      if (operation === "ACCOUNT_CREATE") {
        await first.user.click(await screen.findByRole("button", { name: "开通租户" }));
        const form = within(screen.getByRole("form", { name: "开通租户账号" }));
        for (const [label, value] of [["主账号 ID", "cold-created-account"], ["租户名称", "Cold account"],
          ["主账号登录名", "cold.owner"], ["用户显示名称", "Cold owner"], ["初始密码", secret]]) {
          fireEvent.change(form.getByLabelText(label!, { exact: true }), { target: { value } });
        }
        await first.user.click(form.getByRole("button", { name: "确认开通" }));
      } else {
        await first.user.click(await screen.findByRole("button", { name: "Team A" }));
        if (operation === "ACCOUNT_SET_STATUS") {
          await first.user.click(await screen.findByRole("button", { name: "停用账户" }));
          await first.user.click(screen.getByRole("button", { name: "确认停用账户" }));
        } else {
          await first.user.click(await screen.findByRole("button", { name: "恢复根身份凭据" }));
          fireEvent.change(screen.getByLabelText("初始密码"), { target: { value: secret } });
          await first.user.click(screen.getByRole("button", { name: "确认恢复根身份" }));
        }
      }
      expect(await screen.findByText("原操作结果未知")).toBeTruthy();
      const summary = (screen.getByLabelText("账号操作只读恢复摘要") as HTMLTextAreaElement).value;
      const original = JSON.parse(summary) as AccountLifecycleIntent;
      expect(original.operation).toBe(operation);
      expect(summary).not.toContain(secret);
      expect(summary).not.toContain(credential);
      expect(summary).not.toContain("initialPassword");
      if (operation !== "ACCOUNT_SET_STATUS") expect((screen.getByLabelText("初始密码") as HTMLInputElement).value).toBe("");
      expect(fail).toHaveBeenCalledTimes(1);
      first.view.unmount();
      localStorage.clear();

      const freshCredential = "separate-browser-fresh-user-credential";
      const readCompletion = vi.fn(async (_credential: string, intent: AccountLifecycleIntent) => lifecycleCompletion(intent, "DISABLED"));
      const secondLifecycle = liveAccountLifecycle({ readCompletion });
      const deniedIdentity = { ...identity, capabilities: identity.capabilities.map((item) => item.action === "iam.account.read"
        ? { ...item, available: false, restrictionReason: "AUTHORITY_REQUIRED" as const } : item) };
      const secondRepository = accounts({ accountLifecycle: secondLifecycle, currentIdentity: vi.fn().mockResolvedValue(deniedIdentity) });
      const secondIam = iam({ login: vi.fn().mockResolvedValue({ outcome: "AUTHENTICATED", credential: freshCredential,
        mustChangePassword: false, session: { id: "separate-browser-session", principalId: rootUser.id, organizationId: account.id,
          status: "ACTIVE", issuedAt: timestamp, expiresAt: "2099-01-01T00:00:00Z" } }) });
      const second = await openAccess(secondRepository, secondIam, "tenants", freshCredential);
      expect(await screen.findByTestId("can-read-accounts")).toHaveProperty("textContent", "false");
      await second.user.click(screen.getByText("恢复原账号操作", { selector: "summary" }));
      fireEvent.change(screen.getByLabelText("原账号操作非敏感摘要"), { target: { value: summary } });
      await second.user.click(screen.getByRole("button", { name: "带入摘要并只读检查" }));
      expect(await screen.findByText("已确认原操作完成")).toBeTruthy();
      expect(readCompletion).toHaveBeenCalledExactlyOnceWith(freshCredential, original);
      if (operation === "ACCOUNT_ROOT_CREDENTIALS_RECOVER") expect(screen.getByText("已停用")).toBeTruthy();
      for (const write of [secondLifecycle.create, secondLifecycle.setStatus, secondLifecycle.recoverRootCredentials, secondRepository.execute]) {
        expect(write).not.toHaveBeenCalled();
      }
      expect(secondLifecycle.read).not.toHaveBeenCalled();
      expect(secondLifecycle.list).not.toHaveBeenCalled();
      expect(screen.queryByRole("dialog")).toBeNull();
      const persisted = Array.from({ length: localStorage.length }, (_, index) => localStorage.getItem(localStorage.key(index)!)!).join("\n");
      expect(persisted).not.toContain(freshCredential);
      expect(persisted).not.toContain(secret);
    }
  );

  it.each([403, 404, 503])("retains an unresolved account completion after %s without permitting a new command", async (status) => {
    const readCompletion = vi.fn().mockRejectedValue(new HttpProblem(status, "PRIVATE_FAILURE_DETAIL"));
    const lifecycle = liveAccountLifecycle({ readCompletion });
    const { user } = await openAccess(accounts({ accountLifecycle: lifecycle }), iam(), "tenants");
    const intent = originalAccountStatusIntent();
    await importAccountSummary(user, JSON.stringify(intent));
    expect(await screen.findByText("原操作结果未知")).toBeTruthy();
    expect(readCompletion).toHaveBeenCalledExactlyOnceWith(credential, intent);
    expect((screen.getByRole("button", { name: "开通租户" }) as HTMLButtonElement).disabled).toBe(true);
    expect((screen.getByLabelText("账号操作只读恢复摘要") as HTMLTextAreaElement).value).toContain(intent.commandRequestId);
    expect(screen.queryByRole("button", { name: "登录控制台" })).toBeNull();
    expect(document.body.textContent).not.toContain("PRIVATE_FAILURE_DETAIL");
    for (const write of [lifecycle.create, lifecycle.setStatus, lifecycle.recoverRootCredentials]) expect(write).not.toHaveBeenCalled();
    expect(lifecycle.read).not.toHaveBeenCalled();
    expect(lifecycle.list).not.toHaveBeenCalled();
  });

  it("rejects foreign, secret-bearing and replacement account summaries without querying or losing the original identity", async () => {
    const lifecycle = liveAccountLifecycle();
    const { user } = await openAccess(accounts({ accountLifecycle: lifecycle }), iam(), "tenants");
    const intent = originalAccountStatusIntent();
    for (const invalid of [{ ...intent, initialPassword: "not-exportable" }, { ...intent, credential },
      { ...intent, digest: "not-a-recovery-field" }, { ...intent, actorPrincipalId: "different-actor" }]) {
      await importAccountSummary(user, JSON.stringify(invalid));
      expect(screen.getByText(/摘要无效、含不支持字段/)).toBeTruthy();
    }
    expect(lifecycle.readCompletion).not.toHaveBeenCalled();
    await importAccountSummary(user, JSON.stringify(intent));
    expect(await screen.findByText("原操作结果未知")).toBeTruthy();
    await importAccountSummary(user, JSON.stringify({ ...intent, commandRequestId: "replacement-command" }));
    expect(screen.getByText(/摘要无效、含不支持字段/)).toBeTruthy();
    expect(lifecycle.readCompletion).toHaveBeenCalledTimes(1);
    expect((screen.getByLabelText("账号操作只读恢复摘要") as HTMLTextAreaElement).value).toContain(intent.commandRequestId);
    for (const write of [lifecycle.create, lifecycle.setStatus, lifecycle.recoverRootCredentials]) expect(write).not.toHaveBeenCalled();
  });

  it("retains the original account summary across lookup expiry and reauthorizes it with a fresh same-actor session", async () => {
    const intent = originalAccountStatusIntent();
    const freshCredential = "fresh-account-completion-session-credential";
    const login = vi.fn().mockResolvedValueOnce({ outcome: "AUTHENTICATED", credential, mustChangePassword: false,
      session: { id: "first-account-session", organizationId: account.id, principalId: rootUser.id, status: "ACTIVE", issuedAt: timestamp, expiresAt: "2099-01-01T00:00:00Z" } })
      .mockResolvedValueOnce({ outcome: "AUTHENTICATED", credential: freshCredential, mustChangePassword: false,
        session: { id: "second-account-session", organizationId: account.id, principalId: rootUser.id, status: "ACTIVE", issuedAt: timestamp, expiresAt: "2099-01-01T00:00:00Z" } });
    const readCompletion = vi.fn().mockRejectedValueOnce(new HttpProblem(401, "FIRST_SESSION_EXPIRED"))
      .mockResolvedValue(lifecycleCompletion(intent));
    const lifecycle = liveAccountLifecycle({ readCompletion });
    const repository = accounts({ accountLifecycle: lifecycle });
    const { user } = await openAccess(repository, iam({ login }), "tenants");
    await importAccountSummary(user, JSON.stringify(intent));
    expect(await screen.findByRole("button", { name: "登录控制台" })).toBeTruthy();
    expect(screen.queryByText("Team A")).toBeNull();
    await user.type(screen.getByLabelText("密码", { exact: true }), "Fresh-Login-Password-Only-Test-49!");
    await user.click(screen.getByRole("button", { name: "登录控制台" }));
    await waitFor(() => expect(repository.currentIdentity).toHaveBeenCalledWith(freshCredential));
    expect(await screen.findByText("原操作结果未知")).toBeTruthy();
    expect(readCompletion).toHaveBeenCalledTimes(1);
    await user.click(screen.getByRole("button", { name: "只读检查原账号操作" }));
    expect(await screen.findByText("已确认原操作完成")).toBeTruthy();
    expect(readCompletion).toHaveBeenNthCalledWith(2, freshCredential, intent);
    for (const write of [lifecycle.create, lifecycle.setStatus, lifecycle.recoverRootCredentials]) expect(write).not.toHaveBeenCalled();
    expect(lifecycle.read).not.toHaveBeenCalled();
    const saved = Array.from({ length: localStorage.length }, (_, index) => localStorage.getItem(localStorage.key(index)!)!).join("\n");
    expect(saved).not.toContain(freshCredential);
    expect(saved).not.toContain("Fresh-Login-Password-Only-Test-49!");
  });

  it.each(["success", "expired"] as const)("discards a late account completion %s after the repository owner changes", async (outcome) => {
    let finish!: (value: AccountLifecycleCompletion) => void;
    let fail!: (reason: unknown) => void;
    const readCompletion = vi.fn(() => new Promise<AccountLifecycleCompletion>((resolve, reject) => { finish = resolve; fail = reject; }));
    const original = originalAccountStatusIntent();
    const firstLifecycle = liveAccountLifecycle({ readCompletion });
    const first = await openAccess(accounts({ accountLifecycle: firstLifecycle }), iam(), "tenants");
    await importAccountSummary(first.user, JSON.stringify(original));
    expect((screen.getByRole("button", { name: "正在只读检查原账号操作" }) as HTMLButtonElement).disabled).toBe(true);
    const secondLifecycle = liveAccountLifecycle();
    const secondRepository = accounts({ accountLifecycle: secondLifecycle });
    first.replaceRepository(secondRepository);
    await waitFor(() => expect(secondRepository.currentIdentity).toHaveBeenCalledWith(credential));
    await act(async () => {
      if (outcome === "success") finish(lifecycleCompletion(original));
      else fail(new HttpProblem(401, "OLD_CLIENT_EXPIRED"));
    });
    expect(await screen.findByText("原操作结果未知")).toBeTruthy();
    expect(screen.queryByText("已确认原操作完成")).toBeNull();
    expect(screen.queryByRole("button", { name: "登录控制台" })).toBeNull();
    expect(secondLifecycle.readCompletion).not.toHaveBeenCalled();
    expect(secondLifecycle.setStatus).not.toHaveBeenCalled();
    expect(firstLifecycle.setStatus).not.toHaveBeenCalled();
  });

  it("blocks an account write before dispatch when its non-sensitive summary cannot be saved", async () => {
    const lifecycle = liveAccountLifecycle();
    const { user } = await openAccess(accounts({ accountLifecycle: lifecycle }), iam(), "tenants");
    await user.click(await screen.findByRole("button", { name: "Team A" }));
    await user.click(await screen.findByRole("button", { name: "停用账户" }));
    const unavailable = vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => { throw new Error("STORAGE_BLOCKED"); });
    try {
      await user.click(screen.getByRole("button", { name: "确认停用账户" }));
      expect(await screen.findByText(/无法读取或保存原操作摘要/)).toBeTruthy();
      expect(lifecycle.setStatus).not.toHaveBeenCalled();
      expect(lifecycle.readCompletion).not.toHaveBeenCalled();
      expect((screen.getByRole("button", { name: "停用账户" }) as HTMLButtonElement).disabled).toBe(true);
    } finally { unavailable.mockRestore(); }
  });

  it("keeps an unknown account mutation locked when the tenant view is left and reopened", async () => {
    const setStatus = vi.fn().mockRejectedValue(new HttpProblem(503, "IAM_UNAVAILABLE"));
    const lifecycle = liveAccountLifecycle({ setStatus });
    const { user } = await openAccess(accounts({ accountLifecycle: lifecycle }), iam(), "tenants");
    await user.click(await screen.findByRole("button", { name: "Team A" }));
    await user.click(await screen.findByRole("button", { name: "停用账户" }));
    await user.click(screen.getByRole("button", { name: "确认停用账户" }));

    expect(await screen.findByText("原操作结果未知")).toBeTruthy();
    const originalRequestId = setStatus.mock.calls[0]![2].requestId;
    await user.click(screen.getByTestId("nav-roles"));
    await user.click(screen.getByTestId("nav-tenants"));

    expect(await screen.findByText("原操作结果未知")).toBeTruthy();
    expect(screen.getByText(originalRequestId)).toBeTruthy();
    expect((screen.getByRole("button", { name: "开通租户" }) as HTMLButtonElement).disabled).toBe(true);
    expect(setStatus).toHaveBeenCalledTimes(1);
  });

  it("uses a replacement repository only to inspect the original account completion, never to replay its command", async () => {
    const oldSetStatus = vi.fn().mockRejectedValue(new HttpProblem(503, "IAM_UNAVAILABLE"));
    const oldRepository = accounts({ accountLifecycle: liveAccountLifecycle({ setStatus: oldSetStatus }) });
    const newSetStatus = vi.fn();
    const readCompletion = vi.fn(async (_credential: string, intent: AccountLifecycleIntent) => lifecycleCompletion(intent));
    const newRepository = accounts({ accountLifecycle: liveAccountLifecycle({ setStatus: newSetStatus, readCompletion }) });
    const { user, replaceRepository } = await openAccess(oldRepository, iam(), "tenants");
    await user.click(await screen.findByRole("button", { name: "Team A" }));
    await user.click(await screen.findByRole("button", { name: "停用账户" }));
    await user.click(screen.getByRole("button", { name: "确认停用账户" }));
    expect(await screen.findByText("原操作结果未知")).toBeTruthy();

    replaceRepository(newRepository);
    await waitFor(() => expect(newRepository.currentIdentity).toHaveBeenCalledWith(credential));
    expect(await screen.findByText("原操作结果未知")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "精确重试原请求" })).toBeNull();
    expect((screen.getByRole("button", { name: "开通租户" }) as HTMLButtonElement).disabled).toBe(true);
    expect(oldSetStatus).toHaveBeenCalledTimes(1);
    expect(newSetStatus).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "只读检查原账号操作" }));
    expect(await screen.findByText("已确认原操作完成")).toBeTruthy();
    expect(readCompletion).toHaveBeenCalledTimes(1);
    expect(newSetStatus).not.toHaveBeenCalled();
  });

  it("rereads after a lifecycle conflict but requires a new explicit request with a new version and requestId", async () => {
    const latest = { ...account, resourceVersion: 4 };
    const disabled = { ...latest, status: "DISABLED" as const, resourceVersion: 5 };
    const read = vi.fn()
      .mockResolvedValueOnce(accountAccess(structuredClone(account)))
      .mockResolvedValueOnce(accountAccess(structuredClone(latest)))
      .mockResolvedValue(accountAccess(structuredClone(disabled)));
    const setStatus = vi.fn()
      .mockRejectedValueOnce(new HttpProblem(409, "IAM_CONFLICT"))
      .mockResolvedValueOnce(structuredClone(disabled));
    const lifecycle = liveAccountLifecycle({ read, setStatus });
    const { user } = await openAccess(accounts({ accountLifecycle: lifecycle }), iam(), "tenants");
    await user.click(await screen.findByRole("button", { name: "Team A" }));
    await user.click(await screen.findByRole("button", { name: "停用账户" }));
    await user.click(screen.getByRole("button", { name: "确认停用账户" }));

    expect(await screen.findByText("资源已变化，原请求未被确认")).toBeTruthy();
    expect(screen.getByText("当前状态：正常 · 资源版本 4")).toBeTruthy();
    const first = setStatus.mock.calls[0]![2];
    await user.click(screen.getByRole("button", { name: "确认停用账户" }));
    await waitFor(() => expect(setStatus).toHaveBeenCalledTimes(2));
    const second = setStatus.mock.calls[1]![2];
    expect(second.resourceVersion).toBe(4);
    expect(second.requestId).not.toBe(first.requestId);
    expect(await screen.findByText("账户状态已更新；目标能力已重新读取。")).toBeTruthy();
  });

  it("does not claim refreshed capabilities when the post-mutation target read fails", async () => {
    const disabled = { ...account, status: "DISABLED" as const, resourceVersion: 2 };
    const read = vi.fn()
      .mockResolvedValueOnce(accountAccess(structuredClone(account)))
      .mockRejectedValueOnce(new HttpProblem(503, "IAM_UNAVAILABLE"));
    const lifecycle = liveAccountLifecycle({ read, setStatus: vi.fn().mockResolvedValue(structuredClone(disabled)) });
    const { user } = await openAccess(accounts({ accountLifecycle: lifecycle }), iam(), "tenants");
    await user.click(await screen.findByRole("button", { name: "Team A" }));
    await user.click(await screen.findByRole("button", { name: "停用账户" }));
    await user.click(screen.getByRole("button", { name: "确认停用账户" }));

    expect(await screen.findByText("操作已返回成功，但目标账户的重新鉴权读取失败。请重试读取；旧能力不会继续用于操作。")).toBeTruthy();
    expect(screen.queryByText("账户状态已更新；目标能力已重新读取。")).toBeNull();
    expect(screen.queryByRole("button", { name: "恢复账户访问" })).toBeNull();
    expect(screen.queryByRole("button", { name: "恢复根身份凭据" })).toBeNull();
  });

  it("keeps system-owned account lifecycle actions unavailable from exact target capabilities", async () => {
    const protectedAccess: AccountAccess = { account: structuredClone(account), capabilities: [
      capability("iam.account.set-status", "ACCOUNT", account.id, "SYSTEM_ACCOUNT_PROTECTED"),
      capability("iam.account.recover-root-credentials", "ACCOUNT", account.id, "SYSTEM_ACCOUNT_PROTECTED")
    ] };
    const lifecycle = liveAccountLifecycle({ read: vi.fn().mockResolvedValue(protectedAccess) });
    const { user } = await openAccess(accounts({ accountLifecycle: lifecycle }), iam(), "tenants");
    await user.click(await screen.findByRole("button", { name: "Team A" }));
    expect((await screen.findByRole("button", { name: "停用账户" }) as HTMLButtonElement).disabled).toBe(true);
    expect((screen.getByRole("button", { name: "恢复根身份凭据" }) as HTMLButtonElement).disabled).toBe(true);
    expect(lifecycle.setStatus).not.toHaveBeenCalled();
    expect(lifecycle.recoverRootCredentials).not.toHaveBeenCalled();
  });

  it("expires the exact session and clears the account projection after a lifecycle 401", async () => {
    const lifecycle = liveAccountLifecycle({ read: vi.fn().mockRejectedValue(new HttpProblem(401, "private upstream")) });
    const { user } = await openAccess(accounts({ accountLifecycle: lifecycle }), iam(), "tenants");
    await user.click(await screen.findByRole("button", { name: "Team A" }));

    expect(await screen.findByRole("button", { name: "登录控制台" })).toBeTruthy();
    expect(screen.queryByRole("table", { name: "租户账号列表" })).toBeNull();
    expect(screen.queryByText("Team A")).toBeNull();
  });

  it("keeps status and authority unchanged when root credentials are recovered", async () => {
    const disabled = { ...account, status: "DISABLED" as const, resourceVersion: 3 };
    const recovered = { ...disabled, resourceVersion: 4 };
    const read = vi.fn()
      .mockResolvedValueOnce(accountAccess(structuredClone(disabled)))
      .mockResolvedValue(accountAccess(structuredClone(recovered)));
    const recoverRootCredentials = vi.fn().mockResolvedValue(structuredClone(recovered));
    const lifecycle = liveAccountLifecycle({ read, recoverRootCredentials });
    const { user } = await openAccess(accounts({ accountLifecycle: lifecycle }), iam(), "tenants");
    await user.click(await screen.findByRole("button", { name: "Team A" }));
    await user.click(await screen.findByRole("button", { name: "恢复根身份凭据" }));
    await user.type(screen.getByLabelText("初始密码"), "Recovery-Test-Password-49!");
    await user.click(screen.getByRole("button", { name: "确认恢复根身份" }));

    expect(await screen.findByText("根身份凭据已恢复；原会话已撤销，首次登录必须修改密码。账户状态和平台角色没有改变。")).toBeTruthy();
    expect(screen.getByRole("button", { name: "恢复账户访问" })).toBeTruthy();
    expect(screen.getAllByText("已停用").length).toBeGreaterThan(0);
    expect(recoverRootCredentials).toHaveBeenCalledWith(credential, account.id, {
      initialPassword: "Recovery-Test-Password-49!",
      resourceVersion: disabled.resourceVersion,
      requestId: expect.any(String)
    });
  });

  it("starts on a dedicated overview and opens the user workspace without an extra fetch", async () => {
    const repository = accounts();
    const { user } = await openAccess(repository, iam(), "overview");
    await screen.findByText("Account owner");
    expect(screen.getByText("所属账号 · 资源归属")).toBeTruthy();
    expect(screen.queryByRole("table", { name: "子用户列表" })).toBeNull();
    await user.click(screen.getByTestId("nav-users"));
    await screen.findByText("Developer A");
    expect(repository.currentIdentity).toHaveBeenCalledTimes(1);
  });

  it("pages each live directory without reloading identity or unrelated IAM collections", async () => {
    const userCursor = "ic1.dXNlcnM";
    const accountCursor = "ic1.YWNjb3VudHM";
    const nextUser: UserAccess = {
      user: { ...childUser, id: "child-b", loginName: "auditor", displayName: "Auditor B" },
      policyAttachments: [],
      capabilities: userCapabilities({ ...childUser, id: "child-b", loginName: "auditor", displayName: "Auditor B" })
    };
    const nextAccount: Account = {
      ...account,
      id: "tenant-b",
      displayName: "Team B",
      rootIdentity: { principalId: "primary-b", loginName: "owner-b" }
    };
    const listUsers = vi.fn(async (_credential: string, after?: string) => after
      ? { items: [nextUser], nextAfter: null }
      : { items: [child], nextAfter: userCursor });
    const listAccounts = vi.fn(async (_credential: string, after?: string) => after
      ? { items: [accountAccess(nextAccount)], nextAfter: null }
      : { items: [accountAccess(account)], nextAfter: accountCursor });
    const listPolicies = vi.fn(async (_credential: string, platform: boolean) => directory(platform));
    const repository = accounts({ listUsers, listAccounts, listPolicies });
    const { user } = await openAccess(repository);

    await screen.findByText("Developer A");
    await user.click(screen.getByRole("button", { name: "下一页" }));
    expect(await screen.findByText("Auditor B")).toBeTruthy();
    expect(listUsers).toHaveBeenNthCalledWith(2, credential, userCursor);
    expect(repository.currentIdentity).toHaveBeenCalledTimes(1);
    expect(listPolicies).toHaveBeenCalledTimes(2);
    expect(listAccounts).toHaveBeenCalledTimes(1);

    await user.click(screen.getByTestId("nav-tenants"));
    await user.click(screen.getByRole("button", { name: "下一页" }));
    expect(await screen.findByRole("button", { name: "Team B" })).toBeTruthy();
    expect(listAccounts).toHaveBeenNthCalledWith(2, credential, accountCursor);
    expect(repository.currentIdentity).toHaveBeenCalledTimes(1);
    expect(listUsers).toHaveBeenCalledTimes(2);
    expect(listPolicies).toHaveBeenCalledTimes(2);
  });

  it.each([true, false])("reads a stable user ID outside the current directory page with user-list permission=%s", async (canList) => {
    const otherUser = { ...childUser, id: "child-other", loginName: "other", displayName: "Other User" };
    const listUsers = vi.fn().mockResolvedValue({ items: [{ user: otherUser, policyAttachments: [], capabilities: userCapabilities(otherUser) }], nextAfter: "next-user-page" });
    const target = structuredClone(child);
    target.capabilities = userCapabilities(childUser, target.policyAttachments, "AUTHORITY_REQUIRED").map((entry) => entry.action === "iam.user.read" ? { ...entry, available: true, restrictionReason: null } : entry);
    const repository = accounts({ listUsers, currentIdentity: vi.fn().mockResolvedValue({ ...identity, capabilities: currentCapabilities(canList) }), getUser: vi.fn().mockResolvedValue(target) });
    await openAccess(repository, iam(), "users", credential, childUser.id);
    expect(await screen.findByRole("button", { name: "修改显示名称" })).toHaveProperty("disabled", true);
    expect(repository.getUser).toHaveBeenCalledExactlyOnceWith(credential, childUser.id);
    expect(listUsers).toHaveBeenCalledTimes(canList ? 1 : 0);
    expect(repository.execute).not.toHaveBeenCalled();
    expect(screen.queryByRole("table", { name: "租户用户列表" })).toBeNull();
    expect(screen.queryByText("对象不可用")).toBeNull();
  });

  it.each([403, 404])("keeps an unavailable stable user ID private after an exact %s", async (status) => {
    const repository = accounts({ currentIdentity: vi.fn().mockResolvedValue({ ...identity, capabilities: currentCapabilities(false) }), getUser: vi.fn().mockRejectedValue(new HttpProblem(status, "PRIVATE_TARGET")) });
    await openAccess(repository, iam(), "users", credential, "known-user-id");
    expect(await screen.findByText("对象不可用")).toBeTruthy();
    expect(repository.getUser).toHaveBeenCalledExactlyOnceWith(credential, "known-user-id");
    expect(repository.listUsers).not.toHaveBeenCalled();
    expect(screen.queryByText("PRIVATE_TARGET")).toBeNull();
    expect(screen.queryByRole("button", { name: "修改显示名称" })).toBeNull();
  });

  it("reads service consent independently without ordinary Role-list authority", async () => {
    const roleRepository = { list: vi.fn() } as unknown as NonNullable<AccountRepository["roles"]>;
    const listServiceLinkedRoles = vi.fn().mockResolvedValue({ accountId: account.id, items: [], nextAfter: null });
    const serviceCapabilities = currentCapabilities(false).map((item) => item.action === "iam.service-role-template.list" || item.action === "iam.service-linked-role.list"
      ? { ...item, available: true, restrictionReason: null } : item);
    const repository = accounts({ currentIdentity: vi.fn().mockResolvedValue({ ...identity, capabilities: serviceCapabilities }), roles: roleRepository,
      listServiceLinkedRoles, getServiceLinkedRole: vi.fn(), listServiceRoleTemplates: vi.fn().mockResolvedValue({ accountId: account.id, items: [] }) });
    await openAccess(repository, iam(), "service-authorizations");
    expect(await screen.findByText("当前账号暂无服务授权")).toBeTruthy();
    expect(listServiceLinkedRoles).toHaveBeenCalledExactlyOnceWith(credential, account.id, undefined);
    expect(roleRepository.list).not.toHaveBeenCalled();
    expect(screen.queryByRole("button", { name: "返回角色列表" })).toBeNull();
  });

  it("does not let a previous repository's late exact User response restore old controls", async () => {
    let finish!: (value: UserAccess) => void;
    const first = accounts({ getUser: vi.fn(() => new Promise<UserAccess>((resolve) => { finish = resolve; })) });
    const next = structuredClone(child);
    next.user.displayName = "Current read-only identity";
    next.capabilities = userCapabilities(next.user, next.policyAttachments, "AUTHORITY_REQUIRED");
    const replacement = accounts({ getUser: vi.fn().mockResolvedValue(next) });
    const opened = await openAccess(first, iam(), "users", credential, childUser.id);
    await waitFor(() => expect(first.getUser).toHaveBeenCalledTimes(1));
    opened.replaceRepository(replacement);
    await screen.findByText("Current read-only identity");
    await act(async () => { finish(structuredClone(child)); });
    expect(screen.getByRole("button", { name: "修改显示名称" })).toHaveProperty("disabled", true);
    expect(screen.queryByText("Developer A")).toBeNull();
    expect(first.execute).not.toHaveBeenCalled();
    expect(replacement.execute).not.toHaveBeenCalled();
  });

  it("hides the previous repository's verified User controls while the replacement exact read is pending", async () => {
    const first = accounts();
    let finish!: (value: UserAccess) => void;
    const pending = new Promise<UserAccess>((resolve) => { finish = resolve; });
    const replacement = accounts({ getUser: vi.fn().mockReturnValue(pending) });
    const opened = await openAccess(first, iam(), "users", credential, childUser.id);
    expect(await screen.findByRole("button", { name: "修改显示名称" })).toHaveProperty("disabled", false);
    opened.replaceRepository(replacement);
    await waitFor(() => expect(replacement.getUser).toHaveBeenCalled());
    expect(screen.queryByRole("button", { name: "修改显示名称" })).toBeNull();
    const readonly = structuredClone(child);
    readonly.capabilities = userCapabilities(readonly.user, readonly.policyAttachments, "AUTHORITY_REQUIRED");
    await act(async () => { finish(readonly); });
    expect(await screen.findByRole("button", { name: "修改显示名称" })).toHaveProperty("disabled", true);
    expect(first.execute).not.toHaveBeenCalled();
    expect(replacement.execute).not.toHaveBeenCalled();
  });

  it("quarantines a foreign User directory but still reads an independently known exact User", async () => {
    const foreign = structuredClone(child);
    foreign.user.accountId = "foreign-directory-account";
    const repository = accounts({ listUsers: vi.fn().mockResolvedValue({ items: [foreign], nextAfter: null }) });
    await openAccess(repository, iam(), "users", credential, childUser.id);
    expect(await screen.findByText("用户资料")).toBeTruthy();
    expect(screen.queryByText("foreign-directory-account")).toBeNull();
    expect(repository.getUser).toHaveBeenCalledExactlyOnceWith(credential, childUser.id);
    expect(repository.execute).not.toHaveBeenCalled();
  });

  it("does not render a foreign Account's exact User result as the requested target", async () => {
    const foreign = structuredClone(child);
    foreign.user.accountId = "foreign-account";
    const repository = accounts({ currentIdentity: vi.fn().mockResolvedValue({ ...identity, capabilities: currentCapabilities(false) }), getUser: vi.fn().mockResolvedValue(foreign) });
    await openAccess(repository, iam(), "users", credential, childUser.id);
    expect(await screen.findByText("对象不可用")).toBeTruthy();
    expect(screen.queryByText("foreign-account")).toBeNull();
    expect(screen.queryByRole("button", { name: "修改显示名称" })).toBeNull();
    expect(repository.execute).not.toHaveBeenCalled();
  });

  it("opens another known user's keys from an exact detail without listing the users", async () => {
    const list = vi.fn().mockResolvedValue({ accountId: account.id, userId: childUser.id, userResourceVersion: childUser.resourceVersion, capabilities: [], items: [] });
    const repository = accounts({ currentIdentity: vi.fn().mockResolvedValue({ ...identity, capabilities: currentCapabilities(false) }),
      accessKeys: { list, read: vi.fn(), create: vi.fn(), setStatus: vi.fn(), setNetworkRestrictions: vi.fn(), delete: vi.fn() } });
    const { user } = await openAccess(repository, iam(), "users", credential, childUser.id);
    await user.click(await screen.findByRole("button", { name: "查看/管理访问密钥" }));
    expect(await screen.findByText("尚未创建访问密钥")).toBeTruthy();
    expect(list).toHaveBeenCalledExactlyOnceWith(credential, account.id, childUser.id);
    expect(repository.getUser).toHaveBeenCalledTimes(1);
    expect(repository.listUsers).not.toHaveBeenCalled();
    expect(repository.accessKeys!.create).not.toHaveBeenCalled();
  });

  it("opens an exact LIVE user at the requested policy section and focuses the stable target", async () => {
    const repository = accounts({ currentIdentity: vi.fn().mockResolvedValue({ ...identity, capabilities: currentCapabilities(false) }) });
    await openAccess(repository, iam(), "users", credential, childUser.id, "policies");

    const section = await screen.findByRole("region", { name: "直接关联策略" });
    await waitFor(() => expect(document.activeElement).toBe(section));
    expect(repository.getUser).toHaveBeenCalledExactlyOnceWith(credential, childUser.id);
    expect(repository.listUsers).not.toHaveBeenCalled();
  });

  it("opens an exact LIVE user at the requested key section and expands only its key inventory", async () => {
    const list = vi.fn().mockResolvedValue({ accountId: account.id, userId: childUser.id, userResourceVersion: childUser.resourceVersion, capabilities: [], items: [] });
    const repository = accounts({ currentIdentity: vi.fn().mockResolvedValue({ ...identity, capabilities: currentCapabilities(false) }),
      accessKeys: { list, read: vi.fn(), create: vi.fn(), setStatus: vi.fn(), setNetworkRestrictions: vi.fn(), delete: vi.fn() } });
    await openAccess(repository, iam(), "users", credential, childUser.id, "keys");

    const section = await screen.findByRole("region", { name: "访问方式与凭据" });
    await waitFor(() => expect(document.activeElement).toBe(section));
    expect(await screen.findByText("尚未创建访问密钥")).toBeTruthy();
    expect(list).toHaveBeenCalledExactlyOnceWith(credential, account.id, childUser.id);
    expect(repository.listUsers).not.toHaveBeenCalled();
  });

  it("reads a member's own keys without any user-list or user-detail request", async () => {
    const list = vi.fn().mockResolvedValue({ accountId: account.id, userId: childUser.id, userResourceVersion: childUser.resourceVersion, capabilities: [], items: [] });
    const repository = accounts({ currentIdentity: vi.fn().mockResolvedValue({ ...identity, user: childUser, identityKind: "USER", permissionBoundary: { accountId: account.id, userId: childUser.id, resourceVersion: childUser.resourceVersion, policy: null }, capabilities: currentCapabilities(false, childUser.id, true) }),
      accessKeys: { list, read: vi.fn(), create: vi.fn(), setStatus: vi.fn(), setNetworkRestrictions: vi.fn(), delete: vi.fn() } });
    await openAccess(repository, iam({}, childUser.id), "keys");
    expect(await screen.findByText("尚未创建访问密钥")).toBeTruthy();
    expect(list).toHaveBeenCalledExactlyOnceWith(credential, account.id, childUser.id);
    expect(repository.listUsers).not.toHaveBeenCalled();
    expect(repository.getUser).not.toHaveBeenCalled();
    expect(repository.accessKeys!.create).not.toHaveBeenCalled();
  });

  it("keeps the verified directory identity visible while loading the exact live user detail", async () => {
    let resolveUser!: (value: UserAccess) => void;
    const getUser = vi.fn(() => new Promise<UserAccess>((resolve) => { resolveUser = resolve; }));
    const repository = accounts({ getUser });
    const { user } = await openAccess(repository);
    await screen.findByText("Developer A");
    await user.click(screen.getByRole("button", { name: "查看用户 developer" }));
    expect(screen.queryByRole("table", { name: "租户用户列表" })).toBeNull();
    expect(screen.getByRole("heading", { name: "developer" })).toBeTruthy();
    expect(screen.getByText("Developer A")).toBeTruthy();
    expect(screen.getByText("developer@tenant-a")).toBeTruthy();
    expect(screen.getByText("正在读取用户详情…")).toBeTruthy();
    expect(screen.queryByText("用户资料")).toBeNull();
    expect(screen.queryByRole("button", { name: "修改显示名称" })).toBeNull();
    await act(async () => { resolveUser(structuredClone(child)); });
    expect(await screen.findByText("用户资料")).toBeTruthy();
    expect(getUser).toHaveBeenCalledWith(credential, "child-a");
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(screen.getByText(/不根据用户状态推断访问方式/)).toBeTruthy();
  });

  it("keeps the verified user snapshot and retries an unavailable exact detail in place", async () => {
    let resolveUser!: (value: UserAccess) => void;
    const getUser = vi.fn()
      .mockRejectedValueOnce(new HttpProblem(503, "IAM_UNAVAILABLE"))
      .mockImplementationOnce(() => new Promise<UserAccess>((resolve) => { resolveUser = resolve; }));
    const repository = accounts({ getUser });
    const { user } = await openAccess(repository);
    await screen.findByText("Developer A");
    await user.click(screen.getByRole("button", { name: "查看用户 developer" }));

    expect(await screen.findByRole("button", { name: "重试读取" })).toBeTruthy();
    expect(screen.getByRole("heading", { name: "developer" })).toBeTruthy();
    expect(screen.getByText("Developer A")).toBeTruthy();
    expect(screen.getByText("developer@tenant-a")).toBeTruthy();
    expect(screen.getByText("对象不可用")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "修改显示名称" })).toBeNull();

    await user.click(screen.getByRole("button", { name: "重试读取" }));
    expect(screen.getByText("正在读取用户详情…")).toBeTruthy();
    await act(async () => { resolveUser(structuredClone(child)); });
    expect(await screen.findByText("用户资料")).toBeTruthy();
    expect(getUser).toHaveBeenCalledTimes(2);
  });

  it("keeps access-method facts unknown while opening the user's real key inventory in context", async () => {
    const list = vi.fn().mockResolvedValue({ accountId: account.id, userId: childUser.id, userResourceVersion: childUser.resourceVersion, capabilities: [], items: [] });
    const repository = accounts({ accessKeys: { list, read: vi.fn(), create: vi.fn(), setStatus: vi.fn(), setNetworkRestrictions: vi.fn(), delete: vi.fn() } });
    const { user } = await openAccess(repository);
    await user.click(await screen.findByRole("button", { name: "查看用户 developer" }));

    expect(await screen.findByText(/控制台登录与编程访问的启用状态尚无独立契约/)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "查看\/管理访问密钥" }));
    expect(await screen.findByText("尚未创建访问密钥")).toBeTruthy();
    expect(list).toHaveBeenCalledWith(credential, account.id, childUser.id);
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("keeps access-key owner search page-scoped and follows the user cursor without inventing a total", async () => {
    const otherUser = { ...childUser, id: "child-b", loginName: "operator", displayName: "Operator B" };
    const other: UserAccess = { user: otherUser, policyAttachments: [], capabilities: userCapabilities(otherUser) };
    const listUsers = vi.fn(async (_credential: string, after?: string) => after === "users-page-2"
      ? { items: [other], nextAfter: null }
      : { items: [child], nextAfter: "users-page-2" });
    const repository = accounts({ listUsers, accessKeys: {
      list: vi.fn(), read: vi.fn(), create: vi.fn(), setStatus: vi.fn(), setNetworkRestrictions: vi.fn(), delete: vi.fn()
    } });
    const { user } = await openAccess(repository, iam(), "keys");
    expect(await screen.findByText("已加载 1 位用户")).toBeTruthy();
    expect(screen.getByText(/搜索只覆盖本页/)).toBeTruthy();
    const search = screen.getByRole("searchbox", { name: "搜索已加载用户" });
    await user.type(search, "missing");
    expect(screen.getByText("没有匹配的用户")).toBeTruthy();
    expect(screen.getByText(/搜索仅覆盖当前已加载的用户页/)).toBeTruthy();
    await user.clear(search);
    await user.click(screen.getByRole("button", { name: "下一页" }));
    expect(await screen.findByRole("button", { name: "管理 operator 的访问密钥" })).toBeTruthy();
    expect(screen.getByText("第 2 页")).toBeTruthy();
    expect(listUsers).toHaveBeenLastCalledWith(credential, "users-page-2");
    await user.click(screen.getByRole("button", { name: "首页" }));
    expect(await screen.findByRole("button", { name: "管理 developer 的访问密钥" })).toBeTruthy();
    expect(listUsers).toHaveBeenLastCalledWith(credential, undefined);
  });

  it("retains one live key creation across view unmount and login, then unlocks only after recovered-key retirement is acknowledged", async () => {
    const key = { id: "mak1.lost-secret", accountId: account.id, userId: childUser.id, status: "DISABLED" as const,
      networkRestrictions: { allowedSourceCidrs: [] },
      resourceVersion: 2, createdAt: timestamp, updatedAt: timestamp };
    const create = vi.fn().mockRejectedValueOnce(new HttpProblem(503, "IAM_UNAVAILABLE"))
      .mockResolvedValueOnce({ outcome: "EQUAL_REPLAY", key });
    const remove = vi.fn().mockResolvedValue({ outcome: "APPLIED", deletion: {
      id: key.id, accountId: account.id, userId: childUser.id, resourceVersion: 3, deletedAt: timestamp
    } });
    const otherIdentity = { ...childUser, id: "child-b", loginName: "other" };
    const otherUser = { user: otherIdentity, policyAttachments: [], capabilities: userCapabilities(otherIdentity) };
    const repository = accounts({
      listUsers: vi.fn().mockResolvedValue({ items: [child, otherUser], nextAfter: null }),
      accessKeys: { list: vi.fn(), read: vi.fn(), create, setStatus: vi.fn(), setNetworkRestrictions: vi.fn(), delete: remove }
    });
    const auth = iam();
    const user = userEvent.setup();
    const tree = () => <LocaleProvider><SessionProvider repository={auth}><AccountAccessProvider repository={repository}><AccessKeyIntentProbe /></AccountAccessProvider></SessionProvider></LocaleProvider>;
    const first = render(tree());
    await user.click(screen.getByRole("button", { name: "login-key-probe" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "create-original-key" }).hasAttribute("disabled")).toBe(false));
    await user.click(screen.getByRole("button", { name: "create-original-key" }));
    await waitFor(() => expect(screen.getByLabelText("key-create-intent").textContent).toBe(`unknown:${childUser.id}:${originalKeyRequestId}`));
    await user.click(screen.getByRole("button", { name: "create-new-key" }));
    await user.click(screen.getByRole("button", { name: "create-other-user-key" }));
    expect(create).toHaveBeenCalledTimes(1);
    await user.click(screen.getByRole("button", { name: "toggle-key-view" }));
    await user.click(screen.getByRole("button", { name: "toggle-key-view" }));
    expect(screen.getByLabelText("key-create-intent").textContent).toBe(`unknown:${childUser.id}:${originalKeyRequestId}`);
    first.unmount();

    render(tree());
    await user.click(screen.getByRole("button", { name: "login-key-probe" }));
    await waitFor(() => expect(screen.getByLabelText("key-create-intent").textContent).toBe(`unknown:${childUser.id}:${originalKeyRequestId}`));
    await user.click(screen.getByRole("button", { name: "create-original-key" }));
    await waitFor(() => expect(screen.getByLabelText("key-create-intent").textContent).toBe(`recovered:${childUser.id}:${originalKeyRequestId}`));
    expect(create).toHaveBeenCalledTimes(2);
    expect(create.mock.calls[0]?.[3]).toEqual(create.mock.calls[1]?.[3]);
    await user.click(screen.getByRole("button", { name: "create-new-key" }));
    expect(create).toHaveBeenCalledTimes(2);
    await user.click(screen.getByRole("button", { name: "retire-recovered-key" }));
    await waitFor(() => expect(screen.getByLabelText("key-mutation-intent").textContent).toBe(`completed:delete:${childUser.id}:${originalKeyDeleteRequestId}`));
    expect(screen.getByLabelText("key-create-intent").textContent).toBe(`recovered:${childUser.id}:${originalKeyRequestId}`);
    await user.click(screen.getByRole("button", { name: "acknowledge-key-mutation" }));
    await waitFor(() => expect(screen.getByLabelText("key-create-intent").textContent).toBe("none"));
    expect(screen.getByLabelText("key-mutation-intent").textContent).toBe("none");
    expect(remove).toHaveBeenCalledWith(credential, account.id, childUser.id, key.id, expect.anything());
  });

  it("keeps an applied key locked until its one-time Secret is acknowledged", async () => {
    const key = { id: "mak1.lost-secret", accountId: account.id, userId: childUser.id, status: "DISABLED" as const,
      networkRestrictions: { allowedSourceCidrs: [] },
      resourceVersion: 2, createdAt: timestamp, updatedAt: timestamp };
    const create = vi.fn().mockResolvedValue({ outcome: "APPLIED", key, secret: "test-only-one-time-secret" });
    const repository = accounts({ accessKeys: { list: vi.fn(), read: vi.fn(), create, setStatus: vi.fn(), setNetworkRestrictions: vi.fn(), delete: vi.fn() } });
    const auth = iam();
    const user = userEvent.setup();
    const tree = () => <LocaleProvider><SessionProvider repository={auth}><AccountAccessProvider repository={repository}><AccessKeyIntentProbe /></AccountAccessProvider></SessionProvider></LocaleProvider>;
    render(tree());
    await user.click(screen.getByRole("button", { name: "login-key-probe" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "create-original-key" }).hasAttribute("disabled")).toBe(false));
    await user.click(screen.getByRole("button", { name: "create-original-key" }));
    await waitFor(() => expect(screen.getByLabelText("key-create-intent").textContent).toBe(`recovered:${childUser.id}:${originalKeyRequestId}`));
    await user.click(screen.getByRole("button", { name: "create-new-key" }));
    expect(create).toHaveBeenCalledTimes(1);
    await user.click(screen.getByRole("button", { name: "acknowledge-issued-key" }));
    await waitFor(() => expect(screen.getByLabelText("key-create-intent").textContent).toBe("none"));
    expect(sessionStorage.length).toBe(0);
  });

  it("treats an applied Secret as lost after page loss and requires the recovered key to be retired", async () => {
    const key = { id: "mak1.lost-secret", accountId: account.id, userId: childUser.id, status: "DISABLED" as const,
      networkRestrictions: { allowedSourceCidrs: [] },
      resourceVersion: 2, createdAt: timestamp, updatedAt: timestamp };
    const create = vi.fn().mockResolvedValue({ outcome: "APPLIED", key, secret: "test-only-one-time-secret" });
    const remove = vi.fn().mockResolvedValue({ outcome: "APPLIED", deletion: {
      id: key.id, accountId: account.id, userId: childUser.id, resourceVersion: 3, deletedAt: timestamp
    } });
    const repository = accounts({ accessKeys: { list: vi.fn(), read: vi.fn(), create, setStatus: vi.fn(), setNetworkRestrictions: vi.fn(), delete: remove } });
    const auth = iam();
    const user = userEvent.setup();
    const tree = () => <LocaleProvider><SessionProvider repository={auth}><AccountAccessProvider repository={repository}><AccessKeyIntentProbe /></AccountAccessProvider></SessionProvider></LocaleProvider>;
    const first = render(tree());
    await user.click(screen.getByRole("button", { name: "login-key-probe" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "create-original-key" }).hasAttribute("disabled")).toBe(false));
    await user.click(screen.getByRole("button", { name: "create-original-key" }));
    await waitFor(() => expect(screen.getByLabelText("key-create-intent").textContent).toBe(`recovered:${childUser.id}:${originalKeyRequestId}`));
    first.unmount();

    render(tree());
    await user.click(screen.getByRole("button", { name: "login-key-probe" }));
    await waitFor(() => expect(screen.getByLabelText("key-create-intent").textContent).toBe(`recovered:${childUser.id}:${originalKeyRequestId}`));
    await user.click(screen.getByRole("button", { name: "acknowledge-issued-key" }));
    expect(screen.getByLabelText("key-create-intent").textContent).toBe(`recovered:${childUser.id}:${originalKeyRequestId}`);
    await user.click(screen.getByRole("button", { name: "retire-recovered-key" }));
    await waitFor(() => expect(screen.getByLabelText("key-mutation-intent").textContent).toBe(`completed:delete:${childUser.id}:${originalKeyDeleteRequestId}`));
    expect(screen.getByLabelText("key-create-intent").textContent).toBe(`recovered:${childUser.id}:${originalKeyRequestId}`);
    await user.click(screen.getByRole("button", { name: "acknowledge-key-mutation" }));
    await waitFor(() => expect(screen.getByLabelText("key-create-intent").textContent).toBe("none"));
    expect(screen.getByLabelText("key-mutation-intent").textContent).toBe("none");
  });

  it("persists an uncertain recovered-key deletion before the response can be lost", async () => {
    const key = { id: "mak1.lost-secret", accountId: account.id, userId: childUser.id, status: "DISABLED" as const,
      networkRestrictions: { allowedSourceCidrs: [] },
      resourceVersion: 2, createdAt: timestamp, updatedAt: timestamp };
    const create = vi.fn().mockResolvedValue({ outcome: "APPLIED", key, secret: "test-only-one-time-secret" });
    const remove = vi.fn().mockRejectedValue(new HttpProblem(503, "IAM_UNAVAILABLE"));
    const repository = accounts({ accessKeys: { list: vi.fn(), read: vi.fn(), create, setStatus: vi.fn(), setNetworkRestrictions: vi.fn(), delete: remove } });
    const auth = iam();
    const user = userEvent.setup();
    render(<LocaleProvider><SessionProvider repository={auth}><AccountAccessProvider repository={repository}><AccessKeyIntentProbe /></AccountAccessProvider></SessionProvider></LocaleProvider>);

    await user.click(screen.getByRole("button", { name: "login-key-probe" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "create-original-key" }).hasAttribute("disabled")).toBe(false));
    await user.click(screen.getByRole("button", { name: "create-original-key" }));
    await waitFor(() => expect(screen.getByLabelText("key-create-intent").textContent).toBe(`recovered:${childUser.id}:${originalKeyRequestId}`));
    await user.click(screen.getByRole("button", { name: "retire-recovered-key" }));
    await waitFor(() => expect(remove).toHaveBeenCalledOnce());

    const raw = sessionStorage.getItem(`matrix-iam-access-key-mutation:v1:${encodeURIComponent(account.id)}:${encodeURIComponent(rootUser.id)}`);
    expect(raw && JSON.parse(raw)).toEqual({
      accountId: account.id,
      actorId: rootUser.id,
      userId: childUser.id,
      accessKeyId: key.id,
      accessKeyResourceVersion: key.resourceVersion,
      operation: "delete",
      requestId: originalKeyDeleteRequestId,
      phase: "unknown"
    });
    await user.click(screen.getByRole("button", { name: "retire-recovered-key-new-intent" }));
    expect(remove).toHaveBeenCalledOnce();
    expect(sessionStorage.getItem(`matrix-iam-access-key-mutation:v1:${encodeURIComponent(account.id)}:${encodeURIComponent(rootUser.id)}`)).toBe(raw);
  });

  it.each([
    { label: "status", button: "disable-key", requestId: originalKeyStatusRequestId, operation: "set-status" as const },
    { label: "network", button: "restrict-key-network", requestId: originalKeyNetworkRequestId, operation: "set-network-restrictions" as const },
    { label: "delete", button: "retire-recovered-key", requestId: originalKeyDeleteRequestId, operation: "delete" as const }
  ])("restores and explicitly replays one uncertain AccessKey $label intent after login", async ({ button, requestId, operation }) => {
    const changedKey = { id: "mak1.lost-secret", accountId: account.id, userId: childUser.id, status: "DISABLED" as const,
      networkRestrictions: operation === "set-network-restrictions" ? { allowedSourceCidrs: ["203.0.113.0/24"] } : { allowedSourceCidrs: [] },
      resourceVersion: 3, createdAt: timestamp, updatedAt: timestamp };
    const setStatus = vi.fn().mockRejectedValueOnce(new HttpProblem(503, "IAM_UNAVAILABLE"))
      .mockResolvedValueOnce({ outcome: "EQUAL_REPLAY", key: changedKey });
    const setNetworkRestrictions = vi.fn().mockRejectedValueOnce(new HttpProblem(503, "IAM_UNAVAILABLE"))
      .mockResolvedValueOnce({ outcome: "EQUAL_REPLAY", key: changedKey });
    const remove = vi.fn().mockRejectedValueOnce(new HttpProblem(503, "IAM_UNAVAILABLE"))
      .mockResolvedValueOnce({ outcome: "EQUAL_REPLAY", deletion: { id: changedKey.id, accountId: account.id, userId: childUser.id, resourceVersion: 3, deletedAt: timestamp } });
    const repository = accounts({ accessKeys: { list: vi.fn(), read: vi.fn(), create: vi.fn(), setStatus, setNetworkRestrictions, delete: remove } });
    const auth = iam();
    const user = userEvent.setup();
    const tree = () => <LocaleProvider><SessionProvider repository={auth}><AccountAccessProvider repository={repository}><AccessKeyIntentProbe /></AccountAccessProvider></SessionProvider></LocaleProvider>;
    const first = render(tree());
    await user.click(screen.getByRole("button", { name: "login-key-probe" }));
    await waitFor(() => expect(screen.getByRole("button", { name: button }).hasAttribute("disabled")).toBe(false));
    await user.click(screen.getByRole("button", { name: button }));
    await waitFor(() => expect(screen.getByLabelText("key-mutation-intent").textContent).toBe(`unknown:${operation}:${childUser.id}:${requestId}`));
    first.unmount();

    render(tree());
    await user.click(screen.getByRole("button", { name: "login-key-probe" }));
    await waitFor(() => expect(screen.getByLabelText("key-mutation-intent").textContent).toBe(`unknown:${operation}:${childUser.id}:${requestId}`));
    await user.click(screen.getByRole("button", { name: button }));
    await waitFor(() => expect(screen.getByLabelText("key-mutation-intent").textContent).toBe(`completed:${operation}:${childUser.id}:${requestId}`));

    const invoked = operation === "set-status" ? setStatus : operation === "set-network-restrictions" ? setNetworkRestrictions : remove;
    expect(invoked).toHaveBeenCalledTimes(2);
    expect(invoked.mock.calls[0]).toEqual(invoked.mock.calls[1]);
    await user.click(screen.getByRole("button", { name: "acknowledge-key-mutation" }));
    await waitFor(() => expect(screen.getByLabelText("key-mutation-intent").textContent).toBe("none"));
  });

  it.each(["success", "unauthorized"] as const)("rejects a late AccessKey create %s from an unmounted Session owner", async (outcome) => {
    const lateKey = { id: "mak1.late-old-session", accountId: account.id, userId: childUser.id, status: "ENABLED" as const,
      credentialState: "CURRENT" as const, networkRestrictions: { allowedSourceCidrs: [] }, resourceVersion: 1, createdAt: timestamp, updatedAt: timestamp };
    let resolveOld!: (value: { outcome: "APPLIED"; key: typeof lateKey; secret: string }) => void;
    let rejectOld!: (reason: unknown) => void;
    const oldCreate = vi.fn(() => new Promise<{ outcome: "APPLIED"; key: typeof lateKey; secret: string }>((resolve, reject) => { resolveOld = resolve; rejectOld = reject; }));
    const oldRepository = accounts({ accessKeys: { list: vi.fn(), read: vi.fn(), create: oldCreate, setStatus: vi.fn(), setNetworkRestrictions: vi.fn(), delete: vi.fn() } });
    const newRepository = accounts({ accessKeys: { list: vi.fn(), read: vi.fn(), create: vi.fn(), setStatus: vi.fn(), setNetworkRestrictions: vi.fn(), delete: vi.fn() } });
    const auth = iam();
    const user = userEvent.setup();
    const tree = (repository: AccountRepository) => <LocaleProvider><SessionProvider repository={auth}><AccountAccessProvider repository={repository}><AccessKeyIntentProbe /></AccountAccessProvider></SessionProvider></LocaleProvider>;
    const first = render(tree(oldRepository));
    await user.click(screen.getByRole("button", { name: "login-key-probe" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "create-original-key" }).hasAttribute("disabled")).toBe(false));
    await user.click(screen.getByRole("button", { name: "create-original-key" }));
    await waitFor(() => expect(screen.getByLabelText("key-create-intent").textContent).toBe(`unknown:${childUser.id}:${originalKeyRequestId}`));
    first.unmount();

    render(tree(newRepository));
    await user.click(screen.getByRole("button", { name: "login-key-probe" }));
    await waitFor(() => expect(screen.getByLabelText("key-create-intent").textContent).toBe(`unknown:${childUser.id}:${originalKeyRequestId}`));
    await act(async () => {
      if (outcome === "success") resolveOld({ outcome: "APPLIED", key: lateKey, secret: "late-secret-must-not-surface" });
      else rejectOld(new HttpProblem(401, "SESSION_EXPIRED"));
    });

    const stored = sessionStorage.getItem(`matrix-iam-access-key-create:v1:${encodeURIComponent(account.id)}:${encodeURIComponent(rootUser.id)}`);
    expect(stored && JSON.parse(stored)).toEqual(expect.objectContaining({ phase: "unknown", requestId: originalKeyRequestId }));
    expect(screen.getByLabelText("key-create-intent").textContent).toBe(`unknown:${childUser.id}:${originalKeyRequestId}`);
    expect(screen.queryByText("late-secret-must-not-surface")).toBeNull();
  });

  it.each(["success", "unauthorized"] as const)("rejects a late recovered-key delete %s from an unmounted Session owner", async (outcome) => {
    const recoveredKey = { id: "mak1.lost-secret", accountId: account.id, userId: childUser.id, status: "DISABLED" as const,
      credentialState: "CURRENT" as const, networkRestrictions: { allowedSourceCidrs: [] }, resourceVersion: 2, createdAt: timestamp, updatedAt: timestamp };
    const deletion = { id: recoveredKey.id, accountId: account.id, userId: childUser.id, resourceVersion: 3, deletedAt: timestamp };
    let resolveOld!: (value: { outcome: "APPLIED"; deletion: typeof deletion }) => void;
    let rejectOld!: (reason: unknown) => void;
    const oldDelete = vi.fn(() => new Promise<{ outcome: "APPLIED"; deletion: typeof deletion }>((resolve, reject) => { resolveOld = resolve; rejectOld = reject; }));
    const newDelete = vi.fn().mockResolvedValue({ outcome: "EQUAL_REPLAY", deletion });
    const oldRepository = accounts({ accessKeys: {
      list: vi.fn(), read: vi.fn(), create: vi.fn().mockResolvedValue({ outcome: "APPLIED", key: recoveredKey, secret: "one-time-secret" }),
      setStatus: vi.fn(), setNetworkRestrictions: vi.fn(), delete: oldDelete
    } });
    const newRepository = accounts({ accessKeys: {
      list: vi.fn(), read: vi.fn(), create: vi.fn(), setStatus: vi.fn(), setNetworkRestrictions: vi.fn(), delete: newDelete
    } });
    const auth = iam();
    const user = userEvent.setup();
    const tree = (repository: AccountRepository) => <LocaleProvider><SessionProvider repository={auth}><AccountAccessProvider repository={repository}><AccessKeyIntentProbe /></AccountAccessProvider></SessionProvider></LocaleProvider>;
    const first = render(tree(oldRepository));
    await user.click(screen.getByRole("button", { name: "login-key-probe" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "create-original-key" }).hasAttribute("disabled")).toBe(false));
    await user.click(screen.getByRole("button", { name: "create-original-key" }));
    await waitFor(() => expect(screen.getByLabelText("key-create-intent").textContent).toBe(`recovered:${childUser.id}:${originalKeyRequestId}`));
    await user.click(screen.getByRole("button", { name: "retire-recovered-key" }));
    await waitFor(() => expect(screen.getByLabelText("key-mutation-intent").textContent).toBe(`unknown:delete:${childUser.id}:${originalKeyDeleteRequestId}`));
    first.unmount();

    render(tree(newRepository));
    await user.click(screen.getByRole("button", { name: "login-key-probe" }));
    await waitFor(() => expect(screen.getByLabelText("key-mutation-intent").textContent).toBe(`unknown:delete:${childUser.id}:${originalKeyDeleteRequestId}`));
    await act(async () => {
      if (outcome === "success") resolveOld({ outcome: "APPLIED", deletion });
      else rejectOld(new HttpProblem(401, "SESSION_EXPIRED"));
    });

    expect(screen.getByLabelText("key-probe-session").textContent).toContain("authenticated");
    expect(screen.getByLabelText("key-create-intent").textContent).toBe(`recovered:${childUser.id}:${originalKeyRequestId}`);
    expect(screen.getByLabelText("key-mutation-intent").textContent).toBe(`unknown:delete:${childUser.id}:${originalKeyDeleteRequestId}`);
    await user.click(screen.getByRole("button", { name: "retire-recovered-key" }));
    await waitFor(() => expect(screen.getByLabelText("key-mutation-intent").textContent).toBe(`completed:delete:${childUser.id}:${originalKeyDeleteRequestId}`));
    expect(newDelete).toHaveBeenCalledOnce();
    await user.click(screen.getByRole("button", { name: "acknowledge-key-mutation" }));
    await waitFor(() => expect(screen.getByLabelText("key-mutation-intent").textContent).toBe("none"));
    expect(screen.getByLabelText("key-create-intent").textContent).toBe("none");
  });

  it("fails closed for foreign or malformed stored AccessKey mutation bindings", async () => {
    const valid = {
      accountId: account.id, actorId: rootUser.id, userId: childUser.id, accessKeyId: "mak1.lost-secret",
      accessKeyResourceVersion: 2, operation: "delete", requestId: originalKeyDeleteRequestId, phase: "unknown"
    };
    const invalid = [
      { ...valid, accountId: "tenant-foreign" },
      { ...valid, actorId: "principal-foreign" },
      { ...valid, userId: "invalid user" },
      { ...valid, accessKeyResourceVersion: 0 },
      { ...valid, requestId: replacementKeyDeleteRequestId, unexpected: true }
    ];
    const storageKey = `matrix-iam-access-key-mutation:v1:${encodeURIComponent(account.id)}:${encodeURIComponent(rootUser.id)}`;
    for (const record of invalid) {
      sessionStorage.clear();
      sessionStorage.setItem(storageKey, JSON.stringify(record));
      const remove = vi.fn();
      const repository = accounts({ accessKeys: { list: vi.fn(), read: vi.fn(), create: vi.fn(), setStatus: vi.fn(), setNetworkRestrictions: vi.fn(), delete: remove } });
      const user = userEvent.setup();
      const view = render(<LocaleProvider><SessionProvider repository={iam()}><AccountAccessProvider repository={repository}><AccessKeyIntentProbe /></AccountAccessProvider></SessionProvider></LocaleProvider>);
      await user.click(screen.getByRole("button", { name: "login-key-probe" }));
      await waitFor(() => expect(screen.getByRole("button", { name: "create-original-key" }).hasAttribute("disabled")).toBe(false));
      expect(screen.getByLabelText("key-mutation-intent").textContent).toBe("none");
      expect(remove).not.toHaveBeenCalled();
      view.unmount();
    }
  });

  it.each(["read", "write"] as const)("does not dispatch an AccessKey mutation when intent storage %s fails", async (failure) => {
    const storagePrefix = "matrix-iam-access-key-mutation:v1:";
    const originalRead = Storage.prototype.getItem;
    const originalWrite = Storage.prototype.setItem;
    let storageFault: ReturnType<typeof vi.spyOn> | null = null;
    const setStatus = vi.fn().mockResolvedValue({ outcome: "APPLIED", key: {
      id: "mak1.lost-secret", accountId: account.id, userId: childUser.id, status: "DISABLED" as const,
      credentialState: "CURRENT" as const, networkRestrictions: { allowedSourceCidrs: [] },
      resourceVersion: 3, createdAt: timestamp, updatedAt: timestamp
    } });
    const repository = accounts({ accessKeys: { list: vi.fn(), read: vi.fn(), create: vi.fn(), setStatus, setNetworkRestrictions: vi.fn(), delete: vi.fn() } });
    const user = userEvent.setup();

    try {
      if (failure === "read") {
        storageFault = vi.spyOn(Storage.prototype, "getItem").mockImplementation(function(this: Storage, key: string) {
          if (key.startsWith(storagePrefix)) throw new Error("storage read blocked");
          return originalRead.call(this, key);
        });
      }
      render(<LocaleProvider><SessionProvider repository={iam()}><AccountAccessProvider repository={repository}><AccessKeyIntentProbe /></AccountAccessProvider></SessionProvider></LocaleProvider>);
      await user.click(screen.getByRole("button", { name: "login-key-probe" }));
      await waitFor(() => expect(screen.getByRole("button", { name: "disable-key" }).hasAttribute("disabled")).toBe(false));
      if (failure === "write") {
        await waitFor(() => expect(screen.getByLabelText("key-recovery-error").textContent).toBe("false"));
        storageFault = vi.spyOn(Storage.prototype, "setItem").mockImplementation(function(this: Storage, key: string, value: string) {
          if (key.startsWith(storagePrefix)) throw new Error("storage write blocked");
          return originalWrite.call(this, key, value);
        });
      }

      await user.click(screen.getByRole("button", { name: "disable-key" }));

      await waitFor(() => expect(screen.getByLabelText("key-recovery-error").textContent).toBe("true"));
      expect(setStatus).not.toHaveBeenCalled();
    } finally {
      storageFault?.mockRestore();
    }
  });

  it("does not replace a malformed stored AccessKey mutation with a new write", async () => {
    const storageKey = `matrix-iam-access-key-mutation:v1:${encodeURIComponent(account.id)}:${encodeURIComponent(rootUser.id)}`;
    const malformed = JSON.stringify({
      accountId: account.id,
      actorId: rootUser.id,
      userId: childUser.id,
      accessKeyId: "mak1.lost-secret",
      accessKeyResourceVersion: 2,
      operation: "delete",
      requestId: originalKeyDeleteRequestId,
      phase: "unknown",
      unexpected: true
    });
    sessionStorage.setItem(storageKey, malformed);
    const setStatus = vi.fn();
    const repository = accounts({ accessKeys: { list: vi.fn(), read: vi.fn(), create: vi.fn(), setStatus, setNetworkRestrictions: vi.fn(), delete: vi.fn() } });
    const user = userEvent.setup();
    render(<LocaleProvider><SessionProvider repository={iam()}><AccountAccessProvider repository={repository}><AccessKeyIntentProbe /></AccountAccessProvider></SessionProvider></LocaleProvider>);

    await user.click(screen.getByRole("button", { name: "login-key-probe" }));
    await waitFor(() => expect(screen.getByLabelText("key-recovery-error").textContent).toBe("true"));
    await user.click(screen.getByRole("button", { name: "disable-key" }));

    expect(setStatus).not.toHaveBeenCalled();
    expect(sessionStorage.getItem(storageKey)).toBe(malformed);
  });

  it("does not dispatch an AccessKey create before its intent is durably stored", async () => {
    const storagePrefix = "matrix-iam-access-key-create:v1:";
    const originalWrite = Storage.prototype.setItem;
    const create = vi.fn();
    const repository = accounts({ accessKeys: { list: vi.fn(), read: vi.fn(), create, setStatus: vi.fn(), setNetworkRestrictions: vi.fn(), delete: vi.fn() } });
    const user = userEvent.setup();
    render(<LocaleProvider><SessionProvider repository={iam()}><AccountAccessProvider repository={repository}><AccessKeyIntentProbe /></AccountAccessProvider></SessionProvider></LocaleProvider>);
    await user.click(screen.getByRole("button", { name: "login-key-probe" }));
    await waitFor(() => expect(screen.getByLabelText("key-recovery-error").textContent).toBe("false"));
    const storageFault = vi.spyOn(Storage.prototype, "setItem").mockImplementation(function(this: Storage, key: string, value: string) {
      if (key.startsWith(storagePrefix)) throw new Error("storage write blocked");
      return originalWrite.call(this, key, value);
    });

    try {
      await user.click(screen.getByRole("button", { name: "create-original-key" }));
      await waitFor(() => expect(screen.getByLabelText("key-recovery-error").textContent).toBe("true"));
      expect(create).not.toHaveBeenCalled();
      expect(screen.getByLabelText("key-create-intent").textContent).toBe("none");
    } finally {
      storageFault.mockRestore();
    }
  });

  it("keeps a recovered AccessKey create locked when clearing its intent storage fails", async () => {
    const storagePrefix = "matrix-iam-access-key-create:v1:";
    const storageKey = `${storagePrefix}${encodeURIComponent(account.id)}:${encodeURIComponent(rootUser.id)}`;
    const key = { id: "mak1.lost-secret", accountId: account.id, userId: childUser.id, status: "DISABLED" as const,
      credentialState: "CURRENT" as const, networkRestrictions: { allowedSourceCidrs: [] }, resourceVersion: 2, createdAt: timestamp, updatedAt: timestamp };
    const create = vi.fn().mockResolvedValue({ outcome: "APPLIED", key, secret: "test-only-one-time-secret" });
    const repository = accounts({ accessKeys: { list: vi.fn(), read: vi.fn(), create, setStatus: vi.fn(), setNetworkRestrictions: vi.fn(), delete: vi.fn() } });
    const user = userEvent.setup();
    render(<LocaleProvider><SessionProvider repository={iam()}><AccountAccessProvider repository={repository}><AccessKeyIntentProbe /></AccountAccessProvider></SessionProvider></LocaleProvider>);
    await user.click(screen.getByRole("button", { name: "login-key-probe" }));
    await waitFor(() => expect(screen.getByLabelText("key-recovery-error").textContent).toBe("false"));
    await user.click(screen.getByRole("button", { name: "create-original-key" }));
    await waitFor(() => expect(screen.getByLabelText("key-create-intent").textContent).toBe(`recovered:${childUser.id}:${originalKeyRequestId}`));
    const originalRemove = Storage.prototype.removeItem;
    const storageFault = vi.spyOn(Storage.prototype, "removeItem").mockImplementation(function(this: Storage, storageItem: string) {
      if (storageItem.startsWith(storagePrefix)) throw new Error("storage clear blocked");
      return originalRemove.call(this, storageItem);
    });

    try {
      await user.click(screen.getByRole("button", { name: "acknowledge-issued-key" }));
      await waitFor(() => expect(screen.getByLabelText("key-recovery-error").textContent).toBe("true"));
      expect(screen.getByLabelText("key-create-intent").textContent).toBe(`recovered:${childUser.id}:${originalKeyRequestId}`);
      expect(sessionStorage.getItem(storageKey)).not.toBeNull();
    } finally {
      storageFault.mockRestore();
    }
  });

  it("keeps a completed AccessKey mutation locked when clearing its intent storage fails", async () => {
    const storagePrefix = "matrix-iam-access-key-mutation:v1:";
    const storageKey = `${storagePrefix}${encodeURIComponent(account.id)}:${encodeURIComponent(rootUser.id)}`;
    const changedKey = { id: "mak1.lost-secret", accountId: account.id, userId: childUser.id, status: "DISABLED" as const,
      credentialState: "CURRENT" as const, networkRestrictions: { allowedSourceCidrs: [] }, resourceVersion: 3, createdAt: timestamp, updatedAt: timestamp };
    const setStatus = vi.fn().mockResolvedValue({ outcome: "APPLIED", key: changedKey });
    const repository = accounts({ accessKeys: { list: vi.fn(), read: vi.fn(), create: vi.fn(), setStatus, setNetworkRestrictions: vi.fn(), delete: vi.fn() } });
    const user = userEvent.setup();
    render(<LocaleProvider><SessionProvider repository={iam()}><AccountAccessProvider repository={repository}><AccessKeyIntentProbe /></AccountAccessProvider></SessionProvider></LocaleProvider>);
    await user.click(screen.getByRole("button", { name: "login-key-probe" }));
    await waitFor(() => expect(screen.getByLabelText("key-recovery-error").textContent).toBe("false"));
    await user.click(screen.getByRole("button", { name: "disable-key" }));
    await waitFor(() => expect(screen.getByLabelText("key-mutation-intent").textContent).toBe(`completed:set-status:${childUser.id}:${originalKeyStatusRequestId}`));
    const originalRemove = Storage.prototype.removeItem;
    const storageFault = vi.spyOn(Storage.prototype, "removeItem").mockImplementation(function(this: Storage, storageItem: string) {
      if (storageItem.startsWith(storagePrefix)) throw new Error("storage clear blocked");
      return originalRemove.call(this, storageItem);
    });

    try {
      await user.click(screen.getByRole("button", { name: "acknowledge-key-mutation" }));
      await waitFor(() => expect(screen.getByLabelText("key-recovery-error").textContent).toBe("true"));
      expect(screen.getByLabelText("key-mutation-intent").textContent).toBe(`completed:set-status:${childUser.id}:${originalKeyStatusRequestId}`);
      expect(sessionStorage.getItem(storageKey)).not.toBeNull();
    } finally {
      storageFault.mockRestore();
    }
  });

  it("updates only the display name through the live user revision", async () => {
    const repository = accounts();
    const { user } = await openAccess(repository);
    await user.click(await screen.findByRole("button", { name: "查看用户 developer" }));
    await user.click(await screen.findByRole("button", { name: "修改显示名称" }));
    const field = screen.getByLabelText("用户显示名称");
    await user.clear(field);
    await user.type(field, "Developer Renamed");
    await user.click(screen.getByRole("button", { name: "审阅更改" }));
    expect(repository.userManagement!.submit).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "保存显示名称" }));
    await waitFor(() => expect(repository.userManagement!.submit).toHaveBeenCalledWith(credential, expect.objectContaining({ accountId: account.id, actorPrincipalId: identity.user.id, operation: "USER_UPDATE", userId: "child-a", intendedDisplayName: "Developer Renamed", expectedResourceVersion: 2, commandRequestId: expect.stringMatching(/^ui-user-management-/) })));
    expect(repository.execute).not.toHaveBeenCalled();
  });

  it("guards an unsubmitted LIVE name draft and restores its source action after explicit cancellation", async () => {
    const repository = accounts(); const { user } = await openAccess(repository);
    await user.click(await screen.findByRole("button", { name: "查看用户 developer" })); await user.click(await screen.findByRole("button", { name: "修改显示名称" }));
    await user.clear(screen.getByLabelText("用户显示名称")); await user.type(screen.getByLabelText("用户显示名称"), "Unsubmitted name");
    await user.click(screen.getByTestId("nav-policies"));
    await user.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "继续编辑" }));
    expect(screen.getByLabelText("用户显示名称")).toHaveProperty("value", "Unsubmitted name");
    await user.click(screen.getByRole("button", { name: "取消" }));
    await user.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "放弃并离开" }));
    expect(await screen.findByRole("button", { name: "修改显示名称" })).toBe(document.activeElement);
    expect(repository.userManagement!.submit).not.toHaveBeenCalled(); expect(repository.userManagement!.readCompletion).not.toHaveBeenCalled(); expect(sessionStorage.length).toBe(0);
  });

  it("explains read-only User controls when original-result recovery is unavailable without falling back to generic writes", async () => {
    const repository = accounts({ userManagement: undefined }); const { user } = await openAccess(repository);
    await user.click(await screen.findByRole("button", { name: "查看用户 developer" }));
    expect(await screen.findByText("当前环境未提供用户变更的安全结果恢复能力，资料与状态操作暂为只读。")).toBeTruthy();
    expect(screen.getByRole("button", { name: "修改显示名称" })).toHaveProperty("disabled", true); expect(screen.getByRole("button", { name: "禁用用户" })).toHaveProperty("disabled", true);
    expect(repository.execute).not.toHaveBeenCalled();
  });

  it("explains an unreadable original User reminder before disabling new changes", async () => {
    const getItem = Storage.prototype.getItem;
    const fault = vi.spyOn(Storage.prototype, "getItem").mockImplementation(function(this: Storage, key: string) {
      if (key.startsWith("matrix.iam.user-management.v1:")) throw new Error("storage blocked");
      return getItem.call(this, key);
    });
    try {
      const repository = accounts(); const { user } = await openAccess(repository); await user.click(await screen.findByRole("button", { name: "查看用户 developer" }));
      expect(await screen.findByText(/无法安全读取或保存原请求提醒/)).toBeTruthy();
      expect(screen.getByRole("button", { name: "修改显示名称" })).toHaveProperty("disabled", true); expect(screen.getByRole("button", { name: "禁用用户" })).toHaveProperty("disabled", true);
      expect(repository.userManagement!.submit).not.toHaveBeenCalled(); expect(repository.execute).not.toHaveBeenCalled();
    } finally { fault.mockRestore(); }
  });

  it("checks an original User result by known locator without requiring current detail or directory authority", async () => {
    const intent: UserManagementIntent = { format: 1, accountId: account.id, actorPrincipalId: identity.user.id, userId: childUser.id, commandRequestId: "lost-user-rename", expectedResourceVersion: childUser.resourceVersion, operation: "USER_UPDATE", intendedDisplayName: "Original renamed user" };
    writeUserManagementIntent(sessionStorage, intent);
    const reader = { ...identity, capabilities: identity.capabilities.map((item) => item.action === "iam.user.list" ? { ...item, available: false, restrictionReason: "AUTHORITY_REQUIRED" as const } : item) };
    const readCompletion = vi.fn().mockResolvedValue({ accountId: account.id, actorPrincipalId: identity.user.id, userId: childUser.id, commandRequestId: intent.commandRequestId, expectedResourceVersion: intent.expectedResourceVersion, operation: intent.operation,
      result: { ...childUser, displayName: intent.intendedDisplayName, resourceVersion: intent.expectedResourceVersion + 1 }, eventId: "original-user-event", occurredAt: timestamp });
    const repository = accounts({ currentIdentity: vi.fn().mockResolvedValue(reader), getUser: vi.fn().mockRejectedValue(new HttpProblem(403, "PRIVATE USER READ")), userManagement: { submit: vi.fn(), readCompletion } });
    const { user, view } = await openAccess(repository, iam(), "users", credential, childUser.id);
    await screen.findByRole("button", { name: "查询原请求结果" });
    expect(readCompletion).not.toHaveBeenCalled(); expect(repository.listUsers).not.toHaveBeenCalled(); expect(repository.userManagement!.submit).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "查询原请求结果" }));
    expect(await screen.findByRole("status", { name: "已确认原用户变更" })).toBeTruthy();
    expect(readCompletion).toHaveBeenCalledExactlyOnceWith(credential, intent);
    await waitFor(() => expect(repository.getUser).toHaveBeenCalledTimes(2));
    expect(screen.getByRole("button", { name: "重试读取" })).toBeTruthy();
    expect(view.container.textContent).not.toContain("PRIVATE USER READ");
    expect(readUserManagementIntent(sessionStorage, intent)).toBeNull(); expect(repository.userManagement!.submit).not.toHaveBeenCalled(); expect(repository.execute).not.toHaveBeenCalled();
  });

  it.each([403, 404, 409, 503])("retains one original User command after a %s lookup without a replacement or automatic write", async (status) => {
    const submit = vi.fn().mockRejectedValue(new Error("lost write response")); const readCompletion = vi.fn().mockRejectedValue(new HttpProblem(status, "PRIVATE LOOKUP"));
    const repository = accounts({ userManagement: { submit, readCompletion } }); const { user, view } = await openAccess(repository);
    await user.click(await screen.findByRole("button", { name: "查看用户 developer" })); await user.click(await screen.findByRole("button", { name: "禁用用户" }));
    await user.click(screen.getByRole("button", { name: "确认禁用" }));
    await screen.findByRole("button", { name: "查询原请求结果" });
    const intent = vi.mocked(submit).mock.calls[0]![1] as UserManagementIntent;
    expect(readUserManagementIntent(sessionStorage, intent)).toEqual(intent); expect(readCompletion).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "查询原请求结果" }));
    await waitFor(() => expect(readCompletion).toHaveBeenCalledExactlyOnceWith(credential, intent));
    const workflow = within(screen.getByRole("group", { name: /变更用户状态 · developer/ }));
    expect(workflow.getAllByText("尚未确认原请求结果，请勿再次提交其他更改。")).toHaveLength(1);
    expect(workflow.getByRole("button", { name: "稍后查询" })).toBeTruthy();
    expect(readUserManagementIntent(sessionStorage, intent)).toEqual(intent); expect(screen.queryByRole("button", { name: "确认禁用" })).toBeNull();
    expect(screen.queryByRole("button", { name: "修改显示名称" })).toBeNull(); expect(screen.queryByRole("status", { name: "已确认原用户变更" })).toBeNull();
    expect(submit).toHaveBeenCalledOnce(); expect(repository.execute).not.toHaveBeenCalled(); expect(view.container.textContent).not.toContain("PRIVATE LOOKUP");
    await user.click(screen.getByRole("button", { name: "返回用户列表" }));
    await user.click(await screen.findByRole("button", { name: "查看用户 developer" }));
    expect(await screen.findByRole("button", { name: "查询原请求结果" })).toBeTruthy();
    expect(readUserManagementIntent(sessionStorage, intent)).toEqual(intent); expect(submit).toHaveBeenCalledOnce(); expect(readCompletion).toHaveBeenCalledOnce();
  });

  it("retains a confirmed User change when its independent current read fails and only retries that read", async () => {
    const repository = accounts({ getUser: vi.fn().mockResolvedValueOnce(structuredClone(child)).mockRejectedValue(new HttpProblem(503, "READ UNAVAILABLE")) });
    const { user } = await openAccess(repository); await user.click(await screen.findByRole("button", { name: "查看用户 developer" }));
    await user.click(await screen.findByRole("button", { name: "禁用用户" })); await user.click(screen.getByRole("button", { name: "确认禁用" }));
    expect(await screen.findByRole("status", { name: "已确认原用户变更" })).toBeTruthy();
    await user.click(await screen.findByRole("button", { name: "重试读取" }));
    await waitFor(() => expect(repository.getUser).toHaveBeenCalledTimes(3));
    expect(screen.getByRole("status", { name: "已确认原用户变更" })).toBeTruthy();
    expect(screen.queryByText("正常", { exact: true })).toBeNull();
    expect(repository.userManagement!.submit).toHaveBeenCalledOnce(); expect(repository.userManagement!.readCompletion).not.toHaveBeenCalled(); expect(repository.execute).not.toHaveBeenCalled();
  });

  it("rereads a conflicting User revision and requires a fresh explicit status review and request", async () => {
    const newerUser: User = { ...childUser, resourceVersion: 3 };
    const newer = { ...child, user: newerUser, capabilities: userCapabilities(newerUser, child.policyAttachments) };
    const submit = vi.fn().mockRejectedValueOnce(new HttpProblem(409, "CONFLICT")).mockResolvedValue({ ...newerUser, resourceVersion: 4, status: "DISABLED" });
    const repository = accounts({ getUser: vi.fn().mockResolvedValueOnce(structuredClone(child)).mockResolvedValue(newer), userManagement: { submit, readCompletion: vi.fn() } });
    const { user } = await openAccess(repository); await user.click(await screen.findByRole("button", { name: "查看用户 developer" }));
    await user.click(await screen.findByRole("button", { name: "禁用用户" })); await user.click(screen.getByRole("button", { name: "确认禁用" }));
    await waitFor(() => expect(repository.getUser).toHaveBeenCalledTimes(2));
    expect(await screen.findByText("目标或当前权限已变化，请重新读取用户并审阅新的更改。")).toBeTruthy();
    expect(submit).toHaveBeenCalledOnce(); expect(sessionStorage.length).toBe(0); expect(repository.userManagement!.readCompletion).not.toHaveBeenCalled();
    await user.click(await screen.findByRole("button", { name: "禁用用户" }));
    expect(submit).toHaveBeenCalledOnce(); await user.click(screen.getByRole("button", { name: "确认禁用" }));
    await waitFor(() => expect(submit).toHaveBeenCalledTimes(2));
    const previous = submit.mock.calls[0]![1] as UserManagementIntent, next = submit.mock.calls[1]![1] as UserManagementIntent;
    expect(previous.expectedResourceVersion).toBe(2); expect(next.expectedResourceVersion).toBe(3); expect(next.commandRequestId).not.toBe(previous.commandRequestId);
  });

  it("expires the current Session on original User lookup 401 while retaining the non-secret reminder", async () => {
    const intent: UserManagementIntent = { format: 1, accountId: account.id, actorPrincipalId: identity.user.id, userId: childUser.id, commandRequestId: "lost-user-status", expectedResourceVersion: childUser.resourceVersion, operation: "USER_SET_STATUS", intendedStatus: "DISABLED" };
    writeUserManagementIntent(sessionStorage, intent); const repository = accounts({ userManagement: { submit: vi.fn(), readCompletion: vi.fn().mockRejectedValue(new HttpProblem(401, "EXPIRED")) } });
    const { user } = await openAccess(repository, iam(), "users", credential, childUser.id);
    await user.click(await screen.findByRole("button", { name: "查询原请求结果" }));
    expect(await screen.findByRole("button", { name: "登录控制台" })).toBeTruthy();
    expect(readUserManagementIntent(sessionStorage, intent)).toEqual(intent); expect(repository.userManagement!.submit).not.toHaveBeenCalled();
  });

  it("ignores a late User lookup 401 from an old repository without expiring or submitting for the replacement owner", async () => {
    const intent: UserManagementIntent = { format: 1, accountId: account.id, actorPrincipalId: identity.user.id, userId: childUser.id, commandRequestId: "old-owner-user-status", expectedResourceVersion: childUser.resourceVersion, operation: "USER_SET_STATUS", intendedStatus: "DISABLED" };
    writeUserManagementIntent(sessionStorage, intent); let reject!: (failure: unknown) => void;
    const previous = accounts({ userManagement: { submit: vi.fn(), readCompletion: vi.fn(() => new Promise<UserManagementCompletion>((_resolve, fail) => { reject = fail; })) } });
    const next = accounts(); const { user, replaceRepository } = await openAccess(previous, iam(), "users", credential, childUser.id);
    await user.click(await screen.findByRole("button", { name: "查询原请求结果" })); replaceRepository(next);
    await waitFor(() => expect(next.currentIdentity).toHaveBeenCalled());
    await act(async () => { reject(new HttpProblem(401, "OLD OWNER")); });
    await waitFor(() => expect(screen.getByRole("button", { name: "查询原请求结果" }).hasAttribute("disabled")).toBe(false));
    expect(screen.queryByRole("button", { name: "登录控制台" })).toBeNull(); expect(next.userManagement!.submit).not.toHaveBeenCalled(); expect(next.userManagement!.readCompletion).not.toHaveBeenCalled();
    expect(readUserManagementIntent(sessionStorage, intent)).toEqual(intent);
  });

  it("requires disablement and typed confirmation before irreversible live deletion", async () => {
    const disabledUser: User = { ...childUser, status: "DISABLED", resourceVersion: 5 };
    const disabledAttachment = attachment(disabledUser.id, tenantPolicy);
    const disabled: UserAccess = { user: disabledUser, policyAttachments: [disabledAttachment], capabilities: userCapabilities(disabledUser, [disabledAttachment]) };
    const deleteUser = vi.fn().mockImplementation(async () => {
      const persisted = readUserDeletionIntents(sessionStorage, { accountId: account.id, actorPrincipalId: rootUser.id });
      expect(persisted).toEqual([expect.objectContaining({ userId: disabledUser.id, loginName: disabledUser.loginName,
        expectedResourceVersion: disabledUser.resourceVersion, commandRequestId: expect.stringMatching(/^ui-user-delete-[0-9a-f]{32}$/) })]);
      return { accountId: account.id, id: disabledUser.id, loginName: disabledUser.loginName,
        resourceVersion: disabledUser.resourceVersion + 1, deletedAt: timestamp };
    });
    const repository = accounts({
      listUsers: vi.fn().mockResolvedValue({ items: [disabled], nextAfter: null }),
      getUser: vi.fn().mockResolvedValue(structuredClone(disabled)),
      deleteUser
    });
    const { user } = await openAccess(repository);
    await user.click(await screen.findByRole("button", { name: "查看用户 developer" }));
    const deleteButton = await screen.findByRole("button", { name: "删除用户" });
    expect((deleteButton as HTMLButtonElement).disabled).toBe(false);
    await user.click(deleteButton);
    expect(deleteUser).not.toHaveBeenCalled();
    const confirmation = screen.getByLabelText("输入名称以确认");
    await user.type(confirmation, "developer");
    await user.click(screen.getByRole("button", { name: "确认删除" }));
    await waitFor(() => expect(deleteUser).toHaveBeenCalledExactlyOnceWith(credential, account.id, disabledUser.id, {
      resourceVersion: disabledUser.resourceVersion, requestId: expect.stringMatching(/^ui-user-delete-[0-9a-f]{32}$/), expectedLoginName: disabledUser.loginName
    }));
    const receipt = await screen.findByRole("status", { name: "用户删除回执" });
    expect(receipt.textContent).toContain(disabledUser.loginName);
    expect(receipt.textContent).toContain(disabledUser.id);
    expect(receipt.querySelector("time")?.getAttribute("datetime")).toBe(timestamp);
    expect(receipt.textContent).toContain("服务器回执");
    expect(readUserDeletionIntents(sessionStorage, { accountId: account.id, actorPrincipalId: rootUser.id })).toEqual([]);
    expect(repository.listUsers).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole("table", { name: "租户用户列表" })).toBeNull();
    await user.click(screen.getByRole("button", { name: "完成并返回用户列表" }));
    await waitFor(() => expect(repository.listUsers).toHaveBeenCalledTimes(2));
    expect(await screen.findByRole("table", { name: "租户用户列表" })).toBeTruthy();
    expect(repository.execute).not.toHaveBeenCalled();
  });

  it("freezes an unavailable live user deletion as unconfirmed without retrying or inferring success", async () => {
    const disabledUser: User = { ...childUser, status: "DISABLED", resourceVersion: 5 };
    const disabled: UserAccess = { user: disabledUser, policyAttachments: [], capabilities: userCapabilities(disabledUser) };
    const deleteUser = vi.fn().mockRejectedValue(new HttpProblem(503, "DELETE_RESULT_LOST"));
    const repository = accounts({ listUsers: vi.fn().mockResolvedValue({ items: [disabled], nextAfter: null }),
      getUser: vi.fn().mockResolvedValue(structuredClone(disabled)), deleteUser });
    const { user } = await openAccess(repository);
    await user.click(await screen.findByRole("button", { name: "查看用户 developer" }));
    await user.click(await screen.findByRole("button", { name: "删除用户" }));
    await user.type(screen.getByLabelText("输入名称以确认"), disabledUser.loginName);
    await user.click(screen.getByRole("button", { name: "确认删除" }));
    const unknown = await screen.findByRole("alert", { name: "用户删除结果未确认" });
    expect(unknown.textContent).toContain(disabledUser.loginName);
    expect(unknown.textContent).toContain(disabledUser.id);
    expect(unknown.textContent).toContain(String(disabledUser.resourceVersion));
    expect(unknown.textContent).toContain("404");
    expect(deleteUser).toHaveBeenCalledTimes(1);
    expect(unknown.textContent).toContain(deleteUser.mock.calls[0]![3].requestId);
    expect(readUserDeletionIntents(sessionStorage, { accountId: account.id, actorPrincipalId: rootUser.id })).toEqual([
      expect.objectContaining({ userId: disabledUser.id, commandRequestId: deleteUser.mock.calls[0]![3].requestId })
    ]);
    expect(screen.queryByRole("button", { name: "确认删除" })).toBeNull();
    await user.click(screen.getByRole("button", { name: "保留记录并返回用户列表" }));
    await waitFor(() => expect(repository.listUsers).toHaveBeenCalledTimes(2));
    expect(await screen.findByRole("alert", { name: "用户删除结果未确认" })).toBeTruthy();
    await user.click(screen.getByTestId("nav-settings"));
    expect(await screen.findByRole("alert", { name: "用户删除结果未确认" })).toBeTruthy();
    await user.click(screen.getByTestId("nav-users"));
    await user.click(await screen.findByRole("button", { name: "查看用户 developer" }));
    expect(await screen.findByRole("alert", { name: "用户删除结果未确认" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "删除用户" })).toBeNull();
    expect(deleteUser).toHaveBeenCalledTimes(1);
  });

  it("discards a late live user deletion result after repository ownership changes", async () => {
    const disabledUser: User = { ...childUser, status: "DISABLED", resourceVersion: 5 };
    const disabled: UserAccess = { user: disabledUser, policyAttachments: [], capabilities: userCapabilities(disabledUser) };
    let resolve!: (value: UserDeletion) => void;
    const oldDelete = vi.fn((...args: Parameters<NonNullable<AccountRepository["deleteUser"]>>) => {
      void args;
      return new Promise<UserDeletion>((complete) => { resolve = complete; });
    });
    const previous = accounts({ listUsers: vi.fn().mockResolvedValue({ items: [disabled], nextAfter: null }),
      getUser: vi.fn().mockResolvedValue(structuredClone(disabled)), deleteUser: oldDelete });
    const nextDelete = vi.fn().mockRejectedValue(new Error("replacement delete must not run"));
    const next = accounts({ listUsers: vi.fn().mockResolvedValue({ items: [disabled], nextAfter: null }),
      getUser: vi.fn().mockResolvedValue(structuredClone(disabled)), deleteUser: nextDelete });
    const opened = await openAccess(previous, iam(), "users", credential, disabledUser.id);
    await opened.user.click(await screen.findByRole("button", { name: "删除用户" }));
    await opened.user.type(screen.getByLabelText("输入名称以确认"), disabledUser.loginName);
    await opened.user.click(screen.getByRole("button", { name: "确认删除" }));
    await waitFor(() => expect(oldDelete).toHaveBeenCalledTimes(1));
    opened.replaceRepository(next);
    await waitFor(() => expect(next.currentIdentity).toHaveBeenCalled());
    const unknown = await screen.findByRole("alert", { name: "用户删除结果未确认" });
    expect(unknown.textContent).toContain(oldDelete.mock.calls[0]![3].requestId);
    await act(async () => { resolve({ accountId: account.id, id: disabledUser.id, loginName: disabledUser.loginName,
      resourceVersion: disabledUser.resourceVersion + 1, deletedAt: timestamp }); });
    expect(screen.queryByRole("status", { name: "用户删除回执" })).toBeNull();
    expect(screen.getByRole("alert", { name: "用户删除结果未确认" })).toBeTruthy();
    expect(readUserDeletionIntents(sessionStorage, { accountId: account.id, actorPrincipalId: rootUser.id })).toEqual([
      expect.objectContaining({ userId: disabledUser.id, commandRequestId: oldDelete.mock.calls[0]![3].requestId })
    ]);
    expect(screen.queryByRole("button", { name: "登录控制台" })).toBeNull();
    expect(nextDelete).not.toHaveBeenCalled();
  });

  it("does not dispatch a live deletion when the preflight recovery record cannot be persisted", async () => {
    const disabledUser: User = { ...childUser, status: "DISABLED", resourceVersion: 5 };
    const disabled: UserAccess = { user: disabledUser, policyAttachments: [], capabilities: userCapabilities(disabledUser) };
    const deleteUser = vi.fn();
    const repository = accounts({ listUsers: vi.fn().mockResolvedValue({ items: [disabled], nextAfter: null }),
      getUser: vi.fn().mockResolvedValue(structuredClone(disabled)), deleteUser });
    const { user } = await openAccess(repository);
    await user.click(await screen.findByRole("button", { name: "查看用户 developer" }));
    await user.click(await screen.findByRole("button", { name: "删除用户" }));
    const originalSetItem = Storage.prototype.setItem;
    const key = userDeletionStorageKey({ accountId: account.id, actorPrincipalId: rootUser.id, userId: disabledUser.id });
    const storage = vi.spyOn(Storage.prototype, "setItem").mockImplementation(function (this: Storage, candidate, value) {
      if (candidate === key) throw new Error("storage unavailable");
      return originalSetItem.call(this, candidate, value);
    });
    await user.type(screen.getByLabelText("输入名称以确认"), disabledUser.loginName);
    await user.click(screen.getByRole("button", { name: "确认删除" }));
    await waitFor(() => expect(screen.getAllByText(/无法验证当前标签页的用户删除恢复记录/).length).toBeGreaterThan(0));
    expect(deleteUser).not.toHaveBeenCalled();
    expect(sessionStorage.getItem(key)).toBeNull();
    storage.mockRestore();
  });

  it("fails closed on a damaged same-owner deletion reminder without blocking unrelated IAM reads", async () => {
    const intent = storedUserDeletion();
    sessionStorage.setItem(userDeletionStorageKey(intent), "{not-json");
    const deleteUser = vi.fn();
    const repository = accounts({ deleteUser });
    const { user } = await openAccess(repository);
    expect(await screen.findByText(/真实用户删除入口已关闭/)).toBeTruthy();
    expect(await screen.findByRole("table", { name: "租户用户列表" })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "查看用户 developer" }));
    expect(screen.queryByRole("button", { name: "删除用户" })).toBeNull();
    expect(deleteUser).not.toHaveBeenCalled();
  });

  it("restores an unknown deletion after a same-owner reload and sign-in without issuing another command", async () => {
    const disabledUser: User = { ...childUser, status: "DISABLED", resourceVersion: 5 };
    const disabled: UserAccess = { user: disabledUser, policyAttachments: [], capabilities: userCapabilities(disabledUser) };
    const deleteUser = vi.fn().mockRejectedValue(new HttpProblem(503, "DELETE_RESULT_LOST"));
    const repository = accounts({ listUsers: vi.fn().mockResolvedValue({ items: [disabled], nextAfter: null }),
      getUser: vi.fn().mockResolvedValue(structuredClone(disabled)), deleteUser });
    const first = await openAccess(repository);
    await first.user.click(await screen.findByRole("button", { name: "查看用户 developer" }));
    await first.user.click(await screen.findByRole("button", { name: "删除用户" }));
    await first.user.type(screen.getByLabelText("输入名称以确认"), disabledUser.loginName);
    await first.user.click(screen.getByRole("button", { name: "确认删除" }));
    const original = await screen.findByRole("alert", { name: "用户删除结果未确认" });
    const requestId = deleteUser.mock.calls[0]![3].requestId;
    expect(original.textContent).toContain(requestId);
    first.view.unmount();

    const second = await openAccess(repository);
    const restored = await screen.findByRole("alert", { name: "用户删除结果未确认" });
    expect(restored.textContent).toContain(requestId);
    await second.user.click(await screen.findByRole("button", { name: "查看用户 developer" }));
    expect(await screen.findByRole("alert", { name: "用户删除结果未确认" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "删除用户" })).toBeNull();
    expect(deleteUser).toHaveBeenCalledTimes(1);
  });

  it("does not expose or clear another actor's deletion reminder", async () => {
    const foreign = storedUserDeletion({ actorPrincipalId: "operator-b" });
    const key = userDeletionStorageKey(foreign);
    sessionStorage.setItem(key, JSON.stringify(foreign));
    const repository = accounts();
    await openAccess(repository);
    expect(await screen.findByRole("table", { name: "租户用户列表" })).toBeTruthy();
    expect(screen.queryByRole("alert", { name: "用户删除结果未确认" })).toBeNull();
    expect(sessionStorage.getItem(key)).toBe(JSON.stringify(foreign));
  });

  it("keeps a verified success receipt when clearing the local deletion fence fails", async () => {
    const disabledUser: User = { ...childUser, status: "DISABLED", resourceVersion: 5 };
    const disabled: UserAccess = { user: disabledUser, policyAttachments: [], capabilities: userCapabilities(disabledUser) };
    const deleteUser = vi.fn().mockResolvedValue({ accountId: account.id, id: disabledUser.id, loginName: disabledUser.loginName,
      resourceVersion: disabledUser.resourceVersion + 1, deletedAt: timestamp });
    const repository = accounts({ listUsers: vi.fn().mockResolvedValue({ items: [disabled], nextAfter: null }),
      getUser: vi.fn().mockResolvedValue(structuredClone(disabled)), deleteUser });
    const { user } = await openAccess(repository);
    await user.click(await screen.findByRole("button", { name: "查看用户 developer" }));
    await user.click(await screen.findByRole("button", { name: "删除用户" }));
    const originalRemoveItem = Storage.prototype.removeItem;
    const key = userDeletionStorageKey({ accountId: account.id, actorPrincipalId: rootUser.id, userId: disabledUser.id });
    const storage = vi.spyOn(Storage.prototype, "removeItem").mockImplementation(function (this: Storage, candidate) {
      if (candidate === key) throw new Error("storage unavailable");
      return originalRemoveItem.call(this, candidate);
    });
    await user.type(screen.getByLabelText("输入名称以确认"), disabledUser.loginName);
    await user.click(screen.getByRole("button", { name: "确认删除" }));
    expect(await screen.findByRole("status", { name: "用户删除回执" })).toBeTruthy();
    expect(screen.getByText(/真实用户删除入口已关闭/)).toBeTruthy();
    expect(sessionStorage.getItem(key)).not.toBeNull();
    expect(screen.queryByRole("alert", { name: "用户删除结果未确认" })).toBeNull();
    storage.mockRestore();
  });

  it("clears a rejected pre-unknown deletion and permits a freshly reviewed request", async () => {
    const disabledUser: User = { ...childUser, status: "DISABLED", resourceVersion: 5 };
    const disabled: UserAccess = { user: disabledUser, policyAttachments: [], capabilities: userCapabilities(disabledUser) };
    const deleteUser = vi.fn().mockRejectedValueOnce(new HttpProblem(409, "STALE_USER"))
      .mockResolvedValue({ accountId: account.id, id: disabledUser.id, loginName: disabledUser.loginName,
        resourceVersion: disabledUser.resourceVersion + 1, deletedAt: timestamp });
    const repository = accounts({ listUsers: vi.fn().mockResolvedValue({ items: [disabled], nextAfter: null }),
      getUser: vi.fn().mockResolvedValue(structuredClone(disabled)), deleteUser });
    const { user } = await openAccess(repository);
    await user.click(await screen.findByRole("button", { name: "查看用户 developer" }));
    await user.click(await screen.findByRole("button", { name: "删除用户" }));
    await user.type(screen.getByLabelText("输入名称以确认"), disabledUser.loginName);
    await user.click(screen.getByRole("button", { name: "确认删除" }));
    await waitFor(() => expect(deleteUser).toHaveBeenCalledTimes(1));
    expect(readUserDeletionIntents(sessionStorage, { accountId: account.id, actorPrincipalId: rootUser.id })).toEqual([]);
    await user.click(screen.getByRole("button", { name: "确认删除" }));
    expect(await screen.findByRole("status", { name: "用户删除回执" })).toBeTruthy();
    expect(deleteUser).toHaveBeenCalledTimes(2);
    expect(deleteUser.mock.calls[1]![3].requestId).not.toBe(deleteUser.mock.calls[0]![3].requestId);
  });

  it("keeps unsupported LIVE creation closed rather than using the preview workspace", async () => {
    const { user, repository, view } = await openAccess();
    await screen.findByText("Developer A");
    expect(screen.queryByRole("button", { name: "管理 admin" })).toBeNull();
    await user.click(screen.getByRole("button", { name: "创建用户" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(screen.queryByRole("form", { name: "创建子用户" })).toBeNull();
    expect(screen.getByRole("heading", { name: "安全委派创建尚未接入" })).toBeTruthy();
    expect(screen.getByText(/此处尚未接入委派创建/)).toBeTruthy();
    expect(screen.queryByLabelText(/^初始密码/)).toBeNull();
    expect(repository.execute).not.toHaveBeenCalled();
    expect(view.container.textContent).not.toContain(credential);
  });

  it("creates a LIVE child from the shared wizard, clears its password and rereads the precise identity", async () => {
    const created: User = { ...childUser, id: "live-created-user", loginName: "live.new", displayName: "Live New User", resourceVersion: 1, mustChangePassword: true };
    let createdAccess: UserAccess | null = null;
    const createUser = vi.fn().mockImplementation(async () => {
      createdAccess = { user: created, policyAttachments: [], capabilities: userCapabilities(created) };
      return created;
    });
    const repository = accounts({ createUser, listUsers: vi.fn(async () => ({ items: createdAccess ? [child, createdAccess] : [child], nextAfter: null })),
      getUser: vi.fn(async (_credential, id) => id === created.id && createdAccess ? createdAccess : child) });
    const { user } = await openAccess(repository);
    await reviewLiveNewUser(user);
    await user.click(screen.getByRole("button", { name: "确认创建用户" }));
    expect(await screen.findByText("用户创建成功")).toBeTruthy();
    expect(screen.getByText(created.id)).toBeTruthy();
    expect(screen.queryByText("授权配置已保存")).toBeNull();
    expect(screen.queryByLabelText(/^初始密码/)).toBeNull();
    expect(createUser).toHaveBeenCalledExactlyOnceWith(credential, account.id, {
      loginName: "live.new", displayName: "Live New User", initialPassword: "Initial-password-for-browser-1!",
      permissionBoundary: null, requestId: expect.stringMatching(/^ui-user-create-/)
    });
    expect(repository.getUser).toHaveBeenCalledWith(credential, created.id);
    expect(repository.execute).not.toHaveBeenCalled();
    const done = screen.getByRole("button", { name: "完成，返回用户列表" }) as HTMLButtonElement;
    await waitFor(() => expect(done.disabled).toBe(false));
    await user.click(done);
    expect(await screen.findByText("Live New User")).toBeTruthy();
  });

  it("keeps UNKNOWN creation out of MOCK and retries only the original frozen request after route remount", async () => {
    const created: User = { ...childUser, id: "live-created-unknown", loginName: "live.new", displayName: "Live New User", resourceVersion: 1, mustChangePassword: true };
    const createUser = vi.fn().mockRejectedValueOnce(new HttpProblem(503, "UNKNOWN")).mockResolvedValue(created);
    const repository = accounts({ createUser, getUser: vi.fn().mockResolvedValue({ user: created, policyAttachments: [], capabilities: userCapabilities(created) }) });
    const { user, setAccessActive } = await openAccess(repository);
    await reviewLiveNewUser(user);
    await user.click(screen.getByRole("button", { name: "确认创建用户" }));
    expect(await screen.findByText(/原请求结果尚未确认/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: "确认创建用户" })).toBeNull();
    expect(screen.queryByLabelText(/^初始密码/)).toBeNull();
    setAccessActive(false);
    expect(createUser).toHaveBeenCalledTimes(1);
    setAccessActive(true);
    expect(await screen.findByText(/原请求结果尚未确认/)).toBeTruthy();
    await user.click(screen.getByTestId("nav-settings"));
    await user.click(screen.getByRole("button", { name: "放弃并离开" }));
    await user.click(screen.getByTestId("nav-users"));
    await user.click(await screen.findByRole("button", { name: "创建用户" }));
    expect(screen.getByText(/原请求结果尚未确认/)).toBeTruthy();
    expect(screen.getByRole("button", { name: "填写用户信息" })).toHaveProperty("disabled", true);
    expect(screen.getByRole("form", { name: "创建子用户" }).getAttribute("aria-busy")).not.toBe("true");
    await user.click(screen.getByTestId("nav-settings"));
    expect(screen.getByRole("dialog", { name: "离开结果待确认的创建流程？" })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "放弃并离开" }));
    await user.click(screen.getByTestId("nav-users"));
    await user.click(await screen.findByRole("button", { name: "创建用户" }));
    await user.click(screen.getByRole("button", { name: "重试原请求" }));
    expect(await screen.findByText("用户创建成功")).toBeTruthy();
    expect(createUser.mock.calls[1]).toEqual(createUser.mock.calls[0]);
    expect(repository.execute).not.toHaveBeenCalled();
  });

  it("does not expose Root's no-boundary form to an ordinary identity even if create capability is available", async () => {
    const createUser = vi.fn();
    const repository = accounts({ createUser, currentIdentity: vi.fn().mockResolvedValue({ ...identity, user: childUser, identityKind: "USER",
      permissionBoundary: { accountId: account.id, userId: childUser.id, resourceVersion: childUser.resourceVersion, policy: null } }) });
    const { user } = await openAccess(repository, iam({}, childUser.id));
    await user.click(await screen.findByRole("button", { name: "创建用户" }));
    expect(screen.getByRole("heading", { name: "安全委派创建尚未接入" })).toBeTruthy();
    expect(screen.queryByLabelText(/^初始密码/)).toBeNull();
    expect(createUser).not.toHaveBeenCalled();
  });

  it("waits for the replacement source's verified identity instead of reusing old Root capability", async () => {
    const { user, replaceRepository } = await openAccess(accounts({ createUser: vi.fn() }));
    await screen.findByRole("button", { name: "创建用户" });
    let releaseIdentity!: (value: AccountIdentity) => void;
    const createUser = vi.fn();
    const currentIdentity = vi.fn(() => new Promise<AccountIdentity>((resolve) => { releaseIdentity = resolve; }));
    replaceRepository(accounts({ createUser, currentIdentity }));
    await waitFor(() => expect(currentIdentity).toHaveBeenCalledWith(credential));
    await user.click(screen.getByRole("button", { name: "创建用户" }));
    expect(screen.queryByLabelText(/^初始密码/)).toBeNull();
    expect(createUser).not.toHaveBeenCalled();
    await act(async () => { releaseIdentity(structuredClone(identity)); });
    expect(await screen.findByLabelText(/^初始密码/)).toBeTruthy();
    expect(createUser).not.toHaveBeenCalled();
  });

  it("sets an independent account alias with an optimistic version and shows both login forms", async () => {
    const repository = accounts();
    const { user } = await openAccess(repository);
    await screen.findByText("Developer A");
    await user.click(screen.getByTestId("nav-settings"));
    await user.type(screen.getByLabelText(/^主账号别名/), "acme");
    await user.click(screen.getByRole("button", { name: "保存别名" }));
    await waitFor(() => expect(repository.execute).toHaveBeenCalledWith(credential, { kind: "set-alias", alias: "acme", resourceVersion: 1 }));
    expect(screen.getByText("username@tenant-a")).toBeTruthy();
    expect(screen.getByText("admin", { exact: true })).toBeTruthy();
  });

  it("navigates the long settings page by responsibility without remounting or refetching it", async () => {
    const repository = accounts();
    const { user } = await openAccess(repository, iam(), "settings");
    const navigation = screen.getByRole("navigation", { name: "账号设置分区" });
    const initialReads = vi.mocked(repository.currentIdentity).mock.calls.length;

    await user.click(within(navigation).getByRole("link", { name: /^本人安全/ }));
    expect(screen.getByRole("heading", { name: "安全通知与身份验证器" })).toBe(document.activeElement);

    await user.click(within(navigation).getByRole("link", { name: /^账号安全/ }));
    expect(screen.getByRole("heading", { name: "账号安全规则" })).toBe(document.activeElement);

    await user.click(within(navigation).getByRole("link", { name: /^登录标识/ }));
    expect(screen.getByRole("heading", { name: "主账号别名" })).toBe(document.activeElement);
    expect(repository.currentIdentity).toHaveBeenCalledTimes(initialReads);
  });

  it("keeps the personal-security shell stable while only live security cards load", async () => {
    let finishContact!: (value: NotificationContact) => void;
    let finishFactor!: (value: AuthenticatorState) => void;
    const security = {
      notificationContact: vi.fn(() => new Promise<NotificationContact>((resolve) => { finishContact = resolve; })),
      authenticatorState: vi.fn(() => new Promise<AuthenticatorState>((resolve) => { finishFactor = resolve; })),
      startNotificationVerification: vi.fn(), notificationVerification: vi.fn(), confirmNotificationVerification: vi.fn(),
      startTOTPEnrollment: vi.fn(), totpEnrollment: vi.fn(), totpEnrollmentByRequest: vi.fn(), cancelTOTPEnrollment: vi.fn(), confirmTOTPEnrollment: vi.fn()
    };
    await openAccess(accounts(), iam({ personalSecurity: security }), "settings");
    const securityRegion = (await screen.findByRole("heading", { name: "安全通知与身份验证器" })).closest("section")!;
    expect(within(securityRegion).getByRole("heading", { name: "安全通知地址" })).toBeTruthy();
    expect(within(securityRegion).getByRole("heading", { name: "身份验证器应用" })).toBeTruthy();
    expect(screen.queryByRole("dialog")).toBeNull();
    await waitFor(() => {
      expect(security.notificationContact).toHaveBeenCalled();
      expect(security.authenticatorState).toHaveBeenCalled();
    });
    await act(async () => {
      finishContact({ accountId: account.id, userId: rootUser.id, state: "NONE", resourceVersion: 0, pendingVerificationId: null });
      finishFactor({ enrollmentState: "NEVER_BOUND", factorRevision: 1, factorId: null });
    });
    expect(await within(securityRegion).findByText("未设置")).toBeTruthy();
  });

  it("verifies the first notification address inline before enabling first authenticator enrollment", async () => {
    const none = { accountId: account.id, userId: rootUser.id, state: "NONE" as const, resourceVersion: 0 as const, pendingVerificationId: null };
    const verified = { accountId: account.id, userId: rootUser.id, state: "VERIFIED" as const, resourceVersion: 1, email: "admin@example.com", verifiedAt: timestamp, pendingVerificationId: null };
    const verification = { id: "verification-one", accountId: account.id, userId: rootUser.id, requestId: "request-one", email: "admin@example.com", state: "PENDING" as const, issuedAt: timestamp, expiresAt: "2026-09-11T08:10:00Z", completedAt: null, delivery: { state: "ACCEPTED" as const, attempts: 1, lastOutcome: "ACCEPTED" as const, lastSmtpCode: 250, updatedAt: timestamp } };
    const security = {
      notificationContact: vi.fn().mockResolvedValueOnce(none).mockResolvedValue(verified),
      authenticatorState: vi.fn().mockResolvedValue({ enrollmentState: "NEVER_BOUND", factorRevision: 1, factorId: null }),
      startNotificationVerification: vi.fn().mockResolvedValue(verification),
      notificationVerification: vi.fn(),
      confirmNotificationVerification: vi.fn().mockResolvedValue({ ...verification, state: "VERIFIED", completedAt: "2026-09-11T08:02:00Z" }),
      startTOTPEnrollment: vi.fn(), totpEnrollment: vi.fn(), totpEnrollmentByRequest: vi.fn(), cancelTOTPEnrollment: vi.fn(), confirmTOTPEnrollment: vi.fn()
    };
    const { user } = await openAccess(accounts(), iam({ personalSecurity: security }), "settings");
    const securityRegion = (await screen.findByRole("heading", { name: "安全通知与身份验证器" })).closest("section")!;
    await within(securityRegion).findByText("未设置");
    await user.type(screen.getByLabelText("邮箱地址"), "admin@example.com");
    await user.type(screen.getAllByLabelText("当前密码")[0]!, "Private-Password-49!");
    await user.click(screen.getByRole("button", { name: "发送验证码" }));
    expect(await screen.findByText(/邮件服务器已接受/)).toBeTruthy();
    expect(screen.getByText(/不代表收件人已收到或阅读/)).toBeTruthy();
    await user.type(screen.getByLabelText("8 位邮箱验证码"), "12345678");
    await user.click(screen.getByRole("button", { name: "验证通知地址" }));
    expect(await screen.findByText("admin@example.com")).toBeTruthy();
    expect(screen.getByRole("button", { name: /开始绑定/ })).toBeTruthy();
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(security.startNotificationVerification).toHaveBeenCalledWith(credential, expect.objectContaining({ email: "admin@example.com", password: "Private-Password-49!" }));
    expect(security.confirmNotificationVerification).toHaveBeenCalledWith(credential, "verification-one", expect.objectContaining({ code: "12345678" }));
  });

  it("replaces a verified notification address inline through one purpose-bound live intent", async () => {
    const verified = { accountId: account.id, userId: rootUser.id, state: "VERIFIED" as const, resourceVersion: 1, email: "old@example.com", verifiedAt: timestamp, pendingVerificationId: null };
    const updated = { ...verified, resourceVersion: 2, email: "new@example.com", verifiedAt: "2026-09-11T08:03:00Z" };
    const pendingStepUp: SecurityStepUp = {
      id: "step-up-replace-contact", requestId: "replace-contact-request", operation: "NOTIFICATION_CONTACT_REPLACE",
      expectedFactorRevision: 3, notificationContact: { expectedResourceVersion: 1, email: "new@example.com" },
      state: "PENDING", createdAt: timestamp, expiresAt: "2026-09-11T08:02:00Z", provedAt: null, consumedAt: null
    };
    const pendingVerification = {
      id: "verification-replace-contact", accountId: account.id, userId: rootUser.id, requestId: "replace-contact-request",
      purpose: "REPLACEMENT" as const, expectedResourceVersion: 1, email: "new@example.com", state: "PENDING" as const,
      issuedAt: timestamp, expiresAt: "2026-09-11T08:10:00Z", completedAt: null,
      delivery: { state: "ACCEPTED" as const, attempts: 1, lastOutcome: "ACCEPTED" as const, lastSmtpCode: 250, updatedAt: timestamp }
    };
    const replacement = {
      startStepUp: vi.fn(async (_credential: string, command: { requestId: string }) => ({ ...pendingStepUp, requestId: command.requestId })),
      stepUpByRequest: vi.fn(),
      verifyStepUp: vi.fn(async (_credential: string, _stepUpId: string, originalRequestId: string) => ({ ...pendingStepUp, requestId: originalRequestId, state: "PROVED" as const, provedAt: "2026-09-11T08:00:30Z" })),
      startVerification: vi.fn(async (_credential: string, command: { requestId: string }) => ({ ...pendingVerification, requestId: command.requestId })),
      verification: vi.fn(),
      confirmVerification: vi.fn(async (_credential: string, _verificationId: string, original: { requestId: string }) => ({ ...pendingVerification, requestId: original.requestId, state: "VERIFIED" as const, completedAt: "2026-09-11T08:03:00Z" }))
    };
    const security = {
      notificationContact: vi.fn().mockResolvedValueOnce(verified).mockResolvedValue(updated),
      authenticatorState: vi.fn().mockResolvedValue({ enrollmentState: "BOUND" as const, factorRevision: 3, factorId: "factor-current" }),
      startNotificationVerification: vi.fn(), notificationVerification: vi.fn(), confirmNotificationVerification: vi.fn(), notificationReplacement: replacement,
      startTOTPEnrollment: vi.fn(), totpEnrollment: vi.fn(), totpEnrollmentByRequest: vi.fn(), cancelTOTPEnrollment: vi.fn(), confirmTOTPEnrollment: vi.fn()
    };
    const { user } = await openAccess(accounts(), iam({ personalSecurity: security }), "settings");
    const securityRegion = (await screen.findByRole("heading", { name: "安全通知与身份验证器" })).closest("section")!;
    await within(securityRegion).findByText("old@example.com");

    await user.click(within(securityRegion).getByRole("button", { name: "更换地址" }));
    await user.type(within(securityRegion).getByLabelText("目标地址"), "new@example.com");
    await user.click(within(securityRegion).getByRole("button", { name: "继续验证本人身份" }));
    await user.type(await within(securityRegion).findByLabelText("当前密码"), "Private-Password-49!");
    await user.type(within(securityRegion).getByLabelText("6 位动态验证码"), "123456");
    await user.click(within(securityRegion).getByRole("button", { name: "验证本人身份" }));
    await user.click(await within(securityRegion).findByRole("button", { name: "发送到新地址" }));
    expect(await within(securityRegion).findByText(/不代表收件人已收到或阅读/)).toBeTruthy();
    await user.type(within(securityRegion).getByLabelText("新地址的 8 位验证码"), "12345678");
    await user.click(within(securityRegion).getByRole("button", { name: "确认并更换地址" }));

    expect(await within(securityRegion).findByText("new@example.com")).toBeTruthy();
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(replacement.startStepUp).toHaveBeenCalledTimes(1);
    expect(replacement.verifyStepUp).toHaveBeenCalledWith(credential, "step-up-replace-contact", expect.any(String), 3,
      { expectedResourceVersion: 1, email: "new@example.com" }, expect.objectContaining({ password: "Private-Password-49!", code: "123456" }));
    expect(replacement.startVerification).toHaveBeenCalledTimes(1);
    expect(replacement.confirmVerification).toHaveBeenCalledWith(credential, "verification-replace-contact",
      expect.objectContaining({ expectedResourceVersion: 1, email: "new@example.com" }), expect.objectContaining({ code: "12345678" }));
  });

  it("keeps a separately pending replacement locked to its original intent context", async () => {
    const verified = {
      accountId: account.id,
      userId: rootUser.id,
      state: "VERIFIED" as const,
      resourceVersion: 1,
      email: "old@example.com",
      verifiedAt: timestamp,
      pendingVerificationId: "verification-pending-elsewhere"
    };
    const replacement = {
      startStepUp: vi.fn(), stepUpByRequest: vi.fn(), verifyStepUp: vi.fn(),
      startVerification: vi.fn(), verification: vi.fn(), confirmVerification: vi.fn()
    };
    const security = {
      notificationContact: vi.fn().mockResolvedValue(verified),
      authenticatorState: vi.fn().mockResolvedValue({ enrollmentState: "BOUND" as const, factorRevision: 3, factorId: "factor-current" }),
      startNotificationVerification: vi.fn(), notificationVerification: vi.fn(), confirmNotificationVerification: vi.fn(), notificationReplacement: replacement,
      startTOTPEnrollment: vi.fn(), totpEnrollment: vi.fn(), totpEnrollmentByRequest: vi.fn(), cancelTOTPEnrollment: vi.fn(), confirmTOTPEnrollment: vi.fn()
    };
    await openAccess(accounts(), iam({ personalSecurity: security }), "settings");
    const securityRegion = (await screen.findByRole("heading", { name: "安全通知与身份验证器" })).closest("section")!;

    expect(await within(securityRegion).findByText(/IAM 已记录一条待确认的替换/)).toBeTruthy();
    expect((within(securityRegion).getByRole("button", { name: "更换地址" }) as HTMLButtonElement).disabled).toBe(true);
    expect(within(securityRegion).queryByLabelText("目标地址")).toBeNull();
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(replacement.startStepUp).not.toHaveBeenCalled();
  });

  it("reports busy step-up capacity without claiming that the password or authenticator code was rejected", async () => {
    const { verified, pendingStepUp } = replacementFixtures();
    const replacement = {
      startStepUp: vi.fn(async (_credential: string, command: { requestId: string }) => ({ ...pendingStepUp, requestId: command.requestId })),
      stepUpByRequest: vi.fn(),
      verifyStepUp: vi.fn().mockRejectedValue(new HttpProblem(429, "iam.authentication.busy")),
      startVerification: vi.fn(), verification: vi.fn(), confirmVerification: vi.fn()
    };
    const security = {
      notificationContact: vi.fn().mockResolvedValue(verified),
      authenticatorState: vi.fn().mockResolvedValue({ enrollmentState: "BOUND" as const, factorRevision: 3, factorId: "factor-current" }),
      startNotificationVerification: vi.fn(), notificationVerification: vi.fn(), confirmNotificationVerification: vi.fn(), notificationReplacement: replacement,
      startTOTPEnrollment: vi.fn(), totpEnrollment: vi.fn(), totpEnrollmentByRequest: vi.fn(), cancelTOTPEnrollment: vi.fn(), confirmTOTPEnrollment: vi.fn()
    };
    const { user } = await openAccess(accounts(), iam({ personalSecurity: security }), "settings");
    const securityRegion = (await screen.findByRole("heading", { name: "安全通知与身份验证器" })).closest("section")!;
    await within(securityRegion).findByText("old@example.com");
    await user.click(within(securityRegion).getByRole("button", { name: "更换地址" }));
    await user.type(within(securityRegion).getByLabelText("目标地址"), "new@example.com");
    await user.click(within(securityRegion).getByRole("button", { name: "继续验证本人身份" }));
    await user.type(await within(securityRegion).findByLabelText("当前密码"), "Private-Password-49!");
    await user.type(within(securityRegion).getByLabelText("6 位动态验证码"), "123456");
    await user.click(within(securityRegion).getByRole("button", { name: "验证本人身份" }));

    expect(await within(securityRegion).findByText(/认证容量暂时繁忙/)).toBeTruthy();
    expect(within(securityRegion).queryByText(/当前密码或动态验证码未通过/)).toBeNull();
    expect(within(securityRegion).getByRole("button", { name: "验证本人身份" })).toBeTruthy();
    expect(replacement.verifyStepUp).toHaveBeenCalledTimes(1);
    expect(replacement.startVerification).not.toHaveBeenCalled();
  });

  it("keeps an unknown proof locked when the bearer probe is unavailable", async () => {
    const { verified, pendingStepUp } = replacementFixtures();
    const replacement = {
      startStepUp: vi.fn(async (_credential: string, command: { requestId: string }) => ({ ...pendingStepUp, requestId: command.requestId })),
      stepUpByRequest: vi.fn(),
      verifyStepUp: vi.fn().mockRejectedValue(new HttpProblem(401, "iam.authentication.failed")),
      startVerification: vi.fn(), verification: vi.fn(), confirmVerification: vi.fn()
    };
    const security = {
      notificationContact: vi.fn().mockResolvedValueOnce(verified).mockRejectedValueOnce(new HttpProblem(503, "iam.unavailable")),
      authenticatorState: vi.fn().mockResolvedValue({ enrollmentState: "BOUND" as const, factorRevision: 3, factorId: "factor-current" }),
      startNotificationVerification: vi.fn(), notificationVerification: vi.fn(), confirmNotificationVerification: vi.fn(), notificationReplacement: replacement,
      startTOTPEnrollment: vi.fn(), totpEnrollment: vi.fn(), totpEnrollmentByRequest: vi.fn(), cancelTOTPEnrollment: vi.fn(), confirmTOTPEnrollment: vi.fn()
    };
    const { user } = await openAccess(accounts(), iam({ personalSecurity: security }), "settings");
    const securityRegion = (await screen.findByRole("heading", { name: "安全通知与身份验证器" })).closest("section")!;
    await within(securityRegion).findByText("old@example.com");
    await user.click(within(securityRegion).getByRole("button", { name: "更换地址" }));
    await user.type(within(securityRegion).getByLabelText("目标地址"), "new@example.com");
    await user.click(within(securityRegion).getByRole("button", { name: "继续验证本人身份" }));
    await user.type(await within(securityRegion).findByLabelText("当前密码"), "Private-Password-49!");
    await user.type(within(securityRegion).getByLabelText("6 位动态验证码"), "123456");
    await user.click(within(securityRegion).getByRole("button", { name: "验证本人身份" }));

    expect(await within(securityRegion).findByText(/本人验证结果未知/)).toBeTruthy();
    expect(within(securityRegion).queryByText(/当前密码或动态验证码未通过/)).toBeNull();
    expect(within(securityRegion).queryByLabelText("当前密码")).toBeNull();
    expect(within(securityRegion).getByRole("button", { name: "查询原安全验证" })).toBeTruthy();
    expect(replacement.verifyStepUp).toHaveBeenCalledTimes(1);
    expect(replacement.startVerification).not.toHaveBeenCalled();
  });

  it("does not repeat identity proof when new-address delivery starts with an unknown result", async () => {
    const { verified, pendingStepUp } = replacementFixtures();
    const replacement = {
      startStepUp: vi.fn(async (_credential: string, command: { requestId: string }) => ({ ...pendingStepUp, requestId: command.requestId })),
      stepUpByRequest: vi.fn(),
      verifyStepUp: vi.fn(async (_credential: string, _stepUpId: string, originalRequestId: string) => ({ ...pendingStepUp, requestId: originalRequestId, state: "PROVED" as const, provedAt: "2026-09-11T08:00:30Z" })),
      startVerification: vi.fn().mockRejectedValue(new HttpProblem(503, "iam.unavailable")),
      verification: vi.fn(), confirmVerification: vi.fn()
    };
    const security = {
      notificationContact: vi.fn().mockResolvedValue(verified),
      authenticatorState: vi.fn().mockResolvedValue({ enrollmentState: "BOUND" as const, factorRevision: 3, factorId: "factor-current" }),
      startNotificationVerification: vi.fn(), notificationVerification: vi.fn(), confirmNotificationVerification: vi.fn(), notificationReplacement: replacement,
      startTOTPEnrollment: vi.fn(), totpEnrollment: vi.fn(), totpEnrollmentByRequest: vi.fn(), cancelTOTPEnrollment: vi.fn(), confirmTOTPEnrollment: vi.fn()
    };
    const { user } = await openAccess(accounts(), iam({ personalSecurity: security }), "settings");
    const securityRegion = (await screen.findByRole("heading", { name: "安全通知与身份验证器" })).closest("section")!;
    await within(securityRegion).findByText("old@example.com");
    await user.click(within(securityRegion).getByRole("button", { name: "更换地址" }));
    await user.type(within(securityRegion).getByLabelText("目标地址"), "new@example.com");
    await user.click(within(securityRegion).getByRole("button", { name: "继续验证本人身份" }));
    await user.type(await within(securityRegion).findByLabelText("当前密码"), "Private-Password-49!");
    await user.type(within(securityRegion).getByLabelText("6 位动态验证码"), "123456");
    await user.click(within(securityRegion).getByRole("button", { name: "验证本人身份" }));
    await user.click(await within(securityRegion).findByRole("button", { name: "发送到新地址" }));

    expect(await within(securityRegion).findByText(/验证码发送请求结果未知/)).toBeTruthy();
    expect(within(securityRegion).queryByLabelText("当前密码")).toBeNull();
    expect(within(securityRegion).getByRole("button", { name: "按原请求重试" })).toBeTruthy();
    expect(replacement.verifyStepUp).toHaveBeenCalledTimes(1);
    expect(replacement.startVerification).toHaveBeenCalledTimes(1);
  });

  it("retries only new-address delivery when that endpoint is temporarily busy", async () => {
    const { verified, pendingStepUp } = replacementFixtures();
    const replacement = {
      startStepUp: vi.fn(async (_credential: string, command: { requestId: string }) => ({ ...pendingStepUp, requestId: command.requestId })),
      stepUpByRequest: vi.fn(),
      verifyStepUp: vi.fn(async (_credential: string, _stepUpId: string, originalRequestId: string) => ({ ...pendingStepUp, requestId: originalRequestId, state: "PROVED" as const, provedAt: "2026-09-11T08:00:30Z" })),
      startVerification: vi.fn().mockRejectedValue(new HttpProblem(429, "iam.authentication.busy")),
      verification: vi.fn(), confirmVerification: vi.fn()
    };
    const security = {
      notificationContact: vi.fn().mockResolvedValue(verified),
      authenticatorState: vi.fn().mockResolvedValue({ enrollmentState: "BOUND" as const, factorRevision: 3, factorId: "factor-current" }),
      startNotificationVerification: vi.fn(), notificationVerification: vi.fn(), confirmNotificationVerification: vi.fn(), notificationReplacement: replacement,
      startTOTPEnrollment: vi.fn(), totpEnrollment: vi.fn(), totpEnrollmentByRequest: vi.fn(), cancelTOTPEnrollment: vi.fn(), confirmTOTPEnrollment: vi.fn()
    };
    const { user } = await openAccess(accounts(), iam({ personalSecurity: security }), "settings");
    const securityRegion = (await screen.findByRole("heading", { name: "安全通知与身份验证器" })).closest("section")!;
    await within(securityRegion).findByText("old@example.com");
    await user.click(within(securityRegion).getByRole("button", { name: "更换地址" }));
    await user.type(within(securityRegion).getByLabelText("目标地址"), "new@example.com");
    await user.click(within(securityRegion).getByRole("button", { name: "继续验证本人身份" }));
    await user.type(await within(securityRegion).findByLabelText("当前密码"), "Private-Password-49!");
    await user.type(within(securityRegion).getByLabelText("6 位动态验证码"), "123456");
    await user.click(within(securityRegion).getByRole("button", { name: "验证本人身份" }));
    await user.click(await within(securityRegion).findByRole("button", { name: "发送到新地址" }));

    expect(await within(securityRegion).findByText(/发送新地址验证码的服务暂时繁忙/)).toBeTruthy();
    expect(within(securityRegion).queryByLabelText("当前密码")).toBeNull();
    expect(within(securityRegion).getByRole("button", { name: "发送到新地址" })).toBeTruthy();
    expect(replacement.verifyStepUp).toHaveBeenCalledTimes(1);
    expect(replacement.startVerification).toHaveBeenCalledTimes(1);
  });

  it("never reconfirms a committed replacement while authoritative contact refresh is unavailable", async () => {
    const verified = { accountId: account.id, userId: rootUser.id, state: "VERIFIED" as const, resourceVersion: 1, email: "old@example.com", verifiedAt: timestamp, pendingVerificationId: null };
    const updated = { ...verified, resourceVersion: 2, email: "new@example.com", verifiedAt: "2026-09-11T08:03:00Z" };
    const pendingStepUp: SecurityStepUp = {
      id: "step-up-replace-contact", requestId: "replace-contact-request", operation: "NOTIFICATION_CONTACT_REPLACE",
      expectedFactorRevision: 3, notificationContact: { expectedResourceVersion: 1, email: "new@example.com" },
      state: "PENDING", createdAt: timestamp, expiresAt: "2026-09-11T08:02:00Z", provedAt: null, consumedAt: null
    };
    const pendingVerification = {
      id: "verification-replace-contact", accountId: account.id, userId: rootUser.id, requestId: "replace-contact-request",
      purpose: "REPLACEMENT" as const, expectedResourceVersion: 1, email: "new@example.com", state: "PENDING" as const,
      issuedAt: timestamp, expiresAt: "2026-09-11T08:10:00Z", completedAt: null,
      delivery: { state: "ACCEPTED" as const, attempts: 1, lastOutcome: "ACCEPTED" as const, lastSmtpCode: 250, updatedAt: timestamp }
    };
    const replacement = {
      startStepUp: vi.fn(async (_credential: string, command: { requestId: string }) => ({ ...pendingStepUp, requestId: command.requestId })),
      stepUpByRequest: vi.fn(),
      verifyStepUp: vi.fn(async (_credential: string, _stepUpId: string, originalRequestId: string) => ({ ...pendingStepUp, requestId: originalRequestId, state: "PROVED" as const, provedAt: "2026-09-11T08:00:30Z" })),
      startVerification: vi.fn(async (_credential: string, command: { requestId: string }) => ({ ...pendingVerification, requestId: command.requestId })),
      verification: vi.fn(),
      confirmVerification: vi.fn(async (_credential: string, _verificationId: string, original: { requestId: string }) => ({ ...pendingVerification, requestId: original.requestId, state: "VERIFIED" as const, completedAt: "2026-09-11T08:03:00Z" }))
    };
    const security = {
      notificationContact: vi.fn()
        .mockResolvedValueOnce(verified)
        .mockRejectedValueOnce(new HttpProblem(503, "iam.unavailable"))
        .mockResolvedValue(updated),
      authenticatorState: vi.fn().mockResolvedValue({ enrollmentState: "BOUND" as const, factorRevision: 3, factorId: "factor-current" }),
      startNotificationVerification: vi.fn(), notificationVerification: vi.fn(), confirmNotificationVerification: vi.fn(), notificationReplacement: replacement,
      startTOTPEnrollment: vi.fn(), totpEnrollment: vi.fn(), totpEnrollmentByRequest: vi.fn(), cancelTOTPEnrollment: vi.fn(), confirmTOTPEnrollment: vi.fn()
    };
    const { user } = await openAccess(accounts(), iam({ personalSecurity: security }), "settings");
    const securityRegion = (await screen.findByRole("heading", { name: "安全通知与身份验证器" })).closest("section")!;
    await within(securityRegion).findByText("old@example.com");

    await user.click(within(securityRegion).getByRole("button", { name: "更换地址" }));
    await user.type(within(securityRegion).getByLabelText("目标地址"), "new@example.com");
    await user.click(within(securityRegion).getByRole("button", { name: "继续验证本人身份" }));
    await user.type(await within(securityRegion).findByLabelText("当前密码"), "Private-Password-49!");
    await user.type(within(securityRegion).getByLabelText("6 位动态验证码"), "123456");
    await user.click(within(securityRegion).getByRole("button", { name: "验证本人身份" }));
    await user.click(await within(securityRegion).findByRole("button", { name: "发送到新地址" }));
    await user.type(await within(securityRegion).findByLabelText("新地址的 8 位验证码"), "12345678");
    await user.click(within(securityRegion).getByRole("button", { name: "确认并更换地址" }));

    expect(await within(securityRegion).findByText(/IAM 已提交地址替换/)).toBeTruthy();
    expect(within(securityRegion).queryByRole("button", { name: "确认并更换地址" })).toBeNull();
    expect(replacement.confirmVerification).toHaveBeenCalledTimes(1);
    await user.click(within(securityRegion).getByRole("button", { name: "重新读取当前联系人" }));
    expect(await within(securityRegion).findByText("new@example.com")).toBeTruthy();
    expect(within(securityRegion).getByRole("button", { name: "更换地址" })).toBeTruthy();
    expect(replacement.confirmVerification).toHaveBeenCalledTimes(1);
  });

  it("queries the original replacement verification after an unknown atomic confirmation without submitting twice", async () => {
    const verified = { accountId: account.id, userId: rootUser.id, state: "VERIFIED" as const, resourceVersion: 1, email: "old@example.com", verifiedAt: timestamp, pendingVerificationId: null };
    const updated = { ...verified, resourceVersion: 2, email: "new@example.com", verifiedAt: "2026-09-11T08:03:00Z" };
    const pendingStepUp: SecurityStepUp = {
      id: "step-up-replace-contact", requestId: "replace-contact-request", operation: "NOTIFICATION_CONTACT_REPLACE",
      expectedFactorRevision: 3, notificationContact: { expectedResourceVersion: 1, email: "new@example.com" },
      state: "PENDING", createdAt: timestamp, expiresAt: "2026-09-11T08:02:00Z", provedAt: null, consumedAt: null
    };
    const pendingVerification = {
      id: "verification-replace-contact", accountId: account.id, userId: rootUser.id, requestId: "replace-contact-request",
      purpose: "REPLACEMENT" as const, expectedResourceVersion: 1, email: "new@example.com", state: "PENDING" as const,
      issuedAt: timestamp, expiresAt: "2026-09-11T08:10:00Z", completedAt: null,
      delivery: { state: "ACCEPTED" as const, attempts: 1, lastOutcome: "ACCEPTED" as const, lastSmtpCode: 250, updatedAt: timestamp }
    };
    const replacement = {
      startStepUp: vi.fn(async (_credential: string, command: { requestId: string }) => ({ ...pendingStepUp, requestId: command.requestId })),
      stepUpByRequest: vi.fn(),
      verifyStepUp: vi.fn(async (_credential: string, _stepUpId: string, originalRequestId: string) => ({ ...pendingStepUp, requestId: originalRequestId, state: "PROVED" as const, provedAt: "2026-09-11T08:00:30Z" })),
      startVerification: vi.fn(async (_credential: string, command: { requestId: string }) => ({ ...pendingVerification, requestId: command.requestId })),
      verification: vi.fn()
        .mockImplementationOnce(async (_credential: string, _verificationId: string, command: { requestId: string }) => ({ ...pendingVerification, requestId: command.requestId }))
        .mockImplementationOnce(async (_credential: string, _verificationId: string, command: { requestId: string }) => ({ ...pendingVerification, requestId: command.requestId, state: "VERIFIED" as const, completedAt: "2026-09-11T08:03:00Z" })),
      confirmVerification: vi.fn().mockRejectedValue(new HttpProblem(503, "iam.unavailable"))
    };
    const security = {
      notificationContact: vi.fn().mockResolvedValueOnce(verified).mockResolvedValue(updated),
      authenticatorState: vi.fn().mockResolvedValue({ enrollmentState: "BOUND" as const, factorRevision: 3, factorId: "factor-current" }),
      startNotificationVerification: vi.fn(), notificationVerification: vi.fn(), confirmNotificationVerification: vi.fn(), notificationReplacement: replacement,
      startTOTPEnrollment: vi.fn(), totpEnrollment: vi.fn(), totpEnrollmentByRequest: vi.fn(), cancelTOTPEnrollment: vi.fn(), confirmTOTPEnrollment: vi.fn()
    };
    const { user } = await openAccess(accounts(), iam({ personalSecurity: security }), "settings");
    const securityRegion = (await screen.findByRole("heading", { name: "安全通知与身份验证器" })).closest("section")!;
    await within(securityRegion).findByText("old@example.com");
    await user.click(within(securityRegion).getByRole("button", { name: "更换地址" }));
    await user.type(within(securityRegion).getByLabelText("目标地址"), "new@example.com");
    await user.click(within(securityRegion).getByRole("button", { name: "继续验证本人身份" }));
    await user.type(await within(securityRegion).findByLabelText("当前密码"), "Private-Password-49!");
    await user.type(within(securityRegion).getByLabelText("6 位动态验证码"), "123456");
    await user.click(within(securityRegion).getByRole("button", { name: "验证本人身份" }));
    await user.click(await within(securityRegion).findByRole("button", { name: "发送到新地址" }));
    await user.type(await within(securityRegion).findByLabelText("新地址的 8 位验证码"), "12345678");
    await user.click(within(securityRegion).getByRole("button", { name: "确认并更换地址" }));
    expect(await within(securityRegion).findByText(/确认回包未知/)).toBeTruthy();
    expect(within(securityRegion).queryByRole("button", { name: "确认并更换地址" })).toBeNull();

    await user.click(within(securityRegion).getByRole("button", { name: "查询原确认结果" }));
    expect(await within(securityRegion).findByText(/确认回包未知/)).toBeTruthy();
    expect(within(securityRegion).queryByRole("button", { name: "确认并更换地址" })).toBeNull();
    expect(replacement.confirmVerification).toHaveBeenCalledTimes(1);
    await user.click(within(securityRegion).getByRole("button", { name: "查询原确认结果" }));
    expect(await within(securityRegion).findByText("new@example.com")).toBeTruthy();
    expect(replacement.confirmVerification).toHaveBeenCalledTimes(1);
    expect(replacement.verification).toHaveBeenCalledWith(credential, "verification-replace-contact",
      expect.objectContaining({ expectedResourceVersion: 1, email: "new@example.com" }));
  });

  it("refreshes the original notification delivery without creating or resending an intent", async () => {
    const none = { accountId: account.id, userId: rootUser.id, state: "NONE" as const, resourceVersion: 0 as const, pendingVerificationId: null };
    const pending = { id: "verification-one", accountId: account.id, userId: rootUser.id, requestId: "request-one", email: "admin@example.com", state: "PENDING" as const, issuedAt: timestamp, expiresAt: "2026-09-11T08:10:00Z", completedAt: null, delivery: { state: "PENDING" as const, attempts: 0, lastOutcome: null, lastSmtpCode: null, updatedAt: timestamp } };
    const accepted = { ...pending, delivery: { state: "ACCEPTED" as const, attempts: 1, lastOutcome: "ACCEPTED" as const, lastSmtpCode: 250, updatedAt: "2026-09-11T08:00:05Z" } };
    const security = {
      notificationContact: vi.fn().mockResolvedValue(none),
      authenticatorState: vi.fn().mockResolvedValue({ enrollmentState: "NEVER_BOUND", factorRevision: 1, factorId: null }),
      startNotificationVerification: vi.fn().mockResolvedValue(pending),
      notificationVerification: vi.fn().mockResolvedValue(accepted),
      confirmNotificationVerification: vi.fn(),
      startTOTPEnrollment: vi.fn(), totpEnrollment: vi.fn(), totpEnrollmentByRequest: vi.fn(), cancelTOTPEnrollment: vi.fn(), confirmTOTPEnrollment: vi.fn()
    };
    const { user } = await openAccess(accounts(), iam({ personalSecurity: security }), "settings");
    const securityRegion = (await screen.findByRole("heading", { name: "安全通知与身份验证器" })).closest("section")!;
    await within(securityRegion).findByLabelText("邮箱地址");
    await user.type(within(securityRegion).getByLabelText("邮箱地址"), "admin@example.com");
    await user.type(within(securityRegion).getAllByLabelText("当前密码")[0]!, "Private-Password-49!");
    await user.click(screen.getByRole("button", { name: "发送验证码" }));
    expect(await screen.findByText(/等待投递/)).toBeTruthy();

    await user.click(screen.getByRole("button", { name: "刷新发送状态" }));
    expect(await screen.findByText(/邮件服务器已接受/)).toBeTruthy();
    expect(screen.getByText("状态更新时间")).toBeTruthy();
    expect(screen.getByText(/不会重发邮件、延长有效期或创建新的验证码/)).toBeTruthy();
    expect(security.startNotificationVerification).toHaveBeenCalledTimes(1);
    expect(security.notificationVerification).toHaveBeenCalledWith(credential, "verification-one");
    expect(security.confirmNotificationVerification).not.toHaveBeenCalled();
  });

  it("keeps verification rejection separate from temporary authentication capacity", async () => {
    const none = { accountId: account.id, userId: rootUser.id, state: "NONE" as const, resourceVersion: 0 as const, pendingVerificationId: null };
    const pending = { id: "verification-one", accountId: account.id, userId: rootUser.id, requestId: "request-one", email: "admin@example.com", state: "PENDING" as const, issuedAt: timestamp, expiresAt: "2026-09-11T08:10:00Z", completedAt: null, delivery: { state: "ACCEPTED" as const, attempts: 1, lastOutcome: "ACCEPTED" as const, lastSmtpCode: 250, updatedAt: timestamp } };
    const security = {
      notificationContact: vi.fn().mockResolvedValue(none),
      authenticatorState: vi.fn().mockResolvedValue({ enrollmentState: "NEVER_BOUND", factorRevision: 1, factorId: null }),
      startNotificationVerification: vi.fn().mockResolvedValue(pending),
      notificationVerification: vi.fn().mockResolvedValue(pending),
      confirmNotificationVerification: vi.fn()
        .mockRejectedValueOnce(new HttpProblem(422, "iam.verification.rejected"))
        .mockRejectedValueOnce(new HttpProblem(429, "iam.authentication.busy")),
      startTOTPEnrollment: vi.fn(), totpEnrollment: vi.fn(), totpEnrollmentByRequest: vi.fn(), cancelTOTPEnrollment: vi.fn(), confirmTOTPEnrollment: vi.fn()
    };
    const { user } = await openAccess(accounts(), iam({ personalSecurity: security }), "settings");
    const securityRegion = (await screen.findByRole("heading", { name: "安全通知与身份验证器" })).closest("section")!;
    await within(securityRegion).findByLabelText("邮箱地址");
    await user.type(within(securityRegion).getByLabelText("邮箱地址"), "admin@example.com");
    await user.type(within(securityRegion).getAllByLabelText("当前密码")[0]!, "Private-Password-49!");
    await user.click(screen.getByRole("button", { name: "发送验证码" }));

    const code = await screen.findByLabelText("8 位邮箱验证码");
    await user.type(code, "12345678");
    await user.click(screen.getByRole("button", { name: "验证通知地址" }));
    expect(await screen.findByText(/验证码未通过验证/)).toBeTruthy();
    expect(code.getAttribute("aria-invalid")).toBe("true");
    expect(code).toBe(document.activeElement);
    expect((code as HTMLInputElement).value).toBe("");

    await user.type(code, "87654321");
    expect(code.getAttribute("aria-invalid")).toBeNull();
    await user.click(screen.getByRole("button", { name: "验证通知地址" }));
    expect(await screen.findByText(/认证工作容量暂时繁忙/)).toBeTruthy();
    expect((code as HTMLInputElement).value).toBe("");
    expect((code as HTMLInputElement).disabled).toBe(false);
    expect((screen.getByRole("button", { name: "验证通知地址" }) as HTMLButtonElement).disabled).toBe(true);
    expect((screen.getByRole("button", { name: "刷新发送状态" }) as HTMLButtonElement).disabled).toBe(false);
    expect(screen.getByRole("heading", { name: "安全通知与身份验证器" })).toBeTruthy();
    expect(security.startNotificationVerification).toHaveBeenCalledTimes(1);
    expect(security.confirmNotificationVerification).toHaveBeenCalledTimes(2);
  });

  it("marks only the password field invalid after a contact password rejection when a bearer-only read still succeeds", async () => {
    const none = { accountId: account.id, userId: rootUser.id, state: "NONE" as const, resourceVersion: 0 as const, pendingVerificationId: null };
    const security = {
      notificationContact: vi.fn().mockResolvedValue(none),
      authenticatorState: vi.fn().mockResolvedValue({ enrollmentState: "NEVER_BOUND", factorRevision: 1, factorId: null }),
      startNotificationVerification: vi.fn().mockRejectedValue(new HttpProblem(401, "iam.authentication.failed")),
      notificationVerification: vi.fn(), confirmNotificationVerification: vi.fn(),
      startTOTPEnrollment: vi.fn(), totpEnrollment: vi.fn(), totpEnrollmentByRequest: vi.fn(), cancelTOTPEnrollment: vi.fn(), confirmTOTPEnrollment: vi.fn()
    };
    const { user } = await openAccess(accounts(), iam({ personalSecurity: security }), "settings");
    const securityRegion = (await screen.findByRole("heading", { name: "安全通知与身份验证器" })).closest("section")!;
    await within(securityRegion).findByLabelText("邮箱地址");
    await user.type(within(securityRegion).getByLabelText("邮箱地址"), "admin@example.com");
    const password = within(securityRegion).getAllByLabelText("当前密码")[0]! as HTMLInputElement;
    await user.type(password, "Wrong-Password-49!");
    await user.click(screen.getByRole("button", { name: "发送验证码" }));

    expect(await within(securityRegion).findByText(/当前密码不正确/)).toBeTruthy();
    expect(within(securityRegion).queryByText(/无法开始邮箱验证/)).toBeNull();
    expect(password.getAttribute("aria-invalid")).toBe("true");
    expect(password).toBe(document.activeElement);
    expect(password.value).toBe("");
    expect(within(securityRegion).getByLabelText("邮箱地址")).toBeTruthy();
    expect(screen.queryByRole("heading", { name: "登录控制台" })).toBeNull();
    expect(security.notificationContact).toHaveBeenCalledTimes(2);
    expect(security.startNotificationVerification).toHaveBeenCalledTimes(1);
  });

  it("keeps an ambiguous contact authentication rejection generic and clears the password", async () => {
    const none = { accountId: account.id, userId: rootUser.id, state: "NONE" as const, resourceVersion: 0 as const, pendingVerificationId: null };
    const security = {
      notificationContact: vi.fn().mockResolvedValueOnce(none).mockRejectedValue(new HttpProblem(503, "iam.unavailable")),
      authenticatorState: vi.fn().mockResolvedValue({ enrollmentState: "NEVER_BOUND", factorRevision: 1, factorId: null }),
      startNotificationVerification: vi.fn().mockRejectedValue(new HttpProblem(401, "iam.authentication.failed")),
      notificationVerification: vi.fn(), confirmNotificationVerification: vi.fn(),
      startTOTPEnrollment: vi.fn(), totpEnrollment: vi.fn(), totpEnrollmentByRequest: vi.fn(), cancelTOTPEnrollment: vi.fn(), confirmTOTPEnrollment: vi.fn()
    };
    const { user } = await openAccess(accounts(), iam({ personalSecurity: security }), "settings");
    const securityRegion = (await screen.findByRole("heading", { name: "安全通知与身份验证器" })).closest("section")!;
    await within(securityRegion).findByLabelText("邮箱地址");
    await user.type(within(securityRegion).getByLabelText("邮箱地址"), "admin@example.com");
    const password = within(securityRegion).getAllByLabelText("当前密码")[0]! as HTMLInputElement;
    await user.type(password, "Private-Password-49!");
    await user.click(screen.getByRole("button", { name: "发送验证码" }));

    expect(await within(securityRegion).findByText(/当前登录状态无法确认/)).toBeTruthy();
    expect(within(securityRegion).queryByText(/当前密码不正确/)).toBeNull();
    expect(password.getAttribute("aria-invalid")).toBeNull();
    expect(password.value).toBe("");
    expect(screen.queryByRole("heading", { name: "登录控制台" })).toBeNull();
    expect(security.notificationContact).toHaveBeenCalledTimes(2);
  });

  it("freezes an unknown notification start and retries with the original request id without retaining the password", async () => {
    const none = { accountId: account.id, userId: rootUser.id, state: "NONE" as const, resourceVersion: 0 as const, pendingVerificationId: null };
    const pending = { id: "verification-one", accountId: account.id, userId: rootUser.id, requestId: "request-one", email: "admin@example.com", state: "PENDING" as const, issuedAt: timestamp, expiresAt: "2026-09-11T08:10:00Z", completedAt: null, delivery: { state: "PENDING" as const, attempts: 0, lastOutcome: null, lastSmtpCode: null, updatedAt: timestamp } };
    const security = {
      notificationContact: vi.fn().mockResolvedValue(none),
      authenticatorState: vi.fn().mockResolvedValue({ enrollmentState: "NEVER_BOUND", factorRevision: 1, factorId: null }),
      startNotificationVerification: vi.fn()
        .mockRejectedValueOnce(new HttpProblem(503, "iam.unavailable"))
        .mockResolvedValueOnce(pending),
      notificationVerification: vi.fn(), confirmNotificationVerification: vi.fn(),
      startTOTPEnrollment: vi.fn(), totpEnrollment: vi.fn(), totpEnrollmentByRequest: vi.fn(), cancelTOTPEnrollment: vi.fn(), confirmTOTPEnrollment: vi.fn()
    };
    const { user } = await openAccess(accounts(), iam({ personalSecurity: security }), "settings");
    const securityRegion = (await screen.findByRole("heading", { name: "安全通知与身份验证器" })).closest("section")!;
    const email = await within(securityRegion).findByLabelText("邮箱地址") as HTMLInputElement;
    const password = within(securityRegion).getAllByLabelText("当前密码")[0]! as HTMLInputElement;
    await user.type(email, "admin@example.com");
    await user.type(password, "Private-Password-49!");
    await user.click(screen.getByRole("button", { name: "发送验证码" }));

    expect(await within(securityRegion).findByText(/创建验证意图的结果未知/)).toBeTruthy();
    expect(email.disabled).toBe(true);
    expect(password.value).toBe("");
    const firstRequestId = security.startNotificationVerification.mock.calls[0]![1].requestId;

    await user.type(password, "Private-Password-49!");
    await user.click(screen.getByRole("button", { name: "按原请求重试发送" }));
    expect(await screen.findByLabelText("8 位邮箱验证码")).toBeTruthy();
    expect(security.startNotificationVerification.mock.calls[1]![1].requestId).toBe(firstRequestId);
    expect(within(securityRegion).queryByDisplayValue("Private-Password-49!")).toBeNull();
  });

  it("expires the login session only after the contact rejection and bearer-only read both return 401", async () => {
    const none = { accountId: account.id, userId: rootUser.id, state: "NONE" as const, resourceVersion: 0 as const, pendingVerificationId: null };
    const security = {
      notificationContact: vi.fn().mockResolvedValueOnce(none).mockRejectedValue(new HttpProblem(401, "iam.authentication.failed")),
      authenticatorState: vi.fn().mockResolvedValue({ enrollmentState: "NEVER_BOUND", factorRevision: 1, factorId: null }),
      startNotificationVerification: vi.fn().mockRejectedValue(new HttpProblem(401, "iam.authentication.failed")),
      notificationVerification: vi.fn(), confirmNotificationVerification: vi.fn(),
      startTOTPEnrollment: vi.fn(), totpEnrollment: vi.fn(), totpEnrollmentByRequest: vi.fn(), cancelTOTPEnrollment: vi.fn(), confirmTOTPEnrollment: vi.fn()
    };
    const { user } = await openAccess(accounts(), iam({ personalSecurity: security }), "settings");
    const securityRegion = (await screen.findByRole("heading", { name: "安全通知与身份验证器" })).closest("section")!;
    await within(securityRegion).findByLabelText("邮箱地址");
    await user.type(within(securityRegion).getByLabelText("邮箱地址"), "admin@example.com");
    await user.type(within(securityRegion).getAllByLabelText("当前密码")[0]!, "Private-Password-49!");
    await user.click(screen.getByRole("button", { name: "发送验证码" }));

    expect(await screen.findByRole("heading", { name: "登录控制台" })).toBeTruthy();
    expect(security.notificationContact).toHaveBeenCalledTimes(2);
  });

  it("shows INITIAL APPLIED provisioning once and cannot restore it from a metadata query after remount", async () => {
    const verified = { accountId: account.id, userId: rootUser.id, state: "VERIFIED" as const, resourceVersion: 1, email: "admin@example.com", verifiedAt: timestamp, pendingVerificationId: null };
    const enrollment = { apiVersion: "iam.matrix.xiak.com/v1", kind: "TOTPEnrollment", id: "enrollment-applied", requestId: "", purpose: "INITIAL", factorRevision: 1, state: "PENDING", createdAt: timestamp, expiresAt: "2026-09-11T08:05:00Z" };
    const seed = "INITIALSECRETONCE2345";
    const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      if (init?.method === "POST") {
        expect(String(input)).toBe("/api/iam/v1/auth/totp/enrollments");
        enrollment.requestId = JSON.parse(String(init.body)).requestId;
        return new Response(JSON.stringify({ outcome: "APPLIED", enrollment, provisioning: { seed, uri: `otpauth://totp/Matrix:admin?secret=${seed}` } }), { status: 200 });
      }
      expect(String(input)).toBe(`/api/iam/v1/auth/totp/enrollments/by-request/${enrollment.requestId}`);
      return new Response(JSON.stringify(enrollment), { status: 200 });
    });
    vi.stubGlobal("fetch", fetcher);
    const security = {
      notificationContact: vi.fn().mockResolvedValue(verified),
      authenticatorState: vi.fn().mockResolvedValue({ enrollmentState: "NEVER_BOUND" as const, factorRevision: 1, factorId: null }),
      startNotificationVerification: vi.fn(), notificationVerification: vi.fn(), confirmNotificationVerification: vi.fn(),
      startTOTPEnrollment: vi.fn(httpIamRepository.personalSecurity!.startTOTPEnrollment),
      totpEnrollment: vi.fn(), totpEnrollmentByRequest: vi.fn(httpIamRepository.personalSecurity!.totpEnrollmentByRequest), cancelTOTPEnrollment: vi.fn(), confirmTOTPEnrollment: vi.fn()
    };
    const { user, view } = await openAccess(accounts(), iam({ personalSecurity: security }), "settings");
    await screen.findByText("admin@example.com");
    await user.type(screen.getByLabelText("当前密码"), "Private-Password-49!");
    await user.click(screen.getByRole("button", { name: "开始绑定" }));
    expect(await screen.findByText(seed, { exact: true })).toBeTruthy();
    expect(screen.getByLabelText("6 位动态验证码")).toBeTruthy();
    expect(screen.queryByText(/首次绑定提交结果未知/)).toBeNull();
    expect(view.container.innerHTML).not.toContain("Private-Password-49!");
    const command = JSON.parse(String(fetcher.mock.calls[0]![1]!.body));
    expect(command).toEqual({ requestId: expect.stringMatching(/^ui-totp-enroll-/), password: "Private-Password-49!", expectedFactorRevision: 1 });
    await user.click(screen.getByTestId("nav-users"));
    await screen.findByRole("table", { name: "租户用户列表" });
    await user.click(screen.getByTestId("nav-settings"));
    expect(await screen.findByText(enrollment.requestId)).toBeTruthy();
    expect(screen.queryByText(seed, { exact: true })).toBeNull();
    await user.click(screen.getByRole("button", { name: "查询原绑定意图" }));
    expect(await screen.findByText(/等值重放/)).toBeTruthy();
    expect(screen.queryByText(seed, { exact: true })).toBeNull();
    expect(screen.queryByLabelText("6 位动态验证码")).toBeNull();
    expect(fetcher.mock.calls.filter(([, init]) => init?.method === "POST")).toHaveLength(1);
    expect(localStorage.length + sessionStorage.length).toBe(0);
  });

  it("never renders TOTP provisioning or confirmation controls for an equal replay", async () => {
    const verified = { accountId: account.id, userId: rootUser.id, state: "VERIFIED" as const, resourceVersion: 1, email: "admin@example.com", verifiedAt: timestamp, pendingVerificationId: null };
    const enrollment = { id: "enrollment-one", requestId: "request-one", purpose: "INITIAL" as const, factorRevision: 1, state: "PENDING" as const, createdAt: timestamp, expiresAt: "2026-09-11T08:05:00Z", completedAt: null };
    vi.stubGlobal("fetch", vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      enrollment.requestId = JSON.parse(String(init?.body)).requestId;
      return new Response(JSON.stringify({ outcome: "EQUAL_REPLAY", enrollment: { apiVersion: "iam.matrix.xiak.com/v1", kind: "TOTPEnrollment", ...enrollment, completedAt: undefined } }), { status: 200 });
    }));
    const security = {
      notificationContact: vi.fn().mockResolvedValue(verified),
      authenticatorState: vi.fn().mockResolvedValue({ enrollmentState: "NEVER_BOUND" as const, factorRevision: 1, factorId: null }),
      startNotificationVerification: vi.fn(), notificationVerification: vi.fn(), confirmNotificationVerification: vi.fn(),
      startTOTPEnrollment: vi.fn(httpIamRepository.personalSecurity!.startTOTPEnrollment),
      totpEnrollment: vi.fn(), totpEnrollmentByRequest: vi.fn(), cancelTOTPEnrollment: vi.fn().mockResolvedValue({ ...enrollment, state: "CANCELLED", completedAt: "2026-09-11T08:01:00Z" }), confirmTOTPEnrollment: vi.fn()
    };
    const { user } = await openAccess(accounts(), iam({ personalSecurity: security }), "settings");
    const securityRegion = (await screen.findByRole("heading", { name: "安全通知与身份验证器" })).closest("section")!;
    await within(securityRegion).findByText("admin@example.com");
    await user.type(screen.getByLabelText("当前密码"), "Private-Password-49!");
    await user.click(screen.getByRole("button", { name: "开始绑定" }));
    expect(await screen.findByText(/等值重放/)).toBeTruthy();
    expect(screen.queryByLabelText("6 位动态验证码")).toBeNull();
    expect(screen.queryByText(/手动密钥/)).toBeNull();
    expect(screen.getByRole("button", { name: "取消绑定" })).toBeTruthy();
    expect(security.confirmTOTPEnrollment).not.toHaveBeenCalled();
  });

  it("keeps an unknown first-enrollment request across content remounts and resolves only that intent", async () => {
    const verified = { accountId: account.id, userId: rootUser.id, state: "VERIFIED" as const, resourceVersion: 1, email: "admin@example.com", verifiedAt: timestamp, pendingVerificationId: null };
    let originalRequestId = "";
    const enrollment = { id: "enrollment-unknown", requestId: "", purpose: "INITIAL" as const, factorRevision: 1, state: "PENDING" as const, createdAt: timestamp, expiresAt: "2026-09-11T08:05:00Z", completedAt: null };
    const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input) === "/api/iam/v1/auth/totp/enrollments" && init?.method === "POST") {
        originalRequestId = JSON.parse(String(init.body)).requestId;
        enrollment.requestId = originalRequestId;
        throw new Error("connection lost after submit");
      }
      expect(String(input)).toBe(`/api/iam/v1/auth/totp/enrollments/by-request/${originalRequestId}`);
      return new Response(JSON.stringify({ apiVersion: "iam.matrix.xiak.com/v1", kind: "TOTPEnrollment", ...enrollment, completedAt: undefined }), { status: 200 });
    });
    vi.stubGlobal("fetch", fetcher);
    const security = {
      notificationContact: vi.fn().mockResolvedValue(verified),
      authenticatorState: vi.fn().mockResolvedValue({ enrollmentState: "NEVER_BOUND" as const, factorRevision: 1, factorId: null }),
      startNotificationVerification: vi.fn(), notificationVerification: vi.fn(), confirmNotificationVerification: vi.fn(),
      startTOTPEnrollment: vi.fn(httpIamRepository.personalSecurity!.startTOTPEnrollment),
      totpEnrollment: vi.fn(),
      totpEnrollmentByRequest: vi.fn(httpIamRepository.personalSecurity!.totpEnrollmentByRequest),
      cancelTOTPEnrollment: vi.fn().mockImplementation(async (_credential: string, enrollmentId: string) => ({ ...enrollment, id: enrollmentId, state: "CANCELLED" as const, completedAt: "2026-09-11T08:02:00Z" })),
      confirmTOTPEnrollment: vi.fn()
    };
    const { user, view } = await openAccess(accounts(), iam({ personalSecurity: security }), "settings");
    await screen.findByText("admin@example.com");
    await user.type(screen.getByLabelText("当前密码"), "Private-Password-49!");
    await user.click(screen.getByRole("button", { name: "开始绑定" }));

    expect(await screen.findByText(/上一次绑定请求的结果尚未确认/)).toBeTruthy();
    expect(screen.getByText(originalRequestId)).toBeTruthy();
    expect(screen.queryByLabelText("当前密码")).toBeNull();
    expect(view.container.innerHTML).not.toContain("Private-Password-49!");

    await user.click(screen.getByTestId("nav-users"));
    await screen.findByRole("table", { name: "租户用户列表" });
    await user.click(screen.getByTestId("nav-settings"));
    expect(await screen.findByText(originalRequestId)).toBeTruthy();
    expect(screen.queryByLabelText("当前密码")).toBeNull();

    await user.click(screen.getByRole("button", { name: "查询原绑定意图" }));
    expect(await screen.findByText(/等值重放/)).toBeTruthy();
    expect(security.totpEnrollmentByRequest).toHaveBeenCalledWith(credential, originalRequestId);
    expect(screen.queryByLabelText("6 位动态验证码")).toBeNull();
    expect(screen.queryByText(/手动设置密钥/)).toBeNull();
    expect(fetcher.mock.calls.filter(([, init]) => init?.method === "POST")).toHaveLength(1);

    await user.click(screen.getByRole("button", { name: "取消绑定" }));
    await waitFor(() => expect(security.cancelTOTPEnrollment).toHaveBeenCalledWith(credential, "enrollment-unknown"));
    expect(await screen.findByRole("button", { name: "开始绑定" })).toBeTruthy();
    expect(screen.getByLabelText("当前密码")).toHaveProperty("value", "");
    expect(localStorage.length + sessionStorage.length).toBe(0);
  });

  it("does not treat a missing by-request lookup as proof that an unknown enrollment never committed", async () => {
    const verified = { accountId: account.id, userId: rootUser.id, state: "VERIFIED" as const, resourceVersion: 1, email: "admin@example.com", verifiedAt: timestamp, pendingVerificationId: null };
    const security = {
      notificationContact: vi.fn().mockResolvedValue(verified),
      authenticatorState: vi.fn().mockResolvedValue({ enrollmentState: "NEVER_BOUND" as const, factorRevision: 1, factorId: null }),
      startNotificationVerification: vi.fn(), notificationVerification: vi.fn(), confirmNotificationVerification: vi.fn(),
      startTOTPEnrollment: vi.fn().mockRejectedValue(new Error("connection lost after submit")),
      totpEnrollment: vi.fn(), totpEnrollmentByRequest: vi.fn().mockRejectedValue(new HttpProblem(404, "IAM_NOT_FOUND")), cancelTOTPEnrollment: vi.fn(), confirmTOTPEnrollment: vi.fn()
    };
    const { user } = await openAccess(accounts(), iam({ personalSecurity: security }), "settings");
    await screen.findByText("admin@example.com");
    await user.type(screen.getByLabelText("当前密码"), "Private-Password-49!");
    await user.click(screen.getByRole("button", { name: "开始绑定" }));
    await user.click(await screen.findByRole("button", { name: "查询原绑定意图" }));

    expect(await screen.findByText(/不能证明请求从未提交/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: "开始绑定" })).toBeNull();
    expect(screen.getByRole("button", { name: "查询原绑定意图" })).toBeTruthy();
  });

  it("regenerates recovery codes through a purpose-limited live step-up and clears one-time material", async () => {
    const verified = { accountId: account.id, userId: rootUser.id, state: "VERIFIED" as const, resourceVersion: 1, email: "admin@example.com", verifiedAt: timestamp, pendingVerificationId: null };
    let operationRequestId = "";
    const recoveryCodes = Array.from({ length: 10 }, (_, index) => `ROTATED-RECOVERY-${index}`);
    const recovery = {
      startStepUp: vi.fn().mockImplementation(async (_credential: string, command: { requestId: string; expectedFactorRevision: number }) => {
        operationRequestId = command.requestId;
        return { id: "step-up-one", requestId: command.requestId, operation: "RECOVERY_CODES_REGENERATE" as const, expectedFactorRevision: 2, state: "PENDING" as const, createdAt: timestamp, expiresAt: "2026-09-11T08:02:00Z", provedAt: null, consumedAt: null };
      }),
      stepUpByRequest: vi.fn(),
      verifyStepUp: vi.fn().mockImplementation(async () => ({ id: "step-up-one", requestId: operationRequestId, operation: "RECOVERY_CODES_REGENERATE" as const, expectedFactorRevision: 2, state: "PROVED" as const, createdAt: timestamp, expiresAt: "2026-09-11T08:02:00Z", provedAt: "2026-09-11T08:00:30Z", consumedAt: null })),
      regenerate: vi.fn().mockImplementation(async () => ({ outcome: "APPLIED" as const, regeneration: { id: "regeneration-one", requestId: operationRequestId, factorId: "factor-one", factorRevision: 2, createdAt: "2026-09-11T08:00:40Z" }, recoveryCodes })),
      regenerationByRequest: vi.fn()
    };
    const security = {
      notificationContact: vi.fn().mockResolvedValue(verified),
      authenticatorState: vi.fn().mockResolvedValue({ enrollmentState: "BOUND" as const, factorRevision: 2, factorId: "factor-one" }),
      startNotificationVerification: vi.fn(), notificationVerification: vi.fn(), confirmNotificationVerification: vi.fn(),
      startTOTPEnrollment: vi.fn(), totpEnrollment: vi.fn(), totpEnrollmentByRequest: vi.fn(), cancelTOTPEnrollment: vi.fn(), confirmTOTPEnrollment: vi.fn(),
      recoveryCodes: recovery
    };
    const { user, view } = await openAccess(accounts(), iam({ personalSecurity: security }), "settings");
    await screen.findByText("admin@example.com");
    await user.click(screen.getByRole("button", { name: "重新生成恢复码" }));
    await user.type(screen.getByLabelText("当前密码"), "Private-Password-49!");
    await user.type(screen.getByLabelText("6 位动态验证码"), "123456");
    await user.click(screen.getByRole("button", { name: "验证本次操作" }));
    expect(await screen.findByRole("button", { name: "生成新的 10 条恢复码" })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "生成新的 10 条恢复码" }));
    const list = await screen.findByRole("list", { name: "新恢复码" });
    expect(within(list).getByText("ROTATED-RECOVERY-9")).toBeTruthy();
    expect(screen.queryByLabelText("当前密码")).toBeNull();
    expect(screen.queryByLabelText("6 位动态验证码")).toBeNull();
    expect(view.container.innerHTML).not.toContain("Private-Password-49!");
    expect(view.container.innerHTML).not.toContain(credential);
    expect(recovery.startStepUp).toHaveBeenCalledWith(credential, { requestId: operationRequestId, expectedFactorRevision: 2 });
    expect(recovery.regenerate).toHaveBeenCalledWith(credential, { requestId: operationRequestId, stepUpId: "step-up-one", expectedFactorRevision: 2 });
    await user.click(screen.getByRole("checkbox", { name: "我已安全保存全部新恢复码" }));
    await user.click(screen.getByRole("button", { name: "完成并清除页面材料" }));
    expect(screen.queryByText("ROTATED-RECOVERY-9")).toBeNull();
    expect(screen.getByRole("button", { name: "重新生成恢复码" })).toBeTruthy();
    expect(localStorage.length + sessionStorage.length).toBe(0);
  });

  it("retries an unknown step-up creation only with the frozen request", async () => {
    const verified = { accountId: account.id, userId: rootUser.id, state: "VERIFIED" as const, resourceVersion: 1, email: "admin@example.com", verifiedAt: timestamp, pendingVerificationId: null };
    const requestIds: string[] = [];
    const recovery = {
      startStepUp: vi.fn().mockImplementation(async (_credential: string, command: { requestId: string }) => {
        requestIds.push(command.requestId);
        if (requestIds.length === 1) throw new Error("connection lost after step-up creation");
        return { id: "step-up-retried", requestId: command.requestId, operation: "RECOVERY_CODES_REGENERATE" as const, expectedFactorRevision: 2, state: "PENDING" as const, createdAt: timestamp, expiresAt: "2026-09-11T08:02:00Z", provedAt: null, consumedAt: null };
      }),
      stepUpByRequest: vi.fn(), verifyStepUp: vi.fn(), regenerate: vi.fn(), regenerationByRequest: vi.fn()
    };
    const security = {
      notificationContact: vi.fn().mockResolvedValue(verified),
      authenticatorState: vi.fn().mockResolvedValue({ enrollmentState: "BOUND" as const, factorRevision: 2, factorId: "factor-one" }),
      startNotificationVerification: vi.fn(), notificationVerification: vi.fn(), confirmNotificationVerification: vi.fn(),
      startTOTPEnrollment: vi.fn(), totpEnrollment: vi.fn(), totpEnrollmentByRequest: vi.fn(), cancelTOTPEnrollment: vi.fn(), confirmTOTPEnrollment: vi.fn(),
      recoveryCodes: recovery
    };
    const { user } = await openAccess(accounts(), iam({ personalSecurity: security }), "settings");
    await screen.findByText("admin@example.com");
    await user.click(screen.getByRole("button", { name: "重新生成恢复码" }));
    expect(await screen.findByText("用途限定验证的创建结果未知。不要创建第二个意图；请查询原 requestId，或用完全相同的请求重试。")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "重新生成恢复码" })).toBeNull();
    await user.click(screen.getByRole("button", { name: "按原请求重试" }));
    expect(await screen.findByLabelText("当前密码")).toBeTruthy();
    expect(requestIds).toHaveLength(2);
    expect(requestIds[1]).toBe(requestIds[0]);
  });

  it("does not interpret a rejected step-up password or OTP as proof that the login bearer expired", async () => {
    const verified = { accountId: account.id, userId: rootUser.id, state: "VERIFIED" as const, resourceVersion: 1, email: "admin@example.com", verifiedAt: timestamp, pendingVerificationId: null };
    let operationRequestId = "";
    const recovery = {
      startStepUp: vi.fn().mockImplementation(async (_credential: string, command: { requestId: string }) => {
        operationRequestId = command.requestId;
        return { id: "step-up-rejected", requestId: command.requestId, operation: "RECOVERY_CODES_REGENERATE" as const, expectedFactorRevision: 2, state: "PENDING" as const, createdAt: timestamp, expiresAt: "2026-09-11T08:02:00Z", provedAt: null, consumedAt: null };
      }),
      stepUpByRequest: vi.fn(),
      verifyStepUp: vi.fn().mockRejectedValue(new HttpProblem(401, "iam.authentication.failed")),
      regenerate: vi.fn(), regenerationByRequest: vi.fn()
    };
    const security = {
      notificationContact: vi.fn().mockResolvedValue(verified),
      authenticatorState: vi.fn().mockResolvedValue({ enrollmentState: "BOUND" as const, factorRevision: 2, factorId: "factor-one" }),
      startNotificationVerification: vi.fn(), notificationVerification: vi.fn(), confirmNotificationVerification: vi.fn(),
      startTOTPEnrollment: vi.fn(), totpEnrollment: vi.fn(), totpEnrollmentByRequest: vi.fn(), cancelTOTPEnrollment: vi.fn(), confirmTOTPEnrollment: vi.fn(), recoveryCodes: recovery
    };
    const { user } = await openAccess(accounts(), iam({ personalSecurity: security }), "settings");
    await screen.findByText("admin@example.com");
    await user.click(screen.getByRole("button", { name: "重新生成恢复码" }));
    await user.type(screen.getByLabelText("当前密码"), "Wrong-Password-49!");
    await user.type(screen.getByLabelText("6 位动态验证码"), "123456");
    await user.click(screen.getByRole("button", { name: "验证本次操作" }));
    expect(await screen.findByText(/密码或动态验证码未通过/)).toBeTruthy();
    expect(screen.getByRole("heading", { name: "安全通知与身份验证器" })).toBeTruthy();
    expect(screen.getByTestId("nav-settings").getAttribute("aria-current")).toBe("page");
    expect(screen.queryByRole("button", { name: "登录控制台" })).toBeNull();
    expect(screen.getByText(operationRequestId)).toBeTruthy();
  });

  it("never replays proof secrets or a regeneration after an unknown outcome", async () => {
    const verified = { accountId: account.id, userId: rootUser.id, state: "VERIFIED" as const, resourceVersion: 1, email: "admin@example.com", verifiedAt: timestamp, pendingVerificationId: null };
    let operationRequestId = "";
    const pending = () => ({ id: "step-up-unknown", requestId: operationRequestId, operation: "RECOVERY_CODES_REGENERATE" as const, expectedFactorRevision: 2, state: "PENDING" as const, createdAt: timestamp, expiresAt: "2026-09-11T08:02:00Z", provedAt: null, consumedAt: null });
    const proved = () => ({ ...pending(), state: "PROVED" as const, provedAt: "2026-09-11T08:00:30Z" });
    const recovery = {
      startStepUp: vi.fn().mockImplementation(async (_credential: string, command: { requestId: string }) => { operationRequestId = command.requestId; return pending(); }),
      stepUpByRequest: vi.fn().mockImplementation(async () => proved()),
      verifyStepUp: vi.fn().mockRejectedValue(new Error("connection lost after proof submission")),
      regenerate: vi.fn().mockRejectedValue(new Error("connection lost after regeneration submission")),
      regenerationByRequest: vi.fn().mockImplementation(async () => ({ id: "regeneration-unknown", requestId: operationRequestId, factorId: "factor-one", factorRevision: 2, createdAt: "2026-09-11T08:00:40Z" }))
    };
    const security = {
      notificationContact: vi.fn().mockResolvedValue(verified),
      authenticatorState: vi.fn().mockResolvedValue({ enrollmentState: "BOUND" as const, factorRevision: 2, factorId: "factor-one" }),
      startNotificationVerification: vi.fn(), notificationVerification: vi.fn(), confirmNotificationVerification: vi.fn(),
      startTOTPEnrollment: vi.fn(), totpEnrollment: vi.fn(), totpEnrollmentByRequest: vi.fn(), cancelTOTPEnrollment: vi.fn(), confirmTOTPEnrollment: vi.fn(),
      recoveryCodes: recovery
    };
    const { user, view } = await openAccess(accounts(), iam({ personalSecurity: security }), "settings");
    await screen.findByText("admin@example.com");
    await user.click(screen.getByRole("button", { name: "重新生成恢复码" }));
    await user.type(screen.getByLabelText("当前密码"), "Private-Password-49!");
    await user.type(screen.getByLabelText("6 位动态验证码"), "123456");
    await user.click(screen.getByRole("button", { name: "验证本次操作" }));
    expect(await screen.findByText(/结果未知时只能读取原安全验证状态/)).toBeTruthy();
    expect(screen.queryByLabelText("当前密码")).toBeNull();
    expect(screen.queryByLabelText("6 位动态验证码")).toBeNull();
    expect(view.container.innerHTML).not.toContain("Private-Password-49!");
    await user.click(screen.getByRole("button", { name: "查询原安全验证" }));
    expect(await screen.findByRole("button", { name: "生成新的 10 条恢复码" })).toBeTruthy();
    expect(recovery.verifyStepUp).toHaveBeenCalledTimes(1);

    await user.click(screen.getByRole("button", { name: "生成新的 10 条恢复码" }));
    expect(await screen.findByText("重新生成结果未知。不要再次提交或创建第二个意图；请只查询原 requestId。")).toBeTruthy();
    await user.click(screen.getByTestId("nav-users"));
    await screen.findByRole("table", { name: "租户用户列表" });
    await user.click(screen.getByTestId("nav-settings"));
    expect(await screen.findByText(operationRequestId)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "查询原重新生成结果" }));
    expect(await screen.findByText(/一次性恢复码材料已不在当前页面/)).toBeTruthy();
    expect(screen.queryByRole("list", { name: "新恢复码" })).toBeNull();
    expect(recovery.regenerate).toHaveBeenCalledTimes(1);
    expect(recovery.regenerationByRequest).toHaveBeenCalledWith(credential, operationRequestId);
  });

  it("allows an unprivileged user to inspect its own settings without querying admin directories", async () => {
    const reader: AccountIdentity = { ...identity, user: child.user, identityKind: "USER", permissionBoundary: { accountId: account.id, userId: child.user.id, resourceVersion: child.user.resourceVersion, policy: null }, policySources: [], capabilities: currentCapabilities(false) };
    const repository = accounts({ currentIdentity: vi.fn().mockResolvedValue(reader), listUsers: vi.fn().mockRejectedValue(new HttpProblem(403, "FORBIDDEN")) });
    await openAccess(repository, iam({}, "child-a"), "overview");
    await screen.findByText("未授权");
    expect(repository.listUsers).not.toHaveBeenCalled();
    expect(repository.listAccounts).not.toHaveBeenCalled();
    expect(screen.queryByRole("tab", { name: "租户管理" })).toBeNull();
    expect(screen.queryByRole("button", { name: "保存别名" })).toBeNull();
    expect(screen.getByText("username@tenant-a")).toBeTruthy();
  });

  it("keeps the tenant policy directory usable when only the platform directory is forbidden", async () => {
    const listPolicies = vi.fn(async (_credential: string, platform: boolean) => {
      if (platform) throw new HttpProblem(403, "FORBIDDEN");
      return directory(false);
    });
    const repository = accounts({ listPolicies });
    await openAccess(repository, iam(), "policies");
    const table = await screen.findByRole("table", { name: "策略元数据目录" });
    expect(table.getAttribute("data-mobile-layout")).toBe("stack");
    const policyRow = within(table).getByRole("button", { name: "ReadOnlyAccess" }).closest("tr")!;
    expect(policyRow.cells[0]?.getAttribute("data-label")).toBe("策略");
    expect(policyRow.cells[5]?.getAttribute("data-label")).toBe("更新时间");
    expect(screen.getByText("ReadOnlyAccess")).toBeTruthy();
    expect(screen.getByText(/租户策略仍可查看/)).toBeTruthy();
    expect(listPolicies).toHaveBeenCalledTimes(2);
  });

  it("reads a tenant policy's default document only after opening its detail and keeps platform metadata separate", async () => {
    const readPolicy = vi.fn().mockResolvedValue(policyAccess(tenantPolicyDetail));
    const { user } = await openAccess(accounts({ readPolicy }), iam(), "policies");
    await screen.findByRole("table", { name: "策略元数据目录" });
    expect(readPolicy).not.toHaveBeenCalled();

    await user.click(screen.getByRole("button", { name: tenantPolicy.displayName }));
    expect(await screen.findByRole("table", { name: "策略声明" })).toBeTruthy();
    expect(readPolicy).toHaveBeenCalledWith(credential, account.id, tenantPolicy.id);
    expect(screen.getByText("paas.application.read")).toBeTruthy();
    expect(screen.getByText(/不代表当前身份或任何主体的有效权限/)).toBeTruthy();
    const provenance = screen.getByRole("region", { name: "发布编译溯源" });
    expect(within(provenance).getByText("旧版")).toBeTruthy();
    expect(within(provenance).getByText(/不会用当前目录推断或改写历史结果/)).toBeTruthy();
    expect(within(provenance).queryByRole("table")).toBeNull();
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(screen.queryByRole("button", { name: "保存" })).toBeNull();

    await user.click(screen.getByRole("button", { name: "返回列表" }));
    await user.click(screen.getByRole("button", { name: platformPolicy.displayName }));
    expect(screen.getByText(/平台安装策略当前只提供目录元数据/)).toBeTruthy();
    expect(readPolicy).toHaveBeenCalledTimes(1);
  });

  it("separates authored family syntax from the frozen v2 action expansion", async () => {
    const readPolicy = vi.fn().mockResolvedValue(policyAccess({ ...tenantPolicyDetail, version: {
      ...tenantPolicyDetail.version, contractVersion: 2,
      document: { ...tenantPolicyDetail.version.document, statements: [{ ...tenantPolicyDetail.version.document.statements[0],
        actions: ["paas.application.*"] }] },
      compilation: { compilationVersion: "1", profiles: [{ product: "paas", revision: 2,
        contentDigest: `sha256:${"b".repeat(64)}` }], resolvedStatements: [{ sid: "read-applications", actions: ["paas.application.read"] }] }
    } } as AccountPolicyDetail));
    const { user } = await openAccess(accounts({ readPolicy }), iam(), "policies");
    await user.click(await screen.findByRole("button", { name: tenantPolicy.displayName }));
    const table = await screen.findByRole("table", { name: "策略声明" });
    expect(within(table).getByText("paas.application.*")).toBeTruthy();
    expect(within(table).getByText("发布时冻结的 Action")).toBeTruthy();
    expect(within(table).getByText("paas.application.read")).toBeTruthy();
    const provenance = screen.getByRole("region", { name: "发布编译溯源" });
    expect(within(provenance).getByText("编译契约 v1")).toBeTruthy();
    const profiles = within(provenance).getByRole("table", { name: "冻结的产品声明快照" });
    expect(within(profiles).getByText("paas")).toBeTruthy();
    expect(within(profiles).getByText("2")).toBeTruthy();
    expect(within(profiles).getByText(`sha256:${"b".repeat(64)}`)).toBeTruthy();
  });

  it("loads customer versions only when selected and inspects a non-default version inline", async () => {
    const customer = { ...tenantPolicy, id: "customer.logs", management: "CUSTOMER" as const, accountId: account.id,
      displayName: "LogBoundary", defaultVersionId: "version-logs" };
    const current = { ...tenantPolicyDetail.version, policyId: customer.id, versionId: customer.defaultVersionId };
    const earlier = { ...current, versionId: "version-a", contentDigest: `sha256:${"b".repeat(64)}` };
    const readPolicy = vi.fn().mockResolvedValue(policyAccess({ policy: customer, version: current }));
    const listPolicyVersions = vi.fn().mockResolvedValue({ policy: customer, items: [earlier, current] });
    const readPolicyVersion = vi.fn().mockResolvedValue({ policy: customer, version: earlier });
    const repository = accounts({ readPolicy, listPolicyVersions, readPolicyVersion,
      listPolicies: vi.fn(async (_credential: string, platform: boolean) => platform ? directory(true) : { ...directory(false), items: [customer, tenantPolicy] }) });
    const { user } = await openAccess(repository, iam(), "policies");
    await user.click(await screen.findByRole("button", { name: customer.displayName }));
    expect(await screen.findByRole("tab", { name: "策略版本" })).toBeTruthy();
    expect(listPolicyVersions).not.toHaveBeenCalled();
    expect(readPolicyVersion).not.toHaveBeenCalled();

    await user.click(screen.getByRole("tab", { name: "策略版本" }));
    const table = await screen.findByRole("table", { name: "策略版本目录" });
    expect(within(table).queryByRole("columnheader", { name: "操作" })).toBeNull();
    expect(within(table).getByText("当前默认")).toBeTruthy();
    expect(screen.getByText("当前可管理版本：2 / 5")).toBeTruthy();
    expect(listPolicyVersions).toHaveBeenCalledWith(credential, account.id, customer.id);
    expect(readPolicyVersion).not.toHaveBeenCalled();

    await user.click(within(table).getByRole("button", { name: "version-a" }));
    expect(await screen.findByRole("heading", { name: "查看版本 version-a" })).toBe(document.activeElement);
    expect(await screen.findByRole("table", { name: "策略声明" })).toBeTruthy();
    expect(readPolicyVersion).toHaveBeenCalledWith(credential, account.id, customer.id, "version-a");
    expect(screen.queryByRole("dialog")).toBeNull();
    await user.click(screen.getByRole("button", { name: "返回版本目录" }));
    expect(within(screen.getByRole("table", { name: "策略版本目录" })).getByRole("button", { name: "version-a" })).toBe(document.activeElement);
  });

  it("renames live Policy metadata inline with old/new review, byte validation and a stable target", async () => {
    enablePolicyLocks(); const fixture = livePolicyMetadata();
    const { user } = await openAccess(fixture.repository, iam(), "policies");
    await user.click(await screen.findByRole("button", { name: "LogBoundary" }));
    await screen.findByRole("table", { name: "策略声明" });
    await invokeMoreAction(user, "修改显示名");
    const group = screen.getByRole("group", { name: "修改显示名 · LogBoundary" });
    expect(within(group).getByRole("heading", { name: "修改显示名 · LogBoundary" })).toBe(document.activeElement);
    expect(screen.queryByRole("dialog")).toBeNull();
    const field = within(group).getByRole("textbox", { name: "新显示名" });
    for (const value of ["", " space ", "汉".repeat(43)]) {
      fireEvent.change(field, { target: { value } });
      expect(within(group).getByRole("button", { name: "审阅修改" }).hasAttribute("disabled")).toBe(true);
    }
    expect(fixture.updatePolicy).not.toHaveBeenCalled();
    fireEvent.change(field, { target: { value: "Production log reader" } });
    await user.click(within(group).getByRole("button", { name: "审阅修改" }));
    const review = screen.getByRole("group", { name: "审阅显示名修改 · LogBoundary" });
    expect(within(review).getByText("LogBoundary")).toBeTruthy(); expect(within(review).getByText("Production log reader")).toBeTruthy();
    expect(fixture.updatePolicy).not.toHaveBeenCalled();
    await user.click(within(review).getByRole("button", { name: "确认修改显示名" }));
    expect(await screen.findByRole("heading", { name: "Production log reader" })).toBeTruthy();
    expect(fixture.updatePolicy).toHaveBeenCalledTimes(1);
    expect(fixture.updatePolicy.mock.calls[0]![3]).toEqual({ displayName: "Production log reader", resourceVersion: 4, requestId: expect.stringMatching(/^ui-policy-metadata-/) });
    expect(fixture.updatePolicy.mock.calls[0]![2]).toEqual({ policy: expect.objectContaining({ id: "customer.logs", defaultVersionId: "version-logs", displayName: "LogBoundary" }), contentDigest: fixture.version.contentDigest });
    await waitFor(() => expect(fixture.readPolicy.mock.calls.length).toBeGreaterThan(1));
    expect(fixture.listPolicies.mock.calls.length).toBeGreaterThan(2); expect(fixture.deletePolicy).not.toHaveBeenCalled();
  });

  it("cancels a whole-Policy review without writes and requires an exact typed name before terminal retirement", async () => {
    enablePolicyLocks(); const fixture = livePolicyMetadata(); const { user } = await openAccess(fixture.repository, iam(), "policies");
    await user.click(await screen.findByRole("button", { name: "LogBoundary" }));
    await invokeMoreAction(user, "退役整条策略");
    let group = screen.getByRole("group", { name: "退役整条策略 · LogBoundary" });
    expect(within(group).getByText(/保留版本和审计，不支持恢复/)).toBeTruthy();
    expect(within(group).getByText(/不会自动解除任何关联/)).toBeTruthy();
    await user.click(within(group).getByRole("button", { name: "取消" }));
    expect(fixture.deletePolicy).not.toHaveBeenCalled();
    await waitFor(() => expect(screen.getByRole("button", { name: "更多操作" })).toBe(document.activeElement));
    await invokeMoreAction(user, "退役整条策略"); group = screen.getByRole("group", { name: "退役整条策略 · LogBoundary" });
    const field = within(group).getByRole("textbox", { name: "输入策略显示名「LogBoundary」确认" });
    for (const value of ["logboundary", "LogBoundary ", "different"]) {
      fireEvent.change(field, { target: { value } });
      expect(within(group).getByRole("button", { name: "确认退役整条策略" }).hasAttribute("disabled")).toBe(true);
    }
    expect(fixture.deletePolicy).not.toHaveBeenCalled(); fireEvent.change(field, { target: { value: "LogBoundary" } });
    await user.click(within(group).getByRole("button", { name: "确认退役整条策略" }));
    await screen.findByRole("table", { name: "策略元数据目录" });
    expect(screen.queryByRole("button", { name: "LogBoundary" })).toBeNull();
    expect(fixture.deletePolicy).toHaveBeenCalledTimes(1); expect(fixture.updatePolicy).not.toHaveBeenCalled();
    expect(fixture.deletePolicy.mock.calls[0]![3]).toEqual({ resourceVersion: 4, requestId: expect.stringMatching(/^ui-policy-metadata-/) });
    expect(screen.queryByRole("button", { name: /恢复策略|回收站/ })).toBeNull();
  });

  it("keeps system Policy actions disabled with a reason rather than treating Root as an unrestricted editor", async () => {
    enablePolicyLocks(); const fixture = livePolicyMetadata(); const { user } = await openAccess(fixture.repository, iam(), "policies");
    await user.click(await screen.findByRole("button", { name: "ReadOnlyAccess" }));
    await user.click(await screen.findByRole("button", { name: "更多操作" }));
    const menu = await screen.findByRole("menu", { name: "更多操作" });
    expect(within(menu).getByRole("menuitem", { name: "修改显示名" }).getAttribute("aria-disabled")).toBe("true");
    expect(within(menu).getByRole("menuitem", { name: "退役整条策略" }).getAttribute("aria-disabled")).toBe("true");
    expect(within(menu).getByText(/系统、平台、其他账户或已退役策略/)).toBeTruthy();
    expect(fixture.updatePolicy).not.toHaveBeenCalled(); expect(fixture.deletePolicy).not.toHaveBeenCalled();
  });

  it("lets a delegated identity request the same Policy rename path but reports a definite IAM denial without inventing a capability", async () => {
    enablePolicyLocks(); const fixture = livePolicyMetadata();
    fixture.repository.currentIdentity = vi.fn().mockResolvedValue({ ...identity, user: childUser, identityKind: "USER",
      permissionBoundary: { accountId: account.id, userId: childUser.id, resourceVersion: childUser.resourceVersion, policy: null } });
    fixture.updatePolicy.mockRejectedValueOnce(new HttpProblem(403, "DENIED"));
    const { user } = await openAccess(fixture.repository, iam({}, childUser.id), "policies");
    await user.click(await screen.findByRole("button", { name: "LogBoundary" })); await invokeMoreAction(user, "修改显示名");
    fireEvent.change(screen.getByRole("textbox", { name: "新显示名" }), { target: { value: "Proposed name" } });
    await user.click(screen.getByRole("button", { name: "审阅修改" })); await user.click(screen.getByRole("button", { name: "确认修改显示名" }));
    expect(await screen.findByText(/IAM 拒绝了本次尝试的权限/)).toBeTruthy();
    expect(screen.getByRole("group", { name: "审阅显示名修改 · LogBoundary" })).toBeTruthy();
    expect(screen.queryByRole("heading", { name: "策略操作结果未确认" })).toBeNull();
    expect(fixture.updatePolicy).toHaveBeenCalledTimes(1);
  });

  it("keeps a whole-Policy UNKNOWN after a later conflict and requires an explicit acknowledgement to abandon only local recovery", async () => {
    enablePolicyLocks(); const fixture = livePolicyMetadata();
    fixture.deletePolicy.mockRejectedValueOnce(new HttpProblem(503, "LOST")).mockRejectedValueOnce(new HttpProblem(409, "REFERENCED"));
    const { user } = await openAccess(fixture.repository, iam(), "policies");
    await user.click(await screen.findByRole("button", { name: "LogBoundary" })); await invokeMoreAction(user, "退役整条策略");
    fireEvent.change(screen.getByRole("textbox", { name: "输入策略显示名「LogBoundary」确认" }), { target: { value: "LogBoundary" } });
    await user.click(screen.getByRole("button", { name: "确认退役整条策略" }));
    const recovery = await screen.findByRole("region", { name: "策略操作结果未确认" });
    expect(within(recovery).getByRole("button", { name: "仅放弃本地恢复" }).hasAttribute("disabled")).toBe(true);
    await waitFor(() => expect(within(recovery).getByRole("button", { name: "重试完全相同的原命令" }).hasAttribute("disabled")).toBe(false));
    await user.click(within(recovery).getByRole("button", { name: "重试完全相同的原命令" }));
    await waitFor(() => expect(fixture.deletePolicy).toHaveBeenCalledTimes(2));
    await waitFor(() => expect(screen.getByRole("region", { name: "策略操作结果未确认" }).textContent).toContain("未知原请求仍然未知"));
    expect(fixture.deletePolicy.mock.calls[1]).toEqual(fixture.deletePolicy.mock.calls[0]);
    const currentRecovery = screen.getByRole("region", { name: "策略操作结果未确认" });
    await user.click(within(currentRecovery).getByRole("checkbox")); await user.click(within(currentRecovery).getByRole("button", { name: "仅放弃本地恢复" }));
    await waitFor(() => expect(screen.queryByRole("region", { name: "策略操作结果未确认" })).toBeNull());
    expect(fixture.deletePolicy).toHaveBeenCalledTimes(2); expect(fixture.updatePolicy).not.toHaveBeenCalled();
  });

  it("resolves a committed retirement with the original request after the retired Policy becomes unreadable", async () => {
    enablePolicyLocks();
    const fixture = livePolicyMetadata();
    const commit = fixture.deletePolicy.getMockImplementation()!;
    const read = fixture.readPolicy.getMockImplementation()!;
    let committed: AccountPolicy | null = null;
    fixture.deletePolicy.mockReset();
    fixture.deletePolicy.mockImplementationOnce(async (...args) => {
      committed = await commit(...args);
      throw new HttpProblem(503, "RESPONSE_LOST_AFTER_COMMIT");
    }).mockImplementationOnce(async () => structuredClone(committed!));
    fixture.readPolicy.mockImplementation(async (...args) => {
      if (committed && args[2] === "customer.logs") throw new HttpProblem(403, "RETIRED_POLICY_NOT_READABLE");
      return read(...args);
    });
    const { user } = await openAccess(fixture.repository, iam(), "policies");
    await user.click(await screen.findByRole("button", { name: "LogBoundary" }));
    await invokeMoreAction(user, "退役整条策略");
    fireEvent.change(screen.getByRole("textbox", { name: "输入策略显示名「LogBoundary」确认" }), { target: { value: "LogBoundary" } });
    await user.click(screen.getByRole("button", { name: "确认退役整条策略" }));
    const recovery = await screen.findByRole("region", { name: "策略操作结果未确认" });
    const readsBeforeInspection = fixture.readPolicy.mock.calls.length;
    await user.click(within(recovery).getByRole("button", { name: "查看策略当前状态" }));
    await waitFor(() => expect(fixture.readPolicy.mock.calls.length).toBeGreaterThan(readsBeforeInspection));
    await waitFor(() => expect(within(recovery).getByRole("button", { name: "重试完全相同的原命令" })).toHaveProperty("disabled", false));
    await user.click(within(recovery).getByRole("button", { name: "重试完全相同的原命令" }));
    await waitFor(() => expect(fixture.deletePolicy).toHaveBeenCalledTimes(2));
    expect(fixture.deletePolicy.mock.calls[1]).toEqual(fixture.deletePolicy.mock.calls[0]);
    await screen.findByRole("table", { name: "策略元数据目录" });
    expect(screen.queryByRole("region", { name: "策略操作结果未确认" })).toBeNull();
  });

  it("does not borrow an old Policy detail to enable writes after the repository changes", async () => {
    enablePolicyLocks(); const fixture = livePolicyMetadata();
    const { user, replaceRepository } = await openAccess(fixture.repository, iam(), "policies");
    await user.click(await screen.findByRole("button", { name: "LogBoundary" })); await screen.findByRole("table", { name: "策略声明" });
    const next = livePolicyMetadata(); const fresh = await next.readPolicy(credential, account.id, "customer.logs"); let complete!: (value: AccountPolicyAccess) => void;
    const read = vi.fn(() => new Promise<AccountPolicyAccess>((resolve) => { complete = resolve; }));
    const repository = { ...next.repository, readPolicy: read };
    replaceRepository(repository); await waitFor(() => expect(read).toHaveBeenCalled());
    await user.click(await screen.findByRole("button", { name: "更多操作" }));
    let menu = await screen.findByRole("menu", { name: "更多操作" });
    expect(within(menu).getByRole("menuitem", { name: "修改显示名" }).getAttribute("aria-disabled")).toBe("true");
    expect(within(menu).getByText(/请先成功读取该策略的当前默认版本/)).toBeTruthy();
    expect(next.updatePolicy).not.toHaveBeenCalled(); expect(next.deletePolicy).not.toHaveBeenCalled();
    await user.keyboard("{Escape}"); await act(async () => { complete(fresh); });
    await screen.findByRole("table", { name: "策略声明" });
    await user.click(screen.getByRole("button", { name: "更多操作" })); menu = await screen.findByRole("menu", { name: "更多操作" });
    expect(within(menu).getByRole("menuitem", { name: "修改显示名" }).getAttribute("aria-disabled")).not.toBe("true");
  });

  it("keeps the same Policy recovery region visible while an exact retry is in flight", async () => {
    enablePolicyLocks(); const fixture = livePolicyMetadata(); let failRetry!: (reason: unknown) => void;
    fixture.deletePolicy.mockRejectedValueOnce(new HttpProblem(503, "LOST"))
      .mockImplementationOnce(() => new Promise((_resolve, reject) => { failRetry = reject; }));
    const { user } = await openAccess(fixture.repository, iam(), "policies");
    await user.click(await screen.findByRole("button", { name: "LogBoundary" })); await invokeMoreAction(user, "退役整条策略");
    fireEvent.change(screen.getByRole("textbox", { name: "输入策略显示名「LogBoundary」确认" }), { target: { value: "LogBoundary" } });
    await user.click(screen.getByRole("button", { name: "确认退役整条策略" }));
    const region = await screen.findByRole("region", { name: "策略操作结果未确认" });
    await waitFor(() => expect(within(region).getByRole("button", { name: "重试完全相同的原命令" }).hasAttribute("disabled")).toBe(false));
    await user.click(within(region).getByRole("button", { name: "重试完全相同的原命令" }));
    expect(screen.getByRole("region", { name: "策略操作结果未确认" })).toBe(region);
    expect(region.getAttribute("aria-busy")).toBe("true");
    expect(within(region).getByText("LogBoundary")).toBeTruthy();
    expect(within(region).getByRole("button", { name: "仅放弃本地恢复" }).hasAttribute("disabled")).toBe(true);
    await act(async () => { failRetry(new HttpProblem(503, "STILL_UNKNOWN")); });
    expect(screen.getByRole("region", { name: "策略操作结果未确认" })).toBe(region);
    expect(fixture.deletePolicy).toHaveBeenCalledTimes(2);
  });

  it("blocks live version writes while Policy metadata recovery remains unresolved", async () => {
    enablePolicyLocks(); const fixture = livePolicyVersions();
    fixture.repository.updatePolicy = vi.fn().mockRejectedValueOnce(new HttpProblem(503, "LOST"));
    fixture.repository.deletePolicy = vi.fn();
    const { user } = await openAccess(fixture.repository, iam(), "policies");
    await user.click(await screen.findByRole("button", { name: "LogBoundary" })); await invokeMoreAction(user, "修改显示名");
    fireEvent.change(screen.getByRole("textbox", { name: "新显示名" }), { target: { value: "Changed name" } });
    await user.click(screen.getByRole("button", { name: "审阅修改" })); await user.click(screen.getByRole("button", { name: "确认修改显示名" }));
    await screen.findByRole("heading", { name: "策略操作结果未确认" });
    await user.click(await screen.findByRole("tab", { name: "策略版本" }));
    await screen.findByRole("table", { name: "策略版本目录" });
    expect(screen.getByRole("button", { name: "发布新版本" }).hasAttribute("disabled")).toBe(true);
    await user.click(screen.getByRole("button", { name: "版本 version-a 的操作" }));
    const menu = await screen.findByRole("menu", { name: "版本 version-a 的操作" });
    expect(within(menu).getByRole("menuitem", { name: "切换默认版本" }).getAttribute("aria-disabled")).toBe("true");
    expect(fixture.createPolicyVersion).not.toHaveBeenCalled(); expect(fixture.setDefaultPolicyVersion).not.toHaveBeenCalled(); expect(fixture.retirePolicyVersion).not.toHaveBeenCalled();
  });

  it("restores a Policy UNKNOWN after reopening the authenticated UI and retries with the new verified bearer only", async () => {
    enablePolicyLocks(); const fixture = livePolicyMetadata(); fixture.updatePolicy.mockRejectedValueOnce(new Error("lost"));
    const first = await openAccess(fixture.repository, iam(), "policies");
    await first.user.click(await screen.findByRole("button", { name: "LogBoundary" })); await invokeMoreAction(first.user, "修改显示名");
    fireEvent.change(screen.getByRole("textbox", { name: "新显示名" }), { target: { value: "Recovered name" } });
    await first.user.click(screen.getByRole("button", { name: "审阅修改" })); await first.user.click(screen.getByRole("button", { name: "确认修改显示名" }));
    await screen.findByRole("heading", { name: "策略操作结果未确认" }); const original = fixture.updatePolicy.mock.calls[0]!; first.view.unmount();
    const authentication = iam({ login: vi.fn().mockResolvedValue({ credential: "new-verified-bearer", mustChangePassword: false,
      session: { id: "new-session", organizationId: account.id, principalId: rootUser.id, status: "ACTIVE", issuedAt: timestamp, expiresAt: "2099-08-27T00:00:00Z" } }) });
    const second = await openAccess(fixture.repository, authentication, "policies", "new-verified-bearer");
    const recovery = await screen.findByRole("region", { name: "策略操作结果未确认" });
    expect(fixture.updatePolicy).toHaveBeenCalledTimes(1);
    await waitFor(() => expect(within(recovery).getByRole("button", { name: "重试完全相同的原命令" })).toHaveProperty("disabled", false));
    await second.user.click(within(recovery).getByRole("button", { name: "重试完全相同的原命令" }));
    await waitFor(() => expect(fixture.updatePolicy).toHaveBeenCalledTimes(2));
    expect(fixture.updatePolicy.mock.calls[1]).toEqual(["new-verified-bearer", ...original.slice(1)]);
    expect(await screen.findByRole("button", { name: "Recovered name" })).toBeTruthy();
  });

  it("keeps a version review frozen until both the current exact Policy and version directory are reauthorized", async () => {
    const fixture = livePolicyVersions();
    const initialAccess = await fixture.readPolicy();
    const initialDirectory = await fixture.listPolicyVersions();
    fixture.readPolicy.mockReset(); fixture.listPolicyVersions.mockReset();
    let finishIdentity!: (value: AccountIdentity) => void;
    const pendingIdentity = new Promise<AccountIdentity>((resolve) => { finishIdentity = resolve; });
    fixture.repository.currentIdentity = vi.fn().mockResolvedValueOnce(structuredClone(identity)).mockReturnValueOnce(pendingIdentity);
    let finishExact!: (value: AccountPolicyAccess) => void;
    const pendingExact = new Promise<AccountPolicyAccess>((resolve) => { finishExact = resolve; });
    let finishDirectory!: (value: typeof initialDirectory) => void;
    const pendingDirectory = new Promise<typeof initialDirectory>((resolve) => { finishDirectory = resolve; });
    fixture.readPolicy.mockResolvedValueOnce(initialAccess).mockReturnValueOnce(pendingExact);
    fixture.listPolicyVersions.mockResolvedValueOnce(initialDirectory).mockReturnValueOnce(pendingDirectory);
    const { user } = await openAccess(fixture.repository, iam(), "policies");
    await user.click(await screen.findByRole("button", { name: "LogBoundary" }));
    await user.click(await screen.findByRole("tab", { name: "策略版本" }));
    await screen.findByRole("table", { name: "策略版本目录" });
    await user.click(screen.getByRole("button", { name: "版本 version-a 的操作" }));
    await user.click(await screen.findByRole("menuitem", { name: "切换默认版本" }));
    const confirm = screen.getByRole("button", { name: "确认切换" });
    expect(confirm).toHaveProperty("disabled", false);

    await user.click(screen.getByRole("button", { name: "recheck-test-authority" }));
    await waitFor(() => expect(fixture.repository.currentIdentity).toHaveBeenCalledTimes(2));
    expect(screen.getByRole("heading", { name: "将 version-a 设为默认版本" })).toBeTruthy();
    expect(confirm).toHaveProperty("disabled", true);
    await act(async () => { finishIdentity(structuredClone(identity)); await pendingIdentity; });
    await waitFor(() => expect(fixture.readPolicy).toHaveBeenCalledTimes(2));
    await waitFor(() => expect(fixture.listPolicyVersions).toHaveBeenCalledTimes(2));
    expect(confirm).toHaveProperty("disabled", true);
    await act(async () => { finishExact(initialAccess); await pendingExact; });
    expect(confirm).toHaveProperty("disabled", true);
    await act(async () => { finishDirectory(initialDirectory); await pendingDirectory; });
    await waitFor(() => expect(confirm).toHaveProperty("disabled", false));
    await user.click(confirm);
    await waitFor(() => expect(fixture.setDefaultPolicyVersion).toHaveBeenCalledTimes(1));
  });

  it("reviews a live default switch and retirement inline against the exact resource revision", async () => {
    const fixture = livePolicyVersions();
    const { user } = await openAccess(fixture.repository, iam(), "policies");
    await user.click(await screen.findByRole("button", { name: "LogBoundary" }));
    await user.click(await screen.findByRole("tab", { name: "策略版本" }));
    await screen.findByRole("table", { name: "策略版本目录" });
    await user.click(screen.getByRole("button", { name: "版本 version-a 的操作" }));
    await user.click(await screen.findByRole("menuitem", { name: "切换默认版本" }));
    expect(screen.getByRole("heading", { name: "将 version-a 设为默认版本" })).toBe(document.activeElement);
    expect(screen.getByText(/包括用户、组及角色/)).toBeTruthy();
    expect(screen.queryByRole("dialog")).toBeNull();
    await user.click(screen.getByRole("button", { name: "确认切换" }));
    await waitFor(() => expect(fixture.setDefaultPolicyVersion).toHaveBeenCalledTimes(1));
    expect(fixture.setDefaultPolicyVersion.mock.calls[0]).toEqual([credential, account.id, "customer.logs", {
      versionId: "version-a", resourceVersion: 4, requestId: expect.stringMatching(/^ui-policy-version-/)
    }]);
    await waitFor(() => expect(within(screen.getByRole("table", { name: "策略版本目录" })).getByText("当前默认")).toBeTruthy());
    await user.click(screen.getByRole("button", { name: "版本 version-logs 的操作" }));
    await user.click(await screen.findByRole("menuitem", { name: "退休版本" }));
    expect(screen.getByText(/历史记录仍保留/)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "确认退休" }));
    await waitFor(() => expect(fixture.retirePolicyVersion).toHaveBeenCalledTimes(1));
    expect(fixture.retirePolicyVersion.mock.calls[0]).toEqual([credential, account.id, "customer.logs", "version-logs", {
      resourceVersion: 5, expectedDefaultVersionId: "version-a", requestId: expect.stringMatching(/^ui-policy-version-/)
    }]);
    expect(await screen.findByText("当前可管理版本：1 / 5")).toBeTruthy();
  });

  it("reviews and publishes a live policy version without switching the default or leaving the content area", async () => {
    const fixture = livePolicyVersions();
    const { user } = await openAccess(fixture.repository, iam(), "policies");
    await user.click(await screen.findByRole("button", { name: "LogBoundary" }));
    await user.click(await screen.findByRole("tab", { name: "策略版本" }));
    await screen.findByRole("table", { name: "策略版本目录" });
    await user.click(screen.getByRole("button", { name: "发布新版本" }));
    expect(screen.getByRole("heading", { name: "编写新版本" })).toBe(document.activeElement);
    expect(screen.queryByRole("dialog")).toBeNull();
    const proposed = structuredClone(tenantPolicyDetail.version.document);
    proposed.statements[0]!.actions = ["paas.application.list"];
    fireEvent.change(screen.getByRole("textbox", { name: "待发布声明 JSON" }), { target: { value: JSON.stringify(proposed, null, 2) } });
    await user.click(screen.getByRole("button", { name: "审阅变更" }));
    expect(screen.getByRole("heading", { name: "审阅待发布版本" })).toBe(document.activeElement);
    expect(screen.queryByRole("region", { name: "声明摘要" })).toBeNull();
    expect(screen.getByText(/发布只创建不可变版本/)).toBeTruthy();
    expect(fixture.createPolicyVersion).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "确认发布新版本" }));
    await waitFor(() => expect(fixture.createPolicyVersion).toHaveBeenCalledTimes(1));
    expect(fixture.createPolicyVersion.mock.calls[0]).toEqual([credential, account.id, "customer.logs", {
      document: proposed, resourceVersion: 4, expectedDefaultVersionId: "version-logs", requestId: expect.stringMatching(/^ui-policy-version-/)
    }]);
    expect(await screen.findByRole("heading", { name: "版本 version-new 已发布" })).toBeTruthy();
    expect(screen.getByText(/当前默认版本仍是 version-logs/)).toBeTruthy();
    expect(fixture.setDefaultPolicyVersion).not.toHaveBeenCalled();
    expect(screen.queryByRole("dialog")).toBeNull();
    await user.click(screen.getByRole("button", { name: "版本 version-new 的操作" }));
    await user.click(screen.getByRole("menuitem", { name: "切换默认版本" }));
    await user.click(screen.getByRole("button", { name: "确认切换" }));
    await waitFor(() => expect(fixture.setDefaultPolicyVersion).toHaveBeenCalledTimes(1));
    await screen.findByRole("table", { name: "策略版本目录" });
    expect(screen.queryByRole("heading", { name: "版本 version-new 已发布" })).toBeNull();
    expect(screen.queryByText(/当前默认版本仍是 version-logs/)).toBeNull();
  });

  async function openVisualVersionDraft() {
    const fixture = livePolicyVersions();
    const catalog = profileDirectory();
    catalog.items[0]!.profile.actions.push({ action: "paas.application.list", resourceKind: "APPLICATION", scope: "TENANT",
      resourceShapes: [{ mode: "COLLECTION", prefixAllowed: false, collectionUsage: "COLLECTION_LIST" }] });
    const listAuthorizationProfiles = vi.fn().mockResolvedValue(catalog);
    const { user } = await openAccess(accounts({ ...fixture.repository, listAuthorizationProfiles }), iam(), "policies");
    await user.click(await screen.findByRole("button", { name: "LogBoundary" }));
    await user.click(await screen.findByRole("tab", { name: "策略版本" }));
    await screen.findByRole("table", { name: "策略版本目录" });
    await user.click(screen.getByRole("button", { name: "发布新版本" }));
    expect(listAuthorizationProfiles).not.toHaveBeenCalled();
    const publisher = within(screen.getByRole("region", { name: "编写新版本" }));
    await user.click(publisher.getByRole("tab", { name: "可视化编辑" }));
    expect(await screen.findByRole("checkbox", { name: /paas.application.read/ })).toBeTruthy();
    const authoringSnapshot = screen.getByRole("region", { name: "当前声明依赖的产品目录" });
    expect(within(authoringSnapshot).getByText("paas @ r1", { selector: "code" })).toBeTruthy();
    expect(within(authoringSnapshot).getByText(/提交时 IAM 会重新校验目录并冻结精确 Action 集/)).toBeTruthy();
    expect(listAuthorizationProfiles).toHaveBeenCalledTimes(1);
    await user.click(publisher.getByLabelText("授权效果", { selector: "button" }));
    await user.click(within(screen.getByRole("listbox")).getByRole("option", { name: "拒绝" }));
    await user.click(publisher.getByLabelText("资源选择器 1", { selector: "button" }));
    await user.click(within(screen.getByRole("listbox")).getByRole("option", { name: "精确 ID" }));
    return { user, fixture, listAuthorizationProfiles, publisher };
  }
  it("loads the catalog only for visual version authoring and rejects incomplete or incompatible resource choices", async () => {
    const { user, fixture, publisher } = await openVisualVersionDraft();
    await user.click(publisher.getByRole("button", { name: "审阅变更" }));
    expect(screen.getByText(/可视化草稿还有未完成/)).toBeTruthy();
    expect(fixture.createPolicyVersion).not.toHaveBeenCalled();
    await user.click(publisher.getByLabelText("资源 ID 或前缀", { selector: "input" }));
    await user.paste("app-prod");
    expect(screen.getByRole("checkbox", { name: /paas.application.list/ })).toHaveProperty("disabled", true);
    expect(screen.getByText("当前 1 个操作可共享本声明的资源与条件；1 个需调整当前声明或另建声明。")).toBeTruthy();
    expect(screen.getByText("资源形状与当前所选操作不同；请另建声明。")).toBeTruthy();
    await user.click(publisher.getByRole("button", { name: "仅看已选" }));
    expect(screen.queryByRole("checkbox", { name: /paas.application.list/ })).toBeNull();
    await user.click(publisher.getByRole("button", { name: "显示全部操作" }));
    expect(fixture.createPolicyVersion).not.toHaveBeenCalled();
  });
  it("reviews visual version semantics and the exact comparison while retaining the draft on back", async () => {
    const { user, fixture, listAuthorizationProfiles, publisher } = await openVisualVersionDraft();
    await user.click(publisher.getByLabelText("资源 ID 或前缀", { selector: "input" }));
    await user.paste("app-prod");
    await user.click(publisher.getByRole("button", { name: "审阅变更" }));
    expect(screen.getByRole("heading", { name: "审阅待发布版本" })).toBeTruthy();
    const summary = screen.getByRole("region", { name: "声明摘要" });
    const reviewSnapshot = within(summary).getByRole("region", { name: "待 IAM 校验的产品声明" });
    expect(within(reviewSnapshot).getByText("paas @ r1", { selector: "code" })).toBeTruthy();
    expect(within(reviewSnapshot).getByText(/后续 Profile 新增 Action 不会自动扩大已发布版本/)).toBeTruthy();
    const semantics = within(summary).getByRole("region", { name: "授权语义" });
    expect(within(semantics).getByText("ALLOW 0 条 · DENY 1 条")).toBeTruthy();
    expect(within(semantics).getByText(/发布版本本身不授权/)).toBeTruthy();
    expect(within(semantics).getByText(/匹配的 Deny 会覆盖匹配的 Allow/)).toBeTruthy();
    expect(within(summary).getByText("拒绝")).toBeTruthy();
    expect(within(summary).getByText("paas.application.read", { selector: "code" })).toBeTruthy();
    expect(within(summary).getByText("app-prod", { selector: "code" })).toBeTruthy();
    const comparison = screen.getByText("对比当前与目标声明 JSON").closest("details");
    expect(comparison?.open).toBe(false);
    await user.click(screen.getByText("对比当前与目标声明 JSON"));
    expect(comparison?.open).toBe(true);
    expect(within(comparison!).getByRole("heading", { name: /当前默认版本/ })).toBeTruthy();
    expect(within(comparison!).getByRole("heading", { name: "待发布声明 JSON" })).toBeTruthy();
    expect(screen.queryByRole("dialog")).toBeNull();
    await user.click(publisher.getByRole("button", { name: "返回编辑" }));
    expect(screen.getByRole("checkbox", { name: /paas.application.read/ })).toHaveProperty("checked", true);
    expect((screen.getByRole("textbox", { name: "资源 ID 或前缀" }) as HTMLInputElement).value).toBe("app-prod");
    expect(listAuthorizationProfiles).toHaveBeenCalledTimes(1);
    expect(fixture.createPolicyVersion).not.toHaveBeenCalled();
  });
  it("publishes the reviewed exact visual declaration without switching the default", async () => {
    const { user, fixture, publisher } = await openVisualVersionDraft();
    await user.click(publisher.getByLabelText("资源 ID 或前缀", { selector: "input" }));
    await user.paste("app-prod");
    await user.click(publisher.getByRole("button", { name: "审阅变更" }));
    await user.click(publisher.getByRole("button", { name: "返回编辑" }));
    await user.click(publisher.getByRole("button", { name: "审阅变更" }));
    await user.click(publisher.getByRole("button", { name: "确认发布新版本" }));
    await waitFor(() => expect(fixture.createPolicyVersion).toHaveBeenCalledTimes(1));
    const submitted = fixture.createPolicyVersion.mock.calls[0]![3].document;
    expect(submitted).toEqual({ languageVersion: "1", scope: "TENANT", statements: [{ sid: "read-applications", effect: "DENY",
      actions: ["paas.application.read"], resources: [{ kind: "APPLICATION", match: "EXACT", id: "app-prod" }] }] });
    expect(fixture.setDefaultPolicyVersion).not.toHaveBeenCalled();
  });

  it("selects compatible Actions together while keeping resource and condition limits shared", async () => {
    const fixture = livePolicyVersions();
    const catalog = profileDirectory();
    catalog.items[0]!.profile.actions.push({ action: "paas.application.inspect", resourceKind: "APPLICATION", scope: "TENANT",
      resourceShapes: [{ mode: "INSTANCE", prefixAllowed: true }] });
    catalog.items[0]!.profile.actions.push({ action: "paas.application.upsert", resourceKind: "APPLICATION", scope: "TENANT",
      resourceShapes: [{ mode: "INSTANCE", prefixAllowed: true }, { mode: "COLLECTION", prefixAllowed: false, collectionUsage: "COLLECTION_CREATE" }] });
    const { user } = await openAccess(accounts({ ...fixture.repository, listAuthorizationProfiles: vi.fn().mockResolvedValue(catalog) }), iam(), "policies");
    await user.click(await screen.findByRole("button", { name: "LogBoundary" }));
    await user.click(await screen.findByRole("tab", { name: "策略版本" }));
    await screen.findByRole("table", { name: "策略版本目录" });
    await user.click(screen.getByRole("button", { name: "发布新版本" }));
    await user.click(screen.getByRole("tab", { name: "可视化编辑" }));
    const read = await screen.findByRole("checkbox", { name: /paas.application.read/ });
    expect(read).toHaveProperty("disabled", true);
    expect(screen.getByRole("checkbox", { name: /paas.application.upsert/ })).toHaveProperty("disabled", true);
    expect(screen.getByText("当前 2 个操作可共享本声明的资源与条件；1 个需调整当前声明或另建声明。")).toBeTruthy();
    expect(screen.getByText("资源形状与当前所选操作不同；请另建声明。")).toBeTruthy();
    await user.click(screen.getByRole("checkbox", { name: /paas.application.inspect/ }));
    expect(read).toHaveProperty("disabled", false);
    expect(screen.getByText(/已选 2 \/ 128 个操作/)).toBeTruthy();
    expect(screen.getByText("所选操作没有共同支持的策略条件。")).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "审阅变更" }));
    expect(screen.getByRole("heading", { name: "审阅待发布版本" })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "确认发布新版本" }));
    await waitFor(() => expect(fixture.createPolicyVersion).toHaveBeenCalledTimes(1));
    expect(fixture.createPolicyVersion.mock.calls[0]![3].document.statements[0]!.actions)
      .toEqual(["paas.application.inspect", "paas.application.read"]);
  });

  async function openVisualPolicyDraft() {
    const createPolicy = vi.fn(async (_credential: string, _accountId: string,
      command: { displayName: string; document: AccountPolicyDocument; requestId: string }): Promise<AccountPolicyDetail> => {
      const policy: AccountPolicy = { ...tenantPolicy, id: "customer.new", management: "CUSTOMER", accountId: account.id,
        displayName: command.displayName, defaultVersionId: "version-new", resourceVersion: 1 };
      return { policy, version: { ...tenantPolicyDetail.version, policyId: policy.id, versionId: policy.defaultVersionId,
        document: structuredClone(command.document) } };
    });
    const listAuthorizationProfiles = vi.fn().mockResolvedValue(profileDirectory());
    const readPolicy = vi.fn(async (_credential: string, _accountId: string, policyId: string) => {
      const call = createPolicy.mock.calls[0];
      if (policyId !== "customer.new" || !call) throw new Error("INVALID_TEST_TARGET");
      return policyAccess(await createPolicy.mock.results[0]!.value);
    });
    const { user } = await openAccess(accounts({ createPolicy, readPolicy, listAuthorizationProfiles }), iam(), "policies");
    await user.click(screen.getByRole("button", { name: "新建自定义策略" }));
    expect(listAuthorizationProfiles).not.toHaveBeenCalled();
    fireEvent.change(screen.getByRole("textbox", { name: "策略名称" }), { target: { value: "Application reader" } });
    await user.click(screen.getByRole("tab", { name: "可视化编辑" }));
    const action = await screen.findByRole("radio", { name: /paas.application.read/ });
    await user.click(action);
    return { user, createPolicy, listAuthorizationProfiles };
  }
  async function enterVisualPolicyConstraints(user: ReturnType<typeof userEvent.setup>) {
    await user.click(screen.getByRole("textbox", { name: "资源 ID 或前缀" }));
    await user.paste("app-prod");
    await user.click(screen.getByRole("button", { name: "添加条件" }));
    await user.click(screen.getByRole("textbox", { name: "条件值" }));
    await user.paste("tenant-a");
  }
  it("inspects a selected catalog Action's declaration without treating it as authorization", async () => {
    const { user, createPolicy } = await openVisualPolicyDraft();
    expect(within(screen.getByRole("region", { name: "当前声明依赖的产品目录" }))
      .getByText("paas @ r1", { selector: "code" })).toBeTruthy();
    expect(screen.queryByRole("region", { name: "已选 Action 的产品声明" })).toBeNull();
    await user.click(screen.getByRole("button", { name: "查看声明详情" }));
    const declaration = screen.getByRole("region", { name: "已选 Action 的产品声明" });
    expect(within(declaration).getByText("paas.application.read", { selector: "code" })).toBeTruthy();
    expect(within(declaration).getByText("租户")).toBeTruthy();
    expect(within(declaration).getByText("实例（支持已声明前缀）")).toBeTruthy();
    expect(within(declaration).getByText("用户")).toBeTruthy();
    expect(within(declaration).getByText("iam.account-id", { selector: "code" })).toBeTruthy();
    expect(screen.getByText(/不是当前用户的授权结果，也不是策略编译结果/)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "收起声明详情" }));
    expect(screen.queryByRole("region", { name: "已选 Action 的产品声明" })).toBeNull();
    expect(screen.getAllByText("paas.application.read", { selector: "code" }).length).toBeGreaterThan(0);
    expect(createPolicy).not.toHaveBeenCalled();
  });
  it("retains a complete visual policy draft across review and back without creating or attaching it", async () => {
    const { user, createPolicy, listAuthorizationProfiles } = await openVisualPolicyDraft();
    await user.click(screen.getByRole("button", { name: "审阅策略" }));
    expect(screen.getByText(/可视化声明还有未完成/)).toBeTruthy();
    await enterVisualPolicyConstraints(user);
    await user.click(screen.getByRole("button", { name: "审阅策略" }));
    expect(screen.getByRole("heading", { name: "审阅新策略" })).toBeTruthy();
    const summary = screen.getByRole("region", { name: "声明摘要" });
    expect(within(summary).getByRole("region", { name: "待 IAM 校验的产品声明" })).toBeTruthy();
    const semantics = within(summary).getByRole("region", { name: "授权语义" });
    expect(within(semantics).getByText("ALLOW 1 条 · DENY 0 条")).toBeTruthy();
    expect(within(semantics).queryByText(/显式 Deny/)).toBeNull();
    expect(within(summary).getByText("paas.application.read", { selector: "code" })).toBeTruthy();
    expect(within(summary).queryByRole("region", { name: "已选 Action 的产品声明" })).toBeNull();
    await user.click(within(summary).getByRole("button", { name: "查看声明详情" }));
    expect(within(summary).getByRole("region", { name: "已选 Action 的产品声明" })).toBeTruthy();
    expect(within(summary).getByText("app-prod", { selector: "code" })).toBeTruthy();
    expect(within(summary).getByText("当前账号 ID", { exact: false })).toBeTruthy();
    expect(within(summary).getByText("tenant-a", { selector: "code" })).toBeTruthy();
    expect(screen.getByText("查看完整 JSON").closest("details")?.open).toBe(false);
    await user.click(screen.getByRole("button", { name: "返回编辑" }));
    expect((screen.getByRole("textbox", { name: "策略名称" }) as HTMLInputElement).value).toBe("Application reader");
    expect(document.activeElement).toBe(screen.getByRole("textbox", { name: "策略名称" }));
    expect(screen.getByRole("checkbox", { name: /paas.application.read/ })).toHaveProperty("checked", true);
    expect((screen.getByRole("textbox", { name: "资源 ID 或前缀" }) as HTMLInputElement).value).toBe("app-prod");
    expect(listAuthorizationProfiles).toHaveBeenCalledTimes(1);
    expect(createPolicy).not.toHaveBeenCalled();
  });
  it("creates a live custom policy from the reviewed catalog declaration without attaching it", async () => {
    const { user, createPolicy } = await openVisualPolicyDraft();
    await enterVisualPolicyConstraints(user);
    await user.click(screen.getByRole("button", { name: "审阅策略" }));
    await user.click(screen.getByRole("button", { name: "返回编辑" }));
    await user.click(screen.getByRole("button", { name: "审阅策略" }));
    expect(createPolicy).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "确认创建" }));
    await waitFor(() => expect(createPolicy).toHaveBeenCalledTimes(1));
    const submitted = createPolicy.mock.calls[0]![2];
    expect(submitted.displayName).toBe("Application reader");
    expect(submitted.document).toEqual({ languageVersion: "1", scope: "TENANT", statements: [{ sid: "statement-1", effect: "ALLOW",
      actions: ["paas.application.read"], resources: [{ kind: "APPLICATION", match: "EXACT", id: "app-prod" }],
      conditions: [{ key: "iam.account-id", operator: "STRING_EQUALS", values: ["tenant-a"] }] }] });
    expect(submitted.requestId).toMatch(/^ui-policy-create-/);
    expect(await screen.findByText(/策略 customer.new 已创建/)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "查看策略" }));
    expect(await screen.findByText("customer.new")).toBeTruthy();
  });

  it("explains and reviews a Profile-declared trusted request-tag condition without exposing arbitrary keys", async () => {
    const catalog: AuthorizationProfileDirectory = { accountId: account.id, items: [{
      profile: { product: "paas", revision: 4, callingService: "PAAS", actions: [{
        action: "paas.application.create", resourceKind: "APPLICATION", scope: "TENANT",
        resourceShapes: [{ mode: "COLLECTION", prefixAllowed: false, collectionUsage: "COLLECTION_CREATE" }],
        conditions: [
          { key: "request.source-ip", valueType: "IP", source: "CALLING_SERVICE_NETWORK" },
          { key: "request.tag/environment", valueType: "STRING", source: "CALLING_SERVICE_REQUEST_TAG" }
        ],
        resultResourceKind: "APPLICATION"
      }] }, contentDigest: `sha256:${"a".repeat(64)}`
    }] };
    const createPolicy = vi.fn();
    const { user } = await openAccess(accounts({ createPolicy, listAuthorizationProfiles: vi.fn().mockResolvedValue(catalog) }), iam(), "policies");
    await user.click(screen.getByRole("button", { name: "新建自定义策略" }));
    fireEvent.change(screen.getByRole("textbox", { name: "策略名称" }), { target: { value: "Production application creator" } });
    await user.click(screen.getByRole("tab", { name: "可视化编辑" }));
    await user.click(await screen.findByRole("radio", { name: /paas.application.create/ }));
    expect(within(screen.getByRole("region", { name: "当前声明依赖的产品目录" }))
      .getByText("paas @ r4", { selector: "code" })).toBeTruthy();
    expect(screen.getByText("可信请求上下文")).toBeTruthy();
    expect(screen.getByText(/来源 IP 由调用服务的受信网络边界提供/)).toBeTruthy();
    expect(screen.getByText(/浏览器输入和转发请求头不能证明真实来源/)).toBeTruthy();
    expect(screen.getByText(/浏览器不会直接向 IAM 提交授权上下文/)).toBeTruthy();
    expect(screen.getByText(/请求缺少标签时/)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "添加条件" }));
    await user.click(screen.getByRole("combobox", { name: "条件 1" }));
    await user.click(screen.getByRole("option", { name: "可信请求标签 · environment" }));
    expect(screen.getByRole("combobox", { name: "条件 1" }).textContent).toContain("可信请求标签 · environment");
    await user.type(screen.getByRole("textbox", { name: "条件值" }), "production");
    await user.click(screen.getByRole("button", { name: "审阅策略" }));
    const summary = screen.getByRole("region", { name: "声明摘要" });
    expect(within(summary).getByText("可信请求标签 · environment", { exact: false })).toBeTruthy();
    expect(within(summary).getByText("production", { selector: "code" })).toBeTruthy();
    expect(createPolicy).not.toHaveBeenCalled();
  });

  it("explains and reviews a Profile-declared trusted resource-tag condition without accepting browser resource facts", async () => {
    const catalog: AuthorizationProfileDirectory = { accountId: account.id, items: [{
      profile: { product: "paas", revision: 5, callingService: "PAAS", actions: [{
        action: "paas.application.read", resourceKind: "APPLICATION", scope: "TENANT",
        resourceShapes: [{ mode: "INSTANCE", prefixAllowed: true }],
        conditions: [
          { key: "request.source-ip", valueType: "IP", source: "CALLING_SERVICE_NETWORK" },
          { key: "resource.tag/environment", valueType: "STRING", source: "CALLING_SERVICE_RESOURCE_TAG" }
        ]
      }] }, contentDigest: `sha256:${"b".repeat(64)}`
    }] };
    const createPolicy = vi.fn();
    const { user } = await openAccess(accounts({ createPolicy, listAuthorizationProfiles: vi.fn().mockResolvedValue(catalog) }), iam(), "policies");
    await user.click(screen.getByRole("button", { name: "新建自定义策略" }));
    fireEvent.change(screen.getByRole("textbox", { name: "策略名称" }), { target: { value: "Production application reader" } });
    await user.click(screen.getByRole("tab", { name: "可视化编辑" }));
    await user.click(await screen.findByRole("radio", { name: /paas.application.read/ }));
    expect(within(screen.getByRole("region", { name: "当前声明依赖的产品目录" }))
      .getByText("paas @ r5", { selector: "code" })).toBeTruthy();
    expect(screen.getByText(/产品服务读取目标资源的持久化标签/)).toBeTruthy();
    expect(screen.getByText(/浏览器不会提交或覆盖这些事实/)).toBeTruthy();
    expect(screen.getByText(/不能把列表权限推导成所有实例均可访问/)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "添加条件" }));
    await user.click(screen.getByRole("combobox", { name: "条件 1" }));
    await user.click(screen.getByRole("option", { name: "可信资源标签 · environment" }));
    expect(screen.getByRole("combobox", { name: "条件 1" }).textContent).toContain("可信资源标签 · environment");
    expect(screen.getByText(/这里定义匹配条件，不修改资源标签/)).toBeTruthy();
    await user.type(screen.getByRole("textbox", { name: "条件值" }), "production");
    await user.type(screen.getByRole("textbox", { name: "资源 ID 或前缀" }), "app-prod");
    await user.click(screen.getByRole("button", { name: "审阅策略" }));
    const summary = screen.getByRole("region", { name: "声明摘要" });
    expect(within(summary).getByText("可信资源标签 · environment", { exact: false })).toBeTruthy();
    expect(within(summary).getByText("production", { selector: "code" })).toBeTruthy();
    expect(createPolicy).not.toHaveBeenCalled();
  });

  it("keeps an unknown policy creation frozen across navigation and retries byte-equivalently", async () => {
    const createPolicy = vi.fn().mockRejectedValueOnce(new HttpProblem(503, "IAM_UNAVAILABLE"))
      .mockRejectedValueOnce(new HttpProblem(409, "IAM_CONFLICT"));
    const { user } = await openAccess(accounts({ createPolicy }), iam(), "policies");
    await user.click(screen.getByRole("button", { name: "新建自定义策略" }));
    fireEvent.change(screen.getByRole("textbox", { name: "策略名称" }), { target: { value: "Uncertain policy" } });
    fireEvent.change(screen.getByRole("textbox", { name: "策略声明 JSON" }), { target: { value: JSON.stringify(tenantPolicyDetail.version.document) } });
    await user.click(screen.getByRole("button", { name: "审阅策略" }));
    expect(screen.queryByRole("region", { name: "声明摘要" })).toBeNull();
    expect(screen.getByRole("heading", { name: "策略声明 JSON" })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "确认创建" }));
    expect(await screen.findByRole("heading", { name: "策略创建结果未确认" })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "查看策略目录" }));
    expect(screen.getByRole("button", { name: "新建自定义策略" })).toHaveProperty("disabled", true);
    await user.click(screen.getByRole("button", { name: "按原请求重试" }));
    await waitFor(() => expect(createPolicy).toHaveBeenCalledTimes(2));
    expect(createPolicy.mock.calls[1]).toEqual(createPolicy.mock.calls[0]);
    expect(screen.getByRole("heading", { name: "策略创建结果未确认" })).toBeTruthy();
    await user.click(screen.getByRole("checkbox", { name: /我理解结果仍未知/ }));
    await user.click(screen.getByRole("button", { name: "结束旧意图" }));
    expect(screen.getByRole("button", { name: "新建自定义策略" })).toHaveProperty("disabled", false);
  });

  it("keeps an unknown policy creation recoverable after create authority is revoked", async () => {
    const revokedIdentity = structuredClone(identity);
    revokedIdentity.capabilities = revokedIdentity.capabilities.map((item) => item.action === "iam.policy.create"
      ? { ...item, available: false, restrictionReason: "AUTHORITY_REQUIRED" as const }
      : item);
    const createPolicy = vi.fn()
      .mockRejectedValueOnce(new HttpProblem(503, "IAM_UNAVAILABLE"))
      .mockRejectedValueOnce(new HttpProblem(409, "IAM_CONFLICT"));
    const initial = accounts({ createPolicy });
    const replacement = accounts({ createPolicy, currentIdentity: vi.fn().mockResolvedValue(revokedIdentity) });
    const { user, replaceRepository } = await openAccess(initial, iam(), "policies");
    await user.click(screen.getByRole("button", { name: "新建自定义策略" }));
    fireEvent.change(screen.getByRole("textbox", { name: "策略名称" }), { target: { value: "Recovery survives revoke" } });
    fireEvent.change(screen.getByRole("textbox", { name: "策略声明 JSON" }), { target: { value: JSON.stringify(tenantPolicyDetail.version.document) } });
    await user.click(screen.getByRole("button", { name: "审阅策略" }));
    await user.click(screen.getByRole("button", { name: "确认创建" }));
    expect(await screen.findByRole("heading", { name: "策略创建结果未确认" })).toBeTruthy();
    const original = createPolicy.mock.calls[0];

    replaceRepository(replacement);
    await waitFor(() => expect(replacement.currentIdentity).toHaveBeenCalledWith(credential));
    expect(screen.getByRole("heading", { name: "策略创建结果未确认" })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "按原请求重试" }));
    await waitFor(() => expect(createPolicy).toHaveBeenCalledTimes(2));
    expect(createPolicy.mock.calls[1]).toEqual(original);
    expect(screen.getByRole("heading", { name: "策略创建结果未确认" })).toBeTruthy();

    await user.click(screen.getByRole("checkbox", { name: /我理解结果仍未知/ }));
    await user.click(screen.getByRole("button", { name: "结束旧意图" }));
    expect(screen.queryByRole("button", { name: "新建自定义策略" })).toBeNull();
  });

  it("keeps JSON available when the live catalog is forbidden", async () => {
    const fixture = livePolicyVersions();
    const listAuthorizationProfiles = vi.fn().mockRejectedValue(new HttpProblem(403, "IAM_FORBIDDEN"));
    const { user } = await openAccess(accounts({ ...fixture.repository, listAuthorizationProfiles }), iam(), "policies");
    await user.click(await screen.findByRole("button", { name: "LogBoundary" }));
    await user.click(await screen.findByRole("tab", { name: "策略版本" }));
    await screen.findByRole("table", { name: "策略版本目录" });
    await user.click(screen.getByRole("button", { name: "发布新版本" }));
    await user.click(screen.getByRole("tab", { name: "可视化编辑" }));
    expect(await screen.findByText(/无权读取权限能力目录/)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "审阅变更" }));
    expect(screen.getByText(/可视化草稿还有未完成/)).toBeTruthy();
    expect(fixture.createPolicyVersion).not.toHaveBeenCalled();
    await user.click(screen.getByRole("tab", { name: "JSON 编辑" }));
    expect((screen.getByRole("textbox", { name: "待发布声明 JSON" }) as HTMLTextAreaElement).value).toContain("read-applications");
    expect(fixture.createPolicyVersion).not.toHaveBeenCalled();
  });

  it("renders only the current action page when the product catalog grows past a thousand actions", async () => {
    const fixture = livePolicyVersions();
    const catalog = profileDirectory();
    const base = catalog.items[0]!.profile.actions[0]!;
    catalog.items[0]!.profile.actions.push(...Array.from({ length: 1200 }, (_, index) => ({ ...base, action: `paas.application.read-${String(index).padStart(4, "0")}` })));
    const { user } = await openAccess(accounts({ ...fixture.repository, listAuthorizationProfiles: vi.fn().mockResolvedValue(catalog) }), iam(), "policies");
    await user.click(await screen.findByRole("button", { name: "LogBoundary" }));
    await user.click(await screen.findByRole("tab", { name: "策略版本" }));
    await screen.findByRole("table", { name: "策略版本目录" });
    await user.click(screen.getByRole("button", { name: "发布新版本" }));
    await user.click(screen.getByRole("tab", { name: "可视化编辑" }));
    const actionRegion = await screen.findByRole("region", { name: "产品操作" });
    expect(within(actionRegion).getAllByRole("checkbox")).toHaveLength(10);
    await user.type(within(actionRegion).getByRole("searchbox", { name: "搜索当前产品操作" }), "read-1199");
    expect(within(actionRegion).getAllByRole("checkbox")).toHaveLength(1);
    expect(within(actionRegion).getByRole("checkbox", { name: /paas.application.read-1199/ })).toBeTruthy();
  });

  it("never drops unknown JSON fields while attempting to switch to the visual editor", async () => {
    const fixture = livePolicyVersions();
    const { user } = await openAccess(fixture.repository, iam(), "policies");
    await user.click(await screen.findByRole("button", { name: "LogBoundary" }));
    await user.click(await screen.findByRole("tab", { name: "策略版本" }));
    await screen.findByRole("table", { name: "策略版本目录" });
    await user.click(screen.getByRole("button", { name: "发布新版本" }));
    const original = JSON.stringify({ ...tenantPolicyDetail.version.document, futureField: "keep-me" }, null, 2);
    fireEvent.change(screen.getByRole("textbox", { name: "待发布声明 JSON" }), { target: { value: original } });
    await user.click(screen.getByRole("tab", { name: "可视化编辑" }));
    expect(await screen.findByText(/无法无损呈现的字段或结构/)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "返回 JSON 编辑" }));
    expect((screen.getByRole("textbox", { name: "待发布声明 JSON" }) as HTMLTextAreaElement).value).toBe(original);
    expect(fixture.createPolicyVersion).not.toHaveBeenCalled();
  });

  it("replays the exact unpublished document after an unknown publish response", async () => {
    const fixture = livePolicyVersions();
    fixture.createPolicyVersion.mockRejectedValueOnce(new HttpProblem(503, "IAM_UNAVAILABLE"));
    const { user } = await openAccess(fixture.repository, iam(), "policies");
    await user.click(await screen.findByRole("button", { name: "LogBoundary" }));
    await user.click(await screen.findByRole("tab", { name: "策略版本" }));
    await screen.findByRole("table", { name: "策略版本目录" });
    await user.click(screen.getByRole("button", { name: "发布新版本" }));
    const proposed = structuredClone(tenantPolicyDetail.version.document);
    proposed.statements[0]!.actions = ["paas.application.list"];
    fireEvent.change(screen.getByRole("textbox", { name: "待发布声明 JSON" }), { target: { value: JSON.stringify(proposed) } });
    await user.click(screen.getByRole("button", { name: "审阅变更" }));
    await user.click(screen.getByRole("button", { name: "确认发布新版本" }));
    expect(await screen.findByRole("heading", { name: "版本变更结果未确认" })).toBeTruthy();
    expect(screen.getByText(/原请求：发布新版本/)).toBeTruthy();
    expect(screen.getByRole("button", { name: "发布新版本" }).hasAttribute("disabled")).toBe(true);
    await user.click(screen.getByRole("button", { name: "按原请求重试" }));
    await waitFor(() => expect(fixture.createPolicyVersion).toHaveBeenCalledTimes(2));
    expect(fixture.createPolicyVersion.mock.calls[1]).toEqual(fixture.createPolicyVersion.mock.calls[0]);
    expect(fixture.setDefaultPolicyVersion).not.toHaveBeenCalled();
  });

  it("keeps invalid publish input local and a definite IAM validation rejection in review", async () => {
    const fixture = livePolicyVersions();
    fixture.createPolicyVersion.mockRejectedValueOnce(new HttpProblem(422, "iam.argument.invalid"));
    const { user } = await openAccess(fixture.repository, iam(), "policies");
    await user.click(await screen.findByRole("button", { name: "LogBoundary" }));
    await user.click(await screen.findByRole("tab", { name: "策略版本" }));
    await screen.findByRole("table", { name: "策略版本目录" });
    await user.click(screen.getByRole("button", { name: "发布新版本" }));
    const editor = screen.getByRole("textbox", { name: "待发布声明 JSON" });
    fireEvent.change(editor, { target: { value: "{" } });
    await user.click(screen.getByRole("button", { name: "审阅变更" }));
    expect(screen.getByText("JSON 语法无效，请修正后再审阅。")).toBeTruthy();
    expect(fixture.createPolicyVersion).not.toHaveBeenCalled();
    fireEvent.change(editor, { target: { value: JSON.stringify(tenantPolicyDetail.version.document) } });
    await user.click(screen.getByRole("button", { name: "审阅变更" }));
    await user.click(screen.getByRole("button", { name: "确认发布新版本" }));
    expect(await screen.findByText("提交未通过校验；请核对当前版本与声明。")).toBeTruthy();
    expect(screen.getByRole("heading", { name: "审阅待发布版本" })).toBeTruthy();
    expect(screen.queryByRole("heading", { name: "版本变更结果未确认" })).toBeNull();
  });

  it("keeps an edited live version draft until the operator explicitly discards it", async () => {
    const fixture = livePolicyVersions();
    const { user } = await openAccess(fixture.repository, iam(), "policies");
    await user.click(await screen.findByRole("button", { name: "LogBoundary" }));
    await user.click(await screen.findByRole("tab", { name: "策略版本" }));
    await screen.findByRole("table", { name: "策略版本目录" });
    await user.click(screen.getByRole("button", { name: "发布新版本" }));
    const editor = screen.getByRole("textbox", { name: "待发布声明 JSON" });
    fireEvent.change(editor, { target: { value: "{\n  \"languageVersion\": \"1\"\n}" } });
    await user.click(screen.getByTestId("nav-users"));
    expect(await screen.findByRole("dialog", { name: "离开未发布的策略草稿？" })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "继续编辑" }));
    expect((screen.getByRole("textbox", { name: "待发布声明 JSON" }) as HTMLTextAreaElement).value).toContain("languageVersion");
    expect(fixture.createPolicyVersion).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "取消" }));
    await user.click(await screen.findByRole("button", { name: "放弃并离开" }));
    expect(await screen.findByRole("table", { name: "策略版本目录" })).toBeTruthy();
  });

  it("keeps an uncertain live version intent across IAM navigation and retries with identical input", async () => {
    const fixture = livePolicyVersions();
    fixture.setDefaultPolicyVersion.mockRejectedValueOnce(new HttpProblem(503, "IAM_UNAVAILABLE"));
    const { user } = await openAccess(fixture.repository, iam(), "policies");
    await user.click(await screen.findByRole("button", { name: "LogBoundary" }));
    await user.click(await screen.findByRole("tab", { name: "策略版本" }));
    await screen.findByRole("table", { name: "策略版本目录" });
    await user.click(screen.getByRole("button", { name: "版本 version-a 的操作" }));
    await user.click(await screen.findByRole("menuitem", { name: "切换默认版本" }));
    await user.click(screen.getByRole("button", { name: "确认切换" }));
    const recoveryHeading = await screen.findByRole("heading", { name: "版本变更结果未确认" });
    await waitFor(() => expect(recoveryHeading).toBe(document.activeElement));
    await user.click(screen.getByTestId("nav-users"));
    await user.click(screen.getByTestId("nav-policies"));
    expect(await screen.findByRole("heading", { name: "版本变更结果未确认" })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "按原请求重试" }));
    await waitFor(() => expect(fixture.setDefaultPolicyVersion).toHaveBeenCalledTimes(2));
    expect(fixture.setDefaultPolicyVersion.mock.calls[1]).toEqual(fixture.setDefaultPolicyVersion.mock.calls[0]);
    await waitFor(() => expect(screen.queryByRole("heading", { name: "版本变更结果未确认" })).toBeNull());
  });

  it("does not treat a retry conflict or current-state read as proof of the original version mutation", async () => {
    const fixture = livePolicyVersions();
    const read = fixture.readPolicy.getMockImplementation()!;
    let writeAuthorityRevoked = false;
    fixture.readPolicy.mockImplementation(async (...args) => {
      const access = await read(...args);
      return writeAuthorityRevoked ? { ...access,
        capabilities: access.capabilities.filter((item) => item.action !== "iam.policy.set-default-version") } : access;
    });
    fixture.setDefaultPolicyVersion.mockRejectedValueOnce(new HttpProblem(503, "IAM_UNAVAILABLE"))
      .mockRejectedValueOnce(new HttpProblem(409, "IAM_CONFLICT"));
    const { user } = await openAccess(fixture.repository, iam(), "policies");
    await user.click(await screen.findByRole("button", { name: "LogBoundary" }));
    await user.click(await screen.findByRole("tab", { name: "策略版本" }));
    await screen.findByRole("table", { name: "策略版本目录" });
    await user.click(screen.getByRole("button", { name: "版本 version-a 的操作" }));
    await user.click(await screen.findByRole("menuitem", { name: "切换默认版本" }));
    await user.click(screen.getByRole("button", { name: "确认切换" }));
    const recovery = (await screen.findByRole("heading", { name: "版本变更结果未确认" })).closest("section") as HTMLElement;
    const readsBeforeRecheck = fixture.readPolicy.mock.calls.length;
    writeAuthorityRevoked = true;
    await user.click(screen.getByRole("button", { name: "recheck-test-authority" }));
    await waitFor(() => expect(fixture.readPolicy.mock.calls.length).toBeGreaterThan(readsBeforeRecheck));
    await waitFor(() => expect(within(recovery).getByRole("button", { name: "按原请求重试" })).toHaveProperty("disabled", false));
    expect(within(recovery).getByRole("button", { name: "读取当前状态" })).toHaveProperty("disabled", false);
    await user.click(within(recovery).getByRole("button", { name: "按原请求重试" }));
    await waitFor(() => expect(fixture.setDefaultPolicyVersion).toHaveBeenCalledTimes(2));
    expect(screen.getByText(/即使重试返回冲突/)).toBeTruthy();
    await user.click(within(recovery).getByRole("button", { name: "读取当前状态" }));
    expect(await screen.findByText(/当前读取：默认版本 version-logs/)).toBeTruthy();
    expect(screen.getByText(/不能证明原请求是否执行/)).toBeTruthy();
    const end = screen.getByRole("button", { name: "结束旧意图" });
    expect(end.hasAttribute("disabled")).toBe(true);
    await user.click(screen.getByRole("checkbox", { name: /我理解原请求结果仍未知/ }));
    await user.click(end);
    await waitFor(() => expect(screen.queryByRole("heading", { name: "版本变更结果未确认" })).toBeNull());
    expect(fixture.setDefaultPolicyVersion.mock.calls[1]).toEqual(fixture.setDefaultPolicyVersion.mock.calls[0]);
  });

  it("keeps a first-submit authorization rejection in review without claiming version-write permission", async () => {
    const fixture = livePolicyVersions();
    fixture.setDefaultPolicyVersion.mockRejectedValueOnce(new HttpProblem(403, "IAM_FORBIDDEN"));
    const { user } = await openAccess(fixture.repository, iam(), "policies");
    await user.click(await screen.findByRole("button", { name: "LogBoundary" }));
    await user.click(await screen.findByRole("tab", { name: "策略版本" }));
    await screen.findByRole("table", { name: "策略版本目录" });
    await user.click(screen.getByRole("button", { name: "版本 version-a 的操作" }));
    await user.click(await screen.findByRole("menuitem", { name: "切换默认版本" }));
    await user.click(screen.getByRole("button", { name: "确认切换" }));
    expect(await screen.findByText("当前身份无权执行此操作。")).toBeTruthy();
    expect(screen.getByRole("heading", { name: "将 version-a 设为默认版本" })).toBeTruthy();
    expect(screen.queryByRole("heading", { name: "版本变更结果未确认" })).toBeNull();
    expect(fixture.setDefaultPolicyVersion).toHaveBeenCalledTimes(1);
  });

  it("keeps a forbidden version directory local while the independently readable default remains visible", async () => {
    const customer = { ...tenantPolicy, id: "customer.logs", management: "CUSTOMER" as const, accountId: account.id,
      displayName: "LogBoundary", defaultVersionId: "version-logs" };
    const readPolicy = vi.fn().mockResolvedValue(policyAccess({ policy: customer, version: { ...tenantPolicyDetail.version,
      policyId: customer.id, versionId: customer.defaultVersionId } }));
    const listPolicyVersions = vi.fn().mockRejectedValue(new HttpProblem(403, "FORBIDDEN"));
    const repository = accounts({ readPolicy, listPolicyVersions, readPolicyVersion: vi.fn(),
      listPolicies: vi.fn(async (_credential: string, platform: boolean) => platform ? directory(true) : { ...directory(false), items: [customer] }) });
    const { user } = await openAccess(repository, iam(), "policies");
    await user.click(await screen.findByRole("button", { name: customer.displayName }));
    expect(await screen.findByRole("table", { name: "策略声明" })).toBeTruthy();
    await user.click(screen.getByRole("tab", { name: "策略版本" }));
    expect(await screen.findByText(/无权读取这些版本/)).toBeTruthy();
    await user.click(screen.getByRole("tab", { name: "当前默认版本" }));
    expect(screen.getByRole("table", { name: "策略声明" })).toBeTruthy();
    expect(readPolicy).toHaveBeenCalledTimes(1);
  });

  it("keeps a forbidden policy detail local and never substitutes MOCK content", async () => {
    const readPolicy = vi.fn().mockRejectedValue(new HttpProblem(403, "FORBIDDEN"));
    const { user } = await openAccess(accounts({ readPolicy }), iam(), "policies");
    await user.click(await screen.findByRole("button", { name: tenantPolicy.displayName }));
    expect(await screen.findByText(/无权读取该策略的详情/)).toBeTruthy();
    expect(screen.queryByRole("table", { name: "策略声明" })).toBeNull();
    await user.click(screen.getByRole("button", { name: "返回列表" }));
    expect(screen.getByRole("table", { name: "策略元数据目录" })).toBeTruthy();
    expect(screen.queryByText(/隔离 MOCK 的权限能力目录/)).toBeNull();
  });

  it("loads the permission catalog only after its tab opens and keeps product detail in the content area", async () => {
    const listAuthorizationProfiles = vi.fn().mockResolvedValue(profileDirectory());
    const { user } = await openAccess(accounts({ listAuthorizationProfiles }), iam(), "policies");
    expect(await screen.findByRole("table", { name: "策略元数据目录" })).toBeTruthy();
    expect(listAuthorizationProfiles).not.toHaveBeenCalled();

    await user.click(screen.getByRole("tab", { name: "权限能力目录" }));
    expect(await screen.findByRole("table", { name: "产品权限能力目录" })).toBeTruthy();
    expect(listAuthorizationProfiles).toHaveBeenCalledTimes(1);
    expect(screen.getByText(/不是当前用户权限/)).toBeTruthy();

    await user.click(screen.getByRole("button", { name: "paas" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(screen.getByRole("heading", { level: 2, name: "paas" })).toBe(document.activeElement);
    const ownership = screen.getByRole("region", { name: "产品接入与租户授权是三段独立职责" });
    expect(within(ownership).getByText("定义能力并落实 PEP")).toBeTruthy();
    expect(within(ownership).getByText("校验契约并受信发布")).toBeTruthy();
    expect(within(ownership).getByText("消费目录并分配权限")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "查看内部接入流程（MOCK）" })).toBeNull();
    expect(screen.getByRole("table", { name: "产品 paas 的 Action 声明" })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "返回能力目录" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "paas" })).toBe(document.activeElement));
  });

  it("distinguishes declared subjects and credentials from the sealed legacy defaults", async () => {
    const catalog = profileDirectory();
    const entry = catalog.items[0]!;
    const sample = entry.profile.actions[0]!;
    entry.profile.actions = [
      { ...sample, subjectTypes: ["USER", "ROLE"], userAuthenticationMethods: ["ACCESS_KEY"] },
      { ...sample, action: "paas.application.legacy" },
      { ...sample, action: "paas.application.probe", scope: "INSTALLATION_PROBE", conditions: [] }
    ];
    const { user } = await openAccess(accounts({ listAuthorizationProfiles: vi.fn().mockResolvedValue(catalog) }), iam(), "policies");
    await user.click(await screen.findByRole("tab", { name: "权限能力目录" }));
    await user.click(await screen.findByRole("button", { name: "paas" }));
    const rows = within(screen.getByRole("table", { name: "产品 paas 的 Action 声明" })).getAllByRole("row");
    expect(within(rows[1]!).getByText("用户 · 角色")).toBeTruthy();
    expect(within(rows[1]!).getByText("用户凭证: 访问密钥")).toBeTruthy();
    expect(within(rows[1]!).queryByText(/历史默认/)).toBeNull();
    expect(within(rows[2]!).getByText("身份类型沿用历史默认")).toBeTruthy();
    expect(within(rows[2]!).getByText("凭证沿用历史默认（仅登录会话）")).toBeTruthy();
    expect(within(rows[3]!).getByText("服务身份")).toBeTruthy();
    expect(within(rows[3]!).getByText("用户凭证: 不适用")).toBeTruthy();
    expect(within(rows[3]!).queryByText(/仅登录会话/)).toBeNull();

    expect(screen.queryByRole("combobox", { name: "用户凭据" })).toBeNull();
    await user.click(screen.getByRole("button", { name: "筛选" }));
    await user.click(screen.getByRole("combobox", { name: "用户凭据" }));
    await user.click(screen.getByRole("option", { name: "访问密钥" }));
    expect(within(screen.getByRole("table", { name: "产品 paas 的 Action 声明" })).getAllByRole("row")).toHaveLength(2);
    expect(screen.getByRole("button", { name: "移除筛选：用户凭据: 访问密钥" })).toBeTruthy();

    await user.click(screen.getByRole("button", { name: "清除筛选" }));
    expect(within(screen.getByRole("table", { name: "产品 paas 的 Action 声明" })).getAllByRole("row")).toHaveLength(4);
    await user.click(screen.getByRole("combobox", { name: "适用主体" }));
    await user.click(screen.getByRole("option", { name: "服务身份" }));
    const serviceRows = within(screen.getByRole("table", { name: "产品 paas 的 Action 声明" })).getAllByRole("row");
    expect(serviceRows).toHaveLength(2);
    expect(within(serviceRows[1]!).getByText("paas.application.probe")).toBeTruthy();

    await user.click(screen.getByRole("button", { name: "清除筛选" }));
    await user.type(screen.getByRole("searchbox", { name: "搜索 Action" }), "ACCESS_KEY");
    expect(within(screen.getByRole("table", { name: "产品 paas 的 Action 声明" })).getAllByRole("row")).toHaveLength(2);
  });

  it("keeps the catalog notice and search in place while its data region waits", async () => {
    let resolve!: (value: AuthorizationProfileDirectory) => void;
    const pending = new Promise<AuthorizationProfileDirectory>((done) => { resolve = done; });
    const listAuthorizationProfiles = vi.fn().mockReturnValue(pending);
    const { user } = await openAccess(accounts({ listAuthorizationProfiles }), iam(), "policies");
    await screen.findByRole("table", { name: "策略元数据目录" });
    await user.click(screen.getByRole("tab", { name: "权限能力目录" }));
    expect(listAuthorizationProfiles).toHaveBeenCalledTimes(1);
    expect(screen.getByText(/不是当前用户权限/)).toBeTruthy();
    const search = screen.getByRole("searchbox", { name: "搜索产品能力" });
    await user.type(search, "paas");
    expect((search as HTMLInputElement).value).toBe("paas");
    expect(screen.queryByRole("table", { name: "产品权限能力目录" })).toBeNull();
    await act(async () => resolve(profileDirectory()));
    expect(screen.getByRole("searchbox", { name: "搜索产品能力" })).toBe(search);
    expect(await screen.findByRole("table", { name: "产品权限能力目录" })).toBeTruthy();
  });

  it("retains the same catalog search control and query through a local retry", async () => {
    let resolve!: (value: AuthorizationProfileDirectory) => void;
    const pending = new Promise<AuthorizationProfileDirectory>((done) => { resolve = done; });
    const listAuthorizationProfiles = vi.fn().mockRejectedValueOnce(new HttpProblem(503, "IAM_UNAVAILABLE")).mockReturnValueOnce(pending);
    const { user } = await openAccess(accounts({ listAuthorizationProfiles }), iam(), "policies");
    await user.click(await screen.findByRole("tab", { name: "权限能力目录" }));
    expect(await screen.findByText(/权限能力目录暂时不可用/)).toBeTruthy();
    const search = screen.getByRole("searchbox", { name: "搜索产品能力" });
    await user.type(search, "paas");
    await user.click(screen.getByRole("button", { name: "重新读取" }));
    expect(screen.getByRole("searchbox", { name: "搜索产品能力" })).toBe(search);
    expect((search as HTMLInputElement).value).toBe("paas");
    await act(async () => resolve(profileDirectory()));
    expect(within(await screen.findByRole("table", { name: "产品权限能力目录" })).getByRole("button", { name: "paas" })).toBeTruthy();
  });

  it("hides the previous identity's permission catalog while a replacement client reauthorizes", async () => {
    const firstLoad = vi.fn().mockResolvedValue(profileDirectory());
    let rejectReplacement!: (reason: unknown) => void;
    const replacementResult = new Promise<AuthorizationProfileDirectory>((_resolve, reject) => { rejectReplacement = reject; });
    const replacementLoad = vi.fn(() => replacementResult);
    const { user, replaceRepository } = await openAccess(accounts({ listAuthorizationProfiles: firstLoad }), iam(), "policies");
    await user.click(await screen.findByRole("tab", { name: "权限能力目录" }));
    await user.click(await screen.findByRole("button", { name: "paas" }));
    expect(screen.getByRole("heading", { level: 2, name: "paas" })).toBeTruthy();
    expect(screen.getByText(`sha256:${"a".repeat(64)}`)).toBeTruthy();

    act(() => replaceRepository(accounts({ listAuthorizationProfiles: replacementLoad })));
    expect(screen.queryByRole("heading", { level: 2, name: "paas" })).toBeNull();
    expect(screen.queryByText(`sha256:${"a".repeat(64)}`)).toBeNull();
    expect(screen.getAllByText("正在读取权限能力目录…").length).toBeGreaterThan(0);
    await waitFor(() => expect(replacementLoad).toHaveBeenCalled());

    await act(async () => rejectReplacement(new HttpProblem(403, "IAM_FORBIDDEN")));
    expect(await screen.findByText(/当前身份无权读取权限能力目录/)).toBeTruthy();
    expect(screen.queryByRole("table", { name: "产品权限能力目录" })).toBeNull();
    expect(screen.queryByRole("heading", { level: 2, name: "paas" })).toBeNull();
  });

  it("pages a complete product snapshot locally and preserves the page when returning from detail", async () => {
    const sample = profileDirectory().items[0]!;
    const items = Array.from({ length: 12 }, (_, index) => ({
      ...sample,
      profile: { ...sample.profile, product: `product-${String(index).padStart(2, "0")}` }
    }));
    const { user } = await openAccess(accounts({ listAuthorizationProfiles: vi.fn().mockResolvedValue({ accountId: account.id, items }) }), iam(), "policies");
    await user.click(await screen.findByRole("tab", { name: "权限能力目录" }));
    const table = await screen.findByRole("table", { name: "产品权限能力目录" });
    expect(within(table).getAllByRole("row")).toHaveLength(11);
    expect(within(table).queryByRole("button", { name: "product-10" })).toBeNull();
    expect(screen.getByText("第 1 / 2 页")).toBeTruthy();

    await user.click(screen.getByRole("button", { name: "下一页" }));
    expect(within(table).getAllByRole("row")).toHaveLength(3);
    await user.click(within(table).getByRole("button", { name: "product-11" }));
    expect(screen.getByRole("heading", { level: 2, name: "product-11" })).toBe(document.activeElement);
    await user.click(screen.getByRole("button", { name: "返回能力目录" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "product-11" })).toBe(document.activeElement));
    expect(screen.getByText("第 2 / 2 页")).toBeTruthy();

    await user.type(screen.getByRole("searchbox", { name: "搜索产品能力" }), "product-03");
    expect(screen.getByText("第 1 / 1 页")).toBeTruthy();
    const filteredTable = screen.getByRole("table", { name: "产品权限能力目录" });
    expect(within(filteredTable).getAllByRole("row")).toHaveLength(2);
    expect(within(filteredTable).getByRole("button", { name: "product-03" })).toBeTruthy();
  });

  it.each([
    [403, "PRIVATE", "当前身份无权读取权限能力目录"],
    [404, "iam.route.notfound", "后端版本或路由可能未匹配"],
    [404, "PRIVATE", "权限能力目录暂时不可用"],
    [503, "PRIVATE", "权限能力目录暂时不可用"]
  ])("localizes catalog HTTP %s %s without replacing the policy directory or falling back to MOCK", async (status, code, message) => {
    const { user } = await openAccess(accounts({ listAuthorizationProfiles: vi.fn().mockRejectedValue(new HttpProblem(status, code)) }), iam(), "policies");
    await screen.findByRole("table", { name: "策略元数据目录" });
    await user.click(screen.getByRole("tab", { name: "权限能力目录" }));
    expect(await screen.findByText(new RegExp(message))).toBeTruthy();
    expect(screen.queryByText(/隔离 MOCK 的权限能力目录/)).toBeNull();
    await user.click(screen.getByRole("tab", { name: "策略目录" }));
    expect(screen.getByRole("table", { name: "策略元数据目录" })).toBeTruthy();
  });

  it.each([
    ["iam.route.notfound", "routeUnavailable", "routeUnavailable", "routeUnavailable", "routeUnavailable", "routeUnavailable"],
    ["PRIVATE_TARGET_404", "notFound", "notFound", "unavailable", "unavailable", "unavailable"]
  ])("classifies stable route and target 404s without inferring empty state for %s", async (code, serviceRole, policy, profiles, templates, settings) => {
    const missing = () => Promise.reject(new HttpProblem(404, code));
    const repository = accounts({
      listServiceLinkedRoles: vi.fn(),
      getServiceLinkedRole: vi.fn(missing),
      readPolicy: vi.fn(missing),
      listAuthorizationProfiles: vi.fn(missing),
      listServiceRoleTemplates: vi.fn(missing),
      accountSecuritySettings: { read: vi.fn(missing) }
    });
    const user = userEvent.setup();
    render(<LocaleProvider><SessionProvider repository={iam()}><AccountAccessProvider repository={repository}><ReadClassificationProbe /></AccountAccessProvider></SessionProvider></LocaleProvider>);

    await user.click(screen.getByRole("button", { name: "login-read-classification" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "read-service-role" }).hasAttribute("disabled")).toBe(false));
    await user.click(screen.getByRole("button", { name: "read-service-role" }));
    await user.click(screen.getByRole("button", { name: "read-policy" }));
    await user.click(screen.getByRole("button", { name: "read-profiles" }));
    await user.click(screen.getByRole("button", { name: "read-templates" }));
    await user.click(screen.getByRole("button", { name: "read-settings" }));

    await waitFor(() => {
      expect(screen.getByLabelText("service-role-read-status").textContent).toBe(serviceRole);
      expect(screen.getByLabelText("policy-read-status").textContent).toBe(policy);
      expect(screen.getByLabelText("profile-read-status").textContent).toBe(profiles);
      expect(screen.getByLabelText("template-read-status").textContent).toBe(templates);
      expect(screen.getByLabelText("settings-read-status").textContent).toBe(settings);
    });
  });

  it("rejects a catalog bound to another account without clearing the policy scene", async () => {
    const { user } = await openAccess(accounts({ listAuthorizationProfiles: vi.fn().mockResolvedValue({ ...profileDirectory(), accountId: "tenant-b" }) }), iam(), "policies");
    await user.click(await screen.findByRole("tab", { name: "权限能力目录" }));
    expect(await screen.findByText(/权限能力目录暂时不可用/)).toBeTruthy();
    await user.click(screen.getByRole("tab", { name: "策略目录" }));
    expect(screen.getByRole("table", { name: "策略元数据目录" })).toBeTruthy();
  });

  it("opens one known Role without Role directory or creation authority", async () => {
    const list = vi.fn().mockResolvedValue(managedRoleDirectory);
    const read = vi.fn().mockResolvedValue(managedRoleAccess);
    const repository = accounts({
      currentIdentity: vi.fn().mockResolvedValue({ ...identity, capabilities: currentCapabilities(false) }),
      roles: {
        ...unusedLiveRoleRepositoryMutations(),
        list,
        read,
        readPermissionBoundary: vi.fn().mockResolvedValue({ accountId: account.id, roleId: managedRole.id, resourceVersion: 1, policy: null }),
        setPermissionBoundary: vi.fn().mockRejectedValue(new Error("unused boundary set")),
        removePermissionBoundary: vi.fn().mockRejectedValue(new Error("unused boundary removal")),
        listTrustVersions: vi.fn(),
        create: vi.fn().mockResolvedValue(managedRole),
        listSessions: vi.fn().mockResolvedValue({ accountId: account.id, roleId: managedRole.id, observedAt: timestamp, items: [], nextAfter: null }),
        readSession: vi.fn().mockRejectedValue(new Error("unused session read")),
        revokeSession: vi.fn().mockRejectedValue(new Error("unused session revoke"))
      }
    });

    const { user } = await openAccess(repository, iam(), "roles", credential, managedRole.id);

    expect(await screen.findByRole("heading", { name: managedRole.name })).toBeTruthy();
    expect(read).toHaveBeenCalledExactlyOnceWith(credential, account.id, managedRole.id);
    expect(list).not.toHaveBeenCalled();
    expect(screen.queryByRole("button", { name: "新建角色" })).toBeNull();

    await user.click(screen.getByTestId("nav-roles"));
    expect(await screen.findByRole("heading", { name: "没有此页面的管理权限" })).toBeTruthy();
    expect(list).not.toHaveBeenCalled();
  });

  it("loads current-account service authorization before the optional platform template directory", async () => {
    const roleIdentity: AccountIdentity = { ...identity, capabilities: [
      ...identity.capabilities,
      capability("iam.role.list", "ACCOUNT", account.id)
    ] };
    const templateReference = { id: "managedservice.installation-reader", version: 1, contentDigest: `sha256:${"c".repeat(64)}` };
    const relation = {
      role: {
        ...managedRole,
        id: "role-managedservice-reader",
        name: "ManagedServiceInstallationReader",
        description: "Allows one service to inspect a consented installation.",
        management: "SERVICE_LINKED" as const,
        resourceVersion: 1,
        currentTrustVersionId: "trust-managedservice-v1"
      },
      template: templateReference,
      servicePrincipal: { installationId: "installation-managedservice", principalId: "service-managedservice", purpose: "PAAS" as const },
      permissionCeiling: { policyId: "system.managedservice-installation-reader", versionId: "version-managedservice-installation-reader-v1", contentDigest: `sha256:${"b".repeat(64)}` }
    };
    const listServiceLinkedRoles = vi.fn().mockResolvedValue({ accountId: account.id, items: [{ relation, bindingCount: 1, activeBindingCount: 1 }], nextAfter: null });
    const getServiceLinkedRole = vi.fn().mockResolvedValue({ relation, bindings: [{
      id: "binding-managedservice", accountId: account.id, roleId: relation.role.id, template: templateReference,
      workload: { kind: "SERVICE_INSTALLATION", id: "installation-1" }, status: "ACTIVE", resourceVersion: 1,
      createdAt: timestamp, updatedAt: timestamp, revokedAt: null
    }], nextAfter: null });
    const listServiceRoleTemplates = vi.fn().mockResolvedValue({ items: [] });
    const repository = accounts({
      currentIdentity: vi.fn().mockResolvedValue(roleIdentity),
      listServiceLinkedRoles,
      getServiceLinkedRole,
      listServiceRoleTemplates,
      roles: {
        ...unusedLiveRoleRepositoryMutations(),
        list: vi.fn().mockResolvedValue(managedRoleDirectory),
        read: vi.fn().mockResolvedValue(managedRoleAccess),
        readPermissionBoundary: vi.fn().mockResolvedValue({ accountId: account.id, roleId: managedRole.id, resourceVersion: 1, policy: null }),
        setPermissionBoundary: vi.fn().mockRejectedValue(new Error("unused boundary set")),
        removePermissionBoundary: vi.fn().mockRejectedValue(new Error("unused boundary removal")),
        listTrustVersions: vi.fn(),
        create: vi.fn().mockResolvedValue(managedRole),
        listSessions: vi.fn().mockResolvedValue({ accountId: account.id, roleId: managedRole.id, observedAt: timestamp, items: [], nextAfter: null }),
        readSession: vi.fn().mockRejectedValue(new Error("unused session read")),
        revokeSession: vi.fn().mockRejectedValue(new Error("unused session revoke"))
      }
    });
    const { user } = await openAccess(repository, iam(), "roles");

    await screen.findByRole("table", { name: "角色" });
    expect(listServiceLinkedRoles).not.toHaveBeenCalled();
    expect(listServiceRoleTemplates).not.toHaveBeenCalled();
    await invokeMoreAction(user, "服务授权");
    expect(await screen.findByRole("table", { name: "当前账号服务授权关系" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "返回角色列表" })).toBeNull();
    expect(listServiceLinkedRoles).toHaveBeenCalledWith(expect.any(String), account.id, undefined);
    expect(listServiceRoleTemplates).not.toHaveBeenCalled();

    await user.click(screen.getByRole("button", { name: relation.role.name }));
    expect(await screen.findByRole("table", { name: "服务授权资源绑定历史" })).toBeTruthy();
    expect(getServiceLinkedRole).toHaveBeenCalledWith(expect.any(String), account.id, relation.role.id, undefined);
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("loads the live platform service-role templates only after the inline directory opens", async () => {
    const roleIdentity: AccountIdentity = { ...identity, capabilities: [
      ...identity.capabilities,
      capability("iam.role.list", "ACCOUNT", account.id)
    ] };
    const listServiceRoleTemplates = vi.fn().mockResolvedValue({ items: [{
      id: "managedservice.installation-reader", version: 1,
      spec: {
        product: "managedservice", servicePurpose: "PAAS",
        roleName: "ManagedServiceInstallationReader",
        roleDescription: "Allows inspection of one consented installation.",
        policyVersion: { policyId: "system.managedservice-installation-reader", versionId: "version-managedservice-installation-reader-v1", contentDigest: `sha256:${"b".repeat(64)}` },
        workloads: [{ resourceKind: "SERVICE_INSTALLATION", bindAction: "managedservice.service-installation.service-role.bind", unbindAction: "managedservice.service-installation.service-role.unbind" }],
        maxSessionDurationSeconds: 900
      },
      contentDigest: `sha256:${"c".repeat(64)}`, status: "ACTIVE"
    }] });
    const repository = accounts({
      currentIdentity: vi.fn().mockResolvedValue(roleIdentity),
      listServiceRoleTemplates,
      roles: {
        ...unusedLiveRoleRepositoryMutations(),
        list: vi.fn().mockResolvedValue(managedRoleDirectory),
        read: vi.fn().mockResolvedValue(managedRoleAccess),
        readPermissionBoundary: vi.fn().mockResolvedValue({ accountId: account.id, roleId: managedRole.id, resourceVersion: 1, policy: null }),
        setPermissionBoundary: vi.fn().mockRejectedValue(new Error("unused boundary set")),
        removePermissionBoundary: vi.fn().mockRejectedValue(new Error("unused boundary removal")),
        listTrustVersions: vi.fn(),
        create: vi.fn().mockResolvedValue(managedRole),
        listSessions: vi.fn().mockResolvedValue({ accountId: account.id, roleId: managedRole.id, observedAt: timestamp, items: [], nextAfter: null }),
        readSession: vi.fn().mockRejectedValue(new Error("unused session read")),
        revokeSession: vi.fn().mockRejectedValue(new Error("unused session revoke"))
      }
    });
    const { user } = await openAccess(repository, iam(), "roles");

    await screen.findByRole("table", { name: "角色" });
    expect(listServiceRoleTemplates).not.toHaveBeenCalled();
    await invokeMoreAction(user, "服务授权");
    await user.click(screen.getByRole("tab", { name: "平台模板" }));
    expect(await screen.findByRole("table", { name: "服务授权模板目录" })).toBeTruthy();
    expect(listServiceRoleTemplates).toHaveBeenCalledTimes(1);
    expect(screen.getByText("非账号授权状态")).toBeTruthy();
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("creates a live role in the content area and retains the exact request after an unknown result", async () => {
    const roleIdentity: AccountIdentity = { ...identity, capabilities: [
      ...identity.capabilities,
      capability("iam.role.list", "ACCOUNT", account.id),
      capability("iam.role.create", "ACCOUNT", account.id)
    ] };
    const create = vi.fn()
      .mockRejectedValueOnce(new Error("connection lost after submit"))
      .mockResolvedValue({ ...managedRole, name: "IncidentResponder", description: "Temporary incident response" });
    const repository = accounts({
      currentIdentity: vi.fn().mockResolvedValue(roleIdentity),
      roles: {
        ...unusedLiveRoleRepositoryMutations(),
        list: vi.fn().mockResolvedValue(managedRoleDirectory),
        read: vi.fn().mockResolvedValue(managedRoleAccess),
        readPermissionBoundary: vi.fn().mockResolvedValue({ accountId: account.id, roleId: managedRole.id, resourceVersion: 1, policy: null }),
        setPermissionBoundary: vi.fn().mockRejectedValue(new Error("unused boundary set")),
        removePermissionBoundary: vi.fn().mockRejectedValue(new Error("unused boundary removal")),
        listTrustVersions: vi.fn(),
        create,
        listSessions: vi.fn().mockResolvedValue({ accountId: account.id, roleId: managedRole.id, observedAt: timestamp, items: [], nextAfter: null }),
        readSession: vi.fn().mockRejectedValue(new Error("unused session read")),
        revokeSession: vi.fn().mockRejectedValue(new Error("unused session revoke"))
      }
    });
    const { user } = await openAccess(repository, iam(), "roles");

    await user.click(await screen.findByRole("button", { name: "新建角色" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    await user.click(screen.getByRole("button", { name: "下一步" }));
    expect(screen.getByRole("alert").textContent).toContain("至少选择一名");
    await user.click(screen.getByRole("checkbox", { name: "developer" }));
    await user.click(screen.getByRole("button", { name: "下一步" }));
    await user.click(screen.getByLabelText("名称", { exact: true }));
    await user.paste("IncidentResponder");
    await user.click(screen.getByLabelText("描述", { exact: true }));
    await user.paste("Temporary incident response");
    await user.click(screen.getByRole("button", { name: "下一步" }));
    expect(create).not.toHaveBeenCalled();
    expect(screen.getByText("本次 Root 命令只创建角色元数据", { exact: false })).toBeTruthy();

    await user.click(screen.getByRole("button", { name: "新建角色" }));
    expect(await screen.findByText("创建结果尚未确认", { exact: false })).toBeTruthy();
    const original = create.mock.calls[0]?.[2];
    expect(original).toMatchObject({
      name: "IncidentResponder",
      description: "Temporary incident response",
      maxSessionDurationSeconds: 3600,
      trustPolicy: { statements: [{ principals: [{ type: "USER", id: childUser.id }] }] }
    });
    await user.click(screen.getByRole("button", { name: "重试原请求" }));
    expect(await screen.findByRole("heading", { name: "角色已创建" })).toBeTruthy();
    expect(create).toHaveBeenCalledTimes(2);
    expect(create.mock.calls[1]?.[2]).toEqual(original);
  });

  it("explains delegated role creation without adding a client-selected permission boundary", async () => {
    const delegatedBoundary = {
      accountId: account.id,
      userId: childUser.id,
      resourceVersion: childUser.resourceVersion,
      policy: { policyId: "policy-developer-ceiling", versionId: "v4", contentDigest: `sha256:${"c".repeat(64)}` }
    };
    const delegatedIdentity: AccountIdentity = {
      ...identity,
      user: childUser,
      identityKind: "USER",
      permissionBoundary: delegatedBoundary,
      policySources: child.policyAttachments.map((item) => ({ kind: "DIRECT" as const, attachment: item })),
      capabilities: [
        ...identity.capabilities,
        capability("iam.role.list", "ACCOUNT", account.id),
        capability("iam.role.create", "ACCOUNT", account.id)
      ]
    };
    const create = vi.fn().mockResolvedValue({ ...managedRole, name: "DelegatedReviewer" });
    const repository = accounts({
      currentIdentity: vi.fn().mockResolvedValue(delegatedIdentity),
      roles: {
        ...unusedLiveRoleRepositoryMutations(),
        list: vi.fn().mockResolvedValue(managedRoleDirectory),
        read: vi.fn().mockResolvedValue(managedRoleAccess),
        readPermissionBoundary: vi.fn().mockResolvedValue({ accountId: account.id, roleId: managedRole.id, resourceVersion: 1, policy: delegatedBoundary.policy }),
        setPermissionBoundary: vi.fn().mockRejectedValue(new Error("delegated boundary management must stay closed")),
        removePermissionBoundary: vi.fn().mockRejectedValue(new Error("delegated boundary management must stay closed")),
        listTrustVersions: vi.fn(),
        create,
        listSessions: vi.fn().mockResolvedValue({ accountId: account.id, roleId: managedRole.id, observedAt: timestamp, items: [], nextAfter: null }),
        readSession: vi.fn().mockRejectedValue(new Error("unused session read")),
        revokeSession: vi.fn().mockRejectedValue(new Error("unused session revoke"))
      }
    });
    const { user } = await openAccess(repository, iam({}, childUser.id), "roles");

    await user.click(await screen.findByRole("button", { name: "新建角色" }));
    expect(screen.getByText("受限委派创建不提供边界选择器", { exact: false })).toBeTruthy();
    expect(screen.getByText(delegatedBoundary.policy.policyId)).toBeTruthy();
    expect(screen.getByText(delegatedBoundary.policy.versionId)).toBeTruthy();
    await user.click(screen.getByRole("checkbox", { name: "developer" }));
    await user.click(screen.getByRole("button", { name: "下一步" }));
    await user.type(screen.getByLabelText("名称", { exact: true }), "DelegatedReviewer");
    await user.click(screen.getByRole("button", { name: "下一步" }));

    expect(screen.getByText("请求没有边界选择器", { exact: false })).toBeTruthy();
    expect(screen.getByText("创建时权限上限")).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "新建角色" }));

    expect(await screen.findByRole("heading", { name: "角色已创建" })).toBeTruthy();
    expect(screen.getAllByText("同一事务中创建角色", { exact: false })).toHaveLength(2);
    const submitted = create.mock.calls[0]?.[2];
    expect(submitted).toEqual({
      name: "DelegatedReviewer",
      description: "",
      tags: [],
      maxSessionDurationSeconds: 3600,
      trustPolicy: {
        languageVersion: "1",
        statements: [{ sid: "trusted-users", effect: "ALLOW", principals: [{ type: "USER", id: childUser.id }] }]
      },
      requestId: expect.any(String)
    });
    expect(submitted).not.toHaveProperty("boundaryId");
    expect(submitted).not.toHaveProperty("permissionBoundary");
  });

  it("loads a fresh tenant policy directory only when inline role-boundary editing opens", async () => {
    const roleIdentity: AccountIdentity = { ...identity, capabilities: [
      ...identity.capabilities,
      capability("iam.role.list", "ACCOUNT", account.id)
    ] };
    const closed = { accountId: account.id, roleId: managedRole.id, resourceVersion: 1, policy: null };
    const applied = { accountId: account.id, roleId: managedRole.id, resourceVersion: 2,
      policy: { policyId: tenantPolicy.id, versionId: tenantPolicy.defaultVersionId, contentDigest: `sha256:${"d".repeat(64)}` } };
    const listPolicies = vi.fn(async (_credential: string, platform: boolean) => directory(platform));
    const readPermissionBoundary = vi.fn().mockResolvedValueOnce(closed).mockResolvedValue(applied);
    const setPermissionBoundary = vi.fn().mockResolvedValue(applied);
    const repository = accounts({
      currentIdentity: vi.fn().mockResolvedValue(roleIdentity),
      listPolicies,
      roles: {
        ...unusedLiveRoleRepositoryMutations(),
        list: vi.fn().mockResolvedValue(managedRoleDirectory),
        read: vi.fn().mockResolvedValue(managedRoleAccess),
        readPermissionBoundary,
        setPermissionBoundary,
        removePermissionBoundary: vi.fn().mockRejectedValue(new Error("unused boundary removal")),
        listTrustVersions: vi.fn(),
        create: vi.fn().mockResolvedValue(managedRole),
        listSessions: vi.fn().mockResolvedValue({ accountId: account.id, roleId: managedRole.id, observedAt: timestamp, items: [], nextAfter: null }),
        readSession: vi.fn().mockRejectedValue(new Error("unused session read")),
        revokeSession: vi.fn().mockRejectedValue(new Error("unused session revoke"))
      }
    });
    const { user } = await openAccess(repository, iam(), "roles");

    await user.click(await screen.findByRole("button", { name: managedRole.name }));
    expect(await screen.findByText("未设置权限上限 · 角色承担已关闭")).toBeTruthy();
    const initialTenantReads = listPolicies.mock.calls.filter((call) => call[1] === false).length;
    await user.click(screen.getByRole("button", { name: "修改权限边界" }));
    await waitFor(() => expect(listPolicies.mock.calls.filter((call) => call[1] === false)).toHaveLength(initialTenantReads + 1));
    await user.click(screen.getByRole("combobox", { name: "权限边界" }));
    await user.click(await screen.findByRole("option", { name: `${tenantPolicy.displayName} · ${tenantPolicy.id}` }));
    await user.click(screen.getByRole("button", { name: "审阅变更" }));
    await user.click(screen.getByRole("button", { name: "确认变更" }));

    await waitFor(() => expect(setPermissionBoundary).toHaveBeenCalledWith(credential, account.id, managedRole.id, expect.objectContaining({
      policyId: tenantPolicy.id,
      policyResourceVersion: tenantPolicy.resourceVersion,
      resourceVersion: closed.resourceVersion,
      requestId: expect.stringMatching(/^role-boundary-/)
    })));
    expect(await screen.findByText("IAM 已确认权限上限变更，并完成权威状态回读。")).toBeTruthy();
    expect(readPermissionBoundary).toHaveBeenCalledTimes(2);
  });

  it("does not expire the current Session when an old role repository returns a late 401", async () => {
    const roleIdentity: AccountIdentity = { ...identity, capabilities: [
      ...identity.capabilities,
      capability("iam.role.list", "ACCOUNT", account.id)
    ] };
    let rejectOldRequest: ((reason?: unknown) => void) | undefined;
    const oldCreatePolicyAttachment = vi.fn(() => new Promise<never>((_resolve, reject) => { rejectOldRequest = reject; }));
    const replacementCreatePolicyAttachment = vi.fn().mockRejectedValue(new Error("replacement write must not start"));
    const roleRepository = (createPolicyAttachment: typeof oldCreatePolicyAttachment) => ({
      ...unusedLiveRoleRepositoryMutations(),
      list: vi.fn().mockResolvedValue(managedRoleDirectory),
      read: vi.fn().mockResolvedValue(managedRoleAccess),
      readPermissionBoundary: vi.fn().mockResolvedValue({ accountId: account.id, roleId: managedRole.id, resourceVersion: 1, policy: null }),
      setPermissionBoundary: vi.fn().mockRejectedValue(new Error("unused boundary set")),
      removePermissionBoundary: vi.fn().mockRejectedValue(new Error("unused boundary removal")),
      listTrustVersions: vi.fn(),
      create: vi.fn().mockResolvedValue(managedRole),
      createPolicyAttachment,
      listSessions: vi.fn().mockResolvedValue({ accountId: account.id, roleId: managedRole.id, observedAt: timestamp, items: [], nextAfter: null }),
      readSession: vi.fn().mockRejectedValue(new Error("unused session read")),
      revokeSession: vi.fn().mockRejectedValue(new Error("unused session revoke"))
    });
    const previous = accounts({ currentIdentity: vi.fn().mockResolvedValue(roleIdentity), roles: roleRepository(oldCreatePolicyAttachment) });
    const replacement = accounts({ currentIdentity: vi.fn().mockResolvedValue(roleIdentity), roles: roleRepository(replacementCreatePolicyAttachment) });
    const { user, replaceRepository } = await openAccess(previous, iam(), "roles", credential, managedRole.id);

    expect(await screen.findByRole("heading", { name: managedRole.name })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "关联策略" }));
    await user.click(await screen.findByRole("combobox", { name: "要关联的策略" }));
    await user.click(await screen.findByRole("option", { name: `${tenantPolicy.displayName} · ${tenantPolicy.id}` }));
    await user.click(screen.getByRole("button", { name: "审阅变更" }));
    await user.click(screen.getByRole("button", { name: "确认关联策略" }));
    await waitFor(() => expect(oldCreatePolicyAttachment).toHaveBeenCalledTimes(1));

    replaceRepository(replacement);
    await waitFor(() => expect(replacement.currentIdentity).toHaveBeenCalledTimes(1));
    expect(await screen.findByText("策略关联结果尚未确认")).toBeTruthy();
    await act(async () => { rejectOldRequest?.(new HttpProblem(401, "IAM_SESSION_EXPIRED")); });

    expect(screen.queryByRole("button", { name: "登录控制台" })).toBeNull();
    expect(screen.getByRole("heading", { name: managedRole.name })).toBeTruthy();
    expect(screen.getByText("策略关联结果尚未确认")).toBeTruthy();
    expect(replacementCreatePolicyAttachment).not.toHaveBeenCalled();
    expect(sessionStorage.length).toBe(1);
  });

  it("discards a late role creation result when the Session-scoped client changes", async () => {
    const roleIdentity: AccountIdentity = { ...identity, capabilities: [
      ...identity.capabilities,
      capability("iam.role.list", "ACCOUNT", account.id),
      capability("iam.role.create", "ACCOUNT", account.id)
    ] };
    const scene = buildAccountAccessScene(roleIdentity, { items: [child], nextAfter: null }, null, directory(false), directory(true));
    let resolveCreate!: (value: typeof managedRole) => void;
    const create = vi.fn(() => new Promise<typeof managedRole>((resolve) => { resolveCreate = resolve; }));
    const roleClient = (clientIdentity: string, operation: RoleAccessClient["create"]): RoleAccessClient => ({
      identity: clientIdentity,
      accountId: account.id,
      actorPrincipalId: identity.user.id,
      sessionRevision: 1,
      canCreate: true,
      createRestrictionReason: null,
      list: vi.fn().mockResolvedValue(managedRoleDirectory),
      read: vi.fn().mockResolvedValue(managedRoleAccess),
      readPermissionBoundary: vi.fn().mockResolvedValue({ accountId: account.id, roleId: managedRole.id, resourceVersion: 1, policy: null }),
      listTenantPolicies: vi.fn().mockResolvedValue({ items: [], available: true }),
      setPermissionBoundary: vi.fn().mockRejectedValue(new Error("unused boundary set")),
      removePermissionBoundary: vi.fn().mockRejectedValue(new Error("unused boundary removal")),
      listTrustVersions: vi.fn(),
      create: operation,
      update: vi.fn().mockRejectedValue(new Error("unused role update")),
      setStatus: vi.fn().mockRejectedValue(new Error("unused role status")),
      setTrustPolicy: vi.fn().mockRejectedValue(new Error("unused role trust")),
      delete: vi.fn().mockRejectedValue(new Error("unused role delete")),
      createPolicyAttachment: vi.fn().mockRejectedValue(new Error("unused role attachment")),
      inspectPolicyAttachmentChange: vi.fn().mockRejectedValue(new Error("unused policy attachment completion")),
      revokePolicyAttachment: vi.fn().mockRejectedValue(new Error("unused role revocation")),
      listSessions: vi.fn().mockResolvedValue({ accountId: account.id, roleId: managedRole.id, observedAt: timestamp, items: [], nextAfter: null }),
      readSession: vi.fn().mockRejectedValue(new Error("unused session read")),
      revokeSession: vi.fn().mockRejectedValue(new Error("unused session revoke"))
    });
    const firstClient = roleClient("role-client-first", create);
    const secondClient = roleClient("role-client-second", vi.fn().mockResolvedValue(managedRole));
    const user = userEvent.setup();
    const onDone = vi.fn();
    const wizard = (client: RoleAccessClient) => <LocaleProvider><UnsavedChangesProvider>
      <LiveRoleCreationWizard client={client} scene={scene} onBack={vi.fn()} onDone={onDone} />
    </UnsavedChangesProvider></LocaleProvider>;
    const view = render(wizard(firstClient));

    await user.click(screen.getByRole("checkbox", { name: "developer" }));
    await user.click(screen.getByRole("button", { name: "下一步" }));
    await user.type(screen.getByLabelText("名称", { exact: true }), "OldSessionRole");
    await user.click(screen.getByRole("button", { name: "下一步" }));
    await user.click(screen.getByRole("button", { name: "新建角色" }));
    await waitFor(() => expect(create).toHaveBeenCalledTimes(1));

    view.rerender(wizard(secondClient));
    await waitFor(() => expect((screen.getByRole("checkbox", { name: "developer" }) as HTMLInputElement).checked).toBe(false));
    await act(async () => { resolveCreate({ ...managedRole, id: "late-old-session-role", name: "OldSessionRole" }); });

    expect(screen.queryByRole("heading", { name: "角色已创建" })).toBeNull();
    expect(screen.queryByText("late-old-session-role")).toBeNull();
    expect(onDone).not.toHaveBeenCalled();
  });

  it("retains one uncertain role-session revoke across the real keyed directory navigation boundary", async () => {
    const roleIdentity: AccountIdentity = { ...identity, capabilities: [
      ...identity.capabilities,
      capability("iam.role.list", "ACCOUNT", account.id),
      capability("iam.role.create", "ACCOUNT", "collection")
    ] };
    const revoked = { ...managedRoleSession, status: "REVOKED" as const, revokedAt: "2026-09-21T08:31:00Z" };
    const revokeSession = vi.fn().mockRejectedValueOnce(new Error("connection lost after submit")).mockResolvedValue({ outcome: "EQUAL_REPLAY" as const, session: revoked });
    const repository = accounts({
      currentIdentity: vi.fn().mockResolvedValue(roleIdentity),
      roles: {
        ...unusedLiveRoleRepositoryMutations(),
        list: vi.fn().mockResolvedValue(managedRoleDirectory),
        read: vi.fn().mockResolvedValue(managedRoleAccess),
        readPermissionBoundary: vi.fn().mockResolvedValue({ accountId: account.id, roleId: managedRole.id, resourceVersion: 1, policy: null }),
        setPermissionBoundary: vi.fn().mockRejectedValue(new Error("unused boundary set")),
        removePermissionBoundary: vi.fn().mockRejectedValue(new Error("unused boundary removal")),
        listTrustVersions: vi.fn(),
        create: vi.fn().mockResolvedValue(managedRole),
        listSessions: vi.fn().mockResolvedValue({ accountId: account.id, roleId: managedRole.id, observedAt: timestamp, items: [managedRoleSessionItem], nextAfter: null }),
        readSession: vi.fn().mockResolvedValue({ observedAt: timestamp, item: managedRoleSessionItem }),
        revokeSession
      }
    });
    const { user } = await openAccess(repository, iam(), "roles");

    await user.click(await screen.findByRole("button", { name: managedRole.name }));
    await user.click(await screen.findByRole("tab", { name: "角色会话" }));
    await user.click(await screen.findByRole("button", { name: `会话 ${managedRoleSession.id} 的操作` }));
    await user.click(screen.getByRole("menuitem", { name: "撤销会话" }));
    let workflow = screen.getByRole("group", { name: "撤销会话" });
    await user.click(within(workflow).getByRole("button", { name: "撤销会话" }));
    expect(await within(workflow).findByText("撤销结果尚未确认", { exact: false })).toBeTruthy();
    const originalRequestId = revokeSession.mock.calls[0]?.[4];
    await user.click(within(workflow).getByRole("button", { name: "取消" }));
    await user.click(screen.getByRole("button", { name: "返回列表" }));
    await user.click(await screen.findByRole("button", { name: managedRole.name }));
    await user.click(await screen.findByRole("tab", { name: "角色会话" }));
    await user.click(await screen.findByRole("button", { name: "继续处理未知结果" }));
    workflow = screen.getByRole("group", { name: "撤销会话" });
    expect(within(workflow).getByText(originalRequestId ?? "missing")).toBeTruthy();
    await user.click(within(workflow).getByRole("button", { name: "重试原请求" }));
    await waitFor(() => expect(revokeSession).toHaveBeenCalledTimes(2));
    expect(revokeSession.mock.calls[1]?.[4]).toBe(originalRequestId);
  });

  it("clears a pending role-session revoke across accounts and rejects a late callback from the old account", async () => {
    const identityFor = (suffix: "a" | "b"): AccountIdentity => {
      const tenant = `tenant-${suffix}`;
      const principal = `primary-${suffix}`;
      return {
        account: { id: tenant, displayName: `Team ${suffix.toUpperCase()}`, status: "ACTIVE", rootIdentity: { principalId: principal, loginName: `admin-${suffix}` }, loginAlias: null, resourceVersion: 1 },
        user: { id: principal, accountId: tenant, loginName: `admin-${suffix}`, displayName: `Admin ${suffix.toUpperCase()}`, status: "ACTIVE", resourceVersion: 1, mustChangePassword: false },
        identityKind: "ROOT_IDENTITY",
        policySources: [],
        permissionBoundary: { accountId: tenant, userId: principal, resourceVersion: 1, policy: null },
        capabilities: []
      };
    };
    const auth = iam({
      login: vi.fn(async ({ loginName }) => {
        const suffix = loginName.endsWith("-b") ? "b" : "a";
        return { outcome: "AUTHENTICATED" as const, credential: `credential-tenant-${suffix}`, mustChangePassword: false, session: { id: `session-${suffix}`, organizationId: `tenant-${suffix}`, principalId: `primary-${suffix}`, status: "ACTIVE" as const, issuedAt: timestamp, expiresAt: "2099-08-27T00:00:00Z" } };
      })
    });
    const repository = accounts({
      currentIdentity: vi.fn(async (activeCredential: string) => identityFor(activeCredential.endsWith("-b") ? "b" : "a")),
      listPolicies: vi.fn(async (activeCredential: string, platform: boolean) => ({
        accountId: activeCredential.endsWith("-b") ? "tenant-b" : "tenant-a",
        scope: platform ? "INSTALLATION" as const : "TENANT" as const,
        installationId: platform ? "installation-test" : null,
        items: []
      }))
    });
    const user = userEvent.setup();
    render(<LocaleProvider><SessionProvider repository={auth}><AccountAccessProvider repository={repository}><AccountIntentProbe /></AccountAccessProvider></SessionProvider></LocaleProvider>);

    await user.click(screen.getByRole("button", { name: "login-a" }));
    await waitFor(() => expect(screen.getByLabelText("active-account").textContent).toBe("tenant-a"));
    await user.click(screen.getByRole("button", { name: "remember-revoke" }));
    expect(screen.getByLabelText("pending-revoke").textContent).toBe(accountSwitchIntent.requestId);
    await user.click(screen.getByRole("button", { name: "logout" }));
    await waitFor(() => expect(screen.getByLabelText("pending-revoke").textContent).toBe("none"));
    await user.click(screen.getByRole("button", { name: "login-b" }));
    await waitFor(() => expect(screen.getByLabelText("active-account").textContent).toBe("tenant-b"));
    await user.click(screen.getByRole("button", { name: "late-old-update" }));
    expect(screen.getByLabelText("pending-revoke").textContent).toBe("none");
  });

  it("does not deliver an old attachment result into a new account session", async () => {
    const auth = iam({
      login: vi.fn(async ({ loginName }) => {
        const suffix = loginName.endsWith("-b") ? "b" : "a";
        return { outcome: "AUTHENTICATED" as const, credential: `credential-tenant-${suffix}`, mustChangePassword: false,
          session: { id: `session-${suffix}`, organizationId: `tenant-${suffix}`, principalId: `primary-${suffix}`, status: "ACTIVE" as const,
            issuedAt: timestamp, expiresAt: "2099-08-27T00:00:00Z" } };
      })
    });
    let finishOldRequest: (() => void) | undefined;
    const execute = vi.fn(() => new Promise<void>((resolve) => { finishOldRequest = resolve; }));
    const repository = accounts({
      execute,
      currentIdentity: vi.fn(async (activeCredential: string) => activeCredential.endsWith("-a") ? structuredClone(identity) : {
        ...structuredClone(identity),
        account: { ...account, id: "tenant-b", displayName: "Team B", rootIdentity: { principalId: "primary-b", loginName: "admin-b" } },
        user: { ...rootUser, id: "primary-b", accountId: "tenant-b", loginName: "admin-b" },
        permissionBoundary: { ...identity.permissionBoundary, accountId: "tenant-b", userId: "primary-b" },
        capabilities: []
      }),
      listUsers: vi.fn(async (activeCredential: string) => ({ items: activeCredential.endsWith("-a") ? [child] : [], nextAfter: null })),
      listPolicies: vi.fn(async (activeCredential: string, platform: boolean) => activeCredential.endsWith("-a") ? directory(platform) : {
        accountId: "tenant-b", scope: platform ? "INSTALLATION" as const : "TENANT" as const,
        installationId: platform ? "installation-test" : null, items: []
      })
    });
    const user = userEvent.setup();
    render(<LocaleProvider><SessionProvider repository={auth}><AccountAccessProvider repository={repository}><AccountIntentProbe /></AccountAccessProvider></SessionProvider></LocaleProvider>);

    await user.click(screen.getByRole("button", { name: "login-a" }));
    await waitFor(() => expect(screen.getByLabelText("active-account").textContent).toBe("tenant-a"));
    await user.click(screen.getByRole("button", { name: "begin-attachment" }));
    expect(screen.getByLabelText("pending-attachment").textContent).toMatch(/^ui-user-attachment-/);
    await user.click(screen.getByRole("button", { name: "submit-attachment" }));
    await waitFor(() => expect(execute).toHaveBeenCalledTimes(1));
    await user.click(screen.getByRole("button", { name: "logout" }));
    await user.click(screen.getByRole("button", { name: "login-b" }));
    await waitFor(() => expect(screen.getByLabelText("active-account").textContent).toBe("tenant-b"));
    expect(screen.getByLabelText("pending-attachment").textContent).toBe("none");
    await act(async () => { finishOldRequest?.(); });
    expect(screen.getByLabelText("pending-attachment").textContent).toBe("none");
    expect(screen.getByLabelText("attachment-success").textContent).toBe("none");
  });

  it("keeps the original direct attachment locked when an old repository resolves after its owner is replaced", async () => {
    let finishOldRequest: (() => void) | undefined;
    let requestId = "";
    const execute = vi.fn((_credential: string, command: Parameters<AccountRepository["execute"]>[1]) => {
      if (command.kind !== "create-policy-attachment") throw new Error("unexpected account command");
      requestId = command.requestId;
      return new Promise<void>((resolve) => { finishOldRequest = resolve; });
    });
    const previous = accounts({ execute });
    const replacement = accounts();
    const { user, replaceRepository } = await openAccess(previous);

    await user.click(await screen.findByRole("button", { name: "查看用户 developer" }));
    await user.click(screen.getByRole("combobox", { name: "关联策略" }));
    await user.click(screen.getByRole("option", { name: /PlatformAdministrator/ }));
    await user.click(screen.getByRole("button", { name: "审阅关联" }));
    await user.click(screen.getByRole("button", { name: "确认关联" }));
    await waitFor(() => expect(execute).toHaveBeenCalledTimes(1));
    expect(requestId).toMatch(/^ui-user-attachment-/);
    expect(sessionStorage.length).toBe(1);

    replaceRepository(replacement);
    await waitFor(() => expect(replacement.currentIdentity).toHaveBeenCalledTimes(1));
    expect(await screen.findByText("策略关系结果待确认")).toBeTruthy();
    const review = screen.getByRole("region", { name: "确认直接关联策略" });
    expect(within(review).getByText((content) => content.includes(requestId))).toBeTruthy();
    expect(within(review).getByRole("button", { name: "检查原请求结果" })).toBeTruthy();

    await act(async () => { finishOldRequest?.(); });
    expect(screen.getByText("策略关系结果待确认")).toBeTruthy();
    expect(screen.queryByText("操作已完成")).toBeNull();
    expect(replacement.execute).not.toHaveBeenCalled();
    expect(sessionStorage.length).toBe(1);
  });

  it("withholds direct USER policy controls until a replacement repository identity is verified", async () => {
    let verifyReplacement!: (value: AccountIdentity) => void;
    const replacementExecute = vi.fn().mockResolvedValue(undefined);
    const replacementRevoke = vi.fn().mockResolvedValue({
      id: "attachment-child-a-system.paas-viewer", resourceVersion: 2, revokedAt: timestamp
    });
    const replacement = accounts({
      currentIdentity: vi.fn(() => new Promise<AccountIdentity>((resolve) => { verifyReplacement = resolve; })),
      getUser: vi.fn().mockResolvedValue(structuredClone(child)),
      execute: replacementExecute,
      revokePolicyAttachment: replacementRevoke
    });
    const { user, replaceRepository } = await openAccess();
    await user.click(await screen.findByRole("button", { name: "查看用户 developer" }));
    await screen.findByRole("combobox", { name: "关联策略" });

    replaceRepository(replacement);
    await waitFor(() => expect(replacement.currentIdentity).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(replacement.getUser).toHaveBeenCalledTimes(1));
    const policySelector = await screen.findByRole("combobox", { name: "关联策略" }) as HTMLButtonElement;
    const revoke = screen.getByRole("button", { name: "撤销策略 ReadOnlyAccess" }) as HTMLButtonElement;
    expect(policySelector.disabled).toBe(true);
    expect(revoke.disabled).toBe(true);
    expect(replacementExecute).not.toHaveBeenCalled();
    expect(replacementRevoke).not.toHaveBeenCalled();

    await act(async () => { verifyReplacement(structuredClone(identity)); });
    await waitFor(() => expect((screen.getByRole("combobox", { name: "关联策略" }) as HTMLButtonElement).disabled).toBe(false));
    expect((screen.getByRole("button", { name: "撤销策略 ReadOnlyAccess" }) as HTMLButtonElement).disabled).toBe(false);
    await user.click(screen.getByRole("combobox", { name: "关联策略" }));
    await user.click(screen.getByRole("option", { name: /PlatformAdministrator/ }));
    await user.click(screen.getByRole("button", { name: "审阅关联" }));
    await user.click(screen.getByRole("button", { name: "确认关联" }));
    await waitFor(() => expect(replacementExecute).toHaveBeenCalledTimes(1));
  });

  it("withholds original USER attachment completion reads until a replacement repository identity is verified", async () => {
    let verifyReplacement!: (value: AccountIdentity) => void;
    const execute = vi.fn().mockRejectedValue(new Error("connection lost after commit"));
    const readPolicyAttachmentChange = vi.fn(async (_credential: string, expected: PolicyAttachmentChangeExpectation) => {
      if (expected.operation !== "CREATE") throw new Error("unexpected operation");
      return {
        operation: "CREATE" as const,
        accountId: expected.accountId,
        actorPrincipalId: expected.actorPrincipalId,
        requestId: expected.requestId,
        completedAt: timestamp,
        target: expected.target,
        policyId: expected.policyId,
        policyResourceVersion: expected.policyResourceVersion,
        attachment: attachment(expected.target.id, platformPolicy)
      };
    });
    const replacement = accounts({
      currentIdentity: vi.fn(() => new Promise<AccountIdentity>((resolve) => { verifyReplacement = resolve; })),
      getUser: vi.fn().mockResolvedValue(structuredClone(child)),
      readPolicyAttachmentChange
    });
    const { user, replaceRepository } = await openAccess(accounts({ execute }));
    await user.click(await screen.findByRole("button", { name: "查看用户 developer" }));
    await user.click(screen.getByRole("combobox", { name: "关联策略" }));
    await user.click(screen.getByRole("option", { name: /PlatformAdministrator/ }));
    await user.click(screen.getByRole("button", { name: "审阅关联" }));
    await user.click(screen.getByRole("button", { name: "确认关联" }));
    expect(await screen.findByText("策略关系结果待确认")).toBeTruthy();

    replaceRepository(replacement);
    await waitFor(() => expect(replacement.currentIdentity).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(replacement.getUser).toHaveBeenCalledTimes(1));
    expect(await screen.findByText("策略关系结果待确认")).toBeTruthy();
    const inspect = screen.getByRole("button", { name: "检查原请求结果" }) as HTMLButtonElement;
    expect(inspect.disabled).toBe(true);
    await user.click(inspect);
    expect(readPolicyAttachmentChange).not.toHaveBeenCalled();

    await act(async () => { verifyReplacement(structuredClone(identity)); });
    await waitFor(() => expect((screen.getByRole("button", { name: "检查原请求结果" }) as HTMLButtonElement).disabled).toBe(false));
    await user.click(screen.getByRole("button", { name: "检查原请求结果" }));
    expect(await screen.findByRole("status", { name: "原策略关联命令已确认" })).toBeTruthy();
    expect(readPolicyAttachmentChange).toHaveBeenCalledTimes(1);
    expect(execute).toHaveBeenCalledTimes(1);
  });

  it("fails closed when direct USER policy context commands bypass the controls before replacement identity verification", async () => {
    let replacementVerified = false;
    let verifyReplacement!: (value: AccountIdentity) => void;
    const replacementExecute = vi.fn().mockResolvedValue(undefined);
    const replacementRevoke = vi.fn().mockResolvedValue({
      id: "attachment-child-a-system.paas-viewer", resourceVersion: 2, revokedAt: timestamp
    });
    const replacement = accounts({
      currentIdentity: vi.fn(() => replacementVerified ? Promise.resolve(structuredClone(identity)) :
        new Promise<AccountIdentity>((resolve) => { verifyReplacement = (value) => { replacementVerified = true; resolve(value); }; })),
      getUser: vi.fn().mockResolvedValue(structuredClone(child)),
      execute: replacementExecute,
      revokePolicyAttachment: replacementRevoke
    });
    const { user, replaceRepository } = await openDirectUserPolicyOwnerProbe(accounts());

    replaceRepository(replacement);
    await waitFor(() => expect(replacement.currentIdentity).toHaveBeenCalledTimes(1));
    await user.click(screen.getByRole("button", { name: "direct-read-user" }));
    await waitFor(() => expect(screen.getByLabelText("direct-read-result").textContent).toBe("ready"));
    expect(replacement.getUser).toHaveBeenCalledTimes(1);
    expect(screen.getByLabelText("direct-owner-ready").textContent).toBe("false");

    await user.click(screen.getByRole("button", { name: "direct-begin-attachment" }));
    await user.click(screen.getByRole("button", { name: "direct-begin-revocation" }));
    await user.click(screen.getByRole("button", { name: "direct-submit-attachment" }));
    await waitFor(() => expect(screen.getByLabelText("direct-submit-result").textContent).toBe("false"));
    expect(screen.getByLabelText("direct-attach-result").textContent).toBe("false");
    expect(screen.getByLabelText("direct-revoke-result").textContent).toBe("false");
    expect(screen.getByLabelText("direct-policy-intent").textContent).toBe("none");
    expect(replacementExecute).not.toHaveBeenCalled();
    expect(replacementRevoke).not.toHaveBeenCalled();

    await act(async () => { verifyReplacement(structuredClone(identity)); });
    await waitFor(() => expect(screen.getByLabelText("direct-owner-ready").textContent).toBe("true"));
    await user.click(screen.getByRole("button", { name: "direct-begin-attachment" }));
    await waitFor(() => expect(screen.getByLabelText("direct-attach-result").textContent).toBe("true"));
    expect(screen.getByLabelText("direct-policy-intent").textContent).toMatch(/^review:ui-user-attachment-/);
    await user.click(screen.getByRole("button", { name: "direct-end-attachment" }));
    await waitFor(() => expect(screen.getByLabelText("direct-policy-intent").textContent).toBe("none"));
    expect(screen.getByLabelText("direct-end-result").textContent).toBe("true");
    await user.click(screen.getByRole("button", { name: "direct-begin-revocation" }));
    await waitFor(() => expect(screen.getByLabelText("direct-revoke-result").textContent).toBe("true"));
    expect(screen.getByLabelText("direct-policy-intent").textContent).toMatch(/^review:ui-user-revocation-/);
    await user.click(screen.getByRole("button", { name: "direct-end-attachment" }));
    await waitFor(() => expect(screen.getByLabelText("direct-policy-intent").textContent).toBe("none"));
    await user.click(screen.getByRole("button", { name: "direct-begin-attachment" }));
    await waitFor(() => expect(screen.getByLabelText("direct-policy-intent").textContent).toMatch(/^review:ui-user-attachment-/));
    await user.click(screen.getByRole("button", { name: "direct-submit-attachment" }));
    await waitFor(() => expect(screen.getByLabelText("direct-submit-result").textContent).toBe("true"));
    expect(replacementExecute).toHaveBeenCalledTimes(1);
  });

  it("fails closed when direct UNKNOWN inspection bypasses the controls before replacement identity verification", async () => {
    let replacementVerified = false;
    let verifyReplacement!: (value: AccountIdentity) => void;
    const execute = vi.fn().mockRejectedValue(new Error("connection lost after commit"));
    const readPolicyAttachmentChange = vi.fn(async (_credential: string, expected: PolicyAttachmentChangeExpectation) => {
      if (expected.operation !== "CREATE") throw new Error("unexpected operation");
      return {
        operation: "CREATE" as const,
        accountId: expected.accountId,
        actorPrincipalId: expected.actorPrincipalId,
        requestId: expected.requestId,
        completedAt: timestamp,
        target: expected.target,
        policyId: expected.policyId,
        policyResourceVersion: expected.policyResourceVersion,
        attachment: attachment(expected.target.id, platformPolicy)
      };
    });
    const replacement = accounts({
      currentIdentity: vi.fn(() => replacementVerified ? Promise.resolve(structuredClone(identity)) :
        new Promise<AccountIdentity>((resolve) => { verifyReplacement = (value) => { replacementVerified = true; resolve(value); }; })),
      getUser: vi.fn().mockResolvedValue(structuredClone(child)),
      readPolicyAttachmentChange
    });
    const { user, replaceRepository } = await openDirectUserPolicyOwnerProbe(accounts({ execute }));
    await user.click(screen.getByRole("button", { name: "direct-begin-attachment" }));
    await waitFor(() => expect(screen.getByLabelText("direct-policy-intent").textContent).toMatch(/^review:ui-user-attachment-/));
    await user.click(screen.getByRole("button", { name: "direct-submit-attachment" }));
    await waitFor(() => expect(screen.getByLabelText("direct-policy-intent").textContent).toMatch(/^unknown:ui-user-attachment-/));
    expect(execute).toHaveBeenCalledTimes(1);

    replaceRepository(replacement);
    await waitFor(() => expect(replacement.currentIdentity).toHaveBeenCalledTimes(1));
    await user.click(screen.getByRole("button", { name: "direct-read-user" }));
    await waitFor(() => expect(screen.getByLabelText("direct-read-result").textContent).toBe("ready"));
    expect(screen.getByLabelText("direct-owner-ready").textContent).toBe("false");
    expect(screen.getByLabelText("direct-policy-intent").textContent).toMatch(/^unknown:ui-user-attachment-/);
    await user.click(screen.getByRole("button", { name: "direct-inspect-attachment" }));
    await waitFor(() => expect(screen.getByLabelText("direct-inspect-result").textContent).toBe("false"));
    expect(readPolicyAttachmentChange).not.toHaveBeenCalled();

    await act(async () => { verifyReplacement(structuredClone(identity)); });
    await waitFor(() => expect(screen.getByLabelText("direct-owner-ready").textContent).toBe("true"));
    await user.click(screen.getByRole("button", { name: "direct-inspect-attachment" }));
    await waitFor(() => expect(screen.getByLabelText("direct-inspect-result").textContent).toBe("true"));
    expect(readPolicyAttachmentChange).toHaveBeenCalledTimes(1);
    expect(screen.getByLabelText("direct-policy-intent").textContent).toMatch(/^confirmed:ui-user-attachment-/);
    expect(execute).toHaveBeenCalledTimes(1);
  });

  it("expires the current Session when a normal direct attachment submission is rejected with 401", async () => {
    const execute = vi.fn().mockRejectedValue(new HttpProblem(401, "IAM_SESSION_EXPIRED"));
    const { user } = await openAccess(accounts({ execute }));

    await user.click(await screen.findByRole("button", { name: "查看用户 developer" }));
    await user.click(screen.getByRole("combobox", { name: "关联策略" }));
    await user.click(screen.getByRole("option", { name: /PlatformAdministrator/ }));
    await user.click(screen.getByRole("button", { name: "审阅关联" }));
    await user.click(screen.getByRole("button", { name: "确认关联" }));

    expect(await screen.findByRole("button", { name: "登录控制台" })).toBeTruthy();
    expect(execute).toHaveBeenCalledTimes(1);
    expect(sessionStorage.length).toBe(0);
  });

  it("rejects a second user policy write after the original result becomes unknown", async () => {
    const execute = vi.fn().mockRejectedValue(new Error("connection lost after commit"));
    const user = userEvent.setup();
    render(<LocaleProvider><SessionProvider repository={iam()}><AccountAccessProvider repository={accounts({ execute })}><AccountIntentProbe /></AccountAccessProvider></SessionProvider></LocaleProvider>);

    await user.click(screen.getByRole("button", { name: "login-a" }));
    await waitFor(() => expect(screen.getByLabelText("active-account").textContent).toBe("tenant-a"));
    await user.click(screen.getByRole("button", { name: "begin-attachment" }));
    await user.click(screen.getByRole("button", { name: "submit-attachment" }));
    await waitFor(() => expect(execute).toHaveBeenCalledTimes(1));

    await user.click(screen.getByRole("button", { name: "submit-attachment" }));
    expect(execute).toHaveBeenCalledTimes(1);
  });

  it("fails only the policy directory region without substituting MOCK data after a non-authorization error", async () => {
    const repository = accounts({ listPolicies: vi.fn(async (_credential: string, platform: boolean) => {
      if (platform) throw new HttpProblem(503, "UPSTREAM_UNAVAILABLE");
      return directory(false);
    }) });
    await openAccess(repository, iam(), "policies");
    expect(await screen.findByText("平台策略目录暂时不可用")).toBeTruthy();
    expect(screen.queryByRole("table", { name: "策略元数据目录" })).toBeNull();
    expect(screen.queryByText("ReadOnlyAccess")).toBeNull();
  });

  it("reviews the exact user, scope and current policy revision before a direct attachment", async () => {
    const { user, repository } = await openAccess();
    await user.click(await screen.findByRole("button", { name: "查看用户 developer" }));
    expect((screen.getByRole("button", { name: "审阅关联" }) as HTMLButtonElement).disabled).toBe(true);
    await user.click(screen.getByRole("combobox", { name: "关联策略" }));
    await user.click(screen.getByRole("option", { name: /PlatformAdministrator/ }));
    await user.click(screen.getByRole("button", { name: "审阅关联" }));
    expect(repository.execute).not.toHaveBeenCalled();
    const review = screen.getByRole("region", { name: "确认直接关联策略" });
    expect(within(review).getByText("system.platform-admin")).toBeTruthy();
    expect(within(review).getByText("平台安装")).toBeTruthy();
    expect(within(review).getByText("version-1 · 修订 2")).toBeTruthy();
    expect(within(review).getByText(/仅具有对应平台授权能力/)).toBeTruthy();
    expect(within(review).getByRole("heading", { name: "确认直接关联策略" })).toBe(document.activeElement);
    expect((screen.getByRole("button", { name: "撤销策略 ReadOnlyAccess" }) as HTMLButtonElement).disabled).toBe(true);
    await user.click(within(review).getByRole("button", { name: "返回选择" }));
    expect(screen.getByRole("button", { name: "审阅关联" })).toBe(document.activeElement);
    expect((screen.getByRole("button", { name: "撤销策略 ReadOnlyAccess" }) as HTMLButtonElement).disabled).toBe(false);
    expect(repository.execute).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "审阅关联" }));
    await user.click(screen.getByRole("button", { name: "确认关联" }));
    await waitFor(() => expect(repository.execute).toHaveBeenCalledWith(credential, { kind: "create-policy-attachment", userId: "child-a", policyId: "system.platform-admin", policyResourceVersion: 2, requestId: expect.any(String) }));
    await waitFor(() => expect(screen.getByRole("combobox", { name: "关联策略" }).textContent).toBe("选择可关联策略"));
    expect((screen.getByRole("button", { name: "审阅关联" }) as HTMLButtonElement).disabled).toBe(true);
  });

  it("keeps platform grants unavailable without the exact platform capability while tenant grants remain reviewable", async () => {
    const restricted: UserAccess = { ...child, capabilities: child.capabilities.map((item) => item.action === "iam.platform-policy-attachment.create"
      ? { ...item, available: false, restrictionReason: "AUTHORITY_REQUIRED" as const } : item) };
    const tenantCandidate: AccountPolicy = { ...tenantPolicy, id: "customer.team-read", management: "CUSTOMER",
      accountId: account.id, displayName: "TeamReadOnly", resourceVersion: 4 };
    const repository = accounts({
      listUsers: vi.fn().mockResolvedValue({ items: [restricted], nextAfter: null }),
      getUser: vi.fn().mockResolvedValue(structuredClone(restricted)),
      listPolicies: vi.fn(async (_credential: string, platform: boolean) => platform ? directory(true) :
        { ...directory(false), items: [tenantPolicy, tenantCandidate] })
    });
    const { user } = await openAccess(repository);
    await user.click(await screen.findByRole("button", { name: "查看用户 developer" }));
    expect(screen.getByText(/平台安装策略不可关联/).textContent).toContain("当前身份没有执行此操作所需的权限");
    await user.click(screen.getByRole("combobox", { name: "关联策略" }));
    expect(screen.queryByRole("option", { name: /PlatformAdministrator/ })).toBeNull();
    await user.click(screen.getByRole("option", { name: /TeamReadOnly/ }));
    await user.click(screen.getByRole("button", { name: "审阅关联" }));
    const review = screen.getByRole("region", { name: "确认直接关联策略" });
    expect(within(review).getByText("当前租户")).toBeTruthy();
    expect(within(review).getByText(/用户组继承、权限边界与显式拒绝/)).toBeTruthy();
    expect(repository.execute).not.toHaveBeenCalled();
  });

  it("never exposes a write replay after a direct attachment result becomes unknown", async () => {
    const execute = vi.fn().mockRejectedValue(new Error("connection lost after commit"));
    const { user } = await openAccess(accounts({ execute }));
    await user.click(await screen.findByRole("button", { name: "查看用户 developer" }));
    await user.click(screen.getByRole("combobox", { name: "关联策略" }));
    await user.click(screen.getByRole("option", { name: /PlatformAdministrator/ }));
    await user.click(screen.getByRole("button", { name: "审阅关联" }));
    await user.click(screen.getByRole("button", { name: "确认关联" }));
    const check = await screen.findByRole("button", { name: "检查原请求结果" });
    expect(screen.getByText(/当前关系目录不能证明这次请求已完成/)).toBeTruthy();
    expect(execute).toHaveBeenCalledTimes(1);
    expect(execute.mock.calls[0]?.[1]).toEqual(expect.objectContaining({ requestId: expect.any(String) }));
    expect(check).toBeTruthy();
    expect(screen.queryByRole("button", { name: "原请求重试" })).toBeNull();
  });

  it("confirms an uncertain direct attachment only from its immutable completion without replaying the write", async () => {
    const execute = vi.fn().mockRejectedValue(new Error("connection lost after commit"));
    const readPolicyAttachmentChange = vi.fn(async (_credential: string, expected: PolicyAttachmentChangeExpectation) => {
      if (expected.operation !== "CREATE") throw new Error("unexpected operation");
      return {
        operation: "CREATE" as const,
        accountId: expected.accountId,
        actorPrincipalId: expected.actorPrincipalId,
        requestId: expected.requestId,
        completedAt: timestamp,
        target: expected.target,
        policyId: expected.policyId,
        policyResourceVersion: expected.policyResourceVersion,
        attachment: attachment(expected.target.id, platformPolicy)
      };
    });
    const { user } = await openAccess(accounts({ execute, readPolicyAttachmentChange }));
    await user.click(await screen.findByRole("button", { name: "查看用户 developer" }));
    await user.click(screen.getByRole("combobox", { name: "关联策略" }));
    await user.click(screen.getByRole("option", { name: /PlatformAdministrator/ }));
    await user.click(screen.getByRole("button", { name: "审阅关联" }));
    await user.click(screen.getByRole("button", { name: "确认关联" }));
    expect(await screen.findByText("策略关系结果待确认")).toBeTruthy();
    expect(sessionStorage.length).toBe(1);

    await user.click(screen.getByRole("button", { name: "检查原请求结果" }));
    expect(await screen.findByText("原策略关联命令已确认")).toBeTruthy();
    expect(screen.getByText(/attachment-child-a-system\.platform-admin/)).toBeTruthy();
    const originalRequestId = execute.mock.calls[0]?.[1].requestId;
    const receipt = within(screen.getByRole("status", { name: "原策略关联命令已确认" }));
    expect(receipt.getByText(originalRequestId)).toBeTruthy();
    expect(receipt.getByText(childUser.id)).toBeTruthy();
    expect(receipt.getByText(platformPolicy.id)).toBeTruthy();
    expect(receipt.getByText("attachment-child-a-system.platform-admin")).toBeTruthy();
    expect(readPolicyAttachmentChange).toHaveBeenCalledWith(credential, {
      operation: "CREATE", accountId: account.id, actorPrincipalId: rootUser.id,
      requestId: expect.stringMatching(/^ui-user-attachment-[0-9a-f]{32}$/),
      target: { kind: "USER", id: childUser.id }, policyId: platformPolicy.id, policyResourceVersion: platformPolicy.resourceVersion
    });
    expect(execute).toHaveBeenCalledTimes(1);
    expect(sessionStorage.length).toBe(1);
    const finish = screen.getByRole("button", { name: "完成并重新读取" }) as HTMLButtonElement;
    await waitFor(() => expect(finish.disabled).toBe(false));
    await user.click(finish);
    await waitFor(() => expect(screen.queryByText("原策略关联命令已确认")).toBeNull());
    expect(sessionStorage.length).toBe(0);
  });

  it.each([
    [404, /IAM 没有返回该请求的完成记录/],
    [403, /当前身份没有读取该完成记录的权限/],
    [503, /IAM 暂时无法返回可验证的完成记录/],
    [0, /IAM 暂时无法返回可验证的完成记录/]
  ])("keeps an uncertain direct attachment locked when completion lookup fails with %s", async (status, message) => {
    const execute = vi.fn().mockRejectedValue(new Error("connection lost after commit"));
    const readPolicyAttachmentChange = vi.fn().mockRejectedValue(status === 0
      ? new Error("network unavailable")
      : new HttpProblem(status, status === 404 ? "IAM_NOT_FOUND" : status === 403 ? "IAM_FORBIDDEN" : "IAM_UNAVAILABLE"));
    const { user } = await openAccess(accounts({ execute, readPolicyAttachmentChange }));
    await user.click(await screen.findByRole("button", { name: "查看用户 developer" }));
    await user.click(screen.getByRole("combobox", { name: "关联策略" }));
    await user.click(screen.getByRole("option", { name: /PlatformAdministrator/ }));
    await user.click(screen.getByRole("button", { name: "审阅关联" }));
    await user.click(screen.getByRole("button", { name: "确认关联" }));
    await user.click(await screen.findByRole("button", { name: "检查原请求结果" }));
    expect(await screen.findByText(message)).toBeTruthy();
    const review = screen.getByRole("region", { name: "确认直接关联策略" });
    expect(within(review).getByRole("button", { name: "检查原请求结果" })).toBeTruthy();
    expect(within(review).queryByRole("button", { name: "原请求重试" })).toBeNull();
    expect(within(review).queryByRole("button", { name: "结束原意图并重新读取" })).toBeNull();
    expect(execute).toHaveBeenCalledTimes(1);
    expect(readPolicyAttachmentChange).toHaveBeenCalledTimes(1);
    expect(sessionStorage.length).toBe(1);
  });

  it("preserves an unknown policy completion across login expiry and never replays it after authentication", async () => {
    const execute = vi.fn().mockRejectedValue(new Error("connection lost after commit"));
    const readPolicyAttachmentChange = vi.fn().mockRejectedValue(new HttpProblem(401, "IAM_SESSION_EXPIRED"));
    const repository = accounts({ execute, readPolicyAttachmentChange });
    const auth = iam();
    const { user } = await openAccess(repository, auth);
    await user.click(await screen.findByRole("button", { name: "查看用户 developer" }));
    await user.click(screen.getByRole("combobox", { name: "关联策略" }));
    await user.click(screen.getByRole("option", { name: /PlatformAdministrator/ }));
    await user.click(screen.getByRole("button", { name: "审阅关联" }));
    await user.click(screen.getByRole("button", { name: "确认关联" }));
    await user.click(await screen.findByRole("button", { name: "检查原请求结果" }));
    expect(await screen.findByRole("button", { name: "登录控制台" })).toBeTruthy();
    expect(sessionStorage.length).toBe(1);
    expect(execute).toHaveBeenCalledTimes(1);

    await user.type(screen.getByLabelText("密码", { exact: true }), "Only-Test-Password-49!");
    await user.click(screen.getByRole("button", { name: "登录控制台" }));
    await waitFor(() => expect(repository.currentIdentity).toHaveBeenCalledTimes(2));
    await user.click(await screen.findByRole("button", { name: "查看用户 developer" }));
    expect(await screen.findByText(/当前登录会话已失效/)).toBeTruthy();
    expect(screen.getByRole("button", { name: "检查原请求结果" })).toBeTruthy();
    expect(execute).toHaveBeenCalledTimes(1);
    expect(readPolicyAttachmentChange).toHaveBeenCalledTimes(1);
  });

  it("restores only the same actor's non-secret policy completion reminder after reload", async () => {
    const execute = vi.fn().mockRejectedValue(new Error("connection lost after commit"));
    const readPolicyAttachmentChange = vi.fn().mockRejectedValue(new HttpProblem(404, "IAM_NOT_FOUND"));
    const repository = accounts({ execute, readPolicyAttachmentChange });
    const first = await openAccess(repository);
    await first.user.click(await screen.findByRole("button", { name: "查看用户 developer" }));
    await first.user.click(screen.getByRole("combobox", { name: "关联策略" }));
    await first.user.click(screen.getByRole("option", { name: /PlatformAdministrator/ }));
    await first.user.click(screen.getByRole("button", { name: "审阅关联" }));
    await first.user.click(screen.getByRole("button", { name: "确认关联" }));
    expect(await screen.findByText("策略关系结果待确认")).toBeTruthy();
    const key = sessionStorage.key(0)!;
    const reminder = JSON.parse(sessionStorage.getItem(key)!);
    expect(reminder).toMatchObject({
      kind: "attach", accountId: account.id, actorId: rootUser.id, userId: childUser.id,
      policyId: platformPolicy.id, policyResourceVersion: platformPolicy.resourceVersion,
      requestId: expect.stringMatching(/^ui-user-attachment-[0-9a-f]{32}$/), phase: "unknown"
    });
    expect(JSON.stringify(reminder)).not.toContain(credential);
    first.view.unmount();

    const resumed = await openAccess(repository);
    await resumed.user.click(await screen.findByRole("button", { name: "查看用户 developer" }));
    expect(await screen.findByText("策略关系结果待确认")).toBeTruthy();
    expect(screen.getByText(/本地提醒丢失也不能证明原请求失败/)).toBeTruthy();
    expect(execute).toHaveBeenCalledTimes(1);
    expect(screen.getByRole("button", { name: "检查原请求结果" })).toBeTruthy();
    resumed.view.unmount();

    sessionStorage.setItem(key, JSON.stringify({ ...reminder, actorId: "different-actor" }));
    const foreign = await openAccess(repository);
    await foreign.user.click(await screen.findByRole("button", { name: "查看用户 developer" }));
    expect(screen.queryByText("策略关系结果待确认")).toBeNull();
    expect(screen.getByRole("button", { name: "审阅关联" })).toBeTruthy();
    expect(execute).toHaveBeenCalledTimes(1);
  });

  it("keeps an uncertain direct attachment across IAM routes without issuing a new request", async () => {
    const execute = vi.fn().mockRejectedValue(new Error("connection lost after commit"));
    const { user } = await openAccess(accounts({ execute }));
    await user.click(await screen.findByRole("button", { name: "查看用户 developer" }));
    await user.click(screen.getByRole("combobox", { name: "关联策略" }));
    await user.click(screen.getByRole("option", { name: /PlatformAdministrator/ }));
    await user.click(screen.getByRole("button", { name: "审阅关联" }));
    await user.click(screen.getByRole("button", { name: "确认关联" }));
    await screen.findByRole("button", { name: "检查原请求结果" });
    const originalCommand = execute.mock.calls[0]?.[1];

    await user.click(screen.getByTestId("nav-policies"));
    expect(screen.queryByRole("region", { name: "确认直接关联策略" })).toBeNull();
    await user.click(screen.getByTestId("nav-users"));
    await user.click(await screen.findByRole("button", { name: "查看用户 developer" }));
    const review = screen.getByRole("region", { name: "确认直接关联策略" });
    expect(within(review).getByText((content) => content.includes(originalCommand.requestId))).toBeTruthy();
    expect(within(review).getByRole("button", { name: "检查原请求结果" })).toBeTruthy();
    expect(within(review).queryByRole("button", { name: "原请求重试" })).toBeNull();
    expect(execute).toHaveBeenCalledTimes(1);
  });

  it("does not start another user's attachment while the original result is unknown", async () => {
    const otherUser: User = { ...childUser, id: "child-b", loginName: "operator", displayName: "Operator B" };
    const other: UserAccess = { user: otherUser, policyAttachments: [], capabilities: userCapabilities(otherUser) };
    const execute = vi.fn().mockRejectedValue(new Error("connection lost after commit"));
    const { user } = await openAccess(accounts({
      execute,
      listUsers: vi.fn().mockResolvedValue({ items: [child, other], nextAfter: null }),
      getUser: vi.fn(async (_credential: string, id: string) => structuredClone(id === childUser.id ? child : other))
    }));
    await user.click(await screen.findByRole("button", { name: "查看用户 developer" }));
    await user.click(screen.getByRole("combobox", { name: "关联策略" }));
    await user.click(screen.getByRole("option", { name: /PlatformAdministrator/ }));
    await user.click(screen.getByRole("button", { name: "审阅关联" }));
    await user.click(screen.getByRole("button", { name: "确认关联" }));
    await screen.findByRole("button", { name: "检查原请求结果" });
    await user.click(screen.getByRole("button", { name: "返回列表" }));
    await user.click(await screen.findByRole("button", { name: "查看用户 operator" }));
    expect(screen.getByText(/developer@tenant-a 的策略关系请求仍待处理/)).toBeTruthy();
    expect((screen.getByRole("button", { name: "审阅关联" }) as HTMLButtonElement).disabled).toBe(true);
    expect(execute).toHaveBeenCalledTimes(1);
  });

  it("requires confirmation for revocation and disabling and clears a submitted reset password", async () => {
    const { user, repository } = await openAccess();
    await user.click(await screen.findByRole("button", { name: "查看用户 developer" }));
    await user.click(screen.getByRole("button", { name: "撤销策略 ReadOnlyAccess" }));
    expect(repository.execute).not.toHaveBeenCalled();
    expect(repository.revokePolicyAttachment).not.toHaveBeenCalled();
    let review = screen.getByRole("region", { name: "确认撤销直接关联" });
    expect(within(review).getByText(/attachment-child-a-system.paas-viewer/)).toBeTruthy();
    expect(within(review).getByText(/修订 1/)).toBeTruthy();
    expect(within(review).getByRole("heading", { name: "确认撤销直接关联" })).toBe(document.activeElement);
    await user.click(within(review).getByRole("button", { name: "取消" }));
    expect(screen.getByRole("button", { name: "撤销策略 ReadOnlyAccess" })).toBe(document.activeElement);
    expect(repository.revokePolicyAttachment).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "撤销策略 ReadOnlyAccess" }));
    review = screen.getByRole("region", { name: "确认撤销直接关联" });
    await user.click(within(review).getByRole("button", { name: "确认撤销" }));
    await waitFor(() => expect(repository.revokePolicyAttachment).toHaveBeenCalledWith(credential, "attachment-child-a-system.paas-viewer", { resourceVersion: 1, requestId: expect.stringMatching(/^ui-user-revocation-/) }));
    await waitFor(() => expect((screen.getByRole("button", { name: "禁用用户" }) as HTMLButtonElement).disabled).toBe(false));
    await user.click(screen.getByRole("button", { name: "禁用用户" }));
    expect(repository.execute).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "确认禁用" }));
    await waitFor(() => expect(repository.userManagement!.submit).toHaveBeenCalledWith(credential, expect.objectContaining({ operation: "USER_SET_STATUS", userId: "child-a", intendedStatus: "DISABLED", expectedResourceVersion: 2 })));
    await waitFor(() => expect((screen.getByRole("button", { name: "重置密码" }) as HTMLButtonElement).disabled).toBe(false));
    await user.click(screen.getByRole("button", { name: "重置密码" }));
    await user.type(screen.getByLabelText(/^初始密码/), "Reset-Only-Test-Password-74!");
    await user.click(screen.getByRole("button", { name: "审阅重置" }));
    let resetReview = screen.getByRole("region", { name: "确认重置目标与影响" });
    expect(within(resetReview).getByText("developer@tenant-a")).toBeTruthy();
    expect(within(resetReview).getByText(/撤销所有现有会话/)).toBeTruthy();
    expect(within(resetReview).getByRole("heading", { name: "确认重置目标与影响" })).toBe(document.activeElement);
    expect(resetReview.textContent).not.toContain("Reset-Only-Test-Password-74!");
    expect(repository.execute).not.toHaveBeenCalled();
    await user.click(within(resetReview).getByRole("button", { name: "修改初始密码" }));
    expect(screen.getByLabelText(/^初始密码/)).toHaveProperty("value", "Reset-Only-Test-Password-74!");
    await user.click(screen.getByRole("button", { name: "审阅重置" }));
    resetReview = screen.getByRole("region", { name: "确认重置目标与影响" });
    await user.click(within(resetReview).getByRole("button", { name: "确认重置密码" }));
    await waitFor(() => expect(repository.execute).toHaveBeenCalledWith(credential, { kind: "reset-password", userId: "child-a", initialPassword: "Reset-Only-Test-Password-74!", resourceVersion: 2, requestId: expect.stringMatching(/^ui-user-reset-/) }));
    expect(screen.queryByDisplayValue("Reset-Only-Test-Password-74!")).toBeNull();
  });

  it("retains a non-secret unknown reset notice across IAM navigation and never auto-retries", async () => {
    const execute = vi.fn(async (_credential: string, command: { kind: string; requestId?: string }) => {
      if (command.kind === "reset-password") throw new Error("connection lost after dispatch");
    });
    const readPasswordResetCompletion = vi.fn(async (_credential: string, request: { accountId: string; actorId: string; userId: string; requestId: string; resourceVersion: number }) => ({
      accountId: request.accountId, actorPrincipalId: request.actorId, userId: request.userId,
      requestId: request.requestId, expectedResourceVersion: request.resourceVersion,
      resultingResourceVersion: request.resourceVersion + 1, eventId: "event-original", occurredAt: timestamp
    }));
    const { user } = await openAccess(accounts({ execute, readPasswordResetCompletion }));
    await user.click(await screen.findByRole("button", { name: "查看用户 developer" }));
    await user.click(screen.getByRole("button", { name: "重置密码" }));
    await user.type(screen.getByLabelText(/^初始密码/), "Reset-Only-Test-Password-74!");
    await user.click(screen.getByRole("button", { name: "审阅重置" }));
    await user.click(screen.getByRole("button", { name: "确认重置密码" }));
    expect(await screen.findByText("重置密码结果尚未确认")).toBeTruthy();
    expect(screen.getByText(/再次重置可能覆盖已生效的临时密码/)).toBeTruthy();
    expect((screen.getByRole("button", { name: "重置密码" }) as HTMLButtonElement).disabled).toBe(true);
    expect(screen.queryByDisplayValue("Reset-Only-Test-Password-74!")).toBeNull();
    expect(document.body.textContent).not.toContain("Reset-Only-Test-Password-74!");
    expect(execute.mock.calls[0]?.[1].requestId).toMatch(/^ui-user-reset-/);
    expect(execute).toHaveBeenCalledTimes(1);
    expect(sessionStorage.length).toBe(1);
    const stored = JSON.parse(sessionStorage.getItem(sessionStorage.key(0)!)!);
    expect(stored).toMatchObject({ accountId: account.id, actorId: rootUser.id, userId: "child-a", resourceVersion: 2, requestId: execute.mock.calls[0]?.[1].requestId });
    expect(JSON.stringify(stored)).not.toContain("Reset-Only-Test-Password-74!");
    expect(JSON.stringify(stored)).not.toContain(credential);
    await user.click(screen.getByTestId("nav-overview"));
    expect(screen.getByText("重置密码结果尚未确认")).toBeTruthy();
    await user.click(screen.getByTestId("nav-users"));
    await user.click(await screen.findByRole("button", { name: "查看用户 developer" }));
    expect((screen.getByRole("button", { name: "重置密码" }) as HTMLButtonElement).disabled).toBe(true);
    expect(execute).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole("button", { name: "完成审阅" })).toBeNull();
    await user.click(screen.getByRole("button", { name: "查询原请求结果" }));
    expect(await screen.findByText("原重置请求已确认提交")).toBeTruthy();
    expect(readPasswordResetCompletion).toHaveBeenCalledTimes(1);
    await user.click(screen.getByRole("button", { name: "完成审阅" }));
    expect(screen.queryByText("重置密码结果尚未确认")).toBeNull();
    expect((screen.getByRole("button", { name: "重置密码" }) as HTMLButtonElement).disabled).toBe(false);
    expect(execute).toHaveBeenCalledTimes(1);
    expect(sessionStorage.length).toBe(0);
  });

  it.each(["same-identity", "foreign", "malformed"])("restores only a same-identity live reset reminder after reload: %s record", async (recordKind) => {
    const execute = vi.fn(async (_credential: string, command: { kind: string }) => {
      if (command.kind === "reset-password") throw new Error("connection lost after dispatch");
    });
    const repository = accounts({ execute });
    const first = await openAccess(repository);
    await first.user.click(await screen.findByRole("button", { name: "查看用户 developer" }));
    await first.user.click(screen.getByRole("button", { name: "重置密码" }));
    await first.user.type(screen.getByLabelText(/^初始密码/), "Reset-Only-Test-Password-74!");
    await first.user.click(screen.getByRole("button", { name: "审阅重置" }));
    await first.user.click(screen.getByRole("button", { name: "确认重置密码" }));
    expect(await screen.findByText("重置密码结果尚未确认")).toBeTruthy();
    const key = sessionStorage.key(0)!;
    const record = JSON.parse(sessionStorage.getItem(key)!);
    first.view.unmount();

    if (recordKind === "foreign") sessionStorage.setItem(key, JSON.stringify({ ...record, actorId: "different-actor" }));
    if (recordKind === "malformed") sessionStorage.setItem(key, "{not-json");
    const resumed = await openAccess(repository);
    if (recordKind === "same-identity") {
      expect(await screen.findByText("重置密码结果尚未确认")).toBeTruthy();
      expect(screen.getByText(/本地提醒丢失也不能证明结果/)).toBeTruthy();
    } else expect(screen.queryByText("重置密码结果尚未确认")).toBeNull();
    expect(execute).toHaveBeenCalledTimes(1);
    resumed.view.unmount();
  });

  it("treats an explicit reset version conflict as rejected, not an unconfirmed outcome", async () => {
    const execute = vi.fn(async (_credential: string, command: { kind: string }) => {
      if (command.kind === "reset-password") throw new HttpProblem(409, "IAM_CONFLICT");
    });
    const { user } = await openAccess(accounts({ execute }));
    await user.click(await screen.findByRole("button", { name: "查看用户 developer" }));
    await user.click(screen.getByRole("button", { name: "重置密码" }));
    await user.type(screen.getByLabelText(/^初始密码/), "Reset-Only-Test-Password-74!");
    await user.click(screen.getByRole("button", { name: "审阅重置" }));
    await user.click(screen.getByRole("button", { name: "确认重置密码" }));
    await waitFor(() => expect(screen.getAllByText(/资源已变化/).length).toBeGreaterThan(0));
    expect(screen.queryByText("重置密码结果尚未确认")).toBeNull();
    expect(execute).toHaveBeenCalledTimes(1);
  });

  it("keeps an uncertain direct revocation query-only across IAM routes", async () => {
    const revokePolicyAttachment = vi.fn().mockRejectedValue(new Error("connection lost after commit"));
    const { user, repository } = await openAccess(accounts({ revokePolicyAttachment }));
    await user.click(await screen.findByRole("button", { name: "查看用户 developer" }));
    await user.click(screen.getByRole("button", { name: "撤销策略 ReadOnlyAccess" }));
    const review = screen.getByRole("region", { name: "确认撤销直接关联" });
    expect(within(review).getByText(/仅撤销该子用户的这条直接关联/)).toBeTruthy();
    expect((screen.getByRole("button", { name: "撤销策略 ReadOnlyAccess" }) as HTMLButtonElement).disabled).toBe(true);
    await user.click(within(review).getByRole("button", { name: "确认撤销" }));
    await screen.findByRole("button", { name: "检查原请求结果" });
    const original = revokePolicyAttachment.mock.calls[0]!;
    expect(original).toEqual([credential, "attachment-child-a-system.paas-viewer", {
      resourceVersion: 1, requestId: expect.stringMatching(/^ui-user-revocation-/)
    }]);
    expect(screen.getByText(/当前关系目录不能证明这次请求是否完成/)).toBeTruthy();

    await user.click(screen.getByTestId("nav-policies"));
    expect(screen.queryByRole("region", { name: "确认撤销直接关联" })).toBeNull();
    await user.click(screen.getByTestId("nav-users"));
    await user.click(await screen.findByRole("button", { name: "查看用户 developer" }));
    const recovered = screen.getByRole("region", { name: "确认撤销直接关联" });
    expect(within(recovered).getByText((content) => content.includes(original[2].requestId))).toBeTruthy();
    expect(revokePolicyAttachment).toHaveBeenCalledTimes(1);
    expect(within(recovered).getByRole("button", { name: "检查原请求结果" })).toBeTruthy();
    expect(within(recovered).queryByRole("button", { name: "原请求重试" })).toBeNull();
    expect(repository.execute).not.toHaveBeenCalled();
  });

  it("confirms an uncertain direct revocation only from the original immutable completion", async () => {
    const revokePolicyAttachment = vi.fn().mockRejectedValue(new Error("connection lost after commit"));
    const readPolicyAttachmentChange = vi.fn(async (_credential: string, expected: PolicyAttachmentChangeExpectation) => {
      if (expected.operation !== "REVOKE") throw new Error("unexpected operation");
      return {
        operation: "REVOKE" as const,
        accountId: expected.accountId,
        actorPrincipalId: expected.actorPrincipalId,
        requestId: expected.requestId,
        completedAt: timestamp,
        attachmentId: expected.attachmentId,
        expectedResourceVersion: expected.expectedResourceVersion,
        revocation: { id: expected.attachmentId, resourceVersion: expected.expectedResourceVersion + 1, revokedAt: timestamp }
      };
    });
    const { user } = await openAccess(accounts({ revokePolicyAttachment, readPolicyAttachmentChange }));
    await user.click(await screen.findByRole("button", { name: "查看用户 developer" }));
    await user.click(screen.getByRole("button", { name: "撤销策略 ReadOnlyAccess" }));
    await user.click(screen.getByRole("button", { name: "确认撤销" }));
    await user.click(await screen.findByRole("button", { name: "检查原请求结果" }));
    expect(await screen.findByText("原策略关联命令已确认")).toBeTruthy();
    const originalRequestId = revokePolicyAttachment.mock.calls[0]?.[2].requestId;
    const receipt = within(screen.getByRole("status", { name: "原策略关联命令已确认" }));
    expect(receipt.getByText(originalRequestId)).toBeTruthy();
    expect(receipt.getByText(childUser.id)).toBeTruthy();
    expect(receipt.getByText(tenantPolicy.id)).toBeTruthy();
    expect(receipt.getByText("attachment-child-a-system.paas-viewer")).toBeTruthy();
    expect(readPolicyAttachmentChange).toHaveBeenCalledWith(credential, {
      operation: "REVOKE", accountId: account.id, actorPrincipalId: rootUser.id,
      requestId: expect.stringMatching(/^ui-user-revocation-[0-9a-f]{32}$/),
      attachmentId: "attachment-child-a-system.paas-viewer", expectedResourceVersion: 1
    });
    expect(revokePolicyAttachment).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole("button", { name: "原请求重试" })).toBeNull();
    expect(sessionStorage.length).toBe(1);
    const finish = screen.getByRole("button", { name: "完成并重新读取" }) as HTMLButtonElement;
    await waitFor(() => expect(finish.disabled).toBe(false));
    await user.click(finish);
    await waitFor(() => expect(screen.queryByText("原策略关联命令已确认")).toBeNull());
    expect(sessionStorage.length).toBe(0);
  });

  it("closes a conflicting direct revocation intent without claiming the attachment was removed", async () => {
    const revokePolicyAttachment = vi.fn().mockRejectedValue(new HttpProblem(409, "IAM_CONFLICT"));
    const { user } = await openAccess(accounts({ revokePolicyAttachment }));
    await user.click(await screen.findByRole("button", { name: "查看用户 developer" }));
    await user.click(screen.getByRole("button", { name: "撤销策略 ReadOnlyAccess" }));
    await user.click(screen.getByRole("button", { name: "确认撤销" }));
    const review = screen.getByRole("region", { name: "确认撤销直接关联" });
    await within(review).findByText(/未完成可信确认/);
    expect(within(review).queryByRole("button", { name: "原请求重试" })).toBeNull();
    expect(within(review).queryByRole("button", { name: "确认撤销" })).toBeNull();
    expect(within(review).queryByRole("button", { name: "检查原请求结果" })).toBeNull();
    await user.click(within(review).getByRole("button", { name: "结束原意图并重新读取" }));
    await waitFor(() => expect(screen.queryByRole("region", { name: "确认撤销直接关联" })).toBeNull());
    expect(revokePolicyAttachment).toHaveBeenCalledTimes(1);
  });

  it.each(["identity", "directory", "principal", "root-directory"])("fails closed on a mismatched %s instead of showing another subject", async (mismatch) => {
    const other = structuredClone(identity);
    if (mismatch === "identity") other.account.id = "tenant-b";
    if (mismatch === "principal") other.user.id = "other-principal";
    const foreignUser: User = { ...child.user, accountId: "tenant-b", displayName: "PRIVATE OTHER USER" };
    const directoryUser = mismatch === "root-directory"
      ? { user: rootUser, policyAttachments: [], capabilities: userCapabilities(rootUser, [], "ROOT_IDENTITY_PROTECTED") }
      : { user: foreignUser, policyAttachments: [], capabilities: userCapabilities(foreignUser) };
    const repository = accounts({ currentIdentity: vi.fn().mockResolvedValue(other), ...(["directory", "root-directory"].includes(mismatch) ? { listUsers: vi.fn().mockResolvedValue({ items: [directoryUser], nextAfter: null }) } : {}) });
    await openAccess(repository);
    const failedDirectory = mismatch === "directory" || mismatch === "root-directory";
    if (failedDirectory) expect(await screen.findByText("用户目录暂时不可用")).toBeTruthy();
    else expect((await screen.findByRole("alert")).textContent).toContain("暂时不可用");
    expect(screen.queryByText("PRIVATE OTHER USER")).toBeNull();
    expect(screen.queryByRole("table", { name: "租户用户列表" })).toBeNull();
    if (!failedDirectory) expect(screen.queryByRole("button", { name: "创建用户" })).toBeNull();
    expect(repository.execute).not.toHaveBeenCalled();
  });
});
