import { HttpProblem } from "@/infrastructure/http/jsonRequest";
import type {
  Account,
  AccountAccess,
  AccountCommand,
  AccountIdentity,
  AccountPolicy,
  ActionCapability,
  AuthorizationProfileEntry,
  CapabilityRestriction,
  DirectoryPage,
  Group,
  GroupAccess,
  GroupDeletion,
  GroupMembership,
  GroupMembershipAccess,
  GroupMembershipPage,
  GroupPolicyAttachment,
  IamAction,
  PolicyAttachmentRevocation,
  PolicyDirectory,
  PolicyScope,
  User,
  UserAccess,
  UserPolicyAttachment
} from "../domain/accounts";
import { enterprisePrincipalId, previewUserPrincipalId, type AccessWorkspace } from "../domain/accessWorkspace";
import { AccessWorkspaceError } from "../domain/accessWorkspaceError";
import { applyUserBatch } from "../domain/userBatch";
import type { LoginResult, OtherSessionsRevocation, OwnSessionRevocation, SessionSummary } from "../domain/session";
import type { AccountRepository, IamRepository } from "./iamRepository";
import { createPreviewAccessWorkspace } from "./previewAccessWorkspace";

export const previewCredential = "matrix-ux-preview-memory-only";
const previewPassword = "demo-password";
const previewRecoveryCodes = ["MTRX-RECOVER-01", "MTRX-RECOVER-02"] as const;
const previewAt = "2026-09-08T09:00:00Z";
const previewSessionObservedAt = "2026-09-18T12:00:00Z";

// This exact-shaped sample lets the DEV console exercise the catalog UX while
// remaining visibly isolated from IAM's trusted registry and digests.
const previewAuthorizationProfiles: AuthorizationProfileEntry[] = [
  {
    profile: {
      product: "iam", revision: 1, callingService: "IAM", actions: [
        { action: "iam.group.create", resourceKind: "ACCOUNT", scope: "TENANT", resourceShapes: [{ mode: "INSTANCE", prefixAllowed: false }],
          conditions: [
            { key: "iam.account-id", valueType: "STRING", source: "IAM_AUTHENTICATED_IDENTITY" },
            { key: "iam.current-time", valueType: "TIME", source: "IAM_TRANSACTION_TIME" },
            { key: "iam.principal-id", valueType: "STRING", source: "IAM_AUTHENTICATED_IDENTITY" }
          ], resultResourceKind: "GROUP" },
        { action: "iam.policy.list", resourceKind: "ACCOUNT", scope: "TENANT", resourceShapes: [{ mode: "INSTANCE", prefixAllowed: false }],
          conditions: [
            { key: "iam.account-id", valueType: "STRING", source: "IAM_AUTHENTICATED_IDENTITY" },
            { key: "iam.current-time", valueType: "TIME", source: "IAM_TRANSACTION_TIME" },
            { key: "iam.principal-id", valueType: "STRING", source: "IAM_AUTHENTICATED_IDENTITY" }
          ] },
        { action: "iam.user.create", resourceKind: "ACCOUNT", scope: "TENANT", resourceShapes: [{ mode: "INSTANCE", prefixAllowed: false }],
          conditions: [
            { key: "iam.account-id", valueType: "STRING", source: "IAM_AUTHENTICATED_IDENTITY" },
            { key: "iam.current-time", valueType: "TIME", source: "IAM_TRANSACTION_TIME" },
            { key: "iam.principal-id", valueType: "STRING", source: "IAM_AUTHENTICATED_IDENTITY" }
          ], resultResourceKind: "USER" }
      ]
    },
    contentDigest: `sha256:${"1".repeat(64)}`
  },
  {
    profile: {
      product: "managedservice", revision: 1, callingService: "PAAS", actions: [
        { action: "managedservice.installation.create", resourceKind: "SERVICE_INSTALLATION", scope: "TENANT",
          resourceShapes: [{ mode: "COLLECTION", prefixAllowed: false, collectionUsage: "COLLECTION_CREATE" }],
          conditions: [
            { key: "iam.account-id", valueType: "STRING", source: "IAM_AUTHENTICATED_IDENTITY" },
            { key: "iam.current-time", valueType: "TIME", source: "IAM_TRANSACTION_TIME" },
            { key: "iam.principal-id", valueType: "STRING", source: "IAM_AUTHENTICATED_IDENTITY" }
          ], resultResourceKind: "SERVICE_INSTALLATION" },
        { action: "managedservice.installation.read", resourceKind: "SERVICE_INSTALLATION", scope: "TENANT",
          resourceShapes: [{ mode: "INSTANCE", prefixAllowed: false }, { mode: "COLLECTION", prefixAllowed: false, collectionUsage: "COLLECTION_LIST" }],
          conditions: [
            { key: "iam.account-id", valueType: "STRING", source: "IAM_AUTHENTICATED_IDENTITY" },
            { key: "iam.current-time", valueType: "TIME", source: "IAM_TRANSACTION_TIME" },
            { key: "iam.principal-id", valueType: "STRING", source: "IAM_AUTHENTICATED_IDENTITY" }
          ] }
      ]
    },
    contentDigest: `sha256:${"2".repeat(64)}`
  },
  {
    profile: {
      product: "paas", revision: 1, callingService: "PAAS", actions: [
        { action: "paas.application.create", resourceKind: "APPLICATION", scope: "TENANT",
          resourceShapes: [{ mode: "COLLECTION", prefixAllowed: false, collectionUsage: "COLLECTION_CREATE" }],
          conditions: [
            { key: "iam.account-id", valueType: "STRING", source: "IAM_AUTHENTICATED_IDENTITY" },
            { key: "iam.current-time", valueType: "TIME", source: "IAM_TRANSACTION_TIME" },
            { key: "iam.principal-id", valueType: "STRING", source: "IAM_AUTHENTICATED_IDENTITY" }
          ], resultResourceKind: "APPLICATION" },
        { action: "paas.application.read", resourceKind: "APPLICATION", scope: "TENANT",
          resourceShapes: [{ mode: "INSTANCE", prefixAllowed: true }],
          conditions: [
            { key: "iam.account-id", valueType: "STRING", source: "IAM_AUTHENTICATED_IDENTITY" },
            { key: "iam.current-time", valueType: "TIME", source: "IAM_TRANSACTION_TIME" },
            { key: "iam.principal-id", valueType: "STRING", source: "IAM_AUTHENTICATED_IDENTITY" }
          ] },
        { action: "paas.execution-target.register", resourceKind: "EXECUTION_TARGET", scope: "INSTALLATION",
          resourceShapes: [{ mode: "INSTANCE", prefixAllowed: false }], resultResourceKind: "EXECUTION_TARGET" }
      ]
    },
    contentDigest: `sha256:${"3".repeat(64)}`
  }
];

let account: Account = {
  id: "org-xiak",
  displayName: "Xiak 科技",
  status: "ACTIVE",
  rootIdentity: { principalId: "principal-admin", loginName: "admin" },
  loginAlias: "xiak-cloud",
  resourceVersion: 7
};

let users: User[] = [
  {
    id: "principal-lin", accountId: "org-xiak", loginName: "lin", displayName: "林工程师", status: "ACTIVE", mustChangePassword: false, resourceVersion: 3
  },
  {
    id: "principal-chen", accountId: "org-xiak", loginName: "chen", displayName: "陈审计员", status: "ACTIVE", mustChangePassword: false, resourceVersion: 2
  },
  ...[
    { loginName: "qiao", displayName: "乔发布工程师" },
    { loginName: "wu", displayName: "吴新同事" }
  ].map(({ loginName, displayName }) => ({
    id: `principal-${loginName}`, accountId: "org-xiak", loginName, displayName, status: "ACTIVE" as const, mustChangePassword: false, resourceVersion: 1
  }))
];

let accounts: Account[] = [
  account,
  {
    id: "org-sandbox",
    displayName: "体验沙箱",
    status: "ACTIVE",
    rootIdentity: { principalId: "principal-sandbox-admin", loginName: "sandbox-admin" },
    loginAlias: "sandbox",
    resourceVersion: 1
  }
];
let userPlatformPolicies: Record<string, string[]> = {};
const previewGroupVersions = new Map<string, { resourceVersion: number; updatedAt: string }>();
const previewMemberships = new Map<string, GroupMembership>();
const previewGroupAttachments = new Map<string, GroupPolicyAttachment>();
const initialPreviewSessions: SessionSummary[] = [
  {
    id: "session-ux-preview",
    organizationId: "org-xiak",
    principalId: "principal-admin",
    status: "ACTIVE",
    issuedAt: "2026-09-07T01:00:00Z",
    expiresAt: "2099-09-07T01:00:00Z"
  },
  {
    id: "session-ux-preview-002",
    organizationId: "org-xiak",
    principalId: "principal-admin",
    status: "ACTIVE",
    issuedAt: "2026-09-08T03:30:00Z",
    expiresAt: "2099-09-08T03:30:00Z"
  },
  {
    id: "session-ux-preview-003",
    organizationId: "org-xiak",
    principalId: "principal-admin",
    status: "ACTIVE",
    issuedAt: "2026-09-12T10:15:00Z",
    expiresAt: "2099-09-12T10:15:00Z"
  }
];
let previewOwnSessions = structuredClone(initialPreviewSessions);
const previewOwnSessionReplays = new Map<string, { targetSessionId: string; result: OwnSessionRevocation }>();
const previewOtherSessionReplays = new Map<string, OtherSessionsRevocation>();

let activePreviewCredential: string | null = null;
let activeRecoveryChallenge: string | null = null;
let activeLoginChallenge: { id: string; credential: string; nextStep: "TOTP" | "PASSWORD_CHANGE" } | null = null;
const consumedRecoveryCodes = new Set<string>();

export function isPreviewCredential(credential: string): boolean {
  // Browser sessions receive a fresh opaque value so a superseded bearer
  // cannot be reused. The stable fixture is accepted only by unit tests.
  return credential === activePreviewCredential
    || (process.env.NODE_ENV === "test" && credential === previewCredential);
}

function requirePreviewCredential(credential: string): void {
  if (!isPreviewCredential(credential)) throw new HttpProblem(401, "PREVIEW_SESSION_EXPIRED");
}

function invalidateActivePreviewCredential(credential?: string): void {
  if (!credential || credential === activePreviewCredential) activePreviewCredential = null;
}

function requirePreviewAccount(accountId: string): void {
  if (accountId !== account.id) throw new HttpProblem(403, "PREVIEW_ACCOUNT_UNAVAILABLE");
}

function requireRequestId(requestId: string): void {
  if (!requestId.trim()) throw new HttpProblem(422, "PREVIEW_REQUEST_ID_REQUIRED");
}

function clearPreviewGroupContractState(): void {
  previewGroupVersions.clear();
  previewMemberships.clear();
  previewGroupAttachments.clear();
}

function resetPreviewOwnSessions(): void {
  previewOwnSessions = structuredClone(initialPreviewSessions);
  previewOwnSessionReplays.clear();
  previewOtherSessionReplays.clear();
}

const initialPreviewState = structuredClone({ account, users, accounts, userPlatformPolicies });
const workspace = createPreviewAccessWorkspace(account.id, () => users.map((user) => user.id), account.rootIdentity.principalId);
let previewLoginVerified = false;

export function previewPersonalMfaSnapshot() {
  return workspace.snapshot().personalMfa;
}

export function preparePreviewPersonalMfaDemo() {
  const current = workspace.snapshot().personalMfa;
  if (current.factorState === "never-bound") {
    workspace.transact((source) => ({ workspace: { ...source, personalMfa: { factorState: "bound", reauthenticationRequired: false, recoveryState: "idle" } } }));
  }
  return workspace.snapshot().personalMfa;
}

export function nextPreviewPersonalMfaRecoveryCode(): string | null {
  return previewRecoveryCodes.find((code) => !consumedRecoveryCodes.has(code)) ?? null;
}

export async function beginPreviewPersonalMfaRecovery(password: string, recoveryCode: string): Promise<string | null> {
  try {
    if (password !== previewPassword || !previewRecoveryCodes.includes(recoveryCode as typeof previewRecoveryCodes[number]) || consumedRecoveryCodes.has(recoveryCode)) return null;
    const state = workspace.snapshot().personalMfa;
    if (state.recoveryState === "idle") await workspace.execute(previewCredential, { kind: "begin-personal-mfa-recovery" });
    else if (state.recoveryState !== "rebind-required") return null;
    consumedRecoveryCodes.add(recoveryCode);
    activeRecoveryChallenge = `preview-mfa-recovery-${crypto.randomUUID()}`;
    return activeRecoveryChallenge;
  } catch {
    return null;
  }
}

export function cancelPreviewPersonalMfaRecovery(challenge: string): void {
  if (challenge === activeRecoveryChallenge) activeRecoveryChallenge = null;
}

export async function confirmPreviewPersonalMfaRecovery(challenge: string): Promise<boolean> {
  try {
    if (!challenge || challenge !== activeRecoveryChallenge) return false;
    await workspace.execute(previewCredential, { kind: "confirm-personal-mfa" });
    activeRecoveryChallenge = null;
    invalidateActivePreviewCredential();
    return true;
  } catch {
    return false;
  }
}

export async function completePreviewPersonalMfaLogin(): Promise<boolean> {
  const state = workspace.snapshot().personalMfa;
  try {
    if (state.factorState !== "never-bound") await workspace.execute(previewCredential, { kind: "complete-personal-mfa-reauthentication" });
    previewLoginVerified = true;
    return true;
  } catch {
    return false;
  }
}

export function resetPreviewEnvironment(): void {
  previewLoginVerified = false;
  activePreviewCredential = null;
  activeRecoveryChallenge = null;
  activeLoginChallenge = null;
  consumedRecoveryCodes.clear();
  workspace.reset();
  const initial = structuredClone(initialPreviewState);
  account = initial.account;
  users = initial.users;
  accounts = initial.accounts;
  userPlatformPolicies = initial.userPlatformPolicies;
  clearPreviewGroupContractState();
  resetPreviewOwnSessions();
}

function loginResult(credential: string): LoginResult {
  return {
    outcome: "AUTHENTICATED",
    credential,
    mustChangePassword: false,
    session: {
      id: "session-ux-preview",
      organizationId: account.id,
      principalId: account.rootIdentity.principalId,
      status: "ACTIVE",
      issuedAt: "2026-09-07T01:00:00Z",
      expiresAt: "2099-09-07T01:00:00Z"
    }
  };
}

export const previewIamRepository: IamRepository = {
  async login() {
    const mfa = workspace.snapshot().personalMfa;
    if ((mfa.factorState !== "never-bound" || mfa.recoveryState !== "idle") && !previewLoginVerified) {
      activePreviewCredential = null;
      activeLoginChallenge = {
        id: `preview-login-challenge-${crypto.randomUUID()}`,
        credential: `preview-challenge-${crypto.randomUUID()}`,
        nextStep: "TOTP"
      };
      return {
        outcome: "CHALLENGE_REQUIRED",
        challenge: {
          id: activeLoginChallenge.id,
          purpose: "LOGIN",
          nextStep: "TOTP",
          expiresAt: new Date(Date.now() + 5 * 60_000).toISOString()
        },
        challengeCredential: activeLoginChallenge.credential
      };
    }
    previewLoginVerified = false;
    activePreviewCredential = `matrix-ux-preview-${crypto.randomUUID()}`;
    return loginResult(activePreviewCredential);
  },
  authenticationChallenges: {
    async verify(command) {
      if (!activeLoginChallenge || activeLoginChallenge.nextStep !== "TOTP"
          || command.challengeId !== activeLoginChallenge.id
          || command.challengeCredential !== activeLoginChallenge.credential) {
        throw new HttpProblem(409, "PREVIEW_CHALLENGE_EXPIRED");
      }
      if (command.code !== "624810" && command.code !== "624811") {
        throw new HttpProblem(401, "PREVIEW_CHALLENGE_INVALID_CODE");
      }
      if (command.code === "624811") {
        activeLoginChallenge = {
          id: `preview-password-challenge-${crypto.randomUUID()}`,
          credential: `preview-challenge-${crypto.randomUUID()}`,
          nextStep: "PASSWORD_CHANGE"
        };
        return {
          outcome: "CHALLENGE_REQUIRED",
          challenge: {
            id: activeLoginChallenge.id,
            purpose: "LOGIN",
            nextStep: "PASSWORD_CHANGE",
            expiresAt: new Date(Date.now() + 5 * 60_000).toISOString()
          },
          challengeCredential: activeLoginChallenge.credential
        };
      }
      activeLoginChallenge = null;
      activePreviewCredential = `matrix-ux-preview-${crypto.randomUUID()}`;
      return loginResult(activePreviewCredential);
    },
    async changePassword(command) {
      if (!activeLoginChallenge || activeLoginChallenge.nextStep !== "PASSWORD_CHANGE"
          || command.challengeId !== activeLoginChallenge.id
          || command.challengeCredential !== activeLoginChallenge.credential) {
        throw new HttpProblem(409, "PREVIEW_CHALLENGE_EXPIRED");
      }
      if (command.newPassword.length < 12) throw new HttpProblem(422, "PREVIEW_PASSWORD_POLICY");
      activeLoginChallenge = null;
      activePreviewCredential = null;
      return { nextStep: "REAUTHENTICATE", changedAt: new Date().toISOString() };
    }
  },
  async changePassword(credential) { requirePreviewCredential(credential); },
  async logout(credential) {
    requirePreviewCredential(credential);
    invalidateActivePreviewCredential(credential);
    previewLoginVerified = false;
  },
  sessions: {
    async list(credential, after) {
      requirePreviewCredential(credential);
      if (after !== undefined) throw new HttpProblem(422, "PREVIEW_SESSION_CURSOR_UNAVAILABLE");
      return {
        accountId: account.id,
        userId: account.rootIdentity.principalId,
        currentSessionId: "session-ux-preview",
        observedAt: previewSessionObservedAt,
        items: structuredClone(previewOwnSessions).sort((left, right) => left.id.localeCompare(right.id)),
        nextCursor: null
      };
    },
    async revoke(credential, targetSessionId, requestId) {
      requirePreviewCredential(credential);
      requireRequestId(requestId);
      if (targetSessionId === "session-ux-preview") throw new HttpProblem(409, "CURRENT_SESSION_REQUIRES_LOGOUT");
      const replay = previewOwnSessionReplays.get(requestId);
      if (replay) {
        if (replay.targetSessionId !== targetSessionId) throw new HttpProblem(409, "REQUEST_ID_CONFLICT");
        return structuredClone({ ...replay.result, outcome: "EQUAL_REPLAY" as const });
      }
      if (!previewOwnSessions.some((session) => session.id === targetSessionId)) {
        throw new HttpProblem(409, "SESSION_NOT_REVOCABLE");
      }
      const result: OwnSessionRevocation = {
        outcome: "APPLIED",
        revocation: {
          id: targetSessionId,
          resourceVersion: 2,
          revokedAt: previewSessionObservedAt
        }
      };
      previewOwnSessions = previewOwnSessions.filter((session) => session.id !== targetSessionId);
      previewOwnSessionReplays.set(requestId, { targetSessionId, result: structuredClone(result) });
      return structuredClone(result);
    },
    async revokeOthers(credential, requestId) {
      requirePreviewCredential(credential);
      requireRequestId(requestId);
      const replay = previewOtherSessionReplays.get(requestId);
      if (replay) return structuredClone({ ...replay, outcome: "EQUAL_REPLAY" as const });
      const currentSessionId = "session-ux-preview";
      const revokedCount = previewOwnSessions.filter((session) => session.id !== currentSessionId).length;
      const result: OtherSessionsRevocation = {
        outcome: "APPLIED",
        accountId: account.id,
        userId: account.rootIdentity.principalId,
        currentSessionId,
        requestId,
        revokedCount,
        completedAt: previewSessionObservedAt
      };
      previewOwnSessions = previewOwnSessions.filter((session) => session.id === currentSessionId);
      previewOtherSessionReplays.set(requestId, structuredClone(result));
      return structuredClone(result);
    }
  }
};

function policyAttachment(principalId: string, policyId: string, scope: PolicyScope = "TENANT"): UserPolicyAttachment {
  return {
    id: `attachment-${principalId}-${policyId}`,
    accountId: account.id,
    target: { kind: "USER", id: principalId },
    policyId,
    scope,
    installationId: scope === "INSTALLATION" ? "matrix-preview" : null,
    resourceVersion: 1,
    createdAt: previewAt,
    updatedAt: previewAt
  };
}

function capability(
  action: IamAction,
  kind: ActionCapability["resource"]["kind"],
  id: string,
  restrictionReason: CapabilityRestriction | null = null
): ActionCapability {
  return { action, resource: { kind, id }, available: restrictionReason === null, restrictionReason };
}

function rootUser(): User {
  return {
    id: account.rootIdentity.principalId,
    accountId: account.id,
    loginName: account.rootIdentity.loginName,
    displayName: "平台管理员",
    status: "ACTIVE",
    mustChangePassword: false,
    resourceVersion: 5
  };
}

function currentIdentity(): AccountIdentity {
  const user = rootUser();
  return {
    account,
    user,
    identityKind: "ROOT_IDENTITY",
    policySources: [],
    permissionBoundary: { accountId: account.id, userId: user.id, resourceVersion: user.resourceVersion, policy: null },
    capabilities: [
      capability("iam.account.create", "ACCOUNT", "collection"),
      capability("iam.account.read", "ACCOUNT", "collection"),
      capability("iam.account.alias-set", "ACCOUNT", account.id),
      capability("iam.user.list", "ACCOUNT", account.id),
      capability("iam.user.create", "ACCOUNT", account.id),
      capability("iam.policy.list", "ACCOUNT", account.id),
      capability("iam.group.list", "ACCOUNT", account.id),
      capability("iam.group.create", "ACCOUNT", account.id)
    ],
  };
}

function page<T>(items: T[]): DirectoryPage<T> {
  return { items: structuredClone(items), nextAfter: null };
}

function updateUser(userId: string, update: (user: User) => User): void {
  users = users.map((user) => user.id === userId ? update(user) : user);
}

function tenantPolicyDirectory(source: AccessWorkspace): PolicyDirectory {
  const items: AccountPolicy[] = source.policies.map((policy): AccountPolicy => ({
    id: policy.id,
    management: policy.kind === "system" ? "SYSTEM" : "CUSTOMER",
    accountId: policy.kind === "system" ? null : account.id,
    displayName: policy.name,
    scope: "TENANT",
    status: "ACTIVE",
    defaultVersionId: String(policy.defaultVersion),
    resourceVersion: Math.max(1, policy.lastVersion),
    createdAt: policy.createdAt,
    updatedAt: policy.updatedAt
  })).sort((left, right) => left.id.localeCompare(right.id));
  return { accountId: account.id, scope: "TENANT", installationId: null, items };
}

function platformPolicyDirectory(): PolicyDirectory {
  return {
    accountId: account.id,
    scope: "INSTALLATION",
    installationId: "matrix-preview",
    items: [{
      id: "system.matrix-installation-admin",
      management: "SYSTEM",
      accountId: null,
      displayName: "MatrixInstallationAdministrator",
      scope: "INSTALLATION",
      status: "ACTIVE",
      defaultVersionId: "1",
      resourceVersion: 1,
      createdAt: previewAt,
      updatedAt: previewAt
    }]
  };
}

function usersWithAttachments(source: AccessWorkspace): UserAccess[] {
  return users.map((user) => {
    const policyAttachments = [
      ...(source.userPolicies[user.id] ?? []).map((policyId) => policyAttachment(user.id, policyId)),
      ...(userPlatformPolicies[user.id] ?? []).map((policyId) => policyAttachment(user.id, policyId, "INSTALLATION"))
    ];
    const hasInstallationAuthority = policyAttachments.some((attachment) => attachment.scope === "INSTALLATION");
    return {
      user,
      policyAttachments,
      capabilities: [
      capability("iam.user.read", "USER", user.id),
      capability("iam.user.permission-boundary.set", "USER", user.id),
      capability("iam.user.permission-boundary.remove", "USER", user.id),
      capability("iam.user.update", "USER", user.id),
      capability("iam.user.delete", "USER", user.id,
        hasInstallationAuthority ? "INSTALLATION_AUTHORITY_PROTECTED" : user.status === "ACTIVE" ? "TARGET_MUST_BE_DISABLED" : null),
      capability("iam.user.set-status", "USER", user.id),
      capability("iam.user.reset-password", "USER", user.id),
      capability("iam.policy-attachment.create", "USER", user.id, user.status === "DISABLED" ? "TARGET_DISABLED" : null),
      capability("iam.platform-policy-attachment.create", "USER", user.id,
        user.status === "DISABLED" ? "TARGET_DISABLED" : user.mustChangePassword ? "TARGET_CREDENTIAL_CHANGE_REQUIRED" : null),
      ...policyAttachments.map((attachment) => capability(
        attachment.scope === "INSTALLATION" ? "iam.platform-policy-attachment.revoke" : "iam.policy-attachment.revoke",
        "POLICY_ATTACHMENT",
        attachment.id
      ))
      ].map((item) => hasInstallationAuthority && (item.action === "iam.user.set-status" || item.action === "iam.user.reset-password")
        ? { ...item, available: false, restrictionReason: "INSTALLATION_AUTHORITY_PROTECTED" as const }
        : item)
    };
  });
}

function accountsWithCapabilities(): AccountAccess[] {
  return accounts.map((entry) => ({
    account: entry,
    capabilities: [
      capability("iam.account.set-status", "ACCOUNT", entry.id, entry.id === account.id ? "SYSTEM_ACCOUNT_PROTECTED" : null),
      capability("iam.account.recover-root-credentials", "ACCOUNT", entry.id, entry.id === account.id ? "INSTALLATION_AUTHORITY_PROTECTED" : null)
    ]
  }));
}

type PreviewAccessGroup = AccessWorkspace["groups"][number];

function previewGroupMeta(group: PreviewAccessGroup): { resourceVersion: number; updatedAt: string } {
  const current = previewGroupVersions.get(group.id);
  if (current) return current;
  const initial = { resourceVersion: 1, updatedAt: group.createdAt };
  previewGroupVersions.set(group.id, initial);
  return initial;
}

function previewGroup(group: PreviewAccessGroup): Group {
  const metadata = previewGroupMeta(group);
  return {
    id: group.id,
    accountId: account.id,
    name: group.name,
    description: group.description,
    resourceVersion: metadata.resourceVersion,
    createdAt: group.createdAt,
    updatedAt: metadata.updatedAt
  };
}

function membershipKey(groupId: string, userId: string): string {
  return `${groupId}\u0000${userId}`;
}

function previewMembership(group: PreviewAccessGroup, userId: string): GroupMembership {
  const key = membershipKey(group.id, userId);
  const current = previewMemberships.get(key);
  if (current && current.removedAt === undefined) return current;
  const createdAt = group.createdAt;
  const membership: GroupMembership = {
    id: `preview-membership-${group.id}-${userId}`,
    accountId: account.id,
    groupId: group.id,
    userId,
    createdBy: account.rootIdentity.principalId,
    resourceVersion: 1,
    createdAt,
    updatedAt: createdAt
  };
  previewMemberships.set(key, membership);
  return membership;
}

function groupAttachmentKey(groupId: string, policyId: string): string {
  return `${groupId}\u0000${policyId}`;
}

function previewGroupAttachment(group: PreviewAccessGroup, policyId: string): GroupPolicyAttachment {
  const key = groupAttachmentKey(group.id, policyId);
  const current = previewGroupAttachments.get(key);
  if (current) return current;
  const attachment: GroupPolicyAttachment = {
    id: `preview-group-attachment-${group.id}-${policyId}`,
    accountId: account.id,
    target: { kind: "GROUP", id: group.id },
    policyId,
    scope: "TENANT",
    installationId: null,
    resourceVersion: 1,
    createdAt: group.createdAt,
    updatedAt: group.createdAt
  };
  previewGroupAttachments.set(key, attachment);
  return attachment;
}

const groupActions: IamAction[] = [
  "iam.group.read",
  "iam.group.update",
  "iam.group.delete",
  "iam.group-membership.list",
  "iam.group-membership.create",
  "iam.group-policy-attachment.create"
];

function previewGroupAccess(group: PreviewAccessGroup): GroupAccess {
  const policyAttachments = group.policyIds.map((policyId) => previewGroupAttachment(group, policyId));
  return {
    group: previewGroup(group),
    policyAttachments,
    capabilities: [
      ...groupActions.map((action) => capability(action, "GROUP", group.id)),
      ...policyAttachments.map((attachment) => capability("iam.group-policy-attachment.revoke", "POLICY_ATTACHMENT", attachment.id))
    ]
  };
}

function previewMembershipAccess(group: PreviewAccessGroup, userId: string): GroupMembershipAccess {
  const membership = previewMembership(group, userId);
  return {
    membership,
    capabilities: [capability("iam.group-membership.remove", "GROUP_MEMBERSHIP", membership.id)]
  };
}

function findPreviewGroup(source: AccessWorkspace, groupId: string): PreviewAccessGroup {
  const group = source.groups.find((entry) => entry.id === groupId);
  if (!group) throw new HttpProblem(404, "PREVIEW_GROUP_NOT_FOUND");
  return group;
}

function pageAfter<T>(items: T[], after: string | undefined, prefix: string, id: (item: T) => string): DirectoryPage<T> {
  const sorted = [...items].sort((left, right) => id(left).localeCompare(id(right)));
  let start = 0;
  if (after !== undefined) {
    if (!after.startsWith(prefix)) throw new HttpProblem(400, "PREVIEW_CURSOR_INVALID");
    const cursorId = after.slice(prefix.length);
    const cursorIndex = sorted.findIndex((item) => id(item) === cursorId);
    if (cursorIndex < 0) throw new HttpProblem(400, "PREVIEW_CURSOR_INVALID");
    start = cursorIndex + 1;
  }
  const result = sorted.slice(start, start + 100);
  const last = result.at(-1);
  return { items: structuredClone(result), nextAfter: start + result.length < sorted.length && last ? `${prefix}${id(last)}` : null };
}

function groupVersionChanged(group: PreviewAccessGroup, at: string): void {
  const current = previewGroupMeta(group);
  previewGroupVersions.set(group.id, { resourceVersion: current.resourceVersion + 1, updatedAt: at });
}

export const previewAccountRepository: AccountRepository = {
  async executeUserBatch(credential, command) {
    requirePreviewCredential(credential);
    const result = workspace.transact((source) => applyUserBatch(source, usersWithAttachments(source), currentIdentity(), command, { id: crypto.randomUUID(), at: new Date().toISOString(), canListUsers: true }));
    users = result.users.map((entry) => entry.user);
    return { workspace: result.workspace };
  },
  workspace: {
    async read(credential) { requirePreviewCredential(credential); return workspace.read(credential); },
    async execute(credential, command) {
      requirePreviewCredential(credential);
      if (command.kind === "create-subuser" && (users.some((user) => user.loginName === command.loginName) || account.rootIdentity.loginName === command.loginName)) throw new AccessWorkspaceError("duplicate");
      const result = await workspace.execute(credential, command);
      if (command.kind === "create-subuser") users.push({
        id: previewUserPrincipalId(command.loginName), accountId: account.id, loginName: command.loginName,
        displayName: command.displayName.trim(), status: "ACTIVE",
        mustChangePassword: command.profile.consoleAccess && command.profile.passwordResetRequired, resourceVersion: 1
      });
      if (command.kind === "import-enterprise-members") {
        for (const memberId of command.memberIds) {
          const principalId = enterprisePrincipalId(command.id, memberId);
          const member = result.workspace.enterpriseMembers.find((entry) => entry.id === memberId)!;
          if (!users.some((entry) => entry.id === principalId)) users.push({
            id: principalId, accountId: account.id, loginName: `wecom.${command.id.slice(0, 8)}.${memberId}`,
            displayName: member.name, status: "ACTIVE", mustChangePassword: false, resourceVersion: 1
          });
        }
      }
      if (command.kind === "delete-user") {
        users = users.filter((user) => user.id !== command.principalId);
        delete userPlatformPolicies[command.principalId];
      }
      if (command.kind === "update-user") updateUser(command.principalId, (user) => ({ ...user, displayName: command.displayName.trim(), resourceVersion: user.resourceVersion + 1 }));
      if (command.kind === "confirm-personal-mfa" || command.kind === "remove-personal-mfa") invalidateActivePreviewCredential(credential);
      return result;
    }
  },
  async currentIdentity(credential) {
    requirePreviewCredential(credential);
    return structuredClone(currentIdentity());
  },
  async listUsers(credential) {
    requirePreviewCredential(credential);
    return page(usersWithAttachments(await workspace.read(credential)));
  },
  async getUser(credential, userId) {
    requirePreviewCredential(credential);
    const access = usersWithAttachments(await workspace.read(credential)).find((entry) => entry.user.id === userId);
    if (!access) throw new HttpProblem(403, "PREVIEW_USER_UNAVAILABLE");
    return structuredClone(access);
  },
  async listPolicies(credential, platform) {
    requirePreviewCredential(credential);
    return structuredClone(platform ? platformPolicyDirectory() : tenantPolicyDirectory(await workspace.read(credential)));
  },
  async listAuthorizationProfiles(credential) {
    requirePreviewCredential(credential);
    return { accountId: account.id, items: structuredClone(previewAuthorizationProfiles) };
  },
  async listAccounts(credential) {
    requirePreviewCredential(credential);
    return page(accountsWithCapabilities());
  },
  async listGroups(credential, accountId, after) {
    requirePreviewCredential(credential);
    requirePreviewAccount(accountId);
    const source = await workspace.read(credential);
    return pageAfter(source.groups.map(previewGroupAccess), after, "preview-group:", (entry) => entry.group.id);
  },
  async getGroup(credential, accountId, groupId) {
    requirePreviewCredential(credential);
    requirePreviewAccount(accountId);
    return structuredClone(previewGroupAccess(findPreviewGroup(await workspace.read(credential), groupId)));
  },
  async createGroup(credential, accountId, command) {
    requirePreviewCredential(credential);
    requirePreviewAccount(accountId);
    requireRequestId(command.requestId);
    const before = await workspace.read(credential);
    const result = await workspace.execute(credential, { kind: "create-group", name: command.name, description: command.description ?? "" });
    const created = result.workspace.groups.find((entry) => !before.groups.some((previous) => previous.id === entry.id));
    if (!created) throw new Error("INVALID_PREVIEW_WORKSPACE");
    previewGroupVersions.set(created.id, { resourceVersion: 1, updatedAt: created.createdAt });
    return structuredClone(previewGroup(created));
  },
  async updateGroup(credential, accountId, groupId, command) {
    requirePreviewCredential(credential);
    requirePreviewAccount(accountId);
    requireRequestId(command.requestId);
    const source = await workspace.read(credential);
    const current = findPreviewGroup(source, groupId);
    if (previewGroupMeta(current).resourceVersion !== command.resourceVersion) throw new HttpProblem(409, "PREVIEW_GROUP_CHANGED");
    const changedAt = new Date().toISOString();
    const result = await workspace.execute(credential, { kind: "update-group", id: groupId, name: command.name, description: command.description ?? "" });
    const updated = findPreviewGroup(result.workspace, groupId);
    groupVersionChanged(updated, changedAt);
    return structuredClone(previewGroup(updated));
  },
  async deleteGroup(credential, accountId, groupId, command) {
    requirePreviewCredential(credential);
    requirePreviewAccount(accountId);
    requireRequestId(command.requestId);
    const source = await workspace.read(credential);
    const current = findPreviewGroup(source, groupId);
    const currentVersion = previewGroupMeta(current).resourceVersion;
    if (currentVersion !== command.resourceVersion) throw new HttpProblem(409, "PREVIEW_GROUP_CHANGED");
    const deletedAt = new Date().toISOString();
    await workspace.execute(credential, { kind: "delete-group", id: groupId });
    const receipt: GroupDeletion = {
      id: current.id,
      accountId,
      name: current.name,
      resourceVersion: currentVersion + 1,
      removedMemberships: current.memberIds.length,
      revokedPolicyAttachments: current.policyIds.length,
      deletedAt
    };
    previewGroupVersions.delete(groupId);
    for (const userId of current.memberIds) previewMemberships.delete(membershipKey(groupId, userId));
    for (const policyId of current.policyIds) previewGroupAttachments.delete(groupAttachmentKey(groupId, policyId));
    return receipt;
  },
  async listGroupMemberships(credential, accountId, groupId, after) {
    requirePreviewCredential(credential);
    requirePreviewAccount(accountId);
    const group = findPreviewGroup(await workspace.read(credential), groupId);
    const result = pageAfter(group.memberIds.map((userId) => previewMembershipAccess(group, userId)), after, `preview-membership:${groupId}:`, (entry) => entry.membership.id);
    const response: GroupMembershipPage = { accountId, groupId, ...result };
    return response;
  },
  async createGroupMembership(credential, accountId, groupId, command) {
    requirePreviewCredential(credential);
    requirePreviewAccount(accountId);
    requireRequestId(command.requestId);
    const source = await workspace.read(credential);
    const group = findPreviewGroup(source, groupId);
    if (!users.some((entry) => entry.id === command.userId)) throw new HttpProblem(404, "PREVIEW_USER_NOT_FOUND");
    if (group.memberIds.includes(command.userId)) throw new HttpProblem(409, "PREVIEW_MEMBERSHIP_EXISTS");
    const createdAt = new Date().toISOString();
    await workspace.execute(credential, { kind: "change-group-members", id: groupId, added: [command.userId], removed: [] });
    const membership: GroupMembership = {
      id: `preview-membership-${crypto.randomUUID()}`,
      accountId,
      groupId,
      userId: command.userId,
      createdBy: account.rootIdentity.principalId,
      resourceVersion: 1,
      createdAt,
      updatedAt: createdAt
    };
    previewMemberships.set(membershipKey(groupId, command.userId), membership);
    return structuredClone(membership);
  },
  async removeGroupMembership(credential, accountId, groupId, membershipId, command) {
    requirePreviewCredential(credential);
    requirePreviewAccount(accountId);
    requireRequestId(command.requestId);
    const group = findPreviewGroup(await workspace.read(credential), groupId);
    const current = group.memberIds.map((userId) => previewMembership(group, userId)).find((entry) => entry.id === membershipId);
    if (!current) throw new HttpProblem(404, "PREVIEW_MEMBERSHIP_NOT_FOUND");
    if (current.resourceVersion !== command.resourceVersion) throw new HttpProblem(409, "PREVIEW_MEMBERSHIP_CHANGED");
    const removedAt = new Date().toISOString();
    await workspace.execute(credential, { kind: "change-group-members", id: groupId, added: [], removed: [current.userId] });
    const removed: GroupMembership = {
      ...current,
      resourceVersion: current.resourceVersion + 1,
      updatedAt: removedAt,
      removedAt,
      removedBy: account.rootIdentity.principalId
    };
    previewMemberships.set(membershipKey(groupId, current.userId), removed);
    return structuredClone(removed);
  },
  async createGroupPolicyAttachment(credential, accountId, groupId, command) {
    requirePreviewCredential(credential);
    requirePreviewAccount(accountId);
    requireRequestId(command.requestId);
    const source = await workspace.read(credential);
    const group = findPreviewGroup(source, groupId);
    const policy = source.policies.find((entry) => entry.id === command.policyId);
    if (!policy) throw new HttpProblem(404, "PREVIEW_POLICY_NOT_FOUND");
    if (Math.max(1, policy.lastVersion) !== command.policyResourceVersion) throw new HttpProblem(409, "PREVIEW_POLICY_CHANGED");
    if (group.policyIds.includes(command.policyId)) throw new HttpProblem(409, "PREVIEW_ATTACHMENT_EXISTS");
    const createdAt = new Date().toISOString();
    await workspace.execute(credential, { kind: "change-group-policies", id: groupId, added: [command.policyId], removed: [] });
    const attachment: GroupPolicyAttachment = {
      id: `preview-group-attachment-${crypto.randomUUID()}`,
      accountId,
      target: { kind: "GROUP", id: groupId },
      policyId: command.policyId,
      scope: "TENANT",
      installationId: null,
      resourceVersion: 1,
      createdAt,
      updatedAt: createdAt
    };
    previewGroupAttachments.set(groupAttachmentKey(groupId, command.policyId), attachment);
    return structuredClone(attachment);
  },
  async revokePolicyAttachment(credential, attachmentId, command) {
    requirePreviewCredential(credential);
    requireRequestId(command.requestId);
    const source = await workspace.read(credential);
    for (const group of source.groups) {
      const match = group.policyIds
        .map((policyId) => ({ policyId, attachment: previewGroupAttachment(group, policyId) }))
        .find((entry) => entry.attachment.id === attachmentId);
      if (!match) continue;
      if (match.attachment.resourceVersion !== command.resourceVersion) throw new HttpProblem(409, "PREVIEW_ATTACHMENT_CHANGED");
      const revokedAt = new Date().toISOString();
      await workspace.execute(credential, { kind: "change-group-policies", id: group.id, added: [], removed: [match.policyId] });
      previewGroupAttachments.delete(groupAttachmentKey(group.id, match.policyId));
      const result: PolicyAttachmentRevocation = { id: attachmentId, resourceVersion: command.resourceVersion + 1, revokedAt };
      return result;
    }
    const userMatch = users.flatMap((user) => [
      ...(source.userPolicies[user.id] ?? []).map((policyId) => policyAttachment(user.id, policyId)),
      ...(userPlatformPolicies[user.id] ?? []).map((policyId) => policyAttachment(user.id, policyId, "INSTALLATION"))
    ]).find((attachment) => attachment.id === attachmentId);
    if (!userMatch) throw new HttpProblem(404, "PREVIEW_ATTACHMENT_NOT_FOUND");
    if (userMatch.resourceVersion !== command.resourceVersion) throw new HttpProblem(409, "PREVIEW_ATTACHMENT_CHANGED");
    await previewAccountRepository.execute(credential, { kind: "revoke-policy-attachment", attachmentId, resourceVersion: command.resourceVersion });
    return { id: attachmentId, resourceVersion: command.resourceVersion + 1, revokedAt: new Date().toISOString() };
  },
  async execute(credential, command: AccountCommand) {
    requirePreviewCredential(credential);
    if ((command.kind === "update-user" || command.kind === "delete-user" || command.kind === "set-status" || command.kind === "reset-password" || command.kind === "create-policy-attachment") && command.userId === account.rootIdentity.principalId) throw new HttpProblem(403, "ROOT_IDENTITY_PROTECTED");
    if (command.kind === "create-user") {
      if (users.some((user) => user.loginName === command.loginName) || account.rootIdentity.loginName === command.loginName) throw new HttpProblem(409, "PREVIEW_NAME_CONFLICT");
      if (!/^[a-z][a-z0-9._-]{2,63}$/.test(command.loginName) || !command.displayName.trim() || command.initialPassword.length < 14) throw new HttpProblem(422, "PREVIEW_INVALID_USER");
      users = [...users, {
        id: `principal-${command.loginName}`, accountId: account.id, loginName: command.loginName,
        displayName: command.displayName, status: "ACTIVE", mustChangePassword: true, resourceVersion: 1
      }];
      return;
    }
    if (command.kind === "create-account") {
      if (accounts.some((entry) => entry.id === command.id)) throw new HttpProblem(409, "PREVIEW_NAME_CONFLICT");
      accounts = [...accounts, {
        id: command.id, displayName: command.displayName, status: "ACTIVE",
        rootIdentity: { principalId: `principal-${command.id}-root`, loginName: command.rootLoginName },
        loginAlias: null, resourceVersion: 1
      }];
      return;
    }
    if (command.kind === "set-account-status") {
      const existing = accounts.find((entry) => entry.id === command.accountId);
      if (!existing || existing.resourceVersion !== command.resourceVersion) throw new HttpProblem(409, "PREVIEW_STALE_ACCOUNT");
      if (existing.id === account.id) throw new HttpProblem(403, "SYSTEM_ACCOUNT_PROTECTED");
      const next = { ...existing, status: command.status, resourceVersion: existing.resourceVersion + 1 };
      accounts = accounts.map((entry) => entry.id === command.accountId ? next : entry);
      return;
    }
    if (command.kind === "recover-root-credentials") {
      const existing = accounts.find((entry) => entry.id === command.accountId);
      if (!existing || existing.resourceVersion !== command.resourceVersion || command.initialPassword.length < 14) throw new HttpProblem(409, "PREVIEW_RECOVERY_CONFLICT");
      if (existing.id === account.id) throw new HttpProblem(403, "INSTALLATION_AUTHORITY_PROTECTED");
      const next = { ...existing, resourceVersion: existing.resourceVersion + 1 };
      accounts = accounts.map((entry) => entry.id === command.accountId ? next : entry);
      return;
    }
    if (command.kind === "set-alias") {
      account = { ...account, loginAlias: command.alias, resourceVersion: account.resourceVersion + 1 };
      accounts = accounts.map((entry) => entry.id === account.id ? account : entry);
      return;
    }
    if (command.kind === "update-user") {
      const existing = users.find((user) => user.id === command.userId);
      if (!existing || existing.resourceVersion !== command.resourceVersion) throw new HttpProblem(409, "PREVIEW_USER_CHANGED");
      if (!command.displayName.trim()) throw new HttpProblem(422, "PREVIEW_INVALID_USER");
      updateUser(command.userId, (user) => ({ ...user, displayName: command.displayName.trim(), resourceVersion: user.resourceVersion + 1 }));
      return;
    }
    if (command.kind === "delete-user") {
      const existing = users.find((user) => user.id === command.userId);
      if (!existing || existing.resourceVersion !== command.resourceVersion) throw new HttpProblem(409, "PREVIEW_USER_CHANGED");
      if (existing.status !== "DISABLED") throw new HttpProblem(409, "TARGET_MUST_BE_DISABLED");
      if ((userPlatformPolicies[existing.id] ?? []).length) throw new HttpProblem(403, "INSTALLATION_AUTHORITY_PROTECTED");
      await workspace.execute(credential, { kind: "delete-user", principalId: existing.id });
      users = users.filter((user) => user.id !== existing.id);
      delete userPlatformPolicies[existing.id];
      return;
    }
    if (command.kind === "set-status") {
      updateUser(command.userId, (user) => ({ ...user, status: command.status, resourceVersion: user.resourceVersion + 1 }));
      return;
    }
    if (command.kind === "reset-password") {
      updateUser(command.userId, (user) => ({ ...user, mustChangePassword: true, resourceVersion: user.resourceVersion + 1 }));
      return;
    }
    const snapshot = await workspace.read(credential);
    if (command.kind === "create-policy-attachment") {
      const tenantPolicy = snapshot.policies.find((entry) => entry.id === command.policyId);
      const platformPolicy = platformPolicyDirectory().items.find((entry) => entry.id === command.policyId);
      const user = users.find((entry) => entry.id === command.userId);
      const policy = tenantPolicy ?? platformPolicy;
      if (!policy || !user) throw new HttpProblem(403, "PREVIEW_UNKNOWN_POLICY_OR_USER");
      const resourceVersion = tenantPolicy ? Math.max(1, tenantPolicy.lastVersion) : platformPolicy!.resourceVersion;
      if (resourceVersion !== command.policyResourceVersion) throw new HttpProblem(409, "PREVIEW_POLICY_CHANGED");
      const selected = tenantPolicy ? snapshot.userPolicies[command.userId] ?? [] : userPlatformPolicies[command.userId] ?? [];
      if (selected.includes(command.policyId)) throw new HttpProblem(409, "PREVIEW_ATTACHMENT_EXISTS");
      if (tenantPolicy) await workspace.execute(credential, { kind: "set-user-policies", principalId: command.userId, policyIds: [...selected, command.policyId] });
      else userPlatformPolicies = { ...userPlatformPolicies, [command.userId]: [...selected, command.policyId] };
      return;
    }
    const match = users.flatMap((user) => [
      ...(snapshot.userPolicies[user.id] ?? []).map((policyId) => ({ user, policyId, attachment: policyAttachment(user.id, policyId) })),
      ...(userPlatformPolicies[user.id] ?? []).map((policyId) => ({ user, policyId, attachment: policyAttachment(user.id, policyId, "INSTALLATION") }))
    ]).find((entry) => entry.attachment.id === command.attachmentId);
    if (!match || match.attachment.resourceVersion !== command.resourceVersion) throw new HttpProblem(409, "PREVIEW_ATTACHMENT_CHANGED");
    if (match.attachment.scope === "INSTALLATION") userPlatformPolicies = { ...userPlatformPolicies, [match.user.id]: (userPlatformPolicies[match.user.id] ?? []).filter((policyId) => policyId !== match.policyId) };
    else await workspace.execute(credential, { kind: "set-user-policies", principalId: match.user.id, policyIds: (snapshot.userPolicies[match.user.id] ?? []).filter((policyId) => policyId !== match.policyId) });
  }
};
