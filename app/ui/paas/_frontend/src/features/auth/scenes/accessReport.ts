import type { AccessWorkspace } from "../domain/accessWorkspace";
import type { AccountAccessView } from "../domain/accounts";
import type { SessionSummary } from "../domain/session";
import type { AccountAccessScene } from "./accountAccessScene";

export type AccessSecurityCheckState = "review" | "configured" | "notApplicable" | "unknown";
export type AccessSecurityEvidenceState = "observed" | "unobserved" | "incomplete" | "notApplicable";
export type AccessSecurityCheck = {
  id: "activeKeys" | "directGrants" | "loginProtection" | "pendingPasswords" | "mfaEvidence";
  state: AccessSecurityCheckState;
  evidence: AccessSecurityEvidenceState;
  count: number | null;
  target: Extract<AccountAccessView, "keys" | "settings" | "users" | "groups"> | null;
};

export type AccessActivityObservation = {
  id: "successfulLogin" | "accessKeyUse" | "roleUse" | "businessOutcome";
  state: "observed" | "unknown" | "notApplicable";
  occurredAt: string | null;
  source: "CURRENT_PREVIEW_SESSION" | null;
};

export type UnusedAccessFindingPreview = {
  id: string;
  accountId: string;
  name: string;
  subjectId: string;
  subjectKind: "user" | "accessKey" | "role";
  findingType: "unusedPassword" | "unusedAccessKey" | "unusedRole";
  lifecycle: "ACTIVE" | "ARCHIVED" | "RESOLVED";
  lifecycleEvidence: {
    lifecycle: "ACTIVE" | "ARCHIVED" | "RESOLVED";
    occurredAt: string;
    source: "SYNTHETIC_ANALYZER" | "SYNTHETIC_HUMAN_REVIEW";
  }[];
  lastObservedAt: string;
  generatedAt: string;
  windowDays: 90;
  target: { view: Extract<AccountAccessView, "users" | "keys" | "roles">; id?: string };
};

export type AccessAnalysisScanPreview = {
  state: "FAILED";
  evidence: "PREVIOUS_SNAPSHOT_STALE";
  lastSucceededAt: string;
  lastAttemptedAt: string;
};

export type AccessAnalysisRulePreview = {
  id: string;
  accountId: string;
  type: "UNUSED_ACCESS";
  resourceVersion: number;
  windowDays: number;
  status: "ACTIVE" | "DISABLED";
  evidence: "SYNTHETIC_COMPLETE_WINDOW";
};

export type AccessAnalysisCoverageState = "INSUFFICIENT_COVERAGE" | "NOT_INCLUDED";
export type AccessAnalysisCoverageReason = "SOURCE_NOT_READY" | "SOURCE_NOT_IMPLEMENTED";
export type AccessAnalysisCoverage =
  | {
    id: "IAM_PASSWORD_SESSIONS" | "IAM_ACCESS_KEY_AUTHORIZATIONS" | "IAM_ROLE_SESSIONS" | "IAM_ROLE_AUTHORIZATIONS";
    state: Extract<AccessAnalysisCoverageState, "INSUFFICIENT_COVERAGE">;
    reason: Extract<AccessAnalysisCoverageReason, "SOURCE_NOT_READY">;
    observedFrom: string;
    observedThrough: string;
  }
  | {
    id: "PAAS_RESULTS" | "EXTERNAL_FEDERATION";
    state: Extract<AccessAnalysisCoverageState, "NOT_INCLUDED">;
    reason: Extract<AccessAnalysisCoverageReason, "SOURCE_NOT_IMPLEMENTED">;
    observedFrom: null;
    observedThrough: null;
  };
export type AccessAnalysisTrustEntry = {
  id: string;
  accountId: string;
  name: string;
  kind: "roleSsoMapping" | "serviceWorkload";
  principal: string;
  roleId: string;
  roleName: string;
  sourceId: string;
  sourceName: string;
  configuration: "configured" | "incomplete" | "disabled";
  createdAt: string;
  target: { view: Extract<AccountAccessView, "providers" | "roles">; id?: string };
};

function assertReportAccount(workspace: AccessWorkspace, scene: AccountAccessScene) {
  if (workspace.accountId !== scene.accountId) throw new Error("INVALID_IAM_TENANT");
}

// This is a visibly synthetic UX sample. Current Matrix activity sources do
// not prove a complete collection window, so no current workspace principal is
// classified as unused. The sample lets the review workflow be evaluated
// without inventing a live analyzer or a destructive command.
export function buildUnusedAccessFindingPreview(workspace: AccessWorkspace, scene: AccountAccessScene): UnusedAccessFindingPreview[] {
  assertReportAccount(workspace, scene);
  const user = scene.users[0];
  const key = workspace.keys[0];
  const role = workspace.roles[0];
  const findings: UnusedAccessFindingPreview[] = [];
  if (user) findings.push({
      id: "mock-unused-password",
      accountId: workspace.accountId,
      name: user.loginName,
      subjectId: user.id,
      subjectKind: "user",
      findingType: "unusedPassword",
      lifecycle: "ACTIVE",
      lifecycleEvidence: [
        { lifecycle: "ACTIVE", occurredAt: "2026-09-09T03:00:00Z", source: "SYNTHETIC_ANALYZER" }
      ],
      lastObservedAt: "2026-05-18T08:15:00Z",
      generatedAt: "2026-09-09T03:00:00Z",
      windowDays: 90,
      target: { view: "users", id: user.id }
    });
  if (key) findings.push({
      id: "mock-unused-access-key",
      accountId: workspace.accountId,
      name: key.id,
      subjectId: key.ownerId,
      subjectKind: "accessKey",
      findingType: "unusedAccessKey",
      lifecycle: "ARCHIVED",
      lifecycleEvidence: [
        { lifecycle: "ACTIVE", occurredAt: "2026-09-09T03:00:00Z", source: "SYNTHETIC_ANALYZER" },
        { lifecycle: "ARCHIVED", occurredAt: "2026-09-10T02:20:00Z", source: "SYNTHETIC_HUMAN_REVIEW" }
      ],
      lastObservedAt: "2026-05-04T11:30:00Z",
      generatedAt: "2026-09-09T03:00:00Z",
      windowDays: 90,
      target: { view: "keys" }
    });
  if (role) findings.push({
      id: "mock-unused-role",
      accountId: workspace.accountId,
      name: role.name,
      subjectId: role.id,
      subjectKind: "role",
      findingType: "unusedRole",
      lifecycle: "RESOLVED",
      lifecycleEvidence: [
        { lifecycle: "ACTIVE", occurredAt: "2026-09-09T03:00:00Z", source: "SYNTHETIC_ANALYZER" },
        { lifecycle: "RESOLVED", occurredAt: "2026-09-12T05:10:00Z", source: "SYNTHETIC_ANALYZER" }
      ],
      lastObservedAt: "2026-04-21T01:45:00Z",
      generatedAt: "2026-09-09T03:00:00Z",
      windowDays: 90,
      target: { view: "roles", id: role.id }
    });
  return findings;
}

// This preview inventories tenant configuration only. A configured assertion
// mapping preview or service role is not proof that a principal can currently assume
// the role, reach a resource, or has ever used the path.
export function buildAccessAnalysisPreview(workspace: AccessWorkspace, scene: AccountAccessScene): {
  accountId: string;
  coverage: AccessAnalysisCoverage[];
  trustEntries: AccessAnalysisTrustEntry[];
  unusedFindings: UnusedAccessFindingPreview[];
  scanPreview: AccessAnalysisScanPreview;
  rule: AccessAnalysisRulePreview;
} {
  assertReportAccount(workspace, scene);
  const mappingEntries: AccessAnalysisTrustEntry[] = workspace.roleSsoMappings.map((mapping) => {
    const provider = workspace.providers.find((candidate) => candidate.id === mapping.providerId);
    const role = workspace.roles.find((candidate) => candidate.id === mapping.roleId);
    const configuration = !mapping.enabled
      ? "disabled"
      : !provider?.enabled || !role || role.principalType !== "provider" || role.principal !== mapping.providerId
        ? "incomplete"
        : "configured";
    return {
      id: `role-sso-mapping:${mapping.id}`,
      accountId: workspace.accountId,
      name: mapping.name,
      kind: "roleSsoMapping",
      principal: mapping.assertionSubject,
      roleId: mapping.roleId,
      roleName: role?.name ?? mapping.roleId,
      sourceId: mapping.providerId,
      sourceName: provider?.name ?? mapping.providerId,
      configuration,
      createdAt: mapping.createdAt,
      target: { view: "providers" }
    };
  });
  const serviceEntries: AccessAnalysisTrustEntry[] = workspace.roles
    .filter((role) => role.principalType === "service")
    .map((role) => ({
      id: `service:${role.id}`,
      accountId: workspace.accountId,
      name: role.name,
      kind: "serviceWorkload",
      principal: role.principal,
      roleId: role.id,
      roleName: role.name,
      sourceId: role.principal,
      sourceName: role.principal,
      configuration: "configured",
      createdAt: role.createdAt,
      target: { view: "roles", id: role.id }
    }));
  return {
    accountId: workspace.accountId,
    coverage: [
      { id: "IAM_PASSWORD_SESSIONS", state: "INSUFFICIENT_COVERAGE", reason: "SOURCE_NOT_READY", observedFrom: "2026-06-11T03:00:00Z", observedThrough: "2026-09-09T03:00:00Z" },
      { id: "IAM_ACCESS_KEY_AUTHORIZATIONS", state: "INSUFFICIENT_COVERAGE", reason: "SOURCE_NOT_READY", observedFrom: "2026-06-11T03:00:00Z", observedThrough: "2026-09-09T03:00:00Z" },
      { id: "IAM_ROLE_SESSIONS", state: "INSUFFICIENT_COVERAGE", reason: "SOURCE_NOT_READY", observedFrom: "2026-06-11T03:00:00Z", observedThrough: "2026-09-09T03:00:00Z" },
      { id: "IAM_ROLE_AUTHORIZATIONS", state: "INSUFFICIENT_COVERAGE", reason: "SOURCE_NOT_READY", observedFrom: "2026-06-11T03:00:00Z", observedThrough: "2026-09-09T03:00:00Z" },
      { id: "PAAS_RESULTS", state: "NOT_INCLUDED", reason: "SOURCE_NOT_IMPLEMENTED", observedFrom: null, observedThrough: null },
      { id: "EXTERNAL_FEDERATION", state: "NOT_INCLUDED", reason: "SOURCE_NOT_IMPLEMENTED", observedFrom: null, observedThrough: null }
    ],
    trustEntries: [...mappingEntries, ...serviceEntries],
    unusedFindings: buildUnusedAccessFindingPreview(workspace, scene),
    scanPreview: {
      state: "FAILED",
      evidence: "PREVIOUS_SNAPSHOT_STALE",
      lastSucceededAt: "2026-09-09T03:00:00Z",
      lastAttemptedAt: "2026-09-10T03:00:00Z"
    },
    rule: {
      id: "access-analyzer-preview",
      accountId: workspace.accountId,
      type: "UNUSED_ACCESS",
      resourceVersion: 3,
      windowDays: 90,
      status: "ACTIVE",
      evidence: "SYNTHETIC_COMPLETE_WINDOW"
    }
  };
}

// This is a preview of evidence *shape*, not an activity/idle judgment. Only
// the current issued Session proves a sample login; generic operation events,
// metadata and absent events cannot establish a collection window or watermark.
export function buildAccessActivityObservations(workspace: AccessWorkspace, currentSession: SessionSummary | null = null): AccessActivityObservation[] {
  const issuedAt = currentSession?.organizationId === workspace.accountId && currentSession.status === "ACTIVE" && Number.isFinite(Date.parse(currentSession.issuedAt))
    ? currentSession.issuedAt : null;
  return [
    { id: "successfulLogin", state: issuedAt ? "observed" : "unknown", occurredAt: issuedAt, source: issuedAt ? "CURRENT_PREVIEW_SESSION" : null },
    { id: "accessKeyUse", state: workspace.keys.length ? "unknown" : "notApplicable", occurredAt: null, source: null },
    { id: "roleUse", state: "unknown", occurredAt: null, source: null },
    { id: "businessOutcome", state: "unknown", occurredAt: null, source: null }
  ];
}

// Preview diagnostics deliberately distinguish an absent control from missing
// evidence. They are recommendations over local synthetic data, never a PDP
// decision, a security score, or proof that an authenticator is enrolled.
export function buildAccessSecuritySnapshot(workspace: AccessWorkspace, directoryComplete = true): {
  source: "MOCK";
  checks: AccessSecurityCheck[];
  counts: Record<AccessSecurityCheckState, number>;
  evidenceCounts: Record<AccessSecurityEvidenceState, number>;
} {
  const profiles = Object.values(workspace.userProfiles);
  const consoleUsers = profiles.filter((profile) => profile.consoleAccess).length;
  const programmaticUsers = profiles.filter((profile) => profile.programmaticAccess).length;
  const activeKeys = workspace.keys.filter((key) => key.status === "ENABLED").length;
  const directGrants = Object.values(workspace.userPolicies).filter((policyIds) => policyIds.length > 0).length;
  const pendingPasswords = profiles.filter((profile) => profile.consoleAccess && profile.passwordResetRequired).length;
  const checks: AccessSecurityCheck[] = [
    {
      id: "activeKeys",
      state: !programmaticUsers && !workspace.keys.length
        ? directoryComplete ? "notApplicable" : "unknown"
        : activeKeys ? "review" : "configured",
      evidence: !programmaticUsers && !workspace.keys.length
        ? directoryComplete ? "notApplicable" : "incomplete"
        : "observed",
      count: activeKeys,
      target: "keys"
    },
    {
      id: "directGrants",
      state: directGrants
        ? "review"
        : !directoryComplete ? "unknown" : profiles.length === 0 ? "notApplicable" : "configured",
      evidence: profiles.length === 0 && directoryComplete ? "notApplicable" : directoryComplete ? "observed" : "incomplete",
      count: directGrants,
      target: "users"
    },
    {
      id: "loginProtection",
      state: consoleUsers === 0
        ? directoryComplete ? "notApplicable" : "unknown"
        : workspace.settings.loginProtection ? "configured" : "review",
      evidence: consoleUsers === 0 && directoryComplete ? "notApplicable" : directoryComplete ? "observed" : "incomplete",
      count: consoleUsers,
      target: "settings"
    },
    {
      id: "pendingPasswords",
      state: pendingPasswords
        ? "review"
        : !directoryComplete ? "unknown" : consoleUsers === 0 ? "notApplicable" : "configured",
      evidence: consoleUsers === 0 && directoryComplete ? "notApplicable" : directoryComplete ? "observed" : "incomplete",
      count: pendingPasswords,
      target: "users"
    },
    {
      id: "mfaEvidence",
      // Requiring sign-in protection is not evidence that any user has bound
      // an authenticator. The current preview has no authenticator inventory.
      state: consoleUsers === 0 && directoryComplete ? "notApplicable" : "unknown",
      evidence: consoleUsers === 0 && directoryComplete ? "notApplicable" : "unobserved",
      count: null,
      target: null
    }
  ];
  return {
    source: "MOCK",
    checks,
    counts: checks.reduce<Record<AccessSecurityCheckState, number>>((counts, check) => {
      counts[check.state] += 1;
      return counts;
    }, { review: 0, configured: 0, notApplicable: 0, unknown: 0 }),
    evidenceCounts: checks.reduce<Record<AccessSecurityEvidenceState, number>>((counts, check) => {
      counts[check.evidence] += 1;
      return counts;
    }, { observed: 0, unobserved: 0, incomplete: 0, notApplicable: 0 })
  };
}

// Allowlist report fields: neither credentials nor metadata may enter a report.
// This is the older credential inventory preview, not AccountSecurityReport.
export function buildCredentialReport(workspace: AccessWorkspace, scene: AccountAccessScene, generatedAt: string) {
  assertReportAccount(workspace, scene);
  return {
    mode: "MOCK", kind: "credentials" as const, accountId: workspace.accountId, generatedAt,
    coverage: {
      directory: scene.directoryComplete ? "COMPLETE" : "PARTIAL",
      authenticatorEnrollment: "UNOBSERVED",
      accessKeyInventory: "MOCK_OBSERVED",
      activityWindow: "UNAVAILABLE",
      collectionStart: null,
      sourceWatermarks: { successfulLogin: null, accessKeyUse: null, roleUse: null, businessOutcome: null }
    },
    users: scene.users.map((user) => {
      const profile = workspace.userProfiles[user.id];
      const keys = workspace.keys.filter((key) => key.ownerId === user.id);
      return {
        loginName: user.loginName,
        status: user.state,
        consoleAccess: profile?.consoleAccess ?? "UNKNOWN",
        programmaticAccess: profile?.programmaticAccess ?? "UNKNOWN",
        passwordResetRequired: profile ? profile.consoleAccess ? profile.passwordResetRequired : "NOT_APPLICABLE" : "UNKNOWN",
        authenticatorEnrollment: profile?.consoleAccess === false ? "NOT_APPLICABLE" : "UNKNOWN",
        directPolicyIds: user.attachments.map((attachment) => attachment.policyId),
        accessKeys: { total: keys.length, active: keys.filter((key) => key.status === "ENABLED").length }
      };
    })
  };
}

export const accountSecurityReportLimits = {
  users: 1000,
  accessKeys: 2000,
  rows: 3001,
  contentBytes: 4 * 1024 * 1024,
  retainedDays: 7,
  retainedReports: 20
} as const;

export type AccountSecurityReportObservationState = "OBSERVED" | "NOT_OBSERVED_IN_RETAINED_IAM_STATE" | "UNKNOWN";
export type AccountSecurityReportCoverageSource =
  | "IAM_ACCOUNT"
  | "IAM_USERS"
  | "IAM_LOGIN_SESSIONS"
  | "IAM_ACCESS_KEYS"
  | "IAM_ROLE_ACTIVITY"
  | "PAAS_RESULTS"
  | "AUDIT_STATISTICS"
  | "NOTIFICATION_DELIVERY"
  | "EXTERNAL_RISK";

export type AccountSecurityReportCoverage = {
  source: AccountSecurityReportCoverageSource;
  state: "COMPLETE" | "NOT_INCLUDED";
};

export type AccountSecurityReportUserPreview = {
  id: string;
  name: string;
  loginName: string;
  displayName: string;
  status: "ACTIVE" | "DISABLED";
  root: boolean;
  mustChangePassword: boolean;
  resourceVersion: number | null;
  mfaState: "NEVER_BOUND" | "BOUND" | "REMOVED" | "UNKNOWN";
  lastPasswordLogin: { state: AccountSecurityReportObservationState; observedAt: string | null };
};

export type AccountSecurityReportAccessKeyPreview = {
  id: string;
  name: string;
  userId: string;
  status: "ENABLED" | "DISABLED";
  resourceVersion: number;
  createdAt: string;
  allowedSourceCidrs: string[];
  authorization: {
    state: AccountSecurityReportObservationState;
    observedAt: string | null;
    allowed: boolean | null;
    product: string | null;
    action: string | null;
    sourceIp: string | null;
  };
};

export type AccountSecurityReportPreview = {
  mode: "MOCK";
  accountId: string;
  requestId: string;
  reportId: string;
  formatVersion: 1;
  observedAt: string;
  expiresAt: string;
  immutable: true;
  accountSecuritySettingsVersion: number;
  coverage: AccountSecurityReportCoverage[];
  users: AccountSecurityReportUserPreview[];
  accessKeys: AccountSecurityReportAccessKeyPreview[];
  totals: { users: number; accessKeys: number; rows: number };
};

export type AccountSecurityReportRejectionReason = "USER_LIMIT" | "ACCESS_KEY_LIMIT" | "ROW_LIMIT";

export type AccountSecurityReportCreation =
  | { outcome: "COMPLETED"; report: AccountSecurityReportPreview }
  | { outcome: "REJECTED"; reason: AccountSecurityReportRejectionReason };

export type AccountSecurityReportDirectoryStatus = "available" | "expiringSoon" | "expired";

export type AccountSecurityReportDirectoryEntry = {
  id: string;
  name: string;
  status: AccountSecurityReportDirectoryStatus;
  report: AccountSecurityReportPreview;
};

export function accountSecurityReportLimitViolation(users: number, accessKeys: number): AccountSecurityReportRejectionReason | null {
  if (users > accountSecurityReportLimits.users) return "USER_LIMIT";
  if (accessKeys > accountSecurityReportLimits.accessKeys) return "ACCESS_KEY_LIMIT";
  if (1 + users + accessKeys > accountSecurityReportLimits.rows) return "ROW_LIMIT";
  return null;
}

// This preview owns information architecture only. The server candidate remains
// authoritative for the immutable JSON/CSV documents, byte limit and permission
// checks; the browser never creates a report file or a LIVE success fact.
export function createAccountSecurityReportPreview(
  workspace: AccessWorkspace,
  scene: AccountAccessScene,
  generatedAt: string,
  requestId: string,
  currentSession: SessionSummary | null = null
): AccountSecurityReportCreation {
  assertReportAccount(workspace, scene);
  const users = scene.users.length + 1;
  const accessKeys = workspace.keys.length;
  const rows = 1 + users + accessKeys;
  const limitViolation = accountSecurityReportLimitViolation(users, accessKeys);
  if (limitViolation) return { outcome: "REJECTED", reason: limitViolation };
  const validCurrentSession = currentSession?.organizationId === workspace.accountId
    && currentSession.principalId === scene.currentUserId
    && currentSession.status === "ACTIVE"
    && Number.isFinite(Date.parse(currentSession.issuedAt))
    ? currentSession
    : null;
  const generated = new Date(generatedAt);
  if (!requestId || !Number.isFinite(generated.getTime())) throw new Error("INVALID_IAM_REPORT");
  const expiresAt = new Date(generated.getTime() + accountSecurityReportLimits.retainedDays * 24 * 60 * 60 * 1000).toISOString();
  const rootMfaState = scene.accountOwner.isCurrent
    ? workspace.personalMfa.factorState === "bound" ? "BOUND" as const
      : workspace.personalMfa.factorState === "removed" ? "REMOVED" as const
        : "NEVER_BOUND" as const
    : "UNKNOWN" as const;
  const reportUsers: AccountSecurityReportUserPreview[] = [
    {
      id: scene.accountOwner.id,
      name: scene.accountOwner.loginName,
      loginName: scene.accountOwner.loginName,
      displayName: scene.accountOwner.name ?? scene.accountOwner.loginName,
      status: scene.accountOwner.state === "disabled" ? "DISABLED" as const : "ACTIVE" as const,
      root: true,
      mustChangePassword: scene.accountOwner.state === "passwordChangeRequired",
      resourceVersion: scene.accountOwner.isCurrent ? scene.permissionBoundary.resourceVersion : null,
      mfaState: rootMfaState,
      lastPasswordLogin: validCurrentSession?.principalId === scene.accountOwner.id
        ? { state: "OBSERVED" as const, observedAt: validCurrentSession.issuedAt }
        : { state: "NOT_OBSERVED_IN_RETAINED_IAM_STATE" as const, observedAt: null }
    },
    ...scene.users.map((user) => ({
      id: user.id,
      name: user.loginName,
      loginName: user.loginName,
      displayName: user.name,
      status: user.enabled ? "ACTIVE" as const : "DISABLED" as const,
      root: false,
      mustChangePassword: user.state === "passwordChangeRequired",
      resourceVersion: user.resourceVersion,
      mfaState: "UNKNOWN" as const,
      lastPasswordLogin: validCurrentSession?.principalId === user.id
        ? { state: "OBSERVED" as const, observedAt: validCurrentSession.issuedAt }
        : { state: "NOT_OBSERVED_IN_RETAINED_IAM_STATE" as const, observedAt: null }
    }))
  ].sort((left, right) => left.id.localeCompare(right.id, "en"));
  const reportKeys: AccountSecurityReportAccessKeyPreview[] = workspace.keys.map((key) => ({
    id: key.id,
    name: key.id,
    userId: key.ownerId,
    status: key.status,
    resourceVersion: key.resourceVersion,
    createdAt: key.createdAt,
    allowedSourceCidrs: [...key.networkRestrictions.allowedSourceCidrs],
    authorization: key.usage.lastAuthorization ? {
      state: "OBSERVED" as const,
      observedAt: key.usage.lastAuthorization.evaluatedAt,
      allowed: key.usage.lastAuthorization.allowed,
      product: key.usage.lastAuthorization.product,
      action: key.usage.lastAuthorization.action,
      sourceIp: key.usage.lastAuthorization.sourceIp
    } : {
      state: "NOT_OBSERVED_IN_RETAINED_IAM_STATE" as const,
      observedAt: null,
      allowed: null,
      product: null,
      action: null,
      sourceIp: null
    }
  })).sort((left, right) => left.id.localeCompare(right.id, "en"));
  return {
    outcome: "COMPLETED",
    report: {
      mode: "MOCK",
      accountId: workspace.accountId,
      requestId,
      reportId: `security-report-${requestId}`,
      formatVersion: 1,
      observedAt: generated.toISOString(),
      expiresAt,
      immutable: true,
      accountSecuritySettingsVersion: workspace.settings.accountRuleVersion,
      coverage: [
        { source: "IAM_ACCOUNT", state: "COMPLETE" },
        { source: "IAM_USERS", state: "COMPLETE" },
        { source: "IAM_LOGIN_SESSIONS", state: "COMPLETE" },
        { source: "IAM_ACCESS_KEYS", state: "COMPLETE" },
        { source: "IAM_ROLE_ACTIVITY", state: "NOT_INCLUDED" },
        { source: "PAAS_RESULTS", state: "NOT_INCLUDED" },
        { source: "AUDIT_STATISTICS", state: "NOT_INCLUDED" },
        { source: "NOTIFICATION_DELIVERY", state: "NOT_INCLUDED" },
        { source: "EXTERNAL_RISK", state: "NOT_INCLUDED" }
      ],
      users: reportUsers,
      accessKeys: reportKeys,
      totals: { users, accessKeys, rows }
    }
  };
}

// The service currently exposes create/read/download by reportId, but no list
// contract. Keep this directory a deterministic, synthetic UX fixture until a
// server-owned collection exists; callers must never merge it with LIVE data.
export function buildAccountSecurityReportDirectoryPreview(
  workspace: AccessWorkspace,
  scene: AccountAccessScene,
  referenceAt: string,
  currentSession: SessionSummary | null = null
): AccountSecurityReportDirectoryEntry[] {
  assertReportAccount(workspace, scene);
  const reference = new Date(referenceAt);
  if (!Number.isFinite(reference.getTime())) throw new Error("INVALID_IAM_REPORT");
  const hour = 60 * 60 * 1000;
  const fixtures = [
    { requestId: "mock-directory-recent", ageHours: 36 },
    { requestId: "mock-directory-expiring", ageHours: accountSecurityReportLimits.retainedDays * 24 - 6 },
    { requestId: "mock-directory-expired", ageHours: (accountSecurityReportLimits.retainedDays + 1) * 24 }
  ] as const;

  return fixtures.flatMap(({ requestId, ageHours }) => {
    const observedAt = new Date(reference.getTime() - ageHours * hour).toISOString();
    const created = createAccountSecurityReportPreview(workspace, scene, observedAt, requestId, currentSession);
    if (created.outcome !== "COMPLETED") return [];
    const remaining = Date.parse(created.report.expiresAt) - reference.getTime();
    const status: AccountSecurityReportDirectoryStatus = remaining <= 0
      ? "expired"
      : remaining <= 24 * hour ? "expiringSoon" : "available";
    return [{ id: created.report.reportId, name: created.report.reportId, status, report: created.report }];
  });
}
