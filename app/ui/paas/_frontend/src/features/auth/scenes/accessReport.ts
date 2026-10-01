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
  status: "active" | "archived" | "resolved";
  lastObservedAt: string;
  generatedAt: string;
  windowDays: 90;
  target: { view: Extract<AccountAccessView, "users" | "keys" | "roles">; id?: string };
};

export type AccessAnalysisCoverageState = "mockObserved" | "unobserved" | "unsupported";
export type AccessAnalysisCoverage = {
  id: "roleSsoMapping" | "serviceWorkload" | "resourcePolicies" | "crossAccountDelegation" | "activityWindow";
  state: AccessAnalysisCoverageState;
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
      status: "active",
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
      status: "archived",
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
      status: "resolved",
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
      { id: "roleSsoMapping", state: "mockObserved" },
      { id: "serviceWorkload", state: "mockObserved" },
      { id: "resourcePolicies", state: "unsupported" },
      { id: "crossAccountDelegation", state: "unsupported" },
      { id: "activityWindow", state: "unobserved" }
    ],
    trustEntries: [...mappingEntries, ...serviceEntries],
    unusedFindings: buildUnusedAccessFindingPreview(workspace, scene)
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

export type AccountSecurityReportScope = {
  id: "account" | "users" | "accessKeys";
  rows: number;
};

export type AccountSecurityReportEvidence = {
  id: "passwordLoginSession" | "accessKeyAuthorization" | "roleActivity" | "paasOutcomes" | "auditStatistics" | "notificationDelivery" | "externalRisk";
  coverage: "INCLUDED" | "NOT_INCLUDED";
  observed: number;
  notObserved: number;
  unknown: number;
};

export type AccountSecurityReportPreview = {
  mode: "MOCK";
  accountId: string;
  requestId: string;
  reportId: string;
  formatVersion: 1;
  generatedAt: string;
  expiresAt: string;
  immutable: true;
  scopes: AccountSecurityReportScope[];
  evidence: AccountSecurityReportEvidence[];
  totals: { users: number; accessKeys: number; rows: number };
};

export type AccountSecurityReportCreation =
  | { outcome: "COMPLETED"; report: AccountSecurityReportPreview }
  | { outcome: "REJECTED"; reason: "USER_LIMIT" | "ACCESS_KEY_LIMIT" | "ROW_LIMIT" };

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
  const users = scene.users.length;
  const accessKeys = workspace.keys.length;
  const rows = 1 + users + accessKeys;
  if (users > accountSecurityReportLimits.users) return { outcome: "REJECTED", reason: "USER_LIMIT" };
  if (accessKeys > accountSecurityReportLimits.accessKeys) return { outcome: "REJECTED", reason: "ACCESS_KEY_LIMIT" };
  if (rows > accountSecurityReportLimits.rows) return { outcome: "REJECTED", reason: "ROW_LIMIT" };
  const issuedSessionObserved = currentSession?.organizationId === workspace.accountId
    && currentSession.principalId === scene.currentUserId
    && currentSession.status === "ACTIVE"
    && Number.isFinite(Date.parse(currentSession.issuedAt));
  const observedKeyAuthorizations = workspace.keys.filter((key) => key.usage.lastAuthorization).length;
  const generated = new Date(generatedAt);
  if (!requestId || !Number.isFinite(generated.getTime())) throw new Error("INVALID_IAM_REPORT");
  const expiresAt = new Date(generated.getTime() + accountSecurityReportLimits.retainedDays * 24 * 60 * 60 * 1000).toISOString();
  return {
    outcome: "COMPLETED",
    report: {
      mode: "MOCK",
      accountId: workspace.accountId,
      requestId,
      reportId: `security-report-${requestId}`,
      formatVersion: 1,
      generatedAt: generated.toISOString(),
      expiresAt,
      immutable: true,
      scopes: [
        { id: "account", rows: 1 },
        { id: "users", rows: users },
        { id: "accessKeys", rows: accessKeys }
      ],
      evidence: [
        { id: "passwordLoginSession", coverage: "INCLUDED", observed: issuedSessionObserved ? 1 : 0, notObserved: Math.max(0, users - (issuedSessionObserved ? 1 : 0)), unknown: 0 },
        { id: "accessKeyAuthorization", coverage: "INCLUDED", observed: observedKeyAuthorizations, notObserved: 0, unknown: Math.max(0, accessKeys - observedKeyAuthorizations) },
        ...(["roleActivity", "paasOutcomes", "auditStatistics", "notificationDelivery", "externalRisk"] as const).map((id) => ({ id, coverage: "NOT_INCLUDED" as const, observed: 0, notObserved: 0, unknown: 0 }))
      ],
      totals: { users, accessKeys, rows }
    }
  };
}
