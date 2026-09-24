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
export function buildAccessReport(kind: "credentials" | "security", workspace: AccessWorkspace, scene: AccountAccessScene, generatedAt: string, currentSession: SessionSummary | null = null) {
  const snapshot = buildAccessSecuritySnapshot(workspace, scene.directoryComplete);
  return {
    mode: "MOCK", kind, accountId: workspace.accountId, generatedAt,
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
    }),
    ...(kind === "security" ? {
      protections: { login: workspace.settings.loginProtection, userSso: workspace.settings.userSsoEnabled },
      counts: { groups: workspace.groups.length, policies: workspace.policies.length, roles: workspace.roles.length, providers: workspace.providers.length },
      evidenceCounts: snapshot.evidenceCounts,
      checks: snapshot.checks.map(({ id, state, evidence, count }) => ({ id, state, evidence, count })),
      activity: { observedAt: generatedAt, accountId: workspace.accountId, observations: buildAccessActivityObservations(workspace, currentSession?.principalId === scene.currentUserId ? currentSession : null) },
      events: workspace.events.map(({ action, target, at }) => ({ action, target, at }))
    } : {})
  };
}
