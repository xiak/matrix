import type { AccessWorkspace } from "../domain/accessWorkspace";
import type { AccountAccessView } from "../domain/accounts";
import type { AccountAccessScene } from "./accountAccessScene";

export type AccessSecurityCheckState = "review" | "configured" | "notApplicable" | "unknown";
export type AccessSecurityCheck = {
  id: "activeKeys" | "directGrants" | "loginProtection" | "pendingPasswords" | "mfaEvidence";
  state: AccessSecurityCheckState;
  count: number | null;
  target: Extract<AccountAccessView, "keys" | "settings" | "users" | "groups"> | null;
};

// Preview diagnostics deliberately distinguish an absent control from missing
// evidence. They are recommendations over local synthetic data, never a PDP
// decision, a security score, or proof that an authenticator is enrolled.
export function buildAccessSecuritySnapshot(workspace: AccessWorkspace): {
  source: "MOCK";
  checks: AccessSecurityCheck[];
  counts: Record<AccessSecurityCheckState, number>;
} {
  const profiles = Object.values(workspace.userProfiles);
  const consoleUsers = profiles.filter((profile) => profile.consoleAccess).length;
  const programmaticUsers = profiles.filter((profile) => profile.programmaticAccess).length;
  const activeKeys = workspace.keys.filter((key) => key.enabled).length;
  const directGrants = Object.values(workspace.userPolicies).filter((policyIds) => policyIds.length > 0).length;
  const pendingPasswords = profiles.filter((profile) => profile.consoleAccess && profile.passwordResetRequired).length;
  const checks: AccessSecurityCheck[] = [
    {
      id: "activeKeys",
      state: !programmaticUsers && !workspace.keys.length ? "notApplicable" : activeKeys ? "review" : "configured",
      count: activeKeys,
      target: "keys"
    },
    {
      id: "directGrants",
      state: profiles.length === 0 ? "notApplicable" : directGrants ? "review" : "configured",
      count: directGrants,
      target: "users"
    },
    {
      id: "loginProtection",
      state: consoleUsers === 0 ? "notApplicable" : workspace.settings.loginProtection ? "configured" : "review",
      count: consoleUsers,
      target: "settings"
    },
    {
      id: "pendingPasswords",
      state: consoleUsers === 0 ? "notApplicable" : pendingPasswords ? "review" : "configured",
      count: pendingPasswords,
      target: "users"
    },
    {
      id: "mfaEvidence",
      // Requiring sign-in protection is not evidence that any user has bound
      // an authenticator. The current preview has no authenticator inventory.
      state: consoleUsers === 0 ? "notApplicable" : "unknown",
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
    }, { review: 0, configured: 0, notApplicable: 0, unknown: 0 })
  };
}

// Allowlist report fields: neither credentials nor metadata may enter a report.
export function buildAccessReport(kind: "credentials" | "security", workspace: AccessWorkspace, scene: AccountAccessScene, generatedAt: string) {
  const snapshot = buildAccessSecuritySnapshot(workspace);
  return {
    mode: "MOCK", kind, accountId: workspace.accountId, generatedAt,
    coverage: {
      directory: scene.directoryComplete ? "COMPLETE" : "PARTIAL",
      authenticatorEnrollment: "UNKNOWN",
      credentialActivity: "MOCK_ONLY"
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
        accessKeys: { total: keys.length, active: keys.filter((key) => key.enabled).length }
      };
    }),
    ...(kind === "security" ? {
      protections: { login: workspace.settings.loginProtection, userSso: workspace.settings.userSsoEnabled },
      counts: { groups: workspace.groups.length, policies: workspace.policies.length, roles: workspace.roles.length, providers: workspace.providers.length },
      checks: snapshot.checks.map(({ id, state, count }) => ({ id, state, count })),
      events: workspace.events.map(({ action, target, at }) => ({ action, target, at }))
    } : {})
  };
}
