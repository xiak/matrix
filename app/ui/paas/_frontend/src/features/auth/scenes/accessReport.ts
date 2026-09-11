import type { AccessWorkspace } from "../domain/accessWorkspace";
import type { AccountAccessScene } from "./accountAccessScene";

// Allowlist report fields: neither credentials nor metadata may enter a report.
export function buildAccessReport(kind: "credentials" | "security", workspace: AccessWorkspace, scene: AccountAccessScene, generatedAt: string) {
  return {
    mode: "MOCK", kind, accountId: workspace.accountId, generatedAt,
    users: scene.users.map((user) => ({ loginName: user.loginName, status: user.state, directPolicyIds: user.attachments.map((attachment) => attachment.policyId), keyCount: workspace.keys.filter((key) => key.ownerId === user.id).length })),
    ...(kind === "security" ? {
      protections: { login: workspace.settings.loginProtection, sensitiveOperations: workspace.settings.sensitiveProtection, userSso: workspace.settings.userSsoEnabled },
      counts: { groups: workspace.groups.length, policies: workspace.policies.length, roles: workspace.roles.length, providers: workspace.providers.length },
      events: workspace.events.map(({ action, target, at }) => ({ action, target, at }))
    } : {})
  };
}
