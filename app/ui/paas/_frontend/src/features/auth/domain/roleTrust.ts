import type { AccessRole, AccessRoleSession, AccessWorkspace } from "./accessWorkspace";
import { AccessWorkspaceError } from "./accessWorkspaceError";

// Known synthetic workloads, not an assertion accepted from an arbitrary string.
export const roleServicePrincipals = ["devops.matrix.internal"] as const;
export type RoleSessionCaller = { type: "user" | "service" | "federation"; id: string };
export type RoleTrust = Pick<AccessRole, "principalType" | "principal" | "trustedUserIds">;
export function validateRoleTrust(workspace: AccessWorkspace, trust: RoleTrust, userIds: readonly string[]): void {
  const invalid = () => { throw new AccessWorkspaceError("invalidTrust"); };
  if (trust.trustedUserIds.length > 30) invalid();
  switch (trust.principalType) {
    case "account":
      if (trust.principal !== workspace.accountId || !trust.trustedUserIds.length || trust.trustedUserIds.some((id) => !userIds.includes(id))) invalid();
      break;
    case "service":
      if (trust.trustedUserIds.length || !roleServicePrincipals.some((id) => id === trust.principal)) invalid();
      break;
    case "provider":
      if (trust.trustedUserIds.length || !workspace.providers.some((provider) => provider.id === trust.principal && provider.enabled)) invalid();
      break;
    default: invalid();
  }
}
export function roleTrustDocument(role: RoleTrust) {
  const principal = role.principalType === "account" ? { tenant: role.principal, userIds: role.trustedUserIds } : role.principalType === "service" ? { service: role.principal } : { providerId: role.principal };
  return { version: "1", statement: [{ effect: "allow", action: "iam:assumeRole", principal }] };
}
export function roleSessionStatus(workspace: AccessWorkspace, session: AccessRoleSession, userIds: readonly string[], now: string): "active" | "expired" | "revoked" | "unavailable" {
  if (session.revokedAt) return "revoked";
  if (!["user", "service", "federation"].includes(session.caller.type)) return "unavailable";
  const time = Date.parse(now), start = Date.parse(session.createdAt), expiry = Date.parse(session.expiresAt);
  if (![time, start, expiry].every(Number.isFinite) || time < start || expiry <= start || !workspace.roles.some((role) => role.id === session.roleId)) return "unavailable";
  if (time >= expiry) return "expired";
  if (session.caller.type === "user" && !userIds.includes(session.caller.id) || session.caller.type === "service" && !roleServicePrincipals.some((id) => id === session.caller.id) || session.caller.type === "federation" && !workspace.federations.some((entry) => entry.id === session.caller.id)) return "unavailable";
  return "active";
}
