import type { AccessRole, AccessRoleSession, AccessWorkspace } from "./accessWorkspace";
import { AccessWorkspaceError } from "./accessWorkspaceError";
import type { RoleTrustDocument } from "./roles";

export type RoleSessionCaller = { type: "user"; id: string };
export type RoleTrust = Pick<AccessRole, "trustedUserIds">;
export function validateRoleTrust(trust: RoleTrust, userIds: readonly string[]): void {
  const invalid = () => { throw new AccessWorkspaceError("invalidTrust"); };
  if (!trust.trustedUserIds.length || trust.trustedUserIds.length > 30 || trust.trustedUserIds.some((id) => !userIds.includes(id))) invalid();
}
export function roleTrustPreview(role: RoleTrust) {
  return {
    languageVersion: "1",
    statements: [{ sid: "trusted-users", effect: "ALLOW", principals: role.trustedUserIds.map((id) => ({ type: "USER", id })) }]
  } satisfies RoleTrustDocument;
}
export function roleSessionStatus(workspace: AccessWorkspace, session: AccessRoleSession, userIds: readonly string[], now: string): "active" | "expired" | "revoked" | "unavailable" {
  if (session.revokedAt) return "revoked";
  const time = Date.parse(now), start = Date.parse(session.createdAt), expiry = Date.parse(session.expiresAt);
  if (![time, start, expiry].every(Number.isFinite) || time < start || expiry <= start || !workspace.roles.some((role) => role.id === session.roleId)) return "unavailable";
  if (time >= expiry) return "expired";
  if (!userIds.includes(session.caller.id)) return "unavailable";
  return "active";
}
