import type { AccountIdentity, AccountUser } from "./accounts";
import { applyAccessWorkspaceCommand, withoutUserAccess, type AccessWorkspace } from "./accessWorkspace";
import { AccessWorkspaceError } from "./accessWorkspaceError";

export const userBatchLimit = 30;
export const userBatchActions = ["add-groups", "authorize", "enable", "disable", "delete"] as const;
export type UserBatchAction = typeof userBatchActions[number];
type UserBatchTarget = { id: string; resourceVersion: number | null };
export type UserBatchCommand = { targets: UserBatchTarget[] } & (
  | { action: "add-groups"; groupIds: string[] }
  | { action: "authorize"; policyIds: string[] }
  | { action: "enable" | "disable" | "delete" }
);
export type UserBatchContext = {
  canManage: boolean; supported: boolean; primaryId: string; actorId: string;
  targets: { id: string; enabled: boolean | null }[];
};

// The same eligibility rule drives menu explanations and mutation validation.
// An ineligible target blocks the whole selection; it is never silently skipped.
export function userBatchDisabledReason(action: UserBatchAction, context: UserBatchContext) {
  if (!context.canManage) return "forbidden";
  if (!context.supported) return "unsupported";
  if (!context.targets.length) return "empty";
  if (context.targets.length > userBatchLimit) return "limit";
  if (action === "add-groups") return null;
  if (context.targets.some((target) => target.id === context.primaryId)) return "primary";
  if (action === "authorize") return null;
  if (context.targets.some((target) => target.id === context.actorId)) return "self";
  if (action === "enable" && context.targets.some((target) => target.enabled !== false)) return "notDisabled";
  if (action === "disable" && context.targets.some((target) => target.enabled !== true)) return "notEnabled";
  return null;
}

// One preview transaction spans directory identities and their workspace access.
// Both results are published by the adapter only after every check succeeds.
export function applyUserBatch(source: AccessWorkspace, users: AccountUser[], identity: AccountIdentity, command: UserBatchCommand, clock: { id: string; at: string }) {
  const invalid = () => { throw new AccessWorkspaceError("invalid"); };
  if (source.accountId !== identity.account.organization.id || identity.principal.organizationId !== source.accountId ||
    users.some((user) => user.principal.organizationId !== source.accountId) || !userBatchActions.includes(command.action) ||
    new Set(command.targets.map((target) => target.id)).size !== command.targets.length) invalid();
  const directory = new Map(users.map((user) => [user.principal.id, user]));
  const primaryId = identity.account.primaryPrincipalId;
  const targets = command.targets.map((target) => {
    if (target.id === primaryId) return { id: target.id, enabled: null };
    const user = directory.get(target.id);
    if (!user) throw new AccessWorkspaceError("notFound");
    if (target.resourceVersion !== user.principal.resourceVersion) throw new AccessWorkspaceError("staleUsers");
    return { id: target.id, enabled: user.principal.status === "ACTIVE" };
  });
  const reason = userBatchDisabledReason(command.action, { targets, primaryId, actorId: identity.principal.id, supported: true,
    canManage: identity.account.organization.status === "ACTIVE" && identity.principal.status === "ACTIVE" && !identity.principal.mustChangePassword && identity.roles.includes("ORGANIZATION_ADMIN") });
  if (reason) throw new AccessWorkspaceError("ineligibleUsers");
  const ids = new Set(targets.map((target) => target.id));
  const context = { ...clock, primaryPrincipalId: primaryId, userIds: users.filter((user) => user.principal.id !== primaryId).map((user) => user.principal.id) };
  let workspace = source;
  let nextUsers = users;
  if (command.action === "authorize") {
    for (const id of ids) if (new Set([...(source.userPolicies[id] ?? []), ...command.policyIds]).size > 30) throw new AccessWorkspaceError("associationLimit");
    workspace = applyAccessWorkspaceCommand(source, { kind: "attach-policies", policyIds: command.policyIds, targets: { userIds: [...ids], groupIds: [], roleIds: [] } }, context);
  } else if (command.action === "add-groups") {
    if (!command.groupIds.length || command.groupIds.length > 30 || new Set(command.groupIds).size !== command.groupIds.length || command.groupIds.some((id) => !source.groups.some((group) => group.id === id))) invalid();
    for (const id of ids) {
      const total = new Set([...source.groups.filter((group) => group.memberIds.includes(id)).map((group) => group.id), ...command.groupIds]);
      if (total.size > 30) throw new AccessWorkspaceError("associationLimit");
    }
    workspace = structuredClone(source);
    for (const group of workspace.groups) if (command.groupIds.includes(group.id)) group.memberIds = [...new Set([...group.memberIds, ...ids])];
  } else if (command.action === "delete") {
    workspace = withoutUserAccess(source, [...ids], clock.at);
    nextUsers = users.filter((user) => !ids.has(user.principal.id));
  } else {
    nextUsers = users.map((user) => ids.has(user.principal.id) ? { ...user, principal: { ...user.principal, status: command.action === "enable" ? "ACTIVE" as const : "DISABLED" as const, resourceVersion: user.principal.resourceVersion + 1 } } : user);
  }
  workspace = { ...workspace, events: [{ id: clock.id, action: "batch-users" as const, target: command.action + ": " + [...ids].join(", "), at: clock.at }, ...source.events].slice(0, 100) };
  return { workspace, users: nextUsers };
}
