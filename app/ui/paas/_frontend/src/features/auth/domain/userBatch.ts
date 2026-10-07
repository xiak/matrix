import type { AccountIdentity, UserAccess } from "./accounts";
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
  canListUsers: boolean; supported: boolean; rootId: string; actorId: string;
  targets: { id: string; enabled: boolean | null; canSetStatus: boolean; canAttachPolicy: boolean; protected: boolean }[];
};

// The same eligibility rule drives menu explanations and mutation validation.
// An ineligible target blocks the whole selection; it is never silently skipped.
export function userBatchDisabledReason(action: UserBatchAction, context: UserBatchContext) {
  if (!context.canListUsers) return "forbidden";
  if (!context.supported) return "unsupported";
  if (!context.targets.length) return "empty";
  if (context.targets.length > userBatchLimit) return "limit";
  if (context.targets.some((target) => target.id === context.rootId)) return "primary";
  if (action === "add-groups") return null;
  if (action === "authorize") return context.targets.some((target) => !target.canAttachPolicy) ? "protected" : null;
  if (context.targets.some((target) => target.id === context.actorId)) return "self";
  if (action === "delete" && context.targets.some((target) => target.protected)) return "protected";
  if ((action === "enable" || action === "disable") && context.targets.some((target) => !target.canSetStatus)) return "protected";
  if (action === "enable" && context.targets.some((target) => target.enabled !== false)) return "notDisabled";
  if (action === "disable" && context.targets.some((target) => target.enabled !== true)) return "notEnabled";
  return null;
}

// One preview transaction spans directory identities and their workspace access.
// Both results are published by the adapter only after every check succeeds.
export function applyUserBatch(source: AccessWorkspace, users: UserAccess[], identity: AccountIdentity, command: UserBatchCommand, clock: { id: string; at: string; canListUsers: boolean }) {
  const invalid = () => { throw new AccessWorkspaceError("invalid"); };
  if (source.accountId !== identity.account.id || identity.user.accountId !== source.accountId ||
    users.some((entry) => entry.user.accountId !== source.accountId) || !userBatchActions.includes(command.action) ||
    new Set(command.targets.map((target) => target.id)).size !== command.targets.length) invalid();
  const directory = new Map(users.map((entry) => [entry.user.id, entry]));
  const rootId = identity.account.rootIdentity.principalId;
  const targets = command.targets.map((target) => {
    if (target.id === rootId) return { id: target.id, enabled: null, canSetStatus: false, canAttachPolicy: false, protected: true };
    const entry = directory.get(target.id);
    if (!entry) throw new AccessWorkspaceError("notFound");
    if (target.resourceVersion !== entry.user.resourceVersion) throw new AccessWorkspaceError("staleUsers");
    const capability = (action: string) => entry.capabilities.find((item) => item.action === action && item.resource.kind === "USER" && item.resource.id === entry.user.id);
    return {
      id: target.id,
      enabled: entry.user.status === "ACTIVE",
      canSetStatus: capability("iam.user.set-status")?.available === true,
      canAttachPolicy: capability("iam.policy-attachment.create")?.available === true,
      protected: entry.capabilities.some((item) => item.restrictionReason === "INSTALLATION_AUTHORITY_PROTECTED")
    };
  });
  const reason = userBatchDisabledReason(command.action, { targets, rootId, actorId: identity.user.id, supported: true, canListUsers: clock.canListUsers });
  if (reason) throw new AccessWorkspaceError("ineligibleUsers");
  const ids = new Set(targets.map((target) => target.id));
  const context = { id: clock.id, at: clock.at, primaryPrincipalId: rootId, userIds: users.map((entry) => entry.user.id) };
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
    nextUsers = users.filter((entry) => !ids.has(entry.user.id));
  } else {
    nextUsers = users.map((entry) => ids.has(entry.user.id) ? { ...entry, user: { ...entry.user, status: command.action === "enable" ? "ACTIVE" as const : "DISABLED" as const, resourceVersion: entry.user.resourceVersion + 1 } } : entry);
  }
  workspace = { ...workspace, events: [{ id: clock.id, action: "batch-users" as const, target: command.action + ": " + [...ids].join(", "), at: clock.at }, ...source.events].slice(0, 100) };
  return { workspace, users: nextUsers };
}
