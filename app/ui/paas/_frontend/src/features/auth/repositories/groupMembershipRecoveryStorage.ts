import type { GroupMembershipMutationIntent } from "../domain/accounts";

export type GroupMembershipMutationScope = Pick<GroupMembershipMutationIntent, "accountId" | "actorPrincipalId" | "groupId">;
const identifier = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const fields = ["format", "operation", "accountId", "actorPrincipalId", "groupId", "userId", "requestId"];

export function groupMembershipStorageKey(scope: GroupMembershipMutationScope): string {
  if (![scope.accountId, scope.actorPrincipalId, scope.groupId].every((value) => typeof value === "string" && identifier.test(value))) throw new Error("INVALID_MEMBERSHIP_OWNER");
  return `matrix.iam.group-membership.v1:${encodeURIComponent(JSON.stringify([scope.accountId, scope.actorPrincipalId, scope.groupId]))}`;
}

export function parseGroupMembershipIntent(value: unknown): GroupMembershipMutationIntent | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const record = value as Record<string, unknown>;
  const keys = record.operation === "CREATE" ? fields : [...fields, "membershipId", "resourceVersion"];
  if (record.format !== 1 || (record.operation !== "CREATE" && record.operation !== "REMOVE") || Object.keys(record).length !== keys.length ||
      keys.some((key) => !Object.hasOwn(record, key)) || ["accountId", "actorPrincipalId", "groupId", "userId", "requestId"].some((key) => typeof record[key] !== "string" || !identifier.test(record[key] as string))) return null;
  const base = { format: 1 as const, accountId: record.accountId as string, actorPrincipalId: record.actorPrincipalId as string,
    groupId: record.groupId as string, userId: record.userId as string, requestId: record.requestId as string };
  if (record.operation === "CREATE") return Object.freeze({ ...base, operation: "CREATE" });
  if (typeof record.membershipId !== "string" || !identifier.test(record.membershipId) || typeof record.resourceVersion !== "number" ||
      !Number.isSafeInteger(record.resourceVersion) || record.resourceVersion < 1 || record.resourceVersion >= Number.MAX_SAFE_INTEGER) return null;
  return Object.freeze({ ...base, operation: "REMOVE", membershipId: record.membershipId, resourceVersion: record.resourceVersion });
}

export function readGroupMembershipIntent(storage: Storage, scope: GroupMembershipMutationScope): GroupMembershipMutationIntent | null {
  const raw = storage.getItem(groupMembershipStorageKey(scope));
  if (raw === null) return null;
  if (raw.length > 4096) throw new Error("INVALID_MEMBERSHIP_REMINDER");
  const intent = parseGroupMembershipIntent(JSON.parse(raw));
  if (!intent || intent.accountId !== scope.accountId || intent.actorPrincipalId !== scope.actorPrincipalId || intent.groupId !== scope.groupId) throw new Error("INVALID_MEMBERSHIP_REMINDER");
  return intent;
}

export function writeGroupMembershipIntent(storage: Storage, intent: GroupMembershipMutationIntent): void {
  const parsed = parseGroupMembershipIntent(intent);
  if (!parsed || readGroupMembershipIntent(storage, parsed)) throw new Error("MEMBERSHIP_REMINDER_UNAVAILABLE");
  storage.setItem(groupMembershipStorageKey(parsed), JSON.stringify(parsed));
  if (JSON.stringify(readGroupMembershipIntent(storage, parsed)) !== JSON.stringify(parsed)) throw new Error("MEMBERSHIP_REMINDER_UNAVAILABLE");
}

export function clearGroupMembershipIntent(storage: Storage, intent: GroupMembershipMutationIntent): void {
  if (JSON.stringify(readGroupMembershipIntent(storage, intent)) !== JSON.stringify(intent)) throw new Error("MEMBERSHIP_REMINDER_CHANGED");
  const key = groupMembershipStorageKey(intent);
  storage.removeItem(key);
  if (storage.getItem(key) !== null) throw new Error("MEMBERSHIP_REMINDER_UNAVAILABLE");
}
