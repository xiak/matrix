import { userManagementDisplayNameValid, type UserManagementIntent } from "../domain/accounts";

export type UserManagementScope = Pick<UserManagementIntent, "accountId" | "actorPrincipalId" | "userId">;
const identifier = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const baseFields = ["format", "accountId", "actorPrincipalId", "userId", "commandRequestId", "expectedResourceVersion", "operation"];

export function userManagementStorageKey(scope: UserManagementScope): string {
  if (![scope.accountId, scope.actorPrincipalId, scope.userId].every((value) => typeof value === "string" && identifier.test(value))) throw new Error("INVALID_USER_MANAGEMENT_OWNER");
  return `matrix.iam.user-management.v1:${encodeURIComponent(JSON.stringify([scope.accountId, scope.actorPrincipalId, scope.userId]))}`;
}

export function parseUserManagementIntent(value: unknown): UserManagementIntent | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const record = value as Record<string, unknown>;
  const keys = [...baseFields, record.operation === "USER_UPDATE" ? "intendedDisplayName" : "intendedStatus"];
  if (record.format !== 1 || (record.operation !== "USER_UPDATE" && record.operation !== "USER_SET_STATUS") || Object.keys(record).length !== keys.length ||
      keys.some((key) => !Object.hasOwn(record, key)) || ["accountId", "actorPrincipalId", "userId", "commandRequestId"].some((key) => typeof record[key] !== "string" || !identifier.test(record[key] as string)) ||
      typeof record.expectedResourceVersion !== "number" || !Number.isSafeInteger(record.expectedResourceVersion) || record.expectedResourceVersion < 1 || record.expectedResourceVersion >= Number.MAX_SAFE_INTEGER) return null;
  const base = { format: 1 as const, accountId: record.accountId as string, actorPrincipalId: record.actorPrincipalId as string,
    userId: record.userId as string, commandRequestId: record.commandRequestId as string, expectedResourceVersion: record.expectedResourceVersion };
  if (record.operation === "USER_UPDATE") return userManagementDisplayNameValid(record.intendedDisplayName)
    ? Object.freeze({ ...base, operation: "USER_UPDATE", intendedDisplayName: record.intendedDisplayName }) : null;
  return record.intendedStatus === "ACTIVE" || record.intendedStatus === "DISABLED"
    ? Object.freeze({ ...base, operation: "USER_SET_STATUS", intendedStatus: record.intendedStatus }) : null;
}

export function readUserManagementIntent(storage: Storage, scope: UserManagementScope): UserManagementIntent | null {
  const raw = storage.getItem(userManagementStorageKey(scope));
  if (raw === null) return null;
  if (raw.length > 4096) throw new Error("INVALID_USER_MANAGEMENT_REMINDER");
  const intent = parseUserManagementIntent(JSON.parse(raw));
  if (!intent || intent.accountId !== scope.accountId || intent.actorPrincipalId !== scope.actorPrincipalId || intent.userId !== scope.userId) throw new Error("INVALID_USER_MANAGEMENT_REMINDER");
  return intent;
}

export function writeUserManagementIntent(storage: Storage, intent: UserManagementIntent): void {
  const parsed = parseUserManagementIntent(intent);
  if (!parsed || readUserManagementIntent(storage, parsed)) throw new Error("USER_MANAGEMENT_REMINDER_UNAVAILABLE");
  storage.setItem(userManagementStorageKey(parsed), JSON.stringify(parsed));
  if (JSON.stringify(readUserManagementIntent(storage, parsed)) !== JSON.stringify(parsed)) throw new Error("USER_MANAGEMENT_REMINDER_UNAVAILABLE");
}

export function clearUserManagementIntent(storage: Storage, intent: UserManagementIntent): void {
  if (JSON.stringify(readUserManagementIntent(storage, intent)) !== JSON.stringify(intent)) throw new Error("USER_MANAGEMENT_REMINDER_CHANGED");
  const key = userManagementStorageKey(intent);
  storage.removeItem(key);
  if (storage.getItem(key) !== null) throw new Error("USER_MANAGEMENT_REMINDER_UNAVAILABLE");
}
