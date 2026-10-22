import type { UserDeletionIntent } from "../domain/accounts";

export type UserDeletionOwner = Pick<UserDeletionIntent, "accountId" | "actorPrincipalId">;
export type UserDeletionTarget = UserDeletionOwner & Pick<UserDeletionIntent, "userId">;

const identifier = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const fields = ["format", "accountId", "actorPrincipalId", "userId", "loginName", "expectedResourceVersion", "commandRequestId"];
const storagePrefix = "matrix.iam.user-deletion.v1:";

function validIdentifier(value: unknown): value is string {
  return typeof value === "string" && identifier.test(value);
}

function ownerStoragePrefix(owner: UserDeletionOwner): string {
  if (!validIdentifier(owner.accountId) || !validIdentifier(owner.actorPrincipalId)) throw new Error("INVALID_USER_DELETION_OWNER");
  return `${storagePrefix}${encodeURIComponent(owner.accountId)}:${encodeURIComponent(owner.actorPrincipalId)}:`;
}

export function userDeletionStorageKey(target: UserDeletionTarget): string {
  if (!validIdentifier(target.userId)) throw new Error("INVALID_USER_DELETION_TARGET");
  return ownerStoragePrefix(target) + encodeURIComponent(target.userId);
}

export function parseUserDeletionIntent(value: unknown): UserDeletionIntent | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const record = value as Record<string, unknown>;
  if (Object.keys(record).length !== fields.length || fields.some((field) => !Object.hasOwn(record, field)) || record.format !== 1 ||
      !validIdentifier(record.accountId) || !validIdentifier(record.actorPrincipalId) || !validIdentifier(record.userId) ||
      typeof record.loginName !== "string" || record.loginName.trim() !== record.loginName || !record.loginName || Array.from(record.loginName).length > 128 ||
      typeof record.expectedResourceVersion !== "number" || !Number.isSafeInteger(record.expectedResourceVersion) ||
      record.expectedResourceVersion < 1 || record.expectedResourceVersion >= Number.MAX_SAFE_INTEGER ||
      typeof record.commandRequestId !== "string" || !/^ui-user-delete-[0-9a-f]{32}$/.test(record.commandRequestId)) return null;
  return Object.freeze({
    format: 1,
    accountId: record.accountId,
    actorPrincipalId: record.actorPrincipalId,
    userId: record.userId,
    loginName: record.loginName,
    expectedResourceVersion: record.expectedResourceVersion,
    commandRequestId: record.commandRequestId
  });
}

export function readUserDeletionIntents(storage: Storage, owner: UserDeletionOwner): readonly UserDeletionIntent[] {
  const prefix = ownerStoragePrefix(owner);
  const intents: UserDeletionIntent[] = [];
  if (storage.length > 4096) throw new Error("USER_DELETION_REMINDER_DIRECTORY_TOO_LARGE");
  for (let index = 0; index < storage.length; index += 1) {
    const key = storage.key(index);
    if (key === null || !key.startsWith(prefix)) continue;
    const raw = storage.getItem(key);
    if (raw === null || raw.length > 4096) throw new Error("INVALID_USER_DELETION_REMINDER");
    const intent = parseUserDeletionIntent(JSON.parse(raw));
    if (!intent || intent.accountId !== owner.accountId || intent.actorPrincipalId !== owner.actorPrincipalId ||
        userDeletionStorageKey(intent) !== key || intents.some((known) => known.userId === intent.userId)) {
      throw new Error("INVALID_USER_DELETION_REMINDER");
    }
    intents.push(intent);
    if (intents.length > 100) throw new Error("USER_DELETION_REMINDER_LIMIT_EXCEEDED");
  }
  return Object.freeze(intents.sort((left, right) => left.userId.localeCompare(right.userId)));
}

export function writeUserDeletionIntent(storage: Storage, intent: UserDeletionIntent): void {
  const parsed = parseUserDeletionIntent(intent);
  if (!parsed) throw new Error("INVALID_USER_DELETION_INTENT");
  const existing = readUserDeletionIntents(storage, parsed);
  if (existing.some((known) => known.userId === parsed.userId)) throw new Error("USER_DELETION_REMINDER_EXISTS");
  storage.setItem(userDeletionStorageKey(parsed), JSON.stringify(parsed));
  const written = readUserDeletionIntents(storage, parsed).find((known) => known.userId === parsed.userId);
  if (JSON.stringify(written) !== JSON.stringify(parsed)) throw new Error("USER_DELETION_REMINDER_UNAVAILABLE");
}

export function clearUserDeletionIntent(storage: Storage, intent: UserDeletionIntent): void {
  const current = readUserDeletionIntents(storage, intent).find((known) => known.userId === intent.userId);
  if (JSON.stringify(current) !== JSON.stringify(intent)) throw new Error("USER_DELETION_REMINDER_CHANGED");
  const key = userDeletionStorageKey(intent);
  storage.removeItem(key);
  if (storage.getItem(key) !== null) throw new Error("USER_DELETION_REMINDER_UNAVAILABLE");
}
