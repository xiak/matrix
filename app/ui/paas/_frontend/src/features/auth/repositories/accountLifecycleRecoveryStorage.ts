import type { AccountLifecycleActor, AccountLifecycleIntent } from "../domain/accounts";

const identifier = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const fields = ["format", "actorAccountId", "actorPrincipalId", "operation", "accountId", "commandRequestId", "expectedResourceVersion"];

export function parseAccountLifecycleIntent(value: unknown): AccountLifecycleIntent | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const wire = value as Record<string, unknown>;
  const expected = wire.operation === "ACCOUNT_SET_STATUS" ? [...fields, "intendedStatus"] : fields;
  if (wire.format !== 1 || Object.keys(wire).length !== expected.length || expected.some((key) => !Object.hasOwn(wire, key))) return null;
  for (const key of ["actorAccountId", "actorPrincipalId", "accountId", "commandRequestId"]) {
    if (typeof wire[key] !== "string" || !identifier.test(wire[key])) return null;
  }
  if (typeof wire.expectedResourceVersion !== "number" || !Number.isSafeInteger(wire.expectedResourceVersion) ||
      wire.expectedResourceVersion < 0 || wire.expectedResourceVersion >= Number.MAX_SAFE_INTEGER) return null;
  const base = { format: 1 as const, actorAccountId: wire.actorAccountId as string, actorPrincipalId: wire.actorPrincipalId as string,
    accountId: wire.accountId as string, commandRequestId: wire.commandRequestId as string };
  if (wire.operation === "ACCOUNT_CREATE" && wire.expectedResourceVersion === 0) {
    return { ...base, operation: wire.operation, expectedResourceVersion: 0 };
  }
  if (wire.expectedResourceVersion < 1) return null;
  if (wire.operation === "ACCOUNT_SET_STATUS" && (wire.intendedStatus === "ACTIVE" || wire.intendedStatus === "DISABLED")) {
    return { ...base, operation: wire.operation, expectedResourceVersion: wire.expectedResourceVersion, intendedStatus: wire.intendedStatus };
  }
  if (wire.operation === "ACCOUNT_ROOT_CREDENTIALS_RECOVER") {
    return { ...base, operation: wire.operation, expectedResourceVersion: wire.expectedResourceVersion };
  }
  return null;
}

export function sameAccountLifecycleActor(left: AccountLifecycleActor, right: AccountLifecycleActor): boolean {
  return left.actorAccountId === right.actorAccountId && left.actorPrincipalId === right.actorPrincipalId;
}

export function accountLifecycleStorageKey(actor: AccountLifecycleActor): string {
  return `matrix.iam.account-lifecycle.v1:${encodeURIComponent(JSON.stringify([actor.actorAccountId, actor.actorPrincipalId]))}`;
}

export function readAccountLifecycleIntent(storage: Storage, actor: AccountLifecycleActor): AccountLifecycleIntent | null {
  const raw = storage.getItem(accountLifecycleStorageKey(actor));
  if (raw === null) return null;
  if (raw.length > 16_384) throw new Error("INVALID_ACCOUNT_LIFECYCLE_STORAGE");
  const intent = parseAccountLifecycleIntent(JSON.parse(raw));
  if (!intent || !sameAccountLifecycleActor(intent, actor)) throw new Error("INVALID_ACCOUNT_LIFECYCLE_STORAGE");
  return intent;
}

export function writeAccountLifecycleIntent(storage: Storage, intent: AccountLifecycleIntent): void {
  const parsed = parseAccountLifecycleIntent(intent);
  if (!parsed) throw new Error("INVALID_ACCOUNT_LIFECYCLE_STORAGE");
  storage.setItem(accountLifecycleStorageKey(parsed), JSON.stringify(parsed));
}

export function clearAccountLifecycleIntent(storage: Storage, intent: AccountLifecycleIntent): void {
  const parsed = parseAccountLifecycleIntent(intent);
  if (!parsed) throw new Error("INVALID_ACCOUNT_LIFECYCLE_STORAGE");
  const current = readAccountLifecycleIntent(storage, parsed);
  if (current && JSON.stringify(current) !== JSON.stringify(parsed)) throw new Error("ACCOUNT_LIFECYCLE_INTENT_CHANGED");
  storage.removeItem(accountLifecycleStorageKey(parsed));
}
