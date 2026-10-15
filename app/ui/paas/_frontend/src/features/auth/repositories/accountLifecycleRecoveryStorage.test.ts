import { afterEach, describe, expect, it } from "vitest";
import type { AccountLifecycleIntent } from "../domain/accounts";
import { accountLifecycleStorageKey, clearAccountLifecycleIntent, parseAccountLifecycleIntent, readAccountLifecycleIntent, writeAccountLifecycleIntent } from "./accountLifecycleRecoveryStorage";

const actor = { actorAccountId: "platform-account", actorPrincipalId: "operator-user" };
const base = { format: 1 as const, ...actor, accountId: "customer-account", commandRequestId: "original-account-command" };
const intents: AccountLifecycleIntent[] = [
  { ...base, operation: "ACCOUNT_CREATE", expectedResourceVersion: 0 },
  { ...base, operation: "ACCOUNT_SET_STATUS", expectedResourceVersion: 3, intendedStatus: "DISABLED" },
  { ...base, operation: "ACCOUNT_ROOT_CREDENTIALS_RECOVER", expectedResourceVersion: 3 }
];

afterEach(() => localStorage.clear());

describe("non-sensitive account lifecycle recovery summaries", () => {
  it.each(intents)("round-trips only the original $operation identity without credentials or a command payload", (intent) => {
    writeAccountLifecycleIntent(localStorage, intent);
    expect(readAccountLifecycleIntent(localStorage, actor)).toEqual(intent);
    expect(parseAccountLifecycleIntent(JSON.parse(localStorage.getItem(accountLifecycleStorageKey(actor))!))).toEqual(intent);
    expect(readAccountLifecycleIntent(localStorage, { ...actor, actorPrincipalId: "another-user" })).toBeNull();
    clearAccountLifecycleIntent(localStorage, intent);
    expect(readAccountLifecycleIntent(localStorage, actor)).toBeNull();
  });

  it.each(["password", "initialPassword", "passwordHash", "credential", "bearer", "digest", "command", "decision", "permit"])(
    "rejects a summary bearing %s rather than stripping it into an accepted record", (field) => {
      const unsafe = { ...intents[0]!, [field]: "not-exportable" };
      expect(parseAccountLifecycleIntent(unsafe)).toBeNull();
      expect(() => writeAccountLifecycleIntent(localStorage, unsafe as AccountLifecycleIntent)).toThrow();
      expect(localStorage.length).toBe(0);
    }
  );

  it.each([
    { format: 2 }, { operation: "ACCOUNT_DELETE" }, { accountId: "../foreign" }, { commandRequestId: "" },
    { actorAccountId: "" }, { actorPrincipalId: "" }, { expectedResourceVersion: "0" },
    { expectedResourceVersion: -1 }, { expectedResourceVersion: 1 }, { expectedResourceVersion: 0.5 },
    { expectedResourceVersion: Number.MAX_SAFE_INTEGER }, { intendedStatus: "ACTIVE" }
  ])("rejects malformed or operation-incompatible original identities: %j", (change) => {
    expect(parseAccountLifecycleIntent({ ...intents[0], ...change })).toBeNull();
  });

  it("requires the exact original status intent and positive versions outside creation", () => {
    for (const operation of ["ACCOUNT_SET_STATUS", "ACCOUNT_ROOT_CREDENTIALS_RECOVER"]) {
      expect(parseAccountLifecycleIntent({ ...base, operation, expectedResourceVersion: 0 })).toBeNull();
    }
    expect(parseAccountLifecycleIntent({ ...intents[1], intendedStatus: "UNKNOWN" })).toBeNull();
    const missing = { ...intents[1] } as Record<string, unknown>;
    delete missing.intendedStatus;
    expect(parseAccountLifecycleIntent(missing)).toBeNull();
    expect(parseAccountLifecycleIntent({ ...intents[2], expectedResourceVersion: Number.MAX_SAFE_INTEGER - 1 })).toBeTruthy();
  });

  it("keeps original actor components distinct and never clears another actor or a newer command", () => {
    const first = { ...intents[0]!, actorAccountId: "a:b", actorPrincipalId: "c" };
    const second = { ...intents[0]!, actorAccountId: "a", actorPrincipalId: "b:c" };
    writeAccountLifecycleIntent(localStorage, first);
    writeAccountLifecycleIntent(localStorage, second);
    clearAccountLifecycleIntent(localStorage, first);
    expect(readAccountLifecycleIntent(localStorage, second)).toEqual(second);
    expect(() => clearAccountLifecycleIntent(localStorage, { ...second, commandRequestId: "older-command" })).toThrow();
    expect(readAccountLifecycleIntent(localStorage, second)).toEqual(second);
  });

  it("does not silently discard malformed or foreign stored evidence to unlock another write", () => {
    const key = accountLifecycleStorageKey(actor);
    for (const raw of ["broken-json", JSON.stringify({ ...intents[0], credential: "not-exportable" }),
      JSON.stringify({ ...intents[0], actorPrincipalId: "another-user" })]) {
      localStorage.setItem(key, raw);
      expect(() => readAccountLifecycleIntent(localStorage, actor)).toThrow();
      expect(localStorage.getItem(key)).toBe(raw);
    }
  });
});
