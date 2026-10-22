import { afterEach, describe, expect, it } from "vitest";
import type { UserDeletionIntent } from "../domain/accounts";
import { clearUserDeletionIntent, parseUserDeletionIntent, readUserDeletionIntents, userDeletionStorageKey, writeUserDeletionIntent } from "./userDeletionRecoveryStorage";

const intent = (overrides: Partial<UserDeletionIntent> = {}): UserDeletionIntent => ({
  format: 1,
  accountId: "account-a",
  actorPrincipalId: "actor-a",
  userId: "user-a",
  loginName: "developer",
  expectedResourceVersion: 4,
  commandRequestId: `ui-user-delete-${"a".repeat(32)}`,
  ...overrides
});

afterEach(() => sessionStorage.clear());

describe("user deletion recovery storage", () => {
  it("round-trips and precisely clears one bounded target intent", () => {
    const original = intent();
    writeUserDeletionIntent(sessionStorage, original);
    expect(readUserDeletionIntents(sessionStorage, original)).toEqual([original]);
    expect(() => writeUserDeletionIntent(sessionStorage, original)).toThrow("USER_DELETION_REMINDER_EXISTS");
    clearUserDeletionIntent(sessionStorage, original);
    expect(readUserDeletionIntents(sessionStorage, original)).toEqual([]);
  });

  it("rejects open, malformed, and unbounded records", () => {
    const original = intent();
    expect(parseUserDeletionIntent({ ...original, extra: true })).toBeNull();
    expect(parseUserDeletionIntent({ ...original, commandRequestId: "request" })).toBeNull();
    expect(parseUserDeletionIntent({ ...original, loginName: "x".repeat(129) })).toBeNull();
    sessionStorage.setItem(userDeletionStorageKey(original), JSON.stringify({ ...original, actorPrincipalId: "actor-b" }));
    expect(() => readUserDeletionIntents(sessionStorage, original)).toThrow("INVALID_USER_DELETION_REMINDER");
    sessionStorage.setItem(userDeletionStorageKey(original), "x".repeat(4097));
    expect(() => readUserDeletionIntents(sessionStorage, original)).toThrow("INVALID_USER_DELETION_REMINDER");
  });

  it("does not enumerate or clear another owner record", () => {
    const foreign = intent({ actorPrincipalId: "actor-b" });
    writeUserDeletionIntent(sessionStorage, foreign);
    expect(readUserDeletionIntents(sessionStorage, intent())).toEqual([]);
    expect(sessionStorage.getItem(userDeletionStorageKey(foreign))).toBe(JSON.stringify(foreign));
    expect(() => clearUserDeletionIntent(sessionStorage, intent())).toThrow("USER_DELETION_REMINDER_CHANGED");
    expect(sessionStorage.getItem(userDeletionStorageKey(foreign))).toBe(JSON.stringify(foreign));
  });
});
