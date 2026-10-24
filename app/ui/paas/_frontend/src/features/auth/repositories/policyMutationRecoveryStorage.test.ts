import { afterEach, describe, expect, it, vi } from "vitest";
import type { PolicyMutationIntent } from "../domain/accounts";
import { clearPolicyMutationIntent, isPolicyMetadataMutationIntent, isPolicyVersionMutationIntent, parsePolicyMutationIntent, policyMutationStorageKey, readPolicyMutationIntent, withPolicyMutationLock, writePolicyMutationIntent } from "./policyMutationRecoveryStorage";

const intent: PolicyMutationIntent = { format: 1, kind: "update", accountId: "account-a", actorPrincipalId: "actor-a",
  policy: { id: "policy-a", accountId: "account-a", management: "CUSTOMER", scope: "TENANT", status: "ACTIVE",
    displayName: "Original policy", resourceVersion: 4, defaultVersionId: "version-a", createdAt: "2026-09-11T08:00:00Z", updatedAt: "2026-09-11T08:00:00Z" },
  contentDigest: `sha256:${"a".repeat(64)}`, requestId: "original-request", displayName: "Renamed policy", createdAt: "2000-01-01T00:00:00Z", state: "UNKNOWN" };
const oldLocks = Object.getOwnPropertyDescriptor(navigator, "locks");
afterEach(() => { localStorage.clear(); vi.restoreAllMocks(); if (oldLocks) Object.defineProperty(navigator, "locks", oldLocks); else Reflect.deleteProperty(navigator, "locks"); });

describe("Policy original-command recovery metadata", () => {
  it("retains an old unknown intent without a TTL and isolates account and actor keys", () => {
    writePolicyMutationIntent(localStorage, intent);
    expect(readPolicyMutationIntent(localStorage, intent)).toEqual(intent);
    expect(readPolicyMutationIntent(localStorage, { ...intent, actorPrincipalId: "actor-b" })).toBeNull();
    expect(readPolicyMutationIntent(localStorage, { ...intent, accountId: "account-b" })).toBeNull();
    expect(policyMutationStorageKey({ accountId: "a:b", actorPrincipalId: "c" })).not.toBe(policyMutationStorageKey({ accountId: "a", actorPrincipalId: "b:c" }));
    expect(Object.keys(JSON.parse(localStorage.getItem(policyMutationStorageKey(intent))!))).not.toContain("document");
    expect(isPolicyMetadataMutationIntent(readPolicyMutationIntent(localStorage, intent))).toBe(true);
  });
  it.each(["document", "credential", "sessionId", "decision", "proof", "expiresAt", "permit"])("rejects a record carrying %s rather than silently stripping it", (field) => {
    const invalid = { ...intent, [field]: "not-recovery-metadata" };
    expect(parsePolicyMutationIntent(invalid)).toBeNull();
    expect(() => writePolicyMutationIntent(localStorage, invalid)).toThrow();
    expect(localStorage.length).toBe(0);
  });
  it("preserves the one-pending-item capacity and never clears a changed original command", () => {
    writePolicyMutationIntent(localStorage, intent);
    expect(() => writePolicyMutationIntent(localStorage, { ...intent, requestId: "other-request" })).toThrow("POLICY_MUTATION_PENDING");
    expect(() => clearPolicyMutationIntent(localStorage, { ...intent, displayName: "Other name" })).toThrow("POLICY_MUTATION_CHANGED");
    expect(readPolicyMutationIntent(localStorage, intent)).toEqual(intent);
    clearPolicyMutationIntent(localStorage, intent);
    expect(readPolicyMutationIntent(localStorage, intent)).toBeNull();
  });
  it.each(["invalid-json", "x".repeat(96 * 1024 + 1), JSON.stringify({ ...intent, actorPrincipalId: "foreign-actor" }),
    JSON.stringify({ ...intent, policy: { ...intent.policy, status: "RETIRED" } }),
    JSON.stringify({ ...intent, policy: { ...intent.policy, document: {} } })])("does not evict malformed stored evidence to admit a new write", (raw) => {
    localStorage.setItem(policyMutationStorageKey(intent), raw);
    expect(() => readPolicyMutationIntent(localStorage, intent)).toThrow();
    expect(() => writePolicyMutationIntent(localStorage, intent)).toThrow();
    expect(localStorage.getItem(policyMutationStorageKey(intent))).toBe(raw);
  });
  it("retains one exact version command in the same actor-scoped policy slot", () => {
    const publish: PolicyMutationIntent = { format: 1, kind: "publish-version", accountId: intent.accountId,
      actorPrincipalId: intent.actorPrincipalId, policy: intent.policy, contentDigest: intent.contentDigest,
      requestId: "publish-version-request", createdAt: intent.createdAt, state: "UNKNOWN",
      documentJSON: JSON.stringify({ languageVersion: "1", scope: "TENANT", statements: [{ sid: "read", effect: "ALLOW",
        actions: ["paas.application.read"], resources: [{ kind: "APPLICATION", match: "ANY_IN_AUTHORITY" }] }] }) };
    writePolicyMutationIntent(localStorage, publish);
    const stored = readPolicyMutationIntent(localStorage, publish);
    expect(stored).toEqual(publish);
    expect(isPolicyVersionMutationIntent(stored)).toBe(true);
    expect(isPolicyMetadataMutationIntent(stored)).toBe(false);
    expect(() => writePolicyMutationIntent(localStorage, intent)).toThrow("POLICY_MUTATION_PENDING");
    clearPolicyMutationIntent(localStorage, publish);

    const versionBase = { format: 1 as const, accountId: intent.accountId, actorPrincipalId: intent.actorPrincipalId,
      policy: intent.policy, contentDigest: intent.contentDigest, createdAt: intent.createdAt, state: "UNKNOWN" as const };
    for (const version of [
      { ...versionBase, kind: "set-default-version" as const, requestId: "set-default-request", versionId: "version-b" },
      { ...versionBase, kind: "retire-version" as const, requestId: "retire-version-request", versionId: "version-b" }
    ]) {
      writePolicyMutationIntent(localStorage, version);
      expect(readPolicyMutationIntent(localStorage, version)).toEqual(version);
      clearPolicyMutationIntent(localStorage, version);
    }
  });
  it("rejects storage failure rather than returning a fabricated empty slot", () => {
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => { throw new Error("storage unavailable"); });
    expect(() => readPolicyMutationIntent(localStorage, intent)).toThrow();
    expect(() => writePolicyMutationIntent(localStorage, intent)).toThrow();
  });
  it("refuses an attempt without cross-tab coordination", async () => {
    Object.defineProperty(navigator, "locks", { configurable: true, value: undefined });
    const send = vi.fn();
    await expect(withPolicyMutationLock(intent, send)).rejects.toThrow("POLICY_MUTATION_COORDINATION_UNAVAILABLE");
    expect(send).not.toHaveBeenCalled();
  });
  it("admits one holder, rejects a competing tab and can recover after the holder releases", async () => {
    const held = new Set<string>();
    Object.defineProperty(navigator, "locks", { configurable: true, value: { request: async (name: string, _options: LockOptions, run: (lock: Lock | null) => unknown) => {
      if (held.has(name)) return run(null);
      held.add(name);
      try { return await run({ name, mode: "exclusive" }); } finally { held.delete(name); }
    } } });
    let release!: () => void;
    const send = vi.fn(() => new Promise<void>((resolve) => { release = resolve; }));
    const first = withPolicyMutationLock(intent, send);
    await expect(withPolicyMutationLock(intent, send)).rejects.toThrow("POLICY_MUTATION_BUSY");
    expect(send).toHaveBeenCalledOnce();
    release(); await first;
    await expect(withPolicyMutationLock(intent, async () => "recovered")).resolves.toBe("recovered");
  });
});
