import { act, cleanup, renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { HttpProblem } from "@/infrastructure/http/jsonRequest";
import type { AccountPolicyDetail, PolicyMutationIntent } from "../domain/accounts";
import { policyMutationStorageKey, readPolicyMutationIntent } from "../repositories/policyMutationRecoveryStorage";
import { useLivePolicyMutation, type PolicyMutationResult } from "./policyMutation";

const detail: AccountPolicyDetail = {
  policy: { id: "customer.logs", accountId: "account-a", management: "CUSTOMER", scope: "TENANT", status: "ACTIVE", displayName: "Log reader",
    resourceVersion: 4, defaultVersionId: "version-a", createdAt: "2026-09-11T08:00:00Z", updatedAt: "2026-09-11T08:00:00Z" },
  version: { policyId: "customer.logs", versionId: "version-a", contentDigest: `sha256:${"a".repeat(64)}`, contractVersion: 1,
    document: { languageVersion: "1", scope: "TENANT", statements: [{ sid: "logs", effect: "ALLOW", actions: ["paas.application.read"], resources: [{ kind: "APPLICATION", match: "ANY_IN_AUTHORITY" }] }] } }
};
const rename = { kind: "update" as const, displayName: "Production reader" };
const renamed = (): AccountPolicyDetail => ({ policy: { ...detail.policy, displayName: rename.displayName, resourceVersion: 5 }, version: structuredClone(detail.version) });
const retired = () => ({ ...detail.policy, status: "RETIRED" as const, resourceVersion: 5 });
const owner = { accountId: "account-a", actorPrincipalId: "user-a" };
const options = () => ({ enabled: true, ...owner, credential: "old-bearer", sessionRevision: 1,
  repository: { updatePolicy: vi.fn().mockResolvedValue(renamed()), deletePolicy: vi.fn().mockResolvedValue(retired()) },
  protect: <T,>(run: () => Promise<T>) => run(), onExpired: vi.fn(), versionPolicyId: undefined as string | undefined,
  authorityPending: false, authorizeBegin: vi.fn().mockReturnValue(true) });
const locksDescriptor = Object.getOwnPropertyDescriptor(navigator, "locks");
beforeEach(() => {
  const held = new Set<string>();
  Object.defineProperty(navigator, "locks", { configurable: true, value: { request: async (name: string, _options: LockOptions, run: (lock: Lock | null) => unknown) => {
    if (held.has(name)) return run(null);
    held.add(name);
    try { return await run({ name, mode: "exclusive" }); } finally { held.delete(name); }
  } } });
});
afterEach(() => {
  cleanup(); localStorage.clear(); vi.restoreAllMocks();
  if (locksDescriptor) Object.defineProperty(navigator, "locks", locksDescriptor); else Reflect.deleteProperty(navigator, "locks");
});
async function open(props = options()) {
  const hook = renderHook((current) => useLivePolicyMutation(current), { initialProps: props });
  await waitFor(() => expect(hook.result.current?.ready).toBe(true));
  return hook;
}

describe("LIVE Policy original-command lifecycle", () => {
  it("freezes new writes during authority refresh and requires the current exact target before dispatch", async () => {
    const props = options(); props.authorityPending = true;
    const hook = renderHook((current) => useLivePolicyMutation(current), { initialProps: props });
    await waitFor(() => expect(hook.result.current).not.toBeNull());
    expect(hook.result.current!.ready).toBe(false);
    await act(async () => { expect(await hook.result.current!.begin(detail, rename)).toEqual({ status: "blocked" }); });
    expect(props.repository.updatePolicy).not.toHaveBeenCalled();
    hook.rerender({ ...props, authorityPending: false });
    await waitFor(() => expect(hook.result.current!.ready).toBe(true));
    props.authorizeBegin.mockReturnValue(false);
    hook.rerender({ ...props, authorityPending: false });
    await act(async () => { expect(await hook.result.current!.begin(detail, rename)).toEqual({ status: "blocked" }); });
    expect(props.repository.updatePolicy).not.toHaveBeenCalled();
  });

  it("freezes an UNKNOWN original request during recheck, then retries it without requiring a new target authorization", async () => {
    const props = options(); props.repository.updatePolicy.mockRejectedValueOnce(new Error("lost"));
    const hook = await open(props);
    await act(async () => { expect(await hook.result.current!.begin(detail, rename)).toEqual({ status: "unknown" }); });
    const requestId = hook.result.current!.pending?.requestId;
    hook.rerender({ ...props, authorityPending: true });
    await waitFor(() => expect(hook.result.current!.ready).toBe(false));
    expect(hook.result.current!.pending?.requestId).toBe(requestId);
    await act(async () => { expect(await hook.result.current!.retry()).toEqual({ status: "blocked" }); });
    expect(props.repository.updatePolicy).toHaveBeenCalledTimes(1);
    expect(readPolicyMutationIntent(localStorage, owner)?.requestId).toBe(requestId);
    hook.rerender({ ...props, authorityPending: false, authorizeBegin: vi.fn().mockReturnValue(false) });
    await waitFor(() => expect(hook.result.current!.ready).toBe(true));
    await act(async () => { expect(await hook.result.current!.retry()).toMatchObject({ status: "applied" }); });
    expect(props.repository.updatePolicy.mock.calls[1]).toEqual(props.repository.updatePolicy.mock.calls[0]);
  });

  it("rechecks the live authority fence after acquiring a delayed browser lock", async () => {
    const props = options(); props.repository.updatePolicy.mockRejectedValueOnce(new Error("lost"));
    const hook = await open(props);
    await act(async () => { expect(await hook.result.current!.begin(detail, rename)).toEqual({ status: "unknown" }); });
    const original = localStorage.getItem(policyMutationStorageKey(owner));
    let releaseLock!: () => Promise<void>;
    Object.defineProperty(navigator, "locks", { configurable: true, value: { request: (name: string, _options: LockOptions,
      run: (lock: Lock | null) => unknown) => new Promise((resolve, reject) => {
      releaseLock = async () => { try { resolve(await run({ name, mode: "exclusive" })); } catch (failure) { reject(failure); } };
    }) } });
    let retry!: Promise<PolicyMutationResult>;
    await act(async () => { retry = hook.result.current!.retry(); await Promise.resolve(); });
    hook.rerender({ ...props, authorityPending: true });
    await waitFor(() => expect(hook.result.current!.ready).toBe(false));
    await act(async () => { await releaseLock(); expect(await retry).toEqual({ status: "blocked" }); });
    expect(props.repository.updatePolicy).toHaveBeenCalledTimes(1);
    expect(localStorage.getItem(policyMutationStorageKey(owner))).toBe(original);
    expect(hook.result.current!.pending?.state).toBe("UNKNOWN");
  });

  it("journals metadata before sending one frozen rename, then accepts only the matching result", async () => {
    const props = options();
    props.repository.updatePolicy.mockImplementation(async () => {
      const stored = readPolicyMutationIntent(localStorage, owner)!;
      expect(stored).toMatchObject({ ...owner, kind: "update", displayName: rename.displayName, policy: detail.policy, contentDigest: detail.version.contentDigest });
      expect(JSON.stringify(stored)).not.toMatch(/old-bearer|document|sessionId|permission|proof/);
      return renamed();
    });
    const { result } = await open(props);
    const source = structuredClone(detail);
    await act(async () => { expect(await result.current!.begin(source, rename)).toMatchObject({ status: "applied", policy: renamed().policy }); });
    expect(props.repository.updatePolicy).toHaveBeenCalledExactlyOnceWith("old-bearer", owner.accountId,
      { policy: detail.policy, contentDigest: detail.version.contentDigest },
      { displayName: rename.displayName, resourceVersion: 4, requestId: expect.stringMatching(/^ui-policy-metadata-/) });
    expect(source).toEqual(detail);
    expect(props.repository.deletePolicy).not.toHaveBeenCalled();
    expect(result.current!.pending).toBeNull();
    expect(readPolicyMutationIntent(localStorage, owner)).toBeNull();
  });

  it("retires the whole Policy using its original revision, not a version or detach command", async () => {
    const props = options();
    const { result } = await open(props);
    await act(async () => { expect(await result.current!.begin(detail, { kind: "retire" })).toEqual({ status: "applied", policy: retired() }); });
    expect(props.repository.deletePolicy).toHaveBeenCalledExactlyOnceWith("old-bearer", owner.accountId, detail.policy,
      { resourceVersion: 4, requestId: expect.stringMatching(/^ui-policy-metadata-/) });
    expect(props.repository.updatePolicy).not.toHaveBeenCalled();
  });

  it("rejects ineligible, stale-version and invalid-name input without writes", async () => {
    const props = options();
    const { result, rerender } = await open(props);
    for (const displayName of ["", " surrounding ", "a\nb", "汉".repeat(43), detail.policy.displayName]) {
      await act(async () => { expect(await result.current!.begin(detail, { kind: "update", displayName })).toEqual({ status: "blocked" }); });
    }
    for (const patch of [{ accountId: "other" }, { management: "SYSTEM" as const }, { scope: "INSTALLATION" as const }, { status: "RETIRED" as const }, { resourceVersion: 0 }]) {
      await act(async () => { expect(await result.current!.begin({ ...detail, policy: { ...detail.policy, ...patch } }, rename)).toEqual({ status: "blocked" }); });
    }
    await act(async () => { expect(await result.current!.begin({ ...detail, version: { ...detail.version, versionId: "other" } }, rename)).toEqual({ status: "blocked" }); });
    rerender({ ...props, versionPolicyId: detail.policy.id });
    await act(async () => { expect(await result.current!.begin(detail, rename)).toEqual({ status: "blocked" }); });
    expect(props.repository.updatePolicy).not.toHaveBeenCalled(); expect(props.repository.deletePolicy).not.toHaveBeenCalled();
    expect(localStorage.length).toBe(0);
  });

  it.each([400, 401, 403, 404, 409, 422])("clears an initial explicit %s rejection, expiring only the originating Session for 401", async (status) => {
    const props = options(); props.repository.updatePolicy.mockRejectedValue(new HttpProblem(status, "REJECTED"));
    const { result } = await open(props);
    await act(async () => { expect((await result.current!.begin(detail, rename)).status).toBe("rejected"); });
    expect(result.current!.pending).toBeNull(); expect(readPolicyMutationIntent(localStorage, owner)).toBeNull();
    if (status === 401) expect(props.onExpired).toHaveBeenCalledExactlyOnceWith("old-bearer", 1); else expect(props.onExpired).not.toHaveBeenCalled();
  });

  it.each([new Error("response lost"), new HttpProblem(503, "UNAVAILABLE")])("retains uncertainty across a full unmount and retries only the original command with a new bearer", async (failure) => {
    const props = options(); props.repository.updatePolicy.mockRejectedValueOnce(failure);
    const first = await open(props);
    await act(async () => { expect(await first.result.current!.begin(detail, rename)).toEqual({ status: "unknown" }); });
    const stored = localStorage.getItem(policyMutationStorageKey(owner));
    const original = props.repository.updatePolicy.mock.calls[0]!;
    first.unmount();
    const next = { ...props, credential: "new-bearer", sessionRevision: 2 };
    const second = await open(next);
    expect(second.result.current!.pending).toMatchObject({ kind: "update", requestId: original[3].requestId });
    expect(localStorage.getItem(policyMutationStorageKey(owner))).toBe(stored);
    expect(props.repository.updatePolicy).toHaveBeenCalledTimes(1);
    await act(async () => { expect((await second.result.current!.retry()).status).toBe("applied"); });
    expect(props.repository.updatePolicy.mock.calls[1]).toEqual(["new-bearer", ...original.slice(1)]);
    expect(localStorage.length).toBe(0);
  });

  it.each([401, 403, 409, 503])("does not reclassify an unknown original request after a later %s retry", async (status) => {
    const props = options(); props.repository.updatePolicy.mockRejectedValueOnce(new Error("lost")).mockRejectedValueOnce(new HttpProblem(status, "RETRY"));
    const { result } = await open(props);
    await act(async () => { await result.current!.begin(detail, rename); });
    const original = localStorage.getItem(policyMutationStorageKey(owner));
    await act(async () => { expect(await result.current!.retry()).toEqual({ status: "unknown" }); });
    expect(localStorage.getItem(policyMutationStorageKey(owner))).toBe(original);
    expect(result.current!.pending?.state).toBe("UNKNOWN");
    expect(props.repository.updatePolicy.mock.calls[1]).toEqual(props.repository.updatePolicy.mock.calls[0]);
    await act(async () => { expect(await result.current!.begin(detail, { kind: "retire" })).toEqual({ status: "blocked" }); });
    expect(props.repository.deletePolicy).not.toHaveBeenCalled();
  });

  it("keeps an uncommitted retirement locked when the byte-identical retry is now forbidden", async () => {
    const props = options();
    props.repository.deletePolicy.mockRejectedValueOnce(new HttpProblem(503, "LOST"))
      .mockRejectedValueOnce(new HttpProblem(403, "REVOKED"));
    const { result } = await open(props);
    await act(async () => { expect(await result.current!.begin(detail, { kind: "retire" })).toEqual({ status: "unknown" }); });
    const original = props.repository.deletePolicy.mock.calls[0]!;
    const stored = localStorage.getItem(policyMutationStorageKey(owner));
    await act(async () => { expect(await result.current!.retry()).toEqual({ status: "unknown" }); });
    expect(props.repository.deletePolicy.mock.calls[1]).toEqual(original);
    expect(localStorage.getItem(policyMutationStorageKey(owner))).toBe(stored);
    expect(result.current!.pending).toMatchObject({ kind: "retire", requestId: original[3].requestId, state: "UNKNOWN" });
    expect(result.current!.lastError).toBe("forbidden");
  });

  it.each(["target", "default", "digest", "revision"])("keeps a successful-looking rename with wrong %s correlation unknown", async (field) => {
    const props = options(); const invalid = renamed();
    if (field === "target") invalid.policy.id = "foreign";
    if (field === "default") invalid.policy.defaultVersionId = "foreign";
    if (field === "digest") invalid.version.contentDigest = `sha256:${"b".repeat(64)}`;
    if (field === "revision") invalid.policy.resourceVersion = 7;
    props.repository.updatePolicy.mockResolvedValue(invalid);
    const { result } = await open(props);
    await act(async () => { expect(await result.current!.begin(detail, rename)).toEqual({ status: "unknown" }); });
    expect(readPolicyMutationIntent(localStorage, owner)?.state).toBe("UNKNOWN");
  });

  it("coordinates two mounted tabs and prevents retry, abandonment or duplicate dispatch while a holder is in flight", async () => {
    const props = options(); let release!: (value: AccountPolicyDetail) => void;
    props.repository.updatePolicy.mockImplementationOnce(() => new Promise((resolve) => { release = resolve; }));
    const first = await open(props); const second = await open(props);
    let flight!: Promise<PolicyMutationResult>;
    await act(async () => { flight = first.result.current!.begin(detail, rename); await Promise.resolve(); });
    expect(second.result.current!.pending).not.toBeNull();
    await act(async () => { expect(await second.result.current!.retry()).toEqual({ status: "blocked" }); expect(await second.result.current!.abandon()).toBe(false); });
    expect(props.repository.updatePolicy).toHaveBeenCalledTimes(1);
    await act(async () => { release(renamed()); expect((await flight).status).toBe("applied"); });
    expect(second.result.current!.pending).toBeNull(); expect(localStorage.length).toBe(0);
  });

  it.each(["credential", "sessionRevision", "repository", "accountId", "actorPrincipalId"])("fences a delayed old response after %s changes without clearing its journal", async (field) => {
    const props = options(); let reject!: (failure: unknown) => void;
    props.repository.updatePolicy.mockImplementationOnce(() => new Promise((_resolve, fail) => { reject = fail; }));
    const { result, rerender } = await open(props); let flight!: Promise<PolicyMutationResult>;
    await act(async () => { flight = result.current!.begin(detail, rename); await Promise.resolve(); });
    const original = localStorage.getItem(policyMutationStorageKey(owner));
    const next = { ...props, ...(field === "repository" ? { repository: options().repository } : field === "sessionRevision" ? { sessionRevision: 2 } : { [field]: "changed" }) };
    rerender(next); await waitFor(() => expect(result.current?.ready).toBe(true));
    await act(async () => { reject(new HttpProblem(401, "LATE")); expect(await flight).toEqual({ status: "blocked" }); });
    expect(props.onExpired).not.toHaveBeenCalled(); expect(localStorage.getItem(policyMutationStorageKey(owner))).toBe(original);
    expect(result.current!.pending === null).toBe(field === "accountId" || field === "actorPrincipalId");
  });

  it("does not clear a delayed successful old reply after re-authentication, then admits an explicit equal retry", async () => {
    const props = options(); let release!: (value: AccountPolicyDetail) => void;
    props.repository.updatePolicy.mockImplementationOnce(() => new Promise((resolve) => { release = resolve; }));
    const { result, rerender } = await open(props); let flight!: Promise<PolicyMutationResult>;
    await act(async () => { flight = result.current!.begin(detail, rename); await Promise.resolve(); });
    const original = localStorage.getItem(policyMutationStorageKey(owner));
    rerender({ ...props, credential: "new-bearer", sessionRevision: 2 });
    await waitFor(() => expect(result.current!.ready).toBe(true));
    await act(async () => { release(renamed()); expect(await flight).toEqual({ status: "blocked" }); });
    expect(localStorage.getItem(policyMutationStorageKey(owner))).toBe(original);
    expect(result.current!.pending?.requestId).toBe(props.repository.updatePolicy.mock.calls[0]![3].requestId);
    await act(async () => { expect((await result.current!.retry()).status).toBe("applied"); });
    expect(props.repository.updatePolicy.mock.calls[1]).toEqual(["new-bearer", ...props.repository.updatePolicy.mock.calls[0]!.slice(1)]);
    expect(localStorage.length).toBe(0);
  });

  it("fails closed for corrupt, unavailable or full storage and for a missing browser lock", async () => {
    const props = options(); const hook = await open(props);
    localStorage.setItem(policyMutationStorageKey(owner), "corrupt-retained-record");
    await act(async () => { expect(await hook.result.current!.begin(detail, rename)).toEqual({ status: "blocked" }); });
    expect(localStorage.getItem(policyMutationStorageKey(owner))).toBe("corrupt-retained-record");
    expect(hook.result.current!.recoveryError).toBe("unavailable"); hook.unmount(); localStorage.clear();
    const full = await open(props);
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => { throw new Error("quota exceeded"); });
    await act(async () => { expect(await full.result.current!.begin(detail, rename)).toEqual({ status: "blocked" }); });
    expect(full.result.current!.recoveryError).toBe("unavailable"); full.unmount(); vi.restoreAllMocks();
    Object.defineProperty(navigator, "locks", { configurable: true, value: undefined });
    const unsupported = renderHook(() => useLivePolicyMutation(props));
    await waitFor(() => expect(unsupported.result.current!.recoveryError).toBe("unavailable"));
    await act(async () => { expect(await unsupported.result.current!.begin(detail, rename)).toEqual({ status: "blocked" }); });
    expect(props.repository.updatePolicy).not.toHaveBeenCalled(); expect(props.repository.deletePolicy).not.toHaveBeenCalled();
  });

  it("abandons only the exact local recovery record without issuing a server command", async () => {
    const props = options(); props.repository.deletePolicy.mockRejectedValueOnce(new HttpProblem(503, "LOST"));
    const { result } = await open(props);
    await act(async () => { await result.current!.begin(detail, { kind: "retire" }); });
    const pending = result.current!.pending as PolicyMutationIntent;
    localStorage.setItem(policyMutationStorageKey(owner), JSON.stringify({ ...pending, requestId: "changed-request" }));
    await act(async () => { expect(await result.current!.abandon()).toBe(false); });
    expect(readPolicyMutationIntent(localStorage, owner)?.requestId).toBe("changed-request");
    expect(props.repository.deletePolicy).toHaveBeenCalledTimes(1); expect(props.repository.updatePolicy).not.toHaveBeenCalled();
  });
});
