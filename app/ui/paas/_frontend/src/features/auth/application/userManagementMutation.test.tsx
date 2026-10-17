import { act, cleanup, renderHook, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { HttpProblem } from "@/infrastructure/http/jsonRequest";
import type { UserManagementClient } from "./AccountAccessProvider";
import type { User, UserManagementCompletion, UserManagementIntent } from "../domain/accounts";
import { readUserManagementIntent, userManagementStorageKey, writeUserManagementIntent } from "../repositories/userManagementRecoveryStorage";
import { useUserManagementMutation, UserManagementReviewRejected, type UserManagementDraft } from "./userManagementMutation";

const scope = { accountId: "account-one", actorPrincipalId: "actor-one", userId: "user-one" };
const user: User = { id: scope.userId, accountId: scope.accountId, loginName: "engineer", displayName: "New Name", status: "ACTIVE", mustChangePassword: false, resourceVersion: 4 };
const draft: UserManagementDraft = { operation: "USER_UPDATE", expectedResourceVersion: 3, intendedDisplayName: "New Name" };
const original: UserManagementIntent = { format: 1, ...scope, ...draft, commandRequestId: "original-user-change" };
function completion(intent = original): UserManagementCompletion {
  return { accountId: intent.accountId, actorPrincipalId: intent.actorPrincipalId, userId: intent.userId, operation: intent.operation,
    commandRequestId: intent.commandRequestId, expectedResourceVersion: intent.expectedResourceVersion, eventId: "event-one", occurredAt: "2026-10-17T02:00:00Z",
    result: { ...user, ...(intent.operation === "USER_UPDATE" ? { displayName: intent.intendedDisplayName } : { status: intent.intendedStatus }) } };
}
function source(overrides: Partial<UserManagementClient> = {}): UserManagementClient {
  return { identity: "owner-one", accountId: scope.accountId, actorPrincipalId: scope.actorPrincipalId, canBegin: vi.fn().mockReturnValue(true),
    submit: vi.fn().mockResolvedValue(user), readCompletion: vi.fn(async (intent) => completion(intent)), expire: vi.fn(), ...overrides };
}
function deferred<T>() { let resolve!: (value: T) => void; let reject!: (failure: unknown) => void; const promise = new Promise<T>((done, fail) => { resolve = done; reject = fail; }); return { resolve, reject, promise }; }
afterEach(() => { cleanup(); vi.restoreAllMocks(); sessionStorage.clear(); });

describe("original User profile/status commands", () => {
  it("journals the exact non-secret intent before one write and waits for acknowledgement without an outcome read", async () => {
    const request = deferred<User>(); const client = source({ submit: vi.fn((intent) => { expect(readUserManagementIntent(sessionStorage, scope)).toEqual(intent); return request.promise; }) });
    const { result } = renderHook(() => useUserManagementMutation(client, scope.userId));
    await waitFor(() => expect(result.current.ready).toBe(true));
    let running!: ReturnType<typeof result.current.begin>;
    const input = { ...draft }; act(() => { running = result.current.begin(input); });
    const intent = result.current.pending!;
    expect(intent).toEqual({ format: 1, ...scope, ...draft, commandRequestId: expect.stringMatching(/^ui-user-management-/) });
    input.expectedResourceVersion = 99;
    await act(async () => { expect(await result.current.begin(draft)).toEqual({ status: "blocked" }); expect(await result.current.inspect()).toEqual({ status: "blocked" }); });
    await act(async () => { request.resolve(user); expect(await running).toEqual({ status: "applied" }); });
    expect(result.current.receipt).toEqual({ intent, result: user });
    await act(async () => { expect(await result.current.inspect()).toEqual({ status: "blocked" }); });
    act(() => { expect(result.current.acknowledge()).toBe(true); });
    expect(result.current.pending).toBeNull(); expect(result.current.receipt?.result).toEqual(user); expect(sessionStorage.length).toBe(0);
    expect(client.submit).toHaveBeenCalledExactlyOnceWith(intent); expect(client.readCompletion).not.toHaveBeenCalled();
  });

  it("restores the original same-actor command in a fresh Session and only reads after explicit inspection", async () => {
    writeUserManagementIntent(sessionStorage, original);
    const client = source({ identity: "fresh-session" });
    const { result } = renderHook(() => useUserManagementMutation(client, scope.userId));
    await waitFor(() => expect(result.current.pending).toEqual(original));
    expect(client.submit).not.toHaveBeenCalled(); expect(client.readCompletion).not.toHaveBeenCalled();
    await act(async () => { expect(await result.current.begin({ operation: "USER_SET_STATUS", expectedResourceVersion: 9, intendedStatus: "DISABLED" })).toEqual({ status: "blocked" }); });
    await act(async () => { expect(await result.current.inspect()).toEqual({ status: "applied" }); });
    expect(client.readCompletion).toHaveBeenCalledExactlyOnceWith(original); expect(client.canBegin).not.toHaveBeenCalled(); expect(client.submit).not.toHaveBeenCalled();
    expect(result.current.receipt).toEqual({ intent: original, result: user, completion: completion() });
  });

  it.each([401, 403, 404, 409, 422, 500, 503, 0])("never unlocks a prior UNKNOWN or resends a write when lookup returns %s", async (status) => {
    const client = source({ submit: vi.fn().mockRejectedValue(new Error("lost response")), readCompletion: vi.fn().mockRejectedValue(status ? new HttpProblem(status, "REJECTED") : new Error("network")) });
    const { result } = renderHook(() => useUserManagementMutation(client, scope.userId));
    await act(async () => { expect(await result.current.begin(draft)).toEqual({ status: "unknown" }); });
    const intent = result.current.pending;
    expect(client.readCompletion).not.toHaveBeenCalled();
    await act(async () => { expect(await result.current.inspect()).toEqual({ status: "unknown" }); expect(await result.current.begin(draft)).toEqual({ status: "blocked" }); });
    expect(result.current.pending).toEqual(intent); expect(readUserManagementIntent(sessionStorage, scope)).toEqual(intent); expect(result.current.receipt).toBeNull(); expect(result.current.acknowledge()).toBe(false);
    expect(client.submit).toHaveBeenCalledOnce(); expect(client.readCompletion).toHaveBeenCalledExactlyOnceWith(intent); expect(client.expire).toHaveBeenCalledTimes(status === 401 ? 1 : 0);
  });

  it.each([400, 401, 403, 409, 413, 415, 422])("closes a definitely rejected first %s write without claiming completion", async (status) => {
    const client = source({ submit: vi.fn().mockRejectedValue(new HttpProblem(status, "REJECTED")) });
    const { result } = renderHook(() => useUserManagementMutation(client, scope.userId));
    await act(async () => { expect((await result.current.begin(draft)).status).toBe("rejected"); });
    expect(result.current.pending).toBeNull(); expect(result.current.receipt).toBeNull(); expect(sessionStorage.length).toBe(0); expect(client.readCompletion).not.toHaveBeenCalled();
  });

  it.each([404, 429])("keeps an undeclared first-write %s outcome UNKNOWN instead of assuming rollback", async (status) => {
    const client = source({ submit: vi.fn().mockRejectedValue(new HttpProblem(status, "UNDECLARED")) }); const { result } = renderHook(() => useUserManagementMutation(client, scope.userId));
    await act(async () => { expect(await result.current.begin(draft)).toEqual({ status: "unknown" }); });
    expect(result.current.pending).not.toBeNull(); expect(result.current.receipt).toBeNull(); expect(result.current.acknowledge()).toBe(false);
  });

  it("keeps an unsubmitted stale review out of UNKNOWN, before and immediately after journaling", async () => {
    const client = source({ canBegin: vi.fn().mockReturnValue(false) });
    const { result } = renderHook(() => useUserManagementMutation(client, scope.userId));
    await act(async () => { expect(await result.current.begin(draft)).toEqual({ status: "rejected", reason: "conflict" }); });
    expect(sessionStorage.length).toBe(0); expect(client.submit).not.toHaveBeenCalled();
    vi.mocked(client.canBegin).mockReturnValue(true); vi.mocked(client.submit).mockRejectedValue(new UserManagementReviewRejected());
    await act(async () => { expect(await result.current.begin(draft)).toEqual({ status: "rejected", reason: "conflict" }); });
    expect(sessionStorage.length).toBe(0); expect(result.current.pending).toBeNull();
  });

  it.each(["Session", "repository", "User"])("fences an old result after its %s owner changes", async (change) => {
    const request = deferred<User>(); const previous = source({ submit: vi.fn(() => request.promise) }); const next = source({ identity: "replacement-owner" });
    const { result, rerender } = renderHook(({ client, userId }) => useUserManagementMutation(client, userId), { initialProps: { client: previous, userId: scope.userId } });
    let running!: ReturnType<typeof result.current.begin>; act(() => { running = result.current.begin(draft); }); const intent = result.current.pending;
    rerender({ client: change === "User" ? previous : next, userId: change === "User" ? "user-two" : scope.userId });
    await act(async () => { request.resolve(user); expect(await running).toEqual({ status: "blocked" }); });
    expect(result.current.receipt).toBeNull(); expect(readUserManagementIntent(sessionStorage, scope)).toEqual(intent); expect(next.submit).not.toHaveBeenCalled(); expect(next.expire).not.toHaveBeenCalled();
  });

  it("ignores a late lookup 401 after unmount without expiring a replacement owner", async () => {
    writeUserManagementIntent(sessionStorage, original); const request = deferred<UserManagementCompletion>(); const client = source({ readCompletion: vi.fn(() => request.promise) });
    const { result, unmount } = renderHook(() => useUserManagementMutation(client, scope.userId)); let running!: ReturnType<typeof result.current.inspect>;
    act(() => { running = result.current.inspect(); }); unmount();
    await act(async () => { request.reject(new HttpProblem(401, "OLD_SESSION")); expect(await running).toEqual({ status: "blocked" }); });
    expect(client.expire).not.toHaveBeenCalled(); expect(readUserManagementIntent(sessionStorage, scope)).toEqual(original); expect(client.submit).not.toHaveBeenCalled();
  });

  it.each(["account", "actor"])("does not expose another %s's reminder", async (change) => {
    writeUserManagementIntent(sessionStorage, original); const client = source(change === "account" ? { accountId: "account-two" } : { actorPrincipalId: "actor-two" });
    const { result } = renderHook(() => useUserManagementMutation(client, scope.userId));
    await waitFor(() => expect(result.current.ready).toBe(true)); expect(result.current.pending).toBeNull(); expect(client.readCompletion).not.toHaveBeenCalled(); expect(client.submit).not.toHaveBeenCalled();
  });

  it.each(["getItem", "setItem"] as const)("does not write when original-request storage %s fails", async (method) => {
    vi.spyOn(Storage.prototype, method).mockImplementation(() => { throw new Error("blocked storage"); }); const client = source();
    const { result } = renderHook(() => useUserManagementMutation(client, scope.userId));
    await act(async () => { expect(await result.current.begin(draft)).toEqual({ status: "blocked" }); });
    expect(result.current.recoveryError).toBe(true); expect(result.current.ready).toBe(false); expect(client.submit).not.toHaveBeenCalled();
  });

  it("retains a known receipt when acknowledgement storage fails and never dispatches or queries again", async () => {
    const client = source(); const { result } = renderHook(() => useUserManagementMutation(client, scope.userId));
    await act(async () => { expect(await result.current.begin(draft)).toEqual({ status: "applied" }); });
    const originalReceipt = result.current.receipt; const fault = vi.spyOn(Storage.prototype, "removeItem").mockImplementation(() => { throw new Error("blocked cleanup"); });
    act(() => { expect(result.current.acknowledge()).toBe(false); });
    expect(result.current.receipt).toEqual(originalReceipt); expect(result.current.recoveryError).toBe(true);
    await act(async () => { expect(await result.current.inspect()).toEqual({ status: "blocked" }); expect(await result.current.begin(draft)).toEqual({ status: "blocked" }); });
    fault.mockRestore(); act(() => { expect(result.current.acknowledge()).toBe(true); });
    expect(client.submit).toHaveBeenCalledOnce(); expect(client.readCompletion).not.toHaveBeenCalled();
  });

  it.each([null, undefined, { ...completion(), actorPrincipalId: "other" }, { ...completion(), commandRequestId: "other" },
    { ...completion(), result: { ...user, resourceVersion: 8 } }, { ...completion(), result: { ...user, displayName: "wrong" } }])("leaves a malformed original-result read UNKNOWN without a fallback POST: %j", async (response) => {
    writeUserManagementIntent(sessionStorage, original); const client = source({ readCompletion: vi.fn().mockResolvedValue(response) });
    const { result } = renderHook(() => useUserManagementMutation(client, scope.userId));
    await act(async () => { expect(await result.current.inspect()).toEqual({ status: "unknown" }); });
    expect(result.current.pending).toEqual(original); expect(result.current.receipt).toBeNull(); expect(client.submit).not.toHaveBeenCalled();
  });

  it.each([{ ...user, accountId: "other" }, { ...user, id: "other" }, { ...user, resourceVersion: 5 }, { ...user, displayName: "wrong" }])("does not confirm a misbound immediate response: %j", async (response) => {
    const client = source({ submit: vi.fn().mockResolvedValue(response) }); const { result } = renderHook(() => useUserManagementMutation(client, scope.userId));
    await act(async () => { expect(await result.current.begin(draft)).toEqual({ status: "unknown" }); });
    expect(result.current.receipt).toBeNull(); expect(result.current.pending).not.toBeNull();
  });

  it.each(["{", JSON.stringify({ ...original, password: "not-a-reminder" }), JSON.stringify({ ...original, accountId: "foreign" }), JSON.stringify({ ...original, expectedResourceVersion: Number.MAX_SAFE_INTEGER })])("blocks malformed or foreign reminders without erasing them: %s", async (raw) => {
    sessionStorage.setItem(userManagementStorageKey(scope), raw); const client = source(); const { result } = renderHook(() => useUserManagementMutation(client, scope.userId));
    expect(result.current.recoveryError).toBe(true);
    await act(async () => { expect(await result.current.begin(draft)).toEqual({ status: "blocked" }); });
    expect(sessionStorage.getItem(userManagementStorageKey(scope))).toBe(raw); expect(client.submit).not.toHaveBeenCalled();
  });

  it("rejects caller selectors before persistence and keeps absent clients read-only", async () => {
    const client = source(); const { result, rerender } = renderHook(({ value }) => useUserManagementMutation(value, scope.userId), { initialProps: { value: client as UserManagementClient | null } });
    await act(async () => { expect(await result.current.begin({ ...draft, accountId: "other" } as UserManagementDraft)).toEqual({ status: "blocked" }); });
    expect(sessionStorage.length).toBe(0); expect(client.submit).not.toHaveBeenCalled(); rerender({ value: null });
    expect(result.current.ready).toBe(false); await act(async () => { expect(await result.current.begin(draft)).toEqual({ status: "blocked" }); });
  });

  it("preserves one status intent across remounts and confirms its historical value rather than a later User state", async () => {
    const input: UserManagementDraft = { operation: "USER_SET_STATUS", expectedResourceVersion: 3, intendedStatus: "DISABLED" };
    const client = source({ submit: vi.fn().mockRejectedValue(new Error("response lost")) }); const first = renderHook(() => useUserManagementMutation(client, scope.userId));
    await act(async () => { expect(await first.result.current.begin(input)).toEqual({ status: "unknown" }); }); const intent = first.result.current.pending!; first.unmount();
    const next = source({ identity: "fresh-session" }); const { result } = renderHook(() => useUserManagementMutation(next, scope.userId));
    await act(async () => { expect(await result.current.inspect()).toEqual({ status: "applied" }); });
    expect(result.current.receipt?.result.status).toBe("DISABLED"); expect(next.readCompletion).toHaveBeenCalledExactlyOnceWith(intent); expect(next.submit).not.toHaveBeenCalled();
  });
});
