import { act, cleanup, renderHook, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { HttpProblem } from "@/infrastructure/http/jsonRequest";
import type { GroupAccessClient } from "./AccountAccessProvider";
import type { GroupMembership, GroupMembershipMutationIntent } from "../domain/accounts";
import { groupMembershipStorageKey, readGroupMembershipIntent, writeGroupMembershipIntent } from "../repositories/groupMembershipRecoveryStorage";
import { useGroupMembershipMutation } from "./groupMembershipMutation";

const scope = { accountId: "account-one", actorPrincipalId: "actor-one", groupId: "group-one" };
const membership: GroupMembership = { id: "membership-one", accountId: scope.accountId, groupId: scope.groupId, userId: "user-one", createdBy: scope.actorPrincipalId,
  resourceVersion: 1, createdAt: "2026-10-17T02:00:00Z", updatedAt: "2026-10-17T02:00:00Z" };
const removed: GroupMembership = { ...membership, resourceVersion: 2, removedBy: scope.actorPrincipalId, removedAt: "2026-10-17T02:01:00Z", updatedAt: "2026-10-17T02:01:00Z" };
const intent: GroupMembershipMutationIntent = { format: 1, ...scope, operation: "CREATE", userId: membership.userId, requestId: "original-membership-request" };
function source(overrides: Partial<GroupAccessClient> = {}): GroupAccessClient {
  return { identity: "groups-view-one", accountId: scope.accountId, actorPrincipalId: scope.actorPrincipalId, expire: vi.fn(), canList: true, listRestrictionReason: null,
    canCreate: true, createRestrictionReason: null, list: vi.fn(), get: vi.fn(), create: vi.fn(), update: vi.fn(), delete: vi.fn(), listMemberships: vi.fn(),
    createMembership: vi.fn().mockResolvedValue(membership), removeMembership: vi.fn().mockResolvedValue(removed), createPolicyAttachment: vi.fn(), revokePolicyAttachment: vi.fn(), inspectPolicyAttachmentChange: vi.fn(), ...overrides };
}
function deferred<T>() { let resolve!: (value: T) => void; let reject!: (failure: unknown) => void; const promise = new Promise<T>((done, fail) => { resolve = done; reject = fail; }); return { resolve, reject, promise }; }
afterEach(() => { cleanup(); vi.restoreAllMocks(); sessionStorage.clear(); });

describe("original Group Membership commands", () => {
  it("persists one closed non-secret intent before dispatch and blocks duplicates until exact success is acknowledged", async () => {
    const request = deferred<GroupMembership>(); const client = source({ createMembership: vi.fn(() => request.promise) });
    const { result } = renderHook(() => useGroupMembershipMutation(client, scope.groupId));
    await waitFor(() => expect(result.current.ready).toBe(true));
    let running!: ReturnType<typeof result.current.begin>;
    act(() => { running = result.current.begin({ operation: "CREATE", userId: membership.userId }); });
    const pending = result.current.pending!;
    expect(readGroupMembershipIntent(sessionStorage, scope)).toEqual(pending);
    expect(pending).toEqual({ format: 1, ...scope, operation: "CREATE", userId: membership.userId, requestId: expect.stringMatching(/^ui-group-membership-/) });
    expect(client.createMembership).toHaveBeenCalledExactlyOnceWith(scope.groupId, { userId: membership.userId, requestId: pending.requestId });
    await act(async () => { expect(await result.current.begin({ operation: "CREATE", userId: "another-user" })).toEqual({ status: "blocked" }); });
    await act(async () => { request.resolve(membership); expect(await running).toEqual({ status: "applied", membership }); });
    await act(async () => { expect(await result.current.retry()).toEqual({ status: "blocked" }); });
    expect(result.current.receipt).toEqual(membership); expect(readGroupMembershipIntent(sessionStorage, scope)).toEqual(pending);
    act(() => { expect(result.current.acknowledge()).toBe(true); });
    expect(result.current.pending).toBeNull(); expect(result.current.receipt).toEqual(membership); expect(sessionStorage.length).toBe(0);
    expect(client.get).not.toHaveBeenCalled(); expect(client.listMemberships).not.toHaveBeenCalled(); expect(client.delete).not.toHaveBeenCalled();
  });

  it("restores the same actor's original input with a new Session and sends nothing until explicit exact retry", async () => {
    writeGroupMembershipIntent(sessionStorage, intent);
    const client = source({ identity: "fresh-normal-session" });
    const { result } = renderHook(() => useGroupMembershipMutation(client, scope.groupId));
    await waitFor(() => expect(result.current.pending).toEqual(intent));
    expect(client.createMembership).not.toHaveBeenCalled();
    await act(async () => { expect(await result.current.begin({ operation: "CREATE", userId: "other-user" })).toEqual({ status: "blocked" }); });
    await act(async () => { expect(await result.current.retry()).toEqual({ status: "applied", membership }); });
    expect(client.createMembership).toHaveBeenCalledExactlyOnceWith(scope.groupId, { requestId: intent.requestId, userId: intent.userId });
  });

  it.each([401, 403, 409, 422, 503, 0])("keeps a prior UNKNOWN locked after exact replay returns %s", async (status) => {
    const client = source({ createMembership: vi.fn().mockRejectedValueOnce(new HttpProblem(503, "UNKNOWN")).mockRejectedValueOnce(status ? new HttpProblem(status, "REJECTED") : new Error("network")) });
    const { result } = renderHook(() => useGroupMembershipMutation(client, scope.groupId));
    await act(async () => { expect(await result.current.begin({ operation: "CREATE", userId: membership.userId })).toEqual({ status: "unknown" }); });
    const original = result.current.pending;
    await act(async () => { expect(await result.current.retry()).toEqual({ status: "unknown" }); });
    expect(result.current.pending).toEqual(original); expect(readGroupMembershipIntent(sessionStorage, scope)).toEqual(original);
    expect(result.current.acknowledge()).toBe(false); expect(result.current.receipt).toBeNull();
    expect(client.createMembership).toHaveBeenCalledTimes(2); expect(vi.mocked(client.createMembership).mock.calls[1]).toEqual(vi.mocked(client.createMembership).mock.calls[0]);
    await act(async () => { expect(await result.current.begin({ operation: "CREATE", userId: "another-user" })).toEqual({ status: "blocked" }); });
    expect(client.expire).toHaveBeenCalledTimes(status === 401 ? 1 : 0);
  });

  it.each([400, 401, 403, 409, 413, 415, 422, 429])("treats a definite first %s response as rejected rather than claiming success or replaying it", async (status) => {
    const client = source({ createMembership: vi.fn().mockRejectedValue(new HttpProblem(status, "REJECTED")) });
    const { result } = renderHook(() => useGroupMembershipMutation(client, scope.groupId));
    await act(async () => { expect((await result.current.begin({ operation: "CREATE", userId: membership.userId })).status).toBe("rejected"); });
    expect(result.current.pending).toBeNull(); expect(result.current.receipt).toBeNull(); expect(sessionStorage.length).toBe(0);
    expect(client.createMembership).toHaveBeenCalledOnce(); expect(client.expire).toHaveBeenCalledTimes(status === 401 ? 1 : 0);
  });

  it("freezes the exact removal relationship and revision, not a User ID or later mutable selection", async () => {
    const request = deferred<GroupMembership>(); const client = source({ removeMembership: vi.fn(() => request.promise) });
    const { result } = renderHook(() => useGroupMembershipMutation(client, scope.groupId));
    const selected = structuredClone(membership); let running!: ReturnType<typeof result.current.begin>;
    act(() => { running = result.current.begin({ operation: "REMOVE", membership: selected }); });
    const original = result.current.pending!; selected.resourceVersion = 99; selected.userId = "changed-selection";
    expect(client.removeMembership).toHaveBeenCalledExactlyOnceWith(scope.groupId, membership.id, { resourceVersion: 1, requestId: original.requestId });
    await act(async () => { request.resolve(removed); expect(await running).toEqual({ status: "applied", membership: removed }); });
    expect(result.current.pending).toMatchObject({ operation: "REMOVE", userId: membership.userId, membershipId: membership.id, resourceVersion: 1 });
    expect(client.delete).not.toHaveBeenCalled(); expect(client.createMembership).not.toHaveBeenCalled();
  });

  it.each(["Session", "repository", "group"])("drops an old in-flight success after the %s owner changes without clearing its original reminder", async (change) => {
    const request = deferred<GroupMembership>(); const previous = source({ createMembership: vi.fn(() => request.promise) }); const next = source({ identity: "new-owner" });
    const { result, rerender } = renderHook(({ client, group }) => useGroupMembershipMutation(client, group), { initialProps: { client: previous, group: scope.groupId } });
    let running!: ReturnType<typeof result.current.begin>;
    act(() => { running = result.current.begin({ operation: "CREATE", userId: membership.userId }); });
    const original = result.current.pending;
    rerender({ client: change === "group" ? previous : next, group: change === "group" ? "other-group" : scope.groupId });
    await act(async () => { request.resolve(membership); expect(await running).toEqual({ status: "blocked" }); });
    expect(result.current.receipt).toBeNull(); expect(readGroupMembershipIntent(sessionStorage, scope)).toEqual(original);
    expect(next.createMembership).not.toHaveBeenCalled(); expect(next.expire).not.toHaveBeenCalled();
  });

  it("does not clear a reminder or publish a receipt after unmount", async () => {
    const request = deferred<GroupMembership>(); const client = source({ createMembership: vi.fn(() => request.promise) });
    const { result, unmount } = renderHook(() => useGroupMembershipMutation(client, scope.groupId)); let running!: ReturnType<typeof result.current.begin>;
    act(() => { running = result.current.begin({ operation: "CREATE", userId: membership.userId }); }); const original = result.current.pending;
    unmount(); await act(async () => { request.resolve(membership); expect(await running).toEqual({ status: "blocked" }); });
    expect(readGroupMembershipIntent(sessionStorage, scope)).toEqual(original);
  });

  it("replays an unknown removal after reconstruction with the exact original relationship and revision", async () => {
    const previous = source({ removeMembership: vi.fn().mockRejectedValue(new HttpProblem(503, "UNKNOWN")) });
    const first = renderHook(() => useGroupMembershipMutation(previous, scope.groupId));
    await act(async () => { await first.result.current.begin({ operation: "REMOVE", membership }); });
    const original = first.result.current.pending!; first.unmount(); const next = source({ identity: "new-normal-session" });
    const second = renderHook(() => useGroupMembershipMutation(next, scope.groupId));
    expect(second.result.current.pending).toEqual(original); expect(next.removeMembership).not.toHaveBeenCalled();
    await act(async () => { expect(await second.result.current.retry()).toEqual({ status: "applied", membership: removed }); });
    expect(next.removeMembership).toHaveBeenCalledExactlyOnceWith(scope.groupId, membership.id, { requestId: original.requestId, resourceVersion: membership.resourceVersion });
  });

  it("does not expire a replacement owner's Session on a late old-repository 401", async () => {
    const request = deferred<GroupMembership>(); const previous = source({ createMembership: vi.fn(() => request.promise) }); const next = source({ identity: "new-repository" });
    const { result, rerender } = renderHook(({ client }) => useGroupMembershipMutation(client, scope.groupId), { initialProps: { client: previous } });
    let running!: ReturnType<typeof result.current.begin>;
    act(() => { running = result.current.begin({ operation: "CREATE", userId: membership.userId }); });
    const original = result.current.pending; rerender({ client: next });
    await act(async () => { request.reject(new HttpProblem(401, "EXPIRED")); expect(await running).toEqual({ status: "blocked" }); });
    expect(previous.expire).not.toHaveBeenCalled(); expect(next.expire).not.toHaveBeenCalled(); expect(readGroupMembershipIntent(sessionStorage, scope)).toEqual(original);
  });

  it.each(["read", "write"])("blocks dispatch if recovery storage cannot %s", async (failure) => {
    vi.spyOn(Storage.prototype, failure === "read" ? "getItem" : "setItem").mockImplementation(() => { throw new Error("storage unavailable"); });
    const client = source(); const { result } = renderHook(() => useGroupMembershipMutation(client, scope.groupId));
    await act(async () => { expect(await result.current.begin({ operation: "CREATE", userId: membership.userId })).toEqual({ status: "blocked" }); });
    expect(result.current.recoveryError).toBe(true); expect(client.createMembership).not.toHaveBeenCalled();
  });

  it.each(["account", "actor", "group", "extra-secret", "version", "bad-id", "malformed"])("fails closed on a %s local reminder without accepting or erasing it", async (variant) => {
    const record: Record<string, unknown> = { ...intent };
    if (variant === "account") record.accountId = "foreign-account";
    if (variant === "actor") record.actorPrincipalId = "foreign-actor";
    if (variant === "group") record.groupId = "foreign-group";
    if (variant === "extra-secret") record.credential = "never-accept-a-bearer";
    if (variant === "version") record.format = 2;
    if (variant === "bad-id") record.userId = "not an identifier";
    const raw = variant === "malformed" ? "{" : JSON.stringify(record); const key = groupMembershipStorageKey(scope); sessionStorage.setItem(key, raw);
    const client = source(); const { result } = renderHook(() => useGroupMembershipMutation(client, scope.groupId));
    expect(result.current.recoveryError).toBe(true); expect(result.current.pending).toBeNull();
    await act(async () => { expect(await result.current.begin({ operation: "CREATE", userId: membership.userId })).toEqual({ status: "blocked" }); });
    expect(sessionStorage.getItem(key)).toBe(raw); expect(client.createMembership).not.toHaveBeenCalled();
  });

  it.each(["account", "group", "user", "actor", "revision", "removed"])("retains UNKNOWN instead of accepting a misbound create %s result", async (variant) => {
    const response = { ...membership };
    if (variant === "account") response.accountId = "another-account";
    if (variant === "group") response.groupId = "another-group";
    if (variant === "user") response.userId = "another-user";
    if (variant === "actor") response.createdBy = "another-actor";
    if (variant === "revision") response.resourceVersion = 2;
    if (variant === "removed") Object.assign(response, { removedAt: removed.removedAt, removedBy: removed.removedBy });
    const client = source({ createMembership: vi.fn().mockResolvedValue(response) }); const { result } = renderHook(() => useGroupMembershipMutation(client, scope.groupId));
    await act(async () => { expect(await result.current.begin({ operation: "CREATE", userId: membership.userId })).toEqual({ status: "unknown" }); });
    expect(result.current.receipt).toBeNull(); expect(result.current.pending).toBeTruthy(); expect(client.createMembership).toHaveBeenCalledOnce();
  });

  it("keeps known success distinct from local acknowledgement failure and never resends it", async () => {
    const client = source(); const { result } = renderHook(() => useGroupMembershipMutation(client, scope.groupId));
    await act(async () => { await result.current.begin({ operation: "CREATE", userId: membership.userId }); });
    const remove = vi.spyOn(Storage.prototype, "removeItem").mockImplementation(() => { throw new Error("storage unavailable"); });
    act(() => { expect(result.current.acknowledge()).toBe(false); });
    expect(result.current.receipt).toEqual(membership); expect(result.current.pending).toBeTruthy();
    await act(async () => { expect(await result.current.retry()).toEqual({ status: "blocked" }); });
    remove.mockRestore(); act(() => { expect(result.current.acknowledge()).toBe(true); });
    expect(client.createMembership).toHaveBeenCalledOnce(); expect(result.current.receipt).toEqual(membership);
  });

  it.each(["account", "group", "removed", "zero", "unsafe"])("rejects a %s removal snapshot before dispatch", async (variant) => {
    const selected = { ...membership };
    if (variant === "account") selected.accountId = "another-account";
    if (variant === "group") selected.groupId = "another-group";
    if (variant === "removed") selected.removedAt = removed.removedAt;
    if (variant === "zero") selected.resourceVersion = 0;
    if (variant === "unsafe") selected.resourceVersion = Number.MAX_SAFE_INTEGER;
    const client = source(); const { result } = renderHook(() => useGroupMembershipMutation(client, scope.groupId));
    await act(async () => { expect(await result.current.begin({ operation: "REMOVE", membership: selected })).toEqual({ status: "blocked" }); });
    expect(result.current.pending).toBeNull(); expect(sessionStorage.length).toBe(0); expect(client.removeMembership).not.toHaveBeenCalled();
  });

  it.each(["account", "group", "user", "actor", "membership", "revision", "time"])("does not accept a misbound removal %s result", async (variant) => {
    const response = { ...removed };
    if (variant === "account") response.accountId = "another-account";
    if (variant === "group") response.groupId = "another-group";
    if (variant === "user") response.userId = "another-user";
    if (variant === "actor") response.removedBy = "another-actor";
    if (variant === "membership") response.id = "another-membership";
    if (variant === "revision") response.resourceVersion = 3;
    if (variant === "time") response.removedAt = membership.createdAt;
    const client = source({ removeMembership: vi.fn().mockResolvedValue(response) }); const { result } = renderHook(() => useGroupMembershipMutation(client, scope.groupId));
    await act(async () => { expect(await result.current.begin({ operation: "REMOVE", membership })).toEqual({ status: "unknown" }); });
    expect(result.current.receipt).toBeNull(); expect(result.current.pending?.operation).toBe("REMOVE");
  });

  it("does not allow additional caller selectors to replace the verified owner", async () => {
    const client = source(); const { result } = renderHook(() => useGroupMembershipMutation(client, scope.groupId));
    const invalid = { operation: "CREATE" as const, userId: membership.userId, accountId: "foreign-account", groupId: "foreign-group" };
    await act(async () => { expect(await result.current.begin(invalid)).toEqual({ status: "blocked" }); });
    expect(client.createMembership).not.toHaveBeenCalled(); expect(sessionStorage.length).toBe(0);
  });

  it("blocks another request when a definite rejection's reminder cannot be cleared", async () => {
    const client = source({ createMembership: vi.fn().mockRejectedValue(new HttpProblem(403, "DENIED")) });
    const { result } = renderHook(() => useGroupMembershipMutation(client, scope.groupId));
    vi.spyOn(Storage.prototype, "removeItem").mockImplementation(() => { throw new Error("storage unavailable"); });
    await act(async () => { await result.current.begin({ operation: "CREATE", userId: membership.userId }); });
    expect(result.current.recoveryError).toBe(true); expect(result.current.pending).toBeTruthy(); expect(result.current.receipt).toBeNull();
    await act(async () => { expect(await result.current.retry()).toEqual({ status: "blocked" }); }); expect(client.createMembership).toHaveBeenCalledOnce();
  });
});
