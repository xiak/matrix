import { act, cleanup, renderHook } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { HttpProblem } from "@/infrastructure/http/jsonRequest";
import type { CreateUserCommand, User, UserAccess } from "../domain/accounts";
import { useLiveUserCreation } from "./userCreation";

const user: User = { id: "new-user", accountId: "account-a", loginName: "alex", displayName: "Alex",
  status: "ACTIVE", mustChangePassword: true, resourceVersion: 1 };
const input = { loginName: "alex", displayName: "Alex", initialPassword: "secret-only-in-original-session" };
const detail: UserAccess = { user, policyAttachments: [], capabilities: [] };
function options() {
  return { active: true, accountId: "account-a", credential: "session-a", rootUserId: "root-a", sessionRevision: 1,
    repository: { createUser: vi.fn().mockResolvedValue(user), getUser: vi.fn().mockResolvedValue(detail) },
    onExpired: vi.fn(), onCreated: vi.fn() };
}
afterEach(cleanup);

describe("LIVE root user creation", () => {
  it("freezes one explicit no-boundary request and rereads the exact created identity without publishing the password", async () => {
    const props = options();
    const { result } = renderHook(() => useLiveUserCreation(props));
    await act(async () => { expect(await result.current!.create(input)).toBe(true); });
    const command = props.repository.createUser.mock.calls[0]![2] as CreateUserCommand;
    expect(command).toEqual({ ...input, permissionBoundary: null, requestId: expect.stringMatching(/^ui-user-create-/) });
    expect(Object.isFrozen(command)).toBe(true);
    expect(props.repository.getUser).toHaveBeenCalledExactlyOnceWith("session-a", user.id);
    expect(result.current!.state).toMatchObject({ phase: "applied", read: "ready", user });
    expect(JSON.stringify(result.current!.state)).not.toContain(input.initialPassword);
    expect(props.onCreated).toHaveBeenCalledTimes(1);
    await act(async () => { expect(await result.current!.create(input)).toBe(false); });
    expect(props.repository.createUser).toHaveBeenCalledTimes(1);
    act(() => result.current!.finish());
    expect(result.current!.state.phase).toBe("idle");
  });

  it.each([new Error("lost response"), new HttpProblem(409, "CONFLICT"), new HttpProblem(503, "UNAVAILABLE")])("keeps an uncertain result locked and only retries the identical input", async (failure) => {
    const props = options();
    props.repository.createUser.mockRejectedValueOnce(failure).mockRejectedValueOnce(new HttpProblem(409, "CONFLICT"));
    const { result } = renderHook(() => useLiveUserCreation(props));
    await act(async () => { await result.current!.create(input); });
    expect(result.current!.state.phase).toBe("unknown");
    expect(JSON.stringify(result.current!.state)).not.toContain(input.initialPassword);
    await act(async () => { expect(await result.current!.create({ ...input, loginName: "other" })).toBe(false); });
    act(() => result.current!.finish());
    expect(result.current!.state.phase).toBe("unknown");
    await act(async () => { await result.current!.retry(); });
    expect(result.current!.state.phase).toBe("unknown");
    expect(props.repository.createUser.mock.calls[1]).toEqual(props.repository.createUser.mock.calls[0]);
    expect(props.repository.getUser).not.toHaveBeenCalled();
    await act(async () => { expect(await result.current!.retry()).toBe(true); });
    expect(result.current!.state.phase).toBe("applied");
  });

  it.each([401, 403, 422])("handles definite %s rejection locally and expires only the original owner for 401", async (status) => {
    const props = options();
    props.repository.createUser.mockRejectedValue(new HttpProblem(status, "REJECTED"));
    const { result } = renderHook(() => useLiveUserCreation(props));
    await act(async () => { await result.current!.create(input); });
    expect(result.current!.state).toEqual({ phase: "rejected", reason: status === 401 ? "expired" : status === 403 ? "forbidden" : "invalid" });
    expect(props.repository.getUser).not.toHaveBeenCalled();
    if (status === 401) expect(props.onExpired).toHaveBeenCalledExactlyOnceWith("session-a", 1);
    else expect(props.onExpired).not.toHaveBeenCalled();
  });

  it("keeps confirmed creation when a detail reread fails and retries only the read", async () => {
    const props = options();
    props.repository.getUser.mockRejectedValueOnce(new HttpProblem(503, "UNAVAILABLE"));
    const { result } = renderHook(() => useLiveUserCreation(props));
    await act(async () => { expect(await result.current!.create(input)).toBe(true); });
    expect(result.current!.state).toMatchObject({ phase: "applied", read: "unavailable" });
    await act(async () => { expect(await result.current!.retry()).toBe(false); await result.current!.reread(); });
    expect(result.current!.state).toMatchObject({ phase: "applied", read: "ready" });
    expect(props.repository.createUser).toHaveBeenCalledTimes(1);
    expect(props.repository.getUser).toHaveBeenCalledTimes(2);
  });

  it("rejects another account, the root identity and incompatible successful-looking replies", async () => {
    for (const patch of [{ accountId: "account-b" }, { id: "root-a" }, { mustChangePassword: false }, { resourceVersion: 2 }]) {
      const props = options();
      props.repository.createUser.mockResolvedValue({ ...user, ...patch });
      const { result, unmount } = renderHook(() => useLiveUserCreation(props));
      await act(async () => { await result.current!.create(input); });
      expect(result.current!.state.phase).toBe("unknown");
      expect(props.repository.getUser).not.toHaveBeenCalled();
      unmount();
    }
  });

  it("does not accept a late result, expire a new session or reuse the old password across owners", async () => {
    let release!: (value: User) => void;
    const props = options();
    props.repository.createUser.mockReturnValueOnce(new Promise<User>((resolve) => { release = resolve; }));
    const { result, rerender } = renderHook((next) => useLiveUserCreation(next), { initialProps: props });
    let submission!: Promise<boolean>;
    act(() => { submission = result.current!.create(input); });
    expect(result.current!.state.phase).toBe("submitting");
    rerender({ ...props, credential: "session-b", sessionRevision: 2 });
    expect(result.current!.state.phase).toBe("idle");
    await act(async () => { release(user); expect(await submission).toBe(false); });
    expect(props.repository.getUser).not.toHaveBeenCalled();
    expect(props.onCreated).not.toHaveBeenCalled();
    expect(props.onExpired).not.toHaveBeenCalled();
    await act(async () => { expect(await result.current!.retry()).toBe(false); });
  });

  it("does not expose creation without the exact active ownership/capability input", () => {
    const props = options();
    expect(renderHook(() => useLiveUserCreation({ ...props, active: false })).result.current).toBeNull();
    expect(renderHook(() => useLiveUserCreation({ ...props, repository: { ...props.repository, createUser: undefined } })).result.current).toBeNull();
    expect(props.repository.createUser).not.toHaveBeenCalled();
  });

  it("ignores completion after the owning provider unmounts instead of issuing another read", async () => {
    let release!: (value: User) => void;
    const props = options();
    props.repository.createUser.mockReturnValueOnce(new Promise<User>((resolve) => { release = resolve; }));
    const { result, unmount } = renderHook(() => useLiveUserCreation(props));
    let submission!: Promise<boolean>;
    act(() => { submission = result.current!.create(input); });
    unmount();
    await act(async () => { release(user); expect(await submission).toBe(false); });
    expect(props.repository.getUser).not.toHaveBeenCalled();
    expect(props.onCreated).not.toHaveBeenCalled();
    expect(props.onExpired).not.toHaveBeenCalled();
  });

  it("does not dispatch a second retry while the original frozen retry is still in flight", async () => {
    let release!: (value: User) => void;
    const props = options();
    props.repository.createUser.mockRejectedValueOnce(new HttpProblem(503, "UNKNOWN"))
      .mockReturnValueOnce(new Promise<User>((resolve) => { release = resolve; }));
    const { result } = renderHook(() => useLiveUserCreation(props));
    await act(async () => { await result.current!.create(input); });
    let retry!: Promise<boolean>;
    act(() => { retry = result.current!.retry(); });
    await act(async () => { expect(await result.current!.retry()).toBe(false); });
    expect(props.repository.createUser).toHaveBeenCalledTimes(2);
    expect(props.repository.createUser.mock.calls[1]).toEqual(props.repository.createUser.mock.calls[0]);
    await act(async () => { release(user); expect(await retry).toBe(true); });
  });

  it("cannot expire a replacement session from the old owner's late rejection", async () => {
    let reject!: (failure: Error) => void;
    const props = options();
    props.repository.createUser.mockReturnValueOnce(new Promise<User>((_resolve, fail) => { reject = fail; }));
    const { result, rerender } = renderHook((next) => useLiveUserCreation(next), { initialProps: props });
    let submission!: Promise<boolean>;
    act(() => { submission = result.current!.create(input); });
    rerender({ ...props, credential: "session-b", sessionRevision: 2 });
    await act(async () => { reject(new HttpProblem(401, "EXPIRED")); expect(await submission).toBe(false); });
    expect(result.current!.state.phase).toBe("idle");
    expect(props.onExpired).not.toHaveBeenCalled();
  });
});
