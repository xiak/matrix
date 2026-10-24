import { describe, expect, it, vi } from "vitest";
import { HttpProblem } from "@/infrastructure/http/jsonRequest";
import {
  createForegroundSessionTouchReporter,
  foregroundSessionTouchThrottleMilliseconds,
  isExplicitForegroundSessionActivity
} from "./foregroundSessionActivity";

function activity(type: string, options: { isTrusted?: boolean; key?: string } = {}) {
  return { type, isTrusted: options.isTrusted ?? true, key: options.key };
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((promiseResolve, promiseReject) => {
    resolve = promiseResolve;
    reject = promiseReject;
  });
  return { promise, reject, resolve };
}

describe("foreground Session activity", () => {
  it("recognizes only trusted, explicit interaction while the document is visible", () => {
    expect(isExplicitForegroundSessionActivity(activity("pointerdown"), "visible")).toBe(true);
    expect(isExplicitForegroundSessionActivity(activity("popstate"), "visible")).toBe(true);
    expect(isExplicitForegroundSessionActivity(activity("keydown", { key: "Enter" }), "visible")).toBe(true);
    expect(isExplicitForegroundSessionActivity(activity("keydown", { key: "Shift" }), "visible")).toBe(false);
    expect(isExplicitForegroundSessionActivity(activity("keydown", { key: "Unidentified" }), "visible")).toBe(false);
    expect(isExplicitForegroundSessionActivity(activity("visibilitychange"), "visible")).toBe(false);
    expect(isExplicitForegroundSessionActivity(activity("focus"), "visible")).toBe(false);
    expect(isExplicitForegroundSessionActivity(activity("pointerdown"), "hidden")).toBe(false);
    expect(isExplicitForegroundSessionActivity(activity("pointerdown", { isTrusted: false }), "visible")).toBe(false);
  });

  it("coalesces rapid interaction and never overlaps a current-Session touch", async () => {
    let now = 10;
    const first = deferred<void>();
    const touch = vi.fn().mockImplementationOnce(() => first.promise).mockResolvedValue(undefined);
    const reporter = createForegroundSessionTouchReporter({ expire: vi.fn(), isCurrent: () => true, now: () => now, touch });

    reporter.handle(activity("pointerdown"), "visible");
    reporter.handle(activity("keydown", { key: "a" }), "visible");
    expect(touch).toHaveBeenCalledOnce();
    now += foregroundSessionTouchThrottleMilliseconds;
    reporter.handle(activity("popstate"), "visible");
    expect(touch).toHaveBeenCalledOnce();

    first.resolve();
    await first.promise;
    await Promise.resolve();
    reporter.handle(activity("popstate"), "visible");
    expect(touch).toHaveBeenCalledTimes(2);
  });

  it("expires only the still-current Session on an authoritative 401", async () => {
    const expire = vi.fn();
    const reporter = createForegroundSessionTouchReporter({
      expire,
      isCurrent: () => true,
      now: () => 1,
      touch: () => Promise.reject(new HttpProblem(401, "SESSION_EXPIRED"))
    });
    reporter.handle(activity("pointerdown"), "visible");
    await Promise.resolve();
    await Promise.resolve();
    expect(expire).toHaveBeenCalledOnce();
  });

  it.each([400, 403, 500, 503])("does not invent expiry or renewal after a %s failure", async (status) => {
    const expire = vi.fn();
    const reporter = createForegroundSessionTouchReporter({
      expire,
      isCurrent: () => true,
      now: () => 1,
      touch: () => Promise.reject(new HttpProblem(status, "TOUCH_FAILED"))
    });
    reporter.handle(activity("keydown", { key: "Tab" }), "visible");
    await Promise.resolve();
    await Promise.resolve();
    expect(expire).not.toHaveBeenCalled();
  });

  it("discards a late failure after replacement or disposal", async () => {
    let current = true;
    const expire = vi.fn();
    const first = deferred<void>();
    const firstReporter = createForegroundSessionTouchReporter({ expire, isCurrent: () => current, now: () => 1, touch: () => first.promise });
    firstReporter.handle(activity("pointerdown"), "visible");
    current = false;
    first.reject(new HttpProblem(401, "OLD_SESSION"));
    await first.promise.catch(() => undefined);
    await Promise.resolve();

    const second = deferred<void>();
    const secondReporter = createForegroundSessionTouchReporter({ expire, isCurrent: () => true, now: () => 1, touch: () => second.promise });
    secondReporter.handle(activity("pointerdown"), "visible");
    secondReporter.dispose();
    second.reject(new HttpProblem(401, "UNMOUNTED_SESSION"));
    await second.promise.catch(() => undefined);
    await Promise.resolve();

    expect(expire).not.toHaveBeenCalled();
  });
});
