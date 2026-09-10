import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError, createApiSession, resourcePath } from "./client";

function json(value: unknown, status = 200) { return new Response(JSON.stringify(value), { status, headers: { "Content-Type": "application/json" } }); }
function login(id = "session-a", organizationId = "organization-a") {
  return { credential: "mx1.TestOnlyCredentialNotARealSecret00000000001", session: { apiVersion: "iam.matrix.xiak.com/v1", kind: "Session", id, principalId: "principal-a", organizationId, status: "ACTIVE", issuedAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 60000).toISOString() } };
}
afterEach(() => vi.useRealTimers());
describe("memory-only public API session", () => {
  it("binds requests to the authenticated identity and sends bodyless guarded commands", async () => {
    const calls: [string, RequestInit | undefined][] = [];
    const api = createApiSession(async (url, options) => { calls.push([String(url), options]); return json(String(url).endsWith("/login") ? login() : { scope: { tenantId: "organization-a" } }); });
    await api.login("admin", "test-password");
    expect(JSON.stringify(api.snapshot())).not.toContain("credential");
    const bound = api.forSession(api.snapshot()!.id);
    await bound.request({ Item: () => true }, "Item", "/api/devops/v1/pipelines/pipeline-a/activate", { method: "POST", version: 7, idempotencyKey: "same-command" });
    const request = calls.at(-1)![1]!;
    expect(request.body).toBeUndefined();
    expect(new Headers(request.headers).get("If-Match")).toBe('"7"');
    expect(new Headers(request.headers).get("Idempotency-Key")).toBe("same-command");
    expect(request).toMatchObject({ credentials: "omit", cache: "no-store", redirect: "error" });
    api.dispose();
  });
  it("discards late results and rejects a previous identity's continuation before sending", async () => {
    let resolve!: (value: Response) => void;
    const fetcher = vi.fn(async (url: RequestInfo | URL) => String(url).endsWith("/login") ? json(login("session-" + fetcher.mock.calls.length)) : await new Promise<Response>(done => { resolve = done; }));
    const api = createApiSession(fetcher);
    await api.login("a", "test-password");
    const bound = api.forSession(api.snapshot()!.id);
    const pending = bound.request({ Item: () => true }, "Item", "/api/paas/v1/applications/app-a");
    const rejected = expect(pending).rejects.toMatchObject({ code: "CANCELLED" });
    await api.login("b", "test-password");
    resolve(json({ old: true }));
    await rejected;
    const before = fetcher.mock.calls.length;
    await expect(bound.request({ Item: () => true }, "Item", "/api/paas/v1/applications/app-a")).rejects.toMatchObject({ code: "CANCELLED" });
    expect(fetcher.mock.calls.length).toBe(before);
    api.dispose();
  });
  it("rejects nested foreign scope and never returns raw problems", async () => {
    const api = createApiSession(async url => String(url).endsWith("/login") ? json(login()) : json({ pipeline: { metadata: { scope: { tenantId: "organization-b" } } } }));
    await api.login("admin", "test-password");
    await expect(api.request({ Item: () => true }, "Item", "/api/devops/v1/pipelines/pipeline-a/activate")).rejects.toMatchObject({ code: "SCOPE" });
    api.dispose();
    const denied = createApiSession(async url => String(url).endsWith("/login") ? json(login()) : json({ detail: "private database password", title: "internal trace" }, 403));
    await denied.login("admin", "test-password");
    try { await denied.request({ Item: () => true }, "Item", "/api/paas/v1/applications/app-a"); } catch (error) { expect(error).toBeInstanceOf(ApiError); expect(String(error)).toBe("Error: DENIED"); }
    denied.dispose();
  });
  it("clears authentication on revocation and announces an uncertain remote sign-out", async () => {
    const api = createApiSession(async url => String(url).endsWith("/login") ? json(login()) : json({}, 401));
    await api.login("admin", "test-password");
    await expect(api.request({ Item: () => true }, "Item", "/api/paas/v1/applications/app-a")).rejects.toMatchObject({ code: "SESSION" });
    expect(api.snapshot()).toBeNull(); expect(api.notice()).toBe("sessionEnded");
    await api.login("admin", "test-password");
    await api.logout();
    expect(api.snapshot()).toBeNull();
    api.dispose();
    const failure = createApiSession(async url => { if (String(url).endsWith("/login")) return json(login()); throw Error("network"); });
    await failure.login("admin", "test-password");
    await failure.logout();
    expect(failure.snapshot()).toBeNull(); expect(failure.notice()).toBe("logoutUncertain");
    failure.dispose();
  });
  it("rejects malformed, overlarge and untyped responses before rendering", async () => {
    for (const response of [new Response("<html>failure</html>", { headers: { "Content-Type": "text/html" } }), json({ text: "x".repeat(2 * 1024 * 1024) }), json({ wrong: true })]) {
      const api = createApiSession(async url => String(url).endsWith("/login") ? json(login()) : response);
      await api.login("admin", "test-password");
      await expect(api.request({ Item: () => false }, "Item", "/api/paas/v1/applications/app-a")).rejects.toBeInstanceOf(ApiError);
      api.dispose();
    }
  });
  it("does not admit arbitrary routes, resource paths or weak preconditions", async () => {
    const fetcher = vi.fn(async () => json(login()));
    const api = createApiSession(fetcher);
    await api.login("admin", "test-password");
    for (const path of ["https://attacker.example/", "/api/iam/internal/admin", "/console/preview"]) await expect(api.request({ Item: () => true }, "Item", path)).rejects.toMatchObject({ code: "INPUT" });
    await expect(api.request({ Item: () => true }, "Item", "/api/devops/v1/runs/run-a/cancel", { version: 0 })).rejects.toMatchObject({ code: "VERSION" });
    for (const id of ["../other", "a/b", "a?tenant=b", "a\nheader", "a%2Fb", "a".repeat(129)]) expect(() => resourcePath(id)).toThrow(ApiError);
    expect(resourcePath("App:Prod_01.2-a")).toBe("App%3AProd_01.2-a");
    expect(fetcher).toHaveBeenCalledTimes(1);
    api.dispose();
  });
});
