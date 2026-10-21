import { afterEach, describe, expect, it, vi } from "vitest";
import { HttpProblem, requestJSON } from "./jsonRequest";

afterEach(() => vi.restoreAllMocks());

describe("requestJSON", () => {
  it("retains only a validated problem request ID for safe diagnostics", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({
      status: 403,
      code: "iam.authorization.forbidden",
      detail: "private policy evaluation details",
      requestId: "request-safe-diagnostic"
    }), { status: 403, headers: { "Content-Type": "application/json" } })));

    const failure = await requestJSON("/api/iam/v1/example").catch((error: unknown) => error);

    expect(failure).toBeInstanceOf(HttpProblem);
    expect(failure).toMatchObject({ status: 403, code: "iam.authorization.forbidden", requestId: "request-safe-diagnostic" });
    expect(failure).not.toHaveProperty("detail");
  });

  it.each(["", " request-with-spaces ", "x".repeat(129)])("drops an unsafe problem request ID: %s", async (requestId) => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({
      code: "iam.authorization.forbidden",
      requestId
    }), { status: 403, headers: { "Content-Type": "application/json" } })));

    const failure = await requestJSON("/api/iam/v1/example").catch((error: unknown) => error);

    expect(failure).toMatchObject({ status: 403, code: "iam.authorization.forbidden", requestId: null });
  });

  it("replaces an unbounded response code without discarding a valid request ID", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({
      code: "iam.authorization.denied\nAuthorization: Bearer private-upstream-secret",
      requestId: "request-safe-diagnostic"
    }), { status: 403, headers: { "Content-Type": "application/json" } })));

    const failure = await requestJSON("/api/iam/v1/example").catch((error: unknown) => error);

    expect(failure).toMatchObject({ status: 403, code: "PLATFORM_REQUEST_REJECTED", requestId: "request-safe-diagnostic" });
    expect(String(failure)).not.toContain("private-upstream-secret");
  });
});
