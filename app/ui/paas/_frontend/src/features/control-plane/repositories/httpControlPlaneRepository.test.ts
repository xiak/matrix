import { afterEach, describe, expect, it, vi } from "vitest";
import { httpControlPlaneRepository } from "./httpControlPlaneRepository";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("httpControlPlaneRepository", () => {
  it("reads one installation through its encoded resource route", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      id: "postgres-primary",
      name: "Postgres primary",
      offeringId: "postgresql-18",
      engineVersion: "18",
      quotaEntitlementId: "quota-primary",
      regionId: "local-primary",
      phase: "PROVISIONING",
      endpoint: null,
      credentialReference: null,
      createdAt: "2026-08-26T12:00:00Z",
      operation: {
        id: "operation-primary",
        phase: "PROVISIONING",
        safeFailureCode: null,
        observedAt: "2026-08-26T12:00:04Z"
      }
    }), {
      status: 200,
      headers: { "Content-Type": "application/json" }
    }));
    vi.stubGlobal("fetch", fetchMock);

    const installation = await httpControlPlaneRepository.getInstallation(
      "memory-only-session",
      "postgres-primary"
    );

    expect(installation.phase).toBe("PROVISIONING");
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/managed-services/v1/service-installations/postgres-primary",
      expect.objectContaining({
        cache: "no-store",
        headers: expect.objectContaining({ Authorization: "Bearer memory-only-session" })
      })
    );
  });

  it("rejects a resource response whose identity differs from the route", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({
      id: "postgres-other",
      name: "Postgres other",
      offeringId: "postgresql-18",
      engineVersion: "18",
      quotaEntitlementId: "quota-primary",
      regionId: "local-primary",
      phase: "PENDING",
      endpoint: null,
      credentialReference: null,
      createdAt: "2026-08-26T12:00:00Z",
      operation: {
        id: "operation-other",
        phase: "PENDING",
        safeFailureCode: null,
        observedAt: "2026-08-26T12:00:00Z"
      }
    }), { status: 200, headers: { "Content-Type": "application/json" } })));

    await expect(httpControlPlaneRepository.getInstallation(
      "memory-only-session",
      "postgres-primary"
    )).rejects.toThrow("INVALID_INSTALLATION_ID_RESPONSE");
  });
});
