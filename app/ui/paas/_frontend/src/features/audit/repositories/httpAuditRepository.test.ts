import { afterEach, describe, expect, it, vi } from "vitest";
import { AUDIT_API_VERSION, parseAuditChainVerification, parseAuditRecordPage } from "../domain/audit";
import { httpAuditRepository } from "./httpAuditRepository";

const hash = (character: string) => `sha256:${character.repeat(64)}`;

function response(body: unknown) {
  return new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } });
}

function recordPage() {
  return {
    apiVersion: AUDIT_API_VERSION,
    kind: "AuditRecordPage",
    tenantId: "organization-test",
    records: [{
      apiVersion: AUDIT_API_VERSION,
      kind: "AuditRecord",
      source: "PAAS",
      sequence: 42,
      event: {
        apiVersion: AUDIT_API_VERSION,
        kind: "AuditEvent",
        eventId: "event-deployment-created",
        tenantId: "organization-test",
        actor: { type: "USER", id: "principal-developer" },
        iamDecisionId: "decision-deployment-create",
        action: "paas.deployment.created",
        target: { kind: "DEPLOYMENT", id: "deployment-example" },
        result: "ACCEPTED",
        requestDigest: hash("1"),
        requestId: "request-deployment-create",
        correlationId: "correlation-deployment-create",
        operationId: "operation-deployment-create",
        occurredAt: "2026-08-25T03:04:05.000Z"
      },
      contentDigest: hash("2"),
      previousHash: hash("3"),
      recordHash: hash("4"),
      ingestedAt: "2026-08-25T03:04:06.000Z",
      retention: "INDEFINITE"
    }],
    nextCursor: `v1.${"payload-example-1"}.${"A".repeat(43)}`
  };
}

afterEach(() => vi.unstubAllGlobals());

describe("httpAuditRepository", () => {
  it("queries the current credential boundary without accepting a tenant selector", async () => {
    const fetchMock = vi.fn().mockResolvedValue(response(recordPage()));
    vi.stubGlobal("fetch", fetchMock);

    const page = await httpAuditRepository.query("session-secret", {
      pageSize: 25,
      action: "paas.deployment.created",
      actor: { type: "USER", id: "principal-developer" }
    });

    expect(page.tenantId).toBe("organization-test");
    expect(fetchMock).toHaveBeenCalledOnce();
    const [path, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(path).toBe("/api/audit/v1/records:query");
    expect(init).toEqual(expect.objectContaining({ method: "POST", cache: "no-store", headers: expect.objectContaining({ Authorization: "Bearer session-secret", "Content-Type": "application/json" }) }));
    expect(JSON.parse(String(init.body))).toEqual({ pageSize: 25, action: "paas.deployment.created", actor: { type: "USER", id: "principal-developer" } });
    expect(String(init.body)).not.toContain("tenant");
  });

  it("fails closed on unknown fields and cross-tenant records", async () => {
    const unknown = { ...recordPage(), total: 1 };
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(response(unknown)));
    await expect(httpAuditRepository.query("session-secret", { pageSize: 10 })).rejects.toThrow("INVALID_AUDIT_RECORD_PAGE");

    const crossTenant = recordPage();
    crossTenant.records[0]!.event.tenantId = "organization-other";
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(response(crossTenant)));
    await expect(httpAuditRepository.query("session-secret", { pageSize: 10 })).rejects.toThrow("INVALID_AUDIT_RECORD_ORDER");
  });

  it("decodes role-session lineage and rejects unknown nested identity fields", () => {
    const rolePage = recordPage();
    rolePage.records[0]!.event.actor = {
      type: "ROLE",
      id: "role-deployer",
      roleSession: { sessionId: "session-deploy", sourceUserId: "principal-developer" }
    } as never;
    expect(parseAuditRecordPage(rolePage, "TENANT").records[0]!.event.actor).toEqual({
      type: "ROLE",
      id: "role-deployer",
      roleSession: { sessionId: "session-deploy", sourceUserId: "principal-developer" }
    });

    const unknownLineage = structuredClone(rolePage);
    (unknownLineage.records[0]!.event.actor as unknown as Record<string, unknown>).displayName = "must not be trusted";
    expect(() => parseAuditRecordPage(unknownLineage, "TENANT")).toThrow("INVALID_AUDIT_ACTOR");
  });

  it("requires exactly one authority and keeps tenant and platform responses distinct", () => {
    const both = structuredClone(recordPage()) as unknown as Record<string, unknown>;
    both.installationId = "installation-test";
    expect(() => parseAuditRecordPage(both)).toThrow("INVALID_AUDIT_AUTHORITY");

    const platform = structuredClone(recordPage()) as unknown as Record<string, unknown>;
    delete platform.tenantId;
    platform.installationId = "installation-test";
    const platformRecord = ((platform.records as Array<Record<string, unknown>>)[0]!);
    const platformEvent = platformRecord.event as Record<string, unknown>;
    delete platformEvent.tenantId;
    platformEvent.installationId = "installation-test";
    expect(parseAuditRecordPage(platform, "INSTALLATION")).toMatchObject({ authorityKind: "INSTALLATION", installationId: "installation-test" });
    expect(() => parseAuditRecordPage(platform, "TENANT")).toThrow("INVALID_AUDIT_AUTHORITY");
  });

  it("validates bounded chain-verification evidence", async () => {
    const verification = {
      apiVersion: AUDIT_API_VERSION,
      kind: "ChainVerification",
      tenantId: "organization-test",
      state: "VERIFIED",
      fromSequence: 1,
      toSequence: 42,
      recordCount: 42,
      firstPreviousHash: hash("0"),
      lastRecordHash: hash("4"),
      complete: false,
      nextSequence: 43,
      verifiedAt: "2026-08-25T03:06:07.000Z"
    };
    const fetchMock = vi.fn().mockResolvedValue(response(verification));
    vi.stubGlobal("fetch", fetchMock);

    await expect(httpAuditRepository.verify("session-secret", { fromSequence: 1, maximumRecords: 42 })).resolves.toMatchObject({ complete: false, nextSequence: 43 });
    const [path, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(path).toBe("/api/audit/v1/integrity:verify");
    expect(JSON.parse(String(init.body))).toEqual({ fromSequence: 1, maximumRecords: 42 });
  });

  it("rejects chain verification without exactly one authority", () => {
    const verification = {
      apiVersion: AUDIT_API_VERSION,
      kind: "ChainVerification",
      state: "VERIFIED",
      fromSequence: 1,
      toSequence: 1,
      recordCount: 1,
      firstPreviousHash: hash("0"),
      lastRecordHash: hash("4"),
      complete: true,
      verifiedAt: "2026-08-25T03:06:07.000Z"
    };
    expect(() => parseAuditChainVerification(verification)).toThrow("INVALID_AUDIT_AUTHORITY");
  });
});
