import { describe, expect, it } from "vitest";
import type { ControlPlaneSnapshot } from "../domain/resources";
import { buildConsoleScene } from "./buildConsoleScene";

const snapshot: ControlPlaneSnapshot = {
  offerings: [{
    id: "postgresql-18",
    kind: "POSTGRESQL",
    displayName: "PostgreSQL",
    description: "托管关系数据库",
    engineFamily: "PostgreSQL",
    engineVersion: "18",
    state: "AVAILABLE",
    quotaShapes: [{
      id: "development",
      displayName: "开发型",
      cpuMillicores: 1000,
      memoryMiB: 2048,
      storageGiB: 20
    }]
  }],
  regions: [{
    id: "local-primary",
    displayName: "本机主区域",
    profile: "LOCAL_MACHINE",
    state: "READY",
    inspectedAt: "2026-08-26T12:00:00Z",
    capacity: { cpuMillicores: 8000, memoryMiB: 16384, storageGiB: 500 }
  }],
  entitlements: [{
    id: "quota-postgres-dev",
    offeringId: "postgresql-18",
    quotaShapeId: "development",
    purchasedCount: 2,
    reservedCount: 0,
    consumedCount: 1,
    resourceVersion: 1,
    activatedAt: "2026-08-26T12:00:00Z"
  }],
  installations: [{
    id: "postgres-primary",
    name: "Primary database",
    offeringId: "postgresql-18",
    engineVersion: "18",
    quotaEntitlementId: "quota-postgres-dev",
    regionId: "local-primary",
    phase: "READY",
    endpoint: "postgres-primary.local:5432",
    credentialReference: "credential-postgres-primary",
    createdAt: "2026-08-26T12:00:00Z",
    operation: {
      id: "operation-postgres-primary",
      phase: "READY",
      safeFailureCode: null,
      observedAt: "2026-08-26T12:05:00Z"
    }
  }]
};

describe("buildConsoleScene", () => {
  it("projects real resources into the complete console shell", () => {
    const scene = buildConsoleScene("overview", snapshot);
    expect(scene.rail.map((item) => item.label)).toEqual(["控制面概览", "托管数据库", "访问管理"]);
    expect(scene.navigation.map((item) => item.id)).toEqual([
      "catalog",
      "quotas",
      "installations",
      "regions",
      "access"
    ]);
    expect(scene.content.kind).toBe("overview");
    if (scene.content.kind === "overview") {
      expect(scene.content.metrics.find((item) => item.id === "quota")?.value).toBe("1");
      expect(scene.content.recentInstallations[0]?.endpoint).toBe("postgres-primary.local:5432");
    }
    expect(scene.workspace).toMatchObject({ kind: "platform-status", readyRegions: 1 });
  });

  it("exposes install choices only from available quota and ready regions", () => {
    const scene = buildConsoleScene("installations", snapshot);
    expect(scene.workspace).toMatchObject({
      kind: "installation-order",
      entitlementOptions: [{
        entitlementId: "quota-postgres-dev",
        offeringId: "postgresql-18",
        available: 1
      }],
      regionOptions: [{ id: "local-primary", label: "本机主区域" }]
    });
  });

  it("contains no donor social vocabulary", () => {
    const serialized = JSON.stringify(buildConsoleScene("catalog", snapshot)).toLowerCase();
    for (const forbidden of ["guild", "channel", "message", "friend", "discord"]) {
      expect(serialized).not.toContain(forbidden);
    }
  });
});
