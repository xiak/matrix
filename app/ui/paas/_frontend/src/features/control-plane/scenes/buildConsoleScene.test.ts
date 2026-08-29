import { describe, expect, it } from "vitest";
import type { ControlPlaneSnapshot } from "../domain/resources";
import type { HostInventory } from "../domain/hosts";
import { buildConsoleScene, buildHostConsoleScene } from "./buildConsoleScene";

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

const hosts: HostInventory = {
  items: [{
    id: "node-a",
    name: "node-a",
    labels: { "matrix-os": "linux", "matrix-arch": "amd64" },
    resourceVersion: 4,
    executionPoolId: "linux-hosts",
    infrastructureAdapter: "nodehttps",
    deploymentExecutor: "compose",
    desiredState: "ACTIVE",
    health: "READY",
    capacity: { cpuMillis: 4000, memoryBytes: 8_589_934_592, storageBytes: 107_374_182_400, workloadSlots: 24 },
    allocatable: { cpuMillis: 3000, memoryBytes: 6_442_450_944, storageBytes: 85_899_345_920, workloadSlots: 16 },
    supportedIsolationGuarantees: ["WORKLOAD"],
    observedAt: "2026-08-30T08:01:00Z",
    usage: {
      observedAt: "2026-08-30T08:01:00Z",
      validUntil: "2026-08-30T08:01:15Z",
      cpu: {
        state: "AVAILABLE",
        value: { logicalCpus: 4, windowMillis: 5000, utilizationRatio: 0.25, ioWaitRatio: 0.05, load1: 0.8, load5: 0.6, load15: 0.4 }
      },
      memory: {
        state: "AVAILABLE",
        value: { totalBytes: 8_589_934_592, availableBytes: 6_442_450_944, usedBytes: 2_147_483_648, swapTotalBytes: 0, swapFreeBytes: 0 }
      },
      filesystemsState: "AVAILABLE",
      filesystems: [{
        device: "/dev/vda1", mountPoint: "/", filesystemType: "ext4", state: "AVAILABLE",
        value: { totalBytes: 107_374_182_400, usedBytes: 21_474_836_480, availableBytes: 85_899_345_920, inodesState: "UNSUPPORTED", totalInodes: null, freeInodes: null, readOnly: false }
      }]
    }
  }]
};

describe("buildConsoleScene", () => {
  it("projects real resources into the complete console shell", () => {
    const scene = buildConsoleScene("overview", snapshot);
    expect(scene.rail.map((item) => item.label)).toEqual(["控制面概览", "托管数据库", "基础设施", "访问管理"]);
    expect(scene.navigation.map((item) => item.id)).toEqual([
      "catalog",
      "quotas",
      "installations",
      "regions",
      "hosts",
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

  it("projects source-timed host usage without converting it to placement capacity", () => {
    const scene = buildHostConsoleScene(hosts);
    expect(scene.section).toBe("hosts");
    expect(scene.rail.find((item) => item.id === "infrastructure")?.selected).toBe(true);
    expect(scene.content).toMatchObject({
      kind: "hosts",
      hosts: [{
        id: "node-a",
        health: "READY",
        sampleState: "采样有效",
        cpu: { value: "25.0%", progress: 25, state: "AVAILABLE" },
        memory: { progress: 25, state: "AVAILABLE" },
        filesystems: [{ mountPoint: "/", progress: 20 }]
      }]
    });
  });
});
