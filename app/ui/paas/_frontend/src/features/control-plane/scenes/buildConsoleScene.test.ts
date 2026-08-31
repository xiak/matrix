import { describe, expect, it } from "vitest";
import type { ControlPlaneSnapshot } from "../domain/resources";
import type { HostInventory } from "../domain/hosts";
import type { DeploymentInventory, DeploymentRuntimeSnapshot } from "../domain/deployments";
import {
  buildConsoleScene,
  buildDeploymentConsoleScene,
  buildHostConsoleScene
} from "./buildConsoleScene";

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

const deployments: DeploymentInventory = {
  tenantId: "tenant-alpha",
  nextAfter: "deployment-next",
  items: [{
    id: "deployment-alpha",
    name: "database-alpha",
    tenantId: "tenant-alpha",
    resourceVersion: 4,
    generation: 2,
    applicationRevisionId: "revision-alpha-v2",
    placementPolicyId: "placement-policy-default",
    desiredState: "RUNNING",
    components: [{ name: "database", replicas: 1 }],
    phase: "READY",
    observedGeneration: 2,
    placementDecisionId: "decision-alpha",
    currentOperationId: null,
    observedApplicationRevisionId: "revision-alpha-v2",
    readyComponents: 1,
    observedAt: "2026-08-30T08:01:00Z",
    createdAt: "2026-08-30T07:00:00Z",
    updatedAt: "2026-08-30T08:01:00Z"
  }]
};

const runtime: DeploymentRuntimeSnapshot = {
  tenantId: "tenant-alpha",
  state: "STALE",
  value: {
    deploymentId: "deployment-alpha",
    generation: 2,
    applicationRevisionId: "revision-alpha-v2",
    executionTargetId: "node-a",
    instances: [{
      id: "instance-0123456789abcdef0123456789abcdef",
      componentName: "database",
      state: "RUNNING",
      health: "HEALTHY",
      exitCode: null
    }],
    observedAt: "2026-08-30T08:01:00Z",
    validUntil: "2026-08-30T08:01:15Z"
  },
  resources: {
    state: "STALE",
    value: {
      deploymentId: "deployment-alpha",
      generation: 2,
      applicationRevisionId: "revision-alpha-v2",
      executionTargetId: "node-a",
      instances: [{
        id: "instance-0123456789abcdef0123456789abcdef",
        cpu: { state: "AVAILABLE", value: { windowMillis: 1000, usedCores: 0.25, limitCpuMillis: 500 } },
        memory: { state: "AVAILABLE", value: { usedBytes: 268435456, limitBytes: 536870912 } },
        network: { state: "AVAILABLE", value: {
          receivedBytes: 1024, transmittedBytes: 2048,
          receiveErrors: 0, transmitErrors: 0, receiveDrops: 0, transmitDrops: 0
        } },
        blockIo: { state: "AVAILABLE", value: {
          readBytes: 4096, writeBytes: 8192, readOperations: 4, writeOperations: 8
        } },
        storage: { state: "STALE", value: {
          observedAt: "2026-08-30T08:00:45Z",
          validUntil: "2026-08-30T08:01:15Z",
          writableLayerBytes: 16384,
          imageTotalBytes: 104857600,
          imageSharedBytes: 52428800,
          imageUniqueBytes: 52428800,
          volumesState: "AVAILABLE",
          volumes: { count: 2, bytes: 2097152, sharedCount: 1, sharedBytes: 1048576 }
        } }
      }],
      observedAt: "2026-08-30T08:01:00Z",
      validUntil: "2026-08-30T08:01:15Z"
    }
  }
};

describe("buildConsoleScene", () => {
  it("projects real resources into the complete console shell", () => {
    const scene = buildConsoleScene("overview", snapshot);
    expect(scene.rail.map((item) => item.label)).toEqual(["控制面概览", "托管数据库", "应用托管", "基础设施", "访问管理"]);
    expect(scene.navigation.map((item) => item.id)).toEqual([
      "catalog",
      "quotas",
      "installations",
      "deployments",
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

  it("projects only the selected deployment runtime and preserves stale source proof", () => {
    const scene = buildDeploymentConsoleScene(deployments, "deployment-alpha", runtime);
    expect(scene.section).toBe("deployments");
    expect(scene.rail.find((item) => item.id === "workloads")?.selected).toBe(true);
    expect(scene.content).toMatchObject({
      kind: "deployments",
      selectedDeploymentId: "deployment-alpha",
      truncated: true,
      deployments: [{ id: "deployment-alpha", selected: true, readiness: "1/1 组件就绪" }],
      runtime: {
        state: "STALE",
        stateLabel: "采样已过期",
        executionTargetId: "node-a",
        resources: {
          state: "STALE",
          stateLabel: "资源采样已过期"
        },
        instances: [{
          id: "instance-0123456789abcdef0123456789abcdef",
          stateLabel: "运行中",
          healthLabel: "健康",
          resources: {
            cpu: { state: "AVAILABLE", value: "0.25 核 / 上限 500m" },
            memory: { value: "256 MiB / 512 MiB" },
            storage: { state: "STALE", value: "可写层 16 KiB · 镜像独占 50 MiB" }
          }
        }]
      }
    });
  });
});
