import type {
  ControlPlaneSnapshot,
  QuotaEntitlement,
  ServiceInstallation
} from "../domain/resources";
import type { ControlPlaneRepository } from "./controlPlaneRepository";
import { previewCredential } from "@/features/auth/repositories/previewIamRepository";

let entitlementSequence = 3;

let snapshot: ControlPlaneSnapshot = {
  offerings: [{
    id: "postgresql-18",
    kind: "POSTGRESQL",
    displayName: "PostgreSQL 18",
    description: "平台托管的高可用关系数据库，制品、凭据与生命周期策略均由服务端管理。",
    engineFamily: "PostgreSQL",
    engineVersion: "18",
    state: "AVAILABLE",
    quotaShapes: [
      { id: "development", displayName: "开发型", cpuMillicores: 1000, memoryMiB: 2048, storageGiB: 20 },
      { id: "production", displayName: "生产型", cpuMillicores: 4000, memoryMiB: 8192, storageGiB: 100 },
      { id: "performance", displayName: "性能型", cpuMillicores: 8000, memoryMiB: 16384, storageGiB: 250 }
    ]
  }],
  regions: [
    {
      id: "shanghai-a",
      displayName: "上海私有云 A 区",
      profile: "LOCAL_MACHINE",
      state: "READY",
      inspectedAt: "2026-09-07T00:56:00Z",
      capacity: { cpuMillicores: 64000, memoryMiB: 262144, storageGiB: 4096 }
    },
    {
      id: "shanghai-b",
      displayName: "上海私有云 B 区",
      profile: "LOCAL_MACHINE",
      state: "READY",
      inspectedAt: "2026-09-07T00:52:00Z",
      capacity: { cpuMillicores: 48000, memoryMiB: 196608, storageGiB: 3072 }
    }
  ],
  entitlements: [
    { id: "quota-postgres-production", offeringId: "postgresql-18", quotaShapeId: "production", purchasedCount: 4, reservedCount: 1, consumedCount: 2, resourceVersion: 4, activatedAt: "2026-08-14T02:20:00Z" },
    { id: "quota-postgres-development", offeringId: "postgresql-18", quotaShapeId: "development", purchasedCount: 6, reservedCount: 0, consumedCount: 2, resourceVersion: 2, activatedAt: "2026-08-20T07:45:00Z" }
  ],
  installations: [
    {
      id: "pg-order-prod",
      name: "订单主库",
      offeringId: "postgresql-18",
      engineVersion: "18",
      quotaEntitlementId: "quota-postgres-production",
      regionId: "shanghai-a",
      phase: "READY",
      endpoint: "pg-order-prod.service.local:5432",
      credentialReference: "credential-pg-order-prod",
      createdAt: "2026-08-18T03:30:00Z",
      operation: { id: "operation-pg-order-prod", phase: "READY", safeFailureCode: null, observedAt: "2026-09-07T00:58:00Z" }
    },
    {
      id: "pg-matrix-dev",
      name: "Matrix 开发库",
      offeringId: "postgresql-18",
      engineVersion: "18",
      quotaEntitlementId: "quota-postgres-development",
      regionId: "shanghai-b",
      phase: "READY",
      endpoint: "pg-matrix-dev.service.local:5432",
      credentialReference: "credential-pg-matrix-dev",
      createdAt: "2026-08-25T09:10:00Z",
      operation: { id: "operation-pg-matrix-dev", phase: "READY", safeFailureCode: null, observedAt: "2026-09-07T00:57:00Z" }
    },
    {
      id: "pg-analytics-stage",
      name: "分析预发库",
      offeringId: "postgresql-18",
      engineVersion: "18",
      quotaEntitlementId: "quota-postgres-production",
      regionId: "shanghai-b",
      phase: "PROVISIONING",
      endpoint: null,
      credentialReference: null,
      createdAt: "2026-09-07T00:55:00Z",
      operation: { id: "operation-pg-analytics-stage", phase: "PROVISIONING", safeFailureCode: null, observedAt: "2026-09-07T00:58:00Z" }
    }
  ]
};

function requirePreviewCredential(credential: string): void {
  if (credential !== previewCredential) throw new Error("INVALID_PREVIEW_CREDENTIAL");
}

function copySnapshot(): ControlPlaneSnapshot {
  return structuredClone(snapshot);
}

function currentTime(): string {
  return new Date().toISOString();
}

export const previewControlPlaneRepository: ControlPlaneRepository = {
  async load(credential) {
    requirePreviewCredential(credential);
    return copySnapshot();
  },
  async getInstallation(credential, installationId) {
    requirePreviewCredential(credential);
    const current = snapshot.installations.find((item) => item.id === installationId);
    if (!current) throw new Error("PREVIEW_INSTALLATION_NOT_FOUND");
    if (current.phase === "PENDING" || current.phase === "PROVISIONING") {
      const ready: ServiceInstallation = {
        ...current,
        phase: "READY",
        endpoint: `${current.id}.service.local:5432`,
        credentialReference: `credential-${current.id}`,
        operation: { ...current.operation, phase: "READY", observedAt: currentTime() }
      };
      snapshot = {
        ...snapshot,
        installations: snapshot.installations.map((item) => item.id === installationId ? ready : item)
      };
      return structuredClone(ready);
    }
    return structuredClone(current);
  },
  async activateQuota(credential, command) {
    requirePreviewCredential(credential);
    entitlementSequence += 1;
    const entitlement: QuotaEntitlement = {
      id: `quota-preview-${entitlementSequence}`,
      offeringId: command.offeringId,
      quotaShapeId: command.quotaShapeId,
      purchasedCount: command.instanceCount,
      reservedCount: 0,
      consumedCount: 0,
      resourceVersion: 1,
      activatedAt: currentTime()
    };
    snapshot = { ...snapshot, entitlements: [...snapshot.entitlements, entitlement] };
    return structuredClone(entitlement);
  },
  async createInstallation(credential, command) {
    requirePreviewCredential(credential);
    const installation: ServiceInstallation = {
      id: command.id,
      name: command.name,
      offeringId: command.offeringId,
      engineVersion: "18",
      quotaEntitlementId: command.quotaEntitlementId,
      regionId: command.regionId,
      phase: "PENDING",
      endpoint: null,
      credentialReference: null,
      createdAt: currentTime(),
      operation: {
        id: `operation-${command.id}`,
        phase: "PENDING",
        safeFailureCode: null,
        observedAt: currentTime()
      }
    };
    snapshot = { ...snapshot, installations: [...snapshot.installations, installation] };
    return structuredClone(installation);
  }
};
