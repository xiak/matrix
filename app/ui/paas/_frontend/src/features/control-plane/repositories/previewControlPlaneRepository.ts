import type {
  ControlPlaneSnapshot,
  QuotaEntitlement,
  ServiceInstallation
} from "../domain/resources";
import type { ControlPlaneRepository } from "./controlPlaneRepository";
import type { ControlPlaneResourceSnapshot } from "./controlPlaneRepository";
import { isPreviewCredential } from "@/features/auth/repositories/previewIamRepository";

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
      { id: "pg-small", displayName: "开发型", cpuMillicores: 500, memoryMiB: 1024, storageGiB: 10 },
      { id: "pg-medium", displayName: "标准型", cpuMillicores: 1000, memoryMiB: 2048, storageGiB: 20 }
    ]
  }, {
    id: "mysql-8.4",
    kind: "MYSQL",
    displayName: "MySQL 8.4 LTS",
    description: "由 Matrix 在本地区域安装和管理的 MySQL 8.4 LTS 服务。",
    engineFamily: "MySQL",
    engineVersion: "8.4",
    state: "AVAILABLE",
    quotaShapes: [
      { id: "mysql-small", displayName: "开发型", cpuMillicores: 500, memoryMiB: 1024, storageGiB: 10 },
      { id: "mysql-medium", displayName: "标准型", cpuMillicores: 1000, memoryMiB: 2048, storageGiB: 20 }
    ]
  }, {
    id: "elasticsearch-8.19",
    kind: "ELASTICSEARCH",
    displayName: "Elasticsearch 8.19",
    description: "由 Matrix 在本地区域安装和管理的 Elasticsearch 8.19 搜索服务。",
    engineFamily: "Elasticsearch",
    engineVersion: "8.19.23",
    state: "AVAILABLE",
    quotaShapes: [
      { id: "elasticsearch-small", displayName: "开发型", cpuMillicores: 1000, memoryMiB: 1536, storageGiB: 10 },
      { id: "elasticsearch-medium", displayName: "标准型", cpuMillicores: 2000, memoryMiB: 3072, storageGiB: 20 }
    ]
  }, {
    id: "rabbitmq-4.1",
    kind: "RABBITMQ",
    displayName: "RabbitMQ 4.1",
    description: "由 Matrix 在本地区域安装和管理的 RabbitMQ 4.1 消息队列服务。",
    engineFamily: "RabbitMQ",
    engineVersion: "4.1.8",
    state: "AVAILABLE",
    quotaShapes: [
      { id: "rabbitmq-small", displayName: "开发型", cpuMillicores: 500, memoryMiB: 768, storageGiB: 10 },
      { id: "rabbitmq-medium", displayName: "标准型", cpuMillicores: 1000, memoryMiB: 1536, storageGiB: 20 }
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
    { id: "quota-postgres-production", offeringId: "postgresql-18", quotaShapeId: "pg-medium", purchasedCount: 4, reservedCount: 1, consumedCount: 2, resourceVersion: 4, activatedAt: "2026-08-14T02:20:00Z" },
    { id: "quota-postgres-development", offeringId: "postgresql-18", quotaShapeId: "pg-small", purchasedCount: 6, reservedCount: 0, consumedCount: 2, resourceVersion: 2, activatedAt: "2026-08-20T07:45:00Z" }
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
      resourceVersion: 3,
      createdAt: "2026-08-18T03:30:00Z",
      operation: { id: "operation-pg-order-prod", kind: "PROVISION", phase: "READY", safeFailureCode: null, observedAt: "2026-09-07T00:58:00Z" }
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
      resourceVersion: 2,
      createdAt: "2026-08-25T09:10:00Z",
      operation: { id: "operation-pg-matrix-dev", kind: "PROVISION", phase: "READY", safeFailureCode: null, observedAt: "2026-09-07T00:57:00Z" }
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
      resourceVersion: 1,
      createdAt: "2026-09-07T00:55:00Z",
      operation: { id: "operation-pg-analytics-stage", kind: "PROVISION", phase: "PROVISIONING", safeFailureCode: null, observedAt: "2026-09-07T00:58:00Z" }
    }
  ]
};

function requirePreviewCredential(credential: string): void {
  if (!isPreviewCredential(credential)) throw new Error("INVALID_PREVIEW_CREDENTIAL");
}

function copySnapshot(resources: Parameters<ControlPlaneRepository["load"]>[1]): ControlPlaneResourceSnapshot {
  return Object.fromEntries(resources.map((resource) => [resource, structuredClone(snapshot[resource])])) as ControlPlaneResourceSnapshot;
}

function currentTime(): string {
  return new Date().toISOString();
}

function previewEndpoint(installation: ServiceInstallation): string {
  const kind = snapshot.offerings.find((offering) => offering.id === installation.offeringId)?.kind;
  const port = kind === "MYSQL" ? 3306 : kind === "ELASTICSEARCH" ? 9200 : kind === "RABBITMQ" ? 5672 : 5432;
  return `${installation.id}.service.local:${port}`;
}

export const previewControlPlaneRepository: ControlPlaneRepository = {
  async load(credential, resources) {
    requirePreviewCredential(credential);
    return copySnapshot(resources);
  },
  async getInstallation(credential, installationId) {
    requirePreviewCredential(credential);
    const current = snapshot.installations.find((item) => item.id === installationId);
    if (!current) throw new Error("PREVIEW_INSTALLATION_NOT_FOUND");
    if (current.phase === "PENDING" || current.phase === "PROVISIONING") {
      const ready: ServiceInstallation = {
        ...current,
        phase: "READY",
        endpoint: previewEndpoint(current),
        credentialReference: `credential-${current.id}`,
        resourceVersion: current.resourceVersion + 1,
        operation: { ...current.operation, phase: "READY", observedAt: currentTime() }
      };
      snapshot = {
        ...snapshot,
        installations: snapshot.installations.map((item) => item.id === installationId ? ready : item)
      };
      return structuredClone(ready);
    }
    if (current.phase === "TERMINATION_PENDING" || current.phase === "TERMINATING") {
      const terminated: ServiceInstallation = {
        ...current,
        phase: "TERMINATED",
        endpoint: null,
        credentialReference: null,
        resourceVersion: current.resourceVersion + 1,
        operation: { ...current.operation, phase: "TERMINATED", observedAt: currentTime() }
      };
      snapshot = {
        ...snapshot,
        installations: snapshot.installations.filter((item) => item.id !== installationId)
      };
      return structuredClone(terminated);
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
    const offering = snapshot.offerings.find((item) => item.id === command.offeringId);
    if (!offering) throw new Error("PREVIEW_OFFERING_NOT_FOUND");
    const installation: ServiceInstallation = {
      id: command.id,
      name: command.name,
      offeringId: command.offeringId,
      engineVersion: offering.engineVersion,
      quotaEntitlementId: command.quotaEntitlementId,
      regionId: command.regionId,
      phase: "PENDING",
      endpoint: null,
      credentialReference: null,
      resourceVersion: 1,
      createdAt: currentTime(),
      operation: {
        id: `operation-${command.id}`,
        kind: "PROVISION",
        phase: "PENDING",
        safeFailureCode: null,
        observedAt: currentTime()
      }
    };
    snapshot = { ...snapshot, installations: [...snapshot.installations, installation] };
    return structuredClone(installation);
  },
  async terminateInstallation(credential, installationId) {
    requirePreviewCredential(credential);
    const current = snapshot.installations.find((item) => item.id === installationId);
    if (!current) throw new Error("PREVIEW_INSTALLATION_NOT_FOUND");
    if (!["READY", "ROLLBACK_FAILED", "TERMINATION_FAILED"].includes(current.phase)) {
      throw new Error("PREVIEW_INSTALLATION_STATE_CONFLICT");
    }
    const terminating: ServiceInstallation = {
      ...current,
      phase: "TERMINATION_PENDING",
      resourceVersion: current.resourceVersion + 1,
      operation: {
        id: `operation-terminate-${installationId}`,
        kind: "TERMINATE",
        phase: "TERMINATION_PENDING",
        safeFailureCode: null,
        observedAt: currentTime()
      }
    };
    snapshot = {
      ...snapshot,
      installations: snapshot.installations.map((item) => item.id === installationId ? terminating : item)
    };
    return structuredClone(terminating);
  }
};
