import { requestJSON, requestToken } from "@/infrastructure/http/jsonRequest";
import type {
  ActivateQuotaCommand,
  ControlPlaneSnapshot,
  CreateInstallationCommand,
  QuotaEntitlement,
  QuotaShape,
  Region,
  ServiceInstallation,
  ServiceOffering
} from "../domain/resources";
import type { ControlPlaneRepository } from "./controlPlaneRepository";

type UnknownRecord = Record<string, unknown>;

function record(value: unknown, name: string): UnknownRecord {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`INVALID_${name.toUpperCase()}_RESPONSE`);
  }
  return value as UnknownRecord;
}

function text(value: unknown, name: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`INVALID_${name.toUpperCase()}_RESPONSE`);
  }
  return value;
}

function integer(value: unknown, name: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new Error(`INVALID_${name.toUpperCase()}_RESPONSE`);
  }
  return value;
}

function nullableText(value: unknown, name: string): string | null {
  if (value === null) return null;
  return text(value, name);
}

function listItems(value: unknown, expectedKind: string): unknown[] {
  const wire = record(value, expectedKind);
  if (wire.kind !== expectedKind || !Array.isArray(wire.items)) {
    throw new Error(`INVALID_${expectedKind.toUpperCase()}_RESPONSE`);
  }
  return wire.items;
}

function parseShape(value: unknown): QuotaShape {
  const wire = record(value, "quota shape");
  return {
    id: text(wire.id, "quota shape id"),
    displayName: text(wire.displayName, "quota shape display name"),
    cpuMillicores: integer(wire.cpuMillicores, "quota cpu"),
    memoryMiB: integer(wire.memoryMiB, "quota memory"),
    storageGiB: integer(wire.storageGiB, "quota storage")
  };
}

function parseOffering(value: unknown): ServiceOffering {
  const wire = record(value, "offering");
  if (
    wire.kind !== "POSTGRESQL" ||
    (wire.state !== "AVAILABLE" && wire.state !== "UNAVAILABLE") ||
    !Array.isArray(wire.quotaShapes)
  ) {
    throw new Error("INVALID_OFFERING_RESPONSE");
  }
  return {
    id: text(wire.id, "offering id"),
    kind: "POSTGRESQL",
    displayName: text(wire.displayName, "offering display name"),
    description: text(wire.description, "offering description"),
    engineFamily: text(wire.engineFamily, "engine family"),
    engineVersion: text(wire.engineVersion, "engine version"),
    state: wire.state,
    quotaShapes: wire.quotaShapes.map(parseShape)
  };
}

function parseRegion(value: unknown): Region {
  const wire = record(value, "region");
  const capacity = record(wire.capacity, "region capacity");
  if (
    wire.profile !== "LOCAL_MACHINE" ||
    !["READY", "STALE", "UNAVAILABLE"].includes(String(wire.state))
  ) {
    throw new Error("INVALID_REGION_RESPONSE");
  }
  return {
    id: text(wire.id, "region id"),
    displayName: text(wire.displayName, "region display name"),
    profile: "LOCAL_MACHINE",
    state: wire.state as Region["state"],
    inspectedAt: wire.inspectedAt === null ? null : text(wire.inspectedAt, "region inspected time"),
    capacity: {
      cpuMillicores: integer(capacity.cpuMillicores, "region cpu"),
      memoryMiB: integer(capacity.memoryMiB, "region memory"),
      storageGiB: integer(capacity.storageGiB, "region storage")
    }
  };
}

function parseEntitlement(value: unknown): QuotaEntitlement {
  const wire = record(value, "quota entitlement");
  return {
    id: text(wire.id, "entitlement id"),
    offeringId: text(wire.offeringId, "entitlement offering"),
    quotaShapeId: text(wire.quotaShapeId, "entitlement shape"),
    purchasedCount: integer(wire.purchasedCount, "entitlement count"),
    reservedCount: integer(wire.reservedCount, "entitlement reserved"),
    consumedCount: integer(wire.consumedCount, "entitlement consumed"),
    resourceVersion: integer(wire.resourceVersion, "entitlement version"),
    activatedAt: text(wire.activatedAt, "entitlement activation")
  };
}

function parseInstallation(value: unknown): ServiceInstallation {
  const wire = record(value, "service installation");
  const operation = record(wire.operation, "installation operation");
  const phase = String(wire.phase);
  if (!["PENDING", "PROVISIONING", "READY", "FAILED"].includes(phase)) {
    throw new Error("INVALID_INSTALLATION_RESPONSE");
  }
  return {
    id: text(wire.id, "installation id"),
    name: text(wire.name, "installation name"),
    offeringId: text(wire.offeringId, "installation offering"),
    engineVersion: text(wire.engineVersion, "installation engine version"),
    quotaEntitlementId: text(wire.quotaEntitlementId, "installation entitlement"),
    regionId: text(wire.regionId, "installation region"),
    phase: phase as ServiceInstallation["phase"],
    endpoint: nullableText(wire.endpoint, "installation endpoint"),
    credentialReference: nullableText(wire.credentialReference, "installation credential reference"),
    createdAt: text(wire.createdAt, "installation creation"),
    operation: {
      id: text(operation.id, "operation id"),
      phase: phase as ServiceInstallation["phase"],
      safeFailureCode: nullableText(operation.safeFailureCode, "operation failure"),
      observedAt: text(operation.observedAt, "operation observation")
    }
  };
}

function authorization(credential: string): HeadersInit {
  return { Authorization: `Bearer ${credential}` };
}

export const httpControlPlaneRepository: ControlPlaneRepository = {
  async load(credential: string): Promise<ControlPlaneSnapshot> {
    const headers = authorization(credential);
    const [offerings, regions, entitlements, installations] = await Promise.all([
      requestJSON<unknown>("/api/managed-services/v1/offerings", { headers }),
      requestJSON<unknown>("/api/managed-services/v1/regions", { headers }),
      requestJSON<unknown>("/api/managed-services/v1/quota-entitlements", { headers }),
      requestJSON<unknown>("/api/managed-services/v1/service-installations", { headers })
    ]);
    return {
      offerings: listItems(offerings, "ServiceOfferingList").map(parseOffering),
      regions: listItems(regions, "RegionList").map(parseRegion),
      entitlements: listItems(entitlements, "QuotaEntitlementList").map(parseEntitlement),
      installations: listItems(installations, "ServiceInstallationList").map(parseInstallation)
    };
  },

  async activateQuota(credential, command: ActivateQuotaCommand) {
    const value = await requestJSON<unknown>("/api/managed-services/v1/quota-entitlements", {
      method: "POST",
      headers: {
        ...authorization(credential),
        "Content-Type": "application/json",
        "Idempotency-Key": requestToken("ui-quota-")
      },
      body: JSON.stringify(command)
    });
    return parseEntitlement(value);
  },

  async createInstallation(credential, command: CreateInstallationCommand) {
    const value = await requestJSON<unknown>("/api/managed-services/v1/service-installations", {
      method: "POST",
      headers: {
        ...authorization(credential),
        "Content-Type": "application/json",
        "Idempotency-Key": requestToken("ui-install-")
      },
      body: JSON.stringify(command)
    });
    return parseInstallation(value);
  }
};
