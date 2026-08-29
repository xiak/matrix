import { requestJSON } from "@/infrastructure/http/jsonRequest";
import type {
  HostCPUUsageValue,
  HostCapacity,
  HostFilesystemUsage,
  HostFilesystemUsageValue,
  HostInventory,
  HostMeasurementState,
  HostMemoryUsageValue,
  HostTarget,
  HostUsage
} from "../domain/hosts";
import type { HostInventoryRepository } from "./hostInventoryRepository";

type UnknownRecord = Record<string, unknown>;

const apiVersion = "paas.matrix.xiak.com/v1";
const maximumTargets = 129;
const maximumFilesystems = 128;
const measurementStates = new Set<HostMeasurementState>([
  "AVAILABLE", "WARMING_UP", "UNAVAILABLE", "UNSUPPORTED", "STALE"
]);

function invalid(name: string): Error {
  return new Error(`INVALID_${name.toUpperCase().replaceAll(/[^A-Z0-9]+/g, "_")}_RESPONSE`);
}

function record(value: unknown, name: string): UnknownRecord {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw invalid(name);
  }
  return value as UnknownRecord;
}

function closed(value: unknown, name: string, keys: readonly string[]): UnknownRecord {
  const wire = record(value, name);
  const allowed = new Set(keys);
  if (Object.keys(wire).some((key) => !allowed.has(key))) {
    throw invalid(name);
  }
  return wire;
}

function text(value: unknown, name: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw invalid(name);
  }
  return value;
}

function timestamp(value: unknown, name: string): string {
  const result = text(value, name);
  if (!Number.isFinite(Date.parse(result))) {
    throw invalid(name);
  }
  return result;
}

function integer(value: unknown, name: string, positive = false): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < (positive ? 1 : 0)) {
    throw invalid(name);
  }
  return value;
}

function ratio(value: unknown, name: string): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0 || value > 1) {
    throw invalid(name);
  }
  return value;
}

function nonnegative(value: unknown, name: string): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
    throw invalid(name);
  }
  return value;
}

function state(value: unknown, name: string, warming: boolean): HostMeasurementState {
  if (!measurementStates.has(value as HostMeasurementState) || (!warming && value === "WARMING_UP")) {
    throw invalid(name);
  }
  return value as HostMeasurementState;
}

function labels(value: unknown): Record<string, string> {
  if (value === undefined) return {};
  const wire = record(value, "host labels");
  if (Object.keys(wire).length > 64) throw new Error("INVALID_HOST_LABELS_RESPONSE");
  const result: Record<string, string> = {};
  for (const [key, item] of Object.entries(wire)) {
    result[text(key, "host label key")] = text(item, "host label value");
  }
  return result;
}

function capacity(value: unknown, name: string): HostCapacity {
  const wire = closed(value, name, ["cpuMillis", "memoryBytes", "storageBytes", "workloadSlots"]);
  return {
    cpuMillis: integer(wire.cpuMillis, `${name} cpu`),
    memoryBytes: integer(wire.memoryBytes, `${name} memory`),
    storageBytes: integer(wire.storageBytes, `${name} storage`),
    workloadSlots: integer(wire.workloadSlots, `${name} slots`)
  };
}

function cpuValue(value: unknown): HostCPUUsageValue {
  const wire = closed(value, "host cpu value", [
    "logicalCpus", "windowMillis", "utilizationRatio", "ioWaitRatio", "load1", "load5", "load15"
  ]);
  const result = {
    logicalCpus: integer(wire.logicalCpus, "host logical cpus", true),
    windowMillis: integer(wire.windowMillis, "host cpu window", true),
    utilizationRatio: ratio(wire.utilizationRatio, "host cpu utilization"),
    ioWaitRatio: ratio(wire.ioWaitRatio, "host cpu io wait"),
    load1: nonnegative(wire.load1, "host load 1"),
    load5: nonnegative(wire.load5, "host load 5"),
    load15: nonnegative(wire.load15, "host load 15")
  };
  if (result.logicalCpus > 4096 || result.windowMillis > 60_000 || result.utilizationRatio + result.ioWaitRatio > 1.000000001) {
    throw new Error("INVALID_HOST_CPU_VALUE_RESPONSE");
  }
  return result;
}

function memoryValue(value: unknown): HostMemoryUsageValue {
  const wire = closed(value, "host memory value", [
    "totalBytes", "availableBytes", "usedBytes", "swapTotalBytes", "swapFreeBytes"
  ]);
  const result = {
    totalBytes: integer(wire.totalBytes, "host total memory", true),
    availableBytes: integer(wire.availableBytes, "host available memory"),
    usedBytes: integer(wire.usedBytes, "host used memory"),
    swapTotalBytes: integer(wire.swapTotalBytes, "host swap total"),
    swapFreeBytes: integer(wire.swapFreeBytes, "host swap free")
  };
  if (result.availableBytes > result.totalBytes || result.usedBytes !== result.totalBytes - result.availableBytes || result.swapFreeBytes > result.swapTotalBytes) {
    throw new Error("INVALID_HOST_MEMORY_VALUE_RESPONSE");
  }
  return result;
}

function optionalMeasurementValue<T>(
  wire: UnknownRecord,
  measurementState: HostMeasurementState,
  parser: (value: unknown) => T
): T | null {
  const present = Object.hasOwn(wire, "value") && wire.value !== undefined;
  if (measurementState === "AVAILABLE" && !present) throw new Error("INVALID_HOST_MEASUREMENT_RESPONSE");
  if (["WARMING_UP", "UNAVAILABLE", "UNSUPPORTED"].includes(measurementState) && present) {
    throw new Error("INVALID_HOST_MEASUREMENT_RESPONSE");
  }
  return present ? parser(wire.value) : null;
}

function filesystemValue(value: unknown): HostFilesystemUsageValue {
  const wire = closed(value, "host filesystem value", [
    "totalBytes", "usedBytes", "availableBytes", "inodesState", "totalInodes", "freeInodes", "readOnly"
  ]);
  const inodesState = state(wire.inodesState, "host inode state", false);
  const hasTotal = Object.hasOwn(wire, "totalInodes");
  const hasFree = Object.hasOwn(wire, "freeInodes");
  if (hasTotal !== hasFree || (inodesState === "AVAILABLE" && !hasTotal) ||
      (["UNAVAILABLE", "UNSUPPORTED"].includes(inodesState) && hasTotal) || typeof wire.readOnly !== "boolean") {
    throw new Error("INVALID_HOST_FILESYSTEM_VALUE_RESPONSE");
  }
  const result: HostFilesystemUsageValue = {
    totalBytes: integer(wire.totalBytes, "host filesystem total"),
    usedBytes: integer(wire.usedBytes, "host filesystem used"),
    availableBytes: integer(wire.availableBytes, "host filesystem available"),
    inodesState,
    totalInodes: hasTotal ? integer(wire.totalInodes, "host total inodes", true) : null,
    freeInodes: hasFree ? integer(wire.freeInodes, "host free inodes") : null,
    readOnly: wire.readOnly
  };
  if (result.usedBytes > result.totalBytes || result.availableBytes > result.totalBytes - result.usedBytes ||
      (result.totalInodes !== null && result.freeInodes !== null && result.freeInodes > result.totalInodes)) {
    throw new Error("INVALID_HOST_FILESYSTEM_VALUE_RESPONSE");
  }
  return result;
}

function filesystem(value: unknown): HostFilesystemUsage {
  const wire = closed(value, "host filesystem", ["device", "mountPoint", "filesystemType", "state", "value"]);
  const measurementState = state(wire.state, "host filesystem state", false);
  const mountPoint = text(wire.mountPoint, "host mount point");
  if (!mountPoint.startsWith("/")) throw new Error("INVALID_HOST_MOUNT_POINT_RESPONSE");
  return {
    device: text(wire.device, "host filesystem device"),
    mountPoint,
    filesystemType: text(wire.filesystemType, "host filesystem type"),
    state: measurementState,
    value: optionalMeasurementValue(wire, measurementState, filesystemValue)
  };
}

function usage(value: unknown): HostUsage {
  const wire = closed(value, "host usage", ["observedAt", "validUntil", "cpu", "memory", "filesystemsState", "filesystems"]);
  const observedAt = timestamp(wire.observedAt, "host usage observation");
  const validUntil = timestamp(wire.validUntil, "host usage expiry");
  const lifetime = Date.parse(validUntil) - Date.parse(observedAt);
  if (lifetime <= 0 || lifetime > 60_000) throw new Error("INVALID_HOST_USAGE_WINDOW_RESPONSE");
  const cpu = closed(wire.cpu, "host cpu", ["state", "value"]);
  const cpuState = state(cpu.state, "host cpu state", true);
  const memory = closed(wire.memory, "host memory", ["state", "value"]);
  const memoryState = state(memory.state, "host memory state", false);
  const filesystemsState = state(wire.filesystemsState, "host filesystems state", false);
  const filesystemsWire = wire.filesystems === undefined ? [] : wire.filesystems;
  if (!Array.isArray(filesystemsWire) || filesystemsWire.length > maximumFilesystems ||
      (filesystemsState === "AVAILABLE" && filesystemsWire.length === 0) ||
      (["UNAVAILABLE", "UNSUPPORTED"].includes(filesystemsState) && filesystemsWire.length > 0)) {
    throw new Error("INVALID_HOST_FILESYSTEMS_RESPONSE");
  }
  const filesystems = filesystemsWire.map(filesystem);
  const identities = new Set(filesystems.map((item) => `${item.device}\0${item.mountPoint}\0${item.filesystemType}`));
  if (identities.size !== filesystems.length) throw new Error("INVALID_HOST_FILESYSTEMS_RESPONSE");
  return {
    observedAt,
    validUntil,
    cpu: { state: cpuState, value: optionalMeasurementValue(cpu, cpuState, cpuValue) },
    memory: { state: memoryState, value: optionalMeasurementValue(memory, memoryState, memoryValue) },
    filesystemsState,
    filesystems
  };
}

function adapterName(value: unknown, kind: "INFRASTRUCTURE" | "DEPLOYMENT_EXECUTOR"): string {
  const wire = closed(value, "host adapter", ["kind", "name", "contractVersion"]);
  if (wire.kind !== kind) throw new Error("INVALID_HOST_ADAPTER_RESPONSE");
  text(wire.contractVersion, "host adapter contract");
  return text(wire.name, "host adapter name");
}

function target(value: unknown): HostTarget {
  const wire = closed(value, "host target", ["apiVersion", "kind", "metadata", "spec", "status"]);
  if (wire.apiVersion !== apiVersion || wire.kind !== "ExecutionTarget") {
    throw new Error("INVALID_HOST_TARGET_RESPONSE");
  }
  const metadata = closed(wire.metadata, "host metadata", ["id", "name", "scope", "labels", "resourceVersion", "createdAt", "updatedAt"]);
  const scope = closed(metadata.scope, "host scope", ["kind"]);
  if (scope.kind !== "PLATFORM") throw new Error("INVALID_HOST_SCOPE_RESPONSE");
  timestamp(metadata.createdAt, "host created time");
  timestamp(metadata.updatedAt, "host updated time");
  const spec = closed(wire.spec, "host spec", ["executionPoolId", "infrastructureAdapter", "deploymentExecutor", "gatewayAdapter", "desiredState"]);
  if (Object.hasOwn(spec, "gatewayAdapter") && spec.gatewayAdapter !== undefined) {
    const gateway = closed(spec.gatewayAdapter, "host gateway adapter", ["kind", "name", "contractVersion"]);
    if (gateway.kind !== "GATEWAY") throw new Error("INVALID_HOST_GATEWAY_RESPONSE");
    text(gateway.name, "host gateway name");
    text(gateway.contractVersion, "host gateway contract");
  }
  if (spec.desiredState !== "ACTIVE" && spec.desiredState !== "DRAINING") {
    throw new Error("INVALID_HOST_DESIRED_STATE_RESPONSE");
  }
  const status = closed(wire.status, "host status", ["health", "capacity", "allocatable", "supportedIsolationGuarantees", "observedAt", "usage"]);
  if (!["UNKNOWN", "READY", "DEGRADED", "UNAVAILABLE"].includes(String(status.health)) || !Array.isArray(status.supportedIsolationGuarantees)) {
    throw new Error("INVALID_HOST_STATUS_RESPONSE");
  }
  const capacityValue = capacity(status.capacity, "host capacity");
  const allocatable = capacity(status.allocatable, "host allocatable");
  if (allocatable.cpuMillis > capacityValue.cpuMillis || allocatable.memoryBytes > capacityValue.memoryBytes ||
      allocatable.storageBytes > capacityValue.storageBytes || allocatable.workloadSlots > capacityValue.workloadSlots) {
    throw new Error("INVALID_HOST_ALLOCATABLE_RESPONSE");
  }
  const guarantees = status.supportedIsolationGuarantees.map((item) => text(item, "host isolation guarantee"));
  if (new Set(guarantees).size !== guarantees.length || guarantees.some((item) => !["WORKLOAD", "TENANT", "HOST"].includes(item)) ||
      (status.health === "READY" && guarantees.length === 0)) {
    throw new Error("INVALID_HOST_ISOLATION_RESPONSE");
  }
  return {
    id: text(metadata.id, "host id"),
    name: text(metadata.name, "host name"),
    labels: labels(metadata.labels),
    resourceVersion: integer(metadata.resourceVersion, "host resource version", true),
    executionPoolId: text(spec.executionPoolId, "host execution pool"),
    infrastructureAdapter: adapterName(spec.infrastructureAdapter, "INFRASTRUCTURE"),
    deploymentExecutor: adapterName(spec.deploymentExecutor, "DEPLOYMENT_EXECUTOR"),
    desiredState: spec.desiredState,
    health: status.health as HostTarget["health"],
    capacity: capacityValue,
    allocatable,
    supportedIsolationGuarantees: guarantees,
    observedAt: timestamp(status.observedAt, "host observation"),
    usage: status.usage === undefined ? null : usage(status.usage)
  };
}

function inventory(value: unknown): HostInventory {
  const wire = closed(value, "host inventory", ["apiVersion", "kind", "items"]);
  if (wire.apiVersion !== apiVersion || wire.kind !== "ExecutionTargetList" ||
      !Array.isArray(wire.items) || wire.items.length > maximumTargets) {
    throw new Error("INVALID_HOST_INVENTORY_RESPONSE");
  }
  const items = wire.items.map(target);
  if (new Set(items.map((item) => item.id)).size !== items.length) {
    throw new Error("INVALID_HOST_INVENTORY_RESPONSE");
  }
  return { items };
}

export const httpHostInventoryRepository: HostInventoryRepository = {
  async load(credential, signal) {
    const value = await requestJSON<unknown>("/api/paas/v1/execution-targets", {
      headers: { Authorization: `Bearer ${credential}` },
      signal
    });
    return inventory(value);
  }
};
