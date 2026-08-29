export type HostHealth = "UNKNOWN" | "READY" | "DEGRADED" | "UNAVAILABLE";
export type HostDesiredState = "ACTIVE" | "DRAINING";
export type HostMeasurementState =
  | "AVAILABLE"
  | "WARMING_UP"
  | "UNAVAILABLE"
  | "UNSUPPORTED"
  | "STALE";

export type HostCapacity = {
  cpuMillis: number;
  memoryBytes: number;
  storageBytes: number;
  workloadSlots: number;
};

export type HostCPUUsageValue = {
  logicalCpus: number;
  windowMillis: number;
  utilizationRatio: number;
  ioWaitRatio: number;
  load1: number;
  load5: number;
  load15: number;
};

export type HostMemoryUsageValue = {
  totalBytes: number;
  availableBytes: number;
  usedBytes: number;
  swapTotalBytes: number;
  swapFreeBytes: number;
};

export type HostFilesystemUsageValue = {
  totalBytes: number;
  usedBytes: number;
  availableBytes: number;
  inodesState: HostMeasurementState;
  totalInodes: number | null;
  freeInodes: number | null;
  readOnly: boolean;
};

export type HostFilesystemUsage = {
  device: string;
  mountPoint: string;
  filesystemType: string;
  state: HostMeasurementState;
  value: HostFilesystemUsageValue | null;
};

export type HostUsage = {
  observedAt: string;
  validUntil: string;
  cpu: { state: HostMeasurementState; value: HostCPUUsageValue | null };
  memory: { state: HostMeasurementState; value: HostMemoryUsageValue | null };
  filesystemsState: HostMeasurementState;
  filesystems: HostFilesystemUsage[];
};

export type HostTarget = {
  id: string;
  name: string;
  labels: Record<string, string>;
  resourceVersion: number;
  executionPoolId: string;
  infrastructureAdapter: string;
  deploymentExecutor: string;
  desiredState: HostDesiredState;
  health: HostHealth;
  capacity: HostCapacity;
  allocatable: HostCapacity;
  supportedIsolationGuarantees: string[];
  observedAt: string;
  usage: HostUsage | null;
};

export type HostInventory = {
  items: HostTarget[];
};
