export type DeploymentDesiredState = "RUNNING" | "STOPPED";

export type DeploymentPhase =
  | "PENDING"
  | "PLACING"
  | "APPLYING"
  | "READY"
  | "DEGRADED"
  | "FAILED"
  | "STOPPING"
  | "STOPPED";

export type DeploymentInventoryItem = {
  id: string;
  name: string;
  tenantId: string;
  resourceVersion: number;
  generation: number;
  applicationRevisionId: string;
  placementPolicyId: string;
  desiredState: DeploymentDesiredState;
  components: Array<{ name: string; replicas: number }>;
  phase: DeploymentPhase;
  observedGeneration: number;
  placementDecisionId: string | null;
  currentOperationId: string | null;
  observedApplicationRevisionId: string | null;
  readyComponents: number;
  observedAt: string;
  createdAt: string;
  updatedAt: string;
};

export type DeploymentInventory = {
  tenantId: string;
  items: DeploymentInventoryItem[];
  nextAfter: string | null;
};

export type DeploymentRuntimeState = "AVAILABLE" | "STALE" | "UNAVAILABLE";
export type DeploymentMeasurementState =
  | "AVAILABLE"
  | "WARMING_UP"
  | "STALE"
  | "UNAVAILABLE"
  | "UNSUPPORTED";
export type DeploymentInstanceState =
  | "CREATED"
  | "RUNNING"
  | "RESTARTING"
  | "REMOVING"
  | "PAUSED"
  | "EXITED"
  | "DEAD";
export type DeploymentInstanceHealth = "NONE" | "STARTING" | "HEALTHY" | "UNHEALTHY";

export type DeploymentRuntimeInstance = {
  id: string;
  componentName: string;
  state: DeploymentInstanceState;
  health: DeploymentInstanceHealth;
  exitCode: number | null;
};

export type DeploymentRuntimeValue = {
  deploymentId: string;
  generation: number;
  applicationRevisionId: string;
  executionTargetId: string;
  instances: DeploymentRuntimeInstance[];
  observedAt: string;
  validUntil: string;
};

export type DeploymentMeasurement<T> = {
  state: DeploymentMeasurementState;
  value: T | null;
};

export type DeploymentResourceInstance = {
  id: string;
  cpu: DeploymentMeasurement<{
    windowMillis: number;
    usedCores: number;
    limitCpuMillis: number;
  }>;
  memory: DeploymentMeasurement<{ usedBytes: number; limitBytes: number }>;
  network: DeploymentMeasurement<{
    receivedBytes: number;
    transmittedBytes: number;
    receiveErrors: number;
    transmitErrors: number;
    receiveDrops: number;
    transmitDrops: number;
  }>;
  blockIo: DeploymentMeasurement<{
    readBytes: number;
    writeBytes: number;
    readOperations: number;
    writeOperations: number;
  }>;
  storage: DeploymentMeasurement<{
    observedAt: string;
    validUntil: string;
    writableLayerBytes: number;
    imageTotalBytes: number;
    imageSharedBytes: number;
    imageUniqueBytes: number;
    volumesState: DeploymentMeasurementState;
    volumes: {
      count: number;
      bytes: number;
      sharedCount: number;
      sharedBytes: number;
    } | null;
  }>;
};

export type DeploymentResourceSnapshot = {
  state: DeploymentRuntimeState;
  value: {
    deploymentId: string;
    generation: number;
    applicationRevisionId: string;
    executionTargetId: string;
    instances: DeploymentResourceInstance[];
    observedAt: string;
    validUntil: string;
  } | null;
};

export type DeploymentRuntimeSnapshot = {
  tenantId: string;
  state: DeploymentRuntimeState;
  value: DeploymentRuntimeValue | null;
  resources: DeploymentResourceSnapshot;
};
