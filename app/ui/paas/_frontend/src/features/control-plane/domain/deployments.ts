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

export type DeploymentRuntimeSnapshot = {
  tenantId: string;
  state: DeploymentRuntimeState;
  value: DeploymentRuntimeValue | null;
};
