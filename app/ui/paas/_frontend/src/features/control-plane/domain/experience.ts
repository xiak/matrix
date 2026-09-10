export type ExperienceResourceState = "HEALTHY" | "RUNNING" | "DEGRADED" | "FAILED";
export type ExperienceOperationState = "SUCCEEDED" | "RUNNING" | "FAILED";
export type ExperienceAlertSeverity = "CRITICAL" | "WARNING" | "INFO";

export type ExperienceResource = {
  id: string;
  name: string;
  kind: "POSTGRESQL" | "APPLICATION" | "PIPELINE" | "SERVICE_MONITOR" | "COMPUTE_NODE";
  productId: "foundation" | "paas" | "devops" | "observability" | "security";
  productName: string;
  projectId: string;
  projectName: string;
  regionId: string;
  regionName: string;
  state: ExperienceResourceState;
  updatedAt: string;
  href: string;
};

export type ExperienceOperation = {
  id: string;
  action: string;
  target: string;
  productName: string;
  actor: string;
  state: ExperienceOperationState;
  progress: number;
  startedAt: string;
  finishedAt?: string;
};

export type ExperiencePipeline = {
  id: string;
  name: string;
  repository: string;
  branch: string;
  commit: string;
  environment: string;
  state: ExperienceOperationState;
  durationSeconds: number;
  triggeredAt: string;
};

export type ExperienceServiceHealth = {
  id: string;
  name: string;
  productName: string;
  availability: number;
  latencyMs: number;
  errorRate: number;
  state: ExperienceResourceState;
  trend: number[];
};

export type ExperienceAlert = {
  id: string;
  title: string;
  serviceName: string;
  severity: ExperienceAlertSeverity;
  state: "FIRING" | "ACKNOWLEDGED";
  startedAt: string;
  owner: string;
};

export type ExperienceSnapshot = {
  organization: { id: string; name: string };
  projects: Array<{ id: string; name: string }>;
  regions: Array<{ id: string; name: string }>;
  resources: ExperienceResource[];
  operations: ExperienceOperation[];
  pipelines: ExperiencePipeline[];
  serviceHealth: ExperienceServiceHealth[];
  alerts: ExperienceAlert[];
  announcements: Array<{ id: string; title: string; body: string; publishedAt: string }>;
  logs: ExperienceLogs;
};

export type ExperienceLogs = {
  topics: Array<{
    id: string;
    name: string;
    regionId: string;
    retentionDays: number;
    storageGiB: number;
    source: "KUBERNETES" | "HOST";
    path: string;
    nodeCount: number;
    state: "ACTIVE" | "PAUSED";
  }>;
  events: Array<{
    id: string;
    timestamp: string;
    topicId: string;
    level: "INFO" | "WARN" | "ERROR";
    service: string;
    message: string;
    traceId: string;
  }>;
};
