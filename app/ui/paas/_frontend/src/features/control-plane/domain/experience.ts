export type ExperienceAvailability = "AVAILABLE" | "PREVIEW" | "PLANNED";
export type ExperienceResourceState = "HEALTHY" | "RUNNING" | "DEGRADED" | "FAILED";
export type ExperienceOperationState = "SUCCEEDED" | "RUNNING" | "FAILED";
export type ExperienceAlertSeverity = "CRITICAL" | "WARNING" | "INFO";

export type ExperienceProduct = {
  id: "foundation" | "paas" | "devops" | "observability" | "security";
  name: string;
  eyebrow: string;
  description: string;
  href: string;
  availability: ExperienceAvailability;
  resourceCount: number;
  capabilities: string[];
};

export type ExperienceResource = {
  id: string;
  name: string;
  kind: string;
  productId: ExperienceProduct["id"];
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
};

export type ExperiencePipeline = {
  id: string;
  name: string;
  repository: string;
  branch: string;
  commit: string;
  environment: string;
  state: ExperienceOperationState;
  duration: string;
  triggeredAt: string;
};

export type ExperienceServiceHealth = {
  id: string;
  name: string;
  productName: string;
  availability: string;
  latency: string;
  errorRate: string;
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
  products: ExperienceProduct[];
  resources: ExperienceResource[];
  operations: ExperienceOperation[];
  pipelines: ExperiencePipeline[];
  serviceHealth: ExperienceServiceHealth[];
  alerts: ExperienceAlert[];
};
