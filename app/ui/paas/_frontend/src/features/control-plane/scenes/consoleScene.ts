import type { ConsoleSection } from "../domain/selection";

export type RailIconKind = "overview" | "database" | "devops" | "observability" | "access";
export type NavigationIconKind =
  | "overview"
  | "products"
  | "resources"
  | "operations"
  | "catalog"
  | "quota"
  | "installation"
  | "region"
  | "pipeline"
  | "observability"
  | "access";
export type ExperienceIconKind = "foundation" | "paas" | "devops" | "observability" | "security";
export type SceneStatus = "neutral" | "info" | "success" | "warning" | "danger";

export type ProductRailItemScene = {
  id: string;
  label: string;
  href: string;
  icon: RailIconKind;
  selected: boolean;
};

export type ConsoleNavigationItemScene = {
  id: ConsoleSection;
  label: string;
  description: string;
  href: string;
  icon: NavigationIconKind;
  selected: boolean;
  count?: number;
};

export type MetricScene = {
  id: string;
  label: string;
  value: string;
  detail: string;
  status: SceneStatus;
};

export type ExperienceProductScene = {
  id: string;
  name: string;
  eyebrow: string;
  description: string;
  href: string;
  icon: ExperienceIconKind;
  status: SceneStatus;
  statusLabel: string;
  resourceCount: number;
  capabilities: string[];
};

export type UnifiedResourceScene = {
  id: string;
  name: string;
  kind: string;
  productId: string;
  productName: string;
  projectId: string;
  projectName: string;
  regionId: string;
  regionName: string;
  stateLabel: string;
  status: SceneStatus;
  updatedAt: string;
  href: string;
};

export type OperationScene = {
  id: string;
  action: string;
  target: string;
  productName: string;
  actor: string;
  stateLabel: string;
  status: SceneStatus;
  progress: number;
  startedAt: string;
};

export type PipelineScene = {
  id: string;
  name: string;
  repository: string;
  branch: string;
  commit: string;
  environment: string;
  stateLabel: string;
  status: SceneStatus;
  duration: string;
  triggeredAt: string;
};

export type ServiceHealthScene = {
  id: string;
  name: string;
  productName: string;
  availability: string;
  latency: string;
  errorRate: string;
  stateLabel: string;
  status: SceneStatus;
  trend: number[];
};

export type AlertScene = {
  id: string;
  title: string;
  serviceName: string;
  severityLabel: string;
  status: SceneStatus;
  stateLabel: string;
  startedAt: string;
  owner: string;
};

export type ConsoleScopeScene = {
  organization: { id: string; name: string };
  projects: Array<{ id: string; name: string }>;
  regions: Array<{ id: string; name: string }>;
};

export type GlobalSearchResultScene = {
  id: string;
  label: string;
  description: string;
  href: string;
  category: "页面" | "产品" | "资源";
  icon: ExperienceIconKind;
};

export type OfferingScene = {
  id: string;
  name: string;
  description: string;
  engine: string;
  version: string;
  available: boolean;
  shapeCount: number;
  shapeSummary: string;
};

export type EntitlementScene = {
  id: string;
  offeringName: string;
  shapeName: string;
  resourceSummary: string;
  purchased: number;
  inUse: number;
  available: number;
  activatedAt: string;
};

export type InstallationScene = {
  id: string;
  name: string;
  engine: string;
  regionName: string;
  phase: string;
  status: SceneStatus;
  endpoint: string | null;
  operationId: string;
  observedAt: string;
};

export type RegionScene = {
  id: string;
  name: string;
  profile: string;
  state: string;
  status: SceneStatus;
  capacity: string;
  inspectedAt: string;
};

export type QuotaOrderOptionScene = {
  offeringId: string;
  offeringName: string;
  shapes: Array<{
    id: string;
    label: string;
    resourceSummary: string;
  }>;
};

export type InstallationOrderOptionScene = {
  entitlementId: string;
  offeringId: string;
  label: string;
  available: number;
};

export type ConsoleContentScene =
  | {
      kind: "overview";
      metrics: MetricScene[];
      recentInstallations: InstallationScene[];
      offering: OfferingScene | null;
    }
  | {
      kind: "cloud-overview";
      metrics: MetricScene[];
      products: ExperienceProductScene[];
      recentResources: UnifiedResourceScene[];
      operations: OperationScene[];
      alerts: AlertScene[];
    }
  | { kind: "products"; products: ExperienceProductScene[] }
  | { kind: "resources"; resources: UnifiedResourceScene[] }
  | { kind: "operations"; operations: OperationScene[] }
  | { kind: "devops"; metrics: MetricScene[]; pipelines: PipelineScene[] }
  | { kind: "observability"; metrics: MetricScene[]; services: ServiceHealthScene[]; alerts: AlertScene[] }
  | { kind: "catalog"; offerings: OfferingScene[] }
  | { kind: "quotas"; entitlements: EntitlementScene[] }
  | { kind: "installations"; installations: InstallationScene[] }
  | { kind: "regions"; regions: RegionScene[] }
  | { kind: "access" };

export type ConsoleWorkspaceScene =
  | {
      kind: "quota-order";
      options: QuotaOrderOptionScene[];
    }
  | {
      kind: "installation-order";
      entitlementOptions: InstallationOrderOptionScene[];
      regionOptions: Array<{ id: string; label: string }>;
    }
  | {
      kind: "platform-status";
      readyRegions: number;
      activeOperations: number;
      serviceCount: number;
    }
  | null;

export type ConsoleScene = {
  section: ConsoleSection;
  title: string;
  eyebrow: string;
  description: string;
  productName: string;
  productEyebrow: string;
  productIcon: RailIconKind;
  preview: boolean;
  scope: ConsoleScopeScene | null;
  search: GlobalSearchResultScene[];
  noticeCount: number;
  notices: AlertScene[];
  activeOperationCount: number;
  rail: ProductRailItemScene[];
  navigation: ConsoleNavigationItemScene[];
  content: ConsoleContentScene;
  workspace: ConsoleWorkspaceScene;
};
