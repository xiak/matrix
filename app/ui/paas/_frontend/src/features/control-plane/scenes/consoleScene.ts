import type { ExperienceResource, ExperienceOperation, ExperiencePipeline, ExperienceServiceHealth } from "../domain/experience";
import type { Region, ServiceInstallation } from "../domain/resources";
import type { ConsoleSection, ServiceView } from "../domain/selection";

export type RailIconKind = "overview" | "database" | "devops" | "observability" | "access";
export type NavigationIconKind =
  | "policy"
  | "sso"
  | "key"
  | "users"
  | "settings"
  | "tenants"
  | "overview"
  | "messages"
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
  href: string;
  icon: RailIconKind;
  selected: boolean;
};

export type ConsoleNavigationItemScene = {
  id: string;
  messageKey: import("./serviceDirectory").ServicePageId | ConsoleSection;
  href: string;
  icon: NavigationIconKind;
  selected: boolean;
  count?: number;
  group?: "identity" | "authorization" | "identityProviders" | "security" | "administration";
};

export type MetricScene = {
  id: "offerings" | "quota" | "services" | "regions" | "all-resources" | "healthy-resources" | "active-operations" | "active-alerts" | "pipeline-success" | "pipeline-running" | "lead-time" | "deployment-frequency" | "service-health" | "availability" | "alert-firing" | "ingestion";
  value: number;
  detailCount?: number;
  status: SceneStatus;
};

export type UnifiedResourceScene = ExperienceResource & { status: SceneStatus };

export type OperationScene = ExperienceOperation & { status: SceneStatus };

export type PipelineScene = ExperiencePipeline & { status: SceneStatus };

export type ServiceHealthScene = ExperienceServiceHealth & { status: SceneStatus };

export type AlertScene = {
  id: string;
  title: string;
  serviceName: string;
  severity: import("../domain/experience").ExperienceAlertSeverity;
  status: SceneStatus;
  state: import("../domain/experience").ExperienceAlert["state"];
  startedAt: string;
  owner: string;
};

export type ConsoleScopeScene = {
  organization: { id: string; name: string };
  regions: Array<{ id: string; name: string }>;
};

export type ConsoleMessageScene = {
  id: string;
  category: "alert" | "operation" | "platform";
  title: string;
  description: string;
  createdAt: string;
  status: SceneStatus;
  result?: "SUCCEEDED" | "FAILED";
  href?: string;
};

export type GlobalSearchResultScene = {
  id: string;
  label: string;
  description: string;
  href: string;
  category: "page" | "product" | "resource";
  icon: ExperienceIconKind;
  keywords?: readonly string[];
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
  resources: Region["capacity"] | null;
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
  phase: ServiceInstallation["phase"];
  status: SceneStatus;
  endpoint: string | null;
  operationId: string;
  observedAt: string;
};

export type RegionScene = {
  id: string;
  name: string;
  profile: Region["profile"];
  state: Region["state"];
  status: SceneStatus;
  capacity: Region["capacity"];
  inspectedAt: string | null;
};

export type QuotaOrderOptionScene = {
  offeringId: string;
  offeringName: string;
  shapes: Array<{
    id: string;
    label: string;
    resources: Region["capacity"];
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
      regionCount: number;
      readyRegions: number;
      metrics: MetricScene[];
      recentResources: UnifiedResourceScene[];
      operations: OperationScene[];
      alerts: AlertScene[];
    }
  | { kind: "messages"; messages: ConsoleMessageScene[]; preview: boolean }
  | { kind: "resources"; resources: UnifiedResourceScene[] }
  | { kind: "operations"; operations: OperationScene[] }
  | { kind: "devops"; view?: ServiceView; metrics: MetricScene[]; pipelines: PipelineScene[] }
  | { kind: "observability"; view?: ServiceView; metrics: MetricScene[]; services: ServiceHealthScene[]; alerts: AlertScene[] }
  | { kind: "catalog"; offerings: OfferingScene[] }
  | { kind: "quotas"; entitlements: EntitlementScene[] }
  | { kind: "installations"; installations: InstallationScene[] }
  | { kind: "regions"; regions: RegionScene[] }
  | { kind: "logs"; view?: ServiceView; data: import("../domain/experience").ExperienceLogs | null }
  | { kind: "access"; view: import("@/features/auth/domain/accounts").AccountAccessView };

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
  productId: import("./serviceDirectory").ServiceId | "console";
  productIcon: RailIconKind;
  preview: boolean;
  scope: ConsoleScopeScene | null;
  search: Array<GlobalSearchResultScene & { resourceKind: import("../domain/experience").ExperienceResource["kind"] }>;
  messages: ConsoleMessageScene[];
  activeOperationCount: number;
  rail: ProductRailItemScene[];
  navigation: ConsoleNavigationItemScene[];
  content: ConsoleContentScene;
  workspace: ConsoleWorkspaceScene;
};
