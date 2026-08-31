import type { ConsoleSection } from "../domain/selection";
import type { HostMeasurementState } from "../domain/hosts";

export type RailIconKind = "overview" | "database" | "workloads" | "infrastructure" | "access";
export type NavigationIconKind =
  | "catalog"
  | "quota"
  | "installation"
  | "deployment"
  | "region"
  | "host"
  | "access";
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

export type HostMeasurementScene = {
  state: HostMeasurementState;
  stateLabel: string;
  value: string;
  detail: string;
  progress: number | null;
  status: SceneStatus;
};

export type HostFilesystemScene = HostMeasurementScene & {
  id: string;
  device: string;
  mountPoint: string;
  filesystemType: string;
  readOnly: boolean;
};

export type HostScene = {
  id: string;
  name: string;
  platform: string;
  source: string;
  executionPoolId: string;
  desiredState: string;
  health: string;
  status: SceneStatus;
  capacity: string;
  observedAt: string;
  usageObservedAt: string;
  validUntil: string;
  sampleState: string;
  sampleStatus: SceneStatus;
  cpu: HostMeasurementScene;
  memory: HostMeasurementScene;
  filesystemsState: string;
  filesystems: HostFilesystemScene[];
};

export type DeploymentScene = {
  id: string;
  name: string;
  generation: number;
  revisionId: string;
  desiredState: string;
  phase: string;
  status: SceneStatus;
  componentSummary: string;
  readiness: string;
  observedAt: string;
  selected: boolean;
};

export type DeploymentRuntimeInstanceScene = {
  id: string;
  componentName: string;
  state: string;
  stateLabel: string;
  health: string;
  healthLabel: string;
  status: SceneStatus;
  exitCode: string;
  terminalAvailable: boolean;
  resources: DeploymentRuntimeInstanceResourcesScene | null;
};

export type DeploymentResourceMeasurementScene = {
  state: string;
  stateLabel: string;
  status: SceneStatus;
  value: string;
  detail: string;
};

export type DeploymentRuntimeInstanceResourcesScene = {
  cpu: DeploymentResourceMeasurementScene;
  memory: DeploymentResourceMeasurementScene;
  network: DeploymentResourceMeasurementScene;
  blockIo: DeploymentResourceMeasurementScene;
  storage: DeploymentResourceMeasurementScene;
};

export type DeploymentRuntimeScene = {
  state: string;
  stateLabel: string;
  status: SceneStatus;
  generation: number | null;
  revisionId: string | null;
  executionTargetId: string | null;
  observedAt: string;
  validUntil: string;
  resources: {
    state: string;
    stateLabel: string;
    status: SceneStatus;
    observedAt: string;
    validUntil: string;
  };
  instances: DeploymentRuntimeInstanceScene[];
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
  | { kind: "catalog"; offerings: OfferingScene[] }
  | { kind: "quotas"; entitlements: EntitlementScene[] }
  | { kind: "installations"; installations: InstallationScene[] }
  | {
      kind: "deployments";
      deployments: DeploymentScene[];
      selectedDeploymentId: string | null;
      runtime: DeploymentRuntimeScene | null;
      truncated: boolean;
    }
  | { kind: "regions"; regions: RegionScene[] }
  | { kind: "hosts"; hosts: HostScene[] }
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
  rail: ProductRailItemScene[];
  navigation: ConsoleNavigationItemScene[];
  content: ConsoleContentScene;
  workspace: ConsoleWorkspaceScene;
};
