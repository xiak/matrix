import type { ConsoleSection } from "../domain/selection";

export type RailIconKind = "overview" | "database" | "access";
export type NavigationIconKind =
  | "catalog"
  | "quota"
  | "installation"
  | "region"
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
  rail: ProductRailItemScene[];
  navigation: ConsoleNavigationItemScene[];
  content: ConsoleContentScene;
  workspace: ConsoleWorkspaceScene;
};
