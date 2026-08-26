export type OfferingKind = "POSTGRESQL";
export type OfferingState = "AVAILABLE" | "UNAVAILABLE";
export type RegionState = "READY" | "STALE" | "UNAVAILABLE";
export type InstallationPhase =
  | "PENDING"
  | "PROVISIONING"
  | "READY"
  | "FAILED";

export type QuotaShape = {
  id: string;
  displayName: string;
  cpuMillicores: number;
  memoryMiB: number;
  storageGiB: number;
};

export type ServiceOffering = {
  id: string;
  kind: OfferingKind;
  displayName: string;
  description: string;
  engineFamily: string;
  engineVersion: string;
  state: OfferingState;
  quotaShapes: QuotaShape[];
};

export type Region = {
  id: string;
  displayName: string;
  profile: "LOCAL_MACHINE";
  state: RegionState;
  inspectedAt: string | null;
  capacity: {
    cpuMillicores: number;
    memoryMiB: number;
    storageGiB: number;
  };
};

export type QuotaEntitlement = {
  id: string;
  offeringId: string;
  quotaShapeId: string;
  purchasedCount: number;
  reservedCount: number;
  consumedCount: number;
  resourceVersion: number;
  activatedAt: string;
};

export type InstallationOperation = {
  id: string;
  phase: InstallationPhase;
  safeFailureCode: string | null;
  observedAt: string;
};

export type ServiceInstallation = {
  id: string;
  name: string;
  offeringId: string;
  engineVersion: string;
  quotaEntitlementId: string;
  regionId: string;
  phase: InstallationPhase;
  endpoint: string | null;
  credentialReference: string | null;
  operation: InstallationOperation;
  createdAt: string;
};

export type ControlPlaneSnapshot = {
  offerings: ServiceOffering[];
  regions: Region[];
  entitlements: QuotaEntitlement[];
  installations: ServiceInstallation[];
};

export type ActivateQuotaCommand = {
  offeringId: string;
  quotaShapeId: string;
  instanceCount: number;
};

export type CreateInstallationCommand = {
  id: string;
  name: string;
  offeringId: string;
  quotaEntitlementId: string;
  regionId: string;
};
