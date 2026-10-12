export type OfferingState = "AVAILABLE" | "UNAVAILABLE";
export type RegionState = "READY" | "STALE" | "UNAVAILABLE";
export type InstallationPhase =
  | "PENDING"
  | "PROVISIONING"
  | "READY"
  | "FAILED"
  | "ROLLBACK_FAILED"
  | "TERMINATION_PENDING"
  | "TERMINATING"
  | "TERMINATION_FAILED"
  | "TERMINATED";

export type InstallationOperationKind = "PROVISION" | "TERMINATE";

export type QuotaShape = {
  id: string;
  displayName: string;
  cpuMillicores: number;
  memoryMiB: number;
  storageGiB: number;
};

// A managed-service offering is committed to one exact published service
// definition. The service ID is a product-catalog identity, not an IAM
// ProductID and not a presentation-only enum.
export type ServiceDefinitionReference = {
  id: string;
  revision: number;
  contentDigest: string;
};

export type ServiceOffering = {
  id: string;
  service: ServiceDefinitionReference;
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
  kind: InstallationOperationKind;
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
  resourceVersion: number;
  createdAt: string;
};

export type InstallationTerminationMutationError =
  | "expired"
  | "forbidden"
  | "notFound"
  | "conflict"
  | "invalid"
  | "unknown";

export type InstallationTerminationIntent = {
  installation: ServiceInstallation;
  requestId: string;
  phase: "review" | "submitting" | "failed";
  error: InstallationTerminationMutationError | null;
  open: boolean;
};

export type InstallationReadLoad =
  | { status: "ready"; installation: ServiceInstallation }
  | { status: "expired" | "forbidden" | "notFound" | "unavailable" };

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
