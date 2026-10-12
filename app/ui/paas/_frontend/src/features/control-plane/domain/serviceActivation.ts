import type { ServiceDefinitionReference } from "./resources";

export type ServiceActivationScope = {
  accountId: string;
  serviceKey: string;
};

export type ServiceActivationRecord = ServiceActivationScope & {
  termsVersion: string;
  acceptedBy: string;
  acceptedAt: string;
  enabledAt: string;
};

export type ServiceDefinition = ServiceDefinitionReference & {
  displayName: string;
  description: string;
  activationPrerequisite: "PERMISSION_ONLY";
  state: "AVAILABLE" | "UNAVAILABLE";
};

export type ServiceActivationCapability = {
  action: "managedservice.service-activation.activate";
  resource: { kind: "SERVICE_ACTIVATION"; id: "collection" };
  available: boolean;
  restrictionReason?: "AUTHORITY_REQUIRED";
};

export type ServiceDefinitionDirectory = {
  services: ServiceDefinition[];
  activationCapability: ServiceActivationCapability;
};

export type ServiceActivation = {
  service: ServiceDefinitionReference;
  resourceVersion: number;
  activatedAt: string;
};

export type ServiceActivationState =
  | { status: "checking" | "not-enabled" | "enabling" | "failed" | "unavailable" }
  | { status: "enabled"; scope: ServiceActivationScope; activation: ServiceActivation | ServiceActivationRecord }
  // Activation-directory access is independent from product-resource access.
  // In this state the UI may probe the owning resource API, which remains the
  // only authority for whether resource content is visible.
  | { status: "unobservable"; scope: ServiceActivationScope };

// `canEnable` is the exact activation capability. `mayLoadWorkspace` is only
// presentation admission: MOCK supplies it as a scenario input, while LIVE
// uses it to allow an independently authorized resource read. It is never an
// authorization permit and every resource request is still checked server-side.
export type ServiceActivationAccess = {
  canEnable: boolean;
  mayLoadWorkspace: boolean;
};

export function serviceWorkspaceMayLoad(
  state: ServiceActivationState,
  access: ServiceActivationAccess,
  scope: ServiceActivationScope
): boolean {
  return access.mayLoadWorkspace &&
    (state.status === "enabled" || state.status === "unobservable") &&
    state.scope.accountId === scope.accountId &&
    state.scope.serviceKey === scope.serviceKey;
}
