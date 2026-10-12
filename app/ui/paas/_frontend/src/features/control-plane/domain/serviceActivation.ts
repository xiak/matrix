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

export type ServiceActivationState =
  | { status: "checking" | "not-enabled" | "enabling" | "failed" | "unavailable" }
  | { status: "enabled"; record: ServiceActivationRecord };

// These are independently supplied capabilities. Identity names and activation
// records cannot establish either capability.
export type ServiceActivationAccess = {
  canEnable: boolean;
  canUse: boolean;
};
