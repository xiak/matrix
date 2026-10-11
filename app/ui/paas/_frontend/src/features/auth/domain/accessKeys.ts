import type { ActionCapability } from "./accounts";
import type { AccessKeyNetworkRestrictions, AccessKeyUsageObservation } from "./accessKeyNetwork";

export type AccessKeyStatus = "ENABLED" | "DISABLED";
export type AccessKeyCredentialState = "CURRENT" | "RECOVERY_FENCED";

export type ManagedAccessKey = {
  id: string;
  accountId: string;
  userId: string;
  status: AccessKeyStatus;
  credentialState: AccessKeyCredentialState;
  networkRestrictions: AccessKeyNetworkRestrictions;
  resourceVersion: number;
  createdAt: string;
  updatedAt: string;
};

export type AccessKeyAccess = {
  key: ManagedAccessKey;
  usage: AccessKeyUsageObservation;
  capabilities: ActionCapability[];
};

export type AccessKeyDirectory = {
  accountId: string;
  userId: string;
  userResourceVersion: number;
  capabilities: ActionCapability[];
  items: AccessKeyAccess[];
};

export type AccessKeyCreation =
  | { outcome: "APPLIED"; key: ManagedAccessKey; secret: string }
  | { outcome: "EQUAL_REPLAY"; key: ManagedAccessKey };

export type AccessKeyStatusChange = {
  outcome: "APPLIED" | "EQUAL_REPLAY";
  key: ManagedAccessKey;
};

export type AccessKeyNetworkChange = AccessKeyStatusChange;

export type AccessKeyDeletion = {
  outcome: "APPLIED" | "EQUAL_REPLAY";
  deletion: {
    id: string;
    accountId: string;
    userId: string;
    resourceVersion: number;
    deletedAt: string;
  };
};
