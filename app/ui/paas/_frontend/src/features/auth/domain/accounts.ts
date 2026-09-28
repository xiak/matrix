export type Account = {
  id: string;
  displayName: string;
  status: "ACTIVE" | "DISABLED";
  rootIdentity: { principalId: string; loginName: string };
  loginAlias: string | null;
  resourceVersion: number;
};

export type AccountUser = {
  id: string;
  accountId: string;
  loginName: string;
  displayName: string;
  status: "ACTIVE" | "DISABLED";
  mustChangePassword: boolean;
  resourceVersion: number;
};

export type ActionCapability = {
  action: string;
  resource: { kind: string; id: string };
  available: boolean;
};

export type PolicyAttachment = {
  id: string;
  accountId: string;
  target: { kind: "USER" | "GROUP" | "ROLE"; id: string };
  policyId: string;
  scope: "TENANT" | "INSTALLATION";
  resourceVersion: number;
};

export type Policy = {
  id: string;
  displayName: string;
  management: "SYSTEM" | "CUSTOMER";
  scope: "TENANT";
  resourceVersion: number;
};

export type AccountIdentity = {
  account: Account;
  user: AccountUser;
  identityKind: "ROOT_IDENTITY" | "USER";
  policySources: { attachment: PolicyAttachment }[];
  capabilities: ActionCapability[];
};

export type UserAccess = { user: AccountUser; policyAttachments: PolicyAttachment[]; capabilities: ActionCapability[] };
export type AccountAccess = { account: Account; capabilities: ActionCapability[] };
export type DirectoryPage<T> = { items: T[]; nextAfter: string | null };

export type AccountCommand =
  | { kind: "create-user"; loginName: string; displayName: string; initialPassword: string }
  | { kind: "create-account"; id: string; displayName: string; rootLoginName: string; rootDisplayName: string; initialPassword: string }
  | { kind: "set-account-status"; accountId: string; status: "ACTIVE" | "DISABLED"; resourceVersion: number }
  | { kind: "recover-root"; accountId: string; initialPassword: string; resourceVersion: number }
  | { kind: "set-alias"; alias: string; resourceVersion: number }
  | { kind: "set-user-status"; userId: string; status: "ACTIVE" | "DISABLED"; resourceVersion: number }
  | { kind: "reset-password"; userId: string; initialPassword: string; resourceVersion: number }
  | { kind: "attach-policy"; userId: string; policyId: string; policyResourceVersion: number }
  | { kind: "revoke-policy"; attachmentId: string; resourceVersion: number };

export function can(capabilities: ActionCapability[], action: string, kind: string, id: string): boolean {
  return capabilities.some((capability) => capability.action === action && capability.resource.kind === kind &&
    capability.resource.id === id && capability.available);
}
