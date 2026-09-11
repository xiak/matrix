export type PolicyScope = "TENANT" | "INSTALLATION";
export type PolicyManagement = "SYSTEM" | "CUSTOMER";
export type PolicyStatus = "ACTIVE" | "RETIRED";
export type IdentityKind = "ROOT_IDENTITY" | "USER";

export type RootIdentity = {
  principalId: string;
  loginName: string;
};

export type Account = {
  id: string;
  displayName: string;
  status: "ACTIVE" | "DISABLED";
  rootIdentity: RootIdentity;
  loginAlias: string | null;
  resourceVersion: number;
};

export type User = {
  id: string;
  accountId: string;
  loginName: string;
  displayName: string;
  status: "ACTIVE" | "DISABLED";
  mustChangePassword: boolean;
  resourceVersion: number;
};

export type AccountPolicy = {
  id: string;
  management: PolicyManagement;
  accountId: string | null;
  displayName: string;
  scope: PolicyScope;
  status: PolicyStatus;
  defaultVersionId: string;
  resourceVersion: number;
  createdAt: string;
  updatedAt: string;
};

export type UserPolicyAttachment = {
  id: string;
  accountId: string;
  target: { kind: "USER"; id: string };
  policyId: string;
  scope: PolicyScope;
  installationId: string | null;
  resourceVersion: number;
  createdAt: string;
  updatedAt: string;
};

export type PolicyDirectory = {
  accountId: string;
  scope: PolicyScope;
  installationId: string | null;
  items: AccountPolicy[];
};

export type AccountIdentity = {
  account: Account;
  user: User;
  identityKind: IdentityKind;
  policyAttachments: UserPolicyAttachment[];
  canCreateAccounts: boolean;
};

export type UserAccess = { user: User; policyAttachments: UserPolicyAttachment[] };
export type DirectoryPage<T> = { items: T[]; nextAfter: string | null };

export type AccountCommand =
  | { kind: "create-user"; loginName: string; displayName: string; initialPassword: string }
  | { kind: "create-account"; id: string; displayName: string; rootLoginName: string; rootDisplayName: string; initialPassword: string }
  | { kind: "set-account-status"; accountId: string; status: "ACTIVE" | "DISABLED"; resourceVersion: number }
  | { kind: "recover-root-credentials"; accountId: string; initialPassword: string; resourceVersion: number }
  | { kind: "set-alias"; alias: string; resourceVersion: number }
  | { kind: "set-status"; userId: string; status: "ACTIVE" | "DISABLED"; resourceVersion: number }
  | { kind: "reset-password"; userId: string; initialPassword: string; resourceVersion: number }
  | { kind: "create-policy-attachment"; userId: string; policyId: string; policyResourceVersion: number }
  | { kind: "revoke-policy-attachment"; attachmentId: string; resourceVersion: number };
