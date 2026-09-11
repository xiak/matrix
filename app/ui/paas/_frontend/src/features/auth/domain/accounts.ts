export type PolicyScope = "TENANT" | "INSTALLATION";
export type PolicyManagement = "SYSTEM" | "CUSTOMER";
export type PolicyStatus = "ACTIVE" | "RETIRED";

export type Account = {
  organization: { id: string; displayName: string; status: "ACTIVE" | "DISABLED"; resourceVersion: number };
  primaryPrincipalId: string;
  primaryLoginName: string;
  loginAlias: string | null;
};

export type AccountPrincipal = {
  id: string;
  organizationId: string;
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
  principal: AccountPrincipal;
  policyAttachments: UserPolicyAttachment[];
  canCreateOrganizations: boolean;
};

export type AccountUser = { principal: AccountPrincipal; policyAttachments: UserPolicyAttachment[] };
export type DirectoryPage<T> = { items: T[]; nextAfter: string | null };

export type AccountCommand =
  | { kind: "create-user"; loginName: string; displayName: string; initialPassword: string }
  | { kind: "create-organization"; id: string; displayName: string; administratorLoginName: string; administratorDisplayName: string; initialPassword: string }
  | { kind: "set-organization-status"; organizationId: string; status: "ACTIVE" | "DISABLED"; resourceVersion: number }
  | { kind: "recover-primary"; organizationId: string; principalId: string; initialPassword: string; resourceVersion: number }
  | { kind: "set-alias"; alias: string; resourceVersion: number }
  | { kind: "set-status"; principalId: string; status: "ACTIVE" | "DISABLED"; resourceVersion: number }
  | { kind: "reset-password"; principalId: string; initialPassword: string; resourceVersion: number }
  | { kind: "create-policy-attachment"; principalId: string; policyId: string; policyResourceVersion: number }
  | { kind: "revoke-policy-attachment"; attachmentId: string; resourceVersion: number };
