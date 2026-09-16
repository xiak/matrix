export type PolicyScope = "TENANT" | "INSTALLATION";
export type PolicyManagement = "SYSTEM" | "CUSTOMER";
export type PolicyStatus = "ACTIVE" | "RETIRED";
export type IdentityKind = "ROOT_IDENTITY" | "USER";

export type IamAction =
  | "iam.account.create"
  | "iam.account.read"
  | "iam.account.set-status"
  | "iam.account.recover-root-credentials"
  | "iam.account.alias-set"
  | "iam.user.list"
  | "iam.user.create"
  | "iam.group.list"
  | "iam.group.create"
  | "iam.group.read"
  | "iam.group.update"
  | "iam.group.delete"
  | "iam.group-membership.list"
  | "iam.group-membership.create"
  | "iam.group-membership.remove"
  | "iam.group-policy-attachment.create"
  | "iam.group-policy-attachment.revoke"
  | "iam.user.read"
  | "iam.user.update"
  | "iam.user.delete"
  | "iam.user.permission-boundary.set"
  | "iam.user.permission-boundary.remove"
  | "iam.policy.list"
  | "iam.user.set-status"
  | "iam.user.reset-password"
  | "iam.policy-attachment.create"
  | "iam.platform-policy-attachment.create"
  | "iam.policy-attachment.revoke"
  | "iam.platform-policy-attachment.revoke";

export type CapabilityRestriction =
  | "AUTHORITY_REQUIRED"
  | "CURRENT_CREDENTIAL_CHANGE_REQUIRED"
  | "SELF_PROTECTED"
  | "ROOT_IDENTITY_PROTECTED"
  | "INSTALLATION_AUTHORITY_PROTECTED"
  | "SYSTEM_ACCOUNT_PROTECTED"
  | "TARGET_DISABLED"
  | "TARGET_CREDENTIAL_CHANGE_REQUIRED"
  | "TARGET_MUST_BE_DISABLED";

export type ActionCapability = {
  action: IamAction;
  resource: { kind: "ACCOUNT" | "USER" | "GROUP" | "GROUP_MEMBERSHIP" | "POLICY_ATTACHMENT"; id: string };
  available: boolean;
  restrictionReason: CapabilityRestriction | null;
};

export const accountAccessViews = ["users", "create-user", "groups", "create-group", "policies", "create-policy", "simulator", "roles", "create-role", "providers", "user-sso", "federations", "keys", "settings", "tenants"] as const;
export type AccountAccessView = "overview" | typeof accountAccessViews[number];

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
  policySources: PolicyGrantSource[];
  permissionBoundary: UserPermissionBoundary;
  capabilities: ActionCapability[];
};

export type PolicyVersionReference = {
  policyId: string;
  versionId: string;
  contentDigest: string;
};

// A bound revision of the user's permission ceiling, never a positive grant.
// Only an explicit null policy means that this user has no tenant boundary.
export type UserPermissionBoundary = {
  accountId: string;
  userId: string;
  resourceVersion: number;
  policy: PolicyVersionReference | null;
};

export type GroupPolicyAttachment = Omit<UserPolicyAttachment, "target" | "scope" | "installationId"> & {
  target: { kind: "GROUP"; id: string };
  scope: "TENANT";
  installationId: null;
};

export type GroupMembership = {
  id: string;
  accountId: string;
  groupId: string;
  userId: string;
  createdBy: string;
  resourceVersion: number;
  createdAt: string;
  updatedAt: string;
  removedAt?: string;
  removedBy?: string;
};

export type Group = {
  id: string;
  accountId: string;
  name: string;
  description: string;
  resourceVersion: number;
  createdAt: string;
  updatedAt: string;
};

export type GroupAccess = {
  group: Group;
  policyAttachments: GroupPolicyAttachment[];
  capabilities: ActionCapability[];
};

export type GroupMembershipAccess = {
  membership: GroupMembership;
  capabilities: ActionCapability[];
};

export type GroupMembershipPage = DirectoryPage<GroupMembershipAccess> & {
  accountId: string;
  groupId: string;
};

export type GroupDeletion = {
  id: string;
  accountId: string;
  name: string;
  resourceVersion: number;
  removedMemberships: number;
  revokedPolicyAttachments: number;
  deletedAt: string;
};

export type PolicyAttachmentRevocation = {
  id: string;
  resourceVersion: number;
  revokedAt: string;
};

export type PolicyGrantSource =
  | { kind: "DIRECT"; attachment: UserPolicyAttachment }
  | { kind: "GROUP"; attachment: GroupPolicyAttachment; membership: GroupMembership };

export type UserAccess = { user: User; policyAttachments: UserPolicyAttachment[]; capabilities: ActionCapability[] };
export type AccountAccess = { account: Account; capabilities: ActionCapability[] };
export type DirectoryPage<T> = { items: T[]; nextAfter: string | null };

export type AccountCommand =
  | { kind: "create-user"; loginName: string; displayName: string; initialPassword: string }
  | { kind: "create-account"; id: string; displayName: string; rootLoginName: string; rootDisplayName: string; initialPassword: string }
  | { kind: "set-account-status"; accountId: string; status: "ACTIVE" | "DISABLED"; resourceVersion: number }
  | { kind: "recover-root-credentials"; accountId: string; initialPassword: string; resourceVersion: number }
  | { kind: "set-alias"; alias: string; resourceVersion: number }
  | { kind: "update-user"; userId: string; displayName: string; resourceVersion: number }
  | { kind: "delete-user"; userId: string; resourceVersion: number }
  | { kind: "set-status"; userId: string; status: "ACTIVE" | "DISABLED"; resourceVersion: number }
  | { kind: "reset-password"; userId: string; initialPassword: string; resourceVersion: number }
  | { kind: "create-policy-attachment"; userId: string; policyId: string; policyResourceVersion: number }
  | { kind: "revoke-policy-attachment"; attachmentId: string; resourceVersion: number };
