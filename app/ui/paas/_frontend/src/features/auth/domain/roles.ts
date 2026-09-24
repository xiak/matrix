import type { CapabilityRestriction } from "./accounts";

export type RoleStatus = "ACTIVE" | "DISABLED";

export type RoleTag = { key: string; value: string };

export type Role = {
  id: string;
  accountId: string;
  name: string;
  description: string;
  tags: RoleTag[];
  management: "CUSTOMER";
  status: RoleStatus;
  maxSessionDurationSeconds: number;
  resourceVersion: number;
  currentTrustVersionId: string;
  createdAt: string;
  updatedAt: string;
};

export type RoleCapabilityAction =
  | "iam.role.read"
  | "iam.role.update"
  | "iam.role.set-status"
  | "iam.role.delete"
  | "iam.role-trust.set"
  | "iam.role-policy-attachment.create"
  | "iam.role-policy-attachment.revoke"
  | "iam.role.permission-boundary.set"
  | "iam.role.permission-boundary.remove"
  | "iam.role-session.list"
  | "iam.role-session.read"
  | "iam.role-session.revoke"
  | "iam.role.assume";

export type RoleCapability = {
  action: RoleCapabilityAction;
  resource: { kind: "ROLE" | "ROLE_SESSION" | "POLICY_ATTACHMENT"; id: string };
  available: boolean;
  restrictionReason: CapabilityRestriction | null;
};

export type RoleListing = { role: Role; capabilities: RoleCapability[] };

export type RoleDirectory = {
  accountId: string;
  items: RoleListing[];
  nextAfter: string | null;
};

export type RoleTrustPrincipal = { type: "USER"; id: string };
export type RoleTrustStatement = { sid: string; effect: "ALLOW" | "DENY"; principals: RoleTrustPrincipal[] };
export type RoleTrustDocument = { languageVersion: "1"; statements: RoleTrustStatement[] };

export type RoleTrustVersion = {
  id: string;
  accountId: string;
  roleId: string;
  document: RoleTrustDocument;
  contentDigest: string;
  createdAt: string;
};

export type CreateRoleCommand = {
  name: string;
  description: string;
  tags: RoleTag[];
  maxSessionDurationSeconds: number;
  trustPolicy: RoleTrustDocument;
  requestId: string;
};

export type RolePolicyAttachment = {
  id: string;
  accountId: string;
  target: { kind: "ROLE"; id: string };
  policyId: string;
  scope: "TENANT";
  resourceVersion: number;
  createdAt: string;
  updatedAt: string;
};

export type RoleAccess = {
  role: Role;
  trustVersion: RoleTrustVersion;
  policyAttachments: RolePolicyAttachment[];
  capabilities: RoleCapability[];
};

export type RoleSessionLifecycle = "UNREVOKED" | "EXPIRED" | "REVOKED";
export type RoleSessionFilterLifecycle = RoleSessionLifecycle | "ALL";

export type LiveRoleSession = {
  id: string;
  accountId: string;
  roleId: string;
  sourceUserId: string;
  status: "ACTIVE" | "REVOKED";
  issuedAt: string;
  expiresAt: string;
  revokedAt: string | null;
};

export type RoleSessionSourceUser = { id: string; loginName: string; displayName: string };

export type RoleSessionListing = {
  session: LiveRoleSession;
  sourceUser: RoleSessionSourceUser;
  lifecycle: RoleSessionLifecycle;
  revokeCapability: RoleCapability;
};

export type RoleSessionDirectory = {
  accountId: string;
  roleId: string;
  observedAt: string;
  items: RoleSessionListing[];
  nextAfter: string | null;
};

export type RoleSessionAccess = { observedAt: string; item: RoleSessionListing };
export type RoleSessionRevocation = { outcome: "APPLIED" | "EQUAL_REPLAY"; session: LiveRoleSession };
export type RoleSessionFilter = { exactKind: "session" | "sourceUser"; exactId: string; lifecycle: RoleSessionFilterLifecycle };
