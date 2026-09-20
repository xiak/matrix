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
  | "iam.role.assume";

export type RoleCapability = {
  action: RoleCapabilityAction;
  resource: { kind: "ROLE" | "POLICY_ATTACHMENT"; id: string };
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
