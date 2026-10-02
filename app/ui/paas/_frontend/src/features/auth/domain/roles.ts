import type { CapabilityRestriction, PolicyVersionReference } from "./accounts";
import type { ServicePrincipalReference } from "./serviceAuthorization";

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

export type RoleTrustVersionDirectory = {
  accountId: string;
  roleId: string;
  items: RoleTrustVersion[];
  nextAfter: string | null;
};

// A role boundary is a mandatory ceiling for assumption. Unlike a user
// boundary, an explicit null policy closes assumption instead of meaning an
// unlimited ceiling.
export type RolePermissionBoundary = {
  accountId: string;
  roleId: string;
  resourceVersion: number;
  policy: PolicyVersionReference | null;
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

type RoleSessionRecord = {
  id: string;
  accountId: string;
  roleId: string;
  status: "ACTIVE" | "REVOKED";
  issuedAt: string;
  expiresAt: string;
  revokedAt: string | null;
};

export type UserRoleSession = RoleSessionRecord & { sourceUserId: string; sourceServicePrincipalId?: never };
export type ServiceRoleSession = RoleSessionRecord & { sourceUserId?: never; sourceServicePrincipalId: string };
export type LiveRoleSession = UserRoleSession | ServiceRoleSession;

export type RoleSessionSourceUser = { id: string; loginName: string; displayName: string };
export type RoleSessionSource =
  | { type: "USER"; user: RoleSessionSourceUser; servicePrincipal?: never }
  | { type: "SERVICE_ACCOUNT"; user?: never; servicePrincipal: ServicePrincipalReference };

export type RoleSessionListing = {
  session: LiveRoleSession;
  source: RoleSessionSource;
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
export type RoleSessionFilter = {
  exactKind: "session" | "sourceUser" | "sourceServicePrincipal";
  exactId: string;
  sourceType: "ALL" | RoleSessionSource["type"];
  lifecycle: RoleSessionFilterLifecycle;
};

// Member self-service is intentionally separate from account-scoped Role
// administration. The authenticated USER selects its own account/source
// identity, while the path selects only the Role.
export type AssumableRole = {
  roleId: string;
  accountId: string;
  name: string;
  status: "ACTIVE";
  maxSessionDurationSeconds: number;
  resourceVersion: number;
  capability: RoleCapability & { action: "iam.role.assume"; resource: { kind: "ROLE"; id: string }; available: true; restrictionReason: null };
};

export type AssumableRoleDirectory = {
  accountId: string;
  sourceUserId: string;
  items: AssumableRole[];
  nextAfter: string | null;
};

export type AssumeRoleCommand = {
  resourceVersion: number;
  durationSeconds: number;
  requestId: string;
};

export type AssumeRoleResult =
  | { outcome: "APPLIED"; session: UserRoleSession; credential: string }
  | { outcome: "EQUAL_REPLAY"; session: UserRoleSession; credential: null };

export type CurrentRoleIdentity = {
  session: UserRoleSession & { status: "ACTIVE"; revokedAt: null };
  account: { id: string; displayName: string };
  role: { id: string; name: string };
  sourceUser: RoleSessionSourceUser;
};
