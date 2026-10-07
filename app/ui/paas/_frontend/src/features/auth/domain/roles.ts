import type { CapabilityRestriction, PolicyVersionReference, RolePolicyAttachment } from "./accounts";
import type { ServicePrincipalReference } from "./serviceAuthorization";

export type RoleStatus = "ACTIVE" | "DISABLED";

export type RoleTag = { key: string; value: string };

export type RoleMetadataIssue = "invalidName" | "invalidMetadata";

export function validateRoleMetadataInput(name: string, description: string, tags: RoleTag[], minutes: number): RoleMetadataIssue | null {
  if (!name || Array.from(name).length > 64 || /[<>\p{Cc}]/u.test(name)) return "invalidName";
  if (!Number.isInteger(minutes) || minutes < 1 || minutes > 720 || Array.from(description).length > 512 || /\p{Cc}/u.test(description)) return "invalidMetadata";
  if (tags.length > 50 || new Set(tags.map((tag) => tag.key.trim())).size !== tags.length ||
      tags.some((tag) => !tag.key.trim() || tag.key !== tag.key.trim() || tag.value !== tag.value.trim() ||
        Array.from(tag.key).length > 64 || Array.from(tag.value).length > 256 || /[<>\p{Cc}]/u.test(tag.key + tag.value)) ||
      tags.reduce((size, tag) => size + tag.key.length + tag.value.length, name.length + description.length) > 4096) return "invalidMetadata";
  return null;
}

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

export function roleTrustDocumentFromUnknown(value: unknown): RoleTrustDocument | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const document = value as Record<string, unknown>;
  if (Object.keys(document).sort().join("|") !== "languageVersion|statements" || document.languageVersion !== "1" ||
      !Array.isArray(document.statements) || document.statements.length > 8) return null;
  const ids = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
  const seenSids = new Set<string>();
  let visits = 0;
  const statements: RoleTrustStatement[] = [];
  for (const candidate of document.statements) {
    if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) return null;
    const statement = candidate as Record<string, unknown>;
    if (Object.keys(statement).sort().join("|") !== "effect|principals|sid" || typeof statement.sid !== "string" || !ids.test(statement.sid) ||
        seenSids.has(statement.sid) || (statement.effect !== "ALLOW" && statement.effect !== "DENY") ||
        !Array.isArray(statement.principals) || statement.principals.length < 1 || statement.principals.length > 32) return null;
    const seenPrincipals = new Set<string>();
    const principals: RoleTrustPrincipal[] = [];
    for (const entry of statement.principals) {
      if (!entry || typeof entry !== "object" || Array.isArray(entry)) return null;
      const principal = entry as Record<string, unknown>;
      if (Object.keys(principal).sort().join("|") !== "id|type" || principal.type !== "USER" || typeof principal.id !== "string" ||
          !ids.test(principal.id) || seenPrincipals.has(principal.id)) return null;
      seenPrincipals.add(principal.id);
      principals.push({ type: "USER", id: principal.id });
    }
    visits += principals.length;
    if (visits > 256) return null;
    seenSids.add(statement.sid);
    statements.push({ sid: statement.sid, effect: statement.effect, principals });
  }
  const result: RoleTrustDocument = { languageVersion: "1", statements };
  return new TextEncoder().encode(JSON.stringify(result)).length <= 16 * 1024 ? result : null;
}

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

export type SetRolePermissionBoundaryCommand = {
  policyId: string;
  policyResourceVersion: number;
  resourceVersion: number;
  requestId: string;
};

export type RemoveRolePermissionBoundaryCommand = {
  resourceVersion: number;
  requestId: string;
};

export type CreateRoleCommand = {
  name: string;
  description: string;
  tags: RoleTag[];
  maxSessionDurationSeconds: number;
  trustPolicy: RoleTrustDocument;
  requestId: string;
};

export type UpdateRoleCommand = {
  name: string;
  description: string;
  tags: RoleTag[];
  maxSessionDurationSeconds: number;
  resourceVersion: number;
  requestId: string;
};

export type SetRoleStatusCommand = {
  status: RoleStatus;
  resourceVersion: number;
  requestId: string;
};

export type SetRoleTrustPolicyCommand = {
  document: RoleTrustDocument;
  resourceVersion: number;
  requestId: string;
};

export type DeleteRoleCommand = {
  resourceVersion: number;
  requestId: string;
  /** Local response binding only. It is never serialized to IAM. */
  expectedName: string;
};

export type RoleDeletion = {
  id: string;
  accountId: string;
  name: string;
  resourceVersion: number;
  revokedPolicyAttachments: number;
  deletedAt: string;
};

export type CreateRolePolicyAttachmentCommand = {
  policyId: string;
  policyResourceVersion: number;
  requestId: string;
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
