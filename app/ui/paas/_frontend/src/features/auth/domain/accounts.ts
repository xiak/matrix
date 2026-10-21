import { accessKeyNetworkRestrictionsEqual, type AccessKeyNetworkRestrictions } from "./accessKeyNetwork";

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
  | "iam.role.list"
  | "iam.role.create"
  | "iam.access-analyzer.list"
  | "iam.access-analyzer.create"
  | "iam.access-analyzer.update"
  | "iam.access-analyzer.set-disposition"
  | "iam.access-finding.list"
  | "iam.access-finding.archive"
  | "iam.access-finding.unarchive"
  | "iam.security-report.create"
  | "iam.security-report.download"
  | "iam.service-role-template.list"
  | "iam.service-linked-role.list"
  | "iam.security-settings.read"
  | "iam.security-settings.update"
  | "iam.policy.create"
  | "iam.policy.update"
  | "iam.policy.delete"
  | "iam.policy-version.list"
  | "iam.policy-version.read"
  | "iam.policy-version.create"
  | "iam.policy-version.delete"
  | "iam.policy.set-default-version"
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
  | "iam.platform-policy-attachment.revoke"
  | "iam.access-key.list"
  | "iam.access-key.create"
  | "iam.access-key.read"
  | "iam.access-key.set-status"
  | "iam.access-key.set-network-restrictions"
  | "iam.access-key.delete";

export type CapabilityRestriction =
  | "AUTHORITY_REQUIRED"
  | "CURRENT_CREDENTIAL_CHANGE_REQUIRED"
  | "SELF_PROTECTED"
  | "ROOT_IDENTITY_PROTECTED"
  | "INSTALLATION_AUTHORITY_PROTECTED"
  | "SYSTEM_ACCOUNT_PROTECTED"
  | "TARGET_DISABLED"
  | "TARGET_CREDENTIAL_CHANGE_REQUIRED"
  | "TARGET_MUST_BE_DISABLED"
  | "SESSION_NOT_REVOCABLE"
  | "ACCESS_KEY_LIMIT_REACHED"
  | "RESOURCE_VERSION_EXHAUSTED";

export type ActionCapability = {
  action: IamAction;
  resource: { kind: "ACCOUNT" | "USER" | "GROUP" | "GROUP_MEMBERSHIP" | "POLICY_ATTACHMENT" | "ACCESS_KEY" | "POLICY" | "ACCESS_ANALYZER" | "ACCESS_FINDING" | "SECURITY_REPORT"; id: string };
  available: boolean;
  restrictionReason: CapabilityRestriction | null;
};

export const accountAccessViews = ["users", "create-user", "groups", "create-group", "policies", "create-policy", "policy-language", "policy-configuration", "access-diagnosis", "roles", "create-role", "service-authorizations", "role-access", "providers", "user-sso", "federations", "keys", "sessions", "access-analysis", "security-reports", "settings", "authorization-profiles", "tenants"] as const;
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

export type CreateAccountLifecycleCommand = {
  id: string;
  displayName: string;
  rootLoginName: string;
  rootDisplayName: string;
  initialPassword: string;
  requestId: string;
};

export type SetAccountLifecycleStatusCommand = {
  status: "ACTIVE" | "DISABLED";
  resourceVersion: number;
  requestId: string;
};

export type RecoverAccountRootCredentialsCommand = {
  initialPassword: string;
  resourceVersion: number;
  requestId: string;
};

export type AccountLifecycleActor = Readonly<{ actorAccountId: string; actorPrincipalId: string }>;
export type AccountLifecycleOperation = "ACCOUNT_CREATE" | "ACCOUNT_SET_STATUS" | "ACCOUNT_ROOT_CREDENTIALS_RECOVER";

/** Portable original-command identity. Never contains the submitted credentials. */
export type AccountLifecycleIntent = AccountLifecycleActor & Readonly<{
  format: 1;
  accountId: string;
  commandRequestId: string;
}> & (
  | Readonly<{ operation: "ACCOUNT_CREATE"; expectedResourceVersion: 0 }>
  | Readonly<{ operation: "ACCOUNT_SET_STATUS"; expectedResourceVersion: number; intendedStatus: Account["status"] }>
  | Readonly<{ operation: "ACCOUNT_ROOT_CREDENTIALS_RECOVER"; expectedResourceVersion: number }>
);

/** Immutable completion fact, not present Account state or a resource-access permit. */
export type AccountLifecycleCompletion = AccountLifecycleActor & Readonly<{
  accountId: string;
  commandRequestId: string;
  eventId: string;
  occurredAt: string;
}> & (
  | Readonly<{ operation: "ACCOUNT_CREATE"; expectedResourceVersion: 0; resultingResourceVersion: 1; status: "ACTIVE"; rootPrincipalId: string }>
  | Readonly<{ operation: "ACCOUNT_SET_STATUS"; expectedResourceVersion: number; resultingResourceVersion: number; status: Account["status"] }>
  | Readonly<{ operation: "ACCOUNT_ROOT_CREDENTIALS_RECOVER"; expectedResourceVersion: number; resultingResourceVersion: number; status: Account["status"]; rootPrincipalId: string }>
);

export type AccountSecuritySettings = {
  accountId: string;
  resourceVersion: number;
  mfa: { requiredForUsers: boolean };
  password: AccountPasswordSettings;
  session: AccountSessionSettings;
  accessKeyNetwork: AccessKeyNetworkRestrictions;
  updatedAt: string;
};

export type AccountPasswordSettings = {
  minimumLength: number;
  requireLowercase: boolean;
  requireUppercase: boolean;
  requireDigit: boolean;
  requireSymbol: boolean;
  historyCount: number;
  maxAgeDays: number;
  expiryMode: "CHANGE_PASSWORD" | "ADMIN_RESET";
};

export type AccountSessionSettings = { idleTimeoutMinutes: number };

export type RetainedAccountSecuritySettings = Omit<AccountSecuritySettings, "password" | "session" | "accessKeyNetwork"> & {
  password: (Omit<AccountPasswordSettings, "maxAgeDays" | "expiryMode"> & Partial<Pick<AccountPasswordSettings, "maxAgeDays" | "expiryMode">>) | null;
  session: AccountSessionSettings | null;
  accessKeyNetwork: AccessKeyNetworkRestrictions | null;
};

export type SecuritySettingsUpdateIntent = {
  expectedResourceVersion: number;
  mfa: { requiredForUsers: boolean };
  password: AccountPasswordSettings;
  session: AccountSessionSettings;
  accessKeyNetwork: AccessKeyNetworkRestrictions;
};

export function sameSecuritySettingsIntent(left: SecuritySettingsUpdateIntent, right: SecuritySettingsUpdateIntent): boolean {
  return left.expectedResourceVersion === right.expectedResourceVersion && left.mfa.requiredForUsers === right.mfa.requiredForUsers &&
    left.password.minimumLength === right.password.minimumLength && left.password.requireLowercase === right.password.requireLowercase &&
    left.password.requireUppercase === right.password.requireUppercase && left.password.requireDigit === right.password.requireDigit &&
    left.password.requireSymbol === right.password.requireSymbol && left.password.historyCount === right.password.historyCount &&
    left.password.maxAgeDays === right.password.maxAgeDays && left.password.expiryMode === right.password.expiryMode &&
    left.session.idleTimeoutMinutes === right.session.idleTimeoutMinutes && accessKeyNetworkRestrictionsEqual(left.accessKeyNetwork, right.accessKeyNetwork);
}

export type AccountSecuritySettingsChange = {
  requestId: string;
  expectedResourceVersion: number;
  settings: RetainedAccountSecuritySettings;
  callerSessionEnded: true;
};

export type AccountSecuritySettingsUpdate = {
  outcome: "APPLIED" | "EQUAL_REPLAY";
  change: AccountSecuritySettingsChange;
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

export type UserManagementIntent = Readonly<{
  format: 1; accountId: string; actorPrincipalId: string; userId: string;
  commandRequestId: string; expectedResourceVersion: number;
} & ({ operation: "USER_UPDATE"; intendedDisplayName: string } | { operation: "USER_SET_STATUS"; intendedStatus: User["status"] })>;

/** Original committed User result, never a current-state or resource-access verdict. */
export type UserManagementCompletion = Readonly<{
  accountId: string; actorPrincipalId: string; userId: string; commandRequestId: string;
  operation: UserManagementIntent["operation"]; expectedResourceVersion: number;
  result: User; eventId: string; occurredAt: string;
}>;

export function userManagementDisplayNameValid(value: unknown): value is string {
  return typeof value === "string" && value.trim() === value && value.length > 0 && Array.from(value).length <= 128;
}

export function userManagementResultMatches(result: User, intent: UserManagementIntent): boolean {
  return Boolean(result && Object.keys(result).length === 7 && result.accountId === intent.accountId && result.id === intent.userId &&
    typeof result.loginName === "string" && result.loginName.length > 0 && typeof result.mustChangePassword === "boolean" &&
    typeof result.displayName === "string" && result.displayName.length > 0 && Array.from(result.displayName).length <= 128 && (result.status === "ACTIVE" || result.status === "DISABLED") &&
    result.resourceVersion === intent.expectedResourceVersion + 1 &&
    (intent.operation === "USER_UPDATE" ? result.displayName === intent.intendedDisplayName : result.status === intent.intendedStatus));
}

export function userManagementCompletionMatches(result: UserManagementCompletion, intent: UserManagementIntent): boolean {
  return Boolean(result && Object.keys(result).length === 9 && result.accountId === intent.accountId && result.actorPrincipalId === intent.actorPrincipalId &&
    result.userId === intent.userId && result.commandRequestId === intent.commandRequestId && result.operation === intent.operation &&
    result.expectedResourceVersion === intent.expectedResourceVersion && typeof result.eventId === "string" && result.eventId.length > 0 &&
    typeof result.occurredAt === "string" && Number.isFinite(Date.parse(result.occurredAt)) && userManagementResultMatches(result.result, intent));
}

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

export type AccountPolicyDocument = {
  languageVersion: "1";
  scope: "TENANT";
  statements: {
    sid: string;
    effect: "ALLOW" | "DENY";
    actions: string[];
    resources: { kind: string; match: "EXACT" | "PREFIX_IN_AUTHORITY" | "ANY_IN_AUTHORITY"; id?: string }[];
    conditions?: { key: string; operator: string; values: string[] }[];
  }[];
};

export type AccountPolicyVersion = {
  policyId: string;
  versionId: string;
  document: AccountPolicyDocument;
  contentDigest: string;
  contractVersion: 1 | 2;
  compilation?: {
    compilationVersion: "1";
    profiles: { product: string; revision: number; contentDigest: string }[];
    resolvedStatements: { sid: string; actions: string[] }[];
  };
};

export type AccountPolicyDetail = { policy: AccountPolicy; version: AccountPolicyVersion };
export type AccountPolicyAccess = { detail: AccountPolicyDetail; capabilities: ActionCapability[] };
export type AccountPolicyVersionDirectory = { policy: AccountPolicy; items: AccountPolicyVersion[] };

/** Non-secret original command metadata, never a receipt or authorization permit. */
export type PolicyMutationIntent = Readonly<{
  format: 1;
  accountId: string;
  actorPrincipalId: string;
  policy: AccountPolicy;
  contentDigest: string;
  requestId: string;
  createdAt: string;
  state: "UNKNOWN";
} & ({ kind: "update"; displayName: string } | { kind: "retire" })>;

export function policyDisplayNameValid(value: string): boolean {
  return Boolean(value) && value.trim() === value && !/\p{Cc}/u.test(value) && new TextEncoder().encode(value).length <= 128;
}

export function policyMetadataResultMatches(result: AccountPolicy, source: AccountPolicy, displayName: string, status: PolicyStatus): boolean {
  return result.id === source.id && result.accountId === source.accountId && result.management === "CUSTOMER" &&
    result.scope === "TENANT" && result.status === status && result.displayName === displayName &&
    result.resourceVersion === source.resourceVersion + 1 && result.defaultVersionId === source.defaultVersionId &&
    result.createdAt === source.createdAt;
}

// Product-owned authorization declarations are policy-authoring metadata. They
// are not Policy records, grants, effective permissions or tenant-owned
// registration state, so keep their open action namespace separate from the
// console's closed management-action union above.
export type AuthorizationAuthorityScope = "TENANT" | "INSTALLATION" | "INSTALLATION_PROBE";
export type AuthorizationResourceMode = "INSTANCE" | "COLLECTION";
export type AuthorizationCollectionUsage = "COLLECTION_LIST" | "COLLECTION_CREATE";
export type AuthorizationConditionKey =
  | "iam.account-id"
  | "iam.current-time"
  | "iam.principal-id"
  | "request.source-ip"
  | "request.tag/environment"
  | "resource.tag/environment";
export type AuthorizationSubjectType = "USER" | "SERVICE_ACCOUNT" | "ROLE";
export type AuthorizationUserAuthenticationMethod = "LOGIN_SESSION" | "ACCESS_KEY";

export type AuthorizationProfileCondition = {
  key: AuthorizationConditionKey;
  valueType: "STRING" | "TIME" | "IP";
  source: "IAM_AUTHENTICATED_IDENTITY" | "IAM_TRANSACTION_TIME" | "CALLING_SERVICE_NETWORK" |
    "CALLING_SERVICE_REQUEST_TAG" | "CALLING_SERVICE_RESOURCE_TAG";
};

export type AuthorizationResourceShape = {
  mode: AuthorizationResourceMode;
  prefixAllowed: boolean;
  collectionUsage?: AuthorizationCollectionUsage;
};

export type AuthorizationProfileAction = {
  action: string;
  resourceKind: string;
  scope: AuthorizationAuthorityScope;
  resourceShapes: AuthorizationResourceShape[];
  // Product PEP transport capability for bounded candidate filtering. This is
  // declaration metadata, never an allow decision or a policy grant.
  instanceListBatch?: boolean;
  conditions?: AuthorizationProfileCondition[];
  resultResourceKind?: string;
  // Missing sets retain the sealed legacy ceiling; they never mean all
  // subjects or all USER credential carriers.
  subjectTypes?: AuthorizationSubjectType[];
  userAuthenticationMethods?: AuthorizationUserAuthenticationMethod[];
};

// An omitted admission set retains IAM's sealed legacy ceiling; absence never
// means that every subject or credential carrier is supported.
export function admittedAuthorizationSubjects(action: AuthorizationProfileAction): AuthorizationSubjectType[] {
  return action.subjectTypes ?? (action.scope === "INSTALLATION_PROBE" ? ["SERVICE_ACCOUNT"] : ["USER"]);
}

export function admittedAuthorizationUserAuthenticationMethods(
  action: AuthorizationProfileAction
): AuthorizationUserAuthenticationMethod[] {
  return admittedAuthorizationSubjects(action).includes("USER")
    ? action.userAuthenticationMethods ?? ["LOGIN_SESSION"]
    : [];
}

export function authorizationResourceShapeKind(shape: AuthorizationResourceShape): "INSTANCE" | "INSTANCE_PREFIX" | "COLLECTION_LIST" | "COLLECTION_CREATE" {
  if (shape.mode === "COLLECTION") return shape.collectionUsage === "COLLECTION_CREATE" ? "COLLECTION_CREATE" : "COLLECTION_LIST";
  return shape.prefixAllowed ? "INSTANCE_PREFIX" : "INSTANCE";
}

export type AuthorizationProfile = {
  product: string;
  revision: number;
  callingService: string;
  actions: AuthorizationProfileAction[];
};

export type AuthorizationProfileEntry = {
  profile: AuthorizationProfile;
  contentDigest: string;
};

export type AuthorizationProfileDirectory = {
  accountId: string;
  items: AuthorizationProfileEntry[];
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

export type RolePolicyAttachment = Omit<UserPolicyAttachment, "target" | "scope" | "installationId"> & {
  target: { kind: "ROLE"; id: string };
  scope: "TENANT";
};

export type DirectPolicyAttachment = UserPolicyAttachment | GroupPolicyAttachment | RolePolicyAttachment;

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

export type GroupMembershipMutationIntent = Readonly<{
  format: 1;
  accountId: string;
  actorPrincipalId: string;
  groupId: string;
  userId: string;
  requestId: string;
} & ({ operation: "CREATE" } | { operation: "REMOVE"; membershipId: string; resourceVersion: number })>;

export function groupMembershipResultMatches(result: GroupMembership, intent: GroupMembershipMutationIntent): boolean {
  if (result.accountId !== intent.accountId || result.groupId !== intent.groupId || result.userId !== intent.userId ||
      !result.id || !Number.isFinite(Date.parse(result.createdAt)) || !Number.isFinite(Date.parse(result.updatedAt))) return false;
  return intent.operation === "CREATE"
    ? result.resourceVersion === 1 && result.createdBy === intent.actorPrincipalId && result.removedAt === undefined && result.removedBy === undefined && result.createdAt === result.updatedAt
    : result.id === intent.membershipId && result.resourceVersion === intent.resourceVersion + 1 && result.removedBy === intent.actorPrincipalId &&
      typeof result.removedAt === "string" && Number.isFinite(Date.parse(result.removedAt)) && result.removedAt === result.updatedAt;
}

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

type PolicyAttachmentChangeBase = {
  accountId: string;
  actorPrincipalId: string;
  requestId: string;
  completedAt: string;
};

// Immutable completion evidence for one direct User, Group, or Role policy
// relationship command. It records the original result, not the
// relationship's current state and not a reusable authorization decision.
export type PolicyAttachmentChange = PolicyAttachmentChangeBase & (
  | {
      operation: "CREATE";
      target: DirectPolicyAttachment["target"];
      policyId: string;
      policyResourceVersion: number;
      attachment: DirectPolicyAttachment;
    }
  | {
      operation: "REVOKE";
      attachmentId: string;
      expectedResourceVersion: number;
      revocation: PolicyAttachmentRevocation;
    }
);

export type PolicyAttachmentChangeOperationExpectation =
  | { operation: "CREATE"; requestId: string; target: DirectPolicyAttachment["target"]; policyId: string; policyResourceVersion: number }
  | { operation: "REVOKE"; requestId: string; attachmentId: string; expectedResourceVersion: number };

export type PolicyAttachmentChangeExpectation = {
  accountId: string;
  actorPrincipalId: string;
} & PolicyAttachmentChangeOperationExpectation;

export type PolicyGrantSource =
  | { kind: "DIRECT"; attachment: UserPolicyAttachment }
  | { kind: "GROUP"; attachment: GroupPolicyAttachment; membership: GroupMembership };

export type UserAccess = { user: User; policyAttachments: UserPolicyAttachment[]; capabilities: ActionCapability[] };
export type AccountAccess = { account: Account; capabilities: ActionCapability[] };
export type DirectoryPage<T> = { items: T[]; nextAfter: string | null };

export type PasswordResetRequestIdentity = Readonly<{
  accountId: string;
  actorId: string;
  userId: string;
  resourceVersion: number;
  requestId: string;
}>;

export type UserPasswordResetCompletion = Readonly<{
  accountId: string;
  actorPrincipalId: string;
  userId: string;
  requestId: string;
  expectedResourceVersion: number;
  resultingResourceVersion: number;
  eventId: string;
  occurredAt: string;
}>;

export type CreateUserCommand = Readonly<{
  loginName: string;
  displayName: string;
  initialPassword: string;
  permissionBoundary: null;
  requestId: string;
}>;

export type AccountCommand =
  | { kind: "create-account"; id: string; displayName: string; rootLoginName: string; rootDisplayName: string; initialPassword: string }
  | { kind: "set-account-status"; accountId: string; status: "ACTIVE" | "DISABLED"; resourceVersion: number }
  | { kind: "recover-root-credentials"; accountId: string; initialPassword: string; resourceVersion: number }
  | { kind: "set-alias"; alias: string; resourceVersion: number }
  | { kind: "delete-user"; userId: string; resourceVersion: number }
  | { kind: "set-status"; userId: string; status: "ACTIVE" | "DISABLED"; resourceVersion: number }
  | { kind: "reset-password"; userId: string; initialPassword: string; resourceVersion: number; requestId: string }
  | { kind: "create-policy-attachment"; userId: string; policyId: string; policyResourceVersion: number; requestId: string };
