import type {
  AuthenticatorRecovery,
  AuthenticatorRecoveryConfirmation,
  AuthenticatorRecoveryStart,
  LoginResult,
  OtherSessionsRevocation,
  OwnSessionPage,
  OwnSessionRevocation
} from "../domain/session";
import type {
  AccountAccess,
  AccountCommand,
  AccountIdentity,
  AccountPolicyDetail,
  AccountPolicyDocument,
  AccountPolicyVersionDirectory,
  AccountSecuritySettings,
  AccountSecuritySettingsChange,
  AccountSecuritySettingsUpdate,
  SecuritySettingsUpdateIntent,
  DirectoryPage,
  Group,
  GroupAccess,
  GroupDeletion,
  GroupMembership,
  GroupMembershipPage,
  GroupPolicyAttachment,
  PolicyAttachmentRevocation,
  PolicyDirectory,
  AuthorizationProfileDirectory,
  PasswordResetRequestIdentity,
  UserPasswordResetCompletion,
  UserPolicyAttachmentChange,
  UserPolicyAttachmentChangeExpectation,
  UserAccess,
  UserPermissionBoundary
} from "../domain/accounts";
import type { ServiceLinkedRoleAccess, ServiceLinkedRoleDirectory, ServiceRoleTemplateDirectory } from "../domain/serviceAuthorization";
import type { AccessWorkspace, AccessWorkspaceCommand } from "../domain/accessWorkspace";
import type { AccessKeyAccess, AccessKeyCreation, AccessKeyDeletion, AccessKeyDirectory, AccessKeyNetworkChange, AccessKeyStatus, AccessKeyStatusChange } from "../domain/accessKeys";
import type { AccessKeyNetworkRestrictions } from "../domain/accessKeyNetwork";
import type { AuthenticatorState, EnrollmentChallengeState, NotificationContact, NotificationContactReplacementIntent, NotificationContactReplacementVerification, NotificationContactVerification, RecoveryCodeRegeneration, RecoveryCodeRegenerationResponse, SecurityStepUp, TOTPEnrollment, TOTPEnrollmentConfirmation, TOTPEnrollmentStart } from "../domain/personalSecurity";
import type { UserBatchCommand } from "../domain/userBatch";
import type { AssumeRoleCommand, AssumeRoleResult, AssumableRoleDirectory, CreateRoleCommand, CurrentRoleIdentity, RemoveRolePermissionBoundaryCommand, Role, RoleAccess, RoleDirectory, RolePermissionBoundary, RoleSessionAccess, RoleSessionDirectory, RoleSessionFilter, RoleSessionRevocation, RoleTrustVersionDirectory, SetRolePermissionBoundaryCommand, UserRoleSession } from "../domain/roles";
import type { AccessAnalyzer, AccessAnalyzerDirectory, AccessFinding, AccessFindingDirectory, AccessFindingDispositionCommand, AccessFindingStatusFilter, CreateAccessAnalyzerCommand, SetAccessDispositionCommand, UpdateAccessAnalyzerCommand } from "../domain/accessAnalysis";
import type { AccountSecurityReport, AccountSecurityReportCreation, AccountSecurityReportDownload } from "../domain/securityReports";

export type LoginCommand = { loginName: string; password: string };
export type ChangePasswordCommand = { currentPassword: string; newPassword: string; revokeOtherSessions?: boolean };
export type VerifyAuthenticationChallengeCommand = { challengeId: string; challengeCredential: string; code: string };
export type ChangeChallengePasswordCommand = { challengeId: string; challengeCredential: string; newPassword: string };
export type StartAuthenticatorRecoveryCommand = {
  challengeId: string;
  challengeCredential: string;
  recoveryCode: string;
  requestId: string;
};
export type ConfirmAuthenticatorRecoveryCommand = {
  challengeId: string;
  challengeCredential: string;
  code: string;
  requestId: string;
  recoveryRequestId: string;
};
export type InspectAuthenticatorRecoveryCommand = {
  challengeId: string;
  challengeCredential: string;
  requestId: string;
};

export interface IamRepository {
  login(command: LoginCommand): Promise<LoginResult>;
  authenticationChallenges?: {
    verify(command: VerifyAuthenticationChallengeCommand): Promise<LoginResult>;
    changePassword(command: ChangeChallengePasswordCommand): Promise<{ nextStep: "REAUTHENTICATE"; changedAt: string }>;
    inspectFirstEnrollment?(command: { challengeId: string; challengeCredential: string }): Promise<EnrollmentChallengeState>;
    startFirstContact?(command: { challengeId: string; challengeCredential: string; email: string; requestId: string }): Promise<NotificationContactVerification>;
    confirmFirstContact?(command: { challengeId: string; challengeCredential: string; verificationId: string; code: string; requestId: string }): Promise<NotificationContactVerification>;
    startFirstTOTP?(command: { challengeId: string; challengeCredential: string; requestId: string }): Promise<TOTPEnrollmentStart>;
    confirmFirstTOTP?(command: { challengeId: string; challengeCredential: string; enrollmentId: string; code: string; requestId: string }): Promise<TOTPEnrollmentConfirmation>;
    startRecovery?(command: StartAuthenticatorRecoveryCommand): Promise<AuthenticatorRecoveryStart>;
    confirmRecovery?(command: ConfirmAuthenticatorRecoveryCommand): Promise<AuthenticatorRecoveryConfirmation>;
    inspectRecovery?(command: InspectAuthenticatorRecoveryCommand): Promise<AuthenticatorRecovery>;
  };
  changePassword(credential: string, command: ChangePasswordCommand): Promise<void>;
  logout(credential: string): Promise<void>;
  roleSelfService?: {
    listAssumable(credential: string, after?: string): Promise<AssumableRoleDirectory>;
    assume(credential: string, roleId: string, command: AssumeRoleCommand): Promise<AssumeRoleResult>;
    readByRequest(credential: string, requestId: string): Promise<UserRoleSession>;
    revokeByRequest(credential: string, issuanceRequestId: string, requestId: string): Promise<UserRoleSession>;
    currentIdentity(roleCredential: string): Promise<CurrentRoleIdentity>;
    logout(roleCredential: string, requestId: string): Promise<UserRoleSession>;
    revalidateSource(credential: string, accountId: string, userId: string): Promise<void>;
  };
  sessions?: {
    list(credential: string, after?: string): Promise<OwnSessionPage>;
    revoke(credential: string, targetSessionId: string, requestId: string): Promise<OwnSessionRevocation>;
    revokeOthers(credential: string, requestId: string): Promise<OtherSessionsRevocation>;
  };
  personalSecurity?: {
    notificationContact(credential: string): Promise<NotificationContact>;
    startNotificationVerification(credential: string, command: { email: string; password: string; requestId: string }): Promise<NotificationContactVerification>;
    notificationVerification(credential: string, verificationId: string): Promise<NotificationContactVerification>;
    confirmNotificationVerification(credential: string, verificationId: string, command: { code: string; requestId: string }): Promise<NotificationContactVerification>;
    /**
     * Purpose-bound verified-address replacement. It remains optional until the
     * independently accepted IAM runtime is the deployment baseline.
     */
    notificationReplacement?: {
      startStepUp(credential: string, command: { requestId: string; expectedFactorRevision: number; notificationContact: NotificationContactReplacementIntent }): Promise<SecurityStepUp>;
      stepUpByRequest(credential: string, requestId: string, expectedFactorRevision: number, notificationContact: NotificationContactReplacementIntent): Promise<SecurityStepUp>;
      verifyStepUp(credential: string, stepUpId: string, originalRequestId: string, expectedFactorRevision: number, notificationContact: NotificationContactReplacementIntent, command: { requestId: string; password: string; code: string }): Promise<SecurityStepUp>;
      startVerification(credential: string, command: { stepUpId: string; requestId: string } & NotificationContactReplacementIntent): Promise<NotificationContactReplacementVerification>;
      verification(credential: string, verificationId: string, command: { requestId: string } & NotificationContactReplacementIntent): Promise<NotificationContactReplacementVerification>;
      confirmVerification(credential: string, verificationId: string, original: { requestId: string } & NotificationContactReplacementIntent, command: { code: string; requestId: string }): Promise<NotificationContactReplacementVerification>;
    };
    authenticatorState(credential: string): Promise<AuthenticatorState>;
    startTOTPEnrollment(credential: string, command: { requestId: string; password: string; expectedFactorRevision: number }): Promise<TOTPEnrollmentStart>;
    replacement?: {
      startStepUp(credential: string, command: { requestId: string; expectedFactorRevision: number }): Promise<SecurityStepUp>;
      stepUpByRequest(credential: string, requestId: string): Promise<SecurityStepUp>;
      verifyStepUp(credential: string, stepUpId: string, command: { requestId: string; password: string; code: string }): Promise<SecurityStepUp>;
      startEnrollment(credential: string, command: { requestId: string; stepUpId: string; expectedFactorRevision: number }): Promise<TOTPEnrollmentStart>;
      enrollmentByRequest(credential: string, requestId: string): Promise<TOTPEnrollment>;
    };
    totpEnrollment(credential: string, enrollmentId: string): Promise<TOTPEnrollment>;
    totpEnrollmentByRequest(credential: string, requestId: string): Promise<TOTPEnrollment>;
    cancelTOTPEnrollment(credential: string, enrollmentId: string): Promise<TOTPEnrollment>;
    confirmTOTPEnrollment(credential: string, enrollmentId: string, command: { requestId: string; code: string }): Promise<TOTPEnrollmentConfirmation>;
    recoveryCodes?: {
      startStepUp(credential: string, command: { requestId: string; expectedFactorRevision: number }): Promise<SecurityStepUp>;
      stepUpByRequest(credential: string, requestId: string): Promise<SecurityStepUp>;
      verifyStepUp(credential: string, stepUpId: string, command: { requestId: string; password: string; code: string }): Promise<SecurityStepUp>;
      regenerate(credential: string, command: { requestId: string; stepUpId: string; expectedFactorRevision: number }): Promise<RecoveryCodeRegenerationResponse>;
      regenerationByRequest(credential: string, requestId: string): Promise<RecoveryCodeRegeneration>;
    };
  };
}

export interface AccountRepository {
  // Security reports have no collection endpoint. The authenticated Session
  // selects the account; accountId only binds returned resources locally.
  securityReports?: {
    create(credential: string, accountId: string, command: { formatVersion: 1; requestId: string }): Promise<AccountSecurityReportCreation>;
    read(credential: string, accountId: string, reportId: string): Promise<AccountSecurityReport>;
    /** Re-reads metadata, then validates the exact CSV bytes before returning them. */
    download(credential: string, accountId: string, reportId: string): Promise<AccountSecurityReportDownload>;
  };
  // Access analysis is account-scoped by the authenticated Session. The
  // account and analyzer IDs below only verify returned resources locally.
  accessAnalysis?: {
    listAnalyzers(credential: string, accountId: string, after?: string): Promise<AccessAnalyzerDirectory>;
    readAnalyzer(credential: string, accountId: string, analyzerId: string): Promise<AccessAnalyzer>;
    createAnalyzer(credential: string, accountId: string, command: CreateAccessAnalyzerCommand): Promise<AccessAnalyzer>;
    updateAnalyzer(credential: string, accountId: string, analyzerId: string, command: UpdateAccessAnalyzerCommand): Promise<AccessAnalyzer>;
    setDisposition(credential: string, accountId: string, analyzerId: string, command: SetAccessDispositionCommand): Promise<AccessAnalyzer>;
    listFindings(credential: string, accountId: string, analyzerId: string, status: AccessFindingStatusFilter, after?: string): Promise<AccessFindingDirectory>;
    readFinding(credential: string, accountId: string, analyzerId: string, findingId: string): Promise<AccessFinding>;
    archiveFinding(credential: string, accountId: string, analyzerId: string, findingId: string, command: AccessFindingDispositionCommand): Promise<AccessFinding>;
    unarchiveFinding(credential: string, accountId: string, analyzerId: string, findingId: string, command: AccessFindingDispositionCommand): Promise<AccessFinding>;
  };
  accountSecuritySettings?: {
    // The authenticated Session selects the account; accountId only verifies
    // the response locally and is never sent as an authority selector.
    read(credential: string, accountId: string): Promise<AccountSecuritySettings>;
    /** Full-settings replacement guarded by a dedicated step-up ceremony. */
    update?: {
      startStepUp(credential: string, command: { requestId: string; expectedFactorRevision: number; intent: SecuritySettingsUpdateIntent }): Promise<SecurityStepUp>;
      stepUpByRequest(credential: string, requestId: string, expectedFactorRevision: number, intent: SecuritySettingsUpdateIntent): Promise<SecurityStepUp>;
      verifyStepUp(credential: string, stepUpId: string, originalRequestId: string, expectedFactorRevision: number, intent: SecuritySettingsUpdateIntent, command: { requestId: string; password: string; code: string }): Promise<SecurityStepUp>;
      apply(credential: string, accountId: string, command: { requestId: string; stepUpId: string; intent: SecuritySettingsUpdateIntent }): Promise<AccountSecuritySettingsUpdate>;
      changeByRequest(credential: string, accountId: string, requestId: string, intent: SecuritySettingsUpdateIntent): Promise<AccountSecuritySettingsChange>;
    };
  };
  // Live boundary lifecycle is separate from the isolated MOCK workspace.
  // Account/user IDs bind responses locally; they never select HTTP authority.
  permissionBoundaries?: {
    read(credential: string, accountId: string, userId: string): Promise<UserPermissionBoundary>;
    set(credential: string, accountId: string, userId: string, command: {
      policyId: string;
      policyResourceVersion: number;
      resourceVersion: number;
      requestId: string;
    }): Promise<UserPermissionBoundary>;
    remove(credential: string, accountId: string, userId: string, command: {
      resourceVersion: number;
      requestId: string;
    }): Promise<UserPermissionBoundary>;
  };
  accessKeys?: {
    list(credential: string, accountId: string, userId: string): Promise<AccessKeyDirectory>;
    read(credential: string, accountId: string, userId: string, accessKeyId: string): Promise<AccessKeyAccess>;
    create(credential: string, accountId: string, userId: string, command: {
      userResourceVersion: number;
      networkRestrictions: AccessKeyNetworkRestrictions;
      requestId: string;
    }): Promise<AccessKeyCreation>;
    setStatus(credential: string, accountId: string, userId: string, accessKeyId: string, command: {
      accessKeyResourceVersion: number;
      requestId: string;
      status: AccessKeyStatus;
    }): Promise<AccessKeyStatusChange>;
    setNetworkRestrictions(credential: string, accountId: string, userId: string, accessKeyId: string, command: {
      accessKeyResourceVersion: number;
      networkRestrictions: AccessKeyNetworkRestrictions;
      requestId: string;
    }): Promise<AccessKeyNetworkChange>;
    delete(credential: string, accountId: string, userId: string, accessKeyId: string, command: {
      accessKeyResourceVersion: number;
      requestId: string;
    }): Promise<AccessKeyDeletion>;
  };
  // Role management is account-scoped by the authenticated credential. The
  // account ID below verifies responses locally and is never sent as an
  // authority selector.
  roles?: {
    list(credential: string, accountId: string, after?: string): Promise<RoleDirectory>;
    read(credential: string, accountId: string, roleId: string): Promise<RoleAccess>;
    readPermissionBoundary(credential: string, accountId: string, roleId: string): Promise<RolePermissionBoundary>;
    setPermissionBoundary(credential: string, accountId: string, roleId: string, command: SetRolePermissionBoundaryCommand): Promise<RolePermissionBoundary>;
    removePermissionBoundary(credential: string, accountId: string, roleId: string, command: RemoveRolePermissionBoundaryCommand): Promise<RolePermissionBoundary>;
    listTrustVersions(credential: string, accountId: string, roleId: string, after?: string): Promise<RoleTrustVersionDirectory>;
    create(credential: string, accountId: string, command: CreateRoleCommand): Promise<Role>;
    listSessions(credential: string, accountId: string, roleId: string, filter: RoleSessionFilter, after?: string): Promise<RoleSessionDirectory>;
    readSession(credential: string, accountId: string, roleId: string, sessionId: string): Promise<RoleSessionAccess>;
    revokeSession(credential: string, accountId: string, roleId: string, sessionId: string, requestId: string): Promise<RoleSessionRevocation>;
  };
  // Explicit, isolated DEMO capabilities. The live HTTP adapter never exposes them.
  executeUserBatch?(credential: string, command: UserBatchCommand): Promise<{ workspace: AccessWorkspace }>;
  workspace?: {
    read(credential: string): Promise<AccessWorkspace>;
    execute(credential: string, command: AccessWorkspaceCommand): Promise<{ workspace: AccessWorkspace; issuedKey?: { id: string; secret: string }; recoveryCodes?: string[] }>;
  };
  currentIdentity(credential: string): Promise<AccountIdentity>;
  listUsers(credential: string, after?: string): Promise<DirectoryPage<UserAccess>>;
  getUser(credential: string, userId: string): Promise<UserAccess>;
  readPasswordResetCompletion(credential: string, request: PasswordResetRequestIdentity): Promise<UserPasswordResetCompletion>;
  listPolicies(credential: string, platform: boolean): Promise<PolicyDirectory>;
  // TENANT default-version read only. A list permission is not a read grant;
  // the server independently authorizes the exact Policy target.
  readPolicy?(credential: string, accountId: string, policyId: string): Promise<AccountPolicyDetail>;
  createPolicy?(credential: string, accountId: string,
    command: { displayName: string; document: AccountPolicyDocument; requestId: string }): Promise<AccountPolicyDetail>;
  listPolicyVersions?(credential: string, accountId: string, policyId: string): Promise<AccountPolicyVersionDirectory>;
  readPolicyVersion?(credential: string, accountId: string, policyId: string, versionId: string): Promise<AccountPolicyDetail>;
  createPolicyVersion?(credential: string, accountId: string, policyId: string,
    command: { document: AccountPolicyDocument; resourceVersion: number; expectedDefaultVersionId: string; requestId: string }): Promise<AccountPolicyDetail>;
  setDefaultPolicyVersion?(credential: string, accountId: string, policyId: string,
    command: { versionId: string; resourceVersion: number; requestId: string }): Promise<AccountPolicyDetail>;
  retirePolicyVersion?(credential: string, accountId: string, policyId: string, versionId: string,
    command: { resourceVersion: number; expectedDefaultVersionId: string; requestId: string }): Promise<AccountPolicyDetail>;
  // Complete current product declarations under the caller's existing policy
  // list permission. There is deliberately no account or revision selector.
  listAuthorizationProfiles(credential: string): Promise<AuthorizationProfileDirectory>;
  // Platform-published inputs for a future product-owned consent flow. This
  // list contains no Account authorization or workload binding state.
  listServiceRoleTemplates?(credential: string): Promise<ServiceRoleTemplateDirectory>;
  // accountId is a local response-scope assertion and is never sent as a selector.
  listServiceLinkedRoles?(credential: string, accountId: string, after?: string): Promise<ServiceLinkedRoleDirectory>;
  getServiceLinkedRole?(credential: string, accountId: string, roleId: string, after?: string): Promise<ServiceLinkedRoleAccess>;
  listAccounts(credential: string, after?: string): Promise<DirectoryPage<AccountAccess>>;
  // accountId is a local response-scope check, never an HTTP authority selector.
  // Callers retain the same explicit requestId/input for an uncertain outcome.
  listGroups(credential: string, accountId: string, after?: string): Promise<DirectoryPage<GroupAccess>>;
  getGroup(credential: string, accountId: string, groupId: string): Promise<GroupAccess>;
  createGroup(credential: string, accountId: string, command: {
    name: string;
    description?: string;
    requestId: string;
  }): Promise<Group>;
  updateGroup(credential: string, accountId: string, groupId: string, command: {
    name: string;
    description?: string;
    resourceVersion: number;
    requestId: string;
  }): Promise<Group>;
  deleteGroup(credential: string, accountId: string, groupId: string, command: {
    resourceVersion: number;
    requestId: string;
  }): Promise<GroupDeletion>;
  listGroupMemberships(credential: string, accountId: string, groupId: string, after?: string): Promise<GroupMembershipPage>;
  createGroupMembership(credential: string, accountId: string, groupId: string, command: {
    userId: string;
    requestId: string;
  }): Promise<GroupMembership>;
  removeGroupMembership(credential: string, accountId: string, groupId: string, membershipId: string, command: {
    resourceVersion: number;
    requestId: string;
  }): Promise<GroupMembership>;
  createGroupPolicyAttachment(credential: string, accountId: string, groupId: string, command: {
    policyId: string;
    policyResourceVersion: number;
    requestId: string;
  }): Promise<GroupPolicyAttachment>;
  revokePolicyAttachment(credential: string, attachmentId: string, command: {
    resourceVersion: number;
    requestId: string;
  }): Promise<PolicyAttachmentRevocation>;
  // Reads one immutable command receipt. Only requestId is sent; all other
  // fields are local response-binding expectations, never authority selectors.
  readUserPolicyAttachmentChange?(credential: string, expectation: UserPolicyAttachmentChangeExpectation): Promise<UserPolicyAttachmentChange>;
  execute(credential: string, command: AccountCommand): Promise<void>;
}
