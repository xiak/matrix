import type { LoginResult, OtherSessionsRevocation, OwnSessionPage, OwnSessionRevocation } from "../domain/session";
import type {
  AccountAccess,
  AccountCommand,
  AccountIdentity,
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
  UserAccess,
  UserPermissionBoundary
} from "../domain/accounts";
import type { AccessWorkspace, AccessWorkspaceCommand } from "../domain/accessWorkspace";
import type { AccessKeyAccess, AccessKeyCreation, AccessKeyDeletion, AccessKeyDirectory, AccessKeyStatus, AccessKeyStatusChange } from "../domain/accessKeys";
import type { AuthenticatorState, NotificationContact, NotificationContactVerification, TOTPEnrollment, TOTPEnrollmentConfirmation, TOTPEnrollmentStart } from "../domain/personalSecurity";
import type { UserBatchCommand } from "../domain/userBatch";

export type LoginCommand = { loginName: string; password: string };
export type ChangePasswordCommand = { currentPassword: string; newPassword: string; revokeOtherSessions?: boolean };
export type VerifyAuthenticationChallengeCommand = { challengeId: string; challengeCredential: string; code: string };
export type ChangeChallengePasswordCommand = { challengeId: string; challengeCredential: string; newPassword: string };

export interface IamRepository {
  login(command: LoginCommand): Promise<LoginResult>;
  authenticationChallenges?: {
    verify(command: VerifyAuthenticationChallengeCommand): Promise<LoginResult>;
    changePassword(command: ChangeChallengePasswordCommand): Promise<{ nextStep: "REAUTHENTICATE"; changedAt: string }>;
  };
  changePassword(credential: string, command: ChangePasswordCommand): Promise<void>;
  logout(credential: string): Promise<void>;
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
    authenticatorState(credential: string): Promise<AuthenticatorState>;
    startTOTPEnrollment(credential: string, command: { requestId: string; password: string; expectedFactorRevision: number }): Promise<TOTPEnrollmentStart>;
    totpEnrollment(credential: string, enrollmentId: string): Promise<TOTPEnrollment>;
    totpEnrollmentByRequest(credential: string, requestId: string): Promise<TOTPEnrollment>;
    cancelTOTPEnrollment(credential: string, enrollmentId: string): Promise<TOTPEnrollment>;
    confirmTOTPEnrollment(credential: string, enrollmentId: string, command: { requestId: string; code: string }): Promise<TOTPEnrollmentConfirmation>;
  };
}

export interface AccountRepository {
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
      requestId: string;
    }): Promise<AccessKeyCreation>;
    setStatus(credential: string, accountId: string, userId: string, accessKeyId: string, command: {
      accessKeyResourceVersion: number;
      requestId: string;
      status: AccessKeyStatus;
    }): Promise<AccessKeyStatusChange>;
    delete(credential: string, accountId: string, userId: string, accessKeyId: string, command: {
      accessKeyResourceVersion: number;
      requestId: string;
    }): Promise<AccessKeyDeletion>;
  };
  // Explicit, isolated DEMO capabilities. The live HTTP adapter never exposes them.
  executeUserBatch?(credential: string, command: UserBatchCommand): Promise<{ workspace: AccessWorkspace }>;
  workspace?: {
    read(credential: string): Promise<AccessWorkspace>;
    execute(credential: string, command: AccessWorkspaceCommand): Promise<{ workspace: AccessWorkspace; issuedKey?: { id: string; secret: string } }>;
  };
  currentIdentity(credential: string): Promise<AccountIdentity>;
  listUsers(credential: string, after?: string): Promise<DirectoryPage<UserAccess>>;
  getUser(credential: string, userId: string): Promise<UserAccess>;
  listPolicies(credential: string, platform: boolean): Promise<PolicyDirectory>;
  // Complete current product declarations under the caller's existing policy
  // list permission. There is deliberately no account or revision selector.
  listAuthorizationProfiles(credential: string): Promise<AuthorizationProfileDirectory>;
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
  execute(credential: string, command: AccountCommand): Promise<void>;
}
