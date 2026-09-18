import type { OwnSessionPage, OwnSessionRevocation, SessionSummary } from "../domain/session";
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
  UserAccess,
  UserPermissionBoundary
} from "../domain/accounts";
import type { AccessWorkspace, AccessWorkspaceCommand } from "../domain/accessWorkspace";
import type { UserBatchCommand } from "../domain/userBatch";

export type LoginCommand = { loginName: string; password: string };
export type LoginResult = { session: SessionSummary; credential: string; mustChangePassword: boolean };
export type ChangePasswordCommand = { currentPassword: string; newPassword: string; revokeOtherSessions?: boolean };

export interface IamRepository {
  login(command: LoginCommand): Promise<LoginResult>;
  changePassword(credential: string, command: ChangePasswordCommand): Promise<void>;
  logout(credential: string): Promise<void>;
  sessions?: {
    list(credential: string, after?: string): Promise<OwnSessionPage>;
    revoke(credential: string, targetSessionId: string, requestId: string): Promise<OwnSessionRevocation>;
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
