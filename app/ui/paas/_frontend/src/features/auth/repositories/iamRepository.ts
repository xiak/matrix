import type { SessionSummary } from "../domain/session";
import type { AccountAccess, AccountCommand, AccountIdentity, DirectoryPage, Group, GroupAccess, GroupDeletion, GroupMembership,
  GroupMembershipPage, GroupPolicyAttachment, PolicyAttachmentRevocation, PolicyDirectory, UserAccess, UserPermissionBoundary } from "../domain/accounts";

export type LoginCommand = {
  loginName: string;
  password: string;
};

export type LoginResult = {
  session: SessionSummary;
  credential: string;
  mustChangePassword: boolean;
};

export type ChangePasswordCommand = {
  currentPassword: string;
  newPassword: string;
  revokeOtherSessions?: boolean;
};

export interface IamRepository {
  login(command: LoginCommand): Promise<LoginResult>;
  changePassword(
    credential: string,
    command: ChangePasswordCommand
  ): Promise<void>;
  logout(credential: string): Promise<void>;
}

export interface AccountRepository {
  currentIdentity(credential: string): Promise<AccountIdentity>;
  getUserPermissionBoundary(credential: string, accountId: string, userId: string): Promise<UserPermissionBoundary>;
  listUsers(credential: string, after?: string): Promise<DirectoryPage<UserAccess>>;
  listPolicies(credential: string, platform: boolean): Promise<PolicyDirectory>;
  listAccounts(credential: string, after?: string): Promise<DirectoryPage<AccountAccess>>;
  // accountId is a local response-scope check, never an HTTP authority selector.
  // Callers retain the same explicit requestId/input for an uncertain outcome.
  listGroups(credential: string, accountId: string, after?: string): Promise<DirectoryPage<GroupAccess>>;
  getGroup(credential: string, accountId: string, groupId: string): Promise<GroupAccess>;
  createGroup(credential: string, accountId: string, command: { name: string; description?: string; requestId: string }): Promise<Group>;
  updateGroup(credential: string, accountId: string, groupId: string, command: { name: string; description?: string; resourceVersion: number; requestId: string }): Promise<Group>;
  deleteGroup(credential: string, accountId: string, groupId: string, command: { resourceVersion: number; requestId: string }): Promise<GroupDeletion>;
  listGroupMemberships(credential: string, accountId: string, groupId: string, after?: string): Promise<GroupMembershipPage>;
  createGroupMembership(credential: string, accountId: string, groupId: string, command: { userId: string; requestId: string }): Promise<GroupMembership>;
  removeGroupMembership(credential: string, accountId: string, groupId: string, membershipId: string, command: { resourceVersion: number; requestId: string }): Promise<GroupMembership>;
  createGroupPolicyAttachment(credential: string, accountId: string, groupId: string, command: { policyId: string; policyResourceVersion: number; requestId: string }): Promise<GroupPolicyAttachment>;
  revokePolicyAttachment(credential: string, attachmentId: string, command: { resourceVersion: number; requestId: string }): Promise<PolicyAttachmentRevocation>;
  execute(credential: string, command: AccountCommand): Promise<void>;
}
