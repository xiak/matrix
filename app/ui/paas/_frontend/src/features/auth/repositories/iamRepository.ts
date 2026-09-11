import type { SessionSummary } from "../domain/session";
import type { Account, AccountCommand, AccountIdentity, AccountUser, DirectoryPage, PolicyDirectory } from "../domain/accounts";
import type { AccessWorkspace, AccessWorkspaceCommand } from "../domain/accessWorkspace";
import type { UserBatchCommand } from "../domain/userBatch";

export type LoginCommand = { loginName: string; password: string };
export type LoginResult = { session: SessionSummary; credential: string; mustChangePassword: boolean };
export type ChangePasswordCommand = { currentPassword: string; newPassword: string; revokeOtherSessions?: boolean };

export interface IamRepository {
  login(command: LoginCommand): Promise<LoginResult>;
  changePassword(credential: string, command: ChangePasswordCommand): Promise<void>;
  logout(credential: string): Promise<void>;
}

export interface AccountRepository {
  // Explicit, isolated DEMO capabilities. The live HTTP adapter never exposes them.
  executeUserBatch?(credential: string, command: UserBatchCommand): Promise<{ workspace: AccessWorkspace }>;
  workspace?: {
    read(credential: string): Promise<AccessWorkspace>;
    execute(credential: string, command: AccessWorkspaceCommand): Promise<{ workspace: AccessWorkspace; issuedKey?: { id: string; secret: string } }>;
  };
  currentIdentity(credential: string): Promise<AccountIdentity>;
  listUsers(credential: string, after?: string): Promise<DirectoryPage<AccountUser>>;
  listPolicies(credential: string, platform: boolean): Promise<PolicyDirectory>;
  listAccounts(credential: string, after?: string): Promise<DirectoryPage<Account>>;
  execute(credential: string, command: AccountCommand): Promise<void>;
}
