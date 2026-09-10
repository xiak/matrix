import type { SessionSummary } from "../domain/session";
import type { Account, AccountCommand, AccountIdentity, AccountUser, DirectoryPage } from "../domain/accounts";
import type { AccessWorkspace, AccessWorkspaceCommand } from "../domain/accessWorkspace";
import type { UserBatchCommand } from "../domain/userBatch";

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
  // Atomic preview capability; no fallback fan-out into live single-user APIs.
  executeUserBatch?(credential: string, command: UserBatchCommand): Promise<{ workspace: AccessWorkspace }>;
  // Absent on the HTTP adapter until the server owns these capabilities.
  workspace?: {
    read(credential: string): Promise<AccessWorkspace>;
    execute(credential: string, command: AccessWorkspaceCommand): Promise<{ workspace: AccessWorkspace; issuedKey?: { id: string; secret: string } }>;
  };
  currentIdentity(credential: string): Promise<AccountIdentity>;
  listUsers(credential: string, after?: string): Promise<DirectoryPage<AccountUser>>;
  listAccounts(credential: string, after?: string): Promise<DirectoryPage<Account>>;
  execute(credential: string, command: AccountCommand): Promise<void>;
}
