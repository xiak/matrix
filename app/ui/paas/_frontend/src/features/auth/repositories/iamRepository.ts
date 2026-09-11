import type { SessionSummary } from "../domain/session";
import type { AccountAccess, AccountCommand, AccountIdentity, DirectoryPage, PolicyDirectory, UserAccess } from "../domain/accounts";

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
  listUsers(credential: string, after?: string): Promise<DirectoryPage<UserAccess>>;
  listPolicies(credential: string, platform: boolean): Promise<PolicyDirectory>;
  listAccounts(credential: string, after?: string): Promise<DirectoryPage<AccountAccess>>;
  execute(credential: string, command: AccountCommand): Promise<void>;
}
