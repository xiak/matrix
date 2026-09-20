import type { LoginResult } from "../domain/session";
import type { Account, AccountCommand, AccountIdentity, AccountUser, DirectoryPage } from "../domain/accounts";

export type LoginCommand = {
  loginName: string;
  password: string;
};

export type ChangePasswordCommand = {
  currentPassword: string;
  newPassword: string;
  revokeOtherSessions?: boolean;
};

export type VerifyAuthenticationChallengeCommand = {
  challengeId: string;
  challengeCredential: string;
  code: string;
};

export type ChangeChallengePasswordCommand = {
  challengeId: string;
  challengeCredential: string;
  newPassword: string;
};

export interface IamRepository {
  login(command: LoginCommand): Promise<LoginResult>;
  authenticationChallenges?: {
    verify(command: VerifyAuthenticationChallengeCommand): Promise<LoginResult>;
    changePassword(command: ChangeChallengePasswordCommand): Promise<{
      nextStep: "REAUTHENTICATE";
      changedAt: string;
    }>;
  };
  changePassword(
    credential: string,
    command: ChangePasswordCommand
  ): Promise<void>;
  logout(credential: string): Promise<void>;
}

export interface AccountRepository {
  currentIdentity(credential: string): Promise<AccountIdentity>;
  listUsers(credential: string, after?: string): Promise<DirectoryPage<AccountUser>>;
  listAccounts(credential: string, after?: string): Promise<DirectoryPage<Account>>;
  execute(credential: string, command: AccountCommand): Promise<void>;
}
