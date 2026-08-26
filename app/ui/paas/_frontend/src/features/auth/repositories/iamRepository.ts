import type { SessionSummary } from "../domain/session";

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
