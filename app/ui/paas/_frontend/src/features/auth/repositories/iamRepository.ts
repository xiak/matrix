import type { SessionSummary } from "../domain/session";

export type LoginCommand = {
  loginName: string;
  password: string;
};

export type LoginResult = {
  session: SessionSummary;
  credential: string;
};

export interface IamRepository {
  login(command: LoginCommand): Promise<LoginResult>;
  logout(credential: string): Promise<void>;
}
