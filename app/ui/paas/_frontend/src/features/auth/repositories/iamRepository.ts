import type { LoginResult } from "../domain/session";
import type { Account, AccountCommand, AccountIdentity, AccountUser, DirectoryPage } from "../domain/accounts";
import type {
  AuthenticatorState,
  EnrollmentChallengeState,
  NotificationContact,
  NotificationContactVerification,
  TOTPEnrollment,
  TOTPEnrollmentConfirmation,
  TOTPEnrollmentStart
} from "../domain/personalSecurity";

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
    inspectFirstEnrollment?(command: { challengeId: string; challengeCredential: string }): Promise<EnrollmentChallengeState>;
    startFirstContact?(command: { challengeId: string; challengeCredential: string; email: string; requestId: string }): Promise<NotificationContactVerification>;
    confirmFirstContact?(command: { challengeId: string; challengeCredential: string; verificationId: string; code: string; requestId: string }): Promise<NotificationContactVerification>;
    startFirstTOTP?(command: { challengeId: string; challengeCredential: string; requestId: string }): Promise<TOTPEnrollmentStart>;
    confirmFirstTOTP?(command: { challengeId: string; challengeCredential: string; enrollmentId: string; code: string; requestId: string }): Promise<TOTPEnrollmentConfirmation>;
  };
  changePassword(
    credential: string,
    command: ChangePasswordCommand
  ): Promise<void>;
  logout(credential: string): Promise<void>;
  personalSecurity?: {
    notificationContact(credential: string): Promise<NotificationContact>;
    startNotificationVerification(
      credential: string,
      command: { email: string; password: string; requestId: string }
    ): Promise<NotificationContactVerification>;
    notificationVerification(
      credential: string,
      verificationId: string
    ): Promise<NotificationContactVerification>;
    confirmNotificationVerification(
      credential: string,
      verificationId: string,
      command: { code: string; requestId: string }
    ): Promise<NotificationContactVerification>;
    authenticatorState(credential: string): Promise<AuthenticatorState>;
    startTOTPEnrollment(
      credential: string,
      command: { requestId: string; password: string; expectedFactorRevision: number }
    ): Promise<TOTPEnrollmentStart>;
    totpEnrollment(credential: string, enrollmentId: string): Promise<TOTPEnrollment>;
    totpEnrollmentByRequest(credential: string, requestId: string): Promise<TOTPEnrollment>;
    cancelTOTPEnrollment(credential: string, enrollmentId: string): Promise<TOTPEnrollment>;
    confirmTOTPEnrollment(
      credential: string,
      enrollmentId: string,
      command: { requestId: string; code: string }
    ): Promise<TOTPEnrollmentConfirmation>;
  };
}

export interface AccountRepository {
  currentIdentity(credential: string): Promise<AccountIdentity>;
  listUsers(credential: string, after?: string): Promise<DirectoryPage<AccountUser>>;
  listAccounts(credential: string, after?: string): Promise<DirectoryPage<Account>>;
  execute(credential: string, command: AccountCommand): Promise<void>;
}
