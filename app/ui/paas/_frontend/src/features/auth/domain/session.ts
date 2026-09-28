export type SessionSummary = {
  id: string;
  organizationId: string;
  principalId: string;
  status: "ACTIVE";
  issuedAt: string;
  expiresAt: string;
};

export type AuthenticatedSession = {
  loginName: string;
  session: SessionSummary;
};

export type LoginAuthenticationChallenge = {
  id: string;
  purpose: "LOGIN";
  nextStep: "TOTP" | "PASSWORD_CHANGE";
  expiresAt: string;
};

export type EnrollmentAuthenticationChallenge = {
  id: string;
  purpose: "ENROLLMENT";
  nextStep: "PASSWORD_CHANGE" | "ENROLLMENT";
  expiresAt: string;
};

export type AuthenticationChallenge = LoginAuthenticationChallenge | EnrollmentAuthenticationChallenge;

export type PendingAuthenticationChallenge = {
  loginName: string;
  challenge: AuthenticationChallenge;
  challengeCredential: string;
};

export type AuthenticatedLoginResult = {
  outcome: "AUTHENTICATED";
  session: SessionSummary;
  credential: string;
  mustChangePassword: boolean;
};

export type ChallengedLoginResult = {
  outcome: "CHALLENGE_REQUIRED";
  challenge: AuthenticationChallenge;
  challengeCredential: string;
};

export type LoginResult = AuthenticatedLoginResult | ChallengedLoginResult;

export type LoginOutcome = "authenticated" | "password-change-required" | "challenge-required";

export type SessionPhase =
  | "anonymous"
  | "authenticating"
  | "challenge-required"
  | "verifying-challenge"
  | "enrollment-required"
  | "challenge-password-required"
  | "changing-challenge-password"
  | "reauthentication-required"
  | "recovery-codes-required"
  | "password-change-required"
  | "changing-password"
  | "updating-password"
  | "authenticated"
  | "revoking";
