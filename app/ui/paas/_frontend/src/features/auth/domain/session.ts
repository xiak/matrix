export type SessionSummary = {
  id: string;
  organizationId: string;
  principalId: string;
  status: "ACTIVE";
  issuedAt: string;
  expiresAt: string;
};

export type OwnSessionPage = {
  accountId: string;
  userId: string;
  currentSessionId: string;
  observedAt: string;
  items: SessionSummary[];
  nextCursor: string | null;
};

export type OwnSessionRevocation = {
  outcome: "APPLIED" | "EQUAL_REPLAY";
  revocation: {
    id: string;
    resourceVersion: number;
    revokedAt: string;
  };
};

export type OtherSessionsRevocation = {
  outcome: "APPLIED" | "EQUAL_REPLAY";
  accountId: string;
  userId: string;
  currentSessionId: string;
  requestId: string;
  revokedCount: number;
  completedAt: string;
};

export type AuthenticatedSession = {
  loginName: string;
  session: SessionSummary;
};

export type AuthenticationChallenge = {
  id: string;
  purpose: "LOGIN";
  nextStep: "TOTP" | "PASSWORD_CHANGE";
  expiresAt: string;
};

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
  | "challenge-password-required"
  | "changing-challenge-password"
  | "recovery-codes-required"
  | "reauthentication-required"
  | "password-change-required"
  | "changing-password"
  | "authenticated"
  | "revoking";
