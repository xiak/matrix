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

export type LoginAuthenticationChallenge = {
  id: string;
  purpose: "LOGIN";
  nextStep: "TOTP" | "PASSWORD_CHANGE" | "RECOVER";
  expiresAt: string;
};

export type RecoveryAuthenticationChallenge = {
  id: string;
  purpose: "RECOVERY";
  nextStep: "ENROLLMENT";
  expiresAt: string;
};

export type AuthenticationChallenge = LoginAuthenticationChallenge | RecoveryAuthenticationChallenge;

export type PendingAuthenticationChallenge = {
  loginName: string;
  challenge: AuthenticationChallenge;
  challengeCredential: string;
};

export type AuthenticatorRecoveryState = "STARTED" | "COMPLETED" | "SUPERSEDED" | "EXPIRED";

export type AuthenticatorRecovery = {
  id: string;
  requestId: string;
  state: AuthenticatorRecoveryState;
  createdAt: string;
  expiresAt: string;
  completedAt?: string;
};

export type TOTPProvisioning = {
  seed: string;
  uri: string;
};

export type AuthenticatorRecoveryStart = {
  recovery: AuthenticatorRecovery & { state: "STARTED" };
  challenge: RecoveryAuthenticationChallenge;
  challengeCredential: string;
  provisioning: TOTPProvisioning;
};

export type AuthenticatorRecoveryConfirmation = {
  recovery: AuthenticatorRecovery & { state: "COMPLETED"; completedAt: string };
  nextStep: "REAUTHENTICATE";
  recoveryCodes: string[];
};

export type PendingAuthenticatorRecovery = {
  loginName: string;
  requestId: string;
  state: "STARTED" | "START_OUTCOME_UNKNOWN" | "MATERIAL_LOST" | "CONFIRM_OUTCOME_UNKNOWN" | "NOT_FOUND";
  recovery?: AuthenticatorRecovery;
  provisioning?: TOTPProvisioning;
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
  | "recovery-code-required"
  | "starting-recovery"
  | "recovery-enrollment-required"
  | "confirming-recovery"
  | "recovery-result-required"
  | "inspecting-recovery"
  | "recovery-start-unknown"
  | "recovery-confirm-unknown"
  | "challenge-password-required"
  | "changing-challenge-password"
  | "recovery-codes-required"
  | "reauthentication-required"
  | "password-change-required"
  | "changing-password"
  | "authenticated"
  | "revoking";
