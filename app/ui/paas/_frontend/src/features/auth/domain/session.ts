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

export type AuthenticatedSession = {
  loginName: string;
  session: SessionSummary;
};

export type LoginOutcome = "authenticated" | "password-change-required";

export type SessionPhase =
  | "anonymous"
  | "authenticating"
  | "password-change-required"
  | "changing-password"
  | "authenticated"
  | "revoking";
