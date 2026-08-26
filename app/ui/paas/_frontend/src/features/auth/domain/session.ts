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

export type LoginOutcome = "authenticated" | "password-change-required";

export type SessionPhase =
  | "anonymous"
  | "authenticating"
  | "password-change-required"
  | "changing-password"
  | "authenticated"
  | "revoking";
