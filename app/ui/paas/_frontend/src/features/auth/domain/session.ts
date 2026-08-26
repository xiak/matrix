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

export type SessionPhase =
  | "anonymous"
  | "authenticating"
  | "authenticated"
  | "revoking";
