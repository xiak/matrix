export type TerminalSize = {
  columns: number;
  rows: number;
};

export type TerminalSessionState = "PENDING" | "CONNECTING" | "ACTIVE" | "ENDED";

export type TerminalSessionOutcome =
  | "COMPLETED"
  | "UNSUPPORTED"
  | "EXPIRED"
  | "DISCONNECTED"
  | "REVOKED"
  | "REPLACED"
  | "FAILED";

export type TerminalSession = {
  id: string;
  tenantId: string;
  deploymentId: string;
  generation: number;
  applicationRevisionId: string;
  instanceId: string;
  size: TerminalSize;
  state: TerminalSessionState;
  outcome: TerminalSessionOutcome | null;
  createdAt: string;
  connectBefore: string;
  expiresAt: string;
  connectedAt: string | null;
  endedAt: string | null;
};

export type TerminalServerError = "UNSUPPORTED" | "UNAVAILABLE" | "FAILED";
