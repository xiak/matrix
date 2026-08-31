import type {
  TerminalServerError,
  TerminalSession,
  TerminalSize
} from "../domain/terminalSessions";

export type TerminalConnectionHandlers = {
  ready?(): void;
  output?(value: Uint8Array): void;
  exit?(exitCode: number): void;
  error?(code: TerminalServerError): void;
  closed?(): void;
};

export interface TerminalConnection {
  subscribe(handlers: TerminalConnectionHandlers): () => void;
  sendInput(value: Uint8Array): void;
  resize(size: TerminalSize): void;
  closeInput(): void;
  close(): void;
}

export interface TerminalSessionRepository {
  create(
    credential: string,
    tenantId: string,
    deploymentId: string,
    instanceId: string,
    size: TerminalSize,
    idempotencyKey: string,
    signal?: AbortSignal
  ): Promise<TerminalSession>;
  connect(sessionId: string): TerminalConnection;
  close(
    credential: string,
    tenantId: string,
    sessionId: string,
    signal?: AbortSignal
  ): Promise<void>;
}
