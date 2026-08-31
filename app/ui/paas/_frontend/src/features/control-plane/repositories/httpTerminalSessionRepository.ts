import { HttpProblem, requestJSON } from "@/infrastructure/http/jsonRequest";
import type {
  TerminalServerError,
  TerminalSession,
  TerminalSessionOutcome,
  TerminalSessionState,
  TerminalSize
} from "../domain/terminalSessions";
import type {
  TerminalConnection,
  TerminalConnectionHandlers,
  TerminalSessionRepository
} from "./terminalSessionRepository";

type UnknownRecord = Record<string, unknown>;

const apiVersion = "paas.matrix.xiak.com/v1";
const terminalSubprotocol = "matrix.terminal.v1";
const maximumFrameBytes = 64 * 1024;
const idPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const instanceIDPattern = /^instance-[0-9a-f]{32}$/;
const sessionIDPattern = /^terminal-session-[0-9a-f]{32}$/;
const timestampPattern = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z$/;
const states = new Set<TerminalSessionState>(["PENDING", "CONNECTING", "ACTIVE", "ENDED"]);
const outcomes = new Set<TerminalSessionOutcome>([
  "COMPLETED", "UNSUPPORTED", "EXPIRED", "DISCONNECTED", "REVOKED", "REPLACED", "FAILED"
]);
const errors = new Set<TerminalServerError>(["UNSUPPORTED", "UNAVAILABLE", "FAILED"]);

function invalid(name: string): Error {
  return new Error(`INVALID_${name.toUpperCase().replaceAll(/[^A-Z0-9]+/g, "_")}_RESPONSE`);
}

function record(value: unknown, name: string): UnknownRecord {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw invalid(name);
  return value as UnknownRecord;
}

function closed(value: unknown, name: string, keys: readonly string[]): UnknownRecord {
  const wire = record(value, name);
  const allowed = new Set(keys);
  if (Object.keys(wire).some((key) => !allowed.has(key))) throw invalid(name);
  return wire;
}

function text(value: unknown, name: string): string {
  if (typeof value !== "string" || value.length === 0) throw invalid(name);
  return value;
}

function id(value: unknown, name: string): string {
  const result = text(value, name);
  if (!idPattern.test(result)) throw invalid(name);
  return result;
}

function timestamp(value: unknown, name: string): string {
  const result = text(value, name);
  if (!timestampPattern.test(result) || !Number.isFinite(Date.parse(result))) throw invalid(name);
  return result;
}

function optionalTimestamp(wire: UnknownRecord, key: string, name: string): string | null {
  if (!Object.hasOwn(wire, key) || wire[key] === undefined) return null;
  return timestamp(wire[key], name);
}

function integer(value: unknown, name: string, minimum: number, maximum: number): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw invalid(name);
  }
  return value;
}

function terminalSize(value: unknown): TerminalSize {
  const wire = closed(value, "terminal size", ["columns", "rows"]);
  return {
    columns: integer(wire.columns, "terminal columns", 2, 512),
    rows: integer(wire.rows, "terminal rows", 2, 256)
  };
}

function terminalSession(value: unknown, expectedTenantId: string): TerminalSession {
  const wire = closed(value, "terminal session", [
    "apiVersion", "kind", "id", "scope", "deploymentId", "generation",
    "applicationRevisionId", "instanceId", "size", "state", "outcome",
    "createdAt", "connectBefore", "expiresAt", "connectedAt", "endedAt"
  ]);
  if (wire.apiVersion !== apiVersion || wire.kind !== "TerminalSession") throw invalid("terminal session");
  const sessionId = text(wire.id, "terminal session id");
  const instanceId = text(wire.instanceId, "terminal instance id");
  if (!sessionIDPattern.test(sessionId) || !instanceIDPattern.test(instanceId)) throw invalid("terminal session binding");
  const scope = closed(wire.scope, "terminal session scope", ["kind", "tenantId"]);
  if (scope.kind !== "TENANT" || id(scope.tenantId, "terminal tenant") !== expectedTenantId) {
    throw invalid("terminal session scope");
  }
  if (!states.has(wire.state as TerminalSessionState)) throw invalid("terminal session state");
  const state = wire.state as TerminalSessionState;
  const outcome = Object.hasOwn(wire, "outcome") && wire.outcome !== undefined
    ? wire.outcome as TerminalSessionOutcome
    : null;
  if ((outcome !== null && !outcomes.has(outcome)) || (state === "ENDED") !== (outcome !== null)) {
    throw invalid("terminal session outcome");
  }
  const createdAt = timestamp(wire.createdAt, "terminal created at");
  const connectBefore = timestamp(wire.connectBefore, "terminal connect before");
  const expiresAt = timestamp(wire.expiresAt, "terminal expires at");
  const connectedAt = optionalTimestamp(wire, "connectedAt", "terminal connected at");
  const endedAt = optionalTimestamp(wire, "endedAt", "terminal ended at");
  const createdMillis = Date.parse(createdAt);
  const connectMillis = Date.parse(connectBefore);
  const expiresMillis = Date.parse(expiresAt);
  if (connectMillis <= createdMillis || connectMillis > expiresMillis || expiresMillis <= createdMillis ||
      connectMillis - createdMillis > 30_000 || expiresMillis - createdMillis > 15 * 60_000 ||
      (connectedAt !== null && (Date.parse(connectedAt) < createdMillis || Date.parse(connectedAt) > expiresMillis)) ||
      (endedAt !== null && (Date.parse(endedAt) < createdMillis ||
        (connectedAt !== null && Date.parse(endedAt) < Date.parse(connectedAt))))) {
    throw invalid("terminal session time boundary");
  }
  if ((state === "PENDING" || state === "CONNECTING") && (connectedAt !== null || endedAt !== null) ||
      state === "ACTIVE" && (connectedAt === null || endedAt !== null) ||
      state === "ENDED" && endedAt === null) {
    throw invalid("terminal session lifecycle");
  }
  return {
    id: sessionId,
    tenantId: expectedTenantId,
    deploymentId: id(wire.deploymentId, "terminal deployment"),
    generation: integer(wire.generation, "terminal generation", 1, Number.MAX_SAFE_INTEGER),
    applicationRevisionId: id(wire.applicationRevisionId, "terminal application revision"),
    instanceId,
    size: terminalSize(wire.size),
    state,
    outcome,
    createdAt,
    connectBefore,
    expiresAt,
    connectedAt,
    endedAt
  };
}

function websocketURL(sessionId: string): string {
  if (typeof window === "undefined" || (window.location.protocol !== "http:" && window.location.protocol !== "https:")) {
    throw new Error("TERMINAL_WEBSOCKET_UNAVAILABLE");
  }
  const result = new URL(
    `/api/paas/v1/terminal-sessions/${encodeURIComponent(sessionId)}/connect`,
    window.location.origin
  );
  result.protocol = result.protocol === "https:" ? "wss:" : "ws:";
  return result.toString();
}

function terminalControl(value: unknown):
  | { type: "READY" }
  | { type: "EXIT"; exitCode: number }
  | { type: "ERROR"; error: TerminalServerError } {
  const wire = record(value, "terminal control");
  if (wire.type === "READY" && Object.keys(wire).length === 1) return { type: "READY" };
  if (wire.type === "EXIT" && Object.keys(wire).length === 2) {
    return { type: "EXIT", exitCode: integer(wire.exitCode, "terminal exit code", -2147483648, 2147483647) };
  }
  if (wire.type === "ERROR" && Object.keys(wire).length === 2 && errors.has(wire.error as TerminalServerError)) {
    return { type: "ERROR", error: wire.error as TerminalServerError };
  }
  throw invalid("terminal control");
}

class BrowserTerminalConnection implements TerminalConnection {
  readonly #handlers = new Set<TerminalConnectionHandlers>();
  readonly #socket: WebSocket;
  #ready = false;
  #terminal = false;

  constructor(sessionId: string) {
    this.#socket = new WebSocket(websocketURL(sessionId), terminalSubprotocol);
    this.#socket.binaryType = "arraybuffer";
    this.#socket.addEventListener("open", () => {
      if (this.#socket.protocol !== terminalSubprotocol) this.#protocolFailure();
    });
    this.#socket.addEventListener("message", (event) => this.#receive(event));
    this.#socket.addEventListener("close", () => {
      this.#terminal = true;
      this.#broadcast((handlers) => handlers.closed?.());
    });
  }

  subscribe(handlers: TerminalConnectionHandlers): () => void {
    this.#handlers.add(handlers);
    return () => this.#handlers.delete(handlers);
  }

  sendInput(value: Uint8Array): void {
    if (!this.#ready || this.#terminal || value.byteLength === 0 || value.byteLength > maximumFrameBytes) {
      throw new Error("TERMINAL_INPUT_NOT_ACCEPTED");
    }
    this.#socket.send(value);
  }

  resize(size: TerminalSize): void {
    terminalSize(size);
    this.#sendControl({ type: "RESIZE", size });
  }

  closeInput(): void {
    this.#sendControl({ type: "CLOSE" });
  }

  close(): void {
    if (this.#terminal) return;
    this.#terminal = true;
    this.#socket.close(1000, "terminal closed");
  }

  #sendControl(value: { type: "RESIZE"; size: TerminalSize } | { type: "CLOSE" }): void {
    if (!this.#ready || this.#terminal) throw new Error("TERMINAL_CONTROL_NOT_ACCEPTED");
    this.#socket.send(JSON.stringify(value));
  }

  #receive(event: MessageEvent): void {
    if (this.#terminal) return;
    if (typeof event.data === "string") {
      try {
        if (new TextEncoder().encode(event.data).byteLength > 4096) throw invalid("terminal control");
        const control = terminalControl(JSON.parse(event.data) as unknown);
        if (control.type === "READY") {
          if (this.#ready) throw invalid("terminal ready");
          this.#ready = true;
          this.#broadcast((handlers) => handlers.ready?.());
          return;
        }
        if (!this.#ready) throw invalid("terminal control order");
        this.#terminal = true;
        if (control.type === "EXIT") {
          this.#broadcast((handlers) => handlers.exit?.(control.exitCode));
        } else {
          this.#broadcast((handlers) => handlers.error?.(control.error));
        }
        this.#socket.close(1000, "terminal ended");
        return;
      } catch {
        this.#protocolFailure();
        return;
      }
    }
    if (!this.#ready || !(event.data instanceof ArrayBuffer) ||
        event.data.byteLength === 0 || event.data.byteLength > maximumFrameBytes) {
      this.#protocolFailure();
      return;
    }
    const output = new Uint8Array(event.data.slice(0));
    this.#broadcast((handlers) => handlers.output?.(output));
  }

  #protocolFailure(): void {
    if (this.#terminal) return;
    this.#terminal = true;
    this.#broadcast((handlers) => handlers.error?.("FAILED"));
    this.#socket.close(1002, "invalid terminal protocol");
  }

  #broadcast(deliver: (handlers: TerminalConnectionHandlers) => void): void {
    for (const handlers of this.#handlers) deliver(handlers);
  }
}

async function closeSession(
  credential: string,
  sessionId: string,
  signal?: AbortSignal
): Promise<void> {
  const response = await fetch(`/api/paas/v1/terminal-sessions/${encodeURIComponent(sessionId)}`, {
    method: "DELETE",
    cache: "no-store",
    credentials: "same-origin",
    headers: { Accept: "application/json", Authorization: `Bearer ${credential}` },
    signal
  });
  if (response.status === 204) return;
  let code = "PLATFORM_REQUEST_REJECTED";
  try {
    const body = await response.json() as unknown;
    if (typeof body === "object" && body !== null && "code" in body && typeof body.code === "string") {
      code = body.code;
    }
  } catch {
    code = "INVALID_PLATFORM_RESPONSE";
  }
  throw new HttpProblem(response.status, code);
}

export const httpTerminalSessionRepository: TerminalSessionRepository = {
  async create(credential, tenantId, deploymentId, instanceId, size, idempotencyKey, signal) {
    id(tenantId, "terminal tenant");
    id(deploymentId, "terminal deployment");
    if (!instanceIDPattern.test(instanceId)) throw invalid("terminal instance");
    terminalSize(size);
    if (!idPattern.test(idempotencyKey)) throw invalid("terminal idempotency key");
    const value = await requestJSON<unknown>(
      `/api/paas/v1/deployments/${encodeURIComponent(deploymentId)}/terminal-sessions`,
      {
        method: "POST",
        credentials: "same-origin",
        headers: {
          Authorization: `Bearer ${credential}`,
          "Content-Type": "application/json",
          "Idempotency-Key": idempotencyKey
        },
        body: JSON.stringify({ instanceId, size }),
        signal
      }
    );
    return terminalSession(value, tenantId);
  },

  connect(sessionId) {
    if (!sessionIDPattern.test(sessionId)) throw invalid("terminal session id");
    return new BrowserTerminalConnection(sessionId);
  },

  async close(credential, tenantId, sessionId, signal) {
    id(tenantId, "terminal tenant");
    if (!sessionIDPattern.test(sessionId)) throw invalid("terminal session id");
    await closeSession(credential, sessionId, signal);
  }
};
