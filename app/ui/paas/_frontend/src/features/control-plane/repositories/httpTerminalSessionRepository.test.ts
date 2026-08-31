import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { httpTerminalSessionRepository } from "./httpTerminalSessionRepository";

const tenantId = "tenant-a";
const deploymentId = "deployment-a";
const instanceId = "instance-0123456789abcdef0123456789abcdef";
const sessionId = "terminal-session-0123456789abcdef0123456789abcdef";

function session(overrides: Record<string, unknown> = {}) {
  return {
    apiVersion: "paas.matrix.xiak.com/v1",
    kind: "TerminalSession",
    id: sessionId,
    scope: { kind: "TENANT", tenantId },
    deploymentId,
    generation: 2,
    applicationRevisionId: "revision-a",
    instanceId,
    size: { columns: 120, rows: 32 },
    state: "PENDING",
    createdAt: "2026-08-31T10:00:00.000000Z",
    connectBefore: "2026-08-31T10:00:30.000000Z",
    expiresAt: "2026-08-31T10:15:00.000000Z",
    ...overrides
  };
}

class FakeWebSocket {
  static latest: FakeWebSocket | null = null;
  readonly url: string;
  readonly requestedProtocols: string | string[] | undefined;
  protocol = "matrix.terminal.v1";
  binaryType: BinaryType = "blob";
  sent: unknown[] = [];
  closed: { code?: number; reason?: string } | null = null;
  readonly listeners = new Map<string, Array<(event: Event | MessageEvent) => void>>();

  constructor(url: string | URL, protocols?: string | string[]) {
    this.url = String(url);
    this.requestedProtocols = protocols;
    FakeWebSocket.latest = this;
  }

  addEventListener(type: string, listener: EventListenerOrEventListenerObject): void {
    const deliver = typeof listener === "function"
      ? listener as (event: Event | MessageEvent) => void
      : (event: Event | MessageEvent) => listener.handleEvent(event);
    this.listeners.set(type, [...this.listeners.get(type) ?? [], deliver]);
  }

  send(value: unknown): void {
    this.sent.push(value);
  }

  close(code?: number, reason?: string): void {
    this.closed = { code, reason };
  }

  emit(type: string, event: Event | MessageEvent = new Event(type)): void {
    for (const deliver of this.listeners.get(type) ?? []) deliver(event);
  }
}

beforeEach(() => {
  FakeWebSocket.latest = null;
  vi.stubGlobal("WebSocket", FakeWebSocket);
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("httpTerminalSessionRepository", () => {
  it("creates and closes an exact tenant session without exposing the ticket", async () => {
    const fetch = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify(session()), {
        status: 201,
        headers: { "Content-Type": "application/json" }
      }))
      .mockResolvedValueOnce(new Response(null, { status: 204 }));
    vi.stubGlobal("fetch", fetch);

    const created = await httpTerminalSessionRepository.create(
      "memory-only-user-session",
      tenantId,
      deploymentId,
      instanceId,
      { columns: 120, rows: 32 },
      "terminal-session-0123456789abcdef0123456789abcdef"
    );
    expect(created).toMatchObject({ id: sessionId, tenantId, deploymentId, instanceId, state: "PENDING" });
    expect(fetch).toHaveBeenNthCalledWith(1, "/api/paas/v1/deployments/deployment-a/terminal-sessions", expect.objectContaining({
      method: "POST",
      credentials: "same-origin",
      body: JSON.stringify({ instanceId, size: { columns: 120, rows: 32 } })
    }));
    const createHeaders = fetch.mock.calls[0]![1]!.headers as Record<string, string>;
    expect(createHeaders).toEqual(expect.objectContaining({
      Authorization: "Bearer memory-only-user-session",
      "Content-Type": "application/json",
      "Idempotency-Key": "terminal-session-0123456789abcdef0123456789abcdef"
    }));
    expect(JSON.stringify(fetch.mock.calls[0])).not.toContain("matrix_terminal_ticket");

    await httpTerminalSessionRepository.close("memory-only-user-session", tenantId, sessionId);
    expect(fetch).toHaveBeenNthCalledWith(2, `/api/paas/v1/terminal-sessions/${sessionId}`, expect.objectContaining({
      method: "DELETE",
      credentials: "same-origin"
    }));
  });

  it("rejects a cross-tenant or ambiguous lifecycle response", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify(session({
      scope: { kind: "TENANT", tenantId: "tenant-b" },
      state: "ENDED"
    })), { status: 201, headers: { "Content-Type": "application/json" } })));
    await expect(httpTerminalSessionRepository.create(
      "credential", tenantId, deploymentId, instanceId, { columns: 80, rows: 24 },
      "terminal-session-0123456789abcdef0123456789abcdef"
    )).rejects.toThrow("INVALID_TERMINAL_SESSION_SCOPE_RESPONSE");
  });

  it("uses the exact same-origin WebSocket protocol and bridges only closed frames", () => {
    const connection = httpTerminalSessionRepository.connect(sessionId);
    const ready = vi.fn();
    const output = vi.fn();
    const exit = vi.fn();
    connection.subscribe({ ready, output, exit });
    const socket = FakeWebSocket.latest!;

    expect(socket.url).toBe(`ws://localhost:3000/api/paas/v1/terminal-sessions/${sessionId}/connect`);
    expect(socket.requestedProtocols).toBe("matrix.terminal.v1");
    expect(socket.url).not.toContain("credential");
    expect(() => connection.sendInput(new Uint8Array([1]))).toThrow("TERMINAL_INPUT_NOT_ACCEPTED");

    socket.emit("open");
    socket.emit("message", new MessageEvent("message", { data: JSON.stringify({ type: "READY" }) }));
    expect(ready).toHaveBeenCalledTimes(1);
    connection.sendInput(new Uint8Array([0x6c, 0x73, 0x0a]));
    connection.resize({ columns: 100, rows: 30 });
    connection.closeInput();
    expect(socket.sent[0]).toEqual(new Uint8Array([0x6c, 0x73, 0x0a]));
    expect(socket.sent[1]).toBe(JSON.stringify({ type: "RESIZE", size: { columns: 100, rows: 30 } }));
    expect(socket.sent[2]).toBe(JSON.stringify({ type: "CLOSE" }));

    const bytes = new Uint8Array([0x6f, 0x6b, 0x0a]);
    socket.emit("message", new MessageEvent("message", { data: bytes.buffer }));
    expect(output).toHaveBeenCalledWith(bytes);
    socket.emit("message", new MessageEvent("message", { data: JSON.stringify({ type: "EXIT", exitCode: 0 }) }));
    expect(exit).toHaveBeenCalledWith(0);
  });

  it("fails closed on an unknown server frame", () => {
    const connection = httpTerminalSessionRepository.connect(sessionId);
    const error = vi.fn();
    connection.subscribe({ error });
    const socket = FakeWebSocket.latest!;
    socket.emit("open");
    socket.emit("message", new MessageEvent("message", { data: JSON.stringify({ type: "READY", providerId: "private" }) }));
    expect(error).toHaveBeenCalledWith("FAILED");
    expect(socket.closed).toEqual({ code: 1002, reason: "invalid terminal protocol" });
  });
});
