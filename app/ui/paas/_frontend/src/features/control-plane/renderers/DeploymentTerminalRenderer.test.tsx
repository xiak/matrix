import { act, cleanup, fireEvent, render, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { TerminalConsoleState } from "../application/ControlPlaneProvider";
import type { TerminalConnection, TerminalConnectionHandlers } from "../repositories/terminalSessionRepository";
import { DeploymentTerminalRenderer } from "./DeploymentTerminalRenderer";

const terminalHarness = vi.hoisted(() => ({
  instances: [] as Array<{
    writes: Array<string | Uint8Array>;
    input: ((value: string) => void) | null;
    disposed: boolean;
  }>
}));

vi.mock("@xterm/xterm", () => ({
  Terminal: class {
    cols = 100;
    rows = 30;
    readonly state = { writes: [] as Array<string | Uint8Array>, input: null as ((value: string) => void) | null, disposed: false };
    constructor() { terminalHarness.instances.push(this.state); }
    loadAddon() {}
    open() {}
    focus() {}
    write(value: string | Uint8Array) { this.state.writes.push(value); }
    onData(callback: (value: string) => void) {
      this.state.input = callback;
      return { dispose: () => { this.state.input = null; } };
    }
    dispose() { this.state.disposed = true; }
  }
}));

vi.mock("@xterm/addon-fit", () => ({
  FitAddon: class { fit() {} }
}));

class MemoryConnection implements TerminalConnection {
  readonly handlers = new Set<TerminalConnectionHandlers>();
  readonly sendInput = vi.fn();
  readonly resize = vi.fn();
  readonly closeInput = vi.fn();
  readonly close = vi.fn();

  subscribe(handlers: TerminalConnectionHandlers): () => void {
    this.handlers.add(handlers);
    return () => this.handlers.delete(handlers);
  }

  ready(): void { for (const handlers of this.handlers) handlers.ready?.(); }
  output(value: Uint8Array): void { for (const handlers of this.handlers) handlers.output?.(value); }
}

const terminal: TerminalConsoleState = {
  phase: "CONNECTING",
  deploymentId: "deployment-a",
  instanceId: "instance-0123456789abcdef0123456789abcdef",
  session: {
    id: "terminal-session-0123456789abcdef0123456789abcdef",
    tenantId: "tenant-a",
    deploymentId: "deployment-a",
    generation: 2,
    applicationRevisionId: "revision-a",
    instanceId: "instance-0123456789abcdef0123456789abcdef",
    size: { columns: 120, rows: 32 },
    state: "PENDING",
    outcome: null,
    createdAt: "2026-08-31T10:00:00.000000Z",
    connectBefore: "2026-08-31T10:00:30.000000Z",
    expiresAt: "2026-08-31T10:15:00.000000Z",
    connectedAt: null,
    endedAt: null
  },
  message: "正在连接"
};

beforeEach(() => {
  terminalHarness.instances = [];
  vi.stubGlobal("ResizeObserver", class {
    observe() {}
    disconnect() {}
  });
  vi.stubGlobal("requestAnimationFrame", (callback: FrameRequestCallback) =>
    window.setTimeout(() => callback(performance.now()), 0));
  vi.stubGlobal("cancelAnimationFrame", (id: number) => window.clearTimeout(id));
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("DeploymentTerminalRenderer", () => {
  it("fits, streams UTF-8 bytes and closes explicitly without reconnecting", async () => {
    const connection = new MemoryConnection();
    const connect = vi.fn().mockReturnValue(connection);
    const close = vi.fn().mockResolvedValue(undefined);
    const screen = render(
      <DeploymentTerminalRenderer closeTerminal={close} connectTerminal={connect} terminal={terminal} />
    );
    await waitFor(() => expect(terminalHarness.instances).toHaveLength(1));
    expect(connect).toHaveBeenCalledTimes(1);

    await act(async () => {
      connection.ready();
      connection.output(new TextEncoder().encode("ready\n"));
      await new Promise((resolve) => window.setTimeout(resolve, 1));
    });
    expect(connection.resize).toHaveBeenCalledWith({ columns: 100, rows: 30 });
    expect(terminalHarness.instances[0]!.writes.some((value) =>
      typeof value !== "string" && new TextDecoder().decode(value) === "ready\n"
    )).toBe(true);

    terminalHarness.instances[0]!.input?.("echo 你好\n");
    expect(new TextDecoder().decode(connection.sendInput.mock.calls[0]![0] as Uint8Array)).toBe("echo 你好\n");
    fireEvent.click(screen.getByRole("button", { name: "关闭终端面板" }));
    expect(close).toHaveBeenCalledTimes(1);
    expect(connect).toHaveBeenCalledTimes(1);
  });
});
