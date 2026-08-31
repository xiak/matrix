"use client";

import { useEffect, useRef } from "react";
import { ShieldCheck, SquareTerminal, X } from "lucide-react";
import { Badge, Button, Typography } from "@ui/xiak";
import type {
  CloseTerminal,
  ConnectTerminal,
  TerminalConsoleState
} from "../application/ControlPlaneProvider";
import styles from "./DeploymentTerminalRenderer.module.css";

const maximumFrameBytes = 64 * 1024;
const maximumBufferedBytes = 256 * 1024;

function status(phase: TerminalConsoleState["phase"]): "neutral" | "info" | "success" | "warning" | "danger" {
  if (phase === "ACTIVE") return "success";
  if (phase === "CONNECTING" || phase === "CREATING") return "info";
  if (phase === "ENDED") return "warning";
  if (phase === "ERROR") return "danger";
  return "neutral";
}

function phaseLabel(phase: TerminalConsoleState["phase"]): string {
  const labels: Record<TerminalConsoleState["phase"], string> = {
    IDLE: "未启动",
    CREATING: "正在授权",
    CONNECTING: "正在连接",
    ACTIVE: "会话有效",
    ENDED: "会话已结束",
    ERROR: "连接失败"
  };
  return labels[phase];
}

export function DeploymentTerminalRenderer({
  closeTerminal,
  connectTerminal,
  terminal
}: {
  closeTerminal: CloseTerminal;
  connectTerminal: ConnectTerminal;
  terminal: TerminalConsoleState;
}) {
  const host = useRef<HTMLDivElement | null>(null);
  const phase = useRef(terminal.phase);
  const sessionId = terminal.session?.id ?? null;

  useEffect(() => {
    phase.current = terminal.phase;
  }, [terminal.phase]);

  useEffect(() => {
    if (!sessionId || !host.current) return;
    const connection = connectTerminal();
    if (!connection) return;

    let disposed = false;
    let ready = phase.current === "ACTIVE";
    let bufferedBytes = 0;
    let pending: Uint8Array[] = [];
    let emulator: import("@xterm/xterm").Terminal | null = null;
    let fitAddon: import("@xterm/addon-fit").FitAddon | null = null;
    let inputDisposable: { dispose(): void } | null = null;
    let resizeObserver: ResizeObserver | null = null;
    let resizeFrame = 0;
    let lastSize = "";

    const write = (value: string | Uint8Array) => {
      if (!disposed && emulator) emulator.write(value);
    };
    const fitAndResize = () => {
      if (disposed || !emulator || !fitAddon || !ready) return;
      try {
        fitAddon.fit();
        const columns = Math.max(2, Math.min(512, emulator.cols));
        const rows = Math.max(2, Math.min(256, emulator.rows));
        const key = `${columns}:${rows}`;
        if (key === lastSize) return;
        connection.resize({ columns, rows });
        lastSize = key;
      } catch {
        // A zero-sized or detached panel will be measured again by ResizeObserver.
      }
    };
    const scheduleResize = () => {
      if (resizeFrame !== 0) cancelAnimationFrame(resizeFrame);
      resizeFrame = requestAnimationFrame(() => {
        resizeFrame = 0;
        fitAndResize();
      });
    };
    const unsubscribe = connection.subscribe({
      ready: () => {
        ready = true;
        write("\r\n[Matrix] 已进入当前部署实例；会话受审计且不会自动重连。\r\n");
        scheduleResize();
      },
      output: (value) => {
        if (emulator) {
          write(value);
          return;
        }
        bufferedBytes += value.byteLength;
        if (bufferedBytes > maximumBufferedBytes) {
          connection.closeInput();
          return;
        }
        pending.push(value);
      },
      exit: (exitCode) => write(`\r\n[Matrix] 终端进程已退出（${exitCode}）。\r\n`),
      error: (code) => write(`\r\n[Matrix] 终端已结束（${code}）。\r\n`),
      closed: () => write("\r\n[Matrix] 连接已关闭。\r\n")
    });

    void Promise.all([import("@xterm/xterm"), import("@xterm/addon-fit")]).then(([xterm, fit]) => {
      if (disposed || !host.current) return;
      const theme = getComputedStyle(host.current);
      emulator = new xterm.Terminal({
        allowProposedApi: false,
        convertEol: false,
        cursorBlink: true,
        disableStdin: false,
        fontFamily: theme.getPropertyValue("--xiak-font-mono").trim(),
        fontSize: 13,
        scrollback: 2_000,
        theme: {
          background: theme.getPropertyValue("--xiak-color-terminal-bg").trim(),
          foreground: theme.getPropertyValue("--xiak-color-terminal-text").trim(),
          cursor: theme.getPropertyValue("--xiak-color-terminal-cursor").trim(),
          selectionBackground: theme.getPropertyValue("--xiak-color-terminal-selection").trim()
        }
      });
      fitAddon = new fit.FitAddon();
      emulator.loadAddon(fitAddon);
      emulator.open(host.current);
      inputDisposable = emulator.onData((value) => {
        const bytes = new TextEncoder().encode(value);
        for (let offset = 0; offset < bytes.byteLength; offset += maximumFrameBytes) {
          try {
            connection.sendInput(bytes.slice(offset, offset + maximumFrameBytes));
          } catch {
            return;
          }
        }
      });
      for (const value of pending) emulator.write(value);
      pending = [];
      bufferedBytes = 0;
      if (typeof ResizeObserver !== "undefined") {
        resizeObserver = new ResizeObserver(scheduleResize);
        resizeObserver.observe(host.current);
      }
      scheduleResize();
      emulator.focus();
    }).catch(() => {
      try { connection.closeInput(); } catch {}
    });

    return () => {
      disposed = true;
      unsubscribe();
      if (resizeFrame !== 0) cancelAnimationFrame(resizeFrame);
      resizeObserver?.disconnect();
      inputDisposable?.dispose();
      emulator?.dispose();
      pending = [];
    };
  }, [connectTerminal, sessionId]);

  if (terminal.phase === "IDLE") return null;

  return (
    <section aria-label="部署短时终端" className={styles.panel}>
      <header className={styles.header}>
        <div className={styles.identity}>
          <span className={styles.icon}><SquareTerminal aria-hidden="true" /></span>
          <span>
            <strong>短时终端</strong>
            <small>
              {terminal.instanceId ? <Typography.Code>{terminal.instanceId}</Typography.Code> : "等待目标实例"}
            </small>
          </span>
        </div>
        <div className={styles.actions}>
          <Badge status={status(terminal.phase)}>{phaseLabel(terminal.phase)}</Badge>
          <Button aria-label="关闭终端面板" onClick={() => void closeTerminal()} size="small" variant="ghost">
            <X aria-hidden="true" />关闭
          </Button>
        </div>
      </header>
      <div className={styles.securityNote}>
        <ShieldCheck aria-hidden="true" />
        <span>固定当前部署代次与容器实例；仅提供 <Typography.Code>/bin/sh</Typography.Code>，最长 15 分钟。</span>
      </div>
      {terminal.session ? <div aria-label="终端输入输出" className={styles.terminal} ref={host} /> : null}
      {terminal.message ? <p aria-live="polite" className={styles.message} role="status">{terminal.message}</p> : null}
    </section>
  );
}
