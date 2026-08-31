import { cleanup, fireEvent, render } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { idleTerminalConsoleState } from "../application/ControlPlaneProvider";
import type { ConsoleContentScene } from "../scenes/consoleScene";
import { ConsoleContentRenderer } from "./ConsoleContentRenderer";

const scene: Extract<ConsoleContentScene, { kind: "deployments" }> = {
  kind: "deployments",
  selectedDeploymentId: "deployment-alpha",
  truncated: false,
  deployments: [{
    id: "deployment-alpha",
    name: "database-alpha",
    generation: 2,
    revisionId: "revision-alpha-v2",
    desiredState: "RUNNING",
    phase: "READY",
    status: "success",
    componentSummary: "database × 1",
    readiness: "1/1 组件就绪",
    observedAt: "2026年8月30日 16:01",
    selected: true
  }, {
    id: "deployment-beta",
    name: "database-beta",
    generation: 1,
    revisionId: "revision-beta-v1",
    desiredState: "RUNNING",
    phase: "APPLYING",
    status: "info",
    componentSummary: "database × 1",
    readiness: "0/1 组件就绪",
    observedAt: "2026年8月30日 16:00",
    selected: false
  }],
  runtime: {
    state: "AVAILABLE",
    stateLabel: "采样有效",
    status: "success",
    generation: 2,
    revisionId: "revision-alpha-v2",
    executionTargetId: "node-a",
    observedAt: "2026年8月30日 16:01",
    validUntil: "2026年8月30日 16:01",
    resources: {
      state: "AVAILABLE",
      stateLabel: "资源采样有效",
      status: "success",
      observedAt: "2026年8月30日 16:01",
      validUntil: "2026年8月30日 16:01"
    },
    instances: [{
      id: "instance-0123456789abcdef0123456789abcdef",
      componentName: "database",
      state: "RUNNING",
      stateLabel: "运行中",
      health: "HEALTHY",
      healthLabel: "健康",
      status: "success",
      exitCode: "—",
      terminalAvailable: true,
      resources: {
        cpu: { state: "AVAILABLE", stateLabel: "有效", status: "success", value: "0.25 核 / 上限 500m", detail: "1 秒采样窗口" },
        memory: { state: "AVAILABLE", stateLabel: "有效", status: "success", value: "256 MiB / 512 MiB", detail: "已使用 50%" },
        network: { state: "AVAILABLE", stateLabel: "有效", status: "success", value: "接收 1 KiB · 发送 2 KiB", detail: "错误 0 · 丢包 0" },
        blockIo: { state: "AVAILABLE", stateLabel: "有效", status: "success", value: "读 4 KiB · 写 8 KiB", detail: "读操作 4 · 写操作 8" },
        storage: { state: "STALE", stateLabel: "已过期", status: "warning", value: "可写层 16 KiB · 镜像独占 50 MiB", detail: "来源时间独立于快速采样" }
      }
    }]
  }
};

afterEach(cleanup);

describe("ConsoleContentRenderer deployment inventory", () => {
  it("selects by opaque Deployment identity and opens only the opaque running instance", () => {
    const select = vi.fn();
    const openTerminal = vi.fn().mockResolvedValue(true);
    const screen = render(
      <ConsoleContentRenderer
        closeTerminal={vi.fn().mockResolvedValue(undefined)}
        connectTerminal={() => null}
        onOpenTerminal={openTerminal}
        onSelectDeployment={select}
        scene={scene}
        terminal={idleTerminalConsoleState}
      />
    );

    expect(screen.getByText("instance-0123456789abcdef0123456789abcdef")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: /database-beta/ }));
    expect(select).toHaveBeenCalledWith("deployment-beta");
    fireEvent.click(screen.getByRole("button", { name: /database instance-.*打开终端/ }));
    expect(openTerminal).toHaveBeenCalledWith(
      "deployment-alpha",
      "instance-0123456789abcdef0123456789abcdef",
      { columns: 120, rows: 32 }
    );
    expect(screen.getByLabelText("database 资源使用")).toBeTruthy();
    expect(screen.container.textContent).toContain("0.25 核 / 上限 500m");
    expect(screen.container.textContent).toContain("资源采样有效");
    expect(screen.container.textContent).not.toContain("docker.sock");
    expect(screen.container.textContent).not.toContain("containerId");
  });
});
