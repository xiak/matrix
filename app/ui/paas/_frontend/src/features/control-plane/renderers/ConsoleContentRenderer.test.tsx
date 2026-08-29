import { cleanup, fireEvent, render } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
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
    instances: [{
      id: "instance-0123456789abcdef0123456789abcdef",
      componentName: "database",
      state: "RUNNING",
      stateLabel: "运行中",
      health: "HEALTHY",
      healthLabel: "健康",
      status: "success",
      exitCode: "—"
    }]
  }
};

afterEach(cleanup);

describe("ConsoleContentRenderer deployment inventory", () => {
  it("selects by opaque Deployment identity and keeps terminal entry explicitly unavailable", () => {
    const select = vi.fn();
    const screen = render(<ConsoleContentRenderer onSelectDeployment={select} scene={scene} />);

    expect(screen.getByText("instance-0123456789abcdef0123456789abcdef")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: /database-beta/ }));
    expect(select).toHaveBeenCalledWith("deployment-beta");
    expect(screen.getByRole("button", { name: /暂不可用/ }).hasAttribute("disabled")).toBe(true);
    expect(screen.container.textContent).toContain("受审计、限时、按部署授权");
    expect(screen.container.textContent).not.toContain("docker.sock");
    expect(screen.container.textContent).not.toContain("containerId");
  });
});
