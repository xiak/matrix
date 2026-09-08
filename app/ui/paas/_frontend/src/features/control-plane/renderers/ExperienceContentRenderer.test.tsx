import { cleanup, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it } from "vitest";
import type { OperationScene } from "../scenes/consoleScene";
import { ExperienceContentRenderer } from "./ExperienceContentRenderer";

const operations: OperationScene[] = [
  {
    id: "op-scale-primary",
    action: "扩容实例",
    target: "订单主库",
    productName: "云数据库 PostgreSQL",
    actor: "preview-admin",
    stateLabel: "执行中",
    status: "info",
    progress: 64,
    startedAt: "10 分钟前"
  },
  {
    id: "op-release-edge",
    action: "发布应用",
    target: "edge-worker-01",
    productName: "应用平台",
    actor: "deploy-bot",
    stateLabel: "已完成",
    status: "success",
    progress: 100,
    startedAt: "26 分钟前"
  },
  {
    id: "op-backup-failed",
    action: "创建备份",
    target: "分析数据库",
    productName: "云数据库 PostgreSQL",
    actor: "operator-lin",
    stateLabel: "失败",
    status: "danger",
    progress: 31,
    startedAt: "1 小时前"
  }
];

afterEach(cleanup);

describe("ExperienceContentRenderer operation center", () => {
  it("filters operations by searchable context and status", async () => {
    const user = userEvent.setup();
    render(<ExperienceContentRenderer scene={{ kind: "operations", operations }} />);

    await user.type(screen.getByLabelText("搜索操作"), "deploy-bot");
    expect(screen.getByText("发布应用")).toBeTruthy();
    expect(screen.queryByText("扩容实例")).toBeNull();
    expect(screen.getByText("1 个结果")).toBeTruthy();

    await user.clear(screen.getByLabelText("搜索操作"));
    await user.selectOptions(screen.getByLabelText("筛选操作状态"), "danger");
    expect(screen.getByText("创建备份")).toBeTruthy();
    expect(screen.queryByText("发布应用")).toBeNull();
    expect(screen.getByText("1 个结果")).toBeTruthy();
  });

  it("discloses structured operation guidance with a native summary control", async () => {
    const user = userEvent.setup();
    render(<ExperienceContentRenderer scene={{ kind: "operations", operations }} />);

    const summary = screen.getByLabelText("扩容实例：订单主库，执行中，查看详情");
    const disclosure = summary.closest("details");
    expect(disclosure?.open).toBe(false);

    await user.click(summary);

    expect(disclosure?.open).toBe(true);
    expect(within(disclosure as HTMLElement).getByText("操作标识")).toBeTruthy();
    expect(within(disclosure as HTMLElement).getByText("op-scale-primary")).toBeTruthy();
    expect(within(disclosure as HTMLElement).getByText("任务仍在执行；刷新后可查看控制面返回的最新进度。")).toBeTruthy();
  });
});
