import { cleanup, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it } from "vitest";
import type { OperationScene } from "../scenes/consoleScene";
import { LocaleProvider, useLocalePreference } from "@/i18n/LocaleProvider";
import { buildConsoleScene } from "../scenes/buildConsoleScene";
import { previewExperienceSnapshot } from "../repositories/previewExperienceSnapshot";
import { ExperienceContentRenderer } from "./ExperienceContentRenderer";

const operations: OperationScene[] = [
  {
    id: "op-scale-primary",
    action: "扩容实例",
    target: "订单主库",
    productName: "云数据库 PostgreSQL",
    actor: "preview-admin",
    state: "RUNNING",
    status: "info",
    progress: 64,
    startedAt: "2026-09-08T09:05:00Z"
  },
  {
    id: "op-release-edge",
    action: "发布应用",
    target: "edge-worker-01",
    productName: "应用平台",
    actor: "deploy-bot",
    state: "SUCCEEDED",
    status: "success",
    progress: 100,
    startedAt: "2026-09-08T08:49:00Z"
  },
  {
    id: "op-backup-failed",
    action: "创建备份",
    target: "分析数据库",
    productName: "云数据库 PostgreSQL",
    actor: "operator-lin",
    state: "FAILED",
    status: "danger",
    progress: 31,
    startedAt: "2026-09-08T08:15:00Z"
  }
];

function LanguageSwitch() {
  const { locale, setLocale } = useLocalePreference();
  return <button onClick={() => setLocale(locale === "en" ? "zh-CN" : "en")}>Switch language</button>;
}

afterEach(() => { cleanup(); localStorage.clear(); });

describe("ExperienceContentRenderer operation center", () => {
  it("localizes state, search and guidance without dropping the selected lifecycle filter", async () => {
    localStorage.setItem("matrix.locale", "en");
    const user = userEvent.setup();
    render(<LocaleProvider><LanguageSwitch /><ExperienceContentRenderer scene={{ kind: "operations", operations }} /></LocaleProvider>);
    await user.click(screen.getByRole("button", { name: "Filters" }));
    await user.click(screen.getByRole("combobox", { name: "Filter operation status" }));
    await user.click(screen.getByRole("option", { name: "Failed" }));
    expect(screen.getByText("1 result")).toBeTruthy();
    const summary = screen.getByLabelText(/创建备份.*Failed.*view details/);
    await user.click(summary);
    expect(within(summary.closest("details")!).getByText(/Check the target resource state/)).toBeTruthy();
    expect(within(summary).getByText(/UTC/)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Switch language" }));
    expect(screen.getByRole("combobox", { name: "筛选操作状态" }).textContent).toBe("失败");
    expect(screen.getByText("1 个结果")).toBeTruthy();
    expect(screen.getByLabelText(/创建备份.*失败.*查看详情/).closest("details")?.open).toBe(true);
  });

  it("presents numeric monitoring values through locale formatting and keeps source names", () => {
    localStorage.setItem("matrix.locale", "en");
    const scene = buildConsoleScene("observability", { offerings: [], regions: [], entitlements: [], installations: [] }, previewExperienceSnapshot).content;
    if (scene.kind !== "observability") throw new Error("Expected monitoring scene");
    render(<LocaleProvider><ExperienceContentRenderer scene={scene} /></LocaleProvider>);
    expect(screen.getByRole("heading", { name: "Service health" })).toBeTruthy();
    expect(screen.getByText("99.94%")).toBeTruthy();
    expect(screen.getByText("99.98%")).toBeTruthy();
    expect(screen.getByText("386 ms")).toBeTruthy();
    expect(screen.getByText("1.84%")).toBeTruthy();
    expect(screen.getByRole("img", { name: "支付服务 health trend" })).toBeTruthy();
  });

  it("derives environment summaries from the returned runs instead of claiming an absent environment", () => {
    localStorage.setItem("matrix.locale", "en");
    const scene = buildConsoleScene("devops", { offerings: [], regions: [], entitlements: [], installations: [] }, previewExperienceSnapshot, "environments").content;
    if (scene.kind !== "devops") throw new Error("Expected delivery scene");
    render(<LocaleProvider><ExperienceContentRenderer scene={scene} /></LocaleProvider>);
    const environments = screen.getByRole("region", { name: "Delivery environments" });
    expect(within(environments).getAllByText("2 recent runs")).toHaveLength(2);
    expect(within(environments).getByText("Deploying")).toBeTruthy();
    expect(within(environments).getByText("Needs attention")).toBeTruthy();
    expect(screen.queryByText("预发环境")).toBeNull();
  });

  it("filters operations by searchable context and status", async () => {
    const user = userEvent.setup();
    render(<LocaleProvider><ExperienceContentRenderer scene={{ kind: "operations", operations }} /></LocaleProvider>);

    await user.type(screen.getByLabelText("搜索操作"), "deploy-bot");
    expect(screen.getByText("发布应用")).toBeTruthy();
    expect(screen.queryByText("扩容实例")).toBeNull();
    expect(screen.getByText("1 个结果")).toBeTruthy();

    await user.clear(screen.getByLabelText("搜索操作"));
    await user.click(screen.getByRole("button", { name: "筛选" }));
    await user.click(screen.getByRole("combobox", { name: "筛选操作状态" }));
    await user.click(screen.getByRole("option", { name: "失败" }));
    expect(screen.getByText("创建备份")).toBeTruthy();
    expect(screen.queryByText("发布应用")).toBeNull();
    expect(screen.getByText("1 个结果")).toBeTruthy();
  });

  it("discloses structured operation guidance with a native summary control", async () => {
    const user = userEvent.setup();
    render(<LocaleProvider><ExperienceContentRenderer scene={{ kind: "operations", operations }} /></LocaleProvider>);

    const summary = screen.getByLabelText(/扩容实例.*订单主库.*执行中.*查看详情/);
    const disclosure = summary.closest("details");
    expect(disclosure?.open).toBe(false);

    await user.click(summary);

    expect(disclosure?.open).toBe(true);
    expect(within(disclosure as HTMLElement).getByText("操作标识")).toBeTruthy();
    expect(within(disclosure as HTMLElement).getByText("op-scale-primary")).toBeTruthy();
    expect(within(disclosure as HTMLElement).getByText("任务仍在执行；刷新后可查看控制面返回的最新进度。")).toBeTruthy();
  });
});
