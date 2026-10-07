import { cleanup, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { LocaleProvider } from "@/i18n/LocaleProvider";
import { afterEach, describe, expect, it } from "vitest";
import type { ConsoleMessageScene } from "../scenes/consoleScene";
import { useConsoleUiStore } from "../application/consoleUiStore";
import { NotificationCenter } from "./NotificationCenter";
import { MessageCenterRenderer } from "./MessageCenterRenderer";

const messages: ConsoleMessageScene[] = [
  { id: "alert-payment", category: "alert", title: "支付服务错误率升高", description: "支付服务 · SRE 值班组", status: "danger", createdAt: "2026-09-08T09:07:00Z", href: "/console/observability/alerts/" },
  { id: "operation-deploy", category: "operation", title: "部署服务", description: "订单 API · 应用托管", status: "danger", result: "FAILED", createdAt: "2026-09-08T09:06:00Z", href: "/console/operations/" },
  { id: "platform-maintenance", category: "platform", title: "平台维护通知", description: "这是一条 MOCK 平台维护通知，未安排实际维护。", status: "info", createdAt: "2026-09-08T08:00:00Z" }
];

function NotificationCenterHarness() {
  const [open, setOpen] = useState(false);
  return <NotificationCenter activeOperationCount={1} messages={messages} onOpenChange={setOpen} open={open} />;
}

afterEach(() => { cleanup(); localStorage.clear(); useConsoleUiStore.getState().resetSessionUi(); });

describe("Message center", () => {
  it("provides a translated empty state and a full inbox destination, not an alert-only destination", () => {
    localStorage.setItem("matrix.locale", "en");
    render(<LocaleProvider><NotificationCenter activeOperationCount={0} messages={[]} onOpenChange={() => {}} open /></LocaleProvider>);
    expect(screen.getByRole("dialog", { name: "Message center" })).toBeTruthy();
    expect(screen.getByRole("heading", { name: "No matching messages" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Close message center, 0 unread messages" })).toBeTruthy();
    expect(screen.getByRole("link", { name: "View all messages" }).getAttribute("href")).toMatch(/^\/console\/messages\/?$/);
    expect(screen.queryByRole("link", { name: /in progress/ })).toBeNull();
  });

  it("opens on the category controls without marking messages read and restores the bell on Escape", async () => {
    const user = userEvent.setup();
    render(<LocaleProvider><NotificationCenterHarness /></LocaleProvider>);
    const trigger = screen.getByRole("button", { name: "打开消息中心，3 条未读消息" });
    await user.click(trigger);
    expect(trigger.getAttribute("aria-controls")).toBe("global-notification-center");
    expect(document.activeElement).toBe(screen.getByRole("tab", { name: "全部" }));
    expect(useConsoleUiStore.getState().readMessageIds).toEqual([]);
    expect(screen.queryByText(messages[0]!.description)).toBeNull();
    expect(screen.queryByRole("link", { name: "前往告警页面", hidden: true })).toBeNull();
    await user.click(screen.getByLabelText("支付服务错误率升高，未读，查看消息"));
    expect(screen.getByText(messages[0]!.description)).toBeTruthy();
    await user.click(screen.getByLabelText("支付服务错误率升高，已读，查看消息"));
    expect(screen.queryByText(messages[0]!.description)).toBeNull();
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog", { name: "消息中心" })).toBeNull();
    expect(document.activeElement).toBe(trigger);
  });

  it("filters categories and counts unread messages independently from running tasks and alert state", async () => {
    const user = userEvent.setup();
    render(<LocaleProvider><NotificationCenterHarness /></LocaleProvider>);
    await user.click(screen.getByRole("button", { name: "打开消息中心，3 条未读消息" }));
    await user.click(screen.getByRole("tab", { name: "平台" }));
    expect(screen.queryByLabelText(/支付服务错误率升高.*查看消息/)).toBeNull();
    await user.click(screen.getByLabelText("平台维护通知，未读，查看消息"));
    expect(screen.getByText(/未安排实际维护/)).toBeTruthy();
    expect(screen.getByRole("button", { name: "关闭消息中心，2 条未读消息" })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "全部已读" }));
    expect(screen.getByRole("button", { name: "关闭消息中心，0 条未读消息" })).toBeTruthy();
    expect(screen.getByRole("link", { name: /1 个任务进行中/ }).getAttribute("href")).toMatch(/\/console\/operations\/?$/);
    await user.click(screen.getByRole("tab", { name: "告警" }));
    await user.click(screen.getByLabelText("支付服务错误率升高，已读，查看消息"));
    expect(screen.getByText(/已读仅改变消息状态/)).toBeTruthy();
    expect(screen.getByRole("link", { name: "前往告警页面" }).getAttribute("href")).toMatch(/\/observability\/alerts\/?$/);
    expect(messages[0]?.status).toBe("danger");
  });

  it("keeps an opened unread message visible while reading, and moves focus safely when it is dismissed", async () => {
    const user = userEvent.setup();
    render(<LocaleProvider><MessageCenterRenderer scene={{ kind: "messages", messages, preview: true }} /></LocaleProvider>);
    const filter = screen.getByRole("radio", { name: "未读" });
    await user.click(filter);
    await user.click(screen.getByLabelText("平台维护通知，未读，查看消息"));
    const opened = screen.getByLabelText("平台维护通知，已读，查看消息");
    expect(opened.closest("details")?.open).toBe(true);
    expect(screen.getByText(/未安排实际维护/)).toBeTruthy();
    await user.click(opened);
    expect(screen.queryByLabelText("平台维护通知，已读，查看消息")).toBeNull();
    expect(document.activeElement).toBe(filter);
    await user.click(screen.getByRole("radio", { name: "已读" }));
    expect(screen.getByLabelText("平台维护通知，已读，查看消息")).toBeTruthy();
    await user.type(screen.getByRole("searchbox", { name: "搜索消息" }), "missing");
    expect(screen.getByRole("heading", { name: "暂无符合条件的消息" })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "清空搜索" }));
    expect(document.activeElement).toBe(screen.getByRole("searchbox", { name: "搜索消息" }));
  });

  it("shares read state between the popup and full inbox, with no durable storage or live-data fiction", async () => {
    const user = userEvent.setup();
    const view = render(<LocaleProvider><NotificationCenterHarness /></LocaleProvider>);
    await user.click(screen.getByRole("button", { name: "打开消息中心，3 条未读消息" }));
    await user.click(screen.getByRole("button", { name: "全部已读" }));
    view.rerender(<LocaleProvider><MessageCenterRenderer scene={{ kind: "messages", messages, preview: true }} /></LocaleProvider>);
    expect(screen.getByText("0 条未读")).toBeTruthy();
    expect(within(screen.getByRole("list", { name: "消息列表" })).getAllByRole("listitem")).toHaveLength(3);
    expect(localStorage.length).toBe(0);
    view.rerender(<LocaleProvider><MessageCenterRenderer scene={{ kind: "messages", messages: [], preview: false }} /></LocaleProvider>);
    expect(screen.getByRole("heading", { name: "消息服务尚未接入" })).toBeTruthy();
    expect(screen.queryByRole("tablist")).toBeNull();
  });
});
