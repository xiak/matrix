import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it } from "vitest";
import { LocaleProvider } from "@/i18n/LocaleProvider";
import { AuditWorkspace } from "./AuditWorkspace";

afterEach(() => {
  cleanup();
  localStorage.clear();
});

describe("AuditWorkspace", () => {
  it("keeps the route chrome stable while paging an opaque tenant cursor", async () => {
    const user = userEvent.setup();
    render(<LocaleProvider><AuditWorkspace preview /></LocaleProvider>);

    expect(screen.getByRole("heading", { level: 1, name: "审计记录" })).toBeTruthy();
    expect(screen.getByText("租户边界来自当前 IAM 会话")).toBeTruthy();
    const table = await screen.findByRole("table", { name: "审计记录" });
    expect(within(table).getAllByRole("row")).toHaveLength(11);
    expect(screen.queryByRole("searchbox")).toBeNull();
    expect(screen.getByText(/当前租户：org-xiak/)).toBeTruthy();

    await user.click(screen.getByRole("button", { name: "下一页" }));
    await waitFor(() => expect(screen.getByText("第 2 页 · 2 条记录")).toBeTruthy());
    expect(within(screen.getByRole("table", { name: "审计记录" })).getAllByRole("row")).toHaveLength(3);
  });

  it("opens record evidence and chain verification in the content region", async () => {
    const user = userEvent.setup();
    render(<LocaleProvider><AuditWorkspace preview /></LocaleProvider>);
    const table = await screen.findByRole("table", { name: "审计记录" });
    const opener = within(table).getAllByRole("button")[0]!;

    await user.click(opener);
    expect(screen.getByRole("heading", { level: 1, name: /审计记录 #114/ })).toBeTruthy();
    expect(screen.getByText("哈希链证据")).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "返回审计记录" }));
    expect(await screen.findByRole("table", { name: "审计记录" })).toBeTruthy();
    expect(document.activeElement).toBe(within(screen.getByRole("table", { name: "审计记录" })).getAllByRole("button")[0]);

    await user.click(screen.getByRole("button", { name: "校验完整性" }));
    expect(screen.getByRole("heading", { level: 1, name: "审计链完整性校验" })).toBeTruthy();
    expect(screen.getByText(/显式读取操作/)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "开始校验" }));
    expect(await screen.findByText("已校验到当前链尾")).toBeTruthy();
    expect(screen.getByText("1–114")).toBeTruthy();
  });

  it("rejects a preview verification range that starts after the current chain tail", async () => {
    const user = userEvent.setup();
    render(<LocaleProvider><AuditWorkspace preview /></LocaleProvider>);
    await screen.findByRole("table", { name: "审计记录" });

    await user.click(screen.getByRole("button", { name: "校验完整性" }));
    const fromSequence = screen.getByRole("spinbutton", { name: "起始序列" });
    await user.clear(fromSequence);
    await user.type(fromSequence, "115");
    await user.click(screen.getByRole("button", { name: "开始校验" }));

    expect((await screen.findByRole("alert")).textContent).toContain("审计服务返回了不符合契约的数据，页面已拒绝展示。");
    expect(screen.queryByText("已校验到当前链尾")).toBeNull();
  });
});
