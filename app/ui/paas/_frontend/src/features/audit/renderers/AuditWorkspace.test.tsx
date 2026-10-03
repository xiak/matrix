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
    expect(within(table).getAllByRole("columnheader").map((cell) => cell.textContent)).toEqual(["事件", "操作者", "目标资源", "结果"]);
    expect(within(table).getByRole("button", { name: "audit.records.read" })).toBeTruthy();
    expect(within(table).getByText("用户密钥 key-audit-preview")).toBeTruthy();
    expect(screen.getByText(/已接受不等于异步操作完成/)).toBeTruthy();
    expect(screen.queryByRole("searchbox")).toBeNull();
    expect(screen.queryByLabelText("开始时间")).toBeNull();
    expect(screen.getByRole("button", { name: "查询条件" }).getAttribute("aria-expanded")).toBe("false");
    expect(screen.getByText(/当前租户：org-xiak/)).toBeTruthy();

    await user.click(screen.getByRole("button", { name: "下一页" }));
    await waitFor(() => expect(screen.getByText("第 2 页 · 2 条记录")).toBeTruthy());
    expect(within(screen.getByRole("table", { name: "审计记录" })).getAllByRole("row")).toHaveLength(3);
  });

  it("opens record evidence and chain verification in the content region", async () => {
    const user = userEvent.setup();
    render(<LocaleProvider><AuditWorkspace preview /></LocaleProvider>);
    const table = await screen.findByRole("table", { name: "审计记录" });
    const opener = within(table).getByRole("button", { name: "audit.records.read" });

    await user.click(opener);
    expect(screen.getByRole("heading", { level: 1, name: /审计记录 #114/ })).toBeTruthy();
    expect(screen.getByText("哈希链证据")).toBeTruthy();
    expect(screen.getByText(/来源服务记录该事件已按自身语义完成/)).toBeTruthy();
    const source = screen.getByText("事件来源").closest("div")!;
    expect(within(source).getByText("AUDIT")).toBeTruthy();
    expect(within(source).getByText("audit.records.read")).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "返回审计记录" }));
    expect(await screen.findByRole("table", { name: "审计记录" })).toBeTruthy();
    expect(document.activeElement).toBe(within(screen.getByRole("table", { name: "审计记录" })).getByRole("button", { name: "audit.records.read" }));

    await user.click(screen.getByRole("button", { name: "校验完整性" }));
    expect(screen.getByRole("heading", { level: 1, name: "审计链完整性校验" })).toBeTruthy();
    expect(screen.getByText(/显式读取操作/)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "开始校验" }));
    expect(await screen.findByText("已校验到当前链尾")).toBeTruthy();
    expect(screen.getByText("1–114")).toBeTruthy();
  });

  it("explains every audit result without turning evidence into a business outcome", async () => {
    const user = userEvent.setup();
    render(<LocaleProvider><AuditWorkspace preview /></LocaleProvider>);
    await screen.findByRole("table", { name: "审计记录" });
    const cases = [
      { action: "audit.records.read", occurrence: 0, meaning: /不证明相关异步业务的最终结果/ },
      { action: "iam.authorization.decided", occurrence: 0, meaning: /不证明产品已执行请求/ },
      { action: "paas.deployment.created", occurrence: 0, meaning: /不证明 Operation 已完成/ },
      { action: "iam.authorization.decided", occurrence: 1, meaning: /不证明目标资源存在与否/ }
    ] as const;
    for (const item of cases) {
      const table = screen.getByRole("table", { name: "审计记录" });
      await user.click(within(table).getAllByRole("button", { name: item.action })[item.occurrence]!);
      expect(screen.getByText(item.meaning)).toBeTruthy();
      await user.click(screen.getByRole("button", { name: "返回审计记录" }));
      await screen.findByRole("table", { name: "审计记录" });
    }
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

  it("collects complete role-session lineage before querying", async () => {
    const user = userEvent.setup();
    render(<LocaleProvider><AuditWorkspace preview /></LocaleProvider>);
    await screen.findByRole("table", { name: "审计记录" });

    await user.click(screen.getByRole("button", { name: "查询条件" }));
    await user.click(screen.getByRole("combobox", { name: "操作者类型" }));
    await user.click(screen.getByRole("option", { name: "角色会话" }));
    expect(screen.getByLabelText("角色会话 ID")).toBeTruthy();
    expect(screen.getByRole("combobox", { name: "角色来源类型" })).toBeTruthy();

    await user.click(screen.getByLabelText("操作者 ID"));
    await user.paste("role-deployer");
    await user.click(screen.getByRole("button", { name: "查询" }));
    expect((await screen.findByRole("alert")).textContent).toContain("请检查时间范围、操作者 ID 和分页参数");

    await user.click(screen.getByLabelText("角色会话 ID"));
    await user.paste("role-session-preview");
    await user.click(screen.getByLabelText("角色来源 ID"));
    await user.paste("principal-developer");
    await user.click(screen.getByRole("button", { name: "查询" }));
    await waitFor(() => expect(screen.getByText("第 1 页 · 1 条记录")).toBeTruthy());
    expect(screen.getByText("role-deployer")).toBeTruthy();
    expect(screen.queryByLabelText("角色会话 ID")).toBeNull();
    const filterTrigger = screen.getByRole("button", { name: /查询条件.*已应用 1 项/ });
    expect(filterTrigger.getAttribute("aria-expanded")).toBe("false");
    expect(document.activeElement).toBe(filterTrigger);
  });
});
