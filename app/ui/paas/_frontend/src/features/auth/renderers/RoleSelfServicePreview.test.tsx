import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it } from "vitest";
import { LocaleProvider } from "@/i18n/LocaleProvider";
import { RoleSelfServicePreview } from "./RoleSelfServicePreview";

afterEach(cleanup);

describe("RoleSelfServicePreview", () => {
  it("keeps member discovery separate from role administration and reviews assumption inline", async () => {
    const user = userEvent.setup();
    render(<LocaleProvider><RoleSelfServicePreview /></LocaleProvider>);

    expect(screen.getByText("独立 MOCK 成员场景", { exact: false })).toBeTruthy();
    expect(screen.getByText("仅可发现并承担满足全部条件的角色")).toBeTruthy();
    expect(screen.queryByText("编辑角色")).toBeNull();
    expect(screen.queryByRole("dialog")).toBeNull();

    await user.click(screen.getByRole("button", { name: "审阅并承担 AssumeLogReviewRole" }));
    expect(screen.getByRole("heading", { name: "审阅角色会话" })).toBeTruthy();
    expect(screen.getAllByText("ux-assume-role-log-reviewer-001", { exact: false }).length).toBeGreaterThan(0);
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("creates and exits a credential-free preview identity without changing the login claim", async () => {
    const user = userEvent.setup();
    render(<LocaleProvider><RoleSelfServicePreview /></LocaleProvider>);

    await user.click(screen.getByRole("button", { name: "审阅并承担 AssumeLogReviewRole" }));
    await user.click(screen.getByRole("button", { name: "创建体验角色会话" }));

    expect(screen.getByRole("heading", { name: "体验角色身份" })).toBeTruthy();
    expect(screen.getByText("MOCK-RS-role-log-reviewer")).toBeTruthy();
    expect(screen.getByText("不会把当前 Header 登录态切换成该角色", { exact: false })).toBeTruthy();
    expect(screen.queryByRole("dialog")).toBeNull();

    await user.click(screen.getByRole("button", { name: "结束体验角色" }));
    expect(screen.getByText("结束这个体验角色？")).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "确认结束" }));
    expect(screen.getByRole("heading", { name: "可承担角色" })).toBeTruthy();
    expect(screen.queryByText("MOCK-RS-role-log-reviewer")).toBeNull();
  });

  it("does not guess why eligibility was denied and returns to current discovery", async () => {
    const user = userEvent.setup();
    render(<LocaleProvider><RoleSelfServicePreview /></LocaleProvider>);

    await user.click(screen.getByRole("combobox", { name: "体验路径" }));
    await user.click(screen.getByRole("option", { name: "资格在审阅后变化" }));
    await user.click(screen.getByRole("button", { name: "审阅并承担 AssumeLogReviewRole" }));
    await user.click(screen.getByRole("button", { name: "创建体验角色会话" }));

    expect(screen.getByText("iam.authorization.denied")).toBeTruthy();
    expect(screen.getByText("不能据此猜测", { exact: false })).toBeTruthy();
    expect(screen.queryByText("MOCK-RS-role-log-reviewer")).toBeNull();

    await user.click(screen.getByRole("button", { name: "刷新可承担角色" }));
    expect(screen.getByRole("heading", { name: "可承担角色" })).toBeTruthy();
  });

  it("does not treat a generic fresh-intent conflict as a role-detail error", async () => {
    const user = userEvent.setup();
    render(<LocaleProvider><RoleSelfServicePreview /></LocaleProvider>);

    await user.click(screen.getByRole("combobox", { name: "体验路径" }));
    await user.click(screen.getByRole("option", { name: "全新意图状态冲突" }));
    await user.click(screen.getByRole("button", { name: "审阅并承担 AssumeLogReviewRole" }));
    await user.click(screen.getByRole("button", { name: "创建体验角色会话" }));

    expect(screen.getByText("iam.state.conflict")).toBeTruthy();
    expect(screen.getByText("不专属 Role 版本过期", { exact: false })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "重新发现并审阅" }));
    expect(screen.getByRole("heading", { name: "可承担角色" })).toBeTruthy();
    expect(screen.getByText(/版本 5/)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "审阅并承担 AssumeLogReviewRole" }));
    expect(screen.getByText("ux-assume-role-log-reviewer-002", { exact: false })).toBeTruthy();
  });

  it("queries and revokes an uncertain original request before offering a new intent", async () => {
    const user = userEvent.setup();
    render(<LocaleProvider><RoleSelfServicePreview /></LocaleProvider>);

    await user.click(screen.getByRole("combobox", { name: "体验路径" }));
    await user.click(screen.getByRole("option", { name: "签发结果未知" }));
    await user.click(screen.getByRole("button", { name: "审阅并承担 AssumeLogReviewRole" }));
    await user.click(screen.getByRole("button", { name: "创建体验角色会话" }));

    expect(screen.getAllByText("ux-assume-role-log-reviewer-001", { exact: false }).length).toBeGreaterThan(0);
    expect(screen.queryByRole("button", { name: "创建新承担意图" })).toBeNull();
    expect(screen.queryByRole("heading", { name: "体验角色身份" })).toBeNull();

    await user.click(screen.getByRole("button", { name: "查询原请求" }));
    expect(screen.getByText("MOCK-RS-role-log-reviewer", { exact: false })).toBeTruthy();
    expect(screen.getByText("不会再次返回角色凭据", { exact: false })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "撤销已确认会话" }));
    expect(screen.getByRole("button", { name: "创建新承担意图" })).toBeTruthy();

    await user.click(screen.getByRole("button", { name: "创建新承担意图" }));
    expect(screen.getByText("ux-assume-role-log-reviewer-002", { exact: false })).toBeTruthy();
    expect(screen.getByRole("combobox", { name: "体验路径" }).textContent).toContain("正常完成");
  });
});
