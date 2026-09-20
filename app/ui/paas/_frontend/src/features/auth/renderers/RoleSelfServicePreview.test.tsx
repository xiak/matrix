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
    expect(screen.getByText("ux-assume-role-log-reviewer-001", { exact: false })).toBeTruthy();
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
});
