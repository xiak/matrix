import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it } from "vitest";
import { LocaleProvider } from "@/i18n/LocaleProvider";
import { SessionIdleSettingsPreview } from "./SessionIdleSettingsPreview";

afterEach(cleanup);

describe("session idle settings preview", () => {
  it("keeps renewal boundaries visible and changes only the isolated preview", async () => {
    const user = userEvent.setup({ delay: null });
    render(<LocaleProvider><SessionIdleSettingsPreview /></LocaleProvider>);

    expect(screen.getByText("仅前台明确操作触发显式续期")).toBeTruthy();
    expect(screen.getByText("后台轮询、预取和普通 Bearer 请求")).toBeTruthy();
    expect(screen.getByText(/绝对到期仍是硬上限/)).toBeTruthy();

    await user.click(screen.getByRole("button", { name: "编辑空闲策略" }));
    await user.click(screen.getByRole("combobox", { name: "最长空闲时间" }));
    await user.click(screen.getByRole("option", { name: "45 分钟" }));
    await user.click(screen.getByRole("button", { name: "审阅变更" }));

    expect(screen.getByText("30 分钟 → 45 分钟")).toBeTruthy();
    expect(screen.getByText(/受保护身份仍以 30 分钟为上限/)).toBeTruthy();
    expect(screen.getByText(/真实更新会使既有登录会话和挑战失效/)).toBeTruthy();
    expect(screen.getByText(/不会停止工作负载/)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "应用到 MOCK" }));
    expect(screen.getByText(/模拟规则已更新为 45 分钟/)).toBeTruthy();
  });

  it("never exposes a live save action", () => {
    render(<LocaleProvider><SessionIdleSettingsPreview /></LocaleProvider>);
    expect(screen.queryByRole("button", { name: /保存|Save/ })).toBeNull();
    expect(screen.getByText(/不会调用 IAM、不会启动计时器/)).toBeTruthy();
  });
});
