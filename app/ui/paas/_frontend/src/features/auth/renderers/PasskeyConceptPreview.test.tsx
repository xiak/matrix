import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it } from "vitest";
import { LocaleProvider } from "@/i18n/LocaleProvider";
import { PasskeyConceptPreview } from "./PasskeyConceptPreview";

afterEach(cleanup);

describe("passkey concept preview", () => {
  it("explains a browser-mediated flow without exposing registration or save actions", async () => {
    const user = userEvent.setup({ delay: null });
    render(<LocaleProvider><PasskeyConceptPreview /></LocaleProvider>);

    expect(screen.getByText("设计预览")).toBeTruthy();
    expect(screen.getByText(/不会调用浏览器 WebAuthn API/)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "查看接入流程" }));
    expect(screen.getByRole("heading", { name: "拟定接入流程" })).toBe(document.activeElement);
    expect(screen.getByText(/IAM 签发一次性注册挑战/)).toBeTruthy();
    expect(screen.getByText(/不会调用 navigator.credentials.create/)).toBeTruthy();

    await user.click(screen.getByRole("button", { name: "审阅体验边界" }));
    expect(screen.getByRole("heading", { name: "审阅通行密钥体验边界" })).toBe(document.activeElement);
    expect(screen.getByText(/取消、超时或认证器不可用时/)).toBeTruthy();
    expect(screen.getByText(/恢复、撤销、审计和兼容策略/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: /保存|注册|启用/ })).toBeNull();
  });
});
