import { cleanup, fireEvent, render } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { LocaleProvider } from "@/i18n/LocaleProvider";
import { SessionExpiryPreview } from "./SessionExpiryPreview";

afterEach(() => {
  cleanup();
  localStorage.clear();
});

describe("SessionExpiryPreview", () => {
  it("keeps idle and absolute expiry distinct without presenting a live timer or action", () => {
    const screen = render(<LocaleProvider><SessionExpiryPreview /></LocaleProvider>);
    expect(screen.getByRole("heading", { name: "会话到期规则预览" })).toBeTruthy();
    expect(screen.getByText("MOCK")).toBeTruthy();
    expect(screen.getByText("可以延续空闲期限")).toBeTruthy();
    expect(screen.getByText(/具体时长和服务端契约尚待 IAM 确定/)).toBeTruthy();
    expect(screen.queryByRole("button")).toBeNull();
    expect(screen.queryByRole("timer")).toBeNull();

    fireEvent.click(screen.getByRole("radio", { name: /后台轮询或普通请求/ }));
    expect(screen.getByText("不能延续空闲期限")).toBeTruthy();
    expect(screen.queryByText("可以延续空闲期限")).toBeNull();

    fireEvent.click(screen.getByRole("radio", { name: /绝对期限已到/ }));
    expect(screen.getByText("必须重新登录")).toBeTruthy();
    expect(screen.getByText(/绝对期限是硬上限/)).toBeTruthy();
  });
});
