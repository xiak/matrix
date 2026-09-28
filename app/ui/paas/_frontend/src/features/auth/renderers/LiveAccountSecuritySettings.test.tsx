import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { LocaleProvider } from "@/i18n/LocaleProvider";
import type { AccountSecuritySettingsClient, AccountSecuritySettingsLoad } from "../application/AccountAccessProvider";
import { LiveAccountSecuritySettings } from "./LiveAccountSecuritySettings";

function client(result: AccountSecuritySettingsLoad = { status: "ready", settings: {
  accountId: "account-one", resourceVersion: 4, mfa: { requiredForUsers: false }, password: null,
  updatedAt: "2026-09-11T08:00:00Z"
} }): AccountSecuritySettingsClient {
  return { accountId: "account-one", principalId: "user-one", sessionId: "session-one", load: vi.fn().mockResolvedValue(result) };
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}

afterEach(() => { cleanup(); vi.clearAllMocks(); });

describe("live account security settings", () => {
  it("keeps the heading stable, reads the explicit false rule, and never offers preview editing", async () => {
    const source = client();
    render(<LocaleProvider><LiveAccountSecuritySettings client={source} /></LocaleProvider>);
    expect(screen.getByRole("heading", { name: "账号安全规则" })).toBeTruthy();
    expect(await screen.findByText("用户可选")).toBeTruthy();
    expect(screen.getByText("account-one")).toBeTruthy();
    expect(screen.getByText(/不能证明任何人已绑定验证器/)).toBeTruthy();
    expect(screen.getByText(/尚未返回密码规则/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: /编辑|保存/ })).toBeNull();
    expect(source.load).toHaveBeenCalledTimes(1);
  });

  it("shows 403 as read denial without treating it as logout or mock state", async () => {
    render(<LocaleProvider><LiveAccountSecuritySettings client={client({ status: "forbidden" })} /></LocaleProvider>);
    expect(await screen.findByText(/没有查看账号安全规则的权限/)).toBeTruthy();
    expect(screen.queryByText("当前规则")).toBeNull();
    expect(screen.queryByText("用户可选")).toBeNull();
    expect(screen.queryByText("MOCK")).toBeNull();
  });

  it("does not display a late prior-session response after the client changes", async () => {
    const oldRead = deferred<AccountSecuritySettingsLoad>();
    const newRead = deferred<AccountSecuritySettingsLoad>();
    const oldClient = { ...client(), load: vi.fn(() => oldRead.promise) };
    const newClient = { ...client(), accountId: "account-two", principalId: "user-two", sessionId: "session-two", load: vi.fn(() => newRead.promise) };
    const view = render(<LocaleProvider><LiveAccountSecuritySettings client={oldClient} /></LocaleProvider>);
    view.rerender(<LocaleProvider><LiveAccountSecuritySettings client={newClient} /></LocaleProvider>);
    await act(async () => { oldRead.resolve({ status: "ready", settings: { accountId: "account-one", resourceVersion: 4, mfa: { requiredForUsers: true }, password: null, updatedAt: "2026-09-11T08:00:00Z" } }); });
    expect(screen.queryByText("account-one")).toBeNull();
    expect(screen.queryByText("已要求")).toBeNull();
    await act(async () => { newRead.resolve({ status: "ready", settings: { accountId: "account-two", resourceVersion: 5, mfa: { requiredForUsers: false }, password: null, updatedAt: "2026-09-12T08:00:00Z" } }); });
    expect(screen.getByText("account-two")).toBeTruthy();
    expect(screen.getByText("用户可选")).toBeTruthy();
  });

  it("retries only the failed data region without replacing the page", async () => {
    const source = client();
    const read = vi.fn().mockResolvedValueOnce({ status: "unavailable" }).mockResolvedValueOnce({ status: "ready", settings: {
      accountId: "account-one", resourceVersion: 4, mfa: { requiredForUsers: true }, password: null, updatedAt: "2026-09-11T08:00:00Z"
    } });
    source.load = read;
    const user = userEvent.setup();
    render(<LocaleProvider><LiveAccountSecuritySettings client={source} /></LocaleProvider>);
    await user.click(await screen.findByRole("button", { name: "重新读取" }));
    await waitFor(() => expect(screen.getByText("已要求")).toBeTruthy());
    expect(read).toHaveBeenCalledTimes(2);
    expect(screen.getByRole("heading", { name: "账号安全规则" })).toBeTruthy();
  });

  it("shows current account password rules as read-only facts, distinct from MOCK samples and personal requirements", async () => {
    const source = client({ status: "ready", settings: {
      accountId: "account-one", resourceVersion: 7, mfa: { requiredForUsers: true },
      password: { minimumLength: 21, requireLowercase: true, requireUppercase: false,
        requireDigit: true, requireSymbol: false, historyCount: 3 }, updatedAt: "2026-09-11T08:00:00Z"
    } });
    render(<LocaleProvider><LiveAccountSecuritySettings client={source} /></LocaleProvider>);
    expect(await screen.findByText(/至少 21 个码点/)).toBeTruthy();
    expect(screen.getByText("要求小写字母、要求十进制数字")).toBeTruthy();
    expect(screen.getByText(/当前密码 \+ 最近 3 次已知历史/)).toBeTruthy();
    expect(screen.getByText(/不一定是受保护身份或本人/)).toBeTruthy();
    expect(screen.queryByText(/拟定默认/)).toBeNull();
    expect(screen.queryByRole("button", { name: /编辑|保存/ })).toBeNull();
  });
});
