import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { LocaleProvider } from "@/i18n/LocaleProvider";
import type { AccountSecuritySettingsClient, AccountSecuritySettingsLoad } from "../application/AccountAccessProvider";
import { LiveAccountSecuritySettings } from "./LiveAccountSecuritySettings";

const personalSecurity = vi.hoisted(() => ({ current: null as null | { authenticatorState(): Promise<unknown> } }));
vi.mock("../application/PersonalSecurityProvider", () => ({ usePersonalSecurity: () => personalSecurity.current }));

const currentSettings = {
  accountId: "account-one", resourceVersion: 4, mfa: { requiredForUsers: false },
  password: { minimumLength: 15, requireLowercase: false, requireUppercase: false, requireDigit: false, requireSymbol: false, historyCount: 1, maxAgeDays: 0, expiryMode: "CHANGE_PASSWORD" as const },
  session: { idleTimeoutMinutes: 30 }, accessKeyNetwork: { allowedSourceCidrs: [] }, updatedAt: "2026-09-11T08:00:00Z"
};

function client(result: AccountSecuritySettingsLoad = { status: "ready", settings: currentSettings }, update?: AccountSecuritySettingsClient["update"]): AccountSecuritySettingsClient {
  return { accountId: "account-one", principalId: "user-one", sessionId: "session-one", sessionRevision: 1, update, load: vi.fn().mockResolvedValue(result) };
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}

afterEach(() => { cleanup(); vi.clearAllMocks(); personalSecurity.current = null; sessionStorage.clear(); });

describe("live account security settings", () => {
  it("keeps the heading stable, reads the explicit false rule, and never offers preview editing", async () => {
    const source = client();
    render(<LocaleProvider><LiveAccountSecuritySettings client={source} /></LocaleProvider>);
    expect(screen.getByRole("heading", { name: "账号安全规则" })).toBeTruthy();
    expect(await screen.findByText("用户可选")).toBeTruthy();
    expect(screen.getByText("account-one")).toBeTruthy();
    expect(screen.getByText(/不能证明本人已绑定验证器/)).toBeTruthy();
    expect(screen.getByText(/至少 15 个码点/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: /编辑|保存/ })).toBeNull();
    expect(source.load).toHaveBeenCalledTimes(1);
  });

  it("edits only the account AccessKey network in content, freezes the full current settings, and starts dedicated verification", async () => {
    const begin = vi.fn().mockResolvedValue({});
    personalSecurity.current = { authenticatorState: vi.fn().mockResolvedValue({ enrollmentState: "BOUND", factorRevision: 7, factorId: "factor-one" }) };
    const source = client(undefined, {
      intent: null,
      begin,
      retryStepUp: vi.fn(), inspectStepUp: vi.fn(), verifyStepUp: vi.fn(), apply: vi.fn(), inspectChange: vi.fn(), clear: vi.fn()
    });
    const user = userEvent.setup();
    render(<LocaleProvider><LiveAccountSecuritySettings client={source} /></LocaleProvider>);
    await user.click(await screen.findByRole("button", { name: "编辑账号级来源" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    const field = screen.getByRole("textbox", { name: "允许的来源 CIDR" });
    await user.clear(field);
    await user.type(field, "2001:db8::/32\n10.0.0.0/8");
    await user.click(screen.getByRole("button", { name: "审阅变更" }));
    expect(screen.getByText(/MFA、密码与会话设置按当前版本完整冻结/)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "继续身份验证" }));
    await waitFor(() => expect(begin).toHaveBeenCalledWith(currentSettings, { allowedSourceCidrs: ["10.0.0.0/8", "2001:db8::/32"] }, 7));
    expect(personalSecurity.current.authenticatorState).toHaveBeenCalledTimes(1);
  });

  it("keeps verification secrets in component memory and clears them after submission", async () => {
    const verifyStepUp = vi.fn().mockResolvedValue({});
    const settingsIntent = {
      expectedResourceVersion: currentSettings.resourceVersion,
      mfa: currentSettings.mfa,
      password: currentSettings.password,
      session: currentSettings.session,
      accessKeyNetwork: { allowedSourceCidrs: ["10.0.0.0/8"] }
    };
    const source = client(undefined, {
      intent: {
        accountId: "account-one", actorId: "user-one", requestId: `ui-account-security-settings-${"a".repeat(32)}`,
        expectedFactorRevision: 7, state: "PENDING", settings: settingsIntent,
        stepUp: {
          id: "step-up-one", requestId: `ui-account-security-settings-${"a".repeat(32)}`, operation: "SECURITY_SETTINGS_UPDATE",
          expectedFactorRevision: 7, securitySettings: settingsIntent, state: "PENDING",
          createdAt: "2026-09-11T08:00:00Z", expiresAt: "2026-09-11T08:05:00Z", provedAt: null, consumedAt: null
        }
      },
      begin: vi.fn(), retryStepUp: vi.fn(), inspectStepUp: vi.fn(), verifyStepUp, apply: vi.fn(), inspectChange: vi.fn(), clear: vi.fn()
    });
    const user = userEvent.setup();
    render(<LocaleProvider><LiveAccountSecuritySettings client={source} /></LocaleProvider>);
    await user.type(await screen.findByLabelText("当前密码"), "Never-store-this-49!");
    await user.type(screen.getByLabelText("动态验证码"), "123456");
    await user.click(screen.getByRole("button", { name: "验证身份" }));
    await waitFor(() => expect(verifyStepUp).toHaveBeenCalledWith(expect.objectContaining({ password: "Never-store-this-49!", code: "123456" })));
    expect((screen.getByLabelText("当前密码") as HTMLInputElement).value).toBe("");
    expect((screen.getByLabelText("动态验证码") as HTMLInputElement).value).toBe("");
    expect(JSON.stringify(sessionStorage)).not.toContain("Never-store-this-49!");
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
    await act(async () => { oldRead.resolve({ status: "ready", settings: { ...currentSettings, mfa: { requiredForUsers: true } } }); });
    expect(screen.queryByText("account-one")).toBeNull();
    expect(screen.queryByText("已要求")).toBeNull();
    await act(async () => { newRead.resolve({ status: "ready", settings: { ...currentSettings, accountId: "account-two", resourceVersion: 5, updatedAt: "2026-09-12T08:00:00Z" } }); });
    expect(screen.getByText("account-two")).toBeTruthy();
    expect(screen.getByText("用户可选")).toBeTruthy();
  });

  it("retains verified read-only data during a same-session refresh, then replaces it with the new result", async () => {
    const firstClient = client();
    const nextRead = deferred<AccountSecuritySettingsLoad>();
    const nextClient = { ...client(), load: vi.fn(() => nextRead.promise) };
    const view = render(<LocaleProvider><LiveAccountSecuritySettings client={firstClient} /></LocaleProvider>);
    expect(await screen.findByText("用户可选")).toBeTruthy();
    view.rerender(<LocaleProvider><LiveAccountSecuritySettings client={nextClient} /></LocaleProvider>);
    expect(screen.getByText("用户可选")).toBeTruthy();
    expect(screen.getByText(/正在更新当前账号规则/)).toBeTruthy();
    expect(screen.queryByText("正在读取当前账号规则…")).toBeNull();
    expect(screen.getByText("用户可选").closest('[aria-busy="true"]')).toBeTruthy();
    await act(async () => { nextRead.resolve({ status: "ready", settings: { ...currentSettings,
      resourceVersion: 5, mfa: { requiredForUsers: true }, updatedAt: "2026-09-12T08:00:00Z" } }); });
    expect(screen.getByText("已要求")).toBeTruthy();
    expect(screen.queryByText("用户可选")).toBeNull();
    expect(screen.queryByText(/正在更新当前账号规则/)).toBeNull();
    expect(nextClient.load).toHaveBeenCalledOnce();
  });

  it("removes retained data when a same-session refresh reports loss of read access", async () => {
    const refresh = deferred<AccountSecuritySettingsLoad>();
    const view = render(<LocaleProvider><LiveAccountSecuritySettings client={client()} /></LocaleProvider>);
    expect(await screen.findByText("用户可选")).toBeTruthy();
    view.rerender(<LocaleProvider><LiveAccountSecuritySettings client={{ ...client(), load: () => refresh.promise }} /></LocaleProvider>);
    expect(screen.getByText("用户可选")).toBeTruthy();
    await act(async () => { refresh.resolve({ status: "forbidden" }); });
    expect(screen.getByText(/没有查看账号安全规则的权限/)).toBeTruthy();
    expect(screen.queryByText("用户可选")).toBeNull();
  });

  it("retries only the failed data region without replacing the page", async () => {
    const source = client();
    const read = vi.fn().mockResolvedValueOnce({ status: "unavailable" }).mockResolvedValueOnce({ status: "ready", settings: {
      ...currentSettings, mfa: { requiredForUsers: true }
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
        requireDigit: true, requireSymbol: false, historyCount: 3, maxAgeDays: 90, expiryMode: "ADMIN_RESET" },
      session: { idleTimeoutMinutes: 20 }, accessKeyNetwork: { allowedSourceCidrs: ["198.51.100.0/24"] }, updatedAt: "2026-09-11T08:00:00Z"
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
