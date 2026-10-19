import { act, cleanup, fireEvent, render as renderRoot, screen, waitFor, within } from "@testing-library/react";
import type { ReactNode } from "react";
import { UnsavedChangesProvider } from "@ui/xiak";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { LocaleProvider } from "@/i18n/LocaleProvider";
import { HttpProblem } from "@/infrastructure/http/jsonRequest";
import { AccountSecuritySettingsReviewRejected, type AccountSecuritySettingsClient, type AccountSecuritySettingsLoad } from "../application/AccountAccessProvider";
import type { SecurityStepUp } from "../domain/personalSecurity";
import { LiveAccountSecuritySettings } from "./LiveAccountSecuritySettings";

const personalSecurity = vi.hoisted(() => ({ current: null as null | { authenticatorState(): Promise<unknown> } }));
vi.mock("../application/PersonalSecurityProvider", () => ({ usePersonalSecurity: () => personalSecurity.current }));

const currentSettings = {
  accountId: "account-one", resourceVersion: 4, mfa: { requiredForUsers: false },
  password: { minimumLength: 15, requireLowercase: false, requireUppercase: false, requireDigit: false, requireSymbol: false, historyCount: 1, maxAgeDays: 0, expiryMode: "CHANGE_PASSWORD" as const },
  session: { idleTimeoutMinutes: 30 }, accessKeyNetwork: { allowedSourceCidrs: [] }, updatedAt: "2026-09-11T08:00:00Z"
};

function client(result: AccountSecuritySettingsLoad = { status: "ready", settings: currentSettings }, update?: AccountSecuritySettingsClient["update"]): AccountSecuritySettingsClient {
  return { identity: "settings-view-one", accountId: "account-one", principalId: "user-one", sessionId: "session-one", sessionRevision: 1, update, load: vi.fn().mockResolvedValue(result) };
}
function render(value: ReactNode) { return renderRoot(value, { wrapper: UnsavedChangesProvider }); }
function updater(overrides: Partial<NonNullable<AccountSecuritySettingsClient["update"]>> = {}): NonNullable<AccountSecuritySettingsClient["update"]> {
  return { intent: null, begin: vi.fn(), retryStepUp: vi.fn(), inspectStepUp: vi.fn(), verifyStepUp: vi.fn(), apply: vi.fn(), inspectChange: vi.fn(), clear: vi.fn(), ...overrides };
}
function pendingUpdate(overrides: Partial<NonNullable<AccountSecuritySettingsClient["update"]>> = {}) {
  const settings = { expectedResourceVersion: currentSettings.resourceVersion, mfa: currentSettings.mfa,
    password: currentSettings.password, session: currentSettings.session, accessKeyNetwork: { allowedSourceCidrs: ["10.0.0.0/8"] } };
  const requestId = `ui-account-security-settings-${"a".repeat(32)}`;
  return updater({ intent: { accountId: "account-one", actorId: "user-one", requestId, expectedFactorRevision: 7,
    state: "PENDING", settings, stepUp: { id: "step-up-one", requestId, operation: "SECURITY_SETTINGS_UPDATE",
      expectedFactorRevision: 7, securitySettings: settings, state: "PENDING", createdAt: "2026-09-11T08:00:00Z",
      expiresAt: "2026-09-11T08:05:00Z", provedAt: null, consumedAt: null } }, ...overrides });
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
    expect(screen.getByText(/不代表当前本人已绑定验证器/)).toBeTruthy();
    expect(screen.getByText(/至少 15 个码点/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: /编辑|保存/ })).toBeNull();
    expect(source.load).toHaveBeenCalledTimes(1);
  });

  it("edits all four account rule segments in content, reviews every value and starts the original full-intent verification", async () => {
    const begin = vi.fn().mockResolvedValue({});
    personalSecurity.current = { authenticatorState: vi.fn().mockResolvedValue({ enrollmentState: "BOUND", factorRevision: 7, factorId: "factor-one" }) };
    const source = client(undefined, {
      intent: null,
      begin,
      retryStepUp: vi.fn(), inspectStepUp: vi.fn(), verifyStepUp: vi.fn(), apply: vi.fn(), inspectChange: vi.fn(), clear: vi.fn()
    });
    const user = userEvent.setup();
    render(<LocaleProvider><LiveAccountSecuritySettings client={source} /></LocaleProvider>);
    await user.click(await screen.findByRole("button", { name: "编辑账号安全规则" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    await user.click(screen.getByRole("checkbox", { name: "要求子用户使用 MFA" }));
    fireEvent.change(screen.getByRole("textbox", { name: "密码最小长度" }), { target: { value: "21" } });
    fireEvent.change(screen.getByRole("textbox", { name: "额外密码历史次数" }), { target: { value: "3" } });
    fireEvent.change(screen.getByRole("textbox", { name: "密码有效期（天）" }), { target: { value: "90" } });
    fireEvent.change(screen.getByRole("textbox", { name: "登录会话空闲超时（分钟）" }), { target: { value: "20" } });
    await user.click(screen.getByRole("checkbox", { name: "要求小写字母" }));
    await user.click(screen.getByRole("combobox", { name: "密码过期后的处理" }));
    await user.click(screen.getByRole("option", { name: "由管理员重置" }));
    const field = screen.getByRole("textbox", { name: "允许的来源 CIDR" });
    await user.clear(field);
    await user.type(field, "2001:db8::/32\n10.0.0.0/8");
    await user.click(screen.getByRole("button", { name: "审阅变更" }));
    const before = screen.getByRole("region", { name: "修改前的完整规则" });
    const after = screen.getByRole("region", { name: "拟提交的完整规则" });
    expect(within(before).getByText(/至少 15 个码点/)).toBeTruthy(); expect(within(after).getByText(/至少 21 个码点/)).toBeTruthy();
    expect(within(after).getByText("20 分钟")).toBeTruthy(); expect(within(after).getByText("90 天")).toBeTruthy();
    expect(within(after).getByText("由管理员重置")).toBeTruthy();
    expect(begin).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "继续身份验证" }));
    await waitFor(() => expect(begin).toHaveBeenCalledWith(currentSettings, {
      expectedResourceVersion: 4, mfa: { requiredForUsers: true }, password: { ...currentSettings.password, minimumLength: 21, historyCount: 3, maxAgeDays: 90, expiryMode: "ADMIN_RESET", requireLowercase: true },
      session: { idleTimeoutMinutes: 20 }, accessKeyNetwork: { allowedSourceCidrs: ["10.0.0.0/8", "2001:db8::/32"] }
    }, 7));
    expect(personalSecurity.current.authenticatorState).toHaveBeenCalledTimes(1);
  });

  it("keeps verification secrets in component memory and clears them after submission", async () => {
    const verifyStepUp = vi.fn().mockResolvedValue({});
    const source = client(undefined, pendingUpdate({ verifyStepUp }));
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

  it.each(["Session", "repository"])("clears unsubmitted verification secrets on a %s owner change", async (owner) => {
    const previous = pendingUpdate(); const next = pendingUpdate(); const user = userEvent.setup({ delay: null });
    const view = render(<LocaleProvider><LiveAccountSecuritySettings client={client(undefined, previous)} /></LocaleProvider>);
    fireEvent.change(await screen.findByLabelText("当前密码"), { target: { value: "Never-copy-this-49!" } });
    fireEvent.change(screen.getByLabelText("动态验证码"), { target: { value: "123456" } });
    view.rerender(<LocaleProvider><LiveAccountSecuritySettings client={{ ...client(undefined, next), identity: "settings-new-owner", sessionId: owner === "Session" ? "new-session" : "session-one" }} /></LocaleProvider>);
    expect((await screen.findByLabelText("当前密码") as HTMLInputElement).value).toBe("");
    expect((screen.getByLabelText("动态验证码") as HTMLInputElement).value).toBe("");
    await user.click(screen.getByRole("button", { name: "验证身份" })); expect(previous.verifyStepUp).not.toHaveBeenCalled(); expect(next.verifyStepUp).not.toHaveBeenCalled();
    expect(JSON.stringify(sessionStorage)).not.toContain("Never-copy-this-49!");
  });

  it("disables verification inputs during submission and does not apply a late old-owner result to the replacement", async () => {
    const request = deferred<SecurityStepUp>(); const previous = pendingUpdate({ verifyStepUp: vi.fn(() => request.promise) }); const next = pendingUpdate();
    const user = userEvent.setup({ delay: null }); const view = render(<LocaleProvider><LiveAccountSecuritySettings client={client(undefined, previous)} /></LocaleProvider>);
    fireEvent.change(await screen.findByLabelText("当前密码"), { target: { value: "Never-copy-this-49!" } });
    fireEvent.change(screen.getByLabelText("动态验证码"), { target: { value: "123456" } });
    await user.click(screen.getByRole("button", { name: "验证身份" }));
    expect((screen.getByLabelText("当前密码") as HTMLInputElement).disabled).toBe(true); expect((screen.getByLabelText("动态验证码") as HTMLInputElement).disabled).toBe(true);
    view.rerender(<LocaleProvider><LiveAccountSecuritySettings client={{ ...client(undefined, next), identity: "replacement-repository" }} /></LocaleProvider>);
    await act(async () => { request.resolve({ ...previous.intent!.stepUp!, state: "PROVED", provedAt: "2026-09-11T08:01:00Z" }); });
    expect((await screen.findByLabelText("当前密码") as HTMLInputElement).value).toBe(""); expect((screen.getByLabelText("动态验证码") as HTMLInputElement).value).toBe("");
    expect(screen.queryByRole("button", { name: "应用并重新登录" })).toBeNull(); expect(previous.apply).not.toHaveBeenCalled(); expect(next.verifyStepUp).not.toHaveBeenCalled(); expect(next.apply).not.toHaveBeenCalled();
  });

  it("shows regional progress rather than an unknown-outcome warning while a proof is still in flight", async () => {
    const request = deferred<SecurityStepUp>(); const update = pendingUpdate({ verifyStepUp: vi.fn(() => request.promise) });
    const source = client(undefined, update); const user = userEvent.setup({ delay: null });
    const view = render(<LocaleProvider><LiveAccountSecuritySettings client={source} /></LocaleProvider>);
    fireEvent.change(await screen.findByLabelText("当前密码"), { target: { value: "Never-store-this-49!" } });
    fireEvent.change(screen.getByLabelText("动态验证码"), { target: { value: "123456" } });
    await user.click(screen.getByRole("button", { name: "验证身份" }));
    view.rerender(<LocaleProvider><LiveAccountSecuritySettings client={{ ...source, update: { ...update, intent: { ...update.intent!, state: "VERIFICATION_UNKNOWN" } } }} /></LocaleProvider>);
    expect(await screen.findByText("正在处理当前步骤…")).toBeTruthy(); expect(screen.queryByText(/验证响应未知/)).toBeNull();
    expect(screen.queryByText("验证结果未知")).toBeNull();
    const proved = { ...update.intent!.stepUp!, state: "PROVED" as const, provedAt: "2026-09-11T08:01:00Z" };
    await act(async () => { request.resolve(proved); });
    view.rerender(<LocaleProvider><LiveAccountSecuritySettings client={{ ...source, update: { ...update, intent: { ...update.intent!, stepUp: proved, state: "PROVED" } } }} /></LocaleProvider>);
    expect(await screen.findByRole("button", { name: "应用并重新登录" })).toBeTruthy(); expect(screen.queryByText("正在处理当前步骤…")).toBeNull();
    expect(update.apply).not.toHaveBeenCalled();
  });

  it.each([["edit", "forbidden"], ["review", "forbidden"], ["edit", "unavailable"], ["review", "unavailable"]] as const)("retains the frozen %s draft after a %s current read without starting a proof", async (stage, status) => {
    const update = updater(); const source = client(undefined, update); const user = userEvent.setup({ delay: null });
    const view = render(<LocaleProvider><LiveAccountSecuritySettings client={source} /></LocaleProvider>);
    await user.click(await screen.findByRole("button", { name: "编辑账号安全规则" })); await user.click(screen.getByRole("checkbox", { name: "要求子用户使用 MFA" }));
    if (stage === "review") await user.click(screen.getByRole("button", { name: "审阅变更" }));
    view.rerender(<LocaleProvider><LiveAccountSecuritySettings client={{ ...source, load: vi.fn().mockResolvedValue({ status }) }} /></LocaleProvider>);
    await waitFor(() => expect(screen.queryByText(/正在更新当前账号规则/)).toBeNull());
    if (stage === "review") {
      expect(await screen.findByText(/冻结草稿仍可查看或取消/)).toBeTruthy();
      expect(screen.getByRole("region", { name: "拟提交的完整规则" })).toBeTruthy(); expect(screen.getByRole("button", { name: "继续身份验证" }).hasAttribute("disabled")).toBe(true);
    } else expect((screen.getByRole("checkbox", { name: "要求子用户使用 MFA" }) as HTMLInputElement).checked).toBe(true);
    await user.click(screen.getByRole("button", { name: "取消" }));
    await user.click(within(screen.getByRole("dialog")).getByRole("button", { name: "放弃并离开" }));
    expect(update.begin).not.toHaveBeenCalled(); expect(update.apply).not.toHaveBeenCalled();
  });

  it.each([
    ["密码最小长度", ""], ["密码最小长度", "14"], ["密码最小长度", "129"], ["密码最小长度", "15.5"],
    ["额外密码历史次数", "-1"], ["额外密码历史次数", "25"], ["额外密码历史次数", "1.2"],
    ["密码有效期（天）", ""], ["密码有效期（天）", "-1"], ["密码有效期（天）", "366"],
    ["登录会话空闲超时（分钟）", ""], ["登录会话空闲超时（分钟）", "4"], ["登录会话空闲超时（分钟）", "61"], ["登录会话空闲超时（分钟）", "5.5"]
  ])("rejects %s input %s before requesting verification", async (label, value) => {
    const update = updater(); const factor = vi.fn(); personalSecurity.current = { authenticatorState: factor };
    const user = userEvent.setup({ delay: null }); render(<LocaleProvider><LiveAccountSecuritySettings client={client(undefined, update)} /></LocaleProvider>);
    await user.click(await screen.findByRole("button", { name: "编辑账号安全规则" }));
    const field = screen.getByRole("textbox", { name: label }); fireEvent.change(field, { target: { value } });
    await user.click(screen.getByRole("button", { name: "审阅变更" }));
    expect(screen.getByText(/请输入.*整数/)).toBeTruthy(); expect(field).toBe(document.activeElement);
    expect(update.begin).not.toHaveBeenCalled(); expect(factor).not.toHaveBeenCalled(); expect(update.apply).not.toHaveBeenCalled();
  });

  it("keeps unchanged and cancelled drafts free of writes and returns focus to the shared edit action", async () => {
    const update = updater(); const user = userEvent.setup({ delay: null }); render(<LocaleProvider><LiveAccountSecuritySettings client={client(undefined, update)} /></LocaleProvider>);
    await user.click(await screen.findByRole("button", { name: "编辑账号安全规则" }));
    expect(screen.getByRole("button", { name: "审阅变更" }).hasAttribute("disabled")).toBe(true);
    await user.click(screen.getByRole("checkbox", { name: "要求子用户使用 MFA" })); await user.click(screen.getByRole("button", { name: "取消" }));
    const confirmation = await screen.findByRole("dialog"); await user.click(within(confirmation).getByRole("button", { name: "放弃并离开" }));
    expect(await screen.findByRole("button", { name: "编辑账号安全规则" })).toBe(document.activeElement);
    expect(update.begin).not.toHaveBeenCalled(); expect(update.apply).not.toHaveBeenCalled();
  });

  it("requires the pre-change authenticator even when the proposed change only relaxes user MFA", async () => {
    const update = updater(); const before = { ...currentSettings, mfa: { requiredForUsers: true } };
    personalSecurity.current = { authenticatorState: vi.fn().mockResolvedValue({ enrollmentState: "UNBOUND", factorRevision: 7 }) };
    const user = userEvent.setup({ delay: null }); render(<LocaleProvider><LiveAccountSecuritySettings client={client({ status: "ready", settings: before }, update)} /></LocaleProvider>);
    await user.click(await screen.findByRole("button", { name: "编辑账号安全规则" })); await user.click(screen.getByRole("checkbox", { name: "要求子用户使用 MFA" }));
    await user.click(screen.getByRole("button", { name: "审阅变更" })); await user.click(screen.getByRole("button", { name: "继续身份验证" }));
    expect(await screen.findByText(/绑定可用的 MFA 验证器/)).toBeTruthy();
    expect(update.begin).not.toHaveBeenCalled(); expect(update.apply).not.toHaveBeenCalled();
  });

  it("retains every proposed field when returning from review and does not silently rebase after a newer read", async () => {
    const update = updater(); const source = client(undefined, update); const user = userEvent.setup({ delay: null });
    personalSecurity.current = { authenticatorState: vi.fn().mockResolvedValue({ enrollmentState: "BOUND", factorRevision: 7 }) };
    const view = render(<LocaleProvider><LiveAccountSecuritySettings client={source} /></LocaleProvider>);
    await user.click(await screen.findByRole("button", { name: "编辑账号安全规则" }));
    fireEvent.change(screen.getByRole("textbox", { name: "密码有效期（天）" }), { target: { value: "90" } });
    await user.click(screen.getByRole("button", { name: "审阅变更" })); await user.click(screen.getByRole("button", { name: "返回编辑" }));
    expect((screen.getByRole("textbox", { name: "密码有效期（天）" }) as HTMLInputElement).value).toBe("90");
    await user.click(screen.getByRole("button", { name: "审阅变更" }));
    view.rerender(<LocaleProvider><LiveAccountSecuritySettings client={{ ...source, load: vi.fn().mockResolvedValue({ status: "ready", settings: { ...currentSettings, resourceVersion: 5 } }) }} /></LocaleProvider>);
    await waitFor(() => expect(source.load).toHaveBeenCalledOnce());
    await waitFor(() => expect(screen.queryByText(/正在更新当前账号规则/)).toBeNull());
    await user.click(screen.getByRole("button", { name: "继续身份验证" }));
    expect(await screen.findByText(/资源版本或审阅归属已变化/)).toBeTruthy(); expect(update.begin).not.toHaveBeenCalled();
    expect(within(screen.getByRole("region", { name: "拟提交的完整规则" })).getByText("90 天")).toBeTruthy();
  });

  it("keeps the frozen proposal and completion lookup visible when a fresh current read is denied", async () => {
    const update = updater({ intent: { accountId: currentSettings.accountId, actorId: "user-one", requestId: "settings-original",
      expectedFactorRevision: 7, state: "APPLY_UNKNOWN", stepUp: null,
      settings: { expectedResourceVersion: 4, mfa: currentSettings.mfa, password: { ...currentSettings.password, maxAgeDays: 90 }, session: currentSettings.session, accessKeyNetwork: currentSettings.accessKeyNetwork } },
      inspectChange: vi.fn().mockRejectedValue(new HttpProblem(403, "DENIED")) });
    const user = userEvent.setup({ delay: null }); render(<LocaleProvider><LiveAccountSecuritySettings client={client({ status: "forbidden" }, update)} /></LocaleProvider>);
    expect(await screen.findByText(/没有查看账号安全规则的权限/)).toBeTruthy();
    expect(within(screen.getByRole("region", { name: "原命令冻结的完整目标" })).getByText("90 天")).toBeTruthy();
    expect(screen.queryByRole("region", { name: "修改前的完整规则" })).toBeNull();
    await user.click(screen.getByRole("button", { name: "查询原保存结果" }));
    await waitFor(() => expect(update.inspectChange).toHaveBeenCalledOnce()); expect(update.apply).not.toHaveBeenCalled(); expect(update.clear).not.toHaveBeenCalled();
  });

  it("reports an unavailable factor read without inventing an unknown change request", async () => {
    const update = updater(); personalSecurity.current = { authenticatorState: vi.fn().mockRejectedValue(new HttpProblem(503, "UNAVAILABLE")) };
    const user = userEvent.setup({ delay: null }); render(<LocaleProvider><LiveAccountSecuritySettings client={client(undefined, update)} /></LocaleProvider>);
    await user.click(await screen.findByRole("button", { name: "编辑账号安全规则" }));
    await user.click(screen.getByRole("checkbox", { name: "要求子用户使用 MFA" })); await user.click(screen.getByRole("button", { name: "审阅变更" }));
    await user.click(screen.getByRole("button", { name: "继续身份验证" }));
    expect(await screen.findByText(/没有创建变更请求/)).toBeTruthy(); expect(update.begin).not.toHaveBeenCalled();
    expect(screen.queryByText("原命令冻结的完整目标")).toBeNull();
  });

  it("does not claim a retained unknown command when the Provider rejects review before dispatch", async () => {
    const update = updater({ begin: vi.fn().mockRejectedValue(new AccountSecuritySettingsReviewRejected()) });
    personalSecurity.current = { authenticatorState: vi.fn().mockResolvedValue({ enrollmentState: "BOUND", factorRevision: 7 }) };
    const user = userEvent.setup({ delay: null }); render(<LocaleProvider><LiveAccountSecuritySettings client={client(undefined, update)} /></LocaleProvider>);
    await user.click(await screen.findByRole("button", { name: "编辑账号安全规则" })); await user.click(screen.getByRole("checkbox", { name: "要求子用户使用 MFA" }));
    await user.click(screen.getByRole("button", { name: "审阅变更" })); await user.click(screen.getByRole("button", { name: "继续身份验证" }));
    expect(await screen.findByText(/资源版本或审阅归属已变化/)).toBeTruthy();
    expect(screen.queryByText(/原请求已保留/)).toBeNull(); expect(screen.queryByRole("region", { name: "原命令冻结的完整目标" })).toBeNull();
    expect(update.apply).not.toHaveBeenCalled(); expect(update.retryStepUp).not.toHaveBeenCalled();
  });

  it("does not create an old owner's proof when its factor read returns after an owner change", async () => {
    const factor = deferred<{ enrollmentState: string; factorRevision: number }>(); const oldUpdate = updater(); const nextUpdate = updater();
    personalSecurity.current = { authenticatorState: () => factor.promise };
    const user = userEvent.setup({ delay: null }); const view = render(<LocaleProvider><LiveAccountSecuritySettings client={client(undefined, oldUpdate)} /></LocaleProvider>);
    await user.click(await screen.findByRole("button", { name: "编辑账号安全规则" })); await user.click(screen.getByRole("checkbox", { name: "要求子用户使用 MFA" }));
    await user.click(screen.getByRole("button", { name: "审阅变更" })); await user.click(screen.getByRole("button", { name: "继续身份验证" }));
    view.rerender(<LocaleProvider><LiveAccountSecuritySettings client={{ ...client(undefined, nextUpdate), identity: "new-owner", sessionId: "new-session" }} /></LocaleProvider>);
    await act(async () => { factor.resolve({ enrollmentState: "BOUND", factorRevision: 7 }); });
    expect(await screen.findByRole("button", { name: "编辑账号安全规则" })).toBeTruthy();
    expect(oldUpdate.begin).not.toHaveBeenCalled(); expect(nextUpdate.begin).not.toHaveBeenCalled();
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
    const newClient = { ...client(), identity: "settings-view-two", accountId: "account-two", principalId: "user-two", sessionId: "session-two", load: vi.fn(() => newRead.promise) };
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
    expect(screen.getByText("要求小写字母").nextElementSibling?.textContent).toBe("要求");
    expect(screen.getByText("要求大写字母").nextElementSibling?.textContent).toBe("不要求");
    expect(screen.getByText("20 分钟")).toBeTruthy(); expect(screen.getByText("90 天")).toBeTruthy();
    expect(screen.getByText(/当前密码 \+ 最近 3 次已知历史/)).toBeTruthy();
    expect(screen.getByText(/不一定是受保护身份或本人/)).toBeTruthy();
    expect(screen.queryByText(/拟定默认/)).toBeNull();
    expect(screen.queryByRole("button", { name: /编辑|保存/ })).toBeNull();
  });
});
