import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { LocaleProvider } from "@/i18n/LocaleProvider";
import { HttpProblem } from "@/infrastructure/http/jsonRequest";
import { SessionProvider } from "../application/SessionProvider";
import type { IamRepository } from "../repositories/iamRepository";
import { previewIamRepository, resetPreviewEnvironment } from "../repositories/previewIamRepository";
import { LoginRenderer } from "./LoginRenderer";

const navigation = vi.hoisted(() => ({ replace: vi.fn() }));
vi.mock("next/navigation", () => ({ useRouter: () => navigation }));
vi.mock("@/infrastructure/runtime/uxPreviewMode", () => ({ uxPreviewEnabled: true }));
const session = { id: "test-session", organizationId: "org-test", principalId: "p-test", status: "ACTIVE" as const,
  issuedAt: "2026-09-01T00:00:00Z", expiresAt: "2099-09-01T00:00:00Z" };
function repository(mustChangePassword = false): IamRepository {
  return { login: vi.fn().mockResolvedValue({ outcome: "AUTHENTICATED", credential: "memory-only-token", mustChangePassword, session }),
    logout: vi.fn().mockResolvedValue(undefined), changePassword: vi.fn().mockResolvedValue(undefined) };
}
function open(iam = repository(), returnTo: string | undefined = "/console/resources/") {
  const user = userEvent.setup();
  render(<LocaleProvider><SessionProvider repository={iam}><LoginRenderer returnTo={returnTo} /></SessionProvider></LocaleProvider>);
  return { user, iam };
}
afterEach(() => { cleanup(); localStorage.clear(); sessionStorage.clear(); resetPreviewEnvironment(); vi.clearAllMocks(); });

describe("branded sign-in flows", () => {
  it.each(["primary", "subaccount", "preview"])("lands a %s sign-in on the dashboard by default", async (mode) => {
    const user = userEvent.setup();
    render(<LocaleProvider><SessionProvider repository={repository()}><LoginRenderer /></SessionProvider></LocaleProvider>);
    if (mode === "preview") {
      await user.click(screen.getByRole("button", { name: "一键进入体验控制台" }));
    } else {
      if (mode === "subaccount") {
        await user.click(screen.getByRole("tab", { name: "IAM 子账号" }));
        await user.type(screen.getByLabelText("子账号登录名"), "developer@tenant-a");
      }
      await user.type(screen.getByLabelText("密码", { exact: true }), "Only-Test-Password-49!");
      await user.click(screen.getByRole("button", { name: "登录控制台" }));
    }
    await waitFor(() => expect(navigation.replace).toHaveBeenCalledExactlyOnceWith("/console/", { scroll: false }));
  });

  it("returns an IAM user to a requested resource page", async () => {
    const { user } = open();
    await user.click(screen.getByRole("tab", { name: "IAM 子账号" }));
    await user.type(screen.getByLabelText("子账号登录名"), "developer@tenant-a");
    await user.type(screen.getByLabelText("密码", { exact: true }), "Only-Test-Password-49!");
    await user.click(screen.getByRole("button", { name: "登录控制台" }));
    await waitFor(() => expect(navigation.replace).toHaveBeenCalledExactlyOnceWith("/console/resources/", { scroll: false }));
  });

  it.each(["/console/", "/console/resources/"])("returns an IAM user to %s only after required password replacement", async (returnTo) => {
    const { user, iam } = open(repository(true), returnTo);
    await user.click(screen.getByRole("tab", { name: "IAM 子账号" }));
    await user.type(screen.getByLabelText("子账号登录名"), "developer@tenant-a");
    await user.type(screen.getByLabelText("密码", { exact: true }), "Initial-Password-49!");
    await user.click(screen.getByRole("button", { name: "登录控制台" }));
    await screen.findByRole("heading", { name: "设置你的正式密码" });
    expect(navigation.replace).not.toHaveBeenCalled();
    await user.type(screen.getByLabelText("当前初始密码"), "Initial-Password-49!");
    await user.type(screen.getByLabelText("新密码", { exact: true }), "Permanent-Password-49!");
    await user.type(screen.getByLabelText("确认新密码"), "Permanent-Password-49!");
    await user.click(screen.getByRole("button", { name: "保存并进入控制台" }));
    await waitFor(() => expect(navigation.replace).toHaveBeenCalledExactlyOnceWith(returnTo, { scroll: false }));
    expect(iam.changePassword).toHaveBeenCalledOnce();
  });

  it("keeps the preview a separate explicit action and does not persist credentials", async () => {
    const { user, iam } = open();
    await user.type(screen.getByLabelText("密码", { exact: true }), "Unsubmitted-secret-49!");
    await user.click(screen.getByRole("button", { name: "一键进入体验控制台" }));
    expect(iam.login).toHaveBeenCalledWith({ loginName: "preview-admin", password: "experience-only" });
    expect(navigation.replace).toHaveBeenCalledWith("/console/resources/", { scroll: false });
    expect((screen.getByLabelText("密码", { exact: true }) as HTMLInputElement).value).toBe("");
    expect(localStorage.length + sessionStorage.length).toBe(0);
    expect(document.body.textContent).not.toContain("memory-only-token");
  });
  it("keeps the MFA preview sessionless until the challenge is complete", async () => {
    const { user } = open(previewIamRepository);
    await user.click(screen.getByRole("button", { name: "体验 MFA 登录挑战" }));
    expect(screen.getByRole("heading", { name: "完成安全验证" })).toBeTruthy();
    expect(screen.getByText(/验证码通过前不会创建登录会话/)).toBeTruthy();
    expect(navigation.replace).not.toHaveBeenCalled();
    await user.type(screen.getByLabelText("6 位动态验证码"), "000000");
    await user.click(screen.getByRole("button", { name: "验证并登录" }));
    expect(screen.getByRole("alert").textContent).toContain("验证码不正确");
    expect(navigation.replace).not.toHaveBeenCalled();
    await user.clear(screen.getByLabelText("6 位动态验证码"));
    await user.type(screen.getByLabelText("6 位动态验证码"), "624810");
    await user.click(screen.getByRole("button", { name: "验证并登录" }));
    await waitFor(() => expect(navigation.replace).toHaveBeenCalledExactlyOnceWith("/console/resources/", { scroll: false }));
    expect(localStorage.length + sessionStorage.length).toBe(0);
    expect(document.body.textContent).not.toContain("preview-challenge-");
  });
  it("previews required first-time MFA setup without invoking IAM or creating a session", async () => {
    const iam = repository();
    const { user } = open(iam);
    await user.click(screen.getByRole("button", { name: "体验首次强制 MFA 设置" }));
    expect(screen.getByRole("heading", { name: "首次强制 MFA 设置" })).toBeTruthy();
    expect(screen.getAllByText(/NEVER_BOUND/).length).toBeGreaterThan(0);
    await user.click(screen.getByRole("button", { name: "已有可信通知地址" }));
    expect(screen.getByRole("heading", { name: "绑定身份验证器" })).toBeTruthy();
    expect(screen.getByText("MTRXPREVIEWFIRSTFACTORNOTREAL")).toBeTruthy();
    await user.type(screen.getByLabelText("身份验证器 6 位验证码"), "000000");
    await user.click(screen.getByRole("button", { name: "确认演示绑定" }));
    expect(screen.getAllByRole("alert").some((alert) => alert.textContent?.includes("演示验证码不正确"))).toBe(true);
    await user.clear(screen.getByLabelText("身份验证器 6 位验证码"));
    await user.type(screen.getByLabelText("身份验证器 6 位验证码"), "624810");
    await user.click(screen.getByRole("button", { name: "确认演示绑定" }));
    expect(screen.getByRole("heading", { name: "保存一次性恢复码" })).toBeTruthy();
    expect(screen.getAllByText(/^MTRX-FIRST-/)).toHaveLength(10);
    expect(screen.getByRole("button", { name: "完成并返回登录" }).hasAttribute("disabled")).toBe(true);
    await user.click(screen.getByRole("checkbox", { name: "我已了解真实恢复码须单独安全保存" }));
    await user.click(screen.getByRole("button", { name: "完成并返回登录" }));
    expect(screen.getByRole("heading", { name: "设置完成" })).toBeTruthy();
    expect(document.body.textContent).not.toContain("MTRX-FIRST-");
    expect(document.body.textContent).not.toContain("MTRXPREVIEWFIRSTFACTORNOTREAL");
    expect(iam.login).not.toHaveBeenCalled();
    expect(navigation.replace).not.toHaveBeenCalled();
    expect(localStorage.length + sessionStorage.length).toBe(0);
    await user.click(screen.getByRole("button", { name: "返回登录" }));
    expect(screen.getByRole("heading", { name: "登录控制台" })).toBeTruthy();
  });
  it("requires a fresh challenge after password change and address proof before first-time TOTP setup", async () => {
    const iam = repository();
    const { user } = open(iam);
    await user.click(screen.getByRole("button", { name: "体验首次强制 MFA 设置" }));
    await user.click(screen.getByRole("button", { name: "初始密码及通知地址尚未就绪" }));
    expect(screen.getByRole("heading", { name: "先更新初始密码" })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "模拟完成改密" }));
    expect(screen.getByRole("heading", { name: "用新密码重新验证" })).toBeTruthy();
    expect(screen.getByText(/旧挑战及其剩余时间已结束/)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "模拟新的绑定挑战" }));
    expect(screen.getByRole("heading", { name: "验证安全通知地址" })).toBeTruthy();
    expect(document.body.textContent).not.toContain("MTRXPREVIEWFIRSTFACTORNOTREAL");
    await user.click(screen.getByRole("button", { name: "显示演示验证码" }));
    await user.type(screen.getByLabelText("地址验证码"), "000000");
    await user.click(screen.getByRole("button", { name: "确认演示地址" }));
    expect(screen.getAllByRole("alert").some((alert) => alert.textContent?.includes("演示验证码不正确"))).toBe(true);
    await user.clear(screen.getByLabelText("地址验证码"));
    await user.type(screen.getByLabelText("地址验证码"), "624810");
    await user.click(screen.getByRole("button", { name: "确认演示地址" }));
    expect(screen.getByRole("heading", { name: "绑定身份验证器" })).toBeTruthy();
    expect(iam.login).not.toHaveBeenCalled();
    expect(iam.changePassword).not.toHaveBeenCalled();
    expect(navigation.replace).not.toHaveBeenCalled();
    expect(localStorage.length + sessionStorage.length).toBe(0);
  });
  it("ends the isolated enrollment challenge after its absolute five-minute deadline", async () => {
    const startedAt = Date.now();
    const clock = vi.spyOn(Date, "now").mockReturnValue(startedAt);
    try {
      const iam = repository();
      const { user } = open(iam);
      await user.click(screen.getByRole("button", { name: "体验首次强制 MFA 设置" }));
      await user.click(screen.getByRole("button", { name: "已有可信通知地址" }));
      expect(screen.getByRole("heading", { name: "绑定身份验证器" })).toBeTruthy();
      clock.mockReturnValue(startedAt + 5 * 60_000);
      await user.type(screen.getByLabelText("身份验证器 6 位验证码"), "624810");
      await user.click(screen.getByRole("button", { name: "确认演示绑定" }));
      expect(screen.getByRole("heading", { name: "挑战已过期" })).toBeTruthy();
      expect(document.body.textContent).not.toContain("MTRXPREVIEWFIRSTFACTORNOTREAL");
      expect(iam.login).not.toHaveBeenCalled();
      expect(navigation.replace).not.toHaveBeenCalled();
    } finally {
      clock.mockRestore();
    }
  });
  it("previews irreversible authenticator recovery without creating a session or persisting secrets", async () => {
    const { user } = open(previewIamRepository);
    await user.click(screen.getByRole("button", { name: "体验 MFA 登录挑战" }));
    await user.click(screen.getByRole("button", { name: "无法使用当前身份验证器" }));
    expect(screen.getByRole("heading", { name: "使用恢复码重新绑定" })).toBeTruthy();
    expect(screen.getByText(/关闭页面也不能撤销/)).toBeTruthy();
    await user.type(screen.getByLabelText("一次性恢复码"), "MTRX-RECOVER-01");
    await user.click(screen.getByRole("button", { name: "消费恢复码并继续" }));
    expect(await screen.findByRole("heading", { name: "绑定新的身份验证器" })).toBeTruthy();
    expect(screen.getByText("MTRXPREVIEWSEEDNOTREAL")).toBeTruthy();
    expect(navigation.replace).not.toHaveBeenCalled();
    expect(localStorage.length + sessionStorage.length).toBe(0);
    await user.type(screen.getByLabelText("新身份验证器的 6 位验证码"), "624810");
    await user.click(screen.getByRole("button", { name: "确认新身份验证器" }));
    expect(await screen.findByRole("heading", { name: "保存一次性恢复码" })).toBeTruthy();
    expect(screen.getAllByText(/^MTRX-NEW-/)).toHaveLength(10);
    expect(navigation.replace).not.toHaveBeenCalled();
    expect(localStorage.length + sessionStorage.length).toBe(0);
    expect(document.body.textContent).not.toContain("preview-recovery-secret-");
  });
  it("requires a fresh login after challenge-bound password replacement", async () => {
    const { user } = open(previewIamRepository);
    await user.click(screen.getByRole("button", { name: "体验 MFA 登录挑战" }));
    await user.type(screen.getByLabelText("6 位动态验证码"), "624811");
    await user.click(screen.getByRole("button", { name: "验证并登录" }));
    expect(await screen.findByRole("heading", { name: "验证完成，请更新密码" })).toBeTruthy();
    expect(navigation.replace).not.toHaveBeenCalled();
    await user.type(screen.getByLabelText("新密码", { exact: true }), "Replacement-Password-49!");
    await user.type(screen.getByLabelText("确认新密码"), "Replacement-Password-49!");
    await user.click(screen.getByRole("button", { name: "更新密码" }));
    expect(await screen.findByRole("heading", { name: "密码已更新" })).toBeTruthy();
    expect(navigation.replace).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "返回登录" }));
    expect(screen.getByRole("heading", { name: "登录控制台" })).toBeTruthy();
    expect(localStorage.length + sessionStorage.length).toBe(0);
  });
  it("translates an existing authentication error immediately and retains the account draft", async () => {
    const iam = repository();
    vi.mocked(iam.login).mockRejectedValue(new HttpProblem(401, "private-upstream-details"));
    const { user } = open(iam);
    await user.type(screen.getByLabelText("密码", { exact: true }), "Wrong-Password-49!");
    await user.click(screen.getByRole("button", { name: "登录控制台" }));
    expect((await screen.findByRole("alert")).textContent).toContain("账号、主账号标识或密码不正确");
    await user.click(screen.getByRole("button", { name: "语言" }));
    await user.click(screen.getByRole("menuitemradio", { name: "English" }));
    expect(screen.getByRole("alert").textContent).toContain("username, account identifier or password is incorrect");
    expect((screen.getByLabelText("Username") as HTMLInputElement).value).toBe("admin");
    expect(document.body.textContent).not.toContain("private-upstream-details");
    expect(Object.keys(localStorage)).toEqual(["matrix.locale"]);
  });
  it("uses arrow-key account tabs and clears a revealed password when changing the account type", async () => {
    const { user } = open();
    await user.type(screen.getByLabelText("密码", { exact: true }), "Mode-Secret-49!");
    await user.click(screen.getByRole("button", { name: "显示密码" }));
    screen.getByRole("tab", { name: "主账号" }).focus();
    await user.keyboard("{ArrowRight}");
    expect(screen.getByRole("tab", { name: "IAM 子账号" }).getAttribute("aria-selected")).toBe("true");
    expect((screen.getByLabelText("密码", { exact: true }) as HTMLInputElement).type).toBe("password");
    expect((screen.getByLabelText("密码", { exact: true }) as HTMLInputElement).value).toBe("");
    expect(screen.getByRole("tabpanel").getAttribute("aria-labelledby")).toBe(screen.getByRole("tab", { name: "IAM 子账号" }).id);
  });
  it("requires matching passwords on first login, then enters the requested console route", async () => {
    const { user, iam } = open(repository(true));
    await user.type(screen.getByLabelText("密码", { exact: true }), "Initial-Password-49!");
    await user.click(screen.getByRole("button", { name: "登录控制台" }));
    await screen.findByRole("heading", { name: "设置你的正式密码" });
    expect(navigation.replace).not.toHaveBeenCalled();
    await user.type(screen.getByLabelText("当前初始密码"), "Initial-Password-49!");
    await user.type(screen.getByLabelText("新密码", { exact: true }), "Permanent-Password-49!");
    await user.type(screen.getByLabelText("确认新密码"), "Different-Password-49!");
    await user.click(screen.getByRole("button", { name: "保存并进入控制台" }));
    expect(screen.getByRole("alert").textContent).toContain("不一致");
    expect(iam.changePassword).not.toHaveBeenCalled();
    await user.clear(screen.getByLabelText("确认新密码"));
    await user.type(screen.getByLabelText("确认新密码"), "Permanent-Password-49!");
    await user.click(screen.getByRole("button", { name: "保存并进入控制台" }));
    await waitFor(() => expect(navigation.replace).toHaveBeenCalledWith("/console/resources/", { scroll: false }));
    expect(iam.changePassword).toHaveBeenCalledWith("memory-only-token", { currentPassword: "Initial-Password-49!", newPassword: "Permanent-Password-49!" });
  });
  it("retains a restricted session after failed revocation and shows translated feedback", async () => {
    const iam = repository(true);
    vi.mocked(iam.logout).mockRejectedValue(new Error("private upstream"));
    const { user } = open(iam);
    await user.type(screen.getByLabelText("密码", { exact: true }), "Initial-Password-49!");
    await user.click(screen.getByRole("button", { name: "登录控制台" }));
    await user.click(await screen.findByRole("button", { name: "退出此会话" }));
    expect((await screen.findByRole("alert")).textContent).toContain("会话仍保留");
    expect(screen.getByRole("heading", { name: "设置你的正式密码" })).toBeTruthy();
    expect(navigation.replace).not.toHaveBeenCalled();
  });
});
