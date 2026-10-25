import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { useState } from "react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { LocaleProvider } from "@/i18n/LocaleProvider";
import { HttpProblem } from "@/infrastructure/http/jsonRequest";
import { SessionProvider, useSession } from "../application/SessionProvider";
import type { IamRepository } from "../repositories/iamRepository";
import { previewIamRepository, resetPreviewEnvironment } from "../repositories/previewIamRepository";
import { LoginRenderer } from "./LoginRenderer";
import { SelfPasswordSettings } from "./PasswordChangeForm";
import { ConsoleNavigationProvider, useConsoleNavigation } from "@/features/control-plane/routes/ConsoleNavigation";

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
function SecuritySettingsSignOutHarness() {
  const active = useSession();
  if (!active.current) return <><button type="button" onClick={() => void active.login("admin", "password")}>Establish test Session</button><LoginRenderer /></>;
  return <button type="button" onClick={() => active.expire("memory-only-token", active.sessionRevision, { kind: "SECURITY_SETTINGS_UPDATED", requestId: "settings-request-one" })}>Confirm security settings change</button>;
}
afterEach(() => { cleanup(); localStorage.clear(); sessionStorage.clear(); resetPreviewEnvironment(); vi.clearAllMocks(); window.history.replaceState(null, "", "/"); });

function SelfPasswordRoute() {
  const session = useSession(); const nav = useConsoleNavigation(); const [settings, setSettings] = useState(true);
  return <>
    <button onClick={() => void session.login("alex@account-a", "Initial-Test-Password-49!")}>Test sign in</button>
    <button onClick={() => void session.login("bravo@account-b", "Initial-Test-Password-49!")}>Test sign in as replacement</button>
    <output aria-label="Current session phase">{session.phase}</output>
    <button onClick={() => nav.navigate("/console/access/settings/?panel=sessions", { onAccepted: () => setSettings(false) })}>查看会话</button>
    {settings ? <SelfPasswordSettings /> : <h2>会话列表</h2>}
  </>;
}
function SelfPasswordHarness({ iam }: { iam: IamRepository }) {
  return <LocaleProvider><SessionProvider repository={iam}><ConsoleNavigationProvider selection={{ section: "access", view: "settings" }}><SelfPasswordRoute /></ConsoleNavigationProvider></SessionProvider></LocaleProvider>;
}
async function openSelf(iam = repository()) {
  window.history.replaceState(null, "", "/console/access/settings/");
  const user = userEvent.setup({ delay: null }); const view = render(<SelfPasswordHarness iam={iam} />);
  await user.click(screen.getByRole("button", { name: "Test sign in" }));
  await user.click(await screen.findByRole("button", { name: "修改本人密码" }));
  return { iam, user, view };
}
function enterSelfPasswords() {
  fireEvent.change(screen.getByLabelText("当前密码", { exact: true }), { target: { value: "Initial-Test-Password-49!" } });
  fireEvent.change(screen.getByLabelText("新密码", { exact: true }), { target: { value: "Changed-Test-Password-73!" } });
  fireEvent.change(screen.getByLabelText("确认新密码"), { target: { value: "Changed-Test-Password-73!" } });
}

describe("self-service password change", () => {
  it.each([true, false])("submits explicit revokeOthers=%s and keeps success in the current content workspace", async (revoke) => {
    const { iam, user } = await openSelf();
    const choice = screen.getByRole("checkbox", { name: "同时退出其他登录会话（推荐）" }) as HTMLInputElement;
    expect(choice.checked).toBe(true); if (!revoke) await user.click(choice);
    expect(screen.queryByRole("combobox")).toBeNull(); expect(iam.changePassword).not.toHaveBeenCalled();
    enterSelfPasswords(); await user.click(screen.getByRole("button", { name: "更新密码" }));
    expect(iam.changePassword).toHaveBeenCalledExactlyOnceWith("memory-only-token", { currentPassword: "Initial-Test-Password-49!", newPassword: "Changed-Test-Password-73!", revokeOtherSessions: revoke });
    expect(await screen.findByRole("status", { name: "改密结果" })).toBeTruthy(); expect(screen.getByRole("status", { name: "改密结果" }).textContent).toContain("当前会话保留");
    expect(screen.getByLabelText("Current session phase").textContent).toBe("authenticated"); expect(iam.logout).not.toHaveBeenCalled();
    expect(navigation.replace).not.toHaveBeenCalled(); expect(window.location.search).toBe("");
    expect(screen.queryByLabelText("新密码", { exact: true })).toBeNull(); expect(document.body.textContent).not.toContain("Changed-Test-Password-73!");
    expect(JSON.stringify(sessionStorage) + JSON.stringify(localStorage)).not.toContain("Changed-Test-Password-73!");
    await user.click(screen.getByRole("button", { name: "完成" }));
    expect(screen.getByRole("button", { name: "修改本人密码" })).toBe(document.activeElement);
  });

  it("validates bounds and confirmation locally and focuses the field without sending a command", async () => {
    const { iam, user } = await openSelf(); enterSelfPasswords();
    fireEvent.change(screen.getByLabelText("新密码", { exact: true }), { target: { value: "short" } });
    await user.click(screen.getByRole("button", { name: "更新密码" }));
    expect(screen.getByLabelText("新密码", { exact: true })).toBe(document.activeElement); expect(iam.changePassword).not.toHaveBeenCalled();
    fireEvent.change(screen.getByLabelText("新密码", { exact: true }), { target: { value: "Another-Test-Password-73!" } });
    await user.click(screen.getByRole("button", { name: "更新密码" }));
    expect(screen.getByLabelText("确认新密码")).toBe(document.activeElement); expect(screen.getByRole("alert").textContent).toContain("不一致");
    expect(iam.changePassword).not.toHaveBeenCalled();
  });

  it("guards dirty content navigation and discards passwords only after explicit leave consent", async () => {
    const { iam, user } = await openSelf(); enterSelfPasswords();
    await user.click(screen.getByRole("button", { name: "查看会话" })); expect(window.location.search).toBe("");
    await user.click(within(screen.getByRole("dialog")).getByRole("button", { name: "继续编辑" }));
    expect((screen.getByLabelText("新密码", { exact: true }) as HTMLInputElement).value).toBe("Changed-Test-Password-73!");
    await user.click(screen.getByRole("button", { name: "查看会话" }));
    await user.click(within(screen.getByRole("dialog")).getByRole("button", { name: "放弃并离开" }));
    expect(window.location.search).toBe("?panel=sessions"); expect(screen.getByRole("heading", { name: "会话列表" })).toBeTruthy();
    expect(screen.queryByLabelText("新密码", { exact: true })).toBeNull(); expect(iam.changePassword).not.toHaveBeenCalled();
    expect(navigation.replace).not.toHaveBeenCalled();
  });

  it("cancels a dirty edit without writing and restores the shared edit action focus", async () => {
    const { iam, user } = await openSelf(); enterSelfPasswords(); await user.click(screen.getByRole("button", { name: "取消" }));
    await user.click(within(screen.getByRole("dialog")).getByRole("button", { name: "放弃并离开" }));
    expect(screen.getByRole("button", { name: "修改本人密码" })).toBe(document.activeElement);
    expect(iam.changePassword).not.toHaveBeenCalled(); expect(screen.queryByLabelText("新密码", { exact: true })).toBeNull();
  });

  it.each([401, 409, 503])("clears entered secrets and never displays success for a %s response", async (status) => {
    const iam = repository(); vi.mocked(iam.changePassword).mockRejectedValue(new HttpProblem(status, "PRIVATE_FAILURE"));
    const { user } = await openSelf(iam); enterSelfPasswords(); await user.click(screen.getByRole("button", { name: "更新密码" }));
    await waitFor(() => expect(iam.changePassword).toHaveBeenCalledOnce());
    for (const label of ["当前密码", "新密码", "确认新密码"]) expect((screen.getByLabelText(label, { exact: true }) as HTMLInputElement).value).toBe("");
    expect(screen.queryByRole("status", { name: "改密结果" })).toBeNull(); expect(screen.getByLabelText("Current session phase").textContent).toBe("authenticated");
    expect(navigation.replace).not.toHaveBeenCalled(); expect(document.body.textContent).not.toContain("PRIVATE_FAILURE");
    if (status === 503) {
      expect(screen.getByRole("alert").textContent).toContain("结果未确认");
      expect((screen.getByLabelText("新密码", { exact: true }) as HTMLInputElement).disabled).toBe(true);
      await user.click(screen.getByRole("button", { name: "取消" }));
      await user.click(screen.getByRole("button", { name: "查看未确认的改密" }));
      expect(screen.getByRole("button", { name: "更新密码" }).hasAttribute("disabled")).toBe(true); expect(iam.changePassword).toHaveBeenCalledOnce();
    } else expect(screen.getByRole("alert").textContent).toContain(status === 401 ? "登录会话已经失效" : "未确认成功");
  });

  it("keeps busy navigation guarded and never resumes a rejected navigation automatically after save", async () => {
    let resolve!: () => void; const iam = repository(); vi.mocked(iam.changePassword).mockImplementation(() => new Promise<void>((done) => { resolve = done; }));
    const { user } = await openSelf(iam); enterSelfPasswords(); await user.click(screen.getByRole("button", { name: "更新密码" }));
    await user.click(screen.getByRole("button", { name: "查看会话" })); expect(window.location.search).toBe("");
    expect(screen.getByRole("dialog").textContent).toContain("提交"); await act(async () => resolve());
    expect(window.location.search).toBe(""); expect(screen.queryByRole("heading", { name: "会话列表" })).toBeNull();
  });

  it("retains the unknown command and reports failed logout without unlocking another password write", async () => {
    const iam = repository(); vi.mocked(iam.changePassword).mockRejectedValue(new Error("lost response"));
    vi.mocked(iam.logout).mockRejectedValue(new Error("logout unavailable")); const { user } = await openSelf(iam);
    enterSelfPasswords(); await user.click(screen.getByRole("button", { name: "更新密码" }));
    await user.click(await screen.findByRole("button", { name: "退出并重新登录" }));
    expect(await screen.findByText(/会话仍保留/)).toBeTruthy(); expect(screen.getByText(/本次改密结果未确认/)).toBeTruthy();
    expect(screen.getByRole("button", { name: "更新密码" }).hasAttribute("disabled")).toBe(true); expect(iam.changePassword).toHaveBeenCalledOnce();
  });

  it.each(["Session", "repository"])("clears a draft and ignores a late password completion after a %s change", async (owner) => {
    let resolve!: () => void; const iam = repository(); vi.mocked(iam.changePassword).mockImplementation(() => new Promise<void>((done) => { resolve = done; }));
    const { user, view } = await openSelf(iam); enterSelfPasswords(); await user.click(screen.getByRole("button", { name: "更新密码" }));
    if (owner === "Session") await user.click(screen.getByRole("button", { name: "Test sign in as replacement" }));
    else view.rerender(<SelfPasswordHarness iam={repository()} />);
    await act(async () => resolve());
    expect(screen.queryByRole("status", { name: "改密结果" })).toBeNull(); expect(screen.queryByLabelText("新密码", { exact: true })).toBeNull();
    expect(screen.getByRole("button", { name: owner === "Session" ? "修改本人密码" : "查看未确认的改密" })).toBeTruthy(); expect(navigation.replace).not.toHaveBeenCalled();
  });
});

describe("branded sign-in flows", () => {
  it("explains why a confirmed account-security change requires a new sign-in", async () => {
    const user = userEvent.setup();
    render(<LocaleProvider><SessionProvider repository={repository()}><SecuritySettingsSignOutHarness /></SessionProvider></LocaleProvider>);
    await user.click(screen.getByRole("button", { name: "Establish test Session" }));
    await user.click(await screen.findByRole("button", { name: "Confirm security settings change" }));
    const notice = await screen.findByRole("status");
    expect(notice.textContent).toContain("账号安全规则已更新");
    expect(notice.textContent).toContain("后续请求按新规则重新建立身份上下文");
    expect(notice.textContent).toContain("settings-request-one");
  });

  it("does not navigate or resubmit when required first-login password replacement has an unknown outcome", async () => {
    const iam = repository(true); vi.mocked(iam.changePassword).mockRejectedValue(new HttpProblem(503, "PRIVATE"));
    const { user } = open(iam);
    fireEvent.change(screen.getByLabelText("密码", { exact: true }), { target: { value: "Initial-Test-Password-49!" } });
    await user.click(screen.getByRole("button", { name: "登录控制台" })); await screen.findByRole("heading", { name: "设置你的正式密码" });
    expect(screen.queryByRole("checkbox")).toBeNull();
    fireEvent.change(screen.getByLabelText("当前初始密码"), { target: { value: "Initial-Test-Password-49!" } });
    fireEvent.change(screen.getByLabelText("新密码", { exact: true }), { target: { value: "Changed-Test-Password-73!" } });
    fireEvent.change(screen.getByLabelText("确认新密码"), { target: { value: "Changed-Test-Password-73!" } });
    await user.click(screen.getByRole("button", { name: "保存并进入控制台" }));
    expect(await screen.findByText(/本次改密结果未确认/)).toBeTruthy(); expect(navigation.replace).not.toHaveBeenCalled();
    expect(iam.changePassword).toHaveBeenCalledExactlyOnceWith("memory-only-token", { currentPassword: "Initial-Test-Password-49!", newPassword: "Changed-Test-Password-73!", revokeOtherSessions: true });
    expect((screen.getByLabelText("新密码", { exact: true }) as HTMLInputElement).disabled).toBe(true);
  });
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
    // This journey owns submitted values and guarded navigation, not typing speed.
    fireEvent.change(screen.getByLabelText("子账号登录名"), { target: { value: "developer@tenant-a" } });
    fireEvent.change(screen.getByLabelText("密码", { exact: true }), { target: { value: "Initial-Password-49!" } });
    await user.click(screen.getByRole("button", { name: "登录控制台" }));
    await screen.findByRole("heading", { name: "设置你的正式密码" });
    expect(screen.queryByRole("checkbox", { name: "同时退出其他登录会话（推荐）" })).toBeNull();
    expect(navigation.replace).not.toHaveBeenCalled();
    fireEvent.change(screen.getByLabelText("当前初始密码"), { target: { value: "Initial-Password-49!" } });
    fireEvent.change(screen.getByLabelText("新密码", { exact: true }), { target: { value: "Permanent-Password-49!" } });
    fireEvent.change(screen.getByLabelText("确认新密码"), { target: { value: "Permanent-Password-49!" } });
    await user.click(screen.getByRole("button", { name: "保存并进入控制台" }));
    await waitFor(() => expect(navigation.replace).toHaveBeenCalledExactlyOnceWith(returnTo, { scroll: false }));
    expect(iam.changePassword).toHaveBeenCalledOnce();
    expect(iam.login).toHaveBeenCalledWith({ loginName: "developer@tenant-a", password: "Initial-Password-49!" });
    expect(iam.changePassword).toHaveBeenCalledWith("memory-only-token", { currentPassword: "Initial-Password-49!", newPassword: "Permanent-Password-49!", revokeOtherSessions: true });
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
  it("keeps a real first-enrollment challenge sessionless until one-time codes are acknowledged", async () => {
    const expiresAt = "2099-09-01T00:05:00Z";
    const challenge = { id: "enrollment-one", purpose: "ENROLLMENT" as const, nextStep: "ENROLLMENT" as const, expiresAt };
    const codes = Array.from({ length: 10 }, (_, index) => `REAL-RECOVERY-${index}`);
    const iam = repository();
    iam.login = vi.fn().mockResolvedValue({ outcome: "CHALLENGE_REQUIRED", challenge, challengeCredential: "private-enrollment-credential" });
    const contact = { accountId: "account-one", userId: "user-one", state: "VERIFIED" as const,
      resourceVersion: 1, email: "user@example.invalid", verifiedAt: "2099-09-01T00:00:00Z", pendingVerificationId: null };
    const enrollment = { id: "factor-one", requestId: "ui-first-factor-1", purpose: "INITIAL" as const, factorRevision: 1,
      state: "PENDING" as const, createdAt: "2099-09-01T00:01:00Z", expiresAt: "2099-09-01T00:04:00Z", completedAt: null };
    iam.authenticationChallenges = {
      verify: vi.fn(), changePassword: vi.fn(),
      inspectFirstEnrollment: vi.fn().mockResolvedValue({ challenge, notificationContact: contact }),
      startFirstTOTP: vi.fn().mockImplementation(async (command: { requestId: string }) => ({ outcome: "APPLIED",
        enrollment: { ...enrollment, requestId: command.requestId }, provisioning: { seed: "JBSWY3DPEHPK3PXP", uri: "otpauth://totp/Matrix:user?secret=JBSWY3DPEHPK3PXP" } })),
      confirmFirstTOTP: vi.fn().mockImplementation(async () => ({ nextStep: "REAUTHENTICATE",
        enrollment: { ...enrollment, requestId: "ui-first-factor-1", state: "CONFIRMED", completedAt: "2099-09-01T00:03:00Z" }, recoveryCodes: codes }))
    };
    const { user } = open(iam);
    await user.type(screen.getByLabelText("密码", { exact: true }), "Initial-Password-49!");
    await user.click(screen.getByRole("button", { name: "登录控制台" }));
    expect(await screen.findByRole("heading", { name: "设置登录身份验证器" })).toBeTruthy();
    expect(await screen.findByRole("button", { name: "开始绑定身份验证器" })).toBeTruthy();
    expect(navigation.replace).not.toHaveBeenCalled();
    expect(document.body.textContent).not.toContain("private-enrollment-credential");
    await user.click(screen.getByRole("button", { name: "开始绑定身份验证器" }));
    expect(await screen.findByText("JBSWY3DPEHPK3PXP")).toBeTruthy();
    expect(screen.getByRole("img", { name: "身份验证器设置二维码" })).toBeTruthy();
    await user.type(screen.getByLabelText("身份验证器 6 位动态验证码"), "123456");
    await user.click(screen.getByRole("button", { name: "确认绑定" }));
    expect(await screen.findByRole("heading", { name: "保存一次性恢复码" })).toBeTruthy();
    expect(screen.getAllByText(/^REAL-RECOVERY-/)).toHaveLength(10);
    expect(document.body.textContent).not.toContain("JBSWY3DPEHPK3PXP");
    expect(screen.queryByRole("img", { name: "身份验证器设置二维码" })).toBeNull();
    expect(navigation.replace).not.toHaveBeenCalled();
    expect(localStorage.length + sessionStorage.length).toBe(0);
    await user.click(screen.getByRole("checkbox", { name: /安全保存/ }));
    await user.click(screen.getByRole("button", { name: /重新登录/ }));
    expect(await screen.findByRole("heading", { name: "身份验证器已绑定" })).toBeTruthy();
    expect(document.body.textContent).not.toContain("REAL-RECOVERY-0");
    expect(navigation.replace).not.toHaveBeenCalled();
  });
  it("does not show a secret or create a Session when enrollment state reports material already pending", async () => {
    const challenge = { id: "enrollment-lost", purpose: "ENROLLMENT" as const, nextStep: "ENROLLMENT" as const,
      expiresAt: "2099-09-01T00:05:00Z" };
    const iam = repository();
    iam.login = vi.fn().mockResolvedValue({ outcome: "CHALLENGE_REQUIRED", challenge, challengeCredential: "private-lost-credential" });
    iam.authenticationChallenges = { verify: vi.fn(), changePassword: vi.fn(),
      inspectFirstEnrollment: vi.fn().mockResolvedValue({ challenge,
        notificationContact: { accountId: "account-one", userId: "user-one", state: "VERIFIED", resourceVersion: 1,
          email: "user@example.invalid", verifiedAt: "2099-09-01T00:00:00Z", pendingVerificationId: null },
        enrollment: { id: "pending-one", requestId: "original-start", purpose: "INITIAL", factorRevision: 1,
          state: "PENDING", createdAt: "2099-09-01T00:01:00Z", expiresAt: challenge.expiresAt, completedAt: null } }) };
    const { user } = open(iam);
    await user.type(screen.getByLabelText("密码", { exact: true }), "Initial-Password-49!");
    await user.click(screen.getByRole("button", { name: "登录控制台" }));
    expect(await screen.findByText(/一次性密钥已丢失/)).toBeTruthy();
    expect(screen.queryByText("JBSWY3DPEHPK3PXP")).toBeNull();
    expect(screen.queryByRole("img", { name: "身份验证器设置二维码" })).toBeNull();
    expect(navigation.replace).not.toHaveBeenCalled();
    expect(document.body.textContent).not.toContain("private-lost-credential");
  });
  it("verifies a first notification address before enabling factor enrollment", async () => {
    const challenge = { id: "enrollment-contact", purpose: "ENROLLMENT" as const, nextStep: "ENROLLMENT" as const,
      expiresAt: "2099-09-01T00:05:00Z" };
    const none = { accountId: "account-one", userId: "user-one", state: "NONE" as const, resourceVersion: 0 as const,
      pendingVerificationId: null };
    const verified = { accountId: "account-one", userId: "user-one", state: "VERIFIED" as const,
      resourceVersion: 1, email: "user@example.com", verifiedAt: "2099-09-01T00:00:00Z", pendingVerificationId: null };
    const iam = repository();
    iam.login = vi.fn().mockResolvedValue({ outcome: "CHALLENGE_REQUIRED", challenge, challengeCredential: "private-contact-credential" });
    iam.authenticationChallenges = { verify: vi.fn(), changePassword: vi.fn(),
      inspectFirstEnrollment: vi.fn().mockResolvedValueOnce({ challenge, notificationContact: none })
        .mockResolvedValueOnce({ challenge, notificationContact: verified }),
      startFirstContact: vi.fn().mockImplementation(async (command: { email: string; requestId: string }) => ({
        id: "verification-one", accountId: none.accountId, userId: none.userId, email: command.email,
        requestId: command.requestId, state: "PENDING", issuedAt: "2099-09-01T00:00:00Z",
        expiresAt: "2099-09-01T00:05:00Z", completedAt: null,
        delivery: { state: "PENDING", attempts: 0, lastOutcome: null, lastSmtpCode: null, updatedAt: "2099-09-01T00:00:00Z" }
      })),
      confirmFirstContact: vi.fn().mockResolvedValue({ id: "verification-one", accountId: none.accountId,
        userId: none.userId, email: "user@example.com", state: "VERIFIED" }),
      startFirstTOTP: vi.fn()
    };
    const { user } = open(iam);
    await user.type(screen.getByLabelText("密码", { exact: true }), "Initial-Password-49!");
    await user.click(screen.getByRole("button", { name: "登录控制台" }));
    expect(await screen.findByLabelText("安全通知邮箱")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "开始绑定身份验证器" })).toBeNull();
    await user.type(screen.getByLabelText("安全通知邮箱"), "user@example.com");
    await user.click(screen.getByRole("button", { name: "发送地址验证码" }));
    expect(await screen.findByLabelText("邮箱 8 位验证码")).toBeTruthy();
    expect(iam.authenticationChallenges.startFirstTOTP).not.toHaveBeenCalled();
    await user.type(screen.getByLabelText("邮箱 8 位验证码"), "00123456");
    await user.click(screen.getByRole("button", { name: "验证邮箱" }));
    expect(await screen.findByRole("button", { name: "开始绑定身份验证器" })).toBeTruthy();
    expect(iam.authenticationChallenges.confirmFirstContact).toHaveBeenCalledWith(expect.objectContaining({
      challengeId: "enrollment-contact", challengeCredential: "private-contact-credential", code: "00123456"
    }));
    expect(navigation.replace).not.toHaveBeenCalled();
    expect(localStorage.length + sessionStorage.length).toBe(0);
  });
  it("requires a fresh enrollment challenge after restricted initial password change", async () => {
    const expiresAt = "2099-09-01T00:05:00Z";
    const passwordChallenge = { id: "initial-password", purpose: "ENROLLMENT" as const,
      nextStep: "PASSWORD_CHANGE" as const, expiresAt };
    const enrollmentChallenge = { id: "initial-factor", purpose: "ENROLLMENT" as const,
      nextStep: "ENROLLMENT" as const, expiresAt };
    const iam = repository();
    iam.login = vi.fn().mockResolvedValueOnce({ outcome: "CHALLENGE_REQUIRED", challenge: passwordChallenge,
      challengeCredential: "old-restricted-credential" })
      .mockResolvedValueOnce({ outcome: "CHALLENGE_REQUIRED", challenge: enrollmentChallenge,
        challengeCredential: "new-restricted-credential" });
    iam.authenticationChallenges = {
      verify: vi.fn(), changePassword: vi.fn().mockResolvedValue({ nextStep: "REAUTHENTICATE", changedAt: "2099-09-01T00:01:00Z" }),
      inspectFirstEnrollment: vi.fn().mockResolvedValue({ challenge: enrollmentChallenge,
        notificationContact: { accountId: "account-one", userId: "user-one", state: "VERIFIED", resourceVersion: 1,
          email: "user@example.invalid", verifiedAt: "2099-09-01T00:00:00Z", pendingVerificationId: null } })
    };
    const { user } = open(iam);
    await user.type(screen.getByLabelText("密码", { exact: true }), "Initial-Password-49!");
    await user.click(screen.getByRole("button", { name: "登录控制台" }));
    expect(await screen.findByRole("heading", { name: "首次设置前，请更新初始密码" })).toBeTruthy();
    expect(iam.authenticationChallenges.inspectFirstEnrollment).not.toHaveBeenCalled();
    await user.type(screen.getByLabelText("新密码", { exact: true }), "Replacement-Password-49!");
    await user.type(screen.getByLabelText("确认新密码"), "Replacement-Password-49!");
    await user.click(screen.getByRole("button", { name: "更新密码" }));
    expect(await screen.findByText(/旧挑战不能沿用/)).toBeTruthy();
    expect(navigation.replace).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "返回登录" }));
    await user.type(screen.getByLabelText("密码", { exact: true }), "Replacement-Password-49!");
    await user.click(screen.getByRole("button", { name: "登录控制台" }));
    expect(await screen.findByRole("button", { name: "开始绑定身份验证器" })).toBeTruthy();
    expect(iam.authenticationChallenges.inspectFirstEnrollment).toHaveBeenCalledWith({
      challengeId: "initial-factor", challengeCredential: "new-restricted-credential"
    });
    expect(navigation.replace).not.toHaveBeenCalled();
  });
  it("keeps the MFA preview sessionless until the challenge is complete", async () => {
    const { user } = open(previewIamRepository);
    await user.click(screen.getByRole("button", { name: "体验 MFA 登录挑战" }));
    expect(screen.getByRole("heading", { name: "完成安全验证" })).toBe(document.activeElement);
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
    await user.click(screen.getByRole("checkbox", { name: "我已安全保存全部恢复码" }));
    await user.click(screen.getByRole("button", { name: "完成并重新登录" }));
    expect(await screen.findByRole("heading", { name: "身份验证器已绑定" })).toBe(document.activeElement);
    expect(screen.getByText("一次性恢复码已交付。请重新登录并使用新绑定的身份验证器。")).toBeTruthy();
    expect(screen.queryByRole("heading", { name: "密码已更新" })).toBeNull();
  });
  it("requires a fresh login after challenge-bound password replacement", async () => {
    const { user } = open(previewIamRepository);
    await user.click(screen.getByRole("button", { name: "体验 MFA 登录挑战" }));
    await user.type(screen.getByLabelText("6 位动态验证码"), "624811");
    await user.click(screen.getByRole("button", { name: "验证并登录" }));
    expect(await screen.findByRole("heading", { name: "验证完成，请更新密码" })).toBe(document.activeElement);
    expect(navigation.replace).not.toHaveBeenCalled();
    await user.type(screen.getByLabelText("新密码", { exact: true }), "Replacement-Password-49!");
    await user.type(screen.getByLabelText("确认新密码"), "Replacement-Password-49!");
    await user.click(screen.getByRole("button", { name: "更新密码" }));
    expect(await screen.findByRole("heading", { name: "密码已更新" })).toBe(document.activeElement);
    expect(navigation.replace).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "返回登录" }));
    expect(screen.getByRole("heading", { name: "登录控制台" })).toBeTruthy();
    expect(localStorage.length + sessionStorage.length).toBe(0);
  });
  it("shows an unconfirmed password change without offering the old challenge again", async () => {
    const iam = repository();
    iam.login = vi.fn().mockResolvedValue({ outcome: "CHALLENGE_REQUIRED", challenge: {
      id: "challenge-password", purpose: "LOGIN", nextStep: "PASSWORD_CHANGE", expiresAt: "2099-09-20T01:07:03Z"
    }, challengeCredential: "private-password-challenge" });
    const changePassword = vi.fn().mockRejectedValue(new Error("private network failure"));
    iam.authenticationChallenges = { verify: vi.fn(), changePassword };
    const { user } = open(iam);
    await user.click(screen.getByRole("button", { name: "体验 MFA 登录挑战" }));
    expect(await screen.findByRole("heading", { name: "验证完成，请更新密码" })).toBeTruthy();
    await user.type(screen.getByLabelText("新密码", { exact: true }), "Replacement-Password-49!");
    await user.type(screen.getByLabelText("确认新密码"), "Replacement-Password-49!");
    await user.click(screen.getByRole("button", { name: "更新密码" }));
    expect(await screen.findByRole("heading", { name: "无法确认密码是否已更新" })).toBe(document.activeElement);
    expect(screen.getByRole("alert").textContent).toContain("请勿重复提交此挑战");
    expect(screen.queryByRole("button", { name: "更新密码" })).toBeNull();
    expect(document.body.textContent).not.toContain("private-password-challenge");
    expect(document.body.textContent).not.toContain("private network failure");
    expect(changePassword).toHaveBeenCalledTimes(1);
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
    // This case owns submitted values and correction. Keyboard/reveal behavior
    // is covered separately rather than timing a hundred synthetic keystrokes.
    fireEvent.change(screen.getByLabelText("密码", { exact: true }), { target: { value: "Initial-Password-49!" } });
    await user.click(screen.getByRole("button", { name: "登录控制台" }));
    await screen.findByRole("heading", { name: "设置你的正式密码" });
    expect(navigation.replace).not.toHaveBeenCalled();
    fireEvent.change(screen.getByLabelText("当前初始密码"), { target: { value: "Initial-Password-49!" } });
    fireEvent.change(screen.getByLabelText("新密码", { exact: true }), { target: { value: "Permanent-Password-49!" } });
    fireEvent.change(screen.getByLabelText("确认新密码"), { target: { value: "Different-Password-49!" } });
    await user.click(screen.getByRole("button", { name: "保存并进入控制台" }));
    expect(screen.getByRole("alert").textContent).toContain("不一致");
    expect(iam.changePassword).not.toHaveBeenCalled();
    fireEvent.change(screen.getByLabelText("确认新密码"), { target: { value: "Permanent-Password-49!" } });
    await user.click(screen.getByRole("button", { name: "保存并进入控制台" }));
    await waitFor(() => expect(navigation.replace).toHaveBeenCalledWith("/console/resources/", { scroll: false }));
    expect(iam.changePassword).toHaveBeenCalledWith("memory-only-token", { currentPassword: "Initial-Password-49!", newPassword: "Permanent-Password-49!", revokeOtherSessions: true });
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
