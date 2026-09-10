import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { LocaleProvider } from "@/i18n/LocaleProvider";
import { HttpProblem } from "@/infrastructure/http/jsonRequest";
import { SessionProvider } from "../application/SessionProvider";
import type { IamRepository } from "../repositories/iamRepository";
import { LoginRenderer } from "./LoginRenderer";

const navigation = vi.hoisted(() => ({ replace: vi.fn() }));
vi.mock("next/navigation", () => ({ useRouter: () => navigation }));
vi.mock("@/infrastructure/runtime/uxPreviewMode", () => ({ uxPreviewEnabled: true }));
const session = { id: "test-session", organizationId: "org-test", principalId: "p-test", status: "ACTIVE" as const,
  issuedAt: "2026-09-01T00:00:00Z", expiresAt: "2099-09-01T00:00:00Z" };
function repository(mustChangePassword = false): IamRepository {
  return { login: vi.fn().mockResolvedValue({ credential: "memory-only-token", mustChangePassword, session }),
    logout: vi.fn().mockResolvedValue(undefined), changePassword: vi.fn().mockResolvedValue(undefined) };
}
function open(iam = repository(), returnTo: string | undefined = "/console/resources/") {
  const user = userEvent.setup();
  render(<LocaleProvider><SessionProvider repository={iam}><LoginRenderer returnTo={returnTo} /></SessionProvider></LocaleProvider>);
  return { user, iam };
}
afterEach(() => { cleanup(); localStorage.clear(); sessionStorage.clear(); vi.clearAllMocks(); });

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
    await waitFor(() => expect(navigation.replace).toHaveBeenCalledExactlyOnceWith("/console/"));
  });

  it("returns an IAM user to a requested resource page", async () => {
    const { user } = open();
    await user.click(screen.getByRole("tab", { name: "IAM 子账号" }));
    await user.type(screen.getByLabelText("子账号登录名"), "developer@tenant-a");
    await user.type(screen.getByLabelText("密码", { exact: true }), "Only-Test-Password-49!");
    await user.click(screen.getByRole("button", { name: "登录控制台" }));
    await waitFor(() => expect(navigation.replace).toHaveBeenCalledExactlyOnceWith("/console/resources/"));
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
    await waitFor(() => expect(navigation.replace).toHaveBeenCalledExactlyOnceWith(returnTo));
    expect(iam.changePassword).toHaveBeenCalledOnce();
  });

  it("keeps the preview a separate explicit action and does not persist credentials", async () => {
    const { user, iam } = open();
    await user.type(screen.getByLabelText("密码", { exact: true }), "Unsubmitted-secret-49!");
    await user.click(screen.getByRole("button", { name: "一键进入体验控制台" }));
    expect(iam.login).toHaveBeenCalledWith({ loginName: "preview-admin", password: "experience-only" });
    expect(navigation.replace).toHaveBeenCalledWith("/console/resources/");
    expect((screen.getByLabelText("密码", { exact: true }) as HTMLInputElement).value).toBe("");
    expect(localStorage.length + sessionStorage.length).toBe(0);
    expect(document.body.textContent).not.toContain("memory-only-token");
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
    await waitFor(() => expect(navigation.replace).toHaveBeenCalledWith("/console/resources/"));
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
