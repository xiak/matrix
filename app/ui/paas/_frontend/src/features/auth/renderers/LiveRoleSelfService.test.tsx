import { act, cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { HttpProblem } from "@/infrastructure/http/jsonRequest";
import { LocaleProvider } from "@/i18n/LocaleProvider";
import { SessionProvider, useSession } from "../application/SessionProvider";
import type { IamRepository } from "../repositories/iamRepository";
import { LiveRoleSelfService } from "./LiveRoleSelfService";

const session = {
  id: "login-session-a", organizationId: "account-a", principalId: "user-a", status: "ACTIVE" as const,
  issuedAt: "2099-09-29T08:00:00Z", expiresAt: "2099-09-29T20:00:00Z"
};
const role = {
  roleId: "role-reviewer", accountId: "account-a", name: "ReviewerRole", status: "ACTIVE" as const,
  maxSessionDurationSeconds: 3600, resourceVersion: 4,
  capability: { action: "iam.role.assume" as const, resource: { kind: "ROLE" as const, id: "role-reviewer" }, available: true as const, restrictionReason: null }
};
const roleSession = {
  apiVersion: "unused", kind: "unused",
  id: "role-session-a", accountId: "account-a", roleId: "role-reviewer", sourceUserId: "user-a", status: "ACTIVE" as const,
  issuedAt: "2099-09-29T09:00:00Z", expiresAt: "2099-09-29T10:00:00Z", revokedAt: null
};
const assumableDirectory = { accountId: "account-a", sourceUserId: "user-a", items: [role], nextAfter: null };

function repository(listAssumable: NonNullable<IamRepository["roleSelfService"]>["listAssumable"] = vi.fn(async () => assumableDirectory)): IamRepository {
  return {
    login: vi.fn(async () => ({ outcome: "AUTHENTICATED" as const, session, credential: "user-secret", mustChangePassword: false })),
    changePassword: vi.fn(async () => undefined),
    logout: vi.fn(async () => undefined),
    roleSelfService: {
      listAssumable,
      assume: vi.fn(async () => ({ outcome: "APPLIED" as const, session: roleSession, credential: "role-secret" })),
      readByRequest: vi.fn(async () => roleSession),
      revokeByRequest: vi.fn(async () => ({ ...roleSession, status: "REVOKED" as const, revokedAt: "2099-09-29T09:05:00Z" })),
      currentIdentity: vi.fn(async () => ({
        session: roleSession,
        account: { id: "account-a", displayName: "Xiak" },
        role: { id: "role-reviewer", name: "ReviewerRole" },
        sourceUser: { id: "user-a", loginName: "qiao", displayName: "Qiao" }
      })),
      logout: vi.fn(async () => ({ ...roleSession, status: "REVOKED" as const, revokedAt: "2099-09-29T09:05:00Z" })),
      revalidateSource: vi.fn(async () => undefined)
    }
  };
}

function Harness() {
  const auth = useSession();
  return auth.phase === "authenticated" ? <LiveRoleSelfService /> : <button onClick={() => void auth.login("qiao", "password")}>login</button>;
}

afterEach(cleanup);

describe("LiveRoleSelfService", () => {
  it("keeps source identity and the discovery structure mounted while role data loads", async () => {
    let resolveDirectory!: (value: typeof assumableDirectory) => void;
    const listAssumable = vi.fn(() => new Promise<typeof assumableDirectory>((resolve) => { resolveDirectory = resolve; }));
    const user = userEvent.setup();
    render(<LocaleProvider><SessionProvider repository={repository(listAssumable)}><Harness /></SessionProvider></LocaleProvider>);
    await user.click(screen.getByRole("button", { name: "login" }));

    expect(screen.getByRole("heading", { name: "角色会话" })).toBeTruthy();
    expect(screen.getByRole("heading", { name: "来源身份" })).toBeTruthy();
    expect(screen.getByRole("heading", { name: "可承担角色" })).toBeTruthy();
    expect(screen.getByText("角色会话只提供临时业务权限", { exact: false })).toBeTruthy();
    expect(await screen.findByText("正在发现可承担角色")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "审阅并承担 ReviewerRole" })).toBeNull();

    await act(async () => { resolveDirectory(assumableDirectory); });
    expect(await screen.findByRole("button", { name: "审阅并承担 ReviewerRole" })).toBeTruthy();
    expect(listAssumable).toHaveBeenCalledTimes(1);
  });

  it("keeps source identity stable and retries a failed role-directory read in place", async () => {
    let resolveDirectory!: (value: typeof assumableDirectory) => void;
    const listAssumable = vi.fn()
      .mockRejectedValueOnce(new HttpProblem(503, "IAM_UNAVAILABLE"))
      .mockImplementationOnce(() => new Promise<typeof assumableDirectory>((resolve) => { resolveDirectory = resolve; }));
    const user = userEvent.setup();
    render(<LocaleProvider><SessionProvider repository={repository(listAssumable)}><Harness /></SessionProvider></LocaleProvider>);
    await user.click(screen.getByRole("button", { name: "login" }));

    expect(await screen.findByRole("button", { name: "重试读取" })).toBeTruthy();
    expect(screen.getByRole("heading", { name: "来源身份" })).toBeTruthy();
    expect(screen.getByRole("heading", { name: "可承担角色" })).toBeTruthy();
    expect(screen.getByText("当前身份没有改变，也没有创建角色会话。可重试同一目录读取。")).toBeTruthy();
    expect(screen.queryByRole("dialog")).toBeNull();

    await user.click(screen.getByRole("button", { name: "重试读取" }));
    expect(screen.getByText("正在发现可承担角色")).toBeTruthy();
    await act(async () => { resolveDirectory(assumableDirectory); });
    expect(await screen.findByRole("button", { name: "审阅并承担 ReviewerRole" })).toBeTruthy();
    expect(listAssumable).toHaveBeenCalledTimes(2);
  });

  it("renders fixed source context before data and activates the verified role inline", async () => {
    const user = userEvent.setup();
    render(<LocaleProvider><SessionProvider repository={repository()}><Harness /></SessionProvider></LocaleProvider>);
    await user.click(screen.getByRole("button", { name: "login" }));
    expect(screen.getByRole("heading", { name: "角色会话" })).toBeTruthy();
    expect(screen.getByText("账号与用户由当前登录凭据确定", { exact: false })).toBeTruthy();
    await user.click(await screen.findByRole("button", { name: "审阅并承担 ReviewerRole" }));
    expect(screen.getByRole("heading", { name: "审阅角色会话" })).toBeTruthy();
    expect(screen.queryByRole("dialog")).toBeNull();
    await user.click(screen.getByRole("button", { name: "承担角色" }));
    expect(await screen.findByRole("heading", { name: "当前角色身份" })).toBeTruthy();
    expect(screen.getByText("每个业务请求仍需重新检查来源用户", { exact: false })).toBeTruthy();
  });
});
