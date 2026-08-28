import { act, cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { HttpProblem } from "@/infrastructure/http/jsonRequest";
import { SessionProvider, useSession } from "../application/SessionProvider";
import type { Account, AccountIdentity, AccountPrincipal, AccountUser } from "../domain/accounts";
import type { AccountRepository, IamRepository } from "../repositories/iamRepository";
import { AccountAccessRenderer } from "./AccountAccessRenderer";
import { LoginRenderer } from "./LoginRenderer";

const navigation = vi.hoisted(() => ({ replace: vi.fn() }));
vi.mock("next/navigation", () => ({ useRouter: () => navigation }));
const credential = "account-test-only-memory-credential";
const principal: AccountPrincipal = { id: "primary-a", organizationId: "tenant-a", loginName: "admin", displayName: "Account owner", status: "ACTIVE", resourceVersion: 2, mustChangePassword: false };
const identity: AccountIdentity = {
  account: { organization: { id: "tenant-a", displayName: "Team A", status: "ACTIVE", resourceVersion: 1 }, primaryPrincipalId: "primary-a", primaryLoginName: "admin", loginAlias: null },
  principal, roles: ["ORGANIZATION_ADMIN", "PLATFORM_OPERATOR"], canCreateOrganizations: true
};
const child: AccountUser = { principal: { ...principal, id: "child-a", loginName: "developer", displayName: "Developer A" }, roleBindings: [{ id: "binding-child", organizationId: "tenant-a", principalId: "child-a", role: "PAAS_VIEWER" }] };
const customer: Account = { organization: { id: "tenant-b", displayName: "Team B", status: "ACTIVE", resourceVersion: 4 }, primaryPrincipalId: "primary-b", primaryLoginName: "owner-b", loginAlias: null };
const platformIdentity: AccountIdentity = { ...identity, principal: child.principal, roles: ["PLATFORM_OPERATOR"] };

function iam(overrides: Partial<IamRepository> = {}, id = "primary-a"): IamRepository {
  return {
    login: vi.fn().mockResolvedValue({ credential, mustChangePassword: false, session: { id: "session-test", organizationId: "tenant-a", principalId: id, status: "ACTIVE", issuedAt: "2026-08-27T00:00:00Z", expiresAt: "2099-08-27T00:00:00Z" } }),
    changePassword: vi.fn(), logout: vi.fn(), ...overrides
  };
}

function accounts(overrides: Partial<AccountRepository> = {}): AccountRepository {
  return {
    currentIdentity: vi.fn().mockResolvedValue(structuredClone(identity)),
    listUsers: vi.fn().mockResolvedValue({ items: [{ principal, roleBindings: [] }, child], nextAfter: null }),
    listAccounts: vi.fn().mockResolvedValue({ items: [identity.account], nextAfter: null }),
    execute: vi.fn().mockResolvedValue(undefined), ...overrides
  };
}

function AuthenticatedAccess({ repository }: { repository: AccountRepository }) {
  const session = useSession();
  return session.phase === "authenticated" || session.phase === "updating-password" ? <AccountAccessRenderer repository={repository} /> : <LoginRenderer />;
}

async function openAccess(repository = accounts(), iamRepository = iam()) {
  const user = userEvent.setup();
  const view = render(<SessionProvider repository={iamRepository}><AuthenticatedAccess repository={repository} /></SessionProvider>);
  await user.type(screen.getByLabelText("密码", { exact: true }), "Only-Test-Password-49!");
  await user.click(screen.getByRole("button", { name: "登录控制台" }));
  await waitFor(() => expect(repository.currentIdentity).toHaveBeenCalledWith(credential));
  return { user, view, repository };
}

afterEach(() => { cleanup(); vi.clearAllMocks(); localStorage.clear(); sessionStorage.clear(); });

describe("qualified login", () => {
  it("forces other temporary sessions out, clears pending passwords and retains only the verified current session", async () => {
    let complete!: () => void;
    const source = iam({
      login: vi.fn().mockResolvedValue({ credential, mustChangePassword: true, session: {
        id: "session-forced", organizationId: "tenant-a", principalId: "child-a", status: "ACTIVE",
        issuedAt: "2026-08-28T00:00:00Z", expiresAt: "2099-08-28T00:00:00Z"
      } }),
      changePassword: vi.fn().mockImplementation(() => new Promise<void>((resolve) => { complete = resolve; }))
    });
    const repository = accounts({ currentIdentity: vi.fn().mockResolvedValue({ ...identity, principal: child.principal, roles: [], canCreateOrganizations: false }) });
    const user = userEvent.setup();
    render(<SessionProvider repository={source}><AuthenticatedAccess repository={repository} /></SessionProvider>);
    await user.click(screen.getByRole("button", { name: "IAM 子账号" }));
    await user.type(screen.getByLabelText("子账号登录名"), "developer@tenant-a");
    await user.type(screen.getByLabelText("密码", { exact: true }), "Temporary-Test-Password-49!");
    await user.click(screen.getByRole("button", { name: "登录控制台" }));
    await screen.findByRole("heading", { name: "设置你的正式密码" });
    expect(screen.queryByRole("checkbox")).toBeNull();
    expect(repository.currentIdentity).not.toHaveBeenCalled();
    await user.type(screen.getByLabelText("当前初始密码"), "Temporary-Test-Password-49!");
    await user.type(screen.getByLabelText("新密码", { exact: true }), "Replacement-Test-Password-73!");
    await user.type(screen.getByLabelText("确认新密码", { exact: true }), "Replacement-Test-Password-73!");
    await user.click(screen.getByRole("button", { name: "保存并进入控制台" }));
    expect(source.changePassword).toHaveBeenCalledWith(credential, {
      currentPassword: "Temporary-Test-Password-49!", newPassword: "Replacement-Test-Password-73!", revokeOtherSessions: true
    });
    expect((screen.getByLabelText("当前初始密码") as HTMLInputElement).disabled).toBe(true);
    expect(screen.queryByDisplayValue("Temporary-Test-Password-49!")).toBeNull();
    expect(screen.queryByDisplayValue("Replacement-Test-Password-73!")).toBeNull();
    await act(async () => complete());
    await waitFor(() => expect(repository.currentIdentity).toHaveBeenCalledWith(credential));
    expect(navigation.replace).toHaveBeenCalledWith("/console/access/");
    expect(screen.queryByRole("heading", { name: "设置你的正式密码" })).toBeNull();
    expect(localStorage.length + sessionStorage.length).toBe(0);
  });

  it("uses one text identifier, clears secrets on mode change, and preserves IAM's account namespace", async () => {
    const repository = iam();
    const user = userEvent.setup();
    render(<SessionProvider repository={repository}><LoginRenderer /></SessionProvider>);
    await user.type(screen.getByLabelText("密码", { exact: true }), "Previous-mode-secret-49!");
    await user.click(screen.getByRole("button", { name: "IAM 子账号" }));
    expect((screen.getByLabelText("密码", { exact: true }) as HTMLInputElement).value).toBe("");
    const field = screen.getByLabelText("子账号登录名") as HTMLInputElement;
    expect(field.type).toBe("text");
    await user.type(field, "developer@tenant-a");
    await user.type(screen.getByLabelText("密码", { exact: true }), "Only-Test-Password-49!");
    await user.click(screen.getByRole("button", { name: "登录控制台" }));
    await waitFor(() => expect(repository.login).toHaveBeenCalledWith({ loginName: "developer@tenant-a", password: "Only-Test-Password-49!" }));
    expect(navigation.replace).toHaveBeenCalledWith("/console/access/");
    expect(localStorage.length + sessionStorage.length).toBe(0);
  });

  it("does not submit an unqualified child or leak prior authentication errors between modes", async () => {
    const repository = iam({ login: vi.fn().mockRejectedValue(new HttpProblem(401, "private upstream")) });
    const user = userEvent.setup();
    render(<SessionProvider repository={repository}><LoginRenderer /></SessionProvider>);
    await user.type(screen.getByLabelText("密码", { exact: true }), "Wrong-Password-49!");
    await user.click(screen.getByRole("button", { name: "登录控制台" }));
    await screen.findByRole("alert");
    await user.click(screen.getByRole("button", { name: "IAM 子账号" }));
    expect(screen.queryByRole("alert")).toBeNull();
    await user.type(screen.getByLabelText("子账号登录名"), "developer");
    await user.type(screen.getByLabelText("密码", { exact: true }), "Only-Test-Password-49!");
    await user.click(screen.getByRole("button", { name: "登录控制台" }));
    expect(screen.getByRole("alert").textContent).toContain("主账号ID或别名");
    expect(repository.login).toHaveBeenCalledTimes(1);
  });
});

describe("account access", () => {
  it.each([true, false])("offers a default-on ordinary password session choice, including for a child (%s)", async (revokeOtherSessions) => {
    let complete!: () => void;
    const passwordRepository = iam({ changePassword: vi.fn().mockImplementation(() => new Promise<void>((resolve) => { complete = resolve; })) }, "child-a");
    const repository = accounts({ currentIdentity: vi.fn().mockResolvedValue({ ...identity, principal: child.principal, roles: [], canCreateOrganizations: false }) });
    const { user, view } = await openAccess(repository, passwordRepository);
    await user.click(await screen.findByRole("button", { name: "用户设置" }));
    const option = screen.getByRole("checkbox", { name: "同时退出其他登录会话（推荐）" }) as HTMLInputElement;
    expect(option.checked).toBe(true);
    if (!revokeOtherSessions) await user.click(option);
    await user.type(screen.getByLabelText("当前密码", { exact: true }), "Current-Only-Test-Password-49!");
    await user.type(screen.getByLabelText("新密码", { exact: true }), "New-Only-Test-Password-73!");
    await user.type(screen.getByLabelText("确认新密码", { exact: true }), "New-Only-Test-Password-73!");
    await user.click(screen.getByRole("button", { name: "更新密码" }));
    expect(passwordRepository.changePassword).toHaveBeenCalledWith(credential, {
      currentPassword: "Current-Only-Test-Password-49!", newPassword: "New-Only-Test-Password-73!", revokeOtherSessions
    });
    expect((screen.getByRole("button", { name: "正在更新密码…" }) as HTMLButtonElement).disabled).toBe(true);
    expect(screen.queryByDisplayValue("Current-Only-Test-Password-49!")).toBeNull();
    expect(screen.queryByDisplayValue("New-Only-Test-Password-73!")).toBeNull();
    await act(async () => complete());
    expect((await screen.findByRole("status")).textContent).toContain(revokeOtherSessions ? "其他登录会话已退出" : "其他仍有效的登录会话保留");
    expect(view.container.innerHTML).not.toContain(credential);
    expect(localStorage.length + sessionStorage.length).toBe(0);
  });

  it("does not send mismatched passwords or claim success after a revoked session", async () => {
    const source = iam({ changePassword: vi.fn().mockRejectedValue(new HttpProblem(401, "private authentication detail")) });
    const { user } = await openAccess(accounts(), source);
    await user.click(await screen.findByRole("button", { name: "用户设置" }));
    await user.type(screen.getByLabelText("当前密码", { exact: true }), "Current-Only-Test-Password-49!");
    await user.type(screen.getByLabelText("新密码", { exact: true }), "New-Only-Test-Password-73!");
    await user.type(screen.getByLabelText("确认新密码", { exact: true }), "Another-Only-Test-Password-84!");
    await user.click(screen.getByRole("button", { name: "更新密码" }));
    expect(screen.getByRole("alert").textContent).toContain("两次输入的新密码不一致");
    expect(source.changePassword).not.toHaveBeenCalled();
    await user.clear(screen.getByLabelText("确认新密码", { exact: true }));
    await user.type(screen.getByLabelText("确认新密码", { exact: true }), "New-Only-Test-Password-73!");
    await user.click(screen.getByRole("button", { name: "更新密码" }));
    await screen.findByRole("button", { name: "登录控制台" });
    expect(screen.getByRole("alert").textContent).toContain("重新登录");
    expect(screen.queryByText("密码已更新", { exact: false })).toBeNull();
    expect(screen.queryByDisplayValue("New-Only-Test-Password-73!")).toBeNull();
  });

  it("separates the resource owner from subusers and defaults creation to no business grant", async () => {
    const { user, repository, view } = await openAccess();
    await screen.findByText("Developer A");
    expect(screen.queryByRole("button", { name: "管理 admin" })).toBeNull();
    expect(screen.getByText("所属租户 · 资源归属")).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "创建用户" }));
    await user.type(screen.getByLabelText(/^子用户名/), "new.developer");
    await user.type(screen.getByLabelText("用户显示名称"), "New Developer");
    await user.type(screen.getByLabelText(/^初始密码/), "New-Child-Test-Password-49!");
    expect((screen.getByLabelText(/^初始权限/) as HTMLSelectElement).value).toBe("");
    await user.click(within(screen.getByRole("form", { name: "创建子用户" })).getByRole("button", { name: "创建用户" }));
    await waitFor(() => expect(repository.execute).toHaveBeenCalledWith(credential, { kind: "create-user", loginName: "new.developer", displayName: "New Developer", initialPassword: "New-Child-Test-Password-49!", initialRole: undefined }));
    expect(view.container.textContent).not.toContain(credential);
    expect(view.container.innerHTML).not.toContain("New-Child-Test-Password-49!");
  });

  it("sets an independent account alias with an optimistic version and shows both login forms", async () => {
    const repository = accounts();
    const { user } = await openAccess(repository);
    await screen.findByText("Developer A");
    await user.click(screen.getByRole("button", { name: "用户设置" }));
    await user.type(screen.getByLabelText(/^主账号别名/), "acme");
    await user.click(screen.getByRole("button", { name: "保存别名" }));
    await waitFor(() => expect(repository.execute).toHaveBeenCalledWith(credential, { kind: "set-alias", alias: "acme", resourceVersion: 1 }));
    expect(screen.getByText("username@tenant-a")).toBeTruthy();
    expect(screen.getByText("admin", { exact: true })).toBeTruthy();
  });

  it("allows an unprivileged user to inspect its own settings without querying admin directories", async () => {
    const reader: AccountIdentity = { ...identity, principal: child.principal, roles: [], canCreateOrganizations: false };
    const repository = accounts({ currentIdentity: vi.fn().mockResolvedValue(reader) });
    await openAccess(repository, iam({}, "child-a"));
    await screen.findByText("尚未授予业务权限");
    expect(repository.listUsers).not.toHaveBeenCalled();
    expect(repository.listAccounts).not.toHaveBeenCalled();
    expect(screen.queryByRole("button", { name: "租户管理" })).toBeNull();
    expect(screen.queryByRole("button", { name: "保存别名" })).toBeNull();
    expect(screen.getByText("username@tenant-a")).toBeTruthy();
  });

  it("requires an explicit role choice for every grant", async () => {
    const { user, repository } = await openAccess();
    await user.click(await screen.findByRole("button", { name: "管理 developer" }));
    expect((screen.getByRole("button", { name: "授予角色" }) as HTMLButtonElement).disabled).toBe(true);
    await user.selectOptions(screen.getByLabelText("授予角色"), "PAAS_DEVELOPER");
    await user.click(screen.getByRole("button", { name: "授予角色" }));
    await waitFor(() => expect(repository.execute).toHaveBeenCalledWith(credential, { kind: "grant-role", principalId: "child-a", role: "PAAS_DEVELOPER" }));
    await waitFor(() => expect((screen.getByLabelText("授予角色") as HTMLSelectElement).value).toBe(""));
    expect((screen.getByRole("button", { name: "授予角色" }) as HTMLButtonElement).disabled).toBe(true);
  });

  it("requires confirmation for revocation and disabling and clears a submitted reset password", async () => {
    const { user, repository } = await openAccess();
    await user.click(await screen.findByRole("button", { name: "管理 developer" }));
    await user.click(screen.getByRole("button", { name: "撤销只读用户" }));
    expect(repository.execute).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "确认撤销" }));
    await waitFor(() => expect(repository.execute).toHaveBeenCalledWith(credential, { kind: "revoke-role", bindingId: "binding-child" }));
    await waitFor(() => expect((screen.getByRole("button", { name: "禁用用户" }) as HTMLButtonElement).disabled).toBe(false));
    await user.click(screen.getByRole("button", { name: "禁用用户" }));
    expect(repository.execute).toHaveBeenCalledTimes(1);
    await user.click(screen.getByRole("button", { name: "确认禁用" }));
    await waitFor(() => expect(repository.execute).toHaveBeenCalledWith(credential, { kind: "set-status", principalId: "child-a", status: "DISABLED", resourceVersion: 2 }));
    await waitFor(() => expect((screen.getByRole("button", { name: "重置密码" }) as HTMLButtonElement).disabled).toBe(false));
    await user.click(screen.getByRole("button", { name: "重置密码" }));
    await user.type(screen.getByLabelText(/^初始密码/), "Reset-Only-Test-Password-74!");
    await user.click(screen.getByRole("button", { name: "确认重置密码" }));
    await waitFor(() => expect(repository.execute).toHaveBeenCalledWith(credential, { kind: "reset-password", principalId: "child-a", initialPassword: "Reset-Only-Test-Password-74!", resourceVersion: 2 }));
    expect(screen.queryByDisplayValue("Reset-Only-Test-Password-74!")).toBeNull();
  });

  it("lets a platform-only child manage tenants without loading a tenant user directory", async () => {
    const repository = accounts({ currentIdentity: vi.fn().mockResolvedValue(platformIdentity) });
    const { user } = await openAccess(repository, iam({}, "child-a"));
    await screen.findByRole("button", { name: "开通租户" });
    expect(repository.listUsers).not.toHaveBeenCalled();
    expect(screen.queryByRole("button", { name: "用户" })).toBeNull();
    await user.click(screen.getByRole("button", { name: "用户设置" }));
    expect(screen.queryByRole("button", { name: "保存别名" })).toBeNull();
    await user.click(screen.getByRole("button", { name: "租户管理" }));
    await user.click(screen.getByRole("button", { name: "开通租户" }));
    await user.type(screen.getByLabelText(/^租户 ID/), "tenant-b");
    await user.type(screen.getByLabelText("租户名称"), "Team B");
    await user.type(screen.getByLabelText(/^主账号登录名/), "owner-b");
    await user.type(screen.getByLabelText("用户显示名称"), "Owner B");
    await user.type(screen.getByLabelText(/^初始密码/), "Primary-Test-Password-49!");
    await user.click(screen.getByRole("button", { name: "确认开通" }));
    await waitFor(() => expect(repository.execute).toHaveBeenCalledWith(credential, {
      kind: "create-organization", id: "tenant-b", displayName: "Team B",
      administratorLoginName: "owner-b", administratorDisplayName: "Owner B", initialPassword: "Primary-Test-Password-49!"
    }));
    expect(screen.queryByDisplayValue("Primary-Test-Password-49!")).toBeNull();
  });

  it("confirms tenant suspension and resumes with the refreshed organization version", async () => {
    const suspended: Account = { ...customer, organization: { ...customer.organization, status: "DISABLED", resourceVersion: 5 } };
    const repository = accounts({ currentIdentity: vi.fn().mockResolvedValue(platformIdentity),
      listAccounts: vi.fn().mockResolvedValueOnce({ items: [customer], nextAfter: null }).mockResolvedValue({ items: [suspended], nextAfter: null }) });
    const { user } = await openAccess(repository, iam({}, "child-a"));
    await user.click(await screen.findByRole("button", { name: "管理租户 tenant-b" }));
    await user.click(screen.getByRole("button", { name: "停用租户" }));
    expect(repository.execute).not.toHaveBeenCalled();
    expect(screen.getByText(/不删除数据、不停止已有工作负载/)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "确认停用租户" }));
    await waitFor(() => expect(repository.execute).toHaveBeenCalledWith(credential, { kind: "set-organization-status", organizationId: "tenant-b", status: "DISABLED", resourceVersion: 4 }));
    await user.click(await screen.findByRole("button", { name: "恢复租户访问" }));
    expect(repository.execute).toHaveBeenCalledTimes(1);
    await user.click(screen.getByRole("button", { name: "确认恢复访问" }));
    await waitFor(() => expect(repository.execute).toHaveBeenCalledWith(credential, { kind: "set-organization-status", organizationId: "tenant-b", status: "ACTIVE", resourceVersion: 5 }));
  });

  it("recovers only the original primary of a suspended tenant and clears secrets even on a conflict", async () => {
    const repository = accounts({ currentIdentity: vi.fn().mockResolvedValue(platformIdentity),
      listAccounts: vi.fn().mockResolvedValue({ items: [{ ...customer, organization: { ...customer.organization, status: "DISABLED" } }], nextAfter: null }),
      execute: vi.fn().mockRejectedValue(new HttpProblem(409, "PRIVATE conflict")) });
    const { user, view } = await openAccess(repository, iam({}, "child-a"));
    await user.click(await screen.findByRole("button", { name: "管理租户 tenant-b" }));
    await user.click(screen.getByRole("button", { name: "恢复原主账号" }));
    expect(screen.getByText("primary-b")).toBeTruthy();
    expect(screen.queryByRole("combobox")).toBeNull();
    expect(screen.getByText(/不会自动恢复租户访问/)).toBeTruthy();
    expect(repository.execute).not.toHaveBeenCalled();
    await user.type(screen.getByLabelText(/^初始密码/), "Recovery-Only-Password-74!");
    await user.click(screen.getByRole("button", { name: "确认恢复原主账号" }));
    await waitFor(() => expect(repository.execute).toHaveBeenCalledWith(credential, { kind: "recover-primary", organizationId: "tenant-b", principalId: "primary-b", initialPassword: "Recovery-Only-Password-74!", resourceVersion: 4 }));
    expect((await screen.findByRole("alert")).textContent).toContain("资源已变化");
    expect(screen.queryByText("操作已完成。")).toBeNull();
    expect(screen.queryByDisplayValue("Recovery-Only-Password-74!")).toBeNull();
    expect(view.container.textContent).not.toContain("PRIVATE");
    expect(localStorage.length + sessionStorage.length).toBe(0);
  });

  it("does not offer credential changes for a disabled platform-bound user", async () => {
    const protectedChild = { ...child, principal: { ...child.principal, status: "DISABLED" as const },
      roleBindings: [...child.roleBindings, { id: "platform-child", organizationId: "tenant-a", principalId: "child-a", role: "PLATFORM_OPERATOR" as const }] };
    const repository = accounts({ listUsers: vi.fn().mockResolvedValue({ items: [protectedChild], nextAfter: null }) });
    const { user } = await openAccess(repository);
    await user.click(await screen.findByRole("button", { name: "管理 developer" }));
    expect(screen.getByText(/即使已禁用/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: "启用用户" })).toBeNull();
    expect(screen.queryByRole("button", { name: "重置密码" })).toBeNull();
    expect(screen.queryByRole("button", { name: "撤销平台运营者" })).toBeNull();
    expect(screen.queryByRole("option", { name: "平台运营者" })).toBeNull();
    expect(screen.getByRole("button", { name: "撤销只读用户" })).toBeTruthy();
  });

  it("clears protected content when a lifecycle command discovers a revoked session", async () => {
    const repository = accounts({ currentIdentity: vi.fn().mockResolvedValue(platformIdentity),
      listAccounts: vi.fn().mockResolvedValue({ items: [customer], nextAfter: null }),
      execute: vi.fn().mockRejectedValue(new HttpProblem(401, "PRIVATE revoked")) });
    const { user } = await openAccess(repository, iam({}, "child-a"));
    await user.click(await screen.findByRole("button", { name: "管理租户 tenant-b" }));
    await user.click(screen.getByRole("button", { name: "停用租户" }));
    await user.click(screen.getByRole("button", { name: "确认停用租户" }));
    expect((await screen.findByRole("alert")).textContent).toContain("会话已失效");
    expect(screen.queryByText("Team B")).toBeNull();
    expect(screen.queryByRole("button", { name: "开通租户" })).toBeNull();
    expect(screen.queryByText("操作已完成。")).toBeNull();
  });

  it.each([401, 503])("clears stale success after a subsequent account refresh fails with %i", async (status) => {
    const repository = accounts({ currentIdentity: vi.fn().mockResolvedValue(platformIdentity),
      listAccounts: vi.fn().mockResolvedValue({ items: [customer], nextAfter: null }) });
    const { user } = await openAccess(repository, iam({}, "child-a"));
    await user.click(await screen.findByRole("button", { name: "管理租户 tenant-b" }));
    await user.click(screen.getByRole("button", { name: "停用租户" }));
    await user.click(screen.getByRole("button", { name: "确认停用租户" }));
    await screen.findByText("操作已完成。");
    await waitFor(() => expect((screen.getByRole("button", { name: "刷新账号信息" }) as HTMLButtonElement).disabled).toBe(false));
    vi.mocked(repository.currentIdentity).mockRejectedValue(new HttpProblem(status, "PRIVATE refresh failure"));
    await user.click(screen.getByRole("button", { name: "刷新账号信息" }));
    await screen.findByRole("alert");
    expect(screen.queryByText("操作已完成。")).toBeNull();
    expect(screen.queryByText("Team B")).toBeNull();
    expect(screen.queryByRole("button", { name: "开通租户" })).toBeNull();
  });

  it.each(["identity", "directory", "principal"])("fails closed on a mismatched %s instead of showing another subject", async (mismatch) => {
    const other = structuredClone(identity);
    if (mismatch === "identity") other.account.organization.id = "tenant-b";
    if (mismatch === "principal") other.principal.id = "other-principal";
    const repository = accounts({ currentIdentity: vi.fn().mockResolvedValue(other), ...(mismatch === "directory" ? { listUsers: vi.fn().mockResolvedValue({ items: [{ ...child, principal: { ...child.principal, organizationId: "tenant-b", displayName: "PRIVATE OTHER USER" } }], nextAfter: null }) } : {}) });
    await openAccess(repository);
    expect((await screen.findByRole("alert")).textContent).toContain("暂时不可用");
    expect(screen.queryByText("PRIVATE OTHER USER")).toBeNull();
    expect(screen.queryByRole("button", { name: "创建用户" })).toBeNull();
  });
});
