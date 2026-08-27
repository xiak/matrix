import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { HttpProblem } from "@/infrastructure/http/jsonRequest";
import { SessionProvider, useSession } from "../application/SessionProvider";
import type { AccountIdentity, AccountPrincipal, AccountUser } from "../domain/accounts";
import type { AccountRepository, IamRepository } from "../repositories/iamRepository";
import { AccountAccessRenderer } from "./AccountAccessRenderer";
import { LoginRenderer } from "./LoginRenderer";

const navigation = vi.hoisted(() => ({ replace: vi.fn() }));
vi.mock("next/navigation", () => ({ useRouter: () => navigation }));
const credential = "account-test-only-memory-credential";
const principal: AccountPrincipal = { id: "primary-a", organizationId: "tenant-a", loginName: "admin", displayName: "Account owner", status: "ACTIVE", resourceVersion: 2, mustChangePassword: false };
const identity: AccountIdentity = {
  account: { organization: { id: "tenant-a", displayName: "Team A", status: "ACTIVE", resourceVersion: 1 }, primaryPrincipalId: "primary-a", primaryLoginName: "admin", loginAlias: null },
  principal, roles: ["ORGANIZATION_ADMIN"], canCreateOrganizations: true
};
const child: AccountUser = { principal: { ...principal, id: "child-a", loginName: "developer", displayName: "Developer A" }, roleBindings: [{ id: "binding-child", organizationId: "tenant-a", principalId: "child-a", role: "PAAS_VIEWER" }] };

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
  return session.phase === "authenticated" ? <AccountAccessRenderer repository={repository} /> : <LoginRenderer />;
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
  it("separates the resource owner from subusers and defaults creation to no business grant", async () => {
    const { user, repository, view } = await openAccess();
    await screen.findByText("Developer A");
    expect(screen.queryByRole("button", { name: "管理 admin" })).toBeNull();
    expect(screen.getByText("所属账号 · 资源归属")).toBeTruthy();
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
