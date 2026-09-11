import { act, cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { HttpProblem } from "@/infrastructure/http/jsonRequest";
import { SessionProvider, useSession } from "../application/SessionProvider";
import type { Account, AccountIdentity, AccountPolicy, AccountPrincipal, AccountUser, PolicyDirectory, UserPolicyAttachment } from "../domain/accounts";
import type { AccountRepository, IamRepository } from "../repositories/iamRepository";
import { AccountAccessRenderer } from "./AccountAccessRenderer";
import { LoginRenderer } from "./LoginRenderer";

const navigation = vi.hoisted(() => ({ replace: vi.fn() }));
vi.mock("next/navigation", () => ({ useRouter: () => navigation }));
const credential = "account-test-only-memory-credential";
const timestamp = "2026-09-11T08:00:00Z";
const principal: AccountPrincipal = { id: "primary-a", organizationId: "tenant-a", loginName: "admin", displayName: "Account owner", status: "ACTIVE", resourceVersion: 2, mustChangePassword: false };
const account: Account = { organization: { id: "tenant-a", displayName: "Team A", status: "ACTIVE", resourceVersion: 1 }, primaryPrincipalId: "primary-a", primaryLoginName: "admin", loginAlias: null };
function attachment(id: string, principalId: string, policyId: string, scope: "TENANT" | "INSTALLATION" = "TENANT"): UserPolicyAttachment {
  return { id, accountId: "tenant-a", target: { kind: "USER", id: principalId }, policyId, scope,
    installationId: scope === "INSTALLATION" ? "installation-a" : null, resourceVersion: 1, createdAt: timestamp, updatedAt: timestamp };
}
function policy(id: string, displayName: string, scope: "TENANT" | "INSTALLATION" = "TENANT", resourceVersion = 1): AccountPolicy {
  return { id, management: id.startsWith("system.") ? "SYSTEM" : "CUSTOMER", accountId: id.startsWith("system.") ? null : "tenant-a",
    displayName, scope, status: "ACTIVE", defaultVersionId: `version-${id.replaceAll(".", "-")}`, resourceVersion, createdAt: timestamp, updatedAt: timestamp };
}
const tenantAdmin = attachment("attachment-admin", "primary-a", "system.account-administrator");
const platformOperator = attachment("attachment-platform", "primary-a", "system.platform-operator", "INSTALLATION");
const viewer = attachment("attachment-viewer", "child-a", "system.paas-viewer");
const tenantPolicies: PolicyDirectory = { accountId: "tenant-a", scope: "TENANT", installationId: null, items: [
  policy("customer.automation", "自动化发布"),
  policy("system.account-administrator", "租户管理员"),
  policy("system.paas-developer", "服务开发者", "TENANT", 7),
  policy("system.paas-viewer", "只读用户")
] };
const platformPolicies: PolicyDirectory = { accountId: "tenant-a", scope: "INSTALLATION", installationId: "installation-a",
  items: [policy("system.platform-operator", "平台运营者", "INSTALLATION")] };
const identity: AccountIdentity = { account, principal, policyAttachments: [tenantAdmin, platformOperator], canCreateOrganizations: true };
const child: AccountUser = { principal: { ...principal, id: "child-a", loginName: "developer", displayName: "Developer A" }, policyAttachments: [viewer] };
const customer: Account = { organization: { id: "tenant-b", displayName: "Team B", status: "ACTIVE", resourceVersion: 4 }, primaryPrincipalId: "primary-b", primaryLoginName: "owner-b", loginAlias: null };
const platformIdentity: AccountIdentity = { ...identity, principal: child.principal,
  policyAttachments: [attachment("attachment-platform-child", "child-a", "system.platform-operator", "INSTALLATION")], canCreateOrganizations: true };

function forbidden(): Promise<never> { return Promise.reject(new HttpProblem(403, "DENIED")); }

function iam(overrides: Partial<IamRepository> = {}, id = "primary-a"): IamRepository {
  return {
    login: vi.fn().mockResolvedValue({ credential, mustChangePassword: false, session: { id: "session-test", organizationId: "tenant-a", principalId: id, status: "ACTIVE", issuedAt: "2026-08-27T00:00:00Z", expiresAt: "2099-08-27T00:00:00Z" } }),
    changePassword: vi.fn(), logout: vi.fn(), ...overrides
  };
}

function accounts(overrides: Partial<AccountRepository> = {}): AccountRepository {
  return {
    currentIdentity: vi.fn().mockResolvedValue(structuredClone(identity)),
    listUsers: vi.fn().mockResolvedValue({ items: [{ principal, policyAttachments: [] }, child], nextAfter: null }),
    listPolicies: vi.fn().mockImplementation((_credential: string, platform: boolean) => Promise.resolve(structuredClone(platform ? platformPolicies : tenantPolicies))),
    listAccounts: vi.fn().mockResolvedValue({ items: [account], nextAfter: null }),
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
  it("forces other temporary sessions out and clears pending passwords", async () => {
    let complete!: () => void;
    const source = iam({
      login: vi.fn().mockResolvedValue({ credential, mustChangePassword: true, session: {
        id: "session-forced", organizationId: "tenant-a", principalId: "child-a", status: "ACTIVE",
        issuedAt: "2026-08-28T00:00:00Z", expiresAt: "2099-08-28T00:00:00Z"
      } }),
      changePassword: vi.fn().mockImplementation(() => new Promise<void>((resolve) => { complete = resolve; }))
    });
    const repository = accounts({ currentIdentity: vi.fn().mockResolvedValue({ ...identity, principal: child.principal, policyAttachments: [], canCreateOrganizations: false }) });
    const user = userEvent.setup();
    render(<SessionProvider repository={source}><AuthenticatedAccess repository={repository} /></SessionProvider>);
    await user.click(screen.getByRole("button", { name: "IAM 子账号" }));
    await user.type(screen.getByLabelText("子账号登录名"), "developer@tenant-a");
    await user.type(screen.getByLabelText("密码", { exact: true }), "Temporary-Test-Password-49!");
    await user.click(screen.getByRole("button", { name: "登录控制台" }));
    await screen.findByRole("heading", { name: "设置你的正式密码" });
    expect(screen.queryByRole("checkbox")).toBeNull();
    await user.type(screen.getByLabelText("当前初始密码"), "Temporary-Test-Password-49!");
    await user.type(screen.getByLabelText("新密码", { exact: true }), "Replacement-Test-Password-73!");
    await user.type(screen.getByLabelText("确认新密码", { exact: true }), "Replacement-Test-Password-73!");
    await user.click(screen.getByRole("button", { name: "保存并进入控制台" }));
    expect(source.changePassword).toHaveBeenCalledWith(credential, {
      currentPassword: "Temporary-Test-Password-49!", newPassword: "Replacement-Test-Password-73!", revokeOtherSessions: true
    });
    expect(screen.queryByDisplayValue("Temporary-Test-Password-49!")).toBeNull();
    await act(async () => complete());
    await waitFor(() => expect(repository.currentIdentity).toHaveBeenCalledWith(credential));
    expect(navigation.replace).toHaveBeenCalledWith("/console/access/");
    expect(localStorage.length + sessionStorage.length).toBe(0);
  }, 10_000);

  it("uses one qualified identifier and clears secrets on mode change", async () => {
    const repository = iam();
    const user = userEvent.setup();
    render(<SessionProvider repository={repository}><LoginRenderer /></SessionProvider>);
    await user.type(screen.getByLabelText("密码", { exact: true }), "Previous-mode-secret-49!");
    await user.click(screen.getByRole("button", { name: "IAM 子账号" }));
    expect((screen.getByLabelText("密码", { exact: true }) as HTMLInputElement).value).toBe("");
    await user.type(screen.getByLabelText("子账号登录名"), "developer@tenant-a");
    await user.type(screen.getByLabelText("密码", { exact: true }), "Only-Test-Password-49!");
    await user.click(screen.getByRole("button", { name: "登录控制台" }));
    await waitFor(() => expect(repository.login).toHaveBeenCalledWith({ loginName: "developer@tenant-a", password: "Only-Test-Password-49!" }));
    expect(localStorage.length + sessionStorage.length).toBe(0);
  });
});

describe("account access", () => {
  it.each([true, false])("offers a default-on ordinary password session choice (%s)", async (revokeOtherSessions) => {
    let complete!: () => void;
    const passwordRepository = iam({ changePassword: vi.fn().mockImplementation(() => new Promise<void>((resolve) => { complete = resolve; })) }, "child-a");
    const repository = accounts({ currentIdentity: vi.fn().mockResolvedValue({ ...identity, principal: child.principal, policyAttachments: [], canCreateOrganizations: false }) });
    const { user, view } = await openAccess(repository, passwordRepository);
    await user.click(await screen.findByRole("button", { name: "用户设置" }));
    const option = screen.getByRole("checkbox", { name: "同时退出其他登录会话（推荐）" }) as HTMLInputElement;
    if (!revokeOtherSessions) await user.click(option);
    await user.type(screen.getByLabelText("当前密码", { exact: true }), "Current-Only-Test-Password-49!");
    await user.type(screen.getByLabelText("新密码", { exact: true }), "New-Only-Test-Password-73!");
    await user.type(screen.getByLabelText("确认新密码", { exact: true }), "New-Only-Test-Password-73!");
    await user.click(screen.getByRole("button", { name: "更新密码" }));
    expect(passwordRepository.changePassword).toHaveBeenCalledWith(credential, {
      currentPassword: "Current-Only-Test-Password-49!", newPassword: "New-Only-Test-Password-73!", revokeOtherSessions
    });
    await act(async () => complete());
    expect((await screen.findByRole("status")).textContent).toContain(revokeOtherSessions ? "其他登录会话已退出" : "其他仍有效的登录会话保留");
    expect(view.container.innerHTML).not.toContain(credential);
  });

  it("creates a member without an implicit policy", async () => {
    const { user, repository, view } = await openAccess();
    await screen.findByText("Developer A");
    await user.click(screen.getByRole("button", { name: "创建用户" }));
    await user.type(screen.getByLabelText(/^子用户名/), "new.developer");
    await user.type(screen.getByLabelText("用户显示名称"), "New Developer");
    await user.type(screen.getByLabelText(/^初始密码/), "New-Child-Test-Password-49!");
    expect(screen.queryByLabelText(/^初始权限/)).toBeNull();
    await user.click(within(screen.getByRole("form", { name: "创建子用户" })).getByRole("button", { name: "创建用户" }));
    await waitFor(() => expect(repository.execute).toHaveBeenCalledWith(credential, { kind: "create-user", loginName: "new.developer", displayName: "New Developer", initialPassword: "New-Child-Test-Password-49!" }));
    expect(view.container.innerHTML).not.toContain("New-Child-Test-Password-49!");
  });

  it("uses arbitrary catalog policies and exact selected revisions, never fixed role names", async () => {
    const { user, repository } = await openAccess();
    await user.click(await screen.findByRole("button", { name: "管理 developer" }));
    expect((screen.getByRole("button", { name: "关联策略" }) as HTMLButtonElement).disabled).toBe(true);
    await user.selectOptions(screen.getByLabelText("关联策略"), "customer.automation");
    await user.click(screen.getByRole("button", { name: "关联策略" }));
    await waitFor(() => expect(repository.execute).toHaveBeenCalledWith(credential, {
      kind: "create-policy-attachment", principalId: "child-a", policyId: "customer.automation", policyResourceVersion: 1
    }));
    expect(screen.queryByText("PAAS_DEVELOPER")).toBeNull();
  });

  it("does not silently refresh a selected policy revision", async () => {
    const policiesV8 = structuredClone(tenantPolicies);
    policiesV8.items = policiesV8.items.map((item) => item.id === "system.paas-developer" ? { ...item, resourceVersion: 8 } : item);
    const listPolicies = vi.fn().mockImplementation((_credential: string, platform: boolean) =>
      Promise.resolve(structuredClone(platform ? platformPolicies : listPolicies.mock.calls.filter((call) => call[1] === false).length > 1 ? policiesV8 : tenantPolicies)));
    const repository = accounts({ listPolicies });
    const { user } = await openAccess(repository);
    await user.click(await screen.findByRole("button", { name: "管理 developer" }));
    await user.selectOptions(screen.getByLabelText("关联策略"), "system.paas-developer");
    await user.click(screen.getByRole("button", { name: "刷新账号信息" }));
    await screen.findByText("策略版本已经变化，请重新选择后再提交。");
    expect((screen.getByRole("button", { name: "关联策略" }) as HTMLButtonElement).disabled).toBe(true);
    expect(repository.execute).not.toHaveBeenCalled();
    await user.selectOptions(screen.getByLabelText("关联策略"), "system.paas-developer");
    await user.click(screen.getByRole("button", { name: "关联策略" }));
    await waitFor(() => expect(repository.execute).toHaveBeenCalledWith(credential, {
      kind: "create-policy-attachment", principalId: "child-a", policyId: "system.paas-developer", policyResourceVersion: 8
    }));
  });

  it("requires confirmation and exact attachment revision for revoke", async () => {
    const { user, repository } = await openAccess();
    await user.click(await screen.findByRole("button", { name: "管理 developer" }));
    await user.click(screen.getByRole("button", { name: "撤销只读用户" }));
    expect(repository.execute).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "确认撤销" }));
    await waitFor(() => expect(repository.execute).toHaveBeenCalledWith(credential, {
      kind: "revoke-policy-attachment", attachmentId: "attachment-viewer", resourceVersion: 1
    }));
  });

  it("derives accessible sections from separately authorized reads", async () => {
    const reader: AccountIdentity = { ...identity, principal: child.principal, policyAttachments: [], canCreateOrganizations: false };
    const repository = accounts({
      currentIdentity: vi.fn().mockResolvedValue(reader), listUsers: vi.fn().mockImplementation(forbidden),
      listPolicies: vi.fn().mockImplementation(forbidden)
    });
    await openAccess(repository, iam({}, "child-a"));
    await screen.findByText("尚未关联权限策略");
    expect(repository.listUsers).toHaveBeenCalled();
    expect(repository.listPolicies).toHaveBeenCalledTimes(2);
    expect(repository.listAccounts).not.toHaveBeenCalled();
    expect(screen.queryByRole("button", { name: "用户" })).toBeNull();
    expect(screen.queryByRole("button", { name: "策略" })).toBeNull();
    expect(screen.queryByRole("button", { name: "租户管理" })).toBeNull();
    expect(screen.queryByRole("button", { name: "保存别名" })).toBeNull();
  });

  it("shows actual policy metadata, including customer and retired entries", async () => {
    const retired = { ...tenantPolicies.items[3]!, status: "RETIRED" as const, resourceVersion: 2 };
    const repository = accounts({ listPolicies: vi.fn().mockImplementation((_credential: string, platform: boolean) =>
      Promise.resolve(structuredClone(platform ? platformPolicies : { ...tenantPolicies, items: [...tenantPolicies.items.slice(0, 3), retired] }))) });
    const { user } = await openAccess(repository);
    await user.click(await screen.findByRole("button", { name: "策略" }));
    expect(screen.getByText("自动化发布")).toBeTruthy();
    expect(screen.getByText("已停用")).toBeTruthy();
    expect(screen.getByText(/customer\.automation/)).toBeTruthy();
    expect(screen.getByText(/修订 7/)).toBeTruthy();
  });

  it("lets a platform-only member manage tenants without a tenant directory", async () => {
    const repository = accounts({
      currentIdentity: vi.fn().mockResolvedValue(platformIdentity),
      listUsers: vi.fn().mockImplementation(forbidden),
      listPolicies: vi.fn().mockImplementation((_credential: string, platform: boolean) => platform ? Promise.resolve(platformPolicies) : forbidden())
    });
    const { user } = await openAccess(repository, iam({}, "child-a"));
    expect(screen.queryByRole("button", { name: "用户" })).toBeNull();
    await user.click(await screen.findByRole("button", { name: "租户管理" }));
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
  });

  it("confirms tenant suspension and resumes with the refreshed version", async () => {
    const suspended: Account = { ...customer, organization: { ...customer.organization, status: "DISABLED", resourceVersion: 5 } };
    const repository = accounts({ currentIdentity: vi.fn().mockResolvedValue(platformIdentity),
      listUsers: vi.fn().mockImplementation(forbidden),
      listPolicies: vi.fn().mockImplementation((_credential: string, platform: boolean) => platform ? Promise.resolve(platformPolicies) : forbidden()),
      listAccounts: vi.fn().mockResolvedValueOnce({ items: [customer], nextAfter: null }).mockResolvedValue({ items: [suspended], nextAfter: null }) });
    const { user } = await openAccess(repository, iam({}, "child-a"));
    await user.click(await screen.findByRole("button", { name: "租户管理" }));
    await user.click(await screen.findByRole("button", { name: "管理租户 tenant-b" }));
    await user.click(screen.getByRole("button", { name: "停用租户" }));
    await user.click(screen.getByRole("button", { name: "确认停用租户" }));
    await waitFor(() => expect(repository.execute).toHaveBeenCalledWith(credential, { kind: "set-organization-status", organizationId: "tenant-b", status: "DISABLED", resourceVersion: 4 }));
    await user.click(await screen.findByRole("button", { name: "恢复租户访问" }));
    await user.click(screen.getByRole("button", { name: "确认恢复访问" }));
    await waitFor(() => expect(repository.execute).toHaveBeenCalledWith(credential, { kind: "set-organization-status", organizationId: "tenant-b", status: "ACTIVE", resourceVersion: 5 }));
  });

  it("does not offer tenant credential changes for an installation-bound member", async () => {
    const protectedChild: AccountUser = { ...child, principal: { ...child.principal, status: "DISABLED" },
      policyAttachments: [...child.policyAttachments, attachment("attachment-platform-child", "child-a", "system.platform-operator", "INSTALLATION")] };
    const tenantOnlyIdentity: AccountIdentity = { ...identity, policyAttachments: [tenantAdmin], canCreateOrganizations: false };
    const repository = accounts({
      currentIdentity: vi.fn().mockResolvedValue(tenantOnlyIdentity),
      listUsers: vi.fn().mockResolvedValue({ items: [protectedChild], nextAfter: null }),
      listPolicies: vi.fn().mockImplementation((_credential: string, platform: boolean) => platform ? forbidden() : Promise.resolve(tenantPolicies))
    });
    const { user } = await openAccess(repository);
    await user.click(await screen.findByRole("button", { name: "管理 developer" }));
    expect(screen.getByText(/即使已禁用/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: "启用用户" })).toBeNull();
    expect(screen.queryByRole("button", { name: "重置密码" })).toBeNull();
    expect(screen.queryByRole("button", { name: /撤销system\.platform-operator/ })).toBeNull();
    expect(screen.getByRole("button", { name: "撤销只读用户" })).toBeTruthy();
  });

  it("clears protected content when a command discovers a revoked session", async () => {
    const repository = accounts({ currentIdentity: vi.fn().mockResolvedValue(platformIdentity),
      listUsers: vi.fn().mockImplementation(forbidden),
      listPolicies: vi.fn().mockImplementation((_credential: string, platform: boolean) => platform ? Promise.resolve(platformPolicies) : forbidden()),
      listAccounts: vi.fn().mockResolvedValue({ items: [customer], nextAfter: null }),
      execute: vi.fn().mockRejectedValue(new HttpProblem(401, "PRIVATE revoked")) });
    const { user } = await openAccess(repository, iam({}, "child-a"));
    await user.click(await screen.findByRole("button", { name: "租户管理" }));
    await user.click(await screen.findByRole("button", { name: "管理租户 tenant-b" }));
    await user.click(screen.getByRole("button", { name: "停用租户" }));
    await user.click(screen.getByRole("button", { name: "确认停用租户" }));
    expect((await screen.findByRole("alert")).textContent).toContain("会话已失效");
    expect(screen.queryByText("Team B")).toBeNull();
  });

  it.each(["identity", "directory", "principal", "policy"])("fails closed on mismatched %s authority", async (mismatch) => {
    const other = structuredClone(identity);
    if (mismatch === "identity") other.account.organization.id = "tenant-b";
    if (mismatch === "principal") other.principal.id = "other-principal";
    const repository = accounts({
      currentIdentity: vi.fn().mockResolvedValue(other),
      ...(mismatch === "directory" ? { listUsers: vi.fn().mockResolvedValue({ items: [{ ...child, principal: { ...child.principal, organizationId: "tenant-b", displayName: "PRIVATE OTHER USER" } }], nextAfter: null }) } : {}),
      ...(mismatch === "policy" ? { listPolicies: vi.fn().mockImplementation((_credential: string, platform: boolean) =>
        Promise.resolve({ ...(platform ? platformPolicies : tenantPolicies), accountId: "tenant-b" })) } : {})
    });
    await openAccess(repository);
    expect((await screen.findByRole("alert")).textContent).toContain("暂时不可用");
    expect(screen.queryByText("PRIVATE OTHER USER")).toBeNull();
  });
});
