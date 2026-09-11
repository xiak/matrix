import { act, cleanup, render, screen, waitFor, within } from "@testing-library/react";
import { Profiler, useState } from "react";
import userEvent from "@testing-library/user-event";
import { LocaleProvider, useLocalePreference } from "@/i18n/LocaleProvider";
import { UnsavedChangesProvider, useLeaveConfirmation } from "@ui/xiak";
import { afterEach, describe, expect, it, vi } from "vitest";
import { HttpProblem } from "@/infrastructure/http/jsonRequest";
import { SessionProvider, useSession } from "../application/SessionProvider";
import { AccountAccessProvider, useAccountCapabilities } from "../application/AccountAccessProvider";
import type { AccountIdentity, AccountPolicy, AccountPrincipal, AccountUser, AccountAccessView, PolicyDirectory, UserPolicyAttachment } from "../domain/accounts";
import type { AccountRepository, IamRepository } from "../repositories/iamRepository";
import { AccountAccessRenderer } from "./AccountAccessRenderer";
import { LoginRenderer } from "./LoginRenderer";
import { buildAccountAccessScene } from "../scenes/accountAccessScene";

const navigation = vi.hoisted(() => ({ replace: vi.fn() }));
vi.mock("next/navigation", () => ({ useRouter: () => navigation }));
const credential = "account-test-only-memory-credential";
const timestamp = "2026-09-11T08:00:00Z";
const principal: AccountPrincipal = { id: "primary-a", organizationId: "tenant-a", loginName: "admin", displayName: "Account owner", status: "ACTIVE", resourceVersion: 2, mustChangePassword: false };
const tenantPolicy: AccountPolicy = { id: "system.paas-viewer", management: "SYSTEM", accountId: null, displayName: "ReadOnlyAccess", scope: "TENANT", status: "ACTIVE", defaultVersionId: "version-1", resourceVersion: 3, createdAt: timestamp, updatedAt: timestamp };
const platformPolicy: AccountPolicy = { ...tenantPolicy, id: "system.platform-admin", displayName: "PlatformAdministrator", scope: "INSTALLATION", resourceVersion: 2 };
const attachment = (principalId: string, policy: AccountPolicy): UserPolicyAttachment => ({ id: `attachment-${principalId}-${policy.id}`, accountId: "tenant-a", target: { kind: "USER", id: principalId }, policyId: policy.id, scope: policy.scope, installationId: policy.scope === "INSTALLATION" ? "installation-a" : null, resourceVersion: 1, createdAt: timestamp, updatedAt: timestamp });
const directory = (platform: boolean): PolicyDirectory => ({ accountId: "tenant-a", scope: platform ? "INSTALLATION" : "TENANT", installationId: platform ? "installation-a" : null, items: [platform ? platformPolicy : tenantPolicy] });
const identity: AccountIdentity = {
  account: { organization: { id: "tenant-a", displayName: "Team A", status: "ACTIVE", resourceVersion: 1 }, primaryPrincipalId: "primary-a", primaryLoginName: "admin", loginAlias: null },
  principal, policyAttachments: [attachment("primary-a", platformPolicy)], canCreateOrganizations: true
};
const child: AccountUser = { principal: { ...principal, id: "child-a", loginName: "developer", displayName: "Developer A" }, policyAttachments: [attachment("child-a", tenantPolicy)] };

function iam(overrides: Partial<IamRepository> = {}, id = "primary-a"): IamRepository {
  return {
    login: vi.fn().mockResolvedValue({ credential, mustChangePassword: false, session: { id: "session-test", organizationId: "tenant-a", principalId: id, status: "ACTIVE", issuedAt: "2026-08-27T00:00:00Z", expiresAt: "2099-08-27T00:00:00Z" } }),
    changePassword: vi.fn(), logout: vi.fn(), ...overrides
  };
}

function accounts(overrides: Partial<AccountRepository> = {}): AccountRepository {
  return {
    currentIdentity: vi.fn().mockResolvedValue(structuredClone(identity)),
    listUsers: vi.fn().mockResolvedValue({ items: [{ principal, policyAttachments: identity.policyAttachments }, child], nextAfter: null }),
    listPolicies: vi.fn().mockImplementation(async (_credential: string, platform: boolean) => directory(platform)),
    listAccounts: vi.fn().mockResolvedValue({ items: [identity.account], nextAfter: null }),
    execute: vi.fn().mockResolvedValue(undefined), ...overrides
  } as AccountRepository;
}

function LanguageSwitch() {
  const { locale, setLocale } = useLocalePreference();
  return <button onClick={() => setLocale(locale === "en" ? "zh-CN" : "en")}>Switch language</button>;
}

const capabilityCommit = vi.fn();
function CapabilityProbe() {
  const capabilities = useAccountCapabilities();
  return <Profiler id="navigation-capabilities" onRender={capabilityCommit}><output data-testid="can-manage">{String(capabilities.canManage)}</output></Profiler>;
}

function AuthenticatedAccess({ repository, initialView }: { repository: AccountRepository; initialView: AccountAccessView }) {
  const requestLeave = useLeaveConfirmation();
  const session = useSession();
  const [view, setView] = useState(initialView);
  const [entityId, setEntityId] = useState<string>();
  return session.phase === "authenticated" ? <AccountAccessProvider repository={repository}><CapabilityProbe /><nav>{(["overview", "users", "settings", "policies", "roles", "tenants"] as const).map((target) => <button data-testid={"nav-" + target} aria-current={view === target ? "page" : undefined} key={target} onClick={() => requestLeave(() => { setView(target); setEntityId(undefined); })}>{target}</button>)}</nav><AccountAccessRenderer view={view} entityId={entityId} onNavigate={(next, id) => requestLeave(() => { setView(next); setEntityId(id); })} /></AccountAccessProvider> : <LoginRenderer />;
}

async function openAccess(repository = accounts(), iamRepository = iam(), initialView: AccountAccessView = "users") {
  const user = userEvent.setup();
  const view = render(<LocaleProvider><LanguageSwitch /><SessionProvider repository={iamRepository}><UnsavedChangesProvider><AuthenticatedAccess repository={repository} initialView={initialView} /></UnsavedChangesProvider></SessionProvider></LocaleProvider>);
  await user.type(screen.getByLabelText("密码", { exact: true }), "Only-Test-Password-49!");
  await user.click(screen.getByRole("button", { name: "登录控制台" }));
  await waitFor(() => expect(repository.currentIdentity).toHaveBeenCalledWith(credential));
  return { user, view, repository };
}

afterEach(() => { cleanup(); vi.clearAllMocks(); localStorage.clear(); sessionStorage.clear(); });

describe("qualified login", () => {
  it("returns a primary user to the originally requested console page", async () => {
    const repository = iam();
    const user = userEvent.setup();
    render(<LocaleProvider><SessionProvider repository={repository}><LoginRenderer returnTo="/console/resources/" /></SessionProvider></LocaleProvider>);
    await user.type(screen.getByLabelText("密码", { exact: true }), "Only-Test-Password-49!");
    await user.click(screen.getByRole("button", { name: "登录控制台" }));
    await waitFor(() => expect(navigation.replace).toHaveBeenCalledWith("/console/resources/"));
  });

  it("uses one text identifier, clears secrets on mode change, and preserves IAM's account namespace", async () => {
    const repository = iam();
    const user = userEvent.setup();
    render(<LocaleProvider><SessionProvider repository={repository}><LoginRenderer /></SessionProvider></LocaleProvider>);
    await user.type(screen.getByLabelText("密码", { exact: true }), "Previous-mode-secret-49!");
    await user.click(screen.getByRole("tab", { name: "IAM 子账号" }));
    expect((screen.getByLabelText("密码", { exact: true }) as HTMLInputElement).value).toBe("");
    const field = screen.getByLabelText("子账号登录名") as HTMLInputElement;
    expect(field.type).toBe("text");
    await user.type(field, "developer@tenant-a");
    await user.type(screen.getByLabelText("密码", { exact: true }), "Only-Test-Password-49!");
    await user.click(screen.getByRole("button", { name: "登录控制台" }));
    await waitFor(() => expect(repository.login).toHaveBeenCalledWith({ loginName: "developer@tenant-a", password: "Only-Test-Password-49!" }));
    expect(navigation.replace).toHaveBeenCalledWith("/console/");
    expect(localStorage.length + sessionStorage.length).toBe(0);
  });

  it("does not submit an unqualified child or leak prior authentication errors between modes", async () => {
    const repository = iam({ login: vi.fn().mockRejectedValue(new HttpProblem(401, "private upstream")) });
    const user = userEvent.setup();
    render(<LocaleProvider><SessionProvider repository={repository}><LoginRenderer /></SessionProvider></LocaleProvider>);
    await user.type(screen.getByLabelText("密码", { exact: true }), "Wrong-Password-49!");
    await user.click(screen.getByRole("button", { name: "登录控制台" }));
    await screen.findByRole("alert");
    await user.click(screen.getByRole("tab", { name: "IAM 子账号" }));
    expect(screen.queryByRole("alert")).toBeNull();
    await user.type(screen.getByLabelText("子账号登录名"), "developer");
    await user.type(screen.getByLabelText("密码", { exact: true }), "Only-Test-Password-49!");
    await user.click(screen.getByRole("button", { name: "登录控制台" }));
    expect(screen.getByRole("alert").textContent).toContain("主账号ID或别名");
    expect(repository.login).toHaveBeenCalledTimes(1);
  });
});

describe("account access", () => {
  it("keeps owner identity separate from child targets and never infers identity type from policy names", () => {
    const namedAdministrator = { ...tenantPolicy, id: "customer.administrator", management: "CUSTOMER" as const, accountId: "tenant-a", displayName: "TenantAdministrator" };
    const adminChild: AccountUser = { ...child, policyAttachments: [attachment("child-a", namedAdministrator)] };
    const tenantDirectory = { ...directory(false), items: [namedAdministrator, tenantPolicy].sort((left, right) => left.id.localeCompare(right.id)) };
    const scene = buildAccountAccessScene(identity, { items: [{ principal, policyAttachments: identity.policyAttachments }, adminChild], nextAfter: null }, null, tenantDirectory, directory(true));
    expect(scene.primaryUser).toMatchObject({ id: "primary-a", accountType: "primary", name: "Account owner", state: "active" });
    expect(scene.users).toHaveLength(1);
    expect(scene.users[0]).toMatchObject({ id: "child-a", accountType: "subuser", attachments: [{ policyId: "customer.administrator" }] });
    const actingChild = { ...identity, principal: child.principal, policyAttachments: child.policyAttachments, canCreateOrganizations: false };
    const pageWithoutOwner = buildAccountAccessScene(actingChild, { items: [child], nextAfter: "later" }, null, directory(false), null);
    expect(pageWithoutOwner.primaryUser).toMatchObject({ id: "primary-a", loginName: "admin", name: null, state: null, isCurrent: false });
    expect(pageWithoutOwner.primaryUser.name).not.toBe(actingChild.principal.displayName);
    expect(pageWithoutOwner.users[0]?.protected).toBe(true);
  });

  it("shows a read-only resource owner with separate identity, access and permission details", async () => {
    const { user, repository } = await openAccess();
    const owner = within(await screen.findByRole("region", { name: "资源所有者" }));
    expect(owner.getByText("主账号")).toBeTruthy();
    expect(owner.getByText("资源所有者")).toBeTruthy();
    expect(owner.queryByText("未授权")).toBeNull();
    expect(owner.queryByRole("button", { name: "管理 admin" })).toBeNull();
    await user.click(owner.getByRole("button", { name: "查看用户 admin" }));
    expect(await screen.findByRole("heading", { name: "admin" })).toBeTruthy();
    expect(screen.getByRole("tab", { name: "身份信息" }).getAttribute("aria-selected")).toBe("true");
    expect(screen.getByText("primary-a")).toBeTruthy();
    await user.click(screen.getByRole("tab", { name: "权限策略" }));
    expect(screen.getByText(/主账号默认拥有所属账号资源的完整访问权限/)).toBeTruthy();
    for (const name of ["禁用用户", "授予角色", "删除", "重置密码", "关联策略"]) expect(screen.queryByRole("button", { name })).toBeNull();
    await user.click(screen.getByRole("tab", { name: "访问方式" }));
    expect(screen.getByText(/当前页面不提供主账号密钥创建或密码重置/)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Switch language" }));
    expect(screen.getByRole("tab", { name: "Access methods" }).getAttribute("aria-selected")).toBe("true");
    expect(repository.execute).not.toHaveBeenCalled();
  });

  it("filters subusers without hiding the separately projected account owner", async () => {
    const adminChild: AccountUser = { ...child, policyAttachments: [attachment("child-a", tenantPolicy)] };
    const ungranted: AccountUser = { principal: { ...child.principal, id: "ungranted", loginName: "new.user" }, policyAttachments: [] };
    const { user } = await openAccess(accounts({ listUsers: vi.fn().mockResolvedValue({ items: [adminChild, ungranted], nextAfter: null }) }));
    const admin = within((await screen.findByRole("button", { name: "查看用户 developer" })).closest("tr")!);
    expect(admin.getByText("IAM 子用户")).toBeTruthy();
    expect(admin.getByText("ReadOnlyAccess")).toBeTruthy();
    expect(admin.queryByText("主账号")).toBeNull();
    await user.click(screen.getByRole("button", { name: "筛选" }));
    await user.click(screen.getByRole("combobox", { name: "筛选策略来源" }));
    await user.click(screen.getByRole("option", { name: "未关联授权策略" }));
    expect(screen.getByRole("button", { name: "查看用户 new.user" })).toBeTruthy();
    expect(within(screen.getByRole("region", { name: "资源所有者" })).getByRole("button", { name: "查看用户 admin" })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "清除筛选" }));
    expect(within(screen.getByRole("table", { name: "租户用户列表" })).getAllByRole("row")).toHaveLength(3);
  });

  it("keeps navigation out of mutation renders but updates it when permissions change", async () => {
    let finish!: () => void;
    const repository = accounts({ execute: vi.fn(() => new Promise<void>((resolve) => { finish = resolve; })) });
    const { user } = await openAccess(repository, iam(), "settings");
    await screen.findByRole("button", { name: "保存别名" });
    await user.type(screen.getByLabelText(/^主账号别名/), "acme");
    expect(screen.getByTestId("can-manage").textContent).toBe("true");
    capabilityCommit.mockClear();
    await user.click(screen.getByRole("button", { name: "保存别名" }));
    expect(screen.getByRole("button", { name: "正在保存…" })).toBeTruthy();
    expect(capabilityCommit).not.toHaveBeenCalled();
    vi.mocked(repository.listUsers).mockRejectedValue(new HttpProblem(403, "FORBIDDEN"));
    await act(async () => { finish(); });
    await waitFor(() => expect(screen.getByTestId("can-manage").textContent).toBe("false"));
    expect(capabilityCommit).toHaveBeenCalled();
    expect(screen.queryByRole("button", { name: "保存别名" })).toBeNull();
  });

  it("switches a settings draft and an existing safe error without reloading IAM", async () => {
    const repository = accounts({ execute: vi.fn().mockRejectedValue(new HttpProblem(409, "PRIVATE UPSTREAM DETAIL")) });
    const { user } = await openAccess(repository);
    await screen.findByText("Developer A");
    await user.click(screen.getByTestId("nav-settings"));
    await user.type(screen.getByLabelText("主账号别名", { exact: true }), "team-new");
    await user.click(screen.getByRole("button", { name: "Switch language" }));
    expect(screen.getByTestId("nav-settings").getAttribute("aria-current")).toBe("page");
    expect((screen.getByLabelText("Primary account alias", { exact: true }) as HTMLInputElement).value).toBe("team-new");
    await user.click(screen.getByRole("button", { name: "Save alias" }));
    expect((await screen.findByRole("alert")).textContent).toContain("The name is taken or reserved");
    await user.click(screen.getByRole("button", { name: "Switch language" }));
    expect(screen.getByRole("alert").textContent).toContain("名称已被占用或保留");
    expect(screen.getByRole("alert").textContent).not.toContain("PRIVATE UPSTREAM");
    expect((screen.getByLabelText("主账号别名", { exact: true }) as HTMLInputElement).value).toBe("team-new");
    expect(repository.currentIdentity).toHaveBeenCalledTimes(1);
  });

  it("localizes the complete management dialog and restores its initiating action", async () => {
    const { user } = await openAccess();
    await screen.findByText("Developer A");
    await user.click(screen.getByRole("button", { name: "Switch language" }));
    const trigger = screen.getByRole("button", { name: "View user developer" });
    await user.click(trigger);
    const dialog = screen.getByRole("dialog", { name: "Manage Developer A" });
    expect(dialog.textContent).not.toMatch(/\p{Script=Han}/u);
    expect(within(dialog).getByRole("button", { name: "Revoke policy ReadOnlyAccess" })).toBeTruthy();
    expect((within(dialog).getByRole("button", { name: "Attach policy" }) as HTMLButtonElement).disabled).toBe(true);
    await user.click(within(dialog).getByRole("button", { name: "Reset password" }));
    expect(document.activeElement).toBe(within(dialog).getByLabelText("Initial password"));
    expect(dialog.textContent).not.toMatch(/\p{Script=Han}/u);
    await user.click(within(dialog).getAllByRole("button", { name: "Close details" })[0]!);
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(document.activeElement).toBe(trigger);
    await user.click(screen.getByTestId("nav-roles"));
    expect(screen.getByText("This capability is not connected")).toBeTruthy();
    await user.click(screen.getByTestId("nav-policies"));
    expect(screen.getByRole("table", { name: "Policy metadata directory" })).toBeTruthy();
    await user.click(screen.getByTestId("nav-tenants"));
    expect(screen.getByRole("table", { name: "Tenant accounts" })).toBeTruthy();
  });

  it("starts on a dedicated overview and opens the user workspace without an extra fetch", async () => {
    const repository = accounts();
    const { user } = await openAccess(repository, iam(), "overview");
    await screen.findByText("Account owner");
    expect(screen.getByText("所属账号 · 资源归属")).toBeTruthy();
    expect(screen.queryByRole("table", { name: "子用户列表" })).toBeNull();
    await user.click(screen.getByTestId("nav-users"));
    await screen.findByText("Developer A");
    expect(repository.currentIdentity).toHaveBeenCalledTimes(1);
  });

  it("separates the resource owner from subusers and defaults creation to no business grant", async () => {
    const { user, repository, view } = await openAccess();
    await screen.findByText("Developer A");
    expect(screen.queryByRole("button", { name: "管理 admin" })).toBeNull();
    await user.click(screen.getByRole("button", { name: "创建用户" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(screen.getByRole("form", { name: "创建子用户" })).toBeTruthy();
    await user.type(screen.getByLabelText(/^子用户名/), "new.developer");
    await user.type(screen.getByLabelText("用户显示名称"), "New Developer");
    await user.type(screen.getByLabelText(/^初始密码/), "New-Child-Test-Password-49!");
    await user.click(screen.getByRole("button", { name: "下一步" }));
    expect(screen.getByText("新用户将按默认拒绝创建，不在创建请求中捆绑权限。")).toBeTruthy();
    expect(screen.queryByRole("combobox", { name: /^初始权限/ })).toBeNull();
    expect(repository.execute).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "下一步" }));
    expect(screen.queryByDisplayValue("New-Child-Test-Password-49!")).toBeNull();
    await user.click(screen.getByRole("button", { name: "确认创建用户" }));
    await waitFor(() => expect(repository.execute).toHaveBeenCalledWith(credential, { kind: "create-user", loginName: "new.developer", displayName: "New Developer", initialPassword: "New-Child-Test-Password-49!" }));
    expect(view.container.textContent).not.toContain(credential);
    expect(view.container.innerHTML).not.toContain("New-Child-Test-Password-49!");
  });

  it("sets an independent account alias with an optimistic version and shows both login forms", async () => {
    const repository = accounts();
    const { user } = await openAccess(repository);
    await screen.findByText("Developer A");
    await user.click(screen.getByTestId("nav-settings"));
    await user.type(screen.getByLabelText(/^主账号别名/), "acme");
    await user.click(screen.getByRole("button", { name: "保存别名" }));
    await waitFor(() => expect(repository.execute).toHaveBeenCalledWith(credential, { kind: "set-alias", alias: "acme", resourceVersion: 1 }));
    expect(screen.getByText("username@tenant-a")).toBeTruthy();
    expect(screen.getByText("admin", { exact: true })).toBeTruthy();
  });

  it("allows an unprivileged user to inspect its own settings without querying admin directories", async () => {
    const reader: AccountIdentity = { ...identity, principal: child.principal, policyAttachments: [], canCreateOrganizations: false };
    const repository = accounts({ currentIdentity: vi.fn().mockResolvedValue(reader), listUsers: vi.fn().mockRejectedValue(new HttpProblem(403, "FORBIDDEN")) });
    await openAccess(repository, iam({}, "child-a"), "overview");
    await screen.findByText("未授权");
    expect(repository.listUsers).toHaveBeenCalledTimes(1);
    expect(repository.listAccounts).not.toHaveBeenCalled();
    expect(screen.queryByRole("tab", { name: "租户管理" })).toBeNull();
    expect(screen.queryByRole("button", { name: "保存别名" })).toBeNull();
    expect(screen.getByText("username@tenant-a")).toBeTruthy();
  });

  it("keeps the tenant policy directory usable when only the platform directory is forbidden", async () => {
    const listPolicies = vi.fn(async (_credential: string, platform: boolean) => {
      if (platform) throw new HttpProblem(403, "FORBIDDEN");
      return directory(false);
    });
    const repository = accounts({ listPolicies });
    await openAccess(repository, iam(), "policies");
    expect(await screen.findByRole("table", { name: "策略元数据目录" })).toBeTruthy();
    expect(screen.getByText("ReadOnlyAccess")).toBeTruthy();
    expect(screen.getByText(/租户策略仍可查看/)).toBeTruthy();
    expect(listPolicies).toHaveBeenCalledTimes(2);
  });

  it("fails the live scene without substituting MOCK data when a policy directory has a non-authorization error", async () => {
    const repository = accounts({ listPolicies: vi.fn(async (_credential: string, platform: boolean) => {
      if (platform) throw new HttpProblem(503, "UPSTREAM_UNAVAILABLE");
      return directory(false);
    }) });
    await openAccess(repository, iam(), "policies");
    expect((await screen.findByRole("alert")).textContent).toContain("访问管理暂时不可用");
    expect(screen.queryByRole("table", { name: "策略元数据目录" })).toBeNull();
    expect(screen.queryByText("ReadOnlyAccess")).toBeNull();
  });

  it("requires an explicit current policy revision for every direct attachment", async () => {
    const { user, repository } = await openAccess();
    await user.click(await screen.findByRole("button", { name: "查看用户 developer" }));
    expect((screen.getByRole("button", { name: "关联策略" }) as HTMLButtonElement).disabled).toBe(true);
    await user.click(screen.getByRole("combobox", { name: "关联策略" }));
    await user.click(screen.getByRole("option", { name: /PlatformAdministrator/ }));
    await user.click(screen.getByRole("button", { name: "关联策略" }));
    await waitFor(() => expect(repository.execute).toHaveBeenCalledWith(credential, { kind: "create-policy-attachment", principalId: "child-a", policyId: "system.platform-admin", policyResourceVersion: 2 }));
    await waitFor(() => expect(screen.getByRole("combobox", { name: "关联策略" }).textContent).toBe("选择可关联策略"));
    expect((screen.getByRole("button", { name: "关联策略" }) as HTMLButtonElement).disabled).toBe(true);
  });

  it("requires confirmation for revocation and disabling and clears a submitted reset password", async () => {
    const { user, repository } = await openAccess();
    await user.click(await screen.findByRole("button", { name: "查看用户 developer" }));
    await user.click(screen.getByRole("button", { name: "撤销策略 ReadOnlyAccess" }));
    expect(repository.execute).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "确认撤销" }));
    await waitFor(() => expect(repository.execute).toHaveBeenCalledWith(credential, { kind: "revoke-policy-attachment", attachmentId: "attachment-child-a-system.paas-viewer", resourceVersion: 1 }));
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
