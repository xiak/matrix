import { act, cleanup, render, screen, waitFor, within } from "@testing-library/react";
import { Profiler, useState } from "react";
import userEvent from "@testing-library/user-event";
import { LocaleProvider, useLocalePreference } from "@/i18n/LocaleProvider";
import { UnsavedChangesProvider, useLeaveConfirmation } from "@ui/xiak";
import { afterEach, describe, expect, it, vi } from "vitest";
import { HttpProblem } from "@/infrastructure/http/jsonRequest";
import { SessionProvider, useSession } from "../application/SessionProvider";
import { AccountAccessProvider, useAccountCapabilities } from "../application/AccountAccessProvider";
import type { Account, AccountAccess, AccountAccessView, AccountIdentity, AccountPolicy, ActionCapability, AuthorizationProfileDirectory, CapabilityRestriction, IamAction, PolicyDirectory, User, UserAccess, UserPolicyAttachment, UserPermissionBoundary } from "../domain/accounts";
import type { AuthenticatorState, NotificationContact } from "../domain/personalSecurity";
import type { AccountRepository, IamRepository } from "../repositories/iamRepository";
import { AccountAccessRenderer } from "./AccountAccessRenderer";
import { LoginRenderer } from "./LoginRenderer";
import { buildAccountAccessScene } from "../scenes/accountAccessScene";

const navigation = vi.hoisted(() => ({ replace: vi.fn() }));
vi.mock("next/navigation", () => ({ useRouter: () => navigation }));
const credential = "account-test-only-memory-credential";
const timestamp = "2026-09-11T08:00:00Z";
const account: Account = { id: "tenant-a", displayName: "Team A", status: "ACTIVE", rootIdentity: { principalId: "primary-a", loginName: "admin" }, loginAlias: null, resourceVersion: 1 };
const rootUser: User = { id: "primary-a", accountId: "tenant-a", loginName: "admin", displayName: "Account owner", status: "ACTIVE", resourceVersion: 2, mustChangePassword: false };
const tenantPolicy: AccountPolicy = { id: "system.paas-viewer", management: "SYSTEM", accountId: null, displayName: "ReadOnlyAccess", scope: "TENANT", status: "ACTIVE", defaultVersionId: "version-1", resourceVersion: 3, createdAt: timestamp, updatedAt: timestamp };
const platformPolicy: AccountPolicy = { ...tenantPolicy, id: "system.platform-admin", displayName: "PlatformAdministrator", scope: "INSTALLATION", resourceVersion: 2 };
const attachment = (principalId: string, policy: AccountPolicy): UserPolicyAttachment => ({ id: `attachment-${principalId}-${policy.id}`, accountId: "tenant-a", target: { kind: "USER", id: principalId }, policyId: policy.id, scope: policy.scope, installationId: policy.scope === "INSTALLATION" ? "installation-a" : null, resourceVersion: 1, createdAt: timestamp, updatedAt: timestamp });
const directory = (platform: boolean): PolicyDirectory => ({ accountId: "tenant-a", scope: platform ? "INSTALLATION" : "TENANT", installationId: platform ? "installation-a" : null, items: [platform ? platformPolicy : tenantPolicy] });
const profileDirectory = (): AuthorizationProfileDirectory => ({ accountId: account.id, items: [{
  profile: { product: "paas", revision: 1, callingService: "PAAS", actions: [{ action: "paas.application.read", resourceKind: "APPLICATION", scope: "TENANT", resourceShapes: [{ mode: "INSTANCE", prefixAllowed: true }], conditions: [{ key: "iam.account-id", valueType: "STRING", source: "IAM_AUTHENTICATED_IDENTITY" }] }] },
  contentDigest: `sha256:${"a".repeat(64)}`
}] });
const capability = (action: IamAction, kind: ActionCapability["resource"]["kind"], id: string, reason: CapabilityRestriction | null = null): ActionCapability => ({ action, resource: { kind, id }, available: reason === null, restrictionReason: reason });
const currentCapabilities = (available = true): ActionCapability[] => [
  capability("iam.account.create", "ACCOUNT", "collection", available ? null : "AUTHORITY_REQUIRED"),
  capability("iam.account.read", "ACCOUNT", "collection", available ? null : "AUTHORITY_REQUIRED"),
  capability("iam.account.alias-set", "ACCOUNT", account.id, available ? null : "AUTHORITY_REQUIRED"),
  capability("iam.user.list", "ACCOUNT", account.id, available ? null : "AUTHORITY_REQUIRED"),
  capability("iam.user.create", "ACCOUNT", account.id, available ? null : "AUTHORITY_REQUIRED"),
  capability("iam.policy.list", "ACCOUNT", account.id, available ? null : "AUTHORITY_REQUIRED"),
  capability("iam.group.list", "ACCOUNT", account.id, available ? null : "AUTHORITY_REQUIRED"),
  capability("iam.group.create", "ACCOUNT", account.id, available ? null : "AUTHORITY_REQUIRED")
];
const userCapabilities = (user: User, attachments: UserPolicyAttachment[] = [], reason: CapabilityRestriction | null = null): ActionCapability[] => [
  capability("iam.user.read", "USER", user.id, reason),
  capability("iam.user.update", "USER", user.id, reason),
  capability("iam.user.permission-boundary.set", "USER", user.id, reason),
  capability("iam.user.permission-boundary.remove", "USER", user.id, reason),
  capability("iam.user.delete", "USER", user.id, reason ?? (user.status === "ACTIVE" ? "TARGET_MUST_BE_DISABLED" : null)),
  capability("iam.user.set-status", "USER", user.id, reason),
  capability("iam.user.reset-password", "USER", user.id, reason),
  capability("iam.policy-attachment.create", "USER", user.id),
  capability("iam.platform-policy-attachment.create", "USER", user.id),
  ...attachments.map((item) => capability(item.scope === "INSTALLATION" ? "iam.platform-policy-attachment.revoke" : "iam.policy-attachment.revoke", "POLICY_ATTACHMENT", item.id))
];
const accountAccess = (value: Account): AccountAccess => ({ account: value, capabilities: [
  capability("iam.account.set-status", "ACCOUNT", value.id),
  capability("iam.account.recover-root-credentials", "ACCOUNT", value.id)
] });
const identity: AccountIdentity = {
  account, user: rootUser, identityKind: "ROOT_IDENTITY", policySources: [], permissionBoundary: { accountId: account.id, userId: rootUser.id, resourceVersion: rootUser.resourceVersion, policy: null }, capabilities: currentCapabilities()
};
const childUser: User = { ...rootUser, id: "child-a", loginName: "developer", displayName: "Developer A" };
const child: UserAccess = { user: childUser, policyAttachments: [attachment("child-a", tenantPolicy)], capabilities: userCapabilities(childUser, [attachment("child-a", tenantPolicy)]) };

function iam(overrides: Partial<IamRepository> = {}, id = "primary-a"): IamRepository {
  return {
    login: vi.fn().mockResolvedValue({ credential, mustChangePassword: false, session: { id: "session-test", organizationId: "tenant-a", principalId: id, status: "ACTIVE", issuedAt: "2026-08-27T00:00:00Z", expiresAt: "2099-08-27T00:00:00Z" } }),
    changePassword: vi.fn(), logout: vi.fn(), ...overrides
  };
}

function accounts(overrides: Partial<AccountRepository> = {}): AccountRepository {
  return {
    currentIdentity: vi.fn().mockResolvedValue(structuredClone(identity)),
    listUsers: vi.fn().mockResolvedValue({ items: [child], nextAfter: null }),
    getUser: vi.fn().mockResolvedValue(structuredClone(child)),
    listPolicies: vi.fn().mockImplementation(async (_credential: string, platform: boolean) => directory(platform)),
    listAuthorizationProfiles: vi.fn().mockResolvedValue(profileDirectory()),
    listAccounts: vi.fn().mockResolvedValue({ items: [accountAccess(identity.account)], nextAfter: null }),
    execute: vi.fn().mockResolvedValue(undefined), ...overrides
  } as AccountRepository;
}

function boundaryFixture() {
  const target = structuredClone(child);
  let boundary: UserPermissionBoundary = { accountId: account.id, userId: target.user.id, resourceVersion: target.user.resourceVersion, policy: null };
  let policies = [structuredClone(tenantPolicy), { ...tenantPolicy, id: "customer.logs", management: "CUSTOMER" as const, accountId: account.id, displayName: "LogBoundary", resourceVersion: 4, defaultVersionId: "version-logs" }];
  const reference = (policyId: string) => {
    const policy = policies.find((item) => item.id === policyId)!;
    return { policyId, versionId: policy.defaultVersionId, contentDigest: `sha256:${"a".repeat(64)}` };
  };
  const boundaries = {
    read: vi.fn(async () => structuredClone(boundary)),
    set: vi.fn(async (_credential: string, _accountId: string, _userId: string, command: { policyId: string; policyResourceVersion: number; resourceVersion: number; requestId: string }) => {
      if (command.resourceVersion !== target.user.resourceVersion) throw new HttpProblem(409, "IAM_CONFLICT");
      target.user.resourceVersion += 1;
      boundary = { ...boundary, resourceVersion: target.user.resourceVersion, policy: reference(command.policyId) };
      return structuredClone(boundary);
    }),
    remove: vi.fn(async (_credential: string, _accountId: string, _userId: string, command: { resourceVersion: number; requestId: string }) => {
      if (command.resourceVersion !== target.user.resourceVersion) throw new HttpProblem(409, "IAM_CONFLICT");
      target.user.resourceVersion += 1;
      boundary = { ...boundary, resourceVersion: target.user.resourceVersion, policy: null };
      return structuredClone(boundary);
    })
  };
  const repository = accounts({
    permissionBoundaries: boundaries,
    getUser: vi.fn(async () => structuredClone(target)),
    listPolicies: vi.fn(async (_credential: string, platform: boolean) => platform ? directory(true) : { ...directory(false), items: structuredClone(policies) })
  });
  return { repository, boundaries,
    advance() { target.user.resourceVersion += 1; boundary.resourceVersion = target.user.resourceVersion; policies = policies.map((policy) => ({ ...policy, resourceVersion: policy.resourceVersion + 1 })); },
    readOnly() { target.capabilities = target.capabilities.map((capability) => capability.action.includes("permission-boundary") ? { ...capability, available: false, restrictionReason: "AUTHORITY_REQUIRED" } : capability); }
  };
}

async function openBoundary(fixture: ReturnType<typeof boundaryFixture>) {
  const result = await openAccess(fixture.repository);
  await screen.findByText("Developer A");
  await result.user.click(screen.getByRole("button", { name: "查看用户 developer" }));
  await screen.findByRole("region", { name: "权限边界" });
  return result;
}

async function chooseBoundary(user: ReturnType<typeof userEvent.setup>, label: string) {
  await user.click(screen.getByRole("button", { name: "修改权限边界" }));
  await user.click(screen.getByRole("combobox", { name: "权限边界" }));
  await user.click(screen.getByRole("option", { name: label }));
  await user.click(screen.getByRole("button", { name: "审阅变更" }));
}

function LanguageSwitch() {
  const { locale, setLocale } = useLocalePreference();
  return <button onClick={() => setLocale(locale === "en" ? "zh-CN" : "en")}>Switch language</button>;
}

const capabilityCommit = vi.fn();
function CapabilityProbe() {
  const capabilities = useAccountCapabilities();
  return <Profiler id="navigation-capabilities" onRender={capabilityCommit}>
    <output data-testid="can-manage">{String(capabilities.canListUsers)}</output>
    <output data-testid="can-read-accounts">{String(capabilities.canReadAccounts)}</output>
  </Profiler>;
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
    await waitFor(() => expect(navigation.replace).toHaveBeenCalledWith("/console/resources/", { scroll: false }));
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
    expect(navigation.replace).toHaveBeenCalledWith("/console/", { scroll: false });
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
  it("changes a live user boundary through selection, review and confirmation without changing grants", async () => {
    const f = boundaryFixture();
    const { user } = await openBoundary(f);
    expect(screen.queryByRole("dialog")).toBeNull();
    await chooseBoundary(user, "ReadOnlyAccess · system.paas-viewer");
    expect(f.boundaries.set).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "确认变更" }));
    await screen.findByText("权限边界变更已确认，用户状态已重新读取。");
    expect(f.boundaries.set).toHaveBeenLastCalledWith(credential, account.id, childUser.id, { policyId: tenantPolicy.id, policyResourceVersion: tenantPolicy.resourceVersion, resourceVersion: childUser.resourceVersion, requestId: expect.any(String) });
    await chooseBoundary(user, "LogBoundary · customer.logs");
    await user.click(screen.getByRole("button", { name: "确认变更" }));
    await screen.findByText("customer.logs", { exact: true });
    await chooseBoundary(user, "未设置租户权限边界");
    await user.click(screen.getByRole("button", { name: "确认变更" }));
    await screen.findByText("未设置租户权限边界");
    expect(f.boundaries.remove).toHaveBeenCalledWith(credential, account.id, childUser.id, { resourceVersion: childUser.resourceVersion + 2, requestId: expect.any(String) });
    expect(f.repository.execute).not.toHaveBeenCalled();
    expect(f.repository.currentIdentity).toHaveBeenCalledTimes(1);
  });

  it("owns keyboard focus while entering and leaving the inline boundary editor", async () => {
    const f = boundaryFixture();
    const { user } = await openBoundary(f);
    const edit = screen.getByRole("button", { name: "修改权限边界" });
    edit.focus();
    await user.keyboard("{Enter}");
    await waitFor(() => expect(document.activeElement).toBe(screen.getByRole("combobox", { name: "权限边界" })));
    await user.click(screen.getByRole("combobox", { name: "权限边界" }));
    await user.click(screen.getByRole("option", { name: "ReadOnlyAccess · system.paas-viewer" }));
    await user.click(screen.getByRole("button", { name: "审阅变更" }));
    await user.click(screen.getByRole("button", { name: "返回选择" }));
    await waitFor(() => expect(document.activeElement).toBe(screen.getByRole("combobox", { name: "权限边界" })));
    const cancel = screen.getByRole("button", { name: "取消" });
    cancel.focus();
    await user.keyboard("{Enter}");
    await waitFor(() => expect(document.activeElement).toBe(screen.getByRole("button", { name: "修改权限边界" })));
    expect(f.boundaries.set).not.toHaveBeenCalled();
    expect(f.boundaries.remove).not.toHaveBeenCalled();
  });

  it("keeps the exact live boundary request and review after an uncertain outcome", async () => {
    const f = boundaryFixture();
    f.boundaries.set.mockRejectedValueOnce(new HttpProblem(503, "IAM_UNAVAILABLE"));
    const { user } = await openBoundary(f);
    await chooseBoundary(user, "LogBoundary · customer.logs");
    await user.click(screen.getByRole("button", { name: "确认变更" }));
    await screen.findByText(/请求结果尚未确认/);
    expect((screen.getByRole("button", { name: "返回选择" }) as HTMLButtonElement).disabled).toBe(true);
    await user.click(screen.getByRole("button", { name: "重试原请求" }));
    await screen.findByText("权限边界变更已确认，用户状态已重新读取。");
    expect(f.boundaries.set.mock.calls[0]).toEqual(f.boundaries.set.mock.calls[1]);
  });

  it("does not resubmit an acknowledged boundary change when the follow-up read fails", async () => {
    const f = boundaryFixture();
    const { user } = await openBoundary(f);
    await chooseBoundary(user, "LogBoundary · customer.logs");
    f.boundaries.read.mockRejectedValueOnce(new HttpProblem(503, "IAM_UNAVAILABLE"));
    await user.click(screen.getByRole("button", { name: "确认变更" }));
    await screen.findByText(/边界变更已确认，但暂无法重新读取/);
    expect(screen.getByText("customer.logs", { exact: true })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "重试读取" }));
    await screen.findByText("权限边界变更已确认，用户状态已重新读取。");
    expect(f.boundaries.set).toHaveBeenCalledTimes(1);
  });

  it("retains a stale boundary selection but requires fresh revisions and a new explicit review", async () => {
    const f = boundaryFixture();
    const { user } = await openBoundary(f);
    await chooseBoundary(user, "LogBoundary · customer.logs");
    f.advance();
    await user.click(screen.getByRole("button", { name: "确认变更" }));
    await screen.findByText(/用户或策略版本已变化/);
    await user.click(screen.getByRole("button", { name: "重新读取并审阅" }));
    const selection = await screen.findByRole("combobox", { name: "权限边界" });
    expect(selection.textContent).toContain("LogBoundary");
    expect(f.boundaries.set).toHaveBeenCalledTimes(1);
    await user.click(screen.getByRole("button", { name: "审阅变更" }));
    await user.click(screen.getByRole("button", { name: "确认变更" }));
    await screen.findByText("权限边界变更已确认，用户状态已重新读取。");
    const first = f.boundaries.set.mock.calls[0]![3], second = f.boundaries.set.mock.calls[1]![3];
    expect(second.resourceVersion).toBe(first.resourceVersion + 1);
    expect(second.policyResourceVersion).toBe(first.policyResourceVersion + 1);
    expect(second.requestId).not.toBe(first.requestId);
  });

  it("expires sensitive live boundary state on 401 rather than leaving an editable private page", async () => {
    const f = boundaryFixture();
    f.boundaries.set.mockRejectedValueOnce(new HttpProblem(401, "IAM_EXPIRED"));
    const { user, view } = await openBoundary(f);
    await chooseBoundary(user, "LogBoundary · customer.logs");
    await user.click(screen.getByRole("button", { name: "确认变更" }));
    await screen.findByRole("button", { name: "登录控制台" });
    expect(screen.queryByRole("region", { name: "权限边界" })).toBeNull();
    expect(view.container.textContent).not.toContain(credential);
    expect(JSON.stringify([Object.entries(localStorage), Object.entries(sessionStorage)])).not.toContain(credential);
    expect(JSON.stringify([Object.entries(localStorage), Object.entries(sessionStorage)])).not.toContain("customer.logs");
  });

  it("does not offer boundary mutations when both authoritative capabilities are unavailable", async () => {
    const f = boundaryFixture(); f.readOnly();
    await openBoundary(f);
    expect(screen.queryByRole("button", { name: "修改权限边界" })).toBeNull();
    expect(screen.getByText(/当前身份没有此用户的边界变更权限/)).toBeTruthy();
    expect(f.boundaries.set).not.toHaveBeenCalled();
    expect(f.boundaries.remove).not.toHaveBeenCalled();
  });
  it("keeps owner identity separate from child targets and never infers identity type from policy names", () => {
    const namedAdministrator = { ...tenantPolicy, id: "customer.administrator", management: "CUSTOMER" as const, accountId: "tenant-a", displayName: "TenantAdministrator" };
    const adminAttachment = attachment("child-a", namedAdministrator);
    const adminChild: UserAccess = { ...child, policyAttachments: [adminAttachment], capabilities: userCapabilities(child.user, [adminAttachment]) };
    const tenantDirectory = { ...directory(false), items: [namedAdministrator, tenantPolicy].sort((left, right) => left.id.localeCompare(right.id)) };
    const scene = buildAccountAccessScene(identity, { items: [adminChild], nextAfter: null }, null, tenantDirectory, directory(true));
    expect(scene.accountOwner).toMatchObject({ id: "primary-a", accountType: "primary", name: "Account owner", state: "active" });
    expect(scene.users).toHaveLength(1);
    expect(scene.users[0]).toMatchObject({ id: "child-a", accountType: "subuser", attachments: [{ policyId: "customer.administrator" }] });
    const actingChild: AccountIdentity = { ...identity, user: child.user, identityKind: "USER", permissionBoundary: { accountId: account.id, userId: child.user.id, resourceVersion: child.user.resourceVersion, policy: null }, policySources: child.policyAttachments.map((attachment) => ({ kind: "DIRECT" as const, attachment })), capabilities: currentCapabilities(false) };
    const selfProtected: UserAccess = { ...child, capabilities: userCapabilities(child.user, child.policyAttachments, "SELF_PROTECTED") };
    const pageWithoutOwner = buildAccountAccessScene(actingChild, { items: [selfProtected], nextAfter: "later" }, null, directory(false), null);
    expect(pageWithoutOwner.accountOwner).toMatchObject({ id: "primary-a", loginName: "admin", name: null, state: null, isCurrent: false });
    expect(pageWithoutOwner.accountOwner.name).not.toBe(actingChild.user.displayName);
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
    const adminChild: UserAccess = child;
    const ungrantedUser: User = { ...child.user, id: "ungranted", loginName: "new.user" };
    const ungranted: UserAccess = { user: ungrantedUser, policyAttachments: [], capabilities: userCapabilities(ungrantedUser) };
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

  it("keeps navigation out of mutation renders and preserves unrelated exact capabilities", async () => {
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
    expect(screen.getByTestId("can-read-accounts").textContent).toBe("true");
    expect(capabilityCommit).toHaveBeenCalled();
    expect(screen.getByRole("button", { name: "保存别名" })).toBeTruthy();
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

  it("localizes content-area user management and focuses the new destination", async () => {
    const { user } = await openAccess();
    await screen.findByText("Developer A");
    await user.click(screen.getByRole("button", { name: "Switch language" }));
    const trigger = screen.getByRole("button", { name: "View user developer" });
    await user.click(trigger);
    const heading = await screen.findByRole("heading", { name: "developer" });
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(document.activeElement).toBe(heading);
    const region = screen.getByRole("region", { name: "Identity and access" });
    expect(region.textContent).not.toMatch(/\p{Script=Han}/u);
    expect(within(region).getByRole("button", { name: "Revoke policy ReadOnlyAccess" })).toBeTruthy();
    expect((within(region).getByRole("button", { name: "Attach policy" }) as HTMLButtonElement).disabled).toBe(true);
    await user.click(within(region).getByRole("button", { name: "Reset password" }));
    expect(document.activeElement).toBe(within(region).getByLabelText("Initial password"));
    expect(region.textContent).not.toMatch(/\p{Script=Han}/u);
    await user.click(screen.getByRole("button", { name: "Back to list" }));
    expect(await screen.findByRole("table", { name: "Tenant users" })).toBeTruthy();
    await user.click(screen.getByTestId("nav-roles"));
    expect(screen.getByText("This capability is not connected")).toBeTruthy();
    await user.click(screen.getByTestId("nav-policies"));
    expect(screen.getByRole("table", { name: "Policy metadata directory" })).toBeTruthy();
    await user.click(screen.getByTestId("nav-tenants"));
    expect(screen.getByRole("table", { name: "Tenant accounts" })).toBeTruthy();
  });

  it("opens account lifecycle management from the object name without adding an operation column", async () => {
    const repository = accounts();
    const { user } = await openAccess(repository, iam(), "tenants");
    const table = await screen.findByRole("table", { name: "租户账号列表" });
    expect(within(table).queryByRole("columnheader", { name: "操作" })).toBeNull();
    await user.click(within(table).getByRole("button", { name: "Team A" }));
    expect(screen.getByRole("heading", { name: "Team A" })).toBeTruthy();
    expect(screen.queryByRole("table", { name: "租户账号列表" })).toBeNull();
    await user.click(screen.getByRole("button", { name: "停用账户" }));
    await user.click(screen.getByRole("button", { name: "确认停用账户" }));
    await waitFor(() => expect(repository.execute).toHaveBeenCalledWith(credential, {
      kind: "set-account-status",
      accountId: "tenant-a",
      status: "DISABLED",
      resourceVersion: 1
    }));
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

  it("pages each live directory without reloading identity or unrelated IAM collections", async () => {
    const userCursor = "ic1.dXNlcnM";
    const accountCursor = "ic1.YWNjb3VudHM";
    const nextUser: UserAccess = {
      user: { ...childUser, id: "child-b", loginName: "auditor", displayName: "Auditor B" },
      policyAttachments: [],
      capabilities: userCapabilities({ ...childUser, id: "child-b", loginName: "auditor", displayName: "Auditor B" })
    };
    const nextAccount: Account = {
      ...account,
      id: "tenant-b",
      displayName: "Team B",
      rootIdentity: { principalId: "primary-b", loginName: "owner-b" }
    };
    const listUsers = vi.fn(async (_credential: string, after?: string) => after
      ? { items: [nextUser], nextAfter: null }
      : { items: [child], nextAfter: userCursor });
    const listAccounts = vi.fn(async (_credential: string, after?: string) => after
      ? { items: [accountAccess(nextAccount)], nextAfter: null }
      : { items: [accountAccess(account)], nextAfter: accountCursor });
    const listPolicies = vi.fn(async (_credential: string, platform: boolean) => directory(platform));
    const repository = accounts({ listUsers, listAccounts, listPolicies });
    const { user } = await openAccess(repository);

    await screen.findByText("Developer A");
    await user.click(screen.getByRole("button", { name: "下一页" }));
    expect(await screen.findByText("Auditor B")).toBeTruthy();
    expect(listUsers).toHaveBeenNthCalledWith(2, credential, userCursor);
    expect(repository.currentIdentity).toHaveBeenCalledTimes(1);
    expect(listPolicies).toHaveBeenCalledTimes(2);
    expect(listAccounts).toHaveBeenCalledTimes(1);

    await user.click(screen.getByTestId("nav-tenants"));
    await user.click(screen.getByRole("button", { name: "下一页" }));
    expect(await screen.findByRole("button", { name: "Team B" })).toBeTruthy();
    expect(listAccounts).toHaveBeenNthCalledWith(2, credential, accountCursor);
    expect(repository.currentIdentity).toHaveBeenCalledTimes(1);
    expect(listUsers).toHaveBeenCalledTimes(2);
    expect(listPolicies).toHaveBeenCalledTimes(2);
  });

  it("replaces the directory immediately with a local skeleton before loading live user details", async () => {
    let resolveUser!: (value: UserAccess) => void;
    const getUser = vi.fn(() => new Promise<UserAccess>((resolve) => { resolveUser = resolve; }));
    const repository = accounts({ getUser });
    const { user } = await openAccess(repository);
    await screen.findByText("Developer A");
    await user.click(screen.getByRole("button", { name: "查看用户 developer" }));
    expect(screen.queryByRole("table", { name: "租户用户列表" })).toBeNull();
    expect(screen.getByText("正在读取用户详情…")).toBeTruthy();
    expect(screen.queryByText("用户资料")).toBeNull();
    await act(async () => { resolveUser(structuredClone(child)); });
    expect(await screen.findByText("用户资料")).toBeTruthy();
    expect(getUser).toHaveBeenCalledWith(credential, "child-a");
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(screen.getByText(/不根据用户状态推断访问方式/)).toBeTruthy();
  });

  it("updates only the display name through the live user revision", async () => {
    const repository = accounts();
    const { user } = await openAccess(repository);
    await user.click(await screen.findByRole("button", { name: "查看用户 developer" }));
    await user.click(await screen.findByRole("button", { name: "修改显示名称" }));
    const field = screen.getByLabelText("用户显示名称");
    await user.clear(field);
    await user.type(field, "Developer Renamed");
    await user.click(screen.getByRole("button", { name: "保存显示名称" }));
    await waitFor(() => expect(repository.execute).toHaveBeenCalledWith(credential, { kind: "update-user", userId: "child-a", displayName: "Developer Renamed", resourceVersion: 2 }));
  });

  it("requires disablement and typed confirmation before irreversible live deletion", async () => {
    const disabledUser: User = { ...childUser, status: "DISABLED", resourceVersion: 5 };
    const disabledAttachment = attachment(disabledUser.id, tenantPolicy);
    const disabled: UserAccess = { user: disabledUser, policyAttachments: [disabledAttachment], capabilities: userCapabilities(disabledUser, [disabledAttachment]) };
    const repository = accounts({
      listUsers: vi.fn().mockResolvedValue({ items: [disabled], nextAfter: null }),
      getUser: vi.fn().mockResolvedValue(structuredClone(disabled))
    });
    const { user } = await openAccess(repository);
    await user.click(await screen.findByRole("button", { name: "查看用户 developer" }));
    const deleteButton = await screen.findByRole("button", { name: "删除用户" });
    expect((deleteButton as HTMLButtonElement).disabled).toBe(false);
    await user.click(deleteButton);
    expect(repository.execute).not.toHaveBeenCalled();
    const confirmation = screen.getByLabelText("输入 developer 确认删除");
    await user.type(confirmation, "developer");
    await user.click(screen.getByRole("button", { name: "永久删除用户" }));
    await waitFor(() => expect(repository.execute).toHaveBeenCalledWith(credential, { kind: "delete-user", userId: "child-a", resourceVersion: 5 }));
    expect(await screen.findByRole("table", { name: "租户用户列表" })).toBeTruthy();
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

  it("keeps the personal-security shell stable while only live security cards load", async () => {
    let finishContact!: (value: NotificationContact) => void;
    let finishFactor!: (value: AuthenticatorState) => void;
    const security = {
      notificationContact: vi.fn(() => new Promise<NotificationContact>((resolve) => { finishContact = resolve; })),
      authenticatorState: vi.fn(() => new Promise<AuthenticatorState>((resolve) => { finishFactor = resolve; })),
      startNotificationVerification: vi.fn(), notificationVerification: vi.fn(), confirmNotificationVerification: vi.fn(),
      startTOTPEnrollment: vi.fn(), totpEnrollment: vi.fn(), totpEnrollmentByRequest: vi.fn(), cancelTOTPEnrollment: vi.fn(), confirmTOTPEnrollment: vi.fn()
    };
    await openAccess(accounts(), iam({ personalSecurity: security }), "settings");
    const securityRegion = (await screen.findByRole("heading", { name: "安全通知与身份验证器" })).closest("section")!;
    expect(within(securityRegion).getByRole("heading", { name: "安全通知地址" })).toBeTruthy();
    expect(within(securityRegion).getByRole("heading", { name: "身份验证器应用" })).toBeTruthy();
    expect(screen.queryByRole("dialog")).toBeNull();
    await act(async () => {
      finishContact({ accountId: account.id, userId: rootUser.id, state: "NONE", resourceVersion: 0, pendingVerificationId: null });
      finishFactor({ enrollmentState: "NEVER_BOUND", factorRevision: 1, factorId: null });
    });
    expect(await within(securityRegion).findByText("未设置")).toBeTruthy();
  });

  it("verifies the first notification address inline before enabling first authenticator enrollment", async () => {
    const none = { accountId: account.id, userId: rootUser.id, state: "NONE" as const, resourceVersion: 0 as const, pendingVerificationId: null };
    const verified = { accountId: account.id, userId: rootUser.id, state: "VERIFIED" as const, resourceVersion: 1, email: "admin@example.com", verifiedAt: timestamp, pendingVerificationId: null };
    const verification = { id: "verification-one", accountId: account.id, userId: rootUser.id, requestId: "request-one", email: "admin@example.com", state: "PENDING" as const, issuedAt: timestamp, expiresAt: "2026-09-11T08:10:00Z", completedAt: null, delivery: { state: "ACCEPTED" as const, attempts: 1, lastOutcome: "ACCEPTED" as const, lastSmtpCode: 250, updatedAt: timestamp } };
    const security = {
      notificationContact: vi.fn().mockResolvedValueOnce(none).mockResolvedValue(verified),
      authenticatorState: vi.fn().mockResolvedValue({ enrollmentState: "NEVER_BOUND", factorRevision: 1, factorId: null }),
      startNotificationVerification: vi.fn().mockResolvedValue(verification),
      notificationVerification: vi.fn(),
      confirmNotificationVerification: vi.fn().mockResolvedValue({ ...verification, state: "VERIFIED", completedAt: "2026-09-11T08:02:00Z" }),
      startTOTPEnrollment: vi.fn(), totpEnrollment: vi.fn(), totpEnrollmentByRequest: vi.fn(), cancelTOTPEnrollment: vi.fn(), confirmTOTPEnrollment: vi.fn()
    };
    const { user } = await openAccess(accounts(), iam({ personalSecurity: security }), "settings");
    const securityRegion = (await screen.findByRole("heading", { name: "安全通知与身份验证器" })).closest("section")!;
    await within(securityRegion).findByText("未设置");
    await user.type(screen.getByLabelText("邮箱地址"), "admin@example.com");
    await user.type(screen.getAllByLabelText("当前密码")[0]!, "Private-Password-49!");
    await user.click(screen.getByRole("button", { name: "发送验证码" }));
    expect(await screen.findByText(/邮件服务器已接受/)).toBeTruthy();
    expect(screen.getByText(/不代表收件人已收到或阅读/)).toBeTruthy();
    await user.type(screen.getByLabelText("8 位邮箱验证码"), "12345678");
    await user.click(screen.getByRole("button", { name: "验证通知地址" }));
    expect(await screen.findByText("admin@example.com")).toBeTruthy();
    expect(screen.getByRole("button", { name: /开始绑定/ })).toBeTruthy();
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(security.startNotificationVerification).toHaveBeenCalledWith(credential, expect.objectContaining({ email: "admin@example.com", password: "Private-Password-49!" }));
    expect(security.confirmNotificationVerification).toHaveBeenCalledWith(credential, "verification-one", expect.objectContaining({ code: "12345678" }));
  });

  it("never renders TOTP provisioning or confirmation controls for an equal replay", async () => {
    const verified = { accountId: account.id, userId: rootUser.id, state: "VERIFIED" as const, resourceVersion: 1, email: "admin@example.com", verifiedAt: timestamp, pendingVerificationId: null };
    const enrollment = { id: "enrollment-one", requestId: "request-one", factorRevision: 1, state: "PENDING" as const, createdAt: timestamp, expiresAt: "2026-09-11T08:05:00Z", completedAt: null };
    const security = {
      notificationContact: vi.fn().mockResolvedValue(verified),
      authenticatorState: vi.fn().mockResolvedValue({ enrollmentState: "NEVER_BOUND" as const, factorRevision: 1, factorId: null }),
      startNotificationVerification: vi.fn(), notificationVerification: vi.fn(), confirmNotificationVerification: vi.fn(),
      startTOTPEnrollment: vi.fn().mockResolvedValue({ outcome: "EQUAL_REPLAY" as const, enrollment }),
      totpEnrollment: vi.fn(), totpEnrollmentByRequest: vi.fn(), cancelTOTPEnrollment: vi.fn().mockResolvedValue({ ...enrollment, state: "CANCELLED", completedAt: "2026-09-11T08:01:00Z" }), confirmTOTPEnrollment: vi.fn()
    };
    const { user } = await openAccess(accounts(), iam({ personalSecurity: security }), "settings");
    const securityRegion = (await screen.findByRole("heading", { name: "安全通知与身份验证器" })).closest("section")!;
    await within(securityRegion).findByText("admin@example.com");
    await user.type(screen.getByLabelText("当前密码"), "Private-Password-49!");
    await user.click(screen.getByRole("button", { name: "开始绑定" }));
    expect(await screen.findByText(/等值重放/)).toBeTruthy();
    expect(screen.queryByLabelText("6 位动态验证码")).toBeNull();
    expect(screen.queryByText(/手动密钥/)).toBeNull();
    expect(screen.getByRole("button", { name: "取消绑定" })).toBeTruthy();
    expect(security.confirmTOTPEnrollment).not.toHaveBeenCalled();
  });

  it("allows an unprivileged user to inspect its own settings without querying admin directories", async () => {
    const reader: AccountIdentity = { ...identity, user: child.user, identityKind: "USER", permissionBoundary: { accountId: account.id, userId: child.user.id, resourceVersion: child.user.resourceVersion, policy: null }, policySources: [], capabilities: currentCapabilities(false) };
    const repository = accounts({ currentIdentity: vi.fn().mockResolvedValue(reader), listUsers: vi.fn().mockRejectedValue(new HttpProblem(403, "FORBIDDEN")) });
    await openAccess(repository, iam({}, "child-a"), "overview");
    await screen.findByText("未授权");
    expect(repository.listUsers).not.toHaveBeenCalled();
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

  it("loads the permission catalog only after its tab opens and keeps product detail in the content area", async () => {
    const listAuthorizationProfiles = vi.fn().mockResolvedValue(profileDirectory());
    const { user } = await openAccess(accounts({ listAuthorizationProfiles }), iam(), "policies");
    expect(await screen.findByRole("table", { name: "策略元数据目录" })).toBeTruthy();
    expect(listAuthorizationProfiles).not.toHaveBeenCalled();

    await user.click(screen.getByRole("tab", { name: "权限能力目录" }));
    expect(await screen.findByRole("table", { name: "产品权限能力目录" })).toBeTruthy();
    expect(listAuthorizationProfiles).toHaveBeenCalledTimes(1);
    expect(screen.getByText(/不是当前用户权限/)).toBeTruthy();

    await user.click(screen.getByRole("button", { name: "paas" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(screen.getByRole("heading", { level: 2, name: "paas" })).toBe(document.activeElement);
    expect(screen.getByRole("table", { name: "产品 paas 的 Action 声明" })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "返回能力目录" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "paas" })).toBe(document.activeElement));
  });

  it.each([
    [403, "当前身份无权读取权限能力目录"],
    [404, "后端版本或路由可能未匹配"],
    [503, "权限能力目录暂时不可用"]
  ])("localizes catalog HTTP %s without replacing the policy directory or falling back to MOCK", async (status, message) => {
    const { user } = await openAccess(accounts({ listAuthorizationProfiles: vi.fn().mockRejectedValue(new HttpProblem(status, "PRIVATE")) }), iam(), "policies");
    await screen.findByRole("table", { name: "策略元数据目录" });
    await user.click(screen.getByRole("tab", { name: "权限能力目录" }));
    expect(await screen.findByText(new RegExp(message))).toBeTruthy();
    expect(screen.queryByText(/隔离 MOCK 的权限能力目录/)).toBeNull();
    await user.click(screen.getByRole("tab", { name: "策略目录" }));
    expect(screen.getByRole("table", { name: "策略元数据目录" })).toBeTruthy();
  });

  it("rejects a catalog bound to another account without clearing the policy scene", async () => {
    const { user } = await openAccess(accounts({ listAuthorizationProfiles: vi.fn().mockResolvedValue({ ...profileDirectory(), accountId: "tenant-b" }) }), iam(), "policies");
    await user.click(await screen.findByRole("tab", { name: "权限能力目录" }));
    expect(await screen.findByText(/权限能力目录暂时不可用/)).toBeTruthy();
    await user.click(screen.getByRole("tab", { name: "策略目录" }));
    expect(screen.getByRole("table", { name: "策略元数据目录" })).toBeTruthy();
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
    await waitFor(() => expect(repository.execute).toHaveBeenCalledWith(credential, { kind: "create-policy-attachment", userId: "child-a", policyId: "system.platform-admin", policyResourceVersion: 2 }));
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
    await waitFor(() => expect(repository.execute).toHaveBeenCalledWith(credential, { kind: "set-status", userId: "child-a", status: "DISABLED", resourceVersion: 2 }));
    await waitFor(() => expect((screen.getByRole("button", { name: "重置密码" }) as HTMLButtonElement).disabled).toBe(false));
    await user.click(screen.getByRole("button", { name: "重置密码" }));
    await user.type(screen.getByLabelText(/^初始密码/), "Reset-Only-Test-Password-74!");
    await user.click(screen.getByRole("button", { name: "确认重置密码" }));
    await waitFor(() => expect(repository.execute).toHaveBeenCalledWith(credential, { kind: "reset-password", userId: "child-a", initialPassword: "Reset-Only-Test-Password-74!", resourceVersion: 2 }));
    expect(screen.queryByDisplayValue("Reset-Only-Test-Password-74!")).toBeNull();
  });

  it.each(["identity", "directory", "principal", "root-directory"])("fails closed on a mismatched %s instead of showing another subject", async (mismatch) => {
    const other = structuredClone(identity);
    if (mismatch === "identity") other.account.id = "tenant-b";
    if (mismatch === "principal") other.user.id = "other-principal";
    const foreignUser: User = { ...child.user, accountId: "tenant-b", displayName: "PRIVATE OTHER USER" };
    const directoryUser = mismatch === "root-directory"
      ? { user: rootUser, policyAttachments: [], capabilities: userCapabilities(rootUser, [], "ROOT_IDENTITY_PROTECTED") }
      : { user: foreignUser, policyAttachments: [], capabilities: userCapabilities(foreignUser) };
    const repository = accounts({ currentIdentity: vi.fn().mockResolvedValue(other), ...(["directory", "root-directory"].includes(mismatch) ? { listUsers: vi.fn().mockResolvedValue({ items: [directoryUser], nextAfter: null }) } : {}) });
    await openAccess(repository);
    expect((await screen.findByRole("alert")).textContent).toContain("暂时不可用");
    expect(screen.queryByText("PRIVATE OTHER USER")).toBeNull();
    expect(screen.queryByRole("button", { name: "创建用户" })).toBeNull();
  });
});
