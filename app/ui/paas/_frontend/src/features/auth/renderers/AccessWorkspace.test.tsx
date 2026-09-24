import { useState } from "react";
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { LocaleProvider, useLocalePreference } from "@/i18n/LocaleProvider";
import { UnsavedChangesProvider, useLeaveConfirmation } from "@ui/xiak";
import { SessionProvider, useSession } from "../application/SessionProvider";
import { AccountAccessProvider, useAccountAccess } from "../application/AccountAccessProvider";
import { accountAccessViews, type AccountAccessView, type AccountIdentity, type ActionCapability, type CapabilityRestriction, type GroupAccess, type GroupMembershipAccess, type IamAction, type User, type UserAccess } from "../domain/accounts";
import type { AccountRepository, IamRepository } from "../repositories/iamRepository";
import { createPreviewAccessWorkspace } from "../repositories/previewAccessWorkspace";
import { PolicyDocumentViewer } from "./PolicyDocumentViewer";
import type { PolicyDocument } from "../domain/policyDocument";
import { AccountAccessRenderer } from "./AccountAccessRenderer";
import { GroupDirectory } from "./GroupAccessWorkspace";
import { AccessReports } from "./AccessReports";
import { buildAccessActivityObservations, buildAccessReport, buildAccessSecuritySnapshot } from "../scenes/accessReport";
import { buildAccountAccessScene } from "../scenes/accountAccessScene";
import { previewAccountRepository, previewCredential, previewIamRepository, resetPreviewEnvironment } from "../repositories/previewIamRepository";
import { HttpProblem } from "@/infrastructure/http/jsonRequest";

vi.mock("next/link", () => ({
  default: ({ onNavigate, href, children, ...props }: React.ComponentProps<"a"> & { onNavigate?(event: { preventDefault(): void }): void }) => <a {...props} href={href} onClick={(event) => {
    event.preventDefault(); // Real Next routing is a browser gate; jsdom exercises the feature's destination callback.
    if (!event.ctrlKey && !event.metaKey && !event.shiftKey && !event.altKey) onNavigate?.({ preventDefault() {} });
  }}>{children}</a>
}));

const account = { id: "org-xiak", displayName: "Example", status: "ACTIVE" as const, rootIdentity: { principalId: "admin", loginName: "admin" }, loginAlias: "example", resourceVersion: 1 };
const rootUser: User = { id: "admin", accountId: "org-xiak", loginName: "admin", displayName: "Administrator", status: "ACTIVE", mustChangePassword: false, resourceVersion: 1 };
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
const userAccess = (name: string): UserAccess => {
  const user: User = { ...rootUser, id: "principal-" + name, loginName: name, displayName: name };
  return { user, policyAttachments: [], capabilities: [
    capability("iam.user.read", "USER", user.id), capability("iam.user.update", "USER", user.id),
    capability("iam.user.delete", "USER", user.id, "TARGET_MUST_BE_DISABLED"),
    capability("iam.user.permission-boundary.set", "USER", user.id), capability("iam.user.permission-boundary.remove", "USER", user.id),
    capability("iam.user.set-status", "USER", user.id), capability("iam.user.reset-password", "USER", user.id),
    capability("iam.policy-attachment.create", "USER", user.id), capability("iam.platform-policy-attachment.create", "USER", user.id)
  ] };
};
const identity: AccountIdentity = { account, user: rootUser, identityKind: "ROOT_IDENTITY", policySources: [], permissionBoundary: { accountId: account.id, userId: rootUser.id, resourceVersion: rootUser.resourceVersion, policy: null }, capabilities: currentCapabilities() };
const users: UserAccess[] = ["lin", "chen"].map(userAccess);
const reviewUsers: UserAccess[] = [...users, ...["qiao", "wu"].map(userAccess)];
const login: IamRepository = { login: async () => ({ outcome: "AUTHENTICATED", credential: "preview-only", mustChangePassword: false, session: { id: "session", organizationId: "org-xiak", principalId: "admin", status: "ACTIVE", issuedAt: "2026-09-09T00:00:00Z", expiresAt: "2099-01-01T00:00:00Z" } }), changePassword: async () => {}, logout: async () => {} };

function AccountRefresh() {
  const access = useAccountAccess();
  return <button data-testid="refresh-account" onClick={access.reload}>Refresh account</button>;
}

function ReauthenticationGuardProbe() {
  const access = useAccountAccess();
  return <>
    <button data-testid="guard-workspace" onClick={() => void access.executeWorkspace({ kind: "save-sso-settings", userSsoEnabled: false, userSsoConfiguration: null })}>Protected workspace mutation</button>
    <button data-testid="guard-group" onClick={() => void access.groups?.create({ name: "BlockedGroup", description: "must not reach adapter", requestId: "blocked-group" }).catch(() => undefined)}>Protected group mutation</button>
  </>;
}

function Harness({ repository, initialView, initialEntityId }: { repository: AccountRepository; initialView: AccountAccessView; initialEntityId?: string }) {
  const requestLeave = useLeaveConfirmation();
  const session = useSession();
  const locale = useLocalePreference();
  const [view, setView] = useState(initialView);
  const [entityId, setEntityId] = useState(initialEntityId);
  const [policyMethod, setPolicyMethod] = useState<string>();
  if (!session.current) return <button onClick={() => void session.login("admin", "preview")}>Enter</button>;
  return <AccountAccessProvider repository={repository}><button onClick={() => locale.setLocale(locale.locale === "en" ? "zh-CN" : "en")}>Language</button><AccountRefresh /><ReauthenticationGuardProbe /><nav>{accountAccessViews.map((target) => <button data-testid={"go-" + target} key={target} onClick={() => requestLeave(() => { setView(target); setEntityId(undefined); setPolicyMethod(undefined); })}>{target}</button>)}</nav><output aria-label="Entity destination">{entityId ?? "directory"}</output><AccountAccessRenderer key={view + ":" + (entityId ?? "") + ":" + (policyMethod ?? "")} view={view} entityId={entityId} policyMethod={policyMethod} onNavigate={(next, id, method) => requestLeave(() => { setView(next); setEntityId(id); setPolicyMethod(method); })} /></AccountAccessProvider>;
}
async function open(initialView: AccountAccessView, options?: { live?: boolean; reader?: boolean; entityId?: string; users?: UserAccess[]; repository?: Partial<AccountRepository>; seed?(extension: ReturnType<typeof createPreviewAccessWorkspace>): Promise<void> }) {
  const directoryUsers = options?.users ?? users;
  const extension = createPreviewAccessWorkspace("org-xiak", () => directoryUsers.map((entry) => entry.user.id), identity.account.rootIdentity.principalId);
  await options?.seed?.(extension);
  const repository: AccountRepository = {
    currentIdentity: vi.fn().mockResolvedValue(options?.reader ? { ...identity, policySources: [], capabilities: currentCapabilities(false) } : identity),
    listUsers: options?.reader ? vi.fn().mockRejectedValue(new HttpProblem(403, "FORBIDDEN")) : vi.fn().mockResolvedValue({ items: directoryUsers, nextAfter: null }),
    getUser: vi.fn().mockImplementation(async (_credential: string, userId: string) => {
      const entry = directoryUsers.find((candidate) => candidate.user.id === userId);
      if (!entry) throw new HttpProblem(403, "FORBIDDEN");
      return entry;
    }),
    listPolicies: vi.fn().mockImplementation(async (_credential: string, platform: boolean) => ({ accountId: "org-xiak", scope: platform ? "INSTALLATION" : "TENANT", installationId: platform ? "preview" : null, items: [] })),
    listAuthorizationProfiles: vi.fn().mockResolvedValue({ accountId: "org-xiak", items: [{ profile: { product: "paas", revision: 1, callingService: "PAAS", actions: [{ action: "paas.application.read", resourceKind: "APPLICATION", scope: "TENANT", resourceShapes: [{ mode: "INSTANCE", prefixAllowed: true }] }] }, contentDigest: `sha256:${"a".repeat(64)}` }] }),
    listAccounts: vi.fn().mockResolvedValue({ items: [], nextAfter: null }),
    listGroups: vi.fn().mockRejectedValue(new Error("unused group contract")),
    getGroup: vi.fn().mockRejectedValue(new Error("unused group contract")),
    createGroup: vi.fn().mockRejectedValue(new Error("unused group contract")),
    updateGroup: vi.fn().mockRejectedValue(new Error("unused group contract")),
    deleteGroup: vi.fn().mockRejectedValue(new Error("unused group contract")),
    listGroupMemberships: vi.fn().mockRejectedValue(new Error("unused group contract")),
    createGroupMembership: vi.fn().mockRejectedValue(new Error("unused group contract")),
    removeGroupMembership: vi.fn().mockRejectedValue(new Error("unused group contract")),
    createGroupPolicyAttachment: vi.fn().mockRejectedValue(new Error("unused group contract")),
    revokePolicyAttachment: vi.fn().mockRejectedValue(new Error("unused group contract")),
    execute: vi.fn().mockResolvedValue(undefined),
    workspace: options?.live ? undefined : { read: vi.fn(extension.read), execute: vi.fn(extension.execute) },
    ...options?.repository
  };
  const user = userEvent.setup();
  render(<LocaleProvider><SessionProvider repository={login}><UnsavedChangesProvider><Harness initialView={initialView} initialEntityId={options?.entityId} repository={repository} /></UnsavedChangesProvider></SessionProvider></LocaleProvider>);
  await user.click(screen.getByRole("button", { name: "Enter" }));
  await waitFor(() => expect(repository.currentIdentity).toHaveBeenCalled());
  await waitFor(() => expect(screen.queryByLabelText("正在读取 IAM 账号信息…")).toBeNull());
  return { user, repository, extension };
}
async function seedBoundAccountRuleOperator(extension: ReturnType<typeof createPreviewAccessWorkspace>) {
  await extension.execute("preview", { kind: "confirm-personal-mfa" });
  await extension.execute("preview", { kind: "complete-personal-mfa-reauthentication" });
}
async function select(user: ReturnType<typeof userEvent.setup>, label: string, option: string) {
  if (!screen.queryByRole("combobox", { name: label })) await user.click(screen.getByRole("button", { name: /^筛选(?: \d+)?$/ }));
  await user.click(screen.getByRole("combobox", { name: label }));
  await user.click(screen.getByRole("option", { name: option }));
}
async function logActions(user: ReturnType<typeof userEvent.setup>, actions: string[]) {
  await select(user, "产品服务", "日志服务");
  for (const action of actions) await user.click(screen.getByRole("checkbox", { name: action }));
}
async function expectRetainedFailure(dialog: HTMLElement) {
  await waitFor(() => expect(within(dialog).getByRole("alert").textContent).toContain("重试"));
  expect(document.activeElement).toBe(within(dialog).getByRole("alert"));
}
afterEach(() => { cleanup(); localStorage.clear(); sessionStorage.clear(); resetPreviewEnvironment(); });

describe("selection-driven user directory", () => {
  async function openBatch() {
    resetPreviewEnvironment();
    const repository = { ...previewAccountRepository, listUsers: vi.fn(previewAccountRepository.listUsers), execute: vi.fn(previewAccountRepository.execute), executeUserBatch: vi.fn(previewAccountRepository.executeUserBatch!) };
    const user = userEvent.setup();
    render(<LocaleProvider><SessionProvider repository={previewIamRepository}><UnsavedChangesProvider><Harness initialView="users" repository={repository} /></UnsavedChangesProvider></SessionProvider></LocaleProvider>);
    await user.click(screen.getByRole("button", { name: "Enter" }));
    await screen.findByRole("checkbox", { name: "选择用户 lin" });
    return { user, repository };
  }
  async function action(user: ReturnType<typeof userEvent.setup>, label: string) {
    await user.click(screen.getByRole("button", { name: "更多操作" }));
    await user.click(screen.getByRole("menuitem", { name: label }));
  }
  it("keeps criteria distinct from an empty-result reset and clears batch targets across details", async () => {
    const { user } = await openBatch();
    await user.type(screen.getByRole("searchbox", { name: "搜索用户" }), "lin");
    await select(user, "筛选用户状态", "已禁用");
    expect(screen.getByText("没有匹配的用户")).toBeTruthy();
    expect(screen.getAllByRole("button", { name: "清除筛选" })).toHaveLength(1);
    await user.click(screen.getByRole("button", { name: "重置查询" }));
    expect((screen.getByRole("searchbox", { name: "搜索用户" }) as HTMLInputElement).value).toBe("");
    await user.type(screen.getByRole("searchbox", { name: "搜索用户" }), "lin");
    await user.click(screen.getByRole("checkbox", { name: "选择用户 lin" }));
    await user.click(screen.getByRole("button", { name: "查看用户 lin" }));
    await user.click(screen.getByRole("button", { name: "返回列表" }));
    expect((screen.getByRole("searchbox", { name: "搜索用户" }) as HTMLInputElement).value).toBe("lin");
    expect((screen.getByRole("checkbox", { name: "选择用户 lin" }) as HTMLInputElement).checked).toBe(false);
    expect(screen.getByRole("button", { name: "更多操作" }).hasAttribute("disabled")).toBe(true);
  });
  it("has no operation column, supports mixed page selection, and clears selection on filtering and paging", async () => {
    const { user, repository } = await openBatch();
    const table = screen.getByRole("table", { name: "租户用户列表" });
    expect(screen.getByText("第 1 / 1 页")).toBeTruthy();
    expect(screen.getByRole("combobox", { name: "每页条数" })).toBeTruthy();
    expect(within(table).queryByRole("columnheader", { name: "操作" })).toBeNull();
    expect(screen.getByRole("button", { name: "更多操作" }).hasAttribute("disabled")).toBe(true);
    await user.click(screen.getByRole("checkbox", { name: "选择用户 lin" }));
    const page = screen.getByRole("checkbox", { name: "选择当前筛选页的全部用户" }) as HTMLInputElement;
    expect(page.indeterminate).toBe(true);
    expect(screen.getByText("已选 1 位用户")).toBeTruthy();
    await user.click(page);
    expect(page.checked).toBe(true);
    await user.click(screen.getByRole("button", { name: "更多操作" }));
    const menu = within(screen.getByRole("menu", { name: "更多操作" }));
    expect(menu.getByRole("menuitem", { name: "添加到用户组" }).getAttribute("aria-disabled")).not.toBe("true");
    expect(menu.getByRole("menuitem", { name: /删除用户/ }).getAttribute("aria-disabled")).not.toBe("true");
    await user.keyboard("{Escape}");
    expect(document.activeElement).toBe(screen.getByRole("button", { name: "更多操作" }));
    await user.type(screen.getByRole("searchbox", { name: "搜索用户" }), "lin");
    expect(screen.queryByText(/已选 \d 位用户/)).toBeNull();
    await user.click(screen.getByRole("checkbox", { name: "选择当前筛选页的全部用户" }));
    expect(screen.getByText("已选 1 位用户")).toBeTruthy();
    await select(user, "每页条数", "20");
    await waitFor(() => expect(screen.getByRole("button", { name: "更多操作" }).hasAttribute("disabled")).toBe(true));
    expect(repository.executeUserBatch).not.toHaveBeenCalled();
  });
  it("reviews additive user memberships and retains existing associations", async () => {
    const { user, repository } = await openBatch();
    await user.click(screen.getByRole("checkbox", { name: "选择当前筛选页的全部用户" }));
    await action(user, "添加到用户组");
    let dialog = within(screen.getByRole("dialog"));
    expect(dialog.getByRole("table", { name: "本次操作的用户" })).toBeTruthy();
    await user.click(dialog.getByRole("checkbox", { name: "DeliveryTeam" }));
    await user.click(dialog.getByRole("button", { name: "审阅变更" }));
    expect(repository.executeUserBatch).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "Language" }));
    dialog = within(screen.getByRole("dialog"));
    expect(dialog.getByText(/The account owner is not a group member/)).toBeTruthy();
    await user.click(dialog.getByRole("button", { name: "Confirm action" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(repository.executeUserBatch).toHaveBeenCalledTimes(1);
    expect(repository.execute).not.toHaveBeenCalled();
    const state = await previewAccountRepository.workspace!.read(previewCredential);
    expect(state.groups[0]?.memberIds).toEqual(expect.arrayContaining(["principal-lin", "principal-chen"]));
    expect(state.groups[0]?.memberIds).not.toContain("admin");
    expect(state.groups[1]?.memberIds).toContain("principal-chen");
    expect(within(screen.getByRole("region", { name: "Resource owner" })).getByRole("button", { name: "View user admin" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "More actions" }).hasAttribute("disabled")).toBe(true);
  });
  it("preserves targets on failure, locks duplicate submissions and requires explicit destructive acknowledgement", async () => {
    const { user, repository } = await openBatch();
    await user.click(screen.getByRole("checkbox", { name: "选择用户 lin" }));
    await user.click(screen.getByRole("checkbox", { name: "选择用户 chen" }));
    await action(user, "禁用用户");
    let dialog = within(screen.getByRole("dialog"));
    expect(dialog.getByRole("button", { name: "确认执行" }).hasAttribute("disabled")).toBe(true);
    await user.click(dialog.getByRole("button", { name: "取消" }));
    expect(repository.executeUserBatch).not.toHaveBeenCalled();
    expect(screen.getByText("已选 2 位用户")).toBeTruthy();
    await action(user, "禁用用户");
    dialog = within(screen.getByRole("dialog"));
    await user.click(dialog.getByRole("checkbox", { name: /我已确认/ }));
    let reject!: (reason: Error) => void;
    repository.executeUserBatch.mockImplementationOnce(() => new Promise((_resolve, fail) => { reject = fail; }));
    await user.dblClick(dialog.getByRole("button", { name: "确认执行" }));
    expect(repository.executeUserBatch).toHaveBeenCalledTimes(1);
    expect(dialog.getByRole("button", { name: "取消" }).hasAttribute("disabled")).toBe(true);
    await act(async () => reject(new Error("offline")));
    await expectRetainedFailure(screen.getByRole("dialog"));
    expect(screen.getByText("已选 2 位用户")).toBeTruthy();
    await user.click(dialog.getByRole("button", { name: "确认执行" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    const after = (await previewAccountRepository.listUsers(previewCredential)).items;
    expect(after.filter((entry) => ["lin", "chen"].includes(entry.user.loginName)).every((entry) => entry.user.status === "DISABLED")).toBe(true);
    expect(after.filter((entry) => !["lin", "chen"].includes(entry.user.loginName)).every((entry) => entry.user.status === "ACTIVE")).toBe(true);
    expect(repository.executeUserBatch).toHaveBeenCalledTimes(2);
    expect(repository.execute).not.toHaveBeenCalled();
  });
  it("keeps live single-user management reachable without pretending to support bulk requests", async () => {
    const { user, repository } = await open("users", { live: true });
    expect(screen.getByRole("button", { name: "更多操作" }).hasAttribute("disabled")).toBe(true);
    expect(screen.getByText(/当前连接未提供批量操作/)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "查看用户 lin" }));
    expect(await screen.findByRole("heading", { name: "lin" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "返回列表" })).toBeTruthy();
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(screen.getByText(/不根据用户状态推断访问方式/)).toBeTruthy();
    expect(repository.execute).not.toHaveBeenCalled();
  });
});

describe("service-based policy document exploration", () => {
  it("keeps both effect groups and the second service page when returning from operation details", async () => {
    const source: PolicyDocument = { version: "1", statement: [
      { effect: "allow", action: ["*"], resource: ["*"] },
      { effect: "deny", action: ["*"], resource: ["*"] }
    ] };
    const user = userEvent.setup();
    render(<LocaleProvider><PolicyDocumentViewer document={source} /></LocaleProvider>);
    let summary = within(screen.getByRole("table", { name: "策略摘要" }));
    expect(summary.getAllByRole("button")).toHaveLength(10);
    expect(summary.getAllByText("7 个服务")).toHaveLength(2);
    await user.click(screen.getByRole("button", { name: "下一页" }));
    summary = within(screen.getByRole("table", { name: "策略摘要" }));
    expect(summary.getAllByRole("button")).toHaveLength(4);
    expect(summary.queryByText("允许")).toBeNull();
    expect(summary.getByText("7 个服务")).toBeTruthy();
    await user.click(summary.getByRole("button", { name: "查看访问管理的拒绝操作" }));
    await user.click(screen.getByRole("button", { name: "返回服务摘要" }));
    expect(within(screen.getByRole("table", { name: "策略摘要" })).getAllByRole("button")).toHaveLength(4);
    expect(document.activeElement).toBe(screen.getByRole("button", { name: "查看访问管理的拒绝操作" }));
    expect((screen.getByRole("button", { name: "下一页" }) as HTMLButtonElement).disabled).toBe(true);
  });

  it("drills into an operation without merging conditions and restores the searched service and keyboard focus", async () => {
    const source: PolicyDocument = { version: "1", statement: [
      { effect: "allow", action: ["logs:search"], resource: ["matrix:logs:org-xiak:*:topic/prod/*"], condition: { sourceIp: ["192.0.2.0/24"] } },
      { effect: "allow", action: ["logs:search"], resource: ["matrix:logs:org-xiak:*:topic/test/*"], condition: { sourceIp: ["198.51.100.0/24"] } },
      { effect: "deny", action: ["logs:delete"], resource: ["*"] }
    ] };
    const user = userEvent.setup();
    render(<LocaleProvider><PolicyDocumentViewer document={source} /></LocaleProvider>);
    const search = screen.getByRole("searchbox", { name: "搜索服务或操作" });
    await user.type(search, "logs");
    const summary = within(screen.getByRole("table", { name: "策略摘要" }));
    expect(summary.getByRole("button", { name: "查看日志服务的允许操作" })).toBeTruthy();
    expect(summary.getByRole("button", { name: "查看日志服务的拒绝操作" })).toBeTruthy();
    expect(summary.getAllByText("按 2 条声明分别限定")).toHaveLength(2);
    expect(summary.queryByText("192.0.2.0/24")).toBeNull();
    summary.getByRole("button", { name: "查看日志服务的允许操作" }).focus();
    await user.keyboard("{Enter}");
    expect(document.activeElement).toBe(screen.getByRole("heading", { name: "日志服务 logs" }));
    const detail = within(screen.getByRole("table", { name: "操作明细" }));
    const rows = detail.getAllByRole("row").slice(1);
    expect(rows).toHaveLength(2);
    expect(rows[0]!.textContent).toContain("logs:search");
    expect(rows[0]!.textContent).toContain("192.0.2.0/24");
    expect(rows[0]!.textContent).not.toContain("198.51.100.0/24");
    expect(rows[1]!.textContent).toContain("声明 2");
    expect(rows[1]!.textContent).not.toContain("prod/*");
    await user.click(screen.getByRole("tab", { name: "JSON" }));
    expect(JSON.parse(screen.getByRole("region", { name: "策略内容" }).textContent!)).toEqual(source);
    await user.click(screen.getByRole("tab", { name: "策略摘要" }));
    expect(screen.getByRole("table", { name: "操作明细" })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "返回服务摘要" }));
    expect((screen.getByRole("searchbox", { name: "搜索服务或操作" }) as HTMLInputElement).value).toBe("logs");
    expect(document.activeElement).toBe(screen.getByRole("button", { name: "查看日志服务的允许操作" }));
    await user.click(screen.getByRole("button", { name: "查看日志服务的拒绝操作" }));
    expect(within(screen.getByRole("table", { name: "操作明细" })).getByText("logs:delete")).toBeTruthy();
  });
  it("bounds operation rows, searches localized descriptions and retains exact wildcard source rules", async () => {
    localStorage.setItem("matrix.locale", "en");
    const source: PolicyDocument = { version: "1", statement: Array.from({ length: 13 }, (_, index) => ({
      effect: "allow", action: ["logs:search"], resource: ["matrix:logs:org-xiak:*:topic/topic-" + index]
    })) };
    const user = userEvent.setup();
    render(<LocaleProvider><PolicyDocumentViewer document={source} /></LocaleProvider>);
    await user.click(screen.getByRole("button", { name: "View Allow operations for Log service" }));
    expect(within(screen.getByRole("table", { name: "Operation details" })).getAllByRole("row")).toHaveLength(11);
    await user.click(screen.getByRole("button", { name: "Next" }));
    expect(within(screen.getByRole("table", { name: "Operation details" })).getAllByRole("row")).toHaveLength(4);
    const search = screen.getByRole("searchbox", { name: "Search action names or IDs" });
    await user.type(search, "content");
    expect(within(screen.getByRole("table", { name: "Operation details" })).getAllByRole("row")).toHaveLength(11);
    await user.clear(search); await user.type(search, "missing-operation");
    expect(screen.getByText("No matching actions")).toBeTruthy();
    cleanup();
    const wildcard: PolicyDocument = { version: "1", statement: [{ effect: "allow", action: ["logs:*"], resource: ["*"] }] };
    render(<LocaleProvider><PolicyDocumentViewer document={wildcard} /></LocaleProvider>);
    await user.click(screen.getByRole("button", { name: "View Allow operations for Log service" }));
    await user.click(screen.getByText("Inspect source action rules"));
    expect(screen.getByText("logs:*")).toBeTruthy();
    expect(within(screen.getByRole("table", { name: "Operation details" })).queryByText("iam:read")).toBeNull();
  });
});

describe("policy creation entry and directory contract", () => {
  it.each(["按策略生成器创建", "按策略语法创建", "按标签授权", "按产品功能或项目权限创建"])("keeps empty-draft editor tabs clickable from %s", async (method) => {
    const { user, repository } = await open("policies");
    await user.click(screen.getByRole("button", { name: "新建自定义策略" }));
    await user.click(within(screen.getByRole("dialog", { name: "选择创建策略方式" })).getByRole("button", { name: new RegExp("^" + method) }));
    // Selecting a template is not applying it: this reproduces the screenshot.
    await select(user, "从已有策略开始", "ProductionLogReader");
    for (const name of ["JSON 编辑", "可视化编辑", "JSON 编辑", "按资源标签", "JSON 编辑", "产品功能", "JSON 编辑"]) {
      const tab = screen.getByRole("tab", { name });
      expect(tab.hasAttribute("disabled")).toBe(false);
      await user.click(tab);
      expect(tab.getAttribute("aria-selected")).toBe("true");
    }
    expect(JSON.parse((screen.getByLabelText("策略内容", { selector: "textarea" }) as HTMLTextAreaElement).value)).toEqual({ version: "1", statement: [{ effect: "allow", action: [], resource: ["*"] }] });
    expect(screen.queryByText(/当前 JSON 无法无损转换/)).toBeNull();
    await user.click(screen.getByRole("button", { name: "下一步" }));
    expect(screen.queryByLabelText("名称", { exact: true })).toBeNull();
    expect(repository.workspace!.execute).not.toHaveBeenCalled();
  });
  it("keeps cleared feature selections and incomplete conditions editable across JSON tabs", async () => {
    const { user, repository } = await open("create-policy");
    await user.click(screen.getByRole("tab", { name: "产品功能" }));
    await user.click(screen.getByRole("checkbox", { name: /^检索日志/ }));
    await user.click(screen.getByRole("checkbox", { name: /^检索日志/ }));
    await user.click(screen.getByRole("tab", { name: "JSON 编辑" }));
    expect((screen.getByRole("tab", { name: "可视化编辑" }) as HTMLButtonElement).disabled).toBe(false);
    expect((screen.getByRole("tab", { name: "产品功能" }) as HTMLButtonElement).disabled).toBe(false);
    await user.click(screen.getByRole("tab", { name: "可视化编辑" }));
    await user.click(screen.getByRole("button", { name: "添加授权声明" }));
    await logActions(user, ["logs:search"]);
    await user.click(screen.getByRole("checkbox", { name: "按资源标签限制" }));
    await user.type(screen.getByLabelText("标签值 1"), "production");
    await user.click(screen.getByRole("tab", { name: "JSON 编辑" }));
    const text = (screen.getByLabelText("策略内容", { selector: "textarea" }) as HTMLTextAreaElement).value;
    expect((screen.getByRole("tab", { name: "可视化编辑" }) as HTMLButtonElement).disabled).toBe(false);
    expect((screen.getByRole("tab", { name: "按资源标签" }) as HTMLButtonElement).disabled).toBe(false);
    expect((screen.getByRole("tab", { name: "产品功能" }) as HTMLButtonElement).disabled).toBe(true);
    await user.click(screen.getByRole("tab", { name: "按资源标签" }));
    expect((screen.getByLabelText("标签键 1") as HTMLInputElement).value).toBe("");
    expect((screen.getByLabelText("标签值 1") as HTMLInputElement).value).toBe("production");
    await user.click(screen.getByRole("tab", { name: "JSON 编辑" }));
    expect((screen.getByLabelText("策略内容", { selector: "textarea" }) as HTMLTextAreaElement).value).toBe(text);
    await user.click(screen.getByRole("button", { name: "下一步" }));
    expect(repository.workspace!.execute).not.toHaveBeenCalled();
  });
  it("leaves malformed or unrepresentable drafts in JSON without discarding their content", async () => {
    const { user, repository } = await open("create-policy");
    await user.click(screen.getByRole("tab", { name: "JSON 编辑" }));
    const editor = screen.getByLabelText("策略内容", { selector: "textarea" }) as HTMLTextAreaElement;
    const statement = { effect: "allow", action: [], resource: ["*"] };
    for (const text of [
      '{ "version":',
      JSON.stringify({ version: "1", statement: [statement], principal: "unknown" }),
      JSON.stringify({ version: "1", statement: [{ ...statement, notAction: ["logs:delete"] }] }),
      JSON.stringify({ version: "1", statement: [{ ...statement, action: ["logs:unknown"] }] }),
      JSON.stringify({ version: "1", statement: [{ ...statement, condition: { requestTag: { env: "prod" } } }] }),
      JSON.stringify({ version: "1", statement: [{ ...statement, condition: { resourceTag: [{ key: "env", value: "prod", other: "retain" }] } }] }),
      JSON.stringify({ version: "1", statement: [{ ...statement, resource: ["*", "matrix:logs:org-xiak:*:topic/prod/*"] }] }),
      JSON.stringify({ version: "1", statement: [{ ...statement, condition: { notBefore: "invalid date" } }] })
    ]) {
      fireEvent.change(editor, { target: { value: text } });
      for (const name of ["可视化编辑", "按资源标签", "产品功能"]) expect((screen.getByRole("tab", { name }) as HTMLButtonElement).disabled).toBe(true);
      expect(editor.value).toBe(text);
    }
    expect(repository.workspace!.execute).not.toHaveBeenCalled();
  });
  it("previews the current IAM policy author from the MOCK directory without creating or granting", async () => {
    const { user, repository } = await open("policies");
    await user.click(screen.getByRole("button", { name: "体验新版策略编辑" }));
    expect(screen.getByRole("heading", { name: "体验 IAM 策略声明" })).toBeTruthy();
    expect(screen.getByText(/审阅与完成体验均不调用真实 IAM/)).toBeTruthy();
    expect(repository.listAuthorizationProfiles).not.toHaveBeenCalled();
    await user.type(screen.getByRole("textbox", { name: "策略名称" }), "DemoReader");
    await user.click(screen.getByRole("tab", { name: "可视化编辑" }));
    await user.click(await screen.findByRole("radio", { name: /paas.application.read/ }));
    await user.type(screen.getByRole("textbox", { name: "资源 ID 或前缀" }), "app-demo");
    await user.click(screen.getByRole("button", { name: "审阅策略" }));
    expect(screen.getByRole("heading", { name: "审阅新策略" })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "返回编辑" }));
    expect(document.activeElement).toBe(screen.getByRole("textbox", { name: "策略名称" }));
    expect((screen.getByRole("textbox", { name: "资源 ID 或前缀" }) as HTMLInputElement).value).toBe("app-demo");
    expect(screen.getByRole("checkbox", { name: /paas.application.read/ })).toHaveProperty("checked", true);
    expect(repository.listAuthorizationProfiles).toHaveBeenCalledTimes(1);
    await user.click(screen.getByRole("button", { name: "审阅策略" }));
    await user.click(screen.getByRole("button", { name: "完成体验" }));
    expect(screen.getByText(/没有创建策略、关联身份或授予资源权限/)).toBeTruthy();
    expect(repository.workspace!.execute).not.toHaveBeenCalled();
    expect(repository.execute).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "返回策略目录" }));
    expect(screen.getByRole("table", { name: "策略" })).toBeTruthy();
  });
  it("matches CAM directory columns, omits preset metadata in custom view and restores chooser focus", async () => {
    const { user, repository } = await open("policies");
    const headings = () => within(screen.getByRole("table", { name: "策略" })).getAllByRole("columnheader").map((cell) => cell.textContent).filter(Boolean);
    expect(headings()).toEqual(["策略名", "所属产品", "权限级别", "描述", "上次修改时间"]);
    await select(user, "权限级别", "全局权限");
    await user.click(screen.getByRole("tab", { name: "自定义策略" }));
    expect(headings()).toEqual(["策略名", "描述", "上次修改时间"]);
    expect(screen.getByRole("button", { name: "ProductionLogReader" })).toBeTruthy();
    expect(screen.queryByRole("combobox", { name: "权限级别" })).toBeNull();
    const create = screen.getByRole("button", { name: "新建自定义策略" });
    await user.click(create);
    const dialog = within(screen.getByRole("dialog", { name: "选择创建策略方式" }));
    for (const name of [/^按策略生成器创建/, /^按策略语法创建/, /^按标签授权/, /^按产品功能或项目权限创建/]) expect(dialog.getByRole("button", { name })).toBeTruthy();
    // jsdom does not synthesize the native dialog cancel event for Escape.
    fireEvent(screen.getByRole("dialog"), new Event("cancel", { cancelable: true }));
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(document.activeElement).toBe(create);
    expect(repository.workspace!.execute).not.toHaveBeenCalled();
  });
  it("previews the exact-shaped permission catalog without presenting it as the IAM registry", async () => {
    const { user, repository } = await open("policies");
    await screen.findByRole("table", { name: "策略" });
    expect(repository.listAuthorizationProfiles).not.toHaveBeenCalled();
    await user.click(screen.getByRole("tab", { name: "权限能力目录" }));
    expect(await screen.findByRole("table", { name: "产品权限能力目录" })).toBeTruthy();
    expect(screen.getByText(/隔离 MOCK 的权限能力目录示例/)).toBeTruthy();
    expect(repository.listAuthorizationProfiles).toHaveBeenCalledTimes(1);
    await user.click(screen.getByRole("button", { name: "paas" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(screen.getByRole("heading", { level: 2, name: "paas" })).toBe(document.activeElement);
  });
  it("previews product-owned profile onboarding inline without inventing a live publish contract", async () => {
    const { user, repository } = await open("policies");
    await screen.findByRole("table", { name: "策略" });
    await user.click(screen.getByRole("tab", { name: "权限能力目录" }));
    await user.click(await screen.findByRole("button", { name: "paas" }));
    const trigger = screen.getByRole("button", { name: "体验产品接入审阅" });
    await user.click(trigger);

    expect(screen.queryByRole("dialog")).toBeNull();
    expect(screen.getByRole("heading", { level: 2, name: "产品接入审阅 · paas" })).toBe(document.activeElement);
    expect(screen.getByText(/不是租户自助发布入口/)).toBeTruthy();
    expect(screen.getByText(`sha256:${"a".repeat(64)}`)).toBeTruthy();
    expect(screen.getByText("责任人：产品研发团队")).toBeTruthy();

    await user.click(screen.getByRole("button", { name: "下一步" }));
    expect(screen.getByRole("heading", { level: 3, name: "检查 IAM 契约与真实鉴权边界" })).toBeTruthy();
    expect(screen.getByText(/不是在线校验结果/)).toBeTruthy();
    expect(screen.getByText(/subjectTypes 与 userAuthenticationMethods/)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "下一步" }));
    expect(screen.getByRole("heading", { level: 3, name: "审阅不可变发布引用与消费边界" })).toBeTruthy();
    const publish = screen.getByRole("button", { name: "发布修订（未接入）" }) as HTMLButtonElement;
    expect(publish.disabled).toBe(true);
    expect(screen.getByText(/没有对应发布 Action/)).toBeTruthy();
    expect(repository.execute).not.toHaveBeenCalled();
    expect(repository.workspace!.execute).not.toHaveBeenCalled();

    await user.click(screen.getByRole("button", { name: "结束体验" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "体验产品接入审阅" })).toBe(document.activeElement));
  });
  it.each([
    ["visual", "按策略生成器创建", "可视化编辑"],
    ["json", "按策略语法创建", "JSON 编辑"],
    ["tags", "按标签授权", "按资源标签"],
    ["features", "按产品功能或项目权限创建", "产品功能"]
  ] as const)("creates via %s with one reviewed document and no live IAM writes", async (method, title, tab) => {
    const { user, repository, extension } = await open("policies");
    await user.click(screen.getByRole("button", { name: "新建自定义策略" }));
    await user.click(within(screen.getByRole("dialog", { name: "选择创建策略方式" })).getByRole("button", { name: new RegExp("^" + title) }));
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(screen.getByRole("tab", { name: tab }).getAttribute("aria-selected")).toBe("true");
    if (method === "json") {
      fireEvent.change(screen.getByLabelText("策略内容", { selector: "textarea" }), { target: { value: JSON.stringify({ version: "1", statement: [{ effect: "allow", action: ["logs:search"], resource: ["*"] }] }) } });
    } else if (method === "features") {
      await user.click(screen.getByRole("checkbox", { name: /^检索日志/ }));
      const product = screen.getByRole("checkbox", { name: "日志服务" }) as HTMLInputElement;
      expect(product.indeterminate).toBe(true);
      await user.type(screen.getByRole("searchbox", { name: "搜索产品或功能" }), "数据库");
      await user.clear(screen.getByRole("searchbox", { name: "搜索产品或功能" }));
      expect((screen.getByRole("checkbox", { name: /^检索日志/ }) as HTMLInputElement).checked).toBe(true);
    } else {
      await logActions(user, ["logs:search"]);
      if (method === "tags") {
        expect(screen.queryByRole("checkbox", { name: "logs:list" })).toBeNull();
        expect(screen.getByRole("heading", { name: "生效条件（资源标签必填）" })).toBeTruthy();
        await user.click(screen.getByRole("button", { name: "下一步" }));
        expect(screen.queryByLabelText("名称", { exact: true })).toBeNull();
        expect(screen.getByText("请为每条声明开启「按资源标签限制」并填写标签。若不需要标签限制，请切换到可视化编辑。")).toBeTruthy();
        expect(repository.workspace!.execute).not.toHaveBeenCalled();
        await user.click(screen.getByRole("checkbox", { name: "按资源标签限制" }));
        await user.type(screen.getByLabelText("标签键 1"), "environment");
        await user.type(screen.getByLabelText("标签值 1"), "production");
      }
    }
    await user.click(screen.getByRole("button", { name: "下一步" }));
    await user.type(screen.getByLabelText("名称", { exact: true }), "Method-" + method);
    await user.click(screen.getByRole("button", { name: "上一步" }));
    expect(screen.getByRole("tab", { name: tab }).getAttribute("aria-selected")).toBe("true");
    await user.click(screen.getByRole("button", { name: "下一步" }));
    await user.click(screen.getByRole("button", { name: "下一步" }));
    expect(repository.workspace!.execute).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "创建策略" }));
    await screen.findByRole("heading", { name: "策略已保存" });
    const saved = (await extension.read("preview")).policies.find((policy) => policy.name === "Method-" + method)!;
    expect(saved.versions[0]?.document.statement).toEqual([{ effect: "allow", action: ["logs:search"], resource: ["*"], ...(method === "tags" ? { condition: { resourceTag: [{ key: "environment", value: "production" }] } } : {}) }]);
    expect(repository.workspace!.execute).toHaveBeenCalledTimes(1);
    expect(repository.execute).not.toHaveBeenCalled();
  });
  it("never converts restricted or wildcard JSON into a broader product-feature grant", async () => {
    const { user, repository } = await open("create-policy");
    await user.click(screen.getByRole("tab", { name: "JSON 编辑" }));
    const editor = screen.getByLabelText("策略内容", { selector: "textarea" }) as HTMLTextAreaElement;
    for (const statement of [
      { effect: "allow", action: ["logs:*"], resource: ["*"] },
      { effect: "deny", action: ["logs:search"], resource: ["*"] },
      { effect: "allow", action: ["logs:search"], resource: ["*"], condition: { resourceTag: [{ key: "env", value: "test" }] } },
      { effect: "allow", action: ["logs:search"], resource: ["matrix:logs:org-xiak:*:topic/prod/*"] }
    ]) {
      const text = JSON.stringify({ version: "1", statement: [statement] });
      fireEvent.change(editor, { target: { value: text } });
      expect((screen.getByRole("tab", { name: "产品功能" }) as HTMLButtonElement).disabled).toBe(true);
      expect(editor.value).toBe(text);
    }
    expect(repository.workspace!.execute).not.toHaveBeenCalled();
  });
});

describe("CAM-style access workspace", () => {
  it("returns to the same user query and criteria without retaining bulk selection", async () => {
    const { user } = await open("users");
    await user.type(screen.getByRole("searchbox", { name: "搜索用户" }), "lin");
    await select(user, "筛选用户状态", "正常");
    await user.click(screen.getByRole("button", { name: "查看用户 lin" }));
    expect(screen.getByRole("heading", { name: "lin" })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "返回列表" }));
    expect((screen.getByRole("searchbox", { name: "搜索用户" }) as HTMLInputElement).value).toBe("lin");
    expect(screen.getByRole("button", { name: "移除筛选：筛选用户状态: 正常" })).toBeTruthy();
    expect(within(screen.getByRole("table", { name: "租户用户列表" })).getAllByRole("row")).toHaveLength(2);
    expect(screen.getByRole("button", { name: "更多操作" }).hasAttribute("disabled")).toBe(true);
  });
  it("retains incompatible conditions and restricts resource choices to the selected operation capabilities", async () => {
    const { user, repository } = await open("create-policy");
    expect((screen.getByRole("checkbox", { name: "限制来源 IP" }) as HTMLInputElement).disabled).toBe(true);
    await logActions(user, ["logs:search"]);
    await user.click(screen.getByRole("checkbox", { name: "按资源标签限制" }));
    await user.type(screen.getByLabelText("标签键 1"), "env");
    await user.type(screen.getByLabelText("标签值 1"), "prod");
    await user.click(screen.getByRole("checkbox", { name: "logs:list" }));
    expect((screen.getByLabelText("标签值 1") as HTMLInputElement).value).toBe("prod");
    expect(screen.getByText(/现有条件不被全部所选操作支持/)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "下一步" }));
    expect(repository.workspace!.execute).not.toHaveBeenCalled();
    expect(screen.getByRole("checkbox", { name: "logs:list" })).toBeTruthy();
    await user.click(screen.getByRole("checkbox", { name: "logs:list" }));
    expect(screen.queryByText(/现有条件不被全部所选操作支持/)).toBeNull();
    await select(user, "资源授权范围", "指定资源");
    await user.click(screen.getByRole("combobox", { name: "资源服务 1" }));
    expect(screen.getAllByRole("option").map((option) => option.textContent)).toEqual(["日志服务"]);
    await user.keyboard("{Escape}");
    await user.click(screen.getByRole("combobox", { name: "资源类型 1" }));
    expect(screen.getAllByRole("option").map((option) => option.textContent)).toEqual(["日志主题"]);
    await user.keyboard("{Escape}");
  });

  it("paginates policies and keeps the current page when returning from a detail", async () => {
    const { user } = await open("policies", { seed: async (extension) => {
      for (let index = 0; index < 13; index++) await extension.execute("preview", { kind: "save-policy", name: "Paged" + String(index).padStart(2, "0"), description: "", document: { version: "1", statement: [{ effect: "allow", action: ["logs:search"], resource: ["*"] }] } });
    } });
    let table = await screen.findByRole("table", { name: "策略" });
    await user.type(screen.getByRole("searchbox", { name: "搜索策略名称、描述或标签" }), "Paged");
    expect(within(table).getAllByRole("row")).toHaveLength(11);
    await user.click(within(table).getByRole("checkbox", { name: "选择 Paged00" }));
    await user.click(screen.getByRole("button", { name: "下一页" }));
    table = screen.getByRole("table", { name: "策略" });
    expect(within(table).getAllByRole("row")).toHaveLength(4);
    expect(screen.getByText("已选 1 个策略")).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Paged12" }));
    await screen.findByRole("heading", { name: "Paged12" });
    await user.click(screen.getByTestId("go-policies"));
    table = await screen.findByRole("table", { name: "策略" });
    expect(within(table).getAllByRole("row")).toHaveLength(4);
    expect(within(table).getByRole("button", { name: "Paged12" })).toBeTruthy();
    expect((screen.getByRole("button", { name: "下一页" }) as HTMLButtonElement).disabled).toBe(true);
  });
  it("adds inventory resources without overwriting manual patterns and retains tag-mode drafts and error locations", async () => {
    const { user, repository } = await open("create-policy");
    await user.click(await screen.findByRole("tab", { name: "按资源标签" }));
    await logActions(user, ["logs:search"]);
    expect(screen.getAllByText("资源级 · 日志主题").length).toBeGreaterThan(0);
    await select(user, "资源授权范围", "指定资源");
    await user.type(screen.getByLabelText("资源 ID 或前缀 1"), "manual/*");
    await select(user, "从体验资源选择", "production/payment · cn-shanghai-a");
    await user.click(screen.getByRole("button", { name: "添加所选资源" }));
    expect((screen.getByLabelText("资源 ID 或前缀 1") as HTMLInputElement).value).toBe("manual/*");
    expect((screen.getByLabelText("资源 ID 或前缀 2") as HTMLInputElement).value).toBe("production/payment");
    await user.click(screen.getByRole("checkbox", { name: "按资源标签限制" }));
    await user.click(screen.getByLabelText("标签键 1")); await user.paste("environment");
    await user.click(screen.getByLabelText("标签值 1")); await user.paste("production");
    await user.click(screen.getByRole("tab", { name: "JSON 编辑" }));
    const input = screen.getByLabelText("策略内容", { selector: "textarea" }) as HTMLTextAreaElement;
    const draft = JSON.parse(input.value);
    expect(draft.statement[0].resource).toEqual(["matrix:logs:org-xiak:*:topic/manual/*", "matrix:logs:org-xiak:cn-shanghai-a:topic/production/payment"]);
    expect(draft.statement[0].condition.resourceTag).toEqual([{ key: "environment", value: "production" }]);
    draft.statement[0].action = ["logs:unknown"];
    fireEvent.change(input, { target: { value: JSON.stringify(draft) } });
    await user.click(screen.getByRole("button", { name: "查看 $.statement[0]" }));
    expect(document.activeElement).toBe(input);
    expect(input.value).toContain("logs:unknown");
    await user.click(screen.getByRole("button", { name: "下一步" }));
    expect(repository.workspace!.execute).not.toHaveBeenCalled();
    expect(input.value).toContain("manual/*");
    expect((screen.getByRole("tab", { name: "按资源标签" }) as HTMLButtonElement).disabled).toBe(true);
  });
  it("retains independent policy directory filters across details and page navigation", async () => {
    const { user } = await open("policies");
    const directory = await screen.findByRole("table", { name: "策略" });
    expect(within(directory).queryByRole("columnheader", { name: "操作" })).toBeNull();
    expect(within(directory).queryByRole("button", { name: "授权用户/组/角色" })).toBeNull();
    await user.click(screen.getByRole("tab", { name: "预设策略" }));
    await select(user, "所属产品", "访问管理");
    await select(user, "权限级别", "云产品权限");
    await select(user, "排序方式", "最近修改");
    await user.type(screen.getByRole("searchbox"), "Audit");
    await user.click(screen.getByRole("button", { name: "MatrixAuditReadOnly" }));
    expect(await screen.findByRole("heading", { name: "MatrixAuditReadOnly" })).toBeTruthy();
    await user.click(screen.getByTestId("go-policies"));
    expect(await screen.findByRole("table", { name: "策略" })).toBeTruthy();
    expect((screen.getByRole("searchbox") as HTMLInputElement).value).toBe("Audit");
    expect(screen.getByRole("tab", { name: "预设策略" }).getAttribute("aria-selected")).toBe("true");
    expect(screen.getByRole("button", { name: "移除筛选：所属产品: 访问管理" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "移除筛选：权限级别: 云产品权限" })).toBeTruthy();
    expect(screen.getByRole("combobox", { name: "排序方式" }).textContent).toContain("最近修改");
    expect(within(screen.getByRole("table", { name: "策略" })).getAllByRole("row")).toHaveLength(2);
  });
  it("reviews batch attachments, preserves a failed selection and commits only after confirmation", async () => {
    const { user, repository, extension } = await open("policies");
    await user.click(await screen.findByRole("checkbox", { name: "选择 MatrixReadOnlyAccess" }));
    await user.click(screen.getByRole("checkbox", { name: "选择 ProductionLogReader" }));
    await user.click(screen.getByRole("button", { name: "更多操作" }));
    await user.click(screen.getByRole("menuitem", { name: "批量关联" }));
    const workflow = screen.getByRole("form", { name: "批量关联" });
    expect(screen.queryByRole("dialog")).toBeNull();
    await user.click(within(workflow).getByRole("checkbox", { name: /lin/ }));
    await user.click(within(workflow).getByRole("button", { name: "下一步：审阅" }));
    expect(repository.workspace!.execute).not.toHaveBeenCalled();
    expect(within(workflow).getByRole("region", { name: "新增关联" }).textContent).toContain("lin");
    expect(document.activeElement).toBe(within(workflow).getByRole("heading", { name: "审阅关联变更" }));
    await user.click(within(workflow).getByRole("button", { name: "上一步" }));
    expect((within(workflow).getByRole("checkbox", { name: /lin/ }) as HTMLInputElement).checked).toBe(true);
    await user.click(within(workflow).getByRole("button", { name: "下一步：审阅" }));
    vi.mocked(repository.workspace!.execute).mockRejectedValueOnce(new Error("offline"));
    await user.click(within(workflow).getByRole("button", { name: "确认关联" }));
    await expectRetainedFailure(workflow);
    expect((await extension.read("preview")).userPolicies["principal-lin"]).toEqual(["policy-prod-logs"]);
    await user.click(within(workflow).getByRole("button", { name: "确认关联" }));
    expect(await screen.findByRole("heading", { name: "关联已更新" })).toBeTruthy();
    expect((await extension.read("preview")).userPolicies["principal-lin"]).toEqual(["policy-prod-logs", "policy-read"]);
    await user.click(screen.getByRole("button", { name: "完成并返回" }));
    expect(await screen.findByRole("table", { name: "策略" })).toBeTruthy();
    expect(repository.execute).not.toHaveBeenCalled();
  });
  it("explains the remaining direct path when a group attachment is removed", async () => {
    const { user, repository } = await open("policies", { seed: async (extension) => {
      await extension.execute("preview", { kind: "associate-policy", id: "policy-prod-logs", userIds: ["principal-lin"], groupIds: ["group-delivery"], roleIds: [] });
    } });
    await user.click(await screen.findByRole("button", { name: "ProductionLogReader" }));
    await user.click(screen.getByRole("button", { name: "关联用户 / 组 / 角色" }));
    const workflow = screen.getByRole("form", { name: "关联用户 / 组 / 角色 · ProductionLogReader" });
    expect(screen.queryByRole("dialog")).toBeNull();
    await user.click(within(workflow).getByRole("button", { name: /移除 DeliveryTeam/ }));
    await user.click(within(workflow).getByRole("button", { name: "下一步：审阅" }));
    expect(within(workflow).getByText("lin 仍直接关联此策略。")).toBeTruthy();
    expect(within(workflow).getByRole("region", { name: "移除关联" }).textContent).toContain("DeliveryTeam");
    expect(repository.workspace!.execute).not.toHaveBeenCalled();
  });
  it("links high-privilege review candidates to their exact policy, using default content rather than names", async () => {
    const { user, repository } = await open("overview", { seed: async (extension) => {
      await extension.execute("preview", { kind: "save-policy", name: "ReviewGrant", description: "", document: { version: "1", statement: [{ effect: "allow", action: ["iam:grantUser"], resource: ["*"] }] }, tags: [], targets: { userIds: ["principal-lin"], groupIds: ["group-delivery", "group-auditors"], roleIds: [] } });
    } });
    const table = await screen.findByRole("table", { name: "高权限策略" });
    const link = within(table).getByRole("link", { name: "ReviewGrant" });
    const id = new URL(link.getAttribute("href")!, "https://matrix.example.invalid").searchParams.get("id");
    expect(id).toBeTruthy();
    expect(within(table).queryByRole("link", { name: "MatrixReadOnlyAccess" })).toBeNull();
    expect(link.closest("tr")!.textContent).toContain("3");
    expect(screen.getByText(/此列表不是有效权限评估/)).toBeTruthy();
    await user.click(link);
    expect(screen.getByLabelText("Entity destination").textContent).toBe(id);
    expect(await screen.findByRole("heading", { name: "ReviewGrant" })).toBeTruthy();
    expect(screen.getByText(/包含权限管理操作/)).toBeTruthy();
    expect(repository.execute).not.toHaveBeenCalled();
  });
  it("searches products and descriptions in both languages without confusing action types with policy categories", async () => {
    const { user } = await open("policies");
    const table = await screen.findByRole("table", { name: "策略" });
    const row = within(table).getByRole("button", { name: "ProductionLogReader" }).closest("tr")!;
    expect(within(row).queryByText("读取")).toBeNull();
    expect(within(table).getAllByText("全局权限")).toHaveLength(2);
    await user.type(screen.getByRole("searchbox", { name: "搜索策略名称、描述或标签" }), "日志服务 production");
    expect(screen.getByRole("button", { name: "ProductionLogReader" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "MatrixAuditReadOnly" })).toBeNull();
    await user.click(screen.getByRole("button", { name: "Language" }));
    await user.clear(screen.getByRole("searchbox"));
    await user.type(screen.getByRole("searchbox"), "Log read");
    expect(screen.getByRole("button", { name: "ProductionLogReader" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "MatrixAuditReadOnly" })).toBeNull();
  });
  it("keeps inactive keys, policy configuration and missing authenticator evidence semantically distinct", async () => {
    const { user } = await open("overview", { seed: async (extension) => {
      await extension.execute("preview", { kind: "change-group-members", id: "group-delivery", added: [], removed: ["principal-lin"] });
      await extension.execute("preview", { kind: "change-group-policies", id: "group-auditors", added: [], removed: ["policy-audit"] });
      await extension.execute("preview", { kind: "change-group-policies", id: "group-operators", added: [], removed: ["policy-delivery", "policy-tag-logs"] });
      await extension.execute("preview", { kind: "set-key-status", id: "MOCK-pipeline-key", ownerState: "active", status: "DISABLED", resourceVersion: 2, requestId: "disable-pipeline-key" });
      await seedBoundAccountRuleOperator(extension);
      await extension.execute("preview", { kind: "save-account-rule", requestId: "seed-account-rule", expectedRuleVersion: 1, expectedLoginProtection: false, loginProtection: true, responseMode: "success" });
    } });
    expect(await screen.findByText(/0 个启用的模拟长期密钥/)).toBeTruthy();
    expect(screen.getByText(/这里显示账户策略，不代表用户已经绑定 MFA/)).toBeTruthy();
    expect(screen.getByText(/当前数据未提供认证器绑定事实/)).toBeTruthy();
    expect(screen.getAllByText("状态未知").length).toBeGreaterThanOrEqual(1);
    expect(screen.queryByText("已完成")).toBeNull();
    await user.click(screen.getByRole("button", { name: "查看长期访问密钥" }));
    expect(await screen.findByRole("table", { name: "选择要管理的用户" })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "管理 lin 的访问密钥" }));
    const keyDirectory = await screen.findByRole("table", { name: "访问密钥" });
    expect(within(keyDirectory).getByText("已禁用")).toBeTruthy();
    expect(screen.queryByText("最近使用")).toBeNull();
    await user.click(within(keyDirectory).getByRole("button", { name: "MOCK-pipeline-key" }));
    expect(screen.getByText(/没有可靠的最后使用时间或访问日志/)).toBeTruthy();
  });
  it("filters mock user associations by direct and group sources and opens the same management detail", async () => {
    const { user } = await open("users");
    const table = await screen.findByRole("table", { name: "租户用户列表" });
    expect(within(table).getByRole("columnheader", { name: "策略关联" })).toBeTruthy();
    expect(within(table).getAllByText("用户组 1 项")).toHaveLength(2);
    expect(within(table).getByText("直接 1 项")).toBeTruthy();
    await select(user, "筛选策略来源", "直接关联");
    expect(screen.queryByRole("button", { name: "查看用户 chen" })).toBeNull();
    await user.click(screen.getByRole("button", { name: "查看用户 lin" }));
    expect(screen.getByLabelText("Entity destination").textContent).toBe("principal-lin");
    expect(await screen.findByRole("heading", { name: "lin" })).toBeTruthy();
  });
  it("keeps access methods independent of permissions and exposes identity details even without a profile", async () => {
    const { user, repository, extension } = await open("users");
    const method = (scope: HTMLElement, name: string) => within(within(scope).getByText(name, { exact: true }).closest("li")!);
    const row = (await screen.findByRole("button", { name: "查看用户 lin" })).closest("tr")!;
    const lin = within(row);
    expect(method(row, "控制台访问").getByText("已启用")).toBeTruthy();
    expect(method(row, "编程访问").getByText("已启用")).toBeTruthy();
    await user.click(lin.getByRole("button", { name: "查看用户 lin" }));
    expect(screen.getByRole("tab", { name: "身份信息" }).getAttribute("aria-selected")).toBe("true");
    expect(screen.getByText(/授予管理员权限不会将其变成主账号/)).toBeTruthy();
    await user.click(screen.getByRole("tab", { name: "访问方式" }));
    expect(method(document.body, "编程访问").getByText("已启用")).toBeTruthy();
    expect(screen.getByText(/不代表资源权限/)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Language" }));
    expect(method(document.body, "Programmatic access").getByText("Enabled")).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Back to list" }));
    const extensionRead = repository.workspace!.read;
    vi.mocked(extensionRead).mockImplementationOnce(async () => {
      const state = await extension.read("preview");
      delete state.userProfiles["principal-chen"];
      return state;
    });
    // Refresh is the explicit owner of related access-method data. Cursor paging
    // must not reload the identity, policy directories or preview workspace.
    await user.click(screen.getByTestId("refresh-account"));
    await waitFor(() => expect(method(screen.getByRole("button", { name: "View user chen" }).closest("tr")!, "Console access").getByText("Configuration not provided")).toBeTruthy());
    await user.click(await screen.findByRole("button", { name: "View user chen" }));
    expect(screen.getByRole("tab", { name: "Identity" })).toBeTruthy();
    await user.click(screen.getByRole("tab", { name: "Access methods" }));
    expect(method(document.body, "Console access").getByText("Configuration not provided")).toBeTruthy();
    expect(method(document.body, "Console access").queryByText("Disabled")).toBeNull();
  });
  it("presents the account owner outside user selection and group membership", async () => {
    const { user, repository, extension } = await open("users");
    const owner = within(await screen.findByRole("region", { name: "资源所有者" }));
    expect(owner.getByText("资源所有者")).toBeTruthy();
    expect(within(screen.getByRole("table", { name: "租户用户列表" })).queryByRole("button", { name: "查看用户 admin" })).toBeNull();
    expect(screen.queryByRole("checkbox", { name: "选择用户 admin" })).toBeNull();
    await user.click(owner.getByRole("button", { name: "查看用户 admin" }));
    expect(screen.queryByRole("tab", { name: "所属用户组" })).toBeNull();
    await user.click(screen.getByRole("tab", { name: "权限策略" }));
    expect(screen.getByText(/根身份不是普通用户，不加入用户组/)).toBeTruthy();
    await user.click(screen.getByTestId("go-groups"));
    await user.click(await screen.findByRole("button", { name: "DeliveryTeam" }));
    await user.click(screen.getByRole("button", { name: "添加成员" }));
    expect(within(screen.getByRole("dialog")).queryByRole("checkbox", { name: "admin" })).toBeNull();
    expect((await extension.read("preview")).groups[0]?.memberIds).not.toContain("admin");
    expect((await extension.read("preview")).userPolicies["admin"]).toBeUndefined();
    expect(repository.execute).not.toHaveBeenCalled();
  });
  it("does not count empty membership or a boundary as a granting policy in the mock directory", async () => {
    const { user } = await open("users", { seed: async (extension) => {
      await extension.execute("preview", { kind: "change-group-policies", id: "group-auditors", added: [], removed: ["policy-audit"] });
      await extension.execute("preview", { kind: "set-user-boundary", principalId: "principal-chen", policyId: "policy-read" });
    } });
    await select(user, "筛选策略来源", "未关联授权策略");
    expect(await screen.findByRole("button", { name: "查看用户 chen" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "查看用户 lin" })).toBeNull();
  });
  it.each(["create-user", "create-group", "create-policy", "create-role"] as const)("protects the %s draft from menu navigation and leaves without partial mutations only on confirmation", async (view) => {
    const { user, repository } = await open(view);
    let verify: () => void;
    if (view === "create-user") {
      await user.click(await screen.findByRole("button", { name: "下一步" }));
      await user.type(screen.getByLabelText("子用户名"), "retained.user");
      verify = () => expect((screen.getByLabelText("子用户名") as HTMLInputElement).value).toBe("retained.user");
    } else if (view === "create-group") {
      await user.type(await screen.findByLabelText("名称", { exact: true }), "RetainedGroup");
      verify = () => expect((screen.getByLabelText("名称", { exact: true }) as HTMLInputElement).value).toBe("RetainedGroup");
    } else if (view === "create-role") {
      await user.click(await screen.findByRole("checkbox", { name: "lin" }));
      verify = () => expect((screen.getAllByRole("checkbox", { name: "lin" })[0] as HTMLInputElement).checked).toBe(true);
    } else {
      await user.click(await screen.findByRole("tab", { name: "JSON 编辑" }));
      fireEvent.change(screen.getByLabelText("策略内容", { selector: "textarea" }), { target: { value: "{ incomplete policy draft" } });
      verify = () => expect((screen.getByLabelText("策略内容", { selector: "textarea" }) as HTMLTextAreaElement).value).toBe("{ incomplete policy draft");
    }
    await user.click(screen.getByTestId("go-users"));
    expect(screen.getByRole("dialog")).toBeTruthy();
    expect(repository.workspace!.execute).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "继续编辑" }));
    verify();
    await user.click(screen.getByTestId("go-users"));
    await user.click(screen.getByRole("button", { name: "放弃并离开" }));
    expect(await screen.findByRole("button", { name: "创建用户" })).toBeTruthy();
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(repository.workspace!.execute).not.toHaveBeenCalled();
  });

  it("keeps the preview role workspace unavailable to a read-only viewer", async () => {
    const { user, repository } = await open("roles", { reader: true });
    expect(await screen.findByRole("heading", { name: "没有此页面的管理权限" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "新建角色" })).toBeNull();
    await user.click(screen.getByTestId("go-create-role"));
    expect(await screen.findByRole("heading", { name: "没有此页面的管理权限" })).toBeTruthy();
    expect(repository.workspace!.read).not.toHaveBeenCalled();
    expect(repository.workspace!.execute).not.toHaveBeenCalled();
  });
  it("uses the shared stacked mobile contract for compact workspace directories", async () => {
    await open("roles");
    const directory = await screen.findByRole("table", { name: "角色" });
    expect(directory.getAttribute("data-mobile-layout")).toBe("stack");
    expect(within(directory).queryByRole("columnheader", { name: "操作" })).toBeNull();
    expect(within(directory).getByRole("button", { name: "PipelineDeploymentRole" }).closest("td")?.getAttribute("data-label")).toBe("名称");
    expect(within(directory).getByText("云服务").closest("td")?.getAttribute("data-label")).toBe("信任主体类型");
  });
  it("previews service authorization as an inline consent review without creating a role or grant", async () => {
    const { user, repository, extension } = await open("roles");
    const before = await extension.read("preview");
    const trigger = await screen.findByRole("button", { name: "服务授权" });
    await user.click(trigger);

    expect(screen.queryByRole("dialog")).toBeNull();
    expect(screen.getByRole("heading", { level: 2, name: "服务授权" })).toBe(document.activeElement);
    expect(screen.getByText(/产品接入、服务身份和客户授权是三个独立边界/)).toBeTruthy();
    expect(screen.getByRole("table", { name: "服务授权模板" })).toBeTruthy();
    expect(screen.getByText(/普通服务角色仍在角色列表中单独管理/)).toBeTruthy();

    const template = screen.getByRole("button", { name: "Application delivery" });
    await user.click(template);
    expect(screen.getByRole("heading", { level: 2, name: "服务授权模板" })).toBe(document.activeElement);
    expect(screen.getAllByText("devops.matrix.internal").length).toBeGreaterThan(0);
    expect(screen.getByText("MatrixServiceRoleForApplicationDelivery")).toBeTruthy();
    expect(screen.getByText("目标账号").nextElementSibling?.textContent).toBe("org-xiak");
    expect(screen.getByText(/PipelineDeploymentRole 是普通工作负载角色/)).toBeTruthy();

    const review = screen.getByRole("button", { name: "审阅服务授权" });
    await user.click(review);
    expect(screen.getByRole("heading", { level: 2, name: "审阅服务授权" })).toBe(document.activeElement);
    expect(screen.getByRole("heading", { level: 3, name: "确认服务身份与单一用途" })).toBeTruthy();
    expect(screen.getByText(/必须同时校验操作者、目标账号与角色、实际工作负载和 service purpose/)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "下一步" }));
    expect(screen.getByText("MatrixDeliveryAccess · v1")).toBeTruthy();
    expect(screen.getByText("paas:*")).toBeTruthy();
    expect(screen.getByText("devops:*")).toBeTruthy();
    expect(screen.getByText(/跨产品代操作/)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "下一步" }));
    const authorize = screen.getByRole("button", { name: "授权服务（未接入）" }) as HTMLButtonElement;
    expect(authorize.disabled).toBe(true);
    expect(screen.getByText(/尚未发布 ServiceRoleTemplate/)).toBeTruthy();
    expect(repository.execute).not.toHaveBeenCalled();
    expect(repository.workspace!.execute).not.toHaveBeenCalled();
    expect(await extension.read("preview")).toEqual(before);

    await user.click(screen.getByRole("button", { name: "结束审阅" }));
    expect(screen.getByRole("button", { name: "审阅服务授权" })).toBe(document.activeElement);
    await user.click(screen.getByRole("button", { name: "返回服务授权" }));
    expect(screen.getByRole("button", { name: "Application delivery" })).toBe(document.activeElement);
    await user.click(screen.getByRole("button", { name: "返回角色列表" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "服务授权" })).toBe(document.activeElement));
  });
  it("keeps service consent pinned to policy v1 when the policy default later moves to v2", async () => {
    const { user } = await open("roles", { seed: async (extension) => {
      extension.transact((source) => ({ workspace: { ...source, policies: source.policies.map((policy) => policy.id !== "policy-delivery" ? policy : {
        ...policy,
        defaultVersion: 2,
        lastVersion: 2,
        versions: [...policy.versions, { id: 2, document: { version: "1" as const, statement: [{ effect: "allow" as const, action: ["iam:*"], resource: ["*"] }] }, createdAt: "2026-09-10T09:00:00Z" }]
      }) } }));
    } });
    await user.click(await screen.findByRole("button", { name: "服务授权" }));
    await user.click(screen.getByRole("button", { name: "Application delivery" }));
    expect(screen.getByRole("button", { name: "打开策略详情（当前默认 v2）" })).toBeTruthy();
    expect(screen.getByText(/本次服务授权仍固定审阅 v1/)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "审阅服务授权" }));
    await user.click(screen.getByRole("button", { name: "下一步" }));
    expect(screen.getByText("MatrixDeliveryAccess · v1")).toBeTruthy();
    expect(screen.getByText("paas:*")).toBeTruthy();
    expect(screen.queryByText("iam:*")).toBeNull();
  });
  it("blocks service consent instead of falling back when its pinned policy version is missing", async () => {
    const { user } = await open("roles", { seed: async (extension) => {
      extension.transact((source) => ({ workspace: { ...source, policies: source.policies.map((policy) => policy.id !== "policy-delivery" ? policy : {
        ...policy,
        defaultVersion: 2,
        lastVersion: 2,
        versions: [{ id: 2, document: { version: "1" as const, statement: [{ effect: "allow" as const, action: ["iam:*"] , resource: ["*"] }] }, createdAt: "2026-09-10T09:00:00Z" }]
      }) } }));
    } });
    await user.click(await screen.findByRole("button", { name: "服务授权" }));
    const directory = screen.getByRole("table", { name: "服务授权模板" });
    expect(within(directory).getByText("不可用")).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Application delivery" }));
    expect(screen.getByText(/找不到模板固定引用的策略 v1/)).toBeTruthy();
    expect((screen.getByRole("button", { name: "审阅服务授权" }) as HTMLButtonElement).disabled).toBe(true);
    expect(screen.queryByRole("button", { name: /当前默认 v2/ })).toBeNull();
  });
  it("keeps identity-provider and federation mutations in their detail pages", async () => {
    const { user } = await open("providers");
    const providers = await screen.findByRole("table", { name: "角色 SSO" });
    expect(within(providers).queryByRole("columnheader", { name: "操作" })).toBeNull();
    expect(within(providers).queryByRole("button", { name: "编辑" })).toBeNull();
    expect(within(providers).queryByRole("button", { name: "删除" })).toBeNull();
    await user.click(screen.getByRole("tab", { name: "联合身份映射" }));
    const federations = screen.getByRole("table", { name: "联合身份映射" });
    expect(within(federations).queryByRole("columnheader", { name: "操作" })).toBeNull();
    expect(within(federations).queryByRole("button", { name: "编辑" })).toBeNull();
    expect(within(federations).queryByRole("button", { name: "删除" })).toBeNull();
  });
  it("creates a role in the content area with explicit trust, no preselected grants and a preserved localized draft", async () => {
    const { user, repository, extension } = await open("roles");
    await user.click(await screen.findByRole("button", { name: "新建角色" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    await user.click(screen.getByRole("button", { name: "下一步" }));
    expect(screen.getByRole("alert").textContent).toContain("至少一名当前租户用户");
    await user.click(screen.getByRole("button", { name: "Language" }));
    expect(screen.getByRole("alert").textContent).toContain("at least one current-tenant user");
    await user.click(screen.getByRole("checkbox", { name: "lin" }));
    await user.click(screen.getByRole("button", { name: "Next" }));
    expect((screen.getByRole("checkbox", { name: "MatrixReadOnlyAccess" }) as HTMLInputElement).checked).toBe(false);
    await user.click(screen.getByRole("checkbox", { name: "MatrixReadOnlyAccess" }));
    await select(user, "Permission boundary", "ProductionLogReader");
    await user.click(screen.getByRole("button", { name: "Next" }));
    await user.type(screen.getByLabelText("Name", { exact: true }), "PreviewSupport");
    await user.type(screen.getByLabelText("Description", { exact: true }), "Support logs only");
    await user.click(screen.getByRole("button", { name: "Next" }));
    expect(repository.workspace!.execute).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    await user.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Continue editing" }));
    expect(screen.getByText("PreviewSupport")).toBeTruthy();
    const beforeCreate = await extension.read("preview");
    vi.mocked(repository.workspace!.execute).mockRejectedValueOnce(new Error("offline"));
    await user.click(screen.getByRole("button", { name: "Create role" }));
    await waitFor(() => expect(screen.getByRole("alert").textContent).toContain("retry"));
    expect(await extension.read("preview")).toEqual(beforeCreate);
    expect(screen.getByText("PreviewSupport")).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Create role" }));
    await screen.findByRole("heading", { name: "Role created" });
    const state = await extension.read("preview-only"), created = state.roles.find((role) => role.name === "PreviewSupport")!;
    expect(created).toMatchObject({ trustedUserIds: ["principal-lin"], policyIds: ["policy-read"], boundaryPolicyId: "policy-prod-logs", consoleAccess: false });
    expect(state.roleSessions).toEqual([]);
    await user.click(screen.getByRole("button", { name: "View role" }));
    expect(screen.getByLabelText("Entity destination").textContent).toBe(created.id);
    await user.click(screen.getByRole("tab", { name: "Trust relationship" }));
    expect(screen.getByRole("region", { name: "Trust document (Matrix MOCK)" }).textContent).toContain("principal-lin");
  });
  it("reviews exact trust additions/removals, validates before review, and retains the review on failure without changing other role fields", async () => {
    const { user, repository, extension } = await open("roles", { seed: async (extension) => {
      await extension.execute("preview", { kind: "create-role", name: "SupportRole", description: "Support only", principalType: "account", principal: "org-xiak", trustedUserIds: ["principal-lin"], policyIds: ["policy-read"], boundaryPolicyId: "policy-prod-logs", tags: [{ key: "team", value: "support" }], sessionMinutes: 45, consoleAccess: true });
    } });
    const before = await extension.read("preview"), original = before.roles.find((role) => role.name === "SupportRole")!;
    await user.click(await screen.findByRole("button", { name: "SupportRole" }));
    await user.click(screen.getByRole("tab", { name: "信任关系" }));
    const trigger = screen.getByRole("button", { name: "修改信任关系" });
    await user.click(trigger);
    expect(screen.queryByRole("dialog")).toBeNull();
    let workflow = screen.getByRole("group", { name: "修改信任关系" }), panel = within(workflow);
    expect((panel.getByRole("button", { name: "审阅变更" }) as HTMLButtonElement).disabled).toBe(true);
    await user.click(panel.getByRole("checkbox", { name: "lin" }));
    await user.click(panel.getByRole("button", { name: "审阅变更" }));
    expect(panel.getByRole("alert").textContent).toContain("至少一名当前租户用户");
    expect(document.activeElement).toBe(panel.getByRole("alert"));
    expect(repository.workspace!.execute).not.toHaveBeenCalled();
    await user.click(panel.getByRole("checkbox", { name: "chen" }));
    await user.click(panel.getByRole("button", { name: "审阅变更" }));
    expect(document.activeElement).toBe(panel.getByRole("heading", { name: "审阅信任关系变更" }));
    expect(panel.getByRole("article", { name: "变更前" }).textContent).toContain("linprincipal-lin移除信任");
    expect(panel.getByRole("article", { name: "变更后" }).textContent).toContain("chenprincipal-chen新增信任");
    await user.click(panel.getByText("查看完整信任文档对比"));
    const prior = JSON.parse(panel.getByRole("region", { name: "变更前 · 信任文档" }).textContent!);
    const proposed = JSON.parse(panel.getByRole("region", { name: "变更后 · 信任文档" }).textContent!);
    expect(prior.statement[0].principal).toEqual({ tenant: "org-xiak", userIds: ["principal-lin"] });
    expect(proposed.statement[0].principal).toEqual({ tenant: "org-xiak", userIds: ["principal-chen"] });
    await user.click(panel.getByRole("button", { name: "取消" }));
    expect(await extension.read("preview")).toEqual(before);
    expect(document.activeElement).toBe(screen.getByRole("button", { name: "修改信任关系" }));
    await user.click(screen.getByRole("button", { name: "修改信任关系" }));
    workflow = screen.getByRole("group", { name: "修改信任关系" }); panel = within(workflow);
    await user.click(panel.getByRole("checkbox", { name: "lin" }));
    await user.click(panel.getByRole("checkbox", { name: "chen" }));
    await user.click(panel.getByRole("button", { name: "审阅变更" }));
    vi.mocked(repository.workspace!.execute).mockRejectedValueOnce(new Error("offline"));
    await user.click(panel.getByRole("button", { name: "保存" }));
    await expectRetainedFailure(workflow);
    expect(await extension.read("preview")).toEqual(before);
    expect(panel.getByRole("article", { name: "变更后" }).textContent).toContain("principal-chen");
    await user.click(panel.getByRole("button", { name: "返回选择" }));
    expect((panel.getByRole("checkbox", { name: "chen" }) as HTMLInputElement).checked).toBe(true);
    expect(document.activeElement).toBe(panel.getByRole("searchbox"));
    await user.click(panel.getByRole("button", { name: "审阅变更" }));
    await user.click(screen.getByRole("button", { name: "Language" }));
    expect(panel.getByRole("article", { name: "After" }).textContent).toContain("Newly trusted");
    expect(panel.getByRole("article", { name: "Before" }).textContent).toContain("Trust removed");
    await user.click(panel.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(screen.queryByRole("group", { name: "Edit trust" })).toBeNull());
    expect(document.activeElement).toBe(screen.getByRole("button", { name: "Edit trust" }));
    const after = await extension.read("preview");
    expect(after.roles.find((role) => role.id === original.id)).toEqual({ ...original, trustedUserIds: ["principal-chen"] });
    for (const key of ["policies", "groups", "userPolicies", "roleSessions", "userBoundaries"] as const) expect(after[key]).toEqual(before[key]);
  });
  it("does not submit a reordered but unchanged trust set or permit a carrier change", async () => {
    const { user, repository } = await open("roles", { seed: async (extension) => {
      await extension.execute("preview", { kind: "create-role", name: "TeamRole", description: "", principalType: "account", principal: "org-xiak", trustedUserIds: ["principal-lin", "principal-chen"], policyIds: [], tags: [], sessionMinutes: 60, consoleAccess: false });
    } });
    await user.click(await screen.findByRole("button", { name: "TeamRole" }));
    await user.click(screen.getByRole("tab", { name: "信任关系" }));
    await user.click(screen.getByRole("button", { name: "修改信任关系" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    const workflow = screen.getByRole("group", { name: "修改信任关系" }), panel = within(workflow);
    expect((panel.getByRole("combobox", { name: "信任主体类型" }) as HTMLButtonElement).disabled).toBe(true);
    await user.click(panel.getByRole("checkbox", { name: "lin" }));
    await user.click(panel.getByRole("checkbox", { name: "lin" }));
    expect((panel.getByRole("button", { name: "审阅变更" }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.submit(workflow.querySelector("form")!);
    expect(repository.workspace!.execute).not.toHaveBeenCalled();
  });
  it("retains role metadata through a pending command and retry, locking dismissal only until it settles", async () => {
    const { user, repository, extension } = await open("roles", { entityId: "role-pipeline" });
    const before = await extension.read("preview"), original = before.roles.find((role) => role.id === "role-pipeline")!;
    await user.click(await screen.findByRole("button", { name: "编辑角色信息" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    const workflow = screen.getByRole("group", { name: "编辑角色信息" }), panel = within(workflow), form = workflow.querySelector("form")!;
    fireEvent.change(panel.getByLabelText("描述"), { target: { value: "Retained metadata" } });
    await user.click(panel.getByRole("button", { name: "添加标签" }));
    await user.type(panel.getByLabelText("标签键 1"), "team");
    await user.type(panel.getByLabelText("标签值 1"), "delivery");
    let rejectWrite!: (error: Error) => void;
    vi.mocked(repository.workspace!.execute).mockImplementationOnce(() => new Promise((_, reject) => { rejectWrite = reject; }));
    await user.click(panel.getByRole("button", { name: "保存" }));
    expect(form.getAttribute("aria-busy")).toBe("true");
    expect((panel.getByRole("button", { name: "取消" }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.submit(form);
    expect(repository.workspace!.execute).toHaveBeenCalledOnce();
    expect(await extension.read("preview")).toEqual(before);
    await act(async () => { rejectWrite(new Error("offline")); });
    await expectRetainedFailure(workflow);
    expect((panel.getByLabelText("描述") as HTMLTextAreaElement).value).toBe("Retained metadata");
    expect((panel.getByLabelText("标签值 1") as HTMLInputElement).value).toBe("delivery");
    expect((panel.getByRole("button", { name: "取消" }) as HTMLButtonElement).disabled).toBe(false);
    await user.click(panel.getByRole("button", { name: "保存" }));
    await waitFor(() => expect(screen.queryByRole("group", { name: "编辑角色信息" })).toBeNull());
    expect(document.activeElement).toBe(screen.getByRole("button", { name: "编辑角色信息" }));
    expect((await extension.read("preview")).roles.find((role) => role.id === original.id)).toEqual({ ...original, description: "Retained metadata", tags: [{ key: "team", value: "delivery" }] });
  });
  it.each(["add", "remove"] as const)("retains a reviewed role policy %s delta after failure and retries without replacing unrelated grants", async (mode) => {
    const { user, repository, extension } = await open("roles", { entityId: "role-pipeline" });
    const before = await extension.read("preview"), original = before.roles.find((role) => role.id === "role-pipeline")!;
    const workflowName = mode === "add" ? "关联策略" : "移除策略";
    await user.click(await screen.findByRole("button", { name: workflowName }));
    expect(screen.queryByRole("dialog")).toBeNull();
    const workflow = screen.getByRole("group", { name: workflowName }), panel = within(workflow);
    const policyName = mode === "add" ? "MatrixReadOnlyAccess" : "MatrixDeliveryAccess";
    await user.click(panel.getByRole("checkbox", { name: policyName }));
    await user.type(panel.getByRole("searchbox"), "no-matching-policy");
    expect(panel.getByRole("button", { name: "移除 " + policyName })).toBeTruthy();
    await user.click(panel.getByRole("button", { name: "审阅变更" }));
    expect(repository.workspace!.execute).not.toHaveBeenCalled();
    vi.mocked(repository.workspace!.execute).mockRejectedValueOnce(new Error("offline"));
    await user.click(panel.getByRole("button", { name: "保存" }));
    await expectRetainedFailure(workflow);
    expect(await extension.read("preview")).toEqual(before);
    expect(panel.getByRole("list").textContent).toBe(policyName);
    await user.click(panel.getByRole("button", { name: "返回选择" }));
    expect((panel.getByRole("checkbox", { name: policyName }) as HTMLInputElement).checked).toBe(true);
    await user.click(panel.getByRole("button", { name: "审阅变更" }));
    await user.click(panel.getByRole("button", { name: "保存" }));
    await waitFor(() => expect(screen.queryByRole("group", { name: workflowName })).toBeNull());
    expect(document.activeElement).toBe(screen.getByRole("button", { name: mode === "remove" ? "关联策略" : workflowName }));
    const after = await extension.read("preview");
    expect(after.roles.find((role) => role.id === original.id)).toEqual({ ...original, policyIds: mode === "add" ? ["policy-delivery", "policy-read"] : [] });
    expect(after.userPolicies).toEqual(before.userPolicies);
    expect(after.policies).toEqual(before.policies);
  });
  it.each(["set", "remove"] as const)("retains a reviewed role boundary %s after failure without changing policy grants", async (mode) => {
    const { user, repository, extension } = await open("roles", { entityId: "role-pipeline", seed: async (extension) => {
      if (mode === "remove") await extension.execute("preview", { kind: "set-role-boundary", id: "role-pipeline", policyId: "policy-read" });
    } });
    const before = await extension.read("preview"), original = before.roles.find((role) => role.id === "role-pipeline")!;
    await user.click(await screen.findByRole("button", { name: "修改权限边界" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    const workflow = screen.getByRole("group", { name: "修改权限边界" }), panel = within(workflow);
    await select(user, "权限边界", mode === "set" ? "ProductionLogReader" : "未设置权限边界");
    await user.click(panel.getByRole("button", { name: "审阅变更" }));
    vi.mocked(repository.workspace!.execute).mockRejectedValueOnce(new Error("offline"));
    await user.click(panel.getByRole("button", { name: "保存" }));
    await expectRetainedFailure(workflow);
    expect(await extension.read("preview")).toEqual(before);
    expect(panel.getByText(mode === "set" ? "ProductionLogReader" : "MatrixReadOnlyAccess")).toBeTruthy();
    await user.click(panel.getByRole("button", { name: "保存" }));
    await waitFor(() => expect(screen.queryByRole("group", { name: "修改权限边界" })).toBeNull());
    expect(document.activeElement).toBe(screen.getByRole("button", { name: "修改权限边界" }));
    const after = await extension.read("preview");
    expect(after.roles.find((role) => role.id === original.id)).toEqual({ ...original, boundaryPolicyId: mode === "set" ? "policy-prod-logs" : undefined });
    expect(after.userPolicies).toEqual(before.userPolicies);
    expect(after.policies).toEqual(before.policies);
  });
  it("preserves session-setting inputs after failure and never extends an existing session on retry", async () => {
    const { user, repository, extension } = await open("roles", { entityId: "role-pipeline", seed: async (extension) => {
      await extension.execute("preview", { kind: "create-role-session", roleId: "role-pipeline", caller: { type: "service", id: "devops.matrix.internal" }, sessionMinutes: 30 });
    } });
    const before = await extension.read("preview"), original = before.roles.find((role) => role.id === "role-pipeline")!;
    await user.click(await screen.findByRole("tab", { name: "会话设置" }));
    await user.click(screen.getByRole("button", { name: "修改会话设置" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    const workflow = screen.getByRole("group", { name: "修改会话设置" }), panel = within(workflow);
    fireEvent.change(panel.getByLabelText("会话时长（分钟）"), { target: { value: "120" } });
    expect((panel.getByRole("checkbox", { name: "允许通过控制台访问" }) as HTMLInputElement).disabled).toBe(true);
    vi.mocked(repository.workspace!.execute).mockRejectedValueOnce(new Error("offline"));
    await user.click(panel.getByRole("button", { name: "保存" }));
    await expectRetainedFailure(workflow);
    expect(await extension.read("preview")).toEqual(before);
    expect((panel.getByLabelText("会话时长（分钟）") as HTMLInputElement).value).toBe("120");
    await user.click(panel.getByRole("button", { name: "保存" }));
    await waitFor(() => expect(screen.queryByRole("group", { name: "修改会话设置" })).toBeNull());
    expect(document.activeElement).toBe(screen.getByRole("button", { name: "修改会话设置" }));
    const after = await extension.read("preview");
    expect(after.roles.find((role) => role.id === original.id)).toEqual({ ...original, sessionMinutes: 120 });
    expect(after.roleSessions).toEqual(before.roleSessions);
  });
  it("shows provider names and IDs in trust review and retains a referenced-provider rejection", async () => {
    const { user, repository, extension } = await open("roles", { entityId: "role-audit", seed: async (extension) => {
      await extension.execute("preview", { kind: "save-provider", name: "NextSSO", protocol: "SAML", issuer: "https://next.example.invalid/saml", audience: "matrix", metadata: '<EntityDescriptor entityID="next"></EntityDescriptor>', enabled: true });
    } });
    const before = await extension.read("preview"), provider = before.providers.find((entry) => entry.name === "NextSSO")!;
    await user.click(await screen.findByRole("tab", { name: "信任关系" }));
    await user.click(screen.getByRole("button", { name: "修改信任关系" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    const workflow = screen.getByRole("group", { name: "修改信任关系" }), panel = within(workflow);
    await select(user, "信任主体", "NextSSO");
    await user.click(panel.getByRole("button", { name: "审阅变更" }));
    expect(panel.getByRole("article", { name: "变更前" }).textContent).toContain("EnterpriseSSO");
    expect(panel.getByRole("article", { name: "变更后" }).textContent).toContain(provider.id);
    expect(repository.workspace!.execute).not.toHaveBeenCalled();
    await user.click(panel.getByRole("button", { name: "保存" }));
    await waitFor(() => expect(panel.getByRole("alert").textContent).toContain("仍被引用"));
    expect(document.activeElement).toBe(panel.getByRole("alert"));
    expect(await extension.read("preview")).toEqual(before);
    await user.click(panel.getByRole("button", { name: "返回选择" }));
    expect(panel.getByRole("combobox", { name: "信任主体" }).textContent).toContain("NextSSO");
    await user.click(panel.getByRole("button", { name: "取消" }));
    expect(screen.queryByRole("group", { name: "修改信任关系" })).toBeNull();
    expect(await extension.read("preview")).toEqual(before);
  });
  it("retains role deletion confirmation on failure, supports cancellation and retries only the named role", async () => {
    const { user, repository, extension } = await open("roles", { entityId: "role-pipeline" });
    const before = await extension.read("preview");
    await user.click(await screen.findByRole("button", { name: "删除" }));
    let dialog = screen.getByRole("dialog"), panel = within(dialog);
    await user.type(panel.getByLabelText("输入名称以确认"), "wrong-name");
    await user.click(panel.getByRole("button", { name: "确认删除" }));
    expect(repository.workspace!.execute).not.toHaveBeenCalled();
    fireEvent.change(panel.getByLabelText("输入名称以确认"), { target: { value: "PipelineDeploymentRole" } });
    vi.mocked(repository.workspace!.execute).mockRejectedValueOnce(new Error("offline"));
    await user.click(panel.getByRole("button", { name: "确认删除" }));
    await expectRetainedFailure(dialog);
    expect((panel.getByLabelText("输入名称以确认") as HTMLInputElement).value).toBe("PipelineDeploymentRole");
    expect(await extension.read("preview")).toEqual(before);
    await user.click(panel.getByRole("button", { name: "取消" }));
    await user.click(screen.getByRole("button", { name: "删除" }));
    dialog = screen.getByRole("dialog"); panel = within(dialog);
    await user.type(panel.getByLabelText("输入名称以确认"), "PipelineDeploymentRole");
    await user.click(panel.getByRole("button", { name: "确认删除" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    const after = await extension.read("preview");
    expect(after.roles).toEqual(before.roles.filter((role) => role.id !== "role-pipeline"));
    expect(after.policies).toEqual(before.policies);
    expect(after.userPolicies).toEqual(before.userPolicies);
  });
  it("keeps role-session administration separate from self-service assumption and preserves exact revoke intent", async () => {
    let activeSessionId = "", revokedSessionId = "";
    const { user, repository, extension } = await open("roles", { entityId: "role-log-reviewer", users: reviewUsers, seed: async (extension) => {
      await extension.execute("preview", { kind: "create-role-session", roleId: "role-log-reviewer", caller: { type: "user", id: "principal-qiao" }, sessionMinutes: 30 });
      revokedSessionId = (await extension.read("preview-only")).roleSessions[0]!.id;
      await extension.execute("preview", { kind: "revoke-role-session", id: revokedSessionId });
      await extension.execute("preview", { kind: "create-role-session", roleId: "role-log-reviewer", caller: { type: "user", id: "principal-qiao" }, sessionMinutes: 30 });
      activeSessionId = (await extension.read("preview-only")).roleSessions.at(-1)!.id;
    } });
    await user.click(await screen.findByRole("tab", { name: "临时会话" }));
    expect(screen.queryByRole("button", { name: "创建体验会话" })).toBeNull();
    expect(screen.queryByText("模拟访问")).toBeNull();
    expect(screen.getByText("管理员 MOCK 目录", { exact: false })).toBeTruthy();
    expect(screen.getByRole("table", { name: "临时会话" }).textContent).toContain(activeSessionId);
    expect(screen.getByRole("table", { name: "临时会话" }).textContent).not.toContain(revokedSessionId);
    await select(user, "会话生命周期", "全部历史");
    expect(screen.getByRole("table", { name: "临时会话" }).textContent).toContain(revokedSessionId);
    await select(user, "来源用户", "qiao · principal-qiao");
    await user.type(screen.getByRole("searchbox", { name: "输入完整会话 ID" }), activeSessionId);
    const table = screen.getByRole("table", { name: "临时会话" });
    expect(table.textContent).toContain(activeSessionId);
    expect(table.textContent).not.toContain(revokedSessionId);
    const trigger = within(table).getByRole("button", { name: `会话 ${activeSessionId} 的操作` });
    await user.click(trigger);
    await user.click(screen.getByRole("menuitem", { name: "撤销会话" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    const workflow = screen.getByRole("group", { name: "撤销会话" }), panel = within(workflow);
    vi.mocked(repository.workspace!.execute).mockRejectedValueOnce(new Error("offline"));
    await user.click(panel.getByRole("button", { name: "撤销会话" }));
    await expectRetainedFailure(workflow);
    expect((await extension.read("preview-only")).roleSessions.find((session) => session.id === activeSessionId)?.revokedAt).toBeUndefined();
    await user.click(panel.getByRole("button", { name: "撤销会话" }));
    await waitFor(() => expect(screen.queryByRole("group", { name: "撤销会话" })).toBeNull());
    expect(screen.getByRole("table", { name: "临时会话" }).textContent).toContain("已撤销");
    expect((await extension.read("preview-only")).roleSessions.find((session) => session.id === activeSessionId)?.revokedAt).toBeTruthy();
    expect(document.activeElement).toBe(within(screen.getByRole("table", { name: "临时会话" })).getByRole("button", { name: `会话 ${activeSessionId} 的操作` }));
  });
  it("reviews user boundary changes separately and links boundary usage back to its exact owner", async () => {
    const { user, extension } = await open("users", { entityId: "principal-lin" });
    await user.click(await screen.findByRole("tab", { name: "权限策略" }));
    const policies = screen.getByRole("table", { name: "用户关联策略（模拟）" });
    expect(policies.getAttribute("data-mobile-layout")).toBe("stack");
    expect(within(policies).getByText("ProductionLogReader").closest("td")?.getAttribute("data-label")).toBe("名称");
    expect(screen.queryByRole("button", { name: "平台内置角色" })).toBeNull();
    await user.click(await screen.findByRole("button", { name: "修改权限边界" }));
    await select(user, "权限边界", "MatrixReadOnlyAccess");
    await user.click(screen.getByRole("button", { name: "审阅变更" }));
    expect((await extension.read("preview-only")).userBoundaries["principal-lin"]).toBeUndefined();
    await user.click(screen.getByRole("button", { name: "保存" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    await user.click(within(screen.getByRole("region", { name: "权限边界" })).getByRole("button", { name: "MatrixReadOnlyAccess" }));
    await user.click(screen.getByRole("tab", { name: /策略用法/ }));
    expect(screen.getByRole("heading", { name: /作为权限策略使用/ })).toBeTruthy();
    expect(screen.getByRole("heading", { name: /作为权限边界使用/ })).toBeTruthy();
    const uses = screen.getByRole("table", { name: "作为权限边界使用" });
    await user.click(within(uses).getByRole("button", { name: "lin" }));
    expect(screen.getByLabelText("Entity destination").textContent).toBe("principal-lin");
    expect((await extension.read("preview-only")).userPolicies["principal-lin"]).toEqual(["policy-prod-logs"]);
  });
  it.each([
    { tab: "权限策略", trigger: "关联策略", title: "管理直接关联策略", option: "MatrixReadOnlyAccess", change: "新增关联", kind: "policies" },
    { tab: "所属用户组", trigger: "编辑", title: "管理所属用户组", option: "DeliveryTeam", change: "移除关联", kind: "groups" }
  ] as const)("keeps $kind association changes in the content area and retries without losing review", async ({ tab, trigger, title, option, change, kind }) => {
    const { user, repository, extension } = await open("users", { entityId: "principal-lin" });
    await user.click(await screen.findByRole("tab", { name: tab }));
    const panel = screen.getByRole("tabpanel", { name: tab });
    await user.click(within(panel).getByRole("button", { name: trigger }));
    const workflow = screen.getByRole("form", { name: `${title} · lin` });
    expect(screen.queryByRole("dialog")).toBeNull();
    await user.click(within(workflow).getByRole("checkbox", { name: option }));
    await user.click(within(workflow).getByRole("button", { name: "下一步：审阅" }));
    expect(within(workflow).getByRole("region", { name: `${change} · 1` }).textContent).toContain(option);
    expect(repository.workspace!.execute).not.toHaveBeenCalled();
    vi.mocked(repository.workspace!.execute).mockRejectedValueOnce(new Error("offline"));
    await user.click(within(workflow).getByRole("button", { name: "确认关联" }));
    await expectRetainedFailure(workflow);
    expect(within(workflow).getByRole("region", { name: `${change} · 1` }).textContent).toContain(option);
    await user.click(within(workflow).getByRole("button", { name: "确认关联" }));
    expect(await screen.findByRole("heading", { name: "关联已更新" })).toBeTruthy();
    const saved = await extension.read("preview-only");
    if (kind === "policies") expect(saved.userPolicies["principal-lin"]).toEqual(["policy-prod-logs", "policy-read"]);
    else expect(saved.groups.find((group) => group.id === "group-delivery")?.memberIds).not.toContain("principal-lin");
    await user.click(screen.getByRole("button", { name: "完成并返回" }));
    expect(await screen.findByRole("heading", { name: "lin" })).toBeTruthy();
  });
  it("creates through a full-page wizard with inline validation, preserved selections and localized errors", async () => {
    const { user, repository, extension } = await open("create-user");
    await screen.findByRole("heading", { name: "选择使用场景" });
    expect(screen.queryByRole("dialog")).toBeNull();
    await user.click(screen.getByRole("button", { name: "下一步" }));
    await user.type(screen.getByLabelText("子用户名"), "wizard.new");
    await user.type(screen.getByLabelText("用户显示名称"), "Wizard User");
    await user.click(screen.getByRole("checkbox", { name: "控制台访问" }));
    await user.click(screen.getByRole("button", { name: "下一步" }));
    expect(screen.getByRole("alert").textContent).toBe("访问方式必须选择一个。");
    await user.click(screen.getByRole("button", { name: "Language" }));
    expect(screen.getByRole("alert").textContent).toBe("Select at least one access method.");
    await user.click(screen.getByRole("checkbox", { name: "Console access" }));
    await user.click(screen.getByRole("button", { name: "Next" }));
    await user.click(screen.getByRole("checkbox", { name: "Select all on this page" }));
    expect(screen.getByText(/Selected policies or groups include an all-action wildcard grant/)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Clear page selection" }));
    expect(screen.queryByText(/Selected policies or groups include an all-action wildcard grant/)).toBeNull();
    await user.click(screen.getByRole("checkbox", { name: "MatrixReadOnlyAccess" }));
    await user.type(screen.getByRole("searchbox", { name: "Search name, ID, description or tags" }), "no-match");
    expect(screen.getByRole("button", { name: "Remove MatrixReadOnlyAccess" })).toBeTruthy();
    await user.click(screen.getByRole("tab", { name: "Join groups" }));
    await user.click(screen.getByRole("checkbox", { name: "DeliveryTeam" }));
    await user.click(screen.getByRole("button", { name: "User information" }));
    expect((screen.getByLabelText("Display name") as HTMLInputElement).value).toBe("Wizard User");
    await user.click(screen.getByRole("button", { name: "Next" }));
    expect(screen.getByRole("button", { name: "Remove DeliveryTeam" })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Next" }));
    await user.click(screen.getByRole("button", { name: "Add tag" }));
    await user.type(screen.getByLabelText("Tag key 1"), "team");
    await user.type(screen.getByLabelText("Tag value 1"), "platform");
    await user.click(screen.getByRole("button", { name: "Next" }));
    expect(repository.workspace!.execute).not.toHaveBeenCalled();
    expect(screen.getByText("MatrixReadOnlyAccess")).toBeTruthy();
    expect(screen.getByText("DeliveryTeam")).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Confirm mock user" }));
    await screen.findByRole("heading", { name: "User created" });
    const saved = await extension.read("preview");
    expect(saved.userProfiles["principal-wizard.new"]?.tags).toEqual([{ key: "team", value: "platform" }]);
    expect(saved.userPolicies["principal-wizard.new"]).toEqual(["policy-read"]);
    expect(repository.execute).not.toHaveBeenCalled();
    expect(sessionStorage.length).toBe(0);
  });
  it("bounds user policy selection by page and capacity while preserving independent group selections without writes", async () => {
    const { user, repository } = await open("create-user", { seed: async (extension) => {
      extension.transact((source) => ({ workspace: { ...source, policies: [...source.policies, ...Array.from({ length: 42 }, (_, index) => ({
        id: `policy-batch-${index}`, name: "Batch" + String(index).padStart(2, "0"), description: "", kind: "custom" as const, tags: [],
        versions: [{ id: 1, document: { version: "1" as const, statement: [{ effect: "allow" as const, action: ["logs:search"], resource: ["*"] }] }, createdAt: "2026-09-01T00:00:00Z" }],
        defaultVersion: 1, lastVersion: 1, createdAt: "2026-09-01T00:00:00Z", updatedAt: "2026-09-01T00:00:00Z"
      }))] } }));
    } });
    await user.click(await screen.findByRole("button", { name: "下一步" }));
    await user.type(screen.getByLabelText("子用户名"), "bulk.draft");
    await user.type(screen.getByLabelText("用户显示名称"), "Bulk Draft");
    await user.click(screen.getByRole("button", { name: "下一步" }));
    await user.type(screen.getByRole("searchbox"), "Batch");
    expect(within(screen.getByRole("table", { name: "可选策略" })).getAllByRole("row")).toHaveLength(21);
    await user.click(screen.getByRole("checkbox", { name: "选择本页全部" }));
    expect(screen.getByText("直接策略 20/30 · 用户组 0/30", { exact: false })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "下一页" }));
    expect(screen.getByRole("checkbox", { name: "选择本页全部" })).toHaveProperty("disabled", true);
    expect(screen.getByText(/本页还有 20 项未选，剩余可选 10 项/)).toBeTruthy();
    const rows = within(screen.getByRole("table", { name: "可选策略" })).getAllByRole("checkbox").slice(1);
    for (const row of rows.slice(0, 10)) fireEvent.click(row);
    expect(screen.getByText("直接策略 30/30 · 用户组 0/30", { exact: false })).toBeTruthy();
    expect(rows[10]).toHaveProperty("disabled", true);
    expect(rows[0]).toHaveProperty("disabled", false);
    await user.click(screen.getByRole("button", { name: "取消本页选择" }));
    expect(screen.getByText("直接策略 20/30 · 用户组 0/30", { exact: false })).toBeTruthy();
    await user.click(screen.getByRole("tab", { name: "加入用户组" }));
    await user.click(screen.getByRole("checkbox", { name: "DeliveryTeam" }));
    expect(screen.getByText("直接策略 20/30 · 用户组 1/30", { exact: false })).toBeTruthy();
    await user.click(screen.getByRole("tab", { name: "直接关联策略" }));
    await user.click(screen.getByRole("button", { name: "Language" }));
    expect(screen.getByText("Direct policies 20/30 · Groups 1/30", { exact: false })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Remove DeliveryTeam" })).toBeTruthy();
    expect(repository.workspace!.execute).not.toHaveBeenCalled();
    expect(repository.execute).not.toHaveBeenCalled();
  }, 15000);
  it("keeps a draft when cancel is dismissed and never creates it when discarded", async () => {
    const { user, repository } = await open("create-user");
    await screen.findByRole("heading", { name: "选择使用场景" });
    await user.click(screen.getByRole("button", { name: "下一步" }));
    await user.type(screen.getByLabelText("用户显示名称"), "Unsaved User");
    await user.click(screen.getByRole("button", { name: "取消" }));
    await user.click(screen.getByRole("button", { name: "继续编辑" }));
    expect((screen.getByLabelText("用户显示名称") as HTMLInputElement).value).toBe("Unsaved User");
    await user.click(screen.getByRole("button", { name: "取消" }));
    await user.click(screen.getByRole("button", { name: "放弃并离开" }));
    await screen.findByRole("table", { name: "租户用户列表" });
    expect(repository.workspace!.execute).not.toHaveBeenCalled();
  });
  it("treats access-only changes as a draft before any name has been entered", async () => {
    const { user, repository } = await open("create-user");
    await screen.findByRole("heading", { name: "选择使用场景" });
    await user.click(screen.getByRole("button", { name: "下一步" }));
    await user.click(screen.getByRole("checkbox", { name: "编程访问" }));
    await user.click(screen.getByRole("button", { name: "取消" }));
    expect(screen.getByRole("dialog", { name: "放弃创建用户？" })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "继续编辑" }));
    expect((screen.getByRole("checkbox", { name: "编程访问" }) as HTMLInputElement).checked).toBe(true);
    expect(repository.workspace!.execute).not.toHaveBeenCalled();
  });
  it("opens and filters the preview operation history from overview", async () => {
    const { user } = await open("overview");
    await user.click(await screen.findByRole("button", { name: "查看全部记录" }));
    expect(screen.getByText(/不作为真实安全审计凭证/)).toBeTruthy();
    await user.type(screen.getByRole("searchbox", { name: "搜索名称、ID 或关键字" }), "no-matching-target");
    expect(screen.getByText("没有匹配的结果")).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "返回列表" }));
    expect(screen.getByRole("button", { name: "查看全部记录" })).toBeTruthy();
  });
  it.each(["groups", "policies", "simulator", "roles", "providers", "user-sso", "federations", "keys", "settings"] as const)("renders %s with consistent localized controls", async (view) => {
    const { user } = await open(view);
    expect(screen.getByRole("region", { name: "账号与权限" })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Language" }));
    expect(screen.getByRole("region", { name: "Identity and access" })).toBeTruthy();
    expect(document.body.textContent).not.toMatch(/\p{Script=Han}/u);
  });
  it("keeps the group directory action-free and moves management into the selected group", async () => {
    const { user } = await open("groups");
    const directory = await screen.findByRole("table", { name: "用户组" });
    expect(within(directory).queryByText("操作")).toBeNull();
    expect(within(directory).queryByRole("button", { name: "编辑" })).toBeNull();
    expect(within(directory).queryByRole("button", { name: "删除" })).toBeNull();
    expect(within(directory).getAllByText("1 项直接关联")).toHaveLength(2);
    await user.click(within(directory).getByRole("button", { name: "DeliveryTeam" }));
    expect(screen.getByRole("button", { name: "编辑" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "删除" })).toBeTruthy();
    const members = screen.getByRole("table", { name: "成员" });
    expect(within(members).queryByText("操作")).toBeNull();
    expect(within(members).queryByRole("button", { name: /从用户组移除/ })).toBeNull();
    expect(screen.getByRole("tab", { name: "直接关联策略 (1)" })).toBeTruthy();
  });
  it("omits the member-count column when the repository has not supplied an authoritative total", () => {
    render(<LocaleProvider><GroupDirectory
      groups={[{
        id: "group-paged",
        name: "PagedTeam",
        description: "Memberships are loaded independently",
        directPolicyCount: 2,
        createdAt: "2026-09-08T09:00:00Z"
      }]}
      onOpen={vi.fn()}
    /></LocaleProvider>);
    const table = screen.getByRole("table", { name: "用户组" });
    expect(within(table).queryByRole("columnheader", { name: "成员" })).toBeNull();
    expect(within(table).getByRole("columnheader", { name: "直接关联策略" })).toBeTruthy();
    expect(within(table).getByText("2 项直接关联")).toBeTruthy();
  });
  it("reveals the live group object before its membership relationship page finishes", async () => {
    const liveGroup: GroupAccess = {
      group: { id: "group-progressive", accountId: account.id, name: "ProgressiveTeam", description: "Group facts load independently", resourceVersion: 1, createdAt: "2026-09-11T08:00:00Z", updatedAt: "2026-09-11T08:00:00Z" },
      policyAttachments: [],
      capabilities: [
        capability("iam.group.read", "GROUP", "group-progressive"),
        capability("iam.group-membership.list", "GROUP", "group-progressive")
      ]
    };
    let resolveMemberships!: (page: { accountId: string; groupId: string; items: GroupMembershipAccess[]; nextAfter: null }) => void;
    const listGroupMemberships = vi.fn(() => new Promise<{ accountId: string; groupId: string; items: GroupMembershipAccess[]; nextAfter: null }>((resolve) => { resolveMemberships = resolve; }));
    const { user } = await open("groups", { live: true, repository: {
      listGroups: vi.fn().mockResolvedValue({ items: [liveGroup], nextAfter: null }),
      getGroup: vi.fn().mockResolvedValue(liveGroup),
      listGroupMemberships
    } });
    const directory = await screen.findByRole("table", { name: "用户组" });
    await user.click(within(directory).getByRole("button", { name: "ProgressiveTeam" }));
    expect(await screen.findByRole("heading", { name: "ProgressiveTeam" })).toBeTruthy();
    expect(screen.getByText("正在读取成员关系…")).toBeTruthy();
    expect(screen.queryByRole("table", { name: "成员" })).toBeNull();
    await act(async () => { resolveMemberships({ accountId: account.id, groupId: liveGroup.group.id, items: [], nextAfter: null }); });
    expect(await screen.findByText("暂无成员")).toBeTruthy();
    expect(screen.queryByText("正在读取成员关系…")).toBeNull();
  });
  it("keeps live group facts available when membership loading fails and retries only that relation", async () => {
    const liveGroup: GroupAccess = {
      group: { id: "group-retry", accountId: account.id, name: "RetryTeam", description: "Relationship failure stays local", resourceVersion: 1, createdAt: "2026-09-11T08:00:00Z", updatedAt: "2026-09-11T08:00:00Z" },
      policyAttachments: [],
      capabilities: [
        capability("iam.group.read", "GROUP", "group-retry"),
        capability("iam.group-membership.list", "GROUP", "group-retry")
      ]
    };
    const getGroup = vi.fn().mockResolvedValue(liveGroup);
    const listGroupMemberships = vi.fn()
      .mockRejectedValueOnce(new Error("temporary relationship failure"))
      .mockResolvedValueOnce({ accountId: account.id, groupId: liveGroup.group.id, items: [], nextAfter: null });
    const { user } = await open("groups", { live: true, repository: {
      listGroups: vi.fn().mockResolvedValue({ items: [liveGroup], nextAfter: null }),
      getGroup,
      listGroupMemberships
    } });
    const directory = await screen.findByRole("table", { name: "用户组" });
    await user.click(within(directory).getByRole("button", { name: "RetryTeam" }));
    expect(await screen.findByRole("heading", { name: "RetryTeam" })).toBeTruthy();
    expect(await screen.findByText("成员关系暂时无法载入")).toBeTruthy();
    expect(screen.getByText("Relationship failure stays local")).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "重试" }));
    expect(await screen.findByText("暂无成员")).toBeTruthy();
    expect(getGroup).toHaveBeenCalledTimes(1);
    expect(listGroupMemberships).toHaveBeenCalledTimes(2);
  });
  it("uses the fixed live group contract without inventing totals and retries one unchanged relation intent", async () => {
    const liveGroup: GroupAccess = {
      group: { id: "group-live", accountId: account.id, name: "LiveOperators", description: "Backend-owned group", resourceVersion: 4, createdAt: "2026-09-11T08:00:00Z", updatedAt: "2026-09-11T08:00:00Z" },
      policyAttachments: [],
      capabilities: [
        capability("iam.group.read", "GROUP", "group-live"),
        capability("iam.group.update", "GROUP", "group-live"),
        capability("iam.group.delete", "GROUP", "group-live"),
        capability("iam.group-membership.list", "GROUP", "group-live"),
        capability("iam.group-membership.create", "GROUP", "group-live"),
        capability("iam.group-policy-attachment.create", "GROUP", "group-live")
      ]
    };
    const membership = (id: string, userId: string): GroupMembershipAccess => ({
      membership: { id, accountId: account.id, groupId: liveGroup.group.id, userId, createdBy: rootUser.id, resourceVersion: 1, createdAt: "2026-09-11T08:00:00Z", updatedAt: "2026-09-11T08:00:00Z" },
      capabilities: [capability("iam.group-membership.remove", "GROUP_MEMBERSHIP", id)]
    });
    const lin = membership("membership-lin", "principal-lin");
    const chen = membership("membership-chen", "principal-chen");
    const listMemberships = vi.fn()
      .mockResolvedValueOnce({ accountId: account.id, groupId: liveGroup.group.id, items: [lin], nextAfter: null })
      .mockResolvedValueOnce({ accountId: account.id, groupId: liveGroup.group.id, items: [lin, chen], nextAfter: null });
    const createMembership = vi.fn()
      .mockRejectedValueOnce(new Error("unknown outcome"))
      .mockResolvedValueOnce(chen.membership);
    const { user } = await open("groups", { live: true, repository: {
      listGroups: vi.fn().mockResolvedValue({ items: [liveGroup], nextAfter: null }),
      getGroup: vi.fn().mockResolvedValue(liveGroup),
      listGroupMemberships: listMemberships,
      createGroupMembership: createMembership
    } });
    const directory = await screen.findByRole("table", { name: "用户组" });
    expect(within(directory).queryByRole("columnheader", { name: "成员" })).toBeNull();
    expect(screen.getByText(/搜索和筛选仅作用于当前已载入记录/)).toBeTruthy();
    await user.click(within(directory).getByRole("button", { name: "LiveOperators" }));
    expect(await screen.findByRole("heading", { name: "LiveOperators" })).toBeTruthy();
    expect(screen.getByRole("tab", { name: "成员" })).toBeTruthy();
    expect(screen.queryByRole("tab", { name: "成员 (1)" })).toBeNull();
    await user.click(screen.getByRole("button", { name: "添加成员" }));
    const dialog = within(screen.getByRole("dialog"));
    await user.click(dialog.getByRole("checkbox", { name: "chen" }));
    await user.click(dialog.getByRole("button", { name: "审阅变更" }));
    await user.click(dialog.getByRole("button", { name: "确认变更" }));
    await waitFor(() => expect(createMembership).toHaveBeenCalledTimes(1));
    const retained = createMembership.mock.calls[0]?.[3]?.requestId;
    expect(retained).toEqual(expect.any(String));
    expect(dialog.getByText(/暂时无法完成操作/)).toBeTruthy();
    await user.click(dialog.getByRole("button", { name: "确认变更" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(createMembership).toHaveBeenCalledTimes(2);
    expect(createMembership.mock.calls[1]?.[3]?.requestId).toBe(retained);
    expect(screen.getByRole("tab", { name: "成员" })).toBeTruthy();
    expect(screen.queryByRole("tab", { name: "成员 (2)" })).toBeNull();
  });
  it("creates only an empty group, then adds each member and policy relationship separately", async () => {
    const { user, repository, extension } = await open("groups");
    await user.click(await screen.findByRole("button", { name: "新建用户组" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    await user.type(screen.getByLabelText("名称"), "Platform Operators");
    await user.click(screen.getByRole("button", { name: "下一步" }));
    expect(screen.queryByRole("checkbox", { name: "lin" })).toBeNull();
    expect(screen.getByText("本次只创建空用户组；不会添加成员或关联策略。")).toBeTruthy();
    expect(screen.getByText("0 项直接关联")).toBeTruthy();
    expect(repository.workspace!.execute).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "新建用户组" }));
    await screen.findByRole("heading", { name: "用户组已创建" });
    const created = (await extension.read("preview")).groups.at(-1)!;
    expect(created.memberIds).toEqual([]);
    expect(created.policyIds).toEqual([]);
    await user.click(screen.getByRole("button", { name: "查看用户组" }));
    expect(screen.getByLabelText("Entity destination").textContent).toBe(created.id);
    await user.click(screen.getByRole("button", { name: "添加成员" }));
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByRole("button", { name: "审阅变更" })).toHaveProperty("disabled", true);
    await user.click(within(dialog).getByRole("checkbox", { name: "lin" }));
    await user.click(within(dialog).getByRole("button", { name: "审阅变更" }));
    expect(within(dialog).getByText(/本次变更涉及 1 位成员/)).toBeTruthy();
    expect((await extension.read("preview")).groups.at(-1)?.memberIds).toEqual([]);
    await user.click(within(dialog).getByRole("button", { name: "确认变更" }));
    expect(screen.getByRole("tab", { name: "成员 (1)" })).toBeTruthy();
    expect(repository.execute).not.toHaveBeenCalled();
    expect((await extension.read("preview")).groups.at(-1)?.memberIds).toEqual(["principal-lin"]);
    await user.click(screen.getByRole("tab", { name: "直接关联策略 (0)" }));
    await user.click(screen.getByRole("button", { name: "关联策略" }));
    const policyDialog = within(screen.getByRole("dialog"));
    await user.click(policyDialog.getByRole("checkbox", { name: "MatrixReadOnlyAccess" }));
    expect(policyDialog.getByRole("checkbox", { name: "MatrixAuditReadOnly" })).toHaveProperty("disabled", true);
    expect(policyDialog.getByText(/每次选择 1 项/)).toBeTruthy();
    await user.click(policyDialog.getByRole("button", { name: "审阅变更" }));
    expect((await extension.read("preview")).groups.at(-1)?.policyIds).toEqual([]);
    await user.click(policyDialog.getByRole("button", { name: "确认变更" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(screen.getByRole("tab", { name: "直接关联策略 (1)" })).toBeTruthy();
    expect((await extension.read("preview")).groups.at(-1)?.policyIds).toEqual(["policy-read"]);
    await user.click(screen.getByRole("button", { name: "返回列表" }));
    await user.type(screen.getByRole("searchbox", { name: "搜索名称、ID 或关键字" }), "Platform Operators");
    expect(screen.queryByRole("button", { name: "DeliveryTeam" })).toBeNull();
  });
  it("preserves a group draft through back, locale change and dismissed cancellation, and discards without writes", async () => {
    const { user, repository, extension } = await open("create-group");
    const before = await extension.read("preview");
    await screen.findByRole("heading", { name: "填写用户组信息" });
    await user.click(screen.getByRole("button", { name: "下一步" }));
    expect(document.activeElement).toBe(screen.getByLabelText("名称"));
    await user.type(screen.getByLabelText("名称"), "deliveryteam");
    await user.click(screen.getByRole("button", { name: "下一步" }));
    expect(screen.getByText("用户组名称已存在。")).toBeTruthy();
    await user.clear(screen.getByLabelText("名称")); await user.type(screen.getByLabelText("名称"), "Draft Team");
    await user.click(screen.getByRole("button", { name: "下一步" }));
    await user.click(screen.getByRole("button", { name: "上一步" }));
    expect((screen.getByLabelText("名称") as HTMLInputElement).value).toBe("Draft Team");
    await user.click(screen.getByRole("button", { name: "Language" }));
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    await user.click(screen.getByRole("button", { name: "Continue editing" }));
    await user.click(screen.getByRole("button", { name: "Next" }));
    expect(screen.getByText("This creates only an empty group; no members or policies are attached.")).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    await user.click(screen.getByRole("button", { name: "Discard and leave" }));
    await screen.findByRole("table", { name: "User groups" });
    expect(repository.workspace!.execute).not.toHaveBeenCalled();
    expect(await extension.read("preview")).toEqual(before);
  });
  it("keeps failed member changes editable and retries the exact delta without losing existing members", async () => {
    const { user, repository, extension } = await open("groups", { entityId: "group-delivery" });
    const before = await extension.read("preview");
    await user.click(await screen.findByRole("button", { name: "添加成员" }));
    let dialog = within(screen.getByRole("dialog"));
    await user.click(dialog.getByRole("checkbox", { name: "chen" }));
    await user.click(dialog.getByRole("button", { name: "审阅变更" }));
    vi.mocked(repository.workspace!.execute).mockRejectedValueOnce(new Error("offline"));
    await user.click(dialog.getByRole("button", { name: "确认变更" }));
    await waitFor(() => expect(dialog.getAllByRole("alert").some((alert) => alert.textContent?.includes("重试"))).toBe(true));
    expect(await extension.read("preview")).toEqual(before);
    await user.click(dialog.getByRole("button", { name: "返回选择" }));
    expect((dialog.getByRole("checkbox", { name: "chen" }) as HTMLInputElement).checked).toBe(true);
    await user.click(dialog.getByRole("button", { name: "审阅变更" }));
    await user.click(dialog.getByRole("button", { name: "确认变更" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect((await extension.read("preview")).groups[0]?.memberIds).toEqual(["principal-lin", "principal-chen"]);
    await user.click(screen.getByRole("button", { name: "移除成员" }));
    dialog = within(screen.getByRole("dialog"));
    await user.click(dialog.getByRole("checkbox", { name: "chen" }));
    await user.click(dialog.getByRole("button", { name: "审阅变更" }));
    expect(dialog.getByText(/不代表撤销全部访问权限/)).toBeTruthy();
    await user.click(dialog.getByRole("button", { name: "取消" }));
    expect((await extension.read("preview")).groups[0]?.memberIds).toEqual(["principal-lin", "principal-chen"]);
    expect(repository.execute).not.toHaveBeenCalled();
  });
  it("cross-links exact group, member and policy entities with named grant sources on both sides", async () => {
    const { user } = await open("groups", { entityId: "group-delivery", seed: async (extension) => {
      await extension.execute("preview", { kind: "change-group-policies", id: "group-delivery", added: ["policy-prod-logs"], removed: [] });
    } });
    await user.click(await screen.findByRole("button", { name: "lin" }));
    expect(screen.getByLabelText("Entity destination").textContent).toBe("principal-lin");
    await user.click(screen.getByRole("tab", { name: "权限策略" }));
    const policyRow = screen.getByRole("button", { name: "ProductionLogReader" }).closest("tr")!;
    expect(within(policyRow).getByText("直接关联")).toBeTruthy();
    await user.click(within(policyRow).getByRole("button", { name: "继承自 DeliveryTeam" }));
    expect(screen.getByLabelText("Entity destination").textContent).toBe("group-delivery");
    await user.click(screen.getByRole("tab", { name: "直接关联策略 (2)" }));
    await user.click(screen.getByRole("button", { name: "ProductionLogReader" }));
    expect(screen.getByLabelText("Entity destination").textContent).toBe("policy-prod-logs");
    await user.click(screen.getByRole("tab", { name: /策略用法/ }));
    expect(screen.getByRole("button", { name: "lin" })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "DeliveryTeam" }));
    expect(screen.getByRole("heading", { name: "DeliveryTeam" })).toBeTruthy();
  });
  it("changes group policies only after review and keeps metadata edits independent", async () => {
    const { user, extension } = await open("groups", { entityId: "group-delivery" });
    await user.click(await screen.findByRole("button", { name: "编辑" }));
    const metadata = within(screen.getByRole("dialog"));
    expect(metadata.queryByRole("checkbox")).toBeNull();
    await user.type(metadata.getByLabelText("描述"), " updated");
    await user.click(metadata.getByRole("button", { name: "保存" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    const before = await extension.read("preview");
    await user.click(screen.getByRole("tab", { name: "直接关联策略 (1)" }));
    await user.click(screen.getByRole("button", { name: "关联策略" }));
    let dialog = within(screen.getByRole("dialog"));
    await user.click(dialog.getByRole("checkbox", { name: "MatrixReadOnlyAccess" }));
    await user.click(dialog.getByRole("button", { name: "审阅变更" }));
    expect(await extension.read("preview")).toEqual(before);
    await user.click(dialog.getByRole("button", { name: "确认变更" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    const after = await extension.read("preview");
    expect(after.groups[0]?.memberIds).toEqual(before.groups[0]?.memberIds);
    expect(after.groups[0]?.policyIds).toEqual(["policy-delivery", "policy-read"]);
    await user.click(screen.getByRole("button", { name: "解除策略" }));
    dialog = within(screen.getByRole("dialog"));
    await user.click(dialog.getByRole("checkbox", { name: "MatrixReadOnlyAccess" }));
    await user.click(dialog.getByRole("button", { name: "审阅变更" }));
    await user.click(dialog.getByRole("button", { name: "确认变更" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect((await extension.read("preview")).groups[0]).toEqual(before.groups[0]);
  });
  it.each(["users", "groups", "policies", "roles"] as const)("does not substitute another identity for an unavailable %s deep link", async (view) => {
    const { user, repository } = await open(view, { entityId: "foreign-or-missing" });
    await screen.findByText("对象不可用");
    await user.click(screen.getByRole("button", { name: "返回列表" }));
    expect(screen.queryByText("对象不可用")).toBeNull();
    expect(screen.getByLabelText("Entity destination").textContent).toBe("directory");
    expect(repository.workspace!.execute).not.toHaveBeenCalled();
  });
  it("reports an unknown simulator identity instead of simulating the first available user", async () => {
    const { user } = await open("simulator", { entityId: "missing-user" });
    await user.click(await screen.findByRole("button", { name: "运行模拟" }));
    expect(screen.queryByText("策略允许")).toBeNull();
    expect(screen.getByText("请求无法模拟")).toBeTruthy();
  });
  it("keeps a visual policy draft editable and creates a version only on save", async () => {
    const { user, extension } = await open("policies");
    const before = (await extension.read("preview")).policies;
    await user.click(await screen.findByRole("button", { name: "新建自定义策略" }));
    await user.click(within(screen.getByRole("dialog", { name: "选择创建策略方式" })).getByRole("button", { name: /^按策略生成器创建/ }));
    expect(screen.queryByRole("dialog")).toBeNull();
    await logActions(user, ["logs:read", "logs:search"]);
    await select(user, "资源授权范围", "指定资源");
    const resourceId = screen.getByLabelText("资源 ID 或前缀 1");
    await user.clear(resourceId); await user.type(resourceId, "production/*");
    expect((screen.getByRole("checkbox", { name: "logs:search" }) as HTMLInputElement).checked).toBe(true);
    await user.click(screen.getByRole("tab", { name: "JSON 编辑" }));
    expect((screen.getByLabelText("策略内容", { selector: "textarea" }) as HTMLTextAreaElement).value).toContain("logs:search");
    expect((await extension.read("preview")).policies).toEqual(before);
    await user.click(screen.getByRole("button", { name: "下一步" }));
    await user.type(screen.getByLabelText("名称", { exact: true }), "ReadCluster");
    await user.click(screen.getByRole("button", { name: "下一步" }));
    expect((await extension.read("preview")).policies).toEqual(before);
    await user.click(screen.getByRole("button", { name: "创建策略" }));
    expect((await extension.read("preview")).policies.at(-1)?.versions[0]?.document.statement[0]?.action).toEqual(["logs:read", "logs:search"]);
  });
  it("shows dependency errors inside a destructive confirmation", async () => {
    const { user } = await open("providers");
    await user.click(await screen.findByRole("button", { name: "EnterpriseSSO" }));
    await user.click(await screen.findByRole("button", { name: "删除" }));
    await user.type(screen.getByLabelText("输入名称以确认"), "EnterpriseSSO");
    await user.click(screen.getByRole("button", { name: "确认删除" }));
    await waitFor(() => expect(within(screen.getByRole("dialog")).getByRole("alert").textContent).toContain("仍被引用"));
  });
  it("round-trips typed resources and all condition types, preserving restrictions in review and save", async () => {
    const { user, extension, repository } = await open("create-policy");
    await logActions(user, ["logs:search"]);
    await select(user, "资源授权范围", "指定资源");
    fireEvent.change(screen.getByLabelText("资源 ID 或前缀 1"), { target: { value: "production/*" } });
    await user.click(screen.getByRole("checkbox", { name: "限制来源 IP" }));
    fireEvent.change(screen.getByLabelText("来源 IP 范围（CIDR）"), { target: { value: "192.0.2.0/24\n2001:db8::/32" } });
    await user.click(screen.getByRole("checkbox", { name: "按资源标签限制" }));
    fireEvent.change(screen.getByLabelText("标签键 1"), { target: { value: "environment" } });
    fireEvent.change(screen.getByLabelText("标签值 1"), { target: { value: "production" } });
    await user.click(screen.getByRole("checkbox", { name: "设置生效时间下限" }));
    await user.click(screen.getByRole("checkbox", { name: "设置生效时间上限" }));
    fireEvent.change(screen.getByLabelText("不早于（UTC，含边界）"), { target: { value: "2026-09-09T00:00" } });
    fireEvent.change(screen.getByLabelText("不晚于（UTC，含边界）"), { target: { value: "2026-09-10T00:00" } });
    const condition = { sourceIp: ["192.0.2.0/24", "2001:db8::/32"], resourceTag: [{ key: "environment", value: "production" }], notBefore: "2026-09-09T00:00:00.000Z", notAfter: "2026-09-10T00:00:00.000Z" };
    await user.click(screen.getByRole("tab", { name: "JSON 编辑" }));
    expect(JSON.parse((screen.getByLabelText("策略内容", { selector: "textarea" }) as HTMLTextAreaElement).value).statement[0].condition).toEqual(condition);
    await user.click(screen.getByRole("tab", { name: "可视化编辑" }));
    expect((screen.getByLabelText("资源 ID 或前缀 1") as HTMLInputElement).value).toBe("production/*");
    expect((screen.getByLabelText("来源 IP 范围（CIDR）") as HTMLTextAreaElement).value).toBe("192.0.2.0/24\n2001:db8::/32");
    expect((screen.getByLabelText("标签值 1") as HTMLInputElement).value).toBe("production");
    await user.click(screen.getByRole("button", { name: "下一步" }));
    await user.click(screen.getByLabelText("名称", { exact: true })); await user.paste("ConditionalLogAccess");
    await user.click(screen.getByRole("button", { name: "下一步" }));
    const summary = within(screen.getByRole("table", { name: "策略摘要" }));
    expect(summary.getByText(/2001:db8::\/32/)).toBeTruthy();
    expect(summary.getByText('environment = "production"')).toBeTruthy();
    expect(summary.getByText(/2026-09-10T00:00:00.000Z/)).toBeTruthy();
    await user.click(summary.getByRole("button", { name: "查看日志服务的允许操作" }));
    expect(within(screen.getByRole("table", { name: "操作明细" })).getByText("logs:search")).toBeTruthy();
    expect(screen.getByRole("heading", { name: "审阅并保存" })).toBeTruthy();
    expect(repository.workspace!.execute).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "返回服务摘要" }));
    expect(repository.workspace!.execute).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "创建策略" }));
    await screen.findByRole("heading", { name: "策略已保存" });
    expect((await extension.read("preview")).policies.at(-1)?.versions[0]?.document.statement[0]).toEqual({ effect: "allow", action: ["logs:search"], resource: ["matrix:logs:org-xiak:*:topic/production/*"], condition });
    expect(repository.execute).not.toHaveBeenCalled();
  });
  it("blocks empty conditions and incompatible account actions instead of silently widening resource scope", async () => {
    const { user, repository } = await open("create-policy");
    await logActions(user, ["logs:search"]);
    await select(user, "资源授权范围", "指定资源");
    await user.type(screen.getByLabelText("资源 ID 或前缀 1"), "production/*");
    await user.click(screen.getByRole("checkbox", { name: "logs:list" }));
    expect((screen.getByRole("checkbox", { name: "按资源标签限制" }) as HTMLInputElement).disabled).toBe(true);
    await user.click(screen.getByRole("combobox", { name: "资源授权范围" }));
    expect(screen.getByRole("option", { name: "指定资源" }).getAttribute("aria-disabled")).toBe("true");
    await user.keyboard("{Escape}");
    await user.click(screen.getByRole("button", { name: "下一步" }));
    expect(screen.getAllByRole("alert").some((alert) => alert.textContent?.includes("资源"))).toBe(true);
    expect((screen.getByLabelText("资源 ID 或前缀 1") as HTMLInputElement).value).toBe("production/*");
    await user.click(screen.getByRole("checkbox", { name: "logs:list" }));
    await user.click(screen.getByRole("checkbox", { name: "限制来源 IP" }));
    await user.click(screen.getByRole("button", { name: "下一步" }));
    expect(screen.getByRole("alert").textContent).toContain("条件");
    expect(document.activeElement).toBe(screen.getByRole("alert"));
    expect(screen.getByLabelText("来源 IP 范围（CIDR）")).toBeTruthy();
    expect(repository.workspace!.execute).not.toHaveBeenCalled();
  });
  it("confirms a service change, retaining other statements and condition restrictions", async () => {
    const { user } = await open("create-policy");
    await user.click(screen.getByRole("tab", { name: "JSON 编辑" }));
    const initial = { version: "1", statement: [
      { effect: "allow", action: ["logs:search"], resource: ["matrix:logs:org-xiak:*:topic/production/*"], condition: { sourceIp: ["192.0.2.0/24"] } },
      { effect: "deny", action: ["database:delete"], resource: ["*"] }
    ] };
    const json = () => screen.getByLabelText("策略内容", { selector: "textarea" }) as HTMLTextAreaElement;
    await user.clear(json()); await user.paste(JSON.stringify(initial));
    await user.click(screen.getByRole("tab", { name: "可视化编辑" }));
    await user.click(within(screen.getByRole("region", { name: "声明 1" })).getByRole("combobox", { name: "产品服务" }));
    await user.click(screen.getByRole("option", { name: "PostgreSQL 数据库" }));
    await user.click(within(screen.getByRole("dialog")).getByRole("button", { name: "取消" }));
    expect((screen.getByLabelText("资源 ID 或前缀 1") as HTMLInputElement).value).toBe("production/*");
    await user.click(within(screen.getByRole("region", { name: "声明 1" })).getByRole("combobox", { name: "产品服务" }));
    await user.click(screen.getByRole("option", { name: "PostgreSQL 数据库" }));
    await user.click(screen.getByRole("button", { name: "切换服务" }));
    await user.click(within(screen.getByRole("region", { name: "声明 1" })).getByRole("checkbox", { name: "database:read" }));
    await user.click(screen.getByRole("tab", { name: "JSON 编辑" }));
    expect(JSON.parse(json().value).statement).toEqual([{ ...initial.statement[0], action: ["database:read"], resource: ["*"] }, initial.statement[1]]);
  });
  it("explains user grants, clears stale results on input changes and remains preview-only", async () => {
    const { user, repository } = await open("simulator");
    await user.click(await screen.findByRole("button", { name: "运行模拟" }));
    expect(screen.getByText("策略允许")).toBeTruthy();
    expect(document.activeElement).toBe(screen.getByRole("heading", { name: "模拟结果" }));
    const table = screen.getByRole("table", { name: "策略判断依据" });
    expect(screen.getByText("第 1 / 1 页")).toBeTruthy();
    expect(screen.getByRole("combobox", { name: "每页条数" })).toBeTruthy();
    expect(within(table).getByText("直接关联")).toBeTruthy();
    expect(within(table).queryByText("DeliveryTeam")).toBeNull();
    await user.click(screen.getByRole("button", { name: /查看其余 \d+ 条判断依据/ }));
    expect(within(table).getByText("用户组继承")).toBeTruthy();
    expect(within(table).getByText("ProductionLogReader")).toBeTruthy();
    expect(within(table).getByText("DeliveryTeam")).toBeTruthy();
    await select(user, "用户", "chen");
    expect(screen.queryByText("策略允许")).toBeNull();
    await user.click(screen.getByRole("button", { name: "运行模拟" }));
    expect(screen.getByText("默认拒绝")).toBeTruthy();
    expect(screen.getByText("操作不匹配")).toBeTruthy();
    expect(repository.execute).not.toHaveBeenCalled();
    expect(repository.workspace!.execute).not.toHaveBeenCalled();
  });
  it("prefills diagnostic examples without mutation or automatic decisions and links grant sources", async () => {
    const { user, repository, extension } = await open("simulator", { users: reviewUsers });
    const before = await extension.read("preview");
    await select(user, "了解一个授权场景", "直接授权与组继承");
    const example = screen.getByRole("combobox", { name: "了解一个授权场景" });
    expect(document.getElementById(example.getAttribute("aria-describedby")!)?.textContent).toContain("查看同一策略的直接和用户组两条来源");
    expect(screen.getByRole("combobox", { name: "用户" }).textContent).toContain("qiao");
    expect(screen.queryByRole("heading", { name: "模拟结果" })).toBeNull();
    await user.click(screen.getByRole("button", { name: "运行模拟" }));
    expect(screen.getByText("策略允许", { exact: true })).toBeTruthy();
    expect(screen.getByText(/策略允许不代表真实请求一定成功/)).toBeTruthy();
    const evidence = within(screen.getByRole("table", { name: "策略判断依据" }));
    expect(evidence.getAllByRole("button", { name: "ProductionLogsByTag" })).toHaveLength(2);
    expect(evidence.getByText("直接关联")).toBeTruthy();
    expect(evidence.getByText("用户组继承")).toBeTruthy();
    expect(await extension.read("preview")).toEqual(before);
    expect(repository.execute).not.toHaveBeenCalled();
    expect(repository.workspace!.execute).not.toHaveBeenCalled();
    await user.click(evidence.getByRole("button", { name: "ReleaseOperators" }));
    expect(await screen.findByRole("heading", { name: "ReleaseOperators" })).toBeTruthy();
    expect(screen.getByLabelText("Entity destination").textContent).toBe("group-operators");
  });
  it("retains a compatible action across resources and clears it across services", async () => {
    const { user } = await open("simulator");
    await user.click(screen.getByRole("button", { name: "运行模拟" }));
    await select(user, "测试资源", "archive/payment · cn-shanghai-a");
    expect(screen.getByRole("combobox", { name: "请求操作" }).textContent).toContain("logs:search");
    expect(screen.getByRole("button", { name: "运行模拟" }).hasAttribute("disabled")).toBe(false);
    expect(screen.queryByRole("heading", { name: "模拟结果" })).toBeNull();
    await user.click(screen.getByRole("button", { name: "运行模拟" }));
    expect(screen.getByText("默认拒绝", { exact: true })).toBeTruthy();
    await select(user, "测试资源", "account · global");
    expect(screen.getByRole("combobox", { name: "请求操作" }).textContent).toBe("选择操作");
    expect(screen.getByRole("button", { name: "运行模拟" }).hasAttribute("disabled")).toBe(true);
    await select(user, "产品服务", "PostgreSQL 数据库");
    expect(screen.getByRole("combobox", { name: "请求操作" }).textContent).toBe("选择操作");
    expect(screen.getByRole("button", { name: "运行模拟" }).hasAttribute("disabled")).toBe(true);
    expect(screen.queryByRole("heading", { name: "模拟结果" })).toBeNull();
  });
  it("prioritizes the matching deny and boundary evidence with links to their policies", async () => {
    const { user } = await open("simulator", { users: reviewUsers });
    await select(user, "了解一个授权场景", "命中显式拒绝");
    await user.click(screen.getByRole("button", { name: "运行模拟" }));
    expect(screen.getByText("显式拒绝", { exact: true })).toBeTruthy();
    let evidence = within(screen.getByRole("table", { name: "策略判断依据" }));
    expect(evidence.getAllByRole("row")).toHaveLength(2);
    expect(evidence.getByRole("button", { name: "ProtectProductionDeployments" })).toBeTruthy();
    await select(user, "了解一个授权场景", "权限边界限制");
    expect(screen.queryByRole("heading", { name: "模拟结果" })).toBeNull();
    await user.click(screen.getByRole("button", { name: "运行模拟" }));
    expect(screen.getByText("默认拒绝", { exact: true })).toBeTruthy();
    evidence = within(screen.getByRole("table", { name: "策略判断依据" }));
    expect(evidence.queryByRole("button", { name: "MatrixDeliveryAccess" })).toBeNull();
    await user.click(evidence.getAllByRole("button", { name: "ReleaseOperatorBoundary" })[0]!);
    expect(await screen.findByRole("heading", { name: "ReleaseOperatorBoundary" })).toBeTruthy();
    expect(screen.getByLabelText("Entity destination").textContent).toBe("policy-delivery-boundary");
  });
  it("separates an ungranted login profile and a disabled user from policy evaluation", async () => {
    const { user } = await open("simulator", { users: reviewUsers.map((entry) => entry.user.id === "principal-lin" ? { ...entry, user: { ...entry.user, status: "DISABLED" } } : entry) });
    expect(screen.getByText(/此用户已停用/)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "运行模拟" }));
    expect(screen.getByText("策略允许", { exact: true })).toBeTruthy();
    expect(screen.getByText(/未评估：账号／用户可用性/)).toBeTruthy();
    await select(user, "了解一个授权场景", "能登录但尚未授权");
    expect(screen.queryByText(/此用户已停用/)).toBeNull();
    await user.click(screen.getByRole("button", { name: "运行模拟" }));
    expect(screen.getByText("默认拒绝", { exact: true })).toBeTruthy();
    expect(screen.queryByRole("table", { name: "策略判断依据" })).toBeNull();
    await user.click(screen.getByRole("button", { name: "查看用户 wu" }));
    expect(screen.getByLabelText("Entity destination").textContent).toBe("principal-wu");
    await user.click(screen.getByRole("tab", { name: "访问方式" }));
    expect(screen.getByText(/访问方式决定如何登录或调用 API，不代表资源权限/)).toBeTruthy();
  });
  it("shows missing context as indeterminate and a conditional explicit deny with current-version evidence", async () => {
    const { user } = await open("simulator", { seed: async (extension) => {
      await extension.execute("preview", { kind: "save-policy", id: "policy-prod-logs", name: "ProductionLogReader", description: "", document: { version: "1", statement: [{ effect: "deny", action: ["logs:search"], resource: ["*"], condition: { sourceIp: ["192.0.2.0/24"] } }] } });
    } });
    await user.clear(screen.getByLabelText("来源 IP"));
    await user.click(screen.getByRole("button", { name: "运行模拟" }));
    expect(screen.getByText("无法确定")).toBeTruthy();
    expect(screen.getByText("缺少条件上下文")).toBeTruthy();
    await user.type(screen.getByLabelText("来源 IP"), "::ffff:192.0.2.42");
    await user.click(screen.getByRole("button", { name: "运行模拟" }));
    expect(screen.getByText("显式拒绝", { exact: true })).toBeTruthy();
    expect(screen.getByText("v2 · 声明 1")).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Language" }));
    expect(screen.getByText("Explicit deny", { exact: true })).toBeTruthy();
    expect(document.body.textContent).not.toMatch(/\p{Script=Han}/u);
  });
  it("preserves every statement through visual/JSON edits, ordering and removal", async () => {
    const { user, repository } = await open("create-policy");
    await user.click(await screen.findByRole("tab", { name: "JSON 编辑" }));
    const statements = [
      { effect: "allow", action: ["logs:search", "logs:read"], resource: ["matrix:logs:org-xiak:*:topic/production/*"] },
      { effect: "deny", action: ["logs:delete"], resource: ["*"] }
    ];
    const editor = () => screen.getByLabelText("策略内容", { selector: "textarea" }) as HTMLTextAreaElement;
    await user.clear(editor()); await user.paste(JSON.stringify({ version: "1", statement: statements }));
    await user.click(screen.getByRole("tab", { name: "可视化编辑" }));
    for (const action of ["logs:search", "logs:read"]) expect((within(screen.getByRole("region", { name: "声明 1" })).getByRole("checkbox", { name: action }) as HTMLInputElement).checked).toBe(true);
    await user.click(screen.getByRole("button", { name: "上移声明 2" }));
    await user.click(screen.getByRole("tab", { name: "JSON 编辑" }));
    expect(JSON.parse(editor().value).statement).toEqual([statements[1], statements[0]]);
    await user.click(screen.getByRole("tab", { name: "可视化编辑" }));
    await user.click(screen.getByRole("button", { name: "删除声明 2" }));
    await user.click(screen.getByRole("tab", { name: "JSON 编辑" }));
    expect(JSON.parse(editor().value).statement).toEqual([statements[1]]);
    const unrepresentable = JSON.stringify({ version: "1", statement: [{ ...statements[0], resource: [" matrix:logs:org-xiak:*:topic/production/* "] }] });
    await user.clear(editor()); await user.paste(unrepresentable);
    expect(screen.getByRole("tab", { name: "可视化编辑" }).hasAttribute("disabled")).toBe(true);
    expect(editor().value).toBe(unrepresentable);
    expect(repository.workspace!.execute).not.toHaveBeenCalled();
  });
  it("confirms template replacement even after returning to an earlier step and discards only on confirmation", async () => {
    const { user, repository } = await open("create-policy");
    await logActions(user, ["logs:search"]);
    await user.click(screen.getByRole("button", { name: "下一步" }));
    await user.type(screen.getByLabelText("名称", { exact: true }), "TemplateDraft");
    await user.click(screen.getByRole("button", { name: "上一步" }));
    await select(user, "从已有策略开始", "MatrixReadOnlyAccess");
    await user.click(screen.getByRole("button", { name: "使用模板" }));
    expect(screen.getByRole("dialog", { name: "替换当前策略草稿？" })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "保留当前草稿" }));
    expect((screen.getByRole("checkbox", { name: "logs:search" }) as HTMLInputElement).checked).toBe(true);
    await user.click(screen.getByRole("button", { name: "使用模板" }));
    await user.click(screen.getByRole("button", { name: "替换声明" }));
    const templateActions = (screen.getByLabelText("操作", { exact: true }) as HTMLTextAreaElement).value.split("\n");
    expect(templateActions).toContain("logs:search");
    expect(templateActions).not.toContain("logs:delete");
    expect(templateActions).toContain("regions:readNode");
    await user.click(screen.getByRole("button", { name: "下一步" }));
    expect((screen.getByLabelText("名称", { exact: true }) as HTMLInputElement).value).toBe("TemplateDraft");
    await user.click(screen.getByRole("button", { name: "取消" }));
    expect(screen.getByRole("dialog", { name: "放弃策略编辑？" })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "继续编辑" }));
    await user.click(screen.getByRole("button", { name: "取消" }));
    await user.click(screen.getByRole("button", { name: "放弃并离开" }));
    expect(await screen.findByRole("button", { name: "新建自定义策略" })).toBeTruthy();
    expect(repository.workspace!.execute).not.toHaveBeenCalled();
  });
  it("retains metadata and cross-type selections through search, back and a failed save", async () => {
    const { user, repository, extension } = await open("create-policy");
    const before = (await extension.read("preview")).policies;
    await logActions(user, ["logs:search"]);
    await user.click(screen.getByRole("button", { name: "下一步" }));
    await user.type(screen.getByLabelText("名称", { exact: true }), "AtomicPolicy");
    await user.click(screen.getByRole("button", { name: "添加标签" }));
    await user.type(screen.getByLabelText("标签键 1"), "team");
    await user.type(screen.getByLabelText("标签值 1"), "platform");
    await user.click(screen.getByRole("checkbox", { name: "chen" }));
    await user.type(screen.getByRole("searchbox", { name: "搜索名称、ID 或关键字" }), "no-match");
    expect(screen.getByRole("button", { name: "移除 chen" })).toBeTruthy();
    await user.click(screen.getByRole("tab", { name: /^用户组/ }));
    await user.click(screen.getByRole("checkbox", { name: "DeliveryTeam" }));
    await user.click(screen.getByRole("tab", { name: /^角色/ }));
    await user.click(screen.getByRole("checkbox", { name: "PipelineDeploymentRole" }));
    await user.click(screen.getByRole("button", { name: "上一步" }));
    await user.click(screen.getByRole("button", { name: "下一步" }));
    expect((screen.getByLabelText("标签值 1") as HTMLInputElement).value).toBe("platform");
    expect(screen.getByRole("button", { name: "移除 PipelineDeploymentRole" })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "下一步" }));
    expect(repository.workspace!.execute).not.toHaveBeenCalled();
    vi.mocked(repository.workspace!.execute).mockRejectedValueOnce(new Error("network unavailable"));
    await user.click(screen.getByRole("button", { name: "创建策略" }));
    expect(await screen.findByText("暂时无法完成操作，请重试。")).toBeTruthy();
    expect((await extension.read("preview")).policies).toEqual(before);
    expect(screen.getByText("team : platform")).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "创建策略" }));
    await screen.findByRole("heading", { name: "策略已保存" });
    const state = await extension.read("preview");
    const saved = state.policies.find((policy) => policy.name === "AtomicPolicy")!;
    expect(saved.tags).toEqual([{ key: "team", value: "platform" }]);
    expect(state.userPolicies["principal-chen"]).toContain(saved.id);
    expect(state.groups.find((group) => group.id === "group-delivery")?.policyIds).toContain(saved.id);
    expect(state.roles.find((role) => role.id === "role-pipeline")?.policyIds).toContain(saved.id);
    expect(repository.execute).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "完成并返回策略列表" }));
    await user.click(await screen.findByRole("button", { name: "AtomicPolicy" }));
    expect(within(screen.getByRole("region", { name: "策略标签" })).getByText("team : platform")).toBeTruthy();
  });
  it("replaces only a nominated nondefault revision and keeps the review intact on failure", async () => {
    const { user, repository, extension } = await open("policies", { seed: async (extension) => {
      for (let version = 2; version <= 5; version++) await extension.execute("preview", {
        kind: "save-policy", id: "policy-prod-logs", name: "ProductionLogReader", description: "Preview",
        document: { version: "1", statement: [{ effect: "allow", action: ["logs:read"], resource: ["matrix:logs:org-xiak:*:topic/version-" + version] }] }
      });
    } });
    await user.click(await screen.findByRole("button", { name: "ProductionLogReader" }));
    await user.click(screen.getByRole("button", { name: "编辑" }));
    await user.click(screen.getByRole("checkbox", { name: "logs:read" }));
    await user.click(screen.getByRole("checkbox", { name: "logs:search" }));
    await user.click(screen.getByRole("button", { name: "下一步" }));
    await user.click(screen.getByRole("button", { name: "下一步" }));
    await user.click(screen.getByRole("button", { name: "保存策略" }));
    expect(screen.getByRole("combobox", { name: "替换哪个历史版本" }).getAttribute("aria-invalid")).toBe("true");
    expect(repository.workspace!.execute).not.toHaveBeenCalled();
    await user.click(screen.getByRole("combobox", { name: "替换哪个历史版本" }));
    expect(screen.queryByRole("option", { name: "v5" })).toBeNull();
    await user.click(screen.getByRole("option", { name: "v2" }));
    vi.mocked(repository.workspace!.execute).mockRejectedValueOnce(new Error("retry"));
    const before = await extension.read("preview");
    await user.click(screen.getByRole("button", { name: "保存策略" }));
    expect(await screen.findByText("暂时无法完成操作，请重试。")).toBeTruthy();
    expect(await extension.read("preview")).toEqual(before);
    expect(screen.getByRole("combobox", { name: "替换哪个历史版本" }).textContent).toContain("v2");
    await user.click(screen.getByRole("button", { name: "保存策略" }));
    await screen.findByRole("heading", { name: "策略已保存" });
    const saved = (await extension.read("preview")).policies.find((policy) => policy.id === "policy-prod-logs")!;
    expect(saved.versions.map((version) => version.id)).toEqual([1, 3, 4, 5, 6]);
    expect(saved.defaultVersion).toBe(6);
  });
  it("keeps unsupported policy restrictions in the draft and refuses to save", async () => {
    const { user, repository, extension } = await open("policies");
    const before = (await extension.read("preview")).policies;
    await user.click(await screen.findByRole("button", { name: "新建自定义策略" }));
    await user.click(within(screen.getByRole("dialog", { name: "选择创建策略方式" })).getByRole("button", { name: /^按策略语法创建/ }));
    await user.click(screen.getByRole("tab", { name: "JSON 编辑" }));
    const editor = screen.getByLabelText("策略内容", { selector: "textarea" });
    const text = '{"version":"1","statement":[{"effect":"allow","action":["logs:read"],"resource":["*"],"condition":{"ip":"192.0.2.0/24"}}]}';
    await user.clear(editor); await user.paste(text);
    await user.click(screen.getByRole("button", { name: "下一步" }));
    expect(screen.getByRole("alert").textContent).toContain("不会忽略这些限制");
    expect((editor as HTMLTextAreaElement).value).toBe(text);
    expect(screen.getByRole("tab", { name: "可视化编辑" }).hasAttribute("disabled")).toBe(true);
    await user.click(screen.getByRole("button", { name: "Language" }));
    expect(screen.getByRole("alert").textContent).not.toMatch(/\p{Script=Han}/u);
    expect((editor as HTMLTextAreaElement).value).toBe(text);
    expect(repository.workspace!.execute).not.toHaveBeenCalled();
    expect((await extension.read("preview")).policies).toEqual(before);
  });
  it("updates description without creating a version or changing policy grants", async () => {
    const { user, extension } = await open("policies");
    await user.click(await screen.findByRole("button", { name: "ProductionLogReader" }));
    expect(screen.getByRole("table", { name: "策略摘要" })).toBeTruthy();
    const before = (await extension.read("preview")).policies.find((policy) => policy.id === "policy-prod-logs")!;
    await user.click(screen.getByRole("button", { name: "编辑描述" }));
    const editor = screen.getByLabelText("描述");
    await user.clear(editor); await user.paste("Only an updated description");
    await user.click(within(screen.getByRole("dialog")).getByRole("button", { name: "保存" }));
    const saved = (await extension.read("preview")).policies.find((policy) => policy.id === before.id)!;
    expect(saved).toEqual({ ...before, description: "Only an updated description", updatedAt: expect.any(String) });
    expect(Date.parse(saved.updatedAt)).toBeGreaterThan(Date.parse(before.updatedAt));
  });
  it("copies a custom policy without copying its identity, history or associations", async () => {
    const { user, extension } = await open("policies");
    await user.click(await screen.findByRole("button", { name: "ProductionLogReader" }));
    const before = await extension.read("preview");
    const source = before.policies.find((policy) => policy.id === "policy-prod-logs")!;
    await user.click(screen.getByRole("button", { name: "复制为自定义策略" }));
    await user.click(screen.getByRole("button", { name: "下一步" }));
    const name = screen.getByLabelText("名称", { exact: true }) as HTMLInputElement;
    expect(name.readOnly).toBe(false);
    expect(name.value).toBe("ProductionLogReader-copy");
    await user.click(screen.getByRole("button", { name: "下一步" }));
    await user.click(screen.getByRole("button", { name: "创建策略" }));
    const after = await extension.read("preview");
    const copied = after.policies.find((policy) => policy.name === "ProductionLogReader-copy")!;
    expect(copied.id).not.toBe(source.id);
    expect(copied.kind).toBe("custom");
    expect(copied.versions.map((version) => version.id)).toEqual([1]);
    expect(copied.versions[0]!.document).toEqual(source.versions[0]!.document);
    expect(after.userPolicies).toEqual(before.userPolicies);
    expect(after.groups).toEqual(before.groups);
    expect(after.roles).toEqual(before.roles);
  });
  it("inspects history without activating it and reviews both documents before rollback", async () => {
    const { user, repository, extension } = await open("policies");
    await user.click(await screen.findByRole("button", { name: "ProductionLogReader" }));
    await user.click(screen.getByRole("button", { name: "编辑" }));
    await user.click(screen.getByRole("tab", { name: "JSON 编辑" }));
    const editor = screen.getByLabelText("策略内容", { selector: "textarea" });
    const text = '{"version":"1","statement":[{"effect":"allow","action":["logs:search"],"resource":["matrix:logs:org-xiak:*:topic/production/*"]},{"effect":"deny","action":["logs:delete"],"resource":["*"]}]}';
    await user.clear(editor); await user.paste(text);
    await user.click(screen.getByRole("button", { name: "下一步" }));
    expect((screen.getByLabelText("名称", { exact: true }) as HTMLInputElement).readOnly).toBe(true);
    await user.click(screen.getByRole("button", { name: "下一步" }));
    await user.click(screen.getByRole("button", { name: "保存策略" }));
    await user.click(await screen.findByRole("button", { name: "完成并查看策略" }));
    expect(screen.getByRole("button", { name: "查看日志服务的允许操作" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "查看日志服务的拒绝操作" })).toBeTruthy();
    await user.click(screen.getByRole("tab", { name: "策略版本" }));
    await user.click(screen.getByRole("button", { name: "查看版本 v1" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(screen.getByRole("heading", { name: "查看版本 v1" })).toBeTruthy();
    expect(screen.getByText(/只读查看/)).toBeTruthy();
    expect((await extension.read("preview")).policies.find((policy) => policy.id === "policy-prod-logs")?.defaultVersion).toBe(2);
    await user.click(screen.getByRole("button", { name: "返回策略版本" }));
    expect(document.activeElement).toBe(screen.getByRole("button", { name: "查看版本 v1" }));
    await user.click(screen.getByRole("button", { name: "版本 v1 的更多操作" }));
    await user.click(screen.getByRole("menuitem", { name: "将 v1 设为默认版本" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(screen.getByRole("region", { name: "策略内容变更" })).toBeTruthy();
    expect(screen.getByRole("region", { name: "受影响对象" }).textContent).toContain("lin");
    await user.click(screen.getByText("展开完整 JSON 对比"));
    expect(screen.getByRole("region", { name: "当前生效 · v2" }).textContent).toContain("deny");
    expect(screen.getByRole("region", { name: "切换后生效 · v1" }).textContent).not.toContain("deny");
    await user.click(screen.getByRole("button", { name: "取消" }));
    expect((await extension.read("preview")).policies.find((policy) => policy.id === "policy-prod-logs")?.defaultVersion).toBe(2);
    expect(document.activeElement).toBe(screen.getByRole("button", { name: "版本 v1 的更多操作" }));
    await user.click(screen.getByRole("button", { name: "版本 v1 的更多操作" }));
    await user.click(screen.getByRole("menuitem", { name: "将 v1 设为默认版本" }));
    vi.mocked(repository.workspace!.execute).mockRejectedValueOnce(new Error("retry"));
    await user.click(screen.getByRole("button", { name: "设为默认版本" }));
    expect(await screen.findByText("暂时无法完成操作，请重试。")).toBeTruthy();
    expect(screen.getByRole("heading", { name: "将 v1 设为默认版本" })).toBeTruthy();
    expect(screen.queryByRole("dialog")).toBeNull();
    await user.click(screen.getByRole("button", { name: "设为默认版本" }));
    await waitFor(() => expect(screen.queryByRole("heading", { name: "将 v1 设为默认版本" })).toBeNull());
    expect(screen.queryByRole("button", { name: "版本 v1 的更多操作" })).toBeNull();
    expect(document.activeElement).toBe(screen.getByRole("group", { name: "策略版本" }));
    await user.click(screen.getByRole("button", { name: "版本 v2 的更多操作" }));
    await user.click(screen.getByRole("menuitem", { name: "删除版本 v2" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    await user.click(screen.getByRole("button", { name: "确认删除" }));
    await waitFor(() => expect(screen.queryByRole("heading", { name: "删除版本 v2" })).toBeNull());
    const state = await extension.read("preview");
    expect(state.policies.find((policy) => policy.id === "policy-prod-logs")?.versions.map((version) => version.id)).toEqual([1]);
    expect(document.activeElement).toBe(screen.getByRole("group", { name: "策略版本" }));
    expect(state.userPolicies["principal-lin"]).toContain("policy-prod-logs");
  });
  it("shows a mock secret once in the content area, then removes it after acknowledgement", async () => {
    const { user, extension } = await open("keys");
    await user.click(await screen.findByRole("button", { name: "管理 chen 的访问密钥" }));
    await user.click(screen.getByRole("button", { name: "新建访问密钥" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(await screen.findByRole("heading", { name: "核对并创建访问密钥" })).toBe(document.activeElement);
    await user.click(screen.getByRole("button", { name: "新建访问密钥" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    const secret = (await screen.findByText(/^MOCK_NOT_A_CREDENTIAL_/)).textContent!;
    expect(JSON.stringify(await extension.read("preview"))).not.toContain(secret);
    await user.click(screen.getByRole("checkbox"));
    await user.click(screen.getByRole("button", { name: "已完成" }));
    expect(screen.queryByText(secret)).toBeNull();
    expect(screen.getByRole("table", { name: "访问密钥" })).toBeTruthy();
    expect(JSON.stringify(localStorage) + JSON.stringify(sessionStorage)).not.toContain(secret);
  });
  it.each(["SAML", "OIDC"] as const)("validates and retries %s provider drafts without external discovery, then edits and deletes only the created provider", async (protocol) => {
    const { user, repository, extension } = await open("providers");
    const before = await extension.read("preview");
    await user.click(screen.getByRole("button", { name: "新建身份提供商" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    const editor = screen.getByRole("group", { name: "新建身份提供商" });
    expect(within(editor).getByRole("heading", { name: "新建身份提供商" })).toBe(document.activeElement);
    await user.type(within(editor).getByLabelText("名称", { exact: true }), "PreviewIdp");
    await user.click(within(editor).getByRole("combobox", { name: "协议" }));
    await user.click(screen.getByRole("option", { name: protocol }));
    await user.type(within(editor).getByLabelText("身份提供商 URL"), "https://identity.example.invalid/test");
    await user.type(within(editor).getByLabelText("客户端 ID / Audience"), "matrix-preview");
    fireEvent.change(within(editor).getByLabelText("联合元数据 / 签名公钥"), { target: { value: "invalid-document" } });
    await user.click(within(editor).getByRole("button", { name: "保存" }));
    await waitFor(() => expect(within(editor).getByRole("alert").textContent).toContain("输入格式"));
    expect(await extension.read("preview")).toEqual(before);
    const metadata = protocol === "SAML" ? '<EntityDescriptor entityID="https://identity.example.invalid/test"></EntityDescriptor>' : '{"keys":[{"kty":"RSA","kid":"MOCK"}]}';
    fireEvent.change(within(editor).getByLabelText("联合元数据 / 签名公钥"), { target: { value: metadata } });
    vi.mocked(repository.workspace!.execute).mockRejectedValueOnce(new Error("offline"));
    await user.click(within(editor).getByRole("button", { name: "保存" }));
    await expectRetainedFailure(editor);
    expect((within(editor).getByLabelText("联合元数据 / 签名公钥") as HTMLTextAreaElement).value).toBe(metadata);
    await user.click(within(editor).getByRole("button", { name: "保存" }));
    await waitFor(() => expect(screen.queryByRole("group", { name: "新建身份提供商" })).toBeNull());
    expect(document.activeElement).toBe(screen.getByRole("button", { name: "新建身份提供商" }));
    const created = (await extension.read("preview")).providers.find((provider) => provider.name === "PreviewIdp")!;
    expect(created.protocol).toBe(protocol);
    await user.click(screen.getByRole("button", { name: "PreviewIdp" }));
    expect(screen.getByRole("region", { name: "联合元数据 / 签名公钥" }).textContent).toBe(metadata);
    await user.click(screen.getByRole("button", { name: "编辑" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    const edit = screen.getByRole("group", { name: "编辑 · PreviewIdp" });
    await user.click(within(edit).getByRole("checkbox", { name: "启用" }));
    await user.click(within(edit).getByRole("button", { name: "保存" }));
    await waitFor(() => expect(screen.queryByRole("group", { name: "编辑 · PreviewIdp" })).toBeNull());
    expect(document.activeElement).toBe(screen.getByRole("button", { name: "编辑" }));
    expect((await extension.read("preview")).providers.find((provider) => provider.id === created.id)?.enabled).toBe(false);
    await user.click(screen.getByRole("button", { name: "删除" }));
    await user.type(screen.getByLabelText("输入名称以确认"), "PreviewIdp");
    await user.click(within(screen.getByRole("dialog")).getByRole("button", { name: "确认删除" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    const after = await extension.read("preview");
    expect(after.providers).toEqual(before.providers);
    expect(after.roles).toEqual(before.roles);
    expect(after.settings).toEqual(before.settings);
    expect(repository.execute).not.toHaveBeenCalled();
  });
  it("creates and edits a federated identity in the content area without opening a modal", async () => {
    const { user, repository, extension } = await open("providers");
    await user.click(screen.getByRole("tab", { name: "联合身份映射" }));
    await user.click(screen.getByRole("button", { name: "新建联合身份映射" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    const editor = screen.getByRole("group", { name: "新建联合身份映射" });
    expect(within(editor).getByRole("heading", { name: "新建联合身份映射" })).toBe(document.activeElement);
    await user.type(within(editor).getByLabelText("名称", { exact: true }), "PreviewFederation");
    await user.type(within(editor).getByLabelText("外部账号标识"), "preview@example.invalid");
    await select(user, "身份提供商", "EnterpriseSSO");
    await select(user, "映射角色", "FederatedAuditRole");
    await user.click(within(editor).getByRole("button", { name: "保存" }));
    await waitFor(() => expect(screen.queryByRole("group", { name: "新建联合身份映射" })).toBeNull());
    expect(document.activeElement).toBe(screen.getByRole("button", { name: "新建联合身份映射" }));
    const created = (await extension.read("preview")).federations.find((entry) => entry.name === "PreviewFederation")!;
    expect(created.providerId).toBe("idp-example");
    expect(created.roleId).toBe("role-audit");
    await user.click(screen.getByRole("button", { name: "PreviewFederation" }));
    await user.click(screen.getByRole("button", { name: "编辑" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    const edit = screen.getByRole("group", { name: "编辑 · PreviewFederation" });
    await user.click(within(edit).getByRole("checkbox", { name: "启用" }));
    await user.click(within(edit).getByRole("button", { name: "保存" }));
    await waitFor(() => expect(screen.queryByRole("group", { name: "编辑 · PreviewFederation" })).toBeNull());
    expect((await extension.read("preview")).federations.find((entry) => entry.id === created.id)?.enabled).toBe(false);
    expect(document.activeElement).toBe(screen.getByRole("button", { name: "编辑" }));
    expect(repository.execute).not.toHaveBeenCalled();
  });
  it("retains key-state failures, requires disable before deletion, and keeps cancellation non-mutating", async () => {
    const { user, repository, extension } = await open("keys");
    const before = await extension.read("preview");
    await user.click(await screen.findByRole("button", { name: "管理 lin 的访问密钥" }));
    const directory = await screen.findByRole("table", { name: "访问密钥" });
    expect(within(directory).queryByRole("columnheader", { name: "操作" })).toBeNull();
    expect(within(directory).queryByRole("button", { name: "禁用" })).toBeNull();
    expect(within(directory).queryByRole("button", { name: "删除" })).toBeNull();
    await user.click(within(directory).getByRole("button", { name: "MOCK-pipeline-key" }));
    expect((screen.getByRole("button", { name: "删除" }) as HTMLButtonElement).disabled).toBe(true);
    await user.click(screen.getByRole("button", { name: "禁用" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    await user.click(screen.getByRole("button", { name: "取消" }));
    expect(await extension.read("preview")).toEqual(before);
    await user.click(screen.getByRole("button", { name: "禁用" }));
    vi.mocked(repository.workspace!.execute).mockRejectedValueOnce(new Error("offline"));
    await user.click(screen.getByRole("button", { name: "禁用" }));
    expect(await screen.findByText("暂时无法完成操作，请重试。")).toBeTruthy();
    expect(screen.getByRole("heading", { name: "禁用 MOCK-pipeline-key" })).toBeTruthy();
    expect(await extension.read("preview")).toEqual(before);
    await user.click(screen.getByRole("button", { name: "禁用" }));
    await waitFor(() => expect(screen.queryByRole("heading", { name: "禁用 MOCK-pipeline-key" })).toBeNull());
    await user.click(screen.getByRole("button", { name: "删除" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    await user.click(screen.getByRole("checkbox"));
    await user.click(screen.getByRole("button", { name: "确认删除" }));
    await waitFor(() => expect(screen.queryByRole("heading", { name: "删除 MOCK-pipeline-key" })).toBeNull());
    expect((await extension.read("preview")).keys).toEqual([]);
    expect(screen.getByText("尚未创建访问密钥")).toBeTruthy();
    expect(repository.execute).not.toHaveBeenCalled();
  });
  it("locks an uncertain access-key creation to its original request and never reveals the lost secret", async () => {
    const { user, extension } = await open("keys");
    await user.click(await screen.findByRole("button", { name: "管理 chen 的访问密钥" }));
    await user.click(screen.getByRole("button", { name: "新建访问密钥" }));
    await select(user, "MOCK 返回场景", "提交已生效，但响应丢失");
    await user.click(screen.getByRole("button", { name: "新建访问密钥" }));
    expect(await screen.findByText("UNKNOWN")).toBeTruthy();
    expect(screen.queryByText(/^MOCK_NOT_A_CREDENTIAL_/)).toBeNull();
    expect((await extension.read("preview")).pendingKeyCreation).not.toHaveProperty("keyId");
    expect(screen.queryByRole("button", { name: "新建访问密钥" })).toBeNull();
    await user.click(screen.getByTestId("go-users"));
    await user.click(screen.getByTestId("go-keys"));
    expect(await screen.findByText("UNKNOWN")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "返回列表" })).toBeNull();
    await select(user, "原请求查询结果", "暂未找到（保持未知）");
    await user.click(screen.getByRole("button", { name: "按原 requestId 查询" }));
    expect(await screen.findByText(/原 requestId 暂未查询到确定结果/)).toBeTruthy();
    expect((await extension.read("preview")).pendingKeyCreation?.status).toBe("UNKNOWN");
    await select(user, "原请求查询结果", "查询暂不可用（保持未知）");
    await user.click(screen.getByRole("button", { name: "按原 requestId 查询" }));
    expect(await screen.findByText(/暂时无法查询原 requestId/)).toBeTruthy();
    expect((await extension.read("preview")).pendingKeyCreation?.status).toBe("UNKNOWN");
    await select(user, "原请求查询结果", "已找到原创建结果");
    await user.click(screen.getByRole("button", { name: "按原 requestId 查询" }));
    expect(screen.getByText("不可恢复 · 不可重显")).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "查看并处置这把密钥" }));
    expect(screen.getByText(/没有可靠的最后使用时间或访问日志/)).toBeTruthy();
    expect((await extension.read("preview")).keys.filter((key) => key.ownerId === "principal-chen")).toHaveLength(1);
    await user.click(screen.getByRole("button", { name: "禁用" }));
    await user.click(screen.getByRole("button", { name: "禁用" }));
    await user.click(screen.getByRole("button", { name: "删除" }));
    await user.click(screen.getByRole("checkbox"));
    await user.click(screen.getByRole("button", { name: "确认删除" }));
    await waitFor(() => expect(screen.queryByRole("heading", { name: /删除 MOCK-/ })).toBeNull());
    expect((await extension.read("preview")).pendingKeyCreation).toBeNull();
  });
  it("models personal MFA, scoped step-up and the frozen account requirement without invented settings", async () => {
    const { user, extension } = await open("settings");
    expect(screen.getByRole("heading", { name: "身份验证方法" })).toBeTruthy();
    expect(screen.getByRole("heading", { name: "多因素认证要求" })).toBeTruthy();
    expect(screen.getByRole("heading", { name: "登录时的 MFA 要求" })).toBeTruthy();
    expect(screen.getByText("当前规则")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "编辑模拟规则" })).toBeNull();
    expect(screen.getByText(/操作者本人必须先绑定验证器/)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "查看本人身份验证方法" }));
    expect(screen.getByRole("heading", { name: "身份验证方法" })).toBe(document.activeElement);
    expect(screen.queryByRole("checkbox", { name: "要求日常 IAM 用户在登录时完成 MFA" })).toBeNull();
    expect(screen.queryByLabelText("密码最小长度")).toBeNull();
    expect(screen.queryByLabelText("会话时长（分钟）")).toBeNull();
    expect(screen.getByRole("heading", { name: "安全通知" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "验证第一条地址" })).toBeTruthy();

    expect((screen.getByRole("button", { name: "绑定验证器" }) as HTMLButtonElement).disabled).toBe(true);
    await user.click(screen.getByRole("button", { name: "验证第一条地址" }));
    await user.type(screen.getByLabelText("安全通知邮箱"), "mfa.owner@example.com");
    await user.type(screen.getByLabelText("当前密码"), "demo-password");
    await user.click(screen.getByRole("button", { name: "创建验证意图" }));
    await user.type(screen.getByLabelText("8 位邮箱验证码"), "48392017");
    await user.click(screen.getByRole("button", { name: "确认地址" }));
    const bind = screen.getByRole("button", { name: "绑定验证器" }) as HTMLButtonElement;
    expect(bind.disabled).toBe(false);
    await user.click(bind);
    expect(screen.getByRole("heading", { name: "验证身份后绑定验证器" })).toBeTruthy();
    expect(screen.getByText(/不增加任何 IAM 权限/)).toBeTruthy();
    expect(screen.queryByLabelText("6 位动态验证码")).toBeNull();
    await user.type(screen.getByLabelText("当前密码"), "demo-password");
    await user.click(screen.getByRole("button", { name: "验证并继续" }));
    expect(screen.getByRole("heading", { name: "设置身份验证器" })).toBeTruthy();
    expect(screen.getByText(/必须先完成强制改密/)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "继续" }));
    await user.click(screen.getByRole("button", { name: "已添加，下一步" }));
    await user.type(screen.getByLabelText("6 位动态验证码"), "624810");
    await user.click(screen.getByRole("button", { name: "验证并绑定" }));
    expect((await extension.read("preview")).personalMfa).toEqual({ factorState: "bound", reauthenticationRequired: true, recoveryState: "idle" });
    const firstCode = extension.recoveryCodes()[0]!;
    const oneTimeCodes = screen.getByText(firstCode).closest("article")!;
    expect(oneTimeCodes).toBeTruthy();
    expect(extension.recoveryCodes()).toHaveLength(10);
    expect(within(oneTimeCodes).queryByRole("button", { name: "取消" })).toBeNull();
    await user.click(screen.getByRole("checkbox", { name: "我已安全保存这些恢复码" }));
    await user.click(screen.getByRole("button", { name: "完成设置" }));
    expect(screen.getByRole("button", { name: "Enter" })).toBeTruthy();
    expect((await extension.read("preview")).personalMfa).toEqual({ factorState: "bound", reauthenticationRequired: true, recoveryState: "idle" });
  });
  it("keeps authenticator replacement inline and reveals rotated recovery codes only after confirmation", async () => {
    const { user, extension } = await open("settings", { seed: seedBoundAccountRuleOperator });
    const oldCodes = extension.recoveryCodes();
    await user.click(screen.getByRole("button", { name: "替换验证器" }));
    expect(screen.getByRole("heading", { name: "验证身份后替换验证器" })).toBeTruthy();
    await user.type(screen.getByLabelText("当前密码"), "demo-password");
    await user.type(screen.getByLabelText("6 位动态验证码"), "624810");
    await user.click(screen.getByRole("button", { name: "验证并继续" }));
    expect(await screen.findByRole("heading", { name: "替换身份验证器" })).toBeTruthy();
    expect((await extension.read("preview")).personalMfa).toMatchObject({ factorState: "bound", reauthenticationRequired: false, pendingReplacement: { accountRuleVersion: 1 } });
    expect(extension.recoveryCodes()).toEqual(oldCodes);
    await user.click(screen.getByRole("button", { name: "继续" }));
    await user.click(screen.getByRole("button", { name: "已添加，下一步" }));
    await user.type(screen.getByLabelText("6 位动态验证码"), "731942");
    await user.click(screen.getByRole("button", { name: "验证并绑定" }));
    const rotated = extension.recoveryCodes();
    expect(rotated).toHaveLength(10);
    expect(rotated.some((code) => oldCodes.includes(code))).toBe(false);
    expect(screen.getByText(rotated[0]!)).toBeTruthy();
    expect((await extension.read("preview")).personalMfa).toEqual({ factorState: "bound", reauthenticationRequired: true, recoveryState: "idle", demoCode: "731942" });
    await user.click(screen.getByRole("checkbox", { name: "我已安全保存这些恢复码" }));
    await user.click(screen.getByRole("button", { name: "完成设置" }));
    expect(screen.queryByText(rotated[0]!)).toBeNull();
    expect(screen.getByRole("button", { name: "Enter" })).toBeTruthy();
  });
  it("stops an uncertain replacement confirmation without repeating the write or re-showing setup material", async () => {
    const { user, repository, extension } = await open("settings", { seed: seedBoundAccountRuleOperator });
    const previousCodes = extension.recoveryCodes();
    const execute = vi.mocked(repository.workspace!.execute);
    const original = execute.getMockImplementation()!;
    execute.mockImplementation((credential, command) => command.kind === "confirm-personal-mfa-replacement"
      ? Promise.reject(new HttpProblem(503, "IAM_UNAVAILABLE"))
      : original(credential, command));
    await user.click(screen.getByRole("button", { name: "替换验证器" }));
    await user.type(screen.getByLabelText("当前密码"), "demo-password");
    await user.type(screen.getByLabelText("6 位动态验证码"), "624810");
    await user.click(screen.getByRole("button", { name: "验证并继续" }));
    await screen.findByRole("heading", { name: "替换身份验证器" });
    await user.click(screen.getByRole("button", { name: "继续" }));
    await user.click(screen.getByRole("button", { name: "已添加，下一步" }));
    await user.type(screen.getByLabelText("6 位动态验证码"), "731942");
    await user.click(screen.getByRole("button", { name: "验证并绑定" }));
    expect(await screen.findByRole("heading", { name: "本次替换已停止" })).toBeTruthy();
    expect(screen.getByText(/确认结果尚不能确定/)).toBeTruthy();
    expect(screen.queryByText("MTRX-DEMO-NOT-A-SECRET")).toBeNull();
    expect(screen.queryByRole("button", { name: "验证并绑定" })).toBeNull();
    expect(execute.mock.calls.filter(([, command]) => command.kind === "confirm-personal-mfa-replacement")).toHaveLength(1);
    await user.click(screen.getByRole("button", { name: "返回安全设置" }));
    expect(screen.getByRole("heading", { name: "验证器替换尚未确认" })).toBeTruthy();
    expect(extension.recoveryCodes()).toEqual(previousCodes);
  });
  it("hides replacement secrets while confirmation is in flight and goes directly to one-time codes", async () => {
    const { user, repository, extension } = await open("settings", { seed: seedBoundAccountRuleOperator });
    const execute = vi.mocked(repository.workspace!.execute);
    const original = execute.getMockImplementation()!;
    let release!: () => void;
    const gate = new Promise<void>((done) => { release = done; });
    execute.mockImplementation((credential, command) => command.kind === "confirm-personal-mfa-replacement"
      ? gate.then(() => original(credential, command))
      : original(credential, command));
    await user.click(screen.getByRole("button", { name: "替换验证器" }));
    await user.type(screen.getByLabelText("当前密码"), "demo-password");
    await user.type(screen.getByLabelText("6 位动态验证码"), "624810");
    await user.click(screen.getByRole("button", { name: "验证并继续" }));
    await screen.findByRole("heading", { name: "替换身份验证器" });
    await user.click(screen.getByRole("button", { name: "继续" }));
    await user.click(screen.getByRole("button", { name: "已添加，下一步" }));
    await user.type(screen.getByLabelText("6 位动态验证码"), "731942");
    await user.click(screen.getByRole("button", { name: "验证并绑定" }));
    expect(screen.getByRole("heading", { name: "正在核对替换结果" })).toBeTruthy();
    expect(screen.queryByText("MTRX-DEMO-NOT-A-SECRET")).toBeNull();
    expect(screen.queryByRole("button", { name: "验证并绑定" })).toBeNull();
    await act(async () => release());
    expect(screen.queryByRole("heading", { name: "本次替换已停止" })).toBeNull();
    expect(await screen.findByText(extension.recoveryCodes()[0]!)).toBeTruthy();
  });
  it("removes replacement setup material when the account rule changes before confirmation", async () => {
    const { user, extension } = await open("settings", { seed: seedBoundAccountRuleOperator });
    await user.click(screen.getByRole("button", { name: "替换验证器" }));
    await user.type(screen.getByLabelText("当前密码"), "demo-password");
    await user.type(screen.getByLabelText("6 位动态验证码"), "624810");
    await user.click(screen.getByRole("button", { name: "验证并继续" }));
    await screen.findByRole("heading", { name: "替换身份验证器" });
    await user.click(screen.getByRole("button", { name: "继续" }));
    expect(screen.getByText("MTRX-DEMO-NOT-A-SECRET")).toBeTruthy();
    extension.transact((source) => ({ workspace: { ...source, settings: { ...source.settings, accountRuleVersion: source.settings.accountRuleVersion + 1 } } }));
    await user.click(screen.getByTestId("refresh-account"));
    expect(await screen.findByRole("heading", { name: "本次替换已停止" })).toBeTruthy();
    expect(screen.getByText(/验证期限或账号规则已变化/)).toBeTruthy();
    expect(screen.queryByText("MTRX-DEMO-NOT-A-SECRET")).toBeNull();
    expect(screen.queryByRole("button", { name: "验证并绑定" })).toBeNull();
  });
  it("closes the replacement setup view after its absolute proof deadline", async () => {
    const { user, extension } = await open("settings", { seed: seedBoundAccountRuleOperator });
    await user.click(screen.getByRole("button", { name: "替换验证器" }));
    await user.type(screen.getByLabelText("当前密码"), "demo-password");
    await user.type(screen.getByLabelText("6 位动态验证码"), "624810");
    await user.click(screen.getByRole("button", { name: "验证并继续" }));
    await screen.findByRole("heading", { name: "替换身份验证器" });
    await user.click(screen.getByRole("button", { name: "继续" }));
    expect(screen.getByText("MTRX-DEMO-NOT-A-SECRET")).toBeTruthy();
    extension.transact((source) => ({ workspace: { ...source, personalMfa: { ...source.personalMfa, pendingReplacement: { ...source.personalMfa.pendingReplacement!, expiresAt: new Date(Date.now() - 1).toISOString() } } } }));
    await user.click(screen.getByTestId("refresh-account"));
    expect(await screen.findByRole("heading", { name: "本次替换已停止" })).toBeTruthy();
    expect(screen.queryByText("MTRX-DEMO-NOT-A-SECRET")).toBeNull();
    expect((await extension.read("preview")).personalMfa.pendingReplacement).toBeTruthy();
  });
  it("does not reissue replacement setup material after leaving the page and permits cancellation", async () => {
    const { user, extension } = await open("settings", { seed: seedBoundAccountRuleOperator });
    await user.click(screen.getByRole("button", { name: "替换验证器" }));
    await user.type(screen.getByLabelText("当前密码"), "demo-password");
    await user.type(screen.getByLabelText("6 位动态验证码"), "624810");
    await user.click(screen.getByRole("button", { name: "验证并继续" }));
    await screen.findByRole("heading", { name: "替换身份验证器" });
    await user.click(screen.getByTestId("go-users"));
    await user.click(screen.getByTestId("go-settings"));
    expect(await screen.findByRole("heading", { name: "验证器替换尚未确认" })).toBeTruthy();
    expect(screen.queryByText("MTRX-DEMO-NOT-A-SECRET")).toBeNull();
    expect((screen.getByRole("button", { name: "替换验证器" }) as HTMLButtonElement).disabled).toBe(true);
    await user.click(screen.getByRole("button", { name: "取消本次替换" }));
    await waitFor(() => expect((screen.getByRole("button", { name: "替换验证器" }) as HTMLButtonElement).disabled).toBe(false));
    expect((await extension.read("preview")).personalMfa).toEqual({ factorState: "bound", reauthenticationRequired: false, recoveryState: "idle" });
  });
  it("shows the same regenerated MOCK recovery batch that the repository accepts", async () => {
    const { user, extension } = await open("settings", { seed: seedBoundAccountRuleOperator });
    const previous = extension.recoveryCodes();
    await user.click(screen.getByRole("button", { name: "生成新恢复码" }));
    await user.type(screen.getByLabelText("当前密码"), "demo-password");
    await user.type(screen.getByLabelText("6 位动态验证码"), "624810");
    await user.click(screen.getByRole("button", { name: "验证并继续" }));
    expect(await screen.findByRole("heading", { name: "保存新的恢复码" })).toBeTruthy();
    expect(extension.recoveryCodes()).toHaveLength(10);
    expect(extension.recoveryCodes().some((code) => previous.includes(code))).toBe(false);
    expect(screen.getByText(extension.recoveryCodes()[0]!)).toBeTruthy();
  });
  it("keeps account-rule editing closed until a newly bound operator signs in again", async () => {
    const { extension } = await open("settings", { seed: async (workspace) => { await workspace.execute("preview", { kind: "confirm-personal-mfa" }); } });
    expect(screen.getByText(/通过正常登录重新验证后再修改账号规则/)).toBeTruthy();
    expect((screen.getByRole("button", { name: "编辑模拟规则" }) as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByRole("button", { name: "重新登录以继续" })).toBeTruthy();
    expect(await extension.read("preview")).toMatchObject({ personalMfa: { factorState: "bound", reauthenticationRequired: true } });
  });
  it("blocks workspace and group management while the old session requires reauthentication", async () => {
    const createGroup = vi.fn().mockRejectedValue(new Error("must not be called"));
    const { user, repository } = await open("overview", {
      repository: { createGroup },
      seed: async (extension) => { extension.transact((source) => ({ workspace: { ...source, personalMfa: { factorState: "bound", reauthenticationRequired: true, recoveryState: "idle" } } })); }
    });
    await user.click(screen.getByTestId("guard-workspace"));
    await user.click(screen.getByTestId("guard-group"));
    expect(repository.workspace!.execute).not.toHaveBeenCalled();
    expect(createGroup).not.toHaveBeenCalled();
    expect(await screen.findByText(/当前会话不能继续执行受保护操作/)).toBeTruthy();
  });
  it("keeps first security-notification address verification personal, inline, and explicitly MOCK", async () => {
    const { user, repository } = await open("settings");
    const trigger = screen.getByRole("button", { name: "验证第一条地址" });
    await user.click(trigger);
    const flowTitle = screen.getByRole("heading", { name: "验证第一条安全通知地址" });
    await waitFor(() => expect(flowTitle).toBe(document.activeElement));
    await user.click(within(flowTitle.closest("article")!).getByRole("button", { name: "取消" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "验证第一条地址" })).toBe(document.activeElement));

    await user.click(screen.getByRole("button", { name: "验证第一条地址" }));
    await user.type(screen.getByLabelText("安全通知邮箱"), "preview.security@example.com");
    await user.type(screen.getByLabelText("当前密码"), "demo-password");
    await user.click(screen.getByRole("button", { name: "创建验证意图" }));
    const verifyTitle = screen.getByRole("heading", { name: "确认安全通知地址" });
    await waitFor(() => expect(verifyTitle).toBe(document.activeElement));
    expect(screen.getByText("PENDING · 等待验证码")).toBeTruthy();
    expect(screen.getByText("等待投递器处理")).toBeTruthy();
    expect(screen.getByText(/没有渠道受理、最终送达或已读证据/)).toBeTruthy();
    expect(screen.queryByText("渠道已受理")).toBeNull();
    expect(screen.queryByText("已送达")).toBeNull();

    await user.type(screen.getByLabelText("8 位邮箱验证码"), "00000000");
    await user.click(screen.getByRole("button", { name: "确认地址" }));
    expect(screen.getByText("验证码无效、已使用或已过期。地址仍未验证。")).toBeTruthy();
    await user.clear(screen.getByLabelText("8 位邮箱验证码"));
    await user.type(screen.getByLabelText("8 位邮箱验证码"), "48392017");
    await user.click(screen.getByRole("button", { name: "确认地址" }));

    const notification = screen.getByRole("region", { name: "安全通知" });
    await waitFor(() => expect(within(notification).getByRole("heading", { name: "安全通知" })).toBe(document.activeElement));
    expect(within(notification).getByText("preview.security@example.com")).toBeTruthy();
    expect(within(notification).queryByText("PENDING · 等待验证码")).toBeNull();
    expect(within(notification).getAllByText("已验证").length).toBeGreaterThan(0);
    expect(within(notification).getByText(/不提供弱化旁路/)).toBeTruthy();
    expect(within(notification).queryByRole("button")).toBeNull();
    expect(repository.execute).not.toHaveBeenCalled();
  });
  it("retains user SSO inputs on failure and saves only its owned settings on retry", async () => {
    const { user, repository, extension } = await open("user-sso", { seed: async (preview) => {
      preview.transact((source) => ({ workspace: { ...source, providers: [], federations: [], roles: source.roles.filter((role) => role.principalType !== "provider") } }));
    } });
    const before = await extension.read("preview");
    expect(screen.getByText("尚未配置。无需先创建角色 SSO 身份提供商。")).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "去配置" }));
    await user.type(screen.getByLabelText("企业 IdP 的 SAML 元数据 XML"), '<EntityDescriptor entityID="user-sso"></EntityDescriptor>');
    await user.click(screen.getByRole("checkbox", { name: "启用用户 SSO（模拟）" }));
    await user.click(screen.getByRole("button", { name: "审阅配置" }));
    expect(screen.getByText(/原密码登录可能被关闭/)).toBeTruthy();
    vi.mocked(repository.workspace!.execute).mockRejectedValueOnce(new Error("offline"));
    await user.click(screen.getByRole("button", { name: "保存" }));
    await screen.findByText("暂时无法完成操作，请重试。");
    expect(await extension.read("preview")).toEqual(before);
    await user.click(screen.getByRole("button", { name: "保存" }));
    await screen.findByText("由 SAML 元数据声明");
    const state = await extension.read("preview");
    expect(state.settings).toEqual({ ...before.settings, userSsoEnabled: true, userSsoConfiguration: { protocol: "SAML", metadata: '<EntityDescriptor entityID="user-sso"></EntityDescriptor>', mappingClaim: "NameID" } });
    expect(state.providers).toEqual(before.providers);
    expect(state.userPolicies).toEqual(before.userPolicies);
    expect(repository.execute).not.toHaveBeenCalled();
  });
  it("shows the reviewed rule version and requires a new login after an applied account-rule change", async () => {
    const { user, extension, repository } = await open("settings", { seed: seedBoundAccountRuleOperator });
    await user.click(screen.getByRole("button", { name: "编辑模拟规则" }));
    await user.click(screen.getByRole("checkbox", { name: "要求日常 IAM 用户在登录时完成 MFA" }));
    await user.click(screen.getByRole("button", { name: "审阅规则变更" }));
    expect(screen.getByRole("heading", { name: "审阅账号安全规则变更" })).toBeTruthy();
    expect(screen.getByText("规则版本").nextElementSibling?.textContent).toBe("1");
    await user.click(screen.getByRole("button", { name: "继续验证身份" }));
    await user.type(screen.getByLabelText("当前密码"), "demo-password");
    await user.type(screen.getByLabelText("6 位动态验证码"), "624810");
    await user.click(screen.getByRole("button", { name: "验证并继续" }));
    await waitFor(async () => expect((await extension.read("preview")).settings.accountRuleVersion).toBe(2));
    expect((await extension.read("preview")).personalMfa.reauthenticationRequired).toBe(true);
    expect((screen.getByRole("button", { name: "编辑模拟规则" }) as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByText(/身份验证方法或账号规则的变更已生效/)).toBeTruthy();
    expect(repository.execute).not.toHaveBeenCalled();
  });
  it("locks an unknown account-rule save, discards secrets and recovers only through the original intent", async () => {
    const { user, extension } = await open("settings", { seed: seedBoundAccountRuleOperator });
    await user.click(screen.getByRole("button", { name: "编辑模拟规则" }));
    await user.click(screen.getByRole("checkbox", { name: "要求日常 IAM 用户在登录时完成 MFA" }));
    await user.click(screen.getByRole("button", { name: "审阅规则变更" }));
    await select(user, "MOCK 保存结果", "提交后响应丢失（结果未知）");
    await user.click(screen.getByRole("button", { name: "继续验证身份" }));
    await user.type(screen.getByLabelText("当前密码"), "demo-password");
    await user.type(screen.getByLabelText("6 位动态验证码"), "624810");
    await user.click(screen.getByRole("button", { name: "验证并继续" }));

    const unknown = await screen.findByRole("heading", { name: "账号规则的保存结果未知" });
    await waitFor(() => expect(unknown).toBe(document.activeElement));
    expect(screen.queryByText("操作已完成。")).toBeNull();
    expect(screen.queryByLabelText("当前密码")).toBeNull();
    expect(screen.queryByLabelText("6 位动态验证码")).toBeNull();
    expect(screen.queryByRole("button", { name: "编辑模拟规则" })).toBeNull();
    const pending = (await extension.read("preview")).pendingAccountRuleChange;
    expect(pending).toMatchObject({ baselineLoginProtection: false, requestedLoginProtection: true, status: "UNKNOWN" });
    expect((await extension.read("preview")).personalMfa.reauthenticationRequired).toBe(true);
    expect(screen.queryByRole("button", { name: "按原意图查询" })).toBeNull();
    expect(screen.getByText(/账号规则保存结果未知。先重新登录/)).toBeTruthy();
    expect(screen.queryByText(/身份验证方法或账号规则的变更已生效/)).toBeNull();
    expect(screen.getByRole("button", { name: "替换验证器" }).getAttribute("title")).toContain("账号规则结果尚未确定");

    await user.click(screen.getByTestId("go-users"));
    await user.click(screen.getByTestId("go-settings"));
    expect(await screen.findByRole("heading", { name: "账号规则的保存结果未知" })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "重新登录以继续" }));
    expect(screen.getByRole("button", { name: "Enter" })).toBeTruthy();
    await extension.execute("preview", { kind: "complete-personal-mfa-reauthentication" });
    await user.click(screen.getByRole("button", { name: "Enter" }));
    expect(await screen.findByRole("heading", { name: "账号规则的保存结果未知" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "按原意图查询" })).toBeTruthy();
    await select(user, "MOCK 原意图查询结果", "暂未查询到确定结果（保持未知）");
    await user.click(screen.getByRole("button", { name: "按原意图查询" }));
    expect(await screen.findByText(/状态仍为未知，不能重新保存/)).toBeTruthy();
    expect((await extension.read("preview")).pendingAccountRuleChange).toEqual(pending);
    await select(user, "MOCK 原意图查询结果", "确认原变更已应用");
    await user.click(screen.getByRole("button", { name: "按原意图查询" }));
    expect(await screen.findByText(/已保存模拟强制 MFA 要求/)).toBeTruthy();
    expect((await extension.read("preview")).settings.loginProtection).toBe(true);
    expect((await extension.read("preview")).personalMfa.reauthenticationRequired).toBe(false);
    expect(screen.queryByText(/身份验证方法或账号规则的变更已生效/)).toBeNull();
    expect((screen.getByRole("button", { name: "编辑模拟规则" }) as HTMLButtonElement).disabled).toBe(false);
    expect((await extension.read("preview")).pendingAccountRuleChange).toBeNull();
  });
  it("journals an unavailable account-rule save before exposing UNKNOWN and keeps it locked after reload", async () => {
    const { user, repository, extension } = await open("settings", { seed: seedBoundAccountRuleOperator });
    await user.click(screen.getByRole("button", { name: "编辑模拟规则" }));
    await user.click(screen.getByRole("checkbox", { name: "要求日常 IAM 用户在登录时完成 MFA" }));
    await user.click(screen.getByRole("button", { name: "审阅规则变更" }));
    await user.click(screen.getByRole("button", { name: "继续验证身份" }));
    await user.type(screen.getByLabelText("当前密码"), "demo-password");
    await user.type(screen.getByLabelText("6 位动态验证码"), "624810");
    vi.mocked(repository.workspace!.execute).mockRejectedValueOnce(new Error("timeout"));
    await user.click(screen.getByRole("button", { name: "验证并继续" }));

    const pending = (await extension.read("preview")).pendingAccountRuleChange;
    expect(pending).toMatchObject({ baselineLoginProtection: false, requestedLoginProtection: true, status: "UNKNOWN" });
    expect(await screen.findByRole("heading", { name: "账号规则的保存结果未知" })).toBeTruthy();
    expect(screen.queryByText("操作已完成。")).toBeNull();
    expect(screen.queryByLabelText("当前密码")).toBeNull();
    expect(screen.queryByLabelText("6 位动态验证码")).toBeNull();

    await user.click(screen.getByTestId("go-users"));
    await user.click(screen.getByTestId("refresh-account"));
    await waitFor(() => expect(repository.workspace!.read).toHaveBeenCalledTimes(2));
    await user.click(screen.getByTestId("go-settings"));
    expect(await screen.findByRole("heading", { name: "账号规则的保存结果未知" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "编辑模拟规则" })).toBeNull();
    expect((await extension.read("preview")).pendingAccountRuleChange).toEqual(pending);
  });
  it("keeps account-rule writes closed when both the save and recovery journal are unavailable", async () => {
    const { user, repository, extension } = await open("settings", { seed: seedBoundAccountRuleOperator });
    await user.click(screen.getByRole("button", { name: "编辑模拟规则" }));
    await user.click(screen.getByRole("checkbox", { name: "要求日常 IAM 用户在登录时完成 MFA" }));
    await user.click(screen.getByRole("button", { name: "审阅规则变更" }));
    await user.click(screen.getByRole("button", { name: "继续验证身份" }));
    await user.type(screen.getByLabelText("当前密码"), "demo-password");
    await user.type(screen.getByLabelText("6 位动态验证码"), "624810");
    vi.mocked(repository.workspace!.execute)
      .mockRejectedValueOnce(new Error("save timeout"))
      .mockRejectedValueOnce(new Error("recovery journal timeout"));
    await user.click(screen.getByRole("button", { name: "验证并继续" }));

    expect((await extension.read("preview")).pendingAccountRuleChange).toBeNull();
    expect(await screen.findByText(/保存与本地恢复日志同时不可用/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: "按原意图查询" })).toBeNull();
    expect(screen.queryByRole("button", { name: "编辑模拟规则" })).toBeNull();
    expect(screen.queryByLabelText("当前密码")).toBeNull();
    expect(screen.queryByLabelText("6 位动态验证码")).toBeNull();

    await user.click(screen.getByTestId("go-users"));
    await user.click(screen.getByTestId("refresh-account"));
    await waitFor(() => expect(repository.workspace!.read).toHaveBeenCalledTimes(2));
    await user.click(screen.getByTestId("go-settings"));
    expect(await screen.findByText(/保存与本地恢复日志同时不可用/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: "按原意图查询" })).toBeNull();
    expect(screen.queryByRole("button", { name: "编辑模拟规则" })).toBeNull();
  });
  it("keeps readable account rules unchanged when update capability is denied", async () => {
    const { user, extension } = await open("settings", { seed: seedBoundAccountRuleOperator });
    const before = await extension.read("preview");
    await user.click(screen.getByRole("button", { name: "编辑模拟规则" }));
    await user.click(screen.getByRole("checkbox", { name: "要求日常 IAM 用户在登录时完成 MFA" }));
    await user.click(screen.getByRole("button", { name: "审阅规则变更" }));
    await select(user, "MOCK 保存结果", "读取允许，但更新被拒绝");
    await user.click(screen.getByRole("button", { name: "继续验证身份" }));
    await user.type(screen.getByLabelText("当前密码"), "demo-password");
    await user.type(screen.getByLabelText("6 位动态验证码"), "624810");
    await user.click(screen.getByRole("button", { name: "验证并继续" }));
    expect(await screen.findByRole("heading", { name: "当前身份不能更新账号规则" })).toBeTruthy();
    expect(screen.getByText(/能看到当前值不代表可以修改/)).toBeTruthy();
    expect(screen.queryByLabelText("当前密码")).toBeNull();
    expect(await extension.read("preview")).toEqual(before);
  });
  it("discards a stale account-rule review and its operation-bound proof after conflict", async () => {
    const { user, repository, extension } = await open("settings", { seed: seedBoundAccountRuleOperator });
    const before = await extension.read("preview");
    await user.click(screen.getByRole("button", { name: "编辑模拟规则" }));
    await user.click(screen.getByRole("checkbox", { name: "要求日常 IAM 用户在登录时完成 MFA" }));
    await user.click(screen.getByRole("button", { name: "审阅规则变更" }));
    await user.click(screen.getByRole("button", { name: "继续验证身份" }));
    await user.type(screen.getByLabelText("当前密码"), "demo-password");
    await user.type(screen.getByLabelText("6 位动态验证码"), "624810");
    vi.mocked(repository.workspace!.execute).mockRejectedValueOnce(new HttpProblem(409, "IAM_STATE_CONFLICT"));
    await user.click(screen.getByRole("button", { name: "验证并继续" }));

    const conflict = await screen.findByRole("heading", { name: "规则已在审阅期间发生变化" });
    await waitFor(() => expect(conflict).toBe(document.activeElement));
    expect(screen.getByText("本次证明已作废，不能用于新的规则版本")).toBeTruthy();
    expect(screen.getByText(/不会自动重放保存/)).toBeTruthy();
    expect(await extension.read("preview")).toEqual(before);

    await user.click(screen.getByRole("button", { name: "重新载入当前规则" }));
    await waitFor(() => expect(repository.currentIdentity).toHaveBeenCalledTimes(2));
    expect(await screen.findByRole("button", { name: "编辑模拟规则" })).toBeTruthy();
    expect(screen.queryByLabelText("当前密码")).toBeNull();
    await user.click(screen.getByRole("button", { name: "编辑模拟规则" }));
    await user.click(screen.getByRole("checkbox", { name: "要求日常 IAM 用户在登录时完成 MFA" }));
    await user.click(screen.getByRole("button", { name: "审阅规则变更" }));
    await user.click(screen.getByRole("button", { name: "继续验证身份" }));
    expect((screen.getByLabelText("当前密码") as HTMLInputElement).value).toBe("");
    expect((screen.getByLabelText("6 位动态验证码") as HTMLInputElement).value).toBe("");
  });
  it("saves SSO settings only to the preview adapter", async () => {
    const { user, repository, extension } = await open("user-sso");
    await screen.findByText(/用户 SSO 将企业身份映射到已有 IAM 用户/);
    await user.click(screen.getByRole("button", { name: "去配置" }));
    await user.type(screen.getByLabelText("企业 IdP 的 SAML 元数据 XML"), '<EntityDescriptor entityID="user-sso"></EntityDescriptor>');
    await user.click(screen.getByRole("checkbox", { name: "启用用户 SSO（模拟）" }));
    await user.click(screen.getByRole("button", { name: "审阅配置" }));
    await user.click(screen.getByRole("button", { name: "保存" }));
    expect((await extension.read("preview")).settings.userSsoEnabled).toBe(true);
    expect(repository.execute).not.toHaveBeenCalled();
  });
  it("keeps malformed SAML metadata in the editor and focuses its inline error before review", async () => {
    const { user, extension } = await open("user-sso");
    await user.click(screen.getByRole("button", { name: "去配置" }));
    const metadata = screen.getByLabelText("企业 IdP 的 SAML 元数据 XML") as HTMLTextAreaElement;
    await user.type(metadata, "not metadata");
    await user.click(screen.getByRole("button", { name: "审阅配置" }));
    expect(screen.queryByRole("heading", { name: "审阅用户 SSO 变更" })).toBeNull();
    expect(screen.getByRole("alert").textContent).toContain("EntityDescriptor");
    expect(metadata).toBe(document.activeElement);
    expect(metadata.getAttribute("aria-invalid")).toBe("true");
    expect((await extension.read("preview")).settings.userSsoConfiguration).toBeNull();
    await user.clear(metadata);
    await user.type(metadata, '<EntityDescriptor entityID="preview"></EntityDescriptor>');
    expect(metadata.getAttribute("aria-invalid")).toBeNull();
    await user.click(screen.getByRole("button", { name: "审阅配置" }));
    expect(screen.getByRole("heading", { name: "审阅用户 SSO 变更" })).toBe(document.activeElement);
  });
  it("shows OIDC HTTPS and JWKS shape errors next to their fields before review", async () => {
    const { user, extension } = await open("user-sso");
    await user.click(screen.getByRole("button", { name: "去配置" }));
    await select(user, "协议", "OIDC");
    const issuer = screen.getByLabelText("身份提供商 URL") as HTMLInputElement;
    await user.type(issuer, "http://login.example.invalid");
    await user.type(screen.getByLabelText("客户端 ID"), "matrix-preview");
    await user.type(screen.getByLabelText("授权请求地址"), "https://login.example.invalid/authorize");
    await user.type(screen.getByLabelText("映射到 IAM 用户的字段"), "preferred_username");
    const jwks = screen.getByLabelText("签名公钥 JWKS JSON") as HTMLTextAreaElement;
    fireEvent.change(jwks, { target: { value: "not json" } });
    await user.click(screen.getByRole("button", { name: "审阅配置" }));
    expect(issuer).toBe(document.activeElement);
    expect(screen.getByRole("alert").textContent).toContain("HTTPS");
    await user.clear(issuer);
    await user.type(issuer, "https://login.example.invalid");
    await user.click(screen.getByRole("button", { name: "审阅配置" }));
    expect(jwks).toBe(document.activeElement);
    expect(screen.getByRole("alert").textContent).toContain("JWKS JSON");
    expect((await extension.read("preview")).settings.userSsoConfiguration).toBeNull();
    fireEvent.change(jwks, { target: { value: '{"keys":[{"kty":"RSA"}]}' } });
    await user.click(screen.getByRole("button", { name: "审阅配置" }));
    expect(screen.getByRole("heading", { name: "审阅用户 SSO 变更" })).toBe(document.activeElement);
  });
  it("configures OIDC user SSO without selecting or modifying a role SSO provider", async () => {
    const { user, extension } = await open("user-sso");
    const before = await extension.read("preview");
    await user.click(screen.getByRole("button", { name: "去配置" }));
    await select(user, "协议", "OIDC");
    await user.type(screen.getByLabelText("身份提供商 URL"), "https://login.example.invalid/oidc");
    await user.type(screen.getByLabelText("客户端 ID"), "matrix-user-sso");
    await user.type(screen.getByLabelText("授权请求地址"), "https://login.example.invalid/authorize");
    await user.type(screen.getByLabelText("映射到 IAM 用户的字段"), "preferred_username");
    fireEvent.change(screen.getByLabelText("签名公钥 JWKS JSON"), { target: { value: '{"keys":[{"kty":"RSA"}]}' } });
    await user.click(screen.getByRole("checkbox", { name: "启用用户 SSO（模拟）" }));
    await user.click(screen.getByRole("button", { name: "审阅配置" }));
    expect(screen.getByRole("heading", { name: "审阅用户 SSO 变更" })).toBe(document.activeElement);
    expect(screen.getByText("org-xiak")).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "保存" }));
    const state = await extension.read("preview");
    expect(state.settings.userSsoConfiguration).toEqual({ protocol: "OIDC", issuer: "https://login.example.invalid/oidc", clientId: "matrix-user-sso", authorizationEndpoint: "https://login.example.invalid/authorize", mappingClaim: "preferred_username", jwks: '{"keys":[{"kty":"RSA"}]}' });
    expect(state.providers).toEqual(before.providers);
    expect(state.roles).toEqual(before.roles);
    expect(state.federations).toEqual(before.federations);
    await user.click(screen.getByRole("button", { name: "编辑" }));
    await user.click(screen.getByRole("checkbox", { name: "启用用户 SSO（模拟）" }));
    await user.click(screen.getByRole("button", { name: "审阅配置" }));
    expect(screen.getByText(/普通 IAM 用户的非 SSO 登录路径可恢复/)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "保存" }));
    expect((await extension.read("preview")).settings).toMatchObject({ userSsoEnabled: false, userSsoConfiguration: state.settings.userSsoConfiguration });
  });
  it.each(["groups", "simulator"] as const)("never loads the %s preview graph after the directory denies management", async (view) => {
    const { repository } = await open(view, { reader: true });
    await screen.findByText("没有此页面的管理权限");
    expect(repository.workspace?.read).not.toHaveBeenCalled();
    expect(repository.listUsers).not.toHaveBeenCalled();
    expect(screen.queryByRole("button", { name: "新建用户组" })).toBeNull();
  });
  it.each(["keys", "create-policy", "policy-language", "simulator"] as const)("shows an honest unavailable state for %s on the live adapter", async (view) => {
    const { repository } = await open(view, { live: true });
    await screen.findByText("此能力尚未接入后端");
    expect(repository.execute).not.toHaveBeenCalled();
    expect(screen.queryByRole("button", { name: "新建密钥" })).toBeNull();
  });
  it("keeps enterprise member provisioning separate from SSO configuration", async () => {
    const { user, extension } = await open("federations");
    await user.click(await screen.findByRole("button", { name: "模拟关联企业微信" }));
    await user.type(screen.getByLabelText("企业名称"), "Preview Enterprise");
    await user.click(screen.getByRole("checkbox", { name: /Dev Member/ }));
    await user.click(within(screen.getByRole("dialog")).getByRole("button", { name: "保存" }));
    const directory = await screen.findByRole("table", { name: "企业微信" });
    expect(within(directory).queryByRole("columnheader", { name: "操作" })).toBeNull();
    expect(within(directory).queryByRole("button", { name: "导入为子用户" })).toBeNull();
    await user.click(within(directory).getByRole("button", { name: "Preview Enterprise" }));
    await user.click(await screen.findByRole("button", { name: "导入为子用户" }));
    await user.click(screen.getByRole("checkbox", { name: /Dev Member/ }));
    await user.click(within(screen.getByRole("dialog")).getByRole("button", { name: "导入为子用户" }));
    const state = await extension.read("preview");
    expect(state.enterprises[0]?.importedMemberIds).toEqual(["dev01"]);
    expect(state.settings.userSsoEnabled).toBe(false);
    expect(state.providers).toHaveLength(1);
  });
  it("allowlists report fields instead of exporting a raw account snapshot", async () => {
    const extension = createPreviewAccessWorkspace("org-xiak", () => users.map((entry) => entry.user.id), identity.account.rootIdentity.principalId);
    const workspace = await extension.read("preview");
    const scene = buildAccountAccessScene(identity, { items: users, nextAfter: null }, null, { accountId: "org-xiak", scope: "TENANT", installationId: null, items: [] }, { accountId: "org-xiak", scope: "INSTALLATION", installationId: "preview", items: [] });
    const report = buildAccessReport("security", workspace, scene, "2026-09-09T00:00:00Z");
    expect(report.mode).toBe("MOCK");
    expect(report.coverage.authenticatorEnrollment).toBe("UNOBSERVED");
    expect(report.checks?.find((check) => check.id === "mfaEvidence")?.state).toBe("unknown");
    expect(report.checks?.find((check) => check.id === "mfaEvidence")?.evidence).toBe("unobserved");
    expect(report.coverage).toMatchObject({ activityWindow: "UNAVAILABLE", collectionStart: null, sourceWatermarks: { successfulLogin: null, accessKeyUse: null, roleUse: null, businessOutcome: null } });
    expect(report.activity).toMatchObject({ accountId: "org-xiak", observedAt: "2026-09-09T00:00:00Z" });
    expect(report.activity?.observations.find((item) => item.id === "successfulLogin")).toMatchObject({ state: "unknown", occurredAt: null, source: null });
    expect(report.activity?.observations.find((item) => item.id === "accessKeyUse")).toMatchObject({ state: "unknown", occurredAt: null });
    const otherUserSession = { id: "another-session", organizationId: "org-xiak", principalId: "principal-other", status: "ACTIVE" as const, issuedAt: "2026-09-09T02:00:00Z", expiresAt: "2026-09-09T03:00:00Z" };
    const foreignReport = buildAccessReport("security", workspace, scene, "2026-09-09T00:00:00Z", otherUserSession);
    expect(foreignReport.activity?.observations.find((item) => item.id === "successfulLogin")).toMatchObject({ state: "unknown", occurredAt: null, source: null });
    expect(JSON.stringify(report)).not.toContain("EntityDescriptor");
    expect(JSON.stringify(report)).not.toContain("preview-only");
    expect(report.users).toHaveLength(2);
  });
  it("separates review, configured, unknown, and not-applicable security evidence", async () => {
    const extension = createPreviewAccessWorkspace("org-xiak", () => users.map((entry) => entry.user.id), identity.account.rootIdentity.principalId);
    const workspace = await extension.read("preview");
    const snapshot = buildAccessSecuritySnapshot(workspace);
    expect(snapshot.counts).toEqual({ review: 3, configured: 1, notApplicable: 0, unknown: 1 });
    expect(snapshot.evidenceCounts).toEqual({ observed: 4, incomplete: 0, unobserved: 1, notApplicable: 0 });
    expect(snapshot.checks.find((check) => check.id === "mfaEvidence")?.state).toBe("unknown");
    expect(snapshot.checks.find((check) => check.id === "mfaEvidence")?.evidence).toBe("unobserved");

    const withoutApplicableUsers = structuredClone(workspace);
    withoutApplicableUsers.userProfiles = {};
    withoutApplicableUsers.userPolicies = {};
    withoutApplicableUsers.keys = [];
    const empty = buildAccessSecuritySnapshot(withoutApplicableUsers);
    expect(empty.checks.find((check) => check.id === "activeKeys")?.state).toBe("notApplicable");
    expect(empty.checks.find((check) => check.id === "loginProtection")?.state).toBe("notApplicable");
    expect(empty.checks.find((check) => check.id === "mfaEvidence")?.state).toBe("notApplicable");

    const partial = buildAccessSecuritySnapshot(withoutApplicableUsers, false);
    expect(partial.checks.find((check) => check.id === "directGrants")).toMatchObject({ state: "unknown", evidence: "incomplete" });
    expect(partial.checks.find((check) => check.id === "mfaEvidence")).toMatchObject({ state: "unknown", evidence: "unobserved" });

    const partialWithVisibleUsers = structuredClone(workspace);
    partialWithVisibleUsers.userPolicies = Object.fromEntries(Object.keys(partialWithVisibleUsers.userPolicies).map((id) => [id, []]));
    partialWithVisibleUsers.userProfiles = Object.fromEntries(Object.entries(partialWithVisibleUsers.userProfiles).map(([id, profile]) => [id, { ...profile, passwordResetRequired: false }]));
    const partialWithoutVisibleFindings = buildAccessSecuritySnapshot(partialWithVisibleUsers, false);
    expect(partialWithoutVisibleFindings.checks.find((check) => check.id === "directGrants")).toMatchObject({ state: "unknown", count: 0, evidence: "incomplete" });
    expect(partialWithoutVisibleFindings.checks.find((check) => check.id === "pendingPasswords")).toMatchObject({ state: "unknown", count: 0, evidence: "incomplete" });
  });
  it("does not turn key metadata, missing events or role sessions into usage evidence", async () => {
    const extension = createPreviewAccessWorkspace("org-xiak", () => users.map((entry) => entry.user.id), identity.account.rootIdentity.principalId);
    const workspace = await extension.read("preview");
    const observed = buildAccessActivityObservations(workspace);
    expect(observed.find((item) => item.id === "successfulLogin")).toMatchObject({ state: "unknown", occurredAt: null, source: null });
    expect(observed.filter((item) => item.id !== "successfulLogin")).toEqual([
      { id: "accessKeyUse", state: "unknown", occurredAt: null, source: null },
      { id: "roleUse", state: "unknown", occurredAt: null, source: null },
      { id: "businessOutcome", state: "unknown", occurredAt: null, source: null }
    ]);
    const currentSession = { id: "preview-session", organizationId: "org-xiak", principalId: identity.user.id, status: "ACTIVE" as const, issuedAt: "2026-09-09T02:00:00Z", expiresAt: "2026-09-09T03:00:00Z" };
    expect(buildAccessActivityObservations(workspace, currentSession).find((item) => item.id === "successfulLogin")).toMatchObject({ state: "observed", occurredAt: currentSession.issuedAt, source: "CURRENT_PREVIEW_SESSION" });
    expect(buildAccessActivityObservations(workspace, { ...currentSession, organizationId: "other-account" }).find((item) => item.id === "successfulLogin")).toMatchObject({ state: "unknown", occurredAt: null });
    const withoutLogin = structuredClone(workspace);
    withoutLogin.events = [];
    expect(buildAccessActivityObservations(withoutLogin).find((item) => item.id === "successfulLogin")).toMatchObject({ state: "unknown", occurredAt: null });
    withoutLogin.keys = [];
    expect(buildAccessActivityObservations(withoutLogin).find((item) => item.id === "accessKeyUse")).toMatchObject({ state: "notApplicable", occurredAt: null });
  });
  it("presents security evidence before report exports and links checks to their owning pages", async () => {
    const extension = createPreviewAccessWorkspace("org-xiak", () => users.map((entry) => entry.user.id), identity.account.rootIdentity.principalId);
    const workspace = await extension.read("preview");
    const scene = buildAccountAccessScene(identity, { items: users, nextAfter: null }, null, { accountId: "org-xiak", scope: "TENANT", installationId: null, items: [] }, { accountId: "org-xiak", scope: "INSTALLATION", installationId: "preview", items: [] });
    const onNavigate = vi.fn();
    const user = userEvent.setup();
    render(<LocaleProvider><AccessReports workspace={workspace} scene={scene} currentSession={{ id: "preview-session", organizationId: "org-xiak", principalId: identity.user.id, status: "ACTIVE", issuedAt: "2026-09-09T02:00:00Z", expiresAt: "2026-09-09T03:00:00Z" }} onNavigate={onNavigate} /></LocaleProvider>);
    const card = screen.getByRole("heading", { name: "身份安全概览" }).closest("article")!;
    expect(within(card).getByLabelText("身份安全检查状态")).toBeTruthy();
    expect(within(card).getByLabelText("身份安全证据覆盖")).toBeTruthy();
    expect(within(card).getByText("MFA 绑定证据")).toBeTruthy();
    expect(within(card).getByLabelText("活动观测")).toBeTruthy();
    expect(within(card).getByText("访问密钥使用")).toBeTruthy();
    expect(within(card).getByText(/没有签名请求的使用证据/)).toBeTruthy();
    expect(within(card).getAllByText("状态未知").length).toBeGreaterThanOrEqual(1);
    expect(within(card).getAllByText("证据: 未观测").length).toBeGreaterThanOrEqual(1);
    expect(within(card).getByRole("button", { name: "导出报告" })).toBeTruthy();
    await user.click(within(card).getByRole("button", { name: "查看长期访问密钥" }));
    expect(onNavigate).toHaveBeenCalledWith("keys");
  });
});
