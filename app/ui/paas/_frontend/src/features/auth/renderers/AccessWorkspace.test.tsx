import { useState } from "react";
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { LocaleProvider, useLocalePreference } from "@/i18n/LocaleProvider";
import { UnsavedChangesProvider, useLeaveConfirmation } from "@ui/xiak";
import { SessionProvider, useSession } from "../application/SessionProvider";
import { AccountAccessProvider } from "../application/AccountAccessProvider";
import { accountAccessViews, type AccountAccessView, type AccountIdentity, type AccountUser } from "../domain/accounts";
import type { AccountRepository, IamRepository } from "../repositories/iamRepository";
import { createPreviewAccessWorkspace } from "../repositories/previewAccessWorkspace";
import { PolicyDocumentViewer } from "./PolicyDocumentViewer";
import type { PolicyDocument } from "../domain/policyDocument";
import { AccountAccessRenderer } from "./AccountAccessRenderer";
import { buildAccessReport } from "../scenes/accessReport";
import { buildAccountAccessScene } from "../scenes/accountAccessScene";
import { previewAccountRepository, previewCredential, previewIamRepository } from "../repositories/previewIamRepository";
import { HttpProblem } from "@/infrastructure/http/jsonRequest";

vi.mock("next/link", () => ({
  default: ({ onNavigate, href, children, ...props }: React.ComponentProps<"a"> & { onNavigate?(event: { preventDefault(): void }): void }) => <a {...props} href={href} onClick={(event) => {
    event.preventDefault(); // Real Next routing is a browser gate; jsdom exercises the feature's destination callback.
    if (!event.ctrlKey && !event.metaKey && !event.shiftKey && !event.altKey) onNavigate?.({ preventDefault() {} });
  }}>{children}</a>
}));

const platformAttachment = { id: "attachment-admin-platform", accountId: "org-xiak", target: { kind: "USER" as const, id: "admin" }, policyId: "system.platform-admin", scope: "INSTALLATION" as const, installationId: "preview", resourceVersion: 1, createdAt: "2026-09-09T00:00:00Z", updatedAt: "2026-09-09T00:00:00Z" };
const identity: AccountIdentity = { account: { organization: { id: "org-xiak", displayName: "Example", status: "ACTIVE", resourceVersion: 1 }, primaryPrincipalId: "admin", primaryLoginName: "admin", loginAlias: "example" }, principal: { id: "admin", organizationId: "org-xiak", loginName: "admin", displayName: "Administrator", status: "ACTIVE", mustChangePassword: false, resourceVersion: 1 }, policyAttachments: [platformAttachment], canCreateOrganizations: true };
const users: AccountUser[] = ["lin", "chen"].map((name) => ({ principal: { ...identity.principal, id: "principal-" + name, loginName: name, displayName: name }, policyAttachments: [] }));
const reviewUsers: AccountUser[] = [...users, ...["qiao", "wu"].map((name) => ({ principal: { ...identity.principal, id: "principal-" + name, loginName: name, displayName: name }, policyAttachments: [] }))];
const login: IamRepository = { login: async () => ({ credential: "preview-only", mustChangePassword: false, session: { id: "session", organizationId: "org-xiak", principalId: "admin", status: "ACTIVE", issuedAt: "2026-09-09T00:00:00Z", expiresAt: "2099-01-01T00:00:00Z" } }), changePassword: async () => {}, logout: async () => {} };

function Harness({ repository, initialView, initialEntityId }: { repository: AccountRepository; initialView: AccountAccessView; initialEntityId?: string }) {
  const requestLeave = useLeaveConfirmation();
  const session = useSession();
  const locale = useLocalePreference();
  const [view, setView] = useState(initialView);
  const [entityId, setEntityId] = useState(initialEntityId);
  const [policyMethod, setPolicyMethod] = useState<string>();
  if (!session.current) return <button onClick={() => void session.login("admin", "preview")}>Enter</button>;
  return <AccountAccessProvider repository={repository}><button onClick={() => locale.setLocale(locale.locale === "en" ? "zh-CN" : "en")}>Language</button><nav>{accountAccessViews.map((target) => <button data-testid={"go-" + target} key={target} onClick={() => requestLeave(() => { setView(target); setEntityId(undefined); setPolicyMethod(undefined); })}>{target}</button>)}</nav><output aria-label="Entity destination">{entityId ?? "directory"}</output><AccountAccessRenderer key={view + ":" + (entityId ?? "") + ":" + (policyMethod ?? "")} view={view} entityId={entityId} policyMethod={policyMethod} onNavigate={(next, id, method) => requestLeave(() => { setView(next); setEntityId(id); setPolicyMethod(method); })} /></AccountAccessProvider>;
}
async function open(initialView: AccountAccessView, options?: { live?: boolean; reader?: boolean; entityId?: string; users?: AccountUser[]; seed?(extension: ReturnType<typeof createPreviewAccessWorkspace>): Promise<void> }) {
  const directoryUsers = options?.users ?? users;
  const extension = createPreviewAccessWorkspace("org-xiak", () => directoryUsers.map((user) => user.principal.id), identity.account.primaryPrincipalId);
  await options?.seed?.(extension);
  const repository: AccountRepository = {
    currentIdentity: vi.fn().mockResolvedValue(options?.reader ? { ...identity, policyAttachments: [], canCreateOrganizations: false } : identity),
    listUsers: options?.reader ? vi.fn().mockRejectedValue(new HttpProblem(403, "FORBIDDEN")) : vi.fn().mockResolvedValue({ items: directoryUsers, nextAfter: null }),
    listPolicies: vi.fn().mockImplementation(async (_credential: string, platform: boolean) => ({ accountId: "org-xiak", scope: platform ? "INSTALLATION" : "TENANT", installationId: platform ? "preview" : null, items: [] })),
    listAccounts: vi.fn().mockResolvedValue({ items: [], nextAfter: null }),
    execute: vi.fn().mockResolvedValue(undefined),
    workspace: options?.live ? undefined : { read: vi.fn(extension.read), execute: vi.fn(extension.execute) }
  };
  const user = userEvent.setup();
  render(<LocaleProvider><SessionProvider repository={login}><UnsavedChangesProvider><Harness initialView={initialView} initialEntityId={options?.entityId} repository={repository} /></UnsavedChangesProvider></SessionProvider></LocaleProvider>);
  await user.click(screen.getByRole("button", { name: "Enter" }));
  await waitFor(() => expect(repository.currentIdentity).toHaveBeenCalled());
  await waitFor(() => expect(screen.queryByLabelText("正在读取 IAM 账号信息…")).toBeNull());
  return { user, repository, extension };
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
afterEach(() => { cleanup(); localStorage.clear(); sessionStorage.clear(); });

describe("selection-driven user directory", () => {
  async function openBatch() {
    await previewIamRepository.logout(previewCredential);
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
    await user.click(screen.getByRole("button", { name: "首页" }));
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
    expect(after.filter((user) => ["lin", "chen"].includes(user.principal.loginName)).every((user) => user.principal.status === "DISABLED")).toBe(true);
    expect(after.filter((user) => !["lin", "chen"].includes(user.principal.loginName)).every((user) => user.principal.status === "ACTIVE")).toBe(true);
    expect(repository.executeUserBatch).toHaveBeenCalledTimes(2);
    expect(repository.execute).not.toHaveBeenCalled();
  });
  it("keeps live single-user management reachable without pretending to support bulk requests", async () => {
    const { user, repository } = await open("users", { live: true });
    expect(screen.getByRole("button", { name: "更多操作" }).hasAttribute("disabled")).toBe(true);
    expect(screen.getByText(/当前连接未提供批量操作/)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "查看用户 lin" }));
    expect(screen.getByRole("dialog")).toBeTruthy();
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
  it("matches CAM directory columns, omits preset metadata in custom view and restores chooser focus", async () => {
    const { user, repository } = await open("policies");
    const headings = () => within(screen.getByRole("table", { name: "策略" })).getAllByRole("columnheader").map((cell) => cell.textContent).filter(Boolean);
    expect(headings()).toEqual(["策略名", "所属产品", "权限级别", "描述", "上次修改时间", "操作"]);
    await select(user, "权限级别", "全局权限");
    await user.click(screen.getByRole("tab", { name: "自定义策略" }));
    expect(headings()).toEqual(["策略名", "描述", "上次修改时间", "操作"]);
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
    await screen.findByRole("table", { name: "策略" });
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
    let dialog = screen.getByRole("dialog");
    await user.click(within(dialog).getByRole("checkbox", { name: /lin/ }));
    await user.click(within(dialog).getByRole("button", { name: "下一步：审阅" }));
    dialog = screen.getByRole("dialog", { name: "审阅批量关联" });
    expect(repository.workspace!.execute).not.toHaveBeenCalled();
    expect(within(dialog).getByRole("region", { name: "新增关联" }).textContent).toContain("lin");
    expect(document.activeElement).toBe(within(dialog).getByRole("region", { name: "审阅关联变更" }));
    await user.click(within(dialog).getByRole("button", { name: "返回选择" }));
    expect((within(dialog).getByRole("checkbox", { name: /lin/ }) as HTMLInputElement).checked).toBe(true);
    await user.click(within(dialog).getByRole("button", { name: "下一步：审阅" }));
    vi.mocked(repository.workspace!.execute).mockRejectedValueOnce(new Error("offline"));
    await user.click(within(dialog).getByRole("button", { name: "确认关联" }));
    await expectRetainedFailure(dialog);
    expect((await extension.read("preview")).userPolicies["principal-lin"]).toEqual(["policy-prod-logs"]);
    await user.click(within(dialog).getByRole("button", { name: "确认关联" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect((await extension.read("preview")).userPolicies["principal-lin"]).toEqual(["policy-prod-logs", "policy-read"]);
    expect(repository.execute).not.toHaveBeenCalled();
  });
  it("explains the remaining direct path when a group attachment is removed", async () => {
    const { user, repository } = await open("policies", { seed: async (extension) => {
      await extension.execute("preview", { kind: "associate-policy", id: "policy-prod-logs", userIds: ["principal-lin"], groupIds: ["group-delivery"], roleIds: [] });
    } });
    await user.click(await screen.findByRole("checkbox", { name: "选择 ProductionLogReader" }));
    await user.click(screen.getByRole("button", { name: "更多操作" }));
    await user.click(screen.getByRole("menuitem", { name: "关联用户 / 组 / 角色" }));
    const dialog = screen.getByRole("dialog");
    await user.click(within(dialog).getByRole("button", { name: /移除 DeliveryTeam/ }));
    await user.click(within(dialog).getByRole("button", { name: "下一步：审阅" }));
    expect(within(dialog).getByText("lin 仍直接关联此策略。")).toBeTruthy();
    expect(within(dialog).getByRole("region", { name: "移除关联" }).textContent).toContain("DeliveryTeam");
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
    expect(screen.getByText("定期检查高权限用户").parentElement!.parentElement!.textContent).toContain("2 位用户");
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
  it("does not present empty groups, inactive keys or mock protection as completed security", async () => {
    const { user } = await open("overview", { seed: async (extension) => {
      await extension.execute("preview", { kind: "change-group-members", id: "group-delivery", added: [], removed: ["principal-lin"] });
      await extension.execute("preview", { kind: "change-group-policies", id: "group-auditors", added: [], removed: ["policy-audit"] });
      await extension.execute("preview", { kind: "change-group-policies", id: "group-operators", added: [], removed: ["policy-delivery", "policy-tag-logs"] });
      await extension.execute("preview", { kind: "set-key-status", id: "MOCK-pipeline-key", enabled: false });
      await extension.execute("preview", { kind: "save-settings", settings: { ...(await extension.read("preview")).settings, loginProtection: true } });
    } });
    expect(await screen.findByText(/0 个用户组同时具有成员和策略/)).toBeTruthy();
    expect(screen.getByText(/0 个启用的模拟密钥/)).toBeTruthy();
    expect(screen.getByText("已保存模拟登录保护配置，未实际启用 MFA。")).toBeTruthy();
    expect(screen.queryByText("已完成")).toBeNull();
    await user.click(screen.getByRole("link", { name: "检查长期密钥" }));
    expect(await screen.findByRole("table", { name: "API 密钥" })).toBeTruthy();
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
    // A new directory read is requested through the existing page control.
    await user.click(screen.getByRole("button", { name: "First page" }));
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
    let dialog = screen.getByRole("dialog"), panel = within(dialog);
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
    expect(document.activeElement).toBe(trigger);
    await user.click(trigger);
    dialog = screen.getByRole("dialog"); panel = within(dialog);
    await user.click(panel.getByRole("checkbox", { name: "lin" }));
    await user.click(panel.getByRole("checkbox", { name: "chen" }));
    await user.click(panel.getByRole("button", { name: "审阅变更" }));
    vi.mocked(repository.workspace!.execute).mockRejectedValueOnce(new Error("offline"));
    await user.click(panel.getByRole("button", { name: "保存" }));
    await expectRetainedFailure(dialog);
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
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
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
    const panel = within(screen.getByRole("dialog"));
    expect((panel.getByRole("combobox", { name: "信任主体类型" }) as HTMLButtonElement).disabled).toBe(true);
    await user.click(panel.getByRole("checkbox", { name: "lin" }));
    await user.click(panel.getByRole("checkbox", { name: "lin" }));
    expect((panel.getByRole("button", { name: "审阅变更" }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.submit(screen.getByRole("dialog").querySelector("form")!);
    expect(repository.workspace!.execute).not.toHaveBeenCalled();
  });
  it("retains role metadata through a pending command and retry, locking dismissal only until it settles", async () => {
    const { user, repository, extension } = await open("roles", { entityId: "role-pipeline" });
    const before = await extension.read("preview"), original = before.roles.find((role) => role.id === "role-pipeline")!;
    await user.click(await screen.findByRole("button", { name: "编辑角色信息" }));
    const dialog = screen.getByRole("dialog"), panel = within(dialog);
    fireEvent.change(panel.getByLabelText("描述"), { target: { value: "Retained metadata" } });
    await user.click(panel.getByRole("button", { name: "添加标签" }));
    await user.type(panel.getByLabelText("标签键 1"), "team");
    await user.type(panel.getByLabelText("标签值 1"), "delivery");
    let rejectWrite!: (error: Error) => void;
    vi.mocked(repository.workspace!.execute).mockImplementationOnce(() => new Promise((_, reject) => { rejectWrite = reject; }));
    await user.click(panel.getByRole("button", { name: "保存" }));
    expect(dialog.getAttribute("aria-busy")).toBe("true");
    expect((panel.getByRole("button", { name: "取消" }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent(dialog, new Event("cancel", { cancelable: true }));
    fireEvent.submit(dialog.querySelector("form")!);
    expect(repository.workspace!.execute).toHaveBeenCalledOnce();
    expect(await extension.read("preview")).toEqual(before);
    await act(async () => { rejectWrite(new Error("offline")); });
    await expectRetainedFailure(dialog);
    expect((panel.getByLabelText("描述") as HTMLTextAreaElement).value).toBe("Retained metadata");
    expect((panel.getByLabelText("标签值 1") as HTMLInputElement).value).toBe("delivery");
    expect((panel.getByRole("button", { name: "取消" }) as HTMLButtonElement).disabled).toBe(false);
    await user.click(panel.getByRole("button", { name: "保存" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect((await extension.read("preview")).roles.find((role) => role.id === original.id)).toEqual({ ...original, description: "Retained metadata", tags: [{ key: "team", value: "delivery" }] });
  });
  it.each(["add", "remove"] as const)("retains a reviewed role policy %s delta after failure and retries without replacing unrelated grants", async (mode) => {
    const { user, repository, extension } = await open("roles", { entityId: "role-pipeline" });
    const before = await extension.read("preview"), original = before.roles.find((role) => role.id === "role-pipeline")!;
    await user.click(await screen.findByRole("button", { name: mode === "add" ? "关联策略" : "移除策略" }));
    const dialog = screen.getByRole("dialog"), panel = within(dialog);
    const policyName = mode === "add" ? "MatrixReadOnlyAccess" : "MatrixDeliveryAccess";
    await user.click(panel.getByRole("checkbox", { name: policyName }));
    await user.type(panel.getByRole("searchbox"), "no-matching-policy");
    expect(panel.getByRole("button", { name: "移除 " + policyName })).toBeTruthy();
    await user.click(panel.getByRole("button", { name: "审阅变更" }));
    expect(repository.workspace!.execute).not.toHaveBeenCalled();
    vi.mocked(repository.workspace!.execute).mockRejectedValueOnce(new Error("offline"));
    await user.click(panel.getByRole("button", { name: "保存" }));
    await expectRetainedFailure(dialog);
    expect(await extension.read("preview")).toEqual(before);
    expect(panel.getByRole("list").textContent).toBe(policyName);
    await user.click(panel.getByRole("button", { name: "返回选择" }));
    expect((panel.getByRole("checkbox", { name: policyName }) as HTMLInputElement).checked).toBe(true);
    await user.click(panel.getByRole("button", { name: "审阅变更" }));
    await user.click(panel.getByRole("button", { name: "保存" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
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
    const dialog = screen.getByRole("dialog"), panel = within(dialog);
    await select(user, "权限边界", mode === "set" ? "ProductionLogReader" : "未设置权限边界");
    await user.click(panel.getByRole("button", { name: "审阅变更" }));
    vi.mocked(repository.workspace!.execute).mockRejectedValueOnce(new Error("offline"));
    await user.click(panel.getByRole("button", { name: "保存" }));
    await expectRetainedFailure(dialog);
    expect(await extension.read("preview")).toEqual(before);
    expect(panel.getByText(mode === "set" ? "ProductionLogReader" : "MatrixReadOnlyAccess")).toBeTruthy();
    await user.click(panel.getByRole("button", { name: "保存" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
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
    const dialog = screen.getByRole("dialog"), panel = within(dialog);
    fireEvent.change(panel.getByLabelText("会话时长（分钟）"), { target: { value: "120" } });
    expect((panel.getByRole("checkbox", { name: "允许通过控制台访问" }) as HTMLInputElement).disabled).toBe(true);
    vi.mocked(repository.workspace!.execute).mockRejectedValueOnce(new Error("offline"));
    await user.click(panel.getByRole("button", { name: "保存" }));
    await expectRetainedFailure(dialog);
    expect(await extension.read("preview")).toEqual(before);
    expect((panel.getByLabelText("会话时长（分钟）") as HTMLInputElement).value).toBe("120");
    await user.click(panel.getByRole("button", { name: "保存" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
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
    const dialog = screen.getByRole("dialog"), panel = within(dialog);
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
  it("checks a synthetic workload before creating a role session and revokes it without changing the current identity", async () => {
    const { user, repository, extension } = await open("roles", { entityId: "role-pipeline" });
    await user.click(await screen.findByRole("tab", { name: "临时会话" }));
    await user.click(screen.getByRole("button", { name: "创建体验会话" }));
    await select(user, "调用身份", "devops.matrix.internal");
    await user.click(screen.getByRole("button", { name: "检查信任与权限" }));
    expect((await extension.read("preview-only")).roleSessions).toHaveLength(0);
    vi.mocked(repository.workspace!.execute).mockRejectedValueOnce(new Error("offline"));
    await user.click(within(screen.getByRole("dialog")).getByRole("button", { name: "创建体验会话" }));
    await expectRetainedFailure(screen.getByRole("dialog"));
    expect((await extension.read("preview-only")).roleSessions).toHaveLength(0);
    expect(screen.getByRole("combobox", { name: "调用身份" }).textContent).toBe("devops.matrix.internal");
    await user.click(within(screen.getByRole("dialog")).getByRole("button", { name: "创建体验会话" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    const session = (await extension.read("preview-only")).roleSessions[0]!;
    expect(session.caller).toEqual({ type: "service", id: "devops.matrix.internal" });
    await user.click(screen.getByRole("button", { name: "模拟访问" }));
    expect(screen.getByRole("combobox", { name: "身份类型" }).textContent).toContain("角色体验会话");
    expect(screen.queryByRole("combobox", { name: "了解一个授权场景" })).toBeNull();
    await user.click(screen.getByRole("button", { name: "运行模拟" }));
    expect(screen.getByText("默认拒绝", { exact: true })).toBeTruthy();
    await user.click(screen.getByTestId("go-roles"));
    await user.click(await screen.findByRole("button", { name: "PipelineDeploymentRole" }));
    await user.click(screen.getByRole("tab", { name: "临时会话" }));
    await user.click(screen.getByRole("button", { name: "撤销会话" }));
    vi.mocked(repository.workspace!.execute).mockRejectedValueOnce(new Error("offline"));
    await user.click(within(screen.getByRole("dialog")).getByRole("button", { name: "撤销会话" }));
    await expectRetainedFailure(screen.getByRole("dialog"));
    expect((await extension.read("preview-only")).roleSessions[0]).toEqual(session);
    await user.click(within(screen.getByRole("dialog")).getByRole("button", { name: "撤销会话" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(screen.getByRole("table", { name: "临时会话" }).textContent).toContain("已撤销");
    expect((await extension.read("preview-only")).roleSessions[0]?.revokedAt).toBeTruthy();
  });
  it("reviews user boundary changes separately and links boundary usage back to its exact owner", async () => {
    const { user, extension } = await open("users", { entityId: "principal-lin" });
    await user.click(await screen.findByRole("tab", { name: "权限策略" }));
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
      for (let index = 0; index < 42; index++) await extension.execute("preview", { kind: "save-policy", name: "Batch" + String(index).padStart(2, "0"), description: "", document: { version: "1", statement: [{ effect: "allow", action: ["logs:search"], resource: ["*"] }] } });
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
    for (const row of rows.slice(0, 10)) await user.click(row);
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
  it("creates an empty group in a page wizard, then adds members in a separately reviewed change", async () => {
    const { user, repository, extension } = await open("groups");
    await user.click(await screen.findByRole("button", { name: "新建用户组" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    await user.type(screen.getByLabelText("名称"), "Platform Operators");
    await user.click(screen.getByRole("button", { name: "下一步" }));
    expect(screen.queryByRole("checkbox", { name: "lin" })).toBeNull();
    await user.click(screen.getByRole("checkbox", { name: "MatrixReadOnlyAccess" }));
    await user.type(screen.getByRole("searchbox"), "no-match");
    expect(screen.getByRole("button", { name: "移除 MatrixReadOnlyAccess" })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "下一步" }));
    expect(repository.workspace!.execute).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "新建用户组" }));
    await screen.findByRole("heading", { name: "用户组已创建" });
    const created = (await extension.read("preview")).groups.at(-1)!;
    expect(created.memberIds).toEqual([]);
    expect(created.policyIds).toEqual(["policy-read"]);
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
    await user.click(screen.getByRole("checkbox", { name: "MatrixReadOnlyAccess" }));
    await user.click(screen.getByRole("button", { name: "上一步" }));
    expect((screen.getByLabelText("名称") as HTMLInputElement).value).toBe("Draft Team");
    await user.click(screen.getByRole("button", { name: "Language" }));
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    await user.click(screen.getByRole("button", { name: "Continue editing" }));
    await user.click(screen.getByRole("button", { name: "Next" }));
    expect((screen.getByRole("checkbox", { name: "MatrixReadOnlyAccess" }) as HTMLInputElement).checked).toBe(true);
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
    await user.click(screen.getByRole("button", { name: "从用户组移除 chen" }));
    dialog = within(screen.getByRole("dialog"));
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
    await user.click(screen.getByRole("tab", { name: "权限策略 (2)" }));
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
    await user.click(screen.getByRole("tab", { name: "权限策略 (1)" }));
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
    await user.click(await screen.findByRole("button", { name: "删除" }));
    await user.type(screen.getByLabelText("输入名称以确认"), "EnterpriseSSO");
    await user.click(screen.getByRole("button", { name: "确认删除" }));
    await waitFor(() => expect(within(screen.getByRole("dialog")).getByRole("alert").textContent).toContain("仍被引用"));
  });
  it("round-trips typed resources and all condition types, preserving restrictions in review and save", async () => {
    const { user, extension, repository } = await open("create-policy");
    await logActions(user, ["logs:search"]);
    await select(user, "资源授权范围", "指定资源");
    await user.clear(screen.getByLabelText("资源 ID 或前缀 1"));
    await user.paste("production/*");
    await user.click(screen.getByRole("checkbox", { name: "限制来源 IP" }));
    await user.click(screen.getByLabelText("来源 IP 范围（CIDR）")); await user.paste("192.0.2.0/24\n2001:db8::/32");
    await user.click(screen.getByRole("checkbox", { name: "按资源标签限制" }));
    await user.click(screen.getByLabelText("标签键 1")); await user.paste("environment");
    await user.click(screen.getByLabelText("标签值 1")); await user.paste("production");
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
    const { user } = await open("simulator", { users: reviewUsers.map((entry) => entry.principal.id === "principal-lin" ? { ...entry, principal: { ...entry.principal, status: "DISABLED" } } : entry) });
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
    const { user, extension } = await open("policies");
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
    let dialog = screen.getByRole("dialog", { name: "查看版本 v1" });
    expect(within(dialog).getByText(/只读查看/)).toBeTruthy();
    expect((await extension.read("preview")).policies.find((policy) => policy.id === "policy-prod-logs")?.defaultVersion).toBe(2);
    await user.click(within(dialog).getAllByRole("button", { name: "关闭" })[0]!);
    await user.click(screen.getByRole("button", { name: "将 v1 设为默认版本" }));
    dialog = screen.getByRole("dialog");
    expect(within(dialog).getByRole("region", { name: "策略内容变更" })).toBeTruthy();
    expect(within(dialog).getByRole("region", { name: "受影响对象" }).textContent).toContain("lin");
    await user.click(within(dialog).getByText("展开完整 JSON 对比"));
    expect(within(dialog).getByRole("region", { name: "当前生效 · v2" }).textContent).toContain("deny");
    expect(within(dialog).getByRole("region", { name: "切换后生效 · v1" }).textContent).not.toContain("deny");
    await user.click(within(dialog).getByRole("button", { name: "取消" }));
    expect((await extension.read("preview")).policies.find((policy) => policy.id === "policy-prod-logs")?.defaultVersion).toBe(2);
    await user.click(screen.getByRole("button", { name: "将 v1 设为默认版本" }));
    await user.click(within(screen.getByRole("dialog")).getByRole("button", { name: "设为默认版本" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(screen.queryByRole("button", { name: "删除版本 v1" })).toBeNull();
    expect(document.activeElement).toBe(screen.getByRole("region", { name: "策略版本" }));
    await user.click(screen.getByRole("button", { name: "删除版本 v2" }));
    await user.click(within(screen.getByRole("dialog")).getByRole("button", { name: "确认删除" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    const state = await extension.read("preview");
    expect(state.policies.find((policy) => policy.id === "policy-prod-logs")?.versions.map((version) => version.id)).toEqual([1]);
    expect(document.activeElement).toBe(screen.getByRole("region", { name: "策略版本" }));
    expect(state.userPolicies["principal-lin"]).toContain("policy-prod-logs");
  });
  it("shows a mock secret only at creation, then removes it when the dialog closes", async () => {
    const { user, extension } = await open("keys");
    await user.click(await screen.findByRole("button", { name: "新建密钥" }));
    await select(user, "所属用户", "chen · 0/2");
    await user.click(within(screen.getByRole("dialog")).getByRole("button", { name: "新建密钥" }));
    const dialog = await screen.findByRole("dialog", { name: "模拟密钥已创建" });
    const secret = within(dialog).getByText(/^MOCK_NOT_A_CREDENTIAL_/).textContent!;
    expect(JSON.stringify(await extension.read("preview"))).not.toContain(secret);
    await user.click(within(dialog).getByRole("checkbox"));
    await user.click(within(dialog).getByRole("button", { name: "已完成" }));
    expect(screen.queryByText(secret)).toBeNull();
    expect(JSON.stringify(localStorage) + JSON.stringify(sessionStorage)).not.toContain(secret);
  });
  it.each(["SAML", "OIDC"] as const)("validates and retries %s provider drafts without external discovery, then edits and deletes only the created provider", async (protocol) => {
    const { user, repository, extension } = await open("providers");
    const before = await extension.read("preview");
    await user.click(screen.getByRole("button", { name: "新建身份提供商" }));
    const dialog = screen.getByRole("dialog");
    await user.type(within(dialog).getByLabelText("名称", { exact: true }), "PreviewIdp");
    await user.click(within(dialog).getByRole("combobox", { name: "协议" }));
    await user.click(screen.getByRole("option", { name: protocol }));
    await user.type(within(dialog).getByLabelText("身份提供商 URL"), "https://identity.example.invalid/test");
    await user.type(within(dialog).getByLabelText("客户端 ID / Audience"), "matrix-preview");
    fireEvent.change(within(dialog).getByLabelText("联合元数据 / 签名公钥"), { target: { value: "invalid-document" } });
    await user.click(within(dialog).getByRole("button", { name: "保存" }));
    await waitFor(() => expect(within(dialog).getByRole("alert").textContent).toContain("输入格式"));
    expect(await extension.read("preview")).toEqual(before);
    const metadata = protocol === "SAML" ? '<EntityDescriptor entityID="https://identity.example.invalid/test"></EntityDescriptor>' : '{"keys":[{"kty":"RSA","kid":"MOCK"}]}';
    fireEvent.change(within(dialog).getByLabelText("联合元数据 / 签名公钥"), { target: { value: metadata } });
    vi.mocked(repository.workspace!.execute).mockRejectedValueOnce(new Error("offline"));
    await user.click(within(dialog).getByRole("button", { name: "保存" }));
    await expectRetainedFailure(dialog);
    expect((within(dialog).getByLabelText("联合元数据 / 签名公钥") as HTMLTextAreaElement).value).toBe(metadata);
    await user.click(within(dialog).getByRole("button", { name: "保存" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    const created = (await extension.read("preview")).providers.find((provider) => provider.name === "PreviewIdp")!;
    expect(created.protocol).toBe(protocol);
    await user.click(screen.getByRole("button", { name: "PreviewIdp" }));
    expect(screen.getByRole("region", { name: "联合元数据 / 签名公钥" }).textContent).toBe(metadata);
    await user.click(screen.getByRole("button", { name: "编辑" }));
    await user.click(within(screen.getByRole("dialog")).getByRole("checkbox", { name: "启用" }));
    await user.click(within(screen.getByRole("dialog")).getByRole("button", { name: "保存" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
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
  it("retains key-state failures, requires disable before deletion, and keeps cancellation non-mutating", async () => {
    const { user, repository, extension } = await open("keys");
    const before = await extension.read("preview");
    expect((screen.getByRole("button", { name: "删除" }) as HTMLButtonElement).disabled).toBe(true);
    await user.click(screen.getByRole("button", { name: "禁用" }));
    await user.click(within(screen.getByRole("dialog")).getByRole("button", { name: "取消" }));
    expect(await extension.read("preview")).toEqual(before);
    await user.click(screen.getByRole("button", { name: "禁用" }));
    vi.mocked(repository.workspace!.execute).mockRejectedValueOnce(new Error("offline"));
    await user.click(within(screen.getByRole("dialog")).getByRole("button", { name: "保存" }));
    await expectRetainedFailure(screen.getByRole("dialog"));
    expect(await extension.read("preview")).toEqual(before);
    await user.click(within(screen.getByRole("dialog")).getByRole("button", { name: "保存" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    await user.click(screen.getByRole("button", { name: "删除" }));
    await user.type(screen.getByLabelText("输入名称以确认"), "MOCK-pipeline-key");
    await user.click(within(screen.getByRole("dialog")).getByRole("button", { name: "确认删除" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect((await extension.read("preview")).keys).toEqual([]);
    expect(screen.getByText("暂无记录")).toBeTruthy();
    expect(repository.execute).not.toHaveBeenCalled();
  });
  it.each(["settings", "user-sso"] as const)("retains %s inputs on failure and saves only its owned settings on retry", async (view) => {
    const { user, repository, extension } = await open(view);
    const before = await extension.read("preview");
    if (view === "settings") {
      fireEvent.change(screen.getByLabelText("密码最小长度"), { target: { value: "16" } });
      await user.click(screen.getByRole("checkbox", { name: "登录保护（模拟 MFA）" }));
    } else {
      await select(user, "选择身份提供商", "EnterpriseSSO · SAML");
      await user.click(screen.getByRole("checkbox", { name: "启用用户 SSO（模拟）" }));
    }
    vi.mocked(repository.workspace!.execute).mockRejectedValueOnce(new Error("offline"));
    await user.click(screen.getByRole("button", { name: "保存" }));
    await screen.findByText("暂时无法完成操作，请重试。");
    expect(await extension.read("preview")).toEqual(before);
    await user.click(screen.getByRole("button", { name: "保存" }));
    await waitFor(() => expect((screen.getByRole("button", { name: "保存" }) as HTMLButtonElement).disabled).toBe(true));
    const state = await extension.read("preview");
    expect(state.settings).toEqual({ ...before.settings, ...(view === "settings" ? { passwordMinLength: 16, loginProtection: true } : { userSsoEnabled: true, userSsoProviderId: "idp-example" }) });
    expect(state.providers).toEqual(before.providers);
    expect(state.userPolicies).toEqual(before.userPolicies);
    expect(repository.execute).not.toHaveBeenCalled();
  });
  it("saves SSO settings only to the preview adapter", async () => {
    const { user, repository, extension } = await open("user-sso");
    await screen.findByText(/把企业身份/);
    await select(user, "选择身份提供商", "EnterpriseSSO · SAML");
    await user.click(screen.getByRole("checkbox", { name: "启用用户 SSO（模拟）" }));
    await user.click(screen.getByRole("button", { name: "保存" }));
    expect((await extension.read("preview")).settings.userSsoEnabled).toBe(true);
    expect(repository.execute).not.toHaveBeenCalled();
  });
  it.each(["groups", "simulator"] as const)("never loads the %s preview graph after the directory denies management", async (view) => {
    const { repository } = await open(view, { reader: true });
    await screen.findByText("没有此页面的管理权限");
    expect(repository.workspace?.read).not.toHaveBeenCalled();
    expect(repository.listUsers).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole("button", { name: "新建用户组" })).toBeNull();
  });
  it.each(["keys", "create-policy", "simulator"] as const)("shows an honest unavailable state for %s on the live adapter", async (view) => {
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
    await user.click(await screen.findByRole("button", { name: "导入为子用户" }));
    await user.click(screen.getByRole("checkbox", { name: /Dev Member/ }));
    await user.click(within(screen.getByRole("dialog")).getByRole("button", { name: "导入为子用户" }));
    const state = await extension.read("preview");
    expect(state.enterprises[0]?.importedMemberIds).toEqual(["dev01"]);
    expect(state.settings.userSsoEnabled).toBe(false);
    expect(state.providers).toHaveLength(1);
  });
  it("allowlists report fields instead of exporting a raw account snapshot", async () => {
    const extension = createPreviewAccessWorkspace("org-xiak", () => users.map((user) => user.principal.id), identity.account.primaryPrincipalId);
    const workspace = await extension.read("preview");
    const report = buildAccessReport("security", workspace, buildAccountAccessScene(identity, { items: users, nextAfter: null }, null, { accountId: "org-xiak", scope: "TENANT", installationId: null, items: [] }, { accountId: "org-xiak", scope: "INSTALLATION", installationId: "preview", items: [] }), "2026-09-09T00:00:00Z");
    expect(report.mode).toBe("MOCK");
    expect(JSON.stringify(report)).not.toContain("EntityDescriptor");
    expect(JSON.stringify(report)).not.toContain("preview-only");
    expect(report.users).toHaveLength(2);
  });
});
