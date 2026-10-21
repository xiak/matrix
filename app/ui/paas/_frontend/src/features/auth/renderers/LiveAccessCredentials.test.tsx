import { act, cleanup, render as renderRoot, screen, waitFor, within } from "@testing-library/react";
import { useState, type ReactNode } from "react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { LocaleProvider } from "@/i18n/LocaleProvider";
import { UnsavedChangesProvider, useLeaveConfirmation } from "@ui/xiak";
import { HttpProblem } from "@/infrastructure/http/jsonRequest";
import type { AccessKeyClient, AccessKeyCreateIntent, AccessKeyMutationIntent, AccountSecuritySettingsClient, AuthorizationProfileClient, AuthorizationProfileLoad } from "../application/AccountAccessProvider";
import type { AuthorizationProfileDirectory } from "../domain/accounts";
import type { AccessKeyAccess, AccessKeyDirectory } from "../domain/accessKeys";
import type { AccountAccessScene, AccountUserScene } from "../scenes/accountAccessScene";
import { LiveAccessCredentials } from "./LiveAccessCredentials";

const owner: AccountUserScene = {
  accountType: "subuser", accountId: "account-acme", id: "user-alex", name: "Alex", loginName: "alex", source: "local", qualifiedName: "alex@acme",
  protected: false, credentialProtection: null, enabled: true, resourceVersion: 2, state: "active",
  canRead: true, readRestrictionReason: null, canUpdate: true, updateRestrictionReason: null, canDelete: true, deleteRestrictionReason: null,
  canSetStatus: true, statusRestrictionReason: null, canResetPassword: true, passwordRestrictionReason: null,
  canAttachTenantPolicy: true, tenantAttachmentRestrictionReason: null, canAttachPlatformPolicy: false, platformAttachmentRestrictionReason: null,
  canSetPermissionBoundary: true, permissionBoundarySetRestrictionReason: null, canRemovePermissionBoundary: true, permissionBoundaryRemoveRestrictionReason: null,
  attachments: []
};
const scene = { accountId: "account-acme", accountOwner: { id: "root-acme" }, canListUsers: true, isRoot: true, users: [owner] } as unknown as AccountAccessScene;
const key = { id: "mak1.alex-primary", accountId: scene.accountId, userId: owner.id, status: "ENABLED" as const, resourceVersion: 1,
  credentialState: "CURRENT" as const,
  networkRestrictions: { allowedSourceCidrs: ["198.51.100.0/24"] },
  createdAt: "2026-09-21T08:00:00Z", updatedAt: "2026-09-21T08:00:00Z" };
const directory = {
  accountId: scene.accountId, userId: owner.id, userResourceVersion: owner.resourceVersion,
  capabilities: [{ action: "iam.access-key.create" as const, resource: { kind: "USER" as const, id: owner.id }, available: true, restrictionReason: null }],
  items: [{ key, usage: { observedAt: "2026-09-21T08:10:00Z", lastAuthorization: {
    evaluatedAt: "2026-09-21T08:09:00Z", allowed: false, product: "audit", action: "audit.record.read", sourceIp: "198.51.100.42"
  } }, capabilities: [
    { action: "iam.access-key.read" as const, resource: { kind: "ACCESS_KEY" as const, id: key.id }, available: true, restrictionReason: null },
    { action: "iam.access-key.set-status" as const, resource: { kind: "ACCESS_KEY" as const, id: key.id }, available: true, restrictionReason: null },
    { action: "iam.access-key.set-network-restrictions" as const, resource: { kind: "ACCESS_KEY" as const, id: key.id }, available: true, restrictionReason: null },
    { action: "iam.access-key.delete" as const, resource: { kind: "ACCESS_KEY" as const, id: key.id }, available: false, restrictionReason: "TARGET_MUST_BE_DISABLED" as const }
  ] }]
};
const replacementKey = { ...key, id: "mak1.alex-replacement", resourceVersion: 2, updatedAt: "2026-09-21T09:00:00Z" };
const replacementDirectory = {
  ...directory,
  items: [{ ...directory.items[0]!, key: replacementKey, capabilities: directory.items[0]!.capabilities.map((entry) => ({
    ...entry, resource: { ...entry.resource, id: replacementKey.id }
  })) }]
};

function client(overrides: Partial<AccessKeyClient> = {}): AccessKeyClient {
  return {
    accountId: scene.accountId,
    list: vi.fn().mockResolvedValue(directory),
    read: vi.fn().mockResolvedValue(directory.items[0]),
    create: vi.fn().mockResolvedValue({ outcome: "APPLIED", key: { ...key, id: "mak1.alex-rotated" }, secret: "mak1.one-time-secret" }),
    acknowledgeIssued: vi.fn().mockReturnValue(true),
    acknowledgeMutation: vi.fn().mockReturnValue(true),
    setStatus: vi.fn(),
    setNetworkRestrictions: vi.fn(),
    delete: vi.fn(),
    ...overrides
  };
}

function settings(): AccountSecuritySettingsClient {
  return { identity: "settings-view-one", accountId: scene.accountId, principalId: "root-acme", sessionId: "session-one", sessionRevision: 1,
    canRead: true, canUpdate: false, load: vi.fn().mockResolvedValue({ status: "ready", settings: {
    accountId: scene.accountId, resourceVersion: 4, mfa: { requiredForUsers: true },
    password: { minimumLength: 15, requireLowercase: true, requireUppercase: true, requireDigit: true, requireSymbol: true, historyCount: 3, maxAgeDays: 90, expiryMode: "CHANGE_PASSWORD" },
    session: { idleTimeoutMinutes: 30 }, accessKeyNetwork: { allowedSourceCidrs: ["2001:db8::/32"] }, updatedAt: "2026-09-21T08:00:00Z"
  } }) };
}

function render(value: ReactNode) {
  return renderRoot(value, { wrapper: UnsavedChangesProvider });
}

afterEach(cleanup);

describe("LiveAccessCredentials", () => {
  it("mounts the selected user and directory identity before access-key rows resolve", async () => {
    let resolveDirectory!: (value: typeof directory) => void;
    const api = client({ list: vi.fn(() => new Promise<typeof directory>((resolve) => { resolveDirectory = resolve; })) });
    render(<LocaleProvider><LiveAccessCredentials client={api} scene={scene} scopedOwner={owner as unknown as AccountAccessScene["users"][number]} /></LocaleProvider>);

    expect(screen.getByRole("heading", { name: "访问密钥" })).toBeTruthy();
    expect(screen.getByRole("heading", { name: "用户访问密钥" })).toBeTruthy();
    expect(screen.getByText("正在读取该用户的访问密钥…").closest('[role="status"]')).toBeTruthy();
    expect(screen.queryByRole("table", { name: "访问密钥" })).toBeNull();

    await waitFor(() => expect(api.list).toHaveBeenCalledWith(owner.id));
    await act(async () => resolveDirectory(directory));
    expect(await screen.findByRole("button", { name: key.id })).toBeTruthy();
  });

  it("binds directory and detail reads to the exact client while preserving the selected user frame", async () => {
    let resolveOldDetail!: (value: typeof directory.items[0]) => void;
    let resolveReplacement!: (value: typeof replacementDirectory) => void;
    const first = client({ read: vi.fn(() => new Promise<AccessKeyAccess>((resolve) => { resolveOldDetail = resolve; })) });
    const replacement = client({
      list: vi.fn(() => new Promise<AccessKeyDirectory>((resolve) => { resolveReplacement = resolve; })),
      read: vi.fn().mockResolvedValue(replacementDirectory.items[0])
    });
    const user = userEvent.setup();
    const view = render(<LocaleProvider><LiveAccessCredentials client={first} scene={scene} scopedOwner={owner as unknown as AccountAccessScene["users"][number]} /></LocaleProvider>);

    await user.click(await screen.findByRole("button", { name: key.id }));
    expect(screen.getByRole("heading", { name: key.id })).toBeTruthy();

    view.rerender(<LocaleProvider><LiveAccessCredentials client={replacement} scene={scene} scopedOwner={owner as unknown as AccountAccessScene["users"][number]} /></LocaleProvider>);
    expect(screen.getByRole("heading", { name: "访问密钥" })).toBeTruthy();
    expect(screen.queryByRole("heading", { name: key.id })).toBeNull();
    expect(screen.queryByRole("button", { name: key.id })).toBeNull();
    expect(screen.getByText("正在读取该用户的访问密钥…").closest('[role="status"]')).toBeTruthy();

    await waitFor(() => expect(replacement.list).toHaveBeenCalledWith(owner.id));
    await act(async () => resolveReplacement(replacementDirectory));
    expect(await screen.findByRole("button", { name: replacementKey.id })).toBeTruthy();
    expect(screen.queryByRole("button", { name: key.id })).toBeNull();
    await user.click(screen.getByRole("button", { name: replacementKey.id }));
    expect(await screen.findByRole("heading", { name: replacementKey.id })).toBeTruthy();

    await act(async () => resolveOldDetail(directory.items[0]!));
    expect(screen.getByRole("heading", { name: replacementKey.id })).toBeTruthy();
    expect(screen.queryByRole("heading", { name: key.id })).toBeNull();
  });

  it("opens a known user's keys in context without a second user directory", async () => {
    const api = client();
    render(<LocaleProvider><LiveAccessCredentials accountSecuritySettings={settings()} client={api} scene={scene} scopedOwner={owner as unknown as AccountAccessScene["users"][number]} /></LocaleProvider>);

    expect(screen.getByRole("heading", { name: "访问密钥" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "管理 alex 的访问密钥" })).toBeNull();
    expect(await screen.findByRole("button", { name: key.id })).toBeTruthy();
    const table = screen.getByRole("table", { name: "访问密钥" });
    expect(within(table).getAllByRole("columnheader")).toHaveLength(5);
    expect(within(table).getByRole("columnheader", { name: "凭据状态" })).toBeTruthy();
    expect(within(table).getByRole("columnheader", { name: "管理状态" })).toBeTruthy();
    expect(within(table).getByText("未被恢复围栏")).toBeTruthy();
    expect(within(table).getByRole("columnheader", { name: "安全观测" })).toBeTruthy();
    expect(await within(table).findByText("账号 + 密钥")).toBeTruthy();
    expect(within(table).getByText("有历史观测")).toBeTruthy();
    expect(api.list).toHaveBeenCalledWith(owner.id);
    expect(screen.queryByText("本页使用固定的访问密钥管理契约", { exact: false })).toBeNull();
  });

  it("keeps a scoped IAM denial local instead of showing mock keys", async () => {
    const api = client({ list: vi.fn().mockRejectedValue(new HttpProblem(403, "AUTHORITY_REQUIRED")) });
    render(<LocaleProvider><LiveAccessCredentials client={api} scene={scene} scopedOwner={owner as unknown as AccountAccessScene["users"][number]} /></LocaleProvider>);

    const failure = await screen.findByRole("alert", { name: "无法读取访问密钥" });
    expect(within(failure).getByText(/当前身份没有管理该用户访问密钥的权限/)).toBeTruthy();
    expect(within(failure).getByText(/联系账号管理员核对授权/)).toBeTruthy();
    expect(within(failure).queryByRole("button", { name: "重试读取" })).toBeNull();
    expect(screen.queryByRole("table", { name: "访问密钥" })).toBeNull();
    expect(screen.getByRole("button", { name: "新建访问密钥" }).hasAttribute("disabled")).toBe(true);
  });

  it.each([
    ["iam.route.notfound", "当前运行环境无法提供兼容的访问密钥功能；这不代表账号或用户尚未开通服务。"],
    ["PRIVATE_ACCESS_KEY_TARGET", "IAM 未确认指定用户或访问密钥可读取；它可能不存在，或当前身份无法确认。这不代表访问密钥功能未接入。"]
  ])("distinguishes a missing access-key route from an unconfirmed target for %s", async (code, message) => {
    const list = vi.fn().mockRejectedValue(new HttpProblem(404, code));
    const api = client({ list });
    render(<LocaleProvider><LiveAccessCredentials client={api} scene={scene} scopedOwner={owner as unknown as AccountAccessScene["users"][number]} /></LocaleProvider>);

    expect(await screen.findByText(message)).toBeTruthy();
    expect(screen.queryByRole("table", { name: "访问密钥" })).toBeNull();
    expect(screen.queryByRole("button", { name: "重试读取" })).toBeNull();
    expect(list).toHaveBeenCalledExactlyOnceWith(owner.id);
  });

  it("keeps known key evidence visible when the account network rule is unavailable", async () => {
    const evidenceUnknown = { ...directory, items: [{ ...directory.items[0]!, usage: { observedAt: "2026-09-21T08:10:00Z" } }] };
    const api = client({ list: vi.fn().mockResolvedValue(evidenceUnknown) });
    render(<LocaleProvider><LiveAccessCredentials client={api} scene={scene} scopedOwner={owner as unknown as AccountAccessScene["users"][number]} /></LocaleProvider>);

    const table = await screen.findByRole("table", { name: "访问密钥" });
    expect(within(table).getByText("密钥层已限制 · 账号层未知")).toBeTruthy();
    expect(within(table).getByText("保留证据中未知")).toBeTruthy();
    expect(screen.queryByText("从未使用")).toBeNull();
  });

  it("shows fixed LIVE network and authorization evidence and updates only the key layer", async () => {
    const user = userEvent.setup();
    const changedDirectory = { ...directory, items: [{ ...directory.items[0]!, key: {
      ...key, networkRestrictions: { allowedSourceCidrs: ["203.0.113.0/24"] }, resourceVersion: 2
    } }] };
    const setNetworkRestrictions = vi.fn().mockResolvedValue({ outcome: "APPLIED", key: {
      ...key, networkRestrictions: { allowedSourceCidrs: ["203.0.113.0/24"] }, resourceVersion: 2
    } });
    const api = client({ list: vi.fn().mockResolvedValueOnce(directory).mockResolvedValueOnce(changedDirectory), setNetworkRestrictions });
    render(<LocaleProvider><LiveAccessCredentials accountSecuritySettings={settings()} client={api} scene={scene} scopedOwner={owner as unknown as AccountAccessScene["users"][number]} /></LocaleProvider>);

    await user.click(await screen.findByRole("button", { name: key.id }));
    expect(await screen.findByRole("heading", { name: "最近授权观测" })).toBeTruthy();
    expect(screen.getByText("audit.record.read")).toBeTruthy();
    expect(screen.getByText("拒绝")).toBeTruthy();
    expect(screen.getByText(/最近一次拒绝也不证明密钥已禁用/)).toBeTruthy();

    await user.click(screen.getByRole("button", { name: "更多操作" }));
    await user.click(within(screen.getByRole("menu", { name: "更多操作" })).getByRole("menuitem", { name: "配置来源网络" }));
    const field = screen.getByRole("textbox", { name: "允许的来源 CIDR" });
    await user.clear(field);
    await user.type(field, "203.0.113.0/24");
    await user.click(screen.getByRole("button", { name: "保存来源限制" }));
    await waitFor(() => expect(setNetworkRestrictions).toHaveBeenCalledWith(owner.id, key.id, expect.objectContaining({
      accessKeyResourceVersion: 1, networkRestrictions: { allowedSourceCidrs: ["203.0.113.0/24"] }
    })));
    await waitFor(() => expect(api.list).toHaveBeenCalledTimes(2));
    expect(api.acknowledgeMutation).toHaveBeenCalledOnce();
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("keeps a completed key change locked when its authoritative reread fails and retries only that reread", async () => {
    const user = userEvent.setup();
    const changedDirectory = { ...directory, items: [{ ...directory.items[0]!, key: {
      ...key, networkRestrictions: { allowedSourceCidrs: ["203.0.113.0/24"] }, resourceVersion: 2
    } }] };
    const list = vi.fn().mockResolvedValueOnce(directory).mockRejectedValueOnce(new HttpProblem(503, "IAM_UNAVAILABLE")).mockResolvedValueOnce(changedDirectory);
    const setNetworkRestrictions = vi.fn().mockResolvedValue({ outcome: "APPLIED", key: changedDirectory.items[0]!.key });
    const api = client({ list, setNetworkRestrictions });
    render(<LocaleProvider><LiveAccessCredentials client={api} scene={scene} scopedOwner={owner as unknown as AccountAccessScene["users"][number]} /></LocaleProvider>);

    await user.click(await screen.findByRole("button", { name: key.id }));
    await user.click(screen.getByRole("button", { name: "更多操作" }));
    await user.click(within(screen.getByRole("menu", { name: "更多操作" })).getByRole("menuitem", { name: "配置来源网络" }));
    const field = screen.getByRole("textbox", { name: "允许的来源 CIDR" });
    await user.clear(field);
    await user.type(field, "203.0.113.0/24");
    await user.click(screen.getByRole("button", { name: "保存来源限制" }));

    expect(await screen.findByText("原操作已有非秘密完成结果。不会再次提交写请求；请重新读取该用户的权威密钥目录后结束处置。")).toBeTruthy();
    expect(api.acknowledgeMutation).not.toHaveBeenCalled();
    expect(setNetworkRestrictions).toHaveBeenCalledOnce();
    await user.click(screen.getByRole("button", { name: "重新读取当前状态" }));
    await waitFor(() => expect(api.acknowledgeMutation).toHaveBeenCalledOnce());
    expect(setNetworkRestrictions).toHaveBeenCalledOnce();
    expect(list).toHaveBeenCalledTimes(3);
  });

  it("rereads a completed AccessKey mutation without requiring the revoked write capability", async () => {
    const user = userEvent.setup();
    const readOnlyDirectory = { ...directory, items: [{ ...directory.items[0]!, capabilities: directory.items[0]!.capabilities.map((item) =>
      item.action === "iam.access-key.set-network-restrictions" ? { ...item, available: false, restrictionReason: "AUTHORITY_REQUIRED" as const } : item) }] };
    const mutationIntent: AccessKeyMutationIntent = {
      accountId: scene.accountId, actorId: "root-acme", userId: owner.id, accessKeyId: key.id,
      accessKeyResourceVersion: key.resourceVersion, operation: "set-network-restrictions",
      networkRestrictions: key.networkRestrictions, requestId: `ui-access-key-network-${"a".repeat(32)}`, phase: "completed"
    };
    const api = client({ list: vi.fn().mockResolvedValue(readOnlyDirectory) });
    render(<LocaleProvider><LiveAccessCredentials client={api} mutationIntent={mutationIntent} scene={scene} scopedOwner={owner as unknown as AccountAccessScene["users"][number]} /></LocaleProvider>);
    await user.click(await screen.findByRole("button", { name: "继续处理原请求" }));
    const reread = screen.getByRole("button", { name: "重新读取当前状态" });
    expect(reread.hasAttribute("disabled")).toBe(false);
    await user.click(reread);
    await waitFor(() => expect(api.acknowledgeMutation).toHaveBeenCalledWith(mutationIntent.requestId));
    expect(api.list).toHaveBeenCalledTimes(2);
    expect(api.setNetworkRestrictions).not.toHaveBeenCalled();
  });

  it("replays an uncertain delete even when the key row is already absent, then acknowledges only after the full list reread", async () => {
    const user = userEvent.setup();
    const emptyDirectory: AccessKeyDirectory = { ...directory, items: [] };
    const mutationIntent: AccessKeyMutationIntent = {
      accountId: scene.accountId, actorId: "root-acme", userId: owner.id, accessKeyId: key.id,
      accessKeyResourceVersion: key.resourceVersion, operation: "delete",
      requestId: `ui-access-key-delete-${"d".repeat(32)}`, phase: "unknown"
    };
    const remove = vi.fn().mockResolvedValue({ outcome: "EQUAL_REPLAY", deletion: {
      id: key.id, accountId: scene.accountId, userId: owner.id, resourceVersion: 2, deletedAt: "2026-09-21T09:00:00Z"
    } });
    const api = client({ list: vi.fn().mockResolvedValue(emptyDirectory), delete: remove });
    render(<LocaleProvider><LiveAccessCredentials client={api} mutationIntent={mutationIntent} scene={scene} scopedOwner={owner as unknown as AccountAccessScene["users"][number]} /></LocaleProvider>);

    await user.click(await screen.findByRole("button", { name: "继续处理原请求" }));
    expect(screen.getByText("当前目录中已找不到这把密钥。这可能是原删除已经生效，但目录缺少该行本身不能证明结果；仍须重放原删除并完成权威回读。")).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "重试原请求" }));
    await waitFor(() => expect(remove).toHaveBeenCalledWith(owner.id, key.id, {
      accessKeyResourceVersion: key.resourceVersion, requestId: mutationIntent.requestId
    }));
    expect(api.list).toHaveBeenCalledTimes(2);
    expect(api.acknowledgeMutation).toHaveBeenCalledWith(mutationIntent.requestId);
  });

  it("uses the shared detail title and stable page actions instead of repeating key controls in the body", async () => {
    const user = userEvent.setup();
    render(<LocaleProvider><LiveAccessCredentials client={client()} scene={scene} /></LocaleProvider>);

    await user.click(screen.getByRole("button", { name: "管理 alex 的访问密钥" }));
    await user.click(await screen.findByRole("button", { name: key.id }));

    expect(await screen.findByRole("heading", { level: 1, name: key.id })).toBeTruthy();
    expect(screen.queryByRole("heading", { level: 2, name: key.id })).toBeNull();
    expect(screen.getByRole("button", { name: "禁用" })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "更多操作" }));
    const menu = within(screen.getByRole("menu", { name: "更多操作" }));
    expect(menu.getByRole("menuitem", { name: "配置来源网络" }).getAttribute("aria-disabled")).toBeNull();
    const remove = menu.getByRole("menuitem", { name: "删除" });
    expect(remove.getAttribute("aria-disabled")).toBe("true");
    expect(document.getElementById(remove.getAttribute("aria-describedby")!)?.textContent).toBe("请先禁用密钥，再执行删除。");
    await user.keyboard("{Escape}");
    await user.click(screen.getByRole("button", { name: "返回列表" }));
    expect(screen.getByRole("heading", { level: 1, name: "alex · 访问密钥" })).toBeTruthy();
    expect(screen.getByRole("button", { name: key.id })).toBeTruthy();
  });

  it("never presents enable or network editing as a repair for a recovery-fenced LIVE key", async () => {
    const user = userEvent.setup();
    const fencedKey = { ...key, credentialState: "RECOVERY_FENCED" as const };
    const fencedDirectory = { ...directory, items: [{ ...directory.items[0]!, key: fencedKey }] };
    const api = client({ list: vi.fn().mockResolvedValue(fencedDirectory), read: vi.fn().mockResolvedValue(fencedDirectory.items[0]) });
    render(<LocaleProvider><LiveAccessCredentials client={api} scene={scene} scopedOwner={owner as unknown as AccountAccessScene["users"][number]} /></LocaleProvider>);

    const table = await screen.findByRole("table", { name: "访问密钥" });
    expect(within(table).getByText("恢复后永久失效")).toBeTruthy();
    expect(within(table).getByText("已启用")).toBeTruthy();
    await user.click(within(table).getByRole("button", { name: fencedKey.id }));
    expect(await screen.findByText(/原密钥已因恢复永久失效/)).toBeTruthy();
    expect(screen.getByRole("button", { name: "禁用" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "启用" })).toBeNull();
    await user.click(screen.getByRole("button", { name: "更多操作" }));
    const menu = within(screen.getByRole("menu", { name: "更多操作" }));
    expect(menu.getByRole("menuitem", { name: "创建新密钥" })).toBeTruthy();
    expect(menu.queryByRole("menuitem", { name: "配置来源网络" })).toBeNull();
    expect(menu.getByRole("menuitem", { name: "删除" }).getAttribute("aria-disabled")).toBe("true");
  });

  it("loads only the selected user's directory and keeps fixed page content visible", async () => {
    const user = userEvent.setup();
    const api = client();
    render(<LocaleProvider><LiveAccessCredentials client={api} scene={scene} /></LocaleProvider>);

    expect(screen.getByRole("heading", { name: "访问密钥" })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "管理 alex 的访问密钥" }));
    expect(screen.getByRole("heading", { name: "alex · 访问密钥" })).toBeTruthy();
    expect(await screen.findByRole("button", { name: key.id })).toBeTruthy();
    expect(api.list).toHaveBeenCalledWith(owner.id);
    expect(screen.getByText("本页按用户管理真实访问密钥生命周期", { exact: false })).toBeTruthy();
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("resolves an original-intent owner outside the loaded user page only after an explicit exact read", async () => {
    const user = userEvent.setup();
    const offPageOwner = { ...owner, id: "user-auditor", name: "Auditor", loginName: "auditor", qualifiedName: "auditor@acme", resourceVersion: 5 };
    const offPageDirectory: AccessKeyDirectory = {
      ...directory,
      userId: offPageOwner.id,
      userResourceVersion: offPageOwner.resourceVersion,
      capabilities: directory.capabilities.map((entry) => ({ ...entry, resource: { ...entry.resource, id: offPageOwner.id } })),
      items: []
    };
    const intent: AccessKeyCreateIntent = {
      accountId: scene.accountId, actorId: "root-acme", userId: offPageOwner.id, userResourceVersion: offPageOwner.resourceVersion,
      networkRestrictions: { allowedSourceCidrs: [] }, requestId: `ui-access-key-create-${"e".repeat(32)}`, phase: "unknown"
    };
    const api = client({ list: vi.fn().mockResolvedValue(offPageDirectory) });
    const loadOwner = vi.fn().mockResolvedValue(offPageOwner);
    const failedDirectoryScene = { ...scene, directoryFailures: { users: "unavailable" } } as AccountAccessScene;
    render(<LocaleProvider><LiveAccessCredentials client={api} createIntent={intent} loadOwner={loadOwner} scene={failedDirectoryScene} /></LocaleProvider>);

    expect(api.list).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "继续处理原请求" }));
    expect(loadOwner).toHaveBeenCalledExactlyOnceWith(offPageOwner.id);
    expect(await screen.findByRole("heading", { level: 1, name: "auditor · 访问密钥" })).toBeTruthy();
    await waitFor(() => expect(api.list).toHaveBeenCalledExactlyOnceWith(offPageOwner.id));
    expect(api.create).not.toHaveBeenCalled();

    await user.click(await screen.findByRole("button", { name: "继续处理原请求" }));
    expect(screen.getByText(intent.requestId)).toBeTruthy();
    expect(api.create).not.toHaveBeenCalled();
  });

  it.each(["rejected", "wrong-user"] as const)("keeps the exact mutation intent locked when its owner read is %s", async (failure) => {
    const user = userEvent.setup();
    const intent: AccessKeyMutationIntent = {
      accountId: scene.accountId, actorId: "root-acme", userId: "user-auditor", accessKeyId: "key-auditor",
      accessKeyResourceVersion: 2, requestId: `ui-access-key-delete-${"a".repeat(32)}`, phase: "unknown", operation: "delete"
    };
    const api = client();
    const loadOwner = failure === "rejected"
      ? vi.fn().mockRejectedValue(new Error("UNAVAILABLE")) : vi.fn().mockResolvedValue(owner);
    render(<LocaleProvider><LiveAccessCredentials client={api} mutationIntent={intent} loadOwner={loadOwner}
      scene={{ ...scene, directoryFailures: { users: "unavailable" } } as AccountAccessScene} /></LocaleProvider>);

    await user.click(screen.getByRole("button", { name: "继续处理原请求" }));
    expect(await screen.findByText(`无法读取原请求所属用户 ${intent.userId}。原请求仍保持锁定且不会自动重放；请重试精确读取。`)).toBeTruthy();
    expect(loadOwner).toHaveBeenCalledExactlyOnceWith(intent.userId);
    expect((screen.getByRole("button", { name: "继续处理原请求" }) as HTMLButtonElement).disabled).toBe(false);
    expect(api.list).not.toHaveBeenCalled();
    expect(api.create).not.toHaveBeenCalled();
    expect(api.setStatus).not.toHaveBeenCalled();
    expect(api.setNetworkRestrictions).not.toHaveBeenCalled();
    expect(api.delete).not.toHaveBeenCalled();
  });

  it("ignores an original owner's late resolution after the AccessKey client changes", async () => {
    const user = userEvent.setup();
    const offPageOwner = { ...owner, id: "user-auditor", loginName: "auditor" };
    const intent: AccessKeyCreateIntent = {
      accountId: scene.accountId, actorId: "root-acme", userId: offPageOwner.id, userResourceVersion: 5,
      networkRestrictions: { allowedSourceCidrs: [] }, requestId: `ui-access-key-create-${"f".repeat(32)}`, phase: "unknown"
    };
    let resolveOwner!: (value: typeof offPageOwner) => void;
    const loadOwner = vi.fn(() => new Promise<typeof offPageOwner>((resolve) => { resolveOwner = resolve; }));
    const first = client();
    const replacement = client();
    const view = render(<LocaleProvider><LiveAccessCredentials client={first} createIntent={intent} loadOwner={loadOwner} scene={scene} /></LocaleProvider>);

    await user.click(screen.getByRole("button", { name: "继续处理原请求" }));
    expect(loadOwner).toHaveBeenCalledExactlyOnceWith(intent.userId);
    view.rerender(<LocaleProvider><LiveAccessCredentials client={replacement} createIntent={intent} loadOwner={loadOwner} scene={scene} /></LocaleProvider>);
    await act(async () => resolveOwner(offPageOwner));
    expect(screen.queryByRole("heading", { name: "auditor · 访问密钥" })).toBeNull();
    expect(first.list).not.toHaveBeenCalled();
    expect(replacement.list).not.toHaveBeenCalled();
    expect(first.create).not.toHaveBeenCalled();
    expect(replacement.create).not.toHaveBeenCalled();
  });

  it("loads the shared product credential boundary only after the user asks for it", async () => {
    const user = userEvent.setup();
    const api = client();
    const load = vi.fn().mockResolvedValue({ status: "ready", directory: {
      accountId: scene.accountId,
      items: [{ profile: { product: "paas", revision: 7, callingService: "PAAS", actions: [
        { action: "paas.application.create", resourceKind: "APPLICATION", scope: "TENANT", subjectTypes: ["ROLE", "USER"],
          userAuthenticationMethods: ["ACCESS_KEY", "LOGIN_SESSION"],
          resourceShapes: [{ mode: "COLLECTION", prefixAllowed: false, collectionUsage: "COLLECTION_CREATE" }] }
      ] }, contentDigest: `sha256:${"a".repeat(64)}` }]
    } });
    const authorizationProfiles: AuthorizationProfileClient = { accountId: scene.accountId, preview: false, load };
    const onInspectPermissions = vi.fn();
    render(<LocaleProvider><LiveAccessCredentials authorizationProfiles={authorizationProfiles} client={api} scene={scene} onInspectPermissions={onInspectPermissions} /></LocaleProvider>);

    await user.click(screen.getByRole("button", { name: "管理 alex 的访问密钥" }));
    await screen.findByRole("button", { name: key.id });
    expect(load).not.toHaveBeenCalled();
    await user.click(screen.getByText("编程访问边界"));
    expect(await screen.findByText("paas.application.create")).toBeTruthy();
    expect(screen.getByText("权限声明修订 7")).toBeTruthy();
    expect(screen.queryByText("创建 Application 的请求结果")).toBeNull();
    expect(load).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole("dialog")).toBeNull();
    await user.click(screen.getByRole("button", { name: "核对该用户的权限来源" }));
    expect(onInspectPermissions).toHaveBeenCalledWith(owner.id);
  });

  it("reloads an open product credential boundary for the exact replacement catalog client", async () => {
    const user = userEvent.setup();
    const api = client();
    const firstDirectory: AuthorizationProfileDirectory = { accountId: scene.accountId, items: [{ profile: {
      product: "paas", revision: 7, callingService: "PAAS", actions: [{
        action: "paas.application.create", resourceKind: "APPLICATION", scope: "TENANT", subjectTypes: ["USER"],
        userAuthenticationMethods: ["ACCESS_KEY"], resourceShapes: [{ mode: "COLLECTION", prefixAllowed: false, collectionUsage: "COLLECTION_CREATE" }]
      }]
    }, contentDigest: `sha256:${"a".repeat(64)}` }] };
    const replacementDirectory: AuthorizationProfileDirectory = { accountId: scene.accountId, items: [{ profile: {
      product: "audit", revision: 4, callingService: "AUDIT", actions: [{
        action: "audit.record.read", resourceKind: "AUDIT_RECORD", scope: "TENANT", subjectTypes: ["USER"],
        userAuthenticationMethods: ["ACCESS_KEY"], resourceShapes: [{ mode: "COLLECTION", prefixAllowed: false, collectionUsage: "COLLECTION_LIST" }]
      }]
    }, contentDigest: `sha256:${"b".repeat(64)}` }] };
    const first: AuthorizationProfileClient = { accountId: scene.accountId, preview: false, load: vi.fn().mockResolvedValue({ status: "ready", directory: firstDirectory }) };
    let resolveReplacement!: (value: AuthorizationProfileLoad) => void;
    const replacement: AuthorizationProfileClient = { accountId: scene.accountId, preview: false, load: vi.fn(() => new Promise<AuthorizationProfileLoad>((resolve) => { resolveReplacement = resolve; })) };
    const view = render(<LocaleProvider><LiveAccessCredentials authorizationProfiles={first} client={api} scene={scene} /></LocaleProvider>);

    await user.click(screen.getByRole("button", { name: "管理 alex 的访问密钥" }));
    await screen.findByRole("button", { name: key.id });
    await user.click(screen.getByText("编程访问边界"));
    expect(await screen.findByText("paas.application.create")).toBeTruthy();

    view.rerender(<LocaleProvider><LiveAccessCredentials authorizationProfiles={replacement} client={api} scene={scene} /></LocaleProvider>);
    expect(screen.queryByText("paas.application.create")).toBeNull();
    await waitFor(() => expect(replacement.load).toHaveBeenCalledTimes(1));
    expect(screen.getByText("正在读取当前权限能力目录…")).toBeTruthy();

    await act(async () => resolveReplacement({ status: "ready", directory: replacementDirectory }));
    expect(await screen.findByText("audit.record.read")).toBeTruthy();
    expect(screen.queryByText("paas.application.create")).toBeNull();
  });

  it("reveals an applied Secret once and clears it after acknowledgement", async () => {
    const user = userEvent.setup();
    const api = client();
    render(<LocaleProvider><LiveAccessCredentials client={api} scene={scene} /></LocaleProvider>);

    await user.click(screen.getByRole("button", { name: "管理 alex 的访问密钥" }));
    await screen.findByRole("button", { name: key.id });
    await user.click(screen.getByRole("button", { name: "新建访问密钥" }));
    const review = screen.getByRole("heading", { name: "核对并创建访问密钥" });
    expect(review).toBeTruthy();
    expect(screen.queryByText("操作标识")).toBeNull();
    expect(screen.queryByText("用户资源版本")).toBeNull();
    await user.click(screen.getByRole("button", { name: "确认创建" }));

    expect(await screen.findByText("mak1.one-time-secret")).toBeTruthy();
    expect(screen.getByText("LIVE")).toBeTruthy();
    await user.click(screen.getByRole("checkbox", { name: "我已将 Secret 保存到受保护的位置，并理解它无法再次显示" }));
    await user.click(screen.getByRole("button", { name: "已完成" }));
    expect(screen.queryByText("mak1.one-time-secret")).toBeNull();
    expect(api.create).toHaveBeenCalledWith(owner.id, expect.objectContaining({ networkRestrictions: { allowedSourceCidrs: [] } }));
    expect(api.acknowledgeIssued).toHaveBeenCalledOnce();
  });

  it("guards an applied one-time Secret until an explicit leave clears the mounted workflow", async () => {
    const user = userEvent.setup();
    const api = client();
    function Fixture() {
      const requestLeave = useLeaveConfirmation();
      const [open, setOpen] = useState(true);
      return <LocaleProvider>{open ? <LiveAccessCredentials client={api} scene={scene} /> : <p>destination-page</p>}
        <button onClick={() => requestLeave(() => setOpen(false))}>navigate-away</button>
      </LocaleProvider>;
    }
    render(<Fixture />);

    await user.click(screen.getByRole("button", { name: "管理 alex 的访问密钥" }));
    await screen.findByRole("button", { name: key.id });
    await user.click(screen.getByRole("button", { name: "新建访问密钥" }));
    await user.click(screen.getByRole("button", { name: "确认创建" }));
    expect(await screen.findByText("mak1.one-time-secret")).toBeTruthy();

    await user.click(screen.getByRole("button", { name: "navigate-away" }));
    expect(screen.getByRole("dialog", { name: "离开并隐藏一次性 Secret？" })).toBeTruthy();
    expect(screen.getByText("mak1.one-time-secret")).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "留在此页" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(screen.getByText("mak1.one-time-secret")).toBeTruthy();

    await user.click(screen.getByRole("button", { name: "navigate-away" }));
    await user.click(screen.getByRole("button", { name: "清除 Secret 并离开" }));
    expect(await screen.findByText("destination-page")).toBeTruthy();
    expect(screen.queryByText("mak1.one-time-secret")).toBeNull();
    expect(api.acknowledgeIssued).not.toHaveBeenCalled();
  });

  it("removes an unacknowledged one-time Secret immediately when the client changes", async () => {
    const user = userEvent.setup();
    const first = client();
    let resolveReplacement!: (value: typeof replacementDirectory) => void;
    const replacement = client({ list: vi.fn(() => new Promise<AccessKeyDirectory>((resolve) => { resolveReplacement = resolve; })) });
    const view = render(<LocaleProvider><LiveAccessCredentials client={first} scene={scene} /></LocaleProvider>);

    await user.click(screen.getByRole("button", { name: "管理 alex 的访问密钥" }));
    await screen.findByRole("button", { name: key.id });
    await user.click(screen.getByRole("button", { name: "新建访问密钥" }));
    await user.click(screen.getByRole("button", { name: "确认创建" }));
    expect(await screen.findByText("mak1.one-time-secret")).toBeTruthy();

    view.rerender(<LocaleProvider><LiveAccessCredentials client={replacement} scene={scene} /></LocaleProvider>);
    expect(screen.queryByText("mak1.one-time-secret")).toBeNull();
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(screen.getByRole("heading", { level: 1, name: "alex · 访问密钥" })).toBeTruthy();
    expect(screen.getByText("正在读取该用户的访问密钥…").closest('[role="status"]')).toBeTruthy();

    await waitFor(() => expect(replacement.list).toHaveBeenCalledWith(owner.id));
    await act(async () => resolveReplacement(replacementDirectory));
    expect(await screen.findByRole("button", { name: replacementKey.id })).toBeTruthy();
    view.rerender(<LocaleProvider><LiveAccessCredentials client={first} scene={scene} /></LocaleProvider>);
    expect(screen.queryByText("mak1.one-time-secret")).toBeNull();
    expect(first.acknowledgeIssued).not.toHaveBeenCalled();
    expect(replacement.acknowledgeIssued).not.toHaveBeenCalled();
  });

  it("retains the original requestId when an uncertain create is retried", async () => {
    const user = userEvent.setup();
    const create = vi.fn()
      .mockRejectedValueOnce(new HttpProblem(503, "iam.unavailable"))
      .mockResolvedValueOnce({ outcome: "EQUAL_REPLAY", key });
    const api = client({ create });
    render(<LocaleProvider><LiveAccessCredentials client={api} scene={scene} /></LocaleProvider>);

    await user.click(screen.getByRole("button", { name: "管理 alex 的访问密钥" }));
    await screen.findByRole("button", { name: key.id });
    await user.click(screen.getByRole("button", { name: "新建访问密钥" }));
    await user.click(screen.getByRole("button", { name: "确认创建" }));
    expect(await screen.findByText("不要重复发起创建", { exact: false })).toBeTruthy();
    expect(screen.getByText("操作标识")).toBeTruthy();
    expect(screen.getByText(/^ui-access-key-create-/)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "确认创建" }));
    expect(await screen.findByRole("heading", { name: "原创建请求已完成" })).toBeTruthy();

    await waitFor(() => expect(create).toHaveBeenCalledTimes(2));
    expect(create.mock.calls[0]?.[1].requestId).toBe(create.mock.calls[1]?.[1].requestId);
    expect(screen.getByText("Secret 无法再次显示", { exact: false })).toBeTruthy();
  });

  it("resumes an unknown request after the content view remounts without offering a second creation", async () => {
    const user = userEvent.setup();
    const intent: AccessKeyCreateIntent = { accountId: scene.accountId, actorId: "root-acme", userId: owner.id,
      userResourceVersion: owner.resourceVersion, networkRestrictions: { allowedSourceCidrs: [] }, requestId: `ui-access-key-create-${"a".repeat(32)}`, phase: "unknown" };
    const create = vi.fn().mockResolvedValue({ outcome: "EQUAL_REPLAY", key });
    const api = client({ create });
    const view = render(<LocaleProvider><LiveAccessCredentials client={api} scene={scene} createIntent={intent} scopedOwner={owner as unknown as AccountAccessScene["users"][number]} /></LocaleProvider>);
    await screen.findByRole("button", { name: key.id });
    expect(screen.getByRole("button", { name: "新建访问密钥" }).hasAttribute("disabled")).toBe(true);
    view.unmount();
    render(<LocaleProvider><LiveAccessCredentials client={api} scene={scene} createIntent={intent} scopedOwner={owner as unknown as AccountAccessScene["users"][number]} /></LocaleProvider>);
    await user.click(await screen.findByRole("button", { name: "继续处理原请求" }));
    expect(screen.getByText(intent.requestId)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "重试原请求" }));
    expect(await screen.findByRole("heading", { name: "原创建请求已完成" })).toBeTruthy();
    expect(create).toHaveBeenCalledWith(owner.id, { userResourceVersion: intent.userResourceVersion, networkRestrictions: intent.networkRestrictions, requestId: intent.requestId });
    expect(screen.queryByText("mak1.one-time-secret")).toBeNull();
  });

  it("keeps an unknown creation locked but refuses to replay it through a replacement client", async () => {
    const intent: AccessKeyCreateIntent = { accountId: scene.accountId, actorId: "root-acme", userId: owner.id,
      userResourceVersion: owner.resourceVersion, networkRestrictions: { allowedSourceCidrs: [] }, requestId: `ui-access-key-create-${"b".repeat(32)}`, phase: "unknown" };
    const first = client();
    const replacement = client();
    const view = render(<LocaleProvider><LiveAccessCredentials client={first} scene={scene} createIntent={intent} scopedOwner={owner as unknown as AccountAccessScene["users"][number]} /></LocaleProvider>);
    expect(await screen.findByRole("button", { name: "继续处理原请求" })).toBeTruthy();

    view.rerender(<LocaleProvider><LiveAccessCredentials client={replacement} scene={scene} createIntent={intent} scopedOwner={owner as unknown as AccountAccessScene["users"][number]} /></LocaleProvider>);
    expect(await screen.findByText(`后端连接已切换，原创建请求 ${intent.requestId} 不会通过当前连接重放。新建仍保持锁定；请恢复原连接或按操作标识核对结果。`)).toBeTruthy();
    expect(screen.queryByRole("button", { name: "继续处理原请求" })).toBeNull();
    expect(screen.getByRole("button", { name: "新建访问密钥" }).hasAttribute("disabled")).toBe(true);
    expect(first.create).not.toHaveBeenCalled();
    expect(replacement.create).not.toHaveBeenCalled();
  });

  it("keeps an unknown mutation locked but refuses to replay it through a replacement client", async () => {
    const mutationIntent: AccessKeyMutationIntent = {
      accountId: scene.accountId, actorId: "root-acme", userId: owner.id, accessKeyId: key.id,
      accessKeyResourceVersion: key.resourceVersion, operation: "set-status", status: "DISABLED",
      requestId: `ui-access-key-status-${"c".repeat(32)}`, phase: "unknown"
    };
    const first = client();
    const replacement = client();
    const view = render(<LocaleProvider><LiveAccessCredentials client={first} mutationIntent={mutationIntent} scene={scene} scopedOwner={owner as unknown as AccountAccessScene["users"][number]} /></LocaleProvider>);
    expect(await screen.findByRole("button", { name: "继续处理原请求" })).toBeTruthy();

    view.rerender(<LocaleProvider><LiveAccessCredentials client={replacement} mutationIntent={mutationIntent} scene={scene} scopedOwner={owner as unknown as AccountAccessScene["users"][number]} /></LocaleProvider>);
    expect(await screen.findByText(`后端连接已切换，原访问密钥操作 ${mutationIntent.requestId} 不会通过当前连接重放。请恢复原连接后继续核对。`)).toBeTruthy();
    expect(screen.queryByRole("button", { name: "继续处理原请求" })).toBeNull();
    expect(first.setStatus).not.toHaveBeenCalled();
    expect(replacement.setStatus).not.toHaveBeenCalled();
  });
});
