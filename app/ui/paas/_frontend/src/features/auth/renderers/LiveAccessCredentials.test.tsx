import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { LocaleProvider } from "@/i18n/LocaleProvider";
import { HttpProblem } from "@/infrastructure/http/jsonRequest";
import type { AccessKeyClient, AccessKeyCreateIntent, AccountSecuritySettingsClient, AuthorizationProfileClient } from "../application/AccountAccessProvider";
import type { AccountAccessScene } from "../scenes/accountAccessScene";
import { LiveAccessCredentials } from "./LiveAccessCredentials";

const owner = {
  accountType: "subuser", id: "user-alex", name: "Alex", loginName: "alex", source: "local", qualifiedName: "alex@acme",
  protected: false, credentialProtection: null, enabled: true, resourceVersion: 2, state: "active",
  canRead: true, readRestrictionReason: null, canUpdate: true, updateRestrictionReason: null, canDelete: true, deleteRestrictionReason: null,
  canSetStatus: true, statusRestrictionReason: null, canResetPassword: true, passwordRestrictionReason: null,
  canAttachTenantPolicy: true, tenantAttachmentRestrictionReason: null, canAttachPlatformPolicy: false, platformAttachmentRestrictionReason: null,
  canSetPermissionBoundary: true, permissionBoundarySetRestrictionReason: null, canRemovePermissionBoundary: true, permissionBoundaryRemoveRestrictionReason: null,
  attachments: []
} as const;
const scene = { accountId: "account-acme", accountOwner: { id: "root-acme" }, users: [owner] } as unknown as AccountAccessScene;
const key = { id: "mak1.alex-primary", accountId: scene.accountId, userId: owner.id, status: "ENABLED" as const, resourceVersion: 1,
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

function client(overrides: Partial<AccessKeyClient> = {}): AccessKeyClient {
  return {
    accountId: scene.accountId,
    list: vi.fn().mockResolvedValue(directory),
    read: vi.fn().mockResolvedValue(directory.items[0]),
    create: vi.fn().mockResolvedValue({ outcome: "APPLIED", key: { ...key, id: "mak1.alex-rotated" }, secret: "mak1.one-time-secret" }),
    acknowledgeIssued: vi.fn().mockReturnValue(true),
    setStatus: vi.fn(),
    setNetworkRestrictions: vi.fn(),
    delete: vi.fn(),
    ...overrides
  };
}

function settings(): AccountSecuritySettingsClient {
  return { accountId: scene.accountId, principalId: "root-acme", sessionId: "session-one", sessionRevision: 1, load: vi.fn().mockResolvedValue({ status: "ready", settings: {
    accountId: scene.accountId, resourceVersion: 4, mfa: { requiredForUsers: true },
    password: { minimumLength: 15, requireLowercase: true, requireUppercase: true, requireDigit: true, requireSymbol: true, historyCount: 3, maxAgeDays: 90, expiryMode: "CHANGE_PASSWORD" },
    session: { idleTimeoutMinutes: 30 }, accessKeyNetwork: { allowedSourceCidrs: ["2001:db8::/32"] }, updatedAt: "2026-09-21T08:00:00Z"
  } }) };
}

afterEach(cleanup);

describe("LiveAccessCredentials", () => {
  it("opens a known user's keys in context without a second user directory", async () => {
    const api = client();
    render(<LocaleProvider><LiveAccessCredentials accountSecuritySettings={settings()} client={api} scene={scene} scopedOwner={owner as unknown as AccountAccessScene["users"][number]} /></LocaleProvider>);

    expect(screen.getByRole("heading", { name: "访问密钥" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "管理 alex 的访问密钥" })).toBeNull();
    expect(await screen.findByRole("button", { name: key.id })).toBeTruthy();
    const table = screen.getByRole("table", { name: "访问密钥" });
    expect(within(table).getAllByRole("columnheader")).toHaveLength(4);
    expect(within(table).getByRole("columnheader", { name: "安全观测" })).toBeTruthy();
    expect(await within(table).findByText("账号 + 密钥")).toBeTruthy();
    expect(within(table).getByText("有历史观测")).toBeTruthy();
    expect(api.list).toHaveBeenCalledWith(owner.id);
    expect(screen.queryByText("本页使用固定的访问密钥管理契约", { exact: false })).toBeNull();
  });

  it("keeps a scoped IAM denial local instead of showing mock keys", async () => {
    const api = client({ list: vi.fn().mockRejectedValue(new HttpProblem(403, "AUTHORITY_REQUIRED")) });
    render(<LocaleProvider><LiveAccessCredentials client={api} scene={scene} scopedOwner={owner as unknown as AccountAccessScene["users"][number]} /></LocaleProvider>);

    expect(await screen.findByText("当前身份没有管理该用户访问密钥的权限。")).toBeTruthy();
    expect(screen.queryByRole("table", { name: "访问密钥" })).toBeNull();
    expect(screen.getByRole("button", { name: "新建访问密钥" }).hasAttribute("disabled")).toBe(true);
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
    const setNetworkRestrictions = vi.fn().mockResolvedValue({ outcome: "APPLIED", key: {
      ...key, networkRestrictions: { allowedSourceCidrs: ["203.0.113.0/24"] }, resourceVersion: 2
    } });
    const api = client({ setNetworkRestrictions });
    render(<LocaleProvider><LiveAccessCredentials accountSecuritySettings={settings()} client={api} scene={scene} scopedOwner={owner as unknown as AccountAccessScene["users"][number]} /></LocaleProvider>);

    await user.click(await screen.findByRole("button", { name: key.id }));
    expect(await screen.findByRole("heading", { name: "最近授权观测" })).toBeTruthy();
    expect(screen.getByText("audit.record.read")).toBeTruthy();
    expect(screen.getByText("拒绝")).toBeTruthy();
    expect(screen.getByText(/最近一次拒绝也不证明密钥已禁用/)).toBeTruthy();

    await user.click(screen.getByRole("button", { name: "配置来源网络" }));
    const field = screen.getByRole("textbox", { name: "允许的来源 CIDR" });
    await user.clear(field);
    await user.type(field, "203.0.113.0/24");
    await user.click(screen.getByRole("button", { name: "保存来源限制" }));
    await waitFor(() => expect(setNetworkRestrictions).toHaveBeenCalledWith(owner.id, key.id, expect.objectContaining({
      accessKeyResourceVersion: 1, networkRestrictions: { allowedSourceCidrs: ["203.0.113.0/24"] }
    })));
    expect(screen.queryByRole("dialog")).toBeNull();
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
});
