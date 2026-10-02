import { act, cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { useState } from "react";
import { LocaleProvider } from "@/i18n/LocaleProvider";
import type { RoleAccessClient, RoleSessionRevokeIntent, ServiceRoleTemplateClient } from "../application/AccountAccessProvider";
import type { AccountAccessView } from "../domain/accounts";
import type { RoleAccess, RoleCapabilityAction, RoleDirectory } from "../domain/roles";
import { AccountLiveRoles } from "./AccountLiveRoles";

const timestamp = "2026-09-21T08:00:00Z";
const role = {
  id: "role-reviewer", accountId: "account-acme", name: "ProductionLogReviewer", description: "Review production logs during an incident",
  tags: [{ key: "team", value: "operations" }], management: "CUSTOMER" as const, status: "ACTIVE" as const,
  maxSessionDurationSeconds: 3600, resourceVersion: 3, currentTrustVersionId: "trust-reviewer-v2", createdAt: timestamp, updatedAt: timestamp
};
const roleActions: RoleCapabilityAction[] = [
  "iam.role.read", "iam.role.update", "iam.role.set-status", "iam.role.delete", "iam.role-trust.set",
  "iam.role-policy-attachment.create", "iam.role.permission-boundary.set", "iam.role.permission-boundary.remove", "iam.role-session.list"
];
const capabilities = roleActions.map((action) => ({
  action, resource: { kind: "ROLE" as const, id: role.id }, available: action !== "iam.role.delete", restrictionReason: action === "iam.role.delete" ? "AUTHORITY_REQUIRED" as const : null
}));
const directory: RoleDirectory = { accountId: role.accountId, items: [{ role, capabilities }], nextAfter: null };
const access: RoleAccess = {
  role,
  trustVersion: {
    id: role.currentTrustVersionId, accountId: role.accountId, roleId: role.id, createdAt: timestamp,
    contentDigest: `sha256:${"a".repeat(64)}`,
    document: { languageVersion: "1", statements: [{ sid: "incident-review", effect: "ALLOW", principals: [{ type: "USER", id: "user-alex" }] }] }
  },
  policyAttachments: [{
    id: "attachment-reviewer", accountId: role.accountId, target: { kind: "ROLE", id: role.id }, policyId: "system.log-reader",
    scope: "TENANT", resourceVersion: 1, createdAt: timestamp, updatedAt: timestamp
  }],
  capabilities: [...capabilities, {
    action: "iam.role.assume", resource: { kind: "ROLE", id: role.id }, available: false, restrictionReason: "AUTHORITY_REQUIRED"
  }, {
    action: "iam.role-policy-attachment.revoke", resource: { kind: "POLICY_ATTACHMENT", id: "attachment-reviewer" }, available: true, restrictionReason: null
  }]
};
const previousTrustVersion = {
  id: "trust-reviewer-v1", accountId: role.accountId, roleId: role.id, createdAt: "2026-09-20T08:00:00Z",
  contentDigest: `sha256:${"b".repeat(64)}`,
  document: { languageVersion: "1" as const, statements: [{ sid: "initial-review", effect: "ALLOW" as const, principals: [{ type: "USER" as const, id: "user-sam" }] }] }
};
const liveSession = {
  id: "rs1.incident-review", accountId: role.accountId, roleId: role.id, sourceUserId: "user-alex", status: "ACTIVE" as const,
  issuedAt: timestamp, expiresAt: "2026-09-21T09:00:00Z", revokedAt: null
};
const liveSessionItem = {
  session: liveSession,
  source: { type: "USER" as const, user: { id: "user-alex", loginName: "alex", displayName: "Alex" } },
  lifecycle: "UNREVOKED" as const,
  revokeCapability: { action: "iam.role-session.revoke" as const, resource: { kind: "ROLE_SESSION" as const, id: liveSession.id }, available: true, restrictionReason: null }
};

async function openServiceAuthorization(user: ReturnType<typeof userEvent.setup>) {
  await user.click(await screen.findByRole("button", { name: "更多操作" }));
  await user.click(within(await screen.findByRole("menu", { name: "更多操作" })).getByRole("menuitem", { name: "服务授权" }));
}
const serviceSession = {
  id: "rs1.service-read", accountId: role.accountId, roleId: role.id, sourceServicePrincipalId: "service-paas-runtime", status: "ACTIVE" as const,
  issuedAt: timestamp, expiresAt: "2026-09-21T08:15:00Z", revokedAt: null
};
const serviceSessionItem = {
  session: serviceSession,
  source: { type: "SERVICE_ACCOUNT" as const, servicePrincipal: { installationId: "installation-paas-primary", principalId: "service-paas-runtime", purpose: "PAAS" as const } },
  lifecycle: "UNREVOKED" as const,
  revokeCapability: { action: "iam.role-session.revoke" as const, resource: { kind: "ROLE_SESSION" as const, id: serviceSession.id }, available: true, restrictionReason: null }
};

function client(overrides: Partial<RoleAccessClient> = {}): RoleAccessClient {
  return {
    accountId: role.accountId,
    sessionRevision: 1,
    canCreate: true,
    createRestrictionReason: null,
    list: vi.fn().mockResolvedValue(directory),
    read: vi.fn().mockResolvedValue(access),
    readPermissionBoundary: vi.fn().mockResolvedValue({ accountId: role.accountId, roleId: role.id, resourceVersion: 2, policy: { policyId: "policy-role-ceiling", versionId: "v3", contentDigest: `sha256:${"c".repeat(64)}` } }),
    listTrustVersions: vi.fn().mockResolvedValue({ accountId: role.accountId, roleId: role.id, items: [previousTrustVersion, access.trustVersion], nextAfter: null }),
    create: vi.fn().mockResolvedValue(role),
    listSessions: vi.fn().mockResolvedValue({ accountId: role.accountId, roleId: role.id, observedAt: timestamp, items: [], nextAfter: null }),
    readSession: vi.fn().mockRejectedValue(new Error("unused session read")),
    revokeSession: vi.fn().mockRejectedValue(new Error("unused session revoke")),
    ...overrides
  };
}

function RolesHarness({ api, serviceRoleTemplates, entityId, onOpen = vi.fn() }: { api: RoleAccessClient; serviceRoleTemplates?: ServiceRoleTemplateClient; entityId?: string; onOpen?: (view: AccountAccessView, id?: string) => void }) {
  const [intent, setIntent] = useState<RoleSessionRevokeIntent | null>(null);
  const changeIntent = (expectedRequestId: string | null, next: RoleSessionRevokeIntent | null) => setIntent((current) => {
    if (expectedRequestId === null) return current ?? next;
    return current?.requestId === expectedRequestId ? next : current;
  });
  return <AccountLiveRoles client={api} serviceRoleTemplates={serviceRoleTemplates} entityId={entityId} onCreate={vi.fn()} onOpen={onOpen} revokeIntent={intent} onRevokeIntentChange={changeIntent} />;
}

afterEach(cleanup);

describe("AccountLiveRoles", () => {
  it("keeps the fixed directory shell visible while only role data loads", async () => {
    let resolve!: (value: RoleDirectory) => void;
    const api = client({ list: vi.fn().mockImplementation(() => new Promise<RoleDirectory>((done) => { resolve = done; })) });
    render(<LocaleProvider><RolesHarness api={api} /></LocaleProvider>);

    expect(screen.getByRole("heading", { name: "角色" })).toBeTruthy();
    expect(screen.getByText("角色是可被信任身份申请的临时身份", { exact: false })).toBeTruthy();
    expect(screen.getByText("正在加载角色目录")).toBeTruthy();
    resolve(directory);
    expect(await screen.findByRole("button", { name: role.name })).toBeTruthy();
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("opens the live service authorization workspace in the content area instead of a dialog", async () => {
    const user = userEvent.setup();
    const serviceRoleTemplates: ServiceRoleTemplateClient = { sessionRevision: 1, load: vi.fn().mockResolvedValue({ status: "ready", directory: { items: [] } }) };
    render(<LocaleProvider><RolesHarness api={client()} serviceRoleTemplates={serviceRoleTemplates} /></LocaleProvider>);

    await screen.findByRole("button", { name: role.name });
    await openServiceAuthorization(user);
    expect(await screen.findByRole("heading", { name: "服务授权" })).toBeTruthy();
    expect(screen.getByRole("tab", { name: "平台模板", selected: true })).toBeTruthy();
    expect(await screen.findByText("暂无已发布模板")).toBeTruthy();
    expect(serviceRoleTemplates.load).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("opens an inline detail with distinct trust, grant and capability evidence", async () => {
    const user = userEvent.setup();
    const api = client();
    render(<LocaleProvider><RolesHarness api={api} entityId={role.id} /></LocaleProvider>);

    expect(screen.getByRole("heading", { name: role.id })).toBeTruthy();
    expect(await screen.findByRole("heading", { name: role.name })).toBeTruthy();
    expect(screen.getByText("角色信任、调用者的扮演权限与角色自身的资源权限是三个独立条件", { exact: false })).toBeTruthy();
    expect(screen.getByText("system.log-reader")).toBeTruthy();
    await user.click(screen.getByRole("tab", { name: "信任策略 (1)" }));
    expect(screen.getByText("USER · user-alex")).toBeTruthy();
    await user.click(screen.getByRole("tab", { name: "当前操作能力" }));
    expect(screen.getByText("iam.role.assume")).toBeTruthy();
    expect(api.listSessions).not.toHaveBeenCalled();
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("loads immutable trust history only on demand and opens a version inline", async () => {
    const user = userEvent.setup();
    const api = client();
    render(<LocaleProvider><RolesHarness api={api} entityId={role.id} /></LocaleProvider>);

    expect(await screen.findByRole("heading", { name: role.name })).toBeTruthy();
    expect(api.listTrustVersions).not.toHaveBeenCalled();
    await user.click(screen.getByRole("tab", { name: "信任版本" }));

    const table = await screen.findByRole("table", { name: "信任版本" });
    expect(api.listTrustVersions).toHaveBeenCalledWith(role.id);
    expect(within(table).getByText("当前版本")).toBeTruthy();
    expect(within(table).getByText("历史版本")).toBeTruthy();
    await user.click(within(table).getByRole("button", { name: previousTrustVersion.id }));
    const detail = screen.getByRole("group", { name: "信任版本详情" });
    expect(within(detail).getByText(previousTrustVersion.contentDigest)).toBeTruthy();
    expect(within(detail).getByText(/user-sam/)).toBeTruthy();
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("keeps role facts mounted while the mandatory permission boundary loads and treats null as closed", async () => {
    let resolveBoundary!: (value: { accountId: string; roleId: string; resourceVersion: number; policy: null }) => void;
    const api = client({ readPermissionBoundary: vi.fn().mockImplementation(() => new Promise((resolve) => { resolveBoundary = resolve; })) });
    render(<LocaleProvider><RolesHarness api={api} entityId={role.id} /></LocaleProvider>);

    expect(await screen.findByRole("heading", { name: role.name })).toBeTruthy();
    expect(screen.getByText(role.id)).toBeTruthy();
    expect(screen.getByRole("status", { name: "正在读取角色权限边界" })).toBeTruthy();
    await act(async () => { resolveBoundary({ accountId: role.accountId, roleId: role.id, resourceVersion: 2, policy: null }); });

    expect(await screen.findByText("未设置权限上限 · 角色承担已关闭")).toBeTruthy();
    expect(screen.getByText("空的角色权限边界不是无限权限；IAM 会拒绝新的角色承担。")).toBeTruthy();
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("keeps a boundary read failure local and never presents it as no boundary", async () => {
    const user = userEvent.setup();
    const readPermissionBoundary = vi.fn()
      .mockRejectedValueOnce(new Error("unavailable"))
      .mockResolvedValueOnce({ accountId: role.accountId, roleId: role.id, resourceVersion: 3,
        policy: { policyId: "policy-role-ceiling", versionId: "v3", contentDigest: `sha256:${"c".repeat(64)}` } });
    render(<LocaleProvider><RolesHarness api={client({ readPermissionBoundary })} entityId={role.id} /></LocaleProvider>);

    expect(await screen.findByText("边界状态未知")).toBeTruthy();
    expect(screen.getByText("IAM 暂时无法确认角色权限边界；这不表示角色没有边界，也不表示可以承担。", { exact: false })).toBeTruthy();
    expect(screen.queryByText("未配置 · 承担已关闭")).toBeNull();
    expect(screen.getByText(role.id)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "重试" }));

    expect(await screen.findByText("policy-role-ceiling")).toBeTruthy();
    expect(screen.getByText("策略版本 v3 · 边界修订 v3")).toBeTruthy();
    expect(readPermissionBoundary).toHaveBeenCalledTimes(2);
  });

  it("keeps platform template, account consent, and workload binding visibly independent", async () => {
    const user = userEvent.setup();
    const template = {
      id: "managedservice.installation-reader", version: 1,
      spec: {
        product: "managedservice", servicePurpose: "PAAS" as const,
        roleName: "ManagedServiceInstallationReader",
        roleDescription: "Allows inspection of one consented installation.",
        policyVersion: { policyId: "system.managedservice-installation-reader", versionId: "version-managedservice-installation-reader-v1", contentDigest: `sha256:${"b".repeat(64)}` },
        workloads: [{ resourceKind: "SERVICE_INSTALLATION", bindAction: "managedservice.installation.bind-service-role", unbindAction: "managedservice.installation.unbind-service-role" }],
        maxSessionDurationSeconds: 900
      },
      contentDigest: `sha256:${"c".repeat(64)}`, status: "ACTIVE" as const
    };
    const serviceRoleTemplates: ServiceRoleTemplateClient = { sessionRevision: 1, load: vi.fn().mockResolvedValue({ status: "ready", directory: { items: [template] } }) };
    render(<LocaleProvider><RolesHarness api={client()} serviceRoleTemplates={serviceRoleTemplates} /></LocaleProvider>);

    await openServiceAuthorization(user);
    await user.click(await screen.findByRole("button", { name: template.id }));

    const chain = screen.getByRole("heading", { name: "服务授权链" }).closest("section")!;
    expect(within(chain).getByText("平台模板")).toBeTruthy();
    expect(within(chain).getByText("账号同意")).toBeTruthy();
    expect(within(chain).getByText("资源绑定")).toBeTruthy();
    expect(within(chain).getByText("运行时使用")).toBeTruthy();
    expect(within(chain).getAllByText("在账号授权中单独确认")).toHaveLength(2);
    expect(within(chain).getByText("在运行边界中单独观察")).toBeTruthy();
    expect(screen.queryByRole("button", { name: /授权|撤销/ })).toBeNull();
  });

  it("loads live sessions only on demand and preserves one revoke request through an unknown outcome", async () => {
    const user = userEvent.setup();
    const revoked = { ...liveSession, status: "REVOKED" as const, revokedAt: "2026-09-21T08:31:00Z" };
    const api = client({
      listSessions: vi.fn().mockResolvedValue({ accountId: role.accountId, roleId: role.id, observedAt: "2026-09-21T08:30:00Z", items: [liveSessionItem], nextAfter: null }),
      readSession: vi.fn().mockResolvedValue({ observedAt: "2026-09-21T08:30:10Z", item: liveSessionItem }),
      revokeSession: vi.fn().mockRejectedValueOnce(new Error("connection lost")).mockResolvedValue({ outcome: "APPLIED", session: revoked })
    });
    render(<LocaleProvider><RolesHarness api={api} entityId={role.id} /></LocaleProvider>);

    expect(await screen.findByRole("heading", { name: role.name })).toBeTruthy();
    expect(api.listSessions).not.toHaveBeenCalled();
    await user.click(screen.getByRole("tab", { name: "角色会话" }));
    expect(await screen.findByText(liveSession.id)).toBeTruthy();
    expect(within(screen.getByRole("table", { name: "角色会话" })).queryByRole("columnheader", { name: "操作" })).toBeNull();
    await user.click(screen.getByRole("button", { name: `会话 ${liveSession.id} 的操作` }));
    await user.click(screen.getByRole("menuitem", { name: "撤销会话" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    const workflow = screen.getByRole("group", { name: "撤销会话" });
    await user.click(within(workflow).getByRole("button", { name: "撤销会话" }));
    expect(await within(workflow).findByText("撤销结果尚未确认", { exact: false })).toBeTruthy();
    const originalRequestId = vi.mocked(api.revokeSession).mock.calls[0]?.[2];
    await user.click(within(workflow).getByRole("button", { name: "取消" }));
    expect(await screen.findByText("仍有一个结果未知的撤销请求", { exact: false })).toBeTruthy();
    await user.click(screen.getByRole("tab", { name: "角色权限策略 (1)" }));
    await user.click(screen.getByRole("tab", { name: "角色会话" }));
    await user.click(await screen.findByRole("button", { name: "继续处理未知结果" }));
    let resumed = screen.getByRole("group", { name: "撤销会话" });
    expect(within(resumed).getByText(originalRequestId ?? "missing")).toBeTruthy();
    await user.click(within(resumed).getByRole("button", { name: "读取权威状态" }));
    expect(await within(resumed).findByText("仍观测为未撤销", { exact: false })).toBeTruthy();
    await user.click(within(resumed).getByRole("button", { name: "返回会话目录" }));
    await user.click(await screen.findByRole("button", { name: "继续处理未知结果" }));
    resumed = screen.getByRole("group", { name: "撤销会话" });
    await user.click(within(resumed).getByRole("button", { name: "重试原请求" }));
    expect(await screen.findByRole("heading", { name: "没有匹配的角色会话" })).toBeTruthy();
    const revoke = vi.mocked(api.revokeSession);
    expect(revoke.mock.calls[1]?.[2]).toBe(revoke.mock.calls[0]?.[2]);
    expect(api.readSession).toHaveBeenCalledWith(role.id, liveSession.id);
    expect(document.activeElement).toBe(screen.getByRole("heading", { name: "角色会话" }));
  });

  it("renders service-account lineage and sends closed source filters", async () => {
    const user = userEvent.setup();
    const listSessions = vi.fn().mockImplementation((_roleId, filter) => {
      const candidates = filter.sourceType === "USER" ? [liveSessionItem]
        : filter.sourceType === "SERVICE_ACCOUNT" ? [serviceSessionItem] : [liveSessionItem, serviceSessionItem];
      const items = !filter.exactId ? candidates : candidates.filter((item) => filter.exactKind === "session"
        ? item.session.id === filter.exactId
        : filter.exactKind === "sourceUser" ? item.source.type === "USER" && item.source.user.id === filter.exactId
          : item.source.type === "SERVICE_ACCOUNT" && item.source.servicePrincipal.principalId === filter.exactId);
      return Promise.resolve({ accountId: role.accountId, roleId: role.id, observedAt: timestamp, items, nextAfter: null });
    });
    render(<LocaleProvider><RolesHarness api={client({ listSessions })} entityId={role.id} /></LocaleProvider>);

    await user.click(await screen.findByRole("tab", { name: "角色会话" }));
    const initial = await screen.findByRole("table", { name: "角色会话" });
    expect(initial.textContent).toContain("service-paas-runtime");
    expect(initial.textContent).toContain("installation-paas-primary");
    expect(initial.textContent).toContain("PAAS");

    await user.click(screen.getByRole("button", { name: "筛选" }));
    await user.click(screen.getByRole("combobox", { name: "来源类型" }));
    await user.click(screen.getByRole("option", { name: "服务账号" }));
    await waitFor(() => expect(listSessions).toHaveBeenLastCalledWith(role.id, expect.objectContaining({ sourceType: "SERVICE_ACCOUNT" })));
    expect(screen.getByRole("table", { name: "角色会话" }).textContent).not.toContain("user-alex");

    await user.click(screen.getByRole("combobox", { name: "精确查询字段" }));
    await user.click(screen.getByRole("option", { name: "服务主体 ID" }));
    await user.type(screen.getByRole("searchbox", { name: "输入完整服务主体 ID" }), "service-paas-runtime");
    await waitFor(() => expect(listSessions).toHaveBeenLastCalledWith(role.id, {
      exactKind: "sourceServicePrincipal", exactId: "service-paas-runtime", sourceType: "SERVICE_ACCOUNT", lifecycle: "UNREVOKED"
    }));
  });

  it("does not let a late empty-window continuation overwrite a newer lifecycle filter", async () => {
    const user = userEvent.setup();
    let resolveLate!: (value: Awaited<ReturnType<RoleAccessClient["listSessions"]>>) => void;
    const expiredSession = { ...liveSession, id: "rs2.expired", expiresAt: "2026-09-21T08:15:00Z" };
    const expiredItem = {
      ...liveSessionItem,
      session: expiredSession,
      lifecycle: "EXPIRED" as const,
      revokeCapability: { ...liveSessionItem.revokeCapability, resource: { kind: "ROLE_SESSION" as const, id: expiredSession.id }, available: false, restrictionReason: "SESSION_NOT_REVOCABLE" as const }
    };
    const lateSession = { ...liveSession, id: "rs3.late" };
    const lateItem = { ...liveSessionItem, session: lateSession, revokeCapability: { ...liveSessionItem.revokeCapability, resource: { kind: "ROLE_SESSION" as const, id: lateSession.id } } };
    const api = client({
      listSessions: vi.fn().mockImplementation((_roleId, filter, after) => {
        if (after) return new Promise((resolve) => { resolveLate = resolve; });
        if (filter.lifecycle === "ALL") return Promise.resolve({ accountId: role.accountId, roleId: role.id, observedAt: "2026-09-21T08:30:00Z", items: [expiredItem], nextAfter: null });
        return Promise.resolve({ accountId: role.accountId, roleId: role.id, observedAt: "2026-09-21T08:30:00Z", items: [], nextAfter: "ic1.unrevoked" });
      })
    });
    render(<LocaleProvider><RolesHarness api={api} entityId={role.id} /></LocaleProvider>);

    await user.click(await screen.findByRole("tab", { name: "角色会话" }));
    expect(await screen.findByRole("heading", { name: "当前扫描窗口没有匹配会话" })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "继续扫描" }));
    await user.click(screen.getByRole("button", { name: "筛选" }));
    await user.click(screen.getByRole("combobox", { name: "会话生命周期" }));
    await user.click(screen.getByRole("option", { name: "全部历史" }));
    expect(await screen.findByText(expiredSession.id)).toBeTruthy();
    await act(async () => resolveLate({ accountId: role.accountId, roleId: role.id, observedAt: "2026-09-21T08:31:00Z", items: [lateItem], nextAfter: null }));
    await waitFor(() => expect(screen.queryByText(lateSession.id)).toBeNull());
    expect(screen.getByText(expiredSession.id)).toBeTruthy();
  });

  it("treats an authoritative expired observation as terminal without offering another revoke", async () => {
    const user = userEvent.setup();
    const expiredSession = { ...liveSession, expiresAt: "2026-09-21T08:15:00Z" };
    const expiredItem = { ...liveSessionItem, session: expiredSession, lifecycle: "EXPIRED" as const, revokeCapability: { ...liveSessionItem.revokeCapability, available: false, restrictionReason: "SESSION_NOT_REVOCABLE" as const } };
    const api = client({
      listSessions: vi.fn().mockResolvedValue({ accountId: role.accountId, roleId: role.id, observedAt: "2026-09-21T08:10:00Z", items: [liveSessionItem], nextAfter: null }),
      readSession: vi.fn().mockResolvedValue({ observedAt: "2026-09-21T08:30:00Z", item: expiredItem }),
      revokeSession: vi.fn().mockRejectedValue(new Error("connection lost"))
    });
    render(<LocaleProvider><RolesHarness api={api} entityId={role.id} /></LocaleProvider>);

    await user.click(await screen.findByRole("tab", { name: "角色会话" }));
    await user.click(await screen.findByRole("button", { name: `会话 ${liveSession.id} 的操作` }));
    await user.click(screen.getByRole("menuitem", { name: "撤销会话" }));
    let workflow = screen.getByRole("group", { name: "撤销会话" });
    await user.click(within(workflow).getByRole("button", { name: "撤销会话" }));
    workflow = await screen.findByRole("group", { name: "撤销会话" });
    await user.click(within(workflow).getByRole("button", { name: "读取权威状态" }));
    expect(await within(workflow).findByText("权威状态为已到期", { exact: false })).toBeTruthy();
    expect(within(workflow).queryByRole("button", { name: "重试原请求" })).toBeNull();
  });

  it("shows a local LIVE error and never substitutes preview role data", async () => {
    const api = client({ list: vi.fn().mockRejectedValue(new Error("network")) });
    render(<LocaleProvider><RolesHarness api={api} /></LocaleProvider>);

    expect(await screen.findByRole("heading", { name: "角色目录暂时不可用" })).toBeTruthy();
    expect(screen.queryByText("SupportRole")).toBeNull();
    expect(screen.getByRole("button", { name: "重试" })).toBeTruthy();
  });
});
