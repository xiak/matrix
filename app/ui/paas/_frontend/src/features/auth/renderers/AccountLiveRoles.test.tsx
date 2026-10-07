import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { useState } from "react";
import { UnsavedChangesProvider } from "@ui/xiak";
import { LocaleProvider } from "@/i18n/LocaleProvider";
import { HttpProblem } from "@/infrastructure/http/jsonRequest";
import type { RoleAccessClient, RoleSessionRevokeIntent, ServiceRoleTemplateClient } from "../application/AccountAccessProvider";
import type { AccountAccessView, AccountPolicy } from "../domain/accounts";
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
const boundaryPolicy: AccountPolicy = {
  id: "policy-role-boundary-v2", management: "CUSTOMER", accountId: role.accountId, displayName: "Production role ceiling",
  scope: "TENANT", status: "ACTIVE", defaultVersionId: "v8", resourceVersion: 7, createdAt: timestamp, updatedAt: timestamp
};
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
async function chooseRoleBoundary(user: ReturnType<typeof userEvent.setup>, label: string) {
  await user.click(screen.getByRole("combobox", { name: "权限边界" }));
  await user.click(await screen.findByRole("option", { name: label }));
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
    actorPrincipalId: "root-acme",
    sessionRevision: 1,
    canCreate: true,
    createRestrictionReason: null,
    list: vi.fn().mockResolvedValue(directory),
    read: vi.fn().mockResolvedValue(access),
    readPermissionBoundary: vi.fn().mockResolvedValue({ accountId: role.accountId, roleId: role.id, resourceVersion: 2, policy: { policyId: "policy-role-ceiling", versionId: "v3", contentDigest: `sha256:${"c".repeat(64)}` } }),
    listTenantPolicies: vi.fn().mockResolvedValue({ items: [], available: true }),
    setPermissionBoundary: vi.fn().mockRejectedValue(new Error("unused boundary set")),
    removePermissionBoundary: vi.fn().mockRejectedValue(new Error("unused boundary removal")),
    listTrustVersions: vi.fn().mockResolvedValue({ accountId: role.accountId, roleId: role.id, items: [previousTrustVersion, access.trustVersion], nextAfter: null }),
    create: vi.fn().mockResolvedValue(role),
    update: vi.fn().mockResolvedValue({ ...role, resourceVersion: role.resourceVersion + 1 }),
    setStatus: vi.fn().mockResolvedValue({ ...role, resourceVersion: role.resourceVersion + 1 }),
    setTrustPolicy: vi.fn().mockResolvedValue({ ...role, resourceVersion: role.resourceVersion + 1 }),
    delete: vi.fn().mockResolvedValue({ id: role.id, accountId: role.accountId, name: role.name, resourceVersion: role.resourceVersion + 1, revokedPolicyAttachments: 1, deletedAt: timestamp }),
    createPolicyAttachment: vi.fn().mockResolvedValue(access.policyAttachments[0]),
    revokePolicyAttachment: vi.fn().mockResolvedValue({ id: access.policyAttachments[0]!.id, resourceVersion: 2, revokedAt: timestamp }),
    inspectPolicyAttachmentChange: vi.fn().mockRejectedValue(new Error("unused policy attachment completion")),
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
  return <UnsavedChangesProvider><AccountLiveRoles client={api} serviceRoleTemplates={serviceRoleTemplates} entityId={entityId} onCreate={vi.fn()} onOpen={onOpen} revokeIntent={intent} onRevokeIntentChange={changeIntent} /></UnsavedChangesProvider>;
}

afterEach(() => { cleanup(); sessionStorage.clear(); });

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

  it("routes service authorization to its addressable content workspace instead of opening local state", async () => {
    const user = userEvent.setup();
    const onOpen = vi.fn();
    const serviceRoleTemplates: ServiceRoleTemplateClient = { sessionRevision: 1, load: vi.fn().mockResolvedValue({ status: "ready", directory: { items: [] } }) };
    render(<LocaleProvider><RolesHarness api={client()} serviceRoleTemplates={serviceRoleTemplates} onOpen={onOpen} /></LocaleProvider>);

    await screen.findByRole("button", { name: role.name });
    await openServiceAuthorization(user);
    expect(onOpen).toHaveBeenCalledWith("service-authorizations");
    expect(serviceRoleTemplates.load).not.toHaveBeenCalled();
    expect(screen.getByRole("heading", { name: "角色" })).toBeTruthy();
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

  it("edits complete role metadata inline and retries one uncertain command byte-for-byte", async () => {
    const user = userEvent.setup();
    const updatedRole = { ...role, description: "Review retained audit logs", resourceVersion: role.resourceVersion + 1 };
    const updatedAccess = { ...access, role: updatedRole };
    const update = vi.fn().mockRejectedValueOnce(new HttpProblem(503, "IAM_UNAVAILABLE")).mockResolvedValue(updatedRole);
    const api = client({ read: vi.fn().mockResolvedValueOnce(access).mockResolvedValue(updatedAccess), update });
    render(<LocaleProvider><RolesHarness api={api} entityId={role.id} /></LocaleProvider>);

    await user.click(await screen.findByRole("button", { name: "编辑角色信息" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    const description = screen.getByLabelText("描述");
    await user.clear(description);
    await user.type(description, updatedRole.description);
    await user.click(screen.getByRole("button", { name: "审阅变更" }));
    expect(screen.getByText("完整替换角色名称", { exact: false })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "确认更新" }));
    expect(await screen.findByText("提交结果尚未确认", { exact: false })).toBeTruthy();
    const original = update.mock.calls[0];
    await user.click(screen.getByRole("button", { name: "取消" }));
    expect(await screen.findByText("会失去用于安全重试的冻结请求 ID", { exact: false })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "继续编辑" }));
    await user.click(screen.getByRole("button", { name: "重试原请求" }));

    await waitFor(() => expect(update).toHaveBeenCalledTimes(2));
    expect(update.mock.calls[1]).toEqual(original);
    expect(original?.[0]).toBe(role.id);
    expect(original?.[1]).toMatchObject({ description: updatedRole.description, resourceVersion: role.resourceVersion, requestId: expect.stringMatching(/^role-update-/) });
    expect(await screen.findByText(updatedRole.description)).toBeTruthy();
    expect(screen.queryByRole("group", { name: "编辑角色信息" })).toBeNull();
  });

  it("replaces only a valid R1 USER trust document from an inline review", async () => {
    const user = userEvent.setup();
    const nextDocument = { languageVersion: "1" as const, statements: [{ sid: "audit-review", effect: "ALLOW" as const, principals: [{ type: "USER" as const, id: "user-sam" }] }] };
    const updatedRole = { ...role, currentTrustVersionId: "trust-reviewer-v3", resourceVersion: role.resourceVersion + 1 };
    const updatedAccess: RoleAccess = { ...access, role: updatedRole, trustVersion: { ...access.trustVersion, id: updatedRole.currentTrustVersionId, document: nextDocument } };
    const setTrustPolicy = vi.fn().mockResolvedValue(updatedRole);
    const api = client({ read: vi.fn().mockResolvedValueOnce(access).mockResolvedValue(updatedAccess), setTrustPolicy });
    render(<LocaleProvider><RolesHarness api={api} entityId={role.id} /></LocaleProvider>);

    await user.click(await screen.findByRole("tab", { name: "信任策略 (1)" }));
    await user.click(screen.getByRole("button", { name: "修改信任关系" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    const editor = screen.getByLabelText("同账号 USER 信任文档预览");
    fireEvent.change(editor, { target: { value: JSON.stringify({ languageVersion: "1", statements: [{ sid: "service", effect: "ALLOW", principals: [{ type: "SERVICE", id: "paas" }] }] }) } });
    await user.click(screen.getByRole("button", { name: "审阅信任关系变更" }));
    expect(await screen.findByText("请输入有效的 R1 信任文档", { exact: false })).toBeTruthy();
    expect(setTrustPolicy).not.toHaveBeenCalled();

    fireEvent.change(editor, { target: { value: JSON.stringify(nextDocument, null, 2) } });
    await user.click(screen.getByRole("button", { name: "审阅信任关系变更" }));
    expect(screen.getByText("新文档会完整替换当前信任策略", { exact: false })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "确认替换信任策略" }));

    await waitFor(() => expect(setTrustPolicy).toHaveBeenCalledWith(role.id, expect.objectContaining({ document: nextDocument, resourceVersion: role.resourceVersion, requestId: expect.stringMatching(/^role-trust-/) })));
    expect(await screen.findByText("USER · user-sam")).toBeTruthy();
  });

  it("attaches one active tenant policy from an inline relationship workflow", async () => {
    const user = userEvent.setup();
    const attachment = { id: "attachment-boundary", accountId: role.accountId, target: { kind: "ROLE" as const, id: role.id }, policyId: boundaryPolicy.id,
      scope: "TENANT" as const, resourceVersion: 1, createdAt: timestamp, updatedAt: timestamp };
    const updatedAccess: RoleAccess = { ...access, policyAttachments: [...access.policyAttachments, attachment], capabilities: [...access.capabilities, {
      action: "iam.role-policy-attachment.revoke", resource: { kind: "POLICY_ATTACHMENT", id: attachment.id }, available: true, restrictionReason: null
    }] };
    const createPolicyAttachment = vi.fn().mockResolvedValue(attachment);
    const api = client({ listTenantPolicies: vi.fn().mockResolvedValue({ items: [boundaryPolicy], available: true }), createPolicyAttachment,
      read: vi.fn().mockResolvedValueOnce(access).mockResolvedValue(updatedAccess) });
    render(<LocaleProvider><RolesHarness api={api} entityId={role.id} /></LocaleProvider>);

    await user.click(await screen.findByRole("button", { name: "关联策略" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    await user.click(await screen.findByRole("combobox", { name: "要关联的策略" }));
    await user.click(await screen.findByRole("option", { name: `${boundaryPolicy.displayName} · ${boundaryPolicy.id}` }));
    await user.click(screen.getByRole("button", { name: "审阅变更" }));
    await user.click(screen.getByRole("button", { name: "确认关联策略" }));

    await waitFor(() => expect(createPolicyAttachment).toHaveBeenCalledWith(role.id, expect.objectContaining({ policyId: boundaryPolicy.id, policyResourceVersion: boundaryPolicy.resourceVersion, requestId: expect.stringMatching(/^role-attachment-/) })));
    expect(await screen.findByRole("button", { name: boundaryPolicy.id })).toBeTruthy();
  });

  it("checks the immutable completion record after a role policy response is lost without replaying the write", async () => {
    const user = userEvent.setup();
    const attachment = { id: "attachment-boundary", accountId: role.accountId, target: { kind: "ROLE" as const, id: role.id }, policyId: boundaryPolicy.id,
      scope: "TENANT" as const, resourceVersion: 1, createdAt: timestamp, updatedAt: timestamp };
    const updatedAccess: RoleAccess = { ...access, policyAttachments: [...access.policyAttachments, attachment] };
    const createPolicyAttachment = vi.fn().mockRejectedValue(new HttpProblem(503, "IAM_UNAVAILABLE"));
    const inspectPolicyAttachmentChange: RoleAccessClient["inspectPolicyAttachmentChange"] = vi.fn(async (expectation) => {
      if (expectation.operation !== "CREATE") throw new Error("unexpected operation");
      return {
        operation: "CREATE" as const, accountId: role.accountId, actorPrincipalId: "root-acme", requestId: expectation.requestId,
        completedAt: timestamp, target: expectation.target, policyId: expectation.policyId,
        policyResourceVersion: expectation.policyResourceVersion, attachment
      };
    });
    const api = client({
      listTenantPolicies: vi.fn().mockResolvedValue({ items: [boundaryPolicy], available: true }),
      createPolicyAttachment,
      inspectPolicyAttachmentChange,
      read: vi.fn().mockResolvedValueOnce(access).mockResolvedValue(updatedAccess)
    });
    const initial = render(<LocaleProvider><RolesHarness api={api} entityId={role.id} /></LocaleProvider>);

    await user.click(await screen.findByRole("button", { name: "关联策略" }));
    await user.click(await screen.findByRole("combobox", { name: "要关联的策略" }));
    await user.click(await screen.findByRole("option", { name: `${boundaryPolicy.displayName} · ${boundaryPolicy.id}` }));
    await user.click(screen.getByRole("button", { name: "审阅变更" }));
    await user.click(screen.getByRole("button", { name: "确认关联策略" }));

    expect(await screen.findByText("策略关联结果尚未确认")).toBeTruthy();
    const original = createPolicyAttachment.mock.calls[0]?.[1];
    expect(original).toEqual(expect.objectContaining({ requestId: expect.stringMatching(/^role-attachment-/) }));
    expect(sessionStorage.length).toBe(1);

    initial.unmount();
    const foreign = render(<LocaleProvider><RolesHarness api={{ ...api, actorPrincipalId: "another-admin" }} entityId={role.id} /></LocaleProvider>);
    expect(await screen.findByRole("heading", { name: role.name })).toBeTruthy();
    expect(screen.queryByText("策略关联结果尚未确认")).toBeNull();
    foreign.unmount();
    render(<LocaleProvider><RolesHarness api={api} entityId={role.id} /></LocaleProvider>);
    expect(await screen.findByText("策略关联结果尚未确认")).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "检查原请求结果" }));
    await waitFor(() => expect(inspectPolicyAttachmentChange).toHaveBeenCalledWith({
      operation: "CREATE", requestId: original.requestId, target: { kind: "ROLE", id: role.id },
      policyId: boundaryPolicy.id, policyResourceVersion: boundaryPolicy.resourceVersion
    }));
    expect(createPolicyAttachment).toHaveBeenCalledTimes(1);
    expect(await screen.findByRole("button", { name: boundaryPolicy.id })).toBeTruthy();
    expect(sessionStorage.length).toBe(0);
  });

  it("keeps one delete intent after an unknown result and retries the exact request", async () => {
    const user = userEvent.setup();
    const onOpen = vi.fn();
    const deletable: RoleAccess = { ...access, capabilities: access.capabilities.map((candidate) => candidate.action === "iam.role.delete" ? { ...candidate, available: true, restrictionReason: null } : candidate) };
    const remove = vi.fn().mockRejectedValueOnce(new HttpProblem(503, "IAM_UNAVAILABLE")).mockResolvedValue({ id: role.id, accountId: role.accountId, name: role.name,
      resourceVersion: role.resourceVersion + 1, revokedPolicyAttachments: 1, deletedAt: timestamp });
    render(<LocaleProvider><RolesHarness api={client({ read: vi.fn().mockResolvedValue(deletable), delete: remove })} entityId={role.id} onOpen={onOpen} /></LocaleProvider>);

    await screen.findByRole("heading", { name: role.name });
    await user.click(screen.getByRole("button", { name: "更多操作" }));
    await user.click(screen.getByRole("menuitem", { name: "删除" }));
    expect(screen.getByText("这是连接 IAM 的真实删除命令", { exact: false })).toBeTruthy();
    await user.type(screen.getByLabelText("输入名称以确认"), role.name);
    await user.click(screen.getByRole("button", { name: "确认删除" }));
    expect(await screen.findByText("删除结果未知", { exact: false })).toBeTruthy();
    const original = remove.mock.calls[0];
    await user.click(screen.getByRole("button", { name: "取消" }));
    expect(await screen.findByText("会失去用于安全重试的冻结请求 ID", { exact: false })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "继续编辑" }));
    await user.click(screen.getByRole("button", { name: "确认删除" }));

    await waitFor(() => expect(remove).toHaveBeenCalledTimes(2));
    expect(remove.mock.calls[1]).toEqual(original);
    expect(onOpen).toHaveBeenCalledWith("roles");
  });

  it("opens exact current role relationships without extra directory requests", async () => {
    const user = userEvent.setup();
    const onOpen = vi.fn();
    const api = client();
    render(<LocaleProvider><RolesHarness api={api} entityId={role.id} onOpen={onOpen} /></LocaleProvider>);

    expect(await screen.findByRole("heading", { name: role.name })).toBeTruthy();
    await user.click(await screen.findByRole("button", { name: "policy-role-ceiling" }));
    expect(onOpen).toHaveBeenLastCalledWith("policies", "policy-role-ceiling");

    await user.click(screen.getByRole("button", { name: "system.log-reader" }));
    expect(onOpen).toHaveBeenLastCalledWith("policies", "system.log-reader");

    await user.click(screen.getByRole("tab", { name: "信任策略 (1)" }));
    await user.click(screen.getByRole("button", { name: "USER · user-alex" }));
    expect(onOpen).toHaveBeenLastCalledWith("users", "user-alex");
    expect(api.list).not.toHaveBeenCalled();
    expect(api.listTrustVersions).not.toHaveBeenCalled();
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
    expect(within(detail).queryByRole("button", { name: /user-sam/ })).toBeNull();
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

  it("uses the exact server capabilities to keep role-boundary management read-only", async () => {
    const restricted: RoleAccess = { ...access, capabilities: access.capabilities.map((candidate) =>
      candidate.action === "iam.role.permission-boundary.set" || candidate.action === "iam.role.permission-boundary.remove"
        ? { ...candidate, available: false, restrictionReason: "AUTHORITY_REQUIRED" }
        : candidate) };
    render(<LocaleProvider><RolesHarness api={client({ read: vi.fn().mockResolvedValue(restricted) })} entityId={role.id} /></LocaleProvider>);

    expect(await screen.findByText("当前边界为只读。", { exact: false })).toBeTruthy();
    expect(screen.getByText("当前身份没有执行此操作所需的权限。", { exact: false })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "修改权限边界" })).toBeNull();
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

  it("loads eligible policies only after inline editing opens, then sets and authoritatively rereads the role boundary", async () => {
    const user = userEvent.setup();
    const closed = { accountId: role.accountId, roleId: role.id, resourceVersion: 2, policy: null };
    const applied = { accountId: role.accountId, roleId: role.id, resourceVersion: 3,
      policy: { policyId: boundaryPolicy.id, versionId: boundaryPolicy.defaultVersionId, contentDigest: `sha256:${"d".repeat(64)}` } };
    const listTenantPolicies = vi.fn().mockResolvedValue({ items: [boundaryPolicy], available: true });
    const setPermissionBoundary = vi.fn().mockResolvedValue(applied);
    const readPermissionBoundary = vi.fn().mockResolvedValueOnce(closed).mockResolvedValue(applied);
    const api = client({ listTenantPolicies, setPermissionBoundary, readPermissionBoundary });
    render(<LocaleProvider><RolesHarness api={api} entityId={role.id} /></LocaleProvider>);

    expect(await screen.findByText("未设置权限上限 · 角色承担已关闭")).toBeTruthy();
    expect(listTenantPolicies).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "修改权限边界" }));
    await waitFor(() => expect(listTenantPolicies).toHaveBeenCalledTimes(1));
    expect(screen.queryByRole("dialog")).toBeNull();
    await chooseRoleBoundary(user, `${boundaryPolicy.displayName} · ${boundaryPolicy.id}`);
    await user.click(screen.getByRole("button", { name: "审阅变更" }));
    expect(setPermissionBoundary).not.toHaveBeenCalled();
    expect(screen.getByText("请核对新的权限上限", { exact: false })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "确认变更" }));

    await waitFor(() => expect(setPermissionBoundary).toHaveBeenCalledTimes(1));
    expect(setPermissionBoundary).toHaveBeenCalledWith(role.id, expect.objectContaining({
      policyId: boundaryPolicy.id,
      policyResourceVersion: boundaryPolicy.resourceVersion,
      resourceVersion: closed.resourceVersion,
      requestId: expect.stringMatching(/^role-boundary-/)
    }));
    expect(await screen.findByText("IAM 已确认权限上限变更，并完成权威状态回读。")).toBeTruthy();
    expect(screen.getByRole("button", { name: boundaryPolicy.displayName })).toBeTruthy();
    expect(screen.getByText(boundaryPolicy.id, { selector: "code" })).toBeTruthy();
    expect(readPermissionBoundary).toHaveBeenCalledTimes(2);
    expect(api.read).toHaveBeenCalledTimes(2);
  });

  it("keeps one uncertain role-boundary intent and retries it byte-for-byte", async () => {
    const user = userEvent.setup();
    const closed = { accountId: role.accountId, roleId: role.id, resourceVersion: 2, policy: null };
    const applied = { accountId: role.accountId, roleId: role.id, resourceVersion: 3,
      policy: { policyId: boundaryPolicy.id, versionId: boundaryPolicy.defaultVersionId, contentDigest: `sha256:${"e".repeat(64)}` } };
    const setPermissionBoundary = vi.fn().mockRejectedValueOnce(new HttpProblem(503, "IAM_UNAVAILABLE")).mockResolvedValue(applied);
    const api = client({
      listTenantPolicies: vi.fn().mockResolvedValue({ items: [boundaryPolicy], available: true }),
      readPermissionBoundary: vi.fn().mockResolvedValueOnce(closed).mockResolvedValue(applied),
      setPermissionBoundary
    });
    render(<LocaleProvider><RolesHarness api={api} entityId={role.id} /></LocaleProvider>);

    await user.click(await screen.findByRole("button", { name: "修改权限边界" }));
    await chooseRoleBoundary(user, `${boundaryPolicy.displayName} · ${boundaryPolicy.id}`);
    await user.click(screen.getByRole("button", { name: "审阅变更" }));
    await user.click(screen.getByRole("button", { name: "确认变更" }));
    expect(await screen.findByText("提交结果尚未确认", { exact: false })).toBeTruthy();
    const original = setPermissionBoundary.mock.calls[0];
    await user.click(screen.getByRole("button", { name: "重试原请求" }));

    await waitFor(() => expect(setPermissionBoundary).toHaveBeenCalledTimes(2));
    expect(setPermissionBoundary.mock.calls[1]).toEqual(original);
    expect(await screen.findByText("IAM 已确认权限上限变更，并完成权威状态回读。")).toBeTruthy();
  });

  it("can remove an existing role boundary when the policy directory is unavailable and states that assumption closes", async () => {
    const user = userEvent.setup();
    const current = { accountId: role.accountId, roleId: role.id, resourceVersion: 2,
      policy: { policyId: "policy-old-ceiling", versionId: "v2", contentDigest: `sha256:${"3".repeat(64)}` } };
    const closed = { accountId: role.accountId, roleId: role.id, resourceVersion: 3, policy: null };
    const removePermissionBoundary = vi.fn().mockResolvedValue(closed);
    const api = client({
      listTenantPolicies: vi.fn().mockResolvedValue({ items: [], available: false }),
      readPermissionBoundary: vi.fn().mockResolvedValueOnce(current).mockResolvedValue(closed),
      removePermissionBoundary
    });
    render(<LocaleProvider><RolesHarness api={api} entityId={role.id} /></LocaleProvider>);

    await user.click(await screen.findByRole("button", { name: "修改权限边界" }));
    await chooseRoleBoundary(user, "不设置权限上限 · 角色承担关闭");
    await user.click(screen.getByRole("button", { name: "审阅变更" }));
    expect(screen.getByText("移除权限上限后，角色承担将关闭；这不是改为无限权限。", { exact: false })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "确认变更" }));

    await waitFor(() => expect(removePermissionBoundary).toHaveBeenCalledWith(role.id, expect.objectContaining({
      resourceVersion: current.resourceVersion,
      requestId: expect.stringMatching(/^role-boundary-/)
    })));
    expect(await screen.findByText("未设置权限上限 · 角色承担已关闭")).toBeTruthy();
  });

  it("refreshes a conflicting role boundary and requires a fresh review", async () => {
    const user = userEvent.setup();
    const original = { accountId: role.accountId, roleId: role.id, resourceVersion: 2,
      policy: { policyId: "policy-old-ceiling", versionId: "v2", contentDigest: `sha256:${"f".repeat(64)}` } };
    const latest = { accountId: role.accountId, roleId: role.id, resourceVersion: 3,
      policy: { policyId: boundaryPolicy.id, versionId: boundaryPolicy.defaultVersionId, contentDigest: `sha256:${"1".repeat(64)}` } };
    const setPermissionBoundary = vi.fn().mockRejectedValue(new HttpProblem(409, "IAM_ROLE_REVISION_CHANGED"));
    const readPermissionBoundary = vi.fn().mockResolvedValueOnce(original).mockResolvedValue(latest);
    const api = client({ listTenantPolicies: vi.fn().mockResolvedValue({ items: [boundaryPolicy], available: true }), readPermissionBoundary, setPermissionBoundary });
    render(<LocaleProvider><RolesHarness api={api} entityId={role.id} /></LocaleProvider>);

    await user.click(await screen.findByRole("button", { name: "修改权限边界" }));
    await chooseRoleBoundary(user, `${boundaryPolicy.displayName} · ${boundaryPolicy.id}`);
    await user.click(screen.getByRole("button", { name: "审阅变更" }));
    await user.click(screen.getByRole("button", { name: "确认变更" }));
    expect(await screen.findByText("权限上限已被其他操作修改", { exact: false })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "刷新并重新审阅" }));

    expect((await screen.findByRole("combobox", { name: "权限边界" })).textContent).toContain(boundaryPolicy.displayName);
    expect((screen.getByRole("button", { name: "审阅变更" }) as HTMLButtonElement).disabled).toBe(true);
    expect(setPermissionBoundary).toHaveBeenCalledTimes(1);
    expect(readPermissionBoundary).toHaveBeenCalledTimes(2);
  });

  it("treats a failed readback after an acknowledged role-boundary write as a read failure only", async () => {
    const user = userEvent.setup();
    const closed = { accountId: role.accountId, roleId: role.id, resourceVersion: 2, policy: null };
    const applied = { accountId: role.accountId, roleId: role.id, resourceVersion: 3,
      policy: { policyId: boundaryPolicy.id, versionId: boundaryPolicy.defaultVersionId, contentDigest: `sha256:${"2".repeat(64)}` } };
    const read = vi.fn().mockResolvedValueOnce(access).mockRejectedValueOnce(new Error("readback unavailable")).mockResolvedValue(access);
    const readPermissionBoundary = vi.fn().mockResolvedValueOnce(closed).mockResolvedValue(applied);
    const setPermissionBoundary = vi.fn().mockResolvedValue(applied);
    const api = client({ read, readPermissionBoundary, listTenantPolicies: vi.fn().mockResolvedValue({ items: [boundaryPolicy], available: true }), setPermissionBoundary });
    render(<LocaleProvider><RolesHarness api={api} entityId={role.id} /></LocaleProvider>);

    await user.click(await screen.findByRole("button", { name: "修改权限边界" }));
    await chooseRoleBoundary(user, `${boundaryPolicy.displayName} · ${boundaryPolicy.id}`);
    await user.click(screen.getByRole("button", { name: "审阅变更" }));
    await user.click(screen.getByRole("button", { name: "确认变更" }));
    expect(await screen.findByText("IAM 已确认写入，但后续权威回读失败", { exact: false })).toBeTruthy();
    expect(screen.queryByText("提交结果尚未确认", { exact: false })).toBeNull();
    await user.click(screen.getByRole("button", { name: "重试权威读取" }));

    expect(await screen.findByText("IAM 已确认权限上限变更，并完成权威状态回读。")).toBeTruthy();
    expect(setPermissionBoundary).toHaveBeenCalledTimes(1);
    expect(read).toHaveBeenCalledTimes(3);
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
    const sourceGuide = screen.getByRole("region", { name: "会话来源与权限边界" });
    expect(within(sourceGuide).getByText("人员用户")).toBeTruthy();
    expect(within(sourceGuide).getByText("服务账号")).toBeTruthy();
    expect(within(sourceGuide).getByText(/不是租户用户或长期凭据/)).toBeTruthy();
    expect(within(sourceGuide).getByText(/产品 PEP 仍须针对每次业务请求重新鉴权/)).toBeTruthy();
    expect(within(sourceGuide).queryByRole("button")).toBeNull();
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
