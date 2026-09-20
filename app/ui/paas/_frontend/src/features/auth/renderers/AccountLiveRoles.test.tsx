import { cleanup, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { LocaleProvider } from "@/i18n/LocaleProvider";
import type { RoleAccessClient } from "../application/AccountAccessProvider";
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
const liveSession = {
  id: "rs1.incident-review", accountId: role.accountId, roleId: role.id, sourceUserId: "user-alex", status: "ACTIVE" as const,
  issuedAt: timestamp, expiresAt: "2026-09-21T09:00:00Z", revokedAt: null
};
const liveSessionItem = {
  session: liveSession,
  sourceUser: { id: "user-alex", loginName: "alex", displayName: "Alex" },
  lifecycle: "UNREVOKED" as const,
  revokeCapability: { action: "iam.role-session.revoke" as const, resource: { kind: "ROLE_SESSION" as const, id: liveSession.id }, available: true, restrictionReason: null }
};

function client(overrides: Partial<RoleAccessClient> = {}): RoleAccessClient {
  return {
    accountId: role.accountId,
    list: vi.fn().mockResolvedValue(directory),
    read: vi.fn().mockResolvedValue(access),
    listSessions: vi.fn().mockResolvedValue({ accountId: role.accountId, roleId: role.id, observedAt: timestamp, items: [], nextAfter: null }),
    readSession: vi.fn().mockRejectedValue(new Error("unused session read")),
    revokeSession: vi.fn().mockRejectedValue(new Error("unused session revoke")),
    ...overrides
  };
}

afterEach(cleanup);

describe("AccountLiveRoles", () => {
  it("keeps the fixed directory shell visible while only role data loads", async () => {
    let resolve!: (value: RoleDirectory) => void;
    const api = client({ list: vi.fn().mockImplementation(() => new Promise<RoleDirectory>((done) => { resolve = done; })) });
    render(<LocaleProvider><AccountLiveRoles client={api} onOpen={vi.fn()} /></LocaleProvider>);

    expect(screen.getByRole("heading", { name: "角色" })).toBeTruthy();
    expect(screen.getByText("角色是可被信任身份申请的临时身份", { exact: false })).toBeTruthy();
    expect(screen.getByText("正在加载角色目录")).toBeTruthy();
    resolve(directory);
    expect(await screen.findByRole("button", { name: role.name })).toBeTruthy();
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("opens an inline detail with distinct trust, grant and capability evidence", async () => {
    const user = userEvent.setup();
    const api = client();
    render(<LocaleProvider><AccountLiveRoles client={api} entityId={role.id} onOpen={vi.fn()} /></LocaleProvider>);

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

  it("loads live sessions only on demand and preserves one revoke request through an unknown outcome", async () => {
    const user = userEvent.setup();
    const revoked = { ...liveSession, status: "REVOKED" as const, revokedAt: "2026-09-21T08:31:00Z" };
    const api = client({
      listSessions: vi.fn().mockResolvedValue({ accountId: role.accountId, roleId: role.id, observedAt: "2026-09-21T08:30:00Z", items: [liveSessionItem], nextAfter: null }),
      readSession: vi.fn().mockResolvedValue({ observedAt: "2026-09-21T08:30:10Z", item: liveSessionItem }),
      revokeSession: vi.fn().mockRejectedValueOnce(new Error("connection lost")).mockResolvedValue({ outcome: "APPLIED", session: revoked })
    });
    render(<LocaleProvider><AccountLiveRoles client={api} entityId={role.id} onOpen={vi.fn()} /></LocaleProvider>);

    expect(await screen.findByRole("heading", { name: role.name })).toBeTruthy();
    expect(api.listSessions).not.toHaveBeenCalled();
    await user.click(screen.getByRole("tab", { name: "角色会话" }));
    expect(await screen.findByText(liveSession.id)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: `会话 ${liveSession.id} 的操作` }));
    await user.click(screen.getByRole("menuitem", { name: "撤销会话" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    const workflow = screen.getByRole("group", { name: "撤销会话" });
    await user.click(within(workflow).getByRole("button", { name: "撤销会话" }));
    expect(await within(workflow).findByText("撤销结果尚未确认", { exact: false })).toBeTruthy();
    await user.click(within(workflow).getByRole("button", { name: "读取权威状态" }));
    expect(await within(workflow).findByText("仍观测为未撤销", { exact: false })).toBeTruthy();
    await user.click(within(workflow).getByRole("button", { name: "重试原请求" }));
    expect(await screen.findByRole("heading", { name: "没有匹配的角色会话" })).toBeTruthy();
    const revoke = vi.mocked(api.revokeSession);
    expect(revoke.mock.calls[1]?.[2]).toBe(revoke.mock.calls[0]?.[2]);
    expect(api.readSession).toHaveBeenCalledWith(role.id, liveSession.id);
    expect(document.activeElement).toBe(screen.getByRole("heading", { name: "角色会话" }));
  });

  it("shows a local LIVE error and never substitutes preview role data", async () => {
    const api = client({ list: vi.fn().mockRejectedValue(new Error("network")) });
    render(<LocaleProvider><AccountLiveRoles client={api} onOpen={vi.fn()} /></LocaleProvider>);

    expect(await screen.findByRole("heading", { name: "角色目录暂时不可用" })).toBeTruthy();
    expect(screen.queryByText("SupportRole")).toBeNull();
    expect(screen.getByRole("button", { name: "重试" })).toBeTruthy();
  });
});
