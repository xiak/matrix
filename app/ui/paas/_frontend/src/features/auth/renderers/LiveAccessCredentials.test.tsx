import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { LocaleProvider } from "@/i18n/LocaleProvider";
import { HttpProblem } from "@/infrastructure/http/jsonRequest";
import type { AccessKeyClient } from "../application/AccountAccessProvider";
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
  createdAt: "2026-09-21T08:00:00Z", updatedAt: "2026-09-21T08:00:00Z" };
const directory = {
  accountId: scene.accountId, userId: owner.id, userResourceVersion: owner.resourceVersion,
  capabilities: [{ action: "iam.access-key.create" as const, resource: { kind: "USER" as const, id: owner.id }, available: true, restrictionReason: null }],
  items: [{ key, capabilities: [
    { action: "iam.access-key.read" as const, resource: { kind: "ACCESS_KEY" as const, id: key.id }, available: true, restrictionReason: null },
    { action: "iam.access-key.set-status" as const, resource: { kind: "ACCESS_KEY" as const, id: key.id }, available: true, restrictionReason: null },
    { action: "iam.access-key.delete" as const, resource: { kind: "ACCESS_KEY" as const, id: key.id }, available: false, restrictionReason: "TARGET_MUST_BE_DISABLED" as const }
  ] }]
};

function client(overrides: Partial<AccessKeyClient> = {}): AccessKeyClient {
  return {
    accountId: scene.accountId,
    list: vi.fn().mockResolvedValue(directory),
    read: vi.fn().mockResolvedValue(directory.items[0]),
    create: vi.fn().mockResolvedValue({ outcome: "APPLIED", key: { ...key, id: "mak1.alex-rotated" }, secret: "mak1.one-time-secret" }),
    setStatus: vi.fn(),
    delete: vi.fn(),
    ...overrides
  };
}

afterEach(cleanup);

describe("LiveAccessCredentials", () => {
  it("loads only the selected user's directory and keeps fixed page content visible", async () => {
    const user = userEvent.setup();
    const api = client();
    render(<LocaleProvider><LiveAccessCredentials client={api} scene={scene} /></LocaleProvider>);

    expect(screen.getByRole("heading", { name: "访问密钥" })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "管理 alex 的访问密钥" }));
    expect(screen.getByRole("heading", { name: "alex · 访问密钥" })).toBeTruthy();
    expect(await screen.findByRole("button", { name: key.id })).toBeTruthy();
    expect(api.list).toHaveBeenCalledWith(owner.id);
    expect(screen.getByText("本页使用固定的访问密钥管理契约", { exact: false })).toBeTruthy();
    expect(screen.queryByRole("dialog")).toBeNull();
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
    await user.click(screen.getByRole("button", { name: "确认创建" }));

    expect(await screen.findByText("mak1.one-time-secret")).toBeTruthy();
    expect(screen.getByText("LIVE")).toBeTruthy();
    await user.click(screen.getByRole("checkbox", { name: "我已将 Secret 保存到受保护的位置，并理解它无法再次显示" }));
    await user.click(screen.getByRole("button", { name: "已完成" }));
    expect(screen.queryByText("mak1.one-time-secret")).toBeNull();
    expect(api.create).toHaveBeenCalledTimes(1);
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
    expect(await screen.findByText("未收到可信结果时不要生成新的 requestId", { exact: false })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "确认创建" }));
    expect(await screen.findByRole("heading", { name: "原创建请求已完成" })).toBeTruthy();

    await waitFor(() => expect(create).toHaveBeenCalledTimes(2));
    expect(create.mock.calls[0]?.[1].requestId).toBe(create.mock.calls[1]?.[1].requestId);
    expect(screen.getByText("Secret 无法再次显示", { exact: false })).toBeTruthy();
  });
});
