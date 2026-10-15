import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { LocaleProvider } from "@/i18n/LocaleProvider";
import { SessionProvider, useSession } from "@/features/auth/application/SessionProvider";
import type { IamRepository } from "@/features/auth/repositories/iamRepository";
import { AUDIT_API_VERSION } from "../domain/audit";
import { AuditWorkspace } from "./AuditWorkspace";

const evidenceDigest = `sha256:${"a".repeat(64)}`;
const hash = (character: string) => `sha256:${character.repeat(64)}`;

function evidencePage(fields: Record<string, unknown>) {
  return { apiVersion: AUDIT_API_VERSION, kind: "AuditRecordPage", tenantId: "organization-test", records: [{
    apiVersion: AUDIT_API_VERSION, kind: "AuditRecord", source: "IAM", sequence: 42,
    event: { apiVersion: AUDIT_API_VERSION, kind: "AuditEvent", eventId: "event-attachment", tenantId: "organization-test",
      actor: { type: "USER", id: "principal-auditor" }, action: "iam.policy-attachment.created", target: { kind: "POLICY_ATTACHMENT", id: "attachment-example" },
      result: "SUCCEEDED", requestDigest: hash("1"), requestId: "request-attachment", correlationId: "correlation-attachment",
      occurredAt: "2026-10-09T01:02:03.000000Z", ...fields },
    contentDigest: hash("2"), previousHash: hash("3"), recordHash: hash("4"), ingestedAt: "2026-10-09T01:02:04.000000Z", retention: "INDEFINITE"
  }] };
}

function LiveAudit() {
  const session = useSession();
  return session.phase === "authenticated" ? <AuditWorkspace /> : <button onClick={() => void session.login("auditor", "synthetic-audit-password")}>start fixture session</button>;
}

async function renderLiveEvidence(fields: Record<string, unknown>) {
  const repository: IamRepository = {
    async login() { return { outcome: "AUTHENTICATED", credential: "synthetic-audit-session", mustChangePassword: false,
      session: { id: "session-audit-fixture", organizationId: "organization-test", principalId: "principal-auditor", status: "ACTIVE",
        issuedAt: "2026-10-09T01:00:00Z", expiresAt: "2099-10-09T02:00:00Z" } }; },
    async changePassword() {}, async logout() {}
  };
  const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify(evidencePage(fields)), { status: 200, headers: { "Content-Type": "application/json" } }));
  vi.stubGlobal("fetch", fetchMock);
  const user = userEvent.setup();
  render(<LocaleProvider><SessionProvider repository={repository}><LiveAudit /></SessionProvider></LocaleProvider>);
  await user.click(screen.getByRole("button", { name: "start fixture session" }));
  return { user, fetchMock };
}

afterEach(() => {
  cleanup();
  localStorage.clear();
  vi.unstubAllGlobals();
});

describe("AuditWorkspace", () => {
  it.each([true, false])("renders live facts with optional authority evidence present=%s", async present => {
    const { user, fetchMock } = await renderLiveEvidence(present ? { authorityEvidenceDigest: evidenceDigest } : {});
    const table = await screen.findByRole("table", { name: "审计记录" });
    expect(new Headers(fetchMock.mock.calls[0]![1].headers).get("Authorization")).toBe("Bearer synthetic-audit-session");
    await user.click(within(table).getByRole("button", { name: "iam.policy-attachment.created" }));
    expect(screen.getByRole("heading", { level: 1, name: "审计记录 #42" })).toBeTruthy();
    expect(screen.getByText(hash("1"))).toBeTruthy();
    if (present) {
      expect(screen.getByText("授权证据摘要")).toBeTruthy();
      expect(screen.getByText(evidenceDigest)).toBeTruthy();
      expect(screen.getByText("事件所记录证据的摘要，不是当前授权许可。")).toBeTruthy();
    } else {
      expect(screen.queryByText("授权证据摘要")).toBeNull();
      expect(screen.queryByText(evidenceDigest)).toBeNull();
    }
    expect(screen.queryByText("审计服务返回了不符合契约的数据，页面已拒绝展示。")).toBeNull();
  });

  it.each([
    { authorityEvidenceDigest: "sha256:short" },
    { authorityEvidenceDigest: null },
    { authorityEvidenceDigest: evidenceDigest, authorityProof: "synthetic-hidden-evidence" }
  ])("rejects malformed or unsupported live evidence without rendering raw values %#", async fields => {
    await renderLiveEvidence(fields);
    expect(await screen.findByText("审计服务返回了不符合契约的数据，页面已拒绝展示。")).toBeTruthy();
    expect(screen.queryByRole("table", { name: "审计记录" })).toBeNull();
    expect(screen.queryByText("授权证据摘要")).toBeNull();
    expect(screen.queryByText("synthetic-hidden-evidence")).toBeNull();
    expect(screen.queryByText("sha256:short")).toBeNull();
  });

  it("keeps the route chrome stable while paging an opaque tenant cursor", async () => {
    const user = userEvent.setup();
    render(<LocaleProvider><AuditWorkspace preview /></LocaleProvider>);

    expect(screen.getByRole("heading", { level: 1, name: "审计记录" })).toBeTruthy();
    expect(screen.getByText("租户边界来自当前 IAM 会话")).toBeTruthy();
    const table = await screen.findByRole("table", { name: "审计记录" });
    expect(within(table).getAllByRole("row")).toHaveLength(11);
    expect(within(table).getAllByRole("columnheader").map((cell) => cell.textContent)).toEqual(["事件", "操作者", "目标资源", "结果"]);
    expect(within(table).getByRole("button", { name: "audit.records.read" })).toBeTruthy();
    expect(within(table).getByText("用户密钥 key-audit-preview")).toBeTruthy();
    expect(screen.getByText(/已接受不等于异步操作完成/)).toBeTruthy();
    expect(screen.queryByRole("searchbox")).toBeNull();
    expect(screen.queryByLabelText("开始时间")).toBeNull();
    expect(screen.getByRole("button", { name: "查询条件" }).getAttribute("aria-expanded")).toBe("false");
    expect(screen.getByText(/当前租户：org-xiak/)).toBeTruthy();

    await user.click(screen.getByRole("button", { name: "下一页" }));
    await waitFor(() => expect(screen.getByText("第 2 页 · 2 条记录")).toBeTruthy());
    expect(within(screen.getByRole("table", { name: "审计记录" })).getAllByRole("row")).toHaveLength(3);
  });

  it("opens record evidence and chain verification in the content region", async () => {
    const user = userEvent.setup();
    render(<LocaleProvider><AuditWorkspace preview /></LocaleProvider>);
    const table = await screen.findByRole("table", { name: "审计记录" });
    const opener = within(table).getByRole("button", { name: "audit.records.read" });

    await user.click(opener);
    expect(screen.getByRole("heading", { level: 1, name: /审计记录 #114/ })).toBeTruthy();
    expect(screen.getByText("哈希链证据")).toBeTruthy();
    expect(screen.getByText(/来源服务记录该事件已按自身语义完成/)).toBeTruthy();
    const source = screen.getByText("事件来源").closest("div")!;
    expect(within(source).getByText("AUDIT")).toBeTruthy();
    expect(within(source).getByText("audit.records.read")).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "返回审计记录" }));
    expect(await screen.findByRole("table", { name: "审计记录" })).toBeTruthy();
    expect(document.activeElement).toBe(within(screen.getByRole("table", { name: "审计记录" })).getByRole("button", { name: "audit.records.read" }));

    await user.click(screen.getByRole("button", { name: "校验完整性" }));
    expect(screen.getByRole("heading", { level: 1, name: "审计链完整性校验" })).toBeTruthy();
    expect(screen.getByText(/显式读取操作/)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "开始校验" }));
    expect(await screen.findByText("已校验到当前链尾")).toBeTruthy();
    expect(screen.getByText("1–114")).toBeTruthy();
  });

  it("explains every audit result without turning evidence into a business outcome", async () => {
    const user = userEvent.setup();
    render(<LocaleProvider><AuditWorkspace preview /></LocaleProvider>);
    await screen.findByRole("table", { name: "审计记录" });
    const cases = [
      { action: "audit.records.read", occurrence: 0, meaning: /不证明相关异步业务的最终结果/ },
      { action: "iam.authorization.decided", occurrence: 0, meaning: /不证明产品已执行请求/ },
      { action: "paas.deployment.created", occurrence: 0, meaning: /不证明 Operation 已完成/ },
      { action: "iam.authorization.decided", occurrence: 1, meaning: /不证明目标资源存在与否/ }
    ] as const;
    for (const item of cases) {
      const table = screen.getByRole("table", { name: "审计记录" });
      await user.click(within(table).getAllByRole("button", { name: item.action })[item.occurrence]!);
      expect(screen.getByText(item.meaning)).toBeTruthy();
      await user.click(screen.getByRole("button", { name: "返回审计记录" }));
      await screen.findByRole("table", { name: "审计记录" });
    }
  });

  it("rejects a preview verification range that starts after the current chain tail", async () => {
    const user = userEvent.setup();
    render(<LocaleProvider><AuditWorkspace preview /></LocaleProvider>);
    await screen.findByRole("table", { name: "审计记录" });

    await user.click(screen.getByRole("button", { name: "校验完整性" }));
    const fromSequence = screen.getByRole("spinbutton", { name: "起始序列" });
    await user.clear(fromSequence);
    await user.type(fromSequence, "115");
    await user.click(screen.getByRole("button", { name: "开始校验" }));

    expect((await screen.findByRole("alert")).textContent).toContain("审计服务返回了不符合契约的数据，页面已拒绝展示。");
    expect(screen.queryByText("已校验到当前链尾")).toBeNull();
  });

  it("collects complete role-session lineage before querying", async () => {
    const user = userEvent.setup();
    render(<LocaleProvider><AuditWorkspace preview /></LocaleProvider>);
    await screen.findByRole("table", { name: "审计记录" });

    await user.click(screen.getByRole("button", { name: "查询条件" }));
    await user.click(screen.getByRole("combobox", { name: "操作者类型" }));
    await user.click(screen.getByRole("option", { name: "角色会话" }));
    expect(screen.getByLabelText("角色会话 ID")).toBeTruthy();
    expect(screen.getByRole("combobox", { name: "角色来源类型" })).toBeTruthy();

    await user.click(screen.getByLabelText("操作者 ID"));
    await user.paste("role-deployer");
    await user.click(screen.getByRole("button", { name: "查询" }));
    expect((await screen.findByRole("alert")).textContent).toContain("请检查时间范围、操作者 ID 和分页参数");

    await user.click(screen.getByLabelText("角色会话 ID"));
    await user.paste("role-session-preview");
    await user.click(screen.getByLabelText("角色来源 ID"));
    await user.paste("principal-developer");
    await user.click(screen.getByRole("button", { name: "查询" }));
    await waitFor(() => expect(screen.getByText("第 1 页 · 1 条记录")).toBeTruthy());
    expect(screen.getByText("role-deployer")).toBeTruthy();
    expect(screen.queryByLabelText("角色会话 ID")).toBeNull();
    const filterTrigger = screen.getByRole("button", { name: /查询条件.*已应用 1 项/ });
    expect(filterTrigger.getAttribute("aria-expanded")).toBe("false");
    expect(document.activeElement).toBe(filterTrigger);
  });
});
