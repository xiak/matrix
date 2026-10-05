import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { LocaleProvider } from "@/i18n/LocaleProvider";
import { HttpProblem } from "@/infrastructure/http/jsonRequest";
import type { AccessAnalysisClient } from "../application/AccountAccessProvider";
import type { AccessFindingDirectory } from "../domain/accessAnalysis";
import { LiveAccessAnalysis } from "./LiveAccessAnalysis";

const timestamp = "2026-09-11T08:00:00Z";
const analyzer = {
  id: "analyzer-unused", accountId: "account-acme", type: "UNUSED_ACCESS" as const, status: "ACTIVE" as const,
  unusedAccessAgeDays: 90, disposition: { mode: "REVIEW_ONLY" as const, findingDelayDays: 0 as const },
  resourceVersion: 1, createdAt: "2026-06-11T08:00:00Z", updatedAt: "2026-06-11T08:00:00Z"
};
const finding = {
  id: "finding-password-alex", accountId: analyzer.accountId, analyzerId: analyzer.id, analyzerRevision: 1,
  type: "UNUSED_PASSWORD" as const, status: "ACTIVE" as const, target: { kind: "USER" as const, id: "user-alex" },
  targetResourceVersion: 2, conditionGeneration: 1, activityRevision: 1, recoveryEpoch: 0,
  recoveryCommandId: null, recoveryCompletedAt: null, windowStartedAt: "2026-06-11T08:00:00Z", observedAt: timestamp,
  lastActivityAt: "2026-06-01T08:00:00Z", resourceVersion: 1, createdAt: "2026-09-11T07:00:00Z",
  updatedAt: "2026-09-11T07:00:00Z", resolvedAt: null, resolutionReason: null
};
const coverage: AccessFindingDirectory["coverage"] = [
  { source: "IAM_PASSWORD_SESSIONS", state: "COMPLETE", observedFrom: "2026-06-11T08:00:00Z", observedThrough: timestamp, reason: null },
  { source: "IAM_ACCESS_KEY_AUTHORIZATIONS", state: "INSUFFICIENT_COVERAGE", observedFrom: "2026-08-11T08:00:00Z", observedThrough: timestamp, reason: "SOURCE_NOT_READY" },
  { source: "IAM_ROLE_SESSIONS", state: "COMPLETE", observedFrom: "2026-06-11T08:00:00Z", observedThrough: timestamp, reason: null },
  { source: "IAM_ROLE_AUTHORIZATIONS", state: "COMPLETE", observedFrom: "2026-06-11T08:00:00Z", observedThrough: timestamp, reason: null },
  { source: "PAAS_RESULTS", state: "NOT_INCLUDED", observedFrom: null, observedThrough: null, reason: "SOURCE_NOT_IMPLEMENTED" },
  { source: "EXTERNAL_FEDERATION", state: "NOT_INCLUDED", observedFrom: null, observedThrough: null, reason: "SOURCE_NOT_IMPLEMENTED" }
];
const directory: AccessFindingDirectory = {
  accountId: analyzer.accountId, analyzerId: analyzer.id, observedAt: timestamp, coverage, items: [finding], nextAfter: null
};

function client(overrides: Partial<AccessAnalysisClient> = {}): AccessAnalysisClient {
  return {
    accountId: analyzer.accountId,
    sessionRevision: 1,
    listAnalyzers: vi.fn().mockResolvedValue({ accountId: analyzer.accountId, items: [analyzer], nextAfter: null }),
    readAnalyzer: vi.fn().mockResolvedValue(analyzer),
    createAnalyzer: vi.fn().mockResolvedValue(analyzer),
    updateAnalyzer: vi.fn().mockResolvedValue({ ...analyzer, resourceVersion: 2 }),
    setDisposition: vi.fn().mockImplementation(async (_analyzerId, command) => ({
      ...analyzer, disposition: command.disposition, resourceVersion: command.resourceVersion + 1, updatedAt: timestamp
    })),
    listFindings: vi.fn().mockResolvedValue(directory),
    readFinding: vi.fn().mockResolvedValue(finding),
    archiveFinding: vi.fn().mockResolvedValue({ ...finding, status: "ARCHIVED", resourceVersion: 2, updatedAt: timestamp }),
    unarchiveFinding: vi.fn().mockResolvedValue({ ...finding, status: "ACTIVE", resourceVersion: 3, updatedAt: timestamp }),
    ...overrides
  };
}

function view(value: AccessAnalysisClient) {
  return render(<LocaleProvider><LiveAccessAnalysis client={value} onNavigate={vi.fn()} /></LocaleProvider>);
}

afterEach(cleanup);

describe("live access analysis", () => {
  it("renders the stable page shell before the first server response", () => {
    const pending = new Promise<never>(() => undefined);
    view(client({ listAnalyzers: vi.fn().mockReturnValue(pending) }));
    expect(screen.getByRole("heading", { name: "访问分析" })).toBeTruthy();
    expect(screen.getByRole("tab", { name: "来源覆盖" })).toBeTruthy();
    expect(screen.getByRole("tab", { name: "未使用访问" })).toBeTruthy();
    expect(screen.getByRole("tab", { name: "分析规则" })).toBeTruthy();
    expect(screen.getByText(/LIVE · 本页直接读取/)).toBeTruthy();
  });

  it("loads a server-filtered cursor directory without inventing a total", async () => {
    const value = client();
    view(value);
    expect(await screen.findByRole("button", { name: "user-alex" })).toBeTruthy();
    expect(value.listFindings).toHaveBeenCalledWith(analyzer.id, "ACTIVE", undefined);
    expect(screen.getByText("第 1 页")).toBeTruthy();
    expect(screen.queryByText(/共 .* 条/)).toBeNull();
  });

  it("keeps the detail shell stable while reauthorizing and rereading the selected Finding", async () => {
    const user = userEvent.setup();
    let resolveFinding!: (value: typeof finding) => void;
    const detail = new Promise<typeof finding>((resolve) => { resolveFinding = resolve; });
    const readFinding = vi.fn().mockReturnValue(detail);
    view(client({ readFinding }));
    await user.click(await screen.findByRole("button", { name: "user-alex" }));
    expect(screen.getByRole("heading", { name: "复核 Finding · user-alex" })).toBeTruthy();
    expect(screen.getByText(/归档与取消归档只改变 Finding/)).toBeTruthy();
    expect(readFinding).toHaveBeenCalledWith(analyzer.id, finding.id);
    expect(screen.queryByRole("button", { name: "归档 Finding" })).toBeNull();
    resolveFinding(finding);
    expect(await screen.findByRole("button", { name: "归档 Finding" })).toBeTruthy();
  });

  it("keeps a failed Finding detail read local without rendering the list snapshot as authority", async () => {
    const user = userEvent.setup();
    view(client({ readFinding: vi.fn().mockRejectedValue(new HttpProblem(403, "FORBIDDEN")) }));
    await user.click(await screen.findByRole("button", { name: "user-alex" }));
    expect(await screen.findByText("当前身份没有读取或管理访问分析的权限。其他 IAM 页面不受影响。")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "归档 Finding" })).toBeNull();
    expect(screen.getByRole("button", { name: "重新加载" })).toBeTruthy();
  });

  it("archives a Finding in the content area using its exact resource version", async () => {
    const user = userEvent.setup();
    const archiveFinding = vi.fn().mockResolvedValue({ ...finding, status: "ARCHIVED", resourceVersion: 2, updatedAt: timestamp });
    const value = client({ archiveFinding });
    view(value);
    await user.click(await screen.findByRole("button", { name: "user-alex" }));
    expect(screen.getByRole("heading", { name: "复核 Finding · user-alex" })).toBeTruthy();
    await user.click(await screen.findByRole("button", { name: "归档 Finding" }));
    await waitFor(() => expect(archiveFinding).toHaveBeenCalledWith(analyzer.id, finding.id, expect.objectContaining({ resourceVersion: 1 })));
    expect(await screen.findByText("Finding 已归档；目标对象和权限均未改变。")).toBeTruthy();
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("keeps a forbidden live response local and never substitutes MOCK samples", async () => {
    view(client({ listAnalyzers: vi.fn().mockRejectedValue(new HttpProblem(403, "FORBIDDEN")) }));
    expect(await screen.findByText("当前身份没有读取或管理访问分析的权限。其他 IAM 页面不受影响。")).toBeTruthy();
    expect(screen.queryByText(/123 条样例/)).toBeNull();
    expect(screen.queryByText(/LIVE · NOT_CONNECTED/)).toBeNull();
  });

  it("creates the default analyzer from the explicit empty state", async () => {
    const user = userEvent.setup();
    const createAnalyzer = vi.fn().mockResolvedValue(analyzer);
    view(client({
      listAnalyzers: vi.fn().mockResolvedValue({ accountId: analyzer.accountId, items: [], nextAfter: null }),
      createAnalyzer
    }));
    const empty = await screen.findByText("尚未创建访问分析器");
    await user.click(within(empty.parentElement!).getByRole("button", { name: "创建 90 天分析器" }));
    await waitFor(() => expect(createAnalyzer).toHaveBeenCalledWith(expect.objectContaining({ type: "UNUSED_ACCESS" })));
    expect(await screen.findByText("访问分析器已创建；完整观测窗口形成前可能没有 Finding。")).toBeTruthy();
  });

  it("keeps report-only as the default and reviews a bounded access-key opt-in in the content area", async () => {
    const user = userEvent.setup();
    const setDisposition = vi.fn().mockImplementation(async (_analyzerId, command) => ({
      ...analyzer, disposition: command.disposition, resourceVersion: 2, updatedAt: timestamp
    }));
    view(client({ setDisposition }));
    await user.click(screen.getByRole("tab", { name: "分析规则" }));
    expect(await screen.findByText("仅报告（默认）")).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "配置自动处置" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    await user.click(screen.getByRole("radio", { name: "自动停用闲置访问密钥" }));
    const delay = screen.getByRole("spinbutton", { name: "Finding 观察宽限期" });
    await user.clear(delay);
    await user.type(delay, "31");
    expect((screen.getByRole("button", { name: "下一步：审阅" }) as HTMLButtonElement).disabled).toBe(true);
    await user.clear(delay);
    await user.type(delay, "7");
    await user.click(screen.getByRole("button", { name: "下一步：审阅" }));
    expect(screen.getByText(/规则不追溯旧 Finding/)).toBeTruthy();
    expect(screen.getByText(/Root 访问密钥管理入口不属于候选/)).toBeTruthy();
    expect(screen.getByText("iam.access-analyzer.set-disposition")).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "确认并保存规则" }));
    await waitFor(() => expect(setDisposition).toHaveBeenCalledWith(analyzer.id, expect.objectContaining({
      disposition: { mode: "DISABLE_UNUSED_ACCESS_KEYS", findingDelayDays: 7 }, resourceVersion: 1
    })));
    expect(await screen.findByText(/自动处置规则已更新/)).toBeTruthy();
  });

  it("renders an automatic resolution as bounded evidence rather than a general remediation claim", async () => {
    const user = userEvent.setup();
    const resolved = {
      ...finding,
      type: "UNUSED_ACCESS_KEY" as const,
      target: { kind: "ACCESS_KEY" as const, id: "key-ci" },
      status: "RESOLVED" as const,
      observedAt: timestamp,
      updatedAt: timestamp,
      resolvedAt: timestamp,
      resolutionReason: "AUTOMATIC_DISPOSITION" as const
    };
    view(client({
      listFindings: vi.fn().mockResolvedValue({ ...directory, items: [resolved] }),
      readFinding: vi.fn().mockResolvedValue(resolved)
    }));
    await user.click(await screen.findByRole("button", { name: "key-ci" }));
    expect(await screen.findByText("自动处置完成")).toBeTruthy();
    expect(screen.getByText(/只证明该 Finding 记录了自动处置完成/)).toBeTruthy();
  });

  it("shows the exact recovery generation instead of treating a post-recovery Finding as timeless evidence", async () => {
    const user = userEvent.setup();
    const recovered = {
      ...finding,
      recoveryEpoch: 2,
      recoveryCommandId: "recovery-command-2",
      recoveryCompletedAt: "2026-06-10T08:00:00Z"
    };
    view(client({
      listFindings: vi.fn().mockResolvedValue({ ...directory, items: [recovered] }),
      readFinding: vi.fn().mockResolvedValue(recovered)
    }));
    await user.click(await screen.findByRole("button", { name: "user-alex" }));
    expect(screen.getByRole("region", { name: "恢复代次与观测可信度" })).toBeTruthy();
    expect(screen.getByText("恢复后代次")).toBeTruthy();
    expect(screen.getByText("recovery-command-2")).toBeTruthy();
    expect(screen.getByText(/不能复用为其他对象或后续恢复的处置许可/)).toBeTruthy();
  });

  it("elevates a restore gap above the coverage rows and keeps automatic disposition report-only", async () => {
    const user = userEvent.setup();
    const restoredCoverage: AccessFindingDirectory["coverage"] = [{
      source: "IAM_PASSWORD_SESSIONS",
      state: "INSUFFICIENT_COVERAGE" as const,
      observedFrom: "2026-06-10T08:00:00Z",
      observedThrough: timestamp,
      reason: "RESTORE_GAP" as const
    }, ...coverage.slice(1)];
    view(client({ listFindings: vi.fn().mockResolvedValue({ ...directory, coverage: restoredCoverage, items: [] }) }));
    await user.click(screen.getByRole("tab", { name: "来源覆盖" }));
    expect(await screen.findByText("恢复后观测窗口尚未重建")).toBeTruthy();
    expect(screen.getByText(/恢复前 Finding 不能作为当前结论/)).toBeTruthy();
  });
});
