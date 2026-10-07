import { act, cleanup, render, screen, waitFor, within } from "@testing-library/react";
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

  it("clears the old directory immediately when the exact client changes and ignores its late response", async () => {
    let resolveOldDirectory!: (value: Awaited<ReturnType<AccessAnalysisClient["listAnalyzers"]>>) => void;
    const oldDirectory = new Promise<Awaited<ReturnType<AccessAnalysisClient["listAnalyzers"]>>>((resolve) => { resolveOldDirectory = resolve; });
    const first = client({ listAnalyzers: vi.fn().mockReturnValue(oldDirectory) });
    const nextAnalyzer = { ...analyzer, id: "analyzer-replacement", resourceVersion: 8 };
    const nextFinding = {
      ...finding,
      id: "finding-replacement",
      analyzerId: nextAnalyzer.id,
      target: { kind: "USER" as const, id: "user-replacement" }
    };
    const replacement = client({
      listAnalyzers: vi.fn().mockResolvedValue({ accountId: analyzer.accountId, items: [nextAnalyzer], nextAfter: null }),
      listFindings: vi.fn().mockResolvedValue({ ...directory, analyzerId: nextAnalyzer.id, items: [nextFinding] })
    });
    const rendered = view(first);

    rendered.rerender(<LocaleProvider><LiveAccessAnalysis client={replacement} onNavigate={vi.fn()} /></LocaleProvider>);

    expect(screen.getByRole("heading", { name: "访问分析" })).toBeTruthy();
    expect(await screen.findByRole("button", { name: "user-replacement" })).toBeTruthy();
    await act(async () => {
      resolveOldDirectory({ accountId: analyzer.accountId, items: [analyzer], nextAfter: null });
      await oldDirectory;
    });
    expect(screen.getByRole("button", { name: "user-replacement" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "user-alex" })).toBeNull();
  });

  it("removes an old pending Finding detail on exact client replacement and never restores it", async () => {
    const user = userEvent.setup();
    let resolveOldFinding!: (value: typeof finding) => void;
    const oldDetail = new Promise<typeof finding>((resolve) => { resolveOldFinding = resolve; });
    const first = client({ readFinding: vi.fn().mockReturnValue(oldDetail) });
    const replacementFinding = { ...finding, id: "finding-next", target: { kind: "USER" as const, id: "user-next" } };
    const replacement = client({ listFindings: vi.fn().mockResolvedValue({ ...directory, items: [replacementFinding] }) });
    const rendered = view(first);
    await user.click(await screen.findByRole("button", { name: "user-alex" }));
    expect(screen.getByRole("heading", { name: "复核 Finding · user-alex" })).toBeTruthy();

    rendered.rerender(<LocaleProvider><LiveAccessAnalysis client={replacement} onNavigate={vi.fn()} /></LocaleProvider>);

    expect(screen.queryByRole("heading", { name: "复核 Finding · user-alex" })).toBeNull();
    expect(await screen.findByRole("button", { name: "user-next" })).toBeTruthy();
    await act(async () => {
      resolveOldFinding(finding);
      await oldDetail;
    });
    expect(screen.queryByRole("heading", { name: "复核 Finding · user-alex" })).toBeNull();
    expect(screen.getByRole("button", { name: "user-next" })).toBeTruthy();
  });

  it("does not project a write result completed by a client that has been replaced", async () => {
    const user = userEvent.setup();
    let resolveOldUpdate!: (value: typeof analyzer) => void;
    const oldUpdate = new Promise<typeof analyzer>((resolve) => { resolveOldUpdate = resolve; });
    const first = client({ updateAnalyzer: vi.fn().mockReturnValue(oldUpdate) });
    const replacementAnalyzer = { ...analyzer, unusedAccessAgeDays: 120, resourceVersion: 7 };
    const replacement = client({
      listAnalyzers: vi.fn().mockResolvedValue({ accountId: analyzer.accountId, items: [replacementAnalyzer], nextAfter: null }),
      listFindings: vi.fn().mockResolvedValue({ ...directory, analyzerId: replacementAnalyzer.id })
    });
    const rendered = view(first);
    await user.click(screen.getByRole("tab", { name: "分析规则" }));
    const window = await screen.findByRole("spinbutton", { name: "完整观测窗口" });
    await user.clear(window);
    await user.type(window, "30");
    await user.click(screen.getByRole("button", { name: "保存分析规则" }));

    rendered.rerender(<LocaleProvider><LiveAccessAnalysis client={replacement} onNavigate={vi.fn()} /></LocaleProvider>);

    await user.click(screen.getByRole("tab", { name: "分析规则" }));
    await waitFor(() => expect((screen.getByRole("spinbutton", { name: "完整观测窗口" }) as HTMLInputElement).value).toBe("120"));
    expect((screen.getByRole("button", { name: "保存分析规则" }) as HTMLButtonElement).disabled).toBe(true);
    await act(async () => {
      resolveOldUpdate({ ...analyzer, unusedAccessAgeDays: 30, resourceVersion: 2 });
      await oldUpdate;
    });
    expect((screen.getByRole("spinbutton", { name: "完整观测窗口" }) as HTMLInputElement).value).toBe("120");
    expect(screen.queryByText("分析规则已更新；这不会立即重算 Finding 或处置任何对象。")).toBeNull();
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

  it("retries an unknown Analyzer write with the exact original command", async () => {
    const user = userEvent.setup();
    const updateAnalyzer = vi.fn()
      .mockRejectedValueOnce(new HttpProblem(503, "UNAVAILABLE"))
      .mockResolvedValueOnce({ ...analyzer, unusedAccessAgeDays: 30, resourceVersion: 2, updatedAt: timestamp });
    view(client({ updateAnalyzer }));
    await user.click(screen.getByRole("tab", { name: "分析规则" }));
    const window = await screen.findByRole("spinbutton", { name: "完整观测窗口" });
    await user.clear(window);
    await user.type(window, "30");
    await user.click(screen.getByRole("button", { name: "保存分析规则" }));

    expect(await screen.findByRole("button", { name: "重试原命令" })).toBeTruthy();
    const original = updateAnalyzer.mock.calls[0]?.[1];
    expect(original).toEqual(expect.objectContaining({
      status: "ACTIVE", unusedAccessAgeDays: 30, resourceVersion: 1,
      requestId: expect.stringMatching(/^ui-access-analyzer-update-[0-9a-f]{32}$/)
    }));
    expect((screen.getByRole("spinbutton", { name: "完整观测窗口" }) as HTMLInputElement).disabled).toBe(true);
    expect((screen.getByRole("group", { name: "规则状态" }) as HTMLFieldSetElement).disabled).toBe(true);
    await user.click(screen.getByRole("button", { name: "重试原命令" }));
    await waitFor(() => expect(updateAnalyzer).toHaveBeenCalledTimes(2));
    expect(updateAnalyzer.mock.calls[1]?.[1]).toEqual(original);
    expect(await screen.findByText("分析规则已更新；这不会立即重算 Finding 或处置任何对象。")).toBeTruthy();
  });

  it("keeps the Analyzer draft after a stale-version conflict and requires a new explicit command", async () => {
    const user = userEvent.setup();
    const latest = { ...analyzer, unusedAccessAgeDays: 120, resourceVersion: 2, updatedAt: timestamp };
    const updateAnalyzer = vi.fn()
      .mockRejectedValueOnce(new HttpProblem(409, "RESOURCE_VERSION_CONFLICT"))
      .mockResolvedValueOnce({ ...latest, unusedAccessAgeDays: 30, resourceVersion: 3 });
    const readAnalyzer = vi.fn().mockResolvedValue(latest);
    view(client({ readAnalyzer, updateAnalyzer }));
    await user.click(screen.getByRole("tab", { name: "分析规则" }));
    const window = await screen.findByRole("spinbutton", { name: "完整观测窗口" });
    await user.clear(window);
    await user.type(window, "30");
    await user.click(screen.getByRole("button", { name: "保存分析规则" }));

    await waitFor(() => expect(readAnalyzer).toHaveBeenCalledWith(analyzer.id));
    expect((screen.getByRole("spinbutton", { name: "完整观测窗口" }) as HTMLInputElement).value).toBe("30");
    expect(updateAnalyzer).toHaveBeenCalledTimes(1);
    const firstRequestId = updateAnalyzer.mock.calls[0]?.[1].requestId;

    await user.click(screen.getByRole("button", { name: "保存分析规则" }));
    await waitFor(() => expect(updateAnalyzer).toHaveBeenCalledTimes(2));
    expect(updateAnalyzer.mock.calls[1]?.[1]).toEqual(expect.objectContaining({
      status: "ACTIVE", unusedAccessAgeDays: 30, resourceVersion: 2,
      requestId: expect.not.stringMatching(new RegExp(`^${firstRequestId}$`))
    }));
  });

  it("clears Analyzer and Finding projections when the login session expires", async () => {
    const user = userEvent.setup();
    view(client({ updateAnalyzer: vi.fn().mockRejectedValue(new HttpProblem(401, "UNAUTHORIZED")) }));
    await user.click(screen.getByRole("tab", { name: "分析规则" }));
    const window = await screen.findByRole("spinbutton", { name: "完整观测窗口" });
    await user.clear(window);
    await user.type(window, "30");
    await user.click(screen.getByRole("button", { name: "保存分析规则" }));

    expect(await screen.findByText(/页面已清除 Analyzer、Finding 与待处理命令投影/)).toBeTruthy();
    expect(screen.getByText("无法读取访问分析")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "重试原命令" })).toBeNull();
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
