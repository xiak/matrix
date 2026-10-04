import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { LocaleProvider } from "@/i18n/LocaleProvider";
import { HttpProblem } from "@/infrastructure/http/jsonRequest";
import type { SecurityReportClient } from "../application/AccountAccessProvider";
import { accountSecurityReportCoverage, type AccountSecurityReport } from "../domain/securityReports";
import { LiveSecurityReport } from "./LiveSecurityReport";

const report: AccountSecurityReport = {
  metadata: {
    apiVersion: "iam.matrix.xiak.com/v1", kind: "AccountSecurityReportMetadata", id: "report-one", accountId: "account-acme",
    formatVersion: 1, observedAt: "2026-10-01T08:00:00Z", expiresAt: "2099-10-08T08:00:00Z",
    documentDigest: `sha256:${"a".repeat(64)}`, csvContentDigest: `sha256:${"b".repeat(64)}`,
    userCount: 1, accessKeyCount: 1, rowCount: 3, csvBytes: 128
  },
  accountSecuritySettingsVersion: 4,
  coverage: accountSecurityReportCoverage.map(([source, state]) => ({ source, state })),
  users: [{
    id: "root-acme", loginName: "admin", displayName: "Account owner", status: "ACTIVE", root: true,
    resourceVersion: 4, createdAt: "2026-01-01T00:00:00Z", mfa: { enrollmentState: "BOUND", factorRevision: 2 },
    lastPasswordLogin: { state: "OBSERVED", observedAt: "2026-10-01T07:00:00Z" }
  }],
  accessKeys: [{
    id: "key-one", userId: "root-acme", status: "ENABLED", networkRestrictions: { allowedSourceCidrs: [] },
    resourceVersion: 2, createdAt: "2026-02-01T00:00:00Z"
  }]
};

function client(overrides: Partial<SecurityReportClient> = {}): SecurityReportClient {
  return {
    accountId: report.metadata.accountId,
    sessionRevision: 1,
    create: vi.fn().mockResolvedValue({ outcome: "APPLIED", metadata: report.metadata }),
    read: vi.fn().mockResolvedValue(report),
    download: vi.fn().mockResolvedValue({ metadata: report.metadata, bytes: new TextEncoder().encode("report"), filename: "matrix-iam-security-report-report-one.csv" }),
    ...overrides
  };
}

function view(value: SecurityReportClient) {
  return render(<LocaleProvider><LiveSecurityReport client={value} /></LocaleProvider>);
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("live account security report", () => {
  it("renders its fixed scope and known-ID entry without fabricating a report directory", () => {
    view(client());
    expect(screen.getByRole("heading", { name: "账号安全报告" })).toBeTruthy();
    expect(screen.getByText(/只使用 IAM 已固定的生成、按 ID 读取和下载接口/)).toBeTruthy();
    expect(screen.getByRole("button", { name: "生成当前账号安全报告" })).toBeTruthy();
    expect(screen.getByLabelText("报告 ID")).toBeTruthy();
    expect(screen.queryByText("报告目录摘要")).toBeNull();
    expect(screen.queryByText(/MOCK/)).toBeNull();
  });

  it("creates with the fixed command and then reauthorizes the returned report read", async () => {
    const user = userEvent.setup();
    const value = client();
    view(value);
    await user.click(screen.getByRole("button", { name: "生成当前账号安全报告" }));
    await waitFor(() => expect(value.create).toHaveBeenCalledWith(expect.objectContaining({ formatVersion: 1, requestId: expect.stringMatching(/^ui-security-report-[0-9a-f]{32}$/) })));
    await waitFor(() => expect(value.read).toHaveBeenCalledWith(report.metadata.id));
    expect(await screen.findByRole("heading", { name: report.metadata.id })).toBeTruthy();
    expect(screen.getByText("IAM 已验证")).toBeTruthy();
    expect(screen.getByRole("button", { name: "下载已校验 CSV" })).toBeTruthy();
  });

  it("keeps successful creation visible when the separate detail read is forbidden", async () => {
    const user = userEvent.setup();
    const value = client({ read: vi.fn().mockRejectedValue(new HttpProblem(403, "FORBIDDEN")) });
    view(value);
    await user.click(screen.getByRole("button", { name: "生成当前账号安全报告" }));
    expect(await screen.findByText("报告已由 IAM 封存")).toBeTruthy();
    expect(await screen.findByText(/生成成功都不能绕过重新鉴权/)).toBeTruthy();
    expect(screen.queryByText(/MOCK/)).toBeNull();
  });

  it("reads only an explicitly entered reportId and keeps not-found local", async () => {
    const user = userEvent.setup();
    const read = vi.fn().mockRejectedValue(new HttpProblem(404, "NOT_FOUND"));
    view(client({ read }));
    await user.type(screen.getByLabelText("报告 ID"), "report-missing");
    await user.click(screen.getByRole("button", { name: "读取报告" }));
    await waitFor(() => expect(read).toHaveBeenCalledWith("report-missing"));
    expect(await screen.findByText(/不会回退到 MOCK 数据/)).toBeTruthy();
  });

  it("downloads only through the client that re-reads and verifies current metadata", async () => {
    const user = userEvent.setup();
    const value = client();
    const createObjectURL = vi.fn().mockReturnValue("blob:report");
    const revokeObjectURL = vi.fn();
    vi.stubGlobal("URL", { ...URL, createObjectURL, revokeObjectURL });
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => undefined);
    view(value);
    await user.click(screen.getByRole("button", { name: "生成当前账号安全报告" }));
    await user.click(await screen.findByRole("button", { name: "下载已校验 CSV" }));
    await waitFor(() => expect(value.download).toHaveBeenCalledWith(report.metadata.id));
    expect(createObjectURL).toHaveBeenCalledTimes(1);
    expect(revokeObjectURL).toHaveBeenCalledWith("blob:report");
    expect(screen.getByText(/重新读取最新元数据并核对精确字节数与 SHA-256/)).toBeTruthy();
  });
});
