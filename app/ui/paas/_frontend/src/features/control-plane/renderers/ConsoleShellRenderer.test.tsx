import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { SessionProvider } from "@/features/auth/application/SessionProvider";
import type { IamRepository } from "@/features/auth/repositories/iamRepository";
import { HttpProblem } from "@/infrastructure/http/jsonRequest";
import { useConsoleUiStore } from "../application/consoleUiStore";
import type { ControlPlaneSnapshot } from "../domain/resources";
import type { HostInventory } from "../domain/hosts";
import type { ConsoleSection } from "../domain/selection";
import type { ControlPlaneRepository } from "../repositories/controlPlaneRepository";
import type { HostInventoryRepository } from "../repositories/hostInventoryRepository";
import { ConsoleShellRenderer } from "./ConsoleShellRenderer";

const navigation = vi.hoisted(() => ({ replace: vi.fn() }));

vi.mock("next/navigation", () => ({ useRouter: () => navigation }));

const snapshot: ControlPlaneSnapshot = {
  offerings: [{
    id: "postgresql-18",
    kind: "POSTGRESQL",
    displayName: "PostgreSQL 18",
    description: "Managed PostgreSQL",
    engineFamily: "postgresql",
    engineVersion: "18",
    state: "AVAILABLE",
    quotaShapes: [{
      id: "pg-small",
      displayName: "开发型",
      cpuMillicores: 500,
      memoryMiB: 1024,
      storageGiB: 10
    }]
  }],
  regions: [{
    id: "local-primary",
    displayName: "本机主区域",
    profile: "LOCAL_MACHINE",
    state: "READY",
    inspectedAt: "2026-08-26T12:00:00Z",
    capacity: { cpuMillicores: 4000, memoryMiB: 8192, storageGiB: 100 }
  }],
  entitlements: [{
    id: "quota-primary",
    offeringId: "postgresql-18",
    quotaShapeId: "pg-small",
    purchasedCount: 1,
    reservedCount: 0,
    consumedCount: 0,
    resourceVersion: 1,
    activatedAt: "2026-08-26T12:00:00Z"
  }],
  installations: []
};

const hostSnapshot: HostInventory = {
  items: [{
    id: "node-a",
    name: "node-a",
    labels: { "matrix-os": "linux", "matrix-arch": "amd64" },
    resourceVersion: 4,
    executionPoolId: "linux-hosts",
    infrastructureAdapter: "nodehttps",
    deploymentExecutor: "compose",
    desiredState: "ACTIVE",
    health: "READY",
    capacity: { cpuMillis: 4000, memoryBytes: 8_589_934_592, storageBytes: 107_374_182_400, workloadSlots: 24 },
    allocatable: { cpuMillis: 3000, memoryBytes: 6_442_450_944, storageBytes: 85_899_345_920, workloadSlots: 16 },
    supportedIsolationGuarantees: ["WORKLOAD"],
    observedAt: "2026-08-30T08:01:00Z",
    usage: {
      observedAt: "2026-08-30T08:01:00Z",
      validUntil: "2026-08-30T08:01:15Z",
      cpu: { state: "AVAILABLE", value: { logicalCpus: 4, windowMillis: 5000, utilizationRatio: 0.25, ioWaitRatio: 0.05, load1: 0.8, load5: 0.6, load15: 0.4 } },
      memory: { state: "AVAILABLE", value: { totalBytes: 8_589_934_592, availableBytes: 6_442_450_944, usedBytes: 2_147_483_648, swapTotalBytes: 0, swapFreeBytes: 0 } },
      filesystemsState: "AVAILABLE",
      filesystems: [{
        device: "/dev/vda1", mountPoint: "/", filesystemType: "ext4", state: "AVAILABLE",
        value: { totalBytes: 107_374_182_400, usedBytes: 21_474_836_480, availableBytes: 85_899_345_920, inodesState: "UNSUPPORTED", totalInodes: null, freeInodes: null, readOnly: false }
      }]
    }
  }]
};

async function renderConsole({
  section = "overview",
  hostLoad = vi.fn().mockResolvedValue({ items: [] }),
  load = vi.fn().mockResolvedValue(snapshot),
  logout = vi.fn().mockResolvedValue(undefined)
}: {
  section?: ConsoleSection;
  hostLoad?: HostInventoryRepository["load"];
  load?: ControlPlaneRepository["load"];
  logout?: IamRepository["logout"];
} = {}) {
  const repository: ControlPlaneRepository = {
    load,
    getInstallation: vi.fn(),
    activateQuota: vi.fn(),
    createInstallation: vi.fn()
  };
  const hostRepository: HostInventoryRepository = { load: hostLoad };
  const iam: IamRepository = {
    async login() {
      return {
        credential: "renderer-test-memory-only-session",
        mustChangePassword: false,
        session: {
          id: "session-test",
          organizationId: "organization-test",
          principalId: "principal-test",
          status: "ACTIVE",
          issuedAt: "2026-08-26T12:00:00Z",
          expiresAt: "2099-08-26T20:00:00Z"
        }
      };
    },
    async changePassword() {},
    logout
  };
  const user = userEvent.setup();
  const view = render(
    <SessionProvider repository={iam}>
      <ConsoleShellRenderer hostRepository={hostRepository} repository={repository} selection={{ section }} />
    </SessionProvider>
  );
  await user.type(screen.getByLabelText("密码", { exact: true }), "renderer-test-password");
  await user.click(screen.getByRole("button", { name: "登录控制台" }));
  await waitFor(() => expect(section === "hosts" ? hostLoad : load).toHaveBeenCalled());
  navigation.replace.mockClear();
  return { user, view, repository, hostRepository };
}

afterEach(() => {
  cleanup();
  useConsoleUiStore.setState({ sidebarOverlayOpen: false, workspaceOpen: true });
  vi.clearAllMocks();
});

describe("ConsoleShellRenderer", () => {
  it("shows source-timed CPU, memory, and filesystem facts without loading tenant resources", async () => {
    const load = vi.fn();
    await renderConsole({
      section: "hosts",
      load,
      hostLoad: vi.fn().mockResolvedValue(hostSnapshot)
    });

    expect(await screen.findByRole("heading", { level: 1, name: "主机与资源" })).toBeTruthy();
    expect(screen.getByText("25.0%")).toBeTruthy();
    expect(screen.getByText("2 GiB / 8 GiB")).toBeTruthy();
    expect(screen.getByText("/dev/vda1 · ext4")).toBeTruthy();
    expect(screen.getByRole("progressbar", { name: "CPU占用率" })).toHaveProperty("value", 25);
    expect(screen.getByText(/资源采样：/)).toBeTruthy();
    expect(screen.getByText(/有效至：/)).toBeTruthy();
    expect(load).not.toHaveBeenCalled();
  });

  it.each([
    { missing: "quota", label: "配额", value: "quota-primary" },
    { missing: "region", label: "安装区域", value: "local-primary" }
  ] as const)("requires an explicit selection for $missing choices that arrive after reload", async ({ missing, label, value }) => {
    const load = vi.fn().mockResolvedValue({
      ...snapshot,
      ...(missing === "quota" ? { entitlements: [] } : { regions: [] })
    });
    const { user, repository } = await renderConsole({ section: "installations", load });
    expect(screen.queryByRole("button", { name: "提交安装任务" })).toBeNull();
    load.mockResolvedValue(snapshot);
    await user.click(screen.getByRole("button", { name: "刷新" }));

    const select = await screen.findByRole("combobox", { name: label }) as HTMLSelectElement;
    const submit = screen.getByRole("button", { name: "提交安装任务" }) as HTMLButtonElement;
    expect(select.value).toBe("");
    expect(submit.disabled).toBe(true);
    await user.selectOptions(select, value);
    expect(submit.disabled).toBe(false);
    vi.mocked(repository.createInstallation).mockRejectedValue(new HttpProblem(403, "DENIED"));
    await user.click(submit);
    expect(repository.createInstallation).toHaveBeenCalledWith("renderer-test-memory-only-session", {
      id: "postgres-primary", name: "postgres-primary", offeringId: "postgresql-18",
      quotaEntitlementId: "quota-primary", regionId: "local-primary"
    });
  });

  it.each([
    { replaced: "quota", label: "配额", value: "quota-secondary" },
    { replaced: "region", label: "安装区域", value: "local-secondary" }
  ] as const)("never silently rebinds a selected $replaced when refreshed choices change", async ({ replaced, label, value }) => {
    const load = vi.fn().mockResolvedValue(snapshot);
    const { user, repository } = await renderConsole({ section: "installations", load });
    await user.clear(await screen.findByLabelText("实例 ID"));
    await user.type(screen.getByLabelText("实例 ID"), "retained-instance");
    await user.clear(screen.getByLabelText("显示名称"));
    await user.type(screen.getByLabelText("显示名称"), "Retained input");
    load.mockResolvedValue({
      ...snapshot,
      ...(replaced === "quota" ? {
        entitlements: [{ ...snapshot.entitlements[0], id: value }]
      } : {
        regions: [{ ...snapshot.regions[0], id: value }]
      })
    });
    await user.click(screen.getByRole("button", { name: "刷新" }));

    const select = screen.getByRole("combobox", { name: label }) as HTMLSelectElement;
    const submit = screen.getByRole("button", { name: "提交安装任务" }) as HTMLButtonElement;
    await waitFor(() => expect(select.value).toBe(""));
    expect(submit.disabled).toBe(true);
    expect((screen.getByLabelText("实例 ID") as HTMLInputElement).value).toBe("retained-instance");
    expect((screen.getByLabelText("显示名称") as HTMLInputElement).value).toBe("Retained input");
    await user.click(submit);
    expect(repository.createInstallation).not.toHaveBeenCalled();
    await user.selectOptions(select, value);
    expect(submit.disabled).toBe(false);
    vi.mocked(repository.createInstallation).mockRejectedValue(new HttpProblem(403, "DENIED"));
    await user.click(submit);
    expect(repository.createInstallation).toHaveBeenCalledWith("renderer-test-memory-only-session", {
      id: "retained-instance", name: "Retained input", offeringId: "postgresql-18",
      quotaEntitlementId: replaced === "quota" ? value : "quota-primary",
      regionId: replaced === "region" ? value : "local-primary"
    });
  });

  it.each([
    { section: "quotas", mutation: "activateQuota", heading: "激活服务配额", submit: "确认激活配额", success: "配额已由平台确认" },
    { section: "installations", mutation: "createInstallation", heading: "安装 PostgreSQL", submit: "提交安装任务", success: "安装任务已由平台接受" }
  ] as const)("keeps a denied $section command visible in the active panel without duplicate alerts", async ({ section, mutation, heading, submit, success }) => {
    const { user, repository, view } = await renderConsole({ section });
    vi.mocked(repository[mutation]).mockRejectedValue(new HttpProblem(403, "private authority diagnostic"));
    await user.click(await screen.findByRole("button", { name: submit }));

    const alert = await screen.findByRole("alert");
    const panel = screen.getAllByRole("complementary").find((element) =>
      within(element).queryByRole("heading", { name: heading })
    )!;
    expect(within(panel).getByRole("alert")).toBe(alert);
    expect(alert.textContent).toContain("当前角色无权执行此操作");
    expect(within(screen.getByRole("main")).queryByRole("alert")).toBeNull();
    expect(view.container.textContent).not.toContain(success);
    expect(view.container.textContent).not.toContain("private authority diagnostic");
    expect(view.container.textContent).not.toContain("renderer-test-memory-only-session");

    await user.click(screen.getByRole("button", { name: "收起面板" }));
    expect(within(screen.getByRole("main")).getByRole("alert").textContent).toContain("当前角色无权执行此操作");
    expect(screen.getAllByRole("alert")).toHaveLength(1);

    await user.click(screen.getByRole("button", { name: "打开面板" }));
    expect(within(panel).getByRole("alert").textContent).toContain("当前角色无权执行此操作");
    expect(screen.getAllByRole("alert")).toHaveLength(1);
    expect(repository[mutation]).toHaveBeenCalledTimes(1);
  });

  it("shows failed revocation without claiming logout or revealing the upstream error", async () => {
    const logout = vi.fn().mockRejectedValue(new Error("private upstream diagnostic"));
    const { user, view } = await renderConsole({ logout });
    await user.click(await screen.findByRole("button", { name: "注销并撤销 IAM 会话" }));

    expect((await screen.findByRole("alert")).textContent).toContain("会话仍保留");
    expect(screen.getByRole("heading", { level: 1 }).textContent).toBe("控制面概览");
    expect(navigation.replace).not.toHaveBeenCalled();
    expect(view.container.textContent).not.toContain("private upstream diagnostic");
    expect(view.container.textContent).not.toContain("renderer-test-memory-only-session");
  });

  it("allows logout after the resource load fails", async () => {
    const load = vi.fn().mockRejectedValue(new HttpProblem(401, "SESSION_REVOKED"));
    const logout = vi.fn().mockResolvedValue(undefined);
    const { user } = await renderConsole({ load, logout });
    expect((await screen.findByRole("alert")).textContent).toContain("IAM 会话已失效");

    await user.click(screen.getByRole("button", { name: "注销并撤销 IAM 会话" }));

    await screen.findByRole("button", { name: "登录控制台" });
    expect(logout).toHaveBeenCalledWith("renderer-test-memory-only-session");
    expect(navigation.replace).toHaveBeenCalledWith("/");
  });

  it("keeps logout reachable while resources are still loading and disables duplicate revocation", async () => {
    const load = vi.fn(() => new Promise<ControlPlaneSnapshot>(() => {}));
    let confirmRevocation!: () => void;
    const logout = vi.fn(() => new Promise<void>((resolve) => { confirmRevocation = resolve; }));
    const { user } = await renderConsole({ load, logout });
    const exit = screen.getByRole("button", { name: "注销并撤销 IAM 会话" });

    await user.click(exit);
    expect((exit as HTMLButtonElement).disabled).toBe(true);
    await user.click(exit);
    expect(logout).toHaveBeenCalledTimes(1);
    expect(navigation.replace).not.toHaveBeenCalled();

    await act(async () => confirmRevocation());
    expect(navigation.replace).toHaveBeenCalledWith("/");
  });

  it("bounds keyboard resizing without scrolling the page", async () => {
    await renderConsole();
    const separator = await screen.findByRole("separator", { name: "调整上下文面板宽度" });
    for (const [key, value] of [
      ["ArrowLeft", "3"], ["ArrowLeft", "3"], ["ArrowRight", "2"],
      ["Home", "1"], ["ArrowRight", "1"], ["End", "3"]
    ]) {
      expect(fireEvent.keyDown(separator, { key })).toBe(false);
      expect(separator.getAttribute("aria-valuenow")).toBe(value);
    }
    expect(fireEvent.keyDown(separator, { key: "Tab" })).toBe(true);
  });

  it("uses a valid native installation ID pattern with the same admitted IDs as the form", async () => {
    const { user } = await renderConsole({ section: "installations" });
    const input = await screen.findByLabelText("实例 ID") as HTMLInputElement;
    const nativePattern = new RegExp(`^(?:${input.pattern})$`, "v");
    const submit = screen.getByRole("button", { name: "提交安装任务" }) as HTMLButtonElement;

    for (const id of ["pg-primary", "pg_primary", "pg.primary", "pg01"]) {
      await user.clear(input);
      await user.type(input, id);
      expect(nativePattern.test(id)).toBe(true);
      expect(submit.disabled).toBe(false);
    }
    for (const id of ["x", "Pg-primary", "pg/primary", "pg primary", "pg-"]) {
      await user.clear(input);
      await user.type(input, id);
      expect(nativePattern.test(id)).toBe(false);
      expect(submit.disabled).toBe(true);
    }
  });
});
