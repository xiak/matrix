import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { SessionProvider } from "@/features/auth/application/SessionProvider";
import type { IamRepository } from "@/features/auth/repositories/iamRepository";
import { HttpProblem } from "@/infrastructure/http/jsonRequest";
import { useConsoleUiStore } from "../application/consoleUiStore";
import type { ControlPlaneSnapshot } from "../domain/resources";
import type { ConsoleSection } from "../domain/selection";
import type { ControlPlaneRepository } from "../repositories/controlPlaneRepository";
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

async function renderConsole({
  section = "overview",
  load = vi.fn().mockResolvedValue(snapshot),
  logout = vi.fn().mockResolvedValue(undefined)
}: {
  section?: ConsoleSection;
  load?: ControlPlaneRepository["load"];
  logout?: IamRepository["logout"];
} = {}) {
  const repository: ControlPlaneRepository = {
    load,
    getInstallation: vi.fn(),
    activateQuota: vi.fn(),
    createInstallation: vi.fn()
  };
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
      <ConsoleShellRenderer repository={repository} selection={{ section }} />
    </SessionProvider>
  );
  await user.type(screen.getByLabelText("密码", { exact: true }), "renderer-test-password");
  await user.click(screen.getByRole("button", { name: "登录控制台" }));
  await waitFor(() => expect(load).toHaveBeenCalled());
  navigation.replace.mockClear();
  return { user, view, repository };
}

afterEach(() => {
  cleanup();
  useConsoleUiStore.setState({ sidebarOverlayOpen: false, workspaceOpen: true });
  vi.clearAllMocks();
});

describe("ConsoleShellRenderer", () => {
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
