import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { SessionProvider } from "@/features/auth/application/SessionProvider";
import type { IamRepository } from "@/features/auth/repositories/iamRepository";
import { HttpProblem } from "@/infrastructure/http/jsonRequest";
import { useConsoleUiStore } from "../application/consoleUiStore";
import type { ControlPlaneSnapshot } from "../domain/resources";
import type { ExperienceSnapshot } from "../domain/experience";
import type { ConsoleSection } from "../domain/selection";
import type { ControlPlaneRepository } from "../repositories/controlPlaneRepository";
import { previewExperienceSnapshot } from "../repositories/previewExperienceSnapshot";
import { ConsoleShellRenderer } from "./ConsoleShellRenderer";

const navigation = vi.hoisted(() => ({ push: vi.fn(), replace: vi.fn() }));

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
  experience,
  load = vi.fn().mockResolvedValue(snapshot),
  logout = vi.fn().mockResolvedValue(undefined)
}: {
  section?: ConsoleSection;
  experience?: ExperienceSnapshot;
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
      <ConsoleShellRenderer experience={experience} repository={repository} selection={{ section }} />
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
  it("shows failed revocation without claiming logout or revealing the upstream error", async () => {
    const logout = vi.fn().mockRejectedValue(new Error("private upstream diagnostic"));
    const { user, view } = await renderConsole({ logout });
    await user.click(await screen.findByRole("button", { name: /打开账号菜单/ }));
    await user.click(screen.getByRole("menuitem", { name: "注销并撤销 IAM 会话" }));

    expect((await screen.findByRole("alert")).textContent).toContain("会话仍保留");
    expect(screen.queryByRole("dialog", { name: "账号菜单" })).toBeNull();
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

  it("supports global search and keyboard navigation in preview mode", async () => {
    const { user } = await renderConsole({ experience: previewExperienceSnapshot });
    expect((await screen.findByRole("heading", { level: 1 })).textContent).toBe("云控制台");

    const search = screen.getByRole("combobox", { name: "搜索产品、资源和页面" });
    await user.click(search);
    await user.type(search, "支付");
    expect(screen.getByRole("option", { name: /支付服务/ })).toBeTruthy();
    await user.keyboard("{Enter}");
    expect(navigation.push).toHaveBeenCalledWith("/console/observability/");
  });

  it("owns principal identity and logout in one global account menu", async () => {
    const { user } = await renderConsole();
    const account = await screen.findByRole("button", { name: "打开账号菜单，当前用户 admin" });

    expect(screen.queryByRole("button", { name: "注销并撤销 IAM 会话" })).toBeNull();
    await user.click(account);

    const menu = screen.getByRole("dialog", { name: "账号菜单" });
    expect(menu.textContent).toContain("admin");
    expect(menu.textContent).toContain("principal-test");
    expect(menu.textContent).toContain("organization-test");
    expect(screen.getAllByRole("menuitem", { name: "注销并撤销 IAM 会话" })).toHaveLength(1);
    expect(screen.getByRole("menuitem", { name: /账号与权限/ })).toBeTruthy();

    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog", { name: "账号菜单" })).toBeNull();
    expect(document.activeElement).toBe(account);
  });

  it("applies the persistent project scope to unified resources", async () => {
    const { user } = await renderConsole({ section: "resources", experience: previewExperienceSnapshot });
    await screen.findByRole("heading", { level: 1, name: "资源中心" });
    await user.selectOptions(screen.getByRole("combobox", { name: "选择项目范围" }), "platform-dev");

    expect(screen.getByRole("link", { name: "edge-worker-01" })).toBeTruthy();
    expect(screen.getByRole("link", { name: "Matrix 开发库" })).toBeTruthy();
    expect(screen.queryByRole("link", { name: "订单主库" })).toBeNull();

    const compactScope = screen.getByRole("button", { name: /打开资源范围，项目 平台研发 · 测试/ });
    await user.click(compactScope);
    expect((screen.getByRole("combobox", { name: "紧凑模式选择项目范围" }) as HTMLSelectElement).value).toBe("platform-dev");
    await user.click(screen.getByRole("button", { name: "打开产品与服务" }));
    expect(screen.queryByRole("dialog", { name: "资源范围" })).toBeNull();
    expect(screen.getByRole("dialog", { name: "云产品入口" })).toBeTruthy();
  });
});
