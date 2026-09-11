import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import type { ComponentProps } from "react";
import userEvent from "@testing-library/user-event";
import { LocaleProvider } from "@/i18n/LocaleProvider";
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

const navigation = vi.hoisted(() => ({ push: vi.fn(), replace: vi.fn(), query: "" }));
const contentRender = vi.hoisted(() => vi.fn());
const accountMenuRender = vi.hoisted(() => vi.fn());

vi.mock("next/navigation", () => ({ useRouter: () => navigation, useSearchParams: () => new URLSearchParams(navigation.query) }));
vi.mock("./AccountMenu", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./AccountMenu")>();
  return { ...actual, AccountMenu: (props: ComponentProps<typeof actual.AccountMenu>) => { accountMenuRender(); return <actual.AccountMenu {...props} />; } };
});
vi.mock("./ConsoleContentRenderer", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./ConsoleContentRenderer")>();
  return {
    ConsoleContentRenderer: (props: ComponentProps<typeof actual.ConsoleContentRenderer>) => {
      // Assert the page boundary is not invalidated. Descendants such as Next
      // links may legitimately commit their own local prefetch/focus updates.
      contentRender();
      return <actual.ConsoleContentRenderer {...props} />;
    }
  };
});

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
  openWorkspace = false,
  load = vi.fn().mockResolvedValue(snapshot),
  logout = vi.fn().mockResolvedValue(undefined)
}: {
  section?: ConsoleSection;
  experience?: ExperienceSnapshot;
  openWorkspace?: boolean;
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
    <LocaleProvider><SessionProvider repository={iam}>
      <ConsoleShellRenderer experience={experience} repository={repository} selection={{ section }} />
    </SessionProvider></LocaleProvider>
  );
  await user.type(screen.getByLabelText("密码", { exact: true }), "renderer-test-password");
  await user.click(screen.getByRole("button", { name: "登录控制台" }));
  await waitFor(() => expect(load).toHaveBeenCalled());
  if (openWorkspace) await user.click(await screen.findByRole("button", { name: section === "quotas" ? "激活配额" : section === "installations" ? "安装服务" : "查看平台状态" }));
  const loginDestination = navigation.replace.mock.calls.at(-1)?.[0];
  navigation.replace.mockClear();
  return { user, view, repository, loginDestination };
}

afterEach(() => {
  cleanup();
  localStorage.clear();
  useConsoleUiStore.setState({ sidebarOverlayOpen: false, workspaceOpen: false });
  vi.clearAllMocks();
  navigation.query = "";
});

describe("ConsoleShellRenderer", () => {
  it("shows one localized service name and starts its sidebar with useful navigation", async () => {
    const { user } = await renderConsole({ section: "applications", experience: previewExperienceSnapshot });
    const navigation = await screen.findByRole("navigation", { name: "控制台导航" });
    const sidebar = navigation.parentElement!;
    expect(within(sidebar).getAllByText("应用托管")).toHaveLength(1);
    expect(within(sidebar).queryByText("Application hosting")).toBeNull();
    expect(within(navigation).queryByText("服务导航")).toBeNull();
    expect(within(navigation).getByRole("link", { name: /^应用/ }).getAttribute("aria-current")).toBe("page");

    await user.click(screen.getByRole("button", { name: "打开账号菜单，当前用户 admin" }));
    await user.click(screen.getByRole("radio", { name: "English" }));
    expect(within(sidebar).getAllByText("Application hosting")).toHaveLength(1);
    expect(within(sidebar).queryByText("应用托管")).toBeNull();
    expect(within(navigation).queryByText("Service navigation")).toBeNull();
    expect(within(navigation).getByRole("link", { name: /^Applications/ }).getAttribute("href")).toMatch(/^\/console\/applications\/?$/);
  });

  it("keeps data-refresh feedback local without rerendering static global-header controls", async () => {
    let resolve!: (value: ControlPlaneSnapshot) => void;
    const load = vi.fn().mockResolvedValueOnce(snapshot).mockImplementation(() => new Promise<ControlPlaneSnapshot>(done => { resolve = done; }));
    const { user } = await renderConsole({ section: "resources", experience: previewExperienceSnapshot, load });
    await screen.findByRole("heading", { name: "资源中心", level: 1 });
    const header = screen.getByLabelText("全局导航");
    accountMenuRender.mockClear();
    await user.click(screen.getByRole("button", { name: "刷新" }));
    expect(screen.getByRole("progressbar", { name: "正在刷新当前页面…" }).closest("header")).not.toBe(header);
    expect(within(header).queryByRole("progressbar")).toBeNull();
    expect(accountMenuRender).not.toHaveBeenCalled();
    await act(async () => resolve(snapshot));
  });

  it("retains entity search parameters through sign-in without accepting a query redirect", async () => {
    navigation.query = "id=resource%2Fexample&returnTo=https%3A%2F%2Foutside.invalid";
    const { loginDestination } = await renderConsole({ section: "resources", experience: previewExperienceSnapshot });
    expect(loginDestination).toBe("/console/resources/?" + navigation.query);
  });
  it("isolates header interactions from service rendering while still applying region and locale changes", async () => {
    const { user } = await renderConsole({ section: "resources", experience: previewExperienceSnapshot });
    await screen.findByRole("heading", { level: 1, name: "资源中心" });
    contentRender.mockClear();

    for (const trigger of [/打开消息中心/, /打开账号菜单/, /选择区域范围/]) {
      await user.click(screen.getByRole("button", { name: trigger }));
      expect(screen.getByRole("dialog")).toBeTruthy();
      await user.keyboard("{Escape}");
    }
    await user.click(screen.getByRole("button", { name: "打开产品与服务" }));
    expect(screen.getByRole("main").closest("[inert]")).not.toBeNull();
    await user.click(within(screen.getByRole("dialog", { name: "云产品入口" })).getByRole("button", { name: "关闭产品与服务" }));
    await user.click(screen.getByRole("combobox", { name: "搜索产品、资源和页面" }));
    await user.keyboard("{Escape}");
    expect(contentRender).not.toHaveBeenCalled();

    await user.click(screen.getByRole("button", { name: /选择区域范围/ }));
    await user.click(screen.getByRole("option", { name: /上海私有云 B 区/ }));
    expect(screen.queryByRole("link", { name: "订单主库" })).toBeNull();
    expect(screen.getByRole("link", { name: "edge-worker-01" })).toBeTruthy();
    expect(contentRender).toHaveBeenCalled();
    contentRender.mockClear();

    await user.click(screen.getByRole("button", { name: /打开账号菜单/ }));
    await user.click(screen.getByRole("radio", { name: "English" }));
    expect(screen.getByRole("heading", { level: 1 }).textContent).toBe("Resource center");
    expect(contentRender).toHaveBeenCalled();
  });

  it("opens the full-screen directory without a dimming stage while retaining compact-panel dismissal", async () => {
    const { user } = await renderConsole({ experience: previewExperienceSnapshot });
    const trigger = await screen.findByRole("button", { name: "打开产品与服务" });
    const workspace = screen.getByRole("main");

    fireEvent.click(trigger);

    const directory = screen.getByRole("dialog", { name: "云产品入口" });
    expect(within(directory).getByRole("status").textContent).toBe("7 项服务");
    expect(screen.queryByRole("button", { name: "关闭全局浮层", hidden: true })).toBeNull();
    expect(workspace.closest("[inert]")).not.toBeNull();
    expect(screen.getByRole("button", { name: /打开账号菜单/ }).closest("[inert]")).not.toBeNull();
    expect(document.activeElement).toBe(within(directory).getByRole("searchbox"));

    await user.click(trigger);
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(workspace.closest("[inert]")).toBeNull();
    expect(document.activeElement).toBe(trigger);

    await user.click(screen.getByRole("button", { name: /选择区域范围/ }));
    expect(screen.getByRole("dialog", { name: "切换区域" })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "关闭全局浮层" }));
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("uses one service directory and a single header entry for messages and running work", async () => {
    const { user } = await renderConsole({ experience: previewExperienceSnapshot });
    const local = await screen.findByRole("navigation", { name: "控制台导航" });
    expect(within(local).queryByRole("link", { name: /产品与服务/ })).toBeNull();
    const tools = screen.getByLabelText("全局工具");
    expect(within(tools).queryByRole("link", { name: /操作与任务/ })).toBeNull();
    await user.click(screen.getByRole("button", { name: "全部产品" }));
    expect(screen.getAllByRole("dialog", { name: "云产品入口" })).toHaveLength(1);
    await user.click(within(screen.getByRole("dialog", { name: "云产品入口" })).getByRole("button", { name: "关闭产品与服务" }));
    expect(screen.getByRole("heading", { level: 1 }).textContent).toBe("控制台总览");
    await user.click(screen.getByRole("button", { name: "打开消息中心，7 条未读消息" }));
    const inbox = screen.getByRole("dialog", { name: "消息中心" });
    expect(within(inbox).getByRole("link", { name: /1 个任务进行中/ }).getAttribute("href")).toMatch(/\/console\/operations\/?$/);
    expect(within(inbox).getByRole("link", { name: "查看全部消息" }).getAttribute("href")).toMatch(/\/console\/messages\/?$/);
  });

  it("localizes shell navigation and routes translated global-search pages without reloading resources", async () => {
    const load = vi.fn().mockResolvedValue(snapshot);
    const { user } = await renderConsole({ experience: previewExperienceSnapshot, load });
    await user.click(screen.getByRole("button", { name: "打开账号菜单，当前用户 admin" }));
    await user.click(screen.getByRole("radio", { name: "English" }));
    expect(screen.getByRole("heading", { level: 1 }).textContent).toBe("Dashboard");
    expect(within(screen.getByRole("navigation", { name: "Console navigation" })).getByRole("link", { name: /^Message center/ })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Open message center, 7 unread messages" })).toBeTruthy();
    await user.keyboard("{Escape}");
    const input = screen.getByRole("combobox", { name: "Search products, resources and pages" });
    await user.type(input, "resource center");
    await user.click(screen.getByRole("option", { name: /Resource center/ }));
    expect(navigation.push).toHaveBeenCalledWith("/console/resources/");
    expect(load).toHaveBeenCalledTimes(1);
    await user.click(input);
    expect(screen.getByRole("listbox", { name: "Search results" })).toBeTruthy();
    await user.type(input, "compute node");
    const nodeResult = screen.getByRole("option", { name: /edge-worker-01/ });
    expect(nodeResult.textContent).toContain("Compute node");
    await user.click(nodeResult);
    expect(navigation.push).toHaveBeenLastCalledWith("/console/regions/");
    expect(load).toHaveBeenCalledTimes(1);
  });

  it("keeps an installation draft and its accessible ID guidance while switching languages", async () => {
    const load = vi.fn().mockResolvedValue(snapshot);
    const { user } = await renderConsole({ section: "installations", load, openWorkspace: true });
    const id = await screen.findByLabelText("实例 ID") as HTMLInputElement;
    await user.clear(id);
    await user.type(id, "pg-theme-review");
    const name = screen.getByLabelText("显示名称") as HTMLInputElement;
    await user.clear(name);
    await user.type(name, "Theme review DB");
    await user.click(screen.getByRole("button", { name: "打开账号菜单，当前用户 admin" }));
    await user.click(screen.getByRole("radio", { name: "English" }));
    await user.keyboard("{Escape}");
    expect((screen.getByLabelText("Instance ID") as HTMLInputElement).value).toBe("pg-theme-review");
    expect((screen.getByLabelText("Display name") as HTMLInputElement).value).toBe("Theme review DB");
    expect(document.getElementById(id.getAttribute("aria-describedby")!)?.textContent).toContain("2–63 characters");
    expect((screen.getByRole("button", { name: "Submit installation" }) as HTMLButtonElement).disabled).toBe(false);
    expect(load).toHaveBeenCalledTimes(1);
  });

  it("uses localized capacity and validates quota quantities after a language change", async () => {
    const { user } = await renderConsole({ section: "quotas", openWorkspace: true });
    const count = await screen.findByLabelText("实例数量") as HTMLInputElement;
    fireEvent.change(count, { target: { value: "2" } });
    await user.click(screen.getByRole("button", { name: "打开账号菜单，当前用户 admin" }));
    await user.click(screen.getByRole("radio", { name: "English" }));
    await user.keyboard("{Escape}");
    expect((screen.getByLabelText("Instance count") as HTMLInputElement).value).toBe("2");
    expect(screen.getByText("0.5 vCPU · 1,024 MiB · 10 GiB")).toBeTruthy();
    const submit = screen.getByRole("button", { name: "Confirm quota activation" }) as HTMLButtonElement;
    for (const value of ["0", "9", "1.5"]) {
      fireEvent.change(count, { target: { value } });
      expect(submit.disabled).toBe(true);
    }
    fireEvent.change(count, { target: { value: "8" } });
    expect(submit.disabled).toBe(false);
  });

  it("formats region dates in the selected locale and distinguishes missing and invalid observations", async () => {
    const load = vi.fn().mockResolvedValue({ ...snapshot, regions: [
      snapshot.regions[0],
      { ...snapshot.regions[0], id: "uninspected", displayName: "Uninspected region", inspectedAt: null },
      { ...snapshot.regions[0], id: "unknown", displayName: "Unknown observation", inspectedAt: "not-a-date" }
    ] });
    const { user, view } = await renderConsole({ section: "regions", load });
    await user.click(screen.getByRole("button", { name: "打开账号菜单，当前用户 admin" }));
    await user.click(screen.getByRole("radio", { name: "English" }));
    await user.keyboard("{Escape}");
    expect(view.container.textContent).toContain("4 vCPU · 8,192 MiB · 100 GiB");
    expect(view.container.textContent).toContain("Aug 26, 2026");
    expect(view.container.textContent).toContain("UTC");
    expect(view.container.textContent).toContain("Not inspected");
    expect(view.container.textContent).toContain("Unknown time");
    expect(view.container.textContent).not.toContain("Invalid Date");
    expect(load).toHaveBeenCalledTimes(1);
  });

  it("uses the narrow rail only for favorites and synchronizes directory stars", async () => {
    const { user } = await renderConsole({ section: "logs", experience: previewExperienceSnapshot });
    await screen.findByRole("heading", { name: "日志概览", level: 1 });
    const rail = screen.getByRole("navigation", { name: "收藏的服务" });
    expect(within(rail).getAllByRole("link")).toHaveLength(1);
    const local = screen.getByRole("navigation", { name: "控制台导航" });
    expect(within(local).getByRole("link", { name: /检索分析/ }).getAttribute("href")).toMatch(/^\/console\/logs\/search\/?$/);
    expect(within(local).queryByRole("link", { name: /流水线/ })).toBeNull();
    await user.click(screen.getByRole("button", { name: "添加收藏的服务" }));
    const dialog = screen.getByRole("dialog", { name: "云产品入口" });
    await user.click(within(dialog).getByRole("button", { name: "收藏 日志服务" }));
    expect(within(rail).getByRole("link", { name: "日志服务" }).getAttribute("aria-current")).toBe("page");
    expect(rail.closest("[inert]")).not.toBeNull();
    await user.click(within(dialog).getByRole("button", { name: "取消收藏 日志服务" }));
    expect(within(rail).queryByRole("link", { name: "日志服务" })).toBeNull();
    await user.click(within(dialog).getByRole("button", { name: "关闭产品与服务" }));
    expect(rail.closest("[inert]")).toBeNull();
    expect(screen.getByRole("heading", { level: 1 }).textContent).toBe("日志概览");
  });

  it("shows failed revocation without claiming logout or revealing the upstream error", async () => {
    const logout = vi.fn().mockRejectedValue(new Error("private upstream diagnostic"));
    const { user, view } = await renderConsole({ logout });
    await user.click(await screen.findByRole("button", { name: /打开账号菜单/ }));
    await user.click(screen.getByRole("menuitem", { name: "注销并撤销 IAM 会话" }));

    expect((await screen.findByRole("alert")).textContent).toContain("会话仍保留");
    expect(screen.queryByRole("dialog", { name: "账号菜单" })).toBeNull();
    expect(screen.getByRole("heading", { level: 1 }).textContent).toBe("控制台总览");
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
    await renderConsole({ openWorkspace: true });
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
    const { user } = await renderConsole({ section: "installations", openWorkspace: true });
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

  it("shows the instance list first and opens setup only through the named installation action", async () => {
    const { user } = await renderConsole({ section: "installations" });
    const install = await screen.findByRole("button", { name: "安装服务" });
    expect(install.getAttribute("aria-expanded")).toBe("false");
    expect(screen.queryByRole("button", { name: "提交安装任务" })).toBeNull();

    await user.click(install);
    const collapse = await screen.findByRole("button", { name: "收起安装配置" });
    expect(collapse.getAttribute("aria-expanded")).toBe("true");
    expect(screen.getByRole("button", { name: "提交安装任务" })).toBeTruthy();

    await user.click(collapse);

    expect(install.getAttribute("aria-expanded")).toBe("false");
    expect(screen.queryByRole("button", { name: "提交安装任务" })).toBeNull();
  });

  it("contains compact navigation focus and restores the menu trigger", async () => {
    const { user } = await renderConsole();
    const trigger = await screen.findByRole("button", { name: "打开产品导航" });

    await user.click(trigger);

    const dialog = screen.getByRole("dialog", { name: "产品导航" });
    const close = within(dialog).getByRole("button", { name: "关闭导航" });
    const links = within(dialog).getAllByRole("link");
    await waitFor(() => expect(document.activeElement).toBe(close));

    await user.keyboard("{Shift>}{Tab}{/Shift}");
    expect(document.activeElement).toBe(links[links.length - 1]);
    await user.keyboard("{Tab}");
    expect(document.activeElement).toBe(close);

    await user.keyboard("{Escape}");
    await waitFor(() => expect(document.activeElement).toBe(trigger));
    expect(screen.queryByRole("dialog", { name: "产品导航" })).toBeNull();
  });

  it("moves focus into the workspace and returns it after Escape", async () => {
    const { user } = await renderConsole({ section: "installations" });
    const trigger = await screen.findByRole("button", { name: "安装服务" });

    await user.click(trigger);

    const workspace = document.getElementById("console-workspace");
    expect(workspace).toBeTruthy();
    const close = within(workspace as HTMLElement).getByRole("button", { name: "关闭上下文面板" });
    await waitFor(() => expect(document.activeElement).toBe(close));
    await user.keyboard("{Escape}");

    await waitFor(() => expect(document.activeElement).toBe(trigger));
    expect(trigger.getAttribute("aria-expanded")).toBe("false");
  });

  it("supports global search and keyboard navigation in preview mode", async () => {
    const { user } = await renderConsole({ experience: previewExperienceSnapshot });
    expect((await screen.findByRole("heading", { level: 1 })).textContent).toBe("控制台总览");
    expect(screen.getByRole("heading", { name: "常用产品" })).toBeTruthy();
    expect(screen.getByRole("heading", { name: "待处理事项" })).toBeTruthy();
    expect(screen.getByRole("heading", { name: "最近资源" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: /项目|资源范围/ })).toBeNull();

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

  it("keeps exactly one global panel open across product, search, account and scope controls", async () => {
    const { user } = await renderConsole({ experience: previewExperienceSnapshot });
    await user.click(await screen.findByRole("button", { name: "打开产品与服务" }));
    expect(screen.getByRole("dialog", { name: "云产品入口" })).toBeTruthy();
    await user.keyboard("{Meta>}k{/Meta}");
    expect(screen.getByRole("dialog", { name: "云产品入口" })).toBeTruthy();
    expect(screen.queryByRole("listbox", { name: "搜索结果" })).toBeNull();
    await user.click(within(screen.getByRole("dialog", { name: "云产品入口" })).getByRole("button", { name: "关闭产品与服务" }));
    await user.keyboard("{Meta>}k{/Meta}");
    expect(screen.queryByRole("dialog", { name: "云产品入口" })).toBeNull();
    expect(screen.getByRole("listbox", { name: "搜索结果" })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: /打开账号菜单/ }));
    expect(screen.queryByRole("listbox")).toBeNull();
    expect(screen.getByRole("dialog", { name: "账号菜单" })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: /选择区域范围/ }));
    expect(screen.queryByRole("dialog", { name: "账号菜单" })).toBeNull();
    expect(screen.getByRole("dialog", { name: "切换区域" })).toBeTruthy();
    await user.keyboard("{Control>}k{/Control}");
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(screen.getByRole("listbox", { name: "搜索结果" })).toBeTruthy();
    expect(screen.getAllByRole("link", { name: "Matrix Cloud 控制台首页" })).toHaveLength(1);
  });

  it("filters resources by region without a global project selector", async () => {
    const { user } = await renderConsole({ section: "resources", experience: previewExperienceSnapshot });
    await screen.findByRole("heading", { level: 1, name: "资源中心" });
    expect(screen.queryByRole("button", { name: /项目|资源范围/ })).toBeNull();
    await user.click(screen.getByRole("button", { name: /选择区域范围/ }));
    await user.click(screen.getByRole("option", { name: /上海私有云 B 区/ }));

    expect(screen.getByRole("link", { name: "edge-worker-01" })).toBeTruthy();
    expect(screen.getByRole("link", { name: "Matrix 开发库" })).toBeTruthy();
    expect(screen.queryByRole("link", { name: "订单主库" })).toBeNull();

    const regionTrigger = screen.getByRole("button", { name: /选择区域范围，当前 上海私有云 B 区/ });
    await user.click(regionTrigger);
    expect(screen.getByRole("option", { name: /上海私有云 B 区/ }).getAttribute("aria-selected")).toBe("true");
    await user.click(screen.getByRole("button", { name: "打开产品与服务" }));
    expect(screen.queryByRole("dialog", { name: "切换区域" })).toBeNull();
    expect(screen.getByRole("dialog", { name: "云产品入口" })).toBeTruthy();
  });
});
