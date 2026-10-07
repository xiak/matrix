import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { Suspense, useState, type ComponentProps } from "react";
import userEvent from "@testing-library/user-event";
import { LocaleProvider } from "@/i18n/LocaleProvider";
import { afterEach, describe, expect, it, vi } from "vitest";
import { SessionProvider } from "@/features/auth/application/SessionProvider";
import type { AccountRepository, IamRepository } from "@/features/auth/repositories/iamRepository";
import type {
  ServiceLinkedRoleRelation,
  ServiceRoleTemplate,
  WorkloadRoleBinding
} from "@/features/auth/domain/serviceAuthorization";
import { previewAccountRepository, previewIamRepository } from "@/features/auth/repositories/previewIamRepository";
import { HttpProblem } from "@/infrastructure/http/jsonRequest";
import { useConsoleUiStore } from "../application/consoleUiStore";
import type { ControlPlaneSnapshot } from "../domain/resources";
import type { ExperienceSnapshot } from "../domain/experience";
import { consoleRouteHref, type ControlPlaneRouteSelection, type ConsoleSection, type ServiceView } from "../domain/selection";
import type { ControlPlaneRepository } from "../repositories/controlPlaneRepository";
import { previewExperienceSnapshot } from "../repositories/previewExperienceSnapshot";
import { ConsoleShellRenderer } from "./ConsoleShellRenderer";
import { ConsoleContentLoadingRenderer } from "./ConsoleContentLoadingRenderer";
import { parseControlPlanePathname } from "../routes/parseControlPlaneRoute";

const navigation = vi.hoisted(() => ({ push: vi.fn(), replace: vi.fn(), query: "" }));
const contentRender = vi.hoisted(() => vi.fn());
const accountMenuRender = vi.hoisted(() => vi.fn());

vi.mock("next/navigation", () => ({ useRouter: () => navigation, useSearchParams: () => new URLSearchParams(navigation.query) }));
vi.mock("next/link", () => ({
  default: ({ onNavigate, onClick, href, children, replace, scroll, ...props }: ComponentProps<"a"> & { replace?: boolean; scroll?: boolean; onNavigate?(event: { preventDefault(): void }): void }) => <a {...props} href={href} data-replace={replace} data-scroll={scroll} onClick={event => {
    onClick?.(event);
    if (event.defaultPrevented) return;
    event.preventDefault();
    if (event.ctrlKey || event.metaKey || event.shiftKey || event.altKey || props.target === "_blank" || props.download !== undefined) return;
    onNavigate?.({ preventDefault() {} });
  }}>{children}</a>
}));
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

const liveServiceRoleTemplate: ServiceRoleTemplate = {
  id: "managedservice.installation-reader",
  version: 1,
  contentDigest: `sha256:${"c".repeat(64)}`,
  status: "ACTIVE",
  spec: {
    product: "managedservice",
    servicePurpose: "PAAS",
    roleName: "ManagedServiceInstallationReader",
    roleDescription: "Read one installation.",
    maxSessionDurationSeconds: 900,
    policyVersion: {
      policyId: "system.managedservice-installation-reader",
      versionId: "version-v1",
      contentDigest: `sha256:${"b".repeat(64)}`
    },
    workloads: [{
      resourceKind: "SERVICE_INSTALLATION",
      bindAction: "managedservice.service-installation.service-role.bind",
      unbindAction: "managedservice.service-installation.service-role.unbind"
    }]
  }
};

const liveServiceRoleRelation: ServiceLinkedRoleRelation = {
  role: {
    id: "role-managedservice-reader",
    accountId: "organization-test",
    name: "ManagedServiceInstallationReader",
    description: "Read one installation.",
    tags: [],
    management: "SERVICE_LINKED",
    status: "ACTIVE",
    maxSessionDurationSeconds: 900,
    resourceVersion: 1,
    currentTrustVersionId: "trust-v1",
    createdAt: "2026-08-26T12:00:00Z",
    updatedAt: "2026-08-26T12:00:00Z"
  },
  template: {
    id: liveServiceRoleTemplate.id,
    version: liveServiceRoleTemplate.version,
    contentDigest: liveServiceRoleTemplate.contentDigest
  },
  servicePrincipal: {
    installationId: "installation-paas",
    principalId: "service-paas",
    purpose: "PAAS"
  },
  permissionCeiling: liveServiceRoleTemplate.spec.policyVersion
};

function liveServiceRoleBinding(installationId: string): WorkloadRoleBinding {
  return {
    id: `binding-${installationId}`,
    accountId: "organization-test",
    roleId: liveServiceRoleRelation.role.id,
    template: liveServiceRoleRelation.template,
    workload: { kind: "SERVICE_INSTALLATION", id: installationId },
    status: "ACTIVE",
    resourceVersion: 1,
    createdAt: "2026-08-26T12:00:00Z",
    updatedAt: "2026-08-26T12:00:00Z",
    revokedAt: null
  };
}

async function renderConsole({
  section = "overview",
  experience,
  openWorkspace = false,
  load = vi.fn().mockResolvedValue(snapshot),
  inspectServiceAuthorization,
  bindServiceRole,
  unbindServiceRole,
  logout = vi.fn().mockResolvedValue(undefined),
  accountRepository,
  iamRepository,
  view: initialView,
  heldRoute
}: {
  section?: ConsoleSection;
  view?: ServiceView;
  experience?: ExperienceSnapshot;
  openWorkspace?: boolean;
  load?: ControlPlaneRepository["load"];
  inspectServiceAuthorization?: ControlPlaneRepository["inspectServiceAuthorization"];
  bindServiceRole?: ControlPlaneRepository["bindServiceRole"];
  unbindServiceRole?: ControlPlaneRepository["unbindServiceRole"];
  logout?: IamRepository["logout"];
  accountRepository?: AccountRepository;
  iamRepository?: IamRepository;
  heldRoute?: { href: string; ready: boolean; promise: Promise<void> };
} = {}) {
  const repository: ControlPlaneRepository = {
    load,
    getInstallation: vi.fn(),
    activateQuota: vi.fn(),
    createInstallation: vi.fn(),
    inspectServiceAuthorization,
    bindServiceRole,
    unbindServiceRole
  };
  const iam: IamRepository = iamRepository ?? {
    async login() {
      return {
        outcome: "AUTHENTICATED",
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
  const user = userEvent.setup({ delay: null });
  function RoutedPage() {
    const [href, setHref] = useState(consoleRouteHref({ section, view: initialView }));
    if (heldRoute) navigation.push.mockImplementation((target: string) => {
      const url = new URL(target, "https://matrix.invalid");
      navigation.query = url.search.slice(1);
      setHref(target);
    });
    if (heldRoute && href === heldRoute.href && !heldRoute.ready) throw heldRoute.promise;
    return <ConsoleShellRenderer accountRepository={accountRepository} experience={experience} repository={repository} selection={parseControlPlanePathname(new URL(href, "https://matrix.invalid").pathname)} />;
  }
  const view = render(
    <LocaleProvider><SessionProvider repository={iam}>
      <Suspense fallback={<p>Route bundle loading</p>}><RoutedPage /></Suspense>
    </SessionProvider></LocaleProvider>
  );
  await user.type(screen.getByLabelText("密码", { exact: true }), "renderer-test-password");
  await user.click(screen.getByRole("button", { name: "登录控制台" }));
  if (["overview", "catalog", "quotas", "installations", "regions"].includes(section)) {
    await waitFor(() => expect(load).toHaveBeenCalled());
  }
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
  navigation.push.mockReset();
  navigation.replace.mockReset();
  vi.useRealTimers();
  navigation.query = "";
});

describe("ConsoleShellRenderer", () => {
  it.each([
    { selection: { section: "overview" }, role: "article", name: "最近服务实例" },
    { selection: { section: "catalog" }, role: "region", name: "产品规格" },
    { selection: { section: "quotas" }, role: "region", name: "服务配额" },
    { selection: { section: "regions" }, role: "region", name: "区域与节点" },
    { selection: { section: "applications" }, role: "article", name: "统一资源列表" },
    { selection: { section: "resources" }, role: "article", name: "统一资源列表" },
    { selection: { section: "installations" }, role: "article", name: "组织服务实例" },
    { selection: { section: "operations" }, role: "article", name: "操作与任务" },
    { selection: { section: "messages" }, role: "article", name: "消息中心" },
    { selection: { section: "devops", view: "pipelines" }, role: "article", name: "最近流水线" },
    { selection: { section: "devops", view: "environments" }, role: "region", name: "交付环境" },
    { selection: { section: "observability", view: "health" }, role: "article", name: "服务健康" },
    { selection: { section: "observability", view: "alerts" }, role: "article", name: "当前告警" },
    { selection: { section: "logs" }, role: "article", name: "最近日志" },
    { selection: { section: "logs", view: "search" }, role: "article", name: "检索分析" },
    { selection: { section: "logs", view: "topics" }, role: "article", name: "日志主题" },
    { selection: { section: "logs", view: "collection" }, role: "article", name: "采集配置" },
    { selection: { section: "audit" }, role: "article", name: "审计记录" },
    { selection: { section: "access" }, role: "article", name: "概览" },
    { selection: { section: "access", view: "policies" }, role: "article", name: "策略" }
  ] as const)("keeps the $name destination region stable while only its data placeholder is delayed", ({ selection, role, name }) => {
    vi.useFakeTimers();
    render(<LocaleProvider><ConsoleContentLoadingRenderer label={`正在打开${name}…`} selection={selection as ControlPlaneRouteSelection} /></LocaleProvider>);

    const region = screen.getByRole(role, { name });
    const status = within(region).getByRole("status");
    expect(status.textContent).toBe(`正在打开${name}…`);
    expect(status.querySelector("[aria-hidden]")).toBeNull();
    act(() => vi.advanceTimersByTime(199));
    expect(status.querySelector("[aria-hidden]")).toBeNull();
    act(() => vi.advanceTimersByTime(1));
    expect(status.querySelector("[aria-hidden]")).not.toBeNull();
  });

  it("keeps the cloud overview identity stable instead of showing database loading chrome", () => {
    vi.useFakeTimers();
    render(<LocaleProvider><ConsoleContentLoadingRenderer experience label="正在打开控制台总览…" selection={{ section: "overview" }} /></LocaleProvider>);

    expect(screen.getByRole("heading", { level: 2, name: "欢迎使用 Matrix Cloud" })).toBeTruthy();
    expect(screen.queryByRole("heading", { name: "最近服务实例" })).toBeNull();
    const status = screen.getByRole("status");
    expect(status.textContent).toBe("正在打开控制台总览…");
    expect(status.querySelector("[aria-hidden]")).toBeNull();

    act(() => vi.advanceTimersByTime(200));

    expect(status.querySelector("[aria-hidden]")).not.toBeNull();
    expect(screen.getByText("常用产品")).toBeTruthy();
    expect(screen.getByText("最近资源")).toBeTruthy();
    expect(screen.getByText("待处理事项")).toBeTruthy();
  });

  it.each([
    { section: "applications", table: "统一资源列表" },
    { section: "installations", table: "服务实例列表" },
    { section: "devops", table: "流水线运行列表" }
  ] as const)("keeps $section data readable as labelled records on compact tables", async ({ section, table }) => {
    const installation = {
      id: "pg-test", name: "订单主库", offeringId: "postgresql-18", engineVersion: "18",
      quotaEntitlementId: "quota-primary", regionId: "local-primary", phase: "READY" as const,
      endpoint: "pg-test.service.local:5432", credentialReference: null,
      operation: { id: "operation-test", phase: "READY" as const, safeFailureCode: null, observedAt: "2026-08-26T12:00:00Z" },
      createdAt: "2026-08-26T12:00:00Z"
    };
    await renderConsole({
      section,
      experience: previewExperienceSnapshot,
      load: vi.fn().mockResolvedValue({ ...snapshot, installations: [installation] })
    });
    const dataTable = await screen.findByRole("table", { name: table });
    expect(dataTable.getAttribute("data-mobile-layout")).toBe("grid");
    expect(dataTable.querySelector("tbody td[data-label]")).not.toBeNull();
    expect(dataTable.querySelector('tbody td[data-mobile-span="full"]')).not.toBeNull();
  });

  it("does not present the MOCK service-instance directory as an account-wide or IAM-filtered result", async () => {
    const installation = (id: string, name: string) => ({
      id, name, offeringId: "postgresql-18", engineVersion: "18",
      quotaEntitlementId: "quota-primary", regionId: "local-primary", phase: "READY" as const,
      endpoint: `${id}.service.local:5432`, credentialReference: null,
      operation: { id: `operation-${id}`, phase: "READY" as const, safeFailureCode: null, observedAt: "2026-08-26T12:00:00Z" },
      createdAt: "2026-08-26T12:00:00Z"
    });
    await renderConsole({
      section: "installations",
      experience: previewExperienceSnapshot,
      load: vi.fn().mockResolvedValue({ ...snapshot, installations: [installation("pg-one", "订单主库"), installation("pg-two", "分析副本")] })
    });

    expect(await screen.findByText("当前已加载 2")).toBeTruthy();
    expect(screen.getByText(/本地 fixture，未经过 IAM 实例级授权过滤/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: /批量授权/ })).toBeNull();
  });

  it("states the server-side visibility boundary without claiming a live IAM integration", async () => {
    await renderConsole({ section: "installations" });

    expect(await screen.findByText(/实例可见性必须由产品服务在服务端结合 IAM 判定/)).toBeTruthy();
    expect(screen.getByText(/不会把拒绝项下载到浏览器后再隐藏/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: /批量授权/ })).toBeNull();
  });

  it("keeps product-catalog fixtures distinct from IAM-filtered visibility", async () => {
    await renderConsole({ section: "catalog", experience: previewExperienceSnapshot });

    expect(await screen.findByText(/当前已加载 1 项隔离 MOCK 本地 fixture/)).toBeTruthy();
    expect(screen.getByRole("heading", { name: "PostgreSQL 18" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: /批量授权/ })).toBeNull();
  });

  it("distinguishes a successful empty product catalog from an unavailable service", async () => {
    await renderConsole({ section: "catalog", load: vi.fn().mockResolvedValue({ ...snapshot, offerings: [] }) });

    expect(await screen.findByText(/产品服务成功返回了空目录/)).toBeTruthy();
    expect(screen.getByText(/当前已加载 0 项/)).toBeTruthy();
    expect(screen.queryByText("服务目录不可用")).toBeNull();
    expect(screen.queryByText(/拒绝原因/)).not.toBeNull();
  });

  it("starts the isolated service-authorization review from the exact product resource", async () => {
    const installation = {
      id: "pg-test", name: "订单主库", offeringId: "postgresql-18", engineVersion: "18",
      quotaEntitlementId: "quota-primary", regionId: "local-primary", phase: "READY" as const,
      endpoint: "pg-test.service.local:5432", credentialReference: null,
      operation: { id: "operation-test", phase: "READY" as const, safeFailureCode: null, observedAt: "2026-08-26T12:00:00Z" },
      createdAt: "2026-08-26T12:00:00Z"
    };
    const { user } = await renderConsole({
      section: "installations",
      experience: previewExperienceSnapshot,
      load: vi.fn().mockResolvedValue({ ...snapshot, installations: [installation] })
    });

    const instance = await screen.findByRole("button", { name: "订单主库" });
    await user.click(instance);
    expect(screen.getByRole("heading", { name: "订单主库" })).toBeTruthy();
    expect(screen.getByRole("heading", { name: "服务授权链" })).toBeTruthy();
    expect(screen.getByText("账号未授权")).toBeTruthy();
    expect(screen.getByText("实例未绑定")).toBeTruthy();
    expect(screen.getByText("运行时未观测")).toBeTruthy();

    await user.click(screen.getByRole("button", { name: "审阅服务授权" }));
    expect(screen.getByRole("heading", { name: "审阅服务授权 · 订单主库" })).toBe(document.activeElement);
    expect(screen.getByText("这是产品侧发起授权的信息流预览。实例、账号与权限范围来自当前 MOCK 视图，模板与服务主体仍是示例，最终授权写入尚未接入；不会读取或写入 IAM，也不会产生授权成功状态。")).toBeTruthy();
    expect(screen.getByText("SERVICE_INSTALLATION:pg-test")).toBeTruthy();
    expect(screen.queryByRole("dialog")).toBeNull();

    await user.click(screen.getByRole("button", { name: "下一步" }));
    await waitFor(() => expect(screen.getByRole("heading", { level: 3, name: "核对模板权限上限" })).toBe(document.activeElement));
    expect(screen.getByText("managedservice.service-installation.read")).toBeTruthy();
    expect(screen.getByText(/当前权威范围内全部/)).toBeTruthy();
    expect(screen.queryByText("pg-test")).toBeNull();
    await user.click(screen.getByRole("button", { name: "下一步" }));
    await waitFor(() => expect(screen.getByRole("heading", { level: 3, name: "确认客户同意与撤销边界" })).toBe(document.activeElement));
    const authorize = screen.getByRole("button", { name: "模拟授权服务" }) as HTMLButtonElement;
    expect(authorize.disabled).toBe(false);
    await user.click(authorize);
    expect(screen.getByRole("heading", { name: "订单主库" })).toBeTruthy();
    expect(screen.getByText("账号已授权 · MOCK")).toBeTruthy();
    expect(screen.getByText("当前实例已绑定 · MOCK")).toBeTruthy();
    expect(screen.getByText(/不会调用 IAM、创建角色、写入后端或签发临时凭据/)).toBeTruthy();
    const unbind = screen.getByRole("button", { name: "解除实例授权" });
    expect(unbind).toBe(document.activeElement);

    await user.click(unbind);
    expect(screen.getByRole("heading", { name: "解除实例授权 · 订单主库" })).toBe(document.activeElement);
    expect(screen.getByText("preview.workload-role-binding.pg-test")).toBeTruthy();
    expect(screen.getByText("当前 MOCK 已知 0 个")).toBeTruthy();
    expect(screen.getByText(/账号级 ServiceLinkedRoleAccess 继续有效/)).toBeTruthy();
    expect(screen.getByText(/不承诺立即终止既有会话/)).toBeTruthy();
    expect(screen.queryByRole("dialog")).toBeNull();

    await user.click(screen.getByRole("button", { name: "保留实例授权" }));
    expect(screen.getByRole("button", { name: "解除实例授权" })).toBe(document.activeElement);
    await user.click(screen.getByRole("button", { name: "解除实例授权" }));
    await user.click(screen.getByRole("button", { name: "模拟解除授权" }));
    expect(screen.getByRole("heading", { name: "订单主库" })).toBeTruthy();
    expect(screen.getByText("账号已授权 · MOCK")).toBeTruthy();
    expect(screen.getByText(/已在当前浏览器会话中模拟解除这个实例的精确 binding/)).toBeTruthy();
    expect(screen.getByRole("button", { name: "绑定当前实例" })).toBe(document.activeElement);
  });

  it("keeps one frozen intent for unknown results and rereads changed authorization state", async () => {
    const installation = {
      id: "pg-test", name: "订单主库", offeringId: "postgresql-18", engineVersion: "18",
      quotaEntitlementId: "quota-primary", regionId: "local-primary", phase: "READY" as const,
      endpoint: "pg-test.service.local:5432", credentialReference: null,
      operation: { id: "operation-test", phase: "READY" as const, safeFailureCode: null, observedAt: "2026-08-26T12:00:00Z" },
      createdAt: "2026-08-26T12:00:00Z"
    };
    const { user } = await renderConsole({
      section: "installations",
      experience: previewExperienceSnapshot,
      load: vi.fn().mockResolvedValue({ ...snapshot, installations: [installation] })
    });

    await user.click(await screen.findByRole("button", { name: "订单主库" }));
    await user.click(screen.getByRole("button", { name: "审阅服务授权" }));
    await user.click(screen.getByRole("button", { name: "下一步" }));
    await user.click(screen.getByRole("button", { name: "下一步" }));
    await user.click(screen.getByRole("combobox", { name: "模拟返回结果" }));
    expect(screen.getByRole("option", { name: /IDEMPOTENCY_CONFLICT/ })).toBeTruthy();
    expect(screen.getByRole("option", { name: /401/ })).toBeTruthy();
    expect(screen.getByRole("option", { name: /400 \/ 415/ })).toBeTruthy();
    await user.click(screen.getByRole("option", { name: /结果未知/ }));
    await user.click(screen.getByRole("button", { name: "模拟授权服务" }));

    expect(screen.getByText("提交结果未知")).toBeTruthy();
    expect(screen.getByText("preview-service-role-bind-pg-test")).toBeTruthy();
    expect(screen.getByText(/不能宣称成功，也不能创建新意图/)).toBeTruthy();
    expect(screen.queryByText("账号已授权 · MOCK")).toBeNull();
    await user.click(screen.getByRole("button", { name: "使用同一请求原样重试" }));
    expect(screen.getByText("账号已授权 · MOCK")).toBeTruthy();
    expect(screen.getByText("当前实例已绑定 · MOCK")).toBeTruthy();

    await user.click(screen.getByRole("button", { name: "解除实例授权" }));
    await user.click(screen.getByRole("combobox", { name: "模拟返回结果" }));
    await user.click(screen.getByRole("option", { name: /SERVICE_ROLE_CONFLICT/ }));
    await user.click(screen.getByRole("button", { name: "模拟解除授权" }));
    expect(screen.getByText("真实授权状态已变化")).toBeTruthy();
    expect(screen.getByText("preview-service-role-unbind-pg-test")).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "返回并重新读取授权状态" }));
    expect(screen.getByText("当前实例已绑定 · MOCK")).toBeTruthy();
    expect(screen.getByRole("button", { name: "解除实例授权" })).toBe(document.activeElement);
  });

  it("keeps one MOCK account relation while binding and unbinding exact resources independently", async () => {
    const installation = (id: string, name: string) => ({
      id, name, offeringId: "postgresql-18", engineVersion: "18",
      quotaEntitlementId: "quota-primary", regionId: "local-primary", phase: "READY" as const,
      endpoint: `${id}.service.local:5432`, credentialReference: null,
      operation: { id: `operation-${id}`, phase: "READY" as const, safeFailureCode: null, observedAt: "2026-08-26T12:00:00Z" },
      createdAt: "2026-08-26T12:00:00Z"
    });
    const { user } = await renderConsole({
      section: "installations",
      experience: previewExperienceSnapshot,
      load: vi.fn().mockResolvedValue({ ...snapshot, installations: [installation("pg-one", "订单主库"), installation("pg-two", "分析副本")] })
    });
    const authorizeCurrent = async (entryLabel: string) => {
      await user.click(screen.getByRole("button", { name: entryLabel }));
      await user.click(screen.getByRole("button", { name: /审阅服务授权|绑定当前实例/ }));
      await user.click(screen.getByRole("button", { name: "下一步" }));
      await user.click(screen.getByRole("button", { name: "下一步" }));
      await user.click(screen.getByRole("button", { name: "模拟授权服务" }));
    };

    await authorizeCurrent("订单主库");
    await user.click(screen.getByRole("button", { name: "返回服务实例" }));
    await user.click(screen.getByRole("button", { name: "分析副本" }));
    expect(screen.getByText("账号已授权 · MOCK")).toBeTruthy();
    expect(screen.getAllByText("实例未绑定").length).toBeGreaterThan(0);
    await user.click(screen.getByRole("button", { name: "绑定当前实例" }));
    await user.click(screen.getByRole("button", { name: "下一步" }));
    await user.click(screen.getByRole("button", { name: "下一步" }));
    await user.click(screen.getByRole("button", { name: "模拟授权服务" }));
    await user.click(screen.getByRole("button", { name: "返回服务实例" }));

    await user.click(screen.getByRole("button", { name: "订单主库" }));
    await user.click(screen.getByRole("button", { name: "解除实例授权" }));
    expect(screen.getByText("当前 MOCK 已知 1 个")).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "模拟解除授权" }));
    expect(screen.getByText("账号已授权 · MOCK")).toBeTruthy();
    expect(screen.getAllByText("实例未绑定").length).toBeGreaterThan(0);
    await user.click(screen.getByRole("button", { name: "返回服务实例" }));
    await user.click(screen.getByRole("button", { name: "分析副本" }));
    expect(screen.getByText("当前实例已绑定 · MOCK")).toBeTruthy();
  });

  it("keeps live instance chrome stable while only its service-authorization region loads", async () => {
    const installation = {
      id: "pg-test", name: "订单主库", offeringId: "postgresql-18", engineVersion: "18",
      quotaEntitlementId: "quota-primary", regionId: "local-primary", phase: "READY" as const,
      endpoint: "pg-test.service.local:5432", credentialReference: null,
      operation: { id: "operation-test", phase: "READY" as const, safeFailureCode: null, observedAt: "2026-08-26T12:00:00Z" },
      createdAt: "2026-08-26T12:00:00Z"
    };
    let finishInspection!: (value: Awaited<ReturnType<NonNullable<ControlPlaneRepository["inspectServiceAuthorization"]>>>) => void;
    const inspectServiceAuthorization = vi.fn(() => new Promise<Awaited<ReturnType<NonNullable<ControlPlaneRepository["inspectServiceAuthorization"]>>>>((resolve) => {
      finishInspection = resolve;
    }));
    const { user } = await renderConsole({
      section: "installations",
      load: vi.fn().mockResolvedValue({ ...snapshot, installations: [installation] }),
      inspectServiceAuthorization
    });

    await user.click(await screen.findByRole("button", { name: "订单主库" }));
    expect(screen.getByRole("heading", { name: "订单主库" })).toBeTruthy();
    expect(screen.getByText("pg-test.service.local:5432")).toBeTruthy();
    expect(screen.getByRole("heading", { name: "服务访问授权" })).toBeTruthy();
    expect(screen.getByText("正在核对")).toBeTruthy();
    expect(screen.queryByText("授权服务（等待发布）")).toBeNull();

    finishInspection({
      template: {
        id: "managedservice.installation-reader", version: 1, contentDigest: `sha256:${"c".repeat(64)}`, status: "ACTIVE",
        spec: {
          product: "managedservice", servicePurpose: "PAAS", roleName: "ManagedServiceInstallationReader",
          roleDescription: "Read one installation.", maxSessionDurationSeconds: 900,
          policyVersion: { policyId: "system.managedservice-installation-reader", versionId: "version-v1", contentDigest: `sha256:${"b".repeat(64)}` },
          workloads: [{ resourceKind: "SERVICE_INSTALLATION", bindAction: "managedservice.service-installation.service-role.bind", unbindAction: "managedservice.service-installation.service-role.unbind" }]
        }
      },
      relation: null,
      binding: null
    });

    expect(await screen.findByText("待授权")).toBeTruthy();
    expect(screen.getAllByText("待显式授权")).toHaveLength(2);
    expect((screen.getByRole("button", { name: "审阅并授权服务" }) as HTMLButtonElement).disabled).toBe(false);
    expect(inspectServiceAuthorization).toHaveBeenCalledWith("renderer-test-memory-only-session", "organization-test", "pg-test");
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("renders an active account relation separately from an unbound live instance", async () => {
    const { user } = await renderConsole({
      section: "installations",
      load: vi.fn().mockResolvedValue({ ...snapshot, installations: [{
        id: "pg-unbound", name: "审计只读库", offeringId: "postgresql-18", engineVersion: "18",
        quotaEntitlementId: "quota-primary", regionId: "local-primary", phase: "READY" as const,
        endpoint: "pg-unbound.service.local:5432", credentialReference: null,
        operation: { id: "operation-unbound", phase: "READY" as const, safeFailureCode: null, observedAt: "2026-08-26T12:00:00Z" },
        createdAt: "2026-08-26T12:00:00Z"
      }] }),
      inspectServiceAuthorization: vi.fn().mockResolvedValue({
        template: {
          id: "managedservice.installation-reader", version: 1, contentDigest: `sha256:${"c".repeat(64)}`, status: "ACTIVE",
          spec: {
            product: "managedservice", servicePurpose: "PAAS", roleName: "ManagedServiceInstallationReader",
            roleDescription: "Read one installation.", maxSessionDurationSeconds: 900,
            policyVersion: { policyId: "system.managedservice-installation-reader", versionId: "version-v1", contentDigest: `sha256:${"b".repeat(64)}` },
            workloads: [{ resourceKind: "SERVICE_INSTALLATION", bindAction: "managedservice.service-installation.service-role.bind", unbindAction: "managedservice.service-installation.service-role.unbind" }]
          }
        },
        relation: {
          role: {
            id: "role-managedservice-reader", accountId: "organization-test", name: "ManagedServiceInstallationReader",
            description: "Read one installation.", tags: [], management: "SERVICE_LINKED", status: "ACTIVE",
            maxSessionDurationSeconds: 900, resourceVersion: 1, currentTrustVersionId: "trust-v1",
            createdAt: "2026-08-26T12:00:00Z", updatedAt: "2026-08-26T12:00:00Z"
          },
          template: { id: "managedservice.installation-reader", version: 1, contentDigest: `sha256:${"c".repeat(64)}` },
          servicePrincipal: { installationId: "installation-paas", principalId: "service-paas", purpose: "PAAS" },
          permissionCeiling: { policyId: "system.managedservice-installation-reader", versionId: "version-v1", contentDigest: `sha256:${"b".repeat(64)}` }
        },
        binding: null
      })
    });

    await user.click(await screen.findByRole("button", { name: "审计只读库" }));
    expect(await screen.findByText("账号关系有效")).toBeTruthy();
    expect(screen.getAllByText("实例未绑定").length).toBeGreaterThan(0);
    expect(screen.queryByText("当前实例已绑定")).toBeNull();
  });

  it("reviews and binds one live service installation through the product endpoint", async () => {
    const installationId = "pg-live-bind";
    const binding = liveServiceRoleBinding(installationId);
    const inspectServiceAuthorization = vi.fn()
      .mockResolvedValueOnce({ template: liveServiceRoleTemplate, relation: null, binding: null })
      .mockResolvedValue({ template: liveServiceRoleTemplate, relation: liveServiceRoleRelation, binding });
    const bindServiceRole = vi.fn().mockResolvedValue({
      kind: "ServiceRoleBindingReceipt",
      serviceInstallationId: installationId,
      bindingId: binding.id,
      roleId: binding.roleId,
      template: binding.template,
      status: "ACTIVE",
      resourceVersion: 1,
      createdAt: binding.createdAt
    });
    const { user } = await renderConsole({
      section: "installations",
      load: vi.fn().mockResolvedValue({ ...snapshot, installations: [{
        id: installationId, name: "订单主库", offeringId: "postgresql-18", engineVersion: "18",
        quotaEntitlementId: "quota-primary", regionId: "local-primary", phase: "READY" as const,
        endpoint: "pg-live-bind.service.local:5432", credentialReference: null,
        operation: { id: "operation-live-bind", phase: "READY" as const, safeFailureCode: null, observedAt: "2026-08-26T12:00:00Z" },
        createdAt: "2026-08-26T12:00:00Z"
      }] }),
      inspectServiceAuthorization,
      bindServiceRole
    });

    await user.click(await screen.findByRole("button", { name: "订单主库" }));
    await user.click(await screen.findByRole("button", { name: "审阅并授权服务" }));

    expect(screen.queryByRole("dialog")).toBeNull();
    expect(screen.getByRole("heading", { name: "确认服务访问授权" })).toBeTruthy();
    expect(screen.getByText(`${liveServiceRoleTemplate.id}@v1`)).toBeTruthy();
    expect(screen.getByText(installationId)).toBeTruthy();

    await user.click(screen.getByRole("button", { name: "确认授权" }));
    await waitFor(() => expect(bindServiceRole).toHaveBeenCalledTimes(1));
    const firstCall = bindServiceRole.mock.calls[0];
    expect(firstCall).toBeDefined();
    const [credential, actualInstallationId, command] = firstCall!;
    expect(credential).toBe("renderer-test-memory-only-session");
    expect(actualInstallationId).toBe(installationId);
    expect(command.template).toEqual(liveServiceRoleRelation.template);
    expect(command.requestId).toMatch(/^ui-service-role-bind-/);
    expect(await screen.findByText("当前实例已绑定")).toBeTruthy();
    expect(inspectServiceAuthorization).toHaveBeenCalledTimes(2);
  });

  it("preserves and retries an unknown live authorization result with the same idempotency key", async () => {
    const installationId = "pg-live-unknown";
    const bindServiceRole = vi.fn()
      .mockRejectedValueOnce(new Error("connection ended before a response was observed"))
      .mockResolvedValue({
        kind: "ServiceRoleBindingReceipt",
        serviceInstallationId: installationId,
        bindingId: `binding-${installationId}`,
        roleId: liveServiceRoleRelation.role.id,
        template: liveServiceRoleRelation.template,
        status: "ACTIVE",
        resourceVersion: 1,
        createdAt: "2026-08-26T12:00:00Z"
      });
    const { user } = await renderConsole({
      section: "installations",
      load: vi.fn().mockResolvedValue({ ...snapshot, installations: [{
        id: installationId, name: "结果待确认库", offeringId: "postgresql-18", engineVersion: "18",
        quotaEntitlementId: "quota-primary", regionId: "local-primary", phase: "READY" as const,
        endpoint: "pg-live-unknown.service.local:5432", credentialReference: null,
        operation: { id: "operation-live-unknown", phase: "READY" as const, safeFailureCode: null, observedAt: "2026-08-26T12:00:00Z" },
        createdAt: "2026-08-26T12:00:00Z"
      }] }),
      inspectServiceAuthorization: vi.fn().mockResolvedValue({ template: liveServiceRoleTemplate, relation: null, binding: null }),
      bindServiceRole
    });

    await user.click(await screen.findByRole("button", { name: "结果待确认库" }));
    await user.click(await screen.findByRole("button", { name: "审阅并授权服务" }));
    await user.click(screen.getByRole("button", { name: "确认授权" }));

    expect(await screen.findByText(/服务端结果尚未确认/)).toBeTruthy();
    const firstCommand = bindServiceRole.mock.calls[0]![2];
    await user.click(screen.getByRole("button", { name: "返回实例并保留原请求" }));
    expect(await screen.findByRole("button", { name: "继续处理未确认请求" })).toBeTruthy();
    expect(screen.getByText(new RegExp(firstCommand.requestId))).toBeTruthy();

    await user.click(screen.getByRole("button", { name: "继续处理未确认请求" }));
    await user.click(screen.getByRole("button", { name: "使用同一请求原样重试" }));
    await waitFor(() => expect(bindServiceRole).toHaveBeenCalledTimes(2));
    expect(bindServiceRole.mock.calls[1]![2]).toEqual(firstCommand);
  });

  it("reviews and revokes only the selected live service binding", async () => {
    const installationId = "pg-live-unbind";
    const binding = liveServiceRoleBinding(installationId);
    const inspectServiceAuthorization = vi.fn()
      .mockResolvedValueOnce({ template: liveServiceRoleTemplate, relation: liveServiceRoleRelation, binding })
      .mockResolvedValue({ template: liveServiceRoleTemplate, relation: liveServiceRoleRelation, binding: null });
    const unbindServiceRole = vi.fn().mockResolvedValue({
      kind: "ServiceRoleUnbindingReceipt",
      serviceInstallationId: installationId,
      bindingId: binding.id,
      roleId: binding.roleId,
      template: binding.template,
      status: "REVOKED",
      resourceVersion: 2,
      createdAt: binding.createdAt,
      revokedAt: "2026-08-26T13:00:00Z"
    });
    const { user } = await renderConsole({
      section: "installations",
      load: vi.fn().mockResolvedValue({ ...snapshot, installations: [{
        id: installationId, name: "待解绑库", offeringId: "postgresql-18", engineVersion: "18",
        quotaEntitlementId: "quota-primary", regionId: "local-primary", phase: "READY" as const,
        endpoint: "pg-live-unbind.service.local:5432", credentialReference: null,
        operation: { id: "operation-live-unbind", phase: "READY" as const, safeFailureCode: null, observedAt: "2026-08-26T12:00:00Z" },
        createdAt: "2026-08-26T12:00:00Z"
      }] }),
      inspectServiceAuthorization,
      unbindServiceRole
    });

    await user.click(await screen.findByRole("button", { name: "待解绑库" }));
    await user.click(await screen.findByRole("button", { name: "审阅解除实例授权" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(screen.getByRole("heading", { name: "确认解除实例授权" })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "确认解除授权" }));

    await waitFor(() => expect(unbindServiceRole).toHaveBeenCalledTimes(1));
    const firstCall = unbindServiceRole.mock.calls[0];
    expect(firstCall).toBeDefined();
    const [credential, actualInstallationId, command] = firstCall!;
    expect(credential).toBe("renderer-test-memory-only-session");
    expect(actualInstallationId).toBe(installationId);
    expect(command).toEqual({
      bindingId: binding.id,
      resourceVersion: 1,
      expectedTemplate: liveServiceRoleRelation.template,
      requestId: expect.stringMatching(/^ui-service-role-unbind-/)
    });
    expect((await screen.findAllByText("实例未绑定")).length).toBeGreaterThan(0);
    expect(screen.getByText("账号关系有效")).toBeTruthy();
  });

  it.each([
    { href: "/console/regions/", service: /区域与节点/, title: "区域与节点", reads: 1, marker: { role: "text", name: "本机主区域" } },
    { href: "/console/applications/", service: /应用托管/, title: "应用服务", reads: 0, marker: { role: "table", name: "统一资源列表" } },
    { href: "/console/installations/", service: /云数据库 PostgreSQL/, title: "数据库实例", reads: 1, marker: { role: "heading", name: "组织服务实例" } },
    { href: "/console/logs/", service: /日志服务/, title: "日志概览", reads: 0, marker: { role: "text", name: "Matrix · Log Service" } },
    { href: "/console/devops/", service: /研发效能 DevOps/, title: "交付总览", reads: 0, marker: { role: "heading", name: "最近流水线" } },
    { href: "/console/observability/", service: /云监控/, title: "监控总览", reads: 0, marker: { role: "heading", name: "服务健康" } }
  ] as const)("opens the $title service frame immediately while its route bundle is pending", async ({ href, marker, reads, service, title: expectedTitle }) => {
    let release!: () => void;
    const heldRoute = { href, ready: false, promise: new Promise<void>(resolve => { release = resolve; }) };
    const { user, repository } = await renderConsole({ section: "resources", experience: previewExperienceSnapshot, heldRoute });
    const oldResource = await screen.findByRole("link", { name: "订单主库" });
    const header = screen.getByLabelText("全局导航");
    const title = screen.getByRole("heading", { level: 1 });
    const menu = screen.getByRole("navigation", { name: "控制台导航" });

    await user.click(screen.getByRole("button", { name: "打开产品与服务" }));
    fireEvent.click(within(screen.getByRole("dialog", { name: "云产品入口" })).getByRole("link", { name: service }));

    expect(screen.queryByRole("dialog", { name: "云产品入口" })).toBeNull();
    expect(screen.getByRole("heading", { level: 1, name: expectedTitle })).toBe(title);
    expect(title).toBe(document.activeElement);
    expect(screen.getByRole("navigation", { name: "控制台导航" })).toBe(menu);
    expect(screen.queryByRole("link", { name: "订单主库" })).toBeNull();
    if (reads === 0) expect(oldResource.isConnected).toBe(false);
    else expect(oldResource.closest("[hidden]")).toBeTruthy();
    const findDestination = () => marker.role === "table"
      ? screen.findByRole("table", { name: marker.name })
      : marker.role === "heading"
        ? screen.findByRole("heading", { level: 2, name: marker.name })
        : screen.findByText(marker.name);
    const destination = await findDestination();
    if (reads === 0) expect(destination.closest("[inert]")).toBeTruthy();
    expect(destination.closest("[hidden]")).toBeNull();
    expect(screen.queryByText(`正在打开${expectedTitle}…`)).toBeNull();
    accountMenuRender.mockClear();
    expect(accountMenuRender).not.toHaveBeenCalled();
    expect(screen.getByLabelText("全局导航")).toBe(header);
    expect(repository.load).toHaveBeenCalledTimes(reads);

    await act(async () => { heldRoute.ready = true; release(); });
    expect(screen.getByRole("heading", { level: 1, name: expectedTitle })).toBe(title);
    const committedDestination = await findDestination();
    await waitFor(() => expect(committedDestination.closest("[inert]")).toBeNull());
    expect(title).toBe(document.activeElement);
    expect(committedDestination.isConnected).toBe(true);
    expect(screen.queryByRole("progressbar")).toBeNull();
    expect(screen.getByLabelText("全局导航")).toBe(header);
    expect(repository.load).toHaveBeenCalledTimes(reads);
  });

  it("keeps the cloud overview identity while its route and region data are pending", async () => {
    let resolveSnapshot!: (value: ControlPlaneSnapshot) => void;
    let releaseRoute!: () => void;
    const load = vi.fn(() => new Promise<ControlPlaneSnapshot>((resolve) => { resolveSnapshot = resolve; }));
    const heldRoute = { href: "/console/", ready: false, promise: new Promise<void>((resolve) => { releaseRoute = resolve; }) };
    const { user, repository } = await renderConsole({ section: "resources", experience: previewExperienceSnapshot, heldRoute, load });
    const oldResource = await screen.findByRole("link", { name: "订单主库" });

    await user.click(screen.getByRole("link", { name: "Matrix Cloud 控制台首页" }));
    await waitFor(() => expect(load).toHaveBeenCalledTimes(1));

    expect(screen.getByRole("heading", { level: 1, name: "控制台总览" })).toBeTruthy();
    expect(screen.getByRole("heading", { level: 2, name: "欢迎使用 Matrix Cloud" })).toBeTruthy();
    expect(screen.queryByRole("heading", { name: "最近服务实例" })).toBeNull();
    expect(oldResource.closest("[hidden]")).toBeTruthy();
    expect(repository.load).toHaveBeenCalledWith("renderer-test-memory-only-session", ["regions"]);

    await act(async () => resolveSnapshot(snapshot));
    expect(await screen.findByText("常用产品")).toBeTruthy();

    await act(async () => { heldRoute.ready = true; releaseRoute(); });
    await waitFor(() => expect(screen.getByRole("heading", { level: 2, name: "欢迎使用 Matrix Cloud" }).closest("[inert]")).toBeNull());
    expect(repository.load).toHaveBeenCalledTimes(1);
  });

  it("uses the same cached transition between pages of one database service", async () => {
    let release!: () => void;
    const heldRoute = { href: "/console/catalog/", ready: false, promise: new Promise<void>(resolve => { release = resolve; }) };
    const { user, repository } = await renderConsole({ section: "installations", experience: previewExperienceSnapshot, heldRoute });
    const menu = screen.getByRole("navigation", { name: "控制台导航" });

    await user.click(within(menu).getByRole("link", { name: /^产品规格/ }));

    expect(screen.getByRole("heading", { level: 1, name: "产品规格" })).toBeTruthy();
    const product = screen.getByRole("heading", { level: 2, name: "PostgreSQL 18" });
    expect(product.closest("[inert]")).toBeTruthy();
    expect(product.closest("[hidden]")).toBeNull();
    expect(screen.queryByText("正在打开产品规格…")).toBeNull();
    expect(repository.load).toHaveBeenCalledTimes(1);

    await act(async () => { heldRoute.ready = true; release(); });
    await waitFor(() => expect(product.closest("[inert]")).toBeNull());
    expect(product.isConnected).toBe(true);
    expect(repository.load).toHaveBeenCalledTimes(1);
  });

  it("renders a cached IAM destination immediately and reserves loading feedback for its data regions", async () => {
    let release!: () => void;
    const heldRoute = { href: "/console/access/groups/", ready: false, promise: new Promise<void>(resolve => { release = resolve; }) };
    const accountRepository: AccountRepository = {
      ...previewAccountRepository,
      currentIdentity: vi.fn(previewAccountRepository.currentIdentity),
      listUsers: vi.fn(previewAccountRepository.listUsers),
      listGroups: vi.fn(previewAccountRepository.listGroups)
    };
    const { user } = await renderConsole({
      accountRepository,
      experience: previewExperienceSnapshot,
      heldRoute,
      iamRepository: previewIamRepository,
      section: "access",
      view: "users"
    });
    const users = await screen.findByRole("table", { name: "租户用户列表" });
    const menu = screen.getByRole("navigation", { name: "控制台导航" });

    await user.click(within(menu).getByRole("link", { name: "用户组" }));

    expect(screen.getByRole("heading", { level: 1, name: "用户组" })).toBeTruthy();
    expect(users.isConnected).toBe(false);
    expect(screen.queryByText("正在打开用户组…")).toBeNull();
    const groups = await screen.findByRole("table", { name: "用户组" });
    expect(groups.closest("[inert]")).toBeTruthy();
    expect(groups.closest("[hidden]")).toBeNull();
    expect(accountRepository.currentIdentity).toHaveBeenCalledTimes(1);

    await act(async () => { heldRoute.ready = true; release(); });
    await waitFor(() => expect(groups.closest("[inert]")).toBeNull());
    expect(groups.isConnected).toBe(true);
    expect(accountRepository.currentIdentity).toHaveBeenCalledTimes(1);
  });

  it("projects preview-owned service content immediately when navigation starts from IAM", async () => {
    let releaseRoute!: () => void;
    const load = vi.fn().mockResolvedValue(snapshot);
    const heldRoute = { href: "/console/logs/", ready: false, promise: new Promise<void>((resolve) => { releaseRoute = resolve; }) };
    const { user } = await renderConsole({
      accountRepository: previewAccountRepository,
      experience: previewExperienceSnapshot,
      heldRoute,
      iamRepository: previewIamRepository,
      load,
      section: "access",
      view: "users"
    });
    const users = await screen.findByRole("table", { name: "租户用户列表" });
    contentRender.mockClear();

    await user.click(screen.getByRole("button", { name: "打开产品与服务" }));
    expect(load).not.toHaveBeenCalled();
    expect(contentRender).not.toHaveBeenCalled();
    fireEvent.click(within(screen.getByRole("dialog", { name: "云产品入口" })).getByRole("link", { name: /日志服务/ }));
    expect(load).not.toHaveBeenCalled();

    expect(screen.getByRole("heading", { level: 1, name: "日志概览" })).toBeTruthy();
    expect(screen.getByText("Matrix · Log Service").closest("[inert]")).toBeTruthy();
    expect(users.isConnected).toBe(false);

    await act(async () => { heldRoute.ready = true; releaseRoute(); });
    await waitFor(() => expect(screen.getByText("Matrix · Log Service").closest("[inert]")).toBeNull());
    expect(load).not.toHaveBeenCalled();
  });

  it("keeps the database page structure stable while destination data is still pending", async () => {
    let resolveSnapshot!: (value: ControlPlaneSnapshot) => void;
    let releaseRoute!: () => void;
    const load = vi.fn(() => new Promise<ControlPlaneSnapshot>((resolve) => { resolveSnapshot = resolve; }));
    const heldRoute = { href: "/console/installations/", ready: false, promise: new Promise<void>((resolve) => { releaseRoute = resolve; }) };
    const { user } = await renderConsole({
      accountRepository: previewAccountRepository,
      experience: previewExperienceSnapshot,
      heldRoute,
      iamRepository: previewIamRepository,
      load,
      section: "access",
      view: "users"
    });
    const users = await screen.findByRole("table", { name: "租户用户列表" });

    await user.click(screen.getByRole("button", { name: "打开产品与服务" }));
    expect(load).not.toHaveBeenCalled();
    fireEvent.click(within(screen.getByRole("dialog", { name: "云产品入口" })).getByRole("link", { name: /云数据库 PostgreSQL/ }));
    await waitFor(() => expect(load).toHaveBeenCalledTimes(1));

    expect(screen.getByRole("heading", { level: 1, name: "数据库实例" })).toBeTruthy();
    expect(screen.getByRole("heading", { level: 2, name: "组织服务实例" })).toBeTruthy();
    expect(users.closest("[hidden]")).toBeTruthy();
    expect(load).toHaveBeenCalledTimes(1);

    await act(async () => resolveSnapshot(snapshot));
    await act(async () => { heldRoute.ready = true; releaseRoute(); });
    expect(await screen.findByRole("button", { name: "安装服务" })).toBeTruthy();
    expect(screen.getByRole("heading", { level: 1, name: "数据库实例" })).toBeTruthy();
    expect(load).toHaveBeenCalledTimes(1);
  });

  it("projects a pending IAM query into the correct content-area workflow", async () => {
    let release!: () => void;
    const heldRoute = { href: "/console/access/create-policy/?method=json", ready: false, promise: new Promise<void>(resolve => { release = resolve; }) };
    const { user } = await renderConsole({
      accountRepository: previewAccountRepository,
      experience: previewExperienceSnapshot,
      heldRoute,
      iamRepository: previewIamRepository,
      section: "access",
      view: "policies"
    });
    const policies = await screen.findByRole("table", { name: "策略" });
    await user.click(screen.getByRole("button", { name: "新建自定义策略" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(screen.getByRole("heading", { name: "选择创建策略方式" })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: /^按策略语法创建/ }));

    expect(screen.getByRole("heading", { level: 1, name: "新建策略" })).toBeTruthy();
    const jsonTab = screen.getByRole("tab", { name: "JSON 编辑" });
    expect(jsonTab.getAttribute("aria-selected")).toBe("true");
    const editor = screen.getByRole("textbox", { name: "策略内容" });
    expect(editor.closest("[inert]")).toBeTruthy();
    expect(policies.isConnected).toBe(false);

    await act(async () => { heldRoute.ready = true; release(); });
    await waitFor(() => expect(editor.closest("[inert]")).toBeNull());
    expect(editor.isConnected).toBe(true);
    expect(screen.getByRole("tab", { name: "JSON 编辑" }).getAttribute("aria-selected")).toBe("true");
  });

  it("retains the real header, navigation and title while first-load data is pending and after it arrives", async () => {
    let resolve!: (value: ControlPlaneSnapshot) => void;
    const load = vi.fn(() => new Promise<ControlPlaneSnapshot>(done => { resolve = done; }));
    await renderConsole({ section: "installations", load });
    const header = screen.getByLabelText("全局导航");
    const title = screen.getByRole("heading", { name: "数据库实例" });
    const menu = screen.getByRole("navigation", { name: "控制台导航" });
    expect(screen.queryByRole("table")).toBeNull();
    expect(screen.queryByRole("button", { name: "安装服务" })).toBeNull();
    expect(screen.getByRole("button", { name: /打开账号菜单/ })).toBeTruthy();
    expect(screen.getByRole("status").textContent).toContain("数据库实例");
    await act(async () => resolve(snapshot));
    expect(screen.getByLabelText("全局导航")).toBe(header);
    expect(screen.getByRole("navigation", { name: "控制台导航" })).toBe(menu);
    expect(screen.getByRole("heading", { name: "数据库实例" })).toBe(title);
    expect(screen.getByRole("button", { name: "安装服务" })).toBeTruthy();
    expect(screen.queryByRole("status")).toBeNull();
  });

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

  it("renders an application resource and its product-owned tag snapshot in the content area", async () => {
    navigation.query = "resource=app-checkout-api";
    await renderConsole({ section: "applications", experience: previewExperienceSnapshot });

    expect(screen.getByRole("heading", { level: 1, name: "应用服务" })).toBeTruthy();
    expect(screen.getByRole("heading", { level: 2, name: "结算 API" })).toBeTruthy();
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(screen.getByRole("link", { name: "返回应用" }).getAttribute("href")).toBe("/console/applications/");
    expect(screen.getByText("Application · paas.matrix.xiak.com/v1")).toBeTruthy();
    expect(screen.getByText("org-xiak")).toBeTruthy();
    expect(screen.getByText(/权限服务只决定当前身份能否读取/)).toBeTruthy();
    expect(screen.getByText("体验 MOCK 读取状态 · 读取成功")).toBeTruthy();
    const tags = screen.getByRole("table", { name: "应用资源标签" });
    expect(within(tags).getByText("environment")).toBeTruthy();
    expect(within(tags).getByText("production")).toBeTruthy();
    expect(within(tags).getByText("resource.tag/environment")).toBeTruthy();
    expect(within(tags).getAllByText("未由 Profile 声明")).toHaveLength(2);
    expect(screen.getByText('"app-checkout-api:tags:7"')).toBeTruthy();
    expect(screen.getByText(/策略编辑器不会修改资源标签/)).toBeTruthy();
    expect(screen.getByRole("button", { name: "管理标签" })).toBeTruthy();
    expect(screen.getByRole("heading", { name: "部署与版本" })).toBeTruthy();
    expect(screen.getByRole("table", { name: "部署组件状态" })).toBeTruthy();
    expect(screen.getAllByText("revision-checkout-v2-8-0")).toHaveLength(2);
    expect(screen.getByText('"17"')).toBeTruthy();
    expect(screen.getByRole("button", { name: "更新部署" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "更多部署操作" })).toBeTruthy();
  });

  it("keeps the application frame stable and hides unverified data for forbidden and unavailable exact reads", async () => {
    navigation.query = "resource=app-checkout-api";
    const { user } = await renderConsole({ section: "applications", experience: previewExperienceSnapshot });

    await user.click(screen.getByText("体验 MOCK 读取状态 · 读取成功"));
    await user.click(screen.getByRole("combobox", { name: "模拟返回结果" }));
    await user.click(screen.getByRole("option", { name: "403 · 不确认资源是否存在" }));

    expect(screen.getByRole("heading", { level: 1, name: "应用服务" })).toBeTruthy();
    expect(screen.getByRole("heading", { level: 2, name: "应用详情" })).toBeTruthy();
    expect(screen.getByRole("link", { name: "返回应用" })).toBeTruthy();
    expect(screen.getByText(/页面不确认目标是否存在/)).toBeTruthy();
    expect(screen.queryByText("org-xiak")).toBeNull();
    expect(screen.queryByRole("heading", { name: "部署与版本" })).toBeNull();
    expect(screen.queryByRole("button", { name: "管理标签" })).toBeNull();
    expect(screen.queryByRole("dialog")).toBeNull();

    await user.click(screen.getByRole("combobox", { name: "模拟返回结果" }));
    await user.click(screen.getByRole("option", { name: "503 · 身份服务不可用" }));
    expect(screen.getByText(/页面不会沿用旧数据或开放管理操作/)).toBeTruthy();
    expect(screen.getByRole("button", { name: "重新读取" })).toBeTruthy();
    expect(screen.queryByRole("heading", { name: "部署与版本" })).toBeNull();

    await user.click(screen.getByRole("button", { name: "重新读取" }));
    expect(screen.getByRole("heading", { level: 2, name: "结算 API" })).toBeTruthy();
    expect(screen.getByRole("heading", { name: "部署与版本" })).toBeTruthy();
  });

  it("reviews a deployment update and returns an accepted Operation instead of claiming completion", async () => {
    navigation.query = "resource=app-checkout-api";
    const { user } = await renderConsole({ section: "applications", experience: previewExperienceSnapshot });

    await user.click(screen.getByRole("button", { name: "更新部署" }));
    expect(screen.getByRole("heading", { name: "更新部署" })).toBe(document.activeElement);
    expect(screen.queryByRole("dialog")).toBeNull();
    await user.click(screen.getByRole("combobox", { name: "期望副本" }));
    await user.click(screen.getByRole("option", { name: "3" }));
    await user.click(screen.getByRole("button", { name: "审阅变更" }));

    expect(screen.getByRole("heading", { name: "审阅部署更新" })).toBe(document.activeElement);
    expect(screen.getByText("paas.deployment.update")).toBeTruthy();
    expect(screen.getByText("PUT /v1/deployments/deployment-checkout-production")).toBeTruthy();
    expect(screen.getByText('If-Match: "17"')).toBeTruthy();
    expect(screen.getByText(/revision-checkout-v2-9-0 · 3 个副本/)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "模拟提交" }));

    const outcome = screen.getByRole("region", { name: "最近一次模拟操作" });
    expect(within(outcome).getByText("operation-preview-deployment-checkout-production-7")).toBeTruthy();
    expect(within(outcome).getByText("UPDATE")).toBeTruthy();
    expect(within(outcome).getByText("202")).toBeTruthy();
    expect(within(outcome).getByText(/principal-lin · AccessKey MOCK-pipeline-key/)).toBeTruthy();
    expect(screen.getByText(/只表示期望状态与 Operation 已持久化/)).toBeTruthy();
    expect(screen.getByText(/部署尚未完成/)).toBeTruthy();
  });

  it("models stop and rollback as distinct reviewed product requests", async () => {
    navigation.query = "resource=app-checkout-api";
    const { user } = await renderConsole({ section: "applications", experience: previewExperienceSnapshot });

    await user.click(screen.getByRole("button", { name: "更多部署操作" }));
    await user.click(screen.getByRole("menuitem", { name: "停止应用" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(screen.getByRole("heading", { name: "审阅停止应用" })).toBe(document.activeElement);
    expect(screen.getByText("paas.deployment.stop")).toBeTruthy();
    expect(screen.getByText("PUT /v1/deployments/deployment-checkout-production")).toBeTruthy();
    expect(screen.getByText(/其他期望字段保持不变/)).toBeTruthy();
    await user.click(screen.getByText("体验其他服务响应"));
    await user.click(screen.getByRole("combobox", { name: "下一次模拟响应" }));
    await user.click(screen.getByRole("option", { name: "412 · 资源版本已变化" }));
    await user.click(screen.getByRole("button", { name: "模拟提交" }));
    expect(screen.getByRole("heading", { name: "停止应用" })).toBe(document.activeElement);
    expect(screen.queryByRole("combobox", { name: "已接受 generation" })).toBeNull();
    await user.click(screen.getByRole("button", { name: "审阅变更" }));
    expect(screen.getByText('If-Match: "18"')).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "取消" }));

    const more = screen.getByRole("button", { name: "更多部署操作" });
    await waitFor(() => expect(more).toBe(document.activeElement));
    await user.click(more);
    await user.click(screen.getByRole("menuitem", { name: "回滚版本" }));
    expect(screen.getByRole("heading", { name: "选择回滚来源" })).toBe(document.activeElement);
    expect(screen.queryByRole("option", { name: /generation 4/ })).toBeNull();
    await user.click(screen.getByRole("button", { name: "审阅变更" }));
    expect(screen.getByText("paas.deployment.rollback")).toBeTruthy();
    expect(screen.getByText("POST /v1/deployments/deployment-checkout-production/rollback")).toBeTruthy();
    expect(screen.getByText(/generation 5 · revision-checkout-v2-7-3/)).toBeTruthy();
  });

  it("reloads a changed Deployment before review and preserves one request identity after an interrupted response", async () => {
    navigation.query = "resource=app-checkout-api";
    const { user } = await renderConsole({ section: "applications", experience: previewExperienceSnapshot });

    await user.click(screen.getByRole("button", { name: "更新部署" }));
    await user.click(screen.getByRole("combobox", { name: "期望副本" }));
    await user.click(screen.getByRole("option", { name: "3" }));
    await user.click(screen.getByRole("button", { name: "审阅变更" }));
    await user.click(screen.getByText("体验其他服务响应"));
    await user.click(screen.getByRole("combobox", { name: "下一次模拟响应" }));
    await user.click(screen.getByRole("option", { name: "412 · 资源版本已变化" }));
    await user.click(screen.getByRole("button", { name: "模拟提交" }));

    expect(screen.getByRole("heading", { name: "更新部署" })).toBe(document.activeElement);
    expect(screen.getByText(/最新 ETag 为 "18"/)).toBeTruthy();
    expect(screen.queryByRole("region", { name: "最近一次模拟操作" })).toBeNull();
    await user.click(screen.getByRole("button", { name: "审阅变更" }));
    expect(screen.getByText('If-Match: "18"')).toBeTruthy();
    const firstRequestId = screen.getAllByText(/^mock-deployment-/)[0]?.textContent;
    expect(firstRequestId).toBeTruthy();

    await user.click(screen.getByText("体验其他服务响应"));
    await user.click(screen.getByRole("combobox", { name: "下一次模拟响应" }));
    await user.click(screen.getByRole("option", { name: "响应中断 · 结果未知" }));
    await user.click(screen.getByRole("button", { name: "模拟提交" }));
    expect(screen.getByText(/不要创建新意图/)).toBeTruthy();
    expect(screen.getAllByText(firstRequestId!)).toHaveLength(1);
    await user.click(screen.getByRole("button", { name: "安全重试同一意图" }));
    const recovered = screen.getByRole("region", { name: "最近一次模拟操作" });
    expect(within(recovered).getByText(firstRequestId!)).toBeTruthy();
    expect(within(recovered).getByText("200")).toBeTruthy();
    expect(within(recovered).getByText("已完成")).toBeTruthy();
    expect(screen.getByText(/不是新的提交/)).toBeTruthy();
  });

  it("does not offer a blind deployment retry for an idempotency mismatch or an active operation", async () => {
    navigation.query = "resource=app-checkout-api";
    const { user } = await renderConsole({ section: "applications", experience: previewExperienceSnapshot });
    await user.click(screen.getByRole("button", { name: "更新部署" }));
    await user.click(screen.getByRole("combobox", { name: "期望副本" }));
    await user.click(screen.getByRole("option", { name: "3" }));
    await user.click(screen.getByRole("button", { name: "审阅变更" }));
    await user.click(screen.getByText("体验其他服务响应"));
    await user.click(screen.getByRole("combobox", { name: "下一次模拟响应" }));
    await user.click(screen.getByRole("option", { name: "409 · 请求意图冲突" }));
    await user.click(screen.getByRole("button", { name: "模拟提交" }));
    expect(screen.getByText(/不要重试/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: /重试同一意图/ })).toBeNull();
    expect(screen.getByRole("button", { name: "返回修改" })).toBeTruthy();
  });

  it("reviews one permission-sensitive application tag change before applying it to the MOCK snapshot", async () => {
    navigation.query = "resource=app-checkout-api";
    const { user } = await renderConsole({ section: "applications", experience: previewExperienceSnapshot });

    await user.click(screen.getByRole("button", { name: "管理标签" }));
    expect(screen.getByRole("heading", { name: "管理资源标签" })).toBe(document.activeElement);
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(screen.getByText("1 个标签键 / 次")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "添加标签" })).toBeNull();

    await user.type(screen.getByLabelText("标签键", { exact: true }), "environment");
    await user.type(screen.getByLabelText("标签值", { exact: true }), "staging");
    await user.click(screen.getByRole("button", { name: "审阅变更" }));

    expect(screen.getByRole("heading", { name: "审阅标签变更" })).toBe(document.activeElement);
    expect(screen.getByText(/后续请求会使用新标签重新判定权限/)).toBeTruthy();
    expect(screen.getByText(/当前浏览器会话中的 MOCK 快照/)).toBeTruthy();
    expect(screen.getByText("production")).toBeTruthy();
    expect(screen.getByText("staging")).toBeTruthy();
    expect(screen.getByText('"app-checkout-api:tags:7"')).toBeTruthy();
    expect(screen.getByText("paas.application-label.set")).toBeTruthy();
    expect(screen.getByText('If-Match: "app-checkout-api:tags:7"')).toBeTruthy();

    await user.click(screen.getByRole("button", { name: "模拟应用" }));
    const tags = screen.getByRole("table", { name: "应用资源标签" });
    expect(within(tags).getByText("staging")).toBeTruthy();
    expect(within(tags).queryByText("production")).toBeNull();
    expect(screen.getAllByText('"app-checkout-api:tags:8"')).toHaveLength(2);
    expect(screen.getByText(/真实资源未改变/)).toBeTruthy();
    const outcome = screen.getByRole("region", { name: "最近一次模拟操作" });
    expect(within(outcome).getByText("operation-preview-app-checkout-api-tags-8")).toBeTruthy();
    expect(within(outcome).getByText("paas.application-label.set")).toBeTruthy();
    expect(within(outcome).getByText("principal-admin")).toBeTruthy();
    expect(within(outcome).getByText(/返回的 ETag 替换旧版本/)).toBeTruthy();
    expect(screen.getByRole("button", { name: "管理标签" })).toBe(document.activeElement);
  });

  it("deletes exactly one application tag and rejects invalid tag keys without advancing", async () => {
    navigation.query = "resource=app-checkout-api";
    const { user } = await renderConsole({ section: "applications", experience: previewExperienceSnapshot });

    await user.click(screen.getByRole("button", { name: "管理标签" }));
    const key = screen.getByLabelText("标签键", { exact: true });
    await user.type(key, "Environment");
    await user.type(screen.getByLabelText("标签值", { exact: true }), "staging");
    await user.click(screen.getByRole("button", { name: "审阅变更" }));
    expect(screen.getByText("请输入符合规则的标签键。")).toBeTruthy();
    await waitFor(() => expect(key).toBe(document.activeElement));
    expect(screen.queryByRole("heading", { name: "审阅标签变更" })).toBeNull();

    await user.click(screen.getByRole("radio", { name: "删除标签" }));
    await user.click(screen.getByRole("combobox", { name: "选择要删除的标签" }));
    await user.click(screen.getByRole("option", { name: "team = commerce" }));
    await user.click(screen.getByRole("button", { name: "审阅变更" }));
    expect(screen.getByRole("heading", { name: "审阅标签变更" })).toBeTruthy();
    expect(screen.getByText("commerce")).toBeTruthy();
    expect(screen.getByText("删除", { selector: "strong" })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "模拟应用" }));

    const tags = screen.getByRole("table", { name: "应用资源标签" });
    expect(within(tags).queryByText("team")).toBeNull();
    expect(within(tags).queryByText("commerce")).toBeNull();
    expect(within(tags).getByText("environment")).toBeTruthy();
    expect(screen.getAllByText('"app-checkout-api:tags:8"')).toHaveLength(2);
    expect(within(screen.getByRole("region", { name: "最近一次模拟操作" })).getByText("paas.application-label.delete")).toBeTruthy();
  });

  it("reloads a changed application tag snapshot before allowing a version-conflict retry", async () => {
    navigation.query = "resource=app-checkout-api";
    const { user } = await renderConsole({ section: "applications", experience: previewExperienceSnapshot });

    await user.click(screen.getByRole("button", { name: "管理标签" }));
    await user.type(screen.getByLabelText("标签键", { exact: true }), "environment");
    await user.type(screen.getByLabelText("标签值", { exact: true }), "staging");
    await user.click(screen.getByRole("button", { name: "审阅变更" }));
    await user.click(screen.getByText("体验其他服务响应"));
    await user.click(screen.getByRole("combobox", { name: "下一次模拟响应" }));
    await user.click(screen.getByRole("option", { name: "412 · 资源版本已变化" }));
    await user.click(screen.getByRole("button", { name: "模拟应用" }));

    expect(screen.getByText(/系统已重新读取最新标签和 ETag/)).toBeTruthy();
    expect(screen.getByText("external-preview")).toBeTruthy();
    expect(screen.getByText('If-Match: "app-checkout-api:tags:8"')).toBeTruthy();
    expect(screen.queryByRole("region", { name: "最近一次模拟操作" })).toBeNull();
    await user.click(screen.getByRole("button", { name: "基于新版本重新提交" }));

    const outcome = screen.getByRole("region", { name: "最近一次模拟操作" });
    expect(within(outcome).getByText('"app-checkout-api:tags:9"')).toBeTruthy();
    expect(within(screen.getByRole("table", { name: "应用资源标签" })).getByText("staging")).toBeTruthy();
  });

  it("safely replays the same application tag intent after an interrupted response", async () => {
    navigation.query = "resource=app-checkout-api";
    const { user } = await renderConsole({ section: "applications", experience: previewExperienceSnapshot });

    await user.click(screen.getByRole("button", { name: "管理标签" }));
    await user.type(screen.getByLabelText("标签键", { exact: true }), "environment");
    await user.type(screen.getByLabelText("标签值", { exact: true }), "staging");
    await user.click(screen.getByRole("button", { name: "审阅变更" }));
    await user.click(screen.getByText("体验其他服务响应"));
    await user.click(screen.getByRole("combobox", { name: "下一次模拟响应" }));
    await user.click(screen.getByRole("option", { name: "响应中断 · 结果未知" }));
    await user.click(screen.getByRole("button", { name: "模拟应用" }));

    expect(screen.getByText(/不要创建新的变更/)).toBeTruthy();
    expect(screen.getByText('If-Match: "app-checkout-api:tags:7"')).toBeTruthy();
    expect(screen.queryByRole("region", { name: "最近一次模拟操作" })).toBeNull();
    await user.click(screen.getByRole("button", { name: "安全重试同一意图" }));

    expect(screen.getByRole("region", { name: "最近一次模拟操作" })).toBeTruthy();
    expect(screen.getAllByText('"app-checkout-api:tags:8"')).toHaveLength(2);
  });

  it("does not offer a blind retry for rejected application tag outcomes", async () => {
    navigation.query = "resource=app-checkout-api";
    const { user } = await renderConsole({ section: "applications", experience: previewExperienceSnapshot });

    await user.click(screen.getByRole("button", { name: "管理标签" }));
    await user.type(screen.getByLabelText("标签键", { exact: true }), "environment");
    await user.type(screen.getByLabelText("标签值", { exact: true }), "staging");
    await user.click(screen.getByRole("button", { name: "审阅变更" }));
    await user.click(screen.getByText("体验其他服务响应"));
    await user.click(screen.getByRole("combobox", { name: "下一次模拟响应" }));
    await user.click(screen.getByRole("option", { name: "409 · 请求意图冲突" }));
    await user.click(screen.getByRole("button", { name: "模拟应用" }));

    expect(screen.getByText(/原请求标识已经绑定到另一项意图/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: /重试|重新提交/ })).toBeNull();
    expect(screen.getByRole("button", { name: "返回修改" })).toBeTruthy();
  });

  it("does not invent an application resource for an unknown query identifier", async () => {
    navigation.query = "resource=missing";
    await renderConsole({ section: "applications", experience: previewExperienceSnapshot });
    expect(screen.getByText("未找到应用资源")).toBeTruthy();
    expect(screen.queryByRole("table", { name: "应用资源标签" })).toBeNull();
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
    expect(within(directory).getByRole("status").textContent).toBe("8 项服务");
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
    expect(navigation.push).toHaveBeenCalledWith("/console/resources/", { scroll: false });
    expect(load).toHaveBeenCalledTimes(1);
    await user.click(input);
    expect(screen.getByRole("listbox", { name: "Search results" })).toBeTruthy();
    await user.type(input, "compute node");
    const nodeResult = screen.getByRole("option", { name: /edge-worker-01/ });
    expect(nodeResult.textContent).toContain("Compute node");
    await user.click(nodeResult);
    expect(navigation.push).toHaveBeenLastCalledWith("/console/regions/", { scroll: false });
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

    await user.click(screen.getByRole("button", { name: /打开账号菜单/ }));
    await user.click(screen.getByRole("menuitem", { name: "注销并撤销 IAM 会话" }));

    await screen.findByRole("button", { name: "登录控制台" });
    expect(logout).toHaveBeenCalledWith("renderer-test-memory-only-session");
    expect(navigation.replace).toHaveBeenCalledWith("/");
  });

  it("keeps logout reachable while resources are still loading and disables duplicate revocation", async () => {
    const load = vi.fn(() => new Promise<ControlPlaneSnapshot>(() => {}));
    let confirmRevocation!: () => void;
    const logout = vi.fn(() => new Promise<void>((resolve) => { confirmRevocation = resolve; }));
    const { user } = await renderConsole({ load, logout });
    await user.click(screen.getByRole("button", { name: /打开账号菜单/ }));
    const exit = screen.getByRole("menuitem", { name: "注销并撤销 IAM 会话" });

    await user.click(exit);
    expect(exit.isConnected).toBe(false);
    await user.click(screen.getByRole("button", { name: /打开账号菜单/ }));
    const pendingExit = screen.getByRole("menuitem", { name: "注销并撤销 IAM 会话" });
    expect((pendingExit as HTMLButtonElement).disabled).toBe(true);
    await user.click(pendingExit);
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
    const workspace = document.getElementById("console-workspace");
    expect(install.getAttribute("aria-expanded")).toBe("false");
    expect(screen.queryByRole("button", { name: "提交安装任务" })).toBeNull();
    expect(workspace?.querySelector("form")).toBeNull();

    await user.click(install);
    const collapse = await screen.findByRole("button", { name: "收起安装配置" });
    expect(collapse.getAttribute("aria-expanded")).toBe("true");
    expect(screen.getByRole("button", { name: "提交安装任务" })).toBeTruthy();
    const name = screen.getByLabelText("显示名称") as HTMLInputElement;
    await user.clear(name);
    await user.type(name, "复核中的数据库");

    await user.click(collapse);

    expect(install.getAttribute("aria-expanded")).toBe("false");
    expect(screen.queryByRole("button", { name: "提交安装任务" })).toBeNull();
    expect(workspace?.querySelector("form")).toBeTruthy();

    await user.click(install);
    expect((screen.getByLabelText("显示名称") as HTMLInputElement).value).toBe("复核中的数据库");
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
    expect(navigation.push).toHaveBeenCalledWith("/console/observability/", { scroll: false });
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
