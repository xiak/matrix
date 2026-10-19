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
import { previewAccountRepository, previewCredential, previewIamRepository } from "@/features/auth/repositories/previewIamRepository";
import { HttpProblem } from "@/infrastructure/http/jsonRequest";
import { AUDIT_API_VERSION } from "@/features/audit/domain/audit";
import { useConsoleUiStore } from "../application/consoleUiStore";
import { previewServiceActivationStorageKey, writePreviewServiceActivation } from "../application/previewServiceActivation";
import type { ControlPlaneSnapshot, ServiceInstallation } from "../domain/resources";
import type { ExperienceSnapshot } from "../domain/experience";
import type { ApplicationDirectoryPage, ApplicationReadSnapshot } from "../domain/application";
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
    service: { id: "postgresql", revision: 1, contentDigest: `sha256:${"1".repeat(64)}` },
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

const liveServiceDefinition = {
  id: "postgresql",
  displayName: "PostgreSQL",
  description: "由 Matrix 管理的关系数据库服务。",
  revision: 1,
  contentDigest: `sha256:${"1".repeat(64)}`,
  activationPrerequisite: "PERMISSION_ONLY" as const,
  state: "AVAILABLE" as const
};

const liveServiceActivation = {
  service: {
    id: liveServiceDefinition.id,
    revision: liveServiceDefinition.revision,
    contentDigest: liveServiceDefinition.contentDigest
  },
  resourceVersion: 1,
  activatedAt: "2026-10-12T11:00:00.123456Z"
};

function liveServiceDirectory(available: boolean) {
  return {
    services: [liveServiceDefinition],
    activationCapability: {
      action: "managedservice.service-activation.activate" as const,
      resource: { kind: "SERVICE_ACTIVATION" as const, id: "collection" as const },
      available,
      ...(available ? {} : { restrictionReason: "AUTHORITY_REQUIRED" as const })
    }
  };
}

const liveApplicationReadSnapshot: ApplicationReadSnapshot = {
  etag: '"7"',
  application: {
    apiVersion: "paas.matrix.xiak.com/v1",
    kind: "Application",
    metadata: {
      id: "app-live-checkout",
      name: "live-checkout",
      scope: { kind: "TENANT", tenantId: "organization-test" },
      labels: { environment: "production" },
      resourceVersion: 7,
      createdAt: "2026-09-08T08:00:00Z",
      updatedAt: "2026-09-08T09:00:00Z"
    }
  }
};

const liveApplicationDirectoryPage: ApplicationDirectoryPage = {
  items: [liveApplicationReadSnapshot.application],
  nextAfter: null
};

const liveServiceRoleTemplate: ServiceRoleTemplate = {
  id: "managedservice.installation-reader",
  version: 2,
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
  getInstallation,
  terminateInstallation,
  inspectServiceAuthorization,
  readApplication,
  listApplications,
  bindServiceRole,
  unbindServiceRole,
  listServiceDefinitions,
  getServiceActivation,
  activateService,
  activateQuota,
  listCommandResults,
  logout = vi.fn().mockResolvedValue(undefined),
  accountRepository,
  iamRepository,
  roleSelfService,
  product,
  view: initialView,
  heldRoute
}: {
  section?: ConsoleSection;
  view?: ServiceView;
  product?: ControlPlaneRouteSelection["product"];
  experience?: ExperienceSnapshot;
  openWorkspace?: boolean;
  load?: ControlPlaneRepository["load"];
  getInstallation?: ControlPlaneRepository["getInstallation"];
  terminateInstallation?: ControlPlaneRepository["terminateInstallation"];
  inspectServiceAuthorization?: ControlPlaneRepository["inspectServiceAuthorization"];
  readApplication?: ControlPlaneRepository["readApplication"];
  listApplications?: ControlPlaneRepository["listApplications"];
  bindServiceRole?: ControlPlaneRepository["bindServiceRole"];
  unbindServiceRole?: ControlPlaneRepository["unbindServiceRole"];
  listServiceDefinitions?: ControlPlaneRepository["listServiceDefinitions"];
  getServiceActivation?: ControlPlaneRepository["getServiceActivation"];
  activateService?: ControlPlaneRepository["activateService"];
  activateQuota?: ControlPlaneRepository["activateQuota"];
  listCommandResults?: ControlPlaneRepository["listCommandResults"];
  logout?: IamRepository["logout"];
  accountRepository?: AccountRepository;
  iamRepository?: IamRepository;
  roleSelfService?: IamRepository["roleSelfService"];
  heldRoute?: { href: string; ready: boolean; promise: Promise<void> };
} = {}) {
  const loadedInstallations = new Map<string, ControlPlaneSnapshot["installations"][number]>();
  const trackedLoad = vi.fn<ControlPlaneRepository["load"]>(async (...args) => {
    const result = await load(...args);
    for (const installation of result.installations ?? []) loadedInstallations.set(installation.id, installation);
    return result;
  });
  const repository: ControlPlaneRepository = {
    load: trackedLoad,
    getInstallation: getInstallation ?? vi.fn(async (_credential, installationId) => {
      const installation = loadedInstallations.get(installationId);
      if (!installation) throw new HttpProblem(404, "INSTALLATION_NOT_FOUND");
      return installation;
    }),
    terminateInstallation,
    activateQuota: activateQuota ?? vi.fn(),
    createInstallation: vi.fn(),
    readApplication,
    listApplications,
    inspectServiceAuthorization,
    bindServiceRole,
    unbindServiceRole,
    listServiceDefinitions,
    getServiceActivation,
    activateService,
    listCommandResults
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
    logout,
    roleSelfService
  };
  const user = userEvent.setup({ delay: null });
  let replaceRepository: (next: ControlPlaneRepository) => void = () => {};
  let commitRoute: (href: string) => void = () => {};
  function RoutedPage() {
    const [activeRepository, setActiveRepository] = useState(repository);
    replaceRepository = setActiveRepository;
    const [href, setHref] = useState(consoleRouteHref({ section, view: initialView, product }));
    const acceptRoute = (target: string) => {
      const url = new URL(target, "https://matrix.invalid");
      navigation.query = url.search.slice(1);
      setHref(target);
    };
    commitRoute = acceptRoute;
    if (heldRoute) navigation.push.mockImplementation(acceptRoute);
    if (heldRoute && href === heldRoute.href && !heldRoute.ready) throw heldRoute.promise;
    return <ConsoleShellRenderer accountRepository={accountRepository} experience={experience} repository={activeRepository} selection={parseControlPlanePathname(new URL(href, "https://matrix.invalid").pathname)} />;
  }
  const view = render(
    <LocaleProvider><SessionProvider repository={iam}>
      <Suspense fallback={<p>Route bundle loading</p>}><RoutedPage /></Suspense>
    </SessionProvider></LocaleProvider>
  );
  await user.type(screen.getByLabelText("密码", { exact: true }), "renderer-test-password");
  await user.click(screen.getByRole("button", { name: "登录控制台" }));
  if (!product && ["overview", "catalog", "quotas", "installations", "regions"].includes(section)) {
    await waitFor(() => expect(load).toHaveBeenCalled());
  }
  if (openWorkspace) await user.click(await screen.findByRole("button", { name: section === "quotas" ? "激活配额" : section === "installations" ? "安装服务" : "查看平台状态" }));
  const loginDestination = navigation.replace.mock.calls.at(-1)?.[0];
  navigation.replace.mockClear();
  return { user, view, repository, replaceRepository, commitRoute, loginDestination };
}

afterEach(() => {
  cleanup();
  localStorage.clear();
  useConsoleUiStore.setState({ sidebarOverlayOpen: false, workspaceOpen: false });
  vi.clearAllMocks();
  vi.unstubAllGlobals();
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
    { selection: { section: "applications" }, role: "article", name: "应用目录" },
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
    { section: "applications", table: "当前身份可见的应用目录" },
    { section: "installations", table: "服务实例列表" },
    { section: "devops", table: "流水线运行列表" }
  ] as const)("keeps $section data readable as labelled records on compact tables", async ({ section, table }) => {
    const installation = {
      id: "pg-test", name: "订单主库", offeringId: "postgresql-18", engineVersion: "18",
      quotaEntitlementId: "quota-primary", regionId: "local-primary", phase: "READY" as const,
      endpoint: "pg-test.service.local:5432", credentialReference: null,
      resourceVersion: 1,
      operation: { id: "operation-test", kind: "PROVISION" as const, phase: "READY" as const, safeFailureCode: null, observedAt: "2026-08-26T12:00:00Z" },
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
      resourceVersion: 1,
      operation: { id: `operation-${id}`, kind: "PROVISION" as const, phase: "READY" as const, safeFailureCode: null, observedAt: "2026-08-26T12:00:00Z" },
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
    const heading = screen.getByRole("heading", { name: "PostgreSQL 18" });
    const productCard = heading.closest("article");
    expect(productCard?.querySelector("header")).toBeTruthy();
    expect(productCard?.querySelector("footer")).toBeTruthy();
    expect(within(productCard as HTMLElement).getByRole("link", { name: "进入 PostgreSQL 18 服务" }).getAttribute("href")).toBe("/console/products/postgresql/");
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
      resourceVersion: 1,
      operation: { id: "operation-test", kind: "PROVISION" as const, phase: "READY" as const, safeFailureCode: null, observedAt: "2026-08-26T12:00:00Z" },
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
      resourceVersion: 1,
      operation: { id: "operation-test", kind: "PROVISION" as const, phase: "READY" as const, safeFailureCode: null, observedAt: "2026-08-26T12:00:00Z" },
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
      resourceVersion: 1,
      operation: { id: `operation-${id}`, kind: "PROVISION" as const, phase: "READY" as const, safeFailureCode: null, observedAt: "2026-08-26T12:00:00Z" },
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

  it("re-authorizes the exact live instance before presenting directory data as details", async () => {
    const summary = {
      id: "pg-exact-read", name: "精确读取库", offeringId: "postgresql-18", engineVersion: "18",
      quotaEntitlementId: "quota-primary", regionId: "summary-region", phase: "FAILED" as const,
      endpoint: "must-not-leak-summary.service.local:5432", credentialReference: "must-not-leak-summary-credential",
      resourceVersion: 2,
      operation: { id: "must-not-leak-summary-operation", kind: "PROVISION" as const, phase: "FAILED" as const, safeFailureCode: "SUMMARY_ONLY", observedAt: "2026-08-26T12:00:00Z" },
      createdAt: "2026-08-26T12:00:00Z"
    };
    const detail = {
      ...summary,
      regionId: "local-primary",
      phase: "READY" as const,
      endpoint: "pg-exact-read.service.local:5432",
      credentialReference: null,
      resourceVersion: 3,
      operation: { id: "operation-exact-read", kind: "PROVISION" as const, phase: "READY" as const, safeFailureCode: null, observedAt: "2026-08-26T12:00:04Z" }
    };
    let finishRead!: (value: typeof detail) => void;
    const getInstallation = vi.fn(() => new Promise<typeof detail>((resolve) => { finishRead = resolve; }));
    const inspectServiceAuthorization = vi.fn().mockResolvedValue({ template: liveServiceRoleTemplate, relation: null, binding: null });
    const { user } = await renderConsole({
      section: "installations",
      load: vi.fn().mockResolvedValue({ ...snapshot, installations: [summary] }),
      getInstallation,
      inspectServiceAuthorization
    });

    await user.click(await screen.findByRole("button", { name: "精确读取库" }));

    expect(screen.getByRole("heading", { name: "精确读取库" })).toBeTruthy();
    expect(screen.getByRole("status").textContent).toBe("正在重新鉴权并读取这个准确实例");
    expect(getInstallation).toHaveBeenCalledWith("renderer-test-memory-only-session", "pg-exact-read");
    expect(inspectServiceAuthorization).not.toHaveBeenCalled();
    expect(screen.queryByText("must-not-leak-summary.service.local:5432")).toBeNull();
    expect(screen.queryByText("must-not-leak-summary-operation")).toBeNull();
    expect(screen.queryByText("失败")).toBeNull();
    expect(screen.queryByRole("button", { name: /审阅并授权服务|解除实例授权/ })).toBeNull();

    finishRead(detail);

    expect(await screen.findByText("pg-exact-read.service.local:5432")).toBeTruthy();
    expect(screen.getByText("operation-exact-read")).toBeTruthy();
    expect(screen.queryByText("must-not-leak-summary.service.local:5432")).toBeNull();
    expect(screen.queryByText("must-not-leak-summary-operation")).toBeNull();
    await waitFor(() => expect(inspectServiceAuthorization).toHaveBeenCalledWith(
      "renderer-test-memory-only-session",
      "organization-test",
      "pg-exact-read"
    ));
  });

  it("reviews installation termination in the content region and keeps the submit control stable", async () => {
    const installation: ServiceInstallation = {
      id: "pg-termination-review",
      name: "待终止数据库",
      offeringId: "postgresql-18",
      engineVersion: "18",
      quotaEntitlementId: "quota-primary",
      regionId: "local-primary",
      phase: "READY",
      endpoint: "pg-termination-review.service.local:5432",
      credentialReference: "credential-pg-termination-review",
      resourceVersion: 4,
      createdAt: "2026-08-26T12:00:00Z",
      operation: {
        id: "operation-provision-termination-review",
        kind: "PROVISION",
        phase: "READY",
        safeFailureCode: null,
        observedAt: "2026-08-26T12:00:04Z"
      }
    };
    const accepted: ServiceInstallation = {
      ...installation,
      phase: "TERMINATION_PENDING",
      resourceVersion: 5,
      operation: {
        id: "operation-terminate-review",
        kind: "TERMINATE",
        phase: "PENDING",
        safeFailureCode: null,
        observedAt: "2026-08-26T12:04:00Z"
      }
    };
    let acceptTermination!: (value: ServiceInstallation) => void;
    const terminateInstallation = vi.fn(() => new Promise<ServiceInstallation>((resolve) => {
      acceptTermination = resolve;
    }));
    const { user } = await renderConsole({
      section: "installations",
      load: vi.fn().mockResolvedValue({ ...snapshot, installations: [installation] }),
      terminateInstallation
    });

    await user.click(await screen.findByRole("button", { name: installation.name }));
    await user.click(await screen.findByRole("button", { name: "审阅终止实例" }));

    expect(screen.queryByRole("dialog")).toBeNull();
    expect(screen.getByRole("heading", { level: 2, name: `终止实例 · ${installation.name}` })).toBeTruthy();
    expect(screen.getByText("确认后平台将异步物理删除这个实例的容器、网络、持久化数据和托管凭据；只有终止完成后才归还配额。已接受请求不等于已经删除完成。")).toBeTruthy();
    const submit = screen.getByRole("button", { name: "确认终止实例" }) as HTMLButtonElement;
    expect(submit.disabled).toBe(true);
    await user.type(screen.getByRole("textbox", { name: "输入实例 ID 以确认" }), installation.id);
    expect(submit.disabled).toBe(false);
    await user.click(submit);

    const submitting = screen.getByRole("button", { name: "正在提交终止请求" }) as HTMLButtonElement;
    expect(submitting.disabled).toBe(true);
    expect(terminateInstallation).toHaveBeenCalledWith(
      "renderer-test-memory-only-session",
      installation.id,
      expect.stringMatching(/^ui-installation-termination-/)
    );

    acceptTermination(accepted);
    expect((await screen.findAllByText("等待终止")).length).toBeGreaterThan(0);
    expect(screen.getByText(/正在异步清理运行时、网络、数据与凭据/)).toBeTruthy();
  });

  it("confirms an unknown termination through the original public key and independently rereads the instance", async () => {
    const installation: ServiceInstallation = {
      id: "pg-termination-unknown",
      name: "终止结果待确认库",
      offeringId: "postgresql-18",
      engineVersion: "18",
      quotaEntitlementId: "quota-primary",
      regionId: "local-primary",
      phase: "READY",
      endpoint: "pg-termination-unknown.service.local:5432",
      credentialReference: "credential-pg-termination-unknown",
      resourceVersion: 3,
      createdAt: "2026-08-26T12:00:00Z",
      operation: {
        id: "operation-provision-termination-unknown",
        kind: "PROVISION",
        phase: "READY",
        safeFailureCode: null,
        observedAt: "2026-08-26T12:00:04Z"
      }
    };
    const accepted: ServiceInstallation = {
      ...installation,
      phase: "TERMINATION_PENDING",
      resourceVersion: 4,
      operation: {
        id: "operation-terminate-unknown",
        kind: "TERMINATE",
        phase: "PENDING",
        safeFailureCode: null,
        observedAt: "2026-08-26T12:04:00Z"
      }
    };
    const terminateInstallation = vi.fn()
      .mockRejectedValueOnce(new Error("connection ended before a response was observed"));
    const listCommandResults = vi.fn<NonNullable<ControlPlaneRepository["listCommandResults"]>>(async () => [{
      idempotencyKey: terminateInstallation.mock.calls[0]![2], commandType: "INSTALLATION_TERMINATE", inputDigest: `sha256:${"a".repeat(64)}`,
      state: "IN_PROGRESS", target: { kind: "SERVICE_INSTALLATION", id: installation.id }, operation: accepted.operation, bindingId: null, completedAt: null
    }]);
    const getInstallation = vi.fn().mockResolvedValueOnce(installation).mockResolvedValue(accepted);
    const { user } = await renderConsole({
      section: "installations",
      load: vi.fn().mockResolvedValue({ ...snapshot, installations: [installation] }),
      terminateInstallation,
      getInstallation,
      listCommandResults
    });

    await user.click(await screen.findByRole("button", { name: installation.name }));
    await user.click(await screen.findByRole("button", { name: "审阅终止实例" }));
    await user.type(screen.getByRole("textbox", { name: "输入实例 ID 以确认" }), installation.id);
    await user.click(screen.getByRole("button", { name: "确认终止实例" }));

    expect(await screen.findByText(/服务端结果尚未确认/)).toBeTruthy();
    const firstRequestId = terminateInstallation.mock.calls[0]![2];
    await user.click(screen.getByRole("button", { name: "返回实例并保留原请求" }));
    expect(await screen.findByRole("button", { name: "继续处理未确认终止" })).toBeTruthy();
    expect(screen.getByText(firstRequestId)).toBeTruthy();

    await user.click(screen.getByRole("button", { name: "继续处理未确认终止" }));
    await user.click(screen.getByRole("button", { name: "检查原请求结果" }));
    expect(terminateInstallation).toHaveBeenCalledTimes(1);
    expect(listCommandResults).toHaveBeenCalledWith("renderer-test-memory-only-session", "INSTALLATION_TERMINATE");
    await waitFor(() => expect(getInstallation).toHaveBeenCalledTimes(2));
    expect((await screen.findAllByText("等待终止")).length).toBeGreaterThan(0);
  });

  it("keeps a denied live instance read local and retries only the same locator", async () => {
    const installation = {
      id: "pg-denied-read", name: "受限数据库", offeringId: "postgresql-18", engineVersion: "18",
      quotaEntitlementId: "quota-primary", regionId: "local-primary", phase: "READY" as const,
      endpoint: "must-not-leak.service.local:5432", credentialReference: null,
      resourceVersion: 1,
      operation: { id: "operation-denied-read", kind: "PROVISION" as const, phase: "READY" as const, safeFailureCode: null, observedAt: "2026-08-26T12:00:00Z" },
      createdAt: "2026-08-26T12:00:00Z"
    };
    const getInstallation = vi.fn()
      .mockRejectedValueOnce(new HttpProblem(403, "INSTALLATION_READ_FORBIDDEN"))
      .mockResolvedValueOnce(installation);
    const inspectServiceAuthorization = vi.fn();
    const { user } = await renderConsole({
      section: "installations",
      load: vi.fn().mockResolvedValue({ ...snapshot, installations: [installation] }),
      getInstallation,
      inspectServiceAuthorization
    });

    await user.click(await screen.findByRole("button", { name: "受限数据库" }));

    expect(await screen.findByText(/目录中曾出现该实例，并不代表详情读取仍被允许/)).toBeTruthy();
    expect(screen.getByText("详情不可用")).toBeTruthy();
    expect(screen.queryByText("运行中")).toBeNull();
    expect(screen.queryByText("must-not-leak.service.local:5432")).toBeNull();
    expect(inspectServiceAuthorization).not.toHaveBeenCalled();

    await user.click(screen.getByRole("button", { name: "重新读取实例" }));

    expect(await screen.findByText("must-not-leak.service.local:5432")).toBeTruthy();
    expect(getInstallation).toHaveBeenCalledTimes(2);
    expect(getInstallation.mock.calls.every(([, id]) => id === "pg-denied-read")).toBe(true);
  });

  it("keeps live instance chrome stable while only its service-authorization region loads", async () => {
    const installation = {
      id: "pg-test", name: "订单主库", offeringId: "postgresql-18", engineVersion: "18",
      quotaEntitlementId: "quota-primary", regionId: "local-primary", phase: "READY" as const,
      endpoint: "pg-test.service.local:5432", credentialReference: null,
      resourceVersion: 1,
      operation: { id: "operation-test", kind: "PROVISION" as const, phase: "READY" as const, safeFailureCode: null, observedAt: "2026-08-26T12:00:00Z" },
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
    await waitFor(() => expect(inspectServiceAuthorization).toHaveBeenCalledTimes(1));

    finishInspection({
      template: {
        id: "managedservice.installation-reader", version: 2, contentDigest: `sha256:${"c".repeat(64)}`, status: "ACTIVE",
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
        resourceVersion: 1,
        operation: { id: "operation-unbound", kind: "PROVISION" as const, phase: "READY" as const, safeFailureCode: null, observedAt: "2026-08-26T12:00:00Z" },
        createdAt: "2026-08-26T12:00:00Z"
      }] }),
      inspectServiceAuthorization: vi.fn().mockResolvedValue({
        template: {
          id: "managedservice.installation-reader", version: 2, contentDigest: `sha256:${"c".repeat(64)}`, status: "ACTIVE",
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
          template: { id: "managedservice.installation-reader", version: 2, contentDigest: `sha256:${"c".repeat(64)}` },
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
        resourceVersion: 1,
        operation: { id: "operation-live-bind", kind: "PROVISION" as const, phase: "READY" as const, safeFailureCode: null, observedAt: "2026-08-26T12:00:00Z" },
        createdAt: "2026-08-26T12:00:00Z"
      }] }),
      inspectServiceAuthorization,
      bindServiceRole
    });

    await user.click(await screen.findByRole("button", { name: "订单主库" }));
    await user.click(await screen.findByRole("button", { name: "审阅并授权服务" }));

    expect(screen.queryByRole("dialog")).toBeNull();
    expect(screen.getByRole("heading", { name: "确认服务访问授权" })).toBeTruthy();
    expect(screen.getByText(`${liveServiceRoleTemplate.id}@v2`)).toBeTruthy();
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

  it("confirms an unknown live authorization by public key without another bind", async () => {
    const installationId = "pg-live-unknown";
    const bindServiceRole = vi.fn()
      .mockRejectedValueOnce(new Error("connection ended before a response was observed"));
    const listCommandResults = vi.fn<NonNullable<ControlPlaneRepository["listCommandResults"]>>(async () => [{
      idempotencyKey: bindServiceRole.mock.calls[0]![2].requestId, commandType: "SERVICE_ROLE_BIND", inputDigest: `sha256:${"b".repeat(64)}`,
      state: "SUCCEEDED", target: { kind: "SERVICE_INSTALLATION", id: installationId }, operation: null, bindingId: `binding-${installationId}`, completedAt: "2026-10-13T12:00:00Z"
    }]);
    const { user } = await renderConsole({
      section: "installations",
      load: vi.fn().mockResolvedValue({ ...snapshot, installations: [{
        id: installationId, name: "结果待确认库", offeringId: "postgresql-18", engineVersion: "18",
        quotaEntitlementId: "quota-primary", regionId: "local-primary", phase: "READY" as const,
        endpoint: "pg-live-unknown.service.local:5432", credentialReference: null,
        resourceVersion: 1,
        operation: { id: "operation-live-unknown", kind: "PROVISION" as const, phase: "READY" as const, safeFailureCode: null, observedAt: "2026-08-26T12:00:00Z" },
        createdAt: "2026-08-26T12:00:00Z"
      }] }),
      inspectServiceAuthorization: vi.fn().mockResolvedValue({ template: liveServiceRoleTemplate, relation: null, binding: null }),
      bindServiceRole,
      listCommandResults
    });

    await user.click(await screen.findByRole("button", { name: "结果待确认库" }));
    await user.click(await screen.findByRole("button", { name: "审阅并授权服务" }));
    await user.click(screen.getByRole("button", { name: "确认授权" }));

    expect(await screen.findByText(/服务端结果尚未确认/)).toBeTruthy();
    const firstCommand = bindServiceRole.mock.calls[0]![2];
    const summary = JSON.parse((screen.getByLabelText("只读恢复摘要") as HTMLTextAreaElement).value);
    expect(summary.requestId).toBe(firstCommand.requestId);
    expect(summary.owner).toEqual({ accountId: "organization-test", actorKind: "USER", actorId: "principal-test" });
    expect(summary.payload.template).toEqual({ id: "managedservice.installation-reader", version: 2, contentDigest: liveServiceRoleTemplate.contentDigest });
    await user.click(screen.getByRole("button", { name: "返回实例并保留原请求" }));
    expect(await screen.findByRole("button", { name: "继续处理未确认请求" })).toBeTruthy();
    expect(screen.getByText(firstCommand.requestId)).toBeTruthy();

    await user.click(screen.getByRole("button", { name: "继续处理未确认请求" }));
    await user.click(screen.getByRole("button", { name: "检查原请求结果" }));
    expect(await screen.findByText(/服务端已确认匹配的原操作成功/)).toBeTruthy();
    expect(bindServiceRole).toHaveBeenCalledTimes(1);
    expect(listCommandResults).toHaveBeenCalledWith("renderer-test-memory-only-session", "SERVICE_ROLE_BIND");
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
        resourceVersion: 1,
        operation: { id: "operation-live-unbind", kind: "PROVISION" as const, phase: "READY" as const, safeFailureCode: null, observedAt: "2026-08-26T12:00:00Z" },
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
    { href: "/console/applications/", service: /应用托管/, title: "应用服务", reads: 0, marker: { role: "table", name: "当前身份可见的应用目录" } },
    { href: "/console/products/postgresql/", service: /云数据库 PostgreSQL/, title: "产品概览", reads: 1, marker: { role: "heading", name: "云数据库 PostgreSQL" } },
    { href: "/console/logs/", service: /日志服务/, title: "日志概览", reads: 0, marker: { role: "text", name: "Matrix · Log Service" } },
    { href: "/console/devops/", service: /研发效能 DevOps/, title: "交付总览", reads: 0, marker: { role: "heading", name: "最近流水线" } },
    { href: "/console/observability/", service: /云监控/, title: "监控总览", reads: 0, marker: { role: "heading", name: "服务健康" } }
  ] as const)("opens the $title service frame immediately while its route bundle is pending", async ({ href, marker, reads, service, title: expectedTitle }) => {
    if (href.includes("/products/")) writePreviewServiceActivation(localStorage, {
      accountId: previewExperienceSnapshot.organization.id, serviceKey: "postgresql", termsVersion: "mock-v1",
      acceptedBy: "principal-test", acceptedAt: "2026-10-12T01:00:00.000Z", enabledAt: "2026-10-12T01:00:00.000Z"
    });
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
    else expect(!oldResource.isConnected || oldResource.closest("[hidden]")).toBeTruthy();
    if (href.includes("/products/")) await screen.findByText(/对应后端能力仍是待独立验收的候选/);
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
    expect(repository.load).toHaveBeenCalledTimes(4);

    await act(async () => { heldRoute.ready = true; release(); });
    await waitFor(() => expect(product.closest("[inert]")).toBeNull());
    expect(product.isConnected).toBe(true);
    expect(repository.load).toHaveBeenCalledTimes(4);
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

  it("shows product permission onboarding only in the isolated preview navigation", async () => {
    await renderConsole({
      accountRepository: previewAccountRepository,
      experience: previewExperienceSnapshot,
      iamRepository: previewIamRepository,
      section: "access",
      view: "users"
    });
    const menu = await screen.findByRole("navigation", { name: "控制台导航" });
    expect(within(menu).getByRole("link", { name: "产品权限接入" }).getAttribute("href")).toBe("/console/access/authorization-profiles/");
  });

  it("keeps product permission onboarding out of LIVE navigation", async () => {
    const liveRepository: AccountRepository = { ...previewAccountRepository, workspace: undefined };
    await renderConsole({
      accountRepository: liveRepository,
      iamRepository: previewIamRepository,
      section: "access",
      view: "users"
    });
    const menu = await screen.findByRole("navigation", { name: "控制台导航" });
    expect(within(menu).queryByRole("link", { name: "产品权限接入" })).toBeNull();
  });

  it("exposes implemented LIVE security workspaces without exposing preview-only IAM pages", async () => {
    const liveRepository: AccountRepository = {
      ...previewAccountRepository,
      workspace: undefined,
      accessKeys: {} as NonNullable<AccountRepository["accessKeys"]>,
      accessAnalysis: {} as NonNullable<AccountRepository["accessAnalysis"]>,
      securityReports: {} as NonNullable<AccountRepository["securityReports"]>
    };
    await renderConsole({
      accountRepository: liveRepository,
      iamRepository: previewIamRepository,
      section: "access",
      view: "users"
    });

    const menu = await screen.findByRole("navigation", { name: "控制台导航" });
    expect(within(menu).getByRole("link", { name: "访问密钥" }).getAttribute("href")).toBe("/console/access/keys/");
    expect(within(menu).getByRole("link", { name: "访问分析" }).getAttribute("href")).toBe("/console/access/access-analysis/");
    expect(within(menu).getByRole("link", { name: "安全报告" }).getAttribute("href")).toBe("/console/access/security-reports/");
    expect(within(menu).queryByRole("link", { name: "角色 SSO" })).toBeNull();
    expect(within(menu).queryByRole("link", { name: "用户 SSO" })).toBeNull();
    expect(within(menu).queryByRole("link", { name: "跨账号协作" })).toBeNull();
    expect(within(menu).queryByRole("link", { name: "产品权限接入" })).toBeNull();
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

  it("keeps the product homepage structure stable while destination data is still pending", async () => {
    writePreviewServiceActivation(localStorage, {
      accountId: previewExperienceSnapshot.organization.id, serviceKey: "postgresql", termsVersion: "mock-v1",
      acceptedBy: "principal-admin", acceptedAt: "2026-10-12T01:00:00.000Z", enabledAt: "2026-10-12T01:00:00.000Z"
    });
    let resolveSnapshot!: (value: ControlPlaneSnapshot) => void;
    let releaseRoute!: () => void;
    const load = vi.fn(() => new Promise<ControlPlaneSnapshot>((resolve) => { resolveSnapshot = resolve; }));
    const heldRoute = { href: "/console/products/postgresql/", ready: false, promise: new Promise<void>((resolve) => { releaseRoute = resolve; }) };
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

    expect(screen.getByRole("heading", { level: 1, name: "产品概览" })).toBeTruthy();
    expect(screen.getByRole("heading", { level: 2, name: "云数据库 PostgreSQL" })).toBeTruthy();
    expect(!users.isConnected || users.closest("[hidden]")).toBeTruthy();
    expect(load).toHaveBeenCalledTimes(1);

    await act(async () => resolveSnapshot(snapshot));
    await act(async () => { heldRoute.ready = true; releaseRoute(); });
    expect(await screen.findByRole("heading", { level: 2, name: "云数据库 PostgreSQL" })).toBeTruthy();
    expect(await screen.findByRole("link", { name: /进入实例/ })).toBeTruthy();
    expect(screen.getByRole("heading", { level: 1, name: "产品概览" })).toBeTruthy();
    expect(load).toHaveBeenCalledTimes(1);
  });

  it.each(["postgresql", "mysql", "elasticsearch", "rabbitmq"] as const)("requires explicit account-level MOCK enablement for the %s workspace", async (product) => {
    const { user, repository } = await renderConsole({ section: "catalog", product, experience: previewExperienceSnapshot });
    const enable = await screen.findByRole("button", { name: "同意并开通 · MOCK" });
    expect((enable as HTMLButtonElement).disabled).toBe(true);
    expect(screen.queryByRole("link", { name: /进入实例/ })).toBeNull();
    expect(screen.queryByRole("button", { name: "激活配额" })).toBeNull();
    expect(repository.load).not.toHaveBeenCalled();
    await user.click(screen.getByRole("checkbox", { name: /我已阅读开通说明/ }));
    await user.click(enable);
    expect(await screen.findByRole("link", { name: /进入实例/ })).toBeTruthy();
    expect(repository.load).toHaveBeenCalledTimes(1);
    expect(repository.activateQuota).not.toHaveBeenCalled();
    expect(repository.createInstallation).not.toHaveBeenCalled();
    expect(repository.bindServiceRole).toBeUndefined();
    expect(localStorage.getItem(previewServiceActivationStorageKey)).toContain('"serviceKey":"' + product + '"');
  });

  it("projects the first-use gate immediately during held service navigation without loading resources", async () => {
    let releaseRoute!: () => void;
    const heldRoute = { href: "/console/products/postgresql/", ready: false, promise: new Promise<void>((resolve) => { releaseRoute = resolve; }) };
    const { user, repository } = await renderConsole({
      accountRepository: previewAccountRepository, experience: previewExperienceSnapshot, heldRoute,
      iamRepository: previewIamRepository, section: "access", view: "users"
    });
    const users = await screen.findByRole("table", { name: "租户用户列表" });
    await user.click(screen.getByRole("button", { name: "打开产品与服务" }));
    fireEvent.click(within(screen.getByRole("dialog", { name: "云产品入口" })).getByRole("link", { name: /云数据库 PostgreSQL/ }));
    expect(screen.getByRole("heading", { level: 1, name: "产品概览" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "同意并开通 · MOCK" })).toBeTruthy();
    expect(!users.isConnected || users.closest("[hidden]")).toBeTruthy();
    expect(repository.load).not.toHaveBeenCalled();
    await act(async () => { heldRoute.ready = true; releaseRoute(); });
    expect(screen.getByRole("button", { name: "同意并开通 · MOCK" })).toBeTruthy();
    expect(repository.load).not.toHaveBeenCalled();
  });

  it("keeps a late resource failure out of the reset first-use flow", async () => {
    let rejectLoad!: (reason: Error) => void;
    const load = vi.fn<ControlPlaneRepository["load"]>(() => new Promise((_resolve, reject) => { rejectLoad = reject; }));
    const { user } = await renderConsole({ section: "catalog", product: "postgresql", experience: previewExperienceSnapshot, load });
    expect(load).not.toHaveBeenCalled();
    await user.click(screen.getByRole("checkbox", { name: /我已阅读开通说明/ }));
    await user.click(screen.getByRole("button", { name: "同意并开通 · MOCK" }));
    await waitFor(() => expect(load).toHaveBeenCalledTimes(1));
    await user.click(screen.getByText("开通场景与重置"));
    await user.click(screen.getByRole("button", { name: "重置此服务开通" }));
    await act(async () => { rejectLoad(new HttpProblem(503, "RESOURCE_UNAVAILABLE")); });
    expect(screen.getByRole("button", { name: "同意并开通 · MOCK" })).toBeTruthy();
    expect(screen.queryByRole("alert")).toBeNull();
    expect(screen.queryByRole("link", { name: /进入实例/ })).toBeNull();
    expect((screen.getByRole("checkbox", { name: /我已阅读开通说明/ }) as HTMLInputElement).checked).toBe(false);
  });

  it("shows resource failures only inside the opened product without reversing activation", async () => {
    const load = vi.fn<ControlPlaneRepository["load"]>().mockRejectedValue(new HttpProblem(503, "RESOURCE_UNAVAILABLE"));
    const { user } = await renderConsole({ section: "catalog", product: "postgresql", experience: previewExperienceSnapshot, load });
    expect(load).not.toHaveBeenCalled();
    expect(screen.queryByRole("alert")).toBeNull();
    await user.click(screen.getByRole("checkbox", { name: /我已阅读开通说明/ }));
    await user.click(screen.getByRole("button", { name: "同意并开通 · MOCK" }));
    expect(await screen.findByRole("heading", { name: "控制面未能加载" })).toBeTruthy();
    expect(localStorage.getItem(previewServiceActivationStorageKey)).toContain('"serviceKey":"postgresql"');
    expect(screen.queryByRole("button", { name: "重试开通 · MOCK" })).toBeNull();
    await user.click(screen.getByText("开通场景与重置"));
    await user.click(screen.getByRole("button", { name: "重置此服务开通" }));
    expect(screen.getByRole("button", { name: "同意并开通 · MOCK" })).toBeTruthy();
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("guards product subroutes and keeps enablement separate from IAM grants and resource authority", async () => {
    const { user, repository } = await renderConsole({
      section: "installations", product: "postgresql", experience: previewExperienceSnapshot,
      accountRepository: previewAccountRepository, iamRepository: previewIamRepository
    });
    const before = await previewAccountRepository.workspace!.read(previewCredential);
    expect(await screen.findByRole("button", { name: "同意并开通 · MOCK" })).toBeTruthy();
    expect(screen.queryByRole("heading", { name: "组织服务实例" })).toBeNull();
    expect(screen.queryByRole("button", { name: "安装服务" })).toBeNull();
    expect(repository.load).not.toHaveBeenCalled();
    await user.click(screen.getByText("开通场景与重置"));
    await user.click(screen.getByRole("combobox", { name: "身份与权限场景" }));
    await user.click(screen.getByRole("option", { name: "子用户 · 仅获开通授权" }));
    await user.click(screen.getByRole("checkbox", { name: /我已阅读开通说明/ }));
    await user.click(screen.getByRole("button", { name: "同意并开通 · MOCK" }));
    expect(await screen.findByText(/尚未获得资源操作权限/)).toBeTruthy();
    expect(screen.queryByRole("heading", { name: "组织服务实例" })).toBeNull();
    expect(screen.queryByRole("button", { name: "安装服务" })).toBeNull();
    expect(await previewAccountRepository.workspace!.read(previewCredential)).toEqual(before);
    expect(repository.load).not.toHaveBeenCalled();
    expect(repository.activateQuota).not.toHaveBeenCalled();
    expect(repository.createInstallation).not.toHaveBeenCalled();

    await user.click(screen.getByRole("combobox", { name: "身份与权限场景" }));
    await user.click(screen.getByRole("option", { name: "子用户 · 仅获资源权限" }));
    expect(await screen.findByRole("heading", { name: "组织服务实例" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "安装服务" })).toBeTruthy();
    expect(repository.load).toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "重置此服务开通" }));
    expect(await screen.findByText(/当前身份没有开通资格/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: "安装服务" })).toBeNull();
  });

  it.each(["postgresql", "mysql", "elasticsearch", "rabbitmq"])("routes a catalog card using the backend %s service reference rather than its offering or engine name", async (serviceId) => {
    await renderConsole({ section: "catalog", load: vi.fn().mockResolvedValue({ ...snapshot, offerings: [{
      ...snapshot.offerings[0]!, service: { ...snapshot.offerings[0]!.service, id: serviceId }
    }] }) });
    expect((await screen.findByRole("link", { name: "进入 PostgreSQL 18 服务" })).getAttribute("href")).toBe(`/console/products/${serviceId}/`);
  });

  it("reaches the LIVE first-use gate from a catalog card before admitting product data", async () => {
    const listServiceDefinitions = vi.fn().mockResolvedValue(liveServiceDirectory(true));
    const getServiceActivation = vi.fn().mockRejectedValue(new HttpProblem(404, "NOT_FOUND"));
    const activateService = vi.fn().mockResolvedValue(liveServiceActivation);
    const { user, repository } = await renderConsole({ section: "catalog", listServiceDefinitions, getServiceActivation, activateService,
      heldRoute: { href: "/console/products/postgresql/", ready: true, promise: Promise.resolve() }
    });
    const entry = await screen.findByRole("link", { name: "进入 PostgreSQL 18 服务" });
    expect(entry.getAttribute("href")).toBe("/console/products/postgresql/");
    expect(listServiceDefinitions).not.toHaveBeenCalled();
    expect(repository.load).toHaveBeenCalledTimes(1);
    await user.click(entry);
    expect(await screen.findByRole("button", { name: "开通服务" })).toBeTruthy();
    expect(repository.load).toHaveBeenCalledTimes(1);
    expect(getServiceActivation).toHaveBeenCalledWith("renderer-test-memory-only-session", "postgresql");
    await user.click(screen.getByRole("button", { name: "开通服务" }));
    expect(await screen.findByRole("link", { name: /进入实例/ })).toBeTruthy();
    expect(activateService).toHaveBeenCalledWith("renderer-test-memory-only-session", liveServiceActivation.service, expect.stringMatching(/^ui-service-activation-/));
    expect(repository.load).toHaveBeenCalledTimes(2);
  });

  it("reaches a LIVE product from the Header's lazy backend directory while activation authority remains denied", async () => {
    const listServiceDefinitions = vi.fn().mockResolvedValue(liveServiceDirectory(false));
    const activateService = vi.fn();
    const { user, repository } = await renderConsole({
      section: "overview", listServiceDefinitions,
      getServiceActivation: vi.fn().mockRejectedValue(new HttpProblem(404, "NOT_FOUND")), activateService,
      heldRoute: { href: "/console/products/postgresql/", ready: true, promise: Promise.resolve() }
    });
    expect(listServiceDefinitions).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "打开产品与服务" }));
    const entry = await screen.findByRole("link", { name: /PostgreSQL.*由 Matrix/ });
    expect(entry.getAttribute("href")).toBe("/console/products/postgresql/");
    expect(listServiceDefinitions).toHaveBeenCalledExactlyOnceWith("renderer-test-memory-only-session");
    expect(within(screen.getByRole("dialog")).queryByRole("link", { name: /云数据库 MySQL|访问管理 IAM/ })).toBeNull();
    await user.click(entry);
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(await screen.findByText(/当前身份没有开通资格/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: "开通服务" })).toBeNull();
    expect(repository.load).toHaveBeenCalledTimes(1);
    expect(activateService).not.toHaveBeenCalled();
  });

  it("uses the LIVE directory capability for direct permission-only activation and ignores browser MOCK consent", async () => {
    writePreviewServiceActivation(localStorage, {
      accountId: "organization-test", serviceKey: "postgresql", termsVersion: "mock-v1", acceptedBy: "principal-test",
      acceptedAt: "2026-10-12T01:00:00.000Z", enabledAt: "2026-10-12T01:00:00.000Z"
    });
    const listServiceDefinitions = vi.fn().mockResolvedValue(liveServiceDirectory(true));
    const getServiceActivation = vi.fn().mockRejectedValue(new HttpProblem(404, "NOT_FOUND"));
    const activateService = vi.fn().mockResolvedValue(liveServiceActivation);
    const { user, repository } = await renderConsole({
      section: "catalog", product: "postgresql", listServiceDefinitions, getServiceActivation, activateService
    });

    expect(await screen.findByRole("button", { name: "开通服务" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "同意并开通 · MOCK" })).toBeNull();
    expect(screen.queryByRole("checkbox")).toBeNull();
    expect(screen.getByText(/不会创建服务角色/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: "激活配额" })).toBeNull();
    expect(screen.queryByText("开通场景与重置")).toBeNull();
    expect(repository.activateQuota).not.toHaveBeenCalled();
    expect(repository.load).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "开通服务" }));
    expect(await screen.findByRole("link", { name: /进入实例/ })).toBeTruthy();
    expect(activateService).toHaveBeenCalledWith(
      "renderer-test-memory-only-session",
      liveServiceActivation.service,
      expect.stringMatching(/^ui-service-activation-/)
    );
    expect(repository.load).toHaveBeenCalledTimes(1);
  });

  it("keeps activation denied when the exact LIVE capability is unavailable", async () => {
    const { repository } = await renderConsole({
      section: "catalog",
      product: "postgresql",
      listServiceDefinitions: vi.fn().mockResolvedValue(liveServiceDirectory(false)),
      getServiceActivation: vi.fn().mockRejectedValue(new HttpProblem(404, "NOT_FOUND"))
    });
    expect(await screen.findByText(/当前身份没有开通资格/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: "开通服务" })).toBeNull();
    expect(repository.load).not.toHaveBeenCalled();
  });

  it("does not block an independently authorized resource page when activation reads are forbidden", async () => {
    const { repository } = await renderConsole({
      section: "catalog",
      product: "postgresql",
      listServiceDefinitions: vi.fn().mockResolvedValue(liveServiceDirectory(false)),
      getServiceActivation: vi.fn().mockRejectedValue(new HttpProblem(403, "PERMISSION_DENIED"))
    });
    expect(await screen.findByRole("link", { name: /进入实例/ })).toBeTruthy();
    expect(repository.load).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole("button", { name: "开通服务" })).toBeNull();
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
    const title = screen.getByRole("heading", { name: "服务实例" });
    const menu = screen.getByRole("navigation", { name: "控制台导航" });
    expect(screen.queryByRole("table")).toBeNull();
    expect(screen.queryByRole("button", { name: "安装服务" })).toBeNull();
    expect(screen.getByRole("button", { name: /打开账号菜单/ })).toBeTruthy();
    expect(screen.getByRole("status").textContent).toContain("服务实例");
    await act(async () => resolve(snapshot));
    expect(screen.getByLabelText("全局导航")).toBe(header);
    expect(screen.getByRole("navigation", { name: "控制台导航" })).toBe(menu);
    expect(screen.getByRole("heading", { name: "服务实例" })).toBe(title);
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

  it("labels the application preview as a local fixture rather than a server or authorization result", async () => {
    await renderConsole({ section: "applications", experience: previewExperienceSnapshot });

    expect(screen.getByRole("heading", { level: 2, name: "应用目录" })).toBeTruthy();
    expect(screen.getByText("隔离 MOCK")).toBeTruthy();
    expect(screen.getByText(/本地导航 fixture.*不是服务端列表或授权结果/)).toBeTruthy();
    expect(screen.getByText(/提前验收真实目录的信息层级.*不代表当前身份已通过服务端授权/)).toBeTruthy();
    expect(screen.getByRole("table", { name: "当前身份可见的应用目录" })).toBeTruthy();
    expect(screen.getByRole("link", { name: /结算 API/ }).getAttribute("href")).toContain("resource=app-checkout-api");
    expect(screen.queryByRole("searchbox")).toBeNull();
  });

  it("does not misrepresent an unavailable LIVE Application directory as a successful empty list", async () => {
    await renderConsole({ section: "applications" });

    expect(screen.getByRole("heading", { level: 2, name: "应用目录" })).toBeTruthy();
    expect(await screen.findByRole("heading", { level: 3, name: "暂时不可用" })).toBeTruthy();
    expect(screen.getByText(/不会展示旧数据或体验 MOCK/)).toBeTruthy();
    expect(screen.queryByRole("table", { name: "当前身份可见的应用目录" })).toBeNull();
    expect(screen.queryByRole("searchbox", { name: "搜索资源" })).toBeNull();
    expect(screen.queryByText("结算 API")).toBeNull();
  });

  it("keeps the LIVE Application directory frame and fixed table labels stable while data is pending", async () => {
    const listApplications = vi.fn(() => new Promise<ApplicationDirectoryPage>(() => {}));
    await renderConsole({ section: "applications", listApplications });

    expect(screen.getByRole("heading", { level: 1, name: "应用托管" })).toBeTruthy();
    expect(screen.getByRole("heading", { level: 2, name: "应用目录" })).toBeTruthy();
    const table = screen.getByRole("table", { name: "当前身份可见的应用目录" });
    expect(table.getAttribute("aria-busy")).toBe("true");
    expect(within(table).getByRole("columnheader", { name: "应用" })).toBeTruthy();
    expect(within(table).getByRole("columnheader", { name: "资源版本" })).toBeTruthy();
    expect(within(table).getByRole("status").textContent).toContain("正在读取当前授权窗口");
    expect(screen.getByText(/每个窗口最多扫描 50 个候选/)).toBeTruthy();
    expect(screen.queryByRole("searchbox")).toBeNull();
  });

  it("renders the strict LIVE Application directory without inventing totals, search or page size", async () => {
    const listApplications = vi.fn().mockResolvedValue(liveApplicationDirectoryPage);
    await renderConsole({ section: "applications", listApplications });

    const resourceLink = await screen.findByRole("link", { name: "live-checkout" });
    const table = screen.getByRole("table", { name: "当前身份可见的应用目录" });
    expect(resourceLink.getAttribute("href")).toBe("/console/applications/?resource=app-live-checkout");
    expect(within(table).getByText("app-live-checkout")).toBeTruthy();
    expect(within(table).getByText("v7")).toBeTruthy();
    expect(screen.getByText("第 1 个授权窗口")).toBeTruthy();
    expect(screen.getByText(/不包含总数、页大小或权限/)).toBeTruthy();
    expect(screen.queryByRole("searchbox")).toBeNull();
    expect(screen.queryByRole("combobox")).toBeNull();
    expect(listApplications).toHaveBeenCalledWith("renderer-test-memory-only-session", undefined);
  });

  it("continues through an empty authorized window and re-authorizes previous windows", async () => {
    const nextAfter = "pc1.Next_window-123";
    const emptyWindow: ApplicationDirectoryPage = { items: [], nextAfter };
    const listApplications = vi.fn()
      .mockResolvedValueOnce(emptyWindow)
      .mockResolvedValueOnce(liveApplicationDirectoryPage)
      .mockResolvedValueOnce(emptyWindow);
    const { user } = await renderConsole({ section: "applications", listApplications });

    expect(await screen.findByText("当前窗口没有可见应用")).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "下一个授权窗口" }));
    expect(await screen.findByRole("link", { name: "live-checkout" })).toBeTruthy();
    expect(listApplications).toHaveBeenNthCalledWith(2, "renderer-test-memory-only-session", nextAfter);

    await user.click(screen.getByRole("button", { name: "上一个授权窗口" }));
    expect(await screen.findByText("当前窗口没有可见应用")).toBeTruthy();
    expect(listApplications).toHaveBeenNthCalledWith(3, "renderer-test-memory-only-session", undefined);
  });

  it("discards Application cursor and tenant history when the authenticated reader changes", async () => {
    const nextAfter = "pc1.First_identity_next";
    const listApplications = vi.fn()
      .mockResolvedValueOnce({ items: [], nextAfter } satisfies ApplicationDirectoryPage)
      .mockResolvedValueOnce(liveApplicationDirectoryPage);
    const { user, repository, replaceRepository } = await renderConsole({ section: "applications", listApplications });

    await user.click(await screen.findByRole("button", { name: "下一个授权窗口" }));
    expect(await screen.findByRole("link", { name: "live-checkout" })).toBeTruthy();
    expect(screen.getByText("第 2 个授权窗口")).toBeTruthy();

    const secondIdentityPage: ApplicationDirectoryPage = {
      items: [{
        ...liveApplicationReadSnapshot.application,
        metadata: {
          ...liveApplicationReadSnapshot.application.metadata,
          id: "app-second-identity",
          name: "second-identity",
          scope: { kind: "TENANT", tenantId: "organization-second" }
        }
      }],
      nextAfter: null
    };
    const secondList = vi.fn().mockResolvedValue(secondIdentityPage);
    act(() => replaceRepository({ ...repository, listApplications: secondList }));

    expect(await screen.findByRole("link", { name: "second-identity" })).toBeTruthy();
    expect(screen.getByText("第 1 个授权窗口")).toBeTruthy();
    expect(secondList).toHaveBeenCalledTimes(1);
    expect(secondList).toHaveBeenCalledWith("renderer-test-memory-only-session", undefined);
  });

  it("does not leak MOCK rows when the LIVE Application directory is forbidden", async () => {
    const listApplications = vi.fn().mockRejectedValue(new HttpProblem(403, "PERMISSION_DENIED"));
    await renderConsole({ section: "applications", listApplications });

    expect(await screen.findByRole("heading", { level: 3, name: "无权列出" })).toBeTruthy();
    expect(screen.getByText(/不会确认目录中是否存在资源.*不会回退到体验 MOCK/)).toBeTruthy();
    expect(screen.queryByText("结算 API")).toBeNull();
    expect(screen.queryByRole("table", { name: "当前身份可见的应用目录" })).toBeNull();
  });

  it("keeps a LIVE Application frame stable while the exact product read is pending", async () => {
    navigation.query = "resource=app-live-checkout";
    let resolveRead!: (value: ApplicationReadSnapshot) => void;
    const readApplication = vi.fn(() => new Promise<ApplicationReadSnapshot>((resolve) => { resolveRead = resolve; }));
    await renderConsole({ section: "applications", readApplication });

    expect(screen.getByRole("heading", { level: 1, name: "应用托管" })).toBeTruthy();
    expect(screen.getByRole("heading", { level: 2, name: "应用详情" })).toBeTruthy();
    expect(screen.getByRole("link", { name: "返回应用" })).toBeTruthy();
    expect(screen.getByText("app-live-checkout")).toBeTruthy();
    expect(screen.getByRole("status").textContent).toContain("正在读取这个应用");
    expect(screen.queryByText("organization-test")).toBeNull();
    expect(screen.queryByRole("dialog")).toBeNull();

    await act(async () => resolveRead(liveApplicationReadSnapshot));

    expect(screen.getByRole("heading", { level: 2, name: "live-checkout" })).toBeTruthy();
    expect(screen.getByText("organization-test")).toBeTruthy();
    expect(screen.getByText('"7"')).toBeTruthy();
    expect(screen.queryByRole("heading", { name: "部署与版本" })).toBeNull();
    expect(screen.queryByRole("button", { name: "管理标签" })).toBeNull();
    expect(readApplication).toHaveBeenCalledWith("renderer-test-memory-only-session", "app-live-checkout");
  });

  it("hides exact Application data from the previous authenticated reader before re-reading", async () => {
    navigation.query = "resource=app-live-checkout";
    const readApplication = vi.fn().mockResolvedValue(liveApplicationReadSnapshot);
    const { repository, replaceRepository } = await renderConsole({ section: "applications", readApplication });

    expect(await screen.findByRole("heading", { level: 2, name: "live-checkout" })).toBeTruthy();
    expect(screen.getByText("organization-test")).toBeTruthy();

    let resolveSecond!: (value: ApplicationReadSnapshot) => void;
    const secondRead = vi.fn(() => new Promise<ApplicationReadSnapshot>((resolve) => { resolveSecond = resolve; }));
    act(() => replaceRepository({ ...repository, readApplication: secondRead }));

    expect(screen.getByRole("heading", { level: 2, name: "应用详情" })).toBeTruthy();
    expect(screen.getByRole("status").textContent).toContain("正在读取这个应用");
    expect(screen.queryByText("organization-test")).toBeNull();
    expect(screen.queryByText('"7"')).toBeNull();
    expect(secondRead).toHaveBeenCalledWith("renderer-test-memory-only-session", "app-live-checkout");

    await act(async () => resolveSecond({
      etag: '"8"',
      application: {
        ...liveApplicationReadSnapshot.application,
        metadata: {
          ...liveApplicationReadSnapshot.application.metadata,
          name: "second-reader",
          scope: { kind: "TENANT", tenantId: "organization-second" },
          resourceVersion: 8
        }
      }
    }));

    expect(screen.getByRole("heading", { level: 2, name: "second-reader" })).toBeTruthy();
    expect(screen.getByText("organization-second")).toBeTruthy();
    expect(screen.getByText('"8"')).toBeTruthy();
  });

  it("does not leak LIVE Application metadata or management actions after a forbidden read", async () => {
    navigation.query = "resource=app-live-checkout";
    const readApplication = vi.fn().mockRejectedValue(new HttpProblem(403, "APPLICATION_READ_FORBIDDEN"));
    await renderConsole({ section: "applications", readApplication });

    expect(await screen.findByText(/页面不确认目标是否存在/)).toBeTruthy();
    expect(screen.getByRole("heading", { level: 2, name: "应用详情" })).toBeTruthy();
    expect(screen.getByText("app-live-checkout")).toBeTruthy();
    expect(screen.queryByText("live-checkout")).toBeNull();
    expect(screen.queryByText("organization-test")).toBeNull();
    expect(screen.queryByRole("heading", { name: "部署与版本" })).toBeNull();
    expect(screen.queryByRole("button", { name: "管理标签" })).toBeNull();
  });

  it("retries the same LIVE Application locator after an unavailable exact read", async () => {
    navigation.query = "resource=app-live-checkout";
    const readApplication = vi.fn()
      .mockRejectedValueOnce(new HttpProblem(503, "AUTHORIZATION_UNAVAILABLE"))
      .mockResolvedValueOnce(liveApplicationReadSnapshot);
    const { user } = await renderConsole({ section: "applications", readApplication });

    expect(await screen.findByText(/不会沿用旧数据或开放管理操作/)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "重新读取" }));

    expect(await screen.findByRole("heading", { level: 2, name: "live-checkout" })).toBeTruthy();
    expect(readApplication).toHaveBeenCalledTimes(2);
    expect(readApplication.mock.calls.every(([, id]) => id === "app-live-checkout")).toBe(true);
  });

  it("rejects an invalid LIVE Application locator locally without making a product request", async () => {
    navigation.query = "resource=app%2Fcheckout";
    const readApplication = vi.fn();
    await renderConsole({ section: "applications", readApplication });

    expect(await screen.findByText(/浏览器没有发起网络请求/)).toBeTruthy();
    expect(screen.getByText("app/checkout")).toBeTruthy();
    expect(readApplication).not.toHaveBeenCalled();
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
    expect(within(directory).getByRole("status").textContent).toBe("11 项服务");
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
    expect(load).toHaveBeenCalledTimes(4);
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

  describe("quota recovery in the original window", () => {
    it.each([false, true])("rereads authoritative quota data after UNKNOWN with read failure=%s and never resubmits activation", async failRead => {
      let serverCommitted = false; let originalRequest = "";
      const recoveredQuota = { ...snapshot.entitlements[0]!, id: "quota-recovered", reservedCount: 0, consumedCount: 0 };
      const activateQuota = vi.fn<ControlPlaneRepository["activateQuota"]>(async (_credential, _command, requestId) => {
        serverCommitted = true; originalRequest = requestId;
        throw new HttpProblem(503, "SYNTHETIC_LOST_RESPONSE");
      });
      const load = vi.fn<ControlPlaneRepository["load"]>(async (_credential, resources) => {
        if (failRead && resources.length === 1 && resources[0] === "entitlements") throw new HttpProblem(503, "SYNTHETIC_READ_FAILURE");
        return { ...snapshot, entitlements: serverCommitted ? [recoveredQuota] : [] };
      });
      const listCommandResults = vi.fn<NonNullable<ControlPlaneRepository["listCommandResults"]>>(async () => [{
        idempotencyKey: originalRequest, commandType: "QUOTA_ACTIVATE", inputDigest: `sha256:${"d".repeat(64)}`,
        state: "SUCCEEDED", target: { kind: "QUOTA_ENTITLEMENT", id: recoveredQuota.id }, operation: null, bindingId: null,
        completedAt: new Date().toISOString()
      }]);
      const { user } = await renderConsole({ section: "quotas", openWorkspace: true, activateQuota, listCommandResults, load });
      const confirm = screen.getByRole("button", { name: "确认激活配额" });
      await user.click(confirm);
      await waitFor(() => expect((confirm as HTMLButtonElement).disabled).toBe(true));
      await user.click(screen.getByRole("button", { name: "检查原请求结果" }));
      await screen.findByText(recoveredQuota.id);
      await waitFor(() => expect(screen.queryByRole("button", { name: "确认激活配额" })).toBeNull());
      expect(!confirm.isConnected || confirm.closest("[inert]")).toBeTruthy();
      expect(activateQuota).toHaveBeenCalledTimes(1);
      expect(listCommandResults).toHaveBeenCalledWith("renderer-test-memory-only-session", "QUOTA_ACTIVATE");
      expect(load).toHaveBeenLastCalledWith("renderer-test-memory-only-session", ["entitlements"]);
      if (failRead) {
        expect(await screen.findByText("托管服务控制面暂时不可用，未展示任何模拟资源。")).toBeTruthy();
        expect(screen.queryByText("尚未激活服务配额")).toBeNull();
        expect(screen.getByRole("main").textContent).not.toContain("已激活1");
      } else {
        await waitFor(() => expect(screen.getByRole("main").textContent).toContain("已激活1"));
        expect(screen.getByRole("main").textContent).toContain("使用中0");
        expect(screen.getByRole("main").textContent).toContain("可用1");
        expect(screen.queryByText("尚未激活服务配额")).toBeNull();
      }
      expect(navigation.replace).not.toHaveBeenCalled();
    });
  });

  describe("role exit from a business route", () => {
    function selfService(overrides: Partial<NonNullable<IamRepository["roleSelfService"]>> = {}): NonNullable<IamRepository["roleSelfService"]> {
      const role = {
        roleId: "role-support-reader", accountId: "organization-test", name: "Signed UI Support Reader", status: "ACTIVE" as const,
        maxSessionDurationSeconds: 3600, resourceVersion: 4,
        capability: { action: "iam.role.assume" as const, resource: { kind: "ROLE" as const, id: "role-support-reader" }, available: true as const, restrictionReason: null }
      };
      const active = {
        id: "role-session-reader", accountId: role.accountId, roleId: role.roleId, sourceUserId: "principal-test", status: "ACTIVE" as const,
        issuedAt: new Date(Date.now() - 30_000).toISOString(), expiresAt: new Date(Date.now() + 3_600_000).toISOString(), revokedAt: null
      };
      const revoked = { ...active, status: "REVOKED" as const, revokedAt: new Date().toISOString() };
      return {
        listAssumable: vi.fn(async () => ({ accountId: role.accountId, sourceUserId: active.sourceUserId, items: [role], nextAfter: null })),
        assume: vi.fn(async () => ({ outcome: "APPLIED" as const, session: active, credential: "synthetic-role-bearer" })),
        readByRequest: vi.fn(async () => active), revokeByRequest: vi.fn(async () => revoked),
        currentIdentity: vi.fn(async () => ({ session: active, account: { id: role.accountId, displayName: "Xiak" }, role: { id: role.roleId, name: role.name }, sourceUser: { id: active.sourceUserId, loginName: "admin", displayName: "Source member" } })),
        logout: vi.fn(async () => revoked), revalidateSource: vi.fn(async () => undefined), ...overrides
      };
    }

    async function enterAudit(service: NonNullable<IamRepository["roleSelfService"]>, roleStatus: 401 | 403 = 403) {
      const fetchAudit = vi.fn(async (path: RequestInfo | URL, init?: RequestInit) => {
        if (String(path) !== "/api/audit/v1/records:query") throw new Error("Unexpected test API request");
        const role = new Headers(init?.headers).get("Authorization") === "Bearer synthetic-role-bearer";
        return new Response(JSON.stringify(role
          ? { code: roleStatus === 401 ? "SESSION_EXPIRED" : "PERMISSION_DENIED" }
          : { apiVersion: AUDIT_API_VERSION, kind: "AuditRecordPage", tenantId: "organization-test", records: [] }), {
          status: role ? roleStatus : 200,
          headers: { "Content-Type": "application/json" }
        });
      });
      vi.stubGlobal("fetch", fetchAudit);
      const sourceLogout = vi.fn(async () => undefined);
      const result = await renderConsole({ section: "access", view: "role-access", roleSelfService: service, logout: sourceLogout });
      await result.user.click(await screen.findByRole("button", { name: "审阅并承担 Signed UI Support Reader" }));
      await result.user.click(screen.getByRole("button", { name: "承担角色" }));
      await screen.findByRole("heading", { name: "当前角色身份" });
      await act(async () => result.commitRoute("/console/audit/"));
      if (roleStatus === 401) await screen.findByRole("button", { name: "验证并返回用户模式" });
      else await screen.findByText("当前身份没有 audit.record.read 或 audit.integrity.verify 权限。");
      navigation.push.mockClear(); navigation.replace.mockClear();
      return { ...result, fetchAudit, sourceLogout };
    }

    it("blocks a rejected Role bearer and restores the User only after explicit source validation", async () => {
      let restoreSource!: () => void;
      const service = selfService({ revalidateSource: vi.fn(() => new Promise<void>(resolve => { restoreSource = resolve; })) });
      const { user, fetchAudit, sourceLogout } = await enterAudit(service, 401);
      expect(fetchAudit).toHaveBeenCalledTimes(1);
      expect(new Headers(fetchAudit.mock.calls[0]![1]?.headers).get("Authorization")).toBe("Bearer synthetic-role-bearer");
      expect(service.assume).toHaveBeenCalledTimes(1);
      expect(service.revalidateSource).not.toHaveBeenCalled();
      expect(sourceLogout).not.toHaveBeenCalled();

      await user.click(screen.getByRole("button", { name: "验证并返回用户模式" }));
      expect(service.revalidateSource).toHaveBeenCalledWith("renderer-test-memory-only-session", "organization-test", "principal-test");
      expect(fetchAudit).toHaveBeenCalledTimes(1);
      await act(async () => restoreSource());

      await waitFor(() => expect(fetchAudit).toHaveBeenCalledTimes(2));
      expect(new Headers(fetchAudit.mock.calls[1]![1]?.headers).get("Authorization")).toBe("Bearer renderer-test-memory-only-session");
      expect(service.assume).toHaveBeenCalledTimes(1);
      expect(navigation.push).not.toHaveBeenCalled();
      expect(navigation.replace).not.toHaveBeenCalled();
      expect(sourceLogout).not.toHaveBeenCalled();
    });

    it("blocks a Role after a protected product read returns 401 without probing as the source User", async () => {
      let restoreSource!: () => void;
      const service = selfService({ revalidateSource: vi.fn(() => new Promise<void>(resolve => { restoreSource = resolve; })) });
      const load = vi.fn<ControlPlaneRepository["load"]>(async (credential) => {
        if (credential === "synthetic-role-bearer") throw new HttpProblem(401, "ROLE_POLICY_CHANGED");
        return snapshot;
      });
      const result = await renderConsole({ section: "access", view: "role-access", roleSelfService: service, load });
      await result.user.click(await screen.findByRole("button", { name: "审阅并承担 Signed UI Support Reader" }));
      await result.user.click(screen.getByRole("button", { name: "承担角色" }));
      await screen.findByRole("heading", { name: "当前角色身份" });
      await act(async () => result.commitRoute("/console/regions/"));

      await screen.findByRole("button", { name: "验证并返回用户模式" });
      expect(load).toHaveBeenCalledTimes(1);
      expect(load.mock.calls[0]![0]).toBe("synthetic-role-bearer");
      expect(service.assume).toHaveBeenCalledTimes(1);
      await result.user.click(screen.getByRole("button", { name: "验证并返回用户模式" }));
      expect(load).toHaveBeenCalledTimes(1);
      await act(async () => restoreSource());

      await waitFor(() => expect(load.mock.calls.some(([credential]) => credential === "renderer-test-memory-only-session")).toBe(true));
      expect(await screen.findByRole("heading", { level: 1, name: "区域与节点" })).toBeTruthy();
      expect(service.assume).toHaveBeenCalledTimes(1);
      expect(navigation.push).not.toHaveBeenCalled();
      expect(navigation.replace).not.toHaveBeenCalled();
    });

    it("ignores a late 401 from a retired Role after the source User has been revalidated", async () => {
      let rejectRoleRead!: (reason: unknown) => void;
      const service = selfService();
      const load = vi.fn<ControlPlaneRepository["load"]>((credential) => credential === "synthetic-role-bearer"
        ? new Promise((_resolve, reject) => { rejectRoleRead = reject; })
        : Promise.resolve(snapshot));
      const result = await renderConsole({ section: "access", view: "role-access", roleSelfService: service, load });
      await result.user.click(await screen.findByRole("button", { name: "审阅并承担 Signed UI Support Reader" }));
      await result.user.click(screen.getByRole("button", { name: "承担角色" }));
      await screen.findByRole("heading", { name: "当前角色身份" });
      await act(async () => result.commitRoute("/console/regions/"));
      await waitFor(() => expect(load.mock.calls.some(([credential]) => credential === "synthetic-role-bearer")).toBe(true));

      await result.user.click(screen.getByRole("button", { name: /打开账号菜单/ }));
      await result.user.click(screen.getByRole("menuitem", { name: "结束当前角色会话" }));
      await waitFor(() => expect(load.mock.calls.some(([credential]) => credential === "renderer-test-memory-only-session")).toBe(true));
      expect(await screen.findByRole("heading", { level: 1, name: "区域与节点" })).toBeTruthy();
      await act(async () => rejectRoleRead(new HttpProblem(401, "STALE_ROLE_POLICY")));

      expect(screen.queryByRole("button", { name: "验证并返回用户模式" })).toBeNull();
      expect(screen.getByRole("heading", { level: 1, name: "区域与节点" })).toBeTruthy();
      await result.user.click(screen.getByRole("button", { name: /打开账号菜单/ }));
      expect(within(screen.getByRole("dialog", { name: "账号菜单" })).getByText("admin", { exact: true })).toBeTruthy();
      expect(service.assume).toHaveBeenCalledTimes(1);
    });

    it("restores the same Audit route with the User bearer only after source validation", async () => {
      let restoreSource!: () => void;
      const service = selfService({ revalidateSource: vi.fn(() => new Promise<void>(resolve => { restoreSource = resolve; })) });
      const { user, fetchAudit, sourceLogout } = await enterAudit(service);
      await user.click(screen.getByRole("button", { name: /打开账号菜单/ }));
      await user.click(screen.getByRole("menuitem", { name: "结束当前角色会话" }));
      await screen.findByText("来源用户仍需重新验证");
      const restore = screen.getByRole("button", { name: "重新验证来源用户" });
      expect((restore as HTMLButtonElement).disabled).toBe(true);
      expect(screen.queryByText(/IAM 会话已失效/)).toBeNull();
      expect(fetchAudit).toHaveBeenCalledTimes(1);
      await user.click(restore);
      expect(service.revalidateSource).toHaveBeenCalledTimes(1);
      await act(async () => restoreSource());
      await waitFor(() => expect(fetchAudit).toHaveBeenCalledTimes(2));
      expect(new Headers(fetchAudit.mock.calls[1]![1]?.headers).get("Authorization")).toBe("Bearer renderer-test-memory-only-session");
      expect(await screen.findByRole("heading", { level: 1, name: "审计记录" })).toBeTruthy();
      await waitFor(() => expect(screen.queryByText("无法读取审计记录")).toBeNull());
      expect(screen.queryByText(/IAM 会话已失效/)).toBeNull();
      expect(screen.queryByText("Signed UI Support Reader")).toBeNull();
      await user.click(screen.getByRole("button", { name: /打开账号菜单/ }));
      expect(within(screen.getByRole("dialog", { name: "账号菜单" })).getByText("admin", { exact: true })).toBeTruthy();
      expect(navigation.push).not.toHaveBeenCalled(); expect(navigation.replace).not.toHaveBeenCalled();
      expect(sourceLogout).not.toHaveBeenCalled();
    });

    it("drops Role-owned Audit filters when exit and source validation settle immediately", async () => {
      const { user, fetchAudit } = await enterAudit(selfService());
      await user.click(screen.getByRole("button", { name: "查询条件" }));
      // Prepare the fixed criterion; this case owns query/Role-exit semantics.
      fireEvent.change(screen.getByLabelText("操作者 ID", { exact: true }), { target: { value: "role-owned-filter" } });
      await user.click(screen.getByRole("button", { name: "查询" }));
      await waitFor(() => expect(fetchAudit).toHaveBeenCalledTimes(2));
      expect(JSON.parse(String(fetchAudit.mock.calls[1]![1]?.body)).actor).toEqual({ type: "USER", id: "role-owned-filter" });
      await user.click(screen.getByRole("button", { name: /打开账号菜单/ }));
      await user.click(screen.getByRole("menuitem", { name: "结束当前角色会话" }));
      await waitFor(() => expect(fetchAudit.mock.calls.some(([, init]) => new Headers(init?.headers).get("Authorization") === "Bearer renderer-test-memory-only-session")).toBe(true));
      const sourceReads = fetchAudit.mock.calls.filter(([, init]) => new Headers(init?.headers).get("Authorization") === "Bearer renderer-test-memory-only-session");
      expect(JSON.parse(String(sourceReads[0]![1]?.body)).actor).toBeUndefined();
      expect(JSON.parse(String(sourceReads[0]![1]?.body)).cursor).toBeUndefined();
      expect(await screen.findByRole("heading", { level: 1, name: "审计记录" })).toBeTruthy();
      expect(screen.queryByText(/IAM 会话已失效/)).toBeNull();
    });

    it.each(["source-unavailable", "logout-unknown"] as const)("keeps %s in the role recovery surface without navigation or source logout", async (failure) => {
      const service = selfService(failure === "source-unavailable"
        ? { revalidateSource: vi.fn(async () => { throw new HttpProblem(503, "IAM_UNAVAILABLE"); }) }
        : { logout: vi.fn(async () => { throw new Error("Synthetic lost logout response"); }) });
      const { user, fetchAudit, sourceLogout } = await enterAudit(service);
      await user.click(screen.getByRole("button", { name: /打开账号菜单/ }));
      await user.click(screen.getByRole("menuitem", { name: "结束当前角色会话" }));
      expect(await screen.findByText(failure === "source-unavailable" ? "来源用户仍需重新验证" : "角色退出结果尚未确认")).toBeTruthy();
      await waitFor(() => expect((screen.getByRole("button", { name: failure === "source-unavailable" ? "重新验证来源用户" : "重试同一退出" }) as HTMLButtonElement).disabled).toBe(false));
      expect(fetchAudit).toHaveBeenCalledTimes(1);
      expect(screen.queryByText(/IAM 会话已失效/)).toBeNull();
      expect(navigation.push).not.toHaveBeenCalled(); expect(navigation.replace).not.toHaveBeenCalled();
      expect(sourceLogout).not.toHaveBeenCalled();
      expect(service.logout).toHaveBeenCalledTimes(1);
    });
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

  it("expires the exact current User after a protected resource read returns 401", async () => {
    const load = vi.fn().mockRejectedValue(new HttpProblem(401, "SESSION_REVOKED"));
    const logout = vi.fn().mockResolvedValue(undefined);
    await renderConsole({ load, logout });
    await screen.findByRole("button", { name: "登录控制台" });
    expect(load).toHaveBeenCalledWith("renderer-test-memory-only-session", expect.any(Array));
    expect(logout).not.toHaveBeenCalled();
    expect(navigation.replace).not.toHaveBeenCalled();
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
