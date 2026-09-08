import type {
  ExperienceAlert,
  ExperienceOperation,
  ExperiencePipeline,
  ExperienceProduct,
  ExperienceResource,
  ExperienceServiceHealth,
  ExperienceSnapshot
} from "../domain/experience";
import type {
  ControlPlaneSnapshot,
  QuotaShape,
  ServiceInstallation
} from "../domain/resources";
import type { ConsoleSection } from "../domain/selection";
import type {
  AlertScene,
  ConsoleContentScene,
  ConsoleNavigationItemScene,
  ConsoleScene,
  EntitlementScene,
  ExperienceProductScene,
  GlobalSearchResultScene,
  InstallationScene,
  OfferingScene,
  OperationScene,
  PipelineScene,
  RegionScene,
  SceneStatus,
  ServiceHealthScene,
  UnifiedResourceScene
} from "./consoleScene";

const sectionCopy: Record<ConsoleSection, {
  title: string;
  eyebrow: string;
  description: string;
}> = {
  overview: {
    title: "控制面概览",
    eyebrow: "Platform overview",
    description: "查看真实服务目录、组织配额、安装任务与本机区域状态。"
  },
  products: {
    title: "产品与服务",
    eyebrow: "Products and services",
    description: "按工作场景发现云基础平台、PaaS、DevOps 与可观测能力。"
  },
  resources: {
    title: "资源中心",
    eyebrow: "Resource center",
    description: "跨产品、项目与区域查找资源，并回到所属产品继续操作。"
  },
  operations: {
    title: "操作与任务",
    eyebrow: "Activity center",
    description: "集中追踪创建、发布、扩容与基础设施变更的执行状态。"
  },
  catalog: {
    title: "服务目录",
    eyebrow: "Managed service catalog",
    description: "选择平台已验证并由发布制品固定的数据服务。"
  },
  quotas: {
    title: "服务配额",
    eyebrow: "Quota entitlements",
    description: "激活有限的服务额度，并追踪已保留和已使用数量。"
  },
  installations: {
    title: "服务实例",
    eyebrow: "Service installations",
    description: "将已激活的 PostgreSQL 配额安装到一个就绪区域。"
  },
  regions: {
    title: "区域与基础设施",
    eyebrow: "Cloud foundation",
    description: "查看私有云区域的计算、存储容量与最近一次能力检查。"
  },
  devops: {
    title: "研发效能",
    eyebrow: "DevOps delivery",
    description: "从代码提交到多环境发布，持续掌握交付速度与质量。"
  },
  observability: {
    title: "可观测平台",
    eyebrow: "Observability",
    description: "在统一上下文中关联服务健康、关键指标与当前告警。"
  },
  access: {
    title: "访问管理",
    eyebrow: "Identity and access",
    description: "管理当前租户的子账号、角色与主账号专属别名。"
  }
};

function dateTime(value: string | null): string {
  if (!value) return "尚未检查";
  const parsed = new Date(value);
  if (Number.isNaN(parsed.valueOf())) return "未知时间";
  return new Intl.DateTimeFormat("zh-CN", {
    dateStyle: "medium",
    timeStyle: "short"
  }).format(parsed);
}

function shapeSummary(shape: QuotaShape): string {
  const cpu = shape.cpuMillicores % 1000 === 0
    ? `${shape.cpuMillicores / 1000} vCPU`
    : `${shape.cpuMillicores}m CPU`;
  return `${cpu} · ${shape.memoryMiB} MiB · ${shape.storageGiB} GiB`;
}

function offeringScenes(snapshot: ControlPlaneSnapshot): OfferingScene[] {
  return snapshot.offerings.map((offering) => ({
    id: offering.id,
    name: offering.displayName,
    description: offering.description,
    engine: offering.engineFamily,
    version: offering.engineVersion,
    available: offering.state === "AVAILABLE",
    shapeCount: offering.quotaShapes.length,
    shapeSummary: offering.quotaShapes.map((shape) => shape.displayName).join(" · ")
  }));
}

function installationStatus(phase: ServiceInstallation["phase"]): SceneStatus {
  if (phase === "READY") return "success";
  if (phase === "FAILED") return "danger";
  if (phase === "PROVISIONING") return "info";
  return "warning";
}

function installationScenes(snapshot: ControlPlaneSnapshot): InstallationScene[] {
  const offerings = new Map(snapshot.offerings.map((item) => [item.id, item]));
  const regions = new Map(snapshot.regions.map((item) => [item.id, item]));
  return snapshot.installations.map((installation) => {
    const offering = offerings.get(installation.offeringId);
    return {
      id: installation.id,
      name: installation.name,
      engine: `${offering?.engineFamily ?? "Managed service"} ${installation.engineVersion}`,
      regionName: regions.get(installation.regionId)?.displayName ?? installation.regionId,
      phase: installation.phase,
      status: installationStatus(installation.phase),
      endpoint: installation.endpoint,
      operationId: installation.operation.id,
      observedAt: dateTime(installation.operation.observedAt)
    };
  });
}

function entitlementScenes(snapshot: ControlPlaneSnapshot): EntitlementScene[] {
  const offerings = new Map(snapshot.offerings.map((item) => [item.id, item]));
  return snapshot.entitlements.map((entitlement) => {
    const offering = offerings.get(entitlement.offeringId);
    const shape = offering?.quotaShapes.find((item) => item.id === entitlement.quotaShapeId);
    return {
      id: entitlement.id,
      offeringName: offering?.displayName ?? entitlement.offeringId,
      shapeName: shape?.displayName ?? entitlement.quotaShapeId,
      resourceSummary: shape ? shapeSummary(shape) : "资源规格不可用",
      purchased: entitlement.purchasedCount,
      inUse: entitlement.reservedCount + entitlement.consumedCount,
      available: Math.max(0, entitlement.purchasedCount - entitlement.reservedCount - entitlement.consumedCount),
      activatedAt: dateTime(entitlement.activatedAt)
    };
  });
}

function regionScenes(snapshot: ControlPlaneSnapshot): RegionScene[] {
  return snapshot.regions.map((region) => ({
    id: region.id,
    name: region.displayName,
    profile: "本机受管区域",
    state: region.state,
    status: region.state === "READY" ? "success" : region.state === "STALE" ? "warning" : "danger",
    capacity: `${region.capacity.cpuMillicores / 1000} vCPU · ${region.capacity.memoryMiB} MiB · ${region.capacity.storageGiB} GiB`,
    inspectedAt: dateTime(region.inspectedAt)
  }));
}

function productStatus(product: ExperienceProduct): Pick<ExperienceProductScene, "status" | "statusLabel"> {
  if (product.availability === "AVAILABLE") return { status: "success", statusLabel: "可用" };
  if (product.availability === "PREVIEW") return { status: "info", statusLabel: "体验中" };
  return { status: "neutral", statusLabel: "规划中" };
}

function productScenes(experience?: ExperienceSnapshot): ExperienceProductScene[] {
  return experience?.products.map((product) => ({
    id: product.id,
    name: product.name,
    eyebrow: product.eyebrow,
    description: product.description,
    href: product.href,
    icon: product.id,
    ...productStatus(product),
    resourceCount: product.resourceCount,
    capabilities: product.capabilities
  })) ?? [];
}

function resourceStatus(resource: ExperienceResource): Pick<UnifiedResourceScene, "status" | "stateLabel"> {
  if (resource.state === "HEALTHY") return { status: "success", stateLabel: "健康" };
  if (resource.state === "RUNNING") return { status: "info", stateLabel: "运行中" };
  if (resource.state === "DEGRADED") return { status: "warning", stateLabel: "需关注" };
  return { status: "danger", stateLabel: "异常" };
}

function resourceScenes(experience?: ExperienceSnapshot): UnifiedResourceScene[] {
  return experience?.resources.map((resource) => ({ ...resource, ...resourceStatus(resource) })) ?? [];
}

function operationStatus(operation: ExperienceOperation): Pick<OperationScene, "status" | "stateLabel"> {
  if (operation.state === "SUCCEEDED") return { status: "success", stateLabel: "已完成" };
  if (operation.state === "RUNNING") return { status: "info", stateLabel: "执行中" };
  return { status: "danger", stateLabel: "失败" };
}

function operationScenes(experience?: ExperienceSnapshot): OperationScene[] {
  return experience?.operations.map((operation) => ({ ...operation, ...operationStatus(operation) })) ?? [];
}

function pipelineScenes(experience?: ExperienceSnapshot): PipelineScene[] {
  return experience?.pipelines.map((pipeline: ExperiencePipeline) => ({
    ...pipeline,
    ...operationStatus({ ...pipeline, action: "", target: "", productName: "", actor: "", progress: 0, startedAt: pipeline.triggeredAt })
  })) ?? [];
}

function serviceStatus(service: ExperienceServiceHealth): Pick<ServiceHealthScene, "status" | "stateLabel"> {
  if (service.state === "HEALTHY") return { status: "success", stateLabel: "健康" };
  if (service.state === "DEGRADED") return { status: "warning", stateLabel: "性能下降" };
  if (service.state === "RUNNING") return { status: "info", stateLabel: "运行中" };
  return { status: "danger", stateLabel: "异常" };
}

function serviceHealthScenes(experience?: ExperienceSnapshot): ServiceHealthScene[] {
  return experience?.serviceHealth.map((service) => ({ ...service, ...serviceStatus(service) })) ?? [];
}

function alertStatus(alert: ExperienceAlert): Pick<AlertScene, "status" | "severityLabel" | "stateLabel"> {
  const severity = alert.severity === "CRITICAL" ? { status: "danger" as const, severityLabel: "严重" }
    : alert.severity === "WARNING" ? { status: "warning" as const, severityLabel: "警告" }
      : { status: "info" as const, severityLabel: "提示" };
  return { ...severity, stateLabel: alert.state === "FIRING" ? "触发中" : "已确认" };
}

function alertScenes(experience?: ExperienceSnapshot): AlertScene[] {
  return experience?.alerts.map((alert) => ({ ...alert, ...alertStatus(alert) })) ?? [];
}

function isHomeSection(section: ConsoleSection): boolean {
  return ["overview", "products", "resources", "operations"].includes(section);
}

function isPaaSSection(section: ConsoleSection): boolean {
  return ["catalog", "quotas", "installations"].includes(section);
}

function navigation(
  section: ConsoleSection,
  snapshot?: ControlPlaneSnapshot,
  experience?: ExperienceSnapshot
): ConsoleNavigationItemScene[] {
  if (!experience) {
    return [
      { id: "catalog", label: "服务目录", description: "可用产品", href: "/console/catalog/", icon: "catalog", selected: section === "catalog", count: snapshot?.offerings.length },
      { id: "quotas", label: "服务配额", description: "组织额度", href: "/console/quotas/", icon: "quota", selected: section === "quotas", count: snapshot?.entitlements.length },
      { id: "installations", label: "服务实例", description: "安装与运行", href: "/console/installations/", icon: "installation", selected: section === "installations", count: snapshot?.installations.length },
      { id: "regions", label: "区域配置", description: "薄 IaaS 能力", href: "/console/regions/", icon: "region", selected: section === "regions", count: snapshot?.regions.length },
      { id: "access", label: "访问管理", description: "账号与权限", href: "/console/access/", icon: "access", selected: section === "access" }
    ];
  }
  if (isHomeSection(section)) {
    return [
      { id: "overview", label: "总览", description: "平台状态", href: "/console/", icon: "overview", selected: section === "overview" },
      { id: "products", label: "产品与服务", description: "发现云能力", href: "/console/products/", icon: "products", selected: section === "products", count: experience.products.length },
      { id: "resources", label: "资源中心", description: "跨产品查找", href: "/console/resources/", icon: "resources", selected: section === "resources", count: experience.resources.length },
      { id: "operations", label: "操作与任务", description: "异步进度", href: "/console/operations/", icon: "operations", selected: section === "operations", count: experience.operations.filter((item) => item.state === "RUNNING").length }
    ];
  }
  if (isPaaSSection(section)) {
    return [
      { id: "catalog", label: "服务目录", description: "托管产品", href: "/console/catalog/", icon: "catalog", selected: section === "catalog", count: snapshot?.offerings.length },
      { id: "quotas", label: "服务配额", description: "组织额度", href: "/console/quotas/", icon: "quota", selected: section === "quotas", count: snapshot?.entitlements.length },
      { id: "installations", label: "服务实例", description: "安装与运行", href: "/console/installations/", icon: "installation", selected: section === "installations", count: snapshot?.installations.length }
    ];
  }
  if (section === "regions") {
    return [{ id: "regions", label: "区域与节点", description: "容量与就绪状态", href: "/console/regions/", icon: "region", selected: true, count: snapshot?.regions.length }];
  }
  if (section === "devops") {
    return [{ id: "devops", label: "交付总览", description: "流水线与环境", href: "/console/devops/", icon: "pipeline", selected: true, count: experience.pipelines.length }];
  }
  if (section === "observability") {
    return [{ id: "observability", label: "服务健康", description: "指标与告警", href: "/console/observability/", icon: "observability", selected: true, count: experience.alerts.filter((item) => item.state === "FIRING").length }];
  }
  return [{ id: "access", label: "账号与权限", description: "IAM 与角色", href: "/console/access/", icon: "access", selected: true }];
}

function productRail(section: ConsoleSection, experience?: ExperienceSnapshot): ConsoleScene["rail"] {
  if (!experience) {
    return [
      { id: "overview", label: "控制面概览", href: "/console/", icon: "overview", selected: section === "overview" },
      { id: "managed-database", label: "托管数据库", href: "/console/catalog/", icon: "database", selected: section !== "overview" && section !== "access" },
      { id: "access", label: "访问管理", href: "/console/access/", icon: "access", selected: section === "access" }
    ];
  }
  return [
    { id: "home", label: "控制台首页", href: "/console/", icon: "overview", selected: isHomeSection(section) },
    { id: "foundation", label: "云基础平台", href: "/console/regions/", icon: "overview", selected: section === "regions" },
    { id: "paas", label: "应用与数据服务", href: "/console/catalog/", icon: "database", selected: isPaaSSection(section) },
    { id: "devops", label: "研发效能", href: "/console/devops/", icon: "devops", selected: section === "devops" },
    { id: "observability", label: "可观测平台", href: "/console/observability/", icon: "observability", selected: section === "observability" },
    { id: "access", label: "安全与访问", href: "/console/access/", icon: "access", selected: section === "access" }
  ];
}

function productContext(section: ConsoleSection, experience?: ExperienceSnapshot): Pick<ConsoleScene, "productName" | "productEyebrow" | "productIcon"> {
  if (!experience) {
    return section === "access"
      ? { productName: "访问管理", productEyebrow: "Identity and access", productIcon: "access" }
      : { productName: "托管数据库", productEyebrow: "Managed services", productIcon: "database" };
  }
  if (isHomeSection(section)) return { productName: "云控制台", productEyebrow: "Unified cloud", productIcon: "overview" };
  if (section === "regions") return { productName: "云基础平台", productEyebrow: "Cloud foundation", productIcon: "overview" };
  if (isPaaSSection(section)) return { productName: "应用与数据服务", productEyebrow: "PaaS", productIcon: "database" };
  if (section === "devops") return { productName: "研发效能", productEyebrow: "DevOps", productIcon: "devops" };
  if (section === "observability") return { productName: "可观测平台", productEyebrow: "Observability", productIcon: "observability" };
  return { productName: "安全与访问", productEyebrow: "Security & IAM", productIcon: "access" };
}

function globalSearch(experience?: ExperienceSnapshot): GlobalSearchResultScene[] {
  if (!experience) return [];
  const pages: GlobalSearchResultScene[] = [
    { id: "page-products", label: "产品与服务", description: "浏览全部云能力", href: "/console/products/", category: "页面", icon: "foundation" },
    { id: "page-resources", label: "资源中心", description: "跨产品与区域检索", href: "/console/resources/", category: "页面", icon: "foundation" },
    { id: "page-operations", label: "操作与任务", description: "查看异步任务进度", href: "/console/operations/", category: "页面", icon: "foundation" }
  ];
  return [
    ...pages,
    ...productScenes(experience).map((product) => ({
      id: `product-${product.id}`,
      label: product.name,
      description: product.description,
      href: product.href,
      category: "产品" as const,
      icon: product.icon
    })),
    ...resourceScenes(experience).map((resource) => ({
      id: `resource-${resource.id}`,
      label: resource.name,
      description: `${resource.kind} · ${resource.projectName} · ${resource.regionName}`,
      href: resource.href,
      category: "资源" as const,
      icon: resource.productId as GlobalSearchResultScene["icon"]
    }))
  ];
}

function baseScene(section: ConsoleSection, experience?: ExperienceSnapshot): Omit<ConsoleScene, "content" | "workspace" | "navigation"> {
  const copy = experience && section === "overview"
    ? {
        title: "云控制台",
        eyebrow: "Cloud overview",
        description: "从组织全局视角掌握资源、交付任务与运行风险。"
      }
    : sectionCopy[section];
  return {
    section,
    ...copy,
    ...productContext(section, experience),
    preview: Boolean(experience),
    scope: experience ? {
      organization: experience.organization,
      projects: experience.projects,
      regions: experience.regions
    } : null,
    search: globalSearch(experience),
    noticeCount: experience?.alerts.filter((item) => item.state === "FIRING").length ?? 0,
    notices: alertScenes(experience),
    activeOperationCount: experience?.operations.filter((item) => item.state === "RUNNING").length ?? 0,
    rail: productRail(section, experience)
  };
}

// IAM navigation must remain available without permission to read PaaS resources.
export function buildAccessConsoleScene(experience?: ExperienceSnapshot): ConsoleScene {
  return {
    ...baseScene("access", experience),
    navigation: navigation("access", undefined, experience),
    content: { kind: "access" },
    workspace: null
  };
}

function legacyContent(section: ConsoleSection, snapshot: ControlPlaneSnapshot): ConsoleContentScene {
  const offerings = offeringScenes(snapshot);
  const installations = installationScenes(snapshot);
  if (section === "catalog") return { kind: "catalog", offerings };
  if (section === "quotas") return { kind: "quotas", entitlements: entitlementScenes(snapshot) };
  if (section === "installations") return { kind: "installations", installations };
  if (section === "regions") return { kind: "regions", regions: regionScenes(snapshot) };
  if (section === "products") return { kind: "products", products: [] };
  if (section === "resources") return { kind: "resources", resources: [] };
  if (section === "operations") return { kind: "operations", operations: [] };
  if (section === "devops") return { kind: "devops", metrics: [], pipelines: [] };
  if (section === "observability") return { kind: "observability", metrics: [], services: [], alerts: [] };

  const ready = snapshot.installations.filter((item) => item.phase === "READY").length;
  const active = snapshot.installations.filter((item) => item.phase === "PENDING" || item.phase === "PROVISIONING").length;
  const availableQuota = snapshot.entitlements.reduce(
    (total, item) => total + Math.max(0, item.purchasedCount - item.reservedCount - item.consumedCount),
    0
  );
  return {
    kind: "overview",
    offering: offerings[0] ?? null,
    recentInstallations: installations.slice(0, 5),
    metrics: [
      { id: "offerings", label: "可用产品", value: String(snapshot.offerings.filter((item) => item.state === "AVAILABLE").length), detail: "当前仅开放真实可安装产品", status: "info" },
      { id: "quota", label: "可用配额", value: String(availableQuota), detail: "尚未被保留或消费的实例数", status: availableQuota > 0 ? "success" : "warning" },
      { id: "services", label: "就绪实例", value: String(ready), detail: `${active} 个安装任务处理中`, status: active > 0 ? "info" : "neutral" },
      { id: "regions", label: "就绪区域", value: String(snapshot.regions.filter((item) => item.state === "READY").length), detail: "本机能力由安装器管理", status: snapshot.regions.some((item) => item.state === "READY") ? "success" : "warning" }
    ]
  };
}

function experienceContent(section: ConsoleSection, experience: ExperienceSnapshot): ConsoleContentScene | null {
  const products = productScenes(experience);
  const resources = resourceScenes(experience);
  const operations = operationScenes(experience);
  const alerts = alertScenes(experience);
  if (section === "overview") {
    const healthy = experience.resources.filter((item) => item.state === "HEALTHY" || item.state === "RUNNING").length;
    const firing = experience.alerts.filter((item) => item.state === "FIRING").length;
    const running = experience.operations.filter((item) => item.state === "RUNNING").length;
    return {
      kind: "cloud-overview",
      metrics: [
        { id: "all-resources", label: "云资源", value: String(experience.resources.length), detail: `分布在 ${experience.projects.length - 1} 个项目`, status: "info" },
        { id: "healthy-resources", label: "健康运行", value: String(healthy), detail: "跨产品统一健康视图", status: "success" },
        { id: "active-operations", label: "执行中任务", value: String(running), detail: "创建与发布进度持续可见", status: running > 0 ? "info" : "neutral" },
        { id: "active-alerts", label: "待处理告警", value: String(firing), detail: "需关注当前服务风险", status: firing > 0 ? "warning" : "success" }
      ],
      products,
      recentResources: resources.slice(0, 5),
      operations: operations.slice(0, 3),
      alerts: alerts.filter((item) => item.stateLabel === "触发中").slice(0, 2)
    };
  }
  if (section === "products") return { kind: "products", products };
  if (section === "resources") return { kind: "resources", resources };
  if (section === "operations") return { kind: "operations", operations };
  if (section === "devops") {
    const successful = experience.pipelines.filter((item) => item.state === "SUCCEEDED").length;
    const running = experience.pipelines.filter((item) => item.state === "RUNNING").length;
    return {
      kind: "devops",
      metrics: [
        { id: "pipeline-success", label: "近 24h 成功率", value: "94.6%", detail: `${successful} 条最近流水线成功`, status: "success" },
        { id: "pipeline-running", label: "执行中", value: String(running), detail: "构建、验证与发布阶段", status: running > 0 ? "info" : "neutral" },
        { id: "lead-time", label: "平均交付前置时间", value: "18m", detail: "较上周缩短 12%", status: "success" },
        { id: "deployment-frequency", label: "今日发布", value: "12", detail: "生产 4 次 · 测试 8 次", status: "info" }
      ],
      pipelines: pipelineScenes(experience)
    };
  }
  if (section === "observability") {
    const degraded = experience.serviceHealth.filter((item) => item.state === "DEGRADED" || item.state === "FAILED").length;
    return {
      kind: "observability",
      metrics: [
        { id: "service-health", label: "受监控服务", value: String(experience.serviceHealth.length), detail: `${degraded} 个服务需要关注`, status: degraded > 0 ? "warning" : "success" },
        { id: "availability", label: "平台可用性", value: "99.94%", detail: "过去 30 天综合 SLI", status: "success" },
        { id: "alert-firing", label: "触发中告警", value: String(experience.alerts.filter((item) => item.state === "FIRING").length), detail: "按服务与负责人聚合", status: "warning" },
        { id: "ingestion", label: "日志写入", value: "1.8 GB/h", detail: "当前采集链路正常", status: "info" }
      ],
      services: serviceHealthScenes(experience),
      alerts
    };
  }
  return null;
}

export function buildConsoleScene(
  section: ConsoleSection,
  snapshot: ControlPlaneSnapshot,
  experience?: ExperienceSnapshot
): ConsoleScene {
  if (section === "access") return buildAccessConsoleScene(experience);
  const installations = installationScenes(snapshot);
  const activeOperations = snapshot.installations.filter(
    (item) => item.phase === "PENDING" || item.phase === "PROVISIONING"
  ).length;
  const entitlementOptions = entitlementScenes(snapshot)
    .filter((item) => item.available > 0)
    .map((item) => {
      const source = snapshot.entitlements.find((value) => value.id === item.id);
      return {
        entitlementId: item.id,
        offeringId: source?.offeringId ?? "",
        label: `${item.offeringName} · ${item.shapeName}`,
        available: item.available
      };
    });
  const previewContent = experience ? experienceContent(section, experience) : null;

  return {
    ...baseScene(section, experience),
    navigation: navigation(section, snapshot, experience),
    content: previewContent ?? legacyContent(section, snapshot),
    workspace: section === "quotas"
      ? {
          kind: "quota-order",
          options: snapshot.offerings
            .filter((item) => item.state === "AVAILABLE")
            .map((item) => ({
              offeringId: item.id,
              offeringName: item.displayName,
              shapes: item.quotaShapes.map((shape) => ({
                id: shape.id,
                label: shape.displayName,
                resourceSummary: shapeSummary(shape)
              }))
            }))
        }
      : section === "installations"
        ? {
            kind: "installation-order",
            entitlementOptions,
            regionOptions: snapshot.regions
              .filter((item) => item.state === "READY")
              .map((item) => ({ id: item.id, label: item.displayName }))
          }
        : !experience && section === "overview"
          ? {
              kind: "platform-status",
              readyRegions: snapshot.regions.filter((item) => item.state === "READY").length,
              activeOperations,
              serviceCount: installations.length
            }
          : null
  };
}
