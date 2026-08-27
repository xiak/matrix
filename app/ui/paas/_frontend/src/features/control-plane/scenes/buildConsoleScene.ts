import type {
  ControlPlaneSnapshot,
  QuotaShape,
  ServiceInstallation
} from "../domain/resources";
import type { ConsoleSection } from "../domain/selection";
import type {
  ConsoleContentScene,
  ConsoleNavigationItemScene,
  ConsoleScene,
  EntitlementScene,
  InstallationScene,
  OfferingScene,
  RegionScene,
  SceneStatus
} from "./consoleScene";

const sectionCopy: Record<ConsoleSection, {
  title: string;
  eyebrow: string;
  description: string;
}> = {
  overview: {
    title: "控制面概览",
    eyebrow: "Platform overview",
    description: "查看组织配额、受管区域与服务安装的当前状态。"
  },
  catalog: {
    title: "服务目录",
    eyebrow: "Managed service catalog",
    description: "选择平台已验证并由发布制品固定的数据库服务。"
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
    eyebrow: "Regions",
    description: "Phase 2 使用薄 IaaS：仅显示安装器受管的本机区域能力。"
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
  return snapshot.installations.map((installation) => ({
    id: installation.id,
    name: installation.name,
    engine: `${offerings.get(installation.offeringId)?.displayName ?? "Managed service"} ${installation.engineVersion}`,
    regionName: regions.get(installation.regionId)?.displayName ?? installation.regionId,
    phase: installation.phase,
    status: installationStatus(installation.phase),
    endpoint: installation.endpoint,
    operationId: installation.operation.id,
    observedAt: dateTime(installation.operation.observedAt)
  }));
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

function navigation(section: ConsoleSection, snapshot?: ControlPlaneSnapshot): ConsoleNavigationItemScene[] {
  return [
    { id: "catalog", label: "服务目录", description: "可用产品", href: "/console/catalog/", icon: "catalog", selected: section === "catalog", count: snapshot?.offerings.length },
    { id: "quotas", label: "服务配额", description: "组织额度", href: "/console/quotas/", icon: "quota", selected: section === "quotas", count: snapshot?.entitlements.length },
    { id: "installations", label: "服务实例", description: "安装与运行", href: "/console/installations/", icon: "installation", selected: section === "installations", count: snapshot?.installations.length },
    { id: "regions", label: "区域配置", description: "薄 IaaS 能力", href: "/console/regions/", icon: "region", selected: section === "regions", count: snapshot?.regions.length },
    { id: "access", label: "访问管理", description: "账号与权限", href: "/console/access/", icon: "access", selected: section === "access" }
  ];
}

function productRail(section: ConsoleSection): ConsoleScene["rail"] {
  return [
    { id: "overview", label: "控制面概览", href: "/console/", icon: "overview", selected: section === "overview" },
    { id: "managed-database", label: "托管数据库", href: "/console/catalog/", icon: "database", selected: section !== "overview" && section !== "access" },
    { id: "access", label: "访问管理", href: "/console/access/", icon: "access", selected: section === "access" }
  ];
}

// IAM navigation must remain available without permission to read PaaS resources.
export function buildAccessConsoleScene(): ConsoleScene {
  return { section: "access", ...sectionCopy.access, rail: productRail("access"), navigation: navigation("access"), content: { kind: "access" }, workspace: null };
}

function content(section: ConsoleSection, snapshot: ControlPlaneSnapshot): ConsoleContentScene {
  const offerings = offeringScenes(snapshot);
  const installations = installationScenes(snapshot);
  if (section === "catalog") return { kind: "catalog", offerings };
  if (section === "quotas") return { kind: "quotas", entitlements: entitlementScenes(snapshot) };
  if (section === "installations") return { kind: "installations", installations };
  if (section === "regions") return { kind: "regions", regions: regionScenes(snapshot) };

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

export function buildConsoleScene(
  section: ConsoleSection,
  snapshot: ControlPlaneSnapshot
): ConsoleScene {
  if (section === "access") return buildAccessConsoleScene();
  const copy = sectionCopy[section];
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

  return {
    section,
    ...copy,
    rail: productRail(section),
    navigation: navigation(section, snapshot),
    content: content(section, snapshot),
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
        : section === "overview"
          ? {
              kind: "platform-status",
              readyRegions: snapshot.regions.filter((item) => item.state === "READY").length,
              activeOperations,
              serviceCount: installations.length
            }
          : null
  };
}
