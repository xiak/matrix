import type {
  ControlPlaneSnapshot,
  QuotaShape,
  ServiceInstallation
} from "../domain/resources";
import type {
  HostFilesystemUsage,
  HostInventory,
  HostMeasurementState,
  HostTarget
} from "../domain/hosts";
import type {
  DeploymentInstanceHealth,
  DeploymentInstanceState,
  DeploymentInventory,
  DeploymentInventoryItem,
  DeploymentRuntimeSnapshot
} from "../domain/deployments";
import type { ConsoleSection } from "../domain/selection";
import type {
  ConsoleContentScene,
  ConsoleNavigationItemScene,
  ConsoleScene,
  DeploymentRuntimeInstanceScene,
  DeploymentRuntimeScene,
  DeploymentScene,
  EntitlementScene,
  HostFilesystemScene,
  HostMeasurementScene,
  HostScene,
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
  deployments: {
    title: "应用工作负载",
    eyebrow: "Application deployments",
    description: "查看当前租户部署及其来源可追溯的容器运行态；运行实例只在选中部署后按 5 秒采样刷新。"
  },
  regions: {
    title: "区域与基础设施",
    eyebrow: "Regions",
    description: "Phase 2 使用薄 IaaS：仅显示安装器受管的本机区域能力。"
  },
  hosts: {
    title: "主机与资源",
    eyebrow: "Infrastructure hosts",
    description: "查看平台已纳管主机的当前健康状态，以及带来源时间和有效期的 CPU、内存与文件系统采样。"
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

function byteSize(value: number): string {
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let current = value;
  let unit = 0;
  while (current >= 1024 && unit < units.length - 1) {
    current /= 1024;
    unit++;
  }
  return `${new Intl.NumberFormat("zh-CN", { maximumFractionDigits: current >= 100 ? 0 : 1 }).format(current)} ${units[unit]}`;
}

function measurementStatus(value: HostMeasurementState): SceneStatus {
  if (value === "AVAILABLE") return "success";
  if (value === "STALE" || value === "WARMING_UP") return "warning";
  if (value === "UNAVAILABLE") return "danger";
  return "neutral";
}

function measurementLabel(value: HostMeasurementState): string {
  const labels: Record<HostMeasurementState, string> = {
    AVAILABLE: "有效",
    WARMING_UP: "采样中",
    UNAVAILABLE: "不可用",
    UNSUPPORTED: "不支持",
    STALE: "已过期"
  };
  return labels[value];
}

function unavailableMeasurement(state: HostMeasurementState): HostMeasurementScene {
  return {
    state,
    stateLabel: measurementLabel(state),
    value: measurementLabel(state),
    detail: "平台没有可证明的当前数值",
    progress: null,
    status: measurementStatus(state)
  };
}

function cpuScene(target: HostTarget): HostMeasurementScene {
  const measurement = target.usage?.cpu;
  if (!measurement?.value) return unavailableMeasurement(measurement?.state ?? "UNAVAILABLE");
  const value = measurement.value;
  return {
    state: measurement.state,
    stateLabel: measurementLabel(measurement.state),
    value: `${(value.utilizationRatio * 100).toFixed(1)}%`,
    detail: `I/O wait ${(value.ioWaitRatio * 100).toFixed(1)}% · Load ${value.load1.toFixed(2)} / ${value.load5.toFixed(2)} / ${value.load15.toFixed(2)} · ${value.logicalCpus} 逻辑 CPU`,
    progress: value.utilizationRatio * 100,
    status: measurementStatus(measurement.state)
  };
}

function memoryScene(target: HostTarget): HostMeasurementScene {
  const measurement = target.usage?.memory;
  if (!measurement?.value) return unavailableMeasurement(measurement?.state ?? "UNAVAILABLE");
  const value = measurement.value;
  const swapUsed = value.swapTotalBytes - value.swapFreeBytes;
  return {
    state: measurement.state,
    stateLabel: measurementLabel(measurement.state),
    value: `${byteSize(value.usedBytes)} / ${byteSize(value.totalBytes)}`,
    detail: `可用 ${byteSize(value.availableBytes)} · Swap ${byteSize(swapUsed)} / ${byteSize(value.swapTotalBytes)}`,
    progress: value.totalBytes === 0 ? null : value.usedBytes / value.totalBytes * 100,
    status: measurementStatus(measurement.state)
  };
}

function filesystemScene(value: HostFilesystemUsage): HostFilesystemScene {
  const base = value.value ? {
    value: `${byteSize(value.value.usedBytes)} / ${byteSize(value.value.totalBytes)}`,
    detail: `可用 ${byteSize(value.value.availableBytes)}${value.value.totalInodes === null ? "" : ` · Inode 可用 ${value.value.freeInodes}/${value.value.totalInodes}`}`,
    progress: value.value.totalBytes === 0 ? null : value.value.usedBytes / value.value.totalBytes * 100
  } : {
    value: measurementLabel(value.state),
    detail: "平台没有可证明的当前文件系统数值",
    progress: null
  };
  return {
    id: `${value.device}\0${value.mountPoint}\0${value.filesystemType}`,
    device: value.device,
    mountPoint: value.mountPoint,
    filesystemType: value.filesystemType,
    readOnly: value.value?.readOnly ?? false,
    state: value.state,
    stateLabel: measurementLabel(value.state),
    status: measurementStatus(value.state),
    ...base
  };
}

function hostStatus(value: HostTarget["health"]): SceneStatus {
  if (value === "READY") return "success";
  if (value === "DEGRADED") return "warning";
  if (value === "UNAVAILABLE") return "danger";
  return "neutral";
}

function hostScenes(inventory: HostInventory): HostScene[] {
  return [...inventory.items]
    .sort((left, right) => left.id < right.id ? -1 : left.id > right.id ? 1 : 0)
    .map((target) => {
      const states = target.usage ? [target.usage.cpu.state, target.usage.memory.state, target.usage.filesystemsState] : ["UNAVAILABLE" as const];
      const sampleState = states.includes("STALE")
        ? "采样已过期"
        : states.some((item) => item === "UNAVAILABLE" || item === "UNSUPPORTED")
          ? "部分观测不可用"
          : states.includes("WARMING_UP") ? "正在建立采样窗口" : "采样有效";
      const sampleStatus: SceneStatus = states.includes("STALE") || states.includes("WARMING_UP")
        ? "warning"
        : states.includes("UNAVAILABLE") ? "danger"
          : states.includes("UNSUPPORTED") ? "neutral" : "success";
      return {
        id: target.id,
        name: target.name,
        platform: [target.labels["matrix-os"], target.labels["matrix-arch"]].filter(Boolean).join(" · ") || "平台信息未上报",
        source: `${target.infrastructureAdapter} · ${target.deploymentExecutor}`,
        executionPoolId: target.executionPoolId,
        desiredState: target.desiredState,
        health: target.health,
        status: hostStatus(target.health),
        capacity: `${target.capacity.cpuMillis / 1000} vCPU · ${byteSize(target.capacity.memoryBytes)} 内存 · ${byteSize(target.capacity.storageBytes)} 存储`,
        observedAt: dateTime(target.observedAt),
        usageObservedAt: target.usage ? dateTime(target.usage.observedAt) : "尚无资源采样",
        validUntil: target.usage ? dateTime(target.usage.validUntil) : "无有效期",
        sampleState,
        sampleStatus,
        cpu: cpuScene(target),
        memory: memoryScene(target),
        filesystemsState: measurementLabel(target.usage?.filesystemsState ?? "UNAVAILABLE"),
        filesystems: target.usage?.filesystems.map(filesystemScene) ?? []
      };
    });
}

function navigation(
  section: ConsoleSection,
  snapshot?: ControlPlaneSnapshot,
  hostCount?: number,
  deploymentCount?: number
): ConsoleNavigationItemScene[] {
  return [
    { id: "catalog", label: "服务目录", description: "可用产品", href: "/console/catalog/", icon: "catalog", selected: section === "catalog", count: snapshot?.offerings.length },
    { id: "quotas", label: "服务配额", description: "组织额度", href: "/console/quotas/", icon: "quota", selected: section === "quotas", count: snapshot?.entitlements.length },
    { id: "installations", label: "服务实例", description: "安装与运行", href: "/console/installations/", icon: "installation", selected: section === "installations", count: snapshot?.installations.length },
    { id: "deployments", label: "应用工作负载", description: "部署与容器运行态", href: "/console/deployments/", icon: "deployment", selected: section === "deployments", count: deploymentCount },
    { id: "regions", label: "区域配置", description: "薄 IaaS 能力", href: "/console/regions/", icon: "region", selected: section === "regions", count: snapshot?.regions.length },
    { id: "hosts", label: "主机资源", description: "健康与实时占用", href: "/console/hosts/", icon: "host", selected: section === "hosts", count: hostCount },
    { id: "access", label: "访问管理", description: "账号与权限", href: "/console/access/", icon: "access", selected: section === "access" }
  ];
}

function productRail(section: ConsoleSection): ConsoleScene["rail"] {
  return [
    { id: "overview", label: "控制面概览", href: "/console/", icon: "overview", selected: section === "overview" },
    { id: "managed-database", label: "托管数据库", href: "/console/catalog/", icon: "database", selected: ["catalog", "quotas", "installations", "regions"].includes(section) },
    { id: "workloads", label: "应用托管", href: "/console/deployments/", icon: "workloads", selected: section === "deployments" },
    { id: "infrastructure", label: "基础设施", href: "/console/hosts/", icon: "infrastructure", selected: section === "hosts" },
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
  if (section === "hosts") return { kind: "hosts", hosts: [] };

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

export function buildHostConsoleScene(inventory: HostInventory): ConsoleScene {
  return {
    section: "hosts",
    ...sectionCopy.hosts,
    rail: productRail("hosts"),
    navigation: navigation("hosts", undefined, inventory.items.length),
    content: { kind: "hosts", hosts: hostScenes(inventory) },
    workspace: null
  };
}

function deploymentStatus(value: DeploymentInventoryItem["phase"]): SceneStatus {
  if (value === "READY") return "success";
  if (value === "DEGRADED" || value === "STOPPING") return "warning";
  if (value === "FAILED") return "danger";
  if (value === "PENDING" || value === "PLACING" || value === "APPLYING") return "info";
  return "neutral";
}

function deploymentScenes(inventory: DeploymentInventory, selectedDeploymentId: string | null): DeploymentScene[] {
  return inventory.items.map((item) => ({
    id: item.id,
    name: item.name,
    generation: item.generation,
    revisionId: item.applicationRevisionId,
    desiredState: item.desiredState,
    phase: item.phase,
    status: deploymentStatus(item.phase),
    componentSummary: item.components.map((component) => `${component.name} × ${component.replicas}`).join(" · "),
    readiness: `${item.readyComponents}/${item.components.length} 组件就绪`,
    observedAt: dateTime(item.observedAt),
    selected: item.id === selectedDeploymentId
  }));
}

function runtimeInstanceStatus(state: DeploymentInstanceState, health: DeploymentInstanceHealth): SceneStatus {
  if (health === "UNHEALTHY" || state === "DEAD") return "danger";
  if (health === "HEALTHY" && state === "RUNNING") return "success";
  if (state === "CREATED" || state === "RESTARTING" || health === "STARTING") return "warning";
  if (state === "RUNNING") return "info";
  return "neutral";
}

function runtimeStateLabel(value: DeploymentInstanceState): string {
  const labels: Record<DeploymentInstanceState, string> = {
    CREATED: "已创建",
    RUNNING: "运行中",
    RESTARTING: "重启中",
    REMOVING: "移除中",
    PAUSED: "已暂停",
    EXITED: "已退出",
    DEAD: "失效"
  };
  return labels[value];
}

function runtimeHealthLabel(value: DeploymentInstanceHealth): string {
  const labels: Record<DeploymentInstanceHealth, string> = {
    NONE: "未配置",
    STARTING: "检查中",
    HEALTHY: "健康",
    UNHEALTHY: "不健康"
  };
  return labels[value];
}

function runtimeScene(snapshot: DeploymentRuntimeSnapshot | null): DeploymentRuntimeScene | null {
  if (!snapshot) return null;
  const labels = { AVAILABLE: "采样有效", STALE: "采样已过期", UNAVAILABLE: "运行态不可用" } as const;
  const status: SceneStatus = snapshot.state === "AVAILABLE" ? "success" : snapshot.state === "STALE" ? "warning" : "neutral";
  return {
    state: snapshot.state,
    stateLabel: labels[snapshot.state],
    status,
    generation: snapshot.value?.generation ?? null,
    revisionId: snapshot.value?.applicationRevisionId ?? null,
    executionTargetId: snapshot.value?.executionTargetId ?? null,
    observedAt: snapshot.value ? dateTime(snapshot.value.observedAt) : "尚无来源采样",
    validUntil: snapshot.value ? dateTime(snapshot.value.validUntil) : "无有效期",
    instances: snapshot.value?.instances.map((instance): DeploymentRuntimeInstanceScene => ({
      id: instance.id,
      componentName: instance.componentName,
      state: instance.state,
      stateLabel: runtimeStateLabel(instance.state),
      health: instance.health,
      healthLabel: runtimeHealthLabel(instance.health),
      status: runtimeInstanceStatus(instance.state, instance.health),
      exitCode: instance.exitCode === null ? "—" : String(instance.exitCode)
    })) ?? []
  };
}

export function buildDeploymentConsoleScene(
  inventory: DeploymentInventory,
  selectedDeploymentId: string | null,
  runtime: DeploymentRuntimeSnapshot | null
): ConsoleScene {
  const selected = inventory.items.some((item) => item.id === selectedDeploymentId)
    ? selectedDeploymentId
    : null;
  return {
    section: "deployments",
    ...sectionCopy.deployments,
    rail: productRail("deployments"),
    navigation: navigation("deployments", undefined, undefined, inventory.items.length),
    content: {
      kind: "deployments",
      deployments: deploymentScenes(inventory, selected),
      selectedDeploymentId: selected,
      runtime: selected ? runtimeScene(runtime) : null,
      truncated: inventory.nextAfter !== null
    },
    workspace: null
  };
}
