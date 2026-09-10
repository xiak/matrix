import { serviceForSection, serviceNavigation } from "./serviceDirectory";
import { accountAccessViews, type AccountAccessView } from "@/features/auth/domain/accounts";
import type {
  ExperienceAlert,
  ExperienceOperation,
  ExperienceResource,
  ExperienceSnapshot
} from "../domain/experience";
import type {
  ControlPlaneSnapshot,
  ServiceInstallation
} from "../domain/resources";
import { consoleRouteHref, type ConsoleSection, type ServiceView } from "../domain/selection";
import type {
  AlertScene,
  ConsoleContentScene,
  ConsoleMessageScene,
  ConsoleNavigationItemScene,
  ConsoleScene,
  EntitlementScene,
  InstallationScene,
  OfferingScene,
  OperationScene,
  PipelineScene,
  RegionScene,
  SceneStatus,
  ServiceHealthScene,
  UnifiedResourceScene
} from "./consoleScene";

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
      observedAt: installation.operation.observedAt
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
      resources: shape ? { cpuMillicores: shape.cpuMillicores, memoryMiB: shape.memoryMiB, storageGiB: shape.storageGiB } : null,
      purchased: entitlement.purchasedCount,
      inUse: entitlement.reservedCount + entitlement.consumedCount,
      available: Math.max(0, entitlement.purchasedCount - entitlement.reservedCount - entitlement.consumedCount),
      activatedAt: entitlement.activatedAt
    };
  });
}

function regionScenes(snapshot: ControlPlaneSnapshot): RegionScene[] {
  return snapshot.regions.map((region) => ({
    id: region.id,
    name: region.displayName,
    profile: region.profile,
    state: region.state,
    status: region.state === "READY" ? "success" : region.state === "STALE" ? "warning" : "danger",
    capacity: region.capacity,
    inspectedAt: region.inspectedAt
  }));
}

function resourceStatus(state: ExperienceResource["state"]): SceneStatus {
  if (state === "HEALTHY") return "success";
  if (state === "RUNNING") return "info";
  if (state === "DEGRADED") return "warning";
  return "danger";
}

function resourceScenes(experience?: ExperienceSnapshot): UnifiedResourceScene[] {
  return experience?.resources.map((resource) => ({ ...resource, status: resourceStatus(resource.state) })) ?? [];
}

function operationStatus(state: ExperienceOperation["state"]): SceneStatus {
  return state === "SUCCEEDED" ? "success" : state === "RUNNING" ? "info" : "danger";
}

function operationScenes(experience?: ExperienceSnapshot): OperationScene[] {
  return experience?.operations.map((operation) => ({ ...operation, status: operationStatus(operation.state) })) ?? [];
}

function pipelineScenes(experience?: ExperienceSnapshot): PipelineScene[] {
  return experience?.pipelines.map((pipeline) => ({ ...pipeline, status: operationStatus(pipeline.state) })) ?? [];
}

function serviceHealthScenes(experience?: ExperienceSnapshot): ServiceHealthScene[] {
  return experience?.serviceHealth.map((service) => ({ ...service, status: resourceStatus(service.state) })) ?? [];
}

function alertStatus(alert: ExperienceAlert): Pick<AlertScene, "status"> {
  return { status: alert.severity === "CRITICAL" ? "danger" : alert.severity === "WARNING" ? "warning" : "info" };
}

function alertScenes(experience?: ExperienceSnapshot): AlertScene[] {
  return experience?.alerts.map((alert) => ({ ...alert, ...alertStatus(alert) })) ?? [];
}

function isHomeSection(section: ConsoleSection): boolean {
  return ["overview", "messages", "resources", "operations"].includes(section);
}

function messageScenes(experience?: ExperienceSnapshot): ConsoleMessageScene[] {
  if (!experience) return [];
  const alerts: ConsoleMessageScene[] = alertScenes(experience).filter((item) => item.state === "FIRING").map((item) => ({
    id: `alert:${item.id}:${item.startedAt}`, category: "alert", title: item.title,
    description: `${item.serviceName} · ${item.owner}`, createdAt: item.startedAt,
    status: item.status, href: "/console/observability/alerts/"
  }));
  const operations: ConsoleMessageScene[] = experience.operations.flatMap((item) => item.state === "RUNNING" || !item.finishedAt ? [] : [{
    id: `operation:${item.id}:${item.state}:${item.finishedAt}`, category: "operation" as const, title: item.action,
    description: `${item.target} · ${item.productName} · ${item.actor}`, createdAt: item.finishedAt,
    status: operationStatus(item.state), result: item.state, href: "/console/operations/"
  }]);
  const announcements: ConsoleMessageScene[] = experience.announcements.map((item) => ({
    id: `platform:${item.id}`, category: "platform", title: item.title,
    description: item.body, createdAt: item.publishedAt, status: "info"
  }));
  return [...alerts, ...operations, ...announcements].sort((a, b) => b.createdAt.localeCompare(a.createdAt));
}

function isPaaSSection(section: ConsoleSection): boolean {
  return ["catalog", "quotas", "installations", "applications"].includes(section);
}

function navigation(
  section: ConsoleSection,
  snapshot?: ControlPlaneSnapshot,
  experience?: ExperienceSnapshot,
  view?: ServiceView
): ConsoleNavigationItemScene[] {
  if (!experience && section !== "access") {
    return [
      { id: "catalog", messageKey: "catalog", href: "/console/catalog/", icon: "catalog", selected: section === "catalog", count: snapshot?.offerings.length },
      { id: "quotas", messageKey: "quotas", href: "/console/quotas/", icon: "quota", selected: section === "quotas", count: snapshot?.entitlements.length },
      { id: "installations", messageKey: "installations", href: "/console/installations/", icon: "installation", selected: section === "installations", count: snapshot?.installations.length },
      { id: "regions", messageKey: "regions", href: "/console/regions/", icon: "region", selected: section === "regions", count: snapshot?.regions.length },
      { id: "access", messageKey: "access", href: "/console/access/", icon: "access", selected: false }
    ];
  }
  if (experience && isHomeSection(section)) {
    return [
      { id: "overview", messageKey: "overview", href: "/console/", icon: "overview", selected: section === "overview" },
      { id: "resources", messageKey: "resources", href: "/console/resources/", icon: "resources", selected: section === "resources", count: experience.resources.length },
      { id: "operations", messageKey: "operations", href: "/console/operations/", icon: "operations", selected: section === "operations", count: experience.operations.filter((item) => item.state === "RUNNING").length },
      { id: "messages", messageKey: "messages", href: "/console/messages/", icon: "messages", selected: section === "messages" }
    ];
  }
  const service = serviceForSection(section);
  return service ? serviceNavigation[service.id].map((page) => ({
    id: page.id, messageKey: page.id,
    group: "group" in page ? page.group : undefined,
    href: consoleRouteHref(page), icon: page.icon,
    selected: page.section === section && ("view" in page ? page.view : undefined) === (view === "create-user" ? "users" : view === "create-policy" ? "policies" : view === "create-group" ? "groups" : view === "create-role" ? "roles" : view)
  })) : [];

}

function productRail(section: ConsoleSection, experience?: ExperienceSnapshot): ConsoleScene["rail"] {
  if (!experience) {
    return [
      { id: "overview", href: "/console/", icon: "overview", selected: section === "overview" },
      { id: "managed-database", href: "/console/catalog/", icon: "database", selected: section !== "overview" && section !== "access" },
      { id: "access", href: "/console/access/", icon: "access", selected: section === "access" }
    ];
  }
  return []; // Preview shortcuts are the user\'s favorites, not a fixed product list.
}

function productContext(section: ConsoleSection, experience?: ExperienceSnapshot): Pick<ConsoleScene, "productId" | "productEyebrow" | "productIcon"> {
  if (!experience) {
    return section === "access"
      ? { productId: "iam", productEyebrow: "Identity and access", productIcon: "access" }
      : { productId: "postgresql", productEyebrow: "Managed services", productIcon: "database" };
  }
  if (isHomeSection(section)) return { productId: "console", productEyebrow: "Unified cloud", productIcon: "overview" };
  if (section === "regions") return { productId: "regions", productEyebrow: "Cloud foundation", productIcon: "overview" };
  if (section === "applications") return { productId: "applications", productEyebrow: "Application hosting", productIcon: "overview" };
  if (section === "logs") return { productId: "logs", productEyebrow: "Log service", productIcon: "observability" };
  if (isPaaSSection(section)) return { productId: "postgresql", productEyebrow: "PaaS", productIcon: "database" };
  if (section === "devops") return { productId: "devops", productEyebrow: "DevOps", productIcon: "devops" };
  if (section === "observability") return { productId: "monitoring", productEyebrow: "Observability", productIcon: "observability" };
  return { productId: "iam", productEyebrow: "Security & IAM", productIcon: "access" };
}

function globalSearch(experience?: ExperienceSnapshot): ConsoleScene["search"] {
  return experience?.resources.map((resource) => ({
    id: `resource-${resource.id}`,
    label: resource.name,
    description: `${resource.projectName} · ${resource.regionName}`,
    keywords: [resource.id, resource.kind, resource.productName],
    resourceKind: resource.kind,
    href: resource.href,
    category: "resource" as const,
    icon: resource.productId
  })) ?? [];
}

function baseScene(section: ConsoleSection, experience?: ExperienceSnapshot): Omit<ConsoleScene, "content" | "workspace" | "navigation"> {
  return {
    section,
    ...productContext(section, experience),
    preview: Boolean(experience),
    scope: experience ? {
      organization: experience.organization,
      regions: experience.regions
    } : null,
    search: globalSearch(experience),
    messages: messageScenes(experience),
    activeOperationCount: experience?.operations.filter((item) => item.state === "RUNNING").length ?? 0,
    rail: productRail(section, experience)
  };
}

// IAM navigation must remain available without permission to read PaaS resources.
export function buildAccessConsoleScene(experience?: ExperienceSnapshot, view?: ServiceView): ConsoleScene {
  return {
    ...baseScene("access", experience),
    navigation: navigation("access", undefined, experience, view),
    content: { kind: "access", view: (accountAccessViews as readonly string[]).includes(view ?? "") ? view as AccountAccessView : "overview" },
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
  if (section === "messages") return { kind: "messages", messages: [], preview: false };
  if (section === "logs") return { kind: "logs", data: null };
  if (section === "resources") return { kind: "resources", resources: [] };
  if (section === "applications") return { kind: "resources", resources: [] };
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
      { id: "offerings", value: snapshot.offerings.filter((item) => item.state === "AVAILABLE").length, status: "info" },
      { id: "quota", value: availableQuota, status: availableQuota > 0 ? "success" : "warning" },
      { id: "services", value: ready, detailCount: active, status: active > 0 ? "info" : "neutral" },
      { id: "regions", value: snapshot.regions.filter((item) => item.state === "READY").length, status: snapshot.regions.some((item) => item.state === "READY") ? "success" : "warning" }
    ]
  };
}

function experienceContent(section: ConsoleSection, snapshot: ControlPlaneSnapshot, experience: ExperienceSnapshot): ConsoleContentScene | null {
  const resources = resourceScenes(experience);
  const operations = operationScenes(experience);
  const alerts = alertScenes(experience);
  if (section === "overview") {
    const healthy = experience.resources.filter((item) => item.state === "HEALTHY" || item.state === "RUNNING").length;
    const firing = experience.alerts.filter((item) => item.state === "FIRING").length;
    const running = experience.operations.filter((item) => item.state === "RUNNING").length;
    return {
      kind: "cloud-overview",
      regionCount: snapshot.regions.length,
      readyRegions: snapshot.regions.filter((item) => item.state === "READY").length,
      metrics: [
        { id: "all-resources", value: experience.resources.length, detailCount: experience.projects.filter((item) => item.id !== "all").length, status: "info" },
        { id: "healthy-resources", value: healthy, status: "success" },
        { id: "active-operations", value: running, status: running > 0 ? "info" : "neutral" },
        { id: "active-alerts", value: firing, status: firing > 0 ? "warning" : "success" }
      ],
      recentResources: resources.slice(0, 5),
      operations: operations.filter((item) => item.state === "RUNNING"),
      alerts: alerts.filter((item) => item.state === "FIRING").slice(0, 2)
    };
  }
  if (section === "messages") return { kind: "messages", messages: messageScenes(experience), preview: true };
  if (section === "logs") return { kind: "logs", data: experience.logs };
  if (section === "resources") return { kind: "resources", resources };
  if (section === "applications") return { kind: "resources", resources: resourceScenes({ ...experience, resources: experience.resources.filter((resource) => resource.kind === "APPLICATION") }) };
  if (section === "operations") return { kind: "operations", operations };
  if (section === "devops") {
    const successful = experience.pipelines.filter((item) => item.state === "SUCCEEDED").length;
    const running = experience.pipelines.filter((item) => item.state === "RUNNING").length;
    return {
      kind: "devops",
      metrics: [
        { id: "pipeline-success", value: 0.946, detailCount: successful, status: "success" },
        { id: "pipeline-running", value: running, status: running > 0 ? "info" : "neutral" },
        { id: "lead-time", value: 18, status: "success" },
        { id: "deployment-frequency", value: 12, status: "info" }
      ],
      pipelines: pipelineScenes(experience)
    };
  }
  if (section === "observability") {
    const degraded = experience.serviceHealth.filter((item) => item.state === "DEGRADED" || item.state === "FAILED").length;
    return {
      kind: "observability",
      metrics: [
        { id: "service-health", value: experience.serviceHealth.length, detailCount: degraded, status: degraded > 0 ? "warning" : "success" },
        { id: "availability", value: 0.9994, status: "success" },
        { id: "alert-firing", value: experience.alerts.filter((item) => item.state === "FIRING").length, status: "warning" },
        { id: "ingestion", value: 1.8, status: "info" }
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
  experience?: ExperienceSnapshot,
  view?: ServiceView
): ConsoleScene {
  if (section === "access") return buildAccessConsoleScene(experience, view);
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
  const content = (experience ? experienceContent(section, snapshot, experience) : null) ?? legacyContent(section, snapshot);
  if (content.kind === "devops" || content.kind === "observability" || content.kind === "logs") content.view = view;

  return {
    ...baseScene(section, experience),
    navigation: navigation(section, snapshot, experience, view),
    content,
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
                resources: { cpuMillicores: shape.cpuMillicores, memoryMiB: shape.memoryMiB, storageGiB: shape.storageGiB }
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
