import { describe, expect, it } from "vitest";
import type { ControlPlaneSnapshot } from "../domain/resources";
import { previewExperienceSnapshot } from "../repositories/previewExperienceSnapshot";
import { buildConsoleScene } from "./buildConsoleScene";

const snapshot: ControlPlaneSnapshot = {
  offerings: [{
    id: "postgresql-18",
    kind: "POSTGRESQL",
    displayName: "PostgreSQL 18",
    description: "托管关系数据库",
    engineFamily: "PostgreSQL",
    engineVersion: "18",
    state: "AVAILABLE",
    quotaShapes: [{
      id: "development",
      displayName: "开发型",
      cpuMillicores: 1000,
      memoryMiB: 2048,
      storageGiB: 20
    }]
  }],
  regions: [{
    id: "local-primary",
    displayName: "本机主区域",
    profile: "LOCAL_MACHINE",
    state: "READY",
    inspectedAt: "2026-08-26T12:00:00Z",
    capacity: { cpuMillicores: 8000, memoryMiB: 16384, storageGiB: 500 }
  }],
  entitlements: [{
    id: "quota-postgres-dev",
    offeringId: "postgresql-18",
    quotaShapeId: "development",
    purchasedCount: 2,
    reservedCount: 0,
    consumedCount: 1,
    resourceVersion: 1,
    activatedAt: "2026-08-26T12:00:00Z"
  }],
  installations: [{
    id: "postgres-primary",
    name: "Primary database",
    offeringId: "postgresql-18",
    engineVersion: "18",
    quotaEntitlementId: "quota-postgres-dev",
    regionId: "local-primary",
    phase: "READY",
    endpoint: "postgres-primary.local:5432",
    credentialReference: "credential-postgres-primary",
    createdAt: "2026-08-26T12:00:00Z",
    operation: {
      id: "operation-postgres-primary",
      phase: "READY",
      safeFailureCode: null,
      observedAt: "2026-08-26T12:05:00Z"
    }
  }]
};

describe("buildConsoleScene", () => {
  it("switches service-local navigation and keeps features out of the global directory", () => {
    const logs = buildConsoleScene("logs", snapshot, previewExperienceSnapshot, "search");
    expect(logs.navigation.map((item) => item.id)).toEqual(["logs", "search", "topics", "collection"]);
    expect(logs.navigation.filter((item) => item.selected).map((item) => item.id)).toEqual(["search"]);
    expect(logs.content).toMatchObject({ kind: "logs", view: "search", data: { events: previewExperienceSnapshot.logs.events } });
    expect(buildConsoleScene("logs", snapshot).content).toMatchObject({ kind: "logs", data: null });
    const database = buildConsoleScene("installations", snapshot, previewExperienceSnapshot);
    expect(database.navigation.map((item) => item.id)).toEqual(["installations", "catalog", "quotas"]);
    expect(database.navigation.every((item) => !item.href.includes("/logs/"))).toBe(true);
    const monitoring = buildConsoleScene("observability", snapshot, previewExperienceSnapshot, "alerts");
    expect(monitoring.navigation.find((item) => item.selected)?.id).toBe("alerts");
  });

  it("opens application hosting with only application resources", () => {
    const scene = buildConsoleScene("applications", snapshot, previewExperienceSnapshot);
    expect(scene.preview).toBe(true);
    expect(scene.content.kind).toBe("resources");
    if (scene.content.kind === "resources") {
      expect(scene.content.resources.map((resource) => resource.id)).toEqual(["app-checkout-api"]);
      expect(scene.content.resources[0]?.kind).toBe("APPLICATION");
    }
    expect(scene.navigation.find((item) => item.id === "applications")?.selected).toBe(true);
    const live = buildConsoleScene("applications", snapshot);
    expect(live.content).toEqual({ kind: "resources", resources: [] });
  });
  it("projects real resources into the complete console shell", () => {
    const scene = buildConsoleScene("overview", snapshot);
    expect(scene.rail.map((item) => item.id)).toEqual(["overview", "managed-database", "access"]);
    expect(scene.navigation.map((item) => item.id)).toEqual([
      "catalog",
      "quotas",
      "installations",
      "regions",
      "access"
    ]);
    expect(scene.content.kind).toBe("overview");
    if (scene.content.kind === "overview") {
      expect(scene.content.metrics.find((item) => item.id === "quota")?.value).toBe(1);
      expect(scene.content.recentInstallations[0]?.endpoint).toBe("postgres-primary.local:5432");
    }
    expect(scene.workspace).toMatchObject({ kind: "platform-status", readyRegions: 1 });
  });

  it("exposes install choices only from available quota and ready regions", () => {
    const scene = buildConsoleScene("installations", snapshot);
    expect(scene.content.kind).toBe("installations");
    if (scene.content.kind === "installations") {
      expect(scene.content.installations[0]?.engine).toBe("PostgreSQL 18");
    }
    expect(scene.workspace).toMatchObject({
      kind: "installation-order",
      entitlementOptions: [{
        entitlementId: "quota-postgres-dev",
        offeringId: "postgresql-18",
        available: 1
      }],
      regionOptions: [{ id: "local-primary", label: "本机主区域" }]
    });
  });

  it("builds IAM navigation without reading unrelated PaaS resources", () => {
    const unavailable = new Proxy(snapshot, { get() { throw new Error("PaaS unavailable"); } });
    const scene = buildConsoleScene("access", unavailable, undefined, "groups");
    expect(scene.content).toEqual({ kind: "access", view: "groups" });
    expect(scene.navigation.filter((item) => item.selected).map((item) => item.id)).toEqual(["groups"]);
    expect(scene.navigation.filter((item) => item.group === "identityProviders").map((item) => item.id)).toEqual(["providers", "user-sso"]);
    expect(scene.navigation.filter((item) => item.group === "security").map((item) => item.id)).toEqual(["keys", "settings"]);
    expect(scene.navigation.find((item) => item.id === "federations")?.group).toBe("identity");
    expect(scene.navigation.map((item) => item.id)).not.toContain("installations");
  });


  it("keeps message results and running tasks separate, without fabricating a live inbox", () => {
    const preview = buildConsoleScene("messages", snapshot, previewExperienceSnapshot);
    expect(preview.content.kind).toBe("messages");
    expect(preview.activeOperationCount).toBe(1);
    if (preview.content.kind === "messages") expect(preview.content.messages).toEqual(preview.messages);
    const live = buildConsoleScene("messages", snapshot);
    expect(live.messages).toEqual([]);
    expect(live.content).toEqual({ kind: "messages", messages: [], preview: false });
  });

  it("projects the unified private-cloud experience without changing live contracts", () => {
    const overview = buildConsoleScene("overview", snapshot, previewExperienceSnapshot);
    expect(overview.preview).toBe(true);
    expect(overview.productId).toBe("console");
    expect(overview.scope?.regions).toHaveLength(3);
    expect(overview.search.some((item) => item.label === "支付服务")).toBe(true);
    expect(overview.messages).toHaveLength(7);
    expect(overview.messages.filter((message) => message.category === "alert")).toHaveLength(2);
    expect(overview.messages.filter((message) => message.category === "operation")).toHaveLength(3);
    expect(overview.messages.filter((message) => message.category === "platform")).toHaveLength(2);
    expect(overview.messages.some((message) => message.id.includes("op-1042"))).toBe(false);
    expect(overview.messages.find((message) => message.id.includes("op-1041"))?.createdAt).toBe("2026-09-08T09:09:18Z");
    expect(overview.messages.map((message) => message.createdAt)).toEqual(overview.messages.map((message) => message.createdAt).sort().reverse());
    expect(overview.content.kind).toBe("cloud-overview");

    const devops = buildConsoleScene("devops", snapshot, previewExperienceSnapshot);
    expect(devops.productId).toBe("devops");
    expect(devops.navigation.map((item) => item.id)).toEqual(["devops", "pipelines", "environments"]);
    expect(devops.content.kind).toBe("devops");
    if (devops.content.kind === "devops") {
      expect(devops.content.pipelines).toHaveLength(4);
      expect(devops.content.pipelines.find((item) => item.name === "checkout-api")?.state).toBe("RUNNING");
    }
  });
});
