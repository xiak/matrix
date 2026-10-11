import { act, cleanup, fireEvent, render, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { SessionProvider, useSession } from "@/features/auth/application/SessionProvider";
import type { IamRepository } from "@/features/auth/repositories/iamRepository";
import { HttpProblem } from "@/infrastructure/http/jsonRequest";
import type { ControlPlaneSnapshot, ServiceInstallation } from "../domain/resources";
import type {
  ControlPlaneRepository,
  ControlPlaneResourceKind,
  ControlPlaneResourceSnapshot
} from "../repositories/controlPlaneRepository";
import { previewExperienceSnapshot } from "../repositories/previewExperienceSnapshot";
import { serviceDirectory, serviceNavigation } from "../scenes/serviceDirectory";
import { ControlPlaneProvider, useControlPlane } from "./ControlPlaneProvider";

const pendingInstallation: ServiceInstallation = {
  id: "postgres-primary",
  name: "Postgres primary",
  offeringId: "postgresql-18",
  engineVersion: "18",
  quotaEntitlementId: "quota-primary",
  regionId: "local-primary",
  phase: "PENDING",
  endpoint: null,
  credentialReference: null,
  resourceVersion: 1,
  createdAt: "2026-08-26T12:00:00Z",
  operation: {
    id: "operation-primary",
    kind: "PROVISION",
    phase: "PENDING",
    safeFailureCode: null,
    observedAt: "2026-08-26T12:00:00Z"
  }
};

const readyInstallation: ServiceInstallation = {
  ...pendingInstallation,
  phase: "READY",
  endpoint: "127.0.0.1:35432",
  credentialReference: "credential-postgres-primary",
  operation: {
    ...pendingInstallation.operation,
    phase: "READY",
    observedAt: "2026-08-26T12:00:04Z"
  }
};

const terminatingInstallation: ServiceInstallation = {
  ...readyInstallation,
  phase: "TERMINATION_PENDING",
  resourceVersion: 2,
  operation: {
    id: "operation-terminate-primary",
    kind: "TERMINATE",
    phase: "TERMINATION_PENDING",
    safeFailureCode: null,
    observedAt: "2026-08-26T12:04:00Z"
  }
};

function snapshot(installation: ServiceInstallation, consumedCount: number): ControlPlaneSnapshot {
  return {
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
      reservedCount: consumedCount === 0 ? 1 : 0,
      consumedCount,
      resourceVersion: consumedCount === 0 ? 2 : 3,
      activatedAt: "2026-08-26T12:00:00Z"
    }],
    installations: [installation]
  };
}

function resourceSlice(
  source: ControlPlaneSnapshot,
  resources: readonly ControlPlaneResourceKind[]
): ControlPlaneResourceSnapshot {
  return Object.fromEntries(resources.map((resource) => [resource, source[resource]])) as ControlPlaneResourceSnapshot;
}

function Probe() {
  const session = useSession();
  const controlPlane = useControlPlane();
  const installation = controlPlane.scene?.content.kind === "installations"
    ? controlPlane.scene.content.installations[0]
    : null;
  const projections = serviceDirectory.map((service) => (
    controlPlane.projectScene(serviceNavigation[service.id][0])?.content.kind ?? "none"
  ));
  return (
    <div>
      <button onClick={() => void session.login("admin", "password")} type="button">login</button>
      <button onClick={() => void controlPlane.prepare({ section: "catalog" })} type="button">prepare catalog</button>
      <button onClick={() => void controlPlane.prepare({ section: "regions" })} type="button">prepare regions</button>
      <button onClick={() => void controlPlane.prepare({ section: "installations" })} type="button">prepare installations</button>
      <span data-testid="phase">{installation?.phase ?? "none"}</span>
      <span data-testid="section">{controlPlane.scene?.section ?? "none"}</span>
      <span data-testid="error">{controlPlane.error ?? "none"}</span>
      <span data-testid="projections">{JSON.stringify(projections)}</span>
    </div>
  );
}

function iamRepository(): IamRepository {
  return {
    async login() {
      return {
        outcome: "AUTHENTICATED",
        credential: "memory-only-session",
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
    async logout() {}
  };
}

afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

describe("ControlPlaneProvider", () => {
  it("makes the IAM shell available without calling the PaaS resource APIs", async () => {
    const repository: ControlPlaneRepository = { load: vi.fn(), getInstallation: vi.fn(), activateQuota: vi.fn(), createInstallation: vi.fn() };
    const screen = render(<SessionProvider repository={iamRepository()}><ControlPlaneProvider repository={repository} selection={{ section: "access" }}><Probe /></ControlPlaneProvider></SessionProvider>);
    await act(async () => { fireEvent.click(screen.getByText("login")); });
    expect(screen.getByTestId("section").textContent).toBe("access");
    expect(repository.load).not.toHaveBeenCalled();
    expect(repository.getInstallation).not.toHaveBeenCalled();
  });
  it("projects the installation directory while its three enrichments load independently", async () => {
    const source = snapshot(readyInstallation, 1);
    const load = vi.fn<ControlPlaneRepository["load"]>(async (_credential, resources) => resourceSlice(source, resources));
    const repository: ControlPlaneRepository = {
      load,
      getInstallation: vi.fn(),
      activateQuota: vi.fn(),
      createInstallation: vi.fn()
    };
    const screen = render(
      <SessionProvider repository={iamRepository()}>
        <ControlPlaneProvider experience={previewExperienceSnapshot} repository={repository} selection={{ section: "installations" }}>
          <Probe />
        </ControlPlaneProvider>
      </SessionProvider>
    );
    await act(async () => {
      fireEvent.click(screen.getByText("login"));
      await Promise.resolve();
    });
    await waitFor(() => expect(screen.getByTestId("phase").textContent).toBe("READY"));
    await waitFor(() => expect(load).toHaveBeenCalledTimes(4));
    expect(load.mock.calls.map(([, resources]) => resources)).toEqual(expect.arrayContaining([
      ["installations"], ["offerings"], ["regions"], ["entitlements"]
    ]));
    expect(load.mock.calls.every(([, resources]) => resources.length === 1)).toBe(true);
    expect(JSON.parse(screen.getByTestId("projections").textContent ?? "[]")).toEqual([
      "regions", "resources", "installations", "logs", "devops", "observability", "audit", "access"
    ]);
  });
  it.each([
    { resource: "offerings" as const, outcome: "forbidden" as const },
    { resource: "regions" as const, outcome: "unavailable" as const },
    { resource: "entitlements" as const, outcome: "empty" as const }
  ])("keeps the installation directory ready when $resource enrichment is $outcome", async ({ resource, outcome }) => {
    const source = snapshot(readyInstallation, 1);
    const load = vi.fn<ControlPlaneRepository["load"]>(async (_credential, resources) => {
      expect(resources).toHaveLength(1);
      if (resources[0] === resource) {
        if (outcome === "forbidden") throw new HttpProblem(403, "ENRICHMENT_FORBIDDEN");
        if (outcome === "unavailable") throw new HttpProblem(503, "ENRICHMENT_UNAVAILABLE");
        return { [resource]: [] };
      }
      return resourceSlice(source, resources);
    });
    const screen = render(
      <SessionProvider repository={iamRepository()}>
        <ControlPlaneProvider repository={{ load, getInstallation: vi.fn(), activateQuota: vi.fn(), createInstallation: vi.fn() }} selection={{ section: "installations" }}>
          <Probe />
        </ControlPlaneProvider>
      </SessionProvider>
    );
    await act(async () => {
      fireEvent.click(screen.getByText("login"));
      await Promise.resolve();
    });

    await waitFor(() => expect(screen.getByTestId("phase").textContent).toBe("READY"));
    await waitFor(() => expect(load).toHaveBeenCalledTimes(4));
    expect(screen.getByTestId("error").textContent).toBe("none");
    expect(load.mock.calls.map(([, resources]) => resources)).toEqual(expect.arrayContaining([
      ["installations"], ["offerings"], ["regions"], ["entitlements"]
    ]));
  });
  it("keeps IAM independent and incrementally reads only each destination's missing resources", async () => {
    const load = vi.fn<ControlPlaneRepository["load"]>().mockResolvedValue(snapshot(readyInstallation, 1));
    const repository: ControlPlaneRepository = {
      load,
      getInstallation: vi.fn(),
      activateQuota: vi.fn(),
      createInstallation: vi.fn()
    };
    const screen = render(
      <SessionProvider repository={iamRepository()}>
        <ControlPlaneProvider experience={previewExperienceSnapshot} repository={repository} selection={{ section: "access", view: "users" }}>
          <Probe />
        </ControlPlaneProvider>
      </SessionProvider>
    );
    await act(async () => { fireEvent.click(screen.getByText("login")); });
    expect(load).not.toHaveBeenCalled();
    expect(JSON.parse(screen.getByTestId("projections").textContent ?? "[]")).toEqual([
      "none",
      "resources",
      "none",
      "logs",
      "devops",
      "observability",
      "audit",
      "access"
    ]);

    await act(async () => {
      fireEvent.click(screen.getByText("prepare catalog"));
      await Promise.resolve();
    });

    expect(JSON.parse(screen.getByTestId("projections").textContent ?? "[]")).toEqual([
      "none",
      "resources",
      "none",
      "logs",
      "devops",
      "observability",
      "audit",
      "access"
    ]);
    expect(load).toHaveBeenCalledTimes(1);
    expect(load).toHaveBeenLastCalledWith("memory-only-session", ["offerings"]);

    await act(async () => {
      fireEvent.click(screen.getByText("prepare regions"));
      await Promise.resolve();
    });
    expect(load).toHaveBeenLastCalledWith("memory-only-session", ["regions"]);

    await act(async () => {
      fireEvent.click(screen.getByText("prepare installations"));
      await Promise.resolve();
    });
    expect(JSON.parse(screen.getByTestId("projections").textContent ?? "[]")).toEqual([
      "regions", "resources", "installations", "logs", "devops", "observability", "audit", "access"
    ]);
    await waitFor(() => expect(load).toHaveBeenCalledTimes(4));
    expect(load.mock.calls.map(([, resources]) => resources)).toEqual(expect.arrayContaining([
      ["offerings"], ["regions"], ["installations"], ["entitlements"]
    ]));
    expect(load.mock.calls.every(([, resources]) => resources.length === 1)).toBe(true);
  });
  it("polls only pending installation resources before refreshing terminal quota state", async () => {
    vi.useFakeTimers();
    let installationReads = 0;
    const load = vi.fn<ControlPlaneRepository["load"]>(async (_credential, resources) => {
      expect(resources).toHaveLength(1);
      const installation = resources[0] === "installations" && installationReads++ === 0
        ? pendingInstallation
        : readyInstallation;
      return resourceSlice(snapshot(installation, installation.phase === "READY" ? 1 : 0), resources);
    });
    const repository: ControlPlaneRepository = {
      load,
      getInstallation: vi.fn().mockResolvedValue(readyInstallation),
      activateQuota: vi.fn(),
      createInstallation: vi.fn()
    };
    const screen = render(
      <SessionProvider repository={iamRepository()}>
        <ControlPlaneProvider repository={repository} selection={{ section: "installations" }}>
          <Probe />
        </ControlPlaneProvider>
      </SessionProvider>
    );
    await act(async () => {
      fireEvent.click(screen.getByText("login"));
      await Promise.resolve();
      await Promise.resolve();
    });
    expect(load).toHaveBeenCalledTimes(4);
    expect(load.mock.calls.map(([, resources]) => resources)).toEqual(expect.arrayContaining([
      ["installations"], ["offerings"], ["regions"], ["entitlements"]
    ]));
    expect(screen.getByTestId("phase").textContent).toBe("PENDING");

    await act(async () => {
      await vi.advanceTimersByTimeAsync(4_000);
    });

    expect(repository.getInstallation).toHaveBeenCalledWith(
      "memory-only-session",
      "postgres-primary"
    );
    expect(load.mock.calls.filter(([, resources]) => resources[0] === "installations")).toHaveLength(2);
    expect(load.mock.calls.filter(([, resources]) => resources[0] === "entitlements")).toHaveLength(2);
    expect(load.mock.calls.every(([, resources]) => resources.length === 1)).toBe(true);
    expect(screen.getByTestId("phase").textContent).toBe("READY");
  });

  it("refreshes the authoritative directory and quota only when the terminating resource itself disappears", async () => {
    vi.useFakeTimers();
    let installationLoads = 0;
    const source = snapshot(terminatingInstallation, 1);
    const load = vi.fn<ControlPlaneRepository["load"]>(async (_credential, resources) => {
      expect(resources).toHaveLength(1);
      if (resources[0] === "installations") {
        installationLoads += 1;
        return { installations: installationLoads === 1 ? [terminatingInstallation] : [] };
      }
      return resourceSlice(source, resources);
    });
    const repository: ControlPlaneRepository = {
      load,
      getInstallation: vi.fn().mockRejectedValue(new HttpProblem(404, "INSTALLATION_NOT_FOUND")),
      activateQuota: vi.fn(),
      createInstallation: vi.fn()
    };
    const screen = render(
      <SessionProvider repository={iamRepository()}>
        <ControlPlaneProvider repository={repository} selection={{ section: "installations" }}>
          <Probe />
        </ControlPlaneProvider>
      </SessionProvider>
    );
    await act(async () => {
      fireEvent.click(screen.getByText("login"));
      for (let flush = 0; flush < 6; flush += 1) await Promise.resolve();
    });
    expect(screen.getByTestId("phase").textContent).toBe("TERMINATION_PENDING");

    await act(async () => { await vi.advanceTimersByTimeAsync(4_000); });

    expect(load.mock.calls.filter(([, resources]) => resources[0] === "installations")).toHaveLength(2);
    expect(load.mock.calls.filter(([, resources]) => resources[0] === "entitlements")).toHaveLength(2);
    expect(screen.getByTestId("phase").textContent).toBe("none");
    expect(screen.getByTestId("error").textContent).toBe("none");
  });

  it("does not misclassify a provisioning 404 as termination completion because another instance is terminating", async () => {
    vi.useFakeTimers();
    const provisioningOther: ServiceInstallation = {
      ...pendingInstallation,
      id: "mysql-still-provisioning",
      name: "MySQL still provisioning",
      offeringId: "mysql-8.4",
      engineVersion: "8.4",
      operation: { ...pendingInstallation.operation, id: "operation-mysql-provisioning" }
    };
    const source = { ...snapshot(terminatingInstallation, 1), installations: [terminatingInstallation, provisioningOther] };
    const load = vi.fn<ControlPlaneRepository["load"]>(async (_credential, resources) => resourceSlice(source, resources));
    const getInstallation = vi.fn(async (_credential: string, installationId: string) => {
      if (installationId === provisioningOther.id) throw new HttpProblem(404, "INSTALLATION_NOT_FOUND");
      return terminatingInstallation;
    });
    const screen = render(
      <SessionProvider repository={iamRepository()}>
        <ControlPlaneProvider repository={{ load, getInstallation, activateQuota: vi.fn(), createInstallation: vi.fn() }} selection={{ section: "installations" }}>
          <Probe />
        </ControlPlaneProvider>
      </SessionProvider>
    );
    await act(async () => {
      fireEvent.click(screen.getByText("login"));
      for (let flush = 0; flush < 6; flush += 1) await Promise.resolve();
    });
    expect(screen.getByTestId("phase").textContent).toBe("TERMINATION_PENDING");

    await act(async () => { await vi.advanceTimersByTimeAsync(4_000); });

    expect(getInstallation).toHaveBeenCalledTimes(2);
    expect(load.mock.calls.filter(([, resources]) => resources[0] === "installations")).toHaveLength(1);
    expect(screen.getByTestId("error").textContent).not.toBe("none");
  });
});
