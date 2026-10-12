import { act, cleanup, fireEvent, render, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { useState } from "react";
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
    phase: "PENDING",
    safeFailureCode: null,
    observedAt: "2026-08-26T12:04:00Z"
  }
};

function snapshot(installation: ServiceInstallation, consumedCount: number): ControlPlaneSnapshot {
  return {
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
      <button onClick={() => void controlPlane.reload()} type="button">refresh current page</button>
      <button onClick={() => void controlPlane.createInstallation({
        id: "postgres-recovery",
        name: "Postgres recovery",
        offeringId: "postgresql-18",
        quotaEntitlementId: "quota-primary",
        regionId: "local-primary"
      })} type="button">create recovery installation</button>
      <button onClick={() => void controlPlane.retryManagedServiceCommand()} type="button">retry managed command</button>
      <span data-testid="phase">{installation?.phase ?? "none"}</span>
      <span data-testid="section">{controlPlane.scene?.section ?? "none"}</span>
      <span data-testid="error">{controlPlane.error ?? "none"}</span>
      <span data-testid="loading">{String(controlPlane.loading)}</span>
      <span data-testid="command-phase">{controlPlane.managedServiceCommand?.phase ?? "none"}</span>
      <span data-testid="command-request">{controlPlane.managedServiceCommand?.intent.requestId ?? "none"}</span>
      <span data-testid="command-slow">{String(controlPlane.managedServiceCommand?.slow ?? false)}</span>
      <span data-testid="command-restored">{String(controlPlane.managedServiceCommand?.restored ?? false)}</span>
      <span data-testid="projections">{JSON.stringify(projections)}</span>
    </div>
  );
}

function iamRepository(principalId = "principal-test"): IamRepository {
  return {
    async login() {
      return {
        outcome: "AUTHENTICATED",
        credential: "memory-only-session",
        mustChangePassword: false,
        session: {
          id: "session-test",
          organizationId: "organization-test",
          principalId,
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
  localStorage.clear();
  vi.useRealTimers();
});

describe("ControlPlaneProvider", () => {
  it("keeps a slow managed-service command local to its data region and preserves the caller idempotency key", async () => {
    vi.useFakeTimers();
    let resolveInstallation!: (installation: ServiceInstallation) => void;
    const createInstallation = vi.fn<ControlPlaneRepository["createInstallation"]>(() => new Promise((resolve) => {
      resolveInstallation = resolve;
    }));
    const repository: ControlPlaneRepository = {
      load: vi.fn(),
      getInstallation: vi.fn(),
      activateQuota: vi.fn(),
      createInstallation
    };
    const screen = render(
      <SessionProvider repository={iamRepository()}>
        <ControlPlaneProvider repository={repository} selection={{ section: "access" }}><Probe /></ControlPlaneProvider>
      </SessionProvider>
    );
    await act(async () => { fireEvent.click(screen.getByText("login")); });
    await act(async () => { fireEvent.click(screen.getByText("create recovery installation")); await Promise.resolve(); });

    expect(screen.getByTestId("command-phase").textContent).toBe("submitting");
    expect(createInstallation).toHaveBeenCalledTimes(1);
    const [, frozenPayload, frozenRequestId] = createInstallation.mock.calls[0]!;
    expect(frozenPayload).toMatchObject({ id: "postgres-recovery", name: "Postgres recovery" });
    expect(frozenRequestId).toMatch(/^ui-install-/);
    expect(localStorage.getItem("matrix.managed-service.commands.v1")).toContain(frozenRequestId);

    await act(async () => { await vi.advanceTimersByTimeAsync(800); });
    expect(screen.getByTestId("command-slow").textContent).toBe("true");

    await act(async () => { resolveInstallation({ ...pendingInstallation, id: "postgres-recovery", name: "Postgres recovery" }); await Promise.resolve(); });
    expect(screen.getByTestId("command-phase").textContent).toBe("completed");
    expect(localStorage.getItem("matrix.managed-service.commands.v1")).toBeNull();
  });

  it("restores an unknown command only for the exact account actor and retries its frozen request unchanged", async () => {
    const createInstallation = vi.fn<ControlPlaneRepository["createInstallation"]>()
      .mockRejectedValueOnce(new Error("transport disconnected"))
      .mockResolvedValueOnce({ ...pendingInstallation, id: "postgres-recovery", name: "Postgres recovery" });
    const repository: ControlPlaneRepository = {
      load: vi.fn(),
      getInstallation: vi.fn(),
      activateQuota: vi.fn(),
      createInstallation
    };
    const first = render(
      <SessionProvider repository={iamRepository()}>
        <ControlPlaneProvider repository={repository} selection={{ section: "access" }}><Probe /></ControlPlaneProvider>
      </SessionProvider>
    );
    await act(async () => { fireEvent.click(first.getByText("login")); });
    await act(async () => { fireEvent.click(first.getByText("create recovery installation")); });
    await waitFor(() => expect(first.getByTestId("command-phase").textContent).toBe("unknown"));
    const originalCall = createInstallation.mock.calls[0]!;
    const originalRequestId = String(originalCall[2]);
    expect(localStorage.getItem("matrix.managed-service.commands.v1")).toContain(originalRequestId);
    first.unmount();

    const otherActor = render(
      <SessionProvider repository={iamRepository("principal-other")}>
        <ControlPlaneProvider repository={repository} selection={{ section: "access" }}><Probe /></ControlPlaneProvider>
      </SessionProvider>
    );
    await act(async () => { fireEvent.click(otherActor.getByText("login")); await Promise.resolve(); });
    expect(otherActor.getByTestId("command-phase").textContent).toBe("none");
    otherActor.unmount();

    const restored = render(
      <SessionProvider repository={iamRepository()}>
        <ControlPlaneProvider repository={repository} selection={{ section: "access" }}><Probe /></ControlPlaneProvider>
      </SessionProvider>
    );
    await act(async () => { fireEvent.click(restored.getByText("login")); await Promise.resolve(); });
    await waitFor(() => expect(restored.getByTestId("command-phase").textContent).toBe("unknown"));
    expect(restored.getByTestId("command-request").textContent).toBe(originalRequestId);
    expect(restored.getByTestId("command-restored").textContent).toBe("true");

    await act(async () => { fireEvent.click(restored.getByText("retry managed command")); });
    await waitFor(() => expect(restored.getByTestId("command-phase").textContent).toBe("completed"));
    expect(createInstallation).toHaveBeenCalledTimes(2);
    expect(createInstallation.mock.calls[1]).toEqual(originalCall);
    expect(localStorage.getItem("matrix.managed-service.commands.v1")).toBeNull();
  });

  it("makes the IAM shell available without calling the PaaS resource APIs", async () => {
    const repository: ControlPlaneRepository = { load: vi.fn(), getInstallation: vi.fn(), activateQuota: vi.fn(), createInstallation: vi.fn() };
    const screen = render(<SessionProvider repository={iamRepository()}><ControlPlaneProvider repository={repository} selection={{ section: "access" }}><Probe /></ControlPlaneProvider></SessionProvider>);
    await act(async () => { fireEvent.click(screen.getByText("login")); });
    expect(screen.getByTestId("section").textContent).toBe("access");
    expect(repository.load).not.toHaveBeenCalled();
    expect(repository.getInstallation).not.toHaveBeenCalled();
  });
  it.each(["catalog", "quotas", "installations"] as const)("projects a closed %s product frame without resource reads or refresh", async (section) => {
    const repository: ControlPlaneRepository = { load: vi.fn(), getInstallation: vi.fn(), activateQuota: vi.fn(), createInstallation: vi.fn() };
    const screen = render(<SessionProvider repository={iamRepository()}><ControlPlaneProvider repository={repository} selection={{ section, product: "postgresql" }}><Probe /></ControlPlaneProvider></SessionProvider>);
    await act(async () => { fireEvent.click(screen.getByText("login")); });
    expect(screen.getByTestId("section").textContent).toBe(section);
    expect(screen.getByTestId("loading").textContent).toBe("false");
    expect(screen.getByTestId("error").textContent).toBe("none");
    await act(async () => { fireEvent.click(screen.getByText("refresh current page")); });
    expect(repository.load).not.toHaveBeenCalled();
    expect(repository.getInstallation).not.toHaveBeenCalled();
  });

  it("does not reuse another product's data admission", async () => {
    const repository: ControlPlaneRepository = { load: vi.fn(), getInstallation: vi.fn(), activateQuota: vi.fn(), createInstallation: vi.fn() };
    const screen = render(<SessionProvider repository={iamRepository()}><ControlPlaneProvider productAccess={{ product: "mysql", ready: true }} repository={repository} selection={{ section: "catalog", product: "postgresql" }}><Probe /></ControlPlaneProvider></SessionProvider>);
    await act(async () => { fireEvent.click(screen.getByText("login")); });
    expect(screen.getByTestId("section").textContent).toBe("catalog");
    expect(screen.getByTestId("loading").textContent).toBe("false");
    expect(repository.load).not.toHaveBeenCalled();
  });

  it("stops product polling and late directory refresh when resource admission closes", async () => {
    vi.useFakeTimers();
    const source = snapshot(terminatingInstallation, 1);
    const load = vi.fn<ControlPlaneRepository["load"]>(async (_credential, resources) => resourceSlice(source, resources));
    let rejectPoll!: (reason: Error) => void;
    const getInstallation = vi.fn<ControlPlaneRepository["getInstallation"]>(() => new Promise((_resolve, reject) => { rejectPoll = reject; }));
    const repository: ControlPlaneRepository = { load, getInstallation, activateQuota: vi.fn(), createInstallation: vi.fn() };
    function ProductPage() {
      const [ready, setReady] = useState(true);
      return <>
        <button type="button" onClick={() => setReady(false)}>close resource admission</button>
        <ControlPlaneProvider productAccess={{ product: "postgresql", ready }} repository={repository} selection={{ section: "installations", product: "postgresql" }}><Probe /></ControlPlaneProvider>
      </>;
    }
    const screen = render(<SessionProvider repository={iamRepository()}><ProductPage /></SessionProvider>);
    await act(async () => { fireEvent.click(screen.getByText("login")); });
    expect(load.mock.calls.map(([, resources]) => resources)).toEqual(expect.arrayContaining([["installations"], ["offerings"], ["regions"], ["entitlements"]]));
    await act(async () => { await vi.advanceTimersByTimeAsync(4_000); });
    expect(getInstallation).toHaveBeenCalledTimes(1);
    await act(async () => { fireEvent.click(screen.getByText("close resource admission")); });
    load.mockClear();
    await act(async () => { rejectPoll(new HttpProblem(404, "TERMINATED")); });
    await act(async () => { await vi.advanceTimersByTimeAsync(12_000); });
    expect(load).not.toHaveBeenCalled();
    expect(getInstallation).toHaveBeenCalledTimes(1);
    expect(screen.getByTestId("error").textContent).toBe("none");
    expect(screen.getByTestId("loading").textContent).toBe("false");
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
      "regions", "resources", "managed-product", "managed-product", "managed-product", "managed-product", "devops", "observability", "logs", "audit", "access"
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
    // Closed products can project their independent first-use frame before
    // catalog, quota or installation data is available.
    expect(JSON.parse(screen.getByTestId("projections").textContent ?? "[]")).toEqual([
      "none",
      "resources",
      "managed-product",
      "managed-product",
      "managed-product",
      "managed-product",
      "devops",
      "observability",
      "logs",
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
      "managed-product",
      "managed-product",
      "managed-product",
      "managed-product",
      "devops",
      "observability",
      "logs",
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
      "regions", "resources", "managed-product", "managed-product", "managed-product", "managed-product", "devops", "observability", "logs", "audit", "access"
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
