import { act, cleanup, fireEvent, render } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { SessionProvider, useSession } from "@/features/auth/application/SessionProvider";
import type { IamRepository } from "@/features/auth/repositories/iamRepository";
import { HttpProblem } from "@/infrastructure/http/jsonRequest";
import type { ControlPlaneSnapshot, ServiceInstallation } from "../domain/resources";
import type { HostInventory } from "../domain/hosts";
import type { ControlPlaneRepository } from "../repositories/controlPlaneRepository";
import type { HostInventoryRepository } from "../repositories/hostInventoryRepository";
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
  createdAt: "2026-08-26T12:00:00Z",
  operation: {
    id: "operation-primary",
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

function hostInventory(name = "node-a"): HostInventory {
  return {
    items: [{
      id: name,
      name,
      labels: { "matrix-os": "linux", "matrix-arch": "amd64" },
      resourceVersion: 1,
      executionPoolId: "linux-hosts",
      infrastructureAdapter: "nodehttps",
      deploymentExecutor: "compose",
      desiredState: "ACTIVE",
      health: "READY",
      capacity: { cpuMillis: 2000, memoryBytes: 4_294_967_296, storageBytes: 53_687_091_200, workloadSlots: 8 },
      allocatable: { cpuMillis: 1500, memoryBytes: 3_221_225_472, storageBytes: 42_949_672_960, workloadSlots: 6 },
      supportedIsolationGuarantees: ["WORKLOAD"],
      observedAt: "2026-08-30T08:00:00Z",
      usage: null
    }]
  };
}

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

function Probe() {
  const session = useSession();
  const controlPlane = useControlPlane();
  const installation = controlPlane.scene?.content.kind === "installations"
    ? controlPlane.scene.content.installations[0]
    : null;
  const host = controlPlane.scene?.content.kind === "hosts"
    ? controlPlane.scene.content.hosts[0]
    : null;
  return (
    <div>
      <button onClick={() => void session.login("admin", "password")} type="button">login</button>
      <button onClick={() => void controlPlane.activateQuota({ offeringId: "postgresql-18", quotaShapeId: "pg-small", instanceCount: 1 })} type="button">activate quota</button>
      <button onClick={() => void controlPlane.createInstallation({ id: "postgres-next", name: "Next database", offeringId: "postgresql-18", quotaEntitlementId: "quota-primary", regionId: "local-primary" })} type="button">create installation</button>
      <button onClick={() => void controlPlane.reload()} type="button">reload</button>
      <button onClick={() => void session.logout()} type="button">logout</button>
      <span data-testid="phase">{installation?.phase ?? "none"}</span>
      <span data-testid="host">{host?.name ?? "none"}</span>
      <span data-testid="section">{controlPlane.scene?.section ?? "none"}</span>
      <span role="status">{controlPlane.error}</span>
    </div>
  );
}

function iamRepository(): IamRepository {
  return {
    async login() {
      return {
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
  it.each(["activate quota", "create installation"])("keeps %s denial visible through successful background observations", async (command) => {
    vi.useFakeTimers();
    const repository: ControlPlaneRepository = {
      load: vi.fn().mockResolvedValue(snapshot(pendingInstallation, 0)),
      getInstallation: vi.fn().mockResolvedValue(readyInstallation),
      activateQuota: vi.fn().mockRejectedValue(new HttpProblem(403, "PERMISSION_DENIED")),
      createInstallation: vi.fn().mockRejectedValue(new HttpProblem(403, "PERMISSION_DENIED"))
    };
    const screen = render(<SessionProvider repository={iamRepository()}><ControlPlaneProvider repository={repository} selection={{ section: "installations" }}><Probe /></ControlPlaneProvider></SessionProvider>);
    await act(async () => { fireEvent.click(screen.getByText("login")); });
    await act(async () => { fireEvent.click(screen.getByText(command)); });
    const denial = screen.getByRole("status").textContent;
    expect(denial).toContain("无权");
    expect(screen.getByTestId("phase").textContent).toBe("PENDING");
    vi.mocked(repository.load).mockResolvedValue(snapshot(readyInstallation, 1));
    await act(async () => { await vi.advanceTimersByTimeAsync(4_000); });
    expect(screen.getByTestId("phase").textContent).toBe("READY");
    expect(screen.getByRole("status").textContent).toBe(denial);
    await act(async () => { fireEvent.click(screen.getByText("reload")); });
    expect(screen.getByRole("status").textContent).toBe("");
  });

  it.each([401, 403, 503])("removes previously loaded resources when background authorization or availability fails with %i", async (status) => {
    vi.useFakeTimers();
    const repository: ControlPlaneRepository = {
      load: vi.fn().mockResolvedValue(snapshot(pendingInstallation, 0)),
      getInstallation: vi.fn().mockRejectedValue(new HttpProblem(status, "PRIVATE_UPSTREAM_DETAIL")),
      activateQuota: vi.fn(),
      createInstallation: vi.fn()
    };
    const screen = render(<SessionProvider repository={iamRepository()}><ControlPlaneProvider repository={repository} selection={{ section: "installations" }}><Probe /></ControlPlaneProvider></SessionProvider>);
    await act(async () => { fireEvent.click(screen.getByText("login")); });
    expect(screen.getByTestId("phase").textContent).toBe("PENDING");
    await act(async () => { await vi.advanceTimersByTimeAsync(4_000); });
    expect(screen.getByTestId("phase").textContent).toBe("none");
    expect(screen.getByRole("status").textContent).not.toBe("");
    expect(screen.container.textContent).not.toContain("PRIVATE_UPSTREAM_DETAIL");
  });

  it.each(["activate quota", "create installation"])("removes protected resources when %s discovers an invalid session", async (command) => {
    const repository: ControlPlaneRepository = {
      load: vi.fn().mockResolvedValue(snapshot(readyInstallation, 1)),
      getInstallation: vi.fn(),
      activateQuota: vi.fn().mockRejectedValue(new HttpProblem(401, "SESSION_REVOKED")),
      createInstallation: vi.fn().mockRejectedValue(new HttpProblem(401, "SESSION_REVOKED"))
    };
    const screen = render(<SessionProvider repository={iamRepository()}><ControlPlaneProvider repository={repository} selection={{ section: "installations" }}><Probe /></ControlPlaneProvider></SessionProvider>);
    await act(async () => { fireEvent.click(screen.getByText("login")); });
    expect(screen.getByTestId("phase").textContent).toBe("READY");
    await act(async () => { fireEvent.click(screen.getByText(command)); });
    expect(screen.getByTestId("phase").textContent).toBe("none");
    expect(screen.getByRole("status").textContent).toContain("IAM 会话已失效");
  });

  it("makes the IAM shell available without calling the PaaS resource APIs", async () => {
    const repository: ControlPlaneRepository = { load: vi.fn(), getInstallation: vi.fn(), activateQuota: vi.fn(), createInstallation: vi.fn() };
    const screen = render(<SessionProvider repository={iamRepository()}><ControlPlaneProvider repository={repository} selection={{ section: "access" }}><Probe /></ControlPlaneProvider></SessionProvider>);
    await act(async () => { fireEvent.click(screen.getByText("login")); });
    expect(screen.getByTestId("section").textContent).toBe("access");
    expect(repository.load).not.toHaveBeenCalled();
    expect(repository.getInstallation).not.toHaveBeenCalled();
  });
  it("polls only pending installation resources before refreshing terminal quota state", async () => {
    vi.useFakeTimers();
    const repository: ControlPlaneRepository = {
      load: vi.fn()
        .mockResolvedValueOnce(snapshot(pendingInstallation, 0))
        .mockResolvedValueOnce(snapshot(readyInstallation, 1)),
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
    });
    expect(repository.load).toHaveBeenCalledTimes(1);
    expect(screen.getByTestId("phase").textContent).toBe("PENDING");

    await act(async () => {
      await vi.advanceTimersByTimeAsync(4_000);
    });

    expect(repository.getInstallation).toHaveBeenCalledWith(
      "memory-only-session",
      "postgres-primary"
    );
    expect(repository.load).toHaveBeenCalledTimes(2);
    expect(screen.getByTestId("phase").textContent).toBe("READY");
  });

  it("polls platform hosts independently and retains the last proved sample across transient failure", async () => {
    vi.useFakeTimers();
    const managed: ControlPlaneRepository = {
      load: vi.fn(), getInstallation: vi.fn(), activateQuota: vi.fn(), createInstallation: vi.fn()
    };
    const hosts: HostInventoryRepository = {
      load: vi.fn()
        .mockResolvedValueOnce(hostInventory("node-a"))
        .mockRejectedValueOnce(new HttpProblem(503, "PRIVATE_NODE_DETAIL"))
        .mockResolvedValueOnce(hostInventory("node-b"))
    };
    const screen = render(
      <SessionProvider repository={iamRepository()}>
        <ControlPlaneProvider hostRepository={hosts} repository={managed} selection={{ section: "hosts" }}>
          <Probe />
        </ControlPlaneProvider>
      </SessionProvider>
    );
    await act(async () => { fireEvent.click(screen.getByText("login")); });
    expect(screen.getByTestId("host").textContent).toBe("node-a");
    expect(managed.load).not.toHaveBeenCalled();

    await act(async () => { await vi.advanceTimersByTimeAsync(5_000); });
    expect(screen.getByTestId("host").textContent).toBe("node-a");
    expect(screen.getByRole("status").textContent).toContain("保持原时间");
    expect(screen.container.textContent).not.toContain("PRIVATE_NODE_DETAIL");

    await act(async () => { await vi.advanceTimersByTimeAsync(5_000); });
    expect(screen.getByTestId("host").textContent).toBe("node-b");
    expect(screen.getByRole("status").textContent).toBe("");
  });

  it("keeps one host request in flight across polling and manual refresh", async () => {
    vi.useFakeTimers();
    let finishSecond!: (value: HostInventory) => void;
    const hosts: HostInventoryRepository = {
      load: vi.fn()
        .mockResolvedValueOnce(hostInventory())
        .mockImplementationOnce(() => new Promise<HostInventory>((resolve) => { finishSecond = resolve; }))
        .mockResolvedValue(hostInventory("node-c"))
    };
    const screen = render(
      <SessionProvider repository={iamRepository()}>
        <ControlPlaneProvider hostRepository={hosts} selection={{ section: "hosts" }}>
          <Probe />
        </ControlPlaneProvider>
      </SessionProvider>
    );
    await act(async () => { fireEvent.click(screen.getByText("login")); });
    await act(async () => { await vi.advanceTimersByTimeAsync(5_000); });
    expect(hosts.load).toHaveBeenCalledTimes(2);

    await act(async () => {
      fireEvent.click(screen.getByText("reload"));
      await vi.advanceTimersByTimeAsync(20_000);
    });
    expect(hosts.load).toHaveBeenCalledTimes(2);

    await act(async () => { finishSecond(hostInventory("node-b")); });
    expect(screen.getByTestId("host").textContent).toBe("node-b");
    await act(async () => { await vi.advanceTimersByTimeAsync(5_000); });
    expect(hosts.load).toHaveBeenCalledTimes(3);
  });

  it.each([401, 403])("clears protected host facts and stops polling after authorization failure %i", async (status) => {
    vi.useFakeTimers();
    const hosts: HostInventoryRepository = {
      load: vi.fn()
        .mockResolvedValueOnce(hostInventory())
        .mockRejectedValue(new HttpProblem(status, "PRIVATE_AUTHORITY_DETAIL"))
    };
    const screen = render(
      <SessionProvider repository={iamRepository()}>
        <ControlPlaneProvider hostRepository={hosts} selection={{ section: "hosts" }}>
          <Probe />
        </ControlPlaneProvider>
      </SessionProvider>
    );
    await act(async () => { fireEvent.click(screen.getByText("login")); });
    await act(async () => { await vi.advanceTimersByTimeAsync(5_000); });
    expect(screen.getByTestId("host").textContent).toBe("none");
    expect(screen.getByRole("status").textContent).not.toBe("");
    expect(screen.container.textContent).not.toContain("PRIVATE_AUTHORITY_DETAIL");
    await act(async () => { await vi.advanceTimersByTimeAsync(20_000); });
    expect(hosts.load).toHaveBeenCalledTimes(2);
  });

  it("aborts an in-flight host read when navigation leaves the host section", async () => {
    let signal: AbortSignal | undefined;
    let finish!: (value: HostInventory) => void;
    const hosts: HostInventoryRepository = {
      load: vi.fn((_credential, currentSignal) => {
        signal = currentSignal;
        return new Promise<HostInventory>((resolve) => { finish = resolve; });
      })
    };
    const managed: ControlPlaneRepository = {
      load: vi.fn().mockResolvedValue(snapshot(readyInstallation, 1)),
      getInstallation: vi.fn(), activateQuota: vi.fn(), createInstallation: vi.fn()
    };
    const view = render(
      <SessionProvider repository={iamRepository()}>
        <ControlPlaneProvider hostRepository={hosts} repository={managed} selection={{ section: "hosts" }}>
          <Probe />
        </ControlPlaneProvider>
      </SessionProvider>
    );
    await act(async () => { fireEvent.click(view.getByText("login")); });
    expect(signal?.aborted).toBe(false);

    view.rerender(
      <SessionProvider repository={iamRepository()}>
        <ControlPlaneProvider hostRepository={hosts} repository={managed} selection={{ section: "regions" }}>
          <Probe />
        </ControlPlaneProvider>
      </SessionProvider>
    );
    expect(signal?.aborted).toBe(true);
    await act(async () => { finish(hostInventory("late-node")); });
    expect(view.getByTestId("section").textContent).toBe("regions");
    expect(view.getByTestId("host").textContent).toBe("none");
  });

  it("aborts an in-flight host read when the user logs out", async () => {
    let signal: AbortSignal | undefined;
    const hosts: HostInventoryRepository = {
      load: vi.fn((_credential, currentSignal) => {
        signal = currentSignal;
        return new Promise<HostInventory>(() => {});
      })
    };
    const screen = render(
      <SessionProvider repository={iamRepository()}>
        <ControlPlaneProvider hostRepository={hosts} selection={{ section: "hosts" }}>
          <Probe />
        </ControlPlaneProvider>
      </SessionProvider>
    );
    await act(async () => { fireEvent.click(screen.getByText("login")); });
    expect(signal?.aborted).toBe(false);
    await act(async () => { fireEvent.click(screen.getByText("logout")); });
    expect(signal?.aborted).toBe(true);
  });
});
