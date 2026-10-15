import { act, cleanup, fireEvent, render, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { useState } from "react";
import { SessionProvider, useSession } from "@/features/auth/application/SessionProvider";
import type { IamRepository } from "@/features/auth/repositories/iamRepository";
import { HttpProblem } from "@/infrastructure/http/jsonRequest";
import type { ControlPlaneSnapshot, ServiceInstallation } from "../domain/resources";
import type { ControlPlaneRouteSelection } from "../domain/selection";
import { managedServiceCommandType, type ManagedServiceCommandIntent, type ManagedServiceCommandResult } from "../domain/managedServiceCommand";
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
  const [summary, setSummary] = useState("");
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
      <button onClick={() => void session.logout()} type="button">logout</button>
      <textarea aria-label="original summary" onChange={(event) => setSummary(event.target.value)} value={summary} />
      <button onClick={() => { controlPlane.restoreManagedServiceCommand(summary); }} type="button">restore original command</button>
      <button onClick={() => void controlPlane.inspectManagedServiceCommand()} type="button">inspect managed command</button>
      <span data-testid="phase">{installation?.phase ?? "none"}</span>
      <span data-testid="section">{controlPlane.scene?.section ?? "none"}</span>
      <span data-testid="error">{controlPlane.error ?? "none"}</span>
      <span data-testid="loading">{String(controlPlane.loading)}</span>
      <span data-testid="command-phase">{controlPlane.managedServiceCommand?.phase ?? "none"}</span>
      <span data-testid="command-request">{controlPlane.managedServiceCommand?.intent.requestId ?? "none"}</span>
      <span data-testid="command-slow">{String(controlPlane.managedServiceCommand?.slow ?? false)}</span>
      <span data-testid="command-restored">{String(controlPlane.managedServiceCommand?.restored ?? false)}</span>
      <span data-testid="command-error">{controlPlane.managedServiceCommand?.error ?? "none"}</span>
      <span data-testid="command-result">{controlPlane.managedServiceCommand?.result?.target.id ?? "none"}</span>
      <span data-testid="command-checking">{String(controlPlane.managedServiceCommand?.checking ?? false)}</span>
      <span data-testid="quota-records">{controlPlane.scene?.content.kind === "quotas" ? JSON.stringify(controlPlane.scene.content.entitlements) : "unavailable"}</span>
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

function originalCommand(kind: ManagedServiceCommandIntent["kind"]): ManagedServiceCommandIntent {
  const base = { owner: { accountId: "organization-test", actorKind: "USER" as const, actorId: "principal-test" },
    requestId: `original-${kind}`, startedAt: "2026-10-13T10:00:00Z", targetId: "original-installation", targetLabel: "Original operation" };
  const template = { id: "managedservice.installation-reader", version: 2, contentDigest: `sha256:${"c".repeat(64)}` };
  if (kind === "ACTIVATE_QUOTA") return { ...base, kind, targetId: "original-offering", payload: { offeringId: "original-offering", quotaShapeId: "shape-small", instanceCount: 1 } };
  if (kind === "CREATE_INSTALLATION") return { ...base, kind, payload: { id: "original-installation", name: "Original installation", offeringId: "original-offering", quotaEntitlementId: "original-quota", regionId: "local-primary" } };
  if (kind === "TERMINATE_INSTALLATION") return { ...base, kind, payload: { installationId: "original-installation" } };
  if (kind === "BIND_SERVICE_ROLE") return { ...base, kind, payload: { installationId: "original-installation", template } };
  return { ...base, kind, payload: { installationId: "original-installation", bindingId: "original-binding", resourceVersion: 2, expectedTemplate: template } };
}

function originalResult(intent: ManagedServiceCommandIntent): ManagedServiceCommandResult {
  return { idempotencyKey: intent.requestId, commandType: managedServiceCommandType(intent.kind), inputDigest: `sha256:${"d".repeat(64)}`,
    state: "SUCCEEDED", target: { kind: intent.kind === "ACTIVATE_QUOTA" ? "QUOTA_ENTITLEMENT" : "SERVICE_INSTALLATION",
      id: intent.kind === "ACTIVATE_QUOTA" ? "server-allocated-entitlement" : intent.targetId },
    operation: intent.kind === "CREATE_INSTALLATION" ? readyInstallation.operation : intent.kind === "TERMINATE_INSTALLATION"
      ? { ...readyInstallation.operation, kind: "TERMINATE" } : null,
    bindingId: intent.kind === "BIND_SERVICE_ROLE" || intent.kind === "UNBIND_SERVICE_ROLE" ? "original-binding" : null,
    completedAt: "2026-10-13T10:01:00Z" };
}

function recoveryView(read: NonNullable<ControlPlaneRepository["listCommandResults"]>, iam = iamRepository(), options: { load?: ControlPlaneRepository["load"]; selection?: ControlPlaneRouteSelection } = {}) {
  const repository: ControlPlaneRepository = { load: options.load ?? vi.fn(), getInstallation: vi.fn(), activateQuota: vi.fn(), createInstallation: vi.fn(),
    terminateInstallation: vi.fn(), bindServiceRole: vi.fn(), unbindServiceRole: vi.fn(), listCommandResults: read };
  return { repository, ...render(<SessionProvider repository={iam}><ControlPlaneProvider repository={repository} selection={options.selection ?? { section: "access" }}><Probe /></ControlPlaneProvider></SessionProvider>) };
}

async function bringOriginal(screen: ReturnType<typeof recoveryView>, intent: ManagedServiceCommandIntent) {
  await act(async () => { fireEvent.click(screen.getByText("login")); });
  fireEvent.change(screen.getByLabelText("original summary"), { target: { value: JSON.stringify(intent) } });
  await act(async () => { fireEvent.click(screen.getByText("restore original command")); });
}

afterEach(() => {
  cleanup();
  localStorage.clear();
  vi.useRealTimers();
});

describe("ControlPlaneProvider", () => {
  describe("quota recovery", () => {
    const quotaIntent = (): ManagedServiceCommandIntent => ({ ...originalCommand("ACTIVATE_QUOTA"), kind: "ACTIVATE_QUOTA", targetId: "postgresql-18", payload: { offeringId: "postgresql-18", quotaShapeId: "pg-small", instanceCount: 1 } });
    const base = snapshot(readyInstallation, 0);
    const quota = { ...base.entitlements[0]!, id: "server-allocated-entitlement", reservedCount: 0, consumedCount: 0 };
    const page = (resources: readonly ControlPlaneResourceKind[], visible: boolean, purchasedCount = 1) => resourceSlice({ ...base, entitlements: visible ? [{ ...quota, purchasedCount }] : [] }, resources);
    const records = (screen: ReturnType<typeof recoveryView>) => JSON.parse(screen.getByTestId("quota-records").textContent!);

    it("rereads the original window's entitlements after SUCCEEDED without replaying activation", async () => {
      let visible = false;
      const intent = quotaIntent();
      const load = vi.fn(async (_credential: string, resources: readonly ControlPlaneResourceKind[]) => page(resources, visible));
      const read = vi.fn(async () => { visible = true; return [originalResult(intent)]; });
      const screen = recoveryView(read, iamRepository(), { load, selection: { section: "quotas" } });
      await bringOriginal(screen, intent);
      await waitFor(() => expect(records(screen)).toEqual([]));
      await act(async () => { fireEvent.click(screen.getByText("inspect managed command")); });
      expect(load).toHaveBeenLastCalledWith("memory-only-session", ["entitlements"]);
      expect(records(screen)[0]).toMatchObject({ id: quota.id, purchased: 1, inUse: 0, available: 1 });
      expect(screen.getByTestId("command-phase").textContent).toBe("completed");
      expect(screen.repository.activateQuota).not.toHaveBeenCalled();
    });

    it("keeps a confirmed command completed while the independent list read is pending", async () => {
      let finishRead!: (result: ControlPlaneResourceSnapshot) => void;
      const intent = quotaIntent();
      const load = vi.fn((_credential: string, resources: readonly ControlPlaneResourceKind[]) => resources.length === 1
        ? new Promise<ControlPlaneResourceSnapshot>(resolve => { finishRead = resolve; }) : Promise.resolve(page(resources, false)));
      const screen = recoveryView(vi.fn(async () => [originalResult(intent)]), iamRepository(), { load, selection: { section: "quotas" } });
      await bringOriginal(screen, intent);
      await act(async () => { fireEvent.click(screen.getByText("inspect managed command")); });
      expect(screen.getByTestId("command-phase").textContent).toBe("completed");
      expect(screen.getByTestId("command-checking").textContent).toBe("true");
      expect(screen.getByTestId("quota-records").textContent).toBe("unavailable");
      await act(async () => { fireEvent.click(screen.getByText("create recovery installation")); });
      expect(screen.repository.createInstallation).not.toHaveBeenCalled();
      await act(async () => finishRead(page(["entitlements"], true)));
      expect(screen.getByTestId("command-checking").textContent).toBe("false");
      expect(records(screen)[0].available).toBe(1);
    });

    it.each([401, 403, 503, "protocol"] as const)("keeps completion separate from a failed %s entitlement read", async failure => {
      const intent = quotaIntent();
      const load = vi.fn(async (_credential: string, resources: readonly ControlPlaneResourceKind[]) => {
        if (resources.length === 1) {
          if (failure === "protocol") return {};
          throw new HttpProblem(failure, "PRIVATE_READ_DIAGNOSTIC");
        }
        return page(resources, false);
      });
      const screen = recoveryView(vi.fn(async () => [originalResult(intent)]), iamRepository(), { load, selection: { section: "quotas" } });
      await bringOriginal(screen, intent);
      await act(async () => { fireEvent.click(screen.getByText("inspect managed command")); });
      expect(screen.getByTestId("command-phase").textContent).toBe("completed");
      expect(screen.getByTestId("command-error").textContent).toBe("none");
      expect(screen.getByTestId("command-checking").textContent).toBe("false");
      expect(screen.getByTestId("quota-records").textContent).toBe("unavailable");
      expect(screen.getByTestId("error").textContent).toBe(failure === 401 ? "expired" : failure === 403 ? "forbidden" : "unavailable");
      expect(localStorage.getItem("matrix.managed-service.commands.v1")).toBeNull();
      expect(screen.repository.activateQuota).not.toHaveBeenCalled();
    });

    it("retries only the list read after a read failure and retains the original completion", async () => {
      let visible = false;
      const intent = quotaIntent();
      const load = vi.fn(async (_credential: string, resources: readonly ControlPlaneResourceKind[]) => {
        if (resources.length === 1) throw new HttpProblem(503, "READ_UNAVAILABLE");
        return page(resources, visible);
      });
      const read = vi.fn(async () => { visible = true; return [originalResult(intent)]; });
      const screen = recoveryView(read, iamRepository(), { load, selection: { section: "quotas" } });
      await bringOriginal(screen, intent);
      await act(async () => { fireEvent.click(screen.getByText("inspect managed command")); });
      await act(async () => { fireEvent.click(screen.getByText("refresh current page")); });
      expect(records(screen)[0].purchased).toBe(1);
      expect(screen.getByTestId("error").textContent).toBe("none");
      expect(screen.getByTestId("command-phase").textContent).toBe("completed");
      expect(read).toHaveBeenCalledTimes(1);
      expect(screen.repository.activateQuota).not.toHaveBeenCalled();
    });

    it.each(["IN_PROGRESS", "FAILED"] as const)("does not invalidate quota data from a %s receipt", async state => {
      const intent = quotaIntent();
      const load = vi.fn(async (_credential: string, resources: readonly ControlPlaneResourceKind[]) => page(resources, false));
      const result = { ...originalResult(intent), state, completedAt: state === "IN_PROGRESS" ? null : "2026-10-13T10:01:00Z" };
      const screen = recoveryView(vi.fn(async () => [result]), iamRepository(), { load, selection: { section: "quotas" } });
      await bringOriginal(screen, intent);
      await act(async () => { fireEvent.click(screen.getByText("inspect managed command")); });
      expect(load).toHaveBeenCalledTimes(1);
      expect(records(screen)).toEqual([]);
      expect(screen.repository.activateQuota).not.toHaveBeenCalled();
    });

    it("ignores an old session's late quota read after a new User session loads its own list", async () => {
      let finishRead!: (result: ControlPlaneResourceSnapshot) => void; let login = 0;
      const iam = iamRepository(); const firstLogin = iam.login;
      iam.login = async command => ({ ...await firstLogin(command), credential: `quota-session-${++login}` });
      const intent = quotaIntent();
      const load = vi.fn((credential: string, resources: readonly ControlPlaneResourceKind[]) => credential === "quota-session-1" && resources.length === 1
        ? new Promise<ControlPlaneResourceSnapshot>(resolve => { finishRead = resolve; }) : Promise.resolve(page(resources, credential === "quota-session-2", 7)));
      const screen = recoveryView(vi.fn(async () => [originalResult(intent)]), iam, { load, selection: { section: "quotas" } });
      await bringOriginal(screen, intent);
      await act(async () => { fireEvent.click(screen.getByText("inspect managed command")); });
      await act(async () => { fireEvent.click(screen.getByText("logout")); });
      await act(async () => { fireEvent.click(screen.getByText("login")); });
      await waitFor(() => expect(records(screen)[0].purchased).toBe(7));
      await act(async () => finishRead(page(["entitlements"], true)));
      expect(records(screen)[0].purchased).toBe(7);
      expect(screen.getByTestId("error").textContent).toBe("none");
      expect(screen.repository.activateQuota).not.toHaveBeenCalled();
    });

    it("does not let an older in-flight page read overwrite the recovered quota list", async () => {
      let finishOldPage!: (result: ControlPlaneResourceSnapshot) => void; let pageReads = 0;
      const intent = quotaIntent();
      const load = vi.fn((_credential: string, resources: readonly ControlPlaneResourceKind[]) => {
        if (resources.length === 1) return Promise.resolve(page(resources, true));
        if (++pageReads === 2) return new Promise<ControlPlaneResourceSnapshot>(resolve => { finishOldPage = resolve; });
        return Promise.resolve(page(resources, false));
      });
      const screen = recoveryView(vi.fn(async () => [originalResult(intent)]), iamRepository(), { load, selection: { section: "quotas" } });
      await bringOriginal(screen, intent);
      await act(async () => { fireEvent.click(screen.getByText("refresh current page")); });
      await act(async () => { fireEvent.click(screen.getByText("inspect managed command")); });
      expect(records(screen)[0].purchased).toBe(1);
      await act(async () => finishOldPage(page(["offerings", "entitlements"], false)));
      expect(records(screen)[0].purchased).toBe(1);
      expect(screen.repository.activateQuota).not.toHaveBeenCalled();
    });
  });

  it.each(["ACTIVATE_QUOTA", "CREATE_INSTALLATION", "TERMINATE_INSTALLATION", "BIND_SERVICE_ROLE", "UNBIND_SERVICE_ROLE"] as const)(
    "recovers %s in a clean browser from the original non-secret intent without any write", async (kind) => {
      const intent = originalCommand(kind), result = originalResult(intent), read = vi.fn(async () => [result]);
      const screen = recoveryView(read);
      await bringOriginal(screen, intent);
      expect(read).not.toHaveBeenCalled();
      await act(async () => { fireEvent.click(screen.getByText("inspect managed command")); });
      expect(screen.getByTestId("command-phase").textContent).toBe("completed");
      expect(screen.getByTestId("command-result").textContent).toBe(result.target.id);
      expect(read).toHaveBeenCalledWith("memory-only-session", managedServiceCommandType(kind));
      for (const write of [screen.repository.activateQuota, screen.repository.createInstallation, screen.repository.terminateInstallation, screen.repository.bindServiceRole, screen.repository.unbindServiceRole]) expect(write).not.toHaveBeenCalled();
      expect(screen.repository.getInstallation).not.toHaveBeenCalled();
      expect(localStorage.getItem("matrix.managed-service.commands.v1")).toBeNull();
    });

  it.each([403, 404, 409, 503, "protocol", "empty", "target", "binding", "type"])("preserves UNKNOWN after %s without permitting another create", async (failure) => {
    const intent = originalCommand("UNBIND_SERVICE_ROLE");
    const read = vi.fn(async () => {
      if (typeof failure === "number") throw new HttpProblem(failure, "PRIVATE_UPSTREAM_REASON");
      if (failure === "protocol") throw new Error("INVALID_WIRE");
      const result = originalResult(intent);
      if (failure === "empty") return [];
      if (failure === "target") result.target.id = "foreign-installation";
      if (failure === "binding") result.bindingId = "foreign-binding";
      if (failure === "type") result.commandType = "SERVICE_ROLE_BIND";
      return [result];
    });
    const screen = recoveryView(read);
    await bringOriginal(screen, intent);
    await act(async () => { fireEvent.click(screen.getByText("inspect managed command")); });
    expect(screen.getByTestId("command-phase").textContent).toBe("unknown");
    expect(screen.getByTestId("command-result").textContent).toBe("none");
    expect(localStorage.getItem("matrix.managed-service.commands.v1")).toContain(intent.requestId);
    await act(async () => { fireEvent.click(screen.getByText("create recovery installation")); });
    expect(screen.repository.createInstallation).not.toHaveBeenCalled();
  });

  it.each(["IN_PROGRESS", "FAILED"] as const)("separates a confirmed %s result from unknown transport failure", async (state) => {
    const intent = originalCommand("CREATE_INSTALLATION"), result = { ...originalResult(intent), state, completedAt: state === "IN_PROGRESS" ? null : "2026-10-13T10:01:00Z" };
    const screen = recoveryView(vi.fn(async () => [result]));
    await bringOriginal(screen, intent);
    await act(async () => { fireEvent.click(screen.getByText("inspect managed command")); });
    expect(screen.getByTestId("command-phase").textContent).toBe(state === "IN_PROGRESS" ? "inProgress" : "failed");
    expect(screen.repository.createInstallation).not.toHaveBeenCalled();
  });

  it("rejects another actor's summary before any query and clears only the current USER session on 401", async () => {
    const read = vi.fn(async () => { throw new HttpProblem(401, "EXPIRED"); });
    const screen = recoveryView(read);
    const foreign = originalCommand("CREATE_INSTALLATION");
    foreign.owner.actorId = "foreign-user";
    await bringOriginal(screen, foreign);
    await act(async () => { fireEvent.click(screen.getByText("inspect managed command")); });
    expect(read).not.toHaveBeenCalled();
    const intent = originalCommand("CREATE_INSTALLATION");
    await bringOriginal(screen, intent);
    await act(async () => { fireEvent.click(screen.getByText("inspect managed command")); });
    await waitFor(() => expect(screen.getByTestId("command-phase").textContent).toBe("none"));
    expect(localStorage.getItem("matrix.managed-service.commands.v1")).toContain(intent.requestId);
  });

  it("ignores a late result from a replaced session and never restores the old reminder into another actor", async () => {
    let rejectRead!: (error: unknown) => void;
    const read = vi.fn(() => new Promise<ManagedServiceCommandResult[]>((_resolve, reject) => { rejectRead = reject; }));
    let login = 0;
    const iam = iamRepository();
    const firstLogin = iam.login;
    iam.login = async () => ({ ...await firstLogin({ loginName: "admin", password: "in-memory" }), credential: `session-${++login}` });
    const screen = recoveryView(read, iam);
    await bringOriginal(screen, originalCommand("CREATE_INSTALLATION"));
    await act(async () => { fireEvent.click(screen.getByText("inspect managed command")); });
    await act(async () => { fireEvent.click(screen.getByText("logout")); });
    await act(async () => { fireEvent.click(screen.getByText("login")); });
    await act(async () => { rejectRead(new HttpProblem(401, "OLD_SESSION")); });
    expect(screen.getByTestId("command-phase").textContent).toBe("unknown");
    expect(screen.getByTestId("command-restored").textContent).toBe("true");
    expect(read).toHaveBeenCalledTimes(1);
  });
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

  it("restores an unknown command only for the exact account actor and reads its result without repeating the write", async () => {
    const createInstallation = vi.fn<ControlPlaneRepository["createInstallation"]>()
      .mockRejectedValueOnce(new Error("transport disconnected"));
    const repository: ControlPlaneRepository = {
      load: vi.fn(),
      getInstallation: vi.fn(),
      activateQuota: vi.fn(),
      createInstallation,
      listCommandResults: vi.fn<NonNullable<ControlPlaneRepository["listCommandResults"]>>(async (_credential, commandType) => [{
        idempotencyKey: String(createInstallation.mock.calls[0]![2]), commandType, inputDigest: `sha256:${"9".repeat(64)}`,
        state: "SUCCEEDED", target: { kind: "SERVICE_INSTALLATION", id: "postgres-recovery" }, operation: readyInstallation.operation,
        bindingId: null, completedAt: "2026-10-13T12:00:00Z"
      }])
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

    await act(async () => { fireEvent.click(restored.getByText("inspect managed command")); });
    await waitFor(() => expect(restored.getByTestId("command-phase").textContent).toBe("completed"));
    expect(createInstallation).toHaveBeenCalledTimes(1);
    expect(repository.listCommandResults).toHaveBeenCalledWith("memory-only-session", "INSTALLATION_CREATE");
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
