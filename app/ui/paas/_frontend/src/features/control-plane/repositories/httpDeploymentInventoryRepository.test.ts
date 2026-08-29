import { afterEach, describe, expect, it, vi } from "vitest";
import { httpDeploymentInventoryRepository } from "./httpDeploymentInventoryRepository";

const tenantId = "tenant-alpha";

function deployment(id = "deployment-alpha") {
  return {
    apiVersion: "paas.matrix.xiak.com/v1",
    kind: "Deployment",
    metadata: {
      id,
      name: id,
      scope: { kind: "TENANT", tenantId },
      resourceVersion: 7,
      createdAt: "2026-08-30T08:00:00Z",
      updatedAt: "2026-08-30T08:01:00Z"
    },
    generation: 2,
    spec: {
      applicationRevisionId: "revision-alpha-v2",
      placementPolicyId: "placement-policy-alpha",
      desiredState: "RUNNING",
      components: [{ name: "database", replicas: 1 }]
    },
    status: {
      phase: "READY",
      observedGeneration: 2,
      placementDecisionId: "placement-decision-alpha",
      currentOperationId: "operation-alpha",
      observedApplicationRevisionId: "revision-alpha-v2",
      readyComponents: 1,
      observedAt: "2026-08-30T08:01:00Z"
    }
  };
}

function listResponse(items = [deployment()], nextAfter?: string): Response {
  return new Response(JSON.stringify({
    apiVersion: "paas.matrix.xiak.com/v1",
    kind: "DeploymentList",
    scope: { kind: "TENANT", tenantId },
    items,
    ...(nextAfter === undefined ? {} : { nextAfter })
  }), { status: 200, headers: { "Content-Type": "application/json" } });
}

function runtimeResponse(state: "AVAILABLE" | "STALE" | "UNAVAILABLE" = "AVAILABLE"): Response {
  return new Response(JSON.stringify({
    apiVersion: "paas.matrix.xiak.com/v1",
    kind: "DeploymentRuntimeSnapshot",
    scope: { kind: "TENANT", tenantId },
    state,
    ...(state === "UNAVAILABLE" ? {} : {
      value: {
        observation: {
          deploymentId: "deployment-alpha",
          generation: 2,
          applicationRevisionId: "revision-alpha-v2",
          executionTargetId: "node-a",
          instances: [{
            id: "instance-0123456789abcdef0123456789abcdef",
            componentName: "database",
            state: "RUNNING",
            health: "HEALTHY"
          }],
          observedAt: "2026-08-30T08:01:00Z"
        },
        validUntil: "2026-08-30T08:01:15Z"
      }
    })
  }), { status: 200, headers: { "Content-Type": "application/json" } });
}

afterEach(() => vi.unstubAllGlobals());

describe("httpDeploymentInventoryRepository", () => {
  it("loads one bounded tenant page without exposing provider selectors", async () => {
    const fetchMock = vi.fn().mockResolvedValue(listResponse());
    vi.stubGlobal("fetch", fetchMock);
    const controller = new AbortController();

    const inventory = await httpDeploymentInventoryRepository.load("session", tenantId, controller.signal);

    expect(inventory).toMatchObject({
      tenantId,
      nextAfter: null,
      items: [{ id: "deployment-alpha", generation: 2, phase: "READY", components: [{ name: "database", replicas: 1 }] }]
    });
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/paas/v1/deployments",
      expect.objectContaining({
        cache: "no-store",
        signal: controller.signal,
        headers: expect.objectContaining({ Authorization: "Bearer session" })
      })
    );
    expect(fetchMock.mock.calls[0]?.[0]).not.toContain("target");
    expect(fetchMock.mock.calls[0]?.[0]).not.toContain("provider");
  });

  it("loads only the selected deployment runtime and retains source timestamps", async () => {
    const fetchMock = vi.fn().mockResolvedValue(runtimeResponse("STALE"));
    vi.stubGlobal("fetch", fetchMock);

    const snapshot = await httpDeploymentInventoryRepository.loadRuntime(
      "session", tenantId, "deployment-alpha"
    );

    expect(snapshot).toMatchObject({
      state: "STALE",
      value: {
        deploymentId: "deployment-alpha",
        executionTargetId: "node-a",
        observedAt: "2026-08-30T08:01:00Z",
        validUntil: "2026-08-30T08:01:15Z",
        instances: [{ id: "instance-0123456789abcdef0123456789abcdef", exitCode: null }]
      }
    });
    expect(fetchMock.mock.calls[0]?.[0]).toBe("/api/paas/v1/deployments/deployment-alpha/runtime");
  });

  it("accepts unavailable runtime only without a value", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(runtimeResponse("UNAVAILABLE")));
    await expect(httpDeploymentInventoryRepository.loadRuntime("session", tenantId, "deployment-alpha"))
      .resolves.toEqual({ tenantId, state: "UNAVAILABLE", value: null });
  });

  it("fails closed on tenant mismatch, duplicate resources, or provider-native runtime fields", async () => {
    const wrongTenant = deployment();
    wrongTenant.metadata.scope.tenantId = "tenant-beta";
    const leakedRuntime = JSON.parse(await runtimeResponse().text()) as Record<string, unknown>;
    const value = leakedRuntime.value as { observation: { instances: Array<Record<string, unknown>> } };
    value.observation.instances[0]!.containerId = "raw-docker-id";
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(listResponse([wrongTenant]))
      .mockResolvedValueOnce(listResponse([deployment(), deployment()]))
      .mockResolvedValueOnce(new Response(JSON.stringify(leakedRuntime), { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);

    await expect(httpDeploymentInventoryRepository.load("session", tenantId)).rejects.toThrow("INVALID_DEPLOYMENT_SCOPE_RESPONSE");
    await expect(httpDeploymentInventoryRepository.load("session", tenantId)).rejects.toThrow("INVALID_DEPLOYMENT_INVENTORY_RESPONSE");
    await expect(httpDeploymentInventoryRepository.loadRuntime("session", tenantId, "deployment-alpha"))
      .rejects.toThrow("INVALID_DEPLOYMENT_RUNTIME_INSTANCE_RESPONSE");
  });

  it("fails closed on unordered pages or a cursor not bound to the final item", async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(listResponse([deployment("deployment-beta"), deployment("deployment-alpha")]))
      .mockResolvedValueOnce(listResponse([deployment("deployment-alpha")], "deployment-beta"))
      .mockResolvedValueOnce(listResponse([deployment("deployment-alpha")], "deployment-alpha"));
    vi.stubGlobal("fetch", fetchMock);

    await expect(httpDeploymentInventoryRepository.load("session", tenantId))
      .rejects.toThrow("INVALID_DEPLOYMENT_INVENTORY_RESPONSE");
    await expect(httpDeploymentInventoryRepository.load("session", tenantId))
      .rejects.toThrow("INVALID_DEPLOYMENT_INVENTORY_RESPONSE");
    await expect(httpDeploymentInventoryRepository.load("session", tenantId))
      .resolves.toMatchObject({ nextAfter: "deployment-alpha" });
  });

  it("rejects incomplete terminal state and non-canonical source time", async () => {
    const incompleteTerminal = JSON.parse(await runtimeResponse().text()) as {
      value: { observation: { instances: Array<Record<string, unknown>>; observedAt: string } };
    };
    incompleteTerminal.value.observation.instances[0]!.state = "EXITED";
    const nonCanonicalTime = JSON.parse(JSON.stringify(incompleteTerminal)) as typeof incompleteTerminal;
    nonCanonicalTime.value.observation.instances[0]!.state = "RUNNING";
    nonCanonicalTime.value.observation.observedAt = "2026-08-30T08:01:00+00:00";
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify(incompleteTerminal), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify(nonCanonicalTime), { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);

    await expect(httpDeploymentInventoryRepository.loadRuntime("session", tenantId, "deployment-alpha"))
      .rejects.toThrow("INVALID_DEPLOYMENT_RUNTIME_EXIT_CODE_RESPONSE");
    await expect(httpDeploymentInventoryRepository.loadRuntime("session", tenantId, "deployment-alpha"))
      .rejects.toThrow("INVALID_DEPLOYMENT_RUNTIME_OBSERVED_AT_RESPONSE");
  });
});
