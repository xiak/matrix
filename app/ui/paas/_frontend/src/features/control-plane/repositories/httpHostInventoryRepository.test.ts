import { afterEach, describe, expect, it, vi } from "vitest";
import { httpHostInventoryRepository } from "./httpHostInventoryRepository";

function target(desiredState: "ACTIVE" | "DRAINING" | "REMOVED" = "ACTIVE", resourceVersion = 4) {
  return {
    apiVersion: "paas.matrix.xiak.com/v1",
    kind: "ExecutionTarget",
    metadata: {
      id: "node-a",
      name: "node-a",
      scope: { kind: "PLATFORM" },
      labels: { "matrix-os": "linux", "matrix-arch": "amd64" },
      resourceVersion,
      createdAt: "2026-08-30T08:00:00Z",
      updatedAt: "2026-08-30T08:01:00Z"
    },
    spec: {
      executionPoolId: "linux-hosts",
      infrastructureAdapter: { kind: "INFRASTRUCTURE", name: "nodehttps", contractVersion: "v1" },
      deploymentExecutor: { kind: "DEPLOYMENT_EXECUTOR", name: "compose", contractVersion: "v1" },
      desiredState
    },
    status: {
      health: "READY",
      capacity: { cpuMillis: 4000, memoryBytes: 8_589_934_592, storageBytes: 107_374_182_400, workloadSlots: 24 },
      allocatable: { cpuMillis: 3000, memoryBytes: 6_442_450_944, storageBytes: 85_899_345_920, workloadSlots: 16 },
      supportedIsolationGuarantees: ["WORKLOAD"],
      observedAt: "2026-08-30T08:01:00Z",
      usage: {
        observedAt: "2026-08-30T08:01:00Z",
        validUntil: "2026-08-30T08:01:15Z",
        cpu: {
          state: "AVAILABLE",
          value: { logicalCpus: 4, windowMillis: 5000, utilizationRatio: 0.25, ioWaitRatio: 0.05, load1: 0.8, load5: 0.6, load15: 0.4 }
        },
        memory: {
          state: "AVAILABLE",
          value: { totalBytes: 8_589_934_592, availableBytes: 6_442_450_944, usedBytes: 2_147_483_648, swapTotalBytes: 0, swapFreeBytes: 0 }
        },
        filesystemsState: "AVAILABLE",
        filesystems: [{
          device: "/dev/vda1",
          mountPoint: "/",
          filesystemType: "ext4",
          state: "AVAILABLE",
          value: {
            totalBytes: 107_374_182_400,
            usedBytes: 21_474_836_480,
            availableBytes: 85_899_345_920,
            inodesState: "AVAILABLE",
            totalInodes: 1_000_000,
            freeInodes: 800_000,
            readOnly: false
          }
        }]
      }
    }
  };
}

function response(items = [target()]): Response {
  return new Response(JSON.stringify({
    apiVersion: "paas.matrix.xiak.com/v1",
    kind: "ExecutionTargetList",
    items
  }), { status: 200, headers: { "Content-Type": "application/json" } });
}

function targetResponse(item: ReturnType<typeof target>, etag = `"${item.metadata.resourceVersion}"`): Response {
  return new Response(JSON.stringify(item), {
    status: 200,
    headers: { "Content-Type": "application/json", ETag: etag }
  });
}

function operationResponse(action: "DRAIN" | "ACTIVATE" | "REMOVE", version: number): Response {
  return new Response(JSON.stringify({
    apiVersion: "paas.matrix.xiak.com/v1",
    kind: "Operation",
    id: `operation-${action.toLowerCase()}`,
    scope: { kind: "PLATFORM" },
    installationId: "mxi-test",
    action: `${action}_EXECUTION_TARGET`,
    target: { kind: "ExecutionTarget", id: "node-a" },
    requestedBy: { type: "USER", id: "platform-user" },
    idempotencyFingerprint: "sha256:" + "a".repeat(64),
    requestDigest: "sha256:" + "b".repeat(64),
    state: "SUCCEEDED",
    attempt: 1,
    createdAt: "2026-08-30T08:02:00Z",
    updatedAt: "2026-08-30T08:02:00Z",
    terminalAt: "2026-08-30T08:02:00Z"
  }), { status: 200, headers: { "Content-Type": "application/json", ETag: `"${version}"` } });
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("httpHostInventoryRepository", () => {
  it("loads normalized host usage through the installation-scoped route", async () => {
    const fetchMock = vi.fn().mockResolvedValue(response());
    vi.stubGlobal("fetch", fetchMock);
    const controller = new AbortController();

    const inventory = await httpHostInventoryRepository.load(
      "memory-only-platform-session",
      controller.signal
    );

    expect(inventory.items[0]).toMatchObject({
      id: "node-a",
      infrastructureAdapter: "nodehttps",
      health: "READY",
      usage: {
        cpu: { state: "AVAILABLE", value: { utilizationRatio: 0.25 } },
        filesystems: [{ mountPoint: "/", value: { usedBytes: 21_474_836_480 } }]
      }
    });
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/paas/v1/execution-targets",
      expect.objectContaining({
        cache: "no-store",
        signal: controller.signal,
        headers: expect.objectContaining({ Authorization: "Bearer memory-only-platform-session" })
      })
    );
  });

  it("accepts retained values only when the server labels them stale", async () => {
    const item = target();
    item.status.health = "UNAVAILABLE";
    item.status.supportedIsolationGuarantees = [];
    item.status.usage.cpu.state = "STALE";
    item.status.usage.memory.state = "STALE";
    item.status.usage.filesystemsState = "STALE";
    item.status.usage.filesystems[0]!.state = "STALE";
    item.status.usage.filesystems[0]!.value.inodesState = "STALE";
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(response([item])));

    const inventory = await httpHostInventoryRepository.load("session");

    expect(inventory.items[0]!.usage?.cpu).toMatchObject({
      state: "STALE",
      value: { utilizationRatio: 0.25 }
    });
  });

  it("fails closed on duplicate identities or protected binding extensions", async () => {
    const leaked = target() as ReturnType<typeof target> & { bindingRef?: string };
    leaked.bindingRef = "private-node-binding";
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(response([target(), target()]))
      .mockResolvedValueOnce(response([leaked]));
    vi.stubGlobal("fetch", fetchMock);

    await expect(httpHostInventoryRepository.load("session")).rejects.toThrow("INVALID_HOST_INVENTORY_RESPONSE");
    await expect(httpHostInventoryRepository.load("session")).rejects.toThrow("INVALID_HOST_TARGET_RESPONSE");
  });

  it("uses the exact target ETag and an empty idempotent lifecycle request", async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(targetResponse(target("ACTIVE", 4)))
      .mockResolvedValueOnce(operationResponse("DRAIN", 5))
      .mockResolvedValueOnce(targetResponse(target("DRAINING", 5)));
    vi.stubGlobal("fetch", fetchMock);

    const changed = await httpHostInventoryRepository.transition("platform-session", {
      targetId: "node-a", action: "DRAIN", resourceVersion: 4
    });

    expect(changed).toMatchObject({ id: "node-a", desiredState: "DRAINING", resourceVersion: 5 });
    expect(fetchMock.mock.calls[0]).toEqual([
      "/api/paas/v1/execution-targets/node-a",
      expect.objectContaining({ headers: expect.objectContaining({ Authorization: "Bearer platform-session" }) })
    ]);
    expect(fetchMock.mock.calls[1]).toEqual([
      "/api/paas/v1/execution-targets/node-a/drain",
      expect.objectContaining({
        method: "POST",
        headers: expect.objectContaining({
          Authorization: "Bearer platform-session",
          "If-Match": '"4"',
          "Idempotency-Key": expect.stringMatching(/^ui-host-lifecycle-[0-9a-f]{32}$/)
        })
      })
    ]);
    expect((fetchMock.mock.calls[1]![1] as RequestInit).body).toBeUndefined();
    expect(new Headers((fetchMock.mock.calls[1]![1] as RequestInit).headers).has("Content-Type")).toBe(false);
  });

  it("fails closed before mutation when the visible resource version or server ETag is stale", async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(targetResponse(target("ACTIVE", 5)))
      .mockResolvedValueOnce(targetResponse(target("ACTIVE", 4), 'W/"4"'));
    vi.stubGlobal("fetch", fetchMock);

    await expect(httpHostInventoryRepository.transition("session", {
      targetId: "node-a", action: "DRAIN", resourceVersion: 4
    })).rejects.toThrow("STALE_HOST_LIFECYCLE_COMMAND");
    await expect(httpHostInventoryRepository.transition("session", {
      targetId: "node-a", action: "DRAIN", resourceVersion: 4
    })).rejects.toThrow("INVALID_HOST_ETAG_RESPONSE");
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });
});
