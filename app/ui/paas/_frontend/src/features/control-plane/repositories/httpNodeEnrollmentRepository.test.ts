import { Buffer } from "node:buffer";
import { afterEach, describe, expect, it, vi } from "vitest";
import { httpNodeEnrollmentRepository } from "./httpNodeEnrollmentRepository";

const firstEnrollmentID = `node-enrollment-${"1".repeat(32)}`;
const secondEnrollmentID = `node-enrollment-${"2".repeat(32)}`;
const publicOrigin = "https://matrix.example";

function rawURL(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

function enrollment({
  id = firstEnrollmentID,
  resourceVersion = 1,
  state = "WAITING_INSTALL"
}: {
  id?: string;
  resourceVersion?: number;
  state?: "WAITING_INSTALL" | "VERIFYING" | "READY" | "FAILED" | "EXPIRED" | "REVOKED";
} = {}) {
  const createdAt = "2026-09-07T10:00:00Z";
  const updatedAt = state === "WAITING_INSTALL" ? createdAt : "2026-09-07T10:01:00Z";
  const result: Record<string, unknown> = {
    apiVersion: "paas.matrix.xiak.com/v1",
    kind: "NodeEnrollment",
    metadata: {
      id,
      name: "edge-linux-a",
      scope: { kind: "PLATFORM" },
      labels: { location: "edge-a" },
      resourceVersion,
      createdAt,
      updatedAt
    },
    executionTargetId: id === firstEnrollmentID ? "target-edge-a" : "target-edge-b",
    executionPoolId: "linux-pool",
    operationId: id === firstEnrollmentID ? "operation-edge-a" : "operation-edge-b",
    state,
    expiresAt: "2026-09-07T10:20:00Z"
  };
  if (["VERIFYING", "READY", "FAILED"].includes(state)) result.credentialConsumedAt = "2026-09-07T10:00:30Z";
  if (state === "READY") result.readyAt = "2026-09-07T10:01:00Z";
  if (state === "FAILED") {
    result.diagnostic = { code: "MTLS_VERIFICATION_FAILED", retryable: false, occurredAt: updatedAt };
  }
  if (state === "REVOKED") {
    result.diagnostic = { code: "ENROLLMENT_REVOKED", retryable: false, occurredAt: updatedAt };
  }
  return result;
}

function pool() {
  return {
    apiVersion: "paas.matrix.xiak.com/v1",
    kind: "ExecutionPool",
    metadata: {
      id: "linux-pool",
      name: "linux-pool",
      scope: { kind: "PLATFORM" },
      labels: { purpose: "edge" },
      resourceVersion: 3,
      createdAt: "2026-09-07T09:00:00Z",
      updatedAt: "2026-09-07T10:00:00Z"
    },
    spec: {
      executionTargetSelector: { matchLabels: { location: "edge-a" } },
      allowedIsolationGuarantees: ["WORKLOAD"]
    },
    status: {
      phase: "READY",
      executionTargetCount: 2,
      readyExecutionTargetCount: 1,
      observedAt: "2026-09-07T10:00:00Z"
    }
  };
}

function join(id = firstEnrollmentID, target = "target-edge-a") {
  return {
    apiVersion: "node.enrollment.matrix.xiak.com/v1",
    kind: "NodeEnrollmentJoin",
    enrollmentId: id,
    installationId: "mxi-test",
    executionTargetId: target,
    controlPlaneUrl: `${publicOrigin}/api/paas/v1/node-enrollments/${id}/exchange`,
    credentialDigest: `sha256:${"a".repeat(64)}`,
    expiresAt: "2026-09-07T10:20:00Z",
    issuerCertificate: rawURL(new Uint8Array([1, 2, 3])),
    signatureAlgorithm: "ED25519",
    signature: rawURL(new Uint8Array(64).fill(7))
  };
}

function creation(id = firstEnrollmentID) {
  const target = id === firstEnrollmentID ? "target-edge-a" : "target-edge-b";
  return {
    enrollment: enrollment({ id }),
    join: join(id, target),
    wrappedCredential: {
      algorithm: "RSA_OAEP_256",
      ciphertext: rawURL(new Uint8Array(384).fill(9))
    }
  };
}

function jsonResponse(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...headers }
  });
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("httpNodeEnrollmentRepository", () => {
  it("loads only bounded execution-pool choices and public enrollment status", async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse({
        apiVersion: "paas.matrix.xiak.com/v1", kind: "ExecutionPoolList", items: [pool()]
      }))
      .mockResolvedValueOnce(jsonResponse({
        apiVersion: "paas.matrix.xiak.com/v1", kind: "NodeEnrollmentList", items: [enrollment()]
      }));
    vi.stubGlobal("fetch", fetchMock);
    const controller = new AbortController();

    const inventory = await httpNodeEnrollmentRepository.load("memory-only-session", controller.signal);

    expect(inventory.pools).toEqual([expect.objectContaining({
      id: "linux-pool", selectorLabels: { location: "edge-a" }, phase: "READY"
    })]);
    expect(inventory.enrollments).toEqual([expect.objectContaining({
      id: firstEnrollmentID, state: "WAITING_INSTALL", credentialConsumedAt: null
    })]);
    for (const call of fetchMock.mock.calls) {
      expect(call[1]).toEqual(expect.objectContaining({
        signal: controller.signal,
        headers: expect.objectContaining({ Authorization: "Bearer memory-only-session" })
      }));
    }
  });

  it("creates with the exact public origin, idempotency boundary and wrapping public key", async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(creation(), 201, { ETag: '"1"' }));
    vi.stubGlobal("fetch", fetchMock);

    const result = await httpNodeEnrollmentRepository.create("platform-session", publicOrigin, {
      name: "edge-linux-a",
      labels: { location: "edge-a" },
      executionPoolId: "linux-pool",
      wrappingPublicKey: "browser-public-key"
    });

    expect(result.enrollment.id).toBe(firstEnrollmentID);
    expect(fetchMock).toHaveBeenCalledWith("/api/paas/v1/node-enrollments", expect.objectContaining({
      method: "POST",
      headers: expect.objectContaining({
        Authorization: "Bearer platform-session",
        "Content-Type": "application/json",
        "X-Matrix-Public-Origin": publicOrigin,
        "Idempotency-Key": expect.stringMatching(/^ui-node-enrollment-[0-9a-f]{32}$/)
      })
    }));
    expect(JSON.parse((fetchMock.mock.calls[0]![1] as RequestInit).body as string)).toEqual({
      name: "edge-linux-a",
      labels: { location: "edge-a" },
      executionPoolId: "linux-pool",
      wrappingPublicKey: "browser-public-key"
    });
  });

  it("uses the current strong ETag for revoke and sends no request body", async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse(enrollment(), 200, { ETag: '"1"' }))
      .mockResolvedValueOnce(jsonResponse(enrollment({ resourceVersion: 2, state: "REVOKED" }), 200, { ETag: '"2"' }));
    vi.stubGlobal("fetch", fetchMock);

    await expect(httpNodeEnrollmentRepository.revoke("platform-session", {
      enrollmentId: firstEnrollmentID,
      resourceVersion: 1
    })).resolves.toMatchObject({ state: "REVOKED", resourceVersion: 2 });

    expect(fetchMock.mock.calls[1]).toEqual([
      `/api/paas/v1/node-enrollments/${firstEnrollmentID}/revoke`,
      expect.objectContaining({
        method: "POST",
        headers: expect.objectContaining({
          "If-Match": '"1"',
          "Idempotency-Key": expect.stringMatching(/^ui-node-enrollment-revoke-[0-9a-f]{32}$/)
        })
      })
    ]);
    expect((fetchMock.mock.calls[1]![1] as RequestInit).body).toBeUndefined();
    expect(new Headers((fetchMock.mock.calls[1]![1] as RequestInit).headers).has("Content-Type")).toBe(false);
  });

  it("regenerates into a different identity with a fresh browser key", async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse(enrollment(), 200, { ETag: '"1"' }))
      .mockResolvedValueOnce(jsonResponse(creation(secondEnrollmentID), 201, { ETag: '"1"' }));
    vi.stubGlobal("fetch", fetchMock);

    const replacement = await httpNodeEnrollmentRepository.regenerate(
      "platform-session",
      publicOrigin,
      { enrollmentId: firstEnrollmentID, resourceVersion: 1 },
      "fresh-browser-public-key"
    );

    expect(replacement.enrollment.id).toBe(secondEnrollmentID);
    expect(JSON.parse((fetchMock.mock.calls[1]![1] as RequestInit).body as string)).toEqual({
      wrappingPublicKey: "fresh-browser-public-key"
    });
    expect(fetchMock.mock.calls[1]![1]).toEqual(expect.objectContaining({
      headers: expect.objectContaining({ "If-Match": '"1"', "X-Matrix-Public-Origin": publicOrigin })
    }));
  });

  it("fails closed on a stale version, non-HTTPS origin, plaintext extension or malformed envelope", async () => {
    const leaked = { ...creation(), credential: "raw-secret" };
    const malformed = creation();
    malformed.wrappedCredential.ciphertext = rawURL(new Uint8Array(32));
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse(enrollment({ resourceVersion: 2 }), 200, { ETag: '"2"' }))
      .mockResolvedValueOnce(jsonResponse(leaked, 201, { ETag: '"1"' }))
      .mockResolvedValueOnce(jsonResponse(malformed, 201, { ETag: '"1"' }));
    vi.stubGlobal("fetch", fetchMock);

    await expect(httpNodeEnrollmentRepository.revoke("session", {
      enrollmentId: firstEnrollmentID, resourceVersion: 1
    })).rejects.toThrow("STALE_NODE_ENROLLMENT_COMMAND");
    await expect(httpNodeEnrollmentRepository.create("session", "http://matrix.example", {
      name: "edge-linux-a", labels: {}, executionPoolId: "linux-pool", wrappingPublicKey: "key"
    })).rejects.toThrow("INVALID_NODE_ENROLLMENT_PUBLIC_ORIGIN_RESPONSE");
    await expect(httpNodeEnrollmentRepository.create("session", publicOrigin, {
      name: "edge-linux-a", labels: {}, executionPoolId: "linux-pool", wrappingPublicKey: "key"
    })).rejects.toThrow("INVALID_NODE_ENROLLMENT_CREATION_RESPONSE");
    await expect(httpNodeEnrollmentRepository.create("session", publicOrigin, {
      name: "edge-linux-a", labels: {}, executionPoolId: "linux-pool", wrappingPublicKey: "key"
    })).rejects.toThrow("INVALID_WRAPPED_JOIN_CREDENTIAL_RESPONSE");
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });
});
