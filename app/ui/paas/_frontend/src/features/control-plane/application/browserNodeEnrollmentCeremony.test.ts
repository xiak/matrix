import { Buffer } from "node:buffer";
import { webcrypto } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import type {
  NodeEnrollment,
  NodeEnrollmentCreation,
  NodeEnrollmentJoin
} from "../domain/nodeEnrollments";
import type { NodeEnrollmentRepository } from "../repositories/nodeEnrollmentRepository";
import { browserNodeEnrollmentCeremony } from "./browserNodeEnrollmentCeremony";

const enrollmentID = `node-enrollment-${"1".repeat(32)}`;
const rawCredential = Uint8Array.from({ length: 32 }, (_, index) => index + 1);

function rawURL(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

function fromRawURL(value: string): Uint8Array<ArrayBuffer> {
  const source = Buffer.from(value, "base64url");
  const result = new Uint8Array(new ArrayBuffer(source.byteLength));
  result.set(source);
  return result;
}

function enrollment(): NodeEnrollment {
  return {
    id: enrollmentID,
    name: "edge-linux-a",
    labels: { location: "edge-a" },
    resourceVersion: 1,
    createdAt: "2026-09-07T10:00:00Z",
    updatedAt: "2026-09-07T10:00:00Z",
    executionTargetId: "target-edge-a",
    executionPoolId: "linux-pool",
    operationId: "operation-edge-a",
    state: "WAITING_INSTALL",
    expiresAt: "2026-09-07T10:20:00Z",
    credentialConsumedAt: null,
    readyAt: null,
    replacedById: null,
    diagnostic: null
  };
}

async function join(credentialDigest?: string): Promise<NodeEnrollmentJoin> {
  const digest = new Uint8Array(await webcrypto.subtle.digest("SHA-256", rawCredential));
  return {
    apiVersion: "node.enrollment.matrix.xiak.com/v1",
    kind: "NodeEnrollmentJoin",
    enrollmentId: enrollmentID,
    installationId: "mxi-test",
    executionTargetId: "target-edge-a",
    controlPlaneUrl: `https://matrix.example/api/paas/v1/node-enrollments/${enrollmentID}/exchange`,
    credentialDigest: credentialDigest ?? `sha256:${Buffer.from(digest).toString("hex")}`,
    expiresAt: "2026-09-07T10:20:00Z",
    issuerCertificate: rawURL(new Uint8Array([1, 2, 3])),
    signatureAlgorithm: "ED25519",
    signature: rawURL(new Uint8Array(64).fill(8))
  };
}

async function encryptedCreation(
  wrappingPublicKey: string,
  digest?: string,
  bindToEnrollment = true
): Promise<NodeEnrollmentCreation> {
  const publicJoin = await join(digest);
  const publicKey = await webcrypto.subtle.importKey(
    "spki",
    fromRawURL(wrappingPublicKey),
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["encrypt"]
  );
  const label = new TextEncoder().encode(
    `matrix-node-enrollment-v1\0${publicJoin.installationId}\0${publicJoin.enrollmentId}`
  );
  const algorithm: RsaOaepParams = bindToEnrollment
    ? { name: "RSA-OAEP", label }
    : { name: "RSA-OAEP" };
  const ciphertext = new Uint8Array(await webcrypto.subtle.encrypt(
    algorithm,
    publicKey,
    rawCredential
  ));
  label.fill(0);
  return {
    enrollment: enrollment(),
    join: publicJoin,
    wrappedCredential: { algorithm: "RSA_OAEP_256", ciphertext: rawURL(ciphertext) }
  };
}

function repository(create: NodeEnrollmentRepository["create"]): NodeEnrollmentRepository {
  return {
    load: vi.fn(),
    create,
    revoke: vi.fn(),
    regenerate: vi.fn()
  };
}

let originalCreateObjectURL: typeof URL.createObjectURL | undefined;
let originalRevokeObjectURL: typeof URL.revokeObjectURL | undefined;

afterEach(() => {
  if (originalCreateObjectURL === undefined) delete (URL as { createObjectURL?: unknown }).createObjectURL;
  else Object.defineProperty(URL, "createObjectURL", { configurable: true, value: originalCreateObjectURL });
  if (originalRevokeObjectURL === undefined) delete (URL as { revokeObjectURL?: unknown }).revokeObjectURL;
  else Object.defineProperty(URL, "revokeObjectURL", { configurable: true, value: originalRevokeObjectURL });
  originalCreateObjectURL = undefined;
  originalRevokeObjectURL = undefined;
  vi.unstubAllGlobals();
});

describe("browserNodeEnrollmentCeremony", () => {
  it("decrypts only in memory, downloads the exact join file and immediately revokes its URL", async () => {
    vi.stubGlobal("crypto", webcrypto as unknown as Crypto);
    const generateKey = vi.spyOn(webcrypto.subtle, "generateKey");
    let downloaded: Blob | null = null;
    originalCreateObjectURL = URL.createObjectURL;
    originalRevokeObjectURL = URL.revokeObjectURL;
    const createObjectURL = vi.fn((blob: Blob) => {
      downloaded = blob;
      return "blob:matrix-node-enrollment";
    });
    const revokeObjectURL = vi.fn();
    Object.defineProperty(URL, "createObjectURL", { configurable: true, value: createObjectURL });
    Object.defineProperty(URL, "revokeObjectURL", { configurable: true, value: revokeObjectURL });
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
    const storageRead = vi.spyOn(Storage.prototype, "getItem");
    const storageWrite = vi.spyOn(Storage.prototype, "setItem");
    let submittedRequest: Parameters<NodeEnrollmentRepository["create"]>[2] | null = null;
    let returnedCreation: NodeEnrollmentCreation | null = null;
    const create = vi.fn(async (_credential, origin, request) => {
      expect(origin).toBe("https://matrix.example");
      submittedRequest = request;
      returnedCreation = await encryptedCreation(request.wrappingPublicKey);
      return returnedCreation;
    });

    const created = await browserNodeEnrollmentCeremony.create(
      repository(create),
      "memory-only-session",
      "https://matrix.example",
      { name: "edge-linux-a", labels: { location: "edge-a" }, executionPoolId: "linux-pool" }
    );

    expect(created.id).toBe(enrollmentID);
    expect(generateKey).toHaveBeenCalledWith(expect.objectContaining({
      name: "RSA-OAEP",
      modulusLength: 3072,
      hash: "SHA-256"
    }), false, ["encrypt", "decrypt"]);
    expect(submittedRequest).toEqual(expect.objectContaining({
      name: "edge-linux-a",
      labels: { location: "edge-a" },
      executionPoolId: "linux-pool",
      wrappingPublicKey: expect.stringMatching(/^[A-Za-z0-9_-]+$/)
    }));
    expect(Object.keys(submittedRequest ?? {})).toEqual([
      "name", "labels", "executionPoolId", "wrappingPublicKey"
    ]);
    expect(createObjectURL).toHaveBeenCalledTimes(1);
    expect(click).toHaveBeenCalledTimes(1);
    expect(revokeObjectURL).toHaveBeenCalledWith("blob:matrix-node-enrollment");
    expect(document.querySelector("a[download='matrix-node-join.json']")).toBeNull();
    expect(storageRead).not.toHaveBeenCalled();
    expect(storageWrite).not.toHaveBeenCalled();

    const source = await (downloaded as Blob | null)?.text();
    expect(source).toBeDefined();
    const file = JSON.parse(source!);
    expect(file).toEqual({
      apiVersion: "node.installation.matrix.xiak.com/v1",
      kind: "NodeEnrollmentJoinFile",
      join: await join(),
      credential: rawURL(rawCredential)
    });
    expect(source).not.toContain(submittedRequest!.wrappingPublicKey);
    expect(source).not.toContain(returnedCreation!.wrappedCredential.ciphertext);
  }, 15_000);

  it("does not create a download when the decrypted credential misses the signed digest", async () => {
    vi.stubGlobal("crypto", webcrypto as unknown as Crypto);
    originalCreateObjectURL = URL.createObjectURL;
    originalRevokeObjectURL = URL.revokeObjectURL;
    const createObjectURL = vi.fn();
    Object.defineProperty(URL, "createObjectURL", { configurable: true, value: createObjectURL });
    Object.defineProperty(URL, "revokeObjectURL", { configurable: true, value: vi.fn() });
    const create = vi.fn(async (_credential, _origin, request) =>
      encryptedCreation(request.wrappingPublicKey, `sha256:${"f".repeat(64)}`)
    );

    await expect(browserNodeEnrollmentCeremony.create(
      repository(create),
      "memory-only-session",
      "https://matrix.example",
      { name: "edge-linux-a", labels: {}, executionPoolId: "linux-pool" }
    )).rejects.toThrow("NODE_ENROLLMENT_JOIN_FILE_NOT_CREATED");

    expect(createObjectURL).not.toHaveBeenCalled();
    expect(document.querySelector("a[download]")).toBeNull();
  }, 15_000);

  it("rejects ciphertext that is not bound to this installation and enrollment", async () => {
    vi.stubGlobal("crypto", webcrypto as unknown as Crypto);
    originalCreateObjectURL = URL.createObjectURL;
    originalRevokeObjectURL = URL.revokeObjectURL;
    const createObjectURL = vi.fn();
    Object.defineProperty(URL, "createObjectURL", { configurable: true, value: createObjectURL });
    Object.defineProperty(URL, "revokeObjectURL", { configurable: true, value: vi.fn() });
    const create = vi.fn(async (_credential, _origin, request) =>
      encryptedCreation(request.wrappingPublicKey, undefined, false)
    );

    await expect(browserNodeEnrollmentCeremony.create(
      repository(create),
      "memory-only-session",
      "https://matrix.example",
      { name: "edge-linux-a", labels: {}, executionPoolId: "linux-pool" }
    )).rejects.toThrow("NODE_ENROLLMENT_JOIN_FILE_NOT_CREATED");

    expect(createObjectURL).not.toHaveBeenCalled();
    expect(document.querySelector("a[download]")).toBeNull();
  }, 15_000);
});
