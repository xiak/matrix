import type {
  CreateNodeEnrollmentRequest,
  NodeEnrollment,
  NodeEnrollmentCreation,
  NodeEnrollmentVersionCommand
} from "../domain/nodeEnrollments";
import {
  NODE_ENROLLMENT_JOIN_FILE_NAME
} from "../domain/nodeEnrollments";
import type { NodeEnrollmentRepository } from "../repositories/nodeEnrollmentRepository";

const wrappingAlgorithm: RsaHashedKeyGenParams = {
  name: "RSA-OAEP",
  modulusLength: 3072,
  publicExponent: new Uint8Array([1, 0, 1]),
  hash: "SHA-256"
};

type EnrollmentIntent = Omit<CreateNodeEnrollmentRequest, "wrappingPublicKey">;

export interface NodeEnrollmentCeremony {
  create(
    repository: NodeEnrollmentRepository,
    credential: string,
    publicOrigin: string,
    intent: EnrollmentIntent
  ): Promise<NodeEnrollment>;
  regenerate(
    repository: NodeEnrollmentRepository,
    credential: string,
    publicOrigin: string,
    command: NodeEnrollmentVersionCommand
  ): Promise<NodeEnrollment>;
}

function rawURLBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function decodeRawURLBase64(value: string, expectedBytes: number): Uint8Array<ArrayBuffer> {
  if (!/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1) {
    throw new Error("NODE_ENROLLMENT_CIPHERTEXT_INVALID");
  }
  let binary: string;
  try {
    binary = atob(value.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat((4 - value.length % 4) % 4));
  } catch {
    throw new Error("NODE_ENROLLMENT_CIPHERTEXT_INVALID");
  }
  if (binary.length !== expectedBytes) throw new Error("NODE_ENROLLMENT_CIPHERTEXT_INVALID");
  const bytes = new Uint8Array(new ArrayBuffer(binary.length));
  for (let index = 0; index < binary.length; index++) bytes[index] = binary.charCodeAt(index);
  return bytes;
}

function hexadecimal(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function wrappingKey(): Promise<{ privateKey: CryptoKey; publicKey: string }> {
  if (!globalThis.crypto?.subtle) throw new Error("NODE_ENROLLMENT_WEB_CRYPTO_UNAVAILABLE");
  const pair = await globalThis.crypto.subtle.generateKey(
    wrappingAlgorithm,
    false,
    ["encrypt", "decrypt"]
  );
  const exported = new Uint8Array(await globalThis.crypto.subtle.exportKey("spki", pair.publicKey));
  try {
    return { privateKey: pair.privateKey, publicKey: rawURLBase64(exported) };
  } finally {
    exported.fill(0);
  }
}

async function decryptCredential(creation: NodeEnrollmentCreation, privateKey: CryptoKey): Promise<Uint8Array<ArrayBuffer>> {
  if (creation.wrappedCredential.algorithm !== "RSA_OAEP_256") {
    throw new Error("NODE_ENROLLMENT_WRAPPING_ALGORITHM_INVALID");
  }
  const ciphertext = decodeRawURLBase64(creation.wrappedCredential.ciphertext, 384);
  try {
    const plaintext = new Uint8Array(await globalThis.crypto.subtle.decrypt(
      { name: "RSA-OAEP" },
      privateKey,
      ciphertext
    ));
    if (plaintext.byteLength !== 32) {
      plaintext.fill(0);
      throw new Error("NODE_ENROLLMENT_CREDENTIAL_INVALID");
    }
    const digest = new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", plaintext));
    try {
      if (`sha256:${hexadecimal(digest)}` !== creation.join.credentialDigest) {
        plaintext.fill(0);
        throw new Error("NODE_ENROLLMENT_CREDENTIAL_DIGEST_MISMATCH");
      }
    } finally {
      digest.fill(0);
    }
    return plaintext;
  } finally {
    ciphertext.fill(0);
  }
}

async function downloadCreation(creation: NodeEnrollmentCreation, privateKey: CryptoKey): Promise<void> {
  const credential = await decryptCredential(creation, privateKey);
  let fileBytes: Uint8Array<ArrayBuffer> | null = null;
  let objectURL: string | null = null;
  let anchor: HTMLAnchorElement | null = null;
  try {
    const source = JSON.stringify({
      apiVersion: "node.installation.matrix.xiak.com/v1",
      kind: "NodeEnrollmentJoinFile",
      join: creation.join,
      credential: rawURLBase64(credential)
    }, null, 2) + "\n";
    fileBytes = new TextEncoder().encode(source);
    const blob = new Blob([fileBytes], { type: "application/json" });
    objectURL = URL.createObjectURL(blob);
    anchor = document.createElement("a");
    anchor.download = NODE_ENROLLMENT_JOIN_FILE_NAME;
    anchor.href = objectURL;
    anchor.hidden = true;
    document.body.append(anchor);
    anchor.click();
  } finally {
    anchor?.remove();
    if (objectURL !== null) URL.revokeObjectURL(objectURL);
    fileBytes?.fill(0);
    credential.fill(0);
  }
}

async function createAndDownload(
  create: (wrappingPublicKey: string) => Promise<NodeEnrollmentCreation>
): Promise<NodeEnrollment> {
  const key = await wrappingKey();
  const creation = await create(key.publicKey);
  try {
    await downloadCreation(creation, key.privateKey);
  } catch {
    throw new Error("NODE_ENROLLMENT_JOIN_FILE_NOT_CREATED");
  }
  return creation.enrollment;
}

export const browserNodeEnrollmentCeremony: NodeEnrollmentCeremony = {
  create(repository, credential, publicOrigin, intent) {
    return createAndDownload(async (wrappingPublicKey) => repository.create(
      credential,
      publicOrigin,
      { ...intent, wrappingPublicKey }
    ));
  },

  regenerate(repository, credential, publicOrigin, command) {
    return createAndDownload((wrappingPublicKey) => repository.regenerate(
      credential,
      publicOrigin,
      command,
      wrappingPublicKey
    ));
  }
};
