import { requestJSON, requestJSONWithResponse, requestToken } from "@/infrastructure/http/jsonRequest";
import type {
  ExecutionPoolChoice,
  NodeEnrollment,
  NodeEnrollmentCreation,
  NodeEnrollmentDiagnostic,
  NodeEnrollmentDiagnosticCode,
  NodeEnrollmentInventory,
  NodeEnrollmentJoin,
  NodeEnrollmentState,
  NodeEnrollmentVersionCommand,
  WrappedJoinCredential
} from "../domain/nodeEnrollments";
import type { NodeEnrollmentRepository } from "./nodeEnrollmentRepository";

type UnknownRecord = Record<string, unknown>;

const apiVersion = "paas.matrix.xiak.com/v1";
const enrollmentIDPattern = /^node-enrollment-[0-9a-f]{32}$/;
const identifierPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const namePattern = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const digestPattern = /^sha256:[0-9a-f]{64}$/;
const rawURLBase64Pattern = /^[A-Za-z0-9_-]+$/;
const nodeEnrollmentIngressPort = "8443";
const states = new Set<NodeEnrollmentState>([
  "WAITING_INSTALL", "VERIFYING", "READY", "FAILED", "EXPIRED", "REVOKED"
]);
const diagnosticCodes = new Set<NodeEnrollmentDiagnosticCode>([
  "ENROLLMENT_EXPIRED", "ENROLLMENT_REVOKED", "CREDENTIAL_CONSUMED",
  "INSTALLATION_MISMATCH", "IDENTITY_CONFLICT", "RUNTIME_UNSUPPORTED",
  "MANAGEMENT_UNREACHABLE", "MTLS_VERIFICATION_FAILED", "RESOURCE_CONFLICT",
  "NETWORK_INTERRUPTED"
]);

function invalid(name: string): Error {
  return new Error(`INVALID_${name.toUpperCase().replaceAll(/[^A-Z0-9]+/g, "_")}_RESPONSE`);
}

function record(value: unknown, name: string): UnknownRecord {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw invalid(name);
  return value as UnknownRecord;
}

function closed(value: unknown, name: string, keys: readonly string[]): UnknownRecord {
  const wire = record(value, name);
  const allowed = new Set(keys);
  if (Object.keys(wire).some((key) => !allowed.has(key))) throw invalid(name);
  return wire;
}

function text(value: unknown, name: string): string {
  if (typeof value !== "string" || value.length === 0) throw invalid(name);
  return value;
}

function safeText(value: unknown, name: string, maximum: number): string {
  if (typeof value !== "string") throw invalid(name);
  const result = value;
  if (new TextEncoder().encode(result).byteLength > maximum || result.trim() !== result ||
      /[\u0000-\u001f\u007f]/.test(result)) throw invalid(name);
  return result;
}

function identifier(value: unknown, name: string): string {
  const result = text(value, name);
  if (!identifierPattern.test(result)) throw invalid(name);
  return result;
}

function timestamp(value: unknown, name: string): string {
  const result = text(value, name);
  if (!Number.isFinite(Date.parse(result))) throw invalid(name);
  return result;
}

function integer(value: unknown, name: string, positive = false): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < (positive ? 1 : 0)) {
    throw invalid(name);
  }
  return value;
}

function labels(value: unknown, name: string): Record<string, string> {
  if (value === undefined) return {};
  const wire = record(value, name);
  if (Object.keys(wire).length > 64) throw invalid(name);
  const result: Record<string, string> = {};
  for (const [key, item] of Object.entries(wire)) {
    if (!namePattern.test(key)) throw invalid(name);
    result[key] = safeText(item, `${name} value`, 128);
  }
  return result;
}

function rawURLBase64Length(value: unknown, name: string): number {
  const result = text(value, name);
  if (!rawURLBase64Pattern.test(result) || result.length % 4 === 1) throw invalid(name);
  try {
    return atob(result.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat((4 - result.length % 4) % 4)).length;
  } catch {
    throw invalid(name);
  }
}

function platformMetadata(value: unknown, name: string) {
  const wire = closed(value, name, ["id", "name", "scope", "labels", "resourceVersion", "createdAt", "updatedAt"]);
  const scope = closed(wire.scope, `${name} scope`, ["kind", "tenantId"]);
  const id = identifier(wire.id, `${name} id`);
  const displayName = text(wire.name, `${name} name`);
  const createdAt = timestamp(wire.createdAt, `${name} created time`);
  const updatedAt = timestamp(wire.updatedAt, `${name} updated time`);
  if (scope.kind !== "PLATFORM" || Object.hasOwn(scope, "tenantId") || !namePattern.test(displayName) ||
      Date.parse(updatedAt) < Date.parse(createdAt)) {
    throw invalid(name);
  }
  return {
    id,
    name: displayName,
    labels: labels(wire.labels, `${name} labels`),
    resourceVersion: integer(wire.resourceVersion, `${name} resource version`, true),
    createdAt,
    updatedAt
  };
}

function executionPool(value: unknown): ExecutionPoolChoice {
  const wire = closed(value, "execution pool", ["apiVersion", "kind", "metadata", "spec", "status"]);
  if (wire.apiVersion !== apiVersion || wire.kind !== "ExecutionPool") throw invalid("execution pool");
  const metadata = platformMetadata(wire.metadata, "execution pool metadata");
  const spec = closed(wire.spec, "execution pool spec", ["executionTargetSelector", "allowedIsolationGuarantees"]);
  const selector = closed(spec.executionTargetSelector, "execution pool selector", ["matchLabels"]);
  const selectorLabels = labels(selector.matchLabels, "execution pool selector labels");
  if (!Array.isArray(spec.allowedIsolationGuarantees) || spec.allowedIsolationGuarantees.length === 0 ||
      spec.allowedIsolationGuarantees.some((item) => !["WORKLOAD", "TENANT", "HOST"].includes(String(item))) ||
      new Set(spec.allowedIsolationGuarantees).size !== spec.allowedIsolationGuarantees.length) {
    throw invalid("execution pool isolation guarantees");
  }
  const status = closed(wire.status, "execution pool status", [
    "phase", "executionTargetCount", "readyExecutionTargetCount", "observedAt"
  ]);
  if (status.phase !== "READY" && status.phase !== "DEGRADED" && status.phase !== "UNAVAILABLE") {
    throw invalid("execution pool phase");
  }
  const targetCount = integer(status.executionTargetCount, "execution pool target count");
  const readyTargetCount = integer(status.readyExecutionTargetCount, "execution pool ready target count");
  if (readyTargetCount > targetCount) throw invalid("execution pool target count");
  return {
    id: metadata.id,
    name: metadata.name,
    resourceVersion: metadata.resourceVersion,
    selectorLabels,
    phase: status.phase,
    targetCount,
    readyTargetCount,
    observedAt: timestamp(status.observedAt, "execution pool observation")
  };
}

function diagnostic(value: unknown): NodeEnrollmentDiagnostic {
  const wire = closed(value, "node enrollment diagnostic", ["code", "retryable", "occurredAt"]);
  if (!diagnosticCodes.has(wire.code as NodeEnrollmentDiagnosticCode) || typeof wire.retryable !== "boolean") {
    throw invalid("node enrollment diagnostic");
  }
  const code = wire.code as NodeEnrollmentDiagnosticCode;
  const retryable = code === "MANAGEMENT_UNREACHABLE" || code === "NETWORK_INTERRUPTED";
  if (wire.retryable !== retryable) throw invalid("node enrollment diagnostic retryability");
  return { code, retryable, occurredAt: timestamp(wire.occurredAt, "node enrollment diagnostic time") };
}

function optionalTimestamp(wire: UnknownRecord, key: string): string | null {
  return Object.hasOwn(wire, key) ? timestamp(wire[key], `node enrollment ${key}`) : null;
}

function nodeEnrollment(value: unknown): NodeEnrollment {
  const wire = closed(value, "node enrollment", [
    "apiVersion", "kind", "metadata", "executionTargetId", "executionPoolId", "operationId",
    "state", "expiresAt", "credentialConsumedAt", "readyAt", "replacedById", "diagnostic"
  ]);
  if (wire.apiVersion !== apiVersion || wire.kind !== "NodeEnrollment" ||
      !states.has(wire.state as NodeEnrollmentState)) throw invalid("node enrollment");
  const metadata = platformMetadata(wire.metadata, "node enrollment metadata");
  if (!enrollmentIDPattern.test(metadata.id)) throw invalid("node enrollment id");
  if (Object.hasOwn(metadata.labels, "matrix-machine-fingerprint")) throw invalid("node enrollment labels");
  const expiresAt = timestamp(wire.expiresAt, "node enrollment expiry");
  const credentialConsumedAt = optionalTimestamp(wire, "credentialConsumedAt");
  const readyAt = optionalTimestamp(wire, "readyAt");
  const replacedById = Object.hasOwn(wire, "replacedById")
    ? text(wire.replacedById, "replacement enrollment id")
    : null;
  if (replacedById !== null && !enrollmentIDPattern.test(replacedById)) throw invalid("replacement enrollment id");
  const diagnosticValue = Object.hasOwn(wire, "diagnostic") ? diagnostic(wire.diagnostic) : null;
  const state = wire.state as NodeEnrollmentState;
  const created = Date.parse(metadata.createdAt);
  const updated = Date.parse(metadata.updatedAt);
  const expiry = Date.parse(expiresAt);
  const consumed = credentialConsumedAt === null ? null : Date.parse(credentialConsumedAt);
  const ready = readyAt === null ? null : Date.parse(readyAt);
  const diagnosticAt = diagnosticValue === null ? null : Date.parse(diagnosticValue.occurredAt);
  if (expiry <= created || expiry - created > 30 * 60_000 ||
      (consumed !== null && (consumed < created || consumed > updated || consumed >= expiry)) ||
      (ready !== null && (consumed === null || ready < consumed || ready > updated || ready > expiry)) ||
      (diagnosticAt !== null && (diagnosticAt < created || diagnosticAt > updated))) {
    throw invalid("node enrollment timeline");
  }
  const validState =
    (state === "WAITING_INSTALL" && consumed === null && ready === null && replacedById === null && diagnosticValue === null) ||
    (state === "VERIFYING" && consumed !== null && ready === null && replacedById === null && diagnosticValue === null) ||
    (state === "READY" && consumed !== null && ready !== null && replacedById === null && diagnosticValue === null) ||
    (state === "FAILED" && consumed !== null && ready === null && replacedById === null && diagnosticValue !== null &&
      diagnosticValue.code !== "ENROLLMENT_EXPIRED" && diagnosticValue.code !== "ENROLLMENT_REVOKED") ||
    (state === "EXPIRED" && ready === null && replacedById === null && diagnosticValue?.code === "ENROLLMENT_EXPIRED" && updated >= expiry) ||
    (state === "REVOKED" && ready === null && diagnosticValue?.code === "ENROLLMENT_REVOKED");
  if (!validState) throw invalid("node enrollment state");
  return {
    ...metadata,
    executionTargetId: identifier(wire.executionTargetId, "node enrollment target id"),
    executionPoolId: identifier(wire.executionPoolId, "node enrollment pool id"),
    operationId: identifier(wire.operationId, "node enrollment operation id"),
    state,
    expiresAt,
    credentialConsumedAt,
    readyAt,
    replacedById,
    diagnostic: diagnosticValue
  };
}

function executionPoolList(value: unknown): ExecutionPoolChoice[] {
  const wire = closed(value, "execution pool list", ["apiVersion", "kind", "items"]);
  if (wire.apiVersion !== apiVersion || wire.kind !== "ExecutionPoolList" ||
      !Array.isArray(wire.items) || wire.items.length > 129) throw invalid("execution pool list");
  const items = wire.items.map(executionPool);
  if (new Set(items.map((item) => item.id)).size !== items.length) throw invalid("execution pool list");
  return items;
}

function nodeEnrollmentList(value: unknown): NodeEnrollment[] {
  const wire = closed(value, "node enrollment list", ["apiVersion", "kind", "items"]);
  if (wire.apiVersion !== apiVersion || wire.kind !== "NodeEnrollmentList" ||
      !Array.isArray(wire.items) || wire.items.length > 128) throw invalid("node enrollment list");
  const items = wire.items.map(nodeEnrollment);
  if (new Set(items.map((item) => item.id)).size !== items.length) throw invalid("node enrollment list");
  return items;
}

function publicOrigin(value: string): string {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw invalid("node enrollment public origin");
  }
  if ((parsed.protocol !== "http:" && parsed.protocol !== "https:") ||
      parsed.username !== "" || parsed.password !== "" ||
      parsed.pathname !== "/" || parsed.search !== "" || parsed.hash !== "" || parsed.origin !== value) {
    throw invalid("node enrollment public origin");
  }
  // The console is served by the signed HTTP edge, while node bootstrap owns
  // a separate TLS-only listener. Keep the browser from selecting an endpoint:
  // retain only the current authority host and use the product-owned port.
  parsed.protocol = "https:";
  parsed.port = nodeEnrollmentIngressPort;
  return parsed.origin;
}

function join(value: unknown, enrollment: NodeEnrollment, origin: string): NodeEnrollmentJoin {
  const wire = closed(value, "node enrollment join", [
    "apiVersion", "kind", "enrollmentId", "installationId", "executionTargetId",
    "controlPlaneUrl", "credentialDigest", "expiresAt", "issuerCertificate",
    "signatureAlgorithm", "signature"
  ]);
  const expectedURL = `${origin}/api/paas/v1/node-enrollments/${encodeURIComponent(enrollment.id)}/exchange`;
  if (wire.apiVersion !== "node.enrollment.matrix.xiak.com/v1" || wire.kind !== "NodeEnrollmentJoin" ||
      wire.enrollmentId !== enrollment.id || wire.executionTargetId !== enrollment.executionTargetId ||
      wire.expiresAt !== enrollment.expiresAt || wire.controlPlaneUrl !== expectedURL ||
      wire.signatureAlgorithm !== "ED25519" || !digestPattern.test(String(wire.credentialDigest)) ||
      rawURLBase64Length(wire.issuerCertificate, "node enrollment issuer certificate") > 4096 ||
      rawURLBase64Length(wire.signature, "node enrollment signature") !== 64) {
    throw invalid("node enrollment join");
  }
  return {
    apiVersion: wire.apiVersion,
    kind: wire.kind,
    enrollmentId: wire.enrollmentId,
    installationId: identifier(wire.installationId, "node enrollment installation id"),
    executionTargetId: wire.executionTargetId,
    controlPlaneUrl: wire.controlPlaneUrl,
    credentialDigest: wire.credentialDigest,
    expiresAt: wire.expiresAt,
    issuerCertificate: wire.issuerCertificate,
    signatureAlgorithm: wire.signatureAlgorithm,
    signature: wire.signature
  } as NodeEnrollmentJoin;
}

function wrappedCredential(value: unknown): WrappedJoinCredential {
  const wire = closed(value, "wrapped join credential", ["algorithm", "ciphertext"]);
  if (wire.algorithm !== "RSA_OAEP_256" || rawURLBase64Length(wire.ciphertext, "wrapped join credential") !== 384) {
    throw invalid("wrapped join credential");
  }
  return { algorithm: wire.algorithm, ciphertext: wire.ciphertext as string };
}

function creation(value: unknown, origin: string): NodeEnrollmentCreation {
  const wire = closed(value, "node enrollment creation", ["enrollment", "join", "wrappedCredential"]);
  const enrollment = nodeEnrollment(wire.enrollment);
  if (enrollment.state !== "WAITING_INSTALL") throw invalid("node enrollment creation");
  return {
    enrollment,
    join: join(wire.join, enrollment, origin),
    wrappedCredential: wrappedCredential(wire.wrappedCredential)
  };
}

function exactETag(response: Response, resourceVersion: number): string {
  const etag = response.headers.get("ETag");
  if (etag !== `"${resourceVersion}"`) throw invalid("node enrollment etag");
  return etag;
}

async function currentEnrollment(
  credential: string,
  command: NodeEnrollmentVersionCommand
): Promise<{ enrollment: NodeEnrollment; etag: string }> {
  const path = `/api/paas/v1/node-enrollments/${encodeURIComponent(command.enrollmentId)}`;
  const result = await requestJSONWithResponse<unknown>(path, {
    headers: { Authorization: `Bearer ${credential}` }
  });
  const enrollment = nodeEnrollment(result.body);
  if (enrollment.id !== command.enrollmentId || enrollment.resourceVersion !== command.resourceVersion) {
    throw new Error("STALE_NODE_ENROLLMENT_COMMAND");
  }
  return { enrollment, etag: exactETag(result.response, enrollment.resourceVersion) };
}

function creationHeaders(credential: string, origin: string, etag?: string): Record<string, string> {
  return {
    Authorization: `Bearer ${credential}`,
    "Content-Type": "application/json",
    "Idempotency-Key": requestToken("ui-node-enrollment-"),
    "X-Matrix-Public-Origin": origin,
    ...(etag ? { "If-Match": etag } : {})
  };
}

export const httpNodeEnrollmentRepository: NodeEnrollmentRepository = {
  async load(credential, signal): Promise<NodeEnrollmentInventory> {
    const authorization = { Authorization: `Bearer ${credential}` };
    const [pools, enrollments] = await Promise.all([
      requestJSON<unknown>("/api/paas/v1/execution-pools", { headers: authorization, signal }),
      requestJSON<unknown>("/api/paas/v1/node-enrollments", { headers: authorization, signal })
    ]);
    return { pools: executionPoolList(pools), enrollments: nodeEnrollmentList(enrollments) };
  },

  async create(credential, requestedOrigin, request) {
    const origin = publicOrigin(requestedOrigin);
    const result = await requestJSONWithResponse<unknown>("/api/paas/v1/node-enrollments", {
      method: "POST",
      headers: creationHeaders(credential, origin),
      body: JSON.stringify(request)
    });
    const value = creation(result.body, origin);
    exactETag(result.response, value.enrollment.resourceVersion);
    return value;
  },

  async revoke(credential, command) {
    const current = await currentEnrollment(credential, command);
    const path = `/api/paas/v1/node-enrollments/${encodeURIComponent(command.enrollmentId)}/revoke`;
    const result = await requestJSONWithResponse<unknown>(path, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${credential}`,
        "Idempotency-Key": requestToken("ui-node-enrollment-revoke-"),
        "If-Match": current.etag
      }
    });
    const enrollment = nodeEnrollment(result.body);
    if (enrollment.id !== command.enrollmentId || enrollment.state !== "REVOKED" ||
        enrollment.resourceVersion <= command.resourceVersion) throw invalid("node enrollment revoke");
    exactETag(result.response, enrollment.resourceVersion);
    return enrollment;
  },

  async regenerate(credential, requestedOrigin, command, wrappingPublicKey) {
    const origin = publicOrigin(requestedOrigin);
    const current = await currentEnrollment(credential, command);
    const path = `/api/paas/v1/node-enrollments/${encodeURIComponent(command.enrollmentId)}/regenerate`;
    const result = await requestJSONWithResponse<unknown>(path, {
      method: "POST",
      headers: creationHeaders(credential, origin, current.etag),
      body: JSON.stringify({ wrappingPublicKey })
    });
    const value = creation(result.body, origin);
    if (value.enrollment.id === command.enrollmentId) throw invalid("node enrollment regeneration");
    exactETag(result.response, value.enrollment.resourceVersion);
    return value;
  }
};
