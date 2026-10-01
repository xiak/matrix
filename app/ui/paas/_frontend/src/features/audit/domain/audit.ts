export const AUDIT_API_VERSION = "audit.matrix.xiak.com/v1";
export const AUDIT_MAX_PAGE_SIZE = 200;
export const AUDIT_MAX_VERIFY_RECORDS = 10_000;

export const auditSources = ["IAM", "PAAS", "AUDIT"] as const;
export const auditActorTypes = ["USER", "SERVICE_ACCOUNT", "SYSTEM"] as const;
export const auditResults = ["ACCEPTED", "SUCCEEDED", "ALLOWED", "DENIED"] as const;
export const auditRetentions = ["INDEFINITE"] as const;
export const auditActions = [
  "iam.organization.created",
  "iam.account-alias.set",
  "iam.principal.status-set",
  "iam.password.reset",
  "iam.bootstrap.applied",
  "iam.session.issued",
  "iam.session.revoked",
  "iam.password.changed",
  "iam.principal.created",
  "iam.role-binding.put",
  "iam.role-binding.revoked",
  "iam.authorization.decided",
  "paas.application.created",
  "paas.configuration.created",
  "paas.configuration-revision.created",
  "paas.application-revision.created",
  "paas.deployment.created",
  "paas.deployment.updated",
  "paas.deployment.stopped",
  "paas.deployment.rolled-back",
  "managedservice.quota-entitlement.activated",
  "managedservice.service-installation.created",
  "managedservice.service-installation.ready",
  "audit.records.read",
  "audit.integrity.verified"
] as const;

export type AuditSource = typeof auditSources[number];
export type AuditActorType = typeof auditActorTypes[number];
export type AuditResult = typeof auditResults[number];
export type AuditAction = typeof auditActions[number];

export type AuditActor = { type: AuditActorType; id: string };
export type AuditTarget = { kind: string; id: string };
export type AuditEvent = {
  apiVersion: typeof AUDIT_API_VERSION;
  kind: "AuditEvent";
  eventId: string;
  tenantId: string;
  actor: AuditActor;
  iamDecisionId?: string;
  action: AuditAction;
  target: AuditTarget;
  result: AuditResult;
  requestDigest: string;
  requestId: string;
  correlationId: string;
  operationId?: string;
  traceparent?: string;
  occurredAt: string;
};

export type AuditRecord = {
  apiVersion: typeof AUDIT_API_VERSION;
  kind: "AuditRecord";
  source: AuditSource;
  sequence: number;
  event: AuditEvent;
  contentDigest: string;
  previousHash: string;
  recordHash: string;
  ingestedAt: string;
  retention: "INDEFINITE";
};

export type AuditQueryRequest = {
  pageSize: number;
  cursor?: string;
  from?: string;
  to?: string;
  action?: AuditAction;
  actor?: AuditActor;
};

export type AuditRecordPage = {
  apiVersion: typeof AUDIT_API_VERSION;
  kind: "AuditRecordPage";
  tenantId: string;
  records: AuditRecord[];
  nextCursor?: string;
};

export type AuditVerifyRequest = { fromSequence: number; maximumRecords: number };
export type AuditChainVerification = {
  apiVersion: typeof AUDIT_API_VERSION;
  kind: "ChainVerification";
  tenantId: string;
  state: "VERIFIED";
  fromSequence: number;
  toSequence: number;
  recordCount: number;
  firstPreviousHash: string;
  lastRecordHash: string;
  complete: boolean;
  nextSequence?: number;
  verifiedAt: string;
};

const idPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const digestPattern = /^sha256:[0-9a-f]{64}$/;
const cursorPattern = /^v1\.[A-Za-z0-9_-]{16,2048}\.[A-Za-z0-9_-]{43}$/;
const traceparentPattern = /^00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$/;

function object(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`INVALID_${label}`);
  return value as Record<string, unknown>;
}

function exactKeys(value: Record<string, unknown>, required: readonly string[], optional: readonly string[], label: string) {
  const accepted = new Set([...required, ...optional]);
  if (required.some((key) => !(key in value)) || Object.keys(value).some((key) => !accepted.has(key))) throw new Error(`INVALID_${label}`);
}

function text(value: unknown, label: string, pattern?: RegExp): string {
  if (typeof value !== "string" || !value || value.trim() !== value || (pattern && !pattern.test(value))) throw new Error(`INVALID_${label}`);
  return value;
}

function member<T extends string>(value: unknown, values: readonly T[], label: string): T {
  if (typeof value !== "string" || !values.includes(value as T)) throw new Error(`INVALID_${label}`);
  return value as T;
}

function integer(value: unknown, minimum: number, maximum: number, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < minimum || value > maximum) throw new Error(`INVALID_${label}`);
  return value;
}

function timestamp(value: unknown, label: string): string {
  const result = text(value, label);
  if (!result.endsWith("Z") || Number.isNaN(Date.parse(result))) throw new Error(`INVALID_${label}`);
  return result;
}

function optionalText(value: Record<string, unknown>, key: string, label: string, pattern?: RegExp): string | undefined {
  return key in value ? text(value[key], label, pattern) : undefined;
}

function parseActor(value: unknown): AuditActor {
  const data = object(value, "AUDIT_ACTOR");
  exactKeys(data, ["type", "id"], [], "AUDIT_ACTOR");
  return { type: member(data.type, auditActorTypes, "AUDIT_ACTOR_TYPE"), id: text(data.id, "AUDIT_ACTOR_ID", idPattern) };
}

function parseEvent(value: unknown): AuditEvent {
  const data = object(value, "AUDIT_EVENT");
  exactKeys(data, ["apiVersion", "kind", "eventId", "tenantId", "actor", "action", "target", "result", "requestDigest", "requestId", "correlationId", "occurredAt"], ["iamDecisionId", "operationId", "traceparent"], "AUDIT_EVENT");
  if (data.apiVersion !== AUDIT_API_VERSION || data.kind !== "AuditEvent") throw new Error("INVALID_AUDIT_EVENT_TYPE");
  const target = object(data.target, "AUDIT_TARGET");
  exactKeys(target, ["kind", "id"], [], "AUDIT_TARGET");
  return {
    apiVersion: AUDIT_API_VERSION,
    kind: "AuditEvent",
    eventId: text(data.eventId, "AUDIT_EVENT_ID", idPattern),
    tenantId: text(data.tenantId, "AUDIT_TENANT_ID", idPattern),
    actor: parseActor(data.actor),
    iamDecisionId: optionalText(data, "iamDecisionId", "AUDIT_DECISION_ID", idPattern),
    action: member(data.action, auditActions, "AUDIT_ACTION"),
    target: { kind: text(target.kind, "AUDIT_TARGET_KIND"), id: text(target.id, "AUDIT_TARGET_ID", idPattern) },
    result: member(data.result, auditResults, "AUDIT_RESULT"),
    requestDigest: text(data.requestDigest, "AUDIT_REQUEST_DIGEST", digestPattern),
    requestId: text(data.requestId, "AUDIT_REQUEST_ID", idPattern),
    correlationId: text(data.correlationId, "AUDIT_CORRELATION_ID", idPattern),
    operationId: optionalText(data, "operationId", "AUDIT_OPERATION_ID", idPattern),
    traceparent: optionalText(data, "traceparent", "AUDIT_TRACEPARENT", traceparentPattern),
    occurredAt: timestamp(data.occurredAt, "AUDIT_OCCURRED_AT")
  };
}

function parseRecord(value: unknown): AuditRecord {
  const data = object(value, "AUDIT_RECORD");
  exactKeys(data, ["apiVersion", "kind", "source", "sequence", "event", "contentDigest", "previousHash", "recordHash", "ingestedAt", "retention"], [], "AUDIT_RECORD");
  if (data.apiVersion !== AUDIT_API_VERSION || data.kind !== "AuditRecord") throw new Error("INVALID_AUDIT_RECORD_TYPE");
  return {
    apiVersion: AUDIT_API_VERSION,
    kind: "AuditRecord",
    source: member(data.source, auditSources, "AUDIT_SOURCE"),
    sequence: integer(data.sequence, 1, Number.MAX_SAFE_INTEGER, "AUDIT_SEQUENCE"),
    event: parseEvent(data.event),
    contentDigest: text(data.contentDigest, "AUDIT_CONTENT_DIGEST", digestPattern),
    previousHash: text(data.previousHash, "AUDIT_PREVIOUS_HASH", digestPattern),
    recordHash: text(data.recordHash, "AUDIT_RECORD_HASH", digestPattern),
    ingestedAt: timestamp(data.ingestedAt, "AUDIT_INGESTED_AT"),
    retention: member(data.retention, auditRetentions, "AUDIT_RETENTION")
  };
}

export function parseAuditRecordPage(value: unknown): AuditRecordPage {
  const data = object(value, "AUDIT_RECORD_PAGE");
  exactKeys(data, ["apiVersion", "kind", "tenantId", "records"], ["nextCursor"], "AUDIT_RECORD_PAGE");
  if (data.apiVersion !== AUDIT_API_VERSION || data.kind !== "AuditRecordPage" || !Array.isArray(data.records) || data.records.length > AUDIT_MAX_PAGE_SIZE) throw new Error("INVALID_AUDIT_RECORD_PAGE");
  const tenantId = text(data.tenantId, "AUDIT_TENANT_ID", idPattern);
  const records = data.records.map(parseRecord);
  if (records.some((record) => record.event.tenantId !== tenantId) || records.some((record, index) => index > 0 && records[index - 1]!.sequence <= record.sequence)) throw new Error("INVALID_AUDIT_RECORD_ORDER");
  const nextCursor = optionalText(data, "nextCursor", "AUDIT_CURSOR", cursorPattern);
  return { apiVersion: AUDIT_API_VERSION, kind: "AuditRecordPage", tenantId, records, nextCursor };
}

export function parseAuditChainVerification(value: unknown): AuditChainVerification {
  const data = object(value, "AUDIT_CHAIN_VERIFICATION");
  exactKeys(data, ["apiVersion", "kind", "tenantId", "state", "fromSequence", "toSequence", "recordCount", "firstPreviousHash", "lastRecordHash", "complete", "verifiedAt"], ["nextSequence"], "AUDIT_CHAIN_VERIFICATION");
  if (data.apiVersion !== AUDIT_API_VERSION || data.kind !== "ChainVerification" || data.state !== "VERIFIED" || typeof data.complete !== "boolean") throw new Error("INVALID_AUDIT_CHAIN_VERIFICATION");
  const fromSequence = integer(data.fromSequence, 1, Number.MAX_SAFE_INTEGER, "AUDIT_FROM_SEQUENCE");
  const toSequence = integer(data.toSequence, fromSequence, Number.MAX_SAFE_INTEGER, "AUDIT_TO_SEQUENCE");
  const recordCount = integer(data.recordCount, 1, AUDIT_MAX_VERIFY_RECORDS, "AUDIT_RECORD_COUNT");
  const nextSequence = "nextSequence" in data ? integer(data.nextSequence, toSequence + 1, Number.MAX_SAFE_INTEGER, "AUDIT_NEXT_SEQUENCE") : undefined;
  if (recordCount !== toSequence - fromSequence + 1 || (data.complete ? nextSequence !== undefined : nextSequence !== toSequence + 1)) throw new Error("INVALID_AUDIT_CHAIN_RANGE");
  return {
    apiVersion: AUDIT_API_VERSION,
    kind: "ChainVerification",
    tenantId: text(data.tenantId, "AUDIT_TENANT_ID", idPattern),
    state: "VERIFIED",
    fromSequence,
    toSequence,
    recordCount,
    firstPreviousHash: text(data.firstPreviousHash, "AUDIT_FIRST_HASH", digestPattern),
    lastRecordHash: text(data.lastRecordHash, "AUDIT_LAST_HASH", digestPattern),
    complete: data.complete,
    nextSequence,
    verifiedAt: timestamp(data.verifiedAt, "AUDIT_VERIFIED_AT")
  };
}
