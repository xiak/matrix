import {
  AUDIT_API_VERSION,
  type AuditAction,
  type AuditActor,
  type AuditQueryRequest,
  type AuditRecord,
  type AuditTargetKind,
  type AuditVerifyRequest
} from "../domain/audit";
import type { AuditRepository } from "./auditRepository";

const digest = (character: string) => `sha256:${character.repeat(64)}`;
const tenantId = "org-xiak";
const cursorSignature = "A".repeat(43);

type Fixture = {
  action: AuditAction;
  source: AuditRecord["source"];
  target: AuditTargetKind;
  result: AuditRecord["event"]["result"];
  actor?: AuditActor;
  operation?: boolean;
};

const fixtures: readonly Fixture[] = [
  { action: "audit.records.read", source: "AUDIT", target: "AUDIT_RECORDS", result: "SUCCEEDED", actor: { type: "USER", id: "principal-auditor", accessKeyId: "key-audit-preview" } },
  { action: "iam.authorization.decided", source: "IAM", target: "AUTHORIZATION_DECISION", result: "ALLOWED", actor: { type: "USER", id: "principal-admin" } },
  { action: "paas.deployment.created", source: "PAAS", target: "DEPLOYMENT", result: "ACCEPTED", actor: { type: "ROLE", id: "role-deployer", roleSession: { sessionId: "role-session-preview", sourceUserId: "principal-developer" } }, operation: true },
  { action: "iam.role-binding.put", source: "IAM", target: "ROLE_BINDING", result: "SUCCEEDED", actor: { type: "USER", id: "principal-admin" } },
  { action: "paas.application.created", source: "PAAS", target: "APPLICATION", result: "SUCCEEDED", actor: { type: "USER", id: "principal-developer" }, operation: true },
  { action: "iam.session.issued", source: "IAM", target: "SESSION", result: "SUCCEEDED", actor: { type: "USER", id: "principal-auditor" } },
  { action: "managedservice.service-installation.ready", source: "PAAS", target: "SERVICE_INSTALLATION", result: "SUCCEEDED", actor: { type: "SYSTEM", id: "service-managedservice" } },
  { action: "audit.integrity.verified", source: "AUDIT", target: "AUDIT_CHAIN", result: "SUCCEEDED", actor: { type: "USER", id: "principal-auditor" } },
  { action: "iam.authorization.decided", source: "IAM", target: "AUTHORIZATION_DECISION", result: "DENIED", actor: { type: "USER", id: "principal-developer" } },
  { action: "paas.deployment.updated", source: "PAAS", target: "DEPLOYMENT", result: "ACCEPTED", actor: { type: "USER", id: "principal-developer" }, operation: true },
  { action: "iam.principal.created", source: "IAM", target: "PRINCIPAL", result: "SUCCEEDED", actor: { type: "USER", id: "principal-admin" } },
  { action: "iam.account-alias.set", source: "IAM", target: "ORGANIZATION", result: "SUCCEEDED", actor: { type: "USER", id: "principal-admin" } }
];

const records: AuditRecord[] = fixtures.map((fixture, index) => {
  const sequence = 114 - index;
  const eventId = `event-preview-${sequence}`;
  const decisionId = `decision-preview-${sequence}`;
  const occurredAt = new Date(Date.UTC(2026, 8, 30, 10, 58 - index * 3, 0)).toISOString();
  return {
    apiVersion: AUDIT_API_VERSION,
    kind: "AuditRecord",
    source: fixture.source,
    sequence,
    event: {
      apiVersion: AUDIT_API_VERSION,
      kind: "AuditEvent",
      eventId,
      authorityKind: "TENANT",
      tenantId,
      actor: fixture.actor ?? { type: "USER", id: "principal-preview-admin" },
      iamDecisionId: fixture.action === "iam.session.issued" ? undefined : decisionId,
      action: fixture.action,
      target: { kind: fixture.target, id: fixture.action === "iam.authorization.decided" ? decisionId : `${fixture.target.toLowerCase()}-${sequence}` },
      result: fixture.result,
      requestDigest: digest(((index + 1) % 10).toString()),
      requestId: `request-preview-${sequence}`,
      correlationId: `correlation-preview-${Math.floor(index / 2) + 1}`,
      operationId: fixture.operation ? `operation-preview-${sequence}` : undefined,
      occurredAt
    },
    contentDigest: digest(((index + 2) % 10).toString()),
    previousHash: index === fixtures.length - 1 ? digest("0") : digest(((index + 3) % 10).toString()),
    recordHash: digest(((index + 4) % 10).toString()),
    ingestedAt: new Date(Date.parse(occurredAt) + 1_000).toISOString(),
    retention: "INDEFINITE"
  };
});

function cursorFor(offset: number): string {
  return `v1.${`preview-offset-${offset}`.padEnd(16, "x")}.${cursorSignature}`;
}

function cursorOffset(cursor?: string): number {
  if (!cursor) return 0;
  for (let offset = 1; offset <= records.length; offset += 1) if (cursor === cursorFor(offset)) return offset;
  throw new Error("INVALID_PREVIEW_CURSOR");
}

export const previewAuditRepository: AuditRepository = {
  async query(_credential: string, request: AuditQueryRequest) {
    const filtered = records.filter((record) =>
      (!request.action || record.event.action === request.action) &&
      (!request.actor || (record.event.actor.type === request.actor.type && record.event.actor.id === request.actor.id)) &&
      (!request.from || record.event.occurredAt >= request.from) &&
      (!request.to || record.event.occurredAt <= request.to)
    );
    const offset = cursorOffset(request.cursor);
    const page = filtered.slice(offset, offset + request.pageSize);
    const nextOffset = offset + page.length;
    await Promise.resolve();
    return {
      apiVersion: AUDIT_API_VERSION,
      kind: "AuditRecordPage",
      authorityKind: "TENANT",
      tenantId,
      records: page,
      nextCursor: nextOffset < filtered.length ? cursorFor(nextOffset) : undefined
    };
  },
  async verify(_credential: string, request: AuditVerifyRequest) {
    const latest = records[0]?.sequence ?? request.fromSequence;
    if (request.fromSequence > latest) throw new Error("INVALID_PREVIEW_SEQUENCE");
    const toSequence = Math.min(latest, request.fromSequence + request.maximumRecords - 1);
    const complete = toSequence >= latest;
    await Promise.resolve();
    return {
      apiVersion: AUDIT_API_VERSION,
      kind: "ChainVerification",
      authorityKind: "TENANT",
      tenantId,
      state: "VERIFIED",
      fromSequence: request.fromSequence,
      toSequence,
      recordCount: toSequence - request.fromSequence + 1,
      firstPreviousHash: digest("0"),
      lastRecordHash: records[0]?.recordHash ?? digest("0"),
      complete,
      nextSequence: complete ? undefined : toSequence + 1,
      verifiedAt: "2026-09-30T11:00:00.000Z"
    };
  }
};
