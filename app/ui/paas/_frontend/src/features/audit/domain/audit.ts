export const AUDIT_API_VERSION = "audit.matrix.xiak.com/v1";
export const AUDIT_MAX_PAGE_SIZE = 200;
export const AUDIT_MAX_VERIFY_RECORDS = 10_000;

export const auditSources = ["IAM", "PAAS", "DEVOPS", "AUDIT"] as const;
export const auditActorTypes = ["USER", "ROLE", "SERVICE_ACCOUNT", "SYSTEM"] as const;
export const auditRetentions = ["INDEFINITE"] as const;
// Each action admits one target kind and a closed set of results in Audit v1.
export const auditEventVariants = [
  { target: "ACCOUNT", results: ["SUCCEEDED"], actions: [
    "iam.account.created", "iam.account.disabled", "iam.account.enabled", "iam.account.alias-set",
    "iam.security-settings.updated"
  ] },
  { target: "USER", results: ["SUCCEEDED"], actions: [
    "iam.account-root.credentials-recovered", "iam.user.created", "iam.user.updated", "iam.user.deleted",
    "iam.user.permission-boundary.set", "iam.user.permission-boundary.removed", "iam.user.status-set",
    "iam.user.password-reset", "iam.user.password-changed", "iam.notification-contact.verification-started",
    "iam.notification-contact.verified", "iam.notification-contact.replaced"
  ] },
  { target: "USER", results: ["DENIED"], actions: ["iam.user.password-reset-required"] },
  { target: "PRINCIPAL", results: ["SUCCEEDED"], actions: [
    "iam.authenticator.bound", "iam.authenticator.replaced", "iam.authenticator.removed",
    "iam.authenticator.recovery-started", "iam.authenticator.recovered", "iam.recovery-codes.regenerated",
    "iam.tenant-administrator.recovered", "iam.installation-primary.credentials-recovered",
    "iam.principal.status-set", "iam.password.reset", "iam.session.others-revoked", "iam.password.changed",
    "iam.principal.created"
  ] },
  { target: "GROUP", results: ["SUCCEEDED"], actions: [
    "iam.group.created", "iam.group.updated", "iam.group.deleted"
  ] },
  { target: "ROLE", results: ["SUCCEEDED"], actions: [
    "iam.role.created", "iam.role.updated", "iam.role.disabled", "iam.role.enabled", "iam.role.trust-set",
    "iam.role.deleted", "iam.role.permission-boundary.set", "iam.role.permission-boundary.removed",
    "iam.service-linked-role.created"
  ] },
  { target: "ROLE_SESSION", results: ["SUCCEEDED"], actions: [
    "iam.role-session.issued", "iam.role-session.revoked", "iam.role-session.admin-revoked",
    "iam.role-session.exited", "iam.service-role-session.issued"
  ] },
  { target: "WORKLOAD_ROLE_BINDING", results: ["SUCCEEDED"], actions: [
    "iam.workload-role-binding.created", "iam.workload-role-binding.revoked"
  ] },
  { target: "ACCESS_KEY", results: ["SUCCEEDED"], actions: [
    "iam.access-key.created", "iam.access-key.enabled", "iam.access-key.disabled",
    "iam.access-key.network-restrictions-updated", "iam.access-key.deleted",
    "iam.access-key.automatically-disabled"
  ] },
  { target: "SECURITY_REPORT", results: ["SUCCEEDED"], actions: [
    "iam.security-report.created", "iam.security-report.download-started"
  ] },
  { target: "ACCESS_ANALYZER", results: ["SUCCEEDED"], actions: [
    "iam.access-analyzer.created", "iam.access-analyzer.updated", "iam.access-analyzer.disposition-updated"
  ] },
  { target: "ACCESS_FINDING", results: ["SUCCEEDED"], actions: [
    "iam.access-finding.detected", "iam.access-finding.resolved", "iam.access-finding.archived",
    "iam.access-finding.unarchived"
  ] },
  { target: "POLICY", results: ["SUCCEEDED"], actions: [
    "iam.policy.created", "iam.policy-version.created", "iam.policy-version.deleted",
    "iam.policy.default-version-set", "iam.policy.updated", "iam.policy.deleted"
  ] },
  { target: "GROUP_MEMBERSHIP", results: ["SUCCEEDED"], actions: [
    "iam.group-membership.created", "iam.group-membership.removed"
  ] },
  { target: "ORGANIZATION", results: ["SUCCEEDED"], actions: [
    "iam.organization.created", "iam.tenant.created", "iam.tenant.disabled", "iam.tenant.enabled",
    "iam.account-alias.set"
  ] },
  { target: "INSTALLATION", results: ["SUCCEEDED"], actions: [
    "iam.authentication-recovery.closed", "iam.authentication-recovery.reconciled",
    "iam.authentication-recovery.reopened", "iam.bootstrap.applied"
  ] },
  { target: "SESSION", results: ["SUCCEEDED"], actions: [
    "iam.session.issued", "iam.session.revoked"
  ] },
  { target: "ROLE_BINDING", results: ["SUCCEEDED"], actions: [
    "iam.role-binding.put", "iam.role-binding.revoked"
  ] },
  { target: "POLICY_ATTACHMENT", results: ["SUCCEEDED"], actions: [
    "iam.policy-attachment.created", "iam.policy-attachment.revoked", "iam.platform-policy-attachment.created",
    "iam.platform-policy-attachment.revoked"
  ] },
  { target: "AUTHORIZATION_DECISION", results: ["ALLOWED", "DENIED"], actions: ["iam.authorization.decided"] },
  { target: "APPLICATION", results: ["SUCCEEDED"], actions: [
    "paas.application.created", "paas.application-label.updated", "paas.application-label.deleted"
  ] },
  { target: "CONFIGURATION", results: ["SUCCEEDED"], actions: ["paas.configuration.created"] },
  { target: "CONFIGURATION_REVISION", results: ["SUCCEEDED"], actions: ["paas.configuration-revision.created"] },
  { target: "APPLICATION_REVISION", results: ["SUCCEEDED"], actions: ["paas.application-revision.created"] },
  { target: "DEPLOYMENT", results: ["ACCEPTED"], actions: [
    "paas.deployment.created", "paas.deployment.updated", "paas.deployment.stopped", "paas.deployment.rolled-back"
  ] },
  { target: "EXECUTION_POOL", results: ["SUCCEEDED"], actions: ["paas.execution-pool.created"] },
  { target: "EXECUTION_TARGET", results: ["SUCCEEDED"], actions: [
    "paas.execution-target.registered", "paas.execution-target.drained", "paas.execution-target.activated",
    "paas.execution-target.removed"
  ] },
  { target: "TERMINAL_SESSION", results: ["ACCEPTED"], actions: ["paas.terminal-session.created"] },
  { target: "TERMINAL_SESSION", results: ["SUCCEEDED"], actions: ["paas.terminal-session.started"] },
  { target: "TERMINAL_SESSION", results: ["COMPLETED", "UNSUPPORTED", "EXPIRED", "DISCONNECTED", "REVOKED", "REPLACED", "FAILED"], actions: ["paas.terminal-session.ended"] },
  { target: "QUOTA_ENTITLEMENT", results: ["SUCCEEDED"], actions: ["managedservice.quota-entitlement.activated"] },
  { target: "SERVICE_ACTIVATION", results: ["SUCCEEDED"], actions: ["managedservice.service-activation.activated"] },
  { target: "SERVICE_INSTALLATION", results: ["ACCEPTED"], actions: [
    "managedservice.service-installation.created", "managedservice.service-installation.termination-requested"
  ] },
  { target: "SERVICE_INSTALLATION", results: ["SUCCEEDED"], actions: [
    "managedservice.service-installation.ready", "managedservice.service-installation.terminated"
  ] },
  { target: "DEVOPS_PROJECT", results: ["SUCCEEDED"], actions: ["devops.project.created"] },
  { target: "SOURCE_CONNECTION", results: ["SUCCEEDED"], actions: [
    "devops.source-connection.created", "devops.source-connection.updated",
    "devops.source-connection.recheck-scheduled", "devops.source-connection.health-transitioned"
  ] },
  { target: "REPOSITORY_BINDING", results: ["SUCCEEDED"], actions: [
    "devops.repository-binding.created", "devops.repository-binding.updated",
    "devops.repository-binding.recheck-scheduled", "devops.repository-binding.health-transitioned"
  ] },
  { target: "PIPELINE", results: ["SUCCEEDED"], actions: [
    "devops.pipeline.created", "devops.pipeline.draft-updated"
  ] },
  { target: "PIPELINE_REVISION", results: ["SUCCEEDED"], actions: ["devops.pipeline-revision.activated"] },
  { target: "SOURCE_EVENT", results: ["ACCEPTED"], actions: ["devops.source-event.admitted"] },
  { target: "PIPELINE_RUN", results: ["ACCEPTED"], actions: [
    "devops.pipeline-run.created", "devops.pipeline-run.replayed", "devops.pipeline-run.cancellation-requested"
  ] },
  { target: "PIPELINE_RUN", results: ["SUCCEEDED"], actions: [
    "devops.pipeline-run.completed", "devops.pipeline-run.logs-read"
  ] },
  { target: "AUDIT_RECORDS", results: ["SUCCEEDED"], actions: [
    "audit.records.read", "audit.platform-records.read"
  ] },
  { target: "AUDIT_CHAIN", results: ["SUCCEEDED"], actions: [
    "audit.integrity.verified", "audit.platform-integrity.verified"
  ] },
] as const;

type AuditEventVariant = typeof auditEventVariants[number];
export type AuditAction = AuditEventVariant["actions"][number];
export type AuditResult = AuditEventVariant["results"][number];
export type AuditTargetKind = AuditEventVariant["target"];
export const auditResults = [...new Set(auditEventVariants.flatMap<AuditResult>(variant => variant.results))];
export const auditTargetKinds = [...new Set(auditEventVariants.map(variant => variant.target))];
const variantByAction = new Map<AuditAction, AuditEventVariant>();
for (const variant of auditEventVariants) {
  for (const action of variant.actions) variantByAction.set(action, variant);
}
export const auditActions = [...variantByAction.keys()];

export type AuditSource = typeof auditSources[number];
export type AuditActorType = typeof auditActorTypes[number];
export type AuditAuthorityKind = "TENANT" | "INSTALLATION";
export type AuditAuthority =
  | { authorityKind: "TENANT"; tenantId: string; installationId?: never }
  | { authorityKind: "INSTALLATION"; tenantId?: never; installationId: string };
export type AuditRoleSession =
  | { sessionId: string; sourceUserId: string; sourceServicePrincipalId?: never }
  | { sessionId: string; sourceUserId?: never; sourceServicePrincipalId: string };
export type AuditActor =
  | { type: "USER"; id: string; accessKeyId?: string }
  | { type: "ROLE"; id: string; roleSession: AuditRoleSession }
  | { type: "SERVICE_ACCOUNT" | "SYSTEM"; id: string };
export type AuditTarget = { kind: AuditTargetKind; id: string; tenantId?: string };
const pipelineOutcomes = ["SUCCEEDED", "FAILED", "CANCELLED", "MANUAL_INTERVENTION"] as const;
const pipelineReasons = {
  SUCCEEDED: ["COMPLETED"],
  FAILED: ["SOURCE_UNAVAILABLE", "COMMIT_MISMATCH", "EXECUTOR_UNAVAILABLE", "VERIFICATION_FAILED", "DEADLINE_EXCEEDED", "REPORT_UNAVAILABLE", "REPORT_CONFLICT"],
  CANCELLED: ["CANCELLED"],
  MANUAL_INTERVENTION: ["RECONCILIATION_EXHAUSTED"]
} as const;
type PipelineOutcome = typeof pipelineOutcomes[number];
export type AuditEvent = AuditAuthority & {
  apiVersion: typeof AUDIT_API_VERSION;
  kind: "AuditEvent";
  eventId: string;
  actor: AuditActor;
  iamDecisionId?: string;
  action: AuditAction;
  target: AuditTarget;
  result: AuditResult;
  outcome?: PipelineOutcome;
  reason?: typeof pipelineReasons[PipelineOutcome][number];
  requestDigest: string;
  authorityEvidenceDigest?: string;
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
export type AuditRecordPage = AuditAuthority & {
  apiVersion: typeof AUDIT_API_VERSION;
  kind: "AuditRecordPage";
  records: AuditRecord[];
  omittedRecordCount: number;
  nextCursor?: string;
  paginationUnavailable?: boolean;
};
export type AuditVerifyRequest = { fromSequence: number; maximumRecords: number };
export type AuditChainVerification = AuditAuthority & {
  apiVersion: typeof AUDIT_API_VERSION;
  kind: "ChainVerification";
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
  const result = text(value, label, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z$/);
  const date = new Date(result);
  if (Number.isNaN(date.valueOf()) || date.toISOString().slice(0, 19) !== result.slice(0, 19)) throw new Error(`INVALID_${label}`);
  return result;
}
function optionalText(value: Record<string, unknown>, key: string, label: string, pattern?: RegExp): string | undefined {
  return key in value ? text(value[key], label, pattern) : undefined;
}
function parseAuthority(value: Record<string, unknown>, expected?: AuditAuthorityKind | AuditAuthority): AuditAuthority {
  const hasTenant = "tenantId" in value;
  const hasInstallation = "installationId" in value;
  if (hasTenant === hasInstallation) throw new Error("INVALID_AUDIT_AUTHORITY");
  const authority: AuditAuthority = hasTenant
    ? { authorityKind: "TENANT", tenantId: text(value.tenantId, "AUDIT_TENANT_ID", idPattern) }
    : { authorityKind: "INSTALLATION", installationId: text(value.installationId, "AUDIT_INSTALLATION_ID", idPattern) };
  if (expected && (typeof expected === "string" ? authority.authorityKind !== expected : !sameAuthority(authority, expected))) throw new Error("INVALID_AUDIT_AUTHORITY");
  return authority;
}
function sameAuthority(left: AuditAuthority, right: AuditAuthority): boolean {
  if (left.authorityKind !== right.authorityKind) return false;
  return left.authorityKind === "TENANT"
    ? left.tenantId === (right as Extract<AuditAuthority, { authorityKind: "TENANT" }>).tenantId
    : left.installationId === (right as Extract<AuditAuthority, { authorityKind: "INSTALLATION" }>).installationId;
}
function parseActor(value: unknown): AuditActor {
  const data = object(value, "AUDIT_ACTOR");
  const type = member(data.type, auditActorTypes, "AUDIT_ACTOR_TYPE");
  const id = text(data.id, "AUDIT_ACTOR_ID", idPattern);
  if (type === "ROLE") {
    exactKeys(data, ["type", "id", "roleSession"], [], "AUDIT_ACTOR");
    const roleSession = object(data.roleSession, "AUDIT_ROLE_SESSION");
    exactKeys(roleSession, ["sessionId"], ["sourceUserId", "sourceServicePrincipalId"], "AUDIT_ROLE_SESSION");
    const sessionId = text(roleSession.sessionId, "AUDIT_ROLE_SESSION_ID", idPattern);
    const hasUser = "sourceUserId" in roleSession;
    const hasService = "sourceServicePrincipalId" in roleSession;
    if (hasUser === hasService) throw new Error("INVALID_AUDIT_ROLE_SESSION_SOURCE");
    return hasUser
      ? { type, id, roleSession: { sessionId, sourceUserId: text(roleSession.sourceUserId, "AUDIT_ROLE_SOURCE_USER_ID", idPattern) } }
      : { type, id, roleSession: { sessionId, sourceServicePrincipalId: text(roleSession.sourceServicePrincipalId, "AUDIT_ROLE_SOURCE_SERVICE_ID", idPattern) } };
  }
  if (type === "USER") {
    exactKeys(data, ["type", "id"], ["accessKeyId"], "AUDIT_ACTOR");
    return { type, id, accessKeyId: optionalText(data, "accessKeyId", "AUDIT_ACCESS_KEY_ID", idPattern) };
  }
  exactKeys(data, ["type", "id"], [], "AUDIT_ACTOR");
  return { type, id };
}
function sourceForAction(action: AuditAction): AuditSource {
  if (action.startsWith("iam.")) return "IAM";
  if (action.startsWith("audit.")) return "AUDIT";
  if (action.startsWith("devops.")) return "DEVOPS";
  return "PAAS";
}
function parseEvent(value: unknown): AuditEvent {
  const data = object(value, "AUDIT_EVENT");
  exactKeys(data, ["apiVersion", "kind", "eventId", "actor", "action", "target", "result", "requestDigest", "requestId", "correlationId", "occurredAt"], ["tenantId", "installationId", "iamDecisionId", "operationId", "traceparent", "authorityEvidenceDigest", "outcome", "reason"], "AUDIT_EVENT");
  if (data.apiVersion !== AUDIT_API_VERSION || data.kind !== "AuditEvent") throw new Error("INVALID_AUDIT_EVENT_TYPE");
  const target = object(data.target, "AUDIT_TARGET");
  exactKeys(target, ["kind", "id"], ["tenantId"], "AUDIT_TARGET");
  const action = member(data.action, auditActions, "AUDIT_ACTION");
  const variant = variantByAction.get(action)!;
  if (target.kind !== variant.target) throw new Error("INVALID_AUDIT_TARGET_KIND");
  let outcome: PipelineOutcome | undefined;
  let reason: AuditEvent["reason"];
  if (action === "devops.pipeline-run.completed") {
    outcome = member(data.outcome, pipelineOutcomes, "AUDIT_OUTCOME");
    reason = member(data.reason, pipelineReasons[outcome], "AUDIT_REASON");
  } else if ("outcome" in data || "reason" in data) {
    throw new Error("INVALID_AUDIT_OUTCOME");
  }
  return {
    ...parseAuthority(data), apiVersion: AUDIT_API_VERSION, kind: "AuditEvent",
    eventId: text(data.eventId, "AUDIT_EVENT_ID", idPattern), actor: parseActor(data.actor),
    iamDecisionId: optionalText(data, "iamDecisionId", "AUDIT_DECISION_ID", idPattern),
    action, outcome, reason,
    target: { kind: variant.target, id: text(target.id, "AUDIT_TARGET_ID", idPattern), tenantId: optionalText(target, "tenantId", "AUDIT_TARGET_TENANT_ID", idPattern) },
    result: member(data.result, variant.results, "AUDIT_RESULT"), requestDigest: text(data.requestDigest, "AUDIT_REQUEST_DIGEST", digestPattern),
    authorityEvidenceDigest: optionalText(data, "authorityEvidenceDigest", "AUDIT_AUTHORITY_EVIDENCE_DIGEST", digestPattern),
    requestId: text(data.requestId, "AUDIT_REQUEST_ID", idPattern), correlationId: text(data.correlationId, "AUDIT_CORRELATION_ID", idPattern),
    operationId: optionalText(data, "operationId", "AUDIT_OPERATION_ID", idPattern), traceparent: optionalText(data, "traceparent", "AUDIT_TRACEPARENT", traceparentPattern),
    occurredAt: timestamp(data.occurredAt, "AUDIT_OCCURRED_AT")
  };
}
function parseRecord(value: unknown): AuditRecord {
  const data = object(value, "AUDIT_RECORD");
  exactKeys(data, ["apiVersion", "kind", "source", "sequence", "event", "contentDigest", "previousHash", "recordHash", "ingestedAt", "retention"], [], "AUDIT_RECORD");
  if (data.apiVersion !== AUDIT_API_VERSION || data.kind !== "AuditRecord") throw new Error("INVALID_AUDIT_RECORD_TYPE");
  const source = member(data.source, auditSources, "AUDIT_SOURCE");
  const event = parseEvent(data.event);
  if (source !== sourceForAction(event.action)) throw new Error("INVALID_AUDIT_RECORD_SOURCE");
  return { apiVersion: AUDIT_API_VERSION, kind: "AuditRecord", source, sequence: integer(data.sequence, 1, Number.MAX_SAFE_INTEGER, "AUDIT_SEQUENCE"), event,
    contentDigest: text(data.contentDigest, "AUDIT_CONTENT_DIGEST", digestPattern), previousHash: text(data.previousHash, "AUDIT_PREVIOUS_HASH", digestPattern),
    recordHash: text(data.recordHash, "AUDIT_RECORD_HASH", digestPattern), ingestedAt: timestamp(data.ingestedAt, "AUDIT_INGESTED_AT"),
    retention: member(data.retention, auditRetentions, "AUDIT_RETENTION") };
}

export function parseAuditRecordPage(value: unknown, expectedAuthority?: AuditAuthorityKind | AuditAuthority, pageSize = AUDIT_MAX_PAGE_SIZE): AuditRecordPage {
  const data = object(value, "AUDIT_RECORD_PAGE");
  exactKeys(data, ["apiVersion", "kind", "records"], ["tenantId", "installationId", "nextCursor", "omittedRecordCount"], "AUDIT_RECORD_PAGE");
  if (data.apiVersion !== AUDIT_API_VERSION || data.kind !== "AuditRecordPage" || !Array.isArray(data.records) || data.records.length > AUDIT_MAX_PAGE_SIZE) throw new Error("INVALID_AUDIT_RECORD_PAGE");
  const authority = parseAuthority(data, expectedAuthority);
  let omittedRecordCount = "omittedRecordCount" in data ? integer(data.omittedRecordCount, 0, AUDIT_MAX_PAGE_SIZE, "AUDIT_RECORD_COUNT") : 0;
  if (data.records.length + omittedRecordCount > Math.min(pageSize, AUDIT_MAX_PAGE_SIZE)) throw new Error("INVALID_AUDIT_RECORD_PAGE");
  const records: AuditRecord[] = [];
  for (const raw of data.records) {
    let record: AuditRecord;
    try {
      record = parseRecord(raw);
    } catch (failure) {
      if (!(failure instanceof Error) || !failure.message.startsWith("INVALID_AUDIT_")) throw failure;
      omittedRecordCount++;
      continue;
    }
    if (!sameAuthority(record.event, authority)) throw new Error("INVALID_AUDIT_AUTHORITY");
    if (records.length && records[records.length - 1]!.sequence <= record.sequence) throw new Error("INVALID_AUDIT_RECORD_ORDER");
    records.push(record);
  }
  const nextCursor = typeof data.nextCursor === "string" && data.nextCursor.trim() === data.nextCursor && cursorPattern.test(data.nextCursor)
    ? data.nextCursor : undefined;
  return { ...authority, apiVersion: AUDIT_API_VERSION, kind: "AuditRecordPage", records, omittedRecordCount,
    nextCursor, paginationUnavailable: "nextCursor" in data && !nextCursor };
}
export function parseAuditChainVerification(value: unknown, expectedAuthority?: AuditAuthorityKind | AuditAuthority): AuditChainVerification {
  const data = object(value, "AUDIT_CHAIN_VERIFICATION");
  exactKeys(data, ["apiVersion", "kind", "state", "fromSequence", "toSequence", "recordCount", "firstPreviousHash", "lastRecordHash", "complete", "verifiedAt"], ["tenantId", "installationId", "nextSequence"], "AUDIT_CHAIN_VERIFICATION");
  if (data.apiVersion !== AUDIT_API_VERSION || data.kind !== "ChainVerification" || data.state !== "VERIFIED" || typeof data.complete !== "boolean") throw new Error("INVALID_AUDIT_CHAIN_VERIFICATION");
  const authority = parseAuthority(data, expectedAuthority);
  const fromSequence = integer(data.fromSequence, 1, Number.MAX_SAFE_INTEGER, "AUDIT_FROM_SEQUENCE");
  const toSequence = integer(data.toSequence, fromSequence, Number.MAX_SAFE_INTEGER, "AUDIT_TO_SEQUENCE");
  const recordCount = integer(data.recordCount, 1, AUDIT_MAX_VERIFY_RECORDS, "AUDIT_RECORD_COUNT");
  const nextSequence = "nextSequence" in data ? integer(data.nextSequence, toSequence + 1, Number.MAX_SAFE_INTEGER, "AUDIT_NEXT_SEQUENCE") : undefined;
  if (recordCount !== toSequence - fromSequence + 1 || (data.complete ? nextSequence !== undefined : nextSequence !== toSequence + 1)) throw new Error("INVALID_AUDIT_CHAIN_RANGE");
  return { ...authority, apiVersion: AUDIT_API_VERSION, kind: "ChainVerification", state: "VERIFIED", fromSequence, toSequence, recordCount,
    firstPreviousHash: text(data.firstPreviousHash, "AUDIT_FIRST_HASH", digestPattern), lastRecordHash: text(data.lastRecordHash, "AUDIT_LAST_HASH", digestPattern),
    complete: data.complete, nextSequence, verifiedAt: timestamp(data.verifiedAt, "AUDIT_VERIFIED_AT") };
}
