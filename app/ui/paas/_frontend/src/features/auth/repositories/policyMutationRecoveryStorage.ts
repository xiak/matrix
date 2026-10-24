import { policyDisplayNameValid, type AccountPolicy, type PolicyMetadataMutationIntent, type PolicyMutationIntent,
  type PolicyVersionMutationRecoveryIntent } from "../domain/accounts";

export type PolicyMutationOwner = Pick<PolicyMutationIntent, "accountId" | "actorPrincipalId">;
export const policyMutationStorageEvent = "matrix:iam-policy-mutation";
const identifier = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const fields = ["format", "kind", "accountId", "actorPrincipalId", "policy", "contentDigest", "requestId", "createdAt", "state"];
const policyFields = ["id", "management", "accountId", "displayName", "scope", "status", "defaultVersionId", "resourceVersion", "createdAt", "updatedAt"];
const maxStoredPolicyMutationBytes = 96 * 1024;

function object(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
}
function exact(value: Record<string, unknown>, keys: readonly string[]) {
  return Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
}
function text(value: unknown): value is string {
  return typeof value === "string" && policyDisplayNameValid(value);
}
function timestamp(value: unknown): value is string {
  return typeof value === "string" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$/.test(value) &&
    Number.isFinite(Date.parse(value)) && new Date(value).toISOString().slice(0, 10) === value.slice(0, 10);
}

export function policyMutationStorageKey(owner: PolicyMutationOwner): string {
  if (!identifier.test(owner.accountId) || !identifier.test(owner.actorPrincipalId)) throw new Error("INVALID_POLICY_MUTATION_OWNER");
  return `matrix.iam.policy-mutation.v1:${encodeURIComponent(JSON.stringify([owner.accountId, owner.actorPrincipalId]))}`;
}

export function parsePolicyMutationIntent(value: unknown): PolicyMutationIntent | null {
  const wire = object(value);
  const mutationFields = wire?.kind === "update" ? [...fields, "displayName"] :
    wire?.kind === "publish-version" ? [...fields, "documentJSON"] :
    wire?.kind === "set-default-version" || wire?.kind === "retire-version" ? [...fields, "versionId"] : fields;
  if (!wire || !exact(wire, mutationFields) || wire.format !== 1 || wire.state !== "UNKNOWN" ||
      !["update", "retire", "publish-version", "set-default-version", "retire-version"].includes(String(wire.kind))) return null;
  for (const key of ["accountId", "actorPrincipalId", "requestId"]) {
    if (typeof wire[key] !== "string" || !identifier.test(wire[key])) return null;
  }
  const policy = object(wire.policy);
  if (!policy || !exact(policy, policyFields) || policy.management !== "CUSTOMER" || policy.scope !== "TENANT" ||
      policy.status !== "ACTIVE" || policy.accountId !== wire.accountId ||
      typeof policy.id !== "string" || !identifier.test(policy.id) || policy.id.startsWith("system.") ||
      typeof policy.defaultVersionId !== "string" || !identifier.test(policy.defaultVersionId) || !text(policy.displayName) ||
      !Number.isSafeInteger(policy.resourceVersion) || Number(policy.resourceVersion) < 1 || Number(policy.resourceVersion) >= Number.MAX_SAFE_INTEGER ||
      !timestamp(policy.createdAt) || !timestamp(policy.updatedAt) || !timestamp(wire.createdAt) ||
      typeof wire.contentDigest !== "string" || !/^sha256:[a-f0-9]{64}$/.test(wire.contentDigest)) return null;
  if (wire.kind === "update" && (!text(wire.displayName) || wire.displayName === policy.displayName)) return null;
  if ((wire.kind === "set-default-version" || wire.kind === "retire-version") &&
      (typeof wire.versionId !== "string" || !identifier.test(wire.versionId) ||
        wire.kind === "set-default-version" && wire.versionId === policy.defaultVersionId ||
        wire.kind === "retire-version" && wire.versionId === policy.defaultVersionId)) return null;
  if (wire.kind === "publish-version") {
    if (typeof wire.documentJSON !== "string" || new TextEncoder().encode(wire.documentJSON).length > 64 * 1024) return null;
    try {
      const document = JSON.parse(wire.documentJSON);
      if (!object(document) || JSON.stringify(document) !== wire.documentJSON) return null;
    } catch { return null; }
  }
  // Reconstruct only the closed original-command projection. Credentials,
  // Session IDs, decisions and transferable authorization proofs are never
  // admitted. A version publication keeps its exact non-secret document
  // because an equal replay cannot be reconstructed from a later read.
  const source: AccountPolicy = { id: policy.id, accountId: wire.accountId as string, management: "CUSTOMER", scope: "TENANT", status: "ACTIVE",
    displayName: policy.displayName, defaultVersionId: policy.defaultVersionId, resourceVersion: Number(policy.resourceVersion),
    createdAt: policy.createdAt, updatedAt: policy.updatedAt };
  const base = { format: 1 as const, accountId: wire.accountId as string, actorPrincipalId: wire.actorPrincipalId as string,
    policy: source, contentDigest: wire.contentDigest, requestId: wire.requestId as string, createdAt: wire.createdAt, state: "UNKNOWN" as const };
  Object.freeze(source);
  if (wire.kind === "update") return Object.freeze({ ...base, kind: "update", displayName: wire.displayName as string });
  if (wire.kind === "publish-version") return Object.freeze({ ...base, kind: "publish-version", documentJSON: wire.documentJSON as string });
  if (wire.kind === "set-default-version" || wire.kind === "retire-version") {
    return Object.freeze({ ...base, kind: wire.kind, versionId: wire.versionId as string });
  }
  return Object.freeze({ ...base, kind: "retire" });
}

export function isPolicyMetadataMutationIntent(intent: PolicyMutationIntent | null): intent is PolicyMetadataMutationIntent {
  return intent?.kind === "update" || intent?.kind === "retire";
}

export function isPolicyVersionMutationIntent(intent: PolicyMutationIntent | null): intent is PolicyVersionMutationRecoveryIntent {
  return intent?.kind === "publish-version" || intent?.kind === "set-default-version" || intent?.kind === "retire-version";
}

export function readPolicyMutationIntent(storage: Storage, owner: PolicyMutationOwner): PolicyMutationIntent | null {
  const raw = storage.getItem(policyMutationStorageKey(owner));
  if (raw === null) return null;
  if (raw.length > maxStoredPolicyMutationBytes) throw new Error("INVALID_POLICY_MUTATION_STORAGE");
  const intent = parsePolicyMutationIntent(JSON.parse(raw));
  if (!intent || intent.accountId !== owner.accountId || intent.actorPrincipalId !== owner.actorPrincipalId) {
    throw new Error("INVALID_POLICY_MUTATION_STORAGE");
  }
  return intent;
}

/** Caller holds the actor's Web Lock until the command attempt settles. */
export function writePolicyMutationIntent(storage: Storage, intent: PolicyMutationIntent): void {
  const parsed = parsePolicyMutationIntent(intent);
  if (!parsed) throw new Error("INVALID_POLICY_MUTATION_STORAGE");
  if (readPolicyMutationIntent(storage, parsed)) throw new Error("POLICY_MUTATION_PENDING");
  storage.setItem(policyMutationStorageKey(parsed), JSON.stringify(parsed));
  if (JSON.stringify(readPolicyMutationIntent(storage, parsed)) !== JSON.stringify(parsed)) throw new Error("POLICY_MUTATION_CHANGED");
  window.dispatchEvent(new CustomEvent(policyMutationStorageEvent, { detail: policyMutationStorageKey(parsed) }));
}

export function clearPolicyMutationIntent(storage: Storage, intent: PolicyMutationIntent): void {
  const current = readPolicyMutationIntent(storage, intent);
  if (!current || JSON.stringify(current) !== JSON.stringify(parsePolicyMutationIntent(intent))) throw new Error("POLICY_MUTATION_CHANGED");
  storage.removeItem(policyMutationStorageKey(intent));
  if (storage.getItem(policyMutationStorageKey(intent)) !== null) throw new Error("POLICY_MUTATION_CHANGED");
  window.dispatchEvent(new CustomEvent(policyMutationStorageEvent, { detail: policyMutationStorageKey(intent) }));
}

export async function withPolicyMutationLock<T>(owner: PolicyMutationOwner, run: () => Promise<T>): Promise<T> {
  if (typeof navigator === "undefined" || !navigator.locks?.request) throw new Error("POLICY_MUTATION_COORDINATION_UNAVAILABLE");
  return navigator.locks.request(policyMutationStorageKey(owner), { mode: "exclusive", ifAvailable: true }, async (lock) => {
    if (!lock) throw new Error("POLICY_MUTATION_BUSY");
    return run();
  });
}
