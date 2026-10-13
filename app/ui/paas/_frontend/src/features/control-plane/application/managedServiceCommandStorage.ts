import type {
  ManagedServiceCommandIntent,
  ManagedServiceCommandOwner
} from "../domain/managedServiceCommand";
import { sameManagedServiceCommandOwner } from "../domain/managedServiceCommand";

export const managedServiceCommandStorageKey = "matrix.managed-service.commands.v1";

type StoredEnvelope = {
  version: 1;
  commands: ManagedServiceCommandIntent[];
};

const publicId = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const installationId = /^[a-z0-9](?:[a-z0-9._-]{0,61}[a-z0-9])?$/;
const digest = /^sha256:[a-f0-9]{64}$/;

function record(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null;
}

function exactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const expected = new Set(keys);
  return keys.every((key) => key in value) && Object.keys(value).every((key) => expected.has(key));
}

function text(value: unknown, pattern: RegExp = publicId): value is string {
  return typeof value === "string" && pattern.test(value);
}

function owner(value: unknown): ManagedServiceCommandOwner | null {
  const wire = record(value);
  if (!wire || !exactKeys(wire, wire.actorKind === "ROLE" ? ["accountId", "actorKind", "actorId", "sourceUserId"] : ["accountId", "actorKind", "actorId"]) ||
    !text(wire.accountId) || !text(wire.actorId) || !["USER", "ROLE"].includes(String(wire.actorKind))) return null;
  if (wire.actorKind === "ROLE") return text(wire.sourceUserId)
    ? { accountId: wire.accountId, actorKind: "ROLE", actorId: wire.actorId, sourceUserId: wire.sourceUserId } : null;
  return { accountId: wire.accountId, actorKind: "USER", actorId: wire.actorId };
}

function templateReference(value: unknown) {
  const wire = record(value);
  if (!wire || !exactKeys(wire, ["id", "version", "contentDigest"]) || !text(wire.id) ||
    wire.version !== 1 || typeof wire.contentDigest !== "string" || !digest.test(wire.contentDigest)) return null;
  return { id: wire.id, version: 1 as const, contentDigest: wire.contentDigest };
}

export function parseManagedServiceCommandIntent(value: unknown): ManagedServiceCommandIntent | null {
  const wire = record(value);
  if (!wire || !exactKeys(wire, ["owner", "requestId", "startedAt", "targetId", "targetLabel", "kind", "payload"])) return null;
  const commandOwner = owner(wire.owner);
  if (!commandOwner || !text(wire.requestId) || !text(wire.targetId) ||
    typeof wire.targetLabel !== "string" || wire.targetLabel.length < 1 || wire.targetLabel.length > 128 ||
    typeof wire.startedAt !== "string" || !Number.isFinite(Date.parse(wire.startedAt))) return null;
  const payload = record(wire.payload);
  if (!payload) return null;
  const base = {
    owner: commandOwner,
    requestId: wire.requestId,
    startedAt: wire.startedAt,
    targetId: wire.targetId,
    targetLabel: wire.targetLabel
  };

  if (wire.kind === "ACTIVATE_QUOTA" && wire.targetId === payload.offeringId && exactKeys(payload, ["offeringId", "quotaShapeId", "instanceCount"]) &&
    text(payload.offeringId) && text(payload.quotaShapeId) && Number.isSafeInteger(payload.instanceCount) &&
    Number(payload.instanceCount) >= 1 && Number(payload.instanceCount) <= 1_000) {
    return { ...base, kind: wire.kind, payload: {
      offeringId: payload.offeringId,
      quotaShapeId: payload.quotaShapeId,
      instanceCount: Number(payload.instanceCount)
    } };
  }
  if (wire.kind === "CREATE_INSTALLATION" && wire.targetId === payload.id && exactKeys(payload, ["id", "name", "offeringId", "quotaEntitlementId", "regionId"]) &&
    text(payload.id, installationId) && typeof payload.name === "string" && payload.name.trim().length > 0 && payload.name.length <= 128 &&
    text(payload.offeringId) && text(payload.quotaEntitlementId) && text(payload.regionId)) {
    return { ...base, kind: wire.kind, payload: {
      id: payload.id,
      name: payload.name,
      offeringId: payload.offeringId,
      quotaEntitlementId: payload.quotaEntitlementId,
      regionId: payload.regionId
    } };
  }
  if (wire.kind === "TERMINATE_INSTALLATION" && wire.targetId === payload.installationId && exactKeys(payload, ["installationId"]) && text(payload.installationId, installationId)) {
    return { ...base, kind: wire.kind, payload: { installationId: payload.installationId } };
  }
  if (wire.kind === "BIND_SERVICE_ROLE" && commandOwner.actorKind === "USER" && wire.targetId === payload.installationId && exactKeys(payload, ["installationId", "template"]) && text(payload.installationId, installationId)) {
    const template = templateReference(payload.template);
    return template ? { ...base, kind: wire.kind, payload: { installationId: payload.installationId, template } } : null;
  }
  if (wire.kind === "UNBIND_SERVICE_ROLE" && commandOwner.actorKind === "USER" && wire.targetId === payload.installationId && exactKeys(payload, ["installationId", "bindingId", "resourceVersion", "expectedTemplate"]) &&
    text(payload.installationId, installationId) && text(payload.bindingId) && Number.isSafeInteger(payload.resourceVersion) && Number(payload.resourceVersion) >= 1) {
    const expectedTemplate = templateReference(payload.expectedTemplate);
    return expectedTemplate ? { ...base, kind: wire.kind, payload: {
      installationId: payload.installationId,
      bindingId: payload.bindingId,
      resourceVersion: Number(payload.resourceVersion),
      expectedTemplate
    } } : null;
  }
  return null;
}

function readEnvelope(storage: Storage): StoredEnvelope {
  const raw = storage.getItem(managedServiceCommandStorageKey);
  if (!raw) return { version: 1, commands: [] };
  try {
    const wire = record(JSON.parse(raw));
    if (!wire || !exactKeys(wire, ["version", "commands"]) || wire.version !== 1 || !Array.isArray(wire.commands) || wire.commands.length > 8) {
      throw new Error("INVALID_MANAGED_SERVICE_COMMAND_STORAGE");
    }
    const commands = wire.commands.map(parseManagedServiceCommandIntent);
    if (commands.some((command) => command === null)) throw new Error("INVALID_MANAGED_SERVICE_COMMAND_STORAGE");
    return { version: 1, commands: commands as ManagedServiceCommandIntent[] };
  } catch {
    storage.removeItem(managedServiceCommandStorageKey);
    return { version: 1, commands: [] };
  }
}

export function readManagedServiceCommand(storage: Storage, commandOwner: ManagedServiceCommandOwner): ManagedServiceCommandIntent | null {
  return readEnvelope(storage).commands.find((command) => sameManagedServiceCommandOwner(command.owner, commandOwner)) ?? null;
}

export function writeManagedServiceCommand(storage: Storage, command: ManagedServiceCommandIntent): void {
  const current = readEnvelope(storage).commands.filter((item) => !sameManagedServiceCommandOwner(item.owner, command.owner));
  const envelope: StoredEnvelope = { version: 1, commands: [...current, command].slice(-8) };
  storage.setItem(managedServiceCommandStorageKey, JSON.stringify(envelope));
}

export function clearManagedServiceCommand(
  storage: Storage,
  commandOwner: ManagedServiceCommandOwner,
  requestId: string
): void {
  const current = readEnvelope(storage).commands;
  const commands = current.filter((command) => !(sameManagedServiceCommandOwner(command.owner, commandOwner) && command.requestId === requestId));
  if (commands.length === 0) storage.removeItem(managedServiceCommandStorageKey);
  else storage.setItem(managedServiceCommandStorageKey, JSON.stringify({ version: 1, commands } satisfies StoredEnvelope));
}
