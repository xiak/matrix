import { useCallback, useMemo, useState, useSyncExternalStore } from "react";
import type { ServiceActivationAccess, ServiceActivationRecord, ServiceActivationScope, ServiceActivationState } from "../domain/serviceActivation";

export const previewServiceActivationStorageKey = "matrix.preview.service-activations.v1";
const changedEvent = "matrix-preview-service-activation-changed";
const maxRecords = 64;
const unavailableSnapshot = "preview-storage-unavailable";
const identifier = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const timestamp = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const recordKeys = ["accountId", "serviceKey", "termsVersion", "acceptedBy", "acceptedAt", "enabledAt"] as const;

function object(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? value as Record<string, unknown> : null;
}

function exactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  return Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
}

function activationRecord(value: unknown): ServiceActivationRecord | null {
  const wire = object(value);
  if (!wire || !exactKeys(wire, recordKeys) ||
    ![wire.accountId, wire.serviceKey, wire.termsVersion, wire.acceptedBy].every((entry) => typeof entry === "string" && identifier.test(entry)) ||
    typeof wire.acceptedAt !== "string" || !timestamp.test(wire.acceptedAt) || typeof wire.enabledAt !== "string" || !timestamp.test(wire.enabledAt) ||
    !Number.isFinite(Date.parse(wire.acceptedAt)) || !Number.isFinite(Date.parse(wire.enabledAt)) ||
    Date.parse(wire.enabledAt) < Date.parse(wire.acceptedAt)) return null;
  return wire as ServiceActivationRecord;
}

function records(raw: string | null | undefined): ServiceActivationRecord[] {
  if (!raw || raw.length > 65536) return [];
  try {
    const envelope = object(JSON.parse(raw));
    if (!envelope || !exactKeys(envelope, ["version", "activations"]) || envelope.version !== 1 ||
      !Array.isArray(envelope.activations) || envelope.activations.length > maxRecords) return [];
    const parsed = envelope.activations.map(activationRecord);
    if (parsed.some((entry) => !entry)) return [];
    const scopes = parsed.map((entry) => JSON.stringify([entry!.accountId, entry!.serviceKey]));
    return new Set(scopes).size === scopes.length ? parsed as ServiceActivationRecord[] : [];
  } catch {
    return [];
  }
}

export function readPreviewServiceActivation(raw: string | null | undefined, scope: ServiceActivationScope): ServiceActivationRecord | null {
  return records(raw).find((entry) => entry.accountId === scope.accountId && entry.serviceKey === scope.serviceKey) ?? null;
}

export function writePreviewServiceActivation(storage: Storage, activation: ServiceActivationRecord): void {
  if (!activationRecord(activation)) throw new Error("INVALID_PREVIEW_SERVICE_ACTIVATION");
  const current = records(storage.getItem(previewServiceActivationStorageKey));
  // Equal first-use replay preserves the original consent evidence.
  if (current.some((entry) => entry.accountId === activation.accountId && entry.serviceKey === activation.serviceKey)) return;
  storage.setItem(previewServiceActivationStorageKey, JSON.stringify({ version: 1, activations: [...current, activation].slice(-maxRecords) }));
}

export function resetPreviewServiceActivation(storage: Storage, scope: ServiceActivationScope): void {
  const remaining = records(storage.getItem(previewServiceActivationStorageKey)).filter((entry) => entry.accountId !== scope.accountId || entry.serviceKey !== scope.serviceKey);
  if (remaining.length) storage.setItem(previewServiceActivationStorageKey, JSON.stringify({ version: 1, activations: remaining }));
  else storage.removeItem(previewServiceActivationStorageKey);
}

export const previewActivationScenarios = ["owner", "activation-admin", "product-user", "no-access"] as const;
export type PreviewActivationScenario = typeof previewActivationScenarios[number];
const scenarioAccess: Record<PreviewActivationScenario, ServiceActivationAccess> = {
  owner: { canEnable: true, mayLoadWorkspace: true },
  "activation-admin": { canEnable: true, mayLoadWorkspace: false },
  "product-user": { canEnable: false, mayLoadWorkspace: true },
  "no-access": { canEnable: false, mayLoadWorkspace: false }
};

function subscribe(listener: () => void) {
  const storageChanged = (event: StorageEvent) => {
    if (event.key === null || event.key === previewServiceActivationStorageKey) listener();
  };
  window.addEventListener("storage", storageChanged);
  window.addEventListener(changedEvent, listener);
  return () => {
    window.removeEventListener("storage", storageChanged);
    window.removeEventListener(changedEvent, listener);
  };
}

const serverSnapshot = () => undefined;
const noSubscription = () => () => {};

// This adapter owns only browser-local preview state. LIVE never reads it and
// no IAM repository, user policy, quota or installation is changed by activation.
export function usePreviewServiceActivation({ accountId, actorId, preview, serviceKey }: {
  accountId?: string;
  actorId?: string;
  preview: boolean;
  serviceKey?: string;
}) {
  const active = Boolean(preview && accountId && actorId && serviceKey);
  const identityKey = JSON.stringify([accountId, actorId]);
  const scopeKey = JSON.stringify([accountId, actorId, serviceKey]);
  const [selection, setSelection] = useState<{ identityKey: string; scenario: PreviewActivationScenario; failure: boolean }>({ identityKey, scenario: "owner", failure: false });
  const scenario = selection.identityKey === identityKey ? selection.scenario : "owner";
  const simulateFailure = selection.identityKey === identityKey && selection.failure;
  const [failedScope, setFailedScope] = useState<string | null>(null);
  const [resetFailureScope, setResetFailureScope] = useState<string | null>(null);
  const snapshot = useCallback(() => {
    if (!active) return null;
    try { return window.localStorage.getItem(previewServiceActivationStorageKey); } catch { return unavailableSnapshot; }
  }, [active]);
  const raw = useSyncExternalStore(active ? subscribe : noSubscription, snapshot, serverSnapshot);
  const record = useMemo(() => accountId && serviceKey ? readPreviewServiceActivation(raw, { accountId, serviceKey }) : null, [accountId, serviceKey, raw]);
  const access = active ? scenarioAccess[scenario] : { canEnable: false, mayLoadWorkspace: false };
  const state: ServiceActivationState = !active || raw === unavailableSnapshot ? { status: "unavailable" }
    : raw === undefined ? { status: "checking" }
      : record && accountId && serviceKey ? { status: "enabled", scope: { accountId, serviceKey }, activation: record }
        : failedScope === scopeKey ? { status: "failed" } : { status: "not-enabled" };

  function enable() {
    if (!active || !access.canEnable || !accountId || !actorId || !serviceKey) return;
    if (simulateFailure) { setFailedScope(scopeKey); return; }
    try {
      const at = new Date().toISOString();
      writePreviewServiceActivation(window.localStorage, { accountId, serviceKey, termsVersion: "mock-v1", acceptedBy: actorId, acceptedAt: at, enabledAt: at });
      setFailedScope(null);
      setResetFailureScope(null);
      window.dispatchEvent(new Event(changedEvent));
    } catch {
      setFailedScope(scopeKey);
    }
  }

  function reset() {
    if (!active || !accountId || !serviceKey) return;
    try {
      resetPreviewServiceActivation(window.localStorage, { accountId, serviceKey });
      setFailedScope(null);
      setResetFailureScope(null);
      window.dispatchEvent(new Event(changedEvent));
    } catch {
      setResetFailureScope(scopeKey);
    }
  }

  return {
    access, state, definition: null, preview: true as const, scenario, simulateFailure, enable, reset,
    resetFailed: resetFailureScope === scopeKey,
    selectScenario(next: PreviewActivationScenario) { setSelection({ identityKey, scenario: next, failure: simulateFailure }); },
    selectFailure(failure: boolean) { setSelection({ identityKey, scenario, failure }); }
  };
}
