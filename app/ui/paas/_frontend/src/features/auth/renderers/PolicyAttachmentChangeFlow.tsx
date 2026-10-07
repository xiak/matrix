"use client";

import { useEffect, useRef, useState } from "react";
import { useTranslations } from "next-intl";
import { Alert, Button } from "@ui/xiak";
import { accountError } from "../application/AccountAccessProvider";
import type {
  DirectPolicyAttachment,
  PolicyAttachmentChange,
  PolicyAttachmentChangeOperationExpectation
} from "../domain/accounts";
import styles from "./AccountAccessRenderer.module.css";

type RecoverablePolicyAttachmentTarget = Extract<DirectPolicyAttachment["target"], { kind: "GROUP" | "ROLE" }>;

export type PolicyAttachmentChangeScope = {
  accountId: string;
  actorPrincipalId: string;
  target: RecoverablePolicyAttachmentTarget;
};

type StoredPolicyAttachmentChange = PolicyAttachmentChangeScope & {
  version: 1;
  expectation: PolicyAttachmentChangeOperationExpectation;
};

const storagePrefix = "matrix.iam.policy-attachment-change.v1:";

function storageKey(scope: PolicyAttachmentChangeScope): string {
  return storagePrefix + [scope.accountId, scope.actorPrincipalId, scope.target.kind, scope.target.id]
    .map(encodeURIComponent).join(":");
}

function exactFields(record: Record<string, unknown>, fields: readonly string[]): boolean {
  const keys = Object.keys(record);
  return keys.length === fields.length && fields.every((field) => Object.prototype.hasOwnProperty.call(record, field));
}

function boundedIdentifier(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= 512 && !/[\u0000-\u001f\u007f]/.test(value);
}

function positiveVersion(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}

function sameTarget(left: RecoverablePolicyAttachmentTarget, right: RecoverablePolicyAttachmentTarget): boolean {
  return left.kind === right.kind && left.id === right.id;
}

function parseTarget(value: unknown): RecoverablePolicyAttachmentTarget | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const record = value as Record<string, unknown>;
  if (!exactFields(record, ["kind", "id"]) || (record.kind !== "GROUP" && record.kind !== "ROLE") || !boundedIdentifier(record.id)) return null;
  return { kind: record.kind, id: record.id };
}

function parseExpectation(value: unknown, target: RecoverablePolicyAttachmentTarget): PolicyAttachmentChangeOperationExpectation | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const record = value as Record<string, unknown>;
  if (!boundedIdentifier(record.requestId)) return null;
  if (record.operation === "CREATE") {
    if (!exactFields(record, ["operation", "requestId", "target", "policyId", "policyResourceVersion"]) ||
        !boundedIdentifier(record.policyId) || !positiveVersion(record.policyResourceVersion)) return null;
    const expectedTarget = parseTarget(record.target);
    if (!expectedTarget || !sameTarget(expectedTarget, target)) return null;
    return { operation: "CREATE", requestId: record.requestId, target: expectedTarget,
      policyId: record.policyId, policyResourceVersion: record.policyResourceVersion };
  }
  if (record.operation === "REVOKE" && exactFields(record, ["operation", "requestId", "attachmentId", "expectedResourceVersion"]) &&
      boundedIdentifier(record.attachmentId) && positiveVersion(record.expectedResourceVersion)) {
    return { operation: "REVOKE", requestId: record.requestId, attachmentId: record.attachmentId,
      expectedResourceVersion: record.expectedResourceVersion };
  }
  return null;
}

export function readPendingPolicyAttachmentChange(scope: PolicyAttachmentChangeScope): PolicyAttachmentChangeOperationExpectation | null {
  if (typeof window === "undefined") return null;
  const key = storageKey(scope);
  try {
    const raw = window.sessionStorage.getItem(key);
    if (!raw) return null;
    if (raw.length > 4096) throw new Error("INVALID_POLICY_ATTACHMENT_REMINDER");
    const value: unknown = JSON.parse(raw);
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("INVALID_POLICY_ATTACHMENT_REMINDER");
    const record = value as Record<string, unknown>;
    if (!exactFields(record, ["version", "accountId", "actorPrincipalId", "target", "expectation"]) || record.version !== 1 ||
        record.accountId !== scope.accountId || record.actorPrincipalId !== scope.actorPrincipalId) throw new Error("INVALID_POLICY_ATTACHMENT_REMINDER");
    const target = parseTarget(record.target);
    const expectation = target && sameTarget(target, scope.target) ? parseExpectation(record.expectation, target) : null;
    if (!expectation) throw new Error("INVALID_POLICY_ATTACHMENT_REMINDER");
    return expectation;
  } catch {
    try { window.sessionStorage.removeItem(key); } catch { /* An invalid reminder is never authorization evidence. */ }
    return null;
  }
}

function storePendingPolicyAttachmentChange(scope: PolicyAttachmentChangeScope, expectation: PolicyAttachmentChangeOperationExpectation): void {
  if (!parseExpectation(expectation, scope.target)) throw new Error("INVALID_POLICY_ATTACHMENT_INTENT");
  const stored: StoredPolicyAttachmentChange = { version: 1, ...scope, expectation };
  try { window.sessionStorage.setItem(storageKey(scope), JSON.stringify(stored)); }
  catch { /* The in-memory lock remains active while this page is mounted. */ }
}

function clearPendingPolicyAttachmentChange(scope: PolicyAttachmentChangeScope): void {
  try { window.sessionStorage.removeItem(storageKey(scope)); }
  catch { /* Retaining an old reminder is safer than silently unlocking an unresolved write. */ }
}

export type PolicyAttachmentCommandPhase =
  | "idle"
  | "pending"
  | "unknown"
  | "checking"
  | "conflict"
  | "rejected"
  | "refreshFailed"
  | "completed";

export type PolicyAttachmentCommandState = {
  phase: PolicyAttachmentCommandPhase;
  requestId?: string;
  error?: ReturnType<typeof accountError>;
  lookupStatus?: ReturnType<typeof accountError>;
  completion?: PolicyAttachmentChange;
};

export function usePolicyAttachmentCommand<I extends PolicyAttachmentChangeOperationExpectation>({ scope, execute, inspect, refresh }: {
  scope: PolicyAttachmentChangeScope;
  execute(intent: I): Promise<unknown>;
  inspect(intent: I): Promise<PolicyAttachmentChange>;
  refresh(): Promise<unknown>;
}) {
  const mounted = useRef(true);
  const [initialIntent] = useState<I | null>(() => readPendingPolicyAttachmentChange(scope) as I | null);
  const intent = useRef<I | null>(initialIntent);
  const [state, setState] = useState<PolicyAttachmentCommandState>(() => initialIntent
    ? { phase: "unknown", requestId: initialIntent.requestId }
    : { phase: "idle" });
  useEffect(() => {
    mounted.current = true;
    if (!intent.current) {
      const restored = readPendingPolicyAttachmentChange(scope) as I | null;
      if (restored) {
        intent.current = restored;
        setState((current) => current.phase === "idle" ? { phase: "unknown", requestId: restored.requestId } : current);
      }
    }
    return () => { mounted.current = false; };
  }, [scope]);

  const refreshAfterCompletion = async (completion?: PolicyAttachmentChange): Promise<boolean> => {
    try {
      await refresh();
      clearPendingPolicyAttachmentChange(scope);
      intent.current = null;
      if (!mounted.current) return false;
      setState({ phase: "completed", completion });
      return true;
    } catch (failure) {
      if (!mounted.current) return false;
      setState((current) => ({ phase: "refreshFailed", requestId: current.requestId, error: accountError(failure), completion }));
      return false;
    }
  };

  const run = async (next: I): Promise<boolean> => {
    if (state.phase === "pending" || state.phase === "checking" || state.phase === "unknown" || state.phase === "refreshFailed") return false;
    storePendingPolicyAttachmentChange(scope, next);
    intent.current = next;
    setState({ phase: "pending", requestId: next.requestId });
    try {
      await execute(next);
      if (!mounted.current) return false;
      return await refreshAfterCompletion();
    } catch (failure) {
      const error = accountError(failure);
      if (error !== "unavailable") {
        clearPendingPolicyAttachmentChange(scope);
        intent.current = null;
      }
      if (!mounted.current) return false;
      setState({ phase: error === "unavailable" ? "unknown" : error === "conflict" ? "conflict" : "rejected", error, requestId: next.requestId });
      return false;
    }
  };

  const inspectOriginal = async (): Promise<boolean> => {
    const frozen = intent.current;
    if (!frozen || state.phase !== "unknown") return false;
    setState({ phase: "checking", requestId: frozen.requestId });
    try {
      const completion = await inspect(frozen);
      if (!mounted.current) return false;
      return await refreshAfterCompletion(completion);
    } catch (failure) {
      if (!mounted.current) return false;
      const lookupStatus = accountError(failure);
      setState({ phase: "unknown", requestId: frozen.requestId, error: "unavailable", lookupStatus });
      return false;
    }
  };

  const retryRead = async (): Promise<boolean> => {
    if (state.phase !== "refreshFailed") return false;
    setState((current) => ({ ...current, phase: "pending" }));
    return refreshAfterCompletion(state.completion);
  };

  return {
    state,
    intent: intent.current,
    locked: state.phase === "pending" || state.phase === "checking" || state.phase === "unknown" || state.phase === "refreshFailed",
    run,
    inspectOriginal,
    retryRead,
    reset() {
      if (state.phase === "unknown" || state.phase === "checking" || state.phase === "refreshFailed") return false;
      clearPendingPolicyAttachmentChange(scope);
      intent.current = null;
      setState({ phase: "idle" });
      return true;
    }
  };
}

export function PolicyAttachmentChangeFeedback({ state, onRetryRead }: {
  state: PolicyAttachmentCommandState;
  onRetryRead(): Promise<unknown>;
}) {
  const t = useTranslations("PolicyAttachmentChange");
  const a = useTranslations("AccountAccess");
  if (state.phase === "unknown") return <Alert status="warning"><div className={styles.confirmation}>
    <strong>{t("unknownTitle")}</strong>
    <p>{t("unknownHint")}</p>
    {state.lookupStatus ? <p role="status">{t(`lookup.${state.lookupStatus}`)}</p> : null}
    <p>{t("requestId")} <code>{state.requestId}</code></p>
  </div></Alert>;
  if (state.phase === "refreshFailed") return <Alert status="warning"><div className={styles.confirmation}>
    <span>{t("refreshFailed")}</span>
    <Button variant="secondary" onClick={() => void onRetryRead()}>{t("retryRead")}</Button>
  </div></Alert>;
  if ((state.phase === "conflict" || state.phase === "rejected") && state.error) {
    return <Alert status="danger">{state.phase === "conflict" ? t("conflict") : a(`errors.${state.error}`)}</Alert>;
  }
  return null;
}
