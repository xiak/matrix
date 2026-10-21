"use client";

import { useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { HttpProblem, requestToken } from "@/infrastructure/http/jsonRequest";
import { policyMetadataResultMatches, type AccountPolicy, type AccountPolicyDetail, type PolicyMutationIntent } from "../domain/accounts";
import type { AccountRepository } from "../repositories/iamRepository";
import { clearPolicyMutationIntent, parsePolicyMutationIntent, policyMutationStorageEvent, policyMutationStorageKey, readPolicyMutationIntent, withPolicyMutationLock, writePolicyMutationIntent } from "../repositories/policyMutationRecoveryStorage";

type MutationError = "expired" | "forbidden" | "conflict" | "invalid" | "notFound" | "unavailable";
export type PolicyMutationResult = { status: "applied"; policy: AccountPolicy } |
  { status: "rejected"; reason: MutationError } | { status: "unknown" | "blocked" };
export type PolicyMutationClient = {
  identity: object;
  ready: boolean;
  recoveryError: "unavailable" | null;
  pending: PolicyMutationIntent | null;
  busy: boolean;
  lastError: MutationError | "busy" | null;
  begin(detail: AccountPolicyDetail, input: { kind: "update"; displayName: string } | { kind: "retire" }): Promise<PolicyMutationResult>;
  retry(): Promise<PolicyMutationResult>;
  abandon(): Promise<boolean>;
};
type PolicyMutationRepository = Pick<AccountRepository, "updatePolicy" | "deletePolicy">;
type Owner = { identity: object; accountId: string; actorPrincipalId: string; credential: string; sessionRevision: number; repository: PolicyMutationRepository };
type Observation = { owner: Owner; pending: PolicyMutationIntent | null; ready: boolean; recoveryError: "unavailable" | null; lastError: PolicyMutationClient["lastError"] };

function mutationError(failure: unknown): MutationError {
  if (failure instanceof HttpProblem) {
    if (failure.status === 401) return "expired";
    if (failure.status === 403) return "forbidden";
    if (failure.status === 409) return "conflict";
    if (failure.status === 404) return "notFound";
    if ([400, 413, 415, 422].includes(failure.status)) return "invalid";
  }
  return "unavailable";
}

// Own the original command outside route remounts. Persistence contains only
// the closed metadata intent; the current verified Session supplies authority.
export function useLivePolicyMutation({ enabled, accountId, actorPrincipalId, credential, sessionRevision, repository, protect, onExpired, versionPolicyId,
  authorityPending, authorizeBegin }: {
  enabled: boolean; accountId?: string; actorPrincipalId?: string; credential?: string;
  sessionRevision: number; repository: PolicyMutationRepository; versionPolicyId?: string;
  authorityPending: boolean;
  authorizeBegin(detail: AccountPolicyDetail, input: { kind: "update"; displayName: string } | { kind: "retire" }): boolean;
  protect<T>(request: () => Promise<T>): Promise<T>;
  onExpired(credential: string, revision: number): void;
}): PolicyMutationClient | null {
  const owner = useMemo<Owner | null>(() => enabled && accountId && actorPrincipalId && credential && repository.updatePolicy && repository.deletePolicy
    ? { identity: {}, accountId, actorPrincipalId, credential, sessionRevision, repository } : null,
  [enabled, accountId, actorPrincipalId, credential, sessionRevision, repository]);
  const currentOwner = useRef(owner);
  const versionPending = useRef(versionPolicyId);
  const authorityPendingRef = useRef(authorityPending);
  const authorizeBeginRef = useRef(authorizeBegin);
  const observation = useRef<Observation | null>(null);
  const inFlight = useRef<Owner | null>(null);
  const [view, setView] = useState<Observation | null>(null);
  const [busyOwner, setBusyOwner] = useState<Owner | null>(null);
  useLayoutEffect(() => {
    currentOwner.current = owner;
    return () => { currentOwner.current = null; };
  }, [owner]);
  useLayoutEffect(() => { versionPending.current = versionPolicyId; }, [versionPolicyId]);
  useLayoutEffect(() => {
    authorityPendingRef.current = authorityPending;
    authorizeBeginRef.current = authorizeBegin;
  }, [authorityPending, authorizeBegin]);

  useEffect(() => {
    if (!owner) return;
    const observe = () => {
      if (currentOwner.current !== owner) return;
      let next: Observation;
      try {
        if (!navigator.locks?.request) throw new Error("POLICY_MUTATION_COORDINATION_UNAVAILABLE");
        next = { owner, pending: readPolicyMutationIntent(window.localStorage, owner), ready: true, recoveryError: null, lastError: null };
      } catch {
        next = { owner, pending: observation.current?.owner === owner ? observation.current.pending : null,
          ready: false, recoveryError: "unavailable", lastError: null };
      }
      observation.current = next; setView(next);
    };
    const onStorage = (event: StorageEvent) => { if (event.key === null || event.key === policyMutationStorageKey(owner)) observe(); };
    const onLocal = (event: Event) => { if ((event as CustomEvent<unknown>).detail === policyMutationStorageKey(owner)) observe(); };
    queueMicrotask(observe);
    window.addEventListener("storage", onStorage);
    window.addEventListener(policyMutationStorageEvent, onLocal);
    return () => { window.removeEventListener("storage", onStorage); window.removeEventListener(policyMutationStorageEvent, onLocal); };
  }, [owner]);

  return useMemo<PolicyMutationClient | null>(() => {
    if (!owner) return null;
    const snapshot = view?.owner === owner ? view : null;
    const publish = (pending: PolicyMutationIntent | null, lastError: PolicyMutationClient["lastError"] = null, recoveryError: "unavailable" | null = null) => {
      if (currentOwner.current !== owner) return;
      const next = { owner, pending, lastError, recoveryError, ready: recoveryError === null };
      observation.current = next; setView(next);
    };
    const dispatch = async (intent: PolicyMutationIntent, retrying: boolean): Promise<PolicyMutationResult> => {
      if (currentOwner.current !== owner) return { status: "blocked" };
      try {
        let policy: AccountPolicy;
        if (intent.kind === "update") {
          const detail = await owner.repository.updatePolicy!(owner.credential, owner.accountId, { policy: structuredClone(intent.policy), contentDigest: intent.contentDigest }, {
            displayName: intent.displayName, resourceVersion: intent.policy.resourceVersion, requestId: intent.requestId
          });
          if (!policyMetadataResultMatches(detail.policy, intent.policy, intent.displayName, "ACTIVE") ||
              detail.version.policyId !== intent.policy.id || detail.version.versionId !== intent.policy.defaultVersionId ||
              detail.version.contentDigest !== intent.contentDigest) throw new Error("INVALID_IAM_RESPONSE");
          policy = detail.policy;
        } else {
          policy = await owner.repository.deletePolicy!(owner.credential, owner.accountId, structuredClone(intent.policy), {
            resourceVersion: intent.policy.resourceVersion, requestId: intent.requestId
          });
          if (!policyMetadataResultMatches(policy, intent.policy, intent.policy.displayName, "RETIRED")) throw new Error("INVALID_IAM_RESPONSE");
        }
        // A late response must neither clear recovery evidence nor publish into
        // another Session/repository. Re-authentication can retry the old intent.
        if (currentOwner.current !== owner) return { status: "blocked" };
        try { clearPolicyMutationIntent(window.localStorage, intent); }
        catch { publish(intent, "unavailable", "unavailable"); return { status: "unknown" }; }
        publish(null);
        return { status: "applied", policy };
      } catch (failure) {
        if (currentOwner.current !== owner) return { status: "blocked" };
        const reason = mutationError(failure);
        if (!retrying && failure instanceof HttpProblem && reason !== "unavailable") {
          try { clearPolicyMutationIntent(window.localStorage, intent); }
          catch {
            publish(intent, reason, "unavailable");
            if (reason === "expired") onExpired(owner.credential, owner.sessionRevision);
            return { status: "unknown" };
          }
          publish(null);
          if (reason === "expired") onExpired(owner.credential, owner.sessionRevision);
          return { status: "rejected", reason };
        }
        publish(intent, reason);
        if (reason === "expired") onExpired(owner.credential, owner.sessionRevision);
        return { status: "unknown" };
      }
    };
    const coordinate = async <T,>(run: () => Promise<T>, blocked: T): Promise<T> => {
      if (currentOwner.current !== owner || inFlight.current === owner || !observation.current?.ready || observation.current.owner !== owner) return blocked;
      inFlight.current = owner; setBusyOwner(owner);
      try {
        return await protect(() => withPolicyMutationLock(owner, async () => currentOwner.current === owner ? run() : blocked));
      } catch (failure) {
        if (currentOwner.current === owner) {
          const isBusy = failure instanceof Error && failure.message === "POLICY_MUTATION_BUSY";
          publish(observation.current?.owner === owner ? observation.current.pending : null, isBusy ? "busy" : "unavailable", isBusy ? null : "unavailable");
        }
        return blocked;
      } finally {
        if (inFlight.current === owner) inFlight.current = null;
        if (currentOwner.current === owner) setBusyOwner(null);
      }
    };
    return {
      identity: owner.identity,
      ready: Boolean(snapshot?.ready && !authorityPending),
      recoveryError: snapshot?.recoveryError ?? null, pending: snapshot?.pending ?? null,
      busy: busyOwner === owner, lastError: snapshot?.lastError ?? null,
      begin(detail, input) {
        const frozen = structuredClone({ detail, input });
        if (authorityPendingRef.current || !authorizeBeginRef.current(frozen.detail, frozen.input)) return Promise.resolve({ status: "blocked" });
        return coordinate(async () => {
          if (authorityPendingRef.current || !authorizeBeginRef.current(frozen.detail, frozen.input)) return { status: "blocked" };
          const existing = readPolicyMutationIntent(window.localStorage, owner);
          if (existing) { publish(existing); return { status: "blocked" }; }
          if (versionPending.current || frozen.detail.policy.accountId !== owner.accountId ||
              frozen.detail.version.policyId !== frozen.detail.policy.id || frozen.detail.version.versionId !== frozen.detail.policy.defaultVersionId) return { status: "blocked" };
          const intent = parsePolicyMutationIntent({ format: 1, ...frozen.input, accountId: owner.accountId, actorPrincipalId: owner.actorPrincipalId,
            policy: frozen.detail.policy, contentDigest: frozen.detail.version.contentDigest, requestId: requestToken("ui-policy-metadata-"),
            createdAt: new Date().toISOString(), state: "UNKNOWN" });
          if (!intent) return { status: "blocked" };
          writePolicyMutationIntent(window.localStorage, intent);
          publish(intent);
          return dispatch(intent, false);
        }, { status: "blocked" });
      },
      retry() {
        const expected = observation.current?.owner === owner ? observation.current.pending : null;
        if (authorityPendingRef.current || !expected) return Promise.resolve({ status: "blocked" });
        return coordinate(async () => {
          if (authorityPendingRef.current) return { status: "blocked" };
          const stored = readPolicyMutationIntent(window.localStorage, owner);
          if (!stored || JSON.stringify(stored) !== JSON.stringify(expected)) { publish(stored); return { status: "blocked" }; }
          return dispatch(stored, true);
        }, { status: "blocked" });
      },
      abandon() {
        const expected = observation.current?.owner === owner ? observation.current.pending : null;
        if (!expected) return Promise.resolve(false);
        return coordinate(async () => {
          clearPolicyMutationIntent(window.localStorage, expected);
          publish(null);
          return true;
        }, false);
      }
    };
  }, [owner, view, busyOwner, protect, onExpired, authorityPending]);
}
