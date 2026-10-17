"use client";

import { useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { HttpProblem, requestToken } from "@/infrastructure/http/jsonRequest";
import { groupMembershipResultMatches, type GroupMembership, type GroupMembershipMutationIntent } from "../domain/accounts";
import type { GroupAccessClient } from "./AccountAccessProvider";
import { clearGroupMembershipIntent, parseGroupMembershipIntent, readGroupMembershipIntent, writeGroupMembershipIntent } from "../repositories/groupMembershipRecoveryStorage";

type Failure = "expired" | "forbidden" | "conflict" | "invalid" | "unavailable";
type Result = { status: "applied"; membership: GroupMembership } | { status: "unknown" | "blocked" } | { status: "rejected"; reason: Failure };
export type GroupMembershipMutationClient = {
  ready: boolean;
  recoveryError: boolean;
  pending: GroupMembershipMutationIntent | null;
  receipt: GroupMembership | null;
  busy: boolean;
  error: Failure | null;
  begin(input: { operation: "CREATE"; userId: string } | { operation: "REMOVE"; membership: GroupMembership }): Promise<Result>;
  retry(): Promise<Result>;
  acknowledge(): boolean;
};

function failureReason(failure: unknown): Failure {
  if (failure instanceof HttpProblem) {
    if (failure.status === 401) return "expired";
    if (failure.status === 403) return "forbidden";
    if (failure.status === 409) return "conflict";
    if ([400, 413, 415, 422, 429].includes(failure.status)) return "invalid";
  }
  return "unavailable";
}

// The original non-secret command survives route/Session reconstruction.
// A current Membership read is never an outcome query or an implicit replay.
export function useGroupMembershipMutation(client: GroupAccessClient, groupId: string): GroupMembershipMutationClient {
  const owner = useMemo(() => ({ identity: client.identity, accountId: client.accountId, actorPrincipalId: client.actorPrincipalId, groupId }),
    [client.identity, client.accountId, client.actorPrincipalId, groupId]);
  type Observation = { owner: typeof owner; ready: boolean; recoveryError: boolean; pending: GroupMembershipMutationIntent | null; receipt: GroupMembership | null; error: Failure | null };
  const [view, setView] = useState<Observation | null>(null);
  const observed = useRef<Observation | null>(null);
  const current = useRef<typeof owner | null>(owner);
  const inFlight = useRef<typeof owner | null>(null);
  const [busyOwner, setBusyOwner] = useState<typeof owner | null>(null);
  useLayoutEffect(() => { current.current = owner; return () => { current.current = null; }; }, [owner]);
  useEffect(() => {
    if (current.current !== owner) return;
    let next: Observation;
    try { next = { owner, ready: true, recoveryError: false, pending: readGroupMembershipIntent(window.sessionStorage, owner), receipt: null, error: null }; }
    catch { next = { owner, ready: false, recoveryError: true, pending: null, receipt: null, error: "unavailable" }; }
    observed.current = next; setView(next);
  }, [owner]);

  const snapshot = view?.owner === owner ? view : null;
  const publish = (next: Omit<Observation, "owner">) => {
    if (current.current !== owner) return;
    const value = { owner, ...next }; observed.current = value; setView(value);
  };
  const dispatch = async (intent: GroupMembershipMutationIntent, retrying: boolean): Promise<Result> => {
    try {
      const result = intent.operation === "CREATE"
        ? await client.createMembership(intent.groupId, { userId: intent.userId, requestId: intent.requestId })
        : await client.removeMembership(intent.groupId, intent.membershipId, { resourceVersion: intent.resourceVersion, requestId: intent.requestId });
      if (current.current !== owner) return { status: "blocked" };
      if (!groupMembershipResultMatches(result, intent)) throw new Error("INVALID_MEMBERSHIP_RESULT");
      // Keep known success separate from subsequent storage or current-read errors.
      const receipt = Object.freeze(structuredClone(result));
      publish({ ready: true, recoveryError: false, pending: intent, receipt, error: null });
      return { status: "applied", membership: receipt };
    } catch (failure) {
      if (current.current !== owner) return { status: "blocked" };
      const reason = failureReason(failure);
      if (!retrying && failure instanceof HttpProblem && reason !== "unavailable") {
        try {
          clearGroupMembershipIntent(window.sessionStorage, intent);
          publish({ ready: true, recoveryError: false, pending: null, receipt: null, error: reason });
          if (reason === "expired") client.expire();
          return { status: "rejected", reason };
        } catch {
          publish({ ready: false, recoveryError: true, pending: intent, receipt: null, error: reason });
          if (reason === "expired") client.expire();
          return { status: "unknown" };
        }
      }
      publish({ ready: true, recoveryError: false, pending: intent, receipt: null, error: reason });
      if (reason === "expired") client.expire();
      return { status: "unknown" };
    }
  };
  const coordinate = async (run: () => Promise<Result>): Promise<Result> => {
    if (current.current !== owner || inFlight.current === owner || observed.current?.owner !== owner || !observed.current.ready) return { status: "blocked" };
    inFlight.current = owner; setBusyOwner(owner);
    try { return await run(); }
    catch {
      if (current.current === owner) publish({ ready: false, recoveryError: true, pending: observed.current?.owner === owner ? observed.current.pending : null, receipt: null, error: "unavailable" });
      return { status: "blocked" };
    } finally {
      if (inFlight.current === owner) inFlight.current = null;
      if (current.current === owner) setBusyOwner(null);
    }
  };
  return {
    ready: snapshot?.ready ?? false, recoveryError: snapshot?.recoveryError ?? false,
    pending: snapshot?.pending ?? null, receipt: snapshot?.receipt ?? null, error: snapshot?.error ?? null, busy: busyOwner === owner,
    begin(input) {
      const frozen = structuredClone(input);
      return coordinate(async () => {
        const pending = readGroupMembershipIntent(window.sessionStorage, owner);
        if (pending || observed.current?.pending) {
          if (pending) publish({ ready: true, recoveryError: false, pending, receipt: observed.current?.receipt ?? null, error: null });
          return { status: "blocked" };
        }
        if (!frozen || typeof frozen !== "object" || Array.isArray(frozen) || (frozen.operation !== "CREATE" && frozen.operation !== "REMOVE") ||
            Object.keys(frozen).length !== 2 || !Object.hasOwn(frozen, frozen.operation === "CREATE" ? "userId" : "membership")) return { status: "blocked" };
        if (frozen.operation === "REMOVE" && (frozen.membership.accountId !== owner.accountId || frozen.membership.groupId !== owner.groupId || frozen.membership.removedAt !== undefined)) return { status: "blocked" };
        const intent = parseGroupMembershipIntent({ format: 1, accountId: owner.accountId, actorPrincipalId: owner.actorPrincipalId,
          groupId: owner.groupId, requestId: requestToken("ui-group-membership-"),
          ...(frozen.operation === "CREATE" ? { operation: "CREATE", userId: frozen.userId } : { operation: "REMOVE", membershipId: frozen.membership.id, resourceVersion: frozen.membership.resourceVersion, userId: frozen.membership.userId }) });
        if (!intent) return { status: "blocked" };
        writeGroupMembershipIntent(window.sessionStorage, intent);
        publish({ ready: true, recoveryError: false, pending: intent, receipt: null, error: null });
        return dispatch(intent, false);
      });
    },
    retry() {
      return coordinate(async () => {
        const known = observed.current;
        if (known?.owner !== owner || !known.pending || known.receipt) return { status: "blocked" };
        const stored = readGroupMembershipIntent(window.sessionStorage, owner);
        if (!stored || JSON.stringify(stored) !== JSON.stringify(known.pending)) throw new Error("MEMBERSHIP_REMINDER_CHANGED");
        return dispatch(stored, true);
      });
    },
    acknowledge() {
      const known = observed.current;
      if (current.current !== owner || inFlight.current === owner || known?.owner !== owner || !known.pending || !known.receipt) return false;
      try {
        clearGroupMembershipIntent(window.sessionStorage, known.pending);
        publish({ ready: true, recoveryError: false, pending: null, receipt: known.receipt, error: null });
        return true;
      } catch {
        publish({ ...known, ready: false, recoveryError: true });
        return false;
      }
    }
  };
}
