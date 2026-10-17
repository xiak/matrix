"use client";

import { useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { HttpProblem, requestToken } from "@/infrastructure/http/jsonRequest";
import { userManagementCompletionMatches, userManagementResultMatches, type User, type UserManagementCompletion, type UserManagementIntent } from "../domain/accounts";
import type { UserManagementClient } from "./AccountAccessProvider";
import { clearUserManagementIntent, parseUserManagementIntent, readUserManagementIntent, writeUserManagementIntent } from "../repositories/userManagementRecoveryStorage";

export class UserManagementReviewRejected extends Error { constructor() { super("USER_MANAGEMENT_REVIEW_CHANGED"); } }
type Failure = "expired" | "forbidden" | "conflict" | "invalid" | "unavailable";
export type UserManagementReceipt = Readonly<{ intent: UserManagementIntent; result: User; completion?: UserManagementCompletion }>;
type Outcome = { status: "applied" } | { status: "unknown" | "blocked" } | { status: "rejected"; reason: Failure };
export type UserManagementDraft = { operation: "USER_UPDATE"; expectedResourceVersion: number; intendedDisplayName: string } |
  { operation: "USER_SET_STATUS"; expectedResourceVersion: number; intendedStatus: User["status"] };
export type UserManagementMutation = {
  ready: boolean; recoveryError: boolean; pending: UserManagementIntent | null; receipt: UserManagementReceipt | null; busy: boolean; error: Failure | null;
  begin(input: UserManagementDraft): Promise<Outcome>; inspect(): Promise<Outcome>; acknowledge(): boolean;
};
function failureReason(failure: unknown): Failure {
  if (failure instanceof UserManagementReviewRejected) return "conflict";
  if (failure instanceof HttpProblem) {
    if (failure.status === 401) return "expired";
    if (failure.status === 403) return "forbidden";
    if (failure.status === 409) return "conflict";
    if ([400, 413, 415, 422].includes(failure.status)) return "invalid";
  }
  return "unavailable";
}

// Recovery is an explicit original-result read, never a write replay or a
// comparison with the current User's values.
export function useUserManagementMutation(client: UserManagementClient | null, userId: string): UserManagementMutation {
  const identity = client?.identity, accountId = client?.accountId, actorPrincipalId = client?.actorPrincipalId;
  const owner = useMemo(() => identity && accountId && actorPrincipalId ? { identity, accountId, actorPrincipalId, userId } : null,
    [identity, accountId, actorPrincipalId, userId]);
  type Observation = { owner: typeof owner; ready: boolean; recoveryError: boolean; pending: UserManagementIntent | null; receipt: UserManagementReceipt | null; error: Failure | null };
  const [view, setView] = useState<Observation | null>(null);
  const observed = useRef<Observation | null>(null);
  const current = useRef<typeof owner>(owner);
  const inFlight = useRef<typeof owner>(null);
  const [busyOwner, setBusyOwner] = useState<typeof owner>(null);
  useLayoutEffect(() => { current.current = owner; return () => { current.current = null; }; }, [owner]);
  useEffect(() => {
    if (!owner || current.current !== owner) return;
    let next: Observation;
    try { next = { owner, ready: true, recoveryError: false, pending: readUserManagementIntent(window.sessionStorage, owner), receipt: null, error: null }; }
    catch { next = { owner, ready: false, recoveryError: true, pending: null, receipt: null, error: "unavailable" }; }
    observed.current = next; setView(next);
  }, [owner]);
  const snapshot = owner && view?.owner === owner ? view : null;
  const publish = (next: Omit<Observation, "owner">) => {
    if (!owner || current.current !== owner) return;
    const value = { owner, ...next }; observed.current = value; setView(value);
  };
  const perform = async (intent: UserManagementIntent, inspecting: boolean): Promise<Outcome> => {
    if (!owner || !client) return { status: "blocked" };
    try {
      let result: User;
      let completion: UserManagementCompletion | undefined;
      if (inspecting) {
        completion = await client.readCompletion(intent);
        if (current.current !== owner) return { status: "blocked" };
        if (!userManagementCompletionMatches(completion, intent)) throw new Error("INVALID_USER_MANAGEMENT_RESULT");
        result = completion.result;
      } else {
        result = await client.submit(intent);
        if (current.current !== owner) return { status: "blocked" };
        if (!userManagementResultMatches(result, intent)) throw new Error("INVALID_USER_MANAGEMENT_RESULT");
      }
      const frozenResult = Object.freeze(structuredClone(result));
      const receipt = Object.freeze({ intent, result: frozenResult, ...(completion ? { completion: Object.freeze({ ...structuredClone(completion), result: frozenResult }) } : {}) });
      publish({ ready: true, recoveryError: false, pending: intent, receipt, error: null });
      return { status: "applied" };
    } catch (failure) {
      if (current.current !== owner) return { status: "blocked" };
      const reason = failureReason(failure);
      if (!inspecting && (failure instanceof UserManagementReviewRejected || failure instanceof HttpProblem && reason !== "unavailable")) {
        try {
          clearUserManagementIntent(window.sessionStorage, intent);
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
  const coordinate = async (run: () => Promise<Outcome>): Promise<Outcome> => {
    if (!owner || current.current !== owner || inFlight.current === owner || observed.current?.owner !== owner || !observed.current.ready) return { status: "blocked" };
    inFlight.current = owner; setBusyOwner(owner);
    try { return await run(); }
    catch {
      if (current.current === owner) publish({ ready: false, recoveryError: true, pending: observed.current?.pending ?? null, receipt: observed.current?.receipt ?? null, error: "unavailable" });
      return { status: "blocked" };
    } finally {
      if (inFlight.current === owner) inFlight.current = null;
      if (current.current === owner) setBusyOwner(null);
    }
  };
  return {
    ready: snapshot?.ready ?? false, recoveryError: snapshot?.recoveryError ?? false, pending: snapshot?.pending ?? null,
    receipt: snapshot?.receipt ?? null, busy: Boolean(owner && busyOwner === owner), error: snapshot?.error ?? null,
    begin(input) {
      const frozen = structuredClone(input);
      return coordinate(async () => {
        if (!owner || !client) return { status: "blocked" };
        const pending = readUserManagementIntent(window.sessionStorage, owner);
        if (pending || observed.current?.pending) {
          if (pending) publish({ ready: true, recoveryError: false, pending, receipt: observed.current?.receipt ?? null, error: null });
          return { status: "blocked" };
        }
        if (!frozen || typeof frozen !== "object" || Array.isArray(frozen) || Object.keys(frozen).length !== 3 ||
            !Object.hasOwn(frozen, "operation") || !Object.hasOwn(frozen, "expectedResourceVersion") ||
            !Object.hasOwn(frozen, frozen.operation === "USER_UPDATE" ? "intendedDisplayName" : "intendedStatus")) return { status: "blocked" };
        const intent = parseUserManagementIntent({ format: 1, accountId: owner.accountId, actorPrincipalId: owner.actorPrincipalId, userId: owner.userId,
          commandRequestId: requestToken("ui-user-management-"), expectedResourceVersion: frozen.expectedResourceVersion,
          ...(frozen.operation === "USER_UPDATE" ? { operation: frozen.operation, intendedDisplayName: frozen.intendedDisplayName } : { operation: frozen.operation, intendedStatus: frozen.intendedStatus }) });
        if (!intent) return { status: "blocked" };
        if (!client.canBegin(intent)) { publish({ ready: true, recoveryError: false, pending: null, receipt: null, error: "conflict" }); return { status: "rejected", reason: "conflict" }; }
        writeUserManagementIntent(window.sessionStorage, intent);
        publish({ ready: true, recoveryError: false, pending: intent, receipt: null, error: null });
        return perform(intent, false);
      });
    },
    inspect() {
      return coordinate(async () => {
        if (!owner) return { status: "blocked" };
        const known = observed.current;
        if (known?.owner !== owner || !known.pending || known.receipt) return { status: "blocked" };
        const stored = readUserManagementIntent(window.sessionStorage, owner);
        if (!stored || JSON.stringify(stored) !== JSON.stringify(known.pending)) throw new Error("USER_MANAGEMENT_REMINDER_CHANGED");
        return perform(stored, true);
      });
    },
    acknowledge() {
      const known = observed.current;
      if (!owner || current.current !== owner || inFlight.current === owner || known?.owner !== owner || !known.pending || !known.receipt) return false;
      try { clearUserManagementIntent(window.sessionStorage, known.pending); publish({ ready: true, recoveryError: false, pending: null, receipt: known.receipt, error: null }); return true; }
      catch { publish({ ...known, ready: false, recoveryError: true }); return false; }
    }
  };
}
