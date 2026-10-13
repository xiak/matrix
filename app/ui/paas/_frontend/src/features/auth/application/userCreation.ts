"use client";

import { useLayoutEffect, useMemo, useRef, useState } from "react";
import { HttpProblem, requestToken } from "@/infrastructure/http/jsonRequest";
import type { CreateUserCommand, User } from "../domain/accounts";
import type { AccountRepository } from "../repositories/iamRepository";

export type UserCreationState =
  | { phase: "idle" }
  | { phase: "submitting" | "unknown"; requestId: string; loginName: string; displayName: string }
  | { phase: "rejected"; reason: "forbidden" | "expired" | "invalid" | "unavailable" }
  | { phase: "applied"; requestId: string; user: User; read: "checking" | "ready" | "unavailable" };

export type UserCreationClient = {
  state: UserCreationState;
  create(input: Pick<CreateUserCommand, "loginName" | "displayName" | "initialPassword">): Promise<boolean>;
  retry(): Promise<boolean>;
  reread(): Promise<void>;
  finish(): void;
};

type Owner = { accountId: string; credential: string; rootUserId: string; sessionRevision: number; repository: Pick<AccountRepository, "createUser" | "getUser"> };
type Intent = { owner: Owner; command: CreateUserCommand; retrying: boolean; phase: "submitting" | "unknown" };
type Confirmed = { owner: Owner; user: User; requestId: string; reading: boolean };

// Own the sensitive command outside route remounts. Only its non-secret
// projection reaches the renderer; a changed Session/repository cannot replay it.
export function useLiveUserCreation({ active, accountId, credential, rootUserId, sessionRevision, repository, onExpired, onCreated }: {
  active: boolean; accountId?: string; credential?: string; rootUserId?: string; sessionRevision: number;
  repository: Pick<AccountRepository, "createUser" | "getUser">;
  onExpired(credential: string, revision: number): void;
  onCreated(): void;
}): UserCreationClient | null {
  const owner = useMemo<Owner | null>(() => active && accountId && credential && rootUserId && repository.createUser
    ? { accountId, credential, rootUserId, sessionRevision, repository } : null,
  [active, accountId, credential, rootUserId, sessionRevision, repository]);
  const currentOwner = useRef(owner);
  const pending = useRef<Intent | Confirmed | null>(null);
  const [observation, setObservation] = useState<{ owner: Owner; state: UserCreationState } | null>(null);
  useLayoutEffect(() => {
    currentOwner.current = owner;
    if (pending.current?.owner !== owner) pending.current = null;
    return () => { currentOwner.current = null; pending.current = null; };
  }, [owner]);

  const state = useMemo<UserCreationState>(() => owner && observation?.owner === owner ? observation.state : { phase: "idle" }, [owner, observation]);
  return useMemo(() => {
    if (!owner) return null;
    const owns = (intent: Intent | Confirmed) => currentOwner.current === owner && pending.current === intent;
    const publish = (next: UserCreationState) => setObservation({ owner, state: next });
    const read = async (confirmed: Confirmed) => {
      if (!owns(confirmed) || confirmed.reading) return;
      confirmed.reading = true;
      publish({ phase: "applied", user: confirmed.user, requestId: confirmed.requestId, read: "checking" });
      try {
        const detail = await repository.getUser(owner.credential, confirmed.user.id);
        if (!owns(confirmed)) return;
        if (detail.user.accountId !== owner.accountId || detail.user.id !== confirmed.user.id ||
            detail.user.loginName !== confirmed.user.loginName || detail.user.resourceVersion < confirmed.user.resourceVersion) {
          throw new Error("INVALID_IAM_RESPONSE");
        }
        publish({ phase: "applied", user: detail.user, requestId: confirmed.requestId, read: "ready" });
        onCreated();
      } catch (failure) {
        if (!owns(confirmed)) return;
        publish({ phase: "applied", user: confirmed.user, requestId: confirmed.requestId, read: "unavailable" });
        if (failure instanceof HttpProblem && failure.status === 401) onExpired(owner.credential, owner.sessionRevision);
      } finally { confirmed.reading = false; }
    };
    const attempt = async (intent: Intent): Promise<boolean> => {
      if (!owns(intent)) return false;
      publish({ phase: "submitting", requestId: intent.command.requestId, loginName: intent.command.loginName, displayName: intent.command.displayName });
      try {
        const user = await repository.createUser!(owner.credential, owner.accountId, intent.command);
        if (!owns(intent)) return false;
        if (user.accountId !== owner.accountId || user.id === owner.rootUserId || user.loginName !== intent.command.loginName ||
            user.displayName !== intent.command.displayName || user.status !== "ACTIVE" || user.resourceVersion !== 1 || !user.mustChangePassword) {
          throw new Error("INVALID_IAM_RESPONSE");
        }
        const confirmed: Confirmed = { owner, user, requestId: intent.command.requestId, reading: false };
        pending.current = confirmed; // Discard the password before any authoritative reread.
        await read(confirmed);
        return owns(confirmed);
      } catch (failure) {
        if (!owns(intent)) return false;
        if (!intent.retrying && failure instanceof HttpProblem && [400, 401, 403, 404, 413, 415, 422].includes(failure.status)) {
          pending.current = null;
          publish({ phase: "rejected", reason: failure.status === 401 ? "expired" : failure.status === 403 ? "forbidden" : failure.status === 404 ? "unavailable" : "invalid" });
        } else {
          intent.phase = "unknown";
          publish({ phase: "unknown", requestId: intent.command.requestId, loginName: intent.command.loginName, displayName: intent.command.displayName });
        }
        if (failure instanceof HttpProblem && failure.status === 401) onExpired(owner.credential, owner.sessionRevision);
        return false;
      }
    };
    return {
      state,
      create(input) {
        if (currentOwner.current !== owner || pending.current) return Promise.resolve(false);
        const intent: Intent = { owner, retrying: false, phase: "submitting", command: Object.freeze({ loginName: input.loginName, displayName: input.displayName,
          initialPassword: input.initialPassword, permissionBoundary: null, requestId: requestToken("ui-user-create-") }) };
        pending.current = intent;
        return attempt(intent);
      },
      retry() {
        const previous = pending.current;
        if (!previous || !("command" in previous) || !owns(previous) || previous.phase !== "unknown") return Promise.resolve(false);
        const intent: Intent = { ...previous, retrying: true, phase: "submitting" };
        pending.current = intent;
        return attempt(intent);
      },
      async reread() {
        const confirmed = pending.current;
        if (confirmed && "user" in confirmed && state.phase === "applied" && state.read !== "checking") await read(confirmed);
      },
      finish() {
        const confirmed = pending.current;
        if (confirmed && "user" in confirmed && owns(confirmed) && state.phase === "applied" && state.read !== "checking") {
          pending.current = null; publish({ phase: "idle" });
        }
      }
    } satisfies UserCreationClient;
  }, [owner, repository, state, onCreated, onExpired]);
}
