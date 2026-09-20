"use client";

import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useRef,
  useState,
  type ReactNode
} from "react";
import { HttpProblem, requestToken } from "@/infrastructure/http/jsonRequest";
import type { AuthenticatedSession, OwnSessionPage } from "../domain/session";
import type { IamRepository } from "../repositories/iamRepository";

export type OwnSessionsError = "unavailable" | "forbidden" | "conflict" | "rejected";
export type OwnSessionsSuccess = "ended" | "replayed" | "others-ended" | "others-replayed";

type PendingRevocation = {
  credential: string;
  callerSessionId: string;
  targetSessionId: string;
  requestId: string;
};

type PendingOtherSessionsRevocation = {
  credential: string;
  callerSessionId: string;
  requestId: string;
};

type OwnSessionsContextValue = {
  supported: boolean;
  page: OwnSessionPage | null;
  loading: boolean;
  revokingId: string | null;
  revokingOthers: boolean;
  error: OwnSessionsError | null;
  success: OwnSessionsSuccess | null;
  otherRevokedCount: number | null;
  uncertainTargetId: string | null;
  uncertainOthers: boolean;
  load(after?: string): Promise<boolean>;
  revoke(targetSessionId: string): Promise<boolean>;
  revokeOthers(): Promise<boolean>;
  clearFeedback(): void;
};

const OwnSessionsContext = createContext<OwnSessionsContextValue | null>(null);

type OwnSessionsProviderProps = {
  children: ReactNode;
  repository: IamRepository;
  credential: string | null;
  current: AuthenticatedSession | null;
  expire(expectedCredential: string): boolean;
};

function identityKey(credential: string | null, current: AuthenticatedSession | null): string | null {
  return credential && current
    ? `${credential}\u0000${current.session.organizationId}\u0000${current.session.principalId}\u0000${current.session.id}`
    : null;
}

export function OwnSessionsProvider(props: OwnSessionsProviderProps) {
  const ownerKey = identityKey(props.credential, props.current);
  return <OwnSessionsStateProvider {...props} key={ownerKey ?? "anonymous"} ownerKey={ownerKey} />;
}

function OwnSessionsStateProvider({ children, repository, credential, current, expire, ownerKey }: OwnSessionsProviderProps & { ownerKey: string | null }) {
  const pending = useRef<PendingRevocation | null>(null);
  const pendingOthers = useRef<PendingOtherSessionsRevocation | null>(null);
  const [page, setPage] = useState<OwnSessionPage | null>(null);
  const [loading, setLoading] = useState(false);
  const [revokingId, setRevokingId] = useState<string | null>(null);
  const [revokingOthers, setRevokingOthers] = useState(false);
  const [error, setError] = useState<OwnSessionsError | null>(null);
  const [success, setSuccess] = useState<OwnSessionsSuccess | null>(null);
  const [otherRevokedCount, setOtherRevokedCount] = useState<number | null>(null);
  const [uncertainTargetId, setUncertainTargetId] = useState<string | null>(null);
  const [uncertainOthers, setUncertainOthers] = useState(false);
  const supported = Boolean(repository.sessions && credential && current);

  const clearFeedback = useCallback(() => {
    setError(null);
    setSuccess(null);
    setOtherRevokedCount(null);
  }, []);

  const load = useCallback(async (after?: string) => {
    if (!repository.sessions || !credential || !current || !ownerKey) return false;
    const expectedCredential = credential;
    setLoading(true);
    setError(null);
    try {
      const result = await repository.sessions.list(expectedCredential, after);
      if (
        result.accountId !== current.session.organizationId ||
        result.userId !== current.session.principalId ||
        result.currentSessionId !== current.session.id
      ) {
        throw new Error("INVALID_IAM_RESPONSE");
      }
      setPage(result);
      return true;
    } catch (loadError) {
      if (loadError instanceof HttpProblem && loadError.status === 401) {
        pending.current = null;
        pendingOthers.current = null;
        setUncertainTargetId(null);
        setUncertainOthers(false);
        expire(expectedCredential);
      } else {
        setError(loadError instanceof HttpProblem && loadError.status === 403 ? "forbidden" : "unavailable");
      }
      return false;
    } finally {
      setLoading(false);
    }
  }, [credential, current, expire, ownerKey, repository.sessions]);

  const revoke = useCallback(async (targetSessionId: string) => {
    if (!repository.sessions || !credential || !current || !ownerKey) return false;
    if (pendingOthers.current) {
      setError("conflict");
      setSuccess(null);
      return false;
    }
    if (targetSessionId === current.session.id) {
      setError("conflict");
      setSuccess(null);
      return false;
    }
    const expectedCredential = credential;
    const existing = pending.current;
    if (existing && (
      existing.credential !== expectedCredential ||
      existing.callerSessionId !== current.session.id
    )) {
      pending.current = null;
      setUncertainTargetId(null);
    } else if (existing && existing.targetSessionId !== targetSessionId) {
      setError("conflict");
      setSuccess(null);
      return false;
    }
    const command = pending.current ?? {
      credential: expectedCredential,
      callerSessionId: current.session.id,
      targetSessionId,
      requestId: requestToken("ui-session-revoke-")
    };
    pending.current = command;
    setRevokingId(targetSessionId);
    setError(null);
    setSuccess(null);
    setOtherRevokedCount(null);
    try {
      const result = await repository.sessions.revoke(expectedCredential, targetSessionId, command.requestId);
      pending.current = null;
      setUncertainTargetId(null);
      setPage((state) => state
        ? { ...state, items: state.items.filter((item) => item.id !== targetSessionId) }
        : state);
      setSuccess(result.outcome === "EQUAL_REPLAY" ? "replayed" : "ended");
      return true;
    } catch (revokeError) {
      if (revokeError instanceof HttpProblem && revokeError.status === 401) {
        pending.current = null;
        setUncertainTargetId(null);
        expire(expectedCredential);
      } else if (revokeError instanceof HttpProblem && [400, 403, 409, 413, 415, 422].includes(revokeError.status)) {
        pending.current = null;
        setUncertainTargetId(null);
        setError(revokeError.status === 403 ? "forbidden" : revokeError.status === 409 ? "conflict" : "rejected");
      } else {
        setUncertainTargetId(targetSessionId);
      }
      return false;
    } finally {
      setRevokingId(null);
    }
  }, [credential, current, expire, ownerKey, repository.sessions]);

  const revokeOthers = useCallback(async () => {
    if (!repository.sessions || !credential || !current || !ownerKey) return false;
    if (pending.current) {
      setError("conflict");
      setSuccess(null);
      return false;
    }
    const expectedCredential = credential;
    const existing = pendingOthers.current;
    if (existing && (
      existing.credential !== expectedCredential ||
      existing.callerSessionId !== current.session.id
    )) {
      pendingOthers.current = null;
      setUncertainOthers(false);
    }
    const command = pendingOthers.current ?? {
      credential: expectedCredential,
      callerSessionId: current.session.id,
      requestId: requestToken("ui-session-revoke-others-")
    };
    pendingOthers.current = command;
    setRevokingOthers(true);
    setError(null);
    setSuccess(null);
    setOtherRevokedCount(null);
    try {
      const result = await repository.sessions.revokeOthers(expectedCredential, command.requestId);
      if (
        result.accountId !== current.session.organizationId ||
        result.userId !== current.session.principalId ||
        result.currentSessionId !== current.session.id ||
        result.requestId !== command.requestId
      ) throw new Error("INVALID_IAM_RESPONSE");
      pendingOthers.current = null;
      setUncertainOthers(false);
      setPage((state) => state
        ? { ...state, items: state.items.filter((item) => item.id === current.session.id), nextCursor: null }
        : state);
      setOtherRevokedCount(result.revokedCount);
      setSuccess(result.outcome === "EQUAL_REPLAY" ? "others-replayed" : "others-ended");
      return true;
    } catch (revokeError) {
      if (revokeError instanceof HttpProblem && revokeError.status === 401) {
        pendingOthers.current = null;
        setUncertainOthers(false);
        expire(expectedCredential);
      } else if (revokeError instanceof HttpProblem && [400, 403, 409, 413, 415, 422].includes(revokeError.status)) {
        pendingOthers.current = null;
        setUncertainOthers(false);
        setError(revokeError.status === 403 ? "forbidden" : revokeError.status === 409 ? "conflict" : "rejected");
      } else {
        setUncertainOthers(true);
      }
      return false;
    } finally {
      setRevokingOthers(false);
    }
  }, [credential, current, expire, ownerKey, repository.sessions]);

  const value = useMemo<OwnSessionsContextValue>(() => ({
    supported,
    page,
    loading,
    revokingId,
    revokingOthers,
    error,
    success,
    otherRevokedCount,
    uncertainTargetId,
    uncertainOthers,
    load,
    revoke,
    revokeOthers,
    clearFeedback
  }), [clearFeedback, error, load, loading, otherRevokedCount, page, revoke, revokeOthers, revokingId, revokingOthers, success, supported, uncertainOthers, uncertainTargetId]);

  return <OwnSessionsContext.Provider value={value}>{children}</OwnSessionsContext.Provider>;
}

export function useOwnSessions(): OwnSessionsContextValue {
  const value = useContext(OwnSessionsContext);
  if (!value) throw new Error("useOwnSessions must be used inside OwnSessionsProvider");
  return value;
}
