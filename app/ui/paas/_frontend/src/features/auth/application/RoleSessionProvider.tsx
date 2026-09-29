"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode
} from "react";
import { HttpProblem } from "@/infrastructure/http/jsonRequest";
import type { AuthenticatedSession } from "../domain/session";
import type {
  AssumableRole,
  AssumableRoleDirectory,
  CurrentRoleIdentity,
  LiveRoleSession
} from "../domain/roles";
import type { IamRepository } from "../repositories/iamRepository";

export type RoleSessionStage =
  | "idle"
  | "ready"
  | "denied"
  | "conflict"
  | "assume-unknown"
  | "not-found"
  | "located"
  | "revoked"
  | "activation-unknown"
  | "role-active"
  | "role-expired"
  | "exit-unknown"
  | "source-validation-unknown";

export type RoleSessionError = "expired" | "denied" | "conflict" | "unavailable" | "invalidResponse" | null;

export type RoleAssumeIntent = Readonly<{
  role: AssumableRole;
  durationSeconds: number;
  requestId: string;
  revokeRequestId: string;
  logoutRequestId: string;
}>;

type BusyOperation = "discover" | "more" | "assume" | "locate" | "revoke" | "activate" | "exit" | "restore" | null;

type RoleSessionContextValue = {
  supported: boolean;
  mode: "USER" | "ROLE" | "BLOCKED";
  stage: RoleSessionStage;
  busy: BusyOperation;
  error: RoleSessionError;
  directory: AssumableRoleDirectory | null;
  intent: RoleAssumeIntent | null;
  observedSession: LiveRoleSession | null;
  identity: CurrentRoleIdentity | null;
  discover(reset?: boolean): Promise<boolean>;
  assume(role: AssumableRole, durationSeconds: number): Promise<boolean>;
  retryAssume(): Promise<boolean>;
  locateOriginal(): Promise<boolean>;
  revokeOriginal(): Promise<boolean>;
  retryActivation(): Promise<boolean>;
  exitRole(): Promise<boolean>;
  retryExit(): Promise<boolean>;
  revokeAndRestoreSource(): Promise<boolean>;
  restoreSource(): Promise<boolean>;
  clearAttempt(): void;
};

const RoleSessionContext = createContext<RoleSessionContextValue | null>(null);
const EffectiveCredentialContext = createContext<string | null>(null);

function operationFailure(error: unknown): RoleSessionError {
  if (error instanceof HttpProblem) {
    if (error.status === 401) return "expired";
    if (error.status === 403) return "denied";
    if (error.status === 409) return "conflict";
    if ([400, 404, 413, 415, 422].includes(error.status)) return "denied";
    return "unavailable";
  }
  if (error instanceof Error && error.message === "INVALID_IAM_RESPONSE") return "invalidResponse";
  return "unavailable";
}

function requestId(prefix: string): string {
  return `${prefix}${crypto.randomUUID()}`;
}

function sameSession(left: LiveRoleSession, right: LiveRoleSession): boolean {
  return left.id === right.id && left.accountId === right.accountId && left.roleId === right.roleId &&
    left.sourceUserId === right.sourceUserId && left.issuedAt === right.issuedAt && left.expiresAt === right.expiresAt;
}

export function RoleSessionProvider({
  children,
  current,
  expireSource,
  repository,
  sourceCredential
}: {
  children: ReactNode;
  current: AuthenticatedSession | null;
  expireSource(expectedCredential: string): boolean;
  repository: IamRepository;
  sourceCredential: string | null;
}) {
  const service = repository.roleSelfService;
  const [directory, setDirectory] = useState<AssumableRoleDirectory | null>(null);
  const [stage, setStage] = useState<RoleSessionStage>("idle");
  const [busy, setBusy] = useState<BusyOperation>(null);
  const [error, setError] = useState<RoleSessionError>(null);
  const [intent, setIntent] = useState<RoleAssumeIntent | null>(null);
  const [observedSession, setObservedSession] = useState<LiveRoleSession | null>(null);
  const [identity, setIdentity] = useState<CurrentRoleIdentity | null>(null);
  const [activeCredential, setActiveCredential] = useState<string | null>(null);
  const [activeSourceCredential, setActiveSourceCredential] = useState<string | null>(null);
  const roleCredential = useRef<string | null>(null);
  const sourceCredentialRef = useRef(sourceCredential);
  const intentRef = useRef<RoleAssumeIntent | null>(null);
  const identityRef = useRef<CurrentRoleIdentity | null>(null);
  const operationRevision = useRef(0);

  useEffect(() => { intentRef.current = intent; }, [intent]);
  useEffect(() => { identityRef.current = identity; }, [identity]);

  const resetRole = useCallback((nextStage: RoleSessionStage = "idle") => {
    operationRevision.current += 1;
    roleCredential.current = null;
    setActiveCredential(null);
    setActiveSourceCredential(null);
    intentRef.current = null;
    identityRef.current = null;
    setDirectory(null);
    setIntent(null);
    setObservedSession(null);
    setIdentity(null);
    setBusy(null);
    setError(null);
    setStage(nextStage);
  }, []);

  useEffect(() => {
    const previous = sourceCredentialRef.current;
    sourceCredentialRef.current = sourceCredential;
    if (previous === sourceCredential) return;
    const credential = roleCredential.current;
    const activeIntent = intentRef.current;
    resetRole();
    if (credential && activeIntent && service) {
      void service.logout(credential, activeIntent.logoutRequestId).catch(() => undefined);
    }
  }, [resetRole, service, sourceCredential]);

  useEffect(() => {
    if (stage !== "role-active" || !identity) return;
    const remaining = Date.parse(identity.session.expiresAt) - Date.now();
    const expire = () => {
      if (identityRef.current !== identity || Date.now() < Date.parse(identity.session.expiresAt)) return;
      operationRevision.current += 1;
      roleCredential.current = null;
      setActiveCredential(null);
      setActiveSourceCredential(null);
      setBusy(null);
      setError(null);
      setStage("role-expired");
    };
    const timer = window.setTimeout(expire, Math.max(0, Math.min(remaining, 2_147_000_000)));
    window.addEventListener("focus", expire);
    document.addEventListener("visibilitychange", expire);
    return () => {
      window.clearTimeout(timer);
      window.removeEventListener("focus", expire);
      document.removeEventListener("visibilitychange", expire);
    };
  }, [identity, stage]);

  const expireCurrentSource = useCallback(() => {
    const credential = sourceCredentialRef.current;
    if (credential) expireSource(credential);
    resetRole();
  }, [expireSource, resetRole]);

  const validateDirectory = useCallback((page: AssumableRoleDirectory) => {
    if (!current || page.accountId !== current.session.organizationId || page.sourceUserId !== current.session.principalId) {
      throw new Error("INVALID_IAM_RESPONSE");
    }
  }, [current]);

  const discover = useCallback(async (reset = true) => {
    const credential = sourceCredentialRef.current;
    if (!service || !credential || !current || busy || stage === "role-active") return false;
    const after = reset ? undefined : directory?.nextAfter ?? undefined;
    if (!reset && !after) return false;
    const revision = ++operationRevision.current;
    setBusy(reset ? "discover" : "more");
    setError(null);
    try {
      const page = await service.listAssumable(credential, after);
      if (revision !== operationRevision.current || sourceCredentialRef.current !== credential) return false;
      validateDirectory(page);
      setDirectory((existing) => {
        if (reset || !existing) return page;
        if (existing.accountId !== page.accountId || existing.sourceUserId !== page.sourceUserId) throw new Error("INVALID_IAM_RESPONSE");
        const items = [...existing.items, ...page.items];
        if (new Set(items.map((item) => item.roleId)).size !== items.length) throw new Error("INVALID_IAM_RESPONSE");
        return { ...page, items };
      });
      setIntent(null);
      setObservedSession(null);
      setStage("ready");
      return true;
    } catch (failure) {
      if (revision !== operationRevision.current || sourceCredentialRef.current !== credential) return false;
      const reason = operationFailure(failure);
      if (reason === "expired") expireCurrentSource();
      else setError(reason);
      return false;
    } finally {
      if (revision === operationRevision.current) setBusy(null);
    }
  }, [busy, current, directory?.nextAfter, expireCurrentSource, service, stage, validateDirectory]);

  const activate = useCallback(async (credential: string, expected: LiveRoleSession, revision: number) => {
    if (!service || !current) return false;
    setBusy("activate");
    try {
      const nextIdentity = await service.currentIdentity(credential);
      if (revision !== operationRevision.current || roleCredential.current !== credential) return false;
      if (!sameSession(nextIdentity.session, expected) || nextIdentity.account.id !== current.session.organizationId ||
          nextIdentity.sourceUser.id !== current.session.principalId) throw new Error("INVALID_IAM_RESPONSE");
      identityRef.current = nextIdentity;
      setActiveCredential(credential);
      setActiveSourceCredential(sourceCredentialRef.current);
      setIdentity(nextIdentity);
      setObservedSession(nextIdentity.session);
      setError(null);
      setStage("role-active");
      return true;
    } catch (failure) {
      if (revision !== operationRevision.current || roleCredential.current !== credential) return false;
      const reason = operationFailure(failure);
      setError(reason);
      if (reason === "expired" || reason === "denied") {
        roleCredential.current = null;
        setActiveCredential(null);
        setActiveSourceCredential(null);
        setStage("located");
      } else setStage("activation-unknown");
      return false;
    } finally {
      if (revision === operationRevision.current) setBusy(null);
    }
  }, [current, service]);

  const submitAssume = useCallback(async (frozen: RoleAssumeIntent) => {
    const credential = sourceCredentialRef.current;
    if (!service || !credential || !current || busy) return false;
    const revision = ++operationRevision.current;
    setBusy("assume");
    setError(null);
    setIntent(frozen);
    intentRef.current = frozen;
    setObservedSession(null);
    try {
      const result = await service.assume(credential, frozen.role.roleId, {
        resourceVersion: frozen.role.resourceVersion,
        durationSeconds: frozen.durationSeconds,
        requestId: frozen.requestId
      });
      if (revision !== operationRevision.current || sourceCredentialRef.current !== credential) return false;
      if (result.session.accountId !== current.session.organizationId || result.session.sourceUserId !== current.session.principalId) {
        throw new Error("INVALID_IAM_RESPONSE");
      }
      setObservedSession(result.session);
      if (result.outcome === "EQUAL_REPLAY") {
        setStage("located");
        return false;
      }
      roleCredential.current = result.credential;
      setBusy(null);
      return activate(result.credential, result.session, revision);
    } catch (failure) {
      if (revision !== operationRevision.current || sourceCredentialRef.current !== credential) return false;
      const reason = operationFailure(failure);
      if (reason === "expired") expireCurrentSource();
      else if (reason === "denied") { setError(reason); setStage("denied"); }
      else if (reason === "conflict") { setError(reason); setStage("conflict"); }
      else { setError(reason); setStage("assume-unknown"); }
      return false;
    } finally {
      if (revision === operationRevision.current && busy !== "activate") setBusy(null);
    }
  }, [activate, busy, current, expireCurrentSource, service]);

  const assume = useCallback((role: AssumableRole, durationSeconds: number) => {
    if (!directory || !directory.items.some((item) => item.roleId === role.roleId && item.resourceVersion === role.resourceVersion) ||
        !Number.isSafeInteger(durationSeconds) || durationSeconds < 60 || durationSeconds > role.maxSessionDurationSeconds) return Promise.resolve(false);
    const frozen: RoleAssumeIntent = {
      role,
      durationSeconds,
      requestId: requestId("ui-role-assume-"),
      revokeRequestId: requestId("ui-role-revoke-"),
      logoutRequestId: requestId("ui-role-logout-")
    };
    return submitAssume(frozen);
  }, [directory, submitAssume]);

  const retryAssume = useCallback(() => intent ? submitAssume(intent) : Promise.resolve(false), [intent, submitAssume]);

  const locateOriginal = useCallback(async () => {
    const credential = sourceCredentialRef.current;
    if (!service || !credential || !current || !intent || busy) return false;
    const revision = ++operationRevision.current;
    setBusy("locate");
    setError(null);
    try {
      const session = await service.readByRequest(credential, intent.requestId);
      if (revision !== operationRevision.current || sourceCredentialRef.current !== credential) return false;
      if (session.accountId !== current.session.organizationId || session.sourceUserId !== current.session.principalId || session.roleId !== intent.role.roleId) {
        throw new Error("INVALID_IAM_RESPONSE");
      }
      setObservedSession(session);
      setStage("located");
      return true;
    } catch (failure) {
      if (revision !== operationRevision.current || sourceCredentialRef.current !== credential) return false;
      if (failure instanceof HttpProblem && failure.status === 404) {
        setStage("not-found");
        return false;
      }
      const reason = operationFailure(failure);
      if (reason === "expired") expireCurrentSource();
      else setError(reason);
      return false;
    } finally {
      if (revision === operationRevision.current) setBusy(null);
    }
  }, [busy, current, expireCurrentSource, intent, service]);

  const revokeOriginal = useCallback(async () => {
    const credential = sourceCredentialRef.current;
    if (!service || !credential || !current || !intent || !observedSession || busy) return false;
    const revision = ++operationRevision.current;
    setBusy("revoke");
    setError(null);
    try {
      const session = await service.revokeByRequest(credential, intent.requestId, intent.revokeRequestId);
      if (revision !== operationRevision.current || sourceCredentialRef.current !== credential) return false;
      if (!sameSession(session, observedSession) || session.status !== "REVOKED") throw new Error("INVALID_IAM_RESPONSE");
      setObservedSession(session);
      setStage("revoked");
      return true;
    } catch (failure) {
      if (revision !== operationRevision.current || sourceCredentialRef.current !== credential) return false;
      const reason = operationFailure(failure);
      if (reason === "expired") expireCurrentSource();
      else setError(reason);
      return false;
    } finally {
      if (revision === operationRevision.current) setBusy(null);
    }
  }, [busy, current, expireCurrentSource, intent, observedSession, service]);

  const retryActivation = useCallback(() => {
    const credential = roleCredential.current;
    if (!credential || !observedSession || busy) return Promise.resolve(false);
    const revision = ++operationRevision.current;
    return activate(credential, observedSession, revision);
  }, [activate, busy, observedSession]);

  const finishSourceRestore = useCallback(async (revision: number) => {
    const credential = sourceCredentialRef.current;
    if (!service || !credential || !current) return false;
    setBusy("restore");
    try {
      await service.revalidateSource(credential, current.session.organizationId, current.session.principalId);
      if (revision !== operationRevision.current || sourceCredentialRef.current !== credential) return false;
      resetRole();
      return true;
    } catch (failure) {
      if (revision !== operationRevision.current || sourceCredentialRef.current !== credential) return false;
      const reason = operationFailure(failure);
      if (reason === "expired") expireCurrentSource();
      else { setError(reason); setStage("source-validation-unknown"); }
      return false;
    } finally {
      if (revision === operationRevision.current) setBusy(null);
    }
  }, [current, expireCurrentSource, resetRole, service]);

  const performExit = useCallback(async () => {
    const credential = roleCredential.current;
    const activeIntent = intentRef.current;
    const activeSession = identityRef.current?.session ?? observedSession;
    if (!service || !credential || !activeIntent || !activeSession || busy) return false;
    const revision = ++operationRevision.current;
    setBusy("exit");
    setError(null);
    setStage("exit-unknown");
    setActiveCredential(null);
    setActiveSourceCredential(null);
    try {
      const session = await service.logout(credential, activeIntent.logoutRequestId);
      if (revision !== operationRevision.current || roleCredential.current !== credential) return false;
      if (!sameSession(session, activeSession) || session.status !== "REVOKED") throw new Error("INVALID_IAM_RESPONSE");
      roleCredential.current = null;
      setActiveCredential(null);
      setActiveSourceCredential(null);
      setObservedSession(session);
      return finishSourceRestore(revision);
    } catch (failure) {
      if (revision !== operationRevision.current || roleCredential.current !== credential) return false;
      setError(operationFailure(failure));
      setStage("exit-unknown");
      return false;
    } finally {
      if (revision === operationRevision.current && busy !== "restore") setBusy(null);
    }
  }, [busy, finishSourceRestore, observedSession, service]);

  const revokeAndRestoreSource = useCallback(async () => {
    const credential = sourceCredentialRef.current;
    const activeIntent = intentRef.current;
    const activeSession = identityRef.current?.session ?? observedSession;
    if (!service || !credential || !current || !activeIntent || !activeSession || busy) return false;
    const revision = ++operationRevision.current;
    setBusy("restore");
    setError(null);
    try {
      await service.revalidateSource(credential, current.session.organizationId, current.session.principalId);
      if (revision !== operationRevision.current || sourceCredentialRef.current !== credential) return false;
      const session = await service.revokeByRequest(credential, activeIntent.requestId, activeIntent.revokeRequestId);
      if (revision !== operationRevision.current || sourceCredentialRef.current !== credential) return false;
      if (!sameSession(session, activeSession) || session.status !== "REVOKED") throw new Error("INVALID_IAM_RESPONSE");
      roleCredential.current = null;
      setActiveCredential(null);
      setActiveSourceCredential(null);
      resetRole();
      return true;
    } catch (failure) {
      if (revision !== operationRevision.current || sourceCredentialRef.current !== credential) return false;
      const reason = operationFailure(failure);
      if (reason === "expired") expireCurrentSource();
      else { setError(reason); setStage("exit-unknown"); }
      return false;
    } finally {
      if (revision === operationRevision.current) setBusy(null);
    }
  }, [busy, current, expireCurrentSource, observedSession, resetRole, service]);

  const restoreSource = useCallback(() => {
    const revision = ++operationRevision.current;
    return finishSourceRestore(revision);
  }, [finishSourceRestore]);

  const clearAttempt = useCallback(() => {
    if (busy || stage === "activation-unknown" || stage === "role-active" || stage === "exit-unknown" || stage === "source-validation-unknown") return;
    operationRevision.current += 1;
    roleCredential.current = null;
    setActiveCredential(null);
    setActiveSourceCredential(null);
    intentRef.current = null;
    identityRef.current = null;
    setIntent(null);
    setObservedSession(null);
    setIdentity(null);
    setError(null);
    setStage(directory ? "ready" : "idle");
  }, [busy, directory, stage]);

  const blocked = stage === "exit-unknown" || stage === "source-validation-unknown" || stage === "role-expired";
  const mode = stage === "role-active" ? "ROLE" : blocked ? "BLOCKED" : "USER";
  const sourceCredentialUnchanged = sourceCredential !== null && sourceCredential === activeSourceCredential;
  const effectiveCredential = mode === "ROLE" ? sourceCredentialUnchanged ? activeCredential : null : mode === "USER" ? sourceCredential : null;
  const value = useMemo<RoleSessionContextValue>(() => ({
    supported: Boolean(service), mode, stage, busy, error, directory, intent, observedSession, identity,
    discover, assume, retryAssume, locateOriginal, revokeOriginal, retryActivation,
    exitRole: performExit, retryExit: performExit, revokeAndRestoreSource, restoreSource, clearAttempt
  }), [assume, busy, clearAttempt, directory, discover, error, identity, intent, locateOriginal, mode, observedSession, performExit, retryActivation, retryAssume, revokeAndRestoreSource, revokeOriginal, restoreSource, service, stage]);

  return <EffectiveCredentialContext.Provider value={effectiveCredential}>
    <RoleSessionContext.Provider value={value}>{children}</RoleSessionContext.Provider>
  </EffectiveCredentialContext.Provider>;
}

export function useRoleSession(): RoleSessionContextValue {
  const value = useContext(RoleSessionContext);
  if (!value) throw new Error("useRoleSession must be used inside RoleSessionProvider");
  return value;
}

export function useEffectiveCredential(): string | null {
  return useContext(EffectiveCredentialContext);
}
