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
import type {
  AuthenticatedSession,
  LoginOutcome,
  SessionPhase
} from "../domain/session";
import { httpIamRepository } from "../repositories/httpIamRepository";
import type { IamRepository } from "../repositories/iamRepository";

type SessionContextValue = {
  phase: SessionPhase;
  current: AuthenticatedSession | null;
  error: string | null;
  clearError(): void;
  login(loginName: string, password: string): Promise<LoginOutcome | null>;
  changePassword(currentPassword: string, newPassword: string, revokeOtherSessions?: boolean): Promise<boolean>;
  logout(): Promise<boolean>;
};

type CredentialContextValue = {
  credential: string | null;
};

const SessionContext = createContext<SessionContextValue | null>(null);
const CredentialContext = createContext<CredentialContextValue | null>(null);

function authenticationMessage(error: unknown): string {
  if (error instanceof HttpProblem && error.status === 401) {
    return "账号、主账号标识或密码不正确";
  }
  if (error instanceof HttpProblem && error.status === 429) {
    return "登录尝试过于频繁，请稍后重试";
  }
  return "IAM 暂时不可用，请稍后重试";
}

function passwordChangeMessage(error: unknown): string {
  if (error instanceof HttpProblem && error.status === 401) {
    return "当前密码不正确，或登录会话已经失效，请重新登录";
  }
  if (error instanceof HttpProblem && error.status === 422) {
    return "新密码需为 14–128 字节，且至少包含三类：大写字母、小写字母、数字、符号";
  }
  if (error instanceof HttpProblem && error.status === 409) {
    return "密码已在其他会话中更新，请重新登录";
  }
  return "无法确认改密结果，请重新登录后核对";
}

export function SessionProvider({
  children,
  repository = httpIamRepository
}: {
  children: ReactNode;
  repository?: IamRepository;
}) {
  const [phase, setPhase] = useState<SessionPhase>("anonymous");
  const [current, setCurrent] = useState<AuthenticatedSession | null>(null);
  const [credential, setCredential] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const transition = useRef(0);
  const clearError = useCallback(() => { setError(null); }, []);

  const forget = useCallback(() => {
    transition.current++;
    setCredential(null);
    setCurrent(null);
    setError(null);
    setPhase("anonymous");
  }, []);

  useEffect(() => () => { transition.current++; }, []);

  useEffect(() => {
    if (!current) return;
    const remaining = Date.parse(current.session.expiresAt) - Date.now();
    const delay = !Number.isFinite(remaining) || remaining <= 0
      ? 0
      : Math.min(remaining, 2_147_000_000);
    const timer = window.setTimeout(forget, delay);
    return () => window.clearTimeout(timer);
  }, [current, forget]);

  const login = useCallback(async (loginName: string, password: string) => {
    const attempt = ++transition.current;
    setPhase("authenticating");
    setError(null);
    try {
      const result = await repository.login({ loginName, password });
      if (attempt !== transition.current) return null;
      setCredential(result.credential);
      setCurrent({ loginName, session: result.session });
      const outcome: LoginOutcome = result.mustChangePassword
        ? "password-change-required"
        : "authenticated";
      setPhase(outcome);
      return outcome;
    } catch (loginError) {
      if (attempt !== transition.current) return null;
      setCredential(null);
      setCurrent(null);
      setError(authenticationMessage(loginError));
      setPhase("anonymous");
      return null;
    }
  }, [repository]);

  const changePassword = useCallback(async (
    currentPassword: string,
    newPassword: string,
    revokeOtherSessions = true
  ) => {
    if (!credential || !current || (phase !== "password-change-required" && phase !== "authenticated")) {
      return false;
    }
    const required = phase === "password-change-required";
    const attempt = ++transition.current;
    setPhase(required ? "changing-password" : "updating-password");
    setError(null);
    try {
      await repository.changePassword(credential, { currentPassword, newPassword, revokeOtherSessions: required || revokeOtherSessions });
      if (attempt !== transition.current) return false;
      setPhase("authenticated");
      return true;
    } catch (changeError) {
      if (attempt !== transition.current) return false;
      if (changeError instanceof HttpProblem && changeError.status === 422) {
        setPhase(required ? "password-change-required" : "authenticated");
      } else {
        // A revoked credential or an unknown result cannot promote a
        // temporary session, nor can a late response undo logout/expiry.
        forget();
      }
      setError(passwordChangeMessage(changeError));
      return false;
    }
  }, [credential, current, forget, phase, repository]);

  const logout = useCallback(async () => {
    if (!credential) {
      forget();
      return true;
    }
    const attempt = ++transition.current;
    setPhase("revoking");
    setError(null);
    try {
      await repository.logout(credential);
      if (attempt !== transition.current) return false;
      forget();
      return true;
    } catch (logoutError) {
      if (attempt !== transition.current) return false;
      if (logoutError instanceof HttpProblem && logoutError.status === 401) {
        forget();
        return true;
      }
      setError("IAM 注销失败，会话仍保留在当前页面内存中");
      setPhase(
        phase === "password-change-required" || phase === "changing-password"
          ? "password-change-required"
          : "authenticated"
      );
      return false;
    }
  }, [credential, forget, phase, repository]);

  const sessionValue = useMemo<SessionContextValue>(() => ({
    phase,
    current,
    error,
    clearError,
    login,
    changePassword,
    logout
  }), [changePassword, clearError, current, error, login, logout, phase]);
  const credentialValue = useMemo(() => ({ credential }), [credential]);

  return (
    <CredentialContext.Provider value={credentialValue}>
      <SessionContext.Provider value={sessionValue}>
        {children}
      </SessionContext.Provider>
    </CredentialContext.Provider>
  );
}

export function useSession(): SessionContextValue {
  const value = useContext(SessionContext);
  if (!value) throw new Error("useSession must be used inside SessionProvider");
  return value;
}

export function useSessionCredential(): string | null {
  const value = useContext(CredentialContext);
  if (!value) throw new Error("useSessionCredential must be used inside SessionProvider");
  return value.credential;
}
