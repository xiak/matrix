"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
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
  changePassword(currentPassword: string, newPassword: string): Promise<boolean>;
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
    return "当前密码不正确，或登录会话已经失效";
  }
  if (error instanceof HttpProblem && error.status === 422) {
    return "新密码需为 14–128 字节，且至少包含三类：大写字母、小写字母、数字、符号";
  }
  if (error instanceof HttpProblem && error.status === 409) {
    return "密码已在其他会话中更新，请退出后重新登录";
  }
  return "IAM 暂时无法更新密码，请稍后重试";
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
  const clearError = useCallback(() => { setError(null); }, []);

  const forget = useCallback(() => {
    setCredential(null);
    setCurrent(null);
    setError(null);
    setPhase("anonymous");
  }, []);

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
    setPhase("authenticating");
    setError(null);
    try {
      const result = await repository.login({ loginName, password });
      setCredential(result.credential);
      setCurrent({ loginName, session: result.session });
      const outcome: LoginOutcome = result.mustChangePassword
        ? "password-change-required"
        : "authenticated";
      setPhase(outcome);
      return outcome;
    } catch (loginError) {
      setCredential(null);
      setCurrent(null);
      setError(authenticationMessage(loginError));
      setPhase("anonymous");
      return null;
    }
  }, [repository]);

  const changePassword = useCallback(async (
    currentPassword: string,
    newPassword: string
  ) => {
    if (!credential || !current || phase !== "password-change-required") {
      return false;
    }
    setPhase("changing-password");
    setError(null);
    try {
      await repository.changePassword(credential, { currentPassword, newPassword });
      setPhase("authenticated");
      return true;
    } catch (changeError) {
      setError(passwordChangeMessage(changeError));
      setPhase("password-change-required");
      return false;
    }
  }, [credential, current, phase, repository]);

  const logout = useCallback(async () => {
    if (!credential) {
      forget();
      return true;
    }
    setPhase("revoking");
    setError(null);
    try {
      await repository.logout(credential);
      forget();
      return true;
    } catch (logoutError) {
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
