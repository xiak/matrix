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

export type SessionErrorCode = "invalidCredentials" | "tooManyAttempts" | "loginUnavailable"
  | "invalidCurrentPassword" | "passwordPolicy" | "passwordConflict" | "passwordUnavailable" | "logoutUnavailable";

type SessionContextValue = {
  phase: SessionPhase;
  current: AuthenticatedSession | null;
  error: SessionErrorCode | null;
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

function authenticationError(error: unknown): SessionErrorCode {
  if (error instanceof HttpProblem && error.status === 401) {
    return "invalidCredentials";
  }
  if (error instanceof HttpProblem && error.status === 429) {
    return "tooManyAttempts";
  }
  return "loginUnavailable";
}

function passwordChangeError(error: unknown): SessionErrorCode {
  if (error instanceof HttpProblem && error.status === 401) {
    return "invalidCurrentPassword";
  }
  if (error instanceof HttpProblem && error.status === 422) {
    return "passwordPolicy";
  }
  if (error instanceof HttpProblem && error.status === 409) {
    return "passwordConflict";
  }
  return "passwordUnavailable";
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
  const [error, setError] = useState<SessionErrorCode | null>(null);
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
      setError(authenticationError(loginError));
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
      setError(passwordChangeError(changeError));
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
      setError("logoutUnavailable");
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
