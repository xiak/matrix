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
  PendingAuthenticationChallenge,
  LoginOutcome,
  SessionPhase
} from "../domain/session";
import { httpIamRepository } from "../repositories/httpIamRepository";
import type { IamRepository } from "../repositories/iamRepository";
import { OwnSessionsProvider } from "./OwnSessionsProvider";

export type SessionErrorCode = "invalidCredentials" | "tooManyAttempts" | "loginUnavailable"
  | "invalidVerificationCode" | "challengeExpired" | "challengeUnavailable"
  | "invalidCurrentPassword" | "passwordPolicy" | "passwordConflict" | "passwordUnavailable" | "logoutUnavailable";

type SessionContextValue = {
  phase: SessionPhase;
  current: AuthenticatedSession | null;
  challenge: PendingAuthenticationChallenge | null;
  error: SessionErrorCode | null;
  clearError(): void;
  login(loginName: string, password: string): Promise<LoginOutcome | null>;
  verifyAuthenticationChallenge(code: string): Promise<LoginOutcome | null>;
  changeChallengePassword(newPassword: string): Promise<boolean>;
  cancelAuthenticationChallenge(): void;
  acknowledgeReauthentication(): void;
  changePassword(currentPassword: string, newPassword: string): Promise<boolean>;
  logout(): Promise<boolean>;
  expire(expectedCredential: string): boolean;
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

function challengeError(error: unknown): SessionErrorCode {
  if (error instanceof HttpProblem && error.status === 401) return "invalidVerificationCode";
  if (error instanceof HttpProblem && (error.status === 403 || error.status === 409)) return "challengeExpired";
  return "challengeUnavailable";
}

function challengePasswordError(error: unknown): SessionErrorCode {
  if (error instanceof HttpProblem && (error.status === 401 || error.status === 403 || error.status === 409)) {
    return "challengeExpired";
  }
  if (error instanceof HttpProblem && error.status === 422) return "passwordPolicy";
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
  const [challenge, setChallenge] = useState<PendingAuthenticationChallenge | null>(null);
  const [credential, setCredential] = useState<string | null>(null);
  const credentialRef = useRef<string | null>(null);
  const [error, setError] = useState<SessionErrorCode | null>(null);
  const clearError = useCallback(() => { setError(null); }, []);

  const forget = useCallback(() => {
    credentialRef.current = null;
    setCredential(null);
    setCurrent(null);
    setChallenge(null);
    setError(null);
    setPhase("anonymous");
  }, []);

  useEffect(() => {
    if (!challenge) return;
    const remaining = Date.parse(challenge.challenge.expiresAt) - Date.now();
    const delay = !Number.isFinite(remaining) || remaining <= 0 ? 0 : Math.min(remaining, 2_147_000_000);
    const timer = window.setTimeout(() => {
      setChallenge(null);
      setError("challengeExpired");
      setPhase("anonymous");
    }, delay);
    return () => window.clearTimeout(timer);
  }, [challenge]);

  const expire = useCallback((expectedCredential: string) => {
    if (credentialRef.current !== expectedCredential) return false;
    forget();
    return true;
  }, [forget]);

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
      if (result.outcome === "CHALLENGE_REQUIRED") {
        credentialRef.current = null;
        setCredential(null);
        setCurrent(null);
        setChallenge({ loginName, challenge: result.challenge, challengeCredential: result.challengeCredential });
        setPhase(result.challenge.nextStep === "PASSWORD_CHANGE" ? "challenge-password-required" : "challenge-required");
        return "challenge-required";
      }
      setChallenge(null);
      credentialRef.current = result.credential;
      setCredential(result.credential);
      setCurrent({ loginName, session: result.session });
      const outcome: LoginOutcome = result.mustChangePassword
        ? "password-change-required"
        : "authenticated";
      setPhase(outcome);
      return outcome;
    } catch (loginError) {
      credentialRef.current = null;
      setCredential(null);
      setCurrent(null);
      setError(authenticationError(loginError));
      setPhase("anonymous");
      return null;
    }
  }, [repository]);

  const verifyAuthenticationChallenge = useCallback(async (code: string) => {
    if (!challenge || challenge.challenge.nextStep !== "TOTP" ||
        (phase !== "challenge-required" && phase !== "verifying-challenge") ||
        !repository.authenticationChallenges) return null;
    setPhase("verifying-challenge");
    setError(null);
    try {
      const result = await repository.authenticationChallenges.verify({
        challengeId: challenge.challenge.id,
        challengeCredential: challenge.challengeCredential,
        code
      });
      if (result.outcome === "CHALLENGE_REQUIRED") {
        if (result.challenge.nextStep !== "PASSWORD_CHANGE") throw new Error("INVALID_IAM_RESPONSE");
        setChallenge({ loginName: challenge.loginName, challenge: result.challenge, challengeCredential: result.challengeCredential });
        setPhase("challenge-password-required");
        return "password-change-required";
      }
      setChallenge(null);
      credentialRef.current = result.credential;
      setCredential(result.credential);
      setCurrent({ loginName: challenge.loginName, session: result.session });
      const outcome: LoginOutcome = result.mustChangePassword ? "password-change-required" : "authenticated";
      setPhase(outcome);
      return outcome;
    } catch (verifyError) {
      setError(challengeError(verifyError));
      setPhase("challenge-required");
      return null;
    }
  }, [challenge, phase, repository]);

  const changeChallengePassword = useCallback(async (newPassword: string) => {
    if (!challenge || challenge.challenge.nextStep !== "PASSWORD_CHANGE" ||
        (phase !== "challenge-password-required" && phase !== "changing-challenge-password") ||
        !repository.authenticationChallenges) return false;
    setPhase("changing-challenge-password");
    setError(null);
    try {
      await repository.authenticationChallenges.changePassword({
        challengeId: challenge.challenge.id,
        challengeCredential: challenge.challengeCredential,
        newPassword
      });
      setChallenge(null);
      credentialRef.current = null;
      setCredential(null);
      setCurrent(null);
      setPhase("reauthentication-required");
      return true;
    } catch (changeError) {
      setError(challengePasswordError(changeError));
      setPhase("challenge-password-required");
      return false;
    }
  }, [challenge, phase, repository]);

  const cancelAuthenticationChallenge = useCallback(() => {
    setChallenge(null);
    setError(null);
    setPhase("anonymous");
  }, []);

  const acknowledgeReauthentication = useCallback(() => {
    setError(null);
    setPhase("anonymous");
  }, []);

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
    challenge,
    error,
    clearError,
    login,
    verifyAuthenticationChallenge,
    changeChallengePassword,
    cancelAuthenticationChallenge,
    acknowledgeReauthentication,
    changePassword,
    logout,
    expire
  }), [acknowledgeReauthentication, cancelAuthenticationChallenge, challenge, changeChallengePassword, changePassword, clearError, current, error, expire, login, logout, phase, verifyAuthenticationChallenge]);
  const credentialValue = useMemo(() => ({ credential }), [credential]);

  return (
    <CredentialContext.Provider value={credentialValue}>
      <SessionContext.Provider value={sessionValue}>
        <OwnSessionsProvider repository={repository} credential={credential} current={current} expire={expire}>
          {children}
        </OwnSessionsProvider>
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
