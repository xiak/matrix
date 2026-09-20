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
  PendingAuthenticationChallenge,
  SessionPhase
} from "../domain/session";
import { httpIamRepository } from "../repositories/httpIamRepository";
import type { IamRepository } from "../repositories/iamRepository";

type SessionContextValue = {
  phase: SessionPhase;
  current: AuthenticatedSession | null;
  challenge: PendingAuthenticationChallenge | null;
  error: string | null;
  clearError(): void;
  login(loginName: string, password: string): Promise<LoginOutcome | null>;
  verifyAuthenticationChallenge(code: string): Promise<LoginOutcome | null>;
  changeChallengePassword(newPassword: string): Promise<boolean>;
  cancelAuthenticationChallenge(): void;
  acknowledgeReauthentication(): void;
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

function challengeMessage(error: unknown): string {
  if (error instanceof HttpProblem && error.status === 401) return "验证码不正确，请检查后重试";
  if (error instanceof HttpProblem && error.status === 429) return "验证尝试过于频繁，请稍后重试";
  if (error instanceof HttpProblem && (error.status === 403 || error.status === 409)) return "登录验证已过期，请重新登录";
  return "无法确认验证结果，请重新登录";
}

function challengePasswordMessage(error: unknown): string {
  if (error instanceof HttpProblem && error.status === 422) {
    return "新密码需为 14–128 字节，且至少包含三类：大写字母、小写字母、数字、符号";
  }
  if (error instanceof HttpProblem && (error.status === 401 || error.status === 403 || error.status === 409)) {
    return "改密验证已过期，请重新登录";
  }
  return "无法确认改密结果，请使用新密码重新登录核对";
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
  const [error, setError] = useState<string | null>(null);
  const transition = useRef(0);
  const challengeRef = useRef<PendingAuthenticationChallenge | null>(null);
  const clearError = useCallback(() => { setError(null); }, []);

  const replaceChallenge = useCallback((next: PendingAuthenticationChallenge | null) => {
    challengeRef.current = next;
    setChallenge(next);
  }, []);

  const forget = useCallback(() => {
    transition.current++;
    setCredential(null);
    setCurrent(null);
    replaceChallenge(null);
    setError(null);
    setPhase("anonymous");
  }, [replaceChallenge]);

  useEffect(() => () => { transition.current++; }, []);

  useEffect(() => {
    if (!challenge) return;
    const remaining = Date.parse(challenge.challenge.expiresAt) - Date.now();
    const delay = !Number.isFinite(remaining) || remaining <= 0
      ? 0
      : Math.min(remaining, 2_147_000_000);
    const timer = window.setTimeout(() => {
      if (challengeRef.current !== challenge) return;
      transition.current++;
      replaceChallenge(null);
      setError("登录验证已过期，请重新登录");
      setPhase("anonymous");
    }, delay);
    return () => window.clearTimeout(timer);
  }, [challenge, replaceChallenge]);

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
    replaceChallenge(null);
    setPhase("authenticating");
    setError(null);
    try {
      const result = await repository.login({ loginName, password });
      if (attempt !== transition.current) return null;
      if (result.outcome === "CHALLENGE_REQUIRED") {
        setCredential(null);
        setCurrent(null);
        replaceChallenge({ loginName, challenge: result.challenge, challengeCredential: result.challengeCredential });
        setPhase(result.challenge.nextStep === "PASSWORD_CHANGE" ? "challenge-password-required" : "challenge-required");
        return "challenge-required";
      }
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
  }, [replaceChallenge, repository]);

  const verifyAuthenticationChallenge = useCallback(async (code: string) => {
    if (!challenge || challenge.challenge.nextStep !== "TOTP" ||
        (phase !== "challenge-required" && phase !== "verifying-challenge") ||
        !repository.authenticationChallenges) return null;
    const requested = challenge;
    const attempt = ++transition.current;
    setPhase("verifying-challenge");
    setError(null);
    try {
      const result = await repository.authenticationChallenges.verify({
        challengeId: challenge.challenge.id,
        challengeCredential: challenge.challengeCredential,
        code
      });
      if (attempt !== transition.current || challengeRef.current !== requested) return null;
      if (result.outcome === "CHALLENGE_REQUIRED") {
        if (result.challenge.nextStep !== "PASSWORD_CHANGE") throw new Error("INVALID_IAM_RESPONSE");
        replaceChallenge({ loginName: challenge.loginName, challenge: result.challenge, challengeCredential: result.challengeCredential });
        setPhase("challenge-password-required");
        return "password-change-required";
      }
      replaceChallenge(null);
      setCredential(result.credential);
      setCurrent({ loginName: challenge.loginName, session: result.session });
      const outcome: LoginOutcome = result.mustChangePassword ? "password-change-required" : "authenticated";
      setPhase(outcome);
      return outcome;
    } catch (verifyError) {
      if (attempt !== transition.current || challengeRef.current !== requested) return null;
      setError(challengeMessage(verifyError));
      if (verifyError instanceof HttpProblem && (verifyError.status === 401 || verifyError.status === 429)) {
        setPhase("challenge-required");
      } else {
        replaceChallenge(null);
        setPhase("anonymous");
      }
      return null;
    }
  }, [challenge, phase, replaceChallenge, repository]);

  const changeChallengePassword = useCallback(async (newPassword: string) => {
    if (!challenge || challenge.challenge.nextStep !== "PASSWORD_CHANGE" ||
        (phase !== "challenge-password-required" && phase !== "changing-challenge-password") ||
        !repository.authenticationChallenges) return false;
    const requested = challenge;
    const attempt = ++transition.current;
    setPhase("changing-challenge-password");
    setError(null);
    try {
      await repository.authenticationChallenges.changePassword({
        challengeId: challenge.challenge.id,
        challengeCredential: challenge.challengeCredential,
        newPassword
      });
      if (attempt !== transition.current || challengeRef.current !== requested) return false;
      replaceChallenge(null);
      setCredential(null);
      setCurrent(null);
      setPhase("reauthentication-required");
      return true;
    } catch (changeError) {
      if (attempt !== transition.current || challengeRef.current !== requested) return false;
      setError(challengePasswordMessage(changeError));
      if (changeError instanceof HttpProblem && changeError.status === 422) {
        setPhase("challenge-password-required");
      } else {
        replaceChallenge(null);
        setCredential(null);
        setCurrent(null);
        setPhase("reauthentication-required");
      }
      return false;
    }
  }, [challenge, phase, replaceChallenge, repository]);

  const cancelAuthenticationChallenge = useCallback(() => {
    transition.current++;
    replaceChallenge(null);
    setError(null);
    setPhase("anonymous");
  }, [replaceChallenge]);

  const acknowledgeReauthentication = useCallback(() => {
    transition.current++;
    setError(null);
    setPhase("anonymous");
  }, []);

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
    challenge,
    error,
    clearError,
    login,
    verifyAuthenticationChallenge,
    changeChallengePassword,
    cancelAuthenticationChallenge,
    acknowledgeReauthentication,
    changePassword,
    logout
  }), [acknowledgeReauthentication, cancelAuthenticationChallenge, challenge, changeChallengePassword, changePassword, clearError, current, error, login, logout, phase, verifyAuthenticationChallenge]);
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
