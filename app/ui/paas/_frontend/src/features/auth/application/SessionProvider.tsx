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
import { HttpProblem, requestToken } from "@/infrastructure/http/jsonRequest";
import type {
  AuthenticatedSession,
  LoginOutcome,
  PendingAuthenticationChallenge,
  SessionPhase
} from "../domain/session";
import type { EnrollmentRecoveryMaterial, FirstEnrollmentProgress } from "../domain/personalSecurity";
import { httpIamRepository } from "../repositories/httpIamRepository";
import type { IamRepository } from "../repositories/iamRepository";
import { PersonalSecurityProvider } from "./PersonalSecurityProvider";

type SessionContextValue = {
  phase: SessionPhase;
  current: AuthenticatedSession | null;
  challenge: PendingAuthenticationChallenge | null;
  enrollmentRecovery: EnrollmentRecoveryMaterial | null;
  firstEnrollment: FirstEnrollmentProgress | null;
  error: string | null;
  clearError(): void;
  login(loginName: string, password: string): Promise<LoginOutcome | null>;
  verifyAuthenticationChallenge(code: string): Promise<LoginOutcome | null>;
  changeChallengePassword(newPassword: string): Promise<boolean>;
  startFirstEnrollmentContact(email: string): Promise<boolean>;
  confirmFirstEnrollmentContact(code: string): Promise<boolean>;
  startFirstEnrollmentFactor(): Promise<boolean>;
  confirmFirstEnrollmentFactor(code: string): Promise<boolean>;
  cancelAuthenticationChallenge(): void;
  acknowledgeReauthentication(): void;
  acknowledgeEnrollmentRecovery(): void;
  changePassword(currentPassword: string, newPassword: string, revokeOtherSessions?: boolean): Promise<boolean>;
  logout(): Promise<boolean>;
  expire(expectedCredential: string): boolean;
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
  const [enrollmentRecovery, setEnrollmentRecovery] = useState<EnrollmentRecoveryMaterial | null>(null);
  const [firstEnrollment, setFirstEnrollment] = useState<FirstEnrollmentProgress | null>(null);
  const [credential, setCredential] = useState<string | null>(null);
  const credentialRef = useRef<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const transition = useRef(0);
  const challengeRef = useRef<PendingAuthenticationChallenge | null>(null);
  const firstEnrollmentOperation = useRef<number | null>(null);
  const clearError = useCallback(() => { setError(null); }, []);

  const replaceChallenge = useCallback((next: PendingAuthenticationChallenge | null) => {
    challengeRef.current = next;
    setChallenge(next);
  }, []);

  const forget = useCallback(() => {
    transition.current++;
    firstEnrollmentOperation.current = null;
    credentialRef.current = null;
    setCredential(null);
    setCurrent(null);
    replaceChallenge(null);
    setEnrollmentRecovery(null);
    setFirstEnrollment(null);
    setError(null);
    setPhase("anonymous");
  }, [replaceChallenge]);

  const expire = useCallback((expectedCredential: string) => {
    if (credentialRef.current !== expectedCredential) return false;
    forget();
    return true;
  }, [forget]);

  const requireReauthentication = useCallback((expectedCredential: string, message: string) => {
    if (credentialRef.current !== expectedCredential) return false;
    transition.current++;
    firstEnrollmentOperation.current = null;
    credentialRef.current = null;
    setCredential(null);
    setCurrent(null);
    replaceChallenge(null);
    setEnrollmentRecovery(null);
    setFirstEnrollment(null);
    setError(message);
    setPhase("reauthentication-required");
    return true;
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
      firstEnrollmentOperation.current = null;
      replaceChallenge(null);
      setFirstEnrollment(null);
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
    firstEnrollmentOperation.current = null;
    credentialRef.current = null;
    setCredential(null);
    setCurrent(null);
    replaceChallenge(null);
    setEnrollmentRecovery(null);
    setFirstEnrollment(null);
    setPhase("authenticating");
    setError(null);
    try {
      const result = await repository.login({ loginName, password });
      if (attempt !== transition.current) return null;
      if (result.outcome === "CHALLENGE_REQUIRED") {
        credentialRef.current = null;
        setCredential(null);
        setCurrent(null);
        replaceChallenge({ loginName, challenge: result.challenge, challengeCredential: result.challengeCredential });
        if (result.challenge.purpose === "ENROLLMENT" && result.challenge.nextStep === "ENROLLMENT") {
          setFirstEnrollment({ status: repository.authenticationChallenges?.inspectFirstEnrollment ? "INSPECTING" : "UNAVAILABLE",
            busy: false, state: null, verification: null, provisioning: null, enrollmentId: null });
          setPhase("enrollment-required");
          return "challenge-required";
        }
        setPhase(result.challenge.nextStep === "PASSWORD_CHANGE" ? "challenge-password-required" : "challenge-required");
        return "challenge-required";
      }
      credentialRef.current = result.credential;
      setCredential(result.credential);
      setCurrent({ loginName, session: result.session });
      const outcome: LoginOutcome = result.mustChangePassword
        ? "password-change-required"
        : "authenticated";
      setPhase(outcome);
      return outcome;
    } catch (loginError) {
      if (attempt !== transition.current) return null;
      credentialRef.current = null;
      setCredential(null);
      setCurrent(null);
      setError(authenticationMessage(loginError));
      setPhase("anonymous");
      return null;
    }
  }, [replaceChallenge, repository]);

  useEffect(() => {
    if (!challenge || challenge.challenge.purpose !== "ENROLLMENT" || challenge.challenge.nextStep !== "ENROLLMENT" ||
        phase !== "enrollment-required" || firstEnrollment?.status !== "INSPECTING") return;
    const inspect = repository.authenticationChallenges?.inspectFirstEnrollment;
    if (!inspect) return;
    const requested = challenge;
    const attempt = transition.current;
    void inspect({ challengeId: challenge.challenge.id, challengeCredential: challenge.challengeCredential })
      .then((state) => {
        if (transition.current !== attempt || challengeRef.current !== requested) return;
        if (state.challenge.nextStep !== "ENROLLMENT" || state.challenge.expiresAt !== requested.challenge.expiresAt ||
            !state.notificationContact) throw new Error("INVALID_IAM_RESPONSE");
        setFirstEnrollment({
          status: state.enrollment ? "MATERIAL_LOST" : state.notificationContact.state === "VERIFIED" ? "TOTP_READY" :
            state.notificationContact.pendingVerificationId ? "OUTCOME_UNKNOWN" : "CONTACT_REQUIRED",
          busy: false, state, verification: null, provisioning: null, enrollmentId: state.enrollment?.id ?? null
        });
      })
      .catch(() => {
        if (transition.current !== attempt || challengeRef.current !== requested) return;
        setFirstEnrollment((value) => value?.status === "INSPECTING" ? { ...value, status: "UNAVAILABLE" } : value);
        setError("无法确认首次安全设置状态，请重新登录");
      });
  }, [challenge, firstEnrollment?.status, phase, repository]);

  const verifyAuthenticationChallenge = useCallback(async (code: string) => {
    if (!challenge || challenge.challenge.purpose !== "LOGIN" || challenge.challenge.nextStep !== "TOTP" ||
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
        if (result.challenge.purpose !== "LOGIN" || result.challenge.nextStep !== "PASSWORD_CHANGE") throw new Error("INVALID_IAM_RESPONSE");
        replaceChallenge({ loginName: challenge.loginName, challenge: result.challenge, challengeCredential: result.challengeCredential });
        setPhase("challenge-password-required");
        return "password-change-required";
      }
      replaceChallenge(null);
      setFirstEnrollment(null);
      credentialRef.current = result.credential;
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
      credentialRef.current = null;
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
        credentialRef.current = null;
        setCredential(null);
        setCurrent(null);
        setPhase("reauthentication-required");
      }
      return false;
    }
  }, [challenge, phase, replaceChallenge, repository]);

  const startFirstEnrollmentContact = useCallback(async (email: string) => {
    const start = repository.authenticationChallenges?.startFirstContact;
    const contact = firstEnrollment?.state?.notificationContact;
    if (!challenge || challenge.challenge.purpose !== "ENROLLMENT" || challenge.challenge.nextStep !== "ENROLLMENT" ||
        phase !== "enrollment-required" || firstEnrollment?.status !== "CONTACT_REQUIRED" || contact?.state !== "NONE" ||
        !start || firstEnrollmentOperation.current !== null) return false;
    const attempt = ++transition.current;
    firstEnrollmentOperation.current = attempt;
    const requested = challenge;
    setFirstEnrollment({ ...firstEnrollment, busy: true });
    setError(null);
    try {
      const verification = await start({ challengeId: requested.challenge.id, challengeCredential: requested.challengeCredential,
        email, requestId: requestToken("ui-first-contact-") });
      if (attempt !== transition.current || challengeRef.current !== requested) return false;
      if (verification.accountId !== contact.accountId || verification.userId !== contact.userId) throw new Error("INVALID_IAM_RESPONSE");
      setFirstEnrollment({ ...firstEnrollment, status: "CONTACT_PENDING", busy: false, verification });
      return true;
    } catch (failure) {
      if (attempt !== transition.current || challengeRef.current !== requested) return false;
      const invalid = failure instanceof HttpProblem && (failure.status === 400 || failure.status === 422);
      const forbidden = failure instanceof HttpProblem && [401, 403, 409].includes(failure.status);
      setFirstEnrollment({ ...firstEnrollment, status: invalid ? "CONTACT_REQUIRED" : forbidden ? "UNAVAILABLE" : "OUTCOME_UNKNOWN", busy: false });
      setError(invalid ? "邮箱地址格式不正确" : forbidden ? "首次安全设置已失效，请重新登录" : "发送结果不确定，请重新登录后核对；不要重复提交");
      return false;
    } finally { if (firstEnrollmentOperation.current === attempt) firstEnrollmentOperation.current = null; }
  }, [challenge, firstEnrollment, phase, repository]);

  const confirmFirstEnrollmentContact = useCallback(async (code: string) => {
    const confirm = repository.authenticationChallenges?.confirmFirstContact;
    const inspect = repository.authenticationChallenges?.inspectFirstEnrollment;
    const verification = firstEnrollment?.verification;
    if (!challenge || challenge.challenge.purpose !== "ENROLLMENT" || challenge.challenge.nextStep !== "ENROLLMENT" ||
        phase !== "enrollment-required" || firstEnrollment?.status !== "CONTACT_PENDING" || !verification || !confirm || !inspect ||
        firstEnrollmentOperation.current !== null || !/^[0-9]{8}$/.test(code)) return false;
    const attempt = ++transition.current;
    firstEnrollmentOperation.current = attempt;
    const requested = challenge;
    setFirstEnrollment({ ...firstEnrollment, busy: true });
    setError(null);
    try {
      const confirmed = await confirm({ challengeId: requested.challenge.id, challengeCredential: requested.challengeCredential,
        verificationId: verification.id, code, requestId: requestToken("ui-first-contact-confirm-") });
      if (confirmed.id !== verification.id || confirmed.accountId !== verification.accountId || confirmed.userId !== verification.userId ||
          confirmed.email !== verification.email || confirmed.state !== "VERIFIED") throw new Error("INVALID_IAM_RESPONSE");
      const state = await inspect({ challengeId: requested.challenge.id, challengeCredential: requested.challengeCredential });
      if (attempt !== transition.current || challengeRef.current !== requested) return false;
      if (state.challenge.nextStep !== "ENROLLMENT" || state.challenge.expiresAt !== requested.challenge.expiresAt ||
          state.notificationContact?.state !== "VERIFIED" || state.enrollment ||
          state.notificationContact.accountId !== verification.accountId || state.notificationContact.userId !== verification.userId ||
          state.notificationContact.email !== verification.email) throw new Error("INVALID_IAM_RESPONSE");
      setFirstEnrollment({ ...firstEnrollment, status: "TOTP_READY", busy: false, state, verification: null });
      return true;
    } catch (failure) {
      if (attempt !== transition.current || challengeRef.current !== requested) return false;
      const invalid = failure instanceof HttpProblem && (failure.status === 401 || failure.status === 422);
      const forbidden = failure instanceof HttpProblem && (failure.status === 403 || failure.status === 409);
      setFirstEnrollment({ ...firstEnrollment, status: invalid ? "CONTACT_PENDING" : forbidden ? "UNAVAILABLE" : "OUTCOME_UNKNOWN", busy: false });
      setError(invalid ? "邮箱验证码不正确，请重试" : forbidden ? "首次安全设置已失效，请重新登录" : "验证结果不确定，请重新登录后核对");
      return false;
    } finally { if (firstEnrollmentOperation.current === attempt) firstEnrollmentOperation.current = null; }
  }, [challenge, firstEnrollment, phase, repository]);

  const startFirstEnrollmentFactor = useCallback(async () => {
    const start = repository.authenticationChallenges?.startFirstTOTP;
    if (!challenge || challenge.challenge.purpose !== "ENROLLMENT" || challenge.challenge.nextStep !== "ENROLLMENT" ||
        phase !== "enrollment-required" || firstEnrollment?.status !== "TOTP_READY" ||
        firstEnrollment.state?.notificationContact?.state !== "VERIFIED" || !start || firstEnrollmentOperation.current !== null) return false;
    const attempt = ++transition.current;
    firstEnrollmentOperation.current = attempt;
    const requested = challenge;
    setFirstEnrollment({ ...firstEnrollment, busy: true });
    setError(null);
    try {
      const result = await start({ challengeId: requested.challenge.id, challengeCredential: requested.challengeCredential,
        requestId: requestToken("ui-first-factor-") });
      if (attempt !== transition.current || challengeRef.current !== requested) return false;
      if (result.outcome === "EQUAL_REPLAY") {
        setFirstEnrollment({ ...firstEnrollment, status: "MATERIAL_LOST", busy: false, enrollmentId: result.enrollment.id });
        return false;
      }
      if (Date.parse(result.enrollment.expiresAt) > Date.parse(requested.challenge.expiresAt) || result.enrollment.state !== "PENDING") {
        throw new Error("INVALID_IAM_RESPONSE");
      }
      setFirstEnrollment({ ...firstEnrollment, status: "TOTP_PENDING", busy: false, provisioning: result.provisioning,
        enrollmentId: result.enrollment.id });
      return true;
    } catch (failure) {
      if (attempt !== transition.current || challengeRef.current !== requested) return false;
      const forbidden = failure instanceof HttpProblem && [401, 403, 409].includes(failure.status);
      setFirstEnrollment({ ...firstEnrollment, status: forbidden ? "UNAVAILABLE" : "OUTCOME_UNKNOWN", busy: false });
      setError(forbidden ? "首次安全设置已失效，请重新登录" : "身份验证器创建结果不确定，请重新登录后核对");
      return false;
    } finally { if (firstEnrollmentOperation.current === attempt) firstEnrollmentOperation.current = null; }
  }, [challenge, firstEnrollment, phase, repository]);

  const confirmFirstEnrollmentFactor = useCallback(async (code: string) => {
    const confirm = repository.authenticationChallenges?.confirmFirstTOTP;
    if (!challenge || challenge.challenge.purpose !== "ENROLLMENT" || challenge.challenge.nextStep !== "ENROLLMENT" ||
        phase !== "enrollment-required" || firstEnrollment?.status !== "TOTP_PENDING" ||
        !firstEnrollment.provisioning || !firstEnrollment.enrollmentId || !confirm ||
        firstEnrollmentOperation.current !== null || !/^[0-9]{6}$/.test(code)) return false;
    const attempt = ++transition.current;
    firstEnrollmentOperation.current = attempt;
    const requested = challenge;
    setFirstEnrollment({ ...firstEnrollment, busy: true });
    setError(null);
    try {
      const result = await confirm({ challengeId: requested.challenge.id, challengeCredential: requested.challengeCredential,
        enrollmentId: firstEnrollment.enrollmentId, code, requestId: requestToken("ui-first-factor-confirm-") });
      if (attempt !== transition.current || challengeRef.current !== requested) return false;
      if (result.enrollment.id !== firstEnrollment.enrollmentId || result.recoveryCodes.length !== 10 ||
          new Set(result.recoveryCodes).size !== 10) throw new Error("INVALID_IAM_RESPONSE");
      replaceChallenge(null);
      setFirstEnrollment(null);
      setEnrollmentRecovery({ enrollmentId: result.enrollment.id, recoveryCodes: [...result.recoveryCodes] });
      setPhase("recovery-codes-required");
      return true;
    } catch (failure) {
      if (attempt !== transition.current || challengeRef.current !== requested) return false;
      const invalid = failure instanceof HttpProblem && failure.status === 401;
      const forbidden = failure instanceof HttpProblem && (failure.status === 403 || failure.status === 409);
      setFirstEnrollment({ ...firstEnrollment, status: invalid ? "TOTP_PENDING" : forbidden ? "UNAVAILABLE" : "OUTCOME_UNKNOWN", busy: false });
      setError(invalid ? "动态验证码不正确，请重试" : forbidden ? "首次安全设置已失效，请重新登录" : "绑定结果不确定，请重新登录后核对");
      return false;
    } finally { if (firstEnrollmentOperation.current === attempt) firstEnrollmentOperation.current = null; }
  }, [challenge, firstEnrollment, phase, replaceChallenge, repository]);

  const cancelAuthenticationChallenge = useCallback(() => {
    transition.current++;
    firstEnrollmentOperation.current = null;
    replaceChallenge(null);
    setFirstEnrollment(null);
    setError(null);
    setPhase("anonymous");
  }, [replaceChallenge]);

  const acknowledgeReauthentication = useCallback(() => {
    transition.current++;
    setError(null);
    setPhase("anonymous");
  }, []);

  const completeEnrollment = useCallback((
    expectedCredential: string,
    enrollmentId: string,
    recoveryCodes: string[]
  ) => {
    if (credentialRef.current !== expectedCredential || recoveryCodes.length !== 10 ||
        recoveryCodes.some((code) => !code) || new Set(recoveryCodes).size !== recoveryCodes.length) {
      return false;
    }
    transition.current++;
    credentialRef.current = null;
    setCredential(null);
    setCurrent(null);
    replaceChallenge(null);
    setError(null);
    setEnrollmentRecovery({ enrollmentId, recoveryCodes: [...recoveryCodes] });
    setPhase("recovery-codes-required");
    return true;
  }, [replaceChallenge]);

  const acknowledgeEnrollmentRecovery = useCallback(() => {
    transition.current++;
    setEnrollmentRecovery(null);
    setError(null);
    setPhase("reauthentication-required");
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
    enrollmentRecovery,
    firstEnrollment,
    error,
    clearError,
    login,
    verifyAuthenticationChallenge,
    changeChallengePassword,
    startFirstEnrollmentContact,
    confirmFirstEnrollmentContact,
    startFirstEnrollmentFactor,
    confirmFirstEnrollmentFactor,
    cancelAuthenticationChallenge,
    acknowledgeReauthentication,
    acknowledgeEnrollmentRecovery,
    changePassword,
    logout,
    expire
  }), [acknowledgeEnrollmentRecovery, acknowledgeReauthentication, cancelAuthenticationChallenge, challenge, changeChallengePassword, changePassword, clearError, confirmFirstEnrollmentContact, confirmFirstEnrollmentFactor, current, enrollmentRecovery, error, expire, firstEnrollment, login, logout, phase, startFirstEnrollmentContact, startFirstEnrollmentFactor, verifyAuthenticationChallenge]);
  const credentialValue = useMemo(() => ({ credential }), [credential]);

  return (
    <CredentialContext.Provider value={credentialValue}>
      <SessionContext.Provider value={sessionValue}>
        <PersonalSecurityProvider
          completeEnrollment={completeEnrollment}
          credential={credential}
          current={current}
          expire={expire}
          repository={repository}
          requireReauthentication={requireReauthentication}
        >
          {children}
        </PersonalSecurityProvider>
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
