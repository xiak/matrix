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
  AuthenticatorRecovery,
  AuthenticatedSession,
  PendingAuthenticationChallenge,
  PendingAuthenticatorRecovery,
  LoginOutcome,
  SessionPhase
} from "../domain/session";
import type { EnrollmentRecoveryMaterial, FirstEnrollmentProgress } from "../domain/personalSecurity";
import { httpIamRepository } from "../repositories/httpIamRepository";
import type { IamRepository } from "../repositories/iamRepository";
import { OwnSessionsProvider } from "./OwnSessionsProvider";
import { PersonalSecurityProvider } from "./PersonalSecurityProvider";

export type SessionErrorCode = "invalidCredentials" | "tooManyAttempts" | "loginUnavailable"
  | "invalidVerificationCode" | "challengeExpired" | "challengeUnavailable"
  | "invalidRecoveryCode" | "recoveryExpired" | "recoveryUnavailable" | "recoveryOutcomeUnknown" | "recoveryNotFound"
  | "invalidCurrentPassword" | "passwordPolicy" | "passwordConflict" | "passwordUnavailable" | "logoutUnavailable"
  | "enrollmentUnavailable" | "enrollmentContactInvalid" | "enrollmentFactorInvalid" | "enrollmentOutcomeUnknown";

type SessionContextValue = {
  phase: SessionPhase;
  current: AuthenticatedSession | null;
  sessionRevision: number;
  challenge: PendingAuthenticationChallenge | null;
  authenticatorRecovery: PendingAuthenticatorRecovery | null;
  enrollmentRecovery: EnrollmentRecoveryMaterial | null;
  firstEnrollment: FirstEnrollmentProgress | null;
  reauthenticationReason: "PASSWORD" | "ENROLLMENT_PASSWORD" | "FACTOR" | null;
  error: SessionErrorCode | null;
  clearError(): void;
  login(loginName: string, password: string): Promise<LoginOutcome | null>;
  verifyAuthenticationChallenge(code: string): Promise<LoginOutcome | null>;
  enterAuthenticatorRecovery(): boolean;
  startAuthenticatorRecovery(recoveryCode: string): Promise<boolean>;
  confirmAuthenticatorRecovery(code: string): Promise<boolean>;
  inspectAuthenticatorRecovery(): Promise<AuthenticatorRecovery | null>;
  restartAuthenticatorRecovery(): boolean;
  leaveAuthenticatorRecovery(): void;
  changeChallengePassword(newPassword: string): Promise<boolean>;
  startFirstEnrollmentContact(email: string): Promise<boolean>;
  confirmFirstEnrollmentContact(code: string): Promise<boolean>;
  startFirstEnrollmentFactor(): Promise<boolean>;
  confirmFirstEnrollmentFactor(code: string): Promise<boolean>;
  cancelAuthenticationChallenge(): void;
  acknowledgeReauthentication(): void;
  acknowledgeEnrollmentRecovery(): void;
  changePassword(currentPassword: string, newPassword: string): Promise<boolean>;
  logout(): Promise<boolean>;
  expire(expectedCredential: string, expectedSessionRevision?: number): boolean;
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

function knownRecoveryRejection(error: unknown): error is HttpProblem {
  return error instanceof HttpProblem && [400, 401, 403, 409, 413, 415, 422, 429].includes(error.status);
}

function recoveryStartError(error: HttpProblem): SessionErrorCode {
  if (error.status === 401) return "invalidRecoveryCode";
  if (error.status === 403 || error.status === 409) return "recoveryExpired";
  return "recoveryUnavailable";
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
  const [authenticatorRecovery, setAuthenticatorRecovery] = useState<PendingAuthenticatorRecovery | null>(null);
  const [enrollmentRecovery, setEnrollmentRecovery] = useState<EnrollmentRecoveryMaterial | null>(null);
  const [firstEnrollment, setFirstEnrollment] = useState<FirstEnrollmentProgress | null>(null);
  const [reauthenticationReason, setReauthenticationReason] = useState<"PASSWORD" | "ENROLLMENT_PASSWORD" | "FACTOR" | null>(null);
  const [credential, setCredential] = useState<string | null>(null);
  const [sessionRevision, setSessionRevision] = useState(0);
  const credentialRef = useRef<string | null>(null);
  const challengeRef = useRef<PendingAuthenticationChallenge | null>(null);
  const authenticatorRecoveryRef = useRef<PendingAuthenticatorRecovery | null>(null);
  const authenticationRevisionRef = useRef(0);
  const firstEnrollmentOperationRef = useRef<number | null>(null);
  const [error, setError] = useState<SessionErrorCode | null>(null);
  const clearError = useCallback(() => { setError(null); }, []);

  const replaceChallenge = useCallback((next: PendingAuthenticationChallenge | null) => {
    challengeRef.current = next;
    setChallenge(next);
  }, []);

  const replaceAuthenticatorRecovery = useCallback((next: PendingAuthenticatorRecovery | null) => {
    authenticatorRecoveryRef.current = next;
    setAuthenticatorRecovery(next);
  }, []);

  const forget = useCallback(() => {
    authenticationRevisionRef.current += 1;
    firstEnrollmentOperationRef.current = null;
    credentialRef.current = null;
    setCredential(null);
    setCurrent(null);
    replaceChallenge(null);
    replaceAuthenticatorRecovery(null);
    setEnrollmentRecovery(null);
    setFirstEnrollment(null);
    setReauthenticationReason(null);
    setError(null);
    setPhase("anonymous");
  }, [replaceAuthenticatorRecovery, replaceChallenge]);

  useEffect(() => {
    if (!challenge) return;
    const remaining = Date.parse(challenge.challenge.expiresAt) - Date.now();
    const delay = !Number.isFinite(remaining) || remaining <= 0 ? 0 : Math.min(remaining, 2_147_000_000);
    const timer = window.setTimeout(() => {
      if (challengeRef.current !== challenge) return;
      authenticationRevisionRef.current += 1;
      firstEnrollmentOperationRef.current = null;
      replaceChallenge(null);
      setFirstEnrollment(null);
      if (challenge.challenge.purpose === "RECOVERY") {
        const active = authenticatorRecoveryRef.current;
        if (active) replaceAuthenticatorRecovery({
          loginName: active.loginName,
          requestId: active.requestId,
          state: "MATERIAL_LOST",
          recovery: active.recovery
        });
      }
      setError("challengeExpired");
      setPhase("anonymous");
    }, delay);
    return () => window.clearTimeout(timer);
  }, [challenge, replaceAuthenticatorRecovery, replaceChallenge]);

  const expire = useCallback((expectedCredential: string, expectedSessionRevision?: number) => {
    if (credentialRef.current !== expectedCredential ||
        (expectedSessionRevision !== undefined && authenticationRevisionRef.current !== expectedSessionRevision)) return false;
    forget();
    return true;
  }, [forget]);
  const isCurrentSession = useCallback((expectedCredential: string, expectedRevision: number) =>
    credentialRef.current === expectedCredential && authenticationRevisionRef.current === expectedRevision, []);

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
    const authenticationRevision = ++authenticationRevisionRef.current;
    firstEnrollmentOperationRef.current = null;
    replaceChallenge(null);
    setEnrollmentRecovery(null);
    setFirstEnrollment(null);
    setReauthenticationReason(null);
    setPhase("authenticating");
    setError(null);
    try {
      const result = await repository.login({ loginName, password });
      if (authenticationRevisionRef.current !== authenticationRevision) return null;
      if (result.outcome === "CHALLENGE_REQUIRED") {
        credentialRef.current = null;
        setCredential(null);
        setCurrent(null);
        replaceChallenge({ loginName, challenge: result.challenge, challengeCredential: result.challengeCredential });
        if (result.challenge.purpose === "ENROLLMENT") {
          if (result.challenge.nextStep === "PASSWORD_CHANGE") {
            setPhase("challenge-password-required");
          } else {
            setFirstEnrollment({ status: repository.authenticationChallenges?.inspectFirstEnrollment ? "INSPECTING" : "UNAVAILABLE",
              busy: false, state: null, verification: null, provisioning: null, enrollmentId: null });
            setPhase("enrollment-required");
          }
          return "challenge-required";
        }
        const pendingRecovery = authenticatorRecoveryRef.current;
        const unresolvedRecovery = pendingRecovery?.loginName === loginName ? pendingRecovery : null;
        setPhase(result.challenge.nextStep === "PASSWORD_CHANGE"
          ? "challenge-password-required"
          : result.challenge.nextStep === "RECOVER"
            ? unresolvedRecovery ? "recovery-result-required" : "recovery-code-required"
            : unresolvedRecovery?.state === "CONFIRM_OUTCOME_UNKNOWN"
              ? "challenge-required"
              : unresolvedRecovery ? "recovery-result-required" : "challenge-required");
        return "challenge-required";
      }
      replaceChallenge(null);
      replaceAuthenticatorRecovery(null);
      credentialRef.current = result.credential;
      setCredential(result.credential);
      setCurrent({ loginName, session: result.session });
      setSessionRevision(authenticationRevision);
      const outcome: LoginOutcome = result.mustChangePassword
        ? "password-change-required"
        : "authenticated";
      setPhase(outcome);
      return outcome;
    } catch (loginError) {
      if (authenticationRevisionRef.current !== authenticationRevision) return null;
      credentialRef.current = null;
      setCredential(null);
      setCurrent(null);
      setError(authenticationError(loginError));
      setPhase("anonymous");
      return null;
    }
  }, [replaceAuthenticatorRecovery, replaceChallenge, repository]);

  useEffect(() => {
    if (!challenge || challenge.challenge.purpose !== "ENROLLMENT" || challenge.challenge.nextStep !== "ENROLLMENT" ||
        phase !== "enrollment-required" || firstEnrollment?.status !== "INSPECTING") return;
    const requestChallenge = challenge;
    const authenticationRevision = authenticationRevisionRef.current;
    const inspect = repository.authenticationChallenges?.inspectFirstEnrollment;
    if (!inspect) return;
    // The challenge id is only a reference. The credential remains in memory
    // and is transmitted only in this restricted request body.
    void inspect({ challengeId: challenge.challenge.id, challengeCredential: challenge.challengeCredential })
      .then((state) => {
        if (authenticationRevisionRef.current !== authenticationRevision || challengeRef.current !== requestChallenge) return;
        if (state.challenge.nextStep !== "ENROLLMENT" || state.challenge.expiresAt !== challenge.challenge.expiresAt ||
            !state.notificationContact) throw new Error("INVALID_IAM_RESPONSE");
        setFirstEnrollment({
          status: state.enrollment ? "MATERIAL_LOST" : state.notificationContact.state === "VERIFIED" ? "TOTP_READY" :
            state.notificationContact.pendingVerificationId ? "OUTCOME_UNKNOWN" : "CONTACT_REQUIRED",
          busy: false, state, verification: null, provisioning: null, enrollmentId: state.enrollment?.id ?? null
        });
      })
      .catch(() => {
        if (authenticationRevisionRef.current !== authenticationRevision || challengeRef.current !== requestChallenge) return;
        setFirstEnrollment((value) => value?.status === "INSPECTING" ? { ...value, status: "UNAVAILABLE" } : value);
        setError("enrollmentUnavailable");
      });
  }, [challenge, firstEnrollment?.status, phase, repository]);

  const verifyAuthenticationChallenge = useCallback(async (code: string) => {
    if (!challenge || challenge.challenge.purpose !== "LOGIN" || challenge.challenge.nextStep !== "TOTP" ||
        (phase !== "challenge-required" && phase !== "verifying-challenge") ||
        !repository.authenticationChallenges) return null;
    const requestChallenge = challenge;
    const authenticationRevision = ++authenticationRevisionRef.current;
    setPhase("verifying-challenge");
    setError(null);
    try {
      const result = await repository.authenticationChallenges.verify({
        challengeId: challenge.challenge.id,
        challengeCredential: challenge.challengeCredential,
        code
      });
      if (authenticationRevisionRef.current !== authenticationRevision || challengeRef.current !== requestChallenge) return null;
      if (result.outcome === "CHALLENGE_REQUIRED") {
        if (result.challenge.nextStep !== "PASSWORD_CHANGE") throw new Error("INVALID_IAM_RESPONSE");
        replaceChallenge({ loginName: challenge.loginName, challenge: result.challenge, challengeCredential: result.challengeCredential });
        setPhase("challenge-password-required");
        return "password-change-required";
      }
      replaceChallenge(null);
      replaceAuthenticatorRecovery(null);
      credentialRef.current = result.credential;
      setCredential(result.credential);
      setCurrent({ loginName: challenge.loginName, session: result.session });
      setSessionRevision(authenticationRevision);
      const outcome: LoginOutcome = result.mustChangePassword ? "password-change-required" : "authenticated";
      setPhase(outcome);
      return outcome;
    } catch (verifyError) {
      if (authenticationRevisionRef.current !== authenticationRevision || challengeRef.current !== requestChallenge) return null;
      setError(challengeError(verifyError));
      setPhase("challenge-required");
      return null;
    }
  }, [challenge, phase, replaceAuthenticatorRecovery, replaceChallenge, repository]);

  const enterAuthenticatorRecovery = useCallback(() => {
    if (!challenge || challenge.challenge.purpose !== "LOGIN" || challenge.challenge.nextStep !== "TOTP" ||
        (phase !== "challenge-required" && phase !== "verifying-challenge")) return false;
    authenticationRevisionRef.current += 1;
    setError(null);
    setPhase("recovery-code-required");
    return true;
  }, [challenge, phase]);

  const startAuthenticatorRecovery = useCallback(async (recoveryCode: string) => {
    if (!challenge || challenge.challenge.purpose !== "LOGIN" ||
        (challenge.challenge.nextStep !== "TOTP" && challenge.challenge.nextStep !== "RECOVER") ||
        phase !== "recovery-code-required" || !repository.authenticationChallenges?.startRecovery) return false;
    const sourceChallenge = challenge;
    const requestId = `ui-authenticator-recovery-${crypto.randomUUID()}`;
    const pending: PendingAuthenticatorRecovery = {
      loginName: challenge.loginName,
      requestId,
      state: "START_OUTCOME_UNKNOWN"
    };
    const authenticationRevision = ++authenticationRevisionRef.current;
    replaceAuthenticatorRecovery(pending);
    setPhase("starting-recovery");
    setError(null);
    try {
      const result = await repository.authenticationChallenges.startRecovery({
        challengeId: challenge.challenge.id,
        challengeCredential: challenge.challengeCredential,
        recoveryCode,
        requestId
      });
      if (authenticationRevisionRef.current !== authenticationRevision || challengeRef.current !== sourceChallenge ||
          authenticatorRecoveryRef.current !== pending) return false;
      const nextRecovery: PendingAuthenticatorRecovery = {
        loginName: challenge.loginName,
        requestId,
        state: "STARTED",
        recovery: result.recovery,
        provisioning: result.provisioning
      };
      replaceAuthenticatorRecovery(nextRecovery);
      replaceChallenge({
        loginName: challenge.loginName,
        challenge: result.challenge,
        challengeCredential: result.challengeCredential
      });
      setPhase("recovery-enrollment-required");
      return true;
    } catch (startError) {
      if (authenticationRevisionRef.current !== authenticationRevision || challengeRef.current !== sourceChallenge ||
          authenticatorRecoveryRef.current !== pending) return false;
      if (knownRecoveryRejection(startError)) {
        replaceAuthenticatorRecovery(null);
        setError(recoveryStartError(startError));
        setPhase("recovery-code-required");
        return false;
      }
      replaceChallenge(null);
      setError("recoveryOutcomeUnknown");
      setPhase("recovery-start-unknown");
      return false;
    }
  }, [challenge, phase, replaceAuthenticatorRecovery, replaceChallenge, repository]);

  const confirmAuthenticatorRecovery = useCallback(async (code: string) => {
    if (!challenge || challenge.challenge.purpose !== "RECOVERY" || challenge.challenge.nextStep !== "ENROLLMENT" ||
        !authenticatorRecovery || authenticatorRecovery.state !== "STARTED" ||
        phase !== "recovery-enrollment-required" || !repository.authenticationChallenges?.confirmRecovery) return false;
    const recoveryChallenge = challenge;
    const pending = authenticatorRecovery;
    const authenticationRevision = ++authenticationRevisionRef.current;
    setPhase("confirming-recovery");
    setError(null);
    try {
      const result = await repository.authenticationChallenges.confirmRecovery({
        challengeId: challenge.challenge.id,
        challengeCredential: challenge.challengeCredential,
        code,
        requestId: `ui-authenticator-recovery-confirm-${crypto.randomUUID()}`,
        recoveryRequestId: authenticatorRecovery.requestId
      });
      if (authenticationRevisionRef.current !== authenticationRevision || challengeRef.current !== recoveryChallenge ||
          authenticatorRecoveryRef.current !== pending) return false;
      replaceChallenge(null);
      replaceAuthenticatorRecovery(null);
      setEnrollmentRecovery({ enrollmentId: result.recovery.id, recoveryCodes: [...result.recoveryCodes] });
      setPhase("recovery-codes-required");
      return true;
    } catch (confirmError) {
      if (authenticationRevisionRef.current !== authenticationRevision || challengeRef.current !== recoveryChallenge ||
          authenticatorRecoveryRef.current !== pending) return false;
      if (knownRecoveryRejection(confirmError) && confirmError.status === 401) {
        setError("invalidVerificationCode");
        setPhase("recovery-enrollment-required");
        return false;
      }
      if (knownRecoveryRejection(confirmError)) {
        replaceChallenge(null);
        replaceAuthenticatorRecovery({
          loginName: pending.loginName,
          requestId: pending.requestId,
          state: "MATERIAL_LOST",
          recovery: pending.recovery
        });
        setError(confirmError.status === 403 || confirmError.status === 409 ? "recoveryExpired" : "recoveryUnavailable");
        setPhase("recovery-start-unknown");
        return false;
      }
      replaceChallenge(null);
      replaceAuthenticatorRecovery({
        loginName: pending.loginName,
        requestId: pending.requestId,
        state: "CONFIRM_OUTCOME_UNKNOWN",
        recovery: pending.recovery
      });
      setError("recoveryOutcomeUnknown");
      setPhase("recovery-confirm-unknown");
      return false;
    }
  }, [authenticatorRecovery, challenge, phase, replaceAuthenticatorRecovery, replaceChallenge, repository]);

  const inspectAuthenticatorRecovery = useCallback(async () => {
    if (!challenge || challenge.challenge.purpose !== "LOGIN" ||
        (challenge.challenge.nextStep !== "TOTP" && challenge.challenge.nextStep !== "RECOVER") ||
        !authenticatorRecovery || phase !== "recovery-result-required" || !repository.authenticationChallenges?.inspectRecovery) return null;
    const inspectionChallenge = challenge;
    const pending = authenticatorRecovery;
    const authenticationRevision = ++authenticationRevisionRef.current;
    setPhase("inspecting-recovery");
    setError(null);
    try {
      const result = await repository.authenticationChallenges.inspectRecovery({
        challengeId: challenge.challenge.id,
        challengeCredential: challenge.challengeCredential,
        requestId: authenticatorRecovery.requestId
      });
      if (authenticationRevisionRef.current !== authenticationRevision || challengeRef.current !== inspectionChallenge ||
          authenticatorRecoveryRef.current !== pending) return null;
      if (result.state === "COMPLETED") {
        replaceChallenge(null);
        replaceAuthenticatorRecovery(null);
        setPhase("reauthentication-required");
      } else if (result.state === "STARTED") {
        replaceAuthenticatorRecovery({
          loginName: pending.loginName,
          requestId: pending.requestId,
          state: "MATERIAL_LOST",
          recovery: result
        });
        setPhase("recovery-start-unknown");
      } else {
        replaceAuthenticatorRecovery({
          loginName: pending.loginName,
          requestId: pending.requestId,
          state: "MATERIAL_LOST",
          recovery: result
        });
        setError("recoveryExpired");
        setPhase("recovery-code-required");
      }
      return result;
    } catch (inspectError) {
      if (authenticationRevisionRef.current !== authenticationRevision || challengeRef.current !== inspectionChallenge ||
          authenticatorRecoveryRef.current !== pending) return null;
      if (inspectError instanceof HttpProblem && inspectError.status === 404) {
        replaceAuthenticatorRecovery({ ...pending, state: "NOT_FOUND" });
        setError("recoveryNotFound");
        setPhase("recovery-start-unknown");
      } else {
        setError("recoveryUnavailable");
        setPhase("recovery-result-required");
      }
      return null;
    }
  }, [authenticatorRecovery, challenge, phase, replaceAuthenticatorRecovery, replaceChallenge, repository]);

  const restartAuthenticatorRecovery = useCallback(() => {
    if (!challenge || challenge.challenge.purpose !== "LOGIN" ||
        (challenge.challenge.nextStep !== "TOTP" && challenge.challenge.nextStep !== "RECOVER")) {
      return false;
    }
    authenticationRevisionRef.current += 1;
    setError(null);
    setPhase("recovery-code-required");
    return true;
  }, [challenge]);

  const leaveAuthenticatorRecovery = useCallback(() => {
    authenticationRevisionRef.current += 1;
    const pending = authenticatorRecoveryRef.current;
    if (pending?.state === "STARTED") {
      replaceAuthenticatorRecovery({
        loginName: pending.loginName,
        requestId: pending.requestId,
        state: "MATERIAL_LOST",
        recovery: pending.recovery
      });
    }
    replaceChallenge(null);
    setError(null);
    setPhase("anonymous");
  }, [replaceAuthenticatorRecovery, replaceChallenge]);

  const changeChallengePassword = useCallback(async (newPassword: string) => {
    if (!challenge || (challenge.challenge.purpose !== "LOGIN" && challenge.challenge.purpose !== "ENROLLMENT") ||
        challenge.challenge.nextStep !== "PASSWORD_CHANGE" ||
        (phase !== "challenge-password-required" && phase !== "changing-challenge-password") ||
        !repository.authenticationChallenges) return false;
    const requestChallenge = challenge;
    const authenticationRevision = ++authenticationRevisionRef.current;
    setPhase("changing-challenge-password");
    setError(null);
    try {
      await repository.authenticationChallenges.changePassword({
        challengeId: challenge.challenge.id,
        challengeCredential: challenge.challengeCredential,
        newPassword
      });
      if (authenticationRevisionRef.current !== authenticationRevision || challengeRef.current !== requestChallenge) return false;
      replaceChallenge(null);
      credentialRef.current = null;
      setCredential(null);
      setCurrent(null);
      setFirstEnrollment(null);
      setReauthenticationReason(requestChallenge.challenge.purpose === "ENROLLMENT" ? "ENROLLMENT_PASSWORD" : "PASSWORD");
      setPhase("reauthentication-required");
      return true;
    } catch (changeError) {
      if (authenticationRevisionRef.current !== authenticationRevision || challengeRef.current !== requestChallenge) return false;
      const knownError = challengePasswordError(changeError);
      if (knownError === "passwordPolicy") {
        setError(knownError);
        setPhase("challenge-password-required");
      } else if (knownError === "challengeExpired") {
        replaceChallenge(null);
        setError(knownError);
        setPhase("anonymous");
      } else {
        // A missing or malformed response cannot prove the write did not commit.
        // The old challenge must never offer another password command.
        replaceChallenge(null);
        setError(null);
        setPhase("challenge-password-outcome-unknown");
      }
      return false;
    }
  }, [challenge, phase, replaceChallenge, repository]);

  const startFirstEnrollmentContact = useCallback(async (email: string) => {
    const start = repository.authenticationChallenges?.startFirstContact;
    if (!challenge || challenge.challenge.purpose !== "ENROLLMENT" || challenge.challenge.nextStep !== "ENROLLMENT" ||
        phase !== "enrollment-required" || firstEnrollment?.status !== "CONTACT_REQUIRED" ||
        firstEnrollment.state?.notificationContact?.state !== "NONE" || !start || firstEnrollmentOperationRef.current !== null) return false;
    const revision = ++authenticationRevisionRef.current;
    firstEnrollmentOperationRef.current = revision;
    const source = challenge;
    const requestId = `ui-first-contact-${crypto.randomUUID()}`;
    setFirstEnrollment({ ...firstEnrollment, busy: true });
    setError(null);
    try {
      const verification = await start({ challengeId: challenge.challenge.id, challengeCredential: challenge.challengeCredential, email, requestId });
      if (authenticationRevisionRef.current !== revision || challengeRef.current !== source) return false;
      if (verification.accountId !== firstEnrollment.state.notificationContact.accountId ||
          verification.userId !== firstEnrollment.state.notificationContact.userId) throw new Error("INVALID_IAM_RESPONSE");
      setFirstEnrollment({ ...firstEnrollment, status: "CONTACT_PENDING", busy: false, verification });
      return true;
    } catch (failure) {
      if (authenticationRevisionRef.current !== revision || challengeRef.current !== source) return false;
      const invalidInput = failure instanceof HttpProblem && (failure.status === 400 || failure.status === 422);
      const noLongerEligible = failure instanceof HttpProblem && [401, 403, 409].includes(failure.status);
      setFirstEnrollment({ ...firstEnrollment, status: invalidInput ? "CONTACT_REQUIRED" : noLongerEligible ? "UNAVAILABLE" : "OUTCOME_UNKNOWN", busy: false });
      setError(invalidInput ? "enrollmentContactInvalid" : noLongerEligible ? "enrollmentUnavailable" : "enrollmentOutcomeUnknown");
      return false;
    } finally { if (firstEnrollmentOperationRef.current === revision) firstEnrollmentOperationRef.current = null; }
  }, [challenge, firstEnrollment, phase, repository]);

  const confirmFirstEnrollmentContact = useCallback(async (code: string) => {
    const confirm = repository.authenticationChallenges?.confirmFirstContact;
    const inspect = repository.authenticationChallenges?.inspectFirstEnrollment;
    if (!challenge || challenge.challenge.purpose !== "ENROLLMENT" || challenge.challenge.nextStep !== "ENROLLMENT" ||
        phase !== "enrollment-required" || firstEnrollment?.status !== "CONTACT_PENDING" || !firstEnrollment.verification ||
        !confirm || !inspect || firstEnrollmentOperationRef.current !== null || !/^[0-9]{8}$/.test(code)) return false;
    const revision = ++authenticationRevisionRef.current;
    firstEnrollmentOperationRef.current = revision;
    const source = challenge;
    setFirstEnrollment({ ...firstEnrollment, busy: true });
    setError(null);
    try {
      const confirmed = await confirm({ challengeId: challenge.challenge.id, challengeCredential: challenge.challengeCredential,
        verificationId: firstEnrollment.verification.id, code, requestId: `ui-first-contact-confirm-${crypto.randomUUID()}` });
      if (confirmed.id !== firstEnrollment.verification.id || confirmed.accountId !== firstEnrollment.verification.accountId ||
          confirmed.userId !== firstEnrollment.verification.userId || confirmed.email !== firstEnrollment.verification.email ||
          confirmed.state !== "VERIFIED") throw new Error("INVALID_IAM_RESPONSE");
      const state = await inspect({ challengeId: challenge.challenge.id, challengeCredential: challenge.challengeCredential });
      if (authenticationRevisionRef.current !== revision || challengeRef.current !== source) return false;
      if (state.challenge.nextStep !== "ENROLLMENT" || state.challenge.expiresAt !== challenge.challenge.expiresAt ||
          state.notificationContact?.state !== "VERIFIED" || state.enrollment ||
          state.notificationContact.accountId !== firstEnrollment.verification.accountId ||
          state.notificationContact.userId !== firstEnrollment.verification.userId ||
          state.notificationContact.email !== firstEnrollment.verification.email) throw new Error("INVALID_IAM_RESPONSE");
      setFirstEnrollment({ ...firstEnrollment, status: "TOTP_READY", busy: false, state, verification: null });
      return true;
    } catch (failure) {
      if (authenticationRevisionRef.current !== revision || challengeRef.current !== source) return false;
      const retryableCode = failure instanceof HttpProblem && (failure.status === 401 || failure.status === 422);
      const noLongerEligible = failure instanceof HttpProblem && (failure.status === 403 || failure.status === 409);
      setFirstEnrollment({ ...firstEnrollment, status: retryableCode ? "CONTACT_PENDING" : noLongerEligible ? "UNAVAILABLE" : "OUTCOME_UNKNOWN", busy: false });
      setError(retryableCode ? "enrollmentContactInvalid" : noLongerEligible ? "enrollmentUnavailable" : "enrollmentOutcomeUnknown");
      return false;
    } finally { if (firstEnrollmentOperationRef.current === revision) firstEnrollmentOperationRef.current = null; }
  }, [challenge, firstEnrollment, phase, repository]);

  const startFirstEnrollmentFactor = useCallback(async () => {
    const start = repository.authenticationChallenges?.startFirstTOTP;
    if (!challenge || challenge.challenge.purpose !== "ENROLLMENT" || challenge.challenge.nextStep !== "ENROLLMENT" ||
        phase !== "enrollment-required" || firstEnrollment?.status !== "TOTP_READY" ||
        firstEnrollment.state?.notificationContact?.state !== "VERIFIED" || !start || firstEnrollmentOperationRef.current !== null) return false;
    const revision = ++authenticationRevisionRef.current;
    firstEnrollmentOperationRef.current = revision;
    const source = challenge;
    setFirstEnrollment({ ...firstEnrollment, busy: true });
    setError(null);
    try {
      const result = await start({ challengeId: challenge.challenge.id, challengeCredential: challenge.challengeCredential,
        requestId: `ui-first-factor-${crypto.randomUUID()}` });
      if (authenticationRevisionRef.current !== revision || challengeRef.current !== source) return false;
      if (result.outcome === "EQUAL_REPLAY") {
        setFirstEnrollment({ ...firstEnrollment, status: "MATERIAL_LOST", busy: false, enrollmentId: result.enrollment.id });
        return false;
      }
      if (Date.parse(result.enrollment.expiresAt) > Date.parse(challenge.challenge.expiresAt) || result.enrollment.state !== "PENDING") throw new Error("INVALID_IAM_RESPONSE");
      setFirstEnrollment({ ...firstEnrollment, status: "TOTP_PENDING", busy: false, provisioning: result.provisioning,
        enrollmentId: result.enrollment.id });
      return true;
    } catch (failure) {
      if (authenticationRevisionRef.current !== revision || challengeRef.current !== source) return false;
      const noLongerEligible = failure instanceof HttpProblem && [401, 403, 409].includes(failure.status);
      setFirstEnrollment({ ...firstEnrollment, status: noLongerEligible ? "UNAVAILABLE" : "OUTCOME_UNKNOWN", busy: false });
      setError(noLongerEligible ? "enrollmentUnavailable" : "enrollmentOutcomeUnknown");
      return false;
    } finally { if (firstEnrollmentOperationRef.current === revision) firstEnrollmentOperationRef.current = null; }
  }, [challenge, firstEnrollment, phase, repository]);

  const confirmFirstEnrollmentFactor = useCallback(async (code: string) => {
    const confirm = repository.authenticationChallenges?.confirmFirstTOTP;
    if (!challenge || challenge.challenge.purpose !== "ENROLLMENT" || challenge.challenge.nextStep !== "ENROLLMENT" ||
        phase !== "enrollment-required" || firstEnrollment?.status !== "TOTP_PENDING" ||
        !firstEnrollment.provisioning || !firstEnrollment.enrollmentId || !confirm ||
        firstEnrollmentOperationRef.current !== null || !/^[0-9]{6}$/.test(code)) return false;
    const revision = ++authenticationRevisionRef.current;
    firstEnrollmentOperationRef.current = revision;
    const source = challenge;
    setFirstEnrollment({ ...firstEnrollment, busy: true });
    setError(null);
    try {
      const result = await confirm({ challengeId: challenge.challenge.id, challengeCredential: challenge.challengeCredential,
        enrollmentId: firstEnrollment.enrollmentId, code, requestId: `ui-first-factor-confirm-${crypto.randomUUID()}` });
      if (authenticationRevisionRef.current !== revision || challengeRef.current !== source) return false;
      if (result.enrollment.id !== firstEnrollment.enrollmentId || result.recoveryCodes.length !== 10 ||
          new Set(result.recoveryCodes).size !== 10) throw new Error("INVALID_IAM_RESPONSE");
      replaceChallenge(null);
      setFirstEnrollment(null);
      setEnrollmentRecovery({ enrollmentId: result.enrollment.id, recoveryCodes: [...result.recoveryCodes] });
      setReauthenticationReason("FACTOR");
      setPhase("recovery-codes-required");
      return true;
    } catch (failure) {
      if (authenticationRevisionRef.current !== revision || challengeRef.current !== source) return false;
      const retryableCode = failure instanceof HttpProblem && failure.status === 401;
      const noLongerEligible = failure instanceof HttpProblem && (failure.status === 403 || failure.status === 409);
      setFirstEnrollment({ ...firstEnrollment, status: retryableCode ? "TOTP_PENDING" : noLongerEligible ? "UNAVAILABLE" : "OUTCOME_UNKNOWN", busy: false });
      setError(retryableCode ? "enrollmentFactorInvalid" : noLongerEligible ? "enrollmentUnavailable" : "enrollmentOutcomeUnknown");
      return false;
    } finally { if (firstEnrollmentOperationRef.current === revision) firstEnrollmentOperationRef.current = null; }
  }, [challenge, firstEnrollment, phase, replaceChallenge, repository]);

  const cancelAuthenticationChallenge = useCallback(() => {
    authenticationRevisionRef.current += 1;
    firstEnrollmentOperationRef.current = null;
    replaceChallenge(null);
    setFirstEnrollment(null);
    setError(null);
    setPhase("anonymous");
  }, [replaceChallenge]);

  const acknowledgeReauthentication = useCallback(() => {
    authenticationRevisionRef.current += 1;
    replaceAuthenticatorRecovery(null);
    setError(null);
    setPhase("anonymous");
  }, [replaceAuthenticatorRecovery]);

  const completeEnrollment = useCallback((expectedCredential: string, enrollmentId: string, recoveryCodes: string[]) => {
    if (credentialRef.current !== expectedCredential || recoveryCodes.length !== 10 || new Set(recoveryCodes).size !== 10) return false;
    authenticationRevisionRef.current += 1;
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
    authenticationRevisionRef.current += 1;
    setEnrollmentRecovery(null);
    setError(null);
    setPhase("reauthentication-required");
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
    sessionRevision,
    challenge,
    authenticatorRecovery,
    enrollmentRecovery,
    firstEnrollment,
    reauthenticationReason,
    error,
    clearError,
    login,
    verifyAuthenticationChallenge,
    enterAuthenticatorRecovery,
    startAuthenticatorRecovery,
    confirmAuthenticatorRecovery,
    inspectAuthenticatorRecovery,
    restartAuthenticatorRecovery,
    leaveAuthenticatorRecovery,
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
  }), [acknowledgeEnrollmentRecovery, acknowledgeReauthentication, authenticatorRecovery, cancelAuthenticationChallenge, challenge, changeChallengePassword, changePassword, clearError, confirmAuthenticatorRecovery, confirmFirstEnrollmentContact, confirmFirstEnrollmentFactor, current, enrollmentRecovery, firstEnrollment, reauthenticationReason, enterAuthenticatorRecovery, error, expire, inspectAuthenticatorRecovery, leaveAuthenticatorRecovery, login, logout, phase, sessionRevision, restartAuthenticatorRecovery, startAuthenticatorRecovery, startFirstEnrollmentContact, startFirstEnrollmentFactor, verifyAuthenticationChallenge]);
  const credentialValue = useMemo(() => ({ credential }), [credential]);

  return (
    <CredentialContext.Provider value={credentialValue}>
      <SessionContext.Provider value={sessionValue}>
        <PersonalSecurityProvider repository={repository} credential={credential} current={current} sessionRevision={sessionRevision} isCurrentSession={isCurrentSession} expire={expire} completeEnrollment={completeEnrollment}>
          <OwnSessionsProvider repository={repository} credential={credential} current={current} expire={expire}>
            {children}
          </OwnSessionsProvider>
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
