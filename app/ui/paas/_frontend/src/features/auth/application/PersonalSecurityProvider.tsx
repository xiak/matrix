"use client";

import { createContext, useContext, useMemo, useState, type ReactNode } from "react";
import { HttpProblem } from "@/infrastructure/http/jsonRequest";
import type { AuthenticatedSession } from "../domain/session";
import type {
  AuthenticatorState,
  NotificationContact,
  NotificationContactVerification,
  RecoveryCodeRegeneration,
  RecoveryCodeRegenerationIntent,
  RecoveryCodeRegenerationResponse,
  SecurityStepUp,
  TOTPEnrollment,
  TOTPEnrollmentIntent,
  TOTPEnrollmentStart
} from "../domain/personalSecurity";
import type { IamRepository } from "../repositories/iamRepository";

export type PersonalSecurityClient = {
  accountId: string;
  userId: string;
  sessionId: string;
  sessionRevision: number;
  totpEnrollmentIntent: TOTPEnrollmentIntent | null;
  recoveryCodeRegenerationAvailable: boolean;
  recoveryCodeRegenerationIntent: RecoveryCodeRegenerationIntent | null;
  notificationContact(): Promise<NotificationContact>;
  startNotificationVerification(command: { email: string; password: string; requestId: string }): Promise<NotificationContactVerification>;
  notificationVerification(verificationId: string): Promise<NotificationContactVerification>;
  confirmNotificationVerification(verificationId: string, command: { code: string; requestId: string }): Promise<NotificationContactVerification>;
  authenticatorState(): Promise<AuthenticatorState>;
  startTOTPEnrollment(command: { requestId: string; password: string; expectedFactorRevision: number }): Promise<TOTPEnrollmentStart>;
  totpEnrollment(enrollmentId: string): Promise<TOTPEnrollment>;
  totpEnrollmentByRequest(requestId: string): Promise<TOTPEnrollment>;
  cancelTOTPEnrollment(enrollmentId: string): Promise<TOTPEnrollment>;
  confirmTOTPEnrollment(enrollmentId: string, command: { requestId: string; code: string }): Promise<void>;
  clearTOTPEnrollmentIntent(requestId: string): void;
  startRecoveryCodeRegeneration(command: { requestId: string; factorId: string; expectedFactorRevision: number }): Promise<SecurityStepUp>;
  retryRecoveryCodeStepUp(): Promise<SecurityStepUp>;
  inspectRecoveryCodeStepUp(): Promise<SecurityStepUp>;
  verifyRecoveryCodeStepUp(command: { requestId: string; password: string; code: string }): Promise<SecurityStepUp>;
  regenerateRecoveryCodes(): Promise<RecoveryCodeRegenerationResponse>;
  inspectRecoveryCodeRegeneration(): Promise<RecoveryCodeRegeneration>;
  clearRecoveryCodeRegenerationIntent(requestId: string): void;
};

const PersonalSecurityContext = createContext<PersonalSecurityClient | null>(null);

export function PersonalSecurityProvider({ children, repository, credential, current, sessionRevision, isCurrentSession, expire, completeEnrollment }: {
  children: ReactNode;
  repository: IamRepository;
  credential: string | null;
  current: AuthenticatedSession | null;
  sessionRevision: number;
  isCurrentSession(expectedCredential: string, expectedRevision: number): boolean;
  expire(expectedCredential: string): boolean;
  completeEnrollment(expectedCredential: string, enrollmentId: string, recoveryCodes: string[]): boolean;
}) {
  const [enrollmentIntent, setEnrollmentIntent] = useState<{
    credential: string;
    accountId: string;
    userId: string;
    requestId: string;
    state: "UNKNOWN" | "KNOWN";
  } | null>(null);
  const [regenerationIntent, setRegenerationIntent] = useState<{
    credential: string;
    accountId: string;
    userId: string;
    intent: RecoveryCodeRegenerationIntent;
  } | null>(null);
  const client = useMemo<PersonalSecurityClient | null>(() => {
    const security = repository.personalSecurity;
    if (!security || !credential || !current) return null;
    const expectedCredential = credential;
    const expectedRevision = sessionRevision;
    const accountId = current.session.organizationId;
    const userId = current.session.principalId;
    const currentIntent = enrollmentIntent?.credential === expectedCredential &&
      enrollmentIntent.accountId === accountId && enrollmentIntent.userId === userId
      ? { requestId: enrollmentIntent.requestId, state: enrollmentIntent.state }
      : null;
    const currentRegeneration = regenerationIntent?.accountId === accountId && regenerationIntent.userId === userId &&
      (regenerationIntent.credential === expectedCredential ||
        regenerationIntent.intent.state === "REGENERATION_UNKNOWN" || regenerationIntent.intent.state === "COMPLETED")
      ? regenerationIntent.intent
      : null;
    const scoped = async <T,>(request: Promise<T>): Promise<T> => {
      try { return await request; }
      catch (failure) {
        if (failure instanceof HttpProblem && failure.status === 401 && isCurrentSession(expectedCredential, expectedRevision)) expire(expectedCredential);
        throw failure;
      }
    };
    const ownedContact = (value: NotificationContact) => {
      if (value.accountId !== accountId || value.userId !== userId) throw new Error("INVALID_IAM_RESPONSE");
      return value;
    };
    const ownedVerification = (value: NotificationContactVerification) => {
      if (value.accountId !== accountId || value.userId !== userId) throw new Error("INVALID_IAM_RESPONSE");
      return value;
    };
    const recoveryCodes = security.recoveryCodes;
    const replaceRegeneration = (requestId: string, update: (value: RecoveryCodeRegenerationIntent) => RecoveryCodeRegenerationIntent) => {
      if (!isCurrentSession(expectedCredential, expectedRevision)) return;
      setRegenerationIntent((value) => value?.accountId === accountId && value.userId === userId && value.intent.requestId === requestId
        ? { ...value, credential: expectedCredential, intent: update(value.intent) }
        : value);
    };
    const requireRegeneration = () => {
      if (!recoveryCodes || !currentRegeneration) throw new Error("INVALID_IAM_STATE");
      return currentRegeneration;
    };
    const validateStepUp = (value: SecurityStepUp, intent: RecoveryCodeRegenerationIntent) => {
      if (value.requestId !== intent.requestId || value.expectedFactorRevision !== intent.expectedFactorRevision) {
        throw new Error("INVALID_IAM_RESPONSE");
      }
      return value;
    };
    const validateRegeneration = (value: RecoveryCodeRegeneration, intent: RecoveryCodeRegenerationIntent) => {
      if (value.requestId !== intent.requestId || value.factorId !== intent.factorId || value.factorRevision !== intent.expectedFactorRevision) {
        throw new Error("INVALID_IAM_RESPONSE");
      }
      return value;
    };
    return {
      accountId,
      userId,
      sessionId: current.session.id,
      sessionRevision: expectedRevision,
      totpEnrollmentIntent: currentIntent,
      recoveryCodeRegenerationAvailable: Boolean(recoveryCodes),
      recoveryCodeRegenerationIntent: currentRegeneration,
      notificationContact: async () => ownedContact(await scoped(security.notificationContact(expectedCredential))),
      startNotificationVerification: async (command) => ownedVerification(await scoped(security.startNotificationVerification(expectedCredential, command))),
      notificationVerification: async (verificationId) => ownedVerification(await scoped(security.notificationVerification(expectedCredential, verificationId))),
      confirmNotificationVerification: async (verificationId, command) => ownedVerification(await scoped(security.confirmNotificationVerification(expectedCredential, verificationId, command))),
      authenticatorState: () => scoped(security.authenticatorState(expectedCredential)),
      async startTOTPEnrollment(command) {
        const pending = { credential: expectedCredential, accountId, userId, requestId: command.requestId, state: "UNKNOWN" as const };
        setEnrollmentIntent(pending);
        try {
          const result = await scoped(security.startTOTPEnrollment(expectedCredential, command));
          setEnrollmentIntent((value) => value === pending ? { ...pending, state: "KNOWN" } : value);
          return result;
        } catch (failure) {
          if (failure instanceof HttpProblem && [400, 401, 403, 409, 413, 415, 422, 429].includes(failure.status)) {
            setEnrollmentIntent((value) => value === pending ? null : value);
          }
          throw failure;
        }
      },
      totpEnrollment: (enrollmentId) => scoped(security.totpEnrollment(expectedCredential, enrollmentId)),
      async totpEnrollmentByRequest(requestId) {
        const result = await scoped(security.totpEnrollmentByRequest(expectedCredential, requestId));
        setEnrollmentIntent((value) => value?.credential === expectedCredential && value.requestId === requestId
          ? { ...value, state: "KNOWN" }
          : value);
        return result;
      },
      async cancelTOTPEnrollment(enrollmentId) {
        const result = await scoped(security.cancelTOTPEnrollment(expectedCredential, enrollmentId));
        setEnrollmentIntent((value) => value?.credential === expectedCredential && value.requestId === result.requestId ? null : value);
        return result;
      },
      async confirmTOTPEnrollment(enrollmentId, command) {
        const result = await scoped(security.confirmTOTPEnrollment(expectedCredential, enrollmentId, command));
        if (result.enrollment.id !== enrollmentId || !completeEnrollment(expectedCredential, enrollmentId, result.recoveryCodes)) {
          throw new Error("INVALID_IAM_RESPONSE");
        }
        setEnrollmentIntent((value) => value?.credential === expectedCredential && value.requestId === result.enrollment.requestId ? null : value);
      },
      clearTOTPEnrollmentIntent(requestId) {
        setEnrollmentIntent((value) => {
          if (value?.credential !== expectedCredential || value.requestId !== requestId) return value;
          return null;
        });
      },
      async startRecoveryCodeRegeneration(command) {
        if (!recoveryCodes || currentRegeneration) throw new Error("INVALID_IAM_STATE");
        const pending: RecoveryCodeRegenerationIntent = {
          requestId: command.requestId,
          factorId: command.factorId,
          expectedFactorRevision: command.expectedFactorRevision,
          state: "STEP_UP_UNKNOWN",
          stepUp: null,
          regeneration: null
        };
        setRegenerationIntent({ credential: expectedCredential, accountId, userId, intent: pending });
        try {
          const stepUp = validateStepUp(await scoped(recoveryCodes.startStepUp(expectedCredential, {
            requestId: command.requestId,
            expectedFactorRevision: command.expectedFactorRevision
          })), pending);
          replaceRegeneration(command.requestId, (value) => ({ ...value, state: "PENDING", stepUp }));
          return stepUp;
        } catch (failure) {
          if (failure instanceof HttpProblem && [400, 401, 403, 409, 413, 415, 422, 429].includes(failure.status)) {
            setRegenerationIntent((value) => value?.intent === pending ? null : value);
          }
          throw failure;
        }
      },
      async retryRecoveryCodeStepUp() {
        const intent = requireRegeneration();
        if (intent.state !== "STEP_UP_UNKNOWN") throw new Error("INVALID_IAM_STATE");
        const stepUp = validateStepUp(await scoped(recoveryCodes!.startStepUp(expectedCredential, {
          requestId: intent.requestId,
          expectedFactorRevision: intent.expectedFactorRevision
        })), intent);
        replaceRegeneration(intent.requestId, (value) => ({ ...value, state: "PENDING", stepUp }));
        return stepUp;
      },
      async inspectRecoveryCodeStepUp() {
        const intent = requireRegeneration();
        const stepUp = validateStepUp(await scoped(recoveryCodes!.stepUpByRequest(expectedCredential, intent.requestId)), intent);
        const state = stepUp.state === "PENDING" ? "PENDING"
          : stepUp.state === "PROVED" ? "PROVED"
            : stepUp.state === "CONSUMED" ? "REGENERATION_UNKNOWN" : "EXPIRED";
        replaceRegeneration(intent.requestId, (value) => ({ ...value, state, stepUp }));
        return stepUp;
      },
      async verifyRecoveryCodeStepUp(command) {
        const intent = requireRegeneration();
        if (intent.state !== "PENDING" || !intent.stepUp) throw new Error("INVALID_IAM_STATE");
        replaceRegeneration(intent.requestId, (value) => ({ ...value, state: "VERIFICATION_UNKNOWN" }));
        try {
          // A rejected password/TOTP and an invalid bearer intentionally share
          // the same generic 401. Do not destroy the login session based on
          // this operation alone; the next bearer-only read remains authoritative.
          const stepUp = validateStepUp(await recoveryCodes!.verifyStepUp(expectedCredential, intent.stepUp.id, command), intent);
          replaceRegeneration(intent.requestId, (value) => ({ ...value, state: stepUp.state === "PROVED" ? "PROVED" : "EXPIRED", stepUp }));
          return stepUp;
        } catch (failure) {
          if (failure instanceof HttpProblem && [400, 401, 413, 415, 422, 429].includes(failure.status)) {
            replaceRegeneration(intent.requestId, (value) => ({ ...value, state: "PENDING" }));
          }
          throw failure;
        }
      },
      async regenerateRecoveryCodes() {
        const intent = requireRegeneration();
        if (intent.state !== "PROVED" || !intent.stepUp) throw new Error("INVALID_IAM_STATE");
        replaceRegeneration(intent.requestId, (value) => ({ ...value, state: "REGENERATION_UNKNOWN" }));
        const result = await scoped(recoveryCodes!.regenerate(expectedCredential, {
          requestId: intent.requestId,
          stepUpId: intent.stepUp.id,
          expectedFactorRevision: intent.expectedFactorRevision
        }));
        const regeneration = validateRegeneration(result.regeneration, intent);
        if (!isCurrentSession(expectedCredential, expectedRevision)) throw new Error("STALE_IAM_SESSION");
        replaceRegeneration(intent.requestId, (value) => ({ ...value, state: "COMPLETED", stepUp: value.stepUp ? { ...value.stepUp, state: "CONSUMED" } : null, regeneration }));
        return result;
      },
      async inspectRecoveryCodeRegeneration() {
        const intent = requireRegeneration();
        const regeneration = validateRegeneration(await scoped(recoveryCodes!.regenerationByRequest(expectedCredential, intent.requestId)), intent);
        replaceRegeneration(intent.requestId, (value) => ({ ...value, state: "COMPLETED", regeneration }));
        return regeneration;
      },
      clearRecoveryCodeRegenerationIntent(requestId) {
        setRegenerationIntent((value) => {
          if (value?.accountId !== accountId || value.userId !== userId || value.intent.requestId !== requestId ||
              value.intent.state !== "COMPLETED" && value.intent.state !== "EXPIRED") return value;
          return null;
        });
      }
    };
  }, [completeEnrollment, credential, current, enrollmentIntent, expire, isCurrentSession, regenerationIntent, repository.personalSecurity, sessionRevision]);

  return <PersonalSecurityContext.Provider value={client}>{children}</PersonalSecurityContext.Provider>;
}

export function usePersonalSecurity(): PersonalSecurityClient | null {
  return useContext(PersonalSecurityContext);
}
