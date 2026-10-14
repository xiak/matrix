"use client";

import { createContext, useCallback, useContext, useMemo, useRef, useState, type ReactNode } from "react";
import { HttpProblem, requestToken } from "@/infrastructure/http/jsonRequest";
import type { AuthenticatedSession } from "../domain/session";
import { replacementEnrollmentFitsProof } from "../domain/personalSecurity";
import type {
  AuthenticatorState,
  AuthenticatorRemoval,
  NotificationContact,
  NotificationContactReplacementProgress,
  NotificationContactReplacementVerification,
  NotificationContactVerification,
  RecoveryCodeRegeneration,
  RecoveryCodeRegenerationIntent,
  RecoveryCodeRegenerationResponse,
  SecurityStepUp,
  TOTPEnrollment,
  TOTPEnrollmentIntent,
  TOTPEnrollmentStart,
  TOTPChangeIntent,
  TOTPRemovalResponse
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
  notificationReplacementAvailable: boolean;
  notificationReplacementProgress: NotificationContactReplacementProgress | null;
  totpReplacementAvailable: boolean;
  totpRemovalAvailable: boolean;
  totpChangeIntent: TOTPChangeIntent | null;
  totpChangePreviousSession: boolean;
  startTOTPChange(operation: TOTPChangeIntent["operation"], factor: AuthenticatorState): Promise<void>;
  inspectTOTPChange(): Promise<void>;
  verifyTOTPChange(command: { password: string; code: string }): Promise<void>;
  startReplacementEnrollment(): Promise<TOTPEnrollmentStart>;
  confirmReplacementEnrollment(code: string): Promise<void>;
  cancelReplacementEnrollment(): Promise<void>;
  removeTOTP(): Promise<TOTPRemovalResponse>;
  clearTOTPChange(): void;
  notificationContact(): Promise<NotificationContact>;
  startNotificationVerification(command: { email: string; password: string; requestId: string }): Promise<NotificationContactVerification>;
  notificationVerification(verificationId: string): Promise<NotificationContactVerification>;
  confirmNotificationVerification(verificationId: string, command: { code: string; requestId: string }): Promise<NotificationContactVerification>;
  startNotificationReplacement(command: { email: string; expectedResourceVersion: number; expectedFactorRevision: number }): Promise<SecurityStepUp>;
  retryNotificationReplacementStepUp(): Promise<SecurityStepUp>;
  inspectNotificationReplacementStepUp(): Promise<SecurityStepUp>;
  proveNotificationReplacement(command: { password: string; code: string }): Promise<SecurityStepUp>;
  startNotificationReplacementVerification(): Promise<NotificationContactReplacementVerification>;
  inspectNotificationReplacementVerification(): Promise<NotificationContactReplacementVerification>;
  confirmNotificationReplacement(code: string): Promise<NotificationContactReplacementVerification>;
  clearNotificationReplacementProgress(): void;
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

export class NotificationContactPasswordRejected extends Error {
  constructor() {
    super("NOTIFICATION_CONTACT_PASSWORD_REJECTED");
    this.name = "NotificationContactPasswordRejected";
  }
}

export class NotificationReplacementProofRejected extends Error {
  constructor() {
    super("NOTIFICATION_REPLACEMENT_PROOF_REJECTED");
    this.name = "NotificationReplacementProofRejected";
  }
}

const PersonalSecurityContext = createContext<PersonalSecurityClient | null>(null);

export function PersonalSecurityProvider({ children, repository, credential, current, sessionRevision, isCurrentSession, expire, completeEnrollment, completeRemoval }: {
  children: ReactNode;
  repository: IamRepository;
  credential: string | null;
  current: AuthenticatedSession | null;
  sessionRevision: number;
  isCurrentSession(expectedCredential: string, expectedRevision: number): boolean;
  expire(expectedCredential: string): boolean;
  completeEnrollment(expectedCredential: string, enrollmentId: string, recoveryCodes: string[]): boolean;
  completeRemoval(expectedCredential: string): boolean;
}) {
  type FactorChange = { credential: string; sessionId: string; sessionRevision: number; accountId: string; userId: string; intent: TOTPChangeIntent };
  const [factorChange, setFactorChange] = useState<FactorChange | null>(null);
  const factorChangeRef = useRef<FactorChange | null>(null);
  const commitFactorChange = useCallback((value: FactorChange | null) => {
    factorChangeRef.current = value;
    setFactorChange(value);
  }, []);
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
  const [notificationReplacement, setNotificationReplacement] = useState<{
    credential: string;
    accountId: string;
    userId: string;
    progress: NotificationContactReplacementProgress;
  } | null>(null);
  const client = useMemo<PersonalSecurityClient | null>(() => {
    const security = repository.personalSecurity;
    if (!security || !credential || !current) return null;
    const expectedCredential = credential;
    const expectedRevision = sessionRevision;
    const accountId = current.session.organizationId;
    const userId = current.session.principalId;
    const currentFactorChange = factorChange?.accountId === accountId && factorChange.userId === userId ? factorChange : null;
    const previousFactorSession = Boolean(currentFactorChange && (currentFactorChange.credential !== expectedCredential ||
      currentFactorChange.sessionId !== current.session.id || currentFactorChange.sessionRevision !== expectedRevision));
    const currentIntent = enrollmentIntent?.credential === expectedCredential &&
      enrollmentIntent.accountId === accountId && enrollmentIntent.userId === userId
      ? { requestId: enrollmentIntent.requestId, state: enrollmentIntent.state }
      : null;
    const currentRegeneration = regenerationIntent?.accountId === accountId && regenerationIntent.userId === userId &&
      (regenerationIntent.credential === expectedCredential ||
        regenerationIntent.intent.state === "REGENERATION_UNKNOWN" || regenerationIntent.intent.state === "COMPLETED")
      ? regenerationIntent.intent
      : null;
    const currentNotificationReplacement = notificationReplacement?.accountId === accountId && notificationReplacement.userId === userId &&
      notificationReplacement.credential === expectedCredential
      ? notificationReplacement.progress
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
    const ownedReplacementVerification = (value: NotificationContactReplacementVerification) => {
      ownedVerification(value);
      if (value.purpose !== "REPLACEMENT") throw new Error("INVALID_IAM_RESPONSE");
      return value;
    };
    const scopedAfterBearerCheck = async <T,>(request: Promise<T>, classifyPasswordRejection = false): Promise<T> => {
      try { return await request; }
      catch (failure) {
        if (failure instanceof HttpProblem && failure.status === 401 && isCurrentSession(expectedCredential, expectedRevision)) {
          try {
            ownedContact(await security.notificationContact(expectedCredential));
            if (classifyPasswordRejection && isCurrentSession(expectedCredential, expectedRevision)) {
              throw new NotificationContactPasswordRejected();
            }
          } catch (observation) {
            if (observation instanceof NotificationContactPasswordRejected) throw observation;
            if (observation instanceof HttpProblem && observation.status === 401 && isCurrentSession(expectedCredential, expectedRevision)) expire(expectedCredential);
          }
        }
        throw failure;
      }
    };
    const replacement = security.notificationReplacement;
    const replaceNotificationProgress = (requestId: string, update: (value: NotificationContactReplacementProgress) => NotificationContactReplacementProgress) => {
      if (!isCurrentSession(expectedCredential, expectedRevision)) return;
      setNotificationReplacement((value) => value?.credential === expectedCredential && value.accountId === accountId &&
        value.userId === userId && value.progress.requestId === requestId
        ? { ...value, progress: update(value.progress) }
        : value);
    };
    const requireNotificationReplacement = () => {
      if (!replacement || !currentNotificationReplacement) throw new Error("INVALID_IAM_STATE");
      return currentNotificationReplacement;
    };
    const validateReplacementStepUp = (value: SecurityStepUp, intent: NotificationContactReplacementProgress) => {
      if (value.requestId !== intent.requestId || value.expectedFactorRevision !== intent.expectedFactorRevision ||
          value.operation !== "NOTIFICATION_CONTACT_REPLACE" ||
          value.notificationContact?.expectedResourceVersion !== intent.notificationContact.expectedResourceVersion ||
          value.notificationContact?.email !== intent.notificationContact.email) throw new Error("INVALID_IAM_RESPONSE");
      return value;
    };
    const validateReplacementVerification = (value: NotificationContactReplacementVerification, intent: NotificationContactReplacementProgress) => {
      ownedReplacementVerification(value);
      if (value.requestId !== intent.requestId || value.expectedResourceVersion !== intent.notificationContact.expectedResourceVersion ||
          value.email !== intent.notificationContact.email) throw new Error("INVALID_IAM_RESPONSE");
      return value;
    };
    const startReplacementVerification = async (intent: NotificationContactReplacementProgress, stepUp: SecurityStepUp) => {
      replaceNotificationProgress(intent.requestId, (value) => ({ ...value, state: "VERIFICATION_UNKNOWN", stepUp }));
      try {
        const verification = validateReplacementVerification(await scoped(replacement!.startVerification(expectedCredential, {
          stepUpId: stepUp.id,
          requestId: intent.requestId,
          ...intent.notificationContact
        })), intent);
        replaceNotificationProgress(intent.requestId, (value) => ({ ...value, state: verification.state === "PENDING" ? "PENDING_CONFIRMATION" : verification.state === "VERIFIED" ? "COMPLETED" : "EXPIRED", stepUp, verification }));
        return verification;
      } catch (failure) {
        if (failure instanceof HttpProblem && failure.status === 429) {
          replaceNotificationProgress(intent.requestId, (value) => ({ ...value, state: "PROVED", stepUp }));
        } else if (failure instanceof HttpProblem && [403, 404, 422].includes(failure.status)) {
          replaceNotificationProgress(intent.requestId, (value) => ({ ...value, state: "EXPIRED" }));
        }
        throw failure;
      }
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
    const requireFactorChange = (write = false) => {
      const value = factorChangeRef.current;
      if (!isCurrentSession(expectedCredential, expectedRevision) || !value || value.accountId !== accountId || value.userId !== userId ||
          write && (value.credential !== expectedCredential || value.sessionId !== current.session.id || value.sessionRevision !== expectedRevision)) {
        throw new Error("STALE_IAM_SESSION");
      }
      return value.intent;
    };
    const factorInPhase = (intent: TOTPChangeIntent, phase: TOTPChangeIntent["state"]) => {
      const value = factorChangeRef.current;
      if (!isCurrentSession(expectedCredential, expectedRevision) || value?.accountId !== accountId || value.userId !== userId ||
          value.intent.requestId !== intent.requestId || value.intent.state !== phase) return null;
      return value;
    };
    const changeFactor = (intent: TOTPChangeIntent, update: Partial<TOTPChangeIntent>, phase = intent.state) => {
      const value = factorInPhase(intent, phase);
      if (!value) return false;
      commitFactorChange({ ...value, intent: { ...value.intent, ...update } });
      return true;
    };
    const ownedFactorProof = (value: SecurityStepUp, intent: TOTPChangeIntent) => {
      if (value.operation !== intent.operation || value.requestId !== intent.requestId || value.expectedFactorRevision !== intent.expectedFactorRevision ||
          intent.stepUp && (value.id !== intent.stepUp.id || value.createdAt !== intent.stepUp.createdAt || value.expiresAt !== intent.stepUp.expiresAt)) throw new Error("INVALID_IAM_RESPONSE");
      return value;
    };
    const ownedFactorEnrollment = (value: TOTPEnrollment, intent: TOTPChangeIntent) => {
      if (value.purpose !== "REPLACEMENT" || value.requestId !== intent.requestId || value.factorRevision !== intent.expectedFactorRevision ||
          intent.enrollment && (value.id !== intent.enrollment.id || value.createdAt !== intent.enrollment.createdAt || value.expiresAt !== intent.enrollment.expiresAt) ||
          intent.stepUp && !replacementEnrollmentFitsProof(value, intent.stepUp)) throw new Error("INVALID_IAM_RESPONSE");
      return value;
    };
    const ownedRemoval = (value: AuthenticatorRemoval, intent: TOTPChangeIntent) => {
      if (value.requestId !== intent.requestId || value.factorId !== intent.factorId || value.factorRevision !== intent.expectedFactorRevision + 1 ||
          intent.removal && (value.id !== intent.removal.id || value.removedAt !== intent.removal.removedAt)) {
        throw new Error("INVALID_IAM_RESPONSE");
      }
      return value;
    };
    return {
      accountId,
      totpReplacementAvailable: Boolean(security.replacement),
      totpRemovalAvailable: Boolean(security.removal),
      totpChangeIntent: currentFactorChange?.intent ?? null,
      totpChangePreviousSession: previousFactorSession,
      async startTOTPChange(operation, factor) {
        const active = factorChangeRef.current;
        if (!isCurrentSession(expectedCredential, expectedRevision) || factor.enrollmentState !== "BOUND" ||
            !security[operation === "TOTP_REPLACE" ? "replacement" : "removal"] ||
            active?.accountId === accountId && active.userId === userId || currentIntent || currentRegeneration || currentNotificationReplacement) {
          throw new Error("INVALID_IAM_STATE");
        }
        const intent: TOTPChangeIntent = { operation, requestId: requestToken("ui-totp-change-"),
          proofRequestId: requestToken("ui-totp-proof-"), confirmationRequestId: requestToken("ui-totp-confirm-"),
          factorId: factor.factorId, expectedFactorRevision: factor.factorRevision, state: "STEP_UP_UNKNOWN",
          stepUp: null, enrollment: null, removal: null };
        commitFactorChange({ credential: expectedCredential, sessionId: current.session.id, sessionRevision: expectedRevision, accountId, userId, intent });
        try {
          const api = operation === "TOTP_REPLACE" ? security.replacement! : security.removal!;
          const proof = ownedFactorProof(await scoped(api.startStepUp(expectedCredential, {
            requestId: intent.requestId, expectedFactorRevision: intent.expectedFactorRevision
          })), intent);
          if (proof.state !== "PENDING") throw new Error("INVALID_IAM_RESPONSE");
          changeFactor(intent, { state: "PENDING_PROOF", stepUp: proof });
        } catch (failure) {
          if (!factorInPhase(intent, "STEP_UP_UNKNOWN")) throw new Error("STALE_IAM_PHASE");
          if (failure instanceof HttpProblem && [400, 403, 409, 413, 415, 422, 429].includes(failure.status)) changeFactor(intent, { state: "REJECTED" });
          throw failure;
        }
      },
      async inspectTOTPChange() {
        const intent = requireFactorChange();
        if (["REJECTED", "CANCELLED", "EXPIRED"].includes(intent.state)) throw new Error("INVALID_IAM_STATE");
        if (intent.operation === "TOTP_REMOVE" && ["REMOVAL_UNKNOWN", "COMPLETED"].includes(intent.state)) {
          const removal = ownedRemoval(await scoped(security.removal!.removalByRequest(expectedCredential, intent.requestId)), intent);
          changeFactor(intent, { state: "COMPLETED", removal });
        } else if (intent.operation === "TOTP_REPLACE" && ["ENROLLMENT_UNKNOWN", "ENROLLING", "CONFIRM_UNKNOWN", "CANCEL_UNKNOWN", "COMPLETED"].includes(intent.state)) {
          const enrollment = ownedFactorEnrollment(await scoped(security.replacement!.enrollmentByRequest(expectedCredential, intent.requestId)), intent);
          // A current PENDING projection cannot disprove an in-flight confirm/cancel.
          // Only the original terminal observation can unlock an uncertain write.
          changeFactor(intent, { enrollment, state: enrollment.state === "CONFIRMED" ? "COMPLETED"
            : enrollment.state === "CANCELLED" ? "CANCELLED" : enrollment.state === "EXPIRED" ? "EXPIRED"
              : intent.state === "CONFIRM_UNKNOWN" || intent.state === "CANCEL_UNKNOWN" || intent.state === "COMPLETED" ? intent.state : "ENROLLING" });
        } else {
          const api = intent.operation === "TOTP_REPLACE" ? security.replacement! : security.removal!;
          const proof = ownedFactorProof(await scoped(api.stepUpByRequest(expectedCredential, intent.requestId)), intent);
          changeFactor(intent, { stepUp: proof, state: proof.state === "PENDING" ? intent.state === "PROOF_UNKNOWN" ? "PROOF_UNKNOWN" : "PENDING_PROOF" : proof.state === "PROVED" ? "PROVED"
            : proof.state === "CONSUMED" ? intent.operation === "TOTP_REPLACE" ? "ENROLLMENT_UNKNOWN" : "REMOVAL_UNKNOWN" : "EXPIRED" });
        }
      },
      async verifyTOTPChange(command) {
        const intent = requireFactorChange(true);
        if (intent.state !== "PENDING_PROOF" || !intent.stepUp || Date.now() >= Date.parse(intent.stepUp.expiresAt)) throw new Error("INVALID_IAM_STATE");
        changeFactor(intent, { state: "PROOF_UNKNOWN" });
        try {
          const api = intent.operation === "TOTP_REPLACE" ? security.replacement! : security.removal!;
          // Generic proof 401 may reject the password/OTP, not the bearer.
          const proof = ownedFactorProof(await api.verifyStepUp(expectedCredential, intent.stepUp.id, {
            requestId: intent.proofRequestId, password: command.password, code: command.code
          }), intent);
          changeFactor(intent, { state: proof.state === "PROVED" ? "PROVED" : "EXPIRED", stepUp: proof }, "PROOF_UNKNOWN");
        } catch (failure) {
          if (!factorInPhase(intent, "PROOF_UNKNOWN")) throw new Error("STALE_IAM_PHASE");
          if (failure instanceof HttpProblem && [400, 401, 413, 415, 422, 429].includes(failure.status)) {
            changeFactor(intent, { state: "PENDING_PROOF", proofRequestId: requestToken("ui-totp-proof-") }, "PROOF_UNKNOWN");
          }
          throw failure;
        }
      },
      async startReplacementEnrollment() {
        const intent = requireFactorChange(true);
        if (intent.operation !== "TOTP_REPLACE" || intent.state !== "PROVED" || !intent.stepUp || Date.now() >= Date.parse(intent.stepUp.expiresAt)) throw new Error("INVALID_IAM_STATE");
        changeFactor(intent, { state: "ENROLLMENT_UNKNOWN" });
        let result: TOTPEnrollmentStart;
        try {
          result = await scoped(security.replacement!.startEnrollment(expectedCredential, {
            requestId: intent.requestId, stepUpId: intent.stepUp.id, expectedFactorRevision: intent.expectedFactorRevision
          }));
        } catch (failure) {
          if (!factorInPhase(intent, "ENROLLMENT_UNKNOWN")) throw new Error("STALE_IAM_PHASE");
          if (failure instanceof HttpProblem && [400, 403, 409, 413, 415, 422, 429].includes(failure.status)) changeFactor(intent, { state: "REJECTED" }, "ENROLLMENT_UNKNOWN");
          throw failure;
        }
        const enrollment = ownedFactorEnrollment(result.enrollment, intent);
        if (!changeFactor(intent, { state: enrollment.state === "PENDING" ? "ENROLLING" : enrollment.state === "CONFIRMED" ? "COMPLETED"
          : enrollment.state === "CANCELLED" ? "CANCELLED" : "EXPIRED", enrollment }, "ENROLLMENT_UNKNOWN")) throw new Error("STALE_IAM_PHASE");
        return result;
      },
      async confirmReplacementEnrollment(code) {
        const intent = requireFactorChange(true);
        if (intent.operation !== "TOTP_REPLACE" || intent.state !== "ENROLLING" || !intent.enrollment ||
            Date.now() >= Date.parse(intent.enrollment.expiresAt)) throw new Error("INVALID_IAM_STATE");
        changeFactor(intent, { state: "CONFIRM_UNKNOWN" });
        try {
          const result = await scoped(security.replacement!.confirmEnrollment(expectedCredential, intent.enrollment.id, {
            requestId: intent.confirmationRequestId, code
          }));
          const enrollment = ownedFactorEnrollment(result.enrollment, intent);
          if (enrollment.state !== "CONFIRMED") throw new Error("INVALID_IAM_RESPONSE");
          if (!changeFactor(intent, { state: "COMPLETED", enrollment }, "CONFIRM_UNKNOWN")) throw new Error("STALE_IAM_PHASE");
          if (!isCurrentSession(expectedCredential, expectedRevision) ||
              !completeEnrollment(expectedCredential, enrollment.id, result.recoveryCodes)) throw new Error("STALE_IAM_SESSION");
        } catch (failure) {
          if (!factorInPhase(intent, "CONFIRM_UNKNOWN")) throw new Error("STALE_IAM_PHASE");
          if (failure instanceof HttpProblem && failure.status === 422 && failure.code === "iam.verification.rejected") {
            changeFactor(intent, { state: "ENROLLING", confirmationRequestId: requestToken("ui-totp-confirm-") }, "CONFIRM_UNKNOWN");
          }
          throw failure;
        }
      },
      async cancelReplacementEnrollment() {
        const intent = requireFactorChange();
        if (intent.operation !== "TOTP_REPLACE" || intent.state !== "ENROLLING" || !intent.enrollment || intent.enrollment.state !== "PENDING") throw new Error("INVALID_IAM_STATE");
        changeFactor(intent, { state: "CANCEL_UNKNOWN" });
        const enrollment = ownedFactorEnrollment(await scoped(security.replacement!.cancelEnrollment(expectedCredential, intent.enrollment.id)), intent);
        changeFactor(intent, { state: enrollment.state === "CANCELLED" ? "CANCELLED" : "EXPIRED", enrollment }, "CANCEL_UNKNOWN");
      },
      async removeTOTP() {
        const intent = requireFactorChange(true);
        if (intent.operation !== "TOTP_REMOVE" || intent.state !== "PROVED" || !intent.stepUp || Date.now() >= Date.parse(intent.stepUp.expiresAt)) throw new Error("INVALID_IAM_STATE");
        changeFactor(intent, { state: "REMOVAL_UNKNOWN" });
        let result: TOTPRemovalResponse;
        try {
          result = await scoped(security.removal!.remove(expectedCredential, {
            requestId: intent.requestId, stepUpId: intent.stepUp.id, expectedFactorRevision: intent.expectedFactorRevision
          }));
        } catch (failure) {
          if (!factorInPhase(intent, "REMOVAL_UNKNOWN")) throw new Error("STALE_IAM_PHASE");
          if (failure instanceof HttpProblem && [400, 403, 409, 413, 415, 422, 429].includes(failure.status)) changeFactor(intent, { state: "REJECTED" }, "REMOVAL_UNKNOWN");
          throw failure;
        }
        const removal = ownedRemoval(result.removal, intent);
        if (!changeFactor(intent, { state: "COMPLETED", removal }, "REMOVAL_UNKNOWN")) throw new Error("STALE_IAM_PHASE");
        if (result.outcome === "APPLIED" && (!isCurrentSession(expectedCredential, expectedRevision) || !completeRemoval(expectedCredential))) {
          throw new Error("STALE_IAM_SESSION");
        }
        return result;
      },
      clearTOTPChange() {
        const intent = requireFactorChange();
        if (["PENDING_PROOF", "PROVED", "COMPLETED", "REJECTED", "CANCELLED", "EXPIRED"].includes(intent.state)) commitFactorChange(null);
      },
      userId,
      sessionId: current.session.id,
      sessionRevision: expectedRevision,
      totpEnrollmentIntent: currentIntent,
      recoveryCodeRegenerationAvailable: Boolean(recoveryCodes),
      recoveryCodeRegenerationIntent: currentRegeneration,
      notificationReplacementAvailable: Boolean(replacement),
      notificationReplacementProgress: currentNotificationReplacement,
      notificationContact: async () => ownedContact(await scoped(security.notificationContact(expectedCredential))),
      startNotificationVerification: async (command) => ownedVerification(await scopedAfterBearerCheck(security.startNotificationVerification(expectedCredential, command), true)),
      notificationVerification: async (verificationId) => ownedVerification(await scoped(security.notificationVerification(expectedCredential, verificationId))),
      confirmNotificationVerification: async (verificationId, command) => ownedVerification(await scopedAfterBearerCheck(security.confirmNotificationVerification(expectedCredential, verificationId, command))),
      async startNotificationReplacement(command) {
        if (!replacement || currentNotificationReplacement || factorChangeRef.current?.accountId === accountId && factorChangeRef.current.userId === userId || command.expectedResourceVersion <= 0 || command.expectedFactorRevision <= 1) {
          throw new Error("INVALID_IAM_STATE");
        }
        const pending: NotificationContactReplacementProgress = {
          requestId: requestToken("ui-notification-replace-"),
          proofRequestId: requestToken("ui-notification-replace-proof-"),
          confirmationRequestId: requestToken("ui-notification-replace-confirm-"),
          expectedFactorRevision: command.expectedFactorRevision,
          notificationContact: { expectedResourceVersion: command.expectedResourceVersion, email: command.email },
          state: "STEP_UP_UNKNOWN",
          stepUp: null,
          verification: null
        };
        setNotificationReplacement({ credential: expectedCredential, accountId, userId, progress: pending });
        try {
          const stepUp = validateReplacementStepUp(await scoped(replacement.startStepUp(expectedCredential, {
            requestId: pending.requestId,
            expectedFactorRevision: pending.expectedFactorRevision,
            notificationContact: pending.notificationContact
          })), pending);
          replaceNotificationProgress(pending.requestId, (value) => ({ ...value, state: "PENDING_PROOF", stepUp }));
          return stepUp;
        } catch (failure) {
          if (failure instanceof HttpProblem && [400, 401, 403, 413, 415, 422].includes(failure.status)) {
            setNotificationReplacement((value) => value?.progress === pending ? null : value);
          }
          throw failure;
        }
      },
      async retryNotificationReplacementStepUp() {
        const intent = requireNotificationReplacement();
        if (intent.state !== "STEP_UP_UNKNOWN") throw new Error("INVALID_IAM_STATE");
        const stepUp = validateReplacementStepUp(await scoped(replacement!.startStepUp(expectedCredential, {
          requestId: intent.requestId,
          expectedFactorRevision: intent.expectedFactorRevision,
          notificationContact: intent.notificationContact
        })), intent);
        replaceNotificationProgress(intent.requestId, (value) => ({ ...value, state: "PENDING_PROOF", stepUp }));
        return stepUp;
      },
      async inspectNotificationReplacementStepUp() {
        const intent = requireNotificationReplacement();
        if (intent.state !== "STEP_UP_UNKNOWN" && intent.state !== "PROOF_UNKNOWN") throw new Error("INVALID_IAM_STATE");
        const stepUp = validateReplacementStepUp(await scoped(replacement!.stepUpByRequest(
          expectedCredential, intent.requestId, intent.expectedFactorRevision, intent.notificationContact
        )), intent);
        const state = stepUp.state === "PENDING" ? intent.state === "PROOF_UNKNOWN" ? "PROOF_UNKNOWN" : "PENDING_PROOF"
          : stepUp.state === "PROVED" || stepUp.state === "CONSUMED" ? "PROVED" : "EXPIRED";
        replaceNotificationProgress(intent.requestId, (value) => ({ ...value, state, stepUp }));
        return stepUp;
      },
      async proveNotificationReplacement(command) {
        const intent = requireNotificationReplacement();
        if (intent.state !== "PENDING_PROOF" || !intent.stepUp) throw new Error("INVALID_IAM_STATE");
        replaceNotificationProgress(intent.requestId, (value) => ({ ...value, state: "PROOF_UNKNOWN" }));
        let stepUp: SecurityStepUp;
        try {
          stepUp = validateReplacementStepUp(await replacement!.verifyStepUp(
            expectedCredential, intent.stepUp.id, intent.requestId, intent.expectedFactorRevision, intent.notificationContact,
            { requestId: intent.proofRequestId, password: command.password, code: command.code }
          ), intent);
        } catch (failure) {
          if (failure instanceof HttpProblem && failure.status === 401 && isCurrentSession(expectedCredential, expectedRevision)) {
            try {
              ownedContact(await security.notificationContact(expectedCredential));
              replaceNotificationProgress(intent.requestId, (value) => ({ ...value, state: "PENDING_PROOF", proofRequestId: requestToken("ui-notification-replace-proof-") }));
              throw new NotificationReplacementProofRejected();
            } catch (observation) {
              if (observation instanceof NotificationReplacementProofRejected) throw observation;
              if (observation instanceof HttpProblem && observation.status === 401 && isCurrentSession(expectedCredential, expectedRevision)) expire(expectedCredential);
            }
          }
          if (failure instanceof HttpProblem && [400, 413, 415, 422, 429].includes(failure.status)) {
            replaceNotificationProgress(intent.requestId, (value) => ({ ...value, state: "PENDING_PROOF", proofRequestId: requestToken("ui-notification-replace-proof-") }));
          } else if (failure instanceof HttpProblem && [403, 404].includes(failure.status)) {
            replaceNotificationProgress(intent.requestId, (value) => ({ ...value, state: "EXPIRED" }));
          }
          throw failure;
        }
        if (stepUp.state !== "PROVED") {
          replaceNotificationProgress(intent.requestId, (value) => ({ ...value, state: "EXPIRED", stepUp }));
          throw new Error("INVALID_IAM_STATE");
        }
        replaceNotificationProgress(intent.requestId, (value) => ({ ...value, state: "PROVED", stepUp }));
        return stepUp;
      },
      async startNotificationReplacementVerification() {
        const intent = requireNotificationReplacement();
        if (intent.state !== "PROVED" && intent.state !== "VERIFICATION_UNKNOWN" || !intent.stepUp) throw new Error("INVALID_IAM_STATE");
        return startReplacementVerification(intent, intent.stepUp);
      },
      async inspectNotificationReplacementVerification() {
        const intent = requireNotificationReplacement();
        if (!intent.verification || intent.state !== "PENDING_CONFIRMATION" && intent.state !== "CONFIRM_UNKNOWN") throw new Error("INVALID_IAM_STATE");
        const verification = validateReplacementVerification(await scoped(replacement!.verification(
          expectedCredential, intent.verification.id, { requestId: intent.requestId, ...intent.notificationContact }
        )), intent);
        const state = verification.state === "PENDING" ? intent.state === "CONFIRM_UNKNOWN" ? "CONFIRM_UNKNOWN" : "PENDING_CONFIRMATION"
          : verification.state === "VERIFIED" ? "COMPLETED" : "EXPIRED";
        replaceNotificationProgress(intent.requestId, (value) => ({ ...value, state, verification }));
        return verification;
      },
      async confirmNotificationReplacement(code) {
        const intent = requireNotificationReplacement();
        if (intent.state !== "PENDING_CONFIRMATION" || !intent.verification) throw new Error("INVALID_IAM_STATE");
        replaceNotificationProgress(intent.requestId, (value) => ({ ...value, state: "CONFIRM_UNKNOWN" }));
        try {
          const verification = validateReplacementVerification(await scoped(replacement!.confirmVerification(
            expectedCredential, intent.verification.id, { requestId: intent.requestId, ...intent.notificationContact },
            { code, requestId: intent.confirmationRequestId }
          )), intent);
          replaceNotificationProgress(intent.requestId, (value) => ({ ...value, state: "COMPLETED", verification }));
          return verification;
        } catch (failure) {
          if (failure instanceof HttpProblem && failure.status === 422 && failure.code === "iam.verification.rejected") {
            replaceNotificationProgress(intent.requestId, (value) => ({ ...value, state: "PENDING_CONFIRMATION", confirmationRequestId: requestToken("ui-notification-replace-confirm-") }));
          } else if (failure instanceof HttpProblem && failure.status === 429) {
            replaceNotificationProgress(intent.requestId, (value) => ({ ...value, state: "PENDING_CONFIRMATION" }));
          }
          throw failure;
        }
      },
      clearNotificationReplacementProgress() {
        setNotificationReplacement((value) => value?.credential === expectedCredential && value.accountId === accountId && value.userId === userId &&
          (value.progress.state === "COMPLETED" || value.progress.state === "EXPIRED") ? null : value);
      },
      authenticatorState: () => scoped(security.authenticatorState(expectedCredential)),
      async startTOTPEnrollment(command) {
        if (factorChangeRef.current?.accountId === accountId && factorChangeRef.current.userId === userId) throw new Error("INVALID_IAM_STATE");
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
        if (!recoveryCodes || currentRegeneration || factorChangeRef.current?.accountId === accountId && factorChangeRef.current.userId === userId) throw new Error("INVALID_IAM_STATE");
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
  }, [commitFactorChange, completeEnrollment, completeRemoval, credential, current, enrollmentIntent, expire, factorChange, isCurrentSession, notificationReplacement, regenerationIntent, repository.personalSecurity, sessionRevision]);

  return <PersonalSecurityContext.Provider value={client}>{children}</PersonalSecurityContext.Provider>;
}

export function usePersonalSecurity(): PersonalSecurityClient | null {
  return useContext(PersonalSecurityContext);
}
