"use client";

import { createContext, useContext, useMemo, useState, type ReactNode } from "react";
import { HttpProblem } from "@/infrastructure/http/jsonRequest";
import type { AuthenticatedSession } from "../domain/session";
import type {
  AuthenticatorState,
  NotificationContact,
  NotificationContactVerification,
  TOTPEnrollment,
  TOTPEnrollmentIntent,
  TOTPEnrollmentStart
} from "../domain/personalSecurity";
import type { IamRepository } from "../repositories/iamRepository";

export type PersonalSecurityClient = {
  accountId: string;
  userId: string;
  totpEnrollmentIntent: TOTPEnrollmentIntent | null;
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
};

const PersonalSecurityContext = createContext<PersonalSecurityClient | null>(null);

export function PersonalSecurityProvider({ children, repository, credential, current, expire, completeEnrollment }: {
  children: ReactNode;
  repository: IamRepository;
  credential: string | null;
  current: AuthenticatedSession | null;
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
  const client = useMemo<PersonalSecurityClient | null>(() => {
    const security = repository.personalSecurity;
    if (!security || !credential || !current) return null;
    const expectedCredential = credential;
    const accountId = current.session.organizationId;
    const userId = current.session.principalId;
    const currentIntent = enrollmentIntent?.credential === expectedCredential &&
      enrollmentIntent.accountId === accountId && enrollmentIntent.userId === userId
      ? { requestId: enrollmentIntent.requestId, state: enrollmentIntent.state }
      : null;
    const scoped = async <T,>(request: Promise<T>): Promise<T> => {
      try { return await request; }
      catch (failure) {
        if (failure instanceof HttpProblem && failure.status === 401) expire(expectedCredential);
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
    return {
      accountId,
      userId,
      totpEnrollmentIntent: currentIntent,
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
      }
    };
  }, [completeEnrollment, credential, current, enrollmentIntent, expire, repository.personalSecurity]);

  return <PersonalSecurityContext.Provider value={client}>{children}</PersonalSecurityContext.Provider>;
}

export function usePersonalSecurity(): PersonalSecurityClient | null {
  return useContext(PersonalSecurityContext);
}
