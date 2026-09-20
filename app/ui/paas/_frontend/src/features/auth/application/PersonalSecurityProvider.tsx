"use client";

import { createContext, useContext, useMemo, type ReactNode } from "react";
import { HttpProblem } from "@/infrastructure/http/jsonRequest";
import type { AuthenticatedSession } from "../domain/session";
import type {
  AuthenticatorState,
  NotificationContact,
  NotificationContactVerification,
  TOTPEnrollment,
  TOTPEnrollmentStart
} from "../domain/personalSecurity";
import type { IamRepository } from "../repositories/iamRepository";

export type PersonalSecurityClient = {
  accountId: string;
  userId: string;
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
  const client = useMemo<PersonalSecurityClient | null>(() => {
    const security = repository.personalSecurity;
    if (!security || !credential || !current) return null;
    const expectedCredential = credential;
    const accountId = current.session.organizationId;
    const userId = current.session.principalId;
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
      notificationContact: async () => ownedContact(await scoped(security.notificationContact(expectedCredential))),
      startNotificationVerification: async (command) => ownedVerification(await scoped(security.startNotificationVerification(expectedCredential, command))),
      notificationVerification: async (verificationId) => ownedVerification(await scoped(security.notificationVerification(expectedCredential, verificationId))),
      confirmNotificationVerification: async (verificationId, command) => ownedVerification(await scoped(security.confirmNotificationVerification(expectedCredential, verificationId, command))),
      authenticatorState: () => scoped(security.authenticatorState(expectedCredential)),
      startTOTPEnrollment: (command) => scoped(security.startTOTPEnrollment(expectedCredential, command)),
      totpEnrollment: (enrollmentId) => scoped(security.totpEnrollment(expectedCredential, enrollmentId)),
      totpEnrollmentByRequest: (requestId) => scoped(security.totpEnrollmentByRequest(expectedCredential, requestId)),
      cancelTOTPEnrollment: (enrollmentId) => scoped(security.cancelTOTPEnrollment(expectedCredential, enrollmentId)),
      async confirmTOTPEnrollment(enrollmentId, command) {
        const result = await scoped(security.confirmTOTPEnrollment(expectedCredential, enrollmentId, command));
        if (result.enrollment.id !== enrollmentId || !completeEnrollment(expectedCredential, enrollmentId, result.recoveryCodes)) {
          throw new Error("INVALID_IAM_RESPONSE");
        }
      }
    };
  }, [completeEnrollment, credential, current, expire, repository.personalSecurity]);

  return <PersonalSecurityContext.Provider value={client}>{children}</PersonalSecurityContext.Provider>;
}

export function usePersonalSecurity(): PersonalSecurityClient | null {
  return useContext(PersonalSecurityContext);
}
