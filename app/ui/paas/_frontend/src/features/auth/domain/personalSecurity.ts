export type NotificationContact =
  | {
      accountId: string;
      userId: string;
      state: "NONE";
      resourceVersion: 0;
      pendingVerificationId: string | null;
    }
  | {
      accountId: string;
      userId: string;
      state: "VERIFIED";
      resourceVersion: number;
      email: string;
      verifiedAt: string;
      pendingVerificationId: null;
    };

export type NotificationDeliveryObservation = {
  state: "PENDING" | "IN_FLIGHT" | "RETRY_WAIT" | "ACCEPTED" | "FAILED" | "EXPIRED";
  attempts: number;
  lastOutcome: "ACCEPTED" | "REJECTED" | "UNKNOWN" | "UNAVAILABLE" | null;
  lastSmtpCode: number | null;
  updatedAt: string;
};

export type NotificationContactVerification = {
  id: string;
  accountId: string;
  userId: string;
  requestId: string;
  email: string;
  state: "PENDING" | "VERIFIED" | "CANCELLED" | "EXPIRED";
  issuedAt: string;
  expiresAt: string;
  completedAt: string | null;
  delivery: NotificationDeliveryObservation;
};

export type AuthenticatorState =
  | { enrollmentState: "NEVER_BOUND"; factorRevision: 1; factorId: null }
  | { enrollmentState: "BOUND"; factorRevision: number; factorId: string }
  | { enrollmentState: "RECOVERY_REQUIRED"; factorRevision: number; factorId: string | null };

export type TOTPEnrollment = {
  id: string;
  requestId: string;
  factorRevision: number;
  state: "PENDING" | "CONFIRMED" | "CANCELLED" | "EXPIRED";
  createdAt: string;
  expiresAt: string;
  completedAt: string | null;
};

export type TOTPEnrollmentStart =
  | {
      outcome: "APPLIED";
      enrollment: TOTPEnrollment;
      provisioning: { seed: string; uri: string };
    }
  | {
      outcome: "EQUAL_REPLAY";
      enrollment: TOTPEnrollment;
    };

export type TOTPEnrollmentConfirmation = {
  enrollment: TOTPEnrollment;
  nextStep: "REAUTHENTICATE";
  recoveryCodes: string[];
};

export type EnrollmentRecoveryMaterial = {
  enrollmentId: string;
  recoveryCodes: string[];
};
