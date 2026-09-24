import type { SecuritySettingsUpdateIntent } from "./accounts";

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
  /** Present only on the fixed replacement wire; the currently integrated initial wire predates it. */
  purpose?: "INITIAL" | "REPLACEMENT";
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

export type TOTPEnrollmentIntent = {
  requestId: string;
  state: "UNKNOWN" | "KNOWN";
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

export type SecurityStepUpState = "PENDING" | "PROVED" | "CONSUMED" | "EXPIRED";

export type SecurityStepUp = {
  id: string;
  requestId: string;
  operation: "RECOVERY_CODES_REGENERATE" | "TOTP_REPLACE" | "SECURITY_SETTINGS_UPDATE";
  expectedFactorRevision: number;
  securitySettings?: SecuritySettingsUpdateIntent;
  state: SecurityStepUpState;
  createdAt: string;
  expiresAt: string;
  provedAt: string | null;
  consumedAt: string | null;
};

export type RecoveryCodeRegeneration = {
  id: string;
  requestId: string;
  factorId: string;
  factorRevision: number;
  createdAt: string;
};

export type RecoveryCodeRegenerationResponse =
  | {
      outcome: "APPLIED";
      regeneration: RecoveryCodeRegeneration;
      recoveryCodes: string[];
    }
  | {
      outcome: "EQUAL_REPLAY";
      regeneration: RecoveryCodeRegeneration;
    };

export type RecoveryCodeRegenerationIntentState =
  | "STEP_UP_UNKNOWN"
  | "PENDING"
  | "VERIFICATION_UNKNOWN"
  | "PROVED"
  | "REGENERATION_UNKNOWN"
  | "COMPLETED"
  | "EXPIRED";

export type RecoveryCodeRegenerationIntent = {
  requestId: string;
  factorId: string;
  expectedFactorRevision: number;
  state: RecoveryCodeRegenerationIntentState;
  stepUp: SecurityStepUp | null;
  regeneration: RecoveryCodeRegeneration | null;
};
