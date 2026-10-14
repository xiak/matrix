import type { SecuritySettingsUpdateIntent } from "./accounts";
import type { EnrollmentAuthenticationChallenge } from "./session";

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
      /** A replacement keeps this verified address authoritative until confirmation. */
      pendingVerificationId: string | null;
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

export type NotificationContactReplacementIntent = {
  expectedResourceVersion: number;
  email: string;
};

export type NotificationContactReplacementVerification = NotificationContactVerification & {
  purpose: "REPLACEMENT";
  expectedResourceVersion: number;
};

export type NotificationContactReplacementState =
  | "STEP_UP_UNKNOWN"
  | "PENDING_PROOF"
  | "PROOF_UNKNOWN"
  | "PROVED"
  | "VERIFICATION_UNKNOWN"
  | "PENDING_CONFIRMATION"
  | "CONFIRM_UNKNOWN"
  | "COMPLETED"
  | "EXPIRED";

/**
 * Non-secret client knowledge for one purpose-bound address replacement.
 * Passwords and one-time codes deliberately never enter this model.
 */
export type NotificationContactReplacementProgress = {
  requestId: string;
  proofRequestId: string;
  confirmationRequestId: string;
  expectedFactorRevision: number;
  notificationContact: NotificationContactReplacementIntent;
  state: NotificationContactReplacementState;
  stepUp: SecurityStepUp | null;
  verification: NotificationContactReplacementVerification | null;
};

export type AuthenticatorState =
  | { enrollmentState: "NEVER_BOUND"; factorRevision: 1; factorId: null }
  | { enrollmentState: "REMOVED"; factorRevision: number; factorId: null }
  | { enrollmentState: "BOUND"; factorRevision: number; factorId: string }
  | { enrollmentState: "RECOVERY_REQUIRED"; factorRevision: number; factorId: string | null };

export type TOTPEnrollment = {
  id: string;
  requestId: string;
  purpose: "INITIAL" | "REPLACEMENT";
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

// A restricted pre-Session ceremony. Its credential remains in SessionProvider
// memory and cannot be used as a normal authenticated bearer.
export type EnrollmentChallengeState = {
  challenge: EnrollmentAuthenticationChallenge;
  notificationContact?: NotificationContact;
  enrollment?: TOTPEnrollment & { purpose: "INITIAL"; state: "PENDING" };
};

export type FirstEnrollmentProgress = {
  status: "INSPECTING" | "CONTACT_REQUIRED" | "CONTACT_PENDING" | "TOTP_READY" | "TOTP_PENDING"
    | "MATERIAL_LOST" | "OUTCOME_UNKNOWN" | "UNAVAILABLE";
  busy: boolean;
  state: EnrollmentChallengeState | null;
  verification: NotificationContactVerification | null;
  provisioning: { seed: string; uri: string } | null;
  enrollmentId: string | null;
};

export type EnrollmentRecoveryMaterial = {
  enrollmentId: string;
  recoveryCodes: string[];
};

export type SecurityStepUpState = "PENDING" | "PROVED" | "CONSUMED" | "EXPIRED";

export type SecurityStepUp = {
  id: string;
  requestId: string;
  operation: "RECOVERY_CODES_REGENERATE" | "TOTP_REPLACE" | "TOTP_REMOVE" | "SECURITY_SETTINGS_UPDATE" | "NOTIFICATION_CONTACT_REPLACE";
  expectedFactorRevision: number;
  securitySettings?: SecuritySettingsUpdateIntent;
  notificationContact?: NotificationContactReplacementIntent;
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

/** Historical completion only; it does not prove today's factor or Session state. */
export type AuthenticatorRemoval = {
  id: string;
  requestId: string;
  factorId: string;
  factorRevision: number;
  removedAt: string;
};

export type TOTPRemovalResponse =
  | { outcome: "APPLIED"; removal: AuthenticatorRemoval; nextStep: "REAUTHENTICATE" }
  | { outcome: "EQUAL_REPLAY"; removal: AuthenticatorRemoval };

/** One frozen factor-change ceremony. Password, OTP and provisioning remain outside it. */
export type TOTPChangeIntent = {
  operation: "TOTP_REPLACE" | "TOTP_REMOVE";
  requestId: string;
  proofRequestId: string;
  confirmationRequestId: string;
  factorId: string;
  expectedFactorRevision: number;
  state: "STEP_UP_UNKNOWN" | "PENDING_PROOF" | "PROOF_UNKNOWN" | "PROVED" | "ENROLLMENT_UNKNOWN"
    | "ENROLLING" | "CONFIRM_UNKNOWN" | "CANCEL_UNKNOWN" | "REMOVAL_UNKNOWN" | "COMPLETED" | "CANCELLED" | "REJECTED" | "EXPIRED";
  stepUp: SecurityStepUp | null;
  enrollment: TOTPEnrollment | null;
  removal: AuthenticatorRemoval | null;
};

/** IAM UTC timestamps retain microseconds; Date alone loses the proof boundary. */
export function replacementEnrollmentFitsProof(enrollment: TOTPEnrollment, proof: SecurityStepUp): boolean {
  const order = (value: string) => value.slice(0, 19) + "." + value.slice(19, -1).slice(1).padEnd(6, "0");
  return order(enrollment.createdAt) >= order(proof.createdAt) && order(enrollment.expiresAt) <= order(proof.expiresAt);
}

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
