export const NODE_ENROLLMENT_JOIN_FILE_NAME = "matrix-node-join.json";
export const NODE_ENROLLMENT_INSTALL_COMMAND =
  "sudo ./mx node install --root /opt/matrix-node --bundle ./matrix-node-release --trust-key ./release-trust.json --join ./matrix-node-join.json";

export type NodeEnrollmentState =
  | "WAITING_INSTALL"
  | "VERIFYING"
  | "READY"
  | "FAILED"
  | "EXPIRED"
  | "REVOKED";

export type NodeEnrollmentDiagnosticCode =
  | "ENROLLMENT_EXPIRED"
  | "ENROLLMENT_REVOKED"
  | "CREDENTIAL_CONSUMED"
  | "INSTALLATION_MISMATCH"
  | "IDENTITY_CONFLICT"
  | "RUNTIME_UNSUPPORTED"
  | "MANAGEMENT_UNREACHABLE"
  | "MTLS_VERIFICATION_FAILED"
  | "RESOURCE_CONFLICT"
  | "NETWORK_INTERRUPTED";

export type NodeEnrollmentDiagnostic = {
  code: NodeEnrollmentDiagnosticCode;
  retryable: boolean;
  occurredAt: string;
};

export type NodeEnrollment = {
  id: string;
  name: string;
  labels: Record<string, string>;
  resourceVersion: number;
  createdAt: string;
  updatedAt: string;
  executionTargetId: string;
  executionPoolId: string;
  operationId: string;
  state: NodeEnrollmentState;
  expiresAt: string;
  credentialConsumedAt: string | null;
  readyAt: string | null;
  replacedById: string | null;
  diagnostic: NodeEnrollmentDiagnostic | null;
};

export type ExecutionPoolChoice = {
  id: string;
  name: string;
  resourceVersion: number;
  selectorLabels: Record<string, string>;
  phase: "READY" | "DEGRADED" | "UNAVAILABLE";
  targetCount: number;
  readyTargetCount: number;
  observedAt: string;
};

export type NodeEnrollmentInventory = {
  pools: ExecutionPoolChoice[];
  enrollments: NodeEnrollment[];
};

export type CreateNodeEnrollmentCommand = {
  name: string;
  executionPoolId: string;
};

export type CreateNodeEnrollmentRequest = {
  name: string;
  labels: Record<string, string>;
  executionPoolId: string;
  wrappingPublicKey: string;
};

export type NodeEnrollmentVersionCommand = {
  enrollmentId: string;
  resourceVersion: number;
};

export type NodeEnrollmentJoin = {
  apiVersion: "node.enrollment.matrix.xiak.com/v1";
  kind: "NodeEnrollmentJoin";
  enrollmentId: string;
  installationId: string;
  executionTargetId: string;
  controlPlaneUrl: string;
  credentialDigest: string;
  expiresAt: string;
  issuerCertificate: string;
  signatureAlgorithm: "ED25519";
  signature: string;
};

export type WrappedJoinCredential = {
  algorithm: "RSA_OAEP_256";
  ciphertext: string;
};

export type NodeEnrollmentCreation = {
  enrollment: NodeEnrollment;
  join: NodeEnrollmentJoin;
  wrappedCredential: WrappedJoinCredential;
};
