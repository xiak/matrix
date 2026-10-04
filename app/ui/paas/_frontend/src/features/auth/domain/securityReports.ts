import type { AccessKeyAuthorizationObservation, AccessKeyNetworkRestrictions } from "./accessKeyNetwork";

export const accountSecurityReportLimits = {
  users: 1_000,
  accessKeys: 2_000,
  rows: 3_001,
  csvBytes: 4 * 1024 * 1024,
  retainedDays: 7,
  retainedReports: 20
} as const;

export const accountSecurityReportCoverage = [
  ["IAM_ACCOUNT", "COMPLETE"],
  ["IAM_USERS", "COMPLETE"],
  ["IAM_LOGIN_SESSIONS", "COMPLETE"],
  ["IAM_ACCESS_KEYS", "COMPLETE"],
  ["IAM_ROLE_ACTIVITY", "NOT_INCLUDED"],
  ["PAAS_RESULTS", "NOT_INCLUDED"],
  ["AUDIT_STATISTICS", "NOT_INCLUDED"],
  ["NOTIFICATION_DELIVERY", "NOT_INCLUDED"],
  ["EXTERNAL_RISK", "NOT_INCLUDED"]
] as const;

export type SecurityReportObservationState = "OBSERVED" | "NOT_OBSERVED_IN_RETAINED_IAM_STATE" | "UNKNOWN";
export type SecurityReportCoverageSource = typeof accountSecurityReportCoverage[number][0];
export type SecurityReportCoverageState = typeof accountSecurityReportCoverage[number][1];

export type SecurityReportCoverage = {
  source: SecurityReportCoverageSource;
  state: SecurityReportCoverageState;
};

export type SecurityReportTimeObservation = {
  state: SecurityReportObservationState;
  observedAt?: string;
};

export type SecurityReportMFAState = {
  enrollmentState: "NEVER_BOUND" | "BOUND" | "RECOVERY_REQUIRED" | "REMOVED" | "UNKNOWN";
  factorRevision?: number;
};

export type SecurityReportUser = {
  id: string;
  loginName: string;
  displayName: string;
  status: "ACTIVE" | "DISABLED";
  root: boolean;
  mustChangePassword?: boolean;
  resourceVersion: number;
  createdAt: string;
  mfa: SecurityReportMFAState;
  lastPasswordLogin: SecurityReportTimeObservation;
};

export type SecurityReportAccessKey = {
  id: string;
  userId: string;
  status: "ENABLED" | "DISABLED";
  networkRestrictions: AccessKeyNetworkRestrictions;
  resourceVersion: number;
  createdAt: string;
  lastAuthorization?: AccessKeyAuthorizationObservation;
};

export type AccountSecurityReportMetadata = {
  apiVersion: "iam.matrix.xiak.com/v1";
  kind: "AccountSecurityReportMetadata";
  id: string;
  accountId: string;
  formatVersion: 1;
  observedAt: string;
  expiresAt: string;
  documentDigest: string;
  csvContentDigest: string;
  userCount: number;
  accessKeyCount: number;
  rowCount: number;
  csvBytes: number;
};

export type AccountSecurityReport = {
  metadata: AccountSecurityReportMetadata;
  accountSecuritySettingsVersion: number;
  coverage: SecurityReportCoverage[];
  users: SecurityReportUser[];
  accessKeys: SecurityReportAccessKey[];
};

export type AccountSecurityReportCreation = {
  outcome: "APPLIED" | "EQUAL_REPLAY";
  metadata: AccountSecurityReportMetadata;
};

export type AccountSecurityReportDownload = {
  metadata: AccountSecurityReportMetadata;
  bytes: Uint8Array;
  filename: string;
};
