export type AccessAnalyzerStatus = "ACTIVE" | "DISABLED";

export type AccessDispositionMode = "REVIEW_ONLY" | "DISABLE_UNUSED_ACCESS_KEYS";

export type AccessDispositionRule =
  | { mode: "REVIEW_ONLY"; findingDelayDays: 0 }
  | { mode: "DISABLE_UNUSED_ACCESS_KEYS"; findingDelayDays: number };

export type AccessAnalyzer = {
  id: string;
  accountId: string;
  type: "UNUSED_ACCESS";
  status: AccessAnalyzerStatus;
  unusedAccessAgeDays: number;
  disposition: AccessDispositionRule;
  resourceVersion: number;
  createdAt: string;
  updatedAt: string;
};

export type AccessAnalyzerDirectory = {
  accountId: string;
  items: AccessAnalyzer[];
  nextAfter: string | null;
};

export type AccessObservationSource =
  | "IAM_PASSWORD_SESSIONS"
  | "IAM_ACCESS_KEY_AUTHORIZATIONS"
  | "IAM_ROLE_SESSIONS"
  | "IAM_ROLE_AUTHORIZATIONS"
  | "PAAS_RESULTS"
  | "EXTERNAL_FEDERATION";

export const accessObservationSources: readonly AccessObservationSource[] = [
  "IAM_PASSWORD_SESSIONS",
  "IAM_ACCESS_KEY_AUTHORIZATIONS",
  "IAM_ROLE_SESSIONS",
  "IAM_ROLE_AUTHORIZATIONS",
  "PAAS_RESULTS",
  "EXTERNAL_FEDERATION"
];

export type CompleteAccessObservationCoverage = {
  source: AccessObservationSource;
  state: "COMPLETE";
  observedFrom: string;
  observedThrough: string;
  reason: null;
};

export type InsufficientAccessObservationCoverage = {
  source: AccessObservationSource;
  state: "INSUFFICIENT_COVERAGE";
  observedFrom: string;
  observedThrough: string;
  reason:
    | "OBSERVATION_WINDOW_INCOMPLETE"
    | "HISTORICAL_PROVENANCE_UNKNOWN"
    | "RESTORE_GAP"
    | "SOURCE_NOT_READY";
};

export type ExcludedAccessObservationCoverage = {
  source: AccessObservationSource;
  state: "NOT_INCLUDED";
  observedFrom: null;
  observedThrough: null;
  reason: "SOURCE_NOT_IMPLEMENTED";
};

export type AccessObservationCoverage =
  | CompleteAccessObservationCoverage
  | InsufficientAccessObservationCoverage
  | ExcludedAccessObservationCoverage;

type AccessFindingRecord = {
  id: string;
  accountId: string;
  analyzerId: string;
  analyzerRevision: number;
  status: "ACTIVE" | "ARCHIVED" | "RESOLVED";
  targetResourceVersion: number;
  conditionGeneration: number;
  activityRevision: number;
  recoveryEpoch: number;
  recoveryCommandId: string | null;
  recoveryCompletedAt: string | null;
  windowStartedAt: string;
  observedAt: string;
  lastActivityAt: string | null;
  resourceVersion: number;
  createdAt: string;
  updatedAt: string;
  resolvedAt: string | null;
  resolutionReason: "CONDITION_CLEARED" | "AUTOMATIC_DISPOSITION" | null;
};

export type UnusedPasswordFinding = AccessFindingRecord & {
  type: "UNUSED_PASSWORD";
  target: { kind: "USER"; id: string };
};

export type UnusedAccessKeyFinding = AccessFindingRecord & {
  type: "UNUSED_ACCESS_KEY";
  target: { kind: "ACCESS_KEY"; id: string };
};

export type UnusedRoleFinding = AccessFindingRecord & {
  type: "UNUSED_ROLE";
  target: { kind: "ROLE"; id: string };
};

export type AccessFinding = UnusedPasswordFinding | UnusedAccessKeyFinding | UnusedRoleFinding;
export type AccessFindingStatus = AccessFinding["status"];
export type AccessFindingStatusFilter = AccessFindingStatus | "ALL";

export type AccessFindingDirectory = {
  accountId: string;
  analyzerId: string;
  observedAt: string;
  coverage: AccessObservationCoverage[];
  items: AccessFinding[];
  nextAfter: string | null;
};

export type CreateAccessAnalyzerCommand = {
  type: "UNUSED_ACCESS";
  unusedAccessAgeDays?: number;
  requestId: string;
};

export type UpdateAccessAnalyzerCommand = {
  status: AccessAnalyzerStatus;
  unusedAccessAgeDays: number;
  resourceVersion: number;
  requestId: string;
};

export type SetAccessDispositionCommand = {
  disposition: AccessDispositionRule;
  resourceVersion: number;
  requestId: string;
};

export type AccessFindingDispositionCommand = {
  resourceVersion: number;
  requestId: string;
};
