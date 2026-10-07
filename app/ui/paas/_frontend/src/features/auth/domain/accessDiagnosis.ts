import type { PolicyVersionReference } from "./accounts";
import type { AccessWorkspace } from "./accessWorkspace";
import { type AccessTestEvidence, type AccessTestResult, evaluateUserAccess } from "./policyEvaluation";
import { parsePolicyResource } from "./policyLanguage";
import { policyActions, type PolicyService } from "./previewAuthorizationCatalog";

export const accessDiagnosisReasons = [
  "CALLING_SERVICE_UNSUPPORTED",
  "CREDENTIAL_RESTRICTED",
  "EXPLICIT_DENY",
  "NO_MATCHING_ALLOW",
  "RESOURCE_CONTEXT_UNSUPPORTED",
  "ROLE_PERMISSION_BOUNDARY",
  "SESSION_POLICY",
  "SUBJECT_UNSUPPORTED",
  "USER_PERMISSION_BOUNDARY"
] as const;

export type AccessDiagnosisReason = typeof accessDiagnosisReasons[number];
export type AccessDiagnosisSourceKind = "DIRECT" | "GROUP" | "ROLE" | "SERVICE_ROLE";
export type AccessDiagnosisRestrictionKind = "USER_BOUNDARY" | "ROLE_BOUNDARY" | "SESSION_POLICY";

export type AccessDiagnosisSource = {
  kind: AccessDiagnosisSourceKind;
  effect: "ALLOW" | "DENY";
  version: PolicyVersionReference;
  attachmentId?: string;
  membershipId?: string;
};

export type AccessDiagnosisRestriction = {
  kind: AccessDiagnosisRestrictionKind;
  state: "MATCHED" | "BLOCKED" | "NOT_APPLICABLE";
  version?: PolicyVersionReference;
  contentDigest?: string;
};

export type AuthorizationDiagnosisBinding = {
  tenantId: string;
  subject: { type: "USER"; id: string };
  action: string;
  resource: { kind: string; id: string };
  profile: { product: PolicyService; revision: number; contentDigest: string };
  resourceMode: "INSTANCE";
  networkContext?: { sourceIp: string };
  requestTags?: { key: string; value: string }[];
  resourceTags?: { key: string; value: string }[];
};

export type CurrentAccessDiagnosis = AuthorizationDiagnosisBinding & {
  apiVersion: "iam.matrix.xiak.com/v1";
  kind: "CurrentAccessDiagnosis";
  outcome: "ALLOWED" | "DENIED";
  reasons: AccessDiagnosisReason[];
  requestId: string;
  correlationId: string;
  evaluatedAt: string;
  sources: AccessDiagnosisSource[];
  restrictions: AccessDiagnosisRestriction[];
  resourceExistence: "NOT_EVALUATED";
  businessOutcome: "NOT_EVALUATED";
};

export type AccessDiagnosisScenario = AccessWorkspace["testRequests"][number];
export type PreviewAccessDiagnosis =
  | { state: "READY"; diagnosis: CurrentAccessDiagnosis }
  | { state: "UNAVAILABLE" };

// The isolated preview needs format-valid immutable references to exercise the
// fixed response information architecture. This is deliberately not a content
// integrity proof and every rendered reference remains labelled as synthetic.
function syntheticDigest(seed: string): string {
  let state = 2166136261;
  let hex = "";
  for (let block = 0; block < 8; block += 1) {
    for (let index = 0; index < seed.length; index += 1) {
      state ^= seed.charCodeAt(index) + block;
      state = Math.imul(state, 16777619);
    }
    state ^= state >>> 13;
    state = Math.imul(state, 2246822519);
    hex += (state >>> 0).toString(16).padStart(8, "0");
  }
  return `sha256:${hex}`;
}

function policyVersionReference(
  workspace: AccessWorkspace,
  policyId: string,
  versionId?: number
): PolicyVersionReference | null {
  const policy = workspace.policies.find((entry) => entry.id === policyId);
  const version = policy?.versions.find((entry) => entry.id === (versionId ?? policy.defaultVersion));
  if (!policy || !version) return null;
  return {
    policyId: policy.id,
    versionId: `v${version.id}`,
    contentDigest: syntheticDigest(`${policy.id}:v${version.id}:${JSON.stringify(version.document)}`)
  };
}

export function previewAccessDiagnosisBinding(
  workspace: AccessWorkspace,
  scenario: AccessDiagnosisScenario
): AuthorizationDiagnosisBinding | null {
  const action = policyActions.find((entry) => entry.id === scenario.request.action);
  const fixture = workspace.testResources.find((entry) => entry.id === scenario.request.resourceId);
  const resource = parsePolicyResource(fixture?.reference ?? "", false);
  if (!action || !resource || resource.tenant !== workspace.accountId) return null;
  return {
    tenantId: workspace.accountId,
    subject: { type: "USER", id: scenario.request.principalId },
    action: scenario.request.action,
    resource: { kind: resource.type, id: resource.id },
    profile: {
      product: action.service,
      revision: 1,
      contentDigest: syntheticDigest(`profile:${action.service}:1`)
    },
    resourceMode: "INSTANCE",
    networkContext: scenario.request.sourceIp ? { sourceIp: scenario.request.sourceIp } : undefined,
    resourceTags: fixture?.tags
      ? Object.entries(fixture.tags).sort(([left], [right]) => left.localeCompare(right)).map(([key, value]) => ({ key, value }))
      : undefined
  };
}

function diagnosisReasons(result: AccessTestResult): AccessDiagnosisReason[] | null {
  if (result.decision === "indeterminate") return null;
  if (result.error) {
    const reason: AccessDiagnosisReason = result.error === "unknownAction" || result.error === "actionResourceMismatch"
      ? "CALLING_SERVICE_UNSUPPORTED"
      : result.error === "unknownResource" || result.error === "crossTenant"
        ? "RESOURCE_CONTEXT_UNSUPPORTED"
        : result.error === "unknownIdentity" || result.error === "requiresRoleTrust"
          ? "SUBJECT_UNSUPPORTED"
          : "CREDENTIAL_RESTRICTED";
    return [reason];
  }
  if (result.decision === "allow") return [];
  const reasons = new Set<AccessDiagnosisReason>();
  if (result.decision === "explicitDeny") reasons.add("EXPLICIT_DENY");
  if (!result.evidence.some((entry) => entry.source !== "boundary" && entry.effect === "allow" && entry.reason === "matched")) {
    reasons.add("NO_MATCHING_ALLOW");
  }
  if (result.boundary && result.boundary.decision !== "allow") reasons.add("USER_PERMISSION_BOUNDARY");
  return accessDiagnosisReasons.filter((reason) => reasons.has(reason));
}

function sourceKind(source: AccessTestEvidence["source"]): AccessDiagnosisSourceKind | null {
  if (source === "direct") return "DIRECT";
  if (source === "group") return "GROUP";
  if (source === "role") return "ROLE";
  return null;
}

function diagnosisSources(
  workspace: AccessWorkspace,
  scenario: AccessDiagnosisScenario,
  result: AccessTestResult
): AccessDiagnosisSource[] | null {
  const seen = new Set<string>();
  const sources: AccessDiagnosisSource[] = [];
  for (const entry of result.evidence) {
    const kind = sourceKind(entry.source);
    if (!kind || entry.reason !== "matched" || !entry.effect) continue;
    const version = policyVersionReference(workspace, entry.policyId, entry.version);
    if (!version) return null;
    const key = [kind, entry.effect, version.policyId, version.versionId, entry.groupId ?? ""].join(":");
    if (seen.has(key)) continue;
    seen.add(key);
    const attachmentId = kind === "GROUP"
      ? `mock-attachment:group:${entry.groupId}:${entry.policyId}`
      : `mock-attachment:${kind.toLowerCase()}:${scenario.request.principalId}:${entry.policyId}`;
    sources.push({
      kind,
      effect: entry.effect === "allow" ? "ALLOW" : "DENY",
      version,
      attachmentId,
      membershipId: entry.groupId ? `mock-membership:${entry.groupId}:${scenario.request.principalId}` : undefined
    });
  }
  return sources.sort((left, right) => [
    left.kind, left.effect, left.version.policyId, left.version.versionId, left.attachmentId ?? "", left.membershipId ?? ""
  ].join(":").localeCompare([
    right.kind, right.effect, right.version.policyId, right.version.versionId, right.attachmentId ?? "", right.membershipId ?? ""
  ].join(":")));
}

function diagnosisRestrictions(workspace: AccessWorkspace, result: AccessTestResult): AccessDiagnosisRestriction[] | null {
  if (!result.boundary) return [{ kind: "USER_BOUNDARY", state: "NOT_APPLICABLE" }];
  const version = policyVersionReference(workspace, result.boundary.policyId);
  if (!version) return null;
  return [{
    kind: "USER_BOUNDARY",
    state: result.boundary.decision === "allow" ? "MATCHED" : "BLOCKED",
    version
  }];
}

export function projectPreviewAccessDiagnosis(
  workspace: AccessWorkspace,
  userIds: readonly string[],
  scenario: AccessDiagnosisScenario,
  evaluatedAt: string
): PreviewAccessDiagnosis {
  const binding = previewAccessDiagnosisBinding(workspace, scenario);
  if (!binding) return { state: "UNAVAILABLE" };
  const result = evaluateUserAccess(workspace, userIds, scenario.request);
  const reasons = diagnosisReasons(result);
  const sources = diagnosisSources(workspace, scenario, result);
  const restrictions = diagnosisRestrictions(workspace, result);
  if (!reasons || !sources || !restrictions) return { state: "UNAVAILABLE" };
  return {
    state: "READY",
    diagnosis: {
      apiVersion: "iam.matrix.xiak.com/v1",
      kind: "CurrentAccessDiagnosis",
      ...binding,
      outcome: result.decision === "allow" ? "ALLOWED" : "DENIED",
      reasons,
      requestId: `mock-diagnosis:${scenario.id}`,
      correlationId: `mock-current-access:${scenario.id}`,
      evaluatedAt,
      sources,
      restrictions,
      resourceExistence: "NOT_EVALUATED",
      businessOutcome: "NOT_EVALUATED"
    }
  };
}
