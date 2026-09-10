import { type AccessWorkspace } from "./accessWorkspace";
import { parsePolicyDocument, type PolicyCondition } from "./policyDocument";
import { actionMatches, parsePolicyResource, policyActions, resourceMatches, sourceIpMatches, utcTimeValid, type PolicyResource } from "./policyLanguage";
import { roleServicePrincipals, roleSessionStatus, type RoleSessionCaller } from "./roleTrust";

export type AccessTestRequest = { principalId: string; action: string; resourceId: string; sourceIp?: string; at?: string };
export type AccessTestEvidence = {
  policyId: string; policyName: string; version?: number; statement?: number;
  source: "direct" | "group" | "role" | "boundary"; groupId?: string; effect?: "allow" | "deny";
  reason: "matched" | "actionMismatch" | "resourceMismatch" | "conditionMismatch" | "missingContext" | "invalidPolicy";
  missing?: ("sourceIp" | "time" | "resourceTags")[];
};
export type AccessTestResult = {
  decision: "allow" | "explicitDeny" | "implicitDeny" | "indeterminate" | "invalidRequest";
  evidence: AccessTestEvidence[];
  error?: "unknownIdentity" | "unknownResource" | "crossTenant" | "unknownAction" | "actionResourceMismatch" | "requiresRoleTrust" | "expiredSession" | "revokedSession" | "unavailableSession";
  boundary?: { policyId: string; decision: AccessTestResult["decision"] };
};
function conditionsMatch(condition: PolicyCondition | undefined, request: AccessTestRequest, tags: Record<string, string> | undefined) {
  const missing: NonNullable<AccessTestEvidence["missing"]> = [];
  let mismatch = false;
  if (condition?.sourceIp) {
    const result = request.sourceIp ? sourceIpMatches(request.sourceIp, condition.sourceIp) : null;
    if (result === null) missing.push("sourceIp"); else if (!result) mismatch = true;
  }
  if (condition?.notBefore || condition?.notAfter) {
    if (!request.at || !utcTimeValid(request.at)) missing.push("time");
    else if ((condition.notBefore && Date.parse(request.at) < Date.parse(condition.notBefore)) || (condition.notAfter && Date.parse(request.at) > Date.parse(condition.notAfter))) mismatch = true;
  }
  if (condition?.resourceTag) {
    if (!tags) missing.push("resourceTags");
    else if (condition.resourceTag.some((tag) => !Object.hasOwn(tags, tag.key) || tags[tag.key] !== tag.value)) mismatch = true;
  }
  return { reason: mismatch ? "conditionMismatch" as const : missing.length ? "missingContext" as const : "matched" as const, missing };
}

type PolicySource = Pick<AccessTestEvidence, "policyId" | "source" | "groupId">;
function decisionFor(evidence: AccessTestEvidence[]): AccessTestResult["decision"] {
  return evidence.some((entry) => entry.effect === "deny" && entry.reason === "matched") ? "explicitDeny" :
    evidence.some((entry) => entry.reason === "missingContext" || entry.reason === "invalidPolicy") ? "indeterminate" :
    evidence.some((entry) => entry.effect === "allow" && entry.reason === "matched") ? "allow" : "implicitDeny";
}
function userSources(workspace: AccessWorkspace, principalId: string): PolicySource[] {
  return [...(workspace.userPolicies[principalId] ?? []).map((policyId) => ({ policyId, source: "direct" as const })),
    ...workspace.groups.filter((group) => group.memberIds.includes(principalId)).flatMap((group) => group.policyIds.map((policyId) => ({ policyId, source: "group" as const, groupId: group.id })))];
}
function evaluatePolicies(workspace: AccessWorkspace, request: AccessTestRequest, resource: PolicyResource, tags: Record<string, string> | undefined, sources: PolicySource[], boundaryId?: string): AccessTestResult {
  const allSources = boundaryId ? [...sources, { policyId: boundaryId, source: "boundary" as const }] : sources;
  const evidence: AccessTestEvidence[] = [];
  // One request may inherit the same policy through several groups. Parse its
  // default version once, while retaining every grant source in the evidence.
  const documents = new Map<string, ReturnType<typeof parsePolicyDocument> | null>();
  const policies = new Map(workspace.policies.map((policy) => [policy.id, policy]));
  for (const source of allSources) {
    const policy = policies.get(source.policyId);
    const version = policy?.versions.find((entry) => entry.id === policy.defaultVersion);
    const base = { ...source, policyName: policy?.name ?? source.policyId, version: version?.id };
    if (!version) { evidence.push({ ...base, reason: "invalidPolicy" }); continue; }
    try {
      if (!documents.has(source.policyId)) {
        documents.set(source.policyId, null);
        documents.set(source.policyId, parsePolicyDocument(JSON.stringify(version.document), workspace.accountId));
      }
      const document = documents.get(source.policyId);
      if (!document) { evidence.push({ ...base, reason: "invalidPolicy" }); continue; }
      document.statement.forEach((statement, index) => {
        const entry = { ...base, statement: index + 1, effect: statement.effect };
        if (!statement.action.some((pattern) => actionMatches(pattern, request.action))) { evidence.push({ ...entry, reason: "actionMismatch" }); return; }
        if (!statement.resource.some((pattern) => resourceMatches(pattern, resource, workspace.accountId))) { evidence.push({ ...entry, reason: "resourceMismatch" }); return; }
        evidence.push({ ...entry, ...conditionsMatch(statement.condition, request, tags) });
      });
    } catch { evidence.push({ ...base, reason: "invalidPolicy" }); }
  }
  const grant = decisionFor(evidence.filter((entry) => entry.source !== "boundary"));
  if (!boundaryId) return { decision: grant, evidence };
  const boundary = { policyId: boundaryId, decision: decisionFor(evidence.filter((entry) => entry.source === "boundary")) };
  const decisions = [grant, boundary.decision];
  const decision = decisions.includes("explicitDeny") ? "explicitDeny" : decisions.includes("indeterminate") ? "indeterminate" : decisions.every((value) => value === "allow") ? "allow" : "implicitDeny";
  return { decision, evidence, boundary };
}
const invalid = (error: NonNullable<AccessTestResult["error"]>): AccessTestResult => ({ decision: "invalidRequest", evidence: [], error });
function evaluateResource(workspace: AccessWorkspace, request: AccessTestRequest, sources: PolicySource[], boundaryId?: string): AccessTestResult {
  const matches = workspace.testResources.filter((item) => item.id === request.resourceId);
  if (matches.length !== 1) return invalid("unknownResource");
  const selected = matches[0]!;
  const resource = parsePolicyResource(selected.reference, false);
  if (!resource) return invalid("unknownResource");
  if (resource.tenant !== workspace.accountId) return invalid("crossTenant");
  const action = policyActions.find((entry) => entry.id === request.action);
  if (!action) return invalid("unknownAction");
  if (action.id === "iam:assumeRole") return invalid("requiresRoleTrust");
  if (action.service !== resource.service || action.resourceType !== resource.type) return invalid("actionResourceMismatch");
  return evaluatePolicies(workspace, request, resource, selected.tags, sources, boundaryId);
}
/** Pure diagnostic, never used to authorize a backend call. */
export function evaluateUserAccess(workspace: AccessWorkspace, userIds: readonly string[], request: AccessTestRequest): AccessTestResult {
  if (!userIds.includes(request.principalId)) return invalid("unknownIdentity");
  return evaluateResource(workspace, request, userSources(workspace, request.principalId), workspace.userBoundaries[request.principalId]);
}
export type RoleAssumptionRequest = { roleId: string; caller: RoleSessionCaller; at: string; sourceIp?: string };
export type RoleAssumptionResult = { allowed: boolean; reason: "allowed" | "unknownRole" | "trustDenied" | "callerDenied"; callerDecision?: AccessTestResult };
export function evaluateRoleAssumption(workspace: AccessWorkspace, userIds: readonly string[], request: RoleAssumptionRequest): RoleAssumptionResult {
  const role = workspace.roles.find((entry) => entry.id === request.roleId);
  if (!role) return { allowed: false, reason: "unknownRole" };
  const caller = request.caller;
  let trusted = false;
  if (role.principalType === "account") trusted = caller.type === "user" && role.principal === workspace.accountId && userIds.includes(caller.id) && role.trustedUserIds.includes(caller.id);
  if (role.principalType === "service") trusted = caller.type === "service" && caller.id === role.principal && roleServicePrincipals.some((id) => id === caller.id);
  if (role.principalType === "provider") trusted = caller.type === "federation" && workspace.providers.some((entry) => entry.id === role.principal && entry.enabled) && workspace.federations.some((entry) => entry.id === caller.id && entry.enabled && entry.roleId === role.id && entry.providerId === role.principal);
  if (!trusted || !utcTimeValid(request.at)) return { allowed: false, reason: "trustDenied" };
  if (caller.type !== "user") return { allowed: true, reason: "allowed" };
  const resource: PolicyResource = { service: "iam", tenant: workspace.accountId, region: "global", type: "role", id: role.id };
  const callerDecision = evaluatePolicies(workspace, { principalId: caller.id, action: "iam:assumeRole", resourceId: role.id, at: request.at, sourceIp: request.sourceIp }, resource, Object.fromEntries(role.tags.map((tag) => [tag.key, tag.value])), userSources(workspace, caller.id), workspace.userBoundaries[caller.id]);
  return { allowed: callerDecision.decision === "allow", reason: callerDecision.decision === "allow" ? "allowed" : "callerDenied", callerDecision };
}
/** `now` is the diagnostic clock, separate from the policy request's time context. */
export function evaluateRoleSessionAccess(workspace: AccessWorkspace, userIds: readonly string[], sessionId: string, request: AccessTestRequest, now: string): AccessTestResult {
  const session = workspace.roleSessions.find((entry) => entry.id === sessionId);
  if (!session) return invalid("unavailableSession");
  const status = roleSessionStatus(workspace, session, userIds, now);
  if (status !== "active") return invalid(status === "expired" ? "expiredSession" : status === "revoked" ? "revokedSession" : "unavailableSession");
  const role = workspace.roles.find((entry) => entry.id === session.roleId)!;
  return evaluateResource(workspace, request, role.policyIds.map((policyId) => ({ policyId, source: "role" })), role.boundaryPolicyId);
}
