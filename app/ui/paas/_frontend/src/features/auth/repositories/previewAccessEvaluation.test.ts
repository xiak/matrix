import { describe, expect, it } from "vitest";
import { applyAccessWorkspaceCommand, policyUsageCounts, type AccessWorkspace } from "../domain/accessWorkspace";
import { parsePolicyDocument, type PolicyCondition, type PolicyDocument } from "../domain/policyDocument";
import { evaluateUserAccess, evaluateRoleAssumption, evaluateRoleSessionAccess, type AccessTestRequest } from "../domain/policyEvaluation";
import { actionPatternValid, expandPolicyActions, formatPolicyResource, parsePolicyResource, policyActions, policyConditionsForActions, policyConditionKeys, sourceCidrValid, sourceIpMatches, utcTimeValid } from "../domain/policyLanguage";
import { initialAccessWorkspace } from "./previewAccessWorkspace";

const userIds = ["principal-lin", "principal-chen"];
const request: AccessTestRequest = { principalId: "principal-lin", action: "logs:search", resourceId: "logs-production/payment", sourceIp: "192.0.2.42", at: "2026-09-09T12:00:00Z" };
const grant = (condition?: PolicyCondition, effect: "allow" | "deny" = "allow"): PolicyDocument => ({ version: "1", statement: [{ effect, action: ["logs:search"], resource: ["*"], ...(condition !== undefined ? { condition } : {}) }] });
const roleContext = { id: "role-logs", at: request.at!, userIds, primaryPrincipalId: "principal-admin" };
const accountRole = { kind: "create-role" as const, name: "LogSupport", description: "Synthetic support role", principalType: "account" as const, principal: "org-xiak", trustedUserIds: ["principal-lin"], policyIds: ["policy-read"], boundaryPolicyId: "policy-prod-logs", tags: [{ key: "team", value: "support" }], sessionMinutes: 60, consoleAccess: false };
const assumption = { roleId: roleContext.id, caller: { type: "user" as const, id: "principal-lin" }, sourceIp: request.sourceIp, at: request.at! };
function roleWorkspace() { return applyAccessWorkspaceCommand(initialAccessWorkspace("org-xiak"), accountRole, roleContext); }
function issueSession(workspace: AccessWorkspace) { return applyAccessWorkspaceCommand(workspace, { kind: "create-role-session", ...assumption, sessionMinutes: 30 }, { ...roleContext, id: "session-logs" }); }
function withPolicy(condition?: PolicyCondition, effect: "allow" | "deny" = "allow") {
  const workspace = initialAccessWorkspace("org-xiak");
  workspace.policies.find((policy) => policy.id === "policy-prod-logs")!.versions[0]!.document = grant(condition, effect);
  return workspace;
}
describe("coherent access-review examples", () => {
  const ids = ["principal-lin", "principal-chen", "principal-qiao", "principal-wu"];
  const qiao = { ...request, principalId: "principal-qiao" };
  it("computes every example from the current policies, not from an expected verdict in the fixture", () => {
    const workspace = initialAccessWorkspace("org-xiak");
    expect(workspace.testRequests.map((entry) => [entry.id, evaluateUserAccess(workspace, ids, { ...request, ...entry.request }).decision])).toEqual([
      ["path", "allow"], ["duplicate", "allow"], ["tags", "allow"], ["deny", "explicitDeny"], ["boundary", "implicitDeny"], ["ungranted", "implicitDeny"]
    ]);
    expect(workspace.userProfiles["principal-wu"]?.consoleAccess).toBe(true);
    expect(evaluateUserAccess(workspace, ids, { ...qiao, principalId: "principal-wu" }).evidence).toEqual([]);
  });
  it("distinguishes a resource path from tags and preserves both direct and inherited sources", () => {
    let workspace = initialAccessWorkspace("org-xiak");
    const archived = { ...qiao, resourceId: "logs-archive/payment" };
    expect(evaluateUserAccess(workspace, ids, { ...archived, principalId: "principal-lin" }).decision).toBe("implicitDeny");
    const tagged = evaluateUserAccess(workspace, ids, archived);
    expect(tagged.decision).toBe("allow");
    expect(tagged.evidence.filter((entry) => entry.policyId === "policy-tag-logs").map((entry) => entry.source)).toEqual(["direct", "group"]);
    const context = { ...roleContext, userIds: ids };
    workspace = applyAccessWorkspaceCommand(workspace, { kind: "set-user-policies", principalId: qiao.principalId, policyIds: workspace.userPolicies[qiao.principalId]!.filter((id) => id !== "policy-tag-logs") }, context);
    expect(evaluateUserAccess(workspace, ids, archived).decision).toBe("allow");
    workspace = applyAccessWorkspaceCommand(workspace, { kind: "change-group-policies", id: "group-operators", added: [], removed: ["policy-tag-logs"] }, context);
    expect(evaluateUserAccess(workspace, ids, archived).decision).toBe("implicitDeny");
  });
  it("recomputes tag grants from the default revision, not policy metadata tags", () => {
    const workspace = initialAccessWorkspace("org-xiak");
    const staging = { ...qiao, resourceId: "logs-staging/storefront" };
    const policy = workspace.policies.find((entry) => entry.id === "policy-tag-logs")!;
    expect(evaluateUserAccess(workspace, ids, staging).decision).toBe("implicitDeny");
    policy.tags = [{ key: "environment", value: "staging" }];
    expect(evaluateUserAccess(workspace, ids, staging).decision).toBe("implicitDeny");
    const rolled = applyAccessWorkspaceCommand(workspace, { kind: "set-policy-version", id: policy.id, version: 1 }, { ...roleContext, userIds: ids });
    expect(evaluateUserAccess(rolled, ids, staging).decision).toBe("allow");
    expect(rolled.userPolicies).toEqual(workspace.userPolicies);
    expect(rolled.groups).toEqual(workspace.groups);
  });
  it("separates a matching deny from a boundary restriction and a nonmatching deny", () => {
    const workspace = initialAccessWorkspace("org-xiak");
    const deployment = { ...qiao, action: "paas:deploy", resourceId: "paas-storefront-staging" };
    expect(evaluateUserAccess(workspace, ids, deployment).decision).toBe("allow");
    expect(evaluateUserAccess(workspace, ids, { ...deployment, resourceId: "paas-checkout-api" }).decision).toBe("explicitDeny");
    const deletion = { ...deployment, action: "paas:delete" };
    expect(evaluateUserAccess(workspace, ids, deletion)).toMatchObject({ decision: "implicitDeny", boundary: { decision: "implicitDeny" } });
    delete workspace.userBoundaries[qiao.principalId];
    expect(evaluateUserAccess(workspace, ids, deletion).decision).toBe("allow");
  });
  it("supports an explicitly trusted human role without copying personal grants into its session", () => {
    let workspace = initialAccessWorkspace("org-xiak");
    const context = { ...roleContext, id: "session-review", userIds: ids };
    const roleRequest = { roleId: "role-log-reviewer", caller: { type: "user" as const, id: qiao.principalId }, at: request.at! };
    expect(evaluateRoleAssumption(workspace, ids, roleRequest).allowed).toBe(true);
    workspace = applyAccessWorkspaceCommand(workspace, { kind: "create-role-session", ...roleRequest, sessionMinutes: 15 }, context);
    expect(evaluateRoleSessionAccess(workspace, ids, context.id, qiao, request.at!).decision).toBe("allow");
    const deployment = { ...qiao, action: "paas:deploy", resourceId: "paas-storefront-staging" };
    expect(evaluateUserAccess(workspace, ids, deployment).decision).toBe("allow");
    expect(evaluateRoleSessionAccess(workspace, ids, context.id, deployment, request.at!).decision).toBe("implicitDeny");
    expect(evaluateRoleSessionAccess(workspace, ids, context.id, qiao, "2026-09-09T12:15:00Z").error).toBe("expiredSession");
    workspace = applyAccessWorkspaceCommand(workspace, { kind: "revoke-role-session", id: context.id }, context);
    expect(evaluateRoleSessionAccess(workspace, ids, context.id, qiao, request.at!).error).toBe("revokedSession");
  });
});
describe("closed preview policy language", () => {
  it("declares per-operation granularity and condition support independently of action classification", () => {
    expect(policyConditionsForActions([])).toEqual([]);
    expect(policyConditionsForActions(expandPolicyActions(["logs:search"]))).toEqual([...policyConditionKeys]);
    const mixed = expandPolicyActions(["logs:search", "logs:list"]);
    expect(mixed.map((action) => action.level)).toEqual(["list", "read"]);
    expect(policyConditionsForActions(mixed)).toEqual(["sourceIp", "notBefore", "notAfter"]);
    for (const action of policyActions) {
      const statement = { effect: "allow", action: [action.id], resource: ["*"], condition: { resourceTag: [{ key: "env", value: "prod" }] } };
      const parse = () => parsePolicyDocument(JSON.stringify({ version: "1", statement: [statement] }));
      if ((action.conditions as readonly string[]).includes("resourceTag")) expect(parse().statement[0]?.condition).toEqual(statement.condition);
      else expect(parse).toThrow("invalidCondition");
      expect(action.granularity).toBe(action.resourceType === "account" ? "operation" : "resource");
    }
  });

  it("makes fixtures executable and derives read-only access from classification", () => {
    const workspace = initialAccessWorkspace("org-xiak");
    workspace.policies.forEach((policy) => policy.versions.forEach((version) => expect(parsePolicyDocument(JSON.stringify(version.document), workspace.accountId)).toEqual(version.document)));
    const read = workspace.policies.find((policy) => policy.id === "policy-read")!.versions[0]!.document;
    expect(expandPolicyActions(read.statement.flatMap((statement) => statement.action)).map((action) => action.id)).toEqual(policyActions.filter((action) => action.level === "read" || action.level === "list").map((action) => action.id));
    expect(workspace.testResources.every((resource) => parsePolicyResource(resource.reference, false)?.tenant === workspace.accountId)).toBe(true);
  });
  it.each(["unknown:read", "logs:nothing", "logs:sea*", "*".repeat(64) + ":read", "logs:(.*)", " logs:search"])("rejects unregistered or ambiguous patterns %s", (value) => {
    expect(actionPatternValid(value)).toBe(false);
    expect(() => parsePolicyDocument(JSON.stringify({ ...grant(), statement: [{ ...grant().statement[0], action: [value] }] }))).toThrow("unknownAction");
  });
  it("retains all supported conditions and rejects unknown operators without stripping", () => {
    const document = grant({ sourceIp: ["192.0.2.0/24", "2001:db8::/32"], resourceTag: [{ key: "environment", value: "production" }], notBefore: "2026-09-09T00:00:00Z", notAfter: "2026-09-10T00:00:00.000Z" });
    expect(parsePolicyDocument(JSON.stringify(document))).toEqual(document);
    expect(() => parsePolicyDocument(JSON.stringify(grant({ sourceIp: ["192.0.2.0/24"], unsupported: true } as PolicyCondition)))).toThrow("unsupportedPolicy");
  });
  it.each([{}, null, { sourceIp: [] }, { sourceIp: [""] }, { sourceIp: ["192.0.2.1/33"] }, { sourceIp: ["2001:db8::/129"] }, { sourceIp: ["010.0.0.1/8"] }, { sourceIp: ["fe80::1%en0/64"] }, { resourceTag: [] }, { resourceTag: [{ key: "team", value: "one" }, { key: "team", value: "two" }] }, { resourceTag: [{ key: "team", value: 1 }] }, { notBefore: "" }, { notBefore: "2026-02-30T00:00:00Z" }, { notAfter: "2026-09-09T12:00:00+08:00" }, { notBefore: "2026-09-10T00:00:00Z", notAfter: "2026-09-09T00:00:00Z" }])("blocks malformed conditions %j", (condition) => {
    expect(() => parsePolicyDocument(JSON.stringify(grant(condition as PolicyCondition)))).toThrow("invalidCondition");
  });
  it("checks canonical resources, ownership, operation granularity and resource type", () => {
    const specific = (resource: string, action = "logs:search") => JSON.stringify({ version: "1", statement: [{ effect: "allow", action: [action], resource: [resource] }] });
    const ref = "matrix:logs:org-xiak:*:topic/production/*";
    expect(parsePolicyDocument(specific(ref), "org-xiak").statement[0]?.resource).toEqual([ref]);
    expect(() => parsePolicyDocument(specific(ref.replace("org-xiak", "org-other")), "org-xiak")).toThrow("tenantResource");
    expect(() => parsePolicyDocument(specific(ref, "logs:list"))).toThrow("invalidResource");
    expect(() => parsePolicyDocument(specific(ref, "paas:deploy"))).toThrow("invalidResource");
    for (const value of ["production/*", ref.replace("org-xiak", "*"), ref.replace("topic", "unknown"), ref.replace("production/*", "../secret"), ref.replace("production/*", "pre*fix")]) expect(() => parsePolicyDocument(specific(value))).toThrow("invalidResource");
    expect(() => parsePolicyDocument(JSON.stringify({ version: "1", statement: [{ effect: "allow", action: ["logs:list"], resource: ["*"], condition: { resourceTag: [{ key: "team", value: "delivery" }] } }] }))).toThrow("invalidCondition");
    const resource = { service: "logs" as const, tenant: "org-xiak", region: "cn-shanghai-a", type: "topic", id: "production/payment" };
    expect(parsePolicyResource(formatPolicyResource(resource), false)).toEqual(resource);
    expect(parsePolicyResource("matrix:logs:production/*")).toBeNull();
  });
  it("matches IPv4, IPv6 and mapped addresses with strict UTC time values", () => {
    expect(sourceIpMatches("192.0.2.42", ["192.0.2.0/24"])).toBe(true);
    expect(sourceIpMatches("::ffff:192.0.2.42", ["192.0.2.0/24"])).toBe(true);
    expect(sourceIpMatches("192.0.2.42", ["::ffff:192.0.2.0/120"])).toBe(true);
    expect(sourceIpMatches("2001:db8:1234::1", ["2001:db8::/32"])).toBe(true);
    expect(sourceIpMatches("2001:db9::1", ["2001:db8::/32", "192.0.2.0/24"])).toBe(false);
    expect(sourceIpMatches("not-an-ip", ["192.0.2.0/24"])).toBeNull();
    expect(sourceCidrValid("::ffff:192.0.2.0/80")).toBe(false);
    expect(utcTimeValid("2026-09-09T12:00:00.012Z")).toBe(true);
    expect(utcTimeValid("2026-09-09T12:00:00")).toBe(false);
  });
});
describe("role trust, boundaries and temporary session diagnostics", () => {
  it("creates no grants by default and changes metadata without changing trust or policies", () => {
    const source = initialAccessWorkspace("org-xiak");
    let workspace = applyAccessWorkspaceCommand(source, { ...accountRole, policyIds: [], boundaryPolicyId: undefined }, roleContext);
    workspace = applyAccessWorkspaceCommand(workspace, { kind: "update-role-metadata", id: roleContext.id, description: "New description", tags: [] }, roleContext);
    expect(workspace.roles.find((role) => role.id === roleContext.id)).toMatchObject({ name: "LogSupport", description: "New description", policyIds: [], trustedUserIds: ["principal-lin"] });
    expect(workspace.roles).toHaveLength(source.roles.length + 1);
    expect(source.roles.some((role) => role.id === roleContext.id)).toBe(false);
    expect(workspace.events.some((event) => event.action === "update-role-metadata")).toBe(true);
  });
  it.each([
    { principal: "org-other" }, { trustedUserIds: [] }, { trustedUserIds: ["*"] }, { trustedUserIds: ["foreign-user"] },
    { principalType: "service" as const, principal: "unregistered.matrix.internal", trustedUserIds: [] },
    { principalType: "provider" as const, principal: "unknown-provider", trustedUserIds: [] }
  ])("rejects unverified or overbroad trust atomically: %j", (patch) => {
    const workspace = initialAccessWorkspace("org-xiak"), before = structuredClone(workspace);
    expect(() => applyAccessWorkspaceCommand(workspace, { ...accountRole, ...patch }, roleContext)).toThrow("invalidTrust");
    expect(workspace).toEqual(before);
  });
  it("requires both account trust and caller authority, not either alone", () => {
    const workspace = roleWorkspace();
    expect(evaluateRoleAssumption(workspace, userIds, assumption)).toMatchObject({ allowed: false, reason: "callerDenied", callerDecision: { decision: "implicitDeny" } });
    expect(() => issueSession(workspace)).toThrow("callerDenied");
    workspace.userPolicies["principal-chen"] = ["policy-admin"];
    expect(evaluateRoleAssumption(workspace, userIds, { ...assumption, caller: { type: "user", id: "principal-chen" } })).toMatchObject({ allowed: false, reason: "trustDenied" });
    workspace.userPolicies["principal-lin"] = ["policy-admin"];
    expect(evaluateRoleAssumption(workspace, userIds, assumption).allowed).toBe(true);
    expect(issueSession(workspace).roleSessions).toHaveLength(1);
    workspace.userBoundaries["principal-lin"] = "policy-read";
    expect(evaluateRoleAssumption(workspace, userIds, assumption)).toMatchObject({ allowed: false, callerDecision: { decision: "implicitDeny", boundary: { decision: "implicitDeny" } } });
  });
  it("checks resource-specific assumption grants and caller conditions including group denies", () => {
    const workspace = roleWorkspace();
    const policy = workspace.policies.find((policy) => policy.id === "policy-prod-logs")!;
    policy.versions[0]!.document = { version: "1", statement: [{ effect: "allow", action: ["iam:assumeRole"], resource: ["matrix:iam:org-xiak:global:role/role-logs"], condition: { resourceTag: [{ key: "team", value: "support" }], sourceIp: ["192.0.2.0/24"] } }] };
    expect(evaluateRoleAssumption(workspace, userIds, assumption).allowed).toBe(true);
    expect(evaluateRoleAssumption(workspace, userIds, { ...assumption, sourceIp: undefined }).callerDecision?.decision).toBe("indeterminate");
    policy.versions[0]!.document.statement[0]!.resource = ["matrix:iam:org-xiak:global:role/other-role"];
    expect(evaluateRoleAssumption(workspace, userIds, assumption).allowed).toBe(false);
    workspace.userPolicies["principal-lin"] = ["policy-admin"];
    policy.versions[0]!.document = { version: "1", statement: [{ effect: "deny", action: ["iam:assumeRole"], resource: ["*"] }] };
    workspace.groups[0]!.policyIds = [policy.id];
    expect(evaluateRoleAssumption(workspace, userIds, assumption).callerDecision?.decision).toBe("explicitDeny");
  });
  it("uses only role grants and the boundary, never the caller's administrator grant", () => {
    let workspace = roleWorkspace(); workspace.userPolicies["principal-lin"] = ["policy-admin"];
    workspace = issueSession(workspace);
    const result = evaluateRoleSessionAccess(workspace, userIds, "session-logs", request, request.at!);
    expect(result).toMatchObject({ decision: "allow", boundary: { policyId: "policy-prod-logs", decision: "allow" } });
    expect(result.evidence.every((entry) => entry.source === "role" || entry.source === "boundary")).toBe(true);
    expect(result.evidence.some((entry) => entry.policyId === "policy-admin")).toBe(false);
    expect(evaluateRoleSessionAccess(workspace, userIds, "session-logs", { ...request, action: "logs:delete" }, request.at!).decision).toBe("implicitDeny");
    workspace.roles.find((role) => role.id === roleContext.id)!.policyIds = [];
    expect(evaluateRoleSessionAccess(workspace, userIds, "session-logs", request, request.at!).decision).toBe("implicitDeny");
  });
  it("never grants through a user boundary alone, protects boundary references and cleans up deleted users", () => {
    let workspace = initialAccessWorkspace("org-xiak");
    workspace = applyAccessWorkspaceCommand(workspace, { kind: "set-user-boundary", principalId: "principal-chen", policyId: "policy-prod-logs" }, roleContext);
    expect(evaluateUserAccess(workspace, userIds, { ...request, principalId: "principal-chen" }).decision).toBe("implicitDeny");
    expect(policyUsageCounts(workspace, "policy-prod-logs").total).toBe(2);
    workspace.userPolicies = {};
    expect(() => applyAccessWorkspaceCommand(workspace, { kind: "delete-policy", id: "policy-prod-logs" }, roleContext)).toThrow("referenced");
    workspace = applyAccessWorkspaceCommand(workspace, { kind: "delete-user", principalId: "principal-chen" }, roleContext);
    expect(workspace.userBoundaries["principal-chen"]).toBeUndefined();
    expect(workspace.userBoundaries["principal-qiao"]).toBe("policy-delivery-boundary");
    expect(() => applyAccessWorkspaceCommand(workspace, { kind: "set-user-boundary", principalId: "foreign", policyId: "policy-prod-logs" }, roleContext)).toThrow("invalid");
  });
  it("resolves boundary default revisions immediately and supports rollback without rebinding", () => {
    let workspace = roleWorkspace(); workspace.userPolicies["principal-lin"] = ["policy-admin"]; workspace = issueSession(workspace);
    workspace = applyAccessWorkspaceCommand(workspace, { kind: "save-policy", id: "policy-prod-logs", name: "ProductionLogReader", description: "Deny logs", document: grant(undefined, "deny") }, roleContext);
    expect(evaluateRoleSessionAccess(workspace, userIds, "session-logs", request, request.at!).decision).toBe("explicitDeny");
    workspace = applyAccessWorkspaceCommand(workspace, { kind: "set-policy-version", id: "policy-prod-logs", version: 1 }, roleContext);
    expect(evaluateRoleSessionAccess(workspace, userIds, "session-logs", request, request.at!).decision).toBe("allow");
    workspace.userPolicies = {};
    expect(() => applyAccessWorkspaceCommand(workspace, { kind: "delete-policy", id: "policy-prod-logs" }, roleContext)).toThrow("referenced");
    workspace.roles.find((role) => role.id === roleContext.id)!.boundaryPolicyId = "missing-policy";
    expect(evaluateRoleSessionAccess(workspace, userIds, "session-logs", request, request.at!).decision).toBe("indeterminate");
  });
  it("expires using the diagnostic clock, not a user-controlled policy timestamp", () => {
    let workspace = roleWorkspace(); workspace.userPolicies["principal-lin"] = ["policy-admin"]; workspace = issueSession(workspace);
    const session = workspace.roleSessions[0]!;
    expect(evaluateRoleSessionAccess(workspace, userIds, session.id, request, "2026-09-09T12:29:59Z").decision).toBe("allow");
    expect(evaluateRoleSessionAccess(workspace, userIds, session.id, { ...request, at: "2026-09-09T12:00:00Z" }, session.expiresAt).error).toBe("expiredSession");
    expect(evaluateRoleSessionAccess(workspace, userIds, session.id, request, "invalid").error).toBe("unavailableSession");
    expect(evaluateRoleSessionAccess(workspace, userIds, session.id, request, "2026-09-09T11:59:59Z").error).toBe("unavailableSession");
    workspace = applyAccessWorkspaceCommand(workspace, { kind: "update-role-settings", id: roleContext.id, sessionMinutes: 720, consoleAccess: true }, roleContext);
    expect(workspace.roleSessions[0]!.expiresAt).toBe(session.expiresAt);
  });
  it("rechecks trust when issuing, revokes individual sessions and rejects missing role/caller", () => {
    let workspace = roleWorkspace(); workspace.userPolicies["principal-lin"] = ["policy-admin"]; workspace = issueSession(workspace);
    workspace = applyAccessWorkspaceCommand(workspace, { kind: "update-role-trust", id: roleContext.id, principal: "org-xiak", trustedUserIds: ["principal-chen"] }, roleContext);
    expect(() => issueSession(workspace)).toThrow("trustDenied");
    expect(evaluateRoleSessionAccess(workspace, userIds, "session-logs", request, request.at!).decision).toBe("allow");
    expect(evaluateRoleSessionAccess(workspace, ["principal-chen"], "session-logs", request, request.at!).error).toBe("unavailableSession");
    const revoked = applyAccessWorkspaceCommand(workspace, { kind: "revoke-role-session", id: "session-logs" }, roleContext);
    expect(evaluateRoleSessionAccess(revoked, userIds, "session-logs", request, request.at!).error).toBe("revokedSession");
    workspace = applyAccessWorkspaceCommand(workspace, { kind: "delete-role", id: roleContext.id }, roleContext);
    expect(evaluateRoleSessionAccess(workspace, userIds, "session-logs", request, request.at!).error).toBe("unavailableSession");
  });
  it("only recognizes registered workloads and enabled mapped provider identities", () => {
    const workspace = initialAccessWorkspace("org-xiak");
    expect(evaluateRoleAssumption(workspace, userIds, { ...assumption, roleId: "role-pipeline", caller: { type: "service", id: "devops.matrix.internal" } }).allowed).toBe(true);
    expect(evaluateRoleAssumption(workspace, userIds, { ...assumption, roleId: "role-pipeline", caller: { type: "service", id: "forged.matrix.internal" } }).allowed).toBe(false);
    const federated = { ...assumption, roleId: "role-audit", caller: { type: "federation" as const, id: "federation-audit" } };
    expect(evaluateRoleAssumption(workspace, userIds, federated).allowed).toBe(true);
    workspace.providers[0]!.enabled = false;
    expect(evaluateRoleAssumption(workspace, userIds, federated).allowed).toBe(false);
    workspace.providers[0]!.enabled = true; workspace.federations[0]!.enabled = false;
    expect(evaluateRoleAssumption(workspace, userIds, federated).allowed).toBe(false);
  });
  it("validates operation limits without replacing policies not included in a delta", () => {
    let workspace = roleWorkspace();
    workspace.roles.find((role) => role.id === roleContext.id)!.policyIds.push("not-loaded");
    workspace = applyAccessWorkspaceCommand(workspace, { kind: "change-role-policies", id: roleContext.id, added: ["policy-delivery"], removed: [] }, roleContext);
    expect(workspace.roles.find((role) => role.id === roleContext.id)!.policyIds).toContain("not-loaded");
    for (const removed of [["not-bound"], ["policy-read", ...Array.from({ length: 30 }, () => "not-loaded")]]) expect(() => applyAccessWorkspaceCommand(workspace, { kind: "change-role-policies", id: roleContext.id, added: [], removed }, roleContext)).toThrow("invalid");
    expect(() => applyAccessWorkspaceCommand(workspace, { kind: "set-role-boundary", id: roleContext.id, policyId: "unknown" }, roleContext)).toThrow("notFound");
    workspace.userPolicies["principal-lin"] = ["policy-admin"];
    for (const sessionMinutes of [0, 14, 60.5, 61, NaN]) expect(() => applyAccessWorkspaceCommand(workspace, { kind: "create-role-session", ...assumption, sessionMinutes }, roleContext)).toThrow("invalid");
  });
});
describe("user permission explanation", () => {
  it("reflects reviewed group commands without confusing one revoked source with total revocation", () => {
    let workspace = initialAccessWorkspace("org-xiak");
    const context = { id: "group-logs", at: request.at!, userIds, primaryPrincipalId: "principal-admin" };
    workspace = applyAccessWorkspaceCommand(workspace, { kind: "create-group", name: "Log readers", description: "", policyIds: ["policy-prod-logs"] }, context);
    workspace = applyAccessWorkspaceCommand(workspace, { kind: "change-group-members", id: "group-logs", added: ["principal-chen", "principal-lin"], removed: [] }, context);
    const chen = { ...request, principalId: "principal-chen" };
    expect(evaluateUserAccess(workspace, userIds, chen).decision).toBe("allow");
    workspace = applyAccessWorkspaceCommand(workspace, { kind: "change-group-members", id: "group-logs", added: [], removed: ["principal-lin"] }, context);
    expect(evaluateUserAccess(workspace, userIds, request).decision).toBe("allow");
    workspace = applyAccessWorkspaceCommand(workspace, { kind: "delete-group", id: "group-logs" }, context);
    expect(evaluateUserAccess(workspace, userIds, chen).decision).toBe("implicitDeny");
    expect(evaluateUserAccess(workspace, userIds, request).decision).toBe("allow");
    expect(workspace.policies.find((policy) => policy.id === "policy-prod-logs")).toBeDefined();
  });
  it("preserves direct/group provenance without mutating state or losing an inherited grant", () => {
    const workspace = initialAccessWorkspace("org-xiak");
    workspace.groups[0]!.policyIds.push("policy-prod-logs");
    const before = structuredClone(workspace);
    const result = evaluateUserAccess(workspace, userIds, request);
    expect(result.decision).toBe("allow");
    expect(result.evidence.filter((entry) => entry.policyId === "policy-prod-logs")).toEqual([
      expect.objectContaining({ source: "direct", version: 1, statement: 1, reason: "matched" }),
      expect.objectContaining({ source: "group", groupId: "group-delivery", version: 1, statement: 1, reason: "matched" })
    ]);
    expect(workspace).toEqual(before);
    delete workspace.userPolicies["principal-lin"];
    expect(evaluateUserAccess(workspace, userIds, request).decision).toBe("allow");
    workspace.groups[0]!.policyIds = [];
    expect(evaluateUserAccess(workspace, userIds, request).decision).toBe("implicitDeny");
  });
  it("requires known same-tenant resources, matching actions and a grant", () => {
    const workspace = withPolicy();
    expect(evaluateUserAccess(workspace, userIds, { ...request, principalId: "principal-chen" }).decision).toBe("implicitDeny");
    expect(evaluateUserAccess(workspace, userIds, { ...request, principalId: "intruder" }).error).toBe("unknownIdentity");
    expect(evaluateUserAccess(workspace, userIds, { ...request, resourceId: "unknown" }).error).toBe("unknownResource");
    workspace.testResources.push({ id: "foreign", reference: "matrix:logs:org-other:cn-shanghai-a:topic/secret" });
    expect(evaluateUserAccess(workspace, userIds, { ...request, resourceId: "foreign" }).error).toBe("crossTenant");
    expect(evaluateUserAccess(workspace, userIds, { ...request, action: "logs:list" }).error).toBe("actionResourceMismatch");
    expect(evaluateUserAccess(workspace, userIds, { ...request, action: "logs:unknown" }).error).toBe("unknownAction");
  });
  it("prioritizes deny across grant sources and follows default-version rollback", () => {
    let workspace = initialAccessWorkspace("org-xiak");
    workspace.groups[0]!.policyIds.push("policy-read");
    const context = { id: "new", at: "2026-09-09T12:00:00Z", userIds, primaryPrincipalId: "principal-admin" };
    workspace = applyAccessWorkspaceCommand(workspace, { kind: "save-policy", id: "policy-prod-logs", name: "ProductionLogReader", description: "", document: grant(undefined, "deny") }, context);
    expect(evaluateUserAccess(workspace, userIds, request).decision).toBe("explicitDeny");
    workspace = applyAccessWorkspaceCommand(workspace, { kind: "set-policy-version", id: "policy-prod-logs", version: 1 }, context);
    expect(evaluateUserAccess(workspace, userIds, request).decision).toBe("allow");
  });
  it("matches region and ID prefixes independently", () => {
    const workspace = initialAccessWorkspace("org-xiak");
    expect(evaluateUserAccess(workspace, userIds, { ...request, resourceId: "logs-staging/storefront" }).decision).toBe("implicitDeny");
    workspace.policies.find((policy) => policy.id === "policy-prod-logs")!.versions[0]!.document.statement[0]!.resource = ["matrix:logs:org-xiak:cn-shanghai-b:topic/production/*"];
    expect(evaluateUserAccess(workspace, userIds, request).decision).toBe("implicitDeny");
  });
  it("combines condition types with AND, ranges with OR, exact tags and inclusive time bounds", () => {
    const workspace = withPolicy({ sourceIp: ["198.51.100.0/24", "192.0.2.0/24"], resourceTag: [{ key: "environment", value: "production" }, { key: "team", value: "delivery" }], notBefore: request.at, notAfter: request.at });
    expect(evaluateUserAccess(workspace, userIds, request).decision).toBe("allow");
    expect(evaluateUserAccess(workspace, userIds, { ...request, at: "2026-09-09T12:00:00.001Z" }).decision).toBe("implicitDeny");
    expect(evaluateUserAccess(workspace, userIds, { ...request, sourceIp: "203.0.113.1" }).decision).toBe("implicitDeny");
    workspace.testResources.find((resource) => resource.id === request.resourceId)!.tags!.team = "Delivery";
    expect(evaluateUserAccess(workspace, userIds, request).decision).toBe("implicitDeny");
  });
  it("never allows when a potentially applicable deny requires missing/invalid context", () => {
    const workspace = withPolicy({ sourceIp: ["192.0.2.0/24"], notBefore: "2026-09-09T00:00:00Z" }, "deny");
    workspace.groups[0]!.policyIds.push("policy-read");
    const result = evaluateUserAccess(workspace, userIds, { ...request, sourceIp: undefined, at: "invalid" });
    expect(result.decision).toBe("indeterminate");
    expect(result.evidence.find((entry) => entry.policyId === "policy-prod-logs")?.missing).toEqual(["sourceIp", "time"]);
    expect(evaluateUserAccess(workspace, userIds, { ...request, sourceIp: "::ffff:192.0.2.42" }).decision).toBe("explicitDeny");
  });
  it("distinguishes absent tags from an unread tag context and fails closed for corrupt policy references", () => {
    const workspace = withPolicy({ resourceTag: [{ key: "missing", value: "value" }] });
    expect(evaluateUserAccess(workspace, userIds, request).decision).toBe("implicitDeny");
    delete workspace.testResources.find((resource) => resource.id === request.resourceId)!.tags;
    expect(evaluateUserAccess(workspace, userIds, request).decision).toBe("indeterminate");
    workspace.userPolicies["principal-lin"]!.push("missing-policy");
    expect(evaluateUserAccess(workspace, userIds, request).evidence.some((entry) => entry.reason === "invalidPolicy")).toBe(true);
    expect(evaluateUserAccess(workspace, userIds, { ...request, action: "iam:assumeRole", resourceId: "iam-role-pipeline" }).error).toBe("requiresRoleTrust");
  });
});
